//! `T`, its runner and the test-binary driver (`M`, `RunTests`, `Main`).

use std::{
    fmt,
    panic::{self, AssertUnwindSafe},
    sync::Arc,
    time::{Duration, Instant},
};

use super::{
    benchmark::{run_benchmarks_impl, InternalBenchmark},
    common::{
        goexit, impl_tb, is_goexit, panic_message, Chatty, Common, CommonSpec, Sink, TestState,
        PARALLEL_CONFLICT,
    },
    flags,
    fuzz::{run_fuzz_tests, InternalFuzzTarget},
    matcher::{regexp_match, MatchFn, Matcher},
};

/// A test function: Go's `func(*testing.T)`.
pub type TestFn = Arc<dyn Fn(&T) + Send + Sync + 'static>;

/// Go's `testing.InternalTest`.
#[derive(Clone)]
pub struct InternalTest {
    /// Go's `Name`.
    pub name: String,
    /// Go's `F`.
    pub f: TestFn,
}

impl InternalTest {
    /// Builds a test from a name and function.
    pub fn new(name: &str, f: impl Fn(&T) + Send + Sync + 'static) -> InternalTest {
        InternalTest {
            name: name.to_string(),
            f: Arc::new(f),
        }
    }
}

impl fmt::Debug for InternalTest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InternalTest")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// Go's `testing.T`: passed to test functions to manage test state and
/// support formatted test logs.
///
/// A test ends when its function returns or calls any of
/// [`TB::fail_now`](super::TB::fail_now), [`TB::fatal`](super::TB::fatal),
/// [`TB::fatalf`](super::TB::fatalf), [`TB::skip_now`](super::TB::skip_now),
/// [`TB::skip`](super::TB::skip) or [`TB::skipf`](super::TB::skipf), which
/// unwind with the [`Goexit`](super::Goexit) payload.
#[derive(Clone)]
pub struct T {
    pub(crate) c: Common,
}

impl_tb!(T);

fn fmt_duration(d: Duration) -> String {
    format!("{:.2}s", d.as_secs_f64())
}

impl T {
    pub(crate) fn from_common(c: Common) -> T {
        T { c }
    }

    /// Creates the `T` of a `synctest` bubble: a child of this test with the
    /// same name whose output belongs to this test (Go's
    /// `testingSynctestTest`).
    pub(crate) fn synctest_child(&self) -> T {
        if self
            .c
            .cleanup_started
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            panic!("testing: synctest.Run called during t.Cleanup");
        }
        let child = Common::new(self.c.child_spec(self.c.name.clone()));
        child
            .is_synctest
            .store(true, std::sync::atomic::Ordering::SeqCst);
        T::from_common(child)
    }

    /// Go's `Cleanup` with a plain closure (the [`TB`](super::TB) method
    /// takes a boxed one so that the trait stays object safe).
    pub fn cleanup<F: FnOnce() + Send + 'static>(&self, f: F) {
        self.c.cleanup(Box::new(f));
    }

    pub(crate) fn setenv_impl(&self, key: &str, value: &str) {
        self.check_parallel();
        self.c.tb_setenv(key, value);
    }

    pub(crate) fn chdir_impl(&self, dir: &str) {
        self.check_parallel();
        self.c.tb_chdir(dir);
    }

    /// Denies `parallel` for this test, and panics if it or an ancestor is
    /// already parallel: process-wide state cannot be changed by parallel
    /// tests.
    pub fn check_parallel(&self) {
        let mut cur = Some(self.c.clone());
        while let Some(c) = cur {
            if c.lock().is_parallel {
                panic!("{PARALLEL_CONFLICT}");
            }
            cur = c.parent.clone();
        }
        self.c.lock().deny_parallel = true;
    }

    /// Go's `Deadline`: the time at which the test binary will have exceeded
    /// the `-test.timeout`, or `None` for no timeout.
    pub fn deadline(&self) -> Option<Instant> {
        if self.c.is_synctest.load(std::sync::atomic::Ordering::SeqCst) {
            panic!("testing: t.Deadline called inside synctest bubble");
        }
        self.c.tstate.deadline
    }

    /// Go's `Parallel`: signals that this test is to be run in parallel with
    /// (and only with) other parallel tests, pausing it until its parent test
    /// function has returned.
    ///
    /// Only tests running on their own thread can pause: top-level tests and
    /// subtests started with [`T::run_static`]. A subtest started with
    /// [`T::run`] runs inline, borrowing its parent's frame, so there `parallel`
    /// only marks the test as parallel (which forbids `setenv`/`chdir`).
    pub fn parallel(&self) {
        let c = &self.c;
        if c.is_synctest.load(std::sync::atomic::Ordering::SeqCst) {
            panic!("testing: t.Parallel called inside synctest bubble");
        }
        {
            let g = c.lock();
            if g.is_parallel {
                drop(g);
                panic!("testing: t.Parallel called multiple times");
            }
            if g.deny_parallel {
                drop(g);
                panic!("{PARALLEL_CONFLICT}");
            }
        }
        let Some(parent) = c.parent.clone() else {
            panic!("testing: t.Parallel called on the root test");
        };
        if !c.lock().parallel_capable {
            c.lock().is_parallel = true;
            return;
        }
        {
            let mut g = c.lock();
            g.is_parallel = true;
            let since = g.start.elapsed();
            g.duration += since;
        }
        parent.lock().sub.push(c.clone());
        if let Some(ch) = &c.chatty {
            ch.updatef(&c.name, &format!("=== PAUSE {}\n", c.name));
        }
        c.send_signal(true);
        parent.barrier.wait();
        c.tstate.wait_parallel();
        let mut g = c.lock();
        g.par_held = true;
        drop(g);
        if let Some(ch) = &c.chatty {
            ch.updatef(&c.name, &format!("=== CONT  {}\n", c.name));
        }
        c.lock().start = Instant::now();
    }

    fn start_sub(&self, name: &str) -> Option<T> {
        if self.c.is_synctest.load(std::sync::atomic::Ordering::SeqCst) {
            panic!("testing: t.Run called inside synctest bubble");
        }
        if self
            .c
            .cleanup_started
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            panic!("testing: t.Run called during t.Cleanup");
        }
        self.c
            .has_sub
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let (test_name, ok, _) = self
            .c
            .tstate
            .matcher
            .full_name(Some((&self.c.name, self.c.level)), name);
        if !ok || self.c.tstate.should_fail_fast() {
            return None;
        }
        let child = Common::new(self.c.child_spec(test_name));
        if let Some(ch) = &child.chatty {
            ch.updatef(&child.name, &format!("=== RUN   {}\n", child.name));
        }
        Some(T::from_common(child))
    }

    /// Go's `Run`: runs `f` as a subtest called `name` and reports whether it
    /// succeeded.
    ///
    /// `f` runs on the calling thread, so it may borrow from the caller and
    /// need not be `Send`. A subtest that must be paused by
    /// [`parallel`](T::parallel) uses [`run_static`](T::run_static).
    pub fn run<F: FnOnce(&T)>(&self, name: &str, f: F) -> bool {
        let Some(t) = self.start_sub(name) else {
            return true;
        };
        t_runner(&t, f);
        if !t.c.recv_signal() {
            // A subtest called FailNow on a parent: keep aborting up the chain.
            goexit();
        }
        !t.c.failed()
    }

    /// Like [`run`](T::run) but runs `f` on its own thread, so that
    /// [`parallel`](T::parallel) pauses it until the parent test function
    /// returns, exactly as Go's goroutine-per-subtest does.
    pub fn run_static<F: FnOnce(&T) + Send + 'static>(&self, name: &str, f: F) -> bool {
        let Some(t) = self.start_sub(name) else {
            return true;
        };
        t.c.lock().parallel_capable = true;
        let tc = t.clone();
        std::thread::Builder::new()
            .name(t.c.name.clone())
            .spawn(move || t_runner(&tc, f))
            .expect("testing: cannot start subtest thread");
        if !t.c.recv_signal() {
            goexit();
        }
        !t.c.failed()
    }

    fn report(&self) {
        let c = &self.c;
        if c.parent.is_none() || c.is_synctest.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let dstr = fmt_duration(c.lock().duration);
        let status = if c.failed() {
            Some("FAIL")
        } else if c.chatty.is_some() {
            Some(if c.skipped() { "SKIP" } else { "PASS" })
        } else {
            None
        };
        if let Some(s) = status {
            c.flush_to_parent(&c.name, &format!("--- {s}: {} ({dstr})\n", c.name));
        }
    }
}

/// Go's `tRunner`: runs `f` for `t`, then reports.
pub(crate) fn t_runner<F: FnOnce(&T)>(t: &T, f: F) {
    let c = &t.c;
    c.lock().start = Instant::now();
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        f(t);
        c.lock().finished = true;
    }));

    let mut signal = true;
    let mut foreign_panic = None;
    match result {
        Ok(()) => {}
        Err(p) if is_goexit(&*p) => {
            if !c.lock().finished {
                // Goexit raised by another test's FailNow.
                let mut cur = c.parent.clone();
                while let Some(p) = cur {
                    if p.lock().finished {
                        if !c.lock().is_parallel {
                            c.log_at(
                                panic::Location::caller(),
                                "test executed panic(nil) or runtime.Goexit: subtest may have called FailNow on a parent test",
                                true,
                            );
                            c.fail();
                        }
                        signal = false;
                        break;
                    }
                    cur = p.parent.clone();
                }
            }
        }
        Err(p) => foreign_panic = Some(panic_message(&*p)),
    }
    if let Some(msg) = foreign_panic {
        c.fail();
        c.log_plain(&format!("panic: {msg}"));
        c.lock().finished = true;
    }

    let has_parallel_subs = !c.lock().sub.is_empty();
    if !has_parallel_subs {
        if let Some(msg) = c.run_cleanup() {
            c.fail();
            c.log_plain(&format!("cleanup panicked with {msg}"));
        }
    }
    {
        let mut g = c.lock();
        let since = g.start.elapsed();
        g.duration += since;
    }

    if has_parallel_subs {
        // Run the parallel subtests.
        c.tstate.release();
        c.barrier.open();
        let subs: Vec<Common> = c.lock().sub.clone();
        for sub in &subs {
            sub.recv_signal();
        }
        let start = Instant::now();
        if let Some(msg) = c.run_cleanup() {
            c.fail();
            c.log_plain(&format!("cleanup panicked with {msg}"));
        }
        c.lock().duration += start.elapsed();
        if !c.lock().is_parallel {
            // Reacquire the slot for sequential tests.
            c.tstate.wait_parallel();
        }
    } else {
        let held = c.lock().par_held;
        if held {
            c.tstate.release();
        }
    }
    let mut root = Some(c.clone());
    while let Some(r) = root {
        if r.parent.is_none() {
            break;
        }
        r.flush_partial();
        root = r.parent.clone();
    }
    if c.failed() {
        c.tstate
            .num_failed
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    t.report();
    c.lock().done = true;
    if c.parent.is_some() && !c.has_sub.load(std::sync::atomic::Ordering::SeqCst) {
        c.set_ran();
    }
    c.send_signal(signal);
}

// ----- the test binary driver -----

/// What a run of tests writes to and how it is filtered.
#[derive(Clone)]
pub(crate) struct RunEnv {
    pub(crate) sink: Arc<Sink>,
    pub(crate) verbose: bool,
    pub(crate) run: String,
    pub(crate) skip: String,
    pub(crate) parallel: usize,
    pub(crate) failfast: bool,
    pub(crate) fullpath: bool,
    pub(crate) count: u32,
    pub(crate) deadline: Option<Instant>,
    pub(crate) module_path: String,
    pub(crate) import_path: String,
}

impl RunEnv {
    pub(crate) fn from_flags(sink: Arc<Sink>) -> RunEnv {
        let f = flags();
        RunEnv {
            sink,
            verbose: f.verbose,
            run: f.run.clone(),
            skip: f.skip.clone(),
            parallel: f.parallel,
            failfast: f.failfast,
            fullpath: f.fullpath,
            count: f.count,
            deadline: f.timeout.map(|d| Instant::now() + d.to_std()),
            module_path: String::new(),
            import_path: String::new(),
        }
    }
}

pub(crate) fn matcher_or_exit(m: MatchFn, patterns: &str, name: &str, skips: &str) -> Matcher {
    match Matcher::new(m, patterns, name, skips) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

pub(crate) fn root_common(env: &RunEnv, tstate: Arc<TestState>) -> Common {
    Common::new(CommonSpec {
        name: String::new(),
        parent: None,
        level: 0,
        chatty: env.verbose.then(|| Chatty::new(env.sink.clone())),
        sink: env.sink.clone(),
        bench: false,
        tstate,
        module_path: env.module_path.clone(),
        import_path: env.import_path.clone(),
    })
}

pub(crate) fn make_tstate(env: &RunEnv, matcher: Matcher) -> Arc<TestState> {
    let mut ts = TestState::new(env.parallel, matcher);
    ts.deadline = env.deadline;
    ts.failfast = env.failfast;
    ts.fullpath = env.fullpath;
    Arc::new(ts)
}

/// Go's `runTests`: returns (ran, ok).
pub(crate) fn run_tests_impl(
    env: &RunEnv,
    match_fn: &MatchFn,
    tests: &[InternalTest],
) -> (bool, bool) {
    let mut ok = true;
    let mut ran = false;
    for i in 0..env.count {
        if i > 0 && !ran {
            break;
        }
        let matcher = matcher_or_exit(match_fn.clone(), &env.run, "-test.run", &env.skip);
        let tstate = make_tstate(env, matcher);
        let root = T::from_common(root_common(env, tstate.clone()));
        if tstate.should_fail_fast() {
            break;
        }
        t_runner(&root, |t| {
            for test in tests {
                let f = test.f.clone();
                t.run_static(&test.name, move |t| f(t));
            }
        });
        ok = ok && !root.c.failed();
        ran = ran || root.c.lock().ran;
    }
    (ran, ok)
}

/// Go's `testing.RunTests`: runs the tests that match `-test.run`, printing
/// Go's report to standard output, and reports whether they all passed.
pub fn run_tests(
    match_string: impl Fn(&str, &str) -> Result<bool, String> + Send + Sync + 'static,
    tests: &[InternalTest],
) -> bool {
    super::init();
    let env = RunEnv::from_flags(Sink::stdout());
    let (ran, ok) = run_tests_impl(&env, &(Arc::new(match_string) as MatchFn), tests);
    if !ran && !super::have_examples() {
        eprintln!("testing: warning: no tests to run");
    }
    ok
}

/// An example function: it prints to the writer it is given.
pub type ExampleFn = Arc<dyn Fn(&mut dyn std::io::Write) + Send + Sync + 'static>;

/// Go's `testing.InternalExample`. Go captures the example's standard output;
/// Rust cannot redirect the process stdout, so the example writes to the
/// writer it is given.
#[derive(Clone)]
pub struct InternalExample {
    /// Go's `Name`.
    pub name: String,
    /// Go's `F`.
    pub f: ExampleFn,
    /// Go's `Output`: the expected output.
    pub output: String,
    /// Go's `Unordered`: compare the sorted lines.
    pub unordered: bool,
}

fn process_run_result(
    eg: &InternalExample,
    sink: &Sink,
    verbose: bool,
    stdout: &str,
    spent: Duration,
    finished: bool,
    panicked: bool,
) -> bool {
    let dstr = fmt_duration(spent);
    let got = stdout.trim();
    let want = eg.output.trim();
    let mut fail = String::new();
    if eg.unordered {
        let mut g: Vec<&str> = got.split('\n').collect();
        let mut w: Vec<&str> = want.split('\n').collect();
        g.sort_unstable();
        w.sort_unstable();
        if g != w && !panicked {
            fail = format!("got:\n{stdout}\nwant (unordered):\n{}\n", eg.output);
        }
    } else if got != want && !panicked {
        fail = format!("got:\n{got}\nwant:\n{want}\n");
    }
    if !fail.is_empty() || !finished || panicked {
        sink.write(&format!("--- FAIL: {} ({dstr})\n{fail}", eg.name));
        false
    } else {
        if verbose {
            sink.write(&format!("--- PASS: {} ({dstr})\n", eg.name));
        }
        true
    }
}

fn run_example(env: &RunEnv, eg: &InternalExample) -> bool {
    if env.verbose {
        env.sink.write(&format!("=== RUN   {}\n", eg.name));
    }
    let mut buf: Vec<u8> = Vec::new();
    let start = Instant::now();
    let r = panic::catch_unwind(AssertUnwindSafe(|| (eg.f)(&mut buf)));
    let out = String::from_utf8_lossy(&buf).into_owned();
    let (finished, panicked) = match &r {
        Ok(()) => (true, false),
        Err(p) => (false, !is_goexit(&**p)),
    };
    let ok = process_run_result(
        eg,
        &env.sink,
        env.verbose,
        &out,
        start.elapsed(),
        finished,
        panicked,
    );
    if let Err(p) = r {
        panic::resume_unwind(p);
    }
    ok
}

pub(crate) fn run_examples_impl(
    env: &RunEnv,
    match_fn: &MatchFn,
    examples: &[InternalExample],
) -> (bool, bool) {
    let m = matcher_or_exit(match_fn.clone(), &env.run, "-test.run", &env.skip);
    let (mut ran, mut ok) = (false, true);
    for eg in examples {
        let (_, matched, _) = m.full_name(None, &eg.name);
        if !matched {
            continue;
        }
        ran = true;
        if !run_example(env, eg) {
            ok = false;
        }
    }
    (ran, ok)
}

/// Go's `testing.RunExamples`.
pub fn run_examples(
    match_string: impl Fn(&str, &str) -> Result<bool, String> + Send + Sync + 'static,
    examples: &[InternalExample],
) -> bool {
    super::init();
    let env = RunEnv::from_flags(Sink::stdout());
    run_examples_impl(&env, &(Arc::new(match_string) as MatchFn), examples).1
}

/// The functionality that `go test` passes to [`main_start`]: Go's
/// unexported `testDeps` interface.
pub trait TestDeps {
    /// Reports whether `pat` matches `s`.
    fn match_string(&self, pat: &str, s: &str) -> Result<bool, String>;
    /// The import path of the package under test.
    fn import_path(&self) -> String {
        String::new()
    }
    /// The module path of the package under test.
    fn module_path(&self) -> String {
        String::new()
    }
}

/// [`TestDeps`] matching with [`crate::regexp`].
#[derive(Clone, Copy, Debug, Default)]
pub struct RegexpDeps;

impl TestDeps for RegexpDeps {
    fn match_string(&self, pat: &str, s: &str) -> Result<bool, String> {
        crate::regexp::match_string(pat, s).map_err(|e| e.to_string())
    }
}

struct FnDeps<F>(F);

impl<F: Fn(&str, &str) -> Result<bool, String>> TestDeps for FnDeps<F> {
    fn match_string(&self, pat: &str, s: &str) -> Result<bool, String> {
        (self.0)(pat, s)
    }
}

/// Go's `testing.M`: passed to a `TestMain` function to run the tests.
pub struct M {
    match_fn: MatchFn,
    import_path: String,
    module_path: String,
    tests: Vec<InternalTest>,
    benchmarks: Vec<InternalBenchmark>,
    fuzz_targets: Vec<InternalFuzzTarget>,
    examples: Vec<InternalExample>,
    sink: Arc<Sink>,
}

/// Go's `testing.MainStart`: builds an [`M`] for the given tests.
pub fn main_start(
    deps: impl TestDeps + Send + Sync + 'static,
    tests: Vec<InternalTest>,
    benchmarks: Vec<InternalBenchmark>,
    fuzz_targets: Vec<InternalFuzzTarget>,
    examples: Vec<InternalExample>,
) -> M {
    super::init();
    let import_path = deps.import_path();
    let module_path = deps.module_path();
    let deps = Arc::new(deps);
    M {
        match_fn: Arc::new(move |p, s| deps.match_string(p, s)),
        import_path,
        module_path,
        tests,
        benchmarks,
        fuzz_targets,
        examples,
        sink: Sink::stdout(),
    }
}

/// Go's `testing.Main`: runs the tests and exits the process with the result.
pub fn main(
    match_string: impl Fn(&str, &str) -> Result<bool, String> + Send + Sync + 'static,
    tests: Vec<InternalTest>,
    benchmarks: Vec<InternalBenchmark>,
    examples: Vec<InternalExample>,
) -> ! {
    let mut m = main_start(
        FnDeps(match_string),
        tests,
        benchmarks,
        Vec::new(),
        examples,
    );
    std::process::exit(m.run())
}

impl M {
    /// Redirects the report from standard output to `sink`.
    pub fn set_output(&mut self, sink: Arc<Sink>) {
        self.sink = sink;
    }

    /// Go's `M.Run`: runs the tests and returns the exit code (0 on success).
    pub fn run(&mut self) -> i32 {
        super::init();
        let f = flags();
        let print = |s: &str| self.sink.write(s);
        if f.parallel < 1 {
            eprintln!("testing: -parallel can only be given a positive integer");
            return 2;
        }
        if !f.list.is_empty() {
            self.list_tests(&f.list);
            return 0;
        }
        if f.shuffle != "off" {
            let n: i64 = if f.shuffle == "on" {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos() as i64)
            } else {
                match f.shuffle.parse::<i64>() {
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!(
                            "testing: -shuffle should be \"off\", \"on\", or a valid integer: {e}"
                        );
                        return 2;
                    }
                }
            };
            print(&format!("-test.shuffle {n}\n"));
            let mut rng =
                crate::math::rand::v1::Rand::new(crate::math::rand::v1::RngSource::new(n));
            let tests = &mut self.tests;
            rng.shuffle(tests.len(), |i, j| tests.swap(i, j));
            let benches = &mut self.benchmarks;
            rng.shuffle(benches.len(), |i, j| benches.swap(i, j));
        }
        let mut env = RunEnv::from_flags(self.sink.clone());
        env.module_path = self.module_path.clone();
        env.import_path = self.import_path.clone();
        super::set_have_examples(!self.examples.is_empty());
        let (test_ran, test_ok) = run_tests_impl(&env, &self.match_fn, &self.tests);
        let (fuzz_ran, fuzz_ok) = run_fuzz_tests(&env, &self.match_fn, &self.fuzz_targets);
        let (example_ran, example_ok) = run_examples_impl(&env, &self.match_fn, &self.examples);
        if !test_ran && !example_ran && !fuzz_ran && f.bench.is_empty() {
            eprintln!("testing: warning: no tests to run");
        }
        let bench_ok = run_benchmarks_impl(&env, &self.match_fn, &self.benchmarks);
        if !test_ok || !example_ok || !fuzz_ok || !bench_ok {
            print("FAIL\n");
            return 1;
        }
        print("PASS\n");
        0
    }

    fn list_tests(&self, pattern: &str) {
        if let Err(e) = (self.match_fn)(pattern, "non-empty") {
            eprintln!(
                "testing: invalid regexp in -test.list ({}): {e}",
                crate::strconv::quote(pattern)
            );
            std::process::exit(1);
        }
        let names = self
            .tests
            .iter()
            .map(|t| &t.name)
            .chain(self.benchmarks.iter().map(|t| &t.name))
            .chain(self.fuzz_targets.iter().map(|t| &t.name))
            .chain(self.examples.iter().map(|t| &t.name));
        for n in names {
            if (self.match_fn)(pattern, n).unwrap_or(false) {
                self.sink.write(&format!("{n}\n"));
            }
        }
    }
}

/// The default matcher used when none is supplied.
pub fn default_match() -> impl Fn(&str, &str) -> Result<bool, String> + Send + Sync + 'static {
    let m = regexp_match();
    move |p, s| m(p, s)
}
