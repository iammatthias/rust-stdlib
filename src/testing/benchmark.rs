//! `B`, `PB`, `BenchmarkResult` and the benchmark runner (Go's
//! `testing/benchmark.go`).

use std::{
    collections::BTreeMap,
    fmt,
    panic::{self, AssertUnwindSafe},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, Once,
    },
    time::{Duration as StdDuration, Instant},
};

use crate::time::Duration;

use super::{
    alloc_stats,
    common::{impl_tb, is_goexit, panic_message, Chatty, Common, CommonSpec, Sink, TestState, TB},
    flags,
    matcher::{MatchFn, Matcher},
    t::{make_tstate, matcher_or_exit, RunEnv},
};

/// A benchmark function: Go's `func(*testing.B)`.
pub type BenchFn = Arc<dyn Fn(&mut B) + Send + Sync + 'static>;

/// Go's `testing.InternalBenchmark`.
#[derive(Clone)]
pub struct InternalBenchmark {
    /// Go's `Name`.
    pub name: String,
    /// Go's `F`.
    pub f: BenchFn,
}

impl InternalBenchmark {
    /// Builds a benchmark from a name and function.
    pub fn new(name: &str, f: impl Fn(&mut B) + Send + Sync + 'static) -> InternalBenchmark {
        InternalBenchmark {
            name: name.to_string(),
            f: Arc::new(f),
        }
    }
}

/// `-test.benchtime`: a duration, or a fixed iteration count (`100x`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurationOrCount {
    /// The target duration, when `n` is zero.
    pub d: Duration,
    /// The fixed iteration count, if positive.
    pub n: usize,
}

impl Default for DurationOrCount {
    fn default() -> Self {
        DurationOrCount {
            d: Duration::from_secs(1),
            n: 0,
        }
    }
}

impl DurationOrCount {
    /// Parses `Nx` or a Go duration; zero is rejected unless `allow_zero`.
    pub fn parse(s: &str, allow_zero: bool) -> Result<DurationOrCount, String> {
        if let Some(num) = s.strip_suffix('x') {
            return match num.parse::<i64>() {
                Ok(n) if n >= 0 && (allow_zero || n != 0) && i32::try_from(n).is_ok() => {
                    Ok(DurationOrCount {
                        d: Duration::ZERO,
                        n: n as usize,
                    })
                }
                _ => Err("invalid count".to_string()),
            };
        }
        match s.parse::<Duration>() {
            Ok(d) if d.nanoseconds() >= 0 && (allow_zero || d.nanoseconds() != 0) => {
                Ok(DurationOrCount { d, n: 0 })
            }
            _ => Err("invalid duration".to_string()),
        }
    }
}

impl fmt::Display for DurationOrCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.n > 0 {
            write!(f, "{}x", self.n)
        } else {
            f.write_str(&self.d.to_string())
        }
    }
}

/// Go's `testing.BenchmarkResult`: the results of a benchmark run.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BenchmarkResult {
    /// The number of iterations (Go's `N`).
    pub n: usize,
    /// The total time taken (Go's `T`).
    pub t: Duration,
    /// Bytes processed in one iteration.
    pub bytes: i64,
    /// The total number of memory allocations.
    pub mem_allocs: u64,
    /// The total number of bytes allocated.
    pub mem_bytes: u64,
    /// Additional metrics reported by [`B::report_metric`].
    pub extra: BTreeMap<String, f64>,
}

impl BenchmarkResult {
    /// The "ns/op" metric.
    pub fn ns_per_op(&self) -> i64 {
        if let Some(v) = self.extra.get("ns/op") {
            return *v as i64;
        }
        if self.n == 0 {
            return 0;
        }
        (self.t.as_nanos()) / self.n as i64
    }

    fn mb_per_sec(&self) -> f64 {
        if let Some(v) = self.extra.get("MB/s") {
            return *v;
        }
        if self.bytes <= 0 || self.t.is_zero() || self.n == 0 {
            return 0.0;
        }
        (self.bytes as f64 * self.n as f64 / 1e6) / self.t.seconds()
    }

    /// The "allocs/op" metric: `mem_allocs / n`.
    pub fn allocs_per_op(&self) -> i64 {
        if let Some(v) = self.extra.get("allocs/op") {
            return *v as i64;
        }
        if self.n == 0 {
            return 0;
        }
        (self.mem_allocs as i64) / self.n as i64
    }

    /// The "B/op" metric: `mem_bytes / n`.
    pub fn alloced_bytes_per_op(&self) -> i64 {
        if let Some(v) = self.extra.get("B/op") {
            return *v as i64;
        }
        if self.n == 0 {
            return 0;
        }
        (self.mem_bytes as i64) / self.n as i64
    }

    /// A summary in the benchmark result line format, not including the
    /// benchmark name (Go's `String`).
    fn render(&self) -> String {
        let mut buf = format!("{:8}", self.n);
        let ns = match self.extra.get("ns/op") {
            Some(v) => *v,
            None => self.t.as_nanos() as f64 / self.n as f64,
        };
        if ns != 0.0 {
            buf.push('\t');
            pretty_print(&mut buf, ns, "ns/op");
        }
        let mbs = self.mb_per_sec();
        if mbs != 0.0 {
            buf.push_str(&format!("\t{} MB/s", fmt_f(mbs, 7, 2)));
        }
        for (k, v) in &self.extra {
            if matches!(k.as_str(), "ns/op" | "MB/s" | "B/op" | "allocs/op") {
                continue;
            }
            buf.push('\t');
            pretty_print(&mut buf, *v, k);
        }
        buf
    }

    /// `alloced_bytes_per_op` and `allocs_per_op` in the format of `go test`.
    pub fn mem_string(&self) -> String {
        format!(
            "{:8} B/op\t{:8} allocs/op",
            self.alloced_bytes_per_op(),
            self.allocs_per_op()
        )
    }
}

impl fmt::Display for BenchmarkResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

/// Go's `%{width}.{prec}f`, including its spelling of infinities and NaN.
fn fmt_f(x: f64, width: usize, prec: usize) -> String {
    if x.is_nan() {
        format!("{:>width$}", "NaN")
    } else if x.is_infinite() {
        format!("{:>width$}", if x > 0.0 { "+Inf" } else { "-Inf" })
    } else {
        format!("{x:width$.prec$}")
    }
}

fn pretty_print(w: &mut String, x: f64, unit: &str) {
    let y = x.abs();
    let (width, prec) = if y == 0.0 || y >= 999.95 {
        (10, 0)
    } else if y >= 99.995 {
        (12, 1)
    } else if y >= 9.9995 {
        (13, 2)
    } else if y >= 0.99995 {
        (14, 3)
    } else if y >= 0.099995 {
        (15, 4)
    } else if y >= 0.0099995 {
        (16, 5)
    } else if y >= 0.00099995 {
        (17, 6)
    } else {
        (18, 7)
    };
    w.push_str(&fmt_f(x, width, prec));
    w.push(' ');
    w.push_str(unit);
}

pub(crate) struct BenchState {
    pub(crate) matcher: Matcher,
    pub(crate) max_len: AtomicUsize,
    pub(crate) ext_len: usize,
}

const LOOP_POISON_TIMER: u64 = 1 << 63;
const LOOP_POISON_MASK: u64 = !((1u64 << 63) - 1);
const MAX_BENCH_PREDICT_ITERS: i64 = 1_000_000_000;

static BENCH_LOCK: Mutex<()> = Mutex::new(());
static LABELS_ONCE: Once = Once::new();

fn procs() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get())
}

fn benchmark_name(name: &str, n: usize) -> String {
    if n != 1 {
        format!("{name}-{n}")
    } else {
        name.to_string()
    }
}

fn goos() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        o => o,
    }
}

fn goarch() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        "x86" => "386",
        a => a,
    }
}

fn cpu_name() -> String {
    std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("model name").map(|r| r.to_string()))
        })
        .and_then(|l| l.split_once(':').map(|(_, v)| v.trim().to_string()))
        .unwrap_or_default()
}

/// Go's `predictN`.
pub(crate) fn predict_n(goalns: i64, prev_iters: i64, prevns: i64, last: i64) -> i64 {
    let prevns = if prevns == 0 { 1 } else { prevns };
    // Multiply first, then divide.
    let mut n = goalns.saturating_mul(prev_iters) / prevns;
    n += n / 5;
    n = n.min(last.saturating_mul(100));
    n = n.max(last + 1);
    n.min(MAX_BENCH_PREDICT_ITERS)
}

struct LoopState {
    n: u64,
    i: u64,
    done: bool,
}

/// Go's `testing.B`: passed to benchmark functions to manage timing and
/// control the number of iterations.
pub struct B {
    pub(crate) c: Common,
    /// The number of iterations the benchmark function should run (Go's `N`).
    pub n: usize,
    import_path: String,
    bstate: Option<Arc<BenchState>>,
    previous_n: usize,
    previous_duration: StdDuration,
    bench_time: DurationOrCount,
    bytes: i64,
    missing_bytes: bool,
    timer_on: bool,
    show_alloc_result: bool,
    result: BenchmarkResult,
    parallelism: usize,
    start: Instant,
    duration: StdDuration,
    start_allocs: u64,
    start_bytes: u64,
    net_allocs: u64,
    net_bytes: u64,
    extra: BTreeMap<String, f64>,
    loop_state: LoopState,
}

impl_tb!(B);

impl B {
    fn new(c: Common, bench_time: DurationOrCount, bstate: Option<Arc<BenchState>>) -> B {
        B {
            import_path: c.import_path.clone(),
            c,
            n: 0,
            bstate,
            previous_n: 0,
            previous_duration: StdDuration::ZERO,
            bench_time,
            bytes: 0,
            missing_bytes: false,
            timer_on: false,
            show_alloc_result: false,
            result: BenchmarkResult::default(),
            parallelism: 1,
            start: Instant::now(),
            duration: StdDuration::ZERO,
            start_allocs: 0,
            start_bytes: 0,
            net_allocs: 0,
            net_bytes: 0,
            extra: BTreeMap::new(),
            loop_state: LoopState {
                n: 0,
                i: 0,
                done: false,
            },
        }
    }

    /// Go's `Cleanup` with a plain closure.
    pub fn cleanup<F: FnOnce() + Send + 'static>(&self, f: F) {
        self.c.cleanup(Box::new(f));
    }

    pub(crate) fn setenv_impl(&self, key: &str, value: &str) {
        self.c.tb_setenv(key, value);
    }

    pub(crate) fn chdir_impl(&self, dir: &str) {
        self.c.tb_chdir(dir);
    }

    /// Starts timing; called automatically before a benchmark starts, and can
    /// resume timing after [`stop_timer`](B::stop_timer).
    pub fn start_timer(&mut self) {
        if !self.timer_on {
            self.start_allocs = alloc_stats::mallocs();
            self.start_bytes = alloc_stats::total_alloc();
            self.start = Instant::now();
            self.timer_on = true;
            self.loop_state.i &= !LOOP_POISON_TIMER;
        }
    }

    /// Stops timing, pausing the clock for steps that should not be measured.
    pub fn stop_timer(&mut self) {
        if self.timer_on {
            self.duration += self.start.elapsed();
            self.net_allocs += alloc_stats::mallocs().wrapping_sub(self.start_allocs);
            self.net_bytes += alloc_stats::total_alloc().wrapping_sub(self.start_bytes);
            self.timer_on = false;
            self.loop_state.i |= LOOP_POISON_TIMER;
        }
    }

    /// Zeroes the elapsed time and allocation counters and deletes
    /// user-reported metrics. It does not affect whether the timer runs.
    pub fn reset_timer(&mut self) {
        self.extra.clear();
        if self.timer_on {
            self.start_allocs = alloc_stats::mallocs();
            self.start_bytes = alloc_stats::total_alloc();
            self.start = Instant::now();
        }
        self.duration = StdDuration::ZERO;
        self.net_allocs = 0;
        self.net_bytes = 0;
    }

    /// Records the number of bytes processed in a single operation.
    pub fn set_bytes(&mut self, n: i64) {
        self.bytes = n;
    }

    /// Enables allocation statistics for this benchmark (like
    /// `-test.benchmem` for one benchmark). Counts come from
    /// [`alloc_stats`](super::alloc_stats): they stay zero unless the program
    /// installs an allocator that calls [`record_alloc`](super::record_alloc).
    pub fn report_allocs(&mut self) {
        self.show_alloc_result = true;
    }

    /// The measured elapsed time of the benchmark.
    pub fn elapsed(&self) -> Duration {
        let mut d = self.duration;
        if self.timer_on {
            d += self.start.elapsed();
        }
        d.into()
    }

    /// Adds "n unit" to the reported results, replacing a previous value for
    /// the same unit.
    ///
    /// # Panics
    ///
    /// If `unit` is empty or contains white space.
    pub fn report_metric(&mut self, n: f64, unit: &str) {
        if unit.is_empty() {
            panic!("metric unit must not be empty");
        }
        if unit.chars().any(char::is_whitespace) {
            panic!("metric unit must not contain whitespace");
        }
        self.extra.insert(unit.to_string(), n);
    }

    /// Sets the number of threads used by [`run_parallel`](B::run_parallel)
    /// to `p` times the available parallelism. Values below 1 are ignored.
    pub fn set_parallelism(&mut self, p: usize) {
        if p >= 1 {
            self.parallelism = p;
        }
    }

    fn run_n(&mut self, n: usize, f: &mut dyn FnMut(&mut B)) {
        self.c.reset_context();
        self.n = n;
        self.loop_state = LoopState {
            n: 0,
            i: 0,
            done: false,
        };
        self.parallelism = 1;
        self.reset_timer();
        self.start_timer();
        let r = panic::catch_unwind(AssertUnwindSafe(|| f(self)));
        match r {
            Ok(()) => self.stop_timer(),
            Err(p) if is_goexit(&*p) => {}
            Err(p) => {
                self.c.fail();
                self.c.log_plain(&format!("panic: {}", panic_message(&*p)));
                self.c.lock().finished = true;
            }
        }
        let cleanup_panic = self.c.run_cleanup();
        if let Some(msg) = cleanup_panic {
            self.c.fail();
            self.c.log_plain(&format!("cleanup panicked with {msg}"));
        }
        self.previous_n = n;
        self.previous_duration = self.duration;
        if self.loop_state.n > 0 && !self.loop_state.done && !self.c.failed() {
            self.c.log_plain(
                "benchmark function returned without B.Loop() == false (break or return in loop?)",
            );
            self.c.fail();
        }
    }

    fn run1(&mut self, f: &mut dyn FnMut(&mut B)) -> bool {
        if let Some(bs) = &self.bstate {
            let n = self.c.name.len() + bs.ext_len + 1;
            if n > bs.max_len.load(Ordering::SeqCst) {
                bs.max_len.store(n + 8, Ordering::SeqCst);
            }
        }
        self.run_n(1, f);
        if self.c.failed() {
            let out = self.c.lock().output.clone();
            self.c
                .sink
                .write(&format!("--- FAIL: {}\n{}", self.c.name, out));
            return false;
        }
        let finished = self.c.lock().finished;
        let has_sub = self.c.has_sub.load(Ordering::SeqCst);
        if has_sub || finished {
            let tag = if self.c.skipped() { "SKIP" } else { "BENCH" };
            let nonempty = !self.c.lock().output.is_empty();
            if self.c.chatty.is_some() && (nonempty || finished) {
                self.trim_output();
                let out = self.c.lock().output.clone();
                self.c
                    .sink
                    .write(&format!("--- {tag}: {}\n{}", self.c.name, out));
            }
            return false;
        }
        true
    }

    fn run_loop(&mut self, f: &mut dyn FnMut(&mut B)) {
        LABELS_ONCE.call_once(|| {
            let mut s = format!("goos: {}\ngoarch: {}\n", goos(), goarch());
            if !self.import_path.is_empty() {
                s.push_str(&format!("pkg: {}\n", self.import_path));
            }
            let cpu = cpu_name();
            if !cpu.is_empty() {
                s.push_str(&format!("cpu: {cpu}\n"));
            }
            self.c.sink.write(&s);
        });
        if self.bstate.is_some() {
            self.process_bench(f);
        } else {
            self.do_bench(f);
        }
    }

    fn do_bench(&mut self, f: &mut dyn FnMut(&mut B)) -> BenchmarkResult {
        self.launch(f);
        self.result.clone()
    }

    fn launch(&mut self, f: &mut dyn FnMut(&mut B)) {
        if self.loop_state.n == 0 {
            if self.bench_time.n > 0 {
                if self.bench_time.n > 1 {
                    self.run_n(self.bench_time.n, f);
                }
            } else {
                let d = self.bench_time.d;
                let mut n: i64 = 1;
                while !self.c.failed() && self.duration < d.to_std() && n < 1_000_000_000 {
                    let last = n;
                    let goalns = d.as_nanos();
                    let prev_iters = self.n as i64;
                    n = predict_n(goalns, prev_iters, self.duration.as_nanos() as i64, last);
                    self.run_n(n as usize, f);
                }
            }
        }
        self.result = BenchmarkResult {
            n: self.n,
            t: self.duration.into(),
            bytes: self.bytes,
            mem_allocs: self.net_allocs,
            mem_bytes: self.net_bytes,
            extra: self.extra.clone(),
        };
    }

    fn process_bench(&mut self, f: &mut dyn FnMut(&mut B)) {
        let bs = self
            .bstate
            .clone()
            .expect("process_bench needs a benchState");
        let cpus = flags().cpu.clone();
        let cpus = if cpus.is_empty() { vec![procs()] } else { cpus };
        let count = flags().count;
        let max_len = bs.max_len.load(Ordering::SeqCst);
        for (i, &p) in cpus.iter().enumerate() {
            for j in 0..count {
                let bench_name = benchmark_name(&self.c.name, p);
                if self.c.chatty.is_none() {
                    self.c.sink.write(&format!("{bench_name:<max_len$}\t"));
                }
                if i > 0 || j > 0 {
                    let c = Common::new(CommonSpec {
                        name: self.c.name.clone(),
                        parent: self.c.parent.clone(),
                        level: self.c.level,
                        chatty: self.c.chatty.clone(),
                        sink: self.c.sink.clone(),
                        bench: true,
                        tstate: self.c.tstate.clone(),
                        module_path: self.c.module_path.clone(),
                        import_path: self.c.import_path.clone(),
                    });
                    *self = B::new(c, self.bench_time, self.bstate.clone());
                    self.run1(f);
                }
                let r = self.do_bench(f);
                if self.c.failed() {
                    let out = self.c.lock().output.clone();
                    self.c.sink.write(&format!("--- FAIL: {bench_name}\n{out}"));
                    continue;
                }
                let mut results = r.to_string();
                if self.c.chatty.is_some() {
                    self.c.sink.write(&format!("{bench_name:<max_len$}\t"));
                }
                if flags().benchmem || self.show_alloc_result {
                    results.push('\t');
                    results.push_str(&r.mem_string());
                }
                self.c.sink.write(&format!("{results}\n"));
                let has_out = !self.c.lock().output.is_empty();
                if has_out {
                    self.trim_output();
                    let out = self.c.lock().output.clone();
                    self.c
                        .sink
                        .write(&format!("--- BENCH: {bench_name}\n{out}"));
                }
            }
        }
    }

    /// Shortens very long benchmark output.
    fn trim_output(&self) {
        const MAX_NEWLINES: usize = 10;
        let mut g = self.c.lock();
        let mut nl = 0;
        let mut cut = None;
        for (j, b) in g.output.bytes().enumerate() {
            if b == b'\n' {
                nl += 1;
                if nl >= MAX_NEWLINES {
                    cut = Some(j);
                    break;
                }
            }
        }
        if let Some(j) = cut {
            g.output.truncate(j);
            g.output.push_str("\n\t... [output truncated]\n");
        }
    }

    /// Simulates running benchmarks in sequence in a single iteration; used
    /// to give meaningful results when [`benchmark`] is combined with
    /// [`run`](B::run).
    fn add(&mut self, other: &BenchmarkResult) {
        let r = &mut self.result;
        r.n = 1;
        r.t += Duration::from_nanos(other.ns_per_op().max(0));
        if other.bytes == 0 {
            self.missing_bytes = true;
            r.bytes = 0;
        }
        if !self.missing_bytes {
            r.bytes += other.bytes;
        }
        r.mem_allocs += other.allocs_per_op().max(0) as u64;
        r.mem_bytes += other.alloced_bytes_per_op().max(0) as u64;
    }

    /// Go's `Run`: benchmarks `f` as a sub-benchmark called `name` and
    /// reports whether there were no failures. A benchmark that calls `run`
    /// is not measured itself and is called once with `n == 1`.
    pub fn run<F: FnMut(&mut B)>(&mut self, name: &str, mut f: F) -> bool {
        self.c.has_sub.store(true, Ordering::SeqCst);
        let (bench_name, ok, partial) = match &self.bstate {
            Some(bs) => bs
                .matcher
                .full_name(Some((&self.c.name, self.c.level)), name),
            None => (self.c.name.clone(), true, false),
        };
        if !ok {
            return true;
        }
        let c = Common::new(CommonSpec {
            name: bench_name.clone(),
            parent: Some(self.c.clone()),
            level: self.c.level + 1,
            chatty: self.c.chatty.clone(),
            sink: self.c.sink.clone(),
            bench: true,
            tstate: self.c.tstate.clone(),
            module_path: self.c.module_path.clone(),
            import_path: self.import_path.clone(),
        });
        let mut sub = B::new(c, self.bench_time, self.bstate.clone());
        if partial {
            sub.c.has_sub.store(true, Ordering::SeqCst);
        }
        if self.c.chatty.is_some() {
            LABELS_ONCE.call_once(|| {
                let mut s = format!("goos: {}\ngoarch: {}\n", goos(), goarch());
                if !self.import_path.is_empty() {
                    s.push_str(&format!("pkg: {}\n", self.import_path));
                }
                let cpu = cpu_name();
                if !cpu.is_empty() {
                    s.push_str(&format!("cpu: {cpu}\n"));
                }
                self.c.sink.write(&s);
            });
            self.c.sink.write(&format!("{bench_name}\n"));
        }
        if sub.run1(&mut f) {
            sub.run_loop(&mut f);
        }
        self.add(&sub.result);
        !sub.c.failed()
    }

    /// Reports whether the benchmark should continue running (Go's `Loop`).
    ///
    /// ```text
    /// while b.loop_() { /* code to measure */ }
    /// ```
    ///
    /// The first call resets the timer so setup is not measured, and the call
    /// that returns false stops it. Afterwards `b.n` holds the iteration count.
    #[track_caller]
    pub fn loop_(&mut self) -> bool {
        if self.loop_state.i < self.loop_state.n {
            self.loop_state.i += 1;
            return true;
        }
        self.loop_slow_path()
    }

    #[track_caller]
    fn loop_slow_path(&mut self) -> bool {
        if !self.timer_on {
            self.c.tb_fatal(&[&"B.Loop called with timer stopped"]);
        }
        if self.loop_state.i & LOOP_POISON_MASK != 0 {
            panic!("unknown loop stop condition: {:#x}", self.loop_state.i);
        }
        if self.loop_state.n == 0 {
            self.loop_state.n = if self.bench_time.n > 0 {
                self.bench_time.n as u64
            } else {
                1
            };
            self.n = 0;
            self.reset_timer();
            self.loop_state.i += 1;
            return true;
        }
        let more = if self.bench_time.n > 0 {
            if self.loop_state.i != self.bench_time.n as u64 {
                panic!(
                    "iteration count {} < fixed target {}",
                    self.loop_state.i, self.bench_time.n
                );
            }
            false
        } else {
            self.stop_or_scale_b_loop()
        };
        if !more {
            self.stop_timer();
            self.n = self.loop_state.n as usize;
            self.loop_state.done = true;
            return false;
        }
        self.loop_state.i += 1;
        true
    }

    fn stop_or_scale_b_loop(&mut self) -> bool {
        let t = self.elapsed();
        if t >= self.bench_time.d {
            return false;
        }
        let goalns = self.bench_time.d.as_nanos();
        let prev_iters = self.loop_state.n as i64;
        self.loop_state.n = predict_n(goalns, prev_iters, t.as_nanos(), prev_iters) as u64;
        if self.loop_state.n & LOOP_POISON_MASK != 0 {
            panic!("loop iteration target overflow");
        }
        (prev_iters as u64) < self.loop_state.n
    }

    /// Go's `RunParallel`: runs `body` in `parallelism * available
    /// parallelism` threads, distributing `n` iterations among them through
    /// [`PB::next`].
    pub fn run_parallel<F: Fn(&mut PB<'_>) + Sync>(&mut self, body: F) {
        if self.n == 0 {
            return;
        }
        let mut grain: u64 = 0;
        if self.previous_n > 0 && !self.previous_duration.is_zero() {
            grain = 100_000 * self.previous_n as u64 / self.previous_duration.as_nanos() as u64;
        }
        grain = grain.clamp(1, 10_000);
        let global = AtomicU64::new(0);
        let num_procs = self.parallelism * procs();
        let bn = self.n as u64;
        std::thread::scope(|s| {
            for _ in 0..num_procs {
                s.spawn(|| {
                    let mut pb = PB {
                        global_n: &global,
                        grain,
                        cache: 0,
                        bn,
                    };
                    let _ = panic::catch_unwind(AssertUnwindSafe(|| body(&mut pb)));
                });
            }
        });
        if global.load(Ordering::SeqCst) <= bn && !self.c.failed() {
            self.c
                .tb_fatal(&[&"RunParallel: body exited without pb.Next() == false"]);
        }
    }
}

/// Go's `testing.PB`: used by [`B::run_parallel`] to run parallel benchmarks.
pub struct PB<'a> {
    global_n: &'a AtomicU64,
    grain: u64,
    cache: u64,
    bn: u64,
}

impl PB<'_> {
    /// Reports whether there are more iterations to execute.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> bool {
        if self.cache == 0 {
            let n = self.global_n.fetch_add(self.grain, Ordering::SeqCst) + self.grain;
            if n <= self.bn {
                self.cache = self.grain;
            } else if n < self.bn + self.grain {
                self.cache = self.bn + self.grain - n;
            } else {
                return false;
            }
        }
        self.cache -= 1;
        true
    }
}

/// Go's `testing.Benchmark`: benchmarks a single function with the
/// `-test.benchtime` budget. If `f` calls [`B::run`], the result
/// estimates running all its sub-benchmarks in sequence in one benchmark.
pub fn benchmark<F: FnMut(&mut B)>(mut f: F) -> BenchmarkResult {
    super::init();
    let _g = BENCH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tstate = Arc::new(TestState::new(1, Matcher::all()));
    let c = Common::new(CommonSpec {
        name: String::new(),
        parent: None,
        level: 0,
        chatty: None,
        sink: Sink::discard(),
        bench: true,
        tstate,
        module_path: String::new(),
        import_path: String::new(),
    });
    let mut b = B::new(c, flags().benchtime, None);
    if b.run1(&mut f) {
        b.run_loop(&mut f);
    }
    b.result
}

/// Go's `runBenchmarks`: returns whether every benchmark succeeded.
pub(crate) fn run_benchmarks_impl(
    env: &RunEnv,
    match_fn: &MatchFn,
    benchmarks: &[InternalBenchmark],
) -> bool {
    let f = flags();
    if f.bench.is_empty() {
        return true;
    }
    let _g = BENCH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let maxprocs = f.cpu.iter().copied().max().unwrap_or_else(procs).max(1);
    let ext_len = benchmark_name("", maxprocs).len();
    let matcher = matcher_or_exit(match_fn.clone(), &f.bench, "-test.bench", &env.skip);
    let mut selected = Vec::new();
    let mut max_len = 0;
    for b in benchmarks {
        let (_, matched, _) = matcher.full_name(None, &b.name);
        if matched {
            selected.push(b.clone());
            let l = benchmark_name(&b.name, maxprocs).len() + ext_len + 1;
            max_len = max_len.max(l);
        }
    }
    let bstate = Arc::new(BenchState {
        matcher,
        max_len: AtomicUsize::new(max_len),
        ext_len,
    });
    let tstate = make_tstate(
        env,
        Matcher::new(match_fn.clone(), "", "", "").expect("empty filter"),
    );
    let c = Common::new(CommonSpec {
        name: "Main".to_string(),
        parent: None,
        level: 0,
        chatty: env.verbose.then(|| Chatty::new(env.sink.clone())),
        sink: env.sink.clone(),
        bench: true,
        tstate,
        module_path: env.module_path.clone(),
        import_path: env.import_path.clone(),
    });
    let mut main = B::new(c, f.benchtime, Some(bstate));
    let mut body = |b: &mut B| {
        for bench in &selected {
            let f = bench.f.clone();
            b.run(&bench.name, move |b| f(b));
        }
    };
    main.run_n(1, &mut body);
    !main.c.failed()
}

/// Go's `testing.RunBenchmarks`: runs the benchmarks matching
/// `-test.bench`, printing results to standard output.
pub fn run_benchmarks(
    match_string: impl Fn(&str, &str) -> Result<bool, String> + Send + Sync + 'static,
    benchmarks: &[InternalBenchmark],
) {
    super::init();
    let env = RunEnv::from_flags(Sink::stdout());
    run_benchmarks_impl(&env, &(Arc::new(match_string) as MatchFn), benchmarks);
}

/// Go's `testing.AllocsPerRun`: the average number of allocations during
/// calls to `f` after one warm-up call. Allocations are counted by
/// [`alloc_stats`](super::alloc_stats); the result is always integral.
pub fn allocs_per_run(runs: usize, mut f: impl FnMut()) -> f64 {
    f();
    let before = alloc_stats::mallocs();
    for _ in 0..runs {
        f();
    }
    let mallocs = alloc_stats::mallocs().wrapping_sub(before);
    (mallocs / runs.max(1) as u64) as f64
}

#[allow(dead_code)]
fn _assert_tb(_: &dyn TB) {}
