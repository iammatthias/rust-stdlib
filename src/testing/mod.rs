//! Go's `testing` package: tests, benchmarks, fuzz seed corpora, examples and
//! the test-binary driver, with Go's report format.
//!
//! The types ([`T`], [`B`], [`F`], [`M`], [`PB`], [`BenchmarkResult`]) and the
//! [`TB`] trait follow Go. They can drive a whole test binary
//! ([`main_start`], [`M::run`]) or be used from inside a Rust `#[test]`:
//!
//! ```
//! use rust_stdlib::testing::{self, TB};
//!
//! fn it_adds() {
//!     testing::run_test("TestAdd", |t| {
//!         for (a, b, want) in [(1, 2, 3), (2, 2, 4)] {
//!             t.run(&format!("{a}+{b}"), |t| {
//!                 if a + b != want {
//!                     t.errorf(format_args!("{a}+{b} = {}, want {want}", a + b));
//!                 }
//!             });
//!         }
//!     });
//! }
//! # it_adds();
//! ```
//!
//! A failed test panics with Go's report (`--- FAIL: TestAdd (0.00s)` with the
//! indented `file.go:12: message` lines). The [`test_fn!`](crate::test_fn)
//! macro wraps this in a `#[test]` function.
//!
//! # Mapping to Rust
//!
//! - `Fatal`, `FailNow`, `Skip` and `SkipNow` unwind with the [`Goexit`]
//!   payload (`resume_unwind`, so no panic message is printed), which the
//!   runner recognises with [`is_goexit`].
//! - `log`/`error`/`fatal`/`skip` take a slice of `&dyn Display` operands and
//!   format them like `fmt.Sprintln`; the `*f` forms take `format_args!`.
//! - Reported locations come from `#[track_caller]`. `Helper` is a marker:
//!   annotate a helper function with `#[track_caller]` and it is skipped in
//!   the reported `file:line`.
//! - [`T::run`] runs the subtest on the calling thread so it can borrow;
//!   [`T::run_static`] runs it on its own thread so [`T::parallel`] can pause it.
//! - Allocation statistics need an allocator that calls [`record_alloc`]
//!   (installing a `GlobalAlloc` takes `unsafe`, which this crate forbids);
//!   without one `allocs/op` and `B/op` are 0.
//! - `Fuzz` runs the seed corpus (see [`F::fuzz`]); coverage-guided fuzzing is
//!   in the `fuzz/` crate of this repository.

use crate::time::Duration;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, RwLock,
    },
};

pub(crate) mod common;
pub mod fstest;
pub mod iotest;
pub mod quick;
pub mod slogtest;
pub mod synctest;

mod benchmark;
mod fuzz;
mod matcher;
mod t;

pub use benchmark::{
    allocs_per_run, benchmark, run_benchmarks, BenchFn, BenchmarkResult, DurationOrCount,
    InternalBenchmark, B, PB,
};
pub use common::{is_goexit, Goexit, OutputWriter, Sink, TB};
pub use fuzz::{
    unmarshal_corpus_file, FuzzArgs, FuzzFn, FuzzType, FuzzValue, InternalFuzzTarget, F,
};
pub use matcher::{regexp_match, MatchFn};
pub use t::{
    default_match, main, main_start, run_examples, run_tests, ExampleFn, InternalExample,
    InternalTest, RegexpDeps, TestDeps, TestFn, M, T,
};

/// Allocation counters read by [`B::report_allocs`], [`benchmark`] and
/// [`allocs_per_run`].
///
/// Go reads `runtime.MemStats`. Rust has no portable counter, and installing
/// a counting `GlobalAlloc` needs `unsafe`, which this crate forbids, so a
/// program (typically a benchmark binary) installs its own allocator that
/// forwards to [`System`](std::alloc::System) and calls [`record_alloc`] from
/// `alloc`. Without one the counters stay 0.
pub mod alloc_stats {
    use std::sync::atomic::{AtomicU64, Ordering};

    static MALLOCS: AtomicU64 = AtomicU64::new(0);
    static TOTAL_ALLOC: AtomicU64 = AtomicU64::new(0);

    /// Records one allocation of `size` bytes (call it from `GlobalAlloc::alloc`).
    pub fn record_alloc(size: usize) {
        MALLOCS.fetch_add(1, Ordering::Relaxed);
        TOTAL_ALLOC.fetch_add(size as u64, Ordering::Relaxed);
    }

    /// The number of allocations recorded so far (`MemStats.Mallocs`).
    pub fn mallocs() -> u64 {
        MALLOCS.load(Ordering::Relaxed)
    }

    /// The bytes allocated so far (`MemStats.TotalAlloc`).
    pub fn total_alloc() -> u64 {
        TOTAL_ALLOC.load(Ordering::Relaxed)
    }
}
pub use alloc_stats::record_alloc;

// ----- flags -----

/// The `-test.*` flags of a test binary.
#[derive(Clone, Debug)]
pub struct Flags {
    /// `-test.short`.
    pub short: bool,
    /// `-test.v`.
    pub verbose: bool,
    /// `-test.failfast`.
    pub failfast: bool,
    /// `-test.benchmem`.
    pub benchmem: bool,
    /// `-test.fullpath`.
    pub fullpath: bool,
    /// `-test.artifacts`.
    pub artifacts: bool,
    /// `-test.count`.
    pub count: u32,
    /// `-test.run`.
    pub run: String,
    /// `-test.skip`.
    pub skip: String,
    /// `-test.list`.
    pub list: String,
    /// `-test.bench`.
    pub bench: String,
    /// `-test.shuffle`.
    pub shuffle: String,
    /// `-test.outputdir`.
    pub outputdir: String,
    /// `-test.fuzz` (parsed; coverage-guided fuzzing is not implemented).
    pub fuzz: String,
    /// `-test.parallel`.
    pub parallel: usize,
    /// `-test.timeout` (`None` for no timeout).
    pub timeout: Option<Duration>,
    /// `-test.benchtime`.
    pub benchtime: DurationOrCount,
    /// `-test.cpu`: the processor counts to run each benchmark with.
    pub cpu: Vec<usize>,
}

impl Default for Flags {
    fn default() -> Self {
        Flags {
            short: false,
            verbose: false,
            failfast: false,
            benchmem: false,
            fullpath: false,
            artifacts: false,
            count: 1,
            run: String::new(),
            skip: String::new(),
            list: String::new(),
            bench: String::new(),
            shuffle: "off".to_string(),
            outputdir: String::new(),
            fuzz: String::new(),
            parallel: std::thread::available_parallelism().map_or(1, |n| n.get()),
            timeout: None,
            benchtime: DurationOrCount::default(),
            cpu: Vec::new(),
        }
    }
}

static FLAGS: RwLock<Option<Flags>> = RwLock::new(None);
static TESTING: AtomicBool = AtomicBool::new(false);
static HAVE_EXAMPLES: AtomicBool = AtomicBool::new(false);

pub(crate) fn flags() -> Flags {
    if let Some(f) = FLAGS.read().unwrap().as_ref() {
        return f.clone();
    }
    init();
    FLAGS.read().unwrap().clone().unwrap_or_default()
}

pub(crate) fn have_examples() -> bool {
    HAVE_EXAMPLES.load(Ordering::SeqCst)
}

pub(crate) fn set_have_examples(v: bool) {
    HAVE_EXAMPLES.store(v, Ordering::SeqCst);
}

fn parse_bool(s: &str) -> Result<bool, String> {
    match s {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => Ok(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" => Ok(false),
        _ => Err(format!("parse error: invalid boolean value {s:?}")),
    }
}

/// Parses `-test.*` flags from `args` (without the program name) into
/// `flags`, like `flag.Parse` over the flags registered by Go's `Init`.
/// Arguments that are not `-test.` flags are ignored, so the Rust test
/// harness's own arguments can be present.
pub fn parse_flags(flags: &mut Flags, args: &[String]) -> Result<(), String> {
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        let Some(body) = a
            .strip_prefix("--test.")
            .or_else(|| a.strip_prefix("-test."))
        else {
            continue;
        };
        let (name, inline) = match body.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (body, None),
        };
        let is_bool = matches!(
            name,
            "v" | "short"
                | "failfast"
                | "benchmem"
                | "fullpath"
                | "artifacts"
                | "paniconexit0"
                | "fuzzworker"
        );
        let value = if is_bool {
            inline.unwrap_or_else(|| "true".to_string())
        } else if let Some(v) = inline {
            v
        } else if i < args.len() {
            i += 1;
            args[i - 1].clone()
        } else {
            return Err(format!("flag needs an argument: -test.{name}"));
        };
        let bad = |what: &str| format!("invalid value {value:?} for flag -test.{name}: {what}");
        match name {
            "v" => {
                flags.verbose = matches!(value.as_str(), "test2json" | "json")
                    || parse_bool(&value).map_err(|e| bad(&e))?
            }
            "short" => flags.short = parse_bool(&value).map_err(|e| bad(&e))?,
            "failfast" => flags.failfast = parse_bool(&value).map_err(|e| bad(&e))?,
            "benchmem" => flags.benchmem = parse_bool(&value).map_err(|e| bad(&e))?,
            "fullpath" => flags.fullpath = parse_bool(&value).map_err(|e| bad(&e))?,
            "artifacts" => flags.artifacts = parse_bool(&value).map_err(|e| bad(&e))?,
            "count" => flags.count = value.parse().map_err(|_| bad("parse error"))?,
            "parallel" => flags.parallel = value.parse().map_err(|_| bad("parse error"))?,
            "run" => flags.run = value,
            "skip" => flags.skip = value,
            "list" => flags.list = value,
            "bench" => flags.bench = value,
            "shuffle" => flags.shuffle = value,
            "outputdir" => flags.outputdir = value,
            "fuzz" => flags.fuzz = value,
            "timeout" => {
                let d = value.parse::<Duration>().map_err(|e| bad(&e.to_string()))?;
                flags.timeout = (d.nanoseconds() > 0).then_some(d);
            }
            "benchtime" => {
                flags.benchtime = DurationOrCount::parse(&value, false).map_err(|e| bad(&e))?
            }
            "cpu" => {
                flags.cpu.clear();
                for v in value.split(',') {
                    let v = v.trim();
                    if v.is_empty() {
                        continue;
                    }
                    match v.parse::<usize>() {
                        Ok(n) if n > 0 => flags.cpu.push(n),
                        _ => return Err(format!("testing: invalid value {v:?} for -test.cpu")),
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Go's `Init`: registers and parses the `-test.*` flags from the process
/// arguments. It is idempotent and called by every entry point, so calling
/// it is only needed before reading the flags with [`short`] or [`verbose`]
/// in code that runs earlier. Invalid flags are reported to stderr and
/// ignored.
pub fn init() {
    TESTING.store(true, Ordering::SeqCst);
    let mut guard = FLAGS.write().unwrap();
    if guard.is_some() {
        return;
    }
    let mut f = Flags::default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = parse_flags(&mut f, &args) {
        eprintln!("{e}");
    }
    *guard = Some(f);
}

/// Replaces the parsed flags (for programs that parse their own command line).
pub fn set_flags(f: Flags) {
    TESTING.store(true, Ordering::SeqCst);
    *FLAGS.write().unwrap() = Some(f);
}

/// Go's `Short`: reports whether `-test.short` is set.
pub fn short() -> bool {
    flags().short
}

/// Go's `Verbose`: reports whether `-test.v` is set.
pub fn verbose() -> bool {
    flags().verbose
}

/// Go's `Testing`: reports whether the program is running tests, that is,
/// whether [`init`] (called by every test entry point) has run.
pub fn testing() -> bool {
    TESTING.load(Ordering::SeqCst)
}

// ----- coverage -----

/// Go's `testing.CoverBlock`: the coverage data for a single basic block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoverBlock {
    /// Line number for block start.
    pub line0: u32,
    /// Column number for block start.
    pub col0: u16,
    /// Line number for block end.
    pub line1: u32,
    /// Column number for block end.
    pub col1: u16,
    /// Number of statements included in this block.
    pub stmts: u16,
}

/// Go's `testing.Cover`: information about test coverage checking.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cover {
    /// Go's `Mode`.
    pub mode: String,
    /// Go's `Counters`.
    pub counters: HashMap<String, Vec<u32>>,
    /// Go's `Blocks`.
    pub blocks: HashMap<String, Vec<CoverBlock>>,
    /// Go's `CoveredPackages`.
    pub covered_packages: String,
}

/// Go's `RegisterCover`: records the coverage data accumulators. Like Go's,
/// it does nothing.
pub fn register_cover(_c: Cover) {}

/// Go's `CoverMode`: the coverage mode of the test binary. Rust's coverage
/// instrumentation (`-C instrument-coverage`) is not visible at run time, so
/// this is always empty, Go's value when coverage is not enabled.
pub fn cover_mode() -> String {
    String::new()
}

/// Go's `Coverage`: the current code coverage as a fraction in `[0, 1]`;
/// always 0 because coverage is not enabled (see [`cover_mode`]).
pub fn coverage() -> f64 {
    0.0
}

// ----- running tests from Rust #[test] functions -----

/// Options for [`run_test_with`].
#[derive(Clone, Default)]
pub struct Options {
    /// Print `=== RUN` lines and passing results, like `-test.v`.
    pub verbose: bool,
    /// Where the report goes; `None` collects it in [`Report::output`].
    pub sink: Option<Arc<Sink>>,
    /// The most tests that run in parallel (`-test.parallel`); 0 uses the flag.
    pub max_parallel: usize,
}

/// The outcome of [`run_test_with`].
#[derive(Clone, Debug)]
pub struct Report {
    /// Whether the test passed (or was skipped).
    pub ok: bool,
    /// Whether the test was skipped.
    pub skipped: bool,
    /// Go's report text for the test (empty when it passed quietly).
    pub output: String,
}

/// Runs `f` as the test `name` with Go's reporting and returns the outcome
/// instead of panicking.
pub fn run_test_with<F: FnOnce(&T)>(opts: &Options, name: &str, f: F) -> Report {
    TESTING.store(true, Ordering::SeqCst);
    let fl = flags();
    let (sink, buf) = match &opts.sink {
        Some(s) => (s.clone(), None),
        None => {
            let (s, b) = Sink::buffer();
            (s, Some(b))
        }
    };
    let env = t::RunEnv {
        sink,
        verbose: opts.verbose,
        run: String::new(),
        skip: String::new(),
        parallel: if opts.max_parallel > 0 {
            opts.max_parallel
        } else {
            fl.parallel
        },
        failfast: false,
        fullpath: fl.fullpath,
        count: 1,
        deadline: fl.timeout.map(|d| std::time::Instant::now() + d.to_std()),
        module_path: String::new(),
        import_path: String::new(),
    };
    let tstate = t::make_tstate(&env, matcher::Matcher::all());
    let root = T::from_common(t::root_common(&env, tstate));
    let slot: Arc<Mutex<Option<common::Common>>> = Arc::new(Mutex::new(None));
    let slot2 = slot.clone();
    t::t_runner(&root, |root| {
        root.run(name, move |t| {
            *slot2.lock().unwrap() = Some(t.c.clone());
            f(t);
        });
    });
    let output = buf.map(|b| b.lock().unwrap().clone()).unwrap_or_default();
    let skipped = slot.lock().unwrap().as_ref().is_some_and(|c| c.skipped());
    Report {
        ok: !root.c.failed(),
        skipped,
        output,
    }
}

/// Runs `f` as the test `name` with Go's reporting, for use inside a Rust
/// `#[test]` function. If the test fails, panics with Go's report
/// (`--- FAIL: name (0.00s)` and the indented log lines); with `-test.v` it
/// prints the verbose report.
pub fn run_test<F: FnOnce(&T)>(name: &str, f: F) {
    let verbose = flags().verbose;
    let report = run_test_with(
        &Options {
            verbose,
            ..Options::default()
        },
        name,
        f,
    );
    if !report.ok {
        panic!("\n{}FAIL", report.output);
    }
    if verbose {
        print!("{}", report.output);
    }
}

/// Defines `#[test]` functions whose bodies receive a [`testing::T`](crate::testing::T)
/// and report in Go's format.
///
/// The expansion is a `#[test]` function, so under `cargo test` each runs as a test:
///
/// ```
/// use rust_stdlib::testing::TB;
///
/// rust_stdlib::test_fn! {
///     fn test_sum(t) {
///         if 1 + 1 != 2 {
///             t.fatal(&[&"arithmetic is broken"]);
///         }
///     }
/// }
/// ```
#[macro_export]
macro_rules! test_fn {
    ($($(#[$meta:meta])* fn $name:ident($t:ident) $body:block)+) => {
        $(
            #[test]
            $(#[$meta])*
            fn $name() {
                $crate::testing::run_test(stringify!($name), |$t: &$crate::testing::T| $body);
            }
        )+
    };
}
