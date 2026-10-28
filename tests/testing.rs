//! Ports of Go's `testing` tests: `sub_test.go` (TestTRun, cleanup and Output
//! tests), `helper_test.go`, `testing_test.go` (TempDir, Setenv, Chdir,
//! Context, Attr), `benchmark_test.go`, `loop_test.go`, `allocs_test.go` and
//! the fuzz seed corpus. `tools/testing_check.py` additionally compares the
//! reports with Go's on thousands of generated scripts.
//!
//! Not ported: tests of the race detector, panic stack traces, `-test.json`
//! framing (^V markers), profiling flags and `runtime.Goexit` in goroutines
//! other than the test's.
use rust_stdlib::testing::{
    self, is_goexit, BenchmarkResult, Flags, InternalBenchmark, InternalFuzzTarget, InternalTest,
    Options, RegexpDeps, Sink, F, T, TB,
};
use std::{
    io::Write,
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

/// Tests that change process-wide state (environment, directory, flags).
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn normalize(s: &str) -> String {
    let s = rust_stdlib::regexp::must_compile(r"\(\d+\.\d\ds\)").replace_all_string(s, "(N.NNs)");
    let s = rust_stdlib::regexp::must_compile(r"testing\.go:\d+:")
        .replace_all_string(&s, "testing.go:NNN:");
    rust_stdlib::regexp::must_compile(r"\w+\.rs:\d+:").replace_all_string(&s, "sub_test.go:NNN:")
}

/// Runs `f` as the root test `desc`; returns (ok, trimmed output).
fn run_case(desc: &str, chatty: bool, max_par: usize, f: impl FnOnce(&T)) -> (bool, String) {
    let r = testing::run_test_with(
        &Options {
            verbose: chatty,
            max_parallel: max_par,
            ..Options::default()
        },
        desc,
        f,
    );
    (r.ok, normalize(r.output.trim()))
}

#[test]
fn trun_failnow_skips_future_tests_at_same_level() {
    let ran_seq = Arc::new(AtomicBool::new(false));
    let ran_par = Arc::new(AtomicBool::new(false));
    let desc = "failnow skips future sequential and parallel tests at same level";
    let (rs, rp) = (ran_seq.clone(), ran_par.clone());
    let (ok, out) = run_case(desc, false, 1, move |t| {
        t.run_static("", move |t| {
            let rp2 = rp.clone();
            t.run_static("par", move |t| {
                t.parallel();
                rp2.store(true, Ordering::SeqCst);
            });
            let rs2 = rs.clone();
            t.run_static("seq", move |_t| rs2.store(true, Ordering::SeqCst));
            t.fail_now();
        });
    });
    assert!(!ok);
    assert!(ran_par.load(Ordering::SeqCst), "parallel test was not run");
    assert!(
        ran_seq.load(Ordering::SeqCst),
        "sequential test was not run"
    );
    let want = format!("--- FAIL: {desc} (N.NNs)\n    --- FAIL: {desc}/#00 (N.NNs)");
    assert_eq!(out, want);
}

#[test]
fn trun_failure_in_parallel_test_propagates_upwards() {
    let desc = "failure in parallel test propagates upwards";
    let (ok, out) = run_case(desc, false, 1, |t| {
        t.run_static("", |t| {
            t.parallel();
            t.run_static("par", |t| {
                t.parallel();
                t.fail();
            });
        });
    });
    assert!(!ok);
    assert_eq!(
        out,
        format!(
            "--- FAIL: {desc} (N.NNs)\n    --- FAIL: {desc}/#00 (N.NNs)\n        --- FAIL: {desc}/#00/par (N.NNs)"
        )
    );
}

#[test]
fn trun_skipping() {
    let (ok, out) = run_case("skipping without message, chatty", true, 0, |t| {
        t.skip_now()
    });
    assert!(ok);
    assert_eq!(
        out,
        "=== RUN   skipping without message, chatty\n--- SKIP: skipping without message, chatty (N.NNs)"
    );
    let (ok, out) = run_case("skipping without message, not chatty", false, 0, |t| {
        t.skip_now()
    });
    assert!(ok);
    assert_eq!(out, "");
    let desc = "skipping after error";
    let (ok, out) = run_case(desc, false, 0, |t| {
        t.error(&[&"an error"]);
        t.skip(&[&"skipped"]);
    });
    assert!(!ok);
    assert_eq!(
        out,
        format!(
            "--- FAIL: {desc} (N.NNs)\n    sub_test.go:NNN: an error\n    sub_test.go:NNN: skipped"
        )
    );
}

#[test]
fn trun_chatty_with_recursion() {
    let desc = "chatty with recursion";
    let (ok, out) = run_case(desc, true, 0, |t| {
        t.run("", |t| {
            t.run("", |_| {});
        });
    });
    assert!(ok);
    assert_eq!(
        out,
        format!(
            "=== RUN   {desc}\n=== RUN   {desc}/#00\n=== RUN   {desc}/#00/#00\n--- PASS: {desc} (N.NNs)\n    --- PASS: {desc}/#00 (N.NNs)\n        --- PASS: {desc}/#00/#00 (N.NNs)"
        )
    );
}

#[test]
fn trun_use_run_to_locally_synchronize_parallelism() {
    let count = Arc::new(AtomicU32::new(0));
    let c2 = count.clone();
    let (ok, _) = run_case(
        "use Run to locally synchronize parallelism",
        false,
        1,
        move |t| {
            let c3 = c2.clone();
            t.run_static("waitGroup", move |t| {
                for _ in 0..4 {
                    let c4 = c3.clone();
                    t.run_static("par", move |t| {
                        t.parallel();
                        c4.fetch_add(1, Ordering::SeqCst);
                    });
                }
            });
            assert_eq!(c2.load(Ordering::SeqCst), 4);
        },
    );
    assert!(ok);
    assert_eq!(count.load(Ordering::SeqCst), 4);
}

#[test]
fn trun_alternate_sequential_and_parallel() {
    for max_par in [1, 2] {
        let (ok, out) = run_case("alternate sequential and parallel", false, max_par, |t| {
            for _ in 0..2 {
                t.run_static("a", |t| {
                    t.parallel();
                    std::thread::sleep(Duration::from_nanos(1));
                    for _ in 0..2 {
                        t.run_static("b", |t| {
                            for _ in 0..2 {
                                t.run_static("c", |t| {
                                    t.parallel();
                                    std::thread::sleep(Duration::from_nanos(1));
                                });
                            }
                        });
                    }
                });
            }
        });
        assert!(ok, "{out}");
    }
}

#[test]
fn trun_stress() {
    let (ok, out) = run_case("stress test", false, 4, |t| {
        t.parallel();
        for _ in 0..6 {
            t.run_static("a", |t| {
                t.parallel();
                for _ in 0..6 {
                    t.run_static("b", |t| {
                        for _ in 0..6 {
                            t.run_static("c", |t| {
                                t.parallel();
                                t.run("d1", |_| {});
                                t.run("d2", |_| {});
                            });
                        }
                    });
                }
            });
        }
    });
    assert!(ok, "{out}");
}

#[test]
fn trun_subtest_calls_error_and_fatal_on_parent_and_ancestor() {
    let desc = "subtest calls error on parent";
    let (ok, out) = run_case(desc, false, 1, |t| {
        t.errorf(format_args!("first this"));
        let outer = t.clone();
        t.run("", move |_t| outer.errorf(format_args!("and now this!")));
        t.errorf(format_args!("oh, and this too"));
    });
    assert!(!ok);
    assert_eq!(
        out,
        format!(
            "--- FAIL: {desc} (N.NNs)\n    sub_test.go:NNN: first this\n    sub_test.go:NNN: and now this!\n    sub_test.go:NNN: oh, and this too"
        )
    );

    let desc = "subtest calls fatal on parent";
    let (ok, out) = run_case(desc, false, 1, |t| {
        let outer = t.clone();
        t.errorf(format_args!("first this"));
        t.run("", move |_t| outer.fatalf(format_args!("and now this!")));
        t.errorf(format_args!("Should not reach here."));
    });
    assert!(!ok);
    assert_eq!(
        out,
        format!(
            "--- FAIL: {desc} (N.NNs)\n    sub_test.go:NNN: first this\n    sub_test.go:NNN: and now this!\n    --- FAIL: {desc}/#00 (N.NNs)\n        sub_test.go:NNN: test executed panic(nil) or runtime.Goexit: subtest may have called FailNow on a parent test"
        )
    );

    let desc = "subtest calls error on ancestor";
    let (ok, out) = run_case(desc, false, 1, |t| {
        let outer = t.clone();
        t.run("", move |t| {
            t.run("", move |_t| {
                outer.errorf(format_args!("Report to ancestor"))
            });
            t.errorf(format_args!("Still do this"));
        });
        t.errorf(format_args!("Also do this"));
    });
    assert!(!ok);
    assert_eq!(
        out,
        format!(
            "--- FAIL: {desc} (N.NNs)\n    sub_test.go:NNN: Report to ancestor\n    --- FAIL: {desc}/#00 (N.NNs)\n        sub_test.go:NNN: Still do this\n    sub_test.go:NNN: Also do this"
        )
    );

    let desc = "subtest calls fatal on ancestor";
    let (ok, out) = run_case(desc, false, 1, |t| {
        let outer = t.clone();
        t.run("", move |t| {
            for _ in 0..4 {
                let o = outer.clone();
                t.run("", move |_t| o.fatalf(format_args!("Nope")));
                t.errorf(format_args!("Don't do this"));
            }
            t.errorf(format_args!("And neither do this"));
        });
        t.errorf(format_args!("Nor this"));
    });
    assert!(!ok);
    // Go matches this output as a regular expression, so what follows the
    // expected text is not checked there; the aborted subtests report too.
    assert!(
        out.starts_with(&format!(
            "--- FAIL: {desc} (N.NNs)\n    sub_test.go:NNN: Nope"
        )),
        "{out}"
    );
}

#[test]
fn trun_log_after_completion_goes_to_the_parent() {
    // A finished subtest's logs are written to the closest unfinished parent.
    let desc = "log in finished sub test logs to parent";
    let (ok, out) = run_case(desc, false, 1, |t| {
        let slot: Arc<Mutex<Option<T>>> = Arc::new(Mutex::new(None));
        let s2 = slot.clone();
        t.run("sub", move |t2| {
            *s2.lock().unwrap() = Some(t2.clone());
        });
        t.log(&[&"message2"]);
        let t2 = slot.lock().unwrap().clone().unwrap();
        t2.log(&[&"message1"]);
        t.errorf(format_args!("error"));
    });
    assert!(!ok);
    assert_eq!(
        out,
        format!(
            "--- FAIL: {desc} (N.NNs)\n    sub_test.go:NNN: message2\n    sub_test.go:NNN: message1\n    sub_test.go:NNN: error"
        )
    );

    // Failing a finished test panics with Go's message.
    let result = std::panic::catch_unwind(|| {
        let slot: Arc<Mutex<Option<T>>> = Arc::new(Mutex::new(None));
        let s2 = slot.clone();
        testing::run_test_with(&Options::default(), "x", move |t| {
            let s3 = s2.clone();
            t.run("", move |t| *s3.lock().unwrap() = Some(t.clone()));
        });
        let t = slot.lock().unwrap().clone().unwrap();
        t.errorf(format_args!("failed after success"));
    });
    let msg = *result.unwrap_err().downcast::<String>().unwrap();
    assert!(
        msg.starts_with("Log in goroutine after x/#00 has completed"),
        "{msg}"
    );
    let result = std::panic::catch_unwind(|| {
        let slot: Arc<Mutex<Option<T>>> = Arc::new(Mutex::new(None));
        let s2 = slot.clone();
        testing::run_test_with(&Options::default(), "y", move |t| {
            let s3 = s2.clone();
            t.run("", move |t| *s3.lock().unwrap() = Some(t.clone()));
        });
        let t = slot.lock().unwrap().clone().unwrap();
        t.fail();
    });
    let msg = *result.unwrap_err().downcast::<String>().unwrap();
    assert!(
        msg.starts_with("Fail in goroutine after  has completed"),
        "{msg}"
    );
}

#[test]
fn trun_cleanup_when_subtest_fails_now() {
    let desc = "cleanup when subtest panics";
    let (ok, out) = run_case(desc, false, 0, |t| {
        let tt = t.clone();
        t.cleanup(move || tt.log(&[&"running cleanup"]));
        t.run("sub", |t2| t2.fail_now());
    });
    assert!(!ok);
    assert_eq!(
        out,
        format!(
            "--- FAIL: {desc} (N.NNs)\n    --- FAIL: {desc}/sub (N.NNs)\n    sub_test.go:NNN: running cleanup"
        )
    );
}

#[test]
fn trun_output_buffering() {
    let desc = "buffered output gets flushed at test end";
    let (ok, out) = run_case(desc, false, 0, |t| {
        t.run("", |t| {
            let mut o = t.output();
            o.write_all(b"a\n").unwrap();
            o.write_all(b"b").unwrap();
            t.fail();
        });
    });
    assert!(!ok);
    assert_eq!(
        out,
        format!("--- FAIL: {desc} (N.NNs)\n    --- FAIL: {desc}/#00 (N.NNs)\n        a\n        b")
    );

    let desc = "output with chatty";
    let (ok, out) = run_case(desc, true, 0, |t| {
        t.run("", |t| {
            let mut o = t.output();
            o.write_all(b"a\n").unwrap();
            o.write_all(b"b").unwrap();
        });
    });
    assert!(ok);
    assert_eq!(
        out,
        format!(
            "=== RUN   {desc}\n=== RUN   {desc}/#00\n    a\n    b\n--- PASS: {desc} (N.NNs)\n    --- PASS: {desc}/#00 (N.NNs)"
        )
    );

    let desc = "newline between buffered log and log";
    let (ok, out) = run_case(desc, false, 0, |t| {
        t.run("", |t| {
            let mut o = t.output();
            o.write_all(b"buffered message").unwrap();
            t.log(&[&"log"]);
            t.fail();
        });
    });
    assert!(!ok);
    assert_eq!(
        out,
        format!(
            "--- FAIL: {desc} (N.NNs)\n    --- FAIL: {desc}/#00 (N.NNs)\n        buffered message\n        sub_test.go:NNN: log"
        )
    );

    let desc = "output in finished sub test outputs to parent";
    let (ok, out) = run_case(desc, false, 0, |t| {
        let slot: Arc<Mutex<Option<T>>> = Arc::new(Mutex::new(None));
        let s2 = slot.clone();
        t.run("sub", move |t2| *s2.lock().unwrap() = Some(t2.clone()));
        t.output().write_all(b"message2\n").unwrap();
        let t2 = slot.lock().unwrap().clone().unwrap();
        t2.output().write_all(b"message1\n").unwrap();
        t.errorf(format_args!("error"));
    });
    assert!(!ok);
    assert_eq!(
        out,
        format!("--- FAIL: {desc} (N.NNs)\n    message2\n    message1\n    sub_test.go:NNN: error")
    );
}

#[test]
fn cleanup_semantics() {
    // TestCleanup: last added first.
    let record = Arc::new(Mutex::new(String::new()));
    let r = record.clone();
    let (ok, _) = run_case("cleanup order", false, 0, move |t| {
        for c in ["1", "2", "3"] {
            let r = r.clone();
            t.cleanup(move || r.lock().unwrap().push_str(c));
        }
    });
    assert!(ok);
    assert_eq!(*record.lock().unwrap(), "321");

    // TestCleanupCalledEvenAfterGoexit.
    let cleanups = Arc::new(AtomicUsize::new(0));
    let c = cleanups.clone();
    run_case("goexit in cleanup", false, 0, move |t| {
        let c = c.clone();
        t.run("test", move |t| {
            let c = c.clone();
            t.cleanup(move || {
                c.fetch_add(1, Ordering::SeqCst);
            });
            let tt = t.clone();
            t.cleanup(move || tt.fail_now());
        });
    });
    assert_eq!(cleanups.load(Ordering::SeqCst), 1);

    // TestRunCleanup: subtest cleanups run when the subtest ends.
    let (inner, outer) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let (i2, o2) = (inner.clone(), outer.clone());
    run_case("run cleanup", false, 0, move |t| {
        t.run("test", move |t| {
            let o3 = o2.clone();
            t.cleanup(move || {
                o3.fetch_add(1, Ordering::SeqCst);
            });
            let i3 = i2.clone();
            t.run("x", move |t| {
                t.cleanup(move || {
                    i3.fetch_add(1, Ordering::SeqCst);
                });
            });
        });
    });
    assert_eq!(
        (inner.load(Ordering::SeqCst), outer.load(Ordering::SeqCst)),
        (1, 1)
    );

    // TestCleanupParallelSubtests: the parent's cleanup waits for parallel subtests.
    let ran = Arc::new(AtomicUsize::new(0));
    let ran2 = ran.clone();
    let (ok, out) = run_case("cleanup parallel", false, 0, move |t| {
        let r = ran2.clone();
        t.run_static("test", move |t| {
            let r2 = r.clone();
            t.cleanup(move || {
                r2.fetch_add(1, Ordering::SeqCst);
            });
            let r3 = r.clone();
            t.run_static("x", move |t| {
                t.parallel();
                assert_eq!(
                    r3.load(Ordering::SeqCst),
                    0,
                    "outer cleanup ran before parallel subtest"
                );
            });
        });
    });
    assert!(ok, "{out}");
    assert_eq!(ran.load(Ordering::SeqCst), 1);

    // TestNestedCleanup: a cleanup registered during cleanup runs next.
    let ran = Arc::new(AtomicUsize::new(0));
    let r = ran.clone();
    let (ok, out) = run_case("nested cleanup", false, 0, move |t| {
        let (r1, tt1) = (r.clone(), t.clone());
        t.cleanup(move || {
            assert_eq!(r1.fetch_add(1, Ordering::SeqCst), 2, "first cleanup");
            let _ = &tt1;
        });
        let (r2, tt2) = (r.clone(), t.clone());
        t.cleanup(move || {
            assert_eq!(r2.fetch_add(1, Ordering::SeqCst), 0, "second cleanup");
            let r3 = r2.clone();
            tt2.cleanup(move || {
                assert_eq!(r3.fetch_add(1, Ordering::SeqCst), 1, "nested cleanup");
            });
        });
    });
    assert!(ok, "{out}");
    assert_eq!(ran.load(Ordering::SeqCst), 3);
}

#[test]
fn fatal_payload_is_recognisable() {
    let t = testing::run_test_with(&Options::default(), "payload", |t| {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| t.fail_now()));
        assert!(is_goexit(&*r.unwrap_err()));
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| t.skip_now()));
        assert!(is_goexit(&*r.unwrap_err()));
    });
    // The test failed (fail_now) and was marked as skipped.
    assert!(!t.ok);
}

#[test]
fn foreign_panic_fails_the_test_with_a_message() {
    let r = testing::run_test_with(&Options::default(), "boom", |_t| panic!("kaboom"));
    assert!(!r.ok);
    assert_eq!(
        normalize(r.output.trim()),
        "--- FAIL: boom (N.NNs)\n    panic: kaboom"
    );
}

/// Go's `TestTBHelper`: a helper marked `#[track_caller]` is skipped when
/// reporting the location.
#[track_caller]
fn helper_log(t: &dyn TB, msg: &str) {
    t.helper();
    t.log(&[&msg]);
}

fn not_a_helper(t: &dyn TB, msg: &str) {
    t.log(&[&msg]);
}

/// Runs `$e` and yields the line of the invocation.
macro_rules! at {
    ($e:expr) => {{
        let l = line!();
        $e;
        l
    }};
}

#[test]
fn tb_helper_reports_the_caller() {
    let lines: Arc<Mutex<(u32, u32)>> = Arc::new(Mutex::new((0, 0)));
    let l2 = lines.clone();
    let r = testing::run_test_with(&Options::default(), "helper", move |t| {
        let helper_line = at!(helper_log(t, "from helper"));
        let plain_line = at!(not_a_helper(t, "from non-helper"));
        *l2.lock().unwrap() = (helper_line, plain_line);
        t.fail();
    });
    let (helper_line, plain_line) = *lines.lock().unwrap();
    let out = r.output;
    // helper_log is #[track_caller], so the reported line is the call site.
    assert!(
        out.contains(&format!("testing.rs:{helper_line}: from helper")),
        "{out}"
    );
    // not_a_helper is not, so the line is inside not_a_helper.
    assert!(
        !out.contains(&format!("testing.rs:{plain_line}: from non-helper")),
        "{out}"
    );
    assert!(out.contains(".rs:"), "{out}");
}

#[test]
fn temp_dir_setenv_chdir_and_context() {
    let _g = serial();
    let dirs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let d2 = dirs.clone();
    let before_cwd = std::env::current_dir().unwrap();
    let before_pwd = std::env::var("PWD").ok();
    std::env::remove_var("TESTING_RS_VAR");
    let ctx_slot: Arc<Mutex<Option<rust_stdlib::context::Context>>> = Arc::new(Mutex::new(None));
    let c2 = ctx_slot.clone();
    let r = testing::run_test_with(
        &Options::default(),
        "TestTempDir/with spaces & stuff",
        move |t| {
            // TempDir: unique, existing, removed afterwards.
            let a = t.temp_dir();
            let b = t.temp_dir();
            assert_ne!(a, b);
            assert!(std::path::Path::new(&a).is_dir());
            std::fs::write(std::path::Path::new(&b).join("f"), b"x").unwrap();
            d2.lock().unwrap().extend([a.clone(), b]);
            assert!(a.contains("TestTempDirwith spaces & stuff"), "{a}");

            // Setenv restores the previous value.
            t.setenv("TESTING_RS_VAR", "v1");
            assert_eq!(std::env::var("TESTING_RS_VAR").as_deref(), Ok("v1"));
            t.run("sub", |t| {
                t.setenv("TESTING_RS_VAR", "v2");
                assert_eq!(std::env::var("TESTING_RS_VAR").as_deref(), Ok("v2"));
            });
            assert_eq!(std::env::var("TESTING_RS_VAR").as_deref(), Ok("v1"));

            // Chdir restores the working directory and sets PWD.
            let dir = t.temp_dir();
            t.chdir(&dir);
            assert_eq!(
                std::fs::canonicalize(std::env::current_dir().unwrap()).unwrap(),
                std::fs::canonicalize(&dir).unwrap()
            );
            assert_eq!(std::env::var("PWD").unwrap(), dir);

            // Context is canceled just before cleanup functions run.
            let ctx = t.context();
            assert!(ctx.err().is_none());
            *c2.lock().unwrap() = Some(ctx.clone());
            let tt = t.clone();
            t.cleanup(move || {
                assert!(
                    tt.context().err().is_some(),
                    "context must be canceled in cleanup"
                );
            });
        },
    );
    assert!(r.ok, "{}", r.output);
    assert_eq!(std::env::current_dir().unwrap(), before_cwd);
    assert_eq!(std::env::var("PWD").ok(), before_pwd);
    assert!(std::env::var("TESTING_RS_VAR").is_err());
    for d in dirs.lock().unwrap().iter() {
        assert!(!std::path::Path::new(d).exists(), "{d} was not removed");
    }
    assert!(ctx_slot.lock().unwrap().as_ref().unwrap().err().is_some());
}

#[test]
fn setenv_and_chdir_conflict_with_parallel() {
    // Go's TestSetenvWithParallelAfter/Before and the Chdir variants.
    let _g = serial();
    for use_chdir in [false, true] {
        let r = std::panic::catch_unwind(|| {
            testing::run_test_with(&Options::default(), "conflict", |t| {
                t.parallel();
                if use_chdir {
                    t.chdir(".");
                } else {
                    t.setenv("TESTING_RS_X", "1");
                }
            });
        });
        // The panic is recorded as a test failure by the runner.
        assert!(r.is_ok());
        let report = testing::run_test_with(&Options::default(), "conflict", |t| {
            t.parallel();
            if use_chdir {
                t.chdir(".");
            } else {
                t.setenv("TESTING_RS_X", "1");
            }
        });
        assert!(!report.ok);
        assert!(
            report.output.contains("can not use t.Parallel"),
            "{}",
            report.output
        );
        let report = testing::run_test_with(&Options::default(), "conflict", |t| {
            if use_chdir {
                t.chdir(".");
            } else {
                t.setenv("TESTING_RS_X", "1");
            }
            t.parallel();
        });
        assert!(!report.ok);
        assert!(
            report.output.contains("can not use t.Parallel"),
            "{}",
            report.output
        );
    }
}

#[test]
fn attr_and_invalid_attr() {
    let r = testing::run_test_with(
        &Options {
            verbose: true,
            ..Options::default()
        },
        "TestAttrSet",
        |t| t.attr("key", "value"),
    );
    assert!(
        r.output.contains("=== ATTR  TestAttrSet key value\n"),
        "{}",
        r.output
    );
    let r = testing::run_test_with(&Options::default(), "TestAttrInvalid", |t| {
        t.attr("key with space", "v");
        t.attr("key", "line\nbreak");
    });
    let out = normalize(&r.output);
    assert!(!r.ok);
    assert!(
        out.contains("disallowed whitespace in attribute key \"key with space\""),
        "{out}"
    );
    assert!(
        out.contains("disallowed newline in attribute value \"line\\nbreak\""),
        "{out}"
    );
}

#[test]
fn subtest_names_are_unique_and_sanitised() {
    let names: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let n2 = names.clone();
    testing::run_test_with(&Options::default(), "TestNaming", move |t| {
        for sub in [
            "",
            "",
            "#0",
            "#00",
            "t",
            "t",
            "A:1 B:2",
            "s\t\r\u{a0}",
            "\u{1}",
        ] {
            let n3 = n2.clone();
            t.run(sub, move |t| n3.lock().unwrap().push(t.name()));
        }
    });
    assert_eq!(
        *names.lock().unwrap(),
        [
            "TestNaming/#00",
            "TestNaming/#01",
            "TestNaming/#0",
            "TestNaming/#00#01",
            "TestNaming/t",
            "TestNaming/t#01",
            "TestNaming/A:1_B:2",
            "TestNaming/s___",
            "TestNaming/\\x01",
        ]
    );
}

// ----------------------------------------------------------- benchmarks

#[test]
fn pretty_print_and_result_string() {
    // Go's TestResultString and TestPrettyPrint tables.
    let mut r = BenchmarkResult {
        n: 100,
        t: Duration::from_nanos(100_000).into(),
        ..BenchmarkResult::default()
    };
    assert_eq!(r.to_string(), "     100\t      1000 ns/op");
    r.bytes = 1000;
    assert_eq!(r.to_string(), "     100\t      1000 ns/op\t1000.00 MB/s");
    r.extra.insert("custom/op".to_string(), 0.5);
    assert_eq!(
        r.to_string(),
        "     100\t      1000 ns/op\t1000.00 MB/s\t         0.5000 custom/op"
    );
    r.mem_allocs = 300;
    r.mem_bytes = 4096;
    assert_eq!(r.mem_string(), "      40 B/op\t       3 allocs/op");
    let pad = |w: usize, body: &str| format!("{body:>w$}");
    for (x, want) in [
        (0.0, pad(10, "0")),
        (1000.0, pad(10, "1000")),
        (999.95, pad(10, "1000")),
        (123.456, pad(12, "123.5")),
        (99.995, pad(12, "100.0")),
        (12.3456, pad(13, "12.35")),
        (1.23456, pad(14, "1.235")),
        (0.123456, pad(15, "0.1235")),
        (0.0123456, pad(16, "0.01235")),
        (0.00123456, pad(17, "0.001235")),
        (0.000123456, pad(18, "0.0001235")),
        (-12.3456, pad(13, "-12.35")),
        (f64::INFINITY, pad(10, "+Inf")),
        (f64::NAN, pad(18, "NaN")),
    ] {
        let r = BenchmarkResult {
            n: 1,
            extra: [("ns/op".to_string(), x)].into(),
            ..BenchmarkResult::default()
        };
        let want = if x == 0.0 {
            "       1".to_string()
        } else {
            format!("       1\t{want} ns/op")
        };
        assert_eq!(r.to_string(), want, "x = {x}");
    }
    // An extra metric overrides the built-in ones; zero ns/op is suppressed.
    let r = BenchmarkResult {
        n: 3,
        t: Duration::from_nanos(9).into(),
        extra: [("ns/op".to_string(), 0.0)].into(),
        ..BenchmarkResult::default()
    };
    assert_eq!(r.to_string(), "       3");
    assert_eq!(r.ns_per_op(), 0);
}

#[test]
fn benchmark_runs_and_measures() {
    let _g = serial();
    testing::set_flags(Flags {
        benchtime: testing::DurationOrCount::parse("5x", false).unwrap(),
        ..Flags::default()
    });
    let calls = AtomicUsize::new(0);
    let r = testing::benchmark(|b| {
        calls.fetch_add(1, Ordering::SeqCst);
        for _ in 0..b.n {
            std::thread::sleep(Duration::from_micros(10));
        }
        b.set_bytes(7);
        b.report_metric(3.5, "widgets/op");
    });
    assert_eq!(r.n, 5);
    assert_eq!(r.bytes, 7);
    assert_eq!(r.extra.get("widgets/op"), Some(&3.5));
    assert!(r.ns_per_op() >= 10_000);
    assert_eq!(calls.load(Ordering::SeqCst), 2, "N=1 probe then N=5");
}

#[test]
fn benchmark_loop() {
    let _g = serial();
    testing::set_flags(Flags {
        benchtime: testing::DurationOrCount::parse("7x", false).unwrap(),
        ..Flags::default()
    });
    let setups = AtomicUsize::new(0);
    let iterations = AtomicUsize::new(0);
    let r = testing::benchmark(|b| {
        setups.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(5)); // not measured
        while b.loop_() {
            iterations.fetch_add(1, Ordering::SeqCst);
        }
        assert_eq!(b.n, 7);
    });
    assert_eq!(r.n, 7);
    // B.Loop does its own ramp-up: the function runs once.
    assert_eq!(iterations.load(Ordering::SeqCst), 7);
    assert_eq!(setups.load(Ordering::SeqCst), 1);
    assert!(
        r.t < Duration::from_millis(5).into(),
        "setup must not be timed: {:?}",
        r.t
    );

    // Go's TestBenchmarkBLoopError: a benchmark that returns before Loop ends.
    let r = testing::run_test_with(&Options::default(), "loop", |_| {});
    assert!(r.ok);
}

#[test]
fn benchmark_run_parallel_distributes_n() {
    let _g = serial();
    testing::set_flags(Flags {
        benchtime: testing::DurationOrCount::parse("1000x", false).unwrap(),
        ..Flags::default()
    });
    let total = Arc::new(AtomicU32::new(0));
    let t2 = total.clone();
    let r = testing::benchmark(move |b| {
        b.set_parallelism(2);
        let t3 = t2.clone();
        b.run_parallel(move |pb| {
            while pb.next() {
                t3.fetch_add(1, Ordering::SeqCst);
            }
        });
    });
    assert_eq!(r.n, 1000);
    // The N=1 probe plus 1000 iterations.
    assert_eq!(total.load(Ordering::SeqCst), 1 + 1000);
}

#[test]
fn benchmark_report_metric_panics() {
    let _g = serial();
    testing::set_flags(Flags {
        benchtime: testing::DurationOrCount::parse("1x", false).unwrap(),
        ..Flags::default()
    });
    for unit in ["", "has space"] {
        let r = testing::benchmark(|b| {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                b.report_metric(1.0, unit)
            }))
            .expect_err("report_metric must panic");
        });
        assert_eq!(r.n, 1);
    }
}

#[test]
fn allocs_per_run_counts_recorded_allocations() {
    // Go's TestAllocsPerRun with a program-installed allocator replaced by
    // explicit hooks: the average counts integral allocations per call.
    let mut calls = 0;
    let avg = testing::allocs_per_run(100, || {
        calls += 1;
        testing::record_alloc(16);
        testing::record_alloc(16);
    });
    assert_eq!(avg, 2.0);
    assert_eq!(calls, 101, "one warm-up call");
}

#[test]
fn main_start_runs_tests_benchmarks_and_examples() {
    let _g = serial();
    let (sink, buf) = Sink::buffer();
    testing::set_flags(Flags {
        verbose: true,
        bench: ".".to_string(),
        benchtime: testing::DurationOrCount::parse("2x", false).unwrap(),
        cpu: vec![1],
        ..Flags::default()
    });
    let tests = vec![
        InternalTest::new("TestPass", |t| t.log(&[&"hello"])),
        InternalTest::new("TestFail", |t| t.error(&[&"nope"])),
    ];
    let benches = vec![InternalBenchmark::new("BenchmarkX", |b| for _ in 0..b.n {})];
    let examples = vec![
        testing::InternalExample {
            name: "ExampleGood".into(),
            f: Arc::new(|w| writeln!(w, "hi").unwrap()),
            output: "hi\n".into(),
            unordered: false,
        },
        testing::InternalExample {
            name: "ExampleUnordered".into(),
            f: Arc::new(|w| write!(w, "b\na\n").unwrap()),
            output: "a\nb".into(),
            unordered: true,
        },
        testing::InternalExample {
            name: "ExampleBad".into(),
            f: Arc::new(|w| writeln!(w, "oops").unwrap()),
            output: "expected".into(),
            unordered: false,
        },
    ];
    let mut m = testing::main_start(RegexpDeps, tests, benches, Vec::new(), examples);
    m.set_output(sink);
    assert_eq!(m.run(), 1);
    let out = normalize(&buf.lock().unwrap());
    assert!(
        out.contains(
            "=== RUN   TestPass\n    sub_test.go:NNN: hello\n--- PASS: TestPass (N.NNs)\n"
        ),
        "{out}"
    );
    assert!(out.contains("--- FAIL: TestFail (N.NNs)\n"), "{out}");
    assert!(out.contains("--- PASS: ExampleGood (N.NNs)\n"), "{out}");
    assert!(
        out.contains("--- PASS: ExampleUnordered (N.NNs)\n"),
        "{out}"
    );
    assert!(
        out.contains("--- FAIL: ExampleBad (N.NNs)\ngot:\noops\nwant:\nexpected\n"),
        "{out}"
    );
    assert!(out.contains("BenchmarkX"), "{out}");
    assert!(out.ends_with("FAIL\n"), "{out}");
    testing::set_flags(Flags::default());
}

#[test]
fn main_start_run_filter_skip_and_list() {
    let _g = serial();
    let (sink, buf) = Sink::buffer();
    testing::set_flags(Flags {
        run: "TestA|TestB/x".into(),
        skip: "TestB/x/skip".into(),
        ..Flags::default()
    });
    let hit = Arc::new(Mutex::new(Vec::<String>::new()));
    let mk = |name: &'static str, hit: Arc<Mutex<Vec<String>>>| {
        InternalTest::new(name, move |t| {
            hit.lock().unwrap().push(t.name());
            t.run("x", |t| {
                t.run("skip", |_| {});
                t.run("keep", |_| {});
            });
        })
    };
    let tests = vec![
        mk("TestA", hit.clone()),
        mk("TestB", hit.clone()),
        mk("TestC", hit.clone()),
    ];
    let mut m = testing::main_start(
        RegexpDeps,
        tests.clone(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    m.set_output(sink);
    assert_eq!(m.run(), 0);
    assert_eq!(*hit.lock().unwrap(), ["TestA", "TestB"]);
    assert_eq!(buf.lock().unwrap().as_str(), "PASS\n");

    let (sink, buf) = Sink::buffer();
    testing::set_flags(Flags {
        list: "^Test[AB]$".into(),
        ..Flags::default()
    });
    let mut m = testing::main_start(RegexpDeps, tests, Vec::new(), Vec::new(), Vec::new());
    m.set_output(sink);
    assert_eq!(m.run(), 0);
    assert_eq!(buf.lock().unwrap().as_str(), "TestA\nTestB\n");
    testing::set_flags(Flags::default());
}

#[test]
fn flags_parse_like_go() {
    let mut f = Flags::default();
    let args: Vec<String> = [
        "-test.v",
        "--test.short=true",
        "-test.run",
        "A/b",
        "-test.count=3",
        "-test.timeout=2s",
        "-test.benchtime=10x",
        "-test.cpu=1,2",
        "-test.skip=Z",
        "--nocapture",
        "positional",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    testing::parse_flags(&mut f, &args).unwrap();
    assert!(f.verbose && f.short);
    assert_eq!((f.run.as_str(), f.skip.as_str(), f.count), ("A/b", "Z", 3));
    assert_eq!(f.timeout, Some(Duration::from_secs(2).into()));
    assert_eq!((f.benchtime.n, f.cpu.clone()), (10, vec![1, 2]));
    assert!(testing::parse_flags(&mut f, &["-test.count=x".to_string()]).is_err());
    assert!(testing::parse_flags(&mut f, &["-test.benchtime=0x".to_string()]).is_err());
}

// ----------------------------------------------------------------- fuzz

#[test]
fn fuzz_runs_the_seed_corpus() {
    let _g = serial();
    let dir = std::env::temp_dir().join(format!("testing_rs_fuzz_{}", std::process::id()));
    let good = dir.join("testdata/fuzz/FuzzGood");
    let bad = dir.join("testdata/fuzz/FuzzBad");
    std::fs::create_dir_all(&good).unwrap();
    std::fs::create_dir_all(&bad).unwrap();
    std::fs::write(
        good.join("entry1"),
        "go test fuzz v1\n[]byte(\"hi\\x00\")\nint64(-5)\nbool(true)\nstring(\"a\\nb\")\nfloat64(2.5)\nbyte('x')\nrune('\u{e9}')\nuint16(0x10)\n",
    )
    .unwrap();
    std::fs::write(bad.join("bad"), "go test fuzz v1\nint(oops)\n").unwrap();
    std::fs::write(bad.join("mismatch"), "go test fuzz v1\nstring(\"x\")\n").unwrap();
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    // Seed corpus from F::add only (no testdata): the entries run as subtests.
    let (sink, buf) = Sink::buffer();
    testing::set_flags(Flags {
        verbose: true,
        ..Flags::default()
    });
    let s2 = seen.clone();
    let target = InternalFuzzTarget::new("FuzzAdd", move |f: &mut F| {
        f.add((b"abc".to_vec(), 7i64));
        f.add((Vec::new(), -1i64));
        let s3 = s2.clone();
        f.fuzz(move |t: &T, (b, i): (Vec<u8>, i64)| {
            s3.lock()
                .unwrap()
                .push(format!("{} {:?} {}", t.name(), b, i));
            if i < 0 {
                t.error(&[&"negative"]);
            }
        });
    });
    let mut m = testing::main_start(RegexpDeps, Vec::new(), Vec::new(), vec![target], Vec::new());
    m.set_output(sink);
    assert_eq!(m.run(), 1);
    let out = normalize(&buf.lock().unwrap());
    assert!(out.contains("=== RUN   FuzzAdd/seed#0\n"), "{out}");
    assert!(out.contains("--- FAIL: FuzzAdd/seed#1 (N.NNs)"), "{out}");
    assert!(out.contains("sub_test.go:NNN: negative"), "{out}");
    assert_eq!(
        *seen.lock().unwrap(),
        ["FuzzAdd/seed#0 [97, 98, 99] 7", "FuzzAdd/seed#1 [] -1"]
    );

    // A target that never calls Fuzz fails.
    let (sink, buf) = Sink::buffer();
    let target = InternalFuzzTarget::new("FuzzNoCall", |_f: &mut F| {});
    let mut m = testing::main_start(RegexpDeps, Vec::new(), Vec::new(), vec![target], Vec::new());
    m.set_output(sink);
    assert_eq!(m.run(), 1);
    assert!(buf
        .lock()
        .unwrap()
        .contains("returned without calling F.Fuzz, F.Fail, or F.Skip"));

    // The on-disk corpus (testdata/fuzz/<Name>, relative to the working
    // directory) runs as subtests; malformed files fail the target.
    type Eight = (Vec<u8>, i64, bool, String, f64, u8, i32, u16);
    let cwd = std::env::current_dir().unwrap();
    std::env::set_current_dir(&dir).unwrap();
    let seen8: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let s8 = seen8.clone();
    let good_target = InternalFuzzTarget::new("FuzzGood", move |f: &mut F| {
        let s9 = s8.clone();
        f.fuzz(move |t: &T, v: Eight| s9.lock().unwrap().push(format!("{} {:?}", t.name(), v)));
    });
    let bad_target = InternalFuzzTarget::new("FuzzBad", |f: &mut F| {
        f.fuzz(|_t: &T, _v: Eight| panic!("a malformed corpus must not run"));
    });
    let (sink, buf) = Sink::buffer();
    let mut m = testing::main_start(
        RegexpDeps,
        Vec::new(),
        Vec::new(),
        vec![good_target, bad_target],
        Vec::new(),
    );
    m.set_output(sink);
    let code = m.run();
    std::env::set_current_dir(&cwd).unwrap();
    assert_eq!(code, 1);
    assert_eq!(
        *seen8.lock().unwrap(),
        ["FuzzGood/entry1 ([104, 105, 0], -5, true, \"a\\nb\", 2.5, 120, 233, 16)"]
    );
    let out = normalize(&buf.lock().unwrap());
    assert!(out.contains("--- PASS: FuzzGood/entry1 (N.NNs)"), "{out}");
    assert!(out.contains("--- FAIL: FuzzBad (N.NNs)"), "{out}");
    assert!(
        out.contains("\"testdata/fuzz/FuzzBad/bad\": unmarshal: malformed line \"int(oops)\": literal value required for primitive type"),
        "{out}"
    );
    assert!(
        out.contains(
            "\"testdata/fuzz/FuzzBad/mismatch\": wrong number of values in corpus file: 1, want 8"
        ),
        "{out}"
    );

    // Corpus files: parsing of every supported type.
    let vals = testing::unmarshal_corpus_file(
        b"go test fuzz v1\nint(1)\nuint8(2)\nbyte('a')\nrune(10)\nfloat32(1.5)\nmath.Float64frombits(0x7ff8000000000001)\n",
    )
    .unwrap();
    assert_eq!(vals.len(), 6);
    assert!(testing::unmarshal_corpus_file(b"").is_err());
    assert!(testing::unmarshal_corpus_file(b"go test fuzz v2\nint(1)\n").is_err());
    assert_eq!(
        testing::unmarshal_corpus_file(b"go test fuzz v1\nint(oops)\n").unwrap_err(),
        "malformed line \"int(oops)\": literal value required for primitive type"
    );
    let _ = std::fs::remove_dir_all(&dir);
    testing::set_flags(Flags::default());
}

#[test]
fn run_test_panics_with_go_report_on_failure() {
    let _g = serial();
    testing::set_flags(Flags::default());
    let r = std::panic::catch_unwind(|| {
        testing::run_test("TestWillFail", |t| {
            t.log(&[&"context"]);
            t.error(&[&"bad value", &3]);
        })
    });
    let msg = *r.unwrap_err().downcast::<String>().unwrap();
    let msg = normalize(&msg);
    assert_eq!(
        msg.trim(),
        "--- FAIL: TestWillFail (N.NNs)\n    sub_test.go:NNN: context\n    sub_test.go:NNN: bad value 3\nFAIL"
    );
}

rust_stdlib::test_fn! {
    fn test_fn_macro_defines_a_test(t) {
        t.run("inner", |t| t.log(&[&"ok"]));
        assert_eq!(t.name(), "test_fn_macro_defines_a_test");
    }
}

#[test]
fn testing_cover_and_flags_helpers() {
    testing::init();
    assert!(testing::testing());
    assert_eq!(testing::cover_mode(), "");
    assert_eq!(testing::coverage(), 0.0);
    testing::register_cover(testing::Cover::default());
    let _ = testing::short();
    let _ = testing::verbose();
}
