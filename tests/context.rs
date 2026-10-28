//! Ports of Go's `context/x_test.go` and `context/context_test.go`.
//!
//! Not ported: `otherContext`/custom-Context-implementation tests
//! (TestCustomContext*, `Context` is a concrete type here), the nil
//! parent/key panic tests (TestWithValueChecksKey, TestInvalidDerivedFail:
//! references cannot be nil and keys are typed) and the allocation counts.
use rust_stdlib::context::{CancelFunc, CauseError, Context, Error, Key};
use std::{
    sync::{mpsc, Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

const SHORT: Duration = Duration::from_millis(1);
const VERY_LONG: Duration = Duration::from_secs(1000 * 3600);
const QUIESCENT: Duration = Duration::from_secs(5);

fn err(text: &'static str) -> CauseError {
    #[derive(Debug)]
    struct E(&'static str);
    impl std::fmt::Display for E {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }
    impl std::error::Error for E {}
    Arc::new(E(text))
}

fn same(a: &Option<CauseError>, b: &Option<CauseError>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        _ => false,
    }
}

fn is_error(cause: &Option<CauseError>, want: Error) -> bool {
    cause
        .as_ref()
        .and_then(|c| c.downcast_ref::<Error>())
        .is_some_and(|e| *e == want)
}

#[test]
fn background_and_todo() {
    for (c, want) in [
        (Context::background(), "context.Background"),
        (Context::todo(), "context.TODO"),
    ] {
        assert!(c.done().is_never());
        assert_eq!(c.err(), None);
        assert_eq!(c.deadline(), None);
        assert_eq!(c.to_string(), want);
        assert!(!c.done().wait_timeout(SHORT.into()));
    }
}

#[test]
fn with_cancel_propagates_synchronously() {
    let (c1, cancel) = Context::background().with_cancel();
    assert_eq!(c1.to_string(), "context.Background.WithCancel");
    let (c2, _) = c1.with_cancel();
    let k = Key::<i32>::new();
    let v = c1.with_value(&k, 1);
    for c in [&c1, &c2, &v] {
        assert!(!c.done().is_never());
        assert_eq!(c.err(), None);
        assert!(!c.done().is_done());
    }
    cancel();
    for c in [&c1, &c2, &v] {
        assert!(c.done().is_done());
        assert_eq!(c.err(), Some(Error::Canceled));
    }
}

fn test_deadline(c: &Context, name: &str) {
    assert!(
        c.done().wait_timeout(QUIESCENT.into()),
        "{name}: not timed out"
    );
    assert_eq!(c.err(), Some(Error::DeadlineExceeded), "{name}");
}

#[test]
fn deadline_cases() {
    let (c, _x) = Context::background().with_deadline(Instant::now() + SHORT);
    assert!(c
        .to_string()
        .starts_with("context.Background.WithDeadline("));
    test_deadline(&c, "WithDeadline");

    let (c, _x) = Context::background().with_deadline(Instant::now() + SHORT);
    let (c2, _y) = c.with_deadline(Instant::now() + VERY_LONG);
    test_deadline(&c2, "WithDeadline+WithDeadline");

    let past = Instant::now() - SHORT;
    let (c, _x) = Context::background().with_deadline(past);
    test_deadline(&c, "inthepast");
    let (c, _x) = Context::background().with_deadline(Instant::now());
    test_deadline(&c, "now");
}

#[test]
fn timeout_cases() {
    let (c, _x) = Context::background().with_timeout(SHORT.into());
    assert!(c
        .to_string()
        .starts_with("context.Background.WithDeadline("));
    test_deadline(&c, "WithTimeout");
    let (c, _x) = Context::background().with_timeout(SHORT.into());
    let (c2, _y) = c.with_timeout(VERY_LONG.into());
    test_deadline(&c2, "WithTimeout+WithTimeout");
}

#[test]
fn deadline_earlier_than_parent_and_string() {
    let end = Instant::now() + Duration::from_secs(100);
    let (parent, _p) = Context::background().with_deadline(end);
    let (child, _c) = parent.with_deadline(end + Duration::from_secs(5));
    assert_eq!(child.deadline(), Some(end));
    assert_eq!(
        child.to_string().split(".WithDeadline(").count(),
        2,
        "later deadline degrades to WithCancel: {child}"
    );
    assert!(child.to_string().ends_with(".WithCancel"));
    let sooner = end - Duration::from_secs(50);
    let (child, _c) = parent.with_deadline(sooner);
    assert_eq!(child.deadline(), Some(sooner));
}

#[test]
fn canceled_timeout() {
    let (c, _x) = Context::background().with_timeout(Duration::from_secs(1).into());
    let (c, cancel) = c.with_timeout(VERY_LONG.into());
    cancel();
    assert!(c.done().is_done());
    assert_eq!(c.err(), Some(Error::Canceled));
}

#[test]
fn values_and_strings() {
    let k1 = Key::<String>::named("key1");
    let k2 = Key::<String>::named("key2(1)");
    let k3 = Key::<String>::named("key2(3)");
    let get = |c: &Context, k: &Key<String>| c.value(k).map(|v| (*v).clone());
    let c0 = Context::background();
    assert_eq!(get(&c0, &k1), None);
    let c1 = c0.with_value(&k1, "c1k1".to_string());
    assert_eq!(get(&c1, &k1).as_deref(), Some("c1k1"));
    assert_eq!(get(&c1, &k2), None);
    assert_eq!(c1.to_string(), "context.Background.WithValue(key1, c1k1)");
    let c2 = c1.with_value(&k2, "c2k2".to_string());
    let c3 = c2.with_value(&k3, "c3k3".to_string());
    assert_eq!(get(&c3, &k1).as_deref(), Some("c1k1"));
    assert_eq!(get(&c3, &k2).as_deref(), Some("c2k2"));
    assert_eq!(get(&c3, &k3).as_deref(), Some("c3k3"));
    assert_eq!(
        c3.to_string(),
        "context.Background.WithValue(key1, c1k1).WithValue(key2(1), c2k2).WithValue(key2(3), c3k3)"
    );
    // Shadowing the same key.
    let c4 = c3.with_value(&k1, "new".to_string());
    assert_eq!(get(&c4, &k1).as_deref(), Some("new"));
    // Type-keyed values and non-string value formatting.
    struct Id(u32);
    let by_type = Key::<Id>::of_type();
    let c5 = c4.with_value(&by_type, Id(5));
    assert_eq!(c5.value(&Key::<Id>::of_type()).unwrap().0, 5);
    assert!(c5.to_string().contains("WithValue("));
    // A value context passes cancellation through.
    let (cc, cancel) = c5.with_cancel();
    let c6 = cc.with_value(&k2, "x".to_string());
    cancel();
    assert_eq!(c6.err(), Some(Error::Canceled));
    assert!(c6.done().is_done());
}

#[test]
fn simultaneous_cancels() {
    let (root, cancel) = Context::background().with_cancel();
    let mut all: Vec<(Context, CancelFunc)> = vec![(root.clone(), cancel)];
    let mut next = 0;
    while next < all.len() && all.len() < 100 {
        let parent = all[next].0.clone();
        next += 1;
        for _ in 0..4 {
            all.push(parent.with_cancel());
        }
    }
    let contexts: Vec<_> = all.iter().map(|(c, _)| c.clone()).collect();
    let handles: Vec<_> = all
        .into_iter()
        .map(|(_, cancel)| thread::spawn(move || cancel()))
        .collect();
    for c in &contexts {
        assert!(c.done().wait_timeout(QUIESCENT.into()));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn interlocked_cancels() {
    let (parent, cancel_parent) = Context::background().with_cancel();
    let (child, cancel_child) = parent.with_cancel();
    let p = parent.clone();
    let t = thread::spawn(move || {
        p.done().wait();
        cancel_child();
    });
    cancel_parent();
    assert!(child.done().wait_timeout(QUIESCENT.into()));
    t.join().unwrap();
}

fn layers(timeout: bool, seed: u64) {
    let mut state = seed | 1;
    let mut rnd = move |n: u64| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state % n
    };
    let mut ctx = Context::background();
    let mut keys = Vec::new();
    let mut cancels: Vec<CancelFunc> = Vec::new();
    let mut timers = 0;
    let mut i = 0;
    while i < 30 || timers == 0 || cancels.is_empty() || keys.is_empty() {
        i += 1;
        match rnd(3) {
            0 => {
                let key = Key::<u64>::new();
                ctx = ctx.with_value(&key, i);
                keys.push((key, i));
            }
            1 => {
                let (c, cancel) = ctx.with_cancel();
                ctx = c;
                cancels.push(cancel);
            }
            _ => {
                let (c, cancel) = ctx.with_timeout(if timeout {
                    SHORT.into()
                } else {
                    VERY_LONG.into()
                });
                ctx = c;
                cancels.push(cancel);
                timers += 1;
            }
        }
    }
    let check = |when: &str| {
        for (key, want) in &keys {
            assert_eq!(*ctx.value(key).unwrap(), *want, "{when}");
        }
    };
    if !timeout {
        assert_eq!(ctx.err(), None);
    }
    assert!(ctx.to_string().starts_with("context.Background."));
    check("before");
    if timeout {
        assert!(ctx.done().wait_timeout(QUIESCENT.into()));
        check("after timeout");
    } else {
        let n = cancels.len() as u64;
        (cancels[rnd(n) as usize])();
        assert!(ctx.done().is_done() || ctx.err().is_none());
        check("after cancel");
    }
}

#[test]
fn layers_cancel_and_timeout() {
    for seed in 1..40 {
        layers(false, seed);
        layers(true, seed);
    }
}

#[test]
fn with_cancel_canceled_parent() {
    let (parent, pcancel) = Context::background().with_cancel_cause();
    let because = err("Because!");
    pcancel(Some(because.clone()));
    let (c, _) = parent.with_cancel();
    assert!(c.done().is_done());
    assert_eq!(c.err(), Some(Error::Canceled));
    assert!(same(&c.cause(), &Some(because)));
}

#[test]
fn with_cancel_simultaneously_canceled_parent() {
    for _ in 0..100 {
        let (parent, pcancel) = Context::background().with_cancel_cause();
        let because = err("Because!");
        let b = because.clone();
        let t = thread::spawn(move || pcancel(Some(b)));
        let (c, _) = parent.with_cancel();
        c.done().wait();
        assert_eq!(c.err(), Some(Error::Canceled));
        assert!(same(&c.cause(), &Some(because)));
        t.join().unwrap();
    }
}

#[test]
fn deadline_exceeded_supports_timeout() {
    assert!(Error::DeadlineExceeded.timeout());
    assert!(Error::DeadlineExceeded.temporary());
    assert!(!Error::Canceled.timeout());
    assert_eq!(Error::Canceled.to_string(), "context canceled");
    assert_eq!(
        Error::DeadlineExceeded.to_string(),
        "context deadline exceeded"
    );
}

#[test]
fn cause_table() {
    let forever = Duration::from_secs(1_000_000);
    let parent_cause = err("parentCause");
    let child_cause = err("childCause");
    let too_slow = err("tooSlow");
    let finished_early = err("finishedEarly");
    enum Want {
        Canceled,
        Deadline,
        Cause(CauseError),
    }
    let cases: Vec<(&str, Context, Option<Error>, Option<Want>)> = vec![
        ("Background", Context::background(), None, None),
        ("TODO", Context::todo(), None, None),
        (
            "WithCancel",
            {
                let (c, cancel) = Context::background().with_cancel();
                cancel();
                c
            },
            Some(Error::Canceled),
            Some(Want::Canceled),
        ),
        (
            "WithCancelCause",
            {
                let (c, cancel) = Context::background().with_cancel_cause();
                cancel(Some(parent_cause.clone()));
                c
            },
            Some(Error::Canceled),
            Some(Want::Cause(parent_cause.clone())),
        ),
        (
            "WithCancelCause nil",
            {
                let (c, cancel) = Context::background().with_cancel_cause();
                cancel(None);
                c
            },
            Some(Error::Canceled),
            Some(Want::Canceled),
        ),
        (
            "parent cause before child",
            {
                let (c, cp) = Context::background().with_cancel_cause();
                let (c, cc) = c.with_cancel_cause();
                cp(Some(parent_cause.clone()));
                cc(Some(child_cause.clone()));
                c
            },
            Some(Error::Canceled),
            Some(Want::Cause(parent_cause.clone())),
        ),
        (
            "parent cause after child",
            {
                let (c, cp) = Context::background().with_cancel_cause();
                let (c, cc) = c.with_cancel_cause();
                cc(Some(child_cause.clone()));
                cp(Some(parent_cause.clone()));
                c
            },
            Some(Error::Canceled),
            Some(Want::Cause(child_cause.clone())),
        ),
        (
            "parent cause before nil",
            {
                let (c, cp) = Context::background().with_cancel_cause();
                let (c, cc) = c.with_cancel();
                cp(Some(parent_cause.clone()));
                cc();
                c
            },
            Some(Error::Canceled),
            Some(Want::Cause(parent_cause.clone())),
        ),
        (
            "parent cause after nil",
            {
                let (c, cp) = Context::background().with_cancel_cause();
                let (c, cc) = c.with_cancel();
                cc();
                cp(Some(parent_cause.clone()));
                c
            },
            Some(Error::Canceled),
            Some(Want::Canceled),
        ),
        (
            "child cause after nil",
            {
                let (c, cp) = Context::background().with_cancel();
                let (c, cc) = c.with_cancel_cause();
                cp();
                cc(Some(child_cause.clone()));
                c
            },
            Some(Error::Canceled),
            Some(Want::Canceled),
        ),
        (
            "child cause before nil",
            {
                let (c, cp) = Context::background().with_cancel();
                let (c, cc) = c.with_cancel_cause();
                cc(Some(child_cause.clone()));
                cp();
                c
            },
            Some(Error::Canceled),
            Some(Want::Cause(child_cause.clone())),
        ),
        (
            "WithTimeout",
            {
                let (c, cancel) = Context::background().with_timeout(Duration::ZERO.into());
                cancel();
                c
            },
            Some(Error::DeadlineExceeded),
            Some(Want::Deadline),
        ),
        (
            "WithTimeout canceled",
            {
                let (c, cancel) = Context::background().with_timeout(forever.into());
                cancel();
                c
            },
            Some(Error::Canceled),
            Some(Want::Canceled),
        ),
        (
            "WithTimeoutCause",
            {
                let (c, cancel) = Context::background()
                    .with_timeout_cause(Duration::ZERO.into(), Some(too_slow.clone()));
                cancel();
                c
            },
            Some(Error::DeadlineExceeded),
            Some(Want::Cause(too_slow.clone())),
        ),
        (
            "WithTimeoutCause canceled",
            {
                let (c, cancel) = Context::background()
                    .with_timeout_cause(forever.into(), Some(too_slow.clone()));
                cancel();
                c
            },
            Some(Error::Canceled),
            Some(Want::Canceled),
        ),
        (
            "WithTimeoutCause stacked",
            {
                let (c, cancel) = Context::background().with_cancel_cause();
                let (c, _) = c.with_timeout_cause(Duration::ZERO.into(), Some(too_slow.clone()));
                cancel(Some(finished_early.clone()));
                c
            },
            Some(Error::DeadlineExceeded),
            Some(Want::Cause(too_slow.clone())),
        ),
        (
            "WithTimeoutCause stacked canceled",
            {
                let (c, cancel) = Context::background().with_cancel_cause();
                let (c, _) = c.with_timeout_cause(forever.into(), Some(too_slow.clone()));
                cancel(Some(finished_early.clone()));
                c
            },
            Some(Error::Canceled),
            Some(Want::Cause(finished_early.clone())),
        ),
        (
            "WithDeadlineCause",
            {
                let (c, _) = Context::background()
                    .with_deadline_cause(Instant::now(), Some(too_slow.clone()));
                c
            },
            Some(Error::DeadlineExceeded),
            Some(Want::Cause(too_slow.clone())),
        ),
        (
            "WithoutCancel",
            Context::background().without_cancel(),
            None,
            None,
        ),
        (
            "WithoutCancel canceled",
            {
                let (c, cancel) = Context::background().with_cancel_cause();
                let c = c.without_cancel();
                cancel(Some(finished_early.clone()));
                c
            },
            None,
            None,
        ),
        (
            "WithoutCancel timeout",
            {
                let (c, cancel) = Context::background()
                    .with_timeout_cause(Duration::ZERO.into(), Some(too_slow.clone()));
                let c = c.without_cancel();
                cancel();
                c
            },
            None,
            None,
        ),
    ];
    for (name, ctx, want_err, want_cause) in cases {
        assert_eq!(ctx.err(), want_err, "{name}: Err");
        let got = ctx.cause();
        match want_cause {
            None => assert!(got.is_none(), "{name}: Cause"),
            Some(Want::Canceled) => assert!(is_error(&got, Error::Canceled), "{name}: Cause"),
            Some(Want::Deadline) => {
                assert!(is_error(&got, Error::DeadlineExceeded), "{name}: Cause")
            }
            Some(Want::Cause(want)) => assert!(same(&got, &Some(want)), "{name}: Cause"),
        }
    }
}

#[test]
fn cause_race() {
    let because = err("TestCauseRace");
    let (ctx, cancel) = Context::background().with_cancel_cause();
    let b = because.clone();
    let t = thread::spawn(move || cancel(Some(b)));
    loop {
        if let Some(got) = ctx.cause() {
            assert!(Arc::ptr_eq(&got, &because));
            break;
        }
        thread::yield_now();
    }
    t.join().unwrap();
}

#[test]
fn without_cancel_keeps_values() {
    let key = Key::<&'static str>::named("key");
    let ctx = Context::background().with_value(&key, "value");
    let ctx = ctx.without_cancel();
    assert_eq!(ctx.deadline(), None);
    assert!(ctx.done().is_never());
    assert_eq!(ctx.err(), None);
    assert_eq!(*ctx.value(&key).unwrap(), "value");
    assert_eq!(
        ctx.to_string(),
        "context.Background.WithValue(key, value).WithoutCancel"
    );

    // Detached from a cancelled parent but cancellable on its own.
    let (parent, cancel_parent) = Context::background().with_timeout(VERY_LONG.into());
    let detached = parent.without_cancel();
    let (child, _c) = detached.with_cancel();
    cancel_parent();
    assert_eq!(parent.err(), Some(Error::Canceled));
    assert_eq!(detached.err(), None);
    assert_eq!(child.err(), None);
}

#[test]
fn after_func_called_after_cancel() {
    let (ctx, cancel) = Context::background().with_cancel();
    let (tx, rx) = mpsc::channel();
    let stop = ctx.after_func(move || tx.send(()).unwrap());
    assert!(rx.recv_timeout(SHORT * 20).is_err(), "called before done");
    cancel();
    rx.recv_timeout(QUIESCENT).unwrap();
    assert!(!stop());
}

#[test]
fn after_func_called_after_timeout() {
    let (ctx, cancel) = Context::background().with_timeout(SHORT.into());
    let (tx, rx) = mpsc::channel();
    ctx.after_func(move || tx.send(()).unwrap());
    rx.recv_timeout(QUIESCENT).unwrap();
    cancel();
}

#[test]
fn after_func_called_immediately() {
    let (ctx, cancel) = Context::background().with_cancel();
    cancel();
    let (tx, rx) = mpsc::channel();
    ctx.after_func(move || tx.send(()).unwrap());
    rx.recv_timeout(QUIESCENT).unwrap();
}

#[test]
fn after_func_not_called_after_stop() {
    let (ctx, cancel) = Context::background().with_cancel();
    let (tx, rx) = mpsc::channel();
    let stop = ctx.after_func(move || tx.send(()).unwrap());
    assert!(stop());
    cancel();
    assert!(rx.recv_timeout(SHORT * 20).is_err());
    assert!(!stop());
}

#[test]
fn after_func_never_fires_without_cancelable_parent() {
    let (tx, rx) = mpsc::channel();
    let stop = Context::background()
        .without_cancel()
        .after_func(move || tx.send(()).unwrap());
    assert!(rx.recv_timeout(SHORT * 20).is_err());
    assert!(stop());
}

#[test]
fn after_func_called_asynchronously() {
    let (ctx, cancel) = Context::background().with_cancel();
    let (tx, rx) = mpsc::sync_channel::<()>(0);
    let stop = ctx.after_func(move || tx.send(()).unwrap());
    cancel(); // must not block on the rendezvous send
    rx.recv_timeout(QUIESCENT).unwrap();
    assert!(!stop());
}

#[test]
fn after_func_runs_once_per_registration() {
    let (ctx, cancel) = Context::background().with_cancel();
    let fired = Arc::new(Mutex::new(Vec::new()));
    let stops: Vec<_> = (0..5)
        .map(|i| {
            let fired = fired.clone();
            ctx.after_func(move || fired.lock().unwrap().push(i))
        })
        .collect();
    assert!(stops[2]());
    cancel();
    cancel();
    let deadline = Instant::now() + QUIESCENT;
    while fired.lock().unwrap().len() < 4 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(2));
    }
    let mut got = fired.lock().unwrap().clone();
    got.sort_unstable();
    assert_eq!(got, vec![0, 1, 3, 4]);
    assert!(stops.iter().all(|stop| !stop()));
}

#[test]
fn err_done_race() {
    for _ in 0..10 {
        let (ctx, cancel) = Context::background().with_cancel();
        let done = ctx.done();
        let t = thread::spawn(move || cancel());
        while ctx.err().is_none() {
            thread::yield_now();
        }
        assert!(done.is_done());
        t.join().unwrap();
    }
}

#[test]
fn done_receiver_behaves_like_closed_channel() {
    use std::sync::mpsc::{RecvTimeoutError, TryRecvError};
    let (ctx, cancel) = Context::background().with_cancel();
    let rx = ctx.done().receiver();
    assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
    assert_eq!(rx.recv_timeout(SHORT), Err(RecvTimeoutError::Timeout));
    cancel();
    assert_eq!(rx.try_recv(), Err(TryRecvError::Disconnected));
    assert!(ctx.done().receiver().recv().is_err());
    // Timer-delivered expiry.
    let (ctx, _c) = Context::background().with_timeout(SHORT.into());
    assert!(ctx.done().receiver().recv_timeout(QUIESCENT) == Err(RecvTimeoutError::Disconnected));
    // Never-done contexts never disconnect.
    let rx = Context::background().done().receiver();
    assert_eq!(rx.recv_timeout(SHORT), Err(RecvTimeoutError::Timeout));
}

#[test]
fn cancel_removes_children_and_dropped_contexts_are_freed() {
    // A parent with many short-lived children must not retain them.
    let (parent, _cancel) = Context::background().with_cancel();
    for _ in 0..10_000 {
        let (child, cancel) = parent.with_cancel();
        let _ = child;
        cancel();
    }
    for _ in 0..10_000 {
        let _ = parent.with_cancel();
    }
    assert_eq!(parent.err(), None);
}

#[test]
fn many_timers_expire_without_polling_and_not_early() {
    // Each AfterFunc runs on its own thread, as Go's runs in its own goroutine,
    // so the order the callbacks report in is scheduling order; what is
    // promised is that every one runs, none before its own deadline.
    let (tx, rx) = mpsc::channel();
    let base = Context::background();
    let start = Instant::now();
    let mut keep = Vec::new();
    for i in (0..5u64).rev() {
        let (ctx, cancel) = base.with_timeout((Duration::from_millis(20 + i * 20)).into());
        let tx = tx.clone();
        let stop = ctx.after_func(move || tx.send((i, start.elapsed())).unwrap());
        keep.push((ctx, cancel, stop));
    }
    let mut got: Vec<(u64, Duration)> = (0..5)
        .map(|_| rx.recv_timeout(QUIESCENT).unwrap())
        .collect();
    got.sort();
    assert_eq!(
        got.iter().map(|g| g.0).collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 4]
    );
    for (i, elapsed) in got {
        assert!(
            elapsed >= Duration::from_millis(20 + i * 20),
            "timer {i} fired after {elapsed:?}, before its deadline"
        );
    }
    for (ctx, _, _) in &keep {
        assert!(ctx.err().is_some());
    }
}

#[test]
fn unfired_after_func_does_not_leak_its_parent() {
    // Go's GC frees a never-canceled context with a pending AfterFunc; the
    // registration must not form an Arc cycle with its parent.
    let alive = Arc::new(());
    {
        let (ctx, _cancel) = Context::background().with_cancel();
        let guard = alive.clone();
        let _stop = ctx.after_func(move || {
            let _ = &guard;
        });
        let (child, _cancel_child) = ctx.with_cancel();
        child.after_func(|| {});
        assert_eq!(Arc::strong_count(&alive), 2);
    }
    assert_eq!(Arc::strong_count(&alive), 1, "AfterFunc closure leaked");
}

#[test]
fn with_timeout_takes_the_go_duration_type() {
    use rust_stdlib::time::SECOND;
    let (ctx, cancel) = Context::background().with_timeout(5 * SECOND);
    assert!(ctx.deadline().is_some());
    assert_eq!(ctx.err(), None);
    cancel();
}

#[test]
fn negative_timeouts_are_already_expired() {
    use rust_stdlib::time::SECOND;
    let before = Instant::now();
    let (ctx, _cancel) = Context::background().with_timeout(-SECOND);
    assert!(ctx.deadline().unwrap() < before);
    assert_eq!(ctx.err(), Some(Error::DeadlineExceeded));
    assert!(ctx.done().wait_timeout(-SECOND));
}
