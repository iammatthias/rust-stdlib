//! Ported from Go's sync/waitgroup_test.go (shortened).
use rust_stdlib::concurrent::WaitGroup;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn panics_with(f: impl FnOnce()) -> String {
    let result = catch_unwind(AssertUnwindSafe(f));
    match result {
        Ok(()) => "no panic".into(),
        Err(p) => p
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| p.downcast_ref::<String>().cloned())
            .unwrap_or_default(),
    }
}

#[test]
fn waitgroup_basics() {
    let wg = WaitGroup::new();
    wg.wait(); // zero counter returns immediately
    wg.add(3);
    let done = Arc::new(AtomicUsize::new(0));
    for _ in 0..3 {
        let (wg, done) = (wg.clone(), done.clone());
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(5));
            done.fetch_add(1, Ordering::SeqCst);
            wg.done();
        });
    }
    wg.wait();
    assert_eq!(done.load(Ordering::SeqCst), 3);
}

#[test]
fn waitgroup_negative_counter_panics() {
    let wg = WaitGroup::new();
    assert_eq!(
        panics_with(|| wg.done()),
        "sync: negative WaitGroup counter"
    );
    let wg = WaitGroup::new();
    wg.add(1);
    wg.add(-1);
    assert_eq!(
        panics_with(|| wg.add(-1)),
        "sync: negative WaitGroup counter"
    );
}

#[test]
fn waitgroup_spawn_runs_and_survives_panics() {
    let wg = WaitGroup::new();
    let n = Arc::new(AtomicUsize::new(0));
    for _ in 0..10 {
        let n = n.clone();
        wg.spawn(move || {
            n.fetch_add(1, Ordering::SeqCst);
        });
    }
    wg.wait();
    assert_eq!(n.load(Ordering::SeqCst), 10);
    wg.spawn(|| panic!("boom in worker"));
    wg.wait(); // the counter is still released
}

#[test]
fn waitgroup_reuse() {
    let wg = WaitGroup::new();
    for round in 0..50 {
        let n = Arc::new(AtomicUsize::new(0));
        for _ in 0..4 {
            let n = n.clone();
            wg.spawn(move || {
                n.fetch_add(1, Ordering::SeqCst);
            });
        }
        wg.wait();
        assert_eq!(n.load(Ordering::SeqCst), 4, "round {round}");
    }
}
