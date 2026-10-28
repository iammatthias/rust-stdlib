//! Timers and tickers, ported from Go's src/time/sleep_test.go and
//! tick_test.go with generous timing tolerances.
use rust_stdlib::time::{
    self as time, Duration, Ticker, Time, Timer, HOUR, MILLISECOND, NANOSECOND, SECOND,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{RecvTimeoutError, TryRecvError};
use std::sync::Arc;

const SCHED: Duration = Duration::from_nanos(10_000_000);

fn std(d: Duration) -> std::time::Duration {
    std::time::Duration::from_nanos(d.as_nanos() as u64)
}

fn no_tick(c: &time::Channel) {
    assert_eq!(c.try_recv().unwrap_err(), TryRecvError::Empty, "extra tick");
}

fn assert_tick(c: &time::Channel) {
    c.recv_timeout(std::time::Duration::from_secs(5))
        .expect("missing tick");
}

#[test]
fn sleep_and_after() {
    let start = std::time::Instant::now();
    time::sleep(50 * MILLISECOND);
    assert!(start.elapsed() >= std(50 * MILLISECOND));
    time::sleep(Duration::from_nanos(i64::MIN));
    time::sleep(Duration::from_nanos(0));

    let start = time::now();
    let fired = time::after(30 * MILLISECOND).recv().unwrap();
    assert!(fired.sub(&start) >= 30 * MILLISECOND - MILLISECOND);
    // Negative and zero delays fire at once; huge ones never do.
    assert_tick(&time::after(Duration::from_nanos(i64::MIN)));
    assert_tick(&time::after(Duration::from_nanos(0)));
    let big = time::after(Duration::from_nanos(i64::MAX));
    assert_eq!(
        big.recv_timeout(std::time::Duration::from_millis(25)),
        Err(RecvTimeoutError::Timeout)
    );
}

/// Go's testTimerChan for a Timer.
#[test]
fn timer_channel_semantics() {
    let tim = time::Timer::new(10000 * SECOND);
    assert!(tim.stop());
    no_tick(&tim.c);
    assert!(!tim.stop());
    assert!(!tim.reset(10000 * SECOND));
    no_tick(&tim.c);
    assert!(tim.reset(NANOSECOND));
    time::sleep(SCHED);
    assert_tick(&tim.c);
    // Fired and received: not pending.
    assert!(!tim.stop());
    // Fired but not received: Stop discards the value and reports pending.
    tim.reset(NANOSECOND);
    time::sleep(SCHED);
    assert!(tim.stop());
    no_tick(&tim.c);
    tim.reset(NANOSECOND);
    time::sleep(SCHED);
    assert!(tim.reset(10000 * SECOND));
    no_tick(&tim.c);
}

/// Go's testTimerChan for a Ticker.
#[test]
fn ticker_channel_semantics() {
    let tick = time::Ticker::new(10000 * SECOND);
    tick.stop();
    no_tick(&tick.c);
    tick.reset(10000 * SECOND);
    no_tick(&tick.c);
    tick.reset(NANOSECOND);
    time::sleep(SCHED);
    assert_tick(&tick.c);
    // A slow receiver gets at most one buffered tick, never a backlog.
    time::sleep(SCHED);
    assert_tick(&tick.c);
    // Reset discards a tick that happened before it.
    time::sleep(SCHED);
    tick.reset(10000 * SECOND);
    no_tick(&tick.c);
    tick.reset(5 * MILLISECOND);
    for _ in 0..3 {
        assert_tick(&tick.c);
    }
    tick.stop();
    time::sleep(SCHED);
    no_tick(&tick.c);
}

#[test]
fn ticker_tick_and_panics() {
    let ticker = time::Ticker::new(20 * MILLISECOND);
    let start = std::time::Instant::now();
    for _ in 0..5 {
        assert_tick(&ticker.c);
    }
    assert!(start.elapsed() >= std::time::Duration::from_millis(90));
    drop(ticker);
    let c = time::tick(10 * MILLISECOND).expect("positive tick");
    assert_tick(&c);
    assert!(time::tick(Duration::from_nanos(0)).is_none());
    assert!(time::tick(-SECOND).is_none());
    assert!(std::panic::catch_unwind(|| time::Ticker::new(-SECOND)).is_err());
    assert!(std::panic::catch_unwind(|| time::Ticker::new(Duration::from_nanos(0))).is_err());
    let ticker = time::Ticker::new(HOUR);
    let ticker = std::panic::AssertUnwindSafe(ticker);
    assert!(std::panic::catch_unwind(|| ticker.reset(Duration::from_nanos(-1))).is_err());
    ticker.stop();
}

#[test]
fn after_func_runs_stops_and_resets() {
    let count = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = std::sync::mpsc::channel();
    let c = Arc::clone(&count);
    let timer = time::after_func(10 * MILLISECOND, move || {
        c.fetch_add(1, Ordering::SeqCst);
        tx.send(()).ok();
    });
    rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert!(!timer.stop());
    // Reset after firing runs the function again.
    assert!(!timer.reset(5 * MILLISECOND));
    rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 2);
    // Stop before firing prevents the call.
    timer.reset(50 * MILLISECOND);
    assert!(timer.stop());
    time::sleep(100 * MILLISECOND);
    assert_eq!(count.load(Ordering::SeqCst), 2);
    // C of an AfterFunc timer never receives (Go's nil channel).
    no_tick(&timer.c);
    // A dropped handle does not cancel the function, as in Go.
    let (tx, rx) = std::sync::mpsc::channel();
    drop(time::after_func(5 * MILLISECOND, move || {
        tx.send(()).ok();
    }));
    rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
}

#[test]
fn timers_fire_in_order() {
    // Channel timers are sent from the single scheduler thread in deadline
    // order. Deadlines are fixed against one base instant, but a stall between
    // `until` and `Timer::new` still shifts that timer's deadline later, so the
    // timers are 50ms apart to absorb scheduling delays under heavy load.
    let order = [9i64, 2, 7, 0, 5, 3, 8, 1, 6, 4];
    let base = time::now();
    let lead = 200 * MILLISECOND;
    let timers: Vec<(i64, Timer)> = order
        .iter()
        .map(|&i| {
            let deadline = base.add(lead + i * 50 * MILLISECOND + MILLISECOND);
            (i, time::Timer::new(time::until(&deadline)))
        })
        .collect();
    // Polling the channels one after another is not atomic: the scheduler can
    // send a later timer between two polls of an earlier one. So each value is
    // ordered by the send time it carries, not by the poll that saw it.
    let mut fired: Vec<(Time, i64)> = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while fired.len() < timers.len() && std::time::Instant::now() < deadline {
        for (i, t) in &timers {
            if let Ok(at) = t.c.try_recv() {
                fired.push((at, *i));
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    fired.sort_by(|a, b| a.0.compare(&b.0).cmp(&0).then(a.1.cmp(&b.1)));
    let got: Vec<i64> = fired.into_iter().map(|(_, i)| i).collect();
    assert_eq!(got, (0..10).collect::<Vec<_>>());
}

/// Go's testStopResetResult: when one of two racing timers fires, Stop or
/// Reset on the other returns false only if its value is still readable.
#[test]
fn stop_and_reset_results_are_consistent() {
    for test_stop in [true, false] {
        let threads: Vec<_> = (0..16)
            .map(|_| {
                std::thread::spawn(move || {
                    for _ in 0..50 {
                        let t1 = time::Timer::new(MILLISECOND);
                        let t2 = time::Timer::new(MILLISECOND);
                        let stop_or_reset = |t: &Timer| {
                            if test_stop {
                                t.stop()
                            } else {
                                t.reset(HOUR)
                            }
                        };
                        loop {
                            if t1.c.try_recv().is_ok() {
                                if !stop_or_reset(&t2) {
                                    t2.c.recv_timeout(std::time::Duration::from_secs(5))
                                        .unwrap();
                                }
                                break;
                            }
                            if t2.c.try_recv().is_ok() {
                                if !stop_or_reset(&t1) {
                                    t1.c.recv_timeout(std::time::Duration::from_secs(5))
                                        .unwrap();
                                }
                                break;
                            }
                            std::thread::yield_now();
                        }
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
    }
}

#[test]
fn ticker_debug_and_types() {
    let ticker: Ticker = time::Ticker::new(HOUR);
    assert!(format!("{ticker:?}").starts_with("Ticker"));
    let timer: Timer = time::Timer::new(HOUR);
    assert!(timer.stop());
}
