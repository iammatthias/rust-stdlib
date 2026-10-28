//! `os/signal` in-process: signals sent to this test process. The handlers are
//! process-wide, so everything runs in one test.
#![cfg(all(
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64"
))]
use rust_stdlib_sys::errno::{Signal, SIGUSR1, SIGUSR2};
use rust_stdlib_sys::os::signal::{self, Cause, Parent};
use rust_stdlib_sys::os::Process;
use std::time::Duration;

fn send(sig: Signal) {
    Process::find(i64::from(std::process::id()))
        .signal(sig)
        .expect("kill");
}

#[test]
fn signals_are_relayed_to_channels() {
    let wait = Duration::from_secs(5);

    // Notify, deliver, Stop.
    let (c, rx) = signal::channel(1);
    signal::notify(&c, &[SIGUSR1]);
    assert!(!signal::ignored(SIGUSR1));
    send(SIGUSR1);
    assert_eq!(rx.recv_timeout(wait).unwrap(), SIGUSR1);

    // A second channel for the same signal gets its own copy.
    let (c2, rx2) = signal::channel(1);
    signal::notify(&c2, &[SIGUSR1, SIGUSR2]);
    send(SIGUSR1);
    assert_eq!(rx.recv_timeout(wait).unwrap(), SIGUSR1);
    assert_eq!(rx2.recv_timeout(wait).unwrap(), SIGUSR1);

    // A full channel drops signals instead of blocking the relay.
    send(SIGUSR2);
    assert_eq!(rx2.recv_timeout(wait).unwrap(), SIGUSR2);
    send(SIGUSR1);
    std::thread::sleep(Duration::from_millis(100));
    send(SIGUSR2);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(rx2.try_recv().unwrap(), SIGUSR1); // the one that fit
    assert!(rx2.try_recv().is_err()); // SIGUSR2 was dropped
    assert_eq!(rx.try_recv().unwrap(), SIGUSR1);

    // Stop delivers what was queued, then nothing more.
    send(SIGUSR1);
    // Give the kernel time to run the handler: Stop covers signals the
    // package has received, not ones still on their way.
    std::thread::sleep(Duration::from_millis(100));
    signal::stop(&c);
    assert_eq!(rx.recv_timeout(wait).unwrap(), SIGUSR1);
    send(SIGUSR1);
    std::thread::sleep(Duration::from_millis(200));
    assert!(rx.try_recv().is_err());
    assert_eq!(rx2.recv_timeout(wait).unwrap(), SIGUSR1);
    signal::stop(&c2);
    // Stopping a channel twice, or one never notified, does nothing.
    signal::stop(&c2);

    // Ignore discards the signal and Ignored reports it; Notify undoes that.
    let (c3, rx3) = signal::channel(2);
    signal::notify(&c3, &[SIGUSR1]);
    signal::ignore(&[SIGUSR1]);
    assert!(signal::ignored(SIGUSR1));
    send(SIGUSR1);
    std::thread::sleep(Duration::from_millis(200));
    assert!(rx3.try_recv().is_err());
    signal::notify(&c3, &[SIGUSR1]);
    assert!(!signal::ignored(SIGUSR1));
    send(SIGUSR1);
    assert_eq!(rx3.recv_timeout(wait).unwrap(), SIGUSR1);
    signal::reset(&[SIGUSR1]);
    send(SIGUSR1); // caught and ignored, as Go's runtime does
    std::thread::sleep(Duration::from_millis(200));
    assert!(rx3.try_recv().is_err());
    signal::stop(&c3);

    // A signal number out of range is skipped.
    signal::notify(&c3, &[Signal(-1), Signal(99)]);
    assert!(!signal::ignored(Signal(-1)));

    // NotifyContext.
    let (ctx, stop) = signal::notify_context(Parent::background(), &[SIGUSR2, SIGUSR1]);
    assert_eq!(
        ctx.to_string(),
        "signal.NotifyContext(context.Background, [user defined signal 2 user defined signal 1])"
    );
    assert!(!ctx.is_done());
    let (tx, linked) = std::sync::mpsc::channel();
    ctx.on_cancel(move |cause| {
        let _ = tx.send(cause.clone());
    });
    send(SIGUSR2);
    match ctx.wait_timeout(wait) {
        Some(Cause::Signal(e)) => {
            assert_eq!(e.to_string(), "user defined signal 2 signal received")
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        linked.recv_timeout(wait).unwrap(),
        Cause::Signal(_)
    ));
    stop.stop();
    // A stopped context keeps its first cause.
    assert!(matches!(ctx.cause(), Some(Cause::Signal(_))));

    let (ctx2, stop2) = signal::notify_context(Parent::background(), &[]);
    assert_eq!(ctx2.to_string(), "signal.NotifyContext(context.Background)");
    stop2.stop();
    assert_eq!(ctx2.cause(), Some(Cause::Canceled));

    // Dropping the guard stops the context.
    let (ctx3, stop3) = signal::notify_context(Parent::background(), &[SIGUSR1]);
    drop(stop3);
    assert_eq!(ctx3.cause(), Some(Cause::Canceled));

    // The parent ending ends the context.
    let (parent_tx, parent_rx) = std::sync::mpsc::channel::<()>();
    let parent = Parent::new(&"parent", parent_rx);
    let (ctx4, _stop4) = signal::notify_context(parent, &[SIGUSR1]);
    assert_eq!(
        ctx4.to_string(),
        "signal.NotifyContext(parent, [user defined signal 1])"
    );
    assert!(!ctx4.is_done());
    drop(parent_tx);
    assert_eq!(ctx4.wait_timeout(wait), Some(Cause::Parent));
}
