//! Go's `testing/synctest`: testing concurrent code with a fake clock.
//!
//! Go's runtime gives a bubble a fake `time` package and knows which
//! goroutines are durably blocked (on bubble channels, `sync.Cond`,
//! `sync.WaitGroup`, `time.Sleep`). Rust has no such runtime control and the
//! timers of [`crate::time`] and [`crate::context`] run on the real
//! monotonic clock, so a bubble here is a smaller, explicit mechanism with the
//! same shape:
//!
//! - [`fn@test`] runs a function on a bubble thread; threads started with
//!   [`spawn`] join the bubble.
//! - The bubble has its own fake clock ([`now`], starting at midnight UTC,
//!   2000-01-01) that advances only when every thread of the bubble is
//!   durably blocked: asleep in [`sleep`], waiting in [`wait`], or receiving
//!   from an empty bubble [`Chan`].
//! - [`wait`] returns when every other thread of the bubble is durably blocked
//!   (or has exited), and [`fn@test`] fails if all of them are durably blocked
//!   with nothing to wake them.
//!
//! Real `std::time`, `Condvar` and `mpsc` waits are not durably blocking
//! (use [`Chan`]), and `crate::time` timers keep real time. That is the `fake-runtime` deviation recorded for Go's `Test`, `Wait`
//! and `Sleep`.

use std::{
    cell::RefCell,
    collections::{BinaryHeap, VecDeque},
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};

use super::{T, TB};
use crate::time::{self, Time};

/// Midnight UTC, 2000-01-01, as seconds since the Unix epoch.
const EPOCH_2000: i64 = 946_684_800;

#[derive(Default)]
struct State {
    /// Elapsed fake time.
    now: Duration,
    /// Threads in the bubble.
    total: usize,
    /// Threads in the bubble that are not durably blocked.
    active: usize,
    /// Pending sleeps: (wake time, id), earliest first.
    sleepers: BinaryHeap<std::cmp::Reverse<(Duration, u64)>>,
    woken: Vec<u64>,
    next_id: u64,
    /// Threads blocked in `wait`, each released by a ticket.
    waiters: usize,
    wait_tickets: usize,
    /// Set when the bubble found itself deadlocked.
    deadlock: bool,
    /// Set while the root thread (the function given to `test`) is running.
    root_running: bool,
}

struct Bubble {
    state: Mutex<State>,
    cv: Condvar,
}

thread_local! {
    static CURRENT: RefCell<Option<Arc<Bubble>>> = const { RefCell::new(None) };
}

fn current(what: &str) -> Arc<Bubble> {
    CURRENT.with(|c| c.borrow().clone()).unwrap_or_else(|| {
        panic!("synctest.{what} called from outside a bubble");
    })
}

/// Reports whether the calling thread is part of a bubble.
pub fn in_bubble() -> bool {
    CURRENT.with(|c| c.borrow().is_some())
}

impl Bubble {
    /// Called with the lock held whenever `active` may have dropped to zero.
    fn settle(&self, st: &mut State) {
        if st.active != 0 || st.total == 0 {
            return;
        }
        if st.waiters > st.wait_tickets {
            // Release one waiter: everything else is durably blocked.
            st.wait_tickets += 1;
            st.active += 1;
            self.cv.notify_all();
            return;
        }
        if st.waiters > 0 {
            return; // a released waiter is about to run
        }
        if st.root_running {
            if let Some(std::cmp::Reverse((when, _))) = st.sleepers.peek().copied() {
                if when > st.now {
                    st.now = when;
                }
                while let Some(&std::cmp::Reverse((w, id))) = st.sleepers.peek() {
                    if w > st.now {
                        break;
                    }
                    st.sleepers.pop();
                    st.woken.push(id);
                    st.active += 1;
                }
                self.cv.notify_all();
                return;
            }
        } else if let Some(&std::cmp::Reverse((_, _))) = st.sleepers.peek() {
            // Time stops advancing when the root goroutine exits.
        }
        st.deadlock = true;
        self.cv.notify_all();
    }

    fn sleep(&self, d: Duration) {
        let mut st = self.state.lock().unwrap();
        let id = st.next_id;
        st.next_id += 1;
        let when = st.now + d;
        st.sleepers.push(std::cmp::Reverse((when, id)));
        st.active -= 1;
        self.settle(&mut st);
        while !st.woken.contains(&id) {
            st = self.cv.wait(st).unwrap();
        }
        st.woken.retain(|&w| w != id);
    }

    fn wait(&self) {
        let mut st = self.state.lock().unwrap();
        st.active -= 1;
        st.waiters += 1;
        self.settle(&mut st);
        while st.wait_tickets == 0 {
            st = self.cv.wait(st).unwrap();
        }
        st.wait_tickets -= 1;
        st.waiters -= 1;
    }

    fn exit(&self) {
        let mut st = self.state.lock().unwrap();
        st.active -= 1;
        st.total -= 1;
        self.settle(&mut st);
        self.cv.notify_all();
    }
}

struct ExitGuard(Arc<Bubble>);

impl Drop for ExitGuard {
    fn drop(&mut self) {
        self.0.exit();
        CURRENT.with(|c| *c.borrow_mut() = None);
    }
}

fn start_thread(b: &Arc<Bubble>, f: impl FnOnce() + Send + 'static) {
    {
        let mut st = b.state.lock().unwrap();
        st.total += 1;
        st.active += 1;
    }
    let b2 = b.clone();
    std::thread::spawn(move || {
        CURRENT.with(|c| *c.borrow_mut() = Some(b2.clone()));
        let _guard = ExitGuard(b2);
        f();
    });
}

/// Starts a thread in the calling thread's bubble (Go's `go` statement
/// inside a bubble).
///
/// # Panics
///
/// If the caller is not in a bubble.
pub fn spawn(f: impl FnOnce() + Send + 'static) {
    let b = current("Spawn");
    start_thread(&b, f);
}

/// The bubble's fake time: midnight UTC, 2000-01-01 plus the time elapsed
/// in the bubble (Go's `time.Now` inside a bubble).
///
/// # Panics
///
/// If the caller is not in a bubble.
pub fn now() -> Time {
    let b = current("Now");
    let elapsed = b.state.lock().unwrap().now;
    time::unix(EPOCH_2000, 0)
        .utc()
        .add(time::Duration::from_nanos(elapsed.as_nanos() as i64))
}

/// Blocks until the bubble's clock has advanced by `d` and every other thread
/// of the bubble is durably blocked: `time.Sleep(d)` followed by [`wait`].
///
/// # Panics
///
/// If the caller is not in a bubble.
pub fn sleep(d: time::Duration) {
    let b = current("Sleep");
    b.sleep(d.to_std());
    b.wait();
}

/// Go's `time.Sleep` inside a bubble: blocks (durably) for `d` of fake time
/// without waiting for the other threads to settle.
pub fn time_sleep(d: time::Duration) {
    current("Sleep").sleep(d.to_std());
}

/// Blocks until every thread of the bubble other than the caller is durably
/// blocked or has exited (Go's `Wait`). It must not be called concurrently by
/// several threads of one bubble.
///
/// # Panics
///
/// If the caller is not in a bubble.
pub fn wait() {
    current("Wait").wait();
}

/// A bubble-aware unbounded channel (Go's channel created inside a bubble):
/// a thread blocked in [`recv`](Chan::recv) is durably blocked, and a
/// [`send`](Chan::send) wakes it atomically with respect to the bubble's
/// idle detection, so the fake clock cannot advance in between.
pub struct Chan<T> {
    inner: Arc<ChanInner<T>>,
}

impl<T> Clone for Chan<T> {
    fn clone(&self) -> Self {
        Chan {
            inner: self.inner.clone(),
        }
    }
}

struct ChanInner<T> {
    bubble: Arc<Bubble>,
    state: Mutex<ChanState<T>>,
}

struct ChanState<T> {
    queue: VecDeque<T>,
    closed: bool,
    parked: usize,
    wake: usize,
}

impl<T> Chan<T> {
    /// Creates a channel in the calling thread's bubble.
    ///
    /// # Panics
    ///
    /// If the caller is not in a bubble.
    pub fn new() -> Chan<T> {
        Chan {
            inner: Arc::new(ChanInner {
                bubble: current("Chan::new"),
                state: Mutex::new(ChanState {
                    queue: VecDeque::new(),
                    closed: false,
                    parked: 0,
                    wake: 0,
                }),
            }),
        }
    }

    fn check_bubble(&self) {
        let b = current("Chan");
        if !Arc::ptr_eq(&b, &self.inner.bubble) {
            panic!("synctest: channel used from a different bubble");
        }
    }

    /// Sends a value; the channel is unbounded, so this never blocks.
    ///
    /// # Panics
    ///
    /// If the channel is closed or the caller is in another bubble.
    pub fn send(&self, v: T) {
        self.check_bubble();
        let b = &self.inner.bubble;
        let mut st = b.state.lock().unwrap();
        let mut cs = self.inner.state.lock().unwrap();
        if cs.closed {
            panic!("send on closed channel");
        }
        cs.queue.push_back(v);
        if cs.parked > 0 {
            cs.parked -= 1;
            cs.wake += 1;
            st.active += 1;
            b.cv.notify_all();
        }
    }

    /// Closes the channel; receivers drain it and then get `None`.
    pub fn close(&self) {
        self.check_bubble();
        let b = &self.inner.bubble;
        let mut st = b.state.lock().unwrap();
        let mut cs = self.inner.state.lock().unwrap();
        if cs.closed {
            panic!("close of closed channel");
        }
        cs.closed = true;
        let n = cs.parked;
        cs.parked = 0;
        cs.wake += n;
        st.active += n;
        b.cv.notify_all();
    }

    /// Receives a value, durably blocking while the channel is empty.
    /// Returns `None` once the channel is closed and drained.
    pub fn recv(&self) -> Option<T> {
        self.check_bubble();
        let b = &self.inner.bubble;
        let mut st = b.state.lock().unwrap();
        loop {
            let mut cs = self.inner.state.lock().unwrap();
            if let Some(v) = cs.queue.pop_front() {
                return Some(v);
            }
            if cs.closed {
                return None;
            }
            cs.parked += 1;
            drop(cs);
            st.active -= 1;
            b.settle(&mut st);
            loop {
                st = b.cv.wait(st).unwrap();
                let mut cs = self.inner.state.lock().unwrap();
                if cs.wake > 0 {
                    cs.wake -= 1;
                    break;
                }
            }
        }
    }

    /// Receives a value if one is ready.
    pub fn try_recv(&self) -> Option<T> {
        self.inner.state.lock().unwrap().queue.pop_front()
    }
}

impl<T> Default for Chan<T> {
    fn default() -> Self {
        Chan::new()
    }
}

/// Executes `f` in a new bubble and waits for every thread of the bubble to
/// exit before returning (Go's `Test`). `f` receives a `T` whose log output
/// belongs to `t`, whose cleanup functions run inside the bubble just before
/// `test` returns, and on which `run`, `parallel` and `deadline` panic. If
/// the threads of the bubble all become durably blocked with nothing to wake
/// them, the test fails; if `f` fails, `t` is failed with `fail_now`.
///
/// # Panics
///
/// If called from within a bubble.
#[track_caller]
pub fn test(t: &T, f: impl FnOnce(&T) + Send + 'static) {
    if in_bubble() {
        panic!("synctest.Test called from within a bubble");
    }
    let child = t.synctest_child();
    let bubble = Arc::new(Bubble {
        state: Mutex::new(State {
            root_running: true,
            ..State::default()
        }),
        cv: Condvar::new(),
    });
    let c2 = child.clone();
    let b2 = bubble.clone();
    start_thread(&bubble, move || {
        super::t::t_runner(&c2, f);
        b2.state.lock().unwrap().root_running = false;
    });
    // The bubble ends when its last thread has exited.
    let mut deadlocked = false;
    {
        let mut st = bubble.state.lock().unwrap();
        loop {
            if st.total == 0 {
                break;
            }
            if st.deadlock {
                deadlocked = true;
                break;
            }
            st = bubble.cv.wait(st).unwrap();
        }
    }
    if deadlocked {
        // The blocked threads can never finish; they are abandoned.
        t.fatal(&[&"deadlock: all threads in bubble are durably blocked"]);
    }
    child.c.recv_signal();
    if child.c.failed() {
        t.fail_now();
    }
}
