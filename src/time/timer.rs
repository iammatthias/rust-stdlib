//! Go's timers and tickers: `Sleep`, `NewTimer`, `After`, `AfterFunc`,
//! `NewTicker` and `Tick`, with Go 1.23 channel semantics.
//!
//! Threading model: one background scheduler thread, started on first use,
//! keeps a deadline heap under a mutex and sleeps on a condition variable
//! until the earliest deadline. Channel timers deliver the current [`Time`]
//! with a non-blocking send into a one-slot `std::sync::mpsc::sync_channel`,
//! so a slow receiver never blocks the scheduler and a ticker drops ticks it
//! cannot deliver, as in Go. `AfterFunc` callbacks run on a new thread each
//! time they fire (Go starts a goroutine). There is no async runtime.
//!
//! As in Go 1.23, `Stop` and `Reset` discard a value that fired but was not
//! yet received, so no stale time is received afterwards, and report that
//! case as "the timer was still pending". A timer or ticker whose receiver
//! has been dropped is removed at its next firing.
use super::duration::Duration;
use super::instant::{now, Time};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::sync::mpsc::{
    sync_channel, Receiver, RecvError, RecvTimeoutError, SyncSender, TryRecvError, TrySendError,
};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::time::Instant;

type Callback = Arc<dyn Fn() + Send + Sync>;

enum Action {
    Send(SyncSender<Time>),
    Func(Callback),
}

struct Entry {
    /// Bumped on every reschedule so stale heap items are ignored.
    seq: u64,
    /// `None` when the deadline is beyond `Instant`'s range (never fires).
    when: Option<Instant>,
    period: Option<std::time::Duration>,
    action: Action,
    active: bool,
    /// No handle remains (`after`, or a dropped `Timer`): remove the entry
    /// once it has fired.
    orphan: bool,
}

#[derive(Default)]
struct State {
    heap: BinaryHeap<Reverse<(Instant, u64, u64)>>,
    entries: HashMap<u64, Entry>,
    next_id: u64,
    started: bool,
}

struct Scheduler {
    state: Mutex<State>,
    wake: Condvar,
}

fn scheduler() -> &'static Scheduler {
    static SCHED: OnceLock<Scheduler> = OnceLock::new();
    SCHED.get_or_init(|| Scheduler {
        state: Mutex::new(State::default()),
        wake: Condvar::new(),
    })
}

fn lock() -> MutexGuard<'static, State> {
    scheduler()
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Go's `when`: the deadline for a delay; non-positive fires immediately.
fn deadline(d: Duration) -> Option<Instant> {
    let start = Instant::now();
    match u64::try_from(d.as_nanos()) {
        Ok(nanos) if nanos > 0 => start.checked_add(std::time::Duration::from_nanos(nanos)),
        _ => Some(start),
    }
}

impl State {
    fn schedule(&mut self, id: u64, when: Option<Instant>) {
        let Some(entry) = self.entries.get_mut(&id) else {
            return;
        };
        entry.seq += 1;
        entry.when = when;
        entry.active = true;
        if let Some(when) = when {
            self.heap.push(Reverse((when, id, entry.seq)));
        }
        self.compact();
        if !self.started {
            self.started = true;
            std::thread::Builder::new()
                .name("rust-stdlib-time".into())
                .spawn(run)
                .ok();
        }
        scheduler().wake.notify_one();
    }

    /// Rebuild the heap when stale items (from `reset`, `stop` and removed
    /// entries, which are deleted lazily) dominate, so repeated resets stay
    /// bounded in memory.
    fn compact(&mut self) {
        if self.heap.len() <= 2 * self.entries.len() + 1024 {
            return;
        }
        self.heap = self
            .entries
            .iter()
            .filter(|(_, e)| e.active)
            .filter_map(|(&id, e)| e.when.map(|when| Reverse((when, id, e.seq))))
            .collect();
    }

    fn insert(&mut self, action: Action, period: Option<std::time::Duration>, orphan: bool) -> u64 {
        self.next_id += 1;
        let id = self.next_id;
        self.entries.insert(
            id,
            Entry {
                seq: 0,
                when: None,
                period,
                action,
                active: false,
                orphan,
            },
        );
        id
    }
}

/// The scheduler loop: fire due entries, then sleep until the next one.
fn run() {
    let sched = scheduler();
    let mut state = lock();
    loop {
        let now_instant = Instant::now();
        let mut callbacks = Vec::new();
        while let Some(&Reverse((when, id, seq))) = state.heap.peek() {
            if when > now_instant {
                break;
            }
            state.heap.pop();
            let Some(entry) = state.entries.get_mut(&id) else {
                continue;
            };
            if !entry.active || entry.seq != seq {
                continue;
            }
            let mut keep = true;
            match &entry.action {
                Action::Send(tx) => match tx.try_send(now()) {
                    Ok(()) | Err(TrySendError::Full(_)) => {}
                    Err(TrySendError::Disconnected(_)) => keep = false,
                },
                Action::Func(f) => callbacks.push(Arc::clone(f)),
            }
            match (keep, entry.period) {
                (true, Some(period)) => {
                    // Go skips ticks that are already in the past.
                    let late = now_instant.duration_since(when).as_nanos();
                    let missed = late / period.as_nanos().max(1);
                    let step = period.as_nanos().saturating_mul(missed + 1);
                    let next = u64::try_from(step)
                        .ok()
                        .and_then(|n| when.checked_add(std::time::Duration::from_nanos(n)));
                    entry.when = next;
                    entry.seq += 1;
                    if let Some(next) = next {
                        let seq = entry.seq;
                        state.heap.push(Reverse((next, id, seq)));
                    }
                }
                (true, None) if !entry.orphan => entry.active = false,
                _ => {
                    state.entries.remove(&id);
                }
            }
        }
        if !callbacks.is_empty() {
            drop(state);
            for f in callbacks {
                std::thread::spawn(move || f());
            }
            state = lock();
            continue;
        }
        state = match state.heap.peek() {
            Some(&Reverse((when, _, _))) => {
                let wait = when.saturating_duration_since(Instant::now());
                sched
                    .wake
                    .wait_timeout(state, wait)
                    .map(|(guard, _)| guard)
                    .unwrap_or_else(|poisoned| poisoned.into_inner().0)
            }
            None => sched
                .wake
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        };
    }
}

/// Stop `id`, draining a fired-but-unreceived value from `rx`. Returns
/// whether the timer was still pending (Go 1.23 `Stop`).
fn stop(id: u64, rx: Option<&Channel>) -> bool {
    let mut state = lock();
    let mut pending = false;
    if let Some(entry) = state.entries.get_mut(&id) {
        pending = entry.active;
        entry.active = false;
        entry.seq += 1;
    }
    // The scheduler sends only while holding the lock, so nothing can
    // arrive between this drain and the deactivation above.
    if let Some(rx) = rx {
        // A receiver blocked in `recv` holds the lock and by definition
        // sees an empty channel, so there is nothing to drain.
        if let Some(Ok(guard)) = rx.rx.as_ref().map(Mutex::try_lock) {
            while guard.try_recv().is_ok() {
                pending = true;
            }
        }
    }
    pending
}

/// The receiving half of a [`Timer`] or [`Ticker`] (Go's `C`).
///
/// It mirrors the `std::sync::mpsc::Receiver` methods but takes `&self` and
/// is `Sync`, so a timer can be shared between threads. Concurrent receivers
/// take turns; each time is delivered to exactly one of them. The channel of
/// an [`after_func`] timer holds no receiver at all: it never delivers, like
/// Go's nil channel.
#[derive(Debug)]
pub struct Channel {
    rx: Option<Mutex<Receiver<Time>>>,
}

impl Channel {
    fn new(rx: Option<Receiver<Time>>) -> Channel {
        Channel {
            rx: rx.map(Mutex::new),
        }
    }

    fn guard(rx: &Mutex<Receiver<Time>>) -> MutexGuard<'_, Receiver<Time>> {
        rx.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Wait for the next time; blocks forever on an [`after_func`] timer.
    pub fn recv(&self) -> Result<Time, RecvError> {
        match &self.rx {
            Some(rx) => Self::guard(rx).recv(),
            None => loop {
                std::thread::park();
            },
        }
    }

    /// Take a time that has already been delivered, without blocking. While
    /// another thread is waiting in [`Channel::recv`] or
    /// [`Channel::recv_timeout`] the channel counts as empty.
    pub fn try_recv(&self) -> Result<Time, TryRecvError> {
        match self.rx.as_ref().map(Mutex::try_lock) {
            Some(Ok(rx)) => rx.try_recv(),
            Some(Err(std::sync::TryLockError::Poisoned(p))) => p.into_inner().try_recv(),
            _ => Err(TryRecvError::Empty),
        }
    }

    /// Wait up to `timeout` for the next time.
    pub fn recv_timeout(&self, timeout: std::time::Duration) -> Result<Time, RecvTimeoutError> {
        match &self.rx {
            Some(rx) => Self::guard(rx).recv_timeout(timeout),
            None => {
                std::thread::sleep(timeout);
                Err(RecvTimeoutError::Timeout)
            }
        }
    }
}

/// Go's `time.Timer`: a single event. For [`Timer::new`] the current time is
/// delivered on [`Timer::c`]; for [`after_func`] the callback runs instead and
/// `c` never receives (Go's nil channel).
///
/// Like Go's `*time.Timer` it is `Send + Sync`: `stop` and `reset` may be
/// called from several threads at once.
pub struct Timer {
    /// Go's `C`.
    pub c: Channel,
    id: u64,
}

impl std::fmt::Debug for Timer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Timer").field("id", &self.id).finish()
    }
}

/// Go's `After`: the channel of a new timer.
pub fn after(d: Duration) -> Channel {
    let (tx, rx) = sync_channel(1);
    let mut state = lock();
    let id = state.insert(Action::Send(tx), None, true);
    state.schedule(id, deadline(d));
    Channel::new(Some(rx))
}

/// Go's `AfterFunc`: call `f` on its own thread after at least `d`. `Reset`
/// can make it run again.
pub fn after_func(d: Duration, f: impl Fn() + Send + Sync + 'static) -> Timer {
    let mut state = lock();
    let id = state.insert(Action::Func(Arc::new(f)), None, false);
    state.schedule(id, deadline(d));
    Timer {
        c: Channel::new(None),
        id,
    }
}

impl Timer {
    /// Go's `NewTimer`: send the current time on `c` after at least `d`.
    pub fn new(d: Duration) -> Timer {
        let (tx, rx) = sync_channel(1);
        let mut state = lock();
        let id = state.insert(Action::Send(tx), None, false);
        state.schedule(id, deadline(d));
        Timer {
            c: Channel::new(Some(rx)),
            id,
        }
    }

    /// Go's `Stop`: prevent the timer from firing. Returns `true` if the
    /// call stopped it, `false` if it had already fired (and the value, if
    /// any, was received) or been stopped.
    pub fn stop(&self) -> bool {
        stop(self.id, self.c.rx.is_some().then_some(&self.c))
    }

    /// Go's `Reset`: stop the timer and restart it to fire after `d`.
    /// Returns whether it was still pending.
    pub fn reset(&self, d: Duration) -> bool {
        let pending = self.stop();
        lock().schedule(self.id, deadline(d));
        pending
    }
}

impl Drop for Timer {
    /// A pending timer still fires after its handle is dropped, as in Go;
    /// its entry is then removed.
    fn drop(&mut self) {
        let mut state = lock();
        match state.entries.get_mut(&self.id) {
            Some(entry) if entry.active => entry.orphan = true,
            _ => {
                state.entries.remove(&self.id);
            }
        }
    }
}

/// Go's `time.Ticker`: delivers the current time on [`Ticker::c`] every
/// period, dropping ticks a slow receiver cannot take.
///
/// Like Go's `*time.Ticker` it is `Send + Sync`.
pub struct Ticker {
    /// Go's `C`.
    pub c: Channel,
    id: u64,
}

impl std::fmt::Debug for Ticker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ticker").field("id", &self.id).finish()
    }
}

fn period(d: Duration, what: &str) -> std::time::Duration {
    match u64::try_from(d.as_nanos()) {
        Ok(nanos) if nanos > 0 => std::time::Duration::from_nanos(nanos),
        // Go panics here too.
        _ => panic!("non-positive interval for {what}"),
    }
}

fn start_ticker(d: Duration, orphan: bool) -> (Receiver<Time>, u64) {
    let interval = period(d, "NewTicker");
    let (tx, rx) = sync_channel(1);
    let mut state = lock();
    let id = state.insert(Action::Send(tx), Some(interval), orphan);
    state.schedule(id, deadline(d));
    (rx, id)
}

/// Go's `Tick`: the channel of a new ticker, or `None` (Go's nil channel)
/// when `d` is not positive. The ticker stops once the receiver is dropped.
pub fn tick(d: Duration) -> Option<Channel> {
    (d.as_nanos() > 0).then(|| Channel::new(Some(start_ticker(d, true).0)))
}

impl Ticker {
    /// Go's `NewTicker`. Panics if `d` is not positive, like Go.
    pub fn new(d: Duration) -> Ticker {
        let (c, id) = start_ticker(d, false);
        Ticker {
            c: Channel::new(Some(c)),
            id,
        }
    }

    /// Go's `Stop`: no more ticks are sent; a tick not yet received is
    /// discarded.
    pub fn stop(&self) {
        stop(self.id, Some(&self.c));
    }

    /// Go's `Reset`: stop the ticker and restart it with period `d`.
    /// Panics if `d` is not positive, like Go.
    pub fn reset(&self, d: Duration) {
        let interval = period(d, "Ticker.Reset");
        stop(self.id, Some(&self.c));
        let mut state = lock();
        if let Some(entry) = state.entries.get_mut(&self.id) {
            entry.period = Some(interval);
        }
        state.schedule(self.id, deadline(d));
    }
}

impl Drop for Ticker {
    /// Stopping on drop matches Go 1.23, where unreferenced tickers are
    /// collected.
    fn drop(&mut self) {
        lock().entries.remove(&self.id);
    }
}

/// Go's `Sleep`: pause the current thread for at least `d`; non-positive
/// durations return immediately.
pub fn sleep(d: Duration) {
    if let Ok(nanos) = u64::try_from(d.as_nanos()) {
        if nanos > 0 {
            std::thread::sleep(std::time::Duration::from_nanos(nanos));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_resets_keep_the_heap_bounded() {
        let timer = Timer::new(Duration::from_nanos(3_600_000_000_000));
        for _ in 0..10_000 {
            timer.reset(Duration::from_nanos(3_600_000_000_000));
        }
        let state = lock();
        assert!(state.heap.len() <= 2 * state.entries.len() + 1025);
    }

    fn assert_sync<T: Sync + Send>() {}

    #[test]
    fn timer_and_ticker_are_sync_and_send() {
        assert_sync::<Timer>();
        assert_sync::<Ticker>();
        assert_sync::<Channel>();
    }

    #[test]
    fn concurrent_stop_and_reset() {
        let timer = Arc::new(Timer::new(Duration::from_nanos(3_600_000_000_000)));
        let ticker = Arc::new(Ticker::new(Duration::from_nanos(3_600_000_000_000)));
        let fired = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let f = Arc::clone(&fired);
        let func = Arc::new(after_func(
            Duration::from_nanos(3_600_000_000_000),
            move || {
                f.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            },
        ));
        let hour = Duration::from_nanos(3_600_000_000_000);
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let (timer, ticker, func) =
                    (Arc::clone(&timer), Arc::clone(&ticker), Arc::clone(&func));
                std::thread::spawn(move || {
                    for _ in 0..500 {
                        timer.reset(hour);
                        timer.stop();
                        ticker.reset(hour);
                        ticker.stop();
                        func.reset(hour);
                        func.stop();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        // Everything is stopped: a further Stop reports "not pending".
        assert!(!timer.stop());
        assert!(!func.stop());
        // A receiver blocked on the nil channel must not block `try_recv`.
        let blocked = Arc::clone(&func);
        std::thread::spawn(move || {
            let _ = blocked.c.recv();
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(timer.c.try_recv().is_err());
        assert!(func.c.try_recv().is_err());
        assert_eq!(fired.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(!timer.reset(Duration::from_nanos(1)));
        assert!(timer
            .c
            .recv_timeout(std::time::Duration::from_secs(5))
            .is_ok());
    }
}
