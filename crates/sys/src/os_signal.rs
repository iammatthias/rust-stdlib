//! Go's `os/signal`: relaying incoming signals to channels.
//!
//! As in Go's runtime, the process-level handler only records the signal (here
//! it writes the number to a self-pipe, the async-signal-safe equivalent of
//! the runtime's signal queue); one thread reads the pipe and hands each signal
//! to the registered channels without ever blocking on a full one.
//!
//! A Go `chan<- os.Signal` becomes [`Chan`], the sending half of a bounded
//! `std::sync::mpsc` channel made by [`channel`]; the matching `Receiver` is
//! the receiving half. [`notify_context`] returns a context and a [`Stop`] guard.
//! Signals are `syscall.Signal` ([`Signal`]).
//!
//! Go's runtime installs its own handler for every signal when the program
//! starts and so catches, and ignores, signals nobody asked for (for example
//! `SIGUSR1`). A Rust program has no such start-up code, so here an
//! unregistered signal keeps its default action until the package first
//! handles it; after [`stop`] or [`reset`] a signal returns to what Go's
//! runtime would do with it (terminate for `SIGHUP`, `SIGINT`, `SIGTERM`, ...,
//! ignore for `SIGUSR1`, `SIGWINCH`, ...).
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

pub use crate::errno::{
    Signal, SIGABRT, SIGALRM, SIGCHLD, SIGCONT, SIGHUP, SIGINT, SIGKILL, SIGPIPE, SIGQUIT, SIGSEGV,
    SIGSTOP, SIGTERM, SIGUSR1, SIGUSR2,
};
use crate::ffi::signal as ffi;

/// The number of signals tracked: the maximum across all systems.
const NUM_SIG: usize = 65;

#[cfg(target_os = "linux")]
const NOTIFY: &[u8] = &[
    1, 2, 3, 6, 10, 12, 13, 14, 15, 17, 18, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 35, 36, 37, 38,
    39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62,
    63, 64,
];
/// Signals whose Go-runtime default is the system default (kill, throw or
/// leave alone); the other notifiable signals are caught and ignored.
#[cfg(target_os = "linux")]
const GO_DEFAULT: &[u8] = &[1, 2, 3, 6, 15, 18, 20, 21, 22];

#[cfg(target_os = "macos")]
const NOTIFY: &[u8] = &[
    1, 2, 3, 6, 13, 14, 15, 16, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];
#[cfg(target_os = "macos")]
const GO_DEFAULT: &[u8] = &[1, 2, 3, 6, 15, 18, 19, 21, 22];

/// Go's `signum`: the index of a signal, or `None` for one out of range.
fn signum(sig: Signal) -> Option<usize> {
    usize::try_from(sig.0).ok().filter(|&n| n < NUM_SIG)
}

/// Whether Go's runtime lets a program take over `n` (`_SigNotify`).
fn notifiable(n: usize) -> bool {
    NOTIFY.contains(&(n as u8))
}

/// `SIGPROF` has the same number on Linux and macOS. Go's runtime owns it
/// for profiling: its handler runs before any delivery to channels, so a
/// program that asks for it keeps running but never receives it.
const SIGPROF: usize = 27;

type Mask = [u32; NUM_SIG.div_ceil(32)];

fn want(m: &Mask, n: usize) -> bool {
    (m[n / 32] >> (n & 31)) & 1 != 0
}

struct Entry {
    id: u64,
    tx: SyncSender<Signal>,
    mask: Mask,
}

struct State {
    inited: bool,
    started: bool,
    handlers: Vec<Entry>,
    refs: [i64; NUM_SIG],
    stopping: Vec<Entry>,
    /// Go's `sig.ignored`.
    ignored: [bool; NUM_SIG],
    /// Whether the self-pipe handler is installed for the signal.
    handling: [bool; NUM_SIG],
    /// `SIGHUP` or `SIGINT` inherited as ignored (Go keeps those ignored).
    init_ignored: [bool; NUM_SIG],
}

impl State {
    fn new() -> State {
        State {
            inited: false,
            started: false,
            handlers: Vec::new(),
            refs: [0; NUM_SIG],
            stopping: Vec::new(),
            ignored: [false; NUM_SIG],
            handling: [false; NUM_SIG],
            init_ignored: [false; NUM_SIG],
        }
    }
}

static STATE: OnceLock<Mutex<State>> = OnceLock::new();
static PROCESSED: AtomicU64 = AtomicU64::new(0);
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn lock() -> MutexGuard<'static, State> {
    let mut g = STATE
        .get_or_init(|| Mutex::new(State::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if !g.inited {
        g.inited = true;
        // Go's initsig: remember which of SIGHUP and SIGINT arrived ignored.
        for sig in [SIGHUP, SIGINT] {
            if let Some(n) = signum(sig) {
                if ffi::disposition(sig.0) == Ok(ffi::Disposition::Ignore) {
                    g.init_ignored[n] = true;
                    g.ignored[n] = true;
                }
            }
        }
    }
    g
}

/// The sending half of a signal channel (Go's `chan<- os.Signal`). Clones
/// refer to the same channel.
#[derive(Clone)]
pub struct Chan {
    id: u64,
    tx: SyncSender<Signal>,
}

impl PartialEq for Chan {
    fn eq(&self, other: &Chan) -> bool {
        self.id == other.id
    }
}

impl Eq for Chan {}

impl fmt::Debug for Chan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Chan({})", self.id)
    }
}

/// Makes a signal channel with room for `buffer` pending signals
/// (`make(chan os.Signal, buffer)`). Signals that find it full are dropped, as
/// Go documents, so use a buffer of at least one for [`notify`].
pub fn channel(buffer: usize) -> (Chan, Receiver<Signal>) {
    let (tx, rx) = mpsc::sync_channel(buffer);
    (
        Chan {
            id: NEXT_ID.fetch_add(1, Ordering::SeqCst),
            tx,
        },
        rx,
    )
}

/// Starts the signal pipe and the thread relaying from it (Go's
/// `signal_enable` first-call setup and `watchSignalLoop`).
fn ensure_started(s: &mut State) {
    if s.started {
        return;
    }
    s.started = true;
    if ffi::init_pipe().is_err() {
        return;
    }
    thread::Builder::new()
        .name("os/signal".into())
        .spawn(|| loop {
            match ffi::read_signal() {
                Ok(n) => {
                    process(Signal(i32::from(n)));
                    PROCESSED.fetch_add(1, Ordering::SeqCst);
                }
                Err(_) => return,
            }
        })
        .ok();
}

/// Go's `process`: delivers `sig` to every channel that wants it, dropping
/// the signal for channels that are full.
fn process(sig: Signal) {
    let Some(n) = signum(sig) else {
        return;
    };
    if n == SIGPROF {
        return;
    }
    let s = lock();
    for e in s.handlers.iter().chain(s.stopping.iter()) {
        if want(&e.mask, n) {
            match e.tx.try_send(sig) {
                Ok(()) | Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {}
            }
        }
    }
}

/// Go's `signal_enable`: the signal is wanted, so stop ignoring it and make
/// sure the handler is installed.
fn enable_signal(s: &mut State, n: usize) {
    ensure_started(s);
    s.ignored[n] = false;
    if notifiable(n) && !s.handling[n] {
        s.handling[n] = true;
        let _ = ffi::install_handler(n as i32);
    }
}

/// Go's `signal_disable`: nobody wants the signal any more.
fn disable_signal(s: &mut State, n: usize) {
    if !notifiable(n) {
        return;
    }
    if s.init_ignored[n] {
        // SIGHUP/SIGINT inherited as ignored: go back to ignoring them.
        s.handling[n] = false;
        let _ = ffi::set_disposition(n as i32, ffi::Disposition::Ignore);
    } else if !s.ignored[n] {
        // Back to what Go's runtime does with an unwanted signal.
        s.handling[n] = false;
        let d = if GO_DEFAULT.contains(&(n as u8)) {
            ffi::Disposition::Default
        } else {
            ffi::Disposition::Ignore
        };
        let _ = ffi::set_disposition(n as i32, d);
    }
}

/// Go's `signal_ignore`.
fn ignore_signal(s: &mut State, n: usize) {
    s.ignored[n] = true;
    if notifiable(n) {
        s.handling[n] = false;
        let _ = ffi::set_disposition(n as i32, ffi::Disposition::Ignore);
    }
}

/// Go's `cancel`: removes the signals (all of them if `sigs` is empty) from
/// every channel and applies `action` to each.
fn cancel(sigs: &[Signal], action: fn(&mut State, usize)) {
    let mut s = lock();
    let remove = |s: &mut State, n: usize| {
        for i in 0..s.handlers.len() {
            if want(&s.handlers[i].mask, n) {
                s.refs[n] -= 1;
                s.handlers[i].mask[n / 32] &= !(1 << (n & 31));
            }
        }
        s.handlers.retain(|e| e.mask.iter().any(|&w| w != 0));
        action(s, n);
    };
    if sigs.is_empty() {
        for n in 0..NUM_SIG {
            remove(&mut s, n);
        }
    } else {
        for &sig in sigs {
            if let Some(n) = signum(sig) {
                remove(&mut s, n);
            }
        }
    }
}

/// Go's `signal.Ignore`: causes the provided signals to be ignored, undoing
/// any [`notify`] for them. With no signals, all are ignored.
pub fn ignore(sigs: &[Signal]) {
    cancel(sigs, ignore_signal);
}

/// Go's `signal.Ignored`: whether `sig` is currently ignored.
pub fn ignored(sig: Signal) -> bool {
    match signum(sig) {
        Some(n) => lock().ignored[n],
        None => false,
    }
}

/// Go's `signal.Notify`: causes the package to relay incoming signals to `c`.
/// With no signals, all incoming signals are relayed. Sends never block: if
/// `c` is full the signal is dropped, so give the channel a buffer.
///
/// Go panics for a nil channel; a [`Chan`] cannot be nil. Allowed to be called
/// many times with the same channel: the sets of signals are united.
pub fn notify(c: &Chan, sigs: &[Signal]) {
    let mut s = lock();
    let add = |s: &mut State, n: usize| {
        let idx = match s.handlers.iter().position(|e| e.id == c.id) {
            Some(i) => i,
            None => {
                s.handlers.push(Entry {
                    id: c.id,
                    tx: c.tx.clone(),
                    mask: Mask::default(),
                });
                s.handlers.len() - 1
            }
        };
        if !want(&s.handlers[idx].mask, n) {
            s.handlers[idx].mask[n / 32] |= 1 << (n & 31);
            if s.refs[n] == 0 {
                enable_signal(s, n);
            }
            s.refs[n] += 1;
        }
    };
    if sigs.is_empty() {
        for n in 0..NUM_SIG {
            add(&mut s, n);
        }
    } else {
        for &sig in sigs {
            if let Some(n) = signum(sig) {
                add(&mut s, n);
            }
        }
    }
}

/// Go's `signal.Reset`: undoes the effect of any prior [`notify`] for the
/// provided signals. With no signals, all are reset.
pub fn reset(sigs: &[Signal]) {
    cancel(sigs, disable_signal);
}

/// Go's `signal.Stop`: causes the package to stop relaying incoming signals to
/// `c`. When it returns, `c` will receive no more signals.
pub fn stop(c: &Chan) {
    let mut s = lock();
    let Some(i) = s.handlers.iter().position(|e| e.id == c.id) else {
        return;
    };
    let entry = s.handlers.remove(i);
    for n in 0..NUM_SIG {
        if want(&entry.mask, n) {
            s.refs[n] -= 1;
            if s.refs[n] == 0 {
                disable_signal(&mut s, n);
            }
        }
    }
    // A signal already queued for the channel is still delivered, so the
    // entry stays visible to `process` until the queue has drained.
    s.stopping.push(Entry {
        id: entry.id,
        tx: entry.tx,
        mask: entry.mask,
    });
    drop(s);

    wait_until_idle();

    let mut s = lock();
    if let Some(i) = s.stopping.iter().position(|e| e.id == c.id) {
        s.stopping.remove(i);
    }
}

/// Go's `signalWaitUntilIdle`: waits until every signal queued so far has
/// been handed to its channels.
fn wait_until_idle() {
    let target = ffi::received();
    let deadline = Instant::now() + Duration::from_secs(5);
    while PROCESSED.load(Ordering::SeqCst) < target && Instant::now() < deadline {
        thread::sleep(Duration::from_micros(200));
    }
}

/// The cause of a [`NotifyContext`] ending: Go's `signalError`, whose text is
/// `"<signal> signal received"` and which `Is` `context.Canceled`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalError(pub String);

impl fmt::Display for SignalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SignalError {}

/// Why a [`NotifyContext`] ended (`context.Cause`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cause {
    /// [`Stop::stop`] was called (or the [`Stop`] dropped): `context.Canceled`.
    Canceled,
    /// A listed signal arrived.
    Signal(SignalError),
    /// The parent context ended. A [`Parent`] only reports that its done
    /// channel closed, not whether it was cancelled or timed out; read the
    /// parent's own `err` and `cause` for that.
    Parent,
}

/// The parent of a [`notify_context`]: a name for [`Display`](fmt::Display)
/// and the receiver of the parent's done channel.
///
/// This crate cannot depend on the root crate (docs/adr/0004), so it cannot
/// name `rust_stdlib::context::Context`. The root crate's `Context` fits
/// through two std types, its `Display` text and `done().receiver()`, a
/// `std::sync::mpsc::Receiver<()>` that disconnects when the context ends:
///
/// ```ignore
/// let (ctx, _cancel) = rust_stdlib::context::Context::background().with_cancel();
/// let parent = Parent::new(&ctx, ctx.done().receiver());
/// ```
pub struct Parent {
    name: String,
    done: Option<Receiver<()>>,
}

impl Parent {
    /// A parent that never ends: Go's `context.Background()`.
    pub fn background() -> Parent {
        Parent {
            name: "context.Background".to_owned(),
            done: None,
        }
    }

    /// A parent named `name` (its `Context.String()`) that ends when `done`
    /// disconnects or yields a value.
    pub fn new(name: &dyn fmt::Display, done: Receiver<()>) -> Parent {
        Parent {
            name: name.to_string(),
            done: Some(done),
        }
    }
}

impl Default for Parent {
    fn default() -> Parent {
        Parent::background()
    }
}

type Callback = Box<dyn FnOnce(&Cause) + Send>;

struct CtxInner {
    chan: Chan,
    signals: Vec<Signal>,
    name: String,
    cause: Mutex<Option<Cause>>,
    ended: Condvar,
    callbacks: Mutex<Vec<Callback>>,
}

/// The context [`notify_context`] returns, reduced to what this crate can
/// express: this crate has no `context` package, so the context is an object
/// that can be waited on, asked for its cause, and linked to a
/// `rust_stdlib::context` cancel function with [`on_cancel`](Self::on_cancel).
#[derive(Clone)]
pub struct NotifyContext(Arc<CtxInner>);

impl NotifyContext {
    fn finish(&self, cause: Cause) {
        let mut slot = self.0.cause.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_some() {
            return;
        }
        *slot = Some(cause.clone());
        drop(slot);
        self.0.ended.notify_all();
        let callbacks =
            std::mem::take(&mut *self.0.callbacks.lock().unwrap_or_else(|e| e.into_inner()));
        for f in callbacks {
            f(&cause);
        }
    }

    /// Whether the context is done (`Err() != nil`).
    pub fn is_done(&self) -> bool {
        self.cause().is_some()
    }

    /// `context.Cause`: why the context ended, if it has.
    pub fn cause(&self) -> Option<Cause> {
        self.0.cause.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Waits for the context to end and returns the cause.
    pub fn wait(&self) -> Cause {
        let mut slot = self.0.cause.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(c) = slot.as_ref() {
                return c.clone();
            }
            slot = self.0.ended.wait(slot).unwrap_or_else(|e| e.into_inner());
        }
    }

    /// Waits up to `timeout` for the context to end.
    pub fn wait_timeout(&self, timeout: Duration) -> Option<Cause> {
        let slot = self.0.cause.lock().unwrap_or_else(|e| e.into_inner());
        let (slot, _) = self
            .0
            .ended
            .wait_timeout_while(slot, timeout, |c| c.is_none())
            .unwrap_or_else(|e| e.into_inner());
        slot.clone()
    }

    /// Runs `f` once the context ends (immediately if it already has). Use it
    /// to cancel a `rust_stdlib::context` with the cause.
    pub fn on_cancel(&self, f: impl FnOnce(&Cause) + Send + 'static) {
        let mut callbacks = self.0.callbacks.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = self.cause() {
            drop(callbacks);
            f(&c);
        } else {
            callbacks.push(Box::new(f));
        }
    }
}

impl fmt::Display for NotifyContext {
    /// Go's `signalCtx.String`: `signal.NotifyContext(<parent>, [sig sig])`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "signal.NotifyContext({}", self.0.name)?;
        if !self.0.signals.is_empty() {
            let names: Vec<String> = self.0.signals.iter().map(|s| s.to_string()).collect();
            write!(f, ", [{}]", names.join(" "))?;
        }
        f.write_str(")")
    }
}

/// The `stop` function [`notify_context`] returns in Go, as a guard: ends the
/// context (with cause [`Cause::Canceled`]) and stops relaying signals, either
/// by [`stop`](Self::stop) or when dropped (Go's `defer stop()`). Bind it to a
/// name; `let (ctx, _) = ...` would drop it at once.
#[must_use = "dropping the guard stops the signal context immediately"]
pub struct Stop(NotifyContext);

impl Stop {
    /// Ends the context and stops relaying signals. Idempotent.
    pub fn stop(&self) {
        self.0.finish(Cause::Canceled);
        stop(&self.0 .0.chan);
    }
}

impl Drop for Stop {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Go's `signal.NotifyContext`: a context that ends when one of the listed
/// signals arrives, the returned [`Stop`] stops or drops, or `parent` ends.
/// Use [`Parent::background`] for a root.
///
/// Graceful shutdown: catch `SIGTERM` and `SIGINT`, then shut an
/// `net::http::Server` down. (The example is not compiled here because this
/// crate does not depend on the root crate.)
///
/// ```ignore
/// use rust_stdlib::net::http::Server;
/// use rust_stdlib::context::Context;
/// use rust_stdlib_sys::os::signal::{notify_context, Parent, SIGINT, SIGTERM};
/// use std::sync::Arc;
/// use std::time::Duration;
///
/// let root = Context::background();
/// let (ctx, stop) = notify_context(
///     Parent::new(&root, root.done().receiver()),
///     &[SIGINT, SIGTERM],
/// );
/// let mut server = Server::new();
/// server.addr = "127.0.0.1:8080".to_owned();
/// server.handler = Some(handler); // an Arc<dyn Handler>
/// let server = Arc::new(server);
/// let serving = {
///     let server = Arc::clone(&server);
///     std::thread::spawn(move || server.listen_and_serve())
/// };
/// ctx.wait(); // blocks until a signal arrives
/// stop.stop(); // restore default signal behaviour: a second signal kills us
/// let (grace, _cancel) = root.with_timeout(Duration::from_secs(10));
/// server.shutdown(&grace).ok();
/// serving.join().ok();
/// ```
pub fn notify_context(parent: Parent, signals: &[Signal]) -> (NotifyContext, Stop) {
    let (chan, rx) = channel(1);
    let ctx = NotifyContext(Arc::new(CtxInner {
        chan: chan.clone(),
        signals: signals.to_vec(),
        name: parent.name,
        cause: Mutex::new(None),
        ended: Condvar::new(),
        callbacks: Mutex::new(Vec::new()),
    }));
    notify(&chan, signals);
    let waiter = ctx.clone();
    let parent_done = parent.done;
    thread::spawn(move || loop {
        if waiter.is_done() {
            return;
        }
        if let Some(done) = &parent_done {
            // Nothing is ever sent: Disconnected means the parent ended.
            if matches!(done.try_recv(), Err(mpsc::TryRecvError::Disconnected) | Ok(())) {
                waiter.finish(Cause::Parent);
                return;
            }
        }
        match rx.recv_timeout(Duration::from_millis(20)) {
            Ok(s) => {
                waiter.finish(Cause::Signal(SignalError(format!("{s} signal received"))));
                return;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
    });
    (ctx.clone(), Stop(ctx))
}
