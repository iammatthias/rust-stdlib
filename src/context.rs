//! Go's `context` package: cancellation, deadlines, causes and request-scoped
//! values, built on std threads, mutexes and condition variables.
//!
//! `Context` is a cheaply clonable handle (Go's interface becomes a concrete
//! type, so custom `Context` implementations are not possible). Cancellation
//! is event driven: `Done::wait` blocks on a condition variable, deadlines are
//! delivered by one lazily started timer thread that sleeps until the earliest
//! deadline, and nothing polls. Deadlines are also enforced lazily, so `err()`
//! and `Done` report expiry the moment the `Instant` passes regardless of timer
//! thread latency. A context cannot forcibly interrupt user code.
//!
//! Deviations from Go: deadlines are `Instant`s; keys are typed [`Key`]s;
//! `Done` is a handle (with an `mpsc::Receiver` adapter) instead of a channel;
//! cancel functions are `Arc<dyn Fn>` and are called as `cancel()`.
//!
//! Constructors are methods: [`Context::background`] makes a root and
//! `ctx.with_cancel()`, `with_timeout`, `with_deadline`, `with_value` and
//! `without_cancel` derive children from it.
//!
//! ```
//! use rust_stdlib::context::{Context, Error};
//! let (ctx, cancel) = Context::background().with_cancel();
//! assert_eq!(ctx.err(), None);
//! cancel();
//! assert_eq!(ctx.err(), Some(Error::Canceled));
//! ```
use crate::time::Duration;
use std::{
    any::{Any, TypeId},
    collections::{BTreeMap, VecDeque},
    error, fmt,
    marker::PhantomData,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, Sender},
        Arc, Condvar, Mutex, MutexGuard, Once, OnceLock, Weak,
    },
    thread,
    time::{Duration as StdDuration, Instant},
};

/// Go's `context.Canceled` and `context.DeadlineExceeded` error values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// `context.Canceled`: "context canceled".
    Canceled,
    /// `context.DeadlineExceeded`: "context deadline exceeded".
    DeadlineExceeded,
}

impl Error {
    /// Go's `deadlineExceededError.Timeout`; `Canceled` has no such method in
    /// Go, which this reports as `false`.
    pub fn timeout(&self) -> bool {
        matches!(self, Self::DeadlineExceeded)
    }
    /// Go's `deadlineExceededError.Temporary`; `false` for `Canceled`.
    pub fn temporary(&self) -> bool {
        matches!(self, Self::DeadlineExceeded)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Canceled => "context canceled",
            Self::DeadlineExceeded => "context deadline exceeded",
        })
    }
}
impl error::Error for Error {}

/// The error type of `Cause` and of `CancelCauseFunc` arguments.
pub type CauseError = Arc<dyn error::Error + Send + Sync + 'static>;
/// Go's `context.CancelFunc`; call it as `cancel()`. Idempotent.
pub type CancelFunc = Arc<dyn Fn() + Send + Sync>;
/// Go's `context.CancelCauseFunc`; `None` records `Canceled` as the cause.
pub type CancelCauseFunc = Arc<dyn Fn(Option<CauseError>) + Send + Sync>;
/// Function returned by [`Context::after_func`]; returns Go's `stop()` result.
pub type StopFunc = Arc<dyn Fn() -> bool + Send + Sync>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyId {
    Unique(u64),
    Type(TypeId),
}
/// A typed context key. Each [`Key::new`] is distinct (like a pointer key in
/// Go); [`Key::of_type`] is equal for all keys of the same `T` (like a
/// dedicated key type in Go).
pub struct Key<T> {
    id: KeyId,
    name: Option<&'static str>,
    marker: PhantomData<fn() -> T>,
}
impl<T> Clone for Key<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for Key<T> {}
impl<T: Any + Send + Sync> Key<T> {
    fn unique(name: Option<&'static str>) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self {
            id: KeyId::Unique(NEXT.fetch_add(1, Ordering::Relaxed)),
            name,
            marker: PhantomData,
        }
    }
    /// A key distinct from every other key.
    pub fn new() -> Self {
        Self::unique(None)
    }
    /// A distinct key whose `name` appears in `Display` output.
    pub fn named(name: &'static str) -> Self {
        Self::unique(Some(name))
    }
    /// The key identified by the value type `T`.
    pub fn of_type() -> Self {
        Self {
            id: KeyId::Type(TypeId::of::<T>()),
            name: None,
            marker: PhantomData,
        }
    }
}
impl<T: Any + Send + Sync> Default for Key<T> {
    fn default() -> Self {
        Self::new()
    }
}

type AfterFn = Box<dyn FnOnce() + Send>;

enum Kind {
    Background,
    Todo,
    Cancel,
    Timer {
        cause: Option<CauseError>,
    },
    AfterFunc(Mutex<Option<AfterFn>>),
    WithoutCancel,
    Value {
        key: KeyId,
        key_label: &'static str,
        key_name: Option<&'static str>,
        value: Arc<dyn Any + Send + Sync>,
        value_type: &'static str,
    },
}

enum Child {
    // Ordinary children are weak so dropped contexts are freed.
    Weak(Weak<Node>),
    // AfterFunc nodes must fire even if the caller dropped the stop function.
    Strong(Arc<Node>),
}

struct CoreState {
    err: Option<Error>,
    cause: Option<CauseError>,
    children: BTreeMap<u64, Child>,
    next_prune_at: usize,
    receivers: Vec<Sender<()>>,
    timer_key: Option<(Instant, u64)>,
}
struct Core {
    state: Mutex<CoreState>,
    changed: Condvar,
}
impl Core {
    fn new() -> Self {
        Self {
            state: Mutex::new(CoreState {
                err: None,
                cause: None,
                children: BTreeMap::new(),
                next_prune_at: 64,
                receivers: Vec::new(),
                timer_key: None,
            }),
            changed: Condvar::new(),
        }
    }
    fn lock(&self) -> MutexGuard<'_, CoreState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

struct Node {
    id: u64,
    kind: Kind,
    // A child keeps its direct parent alive; reverse links are weak.
    parent: Option<Context>,
    deadline: Option<Instant>,
    core: Option<Core>,
}
impl Drop for Node {
    fn drop(&mut self) {
        if let Some(core) = &mut self.core {
            let key = core
                .state
                .get_mut()
                .unwrap_or_else(|e| e.into_inner())
                .timer_key
                .take();
            if let Some(key) = key {
                timers().remove(key);
            }
        }
        // Parent links form a linear strong chain. Dismantle a uniquely owned
        // chain iteratively so dropping a very deep context does not recurse.
        let mut parent = self.parent.take();
        while let Some(Context(link)) = parent {
            match Arc::try_unwrap(link) {
                Ok(mut node) => parent = node.parent.take(),
                Err(shared) => {
                    drop(shared);
                    parent = None;
                }
            }
        }
    }
}

/// Go's `context.Context`: a clonable handle. Clones share cancellation.
#[derive(Clone)]
pub struct Context(Arc<Node>);

fn new_context(kind: Kind, parent: Option<&Context>, deadline: Option<Instant>) -> Context {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let cancelable = matches!(kind, Kind::Cancel | Kind::Timer { .. } | Kind::AfterFunc(_));
    Context(Arc::new(Node {
        id: NEXT.fetch_add(1, Ordering::Relaxed),
        kind,
        parent: parent.cloned(),
        deadline,
        core: cancelable.then(Core::new),
    }))
}

impl Default for Context {
    fn default() -> Self {
        Context::background()
    }
}

impl Context {
    /// Go's `context.Background`: never canceled, no deadline, no values.
    pub fn background() -> Context {
        new_context(Kind::Background, None, None)
    }

    /// Go's `context.TODO`.
    pub fn todo() -> Context {
        new_context(Kind::Todo, None, None)
    }

    /// The nearest ancestor (or self) that can be canceled, stopping at
    /// `WithoutCancel` and the roots.
    fn cancel_node(&self) -> Option<&Context> {
        let mut cur = self;
        loop {
            match cur.0.kind {
                Kind::Cancel | Kind::Timer { .. } | Kind::AfterFunc(_) => return Some(cur),
                Kind::Background | Kind::Todo | Kind::WithoutCancel => return None,
                Kind::Value { .. } => cur = cur.0.parent.as_ref()?,
            }
        }
    }

    fn core(&self) -> &Core {
        self.0.core.as_ref().expect("cancelable context")
    }

    /// Cancel the owning timer context if the effective deadline has passed.
    fn expire_if_due(&self) {
        let Some(deadline) = self.0.deadline else {
            return;
        };
        if Instant::now() < deadline {
            return;
        }
        let mut cur = self;
        loop {
            match &cur.0.kind {
                Kind::Timer { cause } => {
                    cancel(cur, true, Error::DeadlineExceeded, cause.clone());
                    return;
                }
                Kind::Cancel | Kind::AfterFunc(_) | Kind::Value { .. } => match &cur.0.parent {
                    Some(parent) => cur = parent,
                    None => return,
                },
                _ => return,
            }
        }
    }

    /// Go's `Context.Deadline`.
    pub fn deadline(&self) -> Option<Instant> {
        self.0.deadline
    }

    /// Go's `Context.Done`.
    pub fn done(&self) -> Done {
        Done {
            node: self.cancel_node().cloned(),
        }
    }

    /// Go's `Context.Err`: `None` until the context is done, then `Canceled`
    /// or `DeadlineExceeded`.
    pub fn err(&self) -> Option<Error> {
        let node = self.cancel_node()?;
        self.expire_if_due();
        node.core().lock().err
    }

    /// Go's `Context.Value` with a typed key.
    pub fn value<T: Any + Send + Sync>(&self, key: &Key<T>) -> Option<Arc<T>> {
        let mut cur = self;
        loop {
            match &cur.0.kind {
                Kind::Value { key: k, value, .. } if *k == key.id => {
                    return value.clone().downcast::<T>().ok();
                }
                Kind::Background | Kind::Todo => return None,
                _ => cur = cur.0.parent.as_ref()?,
            }
        }
    }

    /// Rust convenience: `Err(err)` once done, `Ok(())` otherwise.
    pub fn check(&self) -> Result<(), Error> {
        self.err().map_or(Ok(()), Err)
    }
}

impl fmt::Display for Context {
    /// Go's `Context.String` formats, for example `context.Background.WithCancel`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut chain = vec![self];
        let mut cur = self;
        while let Some(parent) = &cur.0.parent {
            chain.push(parent);
            cur = parent;
        }
        for ctx in chain.into_iter().rev() {
            match &ctx.0.kind {
                Kind::Background => f.write_str("context.Background")?,
                Kind::Todo => f.write_str("context.TODO")?,
                Kind::Cancel | Kind::AfterFunc(_) => f.write_str(".WithCancel")?,
                Kind::WithoutCancel => f.write_str(".WithoutCancel")?,
                Kind::Timer { .. } => {
                    let deadline = ctx.0.deadline.unwrap_or_else(Instant::now);
                    let now = Instant::now();
                    let nanos = |d: StdDuration| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX);
                    let until = if deadline >= now {
                        nanos(deadline - now)
                    } else {
                        -nanos(now - deadline)
                    };
                    let until = Duration::from_nanos(until);
                    write!(
                        f,
                        ".WithDeadline({} [{}])",
                        crate::time::now().add(until),
                        until
                    )?;
                }
                Kind::Value {
                    key_label,
                    key_name,
                    value,
                    value_type,
                    ..
                } => {
                    let shown = value
                        .downcast_ref::<String>()
                        .map(String::as_str)
                        .or_else(|| value.downcast_ref::<&'static str>().copied())
                        .unwrap_or(value_type);
                    write!(
                        f,
                        ".WithValue({}, {})",
                        key_name.unwrap_or(key_label),
                        shown
                    )?;
                }
            }
        }
        Ok(())
    }
}
impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Go's `ctx.Done()` channel as a waitable handle. A context that can never
/// be canceled (Background, TODO, WithoutCancel) yields a handle that never
/// fires, like a nil channel.
#[derive(Clone)]
pub struct Done {
    node: Option<Context>,
}
impl Done {
    /// True for contexts that can never be done (Go's nil `Done()` channel).
    pub fn is_never(&self) -> bool {
        self.node.is_none()
    }

    /// Non-blocking check: has the context been canceled or expired?
    pub fn is_done(&self) -> bool {
        let Some(node) = &self.node else {
            return false;
        };
        node.expire_if_due();
        node.core().lock().err.is_some()
    }

    /// Block until done. Never returns for a never-done handle.
    pub fn wait(&self) {
        if self.node.is_none() {
            loop {
                thread::park();
            }
        }
        self.wait_until(None);
    }

    /// Block for at most `timeout`; true if the context became done.
    pub fn wait_timeout(&self, timeout: Duration) -> bool {
        if self.node.is_none() {
            thread::sleep(timeout.to_std());
            return false;
        }
        self.wait_until(Instant::now().checked_add(timeout.to_std()))
    }

    fn wait_until(&self, limit: Option<Instant>) -> bool {
        let Some(node) = &self.node else {
            return false;
        };
        let core = node.core();
        loop {
            node.expire_if_due();
            let state = core.lock();
            if state.err.is_some() {
                return true;
            }
            let now = Instant::now();
            if limit.is_some_and(|l| now >= l) {
                return false;
            }
            let wake = match (limit, node.0.deadline) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            match wake {
                None => drop(core.changed.wait(state).unwrap_or_else(|e| e.into_inner())),
                Some(w) if w > now => drop(
                    core.changed
                        .wait_timeout(state, w - now)
                        .unwrap_or_else(|e| e.into_inner()),
                ),
                Some(_) => {}
            }
        }
    }

    /// Interop with `std::sync::mpsc`: the receiver never yields a value and
    /// reports `Disconnected` once the context is done, like a closed Go
    /// channel (`recv` returns `Err`; `try_recv` returns `Empty` until then).
    /// Expiry by deadline is delivered by the timer thread.
    pub fn receiver(&self) -> Receiver<()> {
        let (tx, rx) = mpsc::channel();
        match &self.node {
            Some(node) => {
                node.expire_if_due();
                let mut state = node.core().lock();
                if state.err.is_none() {
                    state.receivers.push(tx);
                }
            }
            // Never done: the sender must outlive the receiver.
            None => std::mem::forget(tx),
        }
        rx
    }
}

/// Cancel `root` (and descendants) with `err`/`cause`; idempotent.
fn cancel(root: &Context, remove_from_parent: bool, err: Error, cause: Option<CauseError>) {
    let mut pending = VecDeque::from([(root.clone(), cause)]);
    while let Some((ctx, cause)) = pending.pop_front() {
        let Some(core) = &ctx.0.core else {
            continue;
        };
        let (children, timer_key) = {
            let mut state = core.lock();
            if state.err.is_some() {
                continue;
            }
            state.err = Some(err);
            let cause = cause.unwrap_or_else(|| Arc::new(err));
            state.cause = Some(cause.clone());
            state.receivers.clear();
            let children: Vec<_> = std::mem::take(&mut state.children)
                .into_values()
                .filter_map(|child| match child {
                    Child::Weak(weak) => weak.upgrade(),
                    Child::Strong(node) => Some(node),
                })
                .map(|node| (Context(node), Some(cause.clone())))
                .collect();
            (children, state.timer_key.take())
        };
        core.changed.notify_all();
        if let Some(key) = timer_key {
            timers().remove(key);
        }
        if let Kind::AfterFunc(slot) = &ctx.0.kind {
            let f = slot.lock().unwrap_or_else(|e| e.into_inner()).take();
            if let Some(f) = f {
                thread::spawn(f);
            }
        }
        pending.extend(children);
    }
    if remove_from_parent {
        if let Some(parent) = root.0.parent.as_ref().and_then(Context::cancel_node) {
            parent.core().lock().children.remove(&root.0.id);
        }
    }
}

/// Register `child` with the nearest cancelable ancestor of `parent`, or
/// cancel it immediately when that ancestor is already done.
fn propagate(parent: &Context, child: &Context, strong: bool) {
    let Some(ancestor) = parent.cancel_node() else {
        return;
    };
    parent.expire_if_due();
    let mut state = ancestor.core().lock();
    if let Some(err) = state.err {
        let cause = state.cause.clone();
        drop(state);
        cancel(child, false, err, cause);
        return;
    }
    // Sweep geometrically so registering many live siblings is linear in
    // aggregate, while a long-lived parent releases dead weak links.
    if state.children.len() >= state.next_prune_at {
        state
            .children
            .retain(|_, c| !matches!(c, Child::Weak(w) if w.strong_count() == 0));
        state.next_prune_at = state.children.len().saturating_mul(2).max(64);
    }
    let link = if strong {
        Child::Strong(child.0.clone())
    } else {
        Child::Weak(Arc::downgrade(&child.0))
    };
    state.children.insert(child.0.id, link);
}

impl Context {
    /// Go's `context.WithCancel`.
    pub fn with_cancel(&self) -> (Context, CancelFunc) {
        let (ctx, cancel_cause) = self.with_cancel_cause();
        (ctx, Arc::new(move || cancel_cause(None)))
    }

    /// Go's `context.WithCancelCause`.
    pub fn with_cancel_cause(&self) -> (Context, CancelCauseFunc) {
        let ctx = new_context(Kind::Cancel, Some(self), self.deadline());
        propagate(self, &ctx, false);
        let handle = ctx.clone();
        (
            ctx,
            Arc::new(move |cause| cancel(&handle, true, Error::Canceled, cause)),
        )
    }

    /// Go's `context.WithDeadline`.
    pub fn with_deadline(&self, deadline: Instant) -> (Context, CancelFunc) {
        self.with_deadline_cause(deadline, None)
    }

    /// Go's `context.WithDeadlineCause`: `cause` is reported by `cause()` when the
    /// deadline passes.
    pub fn with_deadline_cause(
        &self,
        deadline: Instant,
        cause: Option<CauseError>,
    ) -> (Context, CancelFunc) {
        if self.deadline().is_some_and(|current| current < deadline) {
            // The parent's deadline is already earlier.
            return self.with_cancel();
        }
        let ctx = new_context(
            Kind::Timer {
                cause: cause.clone(),
            },
            Some(self),
            Some(deadline),
        );
        propagate(self, &ctx, false);
        if deadline <= Instant::now() {
            cancel(&ctx, true, Error::DeadlineExceeded, cause);
        } else {
            let mut state = ctx.core().lock();
            if state.err.is_none() {
                let key = (deadline, ctx.0.id);
                timers().insert(key, Arc::downgrade(&ctx.0));
                state.timer_key = Some(key);
            }
        }
        let handle = ctx.clone();
        (
            ctx,
            Arc::new(move || cancel(&handle, true, Error::Canceled, None)),
        )
    }

    /// Go's `context.WithTimeout`. A timeout too large for `Instant` never fires.
    pub fn with_timeout(&self, timeout: Duration) -> (Context, CancelFunc) {
        self.with_timeout_cause(timeout, None)
    }

    /// Go's `context.WithTimeoutCause`.
    pub fn with_timeout_cause(
        &self,
        timeout: Duration,
        cause: Option<CauseError>,
    ) -> (Context, CancelFunc) {
        let now = Instant::now();
        // Negative timeouts are already expired, as in Go.
        let deadline = match StdDuration::try_from(timeout) {
            Ok(d) => now.checked_add(d),
            Err(_) => Some(
                now.checked_sub(StdDuration::from_nanos(timeout.as_nanos().unsigned_abs()))
                    .unwrap_or(now),
            ),
        };
        match deadline {
            Some(deadline) => self.with_deadline_cause(deadline, cause),
            None => self.with_cancel(),
        }
    }

    /// Go's `context.WithValue`. Values are immutable and shared. Strings print
    /// as themselves in `Display`; other values print their type name.
    pub fn with_value<T: Any + Send + Sync>(&self, key: &Key<T>, value: T) -> Context {
        new_context(
            Kind::Value {
                key: key.id,
                key_label: std::any::type_name::<T>(),
                key_name: key.name,
                value: Arc::new(value),
                value_type: std::any::type_name::<T>(),
            },
            Some(self),
            self.deadline(),
        )
    }

    /// Go's `context.WithoutCancel`: keeps values, drops cancellation, deadline
    /// and cause.
    pub fn without_cancel(&self) -> Context {
        new_context(Kind::WithoutCancel, Some(self), None)
    }

    /// Go's `context.Cause`: the cause recorded when the context was canceled,
    /// or `None` while it is not done (and always for `WithoutCancel`).
    pub fn cause(&self) -> Option<CauseError> {
        let node = self.cancel_node()?;
        self.expire_if_due();
        node.core().lock().cause.clone()
    }

    /// Go's `context.AfterFunc`: run `f` in its own thread after this context is done.
    /// The returned function stops the call and returns true if it prevented `f`
    /// from starting; it returns false if `f` has started or was already stopped.
    pub fn after_func<F>(&self, f: F) -> StopFunc
    where
        F: FnOnce() + Send + 'static,
    {
        // The node never surfaces as a Context, so it holds no parent link: the
        // ancestor owns it (strongly, so it fires even if the caller drops the
        // stop function) and a dropped, never-canceled ancestor is still freed.
        let node = new_context(
            Kind::AfterFunc(Mutex::new(Some(Box::new(f)))),
            None,
            self.deadline(),
        );
        propagate(self, &node, true);
        let registrar = self.cancel_node().cloned();
        Arc::new(move || {
            let Kind::AfterFunc(slot) = &node.0.kind else {
                return false;
            };
            let stopped = slot
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
                .is_some();
            if stopped {
                if let Some(registrar) = &registrar {
                    registrar.core().lock().children.remove(&node.0.id);
                }
            }
            stopped
        })
    }
}

// One lazily started thread sleeps on a condition variable until the earliest
// registered deadline and cancels the owning context.
struct Timers {
    entries: Mutex<BTreeMap<(Instant, u64), Weak<Node>>>,
    changed: Condvar,
}
fn timers() -> &'static Timers {
    static TIMERS: OnceLock<Timers> = OnceLock::new();
    static START: Once = Once::new();
    let timers = TIMERS.get_or_init(|| Timers {
        entries: Mutex::new(BTreeMap::new()),
        changed: Condvar::new(),
    });
    START.call_once(|| {
        // If the thread cannot start, deadlines are still enforced lazily.
        let _ = thread::Builder::new()
            .name("rust-stdlib-context-timer".into())
            .spawn(move || timers.run());
    });
    timers
}
impl Timers {
    fn insert(&self, key: (Instant, u64), node: Weak<Node>) {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, node);
        self.changed.notify_all();
    }
    fn remove(&self, key: (Instant, u64)) {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&key);
    }
    fn run(&self) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            let now = Instant::now();
            match entries.first_key_value().map(|(k, _)| *k) {
                None => {
                    entries = self
                        .changed
                        .wait(entries)
                        .unwrap_or_else(|e| e.into_inner())
                }
                Some(key) if key.0 > now => {
                    entries = self
                        .changed
                        .wait_timeout(entries, key.0 - now)
                        .unwrap_or_else(|e| e.into_inner())
                        .0;
                }
                Some(key) => {
                    let node = entries.remove(&key).and_then(|w| w.upgrade());
                    drop(entries);
                    if let Some(node) = node {
                        let ctx = Context(node);
                        if let Kind::Timer { cause } = &ctx.0.kind {
                            cancel(&ctx, true, Error::DeadlineExceeded, cause.clone());
                        }
                    }
                    entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_cancellation_and_typed_values() {
        struct RequestId(u64);
        let key = Key::<RequestId>::of_type();
        let root = Context::background().with_value(&key, RequestId(7));
        let (child, cancel_child) = root.with_cancel();
        let (sibling, _cancel_sibling) = root.with_cancel();
        assert_eq!(child.value(&key).unwrap().0, 7);
        cancel_child();
        assert_eq!(child.err(), Some(Error::Canceled));
        assert!(root.err().is_none());
        assert!(sibling.err().is_none());
        let (parent, cancel_parent) = root.with_cancel();
        let (kid, _c) = parent.with_cancel();
        cancel_parent();
        kid.done().wait();
        assert_eq!(kid.err(), Some(Error::Canceled));
    }

    #[test]
    fn child_deadlines_cannot_extend_parent() {
        let end = Instant::now() + StdDuration::from_millis(30);
        let (root, _c) = Context::background().with_deadline(end);
        let (child, _c2) = root.with_deadline(end + StdDuration::from_secs(1));
        assert_eq!(child.deadline(), Some(end));
        child.done().wait();
        assert_eq!(child.err(), Some(Error::DeadlineExceeded));
    }

    #[test]
    fn parent_cancel_wakes_waiting_child() {
        let (parent, cancel_parent) = Context::background().with_cancel();
        let (mid, _m) = parent.with_cancel();
        let (child, _c) = mid.with_cancel();
        let task = std::thread::spawn(move || {
            child.done().wait();
            child.err()
        });
        cancel_parent();
        assert_eq!(task.join().unwrap(), Some(Error::Canceled));
    }

    #[test]
    fn cancellation_propagates_through_dropped_ancestors_and_late_children() {
        let (root, cancel_root) = Context::background().with_cancel();
        let mut deepest = root.clone();
        for _ in 0..8_192 {
            deepest = deepest.with_cancel().0;
        }
        // The intermediate Context values were dropped during construction;
        // the retained direct-parent links must still connect the tree.
        cancel_root();
        assert_eq!(deepest.err(), Some(Error::Canceled));
        assert_eq!(deepest.with_cancel().0.err(), Some(Error::Canceled));
    }

    #[test]
    fn cancellation_of_child_does_not_reach_parent_or_sibling() {
        let (root, _r) = Context::background().with_cancel();
        let (child, cancel_child) = root.with_cancel();
        let (grandchild, _g) = child.with_cancel();
        let (sibling, _s) = root.with_cancel();
        cancel_child();
        assert_eq!(grandchild.err(), Some(Error::Canceled));
        assert!(root.err().is_none());
        assert!(sibling.err().is_none());
    }

    #[test]
    fn concurrent_child_registration_and_parent_cancellation() {
        use std::sync::Barrier;

        let (root, cancel_root) = Context::background().with_cancel();
        let barrier = Arc::new(Barrier::new(2));
        let cancel_barrier = barrier.clone();
        let canceler = std::thread::spawn(move || {
            cancel_barrier.wait();
            cancel_root();
        });

        let build_root = root.clone();
        let builder = std::thread::spawn(move || {
            barrier.wait();
            (0..500)
                .map(|_| build_root.with_cancel().0.with_cancel().0)
                .collect::<Vec<_>>()
        });

        canceler.join().unwrap();
        let children = builder.join().unwrap();
        assert!(children
            .iter()
            .all(|child| child.err() == Some(Error::Canceled)));
    }

    #[test]
    fn deep_chain_drops_on_small_stack() {
        std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| {
                let mut context = Context::background();
                for _ in 0..50_000 {
                    context = context.with_cancel().0;
                }
                drop(context);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn deep_value_chain_drops_on_small_stack() {
        std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| {
                let key = Key::<u8>::new();
                let mut context = Context::background();
                for _ in 0..50_000 {
                    context = context.with_value(&key, 1u8);
                }
                drop(context);
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
