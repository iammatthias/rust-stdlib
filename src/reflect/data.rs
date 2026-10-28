//! The storage behind `Value`: a typed-by-context tree of `Data` kept in
//! shared cells so that pointers, slices and addressable values alias exactly
//! as Go memory does.
//!
//! Structs and arrays are stored inline (`Data::Agg`); slices, maps, channels
//! and pointers are handles. A `Place` is a cell plus a path of indices into
//! nested aggregates, which is what Go calls an address.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};

use super::kind::Kind;
use super::typ::{Body, Type};
use super::value::Value;

pub(crate) type Cell = Arc<Mutex<Data>>;
pub(crate) type FuncImpl = Arc<dyn Fn(&[Value]) -> Vec<Value> + Send + Sync>;

pub(crate) fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(Clone)]
pub(crate) enum Data {
    Bool(bool),
    Int(i64),
    Uint(u64),
    Float(f64),
    Complex(f64, f64),
    Str(Arc<[u8]>),
    /// Struct fields or array elements.
    Agg(Vec<Data>),
    Slice(SliceH),
    Map(Option<Arc<Mutex<MapData>>>),
    Ptr(Option<Place>),
    Chan(Option<Arc<Chan>>),
    Func(Option<FuncImpl>),
    /// An interface value: the dynamic type and its data.
    Iface(Option<Box<(Type, Data)>>),
    UPtr(UnsafePointer),
}

/// An `unsafe.Pointer` (Go's `unsafe.Pointer`): an opaque handle that can be
/// compared, converted back to a pointer of the type it came from
/// (`value_at`) and printed.
#[derive(Clone, Default)]
pub struct UnsafePointer {
    pub(crate) place: Option<Place>,
    pub(crate) raw: usize,
}

impl UnsafePointer {
    /// The nil `unsafe.Pointer`.
    pub fn nil() -> UnsafePointer {
        UnsafePointer::default()
    }

    /// Reports whether the pointer is nil.
    pub fn is_nil(&self) -> bool {
        self.place.is_none() && self.raw == 0
    }

    /// A numeric stand-in for the address (Go's `uintptr(p)`). It is unique per
    /// live object but is not a machine address.
    pub fn addr(&self) -> usize {
        match &self.place {
            Some(p) => p.addr(),
            None => self.raw,
        }
    }
}

impl PartialEq for UnsafePointer {
    fn eq(&self, other: &UnsafePointer) -> bool {
        match (&self.place, &other.place) {
            (Some(a), Some(b)) => a.same(b),
            (None, None) => self.raw == other.raw,
            _ => false,
        }
    }
}

impl std::fmt::Debug for UnsafePointer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#x}", self.addr())
    }
}

#[derive(Clone)]
pub(crate) struct SliceH {
    /// The backing array: a place holding `Data::Agg`.
    pub buf: Option<Place>,
    pub off: usize,
    pub len: usize,
    pub cap: usize,
}

impl SliceH {
    pub fn nil() -> SliceH {
        SliceH {
            buf: None,
            off: 0,
            len: 0,
            cap: 0,
        }
    }
}

pub(crate) struct MapData {
    /// Entries in insertion order with the key's hash.
    pub entries: Vec<(u64, Data, Data)>,
}

#[derive(Clone)]
pub(crate) struct Place {
    pub cell: Cell,
    pub path: Arc<[u32]>,
}

fn walk<'a>(mut d: &'a Data, path: &[u32]) -> &'a Data {
    for &i in path {
        match d {
            Data::Agg(v) => d = &v[i as usize],
            _ => unreachable_data(),
        }
    }
    d
}

fn walk_mut<'a>(mut d: &'a mut Data, path: &[u32]) -> &'a mut Data {
    for &i in path {
        match d {
            Data::Agg(v) => d = &mut v[i as usize],
            _ => unreachable_data(),
        }
    }
    d
}

#[cold]
fn unreachable_data() -> ! {
    panic!("reflect: internal error: value storage does not match its type")
}

impl Place {
    pub fn new(d: Data) -> Place {
        Place {
            cell: Arc::new(Mutex::new(d)),
            path: Arc::from(Vec::new()),
        }
    }

    pub fn child(&self, i: usize) -> Place {
        let mut p = Vec::with_capacity(self.path.len() + 1);
        p.extend_from_slice(&self.path);
        p.push(i as u32);
        Place {
            cell: self.cell.clone(),
            path: Arc::from(p),
        }
    }

    pub fn read(&self) -> Data {
        walk(&lock(&self.cell), &self.path).clone()
    }

    pub fn write(&self, d: Data) {
        *walk_mut(&mut lock(&self.cell), &self.path) = d;
    }

    pub fn with<R>(&self, f: impl FnOnce(&Data) -> R) -> R {
        f(walk(&lock(&self.cell), &self.path))
    }

    pub fn with_mut<R>(&self, f: impl FnOnce(&mut Data) -> R) -> R {
        f(walk_mut(&mut lock(&self.cell), &self.path))
    }

    pub fn same(&self, o: &Place) -> bool {
        Arc::ptr_eq(&self.cell, &o.cell) && self.path == o.path
    }

    /// A numeric stand-in for the machine address.
    pub fn addr(&self) -> usize {
        let base = Arc::as_ptr(&self.cell) as usize;
        let off = self.path.iter().fold(0usize, |a, &i| {
            a.wrapping_mul(131).wrapping_add(i as usize + 1)
        });
        base.wrapping_add(off.wrapping_mul(8) & 0xff_ffff)
    }
}

/// The zero `Data` of a type.
pub(crate) fn zero_data(t: &Type) -> Data {
    match t.body() {
        Body::Basic(k) => match k {
            Kind::Bool => Data::Bool(false),
            k if k.is_int() => Data::Int(0),
            k if k.is_uint() => Data::Uint(0),
            Kind::Float32 | Kind::Float64 => Data::Float(0.0),
            Kind::Complex64 | Kind::Complex128 => Data::Complex(0.0, 0.0),
            Kind::String => Data::Str(Arc::from(Vec::new())),
            _ => Data::UPtr(UnsafePointer::nil()),
        },
        Body::Array { len, elem } => Data::Agg((0..*len).map(|_| zero_data(elem)).collect()),
        Body::Struct { fields, .. } => {
            Data::Agg(fields.iter().map(|f| zero_data(&f.type_)).collect())
        }
        Body::Slice(_) => Data::Slice(SliceH::nil()),
        Body::Map { .. } => Data::Map(None),
        Body::Pointer(_) => Data::Ptr(None),
        Body::Chan { .. } => Data::Chan(None),
        Body::Func { .. } => Data::Func(None),
        Body::Interface { .. } => Data::Iface(None),
    }
}

pub(crate) fn str_data(s: &[u8]) -> Data {
    Data::Str(Arc::from(s.to_vec()))
}

// ---------------------------------------------------------------------------
// Equality and hashing of keys and interface values (Go's `==`).

fn hash_bytes(h: u64, b: &[u8]) -> u64 {
    let mut h = h ^ 0xcbf2_9ce4_8422_2325;
    for &x in b {
        h ^= x as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

fn mix(h: u64, x: u64) -> u64 {
    hash_bytes(h, &x.to_le_bytes())
}

pub(crate) fn runtime_panic(msg: String) -> ! {
    panic!("runtime error: {msg}")
}

/// Hash of a value as a map key of type `t`. Panics like Go for types that
/// cannot be hashed (functions, maps, slices inside interfaces).
pub(crate) fn hash_data(t: &Type, d: &Data) -> u64 {
    match (t.body(), d) {
        (_, Data::Bool(b)) => mix(1, *b as u64),
        (_, Data::Int(i)) => mix(2, *i as u64),
        (_, Data::Uint(u)) => mix(2, *u),
        (_, Data::Float(f)) => {
            if *f == 0.0 {
                mix(3, 0)
            } else if f.is_nan() {
                static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
                mix(4, NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
            } else {
                mix(
                    3,
                    if t.kind() == Kind::Float32 {
                        (*f as f32).to_bits() as u64
                    } else {
                        f.to_bits()
                    },
                )
            }
        }
        (_, Data::Complex(a, b)) => {
            let ha = hash_data(&Type::basic(Kind::Float64), &Data::Float(*a));
            mix(ha, hash_data(&Type::basic(Kind::Float64), &Data::Float(*b)))
        }
        (_, Data::Str(s)) => hash_bytes(5, s),
        (Body::Array { elem, .. }, Data::Agg(v)) => {
            v.iter().fold(6, |h, x| mix(h, hash_data(elem, x)))
        }
        (Body::Struct { fields, .. }, Data::Agg(v)) => v
            .iter()
            .zip(fields)
            .fold(7, |h, (x, f)| mix(h, hash_data(&f.type_, x))),
        (_, Data::Ptr(p)) => mix(8, p.as_ref().map_or(0, |p| p.addr() as u64)),
        (_, Data::Chan(c)) => mix(9, c.as_ref().map_or(0, |c| Arc::as_ptr(c) as usize as u64)),
        (_, Data::UPtr(p)) => mix(10, p.addr() as u64),
        (_, Data::Iface(None)) => 11,
        (_, Data::Iface(Some(b))) => {
            if !b.0.comparable() {
                runtime_panic(format!("hash of unhashable type {}", b.0));
            }
            mix(hash_data(&b.0, &b.1), b.0.addr() as u64)
        }
        _ => runtime_panic(format!("hash of unhashable type {t}")),
    }
}

/// Go's `==` on two values of type `t`; panics when an interface holds an
/// incomparable dynamic type.
pub(crate) fn data_eq(t: &Type, a: &Data, b: &Data) -> bool {
    match (a, b) {
        (Data::Bool(x), Data::Bool(y)) => x == y,
        (Data::Int(x), Data::Int(y)) => x == y,
        (Data::Uint(x), Data::Uint(y)) => x == y,
        (Data::Float(x), Data::Float(y)) => x == y,
        (Data::Complex(a1, b1), Data::Complex(a2, b2)) => a1 == a2 && b1 == b2,
        (Data::Str(x), Data::Str(y)) => x == y,
        (Data::Agg(x), Data::Agg(y)) => match t.body() {
            Body::Array { elem, .. } => x.iter().zip(y).all(|(p, q)| data_eq(elem, p, q)),
            Body::Struct { fields, .. } => x
                .iter()
                .zip(y)
                .zip(fields)
                .all(|((p, q), f)| f.name == "_" || data_eq(&f.type_, p, q)),
            _ => false,
        },
        (Data::Ptr(x), Data::Ptr(y)) => match (x, y) {
            (None, None) => true,
            (Some(p), Some(q)) => p.same(q),
            _ => false,
        },
        (Data::Chan(x), Data::Chan(y)) => match (x, y) {
            (None, None) => true,
            (Some(p), Some(q)) => Arc::ptr_eq(p, q),
            _ => false,
        },
        (Data::UPtr(x), Data::UPtr(y)) => x == y,
        (Data::Iface(x), Data::Iface(y)) => match (x, y) {
            (None, None) => true,
            (Some(p), Some(q)) => {
                if p.0 != q.0 {
                    return false;
                }
                if !p.0.comparable() {
                    runtime_panic(format!("comparing uncomparable type {}", p.0));
                }
                data_eq(&p.0, &p.1, &q.1)
            }
            _ => false,
        },
        _ => runtime_panic(format!("comparing uncomparable type {t}")),
    }
}

impl MapData {
    pub fn find(&self, t: &Type, h: u64, key: &Data) -> Option<usize> {
        self.entries
            .iter()
            .position(|(eh, k, _)| *eh == h && data_eq(t, k, key))
    }
}

// ---------------------------------------------------------------------------
// Channels.

pub(crate) struct Chan {
    pub cap: usize,
    st: Mutex<ChanSt>,
}

struct ChanSt {
    buf: VecDeque<Data>,
    closed: bool,
    recvq: VecDeque<Waiter>,
    sendq: VecDeque<Waiter>,
}

struct Waiter {
    tok: Arc<Token>,
    case: usize,
    item: Option<Data>,
}

#[derive(Clone)]
pub(crate) enum Fired {
    /// A value (or `None` for a closed channel) arrived for a receive case.
    Recv(usize, Option<Data>),
    /// A send case completed.
    Sent(usize),
    /// The channel was closed under a blocked send.
    Closed,
}

enum TokSt {
    Empty,
    Claimed,
    Done(Fired),
}

pub(crate) struct Token {
    st: Mutex<TokSt>,
    cv: Condvar,
}

impl Token {
    pub fn new() -> Arc<Token> {
        Arc::new(Token {
            st: Mutex::new(TokSt::Empty),
            cv: Condvar::new(),
        })
    }

    fn is_empty(&self) -> bool {
        matches!(*lock(&self.st), TokSt::Empty)
    }

    /// Fires the token on behalf of a counterpart; `f` runs only on success.
    fn fire(&self, f: impl FnOnce() -> Fired) -> bool {
        let mut st = lock(&self.st);
        if !matches!(*st, TokSt::Empty) {
            return false;
        }
        *st = TokSt::Done(f());
        self.cv.notify_all();
        true
    }

    fn claim(&self) -> bool {
        let mut st = lock(&self.st);
        if matches!(*st, TokSt::Empty) {
            *st = TokSt::Claimed;
            true
        } else {
            false
        }
    }

    fn unclaim(&self) {
        let mut st = lock(&self.st);
        if matches!(*st, TokSt::Claimed) {
            *st = TokSt::Empty;
        }
    }

    fn finish(&self, f: Fired) {
        *lock(&self.st) = TokSt::Done(f);
    }

    fn done(&self) -> Option<Fired> {
        match &*lock(&self.st) {
            TokSt::Done(f) => Some(f.clone()),
            _ => None,
        }
    }

    /// Waits up to `ms` milliseconds for the token to fire.
    fn wait(&self, ms: u64) -> Option<Fired> {
        let mut st = lock(&self.st);
        loop {
            if let TokSt::Done(f) = &*st {
                return Some(f.clone());
            }
            let (g, to) = self
                .cv
                .wait_timeout(st, std::time::Duration::from_millis(ms))
                .unwrap_or_else(|e| e.into_inner());
            st = g;
            if let TokSt::Done(f) = &*st {
                return Some(f.clone());
            }
            if to.timed_out() {
                return None;
            }
        }
    }
}

/// One case of a (possibly single-case) select.
pub(crate) enum CaseOp {
    Recv,
    Send(Data),
}

pub(crate) struct SelCase {
    pub chan: Option<Arc<Chan>>,
    pub op: CaseOp,
}

impl Chan {
    pub fn new(cap: usize) -> Arc<Chan> {
        Arc::new(Chan {
            cap,
            st: Mutex::new(ChanSt {
                buf: VecDeque::new(),
                closed: false,
                recvq: VecDeque::new(),
                sendq: VecDeque::new(),
            }),
        })
    }

    pub fn len(&self) -> usize {
        lock(&self.st).buf.len()
    }

    pub fn close(&self) {
        let mut st = lock(&self.st);
        if st.closed {
            drop(st);
            panic!("close of closed channel");
        }
        st.closed = true;
        for w in st.recvq.drain(..) {
            w.tok.fire(|| Fired::Recv(w.case, None));
        }
        for w in st.sendq.drain(..) {
            w.tok.fire(|| Fired::Closed);
        }
    }

    fn prune(q: &mut VecDeque<Waiter>) {
        while q.front().is_some_and(|w| !w.tok.is_empty()) {
            q.pop_front();
        }
    }

    /// Whether a receive could complete right now. Call with the lock held.
    fn recv_ready(st: &mut ChanSt) -> bool {
        Chan::prune(&mut st.sendq);
        !st.buf.is_empty() || !st.sendq.is_empty() || st.closed
    }

    fn send_ready(&self, st: &mut ChanSt) -> bool {
        if st.closed {
            return true; // sending panics
        }
        Chan::prune(&mut st.recvq);
        !st.recvq.is_empty() || st.buf.len() < self.cap
    }

    /// Performs a receive that `recv_ready` approved. `None` means closed and
    /// drained; the outer `Option` is `None` when a concurrent fire made the
    /// operation fail.
    fn do_recv(st: &mut ChanSt) -> Option<Option<Data>> {
        if let Some(item) = st.buf.pop_front() {
            while let Some(mut w) = st.sendq.pop_front() {
                if w.tok.fire(|| Fired::Sent(w.case)) {
                    if let Some(x) = w.item.take() {
                        st.buf.push_back(x);
                    }
                    break;
                }
            }
            return Some(Some(item));
        }
        while let Some(mut w) = st.sendq.pop_front() {
            let mut got = None;
            if w.tok.fire(|| Fired::Sent(w.case)) {
                got = w.item.take();
            }
            if let Some(x) = got {
                return Some(Some(x));
            }
        }
        if st.closed {
            return Some(None);
        }
        None
    }

    fn do_send(&self, st: &mut ChanSt, item: &mut Option<Data>) -> bool {
        if st.closed {
            panic!("send on closed channel");
        }
        while let Some(w) = st.recvq.pop_front() {
            if w.tok.fire(|| Fired::Recv(w.case, item.take())) {
                return true;
            }
        }
        if st.buf.len() < self.cap {
            if let Some(x) = item.take() {
                st.buf.push_back(x);
            }
            return true;
        }
        false
    }
}

/// The result of a select: the chosen case, and for a receive the value
/// (`None` when the channel is closed).
pub(crate) struct Selected {
    pub index: usize,
    pub recv: Option<Option<Data>>,
}

fn rand_start(n: usize) -> usize {
    use std::sync::atomic::{AtomicU64, Ordering};
    static S: AtomicU64 = AtomicU64::new(0x9e37_79b9_7f4a_7c15);
    let mut x = S.load(Ordering::Relaxed)
        ^ (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos() as u64));
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    S.store(x, Ordering::Relaxed);
    (x % n.max(1) as u64) as usize
}

/// Runs a select over `cases`. With `has_default`, returns `None` when no
/// case is ready; otherwise blocks until one is.
pub(crate) fn run_select(cases: &mut [SelCase], has_default: bool) -> Option<Selected> {
    let n = cases.len();
    loop {
        let start = rand_start(n);
        // Pass A: a ready case, without blocking.
        let tok = Token::new();
        for k in 0..n {
            let i = (start + k) % n;
            if let Some(sel) = try_case(cases, i, &tok) {
                return Some(sel);
            }
        }
        if has_default {
            return None;
        }
        if cases.iter().all(|c| c.chan.is_none()) {
            loop {
                std::thread::park();
            }
        }
        // Pass B: queue on every channel, then wait.
        for k in 0..n {
            let i = (start + k) % n;
            let Some(ch) = cases[i].chan.clone() else {
                continue;
            };
            let mut st = lock(&ch.st);
            let ready = match &cases[i].op {
                CaseOp::Recv => Chan::recv_ready(&mut st),
                CaseOp::Send(_) => ch.send_ready(&mut st),
            };
            if ready {
                drop(st);
                if let Some(sel) = try_case(cases, i, &tok) {
                    remove_waiters(cases, &tok);
                    return Some(sel);
                }
                if !tok.is_empty() {
                    break;
                }
                continue;
            }
            match &cases[i].op {
                CaseOp::Recv => st.recvq.push_back(Waiter {
                    tok: tok.clone(),
                    case: i,
                    item: None,
                }),
                CaseOp::Send(d) => st.sendq.push_back(Waiter {
                    tok: tok.clone(),
                    case: i,
                    item: Some(d.clone()),
                }),
            }
        }
        // Wait for a counterpart. After a timeout, claim the token so that no
        // late wakeup is lost; if the claim fails the token fired meanwhile.
        let outcome = tok
            .wait(20)
            .or_else(|| if tok.claim() { None } else { tok.done() });
        match outcome {
            Some(f) => {
                remove_waiters(cases, &tok);
                return Some(match f {
                    Fired::Recv(i, d) => Selected {
                        index: i,
                        recv: Some(d),
                    },
                    Fired::Sent(i) => Selected {
                        index: i,
                        recv: None,
                    },
                    Fired::Closed => panic!("send on closed channel"),
                });
            }
            None => {
                // Timed out: leave the queues and start over, which also heals
                // any wakeup that raced with our own claim.
                remove_waiters(cases, &tok);
            }
        }
    }
}

fn remove_waiters(cases: &[SelCase], tok: &Arc<Token>) {
    for c in cases {
        if let Some(ch) = &c.chan {
            let mut st = lock(&ch.st);
            st.recvq.retain(|w| !Arc::ptr_eq(&w.tok, tok));
            st.sendq.retain(|w| !Arc::ptr_eq(&w.tok, tok));
        }
    }
}

/// Tries case `i` once, claiming `tok` first so a select completes at most one
/// case.
fn try_case(cases: &mut [SelCase], i: usize, tok: &Arc<Token>) -> Option<Selected> {
    let ch = cases[i].chan.clone()?;
    let mut st = lock(&ch.st);
    match &mut cases[i].op {
        CaseOp::Recv => {
            if !Chan::recv_ready(&mut st) {
                return None;
            }
            if !tok.claim() {
                return None;
            }
            match Chan::do_recv(&mut st) {
                Some(r) => {
                    tok.finish(Fired::Recv(i, r.clone()));
                    Some(Selected {
                        index: i,
                        recv: Some(r),
                    })
                }
                None => {
                    tok.unclaim();
                    None
                }
            }
        }
        CaseOp::Send(d) => {
            if !ch.send_ready(&mut st) {
                return None;
            }
            if !tok.claim() {
                return None;
            }
            let mut item = Some(d.clone());
            if ch.do_send(&mut st, &mut item) {
                tok.finish(Fired::Sent(i));
                Some(Selected {
                    index: i,
                    recv: None,
                })
            } else {
                tok.unclaim();
                None
            }
        }
    }
}
