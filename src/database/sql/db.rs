//! The connection pool and `DB` (Go's `sql.go`: `DB`, `driverConn`,
//! `driverStmt` and the dependency tracking that closes them).
use super::conn::{Conn, ConnInner};
use super::ctxutil::{self, cx, Ctx};
use super::driver::{self, Arg, Connector, Driver};
use super::error::{Error, Res, ERR_BAD_CONN, ERR_DB_CLOSED, ERR_SKIP};
use super::rows::{Row, Rows};
use super::stmt::{ConnStmt, Stmt, StmtConnGrabber, StmtInner};
use super::tx::{self, Tx, TxInner};
use super::{convert, Result as SqlResult, TxOptions};
use crate::{context::Context, time};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    hash::{BuildHasher, Hasher},
    sync::{
        atomic::{AtomicI64, AtomicU64, Ordering},
        Arc, Condvar, Mutex, MutexGuard, OnceLock,
    },
    time::{Duration as StdDuration, Instant},
};

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) fn next_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Monotonic nanoseconds.
pub(crate) fn now_ns() -> i64 {
    static BASE: OnceLock<Instant> = OnceLock::new();
    let base = BASE.get_or_init(Instant::now);
    i64::try_from(base.elapsed().as_nanos()).unwrap_or(i64::MAX)
}

fn spawn(name: &str, f: impl FnOnce() + Send + 'static) -> bool {
    std::thread::Builder::new()
        .name(name.to_string())
        .spawn(f)
        .is_ok()
}

type Drivers = Mutex<BTreeMap<String, Arc<dyn Driver>>>;
static DRIVERS: Drivers = Mutex::new(BTreeMap::new());

/// Go's `sql.Register`: makes a database driver available by the given name.
///
/// # Panics
///
/// Panics if called twice with the same name, like Go.
pub fn register(name: &str, driver: Arc<dyn Driver>) {
    let mut drivers = lock(&DRIVERS);
    assert!(
        !drivers.contains_key(name),
        "sql: Register called twice for driver {name}"
    );
    drivers.insert(name.to_string(), driver);
}

/// Go's `sql.Drivers`: the sorted names of the registered drivers.
pub fn drivers() -> Vec<String> {
    lock(&DRIVERS).keys().cloned().collect()
}

// ------------------------------------------------------------------ requests

pub(crate) struct ConnRequest {
    conn: Option<Arc<DriverConn>>,
    err: Option<Error>,
}

#[derive(Default)]
struct SlotState {
    val: Option<ConnRequest>,
    closed: bool,
}

/// A one-element channel a waiting `conn` call receives a connection from.
struct ReqSlot {
    m: Mutex<SlotState>,
    cv: Condvar,
}

enum Waited {
    Got(ConnRequest),
    Closed,
    Ctx(Error),
}

impl ReqSlot {
    fn new() -> Arc<Self> {
        Arc::new(ReqSlot {
            m: Mutex::new(SlotState::default()),
            cv: Condvar::new(),
        })
    }

    fn send(&self, r: ConnRequest) {
        lock(&self.m).val = Some(r);
        self.cv.notify_all();
    }

    fn close(&self) {
        lock(&self.m).closed = true;
        self.cv.notify_all();
    }

    fn try_take(&self) -> Option<ConnRequest> {
        lock(&self.m).val.take()
    }

    /// Blocks until a connection arrives, the slot closes or `ctx` is done.
    /// A helper thread turns the context's event into a wake-up, so the wait
    /// neither polls nor misses a cancellation.
    fn wait(self: &Arc<Self>, ctx: Ctx<'_>) -> Waited {
        let watch = ctx.map(|c| c.with_cancel());
        let mut helper = watch.is_none();
        if let Some((w, _)) = &watch {
            let slot = self.clone();
            let w = w.clone();
            helper = spawn("sql-conn-wait", move || {
                w.done().wait();
                drop(lock(&slot.m));
                slot.cv.notify_all();
            });
        }
        let mut g = lock(&self.m);
        let out = loop {
            if let Some(v) = g.val.take() {
                break Waited::Got(v);
            }
            if g.closed {
                break Waited::Closed;
            }
            if let Some(c) = ctx {
                if let Err(e) = c.check() {
                    break Waited::Ctx(e.into());
                }
            }
            g = if helper {
                self.cv.wait(g).unwrap_or_else(|e| e.into_inner())
            } else {
                self.cv
                    .wait_timeout(g, StdDuration::from_millis(5))
                    .unwrap_or_else(|e| e.into_inner())
                    .0
            };
        };
        drop(g);
        if let Some((_, cancel)) = watch {
            cancel();
        }
        out
    }
}

#[derive(Default)]
struct ConnRequests {
    s: Vec<(u64, Arc<ReqSlot>)>,
    next: u64,
}

impl ConnRequests {
    fn add(&mut self, slot: Arc<ReqSlot>) -> u64 {
        self.next += 1;
        self.s.push((self.next, slot));
        self.next
    }

    fn delete(&mut self, id: u64) -> bool {
        match self.s.iter().position(|(i, _)| *i == id) {
            Some(pos) => {
                self.s.swap_remove(pos);
                true
            }
            None => false,
        }
    }

    fn take_random(&mut self) -> Option<Arc<ReqSlot>> {
        if self.s.is_empty() {
            return None;
        }
        let r = std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish();
        let pick = (r % self.s.len() as u64) as usize;
        Some(self.s.swap_remove(pick).1)
    }

    fn close_and_remove_all(&mut self) {
        for (_, slot) in self.s.drain(..) {
            slot.close();
        }
    }
}

// ------------------------------------------------------------------- cleaner

/// Go's `cleanerCh`: a one-slot signal channel that can be closed.
struct Cleaner {
    m: Mutex<(bool, bool)>, // (signaled, closed)
    cv: Condvar,
}

impl Cleaner {
    fn signal(&self) {
        lock(&self.m).0 = true;
        self.cv.notify_all();
    }

    fn close(&self) {
        lock(&self.m).1 = true;
        self.cv.notify_all();
    }

    /// Waits for the timer, a signal or the close.
    fn wait(&self, d: StdDuration) {
        let mut g = lock(&self.m);
        if !g.0 && !g.1 {
            g = self
                .cv
                .wait_timeout_while(g, d, |s| !s.0 && !s.1)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        g.0 = false;
    }
}

// ------------------------------------------------------------------ closers

pub(crate) trait FinalCloser: Send + Sync {
    fn final_close(&self) -> Res<()>;
}

struct DepEntry {
    closer: Arc<dyn FinalCloser>,
    deps: HashSet<u64>,
}

type CloseFn = Box<dyn FnOnce() -> Res<()> + Send>;

pub(crate) struct DbState {
    pub(crate) free_conn: Vec<Arc<DriverConn>>,
    conn_requests: ConnRequests,
    pub(crate) num_open: i64,
    pub(crate) closed: bool,
    dep: HashMap<u64, DepEntry>,
    max_idle_count: i64,
    max_open: i64,
    max_lifetime: i64,
    max_idle_time: i64,
    cleaner: Option<Arc<Cleaner>>,
    wait_count: i64,
    max_idle_closed: i64,
    max_idle_time_closed: i64,
    max_lifetime_closed: i64,
}

const DEFAULT_MAX_IDLE_CONNS: i64 = 2;

impl DbState {
    fn max_idle_conns(&self) -> i64 {
        match self.max_idle_count {
            0 => DEFAULT_MAX_IDLE_CONNS,
            n if n < 0 => 0,
            n => n,
        }
    }

    fn shortest_idle_time(&self) -> i64 {
        if self.max_idle_time <= 0 {
            return self.max_lifetime;
        }
        if self.max_lifetime <= 0 {
            return self.max_idle_time;
        }
        self.max_idle_time.min(self.max_lifetime)
    }
}

/// Go's `ConnReuseStrategy`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Strategy {
    AlwaysNew,
    CachedOrNew,
}

pub(crate) type ReleaseConn = Arc<dyn Fn(Option<Error>) + Send + Sync>;

pub(crate) fn dc_release(dc: &Arc<DriverConn>) -> ReleaseConn {
    let dc = dc.clone();
    Arc::new(move |err| dc.release_conn(err))
}

// -------------------------------------------------------------- driver conn

pub(crate) struct DcState {
    pub(crate) ci: Option<Box<dyn driver::Conn>>,
    need_reset: bool,
    closed: bool,
    pub(crate) final_closed: bool,
    open_stmt: HashMap<u64, Arc<DriverStmt>>,
}

impl DcState {
    pub(crate) fn ci_mut(&mut self) -> &mut dyn driver::Conn {
        &mut **self.ci.as_mut().expect("driver connection is closed")
    }
}

pub(crate) struct DcDbState {
    pub(crate) in_use: bool,
    pub(crate) dbmu_closed: bool,
    returned_at: i64,
    on_put: Vec<Box<dyn FnOnce() + Send>>,
}

/// Go's `driverConn`: a driver connection plus the pool's bookkeeping.
pub(crate) struct DriverConn {
    pub(crate) id: u64,
    pub(crate) db: Arc<DbInner>,
    created_at: i64,
    /// Go's embedded `sync.Mutex` and the fields it guards.
    pub(crate) state: Mutex<DcState>,
    /// The fields Go guards with `db.mu`; lock after `db.mu`.
    pub(crate) dbmu: Mutex<DcDbState>,
}

impl DriverConn {
    fn new(db: &Arc<DbInner>, ci: Box<dyn driver::Conn>, in_use: bool) -> Arc<DriverConn> {
        Arc::new(DriverConn {
            id: next_id(),
            db: db.clone(),
            created_at: now_ns(),
            state: Mutex::new(DcState {
                ci: Some(ci),
                need_reset: false,
                closed: false,
                final_closed: false,
                open_stmt: HashMap::new(),
            }),
            dbmu: Mutex::new(DcDbState {
                in_use,
                dbmu_closed: false,
                returned_at: now_ns(),
                on_put: Vec::new(),
            }),
        })
    }

    pub(crate) fn release_conn(self: &Arc<Self>, err: Option<Error>) {
        self.db.put_conn(self, err, true);
    }

    pub(crate) fn remove_open_stmt(&self, id: u64) {
        lock(&self.state).open_stmt.remove(&id);
    }

    fn expired(&self, timeout: i64) -> bool {
        if timeout <= 0 {
            return false;
        }
        self.created_at.saturating_add(timeout) < now_ns()
    }

    fn reset_session(&self, ctx: Ctx<'_>) -> Res<()> {
        let mut g = lock(&self.state);
        if !g.need_reset {
            return Ok(());
        }
        match g.ci_mut().as_session_resetter() {
            Some(r) => r.reset_session(cx(ctx)),
            None => Ok(()),
        }
    }

    fn validate_connection(&self, needs_reset: bool) -> bool {
        let mut g = lock(&self.state);
        if needs_reset {
            g.need_reset = true;
        }
        match g.ci_mut().as_validator() {
            Some(v) => v.is_valid(),
            None => true,
        }
    }

    /// Prepares `query`; the connection must be locked (`g`). A statement
    /// that is not owned by a `Tx` or `Conn` (`has_cg`) is tracked so closing
    /// the connection closes it.
    pub(crate) fn prepare_locked(
        self: &Arc<Self>,
        g: &mut DcState,
        ctx: Ctx<'_>,
        has_cg: bool,
        query: &str,
    ) -> Res<Arc<DriverStmt>> {
        let si = ctxutil::ctx_driver_prepare(ctx, g.ci_mut(), query)?;
        let ds = DriverStmt::new(self, Arc::new(Mutex::new(si)));
        if has_cg {
            return Ok(ds);
        }
        g.open_stmt.insert(ds.id, ds.clone());
        Ok(ds)
    }

    fn close_db_locked(self: &Arc<Self>, st: &mut DbState) -> CloseFn {
        let mut g = lock(&self.state);
        if g.closed {
            return Box::new(|| Err(Error::new("sql: duplicate driverConn close")));
        }
        g.closed = true;
        drop(g);
        st.remove_dep_locked(self.id, self.id)
    }

    pub(crate) fn close(self: &Arc<Self>) -> Res<()> {
        let mut g = lock(&self.state);
        if g.closed {
            return Err(Error::new("sql: duplicate driverConn close"));
        }
        g.closed = true;
        drop(g);
        // Not under the connection lock: final_close may need it.
        let mut st = self.db.lock();
        lock(&self.dbmu).dbmu_closed = true;
        let f = st.remove_dep_locked(self.id, self.id);
        drop(st);
        f()
    }
}

impl FinalCloser for DriverConn {
    fn final_close(&self) -> Res<()> {
        let open_stmt: Vec<Arc<DriverStmt>> = {
            let mut g = lock(&self.state);
            g.open_stmt.drain().map(|(_, v)| v).collect()
        };
        for ds in open_stmt {
            let _ = ds.close();
        }
        let err = {
            let mut g = lock(&self.state);
            g.final_closed = true;
            let r = match g.ci.as_mut() {
                Some(ci) => ci.close(),
                None => Ok(()),
            };
            g.ci = None;
            r.err()
        };
        {
            let mut st = self.db.lock();
            st.num_open -= 1;
            self.db.maybe_open_new_connections(&mut st);
        }
        self.db.num_closed.fetch_add(1, Ordering::Relaxed);
        match err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

/// A driver statement shared by the connection's statement cache and the
/// transaction statements derived from it.
pub(crate) type SharedStmt = Arc<Mutex<Box<dyn driver::Stmt>>>;

struct DsState {
    closed: bool,
    close_err: Option<Error>,
}

/// Go's `driverStmt`. Go's embedded `Locker` is the connection's lock: take
/// `dc.state` before `si`.
pub(crate) struct DriverStmt {
    pub(crate) id: u64,
    pub(crate) dc: Arc<DriverConn>,
    pub(crate) si: SharedStmt,
    state: Mutex<DsState>,
}

impl DriverStmt {
    pub(crate) fn new(dc: &Arc<DriverConn>, si: SharedStmt) -> Arc<DriverStmt> {
        Arc::new(DriverStmt {
            id: next_id(),
            dc: dc.clone(),
            si,
            state: Mutex::new(DsState {
                closed: false,
                close_err: None,
            }),
        })
    }

    pub(crate) fn close(&self) -> Res<()> {
        let _g = lock(&self.dc.state);
        let mut st = lock(&self.state);
        if st.closed {
            return match &st.close_err {
                Some(e) => Err(e.clone()),
                None => Ok(()),
            };
        }
        st.closed = true;
        st.close_err = lock(&self.si).close().err();
        match &st.close_err {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }
}

impl DbState {
    pub(crate) fn add_dep_locked(&mut self, x: u64, closer: Arc<dyn FinalCloser>, dep: u64) {
        self.dep
            .entry(x)
            .or_insert_with(|| DepEntry {
                closer,
                deps: HashSet::new(),
            })
            .deps
            .insert(dep);
    }

    pub(crate) fn remove_dep_locked(&mut self, x: u64, dep: u64) -> CloseFn {
        let Some(entry) = self.dep.get_mut(&x) else {
            panic!("unpaired removeDep: no deps for {x}");
        };
        let l0 = entry.deps.len();
        entry.deps.remove(&dep);
        match entry.deps.len() {
            n if n == l0 => panic!("unpaired removeDep: no dep {dep} on {x}"),
            0 => {
                let entry = self.dep.remove(&x).expect("entry present");
                Box::new(move || entry.closer.final_close())
            }
            _ => Box::new(|| Ok(())),
        }
    }
}

// ---------------------------------------------------------------------- DB

/// Go's `driver.Connector` built from a driver and a DSN.
struct DsnConnector {
    dsn: String,
    driver: Arc<dyn Driver>,
}

impl Connector for DsnConnector {
    fn connect(&self, _ctx: &Context) -> Res<Box<dyn driver::Conn>> {
        self.driver.open(&self.dsn)
    }
    fn driver(&self) -> Arc<dyn Driver> {
        self.driver.clone()
    }
}

pub(crate) struct DbInner {
    connector: Box<dyn Connector>,
    wait_duration: AtomicI64,
    pub(crate) num_closed: AtomicU64,
    mu: Mutex<DbState>,
    /// Go's `stop`: cancels the connection opener.
    opener_ctx: Context,
    opener_cancel: crate::context::CancelFunc,
}

/// Go's `sql.DBStats`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DBStats {
    /// Maximum number of open connections to the database.
    pub max_open_connections: i64,
    /// The number of established connections both in use and idle.
    pub open_connections: i64,
    /// The number of connections currently in use.
    pub in_use: i64,
    /// The number of idle connections.
    pub idle: i64,
    /// The total number of connections waited for.
    pub wait_count: i64,
    /// The total time blocked waiting for a new connection.
    pub wait_duration: time::Duration,
    /// The total number of connections closed due to `set_max_idle_conns`.
    pub max_idle_closed: i64,
    /// The total number of connections closed due to `set_conn_max_idle_time`.
    pub max_idle_time_closed: i64,
    /// The total number of connections closed due to `set_conn_max_lifetime`.
    pub max_lifetime_closed: i64,
}

/// Go's `sql.DB`: a handle to a pool of zero or more connections. Clones
/// share the pool, like copies of Go's `*DB`.
#[derive(Clone)]
pub struct DB {
    pub(crate) inner: Arc<DbInner>,
}

impl DB {
    /// Go's `sql.OpenDB`: opens a database using a [`Connector`].
    pub fn from_connector(c: Box<dyn Connector>) -> DB {
        let (opener_ctx, opener_cancel) = Context::background().with_cancel();
        DB {
            inner: Arc::new(DbInner {
                connector: c,
                wait_duration: AtomicI64::new(0),
                num_closed: AtomicU64::new(0),
                mu: Mutex::new(DbState {
                    free_conn: Vec::new(),
                    conn_requests: ConnRequests::default(),
                    num_open: 0,
                    closed: false,
                    dep: HashMap::new(),
                    max_idle_count: 0,
                    max_open: 0,
                    max_lifetime: 0,
                    max_idle_time: 0,
                    cleaner: None,
                    wait_count: 0,
                    max_idle_closed: 0,
                    max_idle_time_closed: 0,
                    max_lifetime_closed: 0,
                }),
                opener_ctx,
                opener_cancel,
            }),
        }
    }

    /// Go's `sql.Open`: opens a database by registered driver name and
    /// driver-specific data source name. No connection is made until needed.
    pub fn open(driver_name: &str, data_source_name: &str) -> Res<DB> {
        let driveri = lock(&DRIVERS).get(driver_name).cloned();
        let Some(driveri) = driveri else {
            return Err(Error::new(format!(
                "sql: unknown driver {} (forgotten import?)",
                crate::strconv::quote(driver_name)
            )));
        };
        if let Some(dc) = driveri.as_driver_context() {
            let connector = dc.open_connector(data_source_name)?;
            return Ok(DB::from_connector(connector));
        }
        Ok(DB::from_connector(Box::new(DsnConnector {
            dsn: data_source_name.to_string(),
            driver: driveri,
        })))
    }
}

impl DbInner {
    pub(crate) fn lock(&self) -> MutexGuard<'_, DbState> {
        lock(&self.mu)
    }

    pub(crate) fn add_dep(&self, x: u64, closer: Arc<dyn FinalCloser>, dep: u64) {
        self.lock().add_dep_locked(x, closer, dep);
    }

    pub(crate) fn remove_dep(&self, x: u64, dep: u64) -> Res<()> {
        let f = self.lock().remove_dep_locked(x, dep);
        f()
    }

    fn ping_dc(&self, ctx: Ctx<'_>, dc: &Arc<DriverConn>, release: &ReleaseConn) -> Res<()> {
        let err = {
            let mut g = lock(&dc.state);
            match g.ci_mut().as_pinger() {
                Some(p) => p.ping(cx(ctx)).err(),
                None => None,
            }
        };
        release(err.clone());
        match err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    pub(crate) fn retry<T>(&self, mut f: impl FnMut(Strategy) -> Res<T>) -> Res<T> {
        for _ in 0..MAX_BAD_CONN_RETRIES {
            match f(Strategy::CachedOrNew) {
                Err(e) if e.is(&ERR_BAD_CONN) => {}
                other => return other,
            }
        }
        f(Strategy::AlwaysNew)
    }

    /// Go's `maybeOpenNewConnections`: starts one opener per waiting request
    /// that the open limit allows.
    pub(crate) fn maybe_open_new_connections(self: &Arc<Self>, st: &mut DbState) {
        let mut num_requests = st.conn_requests.s.len() as i64;
        if st.max_open > 0 {
            let num_can_open = st.max_open - st.num_open;
            if num_requests > num_can_open {
                num_requests = num_can_open;
            }
        }
        while num_requests > 0 {
            st.num_open += 1; // optimistically
            num_requests -= 1;
            if st.closed {
                return;
            }
            let db = self.clone();
            if !spawn("sql-conn-opener", move || db.open_new_connection()) {
                st.num_open -= 1;
            }
        }
    }

    fn open_new_connection(self: &Arc<Self>) {
        let result = self.connector.connect(&self.opener_ctx);
        let mut st = self.lock();
        if st.closed {
            if let Ok(mut ci) = result {
                let _ = ci.close();
            }
            st.num_open -= 1;
            return;
        }
        match result {
            Err(e) => {
                st.num_open -= 1;
                self.put_conn_db_locked(&mut st, None, Some(e));
                self.maybe_open_new_connections(&mut st);
            }
            Ok(ci) => {
                let dc = DriverConn::new(self, ci, false);
                if self.put_conn_db_locked(&mut st, Some(&dc), None) {
                    st.add_dep_locked(dc.id, dc.clone(), dc.id);
                } else {
                    st.num_open -= 1;
                    if let Some(mut ci) = lock(&dc.state).ci.take() {
                        let _ = ci.close();
                    }
                }
            }
        }
    }

    /// Returns a new or cached connection.
    pub(crate) fn conn(self: &Arc<Self>, ctx: Ctx<'_>, strategy: Strategy) -> Res<Arc<DriverConn>> {
        let mut st = self.lock();
        if st.closed {
            return Err(ERR_DB_CLOSED);
        }
        // Check if the context is expired.
        ctxutil::check(ctx)?;
        let lifetime = st.max_lifetime;

        // Prefer a free connection, if possible.
        if strategy == Strategy::CachedOrNew && !st.free_conn.is_empty() {
            let conn = st.free_conn.pop().expect("non-empty");
            lock(&conn.dbmu).in_use = true;
            if conn.expired(lifetime) {
                st.max_lifetime_closed += 1;
                drop(st);
                let _ = conn.close();
                return Err(ERR_BAD_CONN);
            }
            drop(st);
            // Reset the session if required.
            if let Err(e) = conn.reset_session(ctx) {
                if e.is(&ERR_BAD_CONN) {
                    let _ = conn.close();
                    return Err(e);
                }
            }
            return Ok(conn);
        }

        // Out of free connections or we were asked not to use one. If we are
        // not allowed to open any more connections, make a request and wait.
        if st.max_open > 0 && st.num_open >= st.max_open {
            let slot = ReqSlot::new();
            let id = st.conn_requests.add(slot.clone());
            st.wait_count += 1;
            drop(st);
            let wait_start = Instant::now();
            match slot.wait(ctx) {
                Waited::Ctx(err) => {
                    // The request is no longer wanted; remove it, or if it
                    // was already satisfied give the connection back.
                    let deleted = self.lock().conn_requests.delete(id);
                    self.add_wait(wait_start);
                    if !deleted {
                        if let Some(ret) = slot.try_take() {
                            if let Some(conn) = ret.conn {
                                self.put_conn(&conn, ret.err, false);
                            }
                        }
                    }
                    return Err(err);
                }
                Waited::Closed => {
                    self.add_wait(wait_start);
                    return Err(ERR_DB_CLOSED);
                }
                Waited::Got(ret) => {
                    self.add_wait(wait_start);
                    if strategy == Strategy::CachedOrNew
                        && ret.err.is_none()
                        && ret.conn.as_ref().is_some_and(|c| c.expired(lifetime))
                    {
                        self.lock().max_lifetime_closed += 1;
                        if let Some(c) = &ret.conn {
                            let _ = c.close();
                        }
                        return Err(ERR_BAD_CONN);
                    }
                    let Some(conn) = ret.conn else {
                        return Err(ret.err.unwrap_or_else(|| Error::new("sql: no connection")));
                    };
                    // Only check if the connection is expired if the strategy
                    // is cachedOrNewConn; otherwise reset the session.
                    if let Err(e) = conn.reset_session(ctx) {
                        if e.is(&ERR_BAD_CONN) {
                            let _ = conn.close();
                            return Err(e);
                        }
                    }
                    return match ret.err {
                        Some(e) => Err(e),
                        None => Ok(conn),
                    };
                }
            }
        }

        st.num_open += 1; // optimistically
        drop(st);
        let ci = match self.connector.connect(cx(ctx)) {
            Ok(ci) => ci,
            Err(e) => {
                let mut st = self.lock();
                st.num_open -= 1; // correct for earlier optimism
                self.maybe_open_new_connections(&mut st);
                return Err(e);
            }
        };
        let mut st = self.lock();
        let dc = DriverConn::new(self, ci, true);
        st.add_dep_locked(dc.id, dc.clone(), dc.id);
        Ok(dc)
    }

    fn add_wait(&self, start: Instant) {
        let d = i64::try_from(start.elapsed().as_nanos()).unwrap_or(i64::MAX);
        self.wait_duration.fetch_add(d, Ordering::Relaxed);
    }

    /// Go's `noteUnusedDriverStatement`: closes `ds` when its connection is
    /// next returned, or at once if the connection is idle.
    pub(crate) fn note_unused_driver_statement(&self, c: &Arc<DriverConn>, ds: &Arc<DriverStmt>) {
        let _st = self.lock();
        let mut d = lock(&c.dbmu);
        if d.in_use {
            let ds = ds.clone();
            d.on_put.push(Box::new(move || {
                let _ = ds.close();
            }));
        } else {
            drop(d);
            let fc = lock(&c.state).final_closed;
            if !fc {
                let _ = ds.close();
            }
        }
    }

    /// Satisfies a connection request or puts the connection in the idle
    /// pool; `err` is the result of the last use of the connection.
    pub(crate) fn put_conn(
        self: &Arc<Self>,
        dc: &Arc<DriverConn>,
        err: Option<Error>,
        reset_session: bool,
    ) {
        let mut err = err;
        if !err.as_ref().is_some_and(|e| e.is(&ERR_BAD_CONN))
            && !dc.validate_connection(reset_session)
        {
            err = Some(ERR_BAD_CONN);
        }
        let mut st = self.lock();
        if !lock(&dc.dbmu).in_use {
            drop(st);
            panic!("sql: connection returned that was never out");
        }
        if !err.as_ref().is_some_and(|e| e.is(&ERR_BAD_CONN)) && dc.expired(st.max_lifetime) {
            st.max_lifetime_closed += 1;
            err = Some(ERR_BAD_CONN);
        }
        let on_put = {
            let mut d = lock(&dc.dbmu);
            d.in_use = false;
            d.returned_at = now_ns();
            std::mem::take(&mut d.on_put)
        };
        for f in on_put {
            f();
        }
        if err.as_ref().is_some_and(|e| e.is(&ERR_BAD_CONN)) {
            // Don't reuse bad connections. Since the conn is considered
            // bad and is being discarded, treat it as closed.
            self.maybe_open_new_connections(&mut st);
            drop(st);
            let _ = dc.close();
            return;
        }
        let added = self.put_conn_db_locked(&mut st, Some(dc), None);
        drop(st);
        if !added {
            let _ = dc.close();
        }
    }

    /// Satisfies a connection request if there is one, or else adds the
    /// connection to the idle pool. Reports whether `dc` was kept.
    fn put_conn_db_locked(
        self: &Arc<Self>,
        st: &mut DbState,
        dc: Option<&Arc<DriverConn>>,
        err: Option<Error>,
    ) -> bool {
        if st.closed {
            return false;
        }
        if st.max_open > 0 && st.num_open > st.max_open {
            return false;
        }
        if let Some(slot) = st.conn_requests.take_random() {
            if err.is_none() {
                if let Some(dc) = dc {
                    lock(&dc.dbmu).in_use = true;
                }
            }
            slot.send(ConnRequest {
                conn: dc.cloned(),
                err,
            });
            return true;
        } else if err.is_none() && !st.closed {
            if let Some(dc) = dc {
                if st.max_idle_conns() > st.free_conn.len() as i64 {
                    st.free_conn.push(dc.clone());
                    self.start_cleaner_locked(st);
                    return true;
                }
                st.max_idle_closed += 1;
            }
        }
        false
    }

    fn start_cleaner_locked(self: &Arc<Self>, st: &mut DbState) {
        if (st.max_lifetime > 0 || st.max_idle_time > 0) && st.num_open > 0 && st.cleaner.is_none()
        {
            let ch = Arc::new(Cleaner {
                m: Mutex::new((false, false)),
                cv: Condvar::new(),
            });
            st.cleaner = Some(ch.clone());
            let d = st.shortest_idle_time();
            let db = self.clone();
            if !spawn("sql-conn-cleaner", move || db.connection_cleaner(ch, d)) {
                st.cleaner = None;
            }
        }
    }

    fn connection_cleaner(self: Arc<Self>, ch: Arc<Cleaner>, d: i64) {
        const MIN_INTERVAL: i64 = 1_000_000_000;
        let mut d = d.max(MIN_INTERVAL);
        loop {
            ch.wait(StdDuration::from_nanos(d as u64));
            let mut st = self.lock();
            d = st.shortest_idle_time();
            if st.closed || st.num_open == 0 || d <= 0 {
                // Stop the cleaner; it restarts when a connection is put.
                st.cleaner = None;
                return;
            }
            let (nd, closing) = st.cleaner_run(d);
            drop(st);
            for c in closing {
                let _ = c.close();
            }
            d = nd.max(MIN_INTERVAL);
        }
    }
}

const MAX_BAD_CONN_RETRIES: usize = 2;

impl DbState {
    /// Go's `connectionCleanerRunLocked`: removes idle connections that are
    /// too old and returns when the next one expires.
    fn cleaner_run(&mut self, mut d: i64) -> (i64, Vec<Arc<DriverConn>>) {
        let mut idle_closing = 0usize;
        let mut closing: Vec<Arc<DriverConn>> = Vec::new();
        if self.max_idle_time > 0 {
            let idle_since = now_ns() - self.max_idle_time;
            // free_conn is ordered by returned_at, oldest first.
            let split = self
                .free_conn
                .iter()
                .rposition(|c| lock(&c.dbmu).returned_at < idle_since);
            if let Some(i) = split {
                closing = self.free_conn.drain(..=i).collect();
                idle_closing = closing.len();
                self.max_idle_time_closed += idle_closing as i64;
            }
            if let Some(c) = self.free_conn.first() {
                let d2 = lock(&c.dbmu).returned_at - idle_since;
                if d2 < d {
                    d = d2;
                }
            }
        }
        if self.max_lifetime > 0 {
            let expired_since = now_ns() - self.max_lifetime;
            let mut i = 0;
            while i < self.free_conn.len() {
                let c = self.free_conn[i].clone();
                if c.created_at < expired_since {
                    closing.push(self.free_conn.remove(i));
                } else {
                    let d2 = c.created_at - expired_since;
                    if d2 < d {
                        d = d2;
                    }
                    i += 1;
                }
            }
            self.max_lifetime_closed += (closing.len() - idle_closing) as i64;
        }
        (d, closing)
    }
}

// ------------------------------------------------------------ statements

struct DriverResult {
    dc: Arc<DriverConn>,
    resi: Mutex<Box<dyn driver::Result>>,
}

impl SqlResult for DriverResult {
    fn last_insert_id(&self) -> Res<i64> {
        let _g = lock(&self.dc.state);
        lock(&self.resi).last_insert_id()
    }
    fn rows_affected(&self) -> Res<i64> {
        let _g = lock(&self.dc.state);
        lock(&self.resi).rows_affected()
    }
}

fn driver_result(dc: &Arc<DriverConn>, resi: Box<dyn driver::Result>) -> Box<dyn SqlResult> {
    Box::new(DriverResult {
        dc: dc.clone(),
        resi: Mutex::new(resi),
    })
}

pub(crate) fn result_from_statement(
    ctx: Ctx<'_>,
    ds: &Arc<DriverStmt>,
    args: &[Arg],
) -> Res<Box<dyn SqlResult>> {
    let mut g = lock(&ds.dc.state);
    let mut si = lock(&ds.si);
    let dargs = convert::driver_args_conn_locked(g.ci_mut(), Some(&mut **si), args)?;
    let resi = ctxutil::ctx_driver_stmt_exec(ctx, &mut **si, &dargs)?;
    Ok(driver_result(&ds.dc, resi))
}

pub(crate) fn rowsi_from_statement(
    ctx: Ctx<'_>,
    ds: &Arc<DriverStmt>,
    args: &[Arg],
) -> Res<Box<dyn driver::Rows>> {
    let mut g = lock(&ds.dc.state);
    let mut si = lock(&ds.si);
    let dargs = convert::driver_args_conn_locked(g.ci_mut(), Some(&mut **si), args)?;
    ctxutil::ctx_driver_stmt_query(ctx, &mut **si, &dargs)
}

impl DbInner {
    pub(crate) fn prepare_dc(
        self: &Arc<Self>,
        ctx: Ctx<'_>,
        dc: &Arc<DriverConn>,
        release: &ReleaseConn,
        cg: Option<Arc<dyn StmtConnGrabber>>,
        query: &str,
    ) -> Res<Stmt> {
        let ds = {
            let mut g = lock(&dc.state);
            dc.prepare_locked(&mut g, ctx, cg.is_some(), query)
        };
        let ds = match ds {
            Ok(ds) => ds,
            Err(e) => {
                release(Some(e.clone()));
                return Err(e);
            }
        };
        let has_cg = cg.is_some();
        let stmt = StmtInner::new(self, query, None, cg, None, Some(ds.clone()));
        if !has_cg {
            {
                let mut s = lock(&stmt.mu);
                s.css.push(ConnStmt { dc: dc.clone(), ds });
                s.last_num_closed = self.num_closed.load(Ordering::Relaxed);
            }
            self.add_dep(stmt.id, stmt.clone(), stmt.id);
        }
        release(None);
        Ok(Stmt::from_inner(stmt))
    }

    pub(crate) fn exec_dc(
        self: &Arc<Self>,
        ctx: Ctx<'_>,
        dc: &Arc<DriverConn>,
        release: &ReleaseConn,
        query: &str,
        args: &[Arg],
    ) -> Res<Box<dyn SqlResult>> {
        let res = self.exec_dc_inner(ctx, dc, query, args);
        release(res.as_ref().err().cloned());
        res
    }

    fn exec_dc_inner(
        &self,
        ctx: Ctx<'_>,
        dc: &Arc<DriverConn>,
        query: &str,
        args: &[Arg],
    ) -> Res<Box<dyn SqlResult>> {
        let fast = {
            let mut g = lock(&dc.state);
            let ci = g.ci_mut();
            if ctxutil::has_execer(ci) {
                let r = convert::driver_args_conn_locked(ci, None, args)
                    .and_then(|nv| ctxutil::ctx_driver_exec(ctx, ci, query, &nv));
                Some(r)
            } else {
                None
            }
        };
        match fast {
            Some(Err(e)) if e == ERR_SKIP => {}
            Some(Err(e)) => return Err(e),
            Some(Ok(resi)) => return Ok(driver_result(dc, resi)),
            None => {}
        }
        let si = {
            let mut g = lock(&dc.state);
            ctxutil::ctx_driver_prepare(ctx, g.ci_mut(), query)?
        };
        let ds = DriverStmt::new(dc, Arc::new(Mutex::new(si)));
        let result = result_from_statement(ctx, &ds, args);
        let _ = ds.close();
        result
    }

    /// Queries on a connection that is already checked out. `tx` is the
    /// transaction the rows belong to, if any.
    pub(crate) fn query_dc(
        self: &Arc<Self>,
        ctx: Ctx<'_>,
        tx: Option<&Arc<TxInner>>,
        dc: &Arc<DriverConn>,
        release: ReleaseConn,
        query: &str,
        args: &[Arg],
    ) -> Res<Rows> {
        let fast = {
            let mut g = lock(&dc.state);
            let ci = g.ci_mut();
            if ctxutil::has_queryer(ci) {
                let r = convert::driver_args_conn_locked(ci, None, args)
                    .and_then(|nv| ctxutil::ctx_driver_query(ctx, ci, query, &nv));
                Some(r)
            } else {
                None
            }
        };
        match fast {
            Some(Err(e)) if e == ERR_SKIP => {}
            Some(Err(e)) => {
                release(Some(e.clone()));
                return Err(e);
            }
            Some(Ok(rowsi)) => {
                let rows = Rows::new(next_id(), dc.clone(), release, rowsi, None);
                rows.init_context_close(ctx, tx);
                return Ok(rows);
            }
            None => {}
        }
        let si = {
            let mut g = lock(&dc.state);
            ctxutil::ctx_driver_prepare(ctx, g.ci_mut(), query)
        };
        let si = match si {
            Ok(si) => si,
            Err(e) => {
                release(Some(e.clone()));
                return Err(e);
            }
        };
        let ds = DriverStmt::new(dc, Arc::new(Mutex::new(si)));
        let rowsi = match rowsi_from_statement(ctx, &ds, args) {
            Ok(r) => r,
            Err(e) => {
                let _ = ds.close();
                release(Some(e.clone()));
                return Err(e);
            }
        };
        let rows = Rows::new(next_id(), dc.clone(), release, rowsi, Some(ds));
        rows.init_context_close(ctx, tx);
        Ok(rows)
    }
}

// --------------------------------------------------------------- DB methods

impl DB {
    /// Go's `PingContext`: verifies a connection to the database is still
    /// alive, establishing one if necessary.
    pub fn ping_context(&self, ctx: &Context) -> Res<()> {
        self.ping_impl(Some(ctx))
    }

    /// Go's `Ping`.
    pub fn ping(&self) -> Res<()> {
        self.ping_impl(None)
    }

    fn ping_impl(&self, ctx: Ctx<'_>) -> Res<()> {
        let db = &self.inner;
        let dc = db.retry(|strategy| db.conn(ctx, strategy))?;
        db.ping_dc(ctx, &dc, &dc_release(&dc))
    }

    /// Go's `Close`: closes the database and prevents new queries from
    /// starting. It does not wait for connections in use; they are closed
    /// when returned. Calling it again is a no-op.
    pub fn close(&self) -> Res<()> {
        let db = &self.inner;
        let mut st = db.lock();
        if st.closed {
            return Ok(());
        }
        if let Some(c) = &st.cleaner {
            c.close();
        }
        let free = std::mem::take(&mut st.free_conn);
        let fns: Vec<CloseFn> = free.iter().map(|dc| dc.close_db_locked(&mut st)).collect();
        st.closed = true;
        st.conn_requests.close_and_remove_all();
        drop(st);
        let mut err = None;
        for f in fns {
            if let Err(e) = f() {
                err = Some(e);
            }
        }
        (db.opener_cancel)();
        if let Err(e) = db.connector.close() {
            err = Some(e);
        }
        match err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Go's `SetMaxIdleConns`: the maximum number of idle connections
    /// (default 2). `n <= 0` retains no idle connections.
    pub fn set_max_idle_conns(&self, n: i64) {
        let mut st = self.inner.lock();
        st.max_idle_count = if n > 0 { n } else { -1 };
        if st.max_open > 0 && st.max_idle_conns() > st.max_open {
            st.max_idle_count = st.max_open;
        }
        // Close the idle connections beyond the new limit.
        let max_idle = st.max_idle_conns() as usize;
        let closing: Vec<Arc<DriverConn>> = if st.free_conn.len() > max_idle {
            st.free_conn.split_off(max_idle)
        } else {
            Vec::new()
        };
        st.max_idle_closed += closing.len() as i64;
        drop(st);
        for c in closing {
            let _ = c.close();
        }
    }

    /// Go's `SetMaxOpenConns`: the maximum number of open connections;
    /// `n <= 0` means unlimited (the default).
    pub fn set_max_open_conns(&self, n: i64) {
        let mut st = self.inner.lock();
        st.max_open = n.max(0);
        let sync_max_idle = st.max_open > 0 && st.max_idle_conns() > st.max_open;
        drop(st);
        if sync_max_idle {
            self.set_max_idle_conns(n);
        }
    }

    /// Go's `SetConnMaxLifetime`: the maximum time a connection may be
    /// reused; `d <= 0` means connections are not closed for age.
    pub fn set_conn_max_lifetime(&self, d: time::Duration) {
        let d = d.as_nanos().max(0);
        let mut st = self.inner.lock();
        if d > 0 && d < st.shortest_idle_time() {
            if let Some(c) = &st.cleaner {
                c.signal();
            }
        }
        st.max_lifetime = d;
        self.inner.start_cleaner_locked(&mut st);
    }

    /// Go's `SetConnMaxIdleTime`: the maximum time a connection may be idle;
    /// `d <= 0` means connections are not closed for idleness.
    pub fn set_conn_max_idle_time(&self, d: time::Duration) {
        let d = d.as_nanos().max(0);
        let mut st = self.inner.lock();
        if d > 0 && d < st.shortest_idle_time() {
            if let Some(c) = &st.cleaner {
                c.signal();
            }
        }
        st.max_idle_time = d;
        self.inner.start_cleaner_locked(&mut st);
    }

    /// Go's `Stats`: database statistics.
    pub fn stats(&self) -> DBStats {
        let wait = self.inner.wait_duration.load(Ordering::Relaxed);
        let st = self.inner.lock();
        DBStats {
            max_open_connections: st.max_open,
            idle: st.free_conn.len() as i64,
            open_connections: st.num_open,
            in_use: st.num_open - st.free_conn.len() as i64,
            wait_count: st.wait_count,
            wait_duration: time::Duration::from_nanos(wait),
            max_idle_closed: st.max_idle_closed,
            max_idle_time_closed: st.max_idle_time_closed,
            max_lifetime_closed: st.max_lifetime_closed,
        }
    }

    /// Go's `PrepareContext`: a prepared statement for later queries or
    /// executions. The caller must close it (or drop it).
    pub fn prepare_context(&self, ctx: &Context, query: &str) -> Res<Stmt> {
        self.prepare_impl(Some(ctx), query)
    }

    /// Go's `Prepare`.
    pub fn prepare(&self, query: &str) -> Res<Stmt> {
        self.prepare_impl(None, query)
    }

    fn prepare_impl(&self, ctx: Ctx<'_>, query: &str) -> Res<Stmt> {
        let db = &self.inner;
        db.retry(|strategy| {
            let dc = db.conn(ctx, strategy)?;
            db.prepare_dc(ctx, &dc, &dc_release(&dc), None, query)
        })
    }

    /// Go's `ExecContext`: executes a query without returning rows.
    pub fn exec_context(
        &self,
        ctx: &Context,
        query: &str,
        args: &[Arg],
    ) -> Res<Box<dyn SqlResult>> {
        self.exec_impl(Some(ctx), query, args)
    }

    /// Go's `Exec`.
    pub fn exec(&self, query: &str, args: &[Arg]) -> Res<Box<dyn SqlResult>> {
        self.exec_impl(None, query, args)
    }

    fn exec_impl(&self, ctx: Ctx<'_>, query: &str, args: &[Arg]) -> Res<Box<dyn SqlResult>> {
        let db = &self.inner;
        db.retry(|strategy| {
            let dc = db.conn(ctx, strategy)?;
            db.exec_dc(ctx, &dc, &dc_release(&dc), query, args)
        })
    }

    /// Go's `QueryContext`: executes a query that returns rows.
    pub fn query_context(&self, ctx: &Context, query: &str, args: &[Arg]) -> Res<Rows> {
        self.query_impl(Some(ctx), query, args)
    }

    /// Go's `Query`.
    pub fn query(&self, query: &str, args: &[Arg]) -> Res<Rows> {
        self.query_impl(None, query, args)
    }

    fn query_impl(&self, ctx: Ctx<'_>, query: &str, args: &[Arg]) -> Res<Rows> {
        let db = &self.inner;
        db.retry(|strategy| {
            let dc = db.conn(ctx, strategy)?;
            db.query_dc(ctx, None, &dc, dc_release(&dc), query, args)
        })
    }

    /// Go's `QueryRowContext`: executes a query expected to return at most
    /// one row. Errors are deferred until [`Row::scan`].
    pub fn query_row_context(&self, ctx: &Context, query: &str, args: &[Arg]) -> Row {
        Row::from_result(self.query_context(ctx, query, args))
    }

    /// Go's `QueryRow`.
    pub fn query_row(&self, query: &str, args: &[Arg]) -> Row {
        Row::from_result(self.query(query, args))
    }

    /// Go's `BeginTx`: starts a transaction. The transaction is rolled back
    /// if `ctx` is done before `commit` or `rollback`.
    pub fn begin_tx(&self, ctx: &Context, opts: Option<TxOptions>) -> Res<Tx> {
        self.begin_impl(Some(ctx), opts)
    }

    /// Go's `Begin`.
    pub fn begin(&self) -> Res<Tx> {
        self.begin_impl(None, None)
    }

    fn begin_impl(&self, ctx: Ctx<'_>, opts: Option<TxOptions>) -> Res<Tx> {
        let db = &self.inner;
        db.retry(|strategy| {
            let dc = db.conn(ctx, strategy)?;
            tx::begin_dc(db, ctx, &dc, dc_release(&dc), opts.as_ref())
        })
    }

    /// Go's `Driver`: the database's underlying driver.
    pub fn driver(&self) -> Arc<dyn Driver> {
        self.inner.connector.driver()
    }

    /// Go's `Conn`: a single connection from the pool, which the caller must
    /// close (or drop) to return it.
    pub fn conn(&self, ctx: &Context) -> Res<Conn> {
        let db = &self.inner;
        let dc = db.retry(|strategy| db.conn(Some(ctx), strategy))?;
        Ok(Conn::from_inner(ConnInner::new(db, dc)))
    }
}

impl std::fmt::Debug for DB {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DB").finish_non_exhaustive()
    }
}
