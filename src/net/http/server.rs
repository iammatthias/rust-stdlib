//! Go's `http.Server`: one thread per connection, HTTP/1.x keep-alive, the
//! `response` writer with automatic Content-Length, chunking and sniffing,
//! `Expect: 100-continue`, hijacking, timeouts and graceful shutdown.
//!
//! HTTP/2 (`h2` over TLS via ALPN, and `h2c` with prior knowledge) is served
//! by `super::h2::server`; `Protocols`, `TLSNextProto`, `HTTP2` and
//! `DisableClientPriority` select and configure it as in Go.
#![allow(clippy::type_complexity)]
use super::body::{Body, ReadCloser};
use super::handler::{
    handler_func, CloseNotifier, ConnControl, Flusher, Handler, Hijacked, Hijacker, ResponseWriter,
};
use super::header::{
    contains_ctl_byte, has_token, is_error, valid_header_field_name, valid_header_field_value,
    BoxError, ErrorString, Header, Http2Config, Protocols, ERR_ABORT_HANDLER, ERR_BODY_NOT_ALLOWED,
    ERR_CONTENT_LENGTH, ERR_HIJACKED, ERR_SERVER_CLOSED,
};
use super::request::{read_request_limit, valid_host_header, Request};
use super::servemux::DEFAULT_SERVE_MUX;
use super::status::*;
use super::tlsstate::{ConnectionState, TlsConfig};
use super::transfer::{
    body_allowed_for_status, suppressed_headers, BodyHandle, BufioReader, UnsupportedTeError,
};
use super::util::{html_escape, max_bytes_reader};
use super::{detect_content_type, status_text, SNIFF_LEN, TIME_FORMAT, TRAILER_PREFIX};
use crate::bufio;
use crate::context::{CancelFunc, Context, Key};
use crate::net::error::Error as _;
use crate::net::{self, AddrRef, Conn, Listener, NetError};
use crate::time::{self, Duration, Time};
use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    io::{self, Read, Write},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Condvar, LazyLock, Mutex, MutexGuard,
    },
    time::Duration as StdDuration,
};

/// Go's `http.ServerContextKey`: the context value holding the [`Server`].
pub static SERVER_CONTEXT_KEY: LazyLock<Key<Server>> = LazyLock::new(|| Key::named("http-server"));
/// Go's `http.LocalAddrContextKey`: the context value holding the local address.
pub static LOCAL_ADDR_CONTEXT_KEY: LazyLock<Key<AddrRef>> =
    LazyLock::new(|| Key::named("local-addr"));

/// Go's `http.ConnState`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnState(pub i32);
pub const STATE_NEW: ConnState = ConnState(0);
pub const STATE_ACTIVE: ConnState = ConnState(1);
pub const STATE_IDLE: ConnState = ConnState(2);
pub const STATE_HIJACKED: ConnState = ConnState(3);
pub const STATE_CLOSED: ConnState = ConnState(4);
impl fmt::Display for ConnState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0 {
            0 => "new",
            1 => "active",
            2 => "idle",
            3 => "hijacked",
            4 => "closed",
            _ => "",
        })
    }
}

/// `Server.TLSNextProto` values: called with the server, the negotiated
/// connection and a handler that fills in the request fields the protocol
/// implementation leaves unset (Go's `initALPNRequest`).
pub type TlsNextProtoFn = Arc<dyn Fn(&Server, Box<dyn Conn>, Arc<dyn Handler>) + Send + Sync>;

/// Go's `http.Server`.
#[derive(Clone)]
pub struct Server {
    pub addr: String,
    /// `http.DefaultServeMux` when `None`.
    pub handler: Option<Arc<dyn Handler>>,
    pub disable_general_options_handler: bool,
    pub tls_config: Option<Arc<dyn TlsConfig>>,
    pub read_timeout: Duration,
    pub read_header_timeout: Duration,
    pub write_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_header_bytes: i64,
    pub max_header_value_count: i64,
    pub tls_next_proto: Option<BTreeMap<String, TlsNextProtoFn>>,
    pub conn_state: Option<Arc<dyn Fn(&Arc<dyn Conn>, ConnState) + Send + Sync>>,
    pub error_log: Option<Arc<crate::log::Logger>>,
    pub base_context: Option<Arc<dyn Fn(&dyn Listener) -> Context + Send + Sync>>,
    pub conn_context: Option<Arc<dyn Fn(&Context, &dyn Conn) -> Context + Send + Sync>>,
    pub http2: Option<Http2Config>,
    pub protocols: Option<Protocols>,
    pub disable_client_priority: bool,
    /// Runtime state shared by clones of the server; leave it at its default
    /// (`..Server::default()`).
    pub state: Arc<ServerState>,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            addr: String::new(),
            handler: None,
            disable_general_options_handler: false,
            tls_config: None,
            read_timeout: Duration::default(),
            read_header_timeout: Duration::default(),
            write_timeout: Duration::default(),
            idle_timeout: Duration::default(),
            max_header_bytes: 0,
            max_header_value_count: 0,
            tls_next_proto: None,
            conn_state: None,
            error_log: None,
            base_context: None,
            conn_context: None,
            http2: None,
            protocols: None,
            disable_client_priority: false,
            state: Arc::new(ServerState::default()),
        }
    }
}

pub(crate) struct H2Registration {
    state: Arc<ServerState>,
    id: u64,
}
impl Drop for H2Registration {
    fn drop(&mut self) {
        lock(&self.state.h2_conns).retain(|(i, _)| *i != self.id);
    }
}

/// The listeners, connections and shutdown flags behind a [`Server`]. Opaque:
/// it exists so every `Server` field is public and struct-update syntax works.
#[derive(Default)]
pub struct ServerState {
    in_shutdown: AtomicBool,
    disable_keep_alives: AtomicBool,
    inner: Mutex<ServerInner>,
    listener_group: WaitGroup,
    next_id: AtomicU64,
    h2_conns: Mutex<Vec<(u64, std::sync::Weak<super::h2::server::ConnHandle>)>>,
}
#[derive(Default)]
struct ServerInner {
    listeners: Vec<(u64, Arc<dyn Listener>)>,
    active_conn: HashMap<u64, Arc<ConnInner>>,
    on_shutdown: Vec<Arc<dyn Fn() + Send + Sync>>,
}

#[derive(Default)]
struct WaitGroup {
    n: Mutex<i64>,
    cv: Condvar,
}
impl WaitGroup {
    fn add(&self, d: i64) {
        let mut n = self.n.lock().unwrap_or_else(|e| e.into_inner());
        *n += d;
        if *n <= 0 {
            self.cv.notify_all();
        }
    }
    fn wait(&self) {
        let mut n = self.n.lock().unwrap_or_else(|e| e.into_inner());
        while *n > 0 {
            n = self.cv.wait(n).unwrap_or_else(|e| e.into_inner());
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn a_long_time_ago() -> Time {
    time::unix(1, 0)
}

impl Server {
    pub fn new() -> Self {
        Self::default()
    }

    fn max_header_bytes(&self) -> i64 {
        if self.max_header_bytes > 0 {
            self.max_header_bytes
        } else {
            DEFAULT_MAX_HEADER_BYTES as i64
        }
    }
    pub(crate) fn max_header_value_count(&self) -> i64 {
        if self.max_header_value_count > 0 {
            self.max_header_value_count
        } else {
            DEFAULT_MAX_HEADER_VALUE_COUNT as i64
        }
    }
    fn initial_read_limit_size(&self) -> i64 {
        self.max_header_bytes() + 4096
    }
    fn tls_handshake_timeout(&self) -> Duration {
        let mut ret = Duration::default();
        for v in [
            self.read_header_timeout,
            self.read_timeout,
            self.write_timeout,
        ] {
            if v.as_nanos() <= 0 {
                continue;
            }
            if ret.as_nanos() == 0 || v < ret {
                ret = v;
            }
        }
        ret
    }
    fn idle_timeout(&self) -> Duration {
        if self.idle_timeout.as_nanos() != 0 {
            self.idle_timeout
        } else {
            self.read_timeout
        }
    }
    fn read_header_timeout(&self) -> Duration {
        if self.read_header_timeout.as_nanos() != 0 {
            self.read_header_timeout
        } else {
            self.read_timeout
        }
    }
    pub(crate) fn do_keep_alives(&self) -> bool {
        !self.state.disable_keep_alives.load(Ordering::SeqCst) && !self.shutting_down()
    }
    fn shutting_down(&self) -> bool {
        self.state.in_shutdown.load(Ordering::SeqCst)
    }
    pub(crate) fn logf(&self, args: fmt::Arguments<'_>) {
        match &self.error_log {
            Some(l) => l.printf(args),
            None => crate::log::printf(args),
        }
    }

    /// Go's unexported `protocols`.
    pub(crate) fn effective_protocols(&self) -> Protocols {
        if let Some(p) = self.protocols {
            if p.is_empty() {
                let mut p = Protocols::default();
                p.set_http1(true);
                return p;
            }
            return p;
        }
        let has_h2 = self
            .tls_next_proto
            .as_ref()
            .is_some_and(|m| m.contains_key("h2"));
        let disabled = self.tls_next_proto.is_some() && !has_h2;
        let mut p = Protocols::default();
        p.set_http1(true);
        if !disabled {
            p.set_http2(true);
        }
        p
    }

    /// Whether the built-in HTTP/2 serves this server (Go's `s.h2 != nil`):
    /// HTTP/2 is enabled and no `TLSNextProto["h2"]` entry replaces it.
    pub(crate) fn bundled_http2(&self) -> bool {
        let p = self.effective_protocols();
        (p.http2() || p.unencrypted_http2())
            && !self
                .tls_next_proto
                .as_ref()
                .is_some_and(|m| m.contains_key("h2"))
    }

    /// Go's `ListenAndServe`.
    pub fn listen_and_serve(&self) -> Result<(), BoxError> {
        if self.shutting_down() {
            return Err(Box::new(ERR_SERVER_CLOSED));
        }
        let addr = if self.addr.is_empty() {
            ":http"
        } else {
            &self.addr
        };
        let ln = net::listen("tcp", addr)?;
        self.serve(ln)
    }

    /// Go's `ListenAndServeTLS`.
    pub fn listen_and_serve_tls(&self, cert_file: &str, key_file: &str) -> Result<(), BoxError> {
        if self.shutting_down() {
            return Err(Box::new(ERR_SERVER_CLOSED));
        }
        let addr = if self.addr.is_empty() {
            ":https"
        } else {
            &self.addr
        };
        let p = self.effective_protocols();
        if !p.http1() && !p.http2() && !p.unencrypted_http2() {
            return Ok(());
        }
        let ln = net::listen("tcp", addr)?;
        self.serve_tls(ln, cert_file, key_file)
    }

    /// Go's `ServeTLS`: wraps `l` with the TLS backend named by `tls_config`.
    pub fn serve_tls(
        &self,
        l: Box<dyn Listener>,
        cert_file: &str,
        key_file: &str,
    ) -> Result<(), BoxError> {
        let Some(cfg) = self.tls_config.clone() else {
            return Err(
                "http: ServeTLS needs Server.tls_config from a TLS backend (rust-stdlib-tls)"
                    .into(),
            );
        };
        // Go's adjustNextProtos on an empty list: "h2" first, then "http/1.1".
        let mut protos = Vec::new();
        let p = self.effective_protocols();
        if p.http2() {
            protos.push("h2".to_owned());
        }
        if p.http1() {
            protos.push("http/1.1".to_owned());
        }
        if let Some(m) = &self.tls_next_proto {
            for k in m.keys() {
                if k != "h2" && k != "http/1.1" && k != super::h2::NEXT_PROTO_UNENCRYPTED_HTTP2 {
                    protos.push(k.clone());
                }
            }
        }
        let tls_l = cfg.server_listener(l, cert_file, key_file, &protos)?;
        self.serve(tls_l)
    }

    /// Go's `Serve`: accepts connections on `l`, one thread per connection.
    pub fn serve(&self, l: Box<dyn Listener>) -> Result<(), BoxError> {
        let orig: Arc<dyn Listener> = Arc::from(l);
        let once_closed = Arc::new(AtomicBool::new(false));
        let lid = self.track_listener(&orig, true);
        let Some(lid) = lid else {
            let _ = orig.close();
            return Err(Box::new(ERR_SERVER_CLOSED));
        };
        let result = self.serve_loop(&orig);
        if !once_closed.swap(true, Ordering::SeqCst) {
            let _ = orig.close();
        }
        self.untrack_listener(lid);
        result
    }

    fn serve_loop(&self, l: &Arc<dyn Listener>) -> Result<(), BoxError> {
        let base_ctx = match &self.base_context {
            Some(f) => f(&**l),
            None => Context::background(),
        };
        let ctx = base_ctx.with_value(&SERVER_CONTEXT_KEY, self.clone());
        let mut temp_delay = StdDuration::ZERO;
        loop {
            let rw = match l.accept() {
                Ok(rw) => rw,
                Err(e) => {
                    if self.shutting_down() {
                        return Err(Box::new(ERR_SERVER_CLOSED));
                    }
                    if e.temporary() {
                        temp_delay = if temp_delay.is_zero() {
                            StdDuration::from_millis(5)
                        } else {
                            temp_delay * 2
                        };
                        if temp_delay > StdDuration::from_secs(1) {
                            temp_delay = StdDuration::from_secs(1);
                        }
                        self.logf(format_args!(
                            "http: Accept error: {e}; retrying in {temp_delay:?}"
                        ));
                        std::thread::sleep(temp_delay);
                        continue;
                    }
                    return Err(Box::new(e));
                }
            };
            let rw: Arc<dyn Conn> = Arc::from(rw);
            let conn_ctx = match &self.conn_context {
                Some(cc) => cc(&ctx, &*rw),
                None => ctx.clone(),
            };
            temp_delay = StdDuration::ZERO;
            let c = self.new_conn(rw);
            c.set_state(STATE_NEW, true);
            let c2 = c.clone();
            std::thread::spawn(move || c2.serve(conn_ctx));
        }
    }

    fn track_listener(&self, l: &Arc<dyn Listener>, add: bool) -> Option<u64> {
        debug_assert!(add);
        let mut inner = lock(&self.state.inner);
        if self.shutting_down() {
            return None;
        }
        let id = self.state.next_id.fetch_add(1, Ordering::SeqCst);
        inner.listeners.push((id, l.clone()));
        self.state.listener_group.add(1);
        Some(id)
    }
    fn untrack_listener(&self, id: u64) {
        let mut inner = lock(&self.state.inner);
        inner.listeners.retain(|(i, _)| *i != id);
        self.state.listener_group.add(-1);
    }

    fn new_conn(&self, rwc: Arc<dyn Conn>) -> Arc<ConnInner> {
        let id = self.state.next_id.fetch_add(1, Ordering::SeqCst);
        let remote_addr = rwc.remote_addr().map(|a| a.to_string()).unwrap_or_default();
        let shared = Arc::new(ConnReaderShared {
            rwc: rwc.clone(),
            st: Mutex::new(CrState {
                alive: true,
                remain: i64::MAX,
                ..CrState::default()
            }),
            cond: Condvar::new(),
            on_error: Mutex::new(None),
        });
        let werr = Arc::new(Mutex::new(None));
        let bufw = bufio::Writer::with_size(
            ConnWriter {
                rwc: rwc.clone(),
                werr: werr.clone(),
                on_error: Mutex::new(None),
            },
            4 << 10,
        );
        let bufr = BufioReader::new(ConnReader(shared.clone()));
        Arc::new(ConnInner {
            id,
            server: self.clone(),
            rwc,
            remote_addr,
            tls_state: Mutex::new(None),
            r: shared,
            bufr,
            bufw: Arc::new(Mutex::new(Some(bufw))),
            werr,
            mu: Mutex::new(ConnMut::default()),
            cur_state: AtomicU64::new(0),
            cancel: Mutex::new(None),
            cur_req: Mutex::new(None),
        })
    }

    /// Registers an HTTP/2 connection for graceful shutdown (Go's
    /// `RegisterOnShutdown(h2srv.GracefulShutdown)`).
    pub(crate) fn h2_register(
        &self,
        h: &Arc<super::h2::server::ConnHandle>,
    ) -> Option<H2Registration> {
        let id = self.state.next_id.fetch_add(1, Ordering::SeqCst);
        lock(&self.state.h2_conns).push((id, Arc::downgrade(h)));
        if self.shutting_down() {
            let _ = h.send_graceful();
        }
        Some(H2Registration {
            state: self.state.clone(),
            id,
        })
    }

    fn h2_graceful_shutdown(&self) {
        let conns: Vec<_> = lock(&self.state.h2_conns)
            .iter()
            .filter_map(|(_, w)| w.upgrade())
            .collect();
        for c in conns {
            let _ = c.send_graceful();
        }
    }

    /// Go's `Close`: closes listeners and every connection immediately.
    pub fn close(&self) -> Result<(), BoxError> {
        self.state.in_shutdown.store(true, Ordering::SeqCst);
        let err = self.close_listeners();
        self.state.listener_group.wait();
        let conns: Vec<Arc<ConnInner>> = {
            let mut inner = lock(&self.state.inner);
            inner.active_conn.drain().map(|(_, c)| c).collect()
        };
        for c in conns {
            let _ = c.rwc.close();
        }
        err.map_or(Ok(()), |e| Err(Box::new(e)))
    }

    /// Stops accepting connections without touching the open ones (what
    /// `httptest.Server.Close` does to its listener).
    pub(crate) fn stop_accepting(&self) -> Option<NetError> {
        self.state.in_shutdown.store(true, Ordering::SeqCst);
        let err = self.close_listeners();
        self.state.listener_group.wait();
        err
    }

    fn close_listeners(&self) -> Option<NetError> {
        let ls: Vec<Arc<dyn Listener>> = lock(&self.state.inner)
            .listeners
            .iter()
            .map(|(_, l)| l.clone())
            .collect();
        let mut err = None;
        for l in ls {
            if let Err(e) = l.close() {
                if err.is_none() {
                    err = Some(e);
                }
            }
        }
        err
    }

    /// Go's `Shutdown`: stops listening, then waits for connections to go idle.
    pub fn shutdown(&self, ctx: &Context) -> Result<(), BoxError> {
        self.state.in_shutdown.store(true, Ordering::SeqCst);
        let lnerr = self.close_listeners();
        self.h2_graceful_shutdown();
        let fns: Vec<Arc<dyn Fn() + Send + Sync>> = lock(&self.state.inner).on_shutdown.clone();
        for f in fns {
            std::thread::spawn(move || f());
        }
        self.state.listener_group.wait();
        let mut base = StdDuration::from_millis(1);
        loop {
            if self.close_idle_conns() {
                return lnerr.map_or(Ok(()), |e| Err(Box::new(e)));
            }
            let interval = base + StdDuration::from_micros(rand_micros(base));
            base = (base * 2).min(StdDuration::from_millis(500));
            if let Some(err) = ctx.err() {
                return Err(Box::new(err));
            }
            if ctx.done().wait_timeout(interval.into()) {
                if let Some(err) = ctx.err() {
                    return Err(Box::new(err));
                }
            }
        }
    }

    /// Go's `RegisterOnShutdown`.
    pub fn register_on_shutdown<F: Fn() + Send + Sync + 'static>(&self, f: F) {
        lock(&self.state.inner).on_shutdown.push(Arc::new(f));
    }

    fn close_idle_conns(&self) -> bool {
        let mut inner = lock(&self.state.inner);
        let mut quiescent = true;
        let mut remove = Vec::new();
        for (id, c) in &inner.active_conn {
            let (mut st, unix_sec) = c.get_state();
            if st == STATE_NEW && unix_sec < time::now().unix() - 5 {
                st = STATE_IDLE;
            }
            if st != STATE_IDLE || unix_sec == 0 {
                quiescent = false;
                continue;
            }
            let _ = c.rwc.close();
            remove.push(*id);
        }
        for id in remove {
            inner.active_conn.remove(&id);
        }
        quiescent
    }

    /// Go's `SetKeepAlivesEnabled`.
    pub fn set_keep_alives_enabled(&self, v: bool) {
        if v {
            self.state
                .disable_keep_alives
                .store(false, Ordering::SeqCst);
            return;
        }
        self.state.disable_keep_alives.store(true, Ordering::SeqCst);
        self.close_idle_conns();
    }

    fn track_conn(&self, c: &Arc<ConnInner>, add: bool) {
        let mut inner = lock(&self.state.inner);
        if add {
            inner.active_conn.insert(c.id, c.clone());
        } else {
            inner.active_conn.remove(&c.id);
        }
    }

    pub(crate) fn serve_handler(&self, w: &mut dyn ResponseWriter, r: &mut Request) {
        let mut handler: Arc<dyn Handler> = match &self.handler {
            Some(h) => h.clone(),
            None => Arc::new(DefaultMuxHandler),
        };
        if !self.disable_general_options_handler && r.request_uri == "*" && r.method == "OPTIONS" {
            handler = handler_func(global_options_handler);
        }
        handler.serve_http(w, r);
    }
}

/// Go's `serverHandler{srv}`: dispatches to the server's handler.
pub(crate) struct ServerHandler(pub Server);
impl Handler for ServerHandler {
    fn serve_http(&self, w: &mut dyn ResponseWriter, r: &mut Request) {
        self.0.serve_handler(w, r);
    }
}

/// Go's `initALPNRequest`: fills the request fields a `TLSNextProto`
/// implementation may leave unset.
struct InitAlpnRequest {
    h: ServerHandler,
    tls: Option<Arc<ConnectionState>>,
    remote: String,
}
impl Handler for InitAlpnRequest {
    fn serve_http(&self, w: &mut dyn ResponseWriter, r: &mut Request) {
        if r.tls.is_none() {
            r.tls = self.tls.clone();
        }
        if r.body.is_none() {
            r.body = Some(Body::from(super::body::NoBody));
        }
        if r.remote_addr.is_empty() {
            r.remote_addr = self.remote.clone();
        }
        self.h.serve_http(w, r);
    }
}

struct DefaultMuxHandler;
impl Handler for DefaultMuxHandler {
    fn serve_http(&self, w: &mut dyn ResponseWriter, r: &mut Request) {
        DEFAULT_SERVE_MUX.serve_http(w, r);
    }
}

fn global_options_handler(w: &mut dyn ResponseWriter, r: &mut Request) {
    w.header().set("Content-Length", "0");
    if r.content_length != 0 {
        if let Some(b) = r.body.clone() {
            let mut mb = max_bytes_reader(Some(w), b, 4 << 10);
            let _ = io::copy(&mut mb, &mut io::sink());
        }
    }
}

fn rand_micros(base: StdDuration) -> u64 {
    // Go adds rand.IntN(base/10): a tenth of the base, jittered.
    let tenth = (base.as_micros() as u64 / 10).max(1);
    u64::from(time::now().nanosecond() as u32) % tenth
}

// ----------------------------------------------------------- package funcs

/// Go's package-level `ListenAndServe`.
pub fn listen_and_serve(addr: &str, handler: Option<Arc<dyn Handler>>) -> Result<(), BoxError> {
    let server = Server {
        addr: addr.to_owned(),
        handler,
        ..Server::default()
    };
    server.listen_and_serve()
}

/// Go's package-level `ListenAndServeTLS`.
pub fn listen_and_serve_tls(
    addr: &str,
    cert_file: &str,
    key_file: &str,
    handler: Option<Arc<dyn Handler>>,
) -> Result<(), BoxError> {
    let server = Server {
        addr: addr.to_owned(),
        handler,
        ..Server::default()
    };
    server.listen_and_serve_tls(cert_file, key_file)
}

/// Go's package-level `Serve`.
pub fn serve(l: Box<dyn Listener>, handler: Option<Arc<dyn Handler>>) -> Result<(), BoxError> {
    let server = Server {
        handler,
        ..Server::default()
    };
    server.serve(l)
}

/// Go's package-level `ServeTLS`.
pub fn serve_tls(
    l: Box<dyn Listener>,
    handler: Option<Arc<dyn Handler>>,
    cert_file: &str,
    key_file: &str,
) -> Result<(), BoxError> {
    let server = Server {
        handler,
        ..Server::default()
    };
    server.serve_tls(l, cert_file, key_file)
}

// ------------------------------------------------------------ conn reader

#[derive(Default)]
struct CrState {
    alive: bool,
    has_byte: bool,
    byte_buf: u8,
    in_read: bool,
    aborted: bool,
    remain: i64,
}
struct ConnReaderShared {
    rwc: Arc<dyn Conn>,
    st: Mutex<CrState>,
    cond: Condvar,
    on_error: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}
impl ConnReaderShared {
    fn handle_read_error_locked(&self, alive: bool) {
        if !alive {
            return;
        }
        let f = lock(&self.on_error).clone();
        if let Some(f) = f {
            f();
        }
    }
    fn set_read_limit(&self, remain: i64) {
        lock(&self.st).remain = remain;
    }
    fn set_infinite_read_limit(&self) {
        lock(&self.st).remain = i64::MAX;
    }
    fn hit_read_limit(&self) -> bool {
        lock(&self.st).remain <= 0
    }
    fn remain(&self) -> i64 {
        lock(&self.st).remain
    }
    fn release_conn(&self) {
        lock(&self.st).alive = false;
    }
    fn start_background_read(self: &Arc<Self>) {
        let mut st = lock(&self.st);
        if st.in_read {
            panic!("invalid concurrent Body.Read call");
        }
        if st.has_byte {
            return;
        }
        st.in_read = true;
        drop(st);
        let _ = self.rwc.set_read_deadline(&Time::default());
        let me = self.clone();
        std::thread::spawn(move || me.background_read());
    }
    fn background_read(&self) {
        let mut b = [0u8; 1];
        let res = self.rwc.read(&mut b);
        let mut st = lock(&self.st);
        let n = res.as_ref().map_or(0, |n| *n);
        if n == 1 {
            st.has_byte = true;
            st.byte_buf = b[0];
        }
        let is_err = match &res {
            Err(e) => !(st.aborted && e.timeout()),
            // EOF: the peer closed the connection.
            Ok(0) => true,
            Ok(_) => false,
        };
        if is_err {
            let alive = st.alive;
            drop(st);
            self.handle_read_error_locked(alive);
            st = lock(&self.st);
        }
        st.aborted = false;
        st.in_read = false;
        drop(st);
        self.cond.notify_all();
    }
    fn abort_pending_read(&self) {
        let mut st = lock(&self.st);
        if !st.in_read {
            return;
        }
        st.aborted = true;
        let _ = self.rwc.set_read_deadline(&a_long_time_ago());
        while st.in_read {
            st = self.cond.wait(st).unwrap_or_else(|e| e.into_inner());
        }
        let _ = self.rwc.set_read_deadline(&Time::default());
    }
}

struct ConnReader(Arc<ConnReaderShared>);
impl Read for ConnReader {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        let sh = &self.0;
        let mut st = lock(&sh.st);
        if !st.alive {
            drop(st);
            return sh.rwc.read(p).map_err(NetError::into_io);
        }
        if st.in_read {
            panic!("invalid concurrent Body.Read call");
        }
        if st.remain <= 0 {
            return Ok(0);
        }
        if p.is_empty() {
            return Ok(0);
        }
        let mut p = p;
        if p.len() as i64 > st.remain {
            let n = st.remain as usize;
            p = &mut p[..n];
        }
        if st.has_byte {
            p[0] = st.byte_buf;
            st.has_byte = false;
            return Ok(1);
        }
        st.in_read = true;
        drop(st);
        let res = sh.rwc.read(p);
        let mut st = lock(&sh.st);
        st.in_read = false;
        let n = res.as_ref().map_or(0, |n| *n);
        if res.is_err() || n == 0 {
            let alive = st.alive;
            drop(st);
            sh.handle_read_error_locked(alive);
            st = lock(&sh.st);
        }
        st.remain -= n as i64;
        drop(st);
        sh.cond.notify_all();
        res.map_err(NetError::into_io)
    }
}

struct ConnWriter {
    rwc: Arc<dyn Conn>,
    werr: Arc<Mutex<Option<String>>>,
    on_error: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}
impl Write for ConnWriter {
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        match self.rwc.write(p) {
            Ok(n) => Ok(n),
            Err(e) => {
                let mut w = lock(&self.werr);
                if w.is_none() {
                    *w = Some(e.to_string());
                    drop(w);
                    if let Some(f) = lock(&self.on_error).clone() {
                        f();
                    }
                }
                Err(e.into_io())
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A raw writer on a hijacked connection.
struct RawConnWriter(Arc<dyn Conn>);
impl Write for RawConnWriter {
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        self.0.write(p).map_err(NetError::into_io)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// An `Arc<dyn Conn>` as a `Box<dyn Conn>` (for hijacking).
pub(crate) struct SharedConn(pub Arc<dyn Conn>);
impl Conn for SharedConn {
    fn read(&self, b: &mut [u8]) -> Result<usize, NetError> {
        self.0.read(b)
    }
    fn write(&self, b: &[u8]) -> Result<usize, NetError> {
        self.0.write(b)
    }
    fn close(&self) -> Result<(), NetError> {
        self.0.close()
    }
    fn local_addr(&self) -> Option<AddrRef> {
        self.0.local_addr()
    }
    fn remote_addr(&self) -> Option<AddrRef> {
        self.0.remote_addr()
    }
    fn set_deadline(&self, t: &Time) -> Result<(), NetError> {
        self.0.set_deadline(t)
    }
    fn set_read_deadline(&self, t: &Time) -> Result<(), NetError> {
        self.0.set_read_deadline(t)
    }
    fn set_write_deadline(&self, t: &Time) -> Result<(), NetError> {
        self.0.set_write_deadline(t)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self.0.as_any()
    }
    fn tls_connection_state(&self) -> Option<net::TlsConnectionState> {
        self.0.tls_connection_state()
    }
    fn handshake(&self) -> Result<(), NetError> {
        self.0.handshake()
    }
}

// ----------------------------------------------------------------- conn

#[derive(Default)]
struct ConnMut {
    hijacked: bool,
    last_method: String,
}

/// Go's server-side `conn`.
pub(crate) struct ConnInner {
    id: u64,
    server: Server,
    rwc: Arc<dyn Conn>,
    remote_addr: String,
    tls_state: Mutex<Option<Arc<ConnectionState>>>,
    r: Arc<ConnReaderShared>,
    bufr: BufioReader,
    bufw: Arc<Mutex<Option<bufio::Writer<ConnWriter>>>>,
    werr: Arc<Mutex<Option<String>>>,
    mu: Mutex<ConnMut>,
    cur_state: AtomicU64,
    cancel: Mutex<Option<CancelFunc>>,
    cur_req: Mutex<Option<Arc<CloseNotify>>>,
}

#[derive(Default)]
struct CloseNotifyInner {
    tx: Option<std::sync::mpsc::Sender<bool>>,
    triggered: bool,
}
#[derive(Default)]
struct CloseNotify(Mutex<CloseNotifyInner>);
impl CloseNotify {
    fn trigger(&self) {
        let mut g = lock(&self.0);
        if g.triggered {
            return;
        }
        g.triggered = true;
        if let Some(tx) = &g.tx {
            let _ = tx.send(true);
        }
    }
}

enum ReadFail {
    TooLarge,
    UnsupportedTe,
    CommonNetRead,
    Status(u16, String),
    Other,
}

const ERROR_HEADERS: &str =
    "\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n";

impl ConnInner {
    fn hijacked(&self) -> bool {
        lock(&self.mu).hijacked
    }

    fn set_state(self: &Arc<Self>, state: ConnState, run_hook: bool) {
        let srv = &self.server;
        match state {
            STATE_NEW => srv.track_conn(self, true),
            STATE_HIJACKED | STATE_CLOSED => srv.track_conn(self, false),
            _ => {}
        }
        let packed = ((time::now().unix() as u64) << 8) | (state.0 as u64 & 0xff);
        self.cur_state.store(packed, Ordering::SeqCst);
        if !run_hook {
            return;
        }
        if let Some(hook) = &srv.conn_state {
            hook(&self.rwc, state);
        }
    }

    fn get_state(&self) -> (ConnState, i64) {
        let p = self.cur_state.load(Ordering::SeqCst);
        (ConnState((p & 0xff) as i32), (p >> 8) as i64)
    }

    fn cancel_ctx(&self) {
        if let Some(f) = lock(&self.cancel).clone() {
            f();
        }
    }

    fn final_flush(&self) {
        if let Some(bw) = lock(&self.bufw).as_mut() {
            let _ = bw.flush();
        }
        *lock(&self.bufw) = None;
    }

    fn close(&self) {
        self.final_flush();
        let _ = self.rwc.close();
    }

    fn close_write_and_wait(&self) {
        self.final_flush();
        if let Some(tcp) = self.rwc.as_any().downcast_ref::<net::TCPConn>() {
            let _ = tcp.close_write();
        }
        std::thread::sleep(StdDuration::from_millis(500));
    }

    fn write_raw(&self, text: &str) {
        let _ = self.rwc.write(text.as_bytes());
    }

    fn serve(self: Arc<Self>, ctx: Context) {
        let c = self.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.serve_inner(ctx)));
        if let Err(payload) = result {
            let aborted = payload
                .downcast_ref::<ErrorString>()
                .is_some_and(|e| *e == ERR_ABORT_HANDLER);
            if !aborted {
                let msg = payload
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_owned())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .or_else(|| payload.downcast_ref::<ErrorString>().map(|e| e.to_string()))
                    .unwrap_or_else(|| "panic".to_owned());
                self.server.logf(format_args!(
                    "http: panic serving {}: {}",
                    self.remote_addr, msg
                ));
            }
        }
    }

    fn serve_inner(self: &Arc<Self>, ctx: Context) {
        let ctx = match self.rwc.local_addr() {
            Some(a) => ctx.with_value(&LOCAL_ADDR_CONTEXT_KEY, a),
            None => ctx,
        };
        // Deferred cleanup of Go's `serve`.
        let guard = ServeCleanup {
            c: self.clone(),
            in_flight: Mutex::new(None),
        };
        // A TLS connection finishes its handshake under the handshake timeout.
        let tls_to = self.server.tls_handshake_timeout();
        let is_tls = self.is_tls_conn();
        if is_tls {
            if tls_to.as_nanos() > 0 {
                let dl = time::now().add(tls_to);
                let _ = self.rwc.set_read_deadline(&dl);
                let _ = self.rwc.set_write_deadline(&dl);
            }
            if let Err(e) = self.rwc.handshake() {
                self.server.logf(format_args!(
                    "http: TLS handshake error from {}: {}",
                    self.remote_addr, e
                ));
                return;
            }
            if tls_to.as_nanos() > 0 {
                let _ = self.rwc.set_read_deadline(&Time::default());
                let _ = self.rwc.set_write_deadline(&Time::default());
            }
            if let Some(st) = self.rwc.tls_connection_state() {
                *lock(&self.tls_state) = Some(Arc::new(st));
            }
            let proto = lock(&self.tls_state)
                .as_ref()
                .map(|st| st.negotiated_protocol.clone())
                .unwrap_or_default();
            if proto == "h2" && self.server.bundled_http2() {
                // Mark the connection active without running hooks, so Shutdown
                // does not close it as idle (Go's skipHooks).
                self.set_state(STATE_ACTIVE, false);
                super::h2::server::serve_conn(
                    &self.server,
                    self.rwc.clone(),
                    Arc::new(ServerHandler(self.server.clone())),
                    super::h2::server::ServeConnOpts {
                        ctx,
                        saw_client_preface: false,
                    },
                );
                return;
            }
            if !proto.is_empty() && proto != "http/1.1" {
                let f = self
                    .server
                    .tls_next_proto
                    .as_ref()
                    .and_then(|m| m.get(&proto))
                    .cloned();
                if let Some(f) = f {
                    // Legacy TLSNextProto path.
                    self.set_state(STATE_ACTIVE, false);
                    let h = Arc::new(InitAlpnRequest {
                        h: ServerHandler(self.server.clone()),
                        tls: lock(&self.tls_state).clone(),
                        remote: self.remote_addr.clone(),
                    });
                    f(&self.server, Box::new(SharedConn(self.rwc.clone())), h);
                }
                return;
            }
        }

        let (ctx, cancel) = ctx.with_cancel();
        *lock(&self.cancel) = Some(cancel.clone());
        let weak = Arc::downgrade(self);
        let on_err: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            if let Some(c) = weak.upgrade() {
                c.cancel_ctx();
                let cur = lock(&c.cur_req).clone();
                if let Some(cn) = cur {
                    cn.trigger();
                }
            }
        });
        *lock(&self.r.on_error) = Some(on_err.clone());
        if let Some(bw) = lock(&self.bufw).as_mut() {
            bw.get_mut().on_error = Mutex::new(Some(Arc::new({
                let weak = Arc::downgrade(self);
                move || {
                    if let Some(c) = weak.upgrade() {
                        c.cancel_ctx();
                    }
                }
            })));
        }

        let d = self.server.read_header_timeout();
        if d.as_nanos() > 0 {
            let _ = self.rwc.set_read_deadline(&time::now().add(d));
        }
        let protos = self.server.effective_protocols();
        if !is_tls && protos.unencrypted_http2() && self.maybe_serve_unencrypted_http2(&ctx) {
            cancel();
            return;
        }
        if !protos.http1() {
            cancel();
            return;
        }

        loop {
            let read = self.read_request(&ctx);
            if self.r.remain() != self.server.initial_read_limit_size() {
                self.set_state(STATE_ACTIVE, true);
            }
            if self.server.shutting_down() {
                cancel();
                return;
            }
            let mut w = match read {
                Ok(w) => w,
                Err(fail) => {
                    match fail {
                        ReadFail::TooLarge => {
                            const PUBLIC: &str = "431 Request Header Fields Too Large";
                            self.write_raw(&format!("HTTP/1.1 {PUBLIC}{ERROR_HEADERS}{PUBLIC}"));
                            self.close_write_and_wait();
                        }
                        ReadFail::UnsupportedTe => {
                            self.write_raw(&format!(
                                "HTTP/1.1 {} {}{}Unsupported transfer encoding",
                                STATUS_NOT_IMPLEMENTED,
                                status_text(STATUS_NOT_IMPLEMENTED),
                                ERROR_HEADERS
                            ));
                        }
                        ReadFail::CommonNetRead => {}
                        ReadFail::Status(code, text) => {
                            self.write_raw(&format!(
                                "HTTP/1.1 {code} {}: {text}{ERROR_HEADERS}{code} {}: {text}",
                                status_text(code),
                                status_text(code)
                            ));
                        }
                        ReadFail::Other => {
                            const PUBLIC: &str = "400 Bad Request";
                            self.write_raw(&format!("HTTP/1.1 {PUBLIC}{ERROR_HEADERS}{PUBLIC}"));
                        }
                    }
                    cancel();
                    return;
                }
            };
            let mut req = w.take_request();
            if req.expects_continue() {
                if req.proto_at_least(1, 1) && req.content_length != 0 {
                    if let Some(inner) = req.body.clone() {
                        let shared = Arc::new(EcShared {
                            can_write_continue: AtomicBool::new(true),
                            closed: AtomicBool::new(false),
                            mu: Mutex::new(()),
                            conn: self.clone(),
                            close_after_reply: w.close_after_reply.clone(),
                        });
                        w.ec = Some(shared.clone());
                        req.body = Some(Body::new(ExpectContinueReader { inner, shared }));
                    }
                }
            } else if !req.header.get_exact("Expect").is_empty() {
                w.send_expectation_failed();
                cancel();
                return;
            }

            *lock(&self.cur_req) = Some(w.close_notify.clone());
            if w.req_body.as_ref().is_some_and(BodyHandle::body_remains) {
                let r = self.r.clone();
                if let Some(h) = &w.req_body {
                    h.register_on_hit_eof(Some(Box::new(move || r.start_background_read())));
                }
            } else {
                self.r.start_background_read();
            }

            *guard.in_flight.lock().unwrap_or_else(|e| e.into_inner()) = Some(w.shared_parts());
            self.server.serve_handler(&mut w, &mut req);
            *guard.in_flight.lock().unwrap_or_else(|e| e.into_inner()) = None;
            (w.cancel_ctx)();
            if self.hijacked() {
                self.r.release_conn();
                return;
            }
            w.finish_request(&req);
            let _ = self.rwc.set_write_deadline(&Time::default());
            if !w.should_reuse_connection() {
                if w.request_body_limit_hit.load(Ordering::SeqCst) || w.closed_request_body_early()
                {
                    self.close_write_and_wait();
                }
                return;
            }
            self.set_state(STATE_IDLE, true);
            *lock(&self.cur_req) = None;

            if !self.server.do_keep_alives() {
                return;
            }
            let d = self.server.idle_timeout();
            if d.as_nanos() > 0 {
                let _ = self.rwc.set_read_deadline(&time::now().add(d));
            } else {
                let _ = self.rwc.set_read_deadline(&Time::default());
            }
            {
                let mut br = self.bufr.lock();
                let (buf, _err) = br.peek_available(4);
                if buf.len() < 4 {
                    return;
                }
            }
            let d = self.server.read_header_timeout();
            if d.as_nanos() > 0 {
                let _ = self.rwc.set_read_deadline(&time::now().add(d));
            } else {
                let _ = self.rwc.set_read_deadline(&Time::default());
            }
        }
    }

    /// Go's `maybeServeUnencryptedHTTP2`: HTTP/2 with prior knowledge. Only
    /// the connection preface selects it; the bytes are peeked, never consumed
    /// past the preface (the read limit stops the buffered reader short).
    fn maybe_serve_unencrypted_http2(self: &Arc<Self>, ctx: &Context) -> bool {
        let bundled = self.server.bundled_http2();
        let next = if bundled {
            None
        } else {
            match self
                .server
                .tls_next_proto
                .as_ref()
                .and_then(|m| m.get(super::h2::NEXT_PROTO_UNENCRYPTED_HTTP2))
            {
                Some(f) => Some(f.clone()),
                None => return false,
            }
        };
        let has_preface = |preface: &[u8]| -> bool {
            self.r
                .set_read_limit(preface.len() as i64 - self.bufr.buffered() as i64);
            let ok = {
                let mut br = self.bufr.lock();
                let (got, err) = br.peek_available(preface.len());
                err.is_none() && got == preface
            };
            self.r.set_infinite_read_limit();
            ok
        };
        if !has_preface(b"PRI * HTTP/2.0") {
            return false;
        }
        if !has_preface(super::h2::CLIENT_PREFACE) {
            return false;
        }
        self.set_state(STATE_ACTIVE, false);
        match next {
            None => super::h2::server::serve_conn(
                &self.server,
                self.rwc.clone(),
                Arc::new(ServerHandler(self.server.clone())),
                super::h2::server::ServeConnOpts {
                    ctx: ctx.clone(),
                    saw_client_preface: true,
                },
            ),
            Some(f) => {
                let _ = self.rwc.set_read_deadline(&Time::default());
                let _ = self.rwc.set_write_deadline(&Time::default());
                let h = Arc::new(InitAlpnRequest {
                    h: ServerHandler(self.server.clone()),
                    tls: None,
                    remote: self.remote_addr.clone(),
                });
                f(&self.server, Box::new(SharedConn(self.rwc.clone())), h);
            }
        }
        true
    }

    fn is_tls_conn(&self) -> bool {
        self.rwc.tls_connection_state().is_some()
    }

    fn read_request(self: &Arc<Self>, ctx: &Context) -> Result<ServerResponse, ReadFail> {
        if self.hijacked() {
            return Err(ReadFail::CommonNetRead);
        }
        let t0 = time::now();
        let mut whole_req_deadline = Time::default();
        let rt = self.server.read_timeout;
        if rt.as_nanos() > 0 {
            whole_req_deadline = t0.add(rt);
        }
        let wt = self.server.write_timeout;
        let set_write_deadline = |c: &ConnInner| {
            if wt.as_nanos() > 0 {
                let _ = c.rwc.set_write_deadline(&time::now().add(wt));
            }
        };

        self.r.set_read_limit(self.server.initial_read_limit_size());
        let last_method = lock(&self.mu).last_method.clone();
        if last_method == "POST" {
            let mut br = self.bufr.lock();
            let n = {
                let (peek, _) = br.peek_available(4);
                peek.iter()
                    .take_while(|&&b| b == b'\r' || b == b'\n')
                    .count()
            };
            let _ = br.discard(n);
        }
        let parsed = read_request_limit(&self.bufr, self.server.max_header_value_count());
        let mut req = match parsed {
            Ok(r) => r,
            Err(e) => {
                set_write_deadline(self);
                if self.r.hit_read_limit() {
                    return Err(ReadFail::TooLarge);
                }
                return Err(classify_read_error(&e));
            }
        };
        if !http1_server_supports_request(&req) {
            set_write_deadline(self);
            return Err(ReadFail::Status(
                STATUS_HTTP_VERSION_NOT_SUPPORTED,
                "unsupported protocol version".into(),
            ));
        }
        lock(&self.mu).last_method = req.method.clone();
        self.r.set_infinite_read_limit();

        let hosts = req.header.0.get("Host").cloned();
        let have_host = hosts.is_some();
        let hosts = hosts.unwrap_or_default();
        let is_h2_upgrade = req.method == "PRI"
            && req.header.0.is_empty()
            && req.url.path == "*"
            && req.proto == "HTTP/2.0";
        let fail = |text: &str| {
            set_write_deadline(self);
            Err(ReadFail::Status(STATUS_BAD_REQUEST, text.to_owned()))
        };
        if req.proto_at_least(1, 1)
            && (!have_host || hosts.is_empty())
            && !is_h2_upgrade
            && req.method != "CONNECT"
        {
            return fail("missing required Host header");
        }
        if hosts.len() == 1 && !valid_host_header(&hosts[0]) {
            return fail("malformed Host header");
        }
        for (k, vv) in &req.header.0 {
            if !valid_header_field_name(k) {
                return fail("invalid header name");
            }
            for v in vv {
                if !valid_header_field_value(v) {
                    return fail("invalid header value");
                }
            }
        }
        req.header.0.remove("Host");

        let (rctx, cancel_ctx) = ctx.with_cancel();
        req.set_context(rctx);
        req.remote_addr = self.remote_addr.clone();
        req.tls = lock(&self.tls_state).clone();
        let req_body = req.body_handle.clone();
        if let Some(h) = &req_body {
            h.set_do_early_close(true);
        }
        let _ = self.rwc.set_read_deadline(&whole_req_deadline);
        set_write_deadline(self);

        let wants10 = req.wants_http10_keep_alive();
        let wants_close = req.wants_close();
        let mut w = ServerResponse::new(self.clone(), req, req_body, cancel_ctx);
        w.wants10_keep_alive = wants10;
        w.wants_close = wants_close;
        if is_h2_upgrade {
            w.close_after_reply.store(true, Ordering::SeqCst);
        }
        Ok(w)
    }
}

fn http1_server_supports_request(req: &Request) -> bool {
    if req.proto_major == 1 {
        return true;
    }
    req.proto_major == 2 && req.proto_minor == 0 && req.method == "PRI" && req.request_uri == "*"
}

fn classify_read_error(e: &BoxError) -> ReadFail {
    if e.downcast_ref::<UnsupportedTeError>().is_some() {
        return ReadFail::UnsupportedTe;
    }
    if e.downcast_ref::<ErrorString>() == Some(&ErrorString("http: request too large")) {
        return ReadFail::TooLarge;
    }
    if is_common_net_read_error(e) {
        return ReadFail::CommonNetRead;
    }
    ReadFail::Other
}

fn is_common_net_read_error(e: &BoxError) -> bool {
    if e.downcast_ref::<ErrorString>() == Some(&super::header::ERR_EOF) {
        return true;
    }
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(&**e);
    while let Some(err) = cur {
        if let Some(n) = err.downcast_ref::<NetError>() {
            if n.timeout() {
                return true;
            }
            if matches!(n, NetError::Op(op) if op.op == "read") {
                return true;
            }
        }
        if let Some(io) = err.downcast_ref::<io::Error>() {
            if io.kind() == io::ErrorKind::TimedOut {
                return true;
            }
        }
        cur = err.source();
    }
    false
}

struct ServeCleanup {
    c: Arc<ConnInner>,
    in_flight: Mutex<Option<InFlight>>,
}
/// The pieces of an in-flight response the deferred cleanup needs.
struct InFlight {
    cancel_ctx: CancelFunc,
    ec: Option<Arc<EcShared>>,
    req_body: Option<BodyHandle>,
}
impl Drop for ServeCleanup {
    fn drop(&mut self) {
        let in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(f) = &in_flight {
            (f.cancel_ctx)();
            if let Some(ec) = &f.ec {
                ec.disable_write_continue(true);
            }
        }
        if !self.c.hijacked() {
            if let Some(f) = &in_flight {
                self.c.r.abort_pending_read();
                if let Some(b) = &f.req_body {
                    let _ = b.close();
                }
            }
            self.c.close();
            self.c.set_state(STATE_CLOSED, true);
        }
        self.c.cancel_ctx();
    }
}

// ---------------------------------------------------- expect: 100-continue

struct EcShared {
    can_write_continue: AtomicBool,
    closed: AtomicBool,
    mu: Mutex<()>,
    conn: Arc<ConnInner>,
    close_after_reply: Arc<AtomicBool>,
}
impl EcShared {
    fn disable_write_continue(&self, skip_drain: bool) {
        let _g = lock(&self.mu);
        if self.can_write_continue.load(Ordering::SeqCst) {
            self.can_write_continue.store(false, Ordering::SeqCst);
            if skip_drain {
                self.close_after_reply.store(true, Ordering::SeqCst);
                self.closed.store(true, Ordering::SeqCst);
            }
        }
    }
}
struct ExpectContinueReader {
    inner: Body,
    shared: Arc<EcShared>,
}
impl Read for ExpectContinueReader {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        if self.shared.closed.load(Ordering::SeqCst) {
            return Err(super::header::io_error(
                super::header::ERR_BODY_READ_AFTER_CLOSE,
            ));
        }
        if self.shared.can_write_continue.load(Ordering::SeqCst) {
            let _g = lock(&self.shared.mu);
            if self.shared.can_write_continue.load(Ordering::SeqCst) {
                let mut bw = lock(&self.shared.conn.bufw);
                if let Some(bw) = bw.as_mut() {
                    let _ = bw.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
                    let _ = bw.flush();
                }
                self.shared
                    .can_write_continue
                    .store(false, Ordering::SeqCst);
            }
        }
        self.inner.read(p)
    }
}
impl ReadCloser for ExpectContinueReader {
    fn close(&mut self) -> io::Result<()> {
        if self.shared.can_write_continue.load(Ordering::SeqCst) {
            self.shared.disable_write_continue(true);
        }
        if self.shared.closed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        self.inner.close()
    }
}

// ------------------------------------------------------------- response

/// Go's server `response`: buffers output, decides framing headers and
/// writes through the connection's buffered writer.
pub(crate) struct ServerResponse {
    conn: Arc<ConnInner>,
    req: Option<Request>,
    method: String,
    proto_major: i32,
    proto_minor: i32,
    req_content_length: i64,
    req_body: Option<BodyHandle>,
    cancel_ctx: CancelFunc,
    wrote_header: bool,
    wants10_keep_alive: bool,
    wants_close: bool,
    ec: Option<Arc<EcShared>>,
    // chunkWriter
    cw_header: Option<Header>,
    cw_wrote_header: bool,
    cw_chunking: bool,
    // bufio.Writer of 2048 bytes in front of the chunk writer
    wbuf: Vec<u8>,
    handler_header: Header,
    called_header: bool,
    written: i64,
    content_length: i64,
    status: u16,
    close_after_reply: Arc<AtomicBool>,
    full_duplex: bool,
    request_body_limit_hit: Arc<AtomicBool>,
    trailers: Vec<String>,
    handler_done: AtomicBool,
    close_notify: Arc<CloseNotify>,
}

const BUFFER_BEFORE_CHUNKING_SIZE: usize = 2048;
const MAX_POST_HANDLER_READ_BYTES: i64 = 256 << 10;

impl ServerResponse {
    fn new(
        conn: Arc<ConnInner>,
        req: Request,
        req_body: Option<BodyHandle>,
        cancel_ctx: CancelFunc,
    ) -> Self {
        ServerResponse {
            conn,
            method: req.method.clone(),
            proto_major: req.proto_major,
            proto_minor: req.proto_minor,
            req_content_length: req.content_length,
            req: Some(req),
            req_body,
            cancel_ctx,
            wrote_header: false,
            wants10_keep_alive: false,
            wants_close: false,
            ec: None,
            cw_header: None,
            cw_wrote_header: false,
            cw_chunking: false,
            wbuf: Vec::with_capacity(BUFFER_BEFORE_CHUNKING_SIZE),
            handler_header: Header::new(),
            called_header: false,
            written: 0,
            content_length: -1,
            status: 0,
            close_after_reply: Arc::new(AtomicBool::new(false)),
            full_duplex: false,
            request_body_limit_hit: Arc::new(AtomicBool::new(false)),
            trailers: Vec::new(),
            handler_done: AtomicBool::new(false),
            close_notify: Arc::new(CloseNotify::default()),
        }
    }

    fn take_request(&mut self) -> Request {
        self.req.take().expect("request already taken")
    }

    fn shared_parts(&self) -> InFlight {
        InFlight {
            cancel_ctx: self.cancel_ctx.clone(),
            ec: self.ec.clone(),
            req_body: self.req_body.clone(),
        }
    }

    fn proto_at_least(&self, major: i32, minor: i32) -> bool {
        self.proto_major > major || (self.proto_major == major && self.proto_minor >= minor)
    }

    fn logf(&self, args: fmt::Arguments<'_>) {
        self.conn.server.logf(args);
    }

    fn with_bufw<R>(&self, f: impl FnOnce(&mut bufio::Writer<ConnWriter>) -> R) -> Option<R> {
        lock(&self.conn.bufw).as_mut().map(f)
    }

    fn body_allowed(&self) -> bool {
        body_allowed_for_status(self.status)
    }

    fn disable_write_continue(&self, skip_drain: bool) {
        if let Some(ec) = &self.ec {
            ec.disable_write_continue(skip_drain);
        }
    }

    fn can_write_continue(&self) -> bool {
        self.ec
            .as_ref()
            .is_some_and(|e| e.can_write_continue.load(Ordering::SeqCst))
    }

    fn final_trailers(&self) -> Option<Header> {
        let mut t: Option<Header> = None;
        for (k, vv) in &self.handler_header.0 {
            if let Some(kk) = k.strip_prefix(TRAILER_PREFIX) {
                t.get_or_insert_with(Header::new)
                    .0
                    .insert(kk.to_owned(), vv.clone());
            }
        }
        for k in &self.trailers {
            let tt = t.get_or_insert_with(Header::new);
            if let Some(vv) = self.handler_header.0.get(k) {
                for v in vv {
                    tt.add(k, v);
                }
            }
        }
        t
    }

    fn declare_trailer(&mut self, k: &str) {
        let k = crate::net::textproto::canonical_mime_header_key(k);
        if !valid_trailer_header(&k) {
            return;
        }
        self.trailers.push(k);
    }

    // ---- bufio.Writer{2048} over the chunk writer
    fn w_write(&mut self, mut p: &[u8]) -> io::Result<usize> {
        let mut nn = 0;
        while p.len() > BUFFER_BEFORE_CHUNKING_SIZE - self.wbuf.len() {
            let n = if self.wbuf.is_empty() {
                self.cw_write(p)?
            } else {
                let room = BUFFER_BEFORE_CHUNKING_SIZE - self.wbuf.len();
                self.wbuf.extend_from_slice(&p[..room]);
                self.w_flush()?;
                room
            };
            nn += n;
            p = &p[n..];
        }
        self.wbuf.extend_from_slice(p);
        Ok(nn + p.len())
    }

    /// `bufio.Writer.WriteString` over a writer that is not an
    /// `io.StringWriter`: always copies into the buffer, flushing when full.
    fn w_write_string(&mut self, mut p: &[u8]) -> io::Result<usize> {
        let total = p.len();
        while p.len() > BUFFER_BEFORE_CHUNKING_SIZE - self.wbuf.len() {
            let room = BUFFER_BEFORE_CHUNKING_SIZE - self.wbuf.len();
            self.wbuf.extend_from_slice(&p[..room]);
            self.w_flush()?;
            p = &p[room..];
        }
        self.wbuf.extend_from_slice(p);
        Ok(total)
    }

    fn w_flush(&mut self) -> io::Result<()> {
        if self.wbuf.is_empty() {
            return Ok(());
        }
        let buf = std::mem::take(&mut self.wbuf);
        let res = self.cw_write(&buf);
        self.wbuf = buf;
        self.wbuf.clear();
        res.map(|_| ())
    }

    // ---- chunkWriter
    fn cw_write(&mut self, p: &[u8]) -> io::Result<usize> {
        if !self.cw_wrote_header {
            self.cw_write_header(p);
        }
        if self.method == "HEAD" {
            return Ok(p.len());
        }
        let conn = self.conn.clone();
        let chunking = self.cw_chunking;
        let res = (|| -> io::Result<()> {
            let mut g = lock(&conn.bufw);
            let Some(bw) = g.as_mut() else {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "connection closed",
                ));
            };
            if chunking {
                write!(bw, "{:x}\r\n", p.len())?;
            }
            bw.write_all(p)?;
            if chunking {
                bw.write_all(b"\r\n")?;
            }
            Ok(())
        })();
        match res {
            Ok(()) => Ok(p.len()),
            Err(e) => {
                let _ = conn.rwc.close();
                Err(e)
            }
        }
    }

    fn cw_flush(&mut self) -> io::Result<()> {
        if !self.cw_wrote_header {
            self.cw_write_header(&[]);
        }
        match self.with_bufw(|bw| bw.flush()) {
            Some(r) => r,
            None => Ok(()),
        }
    }

    fn cw_close(&mut self) {
        if !self.cw_wrote_header {
            self.cw_write_header(&[]);
        }
        if self.cw_chunking {
            let trailers = self.final_trailers();
            self.with_bufw(|bw| {
                let _ = bw.write_all(b"0\r\n");
                if let Some(t) = &trailers {
                    let _ = t.write(bw);
                }
                let _ = bw.write_all(b"\r\n");
            });
        }
    }

    /// Go's `chunkWriter.writeHeader`.
    fn cw_write_header(&mut self, p: &[u8]) {
        if self.cw_wrote_header {
            return;
        }
        self.cw_wrote_header = true;

        let keep_alives_enabled = self.conn.server.do_keep_alives();
        let is_head = self.method == "HEAD";

        let owned = self.cw_header.is_some();
        let mut header: Header = match self.cw_header.take() {
            Some(h) => h,
            None => self.handler_header.clone(),
        };
        let _ = owned;
        let mut exclude: BTreeMap<String, bool> = BTreeMap::new();
        macro_rules! del_header {
            ($k:expr) => {{
                header.0.remove($k);
            }};
        }
        let mut set_content_type = String::new();
        let mut set_connection = String::new();
        let mut set_transfer_encoding = String::new();
        let mut set_date: Option<String> = None;
        let mut set_content_length: Option<String> = None;

        let mut trailers = false;
        let keys: Vec<String> = header.0.keys().cloned().collect();
        for k in &keys {
            if k.starts_with(TRAILER_PREFIX) {
                exclude.insert(k.clone(), true);
                trailers = true;
            }
        }
        if let Some(vs) = header.0.get("Trailer").cloned() {
            for v in vs {
                trailers = true;
                foreach_header_element(&v, |t| self.declare_trailer(t));
            }
        }

        let te = header.get_exact("Transfer-Encoding").to_owned();
        let has_te = !te.is_empty();

        if self.handler_done.load(Ordering::SeqCst)
            && !trailers
            && !has_te
            && body_allowed_for_status(self.status)
            && !header.has("Content-Length")
            && (!is_head || !p.is_empty())
        {
            self.content_length = p.len() as i64;
            set_content_length = Some(p.len().to_string());
        }

        if self.wants10_keep_alive && keep_alives_enabled {
            let sent_length = !header.get_exact("Content-Length").is_empty();
            if sent_length && header.get_exact("Connection") == "keep-alive" {
                self.close_after_reply.store(false, Ordering::SeqCst);
            }
        }

        let mut has_cl = self.content_length != -1;

        if self.wants10_keep_alive && (is_head || has_cl || !body_allowed_for_status(self.status)) {
            if !header.0.contains_key("Connection") {
                set_connection = "keep-alive".into();
            }
        } else if !self.proto_at_least(1, 1) || self.wants_close {
            self.close_after_reply.store(true, Ordering::SeqCst);
        }

        if header.get_exact("Connection") == "close" || !keep_alives_enabled {
            self.close_after_reply.store(true, Ordering::SeqCst);
        }

        if self.ec.is_some() && self.req_body.as_ref().is_some_and(BodyHandle::body_remains) {
            self.close_after_reply.store(true, Ordering::SeqCst);
        }

        if self.req_content_length != 0
            && self.req_body.is_some()
            && !self.close_after_reply.load(Ordering::SeqCst)
            && !self.full_duplex
        {
            let mut discard = false;
            let mut too_big = false;
            if let Some(rb) = &self.req_body {
                let (closed, saw_eof, unread) = rb.snapshot();
                if closed {
                    if !saw_eof {
                        self.close_after_reply.store(true, Ordering::SeqCst);
                    }
                } else if unread >= MAX_POST_HANDLER_READ_BYTES {
                    too_big = true;
                } else {
                    discard = true;
                }
            }
            if discard {
                if let Some(rb) = &self.req_body {
                    let _ = rb.close();
                    if rb.did_early_close() {
                        self.close_after_reply.store(true, Ordering::SeqCst);
                    }
                }
            }
            if too_big {
                self.request_too_large();
                del_header!("Connection");
                set_connection = "close".into();
            }
        }

        let code = self.status;
        if body_allowed_for_status(code) {
            let have_type = header.0.contains_key("Content-Type");
            let ce = header.get_str("Content-Encoding");
            let has_ce = !ce.is_empty();
            if !has_ce && !have_type && !has_te && !p.is_empty() {
                set_content_type = detect_content_type(p).to_owned();
            }
        } else {
            for k in suppressed_headers(code) {
                del_header!(*k);
            }
        }

        if !header.has("Date") {
            set_date = Some(time::now().utc().format(TIME_FORMAT));
        }

        if has_cl && has_te && te != "identity" {
            self.logf(format_args!(
                "http: WriteHeader called with both Transfer-Encoding of {} and a Content-Length of {}",
                crate::strconv::quote(&te),
                self.content_length
            ));
            del_header!("Content-Length");
            has_cl = false;
        }

        if self.method == "HEAD" || !body_allowed_for_status(code) || code == 204 || has_cl {
            del_header!("Transfer-Encoding");
        } else if self.proto_at_least(1, 1) {
            if has_te && te == "identity" {
                self.cw_chunking = false;
                self.close_after_reply.store(true, Ordering::SeqCst);
                del_header!("Transfer-Encoding");
            } else {
                self.cw_chunking = true;
                set_transfer_encoding = "chunked".into();
                if has_te && te == "chunked" {
                    del_header!("Transfer-Encoding");
                }
            }
        } else {
            self.close_after_reply.store(true, Ordering::SeqCst);
            del_header!("Transfer-Encoding");
        }

        if self.cw_chunking {
            del_header!("Content-Length");
        }
        if !self.proto_at_least(1, 0) {
            return;
        }

        let delete_connection = self.close_after_reply.load(Ordering::SeqCst)
            && (!keep_alives_enabled || !has_token(header.get_exact("Connection"), "close"))
            && !(self.status == 101 && super::response::is_protocol_switch_header(&header));
        if delete_connection {
            del_header!("Connection");
            if self.proto_at_least(1, 1) {
                set_connection = "close".into();
            }
        }

        let is11 = self.proto_at_least(1, 1);
        self.with_bufw(|bw| {
            write_status_line(bw, is11, code);
            let _ = header.write_subset(bw, &exclude);
            if let Some(d) = &set_date {
                let _ = write!(bw, "Date: {d}\r\n");
            }
            if let Some(cl) = &set_content_length {
                let _ = write!(bw, "Content-Length: {cl}\r\n");
            }
            for (k, v) in [
                ("Content-Type", &set_content_type),
                ("Connection", &set_connection),
                ("Transfer-Encoding", &set_transfer_encoding),
            ] {
                if !v.is_empty() {
                    let _ = write!(bw, "{k}: {v}\r\n");
                }
            }
            let _ = bw.write_all(b"\r\n");
        });
        self.cw_header = Some(header);
    }

    fn request_too_large(&mut self) {
        self.close_after_reply.store(true, Ordering::SeqCst);
        self.request_body_limit_hit.store(true, Ordering::SeqCst);
        if !self.wrote_header {
            self.header_mut().set("Connection", "close");
        }
    }

    fn header_mut(&mut self) -> &mut Header {
        if self.cw_header.is_none() && self.wrote_header && !self.cw_wrote_header {
            self.cw_header = Some(self.handler_header.clone());
        }
        self.called_header = true;
        &mut self.handler_header
    }

    fn write_header_impl(&mut self, code: u16) {
        if self.conn.hijacked() {
            self.logf(format_args!(
                "http: response.WriteHeader on hijacked connection"
            ));
            return;
        }
        if self.wrote_header {
            self.logf(format_args!("http: superfluous response.WriteHeader call"));
            return;
        }
        if !(100..=999).contains(&code) {
            panic!("invalid WriteHeader code {code}");
        }
        if code == 100 || code >= 200 {
            self.disable_write_continue(code >= 200);
        }
        if (100..=199).contains(&code) && code != 101 {
            let is11 = self.proto_at_least(1, 1);
            let hh = self.handler_header.clone();
            self.with_bufw(|bw| {
                write_status_line(bw, is11, code);
                let mut ex = BTreeMap::new();
                ex.insert("Content-Length".to_owned(), true);
                ex.insert("Transfer-Encoding".to_owned(), true);
                let _ = hh.write_subset(bw, &ex);
                let _ = bw.write_all(b"\r\n");
                let _ = bw.flush();
            });
            return;
        }
        self.wrote_header = true;
        self.status = code;
        if self.request_body_limit_hit.load(Ordering::SeqCst)
            && !self.handler_header.0.contains_key("Connection")
        {
            self.handler_header.set("Connection", "close");
        }
        if self.called_header && self.cw_header.is_none() {
            self.cw_header = Some(self.handler_header.clone());
        }
        let cl = self.handler_header.get_exact("Content-Length").to_owned();
        if !cl.is_empty() {
            match cl.parse::<i64>() {
                Ok(v) if v >= 0 => self.content_length = v,
                _ => {
                    self.logf(format_args!(
                        "http: invalid Content-Length of {}",
                        crate::strconv::quote(&cl)
                    ));
                    self.handler_header.del("Content-Length");
                }
            }
        }
    }

    fn write_impl(&mut self, data: &[u8], as_string: bool) -> io::Result<usize> {
        if self.conn.hijacked() {
            if !data.is_empty() {
                self.logf(format_args!("http: response.Write on hijacked connection"));
            }
            return Err(super::header::io_error(ERR_HIJACKED));
        }
        if self.can_write_continue() {
            self.disable_write_continue(true);
        }
        if !self.wrote_header {
            self.write_header_impl(STATUS_OK);
        }
        if data.is_empty() {
            return Ok(0);
        }
        if !self.body_allowed() {
            return Err(super::header::io_error(ERR_BODY_NOT_ALLOWED));
        }
        self.written += data.len() as i64;
        if self.content_length != -1 && self.written > self.content_length {
            return Err(super::header::io_error(ERR_CONTENT_LENGTH));
        }
        if as_string {
            self.w_write_string(data)
        } else {
            self.w_write(data)
        }
    }

    fn finish_request(&mut self, req: &Request) {
        self.handler_done.store(true, Ordering::SeqCst);
        if !self.wrote_header {
            self.write_header_impl(STATUS_OK);
        }
        let _ = self.w_flush();
        self.cw_close();
        let _ = self.with_bufw(|bw| bw.flush());
        self.conn.r.abort_pending_read();
        if let Some(rb) = &self.req_body {
            rb.register_on_hit_eof(None);
        }
        // Go removes the temporary files of a parsed multipart form here.
        if let Some(form) = &req.multipart_form {
            let _ = form.remove_all();
        }
        if self.can_write_continue() {
            self.disable_write_continue(true);
        }
        if let Some(rb) = &self.req_body {
            let _ = rb.close();
        }
    }

    fn should_reuse_connection(&self) -> bool {
        if self.close_after_reply.load(Ordering::SeqCst) {
            return false;
        }
        if self.method != "HEAD"
            && self.content_length != -1
            && self.body_allowed()
            && self.content_length != self.written
        {
            return false;
        }
        if lock(&self.conn.werr).is_some() {
            return false;
        }
        if self.closed_request_body_early() {
            return false;
        }
        true
    }

    fn closed_request_body_early(&self) -> bool {
        self.req_body
            .as_ref()
            .is_some_and(BodyHandle::did_early_close)
    }

    fn send_expectation_failed(&mut self) {
        self.header_mut().set("Connection", "close");
        self.write_header_impl(STATUS_EXPECTATION_FAILED);
        let req = Request::default();
        self.finish_request(&req);
    }

    /// Go's `response.ReadFrom`. Only a plain TCP connection (Go: a
    /// `net.Conn` that is an `io.ReaderFrom`) takes the direct path: the first
    /// `SNIFF_LEN` bytes go through the normal write path so the content type
    /// can be sniffed, then the header and buffered data are flushed and the
    /// rest of `src` is streamed to the connection, bypassing the 2048-byte
    /// buffer (so a longer body without a Content-Length is chunked).
    fn read_from(&mut self, src: &mut dyn Read) -> io::Result<u64> {
        let direct = !self.conn.hijacked()
            && self
                .conn
                .rwc
                .as_any()
                .downcast_ref::<net::TCPConn>()
                .is_some();
        if !direct {
            return io::copy(src, self);
        }
        let mut n = 0;
        if !self.cw_wrote_header {
            let n0 = io::copy(&mut Read::take(&mut *src, SNIFF_LEN as u64), self)?;
            n += n0;
            if n0 < SNIFF_LEN as u64 {
                return Ok(n);
            }
        }
        self.w_flush()?;
        self.cw_flush()?;
        if !self.cw_chunking && self.body_allowed() && self.method != "HEAD" {
            let limited = self.content_length != -1;
            let mut remaining = if limited {
                (self.content_length - self.written).max(0) as u64
            } else {
                u64::MAX
            };
            let mut buf = vec![0u8; 32 * 1024];
            while remaining > 0 {
                let want = buf
                    .len()
                    .min(usize::try_from(remaining).unwrap_or(usize::MAX));
                let k = match src.read(&mut buf[..want]) {
                    Ok(0) => break,
                    Ok(k) => k,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                };
                self.cw_write(&buf[..k])?;
                self.written += k as i64;
                n += k as u64;
                remaining -= k as u64;
            }
            // Excess bytes from src are ignored and reported, as in
            // `response.Write`.
            if limited && self.written == self.content_length {
                let mut one = [0u8; 1];
                if matches!(src.read(&mut one), Ok(k) if k != 0) {
                    return Err(super::header::io_error(ERR_CONTENT_LENGTH));
                }
            }
            return Ok(n);
        }
        Ok(n + io::copy(src, self)?)
    }

    fn flush_error_impl(&mut self) -> io::Result<()> {
        if !self.wrote_header {
            self.write_header_impl(STATUS_OK);
        }
        let err = self.w_flush();
        let e2 = self.cw_flush();
        err.and(e2)
    }
}

fn valid_trailer_header(name: &str) -> bool {
    let n = crate::net::textproto::canonical_mime_header_key(name);
    if n.starts_with("If-") || bad_trailer_key(&n) {
        return false;
    }
    true
}
fn bad_trailer_key(k: &str) -> bool {
    matches!(
        k,
        "Authorization"
            | "Cache-Control"
            | "Connection"
            | "Content-Encoding"
            | "Content-Length"
            | "Content-Range"
            | "Content-Type"
            | "Expect"
            | "Host"
            | "Keep-Alive"
            | "Max-Forwards"
            | "Pragma"
            | "Proxy-Authenticate"
            | "Proxy-Authorization"
            | "Proxy-Connection"
            | "Range"
            | "Realm"
            | "Te"
            | "Trailer"
            | "Transfer-Encoding"
            | "Www-Authenticate"
    )
}

fn foreach_header_element(v: &str, mut f: impl FnMut(&str)) {
    let v = crate::net::textproto::trim_string(v);
    if v.is_empty() {
        return;
    }
    if !v.contains(',') {
        f(v);
        return;
    }
    for p in v.split(',') {
        let p = crate::net::textproto::trim_string(p);
        if !p.is_empty() {
            f(p);
        }
    }
}

fn write_status_line(bw: &mut impl Write, is11: bool, code: u16) {
    let _ = bw.write_all(if is11 { b"HTTP/1.1 " } else { b"HTTP/1.0 " });
    let text = status_text(code);
    if text.is_empty() {
        let _ = write!(bw, "{code:03} status code {code}\r\n");
    } else {
        let _ = write!(bw, "{code} {text}\r\n");
    }
}

impl std::io::Write for ServerResponse {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.write_impl(data, false)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl ResponseWriter for ServerResponse {
    fn header(&mut self) -> &mut Header {
        self.header_mut()
    }
    fn write_string(&mut self, s: &str) -> io::Result<usize> {
        self.write_impl(s.as_bytes(), true)
    }
    fn write_header(&mut self, code: u16) {
        self.write_header_impl(code);
    }
    fn copy_from(&mut self, src: &mut dyn Read) -> io::Result<u64> {
        self.read_from(src)
    }
    fn flusher(&mut self) -> Option<&mut dyn Flusher> {
        Some(self)
    }
    fn hijacker(&mut self) -> Option<&mut dyn Hijacker> {
        Some(self)
    }
    fn close_notifier(&mut self) -> Option<&mut dyn CloseNotifier> {
        Some(self)
    }
    fn conn_control(&mut self) -> Option<&mut dyn ConnControl> {
        Some(self)
    }
    fn request_too_large_hook(&mut self) -> Option<Arc<dyn Fn() + Send + Sync>> {
        let close = self.close_after_reply.clone();
        let hit = self.request_body_limit_hit.clone();
        Some(Arc::new(move || {
            close.store(true, Ordering::SeqCst);
            hit.store(true, Ordering::SeqCst);
        }))
    }
}

impl Flusher for ServerResponse {
    fn flush(&mut self) {
        let _ = self.flush_error_impl();
    }
    fn flush_error(&mut self) -> Result<(), BoxError> {
        self.flush_error_impl().map_err(|e| Box::new(e) as BoxError)
    }
}

impl Hijacker for ServerResponse {
    fn hijack(&mut self) -> Result<Hijacked, BoxError> {
        if self.handler_done.load(Ordering::SeqCst) {
            panic!("net/http: Hijack called after ServeHTTP finished");
        }
        self.disable_write_continue(false);
        if self.wrote_header {
            let _ = self.cw_flush();
        }
        let c = self.conn.clone();
        let mut m = lock(&c.mu);
        if m.hijacked {
            return Err(Box::new(ERR_HIJACKED));
        }
        c.r.abort_pending_read();
        m.hijacked = true;
        drop(m);
        let rwc = c.rwc.clone();
        let _ = rwc.set_deadline(&Time::default());
        // Anything buffered but unwritten is dropped, as bufw.Reset does.
        *lock(&c.bufw) = None;
        self.wbuf.clear();
        let writer: bufio::Writer<Box<dyn Write + Send>> =
            bufio::Writer::new(Box::new(RawConnWriter(rwc.clone())));
        c.set_state(STATE_HIJACKED, true);
        Ok(Hijacked {
            conn: Box::new(SharedConn(rwc)),
            reader: c.bufr.clone(),
            writer,
        })
    }
}

impl ConnControl for ServerResponse {
    fn set_read_deadline(&mut self, deadline: &Time) -> Result<(), BoxError> {
        self.conn
            .rwc
            .set_read_deadline(deadline)
            .map_err(|e| Box::new(e) as BoxError)
    }
    fn set_write_deadline(&mut self, deadline: &Time) -> Result<(), BoxError> {
        self.conn
            .rwc
            .set_write_deadline(deadline)
            .map_err(|e| Box::new(e) as BoxError)
    }
    fn enable_full_duplex(&mut self) -> Result<(), BoxError> {
        self.full_duplex = true;
        Ok(())
    }
}

impl CloseNotifier for ServerResponse {
    fn close_notify(&mut self) -> std::sync::mpsc::Receiver<bool> {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut g = lock(&self.close_notify.0);
        if g.triggered {
            let _ = tx.send(true);
        }
        g.tx = Some(tx);
        rx
    }
}

#[allow(dead_code)]
fn _unused() {
    let _ = contains_ctl_byte;
    let _ = html_escape;
    let _ = is_error::<ErrorString>;
}
