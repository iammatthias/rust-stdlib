//! The HTTP/2 client connection (Go's `http2.ClientConn` and connection
//! pool). One reader thread parses frames per connection; each request runs
//! a helper thread that writes the request and waits for the stream to end,
//! while the caller blocks until the response headers arrive.
//!
//! Lock order: `Cc::wmu` before `Cc::mu` before a stream's `Cs::m`.
use super::flow::{self, Inflow, Outflow};
use super::frame::*;
use super::hpack::{Decoder, Encoder, HeaderField};
use super::pipe::Pipe;
use super::{
    adjust_http1_max_header_size, foreach_header_element, Config, H2Error,
    INITIAL_HEADER_TABLE_SIZE, INITIAL_WINDOW_SIZE,
};
use crate::context::Context;
use crate::net::http::body::{Body, NoBody, ReadCloser};
use crate::net::http::header::{has_token, Header, Trailer};
use crate::net::http::httptrace::{self, ClientTrace, WroteRequestInfo};
use crate::net::http::request::{valid_host_header, Request};
use crate::net::http::response::Response;
use crate::net::http::status_text;
use crate::net::http::tlsstate::ConnectionState;
use crate::net::textproto::canonical_mime_header_key;
use crate::net::Conn;
use std::{
    collections::HashMap,
    io::{self, Read},
    sync::{Arc, Condvar, Mutex, MutexGuard, Weak},
    time::{Duration, Instant},
};

const DEFAULT_USER_AGENT: &str = "Go-http-client/2.0";
const INITIAL_MAX_CONCURRENT_STREAMS: u32 = 100;
const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 1000;

pub const ERR_CLIENT_CONN_UNUSABLE: &str = "http2: client conn not usable";
pub const ERR_CLIENT_CONN_NOT_ESTABLISHED: &str = "http2: client conn could not be established";
pub const ERR_CLIENT_CONN_GOT_GOAWAY: &str =
    "http2: Transport received Server's graceful shutdown GOAWAY";
pub const ERR_CLIENT_CONN_CLOSED: &str = "http2: client conn is closed";
pub const ERR_CLIENT_CONN_FORCE_CLOSED: &str =
    "http2: client connection force closed via ClientConn.Close";
pub const ERR_RESPONSE_HEADER_LIST_SIZE: &str =
    "http2: response header list larger than advertised limit";
pub const ERR_REQUEST_HEADER_LIST_SIZE: &str =
    "request header list larger than peer's advertised limit";
pub const ERR_TIMEOUT: &str = "http2: timeout awaiting response headers";
pub const ERR_REQUEST_CANCELED: &str = "net/http: request canceled";
const ERR_STOP_REQ_BODY_WRITE: &str = "http2: aborting request body write";
const ERR_REQ_BODY_TOO_LONG: &str = "http2: request body larger than specified content length";
const ERR_CLOSED_RESPONSE_BODY: &str = "http2: response body closed";
const ERR_STOP_READ_LOOP: &str = "client connection is closing (BUG: this is not user visible)";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// What the HTTP/2 client needs from the owning `http.Transport`.
#[derive(Clone)]
pub(crate) struct TransportConfig {
    pub conf: Config,
    pub disable_compression: bool,
    pub disable_keep_alives: bool,
    pub expect_continue_timeout: Duration,
    pub response_header_timeout: Duration,
    pub idle_conn_timeout: Duration,
    pub max_response_header_bytes: i64,
}

impl TransportConfig {
    /// Go's `Transport.maxHeaderListSize`.
    fn max_header_list_size(&self) -> u32 {
        let mut n: i64 = 0;
        if self.max_response_header_bytes != 0 {
            n = self.max_response_header_bytes;
            if n > 0 {
                n = adjust_http1_max_header_size(n);
            }
        }
        if n <= 0 {
            return 10 << 20;
        }
        if n >= 0xffff_ffff {
            return 0;
        }
        n as u32
    }
}

// ----------------------------------------------------------------- state

#[derive(Clone)]
struct GoAwayInfo {
    last_stream_id: u32,
    code: ErrCode,
    debug: String,
}

struct StreamEntry {
    cs: Arc<Cs>,
    flow: Outflow,
    inflow: Inflow,
}

type Ping = Arc<(Mutex<bool>, Condvar)>;

struct CcState {
    flow: Outflow,
    inflow: Inflow,
    do_not_reuse: bool,
    closing: bool,
    closed: bool,
    closed_on_idle: bool,
    seen_settings: bool,
    want_settings_ack: bool,
    go_away: Option<GoAwayInfo>,
    streams: HashMap<u32, StreamEntry>,
    streams_reserved: i32,
    next_stream_id: u32,
    pending_requests: i32,
    pings: HashMap<[u8; 8], Ping>,
    last_active: Instant,
    last_idle: Option<Instant>,
    max_frame_size: u32,
    max_concurrent_streams: u32,
    peer_max_header_list_size: u64,
    initial_window_size: u32,
    initial_stream_recv_window: i32,
    strict_max_concurrent_streams: bool,
    rst_stream_pings_blocked: bool,
    pending_resets: i32,
    read_before_stream_id: u32,
    last_frame_read: Instant,
    reader_err: Option<H2Error>,
    reader_done: bool,
    idle_deadline: Option<Instant>,
}

struct WState {
    fr: FrameWriter<Vec<u8>>,
    henc: Encoder,
    werr: Option<Arc<io::Error>>,
}

pub(crate) struct Cc {
    cfg: Arc<TransportConfig>,
    conn: Arc<dyn Conn>,
    tls_state: Option<Arc<ConnectionState>>,
    reused: Mutex<bool>,
    single_use: bool,
    mu: Mutex<CcState>,
    cond: Condvar,
    wmu: Mutex<WState>,
    /// Orders stream-ID assignment with HEADERS writes (Go's `reqHeaderMu`).
    req_header: Mutex<bool>,
    req_header_cv: Condvar,
    pool: Mutex<Option<Weak<Pool>>>,
    state_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    read_idle_timeout: Duration,
    ping_timeout: Duration,
    idle_timeout: Duration,
}

/// A client connection (Go's `http2.ClientConn`).
#[derive(Clone)]
pub(crate) struct ClientConn(pub(crate) Arc<Cc>);

impl PartialEq for ClientConn {
    fn eq(&self, o: &Self) -> bool {
        Arc::ptr_eq(&self.0, &o.0)
    }
}

// ---------------------------------------------------------- client stream

#[derive(Default)]
struct CsState {
    abort_err: Option<H2Error>,
    aborted: bool,
    res: Option<ResParts>,
    res_taken: bool,
    peer_closed: bool,
    done: bool,
    req_body_closed: bool,
    sent_end_stream: bool,
    sent_headers: bool,
    first_byte: bool,
    past_headers: bool,
    past_trailers: bool,
    read_closed: bool,
    read_aborted: bool,
    total_header_size: i64,
    trailer: Option<Header>,
    got_100: bool,
    bytes_remain: i64,
}

/// The response head the reader hands to the waiting caller.
struct ResParts {
    status: String,
    status_code: u16,
    header: Header,
    trailer: Option<Header>,
    content_length: i64,
    body: ResBodyKind,
    uncompressed: bool,
}

enum ResBodyKind {
    None,
    Missing,
    Stream,
}

pub(crate) struct Cs {
    cc: Arc<Cc>,
    ctx: Context,
    /// The request context's `httptrace.ClientTrace` (Go's `cs.trace`).
    trace: Option<Arc<ClientTrace>>,
    id: Mutex<u32>,
    m: Mutex<CsState>,
    cv: Condvar,
    buf_pipe: Pipe,
    requested_gzip: bool,
    is_head: bool,
    req_body_content_length: i64,
    req_body: Mutex<Option<Body>>,
    res_trailer: Trailer,
    /// Runs once the stream is finished and the response (if any) was handed out.
    on_done: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Cs {
    /// Go's `traceWroteRequest`.
    fn trace_wrote_request(&self, err: Option<&H2Error>) {
        if let Some(f) = self.trace.as_ref().and_then(|t| t.wrote_request.as_ref()) {
            f(WroteRequestInfo {
                err: err.map(|e| Arc::new(e.clone()) as httptrace::SharedError),
            });
        }
    }

    fn id(&self) -> u32 {
        *lock(&self.id)
    }

    fn state(&self) -> MutexGuard<'_, CsState> {
        lock(&self.m)
    }

    fn set_abort(&self, err: H2Error) {
        {
            let mut g = self.state();
            if !g.aborted {
                g.aborted = true;
                g.abort_err = Some(err);
            }
        }
        self.cv.notify_all();
    }

    /// Go's `abortStream`.
    fn abort_stream(&self, err: H2Error) {
        self.set_abort(err);
        self.close_req_body_async();
        self.cc.cond.notify_all();
    }

    /// Go's `abortStreamLocked` (the caller holds `cc.mu`).
    fn abort_stream_locked(&self, err: H2Error) {
        self.set_abort(err);
        self.close_req_body_async();
        self.cc.cond.notify_all();
    }

    fn aborted(&self) -> Option<H2Error> {
        let g = self.state();
        if g.aborted {
            g.abort_err.clone()
        } else {
            None
        }
    }

    /// Go's `closeReqBodyLocked`: closes the request body on its own thread
    /// so a blocked `Read` cannot hold the caller up.
    fn close_req_body_async(&self) {
        let body = lock(&self.req_body).clone();
        let Some(body) = body else {
            return;
        };
        {
            let mut g = self.state();
            if g.req_body_closed {
                return;
            }
            g.req_body_closed = true;
        }
        std::thread::spawn(move || {
            let _ = body.close();
        });
    }

    fn ctx_err(&self) -> Option<H2Error> {
        self.ctx.err().map(|_| H2Error::msg(ERR_REQUEST_CANCELED))
    }
}

// ----------------------------------------------------------------- pool

/// Go's `clientConnPool` for connections handed over by the transport.
#[derive(Default)]
pub(crate) struct Pool {
    conns: Mutex<HashMap<String, Vec<ClientConn>>>,
}

impl Pool {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Go's `getClientConn` without dialing: a connection that accepts a new
    /// request, with a stream slot reserved on it.
    pub(crate) fn get_cached(&self, addr: &str) -> Option<ClientConn> {
        let conns = lock(&self.conns);
        for cc in conns.get(addr).into_iter().flatten() {
            if cc.reserve_new_request() {
                return Some(cc.clone());
            }
        }
        None
    }

    /// Go's `addConnIfNeeded`: false when an existing connection can take
    /// requests (the new one should be closed by the caller).
    pub(crate) fn add_conn_if_needed(self: &Arc<Self>, key: &str, cc: ClientConn) -> bool {
        let mut conns = lock(&self.conns);
        for existing in conns.get(key).into_iter().flatten() {
            if existing.can_take_new_request() {
                return false;
            }
        }
        *lock(&cc.0.pool) = Some(Arc::downgrade(self));
        conns.entry(key.to_owned()).or_default().push(cc);
        true
    }

    /// Go's `MarkDead`.
    pub(crate) fn mark_dead(&self, cc: &ClientConn) {
        let mut conns = lock(&self.conns);
        conns.retain(|_, v| {
            v.retain(|c| c != cc);
            !v.is_empty()
        });
    }

    /// Go's `closeIdleConnections`.
    pub(crate) fn close_idle_connections(&self) {
        let all: Vec<ClientConn> = lock(&self.conns).values().flatten().cloned().collect();
        for cc in all {
            cc.close_if_idle();
        }
    }
}

// ------------------------------------------------------ connection setup

struct ConnRead(Arc<dyn Conn>);
impl Read for ConnRead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf).map_err(|e| e.into_io())
    }
}

fn io_err(e: &io::Error) -> io::Error {
    io::Error::new(e.kind(), e.to_string())
}

impl ClientConn {
    /// Go's `Transport.newClientConn`: sends the preface and starts the
    /// reader. `strict` is true for the `http.ClientConn` flavour.
    pub(crate) fn new(
        cfg: Arc<TransportConfig>,
        conn: Arc<dyn Conn>,
        tls_state: Option<Arc<ConnectionState>>,
        single_use: bool,
        strict: bool,
        state_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> Result<ClientConn, H2Error> {
        let conf = cfg.conf.clone();
        let mut henc = Encoder::new();
        henc.set_max_dynamic_table_size_limit(conf.max_encoder_header_table_size as u32);
        let now = Instant::now();
        let mut st = CcState {
            flow: Outflow::default(),
            inflow: Inflow::default(),
            do_not_reuse: false,
            closing: false,
            closed: false,
            closed_on_idle: false,
            seen_settings: false,
            want_settings_ack: true,
            go_away: None,
            streams: HashMap::new(),
            streams_reserved: 0,
            next_stream_id: 1,
            pending_requests: 0,
            pings: HashMap::new(),
            last_active: now,
            last_idle: None,
            max_frame_size: 16 << 10,
            max_concurrent_streams: INITIAL_MAX_CONCURRENT_STREAMS,
            peer_max_header_list_size: u64::MAX,
            initial_window_size: 65535,
            initial_stream_recv_window: conf.max_receive_buffer_per_stream as i32,
            strict_max_concurrent_streams: conf.strict_max_concurrent_requests || strict,
            rst_stream_pings_blocked: false,
            pending_resets: 0,
            read_before_stream_id: 0,
            last_frame_read: now,
            reader_err: None,
            reader_done: false,
            idle_deadline: None,
        };
        st.flow.add(INITIAL_WINDOW_SIZE);
        st.inflow
            .init(conf.max_receive_buffer_per_connection as i32 + INITIAL_WINDOW_SIZE);
        let cc = Arc::new(Cc {
            cfg: cfg.clone(),
            conn: conn.clone(),
            tls_state,
            reused: Mutex::new(false),
            single_use,
            mu: Mutex::new(st),
            cond: Condvar::new(),
            wmu: Mutex::new(WState {
                fr: FrameWriter::new(Vec::new()),
                henc,
                werr: None,
            }),
            req_header: Mutex::new(false),
            req_header_cv: Condvar::new(),
            pool: Mutex::new(None),
            state_hook: Mutex::new(state_hook),
            read_idle_timeout: conf.send_ping_timeout.to_std(),
            ping_timeout: conf.ping_timeout.to_std(),
            idle_timeout: cfg.idle_conn_timeout,
        });

        // The client preface, our SETTINGS and the connection-level window.
        {
            let mut w = lock(&cc.wmu);
            w.fr.get_mut().extend_from_slice(CLIENT_PREFACE);
            let mut settings = vec![
                Setting {
                    id: SETTING_ENABLE_PUSH,
                    val: 0,
                },
                Setting {
                    id: SETTING_INITIAL_WINDOW_SIZE,
                    val: conf.max_receive_buffer_per_stream as u32,
                },
                Setting {
                    id: SETTING_MAX_FRAME_SIZE,
                    val: conf.max_read_frame_size as u32,
                },
            ];
            let max_hls = cfg.max_header_list_size();
            if max_hls != 0 {
                settings.push(Setting {
                    id: SETTING_MAX_HEADER_LIST_SIZE,
                    val: max_hls,
                });
            }
            if conf.max_decoder_header_table_size as u32 != INITIAL_HEADER_TABLE_SIZE {
                settings.push(Setting {
                    id: SETTING_HEADER_TABLE_SIZE,
                    val: conf.max_decoder_header_table_size as u32,
                });
            }
            let _ = w.fr.write_settings(&settings);
            let _ =
                w.fr.write_window_update(0, conf.max_receive_buffer_per_connection as u32);
            if let Err(e) = cc.flush_locked(&mut w) {
                drop(w);
                let _ = conn.close();
                return Err(H2Error::Io(Arc::new(e)));
            }
        }

        let reader_cc = cc.clone();
        std::thread::spawn(move || reader_cc.read_loop());
        if !cc.read_idle_timeout.is_zero() || !cc.idle_timeout.is_zero() {
            let timer_cc = cc.clone();
            std::thread::spawn(move || timer_cc.timer_loop());
        }
        Ok(ClientConn(cc))
    }
}

impl Cc {
    fn state(&self) -> MutexGuard<'_, CcState> {
        lock(&self.mu)
    }

    fn call_state_hook(&self) {
        let h = lock(&self.state_hook).clone();
        if let Some(h) = h {
            h();
        }
    }

    /// Writes the buffered frames to the connection.
    fn flush_locked(&self, w: &mut WState) -> io::Result<()> {
        if let Some(e) = &w.werr {
            w.fr.get_mut().clear();
            return Err(io_err(e));
        }
        let buf = std::mem::take(w.fr.get_mut());
        if buf.is_empty() {
            return Ok(());
        }
        let r = write_all(&*self.conn, &buf, self.cfg.conf.write_byte_timeout.to_std());
        let mut buf = buf;
        buf.clear();
        *w.fr.get_mut() = buf;
        if let Err(e) = &r {
            w.werr = Some(Arc::new(io_err(e)));
        }
        r
    }

    fn werr(&self) -> Option<Arc<io::Error>> {
        lock(&self.wmu).werr.clone()
    }

    // ------------------------------------------------------- idle state

    fn too_idle_locked(&self, g: &CcState) -> bool {
        !self.idle_timeout.is_zero() && g.last_idle.is_some_and(|t| t.elapsed() > self.idle_timeout)
    }

    fn is_usable_locked(&self, g: &CcState) -> bool {
        g.go_away.is_none()
            && !g.closed
            && !g.closing
            && !g.do_not_reuse
            && i64::from(g.next_stream_id) + 2 * i64::from(g.pending_requests) < i64::from(i32::MAX)
            && !self.too_idle_locked(g)
    }

    fn current_request_count_locked(g: &CcState) -> i32 {
        g.streams.len() as i32 + g.streams_reserved + g.pending_resets
    }

    fn can_take_new_request_locked(&self, g: &CcState) -> bool {
        if self.single_use && g.next_stream_id > 1 {
            return false;
        }
        let max_concurrent_okay = if g.strict_max_concurrent_streams {
            true
        } else {
            Self::current_request_count_locked(g) < g.max_concurrent_streams as i32
        };
        let mut can = max_concurrent_okay && self.is_usable_locked(g);
        if g.next_stream_id == 1 && g.streams_reserved == 0 && g.closed && !g.closed_on_idle {
            can = true;
        }
        can
    }

    fn can_reserve_locked(&self, g: &CcState) -> bool {
        if Self::current_request_count_locked(g) >= g.max_concurrent_streams as i32 {
            return false;
        }
        self.is_usable_locked(g)
    }

    fn available_locked(&self, g: &CcState) -> i64 {
        if !self.can_take_new_request_locked(g) {
            return 0;
        }
        (i64::from(g.max_concurrent_streams) - i64::from(Self::current_request_count_locked(g)))
            .max(0)
    }

    fn close_conn(&self) {
        let _ = self.conn.close();
        self.call_state_hook();
    }

    fn close_for_error(&self, err: H2Error) {
        {
            let mut g = self.state();
            g.closed = true;
            for e in g.streams.values() {
                e.cs.abort_stream_locked(err.clone());
            }
        }
        self.cond.notify_all();
        self.close_conn();
    }

    /// Go's `closeIfIdle`.
    fn close_if_idle(&self) {
        {
            let mut g = self.state();
            if !g.streams.is_empty() || g.streams_reserved > 0 {
                return;
            }
            g.closed = true;
            g.closed_on_idle = true;
        }
        self.cond.notify_all();
        self.close_conn();
    }

    fn mark_dead(self: &Arc<Self>) {
        let pool = lock(&self.pool).clone();
        if let Some(p) = pool.and_then(|w| w.upgrade()) {
            p.mark_dead(&ClientConn(self.clone()));
        }
    }

    /// Health checks (`Config.SendPingTimeout`) and idle-connection closing
    /// (`Transport.IdleConnTimeout`).
    fn timer_loop(self: Arc<Self>) {
        loop {
            let mut g = self.state();
            if g.reader_done || g.closed {
                return;
            }
            let now = Instant::now();
            let mut next: Option<Instant> = None;
            if !self.read_idle_timeout.is_zero() {
                let at = g.last_frame_read + self.read_idle_timeout;
                if at <= now {
                    drop(g);
                    self.clone().health_check();
                    self.state().last_frame_read = Instant::now();
                    continue;
                }
                next = Some(at);
            }
            if let Some(d) = g.idle_deadline {
                if d <= now {
                    g.idle_deadline = None;
                    drop(g);
                    self.close_if_idle();
                    continue;
                }
                next = Some(next.map_or(d, |n| n.min(d)));
            }
            let wait = next.map_or(Duration::from_secs(3600), |n| {
                n.saturating_duration_since(now)
            });
            let (g2, _) = self
                .cond
                .wait_timeout(g, wait.max(Duration::from_millis(1)))
                .unwrap_or_else(|e| e.into_inner());
            drop(g2);
        }
    }

    fn health_check(self: Arc<Self>) {
        if self.ping(Some(self.ping_timeout)).is_err() {
            if let Some(f) = &self.cfg.conf.count_error {
                f("conn_close_lost_ping");
            }
            self.close_for_error(H2Error::msg("http2: client connection lost"));
        }
    }

    /// Go's `Ping`.
    fn ping(&self, timeout: Option<Duration>) -> Result<(), H2Error> {
        let notify: Ping = Arc::new((Mutex::new(false), Condvar::new()));
        let data;
        loop {
            let p = rand_ping();
            let mut g = self.state();
            if let std::collections::hash_map::Entry::Vacant(v) = g.pings.entry(p) {
                v.insert(notify.clone());
                data = p;
                break;
            }
        }
        {
            let mut w = lock(&self.wmu);
            let r =
                w.fr.write_ping(false, data)
                    .map_err(H2Error::from_frame_error);
            let r = r.and_then(|()| {
                self.flush_locked(&mut w)
                    .map_err(|e| H2Error::Io(Arc::new(e)))
            });
            r?;
        }
        let start = Instant::now();
        let mut g = lock(&notify.0);
        while !*g {
            // Give up when the reader is gone.
            if self.state().reader_done {
                return Err(self
                    .state()
                    .reader_err
                    .clone()
                    .unwrap_or_else(|| H2Error::msg(ERR_CLIENT_CONN_CLOSED)));
            }
            let left = match timeout {
                None => Duration::from_millis(50),
                Some(t) => match t.checked_sub(start.elapsed()) {
                    Some(l) => l.min(Duration::from_millis(50)),
                    None => return Err(H2Error::DeadlineExceeded),
                },
            };
            g = notify
                .1
                .wait_timeout(g, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        Ok(())
    }
}

fn rand_ping() -> [u8; 8] {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut h = RandomState::new().build_hasher();
    h.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64),
    );
    h.finish().to_be_bytes()
}

fn write_all(conn: &dyn Conn, buf: &[u8], byte_timeout: Duration) -> io::Result<()> {
    let mut n = 0;
    while n < buf.len() {
        if !byte_timeout.is_zero() {
            let _ = conn.set_write_deadline(&crate::time::now().add(
                crate::time::Duration::from_nanos(byte_timeout.as_nanos() as i64),
            ));
        }
        match conn.write(&buf[n..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "short write")),
            Ok(k) => n += k,
            Err(e) => return Err(e.into_io()),
        }
    }
    if !byte_timeout.is_zero() {
        let _ = conn.set_write_deadline(&crate::time::Time::default());
    }
    Ok(())
}

// ------------------------------------------------------ ClientConn API

impl ClientConn {
    /// Go's `CanTakeNewRequest`.
    pub(crate) fn can_take_new_request(&self) -> bool {
        let g = self.0.state();
        self.0.can_take_new_request_locked(&g)
    }

    /// Go's `ReserveNewRequest`.
    pub(crate) fn reserve_new_request(&self) -> bool {
        let mut g = self.0.state();
        if !self.0.can_take_new_request_locked(&g) {
            return false;
        }
        g.streams_reserved += 1;
        true
    }

    /// `NetHTTPClientConn.Reserve`.
    pub(crate) fn reserve(&self) -> Result<(), H2Error> {
        let r = {
            let mut g = self.0.state();
            if !self.0.can_reserve_locked(&g) {
                Err(H2Error::msg("connection is unavailable"))
            } else {
                g.streams_reserved += 1;
                Ok(())
            }
        };
        self.0.call_state_hook();
        r
    }

    /// `NetHTTPClientConn.Release`.
    pub(crate) fn release(&self) {
        {
            let mut g = self.0.state();
            if g.streams_reserved > 0 {
                g.streams_reserved -= 1;
            }
        }
        self.0.call_state_hook();
    }

    /// `NetHTTPClientConn.Available`.
    pub(crate) fn available(&self) -> i64 {
        let g = self.0.state();
        self.0.available_locked(&g)
    }

    /// `NetHTTPClientConn.InFlight`.
    pub(crate) fn in_flight(&self) -> i64 {
        let g = self.0.state();
        i64::from(Cc::current_request_count_locked(&g))
    }

    /// `NetHTTPClientConn.Err`.
    pub(crate) fn err(&self) -> Option<String> {
        if self.0.state().closed {
            Some("connection closed".into())
        } else {
            None
        }
    }

    /// Go's `Close`.
    pub(crate) fn close(&self) {
        self.0
            .close_for_error(H2Error::msg(ERR_CLIENT_CONN_FORCE_CLOSED));
    }

    pub(crate) fn close_if_idle(&self) {
        self.0.close_if_idle();
    }

    pub(crate) fn set_state_hook(&self, hook: Option<Arc<dyn Fn() + Send + Sync>>) {
        *lock(&self.0.state_hook) = hook;
    }

    /// True once the connection has been marked reused by a request.
    /// Go's `traceGotConn` idleness: a reused connection with no stream in
    /// flight was idle, since its last activity.
    pub(crate) fn idle_info(&self, reused: bool) -> (bool, Duration) {
        let g = self.0.state();
        let idle = reused && g.streams.is_empty();
        let since = if idle {
            g.last_active.elapsed()
        } else {
            Duration::ZERO
        };
        (idle, since)
    }

    pub(crate) fn mark_reused(&self) -> bool {
        let mut r = lock(&self.0.reused);
        let was = *r;
        *r = true;
        was
    }

    /// The transport connection (Go's `cc.tconn`).
    pub(crate) fn conn(&self) -> Arc<dyn Conn> {
        self.0.conn.clone()
    }
}

// --------------------------------------------------------------- RoundTrip

/// Go's `actualContentLength`.
fn actual_content_length(req: &Request) -> i64 {
    match &req.body {
        None => 0,
        Some(b) if b.is_no_body() => 0,
        Some(_) => {
            if req.content_length != 0 {
                req.content_length
            } else {
                -1
            }
        }
    }
}

fn is_connection_close_request(req: &Request) -> bool {
    req.close
        || req
            .header
            .values("Connection")
            .iter()
            .any(|v| has_token(v, "close"))
}

/// `httpcommon.IsRequestGzip`.
fn is_request_gzip(req: &Request, disable_compression: bool) -> bool {
    !disable_compression
        && req.header.values("Accept-Encoding").is_empty()
        && req.header.values("Range").is_empty()
        && req.method != "HEAD"
}

impl ClientConn {
    /// Go's `ClientConn.RoundTrip`: sends `req` on a new stream and returns
    /// once the response headers have arrived. `ctx` is the request's
    /// context (already carrying `Request.Cancel`).
    pub(crate) fn round_trip(
        &self,
        req: &Request,
        ctx: &Context,
        on_done: Option<Box<dyn FnOnce() + Send>>,
    ) -> Result<Response, H2Error> {
        let cc = &self.0;
        let cs = Arc::new(Cs {
            cc: cc.clone(),
            ctx: ctx.clone(),
            trace: httptrace::context_client_trace(ctx),
            id: Mutex::new(0),
            m: Mutex::new(CsState {
                bytes_remain: -1,
                ..CsState::default()
            }),
            cv: Condvar::new(),
            buf_pipe: Pipe::default(),
            requested_gzip: is_request_gzip(req, cc.cfg.disable_compression),
            is_head: req.method == "HEAD",
            req_body_content_length: actual_content_length(req),
            req_body: Mutex::new(req.body.clone()),
            res_trailer: Trailer::new(None),
            on_done: Mutex::new(on_done),
        });

        // Wake the waiting threads when the request context ends.
        let stop = {
            let cs2 = cs.clone();
            ctx.after_func(move || {
                let err = cs2
                    .ctx_err()
                    .unwrap_or_else(|| H2Error::msg(ERR_REQUEST_CANCELED));
                cs2.abort_stream(err);
            })
        };

        let req2 = req.clone();
        let cs_w = cs.clone();
        std::thread::spawn(move || {
            let err = write_request(&cs_w, &req2);
            cleanup_write_request(&cs_w, err);
        });

        let result = {
            let mut g = cs.state();
            loop {
                if g.res.is_some() {
                    break self.handle_response_headers(&cs, g, req);
                }
                if g.aborted {
                    let err = g
                        .abort_err
                        .clone()
                        .unwrap_or_else(|| H2Error::msg("aborted"));
                    drop(g);
                    self.wait_done(&cs);
                    break Err(err);
                }
                g = cs.cv.wait(g).unwrap_or_else(|e| e.into_inner());
            }
        };
        let _ = stop();
        result
    }

    fn wait_done(&self, cs: &Arc<Cs>) {
        let mut g = cs.state();
        while !g.done {
            let (g2, _) = cs
                .cv
                .wait_timeout(g, Duration::from_millis(20))
                .unwrap_or_else(|e| e.into_inner());
            g = g2;
            if cs.ctx.err().is_some() {
                return;
            }
        }
    }

    fn handle_response_headers(
        &self,
        cs: &Arc<Cs>,
        mut g: MutexGuard<'_, CsState>,
        req: &Request,
    ) -> Result<Response, H2Error> {
        let parts = g.res.take().expect("response parts");
        g.res_taken = true;
        drop(g);
        if parts.status_code > 299 {
            // abortRequestBodyWrite
            let has_body = lock(&cs.req_body).is_some();
            if has_body {
                cs.close_req_body_async();
                self.0.cond.notify_all();
            }
        }
        let was_stream = matches!(parts.body, ResBodyKind::Stream);
        let mut body = match parts.body {
            ResBodyKind::None => Body::from(NoBody),
            ResBodyKind::Missing => Body::new(MissingBody),
            ResBodyKind::Stream => Body::new(ResponseBody {
                cs: cs.clone(),
                read_err: None,
            }),
        };
        let is_no_body = body.is_no_body();
        let mut header = parts.header;
        let mut content_length = parts.content_length;
        let mut uncompressed = parts.uncompressed;
        if was_stream
            && cs.requested_gzip
            && header
                .get_str("Content-Encoding")
                .eq_ignore_ascii_case("gzip")
        {
            header.del("Content-Encoding");
            header.del("Content-Length");
            content_length = -1;
            body = crate::net::http::transport::gzip_body(body);
            uncompressed = true;
        }
        let tr = match parts.trailer {
            Some(t) => {
                cs.res_trailer.set(Some(t));
                cs.res_trailer.clone()
            }
            None => cs.res_trailer.clone(),
        };
        let resp = Response {
            status: format!("{} {}", parts.status, status_text(parts.status_code)),
            status_code: parts.status_code,
            proto: "HTTP/2.0".into(),
            proto_major: 2,
            proto_minor: 0,
            header,
            body: Some(body),
            content_length,
            uncompressed,
            trailer: tr,
            tls: self.0.tls_state.clone(),
            ..Response::default()
        };
        if is_no_body && actual_content_length(req) == 0 {
            // Wait for the stream to finish (the body is empty both ways).
            self.wait_done(cs);
        }
        Ok(resp)
    }
}

// ---------------------------------------------------- request encoding

/// `httpcommon.EncodeHeaders`.
fn encode_request_headers(
    req: &Request,
    add_gzip: bool,
    peer_max_header_list_size: u64,
    actual_cl: i64,
    headerf: &mut dyn FnMut(&str, &str),
) -> Result<(bool, bool), H2Error> {
    let err = |s: String| Err(H2Error::msg(s));
    // checkConnHeaders
    let up = req.header.values("Upgrade");
    if !up.is_empty() && (!up[0].is_empty() && up[0] != "chunked") {
        return err(format!(
            "invalid Upgrade request header: {}",
            quote_list(&up)
        ));
    }
    let te = req.header.values("Transfer-Encoding");
    if !te.is_empty() && (te.len() > 1 || (!te[0].is_empty() && te[0] != "chunked")) {
        return err(format!(
            "invalid Transfer-Encoding request header: {}",
            quote_list(&te)
        ));
    }
    let conn = req.header.values("Connection");
    if !conn.is_empty()
        && (conn.len() > 1
            || (!conn[0].is_empty()
                && !conn[0].eq_ignore_ascii_case("close")
                && !conn[0].eq_ignore_ascii_case("keep-alive")))
    {
        return err(format!(
            "invalid Connection request header: {}",
            quote_list(&conn)
        ));
    }
    if req.url == crate::net::url::Url::default() {
        return err("Request.URL is nil".into());
    }
    let host = if req.host.is_empty() {
        req.url.host.clone()
    } else {
        req.host.clone()
    };
    if !valid_host_header(&host) {
        return err("invalid Host header".into());
    }
    let protocol = req
        .header
        .values(":protocol")
        .first()
        .cloned()
        .unwrap_or_default();
    let mut is_normal_connect = false;
    if req.method == "CONNECT" && protocol.is_empty() {
        is_normal_connect = true;
    } else if !protocol.is_empty() && req.method != "CONNECT" {
        return err("invalid :protocol header in non-CONNECT request".into());
    }
    let mut path = String::new();
    if !is_normal_connect {
        path = req.url.request_uri();
        let valid_pseudo_path = |v: &str| v.starts_with('/') || v == "*";
        if !valid_pseudo_path(&path) {
            let orig = path.clone();
            let prefix = format!("{}://{}", req.url.scheme, host);
            path = path.strip_prefix(&prefix).unwrap_or(&path).to_owned();
            if !valid_pseudo_path(&path) {
                if !req.url.opaque.is_empty() {
                    return err(format!(
                        "invalid request :path {} from URL.Opaque = {}",
                        crate::strconv::quote(&orig),
                        crate::strconv::quote(&req.url.opaque)
                    ));
                }
                return err(format!(
                    "invalid request :path {}",
                    crate::strconv::quote(&orig)
                ));
            }
        }
    }
    let validate = |h: &Header| -> Option<String> {
        for (k, vv) in &h.0 {
            if !crate::net::http::header::valid_header_field_name(k) && k != ":protocol" {
                return Some(format!("name {}", crate::strconv::quote(k)));
            }
            for v in vv {
                if !crate::net::http::header::valid_header_field_value(v) {
                    return Some(format!("value for header {}", crate::strconv::quote(k)));
                }
            }
        }
        None
    };
    if let Some(e) = validate(&req.header) {
        return err(format!("invalid HTTP header {e}"));
    }
    let trailer = req.trailer.get();
    if let Some(t) = &trailer {
        if let Some(e) = validate(t) {
            return err(format!("invalid HTTP trailer {e}"));
        }
    }
    // commaSeparatedTrailers
    let mut keys: Vec<String> = Vec::new();
    if let Some(t) = &trailer {
        for k in t.0.keys() {
            let k = canonical_mime_header_key(k);
            match k.as_str() {
                "Transfer-Encoding" | "Trailer" | "Content-Length" => {
                    return err(format!("invalid Trailer key {}", crate::strconv::quote(&k)));
                }
                _ => keys.push(k),
            }
        }
    }
    keys.sort();
    let trailers = keys.join(",");

    let method = if req.method.is_empty() {
        "GET"
    } else {
        &req.method
    };
    let mut fields: Vec<(String, String)> = Vec::new();
    fields.push((":authority".into(), host));
    fields.push((":method".into(), method.to_owned()));
    if !is_normal_connect {
        fields.push((":path".into(), path));
        fields.push((":scheme".into(), req.url.scheme.clone()));
    }
    if !protocol.is_empty() {
        fields.push((":protocol".into(), protocol));
    }
    if !trailers.is_empty() {
        fields.push(("trailer".into(), trailers.clone()));
    }
    let mut did_ua = false;
    for (k, vv) in &req.header.0 {
        let lk = k.to_ascii_lowercase();
        let mut vv: &[String] = vv;
        match lk.as_str() {
            "host" | "content-length" => continue,
            "connection" | "proxy-connection" | "transfer-encoding" | "upgrade" | "keep-alive" => {
                continue
            }
            "user-agent" => {
                did_ua = true;
                if vv.is_empty() {
                    continue;
                }
                vv = &vv[..1];
                if vv[0].is_empty() {
                    continue;
                }
            }
            "cookie" => {
                for v in vv {
                    let mut v: &str = v;
                    while let Some(p) = v.find(';') {
                        fields.push(("cookie".into(), v[..p].to_owned()));
                        let mut p = p + 1;
                        while p < v.len() && v.as_bytes()[p] == b' ' {
                            p += 1;
                        }
                        v = &v[p..];
                    }
                    if !v.is_empty() {
                        fields.push(("cookie".into(), v.to_owned()));
                    }
                }
                continue;
            }
            _ => {
                if k == ":protocol" {
                    continue;
                }
            }
        }
        for v in vv {
            fields.push((k.clone(), v.clone()));
        }
    }
    let send_cl = if actual_cl > 0 {
        true
    } else if actual_cl < 0 {
        false
    } else {
        matches!(method, "POST" | "PUT" | "PATCH")
    };
    if send_cl {
        fields.push(("content-length".into(), actual_cl.to_string()));
    }
    if add_gzip {
        fields.push(("accept-encoding".into(), "gzip".into()));
    }
    if !did_ua {
        fields.push(("user-agent".into(), DEFAULT_USER_AGENT.into()));
    }
    if peer_max_header_list_size > 0 {
        let mut hl: u64 = 0;
        for (n, v) in &fields {
            hl += (n.len() + v.len() + 32) as u64;
        }
        if hl > peer_max_header_list_size {
            return err(ERR_REQUEST_HEADER_LIST_SIZE.into());
        }
    }
    for (name, value) in &fields {
        // LowerHeader: ASCII printable only.
        if !name.bytes().all(|b| (b' '..=b'~').contains(&b)) {
            continue;
        }
        headerf(&name.to_ascii_lowercase(), value);
    }
    Ok((actual_cl != 0, !trailers.is_empty()))
}

fn quote_list(v: &[String]) -> String {
    let parts: Vec<String> = v.iter().map(crate::strconv::quote).collect();
    format!("[{}]", parts.join(" "))
}

// ------------------------------------------------------- request writer

fn acquire_req_header(cs: &Arc<Cs>) -> Result<(), H2Error> {
    let cc = &cs.cc;
    let mut held = lock(&cc.req_header);
    loop {
        if let Some(e) = cs.aborted() {
            return Err(e);
        }
        if let Some(e) = cs.ctx_err() {
            return Err(e);
        }
        if !*held {
            *held = true;
            return Ok(());
        }
        held = cc
            .req_header_cv
            .wait_timeout(held, Duration::from_millis(20))
            .unwrap_or_else(|e| e.into_inner())
            .0;
    }
}

fn release_req_header(cc: &Cc) {
    *lock(&cc.req_header) = false;
    cc.req_header_cv.notify_one();
}

/// Go's `clientStream.writeRequest`.
fn write_request(cs: &Arc<Cs>, req: &Request) -> Result<(), H2Error> {
    let cc = cs.cc.clone();
    acquire_req_header(cs)?;

    // Wait for an open stream slot and assign the stream ID.
    {
        let mut g = cc.state();
        g.idle_deadline = None;
        if g.streams_reserved > 0 {
            g.streams_reserved -= 1;
        }
        let err = loop {
            if g.closed && g.next_stream_id == 1 && g.streams_reserved == 0 {
                break Some(H2Error::msg(ERR_CLIENT_CONN_NOT_ESTABLISHED));
            }
            g.last_active = Instant::now();
            if g.closed || !cc.can_take_new_request_locked(&g) {
                break Some(H2Error::msg(ERR_CLIENT_CONN_UNUSABLE));
            }
            g.last_idle = None;
            if Cc::current_request_count_locked(&g) < g.max_concurrent_streams as i32 {
                break None;
            }
            g.pending_requests += 1;
            g = cc.cond.wait(g).unwrap_or_else(|e| e.into_inner());
            g.pending_requests -= 1;
            if let Some(e) = cs.aborted() {
                break Some(e);
            }
            if let Some(e) = cs.ctx_err() {
                break Some(e);
            }
        };
        if let Some(e) = err {
            drop(g);
            release_req_header(&cc);
            return Err(e);
        }
        // addStreamLocked
        let id = g.next_stream_id;
        g.next_stream_id += 2;
        *lock(&cs.id) = id;
        let mut entry = StreamEntry {
            cs: cs.clone(),
            flow: Outflow::default(),
            inflow: Inflow::default(),
        };
        entry.flow.add(g.initial_window_size as i32);
        entry.inflow.init(g.initial_stream_recv_window);
        g.streams.insert(id, entry);
        if is_connection_close_request(req) {
            g.do_not_reuse = true;
        }
    }

    let mut continue_timeout = cc.cfg.expect_continue_timeout;
    if !continue_timeout.is_zero() {
        let expects = req
            .header
            .values("Expect")
            .iter()
            .any(|v| has_token(v, "100-continue"));
        if !expects {
            continue_timeout = Duration::ZERO;
        }
    }

    let r = encode_and_write_headers(cs, req);
    release_req_header(&cc);
    r?;

    let has_body = cs.req_body_content_length != 0;
    // The error Go's final traceWroteRequest reports (errStopReqBodyWrite is
    // swallowed by the caller but still traced).
    let mut wrote_err: Option<H2Error> = None;
    if !has_body {
        cs.state().sent_end_stream = true;
    } else {
        if !continue_timeout.is_zero() {
            if let Some(f) = cs.trace.as_ref().and_then(|t| t.wait_100_continue.as_ref()) {
                f();
            }
            let deadline = Instant::now() + continue_timeout;
            let mut g = cs.state();
            loop {
                if g.got_100 {
                    break;
                }
                if g.aborted {
                    let e = g
                        .abort_err
                        .clone()
                        .unwrap_or_else(|| H2Error::msg("aborted"));
                    drop(g);
                    cs.trace_wrote_request(Some(&e));
                    return Err(e);
                }
                if cs.ctx.err().is_some() {
                    drop(g);
                    let e = H2Error::msg(ERR_REQUEST_CANCELED);
                    cs.trace_wrote_request(Some(&e));
                    return Err(e);
                }
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                g = cs
                    .cv
                    .wait_timeout(g, (deadline - now).min(Duration::from_millis(50)))
                    .unwrap_or_else(|e| e.into_inner())
                    .0;
            }
        }
        match write_request_body(cs, req) {
            Err(e) => {
                if !e.is_msg(ERR_STOP_REQ_BODY_WRITE) {
                    cs.trace_wrote_request(Some(&e));
                    return Err(e);
                }
                wrote_err = Some(e);
            }
            Ok(()) => cs.state().sent_end_stream = true,
        }
    }
    cs.trace_wrote_request(wrote_err.as_ref());

    // Wait for the response to finish (or fail).
    let mut deadline = if cc.cfg.response_header_timeout.is_zero() {
        None
    } else {
        Some(Instant::now() + cc.cfg.response_header_timeout)
    };
    let mut g = cs.state();
    loop {
        if g.peer_closed {
            return Ok(());
        }
        if g.aborted {
            return Err(g
                .abort_err
                .clone()
                .unwrap_or_else(|| H2Error::msg("aborted")));
        }
        if cs.ctx.err().is_some() {
            return Err(H2Error::msg(ERR_REQUEST_CANCELED));
        }
        if g.res.is_some() || g.res_taken {
            deadline = None;
        }
        let wait = match deadline {
            Some(d) => {
                let now = Instant::now();
                if now >= d {
                    return Err(H2Error::msg(ERR_TIMEOUT));
                }
                (d - now).min(Duration::from_millis(100))
            }
            None => Duration::from_millis(100),
        };
        g = cs
            .cv
            .wait_timeout(g, wait)
            .unwrap_or_else(|e| e.into_inner())
            .0;
    }
}

/// Go's `encodeAndWriteHeaders`.
fn encode_and_write_headers(cs: &Arc<Cs>, req: &Request) -> Result<(), H2Error> {
    let cc = &cs.cc;
    let mut w = lock(&cc.wmu);
    if let Some(e) = cs.aborted() {
        return Err(e);
    }
    if let Some(e) = cs.ctx_err() {
        return Err(e);
    }
    let (peer_max, max_frame) = {
        let g = cc.state();
        (g.peer_max_header_list_size, g.max_frame_size as usize)
    };
    let mut encoded = Vec::new();
    let res = {
        let henc = &mut w.henc;
        encode_request_headers(
            req,
            cs.requested_gzip,
            peer_max,
            actual_content_length(req),
            &mut |name, value| {
                henc.write_field(&HeaderField::new(name, value), &mut encoded);
                if let Some(f) = cs
                    .trace
                    .as_ref()
                    .and_then(|t| t.wrote_header_field.as_ref())
                {
                    f(name, &[value.to_owned()]);
                }
            },
        )
    };
    let (has_body, has_trailers) = res.map_err(|e| H2Error::msg(format!("http2: {e}")))?;
    let end_stream = !has_body && !has_trailers;
    cs.state().sent_headers = true;
    let r = write_headers_frames(cc, &mut w, cs.id(), end_stream, max_frame, &encoded);
    if let Some(f) = cs.trace.as_ref().and_then(|t| t.wrote_headers.as_ref()) {
        f();
    }
    r
}

fn write_headers_frames(
    cc: &Cc,
    w: &mut WState,
    stream_id: u32,
    end_stream: bool,
    max_frame_size: usize,
    mut hdrs: &[u8],
) -> Result<(), H2Error> {
    let mut first = true;
    while !hdrs.is_empty() && w.werr.is_none() {
        let n = hdrs.len().min(max_frame_size);
        let chunk = &hdrs[..n];
        hdrs = &hdrs[n..];
        let end_headers = hdrs.is_empty();
        if first {
            let _ = w.fr.write_headers(&HeadersParam {
                stream_id,
                block_fragment: chunk,
                end_stream,
                end_headers,
                ..HeadersParam::default()
            });
            first = false;
        } else {
            let _ = w.fr.write_continuation(stream_id, end_headers, chunk);
        }
    }
    cc.flush_locked(w).map_err(|e| H2Error::Io(Arc::new(e)))
}

/// Go's `awaitFlowControl`.
fn await_flow_control(cs: &Arc<Cs>, max_bytes: usize) -> Result<i32, H2Error> {
    let cc = &cs.cc;
    let mut g = cc.state();
    loop {
        if g.closed {
            return Err(H2Error::msg(ERR_CLIENT_CONN_CLOSED));
        }
        if cs.state().req_body_closed {
            return Err(H2Error::msg(ERR_STOP_REQ_BODY_WRITE));
        }
        if let Some(e) = cs.aborted() {
            return Err(e);
        }
        if let Some(e) = cs.ctx_err() {
            return Err(e);
        }
        let id = cs.id();
        let max_frame = g.max_frame_size as i32;
        let CcState { streams, flow, .. } = &mut *g;
        if let Some(entry) = streams.get_mut(&id) {
            let a = flow::available(&entry.flow, flow);
            if a > 0 {
                let mut take = a;
                if take as usize > max_bytes {
                    take = max_bytes as i32;
                }
                if take > max_frame {
                    take = max_frame;
                }
                flow::take(&mut entry.flow, flow, take);
                return Ok(take);
            }
        } else {
            return Err(H2Error::msg(ERR_CLIENT_CONN_CLOSED));
        }
        g = cc
            .cond
            .wait_timeout(g, Duration::from_millis(200))
            .unwrap_or_else(|e| e.into_inner())
            .0;
    }
}

/// Go's `writeRequestBody`.
fn write_request_body(cs: &Arc<Cs>, req: &Request) -> Result<(), H2Error> {
    let cc = &cs.cc;
    let Some(mut body) = lock(&cs.req_body).clone() else {
        return Ok(());
    };
    let mut sent_end = false;
    let has_trailers = !req.trailer.is_nil();
    let mut remain_len = cs.req_body_content_length;
    let has_content_len = remain_len != -1;
    let max_frame_size = cc.state().max_frame_size as usize;

    let mut scratch_len = max_frame_size.min(512 << 10) as i64;
    if has_content_len && remain_len + 1 < scratch_len {
        scratch_len = remain_len + 1;
    }
    let scratch_len = scratch_len.max(1) as usize;
    let mut buf = vec![0u8; scratch_len];

    let mut saw_eof = false;
    while !saw_eof {
        let mut n = 0usize;
        let mut read_err: Option<io::Error> = None;
        match body.read(&mut buf) {
            Ok(k) => n = k,
            Err(e) => read_err = Some(e),
        }
        let mut eof = n == 0 && read_err.is_none();
        if has_content_len {
            remain_len -= n as i64;
            if remain_len == 0 && read_err.is_none() && !eof {
                let mut scratch = [0u8; 1];
                match body.read(&mut scratch) {
                    Ok(0) => eof = true,
                    Ok(k) => remain_len -= k as i64,
                    Err(e) => read_err = Some(e),
                }
            }
            if remain_len < 0 {
                return Err(H2Error::msg(ERR_REQ_BODY_TOO_LONG));
            }
        }
        if eof || read_err.is_some() {
            let closed = cs.state().req_body_closed;
            if closed {
                return Err(H2Error::msg(ERR_STOP_REQ_BODY_WRITE));
            }
            match read_err {
                None => saw_eof = true,
                Some(e) => return Err(H2Error::Io(Arc::new(e))),
            }
        }
        let mut remain = &buf[..n];
        while !remain.is_empty() {
            let allowed = await_flow_control(cs, remain.len())? as usize;
            let data = &remain[..allowed];
            remain = &remain[allowed..];
            sent_end = saw_eof && remain.is_empty() && !has_trailers;
            let mut w = lock(&cc.wmu);
            let r =
                w.fr.write_data(cs.id(), sent_end, data)
                    .map_err(H2Error::from_frame_error);
            let r = r.and_then(|()| {
                cc.flush_locked(&mut w)
                    .map_err(|e| H2Error::Io(Arc::new(e)))
            });
            drop(w);
            r?;
        }
    }
    let _ = &mut body;
    if sent_end {
        return Ok(());
    }
    if let Some(e) = cs.aborted() {
        return Err(e);
    }
    let trailer = req.trailer.get();
    let mut w = lock(&cc.wmu);
    let mut trls: Vec<u8> = Vec::new();
    if let Some(t) = trailer.as_ref().filter(|t| !t.0.is_empty()) {
        trls = encode_trailers(cc, &mut w, t)?;
    }
    if !trls.is_empty() {
        write_headers_frames(cc, &mut w, cs.id(), true, max_frame_size, &trls)
    } else {
        let r =
            w.fr.write_data(cs.id(), true, &[])
                .map_err(H2Error::from_frame_error);
        r.and_then(|()| {
            cc.flush_locked(&mut w)
                .map_err(|e| H2Error::Io(Arc::new(e)))
        })
    }
}

fn encode_trailers(cc: &Cc, w: &mut WState, trailer: &Header) -> Result<Vec<u8>, H2Error> {
    let mut hl: u64 = 0;
    for (k, vv) in &trailer.0 {
        for v in vv {
            hl += (k.len() + v.len() + 32) as u64;
        }
    }
    if hl > cc.state().peer_max_header_list_size {
        return Err(H2Error::msg(ERR_REQUEST_HEADER_LIST_SIZE));
    }
    let mut out = Vec::new();
    for (k, vv) in &trailer.0 {
        if !k.bytes().all(|b| (b' '..=b'~').contains(&b)) {
            continue;
        }
        let lk = k.to_ascii_lowercase();
        for v in vv {
            w.henc.write_field(&HeaderField::new(&lk, v), &mut out);
        }
    }
    Ok(out)
}

/// Go's `cleanupWriteRequest`.
fn cleanup_write_request(cs: &Arc<Cs>, mut err: Result<(), H2Error>) {
    let cc = cs.cc.clone();
    let id = cs.id();

    if id == 0 {
        let mut g = cc.state();
        if g.streams_reserved > 0 {
            g.streams_reserved -= 1;
        }
    }

    let ok = err.is_ok();
    let (close_on_idle, read_since_stream) = {
        let g = cc.state();
        (
            cc.single_use || g.do_not_reuse || cc.cfg.disable_keep_alives || g.go_away.is_some(),
            g.read_before_stream_id > id,
        )
    };
    // Close the request body (if still open) and wait for that to finish.
    {
        let must_close = {
            let g = cs.state();
            !g.req_body_closed
        };
        if must_close {
            let body = lock(&cs.req_body).clone();
            if let Some(b) = body {
                cs.state().req_body_closed = true;
                let _ = b.close();
            }
        }
    }

    if err.is_err() && cs.state().sent_end_stream && cs.state().peer_closed {
        err = Ok(());
    }
    match err {
        Err(e) => {
            cs.abort_stream(e.clone());
            if cs.state().sent_headers {
                if let H2Error::Stream {
                    stream_id: _,
                    code,
                    from_peer,
                    ..
                } = &e
                {
                    if !*from_peer {
                        write_stream_reset(&cc, id, *code, false);
                    }
                } else {
                    let mut ping = false;
                    if !close_on_idle && !read_since_stream {
                        let mut g = cc.state();
                        if !g.rst_stream_pings_blocked {
                            if g.pending_resets == 0 {
                                ping = true;
                            }
                            g.pending_resets += 1;
                        }
                    }
                    write_stream_reset(&cc, id, ERR_CODE_CANCEL, ping);
                }
            }
            cs.buf_pipe.close_with_error(e);
        }
        Ok(()) => {
            let (sent_headers, sent_end) = {
                let g = cs.state();
                (g.sent_headers, g.sent_end_stream)
            };
            if sent_headers && !sent_end {
                write_stream_reset(&cc, id, ERR_CODE_NO, false);
            }
            cs.buf_pipe
                .close_with_error(H2Error::msg(ERR_REQUEST_CANCELED));
        }
    }
    if id != 0 {
        forget_stream_id(&cc, id);
    }
    if cc.werr().is_some() {
        cc.close_for_error(H2Error::msg(ERR_CLIENT_CONN_FORCE_CLOSED));
    }
    let handed_out = {
        let mut g = cs.state();
        g.done = true;
        g.res_taken
    };
    cs.cv.notify_all();
    cc.call_state_hook();
    if ok || handed_out {
        let f = lock(&cs.on_done).take();
        if let Some(f) = f {
            f();
        }
    }
}

fn write_stream_reset(cc: &Cc, id: u32, code: ErrCode, ping: bool) {
    let mut w = lock(&cc.wmu);
    let _ = w.fr.write_rst_stream(id, code);
    if ping {
        let _ = w.fr.write_ping(false, rand_ping());
    }
    let _ = cc.flush_locked(&mut w);
}

/// Go's `forgetStreamID`.
fn forget_stream_id(cc: &Arc<Cc>, id: u32) {
    let close_after;
    {
        let mut g = cc.state();
        g.streams.remove(&id);
        g.last_active = Instant::now();
        if g.streams.is_empty() && !cc.idle_timeout.is_zero() {
            g.idle_deadline = Some(Instant::now() + cc.idle_timeout);
            g.last_idle = Some(Instant::now());
        } else if g.streams.is_empty() {
            g.last_idle = Some(Instant::now());
        }
        cc.cond.notify_all();
        let close_on_idle =
            cc.single_use || g.do_not_reuse || cc.cfg.disable_keep_alives || g.go_away.is_some();
        close_after = close_on_idle && g.streams_reserved == 0 && g.streams.is_empty();
        if close_after {
            g.closed = true;
        }
    }
    if close_after {
        cc.close_conn();
    }
}

// ------------------------------------------------------------ read loop

impl Cc {
    fn read_loop(self: Arc<Self>) {
        let err = self.clone().run_read_loop();
        // A connection error is answered with GOAWAY (best effort).
        if let H2Error::Connection(code) = &err {
            let mut w = lock(&self.wmu);
            let _ = w.fr.write_goaway(0, *code, &[]);
            let _ = self.flush_locked(&mut w);
        }
        self.cleanup_reader(err);
    }

    fn cleanup_reader(self: &Arc<Self>, mut err: H2Error) {
        {
            let mut g = self.state();
            if let Some(ga) = &g.go_away {
                if matches!(&err, H2Error::Eof | H2Error::Io(_)) {
                    err = H2Error::GoAway {
                        last_stream_id: ga.last_stream_id,
                        code: ga.code,
                        debug: ga.debug.clone(),
                    };
                }
            } else if err.is_eof() {
                err = H2Error::UnexpectedEof;
            }
            g.closed = true;
            g.reader_err = Some(err.clone());
            g.reader_done = true;
        }
        self.mark_dead();
        {
            let g = self.state();
            for e in g.streams.values() {
                let closed = e.cs.state().peer_closed;
                if !closed {
                    e.cs.abort_stream_locked(err.clone());
                }
            }
        }
        self.cond.notify_all();
        self.close_conn();
        // Break the reference cycle through a state hook that holds the conn.
        *lock(&self.state_hook) = None;
        // Wake pings.
        let pings: Vec<Ping> = self.state().pings.drain().map(|(_, p)| p).collect();
        for p in pings {
            p.1.notify_all();
        }
    }

    fn run_read_loop(self: Arc<Self>) -> H2Error {
        let conf = &self.cfg.conf;
        let mut fr = FrameReader::new(io::BufReader::with_capacity(
            32 << 10,
            ConnRead(self.conn.clone()),
        ));
        fr.set_max_read_frame_size(conf.max_read_frame_size as u32);
        fr.set_count_error(conf.count_error.clone());
        fr.set_meta_headers_decoder(Some(Decoder::new(
            conf.max_decoder_header_table_size as u32,
        )));
        fr.set_max_header_list_size(self.cfg.max_header_list_size());
        let mut got_settings = false;
        loop {
            let f = fr.read_frame();
            self.state().last_frame_read = Instant::now();
            self.cond.notify_all();
            let f = match f {
                Err(FrameError::Stream {
                    stream_id,
                    code,
                    cause,
                }) => {
                    if let Some(cs) = self.stream_by_id(stream_id, false) {
                        let cause = cause
                            .or_else(|| fr.error_detail().map(str::to_owned))
                            .map(|c| Arc::new(H2Error::msg(c)));
                        self.end_stream_error(
                            &cs,
                            H2Error::Stream {
                                stream_id,
                                code,
                                cause,
                                from_peer: false,
                            },
                        );
                    }
                    continue;
                }
                Err(e) => {
                    self.count_read_frame_error(&e);
                    return H2Error::from_frame_error(e);
                }
                Ok(f) => f,
            };
            if !got_settings {
                if !matches!(f, Frame::Settings { .. }) {
                    crate::log::printf(format_args!(
                        "protocol error: received a frame before a SETTINGS frame"
                    ));
                    return H2Error::Connection(ERR_CODE_PROTOCOL);
                }
                got_settings = true;
            }
            let r = match f {
                Frame::Meta(m) => self.process_headers(m),
                Frame::Data { header, data } => self.process_data(header, data),
                Frame::GoAway {
                    last_stream_id,
                    code,
                    debug_data,
                    ..
                } => self.process_go_away(last_stream_id, code, &debug_data),
                Frame::RstStream { header, code } => {
                    self.process_reset_stream(header.stream_id, code)
                }
                Frame::Settings { header, settings } => self.process_settings(header, &settings),
                Frame::PushPromise { .. } => Err(H2Error::Connection(ERR_CODE_PROTOCOL)),
                Frame::WindowUpdate { header, increment } => {
                    self.process_window_update(header.stream_id, increment)
                }
                Frame::Ping { header, data } => self.process_ping(header, data),
                _ => Ok(()),
            };
            if let Err(e) = r {
                return e;
            }
        }
    }

    fn count_read_frame_error(&self, e: &FrameError) {
        let Some(f) = &self.cfg.conf.count_error else {
            return;
        };
        match e {
            FrameError::Connection(c) => {
                f(&format!("read_frame_conn_error_{}", err_code_token(*c)))
            }
            FrameError::Eof => f("read_frame_eof"),
            FrameError::UnexpectedEof => f("read_frame_unexpected_eof"),
            FrameError::TooLarge { .. } => f("read_frame_too_large"),
            _ => f("read_frame_other"),
        }
    }

    /// Go's `streamByID`.
    fn stream_by_id(&self, id: u32, header_or_data: bool) -> Option<Arc<Cs>> {
        let mut g = self.state();
        if header_or_data {
            g.rst_stream_pings_blocked = false;
        }
        g.read_before_stream_id = g.next_stream_id;
        let cs = g.streams.get(&id)?.cs.clone();
        drop(g);
        if cs.state().read_aborted {
            return None;
        }
        Some(cs)
    }

    fn end_stream_error(&self, cs: &Arc<Cs>, err: H2Error) {
        cs.state().read_aborted = true;
        cs.abort_stream(err);
    }

    fn process_headers(self: &Arc<Self>, f: MetaHeadersFrame) -> Result<(), H2Error> {
        let id = f.header.stream_id;
        let Some(cs) = self.stream_by_id(id, true) else {
            return Ok(());
        };
        {
            let g = cs.state();
            if g.read_closed {
                drop(g);
                self.end_stream_error(
                    &cs,
                    H2Error::stream_cause(
                        id,
                        ERR_CODE_PROTOCOL,
                        H2Error::msg("protocol error: headers after END_STREAM"),
                    ),
                );
                return Ok(());
            }
        }
        let first = std::mem::replace(&mut cs.state().first_byte, true);
        if !first {
            if let Some(f) = cs
                .trace
                .as_ref()
                .and_then(|t| t.got_first_response_byte.as_ref())
            {
                f();
            }
        }
        {
            let mut g = cs.state();
            if g.past_headers {
                drop(g);
                return self.process_trailers(&cs, &f);
            }
            g.past_headers = true;
        }
        match self.handle_response(&cs, &f) {
            Err(HandleErr::Stream(e)) => {
                self.end_stream_error(&cs, H2Error::stream_cause(id, ERR_CODE_PROTOCOL, e));
                Ok(())
            }
            Ok(None) => Ok(()),
            Ok(Some(res)) => {
                {
                    let mut g = cs.state();
                    g.res = Some(res);
                }
                cs.cv.notify_all();
                if f.stream_ended() {
                    self.end_stream(&cs);
                }
                Ok(())
            }
        }
    }

    /// Go's `handleResponse`; `Ok(None)` for an informational response.
    fn handle_response(
        self: &Arc<Self>,
        cs: &Arc<Cs>,
        f: &MetaHeadersFrame,
    ) -> Result<Option<ResParts>, HandleErr> {
        let se = |s: &str| HandleErr::Stream(H2Error::msg(s));
        if f.truncated {
            return Err(se(ERR_RESPONSE_HEADER_LIST_SIZE));
        }
        let status = String::from_utf8_lossy(f.pseudo_value("status")).into_owned();
        if status.is_empty() {
            return Err(se(
                "malformed response from server: missing status pseudo header",
            ));
        }
        let Ok(status_code) = status.parse::<u16>() else {
            return Err(se(
                "malformed response from server: malformed non-numeric status pseudo header",
            ));
        };
        let mut header = Header::new();
        let mut declared: Option<Header> = None;
        for hf in f.regular_fields() {
            let (Ok(name), Ok(val)) = (
                std::str::from_utf8(&hf.name),
                String::from_utf8(hf.value.clone()),
            ) else {
                return Err(se(
                    "malformed response from server: invalid UTF-8 in header",
                ));
            };
            let key = canonical_mime_header_key(name);
            if key == "Trailer" {
                let t = declared.get_or_insert_with(Header::new);
                foreach_header_element(&val, |v| {
                    t.0.insert(canonical_mime_header_key(v), Vec::new());
                });
            } else {
                header.0.entry(key).or_default().push(val);
            }
        }

        if (100..=199).contains(&status_code) {
            if f.stream_ended() {
                return Err(se("1xx informational response with END_STREAM flag"));
            }
            if let Some(hook) = cs.trace.as_ref().and_then(|t| t.got_1xx_response.as_ref()) {
                // The hook's owner limits the number of responses it sees.
                hook(status_code, &header)
                    .map_err(|e| HandleErr::Stream(H2Error::msg(e.to_string())))?;
            } else {
                // Without a hook, limit the size of all 1xx headers.
                let limit = i64::from(self.cfg.max_header_list_size())
                    .max(self.cfg.max_response_header_bytes);
                let mut g = cs.state();
                for h in &f.fields {
                    g.total_header_size += i64::from(h.size());
                }
                if g.total_header_size > limit {
                    return Err(se("header list too large"));
                }
            }
            if status_code == 100 {
                if let Some(f) = cs.trace.as_ref().and_then(|t| t.got_100_continue.as_ref()) {
                    f();
                }
                cs.state().got_100 = true;
            }
            cs.state().past_headers = false;
            cs.cv.notify_all();
            return Ok(None);
        }

        let mut content_length: i64 = -1;
        let clens = header.values("Content-Length");
        if clens.len() == 1 {
            if let Ok(cl) = clens[0].parse::<u64>() {
                if cl < (1 << 63) {
                    content_length = cl as i64;
                }
            }
        } else if clens.len() > 1 {
            // Multiple values: the length stays unknown.
        } else if f.stream_ended() && !cs.is_head {
            content_length = 0;
        }
        let mut res = ResParts {
            status,
            status_code,
            header,
            trailer: declared,
            content_length,
            body: ResBodyKind::None,
            uncompressed: false,
        };
        if cs.is_head {
            return Ok(Some(res));
        }
        if f.stream_ended() {
            res.body = if res.content_length > 0 {
                ResBodyKind::Missing
            } else {
                ResBodyKind::None
            };
            return Ok(Some(res));
        }
        cs.buf_pipe.set_buffer();
        cs.state().bytes_remain = res.content_length;
        res.body = ResBodyKind::Stream;
        Ok(Some(res))
    }

    fn process_trailers(
        self: &Arc<Self>,
        cs: &Arc<Cs>,
        f: &MetaHeadersFrame,
    ) -> Result<(), H2Error> {
        {
            let mut g = cs.state();
            if g.past_trailers {
                return Err(H2Error::Connection(ERR_CODE_PROTOCOL));
            }
            g.past_trailers = true;
        }
        if !f.stream_ended() {
            return Err(H2Error::Connection(ERR_CODE_PROTOCOL));
        }
        if !f.pseudo_fields().is_empty() {
            return Err(H2Error::Connection(ERR_CODE_PROTOCOL));
        }
        if f.truncated {
            self.end_stream_error(
                cs,
                H2Error::stream_cause(
                    f.header.stream_id,
                    ERR_CODE_PROTOCOL,
                    H2Error::msg(ERR_RESPONSE_HEADER_LIST_SIZE),
                ),
            );
            return Ok(());
        }
        let mut trailer = Header::new();
        for hf in f.regular_fields() {
            let (Ok(name), Ok(val)) = (
                std::str::from_utf8(&hf.name),
                String::from_utf8(hf.value.clone()),
            ) else {
                return Err(H2Error::Connection(ERR_CODE_PROTOCOL));
            };
            trailer
                .0
                .entry(canonical_mime_header_key(name))
                .or_default()
                .push(val);
        }
        cs.state().trailer = Some(trailer);
        self.end_stream(cs);
        Ok(())
    }

    /// Go's `endStream`.
    fn end_stream(&self, cs: &Arc<Cs>) {
        {
            let mut g = cs.state();
            if g.read_closed {
                return;
            }
            g.read_closed = true;
        }
        let _guard = self.state();
        let cs2 = cs.clone();
        cs.buf_pipe
            .close_with_error_and_code(H2Error::Eof, move || {
                // copyTrailers
                let t = cs2.state().trailer.take();
                if let Some(t) = t {
                    cs2.res_trailer.merge(t);
                }
            });
        cs.state().peer_closed = true;
        cs.cv.notify_all();
    }

    fn process_data(self: &Arc<Self>, header: FrameHeader, data: Vec<u8>) -> Result<(), H2Error> {
        let id = header.stream_id;
        let cs = self.stream_by_id(id, true);
        let Some(cs) = cs else {
            let never_sent = self.state().next_stream_id;
            if id >= never_sent {
                crate::log::printf(format_args!(
                    "http2: Transport received unsolicited DATA frame; closing connection"
                ));
                return Err(H2Error::Connection(ERR_CODE_PROTOCOL));
            }
            if header.length > 0 {
                let (ok, conn_add) = {
                    let mut g = self.state();
                    let ok = g.inflow.take(header.length);
                    (ok, g.inflow.add(header.length as usize))
                };
                if !ok {
                    return Err(H2Error::Connection(ERR_CODE_FLOW_CONTROL));
                }
                if conn_add > 0 {
                    let mut w = lock(&self.wmu);
                    let _ = w.fr.write_window_update(0, conn_add as u32);
                    let _ = self.flush_locked(&mut w);
                }
            }
            return Ok(());
        };
        let (read_closed, past_headers) = {
            let g = cs.state();
            (g.read_closed, g.past_headers)
        };
        if read_closed {
            crate::log::printf(format_args!(
                "protocol error: received DATA after END_STREAM"
            ));
            self.end_stream_error(&cs, H2Error::stream(id, ERR_CODE_PROTOCOL));
            return Ok(());
        }
        if !past_headers {
            crate::log::printf(format_args!(
                "protocol error: received DATA before a HEADERS frame"
            ));
            self.end_stream_error(&cs, H2Error::stream(id, ERR_CODE_PROTOCOL));
            return Ok(());
        }
        if header.length > 0 {
            if cs.is_head && !data.is_empty() {
                crate::log::printf(format_args!(
                    "protocol error: received DATA on a HEAD request"
                ));
                self.end_stream_error(&cs, H2Error::stream(id, ERR_CODE_PROTOCOL));
                return Ok(());
            }
            let send_conn;
            let mut send_stream = 0;
            let mut write_err: Option<H2Error> = None;
            {
                let mut g = self.state();
                let CcState {
                    inflow, streams, ..
                } = &mut *g;
                let Some(entry) = streams.get_mut(&id) else {
                    return Ok(());
                };
                if !flow::take_inflows(inflow, &mut entry.inflow, header.length) {
                    return Err(H2Error::Connection(ERR_CODE_FLOW_CONTROL));
                }
                let mut refund = 0usize;
                let pad = header.length as usize - data.len();
                if pad > 0 {
                    refund += pad;
                }
                let mut did_reset = false;
                if !data.is_empty() {
                    if let Err(e) = cs.buf_pipe.write(&data) {
                        did_reset = true;
                        refund += data.len();
                        write_err = Some(e);
                    }
                }
                send_conn = inflow.add(refund);
                if !did_reset {
                    send_stream = entry.inflow.add(refund);
                }
            }
            if send_conn > 0 || send_stream > 0 {
                let mut w = lock(&self.wmu);
                if send_conn > 0 {
                    let _ = w.fr.write_window_update(0, send_conn as u32);
                }
                if send_stream > 0 {
                    let _ = w.fr.write_window_update(id, send_stream as u32);
                }
                let _ = self.flush_locked(&mut w);
            }
            if let Some(e) = write_err {
                self.end_stream_error(&cs, e);
                return Ok(());
            }
        }
        if header.has(FLAG_DATA_END_STREAM) {
            self.end_stream(&cs);
        }
        Ok(())
    }

    fn process_go_away(
        self: &Arc<Self>,
        last: u32,
        code: ErrCode,
        debug: &[u8],
    ) -> Result<(), H2Error> {
        self.mark_dead();
        if code != 0 {
            if let Some(f) = &self.cfg.conf.count_error {
                f(&format!("recv_goaway_{}", err_code_token(code)));
            }
        }
        let mut g = self.state();
        let old = g.go_away.clone();
        let mut ga = GoAwayInfo {
            last_stream_id: last,
            code,
            debug: String::new(),
        };
        ga.debug = match &old {
            Some(o) if !o.debug.is_empty() => o.debug.clone(),
            _ => String::from_utf8_lossy(debug).into_owned(),
        };
        if let Some(o) = &old {
            if o.code != ERR_CODE_NO {
                ga.code = o.code;
            }
        }
        let ga_code = ga.code;
        g.go_away = Some(ga);
        if g.streams.is_empty() {
            return Err(H2Error::msg(ERR_STOP_READ_LOOP));
        }
        for (id, e) in &g.streams {
            if *id <= last {
                continue;
            }
            if *id == 1 && ga_code != ERR_CODE_NO {
                e.cs.abort_stream_locked(H2Error::msg(format!(
                    "http2: Transport received GOAWAY from server ErrCode:{}",
                    err_code_string(ga_code)
                )));
            } else {
                e.cs.abort_stream_locked(H2Error::msg(ERR_CLIENT_CONN_GOT_GOAWAY));
            }
        }
        Ok(())
    }

    fn process_settings(
        self: &Arc<Self>,
        header: FrameHeader,
        settings: &[Setting],
    ) -> Result<(), H2Error> {
        let mut w = lock(&self.wmu);
        self.process_settings_no_write(header, settings)?;
        if !header.has(FLAG_SETTINGS_ACK) {
            for s in settings {
                if s.id == SETTING_HEADER_TABLE_SIZE {
                    w.henc.set_max_dynamic_table_size(s.val);
                }
            }
            let _ = w.fr.write_settings_ack();
            let _ = self.flush_locked(&mut w);
        }
        Ok(())
    }

    fn process_settings_no_write(
        self: &Arc<Self>,
        header: FrameHeader,
        settings: &[Setting],
    ) -> Result<(), H2Error> {
        let r = (|| {
            let mut g = self.state();
            if header.has(FLAG_SETTINGS_ACK) {
                if g.want_settings_ack {
                    g.want_settings_ack = false;
                    return Ok(());
                }
                return Err(H2Error::Connection(ERR_CODE_PROTOCOL));
            }
            let mut seen_max_concurrent = false;
            for s in settings {
                if let Err(code) = s.valid() {
                    return Err(H2Error::Connection(code));
                }
                match s.id {
                    SETTING_MAX_FRAME_SIZE => g.max_frame_size = s.val,
                    SETTING_MAX_CONCURRENT_STREAMS => {
                        g.max_concurrent_streams = s.val;
                        seen_max_concurrent = true;
                    }
                    SETTING_MAX_HEADER_LIST_SIZE => g.peer_max_header_list_size = u64::from(s.val),
                    SETTING_INITIAL_WINDOW_SIZE => {
                        let delta = (s.val as i32).wrapping_sub(g.initial_window_size as i32);
                        for e in g.streams.values_mut() {
                            if !e.flow.add(delta) {
                                return Err(H2Error::Connection(ERR_CODE_FLOW_CONTROL));
                            }
                        }
                        self.cond.notify_all();
                        g.initial_window_size = s.val;
                    }
                    _ => {}
                }
            }
            if !g.seen_settings {
                if !seen_max_concurrent {
                    g.max_concurrent_streams = DEFAULT_MAX_CONCURRENT_STREAMS;
                }
                g.seen_settings = true;
            }
            Ok(())
        })();
        self.cond.notify_all();
        self.call_state_hook();
        r
    }

    fn process_window_update(&self, stream_id: u32, increment: u32) -> Result<(), H2Error> {
        let cs = self.stream_by_id(stream_id, false);
        if stream_id != 0 && cs.is_none() {
            return Ok(());
        }
        let mut g = self.state();
        let ok = match &cs {
            Some(cs) => match g.streams.get_mut(&cs.id()) {
                Some(e) => e.flow.add(increment as i32),
                None => return Ok(()),
            },
            None => g.flow.add(increment as i32),
        };
        if !ok {
            if let Some(cs) = &cs {
                cs.state().read_aborted = true;
                cs.abort_stream_locked(H2Error::stream(stream_id, ERR_CODE_FLOW_CONTROL));
                return Ok(());
            }
            return Err(H2Error::Connection(ERR_CODE_FLOW_CONTROL));
        }
        drop(g);
        self.cond.notify_all();
        Ok(())
    }

    fn process_reset_stream(&self, stream_id: u32, code: ErrCode) -> Result<(), H2Error> {
        let Some(cs) = self.stream_by_id(stream_id, false) else {
            return Ok(());
        };
        let serr = H2Error::Stream {
            stream_id,
            code,
            cause: None,
            from_peer: true,
        };
        if code == ERR_CODE_PROTOCOL {
            self.state().do_not_reuse = true;
        }
        if let Some(f) = &self.cfg.conf.count_error {
            f(&format!("recv_rststream_{}", err_code_token(code)));
        }
        cs.abort_stream(serr.clone());
        cs.buf_pipe.close_with_error(serr);
        Ok(())
    }

    fn process_ping(&self, header: FrameHeader, data: [u8; 8]) -> Result<(), H2Error> {
        if header.has(FLAG_PING_ACK) {
            let mut g = self.state();
            if let Some(p) = g.pings.remove(&data) {
                *lock(&p.0) = true;
                p.1.notify_all();
            }
            if g.pending_resets > 0 {
                g.pending_resets = 0;
                g.rst_stream_pings_blocked = true;
                self.cond.notify_all();
            }
            drop(g);
            self.call_state_hook();
            return Ok(());
        }
        let mut w = lock(&self.wmu);
        w.fr.write_ping(true, data)
            .map_err(H2Error::from_frame_error)?;
        self.flush_locked(&mut w)
            .map_err(|e| H2Error::Io(Arc::new(e)))
    }
}

enum HandleErr {
    Stream(H2Error),
}

// ------------------------------------------------------------ the body

/// A response body fed by the reader (Go's `transportResponseBody`).
struct ResponseBody {
    cs: Arc<Cs>,
    read_err: Option<H2Error>,
}

impl Read for ResponseBody {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        let cs = self.cs.clone();
        let cc = &cs.cc;
        if let Some(e) = &self.read_err {
            return Err(e.clone().into_io());
        }
        let r = cs.buf_pipe.read(p);
        let (n, err) = match r {
            Ok(n) => (n, None),
            Err(H2Error::Eof) => (0, Some(H2Error::Eof)),
            Err(e) => (0, Some(e)),
        };
        let mut g = cs.state();
        if g.bytes_remain != -1 {
            if n as i64 > g.bytes_remain {
                let remain = g.bytes_remain as usize;
                drop(g);
                let e = H2Error::msg(
                    "net/http: server replied with more than declared Content-Length; truncated",
                );
                cs.abort_stream(e.clone());
                self.read_err = Some(e.clone());
                let _ = remain;
                return Err(e.into_io());
            }
            g.bytes_remain -= n as i64;
            if matches!(err, Some(H2Error::Eof)) && g.bytes_remain > 0 {
                drop(g);
                self.read_err = Some(H2Error::UnexpectedEof);
                return Err(H2Error::UnexpectedEof.into_io());
            }
        }
        drop(g);
        if n == 0 {
            return match err {
                Some(H2Error::Eof) | None => Ok(0),
                Some(e) => Err(e.into_io()),
            };
        }
        let id = cs.id();
        let (conn_add, stream_add) = {
            let mut g = cc.state();
            let conn_add = g.inflow.add(n);
            let stream_add = if err.is_none() {
                g.streams.get_mut(&id).map_or(0, |e| e.inflow.add(n))
            } else {
                0
            };
            (conn_add, stream_add)
        };
        if conn_add != 0 || stream_add != 0 {
            let mut w = lock(&cc.wmu);
            if conn_add != 0 {
                let _ = w.fr.write_window_update(0, conn_add as u32);
            }
            if stream_add != 0 {
                let _ = w.fr.write_window_update(id, stream_add as u32);
            }
            let _ = cc.flush_locked(&mut w);
        }
        match err {
            Some(H2Error::Eof) => Ok(n),
            Some(e) => Err(e.into_io()),
            None => Ok(n),
        }
    }
}

impl ReadCloser for ResponseBody {
    fn close(&mut self) -> io::Result<()> {
        let cs = &self.cs;
        let cc = &cs.cc;
        cs.buf_pipe
            .break_with_error(H2Error::msg(ERR_CLOSED_RESPONSE_BODY));
        cs.abort_stream(H2Error::msg(ERR_CLOSED_RESPONSE_BODY));
        let unread = cs.buf_pipe.len();
        if unread > 0 {
            let conn_add = cc.state().inflow.add(unread);
            let mut w = lock(&cc.wmu);
            if conn_add > 0 {
                let _ = w.fr.write_window_update(0, conn_add as u32);
            }
            let _ = cc.flush_locked(&mut w);
        }
        // Wait for the stream to finish unwinding.
        let mut g = cs.state();
        while !g.done {
            if cs.ctx.err().is_some() {
                return Ok(());
            }
            g = cs
                .cv
                .wait_timeout(g, Duration::from_millis(20))
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        Ok(())
    }
}

struct MissingBody;
impl Read for MissingBody {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::UnexpectedEof))
    }
}
impl ReadCloser for MissingBody {}

/// Go's `canRetryError` for `RoundTrip` failures.
pub(crate) fn can_retry_error(e: &H2Error) -> bool {
    if e.is_msg(ERR_CLIENT_CONN_UNUSABLE) || e.is_msg(ERR_CLIENT_CONN_GOT_GOAWAY) {
        return true;
    }
    matches!(e, H2Error::Stream { code, .. } if *code == ERR_CODE_REFUSED_STREAM)
}
