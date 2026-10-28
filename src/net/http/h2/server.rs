//! The HTTP/2 server connection (Go's `serverConn`): a single serve thread
//! owns every piece of connection state; a reader thread parses frames, a
//! writer thread owns the socket's write side, and each request runs its
//! handler on its own thread, talking to the serve thread over a channel.
use super::flow::{self, Inflow, Outflow};
use super::frame::*;
use super::hpack::{Decoder, Encoder, HeaderField};
use super::pipe::Pipe;
use super::sched::{Kind, Sched, SchedItem, Take};
use super::{
    adjust_http1_max_header_size, body_allowed_for_status, foreach_header_element, is_bad_cipher,
    Config, H2Error, INITIAL_MAX_FRAME_SIZE, INITIAL_WINDOW_SIZE,
};
use crate::context::{CancelFunc, Context};
use crate::net::error::Error as _;
use crate::net::http::body::{Body, ReadCloser};
use crate::net::http::handler::{CloseNotifier, ConnControl, Flusher, Handler, ResponseWriter};
use crate::net::http::header::{
    BoxError, Header, PushOptions, Pusher, Trailer, ERR_BODY_NOT_ALLOWED, ERR_NOT_SUPPORTED,
};
use crate::net::http::request::Request;
use crate::net::http::server::{ConnState, Server, STATE_ACTIVE, STATE_IDLE};
use crate::net::http::tlsstate::ConnectionState;
use crate::net::http::{detect_content_type, TIME_FORMAT, TRAILER_PREFIX};
use crate::net::textproto::canonical_mime_header_key;
use crate::net::url::{self, Url};
use crate::net::{AddrRef, Conn};
use crate::time::{self, Time};
use std::{
    collections::HashMap,
    io::{self, Read},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender},
        Arc, Condvar, Mutex,
    },
    time::{Duration, Instant},
};

const PREFACE_TIMEOUT: Duration = Duration::from_secs(10);
const FIRST_SETTINGS_TIMEOUT: Duration = Duration::from_secs(2);
const HANDLER_CHUNK_WRITE_SIZE: usize = 4 << 10;
const MAX_QUEUED_CONTROL_FRAMES: i64 = 10000;
const GO_AWAY_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_MAX_HEADER_BYTES: i64 = 1 << 20;

fn err_client_disconnected() -> H2Error {
    H2Error::msg("client disconnected")
}
fn err_stream_closed() -> H2Error {
    H2Error::msg("http2: stream closed")
}
fn err_closed_body() -> H2Error {
    H2Error::msg("body closed by handler")
}
fn err_handler_complete() -> H2Error {
    H2Error::msg("http2: request body closed due to handler exiting")
}
fn err_handler_panicked() -> H2Error {
    H2Error::msg("http2: handler panicked")
}

/// Go's `ErrRecursivePush`.
pub const ERR_RECURSIVE_PUSH: &str = "http2: recursive push not allowed";
/// Go's `ErrPushLimitReached`.
pub const ERR_PUSH_LIMIT_REACHED: &str =
    "http2: push would exceed peer's SETTINGS_MAX_CONCURRENT_STREAMS";

/// What `serve_conn` needs besides the connection.
pub(crate) struct ServeConnOpts {
    pub ctx: Context,
    pub saw_client_preface: bool,
}

// ------------------------------------------------------------- messages

type Done = SyncSender<Result<(), H2Error>>;

enum Write {
    Settings(Vec<Setting>),
    SettingsAck,
    GoAway {
        max_stream_id: u32,
        code: ErrCode,
    },
    Data {
        data: Vec<u8>,
        end_stream: bool,
    },
    ResHeaders(ResHeaders),
    PushPromise(Arc<PushReq>),
    Continue100,
    WindowUpdate {
        n: u32,
    },
    Rst {
        code: ErrCode,
        cause: Option<H2Error>,
    },
    HandlerPanicRst,
    Ping([u8; 8]),
    PingAck([u8; 8]),
}

struct ResHeaders {
    http_res_code: u16,
    /// Header map, `None` for none.
    h: Option<Header>,
    /// Which keys of `h` to write; `None` means all.
    trailers: Option<Vec<String>>,
    end_stream: bool,
    date: String,
    content_type: String,
    content_length: String,
}

struct WriteReq {
    write: Write,
    /// The stream the request belongs to; `None` for connection-level frames.
    stream: Option<u32>,
    /// The stream a RST_STREAM names when there is no stream handle.
    rst_id: u32,
    /// Receives the write result once the frame is on the wire.
    done: Option<Done>,
}

impl SchedItem for WriteReq {
    fn is_control(&self) -> bool {
        self.stream.is_none()
    }
    fn stream_id(&self) -> u32 {
        match self.stream {
            Some(id) => id,
            None => self.rst_id,
        }
    }
}

impl WriteReq {
    fn control(write: Write) -> Self {
        Self {
            write,
            stream: None,
            rst_id: 0,
            done: None,
        }
    }
    fn on_stream(write: Write, id: u32) -> Self {
        Self {
            write,
            stream: Some(id),
            rst_id: 0,
            done: None,
        }
    }
    fn rst(id: u32, code: ErrCode, cause: Option<H2Error>) -> Self {
        Self {
            write: Write::Rst { code, cause },
            stream: None,
            rst_id: id,
            done: None,
        }
    }
    fn reply(&mut self, res: Result<(), H2Error>) {
        if let Some(d) = self.done.take() {
            let _ = d.try_send(res);
        }
    }
    fn ends_stream(&self) -> bool {
        match &self.write {
            Write::Data { end_stream, .. } => *end_stream,
            Write::ResHeaders(h) => h.end_stream,
            _ => false,
        }
    }
}

struct PushReq {
    parent: u32,
    method: String,
    url: Url,
    header: Header,
    done: Mutex<Option<Done>>,
    /// Filled when the PUSH_PROMISE is scheduled.
    promised_id: Mutex<u32>,
}

enum Msg {
    Frame(Result<Frame, FrameError>),
    Write(WriteReq),
    Wrote(Result<(), io::Error>),
    BodyRead { stream: u32, n: usize },
    HandlerDone,
    Graceful,
    StartPush(Arc<PushReq>),
    Func(Box<dyn FnOnce(&mut ServerConn) + Send>),
}

/// The handle handlers and bodies use to reach the serve thread.
pub(crate) struct ConnHandle {
    tx: Mutex<Sender<Msg>>,
    pub(crate) done: AtomicBool,
    pub(crate) remote_addr: String,
    pub(crate) srv: Server,
}

impl ConnHandle {
    /// Starts a graceful shutdown (GOAWAY with NO_ERROR) of the connection.
    pub(crate) fn send_graceful(&self) -> Result<(), H2Error> {
        self.send(Msg::Graceful)
    }

    fn send(&self, m: Msg) -> Result<(), H2Error> {
        if self.done.load(Ordering::SeqCst) {
            return Err(err_client_disconnected());
        }
        self.tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .send(m)
            .map_err(|_| err_client_disconnected())
    }
}

// ------------------------------------------------------------ stream state

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum StState {
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

/// What handlers see of a stream.
pub(crate) struct StreamShared {
    id: u32,
    /// Set (with its cause) when the stream closes: Go's `cw` and `closeErr`.
    closed: Mutex<Option<H2Error>>,
    cv: Condvar,
    ctx: Context,
    cancel: CancelFunc,
}

impl StreamShared {
    fn close(&self, err: H2Error) {
        let mut g = self.closed.lock().unwrap_or_else(|e| e.into_inner());
        if g.is_none() {
            *g = Some(err);
        }
        drop(g);
        self.cv.notify_all();
        (self.cancel)();
    }
    fn close_err(&self) -> Option<H2Error> {
        self.closed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    fn wait_closed(&self) {
        let mut g = self.closed.lock().unwrap_or_else(|e| e.into_inner());
        while g.is_none() {
            g = self.cv.wait(g).unwrap_or_else(|e| e.into_inner());
        }
    }
}

struct Stream {
    id: u32,
    state: StState,
    shared: Arc<StreamShared>,
    body: Option<Arc<Pipe>>,
    body_bytes: i64,
    decl_body_bytes: i64,
    flow: Outflow,
    inflow: Inflow,
    reset_queued: bool,
    got_trailer_header: bool,
    wrote_headers: bool,
    read_deadline: Option<Instant>,
    write_deadline: Option<Instant>,
    /// Accumulated trailers; `None` unless the request declared some.
    trailer: Option<Header>,
    req_trailer: Trailer,
}

impl Stream {
    fn is_pushed(&self) -> bool {
        self.id.is_multiple_of(2)
    }
}

/// Everything a handler thread needs to build its `Request`.
struct ReqParts {
    method: String,
    url: Url,
    request_uri: String,
    header: Header,
    host: String,
    scheme_https: bool,
    content_length: i64,
    trailer: Trailer,
    needs_continue: bool,
    body_pipe: Option<Arc<Pipe>>,
}

#[derive(Clone, Copy)]
enum HandlerKind {
    Normal,
    HeaderListTooLong,
    Bad400,
}

struct Unstarted {
    stream_id: u32,
    parts: ReqParts,
    kind: HandlerKind,
    bad_reason: String,
    stream: Arc<StreamShared>,
}

// ---------------------------------------------------------------- timers

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Timer {
    Settings,
    Idle,
    ReadIdle,
    Shutdown,
    StreamRead(u32),
    StreamWrite(u32),
}

// ---------------------------------------------------------- the connection

pub(crate) struct ServerConn {
    srv: Server,
    conf: Config,
    conn: Arc<dyn Conn>,
    handler: Arc<dyn Handler>,
    base_ctx: Context,
    handle: Arc<ConnHandle>,
    tls_state: Option<Arc<ConnectionState>>,
    remote_addr: String,
    writer_tx: Sender<Vec<u8>>,

    flow: Outflow,
    inflow: Inflow,
    sched: Sched<WriteReq>,
    count_error: Option<super::frame::CountError>,

    push_enabled: bool,
    saw_client_preface: bool,
    saw_first_settings: bool,
    need_to_send_settings_ack: bool,
    unacked_settings: i32,
    queued_control_frames: i64,
    client_max_streams: u32,
    adv_max_streams: u32,
    cur_client_streams: u32,
    cur_pushed_streams: u32,
    cur_handlers: u32,
    max_client_stream_id: u32,
    max_push_promise_id: u32,
    streams: HashMap<u32, Stream>,
    unstarted_handlers: std::collections::VecDeque<Unstarted>,
    initial_stream_send_window: i32,
    initial_stream_recv_window: i32,
    max_frame_size: i32,
    peer_max_header_list_size: u32,
    writing_frame: bool,
    in_frame_schedule_loop: bool,
    in_go_away: bool,
    need_to_send_go_away: bool,
    ping_sent: bool,
    sent_ping_data: [u8; 8],
    go_away_code: ErrCode,
    timers: Vec<(Instant, Timer)>,
    read_idle_timeout: Duration,
    last_frame_time: Instant,
    h2_idle_timeout: Duration,

    hpack_encoder: Encoder,
    header_write_buf: Vec<u8>,
    batch: Vec<u8>,
    batch_reqs: Vec<WriteReq>,
    in_flight: Vec<WriteReq>,

    has_intermediary: bool,
    priority_aware: bool,
    quit: bool,
}

/// `maxHeaderListSize` of the server: `MaxHeaderBytes` plus per-field slack.
fn max_header_list_size(srv: &Server) -> u32 {
    let mut n = srv.max_header_bytes;
    if n <= 0 {
        n = DEFAULT_MAX_HEADER_BYTES;
    }
    adjust_http1_max_header_size(n).clamp(0, i64::from(u32::MAX)) as u32
}

struct ConnRead(Arc<dyn Conn>);
impl Read for ConnRead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf).map_err(|e| e.into_io())
    }
}

/// Serves one HTTP/2 connection until it ends (Go's `Server.ServeConn`).
pub(crate) fn serve_conn(
    srv: &Server,
    conn: Arc<dyn Conn>,
    handler: Arc<dyn Handler>,
    opts: ServeConnOpts,
) {
    let _ = conn.set_read_deadline(&Time::default());
    let _ = conn.set_write_deadline(&Time::default());
    let (base_ctx, cancel) = opts.ctx.with_cancel();
    let conf = Config::from_http2(
        super::merge_http2_config(srv.http2.as_ref(), None).as_ref(),
        true,
    );
    let remote_addr = conn
        .remote_addr()
        .map(|a| a.to_string())
        .unwrap_or_default();
    let (tx, rx) = mpsc::channel::<Msg>();
    let handle = Arc::new(ConnHandle {
        tx: Mutex::new(tx),
        done: AtomicBool::new(false),
        remote_addr: remote_addr.clone(),
        srv: srv.clone(),
    });
    let (writer_tx, writer_rx) = mpsc::channel::<Vec<u8>>();

    let tls_state = conn.tls_connection_state().map(Arc::new);
    let adv_max_streams = conf.max_concurrent_streams as u32;
    let kind = if srv.disable_client_priority {
        Kind::RoundRobin
    } else {
        Kind::Rfc9218
    };
    let mut sc = ServerConn {
        srv: srv.clone(),
        conn: conn.clone(),
        handler,
        base_ctx,
        handle: handle.clone(),
        tls_state: tls_state.clone(),
        remote_addr,
        writer_tx,
        flow: Outflow::default(),
        inflow: Inflow::default(),
        sched: Sched::new(kind),
        count_error: conf.count_error.clone(),
        push_enabled: true,
        saw_client_preface: opts.saw_client_preface,
        saw_first_settings: false,
        need_to_send_settings_ack: false,
        unacked_settings: 0,
        queued_control_frames: 0,
        client_max_streams: u32::MAX,
        adv_max_streams,
        cur_client_streams: 0,
        cur_pushed_streams: 0,
        cur_handlers: 0,
        max_client_stream_id: 0,
        max_push_promise_id: 0,
        streams: HashMap::new(),
        unstarted_handlers: Default::default(),
        initial_stream_send_window: INITIAL_WINDOW_SIZE,
        initial_stream_recv_window: conf.max_receive_buffer_per_stream as i32,
        max_frame_size: INITIAL_MAX_FRAME_SIZE as i32,
        peer_max_header_list_size: 0,
        writing_frame: false,
        in_frame_schedule_loop: false,
        in_go_away: false,
        need_to_send_go_away: false,
        ping_sent: false,
        sent_ping_data: [0; 8],
        go_away_code: ERR_CODE_NO,
        timers: Vec::new(),
        read_idle_timeout: Duration::ZERO,
        last_frame_time: Instant::now(),
        h2_idle_timeout: {
            let d = if srv.idle_timeout.as_nanos() != 0 {
                srv.idle_timeout
            } else {
                srv.read_timeout
            };
            Duration::from_nanos(u64::try_from(d.as_nanos()).unwrap_or(0))
        },
        hpack_encoder: Encoder::new(),
        header_write_buf: Vec::new(),
        batch: Vec::new(),
        batch_reqs: Vec::new(),
        in_flight: Vec::new(),
        has_intermediary: false,
        priority_aware: false,
        quit: false,
        conf,
    };
    sc.flow.add(INITIAL_WINDOW_SIZE);
    sc.inflow.init(INITIAL_WINDOW_SIZE);
    sc.hpack_encoder
        .set_max_dynamic_table_size_limit(sc.conf.max_encoder_header_table_size as u32);

    // Register for graceful shutdown (Go: Server.RegisterOnShutdown(GracefulShutdown)).
    let reg = srv.h2_register(&handle);

    let writer_conn = conn.clone();
    let write_timeout = sc.conf.write_byte_timeout.to_std();
    let writer_handle = handle.clone();
    let writer_thread = std::thread::spawn(move || {
        while let Ok(buf) = writer_rx.recv() {
            let res = write_all_with_timeout(&*writer_conn, &buf, write_timeout);
            if writer_handle.send(Msg::Wrote(res)).is_err() {
                break;
            }
        }
    });

    // TLS requirements (RFC 9113 section 9.2).
    if let Some(st) = &tls_state {
        if st.version < 0x0303 {
            sc.reject_conn(ERR_CODE_INADEQUATE_SECURITY, "TLS version too low");
            finish(&handle, writer_thread, sc, reg, cancel);
            return;
        }
        if !sc.conf.permit_prohibited_cipher_suites && is_bad_cipher(st.cipher_suite) {
            let msg = format!("Prohibited TLS 1.2 Cipher Suite: {:x}", st.cipher_suite);
            sc.reject_conn(ERR_CODE_INADEQUATE_SECURITY, &msg);
            finish(&handle, writer_thread, sc, reg, cancel);
            return;
        }
    }

    sc.serve(rx);
    finish(&handle, writer_thread, sc, reg, cancel);
}

fn finish(
    handle: &Arc<ConnHandle>,
    writer: std::thread::JoinHandle<()>,
    sc: ServerConn,
    reg: Option<crate::net::http::server::H2Registration>,
    cancel: CancelFunc,
) {
    handle.done.store(true, Ordering::SeqCst);
    let _ = sc.conn.close();
    drop(sc); // drops the writer channel so the writer thread exits
    let _ = writer.join();
    drop(reg);
    cancel();
}

fn write_all_with_timeout(conn: &dyn Conn, buf: &[u8], byte_timeout: Duration) -> io::Result<()> {
    let mut n = 0;
    while n < buf.len() {
        if !byte_timeout.is_zero() {
            let _ = conn.set_write_deadline(&time::now().add(crate::time::Duration::from_nanos(
                byte_timeout.as_nanos() as i64,
            )));
        }
        match conn.write(&buf[n..]) {
            Ok(0) => {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "short write"));
            }
            Ok(k) => n += k,
            Err(e) => return Err(e.into_io()),
        }
    }
    if !byte_timeout.is_zero() {
        let _ = conn.set_write_deadline(&Time::default());
    }
    Ok(())
}

impl ServerConn {
    fn logf(&self, args: std::fmt::Arguments<'_>) {
        self.srv.logf(args);
    }

    fn count_err(&self, name: &str, err: &Proc) -> Proc {
        if let Some(f) = &self.count_error {
            let (typ, code) = match err {
                Proc::Conn(c) => ("conn", *c),
                Proc::Stream { code, .. } => ("stream", *code),
                _ => return err.clone(),
            };
            f(&format!("{typ}_{}_{name}", err_code_token(code)));
        }
        err.clone()
    }

    fn reject_conn(&mut self, code: ErrCode, debug: &str) {
        let mut fw = FrameWriter::new(Vec::new());
        let _ = fw.write_goaway(0, code, debug.as_bytes());
        let _ = self.conn.write(fw.get_ref());
        let _ = self.conn.close();
    }

    fn set_conn_state(&self, state: ConnState) {
        if let Some(f) = &self.srv.conn_state {
            f(&self.conn, state);
        }
    }

    // ------------------------------------------------------------- timers

    fn set_timer(&mut self, t: Timer, d: Duration) {
        self.cancel_timer(t);
        self.timers.push((Instant::now() + d, t));
    }
    fn set_timer_at(&mut self, t: Timer, at: Instant) {
        self.cancel_timer(t);
        self.timers.push((at, t));
    }
    fn cancel_timer(&mut self, t: Timer) {
        self.timers.retain(|(_, k)| *k != t);
    }
    fn has_timer(&self, t: Timer) -> bool {
        self.timers.iter().any(|(_, k)| *k == t)
    }
    fn next_deadline(&self) -> Option<Instant> {
        self.timers.iter().map(|(at, _)| *at).min()
    }

    // ---------------------------------------------------------- serve loop

    fn read_preface(&mut self) -> Result<(), String> {
        if self.saw_client_preface {
            return Ok(());
        }
        let _ = self
            .conn
            .set_read_deadline(&time::now().add(crate::time::Duration::from_nanos(
                PREFACE_TIMEOUT.as_nanos() as i64,
            )));
        let mut buf = vec![0u8; CLIENT_PREFACE.len()];
        let mut got = 0;
        while got < buf.len() {
            match self.conn.read(&mut buf[got..]) {
                Ok(0) => {
                    let _ = self.conn.set_read_deadline(&Time::default());
                    return Err(if got == 0 {
                        "EOF".into()
                    } else {
                        "unexpected EOF".into()
                    });
                }
                Ok(n) => got += n,
                Err(e) => {
                    let _ = self.conn.set_read_deadline(&Time::default());
                    if e.timeout() {
                        return Err("timeout waiting for client preface".into());
                    }
                    return Err(e.to_string());
                }
            }
        }
        let _ = self.conn.set_read_deadline(&Time::default());
        if buf != CLIENT_PREFACE {
            return Err(format!(
                "bogus greeting {}",
                crate::strconv::quote(&buf[..])
            ));
        }
        Ok(())
    }

    fn serve(&mut self, rx: Receiver<Msg>) {
        let settings = vec![
            Setting {
                id: SETTING_MAX_FRAME_SIZE,
                val: self.conf.max_read_frame_size as u32,
            },
            Setting {
                id: SETTING_MAX_CONCURRENT_STREAMS,
                val: self.adv_max_streams,
            },
            Setting {
                id: SETTING_MAX_HEADER_LIST_SIZE,
                val: max_header_list_size(&self.srv),
            },
            Setting {
                id: SETTING_HEADER_TABLE_SIZE,
                val: self.conf.max_decoder_header_table_size as u32,
            },
            Setting {
                id: SETTING_INITIAL_WINDOW_SIZE,
                val: self.initial_stream_recv_window as u32,
            },
            // Both write schedulers ignore RFC 7540 priorities.
            Setting {
                id: SETTING_NO_RFC7540_PRIORITIES,
                val: 1,
            },
        ];
        self.write_frame(WriteReq::control(Write::Settings(settings)));
        self.unacked_settings += 1;

        let diff = self.conf.max_receive_buffer_per_connection - i64::from(INITIAL_WINDOW_SIZE);
        if diff > 0 {
            self.send_window_update(None, diff as usize);
        }

        if let Err(e) = self.read_preface() {
            let transient = e == "EOF"
                || e == "unexpected EOF"
                || e.contains("closed network connection")
                || e == "timeout waiting for client preface";
            if !transient {
                self.logf(format_args!(
                    "http2: server: error reading preface from client {}: {}",
                    self.remote_addr, e
                ));
            }
            // Let the SETTINGS frame we queued reach the wire before hanging up.
            self.drain_pending_writes(&rx);
            return;
        }
        self.set_conn_state(STATE_ACTIVE);
        self.set_conn_state(STATE_IDLE);

        if !self.h2_idle_timeout.is_zero() {
            let d = self.h2_idle_timeout;
            self.set_timer(Timer::Idle, d);
        }
        if !self.conf.send_ping_timeout.is_zero() {
            self.read_idle_timeout = self.conf.send_ping_timeout.to_std();
            let d = self.read_idle_timeout;
            self.set_timer(Timer::ReadIdle, d);
        }

        // The reader thread.
        let handle = self.handle.clone();
        let conn = self.conn.clone();
        let max_read = self.conf.max_read_frame_size as u32;
        let decoder_table = self.conf.max_decoder_header_table_size as u32;
        let hls = max_header_list_size(&self.srv);
        let hvc = self.srv.max_header_value_count();
        let count_error = self.count_error.clone();
        std::thread::spawn(move || {
            let mut fr = FrameReader::new(ConnRead(conn));
            fr.set_max_read_frame_size(max_read);
            fr.set_meta_headers_decoder(Some(Decoder::new(decoder_table)));
            fr.set_max_header_list_size(hls);
            fr.set_max_header_value_count(hvc.max(0) as usize);
            fr.set_count_error(count_error);
            loop {
                let r = fr.read_frame();
                let terminal = match &r {
                    Err(e) => e.is_terminal(),
                    Ok(_) => false,
                };
                if handle.send(Msg::Frame(r)).is_err() || terminal {
                    return;
                }
            }
        });

        self.set_timer(Timer::Settings, FIRST_SETTINGS_TIMEOUT);
        self.last_frame_time = Instant::now();

        while !self.quit {
            let msg = match self.next_deadline() {
                None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
                Some(at) => rx.recv_timeout(at.saturating_duration_since(Instant::now())),
            };
            match msg {
                Ok(m) => self.dispatch(m),
                Err(RecvTimeoutError::Timeout) => self.fire_timers(),
                Err(RecvTimeoutError::Disconnected) => return,
            }
            if self.quit {
                break;
            }
            if self.queued_control_frames > MAX_QUEUED_CONTROL_FRAMES {
                self.logf(format_args!(
                    "http2: too many control frames in send queue, closing connection"
                ));
                break;
            }
            let sent_go_away = self.in_go_away && !self.need_to_send_go_away && !self.writing_frame;
            let graceful_complete =
                self.go_away_code == ERR_CODE_NO && self.cur_open_streams() == 0;
            if sent_go_away
                && !self.has_timer(Timer::Shutdown)
                && (self.go_away_code != ERR_CODE_NO || graceful_complete)
            {
                self.set_timer(Timer::Shutdown, GO_AWAY_TIMEOUT);
            }
        }
        self.close_all_streams_on_conn_close();
    }

    /// Waits briefly for the queued frames (the initial SETTINGS) to be
    /// written before the connection is torn down.
    fn drain_pending_writes(&mut self, rx: &Receiver<Msg>) {
        let deadline = Instant::now() + Duration::from_millis(200);
        while self.writing_frame {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok(Msg::Wrote(res)) => self.wrote_frame(res),
                Ok(_) => {}
                Err(_) => break,
            }
        }
    }

    fn dispatch(&mut self, m: Msg) {
        match m {
            Msg::Write(mut wr) => {
                // A StreamError write (RST_STREAM from a handler) goes through reset_stream.
                if let Write::Rst { code, cause } = &wr.write {
                    let (id, code, cause) = (wr.rst_id, *code, cause.clone());
                    wr.reply(Ok(()));
                    self.reset_stream(id, code, cause);
                } else {
                    self.write_frame(wr);
                }
            }
            Msg::Wrote(res) => self.wrote_frame(res),
            Msg::Frame(r) => {
                self.last_frame_time = Instant::now();
                if self.writing_frame {
                    // Go checks for an already-finished write before processing.
                }
                if !self.process_frame_from_reader(r) {
                    self.quit = true;
                    return;
                }
                if self.has_timer(Timer::Settings) {
                    self.cancel_timer(Timer::Settings);
                }
            }
            Msg::BodyRead { stream, n } => self.note_body_read(stream, n),
            Msg::HandlerDone => self.handler_done(),
            Msg::Graceful => self.go_away(ERR_CODE_NO),
            Msg::StartPush(p) => self.start_push(p),
            Msg::Func(f) => f(self),
        }
    }

    fn fire_timers(&mut self) {
        let now = Instant::now();
        let due: Vec<Timer> = self
            .timers
            .iter()
            .filter(|(at, _)| *at <= now)
            .map(|(_, t)| *t)
            .collect();
        self.timers.retain(|(at, _)| *at > now);
        for t in due {
            match t {
                Timer::Settings => {
                    self.logf(format_args!(
                        "timeout waiting for SETTINGS frames from {}",
                        self.remote_addr
                    ));
                    self.quit = true;
                }
                Timer::Idle => self.go_away(ERR_CODE_NO),
                Timer::ReadIdle => self.handle_ping_timer(),
                Timer::Shutdown => {
                    self.quit = true;
                }
                Timer::StreamRead(id) => {
                    if let Some(st) = self.streams.get(&id) {
                        if let Some(b) = &st.body {
                            b.close_with_error(H2Error::DeadlineExceeded);
                        }
                    }
                }
                Timer::StreamWrite(id) => {
                    if self.streams.contains_key(&id) {
                        self.reset_stream(id, ERR_CODE_INTERNAL, Some(H2Error::DeadlineExceeded));
                    }
                }
            }
        }
    }

    fn handle_ping_timer(&mut self) {
        if self.ping_sent {
            self.logf(format_args!("timeout waiting for PING response"));
            if let Some(f) = &self.count_error {
                f("conn_close_lost_ping");
            }
            self.quit = true;
            return;
        }
        let ping_at = self.last_frame_time + self.read_idle_timeout;
        let now = Instant::now();
        if ping_at > now {
            self.set_timer_at(Timer::ReadIdle, ping_at);
            return;
        }
        self.ping_sent = true;
        self.sent_ping_data = rand_ping_data();
        let data = self.sent_ping_data;
        self.write_frame(WriteReq::control(Write::Ping(data)));
        let d = self.conf.ping_timeout.to_std();
        self.set_timer(Timer::ReadIdle, d);
    }

    // ------------------------------------------------------ stream queries

    fn cur_open_streams(&self) -> u32 {
        self.cur_client_streams + self.cur_pushed_streams
    }

    /// Go's `state(streamID)`: the stream's state, or closed/idle for
    /// streams we no longer hold.
    fn state_of(&self, id: u32) -> Option<StState> {
        if let Some(st) = self.streams.get(&id) {
            return Some(st.state);
        }
        if id % 2 == 1 {
            if id <= self.max_client_stream_id {
                return Some(StState::Closed);
            }
        } else if id <= self.max_push_promise_id {
            return Some(StState::Closed);
        }
        None // idle
    }

    // -------------------------------------------------------------- writes

    fn write_frame(&mut self, mut wr: WriteReq) {
        let mut ignore_write = false;
        let sid = wr.stream_id();
        if sid != 0 {
            let is_reset = matches!(wr.write, Write::Rst { .. });
            if self.state_of(sid) == Some(StState::Closed) && !is_reset {
                ignore_write = true;
            }
        }
        match &wr.write {
            Write::ResHeaders(_) => {
                if let Some(st) = wr.stream.and_then(|id| self.streams.get_mut(&id)) {
                    st.wrote_headers = true;
                }
            }
            Write::Continue100 => {
                if let Some(st) = wr.stream.and_then(|id| self.streams.get(&id)) {
                    if st.wrote_headers {
                        ignore_write = true;
                    }
                }
            }
            _ => {}
        }
        if !ignore_write {
            if wr.is_control() {
                self.queued_control_frames += 1;
            }
            self.sched.push(wr);
        } else {
            wr.reply(Err(err_stream_closed()));
        }
        self.schedule_frame_write();
    }

    fn schedule_frame_write(&mut self) {
        if self.writing_frame || self.in_frame_schedule_loop {
            return;
        }
        self.in_frame_schedule_loop = true;
        loop {
            if self.batch.len() >= 64 << 10 {
                break;
            }
            if self.need_to_send_go_away {
                self.need_to_send_go_away = false;
                let wr = WriteReq::control(Write::GoAway {
                    max_stream_id: self.max_client_stream_id,
                    code: self.go_away_code,
                });
                self.encode_frame(wr);
                continue;
            }
            if self.need_to_send_settings_ack {
                self.need_to_send_settings_ack = false;
                self.encode_frame(WriteReq::control(Write::SettingsAck));
                continue;
            }
            if !self.in_go_away || self.go_away_code == ERR_CODE_NO {
                if let Some(wr) = self.pop_write() {
                    if wr.is_control() {
                        self.queued_control_frames -= 1;
                    }
                    self.encode_frame(wr);
                    continue;
                }
            }
            break;
        }
        self.in_frame_schedule_loop = false;
        self.flush_batch();
    }

    /// Pops the next request, splitting DATA to fit the flow-control windows
    /// (Go's `FrameWriteRequest.Consume`).
    fn pop_write(&mut self) -> Option<WriteReq> {
        let max_frame = self.max_frame_size;
        let streams = &mut self.streams;
        let conn_flow = &mut self.flow;
        let mut consume = |wr: &mut WriteReq| -> Take<WriteReq> {
            let Write::Data { data, end_stream } = &mut wr.write else {
                return Take::Whole;
            };
            if data.is_empty() {
                return Take::Whole;
            }
            let Some(id) = wr.stream else {
                return Take::Whole;
            };
            let Some(st) = streams.get_mut(&id) else {
                return Take::Whole;
            };
            let mut allowed = flow::available(&st.flow, conn_flow);
            allowed = allowed.min(max_frame);
            if allowed <= 0 {
                return Take::Blocked;
            }
            if data.len() > allowed as usize {
                flow::take(&mut st.flow, conn_flow, allowed);
                let rest = data.split_off(allowed as usize);
                let piece = std::mem::replace(data, rest);
                let _ = end_stream;
                return Take::Piece(WriteReq {
                    write: Write::Data {
                        data: piece,
                        end_stream: false,
                    },
                    stream: Some(id),
                    rst_id: 0,
                    done: None,
                });
            }
            flow::take(&mut st.flow, conn_flow, data.len() as i32);
            Take::Whole
        };
        self.sched.pop(&mut consume)
    }

    fn flush_batch(&mut self) {
        if self.writing_frame || self.batch.is_empty() {
            return;
        }
        self.writing_frame = true;
        let buf = std::mem::take(&mut self.batch);
        self.in_flight = std::mem::take(&mut self.batch_reqs);
        if self.writer_tx.send(buf).is_err() {
            self.writing_frame = false;
            self.quit = true;
        }
    }

    /// Encodes one request's frame into the pending batch (Go's `startFrameWrite`).
    fn encode_frame(&mut self, mut wr: WriteReq) {
        let mut fw = FrameWriter::new(std::mem::take(&mut self.batch));
        let sid = wr.stream_id();
        let result: Result<(), H2Error> = match &wr.write {
            Write::Settings(s) => fw.write_settings(s).map_err(H2Error::from_frame_error),
            Write::SettingsAck => fw.write_settings_ack().map_err(H2Error::from_frame_error),
            Write::GoAway {
                max_stream_id,
                code,
            } => fw
                .write_goaway(*max_stream_id, *code, &[])
                .map_err(H2Error::from_frame_error),
            Write::Data { data, end_stream } => fw
                .write_data(sid, *end_stream, data)
                .map_err(H2Error::from_frame_error),
            Write::Ping(d) => fw.write_ping(false, *d).map_err(H2Error::from_frame_error),
            Write::PingAck(d) => fw.write_ping(true, *d).map_err(H2Error::from_frame_error),
            Write::WindowUpdate { n } => fw
                .write_window_update(sid, *n)
                .map_err(H2Error::from_frame_error),
            Write::Rst { code, .. } => fw
                .write_rst_stream(sid, *code)
                .map_err(H2Error::from_frame_error),
            Write::HandlerPanicRst => fw
                .write_rst_stream(sid, ERR_CODE_INTERNAL)
                .map_err(H2Error::from_frame_error),
            Write::Continue100 => {
                self.header_write_buf.clear();
                let mut buf = std::mem::take(&mut self.header_write_buf);
                self.hpack_encoder
                    .write_field(&HeaderField::new(":status", "100"), &mut buf);
                let r = fw
                    .write_headers(&HeadersParam {
                        stream_id: sid,
                        block_fragment: &buf,
                        end_stream: false,
                        end_headers: true,
                        ..HeadersParam::default()
                    })
                    .map_err(H2Error::from_frame_error);
                self.header_write_buf = buf;
                r
            }
            Write::ResHeaders(h) => {
                self.header_write_buf.clear();
                let mut buf = std::mem::take(&mut self.header_write_buf);
                if h.http_res_code != 0 {
                    self.hpack_encoder.write_field(
                        &HeaderField::new(":status", http_code_string(h.http_res_code)),
                        &mut buf,
                    );
                }
                if let Some(hh) = &h.h {
                    encode_headers(&mut self.hpack_encoder, &mut buf, hh, h.trailers.as_deref());
                }
                for (k, v) in [
                    ("content-type", &h.content_type),
                    ("content-length", &h.content_length),
                    ("date", &h.date),
                ] {
                    if !v.is_empty() {
                        self.hpack_encoder
                            .write_field(&HeaderField::new(k, v), &mut buf);
                    }
                }
                let r = if buf.is_empty() && h.trailers.is_none() {
                    Err(H2Error::msg("unexpected empty hpack"))
                } else {
                    split_header_block(&mut fw, &buf, &mut |fw, frag, first, last| {
                        if first {
                            fw.write_headers(&HeadersParam {
                                stream_id: sid,
                                block_fragment: frag,
                                end_stream: h.end_stream,
                                end_headers: last,
                                ..HeadersParam::default()
                            })
                        } else {
                            fw.write_continuation(sid, last, frag)
                        }
                    })
                    .map_err(H2Error::from_frame_error)
                };
                self.header_write_buf = buf;
                r
            }
            Write::PushPromise(p) => {
                let promised = self.allocate_promised_id(p);
                match promised {
                    Err(e) => Err(e),
                    Ok(promised_id) => {
                        self.header_write_buf.clear();
                        let mut buf = std::mem::take(&mut self.header_write_buf);
                        let enc = &mut self.hpack_encoder;
                        enc.write_field(&HeaderField::new(":method", &p.method), &mut buf);
                        enc.write_field(&HeaderField::new(":scheme", &p.url.scheme), &mut buf);
                        enc.write_field(&HeaderField::new(":authority", &p.url.host), &mut buf);
                        enc.write_field(&HeaderField::new(":path", p.url.request_uri()), &mut buf);
                        encode_headers(enc, &mut buf, &p.header, None);
                        let parent = p.parent;
                        let r = split_header_block(&mut fw, &buf, &mut |fw, frag, first, last| {
                            if first {
                                fw.write_push_promise(&PushPromiseParam {
                                    stream_id: parent,
                                    promise_id: promised_id,
                                    block_fragment: frag,
                                    end_headers: last,
                                    pad_length: 0,
                                })
                            } else {
                                fw.write_continuation(parent, last, frag)
                            }
                        })
                        .map_err(H2Error::from_frame_error);
                        self.header_write_buf = buf;
                        r
                    }
                }
            }
        };
        self.batch = fw.into_inner();
        match result {
            Ok(()) => self.batch_reqs.push(wr),
            Err(e) => {
                wr.reply(Err(e));
            }
        }
    }

    /// Go's `allocatePromisedID` closure of `startPush`.
    fn allocate_promised_id(&mut self, msg: &Arc<PushReq>) -> Result<u32, H2Error> {
        if !self.push_enabled {
            return Err(H2Error::msg(ERR_NOT_SUPPORTED.error_string));
        }
        if self.cur_pushed_streams + 1 > self.client_max_streams {
            return Err(H2Error::msg(ERR_PUSH_LIMIT_REACHED));
        }
        if self.max_push_promise_id + 2 >= 1 << 31 {
            self.go_away(ERR_CODE_NO);
            return Err(H2Error::msg(ERR_PUSH_LIMIT_REACHED));
        }
        self.max_push_promise_id += 2;
        let promised_id = self.max_push_promise_id;
        *msg.promised_id.lock().unwrap_or_else(|e| e.into_inner()) = promised_id;

        let (urg, inc) = self.initial_priority();
        let shared = self.new_stream(promised_id, msg.parent, StState::HalfClosedRemote, urg, inc);
        let url = &msg.url;
        let mut header = msg.header.clone();
        let parts = self.request_parts_no_body(
            &shared,
            &msg.method,
            &url.scheme,
            &url.host,
            &url.request_uri(),
            &mut header,
        );
        match parts {
            Ok(parts) => {
                self.cur_handlers += 1;
                self.spawn_handler(shared, parts, HandlerKind::Normal, String::new());
                Ok(promised_id)
            }
            Err(e) => Err(H2Error::msg(format!("{e:?}"))),
        }
    }

    fn initial_priority(&self) -> (u8, u8) {
        let p = default_rfc9218_priority(self.priority_aware && !self.has_intermediary);
        (p.urgency(), p.incremental())
    }

    fn wrote_frame(&mut self, res: Result<(), io::Error>) {
        self.writing_frame = false;
        let reqs = std::mem::take(&mut self.in_flight);
        let err = match res {
            Ok(()) => None,
            Err(e) => {
                let _ = self.conn.close();
                Some(H2Error::Io(Arc::new(e)))
            }
        };
        for mut wr in reqs {
            if wr.ends_stream() {
                if let Some(id) = wr.stream {
                    match self.streams.get(&id).map(|s| s.state) {
                        Some(StState::Open) => {
                            if let Some(st) = self.streams.get_mut(&id) {
                                st.state = StState::HalfClosedLocal;
                            }
                            self.reset_stream(id, ERR_CODE_NO, None);
                        }
                        Some(StState::HalfClosedRemote) => {
                            self.close_stream(id, err_handler_complete());
                        }
                        _ => {}
                    }
                }
            } else {
                match &wr.write {
                    Write::Rst { code, cause } => {
                        let id = wr.rst_id;
                        if self.streams.contains_key(&id) {
                            let e = H2Error::Stream {
                                stream_id: id,
                                code: *code,
                                cause: cause.clone().map(Arc::new),
                                from_peer: false,
                            };
                            self.close_stream(id, e);
                        }
                    }
                    Write::HandlerPanicRst => {
                        if let Some(id) = wr.stream {
                            if self.streams.contains_key(&id) {
                                self.close_stream(id, err_handler_panicked());
                            }
                        }
                    }
                    _ => {}
                }
            }
            wr.reply(match &err {
                None => Ok(()),
                Some(e) => Err(e.clone()),
            });
        }
        self.schedule_frame_write();
    }

    fn go_away(&mut self, code: ErrCode) {
        if self.in_go_away {
            if self.go_away_code == ERR_CODE_NO {
                self.go_away_code = code;
            }
            return;
        }
        self.in_go_away = true;
        self.need_to_send_go_away = true;
        self.go_away_code = code;
        self.schedule_frame_write();
    }

    fn reset_stream(&mut self, id: u32, code: ErrCode, cause: Option<H2Error>) {
        self.write_frame(WriteReq::rst(id, code, cause));
        if let Some(st) = self.streams.get_mut(&id) {
            st.reset_queued = true;
        }
    }

    // ------------------------------------------------- frame processing

    fn process_frame_from_reader(&mut self, r: Result<Frame, FrameError>) -> bool {
        let (err, frame) = match r {
            Err(e) => {
                match &e {
                    FrameError::TooLarge { .. } => {
                        self.go_away(ERR_CODE_FRAME_SIZE);
                        return true;
                    }
                    FrameError::Eof | FrameError::UnexpectedEof => return false,
                    FrameError::Io(io) if is_closed_conn_error(io) => return false,
                    _ => {}
                }
                let proc = match &e {
                    FrameError::Stream {
                        stream_id,
                        code,
                        cause,
                    } => Proc::Stream {
                        id: *stream_id,
                        code: *code,
                        cause: cause.clone().map(H2Error::msg),
                    },
                    FrameError::Connection(c) => Proc::Conn(*c),
                    other => Proc::Other(other.to_string()),
                };
                (Some((proc, true)), None)
            }
            Ok(f) => {
                let hid = f.header().stream_id;
                match self.process_frame(f) {
                    Ok(()) => return true,
                    Err(p) => (Some((p, false)), Some(hid)),
                }
            }
        };
        let (proc, from_read_err) = err.expect("error");
        match proc {
            Proc::Stream { id, code, cause } => {
                self.reset_stream(id, code, cause);
                true
            }
            Proc::GoAwayFlow => {
                self.go_away(ERR_CODE_FLOW_CONTROL);
                true
            }
            Proc::Conn(code) => {
                if let Some(id) = frame {
                    if id > self.max_client_stream_id {
                        self.max_client_stream_id = id;
                    }
                }
                self.logf(format_args!(
                    "http2: server connection error from {}: connection error: {}",
                    self.remote_addr,
                    err_code_string(code)
                ));
                self.go_away(code);
                true
            }
            Proc::Other(msg) => {
                if from_read_err {
                    // vlogf only.
                } else {
                    self.logf(format_args!(
                        "http2: server closing client connection: {msg}"
                    ));
                }
                false
            }
        }
    }

    fn process_frame(&mut self, f: Frame) -> Result<(), Proc> {
        if !self.saw_first_settings {
            if !matches!(f, Frame::Settings { .. }) {
                return Err(self.count_err("first_settings", &Proc::Conn(ERR_CODE_PROTOCOL)));
            }
            self.saw_first_settings = true;
        }
        let hdr = f.header();
        if self.in_go_away
            && (self.go_away_code != ERR_CODE_NO || hdr.stream_id > self.max_client_stream_id)
        {
            if let Frame::Data { header, .. } = &f {
                if !self.inflow.take(header.length) {
                    return Err(self.count_err(
                        "data_flow",
                        &Proc::stream(header.stream_id, ERR_CODE_FLOW_CONTROL),
                    ));
                }
                self.send_window_update(None, header.length as usize);
            }
            return Ok(());
        }
        match f {
            Frame::Settings { header, settings } => self.process_settings(header, settings),
            Frame::Meta(m) => self.process_headers(m),
            Frame::WindowUpdate { header, increment } => {
                self.process_window_update(header.stream_id, increment)
            }
            Frame::Ping { header, data } => self.process_ping(header, data),
            Frame::Data { header, data } => self.process_data(header, data),
            Frame::RstStream { header, code } => self.process_reset_stream(header.stream_id, code),
            Frame::Priority { header, priority } => {
                self.process_priority(header.stream_id, priority)
            }
            Frame::GoAway { .. } => {
                self.go_away(ERR_CODE_NO);
                self.push_enabled = false;
                Ok(())
            }
            Frame::PushPromise { .. } => {
                Err(self.count_err("push_promise", &Proc::Conn(ERR_CODE_PROTOCOL)))
            }
            Frame::PriorityUpdate {
                priority,
                prioritized_stream_id,
                ..
            } => self.process_priority_update(prioritized_stream_id, &priority),
            _ => Ok(()),
        }
    }

    fn process_ping(&mut self, header: FrameHeader, data: [u8; 8]) -> Result<(), Proc> {
        if header.has(FLAG_PING_ACK) {
            if self.ping_sent && self.sent_ping_data == data {
                self.ping_sent = false;
                let d = self.read_idle_timeout;
                if !d.is_zero() {
                    self.set_timer(Timer::ReadIdle, d);
                }
            }
            return Ok(());
        }
        if header.stream_id != 0 {
            return Err(self.count_err("ping_on_stream", &Proc::Conn(ERR_CODE_PROTOCOL)));
        }
        self.write_frame(WriteReq::control(Write::PingAck(data)));
        Ok(())
    }

    fn process_window_update(&mut self, stream_id: u32, increment: u32) -> Result<(), Proc> {
        if stream_id != 0 {
            let state = self.state_of(stream_id);
            if state.is_none() {
                return Err(self.count_err("stream_idle", &Proc::Conn(ERR_CODE_PROTOCOL)));
            }
            let Some(st) = self.streams.get_mut(&stream_id) else {
                return Ok(());
            };
            if !st.flow.add(increment as i32) {
                return Err(
                    self.count_err("bad_flow", &Proc::stream(stream_id, ERR_CODE_FLOW_CONTROL))
                );
            }
        } else if !self.flow.add(increment as i32) {
            return Err(Proc::GoAwayFlow);
        }
        self.schedule_frame_write();
        Ok(())
    }

    fn process_reset_stream(&mut self, stream_id: u32, code: ErrCode) -> Result<(), Proc> {
        if self.state_of(stream_id).is_none() {
            return Err(self.count_err("reset_idle_stream", &Proc::Conn(ERR_CODE_PROTOCOL)));
        }
        if let Some(st) = self.streams.get(&stream_id) {
            (st.shared.cancel)();
            self.close_stream(stream_id, H2Error::stream(stream_id, code));
        }
        Ok(())
    }

    fn close_stream(&mut self, id: u32, err: H2Error) {
        let Some(mut st) = self.streams.remove(&id) else {
            return;
        };
        st.state = StState::Closed;
        self.cancel_timer(Timer::StreamRead(id));
        self.cancel_timer(Timer::StreamWrite(id));
        if st.is_pushed() {
            self.cur_pushed_streams -= 1;
        } else {
            self.cur_client_streams -= 1;
        }
        if self.streams.is_empty() {
            self.set_conn_state(STATE_IDLE);
            if !self.h2_idle_timeout.is_zero() {
                let d = self.h2_idle_timeout;
                self.set_timer(Timer::Idle, d);
            }
            if !self.srv.do_keep_alives() {
                self.go_away(ERR_CODE_NO);
            }
        }
        if let Some(p) = &st.body {
            let unread = p.len();
            self.send_window_update(None, unread);
            p.close_with_error(err.clone());
        }
        let mut e = err;
        if let H2Error::Stream { cause, .. } = &e {
            e = match cause {
                Some(c) => (**c).clone(),
                None => err_stream_closed(),
            };
        }
        st.shared.close(e);
        self.sched.close_stream(id);
    }

    fn close_all_streams_on_conn_close(&mut self) {
        let ids: Vec<u32> = self.streams.keys().copied().collect();
        for id in ids {
            self.close_stream(id, err_client_disconnected());
        }
    }

    fn process_settings(
        &mut self,
        header: FrameHeader,
        settings: Vec<Setting>,
    ) -> Result<(), Proc> {
        if header.has(FLAG_SETTINGS_ACK) {
            self.unacked_settings -= 1;
            if self.unacked_settings < 0 {
                return Err(self.count_err("ack_mystery", &Proc::Conn(ERR_CODE_PROTOCOL)));
            }
            return Ok(());
        }
        let dup = (0..settings.len())
            .any(|i| (i + 1..settings.len()).any(|j| settings[i].id == settings[j].id));
        if settings.len() > 100 || dup {
            return Err(self.count_err("settings_big_or_dups", &Proc::Conn(ERR_CODE_PROTOCOL)));
        }
        for s in settings {
            self.process_setting(s)?;
        }
        self.need_to_send_settings_ack = true;
        self.schedule_frame_write();
        Ok(())
    }

    fn process_setting(&mut self, s: Setting) -> Result<(), Proc> {
        if let Err(code) = s.valid() {
            return Err(Proc::Conn(code));
        }
        match s.id {
            SETTING_HEADER_TABLE_SIZE => self.hpack_encoder.set_max_dynamic_table_size(s.val),
            SETTING_ENABLE_PUSH => self.push_enabled = s.val != 0,
            SETTING_MAX_CONCURRENT_STREAMS => self.client_max_streams = s.val,
            SETTING_INITIAL_WINDOW_SIZE => return self.process_setting_initial_window_size(s.val),
            SETTING_MAX_FRAME_SIZE => self.max_frame_size = s.val as i32,
            SETTING_MAX_HEADER_LIST_SIZE => self.peer_max_header_list_size = s.val,
            SETTING_NO_RFC7540_PRIORITIES if s.val > 1 => {
                return Err(Proc::Conn(ERR_CODE_PROTOCOL));
            }
            _ => {}
        }
        Ok(())
    }

    fn process_setting_initial_window_size(&mut self, val: u32) -> Result<(), Proc> {
        let old = self.initial_stream_send_window;
        self.initial_stream_send_window = val as i32;
        let growth = (val as i32).wrapping_sub(old);
        let mut bad = false;
        for st in self.streams.values_mut() {
            if !st.flow.add(growth) {
                bad = true;
            }
        }
        if bad {
            return Err(self.count_err("setting_win_size", &Proc::Conn(ERR_CODE_FLOW_CONTROL)));
        }
        Ok(())
    }

    fn process_data(&mut self, header: FrameHeader, data: Vec<u8>) -> Result<(), Proc> {
        let id = header.stream_id;
        let state = self.state_of(id);
        if id == 0 || state.is_none() {
            return Err(self.count_err("data_on_idle", &Proc::Conn(ERR_CODE_PROTOCOL)));
        }
        let (usable, reset_queued) = match self.streams.get(&id) {
            Some(st) => (
                state == Some(StState::Open) && !st.got_trailer_header && !st.reset_queued,
                st.reset_queued,
            ),
            None => (false, false),
        };
        if !usable {
            if !self.inflow.take(header.length) {
                return Err(self.count_err("data_flow", &Proc::stream(id, ERR_CODE_FLOW_CONTROL)));
            }
            self.send_window_update(None, header.length as usize);
            if reset_queued {
                return Ok(());
            }
            return Err(self.count_err("closed", &Proc::stream(id, ERR_CODE_STREAM_CLOSED)));
        }
        let (decl, seen) = {
            let st = &self.streams[&id];
            (st.decl_body_bytes, st.body_bytes)
        };
        if decl != -1 && seen + data.len() as i64 > decl {
            if !self.inflow.take(header.length) {
                return Err(self.count_err("data_flow", &Proc::stream(id, ERR_CODE_FLOW_CONTROL)));
            }
            self.send_window_update(None, header.length as usize);
            if let Some(b) = &self.streams[&id].body {
                b.close_with_error(H2Error::msg(format!(
                    "sender tried to send more than declared Content-Length of {decl} bytes"
                )));
            }
            return Err(self.count_err("send_too_much", &Proc::stream(id, ERR_CODE_PROTOCOL)));
        }
        if header.length > 0 {
            {
                let st = self.streams.get_mut(&id).expect("stream");
                if !flow::take_inflows(&mut self.inflow, &mut st.inflow, header.length) {
                    return Err(self.count_err(
                        "flow_on_data_length",
                        &Proc::stream(id, ERR_CODE_FLOW_CONTROL),
                    ));
                }
            }
            if !data.is_empty() {
                let st = self.streams.get_mut(&id).expect("stream");
                st.body_bytes += data.len() as i64;
                let wrote = match &st.body {
                    Some(b) => b.write(&data),
                    None => Err(H2Error::msg(
                        "internal error: should have a body in this state",
                    )),
                };
                if wrote.is_err() {
                    self.send_window_update(None, header.length as usize);
                    return Ok(());
                }
            }
            let pad = header.length as i32 - data.len() as i32;
            self.send_window_update(None, pad.max(0) as usize);
            self.send_window_update(Some(id), pad.max(0) as usize);
        }
        if header.has(FLAG_DATA_END_STREAM) {
            self.end_stream(id);
        }
        Ok(())
    }

    fn end_stream(&mut self, id: u32) {
        let Some(st) = self.streams.get_mut(&id) else {
            return;
        };
        if st.decl_body_bytes != -1 && st.decl_body_bytes != st.body_bytes {
            if let Some(b) = &st.body {
                b.close_with_error(H2Error::msg(format!(
                    "request declared a Content-Length of {} but only wrote {} bytes",
                    st.decl_body_bytes, st.body_bytes
                )));
            }
        } else if let Some(b) = &st.body {
            let trailer = st.trailer.clone();
            let req_trailer = st.req_trailer.clone();
            b.close_with_error_and_code(H2Error::Eof, move || {
                // copyTrailersToHandlerRequest
                if let (Some(t), Some(mut rt)) = (trailer, req_trailer.get()) {
                    for (k, vv) in t.0 {
                        if rt.0.contains_key(&k) {
                            rt.0.insert(k, vv);
                        }
                    }
                    req_trailer.set(Some(rt));
                }
            });
        }
        st.state = StState::HalfClosedRemote;
    }

    fn process_headers(&mut self, f: MetaHeadersFrame) -> Result<(), Proc> {
        let id = f.header.stream_id;
        if id % 2 != 1 {
            return Err(self.count_err("headers_even", &Proc::Conn(ERR_CODE_PROTOCOL)));
        }
        if let Some(st) = self.streams.get(&id) {
            if st.reset_queued {
                return Ok(());
            }
            if st.state == StState::HalfClosedRemote {
                return Err(self.count_err(
                    "headers_half_closed",
                    &Proc::stream(id, ERR_CODE_STREAM_CLOSED),
                ));
            }
            return self.process_trailer_headers(id, &f);
        }
        if id <= self.max_client_stream_id {
            return Err(self.count_err("stream_went_down", &Proc::Conn(ERR_CODE_PROTOCOL)));
        }
        self.max_client_stream_id = id;

        if self.has_timer(Timer::Idle) {
            self.cancel_timer(Timer::Idle);
        }

        if self.cur_client_streams + 1 > self.adv_max_streams {
            if self.unacked_settings == 0 {
                return Err(
                    self.count_err("over_max_streams", &Proc::stream(id, ERR_CODE_PROTOCOL))
                );
            }
            return Err(self.count_err(
                "over_max_streams_race",
                &Proc::stream(id, ERR_CODE_REFUSED_STREAM),
            ));
        }

        let initial_state = if f.stream_ended() {
            StState::HalfClosedRemote
        } else {
            StState::Open
        };

        let (mut urgency, mut incremental) = self.initial_priority();
        if self.sched.kind() == Kind::Rfc9218 && !self.has_intermediary {
            let (p, aware, inter) = f.rfc9218_priority(self.priority_aware);
            urgency = p.urgency();
            incremental = p.incremental();
            self.has_intermediary = inter;
            if aware {
                self.priority_aware = true;
            }
        }
        let shared = self.new_stream(id, 0, initial_state, urgency, incremental);

        if f.has_priority() && id == f.priority.stream_dep {
            return Err(self.count_err("priority", &Proc::stream(id, ERR_CODE_PROTOCOL)));
        }

        let parts = self.new_request_parts(&shared, &f)?;
        if let Some(st) = self.streams.get_mut(&id) {
            st.req_trailer = parts.trailer.clone();
            if !parts.trailer.is_nil() {
                st.trailer = Some(Header::new());
            }
            st.body = parts.body_pipe.clone();
            st.decl_body_bytes = parts.content_length;
        }

        let (kind, reason) = if f.truncated {
            (HandlerKind::HeaderListTooLong, String::new())
        } else if let Err(reason) = check_valid_http2_request_headers(&parts.header) {
            (HandlerKind::Bad400, reason)
        } else {
            (HandlerKind::Normal, String::new())
        };

        let rt = Duration::from_nanos(u64::try_from(self.srv.read_timeout.as_nanos()).unwrap_or(0));
        if !rt.is_zero() {
            let at = Instant::now() + rt;
            self.set_timer_at(Timer::StreamRead(id), at);
            if let Some(st) = self.streams.get_mut(&id) {
                st.read_deadline = Some(at);
            }
        }

        self.schedule_handler(id, parts, kind, reason, shared);
        Ok(())
    }

    fn process_trailer_headers(&mut self, id: u32, f: &MetaHeadersFrame) -> Result<(), Proc> {
        {
            let st = self.streams.get_mut(&id).expect("stream");
            if st.got_trailer_header {
                return Err(self.count_err("dup_trailers", &Proc::Conn(ERR_CODE_PROTOCOL)));
            }
            st.got_trailer_header = true;
        }
        if !f.stream_ended() {
            return Err(self.count_err("trailers_not_ended", &Proc::stream(id, ERR_CODE_PROTOCOL)));
        }
        if !f.pseudo_fields().is_empty() {
            return Err(self.count_err("trailers_pseudo", &Proc::stream(id, ERR_CODE_PROTOCOL)));
        }
        if f.truncated {
            return Err(self.count_err("trailers_too_large", &Proc::stream(id, ERR_CODE_PROTOCOL)));
        }
        let declared = self.streams[&id].trailer.is_some();
        if declared {
            for hf in f.regular_fields() {
                let Ok(name) = std::str::from_utf8(&hf.name) else {
                    return Err(
                        self.count_err("trailers_bogus", &Proc::stream(id, ERR_CODE_PROTOCOL))
                    );
                };
                let key = canonical_mime_header_key(name);
                if !valid_trailer_header(&key) {
                    return Err(
                        self.count_err("trailers_bogus", &Proc::stream(id, ERR_CODE_PROTOCOL))
                    );
                }
                let Ok(val) = String::from_utf8(hf.value.clone()) else {
                    return Err(
                        self.count_err("trailers_bogus", &Proc::stream(id, ERR_CODE_PROTOCOL))
                    );
                };
                if let Some(t) = self.streams.get_mut(&id).and_then(|s| s.trailer.as_mut()) {
                    t.0.entry(key).or_default().push(val);
                }
            }
        }
        self.end_stream(id);
        Ok(())
    }

    fn process_priority(&mut self, id: u32, p: PriorityParam) -> Result<(), Proc> {
        if id == p.stream_dep {
            return Err(self.count_err("priority", &Proc::stream(id, ERR_CODE_PROTOCOL)));
        }
        Ok(())
    }

    fn process_priority_update(&mut self, id: u32, priority: &[u8]) -> Result<(), Proc> {
        self.priority_aware = true;
        if self.sched.kind() != Kind::Rfc9218 {
            return Ok(());
        }
        let s = String::from_utf8_lossy(priority);
        let (p, ok) = parse_rfc9218_priority(&s, self.priority_aware);
        if !ok {
            return Err(self.count_err(
                "unparsable_priority_update",
                &Proc::stream(id, ERR_CODE_PROTOCOL),
            ));
        }
        self.sched.adjust_stream(id, p.urgency(), p.incremental());
        Ok(())
    }

    fn new_stream(
        &mut self,
        id: u32,
        _pusher_id: u32,
        state: StState,
        urgency: u8,
        incremental: u8,
    ) -> Arc<StreamShared> {
        let (ctx, cancel) = self.base_ctx.with_cancel();
        let shared = Arc::new(StreamShared {
            id,
            closed: Mutex::new(None),
            cv: Condvar::new(),
            ctx,
            cancel,
        });
        let mut st = Stream {
            id,
            state,
            shared: shared.clone(),
            body: None,
            body_bytes: 0,
            decl_body_bytes: -1,
            flow: Outflow::default(),
            inflow: Inflow::default(),
            reset_queued: false,
            got_trailer_header: false,
            wrote_headers: false,
            read_deadline: None,
            write_deadline: None,
            trailer: None,
            req_trailer: Trailer::new(None),
        };
        st.flow.add(self.initial_stream_send_window);
        st.inflow.init(self.initial_stream_recv_window);
        let wt =
            Duration::from_nanos(u64::try_from(self.srv.write_timeout.as_nanos()).unwrap_or(0));
        if !wt.is_zero() {
            let at = Instant::now() + wt;
            st.write_deadline = Some(at);
            self.timers.push((at, Timer::StreamWrite(id)));
        }
        let pushed = st.is_pushed();
        self.streams.insert(id, st);
        self.sched.open_stream(id, urgency, incremental);
        if pushed {
            self.cur_pushed_streams += 1;
        } else {
            self.cur_client_streams += 1;
        }
        if self.cur_open_streams() == 1 {
            self.set_conn_state(STATE_ACTIVE);
        }
        shared
    }

    /// Go's `newWriterAndRequest`.
    fn new_request_parts(
        &mut self,
        shared: &Arc<StreamShared>,
        f: &MetaHeadersFrame,
    ) -> Result<ReqParts, Proc> {
        let id = f.header.stream_id;
        let pv = |name: &str| String::from_utf8_lossy(f.pseudo_value(name)).into_owned();
        let method = pv("method");
        let scheme = pv("scheme");
        let mut authority = pv("authority");
        let path = pv("path");
        let protocol = pv("protocol");

        // Extended CONNECT is disabled (disableExtendedConnectProtocol).
        if !protocol.is_empty() {
            return Err(self.count_err("bad_connect", &Proc::stream(id, ERR_CODE_PROTOCOL)));
        }
        if method == "CONNECT" {
            if !path.is_empty() || !scheme.is_empty() || authority.is_empty() {
                return Err(self.count_err("bad_connect", &Proc::stream(id, ERR_CODE_PROTOCOL)));
            }
        } else if method.is_empty() || path.is_empty() || (scheme != "https" && scheme != "http") {
            return Err(self.count_err("bad_path_method", &Proc::stream(id, ERR_CODE_PROTOCOL)));
        }

        let mut header = Header::new();
        for hf in f.regular_fields() {
            let (Ok(name), Ok(val)) = (
                std::str::from_utf8(&hf.name),
                String::from_utf8(hf.value.clone()),
            ) else {
                return Err(self.count_err("bad_header_utf8", &Proc::stream(id, ERR_CODE_PROTOCOL)));
            };
            header.add(&canonical_mime_header_key(name), &val);
        }
        if authority.is_empty() {
            authority = header.get_str("Host").to_owned();
        }
        let mut parts =
            self.request_parts_no_body(shared, &method, &scheme, &authority, &path, &mut header)?;
        let body_open = !f.stream_ended();
        let clens = parts.header.0.get("Content-Length").cloned();
        if let Some(clens) = clens {
            parts.content_length = clens[0]
                .parse::<u64>()
                .ok()
                .filter(|v| *v < (1 << 63))
                .map_or(0, |v| v as i64);
            if !body_open && parts.content_length != 0 {
                return Err(self.count_err(
                    "bodyless_content_length",
                    &Proc::stream(id, ERR_CODE_PROTOCOL),
                ));
            }
            if clens.len() > 1 {
                for dup in &clens[1..] {
                    if &clens[0] != dup {
                        return Err(self.count_err(
                            "duplicate_content_length",
                            &Proc::stream(id, ERR_CODE_PROTOCOL),
                        ));
                    }
                }
                parts
                    .header
                    .0
                    .insert("Content-Length".into(), vec![clens[0].clone()]);
            }
        }
        if body_open {
            if !parts.header.0.contains_key("Content-Length") {
                parts.content_length = -1;
            }
            parts.body_pipe = Some(Arc::new(Pipe::with_buffer()));
        }
        Ok(parts)
    }

    /// Go's `newWriterAndRequestNoBody` (with `httpcommon.NewServerRequest`).
    fn request_parts_no_body(
        &mut self,
        shared: &Arc<StreamShared>,
        method: &str,
        scheme: &str,
        authority: &str,
        path: &str,
        header: &mut Header,
    ) -> Result<ReqParts, Proc> {
        let id = shared.id;
        let https = scheme == "https";
        // httpcommon.NewServerRequest
        let needs_continue = crate::net::http::header::values_contain_token(
            &header.values("Expect"),
            "100-continue",
        );
        if needs_continue {
            header.0.remove("Expect");
        }
        if let Some(cookies) = header.0.get("Cookie") {
            if cookies.len() > 1 {
                let joined = cookies.join("; ");
                header.0.insert("Cookie".into(), vec![joined]);
            }
        }
        let mut trailer: Option<Header> = None;
        for v in header.values("Trailer") {
            for key in v.split(',') {
                let key = canonical_mime_header_key(key.trim_matches(|c| c == ' ' || c == '\t'));
                match key.as_str() {
                    "Transfer-Encoding" | "Trailer" | "Content-Length" => {}
                    _ => {
                        trailer
                            .get_or_insert_with(Header::new)
                            .0
                            .insert(key, Vec::new());
                    }
                }
            }
        }
        header.0.remove("Trailer");

        if authority.contains('@') && (scheme == "http" || scheme == "https") {
            return Err(self.count_err(
                "userinfo_in_authority",
                &Proc::stream(id, ERR_CODE_PROTOCOL),
            ));
        }
        let (url, request_uri) = if method == "CONNECT" {
            (
                Url {
                    host: authority.to_owned(),
                    ..Url::default()
                },
                authority.to_owned(),
            )
        } else {
            if path.is_empty() || (!path.starts_with('/') && path != "*") {
                return Err(self.count_err("bad_path", &Proc::stream(id, ERR_CODE_PROTOCOL)));
            }
            match url::parse_request_uri(path) {
                Ok(u) => (u, path.to_owned()),
                Err(_) => {
                    return Err(self.count_err("bad_path", &Proc::stream(id, ERR_CODE_PROTOCOL)))
                }
            }
        };
        Ok(ReqParts {
            method: method.to_owned(),
            url,
            request_uri,
            header: header.clone(),
            host: authority.to_owned(),
            scheme_https: https,
            content_length: 0,
            trailer: Trailer::new(trailer),
            needs_continue,
            body_pipe: None,
        })
    }

    // ---------------------------------------------------------- handlers

    fn schedule_handler(
        &mut self,
        stream_id: u32,
        parts: ReqParts,
        kind: HandlerKind,
        reason: String,
        stream: Arc<StreamShared>,
    ) {
        let max_handlers = self.adv_max_streams;
        if self.cur_handlers < max_handlers {
            self.cur_handlers += 1;
            self.spawn_handler(stream, parts, kind, reason);
            return;
        }
        if self.unstarted_handlers.len() > (4 * self.adv_max_streams) as usize {
            self.go_away(ERR_CODE_ENHANCE_YOUR_CALM);
            return;
        }
        self.unstarted_handlers.push_back(Unstarted {
            stream_id,
            parts,
            kind,
            bad_reason: reason,
            stream,
        });
    }

    fn handler_done(&mut self) {
        self.cur_handlers = self.cur_handlers.saturating_sub(1);
        let max_handlers = self.adv_max_streams;
        while let Some(u) = self.unstarted_handlers.front() {
            if !self.streams.contains_key(&u.stream_id) {
                self.unstarted_handlers.pop_front();
                continue;
            }
            if self.cur_handlers >= max_handlers {
                break;
            }
            let u = self.unstarted_handlers.pop_front().expect("front");
            self.cur_handlers += 1;
            self.spawn_handler(u.stream, u.parts, u.kind, u.bad_reason);
        }
    }

    fn spawn_handler(
        &mut self,
        stream: Arc<StreamShared>,
        parts: ReqParts,
        kind: HandlerKind,
        reason: String,
    ) {
        let handle = self.handle.clone();
        let handler = self.handler.clone();
        let tls = self.tls_state.clone();
        let base_ctx = self.base_ctx.clone();
        let remote_addr = self.remote_addr.clone();
        let st_state_pushed = stream.id.is_multiple_of(2);
        std::thread::spawn(move || {
            run_handler(
                handle,
                handler,
                tls,
                base_ctx,
                remote_addr,
                stream,
                parts,
                kind,
                reason,
                st_state_pushed,
            );
        });
    }

    // ------------------------------------------------------ flow control

    fn send_window_update(&mut self, stream: Option<u32>, n: usize) {
        let (send, stream_id) = match stream {
            None => (self.inflow.add(n), 0),
            Some(id) => match self.streams.get_mut(&id) {
                Some(st) => (st.inflow.add(n), id),
                None => return,
            },
        };
        if send == 0 {
            return;
        }
        let wr = match stream {
            None => WriteReq::control(Write::WindowUpdate { n: send as u32 }),
            Some(_) => WriteReq::on_stream(Write::WindowUpdate { n: send as u32 }, stream_id),
        };
        self.write_frame(wr);
    }

    fn note_body_read(&mut self, id: u32, n: usize) {
        self.send_window_update(None, n);
        let open = matches!(
            self.streams.get(&id).map(|s| s.state),
            Some(StState::Open) | Some(StState::HalfClosedLocal)
        );
        if open {
            self.send_window_update(Some(id), n);
        }
    }

    // -------------------------------------------------------------- push

    fn start_push(&mut self, msg: Arc<PushReq>) {
        let parent_state = self.streams.get(&msg.parent).map(|s| s.state);
        if parent_state != Some(StState::Open) && parent_state != Some(StState::HalfClosedRemote) {
            if let Some(d) = msg.done.lock().unwrap_or_else(|e| e.into_inner()).take() {
                let _ = d.try_send(Err(err_stream_closed()));
            }
            return;
        }
        if !self.push_enabled {
            if let Some(d) = msg.done.lock().unwrap_or_else(|e| e.into_inner()).take() {
                let _ = d.try_send(Err(H2Error::msg(ERR_NOT_SUPPORTED.error_string)));
            }
            return;
        }
        let done = msg.done.lock().unwrap_or_else(|e| e.into_inner()).take();
        let wr = WriteReq {
            write: Write::PushPromise(msg.clone()),
            stream: Some(msg.parent),
            rst_id: 0,
            done,
        };
        self.write_frame(wr);
    }
}

fn rand_ping_data() -> [u8; 8] {
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

fn is_closed_conn_error(e: &io::Error) -> bool {
    let s = e.to_string();
    s.contains("use of closed network connection") || s.contains("closed")
}

fn http_code_string(code: u16) -> String {
    code.to_string()
}

fn valid_trailer_header(name: &str) -> bool {
    if name.starts_with("Grpc-") {
        return false;
    }
    !matches!(
        name,
        "Accept-Encoding"
            | "Authorization"
            | "Cache-Control"
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

/// `checkValidHTTP2RequestHeaders`.
fn check_valid_http2_request_headers(h: &Header) -> Result<(), String> {
    for k in [
        "Connection",
        "Keep-Alive",
        "Proxy-Connection",
        "Transfer-Encoding",
        "Upgrade",
    ] {
        if h.0.contains_key(k) {
            return Err(format!(
                "request header {} is not valid in HTTP/2",
                crate::strconv::quote(k)
            ));
        }
    }
    if let Some(te) = h.0.get("Te") {
        if !te.is_empty() && (te.len() > 1 || (te[0] != "trailers" && !te[0].is_empty())) {
            return Err("request header \"TE\" may only be \"trailers\" in HTTP/2".into());
        }
    }
    Ok(())
}

/// Go's `encodeHeaders`.
fn encode_headers(enc: &mut Encoder, out: &mut Vec<u8>, h: &Header, keys: Option<&[String]>) {
    let all: Vec<&String>;
    let key_list: Vec<&String> = match keys {
        Some(k) => k.iter().collect(),
        None => {
            all = h.0.keys().collect();
            all
        }
    };
    for k in key_list {
        let Some(vv) = h.0.get(k) else {
            continue;
        };
        if !k.bytes().all(|b| (b' '..=b'~').contains(&b)) {
            continue;
        }
        let lk = k.to_ascii_lowercase();
        if !valid_wire_header_field_name(lk.as_bytes()) {
            continue;
        }
        let is_te = lk == "transfer-encoding";
        for v in vv {
            if !valid_header_field_value(v.as_bytes()) {
                continue;
            }
            if is_te && v != "trailers" {
                continue;
            }
            enc.write_field(&HeaderField::new(&lk, v), out);
        }
    }
}

/// Go's `splitHeaderBlock`.
/// The callback `split_header_block` hands each header fragment to.
type FragmentFn<'a> =
    dyn FnMut(&mut FrameWriter<Vec<u8>>, &[u8], bool, bool) -> Result<(), FrameError> + 'a;

fn split_header_block(
    fw: &mut FrameWriter<Vec<u8>>,
    mut block: &[u8],
    f: &mut FragmentFn<'_>,
) -> Result<(), FrameError> {
    const MAX_FRAME: usize = 16384;
    let mut first = true;
    while !block.is_empty() {
        let n = block.len().min(MAX_FRAME);
        let frag = &block[..n];
        block = &block[n..];
        f(fw, frag, first, block.is_empty())?;
        first = false;
    }
    Ok(())
}

// ------------------------------------------------- process-frame outcomes

/// The ways frame processing fails (Go's error switch in `processFrameFromReader`).
#[derive(Clone, Debug)]
enum Proc {
    Conn(ErrCode),
    Stream {
        id: u32,
        code: ErrCode,
        cause: Option<H2Error>,
    },
    GoAwayFlow,
    Other(String),
}
impl Proc {
    fn stream(id: u32, code: ErrCode) -> Self {
        Proc::Stream {
            id,
            code,
            cause: None,
        }
    }
}

// ---------------------------------------------------- running a handler

#[allow(clippy::too_many_arguments)]
fn run_handler(
    handle: Arc<ConnHandle>,
    handler: Arc<dyn Handler>,
    tls: Option<Arc<ConnectionState>>,
    base_ctx: Context,
    remote_addr: String,
    stream: Arc<StreamShared>,
    parts: ReqParts,
    kind: HandlerKind,
    reason: String,
    pushed: bool,
) {
    let ctx = stream.ctx.clone();
    let _ = base_ctx;

    let mut req = Request::default();
    req.set_context(ctx.clone());
    req.method = parts.method.clone();
    req.url = parts.url.clone();
    req.proto = "HTTP/2.0".into();
    req.proto_major = 2;
    req.proto_minor = 0;
    req.header = parts.header.clone();
    req.request_uri = parts.request_uri.clone();
    req.host = parts.host.clone();
    req.remote_addr = remote_addr;
    req.content_length = parts.content_length;
    req.trailer = parts.trailer.clone();
    if parts.scheme_https {
        req.tls = tls;
    }
    req.body = Some(Body::new(H2RequestBody {
        handle: handle.clone(),
        stream: stream.clone(),
        pipe: parts.body_pipe.clone(),
        saw_eof: false,
        needs_continue: parts.needs_continue,
        read_deadline: None,
    }));

    let mut rw = H2ResponseWriter {
        handle: handle.clone(),
        stream: stream.clone(),
        req_method: parts.method.clone(),
        req_host: parts.host.clone(),
        req_https: parts.scheme_https,
        pushed,
        handler_header: Header::new(),
        snap_header: None,
        trailers: Vec::new(),
        status: 0,
        wrote_header: false,
        sent_header: false,
        handler_done: false,
        sent_content_len: 0,
        wrote_bytes: 0,
        bw: Vec::with_capacity(HANDLER_CHUNK_WRITE_SIZE),
        close_notifier_started: None,
    };

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match kind {
        HandlerKind::Normal => handler.serve_http(&mut rw, &mut req),
        HandlerKind::HeaderListTooLong => {
            rw.write_header(431);
            let _ =
                rw.write_string("<h1>HTTP Error 431</h1><p>Request Header Field(s) Too Large</p>");
        }
        HandlerKind::Bad400 => {
            let h = rw.header();
            h.del("Content-Length");
            h.set("Content-Type", "text/plain; charset=utf-8");
            h.set("X-Content-Type-Options", "nosniff");
            rw.write_header(400);
            let _ = rw.write_string(&format!("{reason}\n"));
        }
    }));
    (stream.cancel)();
    match result {
        Ok(()) => {
            rw.handler_done();
        }
        Err(payload) => {
            let _ = handle.send(Msg::Write(WriteReq::on_stream(
                Write::HandlerPanicRst,
                stream.id,
            )));
            let aborted = payload
                .downcast_ref::<crate::net::http::header::ErrorString>()
                .is_some_and(|e| *e == crate::net::http::header::ERR_ABORT_HANDLER);
            if !aborted {
                let msg = payload
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_owned())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "panic".to_owned());
                handle.srv.logf(format_args!(
                    "http2: panic serving {}: {}",
                    handle.remote_addr, msg
                ));
            }
        }
    }
    let _ = handle.send(Msg::HandlerDone);
}

/// The request body of a stream (Go's `requestBody`).
struct H2RequestBody {
    handle: Arc<ConnHandle>,
    stream: Arc<StreamShared>,
    pipe: Option<Arc<Pipe>>,
    saw_eof: bool,
    needs_continue: bool,
    read_deadline: Option<Duration>,
}

impl Read for H2RequestBody {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        if self.needs_continue {
            self.needs_continue = false;
            let _ = self.handle.send(Msg::Write(WriteReq::on_stream(
                Write::Continue100,
                self.stream.id,
            )));
        }
        let Some(pipe) = &self.pipe else {
            return Ok(0);
        };
        if self.saw_eof {
            return Ok(0);
        }
        let r = pipe.read_deadline(p, self.read_deadline.map(Into::into));
        match r {
            Ok(n) => {
                if n > 0 {
                    let _ = self.handle.send(Msg::BodyRead {
                        stream: self.stream.id,
                        n,
                    });
                }
                Ok(n)
            }
            Err(H2Error::Eof) => {
                self.saw_eof = true;
                Ok(0)
            }
            Err(e) => Err(e.into_io()),
        }
    }
}

impl ReadCloser for H2RequestBody {
    fn close(&mut self) -> io::Result<()> {
        if let Some(p) = &self.pipe {
            p.break_with_error(err_closed_body());
        }
        Ok(())
    }
}

// ------------------------------------------------------ response writer

/// The `ResponseWriter` of an HTTP/2 stream (Go's `responseWriter`).
pub(crate) struct H2ResponseWriter {
    handle: Arc<ConnHandle>,
    stream: Arc<StreamShared>,
    req_method: String,
    req_host: String,
    req_https: bool,
    pushed: bool,
    handler_header: Header,
    snap_header: Option<Header>,
    trailers: Vec<String>,
    status: u16,
    wrote_header: bool,
    sent_header: bool,
    handler_done: bool,
    sent_content_len: i64,
    wrote_bytes: i64,
    bw: Vec<u8>,
    close_notifier_started: Option<()>,
}

impl H2ResponseWriter {
    fn write_data_from_handler(&self, data: Vec<u8>, end_stream: bool) -> Result<(), H2Error> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.handle.send(Msg::Write(WriteReq {
            write: Write::Data { data, end_stream },
            stream: Some(self.stream.id),
            rst_id: 0,
            done: Some(tx),
        }))?;
        match rx.recv() {
            Ok(r) => r,
            Err(_) => {
                if self.stream.close_err().is_some() {
                    Err(err_stream_closed())
                } else {
                    Err(err_client_disconnected())
                }
            }
        }
    }

    fn write_headers(&self, h: ResHeaders) -> Result<(), H2Error> {
        let wait = h.h.is_some();
        let (tx, rx) = mpsc::sync_channel(1);
        self.handle.send(Msg::Write(WriteReq {
            write: Write::ResHeaders(h),
            stream: Some(self.stream.id),
            rst_id: 0,
            done: if wait { Some(tx) } else { None },
        }))?;
        if !wait {
            return Ok(());
        }
        match rx.recv() {
            Ok(r) => r,
            Err(_) => {
                if self.stream.close_err().is_some() {
                    Err(err_stream_closed())
                } else {
                    Err(err_client_disconnected())
                }
            }
        }
    }

    fn has_trailers(&self) -> bool {
        !self.trailers.is_empty()
    }

    fn has_nonempty_trailers(&self) -> bool {
        self.trailers
            .iter()
            .any(|t| self.handler_header.0.contains_key(t))
    }

    fn declare_trailer(&mut self, k: &str) {
        let k = canonical_mime_header_key(k);
        if !valid_trailer_header(&k) {
            self.handle.srv.logf(format_args!(
                "ignoring invalid trailer {}",
                crate::strconv::quote(&k)
            ));
            return;
        }
        if !self.trailers.contains(&k) {
            self.trailers.push(k);
        }
    }

    fn promote_undeclared_trailers(&mut self) {
        let items: Vec<(String, Vec<String>)> = self
            .handler_header
            .0
            .iter()
            .filter(|(k, _)| k.starts_with(TRAILER_PREFIX))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (k, vv) in items {
            let trailer_key = k[TRAILER_PREFIX.len()..].to_owned();
            self.declare_trailer(&trailer_key);
            self.handler_header
                .0
                .insert(canonical_mime_header_key(&trailer_key), vv);
        }
        if self.trailers.len() > 1 {
            self.trailers.sort();
        }
    }

    /// Go's `responseWriterState.writeChunk`.
    fn write_chunk(&mut self, p: &[u8]) -> Result<usize, H2Error> {
        if !self.wrote_header {
            self.write_header_inner(200);
        }
        if self.handler_done {
            self.promote_undeclared_trailers();
        }
        let is_head = self.req_method == "HEAD";
        if !self.sent_header {
            self.sent_header = true;
            let mut snap = self.snap_header.take().unwrap_or_default();
            let mut ctype = String::new();
            let mut clen = snap.get_str("Content-Length").to_owned();
            if !clen.is_empty() {
                snap.del("Content-Length");
                match clen.parse::<u64>() {
                    Ok(cl) if cl < (1 << 63) => self.sent_content_len = cl as i64,
                    _ => clen.clear(),
                }
            }
            let has_content_length = snap.0.contains_key("Content-Length");
            if !has_content_length
                && clen.is_empty()
                && self.handler_done
                && body_allowed_for_status(self.status)
                && (!p.is_empty() || !is_head)
            {
                clen = p.len().to_string();
            }
            let has_content_type = snap.0.contains_key("Content-Type");
            let has_ce = !snap.get_str("Content-Encoding").is_empty();
            if !has_ce && !has_content_type && body_allowed_for_status(self.status) && !p.is_empty()
            {
                ctype = detect_content_type(p).to_owned();
            }
            let mut date = String::new();
            if !snap.0.contains_key("Date") {
                date = time::now().utc().format(TIME_FORMAT);
            }
            let trailer_values = snap.values("Trailer");
            for v in &trailer_values {
                let mut elems = Vec::new();
                foreach_header_element(v, |e| elems.push(e.to_owned()));
                for e in elems {
                    self.declare_trailer(&e);
                }
            }
            if snap.0.contains_key("Connection") {
                let v = snap.get_str("Connection").to_owned();
                snap.0.remove("Connection");
                if v == "close" {
                    let _ = self.handle.send(Msg::Graceful);
                }
            }
            let end_stream = (self.handler_done && !self.has_trailers() && p.is_empty()) || is_head;
            self.write_headers(ResHeaders {
                http_res_code: self.status,
                h: if snap.0.is_empty() { None } else { Some(snap) },
                trailers: None,
                end_stream,
                date,
                content_type: ctype,
                content_length: clen,
            })?;
            if end_stream {
                return Ok(0);
            }
        }
        if is_head {
            return Ok(p.len());
        }
        if p.is_empty() && !self.handler_done {
            return Ok(0);
        }
        let has_nonempty_trailers = self.has_nonempty_trailers();
        let end_stream = self.handler_done && !has_nonempty_trailers;
        if !p.is_empty() || end_stream {
            self.write_data_from_handler(p.to_vec(), end_stream)?;
        }
        if self.handler_done && has_nonempty_trailers {
            self.write_headers(ResHeaders {
                http_res_code: 0,
                h: Some(self.handler_header.clone()),
                trailers: Some(self.trailers.clone()),
                end_stream: true,
                date: String::new(),
                content_type: String::new(),
                content_length: String::new(),
            })?;
        }
        Ok(p.len())
    }

    fn chunk_write(&mut self, p: &[u8]) -> io::Result<usize> {
        match self.write_chunk(p) {
            Ok(n) => Ok(n),
            Err(e) => {
                if e.is_msg("http2: stream closed") {
                    if let Some(c) = self.stream.close_err() {
                        return Err(c.into_io());
                    }
                }
                Err(e.into_io())
            }
        }
    }

    fn bw_flush(&mut self) -> io::Result<()> {
        if self.bw.is_empty() {
            return Ok(());
        }
        let buf = std::mem::take(&mut self.bw);
        let r = self.chunk_write(&buf);
        self.bw = buf;
        self.bw.clear();
        r.map(|_| ())
    }

    /// `bufio.Writer.Write` over the chunk writer.
    fn bw_write(&mut self, mut p: &[u8]) -> io::Result<usize> {
        let total = p.len();
        while p.len() > HANDLER_CHUNK_WRITE_SIZE - self.bw.len() {
            if self.bw.is_empty() {
                // Large write, empty buffer: write directly.
                let n = self.chunk_write(p)?;
                p = &p[n.min(p.len())..];
                if n == 0 {
                    break;
                }
                continue;
            }
            let room = HANDLER_CHUNK_WRITE_SIZE - self.bw.len();
            self.bw.extend_from_slice(&p[..room]);
            p = &p[room..];
            self.bw_flush()?;
        }
        self.bw.extend_from_slice(p);
        Ok(total)
    }

    fn write_header_inner(&mut self, code: u16) {
        if self.wrote_header {
            return;
        }
        assert!(
            (100..=999).contains(&code),
            "invalid WriteHeader code {code}"
        );
        if (100..=199).contains(&code) {
            let mut h = self.handler_header.clone();
            if h.0.contains_key("Content-Length") || h.0.contains_key("Transfer-Encoding") {
                h.del("Content-Length");
                h.del("Transfer-Encoding");
            }
            let _ = self.write_headers(ResHeaders {
                http_res_code: code,
                h: if h.0.is_empty() { None } else { Some(h) },
                trailers: None,
                end_stream: self.handler_done && !self.has_trailers(),
                date: String::new(),
                content_type: String::new(),
                content_length: String::new(),
            });
            return;
        }
        self.wrote_header = true;
        self.status = code;
        if !self.handler_header.0.is_empty() {
            self.snap_header = Some(self.handler_header.clone());
        }
    }

    fn write_inner(&mut self, data: &[u8]) -> io::Result<usize> {
        if !self.wrote_header {
            self.write_header_inner(200);
        }
        if !body_allowed_for_status(self.status) {
            return Err(io::Error::other(ERR_BODY_NOT_ALLOWED));
        }
        self.wrote_bytes += data.len() as i64;
        if self.sent_content_len != 0 && self.wrote_bytes > self.sent_content_len {
            return Err(io::Error::other(H2Error::msg(
                "http2: handler wrote more than declared Content-Length",
            )));
        }
        self.bw_write(data)
    }

    fn handler_done(&mut self) {
        self.handler_done = true;
        let _ = self.flush_error_inner();
    }

    fn flush_error_inner(&mut self) -> io::Result<()> {
        if !self.bw.is_empty() {
            return self.bw_flush();
        }
        self.chunk_write(&[])?;
        if let Some(e) = self.stream.close_err() {
            return Err(e.into_io());
        }
        Ok(())
    }
}

impl std::io::Write for H2ResponseWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.write_inner(data)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl ResponseWriter for H2ResponseWriter {
    fn header(&mut self) -> &mut Header {
        &mut self.handler_header
    }
    fn write_string(&mut self, s: &str) -> io::Result<usize> {
        self.write_inner(s.as_bytes())
    }
    fn write_header(&mut self, status_code: u16) {
        self.write_header_inner(status_code);
    }
    fn flusher(&mut self) -> Option<&mut dyn Flusher> {
        Some(self)
    }
    fn conn_control(&mut self) -> Option<&mut dyn ConnControl> {
        Some(self)
    }
    fn pusher(&mut self) -> Option<&mut dyn Pusher> {
        Some(self)
    }
    fn close_notifier(&mut self) -> Option<&mut dyn CloseNotifier> {
        Some(self)
    }
}

impl Flusher for H2ResponseWriter {
    fn flush(&mut self) {
        let _ = self.flush_error_inner();
    }
    fn flush_error(&mut self) -> Result<(), BoxError> {
        self.flush_error_inner()
            .map_err(|e| Box::new(e) as BoxError)
    }
}

impl CloseNotifier for H2ResponseWriter {
    fn close_notify(&mut self) -> mpsc::Receiver<bool> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.close_notifier_started = Some(());
        let stream = self.stream.clone();
        std::thread::spawn(move || {
            stream.wait_closed();
            let _ = tx.send(true);
        });
        // The trait's receiver type is std's unbounded Receiver; bridge it.
        let (utx, urx) = mpsc::channel();
        std::thread::spawn(move || {
            if let Ok(v) = rx.recv() {
                let _ = utx.send(v);
            }
        });
        urx
    }
}

impl ConnControl for H2ResponseWriter {
    fn set_read_deadline(&mut self, deadline: &Time) -> Result<(), BoxError> {
        self.set_deadline(deadline, true)
    }
    fn set_write_deadline(&mut self, deadline: &Time) -> Result<(), BoxError> {
        self.set_deadline(deadline, false)
    }
    fn enable_full_duplex(&mut self) -> Result<(), BoxError> {
        Ok(())
    }
}

impl H2ResponseWriter {
    fn set_deadline(&mut self, deadline: &Time, read: bool) -> Result<(), BoxError> {
        let id = self.stream.id;
        let now = time::now();
        let instant = if deadline.is_zero() {
            None
        } else {
            let left = deadline.sub(&now).as_nanos();
            if left < 0 {
                // Already passed: fire immediately.
                let _ = self
                    .handle
                    .send(Msg::Func(Box::new(move |sc: &mut ServerConn| {
                        if read {
                            if let Some(st) = sc.streams.get(&id) {
                                if let Some(b) = &st.body {
                                    b.close_with_error(H2Error::DeadlineExceeded);
                                }
                            }
                        } else if sc.streams.contains_key(&id) {
                            sc.reset_stream(id, ERR_CODE_INTERNAL, Some(H2Error::DeadlineExceeded));
                        }
                    })));
                return Ok(());
            }
            Some(Instant::now() + Duration::from_nanos(left as u64))
        };
        let _ = self
            .handle
            .send(Msg::Func(Box::new(move |sc: &mut ServerConn| {
                let t = if read {
                    Timer::StreamRead(id)
                } else {
                    Timer::StreamWrite(id)
                };
                match instant {
                    None => sc.cancel_timer(t),
                    Some(at) => sc.set_timer_at(t, at),
                }
            })));
        Ok(())
    }
}

impl Pusher for H2ResponseWriter {
    fn push(&mut self, target: &str, opts: Option<&PushOptions>) -> Result<(), BoxError> {
        if self.pushed {
            return Err(ERR_RECURSIVE_PUSH.into());
        }
        let mut method = opts.map(|o| o.method.clone()).unwrap_or_default();
        let header = opts.map(|o| o.header.clone()).unwrap_or_default();
        if method.is_empty() {
            method = "GET".into();
        }
        let want_scheme = if self.req_https { "https" } else { "http" };
        let mut u = url::parse(target).map_err(|e| Box::new(e) as BoxError)?;
        if u.scheme.is_empty() {
            if !target.starts_with('/') {
                return Err(format!(
                    "target must be an absolute URL or an absolute path: {}",
                    crate::strconv::quote(target)
                )
                .into());
            }
            u.scheme = want_scheme.to_owned();
            u.host = self.req_host.clone();
        } else {
            if u.scheme != want_scheme {
                return Err(format!(
                    "cannot push URL with scheme {} from request with scheme {}",
                    crate::strconv::quote(&u.scheme),
                    crate::strconv::quote(want_scheme)
                )
                .into());
            }
            if u.host.is_empty() {
                return Err("URL must have a host".into());
            }
        }
        for k in header.0.keys() {
            if k.starts_with(':') {
                return Err(format!(
                    "promised request headers cannot include pseudo header {}",
                    crate::strconv::quote(k)
                )
                .into());
            }
            let lk = k.to_ascii_lowercase();
            if matches!(
                lk.as_str(),
                "content-length" | "content-encoding" | "trailer" | "te" | "expect" | "host"
            ) {
                return Err(format!(
                    "promised request headers cannot include {}",
                    crate::strconv::quote(k)
                )
                .into());
            }
        }
        check_valid_http2_request_headers(&header)
            .map_err(|e| Box::new(H2Error::msg(e)) as BoxError)?;
        if method != "GET" && method != "HEAD" {
            return Err(format!(
                "method {} must be GET or HEAD",
                crate::strconv::quote(&method)
            )
            .into());
        }
        let (tx, rx) = mpsc::sync_channel(1);
        let msg = Arc::new(PushReq {
            parent: self.stream.id,
            method,
            url: u,
            header,
            done: Mutex::new(Some(tx)),
            promised_id: Mutex::new(0),
        });
        self.handle
            .send(Msg::StartPush(msg))
            .map_err(|e| Box::new(e) as BoxError)?;
        match rx.recv() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => {
                if e.is_msg("feature not supported") {
                    Err(Box::new(ERR_NOT_SUPPORTED))
                } else {
                    Err(Box::new(e))
                }
            }
            Err(_) => {
                if self.stream.close_err().is_some() {
                    Err(Box::new(err_stream_closed()))
                } else {
                    Err(Box::new(err_client_disconnected()))
                }
            }
        }
    }
}

// Silence unused-import warnings for items used only in some configurations.
#[allow(dead_code)]
fn _unused(_: AddrRef) {}
