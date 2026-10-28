//! Go's `net/http/httptest` over the Go-shaped handler model:
//! [`ResponseRecorder`] implements `http::ResponseWriter`, [`request`]
//! builds server requests with a context and `RemoteAddr`, and [`Server`]
//! wraps a `http::server::Server` (its `config`) with connection tracking.
//!
//! Go's panics on invalid arguments or misuse (`NewRequest`, `WriteHeader`
//! codes, starting twice) become `Result` errors. `StartTLS` and
//! `NewTLSServer` need a TLS backend; see `rust_stdlib_tls::httptest`.
use crate::context::Context;
use crate::net::http::{
    client::Client,
    detect_content_type,
    handler::{Flusher, Handler, ResponseWriter},
    header::{valid_header_field_name, BoxError, Header, ERR_BODY_NOT_ALLOWED},
    request::{read_request, Request, RequestBody},
    response::Response,
    server::{
        ConnState, Server as HttpServer, STATE_ACTIVE, STATE_CLOSED, STATE_HIJACKED, STATE_IDLE,
        STATE_NEW,
    },
    status_text, Body, BufioReader, NoBody, Transport, TRAILER_PREFIX,
};
use crate::net::textproto::{canonical_mime_header_key, trim_string};
use crate::net::{self, Conn, Listener};
use std::{
    collections::HashMap,
    io::{self, Cursor},
    sync::{Arc, Mutex},
    thread,
};

/// Go's `httptest.DefaultRemoteAddr`.
pub const DEFAULT_REMOTE_ADDR: &str = "1.2.3.4";

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------- NewRequest

/// Go's `httptest.NewRequest`.
pub fn request(method: &str, target: &str, body: Option<RequestBody>) -> Result<Request, BoxError> {
    request_with_context(&Context::background(), method, target, body)
}

/// Go's `httptest.NewRequestWithContext`: a request as a handler receives it.
/// `target` is a path or an absolute URL. An empty method means GET.
pub fn request_with_context(
    ctx: &Context,
    method: &str,
    target: &str,
    body: Option<RequestBody>,
) -> Result<Request, BoxError> {
    let method = if method.is_empty() { "GET" } else { method };
    let raw = format!("{method} {target} HTTP/1.0\r\n\r\n");
    let mut req = read_request(&BufioReader::new(Cursor::new(raw.into_bytes())))
        .map_err(|e| -> BoxError { format!("invalid NewRequest arguments; {e}").into() })?;
    req = req.with_context(ctx);
    // HTTP/1.0 was used above to avoid needing a Host field.
    req.proto = "HTTP/1.1".into();
    req.proto_minor = 1;
    req.close = false;
    if let Some(body) = body {
        match body {
            RequestBody::Bytes(b) => {
                req.content_length = b.len() as i64;
                req.body = Some(if b.is_empty() {
                    Body::from(NoBody)
                } else {
                    Body::from_bytes(b)
                });
            }
            RequestBody::Reader(r) => {
                req.content_length = -1;
                req.body = Some(Body::from_reader(r));
            }
            RequestBody::ReadCloser(b) => {
                req.content_length = if b.is_no_body() { 0 } else { -1 };
                req.body = Some(b);
            }
        }
    } else {
        req.body = Some(Body::from(NoBody));
    }
    // The remote address Go assigns.
    req.remote_addr = "192.0.2.1:1234".into();
    if req.host.is_empty() {
        req.host = "example.com".into();
    }
    if target.starts_with("https://") {
        req.tls = Some(Arc::new(crate::net::http::ConnectionState {
            version: 0x0303,
            handshake_complete: true,
            ..Default::default()
        }));
    }
    Ok(req)
}

// ------------------------------------------------------------ ResponseRecorder

fn body_allowed_for_status(status: u16) -> bool {
    !((100..=199).contains(&status) || status == 204 || status == 304)
}

/// Go's `httptest.ResponseRecorder`.
#[derive(Clone, Debug)]
pub struct ResponseRecorder {
    /// The status code from `write_header` (200 by default).
    pub code: u16,
    /// The headers the handler edits through `header()`.
    pub header_map: Header,
    /// The bytes written; `None` records nothing, like a nil `Body`.
    pub body: Option<Vec<u8>>,
    /// Whether `flush` was called.
    pub flushed: bool,
    result: Option<Response>,
    snap_header: Option<Header>,
    wrote_header: bool,
}

impl Default for ResponseRecorder {
    fn default() -> Self {
        Self::new()
    }
}

impl ResponseRecorder {
    /// Go's `NewRecorder`.
    pub fn new() -> Self {
        Self {
            code: 200,
            header_map: Header::new(),
            body: Some(Vec::new()),
            flushed: false,
            result: None,
            snap_header: None,
            wrote_header: false,
        }
    }

    fn write_header_sniff(&mut self, b: Option<&[u8]>, s: &str) {
        if self.wrote_header {
            return;
        }
        let has_type = self.header_map.0.contains_key("Content-Type");
        let has_te = !self.header_map.get_str("Transfer-Encoding").is_empty();
        if !has_type && !has_te {
            let bytes = match b {
                Some(b) => b,
                None => &s.as_bytes()[..s.len().min(512)],
            };
            let ct = detect_content_type(bytes);
            self.header_map.set("Content-Type", ct);
        }
        self.write_header_impl(200);
    }

    /// Go's `WriteHeader` as a `Result`: Go panics for codes outside 100..=999
    /// (as [`ResponseWriter::write_header`] does here), this returns the error.
    pub fn write_header_checked(&mut self, code: u16) -> Result<(), BoxError> {
        if self.wrote_header {
            return Ok(());
        }
        if !(100..=999).contains(&code) {
            return Err(format!("invalid WriteHeader code {code}").into());
        }
        self.write_header_impl(code);
        Ok(())
    }
    fn write_header_impl(&mut self, code: u16) {
        if self.wrote_header {
            return;
        }
        self.code = code;
        self.wrote_header = true;
        self.snap_header = Some(self.header_map.clone());
    }

    /// Go's `WriteString`.
    pub fn write_string_recorded(&mut self, s: &str) -> io::Result<usize> {
        self.write_header_sniff(None, s);
        if let Some(b) = &mut self.body {
            b.extend_from_slice(s.as_bytes());
        }
        if !body_allowed_for_status(self.code) {
            return Err(crate::net::http::header::io_error(ERR_BODY_NOT_ALLOWED));
        }
        Ok(s.len())
    }

    /// Go's `Result`: the response as of the first call.
    pub fn result(&mut self) -> Response {
        if let Some(r) = &self.result {
            return r.clone();
        }
        let snap = self
            .snap_header
            .get_or_insert_with(|| self.header_map.clone())
            .clone();
        let mut res = Response {
            proto: "HTTP/1.1".into(),
            proto_major: 1,
            proto_minor: 1,
            status_code: self.code,
            header: snap.clone(),
            ..Response::default()
        };
        if res.status_code == 0 {
            res.status_code = 200;
        }
        res.status = format!("{:03} {}", res.status_code, status_text(res.status_code));
        res.body = Some(match &self.body {
            Some(b) => Body::from_bytes(b.clone()),
            None => Body::from(NoBody),
        });
        res.content_length = parse_content_length(res.header.get_str("Content-Length"));
        let mut trailer: Option<Header> = None;
        if let Some(trailers) = snap.0.get("Trailer") {
            let t = trailer.get_or_insert_with(Header::new);
            for k in trailers {
                for k in k.split(',') {
                    let k = canonical_mime_header_key(trim_string(k));
                    if !valid_trailer_header(&k) {
                        continue;
                    }
                    if let Some(vv) = self.header_map.0.get(&k) {
                        t.0.insert(k, vv.clone());
                    }
                }
            }
        }
        for (k, vv) in &self.header_map.0 {
            let Some(stripped) = k.strip_prefix(TRAILER_PREFIX) else {
                continue;
            };
            let t = trailer.get_or_insert_with(Header::new);
            for v in vv {
                t.add(stripped, v);
            }
        }
        res.trailer.set(trailer);
        self.result = Some(res.clone());
        res
    }
}

fn parse_content_length(cl: &str) -> i64 {
    let cl = trim_string(cl);
    if cl.is_empty() || !cl.bytes().all(|b| b.is_ascii_digit()) {
        return -1;
    }
    cl.parse::<u64>()
        .ok()
        .filter(|n| *n < 1 << 63)
        .map_or(-1, |n| n as i64)
}

/// `httpguts.ValidTrailerHeader`.
fn valid_trailer_header(name: &str) -> bool {
    let name = canonical_mime_header_key(name);
    if name.starts_with("If-") {
        return false;
    }
    !matches!(
        name.as_str(),
        "Accept-Encoding"
            | "Authorization"
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
    ) && valid_header_field_name(&name)
}

impl std::io::Write for ResponseRecorder {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_header_sniff(Some(buf), "");
        if let Some(b) = &mut self.body {
            b.extend_from_slice(buf);
        }
        if !body_allowed_for_status(self.code) {
            return Err(crate::net::http::header::io_error(ERR_BODY_NOT_ALLOWED));
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl ResponseWriter for ResponseRecorder {
    fn header(&mut self) -> &mut Header {
        &mut self.header_map
    }
    fn write_string(&mut self, s: &str) -> io::Result<usize> {
        self.write_string_recorded(s)
    }
    fn write_header(&mut self, code: u16) {
        // Like Go, an invalid code (outside 100..=999) is a programming
        // error and panics; `write_header_checked` returns it as an error.
        if let Err(e) = self.write_header_checked(code) {
            panic!("{e}");
        }
    }
    fn flusher(&mut self) -> Option<&mut dyn Flusher> {
        Some(self)
    }
}
impl Flusher for ResponseRecorder {
    fn flush(&mut self) {
        if !self.wrote_header {
            self.write_header_impl(200);
        }
        self.flushed = true;
    }
}

// -------------------------------------------------------------------- Server

#[derive(Default)]
struct Tracking {
    closed: bool,
    conns: HashMap<String, (Arc<dyn Conn>, ConnState)>,
    active: usize,
}

/// Go's `httptest.Server`: a loopback test server. Every field is public so
/// struct-update syntax works (`Server { enable_http2: true, ..Server::unstarted(h)? }`
/// or `..Default::default()`, which has no listener or handler).
#[derive(Default)]
pub struct Server {
    /// The base URL (`http://host:port`), set by `start`.
    pub url: String,
    /// The listener; replace it before `start` to serve elsewhere.
    pub listener: Option<Box<dyn Listener>>,
    /// Go's `EnableHTTP2`: `start_tls` offers only ALPN `h2` and `client`
    /// sets `ForceAttemptHTTP2`. Plain `start` is unaffected, as in Go.
    pub enable_http2: bool,
    /// The server that runs the handler; adjust it before `start`.
    pub config: HttpServer,
    /// DER certificate of a TLS server (set by the TLS backend).
    pub certificate: Option<Vec<u8>>,
    /// Go's `TLS`: the server TLS configuration, set by `start_tls`.
    pub tls: Option<Arc<dyn crate::net::http::TlsConfig>>,
    /// Runtime state of a started server; leave it at its default
    /// (`..Server::unstarted(handler)?`).
    pub state: ServerState,
}

/// The connection tracking, client transport and serve thread behind a
/// [`Server`]. Opaque: it exists so every `Server` field is public. Dropping
/// it closes a started server.
#[derive(Default)]
pub struct ServerState {
    client_transport: Arc<Mutex<Option<Arc<Transport>>>>,
    dial_addr: Arc<Mutex<String>>,
    track: Arc<(Mutex<Tracking>, std::sync::Condvar)>,
    started: bool,
    serve_thread: Option<thread::JoinHandle<()>>,
    /// The (connection-tracking) server that was started.
    served: Option<HttpServer>,
    /// Serves every host from the test server (`Server::for_test`).
    fake_net: bool,
    trust_tls: Option<Arc<dyn crate::net::http::TlsConfig>>,
}

impl Drop for ServerState {
    fn drop(&mut self) {
        if let Some(server) = self.served.take() {
            close_impl(&server, &self.track, &self.client_transport);
            if let Some(t) = self.serve_thread.take() {
                let _ = t.join();
            }
        }
    }
}

fn local_listener() -> Result<Box<dyn Listener>, BoxError> {
    net::listen("tcp", "127.0.0.1:0")
        .or_else(|_| net::listen("tcp6", "[::1]:0"))
        .map_err(|e| Box::new(e) as BoxError)
}

impl Server {
    /// Go's `NewServer`: a started server.
    pub fn new(handler: Arc<dyn Handler>) -> Result<Server, BoxError> {
        let mut s = Server::unstarted(handler)?;
        s.start()?;
        Ok(s)
    }

    /// Go's `NewUnstartedServer`.
    pub fn unstarted(handler: Arc<dyn Handler>) -> Result<Server, BoxError> {
        let config = HttpServer {
            handler: Some(handler),
            ..HttpServer::default()
        };
        Ok(Server {
            listener: Some(local_listener()?),
            config,
            ..Server::default()
        })
    }

    /// Go's `NewTestServer`: a started server for a test. The test's cleanup
    /// closes it; every host name reaches the server (Go uses an in-memory
    /// network), and a `None` handler answers 500.
    pub fn for_test(
        t: &dyn crate::testing::TB,
        handler: Option<Arc<dyn Handler>>,
    ) -> Result<Server, BoxError> {
        let h: Arc<dyn Handler> = match handler {
            Some(h) => h,
            None => crate::net::http::handler_func(|w, _| w.write_header(500)),
        };
        let mut s = Server::unstarted(h)?;
        s.state.fake_net = true;
        s.start()?;
        s.url = "http://example.com".into();
        let closer = s.closer();
        t.cleanup(Box::new(move || closer.close()));
        Ok(s)
    }
}

/// A handle that closes a started server from a cleanup function.
pub struct Closer {
    server: HttpServer,
    track: Arc<(Mutex<Tracking>, std::sync::Condvar)>,
    transport: Arc<Mutex<Option<Arc<Transport>>>>,
}
impl Closer {
    pub fn close(&self) {
        close_impl(&self.server, &self.track, &self.transport);
    }
}

fn close_impl(
    server: &HttpServer,
    track: &Arc<(Mutex<Tracking>, std::sync::Condvar)>,
    transport: &Arc<Mutex<Option<Arc<Transport>>>>,
) {
    let (m, cv) = &**track;
    let mut t = lock(m);
    if !t.closed {
        t.closed = true;
        drop(t);
        // Go closes only the listener; active requests finish below.
        let _ = server.stop_accepting();
        server.set_keep_alives_enabled(false);
        let mut t = lock(m);
        let idle: Vec<Arc<dyn Conn>> = t
            .conns
            .values()
            .filter(|(_, st)| *st == STATE_NEW || *st == STATE_IDLE)
            .map(|(c, _)| c.clone())
            .collect();
        drop(t);
        for c in idle {
            let _ = c.close();
        }
        t = lock(m);
        // Wait for active requests to finish.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while t.active > 0 && std::time::Instant::now() < deadline {
            t = cv
                .wait_timeout(t, std::time::Duration::from_millis(20))
                .unwrap_or_else(|e| e.into_inner())
                .0;
            let idle: Vec<Arc<dyn Conn>> = t
                .conns
                .values()
                .filter(|(_, st)| *st == STATE_IDLE)
                .map(|(c, _)| c.clone())
                .collect();
            for c in idle {
                let _ = c.close();
            }
        }
    } else {
        // Closing twice is allowed, as in Go.
        drop(t);
    }
    drop(lock(m));
    use crate::net::http::RoundTripper;
    if let Some(t) = lock(transport).clone() {
        t.close_idle_connections();
    }
    if let Some(dt) = Some(crate::net::http::default_transport()) {
        dt.close_idle_connections();
    }
}

impl Server {
    fn closer(&self) -> Closer {
        Closer {
            server: self.config.clone(),
            track: self.state.track.clone(),
            transport: self.state.client_transport.clone(),
        }
    }

    /// Go's `Start`. Go panics when the server was already started; here
    /// that is an error.
    pub fn start(&mut self) -> Result<(), BoxError> {
        if !self.url.is_empty() || self.state.started {
            return Err("httptest: Start() called multiple times".into());
        }
        let Some(ln) = self.listener.take() else {
            return Err("httptest: Server has no Listener".into());
        };
        let addr = ln.addr().map(|a| a.to_string()).unwrap_or_default();
        *lock(&self.state.dial_addr) = addr.clone();
        self.url = format!("http://{addr}");
        self.start_common(ln);
        Ok(())
    }

    /// Serves `ln` and tracks connection states (Go's `goServe` + `wrap`).
    pub fn start_common(&mut self, ln: Box<dyn Listener>) {
        self.state.started = true;
        let old_hook = self.config.conn_state.clone();
        let track = self.state.track.clone();
        self.config.conn_state = Some(Arc::new(move |c, cs| {
            let (m, cv) = &*track;
            let key = format!(
                "{}->{}",
                c.local_addr().map(|a| a.to_string()).unwrap_or_default(),
                c.remote_addr().map(|a| a.to_string()).unwrap_or_default()
            );
            let mut t = lock(m);
            match cs {
                STATE_NEW => {
                    t.conns.insert(key, (c.clone(), cs));
                    t.active += 1;
                }
                STATE_ACTIVE => {
                    if let Some(e) = t.conns.get_mut(&key) {
                        e.1 = cs;
                    }
                }
                STATE_IDLE => {
                    let closed = t.closed;
                    if let Some(e) = t.conns.get_mut(&key) {
                        e.1 = cs;
                    }
                    if closed {
                        let _ = c.close();
                    }
                }
                STATE_HIJACKED | STATE_CLOSED if t.conns.remove(&key).is_some() => {
                    t.active = t.active.saturating_sub(1);
                }
                _ => {}
            }
            cv.notify_all();
            drop(t);
            if let Some(h) = &old_hook {
                h(c, cs);
            }
        }));
        let srv = self.config.clone();
        self.state.served = Some(srv.clone());
        self.state.serve_thread = Some(thread::spawn(move || {
            let _ = srv.serve(ln);
        }));
    }

    /// Go's `Close`: shuts down the server and blocks until all outstanding
    /// requests have completed.
    pub fn close(&mut self) {
        close_impl(
            &self.config,
            &self.state.track,
            &self.state.client_transport,
        );
        if let Some(t) = self.state.serve_thread.take() {
            let _ = t.join();
        }
    }

    /// Go's `CloseClientConnections`: closes all open connections.
    pub fn close_client_connections(&self) {
        let (m, _) = &*self.state.track;
        let conns: Vec<Arc<dyn Conn>> = lock(m).conns.values().map(|(c, _)| c.clone()).collect();
        for c in conns {
            let _ = c.close();
        }
    }

    /// Go's `Certificate`: the DER certificate of a TLS server, if any.
    pub fn certificate(&self) -> Option<&[u8]> {
        self.certificate.as_deref()
    }

    /// Go's `Client`: a client configured to talk to the server; its
    /// connections are closed with the server.
    pub fn client(&self) -> Client {
        let mut cached = lock(&self.state.client_transport);
        let t = cached
            .get_or_insert_with(|| {
                let mut t = Transport::default();
                if self.state.fake_net {
                    let addr = self.state.dial_addr.clone();
                    t.dial_context = Some(Arc::new(move |ctx, network, _| {
                        let a = lock(&addr).clone();
                        net::Dialer::default()
                            .dial_context(ctx, network, &a)
                            .map_err(|e| Box::new(e) as BoxError)
                    }));
                }
                t.tls_client_config = self.state.trust_tls.clone();
                t.force_attempt_http2 = self.enable_http2;
                Arc::new(t)
            })
            .clone();
        Client {
            transport: Some(t),
            ..Client::default()
        }
    }

    /// Installs a client TLS configuration trusting the server certificate
    /// (used by the TLS backend).
    pub fn set_client_tls(&mut self, cfg: Arc<dyn crate::net::http::TlsConfig>) {
        self.state.trust_tls = Some(cfg);
    }
}
