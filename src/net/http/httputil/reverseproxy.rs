//! Go's `httputil.ReverseProxy` over the Go-shaped handler model: a streaming
//! `http.Handler` with `Director` or `Rewrite`, hop-by-hop handling,
//! `FlushInterval`, response trailers, `ModifyResponse`, `ErrorHandler`,
//! informational (1xx) responses and protocol upgrades through `Hijack`.
use crate::context::Context;
use crate::net::http::{
    self,
    client::RoundTripper,
    handler::{Handler, ResponseWriter},
    header::{
        is_error, valid_header_field_name, values_contain_token, BoxError, ErrorString, Header,
        ERR_ABORT_HANDLER, ERR_NOT_SUPPORTED,
    },
    request::Request,
    response::Response,
    server::SERVER_CONTEXT_KEY,
    status::*,
    TRAILER_PREFIX,
};
use crate::net::textproto::trim_string;
use crate::net::url::{self, Url};
use std::{
    io::{self, Read, Write},
    sync::{mpsc, Arc},
    time::{Duration as StdDuration, Instant},
};

/// Go's `httputil.BufferPool`.
pub trait BufferPool: Send + Sync {
    fn get(&self) -> Vec<u8>;
    fn put(&self, buf: Vec<u8>);
}

/// `ReverseProxy.ErrorHandler`.
pub type ProxyErrorHandler =
    Arc<dyn Fn(&mut dyn ResponseWriter, &Request, &BoxError) + Send + Sync>;
/// `ReverseProxy.ModifyResponse`.
pub type ProxyModifyResponse = Arc<dyn Fn(&mut Response) -> Result<(), BoxError> + Send + Sync>;
/// `ReverseProxy.Director`.
pub type ProxyDirector = Arc<dyn Fn(&mut Request) + Send + Sync>;
/// `ReverseProxy.Rewrite`.
pub type ProxyRewrite = Arc<dyn Fn(&mut ProxyRequest) + Send + Sync>;

/// Go's `httputil.ProxyRequest`.
pub struct ProxyRequest {
    /// The inbound request; it must not be modified.
    pub in_: Request,
    /// The outbound request, to be sent by the proxy.
    pub out: Request,
}

impl ProxyRequest {
    /// Go's `SetURL`: routes `out` to `target`, joining paths and queries.
    pub fn set_url(&mut self, target: &Url) {
        rewrite_request_url(&mut self.out, target);
        self.out.host.clear();
    }

    /// Go's `SetXForwarded`.
    pub fn set_x_forwarded(&mut self) {
        let h = &mut self.out.header;
        match split_host_port(&self.in_.remote_addr) {
            Some(mut client_ip) => {
                if let Some(prior) = h.0.get("X-Forwarded-For").filter(|p| !p.is_empty()) {
                    client_ip = format!("{}, {}", prior.join(", "), client_ip);
                }
                h.set("X-Forwarded-For", &client_ip);
            }
            None => h.del("X-Forwarded-For"),
        }
        h.set("X-Forwarded-Host", &self.in_.host);
        if self.in_.tls.is_none() {
            h.set("X-Forwarded-Proto", "http");
        } else {
            h.set("X-Forwarded-Proto", "https");
        }
    }
}

fn split_host_port(addr: &str) -> Option<String> {
    crate::net::split_host_port(addr).ok().map(|(h, _)| h)
}

/// Go's `httputil.ReverseProxy`. Exactly one of `director` and `rewrite`
/// must be set.
#[derive(Clone, Default)]
pub struct ReverseProxy {
    pub rewrite: Option<ProxyRewrite>,
    pub director: Option<ProxyDirector>,
    /// `http.DefaultTransport` when `None`.
    pub transport: Option<Arc<dyn RoundTripper>>,
    /// Flush interval in nanoseconds: 0 none, negative flushes after every
    /// write.
    pub flush_interval: i64,
    pub error_log: Option<Arc<crate::log::Logger>>,
    pub buffer_pool: Option<Arc<dyn BufferPool>>,
    pub modify_response: Option<ProxyModifyResponse>,
    pub error_handler: Option<ProxyErrorHandler>,
}

fn single_joining_slash(a: &str, b: &str) -> String {
    match (a.ends_with('/'), b.starts_with('/')) {
        (true, true) => format!("{a}{}", &b[1..]),
        (false, false) => format!("{a}/{b}"),
        _ => format!("{a}{b}"),
    }
}

fn join_url_path(a: &Url, b: &Url) -> (String, String) {
    if a.raw_path.is_empty() && b.raw_path.is_empty() {
        return (single_joining_slash(&a.path, &b.path), String::new());
    }
    let apath = a.escaped_path();
    let bpath = b.escaped_path();
    match (apath.ends_with('/'), bpath.starts_with('/')) {
        (true, true) => (
            format!("{}{}", a.path, &b.path[1..]),
            format!("{apath}{}", &bpath[1..]),
        ),
        (false, false) => (format!("{}/{}", a.path, b.path), format!("{apath}/{bpath}")),
        _ => (format!("{}{}", a.path, b.path), format!("{apath}{bpath}")),
    }
}

fn rewrite_request_url(req: &mut Request, target: &Url) {
    let target_query = &target.raw_query;
    req.url.scheme = target.scheme.clone();
    req.url.host = target.host.clone();
    let (path, raw) = join_url_path(target, &req.url);
    req.url.path = path;
    req.url.raw_path = raw;
    if target_query.is_empty() || req.url.raw_query.is_empty() {
        req.url.raw_query = format!("{target_query}{}", req.url.raw_query);
    } else {
        req.url.raw_query = format!("{target_query}&{}", req.url.raw_query);
    }
}

const HOP_HEADERS: [&str; 9] = [
    "Connection",
    "Proxy-Connection",
    "Keep-Alive",
    "Proxy-Authenticate",
    "Proxy-Authorization",
    "Te",
    "Trailer",
    "Transfer-Encoding",
    "Upgrade",
];

/// Go's `removeHopByHopHeaders`.
pub fn remove_hop_by_hop_headers(h: &mut Header) {
    let conn = h.0.get("Connection").cloned().unwrap_or_default();
    for f in conn {
        for sf in f.split(',') {
            let sf = trim_string(sf);
            if !sf.is_empty() {
                h.del(sf);
            }
        }
    }
    for f in HOP_HEADERS {
        h.del(f);
    }
}

fn copy_header(dst: &mut Header, src: &Header) {
    for (k, vv) in &src.0 {
        for v in vv {
            dst.add(k, v);
        }
    }
}

fn upgrade_type(h: &Header) -> String {
    let conn = h.0.get("Connection").cloned().unwrap_or_default();
    if !values_contain_token(&conn, "Upgrade") {
        return String::new();
    }
    h.get_str("Upgrade").to_owned()
}

fn is_print(s: &str) -> bool {
    s.bytes().all(|b| (b' '..=b'~').contains(&b))
}

impl ReverseProxy {
    /// Go's `NewSingleHostReverseProxy`: a proxy that routes requests to
    /// `target`, joining the target's path and query to the request's.
    pub fn single_host(target: Url) -> ReverseProxy {
        ReverseProxy {
            director: Some(Arc::new(move |req: &mut Request| {
                rewrite_request_url(req, &target);
            })),
            ..ReverseProxy::default()
        }
    }

    fn logf(&self, args: std::fmt::Arguments<'_>) {
        match &self.error_log {
            Some(l) => l.printf(args),
            None => crate::log::printf(args),
        }
    }

    fn handle_error(&self, rw: &mut dyn ResponseWriter, req: &Request, err: &BoxError) {
        match &self.error_handler {
            Some(h) => h(rw, req, err),
            None => {
                self.logf(format_args!("http: proxy error: {err}"));
                rw.write_header(STATUS_BAD_GATEWAY);
            }
        }
    }

    fn modify(&self, rw: &mut dyn ResponseWriter, res: &mut Response, req: &Request) -> bool {
        let Some(f) = &self.modify_response else {
            return true;
        };
        if let Err(e) = f(res) {
            res.close_body();
            self.handle_error(rw, req, &e);
            return false;
        }
        true
    }

    fn flush_interval_for(&self, res: &Response) -> i64 {
        let ct = res.header.get_str("Content-Type");
        let (base, _) = crate::mime::parse_media_type(ct);
        if base == "text/event-stream" {
            return -1;
        }
        if res.content_length == -1 {
            return -1;
        }
        self.flush_interval
    }
}

impl Handler for ReverseProxy {
    fn serve_http(&self, rw: &mut dyn ResponseWriter, req: &mut Request) {
        let transport = self
            .transport
            .clone()
            .unwrap_or_else(http::transport::default_transport);
        let ctx = req.context();
        let mut outreq = req.clone_with_context(&ctx);
        if req.content_length == 0 {
            outreq.body = None;
        }
        // Closing the outgoing body on exit (Go: defer outreq.Body.Close()).
        let out_body = outreq.body.clone();
        let _close_body = CloseOnDrop(out_body);

        if self.director.is_some() == self.rewrite.is_some() {
            self.handle_error(
                rw,
                req,
                &"ReverseProxy must have exactly one of Director or Rewrite set".into(),
            );
            return;
        }
        if let Some(d) = &self.director {
            d(&mut outreq);
            if outreq.form.is_some() {
                outreq.url.raw_query = clean_query_params(&outreq.url.raw_query);
            }
        }
        outreq.close = false;

        let req_up_type = upgrade_type(&outreq.header);
        if !is_print(&req_up_type) {
            self.handle_error(
                rw,
                req,
                &format!(
                    "client tried to switch to invalid protocol {}",
                    crate::strconv::quote(&req_up_type)
                )
                .into(),
            );
            return;
        }
        remove_hop_by_hop_headers(&mut outreq.header);

        if values_contain_token(&req.header.values("Te"), "trailers") {
            outreq.header.set("Te", "trailers");
        }
        if !req_up_type.is_empty() {
            outreq.header.set("Connection", "Upgrade");
            outreq.header.set("Upgrade", &req_up_type);
        }

        if let Some(rewrite) = &self.rewrite {
            outreq.header.del("Forwarded");
            outreq.header.del("X-Forwarded-For");
            outreq.header.del("X-Forwarded-Host");
            outreq.header.del("X-Forwarded-Proto");
            outreq.url.raw_query = clean_query_params(&outreq.url.raw_query);
            let mut pr = ProxyRequest {
                in_: req.clone(),
                out: outreq,
            };
            rewrite(&mut pr);
            outreq = pr.out;
        } else if let Some(mut client_ip) = split_host_port(&req.remote_addr) {
            // A present-but-empty X-Forwarded-For (Go: nil) opts out.
            let prior = outreq.header.0.get("X-Forwarded-For").cloned();
            let omit = prior.as_ref().is_some_and(Vec::is_empty);
            if let Some(p) = prior.filter(|p| !p.is_empty()) {
                client_ip = format!("{}, {}", p.join(", "), client_ip);
            }
            if !omit {
                outreq.header.set("X-Forwarded-For", &client_ip);
            }
        }
        if !outreq.header.0.contains_key("User-Agent") {
            // An explicit empty value stops the transport adding its own.
            outreq.header.set("User-Agent", "");
        }

        // The transport runs on a helper thread so informational (1xx)
        // responses can be written to the client as they arrive.
        enum Event {
            Informational(u16, Header),
            Final(Result<Response, BoxError>),
        }
        let (tx, rx) = mpsc::channel::<Event>();
        {
            let tx_hook = std::sync::Mutex::new(tx.clone());
            let trace = crate::net::http::httptrace::ClientTrace {
                got_1xx_response: Some(Arc::new(move |code, h| {
                    let _ = tx_hook
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .send(Event::Informational(code, h.clone()));
                    Ok(())
                })),
                ..Default::default()
            };
            let ctx = crate::net::http::httptrace::with_client_trace(&outreq.context(), trace);
            let rt_req = outreq.with_context(&ctx);
            let transport = transport.clone();
            std::thread::spawn(move || {
                let _ = tx.send(Event::Final(transport.round_trip(&rt_req)));
            });
        }
        let mut res = loop {
            match rx.recv() {
                Ok(Event::Informational(code, h)) => {
                    copy_header(rw.header(), &h);
                    rw.write_header(code);
                    rw.header().0.clear();
                }
                Ok(Event::Final(Ok(r))) => break r,
                Ok(Event::Final(Err(e))) => {
                    self.handle_error(rw, &outreq, &e);
                    return;
                }
                Err(_) => {
                    self.handle_error(rw, &outreq, &"transport thread ended".into());
                    return;
                }
            }
        };

        if res.status_code == STATUS_SWITCHING_PROTOCOLS {
            if !self.modify(rw, &mut res, &outreq) {
                return;
            }
            self.handle_upgrade_response(rw, &outreq, res);
            return;
        }

        remove_hop_by_hop_headers(&mut res.header);
        if !self.modify(rw, &mut res, &outreq) {
            return;
        }
        copy_header(rw.header(), &res.header);

        let announced = res.trailer.get().map_or(0, |t| t.0.len());
        if announced > 0 {
            let keys: Vec<String> = res
                .trailer
                .get()
                .map(|t| t.0.keys().cloned().collect())
                .unwrap_or_default();
            rw.header().add("Trailer", &keys.join(", "));
        }
        rw.write_header(res.status_code);

        let body = res.body.clone();
        let flush = self.flush_interval_for(&res);
        let copy_result = match body {
            Some(b) => self.copy_response(rw, b, flush),
            None => Ok(()),
        };
        if let Err(e) = copy_result {
            res.close_body();
            if should_panic_on_copy_error(req) {
                std::panic::panic_any(ERR_ABORT_HANDLER);
            }
            self.logf(format_args!(
                "suppressing panic for copyResponse error in test; copy error: {e}"
            ));
            return;
        }
        res.close_body();

        let trailers = res.trailer.get();
        if trailers.as_ref().is_some_and(|t| !t.0.is_empty()) {
            let _ = http::ResponseController::new(rw).flush();
        }
        let n = trailers.as_ref().map_or(0, |t| t.0.len());
        if n == announced {
            if let Some(t) = &trailers {
                copy_header(rw.header(), t);
            }
            return;
        }
        if let Some(t) = trailers {
            for (k, vv) in t.0 {
                let k = format!("{TRAILER_PREFIX}{k}");
                for v in vv {
                    rw.header().add(&k, &v);
                }
            }
        }
    }
}

struct CloseOnDrop(Option<http::Body>);
impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        if let Some(b) = &self.0 {
            let _ = b.close();
        }
    }
}

fn should_panic_on_copy_error(req: &Request) -> bool {
    req.context().value(&SERVER_CONTEXT_KEY).is_some()
}

impl ReverseProxy {
    /// Go's `copyResponse`: copies the body, flushing per `flush_interval`.
    fn copy_response(
        &self,
        dst: &mut dyn ResponseWriter,
        src: http::Body,
        flush_interval: i64,
    ) -> Result<(), BoxError> {
        let mut buf = match &self.buffer_pool {
            Some(p) => p.get(),
            None => Vec::new(),
        };
        if buf.is_empty() {
            buf = vec![0; 32 * 1024];
        }
        let result = if flush_interval == 0 {
            self.copy_buffer(dst, src, &mut buf)
        } else {
            self.copy_flushing(dst, src, flush_interval)
        };
        if let Some(p) = &self.buffer_pool {
            p.put(buf);
        }
        result
    }

    fn copy_buffer(
        &self,
        dst: &mut dyn ResponseWriter,
        mut src: http::Body,
        buf: &mut [u8],
    ) -> Result<(), BoxError> {
        loop {
            match src.read(buf) {
                Ok(0) => return Ok(()),
                Ok(n) => {
                    if let Err(e) = dst.write(&buf[..n]) {
                        return Err(Box::new(e));
                    }
                }
                Err(e) => {
                    self.logf(format_args!(
                        "httputil: ReverseProxy read error during body copy: {e}"
                    ));
                    return Err(Box::new(e));
                }
            }
        }
    }

    /// The `maxLatencyWriter` path: a reader thread feeds chunks, and the
    /// writer flushes after `interval` of pending data (immediately when
    /// negative).
    fn copy_flushing(
        &self,
        dst: &mut dyn ResponseWriter,
        mut src: http::Body,
        interval: i64,
    ) -> Result<(), BoxError> {
        let (tx, rx) = mpsc::channel::<io::Result<Vec<u8>>>();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 32 * 1024];
            loop {
                match src.read(&mut buf) {
                    Ok(0) => {
                        let _ = tx.send(Ok(Vec::new()));
                        return;
                    }
                    Ok(n) => {
                        if tx.send(Ok(buf[..n].to_vec())).is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e));
                        return;
                    }
                }
            }
        });
        let latency = StdDuration::from_nanos(interval.unsigned_abs());
        let mut pending_since: Option<Instant> = Some(Instant::now());
        loop {
            let wait = match pending_since {
                Some(t) if interval > 0 => latency.saturating_sub(t.elapsed()),
                _ => StdDuration::from_secs(3600),
            };
            match rx.recv_timeout(wait) {
                Ok(Ok(chunk)) if chunk.is_empty() => {
                    return Ok(());
                }
                Ok(Ok(chunk)) => {
                    dst.write(&chunk).map_err(|e| Box::new(e) as BoxError)?;
                    if interval < 0 {
                        let _ = http::ResponseController::new(dst).flush();
                    } else if pending_since.is_none() {
                        pending_since = Some(Instant::now());
                    }
                }
                Ok(Err(e)) => {
                    self.logf(format_args!(
                        "httputil: ReverseProxy read error during body copy: {e}"
                    ));
                    return Err(Box::new(e));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let _ = http::ResponseController::new(dst).flush();
                    pending_since = None;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
            }
        }
    }

    fn handle_upgrade_response(
        &self,
        rw: &mut dyn ResponseWriter,
        req: &Request,
        mut res: Response,
    ) {
        let req_up = upgrade_type(&req.header);
        let res_up = upgrade_type(&res.header);
        if !is_print(&res_up) {
            self.handle_error(
                rw,
                req,
                &format!(
                    "backend tried to switch to invalid protocol {}",
                    crate::strconv::quote(&res_up)
                )
                .into(),
            );
            return;
        }
        if !req_up.eq_ignore_ascii_case(&res_up) {
            self.handle_error(
                rw,
                req,
                &format!(
                    "backend tried to switch protocol {} when {} was requested",
                    crate::strconv::quote(&res_up),
                    crate::strconv::quote(&req_up)
                )
                .into(),
            );
            return;
        }
        let Some(back) = res.body.clone() else {
            self.handle_error(
                rw,
                req,
                &"internal error: 101 switching protocols response with non-writable body".into(),
            );
            return;
        };
        let Some(back_writer) = back.as_writer().cloned() else {
            self.handle_error(
                rw,
                req,
                &"internal error: 101 switching protocols response with non-writable body".into(),
            );
            return;
        };
        let hijacked = http::ResponseController::new(rw).hijack();
        let hijacked = match hijacked {
            Ok(h) => h,
            Err(e) => {
                let _ = back.close();
                if is_error(&*e, &ERR_NOT_SUPPORTED) {
                    self.handle_error(
                        rw,
                        req,
                        &"can't switch protocols using non-Hijacker ResponseWriter type".into(),
                    );
                } else {
                    self.handle_error(
                        rw,
                        req,
                        &format!("Hijack failed on protocol switch: {e}").into(),
                    );
                }
                return;
            }
        };
        let mut hj = hijacked;
        copy_header(rw.header(), &res.header);
        res.header = rw.header().clone();
        res.body = None;
        let mut head = Vec::new();
        if let Err(e) = res.write(&mut head) {
            self.handle_error(rw, req, &format!("response write: {e}").into());
            let _ = hj.conn.close();
            return;
        }
        if hj.writer.write_all(&head).is_err() || hj.writer.flush().is_err() {
            let _ = hj.conn.close();
            let _ = back.close();
            return;
        }
        let user_conn: Arc<dyn crate::net::Conn> = Arc::from(hj.conn);
        let user_reader = hj.reader.clone();
        // client -> backend
        let to_backend = {
            let user_conn = user_conn.clone();
            let back_writer = back_writer.clone();
            let mut ur = user_reader;
            std::thread::spawn(move || {
                let mut buf = [0u8; 32 * 1024];
                loop {
                    let n = if ur.buffered() > 0 {
                        let k = ur.buffered().min(buf.len());
                        ur.read(&mut buf[..k]).unwrap_or(0)
                    } else {
                        user_conn.read(&mut buf).unwrap_or(0)
                    };
                    if n == 0 {
                        let _ = back_writer.close_write();
                        return;
                    }
                    let mut off = 0;
                    while off < n {
                        match back_writer.write(&buf[off..n]) {
                            Ok(k) => off += k,
                            Err(_) => return,
                        }
                    }
                }
            })
        };
        // backend -> client
        let mut back_reader = back.clone();
        let mut buf = [0u8; 32 * 1024];
        loop {
            match back_reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let mut off = 0;
                    let mut failed = false;
                    while off < n {
                        match user_conn.write(&buf[off..n]) {
                            Ok(k) => off += k,
                            Err(_) => {
                                failed = true;
                                break;
                            }
                        }
                    }
                    if failed {
                        break;
                    }
                }
            }
        }
        let _ = user_conn.close();
        let _ = back.close();
        let _ = to_backend.join();
    }
}

/// Go's `cleanQueryParams` is shared with the buffered proxy.
#[allow(dead_code)]
fn _unused(_: &Context, _: &ErrorString) {
    let _ = valid_header_field_name;
    let _ = url::parse;
}

/// Go's `cleanQueryParams`: re-encode only queries with semicolons or
/// malformed escapes.
fn clean_query_params(text: &str) -> String {
    let data = text.as_bytes();
    let mut i = 0;
    while i < data.len() {
        match data[i] {
            b';' => return reencode_query(text),
            b'%' => {
                if i + 2 >= data.len()
                    || !data[i + 1].is_ascii_hexdigit()
                    || !data[i + 2].is_ascii_hexdigit()
                {
                    return reencode_query(text);
                }
                i += 3;
            }
            _ => i += 1,
        }
    }
    text.to_owned()
}
fn reencode_query(text: &str) -> String {
    url::parse_query(text).0.encode()
}
