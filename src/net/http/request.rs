//! Go's `http.Request`, `NewRequest`, `ReadRequest` and the request methods.
use super::body::{Body, NoBody};
use super::cookie::{read_cookies, sanitize_cookie_name, sanitize_cookie_value, Cookie};
use super::header::{
    contains_ctl_byte, has_token, parse_http_version, textproto_err, BoxError, ErrorString, Header,
    Trailer, ERR_EOF, ERR_MISSING_BOUNDARY, ERR_MISSING_FILE, ERR_NOT_MULTIPART, ERR_NO_COOKIE,
    ERR_UNEXPECTED_EOF,
};
use super::httptrace::{self, ClientTrace};
use super::response::Response;
use super::servemux::Pattern;
use super::tlsstate::ConnectionState;
use super::transfer::{
    bad_string_error, fix_pragma_cache_control, read_transfer, should_close, value_or_default,
    BufioReader, MsgIn, TransferWriter,
};
use crate::context::{self, Context, Done};
use crate::net::textproto;
use crate::net::url::{self, Url, Values};
use crate::{multipart, strconv::quote};
use std::{
    collections::BTreeMap,
    fmt,
    io::{self, Read, Write},
    sync::Arc,
};

const DEFAULT_MAX_MEMORY: i64 = 32 << 20;
const DEFAULT_USER_AGENT: &str = "Go-http-client/1.1";

/// `Request.GetBody`.
pub type GetBody = Arc<dyn Fn() -> Result<Body, BoxError> + Send + Sync>;

/// Go's `http.Request`.
#[derive(Clone, Default)]
pub struct Request {
    pub method: String,
    pub url: Url,
    pub proto: String,
    pub proto_major: i32,
    pub proto_minor: i32,
    pub header: Header,
    pub body: Option<Body>,
    pub get_body: Option<GetBody>,
    pub content_length: i64,
    pub transfer_encoding: Vec<String>,
    pub close: bool,
    pub host: String,
    pub form: Option<Values>,
    pub post_form: Option<Values>,
    pub multipart_form: Option<multipart::Form>,
    pub trailer: Trailer,
    pub remote_addr: String,
    pub request_uri: String,
    pub tls: Option<Arc<ConnectionState>>,
    pub cancel: Option<Done>,
    pub response: Option<Box<Response>>,
    pub pattern: String,
    ctx: Option<Context>,
    pat: Option<Arc<Pattern>>,
    matches: Vec<String>,
    other_values: BTreeMap<String, String>,
    multipart_by_reader: bool,
    pub(crate) body_handle: Option<super::transfer::BodyHandle>,
    id: u64,
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("url", &self.url.to_string())
            .field("proto", &self.proto)
            .field("header", &self.header)
            .field("content_length", &self.content_length)
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

/// What [`Request::with_body`] accepts as a body. In-memory variants carry their
/// length and a `GetBody` like Go's `*bytes.Buffer`, `*bytes.Reader` and
/// `*strings.Reader`.
pub enum RequestBody {
    Bytes(Vec<u8>),
    Reader(Box<dyn Read + Send>),
    ReadCloser(Body),
}
impl RequestBody {
    pub fn reader<R: Read + Send + 'static>(r: R) -> Self {
        Self::Reader(Box::new(r))
    }
}
impl From<Vec<u8>> for RequestBody {
    fn from(v: Vec<u8>) -> Self {
        Self::Bytes(v)
    }
}
impl From<&[u8]> for RequestBody {
    fn from(v: &[u8]) -> Self {
        Self::Bytes(v.to_vec())
    }
}
impl From<String> for RequestBody {
    fn from(v: String) -> Self {
        Self::Bytes(v.into_bytes())
    }
}
impl From<&str> for RequestBody {
    fn from(v: &str) -> Self {
        Self::Bytes(v.as_bytes().to_vec())
    }
}
impl From<Body> for RequestBody {
    fn from(v: Body) -> Self {
        Self::ReadCloser(v)
    }
}

fn next_request_id() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn value_or<'a>(v: &'a str, d: &'a str) -> &'a str {
    value_or_default(v, d)
}

impl Request {
    /// Go's `NewRequest`: a request for `method` (empty means `GET`) and
    /// `url`, without a body. Set one with [`Request::with_body`].
    pub fn new(method: &str, url: &str) -> Result<Request, BoxError> {
        Request::in_context(&Context::background(), method, url)
    }

    /// Go's `NewRequestWithContext`: [`Request::new`] with `ctx` for the
    /// outgoing request's lifetime.
    pub fn in_context(ctx: &Context, method: &str, url_str: &str) -> Result<Request, BoxError> {
        let method = if method.is_empty() { "GET" } else { method };
        if !super::token(method) {
            return Err(format!("net/http: invalid method {}", quote(method)).into());
        }
        let mut u = url::parse(url_str)?;
        u.host = u.host.strip_suffix(':').unwrap_or(&u.host).to_owned();
        let host = u.host.clone();
        Ok(Request {
            id: next_request_id(),
            ctx: Some(ctx.clone()),
            method: method.to_owned(),
            url: u,
            proto: "HTTP/1.1".into(),
            proto_major: 1,
            proto_minor: 1,
            header: Header::new(),
            host,
            ..Request::default()
        })
    }

    /// Sets the outgoing body as `NewRequest` does: in-memory bodies record
    /// their length and a `GetBody` that replays them.
    pub fn with_body(mut self, body: impl Into<RequestBody>) -> Request {
        match body.into() {
            RequestBody::Bytes(buf) => {
                self.content_length = buf.len() as i64;
                if buf.is_empty() {
                    self.body = Some(Body::from(NoBody));
                    self.get_body = Some(Arc::new(|| Ok(Body::from(NoBody))));
                } else {
                    self.body = Some(Body::from_bytes(buf.clone()));
                    let snapshot = Arc::new(buf);
                    self.get_body = Some(Arc::new(move || Ok(Body::from_bytes(snapshot.to_vec()))));
                }
            }
            RequestBody::Reader(r) => self.body = Some(Body::from_reader(r)),
            RequestBody::ReadCloser(b) => self.body = Some(b),
        }
        self
    }

    /// Go's `Context`.
    pub fn context(&self) -> Context {
        self.ctx
            .clone()
            .unwrap_or_else(context::Context::background)
    }

    /// Go's `WithContext`: a shallow copy with `ctx`.
    pub fn with_context(&self, ctx: &Context) -> Request {
        let mut r2 = self.clone();
        r2.ctx = Some(ctx.clone());
        r2
    }

    /// Go's `Clone(ctx)`: a deep copy with `ctx`. (`Request` is `Clone`, which
    /// is Go's shallow struct copy.)
    pub fn clone_with_context(&self, ctx: &Context) -> Request {
        let mut r2 = self.clone();
        r2.ctx = Some(ctx.clone());
        r2.trailer = self.trailer.deep_clone();
        r2
    }

    /// Go's `ProtoAtLeast`.
    pub fn proto_at_least(&self, major: i32, minor: i32) -> bool {
        self.proto_major > major || (self.proto_major == major && self.proto_minor >= minor)
    }

    /// Go's `UserAgent`.
    pub fn user_agent(&self) -> &str {
        self.header.get_str("User-Agent")
    }

    /// Go's `Cookies`.
    pub fn cookies(&self) -> Vec<Cookie> {
        read_cookies(&self.header, "")
    }

    /// Go's `CookiesNamed`.
    pub fn cookies_named(&self, name: &str) -> Vec<Cookie> {
        if name.is_empty() {
            return Vec::new();
        }
        read_cookies(&self.header, name)
    }

    /// Go's `Cookie`: the first cookie named `name`, or `ErrNoCookie`.
    pub fn cookie(&self, name: &str) -> Result<Cookie, ErrorString> {
        if name.is_empty() {
            return Err(ERR_NO_COOKIE);
        }
        read_cookies(&self.header, name)
            .into_iter()
            .next()
            .ok_or(ERR_NO_COOKIE)
    }

    /// Go's `AddCookie`.
    pub fn add_cookie(&mut self, c: &Cookie) {
        let s = format!(
            "{}={}",
            sanitize_cookie_name(&c.name),
            sanitize_cookie_value(&c.value, c.quoted)
        );
        let existing = self.header.get_str("Cookie");
        if existing.is_empty() {
            self.header.set("Cookie", &s);
        } else {
            self.header.set("Cookie", &format!("{existing}; {s}"));
        }
    }

    /// Go's `Referer`.
    pub fn referer(&self) -> &str {
        self.header.get_str("Referer")
    }

    /// Go's `MultipartReader`.
    pub fn multipart_reader(&mut self) -> Result<multipart::Reader<io::BufReader<Body>>, BoxError> {
        if self.multipart_by_reader {
            return Err("http: MultipartReader called twice".into());
        }
        if self.multipart_form.is_some() {
            return Err("http: multipart handled by ParseMultipartForm".into());
        }
        self.multipart_by_reader = true;
        self.multipart_reader_inner(true)
    }

    fn multipart_reader_inner(
        &self,
        allow_mixed: bool,
    ) -> Result<multipart::Reader<io::BufReader<Body>>, BoxError> {
        let v = self.header.get_str("Content-Type");
        if v.is_empty() {
            return Err(Box::new(ERR_NOT_MULTIPART));
        }
        let Some(body) = self.body.clone() else {
            return Err("missing form body".into());
        };
        let (d, params) = crate::mime::parse_media_type(v);
        let params = match params {
            Ok(p) if d == "multipart/form-data" || (allow_mixed && d == "multipart/mixed") => p,
            _ => return Err(Box::new(ERR_NOT_MULTIPART)),
        };
        let Some(boundary) = params.get("boundary") else {
            return Err(Box::new(ERR_MISSING_BOUNDARY));
        };
        Ok(multipart::Reader::new(io::BufReader::new(body), boundary))
    }

    /// Go's `BasicAuth`.
    pub fn basic_auth(&self) -> Option<(String, String)> {
        let auth = self.header.get_str("Authorization");
        if auth.is_empty() {
            return None;
        }
        parse_basic_auth(auth)
    }

    /// Go's `SetBasicAuth`.
    pub fn set_basic_auth(&mut self, username: &str, password: &str) {
        let v = format!(
            "Basic {}",
            crate::encoding::base64::STANDARD.encode(format!("{username}:{password}").as_bytes())
        );
        self.header.set("Authorization", &v);
    }

    /// Go's `ParseForm`. Always populates `form` and `post_form`; the error is
    /// the first parse failure.
    pub fn parse_form(&mut self) -> Result<(), BoxError> {
        let mut err: Option<BoxError> = None;
        if self.post_form.is_none() {
            if matches!(self.method.as_str(), "POST" | "PUT" | "PATCH") {
                let (vs, e) = parse_post_form(self);
                self.post_form = vs;
                err = e;
            }
            if self.post_form.is_none() {
                self.post_form = Some(Values::new());
            }
        }
        if self.form.is_none() {
            let post = self.post_form.clone().unwrap_or_default();
            let mut form = None;
            if !post.0.is_empty() {
                let mut f = Values::new();
                copy_values(&mut f, &post);
                form = Some(f);
            }
            let (new_values, e) = url::parse_query(&self.url.raw_query);
            if err.is_none() {
                err = e;
            }
            match form.as_mut() {
                None => form = Some(new_values),
                Some(f) => copy_values(f, &new_values),
            }
            self.form = form;
        }
        err.map_or(Ok(()), Err)
    }

    /// Go's `ParseMultipartForm`.
    pub fn parse_multipart_form(&mut self, max_memory: i64) -> Result<(), BoxError> {
        if self.multipart_by_reader {
            return Err("http: multipart handled by MultipartReader".into());
        }
        let mut parse_form_err = None;
        if self.form.is_none() {
            parse_form_err = self.parse_form().err();
        }
        if self.multipart_form.is_some() {
            return Ok(());
        }
        let mut mr = self.multipart_reader_inner(false)?;
        let f = mr.read_form(max_memory)?;
        let post = self.post_form.get_or_insert_with(Values::new);
        let form = self.form.get_or_insert_with(Values::new);
        for (k, v) in &f.value {
            form.0
                .entry(k.clone())
                .or_default()
                .extend(v.iter().cloned());
            post.0
                .entry(k.clone())
                .or_default()
                .extend(v.iter().cloned());
        }
        self.multipart_form = Some(f);
        parse_form_err.map_or(Ok(()), Err)
    }

    /// Go's `FormValue`.
    pub fn form_value(&mut self, key: &str) -> String {
        if self.form.is_none() {
            let _ = self.parse_multipart_form(DEFAULT_MAX_MEMORY);
        }
        first(self.form.as_ref(), key)
    }

    /// Go's `PostFormValue`.
    pub fn post_form_value(&mut self, key: &str) -> String {
        if self.post_form.is_none() {
            let _ = self.parse_multipart_form(DEFAULT_MAX_MEMORY);
        }
        first(self.post_form.as_ref(), key)
    }

    /// Go's `FormFile`.
    pub fn form_file(
        &mut self,
        key: &str,
    ) -> Result<(multipart::File, multipart::FileHeader), BoxError> {
        if self.multipart_by_reader {
            return Err("http: multipart handled by MultipartReader".into());
        }
        if self.multipart_form.is_none() {
            self.parse_multipart_form(DEFAULT_MAX_MEMORY)?;
        }
        if let Some(f) = &self.multipart_form {
            if let Some(fh) = f.file.get(key).and_then(|v| v.first()) {
                let file = fh.open()?;
                return Ok((file, fh.clone()));
            }
        }
        Err(Box::new(ERR_MISSING_FILE))
    }

    /// Go's `PathValue`.
    pub fn path_value(&self, name: &str) -> String {
        if let Some(i) = self.pat.as_ref().and_then(|p| p.wildcard_index(name)) {
            return self.matches.get(i).cloned().unwrap_or_default();
        }
        self.other_values.get(name).cloned().unwrap_or_default()
    }

    /// Go's `SetPathValue`.
    pub fn set_path_value(&mut self, name: &str, value: &str) {
        if let Some(i) = self.pat.as_ref().and_then(|p| p.wildcard_index(name)) {
            if i < self.matches.len() {
                self.matches[i] = value.to_owned();
                return;
            }
        }
        self.other_values.insert(name.to_owned(), value.to_owned());
    }

    pub(crate) fn set_context(&mut self, ctx: Context) {
        self.ctx = Some(ctx);
    }
    pub(crate) fn set_context_opt(&mut self, ctx: Option<Context>) {
        self.ctx = ctx;
    }
    pub(crate) fn context_opt(&self) -> Option<Context> {
        self.ctx.clone()
    }
    /// A process-unique identity for `Transport.CancelRequest`, assigned on
    /// first use and kept by copies of the request.
    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    pub(crate) fn set_matched(&mut self, pat: Option<Arc<Pattern>>, matches: Vec<String>) {
        self.pat = pat;
        self.matches = matches;
    }

    pub(crate) fn expects_continue(&self) -> bool {
        has_token(self.header.get_exact("Expect"), "100-continue")
    }
    pub(crate) fn wants_http10_keep_alive(&self) -> bool {
        if self.proto_major != 1 || self.proto_minor != 0 {
            return false;
        }
        has_token(self.header.get_exact("Connection"), "keep-alive")
    }
    pub(crate) fn wants_close(&self) -> bool {
        self.close || has_token(self.header.get_exact("Connection"), "close")
    }
    pub(crate) fn close_body(&self) -> io::Result<()> {
        match &self.body {
            None => Ok(()),
            Some(b) => b.close(),
        }
    }
    pub(crate) fn is_replayable(&self) -> bool {
        let no_body = self.body.as_ref().is_none_or(Body::is_no_body);
        if no_body || self.get_body.is_some() {
            if matches!(
                value_or(&self.method, "GET"),
                "GET" | "HEAD" | "OPTIONS" | "TRACE"
            ) {
                return true;
            }
            if self.header.has("Idempotency-Key") || self.header.has("X-Idempotency-Key") {
                return true;
            }
        }
        false
    }
    pub(crate) fn outgoing_length(&self) -> i64 {
        if self.body.as_ref().is_none_or(Body::is_no_body) {
            return 0;
        }
        if self.content_length != 0 {
            return self.content_length;
        }
        -1
    }
    pub(crate) fn requires_http1(&self) -> bool {
        has_token(self.header.get_str("Connection"), "upgrade")
            && self
                .header
                .get_str("Upgrade")
                .eq_ignore_ascii_case("websocket")
    }
    fn is_h2_upgrade(&self) -> bool {
        self.method == "PRI"
            && self.header.0.is_empty()
            && self.url.path == "*"
            && self.proto == "HTTP/2.0"
    }

    /// Go's `Write`: the request in wire format (origin form), closing the body.
    pub fn write(&self, w: &mut dyn Write) -> Result<(), BoxError> {
        self.write_impl(w, false, None, None)
    }

    /// Go's `WriteProxy`: like `write` but with an absolute request target.
    pub fn write_proxy(&self, w: &mut dyn Write) -> Result<(), BoxError> {
        self.write_impl(w, true, None, None)
    }

    pub(crate) fn write_impl(
        &self,
        w: &mut dyn Write,
        using_proxy: bool,
        extra_headers: Option<&Header>,
        wait_for_continue: Option<&mut dyn FnMut() -> bool>,
    ) -> Result<(), BoxError> {
        let trace = httptrace::context_client_trace(&self.context());
        let mut closed = false;
        let mut res = self.write_inner(
            w,
            using_proxy,
            extra_headers,
            wait_for_continue,
            &mut closed,
            trace.as_deref(),
        );
        if !closed {
            let close_err = self.close_body();
            if res.is_ok() {
                if let Err(e) = close_err {
                    res = Err(Box::new(e));
                }
            }
        }
        // Go runs this deferred hook last, after the body is closed, so it
        // sees the final error.
        if let Some(hook) = trace.as_ref().and_then(|t| t.wrote_request.as_ref()) {
            hook(httptrace::WroteRequestInfo {
                err: res.as_ref().err().map(|e| -> httptrace::SharedError {
                    Arc::new(TraceWriteError(e.to_string()))
                }),
            });
        }
        res
    }

    fn write_inner(
        &self,
        w: &mut dyn Write,
        using_proxy: bool,
        extra_headers: Option<&Header>,
        wait_for_continue: Option<&mut dyn FnMut() -> bool>,
        closed: &mut bool,
        trace: Option<&ClientTrace>,
    ) -> Result<(), BoxError> {
        let mut host = self.host.clone();
        if host.is_empty() {
            host = self.url.host.clone();
        }
        // A nil `URL` in Go: nothing was ever set on the request.
        if host.is_empty() && self.url == Url::default() && self.proto.is_empty() {
            return Err("http: Request.Write on Request with no Host or URL set".into());
        }
        host = punycode_host_port(&host)?;
        if !valid_host_header(&host) {
            if !using_proxy {
                host.clear();
            } else {
                return Err("http: invalid Host header".into());
            }
        }
        host = remove_zone(&host);

        let mut ruri = self.url.request_uri();
        if using_proxy && !self.url.scheme.is_empty() && self.url.opaque.is_empty() {
            ruri = format!("{}://{}{}", self.url.scheme, host, ruri);
        } else if self.method == "CONNECT" && self.url.path.is_empty() {
            ruri = host.clone();
            if !self.url.opaque.is_empty() {
                ruri = self.url.opaque.clone();
            }
        }
        if contains_ctl_byte(&ruri) {
            return Err("net/http: can't write control character in Request.URL".into());
        }

        write!(w, "{} {} HTTP/1.1\r\n", value_or(&self.method, "GET"), ruri)?;
        write!(w, "Host: {host}\r\n")?;
        if let Some(hook) = trace.and_then(|t| t.wrote_header_field.as_ref()) {
            hook("Host", &[host.clone()]);
        }
        let mut user_agent = DEFAULT_USER_AGENT.to_owned();
        if self.header.has("User-Agent") {
            user_agent = self.header.get_str("User-Agent").to_owned();
        }
        if !user_agent.is_empty() {
            let ua = user_agent.replace(['\n', '\r'], " ");
            let ua = textproto::trim_string(&ua);
            write!(w, "User-Agent: {ua}\r\n")?;
            if let Some(hook) = trace.and_then(|t| t.wrote_header_field.as_ref()) {
                hook("User-Agent", &[ua.to_owned()]);
            }
        }
        let mut tw = TransferWriter::for_request(self)?;
        tw.write_header(w, trace)?;
        self.header.write_excluding(
            w,
            &[
                "Host",
                "User-Agent",
                "Content-Length",
                "Transfer-Encoding",
                "Trailer",
            ],
            trace,
        )?;
        if let Some(extra) = extra_headers {
            extra.write_subset_traced(w, &BTreeMap::new(), trace)?;
        }
        w.write_all(b"\r\n")?;
        if let Some(hook) = trace.and_then(|t| t.wrote_headers.as_ref()) {
            hook();
        }

        if let Some(wait) = wait_for_continue {
            w.flush()?;
            if let Some(hook) = trace.and_then(|t| t.wait_100_continue.as_ref()) {
                hook();
            }
            if !wait() {
                *closed = true;
                let _ = self.close_body();
                return Ok(());
            }
        }
        if tw.flush_headers {
            w.flush()?;
        }
        *closed = true;
        tw.write_body(w, !tw.is_response)?;
        w.flush()?;
        Ok(())
    }
}

/// The error text a [`WroteRequestInfo`](httptrace::WroteRequestInfo) carries.
#[derive(Debug)]
struct TraceWriteError(String);

impl fmt::Display for TraceWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TraceWriteError {}

fn first(v: Option<&Values>, key: &str) -> String {
    v.and_then(|v| v.0.get(key))
        .and_then(|vs| vs.first())
        .cloned()
        .unwrap_or_default()
}

fn copy_values(dst: &mut Values, src: &Values) {
    for (k, vs) in &src.0 {
        dst.0
            .entry(k.clone())
            .or_default()
            .extend(vs.iter().cloned());
    }
}

fn parse_post_form(r: &mut Request) -> (Option<Values>, Option<BoxError>) {
    let Some(body) = r.body.clone() else {
        return (None, Some("missing form body".into()));
    };
    let mut ct = r.header.get_str("Content-Type");
    if ct.is_empty() {
        ct = "application/octet-stream";
    }
    let (ct, params) = crate::mime::parse_media_type(ct);
    let mut err: Option<BoxError> = params.err().map(|e| -> BoxError { Box::new(e) });
    if ct == "application/x-www-form-urlencoded" {
        let mut max_form_size = i64::MAX;
        if !body.is_max_bytes() {
            max_form_size = 10 << 20;
        }
        let mut limited = body.clone().take(
            u64::try_from(max_form_size)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        );
        let mut b = Vec::new();
        if let Err(e) = limited.read_to_end(&mut b) {
            if err.is_none() {
                err = Some(Box::new(e));
            }
            return (None, err);
        }
        if (b.len() as i64) > max_form_size {
            return (None, Some("http: POST too large".into()));
        }
        let (vs, e) = url::parse_query(&String::from_utf8_lossy(&b));
        if err.is_none() {
            err = e;
        }
        return (Some(vs), err);
    }
    (None, err)
}

fn parse_basic_auth(auth: &str) -> Option<(String, String)> {
    const PREFIX: &str = "Basic ";
    if auth.len() < PREFIX.len()
        || !auth.as_bytes()[..PREFIX.len()].eq_ignore_ascii_case(PREFIX.as_bytes())
    {
        return None;
    }
    let c = crate::encoding::base64::STANDARD
        .decode(&auth[PREFIX.len()..])
        .ok()?;
    let cs = String::from_utf8_lossy(&c).into_owned();
    let (user, pass) = cs.split_once(':')?;
    Some((user.to_owned(), pass.to_owned()))
}

/// `httpguts.PunycodeHostPort`.
fn punycode_host_port(v: &str) -> Result<String, BoxError> {
    if v.is_ascii() {
        return Ok(v.to_owned());
    }
    let (host, port) = match crate::net::split_host_port(v) {
        Ok((h, p)) => (h, p),
        Err(_) => (v.to_owned(), String::new()),
    };
    let host = super::cookiejar::to_ascii(&host)
        .ok_or_else(|| -> BoxError { "idna: invalid label".into() })?;
    if port.is_empty() {
        Ok(host)
    } else {
        Ok(crate::net::join_host_port(&host, &port))
    }
}

/// `httpguts.ValidHostHeader`.
pub(crate) fn valid_host_header(h: &str) -> bool {
    h.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"!$%&()*+,-.:;=[]'_~".contains(&b))
}

fn remove_zone(host: &str) -> String {
    if !host.starts_with('[') {
        return host.to_owned();
    }
    let Some(i) = host.rfind(']') else {
        return host.to_owned();
    };
    let Some(j) = host[..i].rfind('%') else {
        return host.to_owned();
    };
    format!("{}{}", &host[..j], &host[i..])
}

// --------------------------------------------------------------- reading

const ERR_TOO_LARGE: ErrorString = ErrorString("http: request too large");

/// Go's `ReadRequest`: parses one request from `b`. The body streams from
/// `b` as the caller reads it.
pub fn read_request(b: &BufioReader) -> Result<Request, BoxError> {
    let mut req = read_request_limit(b, i64::MAX)?;
    req.id = next_request_id();
    req.header.0.remove("Host");
    Ok(req)
}

pub(crate) fn read_request_limit(b: &BufioReader, max_headers: i64) -> Result<Request, BoxError> {
    let limits = textproto::Limits {
        max_line_bytes: usize::MAX / 2,
        max_header_bytes: usize::MAX / 2,
        max_headers: usize::try_from(max_headers).unwrap_or(usize::MAX),
        ..textproto::Limits::default()
    };
    let (line, header) = {
        let mut guard = b.lock();
        let mut tp = textproto::Reader::with_limits(&mut *guard, limits);
        let line = tp.read_line_bytes().map_err(textproto_err)?;
        let head = read_request_head(&line, &mut tp, max_headers);
        (line, head)
    };
    let _ = line;
    let mut req = header.map_err(unexpected)?;
    fix_pragma_cache_control(&mut req.header);
    req.close = should_close(req.proto_major, req.proto_minor, &mut req.header, false);
    let t = read_transfer(
        MsgIn {
            is_response: false,
            header: &mut req.header,
            status_code: 200,
            request_method: req.method.clone(),
            proto_major: req.proto_major,
            proto_minor: req.proto_minor,
            close: req.close,
        },
        b,
        max_headers,
    )
    .map_err(unexpected)?;
    req.body = Some(t.body);
    req.body_handle = t.handle;
    req.content_length = t.content_length;
    if t.chunked {
        req.transfer_encoding = vec!["chunked".into()];
    }
    req.close = t.close;
    req.trailer = t.trailer_cell;
    if req.is_h2_upgrade() {
        req.content_length = -1;
        req.close = true;
    }
    Ok(req)
}

/// The deferred `io.EOF` to `io.ErrUnexpectedEOF` conversion.
fn unexpected(e: BoxError) -> BoxError {
    if e.downcast_ref::<ErrorString>() == Some(&ERR_EOF) {
        Box::new(ERR_UNEXPECTED_EOF)
    } else {
        e
    }
}

fn read_request_head<R: io::BufRead>(
    s: &[u8],
    tp: &mut textproto::Reader<R>,
    _max_headers: i64,
) -> Result<Request, BoxError> {
    let mut req = Request::default();
    let bad = || bad_string_error("malformed HTTP request", s);
    let sp1 = s.iter().position(|&b| b == b' ').ok_or_else(bad)?;
    let (method, rest) = (&s[..sp1], &s[sp1 + 1..]);
    let sp2 = rest.iter().position(|&b| b == b' ').ok_or_else(bad)?;
    let (request_uri, proto) = (&rest[..sp2], &rest[sp2 + 1..]);
    req.method = String::from_utf8_lossy(method).into_owned();
    req.request_uri = String::from_utf8_lossy(request_uri).into_owned();
    req.proto = String::from_utf8_lossy(proto).into_owned();
    if method.is_empty()
        || !method
            .iter()
            .all(|&b| super::token(&(b as char).to_string()) && b < 0x80)
    {
        return Err(bad_string_error("invalid method", method));
    }
    let Some((maj, min)) = std::str::from_utf8(proto).ok().and_then(parse_http_version) else {
        return Err(bad_string_error("malformed HTTP version", proto));
    };
    req.proto_major = maj as i32;
    req.proto_minor = min as i32;
    let mut rawurl = req.request_uri.clone();
    let just_authority = req.method == "CONNECT" && !rawurl.starts_with('/');
    if just_authority {
        rawurl = format!("http://{rawurl}");
    }
    req.url = url::parse_request_uri(&rawurl)?;
    if just_authority {
        req.url.scheme.clear();
    }
    let mime = match tp.read_mime_header() {
        Ok(h) => h,
        Err(textproto::Error::MessageTooLarge) => return Err(Box::new(ERR_TOO_LARGE)),
        Err(e) => return Err(textproto_err(e)),
    };
    req.header = Header(mime.into_map());
    if req.header.0.get("Host").is_some_and(|v| v.len() > 1) {
        return Err("too many Host headers".into());
    }
    req.host = req.url.host.clone();
    if req.host.is_empty() {
        req.host = req.header.get_exact("Host").to_owned();
    }
    Ok(req)
}

#[allow(dead_code)]
fn _unused(_: Option<ErrorString>, _: Option<&str>) {
    let _ = ERR_MISSING_BOUNDARY;
    let _ = mime_unused;
}
#[allow(dead_code)]
fn mime_unused() -> Option<Response> {
    None
}
