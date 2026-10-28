//! Go's `http.Header`, `ParseTime`, `ParseHTTPVersion`, `ProtocolError`, the
//! sentinel errors and small value types shared by the Go-shaped API.
#![allow(clippy::type_complexity)]
use super::httptrace::ClientTrace;
use crate::net::textproto::{canonical_mime_header_key, trim_string};
use crate::time::{self, Time};
use std::{borrow::Cow, collections::BTreeMap, error, fmt, io};

pub type BoxError = Box<dyn error::Error + Send + Sync>;

/// A sentinel error made with Go's `errors.New`; equal messages are equal
/// errors, standing in for Go's pointer identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErrorString(pub &'static str);
impl fmt::Display for ErrorString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl error::Error for ErrorString {}

/// Go's `*http.ProtocolError`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolError {
    pub error_string: Cow<'static, str>,
}
impl ProtocolError {
    pub const fn new(text: &'static str) -> Self {
        Self {
            error_string: Cow::Borrowed(text),
        }
    }
    /// Go's `ErrorString` field.
    pub fn error_string(&self) -> &str {
        &self.error_string
    }
    /// Go's `Is`: `ErrNotSupported` matches `errors.ErrUnsupported`.
    pub fn is(&self, err: &(dyn error::Error + 'static)) -> bool {
        *self == ERR_NOT_SUPPORTED && err.to_string() == "unsupported operation"
    }
}
impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.error_string)
    }
}
impl error::Error for ProtocolError {}

pub const ERR_EOF: ErrorString = ErrorString("EOF");
pub const ERR_UNEXPECTED_EOF: ErrorString = ErrorString("unexpected EOF");
pub const ERR_NOT_SUPPORTED: ProtocolError = ProtocolError::new("feature not supported");
pub const ERR_UNEXPECTED_TRAILER: ProtocolError =
    ProtocolError::new("trailer header without chunked transfer encoding");
pub const ERR_MISSING_BOUNDARY: ProtocolError =
    ProtocolError::new("no multipart boundary param in Content-Type");
pub const ERR_NOT_MULTIPART: ProtocolError =
    ProtocolError::new("request Content-Type isn't multipart/form-data");
pub const ERR_HEADER_TOO_LONG: ProtocolError = ProtocolError::new("header too long");
pub const ERR_SHORT_BODY: ProtocolError = ProtocolError::new("entity body too short");
pub const ERR_MISSING_CONTENT_LENGTH: ProtocolError =
    ProtocolError::new("missing ContentLength in HEAD response");
pub const ERR_MISSING_FILE: ErrorString = ErrorString("http: no such file");
pub const ERR_NO_COOKIE: ErrorString = ErrorString("http: named cookie not present");
pub const ERR_NO_LOCATION: ErrorString = ErrorString("http: no Location header in response");
pub const ERR_USE_LAST_RESPONSE: ErrorString = ErrorString("net/http: use last response");
pub const ERR_SCHEME_MISMATCH: ErrorString =
    ErrorString("http: server gave HTTP response to HTTPS client");
pub const ERR_BODY_NOT_ALLOWED: ErrorString =
    ErrorString("http: request method or response status code does not allow body");
pub const ERR_HIJACKED: ErrorString = ErrorString("http: connection has been hijacked");
pub const ERR_CONTENT_LENGTH: ErrorString =
    ErrorString("http: wrote more than the declared Content-Length");
pub const ERR_WRITE_AFTER_FLUSH: ErrorString = ErrorString("unused");
pub const ERR_ABORT_HANDLER: ErrorString = ErrorString("net/http: abort Handler");
pub const ERR_SERVER_CLOSED: ErrorString = ErrorString("http: Server closed");
pub const ERR_HANDLER_TIMEOUT: ErrorString = ErrorString("http: Handler timeout");
pub const ERR_LINE_TOO_LONG: ErrorString = ErrorString("header line too long");
pub const ERR_BODY_READ_AFTER_CLOSE: ErrorString = ErrorString("http: invalid Read on closed Body");
pub const ERR_SKIP_ALT_PROTOCOL: ErrorString = ErrorString("net/http: skip alternate protocol");

/// True if `err`, or an error it wraps (including through `io::Error`), is `target`.
pub fn is_error<E: error::Error + PartialEq + 'static>(
    err: &(dyn error::Error + 'static),
    target: &E,
) -> bool {
    let mut cur: Option<&(dyn error::Error + 'static)> = Some(err);
    while let Some(e) = cur {
        if e.downcast_ref::<E>() == Some(target) {
            return true;
        }
        if let Some(io) = e.downcast_ref::<io::Error>() {
            if let Some(inner) = io.get_ref() {
                let inner: &(dyn error::Error + 'static) = inner;
                if inner.downcast_ref::<E>() == Some(target) {
                    return true;
                }
            }
        }
        cur = e.source();
    }
    false
}
/// Wraps a sentinel error as an `io::Error` so body readers can return it.
pub fn io_error<E: error::Error + Send + Sync + 'static>(err: E) -> io::Error {
    io::Error::other(err)
}

/// Go's `http.Header`: a multimap. The public map allows non-canonical keys
/// exactly as Go's map type does; the methods canonicalize.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header(pub BTreeMap<String, Vec<String>>);

impl Header {
    pub fn new() -> Self {
        Self::default()
    }
    /// Go's `Add`.
    pub fn add(&mut self, key: &str, value: &str) {
        self.0
            .entry(canonical_mime_header_key(key))
            .or_default()
            .push(value.to_owned());
    }
    /// Go's `Set`.
    pub fn set(&mut self, key: &str, value: &str) {
        self.0
            .insert(canonical_mime_header_key(key), vec![value.to_owned()]);
    }
    /// Go's `Get`: the first value of the canonical key. `None` when the key
    /// is absent; Go's `""` for a missing key is `unwrap_or("")` and a present
    /// empty value is `Some("")`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0
            .get(&canonical_mime_header_key(key))
            .and_then(|v| v.first())
            .map(String::as_str)
    }
    /// `get` with Go's `""` for a missing key.
    pub(crate) fn get_str(&self, key: &str) -> &str {
        self.get(key).unwrap_or("")
    }
    /// Go's `Values`.
    pub fn values(&self, key: &str) -> Vec<String> {
        self.0
            .get(&canonical_mime_header_key(key))
            .cloned()
            .unwrap_or_default()
    }
    /// Go's unexported `get`: exact (already canonical) key, first value.
    pub(crate) fn get_exact(&self, key: &str) -> &str {
        self.0
            .get(key)
            .and_then(|v| v.first())
            .map_or("", String::as_str)
    }
    pub(crate) fn has(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }
    /// Go's `Del`.
    pub fn del(&mut self, key: &str) {
        self.0.remove(&canonical_mime_header_key(key));
    }
    /// Go's `Write`.
    pub fn write(&self, w: &mut dyn io::Write) -> io::Result<()> {
        self.write_subset(w, &BTreeMap::new())
    }
    /// Go's `WriteSubset`: sorted keys, invalid names skipped, CR/LF in values
    /// replaced by spaces and values trimmed.
    pub fn write_subset(
        &self,
        w: &mut dyn io::Write,
        exclude: &BTreeMap<String, bool>,
    ) -> io::Result<()> {
        self.write_subset_traced(w, exclude, None)
    }
    /// Go's `writeSubset` with its `trace` argument: after each key's values
    /// are written, `WroteHeaderField` is called with the key and the values
    /// as written.
    pub(crate) fn write_subset_traced(
        &self,
        w: &mut dyn io::Write,
        exclude: &BTreeMap<String, bool>,
        trace: Option<&ClientTrace>,
    ) -> io::Result<()> {
        let hook = trace.and_then(|t| t.wrote_header_field.as_ref());
        for (k, vv) in &self.0 {
            if exclude.get(k).copied().unwrap_or(false) || !valid_header_field_name(k) {
                continue;
            }
            let mut formatted = Vec::new();
            for v in vv {
                let v = v.replace(['\n', '\r'], " ");
                let v = trim_string(&v);
                write!(w, "{k}: {v}\r\n")?;
                if hook.is_some() {
                    formatted.push(v.to_owned());
                }
            }
            if let Some(hook) = hook {
                hook(k, &formatted);
            }
        }
        Ok(())
    }
    pub(crate) fn write_excluding(
        &self,
        w: &mut dyn io::Write,
        exclude: &[&str],
        trace: Option<&ClientTrace>,
    ) -> io::Result<()> {
        let map: BTreeMap<String, bool> = exclude.iter().map(|k| ((*k).to_owned(), true)).collect();
        self.write_subset_traced(w, &map, trace)
    }
}

/// A request or response `Trailer`: Go's `Header` map shared by every copy of
/// the message, because the body fills it in after the last chunk is read.
/// `None` is a nil map.
#[derive(Clone, Debug, Default)]
pub struct Trailer(std::sync::Arc<std::sync::Mutex<Option<Header>>>);
impl Trailer {
    pub fn new(h: Option<Header>) -> Self {
        Self(std::sync::Arc::new(std::sync::Mutex::new(h)))
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Header>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn get(&self) -> Option<Header> {
        self.lock().clone()
    }
    pub fn set(&self, h: Option<Header>) {
        *self.lock() = h;
    }
    pub fn is_nil(&self) -> bool {
        self.lock().is_none()
    }
    /// Go's `mergeSetHeader`.
    pub(crate) fn merge(&self, src: Header) {
        let mut g = self.lock();
        match g.as_mut() {
            None => *g = Some(src),
            Some(dst) => dst.0.extend(src.0),
        }
    }
    /// An independent copy (Go's `Header.Clone`).
    pub fn deep_clone(&self) -> Self {
        Self::new(self.get())
    }
}
impl PartialEq for Trailer {
    fn eq(&self, o: &Self) -> bool {
        self.get() == o.get()
    }
}

/// `httpguts.ValidHeaderFieldName`: a non-empty RFC 7230 token.
pub fn valid_header_field_name(v: &str) -> bool {
    super::token(v)
}
/// `httpguts.ValidHeaderFieldValue`: no control bytes except SP and HTAB.
pub fn valid_header_field_value(v: &str) -> bool {
    v.bytes()
        .all(|b| !(b < b' ' || b == 0x7f) || b == b' ' || b == b'\t')
}
fn is_token_boundary(b: u8) -> bool {
    matches!(b, b' ' | b',' | b'\t')
}
/// Go's unexported `hasToken`: an ASCII case-insensitive `token` bounded by
/// space, comma, tab or the ends of `v`.
pub(crate) fn has_token(v: &str, token: &str) -> bool {
    let (v, token) = (v.as_bytes(), token.as_bytes());
    if token.len() > v.len() || token.is_empty() {
        return false;
    }
    (0..=v.len() - token.len()).any(|sp| {
        (sp == 0 || is_token_boundary(v[sp - 1]))
            && (sp + token.len() == v.len() || is_token_boundary(v[sp + token.len()]))
            && v[sp..sp + token.len()].eq_ignore_ascii_case(token)
    })
}
/// `httpguts.HeaderValuesContainsToken`: comma-separated elements trimmed of
/// optional whitespace, compared ASCII case-insensitively.
pub(crate) fn values_contain_token(values: &[String], token: &str) -> bool {
    values.iter().any(|v| {
        v.split(',').any(|element| {
            let element = element.trim_matches([' ', '\t']);
            element.is_ascii() && element.eq_ignore_ascii_case(token)
        })
    })
}

/// Go's `CanonicalHeaderKey`.
pub fn canonical_header_key(s: &str) -> String {
    canonical_mime_header_key(s)
}

/// Go's `ParseTime`: `TimeFormat`, then RFC 850, then ANSI C.
pub fn parse_time(text: &str) -> Result<Time, time::ParseError> {
    let mut last = None;
    for layout in [super::TIME_FORMAT, time::RFC850, time::ANSIC] {
        match time::Time::parse(layout, text) {
            Ok(t) => return Ok(t),
            Err(e) => last = Some(e),
        }
    }
    Err(last.expect("at least one layout"))
}

/// Go's `ParseHTTPVersion`.
pub fn parse_http_version(vers: &str) -> Option<(u32, u32)> {
    match vers {
        "HTTP/1.1" => return Some((1, 1)),
        "HTTP/1.0" => return Some((1, 0)),
        _ => {}
    }
    let b = vers.as_bytes();
    if !vers.starts_with("HTTP/") || b.len() != 8 || b[6] != b'.' {
        return None;
    }
    if !b[5].is_ascii_digit() || !b[7].is_ascii_digit() {
        return None;
    }
    Some((u32::from(b[5] - b'0'), u32::from(b[7] - b'0')))
}

/// Go's `http.Protocols` bit set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Protocols {
    bits: u8,
}
impl Protocols {
    const HTTP1: u8 = 1;
    const HTTP2: u8 = 2;
    const UNENCRYPTED_HTTP2: u8 = 4;
    fn set_bit(&mut self, bit: u8, ok: bool) {
        if ok {
            self.bits |= bit;
        } else {
            self.bits &= !bit;
        }
    }
    pub fn http1(&self) -> bool {
        self.bits & Self::HTTP1 != 0
    }
    pub fn set_http1(&mut self, ok: bool) {
        self.set_bit(Self::HTTP1, ok);
    }
    pub fn http2(&self) -> bool {
        self.bits & Self::HTTP2 != 0
    }
    pub fn set_http2(&mut self, ok: bool) {
        self.set_bit(Self::HTTP2, ok);
    }
    pub fn unencrypted_http2(&self) -> bool {
        self.bits & Self::UNENCRYPTED_HTTP2 != 0
    }
    pub fn set_unencrypted_http2(&mut self, ok: bool) {
        self.set_bit(Self::UNENCRYPTED_HTTP2, ok);
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.bits == 0
    }
}
impl fmt::Display for Protocols {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = Vec::new();
        if self.http1() {
            s.push("HTTP1");
        }
        if self.http2() {
            s.push("HTTP2");
        }
        if self.unencrypted_http2() {
            s.push("UnencryptedHTTP2");
        }
        write!(f, "{{{}}}", s.join(","))
    }
}

/// Go's `http.HTTP2Config`. HTTP/2 is a later wave; the fields are inert.
#[derive(Clone, Default)]
pub struct Http2Config {
    pub max_concurrent_streams: i64,
    pub strict_max_concurrent_requests: bool,
    pub max_decoder_header_table_size: i64,
    pub max_encoder_header_table_size: i64,
    pub max_read_frame_size: i64,
    pub max_receive_buffer_per_connection: i64,
    pub max_receive_buffer_per_stream: i64,
    pub send_ping_timeout: crate::time::Duration,
    pub ping_timeout: crate::time::Duration,
    pub write_byte_timeout: crate::time::Duration,
    pub permit_prohibited_cipher_suites: bool,
    pub count_error: Option<std::sync::Arc<dyn Fn(&str) + Send + Sync>>,
}
impl fmt::Debug for Http2Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Http2Config")
    }
}

/// Go's `http.PushOptions`.
#[derive(Clone, Debug, Default)]
pub struct PushOptions {
    pub method: String,
    pub header: Header,
}
/// Go's `http.Pusher`. Server push needs HTTP/2.
pub trait Pusher {
    fn push(&mut self, target: &str, opts: Option<&PushOptions>) -> Result<(), BoxError>;
}

/// Go's `removePort`.
pub(crate) fn remove_port(host: &str) -> &str {
    for (i, c) in host.bytes().enumerate().rev() {
        match c {
            b':' => return &host[..i],
            b']' => return host,
            _ => {}
        }
    }
    host
}
pub(crate) fn contains_ctl_byte(s: &str) -> bool {
    s.bytes().any(|b| b < b' ' || b == 0x7f)
}

/// Wrapper used to keep a `textproto` error as a source.
#[derive(Debug)]
pub struct ErrorOrText(pub crate::net::textproto::Error);
impl fmt::Display for ErrorOrText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl error::Error for ErrorOrText {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        error::Error::source(&self.0)
    }
}

/// Maps a textproto error to the Go error value: `io.EOF`,
/// `io.ErrUnexpectedEOF` or the error itself.
pub(crate) fn textproto_err(e: crate::net::textproto::Error) -> BoxError {
    use crate::net::textproto::Error as E;
    match e {
        E::Eof => Box::new(ERR_EOF),
        E::UnexpectedEof => Box::new(ERR_UNEXPECTED_EOF),
        E::Io(e) if e.kind() == io::ErrorKind::UnexpectedEof => Box::new(ERR_UNEXPECTED_EOF),
        other => Box::new(ErrorOrText(other)),
    }
}
