//! Go's `transfer.go`: message framing for `Request.Write`, `Response.Write`,
//! `ReadRequest` and `ReadResponse`.
use super::body::{Body, NoBody, ReadCloser};
use super::header::{
    canonical_header_key, has_token, io_error, valid_header_field_name, valid_header_field_value,
    values_contain_token, BoxError, ErrorString, Header, Trailer, ERR_LINE_TOO_LONG,
};
use super::httptrace::ClientTrace;
use super::request::Request;
use super::response::Response;
use crate::bufio;
use crate::net::textproto::{self, trim_string};
use crate::strconv::quote;
use std::{
    io::{self, Read, Write},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

/// A shared, buffered reader: the stand-in for Go's `*bufio.Reader` that
/// request and response bodies keep reading from after `ReadRequest` returns.
#[derive(Clone)]
pub struct BufioReader(Arc<Mutex<bufio::Reader<Box<dyn Read + Send>>>>);
impl BufioReader {
    pub fn new<R: Read + Send + 'static>(reader: R) -> Self {
        Self(Arc::new(Mutex::new(bufio::Reader::new(Box::new(reader)))))
    }
    pub fn with_size<R: Read + Send + 'static>(reader: R, size: usize) -> Self {
        Self(Arc::new(Mutex::new(bufio::Reader::with_size(
            Box::new(reader),
            size,
        ))))
    }
    pub(crate) fn lock(&self) -> MutexGuard<'_, bufio::Reader<Box<dyn Read + Send>>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
    /// Bytes already buffered (`Reader.Buffered`).
    pub fn buffered(&self) -> usize {
        self.lock().buffered()
    }
    pub fn ptr_eq(&self, other: &BufioReader) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Read for BufioReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.lock().read(buf)
    }
}

pub(crate) fn bad_string_error(what: &str, val: impl AsRef<[u8]>) -> BoxError {
    format!("{what} {}", quote(val)).into()
}

/// `io.ErrUnexpectedEOF` as an `io::Error` whose text is Go's.
pub(crate) fn unexpected_eof() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        super::header::ERR_UNEXPECTED_EOF,
    )
}

pub(crate) fn chunked(te: &[String]) -> bool {
    te.first().is_some_and(|s| s == "chunked")
}
pub(crate) fn is_identity(te: &[String]) -> bool {
    te.len() == 1 && te[0] == "identity"
}
pub(crate) fn no_response_body_expected(method: &str) -> bool {
    method == "HEAD"
}
pub(crate) fn body_allowed_for_status(status: u16) -> bool {
    !((100..=199).contains(&status) || status == 204 || status == 304)
}
pub(crate) fn suppressed_headers(status: u16) -> &'static [&'static str] {
    if status == 304 {
        &["Content-Type", "Content-Length", "Transfer-Encoding"]
    } else if !body_allowed_for_status(status) {
        &["Content-Length", "Transfer-Encoding"]
    } else {
        &[]
    }
}
fn request_method_usually_lacks_body(method: &str) -> bool {
    matches!(
        method,
        "GET" | "HEAD" | "DELETE" | "OPTIONS" | "PROPFIND" | "SEARCH"
    )
}

/// Go's `unsupportedTEError`.
#[derive(Debug)]
pub struct UnsupportedTeError(pub String);
impl std::fmt::Display for UnsupportedTeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for UnsupportedTeError {}

/// Go's `validateHeaders` for trailers: returns the message of the first bad
/// key or value.
pub(crate) fn validate_headers(h: &Header) -> String {
    for (k, vv) in &h.0 {
        if !valid_header_field_name(k) {
            return format!("field name {}", quote(k));
        }
        for v in vv {
            if !valid_header_field_value(v) {
                return format!("field value for {}", quote(k));
            }
        }
    }
    String::new()
}

pub(crate) struct TransferWriter {
    pub method: String,
    pub body: Option<Body>,
    pub response_to_head: bool,
    pub content_length: i64,
    pub close: bool,
    pub transfer_encoding: Vec<String>,
    pub header: Header,
    pub trailer: Option<Trailer>,
    pub is_response: bool,
    pub body_read_error: Option<String>,
    pub flush_headers: bool,
    pub body_closer: Option<Body>,
}

impl TransferWriter {
    pub fn for_request(r: &Request) -> Result<Self, BoxError> {
        if r.content_length != 0 && r.body.is_none() {
            return Err(format!(
                "http: Request.ContentLength={} with nil Body",
                r.content_length
            )
            .into());
        }
        let method = value_or_default(&r.method, "GET").to_owned();
        let mut t = TransferWriter {
            method,
            body: r.body.clone(),
            body_closer: r.body.clone(),
            response_to_head: false,
            content_length: r.outgoing_length(),
            close: r.close,
            transfer_encoding: r.transfer_encoding.clone(),
            header: r.header.clone(),
            trailer: if r.trailer.is_nil() {
                None
            } else {
                Some(r.trailer.clone())
            },
            is_response: false,
            body_read_error: None,
            flush_headers: false,
        };
        if t.content_length < 0
            && t.transfer_encoding.is_empty()
            && t.should_send_chunked_request_body()
        {
            t.transfer_encoding = vec!["chunked".to_owned()];
        }
        if t.content_length != 0 && !t.body.as_ref().is_some_and(Body::is_in_memory) {
            t.flush_headers = true;
        }
        t.finish_new(true)
    }

    pub fn for_response(r: &Response) -> Result<Self, BoxError> {
        let method = r
            .request
            .as_ref()
            .map(|q| q.method.clone())
            .unwrap_or_default();
        let t = TransferWriter {
            response_to_head: no_response_body_expected(&method),
            method,
            body: r.body.clone(),
            body_closer: r.body.clone(),
            content_length: r.content_length,
            close: r.close,
            transfer_encoding: r.transfer_encoding.clone(),
            header: r.header.clone(),
            trailer: if r.trailer.is_nil() {
                None
            } else {
                Some(r.trailer.clone())
            },
            is_response: true,
            body_read_error: None,
            flush_headers: false,
        };
        t.finish_new(r.proto_at_least(1, 1))
    }

    fn finish_new(mut self, at_least_http11: bool) -> Result<Self, BoxError> {
        if self.response_to_head {
            self.body = None;
            if chunked(&self.transfer_encoding) {
                self.content_length = -1;
            }
        } else {
            if !at_least_http11 || self.body.is_none() {
                self.transfer_encoding.clear();
            }
            if chunked(&self.transfer_encoding) {
                self.content_length = -1;
            } else if self.body.is_none() {
                self.content_length = 0;
            }
        }
        if !chunked(&self.transfer_encoding) {
            self.trailer = None;
        }
        if let Some(tr) = self.trailer.as_ref().and_then(Trailer::get) {
            let err = validate_headers(&tr);
            if !err.is_empty() {
                return Err(format!("net/http: invalid trailer {err}").into());
            }
        }
        Ok(self)
    }

    fn should_send_chunked_request_body(&mut self) -> bool {
        if self.content_length >= 0 || self.body.is_none() {
            return false;
        }
        if self.method == "CONNECT" {
            return false;
        }
        if request_method_usually_lacks_body(&self.method) {
            self.probe_request_body();
            return self.body.is_some();
        }
        true
    }

    /// Go's `probeRequestBody`: reads one byte, waiting at most 200 ms.
    fn probe_request_body(&mut self) {
        let Some(body) = self.body.clone() else {
            return;
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let mut reader = body.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1];
            let res = match reader.read(&mut buf) {
                Ok(0) => (None, None),
                Ok(_) => (Some(buf[0]), None),
                Err(e) => (None, Some(e)),
            };
            let _ = tx.send(res);
        });
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok((None, None)) => {
                self.body = None;
                self.content_length = 0;
            }
            Ok((Some(b), err)) => {
                let tail: Box<dyn Read + Send> = match err {
                    Some(e) => Box::new(ErrorReader(Some(e))),
                    None => Box::new(body),
                };
                self.body = Some(Body::from_reader(io::Read::chain(
                    io::Cursor::new(vec![b]),
                    tail,
                )));
            }
            Ok((None, Some(e))) => {
                self.body = Some(Body::from_reader(ErrorReader(Some(e))));
            }
            Err(_) => {
                // Slow body: finish the pending read when the body is copied.
                self.flush_headers = true;
                self.body = Some(Body::from_reader(io::Read::chain(
                    FinishAsyncByteRead(Some(rx)),
                    body,
                )));
            }
        }
    }

    pub fn should_send_content_length(&self) -> bool {
        if chunked(&self.transfer_encoding) {
            return false;
        }
        if self.content_length > 0 {
            return true;
        }
        if self.content_length < 0 {
            return false;
        }
        if matches!(self.method.as_str(), "POST" | "PUT" | "PATCH") {
            return true;
        }
        if self.content_length == 0 && is_identity(&self.transfer_encoding) {
            return !matches!(self.method.as_str(), "GET" | "HEAD");
        }
        false
    }

    pub fn write_header(
        &self,
        w: &mut dyn Write,
        trace: Option<&ClientTrace>,
    ) -> Result<(), BoxError> {
        let hook = trace.and_then(|t| t.wrote_header_field.as_ref());
        if self.close && !has_token(self.header.get_exact("Connection"), "close") {
            w.write_all(b"Connection: close\r\n")?;
            if let Some(hook) = hook {
                hook("Connection", &["close".to_owned()]);
            }
        }
        if self.should_send_content_length() {
            write!(w, "Content-Length: {}\r\n", self.content_length)?;
            if let Some(hook) = hook {
                hook("Content-Length", &[self.content_length.to_string()]);
            }
        } else if chunked(&self.transfer_encoding) {
            w.write_all(b"Transfer-Encoding: chunked\r\n")?;
            if let Some(hook) = hook {
                hook("Transfer-Encoding", &["chunked".to_owned()]);
            }
        }
        if let Some(trailer) = self.trailer.as_ref().and_then(Trailer::get) {
            let mut keys = Vec::new();
            for k in trailer.0.keys() {
                let k = canonical_header_key(k);
                if matches!(
                    k.as_str(),
                    "Transfer-Encoding" | "Trailer" | "Content-Length"
                ) {
                    return Err(bad_string_error("invalid Trailer key", &k));
                }
                keys.push(k);
            }
            if !keys.is_empty() {
                keys.sort();
                write!(w, "Trailer: {}\r\n", keys.join(","))?;
                if let Some(hook) = hook {
                    hook("Trailer", &keys);
                }
            }
        }
        Ok(())
    }

    /// Go's `writeBody`. `flush_after_chunk` mirrors `FlushAfterChunkWriter`.
    pub fn write_body(
        &mut self,
        w: &mut dyn Write,
        flush_after_chunk: bool,
    ) -> Result<(), BoxError> {
        let mut ncopy: i64 = 0;
        let mut closed = false;
        let result = self.write_body_inner(w, flush_after_chunk, &mut ncopy, &mut closed);
        if !closed {
            if let Some(c) = &self.body_closer {
                let close_err = c.close();
                if result.is_ok() {
                    close_err?;
                }
            }
        }
        result
    }

    fn write_body_inner(
        &mut self,
        w: &mut dyn Write,
        flush_after_chunk: bool,
        ncopy: &mut i64,
        closed: &mut bool,
    ) -> Result<(), BoxError> {
        if !self.response_to_head {
            if let Some(body) = self.body.clone() {
                let mut body = body;
                if chunked(&self.transfer_encoding) {
                    self.copy_chunked(w, &mut body, flush_after_chunk)?;
                    w.write_all(b"0\r\n")?;
                } else if self.content_length == -1 {
                    let flush = self.method == "CONNECT";
                    *ncopy = self.copy_plain(w, &mut body, i64::MAX, flush)?;
                } else {
                    let n = self.copy_plain(w, &mut body, self.content_length, false)?;
                    let extra = self.copy_plain(&mut io::sink(), &mut body, i64::MAX, false)?;
                    *ncopy = n + extra;
                }
            }
        }
        if let Some(c) = &self.body_closer {
            *closed = true;
            c.close()?;
        }
        if !self.response_to_head && self.content_length != -1 && self.content_length != *ncopy {
            return Err(format!(
                "http: ContentLength={} with Body length {}",
                self.content_length, ncopy
            )
            .into());
        }
        if !self.response_to_head && chunked(&self.transfer_encoding) {
            if let Some(tr) = self.trailer.as_ref().and_then(Trailer::get) {
                tr.write(w)?;
            }
            w.write_all(b"\r\n")?;
        }
        Ok(())
    }

    fn copy_chunked(
        &mut self,
        w: &mut dyn Write,
        src: &mut Body,
        flush: bool,
    ) -> Result<(), BoxError> {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = match src.read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    self.body_read_error = Some(e.to_string());
                    return Err(Box::new(e));
                }
            };
            write!(w, "{n:x}\r\n")?;
            w.write_all(&buf[..n])?;
            w.write_all(b"\r\n")?;
            if flush {
                w.flush()?;
            }
        }
    }

    /// Copies at most `limit` bytes; read errors are recorded in
    /// `body_read_error`, write errors are returned.
    fn copy_plain(
        &mut self,
        w: &mut dyn Write,
        src: &mut Body,
        limit: i64,
        flush: bool,
    ) -> Result<i64, BoxError> {
        let mut buf = vec![0u8; 32 * 1024];
        let mut total: i64 = 0;
        while total < limit {
            let want = usize::try_from((limit - total).min(buf.len() as i64)).unwrap_or(buf.len());
            let n = match src.read(&mut buf[..want]) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    self.body_read_error = Some(e.to_string());
                    return Err(Box::new(e));
                }
            };
            w.write_all(&buf[..n])?;
            if flush {
                w.flush()?;
            }
            total += n as i64;
        }
        Ok(total)
    }
}

struct ErrorReader(Option<io::Error>);
impl Read for ErrorReader {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(self
            .0
            .take()
            .unwrap_or_else(|| io::Error::other("read error")))
    }
}
struct FinishAsyncByteRead(Option<std::sync::mpsc::Receiver<(Option<u8>, Option<io::Error>)>>);
impl Read for FinishAsyncByteRead {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        if p.is_empty() {
            return Ok(0);
        }
        let Some(rx) = self.0.take() else {
            return Ok(0);
        };
        match rx.recv() {
            Ok((Some(b), None)) => {
                p[0] = b;
                Ok(1)
            }
            Ok((Some(b), Some(_))) => {
                p[0] = b;
                Ok(1)
            }
            Ok((None, Some(e))) => Err(e),
            _ => Ok(0),
        }
    }
}

pub(crate) fn value_or_default<'a>(value: &'a str, def: &'a str) -> &'a str {
    if value.is_empty() {
        def
    } else {
        value
    }
}

// ---------------------------------------------------------------- reading

pub(crate) fn should_close(
    major: i32,
    minor: i32,
    header: &mut Header,
    remove_close: bool,
) -> bool {
    if major < 1 {
        return true;
    }
    let conv = header.0.get("Connection").cloned().unwrap_or_default();
    let has_close = values_contain_token(&conv, "close");
    if major == 1 && minor == 0 {
        return has_close || !values_contain_token(&conv, "keep-alive");
    }
    if has_close && remove_close {
        header.0.remove("Connection");
    }
    has_close
}

pub(crate) fn fix_pragma_cache_control(header: &mut Header) {
    if header
        .0
        .get("Pragma")
        .and_then(|v| v.first())
        .is_some_and(|v| v == "no-cache")
        && !header.0.contains_key("Cache-Control")
    {
        header
            .0
            .insert("Cache-Control".to_owned(), vec!["no-cache".to_owned()]);
    }
}

pub(crate) fn parse_content_length(cl_headers: &[String]) -> Result<i64, BoxError> {
    if cl_headers.is_empty() {
        return Ok(-1);
    }
    let cl = trim_string(&cl_headers[0]);
    if cl.is_empty() {
        return Err(bad_string_error("invalid empty Content-Length", cl));
    }
    // strconv.ParseUint(cl, 10, 63)
    if !cl.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad_string_error("bad Content-Length", cl));
    }
    match cl.parse::<u64>() {
        Ok(n) if n <= i64::MAX as u64 => Ok(n as i64),
        _ => Err(bad_string_error("bad Content-Length", cl)),
    }
}

fn fix_length(
    is_response: bool,
    status: u16,
    request_method: &str,
    header: &mut Header,
    is_chunked: bool,
) -> Result<i64, BoxError> {
    let is_request = !is_response;
    let mut content_lens = header.0.get("Content-Length").cloned().unwrap_or_default();
    if content_lens.len() > 1 {
        let first = trim_string(&content_lens[0]).to_owned();
        for ct in &content_lens[1..] {
            if first != trim_string(ct) {
                return Err(format!(
                    "http: message cannot contain multiple Content-Length headers; got {}",
                    quote_list(&content_lens)
                )
                .into());
            }
        }
        header.0.remove("Content-Length");
        header.add("Content-Length", &first);
        content_lens = header.0.get("Content-Length").cloned().unwrap_or_default();
    }
    let mut n = 0;
    if !content_lens.is_empty() {
        n = parse_content_length(&content_lens)?;
    }
    if is_response && no_response_body_expected(request_method) {
        return Ok(0);
    }
    if status / 100 == 1 {
        return Ok(0);
    }
    if status == 204 || status == 304 {
        return Ok(0);
    }
    if is_chunked {
        header.0.remove("Content-Length");
        return Ok(-1);
    }
    if !content_lens.is_empty() {
        return Ok(n);
    }
    header.0.remove("Content-Length");
    if is_request {
        return Ok(0);
    }
    Ok(-1)
}

/// Go's `%q` of a `[]string`.
pub(crate) fn quote_list(v: &[String]) -> String {
    let items: Vec<String> = v.iter().map(quote).collect();
    format!("[{}]", items.join(" "))
}

fn foreach_header_element(v: &str, mut f: impl FnMut(&str)) {
    let v = trim_string(v);
    if v.is_empty() {
        return;
    }
    if !v.contains(',') {
        f(v);
        return;
    }
    for t in v.split(',') {
        let t = trim_string(t);
        if !t.is_empty() {
            f(t);
        }
    }
}

fn fix_trailer(header: &mut Header, is_chunked: bool) -> Result<Option<Header>, BoxError> {
    let Some(vv) = header.0.get("Trailer").cloned() else {
        return Ok(None);
    };
    if !is_chunked {
        return Ok(None);
    }
    header.0.remove("Trailer");
    let mut trailer = Header::new();
    let mut err: Option<BoxError> = None;
    for v in &vv {
        foreach_header_element(v, |key| {
            let key = canonical_header_key(key);
            if matches!(
                key.as_str(),
                "Transfer-Encoding" | "Trailer" | "Content-Length"
            ) && err.is_none()
            {
                err = Some(bad_string_error("bad trailer key", &key));
                return;
            }
            trailer.0.insert(key, Vec::new());
        });
    }
    if let Some(e) = err {
        return Err(e);
    }
    if trailer.0.is_empty() {
        return Ok(None);
    }
    Ok(Some(trailer))
}

/// The pieces `read_transfer` produces for a message.
pub(crate) struct TransferRead {
    pub body: Body,
    pub handle: Option<BodyHandle>,
    pub content_length: i64,
    pub chunked: bool,
    pub close: bool,
    pub trailer_cell: Trailer,
}

/// Go's `readTransfer`. `msg` supplies and receives the framing fields.
pub(crate) struct MsgIn<'a> {
    pub is_response: bool,
    pub header: &'a mut Header,
    pub status_code: u16,
    pub request_method: String,
    pub proto_major: i32,
    pub proto_minor: i32,
    pub close: bool,
}

pub(crate) fn read_transfer(
    m: MsgIn<'_>,
    r: &BufioReader,
    max_trailer_headers: i64,
) -> Result<TransferRead, BoxError> {
    let MsgIn {
        is_response,
        header,
        status_code,
        request_method,
        mut proto_major,
        mut proto_minor,
        close,
    } = m;
    let mut t_close = if is_response {
        should_close(proto_major, proto_minor, header, true)
    } else {
        close
    };
    if proto_major == 0 && proto_minor == 0 {
        proto_major = 1;
        proto_minor = 1;
    }
    // parseTransferEncoding
    let mut is_chunked = false;
    if let Some(raw) = header.0.remove("Transfer-Encoding") {
        if proto_major > 1 || (proto_major == 1 && proto_minor >= 1) {
            if raw.len() != 1 {
                return Err(Box::new(UnsupportedTeError(format!(
                    "too many transfer encodings: {}",
                    quote_list(&raw)
                ))));
            }
            if !raw[0].eq_ignore_ascii_case("chunked") {
                return Err(Box::new(UnsupportedTeError(format!(
                    "unsupported transfer encoding: {}",
                    quote(&raw[0])
                ))));
            }
            is_chunked = true;
        }
    }
    let real_length = fix_length(
        is_response,
        status_code,
        &request_method,
        header,
        is_chunked,
    )?;
    let content_length = if is_response && request_method == "HEAD" {
        parse_content_length(&header.0.get("Content-Length").cloned().unwrap_or_default())?
    } else {
        real_length
    };
    let trailer = fix_trailer(header, is_chunked)?;
    if is_response && real_length == -1 && !is_chunked && body_allowed_for_status(status_code) {
        t_close = true;
    }
    let trailer_cell = Trailer::new(trailer.clone());
    let mk = |src: Src, tr: Option<Trailer>| {
        let h = BodyHandle(Arc::new(Mutex::new(TransferBody::new(
            src,
            r.clone(),
            t_close,
            tr,
            max_trailer_headers,
        ))));
        (Body::new(h.clone()), Some(h))
    };
    let (body, handle) = if is_chunked {
        if is_response
            && (no_response_body_expected(&request_method) || !body_allowed_for_status(status_code))
        {
            (Body::from(NoBody), None)
        } else {
            mk(
                Src::Chunked(ChunkedState::default()),
                Some(trailer_cell.clone()),
            )
        }
    } else if real_length == 0 {
        (Body::from(NoBody), None)
    } else if real_length > 0 {
        mk(Src::Limited(real_length as u64), None)
    } else if t_close {
        mk(Src::Raw, None)
    } else {
        (Body::from(NoBody), None)
    };
    Ok(TransferRead {
        body,
        handle,
        content_length,
        chunked: is_chunked,
        close: t_close,
        trailer_cell,
    })
}

// ------------------------------------------------------------------ body

#[derive(Default)]
struct ChunkedState {
    n: u64,
    err: Option<(io::ErrorKind, String)>,
    check_end: bool,
    excess: i64,
}

enum Src {
    Limited(u64),
    Chunked(ChunkedState),
    Raw,
}

/// Maximum bytes a server reads from an unread request body before closing
/// the connection (Go's `maxPostHandlerReadBytes`).
pub(crate) const MAX_POST_HANDLER_READ_BYTES: i64 = 256 << 10;

/// Go's `transfer.go` `body`: a length-limited, chunked or raw message body
/// that tracks EOF, trailers and early close.
pub struct TransferBody {
    src: Src,
    r: BufioReader,
    closing: bool,
    pub(crate) do_early_close: bool,
    trailer: Option<Trailer>,
    max_trailer_headers: i64,
    saw_eof: bool,
    closed: bool,
    pub(crate) early_close: bool,
    on_hit_eof: Option<Box<dyn FnMut() + Send>>,
}

impl TransferBody {
    fn new(
        src: Src,
        r: BufioReader,
        closing: bool,
        trailer: Option<Trailer>,
        max_trailer_headers: i64,
    ) -> Self {
        Self {
            src,
            r,
            closing,
            do_early_close: false,
            trailer,
            max_trailer_headers,
            saw_eof: false,
            closed: false,
            early_close: false,
            on_hit_eof: None,
        }
    }

    fn src_read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        match &mut self.src {
            Src::Raw => self.r.read(p),
            Src::Limited(n) => {
                if *n == 0 {
                    return Ok(0);
                }
                let want = usize::try_from(*n).unwrap_or(usize::MAX).min(p.len());
                let got = self.r.read(&mut p[..want])?;
                *n -= got as u64;
                Ok(got)
            }
            Src::Chunked(_) => self.chunked_read(p),
        }
    }

    fn read_locked(&mut self, p: &mut [u8]) -> io::Result<usize> {
        if self.saw_eof {
            return Ok(0);
        }
        let mut res = self.src_read(p);
        let mut hit_eof = false;
        match &res {
            Ok(0) if !p.is_empty() => {
                hit_eof = true;
                if self.trailer.is_some() || matches!(self.src, Src::Chunked(_)) {
                    self.saw_eof = true;
                    if let Err(e) = self.read_trailer() {
                        res = Err(e);
                        self.saw_eof = false;
                        self.closed = true;
                    }
                    self.trailer = None;
                } else if let Src::Limited(n) = &self.src {
                    self.saw_eof = true;
                    if *n > 0 {
                        res = Err(unexpected_eof());
                    }
                } else {
                    self.saw_eof = true;
                }
            }
            Ok(n) if *n > 0 => {
                if let Src::Limited(0) = self.src {
                    // Fully consumed: report EOF with the data.
                    self.saw_eof = true;
                }
            }
            _ => {}
        }
        let _ = hit_eof;
        if self.saw_eof {
            if let Some(f) = self.on_hit_eof.as_mut() {
                f();
            }
        }
        res
    }

    // ---- chunked

    fn read_chunk_line(&mut self) -> io::Result<Vec<u8>> {
        let mut br = self.r.lock();
        let p = match br.read_slice(b'\n') {
            Ok(p) => p,
            Err(e) => {
                let e = e.into_source();
                return Err(if is_buffer_full(&e) {
                    io_error(ERR_LINE_TOO_LONG)
                } else if e.kind() == io::ErrorKind::UnexpectedEof || is_eof_err(&e) {
                    unexpected_eof()
                } else {
                    e
                });
            }
        };
        let mut p = p.to_vec();
        match p.iter().position(|&b| b == b'\r') {
            None => return Err(io::Error::other("chunked line ends with bare LF")),
            Some(idx) if idx != p.len() - 2 => {
                return Err(io::Error::other("invalid CR in chunked line"))
            }
            _ => {}
        }
        p.truncate(p.len() - 2);
        if p.len() >= 4096 {
            return Err(io_error(ERR_LINE_TOO_LONG));
        }
        Ok(p)
    }

    fn begin_chunk(&mut self) {
        let line = match self.read_chunk_line() {
            Ok(l) => l,
            Err(e) => {
                self.set_chunk_err(e);
                return;
            }
        };
        let mut line = line;
        let line_len = line.len() as i64;
        while line.last().is_some_and(|b| *b == b' ' || *b == b'\t') {
            line.pop();
        }
        if let Some(i) = line.iter().position(|&b| b == b';') {
            line.truncate(i);
        }
        let n = match parse_hex_uint(&line) {
            Ok(n) => n,
            Err(e) => {
                self.set_chunk_err(io::Error::other(e));
                return;
            }
        };
        let Src::Chunked(st) = &mut self.src else {
            return;
        };
        st.excess += line_len + 2;
        st.n = n;
        st.excess -= 16 + 2 * (n as i64);
        st.excess = st.excess.max(0);
        if st.excess > 16 * 1024 {
            st.err = Some((
                io::ErrorKind::Other,
                "chunked encoding contains too much non-data".into(),
            ));
        }
        if n == 0 {
            st.err = Some((io::ErrorKind::UnexpectedEof, "EOF".into()));
        }
    }

    fn set_chunk_err(&mut self, e: io::Error) {
        if let Src::Chunked(st) = &mut self.src {
            st.err = Some((e.kind(), e.to_string()));
        }
    }

    fn chunked_read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let mut n = 0usize;
        let mut b = b;
        loop {
            let Src::Chunked(st) = &mut self.src else {
                return Ok(n);
            };
            if let Some((kind, msg)) = &st.err {
                if msg == "EOF" && *kind == io::ErrorKind::UnexpectedEof {
                    return Ok(n);
                }
                if n > 0 {
                    // Report the data now; the error is sticky.
                    return Ok(n);
                }
                return Err(io::Error::new(*kind, msg.clone()));
            }
            if st.check_end {
                if n > 0 && self.r.buffered() < 2 {
                    break;
                }
                let mut two = [0u8; 2];
                let mut got = 0;
                let mut rd = self.r.clone();
                let mut failure = None;
                while got < 2 {
                    match rd.read(&mut two[got..]) {
                        Ok(0) => {
                            failure =
                                Some((io::ErrorKind::UnexpectedEof, "unexpected EOF".to_owned()));
                            break;
                        }
                        Ok(k) => got += k,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) => {
                            failure = Some((e.kind(), e.to_string()));
                            break;
                        }
                    }
                }
                let Src::Chunked(st) = &mut self.src else {
                    return Ok(n);
                };
                if failure.is_none() && &two != b"\r\n" {
                    failure = Some((
                        io::ErrorKind::Other,
                        "malformed chunked encoding".to_owned(),
                    ));
                }
                if let Some(f) = failure {
                    st.err = Some(f);
                    continue;
                }
                st.check_end = false;
            }
            let Src::Chunked(st) = &mut self.src else {
                return Ok(n);
            };
            if st.n == 0 {
                if n > 0 && !self.chunk_header_available() {
                    break;
                }
                self.begin_chunk();
                continue;
            }
            if b.is_empty() {
                break;
            }
            let want = usize::try_from(st.n).unwrap_or(usize::MAX).min(b.len());
            let got = self.r.read(&mut b[..want]);
            let Src::Chunked(st) = &mut self.src else {
                return Ok(n);
            };
            match got {
                Ok(0) => {
                    st.err = Some((io::ErrorKind::UnexpectedEof, "unexpected EOF".to_owned()));
                }
                Ok(k) => {
                    n += k;
                    let rest = std::mem::take(&mut b);
                    b = &mut rest[k..];
                    st.n -= k as u64;
                    if st.n == 0 {
                        st.check_end = true;
                    }
                }
                Err(e) => {
                    st.err = Some((e.kind(), e.to_string()));
                }
            }
        }
        Ok(n)
    }

    fn chunk_header_available(&self) -> bool {
        let mut br = self.r.lock();
        let n = br.buffered();
        if n > 0 {
            let (peek, _) = br.peek_available(n);
            return peek.contains(&b'\n');
        }
        false
    }

    // ---- trailers

    fn read_trailer(&mut self) -> io::Result<()> {
        let mut br = self.r.lock();
        let (buf, _err) = br.peek_available(2);
        if buf == b"\r\n" {
            let _ = br.discard(2);
            return Ok(());
        }
        if buf.len() < 2 {
            return Err(io::Error::other("http: unexpected EOF reading trailer"));
        }
        // seeUpcomingDoubleCRLF
        let mut found = false;
        let mut size = 4;
        loop {
            let (buf, err) = br.peek_available(size);
            if buf.ends_with(b"\r\n\r\n") {
                found = true;
                break;
            }
            if err.is_some() {
                break;
            }
            size += 1;
        }
        if !found {
            return Err(io::Error::other(
                "http: suspiciously long trailer after chunked body",
            ));
        }
        let limits = textproto::Limits {
            max_headers: if self.max_trailer_headers == i64::MAX {
                usize::MAX
            } else {
                usize::try_from(self.max_trailer_headers).unwrap_or(usize::MAX)
            },
            ..textproto::Limits::default()
        };
        let mut tp = textproto::Reader::with_limits(&mut *br, limits);
        let hdr = tp.read_mime_header().map_err(|e| match e {
            textproto::Error::Io(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                io::Error::other("http: unexpected EOF reading trailer")
            }
            other => io::Error::other(other.to_string()),
        })?;
        drop(br);
        if let Some(cell) = &self.trailer {
            cell.merge(Header(hdr.into_map()));
        }
        Ok(())
    }

    pub(crate) fn body_remains(&self) -> bool {
        !self.saw_eof
    }
}

fn is_buffer_full(e: &io::Error) -> bool {
    crate::bufio::Error::BufferFull.is(e)
}
fn is_eof_err(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::UnexpectedEof
}

fn parse_hex_uint(v: &[u8]) -> Result<u64, String> {
    if v.is_empty() {
        return Err("empty hex number for chunk length".into());
    }
    let mut n: u64 = 0;
    for (i, &b) in v.iter().enumerate() {
        let d = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return Err("invalid byte in chunk length".into()),
        };
        if i == 16 {
            return Err("http chunk length too large".into());
        }
        n = (n << 4) | u64::from(d);
    }
    Ok(n)
}

impl Read for TransferBody {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        if self.closed {
            return Err(io_error(super::header::ERR_BODY_READ_AFTER_CLOSE));
        }
        self.read_locked(p)
    }
}

impl ReadCloser for TransferBody {
    fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        let mut err = Ok(());
        let nothing_to_drain = self.saw_eof
            || (self.trailer.is_none() && !matches!(self.src, Src::Chunked(_)) && self.closing);
        if nothing_to_drain {
            // The remaining bytes (if any) die with the connection.
        } else if self.do_early_close {
            if matches!(self.src, Src::Limited(n) if n as i64 > MAX_POST_HANDLER_READ_BYTES) {
                self.early_close = true;
            } else {
                let mut sink = io::sink();
                let mut left = MAX_POST_HANDLER_READ_BYTES + 1;
                let mut buf = [0u8; 8192];
                let mut hit_eof = false;
                while left > 0 {
                    let want = usize::try_from(left).unwrap_or(buf.len()).min(buf.len());
                    match self.read_locked(&mut buf[..want]) {
                        Ok(0) => {
                            hit_eof = true;
                            break;
                        }
                        Ok(k) => {
                            let _ = sink.write_all(&buf[..k]);
                            left -= k as i64;
                        }
                        Err(e) => {
                            err = Err(e);
                            break;
                        }
                    }
                }
                self.early_close = true;
                if hit_eof && left > 0 {
                    self.early_close = false;
                    self.saw_eof = true;
                }
            }
        } else {
            let mut buf = [0u8; 8192];
            loop {
                match self.read_locked(&mut buf) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(e) => {
                        err = Err(e);
                        break;
                    }
                }
            }
        }
        self.closed = true;
        err
    }
}

impl TransferBody {
    /// Server hooks: close early rather than draining large unread bodies.
    pub(crate) fn set_do_early_close(&mut self, v: bool) {
        self.do_early_close = v;
    }
}

#[allow(dead_code)]
pub(crate) const ERR_TRAILER_EOF: ErrorString = ErrorString("http: unexpected EOF reading trailer");

/// A shared handle to a message body's state: the server inspects it to
/// decide whether a connection can be reused (Go's `*body` methods).
#[derive(Clone)]
pub(crate) struct BodyHandle(Arc<Mutex<TransferBody>>);
impl BodyHandle {
    fn lock(&self) -> MutexGuard<'_, TransferBody> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn body_remains(&self) -> bool {
        self.lock().body_remains()
    }
    pub fn close(&self) -> io::Result<()> {
        self.lock().close()
    }
    pub fn set_do_early_close(&self, v: bool) {
        self.lock().set_do_early_close(v);
    }
    pub fn did_early_close(&self) -> bool {
        self.lock().early_close
    }
    pub fn register_on_hit_eof(&self, f: Option<Box<dyn FnMut() + Send>>) {
        self.lock().on_hit_eof = f;
    }
    /// (closed, saw_eof, unread bytes of a length-limited body or -1)
    pub fn snapshot(&self) -> (bool, bool, i64) {
        let g = self.lock();
        let unread = match g.src {
            Src::Limited(n) => i64::try_from(n).unwrap_or(i64::MAX),
            _ => -1,
        };
        (g.closed, g.saw_eof, unread)
    }
}
impl Read for BodyHandle {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        self.lock().read(p)
    }
}
impl ReadCloser for BodyHandle {
    fn close(&mut self) -> io::Result<()> {
        self.lock().close()
    }
}
