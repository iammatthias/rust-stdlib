//! FastCGI from the perspective of a child process (Go's
//! `net/http/fcgi/child.go`).
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Read, Write};
use std::sync::{Arc, LazyLock};

use super::records::{
    read_size, read_string, BeginRequest, BufStream, Records, FLAG_KEEP_CONN, ROLE_RESPONDER,
    STATUS_REQUEST_COMPLETE, STATUS_UNKNOWN_ROLE, TYPE_ABORT_REQUEST, TYPE_BEGIN_REQUEST,
    TYPE_DATA, TYPE_GET_VALUES, TYPE_GET_VALUES_RESULT, TYPE_PARAMS, TYPE_STDERR, TYPE_STDIN,
    TYPE_STDOUT, TYPE_UNKNOWN_TYPE,
};
use crate::context;
use crate::io::{pipe, PipeWriter};
use crate::net::http::body::Body;
use crate::net::http::cgi::request_from_map;
use crate::net::http::header::{BoxError, ErrorString, Header};
use crate::net::http::request::Request;
use crate::net::http::sniff::detect_content_type;
use crate::net::http::status::TIME_FORMAT;
use crate::net::http::{
    handler_func, status_text, Flusher, Handler, ResponseWriter, DEFAULT_SERVE_MUX,
};
use crate::net::{Conn, Listener};
use crate::time;

/// Returned by a read when a handler attempts to read the body of a request
/// that has been aborted by the web server (Go's `ErrRequestAborted`).
pub const ERR_REQUEST_ABORTED: ErrorString = ErrorString("fcgi: request aborted by web server");

/// Returned by a read when a handler attempts to read the body of a request
/// after the connection to the web server has been closed (Go's
/// `ErrConnClosed`).
pub const ERR_CONN_CLOSED: ErrorString = ErrorString("fcgi: connection to web server closed");

/// Context key of the FastCGI variables the request itself does not carry.
static ENV_VARS_KEY: LazyLock<context::Key<HashMap<String, String>>> =
    LazyLock::new(|| context::Key::named("fcgi.envVarsContextKey"));

/// The state of an in-progress request. As soon as it's complete, it's
/// converted to an `http::Request`.
struct PendingRequest {
    pw: Option<PipeWriter>,
    req_id: u16,
    params: HashMap<String, String>,
    raw_params: Vec<u8>,
    keep_conn: bool,
}

impl PendingRequest {
    fn new(req_id: u16, flags: u8) -> PendingRequest {
        PendingRequest {
            pw: None,
            req_id,
            params: HashMap::new(),
            raw_params: Vec::new(),
            keep_conn: flags & FLAG_KEEP_CONN != 0,
        }
    }

    /// Reads the encoded name-value pairs into `params`.
    fn parse_params(&mut self) {
        let raw = std::mem::take(&mut self.raw_params);
        let mut text: &[u8] = &raw;
        while !text.is_empty() {
            let (key_len, n) = read_size(text);
            if n == 0 {
                return;
            }
            text = &text[n..];
            let (val_len, n) = read_size(text);
            if n == 0 {
                return;
            }
            text = &text[n..];
            if key_len as usize + val_len as usize > text.len() {
                return;
            }
            let key = read_string(text, key_len);
            text = &text[key_len as usize..];
            let val = read_string(text, val_len);
            text = &text[val_len as usize..];
            self.params.insert(key, val);
        }
    }
}

/// The FastCGI response writer.
struct Response {
    header: Header,
    code: u16,
    wrote_header: bool,
    wrote_cgi_header: bool,
    w: BufStream,
}

impl Response {
    /// Finalizes the header sent to the client and writes it to the output.
    /// `p` is the first chunk of the body, sniffed for a Content-Type if none
    /// is set explicitly.
    fn write_cgi_header(&mut self, p: &[u8]) {
        if self.wrote_cgi_header {
            return;
        }
        self.wrote_cgi_header = true;
        let _ = write!(
            self.w,
            "Status: {} {}\r\n",
            self.code,
            status_text(self.code)
        );
        if self.code != 304 && !self.header.0.contains_key("Content-Type") {
            self.header.set("Content-Type", detect_content_type(p));
        }
        let _ = self.header.write(&mut self.w);
        let _ = self.w.write_all(b"\r\n");
        let _ = self.w.flush();
    }

    fn close(&mut self) -> io::Result<()> {
        Flusher::flush(self);
        self.w.close()
    }
}

impl std::io::Write for Response {
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        if !self.wrote_header {
            self.write_header(200);
        }
        if !self.wrote_cgi_header {
            self.write_cgi_header(p);
        }
        self.w.write_all(p)?;
        Ok(p.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl ResponseWriter for Response {
    fn header(&mut self) -> &mut Header {
        &mut self.header
    }

    fn write_header(&mut self, code: u16) {
        if self.wrote_header {
            return;
        }
        self.wrote_header = true;
        self.code = code;
        if code == 304 {
            // Must not have a body.
            self.header.del("Content-Type");
            self.header.del("Content-Length");
            self.header.del("Transfer-Encoding");
        }
        if self.header.get_str("Date").is_empty() {
            self.header
                .set("Date", &time::now().utc().format(TIME_FORMAT));
        }
    }

    fn flusher(&mut self) -> Option<&mut dyn Flusher> {
        Some(self)
    }
}

impl Flusher for Response {
    fn flush(&mut self) {
        if !self.wrote_header {
            self.write_header(200);
        }
        let _ = self.w.flush();
    }
}

struct Child {
    records: Arc<Records>,
    handler: Arc<dyn Handler>,
    /// In-flight requests, keyed by request ID.
    requests: HashMap<u16, PendingRequest>,
}

/// One record as read from the connection.
struct Record {
    typ: u8,
    id: u16,
    content: Vec<u8>,
}

fn read_exact(conn: &dyn Conn, buf: &mut [u8]) -> io::Result<()> {
    let mut done = 0;
    while done < buf.len() {
        match conn.read(&mut buf[done..]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => done += n,
            Err(e) => return Err(e.into_io()),
        }
    }
    Ok(())
}

fn read_record(conn: &dyn Conn) -> io::Result<Record> {
    let mut h = [0u8; 8];
    read_exact(conn, &mut h)?;
    if h[0] != 1 {
        return Err(io::Error::other("fcgi: invalid header version"));
    }
    let content_length = usize::from(u16::from_be_bytes([h[4], h[5]]));
    let padding = usize::from(h[6]);
    let mut body = vec![0u8; content_length + padding];
    read_exact(conn, &mut body)?;
    body.truncate(content_length);
    Ok(Record {
        typ: h[1],
        id: u16::from_be_bytes([h[2], h[3]]),
        content: body,
    })
}

impl Child {
    fn serve(mut self) {
        let records = self.records.clone();
        while let Ok(rec) = read_record(&**records.conn()) {
            if self.handle_record(rec).is_err() {
                break;
            }
        }
        self.clean_up();
        let _ = records.close();
    }

    /// Err means the connection should be closed.
    fn handle_record(&mut self, rec: Record) -> Result<(), io::Error> {
        let known = self.requests.contains_key(&rec.id);
        if !known && rec.typ != TYPE_BEGIN_REQUEST && rec.typ != TYPE_GET_VALUES {
            // The spec says to ignore unknown request IDs.
            return Ok(());
        }
        match rec.typ {
            TYPE_BEGIN_REQUEST => {
                if known {
                    // The server is trying to begin a request with the same ID
                    // as an in-progress request. This is an error.
                    return Err(io::Error::other(
                        "fcgi: received ID that is already in-flight",
                    ));
                }
                let br = BeginRequest::read(&rec.content)?;
                if br.role != ROLE_RESPONDER {
                    let _ = self
                        .records
                        .write_end_request(rec.id, 0, STATUS_UNKNOWN_ROLE);
                    return Ok(());
                }
                self.requests
                    .insert(rec.id, PendingRequest::new(rec.id, br.flags));
                Ok(())
            }
            TYPE_PARAMS => {
                // A key-value pair can straddle the boundary between two
                // records, so buffer until all parameters have arrived.
                if let Some(req) = self.requests.get_mut(&rec.id) {
                    if !rec.content.is_empty() {
                        req.raw_params.extend_from_slice(&rec.content);
                    } else {
                        req.parse_params();
                    }
                }
                Ok(())
            }
            TYPE_STDIN => {
                let Some(req) = self.requests.get_mut(&rec.id) else {
                    return Ok(());
                };
                if req.pw.is_none() {
                    let body = if rec.content.is_empty() {
                        Body::from_bytes(Vec::new())
                    } else {
                        let (pr, pw) = pipe();
                        req.pw = Some(pw);
                        Body::from_reader(pr)
                    };
                    let (records, handler) = (self.records.clone(), self.handler.clone());
                    let (req_id, params, keep) = (req.req_id, req.params.clone(), req.keep_conn);
                    std::thread::spawn(move || {
                        serve_request(records, handler, req_id, params, keep, body)
                    });
                }
                if !rec.content.is_empty() {
                    // This blocks until the handler reads from the pipe.
                    if let Some(req) = self.requests.get(&rec.id) {
                        if let Some(pw) = &req.pw {
                            let _ = pw.write_shared(&rec.content);
                        }
                    }
                } else if let Some(req) = self.requests.remove(&rec.id) {
                    if let Some(pw) = req.pw {
                        pw.close();
                    }
                }
                Ok(())
            }
            TYPE_GET_VALUES => {
                let mut values = BTreeMap::new();
                values.insert("FCGI_MPXS_CONNS".to_owned(), "1".to_owned());
                let _ = self.records.write_pairs(TYPE_GET_VALUES_RESULT, 0, &values);
                Ok(())
            }
            // If the filter role is implemented, read the data stream here.
            TYPE_DATA => Ok(()),
            TYPE_ABORT_REQUEST => {
                let Some(req) = self.requests.remove(&rec.id) else {
                    return Ok(());
                };
                let _ = self
                    .records
                    .write_end_request(rec.id, 0, STATUS_REQUEST_COMPLETE);
                if let Some(pw) = &req.pw {
                    pw.close_with_error(Some(io::Error::other(ERR_REQUEST_ABORTED)));
                }
                if !req.keep_conn {
                    // The connection closes upon return.
                    return Err(io::Error::other("fcgi: connection should be closed"));
                }
                Ok(())
            }
            other => {
                let mut b = [0u8; 8];
                b[0] = other;
                let _ = self.records.write_record(TYPE_UNKNOWN_TYPE, 0, &b);
                Ok(())
            }
        }
    }

    fn clean_up(&mut self) {
        for req in self.requests.values() {
            if let Some(pw) = &req.pw {
                // Racing with the close in serve_request doesn't matter: both
                // closes are idempotent.
                pw.close_with_error(Some(io::Error::other(ERR_CONN_CLOSED)));
            }
        }
    }
}

/// Reports whether to include the FastCGI environment variable `s` in the
/// request context, accessible via [`process_env`].
fn add_fast_cgi_env_to_context(s: &str) -> bool {
    // Exclude things supported by net/http natively.
    !matches!(
        s,
        "CONTENT_LENGTH"
            | "CONTENT_TYPE"
            | "HTTPS"
            | "PATH_INFO"
            | "QUERY_STRING"
            | "REMOTE_ADDR"
            | "REMOTE_HOST"
            | "REMOTE_PORT"
            | "REQUEST_METHOD"
            | "REQUEST_URI"
            | "SCRIPT_NAME"
            | "SERVER_PROTOCOL"
    ) && !s.starts_with("HTTP_")
}

fn filter_out_used_env_vars(env: &HashMap<String, String>) -> HashMap<String, String> {
    env.iter()
        .filter(|(k, _)| add_fast_cgi_env_to_context(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

fn serve_request(
    records: Arc<Records>,
    handler: Arc<dyn Handler>,
    req_id: u16,
    params: HashMap<String, String>,
    keep_conn: bool,
    body: Body,
) {
    let mut r = Response {
        header: Header::new(),
        code: 0,
        wrote_header: false,
        wrote_cgi_header: false,
        w: BufStream::new(&records, TYPE_STDOUT, req_id),
    };
    match request_from_map(&params) {
        Err(e) => {
            // There was an error reading the request.
            r.write_header(500);
            let _ = records.write_record(TYPE_STDERR, req_id, e.to_string().as_bytes());
        }
        Ok(mut http_req) => {
            http_req.body = Some(body.clone());
            let ctx = http_req
                .context()
                .with_value(&ENV_VARS_KEY, filter_out_used_env_vars(&params));
            let mut http_req = http_req.with_context(&ctx);
            handler.serve_http(&mut r, &mut http_req);
        }
    }
    // Make sure we serve something even if nothing was written to r.
    let _ = std::io::Write::write(&mut r, &[]);
    let _ = r.close();
    let _ = records.write_end_request(req_id, 0, STATUS_REQUEST_COMPLETE);

    // Consume the entire body, so the host isn't still writing to us when the
    // socket closes in the !keep_conn case: otherwise we'd send a RST
    // (golang.org/issue/4183).
    let mut sink = io::sink();
    let _ = io::copy(&mut (&mut body.clone()).take(100 << 20), &mut sink);
    let _ = body.close();

    if !keep_conn {
        let _ = records.close();
    }
}

/// Go's `fcgi.Serve`: accepts incoming FastCGI connections on the listener
/// `l`, creating a new thread for each. Each reads requests and then calls
/// `handler` to reply to them. A `None` handler uses the default
/// [`ServeMux`](crate::net::http::ServeMux).
///
/// A `None` listener (Go's nil) accepts connections from the listening
/// socket on standard input, as `net.FileListener(os.Stdin)` does.
pub fn serve(l: Option<&dyn Listener>, handler: Option<Arc<dyn Handler>>) -> Result<(), BoxError> {
    let stdin;
    let l = match l {
        Some(l) => l,
        None => {
            stdin = standard_input_listener()?;
            &*stdin
        }
    };
    let handler =
        handler.unwrap_or_else(|| handler_func(|w, r| DEFAULT_SERVE_MUX.serve_http(w, r)));
    loop {
        let rw = l.accept()?;
        let child = Child {
            records: Records::new(Arc::from(rw)),
            handler: handler.clone(),
            requests: HashMap::new(),
        };
        std::thread::spawn(move || child.serve());
    }
}

#[cfg(unix)]
fn standard_input_listener() -> Result<Box<dyn Listener>, BoxError> {
    Ok(crate::net::sock::stdin_listener()?)
}

#[cfg(not(unix))]
fn standard_input_listener() -> Result<Box<dyn Listener>, BoxError> {
    Err(Box::new(crate::net::unsupported::needs_sys(
        "net.FileListener",
    )))
}

/// Go's `fcgi.ProcessEnv`: the FastCGI environment variables associated with
/// the request `r` for which no effort was made to be included in the request
/// itself: the data is hidden in the request's context. For example, if
/// REMOTE_USER is set for a request, it is not found anywhere in `r` but is
/// included in the result.
pub fn process_env(r: &Request) -> Option<HashMap<String, String>> {
    r.context().value(&ENV_VARS_KEY).map(|m| (*m).clone())
}
