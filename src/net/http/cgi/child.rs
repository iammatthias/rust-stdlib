//! CGI from the perspective of a child process (Go's `net/http/cgi/child.go`).
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::sync::Arc;

use crate::net::http::body::Body;
use crate::net::http::header::{parse_http_version, BoxError, Header, Trailer};
use crate::net::http::request::Request;
use crate::net::http::sniff::detect_content_type;
use crate::net::http::tlsstate::ConnectionState;
use crate::net::http::{handler_func, status_text, Handler, ResponseWriter, DEFAULT_SERVE_MUX};
use crate::net::join_host_port;
use crate::net::url;
use crate::net::url::Url;
use crate::strconv;

/// Go's `cgi.Request`: the HTTP request as represented in the current
/// environment. This assumes the current program is being run by a web server
/// in a CGI environment. The returned request's `body` is populated, if
/// applicable.
pub fn request() -> Result<Request, BoxError> {
    let mut r = request_from_map(&env_map(&crate::os::environ()))?;
    if r.content_length > 0 {
        r.body = Some(Body::from_reader(
            io::stdin().take(r.content_length.unsigned_abs()),
        ));
    }
    Ok(r)
}

fn env_map(env: &[String]) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for kv in env {
        if let Some((k, v)) = kv.split_once('=') {
            m.insert(k.to_owned(), v.to_owned());
        }
    }
    m
}

/// Go's `cgi.RequestFromMap`: creates a [`Request`] from CGI variables. The
/// returned request's `body` field is not populated.
pub fn request_from_map(params: &HashMap<String, String>) -> Result<Request, BoxError> {
    let get = |k: &str| params.get(k).map_or("", String::as_str);
    let mut r = Request::default();
    r.method = get("REQUEST_METHOD").to_owned();
    if r.method.is_empty() {
        return Err("cgi: no REQUEST_METHOD in environment".into());
    }

    r.proto = get("SERVER_PROTOCOL").to_owned();
    if r.proto == "INCLUDED" {
        // SSI (Server Side Include) use case, RFC 3875 section 4.1.16.
        r.proto_major = 1;
        r.proto_minor = 0;
    } else if let Some((major, minor)) = parse_http_version(&r.proto) {
        r.proto_major = major as i32;
        r.proto_minor = minor as i32;
    } else {
        return Err("cgi: invalid SERVER_PROTOCOL version".into());
    }

    r.close = true;
    r.trailer = Trailer::new(Some(Header::new()));
    r.header = Header::new();

    r.host = get("HTTP_HOST").to_owned();

    let lenstr = get("CONTENT_LENGTH");
    if !lenstr.is_empty() {
        match strconv::parse_int(lenstr, 10, 64) {
            Ok(n) => r.content_length = n,
            Err(_) => {
                return Err(format!("cgi: bad CONTENT_LENGTH in environment: {lenstr}").into());
            }
        }
    }

    let ct = get("CONTENT_TYPE");
    if !ct.is_empty() {
        r.header.set("Content-Type", ct);
    }

    // Copy "HTTP_FOO_BAR" variables to "Foo-Bar" headers. Go ranges over a
    // map in random order; sorted order is one of its orders.
    let mut keys: Vec<&String> = params.keys().collect();
    keys.sort();
    for k in keys {
        if k == "HTTP_HOST" {
            continue;
        }
        if let Some(after) = k.strip_prefix("HTTP_") {
            r.header.add(&after.replace('_', "-"), &params[k]);
        }
    }

    let mut uri = get("REQUEST_URI").to_owned();
    if uri.is_empty() {
        // Fall back to SCRIPT_NAME, PATH_INFO and QUERY_STRING.
        uri = format!("{}{}", get("SCRIPT_NAME"), get("PATH_INFO"));
        let s = get("QUERY_STRING");
        if !s.is_empty() {
            uri.push('?');
            uri.push_str(s);
        }
    }

    // There's apparently a de-facto standard for this.
    let https = get("HTTPS");
    if https == "on" || https == "ON" || https == "1" {
        r.tls = Some(Arc::new(ConnectionState {
            handshake_complete: true,
            ..ConnectionState::default()
        }));
    }

    let mut parsed: Option<Url> = None;
    if !r.host.is_empty() {
        // A hostname is provided, so we can reasonably construct a URL.
        let rawurl = format!(
            "{}://{}{}",
            if r.tls.is_none() { "http" } else { "https" },
            r.host,
            uri
        );
        match url::parse(&rawurl) {
            Ok(u) => parsed = Some(u),
            Err(_) => {
                return Err(format!(
                    "cgi: failed to parse host and REQUEST_URI into a URL: {rawurl}"
                )
                .into());
            }
        }
    }
    // Fallback logic if we don't have a Host header or the URL failed to parse.
    let u = match parsed {
        Some(u) => u,
        None => match url::parse(&uri) {
            Ok(u) => u,
            Err(_) => {
                return Err(format!("cgi: failed to parse REQUEST_URI into a URL: {uri}").into());
            }
        },
    };
    r.url = u;

    // Request.RemoteAddr has its port set by Go's standard http server, so we
    // do here too. The port is zero if unset or invalid.
    let remote_port = strconv::atoi(get("REMOTE_PORT")).unwrap_or_else(|e| e.int_value() as isize);
    r.remote_addr = join_host_port(get("REMOTE_ADDR"), &remote_port.to_string());

    Ok(r)
}

/// Go's `cgi.Serve`: executes the provided [`Handler`] on the currently
/// active CGI request, if any. If there's no current CGI environment an error
/// is returned. A `None` handler uses the default [`ServeMux`](crate::net::http::ServeMux),
/// as Go's nil does.
pub fn serve(handler: Option<&dyn Handler>) -> Result<(), BoxError> {
    serve_with(handler, Box::new(io::stdout()))
}

/// [`serve`] writing the CGI response to `out` instead of standard output.
pub fn serve_with(
    handler: Option<&dyn Handler>,
    out: Box<dyn Write + Send>,
) -> Result<(), BoxError> {
    let mut req = request()?;
    if req.body.is_none() {
        req.body = Some(Body::from(crate::net::http::NoBody));
    }
    let default = handler_func(|w, r| DEFAULT_SERVE_MUX.serve_http(w, r));
    let handler: &dyn Handler = match handler {
        Some(h) => h,
        None => &*default,
    };
    let mut rw = Response {
        url: req.url.to_string(),
        header: Header::new(),
        code: 0,
        wrote_header: false,
        wrote_cgi_header: false,
        bufw: io::BufWriter::with_capacity(4096, out),
    };
    handler.serve_http(&mut rw, &mut req);
    let _ = rw.write(&[]); // make sure a response is sent
    rw.bufw.flush()?;
    Ok(())
}

/// The CGI response writer (Go's child `response`).
struct Response {
    url: String,
    header: Header,
    code: u16,
    wrote_header: bool,
    wrote_cgi_header: bool,
    bufw: io::BufWriter<Box<dyn Write + Send>>,
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
            self.bufw,
            "Status: {} {}\r\n",
            self.code,
            status_text(self.code)
        );
        if !self.header.0.contains_key("Content-Type") {
            self.header.set("Content-Type", detect_content_type(p));
        }
        let _ = self.header.write(&mut self.bufw);
        let _ = self.bufw.write_all(b"\r\n");
        let _ = self.bufw.flush();
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
        self.bufw.write_all(p)?;
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
            // Explicitly standard error: standard output is the HTTP output.
            eprint!(
                "CGI attempted to write header twice on request for {}",
                self.url
            );
            return;
        }
        self.wrote_header = true;
        self.code = code;
    }

    fn flusher(&mut self) -> Option<&mut dyn crate::net::http::Flusher> {
        Some(self)
    }
}

impl crate::net::http::Flusher for Response {
    fn flush(&mut self) {
        let _ = self.bufw.flush();
    }
}
