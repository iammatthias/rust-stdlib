//! Go's `http.Response`, `ReadResponse` and `Response.Write`.
use super::body::{Body, NoBody};
use super::cookie::{read_set_cookies, Cookie};
use super::header::{
    parse_http_version, textproto_err, values_contain_token, BoxError, Header, Trailer, ERR_EOF,
    ERR_NO_LOCATION, ERR_UNEXPECTED_EOF,
};
use super::request::Request;
use super::status_text;
use super::tlsstate::ConnectionState;
use super::transfer::{
    bad_string_error, body_allowed_for_status, chunked, fix_pragma_cache_control, read_transfer,
    BufioReader, MsgIn, TransferWriter,
};
use crate::net::textproto;
use crate::net::url::{self, Url};
use std::{
    fmt,
    io::{self, Read, Write},
    sync::Arc,
};

/// Go's `http.Response`.
#[derive(Clone, Default)]
pub struct Response {
    /// E.g. "200 OK".
    pub status: String,
    pub status_code: u16,
    pub proto: String,
    pub proto_major: i32,
    pub proto_minor: i32,
    pub header: Header,
    pub body: Option<Body>,
    pub content_length: i64,
    pub transfer_encoding: Vec<String>,
    pub close: bool,
    pub uncompressed: bool,
    pub trailer: Trailer,
    pub request: Option<Box<Request>>,
    pub tls: Option<Arc<ConnectionState>>,
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("proto", &self.proto)
            .field("header", &self.header)
            .field("content_length", &self.content_length)
            .finish_non_exhaustive()
    }
}

impl Response {
    /// Go's `Cookies`.
    pub fn cookies(&self) -> Vec<Cookie> {
        read_set_cookies(&self.header)
    }

    /// Go's `Location`.
    pub fn location(&self) -> Result<Url, BoxError> {
        let lv = self.header.get_str("Location");
        if lv.is_empty() {
            return Err(Box::new(ERR_NO_LOCATION));
        }
        match &self.request {
            Some(r) => Ok(r.url.parse(lv)?),
            None => Ok(url::parse(lv)?),
        }
    }

    /// Go's `ProtoAtLeast`.
    pub fn proto_at_least(&self, major: i32, minor: i32) -> bool {
        self.proto_major > major || (self.proto_major == major && self.proto_minor >= minor)
    }

    pub(crate) fn close_body(&self) {
        if let Some(b) = &self.body {
            let _ = b.close();
        }
    }

    /// Go's `Write`: status line, headers and body in wire format.
    pub fn write(&self, w: &mut dyn Write) -> Result<(), BoxError> {
        let mut text = self.status.clone();
        if text.is_empty() {
            text = status_text(self.status_code).to_owned();
            if text.is_empty() {
                text = format!("status code {}", self.status_code);
            }
        } else {
            let prefix = format!("{} ", self.status_code);
            text = text.strip_prefix(&prefix).unwrap_or(&text).to_owned();
        }
        write!(
            w,
            "HTTP/{}.{} {:03} {}\r\n",
            self.proto_major, self.proto_minor, self.status_code, text
        )?;

        let mut r1 = self.clone();
        if r1.content_length == 0 {
            if let Some(body) = r1.body.clone() {
                let mut buf = [0u8; 1];
                let mut b = body.clone();
                let n = match b.read(&mut buf) {
                    Ok(n) => n,
                    Err(e) => return Err(Box::new(e)),
                };
                if n == 0 {
                    r1.body = Some(Body::from(NoBody));
                } else {
                    r1.content_length = -1;
                    r1.body = Some(Body::from_reader(io::Read::chain(
                        io::Cursor::new(vec![buf[0]]),
                        body,
                    )));
                }
            }
        }
        if r1.content_length == -1
            && !r1.close
            && r1.proto_at_least(1, 1)
            && !chunked(&r1.transfer_encoding)
            && !r1.uncompressed
        {
            r1.close = true;
        }
        let mut tw = TransferWriter::for_response(&r1)?;
        tw.write_header(w, None)?;
        self.header.write_excluding(
            w,
            &["Content-Length", "Transfer-Encoding", "Trailer"],
            None,
        )?;
        let content_length_already_sent = tw.should_send_content_length();
        if r1.content_length == 0
            && !chunked(&r1.transfer_encoding)
            && !content_length_already_sent
            && body_allowed_for_status(self.status_code)
        {
            w.write_all(b"Content-Length: 0\r\n")?;
        }
        w.write_all(b"\r\n")?;
        tw.write_body(w, false)?;
        Ok(())
    }
}

pub(crate) fn is_protocol_switch_header(h: &Header) -> bool {
    !h.get_str("Upgrade").is_empty()
        && values_contain_token(
            &h.0.get("Connection").cloned().unwrap_or_default(),
            "Upgrade",
        )
}

/// Go's `ReadResponse`: reads a response from `r` for `req` (which may be
/// absent, meaning a GET).
pub fn read_response(r: &BufioReader, req: Option<&Request>) -> Result<Response, BoxError> {
    let mut resp = Response {
        request: req.map(|q| Box::new(q.clone())),
        ..Response::default()
    };
    {
        let mut guard = r.lock();
        let limits = textproto::Limits {
            max_line_bytes: usize::MAX / 2,
            max_header_bytes: usize::MAX / 2,
            max_headers: usize::MAX / 2,
            ..textproto::Limits::default()
        };
        let mut tp = textproto::Reader::with_limits(&mut *guard, limits);
        let line = match tp.read_line_bytes() {
            Ok(l) => l,
            Err(e) => {
                let e = textproto_err(e);
                return Err(
                    if e.downcast_ref::<super::header::ErrorString>() == Some(&ERR_EOF) {
                        Box::new(ERR_UNEXPECTED_EOF)
                    } else {
                        e
                    },
                );
            }
        };
        let Some(sp) = line.iter().position(|&b| b == b' ') else {
            return Err(bad_string_error("malformed HTTP response", &line));
        };
        let (proto, status) = (&line[..sp], &line[sp + 1..]);
        resp.proto = String::from_utf8_lossy(proto).into_owned();
        let status: &[u8] = {
            let start = status
                .iter()
                .position(|&b| b != b' ')
                .unwrap_or(status.len());
            &status[start..]
        };
        resp.status = String::from_utf8_lossy(status).into_owned();
        let code_end = status
            .iter()
            .position(|&b| b == b' ')
            .unwrap_or(status.len());
        let status_code = &status[..code_end];
        if status_code.len() != 3 {
            return Err(bad_string_error("malformed HTTP status code", status_code));
        }
        resp.status_code = match std::str::from_utf8(status_code).ok().and_then(atoi) {
            Some(n) if (0..=999).contains(&n) => n as u16,
            _ => return Err(bad_string_error("malformed HTTP status code", status_code)),
        };
        let Some((maj, min)) = std::str::from_utf8(proto).ok().and_then(parse_http_version) else {
            return Err(bad_string_error("malformed HTTP version", proto));
        };
        resp.proto_major = maj as i32;
        resp.proto_minor = min as i32;
        let mime = tp.read_mime_header().map_err(|e| {
            let e = textproto_err(e);
            if e.downcast_ref::<super::header::ErrorString>() == Some(&ERR_EOF) {
                Box::new(ERR_UNEXPECTED_EOF) as BoxError
            } else {
                e
            }
        })?;
        resp.header = Header(mime.into_map());
    }
    fix_pragma_cache_control(&mut resp.header);
    let t = read_transfer(
        MsgIn {
            is_response: true,
            header: &mut resp.header,
            status_code: resp.status_code,
            request_method: req.map_or_else(|| "GET".to_owned(), |q| q.method.clone()),
            proto_major: resp.proto_major,
            proto_minor: resp.proto_minor,
            close: false,
        },
        r,
        i64::MAX,
    )?;
    resp.body = Some(t.body);
    resp.content_length = t.content_length;
    if t.chunked {
        resp.transfer_encoding = vec!["chunked".into()];
    }
    resp.close = t.close;
    resp.trailer = t.trailer_cell;
    Ok(resp)
}

/// `strconv.Atoi` for a 3-character status code.
fn atoi(s: &str) -> Option<i32> {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}
