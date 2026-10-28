//! Go's `DumpRequest`, `DumpRequestOut` and `DumpResponse`, over the crate's
//! [`Request`] and [`Response`].
//!
//! Like Go, each function drains the message body to dump it and puts an
//! in-memory copy back, which is why the messages are taken by `&mut`.
use super::ChunkedWriter;
use crate::net::http::{
    body::{Body, NoBody},
    header::{valid_header_field_name, valid_header_field_value, BoxError, ErrorString, Header},
    request::Request,
    response::Response,
};
use std::io::{self, Read, Write};

/// Go's unexported `errNoBody`: what the stand-in body of a head-only
/// response dump fails with.
const SENTINEL: &str = "sentinel error value";

/// Go's `drainBody`: reads `body` to the end and returns two in-memory
/// copies of it.
fn drain_body(body: &Body) -> io::Result<(Body, Body)> {
    if body.is_no_body() {
        return Ok((Body::from(NoBody), Body::from(NoBody)));
    }
    let data = body.read_all()?;
    Ok((Body::from_bytes(data.clone()), Body::from_bytes(data)))
}

/// Go's `DumpRequest`: the request as a server received it. The request line
/// uses `request_uri` (or the URL's), `Host` comes from `host` (or the URL)
/// and is omitted for absolute-form targets, `Transfer-Encoding` precedes the
/// remaining sorted fields, and with `body` a chunked request is re-encoded.
pub fn dump_request(req: &mut Request, body: bool) -> Result<Vec<u8>, BoxError> {
    let save = req.body.take();
    let (save, send) = match (&save, body) {
        (Some(b), true) => {
            let (keep, send) = drain_body(b)?;
            (Some(keep), Some(send))
        }
        _ => (save, None),
    };
    let result = dump_request_inner(req, send);
    req.body = save;
    result
}

fn dump_request_inner(req: &Request, body: Option<Body>) -> Result<Vec<u8>, BoxError> {
    let mut b = Vec::new();
    let req_uri = if req.request_uri.is_empty() {
        req.url.request_uri()
    } else {
        req.request_uri.clone()
    };
    let method = if req.method.is_empty() {
        "GET"
    } else {
        &req.method
    };
    write!(
        b,
        "{method} {req_uri} HTTP/{}.{}\r\n",
        req.proto_major, req.proto_minor
    )?;
    let absolute =
        req.request_uri.starts_with("http://") || req.request_uri.starts_with("https://");
    if !absolute {
        let host = if req.host.is_empty() {
            &req.url.host
        } else {
            &req.host
        };
        if !host.is_empty() {
            write!(b, "Host: {host}\r\n")?;
        }
    }
    let chunked = req
        .transfer_encoding
        .first()
        .is_some_and(|t| t == "chunked");
    if !req.transfer_encoding.is_empty() {
        write!(
            b,
            "Transfer-Encoding: {}\r\n",
            req.transfer_encoding.join(",")
        )?;
    }
    req.header
        .write_excluding(&mut b, &["Host", "Transfer-Encoding", "Trailer"], None)?;
    b.extend_from_slice(b"\r\n");
    if let Some(body) = body {
        let data = body.read_all()?;
        if chunked {
            let mut dest = ChunkedWriter::new(&mut b);
            dest.write_all(&data)?;
            dest.close()?;
            b.extend_from_slice(b"\r\n");
        } else {
            b.extend_from_slice(&data);
        }
    }
    Ok(b)
}

/// Go's `DumpRequestOut`: the bytes the crate's [`Transport`] would write for
/// `req`, including its default `User-Agent`, `Content-Length` or chunked
/// framing and `Accept-Encoding: gzip`. Without `body`, a request with a
/// body is dumped up to the end of its header.
///
/// [`Transport`]: crate::net::http::Transport
pub fn dump_request_out(req: &mut Request, body: bool) -> Result<Vec<u8>, BoxError> {
    let mut send = req.clone();
    let mut dummy = false;
    if !body {
        let length = req.outgoing_length();
        if length != 0 {
            // Go substitutes a body of `x` bytes of the declared length.
            send.body = Some(Body::from_reader(
                io::repeat(b'x').take(length.max(0) as u64),
            ));
            dummy = true;
        }
    } else if let Some(b) = &req.body {
        let (keep, copy) = drain_body(b)?;
        req.body = Some(keep);
        send.body = Some(copy);
    }
    match send.url.scheme.as_str() {
        "https" => send.url.scheme = "http".into(),
        "http" => {}
        scheme => {
            return Err(format!("unsupported protocol scheme {scheme:?}").into());
        }
    }
    if send.url.host.is_empty() {
        return Err(Box::new(ErrorString("http: no Host in request URL")));
    }
    for (name, values) in &send.header.0 {
        if !valid_header_field_name(name) {
            return Err(format!("net/http: invalid header field name {name:?}").into());
        }
        for value in values {
            if !valid_header_field_value(value) {
                return Err(format!("net/http: invalid header field value for {name:?}").into());
            }
        }
    }
    let mut extra = Header::new();
    if send.header.get_str("Accept-Encoding").is_empty()
        && send.header.get_str("Range").is_empty()
        && send.method != "HEAD"
    {
        extra.set("Accept-Encoding", "gzip");
    }
    let mut dump = Vec::new();
    send.write_impl(&mut dump, false, Some(&extra), None)?;
    if dummy {
        if let Some(end) = dump.windows(4).position(|w| w == b"\r\n\r\n") {
            dump.truncate(end + 4);
        }
    }
    Ok(dump)
}

/// A body that always fails, standing in for a body that was not requested.
struct FailureToReadBody;
impl Read for FailureToReadBody {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other(SENTINEL))
    }
}

/// Go's `DumpResponse`: the response as [`Response::write`] writes it. Without
/// `body`, only the head is returned unless the declared length is zero.
pub fn dump_response(resp: &mut Response, body: bool) -> Result<Vec<u8>, BoxError> {
    let save_length = resp.content_length;
    let (save, send) = match (&resp.body, body) {
        (Some(b), true) => {
            let (keep, send) = drain_body(b)?;
            (Some(keep), send)
        }
        (None, true) => (None, Body::from_bytes(Vec::new())),
        (_, false) if resp.content_length == 0 => (resp.body.take(), Body::from_bytes(Vec::new())),
        (_, false) => (resp.body.take(), Body::from_reader(FailureToReadBody)),
    };
    resp.body = Some(send);
    let mut out = Vec::new();
    let written = resp.write(&mut out);
    resp.body = save;
    resp.content_length = save_length;
    match written {
        Err(e) if e.to_string() != SENTINEL => Err(e),
        _ => Ok(out),
    }
}
