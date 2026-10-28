#![cfg(feature = "net")]
//! httputil behavior, including ports of Go's dump_test.go and
//! internal/chunked_test.go. The dumps, persistent connections and reverse
//! proxy are also checked against Go itself by `tools/httputil_check.py`.
use rust_stdlib::net::http::{
    header::Header,
    httputil::{
        dump_request, dump_request_out, dump_response, ChunkedReader, ChunkedWriter,
        ERR_LINE_TOO_LONG,
    },
    request::read_request,
    Body, BufioReader, Request, RequestBody, Response,
};
use std::io::{self, Cursor, Read, Write};

/// A request as a server receives it (`host` and `transfer-encoding` fields
/// become `Request::host` and `Request::transfer_encoding`).
fn server_request(
    method: &str,
    target: &str,
    fields: &[(&str, &str)],
    body: &[u8],
    minor: i32,
) -> Request {
    let mut req = Request::default();
    req.method = method.into();
    req.request_uri = target.into();
    req.proto_major = 1;
    req.proto_minor = minor;
    for (name, value) in fields {
        match name.to_ascii_lowercase().as_str() {
            "host" => req.host = (*value).into(),
            "transfer-encoding" => req.transfer_encoding.push((*value).into()),
            _ => req.header.add(name, value),
        }
    }
    req.body = Some(Body::from_bytes(body.to_vec()));
    req
}
/// `http.NewRequest(method, "http://"+host+target, body)`.
fn client_request(method: &str, target: &str, fields: &[(&str, &str)], body: &[u8]) -> Request {
    let host = fields
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map_or("", |(_, value)| value);
    let mut req = Request::new(method, &format!("http://{host}{target}"))
        .unwrap()
        .with_body(RequestBody::Bytes(body.to_vec()));
    for (name, value) in fields {
        if !name.eq_ignore_ascii_case("host") {
            req.header.add(name, value);
        }
    }
    req
}
fn response(status: u16, fields: &[(&str, &str)], body: &[u8]) -> Response {
    let mut header = Header::new();
    let mut transfer_encoding = Vec::new();
    for (name, value) in fields {
        if name.eq_ignore_ascii_case("transfer-encoding") {
            transfer_encoding.push((*value).to_owned());
        } else {
            header.add(name, value);
        }
    }
    let content_length = if transfer_encoding.first().is_some_and(|t| t == "chunked") {
        -1
    } else {
        header
            .get("Content-Length")
            .unwrap_or("")
            .trim()
            .parse::<i64>()
            .unwrap_or(body.len() as i64)
    };
    Response {
        status_code: status,
        proto_major: 1,
        proto_minor: 1,
        header,
        transfer_encoding,
        content_length,
        body: Some(Body::from_bytes(body.to_vec())),
        ..Response::default()
    }
}
fn read(raw: &str) -> Request {
    read_request(&BufioReader::new(Cursor::new(raw.as_bytes().to_vec()))).unwrap()
}
fn text(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap()
}

// ---- Go dump_test.go ----

#[test]
fn go_dump_request_chunked_get() {
    let mut req = server_request(
        "GET",
        "/search",
        &[("host", "www.google.com"), ("transfer-encoding", "chunked")],
        b"abcdef",
        1,
    );
    assert_eq!(
        text(dump_request(&mut req, true).unwrap()),
        "GET /search HTTP/1.1\r\nHost: www.google.com\r\nTransfer-Encoding: chunked\r\n\r\n\
         6\r\nabcdef\r\n0\r\n\r\n"
    );
}

#[test]
fn go_dump_request_keeps_version_without_host_or_agent() {
    let mut req = server_request("GET", "/foo", &[("x-foo", "X-Bar")], b"", 0);
    assert_eq!(
        text(dump_request(&mut req, true).unwrap()),
        "GET /foo HTTP/1.0\r\nX-Foo: X-Bar\r\n\r\n"
    );
}

#[test]
fn dump_request_restores_the_body() {
    let mut req = server_request("POST", "/", &[("host", "h")], b"abc", 1);
    assert!(dump_request(&mut req, true).unwrap().ends_with(b"abc"));
    assert_eq!(req.body.unwrap().read_all().unwrap(), b"abc");
}

#[test]
fn go_dump_request_out_defaults() {
    let mut req = client_request("GET", "/foo", &[("host", "example.com")], b"");
    let want = "GET /foo HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Go-http-client/1.1\r\n\
                Accept-Encoding: gzip\r\n\r\n";
    assert_eq!(text(dump_request_out(&mut req, true).unwrap()), want);
    assert_eq!(text(dump_request_out(&mut req, false).unwrap()), want);
}

#[test]
fn go_dump_request_out_without_body() {
    let mut req = client_request("POST", "/", &[("host", "post.tld")], b"abcdef");
    assert_eq!(
        text(dump_request_out(&mut req, false).unwrap()),
        "POST / HTTP/1.1\r\nHost: post.tld\r\nUser-Agent: Go-http-client/1.1\r\n\
         Content-Length: 6\r\nAccept-Encoding: gzip\r\n\r\n"
    );
}

#[test]
fn go_dump_request_large_body() {
    let body = vec![b'a'; 8193];
    let a = "a".repeat(8193);
    let mut req = client_request("POST", "/", &[("host", "post.tld")], &body);
    assert_eq!(
        text(dump_request_out(&mut req, true).unwrap()),
        format!(
            "POST / HTTP/1.1\r\nHost: post.tld\r\nUser-Agent: Go-http-client/1.1\r\n\
             Content-Length: 8193\r\nAccept-Encoding: gzip\r\n\r\n{a}"
        )
    );
    let mut req = server_request(
        "POST",
        "/",
        &[("host", "post.tld"), ("content-length", "8193")],
        &body,
        1,
    );
    assert_eq!(
        text(dump_request(&mut req, true).unwrap()),
        format!("POST / HTTP/1.1\r\nHost: post.tld\r\nContent-Length: 8193\r\n\r\n{a}")
    );
}

#[test]
fn go_dump_request_absolute_target_omits_host() {
    let mut req = server_request("GET", "http://foo.com/", &[("user-agent", "blah")], b"", 1);
    assert_eq!(
        text(dump_request(&mut req, false).unwrap()),
        "GET http://foo.com/ HTTP/1.1\r\nUser-Agent: blah\r\n\r\n"
    );
}

#[test]
fn go_dump_request_content_length_issue_7215() {
    let mut req = read(
        "POST /v2/api/?login HTTP/1.1\r\nHost: passport.myhost.com\r\nContent-Length: 3\r\n\
         \r\nkey1=name1&key2=name2",
    );
    assert_eq!(
        text(dump_request(&mut req, true).unwrap()),
        "POST /v2/api/?login HTTP/1.1\r\nHost: passport.myhost.com\r\nContent-Length: 3\r\n\r\nkey"
    );
    let mut req = read(
        "POST /v2/api/?login HTTP/1.1\r\nHost: passport.myhost.com\r\nContent-Length: 0\r\n\r\n",
    );
    assert_eq!(
        text(dump_request(&mut req, true).unwrap()),
        "POST /v2/api/?login HTTP/1.1\r\nHost: passport.myhost.com\r\nContent-Length: 0\r\n\r\n"
    );
    let mut req = read("POST /v2/api/?login HTTP/1.1\r\nHost: passport.myhost.com\r\n\r\n");
    assert_eq!(
        text(dump_request(&mut req, true).unwrap()),
        "POST /v2/api/?login HTTP/1.1\r\nHost: passport.myhost.com\r\n\r\n"
    );
}

#[test]
fn go_dump_request_out_empty_post() {
    let mut req = client_request("POST", "/foo", &[("host", "example.com")], b"");
    assert_eq!(
        text(dump_request_out(&mut req, true).unwrap()),
        "POST /foo HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Go-http-client/1.1\r\n\
         Content-Length: 0\r\nAccept-Encoding: gzip\r\n\r\n"
    );
}

#[test]
fn go_dump_request_connection_not_duplicated_issue_54616() {
    let mut req = read("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
    assert_eq!(
        text(dump_request(&mut req, false).unwrap()),
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
    );
}

#[test]
fn dump_request_out_requires_host() {
    let mut req = Request::new("GET", "/").unwrap();
    assert!(dump_request_out(&mut req, true).is_err());
}

#[test]
fn go_dump_response_table() {
    let mut res = response(200, &[("foo", "Bar"), ("content-length", "50")], b"foo");
    assert_eq!(
        text(dump_response(&mut res, false).unwrap()),
        "HTTP/1.1 200 OK\r\nContent-Length: 50\r\nFoo: Bar\r\n\r\n"
    );
    let mut res = response(200, &[], b"foo");
    assert_eq!(
        text(dump_response(&mut res, true).unwrap()),
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nfoo"
    );
    let mut res = response(200, &[("transfer-encoding", "chunked")], b"foo");
    assert_eq!(
        text(dump_response(&mut res, true).unwrap()),
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nfoo\r\n0\r\n\r\n"
    );
    let mut res = response(200, &[("foo1", "Bar1"), ("foo2", "Bar2")], b"");
    assert_eq!(
        text(dump_response(&mut res, false).unwrap()),
        "HTTP/1.1 200 OK\r\nFoo1: Bar1\r\nFoo2: Bar2\r\nContent-Length: 0\r\n\r\n"
    );
}

#[test]
fn dump_response_edge_cases() {
    // Unknown status text, an unknown-length body and a length mismatch.
    let mut res = response(299, &[], b"");
    assert_eq!(
        text(dump_response(&mut res, true).unwrap()),
        "HTTP/1.1 299 status code 299\r\nContent-Length: 0\r\n\r\n"
    );
    let mut res = response(200, &[("content-length", "0")], b"abc");
    assert_eq!(
        text(dump_response(&mut res, true).unwrap()),
        "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nabc"
    );
    let mut res = response(200, &[("content-length", "5")], b"abc");
    assert!(dump_response(&mut res, true).is_err());
    let mut res = response(204, &[], b"");
    assert_eq!(
        text(dump_response(&mut res, true).unwrap()),
        "HTTP/1.1 204 No Content\r\n\r\n"
    );
}

// ---- Go internal/chunked_test.go ----

#[test]
fn go_chunk() {
    let mut writer = ChunkedWriter::new(Vec::new());
    writer.write_all(b"hello, ").unwrap();
    writer.write_all(b"world! 0123456789abcdef").unwrap();
    writer.close().unwrap();
    let wire = writer.into_inner();
    assert_eq!(
        text(wire.clone()),
        "7\r\nhello, \r\n17\r\nworld! 0123456789abcdef\r\n0\r\n"
    );
    let mut data = Vec::new();
    ChunkedReader::new(&wire[..])
        .read_to_end(&mut data)
        .unwrap();
    assert_eq!(data, b"hello, world! 0123456789abcdef");
}

#[test]
fn go_chunk_read_multiple() {
    let mut reader = ChunkedReader::new(&b"3\r\nfoo\r\n3\r\nbar\r\n0\r\n"[..]);
    let mut buf = [0; 10];
    assert_eq!(reader.read(&mut buf).unwrap(), 6);
    assert_eq!(&buf[..6], b"foobar");
    assert_eq!(reader.read(&mut buf).unwrap(), 0);

    // The 16-byte buffer holds the first chunk exactly, so the second chunk
    // header is not read until the next call.
    let wire = b"b\r\n0123456789a\r\n3\r\nfoo\r\n0\r\n";
    let mut reader = ChunkedReader::with_buffer_size(&wire[..], 16);
    let mut buf = [0; 14];
    assert_eq!(reader.read(&mut buf).unwrap(), 11);
    assert_eq!(&buf[..11], b"0123456789a");
    assert_eq!(reader.read(&mut buf).unwrap(), 3);
    assert_eq!(reader.read(&mut buf).unwrap(), 0);

    let mut reader = ChunkedReader::new(&b"3\r\nfoo\r\n0\r\n"[..]);
    let mut buf = [0; 3];
    assert_eq!(reader.read(&mut buf).unwrap(), 3);
    assert_eq!(&buf, b"foo");
    assert_eq!(reader.read(&mut buf).unwrap(), 0);
}

fn read_all(wire: &[u8]) -> (Vec<u8>, Option<io::Error>) {
    let mut data = Vec::new();
    let error = ChunkedReader::new(wire).read_to_end(&mut data).err();
    (data, error)
}

#[test]
fn go_parse_hex_uint() {
    let cases: &[(&str, Option<u64>, &str)] = &[
        ("x", None, "invalid byte in chunk length"),
        ("0000000000000000", Some(0), ""),
        ("0000000000000001", Some(1), ""),
        ("000000000000bogus", None, "invalid byte in chunk length"),
        ("00000000000000000", None, "http chunk length too large"),
        ("10000000000000000", None, "http chunk length too large"),
        ("00000000000000001", None, "http chunk length too large"),
        ("", None, "empty hex number for chunk length"),
    ];
    for (input, want, message) in cases {
        let wire = format!("{input}\r\n");
        let (_, error) = read_all(wire.as_bytes());
        match want {
            // A valid size is accepted; 0 ends the body, 1 runs out of data.
            Some(0) => assert!(error.is_none(), "{input}"),
            Some(_) => assert_eq!(error.unwrap().to_string(), "unexpected EOF", "{input}"),
            None => assert_eq!(error.unwrap().to_string(), *message, "{input}"),
        }
    }
    for size in 1..=1234u32 {
        let wire = format!("{size:x}\r\n{}\r\n0\r\n", "z".repeat(size as usize));
        let (data, error) = read_all(wire.as_bytes());
        assert!(error.is_none());
        assert_eq!(data.len(), size as usize);
    }
}

#[test]
fn go_chunk_reading_ignores_extensions() {
    let wire = b"7;ext=\"some quoted string\"\r\nhello, \r\n17;someext\r\n\
                 world! 0123456789abcdef\r\n0;someextension=sometoken\r\n";
    let (data, error) = read_all(wire);
    assert!(error.is_none());
    assert_eq!(data, b"hello, world! 0123456789abcdef");
}

/// Yields scripted reads, then an error or EOF.
struct Script {
    reads: Vec<Vec<u8>>,
    error: Option<io::ErrorKind>,
}
impl Read for Script {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.reads.is_empty() {
            return match self.error {
                Some(kind) => Err(io::Error::new(kind, "chunk end read error")),
                None => Ok(0),
            };
        }
        let next = &mut self.reads[0];
        let n = next.len().min(buf.len());
        buf[..n].copy_from_slice(&next[..n]);
        next.drain(..n);
        if next.is_empty() {
            self.reads.remove(0);
        }
        Ok(n)
    }
}

#[test]
fn go_chunk_read_partial() {
    let mut reader = ChunkedReader::new(Script {
        reads: vec![b"7\r\n1234567".to_vec(), b"xx".to_vec()],
        error: None,
    });
    let mut buf = [0; 7];
    assert_eq!(reader.read(&mut buf).unwrap(), 7);
    assert_eq!(&buf, b"1234567");
    let error = reader.read(&mut buf).unwrap_err();
    assert!(error.to_string().contains("malformed"));
}

#[test]
fn go_incomplete_chunk() {
    let valid = b"4\r\nabcd\r\n5\r\nabc\r\n\r\n0\r\n";
    for i in 0..valid.len() {
        let (_, error) = read_all(&valid[..i]);
        let error = error.unwrap_or_else(|| panic!("{i}"));
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof, "{i}");
    }
    assert!(read_all(valid).1.is_none());
}

#[test]
fn go_chunk_end_read_error() {
    let mut reader = ChunkedReader::new(Script {
        reads: vec![b"4\r\nabcd".to_vec()],
        error: Some(io::ErrorKind::ConnectionReset),
    });
    let mut data = Vec::new();
    let error = reader.read_to_end(&mut data).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(data, b"abcd");
}

#[test]
fn go_chunk_reader_too_much_overhead_and_byte_at_a_time() {
    let mut chunk = b"1;".to_vec();
    chunk.extend_from_slice(&[b'a'; 100]);
    chunk.extend_from_slice(b"\r\nX\r\n");
    let mut wire = chunk.repeat(1000);
    wire.extend_from_slice(b"0\r\n");
    let (_, error) = read_all(&wire);
    assert_eq!(
        error.unwrap().to_string(),
        "chunked encoding contains too much non-data"
    );
    let mut wire = b"1\r\nX\r\n".repeat(1 << 16);
    wire.extend_from_slice(b"0\r\n");
    let (data, error) = read_all(&wire);
    assert!(error.is_none());
    assert_eq!(data.len(), 1 << 16);
}

#[test]
fn go_chunk_invalid_inputs() {
    for wire in [
        &b"1\na\r\n0\r\n"[..],
        b"1\r\r\na\r\n0\r\n",
        b"1\r\na\n0\r\n",
        b"1;\na\r\n0\r\n",
    ] {
        assert!(read_all(wire).1.is_some(), "{wire:?}");
    }
}

#[test]
fn chunk_line_too_long_and_trailers_left_unread() {
    let mut wire = b"1;".to_vec();
    wire.extend_from_slice(&[b'e'; 4100]);
    wire.extend_from_slice(b"\r\nx\r\n0\r\n");
    assert_eq!(read_all(&wire).1.unwrap().to_string(), ERR_LINE_TOO_LONG);
    // The reader stops at the last-chunk line, leaving trailers to the caller.
    let (data, error) = read_all(b"2\r\nab\r\n0\r\nX-T: v\r\n\r\n");
    assert!(error.is_none());
    assert_eq!(data, b"ab");
}
