#![cfg(feature = "net")]
//! Ports of Go's `net/http/cgi` child tests, a CGI handler run against a shell
//! script, and FastCGI conversations over loopback.
use rust_stdlib::net::http::cgi;
use rust_stdlib::net::http::fcgi;
use rust_stdlib::net::http::request::Request;
use rust_stdlib::net::http::{handler_func, Handler, Header, ResponseWriter};
use rust_stdlib::net::listen;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).into(), (*v).into()))
        .collect()
}

#[test]
fn request() {
    let req = cgi::request_from_map(&env(&[
        ("SERVER_PROTOCOL", "HTTP/1.1"),
        ("REQUEST_METHOD", "GET"),
        ("HTTP_HOST", "example.com"),
        ("HTTP_REFERER", "elsewhere"),
        ("HTTP_USER_AGENT", "goclient"),
        ("HTTP_FOO_BAR", "baz"),
        ("REQUEST_URI", "/path?a=b"),
        ("CONTENT_LENGTH", "123"),
        ("CONTENT_TYPE", "text/xml"),
        ("REMOTE_ADDR", "5.6.7.8"),
        ("REMOTE_PORT", "54321"),
    ]))
    .unwrap();
    assert_eq!(req.header.get("User-Agent").unwrap_or(""), "goclient");
    assert_eq!(req.method, "GET");
    assert_eq!(req.header.get("Content-Type").unwrap_or(""), "text/xml");
    assert_eq!(req.content_length, 123);
    assert_eq!(req.header.get("Referer").unwrap_or(""), "elsewhere");
    assert_eq!(req.header.get("Foo-Bar").unwrap_or(""), "baz");
    assert_eq!(req.url.to_string(), "http://example.com/path?a=b");
    assert_eq!(req.url.query().get("a"), "b");
    assert!(req.trailer.get().is_some());
    assert!(req.tls.is_none());
    assert_eq!(req.remote_addr, "5.6.7.8:54321");
}

#[test]
fn request_with_tls() {
    let req = cgi::request_from_map(&env(&[
        ("SERVER_PROTOCOL", "HTTP/1.1"),
        ("REQUEST_METHOD", "GET"),
        ("HTTP_HOST", "example.com"),
        ("REQUEST_URI", "/path?a=b"),
        ("HTTPS", "1"),
        ("REMOTE_ADDR", "5.6.7.8"),
    ]))
    .unwrap();
    assert_eq!(req.url.to_string(), "https://example.com/path?a=b");
    assert!(req.tls.is_some());
}

#[test]
fn request_without_host_request_uri_and_remote_port() {
    let req = cgi::request_from_map(&env(&[
        ("SERVER_PROTOCOL", "HTTP/1.1"),
        ("HTTP_HOST", ""),
        ("REQUEST_METHOD", "GET"),
        ("REQUEST_URI", "/path?a=b"),
        ("CONTENT_LENGTH", "123"),
    ]))
    .unwrap();
    assert_eq!(req.url.to_string(), "/path?a=b");

    let req = cgi::request_from_map(&env(&[
        ("SERVER_PROTOCOL", "HTTP/1.1"),
        ("HTTP_HOST", "example.com"),
        ("REQUEST_METHOD", "GET"),
        ("SCRIPT_NAME", "/dir/scriptname"),
        ("PATH_INFO", "/p1/p2"),
        ("QUERY_STRING", "a=1&b=2"),
    ]))
    .unwrap();
    assert_eq!(
        req.url.to_string(),
        "http://example.com/dir/scriptname/p1/p2?a=1&b=2"
    );

    let req = cgi::request_from_map(&env(&[
        ("SERVER_PROTOCOL", "HTTP/1.1"),
        ("HTTP_HOST", "example.com"),
        ("REQUEST_METHOD", "GET"),
        ("REQUEST_URI", "/path"),
        ("REMOTE_ADDR", "5.6.7.8"),
    ]))
    .unwrap();
    assert_eq!(req.remote_addr, "5.6.7.8:0");
}

#[test]
fn included_server_protocol_and_errors() {
    let req = cgi::request_from_map(&env(&[
        ("REQUEST_METHOD", "GET"),
        ("SERVER_PROTOCOL", "INCLUDED"),
    ]))
    .unwrap();
    assert_eq!(
        (req.proto.as_str(), req.proto_major, req.proto_minor),
        ("INCLUDED", 1, 0)
    );

    let err = cgi::request_from_map(&env(&[("SERVER_PROTOCOL", "HTTP/1.1")])).unwrap_err();
    assert_eq!(err.to_string(), "cgi: no REQUEST_METHOD in environment");
    let err = cgi::request_from_map(&env(&[
        ("REQUEST_METHOD", "GET"),
        ("SERVER_PROTOCOL", "HTTP/9"),
    ]))
    .unwrap_err();
    assert_eq!(err.to_string(), "cgi: invalid SERVER_PROTOCOL version");
    let err = cgi::request_from_map(&env(&[
        ("REQUEST_METHOD", "GET"),
        ("SERVER_PROTOCOL", "HTTP/1.1"),
        ("CONTENT_LENGTH", "x"),
    ]))
    .unwrap_err();
    assert_eq!(err.to_string(), "cgi: bad CONTENT_LENGTH in environment: x");
}

/// A recording ResponseWriter.
#[derive(Default)]
struct Recorder {
    code: u16,
    header: Header,
    body: Vec<u8>,
}

impl std::io::Write for Recorder {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.code == 0 {
            self.code = 200;
        }
        self.body.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl ResponseWriter for Recorder {
    fn header(&mut self) -> &mut Header {
        &mut self.header
    }
    fn write_header(&mut self, code: u16) {
        if self.code == 0 {
            self.code = code;
        }
    }
}

#[cfg(unix)]
#[test]
fn handler_runs_a_script() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("rust-stdlib-cgi-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join("hello.sh");
    std::fs::write(
        &script,
        "#!/bin/sh\nprintf 'Status: 201 Created\\r\\nContent-Type: text/plain\\r\\nX-Method: %s\\r\\n\\r\\n' \"$REQUEST_METHOD\"\nprintf 'path=%s query=%s body=' \"$PATH_INFO\" \"$QUERY_STRING\"\ncat\n",
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let h = cgi::Handler {
        path: script.to_string_lossy().into_owned(),
        root: "/app".into(),
        ..cgi::Handler::default()
    };
    let mut req = Request::new("POST", "http://example.com/app/extra?x=1")
        .map(|r| r.with_body(b"posted".to_vec()))
        .unwrap();
    let mut rec = Recorder::default();
    h.serve_http(&mut rec, &mut req);
    assert_eq!(rec.code, 201);
    assert_eq!(rec.header.get("X-Method").unwrap_or(""), "POST");
    assert_eq!(rec.header.get("Content-Type").unwrap_or(""), "text/plain");
    assert_eq!(
        String::from_utf8_lossy(&rec.body),
        "path=/extra query=x=1 body=posted"
    );

    // Chunked bodies are rejected.
    let mut req = Request::new("POST", "http://example.com/app").unwrap();
    req.transfer_encoding = vec!["chunked".into()];
    let mut rec = Recorder::default();
    h.serve_http(&mut rec, &mut req);
    assert_eq!(rec.code, 400);
    assert_eq!(
        rec.body,
        b"Chunked request bodies are not supported by CGI."
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[cfg(unix)]
#[test]
fn handler_reports_a_bad_script_as_500() {
    let h = cgi::Handler {
        path: "/nonexistent/cgi-program".into(),
        logger: Some(Arc::new(rust_stdlib::log::Logger::new(
            Vec::<u8>::new(),
            "",
            0,
        ))),
        ..cgi::Handler::default()
    };
    let mut req = Request::new("GET", "http://example.com/").unwrap();
    let mut rec = Recorder::default();
    h.serve_http(&mut rec, &mut req);
    assert_eq!(rec.code, 500);
}

// ------------------------------------------------------------------ FastCGI

fn record(typ: u8, id: u16, content: &[u8]) -> Vec<u8> {
    let pad = (content.len().wrapping_neg()) & 7;
    let mut out = vec![1, typ];
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(content.len() as u16).to_be_bytes());
    out.push(pad as u8);
    out.push(0);
    out.extend_from_slice(content);
    out.extend(std::iter::repeat_n(0, pad));
    out
}

fn pairs(list: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (k, v) in list {
        out.push(k.len() as u8);
        out.push(v.len() as u8);
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(v.as_bytes());
    }
    out
}

fn read_until_end(s: &mut TcpStream) -> Vec<(u8, u16, Vec<u8>)> {
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut records = Vec::new();
    loop {
        let mut h = [0u8; 8];
        if s.read_exact(&mut h).is_err() {
            return records;
        }
        let len = usize::from(u16::from_be_bytes([h[4], h[5]]));
        let mut body = vec![0u8; len + usize::from(h[6])];
        s.read_exact(&mut body).unwrap();
        body.truncate(len);
        let typ = h[1];
        records.push((typ, u16::from_be_bytes([h[2], h[3]]), body));
        if typ == 3 {
            return records;
        }
    }
}

fn start(handler: Arc<dyn Handler>) -> TcpStream {
    let l = listen("tcp", "127.0.0.1:0").unwrap();
    let addr = l.addr().unwrap().to_string();
    thread::spawn(move || {
        let _ = fcgi::serve(Some(&*l), Some(handler));
    });
    TcpStream::connect(addr).unwrap()
}

#[test]
fn responder_round_trip_and_process_env() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    let mut s = start(handler_func(
        move |w: &mut dyn ResponseWriter, r: &mut Request| {
            let mut body = Vec::new();
            if let Some(b) = r.body.as_mut() {
                let _ = b.read_to_end(&mut body);
            }
            let env = fcgi::process_env(r).unwrap_or_default();
            let mut keys: Vec<_> = env.keys().cloned().collect();
            keys.sort();
            seen2.lock().unwrap().push(keys);
            w.header().set("Content-Type", "text/plain");
            let _ = w.write(
                format!("{} {} {}", r.method, r.url, String::from_utf8_lossy(&body)).as_bytes(),
            );
        },
    ));
    let mut out = record(1, 1, &[0, 1, 1, 0, 0, 0, 0, 0]);
    out.extend(record(
        4,
        1,
        &pairs(&[
            ("REQUEST_METHOD", "POST"),
            ("SERVER_PROTOCOL", "HTTP/1.1"),
            ("REQUEST_URI", "/x?y=1"),
            ("HTTP_HOST", "example.com"),
            ("REMOTE_USER", "alice"),
            ("SERVER_SOFTWARE", "test"),
        ]),
    ));
    out.extend(record(4, 1, b""));
    out.extend(record(5, 1, b"hello"));
    out.extend(record(5, 1, b""));
    s.write_all(&out).unwrap();
    let records = read_until_end(&mut s);
    let stdout: Vec<u8> = records
        .iter()
        .filter(|r| r.0 == 6)
        .flat_map(|r| r.2.clone())
        .collect();
    let text = String::from_utf8_lossy(&stdout);
    assert!(
        text.starts_with("Status: 200 OK\r\nContent-Type: text/plain\r\n"),
        "{text}"
    );
    assert!(
        text.ends_with("\r\n\r\nPOST http://example.com/x?y=1 hello"),
        "{text}"
    );
    assert_eq!(records.last().unwrap().0, 3);
    // Variables the request does not carry are available from the context.
    assert_eq!(seen.lock().unwrap()[0], ["REMOTE_USER", "SERVER_SOFTWARE"]);
}

#[test]
fn get_values_unknown_role_and_unknown_type() {
    let mut s = start(handler_func(
        |_: &mut dyn ResponseWriter, _: &mut Request| {},
    ));
    s.write_all(&record(9, 0, &pairs(&[("FCGI_MPXS_CONNS", "")])))
        .unwrap();
    s.write_all(&record(1, 5, &[0, 2, 0, 0, 0, 0, 0, 0]))
        .unwrap();
    // An unknown record type is only answered for a request in flight.
    s.write_all(&record(1, 6, &[0, 1, 1, 0, 0, 0, 0, 0]))
        .unwrap();
    s.write_all(&record(77, 6, b"zzz")).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut got = Vec::new();
    for _ in 0..4 {
        let mut h = [0u8; 8];
        s.read_exact(&mut h).unwrap();
        let len = usize::from(u16::from_be_bytes([h[4], h[5]]));
        let mut body = vec![0u8; len + usize::from(h[6])];
        s.read_exact(&mut body).unwrap();
        body.truncate(len);
        got.push((h[1], body));
    }
    assert_eq!(got[0].0, 10);
    assert_eq!(got[0].1, pairs(&[("FCGI_MPXS_CONNS", "1")]));
    // The stream ends with an empty record.
    assert_eq!((got[1].0, got[1].1.len()), (10, 0));
    // End request with protocol status "unknown role" (3).
    assert_eq!((got[2].0, got[2].1[4]), (3, 3));
    // Unknown record type: type 11 holding the offending type.
    assert_eq!((got[3].0, got[3].1[0]), (11, 77));
}

#[test]
fn aborted_requests_and_closed_connections_surface_as_read_errors() {
    let (tx, rx) = std::sync::mpsc::channel();
    let tx = Mutex::new(tx);
    let mut s = start(handler_func(
        move |w: &mut dyn ResponseWriter, r: &mut Request| {
            let mut buf = Vec::new();
            let err = r.body.as_mut().unwrap().read_to_end(&mut buf).unwrap_err();
            let _ = tx.lock().unwrap().send(err.to_string());
            let _ = w.write(b"done");
        },
    ));
    let mut out = record(1, 1, &[0, 1, 1, 0, 0, 0, 0, 0]);
    out.extend(record(
        4,
        1,
        &pairs(&[("REQUEST_METHOD", "POST"), ("SERVER_PROTOCOL", "HTTP/1.1")]),
    ));
    out.extend(record(4, 1, b""));
    out.extend(record(5, 1, b"partial"));
    out.extend(record(2, 1, b""));
    s.write_all(&out).unwrap();
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        fcgi::ERR_REQUEST_ABORTED.to_string()
    );
    assert_eq!(
        fcgi::ERR_REQUEST_ABORTED.to_string(),
        "fcgi: request aborted by web server"
    );
    assert_eq!(
        fcgi::ERR_CONN_CLOSED.to_string(),
        "fcgi: connection to web server closed"
    );
}
