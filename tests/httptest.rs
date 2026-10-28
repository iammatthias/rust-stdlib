#![cfg(feature = "net")]
//! httptest behavior, including ports of Go's recorder_test.go,
//! httptest_test.go and server_test.go. TLS server variants live in
//! backends/tls/tests/gohttp.rs.
use rust_stdlib::net::http::{
    handler::{Flusher, ResponseWriter},
    handler_func,
    httptest::{request, ResponseRecorder, Server, DEFAULT_REMOTE_ADDR},
    status_text, RequestBody,
};
use rust_stdlib::testing::{self, Options};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// Run a handler (writes into the recorder) like `h.ServeHTTP`.
fn serve(handler: impl FnOnce(&mut ResponseRecorder)) -> ResponseRecorder {
    let mut recorder = ResponseRecorder::new();
    handler(&mut recorder);
    recorder
}

fn body_of(rec: &mut ResponseRecorder) -> Vec<u8> {
    rec.body.clone().unwrap_or_default()
}

#[test]
fn recorder_defaults_match_go() {
    let mut recorder = ResponseRecorder::new();
    assert_eq!(recorder.code, 200);
    assert!(recorder.header_map.0.is_empty());
    let result = recorder.result();
    assert_eq!(result.status_code, 200);
    assert!(result.body.unwrap().read_all().unwrap().is_empty());
    assert!(result.header.0.is_empty());
    assert_eq!(DEFAULT_REMOTE_ADDR, "1.2.3.4");
}

// Port of Go's TestRecorder table.
#[test]
fn go_recorder_200_default() {
    let mut rec = serve(|_| {});
    assert_eq!(rec.code, 200);
    assert!(body_of(&mut rec).is_empty());
    assert_eq!(rec.result().status, "200 OK");
}

#[test]
fn go_recorder_first_code_only() {
    let mut rec = serve(|w| {
        w.write_header(201);
        w.write_header(202);
        w.write_all(b"hi").unwrap();
    });
    assert_eq!(rec.code, 201);
    assert_eq!(body_of(&mut rec), b"hi");
}

#[test]
fn go_recorder_write_sends_200() {
    let mut rec = serve(|w| {
        w.write_all(b"hi first").unwrap();
        w.write_header(201);
        w.write_header(202);
    });
    assert_eq!(rec.code, 200);
    assert_eq!(body_of(&mut rec), b"hi first");
    assert!(!rec.flushed);
}

#[test]
fn go_recorder_write_string() {
    let mut rec = serve(|w| {
        w.write_string("hi first").unwrap();
    });
    assert_eq!(rec.code, 200);
    assert_eq!(body_of(&mut rec), b"hi first");
    assert!(!rec.flushed);
    assert_eq!(
        rec.result().header.get("Content-Type").unwrap_or(""),
        "text/plain; charset=utf-8"
    );
}

#[test]
fn go_recorder_flush() {
    let mut rec = serve(|w| {
        Flusher::flush(w);
        w.write_header(201);
    });
    assert_eq!(rec.code, 200);
    assert!(rec.flushed);
    assert_eq!(rec.result().content_length, -1);
}

#[test]
fn go_recorder_content_type_detection() {
    let mut rec = serve(|w| {
        w.write_string("<html>").unwrap();
    });
    assert_eq!(
        rec.result().header.get("Content-Type").unwrap_or(""),
        "text/html; charset=utf-8"
    );
    let mut rec = serve(|w| {
        w.header().set("Transfer-Encoding", "some encoding");
        w.write_string("<html>").unwrap();
    });
    assert!(!rec.result().header.0.contains_key("Content-Type"));
    let mut rec = serve(|w| {
        w.header().set("Content-Type", "some/type");
        w.write_string("<html>").unwrap();
    });
    assert_eq!(
        rec.result().header.get("Content-Type").unwrap_or(""),
        "some/type"
    );
}

#[test]
fn go_recorder_header_not_changed_after_write() {
    let mut rec = serve(|w| {
        w.header().set("Key", "correct");
        w.write_header(200);
        w.header().set("Key", "incorrect");
    });
    assert_eq!(rec.result().header.get("Key").unwrap_or(""), "correct");
}

#[test]
fn go_recorder_trailers() {
    let mut rec = serve(|w| {
        w.header().set("Non-Trailer", "correct");
        w.header().set("Trailer", "Trailer-A, Trailer-B");
        w.header().add("Trailer", "Trailer-C");
        w.write_string("<html>").unwrap();
        w.header().set("Non-Trailer", "incorrect");
        w.header().set("Trailer-A", "valuea");
        w.header().set("Trailer-C", "valuec");
        w.header().set("Trailer-Notdeclared", "should be omitted");
        w.header().set("Trailer:Trailer-D", "with prefix");
    });
    assert_eq!(rec.code, 200);
    let result = rec.result();
    assert_eq!(
        result.header.get("Content-Type").unwrap_or(""),
        "text/html; charset=utf-8"
    );
    assert_eq!(result.header.get("Non-Trailer").unwrap_or(""), "correct");
    for name in ["Trailer-A", "Trailer-B", "Trailer-C", "Trailer-Notdeclared"] {
        assert!(!result.header.0.contains_key(name), "{name}");
    }
    let trailers = result.trailer.get().expect("trailers");
    assert_eq!(trailers.get("Trailer-A").unwrap_or(""), "valuea");
    assert_eq!(trailers.get("Trailer-C").unwrap_or(""), "valuec");
    for name in ["Non-Trailer", "Trailer-B", "Trailer-Notdeclared"] {
        assert!(!trailers.0.contains_key(name), "{name}");
    }
}

#[test]
fn go_recorder_header_map_vs_final_headers() {
    let mut rec = serve(|w| {
        w.header().set("X-Foo", "1");
        w.write_all(b"hi").unwrap();
        w.header().set("X-Foo", "2");
        w.header().set("X-Bar", "2");
    });
    assert_eq!(rec.header_map.get("X-Foo").unwrap_or(""), "2");
    assert_eq!(rec.header_map.get("X-Bar").unwrap_or(""), "2");
    assert_eq!(rec.result().header.get("X-Foo").unwrap_or(""), "1");
    assert!(!rec.result().header.0.contains_key("X-Bar"));
}

#[test]
fn go_recorder_setting_content_length() {
    let mut rec = serve(|w| {
        w.header().set("Content-Length", "9");
        w.write_string("Some body").unwrap();
    });
    assert_eq!(rec.code, 200);
    assert_eq!(body_of(&mut rec), b"Some body");
    assert_eq!(rec.result().content_length, 9);
}

#[test]
fn go_body_not_allowed() {
    let mut rec = ResponseRecorder::new();
    rec.write_header(204);
    let error = rec.write(b"hello ").unwrap_err();
    assert!(error.to_string().contains("does not allow body"));
    assert!(rec.write_string("world").is_err());
    assert_eq!(body_of(&mut rec), b"hello world");
}

#[test]
fn go_parse_content_length() {
    for (value, want) in [
        ("3", 3),
        ("+3", -1),
        ("-3", -1),
        ("9223372036854775807", 9_223_372_036_854_775_807),
        ("9223372036854775808", -1),
    ] {
        let mut rec = ResponseRecorder::new();
        rec.header().set("Content-Length", value);
        assert_eq!(rec.result().content_length, want, "{value}");
    }
}

#[test]
fn go_recorder_rejects_invalid_codes() {
    // Go panics (the trait form); the checked variant returns an error and
    // records nothing.
    for code in [0, 99, 1000, 20000] {
        let mut rec = ResponseRecorder::new();
        assert!(rec.write_header_checked(code).is_err(), "{code}");
        assert_eq!(rec.code, 200);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut rec = ResponseRecorder::new();
            ResponseWriter::write_header(&mut rec, code);
        }));
        let msg = r.unwrap_err();
        let msg = msg.downcast_ref::<String>().cloned().unwrap_or_default();
        assert_eq!(msg, format!("invalid WriteHeader code {code}"));
    }
    // A second call is ignored before the code is checked, as in Go.
    let mut rec = ResponseRecorder::new();
    ResponseWriter::write_header(&mut rec, 204);
    ResponseWriter::write_header(&mut rec, 0);
    assert_eq!(rec.code, 204);
}

// Port of Go's TestNewRequest / TestNewRequestWithContext.
#[test]
fn go_request_cases() {
    let req = request("GET", "/", None).unwrap();
    assert_eq!(
        (req.method.as_str(), req.request_uri.as_str()),
        ("GET", "/")
    );
    assert_eq!(req.host, "example.com");
    assert_eq!(req.remote_addr, "192.0.2.1:1234");
    assert!(req.tls.is_none());
    let req = request("", "/", None).unwrap();
    assert_eq!(req.method, "GET");
    let req = request("GET", "http://foo.com/path/%2f/bar/", None).unwrap();
    assert_eq!(req.host, "foo.com");
    assert_eq!(req.url.escaped_path(), "/path/%2f/bar/");
    let req = request("GET", "https://foo.com/path/", None).unwrap();
    assert_eq!(req.host, "foo.com");
    assert!(req.tls.is_some());
    let req = request("POST", "/", Some(RequestBody::from("foo"))).unwrap();
    assert_eq!(req.content_length, 3);
    assert_eq!(req.body.unwrap().read_all().unwrap(), b"foo");
    // Go panics on these; the crate reports the error.
    assert!(request("GET", "relative", None).is_err());
    assert!(request("BAD METHOD", "/", None).is_err());
}

fn hello() -> std::sync::Arc<dyn rust_stdlib::net::http::Handler> {
    handler_func(|w, _| {
        let _ = w.write_string("hello");
    })
}

// Ports of Go's testServer / testGetAfterClose for NewServer and
// NewUnstartedServer + Start.
fn go_server_variants() -> Vec<Server> {
    let mut manual = Server::unstarted(hello()).unwrap();
    manual.start().unwrap();
    vec![Server::new(hello()).unwrap(), manual]
}

#[test]
fn go_server_and_get_after_close() {
    for mut server in go_server_variants() {
        assert!(server.url.starts_with("http://127.0.0.1:"));
        let url = server.url.clone();
        let client = server.client();
        let response = client.get(&url).unwrap();
        assert_eq!(response.body.unwrap().read_all().unwrap(), b"hello");
        server.close();
        assert!(client.get(&url).is_err());
    }
}

#[test]
fn go_server_close_blocking() {
    for mut server in go_server_variants() {
        let address = server.url.trim_start_matches("http://").to_owned();
        let _new = TcpStream::connect(&address).unwrap();
        let mut idle = TcpStream::connect(&address).unwrap();
        idle.write_all(b"HEAD / HTTP/1.1\r\nHost: foo\r\n\r\n")
            .unwrap();
        let mut reader = BufReader::new(idle.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.starts_with("HTTP/1.1 200"), "{line}");
        // Close must not wait for the New and Idle connections.
        let start = Instant::now();
        server.close();
        assert!(start.elapsed() < Duration::from_secs(5));
    }
}

#[test]
fn start_errors_match_go_panics() {
    let mut server = Server::unstarted(hello()).unwrap();
    server.start().unwrap();
    assert!(server.start().is_err());
    server.close();
}

#[test]
fn persistent_connections_like_go() {
    let mut server = Server::new(handler_func(|w, r| {
        let _ = w.write_string(&r.request_uri);
    }))
    .unwrap();
    let address = server.url.trim_start_matches("http://").to_owned();
    let mut stream = TcpStream::connect(&address).unwrap();
    stream
        .write_all(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    for target in ["/a", "/b"] {
        let mut head = String::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
            head.push_str(&line);
        }
        let mut body = vec![0; target.len()];
        reader.read_exact(&mut body).unwrap();
        assert_eq!(body, target.as_bytes());
        assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    }
    drop(reader);
    let start = Instant::now();
    server.close();
    assert!(start.elapsed() < Duration::from_secs(5));
    let mut rest = Vec::new();
    let _ = stream.read_to_end(&mut rest);
}

#[test]
fn status_text_matches_go_tables() {
    assert_eq!(status_text(418), "I'm a teapot");
    assert_eq!(status_text(413), "Request Entity Too Large");
    assert_eq!(status_text(299), "");
}

#[test]
fn close_waits_for_active_requests() {
    let mut server = Server::new(handler_func(|w, _| {
        std::thread::sleep(Duration::from_millis(200));
        let _ = w.write_string("done");
    }))
    .unwrap();
    let url = server.url.clone();
    let client = server.client();
    let pending = std::thread::spawn(move || {
        client
            .get(&url)
            .map(|r| r.body.unwrap().read_all().unwrap())
    });
    std::thread::sleep(Duration::from_millis(50));
    server.close();
    // Go's Close lets the Active request finish.
    assert_eq!(pending.join().unwrap().unwrap(), b"done");
}

#[test]
fn go_server_close_client_connections() {
    let mut server = Server::new(handler_func(|w, _| {
        std::thread::sleep(Duration::from_millis(300));
        let _ = w.write_string("too late");
    }))
    .unwrap();
    let url = server.url.clone();
    let client = server.client();
    let pending = std::thread::spawn(move || client.get(&url).is_err());
    std::thread::sleep(Duration::from_millis(100));
    server.close_client_connections();
    assert!(pending.join().unwrap());
    server.close();
}

#[test]
fn go_server_in_memory_network() {
    let report = testing::run_test_with(&Options::default(), "TestInMemory", |t| {
        let mut server = Server::for_test(
            t,
            Some(handler_func(|w, _| {
                let _ = w.write_string("ok");
            })),
        )
        .unwrap();
        let client = server.client();
        assert_eq!(server.url, "http://example.com");
        // Every host name reaches the server.
        for url in ["http://example.tld/", "http://127.0.0.1/", "http://[::1]/"] {
            assert_eq!(client.get(url).unwrap().status_code, 200, "{url}");
        }
        // HTTPS on the routed network needs the TLS backend.
        assert!(client.get("https://example.tld/").is_err());
        server.close();
    });
    assert!(report.ok, "{}", report.output);
}

#[test]
fn go_server_nil_handler() {
    let report = testing::run_test_with(&Options::default(), "TestNilHandler", |t| {
        let server = Server::for_test(t, None).unwrap();
        let response = server.client().get("http://example.tld/").unwrap();
        assert_eq!(response.status_code, 500);
    });
    assert!(report.ok, "{}", report.output);
}

#[test]
fn response_writer_is_io_write_for_gzip() {
    use rust_stdlib::compress::gzip;
    let mut rec = ResponseRecorder::new();
    {
        let w: &mut dyn ResponseWriter = &mut rec;
        w.header().set("Content-Encoding", "gzip");
        let mut gz = gzip::Writer::new(&mut *w);
        gz.write_all(b"hello, gzip over a borrowed ResponseWriter")
            .unwrap();
        gz.close().unwrap();
    }
    let body = body_of(&mut rec);
    let mut out = String::new();
    gzip::Reader::new(&body[..])
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    assert_eq!(out, "hello, gzip over a borrowed ResponseWriter");
}

#[test]
fn response_writer_copy_from_defaults_to_io_copy() {
    let mut rec = ResponseRecorder::new();
    let n = ResponseWriter::copy_from(&mut rec, &mut &b"copied body"[..]).unwrap();
    assert_eq!(n, 11);
    assert_eq!(body_of(&mut rec), b"copied body");
}

/// Go's embed files implement io.Seeker, so FileServerFS serves byte ranges
/// from them. Expected values come from Go 1.27's http.FileServerFS over an
/// embed.FS holding the same file.
#[test]
fn file_server_fs_serves_ranges_from_embed() {
    use rust_stdlib::net::http::fs::file_server_fs;
    use std::sync::Arc;
    let files = rust_stdlib::embed::FS::new(&[("files/a.txt", b"0123456789" as &'static [u8])]);
    let handler = file_server_fs(Arc::new(files));
    let cases = [
        ("bytes=0-3", 206, "bytes", "bytes 0-3/10", "4", &b"0123"[..]),
        ("bytes=8-", 206, "bytes", "bytes 8-9/10", "2", &b"89"[..]),
        (
            "bytes=20-",
            416,
            "",
            "bytes */10",
            "",
            &b"invalid range: failed to overlap\n"[..],
        ),
    ];
    for (range, code, accept, content_range, length, body) in cases {
        let mut req = request("GET", "/files/a.txt", None).unwrap();
        req.header.set("Range", range);
        let mut rec = ResponseRecorder::new();
        handler.serve_http(&mut rec, &mut req);
        assert_eq!(rec.code, code, "{range}");
        assert_eq!(
            rec.header_map.get("Accept-Ranges").unwrap_or(""),
            accept,
            "{range}"
        );
        assert_eq!(
            rec.header_map.get("Content-Range").unwrap_or(""),
            content_range,
            "{range}"
        );
        assert_eq!(
            rec.header_map.get("Content-Length").unwrap_or(""),
            length,
            "{range}"
        );
        assert_eq!(body_of(&mut rec), body, "{range}");
    }
}
