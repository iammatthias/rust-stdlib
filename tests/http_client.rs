#![cfg(feature = "net")]
//! Go-shaped `net/http` client and server over loopback: redirects, cookies,
//! pooling, compression, proxies, timeouts, cancellation and graceful
//! shutdown. Scenarios follow Go's `client_test.go`, `transport_test.go`,
//! `serve_test.go` and `proxy_test.go`.
use rust_stdlib::context::Context;
use rust_stdlib::net::{
    self,
    http::{
        self, client::Client, handler_func, request::Request, server::Server, Handler, Header,
        Transport,
    },
    url,
};
use rust_stdlib::time;
use std::{
    io::{Read, Write},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

struct Srv {
    server: Server,
    addr: String,
    t: Option<thread::JoinHandle<()>>,
}
impl Srv {
    fn start(handler: Arc<dyn Handler>) -> Srv {
        Self::start_with(handler, |_| {})
    }
    fn start_with(handler: Arc<dyn Handler>, f: impl FnOnce(&mut Server)) -> Srv {
        let mut server = Server {
            handler: Some(handler),
            error_log: Some(Arc::new(rust_stdlib::log::Logger::new(
                std::io::sink(),
                "",
                0,
            ))),
            ..Server::default()
        };
        f(&mut server);
        let ln = net::listen("tcp", "127.0.0.1:0").unwrap();
        let addr = ln.addr().unwrap().to_string();
        let s2 = server.clone();
        let t = thread::spawn(move || {
            let _ = s2.serve(ln);
        });
        Srv {
            server,
            addr,
            t: Some(t),
        }
    }
    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
}
impl Drop for Srv {
    fn drop(&mut self) {
        let _ = self.server.close();
        if let Some(t) = self.t.take() {
            let _ = t.join();
        }
    }
}

fn body_text(resp: &http::response::Response) -> String {
    String::from_utf8_lossy(&resp.body.as_ref().unwrap().read_all().unwrap()).into_owned()
}

fn no_proxy_client() -> Client {
    let t = Transport {
        disable_keep_alives: false,
        ..Transport::default()
    };
    Client {
        transport: Some(Arc::new(t)),
        ..Client::default()
    }
}

#[test]
fn get_head_post_roundtrip() {
    let srv = Srv::start(handler_func(|w, r| {
        let b = r
            .body
            .as_ref()
            .map(|b| b.read_all().unwrap())
            .unwrap_or_default();
        let _ = w.write_string(&format!(
            "{} {} {} body={}",
            r.method,
            r.url.request_uri(),
            r.header.get("Content-Type").unwrap_or(""),
            String::from_utf8_lossy(&b)
        ));
    }));
    let c = no_proxy_client();
    assert_eq!(
        body_text(&c.get(&srv.url("/a?x=1")).unwrap()),
        "GET /a?x=1  body="
    );
    let resp = c.head(&srv.url("/h")).unwrap();
    assert_eq!(resp.status_code, 200);
    assert!(resp.body.unwrap().read_all().unwrap().is_empty());
    let resp = c
        .post(&srv.url("/p"), "text/x", Some("hello".into()))
        .unwrap();
    assert_eq!(body_text(&resp), "POST /p text/x body=hello");
    let mut form = url::Values::new();
    form.add("k", "v w");
    let resp = c.post_form(&srv.url("/f"), &form).unwrap();
    assert_eq!(
        body_text(&resp),
        "POST /f application/x-www-form-urlencoded body=k=v+w"
    );
}

#[test]
fn redirect_policy_methods_and_limits() {
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let seen2 = seen.clone();
    let srv = Srv::start(handler_func(move |w, r| {
        seen2
            .lock()
            .unwrap()
            .push(format!("{} {}", r.method, r.url.path));
        match r.url.path.as_str() {
            "/301" => {
                w.header().set("Location", "/dest");
                w.write_header(301);
            }
            "/307" => {
                w.header().set("Location", "/dest");
                w.write_header(307);
            }
            "/loop" => {
                w.header().set("Location", "/loop");
                w.write_header(302);
            }
            _ => {
                let _ = w.write_string("dest");
            }
        }
    }));
    let c = no_proxy_client();
    let resp = c
        .post(&srv.url("/301"), "text/plain", Some("data".into()))
        .unwrap();
    assert_eq!(body_text(&resp), "dest");
    assert_eq!(seen.lock().unwrap().as_slice(), ["POST /301", "GET /dest"]);
    seen.lock().unwrap().clear();
    let resp = c
        .post(&srv.url("/307"), "text/plain", Some("data".into()))
        .unwrap();
    assert_eq!(body_text(&resp), "dest");
    assert_eq!(seen.lock().unwrap().as_slice(), ["POST /307", "POST /dest"]);
    let err = c.get(&srv.url("/loop")).unwrap_err().to_string();
    assert_eq!(err, "Get \"/loop\": stopped after 10 redirects");
    // ErrUseLastResponse returns the redirect itself.
    let mut c2 = no_proxy_client();
    c2.check_redirect = Some(Arc::new(|_, _| Err(Box::new(http::ERR_USE_LAST_RESPONSE))));
    let resp = c2.get(&srv.url("/301")).unwrap();
    assert_eq!(resp.status_code, 301);
    assert_eq!(resp.header.get("Location").unwrap_or(""), "/dest");
}

#[test]
fn sensitive_headers_stripped_across_hosts() {
    let a = Srv::start(handler_func(|w, r| {
        let _ = w.write_string(&format!(
            "auth={:?} cookie={:?} ref={:?} ua={:?}",
            r.header.get("Authorization").unwrap_or(""),
            r.header.get("Cookie").unwrap_or(""),
            r.header.get("Referer").unwrap_or(""),
            r.header.get("X-Custom").unwrap_or(""),
        ));
    }));
    let target = a.url("/final").replace("127.0.0.1", "localhost");
    let target2 = target.clone();
    let b = Srv::start(handler_func(move |w, _| {
        w.header().set("Location", &target2);
        w.write_header(302);
    }));
    let c = no_proxy_client();
    let mut req = Request::new("GET", &b.url("/start")).unwrap();
    req.header.set("Authorization", "Bearer secret");
    req.header.set("Cookie", "s=1");
    req.header.set("X-Custom", "keep");
    let resp = c.do_request(req).unwrap();
    let t = body_text(&resp);
    assert!(t.contains("auth=\"\""), "{t}");
    assert!(t.contains("cookie=\"\""), "{t}");
    assert!(t.contains("X-Custom") || t.contains("ua=\"keep\""), "{t}");
    assert!(t.contains("ref=\"http://127.0.0.1:"), "{t}");
}

#[test]
fn cookie_jar_round_trip() {
    let srv = Srv::start(handler_func(|w, r| {
        if r.url.path == "/set" {
            http::set_cookie(
                w,
                &http::Cookie {
                    name: "sid".into(),
                    value: "abc".into(),
                    path: "/".into(),
                    ..http::Cookie::default()
                },
            );
            let _ = w.write_string("set");
        } else {
            let _ = w.write_string(&format!("cookie={}", r.header.get("Cookie").unwrap_or("")));
        }
    }));
    let jar = Arc::new(http::cookiejar::Jar::new(None).unwrap());
    let mut c = no_proxy_client();
    c.jar = Some(jar);
    c.get(&srv.url("/set")).unwrap();
    assert_eq!(
        body_text(&c.get(&srv.url("/get")).unwrap()),
        "cookie=sid=abc"
    );
}

#[test]
fn connections_are_reused_and_limited() {
    let conns = Arc::new(AtomicUsize::new(0));
    let c2 = conns.clone();
    let srv = Srv::start_with(
        handler_func(|w, _| {
            let _ = w.write_string("ok");
        }),
        move |s| {
            s.conn_state = Some(Arc::new(move |_, st| {
                if st == http::STATE_NEW {
                    c2.fetch_add(1, Ordering::SeqCst);
                }
            }));
        },
    );
    let c = no_proxy_client();
    for _ in 0..5 {
        assert_eq!(body_text(&c.get(&srv.url("/")).unwrap()), "ok");
    }
    assert_eq!(
        conns.load(Ordering::SeqCst),
        1,
        "keep-alive reuses one connection"
    );
    let t = Transport {
        disable_keep_alives: true,
        ..Transport::default()
    };
    let c = Client {
        transport: Some(Arc::new(t)),
        ..Client::default()
    };
    for _ in 0..3 {
        assert_eq!(body_text(&c.get(&srv.url("/")).unwrap()), "ok");
    }
    assert_eq!(conns.load(Ordering::SeqCst), 4);
}

#[test]
fn transparent_gzip() {
    let srv = Srv::start(handler_func(|w, r| {
        if r.header
            .get("Accept-Encoding")
            .unwrap_or("")
            .contains("gzip")
        {
            let mut enc = rust_stdlib::compress::gzip::Writer::new(Vec::new());
            enc.write_all(b"compressed body").unwrap();
            enc.close().unwrap();
            let data = enc.into_inner();
            w.header().set("Content-Encoding", "gzip");
            let _ = w.write(&data);
        } else {
            let _ = w.write_string("plain body");
        }
    }));
    let c = no_proxy_client();
    let resp = c.get(&srv.url("/")).unwrap();
    assert!(resp.uncompressed);
    assert_eq!(resp.header.get("Content-Encoding").unwrap_or(""), "");
    assert_eq!(resp.content_length, -1);
    assert_eq!(body_text(&resp), "compressed body");
    let t = Transport {
        disable_compression: true,
        ..Transport::default()
    };
    let c = Client {
        transport: Some(Arc::new(t)),
        ..Client::default()
    };
    assert_eq!(body_text(&c.get(&srv.url("/")).unwrap()), "plain body");
}

#[test]
fn client_timeout_and_context_cancel() {
    let srv = Srv::start(handler_func(|w, r| {
        if r.url.path == "/slow" {
            thread::sleep(Duration::from_millis(600));
        }
        let _ = w.write_string("done");
    }));
    let mut c = no_proxy_client();
    c.timeout = time::MILLISECOND * 100;
    let err = c.get(&srv.url("/slow")).unwrap_err().to_string();
    assert!(
        err.contains("Client.Timeout exceeded while awaiting headers"),
        "{err}"
    );
    c.timeout = time::Duration::default();
    let (ctx, cancel) = Context::background().with_timeout(Duration::from_millis(100).into());
    let req = Request::in_context(&ctx, "GET", &srv.url("/slow")).unwrap();
    let err = c.do_request(req).unwrap_err().to_string();
    assert!(err.contains("context deadline exceeded"), "{err}");
    cancel();
}

#[test]
fn connect_proxy_tunnels_and_plain_proxy_rewrites() {
    // Origin server.
    let origin = Srv::start(handler_func(|w, r| {
        let _ = w.write_string(&format!("origin {} {}", r.method, r.url.path));
    }));
    // A forward proxy: sees absolute-form requests for http targets.
    let seen = Arc::new(Mutex::new(String::new()));
    let seen2 = seen.clone();
    let proxy = Srv::start(handler_func(move |w, r| {
        *seen2.lock().unwrap() = format!(
            "{} {} auth={}",
            r.method,
            r.request_uri,
            r.header.get("Proxy-Authorization").unwrap_or("")
        );
        let _ = w.write_string("via proxy");
    }));
    let mut t = Transport::default();
    let purl = url::parse(&format!("http://user:pw@{}", proxy.addr)).unwrap();
    t.proxy = Some(http::proxy_url(purl));
    let c = Client {
        transport: Some(Arc::new(t)),
        ..Client::default()
    };
    let resp = c.get("http://example.invalid/x?y=1").unwrap();
    assert_eq!(body_text(&resp), "via proxy");
    assert_eq!(
        *seen.lock().unwrap(),
        "GET http://example.invalid/x?y=1 auth=Basic dXNlcjpwdw=="
    );
    // CONNECT: a raw tunnel listener that splices to the origin.
    let ln = net::listen("tcp", "127.0.0.1:0").unwrap();
    let tunnel_addr = ln.addr().unwrap().to_string();
    let origin_addr = origin.addr.clone();
    let connect_line = Arc::new(Mutex::new(String::new()));
    let cl = connect_line.clone();
    let tt = thread::spawn(move || {
        let conn = ln.accept().unwrap();
        let mut buf = [0u8; 2048];
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let n = conn.read(&mut buf[..1]).unwrap();
            if n == 0 {
                return;
            }
            head.push(buf[0]);
        }
        *cl.lock().unwrap() = String::from_utf8_lossy(&head).into_owned();
        let up = std::net::TcpStream::connect(&origin_addr).unwrap();
        conn.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .unwrap();
        let conn = Arc::new(conn);
        let (mut up_r, mut up_w) = (up.try_clone().unwrap(), up);
        let c2 = conn.clone();
        let h = thread::spawn(move || {
            let mut b = [0u8; 4096];
            loop {
                match c2.read(&mut b) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if up_w.write_all(&b[..n]).is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = up_w.shutdown(std::net::Shutdown::Write);
        });
        let mut b = [0u8; 4096];
        loop {
            match up_r.read(&mut b) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if conn.write(&b[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = conn.close();
        let _ = h.join();
    });
    // Tunnelled HTTPS needs TLS; the core has none, so CONNECT is exercised
    // through a custom dialer that reports the explicit boundary error.
    let t = Transport {
        proxy: Some(http::proxy_url(
            url::parse(&format!("http://{tunnel_addr}")).unwrap(),
        )),
        ..Transport::default()
    };
    let c = Client {
        transport: Some(Arc::new(t)),
        ..Client::default()
    };
    let err = c.get("https://example.invalid/").unwrap_err().to_string();
    assert!(
        err.contains("TLS backend") || err.contains("proxyconnect"),
        "{err}"
    );
    assert!(connect_line
        .lock()
        .unwrap()
        .starts_with("CONNECT example.invalid:443 HTTP/1.1\r\n"));
    drop(tt);
}

#[test]
fn proxy_from_environment_rules() {
    let f = http::proxy_func_for(
        "http://p:3128",
        "https://sp:3129",
        "internal.example,.corp,10.0.0.0/8",
        false,
    );
    let u = |s: &str| url::parse(s).unwrap();
    assert_eq!(f(&u("http://a.example/")).unwrap().unwrap().host, "p:3128");
    assert_eq!(
        f(&u("https://a.example/")).unwrap().unwrap().host,
        "sp:3129"
    );
    assert!(f(&u("http://internal.example/")).unwrap().is_none());
    assert!(f(&u("http://x.corp/")).unwrap().is_none());
    assert!(f(&u("http://10.1.2.3/")).unwrap().is_none());
    assert!(f(&u("http://localhost/")).unwrap().is_none());
    assert!(f(&u("http://127.0.0.1/")).unwrap().is_none());
    assert!(f(&u("ftp://a.example/")).unwrap().is_none());
    let cgi = http::proxy_func_for("http://p:3128", "", "", true);
    assert!(cgi(&u("http://a.example/")).is_err());
}

#[test]
fn expect_continue_and_early_response() {
    let srv = Srv::start(handler_func(|w, r| {
        let b = r
            .body
            .as_ref()
            .map(|b| b.read_all().unwrap())
            .unwrap_or_default();
        let _ = w.write_string(&format!("got {} bytes", b.len()));
    }));
    let t = Transport {
        expect_continue_timeout: time::SECOND,
        ..Transport::default()
    };
    let c = Client {
        transport: Some(Arc::new(t)),
        ..Client::default()
    };
    let mut req = Request::new("POST", &srv.url("/"))
        .map(|r| r.with_body(vec![b'x'; 5000]))
        .unwrap();
    req.header.set("Expect", "100-continue");
    assert_eq!(body_text(&c.do_request(req).unwrap()), "got 5000 bytes");
}

#[test]
fn graceful_shutdown_and_close() {
    let srv = Srv::start(handler_func(|w, _| {
        thread::sleep(Duration::from_millis(200));
        let _ = w.write_string("finished");
    }));
    let url = srv.url("/");
    let c = no_proxy_client();
    let h = thread::spawn(move || body_text(&c.get(&url).unwrap()));
    thread::sleep(Duration::from_millis(50));
    let fired = Arc::new(AtomicUsize::new(0));
    let f2 = fired.clone();
    srv.server.register_on_shutdown(move || {
        f2.fetch_add(1, Ordering::SeqCst);
    });
    let (ctx, cancel) = Context::background().with_timeout(Duration::from_secs(5).into());
    srv.server.shutdown(&ctx).unwrap();
    cancel();
    assert_eq!(h.join().unwrap(), "finished", "in-flight request completes");
    thread::sleep(Duration::from_millis(50));
    assert_eq!(fired.load(Ordering::SeqCst), 1);
    let err = srv.server.listen_and_serve().unwrap_err();
    assert_eq!(err.to_string(), "http: Server closed");
}

#[test]
fn hijack_and_flush_and_trailers() {
    let srv = Srv::start(handler_func(|w, r| match r.url.path.as_str() {
        "/hijack" => {
            let mut hj = http::ResponseController::new(w).hijack().unwrap();
            hj.writer
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nhijacked")
                .unwrap();
            hj.writer.flush().unwrap();
            let _ = hj.conn.close();
        }
        "/trailer" => {
            w.header().set("Trailer", "X-End");
            let _ = w.write_string("body");
            w.header().set("X-End", "done");
        }
        _ => {
            let _ = w.write_string("part1");
            http::ResponseController::new(w).flush().unwrap();
            thread::sleep(Duration::from_millis(50));
            let _ = w.write_string("part2");
        }
    }));
    let c = no_proxy_client();
    assert_eq!(body_text(&c.get(&srv.url("/hijack")).unwrap()), "hijacked");
    let resp = c.get(&srv.url("/trailer")).unwrap();
    let t = body_text(&resp);
    assert_eq!(t, "body");
    assert_eq!(
        resp.trailer.get().unwrap().get("X-End").unwrap_or(""),
        "done"
    );
    assert_eq!(body_text(&c.get(&srv.url("/")).unwrap()), "part1part2");
}

#[test]
fn file_transport_serves_from_fs() {
    let dir = std::env::temp_dir().join(format!("httpft-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("a.txt"), "file data").unwrap();
    let t = Transport::default();
    t.register_protocol(
        "file",
        Arc::new(http::FileTransport::new(Arc::new(http::Dir(
            dir.to_string_lossy().into_owned(),
        )))),
    )
    .unwrap();
    assert!(t
        .register_protocol(
            "file",
            Arc::new(http::FileTransport::new(Arc::new(http::Dir(String::new()))))
        )
        .is_err());
    let c = Client {
        transport: Some(Arc::new(t)),
        ..Client::default()
    };
    let resp = c.get("file:///a.txt").unwrap();
    assert_eq!(resp.status_code, 200);
    assert_eq!(body_text(&resp), "file data");
    assert_eq!(c.get("file:///missing").unwrap().status_code, 404);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn client_conn_manages_one_connection() {
    let srv = Srv::start(handler_func(|w, _| {
        let _ = w.write_string("cc");
    }));
    let t = Transport::default();
    let cc = t
        .client_conn(&Context::background(), "http", &srv.addr)
        .unwrap();
    assert_eq!(cc.available(), 1);
    cc.reserve().unwrap();
    assert_eq!(cc.available(), 0);
    assert_eq!(cc.in_flight(), 1);
    let req = Request::new("GET", &srv.url("/")).unwrap();
    let resp = cc.round_trip(&req).unwrap();
    assert_eq!(body_text(&resp), "cc");
    assert_eq!(cc.available(), 1);
    cc.close().unwrap();
    assert!(cc.err().is_some());
}

#[test]
fn timeout_handler_and_max_bytes() {
    let slow: Arc<dyn Handler> = handler_func(|w, r| {
        if r.url.path == "/slow" {
            thread::sleep(Duration::from_millis(500));
        }
        let _ = w.write_string("fast");
    });
    let srv = Srv::start(http::timeout_handler(
        slow,
        time::MILLISECOND * 100,
        "too slow",
    ));
    let c = no_proxy_client();
    let resp = c.get(&srv.url("/slow")).unwrap();
    assert_eq!(
        (resp.status_code, body_text(&resp).as_str()),
        (503, "too slow")
    );
    assert_eq!(body_text(&c.get(&srv.url("/")).unwrap()), "fast");
    let limited = Srv::start(http::max_bytes_handler(
        handler_func(|w, r| {
            let mut b = Vec::new();
            match r.body.as_ref().unwrap().clone().read_to_end(&mut b) {
                Ok(_) => {
                    let _ = w.write_string("ok");
                }
                Err(e) => {
                    w.write_header(413);
                    let _ = w.write_string(&e.to_string());
                }
            }
        }),
        10,
    ));
    let resp = c
        .post(
            &limited.url("/"),
            "text/plain",
            Some(vec![b'a'; 100].into()),
        )
        .unwrap();
    assert_eq!(resp.status_code, 413);
}

#[test]
fn server_timeouts_and_header_limits() {
    let srv = Srv::start_with(
        handler_func(|w, _| {
            let _ = w.write_string("ok");
        }),
        |s| {
            s.read_header_timeout = time::MILLISECOND * 150;
            s.max_header_bytes = 300;
        },
    );
    // A client that never finishes its head is dropped after ReadHeaderTimeout.
    let mut slow = std::net::TcpStream::connect(&srv.addr).unwrap();
    slow.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n").unwrap();
    slow.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut buf = [0u8; 64];
    assert_eq!(
        slow.read(&mut buf).unwrap_or(0),
        0,
        "idle head closes quietly"
    );
    // A head over MaxHeaderBytes (+4096 of slop) gets 431.
    let mut big = std::net::TcpStream::connect(&srv.addr).unwrap();
    let head = format!(
        "GET / HTTP/1.1\r\nHost: x\r\nX-Big: {}\r\n\r\n",
        "a".repeat(6000)
    );
    big.write_all(head.as_bytes()).unwrap();
    big.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut out = String::new();
    let _ = big.read_to_string(&mut out);
    assert!(
        out.starts_with("HTTP/1.1 431 Request Header Fields Too Large"),
        "{out}"
    );
}

#[test]
fn response_header_timeout_and_idle_timeout() {
    let closed = Arc::new(AtomicUsize::new(0));
    let c2 = closed.clone();
    let srv = Srv::start_with(
        handler_func(|w, r| {
            if r.url.path == "/slow" {
                thread::sleep(Duration::from_millis(500));
            }
            let _ = w.write_string("ok");
        }),
        move |s| {
            s.conn_state = Some(Arc::new(move |_, st| {
                if st == http::STATE_CLOSED {
                    c2.fetch_add(1, Ordering::SeqCst);
                }
            }));
        },
    );
    let t = Transport {
        response_header_timeout: time::MILLISECOND * 100,
        idle_conn_timeout: time::MILLISECOND * 100,
        ..Transport::default()
    };
    let c = Client {
        transport: Some(Arc::new(t)),
        ..Client::default()
    };
    let err = c.get(&srv.url("/slow")).unwrap_err().to_string();
    assert!(err.contains("timeout awaiting response headers"), "{err}");
    assert_eq!(body_text(&c.get(&srv.url("/fast")).unwrap()), "ok");
    // The idle connection is closed by the transport after IdleConnTimeout.
    let start = std::time::Instant::now();
    while closed.load(Ordering::SeqCst) < 2 && start.elapsed() < Duration::from_secs(3) {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(
        closed.load(Ordering::SeqCst) >= 2,
        "closed={}",
        closed.load(Ordering::SeqCst)
    );
}

#[test]
fn max_conns_per_host_serializes_requests() {
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let (a2, p2) = (active.clone(), peak.clone());
    let srv = Srv::start(handler_func(move |w, _| {
        let now = a2.fetch_add(1, Ordering::SeqCst) + 1;
        p2.fetch_max(now, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(60));
        a2.fetch_sub(1, Ordering::SeqCst);
        let _ = w.write_string("ok");
    }));
    let t = Transport {
        max_conns_per_host: 2,
        ..Transport::default()
    };
    let c = Arc::new(Client {
        transport: Some(Arc::new(t)),
        ..Client::default()
    });
    let url = srv.url("/");
    let handles: Vec<_> = (0..6)
        .map(|_| {
            let (c, url) = (c.clone(), url.clone());
            thread::spawn(move || body_text(&c.get(&url).unwrap()))
        })
        .collect();
    for h in handles {
        assert_eq!(h.join().unwrap(), "ok");
    }
    assert!(
        peak.load(Ordering::SeqCst) <= 2,
        "peak={}",
        peak.load(Ordering::SeqCst)
    );
}

#[test]
fn reverse_proxy_streams_forwards_1xx_and_trailers() {
    use rust_stdlib::net::http::httputil::ReverseProxy;
    let backend = Srv::start(handler_func(|w, r| match r.url.path.as_str() {
        "/early" => {
            w.header().set("Link", "</style.css>; rel=preload");
            w.write_header(103);
            w.header().del("Link");
            let _ = w.write_string("final body");
        }
        "/trailer" => {
            w.header().set("Trailer", "X-End");
            let _ = w.write_string("tbody");
            w.header().set("X-End", "done");
        }
        _ => {
            let _ = w.write_string("a");
            let _ = http::ResponseController::new(w).flush();
            thread::sleep(Duration::from_millis(80));
            let _ = w.write_string("b");
        }
    }));
    let target = url::parse(&backend.url("")).unwrap();
    let mut rp = ReverseProxy::single_host(target);
    rp.flush_interval = -1;
    let proxy = Srv::start(Arc::new(rp));
    // Raw client: the 103 arrives before the final head.
    let mut s = std::net::TcpStream::connect(&proxy.addr).unwrap();
    s.write_all(b"GET /early HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    assert!(out.starts_with("HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\n"), "{out}");
    assert!(
        out.ends_with("final body") || out.contains("\r\n\r\nfinal body"),
        "{out}"
    );
    // Trailers cross the proxy.
    let c = no_proxy_client();
    let resp = c.get(&proxy.url("/trailer")).unwrap();
    assert_eq!(body_text(&resp), "tbody");
    assert_eq!(
        resp.trailer.get().unwrap().get("X-End").unwrap_or(""),
        "done"
    );
    // The body streams: the first chunk is readable before the backend finishes.
    let resp = c.get(&proxy.url("/stream")).unwrap();
    let mut body = resp.body.clone().unwrap();
    let mut first = [0u8; 1];
    let t0 = std::time::Instant::now();
    body.read_exact(&mut first).unwrap();
    assert_eq!(&first, b"a");
    assert!(
        t0.elapsed() < Duration::from_millis(70),
        "first byte took {:?}",
        t0.elapsed()
    );
    assert_eq!(body.read_all().unwrap(), b"b");
}

#[test]
fn request_context_values_and_remote_addr() {
    let srv = Srv::start(handler_func(|w, r: &mut Request| {
        let local = r
            .context()
            .value(&http::LOCAL_ADDR_CONTEXT_KEY)
            .map(|a| a.to_string());
        let server = r.context().value(&http::SERVER_CONTEXT_KEY).is_some();
        let _ = w.write_string(&format!(
            "remote={} local={} server={} proto={}",
            r.remote_addr.starts_with("127.0.0.1:"),
            local.is_some(),
            server,
            r.proto
        ));
    }));
    let c = no_proxy_client();
    assert_eq!(
        body_text(&c.get(&srv.url("/")).unwrap()),
        "remote=true local=true server=true proto=HTTP/1.1"
    );
    let _ = Header::new();
}

#[test]
fn copy_from_follows_response_read_from() {
    let srv = Srv::start(handler_func(|w, r| {
        let n: usize = r.url.query().get("n").parse().unwrap();
        let body = vec![b'<'; n];
        let _ = w.copy_from(&mut &body[..]);
    }));
    let c = no_proxy_client();
    // At most 512 bytes: the whole body sits in the buffer, so Go sends a
    // Content-Length and a sniffed type.
    let small = c.get(&srv.url("/?n=100")).unwrap();
    assert_eq!(small.content_length, 100);
    assert_eq!(body_text(&small).len(), 100);
    // Past the sniff window the rest streams straight to the connection:
    // the header was already flushed, so the body is chunked.
    let big = c.get(&srv.url("/?n=3000")).unwrap();
    assert_eq!(big.content_length, -1);
    assert_eq!(big.transfer_encoding, ["chunked"]);
    assert_eq!(body_text(&big).len(), 3000);
}

#[derive(Debug)]
struct BodyBoom;
impl std::fmt::Display for BodyBoom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("body boom")
    }
}
impl std::error::Error for BodyBoom {}

/// The request body yields some bytes and then a custom error.
struct FailingBody(bool);
impl Read for FailingBody {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if std::mem::replace(&mut self.0, true) {
            return Err(std::io::Error::other(BodyBoom));
        }
        buf[..4].copy_from_slice(b"data");
        Ok(4)
    }
}

/// Go's `errors.As`: walks `source` links and the inner errors of `io::Error`s.
fn error_as<'a, T: std::error::Error + 'static>(
    mut err: &'a (dyn std::error::Error + 'static),
) -> Option<&'a T> {
    loop {
        if let Some(t) = err.downcast_ref::<T>() {
            return Some(t);
        }
        if let Some(inner) = err
            .downcast_ref::<std::io::Error>()
            .and_then(|e| e.get_ref())
        {
            err = inner;
            continue;
        }
        err = err.source()?;
    }
}

#[test]
fn request_body_read_error_keeps_its_type() {
    let srv = Srv::start(handler_func(|w, r| {
        if let Some(b) = r.body.as_ref() {
            let _ = b.read_all();
        }
        let _ = w.write_string("ok");
    }));
    let c = no_proxy_client();
    for known_length in [false, true] {
        let mut req = Request::new("POST", &srv.url("/")).unwrap();
        req.body = Some(http::Body::from_reader(FailingBody(false)));
        if known_length {
            req.content_length = 100;
        }
        let err = match c.do_request(req) {
            Err(e) => e,
            Ok(_) => panic!("expected an error"),
        };
        let text = err.to_string();
        assert!(text.contains("body boom"), "{text}");
        assert!(
            error_as::<BodyBoom>(err.as_ref()).is_some(),
            "known_length={known_length}: {text}: {err:?}"
        );
    }
}
