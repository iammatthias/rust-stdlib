#![cfg(feature = "net")]
//! `net/http/httptrace` hooks over loopback servers: event order, hook
//! composition, 1xx handling, TLS and DNS/connect hooks.
use rust_stdlib::context::{self, Context};
use rust_stdlib::net::http::httptrace::{
    context_client_trace, with_client_trace, ClientTrace, DNSDoneInfo, DNSStartInfo, GotConnInfo,
    WroteRequestInfo,
};
use rust_stdlib::net::http::Request;
use rust_stdlib::net::http::{RequestBody, RoundTripper, TlsConfig, Transport};
use rust_stdlib::net::{Conn, Dialer, Listener};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

type Log = Arc<Mutex<Vec<String>>>;

fn serve(responses: Vec<&'static str>) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        for response in responses {
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = conn.read(&mut tmp).unwrap();
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            let end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
            buf.drain(..end);
            conn.write_all(response.as_bytes()).unwrap();
        }
        // Drain until the client hangs up.
        while conn.read(&mut tmp).map(|n| n > 0).unwrap_or(false) {}
    });
    (addr, handle)
}

fn tracer(log: &Log) -> ClientTrace {
    let l = |log: &Log, s: String| log.lock().unwrap().push(s);
    let (a, b, c, d, e, f, g, h) = (
        log.clone(),
        log.clone(),
        log.clone(),
        log.clone(),
        log.clone(),
        log.clone(),
        log.clone(),
        log.clone(),
    );
    ClientTrace {
        get_conn: Some(Arc::new(move |hp| l(&a, format!("GetConn {hp}")))),
        got_conn: Some(Arc::new(move |i: GotConnInfo| {
            l(
                &b,
                format!("GotConn reused={} idle={}", i.reused, i.was_idle),
            )
        })),
        put_idle_conn: Some(Arc::new(move |err| {
            l(
                &c,
                format!(
                    "PutIdleConn {}",
                    err.map_or("nil".to_owned(), |e| e.to_string())
                ),
            )
        })),
        got_first_response_byte: Some(Arc::new(move || l(&d, "FirstByte".to_owned()))),
        got_1xx_response: Some(Arc::new(move |code, _| {
            l(&e, format!("1xx {code}"));
            Ok(())
        })),
        wrote_headers: Some(Arc::new(move || l(&f, "WroteHeaders".to_owned()))),
        wrote_request: Some(Arc::new(move |i: WroteRequestInfo| {
            l(&g, format!("WroteRequest {}", i.err.is_none()))
        })),
        wrote_header_field: Some(Arc::new(move |k, v| {
            l(&h, format!("Field {k}={}", v.join("|")))
        })),
        ..ClientTrace::default()
    }
}

fn get(tr: &Transport, ctx: &context::Context, addr: &str, path: &str) -> String {
    let req = Request::in_context(ctx, "GET", &format!("http://{addr}{path}")).unwrap();
    let resp = tr.round_trip(&req).unwrap();
    let body = resp.body.as_ref().unwrap().read_all().unwrap();
    resp.body.as_ref().unwrap().close().unwrap();
    String::from_utf8(body).unwrap()
}

#[test]
fn event_order_and_connection_reuse() {
    let (addr, server) = serve(vec![
        "HTTP/1.1 103 Early Hints\r\nLink: x\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
    ]);
    let tr = Transport::default();
    let log: Log = Arc::default();
    let ctx = with_client_trace(&Context::background(), tracer(&log));
    assert_eq!(get(&tr, &ctx, &addr, "/a"), "ok");
    let first: Vec<String> = log.lock().unwrap().drain(..).collect();
    assert_eq!(first[0], format!("GetConn {addr}"));
    assert_eq!(first[1], "GotConn reused=false idle=false");
    // The write loop and the read loop race: compare each group in order.
    let group = |prefixes: &[&str]| -> Vec<&String> {
        first
            .iter()
            .filter(|s| prefixes.iter().any(|p| s.starts_with(p)))
            .collect()
    };
    assert_eq!(
        group(&["Field", "WroteHeaders", "WroteRequest"]),
        [
            &format!("Field Host={addr}"),
            &"Field User-Agent=Go-http-client/1.1".to_owned(),
            &"Field Accept-Encoding=gzip".to_owned(),
            &"WroteHeaders".to_owned(),
            &"WroteRequest true".to_owned(),
        ]
    );
    assert_eq!(
        group(&["FirstByte", "1xx", "PutIdle"]),
        ["FirstByte", "1xx 103", "PutIdleConn nil"]
    );
    // The second request reuses the idle connection.
    assert_eq!(get(&tr, &ctx, &addr, "/b"), "hi");
    let second = log.lock().unwrap().clone();
    assert_eq!(second[0], format!("GetConn {addr}"));
    assert_eq!(second[1], "GotConn reused=true idle=true");
    tr.close_idle_connections();
    server.join().unwrap();
}

#[test]
fn keep_alive_disabled_is_not_reported_to_put_idle_conn() {
    let (addr, server) = serve(vec!["HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"]);
    let tr = Transport {
        disable_keep_alives: true,
        ..Transport::default()
    };
    let log: Log = Arc::default();
    let ctx = with_client_trace(&Context::background(), tracer(&log));
    assert_eq!(get(&tr, &ctx, &addr, "/"), "ok");
    assert!(!log
        .lock()
        .unwrap()
        .iter()
        .any(|s| s.starts_with("PutIdleConn")));
    server.join().unwrap();
}

#[test]
fn traces_compose_new_first_and_old_decides_1xx() {
    let log: Log = Arc::default();
    let old_log = log.clone();
    let old = ClientTrace {
        get_conn: Some(Arc::new(move |_| {
            old_log.lock().unwrap().push("old".into())
        })),
        got_1xx_response: Some(Arc::new(|_, _| Err("old rejects".into()))),
        ..ClientTrace::default()
    };
    let new_log = log.clone();
    let new = ClientTrace {
        get_conn: Some(Arc::new(move |_| {
            new_log.lock().unwrap().push("new".into())
        })),
        // Go runs both and keeps only the old hook's result.
        got_1xx_response: Some(Arc::new(|_, _| Ok(()))),
        ..ClientTrace::default()
    };
    let ctx = with_client_trace(&Context::background(), old);
    let ctx = with_client_trace(&ctx, new);
    assert!(context_client_trace(&ctx).is_some());
    let (addr, server) = serve(vec![
        "HTTP/1.1 102 Processing\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    ]);
    let tr = Transport::default();
    let req = Request::in_context(&ctx, "GET", &format!("http://{addr}/")).unwrap();
    let Err(err) = tr.round_trip(&req) else {
        panic!("old hook aborts");
    };
    assert!(err.to_string().contains("old rejects"), "{err}");
    assert_eq!(*log.lock().unwrap(), ["new", "old"]);
    tr.close_idle_connections();
    drop(server);
}

#[test]
fn expect_continue_hooks() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = conn.read(&mut tmp).unwrap();
            buf.extend_from_slice(&tmp[..n]);
        }
        conn.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").unwrap();
        while !buf.ends_with(b"payload") {
            let n = conn.read(&mut tmp).unwrap();
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
    });
    let log: Log = Arc::default();
    let (w, g) = (log.clone(), log.clone());
    let trace = ClientTrace {
        wait_100_continue: Some(Arc::new(move || {
            w.lock().unwrap().push("Wait100Continue".into())
        })),
        got_100_continue: Some(Arc::new(move || {
            g.lock().unwrap().push("Got100Continue".into())
        })),
        ..ClientTrace::default()
    };
    let ctx = with_client_trace(&Context::background(), trace);
    let tr = Transport {
        expect_continue_timeout: rust_stdlib::time::SECOND,
        ..Transport::default()
    };
    let mut req = Request::in_context(&ctx, "POST", &format!("http://{addr}/"))
        .map(|r| r.with_body(RequestBody::Bytes(b"payload".to_vec())))
        .unwrap();
    req.header.set("Expect", "100-continue");
    let resp = tr.round_trip(&req).unwrap();
    assert_eq!(resp.status_code, 200);
    let mut events = log.lock().unwrap().clone();
    events.sort();
    assert_eq!(events, ["Got100Continue", "Wait100Continue"]);
    server.join().unwrap();
}

/// A connection that claims to be TLS.
struct FakeTls(Box<dyn Conn>);

impl Conn for FakeTls {
    fn read(&self, b: &mut [u8]) -> Result<usize, rust_stdlib::net::NetError> {
        self.0.read(b)
    }
    fn write(&self, b: &[u8]) -> Result<usize, rust_stdlib::net::NetError> {
        self.0.write(b)
    }
    fn close(&self) -> Result<(), rust_stdlib::net::NetError> {
        self.0.close()
    }
    fn local_addr(&self) -> Option<rust_stdlib::net::AddrRef> {
        self.0.local_addr()
    }
    fn remote_addr(&self) -> Option<rust_stdlib::net::AddrRef> {
        self.0.remote_addr()
    }
    fn set_deadline(&self, t: &rust_stdlib::time::Time) -> Result<(), rust_stdlib::net::NetError> {
        self.0.set_deadline(t)
    }
    fn set_read_deadline(
        &self,
        t: &rust_stdlib::time::Time,
    ) -> Result<(), rust_stdlib::net::NetError> {
        self.0.set_read_deadline(t)
    }
    fn set_write_deadline(
        &self,
        t: &rust_stdlib::time::Time,
    ) -> Result<(), rust_stdlib::net::NetError> {
        self.0.set_write_deadline(t)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn tls_connection_state(&self) -> Option<rust_stdlib::net::TlsConnectionState> {
        Some(rust_stdlib::net::TlsConnectionState {
            version: 0x0304,
            handshake_complete: true,
            ..Default::default()
        })
    }
}

struct Hook {
    fail: bool,
}

impl TlsConfig for Hook {
    fn server_listener(
        &self,
        _: Box<dyn Listener>,
        _: &str,
        _: &str,
        _: &[String],
    ) -> Result<Box<dyn Listener>, Box<dyn std::error::Error + Send + Sync>> {
        Err("unused".into())
    }
    fn client_conn(
        &self,
        conn: Box<dyn Conn>,
        _: &str,
        _: &[String],
    ) -> Result<Box<dyn Conn>, Box<dyn std::error::Error + Send + Sync>> {
        if self.fail {
            return Err("handshake refused".into());
        }
        Ok(Box::new(FakeTls(conn)))
    }
}

#[test]
fn tls_handshake_hooks() {
    for fail in [false, true] {
        let (addr, server) = serve(vec!["HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"]);
        let log: Log = Arc::default();
        let (s, d) = (log.clone(), log.clone());
        let trace = ClientTrace {
            tls_handshake_start: Some(Arc::new(move || s.lock().unwrap().push("start".into()))),
            tls_handshake_done: Some(Arc::new(move |state, err| {
                d.lock().unwrap().push(format!(
                    "done version={:#x} err={}",
                    state.version,
                    err.map_or("nil".to_owned(), |e| e.to_string())
                ))
            })),
            ..ClientTrace::default()
        };
        let ctx = with_client_trace(&Context::background(), trace);
        let tr = Transport {
            tls_client_config: Some(Arc::new(Hook { fail })),
            ..Transport::default()
        };
        // The server speaks plain HTTP, which the fake TLS layer passes through.
        let req = Request::in_context(&ctx, "GET", &format!("https://{addr}/")).unwrap();
        let result = tr.round_trip(&req);
        let events = log.lock().unwrap().clone();
        if fail {
            assert!(result.is_err());
            assert_eq!(events, ["start", "done version=0x0 err=handshake refused"]);
            drop(server);
        } else {
            assert_eq!(result.unwrap().status_code, 200);
            assert_eq!(events, ["start", "done version=0x304 err=nil"]);
            tr.close_idle_connections();
            server.join().unwrap();
        }
    }
}

#[test]
fn dns_and_connect_hooks() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accept = thread::spawn(move || {
        let _ = listener.accept();
    });
    let log: Log = Arc::default();
    let (ds, dd, cs, cd) = (log.clone(), log.clone(), log.clone(), log.clone());
    let trace = ClientTrace {
        dns_start: Some(Arc::new(move |i: DNSStartInfo| {
            ds.lock().unwrap().push(format!("DNSStart {}", i.host))
        })),
        dns_done: Some(Arc::new(move |i: DNSDoneInfo| {
            let found = i.addrs.iter().any(|a| a.ip.to_string() == "127.0.0.1");
            dd.lock()
                .unwrap()
                .push(format!("DNSDone found127={found} err={}", i.err.is_none()))
        })),
        connect_start: Some(Arc::new(move |n, a| {
            if !a.starts_with("[::1]") {
                cs.lock().unwrap().push(format!("ConnectStart {n} {a}"))
            }
        })),
        connect_done: Some(Arc::new(move |n, a, e| {
            if !a.starts_with("[::1]") {
                cd.lock()
                    .unwrap()
                    .push(format!("ConnectDone {n} {a} {}", e.is_none()))
            }
        })),
        ..ClientTrace::default()
    };
    let ctx = with_client_trace(&Context::background(), trace);
    let conn = Dialer::default()
        .dial_context(&ctx, "tcp", &format!("localhost:{port}"))
        .unwrap();
    conn.close().unwrap();
    accept.join().unwrap();
    let events = log.lock().unwrap().clone();
    assert_eq!(events[0], "DNSStart localhost");
    assert_eq!(events[1], "DNSDone found127=true err=true");
    assert_eq!(events[2], format!("ConnectStart tcp 127.0.0.1:{port}"));
    assert_eq!(events[3], format!("ConnectDone tcp 127.0.0.1:{port} true"));
    // An IP literal needs no lookup.
    log.lock().unwrap().clear();
    let l2 = TcpListener::bind("127.0.0.1:0").unwrap();
    let p2 = l2.local_addr().unwrap().port();
    let a2 = thread::spawn(move || {
        let _ = l2.accept();
    });
    Dialer::default()
        .dial_context(&ctx, "tcp", &format!("127.0.0.1:{p2}"))
        .unwrap()
        .close()
        .unwrap();
    a2.join().unwrap();
    assert_eq!(log.lock().unwrap().len(), 2);
}
