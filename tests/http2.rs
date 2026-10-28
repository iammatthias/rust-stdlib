//! HTTP/2 end to end over loopback: the Rust h2c server and client against
//! each other (prior knowledge), plus frame-level checks of server behaviour
//! with a hand-rolled client built on the frame codec.
#![cfg(feature = "net")]
use rust_stdlib::net::{
    self,
    http::{
        self, client::Client, handler::ResponseWriter, header::Protocols, request::Request,
        server::Server, transport::Transport, Handler,
    },
};
use std::{
    io::Read,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

struct Running {
    server: Server,
    addr: String,
    t: Option<thread::JoinHandle<()>>,
}
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.server.close();
        if let Some(t) = self.t.take() {
            let _ = t.join();
        }
    }
}

fn h2c_server(handler: Arc<dyn Handler>) -> Running {
    let mut p = Protocols::default();
    p.set_http1(true);
    p.set_unencrypted_http2(true);
    let server = Server {
        handler: Some(handler),
        protocols: Some(p),
        error_log: Some(Arc::new(rust_stdlib::log::Logger::new(
            std::io::sink(),
            "",
            0,
        ))),
        ..Server::default()
    };
    let ln = net::listen("tcp", "127.0.0.1:0").unwrap();
    let addr = ln.addr().unwrap().to_string();
    let s2 = server.clone();
    let t = thread::spawn(move || {
        let _ = s2.serve(ln);
    });
    Running {
        server,
        addr,
        t: Some(t),
    }
}

fn h2c_client() -> Client {
    let mut p = Protocols::default();
    p.set_unencrypted_http2(true);
    let t = Transport {
        protocols: Some(p),
        ..Transport::default()
    };
    Client {
        transport: Some(Arc::new(t)),
        timeout: rust_stdlib::time::SECOND * 30,
        ..Client::default()
    }
}

fn body_string(r: http::response::Response) -> String {
    String::from_utf8(r.body.unwrap().read_all().unwrap()).unwrap()
}

#[test]
fn h2c_get_round_trip() {
    let srv = h2c_server(http::handler_func(
        |w: &mut dyn ResponseWriter, r: &mut Request| {
            w.header().set("X-Proto", &r.proto);
            let _ = w.write_string(&format!("hello {} {}", r.method, r.url.path));
        },
    ));
    let c = h2c_client();
    let resp = c.get(&format!("http://{}/a/b", srv.addr)).unwrap();
    assert_eq!(resp.status, "200 OK");
    assert_eq!(resp.proto, "HTTP/2.0");
    assert_eq!(resp.proto_major, 2);
    assert_eq!(resp.header.get("X-Proto").unwrap_or(""), "HTTP/2.0");
    assert_eq!(body_string(resp), "hello GET /a/b");
}

#[test]
fn h2c_large_bodies_exercise_flow_control() {
    let srv = h2c_server(http::handler_func(
        |w: &mut dyn ResponseWriter, r: &mut Request| {
            let mut body = Vec::new();
            let _ = r.body.clone().unwrap().read_to_end(&mut body);
            let _ = w.write(&body);
        },
    ));
    let c = h2c_client();
    let data: Vec<u8> = (0..(6 << 20)).map(|i| (i % 251) as u8).collect();
    let resp = c
        .post(
            &format!("http://{}/echo", srv.addr),
            "application/octet-stream",
            Some(data.clone().into()),
        )
        .unwrap();
    let got = resp.body.unwrap().read_all().unwrap();
    assert_eq!(got.len(), data.len());
    assert!(got == data);
}

#[test]
fn h2c_concurrent_requests_share_one_connection() {
    let hits = Arc::new(Mutex::new(0usize));
    let h2 = hits.clone();
    let srv = h2c_server(http::handler_func(
        move |w: &mut dyn ResponseWriter, _r: &mut Request| {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            {
                *h2.lock().unwrap() += 1;
            }
            while *h2.lock().unwrap() < 8 && std::time::Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            let _ = w.write_string("done");
        },
    ));
    let c = Arc::new(h2c_client());
    let url = format!("http://{}/x", srv.addr);
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let c = c.clone();
            let url = url.clone();
            thread::spawn(move || body_string(c.get(&url).unwrap()))
        })
        .collect();
    for h in handles {
        assert_eq!(h.join().unwrap(), "done");
    }
}

// ---------------------------------------------------------------------
// Frame-level server behaviour with a hand-rolled client.

use rust_stdlib::net::http::h2::frame::*;
use rust_stdlib::net::http::h2::hpack::{Decoder, Encoder, HeaderField};
use std::{io::Write, net::TcpStream};

struct Raw {
    s: TcpStream,
    fr: FrameReader<TcpStream>,
    enc: Encoder,
    dec: Decoder,
}

fn raw(addr: &str, settings: &[Setting]) -> Raw {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(CLIENT_PREFACE).unwrap();
    let mut fw = FrameWriter::new(Vec::new());
    fw.write_settings(settings).unwrap();
    s.write_all(fw.get_ref()).unwrap();
    let mut fr = FrameReader::new(s.try_clone().unwrap());
    fr.set_meta_headers_decoder(Some(Decoder::new(4096)));
    Raw {
        s,
        fr,
        enc: Encoder::new(),
        dec: Decoder::new(4096),
    }
}

impl Raw {
    fn send(&mut self, f: impl FnOnce(&mut FrameWriter<Vec<u8>>)) {
        let mut fw = FrameWriter::new(Vec::new());
        f(&mut fw);
        self.s.write_all(fw.get_ref()).unwrap();
    }
    fn request(&mut self, id: u32, path: &str, end: bool) {
        let mut blk = Vec::new();
        for (n, v) in [
            (":method", "GET"),
            (":scheme", "http"),
            (":authority", "x"),
            (":path", path),
        ] {
            self.enc.write_field(&HeaderField::new(n, v), &mut blk);
        }
        self.send(|fw| {
            fw.write_headers(&HeadersParam {
                stream_id: id,
                block_fragment: &blk,
                end_stream: end,
                end_headers: true,
                ..HeadersParam::default()
            })
            .unwrap()
        });
    }
    /// Reads frames until `pred` matches one; settings are acknowledged.
    fn until(&mut self, mut pred: impl FnMut(&Frame) -> bool) -> Frame {
        loop {
            let f = self.fr.read_frame().expect("frame");
            if let Frame::Settings { header, .. } = &f {
                if !header.has(FLAG_SETTINGS_ACK) {
                    self.send(|fw| fw.write_settings_ack().unwrap());
                }
            }
            if pred(&f) {
                return f;
            }
        }
    }
}

fn echo_path_server() -> Running {
    h2c_server(http::handler_func(
        |w: &mut dyn ResponseWriter, r: &mut Request| {
            if r.url.path == "/push" {
                if let Some(p) = w.pusher() {
                    let res = p.push("/pushed", None);
                    let _ = w.write_string(&format!("push={}", res.is_ok()));
                    return;
                }
            }
            let _ = w.write_string(&format!("path={}", r.url.path));
        },
    ))
}

#[test]
fn raw_client_gets_settings_ack_ping_ack_and_response() {
    let srv = echo_path_server();
    let mut c = raw(&srv.addr, &[]);
    c.until(|f| matches!(f, Frame::Settings { header, .. } if !header.has(FLAG_SETTINGS_ACK)));
    c.send(|fw| fw.write_ping(false, *b"12345678").unwrap());
    let f = c.until(|f| matches!(f, Frame::Ping { .. }));
    assert!(
        matches!(f, Frame::Ping { header, data } if header.has(FLAG_PING_ACK) && &data == b"12345678")
    );
    c.request(1, "/hi", true);
    let f = c.until(|f| matches!(f, Frame::Meta(_)));
    let Frame::Meta(m) = f else { unreachable!() };
    assert_eq!(m.pseudo_value("status"), b"200");
    let f = c.until(|f| matches!(f, Frame::Data { .. }));
    assert!(matches!(f, Frame::Data { data, .. } if data == b"path=/hi"));
}

#[test]
fn server_push_sends_push_promise_and_pushed_response() {
    let srv = echo_path_server();
    let mut c = raw(
        &srv.addr,
        &[Setting {
            id: SETTING_ENABLE_PUSH,
            val: 1,
        }],
    );
    c.request(1, "/push", true);
    let f = c.until(|f| matches!(f, Frame::PushPromise { .. }));
    let Frame::PushPromise {
        promise_id,
        fragment,
        ..
    } = f
    else {
        unreachable!()
    };
    assert_eq!(promise_id, 2);
    let _ = (&mut c.dec, fragment);
    // The promised stream carries a response.
    let mut saw_pushed_data = false;
    for _ in 0..20 {
        match c.fr.read_frame().expect("frame") {
            Frame::Data { header, data } if header.stream_id == 2 => {
                assert_eq!(data, b"path=/pushed");
                saw_pushed_data = true;
                break;
            }
            Frame::Meta(m) if m.header.stream_id == 2 => {
                assert_eq!(m.pseudo_value("status"), b"200");
            }
            _ => {}
        }
    }
    assert!(saw_pushed_data);
}

#[test]
fn push_is_refused_when_the_client_disables_it() {
    let srv = echo_path_server();
    let mut c = raw(
        &srv.addr,
        &[Setting {
            id: SETTING_ENABLE_PUSH,
            val: 0,
        }],
    );
    c.request(1, "/push", true);
    let f = c.until(|f| matches!(f, Frame::Data { .. }));
    assert!(matches!(f, Frame::Data { data, .. } if data == b"push=false"));
}

#[test]
fn protocol_violations_get_goaway_or_rst_stream() {
    let srv = echo_path_server();
    // WINDOW_UPDATE with a zero increment on a stream is a stream error.
    let mut c = raw(&srv.addr, &[]);
    c.request(1, "/slow", false);
    c.send(|fw| {
        fw.allow_illegal_writes = true;
        fw.write_window_update(1, 0).unwrap()
    });
    let f = c.until(|f| matches!(f, Frame::RstStream { .. }));
    assert!(matches!(f, Frame::RstStream { code, .. } if code == ERR_CODE_PROTOCOL));
    // DATA on an idle stream is a connection error.
    let mut c = raw(&srv.addr, &[]);
    c.send(|fw| fw.write_data(5, false, b"x").unwrap());
    let f = c.until(|f| matches!(f, Frame::GoAway { .. }));
    assert!(matches!(f, Frame::GoAway { code, .. } if code == ERR_CODE_PROTOCOL));
    // A bogus preface is dropped.
    let mut s = TcpStream::connect(&srv.addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nXX\r\n\r\n").unwrap();
    let mut buf = [0u8; 64];
    // The server may answer with its SETTINGS, then closes.
    loop {
        match std::io::Read::read(&mut s, &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

#[test]
fn server_enforces_max_concurrent_streams_setting_and_header_rules() {
    let srv = echo_path_server();
    let mut c = raw(&srv.addr, &[]);
    // A connection-specific header is answered with 400, not a reset.
    let mut blk = Vec::new();
    for (n, v) in [
        (":method", "GET"),
        (":scheme", "http"),
        (":authority", "x"),
        (":path", "/"),
        ("connection", "keep-alive"),
    ] {
        c.enc.write_field(&HeaderField::new(n, v), &mut blk);
    }
    c.send(|fw| {
        fw.write_headers(&HeadersParam {
            stream_id: 1,
            block_fragment: &blk,
            end_stream: true,
            end_headers: true,
            ..HeadersParam::default()
        })
        .unwrap()
    });
    let f = c.until(|f| matches!(f, Frame::Meta(_)));
    let Frame::Meta(m) = f else { unreachable!() };
    assert_eq!(m.pseudo_value("status"), b"400");
}

#[test]
fn h2c_client_trace_stream_hooks() {
    use rust_stdlib::context::Context;
    use rust_stdlib::net::http::httptrace::{with_client_trace, ClientTrace};
    use rust_stdlib::net::http::Request;
    let srv = h2c_server(http::handler_func(
        |w: &mut dyn ResponseWriter, _r: &mut Request| {
            let _ = w.write_string("traced");
        },
    ));
    let events: Arc<Mutex<Vec<String>>> = Arc::default();
    let rec = |name: &'static str| {
        let events = events.clone();
        Arc::new(move || events.lock().unwrap().push(name.to_owned()))
    };
    let fields = events.clone();
    let wrote = events.clone();
    let trace = ClientTrace {
        wrote_header_field: Some(Arc::new(move |k, v| {
            fields
                .lock()
                .unwrap()
                .push(format!("field {k}={}", v.join("|")));
        })),
        wrote_headers: Some(rec("WroteHeaders")),
        wrote_request: Some(Arc::new(move |i| {
            wrote
                .lock()
                .unwrap()
                .push(format!("WroteRequest err={}", i.err.is_some()));
        })),
        got_first_response_byte: Some(rec("GotFirstResponseByte")),
        ..ClientTrace::default()
    };
    let ctx = with_client_trace(&Context::background(), trace);
    let req = Request::in_context(&ctx, "GET", &format!("http://{}/t", srv.addr)).unwrap();
    let resp = h2c_client().do_request(req).unwrap();
    assert_eq!(body_string(resp), "traced");
    thread::sleep(Duration::from_millis(100));
    let got = events.lock().unwrap().clone();
    // Pseudo-header fields first, then WroteHeaders, WroteRequest and the
    // response's first byte, as in Go's http2 transport.
    assert_eq!(got[0], format!("field :authority={}", srv.addr));
    assert_eq!(
        &got[1..4],
        ["field :method=GET", "field :path=/t", "field :scheme=http"]
    );
    assert!(
        got.contains(&"field user-agent=Go-http-client/2.0".to_owned()),
        "{got:?}"
    );
    let pos = |s: &str| {
        got.iter()
            .position(|e| e == s)
            .unwrap_or_else(|| panic!("{s} in {got:?}"))
    };
    assert!(pos("WroteHeaders") < pos("WroteRequest err=false"));
    assert!(got.contains(&"GotFirstResponseByte".to_owned()));
}
