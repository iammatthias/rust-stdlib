//! Client scenarios shared by the h2c (root crate) and TLS (backends/tls)
//! interop clients. They expect the handlers of
//! `examples/h2_interop_server/handlers.rs`, served by Go's net/http by
//! `tools/h2_interop_server.go`.
use rust_stdlib::net::http::{
    client::Client,
    header::{Header, Trailer},
    response::Response,
    Request, RequestBody,
};
use std::{
    io::{self, Read},
    sync::{
        atomic::{AtomicI64, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

pub struct Env {
    pub client: Client,
    pub base: String,
    pub dials: Arc<AtomicI64>,
}

type R = Result<(), String>;
type Scenario = (&'static str, fn(&Env) -> R);

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

fn fnv(data: &[u8], mut h: u64) -> u64 {
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn body_bytes(resp: Response) -> Result<Vec<u8>, String> {
    resp.body
        .ok_or("no body")?
        .read_all()
        .map_err(|e| e.to_string())
}

impl Env {
    fn get(&self, path: &str) -> Result<(Response, Vec<u8>), String> {
        let mut resp = self
            .client
            .get(&format!("{}{}", self.base, path))
            .map_err(|e| e.to_string())?;
        let body = resp
            .body
            .take()
            .ok_or("no body")?
            .read_all()
            .map_err(|e| e.to_string())?;
        Ok((resp, body))
    }
    fn get_text(&self, path: &str) -> Result<String, String> {
        Ok(String::from_utf8_lossy(&self.get(path)?.1).into_owned())
    }
}

fn want(got: &str, exp: &str) -> R {
    if got == exp {
        Ok(())
    } else {
        Err(format!("got {got:?}, want {exp:?}"))
    }
}

pub fn run_all(env: &Env) -> usize {
    let scenarios: Vec<Scenario> = vec![
        ("hello", hello),
        ("proto", proto),
        ("echo-small", echo_small),
        ("echo-large-known-length", echo_large),
        ("echo-unknown-length-duplex", echo_duplex),
        ("download-large", download_large),
        ("upload-large-flow-control", upload_large),
        ("response-trailers", response_trailers),
        ("request-trailers", request_trailers),
        ("headers-and-cookies", headers_and_cookies),
        ("status-codes", status_codes),
        ("handler-panic-rst", handler_panic),
        ("handler-abort", handler_abort),
        ("client-cancel-rst-stream", client_cancel),
        ("streaming-flush", streaming_flush),
        ("concurrent-streams", concurrent_streams),
        ("connection-reuse", connection_reuse),
        ("connection-close-goaway", connection_close),
        ("push-disabled-by-client", push_disabled),
        ("head", head),
    ];
    let mut failed = 0;
    for (name, f) in scenarios {
        match f(env) {
            Ok(()) => println!("ok {name}"),
            Err(e) => {
                println!("FAIL {name}: {e}");
                failed += 1;
            }
        }
    }
    failed
}

fn hello(env: &Env) -> R {
    let (resp, body) = env.get("/hello")?;
    if resp.proto_major != 2 || resp.proto != "HTTP/2.0" {
        return Err(format!("proto {}", resp.proto));
    }
    if resp.header.get("X-Hello").unwrap_or("") != "world" {
        return Err(format!("header {:?}", resp.header));
    }
    if resp.header.get("Date").unwrap_or("").is_empty()
        || resp.header.get("Content-Type").unwrap_or("").is_empty()
    {
        return Err(format!("missing Date or Content-Type: {:?}", resp.header));
    }
    if resp.header.get("Content-Length").unwrap_or("") != "5" || resp.content_length != 5 {
        return Err(format!(
            "content-length {}",
            resp.header.get("Content-Length").unwrap_or("")
        ));
    }
    want(&String::from_utf8_lossy(&body), "hello")
}

fn proto(env: &Env) -> R {
    let s = env.get_text("/proto")?;
    for frag in [
        "proto=HTTP/2.0",
        "major=2",
        "minor=0",
        "method=GET",
        "uri=/proto",
        "remote=true",
        "ua=Go-http-client/2.0",
    ] {
        if !s.contains(frag) {
            return Err(format!("missing {frag:?} in {s:?}"));
        }
    }
    Ok(())
}

fn post(env: &Env, path: &str, body: RequestBody) -> Result<Response, String> {
    let req = Request::new("POST", &format!("{}{}", env.base, path))
        .map(|r| r.with_body(body))
        .map_err(|e| e.to_string())?;
    env.client.do_request(req).map_err(|e| e.to_string())
}

fn echo_small(env: &Env) -> R {
    let resp = post(env, "/echo", "ping".into())?;
    let seen = resp.header.get("X-Seen-Length").unwrap_or("");
    if seen != "4" {
        return Err(format!("server saw length {seen:?}"));
    }
    want(&String::from_utf8_lossy(&body_bytes(resp)?), "ping")
}

fn echo_large(env: &Env) -> R {
    let data = pattern(3 << 20);
    let resp = post(env, "/echo", data.clone().into())?;
    let got = body_bytes(resp)?;
    if got != data {
        return Err(format!("echo mismatch: got {} bytes", got.len()));
    }
    Ok(())
}

/// A reader fed through a channel: the unknown-length request body.
struct ChanReader {
    rx: std::sync::mpsc::Receiver<Vec<u8>>,
    cur: io::Cursor<Vec<u8>>,
}
impl Read for ChanReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let n = self.cur.read(buf)?;
            if n > 0 {
                return Ok(n);
            }
            match self.rx.recv() {
                Ok(v) => self.cur = io::Cursor::new(v),
                Err(_) => return Ok(0),
            }
        }
    }
}

fn echo_duplex(env: &Env) -> R {
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    tx.send(b"one".to_vec()).unwrap();
    let body = RequestBody::reader(ChanReader {
        rx,
        cur: io::Cursor::new(Vec::new()),
    });
    let mut req = Request::new("POST", &format!("{}/echo", env.base))
        .map(|r| r.with_body(body))
        .map_err(|e| e.to_string())?;
    req.content_length = -1;
    let mut resp = env.client.do_request(req).map_err(|e| e.to_string())?;
    let seen = resp.header.get("X-Seen-Length").unwrap_or("");
    if seen != "-1" {
        return Err(format!("server saw length {seen:?}"));
    }
    let mut body = resp.body.take().ok_or("no body")?;
    let mut buf = [0u8; 3];
    body.read_exact(&mut buf).map_err(|e| e.to_string())?;
    want(&String::from_utf8_lossy(&buf), "one")?;
    tx.send(b"two".to_vec()).unwrap();
    drop(tx);
    let rest = body.read_all().map_err(|e| e.to_string())?;
    want(&String::from_utf8_lossy(&rest), "two")
}

fn download_large(env: &Env) -> R {
    const N: usize = 12 << 20;
    let (resp, body) = env.get(&format!("/big?n={N}"))?;
    if resp.status_code != 200 || body != pattern(N) {
        return Err(format!("status {}, {} bytes", resp.status_code, body.len()));
    }
    Ok(())
}

fn upload_large(env: &Env) -> R {
    const N: usize = 24 << 20;
    let data = pattern(N);
    let resp = post(env, "/upload", data.clone().into())?;
    let b = body_bytes(resp)?;
    want(
        &String::from_utf8_lossy(&b),
        &format!("len={N} fnv={:016x}", fnv(&data, 0xcbf29ce484222325)),
    )
}

fn response_trailers(env: &Env) -> R {
    let mut resp = env
        .client
        .get(&format!("{}/trailers", env.base))
        .map_err(|e| e.to_string())?;
    let body = resp
        .body
        .take()
        .ok_or("no body")?
        .read_all()
        .map_err(|e| e.to_string())?;
    want(&String::from_utf8_lossy(&body), "payload")?;
    let t = resp.trailer.get().ok_or("no trailers")?;
    if t.get("X-Checksum").unwrap_or("") != "abc123"
        || t.get("X-Done").unwrap_or("") != "yes"
        || t.get("X-Late").unwrap_or("") != "late"
    {
        return Err(format!("trailers {t:?}"));
    }
    Ok(())
}

fn request_trailers(env: &Env) -> R {
    let mut req = Request::new("POST", &format!("{}/reqtrailers", env.base))
        .map(|r| r.with_body(RequestBody::reader(io::Cursor::new(b"data".to_vec()))))
        .map_err(|e| e.to_string())?;
    req.content_length = -1;
    let mut t = Header::new();
    t.0.insert("X-Req-A".into(), vec![String::new()]);
    t.0.insert("X-Req-B".into(), vec![String::new()]);
    req.trailer = Trailer::new(Some(t));
    // Trailer values are read after the body, so they can be set late.
    let mut filled = Header::new();
    filled.set("X-Req-A", "1");
    filled.set("X-Req-B", "2");
    req.trailer.set(Some(filled));
    let resp = env.client.do_request(req).map_err(|e| e.to_string())?;
    want(
        &String::from_utf8_lossy(&body_bytes(resp)?),
        "body=data X-Req-A=1 X-Req-B=2",
    )
}

fn headers_and_cookies(env: &Env) -> R {
    let mut req =
        Request::new("GET", &format!("{}/headers", env.base)).map_err(|e| e.to_string())?;
    req.header.add("X-Multi", "a");
    req.header.add("X-Multi", "b");
    req.header.set("Connection", "keep-alive");
    let resp = env.client.do_request(req).map_err(|e| e.to_string())?;
    let b = String::from_utf8_lossy(&body_bytes(resp)?).into_owned();
    if !b.contains("X-Multi=a|b") {
        return Err(format!("headers {b:?}"));
    }
    if b.contains("Connection") {
        return Err(format!("connection header leaked: {b:?}"));
    }
    let mut req2 =
        Request::new("GET", &format!("{}/cookie", env.base)).map_err(|e| e.to_string())?;
    req2.header.set("Cookie", "a=1; b=2");
    let resp2 = env.client.do_request(req2).map_err(|e| e.to_string())?;
    want(&String::from_utf8_lossy(&body_bytes(resp2)?), "a=1; b=2")
}

fn status_codes(env: &Env) -> R {
    for code in [204, 404, 418, 500] {
        let (resp, body) = env.get(&format!("/status/{code}"))?;
        if resp.status_code != code {
            return Err(format!("status {} != {code}", resp.status_code));
        }
        if code != 204 && String::from_utf8_lossy(&body) != format!("status {code}") {
            return Err(format!("body {:?}", String::from_utf8_lossy(&body)));
        }
    }
    Ok(())
}

fn handler_panic(env: &Env) -> R {
    match env.get("/panic") {
        Ok(_) => return Err("want a reset stream error".into()),
        Err(e) if e.contains("INTERNAL_ERROR") => {}
        Err(e) => return Err(format!("want INTERNAL_ERROR reset, got {e}")),
    }
    want(&env.get_text("/hello")?, "hello")
}

fn handler_abort(env: &Env) -> R {
    match env.get("/abort") {
        Ok(_) => Err("want a reset stream error".into()),
        Err(e) if e.contains("INTERNAL_ERROR") => Ok(()),
        Err(e) => Err(format!("want INTERNAL_ERROR reset, got {e}")),
    }
}

fn client_cancel(env: &Env) -> R {
    let (ctx, cancel) =
        rust_stdlib::context::Context::background().with_timeout(Duration::from_millis(300).into());
    let req = Request::in_context(&ctx, "GET", &format!("{}/slow", env.base))
        .map_err(|e| e.to_string())?;
    let start = Instant::now();
    let r = env.client.do_request(req);
    cancel();
    match r {
        Ok(_) => return Err("want a deadline error".into()),
        Err(e) => {
            let s = e.to_string();
            if !s.contains("deadline exceeded") {
                return Err(format!("want deadline exceeded, got {s}"));
            }
        }
    }
    if start.elapsed() > Duration::from_secs(3) {
        return Err("cancel took too long".into());
    }
    want(&env.get_text("/hello")?, "hello")
}

fn streaming_flush(env: &Env) -> R {
    let mut resp = env
        .client
        .get(&format!("{}/flush", env.base))
        .map_err(|e| e.to_string())?;
    let mut body = resp.body.take().ok_or("no body")?;
    let start = Instant::now();
    let mut buf = [0u8; 1];
    body.read_exact(&mut buf).map_err(|e| e.to_string())?;
    if start.elapsed() > Duration::from_millis(80) || buf[0] != b'a' {
        return Err(format!(
            "first chunk after {:?}: {:?}",
            start.elapsed(),
            buf
        ));
    }
    let rest = body.read_all().map_err(|e| e.to_string())?;
    want(&String::from_utf8_lossy(&rest), "b")
}

fn concurrent_streams(env: &Env) -> R {
    env.get("/barrier-reset")?;
    const N: usize = 40;
    let before = env.dials.load(Ordering::SeqCst);
    let results: Vec<_> = (0..N)
        .map(|_| {
            let client = env.client.clone();
            let url = format!("{}/barrier?n={N}", env.base);
            thread::spawn(move || -> Result<String, String> {
                let resp = client.get(&url).map_err(|e| e.to_string())?;
                Ok(String::from_utf8_lossy(&body_bytes(resp)?).into_owned())
            })
        })
        .collect();
    for h in results {
        let s = h.join().map_err(|_| "thread panicked".to_owned())??;
        want(&s, "barrier reached=true")?;
    }
    let d = env.dials.load(Ordering::SeqCst) - before;
    if d > 3 {
        return Err(format!("{d} new connections for {N} concurrent streams"));
    }
    Ok(())
}

fn connection_reuse(env: &Env) -> R {
    let before = env.dials.load(Ordering::SeqCst);
    for _ in 0..30 {
        env.get("/hello")?;
    }
    let d = env.dials.load(Ordering::SeqCst) - before;
    if d > 1 {
        return Err(format!("{d} dials for 30 sequential requests"));
    }
    Ok(())
}

fn connection_close(env: &Env) -> R {
    want(&env.get_text("/close")?, "closing")?;
    thread::sleep(Duration::from_millis(100));
    let before = env.dials.load(Ordering::SeqCst);
    let body = env.get_text("/hello")?;
    if env.dials.load(Ordering::SeqCst) == before {
        return Err("no new connection after GOAWAY".into());
    }
    want(&body, "hello")
}

fn push_disabled(env: &Env) -> R {
    want(&env.get_text("/push")?, "push=err:feature not supported")
}

fn head(env: &Env) -> R {
    let resp = env
        .client
        .head(&format!("{}/hello", env.base))
        .map_err(|e| e.to_string())?;
    let status = resp.status_code;
    let b = body_bytes(resp)?;
    if !b.is_empty() || status != 200 {
        return Err(format!("head: {status} {b:?}"));
    }
    Ok(())
}
