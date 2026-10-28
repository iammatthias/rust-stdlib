//! Line protocol used by `tools/httptrace_check.py` for Go differential checks.
//! See `tools/httptrace_oracle.go` for the request and response formats.
use rust_stdlib::context::Context;
use rust_stdlib::net::http::httptrace::{
    with_client_trace, ClientTrace, DNSDoneInfo, DNSStartInfo, GotConnInfo, HookError,
    WroteRequestInfo,
};
use rust_stdlib::net::http::Request;
use rust_stdlib::net::http::{Header, Protocols, RequestBody, RoundTripper, Transport};
use rust_stdlib::time::{Duration, MILLISECOND};
use std::io::{self, BufRead, Cursor, Write};
use std::sync::{Arc, Mutex};

fn unhex(s: &str) -> String {
    if s == "-" {
        return String::new();
    }
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// `127.0.0.1:<port>` and `[::1]:<port>` become `ADDR`.
fn scrub(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    loop {
        let a = rest.find("127.0.0.1:");
        let b = rest.find("[::1]:");
        let (i, len) = match (a, b) {
            (Some(a), Some(b)) if b < a => (b, "[::1]:".len()),
            (Some(a), _) => (a, "127.0.0.1:".len()),
            (None, Some(b)) => (b, "[::1]:".len()),
            (None, None) => break,
        };
        out.push_str(&rest[..i]);
        out.push_str("ADDR");
        let after = &rest[i + len..];
        let digits = after.bytes().take_while(u8::is_ascii_digit).count();
        rest = &after[digits..];
    }
    out.push_str(rest);
    out
}

#[derive(Default)]
struct Events {
    main: Vec<String>,
    write: Vec<String>,
    read: Vec<String>,
    wrote: bool,
}

type Shared = Arc<Mutex<Events>>;

fn err_text(e: Option<&HookError>) -> String {
    e.map_or_else(|| "nil".to_owned(), ToString::to_string)
}

fn header_text(h: &Header) -> String {
    h.0.iter()
        .map(|(k, v)| format!("{k}:{}", v.join("|")))
        .collect::<Vec<_>>()
        .join(",")
}

fn new_trace(e: &Shared) -> ClientTrace {
    let main = |e: &Shared, s: String| e.lock().unwrap().main.push(scrub(&s));
    let write = |e: &Shared, s: String| e.lock().unwrap().write.push(scrub(&s));
    let read = |e: &Shared, s: String| e.lock().unwrap().read.push(scrub(&s));
    let (e1, e2, e3, e4, e5, e6, e7, e8) = (
        e.clone(),
        e.clone(),
        e.clone(),
        e.clone(),
        e.clone(),
        e.clone(),
        e.clone(),
        e.clone(),
    );
    let (e9, e10, e11, e12, e13, e14, e15, e16) = (
        e.clone(),
        e.clone(),
        e.clone(),
        e.clone(),
        e.clone(),
        e.clone(),
        e.clone(),
        e.clone(),
    );
    ClientTrace {
        get_conn: Some(Arc::new(move |hp| main(&e1, format!("GetConn {hp}")))),
        got_conn: Some(Arc::new(move |i: GotConnInfo| {
            main(
                &e2,
                format!("GotConn reused={} idle={}", i.reused, i.was_idle),
            )
        })),
        put_idle_conn: Some(Arc::new(move |err| {
            read(&e3, format!("PutIdleConn {}", err_text(err)))
        })),
        got_first_response_byte: Some(Arc::new(move || {
            read(&e4, "GotFirstResponseByte".to_owned())
        })),
        got_100_continue: Some(Arc::new(move || read(&e5, "Got100Continue".to_owned()))),
        got_1xx_response: Some(Arc::new(move |code, h| {
            read(&e6, format!("Got1xxResponse {code} {}", header_text(h)));
            Ok(())
        })),
        dns_start: Some(Arc::new(move |i: DNSStartInfo| {
            main(&e7, format!("DNSStart {}", i.host))
        })),
        dns_done: Some(Arc::new(move |i: DNSDoneInfo| {
            let has = i.addrs.iter().any(|a| a.ip.to_string() == "127.0.0.1");
            let err = i.err.as_ref().map_or("nil".to_owned(), |e| e.to_string());
            main(&e8, format!("DNSDone has127={has} err={err}"))
        })),
        connect_start: Some(Arc::new(move |n, a| {
            if !a.starts_with("[::1]") {
                main(&e9, format!("ConnectStart {n} {a}"))
            }
        })),
        connect_done: Some(Arc::new(move |n, a, err| {
            if !a.starts_with("[::1]") {
                main(&e10, format!("ConnectDone {n} {a} {}", err_text(err)))
            }
        })),
        tls_handshake_start: Some(Arc::new(move || main(&e11, "TLSHandshakeStart".to_owned()))),
        tls_handshake_done: Some(Arc::new(move |_, err| {
            main(&e12, format!("TLSHandshakeDone {}", err_text(err)))
        })),
        wrote_header_field: Some(Arc::new(move |k, v| {
            write(&e13, format!("WroteHeaderField {k}={}", v.join("|")))
        })),
        wrote_headers: Some(Arc::new(move || write(&e14, "WroteHeaders".to_owned()))),
        wait_100_continue: Some(Arc::new(move || write(&e15, "Wait100Continue".to_owned()))),
        wrote_request: Some(Arc::new(move |i: WroteRequestInfo| {
            let t = i.err.as_ref().map_or("nil".to_owned(), |e| e.to_string());
            write(&e16, format!("WroteRequest {t}"));
            e16.lock().unwrap().wrote = true;
        })),
    }
}

fn run(port: &str, config: &str, requests: &str) -> String {
    let mut tr = Transport {
        expect_continue_timeout: MILLISECOND * 300,
        ..Transport::default()
    };
    let mut host = "127.0.0.1".to_owned();
    for c in config.split(',') {
        if c == "nokeepalive" {
            tr.disable_keep_alives = true;
        } else if let Some(n) = c.strip_prefix("maxidle=") {
            tr.max_idle_conns_per_host = n.parse().unwrap();
        } else if let Some(n) = c.strip_prefix("maxidleconns=") {
            tr.max_idle_conns = n.parse().unwrap();
        } else if c == "h2c" {
            let mut p = Protocols::default();
            p.set_unencrypted_http2(true);
            tr.protocols = Some(p);
        } else if let Some(n) = c.strip_prefix("ect=") {
            // ExpectContinueTimeout in milliseconds.
            tr.expect_continue_timeout = MILLISECOND * n.parse::<i64>().unwrap();
        } else if let Some(h) = c.strip_prefix("host=") {
            host = h.to_owned();
        }
    }
    let _ = Duration::default();
    let mut out = Vec::new();
    for spec in requests.split(';') {
        let f: Vec<&str> = spec.split(',').collect();
        let (method, path, body) = (f[0], f[1], unhex(f[2]));
        let flags: Vec<&str> = f[4].split('+').collect();
        let has = |name: &str| flags.contains(&name);
        let rbody = if body.is_empty() {
            None
        } else if has("chunked") {
            Some(RequestBody::reader(Cursor::new(body.into_bytes())))
        } else {
            Some(RequestBody::Bytes(body.into_bytes()))
        };
        let events: Shared = Arc::default();
        let ctx = with_client_trace(&Context::background(), new_trace(&events));
        let mut req =
            match Request::in_context(&ctx, method, &format!("http://{host}:{port}{path}")).map(
                |r| match rbody {
                    Some(b) => r.with_body(b),
                    None => r,
                },
            ) {
                Ok(r) => r,
                Err(e) => {
                    out.push(format!("newrequest {e}"));
                    continue;
                }
            };
        if has("chunked") {
            req.content_length = -1;
        }
        if f[3] != "-" {
            for kv in f[3].split('|') {
                let kv = unhex(kv);
                let (k, v) = kv.split_once(':').unwrap_or((&kv, ""));
                req.header.add(k, v);
            }
        }
        if has("expect") {
            req.header.set("Expect", "100-continue");
        }
        let result = match tr.round_trip(&req) {
            Err(e) => format!("err {}", scrub(&e.to_string())),
            Ok(resp) => {
                let status = resp.status_code;
                let body = resp.body.clone();
                if has("noread") {
                    if let Some(b) = &body {
                        let _ = b.close();
                    }
                    format!("status {status} noread")
                } else {
                    let (n, rerr) = match &body {
                        Some(b) => match b.read_all() {
                            Ok(v) => (v.len(), "nil".to_owned()),
                            Err(e) => (0, e.to_string()),
                        },
                        None => (0, "nil".to_owned()),
                    };
                    // Same wait as the Go oracle: let the request body write end (a
                    // trailing RST_STREAM(NO_ERROR) included) before the body is closed.
                    for _ in 0..5000 {
                        if events.lock().unwrap().wrote {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    if let Some(b) = &body {
                        let _ = b.close();
                    }
                    format!("status {status} body {n} {rerr}")
                }
            }
        };
        std::thread::sleep(std::time::Duration::from_millis(20));
        let e = events.lock().unwrap();
        out.push(format!(
            "{result} main[{}] write[{}] read[{}]",
            e.main.join("; "),
            e.write.join("; "),
            e.read.join("; ")
        ));
    }
    tr.close_idle_connections();
    out.join(" || ")
}

fn handle(line: &str) -> String {
    let f: Vec<&str> = line.splitn(4, ' ').collect();
    if f[0] != "T" {
        panic!("bad request {line}");
    }
    run(f[1], f[2], f[3])
}

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut out = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let text =
            std::panic::catch_unwind(|| handle(line)).unwrap_or_else(|_| "rust-panic".to_owned());
        writeln!(out, "{text}")?;
        out.flush()?;
    }
    Ok(())
}
