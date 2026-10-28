//! Line protocol used by `tools/http_check.py` for Go differential checks.
//! Inputs are `MODE:f1,f2,...` with hex fields; outputs match
//! `tools/http_oracle.go`.
use rust_stdlib::net::http::{
    self,
    request::{read_request, Request},
    response::read_response,
    BufioReader, Cookie, Handler, Header, ResponseWriter, ServeMux,
};
use std::{
    io::{self, BufRead, Cursor, Read, Write},
    sync::{Arc, Mutex},
};

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex field"))
        .collect()
}
fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}
fn s(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}
fn record(fields: &[String]) -> String {
    hex(fields.join("\0"))
}
fn header_text(h: &Header) -> String {
    let mut out = Vec::new();
    h.write(&mut out).expect("write to Vec");
    s(&out)
}
fn bool_s(b: bool) -> String {
    b.to_string()
}

/// Serves `req` through `h` into an `httptest.ResponseRecorder` and returns
/// the status, headers and body of its `Result`.
fn serve_recorded(h: &dyn Handler, req: &mut Request) -> (u16, Header, Vec<u8>) {
    let mut rec = rust_stdlib::net::http::httptest::ResponseRecorder::new();
    h.serve_http(&mut rec, req);
    let res = rec.result();
    let body = res
        .body
        .as_ref()
        .map(|b| b.read_all().unwrap_or_default())
        .unwrap_or_default();
    (res.status_code, res.header.clone(), body)
}

fn wildcard_names(pattern: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = pattern;
    while let Some(i) = rest.find('{') {
        let Some(j) = rest[i..].find('}') else { break };
        let raw = &rest[i + 1..i + j];
        let name = raw.strip_suffix("...").unwrap_or(raw);
        if name != "$" && !name.is_empty() {
            names.push(name.to_owned());
        }
        rest = &rest[i + j + 1..];
    }
    names
}

fn mux_table(f: &[Vec<u8>]) -> String {
    let mux = ServeMux::new();
    let mut regs = Vec::new();
    let patterns: Vec<String> = if f[0].is_empty() {
        Vec::new()
    } else {
        f[0].split(|&b| b == 1).map(s).collect()
    };
    for pat in patterns {
        let p = pat.clone();
        let r = mux.handle_func(&pat, move |w, r| {
            let vals: Vec<String> = wildcard_names(&p)
                .iter()
                .map(|n| format!("{n}={}", r.path_value(n)))
                .collect();
            w.header().set("X-Pattern", &r.pattern);
            let _ = w.write(vals.join("&").as_bytes());
        });
        regs.push(if r.is_ok() { "ok" } else { "panic" });
    }
    let mut res = vec![regs.join(" ")];
    if f.len() > 1 && !f[1].is_empty() {
        for rq in f[1].split(|&b| b == 1) {
            let parts: Vec<String> = rq.split(|&b| b == 0).map(s).collect();
            let (method, host, target) = (&parts[0], &parts[1], &parts[2]);
            let mut raw = format!("{method} {target} HTTP/1.1\r\n");
            if !host.is_empty() {
                raw.push_str(&format!("Host: {host}\r\n"));
            }
            raw.push_str("\r\n");
            let mut req = match read_request(&BufioReader::new(Cursor::new(raw.into_bytes()))) {
                Ok(r) => r,
                Err(_) => {
                    res.push(hex("parse-error"));
                    continue;
                }
            };
            let (code, h, body) = serve_recorded(&mux, &mut req);
            res.push(hex([
                code.to_string(),
                h.get("Allow").unwrap_or("").to_owned(),
                h.get("Location").unwrap_or("").to_owned(),
                h.get("X-Pattern").unwrap_or("").to_owned(),
                h.get("Content-Type").unwrap_or("").to_owned(),
                s(&body),
                req.pattern.clone(),
            ]
            .join("\0")));
        }
    }
    res.join(" ")
}

fn cookie_fields(c: &Cookie) -> String {
    let exp = if c.expires.is_zero() {
        "0".to_owned()
    } else {
        c.expires.unix().to_string()
    };
    record(&[
        c.name.clone(),
        c.value.clone(),
        bool_s(c.quoted),
        c.path.clone(),
        c.domain.clone(),
        exp,
        c.raw_expires.clone(),
        c.max_age.to_string(),
        bool_s(c.secure),
        bool_s(c.http_only),
        c.same_site.0.to_string(),
        bool_s(c.partitioned),
        c.raw.clone(),
        c.unparsed.join("\u{1}"),
    ])
}

fn cookie_op(f: &[Vec<u8>]) -> String {
    match s(&f[0]).as_str() {
        "PC" => match http::parse_cookie(&s(&f[1])) {
            Err(e) => format!("ERR {}", hex(e.to_string())),
            Ok(cs) => format!(
                "OK {}",
                cs.iter().map(cookie_fields).collect::<Vec<_>>().join(" ")
            ),
        },
        "PS" => match http::parse_set_cookie(&s(&f[1])) {
            Err(e) => format!("ERR {}", hex(e.to_string())),
            Ok(c) => format!("OK {}", cookie_fields(&c)),
        },
        "ST" => {
            let mut c = Cookie {
                name: s(&f[1]),
                value: s(&f[2]),
                quoted: s(&f[3]) == "1",
                path: s(&f[4]),
                domain: s(&f[5]),
                ..Cookie::default()
            };
            if let Ok(n) = s(&f[6]).parse::<i64>() {
                c.expires = rust_stdlib::time::unix(n, 0);
            }
            c.max_age = s(&f[7]).parse().unwrap_or(0);
            c.secure = s(&f[8]) == "1";
            c.http_only = s(&f[9]) == "1";
            c.same_site = http::SameSite(s(&f[10]).parse().unwrap_or(0));
            c.partitioned = s(&f[11]) == "1";
            let verr = c.valid().err().map(|e| e.to_string()).unwrap_or_default();
            record(&[c.to_string(), verr])
        }
        "RC" => {
            let mut r = Request::default();
            if !f[1].is_empty() {
                for l in f[1].split(|&b| b == 1) {
                    r.header.add("Cookie", &s(l));
                }
            }
            let filter = s(&f[2]);
            let cs = if filter.is_empty() {
                r.cookies()
            } else {
                r.cookies_named(&filter)
            };
            let out: Vec<String> = cs
                .iter()
                .map(|c| record(&[c.name.clone(), c.value.clone(), bool_s(c.quoted)]))
                .collect();
            let first = match r.cookie(&filter) {
                Err(e) => e.to_string(),
                Ok(c) => format!("{}={}", c.name, c.value),
            };
            format!("OK {} {}", hex(first), out.join(" "))
        }
        _ => "UNKNOWN".into(),
    }
}

fn read_all(body: &Option<http::Body>) -> (Vec<u8>, String) {
    let mut out = Vec::new();
    let mut berr = String::new();
    if let Some(b) = body {
        let mut b = b.clone();
        if let Err(e) = b.read_to_end(&mut out) {
            berr = io_err_text(&e);
        }
    }
    (out, berr)
}
/// Go's text for a body read error.
fn io_err_text(e: &io::Error) -> String {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        return "unexpected EOF".into();
    }
    e.to_string()
}

fn request_op(f: &[Vec<u8>]) -> String {
    let raw = f[0].clone();
    let parse = |raw: &[u8]| read_request(&BufioReader::new(Cursor::new(raw.to_vec())));
    let req = match parse(&raw) {
        Ok(r) => r,
        Err(e) => return format!("ERR {}", hex(e.to_string())),
    };
    let (body, berrs) = read_all(&req.body);
    let trailer = req
        .trailer
        .get()
        .map(|t| header_text(&t))
        .unwrap_or_default();
    let req2 = parse(&raw).expect("second parse");
    let mut wb = Vec::new();
    let werr = req2
        .write(&mut wb)
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    let req3 = parse(&raw).expect("third parse");
    let mut pb = Vec::new();
    let perr = req3
        .write_proxy(&mut pb)
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    format!(
        "OK {}",
        record(&[
            req.method.clone(),
            req.request_uri.clone(),
            req.proto.clone(),
            req.proto_major.to_string(),
            req.proto_minor.to_string(),
            req.url.to_string(),
            req.host.clone(),
            req.content_length.to_string(),
            req.transfer_encoding.join(","),
            bool_s(req.close),
            header_text(&req.header),
            trailer,
            s(&body),
            berrs,
            s(&wb),
            werr,
            s(&pb),
            perr,
        ])
    )
}

fn response_op(f: &[Vec<u8>]) -> String {
    let raw = f[0].clone();
    let method = s(&f[1]);
    let req = (!method.is_empty()).then(|| {
        let mut r = Request::default();
        r.method = method.clone();
        r
    });
    let parse =
        |raw: &[u8]| read_response(&BufioReader::new(Cursor::new(raw.to_vec())), req.as_ref());
    let resp = match parse(&raw) {
        Ok(r) => r,
        Err(e) => return format!("ERR {}", hex(e.to_string())),
    };
    let (body, berrs) = read_all(&resp.body);
    let trailer = resp
        .trailer
        .get()
        .map(|t| header_text(&t))
        .unwrap_or_default();
    let resp2 = parse(&raw).expect("second parse");
    let mut wb = Vec::new();
    let werr = resp2
        .write(&mut wb)
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    format!(
        "OK {}",
        record(&[
            resp.status.clone(),
            resp.status_code.to_string(),
            resp.proto.clone(),
            resp.proto_major.to_string(),
            resp.proto_minor.to_string(),
            resp.content_length.to_string(),
            resp.transfer_encoding.join(","),
            bool_s(resp.close),
            bool_s(resp.uncompressed),
            header_text(&resp.header),
            trailer,
            s(&body),
            berrs,
            s(&wb),
            werr,
        ])
    )
}

fn date_op(f: &[Vec<u8>]) -> String {
    match s(&f[0]).as_str() {
        "T" => match http::parse_time(&s(&f[1])) {
            Err(_) => "ERR".into(),
            Ok(t) => format!(
                "OK {} {}",
                t.unix_nano(),
                hex(t.utc().format(http::TIME_FORMAT))
            ),
        },
        "V" => match http::parse_http_version(&s(&f[1])) {
            Some((a, b)) => format!("{a} {b} true"),
            None => "0 0 false".into(),
        },
        "H" => hex(http::canonical_header_key(&s(&f[1]))),
        "S" => hex(http::status_text(s(&f[1]).parse().unwrap_or(0))),
        _ => "UNKNOWN".into(),
    }
}

/// Interprets the handler script of `tools/http_oracle.go`.
fn run_script(script: &str, w: &mut dyn ResponseWriter, r: &mut Request) {
    for line in script.split('\n') {
        if line.is_empty() {
            continue;
        }
        let p: Vec<&str> = line.split('\t').collect();
        match p[0] {
            "h" => w.header().set(p[1], p[2]),
            "a" => w.header().add(p[1], p[2]),
            "d" => w.header().del(p[1]),
            "c" => w.write_header(p[1].parse().unwrap_or(0)),
            "w" => {
                let _ = w.write_string(p[1]);
            }
            "f" => {
                let _ = http::ResponseController::new(w).flush();
            }
            "r" => {
                let mut b = Vec::new();
                let err = match &r.body {
                    Some(body) => body.clone().read_to_end(&mut b).err(),
                    None => None,
                };
                let err = err.map_or("<nil>".to_owned(), |e| io_err_text(&e));
                let _ = w.write(format!("body={}:{} err={}", b.len(), s(&b), err).as_bytes());
            }
            "rn" => {
                let n: usize = p[1].parse().unwrap_or(0);
                let mut buf = vec![0u8; n];
                let mut got = 0;
                let mut err = "<nil>".to_owned();
                if let Some(body) = &r.body {
                    let mut body = body.clone();
                    while got < n {
                        match body.read(&mut buf[got..]) {
                            Ok(0) => {
                                err = if got == 0 {
                                    "EOF".into()
                                } else {
                                    "unexpected EOF".into()
                                };
                                break;
                            }
                            Ok(k) => got += k,
                            Err(e) => {
                                err = io_err_text(&e);
                                break;
                            }
                        }
                    }
                }
                let _ = w.write(format!("rn={}:{} err={}", got, s(&buf[..got]), err).as_bytes());
            }
            "t" => w
                .header()
                .set(&format!("{}{}", http::TRAILER_PREFIX, p[1]), p[2]),
            "p" => std::panic::panic_any(http::ERR_ABORT_HANDLER),
            "m" => {
                let _ = w.write(
                    format!(
                        "{} {} {} {} {:?} cl={}",
                        r.method, r.url.path, r.host, r.proto, r.request_uri, r.content_length
                    )
                    .as_bytes(),
                );
            }
            _ => {}
        }
    }
}

/// Replaces `Date: <HTTP date>` header lines by `Date: X`.
fn normalize_dates(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i..].starts_with(b"Date: ") && raw.len() >= i + 35 && raw[i + 32..i + 35] == *b"GMT"
        {
            out.extend_from_slice(b"Date: X");
            i += 35;
        } else {
            out.push(raw[i]);
            i += 1;
        }
    }
    out
}

fn server_op(f: &[Vec<u8>]) -> String {
    let script = s(&f[0]);
    let raw = f[1].clone();
    let server = http::server::Server {
        handler: Some(http::handler_func(move |w, r| run_script(&script, w, r))),
        error_log: Some(Arc::new(rust_stdlib::log::Logger::new(io::sink(), "", 0))),
        ..http::server::Server::default()
    };
    let ln = rust_stdlib::net::listen("tcp", "127.0.0.1:0").expect("listen");
    let addr = ln.addr().expect("addr").to_string();
    let srv = server.clone();
    let t = std::thread::spawn(move || {
        let _ = srv.serve(ln);
    });
    let mut conn = std::net::TcpStream::connect(&addr).expect("dial");
    let _ = conn.write_all(&raw);
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let mut wait = 1500; // the first byte may be slow on a loaded machine
    loop {
        conn.set_read_timeout(Some(std::time::Duration::from_millis(wait)))
            .ok();
        // tools/http_check.py raises this to rerun a slow pipelined vector.
        wait = std::env::var("HTTP_SERVER_IDLE_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(150);
        match conn.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
    drop(conn);
    let _ = server.close();
    let _ = t.join();
    hex(normalize_dates(&out))
}

/// FileServer / ServeFile / ServeContent over a generated tree, no network.
fn file_op(f: &[Vec<u8>]) -> String {
    use rust_stdlib::time;
    let kind = s(&f[0]);
    let spec = s(&f[1]);
    let root = std::env::temp_dir().join(format!(
        "httpfs-rs-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("tmp root");
    let mut contents: std::collections::HashMap<String, Vec<u8>> = Default::default();
    let mut mtimes: std::collections::HashMap<String, i64> = Default::default();
    for line in spec.split('\n') {
        if line.is_empty() {
            continue;
        }
        let p: Vec<&str> = line.split('\t').collect();
        let full = root.join(p[1]);
        match p[0] {
            "d" => {
                std::fs::create_dir_all(&full).expect("mkdir");
            }
            "f" => {
                if let Some(parent) = full.parent() {
                    std::fs::create_dir_all(parent).expect("mkdir");
                }
                let data = from_hex(p[2]);
                std::fs::write(&full, &data).expect("write");
                let mt: i64 = p[3].parse().unwrap_or(0);
                let ft = std::time::UNIX_EPOCH + std::time::Duration::from_secs(mt as u64);
                std::fs::File::options()
                    .write(true)
                    .open(&full)
                    .and_then(|file| file.set_modified(ft))
                    .expect("set mtime");
                contents.insert(p[1].to_owned(), data);
                mtimes.insert(p[1].to_owned(), mt);
            }
            _ => {}
        }
    }
    // Directory times are part of listings: pin them like the oracle does.
    fn pin_dirs(dir: &std::path::Path) {
        let ft = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_100);
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                if e.path().is_dir() {
                    pin_dirs(&e.path());
                }
            }
        }
        std::fs::File::open(dir)
            .and_then(|f| f.set_modified(ft))
            .expect("pin dir mtime");
    }
    pin_dirs(&root);
    let root_s = root.to_string_lossy().into_owned();
    let handler: Arc<dyn Handler> = if kind == "fs" {
        http::file_server(Arc::new(http::Dir(root_s.clone())))
    } else if let Some(name) = kind.strip_prefix("file:") {
        let path = format!("{root_s}/{name}");
        http::handler_func(move |w, r| http::serve_file(w, r, &path))
    } else {
        let name = kind.strip_prefix("content:").unwrap_or("").to_owned();
        http::handler_func(move |w, r| {
            for (h, k) in [
                ("X-Set-ETag", "ETag"),
                ("X-Set-Type", "Content-Type"),
                ("X-Set-Encoding", "Content-Encoding"),
            ] {
                let v = r.header.get(h).unwrap_or("");
                if !v.is_empty() {
                    w.header().set(k, v);
                }
            }
            let mt = match mtimes.get(&name) {
                Some(&m) if m != 0 => time::unix(m, 0),
                _ => time::Time::default(),
            };
            let mut rd = Cursor::new(contents.get(&name).cloned().unwrap_or_default());
            http::serve_content(w, r, &name, &mt, &mut rd);
        })
    };
    let mut out = Vec::new();
    for raw in f[2].split(|&b| b == 1) {
        let mut raw = raw.to_vec();
        raw.extend_from_slice(b"\r\n\r\n");
        let Ok(mut req) = read_request(&BufioReader::new(Cursor::new(raw))) else {
            out.push(hex("parse-error"));
            continue;
        };
        let (code, h, body) = serve_recorded(&*handler, &mut req);
        let mut text = format!("{}\0{}\0", code, header_text(&h)).into_bytes();
        text.extend_from_slice(&body);
        out.push(hex(replace_boundaries(&text)));
    }
    let _ = std::fs::remove_dir_all(&root);
    out.join(" ")
}

/// Replaces runs of 60 lower-case hex digits (multipart boundaries).
fn replace_boundaries(raw: &[u8]) -> Vec<u8> {
    let is_hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if i + 60 <= raw.len() && raw[i..i + 60].iter().all(|&b| is_hex(b)) {
            out.extend_from_slice(b"BOUNDARY");
            i += 60;
        } else {
            out.push(raw[i]);
            i += 1;
        }
    }
    out
}

/// `io.ReadAll` that keeps the bytes read before an error.
fn read_partial(body: &Option<http::Body>) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(b) = body {
        let mut b = b.clone();
        let mut buf = [0u8; 4096];
        while let Ok(n) = b.read(&mut buf) {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
    }
    out
}

/// httputil.ServerConn / ClientConn over loopback TCP (see `connOp`).
fn conn_op(f: &[Vec<u8>]) -> String {
    use rust_stdlib::net::http::httputil::{ClientConn, ServerConn};
    let kind = s(&f[0]);
    let raw = f[1].clone();
    let nreq: usize = s(&f[2]).parse().unwrap_or(0);
    let ln = rust_stdlib::net::listen("tcp4", "127.0.0.1:0").expect("listen");
    let addr = ln.addr().expect("addr").to_string();
    let mut peer = std::net::TcpStream::connect(&addr).expect("dial");
    let conn = ln.accept().expect("accept");
    let mut peer_w = peer.try_clone().expect("clone");
    std::thread::spawn(move || {
        let _ = peer_w.write_all(&raw);
        let _ = peer_w.shutdown(std::net::Shutdown::Write);
    });
    let seen = Arc::new(Mutex::new(Vec::<u8>::new()));
    let seen2 = seen.clone();
    let reader = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match peer.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => seen2.lock().expect("seen").extend_from_slice(&buf[..n]),
            }
        }
    });
    let mut log: Vec<String> = Vec::new();
    let errs = |e: &Option<rust_stdlib::net::http::httputil::ConnError>| {
        e.as_ref().map_or("<nil>".to_owned(), |e| e.to_string())
    };
    if kind == "S" {
        let sc = ServerConn::new(conn, None);
        for _ in 0..nreq {
            let (req, err) = sc.read();
            if let Some(req) = &req {
                let b = read_partial(&req.body);
                log.push(format!(
                    "R {} {} body={} err={} pending={}",
                    req.method,
                    req.request_uri,
                    go_quote(&b),
                    errs(&err),
                    sc.pending()
                ));
                let resp = rust_stdlib::net::http::response::Response {
                    status_code: 200,
                    proto_major: 1,
                    proto_minor: 1,
                    request: Some(Box::new(req.clone())),
                    body: Some(http::Body::from_bytes(b"ok".to_vec())),
                    content_length: 2,
                    ..Default::default()
                };
                let w = sc.write(req, &resp).err();
                log.push(format!("W {}", errs(&w)));
                if sc.write(req, &resp).err()
                    != Some(rust_stdlib::net::http::httputil::ConnError::Pipeline)
                {
                    log.push("W2 not pipeline".into());
                }
            } else {
                log.push(format!("R nil err={}", errs(&err)));
            }
            if err.is_some() {
                break;
            }
        }
        log.push(format!(
            "close {}",
            sc.close()
                .err()
                .map_or("<nil>".to_owned(), |e| e.to_string())
        ));
    } else {
        let cc = ClientConn::new(conn, None);
        let mut reqs = Vec::new();
        for i in 0..nreq {
            let req = Request::new("GET", &format!("http://example.com/r{i}")).expect("req");
            let err = cc.write(&req).err();
            log.push(format!("W {}", errs(&err)));
            if err.is_none() {
                reqs.push(req);
            }
        }
        log.push(format!("pending={}", cc.pending()));
        for req in &reqs {
            let (resp, err) = cc.read(req);
            match resp {
                Some(resp) => {
                    let b = read_partial(&resp.body);
                    log.push(format!(
                        "R {} {} body={} err={}",
                        resp.status_code,
                        go_quote(resp.status.as_bytes()),
                        go_quote(&b),
                        errs(&err)
                    ));
                }
                None => log.push(format!("R nil err={}", errs(&err))),
            }
        }
        log.push(format!(
            "close {}",
            cc.close()
                .err()
                .map_or("<nil>".to_owned(), |e| e.to_string())
        ));
    }
    let _ = reader.join();
    let mut out = log.join("\n").into_bytes();
    out.extend_from_slice(b"\n--\n");
    out.extend_from_slice(&seen.lock().expect("seen"));
    hex(out)
}

/// ReverseProxy.ServeHTTP with a capturing RoundTripper (see `proxyOp`).
fn proxy_op(f: &[Vec<u8>]) -> String {
    use rust_stdlib::net::http::{
        client::RoundTripper, header::BoxError, httputil::ReverseProxy, response::Response,
    };
    struct Capture {
        spec: String,
        out: Arc<Mutex<String>>,
    }
    impl RoundTripper for Capture {
        fn round_trip(&self, r: &Request) -> Result<Response, BoxError> {
            let spec = &self.spec;
            let (first, trailer_part) = spec.split_once('\u{1}').unwrap_or((spec.as_str(), ""));
            let (head, body) = first.split_once("\n\n").unwrap_or((first, ""));
            let mut lines = head.split('\n');
            let status: u16 = lines.next().unwrap_or("0").parse().unwrap_or(0);
            let mut bh = Header::new();
            for l in lines {
                if let Some((k, v)) = l.split_once(": ") {
                    bh.add(k, v);
                }
            }
            let trailer = if trailer_part.is_empty() {
                None
            } else {
                let mut t = Header::new();
                for l in trailer_part.split('\n') {
                    if let Some((k, v)) = l.split_once(": ") {
                        t.add(k, v);
                    }
                }
                Some(t)
            };
            let b = r
                .body
                .as_ref()
                .map(|b| b.read_all().unwrap_or_default())
                .unwrap_or_default();
            *self.out.lock().expect("capture") = format!(
                "{} {} host={} cl={} close={} hdr={} body={}",
                r.method,
                r.url,
                go_quote(r.host.as_bytes()),
                r.content_length,
                r.close,
                go_quote(header_text(&r.header).as_bytes()),
                go_quote(&b)
            );
            let mut resp = Response {
                status_code: status,
                header: bh.clone(),
                body: Some(http::Body::from_bytes(body.as_bytes().to_vec())),
                content_length: body.len() as i64,
                proto: "HTTP/1.1".into(),
                proto_major: 1,
                proto_minor: 1,
                ..Default::default()
            };
            resp.trailer.set(trailer);
            if !bh.get("X-Unknown-Length").unwrap_or("").is_empty() {
                resp.content_length = -1;
            }
            Ok(resp)
        }
    }
    let mode = s(&f[0]);
    let raw = f[1].clone();
    let remote = s(&f[2]);
    let spec = s(&f[3]);
    let target =
        rust_stdlib::net::url::parse("http://backend.example:8080/base?x=1").expect("target");
    let out = Arc::new(Mutex::new(String::new()));
    let mut rp: ReverseProxy = match mode.as_str() {
        "director" => ReverseProxy::single_host(target.clone()),
        _ => {
            let t = target.clone();
            ReverseProxy {
                rewrite: Some(Arc::new(move |pr| {
                    pr.set_url(&t);
                    pr.set_x_forwarded();
                })),
                ..ReverseProxy::default()
            }
        }
    };
    rp.error_log = Some(Arc::new(rust_stdlib::log::Logger::new(io::sink(), "", 0)));
    rp.transport = Some(Arc::new(Capture {
        spec,
        out: out.clone(),
    }));
    let Ok(mut req) = read_request(&BufioReader::new(Cursor::new(raw))) else {
        return "parse-error".into();
    };
    req.remote_addr = remote;
    let mut rec = rust_stdlib::net::http::httptest::ResponseRecorder::new();
    rp.serve_http(&mut rec, &mut req);
    let res = rec.result();
    let rb = res
        .body
        .as_ref()
        .map(|b| b.read_all().unwrap_or_default())
        .unwrap_or_default();
    let th = res
        .trailer
        .get()
        .map(|t| header_text(&t))
        .unwrap_or_default();
    let captured = out.lock().expect("capture").clone();
    hex(format!(
        "{}\n{}\n{}\n{}\n{}",
        captured,
        res.status_code,
        header_text(&res.header),
        s(&rb),
        th
    ))
}

/// CrossOriginProtection over generated configurations and requests.
fn cors_op(f: &[Vec<u8>]) -> String {
    let cop = http::CrossOriginProtection::new();
    let mut res: Vec<String> = Vec::new();
    for line in s(&f[0]).split('\n') {
        if line.is_empty() {
            continue;
        }
        let p: Vec<&str> = line.split('\t').collect();
        match p[0] {
            "t" => {
                if let Err(e) = cop.add_trusted_origin(p[1]) {
                    res.push(hex(format!("trusted-err:{e}")));
                }
            }
            "b" => {
                if cop.add_insecure_bypass_pattern(p[1]).is_err() {
                    res.push(hex("bypass-panic"));
                }
            }
            "d" => cop.set_deny_handler(Some(http::handler_func(|w, _| w.write_header(418)))),
            _ => {}
        }
    }
    let h = cop.handler(http::handler_func(|w, _| {
        let _ = w.write_string("ok");
    }));
    for raw in f[1].split(|&b| b == 1) {
        let mut raw = raw.to_vec();
        raw.extend_from_slice(b"\r\n\r\n");
        let Ok(mut req) = read_request(&BufioReader::new(Cursor::new(raw))) else {
            res.push(hex("parse-error"));
            continue;
        };
        let (code, _, body) = serve_recorded(&*h, &mut req);
        res.push(hex(format!("{}\0{}", code, s(&body))));
    }
    res.join(" ")
}

/// A client against two scripted servers (see `redirectOp` in the oracle).
fn redirect_op(f: &[Vec<u8>]) -> String {
    use rust_stdlib::net::http::client::Client;
    use std::collections::HashMap;
    struct Spec {
        status: u16,
        headers: Vec<(String, String)>,
        body: String,
    }
    let mut scripts: HashMap<String, HashMap<String, Spec>> = HashMap::new();
    for line in s(&f[0]).split('\n') {
        if line.is_empty() {
            continue;
        }
        let p: Vec<&str> = line.split('\t').collect();
        let mut headers = Vec::new();
        if !p[3].is_empty() {
            for h in p[3].split('\u{2}') {
                let (k, v) = h.split_once('=').unwrap_or((h, ""));
                headers.push((k.to_owned(), v.to_owned()));
            }
        }
        scripts.entry(p[0].to_owned()).or_default().insert(
            p[1].to_owned(),
            Spec {
                status: p[2].parse().unwrap_or(0),
                headers,
                body: p[4].to_owned(),
            },
        );
    }
    let scripts = Arc::new(scripts);
    let log = Arc::new(Mutex::new(Vec::<String>::new()));
    let bases = Arc::new(Mutex::new((String::new(), String::new())));
    let mk = |name: &'static str, addr: &'static str| {
        let (scripts, log, bases) = (scripts.clone(), log.clone(), bases.clone());
        let server = http::server::Server {
            handler: Some(http::handler_func(move |w, r| {
                let body = r
                    .body
                    .as_ref()
                    .map(|b| b.read_all().unwrap_or_default())
                    .unwrap_or_default();
                let mut h = r.header.clone();
                h.del("Accept-Encoding");
                let hb = header_text(&h);
                log.lock().expect("log").push(format!(
                    "{} {} {} host={} body={} hdr={}",
                    name,
                    r.method,
                    r.request_uri,
                    r.host,
                    go_quote(&body),
                    go_quote(hb.as_bytes())
                ));
                let (ba, bb) = bases.lock().expect("bases").clone();
                let (pa, pb) = (
                    ba.rsplit(':').next().unwrap_or("").to_owned(),
                    bb.rsplit(':').next().unwrap_or("").to_owned(),
                );
                let sp = scripts.get(name).and_then(|m| m.get(&r.url.path));
                let (status, headers, body) = match sp {
                    Some(sp) => (sp.status, sp.headers.clone(), sp.body.clone()),
                    None => (404, Vec::new(), "nf".to_owned()),
                };
                for (k, v) in headers {
                    w.header().add(
                        &k,
                        &v.replace("{A}", &ba)
                            .replace("{B}", &bb)
                            .replace("{PORTA}", &pa)
                            .replace("{PORTB}", &pb),
                    );
                }
                w.write_header(status);
                let _ = w.write_string(&body);
            })),
            error_log: Some(Arc::new(rust_stdlib::log::Logger::new(io::sink(), "", 0))),
            ..http::server::Server::default()
        };
        let ln = rust_stdlib::net::listen("tcp", addr).expect("listen");
        let port = ln
            .addr()
            .expect("addr")
            .to_string()
            .rsplit(':')
            .next()
            .unwrap_or("")
            .to_owned();
        let srv = server.clone();
        let t = std::thread::spawn(move || {
            let _ = srv.serve(ln);
        });
        (server, port, t)
    };
    let (sa, port_a, ta) = mk("A", "127.0.0.1:0");
    let (sb, port_b, tb) = mk("B", "[::1]:0");
    let base_a = format!("http://127.0.0.1:{port_a}");
    let base_b = format!("http://[::1]:{port_b}");
    *bases.lock().expect("bases") = (base_a.clone(), base_b.clone());
    let norm = |t: &str| {
        t.replace(&format!("127.0.0.1:{port_a}"), "A")
            .replace(&format!("[::1]:{port_b}"), "B")
    };
    let mut client = Client::default();
    let mut method = "GET".to_owned();
    let mut req_body: Option<http::RequestBody> = None;
    let mut hdrs: Vec<(String, String)> = Vec::new();
    for line in s(&f[1]).split('\n') {
        match line {
            "jar" => client.jar = Some(Arc::new(http::cookiejar::Jar::new(None).expect("jar"))),
            "check=none" => {
                client.check_redirect =
                    Some(Arc::new(|_, _| Err(Box::new(http::ERR_USE_LAST_RESPONSE))))
            }
            "check=err3" => {
                client.check_redirect = Some(Arc::new(|_, via| {
                    if via.len() >= 3 {
                        return Err("custom stop".into());
                    }
                    Ok(())
                }))
            }
            l if l.starts_with("method=") => method = l["method=".len()..].to_owned(),
            l if l.starts_with("body=") => req_body = Some(l["body=".len()..].into()),
            l if l.starts_with("hdr=") => {
                let (k, v) = l["hdr=".len()..]
                    .split_once(':')
                    .unwrap_or((&l["hdr=".len()..], ""));
                hdrs.push((k.to_owned(), v.to_owned()));
            }
            _ => {}
        }
    }
    let start = s(&f[2]).replace("{A}", &base_a).replace("{B}", &base_b);
    let result = match Request::new(&method, &start).map(|r| match req_body {
        Some(b) => r.with_body(b),
        None => r,
    }) {
        Err(e) => format!("NEWREQ {e}"),
        Ok(mut req) => {
            for (k, v) in &hdrs {
                req.header.add(k, v);
            }
            match client.do_request(req) {
                Err(e) => format!("ERR {}", norm(&e.to_string())),
                Ok(resp) => {
                    let body = resp
                        .body
                        .as_ref()
                        .map(|b| b.read_all().unwrap_or_default())
                        .unwrap_or_default();
                    if let Some(b) = &resp.body {
                        let _ = b.close();
                    }
                    format!(
                        "OK {} {} loc={}",
                        resp.status_code,
                        go_quote(&body),
                        go_quote(norm(resp.header.get("Location").unwrap_or("")).as_bytes())
                    )
                }
            }
        }
    };
    let _ = sa.close();
    let _ = sb.close();
    let _ = ta.join();
    let _ = tb.join();
    let transcript = log.lock().expect("log").join("\n");
    hex(format!("{}\n{}", norm(&transcript), result))
}

fn go_quote(b: &[u8]) -> String {
    rust_stdlib::strconv::quote(b)
}

fn handle(line: &str) -> String {
    let (mode, rest) = line.split_once(':').unwrap_or((line, ""));
    let f: Vec<Vec<u8>> = if rest.is_empty() {
        Vec::new()
    } else {
        rest.split(',').map(from_hex).collect()
    };
    match mode {
        "M" => mux_table(&f),
        "K" => cookie_op(&f),
        "Q" => request_op(&f),
        "P" => response_op(&f),
        "D" => date_op(&f),
        "V" => server_op(&f),
        "F" => file_op(&f),
        "X" => cors_op(&f),
        "Y" => proxy_op(&f),
        "Z" => conn_op(&f),
        "L" => redirect_op(&f),
        _ => "UNKNOWN".into(),
    }
}

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    let lines: Vec<String> = stdin
        .lock()
        .lines()
        .map(|l| l.expect("stdin line"))
        .filter(|l| !l.is_empty())
        .collect();
    // Records are independent: run them on a pool, print in order.
    let results: Vec<Mutex<String>> = lines.iter().map(|_| Mutex::new(String::new())).collect();
    let next = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..48 {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if i >= lines.len() {
                    break;
                }
                let line = &lines[i];
                let result = std::panic::catch_unwind(|| handle(line))
                    .unwrap_or_else(|_| "PANIC".to_owned());
                *results[i].lock().expect("result") = result;
            });
        }
    });
    for r in &results {
        writeln!(out, "{}", r.lock().expect("result")).expect("stdout");
    }
    let _: Option<Arc<dyn Handler>> = None;
}
