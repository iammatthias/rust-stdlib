//! Used by `tools/cgi_check.py` for the CGI and FastCGI Go differentials.
//! See `tools/cgi_oracle.go` for the modes and the output formats.
use rust_stdlib::log::Logger;
use rust_stdlib::net::http::cgi;
use rust_stdlib::net::http::fcgi;
use rust_stdlib::net::http::request::Request;
use rust_stdlib::net::http::tlsstate::ConnectionState;
use rust_stdlib::net::http::{handler_func, Handler, Header, RequestBody, ResponseWriter};
use std::collections::HashMap;
use std::io::{self, BufRead, Read, Write};
use std::sync::{Arc, Mutex};

fn unhex_bytes(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn unhex(s: &str) -> String {
    String::from_utf8_lossy(&unhex_bytes(s)).into_owned()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn header_text(h: &Header) -> String {
    h.0.iter()
        .map(|(k, v)| format!("{k}:{}", v.join("|")))
        .collect::<Vec<_>>()
        .join(",")
}

fn map_mode(line: &str) -> String {
    let mut params = HashMap::new();
    let rest = line.trim_start_matches('M').trim();
    if !rest.is_empty() && rest != "-" {
        for kv in rest.split('|') {
            let kv = unhex(kv);
            let (k, v) = kv.split_once('=').unwrap_or((&kv, ""));
            params.insert(k.to_owned(), v.to_owned());
        }
    }
    match cgi::request_from_map(&params) {
        Err(e) => format!("err {e}"),
        Ok(r) => format!(
            "ok method={} proto={} {}.{} host={} url={} clen={} close={} tls={} remote={} trailer={} hdr={}",
            r.method,
            r.proto,
            r.proto_major,
            r.proto_minor,
            r.host,
            r.url,
            r.content_length,
            r.close,
            r.tls.is_some(),
            r.remote_addr,
            r.trailer.get().is_some_and(|t| t.0.is_empty()),
            header_text(&r.header)
        ),
    }
}

/// A minimal recorder that snapshots the header when the status is written.
struct Recorder {
    code: u16,
    header: Header,
    snapshot: Header,
    body: Vec<u8>,
    wrote: bool,
}

impl std::io::Write for Recorder {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if !self.wrote {
            self.write_header(200);
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
        if self.wrote {
            return;
        }
        self.wrote = true;
        self.code = code;
        self.snapshot = self.header.clone();
    }
}

/// A logger that appends to a shared buffer.
#[derive(Clone)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl Write for SharedBuf {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn host_mode(line: &str) -> String {
    let mut f: HashMap<&str, &str> = HashMap::new();
    for kv in line.trim_start_matches('H').split_whitespace() {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        f.insert(k, v);
    }
    let get = |k: &str| f.get(k).copied().unwrap_or("");
    let body = unhex_bytes(get("body"));
    let url = format!("http://{}{}", unhex(get("host")), unhex(get("uri")));
    let rbody = (!body.is_empty()).then(|| RequestBody::Bytes(body.clone()));
    let mut req = match Request::new(&unhex(get("method")), &url).map(|r| match rbody {
        Some(b) => r.with_body(b),
        None => r,
    }) {
        Ok(r) => r,
        Err(e) => return format!("newrequest {e}"),
    };
    req.host = unhex(get("host"));
    req.remote_addr = unhex(get("remote"));
    if get("tls") == "1" {
        req.tls = Some(Arc::new(ConnectionState {
            handshake_complete: true,
            ..ConnectionState::default()
        }));
    }
    let list = |k: &str| -> Vec<String> {
        let v = get(k);
        if v.is_empty() || v == "-" {
            Vec::new()
        } else {
            v.split('|').map(unhex).collect()
        }
    };
    for kv in list("hdr") {
        let (k, v) = kv.split_once(':').unwrap_or((&kv, ""));
        req.header.add(k, v);
    }
    if get("te") == "chunked" {
        req.transfer_encoding = vec!["chunked".into()];
    }
    let logbuf = SharedBuf(Arc::default());
    let errbuf = SharedBuf(Arc::default());
    let dir = if !get("dir").is_empty() && get("dir") != "-" {
        unhex(get("dir"))
    } else {
        String::new()
    };
    let mut h = cgi::Handler {
        path: if get("path").is_empty() {
            std::env::var("CGI_FIXTURE").unwrap_or_default()
        } else {
            unhex(get("path"))
        },
        root: unhex(get("root")),
        dir,
        env: list("envx"),
        inherit_env: list("inherit"),
        args: list("args"),
        logger: Some(Arc::new(Logger::new(logbuf.clone(), "", 0))),
        stderr: Some(Arc::new(Mutex::new(errbuf.clone()))),
        ..cgi::Handler::default()
    };
    if get("loc") == "1" {
        h.path_location_handler = Some(handler_func(|w, r| {
            let _ = w.write(
                format!(
                    "REDIRECT {} {} host={} remote={} tls={} hdrs={}",
                    r.method,
                    r.url,
                    r.host,
                    r.remote_addr,
                    r.tls.is_some(),
                    r.header.0.len()
                )
                .as_bytes(),
            );
        }));
    }
    let mut rec = Recorder {
        code: 0,
        header: Header::new(),
        snapshot: Header::new(),
        body: Vec::new(),
        wrote: false,
    };
    h.serve_http(&mut rec, &mut req);
    if !rec.wrote {
        rec.write_header(200);
    }
    let log = logbuf.0.lock().unwrap().clone();
    let err = errbuf.0.lock().unwrap().clone();
    format!(
        "code={} hdr={} body={} log={} stderr={}",
        rec.code,
        header_text(&rec.snapshot),
        hex(&rec.body),
        hex(&log),
        hex(&err)
    )
}

/// The handler served by the CGI child and the FastCGI server.
fn app_handler(w: &mut dyn ResponseWriter, r: &mut Request) {
    w.header().set("Date", "Thu, 01 Jan 2026 00:00:00 GMT");
    let q = r.url.query();
    let get = |k: &str| q.get(k).to_owned();
    let mode = get("mode");
    match mode.as_str() {
        "echo" | "" => {
            // Like io.ReadAll: the bytes read before an error are kept.
            let mut body = Vec::new();
            let mut err = "nil".to_owned();
            if let Some(b) = r.body.as_mut() {
                let mut buf = [0u8; 4096];
                loop {
                    match b.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => body.extend_from_slice(&buf[..n]),
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) => {
                            err = e.to_string();
                            break;
                        }
                    }
                }
            }
            w.header().set("Content-Type", "text/plain");
            let out = format!(
                "method={}\nurl={}\nproto={} {}.{}\nhost={}\nremote={}\ntls={}\nclen={}\nclose={}\nhdr={}\nbody={}\nbodyerr={}\n",
                r.method,
                r.url,
                r.proto,
                r.proto_major,
                r.proto_minor,
                r.host,
                r.remote_addr,
                r.tls.is_some(),
                r.content_length,
                r.close,
                header_text(&r.header),
                hex(&body),
                err
            );
            let env = fcgi::process_env(r).unwrap_or_default();
            let mut keys: Vec<&String> = env.keys().collect();
            keys.sort();
            // One write per line, as the Go handler's Fprintf calls are.
            let _ = w.write(out.as_bytes());
            let _ = w.write(format!("env={}\n", env.len()).as_bytes());
            for k in keys {
                let _ = w.write(format!("{k}={}\n", env[k]).as_bytes());
            }
        }
        "status" => {
            let code: u16 = get("code").parse().unwrap_or(0);
            if !get("ctype").is_empty() {
                w.header().set("Content-Type", &get("ctype"));
            }
            for h in q.0.get("h").cloned().unwrap_or_default() {
                let (k, v) = h.split_once('=').unwrap_or((&h, ""));
                w.header().add(k, v);
            }
            w.write_header(code);
            let n: usize = get("n").parse().unwrap_or(0);
            if n > 0 {
                let _ = w.write(&vec![b'x'; n]);
            }
        }
        "chunks" => {
            for c in q.0.get("c").cloned().unwrap_or_default() {
                let _ = w.write(c.as_bytes());
                if get("flush") == "1" {
                    if let Some(f) = w.flusher() {
                        f.flush();
                    }
                }
            }
        }
        "big" => {
            let n: usize = get("n").parse().unwrap_or(0);
            w.header().set("Content-Type", "application/octet-stream");
            let buf: Vec<u8> = (0..n).map(|i| b'a' + (i % 26) as u8).collect();
            let _ = w.write(&buf);
        }
        "sniff" => {
            let _ = w.write(&unhex_bytes(&get("data")));
        }
        "twice" => {
            w.write_header(201);
            w.write_header(202);
            let _ = w.write(b"twice");
        }
        "nothing" => {}
        "readn" => {
            let n: usize = get("n").parse().unwrap_or(0);
            let mut buf = vec![0u8; n];
            let mut got = 0;
            let mut err = "<nil>".to_owned();
            if let Some(b) = r.body.as_mut() {
                while got < n {
                    match b.read(&mut buf[got..]) {
                        Ok(0) => {
                            err = if got == 0 { "EOF" } else { "unexpected EOF" }.to_owned();
                            break;
                        }
                        Ok(m) => got += m,
                        Err(e) => {
                            err = e.to_string();
                            break;
                        }
                    }
                }
            }
            let _ = w.write(format!("got={got} err={err}").as_bytes());
        }
        "notmod" => {
            w.header().set("Content-Type", "text/plain");
            w.header().set("Content-Length", "5");
            w.write_header(304);
        }
        _ => {}
    }
}

fn lines(mode: &str) -> io::Result<()> {
    let stdin = io::stdin();
    let mut out = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        let line = line.trim().to_owned();
        if line.is_empty() {
            continue;
        }
        let l2 = line.clone();
        let m = mode.to_owned();
        let text = std::panic::catch_unwind(move || {
            if m == "map" {
                map_mode(&l2)
            } else {
                host_mode(&l2)
            }
        })
        .unwrap_or_else(|_| "rust-panic".to_owned());
        writeln!(out, "{text}")?;
        out.flush()?;
    }
    Ok(())
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    match mode.as_str() {
        "map" | "host" => lines(&mode).expect("io"),
        "child" => {
            let h = handler_func(app_handler);
            if let Err(e) = cgi::serve(Some(&*h)) {
                eprintln!("serve: {e}");
                std::process::exit(1);
            }
        }
        "fcgi" => {
            let l = rust_stdlib::net::listen("tcp", "127.0.0.1:0").expect("listen");
            let addr = l.addr().expect("addr").to_string();
            let port = addr.rsplit(':').next().unwrap_or("");
            println!("PORT {port}");
            let _ = io::stdout().flush();
            let _ = fcgi::serve(Some(&*l), Some(handler_func(app_handler)));
        }
        "fcgistdin" => {
            println!("READY");
            let _ = io::stdout().flush();
            match fcgi::serve(None, Some(handler_func(app_handler))) {
                Err(e) => println!("ERR {e}"),
                Ok(()) => println!("ERR <nil>"),
            }
        }
        _ => {
            eprintln!("usage: cgi_probe map|host|child|fcgi|fcgistdin");
            std::process::exit(2);
        }
    }
}
