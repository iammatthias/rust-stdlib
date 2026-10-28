//! Line protocol used by `tools/pprof_check.py` for Go differential checks.
//! See `tools/pprof_oracle.go` for the request and response formats.
use rust_stdlib::net::http::pprof;
use rust_stdlib::net::http::Request;
use rust_stdlib::net::http::{Header, ResponseWriter};
use std::io::{self, BufRead, Write};

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

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
        if !self.wrote {
            self.wrote = true;
            self.code = code;
            self.snapshot = self.header.clone();
        }
    }
}

fn handle(line: &str) -> String {
    let f: Vec<&str> = line.split_whitespace().collect();
    let (endpoint, method) = (f[1], f[2]);
    let uri = String::from_utf8_lossy(&unhex(f[3])).into_owned();
    let body = unhex(f[4]);
    let mut req = match Request::new(method, &format!("http://example.com{uri}"))
        .map(|r| r.with_body(body.clone()))
    {
        Ok(r) => r,
        Err(e) => return format!("newrequest {e}"),
    };
    if method == "POST" && !body.is_empty() {
        req.header
            .set("Content-Type", "application/x-www-form-urlencoded");
    }
    let mut rec = Recorder {
        code: 0,
        header: Header::new(),
        snapshot: Header::new(),
        body: Vec::new(),
        wrote: false,
    };
    match endpoint {
        "cmdline" => pprof::cmdline(&mut rec, &mut req),
        "index" => pprof::index(&mut rec, &mut req),
        "symbol" => pprof::symbol(&mut rec, &mut req),
        "profile" => pprof::profile(&mut rec, &mut req),
        "trace" => pprof::trace(&mut rec, &mut req),
        e if e.starts_with("handler:") => {
            pprof::handler(&e["handler:".len()..]).serve_http(&mut rec, &mut req)
        }
        other => panic!("bad endpoint {other}"),
    }
    if !rec.wrote {
        rec.write_header(200);
    }
    let hs: Vec<String> = rec
        .snapshot
        .0
        .iter()
        .map(|(k, v)| format!("{k}:{}", v.join("|")))
        .collect();
    format!(
        "code={} hdr={} body={}",
        rec.code,
        hs.join(","),
        hex(&rec.body)
    )
}

use rust_stdlib::net::http::Handler;

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut out = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        let line = line.trim().to_owned();
        if line.is_empty() {
            continue;
        }
        let text =
            std::panic::catch_unwind(|| handle(&line)).unwrap_or_else(|_| "rust-panic".to_owned());
        writeln!(out, "{text}")?;
        out.flush()?;
    }
    Ok(())
}
