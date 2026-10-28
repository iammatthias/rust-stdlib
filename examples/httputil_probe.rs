//! Line protocol used by `tools/httputil_check.py` for Go differential checks.
//! Requests are `MODE:f1,f2,...` with hex fields; responses match
//! `tools/httputil_oracle.go`.
use rust_stdlib::net::{
    http::{
        client::RoundTripper,
        detect_content_type,
        header::{BoxError, Header},
        httptest,
        httputil::{
            dump_request, dump_request_out, dump_response, ChunkedReader, ChunkedWriter,
            ClientConn, ConnError, ReverseProxy, ServerConn,
        },
        Body, NoBody, Request, RequestBody, Response,
    },
    textproto::trim_string,
    url, AddrRef, Conn, NetError,
};
use rust_stdlib::time::Time;
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
fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("UTF-8 field")
}

/// A header list: `name\0value` items joined by `\1`, values trimmed of
/// space and tab.
fn fields(raw: &[u8]) -> Vec<(String, String)> {
    if raw.is_empty() {
        return Vec::new();
    }
    raw.split(|&b| b == 1)
        .map(|item| {
            let at = item.iter().position(|&b| b == 0).unwrap_or(item.len());
            let value = item.get(at + 1..).unwrap_or_default();
            (
                text(&item[..at]),
                text(value).trim_matches([' ', '\t']).to_owned(),
            )
        })
        .collect()
}

/// Separates Host and Transfer-Encoding from the remaining header map.
fn split(list: &[(String, String)]) -> (Option<String>, Vec<String>, Header) {
    let mut host = None;
    let mut te = Vec::new();
    let mut header = Header::new();
    for (name, value) in list {
        match name.to_ascii_lowercase().as_str() {
            "host" => {
                host.get_or_insert_with(|| value.clone());
            }
            "transfer-encoding" => te.push(value.clone()),
            _ => header.add(name, value),
        }
    }
    (host, te, header)
}

fn dump(result: Result<Vec<u8>, BoxError>) -> String {
    result.map_or_else(|_| "ERR".into(), hex)
}

fn header_lines(header: &Header, skip_te: bool) -> String {
    let mut lines = Vec::new();
    for (key, values) in &header.0 {
        if skip_te && key == "Transfer-Encoding" {
            continue;
        }
        // Go's "do not send" sentinel; the oracle omits it.
        if !skip_te && key == "User-Agent" && values.len() == 1 && values[0].is_empty() {
            continue;
        }
        for value in values {
            lines.push(format!("{key}: {value}"));
        }
    }
    lines.join("\n")
}

/// `http.NewRequest(method, "http://"+host+target, body)` with the fields'
/// Transfer-Encoding; a `close` connection token sets `close`.
fn client_request(f: &[Vec<u8>]) -> Option<Request> {
    let (host, te, header) = split(&fields(&f[2]));
    let url = format!("http://{}{}", host.unwrap_or_default(), text(&f[1]));
    let mut req = Request::new(&text(&f[0]), &url)
        .ok()?
        .with_body(RequestBody::Bytes(f[3].clone()));
    for (key, values) in header.0 {
        req.header.0.insert(key, values);
    }
    req.transfer_encoding = te;
    for value in req.header.values("Connection") {
        if value
            .split(',')
            .any(|t| trim_string(t).eq_ignore_ascii_case("close"))
        {
            req.close = true;
        }
    }
    Some(req)
}

/// An in-memory connection: reads from the input, records writes.
struct Fake {
    input: Mutex<Cursor<Vec<u8>>>,
    output: Mutex<Vec<u8>>,
}
impl Conn for Fake {
    fn read(&self, b: &mut [u8]) -> Result<usize, NetError> {
        Ok(self.input.lock().unwrap().read(b).expect("cursor read"))
    }
    fn write(&self, b: &[u8]) -> Result<usize, NetError> {
        self.output.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn close(&self) -> Result<(), NetError> {
        Ok(())
    }
    fn local_addr(&self) -> Option<AddrRef> {
        None
    }
    fn remote_addr(&self) -> Option<AddrRef> {
        None
    }
    fn set_deadline(&self, _: &Time) -> Result<(), NetError> {
        Ok(())
    }
    fn set_read_deadline(&self, _: &Time) -> Result<(), NetError> {
        Ok(())
    }
    fn set_write_deadline(&self, _: &Time) -> Result<(), NetError> {
        Ok(())
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
fn fake(input: &[u8]) -> Box<dyn Conn> {
    Box::new(Fake {
        input: Mutex::new(Cursor::new(input.to_vec())),
        output: Mutex::new(Vec::new()),
    })
}
fn written(hijacked: Option<Arc<dyn Conn>>) -> Vec<u8> {
    hijacked
        .and_then(|c| {
            c.as_any()
                .downcast_ref::<Fake>()
                .map(|f| f.output.lock().unwrap().clone())
        })
        .unwrap_or_default()
}
fn class(error: Option<&ConnError>) -> &'static str {
    match error {
        None => "ok",
        Some(ConnError::PersistEof) => "persist",
        Some(ConnError::Eof) => "eof",
        Some(_) => "err",
    }
}

fn server_conn(data: &[u8]) -> String {
    let conn = ServerConn::new(fake(data), None);
    let mut parts = Vec::new();
    for _ in 0..8 {
        let (request, error) = conn.read();
        if let Some(request) = request {
            let body = request
                .body
                .as_ref()
                .map(|b| b.read_all().unwrap_or_default())
                .unwrap_or_default();
            parts.push(format!(
                "REQ {} {} host={} {} body={}",
                request.method,
                request.request_uri,
                request.host,
                hex(header_lines(&request.header, true)),
                hex(&body)
            ));
            let mut response = Response {
                status_code: 200,
                proto_major: 1,
                proto_minor: 1,
                body: Some(Body::from_bytes(body.clone())),
                content_length: body.len() as i64,
                ..Response::default()
            };
            response.header.set(
                "X-Echo",
                &format!("{} {}", request.method, request.request_uri),
            );
            let written = conn.write(&request, &response).err();
            parts.push(format!("W {}", class(written.as_ref())));
        }
        parts.push(format!("E {} {}", class(error.as_ref()), conn.pending()));
        if error.is_some() {
            break;
        }
    }
    let output = written(conn.hijack().0);
    format!("{},{}", hex(parts.join("\n")), hex(output))
}

fn client_conn(f: &[Vec<u8>]) -> String {
    let conn = ClientConn::new(fake(&f[f.len() - 1]), None);
    let mut parts = Vec::new();
    let mut i = 0;
    while i + 4 < f.len() {
        let request = client_request(&f[i..i + 4]).expect("generated request is valid");
        let (response, error) = conn.do_request(&request);
        if let Some(response) = response {
            let body = response.body.as_ref().map(Body::read_all);
            let (body, berr) = match body {
                Some(Ok(b)) => (b, "ok"),
                Some(Err(_)) => (Vec::new(), "err"),
                None => (Vec::new(), "ok"),
            };
            parts.push(format!(
                "RESP {} {} body={} {berr}",
                response.status_code,
                hex(header_lines(&response.header, true)),
                hex(&body),
            ));
        }
        parts.push(format!("E {} {}", class(error.as_ref()), conn.pending()));
        if error.is_some() {
            break;
        }
        i += 4;
    }
    let output = written(conn.hijack().0);
    format!("{},{}", hex(parts.join("\n")), hex(output))
}

fn proto(f: &[u8]) -> (i32, i32) {
    text(f).split_once('.').map_or((1, 1), |(a, b)| {
        (a.parse().expect("major"), b.parse().expect("minor"))
    })
}

/// Captures the outbound request in place of a network transport.
struct Capture {
    out: Arc<Mutex<Option<Request>>>,
    header: Header,
}
impl RoundTripper for Capture {
    fn round_trip(&self, r: &Request) -> Result<Response, BoxError> {
        *self.out.lock().unwrap() = Some(r.clone());
        Ok(Response {
            status_code: 200,
            proto_major: 1,
            proto_minor: 1,
            header: self.header.clone(),
            body: Some(Body::from(NoBody)),
            request: Some(Box::new(r.clone())),
            ..Response::default()
        })
    }
}

fn proxy(f: &[Vec<u8>]) -> String {
    let (mode, method, target) = (text(&f[0]), text(&f[1]), text(&f[2]));
    let (host, te, mut header) = split(&fields(&f[3]));
    let (remote, backend) = (text(&f[4]), text(&f[5]));
    let (_, rte, mut resp_header) = split(&fields(&f[6]));
    for v in &rte {
        resp_header.add("Transfer-Encoding", v);
    }
    for v in &te {
        header.add("Transfer-Encoding", v);
    }
    let mut req = httptest::request(&method, &target, None).expect("generated request");
    req.header = header;
    req.host = host.unwrap_or_default();
    req.remote_addr = remote;
    let Ok(target_url) = url::parse(&backend) else {
        return "BADTARGET".into();
    };
    let out: Arc<Mutex<Option<Request>>> = Arc::default();
    let failed = Arc::new(Mutex::new(false));
    let flag = failed.clone();
    let mut rp = match mode.as_str() {
        "director" => ReverseProxy::single_host(target_url),
        "rewrite" => ReverseProxy {
            rewrite: Some(Arc::new(move |pr| {
                pr.set_url(&target_url);
                pr.set_x_forwarded();
            })),
            ..ReverseProxy::default()
        },
        "rewrite-host" => ReverseProxy {
            rewrite: Some(Arc::new(move |pr| {
                pr.set_url(&target_url);
                pr.out.host = pr.in_.host.clone();
            })),
            ..ReverseProxy::default()
        },
        "rewrite-append" => ReverseProxy {
            rewrite: Some(Arc::new(move |pr| {
                pr.set_url(&target_url);
                let prior = pr.in_.header.0.get("X-Forwarded-For").cloned();
                match prior {
                    Some(values) => {
                        pr.out.header.0.insert("X-Forwarded-For".into(), values);
                    }
                    None => {
                        pr.out.header.0.remove("X-Forwarded-For");
                    }
                }
                pr.set_x_forwarded();
            })),
            ..ReverseProxy::default()
        },
        _ => return "BADMODE".into(),
    };
    rp.transport = Some(Arc::new(Capture {
        out: out.clone(),
        header: resp_header,
    }));
    rp.error_handler = Some(Arc::new(move |_, _, _| {
        *flag.lock().unwrap() = true;
    }));
    let mut recorder = httptest::ResponseRecorder::new();
    rust_stdlib::net::http::Handler::serve_http(&rp, &mut recorder, &mut req);
    let out = out.lock().unwrap().take();
    let Some(out) = out else {
        return "ERR".into();
    };
    if *failed.lock().unwrap() {
        return "ERR".into();
    }
    // The oracle compares the recorded result without Content-Length.
    let mut result = recorder.result().header;
    result.del("Content-Length");
    hex([
        out.method.clone(),
        out.url.scheme.clone(),
        out.url.host.clone(),
        out.url.request_uri(),
        out.host.clone(),
        header_lines(&out.header, false),
        header_lines(&result, false),
    ]
    .join("|"))
}

fn handle(mode: &str, f: &[Vec<u8>]) -> String {
    match mode {
        "Q" => {
            let (host, te, header) = split(&fields(&f[2]));
            let (major, minor) = proto(&f[5]);
            let mut req = Request::default();
            req.method = text(&f[0]);
            req.request_uri = text(&f[1]);
            req.proto_major = major;
            req.proto_minor = minor;
            req.host = host.unwrap_or_default();
            req.header = header;
            req.transfer_encoding = te;
            req.body = Some(Body::from_bytes(f[3].clone()));
            dump(dump_request(&mut req, f[4] == b"1"))
        }
        "O" => match client_request(f) {
            Some(mut req) => dump(dump_request_out(&mut req, f[4] == b"1")),
            None => "ERR".into(),
        },
        "X" | "Y" => match client_request(f) {
            Some(req) => {
                let mut buf = Vec::new();
                let result = if mode == "X" {
                    req.write(&mut buf)
                } else {
                    req.write_proxy(&mut buf)
                };
                dump(result.map(|()| buf))
            }
            None => "ERR".into(),
        },
        "Z" => server_conn(&f[0]),
        "K" => client_conn(f),
        "R" => {
            let list = fields(&f[1]);
            let (_, te, mut header) = split(&list);
            for (name, value) in &list {
                if name.eq_ignore_ascii_case("host") {
                    header.add(name, value);
                }
            }
            let (major, minor) = proto(&f[4]);
            let content_length = if te.first().is_some_and(|t| t == "chunked") {
                -1
            } else {
                let value = header.get("Content-Length").unwrap_or("");
                let trimmed = value.trim_matches([' ', '\t', '\r', '\n']);
                match trimmed.parse::<u64>() {
                    Ok(n) if !value.is_empty() && n < 1 << 63 => n as i64,
                    _ => f[2].len() as i64,
                }
            };
            let mut resp = Response {
                status_code: text(&f[0]).parse().expect("status"),
                proto_major: major,
                proto_minor: minor,
                header,
                transfer_encoding: te,
                body: Some(Body::from_bytes(f[2].clone())),
                content_length,
                ..Response::default()
            };
            dump(dump_response(&mut resp, f[3] == b"1"))
        }
        "C" => {
            let mut out = Vec::new();
            let message = match ChunkedReader::new(&f[0][..]).read_to_end(&mut out) {
                Ok(_) => String::new(),
                Err(e) => e.to_string(),
            };
            format!("{},{}", hex(out), hex(message))
        }
        "W" => {
            let mut writer = ChunkedWriter::new(Vec::new());
            for chunk in f {
                writer.write_all(chunk).expect("in-memory write");
            }
            writer.close().expect("in-memory write");
            hex(writer.into_inner())
        }
        "S" => hex(detect_content_type(&f[0])),
        "P" => proxy(f),
        _ => "BADMODE".into(),
    }
}

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line?;
        let (mode, rest) = line.split_once(':').expect("MODE:fields");
        let fields: Vec<Vec<u8>> = rest.split(',').map(from_hex).collect();
        writeln!(out, "{}", handle(mode, &fields))?;
    }
    out.flush()
}
