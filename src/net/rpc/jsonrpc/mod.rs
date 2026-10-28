//! Go's `net/rpc/jsonrpc`: a JSON-RPC 1.0 client and server codec for the rpc
//! package. For JSON-RPC 2.0 support, see third-party packages.
//!
//! The arguments and replies are [`reflect::Value`](crate::reflect::Value)s
//! encoded as `encoding/json` encodes them (struct fields follow their `json`
//! tags; the `json` tag of a derived type is written
//! `#[reflect("json:\"name,omitempty\"")]`). A request is
//! `{"method":M,"params":[P],"id":N}` and a response
//! `{"id":N,"result":R,"error":E}`, each followed by a newline.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};

use crate::reflect::Value;
use parse::{parse, Json, Node};

use super::{ClientCodec, Error, ReadWriteCloser, Request, Response, ServerCodec};

mod bridge;
mod parse;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The result of looking for the end of one JSON value.
enum Scan {
    Complete(usize),
    Incomplete,
    Invalid(String),
}

fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

fn quote_char(c: u8) -> String {
    match c {
        b'\'' => "'\\''".into(),
        b'"' => "'\"'".into(),
        c => crate::strconv::quote_rune(c as char).to_string(),
    }
}

/// Finds the end of the JSON value that starts at or after `from`.
fn scan_value(b: &[u8], from: usize, eof: bool) -> Scan {
    let mut i = from;
    while i < b.len() && is_space(b[i]) {
        i += 1;
    }
    if i >= b.len() {
        return Scan::Incomplete;
    }
    match b[i] {
        b'{' | b'[' => {
            let (mut depth, mut in_str, mut esc) = (0usize, false, false);
            while i < b.len() {
                let c = b[i];
                i += 1;
                if in_str {
                    if esc {
                        esc = false;
                    } else if c == b'\\' {
                        esc = true;
                    } else if c == b'"' {
                        in_str = false;
                    }
                    continue;
                }
                match c {
                    b'"' => in_str = true,
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return Scan::Complete(i);
                        }
                    }
                    _ => {}
                }
            }
            Scan::Incomplete
        }
        b'"' => {
            let (mut esc, mut j) = (false, i + 1);
            while j < b.len() {
                let c = b[j];
                j += 1;
                if esc {
                    esc = false;
                } else if c == b'\\' {
                    esc = true;
                } else if c == b'"' {
                    return Scan::Complete(j);
                }
            }
            Scan::Incomplete
        }
        b't' | b'f' | b'n' => {
            let word: &[u8] = match b[i] {
                b't' => b"true",
                b'f' => b"false",
                _ => b"null",
            };
            for (k, w) in word.iter().enumerate() {
                match b.get(i + k) {
                    Some(c) if c == w => {}
                    Some(c) => {
                        return Scan::Invalid(format!(
                            "invalid character {} in literal {} (expecting {})",
                            quote_char(*c),
                            String::from_utf8_lossy(word),
                            quote_char(*w)
                        ))
                    }
                    None => return Scan::Incomplete,
                }
            }
            Scan::Complete(i + word.len())
        }
        c if c == b'-' || c.is_ascii_digit() => {
            let mut j = i + 1;
            while j < b.len() && matches!(b[j], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-') {
                j += 1;
            }
            if j == b.len() && !eof {
                Scan::Incomplete
            } else {
                Scan::Complete(j)
            }
        }
        c => Scan::Invalid(format!(
            "invalid character {} looking for beginning of value",
            quote_char(c)
        )),
    }
}

/// A stream of JSON values (the reading half of Go's `json.Decoder`).
struct Stream {
    conn: Arc<dyn ReadWriteCloser>,
    buf: Vec<u8>,
    start: usize,
}

impl Stream {
    /// The next value's bytes; `io.EOF` at a clean end of input and
    /// `io.ErrUnexpectedEOF` in the middle of a value.
    fn read_value(&mut self) -> io::Result<Vec<u8>> {
        let mut eof = false;
        loop {
            match scan_value(&self.buf, self.start, eof) {
                Scan::Complete(end) => {
                    let v = self.buf[self.start..end].to_vec();
                    self.buf.drain(..end);
                    self.start = 0;
                    return Ok(v.iter().copied().skip_while(|&b| is_space(b)).collect());
                }
                Scan::Invalid(m) => return Err(io::Error::other(m)),
                Scan::Incomplete if eof => {
                    return Err(if self.buf[self.start..].iter().all(|&b| is_space(b)) {
                        crate::io::eof()
                    } else {
                        crate::io::Error::UnexpectedEof.into()
                    });
                }
                Scan::Incomplete => {}
            }
            let mut chunk = [0u8; 4096];
            match self.conn.read(&mut chunk) {
                Ok(0) => eof = true,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
}

/// The members of a JSON object as (key, raw value) pairs.
fn members(raw: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut i = 0;
    while i < raw.len() && is_space(raw[i]) {
        i += 1;
    }
    if raw[i..].starts_with(b"null") {
        // Decoding null into a struct changes nothing.
        return Ok(Vec::new());
    }
    if raw.get(i) != Some(&b'{') {
        let tree = parse(raw)?;
        return Err(format!(
            "json: cannot unmarshal {} into Go value of type struct",
            match tree.json {
                Json::Null => "null",
                Json::Bool(_) => "bool",
                Json::Number(_) => "number",
                Json::String(_) => "string",
                Json::Array(_) => "array",
                Json::Object(_) => "object",
            }
        ));
    }
    // Syntax first, as Go's decoder checks the whole value.
    parse(raw)?;
    i += 1;
    let mut out = Vec::new();
    loop {
        while i < raw.len() && (is_space(raw[i]) || raw[i] == b',') {
            i += 1;
        }
        if raw.get(i) == Some(&b'}') || i >= raw.len() {
            return Ok(out);
        }
        let Scan::Complete(kend) = scan_value(raw, i, true) else {
            return Err("invalid object".into());
        };
        let key = match parse(&raw[i..kend]) {
            Ok(Node {
                json: Json::String(s),
                ..
            }) => s,
            _ => return Err("invalid object key".into()),
        };
        i = kend;
        while i < raw.len() && (is_space(raw[i]) || raw[i] == b':') {
            i += 1;
        }
        let Scan::Complete(vend) = scan_value(raw, i, true) else {
            return Err("invalid object value".into());
        };
        let start = raw[i..vend]
            .iter()
            .position(|&b| !is_space(b))
            .map_or(i, |p| i + p);
        out.push((key, raw[start..vend].to_vec()));
        i = vend;
    }
}

/// The member for a struct field named `name`: an exact match, else a
/// case-insensitive one; the last duplicate wins.
fn member<'a>(m: &'a [(String, Vec<u8>)], name: &str) -> Option<&'a Vec<u8>> {
    m.iter()
        .rev()
        .find(|(k, _)| k == name)
        .or_else(|| m.iter().rev().find(|(k, _)| k.eq_ignore_ascii_case(name)))
        .map(|(_, v)| v)
}

fn is_null(raw: &[u8]) -> bool {
    raw == b"null"
}

/// `RawMessage` as the encoder writes it: compacted and HTML-escaped.
fn compact_html(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let (mut in_str, mut esc) = (false, false);
    for &c in raw {
        if in_str {
            match c {
                _ if esc => {
                    esc = false;
                    out.push(c);
                }
                b'\\' => {
                    esc = true;
                    out.push(c);
                }
                b'"' => {
                    in_str = false;
                    out.push(c);
                }
                b'<' | b'>' | b'&' => {
                    out.extend_from_slice(format!("\\u00{c:02x}").as_bytes());
                }
                _ => out.push(c),
            }
        } else if c == b'"' {
            in_str = true;
            out.push(c);
        } else if !is_space(c) {
            out.push(c);
        }
    }
    out
}

fn write_all(conn: &Arc<dyn ReadWriteCloser>, mut b: &[u8]) -> io::Result<()> {
    while !b.is_empty() {
        let n = conn.write(b)?;
        if n == 0 {
            return Err(crate::io::Error::ShortWrite.into());
        }
        b = &b[n..];
    }
    Ok(())
}

/// Go's `%v` of a decoded `any`.
fn go_v(j: &Json) -> String {
    match j {
        Json::Null => "<nil>".into(),
        Json::Bool(b) => b.to_string(),
        Json::Number(n) => crate::printf::sprintf(
            "%v",
            &[crate::printf::Value::Float64(
                n.parse::<f64>().unwrap_or(0.0),
            )],
        ),
        Json::String(s) => s.clone(),
        Json::Array(a) => format!(
            "[{}]",
            a.iter()
                .map(|n| go_v(&n.json))
                .collect::<Vec<_>>()
                .join(" ")
        ),
        Json::Object(o) => {
            let mut last: Vec<(&String, &Node)> = Vec::new();
            for (k, v) in o {
                match last.iter_mut().find(|(lk, _)| *lk == k) {
                    Some(slot) => slot.1 = v,
                    None => last.push((k, v)),
                }
            }
            last.sort_by(|a, b| a.0.cmp(b.0));
            format!(
                "map[{}]",
                last.iter()
                    .map(|(k, v)| format!("{k}:{}", go_v(&v.json)))
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        }
    }
}

fn marshal_line(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

// ---- client ----

/// The JSON-RPC client codec (Go `jsonrpc.clientCodec`).
pub struct JsonClientCodec {
    conn: Arc<dyn ReadWriteCloser>,
    stream: Mutex<Stream>,
    /// Maps request id to method name: JSON-RPC responses include the request
    /// id but not the request method, and package rpc expects both.
    pending: Mutex<HashMap<u64, String>>,
    result: Mutex<Option<Vec<u8>>>,
}

impl JsonClientCodec {
    /// Go `jsonrpc.NewClientCodec`: a new [`ClientCodec`] using JSON-RPC on
    /// `conn`.
    pub fn new<C: ReadWriteCloser + 'static>(conn: C) -> Self {
        let conn: Arc<dyn ReadWriteCloser> = Arc::new(conn);
        Self {
            stream: Mutex::new(Stream {
                conn: conn.clone(),
                buf: Vec::new(),
                start: 0,
            }),
            conn,
            pending: Mutex::new(HashMap::new()),
            result: Mutex::new(None),
        }
    }
}

impl ClientCodec for JsonClientCodec {
    fn write_request(&self, r: &Request, param: &Value) -> Result<(), Error> {
        lock(&self.pending).insert(r.seq, r.service_method.clone());
        let mut line = Vec::new();
        line.extend_from_slice(b"{\"method\":");
        bridge::write_string(&mut line, r.service_method.as_bytes());
        line.extend_from_slice(b",\"params\":[");
        bridge::marshal_at(&mut line, param, &["params", "0"]).map_err(Error::new)?;
        line.extend_from_slice(b"],\"id\":");
        line.extend_from_slice(r.seq.to_string().as_bytes());
        line.extend_from_slice(b"}\n");
        Ok(write_all(&self.conn, &line)?)
    }

    fn read_response_header(&self, r: &mut Response) -> Result<(), Error> {
        *lock(&self.result) = None;
        let raw = lock(&self.stream).read_value()?;
        let m = members(&raw).map_err(Error::new)?;
        let id = match member(&m, "id") {
            None => 0,
            Some(v) if is_null(v) => 0,
            Some(v) => match std::str::from_utf8(v)
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
            {
                Some(id) => id,
                None => {
                    let what = if v.first() == Some(&b'"') {
                        "string".to_string()
                    } else {
                        format!("number {}", String::from_utf8_lossy(v))
                    };
                    return Err(Error::new(format!(
                        "json: cannot unmarshal {what} into Go struct field clientResponse.id of type uint64"
                    )));
                }
            },
        };
        let result = member(&m, "result").filter(|v| !is_null(v)).cloned();
        let err_raw = member(&m, "error").cloned();
        let err_tree = match &err_raw {
            Some(e) => parse(e).map_err(Error::new)?.json,
            None => Json::Null,
        };
        {
            let mut p = lock(&self.pending);
            r.service_method = p.remove(&id).unwrap_or_default();
        }
        r.error = String::new();
        r.seq = id;
        let has_err = !matches!(err_tree, Json::Null);
        if has_err || result.is_none() {
            let Json::String(x) = &err_tree else {
                return Err(Error::new(format!("invalid error {}", go_v(&err_tree))));
            };
            r.error = if x.is_empty() {
                "unspecified error".to_string()
            } else {
                x.clone()
            };
        }
        *lock(&self.result) = result;
        Ok(())
    }

    fn read_response_body(&self, x: &Value) -> Result<(), Error> {
        if !x.is_valid() {
            return Ok(());
        }
        let result = lock(&self.result)
            .clone()
            .unwrap_or_else(|| b"null".to_vec());
        bridge::unmarshal(&result, x).map_err(Error::new)
    }

    fn close(&self) -> Result<(), Error> {
        Ok(self.conn.close()?)
    }
}

/// Go `jsonrpc.NewClient`: a new [`Client`](super::Client) to handle
/// requests to the set of services at the other end of the connection.
pub fn client<C: ReadWriteCloser + 'static>(conn: C) -> super::Client {
    super::Client::with_codec(JsonClientCodec::new(conn))
}

/// Go `jsonrpc.Dial`: connects to a JSON-RPC server at the specified network
/// address.
pub fn dial(network: &str, address: &str) -> Result<super::Client, Error> {
    let conn: Box<dyn crate::net::Conn> = crate::net::dial(network, address)?;
    Ok(client(conn))
}

// ---- server ----

/// Request ids by sequence number.
type PendingIds = HashMap<u64, Option<Vec<u8>>>;

/// The JSON-RPC server codec (Go `jsonrpc.serverCodec`).
pub struct JsonServerCodec {
    conn: Arc<dyn ReadWriteCloser>,
    stream: Mutex<Stream>,
    params: Mutex<Option<Vec<u8>>>,
    /// JSON-RPC clients can use arbitrary JSON values as request ids; package
    /// rpc expects `u64`. Incoming requests get sequence numbers and their
    /// original ids are kept here.
    state: Mutex<(u64, PendingIds)>,
    write: Mutex<()>,
}

impl JsonServerCodec {
    /// Go `jsonrpc.NewServerCodec`: a new [`ServerCodec`] using JSON-RPC on
    /// `conn`.
    pub fn new<C: ReadWriteCloser + 'static>(conn: C) -> Self {
        let conn: Arc<dyn ReadWriteCloser> = Arc::new(conn);
        Self {
            stream: Mutex::new(Stream {
                conn: conn.clone(),
                buf: Vec::new(),
                start: 0,
            }),
            conn,
            params: Mutex::new(None),
            state: Mutex::new((0, HashMap::new())),
            write: Mutex::new(()),
        }
    }
}

impl ServerCodec for JsonServerCodec {
    fn read_request_header(&self, r: &mut Request) -> Result<(), Error> {
        *lock(&self.params) = None;
        let raw = lock(&self.stream).read_value()?;
        let m = members(&raw).map_err(Error::new)?;
        let method = match member(&m, "method") {
            None => String::new(),
            Some(v) if is_null(v) => String::new(),
            Some(v) => match parse(v) {
                Ok(Node {
                    json: Json::String(s),
                    ..
                }) => s,
                Ok(other) => {
                    let what = match other.json {
                        Json::Bool(_) => "bool",
                        Json::Number(_) => "number",
                        Json::Array(_) => "array",
                        _ => "object",
                    };
                    return Err(Error::new(format!(
                        "json: cannot unmarshal {what} into Go struct field serverRequest.method of type string"
                    )));
                }
                Err(e) => return Err(Error::new(e)),
            },
        };
        r.service_method = method;
        let id = member(&m, "id").filter(|v| !is_null(v)).cloned();
        *lock(&self.params) = member(&m, "params").filter(|v| !is_null(v)).cloned();
        let mut st = lock(&self.state);
        st.0 += 1;
        let seq = st.0;
        st.1.insert(seq, id);
        r.seq = seq;
        Ok(())
    }

    fn read_request_body(&self, x: &Value) -> Result<(), Error> {
        if !x.is_valid() {
            return Ok(());
        }
        let Some(params) = lock(&self.params).clone() else {
            return Err(Error::new("jsonrpc: request body missing params"));
        };
        // JSON params is an array value; RPC params is a struct. Unmarshal
        // into an array containing the struct for now.
        match parse(&params).map_err(Error::new)?.json {
            Json::Array(a) => match a.first() {
                Some(first) => {
                    bridge::unmarshal_tree(&params, first, x, &["0"]).map_err(Error::new)
                }
                None => Ok(()),
            },
            other => {
                let what = match other {
                    Json::Bool(_) => "bool",
                    Json::Number(_) => "number",
                    Json::String(_) => "string",
                    _ => "object",
                };
                Err(Error::new(format!(
                    "json: cannot unmarshal {what} into Go value of type [1]interface {{}}"
                )))
            }
        }
    }

    fn write_response(&self, r: &Response, x: &Value) -> Result<(), Error> {
        let id = {
            let mut st = lock(&self.state);
            match st.1.remove(&r.seq) {
                Some(id) => id,
                None => return Err(Error::new("invalid sequence number in response")),
            }
        };
        let id = match id {
            Some(raw) => compact_html(&raw),
            // Invalid request so no id. Use JSON null.
            None => b"null".to_vec(),
        };
        let mut result = Vec::new();
        let mut error = b"null".to_vec();
        if r.error.is_empty() {
            // The offset of Go's errors counts the response's own prefix.
            let mut doc = b"{\"id\":".to_vec();
            doc.extend_from_slice(&id);
            doc.extend_from_slice(b",\"result\":");
            let start = doc.len();
            bridge::marshal_at(&mut doc, x, &["result"]).map_err(Error::new)?;
            result = doc.split_off(start);
        } else {
            result.extend_from_slice(b"null");
            error.clear();
            bridge::write_string(&mut error, r.error.as_bytes());
        }
        let line = marshal_line(&[
            b"{\"id\":",
            &id,
            b",\"result\":",
            &result,
            b",\"error\":",
            &error,
            b"}\n",
        ]);
        let _g = lock(&self.write);
        Ok(write_all(&self.conn, &line)?)
    }

    fn close(&self) -> Result<(), Error> {
        Ok(self.conn.close()?)
    }
}

/// Go `jsonrpc.ServeConn`: runs the JSON-RPC server on a single connection.
/// It blocks, serving the connection until the client hangs up.
pub fn serve_conn<C: ReadWriteCloser + 'static>(conn: C) {
    super::serve_codec(JsonServerCodec::new(conn));
}
