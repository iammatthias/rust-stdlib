//! The request/response protocol shared by the Go differential
//! (`tools/json_check.py`) and the golden vectors in `tests/json.rs`.
//! Requests are `op field...` with hex fields (`-` is empty); responses are
//! `ok <hex>` or `err <hex message> <offset|->`, as in `tools/json_oracle.go`.
use rust_stdlib::encoding::json::{self, Decoder, Error, Token, Value};
use std::io::{self, Read};

/// Returns at most `n` bytes per read, like Go's chunking test reader (0 means
/// unlimited).
struct ChunkReader {
    data: Vec<u8>,
    pos: usize,
    n: usize,
}
impl Read for ChunkReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut want = out.len().min(self.data.len() - self.pos);
        if self.n > 0 {
            want = want.min(self.n);
        }
        out[..want].copy_from_slice(&self.data[self.pos..self.pos + want]);
        self.pos += want;
        Ok(want)
    }
}

fn token_text(t: &Token) -> String {
    match t {
        Token::Delim(d) => format!("D{d}"),
        Token::Bool(true) => "Btrue".into(),
        Token::Bool(false) => "Bfalse".into(),
        Token::Float64(f) => format!(
            "F{}",
            String::from_utf8(json::marshal(f).expect("finite float")).expect("utf-8")
        ),
        Token::Number(n) => format!("N{}", n.as_str()),
        Token::String(s) => format!("S{}", enc(s.as_bytes())),
        Token::Null => "Z".into(),
    }
}

fn err_text(e: &Error) -> String {
    match e {
        Error::Eof => "EOF".into(),
        Error::SyntaxError(s) => format!("E{}@{}", enc(e.to_string().as_bytes()), s.offset),
        _ => format!("E{}", enc(e.to_string().as_bytes())),
    }
}

fn stream(op: &str, chunk: usize, use_number: bool, data: Vec<u8>) -> String {
    let mut d = Decoder::new(ChunkReader {
        data,
        pos: 0,
        n: chunk,
    });
    if use_number {
        d.use_number();
    }
    let mut parts = Vec::new();
    for _ in 0..100_000 {
        if op == "tokens" {
            let more = d.more();
            match d.token() {
                Ok(t) => parts.push(format!("{}|{}|{}", token_text(&t), d.input_offset(), more)),
                Err(e) => {
                    parts.push(err_text(&e));
                    break;
                }
            }
        } else {
            match d.decode::<Value>() {
                Ok(v) => {
                    let b = json::marshal(&v).expect("marshal decoded value");
                    parts.push(format!(
                        "{}|{}|{}",
                        enc(&b),
                        d.input_offset(),
                        enc(d.buffered())
                    ));
                }
                Err(e) => {
                    parts.push(err_text(&e));
                    break;
                }
            }
        }
    }
    format!("ok {}", enc(parts.join("\n").as_bytes()))
}

pub fn dec(field: &str) -> Vec<u8> {
    if field == "-" {
        return Vec::new();
    }
    (0..field.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&field[i..i + 2], 16).expect("hex field"))
        .collect()
}

pub fn enc(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".into();
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn ok(bytes: &[u8]) -> String {
    format!("ok {}", enc(bytes))
}

fn fail(err: &Error) -> String {
    let offset = match err {
        Error::SyntaxError(e) => e.offset.to_string(),
        Error::UnmarshalType(e) => format!("t{}", e.offset),
        _ => "-".into(),
    };
    format!("err {} {offset}", enc(err.to_string().as_bytes()))
}

/// Answers one request line.
pub fn respond(line: &str) -> String {
    let f: Vec<&str> = line.split_whitespace().collect();
    match f[0] {
        "valid" => format!("ok {}", u8::from(json::valid(&dec(f[1])))),
        "compact" => {
            let mut dst = Vec::new();
            match json::compact(&mut dst, &dec(f[1])) {
                Ok(()) => ok(&dst),
                Err(e) => fail(&e.into()),
            }
        }
        "indent" => {
            let mut dst = Vec::new();
            let prefix = String::from_utf8_lossy(&dec(f[1])).into_owned();
            let indent = String::from_utf8_lossy(&dec(f[2])).into_owned();
            match json::indent(&mut dst, &dec(f[3]), &prefix, &indent) {
                Ok(()) => ok(&dst),
                Err(e) => fail(&e.into()),
            }
        }
        "html" => {
            let mut dst = Vec::new();
            json::html_escape(&mut dst, &dec(f[1]));
            ok(&dst)
        }
        "unmarshal" => match json::unmarshal::<Value>(&dec(f[1])) {
            Ok(v) => match json::marshal(&v) {
                Ok(b) => ok(&b),
                Err(e) => fail(&e),
            },
            Err(e) => fail(&e),
        },
        "tokens" | "decodes" => stream(f[0], f[1].parse().expect("chunk"), f[2] == "1", dec(f[3])),
        other => format!("err {} -", enc(format!("unknown op {other}").as_bytes())),
    }
}
