//! A JSON parser that keeps what `encoding/json` keeps when it decodes into
//! Go values: number literals as written (so a `uint64` or an `int64` does
//! not pass through a float), and every member of an object in order (later
//! duplicates win when applied).

/// A parsed JSON value and where it sits in the input.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Node {
    pub(crate) json: Json,
    /// The value's bytes in the input, without surrounding white space: the
    /// text `encoding/json` passes to an `UnmarshalJSON` method.
    pub(crate) span: Range<usize>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Json {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Node>),
    Object(Vec<(String, Node)>),
}

use std::ops::Range;

struct P<'a> {
    b: &'a [u8],
    i: usize,
}

fn quote_char(c: u8) -> String {
    match c {
        b'\'' => "'\\''".into(),
        b'"' => "'\"'".into(),
        c if c < 0x20 || c == 0x7f => format!("'\\x{c:02x}'").replace("\\x0a", "\\n"),
        c => format!("'{}'", c as char),
    }
}

impl P<'_> {
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\r' | b'\n') {
            self.i += 1;
        }
    }

    fn err_at(&self, ctx: &str) -> String {
        match self.b.get(self.i) {
            Some(&c) => format!("invalid character {} {ctx}", quote_char(c)),
            None => "unexpected end of JSON input".into(),
        }
    }

    fn value(&mut self) -> Result<Node, String> {
        self.ws();
        let start = self.i;
        let json = self.json()?;
        Ok(Node {
            json,
            span: start..self.i,
        })
    }

    fn json(&mut self) -> Result<Json, String> {
        match self.b.get(self.i) {
            None => Err("unexpected end of JSON input".into()),
            Some(b'{') => {
                self.i += 1;
                let mut members = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Ok(Json::Object(members));
                }
                loop {
                    self.ws();
                    if self.b.get(self.i) != Some(&b'"') {
                        return Err(self.err_at("looking for beginning of object key string"));
                    }
                    let key = self.string()?;
                    self.ws();
                    if self.b.get(self.i) != Some(&b':') {
                        return Err(self.err_at("after object key"));
                    }
                    self.i += 1;
                    let v = self.value()?;
                    members.push((key, v));
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(Json::Object(members));
                        }
                        _ => return Err(self.err_at("after object key:value pair")),
                    }
                }
            }
            Some(b'[') => {
                self.i += 1;
                let mut items = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Ok(Json::Array(items));
                }
                loop {
                    items.push(self.value()?);
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Json::Array(items));
                        }
                        _ => return Err(self.err_at("after array element")),
                    }
                }
            }
            Some(b'"') => Ok(Json::String(self.string()?)),
            Some(b't') => self.word(b"true", Json::Bool(true)),
            Some(b'f') => self.word(b"false", Json::Bool(false)),
            Some(b'n') => self.word(b"null", Json::Null),
            Some(c) if *c == b'-' || c.is_ascii_digit() => self.number(),
            Some(_) => Err(self.err_at("looking for beginning of value")),
        }
    }

    fn word(&mut self, w: &[u8], n: Json) -> Result<Json, String> {
        for (k, c) in w.iter().enumerate() {
            match self.b.get(self.i + k) {
                Some(x) if x == c => {}
                Some(x) => {
                    return Err(format!(
                        "invalid character {} in literal {} (expecting {})",
                        quote_char(*x),
                        String::from_utf8_lossy(w),
                        quote_char(*c)
                    ))
                }
                None => return Err("unexpected end of JSON input".into()),
            }
        }
        self.i += w.len();
        Ok(n)
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        if self.b[self.i] == b'-' {
            self.i += 1;
        }
        match self.b.get(self.i) {
            Some(b'0') => self.i += 1,
            Some(c) if c.is_ascii_digit() => {
                while self.b.get(self.i).is_some_and(u8::is_ascii_digit) {
                    self.i += 1;
                }
            }
            _ => return Err(self.err_at("in numeric literal")),
        }
        if self.b.get(self.i) == Some(&b'.') {
            self.i += 1;
            if !self.b.get(self.i).is_some_and(u8::is_ascii_digit) {
                return Err(self.err_at("after decimal point in numeric literal"));
            }
            while self.b.get(self.i).is_some_and(u8::is_ascii_digit) {
                self.i += 1;
            }
        }
        if matches!(self.b.get(self.i), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.b.get(self.i), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !self.b.get(self.i).is_some_and(u8::is_ascii_digit) {
                return Err(self.err_at("in exponent of numeric literal"));
            }
            while self.b.get(self.i).is_some_and(u8::is_ascii_digit) {
                self.i += 1;
            }
        }
        Ok(Json::Number(
            String::from_utf8_lossy(&self.b[start..self.i]).into_owned(),
        ))
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let mut n = 0u32;
        for _ in 0..4 {
            match self.b.get(self.i) {
                Some(c) if c.is_ascii_hexdigit() => {
                    n = n * 16 + (*c as char).to_digit(16).unwrap_or(0);
                    self.i += 1;
                }
                _ => return Err(self.err_at("in \\u hexadecimal character escape")),
            }
        }
        Ok(n)
    }

    fn string(&mut self) -> Result<String, String> {
        self.i += 1; // opening quote
        let mut out: Vec<u8> = Vec::new();
        loop {
            let Some(&c) = self.b.get(self.i) else {
                return Err("unexpected end of JSON input".into());
            };
            match c {
                b'"' => {
                    self.i += 1;
                    return Ok(String::from_utf8_lossy(&out).into_owned());
                }
                b'\\' => {
                    self.i += 1;
                    let Some(&e) = self.b.get(self.i) else {
                        return Err("unexpected end of JSON input".into());
                    };
                    self.i += 1;
                    match e {
                        b'"' | b'\\' | b'/' => out.push(e),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let mut r = self.hex4()?;
                            if (0xd800..0xdc00).contains(&r)
                                && self.b.get(self.i) == Some(&b'\\')
                                && self.b.get(self.i + 1) == Some(&b'u')
                            {
                                let save = self.i;
                                self.i += 2;
                                let lo = self.hex4()?;
                                if (0xdc00..0xe000).contains(&lo) {
                                    r = 0x10000 + ((r - 0xd800) << 10) + (lo - 0xdc00);
                                } else {
                                    self.i = save;
                                }
                            }
                            let ch = char::from_u32(r).unwrap_or('\u{fffd}');
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => {
                            self.i -= 1;
                            return Err(self.err_at("in string escape code"));
                        }
                    }
                }
                c if c < 0x20 => return Err(self.err_at("in string literal")),
                c => {
                    out.push(c);
                    self.i += 1;
                }
            }
        }
    }
}

/// Parses one JSON value; anything after it is an error.
pub(crate) fn parse(data: &[u8]) -> Result<Node, String> {
    let mut p = P { b: data, i: 0 };
    let v = p.value()?;
    p.ws();
    if p.i < data.len() {
        return Err(p.err_at("after top-level value"));
    }
    Ok(v)
}
