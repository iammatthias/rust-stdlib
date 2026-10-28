//! A minimal JSON reader for the test fixtures extracted from Go's tests
//! (the crate has no JSON dependency).
#![allow(dead_code)]

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    pub fn parse(text: &str) -> Json {
        let mut parser = Parser {
            bytes: text.as_bytes(),
            at: 0,
        };
        let value = parser.value();
        parser.space();
        assert_eq!(parser.at, parser.bytes.len(), "trailing JSON data");
        value
    }

    /// The member of an object; `Null` when absent.
    pub fn get(&self, key: &str) -> &Json {
        static NULL: Json = Json::Null;
        match self {
            Json::Object(members) => members
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v)
                .unwrap_or(&NULL),
            _ => &NULL,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Json::String(s) => s,
            Json::Null => "",
            other => panic!("not a string: {other:?}"),
        }
    }

    pub fn as_bool(&self) -> bool {
        matches!(self, Json::Bool(true))
    }

    pub fn as_i64(&self) -> i64 {
        match self {
            Json::Number(n) => *n as i64,
            Json::Null => 0,
            other => panic!("not a number: {other:?}"),
        }
    }

    pub fn as_array(&self) -> &[Json] {
        match self {
            Json::Array(items) => items,
            Json::Null => &[],
            other => panic!("not an array: {other:?}"),
        }
    }

    pub fn strings(&self) -> Vec<String> {
        self.as_array()
            .iter()
            .map(|s| s.as_str().to_string())
            .collect()
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn space(&mut self) {
        while self.at < self.bytes.len() && self.bytes[self.at].is_ascii_whitespace() {
            self.at += 1;
        }
    }

    fn eat(&mut self, c: u8) {
        self.space();
        assert_eq!(
            self.bytes[self.at], c,
            "expected {:?} at {}",
            c as char, self.at
        );
        self.at += 1;
    }

    fn value(&mut self) -> Json {
        self.space();
        match self.bytes[self.at] {
            b'{' => {
                self.at += 1;
                let mut members = Vec::new();
                self.space();
                if self.bytes[self.at] == b'}' {
                    self.at += 1;
                    return Json::Object(members);
                }
                loop {
                    self.space();
                    let key = self.string();
                    self.eat(b':');
                    members.push((key, self.value()));
                    self.space();
                    match self.bytes[self.at] {
                        b',' => self.at += 1,
                        b'}' => {
                            self.at += 1;
                            return Json::Object(members);
                        }
                        other => panic!("unexpected {:?}", other as char),
                    }
                }
            }
            b'[' => {
                self.at += 1;
                let mut items = Vec::new();
                self.space();
                if self.bytes[self.at] == b']' {
                    self.at += 1;
                    return Json::Array(items);
                }
                loop {
                    items.push(self.value());
                    self.space();
                    match self.bytes[self.at] {
                        b',' => self.at += 1,
                        b']' => {
                            self.at += 1;
                            return Json::Array(items);
                        }
                        other => panic!("unexpected {:?}", other as char),
                    }
                }
            }
            b'"' => Json::String(self.string()),
            b't' => {
                self.at += 4;
                Json::Bool(true)
            }
            b'f' => {
                self.at += 5;
                Json::Bool(false)
            }
            b'n' => {
                self.at += 4;
                Json::Null
            }
            _ => {
                let start = self.at;
                while self.at < self.bytes.len()
                    && matches!(
                        self.bytes[self.at],
                        b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9'
                    )
                {
                    self.at += 1;
                }
                let text = std::str::from_utf8(&self.bytes[start..self.at]).unwrap();
                Json::Number(text.parse().expect("number"))
            }
        }
    }

    fn string(&mut self) -> String {
        assert_eq!(self.bytes[self.at], b'"');
        self.at += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            match self.bytes[self.at] {
                b'"' => {
                    self.at += 1;
                    return String::from_utf8(out).expect("UTF-8");
                }
                b'\\' => {
                    self.at += 1;
                    let c = self.bytes[self.at];
                    self.at += 1;
                    match c {
                        b'"' | b'\\' | b'/' => out.push(c),
                        b'n' => out.push(b'\n'),
                        b't' => out.push(b'\t'),
                        b'r' => out.push(b'\r'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'u' => {
                            let hex =
                                std::str::from_utf8(&self.bytes[self.at..self.at + 4]).unwrap();
                            let mut code = u32::from_str_radix(hex, 16).unwrap();
                            self.at += 4;
                            if (0xd800..0xdc00).contains(&code) {
                                // A surrogate pair.
                                assert_eq!(&self.bytes[self.at..self.at + 2], b"\\u");
                                let low = u32::from_str_radix(
                                    std::str::from_utf8(&self.bytes[self.at + 2..self.at + 6])
                                        .unwrap(),
                                    16,
                                )
                                .unwrap();
                                self.at += 6;
                                code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
                            }
                            let ch = char::from_u32(code).expect("scalar value");
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        other => panic!("bad escape {:?}", other as char),
                    }
                }
                c => {
                    out.push(c);
                    self.at += 1;
                }
            }
        }
    }
}
