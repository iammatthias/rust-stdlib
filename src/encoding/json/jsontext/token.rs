//! `jsontext.Token` and `jsontext.Kind`.
use std::fmt;

use super::errors::{Error, NumError};
use super::flags::Flags;
use super::wire;
use crate::strconv;

/// `jsontext.Kind`: the kind of a JSON token or value, identified by the
/// first byte of its text.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Kind(pub u8);

/// An invalid kind (`KindInvalid`).
pub const KIND_INVALID: Kind = Kind(0);
/// `null` (`KindNull`).
pub const KIND_NULL: Kind = Kind(b'n');
/// `false` (`KindFalse`).
pub const KIND_FALSE: Kind = Kind(b'f');
/// `true` (`KindTrue`).
pub const KIND_TRUE: Kind = Kind(b't');
/// A string (`KindString`).
pub const KIND_STRING: Kind = Kind(b'"');
/// A number (`KindNumber`).
pub const KIND_NUMBER: Kind = Kind(b'0');
/// `{` (`KindBeginObject`).
pub const KIND_BEGIN_OBJECT: Kind = Kind(b'{');
/// `}` (`KindEndObject`).
pub const KIND_END_OBJECT: Kind = Kind(b'}');
/// `[` (`KindBeginArray`).
pub const KIND_BEGIN_ARRAY: Kind = Kind(b'[');
/// `]` (`KindEndArray`).
pub const KIND_END_ARRAY: Kind = Kind(b']');

impl Kind {
    /// Maps the first byte of a value to its kind (`normalize`): every digit
    /// and `-` is a number; bytes that begin no value are invalid.
    pub fn normalize(self) -> Kind {
        Kind(match self.0 {
            c @ (b'n' | b'f' | b't' | b'"' | b'{' | b'}' | b'[' | b']') => c,
            b'-' | b'0'..=b'9' => b'0',
            _ => 0,
        })
    }
}

/// The token's text: the unquoted content of a string, the formatted value of
/// a number, or the literal (`null`, `{`, ...).
impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.string_bytes()))
    }
}

/// The kind's name (Go's `Kind.String`).
impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => f.write_str("invalid"),
            b'n' => f.write_str("null"),
            b'f' => f.write_str("false"),
            b't' => f.write_str("true"),
            b'"' => f.write_str("string"),
            b'0' => f.write_str("number"),
            b'{' => f.write_str("{"),
            b'}' => f.write_str("}"),
            b'[' => f.write_str("["),
            b']' => f.write_str("]"),
            c => write!(f, "<invalid jsontext.Kind: {}>", wire::quote_rune(&[c])),
        }
    }
}

impl From<u8> for Kind {
    fn from(b: u8) -> Kind {
        Kind(b)
    }
}

#[derive(Clone, Debug)]
enum Repr {
    /// The zero Token.
    Invalid,
    /// The raw JSON text of a literal, string, number or delimiter.
    Raw(Vec<u8>),
    /// A string made by [`Token::string`].
    Str(Vec<u8>),
    F32(u32),
    F64(u64),
    I64(i64),
    U64(u64),
}

/// `jsontext.Token`: a lexical JSON token, which is `null`, `false`, `true`,
/// a number, a string or one of the four delimiters.
///
/// A Token owns its text, so unlike Go's it never becomes invalid when the
/// `Decoder` that produced it is used again.
#[derive(Clone, Debug)]
pub struct Token(Repr);

impl Default for Token {
    fn default() -> Token {
        Token(Repr::Invalid)
    }
}

fn raw_token(s: &str) -> Token {
    Token(Repr::Raw(s.as_bytes().to_vec()))
}

/// `jsontext.Null`.
pub fn null() -> Token {
    raw_token("null")
}
/// `jsontext.False`.
pub fn false_() -> Token {
    raw_token("false")
}
/// `jsontext.True`.
pub fn true_() -> Token {
    raw_token("true")
}
/// `jsontext.BeginObject`.
pub fn begin_object() -> Token {
    raw_token("{")
}
/// `jsontext.EndObject`.
pub fn end_object() -> Token {
    raw_token("}")
}
/// `jsontext.BeginArray`.
pub fn begin_array() -> Token {
    raw_token("[")
}
/// `jsontext.EndArray`.
pub fn end_array() -> Token {
    raw_token("]")
}

/// `jsontext.Bool`.
pub fn bool(b: bool) -> Token {
    if b {
        true_()
    } else {
        false_()
    }
}

/// `jsontext.String`.
pub fn string(s: &str) -> Token {
    string_bytes(s.as_bytes())
}

/// Like [`string`] for text that may not be valid UTF-8, which a Go string
/// can hold and a Rust `str` cannot.
pub fn string_bytes(s: &[u8]) -> Token {
    if s.is_empty() {
        return raw_token("\"\"");
    }
    Token(Repr::Str(s.to_vec()))
}

/// `jsontext.Float32`.
pub fn float32(n: f32) -> Token {
    if n != 0.0 && !n.is_nan() && !n.is_infinite() {
        return Token(Repr::F32(n.to_bits()));
    }
    float(n as f64)
}

/// `jsontext.Float`. NaN and the infinities become the strings `"NaN"`,
/// `"Infinity"` and `"-Infinity"`.
pub fn float(n: f64) -> Token {
    if n.to_bits() == 0 {
        raw_token("0")
    } else if n.is_nan() {
        string("NaN")
    } else if n == f64::INFINITY {
        string("Infinity")
    } else if n == f64::NEG_INFINITY {
        string("-Infinity")
    } else {
        Token(Repr::F64(n.to_bits()))
    }
}

/// `jsontext.Int`.
pub fn int(n: i64) -> Token {
    if n == 0 {
        raw_token("0")
    } else {
        Token(Repr::I64(n))
    }
}

/// `jsontext.Uint`.
pub fn uint(n: u64) -> Token {
    if n == 0 {
        raw_token("0")
    } else {
        Token(Repr::U64(n))
    }
}

/// Go's `math.NaN()`: its bit pattern is 0x7FF8000000000001.
pub(crate) const NAN: f64 = f64::from_bits(0x7FF8_0000_0000_0001);

fn f64_to_i64(f: f64) -> i64 {
    if f.is_nan() {
        0
    } else if f >= 9223372036854775808.0 {
        i64::MAX
    } else if f < -9223372036854775808.0 {
        i64::MIN
    } else {
        f as i64
    }
}

fn f64_to_u64(f: f64) -> u64 {
    if f.is_nan() {
        0
    } else if f >= 18446744073709551616.0 {
        u64::MAX
    } else if f < 0.0 {
        0
    } else {
        f as u64
    }
}

impl Token {
    /// A token holding the raw text of a decoded string or number.
    pub(crate) fn from_raw(b: &[u8]) -> Token {
        Token(Repr::Raw(b.to_vec()))
    }

    /// Go's `Token.Clone`; a Token already owns its text, so this is the
    /// ordinary `Clone`.
    #[must_use]
    pub fn clone_token(&self) -> Token {
        self.clone()
    }

    /// The token's boolean value. Panics if the token is not `true` or
    /// `false`.
    pub fn bool(&self) -> bool {
        match &self.0 {
            Repr::Raw(b) if b == b"true" => true,
            Repr::Raw(b) if b == b"false" => false,
            _ => panic!("invalid JSON token kind: {}", self.kind()),
        }
    }

    /// Appends the token as a JSON string; panics for other kinds.
    pub(crate) fn append_string(&self, dst: &mut Vec<u8>, f: &Flags) -> Option<Error> {
        match &self.0 {
            Repr::Raw(buf) if buf[0] == b'"' => {
                if wire::consume_simple_string(buf) == buf.len() {
                    dst.extend_from_slice(buf);
                    return None;
                }
                return wire::reformat_string(dst, buf, f).1;
            }
            Repr::Str(s) if !s.is_empty() => return wire::append_quote(dst, s, f),
            _ => {}
        }
        panic!("invalid JSON token kind: {}", self.kind());
    }

    /// Appends the token as a JSON number; panics for other kinds.
    pub(crate) fn append_number(&self, dst: &mut Vec<u8>, f: &Flags) -> Option<Error> {
        match &self.0 {
            Repr::Raw(buf) if Kind(buf[0]).normalize() == super::KIND_NUMBER => {
                return wire::reformat_number(dst, buf, f).1;
            }
            Repr::F32(bits) => {
                wire::append_float(dst, f32::from_bits(*bits) as f64, 32);
                return None;
            }
            Repr::F64(bits) => {
                wire::append_float(dst, f64::from_bits(*bits), 64);
                return None;
            }
            Repr::I64(n) => {
                strconv::append_int(dst, *n, 10);
                return None;
            }
            Repr::U64(n) => {
                strconv::append_uint(dst, *n, 10);
                return None;
            }
            _ => {}
        }
        panic!("invalid JSON token kind: {}", self.kind());
    }

    /// The token's text as bytes (see the `Display` impl for the text form). Text decoded from a string
    /// with invalid UTF-8 has it replaced with U+FFFD, as Go's does.
    pub fn string_bytes(&self) -> Vec<u8> {
        match &self.0 {
            Repr::Raw(buf) => {
                if buf[0] == b'"' {
                    let verbatim = wire::consume_simple_string(buf) == buf.len();
                    wire::unquote_may_copy(buf, verbatim)
                } else {
                    buf.clone()
                }
            }
            Repr::Str(s) => s.clone(),
            Repr::F32(bits) => {
                let mut v = Vec::new();
                wire::append_float(&mut v, f32::from_bits(*bits) as f64, 32);
                v
            }
            Repr::F64(bits) => {
                let mut v = Vec::new();
                wire::append_float(&mut v, f64::from_bits(*bits), 64);
                v
            }
            Repr::I64(n) => n.to_string().into_bytes(),
            Repr::U64(n) => n.to_string().into_bytes(),
            Repr::Invalid => b"<invalid jsontext.Token>".to_vec(),
        }
    }

    fn num_error(&self, accessor: &'static str, err: strconv::Error) -> Option<Error> {
        Some(Error::Num(Box::new(NumError {
            accessor,
            value: self.to_string(),
            err,
        })))
    }

    /// The number as an `f32` (Go's `Token.Float32`). Out-of-range values
    /// give the error and ±Inf or the nearest finite value.
    pub fn float32(&self) -> (f32, Option<Error>) {
        let (f, err) = self.float_bits(32);
        (f as f32, err)
    }

    /// The number as an `f64` (Go's `Token.Float`). The strings `"NaN"`,
    /// `"Infinity"` and `"-Infinity"` are accepted too.
    pub fn float(&self) -> (f64, Option<Error>) {
        self.float_bits(64)
    }

    fn float_bits(&self, bits: i32) -> (f64, Option<Error>) {
        match &self.0 {
            Repr::Raw(buf) if Kind(buf[0]).normalize() == super::KIND_NUMBER => {
                let text = String::from_utf8_lossy(buf);
                return match strconv::parse_float(&text, bits) {
                    Ok(fv) => (fv, None),
                    Err(e) => (e.float_value(), self.num_error("Float", e.err)),
                };
            }
            Repr::F32(b) => return (f32::from_bits(*b) as f64, None),
            Repr::F64(b) => {
                let f64v = f64::from_bits(*b);
                if bits == 32 && !f64v.is_infinite() && (f64v as f32).is_infinite() {
                    return (f64v, self.num_error("Float", strconv::ERR_RANGE));
                }
                return (f64v, None);
            }
            Repr::I64(n) => return (*n as f64, None),
            Repr::U64(n) => return (*n as f64, None),
            _ => {}
        }
        if self.kind() == super::KIND_STRING {
            match self.to_string().as_str() {
                "NaN" => return (NAN, None),
                "Infinity" => return (f64::INFINITY, None),
                "-Infinity" => return (f64::NEG_INFINITY, None),
                _ => {}
            }
        }
        panic!("invalid JSON token kind: {}", self.kind());
    }

    /// The number as an `i64` (Go's `Token.Int`).
    pub fn int(&self) -> (i64, Option<Error>) {
        match &self.0 {
            Repr::Raw(buf) => {
                if buf.first() == Some(&b'-') {
                    let (abs, ok) = wire::parse_uint(&buf[1..]);
                    if abs > 1 << 63 {
                        return (i64::MIN, self.num_error("Int", strconv::ERR_RANGE));
                    } else if ok {
                        return ((abs as i64).wrapping_neg(), None);
                    }
                } else {
                    let (abs, ok) = wire::parse_uint(buf);
                    if abs > i64::MAX as u64 {
                        return (i64::MAX, self.num_error("Int", strconv::ERR_RANGE));
                    } else if ok {
                        return (abs as i64, None);
                    }
                }
                if Kind(buf[0]).normalize() == super::KIND_NUMBER {
                    let f = strconv::parse_float(&String::from_utf8_lossy(buf), 64)
                        .unwrap_or_else(|e| e.float_value());
                    return (f64_to_i64(f), self.num_error("Int", strconv::ERR_SYNTAX));
                }
            }
            Repr::I64(n) => return (*n, None),
            Repr::U64(n) => {
                if *n > i64::MAX as u64 {
                    return (i64::MAX, self.num_error("Int", strconv::ERR_RANGE));
                }
                return (*n as i64, None);
            }
            Repr::F32(_) | Repr::F64(_) => {
                let f = match &self.0 {
                    Repr::F32(b) => f32::from_bits(*b) as f64,
                    Repr::F64(b) => f64::from_bits(*b),
                    _ => unreachable!(),
                };
                let i = f64_to_i64(f);
                if f.is_nan() || f.trunc() != f {
                    return (i, self.num_error("Int", strconv::ERR_SYNTAX));
                } else if (i == i64::MIN && f < -9223372036854775808.0)
                    || (i == i64::MAX && f > 9223372036854775807.0)
                {
                    return (i, self.num_error("Int", strconv::ERR_RANGE));
                }
                return (i, None);
            }
            _ => {}
        }
        panic!("invalid JSON token kind: {}", self.kind());
    }

    /// The number as a `u64` (Go's `Token.Uint`).
    pub fn uint(&self) -> (u64, Option<Error>) {
        match &self.0 {
            Repr::Raw(buf) => {
                let (abs, ok) = wire::parse_uint(buf);
                if ok {
                    return (abs, None);
                } else if abs == u64::MAX {
                    return (u64::MAX, self.num_error("Uint", strconv::ERR_RANGE));
                }
                if Kind(buf[0]).normalize() == super::KIND_NUMBER {
                    let f = strconv::parse_float(&String::from_utf8_lossy(buf), 64)
                        .unwrap_or_else(|e| e.float_value());
                    return (f64_to_u64(f), self.num_error("Uint", strconv::ERR_SYNTAX));
                }
            }
            Repr::U64(n) => return (*n, None),
            Repr::I64(n) => {
                if *n < 0 {
                    return (0, self.num_error("Uint", strconv::ERR_SYNTAX));
                }
                return (*n as u64, None);
            }
            Repr::F32(_) | Repr::F64(_) => {
                let f = match &self.0 {
                    Repr::F32(b) => f32::from_bits(*b) as f64,
                    Repr::F64(b) => f64::from_bits(*b),
                    _ => unreachable!(),
                };
                let u = f64_to_u64(f);
                if f.is_nan() || f.trunc() != f || f.is_sign_negative() {
                    return (u, self.num_error("Uint", strconv::ERR_SYNTAX));
                } else if (u == 0 && f < 0.0) || (u == u64::MAX && f > 18446744073709551615.0) {
                    return (u, self.num_error("Uint", strconv::ERR_RANGE));
                }
                return (u, None);
            }
            _ => {}
        }
        panic!("invalid JSON token kind: {}", self.kind());
    }

    /// The token's kind (Go's `Token.Kind`).
    pub fn kind(&self) -> Kind {
        match &self.0 {
            Repr::Raw(b) => Kind(b[0]).normalize(),
            Repr::F32(_) | Repr::F64(_) | Repr::I64(_) | Repr::U64(_) => KIND_NUMBER,
            Repr::Str(_) => KIND_STRING,
            Repr::Invalid => KIND_INVALID,
        }
    }
}
