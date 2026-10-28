//! A port of Go's `encoding/json` scanner, used to validate and compact the
//! output of `MarshalJSON` methods (Go `scanner.go` and `appendCompact`).

use crate::strconv;

const SCAN_CONTINUE: i32 = 0;
const SCAN_BEGIN_LITERAL: i32 = 1;
const SCAN_BEGIN_OBJECT: i32 = 2;
const SCAN_OBJECT_KEY: i32 = 3;
const SCAN_OBJECT_VALUE: i32 = 4;
const SCAN_END_OBJECT: i32 = 5;
const SCAN_BEGIN_ARRAY: i32 = 6;
const SCAN_ARRAY_VALUE: i32 = 7;
const SCAN_END_ARRAY: i32 = 8;
const SCAN_SKIP_SPACE: i32 = 9;
const SCAN_END: i32 = 10;
const SCAN_ERROR: i32 = 11;

const PARSE_OBJECT_KEY: u8 = 0;
const PARSE_OBJECT_VALUE: u8 = 1;
const PARSE_ARRAY_VALUE: u8 = 2;

const MAX_NESTING_DEPTH: usize = 10000;

const HEX: &[u8; 16] = b"0123456789abcdef";

#[derive(Clone, Copy, PartialEq, Eq)]
enum St {
    BeginValue,
    BeginValueOrEmpty,
    BeginStringOrEmpty,
    BeginString,
    EndValue,
    EndTop,
    InString,
    InStringEsc,
    InStringEscU,
    InStringEscU1,
    InStringEscU12,
    InStringEscU123,
    Neg,
    One,
    Zero,
    Dot,
    Dot0,
    E,
    ESign,
    E0,
    T,
    Tr,
    Tru,
    F,
    Fa,
    Fal,
    Fals,
    N,
    Nu,
    Nul,
    Error,
}

struct Scanner {
    step: St,
    end_top: bool,
    parse_state: Vec<u8>,
    err: Option<String>,
}

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n')
}

fn quote_char(c: u8) -> String {
    if c == b'\'' {
        return "'\\''".to_owned();
    }
    if c == b'"' {
        return "'\"'".to_owned();
    }
    let s = strconv::quote([c]);
    format!("'{}'", &s[1..s.len() - 1])
}

impl Scanner {
    fn new() -> Scanner {
        Scanner {
            step: St::BeginValue,
            end_top: false,
            parse_state: Vec::new(),
            err: None,
        }
    }

    fn error(&mut self, c: u8, context: &str) -> i32 {
        self.step = St::Error;
        self.err = Some(format!("invalid character {} {}", quote_char(c), context));
        SCAN_ERROR
    }

    fn eof(&mut self) -> i32 {
        if self.err.is_some() {
            return SCAN_ERROR;
        }
        if self.end_top {
            return SCAN_END;
        }
        self.step(b' ');
        if self.end_top {
            return SCAN_END;
        }
        if self.err.is_none() {
            self.err = Some("unexpected end of JSON input".to_owned());
        }
        SCAN_ERROR
    }

    fn push_parse_state(&mut self, c: u8, new_state: u8, success: i32) -> i32 {
        self.parse_state.push(new_state);
        if self.parse_state.len() <= MAX_NESTING_DEPTH {
            return success;
        }
        self.error(c, "exceeded max depth")
    }

    fn pop_parse_state(&mut self) {
        self.parse_state.pop();
        if self.parse_state.is_empty() {
            self.step = St::EndTop;
            self.end_top = true;
        } else {
            self.step = St::EndValue;
        }
    }

    fn step(&mut self, c: u8) -> i32 {
        match self.step {
            St::BeginValue => self.state_begin_value(c),
            St::BeginValueOrEmpty => {
                if is_space(c) {
                    return SCAN_SKIP_SPACE;
                }
                if c == b']' {
                    return self.state_end_value(c);
                }
                self.state_begin_value(c)
            }
            St::BeginStringOrEmpty => {
                if is_space(c) {
                    return SCAN_SKIP_SPACE;
                }
                if c == b'}' {
                    let n = self.parse_state.len();
                    self.parse_state[n - 1] = PARSE_OBJECT_VALUE;
                    return self.state_end_value(c);
                }
                self.state_begin_string(c)
            }
            St::BeginString => self.state_begin_string(c),
            St::EndValue => self.state_end_value(c),
            St::EndTop => {
                if !is_space(c) {
                    self.error(c, "after top-level value");
                }
                SCAN_END
            }
            St::InString => {
                if c == b'"' {
                    self.step = St::EndValue;
                    return SCAN_CONTINUE;
                }
                if c == b'\\' {
                    self.step = St::InStringEsc;
                    return SCAN_CONTINUE;
                }
                if c < 0x20 {
                    return self.error(c, "in string literal");
                }
                SCAN_CONTINUE
            }
            St::InStringEsc => match c {
                b'b' | b'f' | b'n' | b'r' | b't' | b'\\' | b'/' | b'"' => {
                    self.step = St::InString;
                    SCAN_CONTINUE
                }
                b'u' => {
                    self.step = St::InStringEscU;
                    SCAN_CONTINUE
                }
                _ => self.error(c, "in string escape code"),
            },
            St::InStringEscU | St::InStringEscU1 | St::InStringEscU12 | St::InStringEscU123 => {
                if c.is_ascii_hexdigit() {
                    self.step = match self.step {
                        St::InStringEscU => St::InStringEscU1,
                        St::InStringEscU1 => St::InStringEscU12,
                        St::InStringEscU12 => St::InStringEscU123,
                        _ => St::InString,
                    };
                    return SCAN_CONTINUE;
                }
                self.error(c, "in \\u hexadecimal character escape")
            }
            St::Neg => {
                if c == b'0' {
                    self.step = St::Zero;
                    return SCAN_CONTINUE;
                }
                if (b'1'..=b'9').contains(&c) {
                    self.step = St::One;
                    return SCAN_CONTINUE;
                }
                self.error(c, "in numeric literal")
            }
            St::One => {
                if c.is_ascii_digit() {
                    self.step = St::One;
                    return SCAN_CONTINUE;
                }
                self.state_zero(c)
            }
            St::Zero => self.state_zero(c),
            St::Dot => {
                if c.is_ascii_digit() {
                    self.step = St::Dot0;
                    return SCAN_CONTINUE;
                }
                self.error(c, "after decimal point in numeric literal")
            }
            St::Dot0 => {
                if c.is_ascii_digit() {
                    return SCAN_CONTINUE;
                }
                if c == b'e' || c == b'E' {
                    self.step = St::E;
                    return SCAN_CONTINUE;
                }
                self.state_end_value(c)
            }
            St::E => {
                if c == b'+' || c == b'-' {
                    self.step = St::ESign;
                    return SCAN_CONTINUE;
                }
                self.state_e_sign(c)
            }
            St::ESign => self.state_e_sign(c),
            St::E0 => {
                if c.is_ascii_digit() {
                    return SCAN_CONTINUE;
                }
                self.state_end_value(c)
            }
            St::T => self.literal(c, b'r', St::Tr, "in literal true (expecting 'r')"),
            St::Tr => self.literal(c, b'u', St::Tru, "in literal true (expecting 'u')"),
            St::Tru => self.literal(c, b'e', St::EndValue, "in literal true (expecting 'e')"),
            St::F => self.literal(c, b'a', St::Fa, "in literal false (expecting 'a')"),
            St::Fa => self.literal(c, b'l', St::Fal, "in literal false (expecting 'l')"),
            St::Fal => self.literal(c, b's', St::Fals, "in literal false (expecting 's')"),
            St::Fals => self.literal(c, b'e', St::EndValue, "in literal false (expecting 'e')"),
            St::N => self.literal(c, b'u', St::Nu, "in literal null (expecting 'u')"),
            St::Nu => self.literal(c, b'l', St::Nul, "in literal null (expecting 'l')"),
            St::Nul => self.literal(c, b'l', St::EndValue, "in literal null (expecting 'l')"),
            St::Error => SCAN_ERROR,
        }
    }

    fn literal(&mut self, c: u8, want: u8, next: St, ctx: &str) -> i32 {
        if c == want {
            self.step = next;
            return SCAN_CONTINUE;
        }
        self.error(c, ctx)
    }

    fn state_e_sign(&mut self, c: u8) -> i32 {
        if c.is_ascii_digit() {
            self.step = St::E0;
            return SCAN_CONTINUE;
        }
        self.error(c, "in exponent of numeric literal")
    }

    fn state_zero(&mut self, c: u8) -> i32 {
        if c == b'.' {
            self.step = St::Dot;
            return SCAN_CONTINUE;
        }
        if c == b'e' || c == b'E' {
            self.step = St::E;
            return SCAN_CONTINUE;
        }
        self.state_end_value(c)
    }

    fn state_begin_value(&mut self, c: u8) -> i32 {
        if is_space(c) {
            return SCAN_SKIP_SPACE;
        }
        match c {
            b'{' => {
                self.step = St::BeginStringOrEmpty;
                return self.push_parse_state(c, PARSE_OBJECT_KEY, SCAN_BEGIN_OBJECT);
            }
            b'[' => {
                self.step = St::BeginValueOrEmpty;
                return self.push_parse_state(c, PARSE_ARRAY_VALUE, SCAN_BEGIN_ARRAY);
            }
            b'"' => {
                self.step = St::InString;
                return SCAN_BEGIN_LITERAL;
            }
            b'-' => {
                self.step = St::Neg;
                return SCAN_BEGIN_LITERAL;
            }
            b'0' => {
                self.step = St::Zero;
                return SCAN_BEGIN_LITERAL;
            }
            b't' => {
                self.step = St::T;
                return SCAN_BEGIN_LITERAL;
            }
            b'f' => {
                self.step = St::F;
                return SCAN_BEGIN_LITERAL;
            }
            b'n' => {
                self.step = St::N;
                return SCAN_BEGIN_LITERAL;
            }
            _ => {}
        }
        if (b'1'..=b'9').contains(&c) {
            self.step = St::One;
            return SCAN_BEGIN_LITERAL;
        }
        self.error(c, "looking for beginning of value")
    }

    fn state_begin_string(&mut self, c: u8) -> i32 {
        if is_space(c) {
            return SCAN_SKIP_SPACE;
        }
        if c == b'"' {
            self.step = St::InString;
            return SCAN_BEGIN_LITERAL;
        }
        self.error(c, "looking for beginning of object key string")
    }

    fn state_end_value(&mut self, c: u8) -> i32 {
        let n = self.parse_state.len();
        if n == 0 {
            // Completed top-level before the current byte.
            self.step = St::EndTop;
            self.end_top = true;
            if !is_space(c) {
                self.error(c, "after top-level value");
            }
            return SCAN_END;
        }
        if is_space(c) {
            self.step = St::EndValue;
            return SCAN_SKIP_SPACE;
        }
        match self.parse_state[n - 1] {
            PARSE_OBJECT_KEY => {
                if c == b':' {
                    self.parse_state[n - 1] = PARSE_OBJECT_VALUE;
                    self.step = St::BeginValue;
                    return SCAN_OBJECT_KEY;
                }
                self.error(c, "after object key")
            }
            PARSE_OBJECT_VALUE => {
                if c == b',' {
                    self.parse_state[n - 1] = PARSE_OBJECT_KEY;
                    self.step = St::BeginString;
                    return SCAN_OBJECT_VALUE;
                }
                if c == b'}' {
                    self.pop_parse_state();
                    return SCAN_END_OBJECT;
                }
                self.error(c, "after object key:value pair")
            }
            PARSE_ARRAY_VALUE => {
                if c == b',' {
                    self.step = St::BeginValue;
                    return SCAN_ARRAY_VALUE;
                }
                if c == b']' {
                    self.pop_parse_state();
                    return SCAN_END_ARRAY;
                }
                self.error(c, "after array element")
            }
            _ => self.error(c, ""),
        }
    }
}

/// Compacts the JSON in `src` onto `dst`, escaping HTML-sensitive characters
/// when asked; the error is the text of Go's `*json.SyntaxError`.
pub(crate) fn append_compact(dst: &mut Vec<u8>, src: &[u8], escape: bool) -> Result<(), String> {
    let orig_len = dst.len();
    let mut scan = Scanner::new();
    let mut start = 0;
    for (i, &c) in src.iter().enumerate() {
        if escape && (c == b'<' || c == b'>' || c == b'&') {
            if start < i {
                dst.extend_from_slice(&src[start..i]);
            }
            dst.extend_from_slice(b"\\u00");
            dst.push(HEX[usize::from(c >> 4)]);
            dst.push(HEX[usize::from(c & 0xF)]);
            start = i + 1;
        }
        // Convert U+2028 and U+2029 (E2 80 A8 and E2 80 A9).
        if escape && c == 0xE2 && i + 2 < src.len() && src[i + 1] == 0x80 && src[i + 2] & !1 == 0xA8
        {
            if start < i {
                dst.extend_from_slice(&src[start..i]);
            }
            dst.extend_from_slice(b"\\u202");
            dst.push(HEX[usize::from(src[i + 2] & 0xF)]);
            start = i + 3;
        }
        let v = scan.step(c);
        if v >= SCAN_SKIP_SPACE {
            if v == SCAN_ERROR {
                break;
            }
            if start < i {
                dst.extend_from_slice(&src[start..i]);
            }
            start = i + 1;
        }
    }
    if scan.eof() == SCAN_ERROR {
        dst.truncate(orig_len);
        return Err(scan.err.unwrap_or_default());
    }
    if start < src.len() {
        dst.extend_from_slice(&src[start..]);
    }
    Ok(())
}
