//! Go's JSON scanner: an explicit state machine, so nesting depth is bounded
//! by Go's limit rather than the native stack and every entry point (`valid`,
//! `compact`, `indent`, `unmarshal`, `Decoder`) reports identical errors and
//! offsets. Ported from `encoding/json/scanner.go` (BSD-licensed, see NOTICE).
use super::errors::{invalid_text, quote_rune_at};
use super::SyntaxError;

// Scan results, in Go's order (`SCAN_SKIP_SPACE` and above stop the scanner).
pub(crate) const SCAN_CONTINUE: u8 = 0;
pub(crate) const SCAN_BEGIN_LITERAL: u8 = 1;
pub(crate) const SCAN_BEGIN_OBJECT: u8 = 2;
pub(crate) const SCAN_OBJECT_KEY: u8 = 3;
pub(crate) const SCAN_OBJECT_VALUE: u8 = 4;
pub(crate) const SCAN_END_OBJECT: u8 = 5;
pub(crate) const SCAN_BEGIN_ARRAY: u8 = 6;
pub(crate) const SCAN_ARRAY_VALUE: u8 = 7;
pub(crate) const SCAN_END_ARRAY: u8 = 8;
pub(crate) const SCAN_SKIP_SPACE: u8 = 9;
pub(crate) const SCAN_END: u8 = 10;
pub(crate) const SCAN_ERROR: u8 = 11;

const MAX_NESTING_DEPTH: usize = 10000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Parse {
    ObjectKey,
    ObjectValue,
    ArrayValue,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
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
    State1,
    State0,
    Dot,
    Dot0,
    E,
    ESign,
    E0,
    /// Inside a literal: which one (0 = true, 1 = false, 2 = null) and the
    /// index of the next expected byte.
    Lit(u8, u8),
    Error,
}

/// A deferred rewrite of the error just recorded, applied by [`Scanner::feed`]
/// once the bytes around the offending one are known.
enum Fix {
    /// Quote the whole UTF-8 sequence at the offending byte.
    Char(String),
    /// Describe the escape sequence starting `back` bytes earlier.
    Escape(usize),
}

pub(crate) struct Scanner {
    step: Step,
    fix: Option<Fix>,
    end_top: bool,
    parse_state: Vec<Parse>,
    pub(crate) err: Option<SyntaxError>,
    /// Bytes consumed so far, maintained by the caller as in Go.
    pub(crate) bytes: i64,
    /// Offset of the first byte of the number being scanned.
    num_start: i64,
    /// `Unmarshal` and `Decoder` call the elements of an array "elements" in
    /// syntax errors, `Compact` and `Indent` call them "values".
    pub(crate) array_element: bool,
}

pub(crate) fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n')
}

const LITERALS: [&[u8]; 3] = [b"true", b"false", b"null"];
const LITERAL_NAMES: [&str; 3] = ["true", "false", "null"];

impl Scanner {
    pub(crate) fn new() -> Self {
        Self {
            step: Step::BeginValue,
            fix: None,
            end_top: false,
            parse_state: Vec::new(),
            err: None,
            bytes: 0,
            num_start: 0,
            array_element: false,
        }
    }
    pub(crate) fn reset(&mut self) {
        self.step = Step::BeginValue;
        self.parse_state.clear();
        self.err = None;
        self.end_top = false;
    }

    /// Signals the end of input; `data` is everything that was fed. Go 1.27
    /// reports every truncated token as "unexpected end of JSON input"
    /// (classic Go complained about a space). The offset is the end of the last
    /// complete unit of the unfinished token; for numbers `number_start`
    /// selects between the token start (`Unmarshal`) and the end of the
    /// longest valid number prefix (`Compact`, `Indent`).
    pub(crate) fn eof(&mut self, data: &[u8], number_start: bool) -> u8 {
        if self.err.is_some() {
            return SCAN_ERROR;
        }
        if self.end_top {
            return SCAN_END;
        }
        let truncated = match self.step {
            Step::InString => Some(self.bytes - incomplete_rune_len(data)),
            Step::InStringEsc => Some(self.bytes - 1),
            Step::InStringEscU => Some(self.bytes - 2),
            Step::InStringEscU1 => Some(self.bytes - 3),
            Step::InStringEscU12 => Some(self.bytes - 4),
            Step::InStringEscU123 => Some(self.bytes - 5),
            Step::Neg => Some(self.num_start),
            Step::Dot | Step::E => Some(if number_start {
                self.num_start
            } else {
                self.bytes - 1
            }),
            Step::ESign => Some(if number_start {
                self.num_start
            } else {
                self.bytes - 2
            }),
            Step::Lit(..) => Some(self.bytes),
            _ => None,
        };
        if let Some(offset) = truncated {
            self.step = Step::Error;
            self.err = Some(SyntaxError::new("unexpected end of JSON input", offset));
            return SCAN_ERROR;
        }
        self.step(b' ');
        if self.end_top {
            return SCAN_END;
        }
        if self.err.is_none() {
            self.err = Some(SyntaxError::new("unexpected end of JSON input", self.bytes));
        }
        SCAN_ERROR
    }

    /// Feeds `data[i]`, counting it, and finishes any error description that
    /// needs the surrounding bytes (Go reports whole runes and escapes).
    pub(crate) fn feed(&mut self, data: &[u8], i: usize) -> u8 {
        self.bytes += 1;
        let result = self.step(data[i]);
        if let Some(fix) = self.fix.take() {
            match fix {
                Fix::Char(context) => {
                    let (quoted, width) = quote_rune_at(&data[i..]);
                    self.err = Some(SyntaxError::new(
                        format!("invalid character {quoted} {context}"),
                        self.bytes - 1 + width as i64,
                    ));
                }
                Fix::Escape(back) => {
                    let start = i - back;
                    let end = if back == 1 {
                        start + 2
                    } else {
                        data.len().min(start + 6)
                    };
                    let what = &data[start..end];
                    self.err = Some(SyntaxError::new(
                        invalid_text("escape sequence", what, "in string"),
                        end as i64,
                    ));
                }
            }
        }
        result
    }

    fn push(&mut self, state: Parse, success: u8) -> u8 {
        self.parse_state.push(state);
        if self.parse_state.len() <= MAX_NESTING_DEPTH {
            success
        } else {
            self.step = Step::Error;
            self.fix = None;
            self.err = Some(SyntaxError::new("exceeded max depth", self.bytes));
            SCAN_ERROR
        }
    }
    fn pop(&mut self) {
        self.parse_state.pop();
        if self.parse_state.is_empty() {
            self.step = Step::EndTop;
            self.end_top = true;
        } else {
            self.step = Step::EndValue;
        }
    }
    fn error(&mut self, c: u8, context: &str) -> u8 {
        self.step = Step::Error;
        self.err = Some(SyntaxError::new(
            format!("invalid character {} {}", quote_char(c), context),
            self.bytes,
        ));
        if c >= 0x80 {
            self.fix = Some(Fix::Char(context.to_string()));
        }
        SCAN_ERROR
    }
    fn escape_error(&mut self, back: usize) -> u8 {
        self.step = Step::Error;
        self.err = Some(SyntaxError::new("invalid escape sequence", self.bytes));
        self.fix = Some(Fix::Escape(back));
        SCAN_ERROR
    }

    /// Feeds one byte to the state machine.
    pub(crate) fn step(&mut self, c: u8) -> u8 {
        match self.step {
            Step::BeginValue => self.begin_value(c),
            Step::BeginValueOrEmpty => {
                if is_space(c) {
                    SCAN_SKIP_SPACE
                } else if c == b']' {
                    self.end_value(c)
                } else {
                    self.begin_value(c)
                }
            }
            Step::BeginStringOrEmpty => {
                if is_space(c) {
                    return SCAN_SKIP_SPACE;
                }
                if c == b'}' {
                    let n = self.parse_state.len();
                    self.parse_state[n - 1] = Parse::ObjectValue;
                    return self.end_value(c);
                }
                self.begin_string(c)
            }
            Step::BeginString => self.begin_string(c),
            Step::EndValue => self.end_value(c),
            Step::EndTop => {
                if !is_space(c) {
                    self.error(c, "after top-level value");
                }
                SCAN_END
            }
            Step::InString => {
                if c == b'"' {
                    self.step = Step::EndValue;
                    SCAN_CONTINUE
                } else if c == b'\\' {
                    self.step = Step::InStringEsc;
                    SCAN_CONTINUE
                } else if c < 0x20 {
                    self.error(c, "in string")
                } else {
                    SCAN_CONTINUE
                }
            }
            Step::InStringEsc => match c {
                b'b' | b'f' | b'n' | b'r' | b't' | b'\\' | b'/' | b'"' => {
                    self.step = Step::InString;
                    SCAN_CONTINUE
                }
                b'u' => {
                    self.step = Step::InStringEscU;
                    SCAN_CONTINUE
                }
                _ => self.escape_error(1),
            },
            Step::InStringEscU
            | Step::InStringEscU1
            | Step::InStringEscU12
            | Step::InStringEscU123 => {
                if c.is_ascii_hexdigit() {
                    self.step = match self.step {
                        Step::InStringEscU => Step::InStringEscU1,
                        Step::InStringEscU1 => Step::InStringEscU12,
                        Step::InStringEscU12 => Step::InStringEscU123,
                        _ => Step::InString,
                    };
                    SCAN_CONTINUE
                } else {
                    let back = match self.step {
                        Step::InStringEscU => 2,
                        Step::InStringEscU1 => 3,
                        Step::InStringEscU12 => 4,
                        _ => 5,
                    };
                    self.escape_error(back)
                }
            }
            Step::Neg => {
                if c == b'0' {
                    self.step = Step::State0;
                    SCAN_CONTINUE
                } else if (b'1'..=b'9').contains(&c) {
                    self.step = Step::State1;
                    SCAN_CONTINUE
                } else {
                    self.error(c, "in numeric literal")
                }
            }
            Step::State1 => {
                if c.is_ascii_digit() {
                    SCAN_CONTINUE
                } else {
                    self.state0(c)
                }
            }
            Step::State0 => self.state0(c),
            Step::Dot => {
                if c.is_ascii_digit() {
                    self.step = Step::Dot0;
                    SCAN_CONTINUE
                } else {
                    self.error(c, "in numeric literal")
                }
            }
            Step::Dot0 => {
                if c.is_ascii_digit() {
                    SCAN_CONTINUE
                } else if c == b'e' || c == b'E' {
                    self.step = Step::E;
                    SCAN_CONTINUE
                } else {
                    self.end_value(c)
                }
            }
            Step::E => {
                if c == b'+' || c == b'-' {
                    self.step = Step::ESign;
                    SCAN_CONTINUE
                } else {
                    self.e_sign(c)
                }
            }
            Step::ESign => self.e_sign(c),
            Step::E0 => {
                if c.is_ascii_digit() {
                    SCAN_CONTINUE
                } else {
                    self.end_value(c)
                }
            }
            Step::Lit(which, at) => {
                let word = LITERALS[which as usize];
                let want = word[at as usize];
                if c == want {
                    self.step = if at as usize + 1 == word.len() {
                        Step::EndValue
                    } else {
                        Step::Lit(which, at + 1)
                    };
                    SCAN_CONTINUE
                } else {
                    let context = format!(
                        "in literal {} (expecting '{}')",
                        LITERAL_NAMES[which as usize], want as char
                    );
                    self.error(c, &context)
                }
            }
            Step::Error => SCAN_ERROR,
        }
    }

    fn state0(&mut self, c: u8) -> u8 {
        if c == b'.' {
            self.step = Step::Dot;
            SCAN_CONTINUE
        } else if c == b'e' || c == b'E' {
            self.step = Step::E;
            SCAN_CONTINUE
        } else {
            self.end_value(c)
        }
    }
    fn e_sign(&mut self, c: u8) -> u8 {
        if c.is_ascii_digit() {
            self.step = Step::E0;
            SCAN_CONTINUE
        } else {
            self.error(c, "in numeric literal")
        }
    }
    fn begin_string(&mut self, c: u8) -> u8 {
        if is_space(c) {
            return SCAN_SKIP_SPACE;
        }
        if c == b'"' {
            self.step = Step::InString;
            return SCAN_BEGIN_LITERAL;
        }
        self.error(c, "looking for beginning of object key string")
    }
    fn begin_value(&mut self, c: u8) -> u8 {
        if is_space(c) {
            return SCAN_SKIP_SPACE;
        }
        match c {
            b'{' => {
                self.step = Step::BeginStringOrEmpty;
                self.push(Parse::ObjectKey, SCAN_BEGIN_OBJECT)
            }
            b'[' => {
                self.step = Step::BeginValueOrEmpty;
                self.push(Parse::ArrayValue, SCAN_BEGIN_ARRAY)
            }
            b'"' => {
                self.step = Step::InString;
                SCAN_BEGIN_LITERAL
            }
            b'-' => {
                self.num_start = self.bytes - 1;
                self.step = Step::Neg;
                SCAN_BEGIN_LITERAL
            }
            b'0' => {
                self.num_start = self.bytes - 1;
                self.step = Step::State0;
                SCAN_BEGIN_LITERAL
            }
            b't' => {
                self.step = Step::Lit(0, 1);
                SCAN_BEGIN_LITERAL
            }
            b'f' => {
                self.step = Step::Lit(1, 1);
                SCAN_BEGIN_LITERAL
            }
            b'n' => {
                self.step = Step::Lit(2, 1);
                SCAN_BEGIN_LITERAL
            }
            b'1'..=b'9' => {
                self.num_start = self.bytes - 1;
                self.step = Step::State1;
                SCAN_BEGIN_LITERAL
            }
            _ => self.error(c, "looking for beginning of value"),
        }
    }

    /// Go's `stateEndValue`; the stream decoder also calls it directly.
    pub(crate) fn end_value(&mut self, c: u8) -> u8 {
        let n = self.parse_state.len();
        if n == 0 {
            self.step = Step::EndTop;
            self.end_top = true;
            if !is_space(c) {
                self.error(c, "after top-level value");
            }
            return SCAN_END;
        }
        if is_space(c) {
            self.step = Step::EndValue;
            return SCAN_SKIP_SPACE;
        }
        match self.parse_state[n - 1] {
            Parse::ObjectKey => {
                if c == b':' {
                    self.parse_state[n - 1] = Parse::ObjectValue;
                    self.step = Step::BeginValue;
                    return SCAN_OBJECT_KEY;
                }
                self.error(c, "after object key")
            }
            Parse::ObjectValue => {
                if c == b',' {
                    self.parse_state[n - 1] = Parse::ObjectKey;
                    self.step = Step::BeginString;
                    return SCAN_OBJECT_VALUE;
                }
                if c == b'}' {
                    self.pop();
                    return SCAN_END_OBJECT;
                }
                self.error(c, "after object key:value pair")
            }
            Parse::ArrayValue => {
                if c == b',' {
                    self.step = Step::BeginValue;
                    return SCAN_ARRAY_VALUE;
                }
                if c == b']' {
                    self.pop();
                    return SCAN_END_ARRAY;
                }
                self.error(
                    c,
                    if self.array_element {
                        "after array element"
                    } else {
                        "after array value"
                    },
                )
            }
        }
    }
}

/// Quotes a single-byte (ASCII) character the way Go's error messages do.
pub(crate) fn quote_char(c: u8) -> String {
    quote_rune_at(&[c]).0
}

/// Length of a trailing, still-incomplete UTF-8 sequence in `data`, which Go
/// leaves out of the offset of an "unexpected end of JSON input" error.
fn incomplete_rune_len(data: &[u8]) -> i64 {
    for k in 1..=data.len().min(3) {
        let b = data[data.len() - k];
        if (0x80..0xc0).contains(&b) {
            continue;
        }
        if b >= 0xc2 && !crate::unicode::rune::full_rune(&data[data.len() - k..]) {
            return k as i64;
        }
        break;
    }
    0
}

/// Validates a whole document the way Go's `checkValid` does.
pub(crate) fn check_valid(data: &[u8], scan: &mut Scanner) -> Result<(), SyntaxError> {
    scan.array_element = true;
    scan.reset();
    scan.bytes = 0;
    for i in 0..data.len() {
        if scan.feed(data, i) == SCAN_ERROR {
            return Err(scan.err.take().expect("scanner error recorded"));
        }
    }
    if scan.eof(data, true) == SCAN_ERROR {
        return Err(scan.err.take().expect("scanner error recorded"));
    }
    Ok(())
}
