//! `Decoder` and `Encoder`: streams of JSON values and tokens.
//!
//! Go 1.27 implements `Decoder` on top of the `jsontext` token reader, so its
//! observable behaviour (the bytes `Buffered` returns, `InputOffset`, error
//! text and offsets) follows that reader rather than the older hand-written
//! stream scanner. This is a port of the parts of `jsontext.Decoder` the
//! `encoding/json` v1 wrapper uses, together with the wrapper's own glue.
use std::io::{self, Read, Write};

use super::{
    decode::{parse_node, root_context, unquote},
    encode::marshal_with,
    errors::{invalid_text, quote_rune_at},
    indent::append_indent,
    DecodeState, Deserialize, Error, Number, Serialize, SyntaxError, UnmarshalTypeError,
};

const MAX_NESTING_DEPTH: usize = 10000;

/// A JSON delimiter token: one of `[`, `]`, `{`, `}` (Go's `Delim`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Delim(pub char);

impl std::fmt::Display for Delim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A token of a JSON stream (Go's `Token`): a [`Delim`], a boolean, a number
/// (`Float64`, or `Number` after `use_number`), a string, or null.
#[derive(Clone, Debug, PartialEq)]
pub enum Token {
    Delim(Delim),
    Bool(bool),
    Float64(f64),
    Number(Number),
    String(String),
    Null,
}

/// Why a read failed, before it is turned into a Go-style error.
enum Cause {
    Eof,
    UnexpectedEof,
    Io(io::Error),
    /// `jsonwire.InvalidTextError`.
    Invalid {
        label: &'static str,
        what: Vec<u8>,
        place: String,
    },
    /// One of the state machine's fixed messages.
    Msg(&'static str),
}

const ERR_NON_STRING_NAME: &str = "object member name must be a string";
const ERR_MISSING_VALUE: &str = "missing value after object name";
const ERR_MISMATCH_DELIM: &str = "mismatching structural token for object or array";
const ERR_MAX_DEPTH: &str = "exceeded max depth";

/// A read error after offsets are attached (`wrapSyntacticError`).
enum Failure {
    Eof,
    Io(io::Error),
    Syntax {
        offset: i64,
        unexpected_eof: bool,
        message: String,
    },
}

type Step<T> = Result<T, (usize, Cause)>;

#[derive(Clone, Copy)]
struct Entry {
    object: bool,
    count: u64,
}
impl Entry {
    fn need_object_name(self) -> bool {
        self.object && self.count.is_multiple_of(2)
    }
    fn need_object_value(self) -> bool {
        self.object && self.count % 2 == 1
    }
    fn need_implicit_comma(self, next: u8) -> bool {
        !self.need_object_value() && self.count > 0 && next != b'}' && next != b']'
    }
}

fn normalize(c: u8) -> u8 {
    match c {
        b'-' | b'0'..=b'9' => b'0',
        c => c,
    }
}

fn whitespace(b: &[u8]) -> usize {
    b.iter()
        .take_while(|c| matches!(c, b' ' | b'\t' | b'\r' | b'\n'))
        .count()
}

/// The first rune of `rest` (or its first byte, if invalid).
fn first_rune(rest: &[u8]) -> Vec<u8> {
    let (_, n) = crate::unicode::rune::decode_rune(rest);
    rest[..n.min(rest.len())].to_vec()
}

fn invalid_char(rest: &[u8], place: &str) -> Cause {
    Cause::Invalid {
        label: "character",
        what: first_rune(rest),
        place: place.to_string(),
    }
}

/// `jsonwire.ConsumeLiteral`: how much of `lit` matches at the start of
/// `rest`, and why matching stopped if it did not complete.
fn literal_prefix(rest: &[u8], lit: &[u8]) -> (usize, Option<Cause>) {
    for i in 0..rest.len().min(lit.len()) {
        if rest[i] != lit[i] {
            let place = format!(
                "in literal {} (expecting {})",
                String::from_utf8_lossy(lit),
                quote_rune_at(&lit[i..]).0
            );
            return (i, Some(invalid_char(&rest[i..], &place)));
        }
    }
    if rest.len() < lit.len() {
        return (rest.len(), Some(Cause::UnexpectedEof));
    }
    (lit.len(), None)
}

fn parse_hex_u16(b: &[u8]) -> Option<u16> {
    if b.len() != 4 {
        return None;
    }
    let mut v = 0u16;
    for &c in b {
        v = v * 16 + (c as char).to_digit(16)? as u16;
    }
    Some(v)
}

/// `jsonwire.hasEscapedUTF16Prefix` for the first (non-low-surrogate) case.
fn has_escaped_utf16_prefix(b: &[u8]) -> bool {
    for (i, &c) in b.iter().enumerate() {
        match c {
            _ if i == 0 && c != b'\\' => return false,
            _ if i == 1 && c != b'u' => return false,
            _ if (2..6).contains(&i) && !c.is_ascii_hexdigit() => return false,
            _ => {}
        }
    }
    true
}

/// `jsonwire.ConsumeStringResumable` (invalid UTF-8 allowed).
fn consume_string(b: &[u8], resume: usize) -> (usize, Option<Cause>) {
    let mut n;
    if resume > 0 {
        n = resume;
    } else if b.is_empty() {
        return (0, Some(Cause::UnexpectedEof));
    } else if b[0] == b'"' {
        n = 1;
    } else {
        return (
            0,
            Some(invalid_char(b, "at start of string (expecting '\"')")),
        );
    }
    while b.len() > n {
        while b.len() > n && b[n] < 0x80 && b[n] >= b' ' && b[n] != b'\\' && b[n] != b'"' {
            n += 1;
        }
        if b.len() <= n {
            return (n, Some(Cause::UnexpectedEof));
        }
        if b[n] == b'"' {
            return (n + 1, None);
        }
        let (r, rn) = crate::unicode::rune::decode_rune(&b[n..]);
        if rn > 1 {
            n += rn;
        } else if r == i32::from(b'\\') {
            let resume_at = n;
            if b.len() < n + 2 {
                return (resume_at, Some(Cause::UnexpectedEof));
            }
            match b[n + 1] {
                b'/' | b'"' | b'\\' | b'b' | b'f' | b'n' | b'r' | b't' => n += 2,
                b'u' => {
                    if b.len() < n + 6 {
                        if has_escaped_utf16_prefix(&b[n..]) {
                            return (resume_at, Some(Cause::UnexpectedEof));
                        }
                        return (n, Some(escape_error(&b[n..])));
                    }
                    if parse_hex_u16(&b[n + 2..n + 6]).is_none() {
                        return (n, Some(escape_error(&b[n..n + 6])));
                    }
                    n += 6;
                }
                _ => return (n, Some(escape_error(&b[n..n + 2]))),
            }
        } else if r == 0xFFFD {
            if !crate::unicode::rune::full_rune(&b[n..]) {
                return (n, Some(Cause::UnexpectedEof));
            }
            n += 1;
        } else if r < i32::from(b' ') {
            return (
                n,
                Some(invalid_char(
                    &b[n..],
                    "in string (expecting non-control character)",
                )),
            );
        } else {
            n += 1;
        }
    }
    (n, Some(Cause::UnexpectedEof))
}

fn escape_error(what: &[u8]) -> Cause {
    Cause::Invalid {
        label: if what.len() > 6 {
            "surrogate pair"
        } else {
            "escape sequence"
        },
        what: what.to_vec(),
        place: "in string".into(),
    }
}

/// `jsonwire.ConsumeSimpleString`: a string without escapes or non-ASCII.
fn consume_simple_string(b: &[u8]) -> usize {
    if b.first() == Some(&b'"') {
        let mut n = 1;
        while n < b.len() && b[n] < 0x80 && b[n] >= b' ' && b[n] != b'\\' && b[n] != b'"' {
            n += 1;
        }
        if n < b.len() && b[n] == b'"' {
            return n + 1;
        }
    }
    0
}

/// `jsonwire.ConsumeSimpleNumber`.
fn consume_simple_number(b: &[u8]) -> usize {
    let mut n = 1;
    match b.first() {
        Some(b'0') => {}
        Some(b'1'..=b'9') => {
            while b.get(n).is_some_and(u8::is_ascii_digit) {
                n += 1;
            }
        }
        _ => return 0,
    }
    if n >= b.len() || !matches!(b[n], b'.' | b'e' | b'E') {
        return n;
    }
    0
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum NumState {
    Init,
    BeforeInteger,
    WithinInteger,
    BeforeFraction,
    WithinFraction,
    BeforeExponent,
    WithinExponent,
    Done,
}

/// `jsonwire.ConsumeNumberResumable`.
fn consume_number(b: &[u8], resume: usize, state: NumState) -> (usize, NumState, Option<Cause>) {
    use NumState::*;
    let mut n = resume;
    let mut state = state;
    let digit = |n: usize| b.get(n).is_some_and(u8::is_ascii_digit);
    // Where to continue: 0 = integer part, 1 = fraction, 2 = exponent.
    let mut stage = 0;
    if state > Init {
        if matches!(state, WithinInteger | WithinFraction | WithinExponent) {
            while digit(n) {
                n += 1;
            }
            if n >= b.len() {
                return (n, state, None);
            }
            state = match state {
                WithinInteger => BeforeFraction,
                WithinFraction => BeforeExponent,
                _ => Done,
            };
        }
        stage = match state {
            BeforeInteger => 0,
            BeforeFraction => 1,
            BeforeExponent => 2,
            _ => return (n, state, None),
        };
    }
    let mut resume_offset;
    if stage == 0 {
        resume_offset = n;
        if b.first() == Some(&b'-') {
            n += 1;
        }
        match b.get(n) {
            None => return (resume_offset, BeforeInteger, Some(Cause::UnexpectedEof)),
            Some(b'0') => {
                n += 1;
                state = BeforeFraction;
            }
            Some(b'1'..=b'9') => {
                n += 1;
                while digit(n) {
                    n += 1;
                }
                state = WithinInteger;
            }
            Some(_) => {
                return (
                    n,
                    state,
                    Some(invalid_char(&b[n..], "in number (expecting digit)")),
                );
            }
        }
    }
    if stage <= 1 && b.get(n) == Some(&b'.') {
        resume_offset = n;
        n += 1;
        match b.get(n) {
            None => return (resume_offset, BeforeFraction, Some(Cause::UnexpectedEof)),
            Some(b'0'..=b'9') => n += 1,
            Some(_) => {
                return (
                    n,
                    state,
                    Some(invalid_char(&b[n..], "in number (expecting digit)")),
                )
            }
        }
        while digit(n) {
            n += 1;
        }
        state = WithinFraction;
    }
    if matches!(b.get(n), Some(b'e' | b'E')) {
        resume_offset = n;
        n += 1;
        if matches!(b.get(n), Some(b'-' | b'+')) {
            n += 1;
        }
        match b.get(n) {
            None => return (resume_offset, BeforeExponent, Some(Cause::UnexpectedEof)),
            Some(b'0'..=b'9') => n += 1,
            Some(_) => {
                return (
                    n,
                    state,
                    Some(invalid_char(&b[n..], "in number (expecting digit)")),
                )
            }
        }
        while digit(n) {
            n += 1;
        }
        state = WithinExponent;
    }
    (n, state, None)
}

/// A port of `jsontext.Decoder` restricted to what the v1 `Decoder` needs.
struct Reader<R> {
    rd: R,
    buf: Vec<u8>,
    cap: usize,
    prev_start: usize,
    prev_end: usize,
    base: i64,
    peek_pos: usize,
    peek_err: Option<Failure>,
    stack: Vec<Entry>,
    last: Entry,
}

impl<R: Read> Reader<R> {
    fn new(rd: R) -> Self {
        Self {
            rd,
            buf: Vec::new(),
            cap: 0,
            prev_start: 0,
            prev_end: 0,
            base: 0,
            peek_pos: 0,
            peek_err: None,
            stack: Vec::new(),
            last: Entry {
                object: false,
                count: 0,
            },
        }
    }
    fn depth(&self) -> usize {
        self.stack.len() + 1
    }
    fn need_more(&self, pos: usize) -> bool {
        pos == self.buf.len()
    }
    fn need_delim(&self, next: u8) -> u8 {
        if self.last.need_object_value() {
            b':'
        } else if self.last.need_implicit_comma(next) && !self.stack.is_empty() {
            b','
        } else {
            0
        }
    }

    /// Reads more input, compacting or growing the buffer as `jsontext` does.
    fn fetch(&mut self) -> Result<(), Cause> {
        if self.cap == 0 {
            self.cap = 64;
        }
        const MAX_BUFFER_SIZE: usize = 4 << 10;
        let mut grow = self.cap <= MAX_BUFFER_SIZE / 2;
        grow = grow && (self.cap as i64) < (self.base + self.prev_end as i64) / 2;
        grow = grow || (self.prev_start == 0 && self.buf.len() >= 3 * self.cap / 4);
        if grow {
            self.cap *= 2;
        }
        self.buf.drain(..self.prev_start);
        self.base += self.prev_start as i64;
        self.prev_end -= self.prev_start;
        self.prev_start = 0;
        let len = self.buf.len();
        self.buf.resize(self.cap, 0);
        loop {
            match self.rd.read(&mut self.buf[len..self.cap]) {
                Ok(0) => {
                    self.buf.truncate(len);
                    return Err(Cause::UnexpectedEof);
                }
                Ok(n) => {
                    self.buf.truncate(len + n);
                    return Ok(());
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    self.buf.truncate(len);
                    return Err(Cause::Io(e));
                }
            }
        }
    }

    fn invalidate_previous_read(&mut self) {
        if self.prev_start < self.prev_end && self.prev_start < self.buf.len() {
            self.buf[self.prev_start] = b'#';
            self.prev_start = self.prev_end;
        }
    }

    /// Reads input until `pos` is a valid index, after dropping whitespace.
    fn consume_whitespace(&mut self, mut pos: usize) -> Step<usize> {
        loop {
            pos += whitespace(&self.buf[pos..]);
            if self.need_more(pos) {
                let abs = self.base + pos as i64;
                let r = self.fetch();
                pos = (abs - self.base) as usize;
                if let Err(c) = r {
                    return Err((pos, c));
                }
                continue;
            }
            return Ok(pos);
        }
    }

    /// `wrapSyntacticError` with the legacy offset rules of the v1 package.
    fn wrap(&self, cause: Cause, pos: usize) -> Failure {
        let (unexpected_eof, message, what_len) = match cause {
            Cause::Eof => return Failure::Eof,
            Cause::Io(e) => return Failure::Io(e),
            Cause::UnexpectedEof => (true, String::new(), None),
            Cause::Msg(m) if m == ERR_MISMATCH_DELIM => {
                let mut place = "at start of value";
                if !self.stack.is_empty() && self.last.count > 0 {
                    place = if self.last.object {
                        "after object value (expecting ',' or '}')"
                    } else {
                        "after array element (expecting ',' or ']')"
                    };
                }
                let what = first_rune(&self.buf[pos.min(self.buf.len())..]);
                (
                    false,
                    invalid_text("character", &what, place),
                    Some(what.len()),
                )
            }
            Cause::Msg(m) => (false, m.to_string(), None),
            Cause::Invalid { label, what, place } => {
                (false, invalid_text(label, &what, &place), Some(what.len()))
            }
        };
        let mut offset = self.base + pos as i64;
        if !unexpected_eof {
            offset += what_len.map_or(1, |n| n as i64);
        }
        Failure::Syntax {
            offset,
            unexpected_eof,
            message,
        }
    }

    fn peek_kind(&mut self) -> u8 {
        if self.peek_pos > 0 {
            return normalize(self.buf[self.peek_pos]);
        }
        self.invalidate_previous_read();
        let mut pos = self.prev_end;
        pos += whitespace(&self.buf[pos..]);
        if self.need_more(pos) {
            match self.consume_whitespace(pos) {
                Ok(p) => pos = p,
                Err((p, mut cause)) => {
                    if matches!(cause, Cause::UnexpectedEof) && self.depth() == 1 {
                        cause = Cause::Eof;
                    }
                    self.peek_pos = 0;
                    self.peek_err = Some(self.wrap(cause, p));
                    return 0;
                }
            }
        }
        let mut delim = 0;
        let c = self.buf[pos];
        if c == b':' || c == b',' {
            delim = c;
            pos += 1;
            pos += whitespace(&self.buf[pos..]);
            if self.need_more(pos) {
                match self.consume_whitespace(pos) {
                    Ok(p) => pos = p,
                    Err((p, cause)) => {
                        let failure = self.wrap(cause, p);
                        self.peek_pos = 0;
                        self.peek_err = Some(self.check_delim_before_io_error(delim, failure));
                        return 0;
                    }
                }
            }
        }
        let next = normalize(self.buf[pos]);
        if self.need_delim(next) != delim {
            self.peek_pos = 0;
            self.peek_err = Some(self.check_delim(delim, next));
            return 0;
        }
        self.peek_pos = pos;
        self.peek_err = None;
        next
    }

    fn check_delim_before_io_error(&self, delim: u8, failure: Failure) -> Failure {
        if self.need_delim(b'"') != delim {
            return self.check_delim(delim, b'"');
        }
        failure
    }

    fn check_delim(&self, delim: u8, next: u8) -> Failure {
        let place = match self.need_delim(next) {
            d if d == delim => "at start of value",
            b':' => "after object name (expecting ':')",
            b',' if self.last.object => "after object value (expecting ',' or '}')",
            b',' => "after array element (expecting ',' or ']')",
            _ => "at start of value",
        };
        let mut pos = self.prev_end;
        pos += whitespace(&self.buf[pos..]);
        self.wrap(invalid_char(&self.buf[pos..], place), pos)
    }

    fn append_literal(&mut self) -> Result<(), Cause> {
        if self.last.need_object_name() {
            return Err(Cause::Msg(ERR_NON_STRING_NAME));
        }
        self.last.count += 1;
        Ok(())
    }
    fn push(&mut self, object: bool) -> Result<(), Cause> {
        if self.last.need_object_name() {
            return Err(Cause::Msg(ERR_NON_STRING_NAME));
        }
        if self.stack.len() == MAX_NESTING_DEPTH {
            return Err(Cause::Msg(ERR_MAX_DEPTH));
        }
        self.last.count += 1;
        self.stack.push(self.last);
        self.last = Entry { object, count: 0 };
        Ok(())
    }
    fn pop(&mut self, object: bool) -> Result<(), Cause> {
        if self.last.object != object || (!object && self.stack.is_empty()) {
            return Err(Cause::Msg(ERR_MISMATCH_DELIM));
        }
        if object && self.last.need_object_value() {
            return Err(Cause::Msg(ERR_MISSING_VALUE));
        }
        self.last = self.stack.pop().expect("non-empty stack");
        Ok(())
    }

    fn consume_literal(&mut self, mut pos: usize, lit: &[u8]) -> Step<usize> {
        loop {
            let (n, cause) = literal_prefix(&self.buf[pos..], lit);
            match cause {
                Some(Cause::UnexpectedEof) => {
                    let abs = self.base + pos as i64;
                    let r = self.fetch();
                    pos = (abs - self.base) as usize;
                    if let Err(c) = r {
                        return Err((pos + n, c));
                    }
                }
                Some(c) => return Err((pos + n, c)),
                None => return Ok(pos + lit.len()),
            }
        }
    }

    fn consume_string_at(&mut self, mut pos: usize) -> Step<usize> {
        let mut n = 0;
        loop {
            let (used, cause) = consume_string(&self.buf[pos..], n);
            n = used;
            match cause {
                Some(Cause::UnexpectedEof) => {
                    let abs = self.base + pos as i64;
                    let r = self.fetch();
                    pos = (abs - self.base) as usize;
                    if let Err(c) = r {
                        return Err((pos + n, c));
                    }
                }
                Some(c) => return Err((pos + n, c)),
                None => return Ok(pos + n),
            }
        }
    }

    fn consume_number_at(&mut self, mut pos: usize) -> Step<usize> {
        let mut n = 0;
        let mut state = NumState::Init;
        loop {
            let (used, st, cause) = consume_number(&self.buf[pos..], n, state);
            n = used;
            state = st;
            let unexpected = matches!(cause, Some(Cause::UnexpectedEof));
            if unexpected || (cause.is_none() && self.need_more(pos + n)) {
                let may_terminate = cause.is_none();
                let abs = self.base + pos as i64;
                let r = self.fetch();
                pos = (abs - self.base) as usize;
                if let Err(c) = r {
                    if may_terminate && matches!(c, Cause::UnexpectedEof) {
                        return Ok(pos + n);
                    }
                    return Err((pos, c));
                }
                continue;
            }
            return match cause {
                Some(c) => Err((pos + n, c)),
                None => Ok(pos + n),
            };
        }
    }

    fn consume_value(&mut self, mut pos: usize, depth: usize) -> Step<usize> {
        loop {
            let next = normalize(self.buf[pos]);
            let (n, cause) = match next {
                b'n' | b'f' | b't' => {
                    let lit: &[u8] = match next {
                        b'n' => b"null",
                        b'f' => b"false",
                        _ => b"true",
                    };
                    literal_prefix(&self.buf[pos..], lit)
                }
                b'"' => {
                    let n = consume_simple_string(&self.buf[pos..]);
                    if n == 0 {
                        return self.consume_string_at(pos);
                    }
                    (n, None)
                }
                b'0' => {
                    let n = consume_simple_number(&self.buf[pos..]);
                    if n == 0 || self.need_more(pos + n) {
                        return self.consume_number_at(pos);
                    }
                    (n, None)
                }
                b'{' => return self.consume_object(pos, depth),
                b'[' => return self.consume_array(pos, depth),
                _ => {
                    if (self.last.object && next == b']') || (!self.last.object && next == b'}') {
                        return Err((pos, Cause::Msg(ERR_MISMATCH_DELIM)));
                    }
                    return Err((pos, invalid_char(&self.buf[pos..], "at start of value")));
                }
            };
            match cause {
                Some(Cause::UnexpectedEof) => {
                    let abs = self.base + pos as i64;
                    let r = self.fetch();
                    pos = (abs - self.base) as usize;
                    if let Err(c) = r {
                        return Err((pos + n, c));
                    }
                }
                Some(c) => return Err((pos + n, c)),
                None => return Ok(pos + n),
            }
        }
    }

    fn skip_space_fetch(&mut self, mut pos: usize) -> Step<usize> {
        pos += whitespace(&self.buf[pos..]);
        if self.need_more(pos) {
            pos = self.consume_whitespace(pos)?;
        }
        Ok(pos)
    }

    fn consume_object(&mut self, mut pos: usize, mut depth: usize) -> Step<usize> {
        if depth == MAX_NESTING_DEPTH + 1 {
            return Err((pos, Cause::Msg(ERR_MAX_DEPTH)));
        }
        pos += 1;
        pos = self.skip_space_fetch(pos)?;
        if self.buf[pos] == b'}' {
            return Ok(pos + 1);
        }
        depth += 1;
        loop {
            pos = self.skip_space_fetch(pos)?;
            let n = consume_simple_string(&self.buf[pos..]);
            if n == 0 {
                pos = self.consume_string_at(pos)?;
            } else {
                pos += n;
            }
            pos = self.skip_space_fetch(pos)?;
            if self.buf[pos] != b':' {
                return Err((
                    pos,
                    invalid_char(&self.buf[pos..], "after object name (expecting ':')"),
                ));
            }
            pos += 1;
            pos = self.skip_space_fetch(pos)?;
            pos = self.consume_value(pos, depth)?;
            pos = self.skip_space_fetch(pos)?;
            match self.buf[pos] {
                b',' => pos += 1,
                b'}' => return Ok(pos + 1),
                _ => {
                    return Err((
                        pos,
                        invalid_char(
                            &self.buf[pos..],
                            "after object value (expecting ',' or '}')",
                        ),
                    ))
                }
            }
        }
    }

    fn consume_array(&mut self, mut pos: usize, mut depth: usize) -> Step<usize> {
        if depth == MAX_NESTING_DEPTH + 1 {
            return Err((pos, Cause::Msg(ERR_MAX_DEPTH)));
        }
        pos += 1;
        pos = self.skip_space_fetch(pos)?;
        if self.buf[pos] == b']' {
            return Ok(pos + 1);
        }
        depth += 1;
        loop {
            pos = self.skip_space_fetch(pos)?;
            pos = self.consume_value(pos, depth)?;
            pos = self.skip_space_fetch(pos)?;
            match self.buf[pos] {
                b',' => pos += 1,
                b']' => return Ok(pos + 1),
                _ => {
                    return Err((
                        pos,
                        invalid_char(
                            &self.buf[pos..],
                            "after array element (expecting ',' or ']')",
                        ),
                    ))
                }
            }
        }
    }

    /// Positions the reader at the start of the next token or value and
    /// returns its first byte.
    fn begin(&mut self) -> Result<(usize, u8), Failure> {
        let pos = self.peek_pos;
        if pos != 0 {
            if let Some(e) = self.peek_err.take() {
                self.peek_pos = 0;
                return Err(e);
            }
            let next = normalize(self.buf[pos]);
            self.peek_pos = 0;
            return Ok((pos, next));
        }
        self.invalidate_previous_read();
        let mut pos = self.prev_end;
        pos += whitespace(&self.buf[pos..]);
        if self.need_more(pos) {
            match self.consume_whitespace(pos) {
                Ok(p) => pos = p,
                Err((p, mut cause)) => {
                    if matches!(cause, Cause::UnexpectedEof) && self.depth() == 1 {
                        cause = Cause::Eof;
                    }
                    return Err(self.wrap(cause, p));
                }
            }
        }
        let mut delim = 0;
        let c = self.buf[pos];
        if c == b':' || c == b',' {
            delim = c;
            pos += 1;
            pos += whitespace(&self.buf[pos..]);
            if self.need_more(pos) {
                match self.consume_whitespace(pos) {
                    Ok(p) => pos = p,
                    Err((p, cause)) => {
                        let failure = self.wrap(cause, p);
                        return Err(self.check_delim_before_io_error(delim, failure));
                    }
                }
            }
        }
        let next = normalize(self.buf[pos]);
        if self.need_delim(next) != delim {
            return Err(self.check_delim(delim, next));
        }
        Ok((pos, next))
    }

    /// `ReadToken`: returns the kind of token read.
    fn read_token(&mut self) -> Result<u8, Failure> {
        let (mut pos, next) = self.begin()?;
        match next {
            b'n' | b'f' | b't' => {
                let lit: &[u8] = match next {
                    b'n' => b"null",
                    b'f' => b"false",
                    _ => b"true",
                };
                if self.buf[pos..].starts_with(lit) {
                    pos += lit.len();
                } else {
                    match self.consume_literal(pos, lit) {
                        Ok(p) => pos = p,
                        Err((p, c)) => return Err(self.wrap(c, p)),
                    }
                }
                if let Err(c) = self.append_literal() {
                    return Err(self.wrap(c, pos - lit.len()));
                }
                self.prev_start = pos;
                self.prev_end = pos;
                Ok(next)
            }
            b'"' => {
                let n = consume_simple_string(&self.buf[pos..]);
                let n = if n == 0 {
                    let old = self.base + pos as i64;
                    match self.consume_string_at(pos) {
                        Ok(p) => {
                            let n = (self.base + p as i64 - old) as usize;
                            pos = p;
                            n
                        }
                        Err((p, c)) => return Err(self.wrap(c, p)),
                    }
                } else {
                    pos += n;
                    n
                };
                self.last.count += 1;
                self.prev_start = pos - n;
                self.prev_end = pos;
                Ok(next)
            }
            b'0' => {
                let mut n = consume_simple_number(&self.buf[pos..]);
                if n == 0 || self.need_more(pos + n) {
                    let old = self.base + pos as i64;
                    match self.consume_number_at(pos) {
                        Ok(p) => {
                            n = (self.base + p as i64 - old) as usize;
                            pos = p;
                        }
                        Err((p, c)) => return Err(self.wrap(c, p)),
                    }
                } else {
                    pos += n;
                }
                if let Err(c) = self.append_literal() {
                    return Err(self.wrap(c, pos - n));
                }
                self.prev_start = pos - n;
                self.prev_end = pos;
                Ok(next)
            }
            b'{' | b'[' => {
                if let Err(c) = self.push(next == b'{') {
                    return Err(self.wrap(c, pos));
                }
                self.prev_start = pos + 1;
                self.prev_end = pos + 1;
                Ok(next)
            }
            b'}' | b']' => {
                if let Err(c) = self.pop(next == b'}') {
                    return Err(self.wrap(c, pos));
                }
                self.prev_start = pos + 1;
                self.prev_end = pos + 1;
                Ok(next)
            }
            _ => {
                let c = invalid_char(&self.buf[pos..], "at start of value");
                Err(self.wrap(c, pos))
            }
        }
    }

    /// `ReadValue`: returns the start and end of the value in the buffer.
    fn read_value(&mut self) -> Result<(usize, usize), Failure> {
        let (pos, next) = self.begin()?;
        let old = self.base + pos as i64;
        let depth = self.depth();
        let pos = match self.consume_value(pos, depth) {
            Ok(p) => p,
            Err((p, c)) => return Err(self.wrap(c, p)),
        };
        let n = (self.base + pos as i64 - old) as usize;
        let appended = match next {
            b'n' | b't' | b'f' | b'0' => self.append_literal(),
            b'"' => {
                self.last.count += 1;
                Ok(())
            }
            b'{' | b'[' => self
                .push(next == b'{')
                .and_then(|()| self.pop(next == b'{')),
            _ => Ok(()),
        };
        if let Err(c) = appended {
            return Err(self.wrap(c, pos - n));
        }
        self.prev_end = pos;
        self.prev_start = pos - n;
        Ok((pos - n, pos))
    }
}

/// The error `jsonwire.AppendUnquote` reports for `text` used as a string
/// literal, worded as the v1 package words syntax errors.
pub(crate) fn string_literal_error(text: &[u8]) -> Option<String> {
    let cause = if text.is_empty() {
        Some(Cause::UnexpectedEof)
    } else if text[0] != b'"' {
        Some(invalid_char(text, "at start of string (expecting '\"')"))
    } else {
        match consume_string(text, 0) {
            (_, Some(cause)) => Some(cause),
            (n, None) if n < text.len() => Some(invalid_char(&text[n..], "after string value")),
            _ => None,
        }
    }?;
    let failure = match cause {
        Cause::UnexpectedEof => Failure::Syntax {
            offset: 0,
            unexpected_eof: true,
            message: String::new(),
        },
        Cause::Invalid { label, what, place } => Failure::Syntax {
            offset: 0,
            unexpected_eof: false,
            message: invalid_text(label, &what, &place),
        },
        _ => return None,
    };
    Some(transform(failure).to_string())
}

/// Go's `transformSyntacticError`.
fn transform(failure: Failure) -> Error {
    match failure {
        Failure::Eof => Error::Eof,
        Failure::Io(e) => Error::Io(e),
        Failure::Syntax {
            offset,
            unexpected_eof,
            message,
        } => {
            let mut msg = if unexpected_eof {
                "unexpected end of JSON input".to_string()
            } else {
                message
            };
            if let Some(i) = msg.find(" (expecting") {
                if !msg.contains(" in literal") {
                    msg.truncate(i);
                }
            }
            let msg = msg
                .replace("object name", "object key")
                .replace("at start of value", "looking for beginning of value")
                .replace(
                    "at start of string",
                    "looking for beginning of object key string",
                )
                .replace("after object value", "after object key:value pair")
                .replace("in number", "in numeric literal");
            Error::SyntaxError(SyntaxError::new(msg, offset))
        }
    }
}

fn unexpected_eof() -> Error {
    Error::Io(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "unexpected EOF",
    ))
}

/// Duplicates a sticky error (Go errors are values; ours are not `Clone`).
fn duplicate(e: &Error) -> Error {
    match e {
        Error::Eof => Error::Eof,
        Error::SyntaxError(s) => Error::SyntaxError(s.clone()),
        Error::Io(io) => Error::Io(io::Error::new(io.kind(), io.to_string())),
        other => Error::Other(other.to_string()),
    }
}

/// Reads a stream of JSON values (Go's `Decoder`).
pub struct Decoder<R> {
    core: Reader<R>,
    cx: DecodeState,
    err: Option<Error>,
    had_peeked: bool,
    had_eof: bool,
}

impl<R: Read> Decoder<R> {
    /// Returns a decoder reading from `r`. It buffers its own reads, so the
    /// decoder may read beyond the values it returns.
    pub fn new(r: R) -> Self {
        Self {
            core: Reader::new(r),
            cx: DecodeState::default(),
            err: None,
            had_peeked: false,
            had_eof: false,
        }
    }
    /// Decodes JSON numbers into [`Number`] rather than `f64`.
    pub fn use_number(&mut self) {
        self.cx.use_number = true;
    }
    /// Makes decoding fail when the destination struct has no field for an
    /// object key.
    pub fn disallow_unknown_fields(&mut self) {
        self.cx.disallow_unknown_fields = true;
    }
    /// Reads the next JSON value and decodes it into a `T`. At the end of the
    /// input it returns [`Error::Eof`].
    pub fn decode<T: Deserialize>(&mut self) -> Result<T, Error> {
        let node_data = self.next_value()?;
        let node = parse_node(&node_data)?;
        let mut cx = self.cx;
        T::unmarshal_json(&node, &mut cx).map_err(root_context::<T>)
    }
    /// Like [`decode`](Self::decode), but decodes into an existing value with
    /// Go's merge rules (see [`unmarshal_into`](super::unmarshal_into)).
    pub fn decode_into<T: Deserialize>(&mut self, v: &mut T) -> Result<(), Error> {
        let data = self.next_value()?;
        let node = parse_node(&data)?;
        let mut cx = self.cx;
        v.unmarshal_json_into(&node, &mut cx)
            .map_err(root_context::<T>)
    }
    /// Reads the text of the next JSON value.
    fn next_value(&mut self) -> Result<Vec<u8>, Error> {
        if let Some(e) = &self.err {
            return Err(duplicate(e));
        }
        let (start, end) = match self.core.read_value() {
            Ok(range) => range,
            Err(failure) => {
                let mut e = transform(failure);
                if matches!(&e, Error::SyntaxError(s) if s.to_string() == "unexpected end of JSON input")
                {
                    e = unexpected_eof();
                }
                self.err = Some(duplicate(&e));
                return Err(e);
            }
        };
        self.had_peeked = false;
        self.had_eof = false;
        Ok(self.core.buf[start..end].to_vec())
    }
    /// The data remaining in the decoder's buffer.
    pub fn buffered(&self) -> &[u8] {
        &self.core.buf[self.core.prev_end.min(self.core.buf.len())..]
    }
    /// Returns the next JSON token. Delimiters and the punctuation between
    /// values are checked, and [`Error::Eof`] marks the end of the input.
    pub fn token(&mut self) -> Result<Token, Error> {
        if let Some(e) = &self.err {
            return Err(duplicate(e));
        }
        let kind = match self.core.read_token() {
            Ok(kind) => kind,
            Err(Failure::Syntax {
                unexpected_eof: true,
                ..
            }) => {
                let unread = &self.core.buf[self.core.prev_end..];
                let trimmed = unread
                    .iter()
                    .filter(|c| !matches!(c, b' ' | b'\r' | b'\n' | b'\t' | b',' | b':'))
                    .count();
                if trimmed == 0 {
                    self.had_eof = true;
                    return Err(Error::Eof);
                }
                return Err(unexpected_eof());
            }
            Err(failure) => return Err(transform(failure)),
        };
        self.had_peeked = false;
        self.had_eof = false;
        let raw = &self.core.buf[self.core.prev_start..self.core.prev_end];
        Ok(match kind {
            b'n' => Token::Null,
            b'f' => Token::Bool(false),
            b't' => Token::Bool(true),
            b'"' => Token::String(unquote(raw)),
            b'0' => {
                let text = String::from_utf8_lossy(raw).into_owned();
                if self.cx.use_number {
                    Token::Number(Number(text))
                } else {
                    match text.parse::<f64>() {
                        Ok(f) if f.is_finite() => Token::Float64(f),
                        _ => {
                            return Err(Error::UnmarshalType(UnmarshalTypeError {
                                value: format!("number {text}"),
                                type_name: "float64".into(),
                                offset: self.input_offset(),
                                ..UnmarshalTypeError::default()
                            }))
                        }
                    }
                }
            }
            c => Token::Delim(Delim(c as char)),
        })
    }
    /// Reports whether there is another element in the current array or
    /// object being parsed.
    pub fn more(&mut self) -> bool {
        self.had_peeked = true;
        let k = self.core.peek_kind();
        if k == 0 {
            if self.err.is_none() {
                let err = match self.core.read_token() {
                    Err(failure) => transform(failure),
                    Ok(_) => Error::Other("json: successful read after failed peek".into()),
                };
                self.err = Some(err);
            }
            return !matches!(self.err, Some(Error::Eof));
        }
        k != b']' && k != b'}'
    }
    /// The input stream offset of the end of the most recently returned token
    /// or value (allowing for whitespace skipped by `more`).
    pub fn input_offset(&self) -> i64 {
        let mut offset = self.core.base + self.core.prev_end as i64;
        if self.had_peeked || self.had_eof {
            let unread = &self.core.buf[self.core.prev_end.min(self.core.buf.len())..];
            let skipped = whitespace(unread);
            let trailing = &unread[skipped..];
            if !trailing.is_empty() {
                offset += skipped as i64;
                if self.had_eof && (trailing[0] == b',' || trailing[0] == b':') {
                    offset += 1;
                }
            }
        }
        offset
    }
}

/// Writes JSON values to an output stream (Go's `Encoder`).
pub struct Encoder<W> {
    w: W,
    err: Option<Error>,
    escape_html: bool,
    indent_prefix: String,
    indent_value: String,
}

impl<W: Write> Encoder<W> {
    pub fn new(w: W) -> Self {
        Self {
            w,
            err: None,
            escape_html: true,
            indent_prefix: String::new(),
            indent_value: String::new(),
        }
    }
    /// Writes the JSON encoding of `v` followed by a newline.
    pub fn encode<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), Error> {
        if let Some(e) = &self.err {
            return Err(duplicate(e));
        }
        let b = marshal_with(v, self.escape_html)?;
        let mut out = if self.indent_prefix.is_empty() && self.indent_value.is_empty() {
            b
        } else {
            let mut out = Vec::new();
            append_indent(&mut out, &b, &self.indent_prefix, &self.indent_value)?;
            out
        };
        out.push(b'\n');
        if let Err(e) = self.w.write_all(&out) {
            self.err = Some(Error::Io(io::Error::new(e.kind(), e.to_string())));
            return Err(Error::Io(e));
        }
        Ok(())
    }
    /// Makes each encoded value start on a new line with the given prefix,
    /// indented by `indent` per nesting level (as `indent` does).
    pub fn set_indent(&mut self, prefix: &str, indent: &str) {
        self.indent_prefix = prefix.to_string();
        self.indent_value = indent.to_string();
    }
    /// Specifies whether `<`, `>` and `&` are escaped; the default is true.
    pub fn set_escape_html(&mut self, on: bool) {
        self.escape_html = on;
    }
    /// The underlying writer.
    pub fn into_inner(self) -> W {
        self.w
    }
}
