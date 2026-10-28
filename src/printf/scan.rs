//! Scanning (Go `fmt/scan.go`): `Scan`, `Scanf` and `Scanln` families over
//! typed destinations.

use std::io::{self, Read};
use std::sync::Arc;

use super::print::parsenum;
use crate::io::{is_eof, RuneReader, RuneScanner};
use crate::strconv::{self, NumError};
use crate::unicode::rune::{append_rune, decode_rune, full_rune, rune_len};

const EOF: i32 = -1;
const HUGE_WID: i64 = 1 << 30;

/// Why a scan stopped (the Go `error` value returned by the scan functions).
#[derive(Debug, Clone)]
pub enum ScanErrorKind {
    /// `io.EOF`
    Eof,
    /// `io.ErrUnexpectedEOF`
    UnexpectedEof,
    /// An error made by the scanner itself, such as `expected integer`.
    Message(String),
    /// A failed number conversion (`strconv.ParseInt: parsing "9": ...`).
    Num(NumError),
    /// A failed unquoting (`invalid syntax`).
    Strconv(strconv::Error),
    /// An error from a reader or from a custom [`Scanner`].
    Other(Arc<dyn std::error::Error + Send + Sync>),
}

impl ScanErrorKind {
    /// A scanner-made error with the given text.
    pub fn msg(s: impl Into<String>) -> ScanErrorKind {
        ScanErrorKind::Message(s.into())
    }

    /// Reports whether this is `io.EOF`.
    pub fn is_eof(&self) -> bool {
        matches!(self, ScanErrorKind::Eof)
    }
}

impl std::fmt::Display for ScanErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanErrorKind::Eof => f.write_str("EOF"),
            ScanErrorKind::UnexpectedEof => f.write_str("unexpected EOF"),
            ScanErrorKind::Message(s) => f.write_str(s),
            ScanErrorKind::Num(e) => e.fmt(f),
            ScanErrorKind::Strconv(e) => e.fmt(f),
            ScanErrorKind::Other(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ScanErrorKind {}

impl From<NumError> for ScanErrorKind {
    fn from(e: NumError) -> ScanErrorKind {
        ScanErrorKind::Num(e)
    }
}

/// The error of a failed scan: the number of items scanned before the
/// failure, as Go's `(n, err)` pair, and the reason.
#[derive(Debug, Clone)]
pub struct ScanError {
    /// The number of items successfully scanned.
    pub n: usize,
    /// Why scanning stopped.
    pub kind: ScanErrorKind,
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.kind.fmt(f)
    }
}

impl std::error::Error for ScanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.kind)
    }
}

type R<T> = Result<T, ScanErrorKind>;

/// The scanner state passed to custom scanners (Go `fmt.ScanState`).
/// `read` (from [`std::io::Read`]) always fails: use `read_rune`.
pub trait ScanState: Read {
    /// Go's `ReadRune`: the next rune and its size. Returns
    /// [`ScanErrorKind::Eof`] at the end of input (or after the first newline
    /// during `Scanln`, or beyond the width).
    fn read_rune(&mut self) -> R<(char, usize)>;
    /// Go's `UnreadRune`.
    fn unread_rune(&mut self) -> R<()>;
    /// Go's `SkipSpace`.
    fn skip_space(&mut self) -> R<()>;
    /// Go's `Token`: skips space if `skip_space`, then returns the run of
    /// runes satisfying `f` (non-space runes if `f` is `None`).
    fn token(&mut self, skip_space: bool, f: Option<&dyn Fn(char) -> bool>) -> R<Vec<u8>>;
    /// Go's `Width`: the width option, if set.
    fn width(&self) -> Option<usize>;
}

/// Implemented by values that scan their own representation (Go
/// `fmt.Scanner`).
pub trait Scanner {
    /// Go's `Scan(state, verb)`.
    fn scan(&mut self, state: &mut dyn ScanState, verb: char) -> R<()>;
}

/// A destination for scanned input: Go's pointer operands.
pub enum ScanArg<'a> {
    Bool(&'a mut bool),
    Int(&'a mut isize),
    Int8(&'a mut i8),
    Int16(&'a mut i16),
    Int32(&'a mut i32),
    Int64(&'a mut i64),
    Uint(&'a mut usize),
    Uint8(&'a mut u8),
    Uint16(&'a mut u16),
    Uint32(&'a mut u32),
    Uint64(&'a mut u64),
    Uintptr(&'a mut u64),
    Float32(&'a mut f32),
    Float64(&'a mut f64),
    /// `*complex64` as (real, imaginary).
    Complex64(&'a mut (f32, f32)),
    Complex128(&'a mut strconv::Complex),
    /// `*string`; invalid UTF-8 in the input becomes U+FFFD.
    String(&'a mut String),
    /// `*[]byte`.
    Bytes(&'a mut Vec<u8>),
    /// Any value with a [`Scanner`] implementation.
    Scanner(&'a mut dyn Scanner),
}

macro_rules! scan_from {
    ($($t:ty => $v:ident;)*) => {$(
        impl<'a> From<&'a mut $t> for ScanArg<'a> {
            fn from(x: &'a mut $t) -> ScanArg<'a> { ScanArg::$v(x) }
        }
    )*};
}

scan_from! {
    bool => Bool; isize => Int; i8 => Int8; i16 => Int16; i32 => Int32; i64 => Int64;
    usize => Uint; u8 => Uint8; u16 => Uint16; u32 => Uint32; u64 => Uint64;
    f32 => Float32; f64 => Float64; (f32, f32) => Complex64; strconv::Complex => Complex128;
    String => String; Vec<u8> => Bytes;
}

impl<'a> From<&'a mut dyn Scanner> for ScanArg<'a> {
    fn from(x: &'a mut dyn Scanner) -> ScanArg<'a> {
        ScanArg::Scanner(x)
    }
}

// ----------------------------------------------------------- rune input

/// Go's `readRune`: UTF-8 decoding over a plain reader, with one rune of
/// pushback that is lost when the call returns.
struct ReadRune<'a> {
    reader: &'a mut dyn Read,
    pending: Vec<u8>,
    peek_rune: i32, // if >=0 next rune; when <0 is ^(previous rune)
}

impl ReadRune<'_> {
    fn read_byte(&mut self) -> R<u8> {
        if !self.pending.is_empty() {
            return Ok(self.pending.remove(0));
        }
        let mut b = [0u8; 1];
        loop {
            match self.reader.read(&mut b) {
                Ok(0) => return Err(ScanErrorKind::Eof),
                Ok(_) => return Ok(b[0]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(from_io(e)),
            }
        }
    }

    fn read_rune(&mut self) -> R<(i32, usize)> {
        if self.peek_rune >= 0 {
            let rr = self.peek_rune;
            self.peek_rune = !self.peek_rune;
            return Ok((rr, rune_len(rr).max(0) as usize));
        }
        let mut buf = [0u8; 4];
        buf[0] = self.read_byte()?;
        if buf[0] < 0x80 {
            let rr = buf[0] as i32;
            self.peek_rune = !rr;
            return Ok((rr, 1));
        }
        let mut n = 1;
        while !full_rune(&buf[..n]) {
            match self.read_byte() {
                Ok(b) => buf[n] = b,
                Err(ScanErrorKind::Eof) => break,
                Err(e) => return Err(e),
            }
            n += 1;
        }
        let (rr, size) = decode_rune(&buf[..n]);
        if size < n {
            // an error, save the bytes for the next read
            self.pending.extend_from_slice(&buf[size..n]);
        }
        self.peek_rune = !rr;
        Ok((rr, size))
    }

    fn unread_rune(&mut self) {
        if self.peek_rune < 0 {
            self.peek_rune = !self.peek_rune;
        }
    }
}

fn from_io(e: io::Error) -> ScanErrorKind {
    if is_eof(&e) {
        ScanErrorKind::Eof
    } else if crate::io::is_unexpected_eof(&e) {
        ScanErrorKind::UnexpectedEof
    } else {
        ScanErrorKind::Other(Arc::new(e))
    }
}

enum Src<'a> {
    Raw(ReadRune<'a>),
    Runes(&'a mut dyn RuneScanner),
}

impl Src<'_> {
    fn read_rune(&mut self) -> R<(i32, usize)> {
        match self {
            Src::Raw(r) => r.read_rune(),
            Src::Runes(r) => match r.read_rune() {
                Ok((c, n)) => Ok((c as i32, n)),
                Err(e) => Err(from_io(e)),
            },
        }
    }

    fn unread_rune(&mut self) {
        match self {
            Src::Raw(r) => r.unread_rune(),
            Src::Runes(r) => {
                let _ = r.unread_rune();
            }
        }
    }
}

/// The scan state (Go `ss`).
struct Ss<'a> {
    rs: Src<'a>,
    buf: Vec<u8>,
    count: i64,
    at_eof: bool,
    nl_is_end: bool,
    nl_is_space: bool,
    arg_limit: i64,
    limit: i64,
    max_wid: i64,
}

fn is_space(r: i32) -> bool {
    if !(0..1 << 16).contains(&r) {
        return false;
    }
    matches!(r,
        0x0009..=0x000d | 0x0020 | 0x0085 | 0x00a0 | 0x1680 | 0x2000..=0x200a
        | 0x2028..=0x2029 | 0x202f | 0x205f | 0x3000)
}

fn not_space(r: i32) -> bool {
    !is_space(r)
}

fn rune_char(r: i32) -> char {
    char::from_u32(r as u32).unwrap_or('\u{FFFD}')
}

fn index_rune(s: &str, r: i32) -> bool {
    s.chars().any(|c| c as i32 == r)
}

const BINARY_DIGITS: &str = "01";
const OCTAL_DIGITS: &str = "01234567";
const DECIMAL_DIGITS: &str = "0123456789";
const HEXADECIMAL_DIGITS: &str = "0123456789aAbBcCdDeEfF";
const SIGN: &str = "+-";
const PERIOD: &str = ".";
const EXPONENT: &str = "eEpP";
const FLOAT_VERBS: &str = "beEfFgGv";

impl Read for Ss<'_> {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other(
            "ScanState's Read should not be called. Use ReadRune",
        ))
    }
}

impl Ss<'_> {
    fn read_rune_raw(&mut self) -> R<(i32, usize)> {
        if self.at_eof || self.count >= self.arg_limit {
            return Err(ScanErrorKind::Eof);
        }
        match self.rs.read_rune() {
            Ok((r, size)) => {
                self.count += 1;
                if self.nl_is_end && r == '\n' as i32 {
                    self.at_eof = true;
                }
                Ok((r, size))
            }
            Err(ScanErrorKind::Eof) => {
                self.at_eof = true;
                Err(ScanErrorKind::Eof)
            }
            Err(e) => Err(e),
        }
    }

    /// If get_rune reaches EOF, the return value is EOF (-1).
    fn get_rune(&mut self) -> R<i32> {
        match self.read_rune_raw() {
            Ok((r, _)) => Ok(r),
            Err(ScanErrorKind::Eof) => Ok(EOF),
            Err(e) => Err(e),
        }
    }

    /// Turns io.EOF into io.ErrUnexpectedEOF: an EOF is a syntax error here.
    fn must_read_rune(&mut self) -> R<i32> {
        let r = self.get_rune()?;
        if r == EOF {
            return Err(ScanErrorKind::UnexpectedEof);
        }
        Ok(r)
    }

    fn unread(&mut self) {
        self.rs.unread_rune();
        self.at_eof = false;
        self.count -= 1;
    }

    fn skip_space_inner(&mut self) -> R<()> {
        loop {
            let r = self.get_rune()?;
            if r == EOF {
                return Ok(());
            }
            if r == '\r' as i32 && self.peek("\n")? {
                continue;
            }
            if r == '\n' as i32 {
                if self.nl_is_space {
                    continue;
                }
                return Err(ScanErrorKind::msg("unexpected newline"));
            }
            if !is_space(r) {
                self.unread();
                return Ok(());
            }
        }
    }

    fn token_inner(&mut self, skip_space: bool, f: &dyn Fn(i32) -> bool) -> R<()> {
        if skip_space {
            self.skip_space_inner()?;
        }
        // read until white space or newline
        loop {
            let r = self.get_rune()?;
            if r == EOF {
                break;
            }
            if !f(r) {
                self.unread();
                break;
            }
            append_rune(&mut self.buf, r);
        }
        Ok(())
    }

    /// Reads the next rune and reports whether it is in `ok`. If `accept` is
    /// true, puts the character into the input token.
    fn consume(&mut self, ok: &str, accept: bool) -> R<bool> {
        let r = self.get_rune()?;
        if r == EOF {
            return Ok(false);
        }
        if index_rune(ok, r) {
            if accept {
                append_rune(&mut self.buf, r);
            }
            return Ok(true);
        }
        if accept {
            self.unread();
        }
        Ok(false)
    }

    /// Reports whether the next character is in `ok`, without consuming it.
    fn peek(&mut self, ok: &str) -> R<bool> {
        let r = self.get_rune()?;
        if r != EOF {
            self.unread();
        }
        Ok(index_rune(ok, r))
    }

    fn not_eof(&mut self) -> R<()> {
        // Guarantee there is data to be read.
        if self.get_rune()? == EOF {
            return Err(ScanErrorKind::Eof);
        }
        self.unread();
        Ok(())
    }

    fn accept(&mut self, ok: &str) -> R<bool> {
        self.consume(ok, true)
    }

    fn ok_verb(&self, verb: char, ok_verbs: &str, typ: &str) -> R<()> {
        if ok_verbs.contains(verb) {
            Ok(())
        } else {
            Err(ScanErrorKind::Message(format!(
                "bad verb '%{verb}' for {typ}"
            )))
        }
    }

    fn scan_bool(&mut self, verb: char) -> R<bool> {
        self.skip_space_inner()?;
        self.not_eof()?;
        self.ok_verb(verb, "tv", "boolean")?;
        // Syntax-checking a boolean is annoying. We're not fastidious about case.
        let err = || ScanErrorKind::msg("syntax error scanning boolean");
        match self.get_rune()? {
            0x30 => Ok(false),
            0x31 => Ok(true),
            0x74 | 0x54 => {
                if self.accept("rR")? && (!self.accept("uU")? || !self.accept("eE")?) {
                    return Err(err());
                }
                Ok(true)
            }
            0x66 | 0x46 => {
                if self.accept("aA")?
                    && (!self.accept("lL")? || !self.accept("sS")? || !self.accept("eE")?)
                {
                    return Err(err());
                }
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    fn get_base(&self, verb: char) -> R<(i32, &'static str)> {
        self.ok_verb(verb, "bdoUxXv", "integer")?;
        Ok(match verb {
            'b' => (2, BINARY_DIGITS),
            'o' => (8, OCTAL_DIGITS),
            'x' | 'X' | 'U' => (16, HEXADECIMAL_DIGITS),
            _ => (10, DECIMAL_DIGITS),
        })
    }

    /// Returns the numerical string with the specified digits starting here.
    fn scan_number(&mut self, digits: &str, have_digits: bool) -> R<String> {
        if !have_digits {
            self.not_eof()?;
            if !self.accept(digits)? {
                return Err(ScanErrorKind::msg("expected integer"));
            }
        }
        while self.accept(digits)? {}
        Ok(String::from_utf8_lossy(&self.buf).into_owned())
    }

    fn scan_rune(&mut self, bit_size: u32) -> R<i64> {
        self.not_eof()?;
        let r = self.get_rune()? as i64;
        let n = bit_size;
        let x = (r << (64 - n)) >> (64 - n);
        if x != r {
            return Err(ScanErrorKind::Message(format!(
                "overflow on character value {}",
                rune_char(r as i32)
            )));
        }
        Ok(r)
    }

    /// Reports whether the integer begins with a base prefix; called only
    /// for %v. Returns the digit string and whether a zero was found.
    fn scan_base_prefix(&mut self) -> R<(i32, String, bool)> {
        if !self.peek("0")? {
            return Ok((0, format!("{DECIMAL_DIGITS}_"), false));
        }
        self.accept("0")?;
        // Special cases for 0, 0b, 0o, 0x.
        if self.peek("bB")? {
            self.consume("bB", true)?;
            Ok((0, format!("{BINARY_DIGITS}_"), true))
        } else if self.peek("oO")? {
            self.consume("oO", true)?;
            Ok((0, format!("{OCTAL_DIGITS}_"), true))
        } else if self.peek("xX")? {
            self.consume("xX", true)?;
            Ok((0, format!("{HEXADECIMAL_DIGITS}_"), true))
        } else {
            Ok((0, format!("{OCTAL_DIGITS}_"), true))
        }
    }

    fn scan_int(&mut self, verb: char, bit_size: u32) -> R<i64> {
        if verb == 'c' {
            return self.scan_rune(bit_size);
        }
        self.skip_space_inner()?;
        self.not_eof()?;
        let (mut base, digits) = self.get_base(verb)?;
        let mut digits = digits.to_string();
        let mut have_digits = false;
        if verb == 'U' {
            if !self.consume("U", false)? || !self.consume("+", false)? {
                return Err(ScanErrorKind::msg("bad unicode format "));
            }
        } else {
            self.accept(SIGN)?; // If there's a sign, it will be left in the token buffer.
            if verb == 'v' {
                (base, digits, have_digits) = self.scan_base_prefix()?;
            }
        }
        let tok = self.scan_number(&digits, have_digits)?;
        let i = strconv::parse_int(&tok, base, 64)?;
        let n = bit_size;
        let x = (i << (64 - n)) >> (64 - n);
        if x != i {
            return Err(ScanErrorKind::Message(format!(
                "integer overflow on token {tok}"
            )));
        }
        Ok(i)
    }

    fn scan_uint(&mut self, verb: char, bit_size: u32) -> R<u64> {
        if verb == 'c' {
            return Ok(self.scan_rune(bit_size)? as u64);
        }
        self.skip_space_inner()?;
        self.not_eof()?;
        let (mut base, digits) = self.get_base(verb)?;
        let mut digits = digits.to_string();
        let mut have_digits = false;
        if verb == 'U' {
            if !self.consume("U", false)? || !self.consume("+", false)? {
                return Err(ScanErrorKind::msg("bad unicode format "));
            }
        } else if verb == 'v' {
            (base, digits, have_digits) = self.scan_base_prefix()?;
        }
        let tok = self.scan_number(&digits, have_digits)?;
        let i = strconv::parse_uint(&tok, base, 64)?;
        let n = bit_size;
        let x = (i << (64 - n)) >> (64 - n);
        if x != i {
            return Err(ScanErrorKind::Message(format!(
                "unsigned integer overflow on token {tok}"
            )));
        }
        Ok(i)
    }

    /// Returns the floating-point number starting here. It's not rigorous
    /// about syntax; the parse will check that.
    fn float_token(&mut self) -> R<String> {
        self.buf.clear();
        let tok = |s: &Ss| String::from_utf8_lossy(&s.buf).into_owned();
        // NaN?
        if self.accept("nN")? && self.accept("aA")? && self.accept("nN")? {
            return Ok(tok(self));
        }
        // leading sign?
        self.accept(SIGN)?;
        // Inf?
        if self.accept("iI")? && self.accept("nN")? && self.accept("fF")? {
            return Ok(tok(self));
        }
        let mut digits = format!("{DECIMAL_DIGITS}_");
        let mut exp = EXPONENT;
        if self.accept("0")? && self.accept("xX")? {
            digits = format!("{HEXADECIMAL_DIGITS}_");
            exp = "pP";
        }
        // digits?
        while self.accept(&digits)? {}
        // decimal point?
        if self.accept(PERIOD)? {
            // fraction?
            while self.accept(&digits)? {}
        }
        // exponent?
        if self.accept(exp)? {
            // leading sign?
            self.accept(SIGN)?;
            // digits?
            let d = format!("{DECIMAL_DIGITS}_");
            while self.accept(&d)? {}
        }
        Ok(tok(self))
    }

    /// The real and imaginary parts of the complex number starting here:
    /// (N+Ni), possibly parenthesized, without spaces.
    fn complex_tokens(&mut self) -> R<(String, String)> {
        let err = || ScanErrorKind::msg("syntax error scanning complex number");
        let parens = self.accept("(")?;
        let real = self.float_token()?;
        self.buf.clear();
        // Must now have a sign.
        if !self.accept("+-")? {
            return Err(err());
        }
        // Sign is now in buffer
        let imag_sign = String::from_utf8_lossy(&self.buf).into_owned();
        let imag = self.float_token()?;
        if !self.accept("i")? {
            return Err(err());
        }
        if parens && !self.accept(")")? {
            return Err(err());
        }
        Ok((real, imag_sign + &imag))
    }

    fn convert_float(&self, s: &str, n: i32) -> R<f64> {
        // ParseFloat handles "+0x1.fp+2", but the non-standard decimal+binary
        // exponent mix (1.2p4) is evaluated here.
        if let Some(p) = s.find('p') {
            if !s.contains(['x', 'X']) {
                let fix = |mut e: NumError| {
                    e.num = s.to_string();
                    ScanErrorKind::Num(e)
                };
                let f = strconv::parse_float(&s[..p], n).map_err(fix)?;
                let m = strconv::atoi(&s[p + 1..]).map_err(fix)?;
                return Ok(ldexp(f, m as i64));
            }
        }
        Ok(strconv::parse_float(s, n)?)
    }

    fn scan_complex(&mut self, verb: char, n: i32) -> R<(f64, f64)> {
        self.ok_verb(verb, FLOAT_VERBS, "complex")?;
        self.skip_space_inner()?;
        self.not_eof()?;
        let (sreal, simag) = self.complex_tokens()?;
        let real = self.convert_float(&sreal, n / 2)?;
        let imag = self.convert_float(&simag, n / 2)?;
        Ok((real, imag))
    }

    fn convert_string(&mut self, verb: char) -> R<Vec<u8>> {
        self.ok_verb(verb, "svqxX", "string")?;
        self.skip_space_inner()?;
        self.not_eof()?;
        match verb {
            'q' => self.quoted_string(),
            'x' | 'X' => self.hex_string(),
            _ => {
                // %s and %v just return the next word
                self.token_inner(true, &not_space)?;
                Ok(self.buf.clone())
            }
        }
    }

    fn quoted_string(&mut self) -> R<Vec<u8>> {
        self.not_eof()?;
        let quote = self.get_rune()?;
        match quote {
            0x60 => {
                // Back-quoted: Anything goes until EOF or back quote.
                loop {
                    let r = self.must_read_rune()?;
                    if r == quote {
                        break;
                    }
                    append_rune(&mut self.buf, r);
                }
                Ok(self.buf.clone())
            }
            0x22 => {
                // Double-quoted: Include the quotes and let strconv.Unquote do the backslash escapes.
                self.buf.push(b'"');
                loop {
                    let r = self.must_read_rune()?;
                    append_rune(&mut self.buf, r);
                    if r == '\\' as i32 {
                        // In a legal backslash escape, no matter how long, only the character
                        // immediately after the escape can itself be a backslash or quote.
                        let r2 = self.must_read_rune()?;
                        append_rune(&mut self.buf, r2);
                    } else if r == '"' as i32 {
                        break;
                    }
                }
                strconv::unquote(&self.buf).map_err(ScanErrorKind::Strconv)
            }
            _ => Err(ScanErrorKind::msg("expected quoted string")),
        }
    }

    /// The next hex-encoded (two-character) byte from the input; None if the
    /// next bytes do not encode a hex byte.
    fn hex_byte(&mut self) -> R<Option<u8>> {
        let rune1 = self.get_rune()?;
        if rune1 == EOF {
            return Ok(None);
        }
        let Some(value1) = hex_digit(rune1) else {
            self.unread();
            return Ok(None);
        };
        let r2 = self.must_read_rune()?;
        let Some(value2) = hex_digit(r2) else {
            return Err(ScanErrorKind::msg("illegal hex digit"));
        };
        Ok(Some((value1 << 4 | value2) as u8))
    }

    fn hex_string(&mut self) -> R<Vec<u8>> {
        self.not_eof()?;
        while let Some(b) = self.hex_byte()? {
            self.buf.push(b);
        }
        if self.buf.is_empty() {
            return Err(ScanErrorKind::msg("no hex data for %x string"));
        }
        Ok(self.buf.clone())
    }

    fn scan_percent(&mut self) -> R<()> {
        self.skip_space_inner()?;
        self.not_eof()?;
        if !self.accept("%")? {
            return Err(ScanErrorKind::msg("missing literal %"));
        }
        Ok(())
    }

    /// Scans a single value into the destination.
    fn scan_one(&mut self, verb: char, arg: &mut ScanArg) -> R<()> {
        self.buf.clear();
        let int_bits = usize::BITS;
        match arg {
            ScanArg::Scanner(v) => {
                return match v.scan(self, verb) {
                    Ok(()) => Ok(()),
                    Err(ScanErrorKind::Eof) => Err(ScanErrorKind::UnexpectedEof),
                    Err(e) => Err(e),
                };
            }
            ScanArg::Bool(v) => **v = self.scan_bool(verb)?,
            ScanArg::Complex64(v) => {
                let (r, i) = self.scan_complex(verb, 64)?;
                **v = (r as f32, i as f32);
            }
            ScanArg::Complex128(v) => {
                let (re, im) = self.scan_complex(verb, 128)?;
                **v = strconv::Complex { re, im };
            }
            ScanArg::Int(v) => **v = self.scan_int(verb, int_bits)? as isize,
            ScanArg::Int8(v) => **v = self.scan_int(verb, 8)? as i8,
            ScanArg::Int16(v) => **v = self.scan_int(verb, 16)? as i16,
            ScanArg::Int32(v) => **v = self.scan_int(verb, 32)? as i32,
            ScanArg::Int64(v) => **v = self.scan_int(verb, 64)?,
            ScanArg::Uint(v) => **v = self.scan_uint(verb, int_bits)? as usize,
            ScanArg::Uint8(v) => **v = self.scan_uint(verb, 8)? as u8,
            ScanArg::Uint16(v) => **v = self.scan_uint(verb, 16)? as u16,
            ScanArg::Uint32(v) => **v = self.scan_uint(verb, 32)? as u32,
            ScanArg::Uint64(v) => **v = self.scan_uint(verb, 64)?,
            ScanArg::Uintptr(v) => **v = self.scan_uint(verb, 64)?,
            // Floats are scanned in the precision of the result.
            ScanArg::Float32(v) => {
                self.ok_verb(verb, FLOAT_VERBS, "float32")?;
                self.skip_space_inner()?;
                self.not_eof()?;
                let tok = self.float_token()?;
                **v = self.convert_float(&tok, 32)? as f32;
            }
            ScanArg::Float64(v) => {
                self.ok_verb(verb, FLOAT_VERBS, "float64")?;
                self.skip_space_inner()?;
                self.not_eof()?;
                let tok = self.float_token()?;
                **v = self.convert_float(&tok, 64)?;
            }
            ScanArg::String(v) => {
                let s = self.convert_string(verb)?;
                **v = String::from_utf8_lossy(&s).into_owned();
            }
            ScanArg::Bytes(v) => **v = self.convert_string(verb)?,
        }
        Ok(())
    }

    fn do_scan(&mut self, a: &mut [ScanArg]) -> (usize, R<()>) {
        let mut n = 0;
        for arg in a.iter_mut() {
            if let Err(e) = self.scan_one('v', arg) {
                return (n, Err(e));
            }
            n += 1;
        }
        // Check for newline (or EOF) if required (Scanln etc.).
        if self.nl_is_end {
            loop {
                let r = match self.get_rune() {
                    Ok(r) => r,
                    Err(e) => return (n, Err(e)),
                };
                if r == '\n' as i32 || r == EOF {
                    break;
                }
                if !is_space(r) {
                    return (n, Err(ScanErrorKind::msg("expected newline")));
                }
            }
        }
        (n, Ok(()))
    }

    /// Determines whether the next characters in the input match those of the
    /// format. Returns the number of bytes consumed in the format; zero if the
    /// format starts with a % (with no following %) or the input is empty;
    /// negative if the input did not match the string.
    fn advance(&mut self, format: &[u8]) -> R<isize> {
        let mut i = 0usize;
        while i < format.len() {
            let (mut fmtc, mut w) = decode_rune(&format[i..]);

            // Space processing. Newline in the format matches input of zero or
            // more spaces and then newline or end-of-input. Spaces in the format
            // before the newline are collapsed into the newline. Spaces in the
            // format after the newline match zero or more spaces after the
            // corresponding input newline. Other spaces in the format match
            // input of one or more spaces or end-of-input.
            if is_space(fmtc) {
                let mut newlines = 0;
                let mut trailing_space = false;
                while is_space(fmtc) && i < format.len() {
                    if fmtc == '\n' as i32 {
                        newlines += 1;
                        trailing_space = false;
                    } else {
                        trailing_space = true;
                    }
                    i += w;
                    (fmtc, w) = decode_rune(&format[i.min(format.len())..]);
                }
                for _ in 0..newlines {
                    let mut inputc = self.get_rune()?;
                    while is_space(inputc) && inputc != '\n' as i32 {
                        inputc = self.get_rune()?;
                    }
                    if inputc != '\n' as i32 && inputc != EOF {
                        return Err(ScanErrorKind::msg("newline in format does not match input"));
                    }
                }
                if trailing_space {
                    let mut inputc = self.get_rune()?;
                    if newlines == 0 {
                        // If the trailing space stood alone (did not follow a newline),
                        // it must find at least one space to consume.
                        if !is_space(inputc) && inputc != EOF {
                            return Err(ScanErrorKind::msg(
                                "expected space in input to match format",
                            ));
                        }
                        if inputc == '\n' as i32 {
                            return Err(ScanErrorKind::msg(
                                "newline in input does not match format",
                            ));
                        }
                    }
                    while is_space(inputc) && inputc != '\n' as i32 {
                        inputc = self.get_rune()?;
                    }
                    if inputc != EOF {
                        self.unread();
                    }
                }
                continue;
            }

            // Verbs.
            if fmtc == '%' as i32 {
                // % at end of string is an error.
                if i + w == format.len() {
                    return Err(ScanErrorKind::msg(
                        "missing verb: % at end of format string",
                    ));
                }
                // %% acts like a real percent
                let (nextc, _) = decode_rune(&format[i + w..]); // will not match % if string is empty
                if nextc != '%' as i32 {
                    return Ok(i as isize);
                }
                i += w; // skip the first %
            }

            // Literals.
            let inputc = self.must_read_rune()?;
            if fmtc != inputc {
                self.unread();
                return Ok(-1);
            }
            i += w;
        }
        Ok(i as isize)
    }

    fn do_scanf(&mut self, format: &[u8], a: &mut [ScanArg]) -> (usize, R<()>) {
        let mut n = 0usize;
        let r = self.do_scanf_inner(format, a, &mut n);
        (n, r)
    }

    fn do_scanf_inner(&mut self, format: &[u8], a: &mut [ScanArg], n: &mut usize) -> R<()> {
        let end = format.len() as i64 - 1;
        // We process one item per non-trivial format
        let mut i = 0i64;
        while i <= end {
            let w = self.advance(&format[i as usize..])?;
            if w > 0 {
                i += w as i64;
                continue;
            }
            // Either we failed to advance, we have a percent character, or we ran out of input.
            if format[i as usize] != b'%' {
                // Can't advance format. Why not?
                if w < 0 {
                    return Err(ScanErrorKind::msg("input does not match format"));
                }
                // Otherwise at EOF; "too many operands" error handled below
                break;
            }
            i += 1; // % is one byte

            // do we have 20 (width)?
            let (wid, wid_present, ni) = parsenum(format, i as usize, end.max(0) as usize);
            i = ni as i64;
            self.max_wid = if wid_present { wid } else { HUGE_WID };

            let (c, w) = decode_rune(&format[(i as usize).min(format.len())..]);
            i += w as i64;

            if c != 'c' as i32 {
                self.skip_space_inner()?;
            }
            if c == '%' as i32 {
                self.scan_percent()?;
                continue; // Do not consume an argument.
            }
            self.arg_limit = self.limit;
            let f = self.count + self.max_wid;
            if f < self.arg_limit {
                self.arg_limit = f;
            }

            if *n >= a.len() {
                // out of operands
                let rest = &format[(i as usize).saturating_sub(w)..];
                return Err(ScanErrorKind::Message(format!(
                    "too few operands for format '%{}'",
                    String::from_utf8_lossy(rest)
                )));
            }
            self.scan_one(rune_char(c), &mut a[*n])?;
            *n += 1;
            self.arg_limit = self.limit;
        }
        if *n < a.len() {
            return Err(ScanErrorKind::msg("too many operands"));
        }
        Ok(())
    }
}

impl ScanState for Ss<'_> {
    fn read_rune(&mut self) -> R<(char, usize)> {
        let (r, n) = self.read_rune_raw()?;
        Ok((rune_char(r), n))
    }

    fn unread_rune(&mut self) -> R<()> {
        self.unread();
        Ok(())
    }

    fn skip_space(&mut self) -> R<()> {
        self.skip_space_inner()
    }

    fn token(&mut self, skip_space: bool, f: Option<&dyn Fn(char) -> bool>) -> R<Vec<u8>> {
        self.buf.clear();
        match f {
            Some(f) => self.token_inner(skip_space, &|r| f(rune_char(r)))?,
            None => self.token_inner(skip_space, &not_space)?,
        }
        Ok(self.buf.clone())
    }

    fn width(&self) -> Option<usize> {
        (self.max_wid != HUGE_WID).then_some(self.max_wid as usize)
    }
}

fn hex_digit(d: i32) -> Option<i32> {
    match d {
        0x30..=0x39 => Some(d - 0x30),
        0x61..=0x66 => Some(10 + d - 0x61),
        0x41..=0x46 => Some(10 + d - 0x41),
        _ => None,
    }
}

/// math.Ldexp: frac × 2**exp, with a single rounding for subnormal results.
fn ldexp(frac: f64, exp: i64) -> f64 {
    if frac == 0.0 || frac.is_infinite() || frac.is_nan() {
        return frac;
    }
    let (frac, e) = if frac.abs() < f64::MIN_POSITIVE {
        (frac * (1u64 << 52) as f64, -52)
    } else {
        (frac, 0)
    };
    let mut exp = exp + e;
    let mut x = frac.to_bits();
    exp += ((x >> 52) & 0x7FF) as i64 - 1023;
    if exp < -1075 {
        return 0.0f64.copysign(frac); // underflow
    }
    if exp > 1023 {
        return if frac < 0.0 {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        };
    }
    let mut m = 1.0;
    if exp < -1022 {
        // denormal
        exp += 53;
        m = 1.0 / (1u64 << 53) as f64;
    }
    x &= !(0x7FFu64 << 52);
    x |= ((exp + 1023) as u64) << 52;
    m * f64::from_bits(x)
}

/// Adapts a [`ScanState`] to a [`RuneScanner`], so that a custom [`Scanner`]
/// can scan its input with [`fscan_runes`] and friends (Go passes the
/// `ScanState` itself to `Fscan`).
pub struct StateRunes<'a>(pub &'a mut dyn ScanState);

fn to_io(e: ScanErrorKind) -> io::Error {
    match e {
        ScanErrorKind::Eof => crate::io::eof(),
        ScanErrorKind::UnexpectedEof => crate::io::Error::UnexpectedEof.into(),
        e => io::Error::other(e),
    }
}

impl RuneReader for StateRunes<'_> {
    fn read_rune(&mut self) -> io::Result<(char, usize)> {
        self.0.read_rune().map_err(to_io)
    }
}

impl RuneScanner for StateRunes<'_> {
    fn unread_rune(&mut self) -> io::Result<()> {
        self.0.unread_rune().map_err(to_io)
    }
}

// ------------------------------------------------------------- driver

fn run<'a>(
    src: Src<'a>,
    nl_is_space: bool,
    nl_is_end: bool,
    f: impl FnOnce(&mut Ss<'a>) -> (usize, R<()>),
) -> Result<usize, ScanError> {
    let mut s = Ss {
        rs: src,
        buf: Vec::new(),
        count: 0,
        at_eof: false,
        nl_is_end,
        nl_is_space,
        arg_limit: HUGE_WID,
        limit: HUGE_WID,
        max_wid: HUGE_WID,
    };
    match f(&mut s) {
        (n, Ok(())) => Ok(n),
        (n, Err(kind)) => Err(ScanError { n, kind }),
    }
}

fn raw(r: &mut dyn Read) -> Src<'_> {
    Src::Raw(ReadRune {
        reader: r,
        pending: Vec::new(),
        peek_rune: -1,
    })
}

/// Scans text read from `r`, storing successive space-separated values into
/// successive arguments. Newlines count as space. Returns the number of
/// items scanned; if that is less than the number of arguments the error
/// says why (Go `Fscan`). If `r` is not a rune scanner, one rune of
/// lookahead may be lost; see [`fscan_runes`].
pub fn fscan<R: Read + ?Sized>(r: &mut R, args: &mut [ScanArg]) -> Result<usize, ScanError> {
    let mut r = r;
    run(raw(&mut r), true, false, |s| s.do_scan(args))
}

/// Like [`fscan`], but stops at a newline and after the final item there must
/// be a newline or EOF (Go `Fscanln`).
pub fn fscanln<R: Read + ?Sized>(r: &mut R, args: &mut [ScanArg]) -> Result<usize, ScanError> {
    let mut r = r;
    run(raw(&mut r), false, true, |s| s.do_scan(args))
}

/// Scans text read from `r` as determined by the format (Go `Fscanf`).
/// Newlines in the input must match newlines in the format.
pub fn fscanf<R: Read + ?Sized>(
    r: &mut R,
    format: impl AsRef<[u8]>,
    args: &mut [ScanArg],
) -> Result<usize, ScanError> {
    let mut r = r;
    run(raw(&mut r), false, false, |s| {
        s.do_scanf(format.as_ref(), args)
    })
}

/// [`fscan`] over a rune scanner, which loses no lookahead: the scanner is
/// positioned right after the last rune used.
pub fn fscan_runes(r: &mut dyn RuneScanner, args: &mut [ScanArg]) -> Result<usize, ScanError> {
    run(Src::Runes(r), true, false, |s| s.do_scan(args))
}

/// [`fscanln`] over a rune scanner.
pub fn fscanln_runes(r: &mut dyn RuneScanner, args: &mut [ScanArg]) -> Result<usize, ScanError> {
    run(Src::Runes(r), false, true, |s| s.do_scan(args))
}

/// [`fscanf`] over a rune scanner.
pub fn fscanf_runes(
    r: &mut dyn RuneScanner,
    format: impl AsRef<[u8]>,
    args: &mut [ScanArg],
) -> Result<usize, ScanError> {
    run(Src::Runes(r), false, false, |s| {
        s.do_scanf(format.as_ref(), args)
    })
}

/// Scans the argument string, storing successive space-separated values into
/// successive arguments (Go `Sscan`).
pub fn sscan(input: impl AsRef<[u8]>, args: &mut [ScanArg]) -> Result<usize, ScanError> {
    fscan(&mut input.as_ref(), args)
}

/// Like [`sscan`], but stops at a newline (Go `Sscanln`).
pub fn sscanln(input: impl AsRef<[u8]>, args: &mut [ScanArg]) -> Result<usize, ScanError> {
    fscanln(&mut input.as_ref(), args)
}

/// Scans the argument string as determined by the format (Go `Sscanf`).
pub fn sscanf(
    input: impl AsRef<[u8]>,
    format: impl AsRef<[u8]>,
    args: &mut [ScanArg],
) -> Result<usize, ScanError> {
    fscanf(&mut input.as_ref(), format, args)
}

/// Scans standard input (Go `Scan`).
pub fn scan(args: &mut [ScanArg]) -> Result<usize, ScanError> {
    fscan(&mut io::stdin().lock(), args)
}

/// Scans standard input, stopping at a newline (Go `Scanln`).
pub fn scanln(args: &mut [ScanArg]) -> Result<usize, ScanError> {
    fscanln(&mut io::stdin().lock(), args)
}

/// Scans standard input as determined by the format (Go `Scanf`).
pub fn scanf(format: impl AsRef<[u8]>, args: &mut [ScanArg]) -> Result<usize, ScanError> {
    fscanf(&mut io::stdin().lock(), format, args)
}
