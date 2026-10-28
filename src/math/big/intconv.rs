// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the NOTICE file.
//
// Ported from $GOROOT/src/math/big/{intconv,intmarsh}.go.

use super::int::Int;
use super::natconv::{self, ByteScanner, ByteSource, ReaderSource, ScanError};
use super::{nat, write_padding, FormatSpec, ParseError};
use std::fmt;
use std::io;
use std::str::FromStr;

/// Go's scanSign: an optional leading '+' or '-'.
pub(super) fn scan_sign<S: ByteSource + ?Sized>(r: &mut S) -> Result<bool, ScanError> {
    match r.read_byte() {
        None => Err(ScanError::Eof),
        Some(b'-') => Ok(true),
        Some(b'+') => Ok(false),
        Some(_) => {
            r.unread_byte();
            Ok(false)
        }
    }
}

/// Go's Int.scan: sign and digits; returns the value and the actual base.
pub(super) fn scan_int<S: ByteSource + ?Sized>(
    r: &mut S,
    base: u32,
) -> Result<(Int, u32), ScanError> {
    let neg = scan_sign(r)?;
    let (scanned, err) = natconv::scan(r, base, false);
    if let Some(err) = err {
        return Err(err);
    }
    Ok((Int::from_parts(neg, scanned.value), scanned.base))
}

pub(super) fn invalid_data(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// A scanner syntax error as an `io::Error` (EOF as `UnexpectedEof`).
pub(super) fn scan_io_error(err: ScanError) -> io::Error {
    match err {
        ScanError::Eof => io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"),
        err => invalid_data(err.message()),
    }
}

/// Go's `%q` quoting of a byte string, for error messages.
pub(super) fn quote_bytes(text: &[u8]) -> String {
    let mut out = String::from("\"");
    let mut rest = text;
    while !rest.is_empty() {
        let (valid, invalid) = match std::str::from_utf8(rest) {
            Ok(s) => (s, &[][..]),
            Err(e) => {
                let (good, bad) = rest.split_at(e.valid_up_to());
                (std::str::from_utf8(good).unwrap_or_default(), bad)
            }
        };
        for c in valid.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\x07' => out.push_str("\\a"),
                '\x08' => out.push_str("\\b"),
                '\x0c' => out.push_str("\\f"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\x0b' => out.push_str("\\v"),
                c if (c as u32) < 0x20 || c == '\x7f' => {
                    out.push_str(&format!("\\x{:02x}", c as u32));
                }
                c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        if let Some((&b, tail)) = invalid.split_first() {
            out.push_str(&format!("\\x{b:02x}"));
            rest = tail;
        } else {
            rest = &[];
        }
    }
    out.push('"');
    out
}

impl Int {
    /// Go's `Text`: x in base 2..=62 (lower-case letters for 10..35,
    /// upper-case for 36..61). Panics on other bases.
    pub fn text(&self, base: u32) -> String {
        String::from_utf8(natconv::itoa(&self.abs, self.neg, base)).unwrap_or_default()
    }

    /// Go's `Append`: buf with [`Int::text`] appended.
    pub fn append(&self, mut buf: Vec<u8>, base: u32) -> Vec<u8> {
        buf.extend(natconv::itoa(&self.abs, self.neg, base));
        buf
    }

    /// Go's `SetString`: parse s in base 0 or 2..=62. Base 0 accepts Go's
    /// prefixes (`0b`, `0o`, `0x`, and `0` for octal) and `_` digit
    /// separators. Returns `None` on a syntax error (Go's `false`); panics
    /// on an invalid base, as Go does. Like a Go string, the input may be
    /// any bytes.
    pub fn from_str_radix<S: AsRef<[u8]> + ?Sized>(s: &S, base: u32) -> Option<Int> {
        Int::from_bytes_radix(s.as_ref(), base)
    }

    fn from_bytes_radix(s: &[u8], base: u32) -> Option<Int> {
        let mut r = ByteScanner::new(s);
        let (z, _) = scan_int(&mut r, base).ok()?;
        r.at_eof().then_some(z)
    }

    /// Go's `Format` for `fmt` verbs `b`, `o`, `O`, `d`, `s`, `v`, `x`,
    /// `X` with the given flags, width and precision. Other verbs produce
    /// Go's `%!c(big.Int=…)` text.
    pub fn format(&self, verb: char, spec: &FormatSpec) -> String {
        let base = match verb {
            'b' => 2,
            'o' | 'O' => 8,
            'd' | 's' | 'v' => 10,
            'x' | 'X' => 16,
            _ => return format!("%!{verb}(big.Int={self})"),
        };
        let sign = if self.neg {
            "-"
        } else if spec.plus {
            "+"
        } else if spec.space {
            " "
        } else {
            ""
        };
        let mut prefix = "";
        if spec.sharp {
            prefix = match verb {
                'b' => "0b",
                'o' => "0",
                'x' => "0x",
                'X' => "0X",
                _ => "",
            };
        }
        if verb == 'O' {
            prefix = "0o";
        }
        let mut digits = natconv::utoa(&self.abs, base);
        if verb == 'X' {
            digits.make_ascii_uppercase();
        }
        let mut left = 0;
        let mut zeros = 0;
        let mut right = 0;
        if let Some(precision) = spec.precision {
            if digits.len() < precision {
                zeros = precision - digits.len();
            } else if digits == b"0" && precision == 0 {
                return String::new();
            }
        }
        let length = sign.len() + prefix.len() + zeros + digits.len();
        if let Some(width) = spec.width {
            if length < width {
                let d = width - length;
                if spec.minus {
                    right = d;
                } else if spec.zero && spec.precision.is_none() {
                    zeros = d;
                } else {
                    left = d;
                }
            }
        }
        let mut out = String::with_capacity(length + left + right);
        write_padding(&mut out, ' ', left);
        out.push_str(sign);
        out.push_str(prefix);
        write_padding(&mut out, '0', zeros);
        out.push_str(std::str::from_utf8(&digits).unwrap_or_default());
        write_padding(&mut out, ' ', right);
        out
    }

    /// Go's `Scan` (`fmt.Scanner`): skip leading white space, then read the
    /// longest prefix of r that is an integer for the verb (`b`, `o`, `d`,
    /// `x`/`X`, or `s`/`v` for Go's base-0 syntax). The byte that ends the
    /// number is left in the reader. Syntax errors are `InvalidData` with
    /// Go's message; empty input is `UnexpectedEof`.
    pub fn scan<R: io::BufRead + ?Sized>(r: &mut R, verb: char) -> io::Result<Int> {
        let base = match verb {
            'b' => 2,
            'o' => 8,
            'd' => 10,
            'x' | 'X' => 16,
            's' | 'v' => 0,
            _ => return Err(invalid_data("Int.Scan: invalid verb")),
        };
        let mut src = ReaderSource::new(r);
        src.skip_space();
        let result = scan_int(&mut src, base);
        if let Some(err) = src.finish() {
            return Err(err);
        }
        result.map(|(z, _)| z).map_err(scan_io_error)
    }

    /// Go's `AppendText`: buf with the decimal text appended.
    pub fn append_text(&self, buf: Vec<u8>) -> Vec<u8> {
        self.append(buf, 10)
    }

    /// Go's `MarshalText`: the decimal text.
    pub fn marshal_text(&self) -> Vec<u8> {
        self.append(Vec::new(), 10)
    }

    /// Go's `UnmarshalText`: parse text in base 0.
    pub fn unmarshal_text(text: &[u8]) -> Result<Int, ParseError> {
        Int::from_bytes_radix(text, 0).ok_or_else(|| {
            ParseError::new(format!(
                "math/big: cannot unmarshal {} into a *big.Int",
                quote_bytes(text)
            ))
        })
    }

    /// Go's `MarshalJSON`: a JSON number.
    pub fn marshal_json(&self) -> Vec<u8> {
        self.marshal_text()
    }

    /// Go's `UnmarshalJSON`: `Ok(None)` for `null` (Go leaves the receiver
    /// unchanged), otherwise as [`Int::unmarshal_text`].
    pub fn unmarshal_json(text: &[u8]) -> Result<Option<Int>, ParseError> {
        if text == b"null" {
            return Ok(None);
        }
        Int::unmarshal_text(text).map(Some)
    }

    /// Go's `GobEncode`.
    pub fn gob_encode(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 1 + self.abs.len() * 8];
        let i = nat::bytes(&self.abs, &mut buf) - 1;
        buf[i] = (1 << 1) | u8::from(self.neg);
        buf.split_off(i)
    }

    /// Go's `GobDecode` (an empty buffer decodes to zero).
    pub fn gob_decode(buf: &[u8]) -> Result<Int, ParseError> {
        let Some((&b, rest)) = buf.split_first() else {
            return Ok(Int::zero());
        };
        if b >> 1 != 1 {
            return Err(ParseError::new(format!(
                "Int.GobDecode: encoding version {} not supported",
                b >> 1
            )));
        }
        // Like Go, a negative sign on a zero magnitude is kept.
        Ok(Int {
            neg: b & 1 != 0,
            abs: nat::set_bytes(rest),
        })
    }
}

/// Parses like Go's `UnmarshalText` (base 0: optional sign, Go prefixes and
/// `_` separators).
impl FromStr for Int {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Int, ParseError> {
        Int::unmarshal_text(s.as_bytes())
    }
}

fn write_go(x: &Int, f: &mut fmt::Formatter<'_>, verb: char) -> fmt::Result {
    let spec = FormatSpec::from_formatter(f);
    f.write_str(&x.format(verb, &spec))
}

/// Decimal, honouring Rust's `+`, `0`, width, precision and `-` alignment
/// flags with Go's `%d` padding rules.
impl fmt::Display for Int {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_go(self, f, 'd')
    }
}

impl fmt::Debug for Int {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_go(self, f, 'd')
    }
}

/// Go's `%x` (`{:#x}` is `%#x`).
impl fmt::LowerHex for Int {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_go(self, f, 'x')
    }
}

/// Go's `%X` (`{:#X}` is `%#X`).
impl fmt::UpperHex for Int {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_go(self, f, 'X')
    }
}

/// Go's `%b` (`{:#b}` is `%#b`, prefix `0b`).
impl fmt::Binary for Int {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_go(self, f, 'b')
    }
}

/// Go's `%o`; `{:#o}` uses Go's `%O` (prefix `0o`, Rust's convention).
impl fmt::Octal for Int {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut spec = FormatSpec::from_formatter(f);
        let verb = if spec.sharp { 'O' } else { 'o' };
        spec.sharp = false;
        f.write_str(&self.format(verb, &spec))
    }
}
