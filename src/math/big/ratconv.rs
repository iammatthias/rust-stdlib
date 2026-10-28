// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the NOTICE file.
//
// Ported from $GOROOT/src/math/big/{ratconv,ratmarsh}.go.

use super::int::Int;
use super::intconv::{invalid_data, quote_bytes, scan_sign};
use super::nat::{self, Nat};
use super::natconv::{self, ByteScanner, ByteSource, ReaderSource, ScanError};
use super::rat::Rat;
use super::ParseError;
use std::fmt;
use std::io;
use std::str::FromStr;

/// Go's scanExponent: an optional `e`/`E` (or, with base2_ok, `p`/`P`)
/// exponent. Returns the exponent and its base (10 or 2).
pub(super) fn scan_exponent<S: ByteSource + ?Sized>(
    r: &mut S,
    base2_ok: bool,
    sep_ok: bool,
) -> Result<(i64, u32), ScanError> {
    let Some(ch) = r.read_byte() else {
        return Ok((0, 10));
    };
    let base = match ch {
        b'e' | b'E' => 10,
        b'p' | b'P' if base2_ok => 2,
        _ => {
            r.unread_byte();
            return Ok((0, 10));
        }
    };
    let mut digits = String::new();
    let mut ch = r.read_byte();
    if let Some(c @ (b'+' | b'-')) = ch {
        if c == b'-' {
            digits.push('-');
        }
        ch = r.read_byte();
    }
    let mut prev = b'.';
    let mut inval_sep = false;
    let mut has_digits = false;
    while let Some(c) = ch {
        if c.is_ascii_digit() {
            digits.push(c as char);
            prev = b'0';
            has_digits = true;
        } else if c == b'_' && sep_ok {
            if prev != b'0' {
                inval_sep = true;
            }
            prev = b'_';
        } else {
            r.unread_byte();
            break;
        }
        ch = r.read_byte();
    }
    if !has_digits {
        return Err(ScanError::NoDigits);
    }
    let exp: i64 = digits.parse().map_err(|_| {
        ScanError::ExpRange(format!(
            "strconv.ParseInt: parsing {}: value out of range",
            quote_bytes(digits.as_bytes())
        ))
    })?;
    if inval_sep || prev == b'_' {
        return Err(ScanError::InvalSep);
    }
    Ok((exp, base))
}

impl Rat {
    /// Go's `SetString`: a fraction `"a/b"` (a in Go's base-0 integer
    /// syntax, b unsigned) or a floating-point number with optional base
    /// prefix, `_` separators, and decimal (`e`) or binary (`p`) exponent.
    /// Returns `None` on a syntax error, a zero denominator, or an exponent
    /// beyond Go's limits (decimal 10⁶, binary 10⁷).
    /// Like a Go string, the input may be any bytes.
    pub fn from_string<S: AsRef<[u8]> + ?Sized>(s: &S) -> Option<Rat> {
        Rat::from_bytes(s.as_ref())
    }

    fn from_bytes(s: &[u8]) -> Option<Rat> {
        if s.is_empty() {
            return None;
        }
        if let Some(sep) = s.iter().position(|&c| c == b'/') {
            let a = Int::from_str_radix(&s[..sep], 0)?;
            let mut r = ByteScanner::new(&s[sep + 1..]);
            let (scanned, err) = natconv::scan(&mut r, 0, false);
            if err.is_some() || !r.at_eof() || scanned.value.is_empty() {
                return None;
            }
            return Some(Rat::from_frac(&a, &Int::from_parts(false, scanned.value)));
        }
        let mut r = ByteScanner::new(s);
        let neg = scan_sign(&mut r).ok()?;
        let (scanned, err) = natconv::scan(&mut r, 0, true);
        if err.is_some() {
            return None;
        }
        let (exp, ebase) = scan_exponent(&mut r, true, true).ok()?;
        if !r.at_eof() {
            return None;
        }
        let mut a_abs = scanned.value;
        if a_abs.is_empty() {
            return Some(Rat::default());
        }
        let (mut exp2, mut exp5) = (0i64, 0i64);
        if scanned.count < 0 {
            let d = scanned.count;
            match scanned.base {
                10 => {
                    exp5 = d;
                    exp2 = d;
                }
                2 => exp2 = d,
                8 => exp2 = d * 3,
                16 => exp2 = d * 4,
                _ => panic!("unexpected mantissa base"),
            }
        }
        match ebase {
            10 => {
                exp5 = exp5.checked_add(exp)?;
                exp2 = exp2.checked_add(exp)?;
            }
            2 => exp2 = exp2.checked_add(exp)?,
            _ => panic!("unexpected exponent base"),
        }
        let mut b_abs: Nat = vec![1];
        if exp5 != 0 {
            let n = exp5.checked_abs()?;
            if n > 1_000_000 {
                return None;
            }
            let pow5 = nat::exp_nn(&[5], &[n as u64], &[]);
            if exp5 > 0 {
                a_abs = nat::mul(&a_abs, &pow5);
            } else {
                b_abs = pow5;
            }
        }
        if !(-10_000_000..=10_000_000).contains(&exp2) {
            return None;
        }
        if exp2 > 0 {
            a_abs = nat::shl(&a_abs, exp2 as usize);
        } else if exp2 < 0 {
            b_abs = nat::shl(&b_abs, (-exp2) as usize);
        }
        Some(Rat::from_frac(
            &Int::from_parts(neg, a_abs),
            &Int::from_parts(false, b_abs),
        ))
    }

    /// Go's `RatString`: `"a/b"`, or just `"a"` when b == 1.
    pub fn rat_string(&self) -> String {
        if self.is_int() {
            self.a.text(10)
        } else {
            self.to_string()
        }
    }

    /// Go's `FloatString`: decimal with prec digits after the point, the
    /// last digit rounded to nearest with halves away from zero.
    pub fn float_string(&self, prec: usize) -> String {
        let mut buf = String::new();
        if self.is_int() {
            buf.push_str(&self.a.text(10));
            if prec > 0 {
                buf.push('.');
                buf.extend(std::iter::repeat_n('0', prec));
            }
            return buf;
        }
        let (mut q, r) = nat::div(&self.a.abs, &self.den().abs);
        let p: Nat = if prec > 0 {
            nat::exp_nn(&[10], &[prec as u64], &[])
        } else {
            vec![1]
        };
        let r = nat::mul(&r, &p);
        let (mut r, r2) = nat::div(&r, &self.den().abs);
        let r2 = nat::add(&r2, &r2);
        if nat::cmp(&self.den().abs, &r2) != std::cmp::Ordering::Greater {
            r = nat::add_w(&r, 1);
            if nat::cmp(&r, &p) != std::cmp::Ordering::Less {
                q = nat::add_w(&q, 1);
                r = nat::sub(&r, &p);
            }
        }
        if self.a.neg {
            buf.push('-');
        }
        buf.push_str(std::str::from_utf8(&natconv::utoa(&q, 10)).unwrap_or_default());
        if prec > 0 {
            buf.push('.');
            let rs = natconv::utoa(&r, 10);
            buf.extend(std::iter::repeat_n('0', prec.saturating_sub(rs.len())));
            buf.push_str(std::str::from_utf8(&rs).unwrap_or_default());
        }
        buf
    }

    /// Go's `FloatPrec`: the number of fractional decimal digits needed to
    /// represent x exactly, and whether that representation is finite.
    pub fn float_prec(&self) -> (usize, bool) {
        let d = &self.den().abs;
        let p2 = nat::trailing_zero_bits(d);
        let mut q = nat::shr(d, p2);
        const FP: usize = 13;
        let mut tab: Vec<Nat> = Vec::new();
        let mut f: Nat = vec![1220703125];
        loop {
            let (_, r) = nat::div(&q, &f);
            if !r.is_empty() {
                break;
            }
            let next = nat::sqr(&f);
            tab.push(f);
            f = next;
        }
        let mut p5 = 0usize;
        for i in (0..tab.len()).rev() {
            let (t, r) = nat::div(&q, &tab[i]);
            if r.is_empty() {
                p5 += FP * (1 << i);
                q = t;
            }
        }
        loop {
            let (t, r) = nat::div_w(&q, 5);
            if r != 0 {
                break;
            }
            p5 += 1;
            q = t;
        }
        (p2.max(p5), nat::is_one(&q))
    }

    /// Go's `Scan` (`fmt.Scanner`): skip leading white space, read the
    /// longest run of the characters `+-/0123456789.eE` and parse it with
    /// [`Rat::from_string`]. The verb must be one of `efgEFGv`. The byte that
    /// ends the token is left in the reader.
    pub fn scan<R: io::BufRead + ?Sized>(r: &mut R, verb: char) -> io::Result<Rat> {
        let mut src = ReaderSource::tokens(r);
        src.skip_space();
        let mut tok = Vec::new();
        while let Some(b) = src.read_byte() {
            if !b"+-/0123456789.eE".contains(&b) {
                src.unread_byte();
                break;
            }
            tok.push(b);
        }
        if let Some(err) = src.finish() {
            return Err(err);
        }
        if !"efgEFGv".contains(verb) {
            return Err(invalid_data("Rat.Scan: invalid verb"));
        }
        Rat::from_bytes(&tok).ok_or_else(|| invalid_data("Rat.Scan: invalid syntax"))
    }

    /// Go's `AppendText`: buf with the [`Rat::marshal_text`] text appended.
    pub fn append_text(&self, mut buf: Vec<u8>) -> Vec<u8> {
        buf.extend(self.marshal_text());
        buf
    }

    /// Go's `MarshalText`: [`Rat::rat_string`] bytes.
    pub fn marshal_text(&self) -> Vec<u8> {
        self.rat_string().into_bytes()
    }

    /// Go's `UnmarshalText`.
    pub fn unmarshal_text(text: &[u8]) -> Result<Rat, ParseError> {
        Rat::from_bytes(text).ok_or_else(|| {
            ParseError::new(format!(
                "math/big: cannot unmarshal {} into a *big.Rat",
                quote_bytes(text)
            ))
        })
    }

    /// Go's `GobEncode`.
    pub fn gob_encode(&self) -> Result<Vec<u8>, ParseError> {
        let (a, b) = (&self.a.abs, &self.b.abs);
        let mut buf = vec![0u8; 1 + 4 + (a.len() + b.len()) * 8];
        let i = nat::bytes(b, &mut buf);
        let j = nat::bytes(a, &mut buf[..i]);
        let n = i - j;
        let n32 =
            u32::try_from(n).map_err(|_| ParseError::new("Rat.GobEncode: numerator too large"))?;
        buf[j - 4..j].copy_from_slice(&n32.to_be_bytes());
        let j = j - 5;
        buf[j] = (1 << 1) | u8::from(self.a.neg);
        Ok(buf.split_off(j))
    }

    /// Go's `GobDecode` (an empty buffer decodes to zero). Like Go it stores
    /// what it reads: an empty or all-zero denominator is 1, the fraction is
    /// not reduced, and a negative sign on a zero numerator is kept.
    pub fn gob_decode(buf: &[u8]) -> Result<Rat, ParseError> {
        if buf.is_empty() {
            return Ok(Rat::default());
        }
        if buf.len() < 5 {
            return Err(ParseError::new("Rat.GobDecode: buffer too small"));
        }
        let b = buf[0];
        if b >> 1 != 1 {
            return Err(ParseError::new(format!(
                "Rat.GobDecode: encoding version {} not supported",
                b >> 1
            )));
        }
        let ln = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        let i = 5usize
            .checked_add(ln)
            .filter(|&i| i <= buf.len())
            .ok_or_else(|| ParseError::new("Rat.GobDecode: buffer too small"))?;
        Ok(Rat {
            a: Int {
                neg: b & 1 != 0,
                abs: nat::set_bytes(&buf[5..i]),
            },
            b: Int {
                neg: false,
                abs: nat::set_bytes(&buf[i..]),
            },
        })
    }
}

/// Parses like Go's `SetString`/`UnmarshalText`.
impl FromStr for Rat {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Rat, ParseError> {
        Rat::unmarshal_text(s.as_bytes())
    }
}

/// Go's `String`: always `"a/b"`.
impl fmt::Display for Rat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.a.text(10), self.den().text(10))
    }
}

impl fmt::Debug for Rat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
