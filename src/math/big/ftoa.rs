// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the NOTICE file.
//
// Ported from $GOROOT/src/math/big/{ftoa,decimal}.go.

use super::float::{Float, Form};
use super::nat::{self, Nat};
use super::natconv;
use super::{write_padding, FormatSpec};
use std::fmt;

/// A decimal mantissa (ASCII digits, no trailing zeros) and exponent: the
/// value is 0.mant × 10**exp.
#[derive(Debug, Clone, Default)]
struct Decimal {
    mant: Vec<u8>,
    exp: i64,
}

/// Maximum shift amount for a single rsh step (Go's maxShift).
const MAX_SHIFT: u32 = 64 - 4;

impl Decimal {
    fn at(&self, i: i64) -> u8 {
        if 0 <= i && (i as usize) < self.mant.len() {
            self.mant[i as usize]
        } else {
            b'0'
        }
    }

    /// x = m × 2**shift.
    fn init(m: &[u64], mut shift: i64) -> Decimal {
        if m.is_empty() {
            return Decimal::default();
        }
        let mut m: Nat = m.to_vec();
        if shift < 0 {
            let ntz = nat::trailing_zero_bits(&m) as i64;
            let s = (-shift).min(ntz);
            m = nat::shr(&m, s as usize);
            shift += s;
        }
        if shift > 0 {
            m = nat::shl(&m, shift as usize);
            shift = 0;
        }
        let s = natconv::utoa(&m, 10);
        let mut n = s.len();
        let mut x = Decimal {
            mant: Vec::new(),
            exp: n as i64,
        };
        while n > 0 && s[n - 1] == b'0' {
            n -= 1;
        }
        x.mant = s[..n].to_vec();
        if shift < 0 {
            while shift < -i64::from(MAX_SHIFT) {
                x.rsh(MAX_SHIFT);
                shift += i64::from(MAX_SHIFT);
            }
            x.rsh((-shift) as u32);
        }
        x
    }

    /// x >>= s for s <= MAX_SHIFT.
    fn rsh(&mut self, s: u32) {
        let mut r = 0usize;
        let mut n: u64 = 0;
        while n >> s == 0 && r < self.mant.len() {
            let ch = u64::from(self.mant[r]);
            r += 1;
            n = n * 10 + ch - u64::from(b'0');
        }
        if n == 0 {
            self.mant.clear();
            return;
        }
        while n >> s == 0 {
            r += 1;
            n *= 10;
        }
        self.exp += 1 - r as i64;
        let mut w = 0usize;
        let mask = (1u64 << s) - 1;
        while r < self.mant.len() {
            let ch = u64::from(self.mant[r]);
            r += 1;
            let d = n >> s;
            n &= mask;
            self.mant[w] = d as u8 + b'0';
            w += 1;
            n = n * 10 + ch - u64::from(b'0');
        }
        while n > 0 && w < self.mant.len() {
            let d = n >> s;
            n &= mask;
            self.mant[w] = d as u8 + b'0';
            w += 1;
            n *= 10;
        }
        self.mant.truncate(w);
        while n > 0 {
            let d = n >> s;
            n &= mask;
            self.mant.push(d as u8 + b'0');
            n *= 10;
        }
        self.trim();
    }

    fn should_round_up(&self, n: usize) -> bool {
        if self.mant[n] == b'5' && n + 1 == self.mant.len() {
            return n > 0 && (self.mant[n - 1] - b'0') & 1 != 0;
        }
        self.mant[n] >= b'5'
    }

    fn round(&mut self, n: i64) {
        if n < 0 || n >= self.mant.len() as i64 {
            return;
        }
        if self.should_round_up(n as usize) {
            self.round_up(n);
        } else {
            self.round_down(n);
        }
    }

    fn round_up(&mut self, n: i64) {
        if n < 0 || n >= self.mant.len() as i64 {
            return;
        }
        let mut n = n as usize;
        while n > 0 && self.mant[n - 1] >= b'9' {
            n -= 1;
        }
        if n == 0 {
            self.mant[0] = b'1';
            self.mant.truncate(1);
            self.exp += 1;
            return;
        }
        self.mant[n - 1] += 1;
        self.mant.truncate(n);
    }

    fn round_down(&mut self, n: i64) {
        if n < 0 || n >= self.mant.len() as i64 {
            return;
        }
        self.mant.truncate(n as usize);
        self.trim();
    }

    fn trim(&mut self) {
        while self.mant.last() == Some(&b'0') {
            self.mant.pop();
        }
        if self.mant.is_empty() {
            self.exp = 0;
        }
    }
}

/// Go's roundShortest: the shortest decimal that rounds back to x at x's
/// precision.
fn round_shortest(d: &mut Decimal, x: &Float) {
    if d.mant.is_empty() {
        return;
    }
    let mut mant: Nat = x.mant.clone();
    let mut exp = i64::from(x.exp) - nat::bit_len(&mant) as i64;
    let s = nat::bit_len(&mant) as i64 - (i64::from(x.prec) + 1);
    if s < 0 {
        mant = nat::shl(&mant, (-s) as usize);
    } else if s > 0 {
        mant = nat::shr(&mant, s as usize);
    }
    exp += s;
    let lower = Decimal::init(&nat::sub_w(&mant, 1), exp);
    let upper = Decimal::init(&nat::add_w(&mant, 1), exp);
    let inclusive = mant[0] & 2 == 0;
    for i in 0..d.mant.len() {
        let m = d.mant[i];
        let l = lower.at(i as i64);
        let u = upper.at(i as i64);
        let okdown = l != m || inclusive && i + 1 == lower.mant.len();
        let okup = m != u
            && (inclusive
                || m + 1 < u
                || i + 1 < upper.mant.len()
                || i >= upper.mant.len() && m < b'9');
        if okdown && okup {
            d.round(i as i64 + 1);
            return;
        } else if okdown {
            d.round_down(i as i64 + 1);
            return;
        } else if okup {
            d.round_up(i as i64 + 1);
            return;
        }
    }
}

fn fmt_e(buf: &mut Vec<u8>, fmt: u8, prec: i64, d: &Decimal) {
    let ch = d.mant.first().copied().unwrap_or(b'0');
    buf.push(ch);
    if prec > 0 {
        buf.push(b'.');
        let mut i = 1usize;
        let m = d.mant.len().min(prec as usize + 1);
        if i < m {
            buf.extend_from_slice(&d.mant[i..m]);
            i = m;
        }
        while (i as i64) <= prec {
            buf.push(b'0');
            i += 1;
        }
    }
    buf.push(fmt);
    let mut exp = if d.mant.is_empty() { 0 } else { d.exp - 1 };
    if exp < 0 {
        buf.push(b'-');
        exp = -exp;
    } else {
        buf.push(b'+');
    }
    if exp < 10 {
        buf.push(b'0');
    }
    buf.extend_from_slice(exp.to_string().as_bytes());
}

fn fmt_f(buf: &mut Vec<u8>, prec: i64, d: &Decimal) {
    if d.exp > 0 {
        let mut m = d.mant.len().min(d.exp as usize);
        buf.extend_from_slice(&d.mant[..m]);
        while (m as i64) < d.exp {
            buf.push(b'0');
            m += 1;
        }
    } else {
        buf.push(b'0');
    }
    if prec > 0 {
        buf.push(b'.');
        for i in 0..prec {
            buf.push(d.at(d.exp + i));
        }
    }
}

impl Float {
    /// Go's `Text`: x in format `'e'`, `'E'`, `'f'`, `'g'`, `'G'` (decimal),
    /// `'b'` (decimal mantissa, binary exponent), `'p'` (hex mantissa,
    /// binary exponent) or `'x'`/`'X'` (hex mantissa, decimal power-of-two
    /// exponent). prec is the number of digits (as Go's `Text`); a negative
    /// prec selects the shortest representation that round-trips at x's
    /// precision. Unknown formats produce `%` followed by the format byte.
    pub fn text(&self, format: u8, prec: i64) -> String {
        let buf = self.append(Vec::with_capacity(10 + prec.max(0) as usize), format, prec);
        String::from_utf8(buf).unwrap_or_default()
    }

    /// Go's `Append`: buf with [`Float::text`] appended.
    pub fn append(&self, mut buf: Vec<u8>, format: u8, mut prec: i64) -> Vec<u8> {
        if self.neg {
            buf.push(b'-');
        }
        if self.form == Form::Inf {
            if !self.neg {
                buf.push(b'+');
            }
            buf.extend_from_slice(b"Inf");
            return buf;
        }
        match format {
            b'b' => return self.fmt_b(buf),
            b'p' => return self.fmt_p(buf),
            b'x' => return self.fmt_x(buf, prec),
            _ => {}
        }
        let mut d = if self.form == Form::Finite {
            Decimal::init(
                &self.mant,
                i64::from(self.exp) - nat::bit_len(&self.mant) as i64,
            )
        } else {
            Decimal::default()
        };
        let mut shortest = false;
        if prec < 0 {
            shortest = true;
            round_shortest(&mut d, self);
            match format {
                b'e' | b'E' => prec = d.mant.len() as i64 - 1,
                b'f' => prec = (d.mant.len() as i64 - d.exp).max(0),
                b'g' | b'G' => prec = d.mant.len() as i64,
                _ => {}
            }
        } else {
            match format {
                b'e' | b'E' => d.round(1 + prec),
                b'f' => d.round(d.exp + prec),
                b'g' | b'G' => {
                    if prec == 0 {
                        prec = 1;
                    }
                    d.round(prec);
                }
                _ => {}
            }
        }
        match format {
            b'e' | b'E' => {
                fmt_e(&mut buf, format, prec, &d);
                buf
            }
            b'f' => {
                fmt_f(&mut buf, prec, &d);
                buf
            }
            b'g' | b'G' => {
                let mut eprec = prec;
                if eprec > d.mant.len() as i64 && d.mant.len() as i64 >= d.exp {
                    eprec = d.mant.len() as i64;
                }
                if shortest {
                    eprec = 6;
                }
                let exp = d.exp - 1;
                if exp < -4 || exp >= eprec {
                    if prec > d.mant.len() as i64 {
                        prec = d.mant.len() as i64;
                    }
                    fmt_e(&mut buf, format + b'e' - b'g', prec - 1, &d);
                    return buf;
                }
                if prec > d.exp {
                    prec = d.mant.len() as i64;
                }
                fmt_f(&mut buf, (prec - d.exp).max(0), &d);
                buf
            }
            _ => {
                if self.neg {
                    buf.pop();
                }
                buf.push(b'%');
                buf.push(format);
                buf
            }
        }
    }

    fn fmt_b(&self, mut buf: Vec<u8>) -> Vec<u8> {
        if self.form == Form::Zero {
            buf.push(b'0');
            return buf;
        }
        let w = self.mant.len() as u64 * 64;
        let prec = u64::from(self.prec);
        let m = if w < prec {
            nat::shl(&self.mant, (prec - w) as usize)
        } else if w > prec {
            nat::shr(&self.mant, (w - prec) as usize)
        } else {
            self.mant.clone()
        };
        buf.extend(natconv::utoa(&m, 10));
        buf.push(b'p');
        let e = i64::from(self.exp) - prec as i64;
        if e >= 0 {
            buf.push(b'+');
        }
        buf.extend_from_slice(e.to_string().as_bytes());
        buf
    }

    fn fmt_x(&self, mut buf: Vec<u8>, prec: i64) -> Vec<u8> {
        if self.form == Form::Zero {
            buf.extend_from_slice(b"0x0");
            if prec > 0 {
                buf.push(b'.');
                buf.extend(std::iter::repeat_n(b'0', prec as usize));
            }
            buf.extend_from_slice(b"p+00");
            return buf;
        }
        let n: u64 = if prec < 0 {
            1 + (self.min_prec() - 1).div_ceil(4) * 4
        } else {
            1 + 4 * prec as u64
        };
        let n = n.min(u64::from(u32::MAX)) as u32;
        let mut x = Float::with_prec(n);
        x.set_mode(self.mode);
        x.set(self);
        let w = x.mant.len() as u64 * 64;
        let n = u64::from(n);
        let m = if w < n {
            nat::shl(&x.mant, (n - w) as usize)
        } else if w > n {
            nat::shr(&x.mant, (w - n) as usize)
        } else {
            x.mant.clone()
        };
        let mut exp64 = i64::from(x.exp) - 1;
        let hm = natconv::utoa(&m, 16);
        buf.extend_from_slice(b"0x1");
        if hm.len() > 1 {
            buf.push(b'.');
            buf.extend_from_slice(&hm[1..]);
        }
        buf.push(b'p');
        if exp64 >= 0 {
            buf.push(b'+');
        } else {
            exp64 = -exp64;
            buf.push(b'-');
        }
        if exp64 < 10 {
            buf.push(b'0');
        }
        buf.extend_from_slice(exp64.to_string().as_bytes());
        buf
    }

    fn fmt_p(&self, mut buf: Vec<u8>) -> Vec<u8> {
        if self.form == Form::Zero {
            buf.push(b'0');
            return buf;
        }
        let i = self
            .mant
            .iter()
            .position(|&w| w != 0)
            .unwrap_or(self.mant.len());
        let m = &self.mant[i..];
        buf.extend_from_slice(b"0x.");
        let mut hex = natconv::utoa(m, 16);
        while hex.last() == Some(&b'0') {
            hex.pop();
        }
        buf.extend(hex);
        buf.push(b'p');
        if self.exp >= 0 {
            buf.push(b'+');
        }
        buf.extend_from_slice(self.exp.to_string().as_bytes());
        buf
    }

    /// Go's `Format` for `fmt` verbs `e`, `E`, `f`, `F`, `g`, `G`, `b`,
    /// `p`, `x` and `v` (as `g`), with Go's flags, width and precision.
    /// Precision defaults to 6 for `e`/`f` and to shortest for `g`/`v`.
    /// Other verbs (including `X`, as in Go) produce Go's
    /// `%!c(*big.Float=…)` text.
    pub fn format(&self, verb: char, spec: &FormatSpec) -> String {
        let has_prec = spec.precision.is_some();
        let mut prec = spec.precision.map_or(6, |p| p as i64);
        let format = match verb {
            'e' | 'E' | 'f' | 'b' | 'p' | 'x' => verb as u8,
            'F' => b'f',
            'v' | 'g' | 'G' => {
                if !has_prec {
                    prec = -1;
                }
                if verb == 'v' {
                    b'g'
                } else {
                    verb as u8
                }
            }
            _ => return format!("%!{verb}(*big.Float={self})"),
        };
        let mut buf = self.append(Vec::new(), format, prec);
        if buf.is_empty() {
            buf = b"?".to_vec();
        }
        let sign = if buf[0] == b'-' {
            buf.remove(0);
            "-"
        } else if buf[0] == b'+' {
            buf.remove(0);
            if spec.space {
                " "
            } else {
                "+"
            }
        } else if spec.plus {
            "+"
        } else if spec.space {
            " "
        } else {
            ""
        };
        let body = String::from_utf8(buf).unwrap_or_default();
        let mut padding = 0;
        if let Some(width) = spec.width {
            if width > sign.len() + body.len() {
                padding = width - sign.len() - body.len();
            }
        }
        let mut out = String::new();
        if spec.zero && !self.is_inf() {
            out.push_str(sign);
            write_padding(&mut out, '0', padding);
            out.push_str(&body);
        } else if spec.minus {
            out.push_str(sign);
            out.push_str(&body);
            write_padding(&mut out, ' ', padding);
        } else {
            write_padding(&mut out, ' ', padding);
            out.push_str(sign);
            out.push_str(&body);
        }
        out
    }
}

/// Go's `String`: `Text('g', 10)`. A Rust precision selects `'g'` digits
/// and width/fill/alignment are applied by the formatter.
impl fmt::Display for Float {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prec = f.precision().map_or(10, |p| p as i64);
        f.pad(&self.text(b'g', prec))
    }
}

/// Go's `%e` with Rust's flags, width and precision.
impl fmt::LowerExp for Float {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.format('e', &FormatSpec::from_formatter(f)))
    }
}

/// Go's `%E` with Rust's flags, width and precision.
impl fmt::UpperExp for Float {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.format('E', &FormatSpec::from_formatter(f)))
    }
}
