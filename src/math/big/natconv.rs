// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the NOTICE file.
//
// Ported from $GOROOT/src/math/big/natconv.go.

//! Conversion between magnitudes and digit strings.
//!
//! Formatting splits large values recursively by tabulated powers of the base
//! (as Go does), so its cost is dominated by division. Parsing collects
//! word-sized digit groups and combines them by divide and conquer
//! (hi·base^k + lo), which is O(M(n)·log n) with Karatsuba multiplication
//! rather than the O(n²) of Go's digit-group loop; results are identical.

use super::nat::{self, Nat};
use std::cmp::Ordering;

pub(super) const DIGITS: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// The largest number base accepted for string conversions.
pub const MAX_BASE: u32 = 62;
const MAX_BASE_SMALL: u64 = 36;

/// Leaf size (in limbs) for recursive formatting, as in Go.
const LEAF_SIZE: usize = 8;

/// (b**n, n) with b**n the largest power of b that fits in a limb.
pub(super) fn max_pow(b: u64) -> (u64, usize) {
    let (mut p, mut n) = (b, 1);
    let max = u64::MAX / b;
    while p <= max {
        p *= b;
        n += 1;
    }
    (p, n)
}

/// x**n for n > 0, and 1 otherwise (wrapping, as Go's Word arithmetic).
pub(super) fn pow(mut x: u64, mut n: usize) -> u64 {
    let mut p = 1u64;
    while n > 0 {
        if n & 1 != 0 {
            p = p.wrapping_mul(x);
        }
        x = x.wrapping_mul(x);
        n >>= 1;
    }
    p
}

/// Go's `io.ByteScanner`: a byte source with one byte of push-back.
pub(super) trait ByteSource {
    fn read_byte(&mut self) -> Option<u8>;
    /// Push back the byte just read.
    fn unread_byte(&mut self);
}

/// A [`ByteSource`] over a byte string (Go's `strings.Reader`).
#[derive(Debug, Clone)]
pub(super) struct ByteScanner<'a> {
    s: &'a [u8],
    pos: usize,
}

impl<'a> ByteScanner<'a> {
    pub(super) fn new(s: &'a [u8]) -> Self {
        Self { s, pos: 0 }
    }

    pub(super) fn at_eof(&self) -> bool {
        self.pos >= self.s.len()
    }
}

impl ByteSource for ByteScanner<'_> {
    fn read_byte(&mut self) -> Option<u8> {
        let b = self.s.get(self.pos).copied();
        if b.is_some() {
            self.pos += 1;
        }
        b
    }

    fn unread_byte(&mut self) {
        self.pos -= 1;
    }
}

/// A [`ByteSource`] over a `BufRead`, standing in for Go's `fmt.ScanState`:
/// a byte is consumed from the reader only once the next byte is requested
/// (or [`ReaderSource::finish`] is called), so a pushed-back byte stays in
/// the reader. Like Go's number scanners, a non-ASCII byte is an error
/// unless the source was made with [`ReaderSource::tokens`].
pub(super) struct ReaderSource<'r, R: std::io::BufRead + ?Sized> {
    r: &'r mut R,
    pending: bool,
    ascii_only: bool,
    err: Option<std::io::Error>,
}

impl<'r, R: std::io::BufRead + ?Sized> ReaderSource<'r, R> {
    pub(super) fn new(r: &'r mut R) -> Self {
        Self {
            r,
            pending: false,
            ascii_only: true,
            err: None,
        }
    }

    /// A source that returns non-ASCII bytes instead of failing (Go's
    /// `ScanState.Token`, which stops at any rune outside the token set).
    pub(super) fn tokens(r: &'r mut R) -> Self {
        Self {
            ascii_only: false,
            ..Self::new(r)
        }
    }

    fn commit(&mut self) {
        if self.pending {
            self.r.consume(1);
            self.pending = false;
        }
    }

    /// Skip leading ASCII white space (Go's `SkipSpace`).
    pub(super) fn skip_space(&mut self) {
        while let Some(b) = self.read_byte() {
            if !b.is_ascii_whitespace() {
                self.unread_byte();
                break;
            }
        }
    }

    /// Consume the last byte read unless it was pushed back, and return any
    /// read error.
    pub(super) fn finish(mut self) -> Option<std::io::Error> {
        self.commit();
        self.err
    }
}

impl<R: std::io::BufRead + ?Sized> ByteSource for ReaderSource<'_, R> {
    fn read_byte(&mut self) -> Option<u8> {
        self.commit();
        if self.err.is_some() {
            return None;
        }
        let b = loop {
            match self.r.fill_buf() {
                Ok(buf) => break buf.first().copied(),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    self.err = Some(e);
                    return None;
                }
            }
        }?;
        if b >= 0x80 && self.ascii_only {
            self.err = Some(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid rune {b:#x}"),
            ));
            return None;
        }
        self.pending = true;
        Some(b)
    }

    fn unread_byte(&mut self) {
        self.pending = false;
    }
}

/// Syntax errors reported by Go's scanners.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ScanError {
    /// "number has no digits"
    NoDigits,
    /// "'_' must separate successive digits"
    InvalSep,
    /// No input at all (Go's io.EOF from scanSign).
    Eof,
    /// An exponent that does not fit in an int64 (Go's strconv error text).
    ExpRange(String),
}

impl ScanError {
    pub(super) fn message(&self) -> String {
        match self {
            ScanError::NoDigits => "number has no digits".to_string(),
            ScanError::InvalSep => "'_' must separate successive digits".to_string(),
            ScanError::Eof => "EOF".to_string(),
            ScanError::ExpRange(msg) => msg.clone(),
        }
    }
}

/// The result of [`scan`]: value, actual base, and Go's digit count (a
/// count <= 0 means a radix point was seen and -count fractional digits).
pub(super) struct Scanned {
    pub(super) value: Nat,
    pub(super) base: u32,
    pub(super) count: i64,
}

/// Go's `nat.scan`: the longest prefix of r that is an unsigned number in
/// the given base. Panics on an invalid base, as Go does.
pub(super) fn scan<S: ByteSource + ?Sized>(
    r: &mut S,
    base: u32,
    mut frac_ok: bool,
) -> (Scanned, Option<ScanError>) {
    let base_ok = base == 0
        || !frac_ok && (2..=MAX_BASE).contains(&base)
        || frac_ok && matches!(base, 2 | 8 | 10 | 16);
    if !base_ok {
        panic!("invalid number base {base}");
    }
    let mut prev = b'.';
    let mut inval_sep = false;
    let mut ch = r.read_byte();
    let mut b = base;
    let mut prefix = 0u8;
    let mut count: i64 = 0;
    if base == 0 {
        b = 10;
        if ch == Some(b'0') {
            prev = b'0';
            count = 1;
            ch = r.read_byte();
            if let Some(c) = ch {
                match c {
                    b'b' | b'B' => (b, prefix) = (2, b'b'),
                    b'o' | b'O' => (b, prefix) = (8, b'o'),
                    b'x' | b'X' => (b, prefix) = (16, b'x'),
                    _ => {
                        if !frac_ok {
                            (b, prefix) = (8, b'0');
                        }
                    }
                }
                if prefix != 0 {
                    count = 0;
                    if prefix != b'0' {
                        ch = r.read_byte();
                    }
                }
            }
        }
    }

    let b1 = u64::from(b);
    let (bn, n) = max_pow(b1);
    let mut groups: Vec<u64> = Vec::new();
    let mut di = 0u64;
    let mut i = 0usize;
    let mut dp: i64 = -1;
    while let Some(c) = ch {
        if c == b'.' && frac_ok {
            frac_ok = false;
            if prev == b'_' {
                inval_sep = true;
            }
            prev = b'.';
            dp = count;
        } else if c == b'_' && base == 0 {
            if prev != b'0' {
                inval_sep = true;
            }
            prev = b'_';
        } else {
            let d1 = match c {
                b'0'..=b'9' => u64::from(c - b'0'),
                b'a'..=b'z' => u64::from(c - b'a') + 10,
                b'A'..=b'Z' => {
                    if b1 <= MAX_BASE_SMALL {
                        u64::from(c - b'A') + 10
                    } else {
                        u64::from(c - b'A') + MAX_BASE_SMALL
                    }
                }
                _ => u64::from(MAX_BASE) + 1,
            };
            if d1 >= b1 {
                r.unread_byte();
                break;
            }
            prev = b'0';
            count += 1;
            di = di * b1 + d1;
            i += 1;
            if i == n {
                groups.push(di);
                di = 0;
                i = 0;
            }
        }
        ch = r.read_byte();
    }

    let mut err = None;
    if inval_sep || prev == b'_' {
        err = Some(ScanError::InvalSep);
    }
    if count == 0 {
        if prefix == b'0' {
            // Only the octal prefix "0" (possibly followed by separators and
            // digits > 7): decimal 0.
            let scanned = Scanned {
                value: Vec::new(),
                base: 10,
                count: 1,
            };
            return (scanned, err);
        }
        err = Some(ScanError::NoDigits);
    }
    let mut value = combine(&groups, bn);
    if i > 0 {
        value = nat::mul_add_ww(&value, pow(b1, i), di);
    }
    if dp >= 0 {
        count = dp - count;
    }
    (
        Scanned {
            value,
            base: b,
            count,
        },
        err,
    )
}

/// The value of full digit groups (most significant first) in base bn.
fn combine(groups: &[u64], bn: u64) -> Nat {
    let mut pows: Vec<Nat> = vec![nat::from_u64(bn)];
    combine_rec(groups, &mut pows)
}

fn combine_rec(groups: &[u64], pows: &mut Vec<Nat>) -> Nat {
    if groups.len() <= 32 {
        let bn = pows[0][0];
        let mut z = Vec::new();
        for &g in groups {
            z = nat::mul_add_ww(&z, bn, g);
        }
        return z;
    }
    let mut k = 0;
    while (2usize << k) < groups.len() {
        k += 1;
    }
    while pows.len() <= k {
        let last = pows.last().map(|p| nat::sqr(p)).unwrap_or_default();
        pows.push(last);
    }
    let split = groups.len() - (1usize << k);
    let hi = combine_rec(&groups[..split], pows);
    let lo = combine_rec(&groups[split..], pows);
    nat::add(&nat::mul(&hi, &pows[k]), &lo)
}

/// Digits of x in base (2..=62), without sign.
pub(super) fn utoa(x: &[u64], base: u32) -> Vec<u8> {
    itoa(x, false, base)
}

/// Digits of x in base, with a leading '-' if neg and x != 0.
pub(super) fn itoa(x: &[u64], neg: bool, base: u32) -> Vec<u8> {
    if !(2..=MAX_BASE).contains(&base) {
        panic!("invalid base");
    }
    if x.is_empty() {
        return b"0".to_vec();
    }
    let b = u64::from(base);
    let mut s: Vec<u8> = if b & (b - 1) == 0 {
        let shift = b.trailing_zeros() as usize;
        let nbits = nat::bit_len(x);
        let ndig = nbits.div_ceil(shift);
        let mut s = Vec::with_capacity(ndig + 1);
        for k in (0..ndig).rev() {
            let mut d = 0usize;
            for j in (0..shift).rev() {
                d = (d << 1) | nat::bit(x, k * shift + j) as usize;
            }
            s.push(DIGITS[d]);
        }
        s
    } else {
        let len = (nat::bit_len(x) as f64 / (base as f64).log2()) as usize + 2;
        let mut s = vec![0u8; len];
        let (bb, ndigits) = max_pow(b);
        let table = divisors(x.len(), b, ndigits, bb);
        convert_words(x.to_vec(), &mut s, b, ndigits, bb, &table);
        let first = s.iter().position(|&c| c != b'0').unwrap_or(s.len() - 1);
        s.drain(..first);
        s
    };
    if neg {
        s.insert(0, b'-');
    }
    s
}

struct Divisor {
    bbb: Nat,
    nbits: usize,
    ndigits: usize,
}

fn divisors(m: usize, b: u64, ndigits: usize, bb: u64) -> Vec<Divisor> {
    if m <= LEAF_SIZE {
        return Vec::new();
    }
    let mut k = 1;
    let mut words = LEAF_SIZE;
    while words < m >> 1 && k < 64 {
        words <<= 1;
        k += 1;
    }
    let mut table: Vec<Divisor> = Vec::with_capacity(k);
    for i in 0..k {
        let (mut bbb, mut nd) = if i == 0 {
            (
                nat::exp_nn(&[bb], &[LEAF_SIZE as u64], &[]),
                ndigits * LEAF_SIZE,
            )
        } else {
            (nat::sqr(&table[i - 1].bbb), 2 * table[i - 1].ndigits)
        };
        // Exploit aggregated extra bits in macro blocks.
        loop {
            let larger = nat::mul_add_ww(&bbb, b, 0);
            if larger.len() != bbb.len() {
                break;
            }
            bbb = larger;
            nd += 1;
        }
        let nbits = nat::bit_len(&bbb);
        table.push(Divisor {
            bbb,
            nbits,
            ndigits: nd,
        });
    }
    table
}

fn convert_words(mut q: Nat, s: &mut [u8], b: u64, ndigits: usize, bb: u64, table: &[Divisor]) {
    let mut end = s.len();
    if !table.is_empty() {
        let mut index = table.len() as isize - 1;
        while q.len() > LEAF_SIZE {
            let max_length = nat::bit_len(&q);
            let min_length = max_length >> 1;
            while index > 0 && table[(index - 1) as usize].nbits > min_length {
                index -= 1;
            }
            let entry = &table[index as usize];
            if entry.nbits >= max_length && nat::cmp(&entry.bbb, &q) != Ordering::Less {
                index -= 1;
                assert!(index >= 0, "internal inconsistency");
            }
            let entry = &table[index as usize];
            let (qq, r) = nat::div(&q, &entry.bbb);
            q = qq;
            let h = end - entry.ndigits;
            convert_words(r, &mut s[h..end], b, ndigits, bb, &table[..index as usize]);
            end = h;
        }
    }
    let s = &mut s[..end];
    let mut i = s.len();
    while !q.is_empty() {
        let (qq, mut r) = nat::div_w(&q, bb);
        q = qq;
        let mut j = 0;
        while j < ndigits && i > 0 {
            i -= 1;
            s[i] = DIGITS[(r % b) as usize];
            r /= b;
            j += 1;
        }
    }
    for c in s[..i].iter_mut() {
        *c = b'0';
    }
}
