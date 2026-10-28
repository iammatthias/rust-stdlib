// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the NOTICE file.
//
// Ported from $GOROOT/src/math/big/{floatconv,floatmarsh}.go.

use super::float::{Float, Form, MAX_EXP, MIN_EXP};
use super::intconv::{invalid_data, quote_bytes, scan_sign};
use super::nat;
use super::natconv::{self, ByteScanner, ByteSource, ReaderSource, ScanError};
use super::ratconv::scan_exponent;
use super::{Accuracy, ParseError, RoundingMode};
use std::io;
use std::str::FromStr;

const POW5_TAB: [u64; 28] = [
    1,
    5,
    25,
    125,
    625,
    3125,
    15625,
    78125,
    390625,
    1953125,
    9765625,
    48828125,
    244140625,
    1220703125,
    6103515625,
    30517578125,
    152587890625,
    762939453125,
    3814697265625,
    19073486328125,
    95367431640625,
    476837158203125,
    2384185791015625,
    11920928955078125,
    59604644775390625,
    298023223876953125,
    1490116119384765625,
    7450580596923828125,
];

/// Go's `%q` for a single byte read as a rune.
fn quote_byte(b: u8) -> String {
    match b {
        b'\'' => "'\\''".to_string(),
        b'\\' => "'\\\\'".to_string(),
        0x07 => "'\\a'".to_string(),
        0x08 => "'\\b'".to_string(),
        0x0c => "'\\f'".to_string(),
        b'\n' => "'\\n'".to_string(),
        b'\r' => "'\\r'".to_string(),
        b'\t' => "'\\t'".to_string(),
        0x0b => "'\\v'".to_string(),
        0..=0x1f | 0x7f => format!("'\\x{b:02x}'"),
        0x80..=0xa0 | 0xad => format!("'\\u{b:04x}'"),
        _ => format!("'{}'", char::from(b)),
    }
}

fn scan_message(err: ScanError) -> String {
    err.message()
}

impl Float {
    /// Go's Float.scan.
    fn scan_from<S: ByteSource + ?Sized>(&mut self, r: &mut S, base: u32) -> Result<u32, String> {
        let prec = if self.prec == 0 { 64 } else { self.prec };
        self.form = Form::Zero;
        self.neg = scan_sign(r).map_err(scan_message)?;
        let (scanned, err) = natconv::scan(r, base, true);
        if let Some(err) = err {
            return Err(scan_message(err));
        }
        let b = scanned.base;
        let (exp, ebase) = scan_exponent(r, true, base == 0).map_err(scan_message)?;
        self.mant = scanned.value;
        if self.mant.is_empty() {
            self.prec = prec;
            self.acc = Accuracy::Exact;
            self.form = Form::Zero;
            return Ok(b);
        }
        let shift = nat::fnorm(&mut self.mant);
        let mut exp2 = self.mant.len() as i64 * 64 - shift;
        let mut exp5 = 0i64;
        if scanned.count < 0 {
            let d = scanned.count;
            match b {
                10 => {
                    exp5 = d;
                    exp2 += d;
                }
                2 => exp2 += d,
                8 => exp2 += d * 3,
                16 => exp2 += d * 4,
                _ => panic!("unexpected mantissa base"),
            }
        }
        // Go's int64 arithmetic wraps; any wrapped value is far outside the
        // exponent range, so overflow is reported the same way.
        let overflow = || "exponent overflow".to_string();
        match ebase {
            10 => {
                exp5 = exp5.checked_add(exp).ok_or_else(overflow)?;
                exp2 = exp2.checked_add(exp).ok_or_else(overflow)?;
            }
            2 => exp2 = exp2.checked_add(exp).ok_or_else(overflow)?,
            _ => panic!("unexpected exponent base"),
        }
        if !(MIN_EXP..=MAX_EXP).contains(&exp2) {
            return Err(overflow());
        }
        self.prec = prec;
        self.form = Form::Finite;
        self.exp = exp2 as i32;
        if exp5 == 0 {
            self.round(0);
            return Ok(b);
        }
        let mut p = Float::with_prec(self.prec.saturating_add(64));
        let z = self.clone();
        if exp5 < 0 {
            p.pow5(exp5.unsigned_abs());
            let _ = self.quo_into(&z, &p);
        } else {
            p.pow5(exp5 as u64);
            let _ = self.mul_into(&z, &p);
        }
        Ok(b)
    }

    /// z = 5**n, using precision z.prec + 64 for intermediate powers.
    fn pow5(&mut self, mut n: u64) {
        const M: u64 = POW5_TAB.len() as u64 - 1;
        if n <= M {
            self.set_uint64(POW5_TAB[n as usize]);
            return;
        }
        self.set_uint64(POW5_TAB[M as usize]);
        n -= M;
        let mut f = Float::with_prec(self.prec.saturating_add(64));
        f.set_uint64(5);
        while n > 0 {
            if n & 1 != 0 {
                let z = self.clone();
                let _ = self.mul_into(&z, &f);
            }
            let ff = f.clone();
            let _ = f.mul_into(&ff, &ff);
            n >>= 1;
        }
    }

    /// Go's `Parse`: parse s in base 0, 2, 8, 10 or 16 (mantissa with
    /// optional radix point, `e`/`p` exponent, `Inf`) and round to the
    /// receiver's precision (64 if 0) and mode. Base 0 accepts Go's
    /// prefixes and `_` separators. Returns the actual base. Panics on
    /// another base, as Go does.
    /// Like a Go string, the input may be any bytes.
    pub fn parse<S: AsRef<[u8]> + ?Sized>(&mut self, s: &S, base: u32) -> Result<u32, ParseError> {
        self.parse_bytes(s.as_ref(), base)
    }

    fn parse_bytes(&mut self, s: &[u8], base: u32) -> Result<u32, ParseError> {
        if s == b"Inf" || s == b"inf" {
            self.set_inf(false);
            return Ok(0);
        }
        if s.len() == 4
            && (s[0] == b'+' || s[0] == b'-')
            && (&s[1..] == b"Inf" || &s[1..] == b"inf")
        {
            self.set_inf(s[0] == b'-');
            return Ok(0);
        }
        let mut r = ByteScanner::new(s);
        let b = self.scan_from(&mut r, base).map_err(ParseError::new)?;
        if let Some(ch) = r.read_byte() {
            return Err(ParseError::new(format!(
                "expected end of string, found {}",
                quote_byte(ch)
            )));
        }
        Ok(b)
    }

    /// Go's `SetString`: [`Float::parse`] in base 0; `None` on error.
    pub fn set_string<S: AsRef<[u8]> + ?Sized>(&mut self, s: &S) -> Option<&mut Float> {
        self.parse(s, 0).ok()?;
        Some(self)
    }

    /// Go's `ParseFloat(s, base, prec, mode)`: a new Float and the actual
    /// base.
    pub fn parse_float<S: AsRef<[u8]> + ?Sized>(
        s: &S,
        base: u32,
        prec: u32,
        mode: RoundingMode,
    ) -> Result<(Float, u32), ParseError> {
        let mut z = Float::with_prec(prec);
        z.set_mode(mode);
        let b = z.parse(s, base)?;
        Ok((z, b))
    }

    /// Go's `Scan` (`fmt.Scanner`): skip leading white space and read the
    /// longest prefix of r that is a number in Go's base-0 float syntax,
    /// rounded to the receiver's precision (64 if 0) and mode. Unlike
    /// [`Float::parse`], `Inf` is not recognized (as in Go). The byte that
    /// ends the number is left in the reader.
    pub fn scan<R: io::BufRead + ?Sized>(&mut self, r: &mut R) -> io::Result<()> {
        let mut src = ReaderSource::new(r);
        src.skip_space();
        let result = self.scan_from(&mut src, 0);
        if let Some(err) = src.finish() {
            return Err(err);
        }
        match result {
            Ok(_) => Ok(()),
            Err(msg) if msg == "EOF" => Err(io::Error::new(io::ErrorKind::UnexpectedEof, msg)),
            Err(msg) => Err(invalid_data(msg)),
        }
    }

    /// Go's `AppendText`: buf with [`Float::marshal_text`] appended.
    pub fn append_text(&self, buf: Vec<u8>) -> Vec<u8> {
        self.append(buf, b'g', -1)
    }

    /// Go's `MarshalText`: `Text('g', -1)` (shortest at x's precision).
    pub fn marshal_text(&self) -> Vec<u8> {
        self.append(Vec::new(), b'g', -1)
    }

    /// Go's `UnmarshalText`: [`Float::parse`] in base 0 into the receiver.
    pub fn unmarshal_text(&mut self, text: &[u8]) -> Result<(), ParseError> {
        self.parse_bytes(text, 0).map(|_| ()).map_err(|err| {
            ParseError::new(format!(
                "math/big: cannot unmarshal {} into a *big.Float ({err})",
                quote_bytes(text)
            ))
        })
    }

    /// Go's `GobEncode`: version, mode/accuracy/form/sign, precision,
    /// exponent and the mantissa words needed for the precision.
    pub fn gob_encode(&self) -> Vec<u8> {
        let mut sz = 1 + 1 + 4;
        let mut n = 0usize;
        if self.form == Form::Finite {
            n = self.prec.div_ceil(64) as usize;
            n = n.min(self.mant.len());
            sz += 4 + n * 8;
        }
        let mut buf = vec![0u8; sz];
        buf[0] = 1;
        let acc_bits = (i16::from(self.acc.0) + 1) as u8 & 3;
        let mut b = (self.mode.0 & 7) << 5 | acc_bits << 3 | (self.form as u8 & 3) << 1;
        if self.neg {
            b |= 1;
        }
        buf[1] = b;
        buf[2..6].copy_from_slice(&self.prec.to_be_bytes());
        if self.form == Form::Finite {
            buf[6..10].copy_from_slice(&self.exp.to_be_bytes());
            let words = &self.mant[self.mant.len() - n..];
            nat::bytes(words, &mut buf[10..]);
        }
        buf
    }

    /// Go's `GobDecode` into the receiver (an empty buffer resets it to the
    /// zero value). If the receiver has a non-zero precision, its precision
    /// and mode are kept and the decoded value is rounded to them.
    pub fn gob_decode(&mut self, buf: &[u8]) -> Result<(), ParseError> {
        if buf.is_empty() {
            *self = Float::new();
            return Ok(());
        }
        if buf.len() < 6 {
            return Err(ParseError::new("Float.GobDecode: buffer too small"));
        }
        if buf[0] != 1 {
            return Err(ParseError::new(format!(
                "Float.GobDecode: encoding version {} not supported",
                buf[0]
            )));
        }
        let old_prec = self.prec;
        let old_mode = self.mode;
        let b = buf[1];
        // Like Go, the mode, accuracy and form bits are stored unvalidated.
        let mode = RoundingMode((b >> 5) & 7);
        let acc = Accuracy(((b >> 3) & 3) as i8 - 1);
        let form = match (b >> 1) & 3 {
            0 => Form::Zero,
            1 => Form::Finite,
            2 => Form::Inf,
            _ => Form::Invalid,
        };
        let mut z = Float {
            prec: u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]),
            mode,
            acc,
            form,
            neg: b & 1 != 0,
            ..Float::default()
        };
        if z.form == Form::Finite {
            if buf.len() < 10 {
                return Err(ParseError::new(
                    "Float.GobDecode: buffer too small for finite form float",
                ));
            }
            z.exp = i32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]);
            z.mant = nat::set_bytes(&buf[10..]);
        }
        if old_prec != 0 {
            z.mode = old_mode;
            z.set_prec(old_prec);
        }
        if z.form == Form::Finite {
            if z.mant.is_empty() {
                return Err(ParseError::new(
                    "Float.GobDecode: nonzero finite number with empty mantissa",
                ));
            }
            if z.mant[z.mant.len() - 1] & (1 << 63) == 0 {
                return Err(ParseError::new(format!(
                    "Float.GobDecode: msb not set in last word {:#x} of {}",
                    z.mant[z.mant.len() - 1],
                    z.text(b'p', 0)
                )));
            }
            if z.prec == 0 {
                return Err(ParseError::new(
                    "Float.GobDecode: zero precision finite number",
                ));
            }
        }
        *self = z;
        Ok(())
    }
}

/// Parses like Go's `UnmarshalText` into a new Float (precision 64).
impl FromStr for Float {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Float, ParseError> {
        let mut z = Float::new();
        z.unmarshal_text(s.as_bytes())?;
        Ok(z)
    }
}
