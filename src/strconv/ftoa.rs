//! Binary to decimal floating point formatting.
//!
//! Digit generation uses Rust's `core::fmt` float formatting (shortest
//! round-trip digits and exactly rounded fixed-precision digits); the layout
//! into Go's `%e`, `%f`, `%g`, `%b` and `%x` text follows Go's
//! `internal/strconv/ftoa.go`.

use super::{append_int, append_uint, lower};

const LOWERHEX: &[u8; 16] = b"0123456789abcdef";
const UPPERHEX: &[u8; 16] = b"0123456789ABCDEF";

/// A finite non-negative float of either precision, formatted at its own
/// precision.
#[derive(Clone, Copy)]
enum Val {
    F32(f32),
    F64(f64),
}

impl Val {
    fn sci(self, prec: Option<usize>) -> String {
        // core::fmt caps precision at u16::MAX; a double has at most 767
        // significant digits, so more are all zeros (trimmed by parse_sci and
        // restored by the layout code).
        let prec = prec.map(|p| p.min(800));
        match (self, prec) {
            (Val::F32(v), None) => format!("{v:e}"),
            (Val::F64(v), None) => format!("{v:e}"),
            (Val::F32(v), Some(p)) => format!("{v:.p$e}"),
            (Val::F64(v), Some(p)) => format!("{v:.p$e}"),
        }
    }

    /// Reports whether text parses back to exactly this value.
    fn round_trips(self, text: &str) -> bool {
        match self {
            Val::F32(v) => text.parse::<f32>().is_ok_and(|p| p == v),
            Val::F64(v) => text.parse::<f64>().is_ok_and(|p| p == v),
        }
    }

    fn fixed(self, prec: usize) -> String {
        // A double has at most 1074 fractional digits (see sci).
        let prec = prec.min(1100);
        match self {
            Val::F32(v) => format!("{v:.prec$}"),
            Val::F64(v) => format!("{v:.prec$}"),
        }
    }
}

/// Splits Rust's `d.ddde<exp>` output into digits (trailing zeros trimmed)
/// and the decimal point position.
fn parse_sci(s: &str) -> (Vec<u8>, isize) {
    let (mant, exp) = s.split_once('e').unwrap_or((s, "0"));
    let exp: isize = exp.parse().unwrap_or(0);
    let mut digits: Vec<u8> = mant.bytes().filter(|c| *c != b'.').collect();
    trim_zeros(&mut digits);
    (digits, exp + 1)
}

/// Splits Rust's fixed-point output into digits and decimal point position.
fn parse_fixed(s: &str) -> (Vec<u8>, isize) {
    let (int, frac) = s.split_once('.').unwrap_or((s, ""));
    let mut dp = int.len() as isize;
    let all: Vec<u8> = int.bytes().chain(frac.bytes()).collect();
    let lead = all.iter().take_while(|c| **c == b'0').count();
    let mut digits = all[lead..].to_vec();
    dp -= lead as isize;
    trim_zeros(&mut digits);
    if digits.is_empty() {
        dp = 0;
    }
    (digits, dp)
}

fn trim_zeros(d: &mut Vec<u8>) {
    while d.last() == Some(&b'0') {
        d.pop();
    }
}

pub(super) fn ftoa32(dst: &mut Vec<u8>, val: f32, fmt: u8, prec: i32) {
    ftoa(dst, val.to_bits() as u64, 23, 8, -127, fmt, prec);
}

pub(super) fn ftoa64(dst: &mut Vec<u8>, val: f64, fmt: u8, prec: i32) {
    ftoa(dst, val.to_bits(), 52, 11, -1023, fmt, prec);
}

fn ftoa(dst: &mut Vec<u8>, b: u64, mant_bits: u32, exp_bits: u32, bias: i32, fmt: u8, prec: i32) {
    let neg = b >> (exp_bits + mant_bits) != 0;
    let mut exp = ((b >> mant_bits) & ((1 << exp_bits) - 1)) as i32;
    let mut mant = b & ((1 << mant_bits) - 1);
    if exp == (1 << exp_bits) - 1 {
        if mant != 0 {
            dst.extend_from_slice(b"NaN");
        } else if neg {
            dst.extend_from_slice(b"-Inf");
        } else {
            dst.extend_from_slice(b"+Inf");
        }
        return;
    }
    let val = if mant_bits == 23 {
        Val::F32(f32::from_bits(b as u32 & 0x7fff_ffff))
    } else {
        Val::F64(f64::from_bits(b & 0x7fff_ffff_ffff_ffff))
    };
    if exp == 0 {
        exp += 1;
    } else {
        mant |= 1 << mant_bits;
    }
    exp += bias;
    let mant_bits = mant_bits as i32;

    // Pick off easy binary, hex formats.
    if fmt == b'b' {
        fmt_b(dst, neg, mant, exp - mant_bits);
        return;
    }
    if fmt == b'x' || fmt == b'X' {
        fmt_x(dst, prec, fmt, neg, mant, exp, mant_bits);
        return;
    }

    // Pick off zero.
    if mant == 0 {
        fmt_efg(dst, neg, &[], 0, 0, prec as isize, fmt, prec < 0);
        return;
    }

    if !matches!(fmt, b'e' | b'E' | b'f' | b'g' | b'G') {
        dst.extend_from_slice(&[b'%', fmt]);
        return;
    }

    // Negative precision means "only as much as needed to be exact."
    if prec < 0 {
        let (mut digits, mut dp) = parse_sci(&val.sci(None));
        // Both Rust and Go print the fewest digits that round-trip; when two
        // candidates of that length are equally close to the value Go takes
        // the even one, which is what exact half-even rounding to that many
        // digits yields.
        let exact = val.sci(Some(digits.len() - 1));
        if val.round_trips(&exact) {
            (digits, dp) = parse_sci(&exact);
        }
        let nd = digits.len() as isize;
        // Precision for shortest representation mode.
        let prec = match fmt {
            b'e' | b'E' => (nd - 1).max(0),
            b'f' => (nd - dp).max(0),
            _ => nd,
        };
        fmt_efg(dst, neg, &digits, dp, digits.len(), prec, fmt, true);
        return;
    }

    let mut prec = prec;
    let (digits, dp) = match fmt {
        b'e' | b'E' => parse_sci(&val.sci(Some(prec as usize))),
        b'f' => parse_fixed(&val.fixed(prec as usize)),
        _ => {
            if prec == 0 {
                prec = 1;
            }
            parse_sci(&val.sci(Some(prec as usize - 1)))
        }
    };
    fmt_efg(
        dst,
        neg,
        &digits,
        dp,
        digits.len(),
        prec as isize,
        fmt,
        false,
    );
}

#[allow(clippy::too_many_arguments)]
fn fmt_efg(
    dst: &mut Vec<u8>,
    neg: bool,
    s: &[u8],
    dp: isize,
    nd: usize,
    prec: isize,
    mut fmt: u8,
    shortest: bool,
) {
    let nd_i = nd as isize;
    let mut prec = prec;
    if fmt == b'g' || fmt == b'G' {
        // trailing fractional zeros in 'e' form will be trimmed.
        let mut eprec = prec;
        if eprec > nd_i && nd_i >= dp {
            eprec = nd_i;
        }
        // %e is used if the exponent from the conversion is less than -4 or
        // greater than or equal to the precision. If precision was the
        // shortest possible, use precision 6 for this decision.
        if shortest {
            eprec = 6;
        }
        let exp = dp - 1;
        if exp < -4 || exp >= eprec {
            if prec > nd_i {
                prec = nd_i;
            }
            prec -= 1;
            fmt = fmt + b'e' - b'g';
        } else {
            if prec > dp {
                prec = nd_i;
            }
            prec = (prec - dp).max(0);
            fmt = b'f';
        }
    }

    match fmt {
        b'e' | b'E' => {
            // %e: -d.ddddde±dd
            if neg {
                dst.push(b'-');
            }

            // first digit
            let ch = if nd != 0 { s[0] } else { b'0' };
            dst.push(ch);

            // .moredigits
            if prec > 0 {
                dst.push(b'.');
                let mut i = 1isize;
                let m = nd_i.min(prec + 1);
                if i < m {
                    dst.extend_from_slice(&s[i as usize..m as usize]);
                    i = m;
                }
                for _ in 0..(prec + 1 - i) {
                    dst.push(b'0');
                }
            }

            // e±
            dst.push(fmt);
            let mut exp = dp - 1;
            if nd == 0 {
                // special case: 0 has exponent 0
                exp = 0;
            }
            if exp < 0 {
                dst.push(b'-');
                exp = -exp;
            } else {
                dst.push(b'+');
            }

            // dd or ddd
            if exp < 10 {
                dst.extend_from_slice(&[b'0', exp as u8 + b'0']);
            } else if exp < 100 {
                dst.extend_from_slice(&[(exp / 10) as u8 + b'0', (exp % 10) as u8 + b'0']);
            } else {
                dst.extend_from_slice(&[
                    (exp / 100) as u8 + b'0',
                    ((exp / 10) % 10) as u8 + b'0',
                    (exp % 10) as u8 + b'0',
                ]);
            }
        }
        b'f' => {
            // %f: -ddddddd.ddddd
            if neg {
                dst.push(b'-');
            }

            // integer, padded with zeros as needed.
            if dp > 0 {
                let m = nd_i.min(dp);
                dst.extend_from_slice(&s[..m as usize]);
                for _ in 0..(dp - m) {
                    dst.push(b'0');
                }
            } else {
                dst.push(b'0');
            }

            // fraction
            if prec > 0 {
                dst.push(b'.');
                let lz = prec.min((-dp).max(0)); // leading zeros
                let off = dp + lz;
                let m = (prec - lz).min((nd_i - off).max(0)); // middle digits
                let tz = (prec - lz - m).max(0); // trailing zeros
                for _ in 0..lz {
                    dst.push(b'0');
                }
                for i in 0..m {
                    dst.push(s[(off + i) as usize]);
                }
                for _ in 0..tz {
                    dst.push(b'0');
                }
            }
        }
        _ => {
            // unknown format
            dst.extend_from_slice(&[b'%', fmt]);
        }
    }
}

/// %b: -ddddddddp±ddd
fn fmt_b(dst: &mut Vec<u8>, neg: bool, mant: u64, exp: i32) {
    if neg {
        dst.push(b'-');
    }
    append_uint(dst, mant, 10);
    dst.push(b'p');
    if exp >= 0 {
        dst.push(b'+');
    }
    append_int(dst, exp as i64, 10);
}

/// %x: -0x1.yyyyyyyyp±ddd or -0x0p+0. (y is hex digit, d is decimal digit)
fn fmt_x(
    dst: &mut Vec<u8>,
    prec: i32,
    fmt: u8,
    neg: bool,
    mut mant: u64,
    mut exp: i32,
    mant_bits: i32,
) {
    if mant == 0 {
        exp = 0;
    }

    // Shift digits so leading 1 (if any) is at bit 1<<60.
    mant <<= 60 - mant_bits;
    while mant != 0 && mant & (1 << 60) == 0 {
        mant <<= 1;
        exp -= 1;
    }

    // Round if requested.
    if (0..15).contains(&prec) {
        let shift = (prec * 4) as u32;
        let extra = (mant << shift) & ((1 << 60) - 1);
        mant >>= 60 - shift;
        if extra | (mant & 1) > 1 << 59 {
            mant += 1;
        }
        mant <<= 60 - shift;
        if mant & (1 << 61) != 0 {
            // Wrapped around.
            mant >>= 1;
            exp += 1;
        }
    }

    let hex = if fmt == b'X' { UPPERHEX } else { LOWERHEX };

    // sign, 0x, leading digit
    if neg {
        dst.push(b'-');
    }
    dst.extend_from_slice(&[b'0', fmt, b'0' + ((mant >> 60) & 1) as u8]);

    // .fraction
    mant <<= 4; // remove leading 0 or 1
    if prec < 0 && mant != 0 {
        dst.push(b'.');
        while mant != 0 {
            dst.push(hex[((mant >> 60) & 15) as usize]);
            mant <<= 4;
        }
    } else if prec > 0 {
        dst.push(b'.');
        for _ in 0..prec {
            dst.push(hex[((mant >> 60) & 15) as usize]);
            mant <<= 4;
        }
    }

    // p±
    dst.push(if fmt == lower(fmt) { b'p' } else { b'P' });
    if exp < 0 {
        dst.push(b'-');
        exp = -exp;
    } else {
        dst.push(b'+');
    }

    // dd or ddd or dddd
    if exp < 100 {
        dst.extend_from_slice(&[(exp / 10) as u8 + b'0', (exp % 10) as u8 + b'0']);
    } else if exp < 1000 {
        dst.extend_from_slice(&[
            (exp / 100) as u8 + b'0',
            ((exp / 10) % 10) as u8 + b'0',
            (exp % 10) as u8 + b'0',
        ]);
    } else {
        dst.extend_from_slice(&[
            (exp / 1000) as u8 + b'0',
            ((exp / 100) % 10) as u8 + b'0',
            ((exp / 10) % 10) as u8 + b'0',
            (exp % 10) as u8 + b'0',
        ]);
    }
}
