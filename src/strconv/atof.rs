//! String to floating point conversion. Go's syntax rules (underscores, hex
//! floats, inf/nan spellings, range errors) from `internal/strconv/atof.go`
//! wrap Rust's correctly rounded `f64`/`f32` `FromStr` for the decimal path.

use super::{lower, underscore_ok, Error};

/// Length of the common prefix of s and prefix, ignoring the case of s. The
/// prefix must be all lower-case.
fn common_prefix_len_ignore_case(s: &[u8], prefix: &str) -> usize {
    let n = prefix.len().min(s.len());
    for (i, (&c, &p)) in s.iter().zip(prefix.as_bytes()).enumerate() {
        if c.to_ascii_lowercase() != p {
            return i;
        }
    }
    n
}

/// Returns the value and consumed length of the special, possibly signed
/// representations inf, infinity and NaN.
fn special(mut s: &[u8]) -> Option<(f64, usize)> {
    if s.is_empty() {
        return None;
    }
    let mut sign = 1.0;
    let mut nsign = 0;
    let mut try_inf = false;
    match s[0] {
        b'+' | b'-' => {
            if s[0] == b'-' {
                sign = -1.0;
            }
            nsign = 1;
            s = &s[1..];
            try_inf = true;
        }
        b'i' | b'I' => try_inf = true,
        b'n' | b'N' if common_prefix_len_ignore_case(s, "nan") == 3 => {
            return Some((f64::from_bits(0x7FF8000000000001), 3));
        }
        _ => {}
    }
    if try_inf {
        let mut n = common_prefix_len_ignore_case(s, "infinity");
        // Anything longer than "inf" is ok, but if we don't have "infinity",
        // only consume "inf".
        if 3 < n && n < 8 {
            n = 3;
        }
        if n == 3 || n == 8 {
            return Some((sign * f64::INFINITY, nsign + n));
        }
    }
    None
}

struct Parsed {
    mantissa: u64,
    exp: isize,
    neg: bool,
    trunc: bool,
    hex: bool,
    n: usize,
    ok: bool,
}

/// Reads a decimal or hexadecimal mantissa and exponent from a float string;
/// the number may be followed by other characters.
fn read_float(s: &[u8]) -> Parsed {
    let mut r = Parsed {
        mantissa: 0,
        exp: 0,
        neg: false,
        trunc: false,
        hex: false,
        n: 0,
        ok: false,
    };
    let mut underscores = false;
    let mut i = 0;

    // optional sign
    if i >= s.len() {
        return r;
    }
    match s[i] {
        b'+' => i += 1,
        b'-' => {
            i += 1;
            r.neg = true;
        }
        _ => {}
    }

    // digits
    let mut base: u64 = 10;
    let mut max_mant_digits = 19; // 10^19 fits in u64
    let mut exp_char = b'e';
    if i + 2 < s.len() && s[i] == b'0' && lower(s[i + 1]) == b'x' {
        base = 16;
        max_mant_digits = 16; // 16^16 fits in u64
        i += 2;
        exp_char = b'p';
        r.hex = true;
    }
    let mut sawdot = false;
    let mut sawdigits = false;
    let mut nd = 0isize;
    let mut nd_mant = 0isize;
    let mut dp = 0isize;
    while i < s.len() {
        let c = s[i];
        if c == b'_' {
            underscores = true;
        } else if c == b'.' {
            if sawdot {
                break;
            }
            sawdot = true;
            dp = nd;
        } else if c.is_ascii_digit() {
            sawdigits = true;
            if c == b'0' && nd == 0 {
                // ignore leading zeros
                dp -= 1;
            } else {
                nd += 1;
                if nd_mant < max_mant_digits {
                    r.mantissa = r
                        .mantissa
                        .wrapping_mul(base)
                        .wrapping_add((c - b'0') as u64);
                    nd_mant += 1;
                } else if c != b'0' {
                    r.trunc = true;
                }
            }
        } else if base == 16 && (b'a'..=b'f').contains(&lower(c)) {
            sawdigits = true;
            nd += 1;
            if nd_mant < max_mant_digits {
                r.mantissa = r
                    .mantissa
                    .wrapping_mul(16)
                    .wrapping_add((lower(c) - b'a' + 10) as u64);
                nd_mant += 1;
            } else {
                r.trunc = true;
            }
        } else {
            break;
        }
        i += 1;
    }
    r.n = i;
    if !sawdigits {
        return r;
    }
    if !sawdot {
        dp = nd;
    }

    if base == 16 {
        dp *= 4;
        nd_mant *= 4;
    }

    // optional exponent moves decimal point.
    if i < s.len() && lower(s[i]) == exp_char {
        i += 1;
        r.n = i;
        if i >= s.len() {
            return r;
        }
        let mut esign = 1;
        match s[i] {
            b'+' => i += 1,
            b'-' => {
                i += 1;
                esign = -1;
            }
            _ => {}
        }
        r.n = i;
        if i >= s.len() || !s[i].is_ascii_digit() {
            return r;
        }
        let mut e: isize = 0;
        while i < s.len() && (s[i].is_ascii_digit() || s[i] == b'_') {
            if s[i] == b'_' {
                underscores = true;
            } else if e < 10000 {
                e = e * 10 + (s[i] - b'0') as isize;
            }
            i += 1;
        }
        r.n = i;
        dp += e * esign;
    } else if base == 16 {
        // Must have exponent.
        return r;
    }

    if r.mantissa != 0 {
        r.exp = dp - nd_mant;
    }

    if underscores && !underscore_ok(&s[..i]) {
        return r;
    }

    r.ok = true;
    r
}

/// Converts the hex floating-point string already parsed into mantissa,
/// exponent and sign to a rounded float32 or float64 value, returned as f64.
fn atof_hex(
    is32: bool,
    mut mantissa: u64,
    mut exp: isize,
    neg: bool,
    trunc: bool,
) -> (f64, Option<Error>) {
    let (mantbits, expbits, bias): (u32, u32, isize) =
        if is32 { (23, 8, -127) } else { (52, 11, -1023) };
    let max_exp = (1isize << expbits) + bias - 2;
    let min_exp = bias + 1;
    exp += mantbits as isize; // mantissa now implicitly divided by 2^mantbits.

    // Shift mantissa and exponent to bring representation into float range.
    // Eventually we want a mantissa with a leading 1-bit followed by mantbits
    // other bits. For rounding, we need two more, where the bottom bit
    // represents whether that bit or any later bit was non-zero.
    while mantissa != 0 && mantissa >> (mantbits + 2) == 0 {
        mantissa <<= 1;
        exp -= 1;
    }
    if trunc {
        mantissa |= 1;
    }
    while mantissa >> (1 + mantbits + 2) != 0 {
        mantissa = mantissa >> 1 | mantissa & 1;
        exp += 1;
    }

    // If exponent is too negative, denormalize in hopes of making it
    // representable. (The -2 is for the rounding bits.)
    while mantissa > 1 && exp < min_exp - 2 {
        mantissa = mantissa >> 1 | mantissa & 1;
        exp += 1;
    }

    // Round using two bottom bits.
    let mut round = mantissa & 3;
    mantissa >>= 2;
    round |= mantissa & 1; // round to even (round up if mantissa is odd)
    exp += 2;
    if round == 3 {
        mantissa += 1;
        if mantissa == 1 << (1 + mantbits) {
            mantissa >>= 1;
            exp += 1;
        }
    }

    if mantissa >> mantbits == 0 {
        // Denormal or zero.
        exp = bias;
    }
    let mut err = None;
    if exp > max_exp {
        // infinity and range error
        mantissa = 1 << mantbits;
        exp = max_exp + 1;
        err = Some(Error::Range);
    }

    let mut bits = mantissa & ((1 << mantbits) - 1);
    bits |= (((exp - bias) as u64) & ((1 << expbits) - 1)) << mantbits;
    if neg {
        bits |= 1 << mantbits << expbits;
    }
    if is32 {
        (f32::from_bits(bits as u32) as f64, err)
    } else {
        (f64::from_bits(bits), err)
    }
}

/// Parses a float prefix of s, returning the value, the number of bytes
/// consumed and any error. bit_size 32 selects float32 rounding; any other
/// value selects float64.
pub(super) fn parse_float_prefix(s: &[u8], bit_size: i32) -> (f64, usize, Option<Error>) {
    let is32 = bit_size == 32;
    if let Some((val, n)) = special(s) {
        let val = if is32 { val as f32 as f64 } else { val };
        return (val, n, None);
    }

    let p = read_float(s);
    if !p.ok {
        return (0.0, p.n, Some(Error::Syntax));
    }
    let n = p.n;
    if p.hex {
        let (f, err) = atof_hex(is32, p.mantissa, p.exp, p.neg, p.trunc);
        return (f, n, err);
    }

    // The scanned text is validated decimal syntax; drop underscores and let
    // Rust's correctly rounded parser do the conversion.
    let text: String = s[..n]
        .iter()
        .filter(|c| **c != b'_')
        .map(|c| *c as char)
        .collect();
    let (f, overflow) = if is32 {
        match text.parse::<f32>() {
            Ok(v) => (v as f64, v.is_infinite()),
            Err(_) => return (0.0, n, Some(Error::Syntax)),
        }
    } else {
        match text.parse::<f64>() {
            Ok(v) => (v, v.is_infinite()),
            Err(_) => return (0.0, n, Some(Error::Syntax)),
        }
    };
    (f, n, if overflow { Some(Error::Range) } else { None })
}
