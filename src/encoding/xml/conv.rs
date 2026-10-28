//! The slice of Go's `strconv` that `encoding/xml` observes: `%q` quoting,
//! `FormatFloat(v, 'g', -1, bits)` and the `Parse*` error texts.
use crate::unicode::{self, rune};

/// The text of a Go string that may hold invalid UTF-8, as a Rust string: every
/// invalid byte becomes one U+FFFD.
pub(super) fn lossy(s: &[u8]) -> String {
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let (r, width) = rune::decode_rune(&s[i..]);
        out.push(char::from_u32(r as u32).unwrap_or('\u{fffd}'));
        i += width;
    }
    out
}

/// Go's `strconv.Quote` for arbitrary bytes (invalid UTF-8 becomes `\xNN`).
pub(super) fn quote(s: &[u8]) -> String {
    let mut out = String::from("\"");
    let mut i = 0;
    while i < s.len() {
        let (r, width) = rune::decode_rune(&s[i..]);
        if width == 1 && r == 0xFFFD {
            out.push_str(&format!("\\x{:02x}", s[i]));
            i += 1;
            continue;
        }
        i += width;
        let c = char::from_u32(r as u32).unwrap_or('\u{fffd}');
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            _ if unicode::is_print(r) => out.push(c),
            '\x07' => out.push_str("\\a"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x0b' => out.push_str("\\v"),
            _ if r < 0x20 || r == 0x7f => out.push_str(&format!("\\x{r:02x}")),
            _ if r < 0x10000 => out.push_str(&format!("\\u{r:04x}")),
            _ => out.push_str(&format!("\\U{r:08x}")),
        }
    }
    out.push('"');
    out
}

/// Go's `strconv.FormatFloat(v, 'g', -1, bits)`.
pub(super) fn format_float_g(v: f64, bits: u32) -> String {
    if v.is_nan() {
        return "NaN".into();
    }
    if v.is_infinite() {
        return if v > 0.0 { "+Inf" } else { "-Inf" }.into();
    }
    let neg = v.is_sign_negative();
    // Shortest round-trip digits from std: "d.ddde<exp>".
    let sci = if bits == 32 {
        format!("{:e}", (v as f32).abs())
    } else {
        format!("{:e}", v.abs())
    };
    // Rust picks the upper of two equally close shortest candidates, Go the even
    // one (exact rounding); use the exact rounding when it round-trips.
    let nd_short = sci
        .bytes()
        .take_while(|b| *b != b'e')
        .filter(u8::is_ascii_digit)
        .count();
    let exact = if bits == 32 {
        format!("{:.*e}", nd_short - 1, (v as f32).abs())
    } else {
        format!("{:.*e}", nd_short - 1, v.abs())
    };
    let round_trips = if bits == 32 {
        exact.parse::<f32>().is_ok_and(|p| p == (v as f32).abs())
    } else {
        exact.parse::<f64>().is_ok_and(|p| p == v.abs())
    };
    let sci = if round_trips { exact } else { sci };
    let (mantissa, exp) = sci
        .split_once('e')
        .expect("LowerExp always has an exponent");
    let mut digits: Vec<u8> = mantissa.bytes().filter(|b| *b != b'.').collect();
    let mut dp: i32 = exp.parse::<i32>().expect("integer exponent") + 1;
    if digits == b"0" {
        digits.clear();
        dp = 0;
    }
    let nd = digits.len() as i32;
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    let eprec = 6;
    let x = dp - 1;
    if x < -4 || x >= eprec {
        // %e with nd-1 fraction digits.
        out.push(*digits.first().unwrap_or(&b'0') as char);
        if nd > 1 {
            out.push('.');
            out.extend(digits[1..].iter().map(|b| *b as char));
        }
        out.push('e');
        let e = if nd == 0 { 0 } else { dp - 1 };
        out.push(if e < 0 { '-' } else { '+' });
        out.push_str(&format!("{:02}", e.abs()));
    } else {
        // %f with max(nd-dp, 0) fraction digits.
        if dp > 0 {
            for i in 0..dp {
                out.push(if i < nd {
                    digits[i as usize] as char
                } else {
                    '0'
                });
            }
        } else {
            out.push('0');
        }
        if nd > dp {
            out.push('.');
            for i in dp..nd {
                out.push(if i < 0 {
                    '0'
                } else {
                    digits[i as usize] as char
                });
            }
        }
    }
    out
}

/// A `*strconv.NumError` rendered as Go prints it.
pub(super) fn num_error(func: &str, num: &str, range: bool) -> String {
    format!(
        "strconv.{func}: parsing {}: {}",
        quote(num.as_bytes()),
        if range {
            "value out of range"
        } else {
            "invalid syntax"
        }
    )
}

/// Go's `strconv.ParseUint(s, 10, bits)`; the error is the full Go text.
pub(super) fn parse_uint(s: &str, bits: u32, func: &str) -> Result<u64, String> {
    if s.is_empty() {
        return Err(num_error(func, s, false));
    }
    let max = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let cutoff = u64::MAX / 10 + 1;
    let mut n: u64 = 0;
    for c in s.bytes() {
        if !c.is_ascii_digit() {
            return Err(num_error(func, s, false));
        }
        if n >= cutoff {
            return Err(num_error(func, s, true));
        }
        n *= 10;
        let n1 = n.wrapping_add(u64::from(c - b'0'));
        if n1 < n || n1 > max {
            return Err(num_error(func, s, true));
        }
        n = n1;
    }
    Ok(n)
}

/// Go's `strconv.ParseInt(s, 10, bits)`.
pub(super) fn parse_int(s0: &str, bits: u32) -> Result<i64, String> {
    let func = "ParseInt";
    if s0.is_empty() {
        return Err(num_error(func, s0, false));
    }
    let (neg, s) = match s0.as_bytes()[0] {
        b'+' => (false, &s0[1..]),
        b'-' => (true, &s0[1..]),
        _ => (false, s0),
    };
    let un = match parse_uint(s, 64, func) {
        Ok(v) => v,
        Err(e) if e.ends_with("value out of range") => return Err(num_error(func, s0, true)),
        Err(_) => return Err(num_error(func, s0, false)),
    };
    let cutoff = 1u64 << (bits.clamp(1, 64) - 1);
    if (!neg && un >= cutoff) || (neg && un > cutoff) {
        return Err(num_error(func, s0, true));
    }
    Ok(if neg {
        (un as i64).wrapping_neg()
    } else {
        un as i64
    })
}

/// Go's `strconv.ParseBool`.
pub(super) fn parse_bool(s: &str) -> Result<bool, String> {
    match s {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
        _ => Err(num_error("ParseBool", s, false)),
    }
}

fn lower(c: u8) -> u8 {
    c | 0x20
}

/// Go's `strconv.ParseFloat(s, bits)`: Go's grammar (inf/nan, underscores with a
/// base prefix, hexadecimal floats) with correctly rounded results.
pub(super) fn parse_float(s: &str, bits: u32) -> Result<f64, String> {
    let fail = || num_error("ParseFloat", s, false);
    let range = || num_error("ParseFloat", s, true);
    let b = s.as_bytes();
    if b.is_empty() {
        return Err(fail());
    }
    // special: signed infinity and unsigned NaN.
    let (sign, rest) = match b[0] {
        b'+' => (1.0, &b[1..]),
        b'-' => (-1.0, &b[1..]),
        _ => (1.0, b),
    };
    let signed = rest.len() != b.len();
    let prefix_len = |word: &[u8]| {
        rest.iter()
            .zip(word)
            .take_while(|(a, w)| lower(**a) == **w)
            .count()
    };
    if signed || matches!(rest.first(), Some(b'i' | b'I')) {
        let mut n = prefix_len(b"infinity");
        if 3 < n && n < 8 {
            n = 3;
        }
        if (n == 3 || n == 8) && (signed as usize) + n == b.len() {
            return Ok(sign * f64::INFINITY);
        }
    } else if matches!(rest.first(), Some(b'n' | b'N')) && prefix_len(b"nan") == 3 && b.len() == 3 {
        return Ok(f64::NAN);
    }
    // readFloat
    let mut i = 0;
    let mut neg = false;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        neg = b[i] == b'-';
        i += 1;
    }
    let mut base = 10u32;
    let mut max_digits = 19;
    if i + 2 < b.len() && b[i] == b'0' && lower(b[i + 1]) == b'x' {
        base = 16;
        max_digits = 16;
        i += 2;
    }
    let mut saw_dot = false;
    let mut saw_digits = false;
    let mut underscores = false;
    let mut nd = 0usize;
    let mut nd_mant = 0usize;
    let mut dp: i64 = 0;
    let mut mant: u64 = 0;
    let mut trunc = false;
    let mut digit_text = String::new();
    while i < b.len() {
        let c = b[i];
        if c == b'_' {
            underscores = true;
            i += 1;
            continue;
        }
        if c == b'.' {
            if saw_dot {
                break;
            }
            saw_dot = true;
            dp = nd as i64;
            i += 1;
            continue;
        }
        let digit = match c {
            b'0'..=b'9' => Some(u64::from(c - b'0')),
            b'a'..=b'f' if base == 16 => Some(u64::from(c - b'a' + 10)),
            b'A'..=b'F' if base == 16 => Some(u64::from(c - b'A' + 10)),
            _ => None,
        };
        let Some(d) = digit else { break };
        saw_digits = true;
        if c == b'0' && nd == 0 {
            // ignore leading zeros
            dp -= 1;
            i += 1;
            continue;
        }
        nd += 1;
        if nd_mant < max_digits {
            mant = mant * u64::from(base) + d;
            nd_mant += 1;
        } else if c != b'0' {
            trunc = true;
        }
        if base == 10 {
            digit_text.push(c as char);
        }
        i += 1;
    }
    if !saw_digits {
        return Err(fail());
    }
    if !saw_dot {
        dp = nd as i64;
    }
    if base == 16 {
        dp *= 4;
        nd_mant *= 4;
    }
    if i < b.len() && lower(b[i]) == if base == 16 { b'p' } else { b'e' } {
        i += 1;
        if i >= b.len() {
            return Err(fail());
        }
        let mut esign = 1;
        if b[i] == b'+' || b[i] == b'-' {
            if b[i] == b'-' {
                esign = -1;
            }
            i += 1;
            if i >= b.len() {
                return Err(fail());
            }
        }
        if !b[i].is_ascii_digit() {
            return Err(fail());
        }
        let mut e: i64 = 0;
        while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'_') {
            if b[i] == b'_' {
                underscores = true;
            } else if e < 10000 {
                e = e * 10 + i64::from(b[i] - b'0');
            }
            i += 1;
        }
        dp += e * esign;
    } else if base == 16 {
        // hexadecimal mantissa requires a 'p' exponent
        return Err(fail());
    }
    if underscores && !underscore_ok(&s[..i]) {
        return Err(fail());
    }
    if i != b.len() {
        return Err(fail());
    }
    let value = if base == 16 {
        if mant == 0 {
            0.0
        } else {
            hex_value(mant, trunc, dp - nd_mant as i64)
        }
    } else {
        let text = format!(
            "{}e{}",
            if digit_text.is_empty() {
                "0"
            } else {
                &digit_text
            },
            dp - nd as i64
        );
        if bits == 32 {
            text.parse::<f32>().map_err(|_| fail())? as f64
        } else {
            text.parse::<f64>().map_err(|_| fail())?
        }
    };
    if value.is_infinite() {
        return Err(range());
    }
    Ok(if neg { -value } else { value })
}

/// mant * 2^exp2 with round-to-nearest-even into f64 (sticky bit for truncation).
fn hex_value(mant: u64, trunc: bool, exp2: i64) -> f64 {
    // Normalise to 64 bits, then let u64 -> f64 do the rounding; scale exactly
    // while the result stays a normal number.
    let mut m = mant;
    let mut e = exp2;
    if trunc {
        m |= 1;
    }
    let shift = m.leading_zeros() as i64;
    m <<= shift;
    e -= shift;
    let top = e + 63;
    if top > 1023 {
        return f64::INFINITY;
    }
    let mut value = m as f64;
    let mut scale = e;
    while scale > 0 {
        let step = scale.min(1000);
        value *= 2f64.powi(step as i32);
        scale -= step;
    }
    while scale < 0 {
        let step = (-scale).min(1000);
        value /= 2f64.powi(step as i32);
        scale += step;
    }
    value
}

/// Go's `underscoreOK`.
fn underscore_ok(s: &str) -> bool {
    let b = s.as_bytes();
    let mut saw = b'^';
    let mut i = 0;
    if !b.is_empty() && (b[0] == b'-' || b[0] == b'+') {
        i = 1;
    }
    let mut hex = false;
    if b.len() >= i + 2 && b[i] == b'0' && matches!(lower(b[i + 1]), b'b' | b'o' | b'x') {
        hex = lower(b[i + 1]) == b'x';
        i += 2;
        saw = b'0';
    }
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_digit() || (hex && matches!(lower(c), b'a'..=b'f')) {
            saw = b'0';
        } else if c == b'_' {
            if saw != b'0' {
                return false;
            }
            saw = b'_';
        } else {
            if saw == b'_' {
                return false;
            }
            saw = b'!';
        }
        i += 1;
    }
    saw != b'_'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn float_g_matches_go() {
        for (v, bits, want) in [
            (0.0, 64, "0"),
            (1.0, 64, "1"),
            (-1.5, 64, "-1.5"),
            (100000.0, 64, "100000"),
            (1e21, 64, "1e+21"),
            (123456789.0, 64, "1.23456789e+08"),
            (0.0001, 64, "0.0001"),
            (0.00001, 64, "1e-05"),
            (0.1, 32, "0.1"),
            (1e6, 64, "1e+06"),
            (f64::from(f32::from_bits(1249173857)), 32, "4.0121202e+06"),
            (f64::from(f32::from_bits(3396080269)), 32, "-3.8678112e+06"),
            (f64::NAN, 64, "NaN"),
            (f64::NEG_INFINITY, 64, "-Inf"),
        ] {
            assert_eq!(format_float_g(v, bits), want, "{v}");
        }
        assert_eq!(format_float_g(-0.0, 64), "-0");
    }

    #[test]
    fn parse_errors_match_go() {
        assert_eq!(
            parse_int("abc", 64).unwrap_err(),
            "strconv.ParseInt: parsing \"abc\": invalid syntax"
        );
        assert_eq!(
            parse_int("300", 8).unwrap_err(),
            "strconv.ParseInt: parsing \"300\": value out of range"
        );
        assert_eq!(parse_int("-128", 8), Ok(-128));
        assert_eq!(parse_float("0x1p-2", 64), Ok(0.25));
        assert_eq!(parse_float("1_0.5", 64), Ok(10.5));
        assert!(parse_float("_1", 64).is_err());
        assert!(parse_float("1e999", 64).is_err());
    }
}
