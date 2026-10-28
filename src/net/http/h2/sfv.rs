//! The slice of HTTP Structured Field Values (RFC 9651) that HTTP/2 priority
//! signalling needs: dictionaries of bare items. Ported from Go's
//! `net/http/internal/httpsfv`.

fn is_lc_alpha(b: u8) -> bool {
    b.is_ascii_lowercase()
}
fn is_alpha(b: u8) -> bool {
    b.is_ascii_alphabetic()
}
fn is_digit(b: u8) -> bool {
    b.is_ascii_digit()
}
fn is_vchar(b: u8) -> bool {
    (0x21..=0x7e).contains(&b)
}
fn is_sp(b: u8) -> bool {
    b == b' '
}
fn is_tchar(b: u8) -> bool {
    is_alpha(b) || is_digit(b) || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn count_left_whitespace(s: &str) -> usize {
    s.bytes().take_while(|&c| c == b' ' || c == b'\t').count()
}

/// Splits `s` into the consumed prefix and the rest.
type Consumed<'a> = Option<(&'a str, &'a str)>;

fn split(s: &str, n: usize) -> (&str, &str) {
    (&s[..n], &s[n..])
}

fn dec_octet_hex(c1: u8, c2: u8) -> Option<u8> {
    let d = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    };
    Some(d(c1)? << 4 | d(c2)?)
}

fn consume_bare_inner_list(s: &str) -> Consumed<'_> {
    let b = s.as_bytes();
    if b.is_empty() || b[0] != b'(' {
        return None;
    }
    let mut rest = &s[1..];
    while !rest.is_empty() {
        rest = &rest[count_left_whitespace(rest)..];
        if rest.as_bytes().first() == Some(&b')') {
            rest = &rest[1..];
            break;
        }
        let (_, r) = consume_bare_item(rest)?;
        let (_, r) = consume_parameter(r)?;
        rest = r;
        match rest.as_bytes().first() {
            Some(&c) if c == b')' || is_sp(c) => {}
            _ => return None,
        }
    }
    Some(split(s, s.len() - rest.len()))
}

fn consume_parameter(s: &str) -> Consumed<'_> {
    let mut rest = s;
    while !rest.is_empty() {
        if rest.as_bytes()[0] != b';' {
            break;
        }
        rest = &rest[1..];
        rest = &rest[count_left_whitespace(rest)..];
        let (_, r) = consume_key(rest)?;
        rest = r;
        if rest.as_bytes().first() == Some(&b'=') {
            rest = &rest[1..];
            let (_, r) = consume_bare_item(rest)?;
            rest = r;
        }
    }
    Some(split(s, s.len() - rest.len()))
}

fn consume_key(s: &str) -> Consumed<'_> {
    let b = s.as_bytes();
    if b.is_empty() || (!is_lc_alpha(b[0]) && b[0] != b'*') {
        return None;
    }
    let i = b
        .iter()
        .take_while(|&&c| is_lc_alpha(c) || is_digit(c) || b"_-.*".contains(&c))
        .count();
    Some(split(s, i))
}

fn consume_integer_or_decimal(s: &str) -> Consumed<'_> {
    let b = s.as_bytes();
    let (mut i, mut sign_offset, mut period_index) = (0usize, 0usize, 0usize);
    let mut is_decimal = false;
    if i < b.len() && b[i] == b'-' {
        i += 1;
        sign_offset += 1;
    }
    if i >= b.len() || !is_digit(b[i]) {
        return None;
    }
    while i < b.len() {
        let ch = b[i];
        if is_digit(ch) {
            i += 1;
            continue;
        }
        if !is_decimal && ch == b'.' {
            if i - sign_offset > 12 {
                return None;
            }
            period_index = i;
            is_decimal = true;
            i += 1;
            continue;
        }
        break;
    }
    if !is_decimal && i - sign_offset > 15 {
        return None;
    }
    if is_decimal && (i - sign_offset > 16 || b[i - 1] == b'.' || i - period_index - 1 > 3) {
        return None;
    }
    Some(split(s, i))
}

fn consume_string(s: &str) -> Consumed<'_> {
    let b = s.as_bytes();
    if b.is_empty() || b[0] != b'"' {
        return None;
    }
    let mut i = 1;
    while i < b.len() {
        match b[i] {
            b'\\' => {
                if i + 1 >= b.len() {
                    return None;
                }
                i += 1;
                if b[i] != b'"' && b[i] != b'\\' {
                    return None;
                }
            }
            b'"' => return Some(split(s, i + 1)),
            ch => {
                if !is_vchar(ch) && !is_sp(ch) {
                    return None;
                }
            }
        }
        i += 1;
    }
    None
}

fn consume_token(s: &str) -> Consumed<'_> {
    let b = s.as_bytes();
    if b.is_empty() || (!is_alpha(b[0]) && b[0] != b'*') {
        return None;
    }
    let i = b
        .iter()
        .take_while(|&&c| is_tchar(c) || c == b':' || c == b'/')
        .count();
    Some(split(s, i))
}

fn consume_byte_sequence(s: &str) -> Consumed<'_> {
    let b = s.as_bytes();
    if b.is_empty() || b[0] != b':' {
        return None;
    }
    for (i, &ch) in b.iter().enumerate().skip(1) {
        if ch == b':' {
            return Some(split(s, i + 1));
        }
        if !is_alpha(ch) && !is_digit(ch) && !b"+/=".contains(&ch) {
            return None;
        }
    }
    None
}

fn consume_boolean(s: &str) -> Consumed<'_> {
    if s.starts_with("?0") || s.starts_with("?1") {
        return Some(split(s, 2));
    }
    None
}

fn consume_date(s: &str) -> Consumed<'_> {
    if !s.starts_with('@') {
        return None;
    }
    let (_, rest) = consume_integer_or_decimal(&s[1..])?;
    let consumed = &s[..s.len() - rest.len()];
    if consumed.contains('.') {
        return None;
    }
    Some((consumed, rest))
}

fn consume_display_string(s: &str) -> Consumed<'_> {
    let b = s.as_bytes();
    if b.len() <= 1 || &b[..2] != b"%\"" {
        return None;
    }
    let mut last = [0u8; 4];
    let mut rune_len = 0usize;
    // Mirrors the incremental UTF-8 check of the Go code: true while the
    // bytes seen so far form valid runes or a prefix of one.
    let mut part_of_valid_rune = |ch: u8| -> bool {
        last[rune_len] = ch;
        rune_len += 1;
        match std::str::from_utf8(&last[..rune_len]) {
            Ok(r) => {
                rune_len = 0;
                // Go rejects a decoded U+FFFD as utf8.RuneError.
                r != "\u{fffd}"
            }
            Err(e) if e.error_len().is_none() => rune_len <= 3,
            Err(_) => false,
        }
    };
    let mut i = 2;
    while i < b.len() {
        let ch = b[i];
        if !is_vchar(ch) && !is_sp(ch) {
            return None;
        }
        match ch {
            b'"' => {
                if rune_len > 0 {
                    return None;
                }
                return Some(split(s, i + 1));
            }
            b'%' => {
                if i + 2 >= b.len() {
                    return None;
                }
                let c = dec_octet_hex(b[i + 1], b[i + 2])?;
                if !part_of_valid_rune(c) {
                    return None;
                }
                i += 3;
            }
            _ => {
                if !part_of_valid_rune(ch) {
                    return None;
                }
                i += 1;
            }
        }
    }
    None
}

fn consume_bare_item(s: &str) -> Consumed<'_> {
    let &ch = s.as_bytes().first()?;
    match ch {
        b'-' | b'0'..=b'9' => consume_integer_or_decimal(s),
        b'"' => consume_string(s),
        b'*' | b'A'..=b'Z' | b'a'..=b'z' => consume_token(s),
        b':' => consume_byte_sequence(s),
        b'?' => consume_boolean(s),
        b'@' => consume_date(s),
        b'%' => consume_display_string(s),
        _ => None,
    }
}

/// Go's `httpsfv.ParseDictionary`: calls `f(key, value, params)` per member.
pub(crate) fn parse_dictionary(mut s: &str, f: &mut dyn FnMut(&str, &str, &str)) -> bool {
    while !s.is_empty() {
        let Some((key, rest)) = consume_key(s) else {
            return false;
        };
        s = rest;
        let mut val = "?1";
        if s.as_bytes().first() == Some(&b'=') {
            s = &s[1..];
            let r = if s.as_bytes().first() == Some(&b'(') {
                consume_bare_inner_list(s)
            } else {
                consume_bare_item(s)
            };
            let Some((v, rest)) = r else {
                return false;
            };
            val = v;
            s = rest;
        }
        let Some((param, rest)) = consume_parameter(s) else {
            return false;
        };
        s = rest;
        f(key, val, param);
        s = &s[count_left_whitespace(s)..];
        if s.is_empty() {
            break;
        }
        if s.as_bytes()[0] == b',' {
            s = &s[1..];
        }
        s = &s[count_left_whitespace(s)..];
        if s.is_empty() {
            return false;
        }
    }
    true
}

/// Go's `httpsfv.ParseInteger`.
pub(crate) fn parse_integer(s: &str) -> Option<i64> {
    match consume_integer_or_decimal(s) {
        Some((_, "")) => s.parse::<i64>().ok(),
        _ => None,
    }
}

/// Go's `httpsfv.ParseBoolean`.
pub(crate) fn parse_boolean(s: &str) -> Option<bool> {
    match consume_boolean(s) {
        Some((_, "")) => Some(s == "?1"),
        _ => None,
    }
}
