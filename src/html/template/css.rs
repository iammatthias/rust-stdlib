//! CSS escaping and filtering (Go `html/template` `css.go`).

use super::content::{stringify, ContentType};
use super::escapers::FILTER_FAILSAFE;
use crate::text::template::value::Value;
use crate::unicode::rune::decode_rune;

/// Reports whether `b` ends with an ident that is case-insensitively equal to
/// the lower-case ASCII word `kw`.
pub(crate) fn ends_with_css_keyword(b: &[u8], kw: &str) -> bool {
    let kw = kw.as_bytes();
    if b.len() < kw.len() {
        return false;
    }
    let i = b.len() - kw.len();
    // Check that b is long enough
    if i != 0 {
        let (r, _) = crate::unicode::rune::decode_last_rune(&b[..i]);
        if is_css_nmchar(r) {
            return false;
        }
    }
    // Many CSS keywords, such as "!important" can have characters encoded,
    // but the URI production does not allow that according to
    // https://www.w3.org/TR/css3-syntax/#TOK-URI
    // This does not attempt to recognize encoded keywords. For example,
    // given "\75\72\6c" and "url" this return false.
    crate::text::BytesExt::to_lower(&b[i..]) == kw
}

/// Reports whether r is a CSS name character, as defined at
/// <https://www.w3.org/TR/css3-syntax/#SUBTOK-nmchar>.
pub(crate) fn is_css_nmchar(r: i32) -> bool {
    (i32::from(b'a')..=i32::from(b'z')).contains(&r)
        || (i32::from(b'A')..=i32::from(b'Z')).contains(&r)
        || (i32::from(b'0')..=i32::from(b'9')).contains(&r)
        || r == i32::from(b'-')
        || r == i32::from(b'_')
        // Non-ASCII cases below.
        || (0x80..=0xd7ff).contains(&r)
        || (0xe000..=0xfffd).contains(&r)
        || (0x10000..=0x10ffff).contains(&r)
}

/// Decodes CSS3 escapes given a sequence of stringchars. If there is no
/// change, it returns a copy of the input.
pub(crate) fn decode_css(s: &[u8]) -> Vec<u8> {
    if !s.contains(&b'\\') {
        // The common case. Most strings aren't escaped.
        return s.to_vec();
    }
    let mut b: Vec<u8> = Vec::with_capacity(s.len());
    let mut s = s;
    while !s.is_empty() {
        let i = s.iter().position(|&c| c == b'\\').unwrap_or(s.len());
        b.extend_from_slice(&s[..i]);
        s = &s[i..];
        if s.len() < 2 {
            break;
        }
        // https://www.w3.org/TR/css3-syntax/#SUBTOK-escape
        // escape : unicode | '\' [#x20-#x7E#x80-#xD7FF#xE000-#xFFFD#x10000-#x10FFFF]
        if is_hex(s[1]) {
            // https://www.w3.org/TR/css3-syntax/#SUBTOK-unicode
            //   unicode : '\' [0-9a-fA-F]{1,6} wc?
            let mut j = 2;
            while j < s.len() && j < 7 && is_hex(s[j]) {
                j += 1;
            }
            let mut r = hex_decode(&s[1..j]);
            if r > 0x10FFFF {
                r /= 16;
                j -= 1;
            }
            match char::from_u32(r) {
                Some(c) => {
                    let mut buf = [0u8; 4];
                    b.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                }
                None => b.extend_from_slice("\u{FFFD}".as_bytes()),
            }
            // The optional space at the end allows a hex sequence to be
            // followed by a literal hex.
            s = skip_css_space(&s[j..]);
        } else {
            // `\\` decodes to `\` and `\"` to `"`.
            let (_, n) = decode_rune(&s[1..]);
            b.extend_from_slice(&s[1..1 + n]);
            s = &s[1 + n..];
        }
    }
    b
}

/// Reports whether c is a hex digit.
pub(crate) fn is_hex(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

/// The value of the hex digits in `s`.
fn hex_decode(s: &[u8]) -> u32 {
    let mut n: u32 = 0;
    for &c in s {
        n <<= 4;
        n |= match c {
            b'0'..=b'9' => u32::from(c - b'0'),
            b'a'..=b'f' => u32::from(c - b'a') + 10,
            b'A'..=b'F' => u32::from(c - b'A') + 10,
            _ => panic!("Bad hex digit in {:?}", String::from_utf8_lossy(s)),
        };
    }
    n
}

/// Returns c without a leading CSS whitespace (one space, or CR LF).
fn skip_css_space(c: &[u8]) -> &[u8] {
    if c.is_empty() {
        return c;
    }
    match c[0] {
        b'\t' | b'\n' | 0x0c | b' ' => &c[1..],
        b'\r' => {
            // This differs from CSS3's wc production because it contains a
            // possible empty match at the end of s.
            if c.len() >= 2 && c[1] == b'\n' {
                &c[2..]
            } else {
                &c[1..]
            }
        }
        _ => c,
    }
}

/// Reports whether b is a CSS whitespace byte.
pub(crate) fn is_css_space(b: u8) -> bool {
    matches!(b, b'\t' | b'\n' | 0x0c | b'\r' | b' ')
}

/// Escapes HTML and CSS special characters using `\<hex>+` escapes.
pub(crate) fn css_escaper(args: &[Value]) -> String {
    let (s, _) = stringify(args);
    let sb = s.as_bytes();
    let mut b = String::new();
    let mut written = 0;
    let mut i = 0;
    while i < sb.len() {
        let (r, w) = decode_rune(&sb[i..]);
        let repl = match css_replacement(r) {
            Some(r) => r,
            None => {
                i += w;
                continue;
            }
        };
        b.push_str(&s[written..i]);
        b.push_str(repl);
        written = i + w;
        if repl != "\\\\"
            && (written == sb.len() || is_hex(sb[written]) || is_css_space(sb[written]))
        {
            b.push(' ');
        }
        i += w;
    }
    if written == 0 {
        return s;
    }
    b.push_str(&s[written..]);
    b
}

fn css_replacement(r: i32) -> Option<&'static str> {
    Some(match r {
        0 => "\\0",
        0x09 => "\\9",
        0x0a => "\\a",
        0x0c => "\\c",
        0x0d => "\\d",
        0x22 => "\\22",
        0x26 => "\\26",
        0x27 => "\\27",
        0x28 => "\\28",
        0x29 => "\\29",
        0x2b => "\\2b",
        0x2f => "\\2f",
        0x3a => "\\3a",
        0x3b => "\\3b",
        0x3c => "\\3c",
        0x3e => "\\3e",
        0x5c => "\\\\",
        0x7b => "\\7b",
        0x7d => "\\7d",
        _ => return None,
    })
}

/// Allows innocuous CSS values through and rejects values that may execute
/// scripts or loads other resources.
pub(crate) fn css_value_filter(args: &[Value]) -> String {
    let (s, t) = stringify(args);
    if t == ContentType::Css {
        return s;
    }
    let b = decode_css(s.as_bytes());
    let mut id: Vec<u8> = Vec::with_capacity(64);

    // CSS3 error handling is specified as honoring string boundaries per
    // https://www.w3.org/TR/css3-syntax/#error-handling :
    //     Malformed declarations. User agents must handle unexpected
    //     tokens encountered while parsing a declaration by reading until
    //     the end of the declaration, while observing the rules for
    //     matching pairs of (), [], {}, "", and '', and correctly handling
    //     escapes. For example, a malformed declaration may be missing a
    //     property, separator (':') or value.
    // So we need to make sure that values do not have mismatched bracket
    // or quote characters to prevent the browser from restarting parsing
    // inside a string that might embed JavaScript source.
    for (i, &c) in b.iter().enumerate() {
        match c {
            0 | b'"' | b'\'' | b'(' | b')' | b'/' | b';' | b'@' | b'[' | b'\\' | b']' | b'`'
            | b'{' | b'}' | b'<' | b'>' => return FILTER_FAILSAFE.to_owned(),
            b'-' => {
                // Disallow <!-- or -->.
                // -- should not appear in valid identifiers.
                if i != 0 && b[i - 1] == b'-' {
                    return FILTER_FAILSAFE.to_owned();
                }
            }
            _ => {
                if c < 0x80 && is_css_nmchar(i32::from(c)) {
                    id.push(c);
                }
            }
        }
    }
    let id = crate::text::BytesExt::to_lower(&id[..]);
    if super::util::index_sub(&id, b"expression").is_some()
        || super::util::index_sub(&id, b"mozbinding").is_some()
    {
        return FILTER_FAILSAFE.to_owned();
    }
    String::from_utf8_lossy(&b).into_owned()
}
