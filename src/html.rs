//! HTML text escaping and character-reference unescaping. These operations
//! target ordinary HTML text; they provide no URL sanitization, JavaScript
//! escaping, or CSS escaping. Context-aware template escaping lives apart in
//! [`template`] (Go `html/template`).

mod entities;
pub mod template;

pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Replaces HTML character references such as `&amp;`, `&#38;` and `&#x26;`.
///
/// This follows Go's `html.UnescapeString` behavior: named references are
/// recognized case-sensitively, legacy names may omit their semicolon, and
/// invalid numeric references follow the HTML numeric-reference replacement
/// rules. This operates on text and does not parse HTML markup.
pub fn unescape(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;

    while cursor < bytes.len() {
        if bytes[cursor] != b'&' {
            let ch = text[cursor..]
                .chars()
                .next()
                .expect("cursor is a char boundary");
            out.push(ch);
            cursor += ch.len_utf8();
            continue;
        }

        if let Some((decoded, consumed)) = decode_reference(&text[cursor + 1..]) {
            out.push_str(&decoded);
            cursor += consumed + 1;
        } else {
            out.push('&');
            cursor += 1;
        }
    }
    out
}

fn decode_reference(source: &str) -> Option<(String, usize)> {
    let bytes = source.as_bytes();
    if bytes.first() == Some(&b'#') {
        return decode_numeric(source);
    }

    let mut end = 0;
    while end < bytes.len() && bytes[end].is_ascii_alphanumeric() {
        end += 1;
    }
    if end < bytes.len() && bytes[end] == b';' {
        end += 1;
    }
    let candidate = &source[..end];
    if let Some(value) = entities::lookup(candidate) {
        return Some((value.to_owned(), end));
    }

    // Go's text unescaper accepts the longest legacy (semicolon-free)
    // reference prefix, but limits that fallback to six bytes.
    let mut prefix_len = end.saturating_sub(1).min(6);
    while prefix_len > 1 {
        if let Some(value) = entities::lookup(&source[..prefix_len]) {
            return Some((value.to_owned(), prefix_len));
        }
        prefix_len -= 1;
    }
    None
}

fn decode_numeric(source: &str) -> Option<(String, usize)> {
    let bytes = source.as_bytes();
    // Go returns the ampersand unchanged when the complete reference prefix
    // is too short to contain a numeric digit.
    if bytes.len() < 2 {
        return None;
    }
    let mut index = 1;
    let is_hex = index < bytes.len() && matches!(bytes[index], b'x' | b'X');
    let radix = if is_hex {
        index += 1;
        16u32
    } else {
        10u32
    };
    let digits_start = index;
    let mut value = 0u32;
    while index < bytes.len() {
        let digit = match bytes[index] {
            b'0'..=b'9' => u32::from(bytes[index] - b'0'),
            b'a'..=b'f' if radix == 16 => u32::from(bytes[index] - b'a' + 10),
            b'A'..=b'F' if radix == 16 => u32::from(bytes[index] - b'A' + 10),
            _ => break,
        };
        value = value.wrapping_mul(radix).wrapping_add(digit);
        index += 1;
    }
    let had_digits = index > digits_start;
    let mut terminated = false;
    if index < bytes.len() && bytes[index] == b';' {
        index += 1;
        terminated = true;
    }
    if !had_digits && !(is_hex && terminated && bytes.len() >= 3) {
        return None;
    }

    const WINDOWS_1252: [u32; 32] = [
        0x20ac, 0x81, 0x201a, 0x192, 0x201e, 0x2026, 0x2020, 0x2021, 0x2c6, 0x2030, 0x160, 0x2039,
        0x152, 0x8d, 0x17d, 0x8f, 0x90, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014,
        0x2dc, 0x2122, 0x161, 0x203a, 0x153, 0x9d, 0x17e, 0x178,
    ];
    if (0x80..=0x9f).contains(&value) {
        value = WINDOWS_1252[(value - 0x80) as usize];
    } else if value == 0 || value > 0x10ffff || (0xd800..=0xdfff).contains(&value) {
        value = 0xfffd;
    }
    let ch = char::from_u32(value).unwrap_or('\u{fffd}');
    Some((ch.to_string(), index))
}
