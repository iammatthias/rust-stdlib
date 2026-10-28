//! URL filtering and escaping (Go `html/template` `url.go`).

use super::content::{stringify, ContentType};
use super::css::is_hex;
use super::escapers::FILTER_FAILSAFE;
use crate::text::template::value::Value;
use crate::text::BytesExt;

/// Filters URL values that have an unsafe protocol.
pub(crate) fn url_filter(args: &[Value]) -> String {
    let (s, t) = stringify(args);
    if t == ContentType::Url {
        // Content is classified as safe, so do not filter.
        return s;
    }
    if !is_safe_url(&s) {
        return format!("#{FILTER_FAILSAFE}");
    }
    s
}

/// Reports whether `s` is a relative URL or has a protocol in (http, https,
/// mailto).
pub(crate) fn is_safe_url(s: &str) -> bool {
    if let Some((protocol, _)) = s.split_once(':') {
        if !protocol.contains('/')
            && !protocol.as_bytes().equal_fold(b"http")
            && !protocol.as_bytes().equal_fold(b"https")
            && !protocol.as_bytes().equal_fold(b"mailto")
        {
            return false;
        }
    }
    true
}

/// Escapes a URL, leaving reserved characters alone only when normalizing.
pub(crate) fn url_escaper(args: &[Value]) -> String {
    url_processor(false, args)
}

/// Normalizes a URL, leaving reserved characters and valid escapes alone.
pub(crate) fn url_normalizer(args: &[Value]) -> String {
    url_processor(true, args)
}

fn url_processor(norm: bool, args: &[Value]) -> String {
    let (s, t) = stringify(args);
    let norm = norm || t == ContentType::Url;
    let mut b = String::new();
    if process_url_onto(&s, norm, &mut b) {
        return b;
    }
    s
}

/// Appends a normalized (or escaped) URL to `b`; reports whether anything
/// changed.
pub(crate) fn process_url_onto(s: &str, norm: bool, b: &mut String) -> bool {
    let sb = s.as_bytes();
    let mut written = 0;
    for (i, &c) in sb.iter().enumerate() {
        let keep = match c {
            // Single quote and parens are sub-delims in RFC 3986, but we
            // escape them so the output can be embedded in single
            // quoted attributes and unquoted CSS url(...) constructs.
            // Single quotes are reserved in URLs, but are only used in
            // the obsolete "mark" rule in an appendix in RFC 3986
            // so can be safely encoded.
            b'!' | b'#' | b'$' | b'&' | b'*' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'?'
            | b'@' | b'[' | b']' => norm,
            // Unreserved according to RFC 3986 sec 2.3
            // "For consistency, percent-encoded octets in the ranges of
            // ALPHA (%41-%5A and %61-%7A), DIGIT (%30-%39), hyphen (%2D),
            // period (%2E), underscore (%5F), or tilde (%7E) should not be
            // created by URI producers
            b'-' | b'.' | b'_' | b'~' => true,
            b'%' => {
                // When normalizing do not re-encode valid escapes.
                norm && i + 2 < sb.len() && is_hex(sb[i + 1]) && is_hex(sb[i + 2])
            }
            _ => c.is_ascii_alphanumeric(),
        };
        if keep {
            continue;
        }
        // Everything kept so far is ASCII; every other byte is escaped.
        b.push_str(&String::from_utf8_lossy(&sb[written..i]));
        b.push_str(&format!("%{c:02x}"));
        written = i + 1;
    }
    b.push_str(&String::from_utf8_lossy(&sb[written..]));
    written != 0
}

/// Filters and normalizes URLs in a srcset attribute value.
pub(crate) fn srcset_filter_and_escaper(args: &[Value]) -> String {
    let (s, t) = stringify(args);
    match t {
        ContentType::Srcset => return s,
        ContentType::Url => {
            // Normalizing gets rid of all HTML whitespace which separate the
            // image URL from its metadata.
            let mut b = String::new();
            let s = if process_url_onto(&s, true, &mut b) {
                b
            } else {
                s
            };
            // Additionally, commas separate one source from another.
            return s.replace(',', "%2c");
        }
        _ => {}
    }

    let sb = s.as_bytes();
    let mut b = String::new();
    let mut written = 0;
    for (i, &c) in sb.iter().enumerate() {
        if c == b',' {
            filter_srcset_element(&s, written, i, &mut b);
            b.push(',');
            written = i + 1;
        }
    }
    filter_srcset_element(&s, written, sb.len(), &mut b);
    b
}

const HTML_SPACE_AND_ASCII_ALNUM_BYTES: &[u8; 16] =
    b"\x00\x36\x00\x00\x01\x00\xff\x03\xfe\xff\xff\x07\xfe\xff\xff\x07";

/// Reports whether `c` is an HTML whitespace character.
fn is_html_space(c: u8) -> bool {
    c <= 0x20 && HTML_SPACE_AND_ASCII_ALNUM_BYTES[usize::from(c >> 3)] & (1 << (c & 0x7)) != 0
}

fn is_html_space_or_ascii_alnum(c: u8) -> bool {
    c < 0x80 && HTML_SPACE_AND_ASCII_ALNUM_BYTES[usize::from(c >> 3)] & (1 << (c & 0x7)) != 0
}

fn filter_srcset_element(s: &str, left: usize, right: usize, b: &mut String) {
    let sb = s.as_bytes();
    let mut start = left;
    while start < right && is_html_space(sb[start]) {
        start += 1; // skip leading whitespace
    }
    let end = (start..right)
        .find(|&i| is_html_space(sb[i]))
        .unwrap_or(right);
    let url = &s[start..end];
    if is_safe_url(url) {
        // If image metadata is only spaces or alnums then it is safe to
        // keep it.
        let mut metadata_ok = true;
        for &c in &sb[end..right] {
            if !is_html_space_or_ascii_alnum(c) {
                metadata_ok = false;
                break;
            }
        }
        if metadata_ok {
            b.push_str(&s[left..start]);
            process_url_onto(url, true, b);
            b.push_str(&s[end..right]);
            return;
        }
    }
    b.push('#');
    b.push_str(FILTER_FAILSAFE);
}
