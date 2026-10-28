//! Go's `mime` media type functions, with Go's grammar: [`parse_media_type`]
//! accepts RFC 2231 continuations and encoded values, and
//! [`format_media_type`] writes them back.
//!
//! The one difference from Go is that a decoded RFC 2231 value that is not
//! valid UTF-8 is reported as [`ERR_INVALID_MEDIA_PARAMETER`]; Go keeps the raw
//! bytes, which `String` cannot hold.
use super::{token, Error, ERR_INVALID_MEDIA_PARAMETER};
use std::collections::BTreeMap;

const NO_MEDIA_TYPE: Error = Error::new("mime: no media type");
const NO_SLASH_AFTER_FIRST_TOKEN: Error = Error::new("mime: expected slash after first token");
const NO_TOKEN_AFTER_SLASH: Error = Error::new("mime: expected token after slash");
const UNEXPECTED_CONTENT: Error = Error::new("mime: unexpected content after media subtype");
const DUPLICATE_PARAMETER: Error = Error::new("mime: duplicate parameter name");

/// Go's `isTSpecial`: the RFC 2045 tspecials.
fn is_tspecial(c: u8) -> bool {
    b"()<>@,;:\\\"/[]?=".contains(&c)
}

/// Go's `isTokenChar` is exactly the RFC 2045 token alphabet.
fn is_token_char(c: u8) -> bool {
    c.is_ascii_graphic() && !is_tspecial(c)
}

/// Go's `needsEncoding`: whether `s` has a byte outside printable ASCII and tab.
fn needs_encoding(s: &str) -> bool {
    s.chars().any(|c| !(' '..='~').contains(&c) && c != '\t')
}

/// Go's `checkMediaTypeDisposition`: `type/subtype` with no trailing content.
fn check_disposition(s: &str) -> Result<(), Error> {
    let (kind, rest) = consume_token(s);
    if kind.is_empty() {
        return Err(NO_MEDIA_TYPE);
    }
    if rest.is_empty() {
        return Ok(());
    }
    let Some(rest) = rest.strip_prefix('/') else {
        return Err(NO_SLASH_AFTER_FIRST_TOKEN);
    };
    let (subtype, rest) = consume_token(rest);
    if subtype.is_empty() {
        return Err(NO_TOKEN_AFTER_SLASH);
    }
    if !rest.is_empty() {
        return Err(UNEXPECTED_CONTENT);
    }
    Ok(())
}

/// Serializes a media type and its parameters as Go's `FormatMediaType` does:
/// names and type are lower-case, values that are not tokens are quoted, and
/// values with bytes outside printable ASCII use RFC 2231 `utf-8''` encoding.
///
/// Returns `None` where Go returns "" because an argument violates the grammar.
pub fn format_media_type(media_type: &str, params: &BTreeMap<String, String>) -> Option<String> {
    let mut out = String::new();
    match media_type.split_once('/') {
        None => {
            if !token(media_type) {
                return None;
            }
            out.push_str(&media_type.to_lowercase());
        }
        Some((major, sub)) => {
            if !token(major) || !token(sub) {
                return None;
            }
            out.push_str(&major.to_lowercase());
            out.push('/');
            out.push_str(&sub.to_lowercase());
        }
    }
    for (attribute, value) in params {
        out.push_str("; ");
        if !token(attribute) {
            return None;
        }
        out.push_str(&attribute.to_lowercase());
        let encoded = needs_encoding(value);
        if encoded {
            out.push('*');
        }
        out.push('=');
        if encoded {
            out.push_str("utf-8''");
            for &b in value.as_bytes() {
                if b <= b' ' || b >= 0x7f || b == b'*' || b == b'\'' || b == b'%' || is_tspecial(b)
                {
                    out.push('%');
                    out.push(char::from(UPPER_HEX[usize::from(b >> 4)]));
                    out.push(char::from(UPPER_HEX[usize::from(b & 0x0f)]));
                } else {
                    out.push(char::from(b));
                }
            }
            continue;
        }
        if token(value) {
            out.push_str(value);
            continue;
        }
        out.push('"');
        for c in value.chars() {
            if c == '"' || c == '\\' {
                out.push('\\');
            }
            out.push(c);
        }
        out.push('"');
    }
    Some(out)
}

const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";

/// Parses a media type and its parameters as Go's `ParseMediaType` does.
///
/// The media type is returned lower-case and trimmed. On failure the media
/// type is "" and the error is returned, except for
/// [`ERR_INVALID_MEDIA_PARAMETER`], which keeps the media type so the caller
/// can use it, as Go does.
pub fn parse_media_type(v: &str) -> (String, Result<BTreeMap<String, String>, Error>) {
    let base = v.split_once(';').map_or(v, |(base, _)| base);
    let media_type = base.to_lowercase();
    let media_type = media_type.trim().to_owned();
    if let Err(error) = check_disposition(&media_type) {
        return (String::new(), Err(error));
    }
    match parse_params(&v[base.len()..]) {
        Ok(params) => (media_type, Ok(params)),
        Err(error) if error == ERR_INVALID_MEDIA_PARAMETER => (media_type, Err(error)),
        Err(error) => (String::new(), Err(error)),
    }
}

fn parse_params(mut rest: &str) -> Result<BTreeMap<String, String>, Error> {
    let mut params = BTreeMap::new();
    // Continuation pieces keyed by base name, then by full piece name.
    let mut continuation: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    while !rest.is_empty() {
        rest = rest.trim_start();
        if rest.is_empty() {
            break;
        }
        let (key, value, next) = consume_media_param(rest);
        if key.is_empty() {
            if next.trim() == ";" {
                break;
            }
            return Err(ERR_INVALID_MEDIA_PARAMETER);
        }
        let target = match key.split_once('*') {
            Some((base_name, _)) => continuation.entry(base_name.to_owned()).or_default(),
            None => &mut params,
        };
        if let Some(existing) = target.get(&key) {
            if *existing != value {
                return Err(DUPLICATE_PARAMETER);
            }
        }
        target.insert(key, value);
        rest = next;
    }
    for (key, pieces) in &continuation {
        if let Some(value) = pieces.get(&format!("{key}*")) {
            if let Some(decoded) = decode_2231(value) {
                params.insert(key.clone(), into_text(decoded)?);
            }
            continue;
        }
        let mut buf = Vec::new();
        let mut valid = false;
        let mut n = 0;
        loop {
            let simple = format!("{key}*{n}");
            if let Some(value) = pieces.get(&simple) {
                valid = true;
                buf.extend_from_slice(value.as_bytes());
                n += 1;
                continue;
            }
            let Some(value) = pieces.get(&format!("{simple}*")) else {
                break;
            };
            valid = true;
            let decoded = if n == 0 {
                decode_2231(value)
            } else {
                percent_hex_unescape(value)
            };
            if let Some(decoded) = decoded {
                buf.extend(decoded);
            }
            n += 1;
        }
        if valid {
            params.insert(key.clone(), into_text(buf)?);
        }
    }
    Ok(params)
}

fn into_text(bytes: Vec<u8>) -> Result<String, Error> {
    String::from_utf8(bytes).map_err(|_| ERR_INVALID_MEDIA_PARAMETER)
}

/// Go's `decode2231Enc`: `charset'language'percent-encoded`, for us-ascii or utf-8.
fn decode_2231(v: &str) -> Option<Vec<u8>> {
    let (charset, rest) = v.split_once('\'')?;
    let (_, encoded) = rest.split_once('\'')?;
    match charset.to_lowercase().as_str() {
        "us-ascii" | "utf-8" => percent_hex_unescape(encoded),
        _ => None,
    }
}

/// Go's `percentHexUnescape`: `None` for a malformed escape.
fn percent_hex_unescape(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        if i + 2 >= bytes.len()
            || !bytes[i + 1].is_ascii_hexdigit()
            || !bytes[i + 2].is_ascii_hexdigit()
        {
            return None;
        }
        out.push(unhex(bytes[i + 1]) << 4 | unhex(bytes[i + 2]));
        i += 3;
    }
    Some(out)
}

fn unhex(c: u8) -> u8 {
    (c as char).to_digit(16).unwrap_or(0) as u8
}

/// Go's `consumeToken`: the leading token and the rest of `v`.
fn consume_token(v: &str) -> (&str, &str) {
    let end = v.bytes().position(|b| !is_token_char(b)).unwrap_or(v.len());
    v.split_at(end)
}

/// Go's `consumeValue`: a token or a quoted string, and the rest of `v`.
/// Returns an empty value and `v` unchanged when a quoted string is unterminated.
fn consume_value(v: &str) -> (String, &str) {
    if v.is_empty() {
        return (String::new(), v);
    }
    if !v.starts_with('"') {
        let (token, rest) = consume_token(v);
        return (token.to_owned(), rest);
    }
    let bytes = v.as_bytes();
    let mut buffer = Vec::new();
    let mut i = 1;
    while i < bytes.len() {
        let r = bytes[i];
        if r == b'"' {
            return (String::from_utf8_lossy(&buffer).into_owned(), &v[i + 1..]);
        }
        if r == b'\\' && i + 1 < bytes.len() && is_tspecial(bytes[i + 1]) {
            buffer.push(bytes[i + 1]);
            i += 2;
            continue;
        }
        if r == b'\r' || r == b'\n' {
            return (String::new(), v);
        }
        buffer.push(r);
        i += 1;
    }
    (String::new(), v)
}

/// Go's `consumeMediaParam`: `; name=value`, with the name lower-cased. An empty
/// name means the input did not start a parameter; the rest is `v` unchanged.
fn consume_media_param(v: &str) -> (String, String, &str) {
    let fail = (String::new(), String::new(), v);
    let Some(rest) = v.trim_start().strip_prefix(';') else {
        return fail;
    };
    let (param, rest) = consume_token(rest.trim_start());
    let param = param.to_ascii_lowercase();
    if param.is_empty() {
        return fail;
    }
    let Some(rest) = rest.trim_start().strip_prefix('=') else {
        return fail;
    };
    let rest = rest.trim_start();
    let (value, next) = consume_value(rest);
    if value.is_empty() && next == rest {
        return fail;
    }
    (param, value, next)
}
