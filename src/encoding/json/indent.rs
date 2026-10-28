//! `Valid`, `Compact`, `Indent` and `HTMLEscape`, byte-oriented like Go's.
use super::scanner::{
    check_valid, Scanner, SCAN_CONTINUE, SCAN_END_ARRAY, SCAN_END_OBJECT, SCAN_ERROR,
    SCAN_SKIP_SPACE,
};
use super::SyntaxError;

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Reports whether `data` is a valid JSON encoding.
pub fn valid(data: &[u8]) -> bool {
    check_valid(data, &mut Scanner::new()).is_ok()
}

fn push_u00(dst: &mut Vec<u8>, c: u8) {
    dst.extend_from_slice(&[
        b'\\',
        b'u',
        b'0',
        b'0',
        HEX[usize::from(c >> 4)],
        HEX[usize::from(c & 0xf)],
    ]);
}

fn push_u202x(dst: &mut Vec<u8>, last: u8) {
    dst.extend_from_slice(&[b'\\', b'u', b'2', b'0', b'2', HEX[usize::from(last & 0xf)]]);
}

/// Appends `src` to `dst`, escaping `<`, `>`, `&`, U+2028 and U+2029 so the
/// JSON can be embedded in HTML `<script>` elements. Go's `HTMLEscape` takes
/// a `*bytes.Buffer`; a `Vec<u8>` is the Rust equivalent.
pub fn html_escape(dst: &mut Vec<u8>, src: &[u8]) {
    dst.reserve(src.len());
    let mut start = 0;
    for (i, &c) in src.iter().enumerate() {
        if c == b'<' || c == b'>' || c == b'&' {
            dst.extend_from_slice(&src[start..i]);
            push_u00(dst, c);
            start = i + 1;
        }
        // U+2028 and U+2029 are E2 80 A8 and E2 80 A9.
        if c == 0xe2 && i + 2 < src.len() && src[i + 1] == 0x80 && src[i + 2] & !1 == 0xa8 {
            dst.extend_from_slice(&src[start..i]);
            push_u202x(dst, src[i + 2]);
            start = i + 3;
        }
    }
    dst.extend_from_slice(&src[start..]);
}

/// Appends to `dst` the JSON-encoded `src` with insignificant space characters
/// elided. Nothing is appended on error.
pub fn compact(dst: &mut Vec<u8>, src: &[u8]) -> Result<(), SyntaxError> {
    append_compact(dst, src, false)
}

pub(crate) fn append_compact(
    dst: &mut Vec<u8>,
    src: &[u8],
    escape: bool,
) -> Result<(), SyntaxError> {
    let orig = dst.len();
    let mut scan = Scanner::new();
    let mut start = 0;
    for (i, &c) in src.iter().enumerate() {
        if escape && (c == b'<' || c == b'>' || c == b'&') {
            if start < i {
                dst.extend_from_slice(&src[start..i]);
            }
            push_u00(dst, c);
            start = i + 1;
        }
        // Convert U+2028 and U+2029 (E2 80 A8 and E2 80 A9).
        if escape && c == 0xe2 && i + 2 < src.len() && src[i + 1] == 0x80 && src[i + 2] & !1 == 0xa8
        {
            if start < i {
                dst.extend_from_slice(&src[start..i]);
            }
            push_u202x(dst, src[i + 2]);
            start = i + 3;
        }
        let v = scan.feed(src, i);
        if v >= SCAN_SKIP_SPACE {
            if v == SCAN_ERROR {
                break;
            }
            if start < i {
                dst.extend_from_slice(&src[start..i]);
            }
            start = i + 1;
        }
    }
    if scan.eof(src, false) == SCAN_ERROR {
        dst.truncate(orig);
        return Err(scan.err.take().expect("scanner error recorded"));
    }
    if start < src.len() {
        dst.extend_from_slice(&src[start..]);
    }
    Ok(())
}

fn append_newline(dst: &mut Vec<u8>, prefix: &str, indent: &str, depth: i64) {
    dst.push(b'\n');
    dst.extend_from_slice(prefix.as_bytes());
    for _ in 0..depth {
        dst.extend_from_slice(indent.as_bytes());
    }
}

/// Appends to `dst` an indented form of the JSON-encoded `src`. Each element
/// in a JSON object or array begins on a new, indented line beginning with
/// `prefix` followed by one or more copies of `indent` according to the
/// nesting. Nothing is appended on error.
pub fn indent(
    dst: &mut Vec<u8>,
    src: &[u8],
    prefix: &str,
    indent: &str,
) -> Result<(), SyntaxError> {
    append_indent(dst, src, prefix, indent)
}

pub(crate) fn append_indent(
    dst: &mut Vec<u8>,
    src: &[u8],
    prefix: &str,
    indent: &str,
) -> Result<(), SyntaxError> {
    let orig = dst.len();
    let mut scan = Scanner::new();
    let mut need_indent = false;
    let mut depth = 0i64;
    for (i, &c) in src.iter().enumerate() {
        let v = scan.feed(src, i);
        if v == SCAN_SKIP_SPACE {
            continue;
        }
        if v == SCAN_ERROR {
            break;
        }
        if need_indent && v != SCAN_END_OBJECT && v != SCAN_END_ARRAY {
            need_indent = false;
            depth += 1;
            append_newline(dst, prefix, indent, depth);
        }
        // Emit semantically uninteresting bytes (in particular, punctuation in
        // strings) unmodified.
        if v == SCAN_CONTINUE {
            dst.push(c);
            continue;
        }
        match c {
            b'{' | b'[' => {
                need_indent = true;
                dst.push(c);
            }
            b',' => {
                dst.push(c);
                append_newline(dst, prefix, indent, depth);
            }
            b':' => {
                dst.push(c);
                dst.push(b' ');
            }
            b'}' | b']' => {
                if need_indent {
                    // Suppress indent in empty object/array.
                    need_indent = false;
                } else {
                    depth -= 1;
                    append_newline(dst, prefix, indent, depth);
                }
                dst.push(c);
            }
            _ => dst.push(c),
        }
    }
    if scan.eof(src, false) == SCAN_ERROR {
        dst.truncate(orig);
        return Err(scan.err.take().expect("scanner error recorded"));
    }
    Ok(())
}
