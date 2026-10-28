//! Go's lossy rune decoding for byte strings that may not be UTF-8.
//!
//! Rust's `str` and `char` cover valid text (`str::from_utf8`, `str::chars`,
//! `char::encode_utf8`, `char::len_utf8`, `char::encode_utf16`,
//! `char::decode_utf16`). What std lacks is Go's rule for *invalid* input:
//! every ill-formed byte decodes as a width-1 [`RUNE_ERROR`]. Runes are `i32`
//! as in Go so that invalid values (negative, surrogates, above [`MAX_RUNE`])
//! can be passed and are handled the way Go handles them. The UTF-16
//! surrogate helpers at the end serve the same purpose for `unicode/utf16`.
//!
//! Decoding is built on `std::str::from_utf8`,
//! `std::str::Utf8Chunks` and `char::encode_utf8`; Go and Rust share the
//! RFC 3629 definition of well-formed UTF-8, and the Go-specific width rules
//! for invalid input (every ill-formed byte is a width-1 `RUNE_ERROR`) are
//! layered on top.

use std::str;

/// The "error" rune, U+FFFD, returned for invalid input.
pub const RUNE_ERROR: i32 = 0xFFFD;
/// Characters below this value are represented as themselves in one byte.
pub const RUNE_SELF: i32 = 0x80;
/// Maximum valid Unicode code point.
pub const MAX_RUNE: i32 = 0x10FFFF;
/// Maximum number of bytes of a UTF-8 encoded Unicode character.
pub const UTF_MAX: usize = 4;

/// Decodes the first rune of `p` (which must be non-empty) from its first
/// `UTF_MAX` bytes. Returns the character and its width, or `Err(incomplete)`
/// when `p` starts with an ill-formed sequence; `incomplete` is true when `p`
/// ends in the middle of an otherwise well-formed sequence.
fn first_rune(p: &[u8]) -> Result<(char, usize), bool> {
    let head = &p[..p.len().min(UTF_MAX)];
    let valid = match str::from_utf8(head) {
        Ok(s) => s,
        Err(e) => {
            if e.valid_up_to() == 0 {
                return Err(e.error_len().is_none());
            }
            match str::from_utf8(&head[..e.valid_up_to()]) {
                Ok(s) => s,
                Err(_) => return Err(false),
            }
        }
    };
    match valid.chars().next() {
        Some(c) => Ok((c, c.len_utf8())),
        None => Err(false),
    }
}

/// Reports whether `p` begins with a full UTF-8 encoding of a rune. An invalid
/// encoding is considered a full rune since it converts as a width-1 error rune.
pub fn full_rune(p: &[u8]) -> bool {
    if p.is_empty() {
        return false;
    }
    !matches!(first_rune(p), Err(true))
}

/// Unpacks the first UTF-8 encoding in `p` and returns the rune and its width
/// in bytes. Empty input gives `(RUNE_ERROR, 0)`; an invalid encoding gives
/// `(RUNE_ERROR, 1)`.
pub fn decode_rune(p: &[u8]) -> (i32, usize) {
    match p.first() {
        None => (RUNE_ERROR, 0),
        Some(&b) if b < 0x80 => (i32::from(b), 1),
        Some(_) => match first_rune(p) {
            Ok((c, n)) => (c as i32, n),
            Err(_) => (RUNE_ERROR, 1),
        },
    }
}

/// Unpacks the last UTF-8 encoding in `p` and returns the rune and its width
/// in bytes. Empty input gives `(RUNE_ERROR, 0)`; an invalid encoding gives
/// `(RUNE_ERROR, 1)`.
pub fn decode_last_rune(p: &[u8]) -> (i32, usize) {
    let end = p.len();
    if end == 0 {
        return (RUNE_ERROR, 0);
    }
    let mut start = end as isize - 1;
    let r = p[start as usize] as i32;
    if r < RUNE_SELF {
        return (r, 1);
    }
    let lim = (end as isize - UTF_MAX as isize).max(0);
    start -= 1;
    while start >= lim {
        if rune_start(p[start as usize]) {
            break;
        }
        start -= 1;
    }
    let start = start.max(0) as usize;
    let (r, size) = decode_rune(&p[start..end]);
    if start + size != end {
        return (RUNE_ERROR, 1);
    }
    (r, size)
}

/// Returns the number of bytes required to encode `r`, or -1 if `r` is not a
/// valid value to encode in UTF-8.
pub fn rune_len(r: i32) -> isize {
    match char::from_u32(r as u32) {
        Some(c) => c.len_utf8() as isize,
        None => -1,
    }
}

/// Writes into `p` (which must be large enough) the UTF-8 encoding of `r` and
/// returns the number of bytes written. Out-of-range runes and surrogates are
/// written as [`RUNE_ERROR`]. Panics if `p` is too short, like Go.
pub fn encode_rune(p: &mut [u8], r: i32) -> usize {
    let c = char::from_u32(r as u32).unwrap_or(char::REPLACEMENT_CHARACTER);
    c.encode_utf8(p).len()
}

/// Appends the UTF-8 encoding of `r` to the end of `p`. Invalid runes are
/// appended as [`RUNE_ERROR`].
pub fn append_rune(p: &mut Vec<u8>, r: i32) {
    let mut buf = [0u8; UTF_MAX];
    let n = encode_rune(&mut buf, r);
    p.extend_from_slice(&buf[..n]);
}

/// Returns the number of runes in `p`. Erroneous and short encodings are
/// treated as single runes of width 1 byte.
pub fn rune_count(p: &[u8]) -> usize {
    str::from_utf8(p).map_or_else(
        |_| {
            p.utf8_chunks()
                .map(|c| c.valid().chars().count() + c.invalid().len())
                .sum()
        },
        |s| s.chars().count(),
    )
}

/// Reports whether the byte could be the first byte of an encoded, possibly
/// invalid rune. Second and subsequent bytes always have the top two bits set
/// to 10.
pub fn rune_start(b: u8) -> bool {
    b & 0xC0 != 0x80
}

/// Reports whether `r` can be legally encoded as UTF-8: it is in range and not
/// a surrogate half.
pub fn valid_rune(r: i32) -> bool {
    char::from_u32(r as u32).is_some()
}

/// Reports whether `r` can appear in a UTF-16 surrogate pair.
pub fn is_surrogate(r: i32) -> bool {
    (0xD800..0xE000).contains(&r)
}

/// Returns the UTF-16 decoding of the surrogate pair `r1`, `r2`, or
/// [`RUNE_ERROR`] if the pair is not a valid surrogate sequence.
pub fn decode_surrogate_pair(r1: i32, r2: i32) -> i32 {
    let unit = |r: i32| u16::try_from(r).ok();
    match (unit(r1), unit(r2)) {
        (Some(a), Some(b)) => match char::decode_utf16([a, b]).next() {
            Some(Ok(c)) if c as i32 >= 0x10000 => c as i32,
            _ => RUNE_ERROR,
        },
        _ => RUNE_ERROR,
    }
}

/// Returns the UTF-16 surrogate pair for `r`, or `(RUNE_ERROR, RUNE_ERROR)` if
/// `r` does not need one.
pub fn encode_surrogate_pair(r: i32) -> (i32, i32) {
    match char::from_u32(r as u32) {
        Some(c) if c.len_utf16() == 2 => {
            let mut buf = [0u16; 2];
            c.encode_utf16(&mut buf);
            (buf[0] as i32, buf[1] as i32)
        }
        _ => (RUNE_ERROR, RUNE_ERROR),
    }
}
