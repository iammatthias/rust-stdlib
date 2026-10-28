//! Crate-private `char` views of this package for [`crate::text::BytesExt`],
//! which passes runes as `char` and decodes invalid UTF-8 as `U+FFFD`. Every
//! function delegates to the public `i32` API so there is one implementation
//! of Go's decoding, case mapping, folding and classification.

use super::rune as utf8;
use super::SpecialCase;

pub(crate) const RUNE_ERROR: char = char::REPLACEMENT_CHARACTER;

fn rune(r: i32) -> char {
    u32::try_from(r)
        .ok()
        .and_then(char::from_u32)
        .unwrap_or(RUNE_ERROR)
}

pub(crate) fn decode_rune(b: &[u8]) -> (char, usize) {
    let (r, n) = utf8::decode_rune(b);
    (rune(r), n)
}

pub(crate) fn decode_last_rune(b: &[u8]) -> (char, usize) {
    let (r, n) = utf8::decode_last_rune(b);
    (rune(r), n)
}

pub(crate) use utf8::rune_count;

pub(crate) fn to_upper(c: char) -> char {
    rune(super::to_upper(c as i32))
}

pub(crate) fn to_lower(c: char) -> char {
    rune(super::to_lower(c as i32))
}

pub(crate) fn to_title(c: char) -> char {
    rune(super::to_title(c as i32))
}

pub(crate) fn simple_fold(c: char) -> char {
    rune(super::simple_fold(c as i32))
}

pub(crate) fn is_space(c: char) -> bool {
    super::is_space(c as i32)
}

pub(crate) fn special_upper(sc: SpecialCase<'_>, c: char) -> char {
    rune(sc.to_upper(c as i32))
}

pub(crate) fn special_lower(sc: SpecialCase<'_>, c: char) -> char {
    rune(sc.to_lower(c as i32))
}

pub(crate) fn special_title(sc: SpecialCase<'_>, c: char) -> char {
    rune(sc.to_title(c as i32))
}

/// Go's `isSeparator` from `strings.Title`: not a letter, digit or
/// underscore (ASCII), otherwise white space.
pub(crate) fn is_separator(r: char) -> bool {
    if r.is_ascii() {
        return !(r.is_ascii_alphanumeric() || r == '_');
    }
    if super::is_letter(r as i32) || super::is_digit(r as i32) {
        return false;
    }
    is_space(r)
}
