//! Unicode code point tests and case mapping (Go `unicode`), plus [`rune`], Go's
//! lossy rune decoding for `unicode/utf8` and `unicode/utf16` (the rest of those
//! packages is `str::from_utf8`, `char::encode_utf8`, `char::encode_utf16`).
//!
//! Runes are `i32` as in Go, so negative, surrogate and out-of-range values
//! can be passed. The range tables are generated from Go's own `unicode`
//! package by `tools/unicode_gen.go`, so they carry Go's Unicode version
//! ([`VERSION`]) rather than the one of the Rust toolchain.
//!
//! Where Rust's `std` has the same definition, it is used directly:
//! `char::is_control` (general category Cc, Go's `IsControl`) and `char::is_whitespace` (White_Space, Go's `IsSpace`). Case
//! mapping stays table driven: Go's `ToUpper`/`ToLower`/`ToTitle` are
//! *simple* one-to-one mappings, while `char::to_uppercase` implements the
//! full multi-character mapping (and std has no title case or case folding
//! orbit), so the results differ for `ß`, `İ`, ligatures and so on.
//!
//! The Go maps (`Categories`, `Scripts`, `Properties`, `FoldCategory`,
//! `FoldScript`, `CategoryAliases`) are sorted slices of pairs, searchable with
//! `binary_search_by_key`.
//!
//! ```
//! use rust_stdlib::unicode;
//! assert!(unicode::is_upper('Ǆ' as i32) && unicode::is_title('ǅ' as i32));
//! assert_eq!(unicode::to_title('ǆ' as i32), 'ǅ' as i32);
//! assert!(unicode::is(unicode::HAN, '世' as i32));
//! ```

pub(crate) mod chars;
pub mod rune;

#[rustfmt::skip]
mod tables;

pub use tables::*;

/// Maximum valid Unicode code point.
pub const MAX_RUNE: i32 = 0x10FFFF;
/// Represents invalid code points.
pub const REPLACEMENT_CHAR: i32 = 0xFFFD;
/// Maximum ASCII value.
pub const MAX_ASCII: i32 = 0x7F;
/// Maximum Latin-1 value.
pub const MAX_LATIN1: i32 = 0xFF;

/// Index of the upper case mapping in [`CaseRange::delta`].
pub const UPPER_CASE: usize = 0;
/// Index of the lower case mapping in [`CaseRange::delta`].
pub const LOWER_CASE: usize = 1;
/// Index of the title case mapping in [`CaseRange::delta`].
pub const TITLE_CASE: usize = 2;
/// Number of case mappings.
pub const MAX_CASE: usize = 3;

/// Delta value marking an upper/lower sequence where upper and lower case
/// alternate (cannot be a valid delta).
pub const UPPER_LOWER: i32 = MAX_RUNE + 1;

/// A 16-bit range of code points: `lo..=hi` taking every `stride`th value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range16 {
    pub lo: u16,
    pub hi: u16,
    pub stride: u16,
}

/// A 32-bit range of code points: `lo..=hi` taking every `stride`th value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range32 {
    pub lo: u32,
    pub hi: u32,
    pub stride: u32,
}

/// A set of code points as sorted, non-overlapping ranges. `r16` holds the
/// ranges below U+10000 and `r32` the rest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RangeTable {
    pub r16: &'static [Range16],
    pub r32: &'static [Range32],
    /// Number of entries in `r16` with `hi <= MAX_LATIN1`.
    pub latin_offset: usize,
}

/// A mapping for a range of code points: the delta to add to reach the upper,
/// lower and title case form, or [`UPPER_LOWER`] for alternating sequences.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaseRange {
    pub lo: u32,
    pub hi: u32,
    pub delta: [i32; MAX_CASE],
}

/// Language-specific case mappings that override the defaults, such as
/// [`TURKISH_CASE`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpecialCase<'a>(pub &'a [CaseRange]);

const LINEAR_MAX: usize = 18;

// A zero stride panics on `%`, as Go's divide does; `is_multiple_of`
// would answer instead.
#[allow(clippy::manual_is_multiple_of)]
fn is16(ranges: &[Range16], r: u16) -> bool {
    if ranges.len() <= LINEAR_MAX || r <= MAX_LATIN1 as u16 {
        for range in ranges {
            if r < range.lo {
                return false;
            }
            if r <= range.hi {
                return range.stride == 1 || (r - range.lo) % range.stride == 0;
            }
        }
        return false;
    }
    let (mut lo, mut hi) = (0, ranges.len());
    while lo < hi {
        let m = (lo + hi) >> 1;
        let range = &ranges[m];
        if range.lo <= r && r <= range.hi {
            return range.stride == 1 || (r - range.lo) % range.stride == 0;
        }
        if r < range.lo {
            hi = m;
        } else {
            lo = m + 1;
        }
    }
    false
}

// A zero stride panics on `%`, as Go's divide does; `is_multiple_of`
// would answer instead.
#[allow(clippy::manual_is_multiple_of)]
fn is32(ranges: &[Range32], r: u32) -> bool {
    if ranges.len() <= LINEAR_MAX {
        for range in ranges {
            if r < range.lo {
                return false;
            }
            if r <= range.hi {
                return range.stride == 1 || (r - range.lo) % range.stride == 0;
            }
        }
        return false;
    }
    let (mut lo, mut hi) = (0, ranges.len());
    while lo < hi {
        let m = (lo + hi) >> 1;
        let range = &ranges[m];
        if range.lo <= r && r <= range.hi {
            return range.stride == 1 || (r - range.lo) % range.stride == 0;
        }
        if r < range.lo {
            hi = m;
        } else {
            lo = m + 1;
        }
    }
    false
}

/// Reports whether the rune is in the specified table of ranges.
pub fn is(range_tab: &RangeTable, r: i32) -> bool {
    let r16 = range_tab.r16;
    if let Some(last) = r16.last() {
        if (r as u32) <= last.hi as u32 {
            return is16(r16, r as u16);
        }
    }
    let r32 = range_tab.r32;
    if let Some(first) = r32.first() {
        if r >= first.lo as i32 {
            return is32(r32, r as u32);
        }
    }
    false
}

fn is_excluding_latin(range_tab: &RangeTable, r: i32) -> bool {
    let r16 = range_tab.r16;
    let off = range_tab.latin_offset;
    if r16.len() > off && (r as u32) <= r16[r16.len() - 1].hi as u32 {
        return is16(&r16[off..], r as u16);
    }
    let r32 = range_tab.r32;
    if let Some(first) = r32.first() {
        if r >= first.lo as i32 {
            return is32(r32, r as u32);
        }
    }
    false
}

/// Reports whether the rune is in any of the tables.
pub fn is_one_of(ranges: &[&RangeTable], r: i32) -> bool {
    ranges.iter().any(|t| is(t, r))
}

/// Reports whether the rune is a member of one of the ranges. (Go's `In`;
/// `in` is a Rust keyword.)
pub fn in_(r: i32, ranges: &[&RangeTable]) -> bool {
    is_one_of(ranges, r)
}

/// Reports whether the rune is a graphic character: a letter, mark, number,
/// punctuation, symbol or space (Zs).
pub fn is_graphic(r: i32) -> bool {
    in_(r, GRAPHIC_RANGES)
}

/// Reports whether the rune is printable by Go's definition: like
/// [`is_graphic`] but the only space allowed is U+0020.
pub fn is_print(r: i32) -> bool {
    if r == ' ' as i32 {
        return true;
    }
    in_(r, PRINT_RANGES)
}

/// Reports whether the rune is a letter (category L).
pub fn is_letter(r: i32) -> bool {
    if (r as u32) <= MAX_LATIN1 as u32 {
        return is(L, r);
    }
    is_excluding_latin(LETTER, r)
}

/// Reports whether the rune is a mark character (category M).
pub fn is_mark(r: i32) -> bool {
    is_excluding_latin(MARK, r)
}

/// Reports whether the rune is a number (category N).
pub fn is_number(r: i32) -> bool {
    if (r as u32) <= MAX_LATIN1 as u32 {
        return is(N, r);
    }
    is_excluding_latin(NUMBER, r)
}

/// Reports whether the rune is a Unicode punctuation character (category P).
pub fn is_punct(r: i32) -> bool {
    is(PUNCT, r)
}

/// Reports whether the rune is a space character as defined by Unicode's
/// White Space property: U+0009-U+000D, U+0020, U+0085, U+00A0 and the
/// categories Z with the White_Space property.
pub(crate) fn is_space(r: i32) -> bool {
    char::from_u32(r as u32).is_some_and(char::is_whitespace)
}

/// Reports whether the rune is a symbolic character (category S).
pub fn is_symbol(r: i32) -> bool {
    if (r as u32) <= MAX_LATIN1 as u32 {
        return is(S, r);
    }
    is_excluding_latin(SYMBOL, r)
}

/// Reports whether the rune is a decimal digit (category Nd).
pub fn is_digit(r: i32) -> bool {
    if r <= MAX_LATIN1 {
        return ('0' as i32..='9' as i32).contains(&r);
    }
    is_excluding_latin(DIGIT, r)
}

/// Reports whether the rune is an upper case letter (category Lu).
pub fn is_upper(r: i32) -> bool {
    if (r as u32) <= MAX_LATIN1 as u32 {
        return is(UPPER, r);
    }
    is_excluding_latin(UPPER, r)
}

/// Reports whether the rune is a lower case letter (category Ll).
pub fn is_lower(r: i32) -> bool {
    if (r as u32) <= MAX_LATIN1 as u32 {
        return is(LOWER, r);
    }
    is_excluding_latin(LOWER, r)
}

/// Reports whether the rune is a title case letter (category Lt).
pub fn is_title(r: i32) -> bool {
    if r <= MAX_LATIN1 {
        return false;
    }
    is_excluding_latin(TITLE, r)
}

fn lookup_case_range(r: i32, case_range: &[CaseRange]) -> Option<&CaseRange> {
    let (mut lo, mut hi) = (0, case_range.len());
    while lo < hi {
        let m = (lo + hi) >> 1;
        let cr = &case_range[m];
        if cr.lo as i32 <= r && r <= cr.hi as i32 {
            return Some(cr);
        }
        if r < cr.lo as i32 {
            hi = m;
        } else {
            lo = m + 1;
        }
    }
    None
}

fn convert_case(case: usize, r: i32, cr: &CaseRange) -> i32 {
    let delta = cr.delta[case];
    if delta > MAX_RUNE {
        // In an Upper-Lower sequence, which always starts with an UpperCase
        // letter, the real deltas always look like: {0, 1, 0}, {-1, 0, -1}.
        return (cr.lo as i32)
            .wrapping_add((r.wrapping_sub(cr.lo as i32) & !1) | (case as i32 & 1));
    }
    r.wrapping_add(delta)
}

fn to_case(case: i32, r: i32, case_range: &[CaseRange]) -> (i32, bool) {
    if !(0..MAX_CASE as i32).contains(&case) {
        return (REPLACEMENT_CHAR, false);
    }
    match lookup_case_range(r, case_range) {
        Some(cr) => (convert_case(case as usize, r, cr), true),
        None => (r, false),
    }
}

/// Maps the rune to the specified case: [`UPPER_CASE`], [`LOWER_CASE`] or
/// [`TITLE_CASE`]. Any other `case` returns [`REPLACEMENT_CHAR`].
pub fn to(case: i32, r: i32) -> i32 {
    to_case(case, r, CASE_RANGES).0
}

/// Maps the rune to upper case.
pub fn to_upper(r: i32) -> i32 {
    if r <= MAX_ASCII {
        return if ('a' as i32..='z' as i32).contains(&r) {
            r - 32
        } else {
            r
        };
    }
    to(UPPER_CASE as i32, r)
}

/// Maps the rune to lower case.
pub fn to_lower(r: i32) -> i32 {
    if r <= MAX_ASCII {
        return if ('A' as i32..='Z' as i32).contains(&r) {
            r + 32
        } else {
            r
        };
    }
    to(LOWER_CASE as i32, r)
}

/// Maps the rune to title case.
pub fn to_title(r: i32) -> i32 {
    if r <= MAX_ASCII {
        // Title case is upper case for ASCII.
        return if ('a' as i32..='z' as i32).contains(&r) {
            r - 32
        } else {
            r
        };
    }
    to(TITLE_CASE as i32, r)
}

impl SpecialCase<'_> {
    fn map(&self, case: usize, r: i32, default: fn(i32) -> i32) -> i32 {
        let (r1, had_mapping) = to_case(case as i32, r, self.0);
        if r1 == r && !had_mapping {
            default(r)
        } else {
            r1
        }
    }

    /// Maps the rune to upper case giving priority to the special mapping.
    pub fn to_upper(&self, r: i32) -> i32 {
        self.map(UPPER_CASE, r, to_upper)
    }

    /// Maps the rune to title case giving priority to the special mapping.
    pub fn to_title(&self, r: i32) -> i32 {
        self.map(TITLE_CASE, r, to_title)
    }

    /// Maps the rune to lower case giving priority to the special mapping.
    pub fn to_lower(&self, r: i32) -> i32 {
        self.map(LOWER_CASE, r, to_lower)
    }
}

/// Iterates over Unicode code points equivalent under the simple case folding
/// and returns the smallest rune greater than `r`, or else the smallest rune
/// overall. Runes outside `0..=MAX_RUNE` are returned unchanged.
pub fn simple_fold(r: i32) -> i32 {
    if !(0..=MAX_RUNE).contains(&r) {
        return r;
    }
    if (r as usize) < ASCII_FOLD.len() {
        return ASCII_FOLD[r as usize] as i32;
    }
    if let Ok(i) = CASE_ORBIT.binary_search_by_key(&r, |&(from, _)| from as i32) {
        return CASE_ORBIT[i].1 as i32;
    }
    if let Some(cr) = lookup_case_range(r, CASE_RANGES) {
        let l = convert_case(LOWER_CASE, r, cr);
        if l != r {
            return l;
        }
        return convert_case(UPPER_CASE, r, cr);
    }
    r
}
