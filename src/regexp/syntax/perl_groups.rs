//! Perl and POSIX character class tables (Go `regexp/syntax/perl_groups.go`).

/// A character class with a sign: -1 negates the range pairs in `class`.
#[derive(Clone, Copy)]
pub(super) struct CharGroup {
    pub sign: i32,
    pub class: &'static [i32],
}

const DIGIT: &[i32] = &[0x30, 0x39];
const SPACE: &[i32] = &[0x9, 0xa, 0xc, 0xd, 0x20, 0x20];
const WORD: &[i32] = &[0x30, 0x39, 0x41, 0x5a, 0x5f, 0x5f, 0x61, 0x7a];

pub(super) fn perl_group(name: &[u8]) -> Option<CharGroup> {
    let (sign, class) = match name {
        b"\\d" => (1, DIGIT),
        b"\\D" => (-1, DIGIT),
        b"\\s" => (1, SPACE),
        b"\\S" => (-1, SPACE),
        b"\\w" => (1, WORD),
        b"\\W" => (-1, WORD),
        _ => return None,
    };
    Some(CharGroup { sign, class })
}

const ALNUM: &[i32] = &[0x30, 0x39, 0x41, 0x5a, 0x61, 0x7a];
const ALPHA: &[i32] = &[0x41, 0x5a, 0x61, 0x7a];
const ASCII: &[i32] = &[0x0, 0x7f];
const BLANK: &[i32] = &[0x9, 0x9, 0x20, 0x20];
const CNTRL: &[i32] = &[0x0, 0x1f, 0x7f, 0x7f];
const GRAPH: &[i32] = &[0x21, 0x7e];
const LOWER: &[i32] = &[0x61, 0x7a];
const PRINT: &[i32] = &[0x20, 0x7e];
const PUNCT: &[i32] = &[0x21, 0x2f, 0x3a, 0x40, 0x5b, 0x60, 0x7b, 0x7e];
const POSIX_SPACE: &[i32] = &[0x9, 0xd, 0x20, 0x20];
const UPPER: &[i32] = &[0x41, 0x5a];
const XDIGIT: &[i32] = &[0x30, 0x39, 0x41, 0x46, 0x61, 0x66];

pub(super) fn posix_group(name: &[u8]) -> Option<CharGroup> {
    let inner = name.strip_prefix(b"[:")?.strip_suffix(b":]")?;
    let (sign, inner) = match inner.strip_prefix(b"^") {
        Some(rest) => (-1, rest),
        None => (1, inner),
    };
    let class = match inner {
        b"alnum" => ALNUM,
        b"alpha" => ALPHA,
        b"ascii" => ASCII,
        b"blank" => BLANK,
        b"cntrl" => CNTRL,
        b"digit" => DIGIT,
        b"graph" => GRAPH,
        b"lower" => LOWER,
        b"print" => PRINT,
        b"punct" => PUNCT,
        b"space" => POSIX_SPACE,
        b"upper" => UPPER,
        b"word" => WORD,
        b"xdigit" => XDIGIT,
        _ => return None,
    };
    Some(CharGroup { sign, class })
}
