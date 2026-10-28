//! The low-level JSON grammar helpers of Go's `encoding/json/internal/jsonwire`:
//! whitespace, literal, string and number scanning, quoting and unquoting,
//! number reformatting and the RFC 8785 string ordering.
use super::errors::{Error, InvalidTextError};
use super::flags::{self, Flags};
use crate::strconv;
use crate::unicode::rune;

/// `jsonwire.ValueFlags`: facts learned while scanning a string.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ValueFlags(u8);

const STRING_NON_VERBATIM: u8 = 1;
const STRING_NON_CANONICAL: u8 = 2;

impl ValueFlags {
    pub(crate) fn join(&mut self, bits: u8) {
        self.0 |= bits;
    }
    pub(crate) fn merge(&mut self, other: ValueFlags) {
        self.0 |= other.0;
    }
    /// Reports whether the string can be treated as valid UTF-8 verbatim.
    pub fn is_verbatim(self) -> bool {
        self.0 & STRING_NON_VERBATIM == 0
    }
    /// Reports whether the string is formatted per RFC 8785, section 3.2.2.2.
    pub fn is_canonical(self) -> bool {
        self.0 & STRING_NON_CANONICAL == 0
    }
}

pub(crate) const NON_VERBATIM: u8 = STRING_NON_VERBATIM;
pub(crate) const NON_CANONICAL: u8 = STRING_NON_CANONICAL;

pub(crate) fn trim_suffix_whitespace(b: &[u8]) -> &[u8] {
    let mut n = b.len();
    while n > 0 && matches!(b[n - 1], b' ' | b'\t' | b'\r' | b'\n') {
        n -= 1;
    }
    &b[..n]
}

pub(crate) fn trim_suffix_string(mut b: &[u8]) -> &[u8] {
    if b.last() == Some(&b'"') {
        b = &b[..b.len() - 1];
    }
    while b.len() >= 2 && !(b[b.len() - 1] == b'"' && b[b.len() - 2] != b'\\') {
        b = &b[..b.len() - 1];
    }
    if b.last() == Some(&b'"') {
        b = &b[..b.len() - 1];
    }
    b
}

pub(crate) fn trim_suffix_byte(b: &[u8], c: u8) -> &[u8] {
    if b.last() == Some(&c) {
        &b[..b.len() - 1]
    } else {
        b
    }
}

/// `jsonwire.QuoteRune`: quotes the first rune of `b` as Go does, including
/// the `'\xNN'` form for an invalid byte.
pub fn quote_rune(b: &[u8]) -> String {
    let (r, n) = rune::decode_rune(b);
    if r == rune::RUNE_ERROR && n == 1 {
        return format!("'\\x{:x}'", b[0]);
    }
    strconv::quote_rune(r)
}

fn cmp_u32(a: u32, b: u32) -> i32 {
    match a.cmp(&b) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

fn is_invalid_utf8(r: i32, rn: usize) -> bool {
    r == rune::RUNE_ERROR && rn == 1
}

/// `jsonwire.CompareUTF16`: compares two UTF-8 strings by their UTF-16 code
/// units, as RFC 8785 sorts object names.
pub fn compare_utf16(mut x: &[u8], mut y: &[u8]) -> i32 {
    let is_utf16_self = |r: i32| (0..=0xD7FF).contains(&r) || (0xE000..=0xFFFF).contains(&r);
    loop {
        if x.is_empty() || y.is_empty() {
            return cmp_u32(x.len() as u32, y.len() as u32);
        }
        if x[0] < 0x80 || y[0] < 0x80 {
            if x[0] != y[0] {
                return cmp_u32(x[0] as u32, y[0] as u32);
            }
            x = &x[1..];
            y = &y[1..];
            continue;
        }
        let (mut rx, nx) = rune::decode_rune(x);
        let (mut ry, ny) = rune::decode_rune(y);
        let selfx = is_utf16_self(rx);
        let selfy = is_utf16_self(ry);
        if selfx && !selfy {
            ry = rune::encode_surrogate_pair(ry).0;
        } else if selfy && !selfx {
            rx = rune::encode_surrogate_pair(rx).0;
        }
        if rx != ry {
            return cmp_u32(rx as u32, ry as u32);
        }
        if (is_invalid_utf8(rx, nx) || is_invalid_utf8(ry, ny)) && x[0] != y[0] {
            return cmp_u32(x[0] as u32, y[0] as u32);
        }
        x = &x[nx..];
        y = &y[ny..];
    }
}

/// `jsonwire.NewInvalidCharacterError`.
pub fn invalid_character_error(prefix: &[u8], place: &str) -> Error {
    let (_, n) = rune::decode_rune(prefix);
    Error::InvalidText(Box::new(InvalidTextError {
        label: "character".into(),
        what: prefix[..n.min(prefix.len())].to_vec(),
        place: place.into(),
    }))
}

/// `jsonwire.NewInvalidEscapeSequenceError`.
pub fn invalid_escape_sequence_error(what: &[u8]) -> Error {
    let label = if what.len() > 6 {
        "surrogate pair"
    } else {
        "escape sequence"
    };
    Error::InvalidText(Box::new(InvalidTextError {
        label: label.into(),
        what: what.to_vec(),
        place: "in string".into(),
    }))
}

/// `jsonwire.TruncatePointer`: shortens a long JSON Pointer for messages.
pub fn truncate_pointer(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_string();
    }
    let sb = s.as_bytes();
    let mut i = n / 2;
    let mut j = s.len() - n / 2;
    if let Some(k) = sb[..i].iter().rposition(|&c| c == b'/') {
        if k > 0 {
            i = k;
        }
    }
    if let Some(k) = sb[j..].iter().position(|&c| c == b'/') {
        j += k + 1;
    }
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    while j < s.len() && !s.is_char_boundary(j) {
        j += 1;
    }
    let mid = &s[i..j];
    let mut middle = match mid.matches('/').count() {
        0 => "…",
        1 => "…/…",
        _ => "…/…/…",
    };
    if mid.starts_with('/') && middle != "…" {
        middle = &middle["…".len()..];
    }
    let mut owned = middle.to_string();
    if mid.ends_with('/') && middle != "…" {
        owned.truncate(owned.len() - "…".len());
    }
    format!("{}{}{}", &s[..i], owned, &s[j..])
}

// ------------------------------------------------------------------ scanning

/// Number of leading JSON whitespace bytes.
pub fn consume_whitespace(b: &[u8]) -> usize {
    b.iter()
        .take_while(|&&c| matches!(c, b' ' | b'\t' | b'\r' | b'\n'))
        .count()
}

pub fn consume_null(b: &[u8]) -> usize {
    if b.starts_with(b"null") {
        4
    } else {
        0
    }
}
pub fn consume_false(b: &[u8]) -> usize {
    if b.starts_with(b"false") {
        5
    } else {
        0
    }
}
pub fn consume_true(b: &[u8]) -> usize {
    if b.starts_with(b"true") {
        4
    } else {
        0
    }
}

/// `jsonwire.ConsumeLiteral`.
pub fn consume_literal(b: &[u8], lit: &str) -> (usize, Option<Error>) {
    let l = lit.as_bytes();
    for i in 0..b.len().min(l.len()) {
        if b[i] != l[i] {
            return (
                i,
                Some(invalid_character_error(
                    &b[i..],
                    &format!(
                        "in literal {lit} (expecting {})",
                        strconv::quote_rune(l[i] as i32)
                    ),
                )),
            );
        }
    }
    if b.len() < l.len() {
        return (b.len(), Some(Error::UnexpectedEof));
    }
    (l.len(), None)
}

const fn escape_table() -> [u8; 128] {
    let mut t = [0u8; 128];
    let mut i = 0;
    while i < 0x20 {
        t[i] = 1;
        i += 1;
    }
    t[b'"' as usize] = 1;
    t[b'&' as usize] = 1;
    t[b'<' as usize] = 1;
    t[b'>' as usize] = 1;
    t[b'\\' as usize] = 1;
    t
}
static ESCAPE_ASCII: [u8; 128] = escape_table();

/// `jsonwire.ConsumeSimpleString`: the length of a string with no escapes
/// and no characters needing them, or 0.
pub fn consume_simple_string(b: &[u8]) -> usize {
    if !b.is_empty() && b[0] == b'"' {
        let mut n = 1;
        while b.len() > n && b[n] < 0x80 && ESCAPE_ASCII[b[n] as usize] == 0 {
            n += 1;
        }
        if b.len() > n && b[n] == b'"' {
            return n + 1;
        }
    }
    0
}

/// `jsonwire.ConsumeString`.
pub fn consume_string(
    flags: &mut ValueFlags,
    b: &[u8],
    validate_utf8: bool,
) -> (usize, Option<Error>) {
    consume_string_resumable(flags, b, 0, validate_utf8)
}

fn parse_hex_uint16(b: &[u8]) -> Option<u16> {
    if b.len() != 4 {
        return None;
    }
    let mut v: u16 = 0;
    for &c in b {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => 10 + c - b'a',
            b'A'..=b'F' => 10 + c - b'A',
            _ => return None,
        };
        v = v.wrapping_mul(16).wrapping_add(d as u16);
    }
    Some(v)
}

fn has_escaped_utf16_prefix(b: &[u8], lower_surrogate_half: bool) -> bool {
    for (i, &c) in b.iter().enumerate() {
        match i {
            0 if c != b'\\' => return false,
            1 if c != b'u' => return false,
            2 if lower_surrogate_half && c != b'd' && c != b'D' => return false,
            3 if lower_surrogate_half
                && !(b'c'..=b'f').contains(&c)
                && !(b'C'..=b'F').contains(&c) =>
            {
                return false
            }
            2..=5 if !c.is_ascii_hexdigit() => return false,
            _ => {}
        }
    }
    true
}

/// `jsonwire.ConsumeStringResumable`.
pub fn consume_string_resumable(
    flags: &mut ValueFlags,
    b: &[u8],
    mut resume_offset: usize,
    validate_utf8: bool,
) -> (usize, Option<Error>) {
    let mut n = 0usize;
    if resume_offset > 0 {
        n = resume_offset;
    } else if b.is_empty() {
        return (n, Some(Error::UnexpectedEof));
    } else if b[0] == b'"' {
        n += 1;
    } else {
        return (
            n,
            Some(invalid_character_error(
                &b[n..],
                "at start of string (expecting '\"')",
            )),
        );
    }
    let no_escape = |c: u8| (b' '..0x80).contains(&c) && c != b'\\' && c != b'"';
    while b.len() > n {
        while b.len() > n && no_escape(b[n]) {
            n += 1;
        }
        if b.len() <= n {
            return (n, Some(Error::UnexpectedEof));
        }
        if b[n] == b'"' {
            return (n + 1, None);
        }
        let (r, rn) = rune::decode_rune(&b[n..]);
        if rn > 1 {
            n += rn;
        } else if r == '\\' as i32 {
            flags.join(NON_VERBATIM);
            resume_offset = n;
            if b.len() < n + 2 {
                return (resume_offset, Some(Error::UnexpectedEof));
            }
            match b[n + 1] {
                b'/' => {
                    flags.join(NON_CANONICAL);
                    n += 2;
                }
                b'"' | b'\\' | b'b' | b'f' | b'n' | b'r' | b't' => n += 2,
                b'u' => {
                    if b.len() < n + 6 {
                        if has_escaped_utf16_prefix(&b[n..], false) {
                            return (resume_offset, Some(Error::UnexpectedEof));
                        }
                        flags.join(NON_CANONICAL);
                        return (n, Some(invalid_escape_sequence_error(&b[n..])));
                    }
                    let Some(v1) = parse_hex_uint16(&b[n + 2..n + 6]) else {
                        flags.join(NON_CANONICAL);
                        return (n, Some(invalid_escape_sequence_error(&b[n..n + 6])));
                    };
                    match v1 {
                        0x08 | 0x0c | 0x0a | 0x0d | 0x09 => flags.join(NON_CANONICAL),
                        _ => {
                            if v1 >= b' ' as u16
                                || b[n + 2..n + 6].iter().any(|c| (b'A'..=b'F').contains(c))
                            {
                                flags.join(NON_CANONICAL);
                            }
                        }
                    }
                    n += 6;
                    let r = v1 as i32;
                    if validate_utf8 && rune::is_surrogate(r) {
                        if b.len() < n + 6 {
                            if has_escaped_utf16_prefix(&b[n..], true) {
                                return (resume_offset, Some(Error::UnexpectedEof));
                            }
                            flags.join(NON_CANONICAL);
                            return (n - 6, Some(invalid_escape_sequence_error(&b[n - 6..])));
                        }
                        let v2 = parse_hex_uint16(&b[n + 2..n + 6]);
                        match v2 {
                            Some(v2) if b[n] == b'\\' && b[n + 1] == b'u' => {
                                if rune::decode_surrogate_pair(r, v2 as i32) == rune::RUNE_ERROR {
                                    flags.join(NON_CANONICAL);
                                    return (
                                        n - 6,
                                        Some(invalid_escape_sequence_error(&b[n - 6..n + 6])),
                                    );
                                }
                                n += 6;
                            }
                            _ => {
                                flags.join(NON_CANONICAL);
                                return (
                                    n - 6,
                                    Some(invalid_escape_sequence_error(&b[n - 6..n + 6])),
                                );
                            }
                        }
                    }
                }
                _ => {
                    flags.join(NON_CANONICAL);
                    return (n, Some(invalid_escape_sequence_error(&b[n..n + 2])));
                }
            }
        } else if r == rune::RUNE_ERROR {
            if !rune::full_rune(&b[n..]) {
                return (n, Some(Error::UnexpectedEof));
            }
            flags.join(NON_VERBATIM | NON_CANONICAL);
            if validate_utf8 {
                return (n, Some(Error::InvalidUtf8));
            }
            n += 1;
        } else if r < ' ' as i32 {
            flags.join(NON_VERBATIM | NON_CANONICAL);
            return (
                n,
                Some(invalid_character_error(
                    &b[n..],
                    "in string (expecting non-control character)",
                )),
            );
        } else {
            unreachable!("jsonwire: unhandled character in string");
        }
    }
    (n, Some(Error::UnexpectedEof))
}

/// `jsonwire.AppendUnquote`: appends the decoded string to `dst`. Invalid
/// UTF-8 and bad escapes are replaced with U+FFFD and reported.
pub fn append_unquote(dst: &mut Vec<u8>, src: &[u8]) -> Option<Error> {
    let mut err: Option<Error> = None;
    let (mut i, mut n);
    if src.is_empty() {
        return Some(Error::UnexpectedEof);
    } else if src[0] == b'"' {
        i = 1;
        n = 1;
    } else {
        return Some(invalid_character_error(
            src,
            "at start of string (expecting '\"')",
        ));
    }
    let no_escape = |c: u8| (b' '..0x80).contains(&c) && c != b'\\' && c != b'"';
    while src.len() > n {
        while src.len() > n && no_escape(src[n]) {
            n += 1;
        }
        if src.len() <= n {
            dst.extend_from_slice(&src[i..n]);
            return Some(Error::UnexpectedEof);
        }
        if src[n] == b'"' {
            dst.extend_from_slice(&src[i..n]);
            n += 1;
            if n < src.len() {
                err = Some(invalid_character_error(&src[n..], "after string value"));
            }
            return err;
        }
        let (r, rn) = rune::decode_rune(&src[n..]);
        if rn > 1 {
            n += rn;
        } else if r == '\\' as i32 {
            dst.extend_from_slice(&src[i..n]);
            if src.len() < n + 2 {
                return Some(Error::UnexpectedEof);
            }
            match src[n + 1] {
                c @ (b'"' | b'\\' | b'/') => {
                    dst.push(c);
                    n += 2;
                }
                b'b' => {
                    dst.push(8);
                    n += 2;
                }
                b'f' => {
                    dst.push(12);
                    n += 2;
                }
                b'n' => {
                    dst.push(b'\n');
                    n += 2;
                }
                b'r' => {
                    dst.push(b'\r');
                    n += 2;
                }
                b't' => {
                    dst.push(b'\t');
                    n += 2;
                }
                b'u' => {
                    if src.len() < n + 6 {
                        if has_escaped_utf16_prefix(&src[n..], false) {
                            return Some(Error::UnexpectedEof);
                        }
                        return Some(invalid_escape_sequence_error(&src[n..]));
                    }
                    let Some(v1) = parse_hex_uint16(&src[n + 2..n + 6]) else {
                        return Some(invalid_escape_sequence_error(&src[n..n + 6]));
                    };
                    n += 6;
                    let mut r = v1 as i32;
                    if rune::is_surrogate(r) {
                        r = rune::RUNE_ERROR;
                        if src.len() < n + 6 {
                            if has_escaped_utf16_prefix(&src[n..], true) {
                                rune::append_rune(dst, r);
                                return Some(Error::UnexpectedEof);
                            }
                            err = Some(invalid_escape_sequence_error(&src[n - 6..]));
                        } else {
                            match parse_hex_uint16(&src[n + 2..n + 6]) {
                                Some(v2) if src[n] == b'\\' && src[n + 1] == b'u' => {
                                    r = rune::decode_surrogate_pair(v1 as i32, v2 as i32);
                                    if r == rune::RUNE_ERROR {
                                        err =
                                            Some(invalid_escape_sequence_error(&src[n - 6..n + 6]));
                                    } else {
                                        n += 6;
                                    }
                                }
                                _ => {
                                    err = Some(invalid_escape_sequence_error(&src[n - 6..n + 6]));
                                }
                            }
                        }
                    }
                    rune::append_rune(dst, r);
                }
                _ => return Some(invalid_escape_sequence_error(&src[n..n + 2])),
            }
            i = n;
        } else if r == rune::RUNE_ERROR {
            dst.extend_from_slice(&src[i..n]);
            if !rune::full_rune(&src[n..]) {
                return Some(Error::UnexpectedEof);
            }
            dst.extend_from_slice("\u{fffd}".as_bytes());
            n += rn;
            i = n;
            err = Some(Error::InvalidUtf8);
        } else if r < ' ' as i32 {
            dst.extend_from_slice(&src[i..n]);
            return Some(invalid_character_error(
                &src[n..],
                "in string (expecting non-control character)",
            ));
        } else {
            unreachable!("jsonwire: unhandled character in string");
        }
    }
    dst.extend_from_slice(&src[i..n]);
    Some(Error::UnexpectedEof)
}

/// `jsonwire.UnquoteMayCopy`.
pub fn unquote_may_copy(b: &[u8], is_verbatim: bool) -> Vec<u8> {
    if is_verbatim {
        return b[1..b.len() - 1].to_vec();
    }
    let mut out = Vec::new();
    let _ = append_unquote(&mut out, b);
    out
}

/// `jsonwire.ConsumeSimpleNumber`: a number without fraction or exponent
/// that is followed by a byte ending it (or the end of input... which the
/// caller must treat as inconclusive), or 0.
pub fn consume_simple_number(b: &[u8]) -> usize {
    if !b.is_empty() {
        let mut n = 0;
        if b[0] == b'0' {
            n += 1;
        } else if (b'1'..=b'9').contains(&b[0]) {
            n += 1;
            while b.len() > n && b[n].is_ascii_digit() {
                n += 1;
            }
        } else {
            return 0;
        }
        if b.len() <= n || (b[n] != b'.' && b[n] != b'e' && b[n] != b'E') {
            return n;
        }
    }
    0
}

/// `jsonwire.ConsumeNumberState`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NumberState {
    Init = 0,
    BeforeIntegerDigits,
    WithinIntegerDigits,
    BeforeFractionalDigits,
    WithinFractionalDigits,
    BeforeExponentDigits,
    WithinExponentDigits,
}

impl NumberState {
    fn next(self) -> NumberState {
        match self {
            NumberState::Init => NumberState::BeforeIntegerDigits,
            NumberState::BeforeIntegerDigits => NumberState::WithinIntegerDigits,
            NumberState::WithinIntegerDigits => NumberState::BeforeFractionalDigits,
            NumberState::BeforeFractionalDigits => NumberState::WithinFractionalDigits,
            NumberState::WithinFractionalDigits => NumberState::BeforeExponentDigits,
            NumberState::BeforeExponentDigits => NumberState::WithinExponentDigits,
            NumberState::WithinExponentDigits => NumberState::WithinExponentDigits,
        }
    }
}

/// `jsonwire.ConsumeNumber`.
pub fn consume_number(b: &[u8]) -> (usize, Option<Error>) {
    let (n, _, err) = consume_number_resumable(b, 0, NumberState::Init);
    (n, err)
}

/// `jsonwire.ConsumeNumberResumable`.
pub fn consume_number_resumable(
    b: &[u8],
    start: usize,
    mut state: NumberState,
) -> (usize, NumberState, Option<Error>) {
    use NumberState::*;
    let mut n = start;
    let mut resume_offset: usize;
    let digit = |b: &[u8], n: usize| b.len() > n && b[n].is_ascii_digit();
    // Entry point selection: which labelled section to continue from.
    #[derive(PartialEq)]
    enum At {
        Integer,
        Fractional,
        Exponent,
    }
    let mut at = At::Integer;
    if state > Init {
        if matches!(
            state,
            WithinIntegerDigits | WithinFractionalDigits | WithinExponentDigits
        ) {
            while digit(b, n) {
                n += 1;
            }
            if b.len() <= n {
                return (n, state, None);
            }
            state = state.next();
        }
        at = match state {
            BeforeIntegerDigits => At::Integer,
            BeforeFractionalDigits => At::Fractional,
            BeforeExponentDigits => At::Exponent,
            _ => return (n, state, None),
        };
    }
    if at == At::Integer {
        resume_offset = n;
        if !b.is_empty() && b[0] == b'-' {
            n += 1;
        }
        if b.len() <= n {
            return (
                resume_offset,
                BeforeIntegerDigits,
                Some(Error::UnexpectedEof),
            );
        } else if b[n] == b'0' {
            n += 1;
            state = BeforeFractionalDigits;
        } else if (b'1'..=b'9').contains(&b[n]) {
            n += 1;
            while digit(b, n) {
                n += 1;
            }
            state = WithinIntegerDigits;
        } else {
            return (
                n,
                state,
                Some(invalid_character_error(
                    &b[n..],
                    "in number (expecting digit)",
                )),
            );
        }
        at = At::Fractional;
    }
    if at == At::Fractional {
        if b.len() > n && b[n] == b'.' {
            resume_offset = n;
            n += 1;
            if b.len() <= n {
                return (
                    resume_offset,
                    BeforeFractionalDigits,
                    Some(Error::UnexpectedEof),
                );
            } else if b[n].is_ascii_digit() {
                n += 1;
            } else {
                return (
                    n,
                    state,
                    Some(invalid_character_error(
                        &b[n..],
                        "in number (expecting digit)",
                    )),
                );
            }
            while digit(b, n) {
                n += 1;
            }
            state = WithinFractionalDigits;
        }
        at = At::Exponent;
    }
    if at == At::Exponent && b.len() > n && (b[n] == b'e' || b[n] == b'E') {
        resume_offset = n;
        n += 1;
        if b.len() > n && (b[n] == b'-' || b[n] == b'+') {
            n += 1;
        }
        if b.len() <= n {
            return (
                resume_offset,
                BeforeExponentDigits,
                Some(Error::UnexpectedEof),
            );
        } else if b[n].is_ascii_digit() {
            n += 1;
        } else {
            return (
                n,
                state,
                Some(invalid_character_error(
                    &b[n..],
                    "in number (expecting digit)",
                )),
            );
        }
        while digit(b, n) {
            n += 1;
        }
        state = WithinExponentDigits;
    }
    (n, state, None)
}

/// `jsonwire.ParseUint`: strict decimal parsing of a JSON integer. When the
/// value overflows the result is `(u64::MAX, false)`.
pub fn parse_uint(b: &[u8]) -> (u64, bool) {
    const UNSAFE_WIDTH: usize = 20;
    let mut v: u64 = 0;
    let mut n = 0;
    while b.len() > n && b[n].is_ascii_digit() {
        v = v.wrapping_mul(10).wrapping_add((b[n] - b'0') as u64);
        n += 1;
    }
    if n == 0 || b.len() != n || (b[0] == b'0' && b != b"0") {
        return (0, false);
    }
    if n >= UNSAFE_WIDTH && (b[0] != b'1' || v < 10_000_000_000_000_000_000 || n > UNSAFE_WIDTH) {
        return (u64::MAX, false);
    }
    (v, true)
}

// ------------------------------------------------------------------ quoting

/// `jsonwire.NeedEscape`.
pub fn need_escape(src: &[u8]) -> bool {
    let mut i = 0;
    while i < src.len() {
        let c = src[i];
        if c < 0x80 {
            if ESCAPE_ASCII[c as usize] > 0 {
                return true;
            }
            i += 1;
        } else {
            let (r, rn) = rune::decode_rune(&src[i..]);
            if r == rune::RUNE_ERROR || r == 0x2028 || r == 0x2029 {
                return true;
            }
            i += rn;
        }
    }
    false
}

fn append_escaped_utf16(dst: &mut Vec<u8>, x: u16) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    dst.extend_from_slice(&[
        b'\\',
        b'u',
        HEX[((x >> 12) & 0xf) as usize],
        HEX[((x >> 8) & 0xf) as usize],
        HEX[((x >> 4) & 0xf) as usize],
        HEX[(x & 0xf) as usize],
    ]);
}

fn append_escaped_ascii(dst: &mut Vec<u8>, c: u8) {
    match c {
        b'"' | b'\\' => dst.extend_from_slice(&[b'\\', c]),
        8 => dst.extend_from_slice(b"\\b"),
        12 => dst.extend_from_slice(b"\\f"),
        b'\n' => dst.extend_from_slice(b"\\n"),
        b'\r' => dst.extend_from_slice(b"\\r"),
        b'\t' => dst.extend_from_slice(b"\\t"),
        _ => append_escaped_utf16(dst, c as u16),
    }
}

fn append_escaped_unicode(dst: &mut Vec<u8>, r: i32) {
    let (r1, r2) = rune::encode_surrogate_pair(r);
    if r1 != 0xFFFD && r2 != 0xFFFD {
        append_escaped_utf16(dst, r1 as u16);
        append_escaped_utf16(dst, r2 as u16);
    } else {
        append_escaped_utf16(dst, r as u16);
    }
}

/// `jsonwire.AppendQuote`: appends `src` as a JSON string. Invalid UTF-8 is
/// replaced with U+FFFD and reported unless `AllowInvalidUTF8` is set.
pub fn append_quote(dst: &mut Vec<u8>, src: &[u8], f: &Flags) -> Option<Error> {
    let mut i = 0;
    let mut n = 0;
    let mut has_invalid = false;
    dst.reserve(src.len() + 2);
    dst.push(b'"');
    while src.len() > n {
        let c = src[n];
        if c < 0x80 {
            n += 1;
            if ESCAPE_ASCII[c as usize] == 0 {
                continue;
            }
            if !(c == b'<' || c == b'>' || c == b'&') || f.get(flags::ESCAPE_FOR_HTML) {
                dst.extend_from_slice(&src[i..n - 1]);
                append_escaped_ascii(dst, c);
                i = n;
            }
        } else {
            let (r, rn) = rune::decode_rune(&src[n..]);
            n += rn;
            if r != rune::RUNE_ERROR && r != 0x2028 && r != 0x2029 {
                continue;
            }
            if is_invalid_utf8(r, rn) {
                has_invalid = true;
                dst.extend_from_slice(&src[i..n - rn]);
                dst.extend_from_slice("\u{fffd}".as_bytes());
                i = n;
            } else if (r == 0x2028 || r == 0x2029) && f.get(flags::ESCAPE_FOR_JS) {
                dst.extend_from_slice(&src[i..n - rn]);
                append_escaped_unicode(dst, r);
                i = n;
            }
        }
    }
    dst.extend_from_slice(&src[i..n]);
    dst.push(b'"');
    if has_invalid && !f.get(flags::ALLOW_INVALID_UTF8) {
        return Some(Error::InvalidUtf8);
    }
    None
}

/// `jsonwire.ReformatString`: validates the string at the start of `src` and
/// appends it to `dst`, escaped as the flags require.
pub fn reformat_string(dst: &mut Vec<u8>, src: &[u8], f: &Flags) -> (usize, Option<Error>) {
    let mut vf = ValueFlags::default();
    let (n, err) = consume_string(&mut vf, src, !f.get(flags::ALLOW_INVALID_UTF8));
    if err.is_some() {
        return (n, err);
    }
    if !f.get(flags::ANY_ESCAPE) && (vf.is_canonical() || f.get(flags::PRESERVE_RAW_STRINGS)) {
        dst.extend_from_slice(&src[..n]);
        return (n, None);
    }
    if f.get(flags::PRESERVE_RAW_STRINGS) {
        let (mut i, mut last) = (0, 0);
        while i < n {
            let c = src[i];
            if c < 0x80 {
                if (c == b'<' || c == b'>' || c == b'&') && f.get(flags::ESCAPE_FOR_HTML) {
                    dst.extend_from_slice(&src[last..i]);
                    append_escaped_ascii(dst, c);
                    last = i + 1;
                }
                i += 1;
            } else {
                let (r, rn) = rune::decode_rune(&src[i..]);
                if (r == 0x2028 || r == 0x2029) && f.get(flags::ESCAPE_FOR_JS) {
                    dst.extend_from_slice(&src[last..i]);
                    append_escaped_unicode(dst, r);
                    last = i + rn;
                }
                i += rn;
            }
        }
        dst.extend_from_slice(&src[last..n]);
        return (n, None);
    }
    let mut b = Vec::new();
    let _ = append_unquote(&mut b, &src[..n]);
    let _ = append_quote(dst, &b, f);
    (n, None)
}

/// `jsonwire.AppendFloat`: formats `src` as an ECMAScript-compatible JSON
/// number (RFC 8785, section 3.2.2.3).
pub fn append_float(dst: &mut Vec<u8>, mut src: f64, bits: i32) {
    if bits == 32 {
        src = src as f32 as f64;
    }
    let abs = src.abs();
    let mut fmt = b'f';
    if abs != 0.0
        && ((bits == 64 && (abs < 1e-6 || abs >= 1e21))
            || (bits == 32 && ((abs as f32) < 1e-6 || (abs as f32) >= 1e21)))
    {
        fmt = b'e';
    }
    strconv::append_float(dst, src, fmt, -1, bits);
    if fmt == b'e' {
        let n = dst.len();
        if n >= 4 && dst[n - 4] == b'e' && dst[n - 3] == b'-' && dst[n - 2] == b'0' {
            dst[n - 2] = dst[n - 1];
            dst.truncate(n - 1);
        }
    }
}

/// `jsonwire.ReformatNumber`.
pub fn reformat_number(dst: &mut Vec<u8>, src: &[u8], f: &Flags) -> (usize, Option<Error>) {
    let (n, err) = consume_number(src);
    if err.is_some() {
        return (n, err);
    }
    if !f.get(flags::CANONICALIZE_NUMBERS) {
        dst.extend_from_slice(&src[..n]);
        return (n, None);
    }
    let is_float = src[..n]
        .iter()
        .any(|&c| c == b'.' || c == b'e' || c == b'E');
    if &src[..n] == b"-0" {
        // canonicalize -0 as 0 regardless of kind
    } else if is_float {
        if !f.get(flags::CANONICALIZE_RAW_FLOATS) {
            dst.extend_from_slice(&src[..n]);
            return (n, None);
        }
    } else {
        const MAX_EXACT_INTEGER_DIGITS: usize = 16;
        if !f.get(flags::CANONICALIZE_RAW_INTS) || n < MAX_EXACT_INTEGER_DIGITS {
            dst.extend_from_slice(&src[..n]);
            return (n, None);
        }
    }
    let text = std::str::from_utf8(&src[..n]).unwrap_or("0");
    let mut fv = strconv::parse_float(text, 64).unwrap_or_else(|e| e.float_value());
    if fv == 0.0 {
        fv = 0.0;
    } else if fv == f64::INFINITY {
        fv = f64::MAX;
    } else if fv == f64::NEG_INFINITY {
        fv = -f64::MAX;
    }
    append_float(dst, fv, 64);
    (n, None)
}

/// Converts bytes to a `String` replacing each invalid byte with U+FFFD, as
/// converting a Go string to runes and back does.
pub fn lossy_string(b: &[u8]) -> String {
    let mut out = Vec::with_capacity(b.len());
    let mut rest = b;
    while !rest.is_empty() {
        let (r, n) = rune::decode_rune(rest);
        if r == rune::RUNE_ERROR && n == 1 {
            out.extend_from_slice("\u{fffd}".as_bytes());
        } else {
            out.extend_from_slice(&rest[..n]);
        }
        rest = &rest[n..];
    }
    String::from_utf8(out).expect("every invalid byte was replaced")
}
