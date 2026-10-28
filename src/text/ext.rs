//! Go's `strings` and `bytes` functions that Rust's std does not provide.
//!
//! Go strings are byte strings that are *usually* UTF-8, so one extension
//! trait on `[u8]` serves both packages: call it on `s.as_bytes()` for a
//! `&str`. Everything here follows Go exactly where it is observable: an
//! invalid byte decodes as `U+FFFD` of width 1, an empty separator splits
//! between runes, and the case functions use Go's simple one-rune mappings
//! from [`crate::unicode`], not Rust's full `char::to_uppercase`.
//!
//! What std already does is not repeated here: `str::contains`, `str::find`,
//! `str::split_once`, `str::strip_prefix`, `str::trim_matches`,
//! `str::split_whitespace`, `<[T]>::starts_with`, `<[T]>::join`, `==`/`Ord`.
//!
//! Conventions: Go's `-1` index is `Option<usize>`; callbacks take `char`
//! (invalid input is passed as `U+FFFD`); cutsets and character sets are byte
//! slices so they may carry invalid UTF-8 as Go strings do.

use crate::unicode::chars::{self as case, decode_last_rune, decode_rune, rune_count, RUNE_ERROR};
use crate::unicode::SpecialCase;

/// Returns the index of the first `c` in `b` (`bytes.IndexByte`).
fn index_byte(b: &[u8], c: u8) -> Option<usize> {
    b.iter().position(|&x| x == c)
}

/// Returns the index of the last `c` in `b` (`bytes.LastIndexByte`).
fn last_index_byte(b: &[u8], c: u8) -> Option<usize> {
    b.iter().rposition(|&x| x == c)
}

const PRIME_RK: u32 = 16_777_619;

fn rk_hash(sep: &[u8]) -> (u32, u32) {
    let hash = sep.iter().fold(0u32, |h, &b| {
        h.wrapping_mul(PRIME_RK).wrapping_add(u32::from(b))
    });
    let (mut pow, mut sq) = (1u32, PRIME_RK);
    let mut i = sep.len();
    while i > 0 {
        if i & 1 != 0 {
            pow = pow.wrapping_mul(sq);
        }
        sq = sq.wrapping_mul(sq);
        i >>= 1;
    }
    (hash, pow)
}

fn index_rabin_karp(s: &[u8], sep: &[u8]) -> Option<usize> {
    let (hash, pow) = rk_hash(sep);
    let n = sep.len();
    let mut h = 0u32;
    for &b in &s[..n] {
        h = h.wrapping_mul(PRIME_RK).wrapping_add(u32::from(b));
    }
    if h == hash && &s[..n] == sep {
        return Some(0);
    }
    for i in n..s.len() {
        h = h.wrapping_mul(PRIME_RK).wrapping_add(u32::from(s[i]));
        h = h.wrapping_sub(pow.wrapping_mul(u32::from(s[i - n])));
        if h == hash && &s[i + 1 - n..=i] == sep {
            return Some(i + 1 - n);
        }
    }
    None
}

fn last_index_rabin_karp(s: &[u8], sep: &[u8]) -> Option<usize> {
    let n = sep.len();
    let rev: Vec<u8> = sep.iter().rev().copied().collect();
    let (hash, pow) = rk_hash(&rev);
    let mut last = s.len() - n;
    let mut h = 0u32;
    for i in (last..s.len()).rev() {
        h = h.wrapping_mul(PRIME_RK).wrapping_add(u32::from(s[i]));
    }
    if h == hash && &s[last..] == sep {
        return Some(last);
    }
    while last > 0 {
        last -= 1;
        h = h.wrapping_mul(PRIME_RK).wrapping_add(u32::from(s[last]));
        h = h.wrapping_sub(pow.wrapping_mul(u32::from(s[last + n])));
        if h == hash && &s[last..last + n] == sep {
            return Some(last);
        }
    }
    None
}

/// Returns the index of the first instance of `sep` in `s` (`bytes.Index`).
/// An empty `sep` is found at 0.
fn index(s: &[u8], sep: &[u8]) -> Option<usize> {
    let n = sep.len();
    if n == 0 {
        return Some(0);
    }
    if n == 1 {
        return index_byte(s, sep[0]);
    }
    if n > s.len() {
        return None;
    }
    if n == s.len() {
        return (s == sep).then_some(0);
    }
    let t = s.len() - n + 1;
    let mut i = 0;
    let mut fails = 0;
    while i < t {
        i += index_byte(&s[i..t], sep[0])?;
        if s[i + 1] == sep[1] && &s[i..i + n] == sep {
            return Some(i);
        }
        i += 1;
        fails += 1;
        if fails >= 4 + (i >> 4) && i < t {
            return index_rabin_karp(&s[i..], sep).map(|j| i + j);
        }
    }
    None
}

/// Returns the index of the last instance of `sep` in `s` (`bytes.LastIndex`).
/// An empty `sep` is found at `s.len()`.
fn last_index(s: &[u8], sep: &[u8]) -> Option<usize> {
    let n = sep.len();
    if n == 0 {
        return Some(s.len());
    }
    if n == 1 {
        return last_index_byte(s, sep[0]);
    }
    if n > s.len() {
        return None;
    }
    if n == s.len() {
        return (s == sep).then_some(0);
    }
    last_index_rabin_karp(s, sep)
}

/// Counts non-overlapping instances of `sep` (`bytes.Count`). An empty `sep`
/// counts the runes of `s` plus one.
fn count(s: &[u8], sep: &[u8]) -> usize {
    if sep.is_empty() {
        return rune_count(s) + 1;
    }
    if sep.len() == 1 {
        return s.iter().filter(|&&b| b == sep[0]).count();
    }
    let (mut n, mut s) = (0, s);
    while let Some(i) = index(s, sep) {
        n += 1;
        s = &s[i + sep.len()..];
    }
    n
}

/// Returns the index of the first occurrence of the rune `r` (`bytes.IndexRune`).
/// `U+FFFD` matches the first invalid byte or literal `U+FFFD`.
fn index_rune(s: &[u8], r: char) -> Option<usize> {
    if r == RUNE_ERROR {
        let mut i = 0;
        while i < s.len() {
            let (c, n) = decode_rune(&s[i..]);
            if c == RUNE_ERROR {
                return Some(i);
            }
            i += n;
        }
        return None;
    }
    let mut buf = [0u8; 4];
    index(s, r.encode_utf8(&mut buf).as_bytes())
}

/// Returns the index of the first rune of `s` that is in `chars`
/// (`bytes.IndexAny`). Invalid bytes in either argument are `U+FFFD`.
fn index_any(s: &[u8], chars: &[u8]) -> Option<usize> {
    if chars.is_empty() {
        return None;
    }
    let mut i = 0;
    while i < s.len() {
        let (r, w) = decode_rune(&s[i..]);
        if set_contains(chars, r) {
            return Some(i);
        }
        i += w;
    }
    None
}

/// Returns the index of the last rune of `s` that is in `chars`
/// (`bytes.LastIndexAny`).
fn last_index_any(s: &[u8], chars: &[u8]) -> Option<usize> {
    if chars.is_empty() {
        return None;
    }
    let mut i = s.len();
    while i > 0 {
        let (r, size) = decode_last_rune(&s[..i]);
        i -= size;
        if set_contains(chars, r) {
            return Some(i);
        }
    }
    None
}

/// Returns the index of the first rune satisfying `f` (`bytes.IndexFunc`).
fn index_func(s: &[u8], f: impl FnMut(char) -> bool) -> Option<usize> {
    index_func_truth(s, f, true)
}

/// Returns the index of the last rune satisfying `f` (`bytes.LastIndexFunc`).
fn last_index_func(s: &[u8], f: impl FnMut(char) -> bool) -> Option<usize> {
    last_index_func_truth(s, f, true)
}

fn index_func_truth(s: &[u8], mut f: impl FnMut(char) -> bool, truth: bool) -> Option<usize> {
    let mut start = 0;
    while start < s.len() {
        let (r, wid) = decode_rune(&s[start..]);
        if f(r) == truth {
            return Some(start);
        }
        start += wid;
    }
    None
}

fn last_index_func_truth(s: &[u8], mut f: impl FnMut(char) -> bool, truth: bool) -> Option<usize> {
    let mut i = s.len();
    while i > 0 {
        let (r, size) = decode_last_rune(&s[..i]);
        i -= size;
        if f(r) == truth {
            return Some(i);
        }
    }
    None
}

fn explode(mut s: &[u8], n: isize) -> Vec<&[u8]> {
    let n = if n <= 0 || n as usize > s.len() {
        s.len()
    } else {
        n as usize
    };
    let mut a = Vec::with_capacity(n);
    while !s.is_empty() {
        if a.len() + 1 >= n {
            a.push(s);
            break;
        }
        let size = decode_rune(s).1;
        a.push(&s[..size]);
        s = &s[size..];
    }
    a
}

fn gen_split<'a>(mut s: &'a [u8], sep: &[u8], sep_save: usize, n: isize) -> Vec<&'a [u8]> {
    if n == 0 {
        return Vec::new();
    }
    if sep.is_empty() {
        return explode(s, n);
    }
    let n = if n < 0 { count(s, sep) + 1 } else { n as usize };
    let n = n.min(s.len() + 1);
    let mut a = Vec::with_capacity(n);
    while a.len() + 1 < n {
        let Some(m) = index(s, sep) else { break };
        a.push(&s[..m + sep_save]);
        s = &s[m + sep.len()..];
    }
    a.push(s);
    a
}

/// Splits `s` around `sep` into at most `n` pieces (`bytes.SplitN`); `n < 0`
/// means all, `n == 0` yields nothing. An empty `sep` splits into runes.
fn split_n<'a>(s: &'a [u8], sep: &[u8], n: isize) -> Vec<&'a [u8]> {
    gen_split(s, sep, 0, n)
}

/// Like [`split_n`] but keeps the separator in each piece (`bytes.SplitAfterN`).
fn split_after_n<'a>(s: &'a [u8], sep: &[u8], n: isize) -> Vec<&'a [u8]> {
    gen_split(s, sep, sep.len(), n)
}

/// Iterator form of [`fields`] (`bytes.FieldsSeq`).
fn fields_seq(s: &[u8]) -> impl Iterator<Item = &[u8]> {
    fields_func_seq(s, case::is_space)
}

/// Iterator form of [`fields_func`] (`bytes.FieldsFuncSeq`).
fn fields_func_seq(s: &[u8], mut f: impl FnMut(char) -> bool) -> impl Iterator<Item = &[u8]> {
    let mut i = 0;
    std::iter::from_fn(move || {
        while i < s.len() {
            let (r, size) = decode_rune(&s[i..]);
            if f(r) {
                i += size;
            } else {
                break;
            }
        }
        if i >= s.len() {
            return None;
        }
        let start = i;
        while i < s.len() {
            let (r, size) = decode_rune(&s[i..]);
            if f(r) {
                break;
            }
            i += size;
        }
        Some(&s[start..i])
    })
}

fn split_seq_impl<'a>(
    mut s: &'a [u8],
    sep: &'a [u8],
    sep_save: usize,
) -> impl Iterator<Item = &'a [u8]> {
    let mut done = false;
    std::iter::from_fn(move || {
        if sep.is_empty() {
            if s.is_empty() {
                return None;
            }
            let size = decode_rune(s).1;
            let (head, tail) = s.split_at(size);
            s = tail;
            return Some(head);
        }
        if done {
            return None;
        }
        match index(s, sep) {
            Some(i) => {
                let frag = &s[..i + sep_save];
                s = &s[i + sep.len()..];
                Some(frag)
            }
            None => {
                done = true;
                Some(s)
            }
        }
    })
}

/// Iterator form of [`split`] (`bytes.SplitSeq`).
fn split_seq<'a>(s: &'a [u8], sep: &'a [u8]) -> impl Iterator<Item = &'a [u8]> {
    split_seq_impl(s, sep, 0)
}

/// Iterator form of [`split_after`] (`bytes.SplitAfterSeq`).
fn split_after_seq<'a>(s: &'a [u8], sep: &'a [u8]) -> impl Iterator<Item = &'a [u8]> {
    split_seq_impl(s, sep, sep.len())
}

/// Iterates over newline-terminated lines, keeping the terminator
/// (`bytes.Lines`).
fn lines(mut s: &[u8]) -> impl Iterator<Item = &[u8]> {
    std::iter::from_fn(move || {
        if s.is_empty() {
            return None;
        }
        let end = index_byte(s, b'\n').map_or(s.len(), |i| i + 1);
        let (line, rest) = s.split_at(end);
        s = rest;
        Some(line)
    })
}

/// Returns a copy of `s` with each rune mapped by `mapping`; `None` drops the
/// rune (`bytes.Map`). Invalid bytes are passed as `U+FFFD` and a mapped
/// `U+FFFD` is written as its three-byte encoding.
fn map(mut mapping: impl FnMut(char) -> Option<char>, s: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let (r, wid) = decode_rune(&s[i..]);
        if let Some(m) = mapping(r) {
            let mut buf = [0u8; 4];
            b.extend_from_slice(m.encode_utf8(&mut buf).as_bytes());
        }
        i += wid;
    }
    b
}

/// Upper-cases `s` (`bytes.ToUpper`).
fn to_upper(s: &[u8]) -> Vec<u8> {
    map(|r| Some(case::to_upper(r)), s)
}

/// Lower-cases `s` (`bytes.ToLower`).
fn to_lower(s: &[u8]) -> Vec<u8> {
    map(|r| Some(case::to_lower(r)), s)
}

/// Title-cases every rune of `s` (`bytes.ToTitle`).
fn to_title(s: &[u8]) -> Vec<u8> {
    map(|r| Some(case::to_title(r)), s)
}

/// Upper-cases `s` with `c` taking precedence (`bytes.ToUpperSpecial`).
fn to_upper_special(c: SpecialCase<'_>, s: &[u8]) -> Vec<u8> {
    map(|r| Some(case::special_upper(c, r)), s)
}

/// Lower-cases `s` with `c` taking precedence (`bytes.ToLowerSpecial`).
fn to_lower_special(c: SpecialCase<'_>, s: &[u8]) -> Vec<u8> {
    map(|r| Some(case::special_lower(c, r)), s)
}

/// Title-cases `s` with `c` taking precedence (`bytes.ToTitleSpecial`).
fn to_title_special(c: SpecialCase<'_>, s: &[u8]) -> Vec<u8> {
    map(|r| Some(case::special_title(c, r)), s)
}

/// Replaces each run of invalid UTF-8 bytes with `replacement`
/// (`bytes.ToValidUTF8`).
fn to_valid_utf8(s: &[u8], replacement: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(s.len() + replacement.len());
    let mut invalid = false;
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if c < 0x80 {
            i += 1;
            invalid = false;
            b.push(c);
            continue;
        }
        let (_, wid) = decode_rune(&s[i..]);
        if wid == 1 {
            i += 1;
            if !invalid {
                invalid = true;
                b.extend_from_slice(replacement);
            }
            continue;
        }
        invalid = false;
        b.extend_from_slice(&s[i..i + wid]);
        i += wid;
    }
    b
}

/// Title-cases the first letter of each word (`bytes.Title`, deprecated).
fn title(s: &[u8]) -> Vec<u8> {
    let mut prev = ' ';
    map(
        |r| {
            let out = if case::is_separator(prev) {
                case::to_title(r)
            } else {
                r
            };
            prev = r;
            Some(out)
        },
        s,
    )
}

/// Returns the runes of `s`, invalid bytes as `U+FFFD` (`bytes.Runes`).
fn runes(mut s: &[u8]) -> Vec<char> {
    let mut t = Vec::with_capacity(s.len());
    while !s.is_empty() {
        let (r, l) = decode_rune(s);
        t.push(r);
        s = &s[l..];
    }
    t
}

/// Strips leading runes satisfying `f` (`bytes.TrimLeftFunc`).
fn trim_left_func(s: &[u8], f: impl FnMut(char) -> bool) -> &[u8] {
    match index_func_truth(s, f, false) {
        Some(i) => &s[i..],
        None => &s[s.len()..],
    }
}

/// Strips trailing runes satisfying `f` (`bytes.TrimRightFunc`).
fn trim_right_func(s: &[u8], f: impl FnMut(char) -> bool) -> &[u8] {
    let end = match last_index_func_truth(s, f, false) {
        Some(i) if s[i] >= 0x80 => i + decode_rune(&s[i..]).1,
        Some(i) => i + 1,
        None => 0,
    };
    &s[..end]
}

/// Strips leading and trailing runes satisfying `f` (`bytes.TrimFunc`).
fn trim_func(s: &[u8], mut f: impl FnMut(char) -> bool) -> &[u8] {
    trim_right_func(trim_left_func(s, &mut f), f)
}

/// Strips leading runes contained in `cutset` (`bytes.TrimLeft`).
fn trim_left<'a>(s: &'a [u8], cutset: &[u8]) -> &'a [u8] {
    if cutset.is_empty() {
        return s;
    }
    trim_left_func(s, |r| set_contains(cutset, r))
}

/// Strips trailing runes contained in `cutset` (`bytes.TrimRight`).
fn trim_right<'a>(s: &'a [u8], cutset: &[u8]) -> &'a [u8] {
    if cutset.is_empty() {
        return s;
    }
    trim_right_func(s, |r| set_contains(cutset, r))
}

/// Strips leading and trailing runes contained in `cutset` (`bytes.Trim`).
fn trim<'a>(s: &'a [u8], cutset: &[u8]) -> &'a [u8] {
    trim_left(trim_right(s, cutset), cutset)
}

/// Strips leading and trailing Unicode white space (`bytes.TrimSpace`).
fn trim_space(s: &[u8]) -> &[u8] {
    trim_func(s, case::is_space)
}

/// Replaces the first `n` instances of `old` with `new`; `n < 0` replaces all
/// (`bytes.Replace`). An empty `old` matches before each rune and at the end.
fn replace(s: &[u8], old: &[u8], new: &[u8], n: isize) -> Vec<u8> {
    let m = if n != 0 { count(s, old) } else { 0 };
    if m == 0 {
        return s.to_vec();
    }
    let n = if n < 0 || m < n as usize {
        m
    } else {
        n as usize
    };
    let mut t = Vec::with_capacity((s.len() + n * new.len()).saturating_sub(n * old.len()));
    let mut start = 0;
    if !old.is_empty() {
        for _ in 0..n {
            let j = start + index(&s[start..], old).unwrap_or(0);
            t.extend_from_slice(&s[start..j]);
            t.extend_from_slice(new);
            start = j + old.len();
        }
    } else {
        t.extend_from_slice(new);
        for _ in 0..n - 1 {
            let wid = decode_rune(&s[start..]).1;
            let j = start + wid;
            t.extend_from_slice(&s[start..j]);
            t.extend_from_slice(new);
            start = j;
        }
    }
    t.extend_from_slice(&s[start..]);
    t
}

/// Reports whether `s` and `t` are equal under Unicode simple case folding
/// (`bytes.EqualFold`). Invalid bytes decode as `U+FFFD`.
fn equal_fold(s: &[u8], t: &[u8]) -> bool {
    let mut tb = t;
    let mut i = 0;
    while i < s.len() {
        let (sr, w) = decode_rune(&s[i..]);
        i += w;
        if tb.is_empty() {
            return false;
        }
        let (tr, size) = decode_rune(tb);
        tb = &tb[size..];
        if tr == sr {
            continue;
        }
        let (sr, tr) = if tr < sr { (tr, sr) } else { (sr, tr) };
        if tr.is_ascii() {
            if sr.is_ascii_uppercase() && tr as u32 == sr as u32 + 32 {
                continue;
            }
            return false;
        }
        let mut r = case::simple_fold(sr);
        while r != sr && r < tr {
            r = case::simple_fold(r);
        }
        if r == tr {
            continue;
        }
        return false;
    }
    tb.is_empty()
}

/// Slices `s` around the first `sep` (`bytes.Cut`).
fn cut<'a>(s: &'a [u8], sep: &[u8]) -> Option<(&'a [u8], &'a [u8])> {
    index(s, sep).map(|i| (&s[..i], &s[i + sep.len()..]))
}

/// Slices `s` around the last `sep` (`bytes.CutLast`).
fn cut_last<'a>(s: &'a [u8], sep: &[u8]) -> Option<(&'a [u8], &'a [u8])> {
    last_index(s, sep).map(|i| (&s[..i], &s[i + sep.len()..]))
}

/// Reports whether the decoded runes of `set` (invalid bytes as U+FFFD)
/// contain `r`, like Go's `strings.ContainsRune` over a `range`.
fn set_contains(mut set: &[u8], r: char) -> bool {
    while !set.is_empty() {
        let (c, n) = decode_rune(set);
        if c == r {
            return true;
        }
        set = &set[n..];
    }
    false
}

/// Go's text functions that std lacks, for byte strings that may not be UTF-8.
pub trait BytesExt {
    /// Index of the first `sep`; an empty `sep` is found at 0 (`strings.Index`).
    fn find_bytes(&self, sep: &[u8]) -> Option<usize>;
    /// Index of the last `sep`; an empty `sep` is found at the end (`strings.LastIndex`).
    fn rfind_bytes(&self, sep: &[u8]) -> Option<usize>;
    /// Index of the first rune `r`; `U+FFFD` also matches an invalid byte (`strings.IndexRune`).
    fn find_rune(&self, r: char) -> Option<usize>;
    /// Index of the first rune that is in `chars` (`strings.IndexAny`).
    fn find_any(&self, chars: &[u8]) -> Option<usize>;
    /// Index of the last rune that is in `chars` (`strings.LastIndexAny`).
    fn rfind_any(&self, chars: &[u8]) -> Option<usize>;
    /// Index of the first rune satisfying `f` (`strings.IndexFunc`).
    fn find_func(&self, f: impl FnMut(char) -> bool) -> Option<usize>;
    /// Index of the last rune satisfying `f` (`strings.LastIndexFunc`).
    fn rfind_func(&self, f: impl FnMut(char) -> bool) -> Option<usize>;
    /// Reports whether `sep` is within `self` (`bytes.Contains`).
    fn contains_bytes(&self, sep: &[u8]) -> bool {
        self.find_bytes(sep).is_some()
    }
    /// Reports whether any rune of `chars` is within `self` (`strings.ContainsAny`).
    fn contains_any(&self, chars: &[u8]) -> bool {
        self.find_any(chars).is_some()
    }
    /// Reports whether `r` is within `self` (`strings.ContainsRune`).
    fn contains_rune(&self, r: char) -> bool {
        self.find_rune(r).is_some()
    }
    /// Reports whether `f` holds for any rune (`strings.ContainsFunc`).
    fn contains_func(&self, f: impl FnMut(char) -> bool) -> bool {
        self.find_func(f).is_some()
    }
    /// Counts non-overlapping `sep`; an empty `sep` counts runes plus one (`strings.Count`).
    fn count_bytes(&self, sep: &[u8]) -> usize;
    /// Splits around every `sep`; an empty `sep` splits into runes
    /// (`strings.SplitSeq`, `strings.Split`).
    fn split_bytes<'a>(&'a self, sep: &'a [u8]) -> impl Iterator<Item = &'a [u8]>;
    /// Like [`split_bytes`](Self::split_bytes), keeping `sep` on each piece (`strings.SplitAfterSeq`).
    fn split_bytes_after<'a>(&'a self, sep: &'a [u8]) -> impl Iterator<Item = &'a [u8]>;
    /// Splits into at most `n` pieces; `n < 0` means all, `0` none (`strings.SplitN`).
    fn split_bytes_n(&self, sep: &[u8], n: isize) -> Vec<&[u8]>;
    /// Like [`split_bytes_n`](Self::split_bytes_n), keeping `sep` (`strings.SplitAfterN`).
    fn split_bytes_after_n(&self, sep: &[u8], n: isize) -> Vec<&[u8]>;
    /// Splits around runs of Unicode white space (`strings.Fields`).
    fn fields(&self) -> impl Iterator<Item = &[u8]>;
    /// Splits around runs of runes satisfying `f` (`strings.FieldsFunc`).
    fn fields_func(&self, f: impl FnMut(char) -> bool) -> impl Iterator<Item = &[u8]>;
    /// Newline-terminated lines, keeping the terminator (`strings.Lines`).
    fn split_lines(&self) -> impl Iterator<Item = &[u8]>;
    /// Maps every rune; `None` drops it (`strings.Map`).
    fn map_runes(&self, mapping: impl FnMut(char) -> Option<char>) -> Vec<u8>;
    /// Upper-cases with Go's simple mapping (`strings.ToUpper`).
    fn to_upper(&self) -> Vec<u8>;
    /// Lower-cases with Go's simple mapping (`strings.ToLower`).
    fn to_lower(&self) -> Vec<u8>;
    /// Title-cases every rune (`strings.ToTitle`).
    fn to_title(&self) -> Vec<u8>;
    /// Upper-cases with `c` taking precedence (`strings.ToUpperSpecial`).
    fn to_upper_special(&self, c: SpecialCase<'_>) -> Vec<u8>;
    /// Lower-cases with `c` taking precedence (`strings.ToLowerSpecial`).
    fn to_lower_special(&self, c: SpecialCase<'_>) -> Vec<u8>;
    /// Title-cases with `c` taking precedence (`strings.ToTitleSpecial`).
    fn to_title_special(&self, c: SpecialCase<'_>) -> Vec<u8>;
    /// Replaces each run of invalid UTF-8 with `replacement` (`strings.ToValidUTF8`).
    fn to_valid_utf8(&self, replacement: &[u8]) -> Vec<u8>;
    /// Title-cases the first letter of each word (`strings.Title`, deprecated in Go).
    fn title(&self) -> Vec<u8>;
    /// The runes, invalid bytes as `U+FFFD` (`bytes.Runes`).
    fn runes(&self) -> Vec<char>;
    /// Strips leading and trailing runes satisfying `f` (`strings.TrimFunc`).
    fn trim_func(&self, f: impl FnMut(char) -> bool) -> &[u8];
    /// Strips leading runes satisfying `f` (`strings.TrimLeftFunc`).
    fn trim_start_func(&self, f: impl FnMut(char) -> bool) -> &[u8];
    /// Strips trailing runes satisfying `f` (`strings.TrimRightFunc`).
    fn trim_end_func(&self, f: impl FnMut(char) -> bool) -> &[u8];
    /// Strips leading and trailing runes contained in `cutset` (`strings.Trim`).
    fn trim_cutset(&self, cutset: &[u8]) -> &[u8];
    /// Strips leading runes contained in `cutset` (`strings.TrimLeft`).
    fn trim_start_cutset(&self, cutset: &[u8]) -> &[u8];
    /// Strips trailing runes contained in `cutset` (`strings.TrimRight`).
    fn trim_end_cutset(&self, cutset: &[u8]) -> &[u8];
    /// Strips leading and trailing Unicode white space (`strings.TrimSpace`).
    fn trim_space(&self) -> &[u8];
    /// Replaces the first `n` `old` with `new`; `n < 0` replaces all (`strings.Replace`).
    /// An empty `old` matches before each rune and at the end.
    fn replace(&self, old: &[u8], new: &[u8], n: isize) -> Vec<u8>;
    /// Replaces every `old` with `new` (`strings.ReplaceAll`).
    fn replace_all(&self, old: &[u8], new: &[u8]) -> Vec<u8> {
        self.replace(old, new, -1)
    }
    /// Equality under Unicode simple case folding (`strings.EqualFold`).
    fn equal_fold(&self, other: &[u8]) -> bool;
    /// Slices around the first `sep` (`strings.Cut`).
    fn cut<'a>(&'a self, sep: &[u8]) -> Option<(&'a [u8], &'a [u8])>;
    /// Slices around the last `sep` (`strings.CutLast`).
    fn cut_last<'a>(&'a self, sep: &[u8]) -> Option<(&'a [u8], &'a [u8])>;
}

impl BytesExt for [u8] {
    fn find_bytes(&self, sep: &[u8]) -> Option<usize> {
        index(self, sep)
    }
    fn rfind_bytes(&self, sep: &[u8]) -> Option<usize> {
        last_index(self, sep)
    }
    fn find_rune(&self, r: char) -> Option<usize> {
        index_rune(self, r)
    }
    fn find_any(&self, chars: &[u8]) -> Option<usize> {
        index_any(self, chars)
    }
    fn rfind_any(&self, chars: &[u8]) -> Option<usize> {
        last_index_any(self, chars)
    }
    fn find_func(&self, f: impl FnMut(char) -> bool) -> Option<usize> {
        index_func(self, f)
    }
    fn rfind_func(&self, f: impl FnMut(char) -> bool) -> Option<usize> {
        last_index_func(self, f)
    }
    fn count_bytes(&self, sep: &[u8]) -> usize {
        count(self, sep)
    }
    fn split_bytes<'a>(&'a self, sep: &'a [u8]) -> impl Iterator<Item = &'a [u8]> {
        split_seq(self, sep)
    }
    fn split_bytes_after<'a>(&'a self, sep: &'a [u8]) -> impl Iterator<Item = &'a [u8]> {
        split_after_seq(self, sep)
    }
    fn split_bytes_n(&self, sep: &[u8], n: isize) -> Vec<&[u8]> {
        split_n(self, sep, n)
    }
    fn split_bytes_after_n(&self, sep: &[u8], n: isize) -> Vec<&[u8]> {
        split_after_n(self, sep, n)
    }
    fn fields(&self) -> impl Iterator<Item = &[u8]> {
        fields_seq(self)
    }
    fn fields_func(&self, f: impl FnMut(char) -> bool) -> impl Iterator<Item = &[u8]> {
        fields_func_seq(self, f)
    }
    fn split_lines(&self) -> impl Iterator<Item = &[u8]> {
        lines(self)
    }
    fn map_runes(&self, mapping: impl FnMut(char) -> Option<char>) -> Vec<u8> {
        map(mapping, self)
    }
    fn to_upper(&self) -> Vec<u8> {
        to_upper(self)
    }
    fn to_lower(&self) -> Vec<u8> {
        to_lower(self)
    }
    fn to_title(&self) -> Vec<u8> {
        to_title(self)
    }
    fn to_upper_special(&self, c: SpecialCase<'_>) -> Vec<u8> {
        to_upper_special(c, self)
    }
    fn to_lower_special(&self, c: SpecialCase<'_>) -> Vec<u8> {
        to_lower_special(c, self)
    }
    fn to_title_special(&self, c: SpecialCase<'_>) -> Vec<u8> {
        to_title_special(c, self)
    }
    fn to_valid_utf8(&self, replacement: &[u8]) -> Vec<u8> {
        to_valid_utf8(self, replacement)
    }
    fn title(&self) -> Vec<u8> {
        title(self)
    }
    fn runes(&self) -> Vec<char> {
        runes(self)
    }
    fn trim_func(&self, f: impl FnMut(char) -> bool) -> &[u8] {
        trim_func(self, f)
    }
    fn trim_start_func(&self, f: impl FnMut(char) -> bool) -> &[u8] {
        trim_left_func(self, f)
    }
    fn trim_end_func(&self, f: impl FnMut(char) -> bool) -> &[u8] {
        trim_right_func(self, f)
    }
    fn trim_cutset(&self, cutset: &[u8]) -> &[u8] {
        trim(self, cutset)
    }
    fn trim_start_cutset(&self, cutset: &[u8]) -> &[u8] {
        trim_left(self, cutset)
    }
    fn trim_end_cutset(&self, cutset: &[u8]) -> &[u8] {
        trim_right(self, cutset)
    }
    fn trim_space(&self) -> &[u8] {
        trim_space(self)
    }
    fn replace(&self, old: &[u8], new: &[u8], n: isize) -> Vec<u8> {
        replace(self, old, new, n)
    }
    fn equal_fold(&self, other: &[u8]) -> bool {
        equal_fold(self, other)
    }
    fn cut<'a>(&'a self, sep: &[u8]) -> Option<(&'a [u8], &'a [u8])> {
        cut(self, sep)
    }
    fn cut_last<'a>(&'a self, sep: &[u8]) -> Option<(&'a [u8], &'a [u8])> {
        cut_last(self, sep)
    }
}
