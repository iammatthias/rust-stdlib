//! Small byte-string helpers shared by the escapers.

/// The index of the first occurrence of `b` in `s`.
pub(crate) fn index_byte(s: &[u8], b: u8) -> Option<usize> {
    s.iter().position(|&c| c == b)
}

/// The index of the first byte of `s` that is in `set` (an ASCII set).
pub(crate) fn index_any(s: &[u8], set: &[u8]) -> Option<usize> {
    s.iter().position(|c| set.contains(c))
}

/// The index of the first occurrence of `sub` in `s`.
pub(crate) fn index_sub(s: &[u8], sub: &[u8]) -> Option<usize> {
    if sub.is_empty() {
        return Some(0);
    }
    if sub.len() > s.len() {
        return None;
    }
    s.windows(sub.len()).position(|w| w == sub)
}

/// The index of the first rune of `s` that is one of the runes in `chars`
/// (which may include non-ASCII runes). Matches Go's `bytes.IndexAny`.
pub(crate) fn index_any_runes(s: &[u8], chars: &str) -> Option<usize> {
    let mut i = 0;
    while i < s.len() {
        let (r, w) = crate::unicode::rune::decode_rune(&s[i..]);
        if let Some(c) = char::from_u32(r as u32) {
            if chars.contains(c) && !(r == 0xFFFD && w == 1 && !chars.contains('\u{FFFD}')) {
                return Some(i);
            }
        }
        i += w.max(1);
    }
    None
}

/// Reports whether `s` has the prefix `p`.
pub(crate) fn has_prefix(s: &[u8], p: &[u8]) -> bool {
    s.len() >= p.len() && &s[..p.len()] == p
}

/// Go's `bytes.EqualFold` (Unicode simple folding).
pub(crate) fn equal_fold(a: &[u8], b: &[u8]) -> bool {
    crate::text::BytesExt::equal_fold(a, b)
}

/// Go's `bytes.ToLower` on a string.
pub(crate) fn to_lower_string(s: &[u8]) -> String {
    String::from_utf8_lossy(&crate::text::BytesExt::to_lower(s)).into_owned()
}

/// Go's `bytes.TrimRight(s, cutset)` for an ASCII cutset.
pub(crate) fn trim_right<'a>(s: &'a [u8], cutset: &[u8]) -> &'a [u8] {
    let mut end = s.len();
    while end > 0 && cutset.contains(&s[end - 1]) {
        end -= 1;
    }
    &s[..end]
}

/// Go's `bytes.TrimLeft(s, cutset)` for an ASCII cutset.
pub(crate) fn trim_left<'a>(s: &'a [u8], cutset: &[u8]) -> &'a [u8] {
    let mut start = 0;
    while start < s.len() && cutset.contains(&s[start]) {
        start += 1;
    }
    &s[start..]
}
