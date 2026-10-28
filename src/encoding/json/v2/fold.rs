//! Case folding of object member names (Go's `fold.go`): ASCII is
//! upper-cased and `_` and `-` are dropped; other runes map to the smallest
//! rune of their simple-fold orbit.
use crate::unicode::{self, rune};

/// `foldName`: the comparison key of a JSON object member name.
pub(crate) fn fold_name(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let c = input[i];
        if c < rune::RUNE_SELF as u8 {
            if c != b'_' && c != b'-' {
                out.push(c.to_ascii_uppercase());
            }
            i += 1;
            continue;
        }
        let (r, n) = rune::decode_rune(&input[i..]);
        rune::append_rune(&mut out, fold_rune(r));
        i += n;
    }
    out
}

fn fold_rune(mut r: i32) -> i32 {
    loop {
        let r2 = unicode::simple_fold(r);
        if r2 <= r {
            return r2;
        }
        r = r2;
    }
}
