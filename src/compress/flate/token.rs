//! LZ77 tokens and their length and offset code tables (Go's `token.go`).
//!
//! A token is a `u32`: a literal is the byte value; a match is
//! `MATCH_TYPE | (length - 3) << 22 | offset_code << 16 | (offset - 1)`.
//! Histograms are kept while tokens are added.

pub(super) const LENGTH_SHIFT: u32 = 22;
pub(super) const OFFSET_MASK: u32 = (1 << LENGTH_SHIFT) - 1;
pub(super) const MATCH_TYPE: u32 = 1 << 30;
pub(super) const MATCH_OFFSET_ONLY_MASK: u32 = 0xffff;
pub(super) const END_BLOCK_MARKER: u32 = 256;
pub(super) const BASE_MATCH_LENGTH: i32 = 3;
pub(super) const LITERAL_COUNT: usize = 286;
pub(super) const OFFSET_CODE_COUNT: usize = 30;

/// `LENGTH_BASE[c]` is `length - 3` for the first length of code `c + 257`.
pub(super) const LENGTH_BASE: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128,
    160, 192, 224, 255, 0, 0, 0,
];

/// Extra bits of length code `i + 257`.
pub(super) const LENGTH_EXTRA_BITS: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0, 0, 0, 0,
];

/// Extra bits of offset code `i`.
pub(super) const OFFSET_EXTRA_BITS: [i8; 32] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14,
];

/// Extra-bit count and base for offset codes 4..=29 in one word
/// (`base << 8 | bits`); the extended-window codes are zero.
pub(super) const OFFSET_COMBINED: [u32; 32] = [
    0x0, 0x0, 0x0, 0x0, 0x401, 0x601, 0x802, 0xc02, 0x1003, 0x1803, 0x2004, 0x3004, 0x4005, 0x6005,
    0x8006, 0xc006, 0x10007, 0x18007, 0x20008, 0x30008, 0x40009, 0x60009, 0x8000a, 0xc000a,
    0x10000b, 0x18000b, 0x20000c, 0x30000c, 0x40000d, 0x60000d, 0x0, 0x0,
];

const fn length_code(x: usize) -> u8 {
    let mut c = 28;
    while LENGTH_BASE[c] as usize > x {
        c -= 1;
    }
    c as u8
}

const fn offset_code_of(off: u32) -> u32 {
    if off < 4 {
        off
    } else {
        let nb = 31 - off.leading_zeros();
        nb * 2 + ((off >> (nb - 1)) & 1)
    }
}

/// `LENGTH_CODES[length - 3]` is the length code minus 257.
pub(super) static LENGTH_CODES: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = length_code(i);
        i += 1;
    }
    t
};

/// `LENGTH_CODES` plus one.
pub(super) static LENGTH_CODES1: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = length_code(i) + 1;
        i += 1;
    }
    t
};

static OFFSET_CODES: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = offset_code_of(i as u32) as u8;
        i += 1;
    }
    t
};

/// Offset code for `off` in `256..=32767`, indexed by `off >> 7`. Entries 0
/// and 1 are only reached by the wrapped index of `off` 32768 and above, as in
/// Go.
static OFFSET_CODES14: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = offset_code_of(i as u32) as u8 + 14;
        i += 1;
    }
    t
};

/// The offset code for `off`, which is the distance minus one.
#[inline]
pub(super) fn offset_code(off: u32) -> u32 {
    if off < 256 {
        u32::from(OFFSET_CODES[off as usize])
    } else {
        u32::from(OFFSET_CODES14[((off >> 7) & 0xff) as usize])
    }
}

/// Fast approximation of `log2(val)` (Go's `mFastLog2`). Go compiled for
/// arm64 fuses the multiply-adds; so does this.
fn m_fast_log2(val: f32) -> f32 {
    let ux = val.to_bits() as i32;
    let mut log2 = (((ux >> 23) & 255) - 128) as f32;
    let ux = (ux & -0x7f80_0001) + (127 << 23);
    let uval = f32::from_bits(ux as u32);
    log2 += (-0.344_848_43f32)
        .mul_add(uval, 2.024_665_8)
        .mul_add(uval, -0.674_877_6);
    log2
}

/// The tokens of one block with their histograms.
pub(super) struct Tokens {
    pub(super) extra_hist: [u16; 32],
    pub(super) off_hist: [u16; 32],
    pub(super) lit_hist: [u16; 256],
    pub(super) n_filled: usize,
    pub(super) n: u16,
    pub(super) tokens: Vec<u32>,
}

impl Tokens {
    pub(super) fn new() -> Self {
        Tokens {
            extra_hist: [0; 32],
            off_hist: [0; 32],
            lit_hist: [0; 256],
            n_filled: 0,
            n: 0,
            tokens: vec![0; 65536],
        }
    }

    pub(super) fn reset(&mut self) {
        if self.n == 0 {
            return;
        }
        self.n = 0;
        self.n_filled = 0;
        self.lit_hist = [0; 256];
        self.extra_hist = [0; 32];
        self.off_hist = [0; 32];
    }

    #[inline]
    fn push(&mut self, t: u32) {
        self.tokens[usize::from(self.n)] = t;
        self.n = self.n.wrapping_add(1);
    }

    /// Append `lit` unmatched bytes.
    pub(super) fn emit_literals(&mut self, lit: &[u8]) {
        for &v in lit {
            self.push(u32::from(v));
            self.lit_hist[usize::from(v)] += 1;
        }
    }

    #[inline]
    pub(super) fn add_literal(&mut self, lit: u8) {
        self.push(u32::from(lit));
        self.lit_hist[usize::from(lit)] += 1;
    }

    /// Estimated minimum size of the block's optimal encoding in bits.
    pub(super) fn estimated_bits(&self) -> i32 {
        let mut shannon = 0f32;
        let mut bits = 0i32;
        let mut n_matches = 0i32;
        let total = i32::from(self.n) + self.n_filled as i32;
        if total > 0 {
            let inv_total = 1.0 / total as f32;
            for &v in self.lit_hist.iter() {
                if v > 0 {
                    let n = f32::from(v);
                    let cost = (-m_fast_log2(n * inv_total)).clamp(1.0, 15.0);
                    shannon = cost.mul_add(n, shannon);
                }
            }
            shannon += 15.0;
            for (i, &v) in self.extra_hist[1..LITERAL_COUNT - 256].iter().enumerate() {
                if v > 0 {
                    let n = f32::from(v);
                    let cost = (-m_fast_log2(n * inv_total)).clamp(1.0, 15.0);
                    shannon = cost.mul_add(n, shannon);
                    bits += i32::from(LENGTH_EXTRA_BITS[i & 31]) * i32::from(v);
                    n_matches += i32::from(v);
                }
            }
        }
        if n_matches > 0 {
            let inv_total = 1.0 / n_matches as f32;
            for (i, &v) in self.off_hist[..OFFSET_CODE_COUNT].iter().enumerate() {
                if v > 0 {
                    let n = f32::from(v);
                    let cost = (-m_fast_log2(n * inv_total)).clamp(1.0, 15.0);
                    shannon = cost.mul_add(n, shannon);
                    bits += i32::from(OFFSET_EXTRA_BITS[i & 31]) * i32::from(v);
                }
            }
        }
        shannon as i32 + bits
    }

    /// Append a match of `xlength = length - 3` at `xoffset = distance - 1`.
    #[inline]
    pub(super) fn add_match(&mut self, xlength: u32, mut xoffset: u32) {
        let o_code = offset_code(xoffset);
        xoffset |= o_code << 16;
        self.extra_hist[usize::from(LENGTH_CODES1[(xlength & 255) as usize])] += 1;
        self.off_hist[(o_code & 31) as usize] += 1;
        self.push(MATCH_TYPE | (xlength << LENGTH_SHIFT) | xoffset);
    }

    /// Like [`Tokens::add_match`] for a `xlength` that is the full match
    /// length and may exceed 258; it is split into several matches.
    pub(super) fn add_match_long(&mut self, mut xlength: i32, mut xoffset: u32) {
        let oc = offset_code(xoffset);
        xoffset |= oc << 16;
        while xlength > 0 {
            let mut xl = xlength;
            if xl > 258 {
                // At least BASE_MATCH_LENGTH must be left for the next match.
                xl = if xl > 258 + BASE_MATCH_LENGTH {
                    258
                } else {
                    258 - BASE_MATCH_LENGTH
                };
            }
            xlength -= xl;
            xl -= BASE_MATCH_LENGTH;
            self.extra_hist[usize::from(LENGTH_CODES1[(xl & 255) as usize])] += 1;
            self.off_hist[(oc & 31) as usize] += 1;
            self.push(MATCH_TYPE | ((xl as u32) << LENGTH_SHIFT) | xoffset);
        }
    }

    pub(super) fn add_eob(&mut self) {
        self.push(END_BLOCK_MARKER);
        self.extra_hist[0] += 1;
    }

    pub(super) fn slice(&self) -> &[u32] {
        &self.tokens[..usize::from(self.n)]
    }
}
