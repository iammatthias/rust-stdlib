//! Length-limited Huffman code construction (Go's `huffman_code.go`).
//!
//! The tree is built by Go's level-by-level algorithm, so ties between equal
//! frequencies resolve exactly as in Go.

use super::token::LITERAL_COUNT;
use std::sync::OnceLock;

const MAX_BITS_LIMIT: usize = 16;

/// A Huffman code: the bit length in the low byte, the (bit-reversed) code
/// above it.
pub(super) type HCode = u32;

#[inline]
pub(super) fn hcode_len(h: HCode) -> u8 {
    h as u8
}

#[inline]
pub(super) fn hcode_code64(h: HCode) -> u64 {
    u64::from(h >> 8)
}

#[inline]
fn newhcode(code: u16, length: u8) -> HCode {
    HCode::from(length) | (HCode::from(code) << 8)
}

#[derive(Clone, Copy, Default)]
struct LiteralNode {
    literal: u16,
    freq: u16,
}

#[derive(Clone, Copy, Default)]
struct LevelInfo {
    level: i32,
    last_freq: i32,
    next_char_freq: i32,
    next_pair_freq: i32,
    needed: i32,
}

fn reverse_bits(x: u16, b: u8) -> u16 {
    (x << ((16 - b) & 15)).reverse_bits()
}

pub(super) struct HuffmanEncoder {
    pub(super) codes: Vec<HCode>,
    bit_count: [i32; 17],
    freqcache: [LiteralNode; LITERAL_COUNT + 1],
}

impl HuffmanEncoder {
    pub(super) fn new(size: usize) -> Self {
        HuffmanEncoder {
            codes: vec![0; size],
            bit_count: [0; 17],
            freqcache: [LiteralNode::default(); LITERAL_COUNT + 1],
        }
    }

    /// Number of bits needed to encode `freq`.
    pub(super) fn bit_length(&self, freq: &[u16]) -> i32 {
        let mut total = 0i32;
        for (i, &f) in freq.iter().enumerate() {
            if f != 0 {
                total += i32::from(f) * i32::from(hcode_len(self.codes[i]));
            }
        }
        total
    }

    /// Bits needed to encode `b`, counting 1 bit for unset codes.
    pub(super) fn bit_length_raw(&self, b: &[u8]) -> i32 {
        let mut total = 0i32;
        for &f in b {
            total += i32::from(hcode_len(self.codes[usize::from(f)])).max(1);
        }
        total
    }

    /// Bits needed to encode `freq`, or `i32::MAX` if a used symbol has no code.
    pub(super) fn can_encode_len(&self, freq: &[u16]) -> i32 {
        let mut total = 0i32;
        for (i, &f) in freq.iter().enumerate() {
            if f != 0 {
                let code = self.codes[i];
                if code == 0 {
                    return i32::MAX;
                }
                total += i32::from(f) * i32::from(hcode_len(code));
            }
        }
        total
    }
}

/// `list` holds the used symbols in order of increasing frequency, with room
/// for one more element; at least three symbols. Fills `bit_count` and returns
/// the (possibly reduced) maximum code length.
fn bit_counts(bit_count: &mut [i32; 17], list: &mut [LiteralNode], mut max_bits: i32) -> usize {
    assert!(
        (max_bits as usize) < MAX_BITS_LIMIT,
        "flate: maxBits too large"
    );
    let n = (list.len() - 1) as i32;
    list[n as usize] = LiteralNode {
        literal: u16::MAX,
        freq: u16::MAX,
    };
    if max_bits > n - 1 {
        max_bits = n - 1;
    }

    let mut levels = [LevelInfo::default(); MAX_BITS_LIMIT];
    let mut leaf_counts = [[0i32; MAX_BITS_LIMIT]; MAX_BITS_LIMIT];

    for level in 1..=max_bits {
        levels[level as usize] = LevelInfo {
            level,
            last_freq: i32::from(list[1].freq),
            next_char_freq: i32::from(list[2].freq),
            next_pair_freq: i32::from(list[0].freq) + i32::from(list[1].freq),
            needed: 0,
        };
        leaf_counts[level as usize][level as usize] = 2;
        if level == 1 {
            levels[level as usize].next_pair_freq = i32::MAX;
        }
    }

    levels[max_bits as usize].needed = 2 * n - 4;

    let mut level = max_bits as usize;
    while level < 16 {
        if levels[level].next_pair_freq == i32::MAX && levels[level].next_char_freq == i32::MAX {
            levels[level].needed = 0;
            levels[level + 1].next_pair_freq = i32::MAX;
            level += 1;
            continue;
        }

        let prev_freq = levels[level].last_freq;
        if levels[level].next_char_freq < levels[level].next_pair_freq {
            let n = leaf_counts[level][level] + 1;
            levels[level].last_freq = levels[level].next_char_freq;
            leaf_counts[level][level] = n;
            let e = list[n as usize];
            levels[level].next_char_freq = if e.literal < u16::MAX {
                i32::from(e.freq)
            } else {
                i32::MAX
            };
        } else {
            levels[level].last_freq = levels[level].next_pair_freq;
            let save = leaf_counts[level][level];
            leaf_counts[level] = leaf_counts[level - 1];
            leaf_counts[level][level] = save;
            levels[level - 1].needed = 2;
        }

        levels[level].needed -= 1;
        if levels[level].needed == 0 {
            if levels[level].level == max_bits {
                break;
            }
            levels[level + 1].next_pair_freq = prev_freq + levels[level].last_freq;
            level += 1;
        } else {
            while levels[level - 1].needed > 0 {
                level -= 1;
            }
        }
    }

    assert_eq!(
        leaf_counts[max_bits as usize][max_bits as usize], n,
        "leafCounts[maxBits][maxBits] != n"
    );

    let counts = &leaf_counts[max_bits as usize];
    let mut bits = 1usize;
    let mut level = max_bits as usize;
    while level > 0 {
        bit_count[bits] = counts[level] - counts[level - 1];
        bits += 1;
        level -= 1;
    }
    max_bits as usize
}

/// Assign codes to the symbols in `list` (sorted by increasing frequency)
/// given the number of symbols at each bit length (RFC 1951, 3.2.2).
fn assign_encoding_and_size(codes: &mut [HCode], bit_count: &[i32], mut list: &mut [LiteralNode]) {
    let mut code = 0u16;
    for (n, &bits) in bit_count.iter().enumerate() {
        code <<= 1;
        if n == 0 || bits == 0 {
            continue;
        }
        let at = list.len() - bits as usize;
        let chunk = &mut list[at..];
        chunk.sort_by_key(|node| node.literal);
        for node in chunk.iter() {
            codes[usize::from(node.literal)] = newhcode(reverse_bits(code, n as u8), n as u8);
            code = code.wrapping_add(1);
        }
        list = &mut list[..at];
    }
}

impl HuffmanEncoder {
    /// Rewrite the codes as the Huffman code for the frequencies `freq`, with
    /// no code longer than `max_bits`.
    pub(super) fn generate(&mut self, freq: &[u16], max_bits: i32) {
        let HuffmanEncoder {
            codes,
            bit_count,
            freqcache,
        } = self;
        let list = &mut freqcache[..freq.len() + 1];
        let mut count = 0;
        for (i, &f) in freq.iter().enumerate() {
            if f != 0 {
                list[count] = LiteralNode {
                    literal: i as u16,
                    freq: f,
                };
                count += 1;
            } else {
                codes[i] = 0;
            }
        }
        list[count] = LiteralNode::default();
        if count <= 2 {
            // With two or fewer symbols everything has bit length 1.
            for i in 0..count {
                codes[usize::from(list[i].literal)] = newhcode(i as u16, 1);
            }
            return;
        }
        list[..count].sort_by_key(|a| (u32::from(a.freq) << 10) + u32::from(a.literal));
        let len = bit_counts(bit_count, &mut list[..count + 1], max_bits);
        assign_encoding_and_size(codes, &bit_count[..=len], &mut list[..count]);
    }
}

fn fixed_literal_encoding() -> HuffmanEncoder {
    let mut h = HuffmanEncoder::new(LITERAL_COUNT);
    for ch in 0..LITERAL_COUNT as u16 {
        let (bits, size) = match ch {
            0..=143 => (ch + 48, 8),
            144..=255 => (ch + 400 - 144, 9),
            256..=279 => (ch - 256, 7),
            _ => (ch + 192 - 280, 8),
        };
        h.codes[usize::from(ch)] = newhcode(reverse_bits(bits, size), size);
    }
    h
}

fn fixed_offset_encoding() -> HuffmanEncoder {
    let mut h = HuffmanEncoder::new(30);
    for ch in 0..30u16 {
        h.codes[usize::from(ch)] = newhcode(reverse_bits(ch, 5), 5);
    }
    h
}

/// The fixed-Huffman literal/length code of RFC 1951.
pub(super) fn fixed_literal() -> &'static HuffmanEncoder {
    static CELL: OnceLock<HuffmanEncoder> = OnceLock::new();
    CELL.get_or_init(fixed_literal_encoding)
}

/// The fixed-Huffman distance code of RFC 1951.
pub(super) fn fixed_offset() -> &'static HuffmanEncoder {
    static CELL: OnceLock<HuffmanEncoder> = OnceLock::new();
    CELL.get_or_init(fixed_offset_encoding)
}

/// The offset code used by Huffman-only blocks: one code of length 1.
pub(super) fn huff_offset() -> &'static HuffmanEncoder {
    static CELL: OnceLock<HuffmanEncoder> = OnceLock::new();
    CELL.get_or_init(|| {
        let mut h = HuffmanEncoder::new(30);
        let mut freq = [0u16; 30];
        freq[0] = 1;
        h.generate(&freq, 15);
        h
    })
}

/// Count byte values in `b` into `h[..256]`.
pub(super) fn histogram(b: &[u8], h: &mut [u16]) {
    for &t in b {
        h[usize::from(t)] += 1;
    }
}
