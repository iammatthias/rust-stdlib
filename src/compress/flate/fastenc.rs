//! The level 1-6 encoders (Go's `deflatefast.go` and `level1.go` to
//! `level6.go`).
//!
//! Each level is a specialised single-pass matcher over a history buffer.
//! Offsets are `i32` and relative to a moving base `cur`, as in Go; the
//! arithmetic (including negative candidate offsets for empty table slots)
//! must stay in `i32`.

use super::token::Tokens;

const TABLE_BITS: u32 = 15;
const TABLE_SIZE: usize = 1 << TABLE_BITS;
const HASH_LONG_BYTES: u32 = 7;
const HASH_SHORT_BYTES: u32 = 4;
const BASE_MATCH_OFFSET: i32 = 1;
const MAX_MATCH_OFFSET: i32 = 1 << 15;
const MAX_MATCH_LENGTH: i32 = 258;
pub(super) const MAX_STORE_BLOCK_SIZE: usize = 65535;
const ALLOC_HISTORY: usize = MAX_STORE_BLOCK_SIZE * 5;
const BUFFER_RESET: i32 = i32::MAX - ALLOC_HISTORY as i32 - MAX_STORE_BLOCK_SIZE as i32;
const INPUT_MARGIN: i32 = 12 - 1;
const MIN_NON_LITERAL_BLOCK_SIZE: usize = 1 + 1 + INPUT_MARGIN as usize;

const PRIME3BYTES: u64 = 506832829;
const PRIME4BYTES: u64 = 2654435761;
const PRIME5BYTES: u64 = 889523592379;
const PRIME6BYTES: u64 = 227718039650203;
const PRIME7BYTES: u64 = 58295818150454627;
const PRIME8BYTES: u64 = 0xcf1bbcdcb7a56463;

/// The level 1-6 encoder interface.
pub(super) trait FastEnc {
    /// Encode `src` into `dst`.
    fn encode(&mut self, dst: &mut Tokens, src: &[u8]);
    /// Reset so matches are not made with previous data.
    fn reset(&mut self);
}

pub(super) fn fast_encoder(level: i32) -> Box<dyn FastEnc> {
    match level {
        1 => Box::new(EncL1::new()),
        2 => Box::new(EncL2::new()),
        3 => Box::new(EncL3::new()),
        4 => Box::new(EncL4::new()),
        5 => Box::new(EncL5::new()),
        6 => Box::new(EncL6::new()),
        _ => unreachable!("invalid level specified"),
    }
}

/// Hash of the first `n` (3 to 8) bytes of `u` to `b` bits; other `n` act as 4.
#[inline]
fn hash_len(u: u64, b: u32, n: u32) -> usize {
    (match n {
        3 => (u32::wrapping_mul((u << 8) as u32, PRIME3BYTES as u32) >> (32 - b)) as u64,
        5 => ((u << (64 - 40)).wrapping_mul(PRIME5BYTES) >> (64 - b)) as u32 as u64,
        6 => ((u << (64 - 48)).wrapping_mul(PRIME6BYTES) >> (64 - b)) as u32 as u64,
        7 => ((u << (64 - 56)).wrapping_mul(PRIME7BYTES) >> (64 - b)) as u32 as u64,
        8 => (u.wrapping_mul(PRIME8BYTES) >> (64 - b)) as u32 as u64,
        _ => (u32::wrapping_mul(u as u32, PRIME4BYTES as u32) >> (32 - b)) as u64,
    }) as usize
}

#[inline]
fn load32(src: &[u8], i: i32) -> u32 {
    let b = &src[i as usize..][..4];
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

#[inline]
fn load64(src: &[u8], i: i32) -> u64 {
    let b = &src[i as usize..][..8];
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Length of the common prefix of `a` and `b`; `a` must be the shorter.
#[inline]
pub(super) fn match_len(a: &[u8], b: &[u8]) -> usize {
    let mut n = 0;
    let mut left = a.len();
    while left >= 8 {
        let x = u64::from_le_bytes(a[n..n + 8].try_into().unwrap());
        let y = u64::from_le_bytes(b[n..n + 8].try_into().unwrap());
        let diff = x ^ y;
        if diff != 0 {
            return n + (diff.trailing_zeros() >> 3) as usize;
        }
        n += 8;
        left -= 8;
    }
    while n < a.len() && a[n] == b[n] {
        n += 1;
    }
    n
}

/// Match length between positions `s` and `t` (`s > t`), capped at 254.
fn match_len_limited(s: i32, t: i32, src: &[u8]) -> i32 {
    let s = s as usize;
    let a = &src[s..(s + MAX_MATCH_LENGTH as usize - 4).min(src.len())];
    match_len(a, &src[t as usize..]) as i32
}

/// Match length between positions `s` and `t` (`s > t`).
fn match_len_long(s: i32, t: i32, src: &[u8]) -> i32 {
    match_len(&src[s as usize..], &src[t as usize..]) as i32
}

/// History buffer shared by the encoders.
struct FastGen {
    hist: Vec<u8>,
    cur: i32,
}

impl FastGen {
    fn new() -> Self {
        FastGen {
            hist: Vec::new(),
            cur: MAX_STORE_BLOCK_SIZE as i32,
        }
    }

    /// Append `src` to the history and return where it starts.
    fn add_block(&mut self, src: &[u8]) -> i32 {
        if self.hist.len() + src.len() > ALLOC_HISTORY {
            // Move down, keeping the last window.
            let offset = self.hist.len() - MAX_MATCH_OFFSET as usize;
            self.hist
                .copy_within(offset..offset + MAX_MATCH_OFFSET as usize, 0);
            self.cur += offset as i32;
            self.hist.truncate(MAX_MATCH_OFFSET as usize);
        } else if self.hist.capacity() == 0 {
            self.hist.reserve_exact(ALLOC_HISTORY);
        }
        let s = self.hist.len() as i32;
        self.hist.extend_from_slice(src);
        s
    }

    fn reset(&mut self) {
        if self.hist.capacity() < ALLOC_HISTORY {
            self.hist.reserve_exact(ALLOC_HISTORY);
        }
        // Offset the position so everything is out of reach.
        if self.cur <= BUFFER_RESET {
            self.cur += MAX_MATCH_OFFSET + self.hist.len() as i32;
        }
        self.hist.clear();
    }
}

/// Subtract the base from a table offset when the history is rebased.
#[inline]
fn rebase(v: i32, min_off: i32, cur: i32) -> i32 {
    if v <= min_off {
        0
    } else {
        v - cur + MAX_MATCH_OFFSET
    }
}

/// Append the pending literals and finish: nothing is emitted if no token
/// was produced at all.
fn emit_remainder(dst: &mut Tokens, src: &[u8], next_emit: i32) {
    if (next_emit as usize) < src.len() {
        if dst.n == 0 {
            return;
        }
        dst.emit_literals(&src[next_emit as usize..]);
    }
}

/// Extend a match backwards over equal bytes, emit the literals before it and
/// the match itself. Returns the (possibly moved) `s`, `t` and the length.
#[inline]
fn emit_match(
    dst: &mut Tokens,
    src: &[u8],
    mut s: i32,
    mut t: i32,
    mut l: i32,
    next_emit: i32,
) -> (i32, i32, i32) {
    while t > 0 && s > next_emit && src[(t - 1) as usize] == src[(s - 1) as usize] {
        s -= 1;
        t -= 1;
        l += 1;
    }
    if next_emit < s {
        dst.emit_literals(&src[next_emit as usize..s as usize]);
    }
    dst.add_match_long(l, (s - t - BASE_MATCH_OFFSET) as u32);
    (s, t, l)
}

// ---------------------------------------------------------------- level 1

/// Level 1: one small table, 5-byte hashes, sparse indexing.
struct EncL1 {
    g: FastGen,
    table: Vec<i32>,
}

impl EncL1 {
    fn new() -> Self {
        EncL1 {
            g: FastGen::new(),
            table: vec![0; TABLE_SIZE],
        }
    }

    fn run(&mut self, dst: &mut Tokens, src: &[u8], mut s: i32) {
        let cur = self.g.cur;
        let mut next_emit = s;
        let s_limit = src.len() as i32 - INPUT_MARGIN;
        let mut cv = load64(src, s);
        'outer: loop {
            const SKIP_LOG: i32 = 5;
            const DO_EVERY: i32 = 2;
            let mut next_s;
            let mut t;
            loop {
                let mut next_hash = hash_len(cv, TABLE_BITS, 5);
                let mut candidate = self.table[next_hash];
                next_s = s + DO_EVERY + ((s - next_emit) >> SKIP_LOG);
                if next_s > s_limit {
                    break 'outer;
                }
                let mut now = load64(src, next_s);
                self.table[next_hash] = s + cur;
                next_hash = hash_len(now, TABLE_BITS, 5);
                t = candidate - cur;
                if s - t < MAX_MATCH_OFFSET && cv as u32 == load32(src, t) {
                    self.table[next_hash] = next_s + cur;
                    break;
                }

                // Do one right away.
                cv = now;
                s = next_s;
                next_s += 1;
                candidate = self.table[next_hash];
                now >>= 8;
                self.table[next_hash] = s + cur;

                t = candidate - cur;
                if s - t < MAX_MATCH_OFFSET && cv as u32 == load32(src, t) {
                    self.table[next_hash] = next_s + cur;
                    break;
                }
                cv = now;
                s = next_s;
            }

            loop {
                let l = match_len_long(s + 4, t + 4, src) + 4;
                let (s2, _, l) = emit_match(dst, src, s, t, l, next_emit);
                s = s2 + l;
                next_emit = s;
                if next_s >= s {
                    s = next_s + 1;
                }
                if s >= s_limit {
                    if ((s + l + 8) as usize) < src.len() {
                        let cv = load64(src, s);
                        self.table[hash_len(cv, TABLE_BITS, 5)] = s + cur;
                    }
                    break 'outer;
                }

                let mut x = load64(src, s - 2);
                let o = cur + s - 2;
                let prev_hash = hash_len(x, TABLE_BITS, 5);
                self.table[prev_hash] = o;
                x >>= 16;
                let curr_hash = hash_len(x, TABLE_BITS, 5);
                let candidate = self.table[curr_hash];
                self.table[curr_hash] = o + 2;

                t = candidate - cur;
                if s - t > MAX_MATCH_OFFSET || x as u32 != load32(src, t) {
                    cv = x >> 8;
                    s += 1;
                    break;
                }
            }
        }
        emit_remainder(dst, src, next_emit);
    }
}

impl FastEnc for EncL1 {
    fn encode(&mut self, dst: &mut Tokens, src: &[u8]) {
        while self.g.cur >= BUFFER_RESET {
            if self.g.hist.is_empty() {
                self.table.fill(0);
                self.g.cur = MAX_MATCH_OFFSET;
                break;
            }
            let min_off = self.g.cur + self.g.hist.len() as i32 - MAX_MATCH_OFFSET;
            for v in self.table.iter_mut() {
                *v = rebase(*v, min_off, self.g.cur);
            }
            self.g.cur = MAX_MATCH_OFFSET;
        }
        let s = self.g.add_block(src);
        if src.len() < MIN_NON_LITERAL_BLOCK_SIZE {
            dst.n = src.len() as u16;
            return;
        }
        let hist = std::mem::take(&mut self.g.hist);
        self.run(dst, &hist, s);
        self.g.hist = hist;
    }

    fn reset(&mut self) {
        self.g.reset();
    }
}

// ---------------------------------------------------------------- level 2

const L2_TABLE_BITS: u32 = 17;
const L2_TABLE_SIZE: usize = 1 << L2_TABLE_BITS;

/// Level 2: one big table, 5-byte hashes, indexing about every 2 bytes.
struct EncL2 {
    g: FastGen,
    table: Vec<i32>,
}

impl EncL2 {
    fn new() -> Self {
        EncL2 {
            g: FastGen::new(),
            table: vec![0; L2_TABLE_SIZE],
        }
    }

    fn run(&mut self, dst: &mut Tokens, src: &[u8], mut s: i32) {
        let cur = self.g.cur;
        let mut next_emit = s;
        let s_limit = src.len() as i32 - INPUT_MARGIN;
        let mut cv = load64(src, s);
        'outer: loop {
            const SKIP_LOG: i32 = 5;
            const DO_EVERY: i32 = 2;
            let mut next_s = s;
            let mut candidate;
            loop {
                let mut next_hash = hash_len(cv, L2_TABLE_BITS, 5);
                s = next_s;
                next_s = s + DO_EVERY + ((s - next_emit) >> SKIP_LOG);
                if next_s > s_limit {
                    break 'outer;
                }
                candidate = self.table[next_hash];
                let mut now = load64(src, next_s);
                self.table[next_hash] = s + cur;
                next_hash = hash_len(now, L2_TABLE_BITS, 5);

                let mut offset = s - (candidate - cur);
                if offset < MAX_MATCH_OFFSET && cv as u32 == load32(src, candidate - cur) {
                    self.table[next_hash] = next_s + cur;
                    break;
                }

                // Do one right away.
                cv = now;
                s = next_s;
                next_s += 1;
                candidate = self.table[next_hash];
                now >>= 8;
                self.table[next_hash] = s + cur;

                offset = s - (candidate - cur);
                if offset < MAX_MATCH_OFFSET && cv as u32 == load32(src, candidate - cur) {
                    break;
                }
                cv = now;
            }

            loop {
                let t = candidate - cur;
                let l = match_len_long(s + 4, t + 4, src) + 4;
                let (s2, _, l) = emit_match(dst, src, s, t, l, next_emit);
                s = s2 + l;
                next_emit = s;
                if next_s >= s {
                    s = next_s + 1;
                }

                if s >= s_limit {
                    if ((s + l + 8) as usize) < src.len() {
                        let cv = load64(src, s);
                        self.table[hash_len(cv, L2_TABLE_BITS, 5)] = s + cur;
                    }
                    break 'outer;
                }

                // Store every 7th hash in-between.
                let mut i = s - l + 2;
                while i < s - 5 {
                    let mut x = load64(src, i);
                    self.table[hash_len(x, L2_TABLE_BITS, 5)] = cur + i;
                    x >>= 16;
                    self.table[hash_len(x, L2_TABLE_BITS, 5)] = cur + i + 2;
                    x >>= 16;
                    self.table[hash_len(x, L2_TABLE_BITS, 5)] = cur + i + 4;
                    i += 7;
                }

                let x = load64(src, s - 2);
                let o = cur + s - 2;
                let prev_hash = hash_len(x, L2_TABLE_BITS, 5);
                let prev_hash2 = hash_len(x >> 8, L2_TABLE_BITS, 5);
                self.table[prev_hash] = o;
                self.table[prev_hash2] = o + 1;
                let curr_hash = hash_len(x >> 16, L2_TABLE_BITS, 5);
                candidate = self.table[curr_hash];
                self.table[curr_hash] = o + 2;

                let offset = s - (candidate - cur);
                if offset > MAX_MATCH_OFFSET || (x >> 16) as u32 != load32(src, candidate - cur) {
                    cv = x >> 24;
                    s += 1;
                    break;
                }
            }
        }
        emit_remainder(dst, src, next_emit);
    }
}

impl FastEnc for EncL2 {
    fn encode(&mut self, dst: &mut Tokens, src: &[u8]) {
        while self.g.cur >= BUFFER_RESET {
            if self.g.hist.is_empty() {
                self.table.fill(0);
                self.g.cur = MAX_MATCH_OFFSET;
                break;
            }
            let min_off = self.g.cur + self.g.hist.len() as i32 - MAX_MATCH_OFFSET;
            for v in self.table.iter_mut() {
                *v = rebase(*v, min_off, self.g.cur);
            }
            self.g.cur = MAX_MATCH_OFFSET;
        }
        let s = self.g.add_block(src);
        if src.len() < MIN_NON_LITERAL_BLOCK_SIZE {
            dst.n = src.len() as u16;
            return;
        }
        let hist = std::mem::take(&mut self.g.hist);
        self.run(dst, &hist, s);
        self.g.hist = hist;
    }

    fn reset(&mut self) {
        self.g.reset();
    }
}

// ---------------------------------------------------------------- level 3

const L3_TABLE_BITS: u32 = 16;
const L3_TABLE_SIZE: usize = 1 << L3_TABLE_BITS;

/// An entry with the current and the previous offset.
type EntryPrev = [i32; 2];

/// Rebase both offsets of a two-candidate table entry independently.
fn rebase_prev_independent(e: &mut EntryPrev, min_off: i32, cur: i32) {
    e[0] = rebase(e[0], min_off, cur);
    e[1] = rebase(e[1], min_off, cur);
}

/// Rebase an entry whose previous offset is dropped with the current one.
fn rebase_prev_nested(e: &mut EntryPrev, min_off: i32, cur: i32) {
    if e[0] <= min_off {
        e[0] = 0;
        e[1] = 0;
    } else {
        e[0] = e[0] - cur + MAX_MATCH_OFFSET;
        e[1] = rebase(e[1], min_off, cur);
    }
}

/// Level 3: a medium table with two candidates per entry, 5-byte hashes.
struct EncL3 {
    g: FastGen,
    table: Vec<EntryPrev>,
}

impl EncL3 {
    fn new() -> Self {
        EncL3 {
            g: FastGen::new(),
            table: vec![[0; 2]; L3_TABLE_SIZE],
        }
    }

    fn run(&mut self, dst: &mut Tokens, src: &[u8], mut s: i32) {
        let cur = self.g.cur;
        let mut next_emit = s;
        let s_limit = src.len() as i32 - INPUT_MARGIN;
        let mut cv = load64(src, s);
        'outer: loop {
            const SKIP_LOG: i32 = 7;
            let mut next_s = s;
            let mut candidate;
            loop {
                let next_hash = hash_len(cv, L3_TABLE_BITS, 5);
                s = next_s;
                next_s = s + 1 + ((s - next_emit) >> SKIP_LOG);
                if next_s > s_limit {
                    break 'outer;
                }
                let candidates = self.table[next_hash];
                let now = load64(src, next_s);

                let min_offset = cur + s - (MAX_MATCH_OFFSET - 4);
                self.table[next_hash] = [s + cur, candidates[0]];

                candidate = candidates[0];
                if candidate < min_offset {
                    cv = now;
                    continue;
                }

                if cv as u32 == load32(src, candidate - cur) {
                    if candidates[1] < min_offset || cv as u32 != load32(src, candidates[1] - cur) {
                        break;
                    }
                    // Both candidates match; take the longer.
                    let offset = s - (candidate - cur);
                    let o2 = s - (candidates[1] - cur);
                    let l1 = match_len(&src[(s + 4) as usize..], &src[(s - offset + 4) as usize..]);
                    let l2 = match_len(&src[(s + 4) as usize..], &src[(s - o2 + 4) as usize..]);
                    if l2 > l1 {
                        candidate = candidates[1];
                    }
                    break;
                } else {
                    candidate = candidates[1];
                    if candidate > min_offset && cv as u32 == load32(src, candidate - cur) {
                        break;
                    }
                }
                cv = now;
            }

            loop {
                let t = candidate - cur;
                let l = match_len_long(s + 4, t + 4, src) + 4;
                let (s2, mut t, l) = emit_match(dst, src, s, t, l, next_emit);
                s = s2 + l;
                next_emit = s;
                if next_s >= s {
                    s = next_s + 1;
                }

                if s >= s_limit {
                    t += l;
                    // Index the position after the match end.
                    if ((t + 8) as usize) < src.len() && t > 0 {
                        cv = load64(src, t);
                        let next_hash = hash_len(cv, L3_TABLE_BITS, 5);
                        self.table[next_hash] = [cur + t, self.table[next_hash][0]];
                    }
                    break 'outer;
                }

                // Store every 6th hash in-between.
                let mut i = s - l + 2;
                while i < s - 5 {
                    let next_hash = hash_len(load64(src, i), L3_TABLE_BITS, 5);
                    self.table[next_hash] = [cur + i, self.table[next_hash][0]];
                    i += 6;
                }

                let mut x = load64(src, s - 2);
                let mut prev_hash = hash_len(x, L3_TABLE_BITS, 5);
                self.table[prev_hash] = [cur + s - 2, self.table[prev_hash][0]];
                x >>= 8;
                prev_hash = hash_len(x, L3_TABLE_BITS, 5);
                self.table[prev_hash] = [cur + s - 1, self.table[prev_hash][0]];
                x >>= 8;
                let curr_hash = hash_len(x, L3_TABLE_BITS, 5);
                let candidates = self.table[curr_hash];
                cv = x;
                self.table[curr_hash] = [s + cur, candidates[0]];

                candidate = candidates[0];
                let min_offset = cur + s - (MAX_MATCH_OFFSET - 4);

                if candidate > min_offset {
                    if cv as u32 == load32(src, candidate - cur) {
                        continue;
                    }
                    candidate = candidates[1];
                    if candidate > min_offset && cv as u32 == load32(src, candidate - cur) {
                        continue;
                    }
                }
                cv = x >> 8;
                s += 1;
                break;
            }
        }
        emit_remainder(dst, src, next_emit);
    }
}

impl FastEnc for EncL3 {
    fn encode(&mut self, dst: &mut Tokens, src: &[u8]) {
        while self.g.cur >= BUFFER_RESET {
            if self.g.hist.is_empty() {
                self.table.fill([0; 2]);
                self.g.cur = MAX_MATCH_OFFSET;
                break;
            }
            let min_off = self.g.cur + self.g.hist.len() as i32 - MAX_MATCH_OFFSET;
            for e in self.table.iter_mut() {
                rebase_prev_independent(e, min_off, self.g.cur);
            }
            self.g.cur = MAX_MATCH_OFFSET;
        }
        let s = self.g.add_block(src);
        if src.len() < MIN_NON_LITERAL_BLOCK_SIZE {
            dst.n = src.len() as u16;
            return;
        }
        let hist = std::mem::take(&mut self.g.hist);
        self.run(dst, &hist, s);
        self.g.hist = hist;
    }

    fn reset(&mut self) {
        self.g.reset();
    }
}

// ---------------------------------------------------------------- level 4

/// Level 4: two tables, 4- and 7-byte hashes, one candidate per entry.
struct EncL4 {
    g: FastGen,
    table: Vec<i32>,
    b_table: Vec<i32>,
}

impl EncL4 {
    fn new() -> Self {
        EncL4 {
            g: FastGen::new(),
            table: vec![0; TABLE_SIZE],
            b_table: vec![0; TABLE_SIZE],
        }
    }

    fn run(&mut self, dst: &mut Tokens, src: &[u8], mut s: i32) {
        let cur = self.g.cur;
        let mut next_emit = s;
        let s_limit = src.len() as i32 - INPUT_MARGIN;
        let mut cv = load64(src, s);
        'outer: loop {
            const SKIP_LOG: i32 = 6;
            const DO_EVERY: i32 = 1;
            let mut next_s = s;
            let mut t;
            loop {
                let next_hash_s = hash_len(cv, TABLE_BITS, HASH_SHORT_BYTES);
                let next_hash_l = hash_len(cv, TABLE_BITS, HASH_LONG_BYTES);

                s = next_s;
                next_s = s + DO_EVERY + ((s - next_emit) >> SKIP_LOG);
                if next_s > s_limit {
                    break 'outer;
                }
                let s_candidate = self.table[next_hash_s];
                let mut l_candidate = self.b_table[next_hash_l];
                let next = load64(src, next_s);
                let entry = s + cur;
                self.table[next_hash_s] = entry;
                self.b_table[next_hash_l] = entry;

                t = l_candidate - cur;
                if s - t < MAX_MATCH_OFFSET && cv as u32 == load32(src, t) {
                    // The long candidate matched; take it.
                    break;
                }

                t = s_candidate - cur;
                if s - t < MAX_MATCH_OFFSET && cv as u32 == load32(src, t) {
                    // The short candidate matched; check for a longer match
                    // at the next position.
                    l_candidate = self.b_table[hash_len(next, TABLE_BITS, HASH_LONG_BYTES)];

                    let l_off = l_candidate - cur;
                    if next_s - l_off < MAX_MATCH_OFFSET && load32(src, l_off) == next as u32 {
                        let l1 = match_len(&src[(s + 4) as usize..], &src[(t + 4) as usize..]);
                        let l2 = match_len(
                            &src[(next_s + 4) as usize..],
                            &src[(next_s - l_off + 4) as usize..],
                        );
                        if l2 > l1 {
                            s = next_s;
                            t = l_candidate - cur;
                        }
                    }
                    break;
                }
                cv = next;
            }

            let l = match_len_long(s + 4, t + 4, src) + 4;
            let (s2, _, l) = emit_match(dst, src, s, t, l, next_emit);
            s = s2 + l;
            next_emit = s;
            if next_s >= s {
                s = next_s + 1;
            }

            if s >= s_limit {
                // Index first pair after match end.
                if ((s + 8) as usize) < src.len() {
                    let cv = load64(src, s);
                    self.table[hash_len(cv, TABLE_BITS, HASH_SHORT_BYTES)] = s + cur;
                    self.b_table[hash_len(cv, TABLE_BITS, HASH_LONG_BYTES)] = s + cur;
                }
                break 'outer;
            }

            // Store every 3rd hash in-between.
            let mut i = next_s;
            if i < s - 1 {
                let cv = load64(src, i);
                let t = i + cur;
                let t2 = t + 1;
                self.b_table[hash_len(cv, TABLE_BITS, HASH_LONG_BYTES)] = t;
                self.b_table[hash_len(cv >> 8, TABLE_BITS, HASH_LONG_BYTES)] = t2;
                self.table[hash_len(cv >> 8, TABLE_BITS, HASH_SHORT_BYTES)] = t2;

                i += 3;
                while i < s - 1 {
                    let cv = load64(src, i);
                    let t = i + cur;
                    let t2 = t + 1;
                    self.b_table[hash_len(cv, TABLE_BITS, HASH_LONG_BYTES)] = t;
                    self.b_table[hash_len(cv >> 8, TABLE_BITS, HASH_LONG_BYTES)] = t2;
                    self.table[hash_len(cv >> 8, TABLE_BITS, HASH_SHORT_BYTES)] = t2;
                    i += 3;
                }
            }

            // Index the last pair.
            let x = load64(src, s - 1);
            let o = cur + s - 1;
            let prev_hash_s = hash_len(x, TABLE_BITS, HASH_SHORT_BYTES);
            let prev_hash_l = hash_len(x, TABLE_BITS, HASH_LONG_BYTES);
            self.table[prev_hash_s] = o;
            self.b_table[prev_hash_l] = o;
            cv = x >> 8;
        }
        emit_remainder(dst, src, next_emit);
    }
}

impl FastEnc for EncL4 {
    fn encode(&mut self, dst: &mut Tokens, src: &[u8]) {
        while self.g.cur >= BUFFER_RESET {
            if self.g.hist.is_empty() {
                self.table.fill(0);
                self.b_table.fill(0);
                self.g.cur = MAX_MATCH_OFFSET;
                break;
            }
            let min_off = self.g.cur + self.g.hist.len() as i32 - MAX_MATCH_OFFSET;
            for v in self.table.iter_mut() {
                *v = rebase(*v, min_off, self.g.cur);
            }
            for v in self.b_table.iter_mut() {
                *v = rebase(*v, min_off, self.g.cur);
            }
            self.g.cur = MAX_MATCH_OFFSET;
        }
        let s = self.g.add_block(src);
        if src.len() < MIN_NON_LITERAL_BLOCK_SIZE {
            dst.n = src.len() as u16;
            return;
        }
        let hist = std::mem::take(&mut self.g.hist);
        self.run(dst, &hist, s);
        self.g.hist = hist;
    }

    fn reset(&mut self) {
        self.g.reset();
    }
}

// ------------------------------------------------------------ levels 5, 6

/// Push `entry` as the newest offset of a two-candidate entry.
#[inline]
fn push_prev(e: &mut EntryPrev, entry: i32) {
    *e = [entry, e[0]];
}

/// Level 5: two tables, 4- and 7-byte hashes, two candidates per 7-byte entry.
struct EncL5 {
    g: FastGen,
    table: Vec<i32>,
    b_table: Vec<EntryPrev>,
}

impl EncL5 {
    fn new() -> Self {
        EncL5 {
            g: FastGen::new(),
            table: vec![0; TABLE_SIZE],
            b_table: vec![[0; 2]; TABLE_SIZE],
        }
    }

    fn run(&mut self, dst: &mut Tokens, src: &[u8], mut s: i32) {
        let cur = self.g.cur;
        let mut next_emit = s;
        let s_limit = src.len() as i32 - INPUT_MARGIN;
        let mut cv = load64(src, s);
        'outer: loop {
            const SKIP_LOG: i32 = 6;
            const DO_EVERY: i32 = 1;
            let mut next_s = s;
            let mut l: i32 = 0;
            let mut t;
            loop {
                let next_hash_s = hash_len(cv, TABLE_BITS, HASH_SHORT_BYTES);
                let next_hash_l = hash_len(cv, TABLE_BITS, HASH_LONG_BYTES);

                s = next_s;
                next_s = s + DO_EVERY + ((s - next_emit) >> SKIP_LOG);
                if next_s > s_limit {
                    break 'outer;
                }
                let s_candidate = self.table[next_hash_s];
                let mut l_candidate = self.b_table[next_hash_l];
                let next = load64(src, next_s);
                let entry = s + cur;
                self.table[next_hash_s] = entry;
                push_prev(&mut self.b_table[next_hash_l], entry);

                let next_hash_s = hash_len(next, TABLE_BITS, HASH_SHORT_BYTES);
                let next_hash_l = hash_len(next, TABLE_BITS, HASH_LONG_BYTES);

                t = l_candidate[0] - cur;
                if s - t < MAX_MATCH_OFFSET {
                    if cv as u32 == load32(src, t) {
                        // Store the next match.
                        self.table[next_hash_s] = next_s + cur;
                        push_prev(&mut self.b_table[next_hash_l], next_s + cur);

                        let t2 = l_candidate[1] - cur;
                        if s - t2 < MAX_MATCH_OFFSET && cv as u32 == load32(src, t2) {
                            l = match_len_limited(s + 4, t + 4, src) + 4;
                            let ml1 = match_len_limited(s + 4, t2 + 4, src) + 4;
                            if ml1 > l {
                                t = t2;
                                l = ml1;
                                break;
                            }
                        }
                        break;
                    }
                    t = l_candidate[1] - cur;
                    if s - t < MAX_MATCH_OFFSET && cv as u32 == load32(src, t) {
                        // Store the next match.
                        self.table[next_hash_s] = next_s + cur;
                        push_prev(&mut self.b_table[next_hash_l], next_s + cur);
                        break;
                    }
                }

                t = s_candidate - cur;
                if s - t < MAX_MATCH_OFFSET && cv as u32 == load32(src, t) {
                    // Found a 4-byte match; check for a longer one at s+1.
                    l = match_len_limited(s + 4, t + 4, src) + 4;
                    l_candidate = self.b_table[next_hash_l];

                    self.table[next_hash_s] = next_s + cur;
                    push_prev(&mut self.b_table[next_hash_l], next_s + cur);

                    let mut t2 = l_candidate[0] - cur;
                    if next_s - t2 < MAX_MATCH_OFFSET {
                        if load32(src, t2) == next as u32 {
                            let ml = match_len_limited(next_s + 4, t2 + 4, src) + 4;
                            if ml > l {
                                t = t2;
                                s = next_s;
                                l = ml;
                                break;
                            }
                        }
                        t2 = l_candidate[1] - cur;
                        if next_s - t2 < MAX_MATCH_OFFSET && load32(src, t2) == next as u32 {
                            let ml = match_len_limited(next_s + 4, t2 + 4, src) + 4;
                            if ml > l {
                                t = t2;
                                s = next_s;
                                l = ml;
                                break;
                            }
                        }
                    }
                    break;
                }
                cv = next;
            }

            // A 4-byte match has been found; extend it.
            if l == 0 {
                l = match_len_long(s + 4, t + 4, src) + 4;
            } else if l == MAX_MATCH_LENGTH {
                l += match_len_long(s + l, t + l, src);
            }

            // Try to locate a better match by checking the end of the best one.
            let s_at = s + l;
            if l < 30 && s_at < s_limit {
                const SKIP_BEGINNING: i32 = 2;
                let e_long =
                    self.b_table[hash_len(load64(src, s_at), TABLE_BITS, HASH_LONG_BYTES)][0];
                let t2 = e_long - cur - l + SKIP_BEGINNING;
                let s2 = s + SKIP_BEGINNING;
                let off = s2 - t2;
                if t2 >= 0 && off < MAX_MATCH_OFFSET && off > 0 {
                    let l2 = match_len_long(s2, t2, src);
                    if l2 > l {
                        t = t2;
                        l = l2;
                        s = s2;
                    }
                }
            }

            let (s2, _, l) = emit_match(dst, src, s, t, l, next_emit);
            s = s2 + l;
            next_emit = s;
            if next_s >= s {
                s = next_s + 1;
            }

            if s >= s_limit {
                break 'outer;
            }

            // Store every 3rd hash in-between.
            const HASH_EVERY: i32 = 3;
            let mut i = s - l + 1;
            if i < s - 1 {
                let mut cv = load64(src, i);
                let mut t = i + cur;
                self.table[hash_len(cv, TABLE_BITS, HASH_SHORT_BYTES)] = t;
                push_prev(
                    &mut self.b_table[hash_len(cv, TABLE_BITS, HASH_LONG_BYTES)],
                    t,
                );

                // Do an long at i+1.
                cv >>= 8;
                t += 1;
                push_prev(
                    &mut self.b_table[hash_len(cv, TABLE_BITS, HASH_LONG_BYTES)],
                    t,
                );

                // i+2 and i+3 are covered by the short hash only.
                cv >>= 8;
                t += 1;
                self.table[hash_len(cv, TABLE_BITS, HASH_SHORT_BYTES)] = t;

                i += 4;
                while i < s - 1 {
                    let cv = load64(src, i);
                    let t = i + cur;
                    let t2 = t + 1;
                    push_prev(
                        &mut self.b_table[hash_len(cv, TABLE_BITS, HASH_LONG_BYTES)],
                        t,
                    );
                    self.table[hash_len(cv >> 8, TABLE_BITS, HASH_SHORT_BYTES)] = t2;
                    i += HASH_EVERY;
                }
            }

            // Index the last pair.
            let x = load64(src, s - 1);
            let o = cur + s - 1;
            let prev_hash_s = hash_len(x, TABLE_BITS, HASH_SHORT_BYTES);
            let prev_hash_l = hash_len(x, TABLE_BITS, HASH_LONG_BYTES);
            self.table[prev_hash_s] = o;
            push_prev(&mut self.b_table[prev_hash_l], o);
            cv = x >> 8;
        }
        emit_remainder(dst, src, next_emit);
    }
}

impl FastEnc for EncL5 {
    fn encode(&mut self, dst: &mut Tokens, src: &[u8]) {
        while self.g.cur >= BUFFER_RESET {
            if self.g.hist.is_empty() {
                self.table.fill(0);
                self.b_table.fill([0; 2]);
                self.g.cur = MAX_MATCH_OFFSET;
                break;
            }
            let min_off = self.g.cur + self.g.hist.len() as i32 - MAX_MATCH_OFFSET;
            for v in self.table.iter_mut() {
                *v = rebase(*v, min_off, self.g.cur);
            }
            for e in self.b_table.iter_mut() {
                rebase_prev_nested(e, min_off, self.g.cur);
            }
            self.g.cur = MAX_MATCH_OFFSET;
        }
        let s = self.g.add_block(src);
        if src.len() < MIN_NON_LITERAL_BLOCK_SIZE {
            dst.n = src.len() as u16;
            return;
        }
        let hist = std::mem::take(&mut self.g.hist);
        self.run(dst, &hist, s);
        self.g.hist = hist;
    }

    fn reset(&mut self) {
        self.g.reset();
    }
}

/// Level 6: two tables, 4- and 7-byte hashes, full indexing, repeat checks.
struct EncL6 {
    g: FastGen,
    table: Vec<i32>,
    b_table: Vec<EntryPrev>,
}

impl EncL6 {
    fn new() -> Self {
        EncL6 {
            g: FastGen::new(),
            table: vec![0; TABLE_SIZE],
            b_table: vec![[0; 2]; TABLE_SIZE],
        }
    }

    fn run(&mut self, dst: &mut Tokens, src: &[u8], mut s: i32) {
        let cur = self.g.cur;
        let mut next_emit = s;
        let s_limit = src.len() as i32 - INPUT_MARGIN;
        let mut cv = load64(src, s);
        // The distance of the previous match, to test for repeats.
        let mut repeat: i32 = 1;
        'outer: loop {
            const SKIP_LOG: i32 = 7;
            const DO_EVERY: i32 = 1;
            let mut next_s = s;
            let mut l: i32 = 0;
            let mut t;
            loop {
                let next_hash_s = hash_len(cv, TABLE_BITS, HASH_SHORT_BYTES);
                let next_hash_l = hash_len(cv, TABLE_BITS, HASH_LONG_BYTES);
                s = next_s;
                next_s = s + DO_EVERY + ((s - next_emit) >> SKIP_LOG);
                if next_s > s_limit {
                    break 'outer;
                }
                let s_candidate = self.table[next_hash_s];
                let mut l_candidate = self.b_table[next_hash_l];
                let next = load64(src, next_s);
                let entry = s + cur;
                self.table[next_hash_s] = entry;
                push_prev(&mut self.b_table[next_hash_l], entry);

                let next_hash_s = hash_len(next, TABLE_BITS, HASH_SHORT_BYTES);
                let next_hash_l = hash_len(next, TABLE_BITS, HASH_LONG_BYTES);

                t = l_candidate[0] - cur;
                if s - t < MAX_MATCH_OFFSET {
                    if cv as u32 == load32(src, t) {
                        // Long candidate matches at least 4 bytes.
                        self.table[next_hash_s] = next_s + cur;
                        push_prev(&mut self.b_table[next_hash_l], next_s + cur);

                        // Check the previous long candidate as well.
                        let t2 = l_candidate[1] - cur;
                        if s - t2 < MAX_MATCH_OFFSET && cv as u32 == load32(src, t2) {
                            l = match_len_limited(s + 4, t + 4, src) + 4;
                            let ml1 = match_len_limited(s + 4, t2 + 4, src) + 4;
                            if ml1 > l {
                                t = t2;
                                l = ml1;
                                break;
                            }
                        }
                        break;
                    }
                    // Current value did not match, but check if previous long value does.
                    t = l_candidate[1] - cur;
                    if s - t < MAX_MATCH_OFFSET && cv as u32 == load32(src, t) {
                        self.table[next_hash_s] = next_s + cur;
                        push_prev(&mut self.b_table[next_hash_l], next_s + cur);
                        break;
                    }
                }

                t = s_candidate - cur;
                if s - t < MAX_MATCH_OFFSET && cv as u32 == load32(src, t) {
                    // Found a 4-byte match; check for a longer one at s+1.
                    l = match_len_limited(s + 4, t + 4, src) + 4;

                    // Look at the next position.
                    l_candidate = self.b_table[next_hash_l];

                    self.table[next_hash_s] = next_s + cur;
                    push_prev(&mut self.b_table[next_hash_l], next_s + cur);

                    // Check repeat at s + repOff.
                    const REP_OFF: i32 = 1;
                    let mut t2 = s - repeat + REP_OFF;
                    if load32(src, t2) == (cv >> (8 * REP_OFF)) as u32 {
                        let ml = match_len_limited(s + 4 + REP_OFF, t2 + 4, src) + 4;
                        if ml > l {
                            t = t2;
                            l = ml;
                            s += REP_OFF;
                            // Not worth checking more.
                            break;
                        }
                    }

                    // If the next long is a candidate, use that.
                    t2 = l_candidate[0] - cur;
                    if next_s - t2 < MAX_MATCH_OFFSET {
                        if load32(src, t2) == next as u32 {
                            let ml = match_len_limited(next_s + 4, t2 + 4, src) + 4;
                            if ml > l {
                                t = t2;
                                s = next_s;
                                l = ml;
                                // This is ok, but check previous as well.
                            }
                        }
                        // If the previous long is a candidate, use that.
                        t2 = l_candidate[1] - cur;
                        if next_s - t2 < MAX_MATCH_OFFSET && load32(src, t2) == next as u32 {
                            let ml = match_len_limited(next_s + 4, t2 + 4, src) + 4;
                            if ml > l {
                                t = t2;
                                s = next_s;
                                l = ml;
                                break;
                            }
                        }
                    }
                    break;
                }
                cv = next;
            }

            // A 4-byte match has been found; extend it.
            if l == 0 {
                l = match_len_long(s + 4, t + 4, src) + 4;
            } else if l == MAX_MATCH_LENGTH {
                l += match_len_long(s + l, t + l, src);
            }

            // Try to locate a better match by checking the end of the best one.
            let s_at = s + l;
            if s_at < s_limit {
                const SKIP_BEGINNING: i32 = 2;
                let e_long = self.b_table[hash_len(load64(src, s_at), TABLE_BITS, HASH_LONG_BYTES)];
                // Test current
                let t2 = e_long[0] - cur - l + SKIP_BEGINNING;
                let s2 = s + SKIP_BEGINNING;
                let off = s2 - t2;
                if off < MAX_MATCH_OFFSET {
                    if off > 0 && t2 >= 0 {
                        let l2 = match_len_long(s2, t2, src);
                        if l2 > l {
                            t = t2;
                            l = l2;
                            s = s2;
                        }
                    }
                    // Test previous entry.
                    let t2 = e_long[1] - cur - l + SKIP_BEGINNING;
                    let off = s2 - t2;
                    if off > 0 && off < MAX_MATCH_OFFSET && t2 >= 0 {
                        let l2 = match_len_long(s2, t2, src);
                        if l2 > l {
                            t = t2;
                            l = l2;
                            s = s2;
                        }
                    }
                }
            }

            let (s2, t2, l) = emit_match(dst, src, s, t, l, next_emit);
            repeat = s2 - t2;
            s = s2 + l;
            next_emit = s;
            if next_s >= s {
                s = next_s + 1;
            }

            if s >= s_limit {
                // Index after the match end before leaving.
                let mut i = next_s + 1;
                while i < src.len() as i32 - 8 {
                    let cv = load64(src, i);
                    self.table[hash_len(cv, TABLE_BITS, HASH_SHORT_BYTES)] = i + cur;
                    push_prev(
                        &mut self.b_table[hash_len(cv, TABLE_BITS, HASH_LONG_BYTES)],
                        i + cur,
                    );
                    i += 2;
                }
                break 'outer;
            }

            // Store every long hash in-between and every second short hash.
            let mut i = next_s + 1;
            while i < s - 1 {
                let cv = load64(src, i);
                let t = i + cur;
                let t2 = t + 1;
                let h1 = hash_len(cv, TABLE_BITS, HASH_LONG_BYTES);
                let h2 = hash_len(cv >> 8, TABLE_BITS, HASH_LONG_BYTES);
                self.table[hash_len(cv, TABLE_BITS, HASH_SHORT_BYTES)] = t;
                push_prev(&mut self.b_table[h1], t);
                push_prev(&mut self.b_table[h2], t2);
                i += 2;
            }
            cv = load64(src, s);
        }
        emit_remainder(dst, src, next_emit);
    }
}

impl FastEnc for EncL6 {
    fn encode(&mut self, dst: &mut Tokens, src: &[u8]) {
        while self.g.cur >= BUFFER_RESET {
            if self.g.hist.is_empty() {
                self.table.fill(0);
                self.b_table.fill([0; 2]);
                self.g.cur = MAX_MATCH_OFFSET;
                break;
            }
            let min_off = self.g.cur + self.g.hist.len() as i32 - MAX_MATCH_OFFSET;
            for v in self.table.iter_mut() {
                *v = rebase(*v, min_off, self.g.cur);
            }
            for e in self.b_table.iter_mut() {
                rebase_prev_nested(e, min_off, self.g.cur);
            }
            self.g.cur = MAX_MATCH_OFFSET;
        }
        let s = self.g.add_block(src);
        if src.len() < MIN_NON_LITERAL_BLOCK_SIZE {
            dst.n = src.len() as u16;
            return;
        }
        let hist = std::mem::take(&mut self.g.hist);
        self.run(dst, &hist, s);
        self.g.hist = hist;
    }

    fn reset(&mut self) {
        self.g.reset();
    }
}
