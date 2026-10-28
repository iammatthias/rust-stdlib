//! DEFLATE encoder, a port of Go's `compress/flate` compressor
//! (`deflate.go`) so that the bytes it produces are Go's bytes.
//!
//! Level 0 stores, level -2 only Huffman-codes, levels 1 to 6 use the
//! single-pass matchers of [`super::fastenc`] and levels 7 to 9 use hash
//! chains with lazy matching. Blocks are written by [`super::bitwriter`].
//! History, hash tables and the Huffman table persist across `Write` and
//! `Flush` calls; only `Reset` clears them.
use super::bitwriter::BitWriter;
use super::fastenc::{fast_encoder, match_len, FastEnc, MAX_STORE_BLOCK_SIZE};
use super::huffman::HuffmanEncoder;
use super::token::{offset_code, Tokens, LENGTH_CODES, LENGTH_EXTRA_BITS, OFFSET_EXTRA_BITS};
use super::{DEFAULT_COMPRESSION, HUFFMAN_ONLY, NO_COMPRESSION};
use std::io::{self, Write};

const WINDOW_SIZE: i32 = 1 << 15;
const WINDOW_MASK: i32 = WINDOW_SIZE - 1;
const MIN_MATCH_LENGTH: i32 = 4;
const MAX_MATCH_LENGTH: i32 = 258;
const MIN_OFFSET_SIZE: i32 = 1;
const MAX_FLATE_BLOCK_TOKENS: u16 = 1 << 15;
const HASH_BITS: u32 = 17;
const HASH_SIZE: usize = 1 << HASH_BITS;
const MAX_HASH_OFFSET: i32 = 1 << 28;
const MAX_MATCH_OFFSET: usize = 1 << 15;
const PRIME4BYTES: u32 = 2654435761;

/// Parameters of levels 7 to 9.
#[derive(Clone, Copy, Default)]
struct CompressionLevel {
    lazy: i32,
    nice: i32,
    chain: i32,
}

const LEVELS: [CompressionLevel; 3] = [
    CompressionLevel {
        lazy: 12,
        nice: 16,
        chain: 24,
    },
    CompressionLevel {
        lazy: 30,
        nice: 40,
        chain: 64,
    },
    CompressionLevel {
        lazy: 258,
        nice: 258,
        chain: 1024,
    },
];

/// State of levels 7 to 9.
struct AdvancedState {
    length: i32,
    offset: i32,
    max_insert_index: i32,
    chain_head: i32,
    hash_offset: i32,
    /// Consecutive literal count; wraps like Go's `uint16`.
    literal_counter: u16,
    /// Unprocessed data is `window[index..window_end]`.
    index: i32,
    /// `hash_head[h]` is the largest input index with hash `h`; if it is
    /// within the window, `hash_prev[head & WINDOW_MASK]` is the previous
    /// index with the same hash.
    hash_head: Vec<i32>,
    hash_prev: Vec<i32>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    Store,
    Huff,
    Fast,
    Lazy,
}

/// The compressor state behind [`super::Writer`].
pub(crate) struct Compressor {
    level: i32,
    params: CompressionLevel,
    /// Literal Huffman coder used to estimate literal cost at level 9.
    h: Option<HuffmanEncoder>,
    w: BitWriter,
    step: Step,
    window: Vec<u8>,
    window_end: i32,
    block_start: i32,
    tokens: Tokens,
    fast: Option<Box<dyn FastEnc>>,
    state: Option<Box<AdvancedState>>,
    sync: bool,
    byte_available: bool,
}

#[inline]
fn hash4(b: &[u8]) -> usize {
    let u = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    (u.wrapping_mul(PRIME4BYTES) >> (32 - HASH_BITS)) as usize
}

impl Compressor {
    /// `level` must already be validated to lie in `[-2, 9]`.
    pub(crate) fn new(level: i32) -> Self {
        let mut d = Compressor {
            level,
            params: CompressionLevel::default(),
            h: None,
            w: BitWriter::new(),
            step: Step::Store,
            window: Vec::new(),
            window_end: 0,
            block_start: 0,
            tokens: Tokens::new(),
            fast: None,
            state: None,
            sync: false,
            byte_available: false,
        };
        let mut level = level;
        if level == NO_COMPRESSION {
            d.window = vec![0; MAX_STORE_BLOCK_SIZE];
            d.step = Step::Store;
        } else if level == HUFFMAN_ONLY {
            d.w.log_new_table_penalty = 10;
            d.window = vec![0; 32 << 10];
            d.step = Step::Huff;
        } else {
            if level == DEFAULT_COMPRESSION {
                level = 6;
            }
            if (1..=6).contains(&level) {
                d.w.log_new_table_penalty = 7;
                d.fast = Some(fast_encoder(level));
                d.window = vec![0; MAX_STORE_BLOCK_SIZE];
                d.step = Step::Fast;
            } else {
                d.w.log_new_table_penalty = 8;
                d.state = Some(Box::new(AdvancedState {
                    length: 0,
                    offset: 0,
                    max_insert_index: 0,
                    chain_head: 0,
                    hash_offset: 0,
                    literal_counter: 0,
                    index: 0,
                    hash_head: vec![0; HASH_SIZE],
                    hash_prev: vec![0; WINDOW_SIZE as usize],
                }));
                d.params = LEVELS[(level - 7) as usize];
                d.window = vec![0; 2 * WINDOW_SIZE as usize];
                d.byte_available = false;
                if let Some(s) = d.state.as_mut() {
                    s.index = 0;
                    s.hash_offset = 1;
                    s.length = MIN_MATCH_LENGTH - 1;
                    s.offset = 0;
                    s.chain_head = -1;
                }
                d.step = Step::Lazy;
            }
            d.level = level;
        }
        d
    }

    pub(crate) fn reset(&mut self) {
        self.w.reset();
        self.sync = false;
        self.window_end = 0;
        if let Some(fast) = self.fast.as_mut() {
            fast.reset();
            self.tokens.reset();
            return;
        }
        if self.params.chain == 0 {
            return;
        }
        if let Some(s) = self.state.as_mut() {
            s.chain_head = -1;
            s.hash_head.fill(0);
            s.hash_prev.fill(0);
            s.hash_offset = 1;
            s.index = 0;
            s.length = MIN_MATCH_LENGTH - 1;
            s.offset = 0;
            s.literal_counter = 0;
            s.max_insert_index = 0;
        }
        self.block_start = 0;
        self.byte_available = false;
        self.tokens.reset();
    }

    /// Prime the window with a preset dictionary without producing output.
    pub(crate) fn fill_window(&mut self, dict: &[u8]) {
        if self.level <= 0 {
            return;
        }
        if let Some(fast) = self.fast.as_mut() {
            // Encode the last data, but discard the result.
            let dict = &dict[dict.len().saturating_sub(MAX_MATCH_OFFSET)..];
            fast.encode(&mut self.tokens, dict);
            self.tokens.reset();
            return;
        }
        let Some(s) = self.state.as_mut() else {
            return;
        };
        let dict = &dict[dict.len().saturating_sub(WINDOW_SIZE as usize)..];
        let at = self.window_end as usize;
        self.window[at..at + dict.len()].copy_from_slice(dict);
        let n = dict.len() as i32;
        // Hash every position that has four bytes after it.
        for di in 0..=(n - MIN_MATCH_LENGTH) {
            let h = hash4(&self.window[di as usize..]);
            s.hash_prev[(di & WINDOW_MASK) as usize] = s.hash_head[h];
            s.hash_head[h] = di + s.hash_offset;
        }
        self.window_end += n;
        s.index = n;
    }

    fn fill(&mut self, b: &[u8]) -> usize {
        if self.step != Step::Lazy {
            return self.fill_block(b);
        }
        let s = self.state.as_mut().expect("levels 7-9 have state");
        if s.index >= 2 * WINDOW_SIZE - (MIN_MATCH_LENGTH + MAX_MATCH_LENGTH) {
            // Shift the window by one window size.
            self.window
                .copy_within(WINDOW_SIZE as usize..2 * WINDOW_SIZE as usize, 0);
            s.index -= WINDOW_SIZE;
            self.window_end -= WINDOW_SIZE;
            if self.block_start >= WINDOW_SIZE {
                self.block_start -= WINDOW_SIZE;
            } else {
                self.block_start = i32::MAX;
            }
            s.hash_offset += WINDOW_SIZE;
            if s.hash_offset > MAX_HASH_OFFSET {
                let delta = s.hash_offset - 1;
                s.hash_offset -= delta;
                s.chain_head -= delta;
                for v in s.hash_prev.iter_mut() {
                    *v = (*v - delta).max(0);
                }
                for v in s.hash_head.iter_mut() {
                    *v = (*v - delta).max(0);
                }
            }
        }
        let at = self.window_end as usize;
        let n = b.len().min(self.window.len() - at);
        self.window[at..at + n].copy_from_slice(&b[..n]);
        self.window_end += n as i32;
        n
    }

    fn fill_block(&mut self, b: &[u8]) -> usize {
        let at = self.window_end as usize;
        let n = b.len().min(self.window.len() - at);
        self.window[at..at + n].copy_from_slice(&b[..n]);
        self.window_end += n as i32;
        n
    }

    fn run_step(&mut self) {
        match self.step {
            Step::Store => self.store(),
            Step::Huff => self.deflate_huff(),
            Step::Fast => self.deflate_fast(),
            Step::Lazy => self.deflate_lazy(),
        }
    }

    /// Write the tokens as a block; `index` is where the block ends in the
    /// window.
    fn write_block(&mut self, index: i32, eof: bool) {
        if index > 0 || eof {
            let window = if self.block_start <= index {
                Some(&self.window[self.block_start as usize..index as usize])
            } else {
                None
            };
            self.block_start = index;
            self.w
                .write_block_dynamic(&mut self.tokens, eof, window, self.sync);
        }
    }

    fn write_stored_block(&mut self, end: usize) {
        self.w.write_stored_header(end, false);
        self.w.write_bytes(&self.window[..end]);
    }

    /// Find the longest match at `pos` in the hash chain that starts at
    /// `prev_head`, searching up to `chain` entries.
    fn find_match(
        &self,
        s: &AdvancedState,
        pos: i32,
        prev_head: i32,
        lookahead: i32,
    ) -> Option<(i32, i32)> {
        let min_match_look = lookahead.min(MAX_MATCH_LENGTH);
        let win = &self.window[..(pos + min_match_look) as usize];

        // Quit when a match at least this long is found.
        let nice = self.params.nice.min(win.len() as i32 - pos);

        let mut tries = self.params.chain;
        let mut length = MIN_MATCH_LENGTH - 1;

        let mut w_end = win[(pos + length) as usize];
        let w_pos = &win[pos as usize..];
        let min_index = (pos - WINDOW_SIZE).max(0);
        let mut offset = 0;
        let mut ok = false;

        // Minimum gain to accept a match.
        let mut c_gain = 4;
        const BASE_COST: i32 = 3;

        let mut i = prev_head;
        while tries > 0 {
            if w_end == win[(i + length) as usize] {
                let n = match_len(&win[i as usize..(i + min_match_look) as usize], w_pos) as i32;
                if n > length {
                    let mut accept = true;
                    if self.params.chain >= 100 {
                        // Estimate the gain over emitting literals.
                        if let Some(h) = self.h.as_ref() {
                            let new_gain = h.bit_length_raw(&w_pos[..n as usize])
                                - i32::from(
                                    OFFSET_EXTRA_BITS[offset_code((pos - i) as u32) as usize],
                                )
                                - BASE_COST
                                - i32::from(
                                    LENGTH_EXTRA_BITS
                                        [usize::from(LENGTH_CODES[((n - 3) & 255) as usize])],
                                );
                            if new_gain <= c_gain {
                                accept = false;
                            } else {
                                c_gain = new_gain;
                            }
                        }
                    }
                    if accept {
                        length = n;
                        offset = pos - i;
                        ok = true;
                        if n >= nice {
                            break;
                        }
                        w_end = win[(pos + n) as usize];
                    }
                }
            }
            if i <= min_index {
                // hash_prev[i & mask] has already been overwritten.
                break;
            }
            i = s.hash_prev[(i & WINDOW_MASK) as usize] - s.hash_offset;
            if i < min_index {
                break;
            }
            tries -= 1;
        }
        if ok {
            Some((length, offset))
        } else {
            None
        }
    }

    /// Insert the string at `s.index` into the hash chains.
    #[inline]
    fn insert_at_index(&self, s: &mut AdvancedState) {
        let h = hash4(&self.window[s.index as usize..]);
        let ch = s.hash_head[h];
        s.chain_head = ch;
        s.hash_prev[(s.index & WINDOW_MASK) as usize] = ch;
        s.hash_head[h] = s.index + s.hash_offset;
    }

    /// Flush the tokens as a block ending at `s.index` once the block is full.
    #[inline]
    fn flush_if_full(&mut self, index: i32) {
        if self.tokens.n == MAX_FLATE_BLOCK_TOKENS {
            self.write_block(index, false);
            self.tokens.reset();
        }
    }

    /// Check whether a better match exists at the end of the previous match
    /// and, if so, emit the skipped literals and adjust the match.
    fn try_better_match_at_end(
        &mut self,
        s: &mut AdvancedState,
        mut prev_length: i32,
        mut prev_offset: i32,
        lookahead: i32,
    ) -> (i32, i32) {
        // Checking starts this far into the match. That allows up to two
        // more literals, which a higher quality match can make up for.
        const CHECK_OFF: i32 = 2;

        if prev_length >= MAX_MATCH_LENGTH - CHECK_OFF {
            return (prev_length, prev_offset);
        }
        let prev_index = s.index - 1;
        if prev_index + prev_length >= s.max_insert_index {
            return (prev_length, prev_offset);
        }

        let end = lookahead.min(MAX_MATCH_LENGTH + CHECK_OFF) + prev_index;
        let min_index = (s.index - WINDOW_SIZE).max(0);

        let h = hash4(&self.window[(prev_index + prev_length) as usize..]);
        let ch2 = s.hash_head[h] - s.hash_offset - prev_length;
        if prev_index - ch2 == prev_offset || ch2 <= min_index + CHECK_OFF {
            return (prev_length, prev_offset);
        }

        let length = match_len(
            &self.window[(prev_index + CHECK_OFF) as usize..end as usize],
            &self.window[(ch2 + CHECK_OFF) as usize..],
        ) as i32;
        if length <= prev_length {
            return (prev_length, prev_offset);
        }

        prev_length = length;
        prev_offset = prev_index - ch2;

        // Extend backwards over the two skipped bytes where they agree.
        let mut i = CHECK_OFF - 1;
        while i >= 0 {
            if prev_length >= MAX_MATCH_LENGTH
                || self.window[(prev_index + i) as usize] != self.window[(ch2 + i) as usize]
            {
                for j in 0..=i {
                    self.tokens
                        .add_literal(self.window[(prev_index + j) as usize]);
                    self.flush_if_full(s.index);
                    s.index += 1;
                    if s.index < s.max_insert_index {
                        self.insert_at_index(s);
                    }
                }
                break;
            }
            prev_length += 1;
            i -= 1;
        }
        (prev_length, prev_offset)
    }

    /// Emit extra literals during long runs of incompressible data, skipping
    /// ahead to avoid futile match searches.
    fn skip_literals(&mut self, s: &mut AdvancedState) {
        let n = i32::from(s.literal_counter) - self.params.chain;
        if n <= 0 {
            return;
        }
        let n = 1 + (n >> 6);
        for _ in 0..n {
            if s.index >= self.window_end - 1 {
                break;
            }
            self.tokens.add_literal(self.window[(s.index - 1) as usize]);
            self.flush_if_full(s.index);
            if s.index < s.max_insert_index {
                self.insert_at_index(s);
            }
            s.index += 1;
        }
        self.tokens.add_literal(self.window[(s.index - 1) as usize]);
        self.byte_available = false;
        self.flush_if_full(s.index);
    }

    /// Encode the window using lazy matching: a match is only emitted after
    /// the next position was checked for a better one.
    fn deflate_lazy(&mut self) {
        let mut s = self.state.take().expect("levels 7-9 have state");
        self.deflate_lazy_with(&mut s);
        self.state = Some(s);
    }

    fn deflate_lazy_with(&mut self, s: &mut AdvancedState) {
        if self.window_end - s.index < MIN_MATCH_LENGTH + MAX_MATCH_LENGTH && !self.sync {
            return;
        }
        if self.window_end != s.index && self.params.chain > 100 {
            // The literal Huffman coder estimates the cost of literals.
            let h = self
                .h
                .get_or_insert_with(|| HuffmanEncoder::new(MAX_FLATE_BLOCK_TOKENS as usize));
            let mut tmp = [0u16; 256];
            let to_index = &self.window[s.index as usize..self.window_end as usize];
            let to_index = &to_index[..to_index.len().min(MAX_FLATE_BLOCK_TOKENS as usize)];
            for &v in to_index {
                tmp[usize::from(v)] += 1;
            }
            h.generate(&tmp, 15);
        }

        s.max_insert_index = self.window_end - (MIN_MATCH_LENGTH - 1);

        loop {
            let lookahead = self.window_end - s.index;
            if lookahead < MIN_MATCH_LENGTH + MAX_MATCH_LENGTH {
                if !self.sync {
                    return;
                }
                if lookahead == 0 {
                    // Flush the current output block, if any.
                    if self.byte_available {
                        // One pending token still needs to be flushed.
                        self.tokens.add_literal(self.window[(s.index - 1) as usize]);
                        self.byte_available = false;
                    }
                    if self.tokens.n > 0 {
                        self.write_block(s.index, false);
                        self.tokens.reset();
                    }
                    return;
                }
            }
            if s.index < s.max_insert_index {
                self.insert_at_index(s);
            }
            let prev_length = s.length;
            let prev_offset = s.offset;
            s.length = MIN_MATCH_LENGTH - 1;
            s.offset = 0;
            let min_index = (s.index - WINDOW_SIZE).max(0);

            if s.chain_head - s.hash_offset >= min_index
                && lookahead > prev_length
                && prev_length < self.params.lazy
            {
                if let Some((new_length, new_offset)) =
                    self.find_match(s, s.index, s.chain_head - s.hash_offset, lookahead)
                {
                    s.length = new_length;
                    s.offset = new_offset;
                }
            }

            if prev_length >= MIN_MATCH_LENGTH && s.length <= prev_length {
                let (prev_length, prev_offset) =
                    self.try_better_match_at_end(s, prev_length, prev_offset, lookahead);

                // There was a match at the previous step and the current one
                // is not better: output the previous match.
                self.tokens.add_match(
                    (prev_length - 3) as u32,
                    (prev_offset - MIN_OFFSET_SIZE) as u32,
                );

                // Insert all strings up to the end of the match into the hash
                // table. `index` and `index - 1` are already inserted; with
                // too little lookahead the last two strings are skipped.
                let new_index = s.index + prev_length - 1;
                let end = new_index.min(s.max_insert_index);
                let start_index = (s.index + 1).min(s.max_insert_index);
                for di in start_index..end {
                    let h = hash4(&self.window[di as usize..]);
                    s.hash_prev[(di & WINDOW_MASK) as usize] = s.hash_head[h];
                    s.hash_head[h] = di + s.hash_offset;
                }

                s.index = new_index;
                self.byte_available = false;
                s.length = MIN_MATCH_LENGTH - 1;
                self.flush_if_full(s.index);
                s.literal_counter = 0;
                continue;
            }
            if s.length >= MIN_MATCH_LENGTH {
                s.literal_counter = 0;
            }
            if self.byte_available {
                s.literal_counter = s.literal_counter.wrapping_add(1);
                self.tokens.add_literal(self.window[(s.index - 1) as usize]);
                self.flush_if_full(s.index);
                s.index += 1;
                self.skip_literals(s);
            } else {
                s.index += 1;
                self.byte_available = true;
            }
        }
    }

    /// Store the window if it has filled or a flush is requested.
    fn store(&mut self) {
        if self.window_end > 0 && (self.window_end as usize == MAX_STORE_BLOCK_SIZE || self.sync) {
            self.write_stored_block(self.window_end as usize);
            self.window_end = 0;
        }
    }

    /// Huffman-only compression of the window if it has filled or a flush is
    /// requested.
    fn deflate_huff(&mut self) {
        if (self.window_end as usize) < self.window.len() && !self.sync || self.window_end == 0 {
            return;
        }
        self.w
            .write_block_huff(false, &self.window[..self.window_end as usize], self.sync);
        self.window_end = 0;
    }

    /// The level 1-6 encoding of the window if it has filled or a flush is
    /// requested.
    fn deflate_fast(&mut self) {
        // Only compress full windows, unless flushing.
        if (self.window_end as usize) < self.window.len() {
            if !self.sync {
                return;
            }
            // Handle extremely small sizes.
            if self.window_end < 128 {
                if self.window_end == 0 {
                    return;
                }
                if self.window_end <= 32 {
                    self.write_stored_block(self.window_end as usize);
                } else {
                    self.w
                        .write_block_huff(false, &self.window[..self.window_end as usize], true);
                }
                self.tokens.reset();
                self.window_end = 0;
                if let Some(fast) = self.fast.as_mut() {
                    fast.reset();
                }
                return;
            }
        }

        let end = self.window_end as usize;
        if let Some(fast) = self.fast.as_mut() {
            fast.encode(&mut self.tokens, &self.window[..end]);
        }
        if self.tokens.n == 0 {
            // No matches were made: store the block as is.
            self.write_stored_block(end);
        } else if i32::from(self.tokens.n) > self.window_end - (self.window_end >> 4) {
            // Less than 1/16th removed: Huffman compress the block.
            self.w
                .write_block_huff(false, &self.window[..end], self.sync);
        } else {
            self.w.write_block_dynamic(
                &mut self.tokens,
                false,
                Some(&self.window[..end]),
                self.sync,
            );
        }
        self.tokens.reset();
        self.window_end = 0;
    }

    pub(crate) fn write<W: Write>(&mut self, w: &mut W, mut b: &[u8]) -> io::Result<()> {
        while !b.is_empty() {
            if self.window_end as usize == self.window.len() || self.sync {
                self.run_step();
                self.w.drain(w)?;
            }
            let n = self.fill(b);
            b = &b[n..];
        }
        Ok(())
    }

    /// Flush pending data, then a sync marker (an empty stored block).
    pub(crate) fn sync_flush<W: Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.sync = true;
        self.run_step();
        self.w.write_stored_header(0, false);
        self.w.flush();
        self.sync = false;
        self.w.drain(w)
    }

    /// Flush pending data, then the final block: an empty fixed-Huffman block
    /// (3 header bits and a 7-bit end-of-block code), as Go writes it.
    pub(crate) fn finish<W: Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.sync = true;
        self.run_step();
        self.w.write_stored_header(0, true);
        self.w.flush();
        self.sync = false;
        self.w.drain(w)
    }
}
