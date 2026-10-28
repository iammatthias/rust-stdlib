//! Block encoding to a bit stream (Go's `huffman_bit_writer.go`).
//!
//! Output accumulates in `out` and is handed to the real writer by
//! [`BitWriter::drain`], one `write` call per call Go would have made, so the
//! sequence and sizes of writes match Go's.

use super::huffman::{
    fixed_literal, fixed_offset, hcode_code64, hcode_len, histogram, huff_offset, HCode,
    HuffmanEncoder,
};
use super::token::{
    Tokens, END_BLOCK_MARKER, LENGTH_BASE, LENGTH_CODES, LENGTH_EXTRA_BITS, LITERAL_COUNT,
    MATCH_OFFSET_ONLY_MASK, OFFSET_CODE_COUNT, OFFSET_COMBINED, OFFSET_EXTRA_BITS,
};
use std::io::{self, Write};

const LENGTH_CODES_START: usize = 257;
const CODEGEN_CODE_COUNT: usize = 19;
const BAD_CODE: u8 = 255;
const MAX_PREDEFINED_TOKENS: u16 = 250;
const BUFFER_FLUSH_SIZE: usize = 246;
const LENGTH_EXTRA_BITS_MIN_CODE: u32 = 8;
const OFFSET_EXTRA_BITS_MIN_CODE: u32 = 4;
const MAX_STORE_BLOCK_SIZE: usize = 65535;
const CODEGEN_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

pub(super) struct BitWriter {
    /// Bytes for the underlying writer; `marks` holds the end of each write.
    out: Vec<u8>,
    marks: Vec<usize>,
    bits: u64,
    nbits: u8,
    nbytes: usize,
    wrote_huffman: bool,
    literal_encoding: HuffmanEncoder,
    tmp_lit_encoding: HuffmanEncoder,
    offset_encoding: HuffmanEncoder,
    codegen_encoding: HuffmanEncoder,
    err: Option<io::Error>,
    /// Nonzero if the Huffman table can be reused; also means an end-of-block
    /// code is owed.
    prev_header: i32,
    pub(super) log_new_table_penalty: u32,
    bytes: [u8; 256 + 8],
    literal_freq: [u16; LENGTH_CODES_START + 32],
    offset_freq: [u16; 32],
    codegen_freq: [u16; CODEGEN_CODE_COUNT],
    codegen: [u8; LITERAL_COUNT + OFFSET_CODE_COUNT + 1],
}

impl BitWriter {
    pub(super) fn new() -> Self {
        BitWriter {
            out: Vec::new(),
            marks: Vec::new(),
            bits: 0,
            nbits: 0,
            nbytes: 0,
            wrote_huffman: false,
            literal_encoding: HuffmanEncoder::new(LITERAL_COUNT),
            tmp_lit_encoding: HuffmanEncoder::new(LITERAL_COUNT),
            offset_encoding: HuffmanEncoder::new(OFFSET_CODE_COUNT),
            codegen_encoding: HuffmanEncoder::new(CODEGEN_CODE_COUNT),
            err: None,
            prev_header: 0,
            log_new_table_penalty: 0,
            bytes: [0; 256 + 8],
            literal_freq: [0; LENGTH_CODES_START + 32],
            offset_freq: [0; 32],
            codegen_freq: [0; CODEGEN_CODE_COUNT],
            codegen: [0; LITERAL_COUNT + OFFSET_CODE_COUNT + 1],
        }
    }

    pub(super) fn reset(&mut self) {
        self.out.clear();
        self.marks.clear();
        self.bits = 0;
        self.nbits = 0;
        self.nbytes = 0;
        self.err = None;
        self.prev_header = 0;
        self.wrote_huffman = false;
    }

    /// Hand the queued output to `w`, one `write` per queued write.
    pub(super) fn drain<W: Write>(&mut self, w: &mut W) -> io::Result<()> {
        if let Some(e) = self.err.take() {
            self.out.clear();
            self.marks.clear();
            return Err(e);
        }
        let mut start = 0;
        let mut result = Ok(());
        for &end in &self.marks {
            if result.is_ok() {
                result = w.write_all(&self.out[start..end]);
            }
            start = end;
        }
        self.out.clear();
        self.marks.clear();
        result
    }

    /// Queue `self.bytes[..n]` as one write.
    fn write_scratch(&mut self, n: usize) {
        if self.err.is_some() {
            return;
        }
        self.out.extend_from_slice(&self.bytes[..n]);
        self.marks.push(self.out.len());
    }

    /// Queue `b` as one write.
    fn write_slice(&mut self, b: &[u8]) {
        if self.err.is_some() {
            return;
        }
        self.out.extend_from_slice(b);
        self.marks.push(self.out.len());
    }

    fn can_reuse(&self, t: &Tokens) -> bool {
        let b = &self.offset_encoding.codes;
        for (i, &v) in t.off_hist[..OFFSET_CODE_COUNT].iter().enumerate() {
            if v != 0 && b[i] == 0 {
                return false;
            }
        }
        let b = &self.literal_encoding.codes[256..LITERAL_COUNT];
        for (i, &v) in t.extra_hist[..LITERAL_COUNT - 256].iter().enumerate() {
            if v != 0 && b[i] == 0 {
                return false;
            }
        }
        let b = &self.literal_encoding.codes[..256];
        for (i, &v) in t.lit_hist.iter().enumerate() {
            if v != 0 && b[i] == 0 {
                return false;
            }
        }
        true
    }

    /// Pay an owed end-of-block code, if any.
    fn pay_eob(&mut self) {
        if self.prev_header > 0 {
            let c = self.literal_encoding.codes[END_BLOCK_MARKER as usize];
            self.write_code(c);
            self.prev_header = 0;
        }
    }

    /// Flush the currently encoded data, ending the current block if needed.
    pub(super) fn flush(&mut self) {
        if self.err.is_some() {
            self.nbits = 0;
            return;
        }
        self.pay_eob();
        let mut n = self.nbytes;
        while self.nbits != 0 {
            self.bytes[n] = self.bits as u8;
            self.bits >>= 8;
            if self.nbits > 8 {
                self.nbits -= 8;
            } else {
                self.nbits = 0;
            }
            n += 1;
        }
        self.bits = 0;
        if n > 0 {
            self.write_scratch(n);
        }
        self.nbytes = 0;
    }

    fn write_bits(&mut self, b: i32, nb: u8) {
        self.bits |= u64::from(b as u32) << (self.nbits & 63);
        self.nbits += nb;
        if self.nbits >= 48 {
            self.flush_bits();
        }
    }

    pub(super) fn write_bytes(&mut self, bytes: &[u8]) {
        if self.err.is_some() {
            return;
        }
        let mut n = self.nbytes;
        if self.nbits & 7 != 0 {
            self.err = Some(io::Error::other(super::InternalError(
                "writeBytes with unfinished bits".into(),
            )));
            return;
        }
        while self.nbits != 0 {
            self.bytes[n] = self.bits as u8;
            self.bits >>= 8;
            self.nbits -= 8;
            n += 1;
        }
        if n != 0 {
            self.write_scratch(n);
        }
        self.nbytes = 0;
        self.write_slice(bytes);
    }

    /// Run-length encode the code lengths of both alphabets (RFC 1951, 3.2.7)
    /// into `codegen`, counting symbol uses in `codegen_freq`.
    fn generate_codegen(
        &mut self,
        num_literals: usize,
        num_offsets: usize,
        off_codes: OffsetSource,
    ) {
        self.codegen_freq = [0; CODEGEN_CODE_COUNT];
        let lit_codes: &[HCode] = &self.literal_encoding.codes;
        let off_codes: &[HCode] = match off_codes {
            OffsetSource::Own => &self.offset_encoding.codes,
            OffsetSource::Huff => &huff_offset().codes,
        };
        let codegen = &mut self.codegen;
        for i in 0..num_literals {
            codegen[i] = hcode_len(lit_codes[i]);
        }
        for i in 0..num_offsets {
            codegen[num_literals + i] = hcode_len(off_codes[i]);
        }
        codegen[num_literals + num_offsets] = BAD_CODE;

        let mut size = codegen[0];
        let mut count = 1i32;
        let mut out_index = 0usize;
        let mut in_index = 1usize;
        while size != BAD_CODE {
            let next_size = codegen[in_index];
            in_index += 1;
            if next_size == size {
                count += 1;
                continue;
            }
            if size != 0 {
                codegen[out_index] = size;
                out_index += 1;
                self.codegen_freq[usize::from(size)] += 1;
                count -= 1;
                while count >= 3 {
                    let n = count.min(6);
                    codegen[out_index] = 16;
                    out_index += 1;
                    codegen[out_index] = (n - 3) as u8;
                    out_index += 1;
                    self.codegen_freq[16] += 1;
                    count -= n;
                }
            } else {
                while count >= 11 {
                    let n = count.min(138);
                    codegen[out_index] = 18;
                    out_index += 1;
                    codegen[out_index] = (n - 11) as u8;
                    out_index += 1;
                    self.codegen_freq[18] += 1;
                    count -= n;
                }
                if count >= 3 {
                    codegen[out_index] = 17;
                    out_index += 1;
                    codegen[out_index] = (count - 3) as u8;
                    out_index += 1;
                    self.codegen_freq[17] += 1;
                    count = 0;
                }
            }
            count -= 1;
            while count >= 0 {
                codegen[out_index] = size;
                out_index += 1;
                self.codegen_freq[usize::from(size)] += 1;
                count -= 1;
            }
            size = next_size;
            count = 1;
        }
        codegen[out_index] = BAD_CODE;
    }

    fn codegens(&self) -> usize {
        let mut n = self.codegen_freq.len();
        while n > 4 && self.codegen_freq[CODEGEN_ORDER[n - 1]] == 0 {
            n -= 1;
        }
        n
    }

    /// Size of the dynamic header with the current encodings and the number
    /// of codegens it uses.
    fn header_size(&self) -> (i32, usize) {
        let num_codegens = self.codegens();
        let size = 3
            + 5
            + 5
            + 4
            + (3 * num_codegens as i32)
            + self.codegen_encoding.bit_length(&self.codegen_freq)
            + i32::from(self.codegen_freq[16]) * 2
            + i32::from(self.codegen_freq[17]) * 3
            + i32::from(self.codegen_freq[18]) * 7;
        (size, num_codegens)
    }

    fn dynamic_reuse_size(&self) -> i32 {
        self.literal_encoding.bit_length(&self.literal_freq)
            + self.offset_encoding.bit_length(&self.offset_freq)
    }

    fn dynamic_size(&self, extra_bits: i32) -> (i32, usize) {
        let (header, num_codegens) = self.header_size();
        let size = header
            + self.literal_encoding.bit_length(&self.literal_freq)
            + self.offset_encoding.bit_length(&self.offset_freq)
            + extra_bits;
        (size, num_codegens)
    }

    /// Bits of extra data written after the length and offset codes of matches.
    fn extra_bit_size(&self) -> i32 {
        let mut total = 0;
        for (i, &n) in self.literal_freq[257..LITERAL_COUNT].iter().enumerate() {
            total += i32::from(n) * i32::from(LENGTH_EXTRA_BITS[i & 31]);
        }
        for (i, &n) in self.offset_freq[..OFFSET_CODE_COUNT].iter().enumerate() {
            total += i32::from(n) * i32::from(OFFSET_EXTRA_BITS[i & 31]);
        }
        total
    }

    fn fixed_size(&self, extra_bits: i32) -> i32 {
        3 + fixed_literal().bit_length(&self.literal_freq)
            + fixed_offset().bit_length(&self.offset_freq)
            + extra_bits
    }

    /// Size in bits of `input` as one stored block, and whether it fits one.
    fn stored_size(input: Option<&[u8]>) -> (i32, bool) {
        match input {
            Some(input) if input.len() <= MAX_STORE_BLOCK_SIZE => {
                ((input.len() as i32 + 5) * 8, true)
            }
            _ => (0, false),
        }
    }

    fn write_code(&mut self, c: HCode) {
        self.bits |= hcode_code64(c) << (self.nbits & 63);
        self.nbits += hcode_len(c);
        if self.nbits >= 48 {
            self.flush_bits();
        }
    }

    fn flush_bits(&mut self) {
        let bits = self.bits;
        self.bits >>= 48;
        self.nbits -= 48;
        let mut n = self.nbytes;
        self.bytes[n..n + 8].copy_from_slice(&bits.to_le_bytes());
        n += 6;
        if n >= BUFFER_FLUSH_SIZE {
            if self.err.is_some() {
                return;
            }
            self.write_scratch(n);
            n = 0;
        }
        self.nbytes = n;
    }

    fn write_dynamic_header(
        &mut self,
        num_literals: usize,
        num_offsets: usize,
        num_codegens: usize,
        is_eof: bool,
    ) {
        if self.err.is_some() {
            return;
        }
        let first_bits = if is_eof { 5 } else { 4 };
        self.write_bits(first_bits, 3);
        self.write_bits(num_literals as i32 - 257, 5);
        self.write_bits(num_offsets as i32 - 1, 5);
        self.write_bits(num_codegens as i32 - 4, 4);
        for &o in &CODEGEN_ORDER[..num_codegens] {
            let value = hcode_len(self.codegen_encoding.codes[o]);
            self.write_bits(i32::from(value), 3);
        }
        let mut i = 0;
        loop {
            let code_word = self.codegen[i];
            i += 1;
            if code_word == BAD_CODE {
                break;
            }
            let c = self.codegen_encoding.codes[usize::from(code_word)];
            self.write_code(c);
            match code_word {
                16 => {
                    self.write_bits(i32::from(self.codegen[i]), 2);
                    i += 1;
                }
                17 => {
                    self.write_bits(i32::from(self.codegen[i]), 3);
                    i += 1;
                }
                18 => {
                    self.write_bits(i32::from(self.codegen[i]), 7);
                    i += 1;
                }
                _ => {}
            }
        }
    }

    /// Write a stored block header. A stored block that only marks the end of
    /// the stream is replaced by an empty fixed-Huffman block.
    pub(super) fn write_stored_header(&mut self, length: usize, is_eof: bool) {
        if self.err.is_some() {
            return;
        }
        self.pay_eob();
        if length == 0 && is_eof {
            self.write_fixed_header(is_eof);
            self.write_bits(0, 7);
            self.flush();
            return;
        }
        self.write_bits(i32::from(is_eof), 3);
        self.flush();
        self.write_bits(length as i32, 16);
        self.write_bits(i32::from(!(length as u16)), 16);
    }

    fn write_fixed_header(&mut self, is_eof: bool) {
        if self.err.is_some() {
            return;
        }
        self.pay_eob();
        self.write_bits(if is_eof { 3 } else { 2 }, 3);
    }

    /// Write a block with a dynamic Huffman table, reusing the previous table
    /// when that is cheaper.
    pub(super) fn write_block_dynamic(
        &mut self,
        tokens: &mut Tokens,
        eof: bool,
        input: Option<&[u8]>,
        sync: bool,
    ) {
        if self.err.is_some() {
            return;
        }
        let sync = sync || eof;
        if sync {
            tokens.add_eob();
        } else {
            tokens.extra_hist[0] = 1;
        }

        if (self.wrote_huffman || eof) && self.prev_header > 0 {
            let c = self.literal_encoding.codes[END_BLOCK_MARKER as usize];
            self.write_code(c);
            self.prev_header = 0;
            self.wrote_huffman = false;
        }

        if self.prev_header > 0 && !self.can_reuse(tokens) {
            let c = self.literal_encoding.codes[END_BLOCK_MARKER as usize];
            self.write_code(c);
            self.prev_header = 0;
        }

        let (num_literals, num_offsets) = self.index_tokens(tokens);
        let mut extra_bits = 0;
        let (ssize, storable) = Self::stored_size(input);
        if storable || self.prev_header > 0 {
            extra_bits = self.extra_bit_size();
        }

        let mut size;
        if self.prev_header > 0 {
            let mut new_size = self.prev_header + tokens.estimated_bits();
            new_size += i32::from(hcode_len(
                self.literal_encoding.codes[END_BLOCK_MARKER as usize],
            )) + (new_size >> self.log_new_table_penalty);
            let reuse_size = self.dynamic_reuse_size() + extra_bits;
            if new_size < reuse_size {
                let c = self.literal_encoding.codes[END_BLOCK_MARKER as usize];
                self.write_code(c);
                size = new_size;
                self.prev_header = 0;
            } else {
                size = reuse_size;
            }

            if tokens.n < MAX_PREDEFINED_TOKENS {
                let pre_size = self.fixed_size(extra_bits) + 7;
                if pre_size < size {
                    if storable && ssize <= size {
                        let input = input.unwrap_or_default();
                        self.write_stored_header(input.len(), eof);
                        self.write_bytes(input);
                        return;
                    }
                    self.write_fixed_header(eof);
                    if !sync {
                        tokens.add_eob();
                    }
                    self.write_tokens(tokens.slice(), true);
                    return;
                }
            }

            if storable && ssize <= size {
                let input = input.unwrap_or_default();
                self.write_stored_header(input.len(), eof);
                self.write_bytes(input);
                return;
            }
        }

        if self.prev_header == 0 {
            self.literal_freq[END_BLOCK_MARKER as usize] = 1;
            self.generate();
            self.generate_codegen(num_literals, num_offsets, OffsetSource::Own);
            self.codegen_encoding.generate(&self.codegen_freq, 7);
            let (dsize, num_codegens) = self.dynamic_size(extra_bits);
            size = dsize;

            if tokens.n < MAX_PREDEFINED_TOKENS {
                let pre_size = self.fixed_size(extra_bits);
                if pre_size <= size {
                    if storable && ssize <= pre_size {
                        let input = input.unwrap_or_default();
                        self.write_stored_header(input.len(), eof);
                        self.write_bytes(input);
                        return;
                    }
                    self.write_fixed_header(eof);
                    if !sync {
                        tokens.add_eob();
                    }
                    self.write_tokens(tokens.slice(), true);
                    return;
                }
            }

            if storable && ssize <= size {
                let input = input.unwrap_or_default();
                self.write_stored_header(input.len(), eof);
                self.write_bytes(input);
                return;
            }

            self.write_dynamic_header(num_literals, num_offsets, num_codegens, eof);
            if !sync {
                self.prev_header = self.header_size().0;
            }
            self.wrote_huffman = false;
        }

        if sync {
            self.prev_header = 0;
        }
        self.write_tokens(tokens.slice(), false);
    }

    /// Copy the token histograms into the frequency tables and return the
    /// number of literal and offset symbols in use.
    fn index_tokens(&mut self, t: &Tokens) -> (usize, usize) {
        self.literal_freq[..256].copy_from_slice(&t.lit_hist);
        self.literal_freq[256..288].copy_from_slice(&t.extra_hist);
        self.offset_freq = t.off_hist;

        if t.n == 0 {
            return (0, 0);
        }
        let mut num_literals = self.literal_freq.len();
        while self.literal_freq[num_literals - 1] == 0 {
            num_literals -= 1;
        }
        let mut num_offsets = self.offset_freq.len();
        while num_offsets > 0 && self.offset_freq[num_offsets - 1] == 0 {
            num_offsets -= 1;
        }
        if num_offsets == 0 {
            // Without a single match the offset tree still needs one symbol to
            // be encodable.
            self.offset_freq[0] = 1;
            num_offsets = 1;
        }
        (num_literals, num_offsets)
    }

    fn generate(&mut self) {
        self.literal_encoding
            .generate(&self.literal_freq[..LITERAL_COUNT], 15);
        self.offset_encoding
            .generate(&self.offset_freq[..OFFSET_CODE_COUNT], 15);
    }

    /// Write `tokens` using either the fixed codes or the current encoders.
    fn write_tokens(&mut self, tokens: &[u32], fixed: bool) {
        if self.err.is_some() {
            return;
        }
        if tokens.is_empty() {
            return;
        }
        let (mut tokens, defer_eob) = match tokens.split_last() {
            Some((&last, rest)) if last == END_BLOCK_MARKER => (rest, true),
            _ => (tokens, false),
        };
        let (len_codes, off_codes): (&[HCode], &[HCode]) = if fixed {
            (&fixed_literal().codes, &fixed_offset().codes)
        } else {
            (&self.literal_encoding.codes, &self.offset_encoding.codes)
        };
        // Work on local copies so the encoders stay borrowed immutably.
        let len_codes = len_codes.to_vec();
        let off_codes = off_codes.to_vec();
        let (mut bits, mut nbits, mut nbytes) = (self.bits, self.nbits, self.nbytes);

        macro_rules! emit {
            ($value:expr, $count:expr) => {{
                bits |= ($value) << (nbits & 63);
                nbits += $count;
                if nbits >= 48 {
                    self.bytes[nbytes..nbytes + 8].copy_from_slice(&bits.to_le_bytes());
                    bits >>= 48;
                    nbits -= 48;
                    nbytes += 6;
                    if nbytes >= BUFFER_FLUSH_SIZE {
                        if self.err.is_some() {
                            self.nbytes = 0;
                            return;
                        }
                        self.write_scratch(nbytes);
                        nbytes = 0;
                    }
                }
            }};
        }

        while let Some((&t, rest)) = tokens.split_first() {
            tokens = rest;
            if t < 256 {
                let c = len_codes[t as usize];
                emit!(hcode_code64(c), hcode_len(c));
                continue;
            }

            let length = (t >> super::token::LENGTH_SHIFT) as u8;
            let len_code = u32::from(LENGTH_CODES[usize::from(length)]) & 31;
            let c = len_codes[LENGTH_CODES_START + len_code as usize];
            emit!(hcode_code64(c), hcode_len(c));

            if len_code >= LENGTH_EXTRA_BITS_MIN_CODE {
                let extra_length_bits = LENGTH_EXTRA_BITS[len_code as usize];
                let extra_length = length.wrapping_sub(LENGTH_BASE[len_code as usize]);
                emit!(u64::from(extra_length), extra_length_bits);
            }

            let offset = t & super::token::OFFSET_MASK;
            let off_code = (offset >> 16) & 31;
            let c = off_codes[off_code as usize];
            emit!(hcode_code64(c), hcode_len(c));

            if off_code >= OFFSET_EXTRA_BITS_MIN_CODE {
                let offset_comb = OFFSET_COMBINED[off_code as usize];
                let value =
                    u64::from(offset.wrapping_sub(offset_comb >> 8) & MATCH_OFFSET_ONLY_MASK);
                emit!(value, offset_comb as u8);
            }
        }
        self.bits = bits;
        self.nbits = nbits;
        self.nbytes = nbytes;

        if defer_eob {
            self.write_code(len_codes[END_BLOCK_MARKER as usize]);
        }
    }

    /// Encode `input` as Huffman-coded literals, or as a stored block if
    /// that gains little.
    pub(super) fn write_block_huff(&mut self, eof: bool, input: &[u8], sync: bool) {
        if self.err.is_some() {
            return;
        }
        self.literal_freq = [0; LENGTH_CODES_START + 32];
        if !self.wrote_huffman {
            self.offset_freq = [0; 32];
        }

        const NUM_LITERALS: usize = END_BLOCK_MARKER as usize + 1;
        const NUM_OFFSETS: usize = 1;

        // 70 bytes; see https://stackoverflow.com/a/25454430
        const GUESS_HEADER_SIZE_BITS: i32 = 70 * 8;
        histogram(input, &mut self.literal_freq[..NUM_LITERALS]);
        let (ssize, storable) = Self::stored_size(Some(input));
        if storable && input.len() > 1024 {
            // Quick check for incompressible content: all frequencies close
            // to the average. This typically only triggers on random data.
            let mut abs = 0f64;
            let avg = input.len() as f64 / 256.0;
            let max = (input.len() * 2) as f64;
            for &v in &self.literal_freq[..256] {
                let diff = f64::from(v) - avg;
                abs += diff * diff;
                if abs >= max {
                    break;
                }
            }
            if abs < max {
                self.write_stored_header(input.len(), eof);
                self.write_bytes(input);
                return;
            }
        }
        self.literal_freq[END_BLOCK_MARKER as usize] = 1;
        self.tmp_lit_encoding
            .generate(&self.literal_freq[..NUM_LITERALS], 15);
        let mut est_bits = self
            .tmp_lit_encoding
            .can_encode_len(&self.literal_freq[..NUM_LITERALS]);
        if est_bits < i32::MAX {
            est_bits += self.prev_header;
            if self.prev_header == 0 {
                est_bits += GUESS_HEADER_SIZE_BITS;
            }
            est_bits += est_bits >> self.log_new_table_penalty;
        }

        if storable && ssize <= est_bits {
            self.write_stored_header(input.len(), eof);
            self.write_bytes(input);
            return;
        }

        if self.prev_header > 0 {
            let reuse_size = self
                .literal_encoding
                .can_encode_len(&self.literal_freq[..256]);
            if est_bits < reuse_size {
                let c = self.literal_encoding.codes[END_BLOCK_MARKER as usize];
                self.write_code(c);
                self.prev_header = 0;
            }
        }

        if self.prev_header == 0 {
            std::mem::swap(&mut self.literal_encoding, &mut self.tmp_lit_encoding);
            self.generate_codegen(NUM_LITERALS, NUM_OFFSETS, OffsetSource::Huff);
            self.codegen_encoding.generate(&self.codegen_freq, 7);
            let num_codegens = self.codegens();
            self.write_dynamic_header(NUM_LITERALS, NUM_OFFSETS, num_codegens, eof);
            self.wrote_huffman = true;
            self.prev_header = self.header_size().0;
        }

        let encoding: Vec<HCode> = self.literal_encoding.codes[..256].to_vec();
        let (mut bits, mut nbits, mut nbytes) = (self.bits, self.nbits, self.nbytes);

        let mut input = input;
        // Unrolled: three codes per round.
        while input.len() > 3 {
            // At least 48 bits must be free.
            if nbits >= 8 {
                let n = nbits >> 3;
                self.bytes[nbytes..nbytes + 8].copy_from_slice(&bits.to_le_bytes());
                bits >>= (n * 8) & 63;
                nbits -= n * 8;
                nbytes += usize::from(n);
            }
            if nbytes >= BUFFER_FLUSH_SIZE {
                if self.err.is_some() {
                    self.nbytes = 0;
                    return;
                }
                self.write_scratch(nbytes);
                nbytes = 0;
            }
            let a = encoding[usize::from(input[0])];
            let b = encoding[usize::from(input[1])];
            bits |= hcode_code64(a) << (nbits & 63);
            bits |= hcode_code64(b) << (nbits.wrapping_add(hcode_len(a)) & 63);
            let c = encoding[usize::from(input[2])];
            nbits = nbits.wrapping_add(hcode_len(b)).wrapping_add(hcode_len(a));
            bits |= hcode_code64(c) << (nbits & 63);
            nbits += hcode_len(c);
            input = &input[3..];
        }

        for &t in input {
            if nbits >= 48 {
                self.bytes[nbytes..nbytes + 8].copy_from_slice(&bits.to_le_bytes());
                bits >>= 48;
                nbits -= 48;
                nbytes += 6;
                if nbytes >= BUFFER_FLUSH_SIZE {
                    if self.err.is_some() {
                        self.nbytes = 0;
                        return;
                    }
                    self.write_scratch(nbytes);
                    nbytes = 0;
                }
            }
            let c = encoding[usize::from(t)];
            bits |= hcode_code64(c) << (nbits & 63);
            nbits += hcode_len(c);
        }
        self.bits = bits;
        self.nbits = nbits;
        self.nbytes = nbytes;

        if self.nbits >= 48 {
            self.flush_bits();
        }

        if eof || sync {
            let c = self.literal_encoding.codes[END_BLOCK_MARKER as usize];
            self.write_code(c);
            self.prev_header = 0;
            self.wrote_huffman = false;
        }
    }
}

/// Where `generate_codegen` finds the offset code lengths.
#[derive(Clone, Copy)]
enum OffsetSource {
    /// The writer's own offset encoding.
    Own,
    /// The static one-symbol offset code of Huffman-only blocks.
    Huff,
}
