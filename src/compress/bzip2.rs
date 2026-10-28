//! Go `compress/bzip2`: streaming bzip2 decompression with explicit limits.
//!
//! Like Go's package this is decompression only. [`Reader`] decodes any
//! [`Read`] source, including concatenated streams, and verifies every block
//! CRC and stream CRC. Randomized blocks (a deprecated bzip2 0.9.0 feature) are
//! rejected, as in Go. Huffman tables are built exactly as Go builds them, so
//! the set of accepted inputs and the bytes produced match Go's reader.
//!
//! Output is streamed: a block's bytes are delivered before its CRC is
//! checked at the end of the block, so data read before an error is
//! unverified. Truncated input is reported as [`io::ErrorKind::UnexpectedEof`]
//! after the same bytes Go returns with `io.ErrUnexpectedEOF`: like Go, the
//! decoder keeps decoding zero bits once the input ends, so an incomplete
//! block can still deliver bytes, and `Read` returns them before the error
//! (a Rust `Read` cannot return both in one call). Malformed data is reported as
//! [`io::ErrorKind::InvalidData`] wrapping a [`StructuralError`]. Like Go's
//! reader without an `io.ByteReader`, the reader buffers its source and may
//! read past the end of the final stream.
use std::fmt;
use std::io::{self, Read};

const FILE_MAGIC: u64 = 0x425a; // "BZ"
const BLOCK_MAGIC: u64 = 0x3141_5926_5359;
const FINAL_MAGIC: u64 = 0x1772_4538_5090;
const INVALID_NODE: u16 = 0xffff;
const MAX_REPEAT: usize = 2 * 1024 * 1024;

/// Decoder resource bounds, enforced while streaming. Go has none, so they
/// are opt-in: the default is unlimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum decompressed bytes across all concatenated streams.
    pub max_output: u64,
    /// Maximum block size a stream header may declare (100 000 times the
    /// level digit). The block buffer holds four bytes per block byte.
    pub max_block_size: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_output: u64::MAX,
            max_block_size: 900_000,
        }
    }
}

/// Syntactically invalid bzip2 data, mirroring Go's `StructuralError`.
///
/// It is carried as the inner error of an [`io::ErrorKind::InvalidData`]
/// error and can be recovered with `io::Error::get_ref` and `downcast_ref`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StructuralError(&'static str);

impl StructuralError {
    /// The reason without the `bzip2 data invalid: ` prefix.
    pub fn reason(&self) -> &'static str {
        self.0
    }
}

impl fmt::Display for StructuralError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bzip2 data invalid: {}", self.0)
    }
}

impl std::error::Error for StructuralError {}

/// Terminal decoder failure, kept so later reads report it again.
#[derive(Clone, Debug)]
enum Failure {
    Structural(&'static str),
    Truncated,
    Limit(&'static str),
    Io(io::ErrorKind, String),
}

impl Failure {
    fn to_error(&self) -> io::Error {
        match self {
            Failure::Structural(reason) => {
                io::Error::new(io::ErrorKind::InvalidData, StructuralError(reason))
            }
            Failure::Truncated => io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "bzip2: unexpected end of input",
            ),
            Failure::Limit(what) => io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bzip2: {what} exceeds decode limit"),
            ),
            Failure::Io(kind, message) => io::Error::new(*kind, message.clone()),
        }
    }
}

type Result<T> = std::result::Result<T, Failure>;

/// MSB-first bit reader over a buffered byte source.
struct BitReader<R> {
    inner: R,
    buf: Box<[u8]>,
    pos: usize,
    len: usize,
    n: u64,
    bits: u32,
    /// Go's `bitReader.err`: set when the source fails or ends mid-read, after
    /// which bit reads that need more input return zero bits, as in Go.
    err: Option<Failure>,
}

impl<R: Read> BitReader<R> {
    fn read_byte(&mut self) -> Result<Option<u8>> {
        if self.pos == self.len {
            loop {
                match self.inner.read(&mut self.buf) {
                    Ok(0) => return Ok(None),
                    Ok(count) => {
                        self.pos = 0;
                        self.len = count;
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(Failure::Io(error.kind(), error.to_string())),
                }
            }
        }
        let byte = self.buf[self.pos];
        self.pos += 1;
        Ok(Some(byte))
    }

    /// Reads up to 48 bits into the low end of the result. When the input
    /// ends or fails first it records the error in `err` and returns zero, as Go's
    /// `ReadBits64` does; decoding goes on with zero bits.
    fn read_bits(&mut self, count: u32) -> Result<u64> {
        while count > self.bits {
            match self.read_byte() {
                Ok(Some(byte)) => {
                    self.n = (self.n << 8) | u64::from(byte);
                    self.bits += 8;
                }
                Ok(None) => {
                    self.err = Some(Failure::Truncated);
                    return Ok(0);
                }
                Err(failure) => {
                    self.err = Some(failure);
                    return Ok(0);
                }
            }
        }
        let value = (self.n >> (self.bits - count)) & ((1u64 << count) - 1);
        self.bits -= count;
        Ok(value)
    }

    fn read_bit(&mut self) -> Result<bool> {
        if self.bits > 0 {
            self.bits -= 1;
            return Ok((self.n >> self.bits) & 1 == 1);
        }
        Ok(self.read_bits(1)? == 1)
    }
}

#[derive(Clone, Copy, Default)]
struct Node {
    left: u16,
    right: u16,
    left_value: u16,
    right_value: u16,
}

/// Go's bit-by-bit Huffman tree. Construction follows Go exactly, including
/// its tolerance of incomplete and over-subscribed length sets, so decoded
/// symbols agree with Go for every table Go accepts.
struct Tree {
    nodes: Vec<Node>,
}

#[derive(Clone, Copy)]
struct Code {
    code: u32,
    value: u16,
}

impl Tree {
    fn new(lengths: &[u8]) -> Result<Self> {
        let mut pairs: Vec<(u8, u16)> = lengths
            .iter()
            .enumerate()
            .map(|(value, &length)| (length, value as u16))
            .collect();
        pairs.sort_unstable();
        // Codes are packed at the most significant end of a u32 and assigned
        // from the longest length down; over-subscription wraps, as in Go.
        let mut codes = vec![Code { code: 0, value: 0 }; pairs.len()];
        let mut code = 0u32;
        let mut length = 32u8;
        for (slot, &(pair_length, value)) in codes.iter_mut().zip(&pairs).rev() {
            length = length.min(pair_length);
            *slot = Code { code, value };
            code = code.wrapping_add(1u32 << (32 - u32::from(length)));
        }
        codes.sort_unstable_by_key(|entry| entry.code);
        let mut tree = Tree {
            nodes: Vec::with_capacity(codes.len()),
        };
        tree.build(&codes, 0)?;
        Ok(tree)
    }

    fn build(&mut self, codes: &[Code], level: u32) -> Result<u16> {
        if level > 31 {
            return Err(Failure::Structural("equal symbols in Huffman tree"));
        }
        let test = 1u32 << (31 - level);
        let split = codes
            .iter()
            .position(|entry| entry.code & test != 0)
            .unwrap_or(codes.len());
        let (left, right) = codes.split_at(split);
        if left.is_empty() || right.is_empty() {
            // A superfluous level (seen from real encoders) is skipped.
            if codes.len() < 2 {
                return Err(Failure::Structural("empty Huffman tree"));
            }
            if level == 31 {
                return Err(Failure::Structural("equal symbols in Huffman tree"));
            }
            let rest = if left.is_empty() { right } else { left };
            return self.build(rest, level + 1);
        }
        let index = self.nodes.len();
        self.nodes.push(Node::default());
        let mut node = Node::default();
        if left.len() == 1 {
            node.left = INVALID_NODE;
            node.left_value = left[0].value;
        } else {
            node.left = self.build(left, level + 1)?;
        }
        if right.len() == 1 {
            node.right = INVALID_NODE;
            node.right_value = right[0].value;
        } else {
            node.right = self.build(right, level + 1)?;
        }
        self.nodes[index] = node;
        Ok(index as u16)
    }

    fn decode<R: Read>(&self, bits: &mut BitReader<R>) -> Result<u16> {
        let mut index = 0usize;
        loop {
            let node = self.nodes[index];
            let bit = bits.read_bit()?;
            let next = if bit { node.left } else { node.right };
            if next == INVALID_NODE {
                return Ok(if bit {
                    node.left_value
                } else {
                    node.right_value
                });
            }
            index = usize::from(next);
        }
    }
}

fn mtf_decode(list: &mut [u8], index: usize) -> u8 {
    let byte = list[index];
    list.copy_within(..index, 1);
    list[0] = byte;
    byte
}

const fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = (i as u32) << 24;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 0x8000_0000 != 0 {
                (crc << 1) ^ 0x04c1_1db7
            } else {
                crc << 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

static CRC_TABLE: [u32; 256] = crc_table();

/// bzip2's CRC-32: the IEEE polynomial processed most significant bit first.
fn update_crc(value: u32, bytes: &[u8]) -> u32 {
    let mut crc = !value;
    for &byte in bytes {
        crc = CRC_TABLE[usize::from((crc >> 24) as u8 ^ byte)] ^ (crc << 8);
    }
    !crc
}

/// Streaming bzip2 decompressor implementing [`Read`].
///
/// The stream header is parsed on the first read, so construction never
/// fails. Errors are terminal: every later read returns the same error.
pub struct Reader<R> {
    bits: BitReader<R>,
    limits: Limits,
    file_crc: u32,
    block_crc: u32,
    want_block_crc: u32,
    setup_done: bool,
    eof: bool,
    block_size: usize,
    /// Inverse-BWT links in the upper 24 bits, block bytes in the low 8.
    tt: Vec<u32>,
    t_pos: u32,
    pre_rle_len: usize,
    pre_rle_used: usize,
    last_byte: i32,
    byte_repeats: u32,
    repeats: u32,
    produced: u64,
    failure: Option<Failure>,
}

impl<R: Read> Reader<R> {
    /// Creates a reader with [`Limits::default`].
    pub fn new(inner: R) -> Self {
        Self::with_limits(inner, Limits::default())
    }

    /// Creates a reader with explicit resource limits.
    pub fn with_limits(inner: R, limits: Limits) -> Self {
        Self {
            bits: BitReader {
                inner,
                buf: vec![0u8; 8192].into_boxed_slice(),
                pos: 0,
                len: 0,
                n: 0,
                bits: 0,
                err: None,
            },
            limits,
            file_crc: 0,
            block_crc: 0,
            want_block_crc: 0,
            setup_done: false,
            eof: false,
            block_size: 0,
            tt: Vec::new(),
            t_pos: 0,
            pre_rle_len: 0,
            pre_rle_used: 0,
            last_byte: -1,
            byte_repeats: 0,
            repeats: 0,
            produced: 0,
            failure: None,
        }
    }

    /// Total decompressed bytes delivered so far.
    pub fn total_out(&self) -> u64 {
        self.produced
    }

    fn setup(&mut self, need_magic: bool) -> Result<()> {
        if need_magic && self.bits.read_bits(16)? != FILE_MAGIC {
            return Err(Failure::Structural("bad magic value"));
        }
        if self.bits.read_bits(8)? != u64::from(b'h') {
            return Err(Failure::Structural("non-Huffman entropy encoding"));
        }
        let level = self.bits.read_bits(8)?;
        if !(u64::from(b'1')..=u64::from(b'9')).contains(&level) {
            return Err(Failure::Structural("invalid compression level"));
        }
        self.file_crc = 0;
        self.block_size = 100_000 * (level - u64::from(b'0')) as usize;
        if self.block_size > self.limits.max_block_size {
            return Err(Failure::Limit("block size"));
        }
        if self.block_size > self.tt.len() {
            self.tt = vec![0; self.block_size];
        }
        Ok(())
    }

    /// Emits pending block bytes; the flag reports an output-limit stop.
    fn read_from_block(&mut self, buf: &mut [u8]) -> (usize, bool) {
        let mut n = 0;
        while (self.repeats > 0 || self.pre_rle_used < self.pre_rle_len) && n < buf.len() {
            if self.repeats > 0 {
                if self.produced == self.limits.max_output {
                    return (n, true);
                }
                buf[n] = self.last_byte as u8;
                n += 1;
                self.produced += 1;
                self.repeats -= 1;
                if self.repeats == 0 {
                    self.last_byte = -1;
                }
                continue;
            }
            self.t_pos = self.tt[self.t_pos as usize];
            let byte = self.t_pos as u8;
            self.t_pos >>= 8;
            self.pre_rle_used += 1;
            // Four equal bytes are followed by a count of further copies.
            if self.byte_repeats == 3 {
                self.repeats = u32::from(byte);
                self.byte_repeats = 0;
                continue;
            }
            if self.last_byte == i32::from(byte) {
                self.byte_repeats += 1;
            } else {
                self.byte_repeats = 0;
            }
            self.last_byte = i32::from(byte);
            if self.produced == self.limits.max_output {
                return (n, true);
            }
            buf[n] = byte;
            n += 1;
            self.produced += 1;
        }
        (n, false)
    }

    fn read_inner(&mut self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let (n, limited) = self.read_from_block(buf);
            if n > 0 || buf.is_empty() {
                self.block_crc = update_crc(self.block_crc, &buf[..n]);
                if limited {
                    self.failure = Some(Failure::Limit("decompressed output"));
                }
                return Ok(n);
            }
            if limited {
                return Err(Failure::Limit("decompressed output"));
            }
            // End of block: the CRC covers every byte the block produced.
            if self.block_crc != self.want_block_crc {
                self.bits.err = Some(Failure::Structural("block checksum mismatch"));
                return Err(Failure::Structural("block checksum mismatch"));
            }
            match self.bits.read_bits(48)? {
                BLOCK_MAGIC => self.read_block()?,
                FINAL_MAGIC => {
                    let want_file_crc = self.bits.read_bits(32)? as u32;
                    if let Some(failure) = &self.bits.err {
                        return Err(failure.clone());
                    }
                    if self.file_crc != want_file_crc {
                        self.bits.err = Some(Failure::Structural("file checksum mismatch"));
                        return Err(Failure::Structural("file checksum mismatch"));
                    }
                    // Skip to a byte boundary; a concatenated stream starts
                    // with "BZ".
                    let padding = self.bits.bits % 8;
                    self.bits.read_bits(padding)?;
                    let Some(first) = self.bits.read_byte()? else {
                        self.eof = true;
                        return Ok(0);
                    };
                    let second = self.bits.read_byte()?.ok_or(Failure::Truncated)?;
                    if first != b'B' || second != b'Z' {
                        return Err(Failure::Structural("bad magic value in continuation file"));
                    }
                    self.setup(false)?;
                }
                _ => return Err(Failure::Structural("bad magic value found")),
            }
        }
    }

    /// Decodes one block; the block magic has already been consumed.
    fn read_block(&mut self) -> Result<()> {
        let bits = &mut self.bits;
        self.want_block_crc = bits.read_bits(32)? as u32;
        self.block_crc = 0;
        self.file_crc = self.file_crc.rotate_left(1) ^ self.want_block_crc;
        if bits.read_bits(1)? != 0 {
            return Err(Failure::Structural("deprecated randomized files"));
        }
        let orig_ptr = bits.read_bits(24)? as usize;

        // Byte values in use, as a two-level 16x16 bitmap.
        let ranges = bits.read_bits(16)?;
        let mut symbols = Vec::with_capacity(256);
        for range in 0..16u32 {
            if ranges & (1 << (15 - range)) != 0 {
                let used = bits.read_bits(16)?;
                for symbol in 0..16u32 {
                    if used & (1 << (15 - symbol)) != 0 {
                        symbols.push((16 * range + symbol) as u8);
                    }
                }
            }
        }
        if symbols.is_empty() {
            return Err(Failure::Structural("no symbols in input"));
        }

        let tree_count = bits.read_bits(3)? as usize;
        if !(2..=6).contains(&tree_count) {
            return Err(Failure::Structural("invalid number of Huffman trees"));
        }
        // Tree selectors are move-to-front coded unary numbers.
        let selector_count = bits.read_bits(15)? as usize;
        let mut selectors = Vec::with_capacity(selector_count);
        let mut tree_mtf: Vec<u8> = (0..tree_count as u8).collect();
        for _ in 0..selector_count {
            let mut c = 0usize;
            while bits.read_bit()? {
                c += 1;
            }
            if c >= tree_count {
                return Err(Failure::Structural("tree index too large"));
            }
            selectors.push(mtf_decode(&mut tree_mtf, c));
        }

        // Alphabet: RUNA, RUNB, the MTF indexes 1..symbols, then EOB.
        let alphabet = symbols.len() + 2;
        let mut trees = Vec::with_capacity(tree_count);
        let mut lengths = vec![0u8; alphabet];
        for _ in 0..tree_count {
            // Code lengths are delta coded from a 5-bit start value.
            let mut length = bits.read_bits(5)? as i32;
            for slot in lengths.iter_mut() {
                loop {
                    if !(1..=20).contains(&length) {
                        return Err(Failure::Structural("Huffman length out of range"));
                    }
                    if !bits.read_bit()? {
                        break;
                    }
                    if bits.read_bit()? {
                        length -= 1;
                    } else {
                        length += 1;
                    }
                }
                *slot = length as u8;
            }
            trees.push(Tree::new(&lengths)?);
        }

        if selectors.is_empty() {
            return Err(Failure::Structural("no tree selectors given"));
        }
        if usize::from(selectors[0]) >= trees.len() {
            return Err(Failure::Structural("tree selector out of range"));
        }
        let mut tree = &trees[usize::from(selectors[0])];
        let mut selector_index = 1;
        let mut mtf = symbols;
        let mut counts = [0usize; 256];
        let mut buf_index = 0usize;
        let mut repeat = 0usize;
        let mut repeat_power = 0usize;
        let mut decoded = 0;
        loop {
            if decoded == 50 {
                if selector_index >= selector_count {
                    return Err(Failure::Structural(
                        "insufficient selector indices for number of symbols",
                    ));
                }
                if usize::from(selectors[selector_index]) >= trees.len() {
                    return Err(Failure::Structural("tree selector out of range"));
                }
                tree = &trees[usize::from(selectors[selector_index])];
                selector_index += 1;
                decoded = 0;
            }
            let value = usize::from(tree.decode(bits)?);
            decoded += 1;

            if value < 2 {
                // RUNA/RUNB: bijective base-2 digits of a run length.
                if repeat == 0 {
                    repeat_power = 1;
                }
                repeat += repeat_power << value;
                repeat_power <<= 1;
                if repeat > MAX_REPEAT {
                    return Err(Failure::Structural("repeat count too large"));
                }
                continue;
            }
            if repeat > 0 {
                if repeat > self.block_size - buf_index {
                    return Err(Failure::Structural("repeats past end of block"));
                }
                let byte = mtf[0];
                self.tt[buf_index..buf_index + repeat].fill(u32::from(byte));
                counts[usize::from(byte)] += repeat;
                buf_index += repeat;
                repeat = 0;
            }
            if value == alphabet - 1 {
                break;
            }
            // MTF index 0 is always coded as a run, so symbol v means v-1.
            let byte = mtf_decode(&mut mtf, value - 1);
            if buf_index >= self.block_size {
                return Err(Failure::Structural("data exceeds block size"));
            }
            self.tt[buf_index] = u32::from(byte);
            counts[usize::from(byte)] += 1;
            buf_index += 1;
        }

        if orig_ptr >= buf_index {
            return Err(Failure::Structural("origPtr out of bounds"));
        }
        self.t_pos = inverse_bwt(&mut self.tt[..buf_index], orig_ptr, &mut counts);
        self.pre_rle_len = buf_index;
        self.pre_rle_used = 0;
        self.last_byte = -1;
        self.byte_repeats = 0;
        self.repeats = 0;
        Ok(())
    }
}

/// Single-array inverse Burrows-Wheeler transform from the bzip2 sources:
/// links to the next byte are stored in the upper 24 bits of `tt`. Returns
/// the index of the first output byte.
fn inverse_bwt(tt: &mut [u32], orig_ptr: usize, counts: &mut [usize; 256]) -> u32 {
    let mut sum = 0;
    for count in counts.iter_mut() {
        let current = *count;
        *count = sum;
        sum += current;
    }
    for i in 0..tt.len() {
        let byte = (tt[i] & 0xff) as usize;
        tt[counts[byte]] |= (i as u32) << 8;
        counts[byte] += 1;
    }
    tt[orig_ptr] >> 8
}

impl<R: Read> Read for Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(failure) = &self.failure {
            return Err(failure.to_error());
        }
        if self.eof {
            return Ok(0);
        }
        let result = if self.setup_done {
            self.read_inner(buf)
        } else {
            self.setup(true).and_then(|()| {
                self.setup_done = true;
                self.read_inner(buf)
            })
        };
        let (n, mut failure) = match result {
            Ok(n) => (n, None),
            Err(failure) => (0, Some(failure)),
        };
        // Go reports the bit reader's error in place of any other, together
        // with the bytes of the same call.
        if let Some(bit_error) = &self.bits.err {
            if !matches!(failure, Some(Failure::Limit(_)))
                && !matches!(self.failure, Some(Failure::Limit(_)))
            {
                failure = Some(bit_error.clone());
            }
        }
        if self.failure.is_some() && failure.is_none() {
            failure = self.failure.clone();
        }
        match failure {
            None => Ok(n),
            Some(failure) => {
                let error = failure.to_error();
                self.failure = Some(failure);
                if n > 0 {
                    Ok(n)
                } else {
                    Err(error)
                }
            }
        }
    }
}

/// Decompresses an in-memory input, which may hold concatenated streams.
pub fn decode(input: &[u8], limits: Limits) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    Reader::with_limits(input, limits).read_to_end(&mut output)?;
    Ok(output)
}
