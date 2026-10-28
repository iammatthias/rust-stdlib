//! DEFLATE decoder with Go's byte-pull discipline.
//!
//! Input is consumed exactly as `compress/flate` consumes it (one byte at a
//! time, only when more bits are needed), so [`CorruptInputError`] offsets,
//! trailing-data behaviour and the bytes delivered before an error all match
//! Go. The Huffman table layout, validity rules and step machine follow Go's
//! `inflate.go` (BSD-licensed; see NOTICE).
use super::{CorruptInputError, Fail, InternalError};
use std::io::{self, BufRead};
use std::sync::OnceLock;

const MAX_NUM_LIT: usize = 286;
const MAX_NUM_DIST: usize = 30;
const NUM_CODES: usize = 19;
const CHUNK_BITS: usize = 9;
const NUM_CHUNKS: usize = 1 << CHUNK_BITS;
const COUNT_MASK: u32 = 15;
const VALUE_SHIFT: u32 = 4;
/// Largest back-reference distance and size of the history window.
pub(crate) const MAX_MATCH_OFFSET: usize = 1 << 15;
const CODE_ORDER: [usize; NUM_CODES] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

pub(crate) fn unexpected_eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")
}

/// Read one byte; `Ok(None)` is a clean end of input.
pub(crate) fn read_byte<R: BufRead + ?Sized>(r: &mut R) -> io::Result<Option<u8>> {
    loop {
        let buf = match r.fill_buf() {
            Ok(buf) => buf,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        let Some(&byte) = buf.first() else {
            return Ok(None);
        };
        r.consume(1);
        return Ok(Some(byte));
    }
}

/// Go's `io.ReadFull`: `Fail::Eof` when nothing was read, `unexpected EOF`
/// when the input ended part-way. Returns the byte count read in all cases.
pub(crate) fn read_full<R: BufRead + ?Sized>(r: &mut R, buf: &mut [u8]) -> (usize, Option<Fail>) {
    let mut n = 0;
    while n < buf.len() {
        let available = match r.fill_buf() {
            Ok(a) => a,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return (n, Some(Fail::Err(e))),
        };
        if available.is_empty() {
            let fail = if n == 0 {
                Fail::Eof
            } else {
                Fail::Err(unexpected_eof())
            };
            return (n, Some(fail));
        }
        let take = available.len().min(buf.len() - n);
        buf[n..n + take].copy_from_slice(&available[..take]);
        r.consume(take);
        n += take;
    }
    (n, None)
}

/// Huffman decoding table: a 9-bit direct lookup plus overflow link tables.
struct HuffDecoder {
    min: usize,
    chunks: [u32; NUM_CHUNKS],
    links: Vec<Vec<u32>>,
    link_mask: u32,
}

impl HuffDecoder {
    fn new() -> Self {
        Self {
            min: 0,
            chunks: [0; NUM_CHUNKS],
            links: Vec::new(),
            link_mask: 0,
        }
    }

    /// Complete trees only, plus Go's exceptions: an empty tree and a single
    /// code of length one are accepted (using them later fails).
    fn init(&mut self, lengths: &[i32]) -> bool {
        if self.min != 0 {
            *self = Self::new();
        }
        let mut count = [0usize; 16];
        let (mut min, mut max) = (0usize, 0usize);
        for &n in lengths {
            if n == 0 {
                continue;
            }
            let n = n as usize;
            if min == 0 || n < min {
                min = n;
            }
            if n > max {
                max = n;
            }
            count[n] += 1;
        }
        if max == 0 {
            return true;
        }
        let mut code = 0usize;
        let mut next_code = [0usize; 16];
        for i in min..=max {
            code <<= 1;
            next_code[i] = code;
            code += count[i];
        }
        if code != 1 << max && !(code == 1 && max == 1) {
            return false;
        }
        self.min = min;
        if max > CHUNK_BITS {
            let num_links = 1usize << (max - CHUNK_BITS);
            self.link_mask = (num_links - 1) as u32;
            let link = next_code[CHUNK_BITS + 1] >> 1;
            self.links = vec![Vec::new(); NUM_CHUNKS - link];
            for j in link..NUM_CHUNKS {
                let reverse = ((j as u16).reverse_bits() >> (16 - CHUNK_BITS)) as usize;
                let off = j - link;
                self.chunks[reverse] = ((off as u32) << VALUE_SHIFT) | (CHUNK_BITS as u32 + 1);
                self.links[off] = vec![0; num_links];
            }
        }
        for (i, &n) in lengths.iter().enumerate() {
            if n == 0 {
                continue;
            }
            let n = n as usize;
            let code = next_code[n];
            next_code[n] += 1;
            let chunk = ((i as u32) << VALUE_SHIFT) | n as u32;
            let reverse = ((code as u16).reverse_bits() >> (16 - n)) as usize;
            if n <= CHUNK_BITS {
                let mut off = reverse;
                while off < NUM_CHUNKS {
                    self.chunks[off] = chunk;
                    off += 1 << n;
                }
            } else {
                let j = reverse & (NUM_CHUNKS - 1);
                let value = (self.chunks[j] >> VALUE_SHIFT) as usize;
                let table = &mut self.links[value];
                let mut off = reverse >> CHUNK_BITS;
                while off < table.len() {
                    table[off] = chunk;
                    off += 1 << (n - CHUNK_BITS);
                }
            }
        }
        true
    }
}

fn fixed_decoder() -> &'static HuffDecoder {
    static FIXED: OnceLock<HuffDecoder> = OnceLock::new();
    FIXED.get_or_init(|| {
        let mut bits = [0i32; 288];
        bits[..144].fill(8);
        bits[144..256].fill(9);
        bits[256..280].fill(7);
        bits[280..].fill(8);
        let mut h = HuffDecoder::new();
        h.init(&bits);
        h
    })
}

fn corrupt(offset: i64) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, CorruptInputError(offset))
}

/// Bit reservoir state shared by the symbol readers.
struct Bits {
    b: u32,
    nb: u32,
    roffset: i64,
}

impl Bits {
    fn more<R: BufRead + ?Sized>(&mut self, r: &mut R) -> io::Result<()> {
        match read_byte(r)? {
            None => Err(unexpected_eof()),
            Some(c) => {
                self.roffset += 1;
                self.b |= u32::from(c) << self.nb;
                self.nb += 8;
                Ok(())
            }
        }
    }

    fn need<R: BufRead + ?Sized>(&mut self, r: &mut R, n: u32) -> io::Result<()> {
        while self.nb < n {
            self.more(r)?;
        }
        Ok(())
    }

    fn take(&mut self, n: u32) -> u32 {
        let v = self.b & ((1u32 << n) - 1);
        self.b >>= n;
        self.nb -= n;
        v
    }

    fn sym<R: BufRead + ?Sized>(&mut self, h: &HuffDecoder, r: &mut R) -> io::Result<usize> {
        let mut n = h.min as u32;
        loop {
            while self.nb < n {
                match read_byte(r)? {
                    None => return Err(unexpected_eof()),
                    Some(c) => {
                        self.roffset += 1;
                        self.b |= u32::from(c) << (self.nb & 31);
                        self.nb += 8;
                    }
                }
            }
            let mut chunk = h.chunks[(self.b as usize) & (NUM_CHUNKS - 1)];
            n = chunk & COUNT_MASK;
            if n > CHUNK_BITS as u32 {
                chunk = h.links[(chunk >> VALUE_SHIFT) as usize]
                    [((self.b >> CHUNK_BITS) & h.link_mask) as usize];
                n = chunk & COUNT_MASK;
            }
            if n <= self.nb {
                if n == 0 {
                    return Err(corrupt(self.roffset));
                }
                self.b >>= n & 31;
                self.nb -= n;
                return Ok((chunk >> VALUE_SHIFT) as usize);
            }
        }
    }
}

/// The 32 KiB output history, as Go's `dictDecoder`.
struct Dict {
    hist: Vec<u8>,
    wr_pos: usize,
    rd_pos: usize,
    full: bool,
}

impl Dict {
    fn new() -> Self {
        Self {
            hist: vec![0; MAX_MATCH_OFFSET],
            wr_pos: 0,
            rd_pos: 0,
            full: false,
        }
    }

    fn init(&mut self, dict: &[u8]) {
        self.full = false;
        let dict = &dict[dict.len().saturating_sub(self.hist.len())..];
        self.hist[..dict.len()].copy_from_slice(dict);
        self.wr_pos = dict.len();
        if self.wr_pos == self.hist.len() {
            self.wr_pos = 0;
            self.full = true;
        }
        self.rd_pos = self.wr_pos;
    }

    fn hist_size(&self) -> usize {
        if self.full {
            self.hist.len()
        } else {
            self.wr_pos
        }
    }

    fn avail_read(&self) -> usize {
        self.wr_pos - self.rd_pos
    }

    fn avail_write(&self) -> usize {
        self.hist.len() - self.wr_pos
    }

    fn write_byte(&mut self, c: u8) {
        self.hist[self.wr_pos] = c;
        self.wr_pos += 1;
    }

    /// Copy up to `length` bytes from `dist` back; returns the count copied.
    fn write_copy(&mut self, dist: usize, length: usize) -> usize {
        let n = length.min(self.avail_write());
        let size = self.hist.len();
        let mut src = if self.wr_pos >= dist {
            self.wr_pos - dist
        } else {
            self.wr_pos + size - dist
        };
        for i in 0..n {
            self.hist[self.wr_pos + i] = self.hist[src];
            src += 1;
            if src == size {
                src = 0;
            }
        }
        self.wr_pos += n;
        n
    }

    fn read_flush(&mut self) -> (usize, usize) {
        let range = (self.rd_pos, self.wr_pos);
        self.rd_pos = self.wr_pos;
        if self.wr_pos == self.hist.len() {
            self.wr_pos = 0;
            self.rd_pos = 0;
            self.full = true;
        }
        range
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    NextBlock,
    HuffmanBlock,
    CopyData,
}

/// Incremental DEFLATE decoder state; the byte source is passed per call so
/// gzip and zlib can share one buffered source with it.
pub(crate) struct Inflater {
    bits: Bits,
    h1: HuffDecoder,
    h2: HuffDecoder,
    lengths: [i32; MAX_NUM_LIT + MAX_NUM_DIST],
    code_bits: [i32; NUM_CODES],
    dict: Dict,
    step: Step,
    resume_copy: bool,
    final_block: bool,
    err: Option<Fail>,
    to_read: (usize, usize),
    fixed: bool,
    copy_len: usize,
    copy_dist: usize,
}

impl Inflater {
    pub(crate) fn new(dict: &[u8]) -> Self {
        let mut f = Self {
            bits: Bits {
                b: 0,
                nb: 0,
                roffset: 0,
            },
            h1: HuffDecoder::new(),
            h2: HuffDecoder::new(),
            lengths: [0; MAX_NUM_LIT + MAX_NUM_DIST],
            code_bits: [0; NUM_CODES],
            dict: Dict::new(),
            step: Step::NextBlock,
            resume_copy: false,
            final_block: false,
            err: None,
            to_read: (0, 0),
            fixed: false,
            copy_len: 0,
            copy_dist: 0,
        };
        f.dict.init(dict);
        f
    }

    pub(crate) fn reset(&mut self, dict: &[u8]) {
        self.bits = Bits {
            b: 0,
            nb: 0,
            roffset: 0,
        };
        self.h1 = HuffDecoder::new();
        self.h2 = HuffDecoder::new();
        self.step = Step::NextBlock;
        self.resume_copy = false;
        self.final_block = false;
        self.err = None;
        self.to_read = (0, 0);
        self.copy_len = 0;
        self.copy_dist = 0;
        self.dict.init(dict);
    }

    /// Go's `Read`: bytes and the error that goes with them. `Fail::Eof` is
    /// the clean end of the final block.
    pub(crate) fn read_stream<R: BufRead + ?Sized>(
        &mut self,
        r: &mut R,
        out: &mut [u8],
    ) -> (usize, Option<Fail>) {
        loop {
            let (start, end) = self.to_read;
            if end > start {
                let n = out.len().min(end - start);
                out[..n].copy_from_slice(&self.dict.hist[start..start + n]);
                self.to_read.0 += n;
                if self.to_read.0 == end {
                    return (n, self.err.as_ref().map(Fail::replay));
                }
                return (n, None);
            }
            if let Some(e) = &self.err {
                return (0, Some(e.replay()));
            }
            match self.step {
                Step::NextBlock => self.next_block(r),
                Step::HuffmanBlock => self.huffman_block(r),
                Step::CopyData => self.copy_data(r),
            }
            if self.err.is_some() && self.to_read.0 == self.to_read.1 {
                self.to_read = self.dict.read_flush();
            }
        }
    }

    pub(crate) fn close(&self) -> io::Result<()> {
        match &self.err {
            None | Some(Fail::Eof) => Ok(()),
            Some(e) => Err(e.to_io()),
        }
    }

    fn fail(&mut self, e: io::Error) {
        self.err = Some(Fail::Err(e));
    }

    fn next_block<R: BufRead + ?Sized>(&mut self, r: &mut R) {
        if let Err(e) = self.bits.need(r, 3) {
            return self.fail(e);
        }
        self.final_block = self.bits.b & 1 == 1;
        self.bits.b >>= 1;
        let typ = self.bits.b & 3;
        self.bits.b >>= 2;
        self.bits.nb -= 3;
        match typ {
            0 => self.data_block(r),
            1 => {
                self.fixed = true;
                self.huffman_block(r);
            }
            2 => {
                if let Err(e) = self.read_huffman(r) {
                    return self.fail(e);
                }
                self.fixed = false;
                self.huffman_block(r);
            }
            _ => self.fail(corrupt(self.bits.roffset)),
        }
    }

    fn read_huffman<R: BufRead + ?Sized>(&mut self, r: &mut R) -> io::Result<()> {
        self.bits.need(r, 5 + 5 + 4)?;
        let nlit = (self.bits.b & 0x1f) as usize + 257;
        if nlit > MAX_NUM_LIT {
            return Err(corrupt(self.bits.roffset));
        }
        self.bits.b >>= 5;
        let ndist = (self.bits.b & 0x1f) as usize + 1;
        if ndist > MAX_NUM_DIST {
            return Err(corrupt(self.bits.roffset));
        }
        self.bits.b >>= 5;
        let nclen = (self.bits.b & 0xf) as usize + 4;
        self.bits.b >>= 4;
        self.bits.nb -= 14;
        for &slot in CODE_ORDER.iter().take(nclen) {
            self.bits.need(r, 3)?;
            self.code_bits[slot] = self.bits.take(3) as i32;
        }
        for &slot in CODE_ORDER.iter().skip(nclen) {
            self.code_bits[slot] = 0;
        }
        if !self.h1.init(&self.code_bits) {
            return Err(corrupt(self.bits.roffset));
        }
        let n = nlit + ndist;
        let mut i = 0;
        while i < n {
            let x = self.bits.sym(&self.h1, r)?;
            if x < 16 {
                self.lengths[i] = x as i32;
                i += 1;
                continue;
            }
            let (rep, nb, value) = match x {
                16 => {
                    if i == 0 {
                        return Err(corrupt(self.bits.roffset));
                    }
                    (3, 2, self.lengths[i - 1])
                }
                17 => (3, 3, 0),
                18 => (11, 7, 0),
                _ => {
                    return Err(io::Error::other(InternalError(
                        "unexpected length code".into(),
                    )))
                }
            };
            self.bits.need(r, nb)?;
            let rep = rep + self.bits.take(nb) as usize;
            if i + rep > n {
                return Err(corrupt(self.bits.roffset));
            }
            self.lengths[i..i + rep].fill(value);
            i += rep;
        }
        if !self.h1.init(&self.lengths[..nlit]) || !self.h2.init(&self.lengths[nlit..nlit + ndist])
        {
            return Err(corrupt(self.bits.roffset));
        }
        // Every block ends with the end-of-block code, so never read past it.
        if self.h1.min < self.lengths[256] as usize {
            self.h1.min = self.lengths[256] as usize;
        }
        Ok(())
    }

    fn huffman_block<R: BufRead + ?Sized>(&mut self, r: &mut R) {
        let mut resume = self.resume_copy;
        loop {
            if !resume {
                let lit = if self.fixed {
                    fixed_decoder()
                } else {
                    &self.h1
                };
                let v = match self.bits.sym(lit, r) {
                    Ok(v) => v,
                    Err(e) => return self.fail(e),
                };
                let (mut length, n) = match v {
                    0..=255 => {
                        self.dict.write_byte(v as u8);
                        if self.dict.avail_write() == 0 {
                            self.to_read = self.dict.read_flush();
                            self.step = Step::HuffmanBlock;
                            self.resume_copy = false;
                            return;
                        }
                        continue;
                    }
                    256 => return self.finish_block(),
                    257..=264 => (v - (257 - 3), 0),
                    265..=268 => (v * 2 - (265 * 2 - 11), 1),
                    269..=272 => (v * 4 - (269 * 4 - 19), 2),
                    273..=276 => (v * 8 - (273 * 8 - 35), 3),
                    277..=280 => (v * 16 - (277 * 16 - 67), 4),
                    281..=284 => (v * 32 - (281 * 32 - 131), 5),
                    285 => (258, 0),
                    _ => return self.fail(corrupt(self.bits.roffset)),
                };
                if n > 0 {
                    if let Err(e) = self.bits.need(r, n) {
                        return self.fail(e);
                    }
                    length += self.bits.take(n) as usize;
                }
                let mut dist;
                if self.fixed {
                    if let Err(e) = self.bits.need(r, 5) {
                        return self.fail(e);
                    }
                    dist = usize::from((((self.bits.b & 0x1f) as u8) << 3).reverse_bits());
                    self.bits.b >>= 5;
                    self.bits.nb -= 5;
                } else {
                    dist = match self.bits.sym(&self.h2, r) {
                        Ok(d) => d,
                        Err(e) => return self.fail(e),
                    };
                }
                if dist < 4 {
                    dist += 1;
                } else if dist < MAX_NUM_DIST {
                    let nb = ((dist - 2) >> 1) as u32;
                    let mut extra = (dist & 1) << nb;
                    if let Err(e) = self.bits.need(r, nb) {
                        return self.fail(e);
                    }
                    extra |= self.bits.take(nb) as usize;
                    dist = (1 << (nb + 1)) + 1 + extra;
                } else {
                    return self.fail(corrupt(self.bits.roffset));
                }
                // No check on length; encoding can be prescient.
                if dist > self.dict.hist_size() {
                    return self.fail(corrupt(self.bits.roffset));
                }
                self.copy_len = length;
                self.copy_dist = dist;
            }
            resume = false;
            let cnt = self.dict.write_copy(self.copy_dist, self.copy_len);
            self.copy_len -= cnt;
            if self.dict.avail_write() == 0 || self.copy_len > 0 {
                self.to_read = self.dict.read_flush();
                self.step = Step::HuffmanBlock;
                self.resume_copy = true;
                return;
            }
        }
    }

    fn data_block<R: BufRead + ?Sized>(&mut self, r: &mut R) {
        self.bits.nb = 0;
        self.bits.b = 0;
        let mut buf = [0u8; 4];
        let (nr, err) = read_full(r, &mut buf);
        self.bits.roffset += nr as i64;
        if let Some(e) = err {
            self.err = Some(e.no_eof());
            return;
        }
        let n = usize::from(buf[0]) | usize::from(buf[1]) << 8;
        let nn = usize::from(buf[2]) | usize::from(buf[3]) << 8;
        if nn as u16 != !(n as u16) {
            return self.fail(corrupt(self.bits.roffset));
        }
        if n == 0 {
            self.to_read = self.dict.read_flush();
            return self.finish_block();
        }
        self.copy_len = n;
        self.copy_data(r);
    }

    fn copy_data<R: BufRead + ?Sized>(&mut self, r: &mut R) {
        let want = self.copy_len.min(self.dict.avail_write());
        let start = self.dict.wr_pos;
        let (cnt, err) = read_full(r, &mut self.dict.hist[start..start + want]);
        self.bits.roffset += cnt as i64;
        self.copy_len -= cnt;
        self.dict.wr_pos += cnt;
        if let Some(e) = err {
            self.err = Some(e.no_eof());
            return;
        }
        if self.dict.avail_write() == 0 || self.copy_len > 0 {
            self.to_read = self.dict.read_flush();
            self.step = Step::CopyData;
            return;
        }
        self.finish_block();
    }

    fn finish_block(&mut self) {
        if self.final_block {
            if self.dict.avail_read() > 0 {
                self.to_read = self.dict.read_flush();
            }
            self.err = Some(Fail::Eof);
        }
        self.step = Step::NextBlock;
    }
}
