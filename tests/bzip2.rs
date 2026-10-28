use rust_stdlib::compress::bzip2::{self, Limits, Reader, StructuralError};
use std::io::{self, ErrorKind, Read};

/// `bz2.compress(b"hello, bzip2!\n" * 3, 9)` from Python.
const HELLO: [u8; 61] = [
    0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x16, 0x81, 0xca, 0x14, 0x00, 0x00,
    0x0b, 0xd9, 0x80, 0x00, 0x10, 0x60, 0x04, 0x10, 0x00, 0x12, 0x64, 0xc0, 0x10, 0x20, 0x00, 0x22,
    0xbf, 0xd5, 0x40, 0x0d, 0x34, 0x20, 0x1a, 0x00, 0xb2, 0xec, 0x21, 0xe6, 0x9d, 0x6d, 0x28, 0x4d,
    0x12, 0x97, 0xc5, 0xdc, 0x91, 0x4e, 0x14, 0x24, 0x05, 0xa0, 0x72, 0x85, 0x00,
];
/// `bz2.compress(b"", 9)`: a stream with no blocks.
const EMPTY: [u8; 14] = [
    0x42, 0x5a, 0x68, 0x39, 0x17, 0x72, 0x45, 0x38, 0x50, 0x90, 0x00, 0x00, 0x00, 0x00,
];

fn hello_text() -> Vec<u8> {
    b"hello, bzip2!\n".repeat(3)
}

fn crc(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte) << 24;
        for _ in 0..8 {
            crc = if crc & 0x8000_0000 != 0 {
                (crc << 1) ^ 0x04c1_1db7
            } else {
                crc << 1
            };
        }
    }
    !crc
}

#[derive(Default)]
struct Bits {
    out: Vec<u8>,
    acc: u8,
    n: u32,
}

impl Bits {
    fn put(&mut self, value: u64, width: u32) {
        for i in (0..width).rev() {
            self.acc = (self.acc << 1) | ((value >> i) & 1) as u8;
            self.n += 1;
            if self.n == 8 {
                self.out.push(self.acc);
                self.acc = 0;
                self.n = 0;
            }
        }
    }
    fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.out.push(self.acc << (8 - self.n));
        }
        self.out
    }
}

/// Fields of one block, built from data and then optionally corrupted.
struct Block {
    crc: u32,
    randomized: bool,
    orig_ptr: u32,
    used: Vec<u8>,
    trees: Vec<Vec<u8>>,
    /// Unary, move-to-front coded tree indexes, one per 50 symbols.
    selectors: Vec<u32>,
    symbols: Vec<u16>,
}

fn run_symbols(mut run: usize, symbols: &mut Vec<u16>) {
    while run > 0 {
        run -= 1;
        symbols.push((run & 1) as u16);
        run >>= 1;
    }
}

/// Lengths of a complete prefix code: every symbol gets k or k-1 bits.
fn complete_lengths(alphabet: usize) -> Vec<u8> {
    let k = alphabet.next_power_of_two().trailing_zeros() as u8;
    let short = (1usize << k) - alphabet;
    (0..alphabet)
        .map(|i| if i < short { k - 1 } else { k })
        .collect()
}

impl Block {
    /// Encodes a small block: initial RLE, naive BWT, MTF and RUNA/RUNB.
    fn from_data(data: &[u8]) -> Self {
        let mut rle = Vec::new();
        let mut i = 0;
        while i < data.len() {
            let mut run = 1;
            while i + run < data.len() && data[i + run] == data[i] && run < 255 + 4 {
                run += 1;
            }
            if run >= 4 {
                rle.extend_from_slice(&[data[i]; 4]);
                rle.push((run - 4) as u8);
            } else {
                rle.extend(std::iter::repeat_n(data[i], run));
            }
            i += run;
        }
        let n = rle.len();
        let mut rotations: Vec<usize> = (0..n).collect();
        rotations.sort_by(|&a, &b| {
            (0..n)
                .map(|k| rle[(a + k) % n])
                .cmp((0..n).map(|k| rle[(b + k) % n]))
        });
        let orig_ptr = rotations.iter().position(|&r| r == 0).unwrap_or(0) as u32;
        let last: Vec<u8> = rotations.iter().map(|&r| rle[(r + n - 1) % n]).collect();
        let mut used: Vec<u8> = last.clone();
        used.sort_unstable();
        used.dedup();
        let mut mtf = used.clone();
        let mut symbols = Vec::new();
        let mut zeros = 0;
        for &byte in &last {
            let index = mtf.iter().position(|&b| b == byte).unwrap();
            if index == 0 {
                zeros += 1;
                continue;
            }
            run_symbols(zeros, &mut symbols);
            zeros = 0;
            symbols.push(index as u16 + 1);
            mtf.remove(index);
            mtf.insert(0, byte);
        }
        run_symbols(zeros, &mut symbols);
        symbols.push(used.len() as u16 + 1);
        let lengths = complete_lengths(used.len() + 2);
        Block {
            crc: crc(data),
            randomized: false,
            orig_ptr,
            selectors: vec![0; symbols.len().div_ceil(50)],
            trees: vec![lengths.clone(), lengths],
            used,
            symbols,
        }
    }

    fn write(&self, bits: &mut Bits) {
        bits.put(0x3141_5926_5359, 48);
        bits.put(u64::from(self.crc), 32);
        bits.put(u64::from(self.randomized), 1);
        bits.put(u64::from(self.orig_ptr), 24);
        let mut ranges = 0u64;
        for &b in &self.used {
            ranges |= 1 << (15 - b / 16);
        }
        bits.put(ranges, 16);
        for range in 0..16u8 {
            if ranges & (1 << (15 - range)) != 0 {
                let mut set = 0u64;
                for &b in self.used.iter().filter(|&&b| b / 16 == range) {
                    set |= 1 << (15 - b % 16);
                }
                bits.put(set, 16);
            }
        }
        bits.put(self.trees.len() as u64, 3);
        bits.put(self.selectors.len() as u64, 15);
        for &selector in &self.selectors {
            for _ in 0..selector {
                bits.put(1, 1);
            }
            bits.put(0, 1);
        }
        let mut codes = Vec::new();
        for lengths in &self.trees {
            let mut current = i32::from(lengths.first().copied().unwrap_or(0));
            bits.put(current as u64, 5);
            for &length in lengths {
                while current < i32::from(length) {
                    bits.put(0b10, 2);
                    current += 1;
                }
                while current > i32::from(length) {
                    bits.put(0b11, 2);
                    current -= 1;
                }
                bits.put(0, 1);
            }
            // Canonical codes: by length, then by symbol value.
            let mut order: Vec<usize> = (0..lengths.len()).collect();
            order.sort_by_key(|&s| (lengths[s], s));
            let mut tree = vec![(0u64, 0u32); lengths.len()];
            let mut code = 0u64;
            let mut previous = 0u32;
            for s in order {
                let length = u32::from(lengths[s]);
                code <<= length - previous.min(length);
                previous = length;
                tree[s] = (code, length);
                code += 1;
            }
            codes.push(tree);
        }
        let mut mtf: Vec<usize> = (0..self.trees.len()).collect();
        let mut tree = 0;
        for (i, &symbol) in self.symbols.iter().enumerate() {
            if i % 50 == 0 && !mtf.is_empty() {
                if let Some(&selector) = self.selectors.get(i / 50) {
                    let index = (selector as usize).min(mtf.len().saturating_sub(1));
                    tree = mtf.remove(index);
                    mtf.insert(0, tree);
                }
            }
            if let Some(&(code, length)) = codes.get(tree).and_then(|t| t.get(symbol as usize)) {
                bits.put(code, length);
            }
        }
    }
}

fn stream(level: u8, blocks: &[Block]) -> Vec<u8> {
    let mut bits = Bits::default();
    bits.put(u64::from_be_bytes(*b"\0\0\0\0\0BZh"), 24);
    bits.put(u64::from(b'0' + level), 8);
    let mut file_crc = 0u32;
    for block in blocks {
        block.write(&mut bits);
        file_crc = file_crc.rotate_left(1) ^ block.crc;
    }
    bits.put(0x1772_4538_5090, 48);
    bits.put(u64::from(file_crc), 32);
    bits.finish()
}

fn decode(input: &[u8]) -> io::Result<Vec<u8>> {
    bzip2::decode(input, Limits::default())
}

fn structural(error: &io::Error) -> &'static str {
    assert_eq!(error.kind(), ErrorKind::InvalidData, "{error}");
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<StructuralError>())
        .unwrap_or_else(|| panic!("not a StructuralError: {error}"))
        .reason()
}

fn rejects(input: &[u8], reason: &str) {
    let error = decode(input).unwrap_err();
    assert_eq!(structural(&error), reason);
}

#[test]
fn decodes_python_streams_and_concatenations() {
    assert_eq!(decode(&HELLO).unwrap(), hello_text());
    assert!(decode(&EMPTY).unwrap().is_empty());
    let joined = [&HELLO[..], &EMPTY, &HELLO].concat();
    assert_eq!(decode(&joined).unwrap(), hello_text().repeat(2));
    let error = decode(&[]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
}

#[test]
fn builder_streams_round_trip_including_runs_and_blocks() {
    let samples: [&[u8]; 6] = [
        b"a",
        b"banana",
        b"aaaa",
        b"aaaab",
        &[7u8; 600],
        b"the quick brown fox jumps over the lazy dog",
    ];
    for data in samples {
        let encoded = stream(1, &[Block::from_data(data)]);
        assert_eq!(decode(&encoded).unwrap(), data, "{data:?}");
    }
    let two = stream(9, &[Block::from_data(b"one "), Block::from_data(b"two")]);
    assert_eq!(decode(&two).unwrap(), b"one two");
    let all: Vec<u8> = (0..=255u8).collect();
    assert_eq!(decode(&stream(2, &[Block::from_data(&all)])).unwrap(), all);
}

struct Trickle<'a> {
    data: &'a [u8],
    interrupt: bool,
}

impl Read for Trickle<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.interrupt = !self.interrupt;
        if self.interrupt {
            return Err(io::Error::from(ErrorKind::Interrupted));
        }
        if self.data.is_empty() || buf.is_empty() {
            return Ok(0);
        }
        buf[0] = self.data[0];
        self.data = &self.data[1..];
        Ok(1)
    }
}

#[test]
fn one_byte_sources_and_small_buffers_stream() {
    let joined = [&HELLO[..], &HELLO].concat();
    let mut reader = Reader::new(Trickle {
        data: &joined,
        interrupt: false,
    });
    let mut output = Vec::new();
    let mut small = [0u8; 3];
    loop {
        let count = reader.read(&mut small).unwrap();
        if count == 0 {
            break;
        }
        output.extend_from_slice(&small[..count]);
    }
    assert_eq!(output, hello_text().repeat(2));
    assert_eq!(reader.total_out(), output.len() as u64);
    assert_eq!(reader.read(&mut small).unwrap(), 0);
}

#[test]
fn source_errors_pass_through_and_latch() {
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(ErrorKind::ConnectionReset, "gone"))
        }
    }
    let mut reader = Reader::new(Broken);
    let mut buf = [0u8; 8];
    assert_eq!(
        reader.read(&mut buf).unwrap_err().kind(),
        ErrorKind::ConnectionReset
    );
    assert_eq!(
        reader.read(&mut buf).unwrap_err().kind(),
        ErrorKind::ConnectionReset
    );
}

#[test]
fn every_truncation_is_rejected() {
    for input in [&HELLO[..], &EMPTY] {
        for cut in 0..input.len() {
            assert!(decode(&input[..cut]).is_err(), "accepted prefix {cut}");
        }
    }
    // A trailing byte that cannot start a continuation stream.
    let error = decode(&[&HELLO[..], b"B"].concat()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
    rejects(
        &[&HELLO[..], b"XY"].concat(),
        "bad magic value in continuation file",
    );
}

#[test]
fn header_errors_match_go() {
    rejects(b"BZx9", "non-Huffman entropy encoding");
    rejects(b"XZh9", "bad magic value");
    rejects(b"BZh0", "invalid compression level");
    rejects(b"BZh:", "invalid compression level");
    let mut bad = EMPTY;
    bad[4] ^= 1;
    rejects(&bad, "bad magic value found");
}

#[test]
fn bad_checksums_are_rejected_after_streaming_the_block() {
    let mut bad_block = HELLO;
    bad_block[12] ^= 0x01;
    let mut reader = Reader::new(&bad_block[..]);
    let mut output = Vec::new();
    let error = reader.read_to_end(&mut output).unwrap_err();
    assert_eq!(structural(&error), "block checksum mismatch");
    // Go also delivers the block before checking its CRC.
    assert_eq!(output, hello_text());
    // Errors are terminal.
    assert_eq!(
        structural(&reader.read(&mut [0u8; 4]).unwrap_err()),
        "block checksum mismatch"
    );

    let mut bad_file = HELLO;
    bad_file[HELLO.len() - 2] ^= 0x10;
    rejects(&bad_file, "file checksum mismatch");
}

#[test]
fn randomized_blocks_and_invalid_origin_pointers_are_rejected() {
    let mut block = Block::from_data(b"banana");
    block.randomized = true;
    rejects(&stream(1, &[block]), "deprecated randomized files");
    for orig_ptr in [6, 7, 0xff_ffff] {
        let mut block = Block::from_data(b"banana");
        block.orig_ptr = orig_ptr;
        rejects(&stream(1, &[block]), "origPtr out of bounds");
    }
    // A valid-but-wrong pointer rotates the output and fails the CRC.
    let mut block = Block::from_data(b"banana");
    block.orig_ptr = (block.orig_ptr + 1) % 6;
    rejects(&stream(1, &[block]), "block checksum mismatch");
    let mut block = Block::from_data(b"a");
    block.used.clear();
    rejects(&stream(1, &[block]), "no symbols in input");
}

#[test]
fn bad_huffman_tables_are_rejected() {
    let base = || Block::from_data(b"banana");
    let alphabet = base().used.len() + 2;
    for count in [0, 1, 7] {
        let mut block = base();
        block.trees = vec![complete_lengths(alphabet); count];
        rejects(&stream(1, &[block]), "invalid number of Huffman trees");
    }
    for bad in [0u8, 21] {
        let mut block = base();
        block.trees[1][2] = bad;
        rejects(&stream(1, &[block]), "Huffman length out of range");
    }
    let mut block = base();
    block.trees[0] = vec![1; alphabet];
    rejects(&stream(1, &[block]), "equal symbols in Huffman tree");
    let mut block = base();
    block.selectors = vec![2];
    rejects(&stream(1, &[block]), "tree index too large");
    let mut block = base();
    block.selectors.clear();
    rejects(&stream(1, &[block]), "no tree selectors given");
    let many: Vec<u8> = (0..120).collect();
    let mut block = Block::from_data(&many);
    assert!(block.symbols.len() > 50);
    block.selectors.truncate(1);
    rejects(
        &stream(1, &[block]),
        "insufficient selector indices for number of symbols",
    );
}

#[test]
fn incomplete_huffman_tables_are_tolerated_like_go() {
    // Go builds trees from incomplete length sets instead of rejecting them;
    // here the incomplete table is declared but never selected.
    let mut block = Block::from_data(b"banana");
    let alphabet = block.trees[0].len();
    block.trees[1] = vec![4; alphabet];
    assert_eq!(decode(&stream(1, &[block])).unwrap(), b"banana");
}

#[test]
fn oversized_runs_and_blocks_are_rejected() {
    let mut block = Block::from_data(b"ab");
    let eob = block.symbols.pop().unwrap();
    block.symbols = vec![1; 22];
    block.symbols.push(eob);
    rejects(&stream(1, &[block]), "repeat count too large");

    let mut block = Block::from_data(b"ab");
    block.symbols.clear();
    run_symbols(100_001, &mut block.symbols);
    block.symbols.push(eob);
    rejects(&stream(1, &[block]), "repeats past end of block");

    let mut block = Block::from_data(b"ab");
    block.symbols.clear();
    run_symbols(100_000, &mut block.symbols);
    block.symbols.extend([2, eob]);
    rejects(&stream(1, &[block]), "data exceeds block size");
}

#[test]
fn output_limit_is_enforced_while_streaming() {
    let text = hello_text();
    let exact = Limits {
        max_output: text.len() as u64,
        ..Limits::default()
    };
    assert_eq!(bzip2::decode(&HELLO, exact).unwrap(), text);
    let short = Limits {
        max_output: text.len() as u64 - 1,
        ..Limits::default()
    };
    let mut reader = Reader::with_limits(&HELLO[..], short);
    let mut output = Vec::new();
    let error = reader.read_to_end(&mut output).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidData);
    assert!(error.to_string().contains("limit"), "{error}");
    assert_eq!(output, text[..text.len() - 1]);

    // Run-length expansion is counted byte by byte.
    let runs = stream(1, &[Block::from_data(&[b'z'; 10_000])]);
    assert_eq!(decode(&runs).unwrap().len(), 10_000);
    let limits = Limits {
        max_output: 300,
        ..Limits::default()
    };
    let mut output = Vec::new();
    let error = Reader::with_limits(&runs[..], limits)
        .read_to_end(&mut output)
        .unwrap_err();
    assert!(error.to_string().contains("limit"), "{error}");
    assert_eq!(output.len(), 300);
}

#[test]
fn block_size_limit_applies_to_every_stream_header() {
    let limits = Limits {
        max_block_size: 300_000,
        ..Limits::default()
    };
    let small = stream(3, &[Block::from_data(b"ok")]);
    assert_eq!(bzip2::decode(&small, limits).unwrap(), b"ok");
    let error = bzip2::decode(&HELLO, limits).unwrap_err();
    assert!(error.to_string().contains("block size"), "{error}");
    let mut output = Vec::new();
    let joined = [&small[..], &HELLO].concat();
    let error = Reader::with_limits(&joined[..], limits)
        .read_to_end(&mut output)
        .unwrap_err();
    assert!(error.to_string().contains("block size"), "{error}");
    assert_eq!(output, b"ok");
}
