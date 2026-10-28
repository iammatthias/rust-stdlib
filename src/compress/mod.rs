//! Bounded RFC 1951 DEFLATE, RFC 1950 zlib and RFC 1952 gzip codecs.
//!
//! The one-shot functions here decode stored, fixed and dynamic Huffman blocks.
//! All I/O is buffered with explicit input/output limits; preset dictionaries
//! are not supported by them. Gzip decoding validates every concatenated
//! member. Encoding is done by the `flate`, `zlib` and `gzip` writers.
//!
//! For Go's streaming `compress/flate`, `compress/gzip` and `compress/zlib`
//! APIs (all levels, dynamic Huffman, dictionaries, flushing) see the
//! [`flate`], [`gzip`] and [`zlib`] modules.
use std::io::{self, Read, Write};
pub mod bzip2;
pub mod flate;
pub mod gzip;
pub mod lzw;
pub mod zlib;

/// Bounds for the entire operation, including concatenated gzip members.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_input: usize,
    pub max_output: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input: 16 * 1024 * 1024,
            max_output: 64 * 1024 * 1024,
        }
    }
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
/// IEEE CRC-32 checksum used by gzip and ZIP.
pub fn crc32(bytes: &[u8]) -> u32 {
    crate::hash::crc32::checksum_ieee(bytes)
}
/// Adler-32 checksum used by zlib.
pub fn adler32(bytes: &[u8]) -> u32 {
    crate::hash::adler32::checksum(bytes)
}
trait BitRead {
    fn get(&mut self, n: u8) -> io::Result<usize>;
    fn align(&mut self);
}
mod stream;
pub use stream::Decoder;
struct Tree {
    counts: [usize; 16],
    first: [usize; 16],
    offset: [usize; 16],
    symbols: Vec<usize>,
}
impl Tree {
    fn new(lengths: &[usize], code_tree: bool) -> io::Result<Self> {
        let mut counts = [0usize; 16];
        for &n in lengths {
            if n > 15 {
                return Err(invalid("Huffman code too long"));
            }
            if n != 0 {
                counts[n] += 1;
            }
        }
        let symbols: usize = counts.iter().sum();
        let mut left = 1isize;
        for &count in &counts[1..] {
            left = left * 2 - count as isize;
            if left < 0 {
                return Err(invalid("oversubscribed Huffman tree"));
            }
        }
        if left != 0 && (code_tree || symbols != 1 || counts[1] != 1) && symbols != 0 {
            return Err(invalid("incomplete Huffman tree"));
        }
        if code_tree && symbols == 0 {
            return Err(invalid("empty code-length tree"));
        }
        let mut next = [0usize; 16];
        let mut code = 0;
        for n in 1..16 {
            code = (code + counts[n - 1]) << 1;
            next[n] = code;
        }
        let mut offset = [0usize; 16];
        let mut ordered = Vec::with_capacity(symbols);
        for (n, slot) in offset.iter_mut().enumerate().skip(1) {
            *slot = ordered.len();
            ordered.extend(
                lengths
                    .iter()
                    .enumerate()
                    .filter_map(|(symbol, &length)| (length == n).then_some(symbol)),
            );
        }
        Ok(Self {
            counts,
            first: next,
            offset,
            symbols: ordered,
        })
    }
    fn symbol(&self, bits: &mut impl BitRead) -> io::Result<usize> {
        let mut code = 0;
        for n in 1..16 {
            code = (code << 1) | bits.get(1)?;
            if code >= self.first[n] {
                let relative = code - self.first[n];
                if relative < self.counts[n] {
                    return Ok(self.symbols[self.offset[n] + relative]);
                }
            }
        }
        Err(invalid("invalid Huffman code"))
    }
}
const LENGTH: [usize; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_BITS: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DISTANCE: [usize; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DISTANCE_BITS: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
fn trees(bits: &mut impl BitRead, kind: usize) -> io::Result<(Tree, Tree)> {
    if kind == 1 {
        let mut lengths = vec![8; 288];
        lengths[144..256].fill(9);
        lengths[256..280].fill(7);
        return Ok((Tree::new(&lengths, false)?, Tree::new(&[5; 32], false)?));
    }
    let literals = bits.get(5)? + 257;
    let distances = bits.get(5)? + 1;
    let n = bits.get(4)? + 4;
    if literals > 286 {
        return Err(invalid("reserved literal code count"));
    }
    let order = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];
    let mut lengths = [0usize; 19];
    for &i in &order[..n] {
        lengths[i] = bits.get(3)?;
    }
    let code = Tree::new(&lengths, true)?;
    let total = literals + distances;
    let mut lengths = Vec::with_capacity(total);
    while lengths.len() < total {
        let symbol = code.symbol(bits)?;
        let (value, count) = match symbol {
            0..=15 => (symbol, 1),
            16 => (
                *lengths
                    .last()
                    .ok_or_else(|| invalid("repeat without previous code"))?,
                bits.get(2)? + 3,
            ),
            17 => (0, bits.get(3)? + 3),
            18 => (0, bits.get(7)? + 11),
            _ => return Err(invalid("invalid code-length symbol")),
        };
        if count > total - lengths.len() {
            return Err(invalid("code-length repeat overrun"));
        }
        lengths.resize(lengths.len() + count, value);
    }
    if lengths[256] == 0 {
        return Err(invalid("missing end-of-block code"));
    }
    Ok((
        Tree::new(&lengths[..literals], false)?,
        Tree::new(&lengths[literals..], false)?,
    ))
}
/// Decode a raw DEFLATE stream; trailing bytes are rejected.
pub fn decode_deflate(reader: impl Read, mut writer: impl Write, limits: Limits) -> io::Result<()> {
    let mut decoder = Decoder::deflate(reader, limits)?;
    let mut output = Vec::new();
    decoder.read_to_end(&mut output)?;
    writer.write_all(&output)
}
/// Decode zlib, rejecting preset dictionaries and trailing bytes.
pub fn decode_zlib(reader: impl Read, mut writer: impl Write, limits: Limits) -> io::Result<()> {
    let mut decoder = Decoder::zlib(reader, limits)?;
    let mut output = Vec::new();
    decoder.read_to_end(&mut output)?;
    writer.write_all(&output)
}
/// Decode and verify all concatenated gzip members. Output is written only
/// after all framing, checksums and resource limits validate.
pub fn decode_gzip(reader: impl Read, mut writer: impl Write, limits: Limits) -> io::Result<()> {
    let mut decoder = Decoder::gzip(reader, limits)?;
    let mut output = Vec::new();
    decoder.read_to_end(&mut output)?;
    writer.write_all(&output)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    const PLAIN: &[u8] = include_bytes!("../../tests/fixtures/compress/plain.bin");
    #[test]
    fn external_fixed_dynamic_and_wrapped_vectors() {
        for bytes in [
            include_bytes!("../../tests/fixtures/compress/fixed.deflate").as_slice(),
            include_bytes!("../../tests/fixtures/compress/dynamic.deflate").as_slice(),
        ] {
            let mut out = Vec::new();
            decode_deflate(bytes, &mut out, Limits::default()).unwrap();
            assert_eq!(out, PLAIN);
        }
        let mut out = Vec::new();
        decode_zlib(
            include_bytes!("../../tests/fixtures/compress/python.zlib").as_slice(),
            &mut out,
            Limits::default(),
        )
        .unwrap();
        assert_eq!(out, PLAIN);
        out.clear();
        decode_gzip(
            include_bytes!("../../tests/fixtures/compress/python.gzip").as_slice(),
            &mut out,
            Limits::default(),
        )
        .unwrap();
        assert_eq!(out, PLAIN);
    }
    #[test]
    fn writer_streams_decode_through_the_bounded_decoders() {
        for n in [0, 1, 65535, 65536, 131070] {
            let plain = vec![42; n];
            for level in [0, -1] {
                let mut raw = flate::Writer::new(Vec::new(), level).unwrap();
                raw.write_all(&plain).unwrap();
                raw.close().unwrap();
                let mut out = Vec::new();
                decode_deflate(&raw.into_inner()[..], &mut out, Limits::default()).unwrap();
                assert_eq!(out, plain);
                let mut z = zlib::Writer::with_level(Vec::new(), level).unwrap();
                z.write_all(&plain).unwrap();
                z.close().unwrap();
                out.clear();
                decode_zlib(&z.into_inner()[..], &mut out, Limits::default()).unwrap();
                assert_eq!(out, plain);
                let mut g = gzip::Writer::with_level(Vec::new(), level).unwrap();
                g.write_all(&plain).unwrap();
                g.close().unwrap();
                out.clear();
                decode_gzip(&g.into_inner()[..], &mut out, Limits::default()).unwrap();
                assert_eq!(out, plain);
            }
        }
    }
    #[test]
    fn checksums_known_vectors() {
        assert_eq!(crc32(b"123456789"), 0xcbf43926);
        assert_eq!(adler32(b"Wikipedia"), 0x11e60398);
    }
    #[test]
    fn gzip_concatenation_and_limits() {
        let member = include_bytes!("../../tests/fixtures/compress/python.gzip");
        let mut both = member.to_vec();
        both.extend_from_slice(member);
        let mut out = Vec::new();
        decode_gzip(&both[..], &mut out, Limits::default()).unwrap();
        assert_eq!(out.len(), PLAIN.len() * 2);
        out.clear();
        assert!(decode_gzip(
            &both[..],
            &mut out,
            Limits {
                max_input: both.len(),
                max_output: PLAIN.len() * 2 - 1
            }
        )
        .is_err());
        assert!(out.is_empty());
    }
    #[test]
    fn corruption_truncation_and_budget_rejected_atomically() {
        let bytes = include_bytes!("../../tests/fixtures/compress/python.gzip");
        for n in 0..bytes.len() {
            let mut out = Vec::new();
            assert!(
                decode_gzip(&bytes[..n], &mut out, Limits::default()).is_err(),
                "prefix {n}"
            );
            assert!(out.is_empty());
        }
        let mut bad = bytes.to_vec();
        let n = bad.len();
        bad[n - 8] ^= 1;
        let mut out = Vec::new();
        assert!(decode_gzip(&bad[..], &mut out, Limits::default()).is_err());
        assert!(out.is_empty());
        assert!(decode_gzip(
            bytes.as_slice(),
            &mut out,
            Limits {
                max_input: bytes.len() - 1,
                max_output: usize::MAX
            }
        )
        .is_err());
        assert!(decode_deflate(&[7][..], &mut out, Limits::default()).is_err());
        assert!(decode_deflate(&[1, 1, 0, 255, 255, 0][..], &mut out, Limits::default()).is_err());
    }
    #[test]
    fn interrupted_reads_retry_and_partial_writes_work() {
        struct One(Vec<u8>);
        impl Write for One {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                let n = b.len().min(1);
                self.0.extend_from_slice(&b[..n]);
                Ok(n)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        struct InterruptedOnce<'a> {
            bytes: &'a [u8],
            first: bool,
        }
        impl Read for InterruptedOnce<'_> {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                if self.first {
                    self.first = false;
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                self.bytes.read(b)
            }
        }
        let mut retry = Vec::new();
        decode_deflate(
            InterruptedOnce {
                bytes: include_bytes!("../../tests/fixtures/compress/fixed.deflate"),
                first: true,
            },
            &mut retry,
            Limits::default(),
        )
        .unwrap();
        assert_eq!(retry, PLAIN);
        let mut writer = One(Vec::new());
        decode_zlib(
            include_bytes!("../../tests/fixtures/compress/python.zlib").as_slice(),
            &mut writer,
            Limits::default(),
        )
        .unwrap();
        assert_eq!(writer.0, PLAIN);
    }
    #[test]
    fn gzip_optional_fields_and_header_crc() {
        let mut stream = vec![31, 139, 8, 30, 0, 0, 0, 0, 0, 255];
        stream.extend_from_slice(&[3, 0, 1, 2, 3]);
        stream.extend_from_slice(b"name.bin\0comment\0");
        let crc = crc32(&stream) as u16;
        stream.extend_from_slice(&crc.to_le_bytes());
        let payload = b"optional header";
        let mut body = flate::Writer::new(Vec::new(), 6).unwrap();
        body.write_all(payload).unwrap();
        body.close().unwrap();
        stream.extend_from_slice(&body.into_inner());
        stream.extend_from_slice(&crc32(payload).to_le_bytes());
        stream.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        let mut out = Vec::new();
        decode_gzip(&stream[..], &mut out, Limits::default()).unwrap();
        assert_eq!(out, payload);
        stream[12] ^= 1;
        assert!(decode_gzip(&stream[..], &mut out, Limits::default()).is_err());
    }
    #[test]
    fn invalid_trees_and_reserved_flags() {
        assert!(Tree::new(&[1, 1, 1], false).is_err());
        assert!(Tree::new(&[2, 2], false).is_err());
        assert!(Tree::new(&[], true).is_err());
        let mut gzip = include_bytes!("../../tests/fixtures/compress/python.gzip").to_vec();
        gzip[3] |= 128;
        assert!(decode_gzip(&gzip[..], &mut Vec::new(), Limits::default()).is_err());
    }
    #[test]
    fn deterministic_bounded_mutation_campaign() {
        let mut seed = 1951u64;
        let original = include_bytes!("../../tests/fixtures/compress/dynamic.deflate");
        let limits = Limits {
            max_input: 1024,
            max_output: 4096,
        };
        for _ in 0..10000 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let mut bytes = original.to_vec();
            let at = seed as usize % bytes.len();
            bytes[at] ^= (seed >> 32) as u8;
            if seed & 7 == 0 {
                bytes.truncate(at);
            }
            let _ = decode_deflate(&bytes[..], &mut Vec::new(), limits);
        }
    }
}
