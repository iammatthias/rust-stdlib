//! Incremental DEFLATE decoding and verified gzip/zlib framing.
use super::{invalid, trees, BitRead, Limits, Tree, DISTANCE, DISTANCE_BITS, LENGTH, LENGTH_BITS};
use std::io::{self, Read};
struct Input<R> {
    reader: R,
    total: usize,
    limit: usize,
    byte: u8,
    remaining: u8,
    buffer: Vec<u8>,
    cursor: usize,
    end: usize,
}
impl<R: Read> Input<R> {
    fn byte(&mut self) -> io::Result<Option<u8>> {
        if self.cursor < self.end {
            let byte = self.buffer[self.cursor];
            self.cursor += 1;
            return Ok(Some(byte));
        }
        let allowed = self
            .limit
            .saturating_sub(self.total)
            .saturating_add(1)
            .min(self.buffer.len());
        loop {
            match self.reader.read(&mut self.buffer[..allowed]) {
                Ok(0) => return Ok(None),
                Ok(n) => {
                    if n > self.limit.saturating_sub(self.total) {
                        return Err(invalid("compressed input limit exceeded"));
                    }
                    self.total += n;
                    self.cursor = 1;
                    self.end = n;
                    return Ok(Some(self.buffer[0]));
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }
    fn required(&mut self) -> io::Result<u8> {
        self.byte()?
            .ok_or_else(|| invalid("truncated compressed stream"))
    }
    fn le32(&mut self) -> io::Result<u32> {
        let mut bytes = [0; 4];
        for b in &mut bytes {
            *b = self.required()?;
        }
        Ok(u32::from_le_bytes(bytes))
    }
    fn header_byte(&mut self, crc: &mut u32) -> io::Result<u8> {
        let byte = self.required()?;
        update_crc(crc, byte);
        Ok(byte)
    }
    fn gzip_header(&mut self, first: u8) -> io::Result<()> {
        let mut crc = !0;
        update_crc(&mut crc, first);
        if first != 31 || self.header_byte(&mut crc)? != 139 || self.header_byte(&mut crc)? != 8 {
            return Err(invalid("invalid gzip header"));
        }
        let flags = self.header_byte(&mut crc)?;
        if flags & 224 != 0 {
            return Err(invalid("invalid gzip flags"));
        }
        for _ in 0..6 {
            self.header_byte(&mut crc)?;
        }
        if flags & 4 != 0 {
            let a = self.header_byte(&mut crc)?;
            let b = self.header_byte(&mut crc)?;
            let length = u16::from_le_bytes([a, b]);
            for _ in 0..length {
                self.header_byte(&mut crc)?;
            }
        }
        for flag in [8, 16] {
            if flags & flag != 0 {
                while self.header_byte(&mut crc)? != 0 {}
            }
        }
        if flags & 2 != 0 {
            let expected = u16::from_le_bytes([self.required()?, self.required()?]);
            if (!crc as u16) != expected {
                return Err(invalid("gzip header checksum mismatch"));
            }
        }
        Ok(())
    }
    fn zlib_header(&mut self) -> io::Result<usize> {
        let cmf = self.required()?;
        let flg = self.required()?;
        if cmf & 15 != 8 || cmf >> 4 > 7 || (u16::from(cmf) * 256 + u16::from(flg)) % 31 != 0 {
            return Err(invalid("invalid zlib header"));
        }
        if flg & 32 != 0 {
            return Err(invalid("zlib preset dictionaries unsupported"));
        }
        Ok(1 << (usize::from(cmf >> 4) + 8))
    }
}
impl<R: Read> BitRead for Input<R> {
    fn get(&mut self, n: u8) -> io::Result<usize> {
        let mut result = 0;
        for shift in 0..n {
            if self.remaining == 0 {
                self.byte = self.required()?;
                self.remaining = 8;
            }
            result |= usize::from(self.byte & 1) << shift;
            self.byte >>= 1;
            self.remaining -= 1;
        }
        Ok(result)
    }
    fn align(&mut self) {
        self.remaining = 0;
    }
}
fn update_crc(crc: &mut u32, byte: u8) {
    *crc ^= u32::from(byte);
    for _ in 0..8 {
        *crc = (*crc >> 1) ^ (0xedb88320u32 & 0u32.wrapping_sub(*crc & 1));
    }
}
enum Block {
    Header,
    Stored(usize),
    Codes(Box<(Tree, Tree)>),
    End,
}
#[derive(Clone, Copy)]
enum Format {
    Deflate,
    /// Raw DEFLATE that ignores bytes after the final block (ZIP members).
    DeflatePrefix,
    Zlib,
    Gzip,
}
/// A bounded incremental compressed-stream reader with a 32 KiB history.
///
/// `Read` returns provisional decoded bytes before the final checksum is known.
/// Call `finish` or read through a successful EOF before accepting those bytes
/// as verified. `is_verified` reports successful framing/checksum completion.
/// Dropping a reader early leaves the stream unverified. Every failure latches;
/// subsequent reads return the same error. No filesystem extraction occurs.
pub struct Decoder<R: Read> {
    input: Input<R>,
    format: Format,
    block: Block,
    last: bool,
    copy: Option<(usize, usize)>,
    history: Vec<u8>,
    position: usize,
    available: usize,
    window: usize,
    output: usize,
    limit: usize,
    crc: u32,
    member_size: u32,
    adler_a: u32,
    adler_b: u32,
    verified: bool,
    failed: Option<(io::ErrorKind, String)>,
}
impl<R: Read> Decoder<R> {
    fn new(reader: R, limits: Limits, format: Format) -> io::Result<Self> {
        let mut input = Input {
            reader,
            total: 0,
            limit: limits.max_input,
            byte: 0,
            remaining: 0,
            buffer: vec![0; 8192],
            cursor: 0,
            end: 0,
        };
        let window = match format {
            Format::Deflate | Format::DeflatePrefix => 32768,
            Format::Zlib => input.zlib_header()?,
            Format::Gzip => {
                let first = input.required()?;
                input.gzip_header(first)?;
                32768
            }
        };
        Ok(Self {
            input,
            format,
            block: Block::Header,
            last: false,
            copy: None,
            history: vec![0; 32768],
            position: 0,
            available: 0,
            window,
            output: 0,
            limit: limits.max_output,
            crc: !0,
            member_size: 0,
            adler_a: 1,
            adler_b: 0,
            verified: false,
            failed: None,
        })
    }
    /// Decode an RFC1951 stream, rejecting trailing bytes after the final block.
    pub fn deflate(reader: R, limits: Limits) -> io::Result<Self> {
        Self::new(reader, limits, Format::Deflate)
    }
    /// Decode an RFC1951 stream and stop after the final block, ignoring any
    /// bytes that follow it (as ZIP members and Go's flate reader do).
    pub fn deflate_prefix(reader: R, limits: Limits) -> io::Result<Self> {
        Self::new(reader, limits, Format::DeflatePrefix)
    }
    /// Decode RFC1950, verifying the advertised window and Adler-32 checksum.
    pub fn zlib(reader: R, limits: Limits) -> io::Result<Self> {
        Self::new(reader, limits, Format::Zlib)
    }
    /// Decode RFC1952 including all concatenated members and optional headers.
    pub fn gzip(reader: R, limits: Limits) -> io::Result<Self> {
        Self::new(reader, limits, Format::Gzip)
    }
    /// Whether the entire source reached a successful verified EOF.
    pub fn is_verified(&self) -> bool {
        self.verified
    }
    /// Drain remaining decoded bytes and verify the entire stream. Output
    /// discarded here still counts against the cumulative decoded-byte limit.
    pub fn finish(&mut self) -> io::Result<()> {
        let mut bytes = [0; 8192];
        while self.read(&mut bytes)? != 0 {}
        Ok(())
    }
    /// Recover the source. Calling this before verified EOF skips validation
    /// and discards up to 8 KiB of read-ahead bytes.
    pub fn into_inner(self) -> R {
        self.input.reader
    }
    fn emit(&mut self, byte: u8) -> io::Result<Option<u8>> {
        if self.output == self.limit {
            return Err(invalid("decoded output limit exceeded"));
        }
        self.output += 1;
        self.history[self.position] = byte;
        self.position = (self.position + 1) % 32768;
        self.available = (self.available + 1).min(32768);
        match self.format {
            Format::Gzip => {
                update_crc(&mut self.crc, byte);
                self.member_size = self.member_size.wrapping_add(1);
            }
            Format::Zlib => {
                self.adler_a = (self.adler_a + u32::from(byte)) % 65521;
                self.adler_b = (self.adler_b + self.adler_a) % 65521;
            }
            Format::Deflate | Format::DeflatePrefix => {}
        }
        Ok(Some(byte))
    }
    fn complete_member(&mut self) -> io::Result<()> {
        self.input.align();
        match self.format {
            Format::DeflatePrefix => {}
            Format::Deflate => {
                if self.input.byte()?.is_some() {
                    return Err(invalid("trailing DEFLATE data"));
                }
            }
            Format::Zlib => {
                let mut bytes = [0; 4];
                for byte in &mut bytes {
                    *byte = self.input.required()?;
                }
                if u32::from_be_bytes(bytes) != (self.adler_b << 16) | self.adler_a {
                    return Err(invalid("zlib checksum mismatch"));
                }
                if self.input.byte()?.is_some() {
                    return Err(invalid("trailing zlib data"));
                }
            }
            Format::Gzip => {
                let expected_crc = self.input.le32()?;
                let expected_size = self.input.le32()?;
                if expected_crc != !self.crc || expected_size != self.member_size {
                    return Err(invalid("gzip checksum or size mismatch"));
                }
                if let Some(first) = self.input.byte()? {
                    self.input.gzip_header(first)?;
                    self.block = Block::Header;
                    self.last = false;
                    self.copy = None;
                    self.position = 0;
                    self.available = 0;
                    self.crc = !0;
                    self.member_size = 0;
                    return Ok(());
                }
            }
        }
        self.verified = true;
        Ok(())
    }
    fn next(&mut self) -> io::Result<Option<u8>> {
        loop {
            if self.verified {
                return Ok(None);
            }
            if let Some((distance, remaining)) = self.copy {
                let byte = self.history[(self.position + 32768 - distance) % 32768];
                self.copy = if remaining == 1 {
                    None
                } else {
                    Some((distance, remaining - 1))
                };
                return self.emit(byte);
            }
            match &mut self.block {
                Block::Header => {
                    self.last = self.input.get(1)? != 0;
                    let kind = self.input.get(2)?;
                    self.block = match kind {
                        0 => {
                            self.input.align();
                            let size = self.input.get(16)?;
                            let inverse = self.input.get(16)?;
                            if size ^ inverse != 65535 {
                                return Err(invalid("stored block length mismatch"));
                            }
                            if size > self.limit.saturating_sub(self.output) {
                                return Err(invalid("decoded output limit exceeded"));
                            }
                            Block::Stored(size)
                        }
                        1 | 2 => {
                            let (lit, dist) = trees(&mut self.input, kind)?;
                            Block::Codes(Box::new((lit, dist)))
                        }
                        _ => return Err(invalid("reserved block type")),
                    };
                }
                Block::Stored(remaining) => {
                    if *remaining == 0 {
                        self.block = if self.last { Block::End } else { Block::Header };
                        continue;
                    }
                    *remaining -= 1;
                    let byte = self.input.get(8)? as u8;
                    return self.emit(byte);
                }
                Block::Codes(pair) => {
                    let (lit, dist) = pair.as_ref();
                    match lit.symbol(&mut self.input)? {
                        v @ 0..=255 => return self.emit(v as u8),
                        256 => self.block = if self.last { Block::End } else { Block::Header },
                        v @ 257..=285 => {
                            let i = v - 257;
                            let length = LENGTH[i] + self.input.get(LENGTH_BITS[i])?;
                            let d = dist.symbol(&mut self.input)?;
                            if d >= 30 {
                                return Err(invalid("reserved distance symbol"));
                            }
                            let distance = DISTANCE[d] + self.input.get(DISTANCE_BITS[d])?;
                            if distance > self.available || distance > self.window {
                                return Err(invalid("invalid back-reference distance"));
                            }
                            if length > self.limit.saturating_sub(self.output) {
                                return Err(invalid("decoded output limit exceeded"));
                            }
                            self.copy = Some((distance, length));
                        }
                        _ => return Err(invalid("reserved literal symbol")),
                    }
                }
                Block::End => self.complete_member()?,
            }
        }
    }
}
impl<R: Read> Read for Decoder<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if let Some((kind, message)) = &self.failed {
            return Err(io::Error::new(*kind, message.clone()));
        }
        let mut count = 0;
        while count < bytes.len() {
            match self.next() {
                Ok(Some(byte)) => {
                    bytes[count] = byte;
                    count += 1;
                }
                Ok(None) => break,
                Err(error) => {
                    self.failed = Some((error.kind(), error.to_string()));
                    if count == 0 {
                        return Err(error);
                    }
                    break;
                }
            }
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PLAIN: &[u8] = include_bytes!("../../tests/fixtures/compress/plain.bin");
    #[test]
    fn small_reads_cross_window_and_verify_all_formats() {
        for size in [1, 7, 8192, 100000] {
            for (mut decoder, expected) in [
                (
                    Decoder::deflate(
                        include_bytes!("../../tests/fixtures/compress/dynamic.deflate").as_slice(),
                        Limits::default(),
                    )
                    .unwrap(),
                    PLAIN,
                ),
                (
                    Decoder::zlib(
                        include_bytes!("../../tests/fixtures/compress/python.zlib").as_slice(),
                        Limits::default(),
                    )
                    .unwrap(),
                    PLAIN,
                ),
                (
                    Decoder::gzip(
                        include_bytes!("../../tests/fixtures/compress/python.gzip").as_slice(),
                        Limits::default(),
                    )
                    .unwrap(),
                    PLAIN,
                ),
            ] {
                assert!(!decoder.is_verified());
                let mut bytes = vec![0; size];
                let mut out = Vec::new();
                loop {
                    let n = decoder.read(&mut bytes).unwrap();
                    if n == 0 {
                        break;
                    }
                    out.extend_from_slice(&bytes[..n]);
                }
                assert_eq!(out, expected);
                assert!(decoder.is_verified());
                assert_eq!(decoder.read(&mut bytes).unwrap(), 0);
            }
        }
    }
    #[test]
    fn provisional_output_requires_finish_and_failure_latches() {
        let mut gzip = include_bytes!("../../tests/fixtures/compress/python.gzip").to_vec();
        let n = gzip.len();
        gzip[n - 8] ^= 1;
        let mut reader = Decoder::gzip(&gzip[..], Limits::default()).unwrap();
        let mut prefix = [0; 16];
        reader.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, &PLAIN[..16]);
        assert!(!reader.is_verified());
        let error = reader.finish().unwrap_err();
        assert!(!reader.is_verified());
        let repeated = reader.read(&mut prefix).unwrap_err();
        assert_eq!(error.kind(), repeated.kind());
        assert_eq!(error.to_string(), repeated.to_string());
        let mut reader = Decoder::gzip(
            include_bytes!("../../tests/fixtures/compress/python.gzip").as_slice(),
            Limits::default(),
        )
        .unwrap();
        reader.read_exact(&mut prefix).unwrap();
        assert!(!reader.is_verified());
        reader.finish().unwrap();
        assert!(reader.is_verified());
    }
    #[test]
    fn cumulative_concatenation_limit_and_history_reset() {
        let member = include_bytes!("../../tests/fixtures/compress/python.gzip");
        let mut joined = member.to_vec();
        joined.extend_from_slice(member);
        let mut reader = Decoder::gzip(
            &joined[..],
            Limits {
                max_input: joined.len(),
                max_output: PLAIN.len() * 2,
            },
        )
        .unwrap();
        reader.finish().unwrap();
        assert!(reader.is_verified());
        let mut reader = Decoder::gzip(
            &joined[..],
            Limits {
                max_input: joined.len(),
                max_output: PLAIN.len() * 2 - 1,
            },
        )
        .unwrap();
        assert!(reader.finish().is_err());
        assert!(!reader.is_verified());
    }
    #[test]
    fn compressed_read_budget_includes_only_one_over_limit_probe() {
        struct Counted<'a> {
            bytes: &'a [u8],
            count: usize,
        }
        impl Read for Counted<'_> {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                let n = self.bytes.read(b)?;
                self.count += n;
                Ok(n)
            }
        }
        let bytes = include_bytes!("../../tests/fixtures/compress/dynamic.deflate");
        let budget = 10;
        let mut reader = Decoder::deflate(
            Counted { bytes, count: 0 },
            Limits {
                max_input: budget,
                ..Limits::default()
            },
        )
        .unwrap();
        assert!(reader.finish().is_err());
        assert_eq!(reader.into_inner().count, budget + 1);
        let mut reader = Decoder::deflate(
            Counted { bytes, count: 0 },
            Limits {
                max_input: bytes.len(),
                ..Limits::default()
            },
        )
        .unwrap();
        reader.finish().unwrap();
        assert_eq!(reader.into_inner().count, bytes.len());
    }
    #[test]
    fn trailing_data_and_early_source_errors_latch() {
        let mut bytes = include_bytes!("../../tests/fixtures/compress/python.zlib").to_vec();
        bytes.push(0);
        let mut reader = Decoder::zlib(&bytes[..], Limits::default()).unwrap();
        assert!(reader.finish().is_err());
        assert!(!reader.is_verified());
        struct Fault;
        impl Read for Fault {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::PermissionDenied, "fault"))
            }
        }
        let mut reader = Decoder::deflate(Fault, Limits::default()).unwrap();
        let mut bytes = [0; 1];
        assert_eq!(
            reader.read(&mut bytes).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            reader.read(&mut bytes).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
