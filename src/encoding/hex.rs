//! Hexadecimal encoding and decoding: lowercase output, case-insensitive strict
//! input.
//!
//! ```
//! use rust_stdlib::encoding::hex;
//!
//! assert_eq!(hex::encode("hello"), "68656c6c6f");
//! assert_eq!(hex::decode("68656C6c6f")?, b"hello");
//! # Ok::<(), hex::Error>(())
//! ```
use std::{error, fmt};

/// The first byte of a pair that is not a hexadecimal digit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidByteError(pub u8);
impl fmt::Display for InvalidByteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Mirrors Go's %#U: the quoted character is shown only when Go's
        // IsPrint accepts it (ASCII space and printable Latin-1 except U+00AD).
        let printable = matches!(self.0, 0x20..=0x7e | 0xa1..=0xff) && self.0 != 0xad;
        if printable {
            write!(
                f,
                "encoding/hex: invalid byte: U+{:04X} '{}'",
                self.0,
                char::from(self.0)
            )
        } else {
            write!(f, "encoding/hex: invalid byte: U+{:04X}", self.0)
        }
    }
}
impl error::Error for InvalidByteError {}

fn invalid_byte(b: u8) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, InvalidByteError(b))
}

/// Decoding failure: a byte that is not a hexadecimal digit, or an odd number
/// of digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A byte that is not a hexadecimal digit.
    InvalidByte(InvalidByteError),
    /// An odd number of digits.
    Length,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidByte(e) => e.fmt(f),
            Error::Length => f.write_str("encoding/hex: odd length hex string"),
        }
    }
}
impl error::Error for Error {}

pub(crate) fn digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// The length of the encoding of `n` bytes.
pub fn encoded_len(n: usize) -> usize {
    n * 2
}

/// The number of bytes that `x` hexadecimal digits decode to.
pub fn decoded_len(x: usize) -> usize {
    x / 2
}

/// Encodes `input` as lowercase hexadecimal.
pub fn encode(input: impl AsRef<[u8]>) -> String {
    let input = input.as_ref();
    let mut out = Vec::with_capacity(encoded_len(input.len()));
    encode_into(input, &mut out);
    out.into_iter().map(char::from).collect()
}

/// Appends the encoding of `input` to `out`.
pub fn encode_into(input: impl AsRef<[u8]>, out: &mut Vec<u8>) {
    for &byte in input.as_ref() {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 15));
    }
}

fn hex_digit(nibble: u8) -> u8 {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    TABLE[usize::from(nibble)]
}

fn decode_pair(pair: &[u8]) -> Result<u8, Error> {
    let hi = digit(pair[0]).ok_or(Error::InvalidByte(InvalidByteError(pair[0])))?;
    let Some(&low) = pair.get(1) else {
        return Err(Error::Length);
    };
    let lo = digit(low).ok_or(Error::InvalidByte(InvalidByteError(low)))?;
    Ok((hi << 4) | lo)
}

/// Decodes `input`.
pub fn decode(input: impl AsRef<[u8]>) -> Result<Vec<u8>, Error> {
    let input = input.as_ref();
    let mut out = Vec::with_capacity(decoded_len(input.len()));
    decode_into(input, &mut out)?;
    Ok(out)
}

/// Appends the decoding of `input` to `out`. On malformed input the bytes
/// decoded before the error stay in `out`, as in Go.
pub fn decode_into(input: impl AsRef<[u8]>, out: &mut Vec<u8>) -> Result<(), Error> {
    for pair in input.as_ref().chunks(2) {
        out.push(decode_pair(pair)?);
    }
    Ok(())
}

/// A `hexdump -C` style listing, 16 bytes per line.
pub fn dump(data: impl AsRef<[u8]>) -> String {
    let data = data.as_ref();
    let mut out = String::new();
    for (index, line) in data.chunks(16).enumerate() {
        out.push_str(&dump_line((index * 16) as u32, line));
    }
    out
}

/// Formats one dump line; the offset wraps at 32 bits as in Go.
fn dump_line(offset: u32, bytes: &[u8]) -> String {
    let mut line = format!("{offset:08x}  ");
    for index in 0..16 {
        match bytes.get(index) {
            Some(byte) => line.push_str(&format!("{byte:02x} ")),
            None => line.push_str("   "),
        }
        if index == 7 {
            line.push(' ');
        }
    }
    line.push_str(" |");
    for &byte in bytes {
        line.push(if (0x20..0x7f).contains(&byte) {
            char::from(byte)
        } else {
            '.'
        });
    }
    line.push_str("|\n");
    line
}

/// Go's `Dumper`: writes a hex dump of everything written to it. Complete
/// 16-byte lines are emitted as they fill; [`Dumper::close`] emits the rest.
pub struct Dumper<W> {
    inner: W,
    pending: Vec<u8>,
    offset: u32,
}
impl<W: std::io::Write> Dumper<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            pending: Vec::with_capacity(16),
            offset: 0,
        }
    }
    /// Writes any partial final line, as Go's `Dumper.Close` does.
    pub fn close(mut self) -> std::io::Result<()> {
        if !self.pending.is_empty() {
            self.write_line()?;
        }
        Ok(())
    }
    fn write_line(&mut self) -> std::io::Result<()> {
        let line = dump_line(self.offset, &self.pending);
        self.inner.write_all(line.as_bytes())?;
        self.offset = self.offset.wrapping_add(self.pending.len() as u32);
        self.pending.clear();
        Ok(())
    }
}
impl<W: std::io::Write> std::io::Write for Dumper<W> {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        for &byte in input {
            self.pending.push(byte);
            if self.pending.len() == 16 {
                self.write_line()?;
            }
        }
        Ok(input.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Incremental hexadecimal writer; fixed-size buffers bound working memory.
/// After an I/O failure it becomes terminal because output may be partial.
pub struct Encoder<W> {
    inner: W,
    failed: bool,
}
/// Wraps `inner` so that bytes written are hex-encoded into it.
pub fn encoder<W: std::io::Write>(inner: W) -> Encoder<W> {
    Encoder {
        inner,
        failed: false,
    }
}

/// Wraps `inner` so that reading yields the decoding of its bytes.
pub fn decoder<R: std::io::Read>(inner: R) -> Decoder<R> {
    Decoder {
        inner,
        pending: None,
        terminal: false,
    }
}

impl<W: std::io::Write> Encoder<W> {
    /// Flushes and returns the inner writer.
    pub fn finish(mut self) -> std::io::Result<W> {
        if self.failed {
            return Err(std::io::Error::other("hex encoder failed"));
        }
        self.inner.flush()?;
        Ok(self.inner)
    }
}
impl<W: std::io::Write> std::io::Write for Encoder<W> {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        if self.failed {
            return Err(std::io::Error::other("hex encoder failed"));
        }
        for block in input.chunks(1024) {
            if let Err(e) = self.inner.write_all(encode(block).as_bytes()) {
                self.failed = true;
                return Err(e);
            }
        }
        Ok(input.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        if self.failed {
            return Err(std::io::Error::other("hex encoder failed"));
        }
        let result = self.inner.flush();
        if result.is_err() {
            self.failed = true
        }
        result
    }
}
/// Incremental strict decoder. Valid preceding bytes can be returned before a
/// later malformed pair; late errors cannot roll back a caller's output.
pub struct Decoder<R> {
    inner: R,
    pending: Option<std::io::Error>,
    terminal: bool,
}
impl<R: std::io::Read> Decoder<R> {
    /// The underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}
impl<R: std::io::Read> std::io::Read for Decoder<R> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if let Some(e) = self.pending.take() {
            return Err(e);
        }
        if self.terminal {
            return Ok(0);
        }
        let mut count = 0;
        while count < output.len() {
            let mut pair = [0u8; 2];
            let first = loop {
                match self.inner.read(&mut pair[..1]) {
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    other => break other,
                }
            };
            let result = match first {
                Ok(0) => {
                    self.terminal = true;
                    break;
                }
                Ok(_) => match self.inner.read_exact(&mut pair[1..]) {
                    // A lone trailing digit: Go reports it if it is invalid,
                    // and `io.ErrUnexpectedEOF` otherwise.
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        Err(match digit(pair[0]) {
                            None => invalid_byte(pair[0]),
                            Some(_) => crate::io::Error::UnexpectedEof.into(),
                        })
                    }
                    Err(e) => Err(e),
                    Ok(()) => digit(pair[0])
                        .ok_or_else(|| invalid_byte(pair[0]))
                        .and_then(|hi| {
                            let lo = digit(pair[1]).ok_or_else(|| invalid_byte(pair[1]))?;
                            Ok((hi << 4) | lo)
                        }),
                },
                Err(e) => Err(e),
            };
            match result {
                Ok(b) => {
                    output[count] = b;
                    count += 1
                }
                Err(e) => {
                    self.terminal = true;
                    if count == 0 {
                        return Err(e);
                    }
                    self.pending = Some(e);
                    break;
                }
            }
        }
        Ok(count)
    }
}
