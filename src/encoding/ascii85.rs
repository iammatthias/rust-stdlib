//! Adobe/btoa-style Ascii85 encoding. The raw functions do not add `<~` or
//! `~>` delimiters. Decoding ignores ASCII control and space bytes, as Go's
//! `encoding/ascii85` does.
use std::{error, fmt, io};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CorruptInputError(pub usize);

impl fmt::Display for CorruptInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "illegal ascii85 data at input byte {}", self.0)
    }
}
impl error::Error for CorruptInputError {}

/// Maximum encoded length for `n` bytes (including a possibly shortened tail).
pub fn max_encoded_len(n: usize) -> usize {
    n.saturating_add(3)
        .checked_div(4)
        .unwrap_or(0)
        .saturating_mul(5)
}

/// Encode source bytes into `dst`, returning bytes written. `dst` must have at
/// least [`max_encoded_len`] bytes.
pub fn encode(dst: &mut [u8], src: &[u8]) -> usize {
    let mut written = 0;
    for block in src.chunks(4) {
        let mut value = 0u32;
        for &byte in block {
            value = (value << 8) | u32::from(byte);
        }
        value <<= (4 - block.len()) * 8;
        if block.len() == 4 && value == 0 {
            dst[written] = b'z';
            written += 1;
            continue;
        }
        let start = written;
        for i in (0..5).rev() {
            dst[start + i] = b'!' + (value % 85) as u8;
            value /= 85;
        }
        let count = if block.len() == 4 { 5 } else { block.len() + 1 };
        written += count;
    }
    written
}

pub fn encode_to_vec(src: &[u8]) -> Vec<u8> {
    let mut result = vec![0; max_encoded_len(src.len())];
    let n = encode(&mut result, src);
    result.truncate(n);
    result
}

/// Decode as much input as fits in `dst`. Returns decoded bytes, consumed
/// source bytes, and an optional corrupt-input error. `flush` marks end of
/// input and permits a final 2–4 digit fragment.
pub fn decode(
    dst: &mut [u8],
    src: &[u8],
    flush: bool,
) -> (usize, usize, Result<(), CorruptInputError>) {
    let (mut out, mut consumed, mut value, mut digits) = (0usize, 0usize, 0u32, 0usize);
    for (i, &byte) in src.iter().enumerate() {
        if dst.len() - out < 4 {
            return (out, consumed, Ok(()));
        }
        if byte <= b' ' {
            continue;
        }
        match byte {
            b'z' if digits == 0 => {
                value = 0;
                digits = 5;
            }
            b'!'..=b'u' => {
                value = value.wrapping_mul(85).wrapping_add(u32::from(byte - b'!'));
                digits += 1;
            }
            _ => return (0, 0, Err(CorruptInputError(i))),
        }
        if digits == 5 {
            dst[out..out + 4].copy_from_slice(&value.to_be_bytes());
            out += 4;
            consumed = i + 1;
            value = 0;
            digits = 0;
        }
    }
    if flush {
        consumed = src.len();
        if digits == 1 {
            return (0, 0, Err(CorruptInputError(src.len())));
        }
        if digits > 1 {
            for _ in digits..5 {
                value = value.wrapping_mul(85).wrapping_add(84);
            }
            for _ in 0..digits - 1 {
                dst[out] = (value >> 24) as u8;
                out += 1;
                value <<= 8;
            }
        }
    }
    (out, consumed, Ok(()))
}

/// Incremental writer. A final partial block is emitted by [`Encoder::finish`].
pub struct Encoder<W> {
    inner: W,
    tail: [u8; 4],
    length: usize,
    failed: bool,
}
impl<W: io::Write> Encoder<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            tail: [0; 4],
            length: 0,
            failed: false,
        }
    }
    pub fn finish(mut self) -> io::Result<W> {
        if self.failed {
            return Err(io::Error::other("ascii85 encoder failed"));
        }
        if self.length > 0 {
            let bytes = encode_to_vec(&self.tail[..self.length]);
            self.inner.write_all(&bytes)?;
        }
        self.inner.flush()?;
        Ok(self.inner)
    }
    fn emit(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.inner.write_all(&encode_to_vec(bytes))
    }
}
impl<W: io::Write> io::Write for Encoder<W> {
    fn write(&mut self, mut input: &[u8]) -> io::Result<usize> {
        if self.failed {
            return Err(io::Error::other("ascii85 encoder failed"));
        }
        if input.is_empty() {
            return Ok(0);
        }
        let total = input.len();
        let result = (|| {
            if self.length != 0 {
                let n = (4 - self.length).min(input.len());
                self.tail[self.length..self.length + n].copy_from_slice(&input[..n]);
                self.length += n;
                input = &input[n..];
                if self.length == 4 {
                    let block = self.tail;
                    self.emit(&block)?;
                    self.length = 0;
                }
            }
            while input.len() >= 4 {
                let n = (input.len().min(3072)) / 4 * 4;
                self.emit(&input[..n])?;
                input = &input[n..];
            }
            self.tail[..input.len()].copy_from_slice(input);
            self.length = input.len();
            Ok(total)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other("ascii85 encoder failed"));
        }
        let result = self.inner.flush();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

/// Size of the input and output buffers. Matches Go's streaming decoder so
/// that a corrupt chunk drops the same output and reports the same offset.
const CHUNK: usize = 1024;

/// Incremental decoder that mirrors Go's streaming reader. Input is buffered in
/// 1024-byte chunks and each chunk is decoded as a unit, so a corrupt byte
/// discards the output of its chunk and the error is sticky. Whitespace and
/// control bytes (0x00–0x20) are ignored; an incomplete final block is decoded
/// at EOF.
pub struct Decoder<R> {
    inner: R,
    input: [u8; CHUNK],
    input_len: usize,
    output: [u8; CHUNK],
    output_start: usize,
    output_end: usize,
    eof: bool,
    read_error: Option<io::Error>,
    error: Option<io::Error>,
}

impl<R: io::Read> Decoder<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            input: [0; CHUNK],
            input_len: 0,
            output: [0; CHUNK],
            output_start: 0,
            output_end: 0,
            eof: false,
            read_error: None,
            error: None,
        }
    }

    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Appends one read from the inner reader. A read error is kept until the
    /// buffered input has been decoded, as in Go.
    fn fill(&mut self) {
        let result = loop {
            match self.inner.read(&mut self.input[self.input_len..]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                other => break other,
            }
        };
        match result {
            Err(error) => self.read_error = Some(error),
            Ok(0) => self.eof = true,
            Ok(n) => self.input_len += n,
        }
    }

    fn fail(&mut self, error: io::Error) -> io::Error {
        let reported = replay(&error);
        self.error = Some(error);
        reported
    }
}

/// Recreates a sticky error so that every later read reports the same failure.
fn replay(error: &io::Error) -> io::Error {
    match error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<CorruptInputError>())
    {
        Some(corrupt) => io::Error::new(io::ErrorKind::InvalidData, *corrupt),
        None => io::Error::new(error.kind(), error.to_string()),
    }
}

impl<R: io::Read> io::Read for Decoder<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if let Some(error) = &self.error {
            return Err(replay(error));
        }
        loop {
            if self.output_start < self.output_end {
                let n = out.len().min(self.output_end - self.output_start);
                out[..n].copy_from_slice(&self.output[self.output_start..self.output_start + n]);
                self.output_start += n;
                return Ok(n);
            }
            if self.input_len > 0 {
                let flush = self.eof || self.read_error.is_some();
                let (written, consumed, result) =
                    decode(&mut self.output, &self.input[..self.input_len], flush);
                if written > 0 {
                    self.output_start = 0;
                    self.output_end = written;
                    self.input.copy_within(consumed..self.input_len, 0);
                    self.input_len -= consumed;
                    continue;
                }
                if let Err(error) = result {
                    return Err(self.fail(io::Error::new(io::ErrorKind::InvalidData, error)));
                }
                // Drop whitespace and control bytes to make room for more input.
                let mut kept = 0;
                for index in 0..self.input_len {
                    if self.input[index] > b' ' {
                        self.input[kept] = self.input[index];
                        kept += 1;
                    }
                }
                self.input_len = kept;
            }
            if let Some(error) = self.read_error.take() {
                return Err(self.fail(error));
            }
            if self.eof {
                return Ok(0);
            }
            self.fill();
        }
    }
}
