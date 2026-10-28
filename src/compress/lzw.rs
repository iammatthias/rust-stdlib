//! GIF/PDF style LZW with variable-width codes up to 12 bits.
//!
//! The payload is an LZW byte stream only; container metadata and TIFF's
//! incompatible LZW variant are outside this module.
use std::collections::HashMap;
use std::io::{self, Read, Write};

const MAX_WIDTH: u8 = 12;
const MAX_CODES: usize = 1 << MAX_WIDTH;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    Lsb,
    Msb,
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
/// Go's check in `init`: a bad litWidth does not fail the constructor; it is
/// latched and reported by the first `Read`, `Write` or `Close`. Returns the
/// width to build the state with (a valid one) and that latched error.
fn check_lit_width(lit_width: u8) -> (u8, Option<io::Error>) {
    if (2..=8).contains(&lit_width) {
        (lit_width, None)
    } else {
        (
            8,
            Some(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("lzw: litWidth {lit_width} out of range"),
            )),
        )
    }
}

/// Streaming LZW encoder, Go's `Writer`. Call [`Writer::close`] (or
/// [`Writer::finish`]) to emit the final code and flush the underlying writer.
pub struct Writer<W: Write> {
    inner: W,
    order: Order,
    lit_width: u8,
    width: u8,
    hi: u16,
    overflow: u16,
    bits: u32,
    n_bits: u8,
    saved_code: Option<u16>,
    table: HashMap<u32, u16>,
    error: Option<io::Error>,
    closed: bool,
}

impl<W: Write> Writer<W> {
    /// Go's `NewWriter`. A `lit_width` outside 2..=8 is reported by `write`
    /// and `close`, not here.
    pub fn new(inner: W, order: Order, lit_width: u8) -> Self {
        let (lit_width, error) = check_lit_width(lit_width);
        let clear = 1u16 << lit_width;
        Self {
            inner,
            order,
            lit_width,
            width: lit_width + 1,
            hi: clear + 1,
            overflow: 1 << (lit_width + 1),
            bits: 0,
            n_bits: 0,
            saved_code: None,
            table: HashMap::with_capacity(MAX_CODES),
            error,
            closed: false,
        }
    }

    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    fn write_code(&mut self, code: u16) -> io::Result<()> {
        let result = self.write_code_inner(code);
        if let Err(error) = &result {
            self.error = Some(io::Error::new(error.kind(), error.to_string()));
        }
        result
    }

    fn write_code_inner(&mut self, code: u16) -> io::Result<()> {
        match self.order {
            Order::Lsb => {
                self.bits |= u32::from(code) << self.n_bits;
                self.n_bits += self.width;
                while self.n_bits >= 8 {
                    self.inner.write_all(&[(self.bits & 0xff) as u8])?;
                    self.bits >>= 8;
                    self.n_bits -= 8;
                }
            }
            Order::Msb => {
                self.bits |= u32::from(code) << (32 - self.width - self.n_bits);
                self.n_bits += self.width;
                while self.n_bits >= 8 {
                    self.inner.write_all(&[(self.bits >> 24) as u8])?;
                    self.bits <<= 8;
                    self.n_bits -= 8;
                }
            }
        }
        Ok(())
    }

    fn increment_hi(&mut self) -> io::Result<bool> {
        self.hi += 1;
        if self.hi == self.overflow {
            self.width += 1;
            self.overflow <<= 1;
        }
        if self.hi == (MAX_CODES - 1) as u16 {
            let clear = 1u16 << self.lit_width;
            self.write_code(clear)?;
            self.width = self.lit_width + 1;
            self.hi = clear + 1;
            self.overflow = clear << 1;
            self.table.clear();
            return Ok(false);
        }
        Ok(true)
    }

    fn write_input(&mut self, input: &[u8]) -> io::Result<usize> {
        if self.closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "lzw: writer is closed",
            ));
        }
        if let Some(error) = &self.error {
            return Err(io::Error::new(error.kind(), error.to_string()));
        }
        if input.is_empty() {
            return Ok(0);
        }
        let max_literal = (1u16 << self.lit_width) - 1;
        if input.iter().any(|&byte| u16::from(byte) > max_literal) {
            let error = invalid_input("lzw: input byte too large for the litWidth");
            self.error = Some(io::Error::new(error.kind(), error.to_string()));
            return Err(error);
        }

        let mut rest = input;
        let mut code = match self.saved_code {
            Some(code) => code,
            None => {
                self.write_code(1u16 << self.lit_width)?;
                let first = u16::from(rest[0]);
                rest = &rest[1..];
                first
            }
        };
        for &byte in rest {
            let literal = u16::from(byte);
            let key = (u32::from(code) << 8) | u32::from(byte);
            if let Some(&next_code) = self.table.get(&key) {
                code = next_code;
                continue;
            }
            if let Err(error) = self.write_code(code) {
                self.error = Some(io::Error::new(error.kind(), error.to_string()));
                return Err(error);
            }
            code = literal;
            let has_space = match self.increment_hi() {
                Ok(value) => value,
                Err(error) => {
                    self.error = Some(io::Error::new(error.kind(), error.to_string()));
                    return Err(error);
                }
            };
            if has_space {
                self.table.insert(key, self.hi);
            }
        }
        self.saved_code = Some(code);
        Ok(input.len())
    }

    /// Starts a new stream on `inner`, discarding all pending state and any
    /// unwritten bits of the previous stream (Go's `Writer.Reset`).
    pub fn reset(&mut self, inner: W, order: Order, lit_width: u8) {
        *self = Self::new(inner, order, lit_width);
    }

    /// Writes the final code and flushes the underlying writer, like Go's
    /// `Writer.Close`. The underlying writer stays open, and closing again is a
    /// no-op.
    pub fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        if let Some(error) = &self.error {
            return Err(io::Error::new(error.kind(), error.to_string()));
        }
        self.closed = true;
        let clear = 1u16 << self.lit_width;
        if let Some(code) = self.saved_code {
            self.write_code(code)?;
            self.increment_hi()?;
        } else {
            self.write_code(clear)?;
        }
        self.write_code(clear + 1)?;
        if self.n_bits > 0 {
            let byte = match self.order {
                Order::Lsb => self.bits as u8,
                Order::Msb => (self.bits >> 24) as u8,
            };
            self.inner.write_all(&[byte])?;
        }
        self.inner.flush()
    }

    /// Closes the stream and returns the underlying writer.
    pub fn finish(mut self) -> io::Result<W> {
        self.close()?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for Writer<W> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.write_input(input)
    }
    fn flush(&mut self) -> io::Result<()> {
        if let Some(error) = &self.error {
            return Err(io::Error::new(error.kind(), error.to_string()));
        }
        if let Err(error) = self.inner.flush() {
            self.error = Some(io::Error::new(error.kind(), error.to_string()));
            return Err(error);
        }
        Ok(())
    }
}

/// Encodes all input bytes and returns the compressed stream.
pub fn encode(input: &[u8], order: Order, lit_width: u8) -> io::Result<Vec<u8>> {
    let mut encoder = Writer::new(Vec::new(), order, lit_width);
    encoder.write_all(input)?;
    encoder.finish()
}

/// Streaming LZW decoder (Go's `Reader`). The decompressed output is unbounded,
/// as in Go, unless [`Reader::with_max_output`] sets a bound.
pub struct Reader<R: Read> {
    inner: R,
    order: Order,
    lit_width: u8,
    width: u8,
    clear: u16,
    eof: u16,
    hi: u16,
    overflow: u16,
    last: Option<u16>,
    prefix: [u16; MAX_CODES],
    suffix: [u8; MAX_CODES],
    bits: u32,
    n_bits: u8,
    pending: [u8; MAX_CODES],
    pending_len: usize,
    pending_pos: usize,
    produced: usize,
    max_output: usize,
    ended: bool,
    error: Option<io::Error>,
}

impl<R: Read> Reader<R> {
    /// Reader of the LZW stream in `inner`. A `lit_width` outside 2..=8 is
    /// reported by the first `read`, not here.
    pub fn new(inner: R, order: Order, lit_width: u8) -> Self {
        let (lit_width, error) = check_lit_width(lit_width);
        let clear = 1u16 << lit_width;
        let eof = clear + 1;
        Self {
            inner,
            order,
            lit_width,
            width: lit_width + 1,
            clear,
            eof,
            hi: eof,
            overflow: 1 << (lit_width + 1),
            last: None,
            prefix: [0; MAX_CODES],
            suffix: [0; MAX_CODES],
            bits: 0,
            n_bits: 0,
            pending: [0; MAX_CODES],
            pending_len: 0,
            pending_pos: 0,
            produced: 0,
            max_output: usize::MAX,
            ended: false,
            error,
        }
    }

    /// Bounds the total decompressed output; reading past it is an error.
    #[must_use]
    pub fn with_max_output(mut self, max_output: usize) -> Self {
        self.max_output = max_output;
        self
    }

    fn read_code(&mut self) -> io::Result<u16> {
        match self.order {
            Order::Lsb => {
                while self.n_bits < self.width {
                    let mut byte = [0u8; 1];
                    match self.inner.read(&mut byte) {
                        Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                        Ok(_) => {
                            self.bits |= u32::from(byte[0]) << self.n_bits;
                            self.n_bits += 8;
                        }
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) => return Err(error),
                    }
                }
                let code = (self.bits & ((1 << self.width) - 1)) as u16;
                self.bits >>= self.width;
                self.n_bits -= self.width;
                Ok(code)
            }
            Order::Msb => {
                while self.n_bits < self.width {
                    let mut byte = [0u8; 1];
                    match self.inner.read(&mut byte) {
                        Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                        Ok(_) => {
                            self.bits = (self.bits << 8) | u32::from(byte[0]);
                            self.n_bits += 8;
                        }
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) => return Err(error),
                    }
                }
                let shift = self.n_bits - self.width;
                let code = ((self.bits >> shift) & ((1 << self.width) - 1)) as u16;
                self.n_bits -= self.width;
                self.bits &= (1u32 << self.n_bits).wrapping_sub(1);
                Ok(code)
            }
        }
    }

    fn next_phrase(&mut self) -> io::Result<bool> {
        loop {
            let code = match self.read_code() {
                Ok(code) => code,
                Err(error) => {
                    self.error = Some(error);
                    return Err(io::Error::new(
                        self.error.as_ref().unwrap().kind(),
                        self.error.as_ref().unwrap().to_string(),
                    ));
                }
            };
            if code == self.clear {
                self.width = self.lit_width + 1;
                self.hi = self.eof;
                self.overflow = 1 << self.width;
                self.last = None;
                continue;
            }
            if code == self.eof {
                self.ended = true;
                return Ok(false);
            }

            let mut reverse = [0u8; MAX_CODES];
            let mut length = 0usize;
            let first;
            let mut special = false;
            if code < self.clear {
                first = code as u8;
                reverse[length] = first;
                length += 1;
            } else if code <= self.hi {
                let mut current = code;
                if code == self.hi {
                    let Some(last) = self.last else {
                        let error = invalid_data("lzw: invalid code");
                        self.error = Some(io::Error::new(error.kind(), error.to_string()));
                        return Err(error);
                    };
                    current = last;
                    special = true;
                    while current >= self.clear {
                        if length >= MAX_CODES - 1 {
                            return Err(invalid_data("lzw: invalid dictionary chain"));
                        }
                        reverse[length] = self.suffix[current as usize];
                        length += 1;
                        current = self.prefix[current as usize];
                    }
                    first = current as u8;
                } else {
                    while current >= self.clear {
                        if current as usize >= MAX_CODES || length >= MAX_CODES - 1 {
                            return Err(invalid_data("lzw: invalid dictionary chain"));
                        }
                        reverse[length] = self.suffix[current as usize];
                        length += 1;
                        current = self.prefix[current as usize];
                    }
                    first = current as u8;
                }
            } else {
                let error = invalid_data("lzw: invalid code");
                self.error = Some(io::Error::new(error.kind(), error.to_string()));
                return Err(error);
            }
            if code >= self.clear {
                reverse[length] = first;
                length += 1;
            }
            if special {
                reverse.copy_within(0..length, 1);
                reverse[0] = first;
                length += 1;
            }

            if self.produced.saturating_add(length) > self.max_output {
                let error = invalid_data("lzw: output limit exceeded");
                self.error = Some(io::Error::new(error.kind(), error.to_string()));
                return Err(error);
            }
            if let Some(last) = self.last {
                if self.hi as usize >= MAX_CODES {
                    let error = invalid_data("lzw: invalid dictionary code");
                    self.error = Some(io::Error::new(error.kind(), error.to_string()));
                    return Err(error);
                }
                self.suffix[self.hi as usize] = first;
                self.prefix[self.hi as usize] = last;
            }
            self.pending_len = length;
            self.pending_pos = 0;
            for index in 0..length {
                self.pending[index] = reverse[length - index - 1];
            }
            self.produced += length;
            self.last = Some(code);
            self.hi += 1;
            if self.hi >= self.overflow {
                if self.width == MAX_WIDTH {
                    self.last = None;
                    self.hi -= 1;
                } else {
                    self.width += 1;
                    self.overflow = 1 << self.width;
                }
            }
            return Ok(true);
        }
    }
}

impl<R: Read> Read for Reader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            if self.pending_pos < self.pending_len {
                let length = output.len().min(self.pending_len - self.pending_pos);
                output[..length]
                    .copy_from_slice(&self.pending[self.pending_pos..self.pending_pos + length]);
                self.pending_pos += length;
                return Ok(length);
            }
            if let Some(error) = &self.error {
                return Err(io::Error::new(error.kind(), error.to_string()));
            }
            if self.ended {
                return Ok(0);
            }
            if !self.next_phrase()? {
                return Ok(0);
            }
        }
    }
}

impl<R: Read> Reader<R> {
    /// Stops all future reads with an error after the buffered output, like Go's
    /// `Reader.Close`. The underlying reader stays open.
    pub fn close(&mut self) -> io::Result<()> {
        self.error = Some(io::Error::other("lzw: reader/writer is closed"));
        Ok(())
    }

    /// Starts a new stream on `inner`, keeping the configured output budget
    /// (Go's `Reader.Reset`).
    pub fn reset(&mut self, inner: R, order: Order, lit_width: u8) {
        *self = Self::new(inner, order, lit_width).with_max_output(self.max_output);
    }
}

/// Decodes an in-memory stream under an explicit decompressed-output budget.
pub fn decode(input: &[u8], order: Order, lit_width: u8, max_output: usize) -> io::Result<Vec<u8>> {
    let mut decoder = Reader::new(input, order, lit_width).with_max_output(max_output);
    let mut output = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        match decoder.read(&mut buffer) {
            Ok(0) => return Ok(output),
            Ok(length) => output.extend_from_slice(&buffer[..length]),
            Err(error) => return Err(error),
        }
    }
}
