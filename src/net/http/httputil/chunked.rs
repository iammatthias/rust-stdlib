//! Go's lenient `httputil` chunked codec. The crate's `BodyReader` is a
//! stricter message decoder (validated extensions, trailer allowlist, body
//! budgets); Go's `NewChunkedReader` instead ignores extensions and stops at
//! the zero-size chunk without reading trailers, so it is ported separately.
//! Error messages match Go's.
use std::io::{self, Read, Write};

/// Go's `maxLineLength`: chunk-size lines must stay below this, including
/// the extension, and fit Go's 4096-byte `bufio.Reader` with their CRLF.
pub const MAX_LINE_LENGTH: usize = 4096;
const BUFFER: usize = 4096;

/// Decodes HTTP/1.1 chunked framing as Go's `httputil.NewChunkedReader`.
/// Reading stops (EOF) after the zero-size chunk line; trailer fields and the
/// final CRLF are left unread in the underlying stream's position after the
/// internal buffer. Errors are sticky.
pub struct ChunkedReader<R> {
    inner: R,
    buf: Box<[u8]>,
    start: usize,
    end: usize,
    inner_eof: bool,
    n: u64,
    error: Option<(io::ErrorKind, String)>,
    eof: bool,
    check_end: bool,
    excess: i64,
}

impl<R: Read> ChunkedReader<R> {
    /// Buffers like Go's default 4096-byte `bufio.Reader`.
    pub fn new(inner: R) -> Self {
        Self::with_buffer_size(inner, BUFFER)
    }
    /// Go's `NewChunkedReader(bufio.NewReaderSize(r, size))`: chunk-size
    /// lines longer than the buffer fail with `ErrLineTooLong`. Sizes below
    /// 16 are raised to 16, as bufio does.
    pub fn with_buffer_size(inner: R, size: usize) -> Self {
        Self {
            inner,
            buf: vec![0; size.max(16)].into_boxed_slice(),
            start: 0,
            end: 0,
            inner_eof: false,
            n: 0,
            error: None,
            eof: false,
            check_end: false,
            excess: 0,
        }
    }
    fn buffered(&self) -> usize {
        self.end - self.start
    }
    /// Read more input into the buffer; false at EOF.
    fn fill(&mut self) -> io::Result<bool> {
        if self.inner_eof {
            return Ok(false);
        }
        if self.start > 0 {
            self.buf.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
        loop {
            match self.inner.read(&mut self.buf[self.end..]) {
                Ok(0) => {
                    self.inner_eof = true;
                    return Ok(false);
                }
                Ok(n) => {
                    self.end += n;
                    return Ok(true);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
    fn fail(&mut self, kind: io::ErrorKind, message: impl Into<String>) {
        self.error = Some((kind, message.into()));
    }
    /// Go's `readChunkLine` over `bufio.Reader.ReadSlice('\n')`.
    fn read_line(&mut self) -> Result<Vec<u8>, (io::ErrorKind, String)> {
        let unexpected = || (io::ErrorKind::UnexpectedEof, "unexpected EOF".to_owned());
        let too_long = || {
            (
                io::ErrorKind::InvalidData,
                "header line too long".to_owned(),
            )
        };
        let end = loop {
            if let Some(i) = self.buf[self.start..self.end]
                .iter()
                .position(|&b| b == b'\n')
            {
                break self.start + i + 1;
            }
            if self.buffered() == self.buf.len() {
                return Err(too_long());
            }
            match self.fill() {
                Ok(true) => {}
                Ok(false) => return Err(unexpected()),
                Err(e) => return Err((e.kind(), e.to_string())),
            }
        };
        let line = self.buf[self.start..end].to_vec();
        self.start = end;
        match line.iter().position(|&b| b == b'\r') {
            None => {
                return Err((
                    io::ErrorKind::InvalidData,
                    "chunked line ends with bare LF".to_owned(),
                ))
            }
            Some(i) if i != line.len() - 2 => {
                return Err((
                    io::ErrorKind::InvalidData,
                    "invalid CR in chunked line".to_owned(),
                ))
            }
            Some(_) => {}
        }
        let line = line[..line.len() - 2].to_vec();
        if line.len() >= MAX_LINE_LENGTH {
            return Err(too_long());
        }
        Ok(line)
    }
    fn begin_chunk(&mut self) {
        let line = match self.read_line() {
            Ok(line) => line,
            Err((kind, message)) => return self.fail(kind, message),
        };
        self.excess = self.excess.wrapping_add(line.len() as i64 + 2);
        let mut line = &line[..];
        while let [rest @ .., b' ' | b'\t'] = line {
            line = rest;
        }
        // Extensions are ignored without validation, as in Go.
        if let Some(semi) = line.iter().position(|&b| b == b';') {
            line = &line[..semi];
        }
        match parse_hex_uint(line) {
            Ok(n) => self.n = n,
            Err(message) => return self.fail(io::ErrorKind::InvalidData, message),
        }
        // Go's int64 arithmetic, including wrap-around for huge sizes.
        self.excess = self
            .excess
            .wrapping_sub(16i64.wrapping_add(2i64.wrapping_mul(self.n as i64)))
            .max(0);
        if self.excess > 16 * 1024 {
            self.fail(
                io::ErrorKind::InvalidData,
                "chunked encoding contains too much non-data",
            );
        }
        if self.n == 0 {
            self.error = None;
            self.eof = true;
        }
    }
    fn chunk_header_available(&self) -> bool {
        self.buf[self.start..self.end].contains(&b'\n')
    }
}

fn parse_hex_uint(v: &[u8]) -> Result<u64, &'static str> {
    if v.is_empty() {
        return Err("empty hex number for chunk length");
    }
    let mut n = 0u64;
    for (i, &b) in v.iter().enumerate() {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return Err("invalid byte in chunk length"),
        };
        if i == 16 {
            return Err("http chunk length too large");
        }
        n = (n << 4) | u64::from(digit);
    }
    Ok(n)
}

impl<R: Read> Read for ChunkedReader<R> {
    fn read(&mut self, mut out: &mut [u8]) -> io::Result<usize> {
        let mut n = 0;
        while self.error.is_none() && !self.eof {
            if self.check_end {
                if n > 0 && self.buffered() < 2 {
                    break;
                }
                while self.buffered() < 2 {
                    match self.fill() {
                        Ok(true) => {}
                        Ok(false) => {
                            self.fail(io::ErrorKind::UnexpectedEof, "unexpected EOF");
                            break;
                        }
                        Err(e) => return if n > 0 { Ok(n) } else { Err(e) },
                    }
                }
                if self.error.is_some() {
                    break;
                }
                let end = [self.buf[self.start], self.buf[self.start + 1]];
                self.start += 2;
                if end != *b"\r\n" {
                    self.fail(io::ErrorKind::InvalidData, "malformed chunked encoding");
                    break;
                }
                self.check_end = false;
            }
            if self.n == 0 {
                if n > 0 && !self.chunk_header_available() {
                    break;
                }
                self.begin_chunk();
                continue;
            }
            if out.is_empty() {
                break;
            }
            if self.buffered() == 0 {
                match self.fill() {
                    Ok(true) => {}
                    Ok(false) => {
                        self.fail(io::ErrorKind::UnexpectedEof, "unexpected EOF");
                        break;
                    }
                    Err(e) => return if n > 0 { Ok(n) } else { Err(e) },
                }
            }
            let take = out
                .len()
                .min(self.buffered())
                .min(usize::try_from(self.n).unwrap_or(usize::MAX));
            out[..take].copy_from_slice(&self.buf[self.start..self.start + take]);
            self.start += take;
            out = &mut out[take..];
            n += take;
            self.n -= take as u64;
            if self.n == 0 {
                self.check_end = true;
            }
        }
        if n > 0 {
            return Ok(n);
        }
        match &self.error {
            Some((kind, message)) => Err(io::Error::new(*kind, message.clone())),
            None => Ok(0),
        }
    }
}

/// Go's `httputil.NewChunkedWriter`: each non-empty write becomes one chunk.
/// `close` writes only the `0\r\n` last-chunk line; the caller writes any
/// trailers and the final CRLF, as in Go.
pub struct ChunkedWriter<W> {
    inner: W,
}
impl<W: Write> ChunkedWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner }
    }
    pub fn close(&mut self) -> io::Result<()> {
        self.inner.write_all(b"0\r\n")
    }
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }
    pub fn into_inner(self) -> W {
        self.inner
    }
}
impl<W: Write> Write for ChunkedWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        self.inner
            .write_all(format!("{:x}\r\n", data.len()).as_bytes())?;
        self.inner.write_all(data)?;
        self.inner.write_all(b"\r\n")?;
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
