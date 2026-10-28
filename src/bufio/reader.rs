//! `bufio.Reader`.

use super::{Error, DEFAULT_BUF_SIZE, MAX_CONSECUTIVE_EMPTY_READS, MIN_READ_BUFFER_SIZE};
use crate::io::{eof, is_eof, ReadError};
use crate::unicode::{chars::decode_rune, rune};
use std::fmt;
use std::io::{self, BufRead, Read, Write};

/// Implements buffering for an `io::Read` (`bufio.Reader`).
#[derive(Debug)]
pub struct Reader<R> {
    buf: Vec<u8>,
    rd: R,
    r: usize,
    w: usize,
    err: Option<io::Error>,
    /// Last byte read for `unread_byte`; -1 means invalid.
    last_byte: i32,
    /// Size of the last rune read for `unread_rune`; -1 means invalid.
    last_rune_size: i32,
}

impl<R: Read> Reader<R> {
    /// Returns a reader with the default 4096-byte buffer (`bufio.NewReader`).
    pub fn new(rd: R) -> Self {
        Self::with_size(rd, DEFAULT_BUF_SIZE)
    }

    /// Returns a reader whose buffer has at least `size` bytes, and at least
    /// 16 (`bufio.NewReaderSize`).
    ///
    /// Unlike Go, a reader that wraps another `bufio::Reader` is not
    /// returned as is; it gets its own buffer.
    pub fn with_size(rd: R, size: usize) -> Self {
        Reader {
            buf: vec![0; size.max(MIN_READ_BUFFER_SIZE)],
            rd,
            r: 0,
            w: 0,
            err: None,
            last_byte: -1,
            last_rune_size: -1,
        }
    }

    /// The size of the underlying buffer in bytes (`Reader.Size`).
    pub fn size(&self) -> usize {
        self.buf.len()
    }

    /// Discards any buffered data and state and switches to reading from
    /// `r` (`Reader.Reset`). Returns the previous underlying reader.
    pub fn reset(&mut self, r: R) -> R {
        self.r = 0;
        self.w = 0;
        self.err = None;
        self.last_byte = -1;
        self.last_rune_size = -1;
        std::mem::replace(&mut self.rd, r)
    }

    /// The underlying reader.
    pub fn get_ref(&self) -> &R {
        &self.rd
    }

    /// The underlying reader, mutably. Reading from it directly bypasses
    /// the buffer.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.rd
    }

    /// Consumes the reader and returns the underlying reader; buffered data
    /// is lost.
    pub fn into_inner(self) -> R {
        self.rd
    }

    /// Reads a new chunk into the buffer.
    fn fill(&mut self) {
        // Slide existing data to the beginning.
        if self.r > 0 {
            self.buf.copy_within(self.r..self.w, 0);
            self.w -= self.r;
            self.r = 0;
        }
        assert!(self.w < self.buf.len(), "bufio: tried to fill full buffer");
        // Read new data: try a limited number of times.
        for _ in 0..MAX_CONSECUTIVE_EMPTY_READS {
            match self.rd.read(&mut self.buf[self.w..]) {
                // A zero-length read into a non-empty buffer is std's EOF.
                Ok(0) => {
                    self.err = Some(eof());
                    return;
                }
                Ok(n) => {
                    self.w += n;
                    return;
                }
                // An interrupted read made no progress, like Go's (0, nil).
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    self.err = Some(e);
                    return;
                }
            }
        }
        self.err = Some(crate::io::Error::NoProgress.into());
    }

    fn read_err(&mut self) -> Option<io::Error> {
        self.err.take()
    }

    /// The bytes buffered but not yet read, without reading more
    /// (`std::io::BufReader::buffer`). After a failed [`Reader::peek`] it is
    /// the data Go's `Peek` returns with the error.
    pub fn buffer(&self) -> &[u8] {
        &self.buf[self.r..self.w]
    }

    /// Returns the next `n` bytes without advancing the reader
    /// (`Reader.Peek`). If fewer than `n` bytes are available the error says
    /// why (`ErrBufferFull` if `n` exceeds the buffer or the buffer filled);
    /// [`Reader::buffer`] then holds the bytes that were available.
    pub fn peek(&mut self, n: usize) -> io::Result<&[u8]> {
        self.last_byte = -1;
        self.last_rune_size = -1;
        while self.w - self.r < n && self.w - self.r < self.buf.len() && self.err.is_none() {
            self.fill(); // self.w-self.r < buf.len() => buffer is not full
        }
        if n > self.buf.len() {
            return Err(Error::BufferFull.into());
        }
        // 0 <= n <= buf.len()
        if self.w - self.r < n {
            // Not enough data in the buffer.
            return Err(self.read_err().unwrap_or_else(|| Error::BufferFull.into()));
        }
        Ok(&self.buf[self.r..self.r + n])
    }

    /// Go's `Peek` result as a pair: the bytes available up to `n` and the
    /// error, if any.
    #[cfg(feature = "net")]
    pub(crate) fn peek_available(&mut self, n: usize) -> (&[u8], Option<io::Error>) {
        let err = self.peek(n).err();
        let b = self.buffer();
        (&b[..b.len().min(n)], err)
    }

    /// Skips the next `n` bytes and returns the number discarded
    /// (`Reader.Discard`). If fewer than `n` were discarded the error says
    /// why and [`ReadError::read`] is the number discarded.
    pub fn discard(&mut self, n: usize) -> Result<usize, ReadError> {
        if n == 0 {
            return Ok(0);
        }
        self.last_byte = -1;
        self.last_rune_size = -1;
        let mut remain = n;
        loop {
            let mut skip = self.buffered();
            if skip == 0 {
                self.fill();
                skip = self.buffered();
            }
            if skip > remain {
                skip = remain;
            }
            self.r += skip;
            remain -= skip;
            if remain == 0 {
                return Ok(n);
            }
            if self.err.is_some() {
                let err = self.read_err().expect("error present");
                return Err(ReadError::new(n - remain, err));
            }
        }
    }

    /// Reads one byte (`Reader.ReadByte`); `io.EOF` is an error.
    pub fn read_byte(&mut self) -> io::Result<u8> {
        self.last_rune_size = -1;
        while self.r == self.w {
            if self.err.is_some() {
                return Err(self.read_err().expect("error present"));
            }
            self.fill(); // buffer is empty
        }
        let c = self.buf[self.r];
        self.r += 1;
        self.last_byte = i32::from(c);
        Ok(c)
    }

    /// Unreads the last byte (`Reader.UnreadByte`). Only the most recently
    /// read byte can be unread; it fails after `peek`, `discard` and a
    /// second consecutive unread.
    pub fn unread_byte(&mut self) -> io::Result<()> {
        if self.last_byte < 0 || self.r == 0 && self.w > 0 {
            return Err(Error::InvalidUnreadByte.into());
        }
        // self.r > 0 || self.w == 0
        if self.r > 0 {
            self.r -= 1;
        } else {
            // self.r == 0 && self.w == 0
            self.w = 1;
        }
        self.buf[self.r] = self.last_byte as u8;
        self.last_byte = -1;
        self.last_rune_size = -1;
        Ok(())
    }

    /// Reads one UTF-8 encoded rune and returns it with its size in bytes
    /// (`Reader.ReadRune`). An invalid encoding consumes one byte and
    /// returns `U+FFFD`.
    pub fn read_rune(&mut self) -> io::Result<(char, usize)> {
        while self.r + rune::UTF_MAX > self.w
            && !rune::full_rune(&self.buf[self.r..self.w])
            && self.err.is_none()
            && self.w - self.r < self.buf.len()
        {
            self.fill(); // self.w-self.r < buf.len() => buffer is not full
        }
        self.last_rune_size = -1;
        if self.r == self.w {
            return Err(self.read_err().expect("fill left an error"));
        }
        let (r, size) = decode_rune(&self.buf[self.r..self.w]);
        self.r += size;
        self.last_byte = i32::from(self.buf[self.r - 1]);
        self.last_rune_size = size as i32;
        Ok((r, size))
    }

    /// Unreads the last rune (`Reader.UnreadRune`); only valid right after
    /// a successful `read_rune`.
    pub fn unread_rune(&mut self) -> io::Result<()> {
        if self.last_rune_size < 0 || self.r < self.last_rune_size as usize {
            return Err(Error::InvalidUnreadRune.into());
        }
        self.r -= self.last_rune_size as usize;
        self.last_byte = -1;
        self.last_rune_size = -1;
        Ok(())
    }

    /// The number of bytes that can be read from the current buffer
    /// (`Reader.Buffered`).
    pub fn buffered(&self) -> usize {
        self.w - self.r
    }

    /// `read_slice` as a range of `buf` (valid until the next fill).
    fn slice_range(&mut self, delim: u8) -> (usize, usize, Option<io::Error>) {
        let mut s = 0; // search start index
        let (lo, hi);
        let mut err = None;
        loop {
            // Search buffer.
            if let Some(i) = self.buf[self.r + s..self.w]
                .iter()
                .position(|&c| c == delim)
            {
                let i = i + s;
                lo = self.r;
                hi = self.r + i + 1;
                self.r += i + 1;
                break;
            }
            // Pending error?
            if self.err.is_some() {
                lo = self.r;
                hi = self.w;
                self.r = self.w;
                err = self.read_err();
                break;
            }
            // Buffer full?
            if self.buffered() >= self.buf.len() {
                lo = 0;
                hi = self.buf.len();
                self.r = self.w;
                err = Some(Error::BufferFull.into());
                break;
            }
            s = self.w - self.r; // do not rescan area we scanned before
            self.fill(); // buffer is not full
        }
        // Handle last byte, if any.
        if hi > lo {
            self.last_byte = i32::from(self.buf[hi - 1]);
            self.last_rune_size = -1;
        }
        (lo, hi, err)
    }

    /// Reads until the first occurrence of `delim` and returns a slice of
    /// the buffer including the delimiter (`Reader.ReadSlice`). The slice is
    /// valid until the next read. If the buffer fills without `delim` the
    /// whole buffer comes back in the error ([`SliceError::data`], with
    /// `ErrBufferFull`); at the end of input without `delim` the remaining
    /// data does, with `io.EOF`.
    pub fn read_slice(&mut self, delim: u8) -> Result<&[u8], SliceError<'_>> {
        let (lo, hi, err) = self.slice_range(delim);
        match err {
            None => Ok(&self.buf[lo..hi]),
            Some(source) => Err(SliceError {
                data: &self.buf[lo..hi],
                source,
            }),
        }
    }

    /// Reads a line without the end-of-line bytes (`Reader.ReadLine`) and
    /// reports whether it is only a prefix: `true` when the line was too long
    /// for the buffer, the rest coming from later calls. A trailing `\r\n`
    /// or `\n` is removed. Prefer [`BufRead::read_until`] or a `Scanner` for
    /// most uses.
    pub fn read_line_bytes(&mut self) -> io::Result<(&[u8], bool)> {
        let (lo, mut hi, err) = self.slice_range(b'\n');
        if err.as_ref().is_some_and(|e| Error::BufferFull.is(e)) {
            // Handle the case where "\r\n" straddles the buffer.
            if hi > lo && self.buf[hi - 1] == b'\r' {
                // Put the '\r' back on buf and drop it from line. Let the
                // next call to ReadLine check for "\r\n".
                assert!(self.r != 0, "bufio: tried to rewind past start of buffer");
                self.r -= 1;
                hi -= 1;
            }
            return Ok((&self.buf[lo..hi], true));
        }
        if hi == lo {
            return match err {
                Some(e) => Err(e),
                None => Ok((&self.buf[lo..hi], false)),
            };
        }
        if self.buf[hi - 1] == b'\n' {
            let mut drop = 1;
            if hi - lo > 1 && self.buf[hi - 2] == b'\r' {
                drop = 2;
            }
            hi -= drop;
        }
        Ok((&self.buf[lo..hi], false))
    }

    fn write_buf<W: Write + ?Sized>(&mut self, w: &mut W) -> (u64, Option<io::Error>) {
        match w.write(&self.buf[self.r..self.w]) {
            Ok(n) => {
                self.r += n;
                (n as u64, None)
            }
            Err(e) => (0, Some(e)),
        }
    }

    /// Writes the buffered data and the rest of the input to `w`
    /// (`Reader.WriteTo`). It does not use the `WriterTo`/`ReaderFrom`
    /// shortcuts of Go.
    pub fn write_to<W: Write + ?Sized>(&mut self, w: &mut W) -> io::Result<u64> {
        self.last_byte = -1;
        self.last_rune_size = -1;
        let mut n = 0;
        if self.r < self.w {
            let (m, err) = self.write_buf(w);
            n += m;
            if let Some(e) = err {
                return Err(e);
            }
        }
        if self.w - self.r < self.buf.len() {
            self.fill(); // buffer not full
        }
        while self.r < self.w {
            // self.r < self.w => buffer is not empty
            let (m, err) = self.write_buf(w);
            n += m;
            if let Some(e) = err {
                return Err(e);
            }
            self.fill(); // buffer is empty
        }
        match self.read_err() {
            Some(e) if !is_eof(&e) => Err(e),
            _ => Ok(n),
        }
    }

    /// One read of the underlying reader into `dst`: the count and the
    /// pending error (`Ok(0)` is `io.EOF`).
    fn read_once(rd: &mut R, dst: &mut [u8]) -> (usize, Option<io::Error>) {
        loop {
            match rd.read(dst) {
                Ok(0) => return (0, Some(eof())),
                Ok(n) => return (n, None),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return (0, Some(e)),
            }
        }
    }
}

impl<R: Read> Read for Reader<R> {
    /// Reads data into `p` (`Reader.Read`). At most one read of the
    /// underlying reader is made, and a read at least as large as the buffer
    /// bypasses it when the buffer is empty. `Ok(0)` is `io.EOF`.
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        if p.is_empty() {
            if self.buffered() > 0 {
                return Ok(0);
            }
            return finish(self.read_err());
        }
        if self.r == self.w {
            if self.err.is_some() {
                return finish(self.read_err());
            }
            if p.len() >= self.buf.len() {
                // Large read, empty buffer.
                // Read directly into p to avoid copy.
                let (n, err) = Self::read_once(&mut self.rd, p);
                self.err = err;
                if n > 0 {
                    self.last_byte = i32::from(p[n - 1]);
                    self.last_rune_size = -1;
                }
                return match self.read_err() {
                    Some(e) if !is_eof(&e) => Err(e),
                    _ => Ok(n),
                };
            }
            // One read.
            self.r = 0;
            self.w = 0;
            let (n, err) = Self::read_once(&mut self.rd, &mut self.buf);
            self.err = err;
            if n == 0 {
                return finish(self.read_err());
            }
            self.w += n;
        }
        // copy as much as we can
        let n = p.len().min(self.w - self.r);
        p[..n].copy_from_slice(&self.buf[self.r..self.r + n]);
        self.r += n;
        self.last_byte = i32::from(self.buf[self.r - 1]);
        self.last_rune_size = -1;
        Ok(n)
    }
}

/// A pending read error as std's `Read` result: EOF is `Ok(0)`.
fn finish(err: Option<io::Error>) -> io::Result<usize> {
    match err {
        Some(e) if !is_eof(&e) => Err(e),
        _ => Ok(0),
    }
}

impl<R: Read> BufRead for Reader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.r == self.w {
            if self.err.is_none() {
                self.fill();
            }
            if self.r == self.w {
                if let Some(e) = self.read_err() {
                    if !is_eof(&e) {
                        return Err(e);
                    }
                }
            }
        }
        Ok(&self.buf[self.r..self.w])
    }

    fn consume(&mut self, amt: usize) {
        self.r = (self.r + amt).min(self.w);
        if amt > 0 && self.r > 0 {
            self.last_byte = i32::from(self.buf[self.r - 1]);
            self.last_rune_size = -1;
        }
    }

    /// `Reader.ReadBytes` (and, with `\n`, `ReadString`): appends the data
    /// up to and including `delim` and returns the count. Like Go it keeps
    /// reading ahead through the buffer, so the read pattern on the
    /// underlying reader matches Go's. Reaching EOF before `delim` is not an
    /// error (`Ok`, with the data not ending in `delim`).
    fn read_until(&mut self, delim: u8, out: &mut Vec<u8>) -> io::Result<usize> {
        let start = out.len();
        loop {
            let (lo, hi, err) = self.slice_range(delim);
            out.extend_from_slice(&self.buf[lo..hi]);
            match err {
                Some(e) if Error::BufferFull.is(&e) => {}
                Some(e) if !is_eof(&e) => return Err(e),
                _ => return Ok(out.len() - start),
            }
        }
    }
}

/// The error of [`Reader::read_slice`]: the failure plus the data consumed
/// before it (Go returns both).
#[derive(Debug)]
pub struct SliceError<'a> {
    data: &'a [u8],
    source: io::Error,
}

impl<'a> SliceError<'a> {
    /// The bytes consumed before the failure.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// The underlying error.
    pub fn source(&self) -> &io::Error {
        &self.source
    }

    /// Consumes the error and returns the underlying one.
    pub fn into_source(self) -> io::Error {
        self.source
    }
}

impl fmt::Display for SliceError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.source, f)
    }
}

impl std::error::Error for SliceError<'_> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl From<SliceError<'_>> for io::Error {
    fn from(e: SliceError<'_>) -> io::Error {
        e.source
    }
}

impl<R: Read> crate::io::RuneReader for Reader<R> {
    fn read_rune(&mut self) -> io::Result<(char, usize)> {
        Reader::read_rune(self)
    }
}

impl<R: Read> crate::io::RuneScanner for Reader<R> {
    fn unread_rune(&mut self) -> io::Result<()> {
        Reader::unread_rune(self)
    }
}
