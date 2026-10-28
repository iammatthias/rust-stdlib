//! `bufio.Writer` and `bufio.ReadWriter`.

use super::{Reader, DEFAULT_BUF_SIZE, MAX_CONSECUTIVE_EMPTY_READS};
use crate::io::stored::Stored;
use crate::io::{eof, is_eof, CopyError};
use crate::unicode::rune;
use std::io::{self, BufRead, Read, Write};

/// Implements buffering for an `io::Write` (`bufio.Writer`).
///
/// If a write to the underlying writer fails, no more data is accepted and
/// every later call returns that error. After writing, call
/// [`Writer::flush`]; like Go (and unlike `std::io::BufWriter`) dropping the
/// writer does not flush.
#[derive(Debug)]
pub struct Writer<W> {
    err: Option<Stored>,
    buf: Vec<u8>,
    n: usize,
    wr: W,
}

impl<W: Write> Writer<W> {
    /// Returns a writer with the default 4096-byte buffer (`bufio.NewWriter`).
    pub fn new(w: W) -> Self {
        Self::with_size(w, DEFAULT_BUF_SIZE)
    }

    /// Returns a writer whose buffer has `size` bytes; a size of 0 selects the
    /// default (`bufio.NewWriterSize`).
    ///
    /// Unlike Go, a writer that wraps another `bufio::Writer` is not returned
    /// as is; it gets its own buffer.
    pub fn with_size(w: W, size: usize) -> Self {
        let size = if size == 0 { DEFAULT_BUF_SIZE } else { size };
        Writer {
            err: None,
            buf: vec![0; size],
            n: 0,
            wr: w,
        }
    }

    /// The size of the underlying buffer in bytes (`Writer.Size`).
    pub fn size(&self) -> usize {
        self.buf.len()
    }

    /// Discards unflushed data, clears the error and switches output to `w`
    /// (`Writer.Reset`). Returns the previous underlying writer.
    pub fn reset(&mut self, w: W) -> W {
        self.err = None;
        self.n = 0;
        std::mem::replace(&mut self.wr, w)
    }

    /// The underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.wr
    }

    /// The underlying writer, mutably. Writing to it directly bypasses the
    /// buffer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.wr
    }

    /// Consumes the writer and returns the underlying writer; unflushed data
    /// is lost.
    pub fn into_inner(self) -> W {
        self.wr
    }

    fn sticky(&self) -> Option<io::Error> {
        self.err.as_ref().map(Stored::get)
    }

    /// One write to the underlying writer. A zero-byte write of non-empty
    /// data is `ErrShortWrite` (Go would call again).
    fn write_once(wr: &mut W, p: &[u8]) -> (usize, Option<io::Error>) {
        loop {
            match wr.write(p) {
                Ok(0) if !p.is_empty() => return (0, Some(crate::io::Error::ShortWrite.into())),
                Ok(n) => return (n.min(p.len()), None),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return (0, Some(e)),
            }
        }
    }

    /// Writes any buffered data to the underlying writer (`Writer.Flush`).
    pub fn flush(&mut self) -> io::Result<()> {
        if let Some(e) = self.sticky() {
            return Err(e);
        }
        if self.n == 0 {
            return Ok(());
        }
        let (n, mut err) = Self::write_once(&mut self.wr, &self.buf[..self.n]);
        if n < self.n && err.is_none() {
            err = Some(crate::io::Error::ShortWrite.into());
        }
        if let Some(e) = err {
            if n > 0 && n < self.n {
                self.buf.copy_within(n..self.n, 0);
            }
            self.n -= n;
            self.err = Some(Stored::new(e));
            return Err(self.sticky().expect("error just stored"));
        }
        self.n = 0;
        Ok(())
    }

    /// The number of unused bytes in the buffer (`Writer.Available`).
    pub fn available(&self) -> usize {
        self.buf.len() - self.n
    }

    /// Returns an empty buffer with capacity [`Writer::available`] to append
    /// to and then pass to [`Write::write`] (`Writer.AvailableBuffer`). Go's
    /// buffer aliases the writer's own spare space; this one is a separate
    /// allocation, so the bytes are copied by the write.
    pub fn available_buffer(&self) -> Vec<u8> {
        Vec::with_capacity(self.available())
    }

    /// The number of bytes written into the current buffer (`Writer.Buffered`).
    pub fn buffered(&self) -> usize {
        self.n
    }

    /// Writes `p` like [`Write::write`] but an error reports the bytes
    /// accepted (buffered or passed on) before it ([`CopyError::written`]),
    /// as Go's `(nn, err)` does (`Writer.Write`). The error is the sticky one.
    pub fn write_counted(&mut self, mut p: &[u8]) -> Result<usize, CopyError> {
        let mut nn = 0;
        while p.len() > self.available() && self.err.is_none() {
            let n;
            if self.buffered() == 0 {
                // Large write, empty buffer. Write directly from p to avoid copy.
                let (m, e) = Self::write_once(&mut self.wr, p);
                n = m;
                self.err = e.map(Stored::new);
            } else {
                n = (self.buf.len() - self.n).min(p.len());
                self.buf[self.n..self.n + n].copy_from_slice(&p[..n]);
                self.n += n;
                let _ = self.flush();
            }
            nn += n;
            p = &p[n..];
        }
        if let Some(e) = self.sticky() {
            return Err(CopyError::new(nn as u64, e));
        }
        let n = p.len();
        self.buf[self.n..self.n + n].copy_from_slice(p);
        self.n += n;
        nn += n;
        Ok(nn)
    }

    /// Writes a single UTF-8 encoded char and returns the bytes written
    /// (`Writer.WriteRune`). Go's `WriteByte` is `write_all(&[b])`.
    pub fn write_char(&mut self, r: char) -> io::Result<usize> {
        if (r as u32) < 0x80 {
            if let Some(e) = self.sticky() {
                return Err(e);
            }
            if self.available() == 0 {
                self.flush()?;
            }
            self.buf[self.n] = r as u8;
            self.n += 1;
            return Ok(1);
        }
        if let Some(e) = self.sticky() {
            return Err(e);
        }
        let mut n = self.available();
        if n < rune::UTF_MAX {
            let _ = self.flush();
            if let Some(e) = self.sticky() {
                return Err(e);
            }
            n = self.available();
            if n < rune::UTF_MAX {
                // Can only happen if buffer is silly small.
                let mut tmp = [0; 4];
                return self
                    .write_string(r.encode_utf8(&mut tmp))
                    .map_err(Into::into);
            }
        }
        let size = rune::encode_rune(&mut self.buf[self.n..], r as i32);
        self.n += size;
        Ok(size)
    }

    /// Writes a string and returns the bytes accepted; an error reports the
    /// bytes accepted before it ([`CopyError::written`]) (`Writer.WriteString`).
    /// The underlying writer's string-writing fast path is not used.
    pub fn write_string(&mut self, s: &str) -> Result<usize, CopyError> {
        // Go's loop for an underlying writer without WriteString: always
        // fill the buffer and flush, never write the string directly.
        let mut s = s.as_bytes();
        let mut nn = 0;
        while s.len() > self.available() && self.err.is_none() {
            let n = self.available().min(s.len());
            self.buf[self.n..self.n + n].copy_from_slice(&s[..n]);
            self.n += n;
            let _ = self.flush();
            nn += n;
            s = &s[n..];
        }
        if let Some(e) = self.sticky() {
            return Err(CopyError::new(nn as u64, e));
        }
        let n = s.len();
        self.buf[self.n..self.n + n].copy_from_slice(s);
        self.n += n;
        Ok(nn + n)
    }

    /// Reads from `r` until EOF and writes everything (`Writer.ReadFrom`).
    pub fn read_from<R: Read + ?Sized>(&mut self, r: &mut R) -> io::Result<u64> {
        if let Some(e) = self.sticky() {
            return Err(e);
        }
        let mut n = 0u64;
        let mut err: Option<io::Error>;
        loop {
            if self.available() == 0 {
                self.flush()?;
            }
            let mut nr = 0;
            let m;
            loop {
                let at = self.n;
                match r.read(&mut self.buf[at..]) {
                    Ok(0) => {
                        m = 0;
                        err = Some(eof());
                        break;
                    }
                    Ok(k) => {
                        m = k;
                        err = None;
                        break;
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                        nr += 1;
                        if nr == MAX_CONSECUTIVE_EMPTY_READS {
                            return Err(crate::io::Error::NoProgress.into());
                        }
                    }
                    Err(e) => {
                        m = 0;
                        err = Some(e);
                        break;
                    }
                }
            }
            self.n += m;
            n += m as u64;
            if err.is_some() {
                break;
            }
        }
        if err.as_ref().is_some_and(is_eof) {
            // If we filled the buffer exactly, flush preemptively.
            err = if self.available() == 0 {
                self.flush().err()
            } else {
                None
            };
        }
        match err {
            Some(e) => Err(e),
            None => Ok(n),
        }
    }
}

impl<W: Write> Write for Writer<W> {
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        self.write_counted(p).map_err(CopyError::into_source)
    }

    /// `Writer.Flush`.
    fn flush(&mut self) -> io::Result<()> {
        Writer::flush(self)
    }
}

/// Stores pointers to a [`Reader`] and a [`Writer`] (`bufio.ReadWriter`).
/// It implements `Read`, `BufRead` and `Write` by delegation, like Go's
/// embedded fields.
#[derive(Debug)]
pub struct ReadWriter<R, W> {
    /// The embedded reader (`ReadWriter.Reader`).
    pub reader: Reader<R>,
    /// The embedded writer (`ReadWriter.Writer`).
    pub writer: Writer<W>,
}

impl<R: Read, W: Write> ReadWriter<R, W> {
    /// Allocates a new `ReadWriter` that dispatches to `r` and `w`
    /// (`bufio.NewReadWriter`).
    pub fn new(r: Reader<R>, w: Writer<W>) -> Self {
        ReadWriter {
            reader: r,
            writer: w,
        }
    }
}

impl<R: Read, W: Write> Read for ReadWriter<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

impl<R: Read, W: Write> BufRead for ReadWriter<R, W> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.reader.fill_buf()
    }
    fn consume(&mut self, amt: usize) {
        self.reader.consume(amt);
    }
}

impl<R: Read, W: Write> Write for ReadWriter<R, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Writer::flush(&mut self.writer)
    }
}
