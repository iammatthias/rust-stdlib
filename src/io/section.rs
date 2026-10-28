//! `io.SectionReader` and `io.OffsetWriter`.

use super::{eof, is_eof, ReadAt, ReadError, WriteAt};
use std::io::{self, Read, Seek, SeekFrom, Write};

fn err_whence() -> io::Error {
    io::Error::other("Seek: invalid whence")
}

fn err_offset() -> io::Error {
    io::Error::other("Seek: invalid offset")
}

/// Reads a section of a [`ReadAt`] (`io.SectionReader`).
#[derive(Clone, Debug)]
pub struct SectionReader<R> {
    r: R,
    base: i64,
    off: i64,
    limit: i64,
    n: i64,
}

impl<R: ReadAt> SectionReader<R> {
    /// Returns a reader of `n` bytes of `r` starting at `off`
    /// (`io.NewSectionReader`).
    pub fn new(r: R, off: i64, n: i64) -> Self {
        let remaining = if off <= i64::MAX.wrapping_sub(n) {
            n.wrapping_add(off)
        } else {
            i64::MAX
        };
        SectionReader {
            r,
            base: off,
            off,
            limit: remaining,
            n,
        }
    }

    /// Returns the size of the section in bytes (`SectionReader.Size`).
    pub fn size(&self) -> i64 {
        self.limit.wrapping_sub(self.base)
    }

    /// Consumes the section and returns the underlying reader.
    pub fn into_inner(self) -> R {
        self.r
    }

    /// Returns the underlying reader and the arguments given to `new`
    /// (`SectionReader.Outer`).
    pub fn outer(&self) -> (&R, i64, i64) {
        (&self.r, self.base, self.n)
    }
}

impl<R: ReadAt> ReadAt for SectionReader<R> {
    /// Reads at `offset` relative to the section start
    /// (`SectionReader.ReadAt`); the end of the section is [`Error::Eof`](super::Error::Eof).
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize, ReadError> {
        let off = match i64::try_from(offset) {
            Ok(off) if off < self.size() => off,
            _ => return Err(ReadError::new(0, eof())),
        };
        let off = off.wrapping_add(self.base);
        let max = self.limit.wrapping_sub(off);
        if buf.len() as i64 > max {
            // The section ends before the buffer is full.
            return Err(match self.r.read_at(&mut buf[..max as usize], off as u64) {
                Ok(n) => ReadError::new(n, eof()),
                Err(e) => e,
            });
        }
        self.r.read_at(buf, off as u64)
    }
}

impl<R: ReadAt> Read for SectionReader<R> {
    /// `SectionReader.Read`; an underlying error other than EOF is returned
    /// only when no bytes were read.
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        if self.off >= self.limit {
            return Ok(0);
        }
        let max = self.limit - self.off;
        let p = if p.len() as i64 > max {
            &mut p[..max as usize]
        } else {
            p
        };
        let (n, err) = match self.r.read_at(p, self.off as u64) {
            Ok(n) => (n, None),
            Err(e) => (e.read(), Some(e.into_source())),
        };
        self.off += n as i64;
        match err {
            Some(e) if n == 0 && !is_eof(&e) => Err(e),
            _ => Ok(n),
        }
    }
}

impl<R: ReadAt> Seek for SectionReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let offset = match pos {
            SeekFrom::Start(o) => i64::try_from(o).unwrap_or(i64::MAX).wrapping_add(self.base),
            SeekFrom::Current(o) => o.wrapping_add(self.off),
            SeekFrom::End(o) => o.wrapping_add(self.limit),
        };
        if offset < self.base {
            return Err(err_offset());
        }
        self.off = offset;
        Ok((offset - self.base) as u64)
    }
}

/// Maps writes to a [`WriteAt`] at a moving offset (`io.OffsetWriter`).
#[derive(Clone, Debug)]
pub struct OffsetWriter<W> {
    w: W,
    base: i64,
    off: i64,
}

impl<W: WriteAt> OffsetWriter<W> {
    /// Returns a writer that writes to `w` starting at `off`
    /// (`io.NewOffsetWriter`).
    pub fn new(w: W, off: i64) -> Self {
        OffsetWriter { w, base: off, off }
    }

    /// Consumes the writer and returns the underlying `WriteAt`.
    pub fn into_inner(self) -> W {
        self.w
    }
}

impl<W: WriteAt> WriteAt for OffsetWriter<W> {
    /// Writes at `offset` relative to the base (`OffsetWriter.WriteAt`).
    fn write_at(&mut self, buf: &[u8], offset: u64) -> io::Result<()> {
        let Ok(off) = i64::try_from(offset) else {
            return Err(err_offset());
        };
        self.w.write_at(buf, off.wrapping_add(self.base) as u64)
    }
}

impl<W: WriteAt> Write for OffsetWriter<W> {
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        self.w.write_at(p, self.off as u64)?;
        self.off += p.len() as i64;
        Ok(p.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<W: WriteAt> Seek for OffsetWriter<W> {
    /// `OffsetWriter.Seek`; seeking from the end is not supported, as in Go.
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let offset = match pos {
            SeekFrom::Start(o) => i64::try_from(o).unwrap_or(i64::MAX).wrapping_add(self.base),
            SeekFrom::Current(o) => o.wrapping_add(self.off),
            SeekFrom::End(_) => return Err(err_whence()),
        };
        if offset < self.base {
            return Err(err_offset());
        }
        self.off = offset;
        Ok((offset - self.base) as u64)
    }
}
