//! Go's `io` package on top of `std::io`.
//!
//! `io.Reader`, `io.Writer` and `io.Seeker` are `std::io::{Read, Write, Seek}`;
//! this module adds only the Go-specific parts: sentinel errors, the
//! interfaces `std` lacks ([`ReadAt`], [`WriteAt`], [`RuneReader`],
//! [`RuneScanner`]), the partial-count `copy`/`read_full`/`read_at_least`,
//! the multi-writer/tee/section adapters and a synchronous in-memory pipe.
//! `ReadAll`, `LimitReader`, `MultiReader`, `WriteString`, `WriteByte`,
//! `SeekStart`/`SeekCurrent`/`SeekEnd` and the composite interfaces are
//! `std` (`read_to_end`, `take`, `chain`, `write_all`, `SeekFrom`, trait
//! bounds).
//!
//! Conventions:
//!
//! - Go's `io.EOF` is `Ok(0)` from `Read` (std's convention). Where Go's single
//!   item methods return `io.EOF` as an error (`ReadByte`, `ReadRune`,
//!   `ReadAt`, ...) it is an `io::Error` whose payload is [`Error::Eof`];
//!   test it with [`is_eof`]. The other sentinels (`ErrUnexpectedEOF`, ...)
//!   are the remaining [`Error`] variants, built with `io::Error::from` and
//!   tested with [`Error::is`].
//! - Functions whose partial count is meaningful on error return it inside
//!   the error: [`CopyError::written`] and [`ReadError::read`].

use std::fmt;
use std::io;
/// std's I/O traits, re-exported: Go's `io.Reader`, `io.Writer`, `io.Seeker`
/// and `bufio`'s buffered reading are these traits, so `rust_stdlib::io::Read`
/// and `std::io::Read` are the same trait.
pub use std::io::{BufRead, Read, Seek, SeekFrom, Write};

pub mod fs;
mod pipe;
mod section;
pub(crate) mod stored;

pub use pipe::{pipe, PipeReader, PipeWriter};
pub use section::{OffsetWriter, SectionReader};

/// Go's `io` sentinel errors, carried as the payload of an `io::Error`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// `io.EOF`
    Eof,
    /// `io.ErrClosedPipe`
    ClosedPipe,
    /// `io.ErrNoProgress`
    NoProgress,
    /// `io.ErrShortBuffer`
    ShortBuffer,
    /// `io.ErrShortWrite`
    ShortWrite,
    /// `io.ErrUnexpectedEOF`
    UnexpectedEof,
}

impl Error {
    /// Reports whether `err` is this sentinel (`errors.Is(err, io.X)`).
    pub fn is(self, err: &io::Error) -> bool {
        chain_has(err, &self)
    }

    fn kind(self) -> io::ErrorKind {
        match self {
            Error::Eof | Error::UnexpectedEof => io::ErrorKind::UnexpectedEof,
            Error::ClosedPipe => io::ErrorKind::BrokenPipe,
            Error::ShortWrite => io::ErrorKind::WriteZero,
            Error::NoProgress | Error::ShortBuffer => io::ErrorKind::Other,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Eof => "EOF",
            Error::ClosedPipe => "io: read/write on closed pipe",
            Error::NoProgress => "multiple Read calls return no data or error",
            Error::ShortBuffer => "short buffer",
            Error::ShortWrite => "short write",
            Error::UnexpectedEof => "unexpected EOF",
        })
    }
}

impl std::error::Error for Error {}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        io::Error::new(e.kind(), e)
    }
}

/// Reports whether `err`, or an error it wraps, is the value `want` (the
/// walk behind `errors.Is` for the sentinel enums of this crate). It looks
/// through `source` links and through `io::Error` values boxed in an
/// `io::Error`, which `source` itself skips.
pub(crate) fn chain_has<T: PartialEq + std::error::Error + 'static>(
    err: &io::Error,
    want: &T,
) -> bool {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = err.get_ref().map(|e| e as _);
    while let Some(e) = cur {
        if e.downcast_ref::<T>() == Some(want) {
            return true;
        }
        if let Some(inner) = e.downcast_ref::<io::Error>() {
            if chain_has(inner, want) {
                return true;
            }
        }
        cur = e.source();
    }
    false
}

/// Returns `io.EOF` as an `io::Error`.
pub fn eof() -> io::Error {
    Error::Eof.into()
}

/// Reports whether `err` is `io.EOF`.
pub fn is_eof(err: &io::Error) -> bool {
    Error::Eof.is(err)
}

/// Reports whether `err` is `io.ErrUnexpectedEOF`.
pub fn is_unexpected_eof(err: &io::Error) -> bool {
    Error::UnexpectedEof.is(err)
}

/// `io.ReaderAt`: positional reads that do not move any cursor. It mirrors
/// `std::os::unix::fs::FileExt::read_at`, but with Go's contract: the buffer
/// is filled unless an error says why not.
pub trait ReadAt {
    /// Reads into `buf` starting at `offset` and returns the bytes read,
    /// which is `buf.len()`. Fewer bytes are an error carrying the count
    /// ([`ReadError::read`]): [`Error::Eof`] at the end of the data.
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize, ReadError>;
}

/// `io.WriterAt`: positional writes.
pub trait WriteAt {
    /// Writes all of `buf` at `offset`; a short write is an error
    /// ([`Error::ShortWrite`]).
    fn write_at(&mut self, buf: &[u8], offset: u64) -> io::Result<()>;
}

/// `io.RuneReader`.
pub trait RuneReader {
    /// Reads one rune and its encoded size; invalid UTF-8 is `U+FFFD`, width 1.
    fn read_rune(&mut self) -> io::Result<(char, usize)>;
}

/// `io.RuneScanner`.
pub trait RuneScanner: RuneReader {
    /// Unreads the last rune read.
    fn unread_rune(&mut self) -> io::Result<()>;
}

impl ReadAt for [u8] {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize, ReadError> {
        let Some(src) = usize::try_from(offset).ok().and_then(|o| self.get(o..)) else {
            return Err(ReadError::new(0, eof()));
        };
        let n = buf.len().min(src.len());
        buf[..n].copy_from_slice(&src[..n]);
        if n < buf.len() {
            return Err(ReadError::new(n, eof()));
        }
        Ok(n)
    }
}

impl<T: ReadAt + ?Sized> ReadAt for &T {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize, ReadError> {
        (**self).read_at(buf, offset)
    }
}

impl<T: ReadAt + ?Sized> ReadAt for std::sync::Arc<T> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize, ReadError> {
        (**self).read_at(buf, offset)
    }
}

impl<T: ReadAt + ?Sized> ReadAt for Box<T> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize, ReadError> {
        (**self).read_at(buf, offset)
    }
}

impl ReadAt for Vec<u8> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize, ReadError> {
        self.as_slice().read_at(buf, offset)
    }
}

/// Reads the whole buffer regardless of the cursor position, which positional
/// reads neither use nor move.
impl<T: AsRef<[u8]>> ReadAt for io::Cursor<T> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize, ReadError> {
        self.get_ref().as_ref().read_at(buf, offset)
    }
}

impl ReadAt for crate::text::Reader<'_> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize, ReadError> {
        let Ok(off) = i64::try_from(offset) else {
            return Err(ReadError::new(0, eof()));
        };
        match crate::text::Reader::read_at(self, buf, off) {
            (n, None) => Ok(n),
            (n, Some(e)) => Err(ReadError::new(n, e)),
        }
    }
}

#[cfg(unix)]
impl ReadAt for std::fs::File {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize, ReadError> {
        use std::os::unix::fs::FileExt;
        positional_read(buf, offset, |b, o| FileExt::read_at(self, b, o))
    }
}

#[cfg(windows)]
impl ReadAt for std::fs::File {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize, ReadError> {
        use std::os::windows::fs::FileExt;
        positional_read(buf, offset, |b, o| FileExt::seek_read(self, b, o))
    }
}

#[cfg(unix)]
impl WriteAt for std::fs::File {
    fn write_at(&mut self, buf: &[u8], offset: u64) -> io::Result<()> {
        use std::os::unix::fs::FileExt;
        positional_write(buf, offset, |b, o| FileExt::write_at(self, b, o))
    }
}

#[cfg(windows)]
impl WriteAt for std::fs::File {
    fn write_at(&mut self, buf: &[u8], offset: u64) -> io::Result<()> {
        use std::os::windows::fs::FileExt;
        positional_write(buf, offset, |b, o| FileExt::seek_write(self, b, o))
    }
}

/// Writes into a fixed buffer: the part that fits is written, and the rest is
/// a short write.
fn write_at_slice(dst: &mut [u8], buf: &[u8], offset: u64) -> io::Result<()> {
    let at = usize::try_from(offset).unwrap_or(usize::MAX).min(dst.len());
    let n = buf.len().min(dst.len() - at);
    dst[at..at + n].copy_from_slice(&buf[..n]);
    if n < buf.len() {
        return Err(Error::ShortWrite.into());
    }
    Ok(())
}

/// Writes into a growable buffer; a gap before `offset` is zero-filled, as
/// `Cursor<Vec<u8>>` does for a write past its end.
fn write_at_vec(dst: &mut Vec<u8>, buf: &[u8], offset: u64) -> io::Result<()> {
    let at = usize::try_from(offset).map_err(|_| io::Error::other("offset too large"))?;
    let end = at
        .checked_add(buf.len())
        .ok_or_else(|| io::Error::other("offset too large"))?;
    if dst.len() < end {
        dst.resize(end, 0);
    }
    dst[at..end].copy_from_slice(buf);
    Ok(())
}

impl WriteAt for io::Cursor<Vec<u8>> {
    fn write_at(&mut self, buf: &[u8], offset: u64) -> io::Result<()> {
        write_at_vec(self.get_mut(), buf, offset)
    }
}

impl WriteAt for io::Cursor<&mut Vec<u8>> {
    fn write_at(&mut self, buf: &[u8], offset: u64) -> io::Result<()> {
        write_at_vec(self.get_mut(), buf, offset)
    }
}

impl WriteAt for io::Cursor<&mut [u8]> {
    fn write_at(&mut self, buf: &[u8], offset: u64) -> io::Result<()> {
        write_at_slice(self.get_mut(), buf, offset)
    }
}

impl WriteAt for io::Cursor<Box<[u8]>> {
    fn write_at(&mut self, buf: &[u8], offset: u64) -> io::Result<()> {
        write_at_slice(self.get_mut(), buf, offset)
    }
}

/// Go's `os.File.ReadAt` loop: reads until `buf` is full, EOF or an error.
#[cfg(any(unix, windows))]
fn positional_read(
    buf: &mut [u8],
    offset: u64,
    mut read: impl FnMut(&mut [u8], u64) -> io::Result<usize>,
) -> Result<usize, ReadError> {
    if offset > i64::MAX as u64 {
        return Err(ReadError::new(0, io::Error::other("negative offset")));
    }
    let mut n = 0;
    while n < buf.len() {
        match read(&mut buf[n..], offset.wrapping_add(n as u64)) {
            Ok(0) => return Err(ReadError::new(n, eof())),
            Ok(m) => n += m,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(ReadError::new(n, e)),
        }
    }
    Ok(n)
}

#[cfg(any(unix, windows))]
fn positional_write(
    buf: &[u8],
    offset: u64,
    mut write: impl FnMut(&[u8], u64) -> io::Result<usize>,
) -> io::Result<()> {
    if offset > i64::MAX as u64 {
        return Err(io::Error::other("negative offset"));
    }
    let mut n = 0;
    while n < buf.len() {
        match write(&buf[n..], offset.wrapping_add(n as u64)) {
            Ok(0) => return Err(Error::ShortWrite.into()),
            Ok(m) => n += m,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

macro_rules! rune_impls {
    ($ty:ty) => {
        impl RuneReader for $ty {
            fn read_rune(&mut self) -> io::Result<(char, usize)> {
                <$ty>::read_rune(self)
            }
        }
        impl RuneScanner for $ty {
            fn unread_rune(&mut self) -> io::Result<()> {
                <$ty>::unread_rune(self)
            }
        }
    };
}
rune_impls!(crate::text::Reader<'_>);
rune_impls!(crate::text::Buffer);

/// The error of [`copy`], [`copy_n`] and [`copy_buffer`]: the failure plus
/// the number of bytes written before it (Go returns both).
#[derive(Debug)]
pub struct CopyError {
    written: u64,
    source: io::Error,
}

impl CopyError {
    /// An error after `written` bytes were written.
    pub fn new(written: u64, source: io::Error) -> Self {
        CopyError { written, source }
    }

    /// The bytes written to the destination before the failure.
    pub fn written(&self) -> u64 {
        self.written
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

impl fmt::Display for CopyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.source, f)
    }
}

impl std::error::Error for CopyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl From<CopyError> for io::Error {
    fn from(e: CopyError) -> io::Error {
        e.source
    }
}

/// The error of [`read_full`] and [`read_at_least`]: the failure plus the
/// number of bytes read before it (Go returns both).
#[derive(Debug)]
pub struct ReadError {
    read: usize,
    source: io::Error,
}

impl ReadError {
    /// An error after `read` bytes were read.
    pub fn new(read: usize, source: io::Error) -> Self {
        ReadError { read, source }
    }

    /// The bytes read into the buffer before the failure.
    pub fn read(&self) -> usize {
        self.read
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

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.source, f)
    }
}

impl std::error::Error for ReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl From<ReadError> for io::Error {
    fn from(e: ReadError) -> io::Error {
        e.source
    }
}

/// Reads from `r` until `buf` holds at least `min` bytes (`io.ReadAtLeast`)
/// and returns the byte count.
///
/// Fails with [`Error::ShortBuffer`] if `buf` is shorter than `min`, with
/// [`Error::Eof`] if nothing was read before EOF and with
/// [`Error::UnexpectedEof`] if EOF came after some but fewer than `min`
/// bytes. `Read::read_exact` is the same loop when the count and the
/// EOF/unexpected-EOF distinction do not matter.
pub fn read_at_least<R: Read + ?Sized>(
    r: &mut R,
    buf: &mut [u8],
    min: usize,
) -> Result<usize, ReadError> {
    if buf.len() < min {
        return Err(ReadError::new(0, Error::ShortBuffer.into()));
    }
    let mut n = 0;
    let mut err = None;
    while n < min && err.is_none() {
        match r.read(&mut buf[n..]) {
            Ok(0) => err = Some(eof()),
            Ok(nn) => n += nn,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => err = Some(e),
        }
    }
    if n >= min {
        return Ok(n);
    }
    let err = match err {
        Some(e) if n > 0 && is_eof(&e) => Error::UnexpectedEof.into(),
        Some(e) => e,
        None => unreachable!("the loop only ends early on an error"),
    };
    Err(ReadError::new(n, err))
}

/// Reads exactly `buf.len()` bytes from `r` (`io.ReadFull`); see
/// [`read_at_least`] for the errors.
pub fn read_full<R: Read + ?Sized>(r: &mut R, buf: &mut [u8]) -> Result<usize, ReadError> {
    let min = buf.len();
    read_at_least(r, buf, min)
}

/// Copies from `src` to `dst` until EOF or an error (`io.Copy`) and returns
/// the bytes written. Unlike `std::io::copy`, a failure reports the bytes
/// written so far and a short write is [`Error::ShortWrite`].
///
/// Unlike Go this never dispatches to `WriterTo`/`ReaderFrom`; the result is
/// the same for conforming implementations.
pub fn copy<W: Write + ?Sized, R: Read + ?Sized>(
    dst: &mut W,
    src: &mut R,
) -> Result<u64, CopyError> {
    copy_with(dst, src, &mut vec![0; 32 * 1024])
}

/// Like [`copy`] but stages the copy through `buf` (`io.CopyBuffer`). An
/// empty `buf` is an error instead of Go's panic.
pub fn copy_buffer<W: Write + ?Sized, R: Read + ?Sized>(
    dst: &mut W,
    src: &mut R,
    buf: &mut [u8],
) -> Result<u64, CopyError> {
    if buf.is_empty() {
        return Err(CopyError::new(
            0,
            io::Error::new(io::ErrorKind::InvalidInput, "empty buffer in CopyBuffer"),
        ));
    }
    copy_with(dst, src, buf)
}

fn copy_with<W: Write + ?Sized, R: Read + ?Sized>(
    dst: &mut W,
    src: &mut R,
    buf: &mut [u8],
) -> Result<u64, CopyError> {
    let mut written = 0u64;
    loop {
        let nr = match src.read(buf) {
            Ok(0) => return Ok(written),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(CopyError::new(written, e)),
        };
        match dst.write(&buf[..nr]) {
            Ok(nw) if nw > nr => {
                return Err(CopyError::new(
                    written,
                    io::Error::other("invalid write result"),
                ));
            }
            Ok(nw) => {
                written += nw as u64;
                if nw != nr {
                    return Err(CopyError::new(written, Error::ShortWrite.into()));
                }
            }
            Err(e) => return Err(CopyError::new(written, e)),
        }
    }
}

/// Copies `n` bytes from `src` to `dst` (`io.CopyN`) and returns the bytes
/// written. Fails with [`Error::Eof`] if `src` ended first.
pub fn copy_n<W: Write + ?Sized, R: Read + ?Sized>(
    dst: &mut W,
    src: &mut R,
    n: u64,
) -> Result<u64, CopyError> {
    let written = match copy(dst, &mut src.take(n)) {
        Ok(w) => w,
        // Like Go, an error after all `n` bytes were written is dropped.
        Err(e) if e.written() == n => return Ok(n),
        Err(e) => return Err(e),
    };
    if written < n {
        // src stopped early; it must have been EOF.
        return Err(CopyError::new(written, eof()));
    }
    Ok(written)
}

/// Duplicates writes to several writers (`io.MultiWriter`).
pub struct MultiWriter<'a> {
    writers: Vec<Box<dyn Write + 'a>>,
}

impl<'a> MultiWriter<'a> {
    /// A writer that writes to all of `writers` (`io.MultiWriter`).
    pub fn new(writers: Vec<Box<dyn Write + 'a>>) -> Self {
        MultiWriter { writers }
    }
}

impl Write for MultiWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for w in &mut self.writers {
            let n = w.write(buf)?;
            if n != buf.len() {
                return Err(Error::ShortWrite.into());
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        for w in &mut self.writers {
            w.flush()?;
        }
        Ok(())
    }
}

/// A reader that writes everything it reads to a writer (`io.TeeReader`).
pub struct TeeReader<R, W> {
    r: R,
    w: W,
}

impl<R: Read, W: Write> TeeReader<R, W> {
    /// A reader that copies what it reads from `r` to `w` (`io.TeeReader`).
    pub fn new(r: R, w: W) -> Self {
        TeeReader { r, w }
    }
}

impl<R: Read, W: Write> Read for TeeReader<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.r.read(buf)?;
        if n > 0 {
            // Like Go, a short write without an error is not an error.
            loop {
                match self.w.write(&buf[..n]) {
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                    Ok(_) => break,
                }
            }
        }
        Ok(n)
    }
}
