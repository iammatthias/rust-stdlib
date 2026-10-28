//! Go `compress/flate`: streaming DEFLATE (RFC 1951) readers and writers.
//!
//! [`Decompressor`] follows Go's reader exactly: it consumes input a byte at a
//! time as needed (so [`CorruptInputError`] offsets and the bytes delivered
//! before an error match Go's), ignores trailing data after the final block and
//! supports preset dictionaries. [`Writer`] implements levels
//! [`NO_COMPRESSION`] through [`BEST_COMPRESSION`], [`DEFAULT_COMPRESSION`] (6)
//! and [`HUFFMAN_ONLY`] as a port of Go's compressor: it makes the same
//! matches, block splits and Huffman tables, so its output is byte-identical
//! to Go's for every level, preset dictionary and `Write`/`Flush` schedule
//! (Go does not promise stable output across releases; this matches Go 1.27).
//! The table-reuse estimate (`estimated_bits`, used at levels 1-9) uses fused multiply-add as Go does on
//! arm64; it was spot-checked equal to amd64 Go on 210 cases.
//!
//! Go's `flate.Reader` interface (`io.Reader` plus `io.ByteReader`) is
//! [`std::io::BufRead`]: a buffered source is read exactly as far as needed, so
//! data after the stream stays available. [`Decompressor::new`] wraps an unbuffered
//! source in a [`BufReader`], which may read past the end of the stream, as Go
//! does when its argument lacks `ReadByte`.
//!
//! Go errors travel as the payload of an [`io::Error`]: [`CorruptInputError`]
//! (kind `InvalidData`), [`InternalError`], `unexpected EOF`
//! (`UnexpectedEof`) and I/O errors from the source, which pass through.
//! `get_ref().and_then(|e| e.downcast_ref::<CorruptInputError>())` recovers the
//! typed value.
use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};

mod bitwriter;
mod deflate;
mod fastenc;
mod huffman;
mod inflate;
mod token;

pub(crate) use inflate::{read_byte, read_full, unexpected_eof, Inflater};

/// Level 0: no compression, only DEFLATE framing (stored blocks).
pub const NO_COMPRESSION: i32 = 0;
/// Level 1: fastest compression.
pub const BEST_SPEED: i32 = 1;
/// Level 9: smallest output.
pub const BEST_COMPRESSION: i32 = 9;
/// Level -1: the default level (6).
pub const DEFAULT_COMPRESSION: i32 = -1;
/// Level -2: Huffman entropy coding only, no match search.
pub const HUFFMAN_ONLY: i32 = -2;

/// Corrupt input detected before the given byte offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorruptInputError(pub i64);

impl fmt::Display for CorruptInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "flate: corrupt input before offset {}", self.0)
    }
}

impl std::error::Error for CorruptInputError {}

/// An error in the flate code itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InternalError(pub String);

impl fmt::Display for InternalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "flate: internal error: {}", self.0)
    }
}

impl std::error::Error for InternalError {}

/// An error encountered while reading input. Deprecated in Go and never
/// returned there; kept for completeness.
#[derive(Debug)]
pub struct ReadError {
    /// Byte offset where the error occurred.
    pub offset: i64,
    /// Error returned by the underlying read.
    pub err: io::Error,
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "flate: read error at offset {}: {}",
            self.offset, self.err
        )
    }
}

impl std::error::Error for ReadError {}

/// An error encountered while writing output. Deprecated in Go and never
/// returned there; kept for completeness.
#[derive(Debug)]
pub struct WriteError {
    /// Byte offset where the error occurred.
    pub offset: i64,
    /// Error returned by the underlying write.
    pub err: io::Error,
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "flate: write error at offset {}: {}",
            self.offset, self.err
        )
    }
}

impl std::error::Error for WriteError {}

/// Switch a reader returned by [`Decompressor::new`] or [`Decompressor::with_dictionary`] to a new
/// source, discarding buffered state (Go's `flate.Resetter`).
pub trait Resetter<R> {
    /// Reset as if newly created with `r` and the preset dictionary `dict`
    /// (empty for none).
    fn reset(&mut self, r: R, dict: &[u8]) -> io::Result<()>;
}

/// End of stream or a failure; Go's `io.EOF` versus other errors.
pub(crate) enum Fail {
    Eof,
    Err(io::Error),
}

impl Fail {
    pub(crate) fn replay(&self) -> Fail {
        match self {
            Fail::Eof => Fail::Eof,
            Fail::Err(e) => Fail::Err(clone_io(e)),
        }
    }

    /// Go's `noEOF`: end of input in the middle of a stream is unexpected.
    pub(crate) fn no_eof(self) -> Fail {
        match self {
            Fail::Eof => Fail::Err(unexpected_eof()),
            other => other,
        }
    }

    /// `Eof` becomes an `UnexpectedEof` error whose text is Go's `EOF`.
    pub(crate) fn to_io(&self) -> io::Error {
        match self {
            Fail::Eof => io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"),
            Fail::Err(e) => clone_io(e),
        }
    }
}

/// Duplicate an error, keeping typed Go payloads downcastable.
pub(crate) fn clone_io(e: &io::Error) -> io::Error {
    if let Some(inner) = e.get_ref() {
        if let Some(c) = inner.downcast_ref::<CorruptInputError>() {
            return io::Error::new(e.kind(), *c);
        }
        if let Some(c) = inner.downcast_ref::<InternalError>() {
            return io::Error::new(e.kind(), c.clone());
        }
        if let Some(c) = inner.downcast_ref::<super::gzip::Error>() {
            return io::Error::new(e.kind(), *c);
        }
        if let Some(c) = inner.downcast_ref::<super::zlib::Error>() {
            return io::Error::new(e.kind(), *c);
        }
    }
    io::Error::new(e.kind(), e.to_string())
}

/// Decompressing reader over a buffered source (Go's `NewReader` result).
pub struct Decompressor<R> {
    inner: R,
    f: Inflater,
}

impl<R> Decompressor<R> {
    /// The underlying source.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// The underlying source, mutably.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Consume the decompressor and return the source.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Returns the stream's error, if any; reaching the end is not an error.
    pub fn close(&mut self) -> io::Result<()> {
        self.f.close()
    }
}

impl<R: BufRead> Read for Decompressor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        match self.f.read_stream(&mut self.inner, buf) {
            (0, Some(Fail::Eof)) => Ok(0),
            (0, Some(Fail::Err(e))) => Err(e),
            (n, _) => Ok(n),
        }
    }
}

impl<R: BufRead> Resetter<R> for Decompressor<R> {
    fn reset(&mut self, r: R, dict: &[u8]) -> io::Result<()> {
        self.inner = r;
        self.f.reset(dict);
        Ok(())
    }
}

impl<R: Read> Decompressor<BufReader<R>> {
    /// Reader of the uncompressed form of `r`. `r` is buffered internally and
    /// may be read past the end of the stream; use
    /// [`Decompressor::from_buf_read`] to avoid it.
    pub fn new(r: R) -> Self {
        Decompressor::from_buf_read(BufReader::new(r))
    }

    /// Like [`Decompressor::new`] with a preset dictionary.
    pub fn with_dictionary(r: R, dict: &[u8]) -> Self {
        Decompressor::from_buf_read_with_dictionary(BufReader::new(r), dict)
    }
}

impl<R: BufRead> Decompressor<R> {
    /// Reader over an already buffered source, consumed only as far as the
    /// stream extends (Go's behaviour for sources implementing `io.ByteReader`).
    pub fn from_buf_read(r: R) -> Self {
        Decompressor::from_buf_read_with_dictionary(r, &[])
    }

    /// [`Decompressor::with_dictionary`] over an already buffered source.
    pub fn from_buf_read_with_dictionary(r: R, dict: &[u8]) -> Self {
        Decompressor {
            inner: r,
            f: Inflater::new(dict),
        }
    }
}

fn closed_writer() -> io::Error {
    io::Error::other("flate: closed writer")
}

/// Compressing writer (Go's `flate.Writer`).
///
/// [`Writer::flush`] is a sync flush: all data written so far can be decoded
/// from the output. [`Writer::close`] writes the final block; the output is
/// incomplete without it.
pub struct Writer<W: Write> {
    w: W,
    d: deflate::Compressor,
    dict: Vec<u8>,
    err: Option<io::Error>,
    closed: bool,
}

impl<W: Write> Writer<W> {
    /// Writer at `level` (-2 to 9). An invalid level returns an error.
    pub fn new(w: W, level: i32) -> io::Result<Self> {
        Self::with_dictionary(w, level, &[])
    }

    /// Like [`Writer::new`], behaving as if `dict` had been written without
    /// producing output. Output decodes only with the same dictionary
    /// ([`Decompressor::with_dictionary`]). Levels 0 and -2 ignore the
    /// dictionary.
    pub fn with_dictionary(w: W, level: i32, dict: &[u8]) -> io::Result<Self> {
        if !(HUFFMAN_ONLY..=BEST_COMPRESSION).contains(&level) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("flate: invalid compression level {level}: want value in range [-2, 9]"),
            ));
        }
        let mut d = deflate::Compressor::new(level);
        d.fill_window(dict);
        Ok(Writer {
            w,
            d,
            dict: dict.to_vec(),
            err: None,
            closed: false,
        })
    }

    /// The underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.w
    }

    /// The underlying writer, mutably. Writing to it directly interleaves with
    /// compressed output.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.w
    }

    /// Consume the writer and return the underlying writer without flushing.
    pub fn into_inner(self) -> W {
        self.w
    }

    fn fail<T>(&mut self, e: io::Error) -> io::Result<T> {
        self.err = Some(clone_io(&e));
        Err(e)
    }

    /// Sync flush (zlib's `Z_SYNC_FLUSH`): pending data is compressed and
    /// written, followed by an empty stored block that byte-aligns the stream.
    /// Flushing with nothing pending still emits that marker.
    pub fn flush(&mut self) -> io::Result<()> {
        if let Some(e) = &self.err {
            return Err(clone_io(e));
        }
        match self.d.sync_flush(&mut self.w) {
            Ok(()) => Ok(()),
            Err(e) => self.fail(e),
        }
    }

    /// Flush pending data and write the final block. Closing twice is fine;
    /// writing after Close fails with `flate: closed writer`.
    pub fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        if let Some(e) = &self.err {
            return Err(clone_io(e));
        }
        if let Err(e) = self.d.finish(&mut self.w) {
            return self.fail(e);
        }
        self.closed = true;
        self.err = Some(closed_writer());
        Ok(())
    }

    /// Discard state and make the writer equivalent to a new one over `w` with
    /// the same level and dictionary.
    pub fn reset(&mut self, w: W) {
        self.w = w;
        self.d.reset();
        self.err = None;
        self.closed = false;
        self.d.fill_window(&self.dict);
    }
}

impl<W: Write> Write for Writer<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(e) = &self.err {
            return Err(clone_io(e));
        }
        match self.d.write(&mut self.w, buf) {
            Ok(()) => Ok(buf.len()),
            Err(e) => self.fail(e),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Writer::flush(self)
    }
}
