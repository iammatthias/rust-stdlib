//! Go `compress/zlib`: RFC 1950 zlib readers and writers.
//!
//! [`Reader`] checks the header, the optional preset-dictionary identifier and
//! the trailing Adler-32. [`Writer`] writes the header on the first `write`,
//! `flush` or `close` and supports preset dictionaries.
//!
//! Go's errors travel as the payload of an [`io::Error`] of kind `InvalidData`:
//! compare with `get_ref().and_then(|e| e.downcast_ref::<Error>())` against
//! [`ERR_CHECKSUM`], [`ERR_DICTIONARY`] and [`ERR_HEADER`].
use super::flate::{self, clone_io, read_full, unexpected_eof, Fail, Inflater};
use crate::hash::adler32::{self, Adler32};
use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};

pub use super::flate::{
    Resetter, BEST_COMPRESSION, BEST_SPEED, DEFAULT_COMPRESSION, HUFFMAN_ONLY, NO_COMPRESSION,
};

const ZLIB_DEFLATE: u8 = 8;
const ZLIB_MAX_WINDOW: u8 = 7;

/// A zlib-specific error value (Go's `ErrChecksum`, `ErrDictionary`, `ErrHeader`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(&'static str);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Error {}

/// The Adler-32 trailer does not match the data.
pub const ERR_CHECKSUM: Error = Error("zlib: invalid checksum");
/// The preset dictionary does not match the stream's dictionary identifier.
pub const ERR_DICTIONARY: Error = Error("zlib: invalid dictionary");
/// The header is invalid.
pub const ERR_HEADER: Error = Error("zlib: invalid header");

fn err_value(e: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

/// Decompressing reader (Go's zlib `reader`).
pub struct Reader<R> {
    r: R,
    f: Option<Inflater>,
    digest: Adler32,
    err: Option<Fail>,
}

impl<R: Read> Reader<BufReader<R>> {
    /// Reader for zlib data in `r`, which is buffered internally and may be read
    /// past the end of the stream. Reads the header immediately.
    pub fn new(r: R) -> io::Result<Self> {
        Reader::with_dictionary(r, &[])
    }

    /// [`Reader::new`] with a preset dictionary for streams that require one.
    pub fn with_dictionary(r: R, dict: &[u8]) -> io::Result<Self> {
        Reader::from_buf_read_with_dictionary(BufReader::new(r), dict)
    }
}

impl<R: BufRead> Reader<R> {
    /// [`Reader::new`] over an already buffered source, consumed only as far as
    /// the stream extends.
    pub fn from_buf_read(r: R) -> io::Result<Self> {
        Reader::from_buf_read_with_dictionary(r, &[])
    }

    /// [`Reader::with_dictionary`] over an already buffered source.
    pub fn from_buf_read_with_dictionary(r: R, dict: &[u8]) -> io::Result<Self> {
        let mut z = Reader {
            r,
            f: None,
            digest: Adler32::new(),
            err: None,
        };
        z.start(dict)?;
        Ok(z)
    }
}

impl<R> Reader<R> {
    /// The underlying source.
    pub fn get_ref(&self) -> &R {
        &self.r
    }

    /// The underlying source, mutably.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.r
    }

    /// Consume the reader and return the source.
    pub fn into_inner(self) -> R {
        self.r
    }
}

impl<R: BufRead> Reader<R> {
    fn start(&mut self, dict: &[u8]) -> io::Result<()> {
        self.err = None;
        match self.read_header(dict) {
            Ok(()) => Ok(()),
            Err(e) => {
                let io_err = e.to_io();
                self.err = Some(e);
                Err(io_err)
            }
        }
    }

    fn read_header(&mut self, dict: &[u8]) -> Result<(), Fail> {
        let mut scratch = [0u8; 4];
        if let (_, Some(e)) = read_full(&mut self.r, &mut scratch[..2]) {
            return Err(e.no_eof());
        }
        let h = u16::from_be_bytes([scratch[0], scratch[1]]);
        if scratch[0] & 0x0f != ZLIB_DEFLATE || scratch[0] >> 4 > ZLIB_MAX_WINDOW || h % 31 != 0 {
            return Err(Fail::Err(err_value(ERR_HEADER)));
        }
        let have_dict = scratch[1] & 0x20 != 0;
        if have_dict {
            if let (_, Some(e)) = read_full(&mut self.r, &mut scratch) {
                return Err(e.no_eof());
            }
            if u32::from_be_bytes(scratch) != adler32::checksum(dict) {
                return Err(Fail::Err(err_value(ERR_DICTIONARY)));
            }
        }
        match &mut self.f {
            None => self.f = Some(Inflater::new(if have_dict { dict } else { &[] })),
            Some(f) => f.reset(dict),
        }
        self.digest = Adler32::new();
        Ok(())
    }

    /// The error that ended the last `read` together with the bytes it
    /// returned. Go's `Read` reports `(n, err)` at once; `io::Read` cannot.
    pub(crate) fn pending_error(&self) -> Option<io::Error> {
        match &self.err {
            Some(Fail::Err(e)) => Some(clone_io(e)),
            _ => None,
        }
    }

    /// Returns the decompressor's error, if any. As in Go, closing a stream
    /// that is still being read clears the reader's own sticky error.
    pub fn close(&mut self) -> io::Result<()> {
        if let Some(Fail::Err(e)) = &self.err {
            return Err(clone_io(e));
        }
        let result = match &self.f {
            Some(f) => f.close(),
            None => Ok(()),
        };
        self.err = result.as_ref().err().map(|e| Fail::Err(clone_io(e)));
        result
    }
}

impl<R: BufRead> Resetter<R> for Reader<R> {
    fn reset(&mut self, r: R, dict: &[u8]) -> io::Result<()> {
        self.r = r;
        self.start(dict)
    }
}

impl<R: BufRead> Read for Reader<R> {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        match &self.err {
            Some(Fail::Eof) => return Ok(0),
            Some(Fail::Err(e)) => return Err(clone_io(e)),
            None => {}
        }
        if p.is_empty() {
            return Ok(0);
        }
        let Some(f) = self.f.as_mut() else {
            return Err(unexpected_eof());
        };
        let (n, err) = f.read_stream(&mut self.r, p);
        self.digest.update(&p[..n]);
        let finish = |z: &mut Self, err: Fail| {
            let result = match (&err, n) {
                (_, 1..) => Ok(n),
                (Fail::Eof, _) => Ok(0),
                (Fail::Err(e), _) => Err(clone_io(e)),
            };
            z.err = Some(err);
            result
        };
        match err {
            None => return Ok(n),
            Some(Fail::Eof) => {}
            Some(e) => return finish(self, e),
        }
        let mut trailer = [0u8; 4];
        if let (_, Some(e)) = read_full(&mut self.r, &mut trailer) {
            return finish(self, e.no_eof());
        }
        if u32::from_be_bytes(trailer) != self.digest.sum32() {
            return finish(self, Fail::Err(err_value(ERR_CHECKSUM)));
        }
        finish(self, Fail::Eof)
    }
}

/// Writer for the zlib format (Go's `zlib.Writer`).
pub struct Writer<W: Write> {
    level: i32,
    dict: Option<Vec<u8>>,
    compressor: flate::Writer<W>,
    digest: Adler32,
    err: Option<io::Error>,
    wrote_header: bool,
}

impl<W: Write> Writer<W> {
    /// Writer at the default compression level.
    pub fn new(w: W) -> Self {
        match Self::with_level_and_dictionary(w, DEFAULT_COMPRESSION, None) {
            Ok(z) => z,
            Err(_) => unreachable!("the default level is valid"),
        }
    }

    /// Writer at `level` (-2 to 9); other levels return an error.
    pub fn with_level(w: W, level: i32) -> io::Result<Self> {
        Self::with_level_and_dictionary(w, level, None)
    }

    /// Writer at `level` with a preset dictionary. `Some` (even empty) sets the
    /// dictionary flag and identifier in the header, as a non-nil slice does in
    /// Go. The stream decodes only with the same dictionary.
    pub fn with_level_and_dictionary(w: W, level: i32, dict: Option<&[u8]>) -> io::Result<Self> {
        if !(HUFFMAN_ONLY..=BEST_COMPRESSION).contains(&level) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("zlib: invalid compression level: {level}"),
            ));
        }
        Ok(Writer {
            level,
            dict: dict.map(<[u8]>::to_vec),
            compressor: flate::Writer::with_dictionary(w, level, dict.unwrap_or(&[]))?,
            digest: Adler32::new(),
            err: None,
            wrote_header: false,
        })
    }

    /// The underlying writer.
    pub fn get_ref(&self) -> &W {
        self.compressor.get_ref()
    }

    /// The underlying writer, mutably.
    pub fn get_mut(&mut self) -> &mut W {
        self.compressor.get_mut()
    }

    /// Consume the writer and return the underlying writer without flushing.
    pub fn into_inner(self) -> W {
        self.compressor.into_inner()
    }

    /// Discard state and make the writer equivalent to a new one over `w` with
    /// the same level and dictionary.
    pub fn reset(&mut self, w: W) {
        self.compressor.reset(w);
        self.digest = Adler32::new();
        self.err = None;
        self.wrote_header = false;
    }

    fn write_header(&mut self) -> io::Result<()> {
        self.wrote_header = true;
        let flevel: u8 = match self.level {
            -2 | 0 | 1 => 0,
            2..=5 => 1,
            -1 | 6 => 2,
            _ => 3,
        };
        let mut header = [0x78, flevel << 6];
        if self.dict.is_some() {
            header[1] |= 1 << 5;
        }
        let h = u16::from_be_bytes(header);
        header[1] = header[1].wrapping_add((31 - h % 31) as u8);
        let w = self.compressor.get_mut();
        w.write_all(&header)?;
        if let Some(dict) = &self.dict {
            w.write_all(&adler32::checksum(dict).to_be_bytes())?;
        }
        Ok(())
    }

    fn ensure_header(&mut self) -> io::Result<()> {
        if !self.wrote_header {
            if let Err(e) = self.write_header() {
                self.err = Some(clone_io(&e));
            }
        }
        match &self.err {
            Some(e) => Err(clone_io(e)),
            None => Ok(()),
        }
    }

    fn keep<T>(&mut self, result: io::Result<T>) -> io::Result<T> {
        if let Err(e) = &result {
            self.err = Some(clone_io(e));
        }
        result
    }

    /// Flush pending data as a sync flush; the stream is not finished.
    pub fn flush(&mut self) -> io::Result<()> {
        self.ensure_header()?;
        let result = self.compressor.flush();
        self.keep(result)
    }

    /// Write the final block and the Adler-32 trailer; it does not close the
    /// underlying writer.
    pub fn close(&mut self) -> io::Result<()> {
        self.ensure_header()?;
        let result = self.compressor.close();
        self.keep(result)?;
        let trailer = self.digest.sum32().to_be_bytes();
        let result = self.compressor.get_mut().write_all(&trailer);
        self.keep(result)
    }
}

impl<W: Write> Write for Writer<W> {
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        self.ensure_header()?;
        if p.is_empty() {
            return Ok(0);
        }
        let result = self.compressor.write(p);
        let n = self.keep(result)?;
        self.digest.update(p);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Writer::flush(self)
    }
}
