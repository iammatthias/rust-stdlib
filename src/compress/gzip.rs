//! Go `compress/gzip`: RFC 1952 gzip readers and writers.
//!
//! [`Reader`] verifies the header CRC, the trailing CRC-32 and size, and by
//! default reads concatenated members as one stream (see
//! [`Reader::multistream`]); only the first member's [`Header`] is reported.
//! [`Writer`] writes the header on the first `write`, `flush` or `close`.
//!
//! Go's errors travel as the payload of an [`io::Error`] of kind `InvalidData`:
//! compare with `get_ref().and_then(|e| e.downcast_ref::<Error>())` against
//! [`ERR_CHECKSUM`] and [`ERR_HEADER`]. A stream that ends cleanly where Go
//! returns `io.EOF` from a constructor surfaces as an `UnexpectedEof` error
//! whose text is `EOF`.
use super::flate::{self, clone_io, read_byte, read_full, Fail, Inflater};
use crate::hash::crc32::Crc32;
use crate::time::DateTime;
use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};

pub use super::flate::{
    BEST_COMPRESSION, BEST_SPEED, DEFAULT_COMPRESSION, HUFFMAN_ONLY, NO_COMPRESSION,
};

const GZIP_ID1: u8 = 0x1f;
const GZIP_ID2: u8 = 0x8b;
const GZIP_DEFLATE: u8 = 8;
const FLAG_HDR_CRC: u8 = 1 << 1;
const FLAG_EXTRA: u8 = 1 << 2;
const FLAG_NAME: u8 = 1 << 3;
const FLAG_COMMENT: u8 = 1 << 4;

/// A gzip-specific error value (Go's `ErrChecksum` and `ErrHeader`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(&'static str);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Error {}

/// The CRC-32 or size in the trailer does not match the data.
pub const ERR_CHECKSUM: Error = Error("gzip: invalid checksum");
/// The header is invalid.
pub const ERR_HEADER: Error = Error("gzip: invalid header");

fn err_value(e: Error) -> Fail {
    Fail::Err(io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Optional gzip header fields. Strings are Latin-1 on the wire (ISO 8859-1)
/// and must not contain NUL when writing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    /// Comment.
    pub comment: String,
    /// "Extra data"; `Some(empty)` still sets the extra-field flag.
    pub extra: Option<Vec<u8>>,
    /// Modification time; `None` is Go's zero time (no timestamp).
    pub mod_time: Option<DateTime>,
    /// File name.
    pub name: String,
    /// Operating system type.
    pub os: u8,
}

/// Decompressing reader (Go's `gzip.Reader`).
pub struct Reader<R> {
    /// Header of the first member, valid after construction or `reset`.
    pub header: Header,
    r: R,
    f: Inflater,
    digest: Crc32,
    size: u32,
    buf: [u8; 512],
    err: Option<Fail>,
    multistream: bool,
}

impl<R: Read> Reader<BufReader<R>> {
    /// Reader for gzip data in `r`, which is buffered internally and may be read
    /// past the end of the stream. Reads and verifies the header immediately.
    pub fn new(r: R) -> io::Result<Self> {
        Reader::from_buf_read(BufReader::new(r))
    }
}

impl<R: BufRead> Reader<R> {
    /// [`Reader::new`] over an already buffered source, consumed only as far as
    /// the stream extends (Go's behaviour for sources implementing
    /// `io.ByteReader`).
    pub fn from_buf_read(r: R) -> io::Result<Self> {
        let mut z = Reader {
            header: Header::default(),
            r,
            f: Inflater::new(&[]),
            digest: Crc32::ieee(),
            size: 0,
            buf: [0; 512],
            err: None,
            multistream: true,
        };
        z.start()?;
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

    /// Enable (the default) or disable reading of concatenated members. When
    /// disabled the reader stops after one member, leaving the source
    /// positioned for the caller (use a buffered source and call `reset`).
    pub fn multistream(&mut self, ok: bool) {
        self.multistream = ok;
    }

    /// Returns the decompressor's error, if any; reaching the end is not one.
    pub fn close(&mut self) -> io::Result<()> {
        self.f.close()
    }
}

impl<R: BufRead> Reader<R> {
    /// Discard state and start reading a new gzip stream from `r`.
    pub fn reset(&mut self, r: R) -> io::Result<()> {
        self.r = r;
        self.size = 0;
        self.multistream = true;
        self.err = None;
        self.start()
    }

    fn start(&mut self) -> io::Result<()> {
        match self.read_header() {
            Ok(header) => {
                self.header = header;
                Ok(())
            }
            Err(e) => {
                self.header = Header::default();
                let io_err = e.to_io();
                self.err = Some(e);
                Err(io_err)
            }
        }
    }

    fn read_string(&mut self) -> Result<String, Fail> {
        let mut need_conv = false;
        for i in 0.. {
            if i >= self.buf.len() {
                return Err(err_value(ERR_HEADER));
            }
            let byte = match read_byte(&mut self.r) {
                Ok(Some(b)) => b,
                Ok(None) => return Err(Fail::Eof),
                Err(e) => return Err(Fail::Err(e)),
            };
            self.buf[i] = byte;
            if byte > 0x7f {
                need_conv = true;
            }
            if byte == 0 {
                self.digest.update(&self.buf[..=i]);
                let raw = &self.buf[..i];
                return Ok(if need_conv {
                    raw.iter().map(|&b| char::from(b)).collect()
                } else {
                    String::from_utf8_lossy(raw).into_owned()
                });
            }
        }
        unreachable!("loop returns")
    }

    fn read_exact_go(&mut self, n: usize) -> Result<(), Fail> {
        let mut tmp = [0u8; 10];
        let (_, err) = read_full(&mut self.r, &mut tmp[..n]);
        match err {
            Some(e) => Err(e),
            None => {
                self.buf[..n].copy_from_slice(&tmp[..n]);
                Ok(())
            }
        }
    }

    fn read_header(&mut self) -> Result<Header, Fail> {
        let mut hdr = Header::default();
        self.read_exact_go(10)?;
        if self.buf[0] != GZIP_ID1 || self.buf[1] != GZIP_ID2 || self.buf[2] != GZIP_DEFLATE {
            return Err(err_value(ERR_HEADER));
        }
        let flg = self.buf[3];
        let t = i64::from(u32::from_le_bytes([
            self.buf[4],
            self.buf[5],
            self.buf[6],
            self.buf[7],
        ]));
        if t > 0 {
            hdr.mod_time = DateTime::from_unix(t, 0, 0).ok();
        }
        hdr.os = self.buf[9];
        self.digest.reset();
        let first = self.buf[..10].to_vec();
        self.digest.update(&first);

        if flg & FLAG_EXTRA != 0 {
            self.read_exact_go(2).map_err(Fail::no_eof)?;
            let len_bytes = [self.buf[0], self.buf[1]];
            self.digest.update(&len_bytes);
            let mut data = vec![0u8; usize::from(u16::from_le_bytes(len_bytes))];
            if let (_, Some(e)) = read_full(&mut self.r, &mut data) {
                return Err(e.no_eof());
            }
            self.digest.update(&data);
            hdr.extra = Some(data);
        }
        if flg & FLAG_NAME != 0 {
            hdr.name = self.read_string().map_err(Fail::no_eof)?;
        }
        if flg & FLAG_COMMENT != 0 {
            hdr.comment = self.read_string().map_err(Fail::no_eof)?;
        }
        if flg & FLAG_HDR_CRC != 0 {
            self.read_exact_go(2).map_err(Fail::no_eof)?;
            let digest = u16::from_le_bytes([self.buf[0], self.buf[1]]);
            if digest != self.digest.sum32() as u16 {
                return Err(err_value(ERR_HEADER));
            }
        }
        self.digest.reset();
        self.f.reset(&[]);
        Ok(hdr)
    }

    fn finish(&mut self, n: usize, err: Fail) -> io::Result<usize> {
        let result = match (&err, n) {
            (_, 1..) => Ok(n),
            (Fail::Eof, _) => Ok(0),
            (Fail::Err(e), _) => Err(clone_io(e)),
        };
        self.err = Some(err);
        result
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
        let mut n = 0;
        while n == 0 {
            let (m, err) = self.f.read_stream(&mut self.r, p);
            n = m;
            self.digest.update(&p[..n]);
            self.size = self.size.wrapping_add(n as u32);
            match err {
                None => return Ok(n),
                Some(Fail::Eof) => {}
                Some(e) => return self.finish(n, e),
            }
            let mut trailer = [0u8; 8];
            if let (_, Some(e)) = read_full(&mut self.r, &mut trailer) {
                return self.finish(n, e.no_eof());
            }
            let digest = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
            let size = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
            if digest != self.digest.sum32() || size != self.size {
                return self.finish(n, err_value(ERR_CHECKSUM));
            }
            self.digest.reset();
            self.size = 0;
            if !self.multistream {
                return self.finish(n, Fail::Eof);
            }
            if let Err(e) = self.read_header() {
                return self.finish(n, e);
            }
        }
        Ok(n)
    }
}

/// Writer for the gzip format (Go's `gzip.Writer`).
pub struct Writer<W: Write> {
    /// Header written at the first `write`, `flush` or `close`; set it before.
    pub header: Header,
    level: i32,
    wrote_header: bool,
    closed: bool,
    compressor: flate::Writer<W>,
    digest: Crc32,
    size: u32,
    err: Option<io::Error>,
}

fn latin1(s: &str) -> io::Result<Vec<u8>> {
    s.chars()
        .map(|c| {
            u8::try_from(u32::from(c))
                .ok()
                .filter(|&b| b != 0)
                .ok_or_else(|| io::Error::other("gzip.Write: non-Latin-1 header string"))
        })
        .collect()
}

impl<W: Write> Writer<W> {
    /// Writer at the default compression level.
    pub fn new(w: W) -> Self {
        match Self::with_level(w, DEFAULT_COMPRESSION) {
            Ok(z) => z,
            Err(_) => unreachable!("the default level is valid"),
        }
    }

    /// Writer at `level` (-2 to 9); other levels return an error.
    pub fn with_level(w: W, level: i32) -> io::Result<Self> {
        if !(HUFFMAN_ONLY..=BEST_COMPRESSION).contains(&level) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("gzip: invalid compression level: {level}"),
            ));
        }
        Ok(Writer {
            header: Header {
                os: 255,
                ..Header::default()
            },
            level,
            wrote_header: false,
            closed: false,
            compressor: flate::Writer::new(w, level)?,
            digest: Crc32::ieee(),
            size: 0,
            err: None,
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

    /// Discard state and make the writer equivalent to a new one over `w` at
    /// the same level; the header is reset to its defaults.
    pub fn reset(&mut self, w: W) {
        self.compressor.reset(w);
        self.header = Header {
            os: 255,
            ..Header::default()
        };
        self.wrote_header = false;
        self.closed = false;
        self.digest.reset();
        self.size = 0;
        self.err = None;
    }

    fn set_err<T>(&mut self, e: io::Error) -> io::Result<T> {
        self.err = Some(clone_io(&e));
        Err(e)
    }

    fn write_header(&mut self) -> io::Result<()> {
        self.wrote_header = true;
        let mut buf = [0u8; 10];
        buf[0] = GZIP_ID1;
        buf[1] = GZIP_ID2;
        buf[2] = GZIP_DEFLATE;
        if self.header.extra.is_some() {
            buf[3] |= FLAG_EXTRA;
        }
        if !self.header.name.is_empty() {
            buf[3] |= FLAG_NAME;
        }
        if !self.header.comment.is_empty() {
            buf[3] |= FLAG_COMMENT;
        }
        if let Some(t) = &self.header.mod_time {
            if t.unix_seconds() > 0 {
                buf[4..8].copy_from_slice(&(t.unix_seconds() as u32).to_le_bytes());
            }
        }
        if self.level == BEST_COMPRESSION {
            buf[8] = 2;
        } else if self.level == BEST_SPEED {
            buf[8] = 4;
        }
        buf[9] = self.header.os;
        let w = self.compressor.get_mut();
        w.write_all(&buf)?;
        if let Some(extra) = &self.header.extra {
            if extra.len() > 0xffff {
                return Err(io::Error::other("gzip.Write: Extra data is too large"));
            }
            w.write_all(&(extra.len() as u16).to_le_bytes())?;
            w.write_all(extra)?;
        }
        for s in [&self.header.name, &self.header.comment] {
            if s.is_empty() {
                continue;
            }
            let mut bytes = latin1(s)?;
            bytes.push(0);
            w.write_all(&bytes)?;
        }
        Ok(())
    }

    fn ensure_header(&mut self) -> io::Result<()> {
        if let Some(e) = &self.err {
            return Err(clone_io(e));
        }
        if !self.wrote_header {
            if let Err(e) = self.write_header() {
                return self.set_err(e);
            }
        }
        Ok(())
    }

    /// Flush pending data as a sync flush; the stream is not finished.
    pub fn flush(&mut self) -> io::Result<()> {
        if let Some(e) = &self.err {
            return Err(clone_io(e));
        }
        if self.closed {
            return Ok(());
        }
        if !self.wrote_header {
            self.ensure_header()?;
        }
        match self.compressor.flush() {
            Ok(()) => Ok(()),
            Err(e) => self.set_err(e),
        }
    }

    /// Write the final block and trailer; it does not close the underlying
    /// writer. Closing twice is fine.
    pub fn close(&mut self) -> io::Result<()> {
        if let Some(e) = &self.err {
            return Err(clone_io(e));
        }
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        if !self.wrote_header {
            self.ensure_header()?;
        }
        if let Err(e) = self.compressor.close() {
            return self.set_err(e);
        }
        let mut trailer = [0u8; 8];
        trailer[..4].copy_from_slice(&self.digest.sum32().to_le_bytes());
        trailer[4..].copy_from_slice(&self.size.to_le_bytes());
        match self.compressor.get_mut().write_all(&trailer) {
            Ok(()) => Ok(()),
            Err(e) => self.set_err(e),
        }
    }
}

impl<W: Write> Write for Writer<W> {
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        self.ensure_header()?;
        self.size = self.size.wrapping_add(p.len() as u32);
        self.digest.update(p);
        match self.compressor.write(p) {
            Ok(n) => Ok(n),
            Err(e) => self.set_err(e),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Writer::flush(self)
    }
}
