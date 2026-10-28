//! `bytes.Reader` and `strings.Reader`: a read-only, seekable reader over a
//! byte string.

use crate::io::eof;
use crate::unicode::chars::decode_rune;
use std::io::{self, BufRead, Read, Seek, SeekFrom, Write};

/// Implements `Read`, `Seek` and `BufRead` over a byte string (`&[u8]` or
/// `&str`), plus Go's `ReadAt`, `ReadByte`, `ReadRune`, `UnreadByte`,
/// `UnreadRune` and `WriteTo` (`bytes.Reader`, `strings.Reader`). It is
/// `std::io::Cursor` plus Go's unread rules, which std lacks.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    s: &'a [u8],
    i: i64,
    prev_rune: i64,
}

impl<'a> Reader<'a> {
    /// Returns a reader reading from `b`.
    pub fn new<S: AsRef<[u8]> + ?Sized>(b: &'a S) -> Self {
        Reader {
            s: b.as_ref(),
            i: 0,
            prev_rune: -1,
        }
    }

    /// Resets the reader to read from `b` (`Reader.Reset`).
    pub fn reset<S: AsRef<[u8]> + ?Sized>(&mut self, b: &'a S) {
        *self = Reader::new(b);
    }

    /// Returns the number of unread bytes (`Reader.Len`).
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        if self.i >= self.s.len() as i64 {
            0
        } else {
            (self.s.len() as i64 - self.i) as usize
        }
    }

    /// Returns the original length of the underlying slice (`Reader.Size`).
    pub fn size(&self) -> i64 {
        self.s.len() as i64
    }

    /// Reads at absolute offset `off` without moving the position
    /// (`Reader.ReadAt`). Returns the byte count and, like Go, an EOF error
    /// when fewer than `b.len()` bytes were available.
    pub fn read_at(&self, b: &mut [u8], off: i64) -> (usize, Option<io::Error>) {
        if off < 0 {
            return (
                0,
                Some(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "bytes.Reader.ReadAt: negative offset",
                )),
            );
        }
        if off >= self.s.len() as i64 {
            return (0, Some(eof()));
        }
        let src = &self.s[off as usize..];
        let n = b.len().min(src.len());
        b[..n].copy_from_slice(&src[..n]);
        (n, (n < b.len()).then(eof))
    }

    /// Reads one byte (`Reader.ReadByte`).
    pub fn read_byte(&mut self) -> io::Result<u8> {
        self.prev_rune = -1;
        if self.i >= self.s.len() as i64 {
            return Err(eof());
        }
        let b = self.s[self.i as usize];
        self.i += 1;
        Ok(b)
    }

    /// Unreads the last byte (`Reader.UnreadByte`).
    pub fn unread_byte(&mut self) -> io::Result<()> {
        if self.i <= 0 {
            return Err(io::Error::other(
                "bytes.Reader.UnreadByte: at beginning of slice",
            ));
        }
        self.prev_rune = -1;
        self.i -= 1;
        Ok(())
    }

    /// Reads one rune and its width (`Reader.ReadRune`).
    pub fn read_rune(&mut self) -> io::Result<(char, usize)> {
        if self.i >= self.s.len() as i64 {
            self.prev_rune = -1;
            return Err(eof());
        }
        self.prev_rune = self.i;
        let (ch, size) = decode_rune(&self.s[self.i as usize..]);
        self.i += size as i64;
        Ok((ch, size))
    }

    /// Unreads the last rune (`Reader.UnreadRune`).
    pub fn unread_rune(&mut self) -> io::Result<()> {
        if self.i <= 0 {
            return Err(io::Error::other(
                "bytes.Reader.UnreadRune: at beginning of slice",
            ));
        }
        if self.prev_rune < 0 {
            return Err(io::Error::other(
                "bytes.Reader.UnreadRune: previous operation was not ReadRune",
            ));
        }
        self.i = self.prev_rune;
        self.prev_rune = -1;
        Ok(())
    }

    /// Writes the unread bytes to `w` with a single write (`Reader.WriteTo`).
    pub fn write_to<W: Write + ?Sized>(&mut self, w: &mut W) -> io::Result<u64> {
        self.prev_rune = -1;
        if self.i >= self.s.len() as i64 {
            return Ok(0);
        }
        let b = &self.s[self.i as usize..];
        let m = w.write(b)?;
        if m > b.len() {
            panic!("bytes.Reader.WriteTo: invalid Write count");
        }
        self.i += m as i64;
        if m != b.len() {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "short write"));
        }
        Ok(m as u64)
    }
}

impl Read for Reader<'_> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        if self.i >= self.s.len() as i64 {
            return Ok(0);
        }
        self.prev_rune = -1;
        let src = &self.s[self.i as usize..];
        let n = b.len().min(src.len());
        b[..n].copy_from_slice(&src[..n]);
        self.i += n as i64;
        Ok(n)
    }
}

impl Seek for Reader<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.prev_rune = -1;
        let abs = match pos {
            SeekFrom::Start(o) => i64::try_from(o).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "bytes.Reader.Seek: offset overflow",
                )
            })?,
            SeekFrom::Current(o) => self.i.wrapping_add(o),
            SeekFrom::End(o) => (self.s.len() as i64).wrapping_add(o),
        };
        if abs < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bytes.Reader.Seek: negative position",
            ));
        }
        self.i = abs;
        Ok(abs as u64)
    }
}

impl BufRead for Reader<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.i >= self.s.len() as i64 {
            return Ok(&[]);
        }
        Ok(&self.s[self.i as usize..])
    }

    fn consume(&mut self, amt: usize) {
        self.prev_rune = -1;
        self.i += amt.min(self.len()) as i64;
    }
}
