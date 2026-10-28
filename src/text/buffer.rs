//! `bytes.Buffer`: a variable-sized byte buffer with Go's read/unread rules and
//! capacity growth.

use super::size_classes::BYTES_SIZE_CLASSES;
use crate::io::eof;
use crate::unicode::chars::decode_rune;
use std::fmt;
use std::io::{self, BufRead, Read, Write};

/// The smallest buffer growth [`Buffer::read_from`] guarantees (`bytes.MinRead`).
pub const MIN_READ: usize = 512;

/// The panic payload used when a [`Buffer`] cannot grow (`bytes.ErrTooLarge`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErrTooLarge;

impl fmt::Display for ErrTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bytes.Buffer: too large")
    }
}

impl std::error::Error for ErrTooLarge {}

fn index_byte(b: &[u8], c: u8) -> Option<usize> {
    b.iter().position(|&x| x == c)
}

const SMALL_BUFFER_SIZE: usize = 64;
const MAX_INT: usize = isize::MAX as usize;

const OP_READ: i8 = -1;
const OP_INVALID: i8 = 0;

/// Rounds an allocation request up to Go's allocator size, as `append` does
/// for byte slices, so that [`Buffer::cap`] matches Go.
fn roundup_size(size: usize) -> usize {
    if size == 0 {
        return 0;
    }
    if size <= 32768 - 8 {
        return BYTES_SIZE_CLASSES
            .iter()
            .copied()
            .find(|&c| c >= size)
            .unwrap_or(size);
    }
    match size.checked_add(8191) {
        Some(n) => n & !8191,
        None => size,
    }
}

fn too_large() -> ! {
    std::panic::panic_any(ErrTooLarge)
}

/// A variable-sized buffer of bytes with read and write methods
/// (`bytes.Buffer`). The zero value (`Buffer::new()`) is an empty buffer.
///
/// `data.len()` is the Go capacity of the underlying slice, `len` its length
/// and `off` the read offset, so the unread bytes are `data[off..len]`.
#[derive(Clone, Debug, Default)]
pub struct Buffer {
    data: Vec<u8>,
    len: usize,
    off: usize,
    last_read: i8,
    /// Set for an allocated-but-zero-capacity slice (`bytes.NewBufferString("")`),
    /// which Go distinguishes from a nil slice when growing.
    non_nil: bool,
}

impl Buffer {
    /// Creates an empty buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes ownership of `buf` as the initial contents (`bytes.NewBuffer`).
    /// The capacity is `buf.capacity()`.
    pub fn from_vec(mut buf: Vec<u8>) -> Self {
        let len = buf.len();
        buf.resize(buf.capacity(), 0);
        Buffer {
            data: buf,
            len,
            off: 0,
            last_read: OP_INVALID,
            non_nil: false,
        }
    }

    /// Creates a buffer holding a copy of `s` (`bytes.NewBufferString`).
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        let mut data = vec![0; roundup_size(s.len())];
        data[..s.len()].copy_from_slice(s.as_bytes());
        Buffer {
            data,
            len: s.len(),
            off: 0,
            last_read: OP_INVALID,
            non_nil: true,
        }
    }

    /// Returns the unread portion (`Buffer.Bytes`).
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[self.off..self.len]
    }

    /// Returns the unused capacity (`Buffer.AvailableBuffer`). Go returns it
    /// with length zero for use with `append`; here its length is
    /// [`Buffer::available`] and bytes written to it are not part of the
    /// buffer until copied in with a write.
    pub fn available_buffer(&mut self) -> &mut [u8] {
        &mut self.data[self.len..]
    }

    /// Returns the first `n` unread bytes without advancing (`Buffer.Peek`).
    /// If fewer than `n` bytes are unread, all of them are returned with an
    /// EOF error.
    pub fn peek(&self, n: usize) -> (&[u8], Option<io::Error>) {
        if self.len() < n {
            return (self.as_bytes(), Some(eof()));
        }
        (&self.data[self.off..self.off + n], None)
    }

    fn empty(&self) -> bool {
        self.len <= self.off
    }

    /// Returns the number of unread bytes (`Buffer.Len`).
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.len - self.off
    }

    /// Returns the capacity of the underlying storage (`Buffer.Cap`).
    pub fn cap(&self) -> usize {
        self.data.len()
    }

    /// Returns the unused capacity (`Buffer.Available`).
    pub fn available(&self) -> usize {
        self.data.len() - self.len
    }

    /// Keeps the first `n` unread bytes (`Buffer.Truncate`).
    ///
    /// # Panics
    /// Panics if `n` is greater than [`Buffer::len`].
    pub fn truncate(&mut self, n: usize) {
        if n == 0 {
            self.reset();
            return;
        }
        self.last_read = OP_INVALID;
        if n > self.len() {
            panic!("bytes.Buffer: truncation out of range");
        }
        self.len = self.off + n;
    }

    /// Empties the buffer, keeping its storage (`Buffer.Reset`).
    pub fn reset(&mut self) {
        self.len = 0;
        self.off = 0;
        self.last_read = OP_INVALID;
    }

    fn try_grow_by_reslice(&mut self, n: usize) -> Option<usize> {
        if n <= self.data.len() - self.len {
            let l = self.len;
            self.len += n;
            Some(l)
        } else {
            None
        }
    }

    /// Reproduces Go's `growSlice`: a new zeroed storage holding the first
    /// `keep` bytes of `data[off..len]`.
    fn grow_slice(&mut self, n: usize) {
        let b_len = self.len - self.off;
        let b_cap = self.data.len() - self.off;
        let mut c = b_len.checked_add(n).unwrap_or_else(|| too_large());
        if c < b_cap.saturating_mul(2) {
            c = b_cap * 2;
        }
        let newcap = roundup_size(c);
        if newcap > MAX_INT {
            too_large();
        }
        let mut fresh: Vec<u8> = Vec::new();
        if fresh.try_reserve_exact(newcap).is_err() {
            too_large();
        }
        fresh.extend_from_slice(&self.data[self.off..self.len]);
        fresh.resize(newcap, 0);
        self.data = fresh;
        self.len = b_len;
        self.off = 0;
    }

    /// Makes room for `n` more bytes and returns the index to write at.
    fn make_room(&mut self, n: usize) -> usize {
        let m = self.len();
        if m == 0 && self.off != 0 {
            self.reset();
        }
        if let Some(i) = self.try_grow_by_reslice(n) {
            return i;
        }
        if self.data.is_empty() && !self.non_nil && n <= SMALL_BUFFER_SIZE {
            self.data = vec![0; SMALL_BUFFER_SIZE];
            self.len = n;
            return 0;
        }
        let c = self.data.len();
        if n + m <= c / 2 {
            self.data.copy_within(self.off..self.len, 0);
        } else if c > MAX_INT.saturating_sub(c).saturating_sub(n) {
            too_large();
        } else {
            self.grow_slice(self.off + n);
        }
        self.off = 0;
        self.len = m + n;
        m
    }

    /// Ensures room for `n` more bytes (`Buffer.Grow`).
    pub fn grow(&mut self, n: usize) {
        let m = self.make_room(n);
        self.len = m;
    }

    /// Appends `p` (`Buffer.Write`); always writes everything.
    fn write_bytes(&mut self, p: &[u8]) -> usize {
        self.last_read = OP_INVALID;
        let m = match self.try_grow_by_reslice(p.len()) {
            Some(m) => m,
            None => self.make_room(p.len()),
        };
        self.data[m..m + p.len()].copy_from_slice(p);
        p.len()
    }

    /// Appends `s` (`Buffer.WriteString`).
    pub fn write_string(&mut self, s: &str) -> usize {
        self.write_bytes(s.as_bytes())
    }

    /// Appends one byte (`Buffer.WriteByte`).
    pub fn write_byte(&mut self, c: u8) {
        self.write_bytes(&[c]);
    }

    /// Appends the UTF-8 encoding of `r` and returns its width
    /// (`Buffer.WriteRune`).
    pub fn write_rune(&mut self, r: char) -> usize {
        let mut buf = [0u8; 4];
        let enc = r.encode_utf8(&mut buf).as_bytes();
        if enc.len() == 1 {
            self.write_byte(enc[0]);
            return 1;
        }
        // Like Go, reserve the maximum encoded width before writing.
        self.last_read = OP_INVALID;
        let m = match self.try_grow_by_reslice(4) {
            Some(m) => m,
            None => self.make_room(4),
        };
        self.data[m..m + enc.len()].copy_from_slice(enc);
        self.len = m + enc.len();
        enc.len()
    }

    /// Reads from `r` until EOF, growing as needed (`Buffer.ReadFrom`).
    /// Returns the number of bytes read. Go also reports the count alongside
    /// an error; here bytes read before an error remain in the buffer.
    pub fn read_from<R: Read + ?Sized>(&mut self, r: &mut R) -> io::Result<u64> {
        self.last_read = OP_INVALID;
        let mut n = 0u64;
        loop {
            let i = self.make_room(MIN_READ);
            self.len = i;
            let cap = self.data.len();
            match r.read(&mut self.data[i..cap]) {
                Ok(0) => return Ok(n),
                Ok(m) => {
                    self.len = i + m;
                    n += m as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// Writes the unread bytes to `w` and empties the buffer
    /// (`Buffer.WriteTo`).
    pub fn write_to<W: Write + ?Sized>(&mut self, w: &mut W) -> io::Result<u64> {
        self.last_read = OP_INVALID;
        let n_bytes = self.len();
        let mut n = 0u64;
        if n_bytes > 0 {
            let m = w.write(&self.data[self.off..self.len])?;
            if m > n_bytes {
                panic!("bytes.Buffer.WriteTo: invalid Write count");
            }
            self.off += m;
            n = m as u64;
            if m != n_bytes {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "short write"));
            }
        }
        self.reset();
        Ok(n)
    }

    /// Consumes and returns the next `n` unread bytes, or all of them
    /// (`Buffer.Next`).
    pub fn next(&mut self, n: usize) -> &[u8] {
        self.last_read = OP_INVALID;
        let n = n.min(self.len());
        let start = self.off;
        self.off += n;
        if n > 0 {
            self.last_read = OP_READ;
        }
        &self.data[start..start + n]
    }

    /// Reads one byte (`Buffer.ReadByte`); EOF is an `UnexpectedEof` error.
    pub fn read_byte(&mut self) -> io::Result<u8> {
        if self.empty() {
            self.reset();
            return Err(eof());
        }
        let c = self.data[self.off];
        self.off += 1;
        self.last_read = OP_READ;
        Ok(c)
    }

    /// Reads one rune and its width (`Buffer.ReadRune`). Invalid UTF-8 yields
    /// `(U+FFFD, 1)`.
    pub fn read_rune(&mut self) -> io::Result<(char, usize)> {
        if self.empty() {
            self.reset();
            return Err(eof());
        }
        let (r, n) = decode_rune(&self.data[self.off..self.len]);
        self.off += n;
        self.last_read = n as i8;
        Ok((r, n))
    }

    /// Unreads the last rune read (`Buffer.UnreadRune`).
    pub fn unread_rune(&mut self) -> io::Result<()> {
        if self.last_read <= OP_INVALID {
            return Err(io::Error::other(
                "bytes.Buffer: UnreadRune: previous operation was not a successful ReadRune",
            ));
        }
        if self.off >= self.last_read as usize {
            self.off -= self.last_read as usize;
        }
        self.last_read = OP_INVALID;
        Ok(())
    }

    /// Unreads the last byte read (`Buffer.UnreadByte`).
    pub fn unread_byte(&mut self) -> io::Result<()> {
        if self.last_read == OP_INVALID {
            return Err(io::Error::other(
                "bytes.Buffer: UnreadByte: previous operation was not a successful read",
            ));
        }
        self.last_read = OP_INVALID;
        if self.off > 0 {
            self.off -= 1;
        }
        Ok(())
    }

    fn read_slice(&mut self, delim: u8) -> (&[u8], Option<io::Error>) {
        let (end, err) = match index_byte(&self.data[self.off..self.len], delim) {
            Some(i) => (self.off + i + 1, None),
            None => (self.len, Some(eof())),
        };
        let start = self.off;
        self.off = end;
        self.last_read = OP_READ;
        (&self.data[start..end], err)
    }

    /// Reads through the first `delim` (`Buffer.ReadBytes`). If `delim` is
    /// missing the remaining data is returned with an EOF error.
    pub fn read_bytes(&mut self, delim: u8) -> (Vec<u8>, Option<io::Error>) {
        let (slice, err) = self.read_slice(delim);
        (slice.to_vec(), err)
    }

    /// Like [`Buffer::read_bytes`] but returns a string (`Buffer.ReadString`);
    /// invalid UTF-8 is replaced with `U+FFFD`.
    pub fn read_string(&mut self, delim: u8) -> (String, Option<io::Error>) {
        let (slice, err) = self.read_slice(delim);
        (String::from_utf8_lossy(slice).into_owned(), err)
    }
}

/// The unread portion as a string (`Buffer.String`). Invalid UTF-8 is
/// replaced with `U+FFFD`; use [`Buffer::as_bytes`] for the exact contents.
impl fmt::Display for Buffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&String::from_utf8_lossy(self.as_bytes()))
    }
}

impl Read for Buffer {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        self.last_read = OP_INVALID;
        if self.empty() {
            self.reset();
            return Ok(0);
        }
        let n = p.len().min(self.len());
        p[..n].copy_from_slice(&self.data[self.off..self.off + n]);
        self.off += n;
        if n > 0 {
            self.last_read = OP_READ;
        }
        Ok(n)
    }
}

impl Write for Buffer {
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        Ok(self.write_bytes(p))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl BufRead for Buffer {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        Ok(Buffer::as_bytes(self))
    }

    fn consume(&mut self, amt: usize) {
        self.last_read = OP_INVALID;
        let n = amt.min(self.len());
        self.off += n;
        if n > 0 {
            self.last_read = OP_READ;
        }
    }
}
