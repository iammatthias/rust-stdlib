//! Go's `testing/iotest`: readers and writers useful mainly for testing.
//!
//! Go's `io.EOF` is `Ok(0)` from `Read` in Rust, so a reader cannot return
//! data together with an error: [`DataErrReader`] keeps its look-ahead but
//! delivers the error with the next call (see its documentation).

use std::{
    error::Error as StdError,
    fmt,
    io::{self, Read, Seek, SeekFrom, Write},
    sync::Arc,
};

use crate::io::{is_eof, ReadAt};

/// Go's `iotest.ErrTimeout`: a fake timeout error with the text "timeout".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ErrTimeout;

impl fmt::Display for ErrTimeout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("timeout")
    }
}

impl StdError for ErrTimeout {}

impl From<ErrTimeout> for io::Error {
    fn from(e: ErrTimeout) -> io::Error {
        io::Error::new(io::ErrorKind::TimedOut, e)
    }
}

/// Go's `iotest.ErrTimeout` value.
pub const ERR_TIMEOUT: ErrTimeout = ErrTimeout;

/// Reports whether `err` is [`ERR_TIMEOUT`].
pub fn is_err_timeout(err: &io::Error) -> bool {
    err.get_ref().is_some_and(|e| e.is::<ErrTimeout>())
}

/// The reader returned by [`one_byte_reader`].
#[derive(Debug)]
pub struct OneByteReader<R> {
    r: R,
}

/// Go's `OneByteReader`: a reader that implements each non-empty `read` by
/// reading one byte from `r`.
pub fn one_byte_reader<R: Read>(r: R) -> OneByteReader<R> {
    OneByteReader { r }
}

impl<R: Read> Read for OneByteReader<R> {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        if p.is_empty() {
            return Ok(0);
        }
        self.r.read(&mut p[..1])
    }
}

/// The reader returned by [`half_reader`].
#[derive(Debug)]
pub struct HalfReader<R> {
    r: R,
}

/// Go's `HalfReader`: a reader that implements `read` by reading half as many
/// requested bytes from `r`.
pub fn half_reader<R: Read>(r: R) -> HalfReader<R> {
    HalfReader { r }
}

impl<R: Read> Read for HalfReader<R> {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        let n = p.len().div_ceil(2);
        self.r.read(&mut p[..n])
    }
}

/// The reader returned by [`data_err_reader`].
///
/// Go changes the way errors are handled: the final error is returned
/// along with the final data instead of in the first call after it. Rust's
/// `Read` cannot return a count and an error together, so this reader keeps
/// Go's one-read look-ahead (it fetches the next chunk, and with it the
/// error, before the last data is delivered) and returns the error from the
/// call after the final data.
#[derive(Debug)]
pub struct DataErrReader<R> {
    r: R,
    unread: Vec<u8>,
    data: Vec<u8>,
    pending: Option<Pending>,
}

/// What the look-ahead found after the data: end of input, or an error.
#[derive(Debug)]
enum Pending {
    Eof,
    Err(io::Error),
}

/// Go's `DataErrReader`; see [`DataErrReader`] for the one difference.
pub fn data_err_reader<R: Read>(r: R) -> DataErrReader<R> {
    DataErrReader {
        r,
        unread: Vec::new(),
        data: vec![0; 1024],
        pending: None,
    }
}

impl<R: Read> DataErrReader<R> {
    fn fetch(&mut self) {
        match self.r.read(&mut self.data) {
            Ok(0) => self.pending = Some(Pending::Eof),
            Ok(n) => self.unread = self.data[..n].to_vec(),
            Err(e) => self.pending = Some(Pending::Err(e)),
        }
    }
}

impl<R: Read> Read for DataErrReader<R> {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        if self.unread.is_empty() && self.pending.is_none() {
            self.fetch();
        }
        if !self.unread.is_empty() {
            let n = p.len().min(self.unread.len());
            p[..n].copy_from_slice(&self.unread[..n]);
            self.unread.drain(..n);
            if n > 0 && self.unread.is_empty() && self.pending.is_none() {
                // Go looks for the error before returning the last data.
                self.fetch();
            }
            return Ok(n);
        }
        match self.pending.take() {
            Some(Pending::Err(e)) => Err(e),
            Some(Pending::Eof) | None => Ok(0),
        }
    }
}

/// The reader returned by [`timeout_reader`].
#[derive(Debug)]
pub struct TimeoutReader<R> {
    r: R,
    count: u32,
}

/// Go's `TimeoutReader`: a reader that returns [`ERR_TIMEOUT`] on the second
/// read with no data. Subsequent calls to read succeed.
pub fn timeout_reader<R: Read>(r: R) -> TimeoutReader<R> {
    TimeoutReader { r, count: 0 }
}

impl<R: Read> Read for TimeoutReader<R> {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        self.count += 1;
        if self.count == 2 {
            return Err(ERR_TIMEOUT.into());
        }
        self.r.read(p)
    }
}

/// An error that can be handed out repeatedly (an `io::Error` is not `Clone`).
#[derive(Debug, Clone)]
struct SharedError(Arc<io::Error>);

impl fmt::Display for SharedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&*self.0, f)
    }
}

impl StdError for SharedError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&*self.0)
    }
}

/// The reader returned by [`err_reader`].
#[derive(Debug)]
pub struct ErrReader {
    err: SharedError,
    kind: io::ErrorKind,
}

/// Go's `ErrReader`: a reader that returns the error `err` from every `read`.
/// Every call returns an `io::Error` of the same kind and text whose source
/// is `err`.
pub fn err_reader(err: io::Error) -> ErrReader {
    let kind = err.kind();
    ErrReader {
        err: SharedError(Arc::new(err)),
        kind,
    }
}

impl Read for ErrReader {
    fn read(&mut self, _p: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(self.kind, self.err.clone()))
    }
}

/// The writer returned by [`truncate_writer`].
#[derive(Debug)]
pub struct TruncateWriter<W> {
    w: W,
    n: i64,
}

/// Go's `TruncateWriter`: a writer that writes to `w` but stops silently
/// after `n` bytes.
pub fn truncate_writer<W: Write>(w: W, n: i64) -> TruncateWriter<W> {
    TruncateWriter { w, n }
}

impl<W: Write> Write for TruncateWriter<W> {
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        if self.n <= 0 {
            return Ok(p.len());
        }
        let mut n = p.len();
        if n as i64 > self.n {
            n = self.n as usize;
        }
        let written = self.w.write(&p[..n])?;
        self.n -= written as i64;
        Ok(p.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

fn hex(p: &[u8]) -> String {
    use std::fmt::Write as _;
    p.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The writer returned by [`WriteLogger::new`].
#[derive(Debug)]
pub struct WriteLogger<W> {
    prefix: String,
    w: W,
}

impl<W: Write> WriteLogger<W> {
    /// Go's `NewWriteLogger`: a writer that behaves like `w` except that it logs
    /// (using [`log::printf`](crate::log::printf)) each write to standard error,
    /// printing the prefix and the hexadecimal data written.
    pub fn new(prefix: &str, w: W) -> WriteLogger<W> {
        WriteLogger {
            prefix: prefix.to_string(),
            w,
        }
    }
}

impl<W: Write> Write for WriteLogger<W> {
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        let r = self.w.write(p);
        match &r {
            Ok(n) => crate::log::printf(format_args!("{} {}", self.prefix, hex(&p[..*n]))),
            Err(e) => crate::log::printf(format_args!("{} {}: {e}", self.prefix, hex(&[]))),
        }
        r
    }

    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

/// The reader returned by [`ReadLogger::new`].
#[derive(Debug)]
pub struct ReadLogger<R> {
    prefix: String,
    r: R,
}

impl<R: Read> ReadLogger<R> {
    /// Go's `NewReadLogger`: a reader that behaves like `r` except that it logs
    /// (using [`log::printf`](crate::log::printf)) each read to standard error,
    /// printing the prefix and the hexadecimal data read.
    pub fn new(prefix: &str, r: R) -> ReadLogger<R> {
        ReadLogger {
            prefix: prefix.to_string(),
            r,
        }
    }
}

impl<R: Read> Read for ReadLogger<R> {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        let r = self.r.read(p);
        match &r {
            Ok(n) => crate::log::printf(format_args!("{} {}", self.prefix, hex(&p[..*n]))),
            Err(e) => crate::log::printf(format_args!("{} {}: {e}", self.prefix, hex(&[]))),
        }
        r
    }
}

// ----- TestReader -----

/// The optional capabilities that Go's `TestReader` discovers with type
/// assertions on `io.ReadSeeker` and `io.ReaderAt` ([`ReadAt`]). Override the methods for
/// those the reader implements, returning `Some(self)`.
pub trait TestableReader: Read {
    /// `r.(io.Seeker)`.
    fn as_seek(&mut self) -> Option<&mut dyn Seek> {
        None
    }
    /// `r.(io.ReaderAt)`.
    fn as_read_at(&self) -> Option<&dyn ReadAt> {
        None
    }
}

impl TestableReader for &[u8] {}

impl<T: AsRef<[u8]>> TestableReader for io::Cursor<T> {
    fn as_seek(&mut self) -> Option<&mut dyn Seek> {
        Some(self)
    }
}

impl TestableReader for crate::text::Reader<'_> {
    fn as_seek(&mut self) -> Option<&mut dyn Seek> {
        Some(self)
    }
    fn as_read_at(&self) -> Option<&dyn ReadAt> {
        Some(self)
    }
}

impl<R: ReadAt> TestableReader for crate::io::SectionReader<R> {
    fn as_seek(&mut self) -> Option<&mut dyn Seek> {
        Some(self)
    }
    fn as_read_at(&self) -> Option<&dyn ReadAt> {
        Some(self)
    }
}

impl<R: Read> TestableReader for OneByteReader<R> {}
impl<R: Read> TestableReader for HalfReader<R> {}
impl<R: Read> TestableReader for DataErrReader<R> {}
impl<R: Read> TestableReader for TimeoutReader<R> {}
impl TestableReader for ErrReader {}

impl<R: TestableReader + ?Sized> TestableReader for Box<R> {
    fn as_seek(&mut self) -> Option<&mut dyn Seek> {
        (**self).as_seek()
    }
    fn as_read_at(&self) -> Option<&dyn ReadAt> {
        (**self).as_read_at()
    }
}

impl<R: TestableReader + ?Sized> TestableReader for &mut R {
    fn as_seek(&mut self) -> Option<&mut dyn Seek> {
        (**self).as_seek()
    }
    fn as_read_at(&self) -> Option<&dyn ReadAt> {
        (**self).as_read_at()
    }
}

/// Reads one to three bytes at a time, wrapping errors with their offset.
struct SmallByteReader<'a, R: ?Sized> {
    r: &'a mut R,
    off: usize,
    n: usize,
}

impl<R: Read + ?Sized> Read for SmallByteReader<'_, R> {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        if p.is_empty() {
            return Ok(0);
        }
        self.n = self.n % 3 + 1;
        let n = self.n.min(p.len());
        match self.r.read(&mut p[..n]) {
            Ok(n) => {
                self.off += n;
                Ok(n)
            }
            Err(e) => Err(io::Error::other(format!(
                "Read({n} bytes at offset {}): {e}",
                self.off
            ))),
        }
    }
}

fn read_all(r: &mut dyn Read) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        match r.read(&mut buf) {
            Ok(0) => return Ok(out),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

fn errf(s: String) -> io::Error {
    io::Error::other(s)
}

fn q(b: &[u8]) -> String {
    crate::strconv::quote(b)
}

fn opt_err(e: &Option<io::Error>) -> String {
    match e {
        None => "<nil>".to_string(),
        Some(e) if is_eof(e) => "EOF".to_string(),
        Some(e) => e.to_string(),
    }
}

/// Go's `TestReader`: tests that reading from `r` returns the expected file
/// content, with reads of different sizes until EOF. If `r` is seekable or
/// implements `ReadAt` (see [`TestableReader`]), those operations are
/// checked too. A misbehaviour is reported as an error whose text may span
/// several lines.
pub fn test_reader(r: &mut dyn TestableReader, content: &[u8]) -> io::Result<()> {
    if !content.is_empty() {
        match r.read(&mut []) {
            Ok(0) => {}
            other => {
                let (n, err) = match other {
                    Ok(n) => (n.to_string(), "<nil>".to_string()),
                    Err(e) => ("0".to_string(), e.to_string()),
                };
                return Err(errf(format!("Read(0) = {n}, {err}, want 0, nil")));
            }
        }
    }

    let data = read_all(&mut SmallByteReader {
        r: &mut *r,
        off: 0,
        n: 0,
    })?;
    if data != content {
        return Err(errf(format!(
            "ReadAll(small amounts) = {}\n\twant {}",
            q(&data),
            q(content)
        )));
    }
    match r.read(&mut [0u8; 10]) {
        Ok(0) => {}
        Ok(n) => return Err(errf(format!("Read(10) at EOF = {n}, <nil>, want 0, EOF"))),
        Err(e) => return Err(errf(format!("Read(10) at EOF = 0, {e}, want 0, EOF"))),
    }

    let len = content.len() as i64;
    if r.as_seek().is_some() {
        let seek = |r: &mut dyn TestableReader, pos: SeekFrom| -> Result<u64, io::Error> {
            r.as_seek().expect("seeker").seek(pos)
        };
        let ok =
            |res: &Result<u64, io::Error>, want: i64| matches!(res, Ok(off) if *off as i64 == want);
        // Seek(0, 1) should report the current file position (EOF).
        let res = seek(r, SeekFrom::Current(0));
        if !ok(&res, len) {
            return Err(errf(format!(
                "Seek(0, 1) from EOF = {}, {}, want {len}, nil",
                off_of(&res),
                err_of(&res)
            )));
        }
        let middle = len - len / 3;
        if middle > 0 {
            let res = seek(r, SeekFrom::Current(-1));
            if !ok(&res, len - 1) {
                return Err(errf(format!(
                    "Seek(-1, 1) from EOF = {}, {}, want {}, nil",
                    -off_of_i(&res),
                    err_of(&res),
                    len - 1
                )));
            }
            let res = seek(r, SeekFrom::Current(-(len / 3)));
            if !ok(&res, middle - 1) {
                return Err(errf(format!(
                    "Seek({}, 1) from {} = {}, {}, want {}, nil",
                    -len / 3,
                    len - 1,
                    off_of(&res),
                    err_of(&res),
                    middle - 1
                )));
            }
            let res = seek(r, SeekFrom::Current(1));
            if !ok(&res, middle) {
                return Err(errf(format!(
                    "Seek(+1, 1) from {} = {}, {}, want {middle}, nil",
                    middle - 1,
                    off_of(&res),
                    err_of(&res)
                )));
            }
        }
        // Seek(0, 1) should report the current file position (middle).
        let res = seek(r, SeekFrom::Current(0));
        if !ok(&res, middle) {
            return Err(errf(format!(
                "Seek(0, 1) from {middle} = {}, {}, want {middle}, nil",
                off_of(&res),
                err_of(&res)
            )));
        }
        // Reading forward should return the last part of the file.
        let data = read_all(&mut SmallByteReader {
            r: &mut *r,
            off: 0,
            n: 0,
        })
        .map_err(|e| errf(format!("ReadAll from offset {middle}: {e}")))?;
        if data != content[middle as usize..] {
            return Err(errf(format!(
                "ReadAll from offset {middle} = {}\n\twant {}",
                q(&data),
                q(&content[middle as usize..])
            )));
        }
        // Seek relative to end of file, but start elsewhere.
        let res = seek(r, SeekFrom::Start((middle / 2) as u64));
        if !ok(&res, middle / 2) {
            return Err(errf(format!(
                "Seek({}, 0) from EOF = {}, {}, want {}, nil",
                middle / 2,
                off_of(&res),
                err_of(&res),
                middle / 2
            )));
        }
        let res = seek(r, SeekFrom::End(-(len / 3)));
        if !ok(&res, middle) {
            return Err(errf(format!(
                "Seek({}, 2) from {} = {}, {}, want {middle}, nil",
                -len / 3,
                middle / 2,
                off_of(&res),
                err_of(&res)
            )));
        }
        // Reading forward should return the last part of the file (again).
        let data = read_all(&mut SmallByteReader {
            r: &mut *r,
            off: 0,
            n: 0,
        })
        .map_err(|e| errf(format!("ReadAll from offset {middle}: {e}")))?;
        if data != content[middle as usize..] {
            return Err(errf(format!(
                "ReadAll from offset {middle} = {}\n\twant {}",
                q(&data),
                q(&content[middle as usize..])
            )));
        }
        // Absolute seek & read forward.
        let res = seek(r, SeekFrom::Start((middle / 2) as u64));
        if !ok(&res, middle / 2) {
            return Err(errf(format!(
                "Seek({}, 0) from EOF = {}, {}, want {}, nil",
                middle / 2,
                off_of(&res),
                err_of(&res),
                middle / 2
            )));
        }
        let data = read_all(&mut *r)
            .map_err(|e| errf(format!("ReadAll from offset {}: {e}", middle / 2)))?;
        if data != content[(middle / 2) as usize..] {
            return Err(errf(format!(
                "ReadAll from offset {} = {}\n\twant {}",
                middle / 2,
                q(&data),
                q(&content[(middle / 2) as usize..])
            )));
        }
    }

    if let Some(ra) = r.as_read_at() {
        let l = content.len();
        let mut data = vec![0xfeu8; l + 1];
        let (n, err) = go_read_at(ra, &mut data[..l], 0);
        if n != l || err.as_ref().is_some_and(|e| !is_eof(e)) {
            return Err(errf(format!(
                "ReadAt({l}, 0) = {n}, {}, want {l}, nil or EOF",
                opt_err(&err)
            )));
        }
        if data[..l] != *content {
            return Err(errf(format!(
                "ReadAt({l}, 0) = {}\n\twant {}",
                q(&data[..l]),
                q(content)
            )));
        }

        let (n, err) = go_read_at(ra, &mut data[..1], l as u64);
        if n != 0 || !err.as_ref().is_some_and(is_eof) {
            return Err(errf(format!(
                "ReadAt(1, {l}) = {n}, {}, want 0, EOF",
                opt_err(&err)
            )));
        }

        data.fill(0xfe);
        let (n, err) = go_read_at(ra, &mut data[..l + 1], 0);
        if n != l || !err.as_ref().is_some_and(is_eof) {
            return Err(errf(format!(
                "ReadAt({}, 0) = {n}, {}, want {l}, EOF",
                l + 1,
                opt_err(&err)
            )));
        }
        if data[..l] != *content {
            return Err(errf(format!(
                "ReadAt({l}, 0) = {}\n\twant {}",
                q(&data[..l]),
                q(content)
            )));
        }

        data.fill(0xfe);
        for i in 0..l {
            let (n, err) = go_read_at(ra, &mut data[i..i + 1], i as u64);
            if n != 1 || err.as_ref().is_some_and(|e| i != l - 1 || !is_eof(e)) {
                let want = if i == l - 1 { "nil or EOF" } else { "nil" };
                return Err(errf(format!(
                    "ReadAt(1, {i}) = {n}, {}, want 1, {want}",
                    opt_err(&err)
                )));
            }
            if data[i] != content[i] {
                return Err(errf(format!(
                    "ReadAt(1, {i}) = {} want {}",
                    q(&data[i..i + 1]),
                    q(&content[i..i + 1])
                )));
            }
        }
    }
    Ok(())
}

/// Go's `(n, err)` result of `ReadAt`.
fn go_read_at(ra: &dyn ReadAt, buf: &mut [u8], off: u64) -> (usize, Option<io::Error>) {
    match ra.read_at(buf, off) {
        Ok(n) => (n, None),
        Err(e) => (e.read(), Some(e.into_source())),
    }
}

fn off_of(r: &Result<u64, io::Error>) -> u64 {
    r.as_ref().copied().unwrap_or(0)
}

fn off_of_i(r: &Result<u64, io::Error>) -> i64 {
    off_of(r) as i64
}

fn err_of(r: &Result<u64, io::Error>) -> String {
    match r {
        Ok(_) => "<nil>".to_string(),
        Err(e) => e.to_string(),
    }
}
