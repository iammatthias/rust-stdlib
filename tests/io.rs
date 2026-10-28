//! Tests for `rust_stdlib::io`, ported from Go's `io_test.go`, `multi_test.go`
//! and `pipe_test.go` (BSD license, see NOTICE). The Go differential is in
//! `tools/io_check.py`.

use rust_stdlib::io::{self as rio, ReadAt, RuneReader, RuneScanner, WriteAt};
use rust_stdlib::text;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::sync::mpsc;
use std::thread;

fn read_all(r: &mut (impl Read + ?Sized)) -> io::Result<Vec<u8>> {
    let mut v = Vec::new();
    r.read_to_end(&mut v)?;
    Ok(v)
}

fn chained<'a>(readers: Vec<Box<dyn Read + 'a>>) -> Box<dyn Read + 'a> {
    readers
        .into_iter()
        .fold(Box::new(io::empty()), |all, r| Box::new(all.chain(r)))
}

fn temp_file(tag: &str) -> (std::fs::File, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!("rust-stdlib-io-{tag}-{}", std::process::id()));
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    (f, path)
}

fn is_err(err: &Option<io::Error>, want: rio::Error) -> bool {
    err.as_ref().is_some_and(|e| want.is(e))
}

/// Go's `(n, err)` shape of the counted results, so the ported assertions
/// read like Go's tests.
fn counted(res: Result<u64, rio::CopyError>) -> (u64, Option<io::Error>) {
    match res {
        Ok(n) => (n, None),
        Err(e) => (e.written(), Some(e.into_source())),
    }
}

fn counted_usize(res: Result<usize, rio::CopyError>) -> (usize, Option<io::Error>) {
    match res {
        Ok(n) => (n, None),
        Err(e) => (e.written() as usize, Some(e.into_source())),
    }
}

fn read_counted(res: Result<usize, rio::ReadError>) -> (usize, Option<io::Error>) {
    match res {
        Ok(n) => (n, None),
        Err(e) => (e.read(), Some(e.into_source())),
    }
}

fn copy<W: Write + ?Sized, R: Read + ?Sized>(w: &mut W, r: &mut R) -> (u64, Option<io::Error>) {
    counted(rio::copy(w, r))
}

fn copy_n<W: Write + ?Sized, R: Read + ?Sized>(
    w: &mut W,
    r: &mut R,
    n: i64,
) -> (u64, Option<io::Error>) {
    // Go treats a negative count like zero.
    counted(rio::copy_n(w, r, n.max(0) as u64))
}

fn read_full<R: Read + ?Sized>(r: &mut R, buf: &mut [u8]) -> (usize, Option<io::Error>) {
    read_counted(rio::read_full(r, buf))
}

fn read_at_least<R: Read + ?Sized>(
    r: &mut R,
    buf: &mut [u8],
    min: usize,
) -> (usize, Option<io::Error>) {
    read_counted(rio::read_at_least(r, buf, min))
}

/// Go's `(offset, whence)` seek arguments as a `SeekFrom`.
fn seek_from(offset: i64, whence: i32) -> io::Result<SeekFrom> {
    match whence {
        0 => u64::try_from(offset)
            .map(SeekFrom::Start)
            .map_err(|_| io::Error::other("Seek: invalid offset")),
        1 => Ok(SeekFrom::Current(offset)),
        2 => Ok(SeekFrom::End(offset)),
        _ => Err(io::Error::other("Seek: invalid whence")),
    }
}

/// Go's `(n, err)` result of `ReadAt`.
fn read_at<R: ReadAt + ?Sized>(r: &R, buf: &mut [u8], off: u64) -> (usize, Option<io::Error>) {
    read_counted(r.read_at(buf, off))
}

#[test]
fn sentinel_errors() {
    for (e, text) in [
        (rio::Error::Eof, "EOF"),
        (rio::Error::ClosedPipe, "io: read/write on closed pipe"),
        (
            rio::Error::NoProgress,
            "multiple Read calls return no data or error",
        ),
        (rio::Error::ShortBuffer, "short buffer"),
        (rio::Error::ShortWrite, "short write"),
        (rio::Error::UnexpectedEof, "unexpected EOF"),
    ] {
        assert_eq!(e.to_string(), text);
        let err = io::Error::from(e);
        assert_eq!(err.to_string(), text);
        assert!(e.is(&err));
        for other in [
            rio::Error::Eof,
            rio::Error::UnexpectedEof,
            rio::Error::ShortWrite,
        ] {
            assert_eq!(other.is(&err), other == e);
        }
    }
    assert!(rio::is_eof(&rio::eof()));
    assert!(!rio::is_eof(&rio::Error::UnexpectedEof.into()));
    assert!(rio::is_unexpected_eof(&rio::Error::UnexpectedEof.into()));
    assert!(!rio::is_eof(&io::Error::other("EOF")));
    // Errors from other first-party readers are the same value.
    let mut r = text::Reader::new(b"");
    assert!(rio::is_eof(&r.read_byte().unwrap_err()));
    assert!(rio::is_eof(&text::Reader::new("").read_byte().unwrap_err()));
    // An io::Error wrapped by another error still matches.
    let wrapped = io::Error::other(rio::eof());
    assert!(rio::is_eof(&wrapped));
}

// ---------------------------------------------------------------- Copy

#[test]
fn copy_and_copy_buffer() {
    // TestCopy / TestCopyBuffer
    let mut dst = Vec::new();
    let (n, err) = copy(&mut dst, &mut Cursor::new(b"hello, world.".to_vec()));
    assert_eq!(
        (n, err.is_none(), dst.as_slice()),
        (13, true, &b"hello, world."[..])
    );

    let mut dst = Vec::new();
    let mut buf = [0u8; 3];
    let (n, err) = counted(rio::copy_buffer(
        &mut dst,
        &mut Cursor::new(b"hello, world.".to_vec()),
        &mut buf,
    ));
    assert_eq!((n, err.is_none()), (13, true));
    assert_eq!(dst, b"hello, world.");
}

#[test]
fn copy_buffer_empty_buffer_is_an_error() {
    // TestCopyBufferNil/Empty: Go panics, here it is an error.
    let mut empty: [u8; 0] = [];
    let err = rio::copy_buffer(&mut io::sink(), &mut io::empty(), &mut empty).unwrap_err();
    assert_eq!(err.written(), 0);
    assert_eq!(err.to_string(), "empty buffer in CopyBuffer");
}

struct ShortWriter;

impl Write for ShortWriter {
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        Ok(p.len().saturating_sub(1))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn copy_errors() {
    // A short write is ErrShortWrite; the count is what the writer accepted.
    let (n, err) = copy(&mut ShortWriter, &mut Cursor::new(b"abcd".to_vec()));
    assert_eq!(n, 3);
    assert!(is_err(&err, rio::Error::ShortWrite));
    // A writer error is returned as is.
    struct Failing;
    impl Write for Failing {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("nope"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let (n, err) = copy(&mut Failing, &mut Cursor::new(b"abcd".to_vec()));
    assert_eq!((n, err.unwrap().to_string()), (0, "nope".to_string()));
    // A reader error (not EOF) is returned and the bytes before it are written.
    struct OneThenErr(bool);
    impl Read for OneThenErr {
        fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
            if self.0 {
                return Err(io::Error::other("read failed"));
            }
            self.0 = true;
            p[0] = b'x';
            Ok(1)
        }
    }
    let mut dst = Vec::new();
    let (n, err) = copy(&mut dst, &mut OneThenErr(false));
    assert_eq!(
        (n, dst.as_slice(), err.unwrap().to_string()),
        (1, &b"x"[..], "read failed".to_string())
    );
}

#[test]
fn copy_n_table() {
    // TestCopyN / TestCopyNEOF
    let mut dst = Vec::new();
    let (n, err) = copy_n(&mut dst, &mut Cursor::new(b"hello world".to_vec()), 5);
    assert_eq!((n, err.is_none(), dst.as_slice()), (5, true, &b"hello"[..]));
    let mut dst = Vec::new();
    let (n, err) = copy_n(&mut dst, &mut Cursor::new(b"abc".to_vec()), 10);
    assert_eq!(n, 3);
    assert!(is_err(&err, rio::Error::Eof));
    let (n, err) = copy_n(&mut io::sink(), &mut Cursor::new(b"abc".to_vec()), 0);
    assert_eq!((n, err.is_none()), (0, true));
    let (n, err) = copy_n(&mut io::sink(), &mut Cursor::new(b"abc".to_vec()), -1);
    assert_eq!((n, err.is_none()), (0, true));
}

// ---------------------------------------------------------------- ReadAtLeast and friends

#[test]
fn read_at_least_table() {
    // TestReadAtLeast
    let mut r = Cursor::new(b"abcd".to_vec());
    let mut buf = [0u8; 2];
    assert_eq!(read_at_least(&mut r, &mut buf, 3).0, 0);
    let (n, err) = read_at_least(&mut Cursor::new(b"abcd".to_vec()), &mut buf, 3);
    assert_eq!(n, 0);
    assert!(is_err(&err, rio::Error::ShortBuffer));

    let mut buf = [0u8; 4];
    let (n, err) = read_at_least(&mut Cursor::new(b"ab".to_vec()), &mut buf, 3);
    assert_eq!(n, 2);
    assert!(is_err(&err, rio::Error::UnexpectedEof));
    let (n, err) = read_at_least(&mut Cursor::new(Vec::new()), &mut buf, 1);
    assert_eq!(n, 0);
    assert!(is_err(&err, rio::Error::Eof));
    let (n, err) = read_at_least(&mut Cursor::new(b"abcdef".to_vec()), &mut buf, 2);
    assert_eq!((n, err.is_none()), (4, true));
    // min 0 reads nothing.
    let (n, err) = read_at_least(&mut Cursor::new(b"abc".to_vec()), &mut buf, 0);
    assert_eq!((n, err.is_none()), (0, true));
}

#[test]
fn read_full_and_read_all() {
    let mut buf = [0u8; 3];
    let (n, err) = read_full(&mut Cursor::new(b"abcdef".to_vec()), &mut buf);
    assert_eq!((n, err.is_none(), &buf), (3, true, b"abc"));
    let (n, err) = read_full(&mut Cursor::new(b"ab".to_vec()), &mut buf);
    assert_eq!(n, 2);
    assert!(is_err(&err, rio::Error::UnexpectedEof));
    let (n, err) = read_full(&mut Cursor::new(Vec::new()), &mut buf);
    assert_eq!(n, 0);
    assert!(is_err(&err, rio::Error::Eof));

    assert_eq!(
        read_all(&mut Cursor::new(b"hello".to_vec())).unwrap(),
        b"hello"
    );
    assert_eq!(read_all(&mut io::empty()).unwrap(), b"");
    struct Fails;
    impl Read for Fails {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("read failed"))
        }
    }
    assert_eq!(read_all(&mut Fails).unwrap_err().to_string(), "read failed");
    let big = vec![7u8; 1 << 20];
    assert_eq!(read_all(&mut Cursor::new(big.clone())).unwrap(), big);
}

#[test]
fn write_string_is_write_all() {
    let mut v = Vec::new();
    v.write_all("héllo".as_bytes()).unwrap();
    v.write_all(b"!").unwrap();
    assert_eq!(v, "héllo!".as_bytes());
}

// ---------------------------------------------------------------- adapters

#[test]
fn limit_reader() {
    // TestLimitedReader
    let mut r = Cursor::new(b"0123456789".to_vec()).take(4);
    let mut buf = [0u8; 3];
    assert_eq!(r.read(&mut buf).unwrap(), 3);
    assert_eq!(r.limit(), 1);
    assert_eq!(r.read(&mut buf).unwrap(), 1);
    assert_eq!(r.read(&mut buf).unwrap(), 0);
    assert_eq!(r.limit(), 0);
    // The rest of the source is untouched.
    r.set_limit(2);
    assert_eq!(r.read(&mut buf).unwrap(), 2);
    assert_eq!(&buf[..2], b"45");
    // A zero limit reads nothing.
    let mut r = Cursor::new(b"abc".to_vec()).take(0);
    assert_eq!(r.read(&mut buf).unwrap(), 0);
    assert_eq!(read_all(r.get_mut()).unwrap(), b"abc");
}

#[test]
fn multi_reader() {
    // TestMultiReader and the empty/EOF cases of multi_test.go
    let mut r = chained(vec![
        Box::new(Cursor::new(b"foo ".to_vec())),
        Box::new(io::empty()),
        Box::new(Cursor::new(b"bar".to_vec())),
        Box::new(Cursor::new(Vec::new())),
    ]);
    let mut buf = [0u8; 4];
    assert_eq!(r.read(&mut buf).unwrap(), 4);
    assert_eq!(&buf, b"foo ");
    assert_eq!(r.read(&mut buf).unwrap(), 3);
    assert_eq!(&buf[..3], b"bar");
    assert_eq!(r.read(&mut buf).unwrap(), 0);
    assert_eq!(r.read(&mut buf).unwrap(), 0);
    assert_eq!(read_all(&mut chained(Vec::new())).unwrap(), b"");

    // An error from a reader is returned and the rest is not read.
    struct Fails;
    impl Read for Fails {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("boom"))
        }
    }
    let mut r = chained(vec![Box::new(Cursor::new(b"a".to_vec())), Box::new(Fails)]);
    assert_eq!(read_all(&mut r).unwrap_err().to_string(), "boom");
}

#[test]
fn multi_writer() {
    // TestMultiWriter / TestMultiWriterSingleChainFlatten (behaviour only)
    let mut a = Vec::new();
    let mut b = Vec::new();
    {
        let mut w = rio::MultiWriter::new(vec![Box::new(&mut a), Box::new(&mut b)]);
        assert_eq!(w.write(b"abc").unwrap(), 3);
        w.write_all(b"def").unwrap();
        w.flush().unwrap();
    }
    assert_eq!(
        (a.as_slice(), b.as_slice()),
        (&b"abcdef"[..], &b"abcdef"[..])
    );

    // A short write is ErrShortWrite; an error stops the later writers.
    let mut c = Vec::new();
    {
        let mut w = rio::MultiWriter::new(vec![Box::new(ShortWriter), Box::new(&mut c)]);
        let err = w.write(b"xy").unwrap_err();
        assert!(rio::Error::ShortWrite.is(&err));
    }
    assert!(c.is_empty());
}

#[test]
fn tee_reader() {
    // TestTeeReader
    let mut sink = Vec::new();
    {
        let mut t = rio::TeeReader::new(Cursor::new(b"hello, world".to_vec()), &mut sink);
        let mut buf = [0u8; 5];
        assert_eq!(t.read(&mut buf).unwrap(), 5);
        assert_eq!(read_all(&mut t).unwrap(), b", world");
    }
    assert_eq!(sink, b"hello, world");
    // A write error is returned from Read.
    struct Failing;
    impl Write for Failing {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("tee failed"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut t = rio::TeeReader::new(Cursor::new(b"abc".to_vec()), Failing);
    assert_eq!(t.read(&mut [0u8; 3]).unwrap_err().to_string(), "tee failed");
}

#[test]
fn discard() {
    // TestNopCloser
    // NopCloser has no counterpart: nothing here needs a Close. ioutil.Discard / io.Discard is std::io::sink.
    let mut d = io::sink();
    assert_eq!(
        copy(&mut d, &mut Cursor::new(vec![0u8; 100_000])).0,
        100_000
    );
}

// ---------------------------------------------------------------- SectionReader / OffsetWriter

#[test]
fn section_reader() {
    // TestSectionReader_ReadAt: (data, off, n, buf_len, at, expected, eof)
    let dat = "a long sample data, 1234567890";
    let l = dat.len();
    #[allow(clippy::type_complexity)]
    let tests: Vec<(&str, i64, i64, usize, i64, &str, bool)> = vec![
        ("", 0, 10, 2, 0, "", true),
        (dat, 0, l as i64, 0, 0, "", false),
        (dat, l as i64, 1, 1, 0, "", true),
        (dat, 0, l as i64 + 2, l, 0, dat, false),
        (dat, 0, l as i64, l / 2, 0, &dat[..l / 2], false),
        (dat, 0, l as i64, l, 0, dat, false),
        (dat, 0, l as i64, l / 2, 2, &dat[2..2 + l / 2], false),
        (dat, 3, l as i64, l / 2, 2, &dat[5..5 + l / 2], false),
        (
            dat,
            3,
            (l / 2) as i64,
            l / 2 - 2,
            2,
            &dat[5..5 + l / 2 - 2],
            false,
        ),
        (
            dat,
            3,
            (l / 2) as i64,
            l / 2 + 2,
            2,
            &dat[5..5 + l / 2 - 2],
            true,
        ),
        (dat, 0, 0, 0, -1, "", true),
        (dat, 0, 0, 0, 1, "", true),
    ];
    for (i, (data, off, n, buf_len, at, exp, want_eof)) in tests.into_iter().enumerate() {
        let r = text::Reader::new(data);
        let s = rio::SectionReader::new(&r, off, n);
        let mut buf = vec![0u8; buf_len];
        let (got, err) = read_at(&s, &mut buf, at as u64);
        assert_eq!(std::str::from_utf8(&buf[..got]).unwrap(), exp, "{i}");
        assert_eq!(
            err.as_ref().is_some_and(rio::is_eof),
            want_eof,
            "{i}: {err:?}"
        );
        assert_eq!(err.is_some(), want_eof, "{i}");
        let (outer, o, nn) = s.outer();
        assert!(std::ptr::eq(*outer, &r) && (o, nn) == (off, n), "{i}");
    }
}

#[test]
fn section_reader_seek_matches_bytes_reader() {
    // TestSectionReader_Seek
    for whence in [0, 1, 2] {
        for offset in -3i64..=4 {
            let mut br = text::Reader::new(b"foo");
            let src = text::Reader::new(b"foo");
            let mut sr = rio::SectionReader::new(&src, 0, 3);
            let pos = seek_from(offset, whence);
            let (b, s) = match pos {
                Ok(pos) => (br.seek(pos), sr.seek(pos)),
                Err(_) => continue,
            };
            assert_eq!(b.is_err(), s.is_err(), "whence={whence} offset={offset}");
            if let (Ok(b), Ok(s)) = (b, s) {
                assert_eq!(b, s, "whence={whence} offset={offset}");
            }
        }
    }
    let src = text::Reader::new(b"foo");
    let mut sr = rio::SectionReader::new(&src, 0, 3);
    assert_eq!(sr.seek(SeekFrom::Start(100)).unwrap(), 100);
    assert_eq!(sr.read(&mut [0u8; 10]).unwrap(), 0);
}

#[test]
fn section_reader_read_seek_size_outer() {
    // TestSectionReader_Seek / Size / Outer
    let src = text::Reader::new(b"0123456789abcdef");
    let mut s = rio::SectionReader::new(&src, 4, 8);
    assert_eq!(s.size(), 8);
    let (outer, off, n) = s.outer();
    assert!(std::ptr::eq(*outer, &src));
    assert_eq!((off, n), (4, 8));

    let mut buf = [0u8; 4];
    assert_eq!(s.read(&mut buf).unwrap(), 4);
    assert_eq!(&buf, b"4567");
    assert_eq!(s.seek(SeekFrom::Current(-2)).unwrap(), 2);
    assert_eq!(s.read(&mut buf).unwrap(), 4);
    assert_eq!(&buf, b"6789");
    assert_eq!(s.seek(SeekFrom::End(-1)).unwrap(), 7);
    assert_eq!(s.read(&mut buf).unwrap(), 1);
    assert_eq!(buf[0], b'b');
    assert_eq!(s.read(&mut buf).unwrap(), 0);
    assert_eq!(s.seek(SeekFrom::Start(3)).unwrap(), 3);
    assert_eq!(
        s.seek(SeekFrom::Current(-4)).unwrap_err().to_string(),
        "Seek: invalid offset"
    );
    // Seeking past the end is allowed and reads EOF.
    assert_eq!(s.seek(SeekFrom::Start(100)).unwrap(), 100);
    assert_eq!(s.read(&mut buf).unwrap(), 0);

    // An enormous section does not overflow; the limit saturates at i64::MAX.
    let big = rio::SectionReader::new(&src, i64::MAX - 2, 10);
    assert_eq!(big.size(), 2);
    let err = big.read_at(&mut buf, 0).unwrap_err();
    assert_eq!(err.read(), 0);
    assert!(rio::is_eof(&err.into_source()));
}

#[test]
fn section_reader_over_a_file() {
    let mut f = temp_file("section");
    f.0.write_all(b"0123456789").unwrap();
    let mut s = rio::SectionReader::new(&f.0, 3, 4);
    assert_eq!(read_all(&mut s).unwrap(), b"3456");
    let err = ReadAt::read_at(&f.0, &mut [0u8; 4], 8).unwrap_err();
    assert_eq!(err.read(), 2);
    assert!(rio::is_eof(&err.into_source()));
    std::fs::remove_file(&f.1).unwrap();
}

#[derive(Default)]
struct Mem(Vec<u8>);

impl WriteAt for Mem {
    fn write_at(&mut self, p: &[u8], off: u64) -> io::Result<()> {
        if off > i64::MAX as u64 {
            return Err(io::Error::other("negative offset"));
        }
        let end = off as usize + p.len();
        if self.0.len() < end {
            self.0.resize(end, 0);
        }
        self.0[off as usize..end].copy_from_slice(p);
        Ok(())
    }
}

#[test]
fn offset_writer() {
    // TestOffsetWriter_Seek / WriteAt / Write
    let mut o = rio::OffsetWriter::new(Mem::default(), 2);
    assert_eq!(o.write(b"ab").unwrap(), 2);
    assert_eq!(o.seek(SeekFrom::Current(1)).unwrap(), 3);
    assert_eq!(o.write(b"c").unwrap(), 1);
    assert_eq!(o.seek(SeekFrom::Start(0)).unwrap(), 0);
    o.write_all(b"X").unwrap();
    o.write_at(b"Z", 6).unwrap();
    assert_eq!(
        o.seek(SeekFrom::Current(-10)).unwrap_err().to_string(),
        "Seek: invalid offset"
    );
    assert_eq!(
        o.seek(SeekFrom::End(0)).unwrap_err().to_string(),
        "Seek: invalid whence"
    );
    let err = o.write_at(b"q", -1i64 as u64).unwrap_err();
    assert_eq!(err.to_string(), "Seek: invalid offset");
    assert_eq!(o.into_inner().0, b"\0\0Xb\0c\0\0Z");
}

#[test]
fn reader_at_for_readers_and_files() {
    let r = text::Reader::new(b"hello");
    let mut b = [0u8; 3];
    assert_eq!(ReadAt::read_at(&r, &mut b, 2).unwrap(), 3);
    assert_eq!(&b, b"llo");
    let (n, err) = read_at(&r, &mut b, 4);
    assert_eq!((n, rio::is_eof(&err.unwrap())), (1, true));
    let sr = text::Reader::new("hello");
    assert_eq!(ReadAt::read_at(&sr, &mut b, 0).unwrap(), 3);
    let (n, err) = read_at(&b"abc"[..], &mut b, 1);
    assert_eq!((n, rio::is_eof(&err.unwrap())), (2, true));

    // WriteAt for files: unix pwrite semantics, holes read back as zeros.
    let (mut f, path) = temp_file("writerat");
    WriteAt::write_at(&mut f, b"xy", 3).unwrap();
    let mut all = Vec::new();
    f.seek(SeekFrom::Start(0)).unwrap();
    f.read_to_end(&mut all).unwrap();
    assert_eq!(all, b"\0\0\0xy");
    // Offsets above i64::MAX are Go's negative offsets.
    assert!(ReadAt::read_at(&f, &mut [0u8; 1], -1i64 as u64).is_err());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn rune_scanner_traits() {
    fn roundtrip<T: RuneScanner>(t: &mut T) -> (char, usize) {
        let r = t.read_rune().unwrap();
        t.unread_rune().unwrap();
        r
    }
    assert_eq!(roundtrip(&mut text::Reader::new("é".as_bytes())), ('é', 2));
    assert_eq!(roundtrip(&mut text::Reader::new("é")), ('é', 2));
    assert_eq!(
        roundtrip(&mut text::Buffer::from_vec("é".as_bytes().to_vec())),
        ('é', 2)
    );
    let rr: &mut dyn RuneReader = &mut text::Reader::new("世");
    assert_eq!(rr.read_rune().unwrap(), ('世', 3));
}

// ---------------------------------------------------------------- Pipe

#[test]
fn pipe_transfers_data_in_order() {
    // TestPipe1 / TestPipe2
    let (mut r, w) = rio::pipe();
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        for chunk in [&b"hello"[..], b", ", b"world"] {
            let (n, err) = counted_usize(w.write_shared(chunk));
            tx.send((n, err.is_none())).unwrap();
        }
        w.close();
    });
    let mut got = Vec::new();
    r.read_to_end(&mut got).unwrap();
    handle.join().unwrap();
    assert_eq!(got, b"hello, world");
    assert_eq!(
        rx.iter().collect::<Vec<_>>(),
        [(5, true), (2, true), (5, true)]
    );
}

#[test]
fn pipe_read_returns_at_most_the_write() {
    let (mut r, mut w) = rio::pipe();
    let handle = thread::spawn(move || {
        w.write_all(b"abcdef").unwrap();
        w.write_all(b"gh").unwrap();
        w.close();
    });
    let mut buf = [0u8; 4];
    // Each Read returns min(len(buf), bytes left of the current Write).
    let mut sizes = Vec::new();
    loop {
        let n = r.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        sizes.push(n);
    }
    handle.join().unwrap();
    assert_eq!(sizes, [4, 2, 2]);
}

#[test]
fn pipe_zero_length_write_reads_zero_bytes_like_go() {
    let (r, mut w) = rio::pipe();
    let handle = thread::spawn(move || {
        assert_eq!(w.write(b"").unwrap(), 0);
        w.write_all(b"x").unwrap();
        w.close();
    });
    let mut buf = [0u8; 4];
    // Go: the first Read consumes the empty Write and returns (0, nil).
    assert_eq!(r.read_raw(&mut buf).unwrap(), 0);
    assert_eq!(r.read_raw(&mut buf).unwrap(), 1);
    assert!(rio::is_eof(&r.read_raw(&mut buf).unwrap_err()));
    handle.join().unwrap();
}

#[test]
fn pipe_close_semantics() {
    // TestPipeReadClose / TestPipeWriteClose
    // Reader closed: pending and later writes fail with ErrClosedPipe.
    let (r, mut w) = rio::pipe();
    r.close();
    let (n, err) = counted_usize(w.write_shared(b"x"));
    assert_eq!(n, 0);
    assert!(is_err(&err, rio::Error::ClosedPipe));
    assert!(rio::Error::ClosedPipe.is(&w.write(b"x").unwrap_err()));

    // Reader closed with an error: writes return that error.
    let (r, w) = rio::pipe();
    r.close_with_error(Some(io::Error::other("reader closed")));
    let (_, err) = counted_usize(w.write_shared(b"x"));
    assert_eq!(err.unwrap().to_string(), "reader closed");
    // Only the first close error counts.
    r.close_with_error(Some(io::Error::other("second")));
    let (_, err) = counted_usize(w.write_shared(b"x"));
    assert_eq!(err.unwrap().to_string(), "reader closed");

    // Writer closed: reads see EOF, then keep seeing it.
    let (mut r, w) = rio::pipe();
    w.close();
    let mut buf = [0u8; 1];
    assert_eq!(r.read(&mut buf).unwrap(), 0);
    assert_eq!(r.read(&mut buf).unwrap(), 0);
    // Writer closed with an error: reads return it.
    let (mut r, w) = rio::pipe();
    w.close_with_error(Some(io::Error::other("writer closed")));
    assert_eq!(r.read(&mut buf).unwrap_err().to_string(), "writer closed");
    assert_eq!(r.read(&mut buf).unwrap_err().to_string(), "writer closed");
    // Writing to a closed writer is ErrClosedPipe.
    let (n, err) = counted_usize(w.write_shared(b"x"));
    assert_eq!(n, 0);
    assert!(is_err(&err, rio::Error::ClosedPipe));
    // Reading after closing the reader is ErrClosedPipe, not the writer's error.
    let (mut r, w) = rio::pipe();
    w.close_with_error(Some(io::Error::other("writer closed")));
    r.close();
    assert!(rio::Error::ClosedPipe.is(&r.read(&mut buf).unwrap_err()));
}

#[test]
fn pipe_blocked_write_is_released_by_close() {
    let (r, w) = rio::pipe();
    let handle = thread::spawn(move || counted_usize(w.write_shared(b"never read")));
    // The write cannot complete until the reader reads or closes.
    r.close();
    let (n, err) = handle.join().unwrap();
    assert_eq!(n, 0);
    assert!(is_err(&err, rio::Error::ClosedPipe));

    // Partially consumed write returns the count consumed.
    let (mut r, w) = rio::pipe();
    let w2 = w.clone();
    let handle = thread::spawn(move || counted_usize(w2.write_shared(b"abcdef")));
    let mut buf = [0u8; 2];
    assert_eq!(r.read(&mut buf).unwrap(), 2);
    r.close();
    let (n, err) = handle.join().unwrap();
    assert_eq!(n, 2);
    assert!(is_err(&err, rio::Error::ClosedPipe));
}

#[test]
fn pipe_writers_are_serialized() {
    // TestPipeConcurrent-style: several writers, each message arrives whole.
    let (mut r, w) = rio::pipe();
    let mut handles = Vec::new();
    for id in 0..4u8 {
        let mut w = w.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..25 {
                w.write_all(&[id; 7]).unwrap();
            }
        }));
    }
    let closer = {
        let w = w.clone();
        thread::spawn(move || {
            for h in handles {
                h.join().unwrap();
            }
            w.close();
        })
    };
    let mut got = Vec::new();
    r.read_to_end(&mut got).unwrap();
    closer.join().unwrap();
    assert_eq!(got.len(), 4 * 25 * 7);
    for chunk in got.chunks(7) {
        assert!(
            chunk.iter().all(|&b| b == chunk[0]),
            "interleaved write: {chunk:?}"
        );
    }
}

#[test]
fn pipe_zero_length_write_waits_for_a_read() {
    let (mut r, mut w) = rio::pipe();
    let handle = thread::spawn(move || {
        let n = w.write(b"").unwrap();
        w.write_all(b"x").unwrap();
        w.close();
        n
    });
    // std's Read would take Ok(0) for EOF, so the reader skips the empty write.
    let mut got = Vec::new();
    r.read_to_end(&mut got).unwrap();
    assert_eq!(handle.join().unwrap(), 0);
    assert_eq!(got, b"x");
}

#[test]
fn pipe_halves_close_explicitly() {
    let (mut r, w) = rio::pipe();
    w.close();
    assert_eq!(r.read(&mut [0u8; 1]).unwrap(), 0);
    r.close();
}

#[test]
fn std_io_traits_are_reexported() {
    use rust_stdlib::io::Read as _;
    let mut out = Vec::new();
    std::io::Cursor::new(b"abc").read_to_end(&mut out).unwrap();
    assert_eq!(out, b"abc");
    fn takes_std<R: std::io::Read>(_: R) {}
    fn takes_ours<R: rust_stdlib::io::Read>(r: R) {
        takes_std(r)
    }
    takes_ours(&b""[..]);
}

#[test]
fn cursor_positional_io() {
    use rust_stdlib::io::{Error, ReadAt, WriteAt};
    use std::io::Cursor;

    let mut c = Cursor::new(b"hello world".to_vec());
    c.set_position(3);
    let mut buf = [0u8; 5];
    assert_eq!(c.read_at(&mut buf, 6).unwrap(), 5);
    assert_eq!(&buf, b"world");
    assert_eq!(c.position(), 3);
    let err = c.read_at(&mut buf, 8).unwrap_err();
    assert_eq!(err.read(), 3);
    assert!(Error::Eof.is(err.source()));
    assert_eq!(
        Cursor::new(&b"abc"[..]).read_at(&mut buf[..2], 1).unwrap(),
        2
    );

    c.write_at(b"HE", 0).unwrap();
    c.write_at(b"!", 13).unwrap();
    assert_eq!(c.get_ref(), b"HEllo world\0\0!");
    assert_eq!(c.position(), 3);

    let mut fixed = [0u8; 4];
    let mut c = Cursor::new(&mut fixed[..]);
    c.write_at(b"ab", 1).unwrap();
    let err = c.write_at(b"xyz", 2).unwrap_err();
    assert!(Error::ShortWrite.is(&err));
    assert_eq!(fixed, [0, b'a', b'x', b'y']);
}
