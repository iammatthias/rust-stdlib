//! Tests for `rust_stdlib::bufio`, ported from Go's `bufio_test.go` and
//! `scan_test.go` (BSD license, see NOTICE). Go's differential coverage is in
//! `tools/io_check.py`.

use rust_stdlib::bufio::{self, Error, Reader, Scanner, Split, Writer, MAX_SCAN_TOKEN_SIZE};
use rust_stdlib::io::{self as rio, RuneScanner};
use std::io::{self, BufRead, Cursor, Read, Write};

/// Returns at most `max` bytes per read (Go's `slowReader`/`oneByteReader`).
struct Slow<R> {
    max: usize,
    inner: R,
}

impl<R: Read> Read for Slow<R> {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        let n = p.len().min(self.max);
        self.inner.read(&mut p[..n])
    }
}

fn slow(max: usize, text: &[u8]) -> Slow<Cursor<Vec<u8>>> {
    Slow {
        max,
        inner: Cursor::new(text.to_vec()),
    }
}

fn is(err: &Option<io::Error>, want: Error) -> bool {
    err.as_ref().is_some_and(|e| want.is(e))
}

fn is_eof(err: &Option<io::Error>) -> bool {
    err.as_ref().is_some_and(rio::is_eof)
}

/// Go's `(data, err)` shapes for the methods that now return `Result`.
trait GoReader {
    fn peek_go(&mut self, n: usize) -> (Vec<u8>, Option<io::Error>);
    fn read_slice_go(&mut self, delim: u8) -> (Vec<u8>, Option<io::Error>);
    fn read_line_go(&mut self) -> (Vec<u8>, bool, Option<io::Error>);
    fn read_bytes_go(&mut self, delim: u8) -> (Vec<u8>, Option<io::Error>);
    fn read_string_go(&mut self, delim: u8) -> (String, Option<io::Error>);
    fn discard_go(&mut self, n: usize) -> (usize, Option<io::Error>);
}

impl<R: Read> GoReader for Reader<R> {
    fn peek_go(&mut self, n: usize) -> (Vec<u8>, Option<io::Error>) {
        let err = self.peek(n).err();
        let b = self.buffer();
        (b[..b.len().min(n)].to_vec(), err)
    }
    fn read_slice_go(&mut self, delim: u8) -> (Vec<u8>, Option<io::Error>) {
        match self.read_slice(delim) {
            Ok(b) => (b.to_vec(), None),
            Err(e) => (e.data().to_vec(), Some(e.into_source())),
        }
    }
    fn read_line_go(&mut self) -> (Vec<u8>, bool, Option<io::Error>) {
        match self.read_line_bytes() {
            Ok((b, prefix)) => (b.to_vec(), prefix, None),
            Err(e) => (Vec::new(), false, Some(e)),
        }
    }
    fn read_bytes_go(&mut self, delim: u8) -> (Vec<u8>, Option<io::Error>) {
        let mut b = Vec::new();
        let err = match self.read_until(delim, &mut b) {
            Err(e) => Some(e),
            Ok(_) if b.last() != Some(&delim) => Some(rio::eof()),
            Ok(_) => None,
        };
        (b, err)
    }
    fn read_string_go(&mut self, delim: u8) -> (String, Option<io::Error>) {
        let (b, err) = self.read_bytes_go(delim);
        (String::from_utf8(b).unwrap(), err)
    }
    fn discard_go(&mut self, n: usize) -> (usize, Option<io::Error>) {
        match self.discard(n) {
            Ok(n) => (n, None),
            Err(e) => (e.read(), Some(e.into_source())),
        }
    }
}

trait GoWriter {
    fn write_go(&mut self, p: &[u8]) -> (usize, Option<io::Error>);
}

impl<W: Write> GoWriter for Writer<W> {
    fn write_go(&mut self, p: &[u8]) -> (usize, Option<io::Error>) {
        match self.write_counted(p) {
            Ok(n) => (n, None),
            Err(e) => (e.written() as usize, Some(e.into_source())),
        }
    }
}

const TEXT: &str =
    "The quick brown fox jumps over the lazy dog.\nThe quick brown fox jumps over the lazy dog.\n";

// ---------------------------------------------------------------- Reader

#[test]
fn reader_simple_and_sizes() {
    // TestReaderSimple and TestReader: reads of every size from readers
    // that return 1, 2, 3, 7 or all bytes at a time, over many buffer sizes.
    let mut all = Reader::new(TEXT.as_bytes());
    let mut data = Vec::new();
    all.read_to_end(&mut data).unwrap();
    assert_eq!(data, TEXT.as_bytes());

    let text: String = (0..1000)
        .map(|i| char::from(b'a' + (i % 26) as u8))
        .collect();
    for max in [1, 2, 3, 7, 4096] {
        for bufsize in [16, 23, 32, 46, 64, 93, 128, 1024, 4096] {
            for readsize in [1, 2, 3, 5, 100, 1000] {
                let mut r = Reader::with_size(slow(max, text.as_bytes()), bufsize);
                let mut got = Vec::new();
                let mut p = vec![0; readsize];
                loop {
                    let n = r.read(&mut p).unwrap();
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&p[..n]);
                }
                assert_eq!(
                    got,
                    text.as_bytes(),
                    "max={max} bufsize={bufsize} readsize={readsize}"
                );
            }
        }
    }
}

#[test]
fn read_rune_and_unread_rune() {
    // TestReadRune / TestUnreadRune
    let segments = ["Hello, world:", "日本語", "\u{80}", "\u{FFFD}", "abc"];
    let data: Vec<u8> = segments.concat().into_bytes();
    let mut r = Reader::new(Cursor::new(data.clone()));
    let mut runes = Vec::new();
    let mut total = 0;
    loop {
        match r.read_rune() {
            Ok((c, n)) => {
                total += n;
                runes.push(c);
            }
            Err(e) => {
                assert!(rio::is_eof(&e));
                break;
            }
        }
    }
    assert_eq!(total, data.len());
    assert!(runes.contains(&'世') || runes.contains(&'本'));

    // Unread every rune and read it again.
    let mut r = Reader::with_size(Cursor::new("日本語abc".as_bytes().to_vec()), 16);
    let mut seen = String::new();
    while let Ok((c, n)) = r.read_rune() {
        r.unread_rune().unwrap();
        let (c2, n2) = r.read_rune().unwrap();
        assert_eq!((c, n), (c2, n2));
        seen.push(c);
    }
    assert_eq!(seen, "日本語abc");
    // At the end, after EOF, UnreadRune fails (TestUnreadRuneAtEOF).
    assert!(is(&r.unread_rune().err(), Error::InvalidUnreadRune));
}

#[test]
fn unread_rune_and_byte_rules() {
    // TestNoUnreadRuneAfterPeek / Discard / WriteTo, TestUnreadByte*
    let new = || Reader::new(Cursor::new(b"abcdefghijklmnop".to_vec()));
    let mut r = new();
    r.read_rune().unwrap();
    r.peek_go(1);
    assert!(is(&r.unread_rune().err(), Error::InvalidUnreadRune));
    let mut r = new();
    r.read_byte().unwrap();
    r.peek_go(1);
    assert!(is(&r.unread_byte().err(), Error::InvalidUnreadByte));
    let mut r = new();
    r.read_rune().unwrap();
    r.discard_go(1);
    assert!(is(&r.unread_rune().err(), Error::InvalidUnreadRune));
    let mut r = new();
    r.read_byte().unwrap();
    r.discard_go(1);
    assert!(is(&r.unread_byte().err(), Error::InvalidUnreadByte));
    let mut r = new();
    r.read_rune().unwrap();
    r.write_to(&mut io::sink()).unwrap();
    assert!(is(&r.unread_rune().err(), Error::InvalidUnreadRune));
    let mut r = new();
    r.read_byte().unwrap();
    r.write_to(&mut io::sink()).unwrap();
    assert!(is(&r.unread_byte().err(), Error::InvalidUnreadByte));

    // TestUnreadByte: unread after reading each way, never twice in a row.
    let mut r = Reader::new(Cursor::new(b"abcdefg".to_vec()));
    assert!(is(&r.unread_byte().err(), Error::InvalidUnreadByte));
    assert_eq!(r.read_byte().unwrap(), b'a');
    r.unread_byte().unwrap();
    assert!(is(&r.unread_byte().err(), Error::InvalidUnreadByte));
    let mut p = [0; 3];
    assert_eq!(r.read(&mut p).unwrap(), 3);
    r.unread_byte().unwrap();
    assert_eq!(r.read_byte().unwrap(), b'c');
    let (line, err) = r.read_slice_go(b'e');
    assert_eq!((line, err.is_none()), (b"de".to_vec(), true));
    r.unread_byte().unwrap();
    assert_eq!(r.read_byte().unwrap(), b'e');

    // ReadRune then UnreadRune then UnreadByte fails (rune unread clears both).
    let mut r = Reader::new(Cursor::new("é".as_bytes().to_vec()));
    r.read_rune().unwrap();
    r.unread_rune().unwrap();
    assert!(is(&r.unread_byte().err(), Error::InvalidUnreadByte));
}

#[test]
fn peek_table() {
    // TestPeek
    let mut buf = Reader::with_size(Cursor::new(b"abcdefghijklmnop".to_vec()), 16);
    let (s, err) = buf.peek_go(1);
    assert_eq!((s, err.is_none()), (b"a".to_vec(), true));
    let (s, err) = buf.peek_go(4);
    assert_eq!((s, err.is_none()), (b"abcd".to_vec(), true));
    let (s, err) = buf.peek_go(32);
    assert_eq!(s, b"abcdefghijklmnop");
    assert!(is(&err, Error::BufferFull));
    let mut p = [0; 10];
    assert_eq!(buf.read(&mut p[..3]).unwrap(), 3);
    assert_eq!(&p[..3], b"abc");
    assert_eq!(buf.peek_go(1).0, b"d");
    assert_eq!(buf.peek_go(2).0, b"de");
    assert_eq!(buf.read(&mut p[..3]).unwrap(), 3);
    assert_eq!(&p[..3], b"def");
    assert_eq!(buf.peek_go(4).0, b"ghij");
    assert_eq!(buf.read(&mut p).unwrap(), 10);
    assert_eq!(&p, b"ghijklmnop");
    let (s, err) = buf.peek_go(0);
    assert!(s.is_empty() && err.is_none());
    let (s, err) = buf.peek_go(1);
    assert!(s.is_empty() && is_eof(&err));
}

#[test]
fn peek_then_unread_rune() {
    // TestPeekThenUnreadRune
    let mut r = Reader::with_size(Cursor::new("x".as_bytes().to_vec()), 16);
    r.read_rune().unwrap();
    r.unread_rune().unwrap();
    r.peek_go(1);
    assert!(is(&r.unread_rune().err(), Error::InvalidUnreadRune));
    assert_eq!(r.read_rune().unwrap(), ('x', 1));
}

#[test]
fn buffer_full_and_line_too_long() {
    // TestBufferFull / TestLineTooLong
    let long =
        "And now, hello, world! It is the time for all good men to come to the aid of their party";
    let mut r = Reader::with_size(Cursor::new(long.as_bytes().to_vec()), 16);
    let (line, err) = r.read_slice_go(b',');
    assert_eq!(line, b"And now,");
    assert!(err.is_none());
    let (line, err) = r.read_slice_go(b'!');
    assert_eq!(line, b" hello, world!");
    assert!(err.is_none());
    let (line, err) = r.read_slice_go(b'|');
    assert_eq!(line.len(), 16);
    assert!(is(&err, Error::BufferFull));

    let data = vec![b'x'; 300];
    let mut r = Reader::with_size(Cursor::new(data), 16);
    let (line, prefix, err) = r.read_line_go();
    assert_eq!((line.len(), prefix, err.is_none()), (16, true, true));
}

#[test]
fn read_line_newlines() {
    // TestReadLineNewlines
    for (input, lines) in [
        ("abc\ndef\n", vec!["abc", "def"]),
        ("abc\r\ndef\r\n", vec!["abc", "def"]),
        ("abc\r\n\r\ndef", vec!["abc", "", "def"]),
        ("\n", vec![""]),
    ] {
        let mut r = Reader::new(Cursor::new(input.as_bytes().to_vec()));
        for want in lines {
            let (line, prefix, err) = r.read_line_go();
            assert_eq!(line, want.as_bytes());
            assert!(!prefix && err.is_none());
        }
        let (line, prefix, err) = r.read_line_go();
        assert!(line.is_empty() && !prefix && is_eof(&err));
    }
    // A "\r" at the very end of a full buffer is pushed back (isPrefix).
    let mut text = vec![b'a'; 15];
    text.extend_from_slice(b"\r\nz\n");
    let mut r = Reader::with_size(Cursor::new(text), 16);
    let (l1, p1, _) = r.read_line_go();
    assert_eq!((l1.len(), p1), (15, true));
    let (l2, p2, _) = r.read_line_go();
    assert_eq!((l2.len(), p2), (0, false));
    let (l3, p3, _) = r.read_line_go();
    assert_eq!((l3, p3), (b"z".to_vec(), false));
}

#[test]
fn read_line_non_nil_line_or_error() {
    // TestReadLineNonNilLineOrError: at EOF the line is empty and the error EOF.
    let mut r = Reader::new(Cursor::new(b"line 1\n".to_vec()));
    for i in 0..2 {
        let (line, _, err) = r.read_line_go();
        if i == 0 {
            assert_eq!(line, b"line 1");
            assert!(err.is_none());
        } else {
            assert!(line.is_empty() && is_eof(&err));
        }
    }
}

#[test]
fn read_bytes_and_string_with_delimiter() {
    // TestReadString-style: long lines spanning several buffer fills.
    let text = format!("{}\n{}\nlast", "x".repeat(100), "y".repeat(40));
    let mut r = Reader::with_size(Cursor::new(text.as_bytes().to_vec()), 16);
    let (b, err) = r.read_bytes_go(b'\n');
    assert_eq!(b.len(), 101);
    assert!(err.is_none());
    let (s, err) = r.read_string_go(b'\n');
    assert_eq!(s.len(), 41);
    assert!(err.is_none());
    let (s, err) = r.read_string_go(b'\n');
    assert_eq!(s, "last");
    assert!(is_eof(&err));
}

#[test]
fn discard_table() {
    // TestReaderDiscard
    let input = "abcdefghijklmnopqrstuvwxyz";
    let mut r = Reader::with_size(Cursor::new(input.as_bytes().to_vec()), 16);
    let (n, err) = r.discard_go(0);
    assert_eq!((n, err.is_none()), (0, true));
    let (n, err) = r.discard_go(5);
    assert_eq!((n, err.is_none()), (5, true));
    assert_eq!(r.read_byte().unwrap(), b'f');
    let (n, err) = r.discard_go(30);
    assert_eq!(n, 20);
    assert!(is_eof(&err));
    let (n, err) = r.discard_go(1);
    assert_eq!(n, 0);
    assert!(is_eof(&err));
}

#[test]
fn reader_size_and_reset() {
    // TestReaderSize / TestReaderReset
    assert_eq!(Reader::new(io::empty()).size(), 4096);
    assert_eq!(Reader::with_size(io::empty(), 1).size(), 16);
    assert_eq!(Reader::with_size(io::empty(), 123).size(), 123);

    let mut r = Reader::new(Cursor::new(b"foo foo".to_vec()));
    let mut buf = [0; 3];
    assert_eq!(r.read(&mut buf).unwrap(), 3);
    assert_eq!(&buf, b"foo");
    let old = r.reset(Cursor::new(b"bar bar".to_vec()));
    assert_eq!(old.position(), 7);
    let mut all = Vec::new();
    r.read_to_end(&mut all).unwrap();
    assert_eq!(all, b"bar bar");
    assert_eq!(r.buffered(), 0);
}

struct ErrAfter {
    left: usize,
}

impl Read for ErrAfter {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 {
            return Err(io::Error::other("boom"));
        }
        let n = p.len().min(self.left);
        p[..n].fill(b'z');
        self.left -= n;
        Ok(n)
    }
}

#[test]
fn reader_clears_error_once() {
    // TestReaderClearError: an error is reported once, then reading resumes.
    let mut r = Reader::new(ErrAfter { left: 2 });
    let mut buf = [0; 8];
    assert_eq!(r.read(&mut buf).unwrap(), 2);
    assert!(r.read(&mut buf).is_err());
    // ErrAfter keeps failing, so the next read fails again (new error).
    assert!(r.read(&mut buf).is_err());
    // Peek reports the error only when the data is short.
    let mut r = Reader::with_size(ErrAfter { left: 4 }, 16);
    let (s, err) = r.peek_go(4);
    assert_eq!((s, err.is_none()), (b"zzzz".to_vec(), true));
    let (s, err) = r.peek_go(8);
    assert_eq!(s, b"zzzz");
    assert_eq!(err.unwrap().to_string(), "boom");
}

#[test]
fn reader_implements_std_traits() {
    let mut r = Reader::with_size(Cursor::new(b"a\nb\nc".to_vec()), 16);
    let lines: Vec<String> = (&mut r).lines().map(Result::unwrap).collect();
    assert_eq!(lines, ["a", "b", "c"]);
    let mut r = Reader::new(Cursor::new(b"xyz".to_vec()));
    assert_eq!(r.fill_buf().unwrap(), b"xyz");
    r.consume(1);
    r.unread_byte().unwrap();
    assert_eq!(r.fill_buf().unwrap(), b"xyz");
    let mut s = String::new();
    r.read_to_string(&mut s).unwrap();
    assert_eq!(s, "xyz");
    // The io interface for runes.
    fn takes_scanners<T: RuneScanner>(t: &mut T) -> (u8, char) {
        let c = t.read_rune().unwrap().0;
        t.unread_rune().unwrap();
        (c as u32 as u8, c)
    }
    assert_eq!(
        takes_scanners(&mut Reader::new(Cursor::new("é".as_bytes().to_vec()))),
        (0xe9, 'é')
    );
}

#[test]
fn reader_write_to() {
    // TestReaderWriteTo
    let mut r = Reader::with_size(slow(3, TEXT.as_bytes()), 16);
    let mut dst = Vec::new();
    assert_eq!(r.write_to(&mut dst).unwrap(), TEXT.len() as u64);
    assert_eq!(dst, TEXT.as_bytes());

    // Errors from the reader and from the writer are returned.
    let mut r = Reader::new(ErrAfter { left: 3 });
    let mut dst = Vec::new();
    assert_eq!(r.write_to(&mut dst).unwrap_err().to_string(), "boom");
    assert_eq!(dst, b"zzz");

    struct FailWriter;
    impl Write for FailWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("write failed"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut r = Reader::new(Cursor::new(b"abc".to_vec()));
    assert_eq!(
        r.write_to(&mut FailWriter).unwrap_err().to_string(),
        "write failed"
    );
}

#[test]
fn large_read_bypasses_buffer() {
    // A read at least as large as the buffer, with an empty buffer, goes
    // straight to the underlying reader (observable through its call sizes).
    struct Spy(Vec<usize>);
    impl Read for Spy {
        fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
            self.0.push(p.len());
            let n = p.len().min(3);
            p[..n].fill(b'q');
            Ok(n)
        }
    }
    let mut r = Reader::with_size(Spy(Vec::new()), 16);
    let mut big = [0; 32];
    assert_eq!(r.read(&mut big).unwrap(), 3);
    let mut small = [0; 4];
    assert_eq!(r.read(&mut small).unwrap(), 3);
    assert_eq!(r.get_ref().0, [32, 16]);
}

// ---------------------------------------------------------------- Writer

/// A writer that accepts `limit` bytes in total and then fails.
struct Limited {
    got: Vec<u8>,
    limit: usize,
}

impl Write for Limited {
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        let room = self.limit - self.got.len();
        if room == 0 {
            return Err(io::Error::other("full"));
        }
        let n = p.len().min(room);
        self.got.extend_from_slice(&p[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn writer_sizes() {
    // TestWriter: every buffer size and write size produces the same bytes.
    let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
    for bufsize in [1, 2, 3, 4, 5, 7, 16, 23, 100, 1024] {
        for writesize in [1, 2, 3, 7, 16, 100, 1000] {
            let mut w = Writer::with_size(Vec::new(), bufsize);
            for chunk in data.chunks(writesize) {
                assert_eq!(w.write(chunk).unwrap(), chunk.len());
            }
            assert_eq!(w.buffered() + w.available(), w.size());
            w.flush().unwrap();
            assert_eq!(
                w.get_ref(),
                &data,
                "bufsize={bufsize} writesize={writesize}"
            );
        }
    }
}

#[test]
fn writer_errors_are_sticky() {
    // TestWriteErrors
    let mut w = Writer::with_size(
        Limited {
            got: Vec::new(),
            limit: 5,
        },
        4,
    );
    assert_eq!(w.write(b"abc").unwrap(), 3);
    let (n, err) = w.write_go(b"defghij");
    assert!(n >= 1);
    assert_eq!(err.unwrap().to_string(), "full");
    // Every later call returns the same error.
    assert_eq!(w.write_all(b"x").unwrap_err().to_string(), "full");
    assert_eq!(w.write_string("x").unwrap_err().to_string(), "full");
    assert_eq!(w.flush().unwrap_err().to_string(), "full");
    assert_eq!(w.write_char('é').unwrap_err().to_string(), "full");
    // Reset clears it.
    let old = w.reset(Limited {
        got: Vec::new(),
        limit: 100,
    });
    assert_eq!(old.got, b"abcde");
    w.write_string("ok").unwrap();
    w.flush().unwrap();
    assert_eq!(w.get_ref().got, b"ok");
}

#[test]
fn writer_short_write_is_error() {
    struct Short;
    impl Write for Short {
        fn write(&mut self, p: &[u8]) -> io::Result<usize> {
            Ok(p.len().min(1))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut w = Writer::with_size(Short, 8);
    w.write_all(b"abc").unwrap();
    let err = w.flush().unwrap_err();
    assert!(rio::Error::ShortWrite.is(&err));
    assert_eq!(w.buffered(), 2);
}

#[test]
fn writer_rune_byte_string_available() {
    // TestReadWriteRune, TestWriteString, TestWriterAppend
    let mut w = Writer::with_size(Vec::new(), 4);
    for c in ['a', 'é', '世', '😀', '\u{7f}', '\u{80}'] {
        let n = w.write_char(c).unwrap();
        assert_eq!(n, c.len_utf8());
    }
    w.write_all(b"!").unwrap();
    assert_eq!(w.write_string("héllo").unwrap(), 6);
    w.flush().unwrap();
    assert_eq!(
        String::from_utf8(w.get_ref().clone()).unwrap(),
        "aé世😀\u{7f}\u{80}!héllo"
    );

    let mut w = Writer::with_size(Vec::new(), 16);
    let mut ab = w.available_buffer();
    assert!(ab.is_empty() && ab.capacity() == 16);
    ab.extend_from_slice(b"1234");
    w.write_all(&ab).unwrap();
    assert_eq!((w.buffered(), w.available()), (4, 12));
}

#[test]
fn writer_read_from() {
    // TestWriterReadFrom and TestWriterReadFromUntilEOF
    for bufsize in [16, 23, 64, 4096] {
        let mut w = Writer::with_size(Vec::new(), bufsize);
        let mut src = slow(5, TEXT.as_bytes());
        assert_eq!(w.read_from(&mut src).unwrap(), TEXT.len() as u64);
        w.flush().unwrap();
        assert_eq!(w.get_ref(), TEXT.as_bytes());
    }
    // A source error is returned, with the data read so far still buffered.
    let mut w = Writer::with_size(Vec::new(), 16);
    let err = w.read_from(&mut ErrAfter { left: 5 }).unwrap_err();
    assert_eq!(err.to_string(), "boom");
    w.flush().unwrap();
    assert_eq!(w.get_ref(), b"zzzzz");
    // A full buffer at EOF is flushed.
    let mut w = Writer::with_size(Vec::new(), 16);
    w.read_from(&mut Cursor::new(vec![b'k'; 16])).unwrap();
    assert_eq!(w.buffered(), 0);
    assert_eq!(w.get_ref().len(), 16);
}

#[test]
fn read_writer() {
    let r = Reader::new(Cursor::new(b"in".to_vec()));
    let w = Writer::new(Vec::new());
    let mut rw = bufio::ReadWriter::new(r, w);
    let mut got = String::new();
    rw.read_to_string(&mut got).unwrap();
    assert_eq!(got, "in");
    rw.write_all(b"out").unwrap();
    rw.flush().unwrap();
    assert_eq!(rw.writer.get_ref(), b"out");
    assert_eq!(rw.reader.buffered(), 0);
}

// ---------------------------------------------------------------- Scanner

const SCAN_TESTS: &[&str] = &[
    "",
    "a",
    "¼",
    "☹",
    "\u{FFFD}",
    "abcdefgh",
    "abc def\n\t\tgh    ",
];

/// Drains the scanner: the tokens and the error that ended it, if any
/// (Go's `Scan` loop followed by `Err`).
fn scan_all<R: Read>(s: Scanner<R>) -> (Vec<Vec<u8>>, Option<io::Error>) {
    let mut out = Vec::new();
    for tok in s {
        match tok {
            Ok(t) => out.push(t),
            Err(e) => return (out, Some(e)),
        }
    }
    (out, None)
}

fn text(t: &[u8]) -> String {
    String::from_utf8_lossy(t).into_owned()
}

#[test]
fn scan_bytes_and_runes() {
    // TestScanByte / TestScanRune (plus an invalid byte)
    for test in SCAN_TESTS
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .chain([b"\x81".to_vec(), b"abc\xc2\x81\xff\x80".to_vec()])
    {
        let s = Scanner::new(Cursor::new(test.clone())).split(bufio::scan_bytes);
        let (toks, err) = scan_all(s);
        assert_eq!(toks.concat(), test);
        assert!(toks.iter().all(|t| t.len() == 1));
        assert!(err.is_none());

        let s = Scanner::new(Cursor::new(test.clone())).split(bufio::scan_runes);
        let (toks, err) = scan_all(s);
        let want = String::from_utf8_lossy(&test);
        let got: String = toks.iter().map(|t| text(t)).collect();
        assert_eq!(got, want);
        assert!(err.is_none());
    }
}

#[test]
fn scan_words_matches_fields() {
    // TestScanWords: same words as str::split_whitespace over Go's inputs.
    for test in [
        "",
        " ",
        "\n",
        "a",
        " a ",
        "abc def",
        " abc def ",
        " abc\tdef\nghi\rjkl\u{c}mno\u{b}pqr\u{85}stu\u{a0}\n",
    ] {
        let s = Scanner::new(Cursor::new(test.as_bytes().to_vec())).split(bufio::scan_words);
        let (toks, err) = scan_all(s);
        let words: Vec<String> = toks.iter().map(|t| text(t)).collect();
        let want: Vec<&str> = test.split_whitespace().collect();
        assert_eq!(words, want, "{test:?}");
        assert!(err.is_none());
    }
}

fn gen_line(line_num: usize, n: usize, add_newline: bool) -> Vec<u8> {
    let mut buf = Vec::new();
    let do_cr = line_num.is_multiple_of(5);
    let n = if do_cr { n.saturating_sub(1) } else { n };
    for i in 0..n.saturating_sub(1) {
        let mut c = b'a'.wrapping_add((line_num + i) as u8);
        if c == b'\n' || c == b'\r' {
            c = b'N';
        }
        buf.push(c);
    }
    if add_newline {
        if do_cr {
            buf.push(b'\r');
        }
        buf.push(b'\n');
    }
    buf
}

#[test]
fn scan_long_lines_with_slow_reader() {
    // TestScanLongLines
    let mut text = Vec::new();
    let mut lines = Vec::new();
    for i in 0..200 {
        let l = gen_line(i, i, true);
        text.extend_from_slice(&l);
        let mut stripped = l.clone();
        stripped.pop();
        if stripped.last() == Some(&b'\r') {
            stripped.pop();
        }
        lines.push(stripped);
    }
    for max in [1, 7, 4096] {
        let (got, err) = scan_all(Scanner::new(slow(max, &text)));
        assert_eq!(got, lines);
        assert!(err.is_none());
    }
}

#[test]
fn scan_line_too_long() {
    // TestScanLineTooLong
    let mut text = Vec::new();
    for i in 0..300 {
        text.extend_from_slice(&gen_line(i, i, true));
    }
    let s = Scanner::new(slow(3, &text)).buffer(Vec::new(), 256);
    let (toks, err) = scan_all(s);
    assert!(toks.iter().all(|t| t.len() < 256));
    assert!(!toks.is_empty() && toks.len() < 300);
    let err = err.unwrap();
    assert_eq!(err.to_string(), "bufio.Scanner: token too long");
    assert!(Error::TooLong.is(&err));
}

#[test]
fn scan_line_endings() {
    // TestScanLineNoNewline / ReturnButNoNewline / EmptyFinalLine(+WithCR)
    let cases: [(&str, &[&str]); 6] = [
        (
            "abcdefghijklmn\nopqrstuvwxyz",
            &["abcdefghijklmn", "opqrstuvwxyz"],
        ),
        (
            "abcdefghijklmn\nopqrstuvwxyz\r",
            &["abcdefghijklmn", "opqrstuvwxyz"],
        ),
        (
            "abcdefghijklmn\nopqrstuvwxyz\n\n",
            &["abcdefghijklmn", "opqrstuvwxyz", ""],
        ),
        ("a\r\n\r\nb\r\n\r\n", &["a", "", "b", ""]),
        ("\r", &[""]),
        ("", &[]),
    ];
    for (input, want) in cases {
        let (toks, err) = scan_all(Scanner::new(slow(3, input.as_bytes())));
        let got: Vec<String> = toks.iter().map(|t| text(t)).collect();
        assert_eq!(got, want, "{input:?}");
        assert!(err.is_none());
    }
}

#[test]
fn scan_split_error_and_err_at_eof() {
    // TestSplitError: the split function's error stops the scan and is the
    // iterator's error.
    let input = "1\n2\n3\n4\n5\n";
    let mut seen = 0;
    let s = Scanner::new(Cursor::new(input.as_bytes().to_vec())).split(
        move |data: &[u8], at_eof: bool| {
            seen += 1;
            if seen == 3 {
                return Err(io::Error::other("custom split error"));
            }
            bufio::scan_lines(data, at_eof)
        },
    );
    let (toks, err) = scan_all(s);
    let got: Vec<String> = toks.iter().map(|t| text(t)).collect();
    assert_eq!(got, ["1", "2"]);
    assert_eq!(err.unwrap().to_string(), "custom split error");

    // TestErrAtEOF: the split function may return an error at EOF.
    let s = Scanner::new(Cursor::new(b"a b c".to_vec())).split(|data: &[u8], at_eof: bool| {
        if at_eof && data.is_empty() {
            return Err(io::Error::other("at eof"));
        }
        bufio::scan_words(data, at_eof)
    });
    let (toks, err) = scan_all(s);
    assert_eq!(toks.len(), 3);
    assert_eq!(err.unwrap().to_string(), "at eof");
}

#[test]
fn scan_final_token() {
    // The ErrFinalToken protocol: a token with the error is delivered, then done.
    fn split(stop_with_empty: bool) -> impl bufio::SplitFunc {
        move |data: &[u8], at_eof: bool| {
            if let Some(i) = data.iter().position(|&c| c == b'|') {
                if stop_with_empty && i == 0 {
                    return Ok(Split::Last(Some(&data[..0])));
                }
                return Ok(Split::Token(i + 1, &data[..i]));
            }
            bufio::scan_lines(data, at_eof)
        }
    }
    let mut s = Scanner::new(Cursor::new(b"a|b||c|d".to_vec())).split(split(true));
    let got: Vec<String> = s.by_ref().map(|t| text(&t.unwrap())).collect();
    assert_eq!(got, ["a", "b", ""]);
    assert!(s.next().is_none());
}

#[test]
fn scan_invalid_advance_counts() {
    // ErrAdvanceTooFar; a negative advance cannot be expressed, a split
    // function reports ErrNegativeAdvance itself.
    let s = Scanner::new(Cursor::new(b"abc".to_vec()))
        .split(|_: &[u8], _| Err(Error::NegativeAdvance.into()));
    let (toks, err) = scan_all(s);
    assert!(toks.is_empty());
    assert_eq!(
        err.unwrap().to_string(),
        "bufio.Scanner: SplitFunc returns negative advance count"
    );
    let s = Scanner::new(Cursor::new(b"abc".to_vec()))
        .split(|d: &[u8], _| Ok(Split::Token(d.len() + 1, d)));
    let (toks, err) = scan_all(s);
    assert!(toks.is_empty());
    assert_eq!(
        err.unwrap().to_string(),
        "bufio.Scanner: SplitFunc returns advance count beyond input"
    );
}

#[test]
fn scan_empty_tokens_error() {
    // TestEmptyTokens / TestDontLoopForever: Go panics, the iterator ends
    // with an error.
    let s = Scanner::new(Cursor::new(b"abc".to_vec())).split(|d: &[u8], at_eof| {
        if at_eof {
            Ok(Split::Token(0, &d[..0]))
        } else {
            bufio::scan_bytes(d, at_eof)
        }
    });
    let (_, err) = scan_all(s);
    let err = err.unwrap();
    assert!(Error::TooManyEmptyTokens.is(&err));
    assert!(err
        .to_string()
        .contains("too many empty tokens without progressing"));
}

#[test]
fn scan_split_and_buffer_after_scan_are_errors() {
    let mut s = Scanner::new(io::empty());
    assert!(s.next().is_none());
    let mut s = s.split(bufio::scan_words);
    assert!(s
        .next()
        .unwrap()
        .unwrap_err()
        .to_string()
        .contains("Split called after Scan"));
    assert!(s.next().is_none());

    let mut s = Scanner::new(io::empty());
    assert!(s.next().is_none());
    let mut s = s.buffer(Vec::new(), 10);
    assert!(s
        .next()
        .unwrap()
        .unwrap_err()
        .to_string()
        .contains("Buffer called after Scan"));
}

#[test]
fn scan_blank_lines_and_huge_buffer() {
    // TestBlankLines / TestEmptyLinesOK
    let (toks, _) = scan_all(Scanner::new(Cursor::new(vec![b'\n'; 1000])));
    assert_eq!(toks.len(), 1000);
    // TestHugeBuffer: a long line fits when the maximum is raised.
    let mut data = vec![b'x'; 1 << 20];
    data.push(b'\n');
    let mut s = Scanner::new(Cursor::new(data.clone())).buffer(Vec::new(), (1 << 20) + 1);
    assert_eq!(s.next().unwrap().unwrap().len(), 1 << 20);
    // The default limit rejects it.
    let mut s = Scanner::new(Cursor::new(data));
    assert!(Error::TooLong.is(&s.next().unwrap().unwrap_err()));
    assert!(s.next().is_none());
    assert_eq!(MAX_SCAN_TOKEN_SIZE, 65536);
}

#[test]
fn scan_reader_error_is_reported() {
    // The data before the error is still delivered, as a final token.
    let mut s = Scanner::new(ErrAfter { left: 3 });
    assert_eq!(s.next().unwrap().unwrap(), b"zzz");
    assert_eq!(s.next().unwrap().unwrap_err().to_string(), "boom");
    assert!(s.next().is_none());
}

#[test]
fn error_values() {
    for (e, text) in [
        (Error::InvalidUnreadByte, "bufio: invalid use of UnreadByte"),
        (Error::InvalidUnreadRune, "bufio: invalid use of UnreadRune"),
        (Error::BufferFull, "bufio: buffer full"),
        (Error::NegativeCount, "bufio: negative count"),
        (Error::TooLong, "bufio.Scanner: token too long"),
        (
            Error::NegativeAdvance,
            "bufio.Scanner: SplitFunc returns negative advance count",
        ),
        (
            Error::AdvanceTooFar,
            "bufio.Scanner: SplitFunc returns advance count beyond input",
        ),
        (
            Error::BadReadCount,
            "bufio.Scanner: Read returned impossible count",
        ),
        (Error::FinalToken, "final token"),
        (
            Error::TooManyEmptyTokens,
            "bufio.Scan: too many empty tokens without progressing",
        ),
    ] {
        assert_eq!(e.to_string(), text);
        let err: io::Error = e.into();
        assert!(e.is(&err));
        assert_eq!(err.to_string(), text);
    }
}
