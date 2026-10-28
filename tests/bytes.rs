//! Ported tables from Go's bytes_test.go, buffer_test.go and reader_test.go.
//! The test-local `bytes` module names the Go functions so the ported
//! assertions read like the originals; each one is a `BytesExt` method or a
//! std item.
use rust_stdlib::text::{Buffer, ErrTooLarge, Reader};
use std::io::{BufRead, Read, Seek, SeekFrom, Write};

mod bytes {
    use rust_stdlib::text::{Buffer, BytesExt};
    use rust_stdlib::unicode::SpecialCase;
    pub use rust_stdlib::unicode::TURKISH_CASE;
    use std::cmp::Ordering;

    pub fn index(s: &[u8], sep: &[u8]) -> Option<usize> {
        s.find_bytes(sep)
    }
    pub fn last_index(s: &[u8], sep: &[u8]) -> Option<usize> {
        s.rfind_bytes(sep)
    }
    pub fn index_byte(s: &[u8], c: u8) -> Option<usize> {
        s.iter().position(|&b| b == c)
    }
    pub fn last_index_byte(s: &[u8], c: u8) -> Option<usize> {
        s.iter().rposition(|&b| b == c)
    }
    pub fn index_rune(s: &[u8], r: char) -> Option<usize> {
        s.find_rune(r)
    }
    pub fn index_any(s: &[u8], chars: &[u8]) -> Option<usize> {
        s.find_any(chars)
    }
    pub fn last_index_any(s: &[u8], chars: &[u8]) -> Option<usize> {
        s.rfind_any(chars)
    }
    pub fn last_index_func(s: &[u8], f: impl FnMut(char) -> bool) -> Option<usize> {
        s.rfind_func(f)
    }
    pub fn contains_any(s: &[u8], chars: &[u8]) -> bool {
        s.contains_any(chars)
    }
    pub fn contains_rune(s: &[u8], r: char) -> bool {
        s.contains_rune(r)
    }
    pub fn count(s: &[u8], sep: &[u8]) -> usize {
        s.count_bytes(sep)
    }
    pub fn compare(a: &[u8], b: &[u8]) -> Ordering {
        a.cmp(b)
    }
    pub fn split_n<'a>(s: &'a [u8], sep: &[u8], n: isize) -> Vec<&'a [u8]> {
        s.split_bytes_n(sep, n)
    }
    pub fn split_after_n<'a>(s: &'a [u8], sep: &[u8], n: isize) -> Vec<&'a [u8]> {
        s.split_bytes_after_n(sep, n)
    }
    pub fn split<'a>(s: &'a [u8], sep: &'a [u8]) -> Vec<&'a [u8]> {
        s.split_bytes(sep).collect()
    }
    pub fn split_after<'a>(s: &'a [u8], sep: &'a [u8]) -> Vec<&'a [u8]> {
        s.split_bytes_after(sep).collect()
    }
    pub fn split_seq<'a>(s: &'a [u8], sep: &'a [u8]) -> impl Iterator<Item = &'a [u8]> {
        s.split_bytes(sep)
    }
    pub fn split_after_seq<'a>(s: &'a [u8], sep: &'a [u8]) -> impl Iterator<Item = &'a [u8]> {
        s.split_bytes_after(sep)
    }
    pub fn lines(s: &[u8]) -> impl Iterator<Item = &[u8]> {
        s.split_lines()
    }
    pub fn fields(s: &[u8]) -> Vec<&[u8]> {
        s.fields().collect()
    }
    pub fn fields_seq(s: &[u8]) -> impl Iterator<Item = &[u8]> {
        s.fields()
    }
    pub fn fields_func(s: &[u8], f: impl FnMut(char) -> bool) -> Vec<&[u8]> {
        s.fields_func(f).collect()
    }
    pub fn fields_func_seq(s: &[u8], f: impl FnMut(char) -> bool) -> impl Iterator<Item = &[u8]> {
        s.fields_func(f)
    }
    pub fn trim<'a>(s: &'a [u8], cutset: &[u8]) -> &'a [u8] {
        s.trim_cutset(cutset)
    }
    pub fn trim_left<'a>(s: &'a [u8], cutset: &[u8]) -> &'a [u8] {
        s.trim_start_cutset(cutset)
    }
    pub fn trim_right<'a>(s: &'a [u8], cutset: &[u8]) -> &'a [u8] {
        s.trim_end_cutset(cutset)
    }
    pub fn trim_space(s: &[u8]) -> &[u8] {
        s.trim_space()
    }
    pub fn trim_func(s: &[u8], f: impl FnMut(char) -> bool) -> &[u8] {
        s.trim_func(f)
    }
    pub fn trim_prefix<'a>(s: &'a [u8], p: &[u8]) -> &'a [u8] {
        s.strip_prefix(p).unwrap_or(s)
    }
    pub fn trim_suffix<'a>(s: &'a [u8], p: &[u8]) -> &'a [u8] {
        s.strip_suffix(p).unwrap_or(s)
    }
    pub fn to_upper(s: &[u8]) -> Vec<u8> {
        s.to_upper()
    }
    pub fn to_lower(s: &[u8]) -> Vec<u8> {
        s.to_lower()
    }
    pub fn to_title(s: &[u8]) -> Vec<u8> {
        s.to_title()
    }
    pub fn title(s: &[u8]) -> Vec<u8> {
        s.title()
    }
    pub fn to_upper_special(c: SpecialCase<'_>, s: &[u8]) -> Vec<u8> {
        s.to_upper_special(c)
    }
    pub fn to_lower_special(c: SpecialCase<'_>, s: &[u8]) -> Vec<u8> {
        s.to_lower_special(c)
    }
    pub fn map(f: impl FnMut(char) -> Option<char>, s: &[u8]) -> Vec<u8> {
        s.map_runes(f)
    }
    pub fn to_valid_utf8(s: &[u8], r: &[u8]) -> Vec<u8> {
        s.to_valid_utf8(r)
    }
    pub fn runes(s: &[u8]) -> Vec<char> {
        s.runes()
    }
    pub fn equal_fold(a: &[u8], b: &[u8]) -> bool {
        a.equal_fold(b)
    }
    pub fn replace(s: &[u8], old: &[u8], new: &[u8], n: isize) -> Vec<u8> {
        s.replace(old, new, n)
    }
    pub fn replace_all(s: &[u8], old: &[u8], new: &[u8]) -> Vec<u8> {
        s.replace_all(old, new)
    }
    pub fn cut<'a>(s: &'a [u8], sep: &[u8]) -> Option<(&'a [u8], &'a [u8])> {
        s.cut(sep)
    }
    pub fn cut_last<'a>(s: &'a [u8], sep: &[u8]) -> Option<(&'a [u8], &'a [u8])> {
        s.cut_last(sep)
    }
    pub fn new_buffer(v: Vec<u8>) -> Buffer {
        Buffer::from_vec(v)
    }
    pub fn new_buffer_string(s: &str) -> Buffer {
        Buffer::from_str(s)
    }
}

fn s(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn strs(parts: Vec<&[u8]>) -> Vec<String> {
    parts.into_iter().map(s).collect()
}

#[test]
fn index_tests() {
    let tests: &[(&str, &str, i64)] = &[
        ("", "", 0),
        ("", "a", -1),
        ("", "foo", -1),
        ("fo", "foo", -1),
        ("foo", "foo", 0),
        ("oofofoofooo", "f", 2),
        ("oofofoofooo", "foo", 4),
        ("barfoobarfoo", "foo", 3),
        ("foo", "", 0),
        ("foo", "o", 1),
        ("abcABCabc", "A", 3),
        (
            "jrzm6jjhorimglljrea4w3rlgosts0w2gia17hno2td4qd1jz",
            "jz",
            47,
        ),
        (
            "ekkuk5oft4eq0ocpacknhwouic1uua46unx12l37nioq9wbpnocqks6",
            "ks6",
            52,
        ),
        ("999f2xmimunbuyew5vrkla9cpwhmxan8o98ec", "98ec", 33),
        ("xx", "xxx", -1),
    ];
    for &(a, b, want) in tests {
        let got = bytes::index(a.as_bytes(), b.as_bytes()).map_or(-1, |i| i as i64);
        assert_eq!(got, want, "Index({a:?}, {b:?})");
    }
    let long = "ab".repeat(5000) + "c";
    assert_eq!(bytes::index(long.as_bytes(), b"bc"), Some(9999));
    assert_eq!(bytes::last_index(long.as_bytes(), b"ab"), Some(9998));
    assert_eq!(bytes::count(long.as_bytes(), b"ab"), 5000);
}

#[test]
fn last_index_and_count_tests() {
    assert_eq!(bytes::last_index(b"go gopher", b"go"), Some(3));
    assert_eq!(bytes::last_index(b"go gopher", b"rodent"), None);
    assert_eq!(bytes::last_index(b"foo", b""), Some(3));
    assert_eq!(bytes::count(b"cheese", b"e"), 3);
    assert_eq!(bytes::count(b"five", b""), 5);
    assert_eq!(bytes::count("a\u{e9}\u{4e2d}".as_bytes(), b""), 4);
    assert_eq!(bytes::count(b"aaaa", b"aa"), 2);
    assert_eq!(bytes::count(b"\xff\xfe", b""), 3);
}

#[test]
fn index_rune_and_any() {
    assert_eq!(bytes::index_rune("chicken".as_bytes(), 'k'), Some(4));
    assert_eq!(
        bytes::index_rune("a\u{fffd}".as_bytes(), '\u{fffd}'),
        Some(1)
    );
    assert_eq!(bytes::index_rune(b"a\xffb", '\u{fffd}'), Some(1));
    assert_eq!(bytes::index_rune(b"abc", '\u{fffd}'), None);
    assert_eq!(bytes::index_any(b"golang", b"y"), None);
    assert_eq!(bytes::index_any(b"ab\xffc", b"\xfe"), Some(2));
    assert_eq!(bytes::index_any(b"abc", b""), None);
    assert_eq!(
        bytes::last_index_any("go \u{4e2d}".as_bytes(), "\u{4e2d}x".as_bytes()),
        Some(3)
    );
    assert_eq!(
        bytes::last_index_any(b"a\xffb\xff", "\u{fffd}".as_bytes()),
        Some(3)
    );
    assert!(bytes::contains_any(b"abc", b"xc"));
    assert!(bytes::contains_rune(b"abc", 'b'));
}

#[test]
fn split_tests() {
    let tests: &[(&str, &str, isize, &[&str])] = &[
        ("", "", -1, &[]),
        ("abc", "", -1, &["a", "b", "c"]),
        (
            "\u{263a}\u{263b}\u{263c}",
            "",
            -1,
            &["\u{263a}", "\u{263b}", "\u{263c}"],
        ),
        ("abcd", "bcd", 2, &["a", ""]),
        ("abcd", "", 2, &["a", "bcd"]),
        ("abcd", "", 4, &["a", "b", "c", "d"]),
        ("abcd", "", 0, &[]),
        ("a,b,c", ",", 0, &[]),
        ("a,b,c", ",", 1, &["a,b,c"]),
        ("a,b,c", ",", -1, &["a", "b", "c"]),
        ("a,b,c", ",", 2, &["a", "b,c"]),
        (",", ",", -1, &["", ""]),
    ];
    for &(input, sep, n, want) in tests {
        let got = strs(bytes::split_n(input.as_bytes(), sep.as_bytes(), n));
        assert_eq!(got, want, "SplitN({input:?}, {sep:?}, {n})");
    }
    assert_eq!(strs(bytes::split_after_n(b"a,b,c", b",", 2)), ["a,", "b,c"]);
    assert_eq!(strs(bytes::split_after(b"a,b,c", b",")), ["a,", "b,", "c"]);
    assert_eq!(strs(bytes::split(b"a\xffb", b"")), ["a", "\u{fffd}", "b"]);
    assert_eq!(strs(bytes::split_seq(b"a,b", b",").collect()), ["a", "b"]);
    assert_eq!(
        strs(bytes::split_after_seq(b"a,b", b",").collect()),
        ["a,", "b"]
    );
    assert_eq!(
        strs(bytes::lines(b"a\nb\r\n\nc").collect()),
        ["a\n", "b\r\n", "\n", "c"]
    );
}

#[test]
fn fields_tests() {
    assert_eq!(
        strs(bytes::fields(b"  foo bar  baz   ")),
        ["foo", "bar", "baz"]
    );
    assert!(bytes::fields(b"").is_empty());
    assert!(bytes::fields(b" \t\n").is_empty());
    let unicode = "\u{85}\u{a0}x\u{2003}y\u{3000}".as_bytes();
    assert_eq!(strs(bytes::fields(unicode)), ["x", "y"]);
    assert_eq!(strs(bytes::fields_seq(unicode).collect()), ["x", "y"]);
    let digit = |r: char| r.is_ascii_digit();
    assert_eq!(strs(bytes::fields_func(b"a1b22c", digit)), ["a", "b", "c"]);
    assert_eq!(strs(bytes::fields_func_seq(b"1a1", digit).collect()), ["a"]);
}

#[test]
fn trim_tests() {
    assert_eq!(bytes::trim(b"abba", b"a"), b"bb");
    assert_eq!(bytes::trim(b"abba", b"ab"), b"");
    assert_eq!(bytes::trim_left(b"abba", b"a"), b"bba");
    assert_eq!(bytes::trim_right(b"abba", b"a"), b"abb");
    assert_eq!(bytes::trim(b"xx", b""), b"xx");
    assert_eq!(
        bytes::trim("\u{4e2d}a\u{4e2d}".as_bytes(), "\u{4e2d}".as_bytes()),
        b"a"
    );
    // Invalid bytes in the cutset are U+FFFD and match invalid input bytes.
    assert_eq!(bytes::trim(b"\xffa\xfe", b"\xfd"), b"a");
    assert_eq!(bytes::trim_space(b" \t\r\n x y \n"), b"x y");
    assert_eq!(bytes::trim_space("\u{2003}\u{a0}x\u{85}".as_bytes()), b"x");
    assert_eq!(bytes::trim_space(b"   "), b"");
    assert_eq!(
        bytes::trim_func(b"123abc456", |r| r.is_ascii_digit()),
        b"abc"
    );
    assert_eq!(bytes::trim_prefix(b"foobar", b"foo"), b"bar");
    assert_eq!(bytes::trim_suffix(b"foobar", b"bar"), b"foo");
    assert_eq!(bytes::trim_prefix(b"foobar", b"x"), b"foobar");
}

#[test]
fn case_tests() {
    assert_eq!(
        bytes::to_upper("abc\u{e9}".as_bytes()),
        "ABC\u{c9}".as_bytes()
    );
    assert_eq!(
        bytes::to_lower("ABC\u{c9}".as_bytes()),
        "abc\u{e9}".as_bytes()
    );
    assert_eq!(
        bytes::to_upper("\u{3c3}\u{3c2}".as_bytes()),
        "\u{3a3}\u{3a3}".as_bytes()
    );
    // Invalid bytes become the three-byte encoding of U+FFFD.
    assert_eq!(bytes::to_upper(b"a\xffb"), "A\u{fffd}B".as_bytes());
    assert_eq!(bytes::to_title(b"ab"), b"AB");
    assert_eq!(bytes::title(b"hello wOrLd-x"), b"Hello WOrLd-X");
    let tr = |f: fn(&[u8]) -> Vec<u8>| s(&f(b"iI"));
    assert_eq!(
        tr(|b| bytes::to_upper_special(bytes::TURKISH_CASE, b)),
        "\u{130}I"
    );
    assert_eq!(
        tr(|b| bytes::to_lower_special(bytes::TURKISH_CASE, b)),
        "i\u{131}"
    );
    assert_eq!(bytes::map(|r| (r != 'a').then_some(r), b"banana"), b"bnn");
    assert_eq!(
        bytes::map(|_| Some('\u{fffd}'), b"x"),
        "\u{fffd}".as_bytes()
    );
}

#[test]
fn equal_fold_tests() {
    let tests: &[(&str, &str, bool)] = &[
        ("abc", "ABC", true),
        ("ABcd", "ABcd", true),
        ("123abc", "123ABC", true),
        ("\u{3b1}\u{3b2}\u{3b3}", "\u{391}\u{392}\u{393}", true),
        ("\u{3c3}", "\u{3c2}", true),
        ("k", "\u{212a}", true),
        ("S", "\u{17f}", true),
        ("abc", "abd", false),
        ("abc", "ab", false),
        ("\u{131}", "I", false),
        ("a", "\u{e1}", false),
    ];
    for &(a, b, want) in tests {
        assert_eq!(
            bytes::equal_fold(a.as_bytes(), b.as_bytes()),
            want,
            "{a:?} {b:?}"
        );
        assert_eq!(
            bytes::equal_fold(b.as_bytes(), a.as_bytes()),
            want,
            "{b:?} {a:?}"
        );
    }
    assert!(bytes::equal_fold(b"\xff", "\u{fffd}".as_bytes()));
}

#[test]
fn replace_and_misc() {
    assert_eq!(
        bytes::replace(b"oink oink oink", b"k", b"ky", 2),
        b"oinky oinky oink"
    );
    assert_eq!(
        bytes::replace(b"oink oink oink", b"oink", b"moo", -1),
        b"moo moo moo"
    );
    assert_eq!(bytes::replace(b"abc", b"", b"-", -1), b"-a-b-c-");
    assert_eq!(bytes::replace(b"abc", b"", b"-", 2), b"-a-bc");
    assert_eq!(
        bytes::replace_all("\u{263a}".as_bytes(), b"", b"-"),
        "-\u{263a}-".as_bytes()
    );
    assert_eq!(bytes::replace(b"a", b"a", b"b", 0), b"a");
    assert_eq!(bytes::to_valid_utf8(b"a\xff\xfeb\x80c", b"?"), b"a?b?c");
    assert_eq!(bytes::to_valid_utf8(b"\xff", b""), b"");
    assert_eq!(
        bytes::runes(b"a\xff\xe4\xb8\xad"),
        ['a', '\u{fffd}', '\u{4e2d}']
    );
    assert_eq!(bytes::cut(b"k=v", b"="), Some((&b"k"[..], &b"v"[..])));
    assert_eq!(
        bytes::cut_last(b"a=b=c", b"="),
        Some((&b"a=b"[..], &b"c"[..]))
    );
    assert_eq!(bytes::cut(b"kv", b"="), None);
    assert_eq!(bytes::compare(b"a", b"b"), std::cmp::Ordering::Less);
    assert_eq!(bytes::index_byte(b"abc", b'c'), Some(2));
    assert_eq!(bytes::last_index_byte(b"abca", b'a'), Some(3));
    assert_eq!(
        bytes::last_index_func(b"ab1c", |r| r.is_ascii_digit()),
        Some(2)
    );
}

#[test]
fn buffer_basics_and_unread_rules() {
    let mut b = Buffer::new();
    assert_eq!(b.cap(), 0);
    b.write_string("hello");
    assert_eq!(b.cap(), 64);
    assert_eq!(b.len(), 5);
    assert_eq!(b.available(), 59);
    assert!(b.unread_byte().is_err());
    assert_eq!(b.read_byte().unwrap(), b'h');
    b.unread_byte().unwrap();
    assert!(b.unread_byte().is_err(), "second unread must fail");
    assert!(b.unread_rune().is_err());
    assert_eq!(b.read_rune().unwrap(), ('h', 1));
    b.unread_rune().unwrap();
    assert_eq!(b.as_bytes(), b"hello");
    // A write between read and unread invalidates the unread.
    b.read_byte().unwrap();
    b.write_byte(b'!');
    assert!(b.unread_byte().is_err());
    // Next, then UnreadByte steps back one byte only.
    assert_eq!(b.next(2), b"el");
    b.unread_byte().unwrap();
    assert_eq!(b.as_bytes(), b"llo!");
    let (p, e) = b.peek(2);
    assert_eq!((p, e.is_none()), (&b"ll"[..], true));
    let (all, err) = b.peek(99);
    assert_eq!(
        (all, err.unwrap().to_string()),
        (&b"llo!"[..], "EOF".to_string())
    );
    b.truncate(2);
    assert_eq!(b.as_bytes(), b"ll");
    b.truncate(0);
    assert_eq!(b.len(), 0);
    assert!(std::panic::catch_unwind(|| Buffer::new().truncate(1)).is_err());
}

#[test]
fn buffer_read_runes_and_lines() {
    let mut b = bytes::new_buffer_string("a\u{4e2d}\u{1f600}\nrest");
    assert_eq!(b.read_rune().unwrap(), ('a', 1));
    assert_eq!(b.read_rune().unwrap(), ('\u{4e2d}', 3));
    b.unread_rune().unwrap();
    assert_eq!(b.read_rune().unwrap(), ('\u{4e2d}', 3));
    assert_eq!(b.read_rune().unwrap(), ('\u{1f600}', 4));
    let (line, err) = b.read_bytes(b'\n');
    assert_eq!((line, err.is_none()), (b"\n".to_vec(), true));
    let (rest, err) = b.read_string(b'\n');
    assert_eq!(rest, "rest");
    assert_eq!(err.unwrap().kind(), std::io::ErrorKind::UnexpectedEof);
    assert_eq!(b.read_byte().unwrap_err().to_string(), "EOF");

    let mut bad = bytes::new_buffer(b"\xff\xe4\xb8".to_vec());
    assert_eq!(bad.read_rune().unwrap(), ('\u{fffd}', 1));
    assert_eq!(bad.read_rune().unwrap(), ('\u{fffd}', 1));
    bad.unread_rune().unwrap();
    assert_eq!(bad.as_bytes(), b"\xe4\xb8");
}

#[test]
fn buffer_io_traits() {
    let mut b = Buffer::new();
    write!(b, "line1\nline2\n").unwrap();
    let mut first = String::new();
    b.read_line(&mut first).unwrap();
    assert_eq!(first, "line1\n");
    let mut sink = Vec::new();
    assert_eq!(b.write_to(&mut sink).unwrap(), 6);
    assert_eq!(sink, b"line2\n");
    assert_eq!(b.len(), 0);

    let mut src: &[u8] = &[7u8; 2000];
    assert_eq!(b.read_from(&mut src).unwrap(), 2000);
    assert_eq!(b.len(), 2000);
    let mut out = [0u8; 10];
    assert_eq!(b.read(&mut out).unwrap(), 10);
    b.reset();
    assert_eq!(b.read(&mut out).unwrap(), 0);
}

#[test]
fn buffer_growth_matches_go() {
    // Capacities observed from Go 1.27 for the same call sequences.
    let mut b = Buffer::new();
    b.grow(10);
    assert_eq!(b.cap(), 64);
    b.grow(100);
    assert_eq!(b.cap(), 128);
    let mut c = bytes::new_buffer_string("abcd");
    assert_eq!(c.cap(), 8);
    c.write_rune('\u{80}');
    c.write_rune('\u{80}');
    assert_eq!(c.cap(), 16);
    let mut d = Buffer::new();
    d.write_all(&[0u8; 65]).unwrap();
    assert_eq!(d.cap(), 80);
}

#[test]
fn buffer_too_large_panics() {
    let err = std::panic::catch_unwind(|| {
        let mut b = Buffer::new();
        b.grow(usize::MAX / 2);
    })
    .unwrap_err();
    assert!(err.downcast_ref::<ErrTooLarge>().is_some());
    assert_eq!(ErrTooLarge.to_string(), "bytes.Buffer: too large");
}

#[test]
fn reader_matches_go_tests() {
    let mut r = Reader::new(b"0123456789");
    assert_eq!(r.len(), 10);
    assert_eq!(r.size(), 10);
    assert_eq!(r.seek(SeekFrom::Start(5)).unwrap(), 5);
    let mut buf = [0u8; 3];
    assert_eq!(r.read(&mut buf).unwrap(), 3);
    assert_eq!(&buf, b"567");
    assert_eq!(r.seek(SeekFrom::Current(-2)).unwrap(), 6);
    assert_eq!(r.seek(SeekFrom::End(-1)).unwrap(), 9);
    assert!(r.seek(SeekFrom::End(-11)).is_err());
    assert_eq!(r.seek(SeekFrom::Start(20)).unwrap(), 20);
    assert_eq!(r.len(), 0);
    assert_eq!(r.read(&mut buf).unwrap(), 0);

    let (n, err) = r.read_at(&mut buf, 8);
    assert_eq!(
        (n, &buf[..n], err.unwrap().to_string()),
        (2, &b"89"[..], "EOF".into())
    );
    let (n, err) = r.read_at(&mut buf, 0);
    assert_eq!((n, err.is_none()), (3, true));
    let (_, err) = r.read_at(&mut buf, -1);
    assert_eq!(
        err.unwrap().to_string(),
        "bytes.Reader.ReadAt: negative offset"
    );
    let (n, err) = r.read_at(&mut buf, 10);
    assert_eq!((n, err.unwrap().to_string()), (0, "EOF".into()));
}

#[test]
fn reader_unread_rules() {
    let mut r = Reader::new("a\u{4e2d}".as_bytes());
    assert_eq!(
        r.unread_byte().unwrap_err().to_string(),
        "bytes.Reader.UnreadByte: at beginning of slice"
    );
    assert_eq!(r.read_rune().unwrap(), ('a', 1));
    assert_eq!(r.read_rune().unwrap(), ('\u{4e2d}', 3));
    r.unread_rune().unwrap();
    assert_eq!(
        r.unread_rune().unwrap_err().to_string(),
        "bytes.Reader.UnreadRune: previous operation was not ReadRune"
    );
    assert_eq!(r.read_byte().unwrap(), 0xe4);
    r.unread_byte().unwrap();
    assert_eq!(r.len(), 3);
    assert_eq!(r.fill_buf().unwrap().len(), 3);
    r.consume(3);
    assert_eq!(r.read_byte().unwrap_err().to_string(), "EOF");

    let mut w = Vec::new();
    r.reset(b"xyz");
    assert_eq!(r.write_to(&mut w).unwrap(), 3);
    assert_eq!(w, b"xyz");
    assert_eq!(r.write_to(&mut w).unwrap(), 0);
}
