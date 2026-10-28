//! Ported from Go's strings example_test.go, strings_test.go, replace_test.go,
//! reader_test.go and iter_test.go. Where std provides the Go function
//! (`str::contains`, `str::find`, `str::split_once`, `str::trim_matches`,
//! `str::split_whitespace`, `str::replacen`, `str::repeat`, `String`) the
//! assertion calls std; `tools/strings_check.py` proves the two agree with Go.
//! Wider coverage is in the Go differential.
use rust_stdlib::text::{BytesExt, Reader, Replacer};
use rust_stdlib::unicode::TURKISH_CASE;
use std::io::{BufRead, Read, Seek, SeekFrom, Write};

/// Byte slices as lossless text for comparisons with `&str` expectations.
fn st(b: &[u8]) -> &str {
    std::str::from_utf8(b).expect("utf8")
}

fn sv<'a>(it: impl IntoIterator<Item = &'a [u8]>) -> Vec<&'a str> {
    it.into_iter().map(st).collect()
}

fn u(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

#[test]
fn examples_search() {
    assert!("seafood".contains("foo") && !"seafood".contains("bar"));
    assert!("seafood".contains("") && "".contains(""));
    assert!(!b"team".contains_any(b"i") && b"fail".contains_any(b"ui"));
    assert!(!b"foo".contains_any(b"") && !b"".contains_any(b""));
    assert!("aardvark".contains('a') && !"timeout".contains('a'));
    assert_eq!("cheese".matches('e').count(), 3);
    assert_eq!("five".matches("").count(), 5);
    assert_eq!("chicken".find("ken"), Some(4));
    assert_eq!("chicken".find("dmr"), None);
    assert_eq!(b"chicken".find_any(b"aeiouy"), Some(2));
    assert_eq!(b"gophers".iter().position(|&c| c == b'h'), Some(3));
    assert_eq!("chicken".find('k'), Some(4));
    assert_eq!("go gopher".rfind("go"), Some(3));
    assert_eq!(b"go gopher".rfind_any(b"go"), Some(4));
    assert_eq!(b"go gopher".rfind_any(b"rodent"), Some(8));
    assert_eq!(b"Hello, world".iter().rposition(|&c| c == b'l'), Some(10));
    assert_eq!("go 123".rfind(|c: char| c.is_numeric()), Some(5));
    assert_eq!("Hello, 世界".find(|c: char| c as u32 > 0x4e00), Some(7));
    assert_eq!("abc".rfind(""), Some(3));
    assert!("Gopher".starts_with("") && "Amigo".ends_with("go"));
    assert_eq!("a".cmp("b"), std::cmp::Ordering::Less);
    assert_eq!(b"cheese".count_bytes(b"e"), 3);
    assert_eq!(b"five".count_bytes(b""), 5);
    assert_eq!(b"chicken".find_bytes(b"ken"), Some(4));
    assert_eq!(b"abc".rfind_bytes(b""), Some(3));
}

#[test]
fn examples_cut_and_trim() {
    assert_eq!("Gopher".split_once("ph"), Some(("Go", "er")));
    assert_eq!("Gopher".split_once("Badger"), None);
    assert_eq!("Gopher".strip_prefix("Go"), Some("pher"));
    assert_eq!("Gopher".strip_suffix("er"), Some("Goph"));
    assert_eq!("a.b.c".rsplit_once("."), Some(("a.b", "c")));
    assert_eq!(b"Gopher".cut(b"ph"), Some((&b"Go"[..], &b"er"[..])));
    assert_eq!(b"a.b.c".cut_last(b"."), Some((&b"a.b"[..], &b"c"[..])));
    assert_eq!(
        st("¡¡¡Hello, Gophers!!!"
            .as_bytes()
            .trim_cutset("!¡".as_bytes())),
        "Hello, Gophers"
    );
    assert_eq!(" \t\n Hello, Gophers \n\t\r\n".trim(), "Hello, Gophers");
    assert_eq!(st(b"xxabcxx".trim_space()), "xxabcxx");
    assert_eq!(st(b"xxabcxx".trim_start_cutset(b"x")), "abcxx");
    assert_eq!(st(b"xxabcxx".trim_end_cutset(b"x")), "xxabc");
    assert_eq!(
        "prefix-x".strip_prefix("prefix-").unwrap_or("prefix-x"),
        "x"
    );
    assert_eq!("x.go".strip_suffix(".go").unwrap_or("x.go"), "x");
    assert_eq!(
        "123abc456".trim_matches(|c: char| c.is_ascii_digit()),
        "abc"
    );
    assert_eq!(st(b"123abc456".trim_func(|c| c.is_ascii_digit())), "abc");
    assert_eq!(st(b"abc".trim_cutset(b"")), "abc");
}

#[test]
fn examples_split_and_fields() {
    assert_eq!(sv(b"a,b,c".split_bytes(b",")), ["a", "b", "c"]);
    assert_eq!(
        sv(b"a man a plan a canal panama".split_bytes(b"a ")),
        ["", "man ", "plan ", "canal panama"]
    );
    assert_eq!(sv(b" xyz ".split_bytes(b"")), [" ", "x", "y", "z", " "]);
    assert_eq!(sv(b"".split_bytes(b"Bernardo O'Higgins")), [""]);
    assert_eq!(sv(b"a,b,c".split_bytes_n(b",", 2)), ["a", "b,c"]);
    assert!(b"a,b,c".split_bytes_n(b",", 0).is_empty());
    assert_eq!(
        sv(b"a,b,c".split_bytes_n(b",", isize::MAX)),
        ["a", "b", "c"]
    );
    assert_eq!(sv(b"a,b,c".split_bytes_after(b",")), ["a,", "b,", "c"]);
    assert_eq!(sv(b"a,b,c".split_bytes_after_n(b",", 2)), ["a,", "b,c"]);
    assert_eq!(
        "  foo bar  baz   ".split_whitespace().collect::<Vec<_>>(),
        ["foo", "bar", "baz"]
    );
    assert_eq!(
        sv("a\u{85}b\u{a0}c\u{3000}d\u{200b}e".as_bytes().fields()),
        ["a", "b", "c", "d\u{200b}e"]
    );
    assert_eq!(
        sv(b"  foo1;bar2,baz3...".fields_func(|c| !c.is_alphanumeric())),
        ["foo1", "bar2", "baz3"]
    );
    assert_eq!(["foo", "bar", "baz"].join(", "), "foo, bar, baz");
    assert_eq!(<[&str]>::join(&[], ","), "");
}

#[test]
fn iterators() {
    assert_eq!(b"".split_lines().count(), 0);
    assert_eq!(sv(b"a\n".split_lines()), ["a\n"]);
    assert_eq!(sv(b"a\nb".split_lines()), ["a\n", "b"]);
    assert_eq!(sv(b"\n\n".split_lines()), ["\n", "\n"]);
    assert_eq!(sv(b"a,b,".split_bytes(b",")), ["a", "b", ""]);
    assert_eq!(sv(b"a,b".split_bytes_after(b",")), ["a,", "b"]);
    assert_eq!(sv("héy".as_bytes().split_bytes(b"")), ["h", "é", "y"]);
    assert_eq!(b"".split_bytes(b"").count(), 0);
    assert_eq!(sv(b"".split_bytes(b",")), [""]);
    assert_eq!(sv(b" a  b ".fields()), ["a", "b"]);
    assert_eq!(
        sv(b"a1b2c".fields_func(|c| c.is_ascii_digit())),
        ["a", "b", "c"]
    );
    // Early termination stops the scan.
    assert_eq!(b"a,b,c".split_bytes(b",").next(), Some(&b"a"[..]));
}

#[test]
fn case_mapping() {
    let up = |s: &str| String::from_utf8(s.as_bytes().to_upper()).unwrap();
    let low = |s: &str| String::from_utf8(s.as_bytes().to_lower()).unwrap();
    let tit = |s: &str| String::from_utf8(s.as_bytes().to_title()).unwrap();
    let title = |s: &str| String::from_utf8(s.as_bytes().title()).unwrap();
    assert_eq!(up("Gopher"), "GOPHER");
    assert_eq!(low("Gopher"), "gopher");
    assert_eq!(tit("брат"), "БРАТ");
    assert_eq!(title("her royal highness"), "Her Royal Highness");
    assert_eq!(title("брат"), "Брат");
    assert_eq!(title("a_b c-d"), "A_b C-D");
    // Go uses simple mappings: no expansion of the sharp s, dotted capital I
    // lowercases to a plain i, titlecase digraphs have their own mapping.
    assert_eq!(up("ß"), "ß");
    assert_eq!(low("İ"), "i");
    assert_eq!(tit("ǆ"), "ǅ");
    assert_eq!(up("ǅ"), "Ǆ");
    assert_eq!(low("ΑΣ"), "ας".replace('ς', "σ"));
    assert_eq!(
        st(&"örnek iş".as_bytes().to_upper_special(TURKISH_CASE)),
        "ÖRNEK İŞ"
    );
    assert_eq!(
        st(&"Örnek İş".as_bytes().to_lower_special(TURKISH_CASE)),
        "örnek iş"
    );
    assert_eq!(
        st(&"dünyanın ilk borsa yapısı Aizonai kabul edilir"
            .as_bytes()
            .to_title_special(TURKISH_CASE)),
        "DÜNYANIN İLK BORSA YAPISI AİZONAİ KABUL EDİLİR"
    );
}

#[test]
fn equal_fold_uses_simple_folding() {
    let ef = |a: &str, b: &str| a.as_bytes().equal_fold(b.as_bytes());
    assert!(ef("Go", "go"));
    assert!(ef("AB", "ab"));
    assert!(!ef("ß", "ss"));
    assert!(ef("K", "\u{212a}"));
    assert!(ef("ſ", "S"));
    assert!(ef("σ", "ς") && ef("Σ", "ς"));
    assert!(!ef("a", "ab"));
    assert!(
        b"\xff".equal_fold(b"\xfe"),
        "invalid bytes are all RuneError"
    );
    assert!(b"\xff".equal_fold("\u{fffd}".as_bytes()));
}

#[test]
fn map_repeat_replace() {
    let rot13 = |r: char| {
        Some(match r {
            'A'..='Z' => (b'A' + (r as u8 - b'A' + 13) % 26) as char,
            'a'..='z' => (b'a' + (r as u8 - b'a' + 13) % 26) as char,
            _ => r,
        })
    };
    assert_eq!(
        st(&"'Twas brillig and the slithy gopher..."
            .as_bytes()
            .map_runes(rot13)),
        "'Gjnf oevyyvt naq gur fyvgul tbcure..."
    );
    assert_eq!(st(&b"banana".map_runes(|c| (c != 'a').then_some(c))), "bnn");
    assert_eq!("na".repeat(2), "nana");
    assert_eq!("".repeat(usize::MAX), "");
    assert_eq!(
        st(&b"oink oink oink".replace(b"k", b"ky", 2)),
        "oinky oinky oink"
    );
    assert_eq!(
        st(&b"oink oink oink".replace(b"oink", b"moo", -1)),
        "moo moo moo"
    );
    assert_eq!("oink oink oink".replacen("k", "ky", 2), "oinky oinky oink");
    assert_eq!("oink oink oink".replace("oink", "moo"), "moo moo moo");
    assert_eq!("abc".replace("", "-"), "-a-b-c-");
    assert_eq!("abc".replacen("", "-", 2), "-a-bc");
    assert_eq!(st(&b"abc".replace_all(b"", b"-")), "-a-b-c-");
    assert_eq!(st(&b"abc".replace(b"", b"-", 2)), "-a-bc");
    assert_eq!(
        st(&"héllo".as_bytes().replace(b"", b"-", -1)),
        "-h-é-l-l-o-"
    );
    assert_eq!(st(&b"abc".replace(b"b", b"b", -1)), "abc");
}

#[test]
fn invalid_utf8_follows_go() {
    let bad: &[u8] = b"a\xffb\xe4\xb8";
    assert_eq!(bad.to_upper(), "A\u{fffd}B\u{fffd}\u{fffd}".as_bytes());
    assert_eq!(bad.to_valid_utf8(b"?"), b"a?b?");
    assert_eq!(b"a\xff\xfeb".to_valid_utf8(b"X"), b"aXb");
    assert_eq!(u("ok").to_valid_utf8(b"?"), b"ok");
    assert_eq!(bad.count_bytes(b""), 6);
    assert_eq!(bad.split_bytes(b"").count(), 5);
    assert_eq!(bad.find_rune('\u{fffd}'), Some(1));
    assert_eq!(
        bad.find_any(b"\xc3"),
        Some(1),
        "a lone high byte in chars means RuneError"
    );
    assert_eq!(b"\xff\xffab\xff".trim_cutset("\u{fffd}".as_bytes()), b"ab");
    assert_eq!(
        b"a \xff b".fields().collect::<Vec<_>>(),
        [&b"a"[..], b"\xff", b"b"]
    );
    assert_eq!(bad.map_runes(Some), "a\u{fffd}b\u{fffd}\u{fffd}".as_bytes());
}

#[test]
fn builder() {
    // strings.Builder is `String` (and `Vec<u8>` for arbitrary bytes).
    let mut b = String::new();
    for i in (1..=3).rev() {
        std::fmt::Write::write_fmt(&mut b, format_args!("{i}...")).unwrap();
    }
    b.push_str("ignition");
    assert_eq!(b, "3...2...1...ignition");
    assert_eq!(b.len(), 20);
    let mut v = b.into_bytes();
    v.push(0xff);
    assert!(std::str::from_utf8(&v).is_err());
    v.extend_from_slice("é".as_bytes());
    assert_eq!(std::io::Write::write(&mut v, b"xy").unwrap(), 2);
    assert_eq!(&v[20..], b"\xff\xc3\xa9xy");
    v.reserve(1000);
    assert!(v.capacity() >= v.len() + 1000);
    v.clear();
    assert!(v.is_empty());
}

#[test]
fn reader_unread_rules() {
    let mut r = Reader::new("héllo");
    assert_eq!(r.len(), 6);
    assert_eq!(r.size(), 6);
    assert!(r.unread_byte().is_err(), "at beginning");
    assert!(r.unread_rune().is_err());
    assert_eq!(r.read_rune().unwrap(), ('h', 1));
    assert_eq!(r.read_rune().unwrap(), ('é', 2));
    r.unread_rune().unwrap();
    assert!(r.unread_rune().is_err(), "second unread without a ReadRune");
    assert_eq!(r.read_rune().unwrap(), ('é', 2));
    r.unread_byte().unwrap();
    assert!(r.unread_rune().is_err(), "UnreadByte clears the rune");
    assert_eq!(r.read_byte().unwrap(), 0xa9);
    let mut buf = [0u8; 2];
    assert_eq!(r.read(&mut buf).unwrap(), 2);
    assert_eq!(&buf, b"ll");
    assert!(r.unread_rune().is_err(), "Read clears the rune");
    assert_eq!(r.read_byte().unwrap(), b'o');
    assert_eq!(
        r.read_byte().unwrap_err().kind(),
        std::io::ErrorKind::UnexpectedEof
    );
    assert_eq!(r.read(&mut buf).unwrap(), 0);
    assert_eq!(r.read_rune().unwrap_err().to_string(), "EOF");
}

#[test]
fn reader_seek_read_at_write_to() {
    let mut r = Reader::new(b"0123456789".as_slice());
    assert_eq!(r.seek(SeekFrom::Start(4)).unwrap(), 4);
    assert_eq!(r.seek(SeekFrom::Current(-1)).unwrap(), 3);
    assert_eq!(r.seek(SeekFrom::End(-2)).unwrap(), 8);
    assert_eq!(
        r.seek(SeekFrom::End(5)).unwrap(),
        15,
        "past the end is allowed"
    );
    assert_eq!(r.len(), 0);
    r.unread_byte().unwrap();
    assert!(r.seek(SeekFrom::Current(-100)).is_err());
    assert_eq!(
        r.stream_position().unwrap(),
        14,
        "failed seek keeps the position"
    );
    let mut buf = [0u8; 4];
    let (n, res) = r.read_at(&mut buf, 8);
    assert_eq!((n, &buf[..n]), (2, &b"89"[..]));
    assert_eq!(res.unwrap().kind(), std::io::ErrorKind::UnexpectedEof);
    let (n, res) = r.read_at(&mut buf, 2);
    assert_eq!((n, &buf, res.is_none()), (4, b"2345", true));
    assert!(r.read_at(&mut buf, -1).1.is_some());
    assert_eq!(r.read_at(&mut buf, 10).0, 0);
    r.seek(SeekFrom::Start(7)).unwrap();
    let mut out = Vec::new();
    assert_eq!(r.write_to(&mut out).unwrap(), 3);
    assert_eq!(out, b"789");
    assert_eq!(r.write_to(&mut out).unwrap(), 0);
    r.reset("ab\ncd");
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    assert_eq!(line, "ab\n");
    assert_eq!(r.fill_buf().unwrap(), b"cd");
}

#[test]
fn replacer_priority_and_algorithms() {
    let rep = |pairs: &[(&str, &str)], s: &str| st(&Replacer::new(pairs).replace(s)).to_string();
    assert_eq!(
        rep(&[("<", "&lt;"), (">", "&gt;")], "This is <b>HTML</b>!"),
        "This is &lt;b&gt;HTML&lt;/b&gt;!"
    );
    // Earlier pairs win over later ones, not the longest match.
    assert_eq!(rep(&[("a", "2"), ("ab", "1")], "ab"), "2b");
    assert_eq!(rep(&[("ab", "1"), ("a", "2")], "ab"), "1");
    // Duplicate keys: the first wins in every algorithm.
    assert_eq!(rep(&[("a", "1"), ("a", "2")], "a"), "1");
    assert_eq!(rep(&[("a", "1"), ("a", "22")], "a"), "1");
    assert_eq!(rep(&[("aa", "1"), ("aa", "2")], "aa"), "1");
    // Empty keys match between bytes, and a following non-empty key still can.
    assert_eq!(rep(&[("", "X")], "abc"), "XaXbXcX");
    assert_eq!(rep(&[("", "X"), ("a", "Y")], "abc"), "XYXbXcX");
    assert_eq!(rep(&[("a", "Y"), ("", "X")], "abc"), "YXbXcX");
    // Single string, byte-to-byte and byte-to-string algorithms.
    assert_eq!(rep(&[("hello", "x")], "hello hello"), "x x");
    assert_eq!(rep(&[("a", "b"), ("b", "a")], "abba"), "baab");
    assert_eq!(rep(&[("a", "xyz"), ("b", "")], "abc"), "xyzc");
    assert_eq!(rep(&[], "abc"), "abc");
    let mut sink = Vec::new();
    let (n, res) = Replacer::new(&[("a", "bb")]).write_to(&mut sink, "xay");
    assert!(res.is_ok());
    assert_eq!((n, sink.as_slice()), (4, &b"xbby"[..]));
}

#[test]
fn replacer_write_error_reports_count() {
    struct Limited(usize);
    impl Write for Limited {
        fn write(&mut self, p: &[u8]) -> std::io::Result<usize> {
            if self.0 == 0 {
                return Err(std::io::Error::other("full"));
            }
            let n = p.len().min(self.0);
            self.0 -= n;
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let r = Replacer::new(&[("a", "123")]);
    let (n, res) = r.write_to(&mut Limited(2), "xxaxx");
    assert!(res.is_err());
    assert_eq!(n, 2);
}

#[test]
fn bytes_ext_agrees_with_std_on_valid_input() {
    for text in ["", "a,b,,c", "héllo wörld", "𝄞 中 ß"] {
        let b = text.as_bytes();
        assert_eq!(b.fields().count(), text.split_whitespace().count());
        assert_eq!(b.find_bytes(b"l"), text.find('l'));
        assert_eq!(
            b.split_bytes(b",").map(st).collect::<Vec<_>>(),
            text.split(',').collect::<Vec<_>>()
        );
    }
}
