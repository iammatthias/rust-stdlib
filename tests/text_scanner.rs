//! Ports of Go's `text/scanner` tests (`scanner_test.go`). The token and
//! number tables are generated from the Go source.
use rust_stdlib::text::scanner::{
    self, Position, Scanner, CHAR, COMMENT, EOF, FLOAT, IDENT, INT, RAW_STRING, STRING,
};
use std::cell::{Cell, RefCell};
use std::io::{self, Read};
use std::rc::Rc;

const F100: &[u8] = b"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

fn t(tok: i32, parts: &[&[u8]]) -> (i32, Vec<u8>) {
    (tok, parts.concat())
}

fn c(ch: char) -> i32 {
    ch as i32
}

fn count_newlines(s: &[u8]) -> usize {
    s.iter().filter(|&&b| b == b'\n').count()
}

fn token_list() -> Vec<(i32, Vec<u8>)> {
    vec![
        t(COMMENT, &[&b"// line comments"[..]]),
        t(COMMENT, &[&b"//"[..]]),
        t(COMMENT, &[&b"////"[..]]),
        t(COMMENT, &[&b"// comment"[..]]),
        t(COMMENT, &[&b"// /* comment */"[..]]),
        t(COMMENT, &[&b"// // comment //"[..]]),
        t(COMMENT, &[&b"//"[..], F100]),
        t(COMMENT, &[&b"// general comments"[..]]),
        t(COMMENT, &[&b"/**/"[..]]),
        t(COMMENT, &[&b"/***/"[..]]),
        t(COMMENT, &[&b"/* comment */"[..]]),
        t(COMMENT, &[&b"/* // comment */"[..]]),
        t(COMMENT, &[&b"/* /* comment */"[..]]),
        t(COMMENT, &[&b"/*\x0a comment\x0a*/"[..]]),
        t(COMMENT, &[&b"/*"[..], F100, &b"*/"[..]]),
        t(COMMENT, &[&b"// identifiers"[..]]),
        t(IDENT, &[&b"a"[..]]),
        t(IDENT, &[&b"a0"[..]]),
        t(IDENT, &[&b"foobar"[..]]),
        t(IDENT, &[&b"abc123"[..]]),
        t(IDENT, &[&b"LGTM"[..]]),
        t(IDENT, &[&b"_"[..]]),
        t(IDENT, &[&b"_abc123"[..]]),
        t(IDENT, &[&b"abc123_"[..]]),
        t(IDENT, &[&b"_abc_123_"[..]]),
        t(IDENT, &[&b"_\xc3\xa4\xc3\xb6\xc3\xbc"[..]]),
        t(IDENT, &[&b"_\xe6\x9c\xac"[..]]),
        t(IDENT, &[&b"\xc3\xa4\xc3\xb6\xc3\xbc"[..]]),
        t(IDENT, &[&b"\xe6\x9c\xac"[..]]),
        t(IDENT, &[&b"a\xdb\xb0\xdb\xb1\xdb\xb8"[..]]),
        t(IDENT, &[&b"foo\xe0\xa5\xac\xe0\xa5\xaa"[..]]),
        t(
            IDENT,
            &[&b"bar\xef\xbc\x99\xef\xbc\x98\xef\xbc\x97\xef\xbc\x96"[..]],
        ),
        t(IDENT, &[F100]),
        t(COMMENT, &[&b"// decimal ints"[..]]),
        t(INT, &[&b"0"[..]]),
        t(INT, &[&b"1"[..]]),
        t(INT, &[&b"9"[..]]),
        t(INT, &[&b"42"[..]]),
        t(INT, &[&b"1234567890"[..]]),
        t(COMMENT, &[&b"// octal ints"[..]]),
        t(INT, &[&b"00"[..]]),
        t(INT, &[&b"01"[..]]),
        t(INT, &[&b"07"[..]]),
        t(INT, &[&b"042"[..]]),
        t(INT, &[&b"01234567"[..]]),
        t(COMMENT, &[&b"// hexadecimal ints"[..]]),
        t(INT, &[&b"0x0"[..]]),
        t(INT, &[&b"0x1"[..]]),
        t(INT, &[&b"0xf"[..]]),
        t(INT, &[&b"0x42"[..]]),
        t(INT, &[&b"0x123456789abcDEF"[..]]),
        t(INT, &[&b"0x"[..], F100]),
        t(INT, &[&b"0X0"[..]]),
        t(INT, &[&b"0X1"[..]]),
        t(INT, &[&b"0XF"[..]]),
        t(INT, &[&b"0X42"[..]]),
        t(INT, &[&b"0X123456789abcDEF"[..]]),
        t(INT, &[&b"0X"[..], F100]),
        t(COMMENT, &[&b"// floats"[..]]),
        t(FLOAT, &[&b"0."[..]]),
        t(FLOAT, &[&b"1."[..]]),
        t(FLOAT, &[&b"42."[..]]),
        t(FLOAT, &[&b"01234567890."[..]]),
        t(FLOAT, &[&b".0"[..]]),
        t(FLOAT, &[&b".1"[..]]),
        t(FLOAT, &[&b".42"[..]]),
        t(FLOAT, &[&b".0123456789"[..]]),
        t(FLOAT, &[&b"0.0"[..]]),
        t(FLOAT, &[&b"1.0"[..]]),
        t(FLOAT, &[&b"42.0"[..]]),
        t(FLOAT, &[&b"01234567890.0"[..]]),
        t(FLOAT, &[&b"0e0"[..]]),
        t(FLOAT, &[&b"1e0"[..]]),
        t(FLOAT, &[&b"42e0"[..]]),
        t(FLOAT, &[&b"01234567890e0"[..]]),
        t(FLOAT, &[&b"0E0"[..]]),
        t(FLOAT, &[&b"1E0"[..]]),
        t(FLOAT, &[&b"42E0"[..]]),
        t(FLOAT, &[&b"01234567890E0"[..]]),
        t(FLOAT, &[&b"0e+10"[..]]),
        t(FLOAT, &[&b"1e-10"[..]]),
        t(FLOAT, &[&b"42e+10"[..]]),
        t(FLOAT, &[&b"01234567890e-10"[..]]),
        t(FLOAT, &[&b"0E+10"[..]]),
        t(FLOAT, &[&b"1E-10"[..]]),
        t(FLOAT, &[&b"42E+10"[..]]),
        t(FLOAT, &[&b"01234567890E-10"[..]]),
        t(COMMENT, &[&b"// chars"[..]]),
        t(CHAR, &[&b"' '"[..]]),
        t(CHAR, &[&b"'a'"[..]]),
        t(CHAR, &[&b"'\xe6\x9c\xac'"[..]]),
        t(CHAR, &[&b"'\x5ca'"[..]]),
        t(CHAR, &[&b"'\x5cb'"[..]]),
        t(CHAR, &[&b"'\x5cf'"[..]]),
        t(CHAR, &[&b"'\x5cn'"[..]]),
        t(CHAR, &[&b"'\x5cr'"[..]]),
        t(CHAR, &[&b"'\x5ct'"[..]]),
        t(CHAR, &[&b"'\x5cv'"[..]]),
        t(CHAR, &[&b"'\x5c''"[..]]),
        t(CHAR, &[&b"'\x5c000'"[..]]),
        t(CHAR, &[&b"'\x5c777'"[..]]),
        t(CHAR, &[&b"'\x5cx00'"[..]]),
        t(CHAR, &[&b"'\x5cxff'"[..]]),
        t(CHAR, &[&b"'\x5cu0000'"[..]]),
        t(CHAR, &[&b"'\x5cufA16'"[..]]),
        t(CHAR, &[&b"'\x5cU00000000'"[..]]),
        t(CHAR, &[&b"'\x5cU0000ffAB'"[..]]),
        t(COMMENT, &[&b"// strings"[..]]),
        t(STRING, &[&b"\x22 \x22"[..]]),
        t(STRING, &[&b"\x22a\x22"[..]]),
        t(STRING, &[&b"\x22\xe6\x9c\xac\x22"[..]]),
        t(STRING, &[&b"\x22\x5ca\x22"[..]]),
        t(STRING, &[&b"\x22\x5cb\x22"[..]]),
        t(STRING, &[&b"\x22\x5cf\x22"[..]]),
        t(STRING, &[&b"\x22\x5cn\x22"[..]]),
        t(STRING, &[&b"\x22\x5cr\x22"[..]]),
        t(STRING, &[&b"\x22\x5ct\x22"[..]]),
        t(STRING, &[&b"\x22\x5cv\x22"[..]]),
        t(STRING, &[&b"\x22\x5c\x22\x22"[..]]),
        t(STRING, &[&b"\x22\x5c000\x22"[..]]),
        t(STRING, &[&b"\x22\x5c777\x22"[..]]),
        t(STRING, &[&b"\x22\x5cx00\x22"[..]]),
        t(STRING, &[&b"\x22\x5cxff\x22"[..]]),
        t(STRING, &[&b"\x22\x5cu0000\x22"[..]]),
        t(STRING, &[&b"\x22\x5cufA16\x22"[..]]),
        t(STRING, &[&b"\x22\x5cU00000000\x22"[..]]),
        t(STRING, &[&b"\x22\x5cU0000ffAB\x22"[..]]),
        t(STRING, &[&b"\x22"[..], F100, &b"\x22"[..]]),
        t(COMMENT, &[&b"// raw strings"[..]]),
        t(RAW_STRING, &[&b"``"[..]]),
        t(RAW_STRING, &[&b"`\x5c`"[..]]),
        t(
            RAW_STRING,
            &[&b"`"[..], &b"\x0a\x0a/* foobar */\x0a\x0a"[..], &b"`"[..]],
        ),
        t(RAW_STRING, &[&b"`"[..], F100, &b"`"[..]]),
        t(COMMENT, &[&b"// individual characters"[..]]),
        t(1, &[&b"\x01"[..]]),
        t(31, &[&b"\x1f"[..]]),
        t(43, &[&b"+"[..]]),
        t(47, &[&b"/"[..]]),
        t(46, &[&b"."[..]]),
        t(126, &[&b"~"[..]]),
        t(40, &[&b"("[..]]),
    ]
}

/// Delivers its data one segment at a time. Like Go's StringReader, an empty
/// segment is not an end of source, so it is skipped.
struct StringReader {
    data: Vec<Vec<u8>>,
    step: usize,
}

impl Read for StringReader {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        while self.step < self.data.len() && self.data[self.step].is_empty() {
            self.step += 1;
        }
        if self.step >= self.data.len() {
            return Ok(0);
        }
        let s = &self.data[self.step];
        let n = s.len().min(p.len());
        p[..n].copy_from_slice(&s[..n]);
        self.step += 1;
        Ok(n)
    }
}

fn read_rune_segments(segments: &[&str]) {
    let data: Vec<Vec<u8>> = segments.iter().map(|s| s.as_bytes().to_vec()).collect();
    let want: String = segments.concat();
    let mut s = Scanner::default();
    s.init(StringReader { data, step: 0 });
    let mut got = String::new();
    loop {
        let ch = s.next();
        if ch == EOF {
            break;
        }
        got.push(char::from_u32(ch as u32).unwrap());
    }
    assert_eq!(got, want, "segments={segments:?}");
}

#[test]
fn next_segments() {
    let segment_list: &[&[&str]] = &[
        &[],
        &[""],
        &["日", "本語"],
        &["\u{65e5}", "\u{672c}", "\u{8a9e}"],
        &["\u{65e5}", " ", "\u{672c}", "\u{8a9e}"],
        &["Hello", ", ", "World", "!"],
        &["Hello", ", ", "", "World", "!"],
    ];
    for segments in segment_list {
        read_rune_segments(segments);
    }
}

fn check_tok(s: &mut Scanner<'_>, line: usize, got: i32, want: i32, text: &[u8]) {
    assert_eq!(
        scanner::token_string(got),
        scanner::token_string(want),
        "token for {:?}",
        String::from_utf8_lossy(text)
    );
    assert_eq!(
        s.position.line,
        line,
        "line for {:?}",
        String::from_utf8_lossy(text)
    );
    assert_eq!(s.token_text(), text, "text");
    // check idempotency of token_text
    assert_eq!(s.token_text(), text, "text (idempotency check)");
}

fn check_scan(s: &mut Scanner<'_>, line: usize, want: i32, text: &[u8]) {
    let tok = s.scan();
    check_tok(s, line, tok, want, text);
}

fn check_next(s: &mut Scanner<'_>, line: usize, want: i32, text: &[u8]) {
    let tok = s.next();
    check_tok(s, line, tok, want, text);
}

fn check_tok_err(s: &mut Scanner<'_>, line: usize, want: i32, text: &[u8]) {
    let prev = s.error_count;
    let tok = s.scan();
    check_tok(s, line, tok, want, text);
    assert_eq!(
        s.error_count,
        prev + 1,
        "want error for {:?}",
        String::from_utf8_lossy(text)
    );
}

fn make_source(pattern: &str) -> Vec<u8> {
    let (before, after) = pattern.split_once("%s").unwrap();
    let mut buf = Vec::new();
    for (_, text) in token_list() {
        buf.extend_from_slice(before.as_bytes());
        buf.extend_from_slice(&text);
        buf.extend_from_slice(after.as_bytes());
    }
    buf
}

fn test_scan(mode: usize) {
    let src = make_source(" \t%s\n");
    let mut s = Scanner::default();
    s.init(&src[..]);
    s.mode = mode;
    let mut tok = s.scan();
    let mut line = 1;
    for (kind, text) in token_list() {
        if mode & scanner::SKIP_COMMENTS == 0 || kind != COMMENT {
            check_tok(&mut s, line, tok, kind, &text);
            tok = s.scan();
        }
        line += count_newlines(&text) + 1; // each token is on a new line
    }
    check_tok(&mut s, line, tok, EOF, b"");
}

#[test]
fn scan_tokens() {
    test_scan(scanner::DEFAULT_TOKENS);
    test_scan(scanner::DEFAULT_TOKENS & !scanner::SKIP_COMMENTS);
}

#[test]
fn invalid_exponent() {
    let src = "1.5e 1.5E 1e+ 1e- 1.5z";
    let errors = Rc::new(RefCell::new(Vec::new()));
    let sink = Rc::clone(&errors);
    let mut s = Scanner::default();
    s.init(src.as_bytes());
    s.error = Some(Rc::new(move |s: &mut Scanner<'_>, msg: &str| {
        let text = s.token_text();
        sink.borrow_mut().push((text, msg.to_string()));
    }));
    check_tok_err(&mut s, 1, FLOAT, b"1.5e");
    check_tok_err(&mut s, 1, FLOAT, b"1.5E");
    check_tok_err(&mut s, 1, FLOAT, b"1e+");
    check_tok_err(&mut s, 1, FLOAT, b"1e-");
    check_scan(&mut s, 1, FLOAT, b"1.5");
    check_scan(&mut s, 1, IDENT, b"z");
    check_scan(&mut s, 1, EOF, b"");
    assert_eq!(s.error_count, 4);
    for (text, msg) in errors.borrow().iter() {
        assert_eq!(
            msg,
            "exponent has no digits",
            "error at {:?}",
            String::from_utf8_lossy(text)
        );
    }
}

#[test]
fn position() {
    let src = make_source("\t\t\t\t%s\n");
    let mut s = Scanner::default();
    s.init(&src[..]);
    s.mode = scanner::DEFAULT_TOKENS & !scanner::SKIP_COMMENTS;
    s.scan();
    let mut pos = Position {
        filename: String::new(),
        offset: 4,
        line: 1,
        column: 5,
    };
    for (_, text) in token_list() {
        assert_eq!(
            s.position.offset,
            pos.offset,
            "offset for {:?}",
            String::from_utf8_lossy(&text)
        );
        assert_eq!(
            s.position.line,
            pos.line,
            "line for {:?}",
            String::from_utf8_lossy(&text)
        );
        assert_eq!(
            s.position.column,
            pos.column,
            "column for {:?}",
            String::from_utf8_lossy(&text)
        );
        pos.offset += 4 + text.len() + 1; // 4 tabs + token bytes + newline
        pos.line += count_newlines(&text) + 1; // each token is on a new line
        s.scan();
    }
    assert_eq!(s.error_count, 0);
}

#[test]
fn scan_zero_mode() {
    let src = make_source("%s\n");
    let text = String::from_utf8(src.clone()).unwrap();
    let mut s = Scanner::default();
    s.init(&src[..]);
    s.mode = 0; // don't recognize any token classes
    s.whitespace = 0; // don't skip any white space
    let mut tok = s.scan();
    for ch in text.chars() {
        assert_eq!(tok, ch as i32, "token for {ch:?}");
        tok = s.scan();
    }
    assert_eq!(tok, EOF);
    assert_eq!(s.error_count, 0);
}

fn test_scan_selected_mode(mode: usize, class: i32) {
    let src = make_source("%s\n");
    let mut s = Scanner::default();
    s.init(&src[..]);
    s.mode = mode;
    let mut tok = s.scan();
    while tok != EOF {
        assert!(!(tok < 0 && tok != class), "tok = {tok}, want {class}");
        tok = s.scan();
    }
    assert_eq!(s.error_count, 0);
}

#[test]
fn scan_selected_mask() {
    test_scan_selected_mode(0, 0);
    test_scan_selected_mode(scanner::SCAN_IDENTS, IDENT);
    // Don't test ints and floats together: some parts of the floats in the
    // source look like invalid octal ints, and floats may be scanned as ints.
    test_scan_selected_mode(scanner::SCAN_CHARS, CHAR);
    test_scan_selected_mode(scanner::SCAN_STRINGS, STRING);
    test_scan_selected_mode(scanner::SKIP_COMMENTS, 0);
    test_scan_selected_mode(scanner::SCAN_COMMENTS, COMMENT);
}

#[test]
fn scan_custom_ident() {
    let src = "faab12345 a12b123 a12 3b";
    let mut s = Scanner::default();
    s.init(src.as_bytes());
    // ident = ( 'a' | 'b' ) { digit } .
    // digit = '0' .. '3' .
    // with a maximum length of 4
    s.is_ident_rune = Some(Box::new(|ch, i| {
        (i == 0 && (ch == c('a') || ch == c('b')))
            || (0 < i && i < 4 && (c('0')..=c('3')).contains(&ch))
    }));
    check_scan(&mut s, 1, c('f'), b"f");
    check_scan(&mut s, 1, IDENT, b"a");
    check_scan(&mut s, 1, IDENT, b"a");
    check_scan(&mut s, 1, IDENT, b"b123");
    check_scan(&mut s, 1, INT, b"45");
    check_scan(&mut s, 1, IDENT, b"a12");
    check_scan(&mut s, 1, IDENT, b"b123");
    check_scan(&mut s, 1, IDENT, b"a12");
    check_scan(&mut s, 1, INT, b"3");
    check_scan(&mut s, 1, IDENT, b"b");
    check_scan(&mut s, 1, EOF, b"");
}

#[test]
fn scan_next_skips_byte_order_marks() {
    let bom = "\u{FEFF}";
    let src = format!(
        "{bom}if a == bcd /* com{bom}ment */ {{\n\ta += c\n}}{bom}// line comment ending in eof"
    );
    let mut s = Scanner::default();
    s.init(src.as_bytes());
    check_scan(&mut s, 1, IDENT, b"if"); // the first BOM is ignored
    check_scan(&mut s, 1, IDENT, b"a");
    check_scan(&mut s, 1, c('='), b"=");
    check_next(&mut s, 0, c('='), b"");
    check_next(&mut s, 0, c(' '), b"");
    check_next(&mut s, 0, c('b'), b"");
    check_scan(&mut s, 1, IDENT, b"cd");
    check_scan(&mut s, 1, c('{'), b"{");
    check_scan(&mut s, 2, IDENT, b"a");
    check_scan(&mut s, 2, c('+'), b"+");
    check_next(&mut s, 0, c('='), b"");
    check_scan(&mut s, 2, IDENT, b"c");
    check_scan(&mut s, 3, c('}'), b"}");
    check_scan(&mut s, 3, c('\u{FEFF}'), bom.as_bytes());
    check_scan(&mut s, 3, -1, b"");
    assert_eq!(s.error_count, 0);
}

#[test]
fn scan_whitespace() {
    // start at 1, the NUL character is not allowed
    let mut buf = Vec::new();
    let mut ws = 0u64;
    for ch in 1u8..b' ' {
        buf.push(ch);
        ws |= 1 << ch;
    }
    let orig = b'x';
    buf.push(orig);

    let mut s = Scanner::default();
    s.init(&buf[..]);
    s.mode = 0;
    s.whitespace = ws;
    assert_eq!(s.scan(), orig as i32);
}

fn test_error(src: &[u8], pos: &str, msg: &str, tok: i32) {
    let first = Rc::new(RefCell::new(None::<(String, String)>));
    let sink = Rc::clone(&first);
    let mut s = Scanner::default();
    s.init(src);
    s.error = Some(Rc::new(move |s: &mut Scanner<'_>, m: &str| {
        if sink.borrow().is_none() {
            // only the first error
            *sink.borrow_mut() = Some((s.pos().to_string(), m.to_string()));
        }
    }));
    let got = s.scan();
    assert_eq!(got, tok, "tok for {:?}", String::from_utf8_lossy(src));
    let first = first.borrow();
    let (got_pos, got_msg) = first.as_ref().unwrap_or_else(|| {
        panic!(
            "error handler not called for {:?}",
            String::from_utf8_lossy(src)
        )
    });
    assert_eq!(got_pos, pos, "pos for {:?}", String::from_utf8_lossy(src));
    assert_eq!(got_msg, msg, "msg for {:?}", String::from_utf8_lossy(src));
    assert!(
        s.error_count > 0,
        "count for {:?}",
        String::from_utf8_lossy(src)
    );
}

#[test]
fn errors() {
    test_error(b"\x00", "<input>:1:1", "invalid character NUL", 0);
    test_error(b"\x80", "<input>:1:1", "invalid UTF-8 encoding", 0xFFFD);
    test_error(b"\xff", "<input>:1:1", "invalid UTF-8 encoding", 0xFFFD);

    test_error(b"a\x00", "<input>:1:2", "invalid character NUL", IDENT);
    test_error(b"ab\x80", "<input>:1:3", "invalid UTF-8 encoding", IDENT);
    test_error(b"abc\xff", "<input>:1:4", "invalid UTF-8 encoding", IDENT);

    test_error(b"\"a\x00", "<input>:1:3", "invalid character NUL", STRING);
    test_error(b"\"ab\x80", "<input>:1:4", "invalid UTF-8 encoding", STRING);
    test_error(
        b"\"abc\xff",
        "<input>:1:5",
        "invalid UTF-8 encoding",
        STRING,
    );

    test_error(
        b"`a\x00",
        "<input>:1:3",
        "invalid character NUL",
        RAW_STRING,
    );
    test_error(
        b"`ab\x80",
        "<input>:1:4",
        "invalid UTF-8 encoding",
        RAW_STRING,
    );
    test_error(
        b"`abc\xff",
        "<input>:1:5",
        "invalid UTF-8 encoding",
        RAW_STRING,
    );

    test_error(br#"'\"'"#, "<input>:1:3", "invalid char escape", CHAR);
    test_error(br#""\'""#, "<input>:1:3", "invalid char escape", STRING);

    test_error(
        b"01238",
        "<input>:1:6",
        "invalid digit '8' in octal literal",
        INT,
    );
    test_error(
        b"01238123",
        "<input>:1:9",
        "invalid digit '8' in octal literal",
        INT,
    );
    test_error(
        b"0x",
        "<input>:1:3",
        "hexadecimal literal has no digits",
        INT,
    );
    test_error(
        b"0xg",
        "<input>:1:3",
        "hexadecimal literal has no digits",
        INT,
    );
    test_error(b"'aa'", "<input>:1:4", "invalid char literal", CHAR);
    test_error(b"1.5e", "<input>:1:5", "exponent has no digits", FLOAT);
    test_error(b"1.5E", "<input>:1:5", "exponent has no digits", FLOAT);
    test_error(b"1.5e+", "<input>:1:6", "exponent has no digits", FLOAT);
    test_error(b"1.5e-", "<input>:1:6", "exponent has no digits", FLOAT);

    test_error(b"'", "<input>:1:2", "literal not terminated", CHAR);
    test_error(b"'\n", "<input>:1:2", "literal not terminated", CHAR);
    test_error(b"\"abc", "<input>:1:5", "literal not terminated", STRING);
    test_error(b"\"abc\n", "<input>:1:5", "literal not terminated", STRING);
    test_error(
        b"`abc\n",
        "<input>:2:1",
        "literal not terminated",
        RAW_STRING,
    );
    test_error(b"/*/", "<input>:1:4", "comment not terminated", EOF);
}

/// Returns an error that is not end of source on every read.
struct ErrReader;

impl Read for ErrReader {
    fn read(&mut self, _b: &mut [u8]) -> io::Result<usize> {
        // some error that is not end of source
        Err(io::Error::other(
            "multiple Read calls return no data or error",
        ))
    }
}

#[test]
fn io_error() {
    let msg = Rc::new(RefCell::new(None::<String>));
    let sink = Rc::clone(&msg);
    let mut s = Scanner::default();
    s.init(ErrReader);
    s.error = Some(Rc::new(move |_: &mut Scanner<'_>, m: &str| {
        if sink.borrow().is_none() {
            *sink.borrow_mut() = Some(m.to_string());
        }
    }));
    assert_eq!(s.scan(), EOF);
    assert_eq!(
        msg.borrow().as_deref(),
        Some("multiple Read calls return no data or error"),
        "error handler not called with the read error"
    );
}

fn check_pos(got: &Position, want: (usize, usize, usize)) {
    assert_eq!(
        (got.offset, got.line, got.column),
        want,
        "got offset, line, column; want {want:?}"
    );
}

fn check_next_pos(s: &mut Scanner<'_>, offset: usize, line: usize, column: usize, ch: i32) {
    assert_eq!(s.next(), ch);
    check_pos(&s.pos(), (offset, line, column));
}

fn check_scan_pos(s: &mut Scanner<'_>, offset: usize, line: usize, column: usize, ch: i32) {
    check_pos(&s.pos(), (offset, line, column));
    assert_eq!(s.scan(), ch);
    check_pos(&s.position, (offset, line, column));
}

#[test]
fn pos() {
    // corner case: empty source
    let mut s = Scanner::default();
    s.init(&b""[..]);
    check_pos(&s.pos(), (0, 1, 1));
    s.peek(); // peek doesn't affect the position
    check_pos(&s.pos(), (0, 1, 1));

    // corner case: source with only a newline
    let mut s = Scanner::default();
    s.init(&b"\n"[..]);
    check_pos(&s.pos(), (0, 1, 1));
    check_next_pos(&mut s, 1, 2, 1, c('\n'));
    // after EOF position doesn't change
    for _ in 0..10 {
        check_scan_pos(&mut s, 1, 2, 1, EOF);
    }
    assert_eq!(s.error_count, 0);

    // corner case: source with only a single character
    let mut s = Scanner::default();
    s.init("本".as_bytes());
    check_pos(&s.pos(), (0, 1, 1));
    check_next_pos(&mut s, 3, 1, 2, c('本'));
    // after EOF position doesn't change
    for _ in 0..10 {
        check_scan_pos(&mut s, 3, 1, 2, EOF);
    }
    assert_eq!(s.error_count, 0);

    // positions after calling next
    let mut s = Scanner::default();
    s.init("  foo६४  \n\n本語\n".as_bytes());
    check_next_pos(&mut s, 1, 1, 2, c(' '));
    s.peek(); // peek doesn't affect the position
    check_next_pos(&mut s, 2, 1, 3, c(' '));
    check_next_pos(&mut s, 3, 1, 4, c('f'));
    check_next_pos(&mut s, 4, 1, 5, c('o'));
    check_next_pos(&mut s, 5, 1, 6, c('o'));
    check_next_pos(&mut s, 8, 1, 7, c('६'));
    check_next_pos(&mut s, 11, 1, 8, c('४'));
    check_next_pos(&mut s, 12, 1, 9, c(' '));
    check_next_pos(&mut s, 13, 1, 10, c(' '));
    check_next_pos(&mut s, 14, 2, 1, c('\n'));
    check_next_pos(&mut s, 15, 3, 1, c('\n'));
    check_next_pos(&mut s, 18, 3, 2, c('本'));
    check_next_pos(&mut s, 21, 3, 3, c('語'));
    check_next_pos(&mut s, 22, 4, 1, c('\n'));
    // after EOF position doesn't change
    for _ in 0..10 {
        check_scan_pos(&mut s, 22, 4, 1, EOF);
    }
    assert_eq!(s.error_count, 0);

    // positions after calling scan
    let mut s = Scanner::default();
    s.init("abc\n本語\n\nx".as_bytes());
    s.mode = 0;
    s.whitespace = 0;
    check_scan_pos(&mut s, 0, 1, 1, c('a'));
    s.peek(); // peek doesn't affect the position
    check_scan_pos(&mut s, 1, 1, 2, c('b'));
    check_scan_pos(&mut s, 2, 1, 3, c('c'));
    check_scan_pos(&mut s, 3, 1, 4, c('\n'));
    check_scan_pos(&mut s, 4, 2, 1, c('本'));
    check_scan_pos(&mut s, 7, 2, 2, c('語'));
    check_scan_pos(&mut s, 10, 2, 3, c('\n'));
    check_scan_pos(&mut s, 11, 3, 1, c('\n'));
    check_scan_pos(&mut s, 12, 4, 1, c('x'));
    // after EOF position doesn't change
    for _ in 0..10 {
        check_scan_pos(&mut s, 13, 4, 2, EOF);
    }
    assert_eq!(s.error_count, 0);
}

/// Counts the calls to read and always reports end of source.
struct CountReader<'a>(&'a Cell<usize>);

impl Read for CountReader<'_> {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        self.0.set(self.0.get() + 1);
        Ok(0)
    }
}

#[test]
fn next_eof_handling() {
    let reads = Cell::new(0);
    // corner case: empty source
    let mut s = Scanner::default();
    s.init(CountReader(&reads));

    assert_eq!(s.next(), EOF, "1) EOF not reported");
    assert_eq!(s.peek(), EOF, "2) EOF not reported");
    assert_eq!(reads.get(), 1, "scanner called Read not once");
}

#[test]
fn scan_eof_handling() {
    let reads = Cell::new(0);
    // corner case: empty source
    let mut s = Scanner::default();
    s.init(CountReader(&reads));

    assert_eq!(s.scan(), EOF, "1) EOF not reported");
    assert_eq!(s.peek(), EOF, "2) EOF not reported");
    assert_eq!(reads.get(), 1, "scanner called Read not once");
}

#[test]
fn issue_29723_token_text_in_error_handler() {
    let seen = Rc::new(RefCell::new(Vec::new()));
    let sink = Rc::clone(&seen);
    let mut s = Scanner::default();
    s.init(&b"x \""[..]);
    s.error = Some(Rc::new(move |s: &mut Scanner<'_>, _: &str| {
        // this call shouldn't panic
        sink.borrow_mut().push(s.token_text());
    }));
    while s.scan() != EOF {}
    assert_eq!(*seen.borrow(), vec![b"\"".to_vec()]);
}

#[test]
fn numbers() {
    let cases: &[(i32, &str, &str, &str)] = &[
        (INT, "0b0", "0b0", ""),
        (INT, "0b1010", "0b1010", ""),
        (INT, "0B1110", "0B1110", ""),
        (INT, "0b", "0b", "binary literal has no digits"),
        (
            INT,
            "0b0190",
            "0b0190",
            "invalid digit '9' in binary literal",
        ),
        (FLOAT, "0b.", "0b.", "invalid radix point in binary literal"),
        (
            FLOAT,
            "0b.1",
            "0b.1",
            "invalid radix point in binary literal",
        ),
        (
            FLOAT,
            "0b1.0",
            "0b1.0",
            "invalid radix point in binary literal",
        ),
        (
            FLOAT,
            "0b1e10",
            "0b1e10",
            "'e' exponent requires decimal mantissa",
        ),
        (
            FLOAT,
            "0b1P-1",
            "0b1P-1",
            "'P' exponent requires hexadecimal mantissa",
        ),
        (INT, "0o0", "0o0", ""),
        (INT, "0o1234", "0o1234", ""),
        (INT, "0O1234", "0O1234", ""),
        (INT, "0o", "0o", "octal literal has no digits"),
        (
            INT,
            "0o8123",
            "0o8123",
            "invalid digit '8' in octal literal",
        ),
        (
            INT,
            "0o1293",
            "0o1293",
            "invalid digit '9' in octal literal",
        ),
        (FLOAT, "0o.", "0o.", "invalid radix point in octal literal"),
        (
            FLOAT,
            "0o.2",
            "0o.2",
            "invalid radix point in octal literal",
        ),
        (
            FLOAT,
            "0o1.2",
            "0o1.2",
            "invalid radix point in octal literal",
        ),
        (
            FLOAT,
            "0o1E+2",
            "0o1E+2",
            "'E' exponent requires decimal mantissa",
        ),
        (
            FLOAT,
            "0o1p10",
            "0o1p10",
            "'p' exponent requires hexadecimal mantissa",
        ),
        (INT, "0", "0", ""),
        (INT, "0123", "0123", ""),
        (INT, "08123", "08123", "invalid digit '8' in octal literal"),
        (INT, "01293", "01293", "invalid digit '9' in octal literal"),
        (INT, "0123F.", "0123 F .", ""),
        (INT, "0123456x", "0123456 x", ""),
        (INT, "1", "1", ""),
        (INT, "1234", "1234", ""),
        (FLOAT, "0.", "0.", ""),
        (FLOAT, "123.", "123.", ""),
        (FLOAT, "0123.", "0123.", ""),
        (FLOAT, ".0", ".0", ""),
        (FLOAT, ".123", ".123", ""),
        (FLOAT, ".0123", ".0123", ""),
        (FLOAT, "0.0", "0.0", ""),
        (FLOAT, "123.123", "123.123", ""),
        (FLOAT, "0123.0123", "0123.0123", ""),
        (FLOAT, "0e0", "0e0", ""),
        (FLOAT, "123e+0", "123e+0", ""),
        (FLOAT, "0123E-1", "0123E-1", ""),
        (FLOAT, "0.e+1", "0.e+1", ""),
        (FLOAT, "123.E-10", "123.E-10", ""),
        (FLOAT, "0123.e123", "0123.e123", ""),
        (FLOAT, ".0e-1", ".0e-1", ""),
        (FLOAT, ".123E+10", ".123E+10", ""),
        (FLOAT, ".0123E123", ".0123E123", ""),
        (FLOAT, "0.0e1", "0.0e1", ""),
        (FLOAT, "123.123E-10", "123.123E-10", ""),
        (FLOAT, "0123.0123e+456", "0123.0123e+456", ""),
        (FLOAT, "0e", "0e", "exponent has no digits"),
        (FLOAT, "0E+", "0E+", "exponent has no digits"),
        (FLOAT, "1e+f", "1e+ f", "exponent has no digits"),
        (
            FLOAT,
            "0p0",
            "0p0",
            "'p' exponent requires hexadecimal mantissa",
        ),
        (
            FLOAT,
            "1.0P-1",
            "1.0P-1",
            "'P' exponent requires hexadecimal mantissa",
        ),
        (INT, "0x0", "0x0", ""),
        (INT, "0x1234", "0x1234", ""),
        (INT, "0xcafef00d", "0xcafef00d", ""),
        (INT, "0XCAFEF00D", "0XCAFEF00D", ""),
        (INT, "0x", "0x", "hexadecimal literal has no digits"),
        (INT, "0x1g", "0x1 g", ""),
        (FLOAT, "0x0p0", "0x0p0", ""),
        (FLOAT, "0x12efp-123", "0x12efp-123", ""),
        (FLOAT, "0xABCD.p+0", "0xABCD.p+0", ""),
        (FLOAT, "0x.0189P-0", "0x.0189P-0", ""),
        (FLOAT, "0x1.ffffp+1023", "0x1.ffffp+1023", ""),
        (FLOAT, "0x.", "0x.", "hexadecimal literal has no digits"),
        (
            FLOAT,
            "0x0.",
            "0x0.",
            "hexadecimal mantissa requires a 'p' exponent",
        ),
        (
            FLOAT,
            "0x.0",
            "0x.0",
            "hexadecimal mantissa requires a 'p' exponent",
        ),
        (
            FLOAT,
            "0x1.1",
            "0x1.1",
            "hexadecimal mantissa requires a 'p' exponent",
        ),
        (
            FLOAT,
            "0x1.1e0",
            "0x1.1e0",
            "hexadecimal mantissa requires a 'p' exponent",
        ),
        (
            FLOAT,
            "0x1.2gp1a",
            "0x1.2 gp1a",
            "hexadecimal mantissa requires a 'p' exponent",
        ),
        (FLOAT, "0x0p", "0x0p", "exponent has no digits"),
        (FLOAT, "0xeP-", "0xeP-", "exponent has no digits"),
        (FLOAT, "0x1234PAB", "0x1234P AB", "exponent has no digits"),
        (FLOAT, "0x1.2p1a", "0x1.2p1 a", ""),
        (INT, "0b_1000_0001", "0b_1000_0001", ""),
        (INT, "0o_600", "0o_600", ""),
        (INT, "0_466", "0_466", ""),
        (INT, "1_000", "1_000", ""),
        (FLOAT, "1_000.000_1", "1_000.000_1", ""),
        (INT, "0x_f00d", "0x_f00d", ""),
        (FLOAT, "0x_f00d.0p1_2", "0x_f00d.0p1_2", ""),
        (
            INT,
            "0b__1000",
            "0b__1000",
            "'_' must separate successive digits",
        ),
        (
            INT,
            "0o60___0",
            "0o60___0",
            "'_' must separate successive digits",
        ),
        (INT, "0466_", "0466_", "'_' must separate successive digits"),
        (FLOAT, "1_.", "1_.", "'_' must separate successive digits"),
        (FLOAT, "0._1", "0._1", "'_' must separate successive digits"),
        (
            FLOAT,
            "2.7_e0",
            "2.7_e0",
            "'_' must separate successive digits",
        ),
        (
            INT,
            "0x___0",
            "0x___0",
            "'_' must separate successive digits",
        ),
        (
            FLOAT,
            "0x1.0_p0",
            "0x1.0_p0",
            "'_' must separate successive digits",
        ),
    ];
    for &(tok, src, tokens, err) in cases {
        let mut s = Scanner::default();
        s.init(src.as_bytes());
        let errs = Rc::new(RefCell::new(String::new()));
        let sink = Rc::clone(&errs);
        s.error = Some(Rc::new(move |_: &mut Scanner<'_>, msg: &str| {
            let mut first = sink.borrow_mut();
            if first.is_empty() {
                *first = msg.to_string();
            }
        }));

        for (i, want) in tokens.split(' ').enumerate() {
            errs.borrow_mut().clear();
            let got = s.scan();
            let lit = s.token_text();
            if i == 0 {
                assert_eq!(got, tok, "{src:?}: token");
                assert_eq!(*errs.borrow(), err, "{src:?}: error");
            }
            assert_eq!(
                String::from_utf8_lossy(&lit),
                want,
                "{src:?}: literal (token {got})"
            );
        }

        // make sure we read all
        assert_eq!(s.scan(), EOF, "{src:?}: not at EOF");
    }
}

#[test]
fn issue_30320_extract_ints() {
    fn extract(src: &str, mode: usize) -> String {
        let mut s = Scanner::default();
        s.init(src.as_bytes());
        s.mode = mode;
        let mut res = String::new();
        loop {
            match s.scan() {
                INT | FLOAT => {
                    if !res.is_empty() {
                        res.push(' ');
                    }
                    res.push_str(&String::from_utf8_lossy(&s.token_text()));
                }
                EOF => return res,
                _ => {}
            }
        }
    }
    let cases = [
        (
            "foo01.bar31.xx-0-1-1-0",
            "01 31 0 1 1 0",
            scanner::SCAN_INTS,
        ),
        ("foo0/12/0/5.67", "0 12 0 5 67", scanner::SCAN_INTS),
        ("xxx1e0yyy", "1 0", scanner::SCAN_INTS),
        ("1_2", "1_2", scanner::SCAN_INTS),
        ("xxx1.0yyy2e3ee", "1 0 2 3", scanner::SCAN_INTS),
        ("xxx1.0yyy2e3ee", "1.0 2e3", scanner::SCAN_FLOATS),
    ];
    for (input, want, mode) in cases {
        assert_eq!(extract(input, mode), want, "{input:?}");
    }
}

#[test]
fn issue_50909_custom_ident_newlines() {
    let mut s = Scanner::default();
    s.init(&b"hello \n\nworld\n!\n"[..]);
    s.is_ident_rune = Some(Box::new(|ch, _| ch != c('\n')));

    let mut r = Vec::new();
    let mut n = 0;
    while s.scan() != EOF && n < 10 {
        r.extend_from_slice(&s.token_text());
        n += 1;
    }
    assert_eq!(r, b"hello world!");
    assert_eq!(n, 3);
}

#[test]
fn token_string_names() {
    assert_eq!(scanner::token_string(EOF), "EOF");
    assert_eq!(scanner::token_string(IDENT), "Ident");
    assert_eq!(scanner::token_string(INT), "Int");
    assert_eq!(scanner::token_string(FLOAT), "Float");
    assert_eq!(scanner::token_string(CHAR), "Char");
    assert_eq!(scanner::token_string(STRING), "String");
    assert_eq!(scanner::token_string(RAW_STRING), "RawString");
    assert_eq!(scanner::token_string(COMMENT), "Comment");
    assert_eq!(scanner::token_string(c('a')), "\"a\"");
    assert_eq!(scanner::token_string(c('\n')), "\"\\n\"");
    assert_eq!(scanner::token_string(0x1F600), "\"😀\"");
}

#[test]
fn position_string() {
    let mut p = Position::default();
    assert_eq!(p.to_string(), "<input>");
    assert!(!p.is_valid());
    p.line = 3;
    p.column = 7;
    assert_eq!(p.to_string(), "<input>:3:7");
    p.filename = "main.go".into();
    assert_eq!(p.to_string(), "main.go:3:7");
    assert!(p.is_valid());
}

#[test]
fn go_tokens_mode_constants() {
    assert_eq!(
        scanner::DEFAULT_TOKENS,
        scanner::SCAN_IDENTS
            | scanner::SCAN_FLOATS
            | scanner::SCAN_CHARS
            | scanner::SCAN_STRINGS
            | scanner::SCAN_RAW_STRINGS
            | scanner::SCAN_COMMENTS
            | scanner::SKIP_COMMENTS
    );
    assert_eq!(
        scanner::DEFAULT_WHITESPACE,
        (1 << 9) | (1 << 10) | (1 << 13) | (1 << 32)
    );
    assert_eq!(scanner::SCAN_IDENTS, 1 << 2);
    assert_eq!(scanner::SKIP_COMMENTS, 1 << 9);
}

#[test]
fn error_callback_may_clear_itself() {
    // As in Go, a callback that sets Error to nil stops being called; later
    // errors go to standard error, so only the first error reaches the callback.
    let calls = Rc::new(Cell::new(0));
    let sink = Rc::clone(&calls);
    let mut s = Scanner::default();
    s.init(&b"\x00\x00"[..]);
    s.error = Some(Rc::new(move |s: &mut Scanner<'_>, _: &str| {
        sink.set(sink.get() + 1);
        s.error = None;
    }));
    assert_eq!(s.scan(), c('\0'));
    assert_eq!(s.error_count, 2); // both NULs are counted
    assert_eq!(calls.get(), 1);
    assert!(s.error.is_none());
}
