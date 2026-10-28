use rust_stdlib::net::textproto::{
    canonical_mime_header_key, trim_bytes, trim_string, Error, Limits, MIMEHeader, ProtocolError,
    Reader, ResponseError, Writer,
};
use std::io::{self, BufRead, BufReader, Read, Write};

fn reader(data: &[u8]) -> Reader<&[u8]> {
    Reader::new(data)
}

/// One byte per `fill_buf`, so every CR/LF and limit check straddles reads.
fn trickle(data: &[u8]) -> Reader<BufReader<&[u8]>> {
    Reader::new(BufReader::with_capacity(1, data))
}

/// Interrupts before every successful read.
struct Interrupting<'a> {
    data: &'a [u8],
    interrupt: bool,
}

impl Read for Interrupting<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.interrupt = !self.interrupt;
        if self.interrupt {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let n = buf.len().min(self.data.len()).min(3);
        buf[..n].copy_from_slice(&self.data[..n]);
        self.data = &self.data[n..];
        Ok(n)
    }
}

#[test]
fn canonical_keys_follow_go_rules() {
    for (input, expected) in [
        ("a-b-c", "A-B-C"),
        ("a-1-c", "A-1-C"),
        ("User-Agent", "User-Agent"),
        ("uSER-aGENT", "User-Agent"),
        ("user-agent", "User-Agent"),
        ("USER-AGENT", "User-Agent"),
        ("foo-bar_baz", "Foo-Bar_baz"),
        ("foo_bar-baz", "Foo_bar-Baz"),
        ("--", "--"),
        ("", ""),
        // Spaces and non-token bytes leave the key untouched.
        ("foo bar", "foo bar"),
        ("foo ", "foo "),
        ("cAfé", "cAfé"),
        ("a:b", "a:b"),
        ("C Ontent-Transfer-Encoding", "C Ontent-Transfer-Encoding"),
        ("x-ID", "X-Id"),
        ("WWW-AUTHENTICATE", "Www-Authenticate"),
    ] {
        assert_eq!(canonical_mime_header_key(input), expected, "{input:?}");
    }
}

#[test]
fn trimming_matches_go_ascii_space_set() {
    assert_eq!(trim_string(" \t\r\n x y \n"), "x y");
    assert_eq!(trim_string("\u{b}x\u{c}"), "\u{b}x\u{c}");
    assert_eq!(trim_bytes(b"\r\n\t"), b"");
    assert_eq!(trim_bytes(b" a "), b"a");
}

#[test]
fn mime_header_methods_canonicalize() {
    let mut header = MIMEHeader::new();
    header.add("content-type", "a");
    header.add("Content-Type", "b");
    header.set("x-id", "1");
    assert_eq!(header.values("CONTENT-TYPE"), ["a", "b"]);
    assert_eq!(header.get("X-ID"), Some("1"));
    header.del("content-type");
    assert_eq!(header.get("Content-Type"), None);
    header.add("bad key", "v");
    assert_eq!(header.raw_values("bad key"), ["v"]);
    assert_eq!(header.len(), 2);
}

#[test]
fn lines_accept_bare_lf_and_keep_bare_cr() {
    let mut r = reader(b"one\r\ntwo\nthree\rx\r\nlast\r");
    assert_eq!(r.read_line().unwrap(), "one");
    assert_eq!(r.read_line().unwrap(), "two");
    assert_eq!(r.read_line().unwrap(), "three\rx");
    // A final line without LF keeps its CR and is still a line.
    assert_eq!(r.read_line().unwrap(), "last\r");
    assert!(matches!(r.read_line(), Err(Error::Eof)));
    let mut r = trickle(b"a\r\nb\r\r\n\r\n");
    assert_eq!(r.read_line().unwrap(), "a");
    assert_eq!(r.read_line().unwrap(), "b\r");
    assert_eq!(r.read_line().unwrap(), "");
    assert!(matches!(r.read_line(), Err(Error::Eof)));
}

#[test]
fn interrupted_reads_are_retried() {
    let data = b"Key: value\r\n continued\r\n\r\n";
    let mut r = Reader::new(BufReader::with_capacity(
        4,
        Interrupting {
            data,
            interrupt: false,
        },
    ));
    let header = r.read_mime_header().unwrap();
    assert_eq!(header.get("key"), Some("value continued"));
}

#[test]
fn line_budget_is_exact_and_ignores_terminators() {
    let limits = Limits {
        max_line_bytes: 5,
        ..Limits::default()
    };
    let mut r = Reader::with_limits(
        BufReader::with_capacity(2, &b"12345\r\n123456\n"[..]),
        limits,
    );
    assert_eq!(r.read_line().unwrap(), "12345");
    assert!(matches!(r.read_line(), Err(Error::MessageTooLarge)));
    let mut r = Reader::with_limits(&b"1234\r"[..], limits);
    assert_eq!(r.read_line().unwrap(), "1234\r");
    let mut r = Reader::with_limits(&b"12345\r"[..], limits);
    assert!(matches!(r.read_line(), Err(Error::MessageTooLarge)));
}

#[test]
fn non_utf8_text_is_an_explicit_error() {
    let mut r = reader(b"caf\xe9\r\nnext\r\n");
    assert!(matches!(r.read_line(), Err(Error::InvalidUtf8)));
    assert_eq!(r.read_line().unwrap(), "next");
    let mut r = reader(b"caf\xe9\r\n");
    assert_eq!(r.read_line_bytes().unwrap(), b"caf\xe9");
    // Go accepts obs-text values; strings here must be UTF-8.
    let mut r = reader(b"X: \xe9\r\n\r\n");
    assert!(matches!(r.read_mime_header(), Err(Error::InvalidUtf8)));
    let mut r = reader("X: é\r\n\r\n".as_bytes());
    assert_eq!(r.read_mime_header().unwrap().get("x"), Some("é"));
}

#[test]
fn continued_lines_fold_like_go() {
    let mut r = reader(b"Line 1\r\n  continued...\r\nLine 2\r\n\r\nx\r\n \r\n\ty\r\n");
    assert_eq!(r.read_continued_line().unwrap(), "Line 1 continued...");
    assert_eq!(r.read_continued_line().unwrap(), "Line 2");
    // Empty lines are never continued.
    assert_eq!(r.read_continued_line().unwrap(), "");
    // A whitespace-only continuation still contributes its separator space.
    assert_eq!(r.read_continued_line().unwrap(), "x  y");
    assert!(matches!(r.read_continued_line(), Err(Error::Eof)));
    // Folding whitespace at end of input is kept as one space.
    let mut r = reader(b"k: v\r\n   ");
    assert_eq!(r.read_continued_line().unwrap(), "k: v ");
}

#[test]
fn folding_whitespace_abuse_is_bounded() {
    let limits = Limits {
        max_line_bytes: 64,
        ..Limits::default()
    };
    let mut input = b"k: v\r\n".to_vec();
    input.extend(std::iter::repeat_n(b' ', 1000));
    input.extend_from_slice(b"x\r\n\r\n");
    let mut r = Reader::with_limits(&input[..], limits);
    assert!(matches!(
        r.read_continued_line(),
        Err(Error::MessageTooLarge)
    ));
    // Many short continuation lines still hit the continued-line budget.
    let mut input = b"k: v\r\n".to_vec();
    for _ in 0..100 {
        input.extend_from_slice(b" x\r\n");
    }
    let mut r = Reader::with_limits(&input[..], limits);
    assert!(matches!(
        r.read_continued_line(),
        Err(Error::MessageTooLarge)
    ));
}

#[test]
fn mime_header_reads_canonical_multi_values() {
    let input =
        b"my-key: Value 1  \r\nLong-key: Even \n Longer Value\r\nmy-Key: Value 2\r\n\n\r\nbody";
    let mut r = trickle(input);
    let header = r.read_mime_header().unwrap();
    assert_eq!(header.values("My-Key"), ["Value 1", "Value 2"]);
    assert_eq!(header.get("Long-Key"), Some("Even Longer Value"));
    assert_eq!(header.len(), 2);
    assert_eq!(r.read_line().unwrap(), "");
    assert_eq!(r.read_line().unwrap(), "body");
}

#[test]
fn mime_header_keys_with_spaces_are_kept_verbatim() {
    let header = reader(b"Foo Bar: 1\r\nfoo : 2\r\nfoo: 3\r\n\r\n")
        .read_mime_header()
        .unwrap();
    assert_eq!(header.raw_values("Foo Bar"), ["1"]);
    assert_eq!(header.raw_values("foo "), ["2"]);
    assert_eq!(header.get("foo"), Some("3"));
}

#[test]
fn mime_header_rejects_malformed_input() {
    for input in [
        &b" first: line\r\n\r\n"[..],
        b"\tfirst: line\r\n\r\n",
        b"no colon\r\n\r\n",
        b": empty key\r\n\r\n",
        b"bad\x01key: v\r\n\r\n",
        b"bad\"key: v\r\n\r\n",
        b"k\xc3\xa9y: v\r\n\r\n",
        b"key: ctl\x01\r\n\r\n",
        b"key: del\x7f\r\n\r\n",
        b"key: nul\x00\r\n\r\n",
        b"key: bare\rcr\r\n\r\n",
        b"Key: v\r\nfoo\r\n\r\n",
    ] {
        assert!(
            matches!(
                reader(input).read_mime_header(),
                Err(Error::Protocol(ProtocolError(_)))
            ),
            "{input:?}"
        );
    }
    // Missing blank line: Go returns io.EOF.
    assert!(matches!(
        reader(b"Key: v\r\n").read_mime_header(),
        Err(Error::Eof)
    ));
    assert!(matches!(reader(b"").read_mime_header(), Err(Error::Eof)));
    assert!(reader(b"\r\n").read_mime_header().unwrap().is_empty());
}

#[test]
fn mime_header_count_and_memory_budgets() {
    let input = b"A: 1\r\nB: 2\r\nC: 3\r\n\r\n";
    let limits = |max_header_bytes, max_headers| Limits {
        max_header_bytes,
        max_headers,
        ..Limits::default()
    };
    assert_eq!(
        Reader::with_limits(&input[..], limits(1 << 20, 3))
            .read_mime_header()
            .unwrap()
            .len(),
        3
    );
    // A budget below the fixed 400-byte overhead still bounds the line read:
    // only an empty header fits, and a huge first line is not buffered.
    assert!(Reader::with_limits(&b"\r\n"[..], limits(10, 10))
        .read_mime_header()
        .unwrap()
        .is_empty());
    let endless = BufReader::new(Read::chain(&b"K: "[..], io::repeat(b'x')).take(1 << 30));
    let mut huge = Reader::with_limits(endless, limits(10, 10));
    assert!(matches!(
        huge.read_mime_header(),
        Err(Error::MessageTooLarge)
    ));
    assert!(matches!(
        Reader::with_limits(&input[..], limits(1 << 20, 2)).read_mime_header(),
        Err(Error::MessageTooLarge)
    ));
    // Go's accounting: 400 once, then key + 200 per new key, plus each value.
    let exact = 400 + 3 * (1 + 200 + 1);
    assert!(Reader::with_limits(&input[..], limits(exact, 10))
        .read_mime_header()
        .is_ok());
    assert!(matches!(
        Reader::with_limits(&input[..], limits(exact - 1, 10)).read_mime_header(),
        Err(Error::MessageTooLarge)
    ));
    // One oversized line fails before it is buffered whole.
    let mut big = b"K: ".to_vec();
    big.extend(std::iter::repeat_n(b'x', 10_000));
    big.extend_from_slice(b"\r\n\r\n");
    assert!(matches!(
        Reader::with_limits(&big[..], limits(1000, 10)).read_mime_header(),
        Err(Error::MessageTooLarge)
    ));
}

#[test]
fn oversized_continuation_line_is_rejected_not_truncated() {
    // Go stops folding and parses the rest of the line as the next field;
    // the port reports the budget violation instead.
    let mut input = b"A: b\r\n ".to_vec();
    input.extend(std::iter::repeat_n(b'c', 2000));
    input.extend_from_slice(b"\r\nD: e\r\n\r\n");
    let limits = Limits {
        max_header_bytes: 1400,
        ..Limits::default()
    };
    assert!(matches!(
        Reader::with_limits(&input[..], limits).read_mime_header(),
        Err(Error::MessageTooLarge)
    ));
}

#[test]
fn code_lines_and_responses() {
    assert_eq!(
        reader(b"220 plan9.bell-labs.com ESMTP\r\n")
            .read_code_line(22)
            .unwrap(),
        (220, "plan9.bell-labs.com ESMTP".to_owned())
    );
    match reader(b"550 denied\r\n").read_code_line(2) {
        Err(Error::Response(ResponseError { code, msg })) => {
            assert_eq!((code, msg.as_str()), (550, "denied"))
        }
        other => panic!("{other:?}"),
    }
    for line in [
        &b"25\r\n"[..],
        b"250x\r\n",
        b"099 low\r\n",
        b"+25 x\r\n",
        b"2a0 x\r\n",
    ] {
        assert!(matches!(
            reader(line).read_code_line(0),
            Err(Error::Protocol(ProtocolError(_)))
        ));
    }
    assert!(matches!(
        reader(b"250-more\r\n250 done\r\n").read_code_line(250),
        Err(Error::Protocol(ProtocolError(_)))
    ));
    let mut r = reader(b"250-mx.example\r\n250-8BITMIME\r\n250 SIZE\r\n");
    assert_eq!(
        r.read_response(25).unwrap(),
        (250, "mx.example\n8BITMIME\nSIZE".to_owned())
    );
    // RFC 959 form: inner lines without the code are kept verbatim.
    let mut r = reader(b"230-Welcome\r\n  to the server\r\n231-other\r\n230 done\r\n");
    assert_eq!(
        r.read_response(0).unwrap(),
        (230, "Welcome\n  to the server\n231-other\ndone".to_owned())
    );
    // A mismatch reports the whole multi-line message.
    match reader(b"550-a\r\n550 b\r\n").read_response(2) {
        Err(Error::Response(ResponseError { code, msg })) => {
            assert_eq!((code, msg.as_str()), (550, "a\nb"))
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        reader(b"250-unterminated\r\n").read_response(0),
        Err(Error::Eof)
    ));
    let limits = Limits {
        max_response_bytes: 16,
        ..Limits::default()
    };
    let mut endless = Vec::new();
    for _ in 0..100 {
        endless.extend_from_slice(b"250-line\r\n");
    }
    assert!(matches!(
        Reader::with_limits(&endless[..], limits).read_response(0),
        Err(Error::MessageTooLarge)
    ));
}

#[test]
fn dot_reader_decodes_and_stops_at_terminator() {
    let input = b"..leading\r\nplain\r\nbare\rcr\r\n.\r\nafter\r\n";
    let mut r = trickle(input);
    let mut body = Vec::new();
    r.dot_reader().read_to_end(&mut body).unwrap();
    assert_eq!(body, b".leading\nplain\nbare\rcr\n");
    assert_eq!(r.read_line().unwrap(), "after");
    // Bare LF terminator and a dot followed by a non-terminator.
    let mut r = reader(b".\rx\n.\n");
    assert_eq!(r.read_dot_bytes().unwrap(), b"\rx\n");
}

#[test]
fn dot_reader_go_quirks() {
    // After a bare-LF line ending, Go's state machine treats a following empty
    // line as data, so ".\r\n" right after "\n\n" is not a terminator.
    assert!(matches!(
        reader(b"a\n\n.\r\n").read_dot_bytes(),
        Err(Error::UnexpectedEof)
    ));
    // read_dot_lines uses line framing and does see that terminator.
    assert_eq!(reader(b"a\n\n.\r\n").read_dot_lines().unwrap(), ["a", ""]);
}

#[test]
fn unterminated_dot_encoding_is_unexpected_eof() {
    for input in [
        &b""[..],
        b"data\r\n",
        b"data\r\n.",
        b"data\r\n.\r",
        b"..\r\n",
    ] {
        assert!(
            matches!(reader(input).read_dot_bytes(), Err(Error::UnexpectedEof)),
            "{input:?}"
        );
        let mut r = reader(input);
        let mut sink = Vec::new();
        let error = r.dot_reader().read_to_end(&mut sink).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }
    for input in [&b""[..], b"one\r\n..two\r\n", b"..\r\n", b"x\r\n.\rx"] {
        assert!(
            matches!(reader(input).read_dot_lines(), Err(Error::UnexpectedEof)),
            "{input:?}"
        );
    }
    // Line framing accepts a final "." without a line ending, as Go does.
    assert_eq!(reader(b"data\r\n.").read_dot_lines().unwrap(), ["data"]);
}

#[test]
fn abandoned_dot_reader_is_drained_by_next_call() {
    let mut r = reader(b"abc\r\n..x\r\n.\r\nnext\r\n");
    let mut one = [0; 1];
    assert_eq!(r.dot_reader().read(&mut one).unwrap(), 1);
    assert_eq!(&one, b"a");
    assert_eq!(r.read_line().unwrap(), "next");
    // The drained reader also gives back the stream to a new block.
    let mut r = reader(b"x\r\n.\r\ny\r\n.\r\n");
    let _ = r.dot_reader();
    assert_eq!(r.read_dot_lines().unwrap(), ["y"]);
}

#[test]
fn dot_budgets() {
    let limits = Limits {
        max_dot_bytes: 4,
        ..Limits::default()
    };
    assert_eq!(
        Reader::with_limits(
            &b"abcd\r\n.\r\n"[..],
            Limits {
                max_dot_bytes: 5,
                ..limits
            }
        )
        .read_dot_bytes()
        .unwrap(),
        b"abcd\n"
    );
    assert!(matches!(
        Reader::with_limits(&b"abcd\r\n.\r\n"[..], limits).read_dot_bytes(),
        Err(Error::MessageTooLarge)
    ));
    // Empty lines cost one byte each, so a flood of them is bounded too.
    assert!(matches!(
        Reader::with_limits(&b"\r\n\r\n\r\n\r\n\r\n.\r\n"[..], limits).read_dot_lines(),
        Err(Error::MessageTooLarge)
    ));
}

#[test]
fn print_line_and_dot_writer_match_go() {
    let mut out = Vec::new();
    let mut w = Writer::new(&mut out);
    w.print_line(format_args!("HELO {}", "example.com"))
        .unwrap();
    let mut dot = w.dot_writer();
    // Split writes exercise state carried between calls.
    for chunk in [&b".a"[..], b"\r", b"\nb\n", b".", b"c\r\r\n"] {
        dot.write_all(chunk).unwrap();
    }
    dot.close().unwrap();
    // A CR not followed by LF stays data, so the later LF gains its own CR.
    assert_eq!(out, b"HELO example.com\r\n..a\r\nb\r\n..c\r\r\r\n.\r\n");

    for (input, expected) in [
        (&b""[..], &b"\r\n.\r\n"[..]),
        (b"x", b"x\r\n.\r\n"),
        (b"x\r", b"x\r\n.\r\n"),
        (b"x\n", b"x\r\n.\r\n"),
        (b".", b"..\r\n.\r\n"),
    ] {
        let mut out = Vec::new();
        let mut w = Writer::new(&mut out);
        let mut dot = w.dot_writer();
        dot.write_all(input).unwrap();
        dot.close().unwrap();
        assert_eq!(out, expected, "{input:?}");
    }
}

#[test]
fn dropped_dot_writer_is_closed_by_next_call() {
    let mut out = Vec::new();
    let mut w = Writer::new(&mut out);
    w.dot_writer().write_all(b"body").unwrap();
    w.print_line("QUIT").unwrap();
    let out = w.into_inner().unwrap();
    assert_eq!(out, b"body\r\n.\r\nQUIT\r\n");
    let mut w = Writer::new(Vec::new());
    w.dot_writer().write_all(b"x\n").unwrap();
    assert_eq!(w.into_inner().unwrap(), b"x\r\n.\r\n");
}

#[test]
fn buffered_reader_position_survives_header_read() {
    let mut r = Reader::new(BufReader::new(&b"A: 1\r\n\r\nrest of body"[..]));
    r.read_mime_header().unwrap();
    let mut inner = r.into_inner();
    let mut rest = String::new();
    inner.read_to_string(&mut rest).unwrap();
    assert_eq!(rest, "rest of body");
    assert!(inner.fill_buf().unwrap().is_empty());
}
