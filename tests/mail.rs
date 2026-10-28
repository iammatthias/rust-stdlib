use rust_stdlib::mime::{self, WordDecoder, WordEncoder};
use rust_stdlib::net::mail::{
    self, parse_address, parse_address_list, parse_date, read_message, read_message_with_limits,
    Address, AddressParser, Error,
};
use rust_stdlib::net::textproto::{self, Limits};
use std::io::Read;

fn addr(name: &str, address: &str) -> Address {
    Address {
        name: name.into(),
        address: address.into(),
    }
}

#[test]
fn parses_rfc5322_address_forms() {
    for (input, expected) in [
        ("jdoe@machine.example", addr("", "jdoe@machine.example")),
        (
            "John Doe <jdoe@machine.example>",
            addr("John Doe", "jdoe@machine.example"),
        ),
        (
            "\"Joe Q. Public\" <john.q.public@example.com>",
            addr("Joe Q. Public", "john.q.public@example.com"),
        ),
        ("  Joe   Q.  <j@x.test>  ", addr("Joe Q.", "j@x.test")),
        (
            "Pete(A nice \\) chap) <pete@silly.test>",
            addr("Pete", "pete@silly.test"),
        ),
        (
            "asdf@example.com (Display Name)",
            addr("Display Name", "asdf@example.com"),
        ),
        ("\"\\\"quoted\\\"\" <a@b.c>", addr("\"quoted\"", "a@b.c")),
        ("\"a b\"@example.com", addr("", "a b@example.com")),
        ("a@[192.0.2.1]", addr("", "a@[192.0.2.1]")),
        ("a@[IPv6:2001:db8::1]", addr("", "a@[IPv6:2001:db8::1]")),
        ("a@[IPv6:1.2.3.4]", addr("", "a@[IPv6:1.2.3.4]")),
        ("a@[::ffff:1.2.3.4]", addr("", "a@[::ffff:1.2.3.4]")),
        ("Ω <ω@ω.ω>", addr("Ω", "ω@ω.ω")),
        ("< a@b.c>", addr("", "a@b.c")),
        ("a@ b.c", addr("", "a@b.c")),
        ("g: a@b;", addr("", "a@b")),
    ] {
        assert_eq!(parse_address(input).unwrap(), expected, "{input:?}");
    }
}

#[test]
fn decodes_encoded_word_display_names() {
    for (input, name) in [
        (
            "=?iso-8859-1?q?J=F6rg_Doe?= <joerg@example.com>",
            "Jörg Doe",
        ),
        ("=?utf-8?q?J=C3=B6rg?= <joerg@example.com>", "Jörg"),
        (
            "=?US-ASCII?Q?Keith_Moore?= <moore@cs.utk.edu>",
            "Keith Moore",
        ),
        ("=?ISO-8859-1?B?SvZyZw==?= <joerg@example.com>", "Jörg"),
        ("=?us-ascii?q?caf=E9?= <a@b.c>", "caf\u{fffd}"),
        // Adjacent encoded words are joined, even across a split character.
        ("=?utf-8?q?=E2=82?= =?utf-8?q?=AC?= <a@b.c>", "€"),
        ("Mr =?utf-8?q?J=C3=B6rg?= Doe <a@b.c>", "Mr Jörg Doe"),
        // Malformed encoded words are kept as written.
        ("=?utf-8?q?bad=?= <a@b.c>", "=?utf-8?q?bad=?="),
        ("=?utf-8?x?abc?= <a@b.c>", "=?utf-8?x?abc?="),
        ("asdf@example.com (=?utf-8?q?J=C3=B6rg?=  Doe)", "Jörg Doe"),
        // Go's charset comparison folds U+017F to "s".
        ("=?u\u{17f}-a\u{17f}cii?q?x?= <a@b.c>", "x"),
    ] {
        assert_eq!(parse_address(input).unwrap().name, name, "{input:?}");
    }
}

#[test]
fn unsupported_charsets_and_invalid_utf8_are_errors() {
    assert!(parse_address("=?koi8-r?q?abc?= <a@b.c>").is_err());
    assert!(parse_address("a@b.c (=?koi8-r?q?abc?=)").is_err());
    // Go keeps the raw bytes; the port rejects names that are not UTF-8.
    assert!(parse_address("=?utf-8?q?=FF?= <a@b.c>").is_err());
    // A group's display name is discarded, so it is never validated.
    assert_eq!(
        parse_address_list("=?utf-8?q?=FF?=: a@b;").unwrap(),
        [addr("", "a@b")]
    );
    // After a first word, Go ignores the charset error and drops that word.
    assert_eq!(
        parse_address("Jo =?koi8-r?q?abc?= <a@b.c>").unwrap(),
        addr("Jo", "a@b.c")
    );
}

#[test]
fn custom_word_decoder_hook() {
    let parser = AddressParser {
        word_decoder: WordDecoder::new().with_charset_reader(|charset, bytes| {
            if charset == "x-rot13" {
                Ok(bytes
                    .iter()
                    .map(|&b| match b {
                        b'a'..=b'z' => char::from((b - b'a' + 13) % 26 + b'a'),
                        _ => char::from(b),
                    })
                    .collect())
            } else {
                Err(mime::Error::new("unsupported test charset"))
            }
        }),
        ..AddressParser::default()
    };
    assert_eq!(
        parser.parse("=?X-ROT13?q?uryyb?= <a@b.c>").unwrap().name,
        "hello"
    );
    assert!(parser.parse("=?koi8-r?q?abc?= <a@b.c>").is_err());
    assert_eq!(parser.parse_list("a@b, c@d").unwrap().len(), 2);
}

#[test]
fn parses_lists_and_groups() {
    assert_eq!(
        parse_address_list("Mary Smith <mary@x.test>, jdoe@example.org, Who? <one@y.test>")
            .unwrap(),
        [
            addr("Mary Smith", "mary@x.test"),
            addr("", "jdoe@example.org"),
            addr("Who?", "one@y.test"),
        ]
    );
    assert_eq!(
        parse_address_list("A Group:Ed Jones <c@a.test>,joe@where.test,John <jdoe@one.test>;, x@y")
            .unwrap(),
        [
            addr("Ed Jones", "c@a.test"),
            addr("", "joe@where.test"),
            addr("John", "jdoe@one.test"),
            addr("", "x@y"),
        ]
    );
    assert!(parse_address_list("Undisclosed recipients:;")
        .unwrap()
        .is_empty());
    assert_eq!(parse_address_list(",a@b,, ,c@d,").unwrap().len(), 2);
    assert!(parse_address("Undisclosed recipients:;").is_err());
    assert!(parse_address("g: a@b, c@d;").is_err());
}

#[test]
fn rejects_malformed_addresses() {
    for input in [
        "",
        " ",
        "@",
        "a@",
        "@b",
        "foo.bar",
        "Full Name",
        "<a@b.c",
        "<a@b.c >",
        "a@b.c>",
        ".a@b.c",
        "a.@b.c",
        "a..b@c.d",
        "a@.b",
        "a@b.",
        "a@b..c",
        "\"\"@example.com",
        "a@[010.0.0.1]",
        "a@[1.2.3]",
        "a@[256.1.1.1]",
        "a@[IPv6:::1%eth0]",
        "a@[::1]",
        "a@[ 1.2.3.4]",
        "a@[1.2.3.4",
        "a@b (unclosed",
        "a@b c@d",
        "a@b;c@d",
        "g: a@b",
        "\x01@b",
        "\"\\\x01\" <a@b>",
        "\"unclosed <a@b>",
        "Name <a@b> extra",
        "a @b.c",
    ] {
        assert!(parse_address(input).is_err(), "{input:?}");
    }
    for input in ["a@b c@d", "a@b;c@d", "g: a@b", "a@b, (x", ""] {
        assert!(parse_address_list(input).is_err(), "{input:?}");
    }
}

#[test]
fn address_parser_budgets() {
    let parser = AddressParser {
        max_bytes: 10,
        max_addresses: 2,
        ..AddressParser::default()
    };
    assert!(matches!(
        parser.parse("abcdef@example.com"),
        Err(Error::TooLarge(_))
    ));
    assert!(matches!(
        parser.parse_list("a@b,c@d,e@f"),
        Err(Error::TooLarge(_))
    ));
    assert_eq!(parser.parse_list("a@b,c@d").unwrap().len(), 2);
    let parser = AddressParser {
        max_addresses: 2,
        ..AddressParser::default()
    };
    assert!(matches!(
        parser.parse_list("g: a@b, c@d, e@f;"),
        Err(Error::TooLarge(_))
    ));
    // Deep comment nesting is iterative, not recursive.
    let deep = format!("a@b {}{}", "(".repeat(100_000), ")".repeat(100_000));
    let parsed = parse_address(&deep).unwrap();
    assert_eq!(parsed.address, "a@b");
    assert_eq!(parsed.name.len(), 2 * 99_999);
    let skipped = format!("<a@b> {}{}", "(".repeat(100_000), ")".repeat(100_000));
    assert_eq!(parse_address(&skipped).unwrap(), addr("", "a@b"));
}

#[test]
fn formats_addresses_like_go() {
    for (name, address, expected) in [
        ("", "bob@example.com", "<bob@example.com>"),
        ("Bob", "bob@example.com", "\"Bob\" <bob@example.com>"),
        (
            "Bob \"B\" Bobson",
            "bob@example.com",
            "\"Bob \\\"B\\\" Bobson\" <bob@example.com>",
        ),
        (
            "Böb",
            "bob@example.com",
            "=?utf-8?q?B=C3=B6b?= <bob@example.com>",
        ),
        (
            "Böb, Jacöb",
            "bob@example.com",
            "=?utf-8?b?QsO2YiwgSmFjw7Zi?= <bob@example.com>",
        ),
        ("", "bob bob@example.com", "<\"bob bob\"@example.com>"),
        ("", "bob.@example.com", "<\"bob.\"@example.com>"),
        ("", ".bob@example.com", "<\".bob\"@example.com>"),
        ("", "bob..b@example.com", "<\"bob..b\"@example.com>"),
        ("", "a.b@example.com", "<a.b@example.com>"),
        ("", "no-at-sign", "<no-at-sign@>"),
        ("", "\"@\"@x", "<\"\\\"@\\\"\"@x>"),
        ("ctl\u{1}", "a@b", "=?utf-8?q?ctl=01?= <a@b>"),
        ("tab\there", "a@b", "\"tab\there\" <a@b>"),
        ("", "日本@example.com", "<日本@example.com>"),
    ] {
        assert_eq!(
            addr(name, address).to_string(),
            expected,
            "{name:?} {address:?}"
        );
    }
    // Long names split into encoded words of at most 75 bytes.
    let long = addr(&"é".repeat(40), "a@b").to_string();
    let words: Vec<&str> = long.trim_end_matches(" <a@b>").split(' ').collect();
    assert!(words.len() > 1);
    assert!(words
        .iter()
        .all(|w| w.len() <= 75 && w.starts_with("=?utf-8?q?")));
    // Formatting then parsing round-trips.
    for a in [
        addr("Jörg (Doe)", "j@example.com"),
        addr("x \"y\"", "a.b@c"),
    ] {
        assert_eq!(parse_address(&a.to_string()).unwrap(), a);
    }
}

#[test]
fn word_encoder_and_decoder() {
    assert_eq!(WordEncoder::Q.encode("utf-8", "plain"), "plain");
    assert_eq!(WordEncoder::B.encode("UTF-8", "€"), "=?UTF-8?b?4oKs?=");
    assert_eq!(WordEncoder::Q.encode("iso-8859-1", "a b_c=?"), "a b_c=?");
    assert_eq!(
        WordEncoder::Q.encode("iso-8859-1", "a\u{1}"),
        "=?iso-8859-1?q?a=01?="
    );
    let d = WordDecoder::new();
    assert_eq!(d.decode("=?UTF-8?b?4oKs?=").unwrap(), "€");
    assert!(d.decode("=?UTF-8?b?4oKs").is_err());
    assert!(d.decode("=?utf-8?q?=FF?=").is_err());
    assert!(d.decode("=??q?x?=").is_err());
    assert_eq!(
        d.decode_header("=?utf-8?q?a?=  \r\n =?utf-8?q?b?= c =?utf-8?q?d?=")
            .unwrap(),
        "ab c d"
    );
    assert_eq!(
        d.decode_header("x=?utf-8?q?bad=?=y").unwrap(),
        "x=?utf-8?q?bad=?=y"
    );
    assert!(d.decode_header("=?koi8-r?q?a?=").is_err());
    assert!(WordDecoder::new()
        .with_max_bytes(4)
        .decode_header("hello")
        .is_err());
}

fn date(text: &str) -> (i64, u32, i32) {
    let parsed = parse_date(text).unwrap_or_else(|e| panic!("{text:?}: {e}"));
    (parsed.unix(), parsed.nanosecond() as u32, parsed.zone().1)
}

#[test]
fn parses_rfc5322_dates() {
    for (input, expected) in [
        ("Mon, 02 Jan 2006 15:04:05 -0700", (1136239445, 0, -25200)),
        ("2 Jan 2006 15:04:05 -0700", (1136239445, 0, -25200)),
        ("mon, 2 jan 06 15:04 -0700", (1136239440, 0, -25200)),
        (
            "Fri, 21 Nov 1997 09:55:06 -0600 (MDT)",
            (880127706, 0, -21600),
        ),
        ("Thu, 20 Nov 1997 09:55:06 MDT (MDT)", (880019706, 0, 0)),
        ("21 Nov 97 09:55:06 GMT", (880106106, 0, 0)),
        ("Wed, 31 Dec 1969 16:00 UT", (-28800, 0, 0)),
        ("02 Jan 2006 15:04 UTC", (1136214240, 0, 0)),
        ("1 Jan 68 00:00 +0000", (3092601600, 0, 0)),
        ("1 Jan 69 00:00 +0000", (-31536000, 0, 0)),
        (
            "Mon, 02 Jan 2006 15:04:05.123456789123 +0000",
            (1136214245, 123456789, 0),
        ),
        (
            "Mon, 02 Jan 2006 15:04:05,5 +0000",
            (1136214245, 500000000, 0),
        ),
        (
            "Mon,  02   Jan 2006 15:04:05 -0700",
            (1136239445, 0, -25200),
        ),
        (
            "  Mon, 02 Jan 2006 15:04:05 -0700 trailing junk",
            (1136239445, 0, -25200),
        ),
        (
            "Mon, 02 Jan\r\n 2006 15:04:05 -0700",
            (1136239445, 0, -25200),
        ),
        ("29 Feb 2024 00:00 +2359", (1709078460, 0, 86340)),
        ("1 Jan 0001 00:00 +0100", (-62135600400, 0, 3600)),
        // Go keeps a named zone's civil time as UTC and only attaches the
        // GMT±h offset.
        ("Mon, 1 Feb 2021 07:00:00 GMT+5", (1612162800, 0, 18000)),
        ("Tue, 02 JAN 1997 09:04:05 GMT-23", (852195845, 0, -82800)),
        ("2 Jan 2006 15:04 +07", (1136214240, 0, 0)),
    ] {
        assert_eq!(date(input), expected, "{input:?}");
    }
}

#[test]
fn rejects_malformed_dates() {
    for input in [
        "",
        " ",
        "(",
        "Mon, 02 Jan 2006",
        "Mon, 02 Jan 2006 15:04:05 -0700\r",
        "Mon, 02 Jan 2006 15:04:05 -0700 (unclosed",
        "29 Feb 2023 00:00 +0000",
        "32 Jan 2006 00:00 +0000",
        "0 Jan 2006 00:00 +0000",
        "2 Foo 2006 00:00 +0000",
        "2 Jan 2006 24:00 +0000",
        "2 Jan 2006 15:60 +0000",
        "2 Jan 2006 15:04:60 +0000",
        "2 Jan 2006 15:04 +2461",
        "2 Jan 2006 15:04 +2500",
        "2 Jan 2006 15:04 -07:00",
        "2 Jan 2006 15:04 ABCDEF",
        "Xyz, 2 Jan 2006 15:04 +0000",
        "Mon,2 Jan 2006 15:04 +0000",
        "2 Jan 20061 15:04 +0000",
        "2 Jan 200 15:04 +0000",
        "2Jan 2006 15:04 +0000",
        "2 Jan 2006 15:04:05. +0000",
    ] {
        assert!(
            matches!(parse_date(input), Err(Error::Parse(_))),
            "{input:?}"
        );
    }
    // Dates at the edges of what Go accepts: year 0, offsets of 24 hours or
    // more, and a GMT+h date that lands in year 10000.
    assert_eq!(date("29 Feb 0000 00:00 +0000"), (-62_162_121_600, 0, 0));
    assert_eq!(date("1 Jan 2006 00:00 +2400").2, 24 * 3600);
    assert_eq!(date("1 Jan 2006 00:00 -2460").2, -(24 * 3600 + 3600));
    assert_eq!(date("31 Dec 9999 23:00 GMT+5").2, 5 * 3600);
    assert!(matches!(
        parse_date(&" ".repeat(100_000)),
        Err(Error::TooLarge(_))
    ));
}

#[test]
fn reads_messages_leniently() {
    let input = b"From: John <j@example.com>\r\nTo: a@b,\r\n c@d\r\nsubject: Hi\r\nX Weird Key: kept\r\n: dropped\r\nDate: Mon, 02 Jan 2006 15:04:05 -0700\r\n\r\nBody line\r\n";
    let mut message = read_message(&input[..]).unwrap();
    let header = &message.header;
    assert_eq!(header.get("subject"), Some("Hi"));
    assert_eq!(header.values("X Weird Key"), ["kept"]);
    assert_eq!(header.len(), 5);
    assert_eq!(
        header.address_list("to").unwrap(),
        [addr("", "a@b"), addr("", "c@d")]
    );
    assert_eq!(header.date().unwrap().unix(), 1136239445);
    assert!(matches!(
        header.address_list("Cc"),
        Err(Error::HeaderNotPresent)
    ));
    let mut body = String::new();
    message.body.read_to_string(&mut body).unwrap();
    assert_eq!(body, "Body line\r\n");

    // Header-only input ending without a blank line is still a message.
    let message = read_message(&b"Subject: x"[..]).unwrap();
    assert_eq!(message.header.get("Subject"), Some("x"));
    assert!(read_message(&b"\n"[..]).unwrap().header.is_empty());
    let message = read_message(&b"Date:\r\n\r\n"[..]).unwrap();
    assert!(matches!(
        message.header.date(),
        Err(Error::HeaderNotPresent)
    ));
}

#[test]
fn rejects_malformed_messages() {
    assert!(matches!(
        read_message(&b""[..]),
        Err(Error::Read(textproto::Error::Eof))
    ));
    assert!(read_message(&b" leading: space\r\n\r\n"[..]).is_err());
    assert!(read_message(&b"A: b\r\nno colon\r\n\r\n"[..]).is_err());
    assert!(matches!(
        read_message(&b"A: caf\xe9\r\n\r\n"[..]),
        Err(Error::Read(textproto::Error::InvalidUtf8))
    ));
    // An empty key is skipped before its bytes are examined, as in Go.
    assert!(read_message(&b": \xff\r\n\r\n"[..]).is_ok());
}

#[test]
fn message_header_budgets() {
    let limits = Limits {
        max_headers: 2,
        ..Limits::default()
    };
    assert!(read_message_with_limits(&b"A: 1\r\nB: 2\r\n\r\n"[..], limits).is_ok());
    assert!(matches!(
        read_message_with_limits(&b"A: 1\r\nB: 2\r\nC: 3\r\n\r\n"[..], limits),
        Err(Error::Read(textproto::Error::MessageTooLarge))
    ));
    let limits = Limits {
        max_header_bytes: 8,
        ..Limits::default()
    };
    assert!(matches!(
        read_message_with_limits(&b"Subject: long value\r\n\r\n"[..], limits),
        Err(Error::Read(textproto::Error::MessageTooLarge))
    ));
    let limits = Limits {
        max_line_bytes: 16,
        ..Limits::default()
    };
    let mut folded = b"Subject: x\r\n".to_vec();
    for _ in 0..10 {
        folded.extend_from_slice(b" more\r\n");
    }
    folded.extend_from_slice(b"\r\n");
    assert!(read_message_with_limits(&folded[..], limits).is_err());
}

#[test]
fn errors_display() {
    assert_eq!(
        Error::HeaderNotPresent.to_string(),
        "mail: header not in message"
    );
    let error = mail::parse_address("").unwrap_err();
    assert!(error.to_string().starts_with("mail: "));
}
