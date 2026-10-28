//! Go `encoding/xml` behaviour: tables ported from Go's xml_test.go,
//! marshal_test.go and read_test.go, plus limit, partial-I/O and hook tests.
//! The typed struct tables live in `tools/derive-check/tests/xml.rs` (they need
//! the derive macros); `tools/xml_check.py` compares everything with Go itself.
use rust_stdlib::encoding::xml::{
    self, Attr, CharData, Comment, Decoder, Directive, Encoder, EndElement, Error, Kind, Name,
    ProcInst, StartElement, TextUnmarshaler, Token, TokenReader, Unmarshal, Unmarshaler,
};
use std::io::{self, Read, Write};

fn name(space: &str, local: &str) -> Name {
    Name::new(space, local)
}

fn start(space: &str, local: &str, attrs: &[(&str, &str, &str)]) -> Token {
    Token::StartElement(StartElement {
        name: name(space, local),
        attr: attrs
            .iter()
            .map(|(s, l, v)| Attr {
                name: name(s, l),
                value: (*v).to_string(),
            })
            .collect(),
    })
}

fn end(space: &str, local: &str) -> Token {
    Token::EndElement(EndElement {
        name: name(space, local),
    })
}

fn chars(s: &str) -> Token {
    Token::CharData(CharData(s.as_bytes().to_vec()))
}

fn comment(s: &str) -> Token {
    Token::Comment(Comment(s.as_bytes().to_vec()))
}

fn directive(s: &str) -> Token {
    Token::Directive(Directive(s.as_bytes().to_vec()))
}

fn pi(target: &str, inst: &str) -> Token {
    Token::ProcInst(ProcInst {
        target: target.into(),
        inst: inst.as_bytes().to_vec(),
    })
}

const TEST_INPUT: &str = "\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\"\n  \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n<body xmlns:foo=\"ns1\" xmlns=\"ns2\" xmlns:tag=\"ns3\" \r\n\t  >\n  <hello lang=\"en\">World &lt;&gt;&apos;&quot; &#x767d;&#40300;翔</hello>\n  <query>&何; &is-it;</query>\n  <goodbye />\n  <outer foo:attr=\"value\" xmlns:tag=\"ns4\">\n    <inner/>\n  </outer>\n  <tag:name>\n    <![CDATA[Some text here.]]>\n  </tag:name>\n</body><!-- missing final newline -->";

fn test_entity() -> std::collections::HashMap<String, String> {
    [("何", "What"), ("is-it", "is it?")]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn raw_tokens() -> Vec<Token> {
    vec![
        chars("\n"),
        pi("xml", "version=\"1.0\" encoding=\"UTF-8\""),
        chars("\n"),
        directive("DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\"\n  \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\""),
        chars("\n"),
        start("", "body", &[("xmlns", "foo", "ns1"), ("", "xmlns", "ns2"), ("xmlns", "tag", "ns3")]),
        chars("\n  "),
        start("", "hello", &[("", "lang", "en")]),
        chars("World <>'\" 白鵬翔"),
        end("", "hello"),
        chars("\n  "),
        start("", "query", &[]),
        chars("What is it?"),
        end("", "query"),
        chars("\n  "),
        start("", "goodbye", &[]),
        end("", "goodbye"),
        chars("\n  "),
        start("", "outer", &[("foo", "attr", "value"), ("xmlns", "tag", "ns4")]),
        chars("\n    "),
        start("", "inner", &[]),
        end("", "inner"),
        chars("\n  "),
        end("", "outer"),
        chars("\n  "),
        start("tag", "name", &[]),
        chars("\n    "),
        chars("Some text here."),
        chars("\n  "),
        end("tag", "name"),
        chars("\n"),
        end("", "body"),
        comment(" missing final newline "),
    ]
}

fn cooked_tokens() -> Vec<Token> {
    vec![
        chars("\n"),
        pi("xml", "version=\"1.0\" encoding=\"UTF-8\""),
        chars("\n"),
        directive("DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\"\n  \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\""),
        chars("\n"),
        start("ns2", "body", &[("xmlns", "foo", "ns1"), ("", "xmlns", "ns2"), ("xmlns", "tag", "ns3")]),
        chars("\n  "),
        start("ns2", "hello", &[("", "lang", "en")]),
        chars("World <>'\" 白鵬翔"),
        end("ns2", "hello"),
        chars("\n  "),
        start("ns2", "query", &[]),
        chars("What is it?"),
        end("ns2", "query"),
        chars("\n  "),
        start("ns2", "goodbye", &[]),
        end("ns2", "goodbye"),
        chars("\n  "),
        start("ns2", "outer", &[("ns1", "attr", "value"), ("xmlns", "tag", "ns4")]),
        chars("\n    "),
        start("ns2", "inner", &[]),
        end("ns2", "inner"),
        chars("\n  "),
        end("ns2", "outer"),
        chars("\n  "),
        start("ns3", "name", &[]),
        chars("\n    "),
        chars("Some text here."),
        chars("\n  "),
        end("ns3", "name"),
        chars("\n"),
        end("ns2", "body"),
        comment(" missing final newline "),
    ]
}

fn token_kind(t: &Token) -> &'static str {
    match t {
        Token::StartElement(_) => "StartElement",
        Token::EndElement(_) => "EndElement",
        Token::CharData(_) => "CharData",
        Token::Comment(_) => "Comment",
        Token::ProcInst(_) => "ProcInst",
        Token::Directive(_) => "Directive",
    }
}

/// Go's `testRawToken`: tokens equal, and `input_offset` brackets the raw text.
fn check_raw(d: &mut Decoder, raw: &str, want: &[Token]) {
    let mut last_end = 0i64;
    for (i, want) in want.iter().enumerate() {
        let start = d.input_offset();
        let have = d.raw_token().unwrap_or_else(|e| panic!("token {i}: {e}"));
        let end = d.input_offset();
        assert_eq!(&have, want, "token {i}");
        assert!(start >= last_end, "token {i}: before previous token");
        if start >= end {
            // EndElement can be synthesized.
            assert!(
                start == end && end == last_end,
                "token {i}: position [{start},{end}) for {} is empty",
                token_kind(&have)
            );
        } else {
            assert!(end as usize <= raw.len(), "token {i}: beyond input");
            let text = &raw.as_bytes()[start as usize..end as usize];
            let text = String::from_utf8_lossy(text);
            if text.contains(['<', '>']) {
                assert!(
                    text.starts_with('<') && text.ends_with('>'),
                    "token {i}: misaligned raw token {text:?}"
                );
            }
        }
        last_end = end;
    }
}

#[test]
fn raw_token_table() {
    let mut d = Decoder::new(TEST_INPUT.as_bytes());
    d.entity = test_entity();
    check_raw(&mut d, TEST_INPUT, &raw_tokens());
}

#[test]
fn cooked_token_table() {
    let mut d = Decoder::new(TEST_INPUT.as_bytes());
    d.entity = test_entity();
    for (i, want) in cooked_tokens().iter().enumerate() {
        assert_eq!(&d.token().unwrap(), want, "token {i}");
    }
}

#[test]
fn non_strict_raw_tokens() {
    const INPUT: &str = "\n<tag>non&entity</tag>\n<tag>&unknown;entity</tag>\n<tag>&#123</tag>\n<tag>&#zzz;</tag>\n<tag>&なまえ3;</tag>\n<tag>&lt-gt;</tag>\n<tag>&;</tag>\n<tag>&0a;</tag>\n";
    let texts = [
        "non&entity",
        "&unknown;entity",
        "&#123",
        "&#zzz;",
        "&なまえ3;",
        "&lt-gt;",
        "&;",
        "&0a;",
    ];
    let mut want = vec![chars("\n")];
    for t in texts {
        want.push(start("", "tag", &[]));
        want.push(chars(t));
        want.push(end("", "tag"));
        want.push(chars("\n"));
    }
    let mut d = Decoder::new(INPUT.as_bytes());
    d.strict = false;
    check_raw(&mut d, INPUT, &want);
}

/// Go's downCaser: a converter that lower-cases every byte it reads.
struct DownCaser<R>(R);

impl<R: Read> Read for DownCaser<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.0.read(buf)?;
        buf[..n].make_ascii_lowercase();
        Ok(n)
    }
}

#[test]
fn raw_token_alt_encoding() {
    const INPUT: &str =
        "\n<?xml version=\"1.0\" encoding=\"x-testing-uppercase\"?>\n<TAG>VALUE</TAG>";
    let mut d = Decoder::new(INPUT.as_bytes());
    d.charset_reader = Some(Box::new(|charset, input| {
        assert_eq!(charset, "x-testing-uppercase");
        Ok(Box::new(DownCaser(input)))
    }));
    let want = vec![
        chars("\n"),
        pi("xml", "version=\"1.0\" encoding=\"x-testing-uppercase\""),
        chars("\n"),
        start("", "tag", &[]),
        chars("value"),
        end("", "tag"),
    ];
    check_raw(&mut d, INPUT, &want);
}

#[test]
fn raw_token_alt_encoding_without_converter() {
    let mut d =
        Decoder::new(&b"\n<?xml version=\"1.0\" encoding=\"x-testing-uppercase\"?><a/>"[..]);
    assert!(d.raw_token().is_ok());
    let err = d.raw_token().unwrap_err();
    assert_eq!(
        err.to_string(),
        "xml: encoding \"x-testing-uppercase\" declared but Decoder.CharsetReader is nil"
    );
    // The failure is sticky: a second call reports the same error.
    assert_eq!(d.raw_token().unwrap_err().to_string(), err.to_string());
}

#[test]
fn charset_reader_error_is_wrapped_and_sticky() {
    let mut d = Decoder::new(&b"<?xml version=\"1.0\" encoding=\"fail\"?><a/>"[..]);
    d.charset_reader = Some(Box::new(|_, _| Err("boom".into())));
    let err = d.token().unwrap_err();
    assert_eq!(err.to_string(), "xml: opening charset \"fail\": boom");
    assert_eq!(d.token().unwrap_err().to_string(), err.to_string());
    assert_eq!(d.token().unwrap_err().to_string(), err.to_string());
}

#[test]
fn nested_directives() {
    let input = "\n<!DOCTYPE [<!ENTITY rdf \"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">]>\n<!DOCTYPE [<!ENTITY xlt \">\">]>\n<!DOCTYPE [<!ENTITY xlt \"<\">]>\n<!DOCTYPE [<!ENTITY xlt '>'>]>\n<!DOCTYPE [<!ENTITY xlt '<'>]>\n<!DOCTYPE [<!ENTITY xlt '\">'>]>\n<!DOCTYPE [<!ENTITY xlt \"'<\">]>\n";
    let want = [
        "DOCTYPE [<!ENTITY rdf \"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">]",
        "DOCTYPE [<!ENTITY xlt \">\">]",
        "DOCTYPE [<!ENTITY xlt \"<\">]",
        "DOCTYPE [<!ENTITY xlt '>'>]",
        "DOCTYPE [<!ENTITY xlt '<'>]",
        "DOCTYPE [<!ENTITY xlt '\">'>]",
        "DOCTYPE [<!ENTITY xlt \"'<\">]",
    ];
    let mut d = Decoder::new(input.as_bytes());
    for w in want {
        assert_eq!(d.token().unwrap(), chars("\n"));
        assert_eq!(d.token().unwrap(), directive(w));
    }
    assert_eq!(d.token().unwrap(), chars("\n"));
}

#[test]
fn directives_with_comments() {
    let input = "\n<!DOCTYPE [<!-- a comment --><!ENTITY rdf \"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">]>\n<!DOCTYPE [<!ENTITY go \"Golang\"><!-- a comment-->]>\n<!DOCTYPE <!-> <!> <!----> <!-->--> <!--->--> [<!ENTITY go \"Golang\"><!-- a comment-->]>\n";
    let want = [
        "DOCTYPE [ <!ENTITY rdf \"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">]",
        "DOCTYPE [<!ENTITY go \"Golang\"> ]",
        "DOCTYPE <!-> <!>       [<!ENTITY go \"Golang\"> ]",
    ];
    let mut d = Decoder::new(input.as_bytes());
    for w in want {
        assert_eq!(d.token().unwrap(), chars("\n"));
        assert_eq!(d.token().unwrap(), directive(w));
    }
    assert_eq!(d.token().unwrap(), chars("\n"));
}

fn drain(d: &mut Decoder) -> Error {
    loop {
        if let Err(e) = d.token() {
            return e;
        }
    }
}

#[test]
fn syntax_errors_for_malformed_input() {
    let inputs = [
        // unexpected EOF cases
        "<",
        "<t",
        "<t ",
        "<t/",
        "<!",
        "<!-",
        "<!--",
        "<!--c-",
        "<!--c--",
        "<!d",
        "<t></",
        "<t></t",
        "<?",
        "<?p",
        "<t a",
        "<t a=",
        "<t a='",
        "<t a=''",
        "<t/><![",
        "<t/><![C",
        "<t/><![CDATA[d",
        "<t/><![CDATA[d]",
        "<t/><![CDATA[d]]",
        // other Syntax errors
        "<>",
        "<t/a",
        "<0 />",
        "<?0 >",
        "</0>",
        "<t 0=''>",
        "<t a='&'>",
        "<t a='<'>",
        "<t>&nbspc;</t>",
        "<t a>",
        "<t a=>",
        "<t a=v>",
        "<t></e>",
        "<t></>",
        "<t></t!",
        "<t>cdata]]></t>",
    ];
    for input in inputs {
        let mut d = Decoder::new(input.as_bytes());
        let err = drain(&mut d);
        assert!(matches!(err, Error::Syntax(_)), "{input:?}: {err:?}");
    }
}

#[test]
fn input_line_and_column() {
    let input =
        "<root>\n<?pi\n ?>  <elt\natt\n=\n\"val\">\n<![CDATA[\n]]><!--\n\n--></elt>\n</root>";
    let want = [
        (1, 7),
        (2, 1),
        (3, 4),
        (3, 6),
        (6, 7),
        (7, 1),
        (8, 4),
        (10, 4),
        (10, 10),
        (11, 1),
        (11, 8),
    ];
    let mut d = Decoder::new(input.as_bytes());
    for w in want {
        d.token().unwrap();
        assert_eq!(d.input_pos(), w);
    }
}

#[test]
fn syntax_error_line_number() {
    let mut d = Decoder::new(&b"<P>Foo<P>\n\n<P>Bar</>\n"[..]);
    match drain(&mut d) {
        Error::Syntax(e) => assert_eq!(e.line, 3),
        other => panic!("expected SyntaxError, got {other:?}"),
    }
}

#[test]
fn unquoted_and_valueless_attributes() {
    let mut d = Decoder::new(&b"<tag attr=azAZ09:-_\t>"[..]);
    d.strict = false;
    let Token::StartElement(t) = d.token().unwrap() else {
        panic!("not a start element");
    };
    assert_eq!(t.name.local, "tag");
    assert_eq!(t.attr[0].name.local, "attr");
    assert_eq!(t.attr[0].value, "azAZ09:-_");

    for (input, tag, attr) in [
        ("<p nowrap>", "p", "nowrap"),
        ("<p nowrap >", "p", "nowrap"),
        ("<input checked/>", "input", "checked"),
        ("<input checked />", "input", "checked"),
    ] {
        let mut d = Decoder::new(input.as_bytes());
        d.strict = false;
        let Token::StartElement(t) = d.token().unwrap() else {
            panic!("not a start element");
        };
        assert_eq!(t.name.local, tag);
        assert_eq!(
            (&t.attr[0].name.local, &t.attr[0].value),
            (&attr.to_string(), &attr.to_string())
        );
    }
}

#[test]
fn trailing_tokens_end_with_eof() {
    for raw in [true, false] {
        let mut d = Decoder::new(&b"<FOO></FOO>  "[..]);
        let err = loop {
            let r = if raw { d.raw_token() } else { d.token() };
            if let Err(e) = r {
                break e;
            }
        };
        assert!(err.is_eof(), "{err:?}");
    }
    let mut d = Decoder::new(&b"<test><![CDATA[ &val=foo ]]></test>"[..]);
    assert!(drain(&mut d).is_eof());
}

#[test]
fn disallowed_characters() {
    let cases: [(&[u8], &str); 9] = [
        (b"\x12<doc/>", "illegal character code U+0012"),
        (
            b"<?xml version=\"1.0\"?>\x0b<doc/>",
            "illegal character code U+000B",
        ),
        (b"\xef\xbf\xbe<doc/>", "illegal character code U+FFFE"),
        (
            b"<?xml version=\"1.0\"?><doc>\r\n<hiya/>\x07<toots/></doc>",
            "illegal character code U+0007",
        ),
        (
            b"<?xml version=\"1.0\"?><doc \x12='value'>what's up</doc>",
            "expected attribute name in element",
        ),
        (
            b"<doc>&abc\x01;</doc>",
            "invalid character entity &abc (no semicolon)",
        ),
        (
            b"<doc>&\x01;</doc>",
            "invalid character entity & (no semicolon)",
        ),
        (
            b"<doc>&\xef\xbf\xbe;</doc>",
            "invalid character entity &\u{fffe};",
        ),
        (b"<doc>&hello;</doc>", "invalid character entity &hello;"),
    ];
    for (input, msg) in cases {
        let mut d = Decoder::new(input);
        match drain(&mut d) {
            Error::Syntax(e) => assert_eq!(e.msg, msg, "{input:?}"),
            other => panic!("{input:?}: {other:?}"),
        }
    }
}

#[test]
fn xml_declaration_encoding_and_version() {
    for (input, ok) in [
        (r#"<?xml encoding="UtF-8" version="1.0"?><root/>"#, true),
        (r#"<?xml encoding="UTF-8" version="1.0"?><root/>"#, true),
        (r#"<?xml encoding="utf-8" version="1.0"?><root/>"#, true),
        (r#"<?xml encoding="uuu-9" version="1.0"?><root/>"#, false),
        (r#"<?xml version="1.1"?><root/>"#, false),
        (r#"<?xml version='1.0' encoding=utf-8?><root/>"#, true),
    ] {
        let mut d = Decoder::new(input.as_bytes());
        let err = drain(&mut d);
        assert_eq!(err.is_eof(), ok, "{input}: {err}");
    }
    let mut d = Decoder::new(&b"<?xml version=\"2.0\"?><root/>"[..]);
    assert_eq!(
        d.token().unwrap_err().to_string(),
        "xml: unsupported version \"2.0\"; only version 1.0 is supported"
    );
}

#[test]
fn unclosed_elements_are_syntax_errors() {
    for input in ["<root>", "<root><foo>", "<root><foo></foo>"] {
        let mut d = Decoder::new(input.as_bytes());
        match drain(&mut d) {
            Error::Syntax(e) => assert_eq!(e.msg, "unexpected EOF"),
            other => panic!("{input}: {other:?}"),
        }
    }
}

#[test]
fn bracket_sequence_in_quoted_attribute_is_text() {
    let mut d = Decoder::new(&b"<item b=']]>'/>"[..]);
    assert_eq!(
        d.raw_token().unwrap(),
        start("", "item", &[("", "b", "]]>")])
    );
    assert_eq!(d.raw_token().unwrap(), end("", "item"));
    assert!(d.raw_token().unwrap_err().is_eof());
}

#[test]
fn xml_name_space_prefixes_and_default_space() {
    let mut d = Decoder::new(
        &b"<a xmlns='urn:d' xmlns:p='urn:p' p:x='1' x='2'><p:b/><c xmlns=''/></a>"[..],
    );
    d.default_space = "urn:fallback".into();
    let Token::StartElement(a) = d.token().unwrap() else {
        panic!()
    };
    assert_eq!(a.name, name("urn:d", "a"));
    assert_eq!(a.attr[2].name, name("urn:p", "x"));
    assert_eq!(a.attr[3].name, name("", "x"));
    let Token::StartElement(b) = d.token().unwrap() else {
        panic!()
    };
    assert_eq!(b.name, name("urn:p", "b"));
    d.token().unwrap();
    let Token::StartElement(c) = d.token().unwrap() else {
        panic!()
    };
    // xmlns='' rebinds the default space to empty, which is not the fallback.
    assert_eq!(c.name, name("", "c"));

    let mut d = Decoder::new(&b"<a/>"[..]);
    d.default_space = "urn:fallback".into();
    let Token::StartElement(a) = d.token().unwrap() else {
        panic!()
    };
    assert_eq!(a.name, name("urn:fallback", "a"));
}

#[test]
fn non_strict_mode_invents_end_tags_and_auto_closes() {
    let mut d = Decoder::new(&b"<p>one<br>two</p>"[..]);
    d.strict = false;
    d.auto_close = xml::html_auto_close();
    d.entity = xml::html_entity();
    let mut seen = Vec::new();
    loop {
        match d.token() {
            Ok(t) => seen.push(t),
            Err(e) => {
                assert!(e.is_eof(), "{e}");
                break;
            }
        }
    }
    assert_eq!(
        seen,
        vec![
            start("", "p", &[]),
            chars("one"),
            start("", "br", &[]),
            end("", "br"),
            chars("two"),
            end("", "p"),
        ]
    );
    let mut d = Decoder::new(&b"<a><b>x&nbsp;y</a>"[..]);
    d.strict = false;
    d.entity = xml::html_entity();
    let mut text = String::new();
    while let Ok(t) = d.token() {
        if let Token::CharData(c) = t {
            text.push_str(&String::from_utf8_lossy(&c.0));
        }
    }
    assert_eq!(text, "x\u{a0}y");
}

#[test]
fn html_tables_match_go() {
    assert_eq!(xml::HTML_ENTITY.len(), 252);
    assert_eq!(xml::html_entity()["eacute"], "\u{e9}");
    assert_eq!(xml::html_entity()["euro"], "\u{20ac}");
    assert_eq!(
        xml::HTML_AUTO_CLOSE,
        [
            "basefont", "br", "area", "link", "img", "param", "hr", "input", "col", "frame",
            "isindex", "base", "meta"
        ]
    );
    assert_eq!(xml::HEADER, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
}

#[test]
fn copy_token_is_independent() {
    let data = CharData(b"same data".to_vec());
    let mut tok = Token::CharData(data.clone());
    let copy = xml::copy_token(&tok);
    assert_eq!(tok, copy);
    if let Token::CharData(c) = &mut tok {
        c.0[1] = b'o';
    }
    assert_ne!(tok, copy);

    let elt = StartElement {
        name: name("", "hello"),
        attr: vec![Attr {
            name: name("", "lang"),
            value: "en".into(),
        }],
    };
    let mut copy = elt.copy();
    assert_eq!(copy, elt);
    copy.attr[0].value = "de".into();
    assert_eq!(elt.attr[0].value, "en");
    assert_eq!(
        elt.end(),
        EndElement {
            name: elt.name.clone()
        }
    );
    assert_eq!(Comment(b"c".to_vec()).copy(), Comment(b"c".to_vec()));
    assert_eq!(Directive(b"d".to_vec()).copy(), Directive(b"d".to_vec()));
    let p = ProcInst {
        target: "t".into(),
        inst: b"i".to_vec(),
    };
    assert_eq!(p.copy(), p);
}

/// A reader that hands out one byte per call and then fails (or ends).
struct Drip<'a>(&'a [u8], Option<io::ErrorKind>);

impl Read for Drip<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.0.split_first() {
            Some((b, rest)) => {
                buf[0] = *b;
                self.0 = rest;
                Ok(1)
            }
            None => match self.1 {
                Some(kind) => Err(io::Error::new(kind, "drip failure")),
                None => Ok(0),
            },
        }
    }
}

#[test]
fn partial_reads_do_not_change_tokens_or_positions() {
    let mut whole = Decoder::new(TEST_INPUT.as_bytes());
    let mut drip = Decoder::new(Drip(TEST_INPUT.as_bytes(), None));
    whole.entity = test_entity();
    drip.entity = test_entity();
    loop {
        let (a, b) = (whole.token(), drip.token());
        assert_eq!(whole.input_pos(), drip.input_pos());
        assert_eq!(whole.input_offset(), drip.input_offset());
        match (a, b) {
            (Ok(a), Ok(b)) => assert_eq!(a, b),
            (Err(a), Err(b)) => {
                assert_eq!(a.to_string(), b.to_string());
                break;
            }
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn read_failures_are_reported_and_sticky() {
    let mut d = Decoder::new(Drip(b"<a>text", Some(io::ErrorKind::BrokenPipe)));
    assert_eq!(d.token().unwrap(), start("", "a", &[]));
    // The text token is delivered even though the read after it fails ...
    assert_eq!(d.token().unwrap(), chars("text"));
    // ... and then the I/O error, not a syntax error, is what comes back.
    let err = d.token().unwrap_err();
    assert!(matches!(err, Error::Io(_)), "{err:?}");
    assert!(matches!(d.token().unwrap_err(), Error::Io(_)));
}

#[test]
fn token_size_budget() {
    let mut d = Decoder::new(&b"<a>0123456789</a>"[..]);
    d.max_token_bytes = 4;
    assert!(d.token().is_ok());
    assert_eq!(
        d.token().unwrap_err().to_string(),
        "xml: token exceeds Decoder.max_token_bytes"
    );
    let mut d = Decoder::new(&b"<a>0123456789</a>"[..]);
    assert!(drain(&mut d).is_eof());
}

#[test]
fn element_depth_budget() {
    let doc = "<a>".repeat(10);
    let mut d = Decoder::new(doc.as_bytes());
    d.max_depth = 5;
    let err = drain(&mut d);
    assert!(
        err.to_string().contains("exceeded maximum element depth"),
        "{err}"
    );
}

struct Wrap<'a>(Decoder<'a>);

impl TokenReader for Wrap<'_> {
    fn token(&mut self) -> Result<Token, Error> {
        self.0.token()
    }
}

#[test]
fn token_decoder_wraps_any_token_reader() {
    let mut d = Decoder::from_token_reader(Wrap(Decoder::new(TEST_INPUT.as_bytes())));
    // The wrapped decoder already translated name spaces; the outer one passes
    // tokens through (Go: TestNewTokenDecoderIdempotent / TestWrapDecoder).
    let first = d.token().unwrap();
    assert_eq!(first, chars("\n"));
}

struct Scripted {
    tokens: Vec<Token>,
    early_eof: bool,
}

impl TokenReader for Scripted {
    fn token(&mut self) -> Result<Token, Error> {
        if self.tokens.is_empty() {
            return Err(Error::Eof);
        }
        let t = self.tokens.remove(0);
        let _ = self.early_eof;
        Ok(t)
    }
}

#[derive(Default)]
struct Named(Name);

impl Unmarshal for Named {
    fn xml_kind(&self) -> Kind {
        Kind::Name
    }
    fn xml_set_name(&mut self, n: &Name) -> bool {
        self.0 = n.clone();
        true
    }
}

#[test]
fn decode_from_a_token_stream_checks_nesting() {
    let test = StartElement {
        name: name("", "test"),
        attr: Vec::new(),
    };
    for early_eof in [false, true] {
        let ok = vec![
            Token::StartElement(test.clone()),
            Token::EndElement(test.end()),
        ];
        let mut d = Decoder::from_token_reader(Scripted {
            tokens: ok,
            early_eof,
        });
        let v: Named = d.decode().unwrap();
        assert_eq!(v.0, name("", "test"));

        let bad = vec![
            Token::StartElement(test.clone()),
            start("", "bad", &[]),
            Token::EndElement(test.end()),
        ];
        let mut d = Decoder::from_token_reader(Scripted {
            tokens: bad,
            early_eof,
        });
        let err = d.decode_into(&mut Named::default()).unwrap_err();
        assert!(matches!(err, Error::Syntax(_)), "{err:?}");
    }
}

// ---- EscapeText / Escape ---------------------------------------------------------

#[test]
fn escape_text_matches_go() {
    let mut out = Vec::new();
    xml::escape_text(&mut out, b"A \x00 terminated string.").unwrap();
    assert_eq!(out, "A \u{fffd} terminated string.".as_bytes());

    let mut out = Vec::new();
    xml::escape_text(&mut out, b"\"'&<>\t\n\r \xff\xc3").unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "&#34;&#39;&amp;&lt;&gt;&#x9;&#xA;&#xD; \u{fffd}\u{fffd}"
    );

    struct Unwritable;
    impl Write for Unwritable {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("unwritable"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let err = xml::escape_text(Unwritable, b"A").unwrap_err();
    assert_eq!(err.to_string(), "unwritable");
    xml::escape(Unwritable, b"A");
}

// ---- Encoder ----------------------------------------------------------------------

fn encode_all(tokens: &[Token]) -> (String, Option<String>) {
    let mut buf = Vec::new();
    let mut err = None;
    {
        let mut enc = Encoder::new(&mut buf);
        for t in tokens {
            if let Err(e) = enc.encode_token(t.clone()) {
                err = Some(e.to_string());
                break;
            }
        }
        enc.flush().unwrap();
    }
    (String::from_utf8(buf).unwrap(), err)
}

#[test]
fn encode_token_table() {
    let xml_url = "http://www.w3.org/XML/1998/namespace";
    type Case = (&'static str, Vec<Token>, &'static str, &'static str);
    let cases: Vec<Case> = vec![
        ("start element with name space", vec![start("space", "local", &[])], "<local xmlns=\"space\">", ""),
        ("start element with no name", vec![start("space", "", &[])], "", "xml: start tag with no name"),
        ("end element with no name", vec![end("space", "")], "", "xml: end tag with no name"),
        ("char data", vec![chars("foo")], "foo", ""),
        ("char data with escaped chars", vec![chars(" \t\n")], " &#x9;\n", ""),
        ("comment", vec![comment("foo")], "<!--foo-->", ""),
        ("comment with invalid content", vec![comment("foo-->")], "", "xml: EncodeToken of Comment containing --> marker"),
        ("proc instruction", vec![pi("Target", "Instruction")], "<?Target Instruction?>", ""),
        ("proc instruction with empty target", vec![pi("", "Instruction")], "", "xml: EncodeToken of ProcInst with invalid Target"),
        ("proc instruction with bad content", vec![pi("", "Instruction?>")], "", "xml: EncodeToken of ProcInst with invalid Target"),
        ("directive", vec![directive("foo")], "<!foo>", ""),
        ("more complex directive", vec![directive("DOCTYPE doc [ <!ELEMENT doc '>'> <!-- com>ment --> ]")], "<!DOCTYPE doc [ <!ELEMENT doc '>'> <!-- com>ment --> ]>", ""),
        ("directive instruction with bad name", vec![directive("foo>")], "", "xml: EncodeToken of Directive containing wrong < or > markers"),
        ("end tag without start tag", vec![end("foo", "bar")], "", "xml: end tag </bar> without start tag"),
        ("mismatching end tag local name", vec![start("", "foo", &[]), end("", "bar")], "<foo>", "xml: end tag </bar> does not match start tag <foo>"),
        ("mismatching end tag namespace", vec![start("space", "foo", &[]), end("another", "foo")], "<foo xmlns=\"space\">", "xml: end tag </foo> in namespace another does not match start tag <foo> in namespace space"),
        ("start element with explicit namespace", vec![start("space", "local", &[("xmlns", "x", "space"), ("space", "foo", "value")])], "<local xmlns=\"space\" xmlns:_xmlns=\"xmlns\" _xmlns:x=\"space\" xmlns:space=\"space\" space:foo=\"value\">", ""),
        ("colliding prefix", vec![start("space", "local", &[("xmlns", "x", "space"), ("space", "foo", "value"), ("x", "bar", "other")])], "<local xmlns=\"space\" xmlns:_xmlns=\"xmlns\" _xmlns:x=\"space\" xmlns:space=\"space\" space:foo=\"value\" xmlns:x=\"x\" x:bar=\"other\">", ""),
        ("previously defined namespace", vec![start("", "local", &[("xmlns", "x", "space")]), start("space", "foo", &[("space", "x", "y")])], "<local xmlns:_xmlns=\"xmlns\" _xmlns:x=\"space\"><foo xmlns=\"space\" xmlns:space=\"space\" space:x=\"y\">", ""),
        ("several prefixes for one space", vec![start("space", "foo", &[("xmlns", "a", "space"), ("xmlns", "b", "space"), ("space", "x", "value")])], "<foo xmlns=\"space\" xmlns:_xmlns=\"xmlns\" _xmlns:a=\"space\" _xmlns:b=\"space\" xmlns:space=\"space\" space:x=\"value\">", ""),
        ("redefine xmlns", vec![start("", "foo", &[("foo", "xmlns", "space")])], "<foo xmlns:foo=\"foo\" foo:xmlns=\"space\">", ""),
        ("xmlns with explicit name space #1", vec![start("space", "foo", &[("xml", "xmlns", "space")])], "<foo xmlns=\"space\" xmlns:_xml=\"xml\" _xml:xmlns=\"space\">", ""),
        ("xmlns with explicit name space #2", vec![start("space", "foo", &[(xml_url, "xmlns", "space")])], "<foo xmlns=\"space\" xml:xmlns=\"space\">", ""),
        ("empty name space declaration is ignored", vec![start("", "foo", &[("xmlns", "foo", "")])], "<foo xmlns:_xmlns=\"xmlns\" _xmlns:foo=\"\">", ""),
        ("attribute with no name is ignored", vec![start("", "foo", &[("", "", "value")])], "<foo>", ""),
        ("namespace URL with non-valid name", vec![start("/34", "foo", &[("/34", "x", "value")])], "<foo xmlns=\"/34\" xmlns:_=\"/34\" _:x=\"value\">", ""),
        ("nested element resets default namespace", vec![start("space", "foo", &[("", "xmlns", "space")]), start("", "foo", &[("", "xmlns", ""), ("", "x", "value"), ("space", "x", "value")])], "<foo xmlns=\"space\" xmlns=\"space\"><foo xmlns=\"\" x=\"value\" xmlns:space=\"space\" space:x=\"value\">", ""),
        ("reserved prefix -- lower case", vec![start("", "foo", &[("http://www.w3.org/2001/xmlSchema-instance", "nil", "true")])], "<foo xmlns:_xmlSchema-instance=\"http://www.w3.org/2001/xmlSchema-instance\" _xmlSchema-instance:nil=\"true\">", ""),
        ("reserved prefix -- mixed case", vec![start("", "foo", &[("http://www.w3.org/2001/XmLSchema-instance", "nil", "true")])], "<foo xmlns:_XmLSchema-instance=\"http://www.w3.org/2001/XmLSchema-instance\" _XmLSchema-instance:nil=\"true\">", ""),
    ];
    for (desc, tokens, want, err) in cases {
        let (got, got_err) = encode_all(&tokens);
        assert_eq!(got_err.as_deref().unwrap_or(""), err, "{desc}");
        assert_eq!(got, want, "{desc}");
    }
}

#[test]
fn nested_prefixes_are_reused_and_scoped() {
    let toks = vec![
        start("", "foo", &[("xmlns", "x", "space1")]),
        start("", "foo", &[("xmlns", "x", "space2")]),
        start(
            "",
            "foo",
            &[
                ("space1", "a", "space1 value"),
                ("space2", "b", "space2 value"),
            ],
        ),
        end("", "foo"),
        end("", "foo"),
        start(
            "",
            "foo",
            &[
                ("space1", "a", "space1 value"),
                ("space2", "b", "space2 value"),
            ],
        ),
    ];
    let (got, err) = encode_all(&toks);
    assert_eq!(err, None);
    assert_eq!(got, "<foo xmlns:_xmlns=\"xmlns\" _xmlns:x=\"space1\"><foo _xmlns:x=\"space2\"><foo xmlns:space1=\"space1\" space1:a=\"space1 value\" xmlns:space2=\"space2\" space2:b=\"space2 value\"></foo></foo><foo xmlns:space1=\"space1\" space1:a=\"space1 value\" xmlns:space2=\"space2\" space2:b=\"space2 value\">");
}

#[test]
fn xml_declaration_only_as_first_token() {
    let mut buf = Vec::new();
    let mut enc = Encoder::new(&mut buf);
    enc.encode_token(pi("xml", "Instruction")).unwrap();
    enc.encode_token(pi("Target", "Instruction")).unwrap();
    assert!(enc.encode_token(pi("xml", "Instruction")).is_err());
    // After a flush the buffer is empty again, as in Go.
    enc.flush().unwrap();
    assert!(enc.encode_token(pi("xml", "Instruction")).is_ok());
}

#[test]
fn close_reports_unclosed_tags_and_rejects_more_writes() {
    let mut buf = Vec::new();
    let mut enc = Encoder::new(&mut buf);
    enc.encode_token(start("", "foo", &[])).unwrap();
    assert_eq!(enc.close().unwrap_err().to_string(), "unclosed tag <foo>");
    assert!(enc.close().is_ok());
    assert_eq!(
        enc.encode_token(directive("foo")).unwrap_err().to_string(),
        "use of closed Encoder"
    );
    drop(enc);
    assert_eq!(buf, b"<foo>");
}

#[test]
fn decode_then_encode_round_trips_tokens() {
    let input =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<?Target Instruction?>\n<root>\n</root>\n";
    let mut d = Decoder::new(input.as_bytes());
    let mut out = Vec::new();
    {
        let mut e = Encoder::new(&mut out);
        while let Ok(t) = d.token() {
            e.encode_token(t).unwrap();
        }
        e.close().unwrap();
    }
    assert_eq!(String::from_utf8(out).unwrap(), input);
}

#[test]
fn encoder_indents_tokens_from_marshal_values() {
    let mut buf = Vec::new();
    {
        let mut enc = Encoder::new(&mut buf);
        enc.indent("> ", "  ");
        enc.encode(&vec![1i32, 2]).unwrap();
        enc.close().unwrap();
    }
    assert_eq!(
        String::from_utf8(buf).unwrap(),
        "> <int32>1</int32>\n> <int32>2</int32>"
    );
}

#[test]
fn write_errors_are_latched_and_reported() {
    struct Fails(usize);
    impl Write for Fails {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            if self.0 < b.len() {
                return Err(io::Error::other("sink failed"));
            }
            self.0 -= b.len();
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut enc = Encoder::new(Fails(0));
    enc.encode_token(start("", "a", &[])).unwrap();
    assert_eq!(enc.flush().unwrap_err().to_string(), "sink failed");
    // The error is sticky for every later operation.
    assert_eq!(
        enc.encode_token(end("", "a")).unwrap_err().to_string(),
        "sink failed"
    );
    assert_eq!(enc.close().unwrap_err().to_string(), "sink failed");
}

// ---- Marshal of untyped values ------------------------------------------------------

#[test]
fn marshal_primitives_and_sequences() {
    let m = |v: Result<Vec<u8>, Error>| String::from_utf8(v.unwrap()).unwrap();
    assert_eq!(m(xml::marshal(&5i32)), "<int32>5</int32>");
    assert_eq!(m(xml::marshal(&5isize)), "<int>5</int>");
    assert_eq!(m(xml::marshal(&"a<b")), "<string>a&lt;b</string>");
    assert_eq!(m(xml::marshal(&true)), "<bool>true</bool>");
    assert_eq!(m(xml::marshal(&1e21f64)), "<float64>1e+21</float64>");
    assert_eq!(m(xml::marshal(&0.1f32)), "<float32>0.1</float32>");
    assert_eq!(
        m(xml::marshal(&vec!["a", "b"])),
        "<string>a</string><string>b</string>"
    );
    assert_eq!(m(xml::marshal(&None::<i32>)), "");
    assert_eq!(m(xml::marshal(&Some(7u8))), "<uint8>7</uint8>");
    assert_eq!(m(xml::marshal(&())), "");
    assert_eq!(
        m(xml::marshal_indent(&vec![1u16, 2], "", "  ")),
        "<uint16>1</uint16>\n<uint16>2</uint16>"
    );
    let e = xml::marshal(&vec![1u8, 2]).unwrap_err();
    assert_eq!(e.to_string(), "xml: unsupported type: []uint8");
    let e = xml::marshal(&std::collections::BTreeMap::<String, i64>::new()).unwrap_err();
    assert_eq!(e.to_string(), "xml: unsupported type: map[string]int64");
}

// ---- Unmarshal of untyped values ------------------------------------------------------

fn decode_str<T: Unmarshal + Default>(input: &str) -> Result<T, Error> {
    xml::unmarshal(input.as_bytes())
}

#[test]
fn unmarshal_returns_a_value_and_into_fills_an_existing_one() {
    let value: String = xml::unmarshal(b"<a>hi</a>").unwrap();
    assert_eq!(value, "hi");
    let mut existing = String::from("old");
    xml::unmarshal_into(b"<a>new</a>", &mut existing).unwrap();
    assert_eq!(existing, "new");
}

#[test]
fn unmarshal_scalars() {
    assert_eq!(decode_str::<i32>("<x> -42 </x>").unwrap(), -42);
    assert_eq!(decode_str::<u8>("<x>255</x>").unwrap(), 255);
    assert_eq!(decode_str::<f64>("<x>12.0</x>").unwrap(), 12.0);
    assert_eq!(decode_str::<f32>("<x>0x1p-2</x>").unwrap(), 0.25);
    assert!(decode_str::<bool>("<x>1</x>").unwrap());
    assert!(!decode_str::<bool>("<x></x>").unwrap());
    assert_eq!(
        decode_str::<String>("<x>a&amp;b<y>skipped</y>c</x>").unwrap(),
        "a&bc"
    );
    assert_eq!(decode_str::<Vec<u8>>("<x>raw</x>").unwrap(), b"raw");
    assert_eq!(decode_str::<Option<i64>>("<x>7</x>").unwrap(), Some(7));
    assert_eq!(
        decode_str::<Name>("<a:b xmlns:a='urn:q'/>").unwrap(),
        name("urn:q", "b")
    );
    for (text, want) in [
        (
            "<x>abc</x>",
            "strconv.ParseInt: parsing \"abc\": invalid syntax",
        ),
        ("<x>300</x>", ""),
    ] {
        let r = decode_str::<i8>(text);
        match want {
            "" => assert_eq!(
                r.unwrap_err().to_string(),
                "strconv.ParseInt: parsing \"300\": value out of range"
            ),
            w => assert_eq!(r.unwrap_err().to_string(), w),
        }
    }
    assert_eq!(
        decode_str::<u16>("<x>-1</x>").unwrap_err().to_string(),
        "strconv.ParseUint: parsing \"-1\": invalid syntax"
    );
    assert_eq!(
        decode_str::<f64>("<x>1e999</x>").unwrap_err().to_string(),
        "strconv.ParseFloat: parsing \"1e999\": value out of range"
    );
    assert_eq!(
        decode_str::<bool>("<x>yes</x>").unwrap_err().to_string(),
        "strconv.ParseBool: parsing \"yes\": invalid syntax"
    );
}

#[test]
fn unmarshal_slices_grow_and_shrink_on_failure() {
    let mut v: Vec<i32> = vec![1];
    let err = xml::unmarshal_into(b"<x>bad</x>", &mut v).unwrap_err();
    assert!(err.to_string().contains("ParseInt"));
    assert_eq!(v, vec![1]);
    xml::unmarshal_into(b"<x>2</x>", &mut v).unwrap();
    assert_eq!(v, vec![1, 2]);
}

#[test]
fn unmarshal_into_unsupported_kinds_reports_go_texts() {
    assert_eq!(
        decode_str::<[i32; 2]>("<x/>").unwrap_err().to_string(),
        "unknown type [2]int32"
    );
    assert_eq!(
        decode_str::<std::collections::BTreeMap<String, i32>>("<x/>")
            .unwrap_err()
            .to_string(),
        "unknown type map[string]int32"
    );
}

#[test]
fn decode_reads_to_the_first_start_element_and_skips_the_rest() {
    let mut d = Decoder::new(&b"<!--c--><?pi?>junk<a>1</a><b>2</b>"[..]);
    let mut a = 0i32;
    d.decode_into(&mut a).unwrap();
    assert_eq!(a, 1);
    let mut b = 0i32;
    d.decode_into(&mut b).unwrap();
    assert_eq!(b, 2);
    assert!(d.decode_into(&mut b).unwrap_err().is_eof());
    let mut d = Decoder::new(&b"no elements"[..]);
    assert!(d.decode_into(&mut a).unwrap_err().is_eof());
}

#[test]
fn decode_element_with_raw_start_is_an_error_not_a_panic() {
    // `RawToken` does not push the element on the decoder's stack, so
    // an Unmarshaler cannot be bracketed; Go dereferences nil here.
    #[derive(Default)]
    struct Hook;
    impl Unmarshal for Hook {
        fn xml_kind(&self) -> Kind {
            Kind::Unknown
        }
        fn xml_unmarshaler(&mut self) -> Option<&mut dyn Unmarshaler> {
            Some(self)
        }
    }
    impl Unmarshaler for Hook {
        fn unmarshal_xml(&mut self, _: &mut Decoder<'_>, _: StartElement) -> Result<(), Error> {
            Ok(())
        }
    }
    let mut d = Decoder::new(&b"<a/>"[..]);
    let Token::StartElement(s) = d.raw_token().unwrap() else {
        panic!()
    };
    let err = d.decode_element_into(&mut Hook, Some(&s)).unwrap_err();
    assert!(
        err.to_string().contains("without an open start element"),
        "{err}"
    );
}

// ---- Unmarshaler / TextUnmarshaler hooks ---------------------------------------------

#[derive(Debug, Default)]
struct Greedy(String);

impl Unmarshal for Greedy {
    fn xml_kind(&self) -> Kind {
        Kind::Unknown
    }
    fn xml_type_string(&self) -> String {
        "Greedy".into()
    }
    fn xml_unmarshaler(&mut self) -> Option<&mut dyn Unmarshaler> {
        Some(self)
    }
}

impl Unmarshaler for Greedy {
    fn unmarshal_xml(&mut self, d: &mut Decoder<'_>, start: StartElement) -> Result<(), Error> {
        match start.name.local.as_str() {
            // Consumes the element through DecodeElement, as Go advises.
            "ok" => d.decode_element_into(&mut self.0, Some(&start)),
            // Reads nothing at all.
            "lazy" => Ok(()),
            // Reads tokens by hand.
            "manual" => loop {
                match d.token()? {
                    Token::CharData(c) => self.0.push_str(&String::from_utf8_lossy(&c.0)),
                    Token::StartElement(_) => d.skip()?,
                    Token::EndElement(_) => return Ok(()),
                    _ => {}
                }
            },
            "raw" => d.raw_token().map(|_| ()),
            "overread" => {
                d.skip()?;
                d.token().map(|_| ())
            }
            _ => Err(Error::msg("unexpected element")),
        }
    }
}

#[test]
fn unmarshaler_must_consume_exactly_one_element() {
    assert_eq!(decode_str::<Greedy>("<ok>v</ok>").unwrap().0, "v");
    assert_eq!(
        decode_str::<Greedy>("<manual>a<b/>c</manual>").unwrap().0,
        "ac"
    );
    assert_eq!(
        decode_str::<Greedy>("<lazy><x/></lazy>")
            .unwrap_err()
            .to_string(),
        "xml: (*Greedy).UnmarshalXML did not consume entire <lazy> element"
    );
    assert_eq!(
        decode_str::<Greedy>("<raw/>").unwrap_err().to_string(),
        "xml: cannot use RawToken from UnmarshalXML method"
    );
    assert!(decode_str::<Greedy>("<overread/>").unwrap_err().is_eof());
    assert_eq!(
        decode_str::<Greedy>("<other/>").unwrap_err().to_string(),
        "unexpected element"
    );
}

#[derive(Default)]
struct Shout(String);

impl Unmarshal for Shout {
    fn xml_kind(&self) -> Kind {
        Kind::Scalar
    }
    fn xml_text_unmarshaler(&mut self) -> Option<&mut dyn TextUnmarshaler> {
        Some(self)
    }
}

impl TextUnmarshaler for Shout {
    fn unmarshal_text(&mut self, text: &[u8]) -> Result<(), Error> {
        self.0 = String::from_utf8_lossy(text).to_uppercase();
        Ok(())
    }
}

#[test]
fn text_unmarshaler_gets_only_the_elements_own_character_data() {
    assert_eq!(
        decode_str::<Shout>("<x>ab<c>skip</c>d</x>").unwrap().0,
        "ABD"
    );
}

// ---- Resource limits ---------------------------------------------------------------------

#[derive(Default)]
struct Nested(Vec<Nested>);

impl Unmarshal for Nested {
    fn xml_kind(&self) -> Kind {
        Kind::Unknown
    }
    fn xml_unmarshaler(&mut self) -> Option<&mut dyn Unmarshaler> {
        Some(self)
    }
}

impl Unmarshaler for Nested {
    fn unmarshal_xml(&mut self, d: &mut Decoder<'_>, _: StartElement) -> Result<(), Error> {
        loop {
            match d.token()? {
                Token::StartElement(t) => {
                    let mut child = Nested::default();
                    d.decode_element_into(&mut child, Some(&t))?;
                    self.0.push(child);
                }
                Token::EndElement(_) => return Ok(()),
                _ => {}
            }
        }
    }
}

fn depth_of(n: &Nested) -> usize {
    1 + n.0.iter().map(depth_of).max().unwrap_or(0)
}

#[test]
fn unmarshal_depth_limit_matches_go() {
    // Go's TestDecodeElementRecursion / TestRecursiveUnmarshalInterfaceDepth:
    // 10000 levels decode, 10001 fail with "exceeded max depth". Deep recursion
    // needs a big stack and a matching stack budget.
    let handle = std::thread::Builder::new()
        .stack_size(1 << 30)
        .spawn(|| {
            let run = |depth: usize| {
                let doc = format!("{}{}", "<a>".repeat(depth), "</a>".repeat(depth));
                let mut d = Decoder::new(doc.as_bytes());
                d.max_unmarshal_stack = usize::MAX;
                let mut n = Nested::default();
                let r = d.decode_into(&mut n);
                (r.map_err(|e| e.to_string()), depth_of(&n))
            };
            let (ok, got) = run(10_000);
            assert_eq!(ok, Ok(()));
            assert_eq!(got, 10_000);
            let (err, _) = run(10_001);
            assert_eq!(err, Err("exceeded max depth".to_string()));
        })
        .unwrap();
    handle.join().unwrap();
}

#[test]
fn unmarshal_stack_budget_stops_hostile_nesting_before_the_stack_does() {
    let handle = std::thread::Builder::new()
        .stack_size(2 << 20)
        .spawn(|| {
            let doc = "<a>".repeat(9_000);
            let mut n = Nested::default();
            let err = xml::unmarshal_into(doc.as_bytes(), &mut n).unwrap_err();
            assert_eq!(err.to_string(), "exceeded max depth");
        })
        .unwrap();
    handle.join().unwrap();
}

#[test]
fn unmarshal_into_discarded_input_is_iterative() {
    // Go's TestCVE202230633: a huge run of start tags into a type that discards
    // children must not recurse.
    let doc = "<a>".repeat(200_000);
    let mut v = 0i32;
    let err = xml::unmarshal_into(doc.as_bytes(), &mut v).unwrap_err();
    assert!(err.to_string().contains("EOF"), "{err}");
}

// ---- mutation robustness ---------------------------------------------------------------

#[test]
fn mutated_documents_never_panic() {
    // Deterministic xorshift mutations of a rich document, through the token
    // stream in every mode and the typed decoder.
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let pieces: [&[u8]; 14] = [
        b"<",
        b">",
        b"&",
        b"&#",
        b"]]>",
        b"--",
        b"<!--",
        b"<![CDATA[",
        b"<?",
        b"?>",
        b"/>",
        b"\xff",
        b"\"",
        b":",
    ];
    for _ in 0..3000 {
        let mut doc = TEST_INPUT.as_bytes().to_vec();
        for _ in 0..(1 + next() % 4) {
            let at = (next() as usize) % doc.len();
            match next() % 4 {
                0 => {
                    doc.remove(at);
                }
                1 => doc.insert(at, next() as u8),
                2 => {
                    let p = pieces[(next() as usize) % pieces.len()];
                    doc.splice(at..at, p.iter().copied());
                }
                _ => doc.truncate(at),
            }
            if doc.is_empty() {
                doc.push(b'<');
            }
        }
        for (strict, raw) in [(true, false), (false, false), (true, true)] {
            let mut d = Decoder::new(&doc[..]);
            d.strict = strict;
            d.entity = test_entity();
            d.auto_close = xml::html_auto_close();
            d.charset_reader = Some(Box::new(|_, r| Ok(r)));
            for _ in 0..2000 {
                let r = if raw { d.raw_token() } else { d.token() };
                if r.is_err() {
                    break;
                }
            }
        }
        let mut names: Vec<String> = Vec::new();
        let _ = xml::unmarshal_into(&doc, &mut names);
        let mut n = Named::default();
        let _ = xml::unmarshal_into(&doc, &mut n);
        let mut e = Encoder::new(Vec::new());
        let mut d = Decoder::new(&doc[..]);
        while let Ok(t) = d.token() {
            if e.encode_token(t).is_err() {
                break;
            }
        }
        let _ = e.close();
    }
}
