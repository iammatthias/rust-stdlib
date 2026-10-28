//! Tests for `encoding::json::jsontext`: tables ported from Go's
//! `state_test.go` (`TestPointer`), `value_test.go` (`TestValueMethods`),
//! `token_test.go` and `coder_test.go`, and golden vectors recorded from Go
//! 1.27.1 by `tools/jsontext_golden.py`.
use rust_stdlib::encoding::json::jsontext::{
    self as jt, Decoder, Encoder, Kind, Options, Pointer, Token, Value, ERR_DUPLICATE_NAME,
    ERR_NON_STRING_NAME,
};
use std::io::Cursor;

#[path = "../examples/jsontext_probe/protocol.rs"]
mod protocol;

#[test]
fn golden_vectors_recorded_from_go() {
    let golden = include_str!("fixtures/jsontext_golden.txt");
    let mut count = 0;
    for line in golden.lines() {
        let (request, want) = line.split_once('\t').expect("request and response");
        let got = std::thread::Builder::new()
            .stack_size(64 << 20)
            .spawn({
                let request = request.to_string();
                move || protocol::respond_safely(&request)
            })
            .expect("spawn")
            .join()
            .expect("respond");
        let shown: String = request.chars().take(160).collect();
        assert_eq!(got, want, "request {shown}");
        count += 1;
    }
    assert!(count > 1000, "{count} vectors");
}

#[test]
fn pointer() {
    // (in, parent, last, tokens, valid) from TestPointer; the entry with
    // invalid UTF-8 cannot be a Rust string.
    let tests: &[(&str, &str, &str, &[&str], bool)] = &[
        ("", "", "", &[], true),
        ("a", "", "a", &["a"], false),
        ("~", "", "~", &["~"], false),
        ("/a", "", "a", &["a"], true),
        ("/foo/bar", "/foo", "bar", &["foo", "bar"], true),
        ("///", "//", "", &["", "", ""], true),
        ("/~0~1", "", "~/", &["~/"], true),
    ];
    for &(input, parent, last, tokens, valid) in tests {
        let p = Pointer::from(input);
        assert_eq!(p.parent().as_str(), parent, "Pointer({input:?}).Parent");
        assert_eq!(p.last_token(), last, "Pointer({input:?}).Last");
        if input.starts_with('/') {
            assert_eq!(p.parent().append_token(&p.last_token()), p);
            let mut cur = p.clone();
            loop {
                assert!(!Pointer::from(format!("{cur}x")).contains(&p));
                assert!(cur.contains(&p));
                if cur == cur.parent() {
                    break;
                }
                cur = cur.parent();
            }
        }
        let got: Vec<String> = p.tokens().collect();
        assert_eq!(got, tokens, "Pointer({input:?}).Tokens");
        assert_eq!(p.is_valid(), valid, "Pointer({input:?}).IsValid");
    }
}

fn value_cases() -> Vec<(
    &'static str,
    &'static str,
    bool,
    &'static str,
    &'static str,
    &'static str,
)> {
    // (name, in, valid, compacted, indented, canonicalized)
    vec![
        (
            "RFC8785/Primitives",
            "{\n\t\t\"numbers\": [333333333.33333329, 1E30, 4.50,\n\t\t\t\t\t2e-3, 0.000000000000000000000000001, -0],\n\t\t\"string\": \"\\u20ac$\\u000F\\u000aA'\\u0042\\u0022\\u005c\\\\\\\"\\/\",\n\t\t\"literals\": [null, true, false]\n\t}",
            true,
            "{\"numbers\":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001,-0],\"string\":\"\\u20ac$\\u000F\\u000aA'\\u0042\\u0022\\u005c\\\\\\\"\\/\",\"literals\":[null,true,false]}",
            "{\n\t    \"numbers\": [\n\t        333333333.33333329,\n\t        1E30,\n\t        4.50,\n\t        2e-3,\n\t        0.000000000000000000000000001,\n\t        -0\n\t    ],\n\t    \"string\": \"\\u20ac$\\u000F\\u000aA'\\u0042\\u0022\\u005c\\\\\\\"\\/\",\n\t    \"literals\": [\n\t        null,\n\t        true,\n\t        false\n\t    ]\n\t}",
            "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27,0],\"string\":\"€$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}",
        ),
        (
            "RFC8785/ObjectOrdering",
            "{\n\t\t\"\\u20ac\": \"Euro Sign\",\n\t\t\"\\r\": \"Carriage Return\",\n\t\t\"\\ufb33\": \"Hebrew Letter Dalet With Dagesh\",\n\t\t\"1\": \"One\",\n\t\t\"\\ud83d\\ude00\": \"Emoji: Grinning Face\",\n\t\t\"\\u0080\": \"Control\",\n\t\t\"\\u00f6\": \"Latin Small Letter O With Diaeresis\"\n\t}",
            true,
            "{\"\\u20ac\":\"Euro Sign\",\"\\r\":\"Carriage Return\",\"\\ufb33\":\"Hebrew Letter Dalet With Dagesh\",\"1\":\"One\",\"\\ud83d\\ude00\":\"Emoji: Grinning Face\",\"\\u0080\":\"Control\",\"\\u00f6\":\"Latin Small Letter O With Diaeresis\"}",
            "{\n\t    \"\\u20ac\": \"Euro Sign\",\n\t    \"\\r\": \"Carriage Return\",\n\t    \"\\ufb33\": \"Hebrew Letter Dalet With Dagesh\",\n\t    \"1\": \"One\",\n\t    \"\\ud83d\\ude00\": \"Emoji: Grinning Face\",\n\t    \"\\u0080\": \"Control\",\n\t    \"\\u00f6\": \"Latin Small Letter O With Diaeresis\"\n\t}",
            "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\"😀\":\"Emoji: Grinning Face\",\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}",
        ),
        (
            "LargeIntegers",
            " [ -9223372036854775808 , 9223372036854775807 ] ",
            true,
            "[-9223372036854775808,9223372036854775807]",
            "[\n\t    -9223372036854775808,\n\t    9223372036854775807\n\t]",
            "[-9223372036854776000,9223372036854776000]",
        ),
        (
            "UppercaseEscaped",
            "\"\\u000B\"",
            true,
            "\"\\u000B\"",
            "\"\\u000B\"",
            "\"\\u000b\"",
        ),
    ]
}

#[test]
fn value_methods() {
    let indent = [jt::with_indent_prefix("\t"), jt::with_indent("    ")];
    for (name, input, valid, compacted, indented, canonicalized) in value_cases() {
        let v = Value::from(input);
        assert_eq!(v.is_valid(&[]), valid, "{name}: IsValid");
        let mut c = v.clone();
        c.compact(&[])
            .unwrap_or_else(|e| panic!("{name}: Compact: {e}"));
        assert_eq!(c.to_string(), compacted, "{name}: Compact");
        let mut i = v.clone();
        i.indent(&indent)
            .unwrap_or_else(|e| panic!("{name}: Indent: {e}"));
        assert_eq!(i.to_string(), indented, "{name}: Indent");
        let mut k = v.clone();
        k.canonicalize(&[])
            .unwrap_or_else(|e| panic!("{name}: Canonicalize: {e}"));
        assert_eq!(k.to_string(), canonicalized, "{name}: Canonicalize");
    }
}

#[test]
fn value_methods_errors() {
    // DuplicateNames: valid fails, Compact keeps the names, Canonicalize
    // reports the duplicate with its pointer.
    let input = " { \"0\" : 0 , \"1\" : 1 , \"0\" : 0 }";
    assert!(!Value::from(input).is_valid(&[]));
    let mut v = Value::from(input);
    v.compact(&[]).expect("compact allows duplicate names");
    assert_eq!(v.to_string(), "{\"0\":0,\"1\":1,\"0\":0}");
    let mut v = Value::from(input);
    let err = v.canonicalize(&[]).expect_err("duplicate name");
    let se = err.as_syntactic().expect("syntactic error");
    assert!(se.err.as_ref().is_some_and(|e| e.is(&ERR_DUPLICATE_NAME)));
    assert_eq!(se.json_pointer.as_str(), "/0");
    assert_eq!(
        v.to_string(),
        input,
        "a failed Canonicalize leaves the value"
    );
    // Whitespace alone ends unexpectedly.
    let mut v = Value::from(" \n\r\t");
    let err = v.compact(&[]).expect_err("no value");
    assert!(err
        .as_syntactic()
        .is_some_and(|s| matches!(s.err, Some(jt::Error::UnexpectedEof))));
    // Invalid UTF-8 and a surrogate half cannot be canonicalized.
    let mut v = Value(b"  \"living\xde\xad\xbe\xef\\ufffd\xef\xbf\xbd\"  ".to_vec());
    assert!(!v.is_valid(&[]));
    assert!(v.canonicalize(&[]).is_err());
    let mut v = Value::from("\"\\ud800\"");
    assert!(!v.is_valid(&[]));
    assert!(v.canonicalize(&[]).is_err());
}

#[test]
fn kinds_and_tokens() {
    assert_eq!(Kind(0).to_string(), "invalid");
    assert_eq!(jt::KIND_NUMBER.to_string(), "number");
    assert_eq!(Kind(b'x').to_string(), "<invalid jsontext.Kind: 'x'>");
    assert_eq!(jt::null().kind(), jt::KIND_NULL);
    assert_eq!(jt::string("").kind(), jt::KIND_STRING);
    assert_eq!(jt::uint(0).to_string(), "0");
    assert_eq!(jt::float(f64::NAN).to_string(), "NaN");
    assert_eq!(jt::float(f64::NEG_INFINITY).to_string(), "-Infinity");
    assert_eq!(Token::default().to_string(), "<invalid jsontext.Token>");
    assert_eq!(jt::int(-9).clone_token().to_string(), "-9");
    assert!(jt::bool(true).bool());
}

#[test]
fn token_accessor_panics() {
    let r = std::panic::catch_unwind(|| jt::null().bool());
    assert!(r.is_err());
    let r = std::panic::catch_unwind(|| jt::string("x").int());
    assert!(r.is_err());
}

#[test]
fn encoder_errors() {
    let mut out: Vec<u8> = Vec::new();
    let mut e = Encoder::new(&mut out, &[]);
    // A name must be a string.
    e.write_token(&jt::begin_object()).expect("{");
    let err = e.write_token(&jt::null()).expect_err("null as a name");
    assert!(err
        .as_syntactic()
        .is_some_and(|s| s.err.as_ref().is_some_and(|x| x.is(&ERR_NON_STRING_NAME))));
    e.write_token(&jt::string("k")).expect("name");
    // The object cannot end before a value.
    assert!(e.write_token(&jt::end_object()).is_err());
    e.write_token(&jt::int(1)).expect("value");
    assert!(e.write_token(&jt::string("k")).is_err(), "duplicate name");
    e.write_token(&jt::end_object()).expect("}");
    assert_eq!(e.output_offset(), 8);
    drop(e);
    assert_eq!(out, b"{\"k\":1}\n");
}

#[test]
fn decoder_stream() {
    let input = Cursor::new(b"{\"a\":[1,{\"b\":true}],\"c\":\"d\"} [] 7".to_vec());
    let mut d = Decoder::new(input, &[]);
    let mut seen = Vec::new();
    loop {
        let before = d.peek_kind();
        match d.read_token() {
            Ok(_) => seen.push(format!("{}{}", before, d.stack_pointer())),
            Err(e) => {
                assert!(matches!(e, jt::Error::Eof), "{e}");
                break;
            }
        }
    }
    assert_eq!(
        seen,
        [
            "{",
            "string/a",
            "[/a",
            "number/a/0",
            "{/a/1",
            "string/a/1/b",
            "true/a/1/b",
            "}/a/1",
            "]/a",
            "string/c",
            "string/c",
            "}",
            "[",
            "]",
            "number"
        ]
    );
    assert_eq!(d.input_offset(), 33);
}

#[test]
fn nesting_limit() {
    // 10000 levels are allowed, 10001 are not; the recursion needs a stack
    // bigger than a test thread's.
    std::thread::Builder::new()
        .stack_size(128 << 20)
        .spawn(|| {
            let ok = format!("{}{}", "[".repeat(10000), "]".repeat(10000));
            assert!(Value::from(ok.as_str()).is_valid(&[]));
            let deep = "[".repeat(10001);
            let mut d = Decoder::from_buffer(deep.into_bytes(), &[]);
            let err = d.read_value().expect_err("too deep");
            assert!(err.to_string().contains("exceeded max depth"), "{err}");
        })
        .expect("spawn")
        .join()
        .expect("thread");
}

#[test]
fn options_join() {
    let o: Options = jt::space_after_colon(true)
        .join(&jt::space_after_colon(false))
        .join(&jt::with_indent("  "));
    let mut v = Value::from("{\"a\":[1]}");
    v.format(&[o]).expect("format");
    assert_eq!(v.to_string(), "{\n  \"a\":[\n    1\n  ]\n}");
}

#[test]
fn append_helpers() {
    let mut dst = b"x".to_vec();
    jt::append_quote(&mut dst, "a\"b<".as_bytes()).expect("quote");
    assert_eq!(dst, b"x\"a\\\"b<\"");
    let mut dst = Vec::new();
    jt::append_unquote(&mut dst, b"\"\\u00e9\\n\"").expect("unquote");
    assert_eq!(dst, "é\n".as_bytes());
    let mut dst = Vec::new();
    jt::append_float(&mut dst, 1e21, 64);
    assert_eq!(dst, b"1e+21");
    let mut dst = Vec::new();
    jt::append_format(&mut dst, b" [ 1 , 2 ] ", &[]).expect("format");
    assert_eq!(dst, b"[1,2]");
}
