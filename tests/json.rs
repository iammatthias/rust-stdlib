//! Tests for the Go-compatible half of `encoding::json` (Marshal, Unmarshal,
//! Valid/Compact/Indent/HTMLEscape, Decoder, Encoder and the error types).
//! Derive-based struct tests live in `tools/derive-check`, which can depend on
//! the derive crate. Tables are ported from Go's `scanner_test.go`,
//! `stream_test.go`, `encode_test.go` and `decode_test.go`; the golden vectors
//! were recorded from Go 1.27.1 by `tools/json_golden.py`.
use rust_stdlib::encoding::json::{
    self, compact, default_options_v1, format_float, html_escape, indent, marshal, marshal_indent,
    unmarshal, valid, Bytes, Decoder, Delim, Encoder, Error, InvalidUTF8Error,
    InvalidUnmarshalError, MarshalerError, Number, RawMessage, Serializer, SyntaxError, Token,
    UnmarshalFieldError, UnmarshalTypeError, UnsupportedTypeError, UnsupportedValueError, Value,
};
use std::{
    collections::{BTreeMap, HashMap},
    io::{self, Read},
};

#[path = "../examples/json_probe/protocol.rs"]
mod protocol;

fn s(b: &[u8]) -> &str {
    std::str::from_utf8(b).unwrap()
}

#[test]
fn golden_vectors_recorded_from_go() {
    let golden = include_str!("fixtures/json_golden.txt");
    let mut count = 0;
    for line in golden.lines() {
        let (request, want) = line.split_once('\t').unwrap();
        assert_eq!(protocol::respond(request), want, "request {request}");
        count += 1;
    }
    assert!(count > 2000, "{count}");
}

#[test]
fn valid_table() {
    for (data, ok) in [
        ("foo", false),
        ("}{", false),
        ("{]", false),
        ("{}", true),
        (r#"{"foo":"bar"}"#, true),
        (r#"{"foo":"bar","bar":{"baz":["qux"]}}"#, true),
        ("", false),
        (" null ", true),
        ("[1 2]", false),
        ("\u{feff}1", false),
    ] {
        assert_eq!(valid(data.as_bytes()), ok, "{data:?}");
    }
    // Strings may hold invalid UTF-8, which Valid does not look at.
    assert!(valid(b"\"\xff\""));
}

#[test]
fn compact_and_indent_table() {
    for (compact_form, indent_form) in [
        ("1", "1"),
        ("{}", "{}"),
        ("[]", "[]"),
        (r#"{"":2}"#, "{\n\t\"\": 2\n}"),
        ("[3]", "[\n\t3\n]"),
        ("[1,2,3]", "[\n\t1,\n\t2,\n\t3\n]"),
        (r#"{"x":1}"#, "{\n\t\"x\": 1\n}"),
        (
            r#"[true,false,null,"x",1,1.5,0,-5e+2]"#,
            "[\n\ttrue,\n\tfalse,\n\tnull,\n\t\"x\",\n\t1,\n\t1.5,\n\t0,\n\t-5e+2\n]",
        ),
        (
            "{\"\":\"<>&\u{2028}\u{2029}\"}",
            "{\n\t\"\": \"<>&\u{2028}\u{2029}\"\n}",
        ),
        ("null", "null \n\r\t"),
    ] {
        let mut out = Vec::new();
        compact(&mut out, indent_form.as_bytes()).unwrap();
        assert_eq!(s(&out), compact_form, "compact {indent_form:?}");
        out.clear();
        compact(&mut out, compact_form.as_bytes()).unwrap();
        assert_eq!(s(&out), compact_form);
        out.clear();
        indent(&mut out, compact_form.as_bytes(), "", "\t").unwrap();
        assert_eq!(
            s(&out),
            indent_form.trim_end_matches([' ', '\n', '\r', '\t'])
        );
    }
}

#[test]
fn indent_prefix_and_trailing_space() {
    let mut out = b"keep".to_vec();
    indent(&mut out, br#"{"a":[1,{}],"b":[]}"#, ">", ".").unwrap();
    assert_eq!(
        s(&out),
        "keep{\n>.\"a\": [\n>..1,\n>..{}\n>.],\n>.\"b\": []\n>}"
    );
    // On error nothing is appended.
    let mut out = b"keep".to_vec();
    assert!(indent(&mut out, b"[1,", "", " ").is_err());
    assert!(compact(&mut out, b"[1,").is_err());
    assert_eq!(s(&out), "keep");
}

#[test]
fn compact_separators_keep_line_separators_in_strings() {
    for (input, want) in [
        ("{\"\u{2028}\": 1}", "{\"\u{2028}\":1}"),
        ("{\"\u{2029}\" :2}", "{\"\u{2029}\":2}"),
    ] {
        let mut out = Vec::new();
        compact(&mut out, input.as_bytes()).unwrap();
        assert_eq!(s(&out), want);
    }
}

#[test]
fn html_escape_matches_go() {
    let mut out = Vec::new();
    html_escape(
        &mut out,
        "<a href=\"x\">&amp;\u{2028}\u{2029}é</a>\u{2027}".as_bytes(),
    );
    assert_eq!(
        s(&out),
        "\\u003ca href=\"x\"\\u003e\\u0026amp;\\u2028\\u2029é\\u003c/a\\u003e\u{2027}"
    );
    // A truncated E2 80 sequence at the end is left alone.
    out.clear();
    html_escape(&mut out, b"\xe2\x80");
    assert_eq!(out, b"\xe2\x80");
}

fn syntax(input: &[u8]) -> (String, i64) {
    let mut out = Vec::new();
    let e = compact(&mut out, input).unwrap_err();
    (e.to_string(), e.offset)
}

#[test]
fn syntax_errors_have_go_text_and_offsets() {
    for (input, msg, offset) in [
        (&b""[..], "unexpected end of JSON input", 0),
        (b"nul", "unexpected end of JSON input", 3),
        (b"nulll", "invalid character 'l' after top-level value", 5),
        (b"[1 2]", "invalid character '2' after array value", 4),
        (b"{\"a\" 1}", "invalid character '1' after object key", 6),
        (
            b"{1:2}",
            "invalid character '1' looking for beginning of object key string",
            2,
        ),
        (
            b"[1,]",
            "invalid character ']' looking for beginning of value",
            4,
        ),
        (b"-", "unexpected end of JSON input", 0),
        (b"1.", "unexpected end of JSON input", 1),
        (b"1e+", "unexpected end of JSON input", 1),
        (b"-a", "invalid character 'a' in numeric literal", 2),
        (
            b"trux",
            "invalid character 'x' in literal true (expecting 'e')",
            4,
        ),
        (b"\"a\x01\"", "invalid character '\\x01' in string", 3),
        (b"\"\\x\"", "invalid escape sequence `\\x` in string", 3),
        (
            b"\"\\u12zz\"",
            "invalid escape sequence `\\u12zz` in string",
            7,
        ),
        (b"\"\\u12", "unexpected end of JSON input", 1),
        (b"\"a\xe2\x80", "unexpected end of JSON input", 2),
        (
            b"\xff",
            "invalid character '\\xff' looking for beginning of value",
            1,
        ),
        (
            "\u{2029}".as_bytes(),
            "invalid character '\\u2029' looking for beginning of value",
            3,
        ),
        (
            "é".as_bytes(),
            "invalid character 'é' looking for beginning of value",
            2,
        ),
        (
            b"'",
            "invalid character '\\'' looking for beginning of value",
            1,
        ),
    ] {
        assert_eq!(
            syntax(input),
            (msg.to_string(), offset),
            "{:?}",
            String::from_utf8_lossy(input)
        );
    }
}

#[test]
fn unmarshal_reports_errors_like_compact_except_array_wording() {
    let e = unmarshal::<Value>(b"[1 2]").unwrap_err();
    assert_eq!(e.to_string(), "invalid character '2' after array element");
    assert!(matches!(
        e,
        Error::SyntaxError(SyntaxError { offset: 4, .. })
    ));
    let e = unmarshal::<Value>(b"1.").unwrap_err();
    assert_eq!(e.to_string(), "unexpected end of JSON input");
    assert!(matches!(
        e,
        Error::SyntaxError(SyntaxError { offset: 0, .. })
    ));
}

#[test]
fn nesting_depth_limit_is_10000() {
    let mut ok = vec![b'['; 10000];
    ok.extend(std::iter::repeat_n(b']', 10000));
    assert!(valid(&ok));
    let mut bad = vec![b'['; 10001];
    bad.extend(std::iter::repeat_n(b']', 10001));
    assert!(!valid(&bad));
    assert_eq!(syntax(&bad), ("exceeded max depth".to_string(), 10001));
    let mut out = Vec::new();
    compact(&mut out, &ok).unwrap();
    assert_eq!(out, ok);
}

#[test]
fn float_formatting_follows_go() {
    for (f, want) in [
        (0.0, "0"),
        (-0.0, "-0"),
        (1.0, "1"),
        (0.1, "0.1"),
        (100.0, "100"),
        (1e20, "100000000000000000000"),
        (1e21, "1e+21"),
        (1e22, "1e+22"),
        (123456789e15, "1.23456789e+23"),
        (123456789e12, "123456789000000000000"),
        (1e-6, "0.000001"),
        (1e-7, "1e-7"),
        (9.999e-7, "9.999e-7"),
        (1.5e-10, "1.5e-10"),
        (5e-324, "5e-324"),
        (f64::MAX, "1.7976931348623157e+308"),
        (-1.5e300, "-1.5e+300"),
        (12345678901234567890.0, "12345678901234567000"),
    ] {
        assert_eq!(format_float(f, 64), want, "{f:e}");
        assert_eq!(s(&marshal(&f).unwrap()), want);
    }
    for (f, want) in [
        (3.4028235e38f32, "3.4028235e+38"),
        (1e-7f32, "1e-7"),
        (16777216.0, "16777216"),
        (0.1, "0.1"),
    ] {
        assert_eq!(s(&marshal(&f).unwrap()), want);
    }
}

/// Go's `TestMarshalFloat`: every float encodes to its shortest round-trip
/// form without the artefacts listed in `badFloatREs`.
#[test]
fn float_encoding_round_trips_in_canonical_form() {
    let digits = "1.2345678901234567890123";
    for i in (2..=digits.len()).rev() {
        for exp in -30..=30 {
            for sign in ["+", "-"] {
                for bits in [32u32, 64] {
                    let text = format!("{sign}{}e{exp}", &digits[..i]);
                    let f: f64 = if bits == 32 {
                        f64::from(text.parse::<f32>().unwrap())
                    } else {
                        text.parse().unwrap()
                    };
                    let out = if bits == 32 {
                        s(&marshal(&(f as f32)).unwrap()).to_string()
                    } else {
                        s(&marshal(&f).unwrap()).to_string()
                    };
                    let back: f64 = if bits == 32 {
                        f64::from(out.parse::<f32>().unwrap())
                    } else {
                        out.parse().unwrap()
                    };
                    assert_eq!(f.to_bits(), back.to_bits(), "{text} -> {out}");
                    let digits_only = out.trim_start_matches('-');
                    assert!(!out.starts_with('+'), "{out}");
                    assert!(
                        !(digits_only.starts_with('0')
                            && !digits_only.starts_with("0.")
                            && digits_only != "0"),
                        "{out}"
                    );
                    assert!(!out.contains(".e") && !out.ends_with('.'), "{out}");
                    assert!(
                        !out.contains("e0") && !out.contains("e-0") && !out.contains("e+0"),
                        "{out}"
                    );
                    if let Some((mantissa, e)) = out.split_once('e') {
                        assert!(e.starts_with(['+', '-']), "{out}");
                        let n: i32 = e.parse().unwrap();
                        assert!(!(-6..21).contains(&n), "{out}");
                        assert!(
                            !mantissa.trim_start_matches('-').contains('.')
                                || mantissa.trim_start_matches('-').len() > 1
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn non_finite_floats_are_unsupported_values() {
    for (f, text) in [
        (f64::NAN, "NaN"),
        (f64::INFINITY, "+Inf"),
        (f64::NEG_INFINITY, "-Inf"),
    ] {
        let e = marshal(&f).unwrap_err();
        assert_eq!(e.to_string(), format!("json: unsupported value: {text}"));
        assert!(matches!(e, Error::UnsupportedValue(_)));
    }
    assert_eq!(
        marshal(&f32::NAN).unwrap_err().to_string(),
        "json: unsupported value: NaN"
    );
}

#[test]
fn string_escaping_matches_go() {
    for (input, want) in [
        ("", "\"\""),
        ("abc", "\"abc\""),
        ("a\"b\\c/d", "\"a\\\"b\\\\c/d\""),
        ("\u{8}\u{c}\n\r\t", "\"\\b\\f\\n\\r\\t\""),
        ("\u{0}\u{1f}\u{7f}", "\"\\u0000\\u001f\u{7f}\""),
        ("<>&", "\"\\u003c\\u003e\\u0026\""),
        ("\u{2028}\u{2029}", "\"\\u2028\\u2029\""),
        ("é日本語😀", "\"é日本語😀\""),
    ] {
        assert_eq!(s(&marshal(input).unwrap()), want, "{input:?}");
    }
    let mut ser = Serializer::new(false);
    ser.write_string("<>&\u{2028}", false);
    assert_eq!(s(ser.as_bytes()), "\"<>&\\u2028\"");
    // Invalid UTF-8 is replaced, one \ufffd per bad byte.
    let mut ser = Serializer::new(true);
    ser.write_string_bytes(b"a\xffb\xe2\x82c", false);
    assert_eq!(s(ser.as_bytes()), "\"a\\ufffdb\\ufffd\\ufffdc\"");
    // The `string` option quotes the quoted form again.
    let mut ser = Serializer::new(true);
    ser.write_string("<q>", true);
    assert_eq!(s(ser.as_bytes()), r#""\"\\u003cq\\u003e\"""#);
}

#[test]
fn maps_sort_by_key_text() {
    let mut m = BTreeMap::new();
    for k in [10i64, 9, -1, 100, 2] {
        m.insert(k, k * 2);
    }
    assert_eq!(
        s(&marshal(&m).unwrap()),
        r#"{"-1":-2,"10":20,"100":200,"2":4,"9":18}"#
    );
    let mut h: HashMap<String, Vec<u8>> = HashMap::new();
    h.insert("b".into(), vec![1]);
    h.insert("a".into(), vec![]);
    h.insert("é".into(), vec![2, 3]);
    h.insert("K".into(), vec![]);
    assert_eq!(
        s(&marshal(&h).unwrap()),
        r#"{"K":[],"a":[],"b":[1],"é":[2,3]}"#
    );
}

#[test]
fn marshal_of_standard_types() {
    assert_eq!(s(&marshal(&Some(5u8)).unwrap()), "5");
    assert_eq!(s(&marshal(&None::<u8>).unwrap()), "null");
    assert_eq!(
        s(&marshal(&vec![Some("a"), None]).unwrap()),
        r#"["a",null]"#
    );
    assert_eq!(s(&marshal(&[1.5f64, 2.0]).unwrap()), "[1.5,2]");
    assert_eq!(
        s(&marshal(&Bytes(b"hello".to_vec())).unwrap()),
        "\"aGVsbG8=\""
    );
    assert_eq!(s(&marshal(&Bytes(vec![])).unwrap()), "\"\"");
    assert_eq!(s(&marshal(&vec![1u8, 2]).unwrap()), "[1,2]");
    assert_eq!(s(&marshal(&true).unwrap()), "true");
    assert_eq!(
        s(&marshal(&std::time::Duration::from_millis(1500)).unwrap()),
        "1500000000"
    );
    assert_eq!(s(&marshal(&Box::new(7i8)).unwrap()), "7");
    assert_eq!(
        s(&marshal(&i128::MIN).unwrap()),
        "-170141183460469231731687303715884105728"
    );
    let v: Value = unmarshal(br#"{"b":[1,2.50,"x"],"a":null}"#).unwrap();
    assert_eq!(s(&marshal(&v).unwrap()), r#"{"a":null,"b":[1,2.5,"x"]}"#);
}

#[test]
fn marshal_indent_applies_prefix_and_indent() {
    let v: Value = unmarshal(br#"{"a":[1,{"b":null}],"c":{}}"#).unwrap();
    assert_eq!(
        s(&marshal_indent(&v, "> ", "  ").unwrap()),
        "{\n>   \"a\": [\n>     1,\n>     {\n>       \"b\": null\n>     }\n>   ],\n>   \"c\": {}\n> }"
    );
}

#[test]
fn numbers() {
    let n = Number::new("12345678901234567890").unwrap();
    assert_eq!(n.to_string(), "12345678901234567890");
    assert_eq!(n.float64().unwrap(), 12345678901234567890.0);
    assert_eq!(
        n.int64().unwrap_err().to_string(),
        "strconv.ParseInt: parsing \"12345678901234567890\": value out of range"
    );
    assert_eq!(Number::new("-12").unwrap().int64().unwrap(), -12);
    assert_eq!(
        Number::new("1.5").unwrap().int64().unwrap_err().to_string(),
        "strconv.ParseInt: parsing \"1.5\": invalid syntax"
    );
    assert_eq!(
        Number::new("1e999")
            .unwrap()
            .float64()
            .unwrap_err()
            .to_string(),
        "strconv.ParseFloat: parsing \"1e999\": value out of range"
    );
    // Construction validates; the zero Number is 0.
    assert_eq!(s(&marshal(&Number::new("").unwrap()).unwrap()), "0");
    assert_eq!(
        s(&marshal(&Number::new("-1.5e+3").unwrap()).unwrap()),
        "-1.5e+3"
    );
    for bad in ["01", "+1", "1.", ".5", "1e", "-", "abc", "1 "] {
        let e = Number::new(bad).unwrap_err();
        assert_eq!(
            e.to_string(),
            format!("json: error calling MarshalJSONTo for type *json.Number: cannot parse {bad:?} as JSON number: invalid syntax")
        );
    }
}

#[test]
fn unmarshal_into_values_and_numbers() {
    let v: Value =
        unmarshal(b" [1, 2.50, -0, 1e2, 1E+2, \"x\", true, null, {\"a\": {}}] ").unwrap();
    assert_eq!(
        s(&marshal(&v).unwrap()),
        r#"[1,2.5,-0,100,100,"x",true,null,{"a":{}}]"#
    );
    // Duplicate keys: the last one wins.
    let v: Value = unmarshal(br#"{"a":1,"a":2}"#).unwrap();
    assert_eq!(s(&marshal(&v).unwrap()), r#"{"a":2}"#);
    // Invalid UTF-8 and lone surrogates become U+FFFD.
    let v: Value = unmarshal(b"[\"\xff\\ud800\\udc00\\ud83dx\\ude00\"]").unwrap();
    assert_eq!(
        s(&marshal(&v).unwrap()),
        "[\"\u{fffd}\u{10000}\u{fffd}x\u{fffd}\"]"
    );
    let e = unmarshal::<Value>(b"[1e999]").unwrap_err();
    assert_eq!(
        e.to_string(),
        "json: cannot unmarshal number 1e999 into .0 of type float64"
    );
    let Error::UnmarshalType(t) = e else { panic!() };
    assert_eq!(
        (t.offset, t.field.as_str(), t.value.as_str()),
        (6, "0", "number 1e999")
    );
}

#[test]
fn typed_unmarshal_errors_have_go_text() {
    for (input, want) in [
        (
            r#"["a"]"#,
            "json: cannot unmarshal string into .0 of type int32",
        ),
        (
            r#"[1.5]"#,
            "json: cannot unmarshal number 1.5 into .0 of type int32",
        ),
        (
            r#"[3000000000]"#,
            "json: cannot unmarshal number 3000000000 into .0 of type int32",
        ),
        (
            r#"{"a":1}"#,
            "json: cannot unmarshal object into Go value of type []int32",
        ),
        (
            "5",
            "json: cannot unmarshal number into Go value of type []int32",
        ),
    ] {
        let e = unmarshal::<Vec<i32>>(input.as_bytes()).unwrap_err();
        assert_eq!(e.to_string(), want, "{input}");
    }
    assert_eq!(
        unmarshal::<u8>(b"-1").unwrap_err().to_string(),
        "json: cannot unmarshal number -1 into Go value of type uint8"
    );
    assert_eq!(
        unmarshal::<String>(b"1").unwrap_err().to_string(),
        "json: cannot unmarshal number into Go value of type string"
    );
    assert_eq!(
        unmarshal::<BTreeMap<u8, bool>>(br#"{"300":true}"#)
            .unwrap_err()
            .to_string(),
        "json: cannot unmarshal number 300 into .300 of type uint8"
    );
    assert_eq!(
        unmarshal::<BTreeMap<String, Vec<bool>>>(br#"{"a/b":[true,1]}"#)
            .unwrap_err()
            .to_string(),
        "json: cannot unmarshal number into .a~1b.1 of type bool"
    );
    // null decodes to the zero value.
    assert_eq!(unmarshal::<i32>(b"null").unwrap(), 0);
    assert_eq!(unmarshal::<Vec<i32>>(b"null").unwrap(), Vec::<i32>::new());
    assert_eq!(unmarshal::<Option<i32>>(b"null").unwrap(), None);
    assert_eq!(unmarshal::<Option<i32>>(b"4").unwrap(), Some(4));
    assert_eq!(unmarshal::<[u8; 3]>(b"[1]").unwrap(), [1, 0, 0]);
    assert_eq!(unmarshal::<[u8; 2]>(b"[1,2,3]").unwrap(), [1, 2]);
    assert_eq!(
        unmarshal::<Bytes>(b"\"aGVsbG8=\"").unwrap(),
        Bytes(b"hello".to_vec())
    );
    assert_eq!(unmarshal::<Bytes>(b"[1,2]").unwrap(), Bytes(vec![1, 2]));
    assert_eq!(
        unmarshal::<Bytes>(b"\"a!\"").unwrap_err().to_string(),
        "json: cannot unmarshal string into Go value of type []uint8: illegal base64 data at input byte 1"
    );
    assert_eq!(
        unmarshal::<std::time::Duration>(b"2500").unwrap(),
        std::time::Duration::from_nanos(2500)
    );
    // Syntax errors come first, even when a type error precedes them.
    let e = unmarshal::<Vec<u8>>(b"[\"x\", 1,]").unwrap_err();
    assert!(matches!(e, Error::SyntaxError(_)));
}

#[test]
fn error_types_have_go_text_and_fields() {
    let t = UnmarshalTypeError {
        value: "number".into(),
        type_name: "int".into(),
        ..Default::default()
    };
    assert_eq!(
        t.to_string(),
        "json: cannot unmarshal number into Go value of type int"
    );
    let t = UnmarshalTypeError {
        value: "string".into(),
        type_name: "int".into(),
        struct_name: "T".into(),
        field: "a.b".into(),
        ..Default::default()
    };
    assert_eq!(
        t.to_string(),
        "json: cannot unmarshal string into Go struct field T.a.b of type int"
    );
    let t = UnmarshalTypeError {
        value: "string".into(),
        type_name: "int".into(),
        struct_name: "T".into(),
        field: "a.0".into(),
        err: Some("too few array elements".into()),
        ..Default::default()
    };
    assert_eq!(
        t.to_string(),
        "json: cannot unmarshal string into T.a.0 of type int: too few array elements"
    );
    assert!(std::error::Error::source(&t).is_some());
    assert_eq!(
        InvalidUnmarshalError::default().to_string(),
        "json: Unmarshal(nil)"
    );
    assert_eq!(
        InvalidUnmarshalError {
            type_name: Some("int".into()),
            pointer: false
        }
        .to_string(),
        "json: Unmarshal(non-pointer int)"
    );
    assert_eq!(
        InvalidUnmarshalError {
            type_name: Some("*int".into()),
            pointer: true
        }
        .to_string(),
        "json: Unmarshal(nil *int)"
    );
    assert_eq!(
        UnsupportedTypeError {
            type_name: "chan int".into()
        }
        .to_string(),
        "json: unsupported type: chan int"
    );
    assert_eq!(
        UnsupportedValueError {
            value: "x".into(),
            str: "NaN".into()
        }
        .to_string(),
        "json: unsupported value: NaN"
    );
    assert_eq!(
        InvalidUTF8Error {
            s: "a\u{1}b".into()
        }
        .to_string(),
        "json: invalid UTF-8 in string: \"a\\x01b\""
    );
    assert_eq!(
        UnmarshalFieldError {
            key: "k\"".into(),
            type_name: "T".into(),
            field: "f".into()
        }
        .to_string(),
        "json: cannot unmarshal object key \"k\\\"\" into unexported field f of type T"
    );
    let m = MarshalerError::new("*T", "boom".into());
    assert_eq!(
        m.to_string(),
        "json: error calling MarshalJSON for type *T: boom"
    );
    assert_eq!(std::error::Error::source(&m).unwrap().to_string(), "boom");
    assert_eq!(SyntaxError::new("bad", 7).to_string(), "bad");
    assert_eq!(Error::Eof.to_string(), "EOF");
    assert!(matches!(
        Error::from(SyntaxError::new("x", 1)),
        Error::SyntaxError(_)
    ));
}

struct Marshals(&'static str);
impl json::Marshaler for Marshals {
    fn marshal_json(&self) -> Result<Vec<u8>, Error> {
        if self.0 == "ERR" {
            return Err(Error::Other("boom".into()));
        }
        Ok(self.0.as_bytes().to_vec())
    }
}
impl json::Serialize for Marshals {
    fn to_json(&self) -> Result<Value, Error> {
        json::serialize_to_value(self)
    }
    fn serialize(&self, out: &mut Serializer) -> Result<(), Error> {
        out.marshaler("main.Marshals", json::Marshaler::marshal_json(self))
    }
}

#[test]
fn marshaler_output_is_validated_compacted_and_escaped() {
    assert_eq!(
        s(&marshal(&Marshals(" { \"a\" : [ 1 , \"<\" ] } ")).unwrap()),
        r#"{"a":[1,"\u003c"]}"#
    );
    let mut buf = Vec::new();
    let mut enc = Encoder::new(&mut buf);
    enc.set_escape_html(false);
    enc.encode(&Marshals("\"<&>\"")).unwrap();
    assert_eq!(s(&buf), "\"<&>\"\n");
    let e = marshal(&Marshals("ERR")).unwrap_err();
    assert_eq!(
        e.to_string(),
        "json: error calling MarshalJSON for type *main.Marshals: boom"
    );
    let Error::Marshaler(m) = &e else { panic!() };
    assert_eq!(m.type_name, "*main.Marshals");
    let e = marshal(&vec![0u8, 1])
        .and_then(|_| marshal(&Marshals("1 2")))
        .unwrap_err();
    assert_eq!(
        e.to_string(),
        "json: error calling MarshalJSON for type *main.Marshals: invalid character '2' after top-level value"
    );
    let Error::Marshaler(m) = &e else { panic!() };
    let inner = m.err.downcast_ref::<SyntaxError>().unwrap();
    assert_eq!(inner.offset, 3);
}

#[test]
fn raw_message_round_trips_and_defaults_to_null() {
    let raw: RawMessage = unmarshal(br#"["\u0056", null]"#).unwrap();
    assert_eq!(s(&raw.0), r#"["\u0056", null]"#);
    assert_eq!(s(&marshal(&raw).unwrap()), r#"["\u0056",null]"#);
    assert_eq!(s(&marshal(&RawMessage::default()).unwrap()), "null");
    let nul: RawMessage = unmarshal(b"null").unwrap();
    assert_eq!(s(&nul.0), "null");
    assert_eq!(
        marshal(&RawMessage(b"[".to_vec())).unwrap_err().to_string(),
        "json: error calling MarshalJSON for type *jsontext.Value: unexpected end of JSON input"
    );
    // A RawMessage sees its text unchanged, and html escaping applies on output.
    let raw: RawMessage = unmarshal(b" {\"a\" : \"<\"} ").unwrap();
    assert_eq!(s(&raw.0), "{\"a\" : \"<\"}");
    assert_eq!(s(&marshal(&raw).unwrap()), r#"{"a":"\u003c"}"#);
}

// ---- Decoder and Encoder -------------------------------------------------

struct FnReader<F>(F);
impl<F: FnMut(&mut [u8]) -> io::Result<usize>> Read for FnReader<F> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        (self.0)(out)
    }
}

const STREAM_ENCODED: &str =
    "0.1\n\"hello\"\nnull\ntrue\nfalse\n[\"a\",\"b\",\"c\"]\n{\"\u{ff}K\":\"x\"}\n3.14\n";

#[test]
fn decoder_reads_values_without_separators() {
    let input: String = STREAM_ENCODED.replace('\n', "");
    let mut d = Decoder::new(input.as_bytes());
    let want = [
        r#"0.1"#,
        r#""hello""#,
        "null",
        "true",
        "false",
        r#"["a","b","c"]"#,
        "{\"\u{ff}K\":\"x\"}",
        "3.14",
    ];
    for w in want {
        let v: Value = d.decode().unwrap();
        assert_eq!(s(&marshal(&v).unwrap()), w);
    }
    assert!(matches!(d.decode::<Value>(), Err(Error::Eof)));
    // The end of input is sticky.
    assert!(matches!(d.decode::<Value>(), Err(Error::Eof)));
}

#[test]
fn decoder_buffered_and_input_offset() {
    let mut d = Decoder::new(&br#"{"Name": "Gopher"} extra "#[..]);
    let v: Value = d.decode().unwrap();
    assert_eq!(s(&marshal(&v).unwrap()), r#"{"Name":"Gopher"}"#);
    assert_eq!(s(d.buffered()), " extra ");
    assert_eq!(d.input_offset(), 18);
}

#[test]
fn decoder_token_errors_match_go() {
    let cases: Vec<(&str, Option<io::ErrorKind>, &str)> = vec![
        ("", None, "EOF"),
        ("{", None, "EOF"),
        ("{\"", Some(io::ErrorKind::UnexpectedEof), "unexpected EOF"),
        ("{\"k\"", None, "EOF"),
        ("{\"k\":", None, "EOF"),
        ("{\"k\",", None, "invalid character ',' after object key@5"),
        ("{\"k\"}", None, "invalid character '}' after object key@5"),
        (" [0", None, "EOF"),
        ("[0.", Some(io::ErrorKind::UnexpectedEof), "unexpected EOF"),
        ("[0. ", None, "invalid character ' ' in numeric literal@4"),
        ("[0,", None, "EOF"),
        ("[0:", None, "invalid character ':' after array element@3"),
        ("n", Some(io::ErrorKind::UnexpectedEof), "unexpected EOF"),
        ("nul", Some(io::ErrorKind::UnexpectedEof), "unexpected EOF"),
        (
            "fal ",
            None,
            "invalid character ' ' in literal false (expecting 's')@4",
        ),
        ("false", None, "EOF"),
        (
            "  1e1000",
            None,
            "json: cannot unmarshal number 1e1000 into Go value of type float64",
        ),
        ("{\"foo\":1}{\"bar\":2}", None, "EOF"),
    ];
    for (input, kind, want) in cases {
        let mut d = Decoder::new(input_reader(input));
        let err = loop {
            match d.token() {
                Ok(_) => {}
                Err(e) => break e,
            }
        };
        let got = match &err {
            Error::SyntaxError(se) => format!("{err}@{}", se.offset),
            _ => err.to_string(),
        };
        assert_eq!(got, want, "{input:?}");
        if let Some(kind) = kind {
            assert!(
                matches!(&err, Error::Io(e) if e.kind() == kind),
                "{input:?}"
            );
        }
    }
}

fn input_reader(input: &str) -> io::Cursor<Vec<u8>> {
    io::Cursor::new(input.as_bytes().to_vec())
}

#[test]
fn decoder_input_offset_with_more() {
    let input = " [\n\t\t[ ] , [ \"one\" ] , [ \"one\" , \"two\" ] ,\n\t\t{ } , { \"alpha\" : \"bravo\" } , { \"alpha\" : \"bravo\" , \"fizz\" : \"buzz\" }\n\t] ";
    let want_offsets: Vec<i64> = vec![
        0, 1, 2, 5, 6, 7, 8, 9, 12, 13, 18, 19, 20, 21, 24, 25, 30, 31, 38, 39, 40, 41, 46, 47, 48,
        49, 52, 53, 60, 61, 70, 71, 72, 73, 76, 77, 84, 85, 94, 95, 103, 104, 112, 113, 114, 116,
        117, 117, 117, 117,
    ];
    let want_mores = [
        true, true, false, true, true, false, true, true, true, false, true, false, true, true,
        true, false, true, true, true, true, true, false, false, false, false,
    ];
    let mut d = Decoder::new(input.as_bytes());
    let mut offsets = vec![d.input_offset()];
    let mut mores = vec![d.more()];
    offsets.push(d.input_offset());
    loop {
        match d.token() {
            Err(Error::Eof) => break,
            Err(e) => panic!("{e}"),
            Ok(_) => {}
        }
        offsets.push(d.input_offset());
        mores.push(d.more());
        offsets.push(d.input_offset());
    }
    offsets.push(d.input_offset());
    mores.push(d.more());
    offsets.push(d.input_offset());
    assert_eq!(offsets, want_offsets);
    assert_eq!(mores, want_mores);

    for (input, want) in [(" [ \"fizz\" , ", 11), (" { \"fizz\" : ", 11)] {
        let mut d = Decoder::new(input.as_bytes());
        while d.token().is_ok() {}
        assert_eq!(d.input_offset(), want, "{input:?}");
    }
}

#[test]
fn decoder_tokens_and_use_number() {
    let mut d = Decoder::new(&br#"{"a":[1,2.5,"x",true,null]}"#[..]);
    d.use_number();
    let mut out = Vec::new();
    while let Ok(t) = d.token() {
        out.push(t);
    }
    assert_eq!(
        out,
        vec![
            Token::Delim(Delim('{')),
            Token::String("a".into()),
            Token::Delim(Delim('[')),
            Token::Number(Number::new("1").unwrap()),
            Token::Number(Number::new("2.5").unwrap()),
            Token::String("x".into()),
            Token::Bool(true),
            Token::Null,
            Token::Delim(Delim(']')),
            Token::Delim(Delim('}')),
        ]
    );
    assert_eq!(Delim('[').to_string(), "[");
    assert_eq!(Delim('}').to_string(), "}");
    // Without UseNumber numbers are floats.
    let mut d = Decoder::new(&b"[7]"[..]);
    d.token().unwrap();
    assert_eq!(d.token().unwrap(), Token::Float64(7.0));
}

#[test]
fn decoder_tolerates_one_byte_reads_and_reports_syntax_errors_once() {
    let data = b"{\"a\": [1, 2, {\"b\": null}]} [3] x";
    let mut pos = 0;
    let mut d = Decoder::new(FnReader(move |out: &mut [u8]| {
        let n = out.len().min(1).min(data.len() - pos);
        out[..n].copy_from_slice(&data[pos..pos + n]);
        pos += n;
        Ok(n)
    }));
    let a: Value = d.decode().unwrap();
    assert_eq!(s(&marshal(&a).unwrap()), r#"{"a":[1,2,{"b":null}]}"#);
    let b: Value = d.decode().unwrap();
    assert_eq!(s(&marshal(&b).unwrap()), "[3]");
    let e = d.decode::<Value>().unwrap_err();
    assert_eq!(
        e.to_string(),
        "invalid character 'x' looking for beginning of value"
    );
    // Errors are sticky.
    assert_eq!(
        d.decode::<Value>().unwrap_err().to_string(),
        "invalid character 'x' looking for beginning of value"
    );
    assert_eq!(
        d.token().unwrap_err().to_string(),
        "invalid character 'x' looking for beginning of value"
    );
}

#[test]
fn decoder_reports_io_errors_unwrapped() {
    let mut first = true;
    let mut d = Decoder::new(FnReader(move |out: &mut [u8]| {
        if first {
            first = false;
            out[..2].copy_from_slice(b"[1");
            Ok(2)
        } else {
            Err(io::Error::new(io::ErrorKind::ConnectionReset, "reset"))
        }
    }));
    let e = d.decode::<Value>().unwrap_err();
    assert!(
        matches!(&e, Error::Io(io) if io.kind() == io::ErrorKind::ConnectionReset),
        "{e}"
    );
}

#[test]
fn encoder_writes_values_with_newlines_indent_and_escaping() {
    let mut buf = Vec::new();
    {
        let mut enc = Encoder::new(&mut buf);
        enc.set_indent(">", ".");
        enc.set_indent("", "");
        enc.encode(&0.1f64).unwrap();
        enc.encode("hello").unwrap();
        enc.encode(&vec![Some(1), None]).unwrap();
    }
    assert_eq!(s(&buf), "0.1\n\"hello\"\n[1,null]\n");

    let mut buf = Vec::new();
    {
        let mut enc = Encoder::new(&mut buf);
        enc.set_indent(">", ".");
        enc.encode(&vec!["a", "b"]).unwrap();
        let mut m = BTreeMap::new();
        m.insert("K".to_string(), 1);
        m.insert("a".to_string(), 2);
        enc.encode(&m).unwrap();
        enc.encode(&2.75f64).unwrap();
    }
    assert_eq!(
        s(&buf),
        "[\n>.\"a\",\n>.\"b\"\n>]\n{\n>.\"K\": 1,\n>.\"a\": 2\n>}\n2.75\n"
    );

    let mut buf = Vec::new();
    {
        let mut enc = Encoder::new(&mut buf);
        enc.encode("<&>").unwrap();
        enc.set_escape_html(false);
        enc.encode("<&>").unwrap();
    }
    assert_eq!(s(&buf), "\"\\u003c\\u0026\\u003e\"\n\"<&>\"\n");

    // A failed encode writes nothing and does not poison the encoder.
    let mut buf = Vec::new();
    let mut enc = Encoder::new(&mut buf);
    assert!(enc.encode(&f64::NAN).is_err());
    enc.encode(&1).unwrap();
    assert_eq!(s(&buf), "1\n");

    // Write errors are sticky.
    struct Broken;
    impl io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("closed"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut enc = Encoder::new(Broken);
    assert!(enc.encode(&1).is_err());
    assert_eq!(enc.encode(&2).unwrap_err().to_string(), "closed");
}

#[test]
fn options_combine_with_later_settings_winning() {
    let v1 = default_options_v1();
    let off = json::omit_empty_with_legacy_semantics(false);
    assert_ne!(v1, v1.join(off));
    assert_eq!(
        v1.join(off)
            .join(json::omit_empty_with_legacy_semantics(true)),
        v1
    );
    assert_eq!(json::Options::default().join(v1), v1);
    // The array option changes decoding of fixed-size arrays.
    let strict = json::unmarshal_array_from_any_length(false);
    assert_eq!(
        json::unmarshal_with_options::<[u8; 2]>(b"[1,2]", strict).unwrap(),
        [1, 2]
    );
    assert_eq!(
        json::unmarshal_with_options::<[u8; 2]>(b"[1]", strict)
            .unwrap_err()
            .to_string(),
        "json: cannot unmarshal array into Go value of type [2]uint8: too few array elements"
    );
    assert_eq!(
        json::unmarshal_with_options::<[u8; 2]>(b"[1,2,3]", strict)
            .unwrap_err()
            .to_string(),
        "json: cannot unmarshal array into Go value of type [2]uint8: too many array elements"
    );
    assert_eq!(
        s(&json::marshal_with_options(&[1, 2], json::Options::default()).unwrap()),
        "[1,2]"
    );
}

#[test]
fn duration_has_no_form_under_format_duration_as_nano_false() {
    let off = json::format_duration_as_nano(false);
    let d = std::time::Duration::from_nanos(5);
    assert_eq!(s(&json::marshal(&d).unwrap()), "5");
    assert_eq!(
        json::marshal_with_options(&d, off).unwrap_err().to_string(),
        "json: unsupported value: no default representation"
    );
    assert_eq!(
        json::unmarshal_with_options::<std::time::Duration>(b"5", off)
            .unwrap_err()
            .to_string(),
        "json: cannot unmarshal number into Go value of type time.Duration: no default representation"
    );
    assert_eq!(
        json::unmarshal_with_options::<std::time::Duration>(b"\"1s\"", off)
            .unwrap_err()
            .to_string(),
        "json: cannot unmarshal string into Go value of type time.Duration: no default representation"
    );
    assert_eq!(
        json::unmarshal_with_options::<std::time::Duration>(b"5", default_options_v1()).unwrap(),
        d
    );
}

#[test]
fn bytes_options_change_base64_and_array_decoding() {
    use json::Bytes;
    let loose =
        json::unmarshal_with_options::<Bytes>(br#""aG\nk=""#, default_options_v1()).unwrap();
    assert_eq!(loose.0, b"hi");
    let strict = json::parse_bytes_with_loose_rfc4648(false);
    assert_eq!(
        json::unmarshal_with_options::<Bytes>(br#""aG\nk=""#, strict)
            .unwrap_err()
            .to_string(),
        "json: cannot unmarshal string into Go value of type []uint8: illegal character '\\n' at offset 2"
    );
    assert_eq!(
        json::unmarshal_with_options::<Bytes>(b"[1,2]", default_options_v1())
            .unwrap()
            .0,
        [1, 2]
    );
    assert_eq!(
        json::unmarshal_with_options::<Bytes>(
            b"[1,2]",
            json::format_bytes_with_legacy_semantics(false)
        )
        .unwrap_err()
        .to_string(),
        "json: cannot unmarshal array into Go value of type []uint8"
    );
}

#[test]
fn value_display_is_total() {
    // An invalid Number cannot be built, so a Value always formats.
    assert!(Number::new("junk").is_err());
    let v = Value::Array(vec![
        Value::Number(Number::new("7").unwrap()),
        Value::Object([("k".to_string(), Value::Number(Number::new("0").unwrap()))].into()),
    ]);
    assert_eq!(v.to_string(), r#"[7,{"k":0}]"#);
    assert_eq!(s(&marshal(&v).unwrap()), r#"[7,{"k":0}]"#);
}

#[test]
fn go_duration_is_signed_nanoseconds() {
    use rust_stdlib::time::{Duration, SECOND};
    assert_eq!(s(&marshal(&(-2 * SECOND)).unwrap()), "-2000000000");
    assert_eq!(
        unmarshal::<Duration>(b"-5").unwrap(),
        Duration::from_nanos(-5)
    );
    assert_eq!(
        unmarshal::<Duration>(b"null").unwrap(),
        Duration::from_nanos(0)
    );
}

#[test]
fn value_objects_keep_insertion_order() {
    // Decoding into a Value sorts, as Go's map[string]any marshals.
    let v: Value = r#"{"b":1,"a":{"z":0,"y":[{"d":1,"c":2}]},"b":3}"#.parse().unwrap();
    assert_eq!(v.to_string(), r#"{"a":{"y":[{"c":2,"d":1}],"z":0},"b":3}"#);
    // Built objects keep the order they were given.
    let built = Value::object([("b", Value::from(1)), ("a", Value::from(2))]);
    assert_eq!(built.to_string(), r#"{"b":1,"a":2}"#);
    assert_eq!(s(&marshal(&built).unwrap()), r#"{"b":1,"a":2}"#);
    // Equality ignores the order, as Go's DeepEqual does for maps.
    assert_eq!(built, r#"{"a":2,"b":1}"#.parse::<Value>().unwrap());
    // Map keys sort; Rust maps become sorted objects.
    let m: HashMap<String, i32> = [("y".into(), 1), ("x".into(), 2)].into();
    assert_eq!(
        json::Serialize::to_json(&m).unwrap().to_string(),
        r#"{"x":2,"y":1}"#
    );
}

#[test]
fn map_insert_replaces_in_place() {
    let mut m = json::Map::new();
    assert_eq!(m.insert("b".into(), Value::from(1)), None);
    m.insert("a".into(), Value::from(2));
    assert_eq!(m.insert("b".into(), Value::from(3)), Some(Value::from(1)));
    assert_eq!(m.keys().collect::<Vec<_>>(), ["b", "a"]);
    assert_eq!(m.get("a"), Some(&Value::from(2)));
    assert_eq!(m.remove("b"), Some(Value::from(3)));
    assert_eq!(m.len(), 1);
    assert!(!m.contains_key("b"));
}

#[test]
fn unmarshal_into_follows_go_for_std_types() {
    use json::unmarshal_into;
    // Scalars are replaced, and null leaves them alone.
    let mut n = 5i64;
    unmarshal_into(b"7", &mut n).unwrap();
    assert_eq!(n, 7);
    unmarshal_into(b"null", &mut n).unwrap();
    assert_eq!(n, 7);
    let mut text = String::from("keep");
    unmarshal_into(b"null", &mut text).unwrap();
    assert_eq!(text, "keep");
    // A type error leaves the value as it was.
    assert!(unmarshal_into(b"\"x\"", &mut n).is_err());
    assert_eq!(n, 7);
    // Maps keep their other entries; null empties them.
    let mut m: BTreeMap<String, i64> = [("a".into(), 1), ("b".into(), 2)].into();
    unmarshal_into(br#"{"b":3,"c":4}"#, &mut m).unwrap();
    assert_eq!(
        m,
        [("a".into(), 1), ("b".into(), 3), ("c".into(), 4)].into()
    );
    unmarshal_into(b"null", &mut m).unwrap();
    assert!(m.is_empty());
    // Vec is resized, an array is zero-filled, null empties a Vec but not an array.
    let mut v = vec![1i64, 2, 3];
    unmarshal_into(b"[9]", &mut v).unwrap();
    assert_eq!(v, [9]);
    let mut arr = [7i64, 8, 9];
    unmarshal_into(b"[1]", &mut arr).unwrap();
    assert_eq!(arr, [1, 0, 0]);
    unmarshal_into(b"null", &mut arr).unwrap();
    assert_eq!(arr, [1, 0, 0]);
    unmarshal_into(b"null", &mut v).unwrap();
    assert!(v.is_empty());
    // Options are allocated, merged into, or cleared.
    let mut o: Option<i64> = None;
    unmarshal_into(b"3", &mut o).unwrap();
    assert_eq!(o, Some(3));
    unmarshal_into(b"null", &mut o).unwrap();
    assert_eq!(o, None);
    // Syntax errors leave everything untouched.
    let mut m: BTreeMap<String, i64> = [("a".into(), 1)].into();
    assert!(unmarshal_into(br#"{"a":2"#, &mut m).is_err());
    assert_eq!(m["a"], 1);
    // A Decoder merges successive values.
    let mut dec = Decoder::new(io::Cursor::new(&br#"{"a":2} {"z":3}"#[..]));
    dec.decode_into(&mut m).unwrap();
    dec.decode_into(&mut m).unwrap();
    assert_eq!(m, [("a".into(), 2), ("z".into(), 3)].into());
}

#[derive(Debug)]
struct Boom(u8);
impl std::fmt::Display for Boom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "boom {}", self.0)
    }
}
impl std::error::Error for Boom {}

#[derive(Debug)]
struct Even(i64);
impl json::Deserialize for Even {
    fn from_json(v: &json::Value) -> Result<Self, Error> {
        let n = i64::from_json(v)?;
        if n % 2 != 0 {
            return Err(Error::custom_source(Boom(n as u8)));
        }
        Ok(Even(n))
    }
}

#[test]
fn custom_errors_from_user_impls() {
    let e = Error::custom(format_args!("bad {}", 7));
    assert_eq!(e.to_string(), "bad 7");
    assert_eq!(Error::from("x").to_string(), "x");
    assert_eq!(Error::from(String::from("y")).to_string(), "y");
    let e = json::unmarshal::<Even>(b"3").unwrap_err();
    assert_eq!(e.to_string(), "boom 3");
    assert_eq!(e.downcast_ref::<Boom>().unwrap().0, 3);
    assert_eq!(json::unmarshal::<Even>(b"4").unwrap().0, 4);
}
