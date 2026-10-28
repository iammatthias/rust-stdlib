//! Tests for `rust_stdlib::strconv`, ported from Go's `strconv` and
//! `internal/strconv` test tables. The large tables are extracted by
//! `tools/strconv_fixtures.py` into `tests/fixtures/strconv`.
use rust_stdlib::strconv::{self, Complex, Error, NumError, ERR_RANGE, ERR_SYNTAX};

/// Go's `(value, error)` pair: the value that comes with an error.
fn pair<T>(r: Result<T, NumError>, partial: impl FnOnce(&NumError) -> T) -> (T, Option<NumError>) {
    match r {
        Ok(v) => (v, None),
        Err(e) => (partial(&e), Some(e)),
    }
}

fn unhex(s: &str) -> String {
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    String::from_utf8(bytes).unwrap()
}

fn err_of(name: &str) -> Option<Error> {
    match name {
        "nil" => None,
        "ErrSyntax" => Some(ERR_SYNTAX),
        "ErrRange" => Some(ERR_RANGE),
        other => panic!("unknown error {other}"),
    }
}

#[test]
fn integer_tables() {
    let cases = include_str!("fixtures/strconv/int_cases.txt");
    let mut n = 0;
    for line in cases.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        let (input, base, bits) = (unhex(f[1]), f[2].parse().unwrap(), f[3].parse().unwrap());
        let want_err = err_of(f[5]);
        if f[0] == "U" {
            let want: u64 = f[4].parse().unwrap();
            let (v, e) = pair(strconv::parse_uint(&input, base, bits), |e| e.uint_value());
            assert_eq!(
                (v, e.map(|e| e.err)),
                (want, want_err),
                "ParseUint({input:?}, {base}, {bits})"
            );
        } else {
            let want: i64 = f[4].parse().unwrap();
            let (v, e) = pair(strconv::parse_int(&input, base, bits), |e| e.int_value());
            assert_eq!(
                (v, e.map(|e| e.err)),
                (want, want_err),
                "ParseInt({input:?}, {base}, {bits})"
            );
        }
        n += 1;
    }
    assert!(n > 200, "only {n} integer cases");
}

#[test]
fn atoi_matches_parse_int() {
    for (s, want) in [
        ("0", 0isize),
        ("-1", -1),
        ("+12345", 12345),
        ("9223372036854775807", isize::MAX),
    ] {
        assert_eq!(strconv::atoi(s).unwrap(), want);
    }
    let e = strconv::atoi("12x").unwrap_err();
    assert_eq!(
        e.to_string(),
        "strconv.Atoi: parsing \"12x\": invalid syntax"
    );
    assert_eq!(
        pair(strconv::atoi("9223372036854775808"), |e| e.int_value()
            as isize),
        (isize::MAX, strconv::atoi("9223372036854775808").err())
    );
    assert_eq!(
        strconv::atoi("-9223372036854775809").unwrap_err().err,
        ERR_RANGE
    );
}

#[test]
fn bit_size_and_base_errors() {
    for (bits, bad) in [(-1, true), (0, false), (64, false), (65, true)] {
        let e = strconv::parse_int("1", 10, bits).err();
        assert_eq!(
            e.map(|e| e.err),
            bad.then_some(Error::InvalidBitSize(bits)),
            "bit size {bits}"
        );
        assert_eq!(strconv::parse_uint("1", 10, bits).is_err(), bad);
    }
    for (base, bad) in [
        (-1, true),
        (0, false),
        (1, true),
        (2, false),
        (36, false),
        (37, true),
    ] {
        let e = strconv::parse_int("1", base, 64).err();
        assert_eq!(
            e.map(|e| e.err),
            bad.then_some(Error::InvalidBase(base)),
            "base {base}"
        );
    }
    assert_eq!(
        strconv::parse_int("1", 37, 0).unwrap_err().to_string(),
        "strconv.ParseInt: parsing \"1\": invalid base 37"
    );
    assert_eq!(
        strconv::parse_uint("1", 10, 65).unwrap_err().to_string(),
        "strconv.ParseUint: parsing \"1\": invalid bit size 65"
    );
}

#[test]
fn num_error_display_and_source() {
    use std::error::Error as _;
    let e = strconv::parse_float("1\u{0}.2", 64).unwrap_err();
    assert_eq!(e.func, "ParseFloat");
    assert_eq!(e.num, "1\u{0}.2");
    assert_eq!(e.err, ERR_SYNTAX);
    assert_eq!(
        e.to_string(),
        "strconv.ParseFloat: parsing \"1\\x00.2\": invalid syntax"
    );
    assert_eq!(e.source().unwrap().to_string(), "invalid syntax");
    assert_eq!(ERR_RANGE.to_string(), "value out of range");
}

#[test]
fn bool_tables() {
    for s in ["1", "t", "T", "true", "TRUE", "True"] {
        assert_eq!(strconv::parse_bool(s), Ok(true));
    }
    for s in ["0", "f", "F", "false", "FALSE", "False"] {
        assert_eq!(strconv::parse_bool(s), Ok(false));
    }
    for s in ["", "asdf", "0.0", "tRUE", " true"] {
        assert_eq!(strconv::parse_bool(s).unwrap_err().err, ERR_SYNTAX);
    }
}

#[test]
fn format_int_bases() {
    assert_eq!(
        strconv::format_int(-1 << 63, 2),
        format!("-1{}", "0".repeat(63))
    );
    assert_eq!(strconv::format_int(i64::MIN, 10), "-9223372036854775808");
    assert_eq!(strconv::format_int(i64::MAX, 36), "1y2p0ij32e8e7");
    assert_eq!(strconv::format_uint(u64::MAX, 16), "ffffffffffffffff");
    assert_eq!(strconv::format_uint(u64::MAX, 2).len(), 64);
    assert_eq!(strconv::format_int(-255, 16), "-ff");
    let mut v = b"abc".to_vec();
    strconv::append_uint(&mut v, 35, 36);
    assert_eq!(v, b"abcz");
}

#[test]
#[should_panic(expected = "illegal AppendInt/FormatInt base")]
fn format_int_bad_base_panics() {
    strconv::format_int(1, 37);
}

#[test]
fn atof_tables() {
    let cases = include_str!("fixtures/strconv/atof_cases.txt");
    let mut n = 0;
    for line in cases.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        let bits: i32 = f[0].parse().unwrap();
        let (input, want) = (unhex(f[1]), unhex(f[2]));
        let (v, e) = pair(strconv::parse_float(&input, bits), |e| e.float_value());
        let got = strconv::format_float(v, b'g', -1, bits);
        assert_eq!(
            (got.as_str(), e.map(|e| e.err)),
            (want.as_str(), err_of(f[3])),
            "ParseFloat({input:?}, {bits})"
        );
        n += 1;
    }
    assert!(n > 250, "only {n} atof cases");
}

#[test]
fn ftoa_table() {
    let cases = include_str!("fixtures/strconv/ftoa_cases.txt");
    let mut n = 0;
    for line in cases.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        let v = strconv::parse_float(f[0], 64).unwrap();
        let got = strconv::format_float(v, f[1].as_bytes()[0], f[2].parse().unwrap(), 64);
        assert_eq!(got, f[3], "FormatFloat({}, {:?}, {})", f[0], f[1], f[2]);
        n += 1;
    }
    assert!(n > 100, "only {n} ftoa cases");
}

#[test]
fn format_float_edges() {
    let f = strconv::format_float;
    assert_eq!(f(f64::INFINITY, b'e', 2, 64), "+Inf");
    assert_eq!(f(f64::NEG_INFINITY, b'g', -1, 32), "-Inf");
    assert_eq!(f(f64::NAN, b'f', 3, 64), "NaN");
    assert_eq!(f(-0.0, b'g', -1, 64), "-0");
    assert_eq!(f(0.0, b'e', 3, 64), "0.000e+00");
    assert_eq!(f(1.0, b'z', 3, 64), "%z");
    assert_eq!(f(1e23, b'g', -1, 64), "1e+23");
    assert_eq!(f(5e-324, b'g', -1, 64), "5e-324");
    assert_eq!(f(f64::MAX, b'g', -1, 64), "1.7976931348623157e+308");
    assert_eq!(f(3.4028234663852886e38, b'g', -1, 32), "3.4028235e+38");
    assert_eq!(f(0.1, b'b', -1, 64), "7205759403792794p-56");
    assert_eq!(f(1.5, b'x', 3, 64), "0x1.800p+00");
    assert_eq!(f(255.0, b'X', -1, 64), "0X1.FEP+07");
    assert_eq!(f(2.5, b'f', 0, 64), "2");
    assert_eq!(
        f(1.0 / 3.0, b'f', 40, 64),
        "0.3333333333333333148296162562473909929395"
    );
}

#[test]
#[should_panic(expected = "bitSize")]
fn format_float_bad_bit_size_panics() {
    strconv::format_float(1.0, b'g', -1, 16);
}

#[test]
fn testbase_fp() {
    let data = include_str!("fixtures/strconv/testfp.txt");
    let mut n = 0;
    for line in data.lines() {
        let line = line.split('#').next().unwrap().trim();
        if line.is_empty() {
            continue;
        }
        let a: Vec<&str> = line.split(' ').collect();
        assert_eq!(a.len(), 4, "{line}");
        let bits = if a[0] == "float32" { 32 } else { 64 };
        let v = match a[2].split_once('p') {
            Some((m, e)) => {
                let m: i64 = m.parse().unwrap();
                let e: i32 = e.parse().unwrap();
                // m * 2**e without overflowing intermediate powers of two.
                let mut v = m as f64;
                let mut e = e;
                while e > 0 {
                    let step = e.min(500);
                    v *= 2f64.powi(step);
                    e -= step;
                }
                while e < 0 {
                    let step = (-e).min(500);
                    v /= 2f64.powi(step);
                    e += step;
                }
                if bits == 32 {
                    (v as f32) as f64
                } else {
                    v
                }
            }
            None => strconv::parse_float(a[2], bits).unwrap_or_else(|e| panic!("{line}: {e}")),
        };
        let got = if a[1] == "%b" {
            strconv::format_float(v, b'b', -1, bits)
        } else {
            let prec: i32 = a[1]
                .trim_start_matches("%.")
                .trim_end_matches('e')
                .parse()
                .unwrap();
            strconv::format_float(v, b'e', prec, bits)
        };
        // C's printf prints at least two exponent digits and a sign, like Go.
        assert_eq!(got, a[3], "{line}");
        n += 1;
    }
    assert!(n > 100, "only {n} testfp cases");
}

#[test]
fn testbase_samples_round_trip() {
    let atof = include_str!("fixtures/strconv/atof1k.txt");
    let ftoa = include_str!("fixtures/strconv/ftoa1k.txt");
    for line in atof.lines().chain(ftoa.lines()) {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        let v = strconv::parse_float(s, 64).unwrap_or_else(|e| panic!("{s}: {e}"));
        let shortest = strconv::format_float(v, b'g', -1, 64);
        assert_eq!(
            strconv::parse_float(&shortest, 64).unwrap().to_bits(),
            v.to_bits(),
            "{s}"
        );
        let e17 = strconv::format_float(v, b'e', 16, 64);
        assert_eq!(
            strconv::parse_float(&e17, 64).unwrap().to_bits(),
            v.to_bits(),
            "{s}"
        );
        for prec in 0..19 {
            let e = strconv::format_float(v, b'e', prec, 64);
            let digits = e
                .split('e')
                .next()
                .unwrap()
                .trim_start_matches('-')
                .replace('.', "");
            assert_eq!(digits.len(), prec as usize + 1, "{e}");
        }
    }
}

#[test]
fn parse_float_range_and_special() {
    let (v, e) = pair(strconv::parse_float("1e400", 64), |e| e.float_value());
    assert_eq!((v, e.unwrap().err), (f64::INFINITY, ERR_RANGE));
    let (v, e) = pair(strconv::parse_float("-1e400", 64), |e| e.float_value());
    assert_eq!((v, e.unwrap().err), (f64::NEG_INFINITY, ERR_RANGE));
    let (v, e) = pair(strconv::parse_float("3.5e38", 32), |e| e.float_value());
    assert_eq!((v, e.unwrap().err), (f64::INFINITY, ERR_RANGE));
    assert_eq!(strconv::parse_float("1e-400", 64), Ok(0.0));
    assert!(strconv::parse_float("nan", 64).unwrap().is_nan());
    assert_eq!(strconv::parse_float("-Infinity", 64), Ok(f64::NEG_INFINITY));
    assert_eq!(strconv::parse_float("1_000.5", 64), Ok(1000.5));
    assert_eq!(strconv::parse_float("0x1.8p1", 64), Ok(3.0));
    assert_eq!(strconv::parse_float("0x_1p0", 64), Ok(1.0));
    assert_eq!(strconv::parse_float("0x1", 64).unwrap_err().err, ERR_SYNTAX);
    assert_eq!(
        strconv::parse_float("1__0", 64).unwrap_err().err,
        ERR_SYNTAX
    );
}

#[test]
fn complex_round_trip() {
    let c = |re, im| Complex { re, im };
    assert_eq!(strconv::parse_complex("1+2i", 128), Ok(c(1.0, 2.0)));
    assert_eq!(strconv::parse_complex("(3-4.5i)", 128), Ok(c(3.0, -4.5)));
    assert_eq!(strconv::parse_complex("7", 128), Ok(c(7.0, 0.0)));
    assert_eq!(strconv::parse_complex("-2i", 64), Ok(c(0.0, -2.0)));
    assert_eq!(
        strconv::parse_complex("1 + 2i", 128).unwrap_err().err,
        ERR_SYNTAX
    );
    assert_eq!(
        strconv::parse_complex("1++2i", 128).unwrap_err().err,
        ERR_SYNTAX
    );
    let (v, e) = pair(strconv::parse_complex("1e400+2i", 128), |e| {
        e.complex_value()
    });
    assert_eq!(
        (v.re, v.im, e.unwrap().err),
        (f64::INFINITY, 2.0, ERR_RANGE)
    );
    assert_eq!(
        strconv::format_complex(c(1.0, 2.0), b'g', -1, 128),
        "(1+2i)"
    );
    assert_eq!(
        strconv::format_complex(c(1.5, -0.25), b'f', 2, 64),
        "(1.50-0.25i)"
    );
    assert_eq!(
        strconv::format_complex(c(0.0, f64::NAN), b'g', -1, 128),
        "(0+NaNi)"
    );
}

const QUOTE_TESTS: &[(&str, &str, &str, &str)] = &[
    (
        "\x07\x08\x0c\r\n\t\x0b",
        r#""\a\b\f\r\n\t\v""#,
        r#""\a\b\f\r\n\t\v""#,
        r#""\a\b\f\r\n\t\v""#,
    ),
    ("\\", r#""\\""#, r#""\\""#, r#""\\""#),
    (
        "abc\u{fffd}def",
        "\"abc\u{fffd}def\"",
        "\"abc\\ufffddef\"",
        "\"abc\u{fffd}def\"",
    ),
    ("\u{263a}", "\"\u{263a}\"", r#""\u263a""#, "\"\u{263a}\""),
    (
        "\u{10ffff}",
        r#""\U0010ffff""#,
        r#""\U0010ffff""#,
        r#""\U0010ffff""#,
    ),
    ("\x04", r#""\x04""#, r#""\x04""#, r#""\x04""#),
    (
        "!\u{a0}!\u{2000}!\u{3000}!",
        r#""!\u00a0!\u2000!\u3000!""#,
        r#""!\u00a0!\u2000!\u3000!""#,
        "\"!\u{a0}!\u{2000}!\u{3000}!\"",
    ),
    ("\x7f", r#""\x7f""#, r#""\x7f""#, r#""\x7f""#),
];

#[test]
fn quote_tables() {
    for (input, out, ascii, graphic) in QUOTE_TESTS {
        assert_eq!(strconv::quote(input), *out, "Quote({input:?})");
        assert_eq!(
            strconv::quote_to_ascii(input),
            *ascii,
            "QuoteToASCII({input:?})"
        );
        assert_eq!(
            strconv::quote_to_graphic(input),
            *graphic,
            "QuoteToGraphic({input:?})"
        );
        let mut buf = b"abc".to_vec();
        strconv::append_quote(&mut buf, input);
        assert_eq!(buf, format!("abc{out}").as_bytes());
        let mut buf = b"abc".to_vec();
        strconv::append_quote_to_ascii(&mut buf, input);
        assert_eq!(buf, format!("abc{ascii}").as_bytes());
        let mut buf = b"abc".to_vec();
        strconv::append_quote_to_graphic(&mut buf, input);
        assert_eq!(buf, format!("abc{graphic}").as_bytes());
    }
}

#[test]
fn quote_invalid_utf8_bytes() {
    assert_eq!(strconv::quote(b"abc\xffdef"), r#""abc\xffdef""#);
    assert_eq!(
        strconv::quote_to_ascii(b"\xed\xa0\x80"),
        r#""\xed\xa0\x80""#
    );
    assert_eq!(strconv::quote(b"\xf4\x90\x80\x80"), r#""\xf4\x90\x80\x80""#);
}

#[test]
fn quote_rune_tables() {
    let cases: &[(i32, &str, &str, &str)] = &[
        ('a' as i32, "'a'", "'a'", "'a'"),
        (7, r"'\a'", r"'\a'", r"'\a'"),
        ('\\' as i32, r"'\\'", r"'\\'", r"'\\'"),
        (0xFF, "'\u{ff}'", r"'\u00ff'", "'\u{ff}'"),
        (0x263a, "'\u{263a}'", r"'\u263a'", "'\u{263a}'"),
        (0xdead, "'\u{fffd}'", r"'\ufffd'", "'\u{fffd}'"),
        (0xfffd, "'\u{fffd}'", r"'\ufffd'", "'\u{fffd}'"),
        (0x10ffff, r"'\U0010ffff'", r"'\U0010ffff'", r"'\U0010ffff'"),
        (0x110000, "'\u{fffd}'", r"'\ufffd'", "'\u{fffd}'"),
        (4, r"'\x04'", r"'\x04'", r"'\x04'"),
        (0xa0, r"'\u00a0'", r"'\u00a0'", "'\u{a0}'"),
        (0x2000, r"'\u2000'", r"'\u2000'", "'\u{2000}'"),
        (0x3000, r"'\u3000'", r"'\u3000'", "'\u{3000}'"),
        (-1, "'\u{fffd}'", r"'\ufffd'", "'\u{fffd}'"),
    ];
    for &(r, out, ascii, graphic) in cases {
        assert_eq!(strconv::quote_rune(r), out, "QuoteRune({r:#x})");
        assert_eq!(
            strconv::quote_rune_to_ascii(r),
            ascii,
            "QuoteRuneToASCII({r:#x})"
        );
        assert_eq!(
            strconv::quote_rune_to_graphic(r),
            graphic,
            "QuoteRuneToGraphic({r:#x})"
        );
        let mut buf = b"abc".to_vec();
        strconv::append_quote_rune(&mut buf, r);
        assert_eq!(buf, format!("abc{out}").as_bytes());
    }
    assert_eq!(strconv::quote_rune('\u{263a}'), "'\u{263a}'");
}

#[test]
fn can_backquote_tables() {
    for r in 0u8..32 {
        assert_eq!(strconv::can_backquote([r]), r == b'\t', "{r}");
    }
    assert!(!strconv::can_backquote("\u{7f}"));
    assert!(!strconv::can_backquote("`"));
    assert!(strconv::can_backquote(
        r##"' !"#$%&'()*+,-./:;<=>?@[\]^_{|}~"##
    ));
    assert!(strconv::can_backquote("\u{263a}"));
    assert!(!strconv::can_backquote(b"\x80"));
    assert!(!strconv::can_backquote(b"a\xe0\xa0z"));
    assert!(!strconv::can_backquote("\u{feff}abc"));
    assert!(!strconv::can_backquote("a\u{feff}z"));
}

fn check_unquote(input: &[u8], want: &[u8], want_err: Option<Error>) {
    let got = strconv::unquote(input);
    match (&got, want_err) {
        (Ok(v), None) => assert_eq!(v, want, "Unquote({input:?})"),
        (Err(e), Some(w)) => assert_eq!(*e, w, "Unquote({input:?})"),
        _ => panic!("Unquote({input:?}) = {got:?}, want ({want:?}, {want_err:?})"),
    }
    // Adding a suffix of special characters must not change QuotedPrefix.
    let mut suffix = b"\n\r\\\"`'".to_vec();
    if let Some(first) = input.first() {
        suffix.retain(|c| c != first);
    }
    let mut extended = input.to_vec();
    extended.extend_from_slice(&suffix);
    let prefix = strconv::quoted_prefix(&extended[..]);
    match (got.is_ok(), prefix) {
        (true, Ok(p)) => assert_eq!(p, input, "QuotedPrefix({extended:?})"),
        (false, Ok(p)) => assert!(
            strconv::unquote(p).is_ok(),
            "QuotedPrefix({extended:?}) = {p:?}"
        ),
        (_, Err(e)) => assert_eq!(
            Some(e),
            want_err.or(Some(ERR_SYNTAX)),
            "QuotedPrefix({extended:?})"
        ),
    }
}

#[test]
fn unquote_tables() {
    let ok: &[(&str, &str)] = &[
        (r#""""#, ""),
        (r#""a""#, "a"),
        (r#""abc""#, "abc"),
        ("\"\u{263a}\"", "\u{263a}"),
        (r#""hello world""#, "hello world"),
        (r#""\u1234""#, "\u{1234}"),
        (r#""\U00010111""#, "\u{10111}"),
        (r#""\U0001011111""#, "\u{10111}11"),
        (r#""\a\b\f\n\r\t\v\\\"""#, "\x07\x08\x0c\n\r\t\x0b\\\""),
        (r#""'""#, "'"),
        ("'a'", "a"),
        ("'\u{2639}'", "\u{2639}"),
        (r"'\a'", "\x07"),
        (r"'\x10'", "\x10"),
        (r"'\u1234'", "\u{1234}"),
        (r"'\t'", "\t"),
        ("' '", " "),
        (r"'\''", "'"),
        (r#"'"'"#, "\""),
        ("''", ""),
        ("``", ""),
        ("`a`", "a"),
        ("`\\xFF`", "\\xFF"),
        ("`\\`", "\\"),
        ("`\n`", "\n"),
        ("`a\rb`", "ab"),
    ];
    for (input, want) in ok {
        check_unquote(input.as_bytes(), want.as_bytes(), None);
    }
    check_unquote(br#""\xFF""#, b"\xff", None);
    check_unquote(br#""\377""#, b"\xff", None);
    check_unquote(br"'\377'", b"\xff", None);
    for (input, out, _, _) in QUOTE_TESTS {
        check_unquote(out.as_bytes(), input.as_bytes(), None);
    }
    let bad: &[&str] = &[
        "",
        "\"",
        "\"a",
        "\"'",
        "b\"",
        r#""\""#,
        r#""\9""#,
        r#""\19""#,
        r#""\129""#,
        r"'\'",
        r"'\9'",
        r"'\19'",
        r"'\129'",
        "'ab'",
        r#""\x1!""#,
        r#""\U12345678""#,
        r#""\z""#,
        "`",
        "`xxx",
        "``x\r",
        "`\"",
        r#""\'""#,
        r#"'\"'"#,
        "\"\n\"",
        "\"\\n\n\"",
        "'\n'",
        r#""\udead""#,
        r#""\ud83d\ude4f""#,
    ];
    for input in bad {
        check_unquote(input.as_bytes(), b"", Some(ERR_SYNTAX));
    }
    // Invalid UTF-8 must not take the fast path (Go issue 23685).
    check_unquote(b"\"\xc0\"", "\u{fffd}".as_bytes(), None);
    check_unquote(b"\"a\xc0\"", "a\u{fffd}".as_bytes(), None);
    check_unquote(b"\"\\t\xc0\"", "\t\u{fffd}".as_bytes(), None);
    check_unquote(br#""foo"#, b"", Some(ERR_SYNTAX));
}

#[test]
fn unquote_char_cases() {
    assert_eq!(
        strconv::unquote_char(b"abc", b'"'),
        Ok((b'a' as u32, false, &b"bc"[..]))
    );
    assert_eq!(
        strconv::unquote_char("\u{263a}x".as_bytes(), b'"'),
        Ok((0x263a, true, &b"x"[..]))
    );
    assert_eq!(
        strconv::unquote_char(br"\x41rest", b'"'),
        Ok((0x41, false, &b"rest"[..]))
    );
    assert_eq!(
        strconv::unquote_char(br"\xffrest", b'"'),
        Ok((0xff, false, &b"rest"[..]))
    );
    assert_eq!(
        strconv::unquote_char(br"\u00e9", b'"'),
        Ok((0xe9, true, &b""[..]))
    );
    assert_eq!(
        strconv::unquote_char(br"\'", b'\''),
        Ok((b'\'' as u32, false, &b""[..]))
    );
    assert_eq!(strconv::unquote_char(br"\'", b'"'), Err(ERR_SYNTAX));
    assert_eq!(strconv::unquote_char(br"\'", 0), Err(ERR_SYNTAX));
    assert_eq!(
        strconv::unquote_char(b"'", 0),
        Ok((b'\'' as u32, false, &b""[..]))
    );
    assert_eq!(strconv::unquote_char(b"\"", b'"'), Err(ERR_SYNTAX));
    assert_eq!(strconv::unquote_char(br"\400", b'"'), Err(ERR_SYNTAX));
    assert_eq!(strconv::unquote_char(br"\ud800", b'"'), Err(ERR_SYNTAX));
    assert_eq!(strconv::unquote_char(b"", b'"'), Err(ERR_SYNTAX));
}

#[test]
fn is_print_and_graphic() {
    for r in 0x20..0x7f {
        assert!(strconv::is_print(r) && strconv::is_graphic(r));
    }
    for r in [0, 0x1f, 0x7f, 0x80, 0x9f, 0xad, 0x2028, 0x110000, -1] {
        assert!(!strconv::is_print(r), "{r:#x}");
    }
    assert!(
        strconv::is_print('\u{00e9}')
            && strconv::is_print('\u{263a}')
            && strconv::is_print('\u{1f600}')
    );
    assert!(!strconv::is_print('\u{00a0}') && strconv::is_graphic('\u{00a0}'));
    assert!(!strconv::is_print('\u{3000}') && strconv::is_graphic('\u{3000}'));
    assert!(!strconv::is_graphic('\u{2028}'));
    assert!(!strconv::is_graphic('\u{0007}'));
}

#[test]
fn int_size() {
    assert_eq!(strconv::INT_SIZE, usize::BITS as usize);
}

#[test]
fn format_float_precision_beyond_core_fmt_limit() {
    // core::fmt caps precision at 65535; Go prints any number of digits and a
    // double's exact expansion ends long before that.
    let f = strconv::format_float(0.5, b'f', 70000, 64);
    assert_eq!(f.len(), 2 + 70000);
    assert!(f.starts_with("0.5") && f[3..].bytes().all(|c| c == b'0'));
    let e = strconv::format_float(1.0, b'e', 70000, 64);
    assert_eq!(e.len(), 2 + 70000 + 4);
    assert!(e.starts_with("1.0") && e.ends_with("e+00"));
    let g = strconv::format_float(0.000123, b'f', 1200, 64);
    assert_eq!(g.len(), 2 + 1200);
}
