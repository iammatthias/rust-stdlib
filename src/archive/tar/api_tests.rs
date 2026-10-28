//! Tables ported from Go's `archive/tar` `strconv_test.go`, `tar_test.go` and
//! `writer_test.go` (BSD-licensed, see NOTICE) for the unexported helpers.
use super::header::*;
use super::sparse::*;
use super::strconv::*;
use super::Error;
use crate::archive::iofs::{time_parts, time_unix, time_zero};
use std::collections::BTreeMap;

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn fits_in_base256_table() {
    for (x, width, ok) in [
        (1i64, 8usize, true),
        (0, 8, true),
        (-1, 8, true),
        (1 << 56, 8, false),
        ((1 << 56) - 1, 8, true),
        (-1 << 56, 8, true),
        ((-1 << 56) - 1, 8, false),
        (121654, 8, true),
        (-9849849, 8, true),
        (i64::MAX, 9, true),
        (0, 9, true),
        (i64::MIN, 9, true),
        (i64::MAX, 12, true),
        (i64::MIN, 12, true),
    ] {
        assert_eq!(fits_in_base256(width, x), ok, "{x} in {width}");
    }
}

#[test]
fn parse_numeric_table() {
    let vectors: &[(&[u8], i64, bool)] = &[
        (b"", 0, true),
        (b"\x80", 0, true),
        (b"\x80\x00", 0, true),
        (b"\xbf", (1 << 6) - 1, true),
        (b"\xbf\xff", (1 << 14) - 1, true),
        (b"\xbf\xff\xff", (1 << 22) - 1, true),
        (b"\xff", -1, true),
        (b"\xff\xff\xff", -1, true),
        (b"\xc0", -(1 << 6), true),
        (b"\xc0\x00", -(1 << 14), true),
        (b"\xc0\x00\x00", -(1 << 22), true),
        (
            b"\x87\x76\xa2\x22\xeb\x8a\x72\x61",
            537795476381659745,
            true,
        ),
        (
            b"\x80\x00\x00\x00\x07\x76\xa2\x22\xeb\x8a\x72\x61",
            537795476381659745,
            true,
        ),
        (
            b"\xf7\x76\xa2\x22\xeb\x8a\x72\x61",
            -615126028225187231,
            true,
        ),
        (
            b"\xff\xff\xff\xff\xf7\x76\xa2\x22\xeb\x8a\x72\x61",
            -615126028225187231,
            true,
        ),
        (b"\x80\x7f\xff\xff\xff\xff\xff\xff\xff", i64::MAX, true),
        (b"\x80\x80\x00\x00\x00\x00\x00\x00\x00", 0, false),
        (b"\xff\x80\x00\x00\x00\x00\x00\x00\x00", i64::MIN, true),
        (b"\xff\x7f\xff\xff\xff\xff\xff\xff\xff", 0, false),
        (
            b"\xf5\xec\xd1\xc7\x7e\x5f\x26\x48\x81\x9f\x8f\x9b",
            0,
            false,
        ),
        (b"0000000\x00", 0, true),
        (b" \x0000000\x00", 0, true),
        (b" \x0000003\x00", 3, true),
        (b"00000000227\x00", 0o227, true),
        (b"032033\x00 ", 0o32033, true),
        (b"320330\x00 ", 0o320330, true),
        (b"0000660\x00 ", 0o660, true),
        (b"\x00 0000660\x00 ", 0o660, true),
        (b"0123456789abcdef", 0, false),
        (b"0123456789\x00abcdef", 0, false),
        (b"01234567\x0089abcdef", 342391, true),
        (b"0123\x7e\x5f\x264123", 0, false),
    ];
    for (input, want, ok) in vectors {
        let mut p = Parser::default();
        let got = p.numeric(input);
        assert_eq!(p.err.is_none(), *ok, "{input:?}");
        if *ok {
            assert_eq!(got, *want, "{input:?}");
        }
    }
}

#[test]
fn format_numeric_table() {
    let vectors: &[(i64, &[u8], bool)] = &[
        (0, b"0\x00", true),
        (7, b"7\x00", true),
        (8, b"\x80\x08", true),
        (0o77, b"77\x00", true),
        (0o100, b"\x80\x00\x40", true),
        (0, b"0000000\x00", true),
        (0o123, b"0000123\x00", true),
        (0o7654321, b"7654321\x00", true),
        (0o10000000, b"\x80\x00\x00\x00\x00\x20\x00\x00", true),
        (0o76543210321, b"76543210321\x00", true),
        (
            0o100000000000,
            b"\x80\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00",
            true,
        ),
        (i64::MAX, b"777777777777777777777\x00", true),
        (-1, b"\xff", true),
        (-1, b"\xff\xff\xff", true),
        (1, b"0", false),
        ((1 << 8) - 1, b"\x80\xff", true),
        (1 << 8, b"0\x00", false),
        (-(1 << 8), b"\xff\x00", true),
        (-(1 << 8) - 1, b"0\x00", false),
        (
            537795476381659745,
            b"\x80\x00\x00\x00\x07\x76\xa2\x22\xeb\x8a\x72\x61",
            true,
        ),
        (537795476381659745, b"0000000\x00", false),
        (
            -615126028225187231,
            b"\xff\xff\xff\xff\xf7\x76\xa2\x22\xeb\x8a\x72\x61",
            true,
        ),
        (
            i64::MAX,
            b"\x80\x00\x00\x00\x7f\xff\xff\xff\xff\xff\xff\xff",
            true,
        ),
        (
            i64::MIN,
            b"\xff\xff\xff\xff\x80\x00\x00\x00\x00\x00\x00\x00",
            true,
        ),
        (i64::MAX, b"\x80\x7f\xff\xff\xff\xff\xff\xff\xff", true),
        (i64::MIN, b"\xff\x80\x00\x00\x00\x00\x00\x00\x00", true),
    ];
    for (x, want, ok) in vectors {
        let mut f = Formatter::default();
        let mut got = vec![0u8; want.len()];
        f.numeric(&mut got, *x);
        assert_eq!(f.err.is_none(), *ok, "{x}");
        assert_eq!(&got[..], *want, "{x}");
    }
}

#[test]
fn fits_in_octal_table() {
    for (x, width, ok) in [
        (-1i64, 1usize, false),
        (0, 1, true),
        (1, 1, false),
        (0o7, 2, true),
        (0o10, 2, false),
        (0o777, 4, true),
        (0o1000, 4, false),
        (0o7777777, 8, true),
        (0o10000000, 8, false),
        (0o77777777777, 12, true),
        (0o100000000000, 12, false),
        (i64::MAX, 22, true),
        (-0o12345670123, 12, false),
        (-1564164, 30, false),
    ] {
        assert_eq!(fits_in_octal(width, x), ok, "{x} in {width}");
    }
}

#[test]
fn parse_pax_time_table() {
    let t = |s, n| Some((s, n));
    for (input, want) in [
        ("1350244992.023960108", t(1350244992, 23960108)),
        ("1350244992.02396010", t(1350244992, 23960100)),
        ("1350244992.0239601089", t(1350244992, 23960108)),
        ("1350244992.3", t(1350244992, 300000000)),
        ("1350244992", t(1350244992, 0)),
        ("-1.000000001", t(-2, 999999999)),
        ("-1.000001", t(-2, 999999000)),
        ("-1", t(-1, 0)),
        ("-1.999999999", t(-2, 1)),
        ("0.000000001", t(0, 1)),
        ("0.999999999", t(0, 999999999)),
        ("1.", t(1, 0)),
        ("0.0", t(0, 0)),
        ("-0.1", t(-1, 900000000)),
        ("-0.99", t(-1, 10000000)),
        ("-5.98", t(-6, 20000000)),
        ("-1350244992.3", t(-1350244993, 700000000)),
        ("", None),
        (".5", None),
        ("-", None),
        ("+", None),
        ("-1.-1", None),
        ("99999999999999999999999999999999999999999999999", None),
        ("0.123456789abcdef", None),
        ("foo", None),
        ("\x00", None),
        ("\u{1d7f5}\u{1d7f4}.0", None),
        ("98765\u{fe52}43210", None),
    ] {
        match (parse_pax_time(input), want) {
            (Ok(got), Some(want)) => assert_eq!(time_parts(&got), want, "{input:?}"),
            (Err(Error::Header), None) => {}
            (got, want) => panic!("{input:?}: got {got:?}, want {want:?}"),
        }
    }
}

#[test]
fn format_pax_time_table() {
    for (secs, nanos, want) in [
        (1350244992i64, 0i64, "1350244992"),
        (1350244992, 300000000, "1350244992.3"),
        (1350244992, 23960100, "1350244992.0239601"),
        (1350244992, 23960108, "1350244992.023960108"),
        (1, 999999999, "1.999999999"),
        (1, 999999000, "1.999999"),
        (1, 0, "1"),
        (1, 1000000, "1.001"),
        (1, 1, "1.000000001"),
        (0, 999999999, "0.999999999"),
        (0, 0, "0"),
        (0, 1, "0.000000001"),
        (-1, -999999999, "-1.999999999"),
        (-1, -1000000, "-1.001"),
        (-1, -1, "-1.000000001"),
        (-1350244992, 0, "-1350244992"),
        (-1350244992, -300000000, "-1350244992.3"),
        (-1350244992, -23960108, "-1350244992.023960108"),
    ] {
        assert_eq!(
            format_pax_time(&time_unix(secs, nanos)),
            want,
            "{secs}.{nanos}"
        );
    }
}

#[test]
fn parse_pax_record_table() {
    let med = "CD".repeat(50);
    let long = "AB".repeat(100);
    let ok: Vec<(String, &str, &str, String)> = vec![
        ("6 k=v\n\n".into(), "k", "v", "\n".into()),
        (
            "19 path=/etc/hosts\n".into(),
            "path",
            "/etc/hosts",
            "".into(),
        ),
        (
            format!("210 path={long}\nabc"),
            "path",
            long.as_str(),
            "abc".into(),
        ),
        (format!("110 path={med}\n"), "path", med.as_str(), "".into()),
        ("9 foo=ba\n".into(), "foo", "ba", "".into()),
        ("11 foo=bar\n\x00".into(), "foo", "bar", "\x00".into()),
        (
            "18 foo=b=\nar=\n==\x00\n".into(),
            "foo",
            "b=\nar=\n==\x00",
            "".into(),
        ),
        (
            "27 foo=hello9 foo=ba\nworld\n".into(),
            "foo",
            "hello9 foo=ba\nworld",
            "".into(),
        ),
        (
            "27 ☺☻☹=日a本b語ç\nmeow mix".into(),
            "☺☻☹",
            "日a本b語ç",
            "meow mix".into(),
        ),
    ];
    for (input, key, val, rest) in &ok {
        let (k, v, r) = parse_pax_record(input.as_bytes()).expect(input);
        assert_eq!(
            (k, v, r),
            (key.as_bytes(), val.as_bytes(), rest.as_bytes()),
            "{input:?}"
        );
    }
    for input in [
        "17 \x00hello=\x00world\n",
        "1 k=1\n",
        "6 k~1\n",
        "6_k=1\n",
        "6 k=1 ",
        "632 k=1\n",
        "16 longkeyname=hahaha\n",
        "3 somelongkey=\n",
        "50 tooshort=\n",
        "0000000000000000000000000000000030 mtime=1432668921.098285006\n30 ctime=2147483649.15163319",
        "06 k=v\n",
        "00006 k=v\n",
        "000006 k=v\n",
        "000000 k=v\n",
        "0 k=v\n",
        "+0000005 x=\n",
    ] {
        assert!(parse_pax_record(input.as_bytes()).is_err(), "{input:?}");
    }
}

#[test]
fn format_pax_record_table() {
    let med = "CD".repeat(50);
    let long = "AB".repeat(100);
    for (k, v, want) in [
        ("k", "v", Some("6 k=v\n".to_string())),
        ("path", "/etc/hosts", Some("19 path=/etc/hosts\n".into())),
        ("path", long.as_str(), Some(format!("210 path={long}\n"))),
        ("path", med.as_str(), Some(format!("110 path={med}\n"))),
        ("foo", "ba", Some("9 foo=ba\n".into())),
        ("foo", "bar", Some("11 foo=bar\n".into())),
        (
            "foo",
            "b=\nar=\n==\x00",
            Some("18 foo=b=\nar=\n==\x00\n".into()),
        ),
        ("☺☻☹", "日a本b語ç", Some("27 ☺☻☹=日a本b語ç\n".into())),
        ("xhello", "\x00world", Some("17 xhello=\x00world\n".into())),
        ("path", "null\x00", None),
        ("null\x00", "value", None),
        (
            "SCHILY.xattr.key",
            "null\x00",
            Some("26 SCHILY.xattr.key=null\x00\n".into()),
        ),
    ] {
        assert_eq!(format_pax_record(k, v).ok(), want, "{k:?} {v:?}");
    }
}

#[test]
fn format_string_and_to_ascii() {
    let mut f = Formatter::default();
    let mut b = [0u8; 4];
    f.string(&mut b, "abcdef");
    assert_eq!(&b, b"abcd");
    assert_eq!(f.err, Some(Error::FieldTooLong));
    // A truncated field never ends in a slash.
    let mut f = Formatter::default();
    let mut b = [0u8; 4];
    f.string(&mut b, "ab/cd");
    assert_eq!(&b, b"ab/c");
    let mut f = Formatter::default();
    let mut b = [0u8; 4];
    f.string(&mut b, "abc/d");
    assert_eq!(&b, b"abc\0");
    assert_eq!(to_ascii("h\u{e9}llo\0w"), "hllow");
    assert!(!is_ascii("a\0b") && is_ascii("plain"));
}

fn formats(h: &Header) -> (Format, BTreeMap<String, String>) {
    h.allowed_formats(false)
        .unwrap_or((FORMAT_UNKNOWN, BTreeMap::new()))
}

#[test]
fn header_allowed_formats_table() {
    let all = Format(FORMAT_USTAR.0 | FORMAT_PAX.0 | FORMAT_GNU.0);
    let pax_gnu = Format(FORMAT_PAX.0 | FORMAT_GNU.0);
    let ustar_pax = Format(FORMAT_USTAR.0 | FORMAT_PAX.0);
    let h = |f: &dyn Fn(&mut Header)| {
        let mut h = Header::default();
        f(&mut h);
        h
    };
    let name100 = "a".repeat(100);
    let name101 = "a".repeat(101);
    type Vector<'a> = (Header, Vec<(&'a str, String)>, Format);
    let vectors: Vec<Vector<'_>> = vec![
        (h(&|_| {}), vec![], all),
        (h(&|x| x.size = 0o77777777777), vec![], all),
        (
            h(&|x| {
                x.size = 0o77777777777;
                x.format = FORMAT_USTAR
            }),
            vec![],
            FORMAT_USTAR,
        ),
        (
            h(&|x| {
                x.size = 0o77777777777;
                x.format = FORMAT_PAX
            }),
            vec![],
            ustar_pax,
        ),
        (
            h(&|x| {
                x.size = 0o77777777777;
                x.format = FORMAT_GNU
            }),
            vec![],
            FORMAT_GNU,
        ),
        (
            h(&|x| x.size = 0o77777777777 + 1),
            vec![("size", "8589934592".into())],
            pax_gnu,
        ),
        (
            h(&|x| {
                x.size = 0o77777777777 + 1;
                x.format = FORMAT_PAX
            }),
            vec![("size", "8589934592".into())],
            FORMAT_PAX,
        ),
        (h(&|x| x.mode = 0o7777777), vec![], all),
        (h(&|x| x.mode = 0o7777777 + 1), vec![], FORMAT_GNU),
        (h(&|x| x.devmajor = -123), vec![], FORMAT_GNU),
        (h(&|x| x.devmajor = (1 << 56) - 1), vec![], FORMAT_GNU),
        (h(&|x| x.devmajor = 1 << 56), vec![], FORMAT_UNKNOWN),
        (h(&|x| x.devmajor = -1 << 56), vec![], FORMAT_GNU),
        (h(&|x| x.devmajor = (-1 << 56) - 1), vec![], FORMAT_UNKNOWN),
        (
            h(&|x| {
                x.name = "用戶名".into();
                x.devmajor = -1 << 56
            }),
            vec![],
            FORMAT_GNU,
        ),
        (
            h(&|x| x.size = i64::MAX),
            vec![("size", "9223372036854775807".into())],
            pax_gnu,
        ),
        (h(&|x| x.size = i64::MIN), vec![], FORMAT_UNKNOWN),
        (
            h(&|x| x.uname = "0123456789abcdef0123456789abcdef".into()),
            vec![],
            all,
        ),
        (
            h(&|x| x.uname = "0123456789abcdef0123456789abcdefx".into()),
            vec![("uname", "0123456789abcdef0123456789abcdefx".into())],
            FORMAT_PAX,
        ),
        (h(&|x| x.name = name100.clone()), vec![], all),
        (
            h(&|x| x.name = name101.clone()),
            vec![("path", name101.clone())],
            pax_gnu,
        ),
        (
            h(&|x| x.linkname = "用戶名".into()),
            vec![("linkpath", "用戶名".into())],
            pax_gnu,
        ),
        (
            h(&|x| x.linkname = "\0hello".into()),
            vec![],
            FORMAT_UNKNOWN,
        ),
        (h(&|x| x.uid = 0o7777777), vec![], all),
        (
            h(&|x| x.uid = 0o7777777 + 1),
            vec![("uid", "2097152".into())],
            pax_gnu,
        ),
        (
            h(&|x| {
                x.xattrs = map(&[("foo", "bar")]);
            }),
            vec![("SCHILY.xattr.foo", "bar".into())],
            FORMAT_PAX,
        ),
        (
            h(&|x| {
                x.xattrs = map(&[("foo", "bar")]);
                x.format = FORMAT_GNU
            }),
            vec![],
            FORMAT_UNKNOWN,
        ),
        (
            h(&|x| x.xattrs = map(&[("foo=bar", "baz")])),
            vec![],
            FORMAT_UNKNOWN,
        ),
        (
            h(&|x| x.xattrs = map(&[("foo", "")])),
            vec![("SCHILY.xattr.foo", "".into())],
            FORMAT_PAX,
        ),
        (h(&|x| x.mod_time = time_unix(0, 0)), vec![], all),
        (
            h(&|x| x.mod_time = time_unix(0o77777777777, 0)),
            vec![],
            all,
        ),
        (
            h(&|x| x.mod_time = time_unix(0o77777777777 + 1, 0)),
            vec![("mtime", "8589934592".into())],
            pax_gnu,
        ),
        (
            h(&|x| {
                x.mod_time = time_unix(i64::MAX, 0);
                x.format = FORMAT_USTAR
            }),
            vec![],
            FORMAT_UNKNOWN,
        ),
        (
            h(&|x| x.mod_time = time_unix(-1, 0)),
            vec![("mtime", "-1".into())],
            pax_gnu,
        ),
        (
            h(&|x| x.mod_time = time_unix(1, 500)),
            vec![("mtime", "1.0000005".into())],
            all,
        ),
        (
            h(&|x| {
                x.mod_time = time_unix(1, 0);
                x.format = FORMAT_PAX
            }),
            vec![],
            ustar_pax,
        ),
        (
            h(&|x| {
                x.mod_time = time_unix(1, 500);
                x.format = FORMAT_USTAR
            }),
            vec![("mtime", "1.0000005".into())],
            FORMAT_USTAR,
        ),
        (
            h(&|x| {
                x.mod_time = time_unix(1, 500);
                x.format = FORMAT_GNU
            }),
            vec![("mtime", "1.0000005".into())],
            FORMAT_GNU,
        ),
        (
            h(&|x| x.mod_time = time_unix(-1, 500)),
            vec![("mtime", "-0.9999995".into())],
            pax_gnu,
        ),
        (
            h(&|x| x.access_time = time_unix(0, 0)),
            vec![("atime", "0".into())],
            pax_gnu,
        ),
        (
            h(&|x| {
                x.access_time = time_unix(0, 0);
                x.format = FORMAT_USTAR
            }),
            vec![],
            FORMAT_UNKNOWN,
        ),
        (
            h(&|x| {
                x.typeflag = TYPE_X_GLOBAL_HEADER;
                x.pax_records = map(&[("path", "foo")]);
            }),
            vec![("path", "foo".into())],
            FORMAT_PAX,
        ),
        (
            h(&|x| {
                x.typeflag = TYPE_X_GLOBAL_HEADER;
                x.size = 1;
            }),
            vec![],
            FORMAT_UNKNOWN,
        ),
        (h(&|x| x.typeflag = TYPE_X_HEADER), vec![], FORMAT_UNKNOWN),
        (
            h(&|x| {
                x.typeflag = TYPE_REG;
                x.name = "dir/".into()
            }),
            vec![],
            FORMAT_UNKNOWN,
        ),
        (
            h(&|x| {
                x.typeflag = TYPE_SYMLINK;
                x.size = -1;
            }),
            vec![("size", "-1".into())],
            pax_gnu,
        ),
        (
            h(&|x| {
                x.typeflag = TYPE_REG;
                x.size = -1;
            }),
            vec![],
            FORMAT_UNKNOWN,
        ),
    ];
    for (i, (header, pax, want)) in vectors.iter().enumerate() {
        let (got, got_pax) = formats(header);
        assert_eq!(got, *want, "vector {i}: {header:?}");
        if got.has(FORMAT_PAX) {
            let want_pax: BTreeMap<String, String> = pax
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect();
            assert_eq!(got_pax, want_pax, "vector {i} PAX records");
        }
        if *want == FORMAT_UNKNOWN {
            assert!(header.allowed_formats(false).is_err(), "vector {i}");
        }
    }
}

#[test]
fn format_names() {
    assert_eq!(FORMAT_UNKNOWN.to_string(), "<unknown>");
    assert_eq!(FORMAT_USTAR.to_string(), "USTAR");
    assert_eq!(FORMAT_PAX.to_string(), "PAX");
    assert_eq!(FORMAT_GNU.to_string(), "GNU");
    assert_eq!(
        Format(FORMAT_USTAR.0 | FORMAT_PAX.0).to_string(),
        "(USTAR | PAX)"
    );
    assert_eq!(
        Format(FORMAT_USTAR.0 | FORMAT_PAX.0 | FORMAT_GNU.0).to_string(),
        "(USTAR | PAX | GNU)"
    );
}

#[test]
fn split_ustar_path_table() {
    let long = |n: usize| "x".repeat(n);
    let cases: Vec<(String, Option<(String, String)>)> = vec![
        ("".into(), None),
        ("abc".into(), None),
        ("用戶名".into(), None),
        (long(100), None),
        (
            format!("{}/{}", long(100), long(1)),
            Some((long(100), long(1))),
        ),
        (
            format!("{}/{}", long(155), long(100)),
            Some((long(155), long(100))),
        ),
        (format!("{}/{}", long(155), long(101)), None),
        (format!("{}/{}", long(156), long(1)), None),
        (
            format!("{}/{}/", long(100), long(10)),
            Some((long(100), format!("{}/", long(10)))),
        ),
        (format!("/{}", long(130)), None),
    ];
    for (name, want) in cases {
        assert_eq!(split_ustar_path(&name), want, "{name:?}");
    }
}

#[test]
fn sparse_entries() {
    let e = |offset, length| SparseEntry { offset, length };
    assert!(validate_sparse_entries(&[], 0));
    assert!(validate_sparse_entries(&[e(0, 0)], 0));
    assert!(validate_sparse_entries(&[e(1, 2), e(3, 4)], 7));
    assert!(!validate_sparse_entries(&[e(0, 4), e(3, 4)], 10));
    assert!(!validate_sparse_entries(&[e(-1, 2)], 5));
    assert!(!validate_sparse_entries(&[e(i64::MAX, 2)], i64::MAX));
    assert!(!validate_sparse_entries(&[e(0, 6)], 5));
    assert!(!validate_sparse_entries(&[], -1));
    // data -> holes and back
    assert_eq!(invert_sparse_entries(&[], 10), vec![e(0, 10)]);
    assert_eq!(
        invert_sparse_entries(&[e(2, 3), e(8, 2)], 10),
        vec![e(0, 2), e(5, 3), e(10, 0)]
    );
    assert_eq!(invert_sparse_entries(&[e(0, 10)], 10), vec![e(10, 0)]);
    // alignment shrinks regions to whole blocks
    assert_eq!(
        align_sparse_entries(&[e(1, 1100), e(2048, 512), e(2600, 100)], 4000),
        vec![e(512, 512), e(2048, 512)]
    );
    assert_eq!(
        align_sparse_entries(&[e(512, 1000)], 1512),
        vec![e(512, 1000)]
    );
}

#[test]
fn zero_time_is_zero() {
    assert!(crate::archive::iofs::time_is_zero(&time_zero()));
    assert!(Header::default().file_info().sys().is_some());
}

use crate::archive::iofs::FileInfo;
