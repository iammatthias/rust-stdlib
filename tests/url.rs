//! Ports the tables of Go's net/url/url_test.go. The large tables are dumped
//! from Go by tools/gen_url_fixtures.py into tests/fixtures/url_go_tables.json;
//! the smaller inline tables are copied below.
use rust_stdlib::{
    encoding::json::{self, Value as Json},
    net::url::{self, Url, Userinfo, Values},
};

fn tables() -> Json {
    (include_str!("fixtures/url_go_tables.json"))
        .parse::<json::Value>()
        .unwrap()
}
fn table(name: &str) -> Vec<Json> {
    tables()
        .get(name)
        .and_then(Json::as_array)
        .unwrap_or_else(|| panic!("missing table {name}"))
        .to_vec()
}
fn s(v: &Json, key: &str) -> String {
    v.get(key).and_then(Json::as_str).unwrap().to_owned()
}
fn b(v: &Json, key: &str) -> bool {
    matches!(v.get(key), Some(Json::Bool(true)))
}
fn url_from(v: &Json) -> Url {
    Url {
        scheme: s(v, "scheme"),
        opaque: s(v, "opaque"),
        user: b(v, "has_user").then(|| {
            if b(v, "password_set") {
                url::user_password(&s(v, "username"), &s(v, "password"))
            } else {
                url::user(&s(v, "username"))
            }
        }),
        host: s(v, "host"),
        path: s(v, "path"),
        raw_path: s(v, "raw_path"),
        omit_host: b(v, "omit_host"),
        force_query: b(v, "force_query"),
        raw_query: s(v, "raw_query"),
        fragment: s(v, "fragment"),
        raw_fragment: s(v, "raw_fragment"),
        ..Url::default()
    }
}
fn values_from(v: &Json) -> Values {
    let mut out = Values::new();
    if let Json::Object(map) = v {
        for (k, vs) in map {
            for item in vs.as_array().unwrap() {
                out.add(k, item.as_str().unwrap());
            }
        }
    }
    out
}

#[test]
fn parse_table() {
    let rows = table("parse");
    assert!(rows.len() > 50);
    for row in rows {
        let input = s(&row, "in");
        let want = url_from(row.get("out").unwrap());
        if input.is_empty() {
            continue;
        }
        let got = url::parse(&input).unwrap_or_else(|e| panic!("Parse({input:?}): {e}"));
        assert_eq!(got, want, "Parse({input:?})");
        // TestURLString: the parsed form reserializes to the roundtrip text.
        assert_eq!(want.to_string(), s(&row, "roundtrip"), "String({input:?})");
        assert_eq!(
            got.to_string(),
            s(&row, "roundtrip"),
            "Parse({input:?}).String()"
        );
    }
}

#[test]
fn parse_request_uri_table() {
    for row in table("parse_request_uri") {
        let input = s(&row, "url");
        assert_eq!(
            url::parse_request_uri(&input).is_ok(),
            b(&row, "valid"),
            "ParseRequestURI({input:?})"
        );
    }
}

#[test]
fn string_table() {
    for row in table("string") {
        assert_eq!(
            url_from(row.get("url").unwrap()).to_string(),
            s(&row, "want")
        );
    }
}

#[test]
fn unescape_table() {
    for row in table("unescape") {
        let (input, out) = (s(&row, "in"), s(&row, "out"));
        let got = url::query_unescape(&input);
        assert_eq!(got.is_err(), b(&row, "err"), "QueryUnescape({input:?})");
        if let Ok(got) = got {
            assert_eq!(got, out, "QueryUnescape({input:?})");
        }
        let path_input = input.replace('+', "%20");
        let got = url::path_unescape(&path_input);
        assert_eq!(got.is_err(), b(&row, "err"), "PathUnescape({path_input:?})");
        if let Ok(got) = got {
            assert_eq!(got, out, "PathUnescape({path_input:?})");
        }
        if !input.contains('+') && !b(&row, "err") {
            assert_eq!(url::path_unescape(&input).unwrap(), out);
        }
    }
}

#[test]
fn escape_tables() {
    for row in table("query_escape") {
        let (input, out) = (s(&row, "in"), s(&row, "out"));
        assert_eq!(url::query_escape(&input), out, "QueryEscape({input:?})");
        if !b(&row, "err") {
            assert_eq!(url::query_unescape(&out).unwrap(), input);
        }
    }
    for row in table("path_escape") {
        let (input, out) = (s(&row, "in"), s(&row, "out"));
        assert_eq!(url::path_escape(&input), out, "PathEscape({input:?})");
        assert_eq!(url::path_unescape(&out).unwrap(), input);
    }
}

#[test]
fn encode_query_table() {
    for row in table("encode_query") {
        let values = values_from(row.get("values").unwrap());
        assert_eq!(values.encode(), s(&row, "expected"));
    }
}

#[test]
fn resolve_reference_table() {
    let opaque = Url {
        scheme: "scheme".into(),
        opaque: "opaque".into(),
        ..Url::default()
    };
    for row in table("resolve_reference") {
        let (base, rel, expected) = (s(&row, "base"), s(&row, "rel"), s(&row, "expected"));
        let base_url = url::parse(&base).unwrap();
        let rel_url = url::parse(&rel).unwrap();
        assert_eq!(
            base_url.resolve_reference(&rel_url).to_string(),
            expected,
            "URL({base:?}).ResolveReference({rel:?})"
        );
        assert_eq!(base_url.parse(&rel).unwrap().to_string(), expected);
        assert_eq!(base_url.resolve_reference(&opaque), opaque);
        assert_eq!(base_url.parse("scheme:opaque").unwrap(), opaque);
    }
}

#[test]
fn resolve_path_table() {
    // Go's resolvePath is unexported; it is what ResolveReference applies to
    // two plain paths.
    for row in table("resolve_path") {
        let (base, rel, expected) = (s(&row, "base"), s(&row, "ref"), s(&row, "expected"));
        let base_url = Url {
            path: base.clone(),
            ..Url::default()
        };
        let rel_url = Url {
            path: rel.clone(),
            ..Url::default()
        };
        assert_eq!(
            base_url.resolve_reference(&rel_url).path,
            expected,
            "resolvePath({base:?}, {rel:?})"
        );
    }
}

#[test]
fn parse_query_table() {
    for row in table("parse_query") {
        let query = s(&row, "query");
        let (got, err) = url::parse_query(&query);
        assert_eq!(
            err.is_none(),
            b(&row, "ok"),
            "ParseQuery({query:?}): {err:?}"
        );
        let want = values_from(row.get("out").unwrap());
        assert_eq!(got, want, "ParseQuery({query:?})");
    }
}

#[test]
fn request_uri_table() {
    for row in table("request_uri") {
        let u = url_from(row.get("url").unwrap());
        assert_eq!(u.request_uri(), s(&row, "out"), "{u:?}");
    }
}

#[test]
fn parse_errors() {
    let tests: &[(&str, bool)] = &[
        ("http://[::1]", false),
        ("http://[::1]:80", false),
        ("http://[::1]:namedport", true),
        ("http://x:namedport", true),
        ("http://[::1]/", false),
        ("http://[::1]a", true),
        ("http://[::1]%23", true),
        ("http://[::1%25en0]", false),
        ("http://[::1]:", false),
        ("http://x:", false),
        ("http://[::1]:%38%30", true),
        ("http://[::1%25%41]", false),
        ("http://[%10::1]", true),
        ("http://[::1]/%48", false),
        ("http://%41:8080/", true),
        ("mysql://x@y(z:123)/foo", true),
        ("mysql://x@y(1.2.3.4:123)/foo", true),
        (" http://foo.com", true),
        ("ht tp://foo.com", true),
        ("ahttp://foo.com", false),
        ("1http://foo.com", true),
        (
            "http://[]%20%48%54%54%50%2f%31%2e%31%0a%4d%79%48%65%61%64%65%72%3a%20%31%32%33%0a%0a/",
            true,
        ),
        ("http://a b.com/", true),
        ("cache_object://foo", true),
        ("cache_object:foo", true),
        ("cache_object:foo/bar", true),
        ("cache_object/:foo/bar", false),
        ("http://[192.168.0.1]/", true),
        ("http://[192.168.0.1]:8080/", true),
        ("http://[::ffff:192.168.0.1]/", false),
        ("http://[::ffff:192.168.0.1000]/", true),
        ("http://[::ffff:192.168.0.1]:8080/", false),
        ("http://[::ffff:c0a8:1]/", false),
        ("http://[not-an-ip]/", true),
        ("http://[fe80::1%foo]/", true),
        ("http://[fe80::1", true),
        ("http://fe80::1]/", true),
        ("http://[test.com]/", true),
        ("http://example.com[::1]", true),
        ("http://example.com[::1", true),
        ("http://[::1", true),
        ("http://.[::1]", true),
        ("http:// [::1]", true),
        ("hxxp://mathepqo[.]serveftp(.)com:9059", true),
    ];
    for (input, want_err) in tests {
        assert_eq!(url::parse(input).is_err(), *want_err, "Parse({input:?})");
    }
}

#[test]
fn error_texts() {
    let cases: &[(&str, &str)] = &[
        (
            "http://foo.com/?foo\nbar",
            "parse \"http://foo.com/?foo\\nbar\": net/url: invalid control character in URL",
        ),
        (
            "http://foo\x7f.com/",
            "parse \"http://foo\\x7f.com/\": net/url: invalid control character in URL",
        ),
        (":foo", "parse \":foo\": missing protocol scheme"),
        ("/a%zz", "parse \"/a%zz\": invalid URL escape \"%zz\""),
        (
            "http://[::1]x/",
            "parse \"http://[::1]x/\": invalid port \"x\" after host",
        ),
        (
            "http://[::1/",
            "parse \"http://[::1/\": missing ']' in host",
        ),
        (
            "http://x[::1]/",
            "parse \"http://x[::1]/\": invalid IP-literal",
        ),
        (
            "http://[1.2.3.4]/",
            "parse \"http://[1.2.3.4]/\": invalid IP-literal",
        ),
        (
            "http://[nope]/",
            "parse \"http://[nope]/\": invalid host: ParseAddr(\"nope\"): unable to parse IP",
        ),
        (
            "http://a b/",
            "parse \"http://a b/\": invalid character \" \" in host name",
        ),
        (
            "http://user^:pw^@foo.com/",
            "parse \"http://user^:pw^@foo.com/\": net/url: invalid userinfo",
        ),
        (
            "http://h:1:2/",
            "parse \"http://h:1:2/\": invalid port \":1:2\" after host",
        ),
    ];
    for (input, want) in cases {
        let err = url::parse(input).expect_err(input);
        assert_eq!(err.to_string(), *want, "Parse({input:?})");
        assert_eq!(err.op, "parse");
        assert!(!err.timeout() && !err.temporary());
    }
    // Only a colon in the *first* segment of a relative path is an error.
    assert_eq!(url::parse("a:b").unwrap().opaque, "b");
    assert_eq!(url::parse("a/b:c").unwrap().path, "a/b:c");
    assert_eq!(url::parse("/a:b/c").unwrap().path, "/a:b/c");
    assert_eq!(url::parse("this:that/../x").unwrap().opaque, "that/../x");
    assert_eq!(url::parse("this:that").unwrap().to_string(), "this:that");
    assert_eq!(
        url::parse_request_uri("").unwrap_err().to_string(),
        "parse \"\": empty url"
    );
    assert_eq!(
        url::parse_request_uri("a/b").unwrap_err().to_string(),
        "parse \"a/b\": invalid URI for request"
    );
    assert_eq!(url::parse("./a:b").map(|u| u.path).unwrap(), "./a:b");
    assert_eq!(
        url::parse("a:b/c#%zz").unwrap_err().to_string(),
        "parse \"a:b/c#%zz\": invalid URL escape \"%zz\""
    );
}

#[test]
fn escape_error_types() {
    let err = url::query_unescape("%zz").unwrap_err();
    assert_eq!(err.to_string(), "invalid URL escape \"%zz\"");
    assert_eq!(
        url::query_unescape("%").unwrap_err().to_string(),
        "invalid URL escape \"%\""
    );
    let wrapped = url::parse("http://a b/").unwrap_err();
    let inner = wrapped
        .unwrap()
        .downcast_ref::<url::InvalidHostError>()
        .unwrap();
    assert_eq!(inner, &url::InvalidHostError(" ".into()));
}

#[test]
fn hostname_and_port() {
    let tests: &[(&str, &str, &str)] = &[
        ("foo.com:80", "foo.com", "80"),
        ("foo.com", "foo.com", ""),
        ("foo.com:", "foo.com", ""),
        ("FOO.COM", "FOO.COM", ""),
        ("1.2.3.4", "1.2.3.4", ""),
        ("1.2.3.4:80", "1.2.3.4", "80"),
        ("[1:2:3:4]", "1:2:3:4", ""),
        ("[1:2:3:4]:80", "1:2:3:4", "80"),
        ("[::1]:80", "::1", "80"),
        ("[::1]", "::1", ""),
        ("[::1]:", "::1", ""),
        ("localhost", "localhost", ""),
        ("localhost:443", "localhost", "443"),
        (
            "some.super.long.domain.example.org:8080",
            "some.super.long.domain.example.org",
            "8080",
        ),
        (
            "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:17000",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "17000",
        ),
        (
            "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "",
        ),
        ("[google.com]:80", "google.com", "80"),
        ("google.com]:80", "google.com]", "80"),
        (
            "google.com:80_invalid_port",
            "google.com:80_invalid_port",
            "",
        ),
        ("[::1]extra]:80", "::1]extra", "80"),
        ("google.com]extra:extra", "google.com]extra:extra", ""),
    ];
    for (host, want_host, want_port) in tests {
        let u = Url {
            host: (*host).into(),
            ..Url::default()
        };
        assert_eq!(u.hostname(), *want_host, "Hostname for {host:?}");
        assert_eq!(u.port(), *want_port, "Port for {host:?}");
    }
}

#[test]
fn redacted() {
    let mut u = Url {
        scheme: "http".into(),
        host: "host.tld".into(),
        path: "this:that".into(),
        user: Some(url::user_password("user", "password")),
        ..Url::default()
    };
    assert_eq!(u.redacted(), "http://user:xxxxx@host.tld/this:that");
    u.user = Some(url::user_password("user", ""));
    assert_eq!(u.redacted(), "http://user:xxxxx@host.tld/this:that");
    u.user = Some(url::user("user"));
    assert_eq!(u.redacted(), "http://user@host.tld/this:that");
    u.user = None;
    assert_eq!(u.redacted(), "http://host.tld/this:that");
    // The original is untouched.
    u.user = Some(url::user_password("a", "b"));
    let _ = u.redacted();
    assert_eq!(u.user.as_ref().unwrap().password(), Some("b"));
}

#[test]
fn join_path() {
    let tests: &[(&str, &[&str], &str)] = &[
        (
            "https://go.googlesource.com",
            &["go"],
            "https://go.googlesource.com/go",
        ),
        (
            "https://go.googlesource.com/a/b/c",
            &["../../../go"],
            "https://go.googlesource.com/go",
        ),
        (
            "https://go.googlesource.com/",
            &["../go"],
            "https://go.googlesource.com/go",
        ),
        (
            "https://go.googlesource.com",
            &["../go", "../../go", "../../../go"],
            "https://go.googlesource.com/go",
        ),
        (
            "https://go.googlesource.com/../go",
            &[],
            "https://go.googlesource.com/go",
        ),
        (
            "https://go.googlesource.com/",
            &["./go"],
            "https://go.googlesource.com/go",
        ),
        (
            "https://go.googlesource.com//",
            &["/go"],
            "https://go.googlesource.com/go",
        ),
        (
            "https://go.googlesource.com//",
            &["/go", "a", "b", "c"],
            "https://go.googlesource.com/go/a/b/c",
        ),
        ("http://[fe80::1%en0]:8080/", &["/go"], ""),
        (
            "https://go.googlesource.com",
            &["go/"],
            "https://go.googlesource.com/go/",
        ),
        (
            "https://go.googlesource.com",
            &["go//"],
            "https://go.googlesource.com/go/",
        ),
        (
            "https://go.googlesource.com",
            &[],
            "https://go.googlesource.com/",
        ),
        (
            "https://go.googlesource.com/",
            &[],
            "https://go.googlesource.com/",
        ),
        (
            "https://go.googlesource.com/a%2fb",
            &["c"],
            "https://go.googlesource.com/a%2fb/c",
        ),
        (
            "https://go.googlesource.com/a%2fb",
            &["c%2fd"],
            "https://go.googlesource.com/a%2fb/c%2fd",
        ),
        (
            "https://go.googlesource.com/a/b",
            &["/go"],
            "https://go.googlesource.com/a/b/go",
        ),
        ("https://go.googlesource.com/", &["100%"], ""),
        ("/", &[], "/"),
        ("a", &[], "a"),
        ("a", &["b"], "a/b"),
        ("a", &["../b"], "b"),
        ("a", &["../../b"], "b"),
        ("", &["a"], "a"),
        ("", &["../a"], "a"),
    ];
    for (base, elems, want) in tests {
        let got = url::join_path(base, elems);
        match got {
            Ok(out) => assert_eq!(out, *want, "JoinPath({base:?}, {elems:?})"),
            Err(e) => assert_eq!(*want, "", "JoinPath({base:?}, {elems:?}): {e}"),
        }
        if let Ok(u) = url::parse(base) {
            let want = if want.is_empty() { base } else { want };
            assert_eq!(
                u.join_path(elems).to_string(),
                *want,
                "{base:?}.JoinPath({elems:?})"
            );
        }
    }
}

#[test]
fn strict_colons_and_query_limits() {
    for input in [
        "https://1:2:3:4:5:6:7:8",
        "https://1:2:3:4:5:6:7:8:80",
        "https://example.com:80:",
    ] {
        assert!(url::parse(input).is_err(), "{input}");
    }
    // Other schemes use the last colon, as before Go's urlstrictcolons change.
    assert!(url::parse("ftp://example.com:80:").is_ok());
    assert!(url::parse("x://1:2:3:4:5:6:7:8:80").is_ok());

    let query = |n: usize| {
        (0..n)
            .map(|i| format!("p{i}"))
            .collect::<Vec<_>>()
            .join("&")
    };
    assert!(url::parse_query(&query(10)).1.is_none());
    assert!(url::parse_query(&query(10_000)).1.is_none());
    let (values, err) = url::parse_query(&query(10_001));
    assert!(values.0.is_empty());
    assert_eq!(
        err.unwrap().to_string(),
        "number of URL query parameters exceeded limit"
    );
    assert!(url::parse_query_with_max(&query(10), Some(9)).1.is_some());
    let (values, err) = url::parse_query_with_max(&query(10_001), Some(0));
    assert!(err.is_none() && values.0.len() == 10_001);
}

#[test]
fn nil_user_and_userinfo() {
    let u = url::parse("http://foo.com/").unwrap();
    assert!(u.user.is_none());
    let u = url::parse("http://us%20er:p%40ss@foo.com/").unwrap();
    let ui: &Userinfo = u.user.as_ref().unwrap();
    assert_eq!(ui.username(), "us er");
    assert_eq!(ui.password(), Some("p@ss"));
    assert_eq!(ui.to_string(), "us%20er:p%40ss");
    assert_eq!(url::user("x").to_string(), "x");
    assert_eq!(url::user("x").password(), None);
    assert_eq!(url::user_password("x", "").to_string(), "x:");
    assert_eq!(url::user_password("x", "").password(), Some(""));
}

#[test]
fn reject_control_characters() {
    for input in [
        "http://foo.com/?foo\nbar",
        "http\r://foo.com/",
        "http://foo\x7f.com/",
    ] {
        let err = url::parse(input).unwrap_err().to_string();
        assert!(
            err.contains("net/url: invalid control character in URL"),
            "{err}"
        );
    }
    assert!(url::parse("http://foo.com/ctl\u{80}").is_ok());
}

#[test]
fn star_request_and_values() {
    assert_eq!(url::parse("*").unwrap().request_uri(), "*");
    let mut v = Values::new();
    assert_eq!(v.get("a"), "");
    v.set("a", "1");
    v.add("a", "2");
    v.add("b", "x y");
    assert_eq!(v.get("a"), "1");
    assert!(v.has("b") && !v.has("c"));
    assert_eq!(v.encode(), "a=1&a=2&b=x+y");
    let copy = v.clone();
    v.del("a");
    assert!(copy.has("a") && !v.has("a"));
}

#[test]
fn url_clone_and_binary() {
    use rust_stdlib::encoding::{BinaryAppender, BinaryMarshaler, BinaryUnmarshaler};
    let u = url::parse("https://u:p@h:1/a%2Fb?q=1#f%20g").unwrap();
    let mut c = u.clone();
    c.user = Some(url::user("other"));
    assert_eq!(u.user.as_ref().unwrap().username(), "u");
    let text = u.marshal_binary().unwrap();
    assert_eq!(text, b"https://u:p@h:1/a%2Fb?q=1#f%20g");
    let mut out = b"x".to_vec();
    BinaryAppender::append_binary(&u, &mut out).unwrap();
    assert_eq!(out, b"xhttps://u:p@h:1/a%2Fb?q=1#f%20g");
    let mut back = Url::default();
    BinaryUnmarshaler::unmarshal_binary(&mut back, &text).unwrap();
    assert_eq!(back, u);
    assert_eq!(BinaryMarshaler::marshal_binary(&back).unwrap(), text);
    assert!(back.unmarshal_binary(b"%zz").is_err());
}

#[test]
fn non_utf8_escapes_round_trip_through_raw_forms() {
    let u = url::parse("http://h/a%ffb?x=%ff#%fe").unwrap();
    assert_eq!(u.path, "a\u{fffd}b".replace("a", "/a"));
    assert_eq!(u.raw_path, "/a%ffb");
    assert_eq!(u.to_string(), "http://h/a%ffb?x=%ff#%fe");
}

#[test]
fn non_utf8_host_string_field_is_lossy_but_string_is_exact() {
    let u = url::parse("http://a%ffb/").unwrap();
    assert_eq!(u.host, "a\u{fffd}b");
    assert_eq!(u.to_string(), "http://a%FFb/");
}

#[test]
fn host_and_userinfo_keep_non_utf8_bytes_through_string() {
    let u = url::parse("http://u%e9:p%ff@h%e9.com/x").unwrap();
    assert_eq!(u.to_string(), "http://u%E9:p%FF@h%E9.com/x");
    assert_eq!(u.host_bytes(), b"h\xe9.com");
    let user = u.user.as_ref().unwrap();
    assert_eq!(user.username_bytes(), b"u\xe9");
    assert_eq!(user.password_bytes(), Some(&b"p\xff"[..]));
    assert_eq!(u.redacted(), "http://u%E9:xxxxx@h%E9.com/x");
    // Replacing the host drops the stale raw bytes.
    let mut v = u.clone();
    v.host = "other".into();
    assert_eq!(v.to_string(), "http://u%E9:p%FF@other/x");
}

#[test]
fn error_timeout_and_temporary_follow_the_wrapped_error() {
    use rust_stdlib::net::NetError;
    let wrap = |err: url::BoxError| url::Error {
        op: "Get".into(),
        url: "http://h/".into(),
        err,
    };
    let e = wrap(Box::new(NetError::IoTimeout));
    assert!(e.timeout());
    assert!(e.temporary());
    let e = wrap(Box::new(NetError::Closed));
    assert!(!e.timeout());
    assert!(!e.temporary());
    let e = wrap(Box::new(std::io::Error::from(std::io::ErrorKind::TimedOut)));
    assert!(e.timeout());
    // Nested url.Error values delegate in turn.
    let inner = wrap(Box::new(NetError::Timeout));
    assert!(wrap(Box::new(inner)).timeout());
    assert!(!wrap("plain".into()).timeout());
}
