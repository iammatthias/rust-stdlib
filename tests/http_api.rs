#![cfg(feature = "net")]
//! Go-shaped `net/http` API: headers, cookies, requests, responses, forms,
//! `ServeMux` patterns and the small handlers. Tables follow Go's
//! `header_test.go`, `cookie_test.go`, `request_test.go`, `readrequest_test.go`
//! and `pattern_test.go`; `tools/http_check.py` covers the same ground against
//! Go itself.
use rust_stdlib::net::http::{
    self, handler_func, max_bytes_reader, not_found_handler, redirect_handler,
    request::{read_request, Request},
    response::{read_response, Response},
    strip_prefix, Body, BufioReader, Cookie, Handler, Header, MaxBytesError, ResponseWriter,
    ServeMux, STATUS_FOUND, STATUS_OK,
};
use std::{
    collections::BTreeMap,
    io::{self, Cursor, Read},
    sync::Arc,
};

#[derive(Default)]
struct Rec {
    header: Header,
    snap: Option<Header>,
    code: u16,
    body: Vec<u8>,
}
impl std::io::Write for Rec {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.snap.is_none() {
            self.write_header(STATUS_OK);
        }
        self.body.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl ResponseWriter for Rec {
    fn header(&mut self) -> &mut Header {
        &mut self.header
    }
    fn write_header(&mut self, code: u16) {
        if self.snap.is_none() {
            self.code = code;
            self.snap = Some(self.header.clone());
        }
    }
}
impl Rec {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    fn get(&self, k: &str) -> String {
        self.snap
            .as_ref()
            .map_or_else(String::new, |h| h.get(k).unwrap_or("").to_owned())
    }
}

fn parse(raw: &str) -> Request {
    read_request(&BufioReader::new(Cursor::new(raw.as_bytes().to_vec()))).unwrap()
}
fn get(mux: &ServeMux, host: &str, method: &str, target: &str) -> Rec {
    let mut raw = format!("{method} {target} HTTP/1.1\r\n");
    if !host.is_empty() {
        raw.push_str(&format!("Host: {host}\r\n"));
    }
    raw.push_str("\r\n");
    let mut req = parse(&raw);
    let mut rec = Rec::default();
    mux.serve_http(&mut rec, &mut req);
    rec
}

#[test]
fn header_methods_canonicalize() {
    let mut h = Header::new();
    h.add("content-type", "a");
    h.add("CONTENT-TYPE", "b");
    h.set("x-y", "1");
    assert_eq!(h.values("Content-Type"), vec!["a", "b"]);
    assert_eq!(h.get("content-type").unwrap_or(""), "a");
    assert_eq!(h.get("missing").unwrap_or(""), "");
    h.del("X-Y");
    assert!(!h.0.contains_key("X-Y"));
    // Direct map access keeps non-canonical keys, as Go's map type does.
    h.0.insert("x-raw".into(), vec!["v".into()]);
    assert_eq!(h.get("x-raw").unwrap_or(""), "");
    assert_eq!(
        http::canonical_header_key("x-forwarded-for"),
        "X-Forwarded-For"
    );
}

#[test]
fn header_write_subset_sorts_and_sanitizes() {
    let mut h = Header::new();
    h.add("B", " v\r\nw ");
    h.add("A", "1");
    h.0.insert("bad key".into(), vec!["x".into()]);
    let mut out = Vec::new();
    h.write(&mut out).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "A: 1\r\nB: v  w\r\n");
    let mut out = Vec::new();
    let mut ex = BTreeMap::new();
    ex.insert("A".to_owned(), true);
    h.write_subset(&mut out, &ex).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "B: v  w\r\n");
}

#[test]
fn time_and_version_parsing() {
    let want = 784_111_777;
    for s in [
        "Sun, 06 Nov 1994 08:49:37 GMT",
        "Sunday, 06-Nov-94 08:49:37 GMT",
        "Sun Nov  6 08:49:37 1994",
    ] {
        assert_eq!(http::parse_time(s).unwrap().unix(), want, "{s}");
    }
    assert!(http::parse_time("Sun, 06 Nov 1994").is_err());
    assert_eq!(http::parse_http_version("HTTP/1.1"), Some((1, 1)));
    assert_eq!(http::parse_http_version("HTTP/0.9"), Some((0, 9)));
    assert_eq!(http::parse_http_version("HTTP/1.10"), None);
    assert_eq!(http::parse_http_version("http/1.1"), None);
}

#[test]
fn constants_match_go() {
    assert_eq!(http::STATUS_TEAPOT, 418);
    assert_eq!(http::STATUS_HTTP_VERSION_NOT_SUPPORTED, 505);
    assert_eq!(http::METHOD_PATCH, "PATCH");
    assert_eq!(http::TIME_FORMAT, "Mon, 02 Jan 2006 15:04:05 GMT");
    assert_eq!(http::TRAILER_PREFIX, "Trailer:");
    assert_eq!(http::DEFAULT_MAX_HEADER_BYTES, 1 << 20);
    assert_eq!(http::status_text(http::STATUS_TEAPOT), "I'm a teapot");
}

#[test]
fn cookie_string_and_valid() {
    let c = Cookie {
        name: "cookie-9".into(),
        value: "expiring".into(),
        max_age: 3600,
        secure: true,
        http_only: true,
        same_site: http::SAME_SITE_LAX_MODE,
        path: "/a".into(),
        domain: ".example.com".into(),
        ..Cookie::default()
    };
    assert_eq!(
        c.to_string(),
        "cookie-9=expiring; Path=/a; Domain=example.com; Max-Age=3600; HttpOnly; Secure; SameSite=Lax"
    );
    assert!(c.valid().is_ok());
    let bad = Cookie {
        name: "a b".into(),
        ..Cookie::default()
    };
    assert_eq!(bad.to_string(), "");
    assert_eq!(
        bad.valid().unwrap_err().to_string(),
        "http: invalid Cookie.Name"
    );
    let c = Cookie {
        name: "n".into(),
        value: "a b".into(),
        ..Cookie::default()
    };
    assert_eq!(c.to_string(), "n=\"a b\"");
}

#[test]
fn parse_cookie_tables() {
    let cs = http::parse_cookie("a=1; b=\"two\\words\"").unwrap_err();
    assert_eq!(cs.to_string(), "http: invalid cookie value");
    let cs = http::parse_cookie("a=1; b=\"2\"").unwrap();
    assert_eq!(cs.len(), 2);
    assert!(cs[1].quoted && cs[1].value == "2");
    assert_eq!(
        http::parse_cookie("").unwrap_err().to_string(),
        "http: blank cookie"
    );
    assert_eq!(
        http::parse_cookie("novalue").unwrap_err().to_string(),
        "http: '=' not found in cookie"
    );
    let c = http::parse_set_cookie(
        "id=a3fWa; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Max-Age=2592000; Secure; HttpOnly; SameSite=Strict; Path=/; Foo=bar",
    )
    .unwrap();
    assert_eq!(c.name, "id");
    assert_eq!(c.max_age, 2_592_000);
    assert_eq!(c.expires.unix(), 1_445_412_480);
    assert_eq!(c.same_site, http::SAME_SITE_STRICT_MODE);
    assert_eq!(c.unparsed, vec!["Foo=bar"]);
    assert!(c.secure && c.http_only);
}

#[test]
fn request_cookies_and_add_cookie() {
    let mut r = Request::default();
    r.add_cookie(&Cookie {
        name: "a".into(),
        value: "1".into(),
        ..Cookie::default()
    });
    r.add_cookie(&Cookie {
        name: "b".into(),
        value: "x y".into(),
        ..Cookie::default()
    });
    assert_eq!(r.header.get("Cookie").unwrap_or(""), "a=1; b=\"x y\"");
    assert_eq!(r.cookies().len(), 2);
    assert_eq!(r.cookie("a").unwrap().value, "1");
    assert_eq!(r.cookie("zz").unwrap_err(), http::ERR_NO_COOKIE);
    assert_eq!(r.cookies_named("b")[0].value, "x y");
    assert!(r.cookies_named("").is_empty());
}

#[test]
fn request_new_sets_length_and_get_body() {
    let mut r = Request::new("POST", "http://example.com:/p?q=1")
        .map(|r| r.with_body("hello"))
        .unwrap();
    assert_eq!(r.content_length, 5);
    assert_eq!(r.url.host, "example.com");
    assert_eq!(r.host, "example.com");
    assert_eq!(r.proto, "HTTP/1.1");
    let get_body = r.get_body.clone().unwrap();
    assert_eq!(r.body.take().unwrap().read_all().unwrap(), b"hello");
    assert_eq!(get_body().unwrap().read_all().unwrap(), b"hello");
    let empty = Request::new("GET", "http://x/")
        .map(|r| r.with_body(Vec::new()))
        .unwrap();
    assert!(empty.body.unwrap().is_no_body());
    assert_eq!(Request::new("", "http://x/").unwrap().method, "GET");
    assert!(Request::new("BAD METHOD", "http://x/").is_err());
    assert!(Request::new("GET", "http://[::1").is_err());
}

#[test]
fn basic_auth_roundtrip() {
    let mut r = Request::default();
    r.set_basic_auth("Aladdin", "open sesame");
    assert_eq!(
        r.header.get("Authorization").unwrap_or(""),
        "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
    );
    assert_eq!(
        r.basic_auth(),
        Some(("Aladdin".to_owned(), "open sesame".to_owned()))
    );
    r.header
        .set("Authorization", "basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
    assert!(r.basic_auth().is_some());
    r.header.set("Authorization", "Basic !!!");
    assert!(r.basic_auth().is_none());
}

#[test]
fn read_request_basics() {
    let r = parse("POST /a/b?x=1 HTTP/1.1\r\nHost: h.example\r\nContent-Length: 5\r\nPragma: no-cache\r\nConnection: close\r\n\r\nhello");
    assert_eq!(r.method, "POST");
    assert_eq!(r.url.path, "/a/b");
    assert_eq!(r.host, "h.example");
    assert_eq!(r.content_length, 5);
    assert!(r.close);
    assert_eq!(r.header.get("Cache-Control").unwrap_or(""), "no-cache");
    assert_eq!(r.body.clone().unwrap().read_all().unwrap(), b"hello");
    assert!(r.proto_at_least(1, 0) && !r.proto_at_least(1, 2));
    let e = read_request(&BufioReader::new(Cursor::new(
        b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n".to_vec(),
    )))
    .unwrap_err();
    assert_eq!(e.to_string(), "too many Host headers");
    let e = read_request(&BufioReader::new(Cursor::new(Vec::new()))).unwrap_err();
    assert_eq!(e.to_string(), "EOF");
}

#[test]
fn chunked_request_reads_trailers() {
    let mut r = parse("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTrailer: X-T\r\n\r\n3\r\nabc\r\n0\r\nX-T: v\r\n\r\n");
    assert_eq!(r.transfer_encoding, vec!["chunked"]);
    assert_eq!(r.content_length, -1);
    assert_eq!(r.body.take().unwrap().read_all().unwrap(), b"abc");
    assert_eq!(r.trailer.get().unwrap().get("X-T").unwrap_or(""), "v");
}

#[test]
fn request_write_matches_go() {
    let mut r = Request::new("POST", "http://example.com/x")
        .map(|r| r.with_body("body"))
        .unwrap();
    r.header.set("X-A", "1");
    let mut out = Vec::new();
    r.write(&mut out).unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "POST /x HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Go-http-client/1.1\r\nContent-Length: 4\r\nX-A: 1\r\n\r\nbody"
    );
    let r = Request::new("GET", "http://example.com/x?y").unwrap();
    let mut out = Vec::new();
    r.write_proxy(&mut out).unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "GET http://example.com/x?y HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Go-http-client/1.1\r\n\r\n"
    );
}

#[test]
fn response_read_and_write() {
    let raw = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nSet-Cookie: a=b; Path=/\r\nLocation: /next\r\n\r\nabc";
    let resp = read_response(
        &BufioReader::new(Cursor::new(raw.as_bytes().to_vec())),
        None,
    )
    .unwrap();
    assert_eq!(resp.status, "200 OK");
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.cookies()[0].name, "a");
    assert_eq!(resp.location().unwrap().path, "/next");
    let mut out = Vec::new();
    resp.write(&mut out).unwrap();
    assert!(String::from_utf8(out).unwrap().ends_with("\r\n\r\nabc"));
    let e = Response::default().location().unwrap_err();
    assert_eq!(e.to_string(), "http: no Location header in response");
}

#[test]
fn head_response_keeps_content_length() {
    let raw = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n";
    let mut req = Request::default();
    req.method = "HEAD".into();
    let resp = read_response(
        &BufioReader::new(Cursor::new(raw.as_bytes().to_vec())),
        Some(&req),
    )
    .unwrap();
    assert_eq!(resp.content_length, 10);
    assert!(resp.body.unwrap().read_all().unwrap().is_empty());
}

#[test]
fn parse_form_urlencoded_and_query() {
    let mut r = Request::new("POST", "http://x/p?a=1&b=2")
        .map(|r| r.with_body("b=3&c=4"))
        .unwrap();
    r.header
        .set("Content-Type", "application/x-www-form-urlencoded");
    r.parse_form().unwrap();
    assert_eq!(r.form_value("a"), "1");
    assert_eq!(r.form_value("b"), "3");
    assert_eq!(r.post_form_value("b"), "3");
    assert_eq!(r.post_form_value("a"), "");
    assert_eq!(r.form.as_ref().unwrap().0["b"], vec!["3", "2"]);
}

#[test]
fn parse_multipart_form_and_form_file() {
    let body = "--XX\r\nContent-Disposition: form-data; name=\"k\"\r\n\r\nv\r\n--XX\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nfile data\r\n--XX--\r\n";
    let mut r = Request::new("POST", "http://x/")
        .map(|r| r.with_body(body))
        .unwrap();
    r.header
        .set("Content-Type", "multipart/form-data; boundary=XX");
    assert_eq!(r.form_value("k"), "v");
    let (mut f, fh) = r.form_file("f").unwrap();
    let mut s = String::new();
    f.read_to_string(&mut s).unwrap();
    assert_eq!(s, "file data");
    assert_eq!(fh.filename, "a.txt");
    assert_eq!(
        r.form_file("zz").unwrap_err().to_string(),
        "http: no such file"
    );
    let mut r2 = Request::new("POST", "http://x/")
        .map(|r| r.with_body("x"))
        .unwrap();
    assert_eq!(
        r2.parse_multipart_form(1 << 20).unwrap_err().to_string(),
        "request Content-Type isn't multipart/form-data"
    );
}

#[test]
fn max_bytes_reader_limits() {
    let b = max_bytes_reader(None, Body::from_bytes(vec![b'x'; 10]), 4);
    let mut b2 = b.clone();
    let mut got = Vec::new();
    let err = b2.read_to_end(&mut got).unwrap_err();
    assert_eq!(got.len(), 4);
    let inner = err
        .get_ref()
        .unwrap()
        .downcast_ref::<MaxBytesError>()
        .unwrap();
    assert_eq!(inner.limit, 4);
    assert_eq!(inner.to_string(), "http: request body too large");
}

#[test]
fn path_values_and_set_path_value() {
    let mux = ServeMux::new();
    mux.handle_func("/u/{id}/f/{rest...}", |w, r| {
        let mut r2 = r.clone();
        r2.set_path_value("id", "changed");
        r2.set_path_value("extra", "e");
        let _ = w.write(
            format!(
                "{}|{}|{}|{}",
                r.path_value("id"),
                r.path_value("rest"),
                r2.path_value("id"),
                r2.path_value("extra")
            )
            .as_bytes(),
        );
    })
    .unwrap();
    let rec = get(&mux, "", "GET", "/u/42/f/a/b");
    assert_eq!(rec.text(), "42|a/b|changed|e");
}

#[test]
fn mux_precedence_and_methods() {
    let mux = ServeMux::new();
    let tag = |s: &'static str| {
        move |w: &mut dyn ResponseWriter, _r: &mut Request| {
            let _ = w.write(s.as_bytes());
        }
    };
    mux.handle_func("/a/", tag("a-tree")).unwrap();
    mux.handle_func("/a/b", tag("a-b")).unwrap();
    mux.handle_func("GET /m", tag("get-m")).unwrap();
    mux.handle_func("POST /m", tag("post-m")).unwrap();
    mux.handle_func("example.com/h", tag("host-h")).unwrap();
    mux.handle_func("/x/{$}", tag("x-exact")).unwrap();
    mux.handle_func("/", tag("root")).unwrap();
    assert_eq!(get(&mux, "", "GET", "/zzz").text(), "root");
    assert_eq!(get(&mux, "", "GET", "/a/q").text(), "a-tree");
    assert_eq!(get(&mux, "", "GET", "/a/b").text(), "a-b");
    assert_eq!(get(&mux, "", "GET", "/m").text(), "get-m");
    assert_eq!(get(&mux, "", "HEAD", "/m").text(), "get-m");
    assert_eq!(get(&mux, "", "POST", "/m").text(), "post-m");
    assert_eq!(get(&mux, "example.com", "GET", "/h").text(), "host-h");
    assert_eq!(get(&mux, "", "GET", "/h").text(), "root");
    assert_eq!(get(&mux, "", "GET", "/x/").text(), "x-exact");
    assert_eq!(get(&mux, "", "GET", "/x/y").text(), "root");
    let only = ServeMux::new();
    only.handle_func("GET /m", tag("get-m")).unwrap();
    only.handle_func("POST /m", tag("post-m")).unwrap();
    let r = get(&only, "", "PUT", "/m");
    assert_eq!(r.code, 405);
    assert_eq!(r.get("Allow"), "GET, HEAD, POST");
    // Redirects: clean path and missing trailing slash.
    let r = get(&mux, "", "GET", "/a//b");
    assert_eq!((r.code, r.get("Location").as_str()), (307, "/a/b"));
    let r = get(&mux, "", "GET", "/a");
    assert_eq!((r.code, r.get("Location").as_str()), (307, "/a/"));
}

#[test]
fn mux_conflicts_and_invalid_patterns() {
    let mux = ServeMux::new();
    let h = || handler_func(|_, _| {});
    mux.handle("/a/{x}", h()).unwrap();
    let e = mux.handle("/a/{y}", h()).unwrap_err().to_string();
    assert!(e.contains("matches the same requests as"), "{e}");
    let e = mux.handle("/{x}/b", h()).unwrap_err().to_string();
    assert!(e.contains("both match some paths"), "{e}");
    assert!(mux.handle("GET /a/{x}", h()).is_ok());
    for (p, want) in [
        ("", "http: invalid pattern"),
        ("ab", "parsing \"ab\": at offset 0: host/path missing /"),
        (
            "/{x",
            "parsing \"/{x\": at offset 1: bad wildcard segment (must end with '}')",
        ),
        (
            "/{x}/{x}",
            "parsing \"/{x}/{x}\": at offset 5: duplicate wildcard name \"x\"",
        ),
        ("/{$}/a", "parsing \"/{$}/a\": at offset 1: {$} not at end"),
    ] {
        assert_eq!(mux.handle(p, h()).unwrap_err().to_string(), want);
    }
}

#[test]
fn mux_handler_lookup_and_star() {
    let mux = ServeMux::new();
    mux.handle("/p/", handler_func(|_, _| {})).unwrap();
    let req = parse("GET /p/x HTTP/1.1\r\nHost: a\r\n\r\n");
    let (_, pat) = mux.handler(&req);
    assert_eq!(pat, "/p/");
    let mut star = parse("OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n");
    let mut rec = Rec::default();
    mux.serve_http(&mut rec, &mut star);
    assert_eq!(rec.code, 400);
    assert_eq!(rec.get("Connection"), "close");
}

#[test]
fn redirect_strip_prefix_not_found() {
    let mut rec = Rec::default();
    let mut req = parse("GET /dir/page HTTP/1.1\r\nHost: a\r\n\r\n");
    redirect_handler("../up?x=1", STATUS_FOUND).serve_http(&mut rec, &mut req);
    assert_eq!(rec.code, 302);
    assert_eq!(rec.get("Location"), "/up?x=1");
    assert_eq!(rec.text(), "<a href=\"/up?x=1\">Found</a>.\n\n");

    let inner: Arc<dyn Handler> = handler_func(|w, r| {
        let _ = w.write(r.url.path.as_bytes());
    });
    let h = strip_prefix("/static", inner);
    let mut rec = Rec::default();
    let mut req = parse("GET /static/a.txt HTTP/1.1\r\nHost: a\r\n\r\n");
    h.serve_http(&mut rec, &mut req);
    assert_eq!(rec.text(), "/a.txt");
    let mut rec = Rec::default();
    let mut req = parse("GET /other HTTP/1.1\r\nHost: a\r\n\r\n");
    h.serve_http(&mut rec, &mut req);
    assert_eq!(rec.code, 404);
    assert_eq!(rec.text(), "404 page not found\n");
    let mut rec = Rec::default();
    not_found_handler().serve_http(&mut rec, &mut req);
    assert_eq!(rec.get("X-Content-Type-Options"), "nosniff");
}

#[test]
fn protocol_error_and_sentinels() {
    assert_eq!(http::ERR_NOT_SUPPORTED.to_string(), "feature not supported");
    assert!(http::ERR_NOT_SUPPORTED.is(&io::Error::other("unsupported operation")));
    assert_eq!(http::ERR_SERVER_CLOSED.to_string(), "http: Server closed");
    assert_eq!(
        http::ERR_ABORT_HANDLER.to_string(),
        "net/http: abort Handler"
    );
}

#[test]
fn protocols_bitset() {
    let mut p = http::Protocols::default();
    assert_eq!(p.to_string(), "{}");
    p.set_http1(true);
    p.set_unencrypted_http2(true);
    assert!(p.http1() && !p.http2() && p.unencrypted_http2());
    assert_eq!(p.to_string(), "{HTTP1,UnencryptedHTTP2}");
}
