#![cfg(feature = "net")]
use rust_stdlib::net::http::cookiejar::{Jar, Options, PublicSuffixList};
use rust_stdlib::net::http::{Cookie, TIME_FORMAT};
use rust_stdlib::net::url::{self, Url};
use rust_stdlib::time;
use std::fmt;

/// Mirrors Go's cookiejar tests: a list of public suffixes where the longest
/// matching suffix wins.
struct Suffixes(&'static [&'static str]);

impl fmt::Display for Suffixes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("test-suffixes")
    }
}

impl PublicSuffixList for Suffixes {
    fn public_suffix(&self, domain: &str) -> String {
        self.0
            .iter()
            .filter(|s| domain == **s || domain.ends_with(&format!(".{s}")))
            .max_by_key(|s| s.len())
            .map_or_else(String::new, |s| (*s).to_owned())
    }
}

fn url(raw: &str) -> Url {
    url::parse(raw).unwrap()
}

fn set_cookie(name: &str, value: &str) -> Cookie {
    Cookie {
        name: name.into(),
        value: value.into(),
        ..Cookie::default()
    }
}

fn pairs(cookies: &[Cookie]) -> Vec<(&str, &str)> {
    cookies
        .iter()
        .map(|c| (c.name.as_str(), c.value.as_str()))
        .collect()
}

#[test]
fn host_only_cookies_match_their_host_and_path() {
    let jar = Jar::new(None).unwrap();
    let mut cookie = set_cookie("sid", "1");
    cookie.path = "/a".into();
    jar.set_cookies(&url("https://example.com/a/x"), &[cookie]);

    assert_eq!(
        pairs(&jar.cookies(&url("https://example.com/a/b"))),
        [("sid", "1")]
    );
    assert_eq!(pairs(&jar.cookies(&url("https://example.com/ab"))), []);
    assert_eq!(pairs(&jar.cookies(&url("https://sub.example.com/a"))), []);
}

#[test]
fn domain_cookies_reach_subdomains_but_not_public_suffixes() {
    let jar = Jar::new(Some(Options {
        public_suffix_list: Some(Box::new(Suffixes(&["com", "co.uk"]))),
    }))
    .unwrap();
    let mut domain = set_cookie("d", "1");
    domain.domain = ".example.com".into();
    jar.set_cookies(&url("http://www.example.com/"), &[domain]);
    assert_eq!(
        pairs(&jar.cookies(&url("http://a.example.com/"))),
        [("d", "1")]
    );

    let mut suffix = set_cookie("s", "1");
    suffix.domain = "com".into();
    jar.set_cookies(&url("http://www.example.com/"), &[suffix]);
    let mut suffix_uk = set_cookie("u", "1");
    suffix_uk.domain = "co.uk".into();
    jar.set_cookies(&url("http://www.example.co.uk/"), &[suffix_uk]);
    assert_eq!(pairs(&jar.cookies(&url("http://other.com/"))), []);
    assert_eq!(pairs(&jar.cookies(&url("http://example.co.uk/"))), []);
}

#[test]
fn domain_attribute_must_match_the_request_host() {
    let jar = Jar::new(None).unwrap();
    let mut cookie = set_cookie("x", "1");
    cookie.domain = "other.org".into();
    jar.set_cookies(&url("http://example.com/"), &[cookie]);
    assert_eq!(pairs(&jar.cookies(&url("http://example.com/"))), []);
    assert_eq!(pairs(&jar.cookies(&url("http://other.org/"))), []);
}

#[test]
fn expired_and_deleted_cookies_are_not_returned() {
    let jar = Jar::new(None).unwrap();
    let mut past = set_cookie("p", "1");
    past.expires = time::Time::parse(TIME_FORMAT, "Sat, 01 Jan 2000 00:00:00 GMT").unwrap();
    let mut future = set_cookie("f", "1");
    future.expires = time::Time::parse(TIME_FORMAT, "Sun, 01 Jan 2090 00:00:00 GMT").unwrap();
    let mut age = set_cookie("m", "1");
    age.max_age = 3600;
    let mut gone = set_cookie("g", "1");
    gone.max_age = -1;
    jar.set_cookies(&url("https://example.com/"), &[past, future, age, gone]);
    assert_eq!(
        pairs(&jar.cookies(&url("https://example.com/"))),
        [("f", "1"), ("m", "1")]
    );
}

#[test]
fn cookies_are_ordered_by_path_length_then_creation() {
    let jar = Jar::new(None).unwrap();
    let mut root = set_cookie("root", "1");
    root.path = "/".into();
    let mut deep = set_cookie("deep", "1");
    deep.path = "/a/b".into();
    let mut shallow = set_cookie("shallow", "1");
    shallow.path = "/a".into();
    jar.set_cookies(&url("https://example.com/a/b/c"), &[root, deep, shallow]);
    assert_eq!(
        pairs(&jar.cookies(&url("https://example.com/a/b/c"))),
        [("deep", "1"), ("shallow", "1"), ("root", "1")]
    );
}

#[test]
fn secure_cookies_need_https_except_for_loopback() {
    let jar = Jar::new(None).unwrap();
    let mut secure = set_cookie("s", "1");
    secure.secure = true;
    jar.set_cookies(&url("http://localhost/"), &[secure.clone()]);
    jar.set_cookies(&url("http://example.com/"), &[secure]);
    assert_eq!(pairs(&jar.cookies(&url("http://localhost/"))), [("s", "1")]);
    assert_eq!(pairs(&jar.cookies(&url("http://example.com/"))), []);
    assert_eq!(
        pairs(&jar.cookies(&url("https://example.com/"))),
        [("s", "1")]
    );
}

#[test]
fn non_http_schemes_are_ignored() {
    let jar = Jar::new(None).unwrap();
    jar.set_cookies(&url("ftp://example.com/"), &[set_cookie("a", "1")]);
    assert_eq!(pairs(&jar.cookies(&url("ftp://example.com/"))), []);
    assert_eq!(pairs(&jar.cookies(&url("http://example.com/"))), []);
}

#[test]
fn non_ascii_hosts_use_punycode_labels() {
    let jar = Jar::new(None).unwrap();
    jar.set_cookies(&url("https://bücher.example.com/"), &[set_cookie("b", "1")]);
    assert_eq!(
        pairs(&jar.cookies(&url("https://xn--bcher-kva.example.com/"))),
        [("b", "1")]
    );
}

#[test]
fn replacing_a_cookie_keeps_its_position() {
    let jar = Jar::new(None).unwrap();
    let first = set_cookie("a", "1");
    let second = set_cookie("b", "1");
    jar.set_cookies(&url("https://example.com/"), &[first, second]);
    jar.set_cookies(&url("https://example.com/"), &[set_cookie("a", "2")]);
    assert_eq!(
        pairs(&jar.cookies(&url("https://example.com/"))),
        [("a", "2"), ("b", "1")]
    );
}

#[test]
fn quoted_flag_is_stored_and_returned() {
    let jar = Jar::new(None).unwrap();
    let u = url("http://example.com/");
    let mut quoted = set_cookie("q", "v");
    quoted.quoted = true;
    jar.set_cookies(&u, &[quoted, set_cookie("p", "w")]);
    let got = jar.cookies(&u);
    let flags: Vec<(&str, bool)> = got.iter().map(|c| (c.name.as_str(), c.quoted)).collect();
    assert_eq!(flags, [("q", true), ("p", false)]);
}

#[test]
fn expiry_is_compared_with_nanosecond_resolution() {
    const SEC: i128 = 1_000_000_000;
    let jar = Jar::new(None).unwrap();
    let u = url("http://example.com/");
    let t0 = 1_700_000_000 * SEC + 500_000_000; // .5 s into a second
    let mut c = set_cookie("a", "1");
    c.max_age = 10;
    jar.set_cookies_at(&u, &[c], t0);
    // Expires at t0 + 10 s exactly: still sent just before, gone at the instant.
    assert_eq!(jar.cookies_at(&u, t0 + 10 * SEC - 1).len(), 1);
    assert_eq!(jar.cookies_at(&u, t0 + 10 * SEC).len(), 0);
}
