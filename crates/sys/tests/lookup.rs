//! LookupAddr and LookupCNAME through the C library
//! (rust_stdlib_sys::net): the answer parser, the choice of resolver and the
//! error values. tools/dns_check.py compares the lookups with Go's cgo
//! resolver.
#![cfg(all(
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64"
))]

use rust_stdlib_sys::net::{
    is_domain_name, parse_cname_answer, DnsError, LookupOrder, PureResolver, Resolver,
};
use std::sync::{Arc, Mutex};

/// A response packet: header, one question, then the given answers.
fn packet(answers: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut p = vec![
        0x12,
        0x34,
        0x81,
        0x80,
        0,
        1,
        0,
        answers.len() as u8,
        0,
        0,
        0,
        0,
    ];
    for label in ["www", "example", "com"] {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.extend_from_slice(&[0, 0, 5, 0, 1]);
    for (typ, rdata) in answers {
        p.extend_from_slice(&[0xc0, 12]); // the question's name, compressed
        p.extend_from_slice(&typ.to_be_bytes());
        p.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
        p.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        p.extend_from_slice(rdata);
    }
    p
}

fn name(labels: &[&str]) -> Vec<u8> {
    let mut v = Vec::new();
    for l in labels {
        v.push(l.len() as u8);
        v.extend_from_slice(l.as_bytes());
    }
    v.push(0);
    v
}

#[test]
fn cname_answer_parsing() {
    let p = packet(&[(5, name(&["edge", "example", "net"]))]);
    assert_eq!(parse_cname_answer(&p).unwrap(), "edge.example.net.");
    // The target may use a compression pointer into the question.
    let p = packet(&[(5, vec![4, b'e', b'd', b'g', b'e', 0xc0, 16])]);
    assert_eq!(parse_cname_answer(&p).unwrap(), "edge.example.com.");
    // Only the first answer counts.
    let p = packet(&[(5, name(&["a", "b"])), (5, name(&["c", "d"]))]);
    assert_eq!(parse_cname_answer(&p).unwrap(), "a.b.");
    assert_eq!(
        parse_cname_answer(&packet(&[])).unwrap_err(),
        "no CNAME record received"
    );
    assert_eq!(
        parse_cname_answer(&packet(&[(1, vec![1, 2, 3, 4])])).unwrap_err(),
        "could not parse CNAME record"
    );
    assert!(parse_cname_answer(&[0; 5]).is_err());
    let mut cut = packet(&[(5, name(&["a", "b"]))]);
    cut.truncate(cut.len() - 3);
    assert!(parse_cname_answer(&cut).is_err());
    // A compression loop is rejected, not followed forever.
    let mut p = packet(&[(5, vec![0xc0, 0])]);
    let n = p.len();
    p[n - 1] = (n - 2) as u8;
    assert!(parse_cname_answer(&p).is_err());
}

#[test]
fn domain_names_follow_go() {
    for ok in [".", "a.b", "a-b.c_d.", "x1y", "localhost", "A.B.C."] {
        assert!(is_domain_name(ok), "{ok}");
    }
    for bad in [
        "",
        "bad name",
        "a..b",
        "-x",
        "x-.y",
        "1.2.3.4",
        "123",
        &"a".repeat(64),
        "a b.c",
        ".x",
    ] {
        assert!(!is_domain_name(bad), "{bad:?}");
    }
    assert!(is_domain_name(&format!("{}.", "a".repeat(63))));
}

#[test]
fn lookup_addr_errors_and_loopback() {
    let e = rust_stdlib_sys::net::lookup_addr("bogus").unwrap_err();
    assert_eq!(e.to_string(), "lookup bogus: invalid address");
    assert!(!e.is_not_found);
    assert!(rust_stdlib_sys::net::lookup_addr("").is_err());
    assert!(rust_stdlib_sys::net::lookup_addr("1.2.3").is_err());
    // /etc/hosts names the loopback address on every supported system.
    let names = rust_stdlib_sys::net::lookup_addr("127.0.0.1").unwrap();
    assert!(!names.is_empty());
    assert!(names.iter().all(|n| !n.is_empty()));
}

#[test]
fn lookup_cname_of_a_non_domain_name_is_no_such_host() {
    let e = rust_stdlib_sys::net::lookup_cname("bad name").unwrap_err();
    assert_eq!(e.to_string(), "lookup bad name: no such host");
    assert!(e.is_not_found);
}

struct Mock(Mutex<Vec<String>>);

impl PureResolver for Mock {
    fn lookup_addr(&self, addr: &str) -> Result<Vec<String>, DnsError> {
        self.0.lock().unwrap().push(format!("addr {addr}"));
        Ok(vec!["pure.test.".into()])
    }
    fn lookup_cname(&self, host: &str) -> Result<String, DnsError> {
        self.0.lock().unwrap().push(format!("cname {host}"));
        Ok("pure-cname.test.".into())
    }
}

#[test]
fn resolver_choice_and_pure_fallback() {
    // The environment is process-wide: keep every case in this one test.
    let saved: Vec<(&str, Option<String>)> =
        ["GODEBUG", "LOCALDOMAIN", "RES_OPTIONS", "HOSTALIASES"]
            .iter()
            .map(|k| (*k, std::env::var(k).ok()))
            .collect();
    for (k, _) in &saved {
        std::env::remove_var(k);
    }
    let mock = Arc::new(Mock(Mutex::new(Vec::new())));
    let pure = Resolver {
        prefer_builtin: true,
        pure: Some(mock.clone()),
    };
    // PreferGo always selects Go's resolver.
    assert_eq!(pure.lookup_order("example.com"), LookupOrder::Go);
    assert_eq!(pure.lookup_addr("127.0.0.1").unwrap(), ["pure.test."]);
    assert_eq!(
        pure.lookup_cname("example.com").unwrap(),
        "pure-cname.test."
    );
    // ... except that a name that is not a domain name never reaches it.
    assert!(pure.lookup_cname("bad name").unwrap_err().is_not_found);
    assert_eq!(mock.0.lock().unwrap().len(), 2);

    // Without a PureResolver the C library answers.
    let bare = Resolver {
        prefer_builtin: true,
        pure: None,
    };
    assert!(bare.lookup_addr("127.0.0.1").is_ok());

    let default = Resolver::default();
    if cfg!(target_os = "macos") {
        assert_eq!(default.lookup_order("example.com"), LookupOrder::Cgo);
    }
    std::env::set_var("GODEBUG", "other=1,netdns=go+1");
    assert_eq!(default.lookup_order("example.com"), LookupOrder::Go);
    std::env::set_var("GODEBUG", "netdns=1+cgo");
    assert_eq!(default.lookup_order("example.com"), LookupOrder::Cgo);
    assert_eq!(default.lookup_order(""), LookupOrder::Cgo);
    // PreferGo wins over netdns=cgo only when netdns is not forcing cgo...
    std::env::set_var("GODEBUG", "netdns=cgo");
    assert_eq!(pure.lookup_order("x"), LookupOrder::Go);
    std::env::set_var("GODEBUG", "netdns=2");
    std::env::set_var("RES_OPTIONS", "ndots:2");
    assert_eq!(default.lookup_order("example.com"), LookupOrder::Cgo);
    std::env::remove_var("RES_OPTIONS");
    std::env::set_var("LOCALDOMAIN", "");
    assert_eq!(default.lookup_order("example.com"), LookupOrder::Cgo);
    std::env::remove_var("LOCALDOMAIN");
    // Special host names go to the C library.
    assert_eq!(default.lookup_order("a%b"), LookupOrder::Cgo);
    assert_eq!(default.lookup_order("a\\b"), LookupOrder::Cgo);

    for (k, v) in saved {
        match v {
            Some(v) => std::env::set_var(k, v),
            None => std::env::remove_var(k),
        }
    }
}
