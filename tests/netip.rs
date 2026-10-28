//! Tables ported from Go's net/netip/netip_test.go (see NOTICE).
use rust_stdlib::net::netip::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

fn parse_addr(s: &str) -> Result<Addr, Error> {
    s.parse()
}

fn parse_addr_port(s: &str) -> Result<AddrPort, Error> {
    s.parse()
}

fn parse_prefix(s: &str) -> Result<Prefix, Error> {
    s.parse()
}

fn must_parse_addr(s: &str) -> Addr {
    s.parse().unwrap()
}

fn must_parse_prefix(s: &str) -> Prefix {
    s.parse().unwrap()
}

fn err(s: &str) -> String {
    parse_addr(s).unwrap_err().to_string()
}

#[test]
fn parse_addr_valid_forms() {
    let ok = [
        ("0.0.0.0", "0.0.0.0"),
        ("1.2.3.4", "1.2.3.4"),
        ("255.255.255.255", "255.255.255.255"),
        ("::", "::"),
        ("::1", "::1"),
        ("1::", "1::"),
        ("1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8"),
        ("2001:db8:0:0:0:0:0:1", "2001:db8::1"),
        ("2001:0DB8::0001", "2001:db8::1"),
        ("1:0:0:2:0:0:0:3", "1:0:0:2::3"),
        ("1:0:2:0:0:3:0:4", "1:0:2::3:0:4"),
        ("::ffff:1.2.3.4", "::ffff:1.2.3.4"),
        ("0:0:0:0:0:ffff:1.2.3.4", "::ffff:1.2.3.4"),
        ("::1.2.3.4", "::102:304"),
        ("1::1.2.3.4", "1::102:304"),
        ("fe80::1%eth0", "fe80::1%eth0"),
        ("::ffff:1.2.3.4%eth0", "::ffff:1.2.3.4%eth0"),
        ("::%x", "::%x"),
    ];
    for (input, want) in ok {
        assert_eq!(parse_addr(input).unwrap().to_string(), want, "{input}");
    }
}

#[test]
fn parse_addr_errors() {
    let cases = [
        ("", "ParseAddr(\"\"): unable to parse IP"),
        ("bad", "ParseAddr(\"bad\"): unable to parse IP"),
        ("%eth0", "ParseAddr(\"%eth0\"): missing IPv6 address"),
        ("1.2.3", "ParseAddr(\"1.2.3\"): IPv4 address too short"),
        ("1.2.3.4.5", "ParseAddr(\"1.2.3.4.5\"): IPv4 address too long"),
        ("01.2.3.4", "ParseAddr(\"01.2.3.4\"): IPv4 field has octet with leading zero"),
        ("256.2.3.4", "ParseAddr(\"256.2.3.4\"): IPv4 field has value >255"),
        ("1..3.4", "ParseAddr(\"1..3.4\"): IPv4 field must have at least one digit (at \".3.4\")"),
        ("1.2.3.a", "ParseAddr(\"1.2.3.a\"): unexpected character (at \"a\")"),
        ("fe80::1%", "ParseAddr(\"fe80::1%\"): zone must be a non-empty string"),
        ("1:2:3:4:5:6:7", "ParseAddr(\"1:2:3:4:5:6:7\"): address string too short"),
        ("1::2::3", "ParseAddr(\"1::2::3\"): multiple :: in address (at \":3\")"),
        ("1:2:3:4:5:6:7::8", "ParseAddr(\"1:2:3:4:5:6:7::8\"): the :: must expand to at least one field of zeros"),
        ("12345::", "ParseAddr(\"12345::\"): each group must have 4 or less digits (at \"12345::\")"),
        ("1:", "ParseAddr(\"1:\"): colon must be followed by more characters (at \":\")"),
        ("1:2:3:4:5:6:7:8:9", "ParseAddr(\"1:2:3:4:5:6:7:8:9\"): trailing garbage after address (at \"9\")"),
        ("1:g::", "ParseAddr(\"1:g::\"): each colon-separated field must have at least one digit (at \"g::\")"),
        ("1.2.3.4::", "ParseAddr(\"1.2.3.4::\"): unexpected character (at \"::\")"),
    ];
    for (input, want) in cases {
        assert_eq!(err(input), want, "{input}");
    }
}

#[test]
fn zero_addr_and_constants() {
    let z = Addr::default();
    assert!(!z.is_valid());
    assert_eq!(z.to_string(), "invalid IP");
    assert_eq!(z.bit_len(), 0);
    assert_eq!(z.marshal_text().unwrap(), b"");
    assert_ne!(z, Addr::from(Ipv4Addr::UNSPECIFIED));
    assert_ne!(
        Addr::from(Ipv4Addr::UNSPECIFIED),
        Addr::from(Ipv6Addr::UNSPECIFIED)
    );
    assert_eq!(Addr::from(Ipv6Addr::LOCALHOST).to_string(), "::1");
    assert_eq!(Addr::from(IPV6_LINK_LOCAL_ALL_NODES).to_string(), "ff02::1");
    assert_eq!(
        Addr::from(IPV6_LINK_LOCAL_ALL_ROUTERS).to_string(),
        "ff02::2"
    );
    assert!(
        Addr::from(Ipv4Addr::UNSPECIFIED).is_unspecified()
            && Addr::from(Ipv6Addr::UNSPECIFIED).is_unspecified()
    );
}

#[test]
fn classification() {
    let p = |s: &str| must_parse_addr(s);
    assert!(
        p("10.1.1.1").is_private() && p("172.16.0.1").is_private() && p("192.168.1.1").is_private()
    );
    assert!(
        !p("172.32.0.1").is_private()
            && p("fc00::1").is_private()
            && p("::ffff:10.0.0.1").is_private()
    );
    assert!(
        p("127.0.0.1").is_loopback()
            && p("::1").is_loopback()
            && p("::ffff:127.0.0.1").is_loopback()
    );
    assert!(p("224.0.0.1").is_multicast() && p("ff02::1").is_multicast());
    assert!(p("224.0.0.5").is_link_local_multicast() && p("ff02::1").is_link_local_multicast());
    assert!(p("ff01::1").is_interface_local_multicast());
    assert!(p("169.254.1.1").is_link_local_unicast() && p("fe80::1").is_link_local_unicast());
    assert!(p("8.8.8.8").is_global_unicast() && p("2001:db8::1").is_global_unicast());
    assert!(!p("0.0.0.0").is_global_unicast() && !p("255.255.255.255").is_global_unicast());
    assert!(!Addr::default().is_global_unicast());
}

#[test]
fn next_prev_and_overflow() {
    assert_eq!(must_parse_addr("1.2.3.255").next().to_string(), "1.2.4.0");
    assert_eq!(must_parse_addr("255.255.255.255").next(), Addr::default());
    assert_eq!(must_parse_addr("0.0.0.0").prev(), Addr::default());
    assert_eq!(must_parse_addr("::").prev(), Addr::default());
    assert_eq!(
        must_parse_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").next(),
        Addr::default()
    );
    assert_eq!(
        must_parse_addr("::ffff:255.255.255.255").next().to_string(),
        "::1:0:0:0"
    );
    assert_eq!(must_parse_addr("fe80::%x").next().to_string(), "fe80::1%x");
}

#[test]
fn conversions_and_ordering() {
    assert_eq!(
        Addr::try_from(&[1, 2, 3, 4][..]).unwrap().to_string(),
        "1.2.3.4"
    );
    assert!(Addr::try_from(&[1, 2, 3][..]).is_err());
    let mapped = Addr::from(must_parse_addr("1.2.3.4").as16());
    assert!(mapped.is4in6() && !mapped.is4());
    assert_eq!(mapped.unmap(), must_parse_addr("1.2.3.4"));
    assert_eq!(mapped.as4(), [1, 2, 3, 4]);
    assert_eq!(must_parse_addr("fe80::1%a").with_zone("").zone(), "");
    assert_eq!(must_parse_addr("1.2.3.4").with_zone("x").zone(), "");
    let mut ips: Vec<Addr> = [
        "::1",
        "1.2.3.4",
        "fe80::1%b",
        "fe80::1",
        "0.0.0.0",
        "fe80::1%a",
    ]
    .iter()
    .map(|s| must_parse_addr(s))
    .collect();
    ips.push(Addr::default());
    ips.sort();
    let got: Vec<String> = ips.iter().map(|i| i.to_string()).collect();
    assert_eq!(
        got,
        [
            "invalid IP",
            "0.0.0.0",
            "1.2.3.4",
            "::1",
            "fe80::1",
            "fe80::1%a",
            "fe80::1%b"
        ]
    );
    let std4: Addr = Ipv4Addr::new(1, 2, 3, 4).into();
    let std6: Addr = Ipv6Addr::LOCALHOST.into();
    assert_eq!(
        IpAddr::try_from(&std4).ok(),
        Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
    );
    assert_eq!(
        IpAddr::try_from(&std6).ok(),
        Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
    );
    assert_eq!(IpAddr::try_from(&Addr::default()).ok(), None);
}

#[test]
#[should_panic(expected = "As4 called on IPv6 address")]
fn as4_panics_on_ipv6() {
    must_parse_addr("::1").as4();
}

#[test]
fn text_and_binary() {
    let ip = must_parse_addr("fe80::1%eth0");
    assert_eq!(
        ip.string_expanded(),
        "fe80:0000:0000:0000:0000:0000:0000:0001%eth0"
    );
    let b = ip.marshal_binary().unwrap();
    assert_eq!(b.len(), 16 + 4);
    let mut back = Addr::default();
    back.unmarshal_binary(&b).unwrap();
    assert_eq!(back, ip);
    assert_eq!(
        back.unmarshal_binary(&[1, 2, 3]).unwrap_err().to_string(),
        "unexpected slice size"
    );
    back.unmarshal_text(b"").unwrap();
    assert!(!back.is_valid());
}

#[test]
fn addr_port() {
    for (s, want) in [
        ("1.2.3.4:80", "1.2.3.4:80"),
        ("[::1]:0", "[::1]:0"),
        ("[fe80::1%eth0]:65535", "[fe80::1%eth0]:65535"),
        ("[::ffff:1.2.3.4]:5", "[::ffff:1.2.3.4]:5"),
    ] {
        assert_eq!(parse_addr_port(s).unwrap().to_string(), want);
    }
    let errs = [
        ("1.2.3.4", "not an ip:port"),
        (":80", "no IP"),
        ("1.2.3.4:", "no port"),
        ("[::1:80", "missing ]"),
        ("1.2.3.4:65536", "invalid port \"65536\" parsing \"1.2.3.4:65536\""),
        ("[1.2.3.4]:80", "invalid ip:port \"[1.2.3.4]:80\", square brackets can only be used with IPv6 addresses"),
        ("::1:80", "invalid ip:port \"::1:80\", IPv6 addresses must be surrounded by square brackets"),
    ];
    for (s, want) in errs {
        assert_eq!(parse_addr_port(s).unwrap_err().to_string(), want, "{s}");
    }
    let p = AddrPort::new(must_parse_addr("::1"), 8080);
    assert_eq!(p.marshal_binary().unwrap().len(), 16 + 2);
    assert_eq!(AddrPort::default().to_string(), "invalid AddrPort");
    assert!(SocketAddr::try_from(&p).unwrap().is_ipv6());
}

#[test]
fn prefixes() {
    let p = must_parse_prefix("192.168.1.77/24");
    assert_eq!(p.bits(), 24);
    assert_eq!(p.masked().to_string(), "192.168.1.0/24");
    assert!(p.contains(&must_parse_addr("192.168.1.200")));
    assert!(!p.contains(&must_parse_addr("192.168.2.1")));
    assert!(!p.contains(&must_parse_addr("::ffff:192.168.1.1")));
    assert!(!must_parse_prefix("fe80::/10").contains(&must_parse_addr("fe80::1%eth0")));
    assert!(must_parse_prefix("10.0.0.0/8").overlaps(&must_parse_prefix("10.1.0.0/16")));
    assert!(!must_parse_prefix("10.0.0.0/8").overlaps(&must_parse_prefix("11.0.0.0/8")));
    assert!(must_parse_prefix("1.2.3.4/32").is_single_ip());
    assert_eq!(Prefix::new(must_parse_addr("1.2.3.4"), 33).bits(), -1);
    assert_eq!(
        Prefix::new(must_parse_addr("1.2.3.4"), 33).to_string(),
        "invalid Prefix"
    );
    assert_eq!(
        Prefix::new(must_parse_addr("fe80::1%x"), 64).addr().zone(),
        ""
    );
    assert_eq!(
        must_parse_prefix("::ffff:1.2.3.4/96").to_string(),
        "::ffff:1.2.3.4/96"
    );
    let errs = [
        ("1.2.3.4", "netip.ParsePrefix(\"1.2.3.4\"): no '/'"),
        (
            "1.2.3.4/33",
            "netip.ParsePrefix(\"1.2.3.4/33\"): prefix length out of range",
        ),
        (
            "1.2.3.4/+8",
            "netip.ParsePrefix(\"1.2.3.4/+8\"): bad bits after slash: \"+8\"",
        ),
        (
            "1.2.3.4/08",
            "netip.ParsePrefix(\"1.2.3.4/08\"): bad bits after slash: \"08\"",
        ),
        (
            "fe80::1%x/64",
            "netip.ParsePrefix(\"fe80::1%x/64\"): IPv6 zones cannot be present in a prefix",
        ),
        (
            "x/8",
            "netip.ParsePrefix(\"x/8\"): ParseAddr(\"x\"): unable to parse IP",
        ),
    ];
    for (s, want) in errs {
        assert_eq!(parse_prefix(s).unwrap_err().to_string(), want, "{s}");
    }
    assert_eq!(
        must_parse_addr("1.2.3.4")
            .prefix(33)
            .unwrap_err()
            .to_string(),
        "prefix length 33 too large for IPv4"
    );
    assert_eq!(
        must_parse_addr("::1").prefix(-1).unwrap_err().to_string(),
        "negative Prefix bits"
    );
    assert_eq!(Addr::default().prefix(5).unwrap(), Prefix::default());
    assert_eq!(Prefix::default().to_string(), "invalid Prefix");
    assert_eq!(Prefix::default().marshal_text().unwrap(), b"");
}
