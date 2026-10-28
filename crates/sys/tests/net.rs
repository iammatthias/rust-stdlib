//! Pure address and parsing tests, ported from Go's `net` tests
//! (`TestSplitHostPort`, `TestJoinHostPort`, `TestIPNetString`, ...).
use rust_stdlib_sys::net::{
    self, Addr, Cause, Flags, IPAddr, IPNet, TCPAddr, UDPAddr, FLAG_LOOPBACK, FLAG_RUNNING, FLAG_UP,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn split_host_port_accepts_go_forms() {
    for (hostport, host, port) in [
        ("localhost:http", "localhost", "http"),
        ("localhost:80", "localhost", "80"),
        ("localhost%lo0:http", "localhost%lo0", "http"),
        ("localhost%lo0:80", "localhost%lo0", "80"),
        ("[localhost%lo0]:http", "localhost%lo0", "http"),
        ("[localhost%lo0]:80", "localhost%lo0", "80"),
        ("127.0.0.1:http", "127.0.0.1", "http"),
        ("127.0.0.1:80", "127.0.0.1", "80"),
        ("[::1]:http", "::1", "http"),
        ("[::1]:80", "::1", "80"),
        ("[::1%lo0]:http", "::1%lo0", "http"),
        ("[::1%lo0]:80", "::1%lo0", "80"),
        (":http", "", "http"),
        (":80", "", "80"),
        ("golang.org:", "golang.org", ""),
        ("127.0.0.1:", "127.0.0.1", ""),
        ("[::1]:", "::1", ""),
        ("golang.org:https%foo", "golang.org", "https%foo"),
    ] {
        assert_eq!(
            net::split_host_port(hostport),
            Ok((host.to_string(), port.to_string())),
            "{hostport}"
        );
    }
}

#[test]
fn split_host_port_rejects_go_forms() {
    for (hostport, why) in [
        ("golang.org", "missing port in address"),
        ("127.0.0.1", "missing port in address"),
        ("[::1]", "missing port in address"),
        ("[fe80::1%lo0]", "missing port in address"),
        ("[localhost%lo0]", "missing port in address"),
        ("localhost%lo0", "missing port in address"),
        ("::1", "too many colons in address"),
        ("fe80::1%lo0", "too many colons in address"),
        ("fe80::1%lo0:80", "too many colons in address"),
        ("[foo:bar]", "missing port in address"),
        ("[foo:bar]baz", "missing port in address"),
        ("[foo]bar:baz", "missing port in address"),
        ("[foo]:[bar]:baz", "too many colons in address"),
        ("[foo]:[bar]baz", "unexpected '[' in address"),
        ("foo[bar]:baz", "unexpected '[' in address"),
        ("foo]bar:baz", "unexpected ']' in address"),
        ("[::1", "missing ']' in address"),
    ] {
        let err = net::split_host_port(hostport).expect_err(hostport);
        let Cause::Address(text) = err else {
            panic!("{hostport}: not an address error");
        };
        // Go's AddrError prints as "address <addr>: <why>".
        assert_eq!(text, format!("address {hostport}: {why}"), "{hostport}");
    }
}

#[test]
fn join_host_port_brackets_literal_ipv6() {
    for (host, port, want) in [
        ("localhost", "http", "localhost:http"),
        ("localhost", "80", "localhost:80"),
        ("localhost%lo0", "80", "localhost%lo0:80"),
        ("127.0.0.1", "80", "127.0.0.1:80"),
        ("::1", "http", "[::1]:http"),
        ("::1%lo0", "80", "[::1%lo0]:80"),
        ("", "80", ":80"),
        ("golang.org", "", "golang.org:"),
    ] {
        assert_eq!(net::join_host_port(host, port), want);
    }
}

#[test]
fn lookup_port_numbers_and_services() {
    assert_eq!(net::lookup_port("tcp", ""), Ok(0));
    assert_eq!(net::lookup_port("tcp", "80"), Ok(80));
    assert_eq!(net::lookup_port("tcp", "+80"), Ok(80));
    assert_eq!(net::lookup_port("udp", "65535"), Ok(65535));
    assert_eq!(net::lookup_port("tcp", "http"), Ok(80));
    assert_eq!(net::lookup_port("tcp", "HTTPS"), Ok(443));
    assert_eq!(net::lookup_port("udp", "domain"), Ok(53));
    for (service, want) in [
        ("65536", "address 65536: invalid port"),
        ("99999999999999", "address 99999999999999: invalid port"),
        ("-5", "address -5: invalid port"),
    ] {
        assert_eq!(
            net::lookup_port("tcp", service).unwrap_err().to_string(),
            want
        );
    }
    assert_eq!(
        net::lookup_port("tcp", "no-such-service")
            .unwrap_err()
            .to_string(),
        "lookup tcp/no-such-service: unknown port"
    );
    assert_eq!(
        net::lookup_port("bogus", "http").unwrap_err().to_string(),
        "address bogus: unknown network"
    );
}

#[test]
fn parse_network_matches_go() {
    assert_eq!(net::parse_network("tcp", false), Ok(("tcp".into(), 0)));
    assert_eq!(net::parse_network("udp6", true), Ok(("udp6".into(), 0)));
    assert_eq!(
        net::parse_network("unixpacket", true),
        Ok(("unixpacket".into(), 0))
    );
    assert_eq!(net::parse_network("ip", false), Ok(("ip".into(), 0)));
    assert!(net::parse_network("ip", true).is_err());
    assert_eq!(net::parse_network("ip4:icmp", true), Ok(("ip4".into(), 1)));
    assert_eq!(
        net::parse_network("ip6:ipv6-icmp", true),
        Ok(("ip6".into(), 58))
    );
    assert_eq!(net::parse_network("ip:47", true), Ok(("ip".into(), 47)));
    assert_eq!(
        net::parse_network("tcp4", true).map(|r| r.0),
        Ok("tcp4".to_string())
    );
    assert_eq!(
        net::parse_network("nonsense", true)
            .unwrap_err()
            .to_string(),
        "unknown network nonsense"
    );
    assert_eq!(
        net::parse_network("tcp:80", true).unwrap_err().to_string(),
        "unknown network tcp:80"
    );
    assert_eq!(
        net::parse_network("ip4:no-such-proto", true)
            .unwrap_err()
            .to_string(),
        "address no-such-proto: unknown IP protocol specified"
    );
}

#[test]
fn resolve_addr_list_literals() {
    let addrs = net::resolve_addr_list("dial", "tcp", "127.0.0.1:8080", None).unwrap();
    assert_eq!(addrs.len(), 1);
    assert_eq!(addrs[0].to_string(), "127.0.0.1:8080");
    assert_eq!(addrs[0].network(), "tcp");
    let addrs = net::resolve_addr_list("listen", "udp", ":53", None).unwrap();
    assert_eq!(addrs[0].to_string(), ":53");
    assert!(addrs[0].is_wildcard());
    let v6 = net::resolve_addr_list("dial", "tcp", "[::1]:80", None).unwrap();
    assert_eq!(v6[0].to_string(), "[::1]:80");
    let zone = net::resolve_addr_list("dial", "tcp", "[fe80::1%lo0]:80", None).unwrap();
    assert_eq!(zone[0].to_string(), "[fe80::1%lo0]:80");
    let ip = net::resolve_addr_list("dial", "ip4:icmp", "127.0.0.1", None).unwrap();
    assert_eq!(ip[0].to_string(), "127.0.0.1");
    assert_eq!(ip[0].network(), "ip");
    let unix = net::resolve_addr_list("dial", "unixgram", "/tmp/x", None).unwrap();
    assert_eq!(unix[0].network(), "unixgram");
    assert_eq!(
        net::resolve_addr_list("dial", "tcp", "", None).unwrap_err(),
        Cause::MissingAddress
    );
    assert!(net::resolve_addr_list("dial", "tcp4", "[::1]:80", None)
        .unwrap_err()
        .to_string()
        .ends_with("no suitable address found"));
}

#[test]
fn ipnet_string_matches_go() {
    let v4 = |a, b, c, d| IpAddr::V4(Ipv4Addr::new(a, b, c, d));
    let v6 = |s: &str| IpAddr::V6(s.parse::<Ipv6Addr>().unwrap());
    let cases = [
        (
            IPNet {
                ip: v4(192, 168, 1, 0),
                mask: vec![255, 255, 255, 192],
            },
            "192.168.1.0/26",
        ),
        (
            IPNet {
                ip: v4(192, 168, 1, 0),
                mask: vec![255, 0, 255, 0],
            },
            "192.168.1.0/ff00ff00",
        ),
        (
            IPNet {
                ip: v6("2001:db8::"),
                mask: [vec![0xff; 6], vec![0; 10]].concat(),
            },
            "2001:db8::/48",
        ),
        (
            IPNet {
                ip: v6("2001:db8::"),
                mask: vec![
                    0x80, 0, 0xf1, 0x23, 0, 0, 0xca, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
            },
            "2001:db8::/8000f1230000cafe0000000000000000",
        ),
    ];
    for (net, want) in cases {
        assert_eq!(net.to_string(), want);
        assert_eq!(net.network(), "ip+net");
    }
}

#[test]
fn ip_string_follows_go() {
    for (ip, want) in [
        ("1.2.3.4", "1.2.3.4"),
        ("::", "::"),
        ("::1", "::1"),
        ("2001:db8::1", "2001:db8::1"),
        ("2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"),
        ("2001:0:0:1:0:0:0:1", "2001:0:0:1::1"),
        ("1:0:3:4:5:6:7:8", "1:0:3:4:5:6:7:8"),
        ("::ffff:1.2.3.4", "1.2.3.4"),
        ("fe80::1", "fe80::1"),
    ] {
        let ip: IpAddr = ip.parse().unwrap();
        assert_eq!(net::ip_string(&ip), want);
    }
}

#[test]
fn address_types_print_like_go() {
    let tcp = TCPAddr {
        ip: Some("127.0.0.1".parse().unwrap()),
        port: 80,
        zone: String::new(),
    };
    assert_eq!(tcp.to_string(), "127.0.0.1:80");
    let wildcard = TCPAddr {
        ip: None,
        port: 8080,
        zone: String::new(),
    };
    assert_eq!(wildcard.to_string(), ":8080");
    let zoned = UDPAddr {
        ip: Some("fe80::1".parse().unwrap()),
        port: 1,
        zone: "en0".into(),
    };
    assert_eq!(zoned.to_string(), "[fe80::1%en0]:1");
    assert_eq!(zoned.network(), "udp");
    let ip = IPAddr {
        ip: Some("fe80::1".parse().unwrap()),
        zone: "en0".into(),
    };
    assert_eq!(ip.to_string(), "fe80::1%en0");
    assert_eq!(
        IPAddr {
            ip: None,
            zone: String::new()
        }
        .to_string(),
        ""
    );
}

#[test]
fn interface_flags_print_like_go() {
    assert_eq!(Flags(0).to_string(), "0");
    assert_eq!(FLAG_UP.to_string(), "up");
    assert_eq!(
        Flags(FLAG_UP.0 | FLAG_LOOPBACK.0 | FLAG_RUNNING.0).to_string(),
        "up|loopback|running"
    );
    assert_eq!(
        net::hardware_addr_string(&[0, 0x1a, 0xff, 0x10]),
        "00:1a:ff:10"
    );
    assert_eq!(net::hardware_addr_string(&[]), "");
}

#[test]
fn op_error_formats_like_go() {
    let e = net::OpError {
        op: "dial".into(),
        net: "tcp".into(),
        source: Some("127.0.0.1:1".into()),
        addr: Some("127.0.0.1:2".into()),
        err: Cause::Timeout,
    };
    assert_eq!(
        e.to_string(),
        "dial tcp 127.0.0.1:1->127.0.0.1:2: i/o timeout"
    );
    assert!(e.timeout());
    let e = net::OpError {
        op: "listen".into(),
        net: "tcp".into(),
        source: None,
        addr: Some(":80".into()),
        err: Cause::MissingAddress,
    };
    assert_eq!(e.to_string(), "listen tcp :80: missing address");
    assert!(!e.timeout());
    assert_eq!(
        net::OpError::new("route", Cause::NoSuchInterface).to_string(),
        "route: no such network interface"
    );
}

#[cfg(all(
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64"
))]
mod supported {
    use super::*;

    #[test]
    fn strip_ipv4_header_matches_go() {
        // 20-byte header (version 4, IHL 5) then "payload".
        let mut packet = vec![0x45u8; 1];
        packet.extend_from_slice(&[0; 19]);
        packet.extend_from_slice(b"payload");
        let n = packet.len();
        let got = net::strip_ipv4_header(n, &mut packet);
        assert_eq!(got, 7);
        assert_eq!(&packet[..7], b"payload");
        // IHL 6 (24-byte header).
        let mut packet = vec![0x46u8];
        packet.extend_from_slice(&[0; 23]);
        packet.extend_from_slice(b"xy");
        let n = packet.len();
        assert_eq!(net::strip_ipv4_header(n, &mut packet), 2);
        assert_eq!(&packet[..2], b"xy");
        // Too short, not IPv4, or bad IHL: left alone.
        let mut short = vec![0x45u8; 10];
        assert_eq!(net::strip_ipv4_header(10, &mut short), 10);
        let mut v6 = vec![0x60u8; 40];
        assert_eq!(net::strip_ipv4_header(40, &mut v6), 40);
        let mut bad = vec![0x44u8; 40];
        assert_eq!(net::strip_ipv4_header(40, &mut bad), 40);
    }

    #[test]
    fn unix_rights_round_trip() {
        let oob = net::unix_rights(&[3, 7, 9]);
        assert_eq!(net::parse_unix_rights(&oob), Ok(vec![3, 7, 9]));
        assert!(net::parse_unix_rights(&oob[..4]).is_err());
        let mut wrong = oob.clone();
        // A different cmsg level is not SOL_SOCKET.
        let level = if cfg!(target_os = "linux") { 8 } else { 4 };
        wrong[level] ^= 0xff;
        assert!(net::parse_unix_rights(&wrong).is_err());
        assert_eq!(net::unix_rights(&[]).len() % 4, 0);
    }

    #[test]
    fn keep_alive_defaults_are_go_defaults() {
        assert_eq!(net::DEFAULT_KEEP_ALIVE_IDLE, 15_000_000_000);
        assert_eq!(net::DEFAULT_KEEP_ALIVE_INTERVAL, 15_000_000_000);
        assert_eq!(net::DEFAULT_KEEP_ALIVE_COUNT, 9);
    }
}
