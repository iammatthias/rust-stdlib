//! Tables ported from Go's net/ip_test.go, mac_test.go, ipsock_test.go and
//! pipe_test.go, plus loopback socket behaviour (see NOTICE).
use rust_stdlib::net::*;
use rust_stdlib::time::{now, Duration, Time};
use std::sync::Arc;
use std::thread;

fn ip(s: &str) -> IP {
    parse_ip(s).unwrap_or_else(|| panic!("ParseIP({s:?})"))
}

#[test]
fn parse_ip_table() {
    let ok = [
        ("127.0.1.2", ipv4(127, 0, 1, 2)),
        ("127.0.0.1", ipv4(127, 0, 0, 1)),
        ("::ffff:127.1.2.3", ipv4(127, 1, 2, 3)),
        ("::ffff:7f01:0203", ipv4(127, 1, 2, 3)),
        ("0:0:0:0:0000:ffff:127.1.2.3", ipv4(127, 1, 2, 3)),
    ];
    for (s, want) in ok {
        let got = ip(s);
        assert!(got.equal(&want), "{s}: {got}");
    }
    assert_eq!(ip("2001:4860:0:2001::68").0.len(), 16);
    for bad in [
        "",
        "127.0.0",
        "127.0.0.1.2",
        "127.0.0.256",
        "::1%en0",
        "1.2.3.4%x",
        "0127.0.0.1",
        "::ffff:1.2.3",
        ":::",
        "abc",
    ] {
        assert!(parse_ip(bad).is_none(), "{bad}");
    }
}

#[test]
fn ip_strings_and_classes() {
    assert_eq!(ipv4(1, 2, 3, 4).to_string(), "1.2.3.4");
    assert_eq!(IP(vec![1, 2, 3, 4]).to_string(), "1.2.3.4");
    assert_eq!(IP(vec![]).to_string(), "<nil>");
    assert_eq!(IP(vec![1, 2, 3]).to_string(), "?010203");
    assert_eq!(ip("2001:db8::1").to_string(), "2001:db8::1");
    assert_eq!(ip("::ffff:1.2.3.4").to_string(), "1.2.3.4");
    assert!(ip("127.0.0.1").is_loopback() && ip("::1").is_loopback());
    assert!(
        ip("10.1.2.3").is_private() && ip("fc00::1").is_private() && !ip("11.0.0.1").is_private()
    );
    assert!(ip("224.0.0.1").is_multicast() && ip("ff02::1").is_link_local_multicast());
    assert!(ip("169.254.0.1").is_link_local_unicast() && ip("fe80::1").is_link_local_unicast());
    assert!(ip("8.8.8.8").is_global_unicast() && !ip("255.255.255.255").is_global_unicast());
    assert!(ip("0.0.0.0").is_unspecified() && ip("::").is_unspecified());
    assert_eq!(
        ip("10.0.0.1").default_mask().unwrap().to_string(),
        "ff000000"
    );
    assert_eq!(
        ip("130.0.0.1").default_mask().unwrap().to_string(),
        "ffff0000"
    );
    assert_eq!(
        ip("200.0.0.1").default_mask().unwrap().to_string(),
        "ffffff00"
    );
    assert!(ip("::1").default_mask().is_none());
    assert_eq!(
        ip("192.168.1.77")
            .mask(&cidr_mask(24, 32).unwrap())
            .unwrap()
            .to_string(),
        "192.168.1.0"
    );
    assert!(ip("1.2.3.4").mask(&cidr_mask(64, 128).unwrap()).is_some());
}

#[test]
fn masks_and_cidrs() {
    assert_eq!(cidr_mask(0, 32).unwrap().to_string(), "00000000");
    assert_eq!(cidr_mask(12, 32).unwrap().to_string(), "fff00000");
    assert_eq!(
        cidr_mask(25, 128).unwrap().to_string(),
        "ffffff80000000000000000000000000"
    );
    assert!(
        cidr_mask(33, 32).is_none() && cidr_mask(-1, 32).is_none() && cidr_mask(8, 16).is_none()
    );
    assert_eq!(cidr_mask(25, 32).unwrap().size(), (25, 32));
    assert_eq!(IPMask(vec![0xff, 0, 0xff, 0]).size(), (0, 0));
    assert_eq!(ipv4_mask(255, 255, 0, 0).to_string(), "ffff0000");

    let (i, n) = parse_cidr("192.0.2.1/24").unwrap();
    assert_eq!(i.to_string(), "192.0.2.1");
    assert_eq!(n.to_string(), "192.0.2.0/24");
    assert!(n.contains(&ip("192.0.2.200")) && !n.contains(&ip("192.0.3.1")));
    let (_, n6) = parse_cidr("2001:db8::/32").unwrap();
    assert_eq!(n6.to_string(), "2001:db8::/32");
    assert!(n6.contains(&ip("2001:db8:1::1")));
    for bad in [
        "",
        "1.2.3.4",
        "1.2.3.4/33",
        "1.2.3.4/-1",
        "::1/129",
        "1.2.3.4/8x",
        "fe80::1%x/64",
        "/8",
        "1.2.3.4/",
    ] {
        let e = parse_cidr(bad).unwrap_err();
        assert_eq!(e.to_string(), format!("invalid CIDR address: {bad}"));
    }
    let odd = IPNet {
        ip: ipv4(198, 51, 100, 0),
        mask: IPMask(vec![0xc0, 0, 0xff, 0]),
    };
    assert_eq!(odd.to_string(), "198.51.100.0/c000ff00");
    assert_eq!(IPNet::default().to_string(), "<nil>");
}

#[test]
fn mac_table() {
    let ok = [
        ("00:00:5e:00:53:01", "00:00:5e:00:53:01"),
        ("00-00-5e-00-53-01", "00:00:5e:00:53:01"),
        ("0000.5e00.5301", "00:00:5e:00:53:01"),
        ("00005e005301", "00:00:5e:00:53:01"),
        ("02:00:5e:10:00:00:00:01", "02:00:5e:10:00:00:00:01"),
        ("0200.5e10.0000.0001", "02:00:5e:10:00:00:00:01"),
        (
            "00:00:00:00:fe:80:00:00:00:00:00:00:02:00:5e:10:00:00:00:01",
            "00:00:00:00:fe:80:00:00:00:00:00:00:02:00:5e:10:00:00:00:01",
        ),
    ];
    for (s, want) in ok {
        assert_eq!(parse_mac(s).unwrap().to_string(), want, "{s}");
    }
    for bad in [
        "",
        "01:23:45:67:89:ab:cd:ef:00",
        "01.02.03.04.05.06",
        "01:23:45:67:89:ag",
        "00:00:5e:00:53",
        "0000.5e00.53011",
        "0123456789ab:",
    ] {
        let want = if bad.is_empty() {
            "invalid MAC address".to_owned()
        } else {
            format!("address {bad}: invalid MAC address")
        };
        assert_eq!(parse_mac(bad).unwrap_err().to_string(), want, "{bad}");
    }
}

#[test]
fn split_and_join_host_port() {
    let ok = [
        ("localhost:80", "localhost", "80"),
        ("[::1]:80", "::1", "80"),
        ("[fe80::1%en0]:http", "fe80::1%en0", "http"),
        (":80", "", "80"),
        ("1.2.3.4:", "1.2.3.4", ""),
        ("[::1]:", "::1", ""),
    ];
    for (hp, h, p) in ok {
        assert_eq!(
            split_host_port(hp).unwrap(),
            (h.to_owned(), p.to_owned()),
            "{hp}"
        );
    }
    let bad = [
        ("localhost", "missing port in address"),
        ("[::1]", "missing port in address"),
        ("[::1]x:80", "missing port in address"),
        ("::1:80", "too many colons in address"),
        ("[::1]:80:80", "too many colons in address"),
        ("[::1:80", "missing ']' in address"),
        ("a[b:80", "unexpected '[' in address"),
        ("a]:80", "unexpected ']' in address"),
    ];
    for (hp, why) in bad {
        assert_eq!(
            split_host_port(hp).unwrap_err().to_string(),
            format!("address {hp}: {why}"),
            "{hp}"
        );
    }
    assert_eq!(join_host_port("::1", "80"), "[::1]:80");
    assert_eq!(join_host_port("example.com", "80"), "example.com:80");
}

#[test]
fn addr_strings() {
    let t = TCPAddr {
        ip: ipv4(1, 2, 3, 4),
        port: 80,
        zone: String::new(),
    };
    assert_eq!(t.to_string(), "1.2.3.4:80");
    assert_eq!(
        TCPAddr {
            ip: ip("fe80::1"),
            port: 22,
            zone: "en0".into()
        }
        .to_string(),
        "[fe80::1%en0]:22"
    );
    assert_eq!(TCPAddr::default().to_string(), ":0");
    assert_eq!(t.network(), "tcp");
    assert_eq!(
        UDPAddr {
            ip: ip("::1"),
            port: 53,
            zone: String::new()
        }
        .to_string(),
        "[::1]:53"
    );
    assert_eq!(
        IPAddr {
            ip: ip("::1"),
            zone: "z".into()
        }
        .to_string(),
        "::1%z"
    );
    assert_eq!(
        UnixAddr {
            name: "/tmp/s".into(),
            net: "unixgram".into()
        }
        .network(),
        "unixgram"
    );
    assert_eq!(
        tcp_addr_from_addr_port(&"[::1]:9".parse::<netip::AddrPort>().unwrap()).to_string(),
        "[::1]:9"
    );
    assert_eq!(t.addr_port().to_string(), "[::ffff:1.2.3.4]:80");
}

#[test]
fn error_texts() {
    let op = OpError {
        op: "dial".into(),
        net: "tcp".into(),
        source: None,
        addr: Some(Arc::new(TCPAddr {
            ip: ipv4(1, 2, 3, 4),
            port: 80,
            zone: String::new(),
        })),
        err: Box::new(NetError::Timeout),
    };
    assert_eq!(op.to_string(), "dial tcp 1.2.3.4:80: i/o timeout");
    assert!(op.timeout() && op.temporary());
    assert_eq!(
        NetError::Closed.to_string(),
        "use of closed network connection"
    );
    assert!(NetError::Op(op).timeout());
    assert_eq!(
        AddrError {
            err: "x".into(),
            addr: String::new()
        }
        .to_string(),
        "x"
    );
    assert_eq!(
        UnknownNetworkError("foo".into()).to_string(),
        "unknown network foo"
    );
    let d = DNSError {
        unwrap_err: None,
        err: "no such host".into(),
        name: "a.test".into(),
        server: "1.1.1.1:53".into(),
        is_timeout: false,
        is_temporary: false,
        is_not_found: true,
    };
    assert_eq!(d.to_string(), "lookup a.test on 1.1.1.1:53: no such host");
    assert_eq!((FLAG_UP | FLAG_LOOPBACK).to_string(), "up|loopback");
    assert_eq!(Flags(0).to_string(), "0");
}

#[test]
fn buffers() {
    let mut b = Buffers(vec![b"ab".to_vec(), b"cde".to_vec(), vec![], b"f".to_vec()]);
    let mut out = Vec::new();
    let mut r = Buffers(b.0.clone());
    let mut small = [0u8; 4];
    assert_eq!(std::io::Read::read(&mut r, &mut small).unwrap(), 4);
    assert_eq!(&small, b"abcd");
    assert_eq!(b.write_to(&mut out).unwrap(), 6);
    assert_eq!(out, b"abcdef");
    assert!(b.0.is_empty());
}

#[test]
fn pipe_semantics() {
    let (a, b) = pipe();
    let b = Arc::new(b);
    let b2 = b.clone();
    let h = thread::spawn(move || {
        let mut buf = [0u8; 3];
        let n = b2.read(&mut buf).unwrap();
        let mut rest = [0u8; 8];
        let m = b2.read(&mut rest).unwrap();
        (buf[..n].to_vec(), rest[..m].to_vec())
    });
    assert_eq!(a.write(b"abcdef").unwrap(), 6);
    let (first, rest) = h.join().unwrap();
    assert_eq!(first, b"abc");
    assert_eq!(rest, b"def");
    // Deadlines.
    a.set_read_deadline(&now().add(Duration::from_nanos(20_000_000)))
        .unwrap();
    let e = a.read(&mut [0u8; 1]).unwrap_err();
    assert_eq!(e.to_string(), "read pipe: i/o timeout");
    assert!(e.timeout());
    a.set_read_deadline(&Time::default()).unwrap();
    b.close().unwrap();
    assert_eq!(a.read(&mut [0u8; 1]).unwrap(), 0);
    assert!(matches!(a.write(b"x"), Err(NetError::ClosedPipe)));
    assert!(matches!(b.read(&mut [0u8; 1]), Err(NetError::ClosedPipe)));
}

#[test]
fn tcp_loopback_echo_and_close() {
    let ln = listen("tcp", "127.0.0.1:0").unwrap();
    let addr = ln.addr().unwrap().to_string();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let server = thread::spawn(move || {
        let c = ln.accept().unwrap();
        let mut buf = [0u8; 16];
        let n = c.read(&mut buf).unwrap();
        c.write(&buf[..n]).unwrap();
        done_rx.recv().unwrap();
        let _ = ln.close();
        assert!(ln.close().unwrap_err().is_closed());
    });
    let c = dial("tcp", &addr).unwrap();
    assert_eq!(c.remote_addr().unwrap().to_string(), addr);
    c.write(b"hello").unwrap();
    let mut buf = [0u8; 16];
    assert_eq!(c.read(&mut buf).unwrap(), 5);
    assert_eq!(&buf[..5], b"hello");
    c.set_read_deadline(&now().add(Duration::from_nanos(30_000_000)))
        .unwrap();
    let e = c.read(&mut buf).unwrap_err();
    assert!(e.timeout(), "{e}");
    c.close().unwrap();
    assert!(c.read(&mut buf).unwrap_err().is_closed());
    done_tx.send(()).unwrap();
    server.join().unwrap();
    let refused = dial("tcp", &addr).unwrap_err();
    assert!(
        refused.to_string().contains("connection refused"),
        "{refused}"
    );
}

#[cfg(unix)]
#[test]
fn unnamed_unix_addresses_print_as_go() {
    // Go's Linux anyToSockaddr shows an unnamed address as "@"; darwin's
    // shows "". A datagram from an unnamed sender has no address on either.
    let unnamed = if cfg!(target_os = "linux") { "@" } else { "" };
    let dir = std::env::temp_dir().join(format!("net-unnamed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("s").to_string_lossy().into_owned();
    let ln = listen("unix", &path).unwrap();
    let server = thread::spawn(move || ln.accept().unwrap().remote_addr().unwrap().to_string());
    let c = dial("unix", &path).unwrap();
    assert_eq!(c.local_addr().unwrap().to_string(), unnamed);
    assert_eq!(server.join().unwrap(), unnamed);

    let gpath = dir.join("g").to_string_lossy().into_owned();
    let pc = listen_packet("unixgram", &gpath).unwrap();
    let to = UnixAddr {
        name: gpath.clone(),
        net: "unixgram".into(),
    };
    let gc = dial_unix("unixgram", None, Some(&to)).unwrap();
    assert_eq!(gc.local_addr().unwrap().to_string(), unnamed);
    gc.write(b"ping").unwrap();
    let (n, from) = pc.read_from(&mut [0u8; 8]).unwrap();
    assert_eq!(n, 4);
    assert!(from.is_none(), "from {:?}", from.map(|a| a.to_string()));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn resolver_literals_and_ports() {
    assert_eq!(lookup_host("1.2.3.4").unwrap(), vec!["1.2.3.4"]);
    assert_eq!(
        lookup_host("").unwrap_err().to_string(),
        "lookup : no such host"
    );
    assert_eq!(lookup_port("tcp", "http").unwrap(), 80);
    assert_eq!(lookup_port("udp", "domain").unwrap(), 53);
    assert_eq!(
        lookup_port("tcp", "70000").unwrap_err().to_string(),
        "address 70000: invalid port"
    );
    assert_eq!(
        lookup_port("foo", "http").unwrap_err().to_string(),
        "address foo: unknown network"
    );
    assert_eq!(
        resolve_tcp_addr("tcp", "127.0.0.1:8080")
            .unwrap()
            .to_string(),
        "127.0.0.1:8080"
    );
    assert_eq!(
        resolve_udp_addr("udp", "[::1]:domain").unwrap().to_string(),
        "[::1]:53"
    );
    assert_eq!(
        resolve_tcp_addr("tcp4", "[::1]:80")
            .unwrap_err()
            .to_string(),
        "address ::1: no suitable address found"
    );
}
