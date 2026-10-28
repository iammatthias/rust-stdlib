//! Line protocol used by `tools/net_check.py` for Go differential checks of the
//! `net` parsers and formatters. See `tools/net_oracle.go` for the formats.
use rust_stdlib::net::{
    self, cidr_mask, ipv4, ipv4_zero, ipv6_loopback, join_host_port, parse_cidr, parse_ip,
    parse_mac, split_host_port, tcp_addr_from_addr_port, udp_addr_from_addr_port, Addr, AddrError,
    DNSError, Error as _, HardwareAddr, IPAddr, IPMask, IPNet, NetError, OpError, ParseError,
    TCPAddr, UDPAddr, UnixAddr, UnknownNetworkError, IP,
};
use std::io::{self, BufRead, Write};
use std::sync::Arc;

fn enc(s: &str) -> String {
    encb(s.as_bytes())
}

fn encb(b: &[u8]) -> String {
    if b.is_empty() {
        return "_".into();
    }
    b.iter().map(|b| format!("{b:02x}")).collect()
}

fn decb(s: &str) -> Vec<u8> {
    if s == "_" {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex argument"))
        .collect()
}

fn flag(b: bool) -> String {
    if b { "1" } else { "0" }.into()
}

fn ip_tok(ip: &Option<IP>) -> String {
    match ip {
        None => "-".into(),
        Some(ip) => enc(&ip.to_string()),
    }
}

fn mask_tok(m: &Option<IPMask>) -> String {
    match m {
        None => "-".into(),
        Some(m) => enc(&m.to_string()),
    }
}

fn probe_masks() -> Vec<Option<IPMask>> {
    vec![
        cidr_mask(0, 32),
        cidr_mask(8, 32),
        cidr_mask(24, 32),
        cidr_mask(32, 32),
        cidr_mask(0, 128),
        cidr_mask(64, 128),
        cidr_mask(120, 128),
        cidr_mask(128, 128),
        Some(IPMask(vec![0xff, 0, 0xff, 0])),
        Some(IPMask(vec![0xff, 0xff, 0xff])),
        Some(IPMask(vec![])),
    ]
}

fn dump_ip(ip: &IP) -> Vec<String> {
    let mut t = vec![ip_tok(&ip.to4()), ip_tok(&ip.to16())];
    let flags = [
        ip.is_unspecified(),
        ip.is_loopback(),
        ip.is_private(),
        ip.is_multicast(),
        ip.is_interface_local_multicast(),
        ip.is_link_local_multicast(),
        ip.is_link_local_unicast(),
        ip.is_global_unicast(),
    ];
    t.push(flags.iter().map(|b| flag(*b)).collect());
    t.push(enc(&ip.to_string()));
    t.push(mask_tok(&ip.default_mask()));
    let mt = ip.marshal_text();
    t.push(match &mt {
        Err(e) => format!("E{}", enc(&e.to_string())),
        Ok(b) => format!("T{}", encb(b)),
    });
    t.push(match ip.append_text(b"x".to_vec()) {
        Err(e) => format!("E{}", enc(&e.to_string())),
        Ok(b) => format!("T{}", encb(&b)),
    });
    for m in probe_masks() {
        // A nil Go mask and an empty one behave identically.
        let m = m.unwrap_or_default();
        t.push(ip_tok(&ip.mask(&m)));
    }
    let others: Vec<IP> = vec![
        ip.clone(),
        ip.to4().unwrap_or_default(),
        ip.to16().unwrap_or_default(),
        ipv4(1, 2, 3, 4),
        ipv4_zero(),
        ipv6_loopback(),
        IP::default(),
    ];
    for o in &others {
        t.push(flag(ip.equal(o)));
    }
    let mut back = IP::default();
    t.push(match back.unmarshal_text(&mt.unwrap_or_default()) {
        Err(e) => format!("E{}", enc(&e.to_string())),
        Ok(()) => ip_tok(&Some(back).filter(|b| !b.0.is_empty())),
    });
    t
}

fn dump_net(n: &IPNet) -> Vec<String> {
    let (ones, bits) = n.mask.size();
    let nz = |ip: &IP| {
        if ip.0.is_empty() {
            None
        } else {
            Some(ip.clone())
        }
    };
    let mut t = vec![
        enc(&n.to_string()),
        enc(n.network()),
        ip_tok(&nz(&n.ip)),
        mask_tok(&if n.mask.0.is_empty() {
            None
        } else {
            Some(n.mask.clone())
        }),
        ones.to_string(),
        bits.to_string(),
    ];
    for p in [
        "1.2.3.4",
        "10.1.2.3",
        "192.168.0.1",
        "::1",
        "2001:db8::1",
        "::ffff:10.1.2.3",
        "fe80::1",
        "0.0.0.0",
    ] {
        t.push(flag(n.contains(&parse_ip(p).unwrap_or_default())));
    }
    t.push(flag(n.contains(&n.ip)));
    t.push(flag(n.contains(&IP::default())));
    t.push(flag(n.contains(&IP(vec![1, 2, 3]))));
    t
}

fn tcp_tok(a: &TCPAddr) -> Vec<String> {
    let ap = a.addr_port();
    vec![
        enc(&a.to_string()),
        enc(a.network()),
        enc(&ap.to_string()),
        flag(ap.is_valid()),
        enc(&tcp_addr_from_addr_port(&ap).to_string()),
    ]
}

fn udp_tok(a: &UDPAddr) -> Vec<String> {
    let ap = a.addr_port();
    vec![
        enc(&a.to_string()),
        enc(a.network()),
        enc(&ap.to_string()),
        flag(ap.is_valid()),
        enc(&udp_addr_from_addr_port(&ap).to_string()),
    ]
}

#[derive(Debug)]
struct Fake(String);

impl std::fmt::Display for Fake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Addr for Fake {
    fn network(&self) -> &str {
        "tcp"
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn s(b: &[u8]) -> String {
    String::from_utf8(b.to_vec()).expect("UTF-8 argument")
}

fn handle(line: &str) -> Vec<String> {
    let f: Vec<&str> = line.split_whitespace().collect();
    let a: Vec<Vec<u8>> = f[1..].iter().map(|x| decb(x)).collect();
    match f[0] {
        "I" => match parse_ip(&s(&a[0])) {
            None => vec!["NIL".into()],
            Some(ip) => [vec!["OK".to_owned()], dump_ip(&ip)].concat(),
        },
        "R" => [vec!["OK".to_owned()], dump_ip(&IP(a[0].clone()))].concat(),
        "D" => match parse_cidr(&s(&a[0])) {
            Err(e) => vec!["ERR".into(), enc(&e.to_string())],
            Ok((ip, n)) => {
                let mut t = vec!["OK".to_owned(), ip_tok(&Some(ip.clone()))];
                t.extend(dump_net(&n));
                t.push(flag(ip.equal(&n.ip)));
                t
            }
        },
        "N" => dump_net(&IPNet {
            ip: IP(a[0].clone()),
            mask: IPMask(a[1].clone()),
        }),
        "M" => {
            let m = IPMask(a[0].clone());
            let (ones, bits) = m.size();
            vec![enc(&m.to_string()), ones.to_string(), bits.to_string()]
        }
        "K" => {
            let ones: isize = s(&a[0]).parse().unwrap_or(0);
            let bits: isize = s(&a[1]).parse().unwrap_or(0);
            vec![mask_tok(&cidr_mask(ones, bits))]
        }
        "H" => match parse_mac(&s(&a[0])) {
            Err(e) => vec!["ERR".into(), enc(&e.to_string())],
            Ok(hw) => vec![
                "OK".into(),
                enc(&hw.to_string()),
                hw.0.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            ],
        },
        "S" => match split_host_port(&s(&a[0])) {
            Err(e) => vec![
                "ERR".into(),
                enc(&e.to_string()),
                flag(e.timeout()),
                flag(e.temporary()),
            ],
            Ok((h, p)) => vec!["OK".into(), enc(&h), enc(&p)],
        },
        "J" => vec![enc(&join_host_port(&s(&a[0]), &s(&a[1])))],
        "T" | "U" => {
            let port: i32 = s(&a[1]).parse().unwrap_or(0);
            if f[0] == "T" {
                tcp_tok(&TCPAddr {
                    ip: IP(a[0].clone()),
                    port,
                    zone: s(&a[2]),
                })
            } else {
                udp_tok(&UDPAddr {
                    ip: IP(a[0].clone()),
                    port,
                    zone: s(&a[2]),
                })
            }
        }
        "P" => {
            let ia = IPAddr {
                ip: IP(a[0].clone()),
                zone: s(&a[1]),
            };
            let ua = UnixAddr {
                name: s(&a[2]),
                net: s(&a[3]),
            };
            vec![
                enc(&ia.to_string()),
                enc(ia.network()),
                enc(&ua.to_string()),
                enc(ua.network()),
            ]
        }
        "Q" => {
            let fake = |b: &[u8]| -> Option<Arc<dyn Addr>> {
                if b == b"-" {
                    None
                } else {
                    Some(Arc::new(Fake(s(b))))
                }
            };
            let inner = match s(&a[4]).as_str() {
                "timeout" => NetError::Timeout,
                "addr" => AddrError {
                    err: s(&a[5]),
                    addr: "a".into(),
                }
                .into(),
                "unknown" => UnknownNetworkError(s(&a[5])).into(),
                "closed" => NetError::Closed,
                "parse" => ParseError {
                    type_: "t".into(),
                    text: s(&a[5]),
                }
                .into(),
                _ => NetError::other(s(&a[5])),
            };
            let e = OpError {
                op: s(&a[0]),
                net: s(&a[1]),
                source: fake(&a[2]),
                addr: fake(&a[3]),
                err: Box::new(inner),
            };
            let n = NetError::from(e.clone());
            vec![
                enc(&e.to_string()),
                flag(e.timeout()),
                flag(e.temporary()),
                flag(n.is_closed()),
            ]
        }
        "X" => {
            let d = DNSError {
                unwrap_err: None,
                err: s(&a[0]),
                name: s(&a[1]),
                server: s(&a[2]),
                is_timeout: s(&a[3]) == "1",
                is_temporary: s(&a[4]) == "1",
                is_not_found: false,
            };
            vec![enc(&d.to_string()), flag(d.timeout()), flag(d.temporary())]
        }
        "Y" => vec![
            enc(&AddrError {
                err: "e".into(),
                addr: String::new(),
            }
            .to_string()),
            enc(&UnknownNetworkError("foo".into()).to_string()),
            enc(&net::InvalidAddrError("bad".into()).to_string()),
            enc(&net::DNSConfigError {
                err: Box::new(NetError::other("boom")),
            }
            .to_string()),
            enc(&NetError::Closed.to_string()),
            enc(&NetError::WriteToConnected.to_string()),
            enc(&ParseError {
                type_: "IP address".into(),
                text: "x".into(),
            }
            .to_string()),
            net::Flags(0).to_string(),
            net::FLAG_UP.to_string(),
            (net::FLAG_UP | net::FLAG_LOOPBACK | net::FLAG_RUNNING).to_string(),
            (net::FLAG_BROADCAST | net::FLAG_POINT_TO_POINT | net::FLAG_MULTICAST).to_string(),
            net::Flags(1 << 9).to_string(),
        ],
        op => panic!("unknown op {op}"),
    }
}

fn main() {
    let _ = HardwareAddr::default();
    let stdin = io::stdin();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        writeln!(out, "{}", handle(&line.unwrap()).join(" ")).unwrap();
    }
}
