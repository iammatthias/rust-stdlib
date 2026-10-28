//! Address parsing and resolution for the dial and listen functions:
//! `SplitHostPort`, `JoinHostPort`, `LookupPort`, `parseNetwork` and
//! `resolveAddrList`.
use super::addr::{Addr, IPAddr, TCPAddr, UDPAddr, UnixAddr};
use super::error::Cause;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

fn addr_error(why: &str, addr: &str) -> Cause {
    Cause::Address(format!("address {addr}: {why}"))
}

/// `net.SplitHostPort`: splits "host:port" or "\[host\]:port".
pub fn split_host_port(hostport: &str) -> Result<(String, String), Cause> {
    const MISSING_PORT: &str = "missing port in address";
    const TOO_MANY_COLONS: &str = "too many colons in address";
    let (mut j, mut k) = (0, 0);
    let Some(i) = hostport.rfind(':') else {
        return Err(addr_error(MISSING_PORT, hostport));
    };
    let host;
    if hostport.starts_with('[') {
        let Some(end) = hostport.find(']') else {
            return Err(addr_error("missing ']' in address", hostport));
        };
        if end + 1 == hostport.len() {
            return Err(addr_error(MISSING_PORT, hostport));
        } else if end + 1 != i {
            if hostport.as_bytes()[end + 1] == b':' {
                return Err(addr_error(TOO_MANY_COLONS, hostport));
            }
            return Err(addr_error(MISSING_PORT, hostport));
        }
        host = &hostport[1..end];
        j = 1;
        k = end + 1;
    } else {
        host = &hostport[..i];
        if host.contains(':') {
            return Err(addr_error(TOO_MANY_COLONS, hostport));
        }
    }
    if hostport[j..].contains('[') {
        return Err(addr_error("unexpected '[' in address", hostport));
    }
    if hostport[k..].contains(']') {
        return Err(addr_error("unexpected ']' in address", hostport));
    }
    Ok((host.to_string(), hostport[i + 1..].to_string()))
}

/// `net.JoinHostPort`: "host:port", with brackets around a literal IPv6 host.
pub fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn read_table(path: &str, proto_index: usize) -> Vec<(String, u32, String)> {
    // services: "name port/proto alias...", protocols: "name number alias..."
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 2 {
            continue;
        }
        if proto_index == 1 {
            // protocols
            if let Ok(n) = f[1].parse::<u32>() {
                for name in std::iter::once(&f[0]).chain(f[2..].iter()) {
                    out.push((name.to_lowercase(), n, String::new()));
                }
            }
        } else if let Some((port, proto)) = f[1].split_once('/') {
            if let Ok(n) = port.parse::<u32>() {
                for name in std::iter::once(&f[0]).chain(f[2..].iter()) {
                    out.push((name.to_lowercase(), n, proto.to_string()));
                }
            }
        }
    }
    out
}

fn services(network: &str) -> HashMap<String, u32> {
    let mut map: HashMap<String, u32> = HashMap::new();
    let builtin: &[(&str, u32)] = if network == "tcp" {
        &[
            ("ftp", 21),
            ("ftps", 990),
            ("gopher", 70),
            ("http", 80),
            ("https", 443),
            ("imap2", 143),
            ("imap3", 220),
            ("imaps", 993),
            ("pop3", 110),
            ("pop3s", 995),
            ("smtp", 25),
            ("submissions", 465),
            ("ssh", 22),
            ("telnet", 23),
        ]
    } else {
        &[("domain", 53)]
    };
    for (name, port) in builtin {
        map.insert((*name).to_string(), *port);
    }
    for (name, port, proto) in read_table("/etc/services", 0) {
        if proto == network {
            map.entry(name).or_insert(port);
        }
    }
    map
}

/// Go's `parsePort`: `(port, needs_lookup)`.
fn parse_port(service: &str) -> (i64, bool) {
    if service.is_empty() {
        return (0, false);
    }
    const MAX: u64 = u32::MAX as u64;
    const CUTOFF: u64 = 1 << 30;
    let (neg, digits) = match service.as_bytes()[0] {
        b'+' => (false, &service[1..]),
        b'-' => (true, &service[1..]),
        _ => (false, service),
    };
    let mut n: u64 = 0;
    for ch in digits.chars() {
        let Some(d) = ch.to_digit(10) else {
            return (0, true);
        };
        if n >= CUTOFF {
            n = MAX;
            break;
        }
        n *= 10;
        let nn = n + u64::from(d);
        if nn > MAX {
            n = MAX;
            break;
        }
        n = nn;
    }
    let port = if !neg && n >= CUTOFF {
        (CUTOFF - 1) as i64
    } else if neg && n > CUTOFF {
        CUTOFF as i64
    } else {
        n as i64
    };
    (if neg { -port } else { port }, false)
}

/// `net.LookupPort`: the port for a service name or number.
pub fn lookup_port(network: &str, service: &str) -> Result<u16, Cause> {
    let (mut port, needs_lookup) = parse_port(service);
    if needs_lookup {
        let table_net = match network {
            "tcp" | "tcp4" | "tcp6" => "tcp",
            "udp" | "udp4" | "udp6" => "udp",
            "ip" | "" => "ip",
            other => return Err(addr_error("unknown network", other)),
        };
        let lower = service.to_lowercase();
        let found = if table_net == "ip" {
            services("tcp")
                .get(&lower)
                .copied()
                .or_else(|| services("udp").get(&lower).copied())
        } else {
            services(table_net).get(&lower).copied()
        };
        match found {
            Some(p) if lower.len() == service.len() => port = i64::from(p),
            _ => {
                return Err(Cause::Dns {
                    name: format!("{table_net}/{service}"),
                    err: "unknown port".into(),
                })
            }
        }
    }
    if !(0..=65535).contains(&port) {
        return Err(addr_error("invalid port", service));
    }
    Ok(port as u16)
}

/// `net.parseNetwork`: the address-family part of a network name and the IP
/// protocol number for "ip:proto" forms.
pub fn parse_network(network: &str, needs_proto: bool) -> Result<(String, i32), Cause> {
    let Some(i) = network.rfind(':') else {
        match network {
            "tcp" | "tcp4" | "tcp6" | "udp" | "udp4" | "udp6" | "unix" | "unixgram"
            | "unixpacket" => {}
            "ip" | "ip4" | "ip6" => {
                if needs_proto {
                    return Err(Cause::UnknownNetwork(network.into()));
                }
            }
            _ => return Err(Cause::UnknownNetwork(network.into())),
        }
        return Ok((network.into(), 0));
    };
    let afnet = &network[..i];
    match afnet {
        "ip" | "ip4" | "ip6" => {
            let protostr = &network[i + 1..];
            let proto = match protostr.parse::<i32>() {
                Ok(p) if !protostr.starts_with('+') && !protostr.starts_with('-') => p,
                _ => lookup_protocol(protostr)?,
            };
            Ok((afnet.into(), proto))
        }
        _ => Err(Cause::UnknownNetwork(network.into())),
    }
}

/// `net.lookupProtocol`: the IP protocol number for a name such as "icmp".
pub fn lookup_protocol(name: &str) -> Result<i32, Cause> {
    let lower = name.to_lowercase();
    let builtin = [
        ("icmp", 1),
        ("igmp", 2),
        ("tcp", 6),
        ("udp", 17),
        ("ipv6-icmp", 58),
    ];
    if let Some((_, n)) = builtin.iter().find(|(p, _)| *p == lower) {
        return Ok(*n);
    }
    if let Some((_, n, _)) = read_table("/etc/protocols", 1)
        .into_iter()
        .find(|(p, _, _)| *p == lower)
    {
        return Ok(n as i32);
    }
    Err(addr_error("unknown IP protocol specified", name))
}

/// One resolved address of a dial or listen.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ResolvedAddr {
    /// A TCP end point.
    Tcp(TCPAddr),
    /// A UDP end point.
    Udp(UDPAddr),
    /// An IP address for a raw IP socket.
    Ip(IPAddr),
    /// A Unix socket path.
    Unix(UnixAddr),
}

impl ResolvedAddr {
    /// The network name `net.Addr.Network` reports.
    pub fn network(&self) -> String {
        match self {
            ResolvedAddr::Tcp(a) => a.network(),
            ResolvedAddr::Udp(a) => a.network(),
            ResolvedAddr::Ip(a) => a.network(),
            ResolvedAddr::Unix(a) => a.network(),
        }
    }

    /// The IP address, for the internet kinds.
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            ResolvedAddr::Tcp(a) => a.ip,
            ResolvedAddr::Udp(a) => a.ip,
            ResolvedAddr::Ip(a) => a.ip,
            ResolvedAddr::Unix(_) => None,
        }
    }

    /// `isWildcard`: an unspecified (or absent) IP address.
    pub fn is_wildcard(&self) -> bool {
        match self.ip() {
            None => !matches!(self, ResolvedAddr::Unix(_)),
            Some(ip) => ip.is_unspecified(),
        }
    }
}

/// The string form (`net.Addr.String`).
impl std::fmt::Display for ResolvedAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&match self {
            ResolvedAddr::Tcp(a) => a.to_string(),
            ResolvedAddr::Udp(a) => a.to_string(),
            ResolvedAddr::Ip(a) => a.to_string(),
            ResolvedAddr::Unix(a) => a.to_string(),
        })
    }
}

impl super::addr::Addr for ResolvedAddr {
    fn network(&self) -> String {
        ResolvedAddr::network(self)
    }
}

fn ipv4_only(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(_) => true,
        IpAddr::V6(a) => a.to_ipv4_mapped().is_some(),
    }
}

/// The literal address and zone in `host`, if it is one.
pub fn parse_literal(host: &str) -> Option<(IpAddr, String)> {
    let (h, zone) = match host.rfind('%') {
        Some(i) if i > 0 => (&host[..i], host[i + 1..].to_string()),
        _ => (host, String::new()),
    };
    if let Ok(v4) = h.parse::<Ipv4Addr>() {
        if zone.is_empty() {
            return Some((IpAddr::V4(v4), zone));
        }
        return None;
    }
    h.parse::<Ipv6Addr>().ok().map(|v6| (IpAddr::V6(v6), zone))
}

fn lookup_ip(host: &str) -> Result<Vec<(IpAddr, String)>, Cause> {
    if host.is_empty() {
        return Err(Cause::Dns {
            name: host.into(),
            err: "no such host".into(),
        });
    }
    if let Some(lit) = parse_literal(host) {
        return Ok(vec![lit]);
    }
    match (host, 0u16).to_socket_addrs() {
        Ok(iter) => {
            let mut out: Vec<(IpAddr, String)> = Vec::new();
            for sa in iter {
                let item = (sa.ip(), String::new());
                if !out.contains(&item) {
                    out.push(item);
                }
            }
            if out.is_empty() {
                Err(Cause::Dns {
                    name: host.into(),
                    err: "no such host".into(),
                })
            } else {
                Ok(out)
            }
        }
        Err(_) => Err(Cause::Dns {
            name: host.into(),
            err: "no such host".into(),
        }),
    }
}

/// `Resolver.internetAddrList`: the addresses for "host:port" on a TCP or
/// UDP network or for "host" on an IP network.
fn internet_addr_list(net: &str, addr: &str) -> Result<Vec<ResolvedAddr>, Cause> {
    let (host, portnum);
    match net {
        "tcp" | "tcp4" | "tcp6" | "udp" | "udp4" | "udp6" => {
            if addr.is_empty() {
                host = String::new();
                portnum = 0;
            } else {
                let (h, port) = split_host_port(addr)?;
                host = h;
                portnum = lookup_port(net, &port)?;
            }
        }
        "ip" | "ip4" | "ip6" => {
            host = addr.to_string();
            portnum = 0;
        }
        _ => return Err(Cause::UnknownNetwork(net.into())),
    }
    let make = |ip: Option<IpAddr>, zone: String| -> ResolvedAddr {
        match net {
            "tcp" | "tcp4" | "tcp6" => ResolvedAddr::Tcp(TCPAddr {
                ip,
                port: portnum,
                zone,
            }),
            "udp" | "udp4" | "udp6" => ResolvedAddr::Udp(UDPAddr {
                ip,
                port: portnum,
                zone,
            }),
            _ => ResolvedAddr::Ip(IPAddr { ip, zone }),
        }
    };
    if host.is_empty() {
        return Ok(vec![make(None, String::new())]);
    }
    let mut ips = lookup_ip(&host)?;
    // Issue 18806: a half-configured IPv6 stack may bind "::" but not connect
    // back to it, so also try 0.0.0.0.
    if ips.len() == 1 && ips[0].0 == IpAddr::V6(Ipv6Addr::UNSPECIFIED) {
        ips.push((IpAddr::V4(Ipv4Addr::UNSPECIFIED), String::new()));
    }
    let want4 = net.ends_with('4');
    let want6 = net.ends_with('6');
    let list: Vec<ResolvedAddr> = ips
        .into_iter()
        .filter(|(ip, _)| (!want4 || ipv4_only(ip)) && (!want6 || !ipv4_only(ip)))
        .map(|(ip, zone)| make(Some(ip), zone))
        .collect();
    if list.is_empty() {
        return Err(Cause::Address(format!(
            "address {host}: no suitable address found"
        )));
    }
    Ok(list)
}

/// `Resolver.resolveAddrList`: the addresses to dial or listen on. `hint`
/// is the dialer's local address, used to drop addresses of another family.
pub fn resolve_addr_list(
    op: &str,
    network: &str,
    addr: &str,
    hint: Option<&ResolvedAddr>,
) -> Result<Vec<ResolvedAddr>, Cause> {
    let (afnet, _) = parse_network(network, true)?;
    if op == "dial" && addr.is_empty() {
        return Err(Cause::MissingAddress);
    }
    if matches!(afnet.as_str(), "unix" | "unixgram" | "unixpacket") {
        let unix = ResolvedAddr::Unix(UnixAddr {
            name: addr.to_string(),
            net: afnet,
        });
        if op == "dial" {
            if let Some(h) = hint {
                if h.network() != unix.network() {
                    return Err(Cause::Address(format!(
                        "address {}: mismatched local address type",
                        h
                    )));
                }
            }
        }
        return Ok(vec![unix]);
    }
    let addrs = internet_addr_list(&afnet, addr)?;
    let Some(hint) = hint.filter(|_| op == "dial") else {
        return Ok(addrs);
    };
    let hint_wildcard = hint.is_wildcard();
    let mut out = Vec::new();
    for a in addrs {
        if a.network() != hint.network() {
            return Err(Cause::Address(format!(
                "address {}: mismatched local address type",
                hint
            )));
        }
        let compatible = match (a.ip(), hint.ip()) {
            (Some(x), Some(y)) => ipv4_only(&x) == ipv4_only(&y),
            _ => true,
        };
        if hint_wildcard || a.is_wildcard() || compatible {
            out.push(a);
        }
    }
    if out.is_empty() {
        return Err(Cause::Address(format!(
            "address {}: no suitable address found",
            hint
        )));
    }
    Ok(out)
}
