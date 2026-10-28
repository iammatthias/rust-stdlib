//! Go's address types used by the interface and raw-socket APIs: `net.Addr`,
//! `net.IPAddr`, `net.IPNet`, `net.UnixAddr` and `net.TCPAddr`/`net.UDPAddr`
//! strings.
use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

/// `net.Addr`: a network end point.
pub trait Addr: fmt::Display {
    /// The name of the network, e.g. "tcp", "ip+net".
    fn network(&self) -> String;
}

/// Go's `IP.String` for an address: dotted decimal for IPv4, RFC 5952 form
/// for IPv6 (a run of two or more zero groups is compressed; IPv4-mapped
/// addresses print as dotted decimal).
pub fn ip_string(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => a.to_string(),
        IpAddr::V6(a) => ipv6_string(a),
    }
}

fn ipv6_string(a: &Ipv6Addr) -> String {
    let o = a.octets();
    if o[..10] == [0; 10] && o[10] == 0xff && o[11] == 0xff {
        return format!("{}.{}.{}.{}", o[12], o[13], o[14], o[15]);
    }
    let words: Vec<u16> = (0..8)
        .map(|i| u16::from_be_bytes([o[2 * i], o[2 * i + 1]]))
        .collect();
    // Longest run of zero words, at least two long, first one on a tie.
    let (mut best_start, mut best_len) = (usize::MAX, 0);
    let mut i = 0;
    while i < 8 {
        if words[i] == 0 {
            let start = i;
            while i < 8 && words[i] == 0 {
                i += 1;
            }
            if i - start > best_len && i - start >= 2 {
                best_start = start;
                best_len = i - start;
            }
        } else {
            i += 1;
        }
    }
    let mut out = String::new();
    let mut i = 0;
    while i < 8 {
        if i == best_start {
            out.push_str("::");
            i += best_len;
            continue;
        }
        if !out.is_empty() && !out.ends_with(':') {
            out.push(':');
        }
        out.push_str(&format!("{:x}", words[i]));
        i += 1;
    }
    out
}

/// `net.IPAddr`: an IP address with an optional IPv6 zone. `None` is Go's
/// nil IP, the wildcard.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct IPAddr {
    /// The address.
    pub ip: Option<IpAddr>,
    /// The IPv6 zone, or empty.
    pub zone: String,
}

impl IPAddr {
    /// An address without a zone.
    pub fn new(ip: IpAddr) -> IPAddr {
        IPAddr {
            ip: Some(ip),
            zone: String::new(),
        }
    }
}

impl fmt::Display for IPAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ip) = &self.ip {
            f.write_str(&ip_string(ip))?;
        }
        if !self.zone.is_empty() {
            write!(f, "%{}", self.zone)?;
        }
        Ok(())
    }
}

impl Addr for IPAddr {
    fn network(&self) -> String {
        "ip".into()
    }
}

/// `net.IPNet`: an IP network, here as an interface address with its mask.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct IPNet {
    /// The address (not masked).
    pub ip: IpAddr,
    /// The mask: 4 bytes for IPv4, 16 for IPv6.
    pub mask: Vec<u8>,
}

impl IPNet {
    /// `IPMask.Size` ones, or `None` when the mask is not canonical.
    pub fn ones(&self) -> Option<usize> {
        let mut ones = 0;
        let mut i = 0;
        while i < self.mask.len() {
            let b = self.mask[i];
            if b == 0xff {
                ones += 8;
                i += 1;
                continue;
            }
            let mut b = b;
            while b & 0x80 != 0 {
                ones += 1;
                b <<= 1;
            }
            if b != 0 {
                return None;
            }
            i += 1;
            while i < self.mask.len() {
                if self.mask[i] != 0 {
                    return None;
                }
                i += 1;
            }
        }
        Some(ones)
    }
}

impl fmt::Display for IPNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&ip_string(&self.ip))?;
        match self.ones() {
            Some(n) => write!(f, "/{n}"),
            None => {
                let hex: String = self.mask.iter().map(|b| format!("{b:02x}")).collect();
                write!(f, "/{hex}")
            }
        }
    }
}

impl Addr for IPNet {
    fn network(&self) -> String {
        "ip+net".into()
    }
}

/// `net.UnixAddr`: a Unix domain socket address.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct UnixAddr {
    /// The path, or on Linux an abstract name starting with `@`.
    pub name: String,
    /// "unix", "unixgram" or "unixpacket".
    pub net: String,
}

impl fmt::Display for UnixAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

impl Addr for UnixAddr {
    fn network(&self) -> String {
        self.net.clone()
    }
}

/// A `net.TCPAddr` or `net.UDPAddr` string: `host:port`, `[v6%zone]:port`.
pub fn hostport_string(addr: &SocketAddr, zone: &str) -> String {
    let host = match addr {
        SocketAddr::V4(a) => a.ip().to_string(),
        SocketAddr::V6(a) => {
            let mut h = ipv6_string(a.ip());
            if !zone.is_empty() {
                h.push('%');
                h.push_str(zone);
            }
            if h.contains(':') {
                format!("[{h}]")
            } else {
                h
            }
        }
    };
    format!("{host}:{}", addr.port())
}

/// Go's `TCPAddr.String` / `UDPAddr.String`: `host:port`, `[v6%zone]:port`,
/// or `:port` for the wildcard.
pub fn addr_string(ip: &Option<IpAddr>, port: u16, zone: &str) -> String {
    let mut host = ip.as_ref().map(ip_string).unwrap_or_default();
    if !zone.is_empty() {
        host.push('%');
        host.push_str(zone);
    }
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// `net.TCPAddr`: a TCP end point.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct TCPAddr {
    /// The IP address; `None` is the wildcard.
    pub ip: Option<IpAddr>,
    /// The port.
    pub port: u16,
    /// The IPv6 zone, or empty.
    pub zone: String,
}

impl fmt::Display for TCPAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&addr_string(&self.ip, self.port, &self.zone))
    }
}

impl Addr for TCPAddr {
    fn network(&self) -> String {
        "tcp".into()
    }
}

/// `net.UDPAddr`: a UDP end point.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct UDPAddr {
    /// The IP address; `None` is the wildcard.
    pub ip: Option<IpAddr>,
    /// The port.
    pub port: u16,
    /// The IPv6 zone, or empty.
    pub zone: String,
}

impl fmt::Display for UDPAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&addr_string(&self.ip, self.port, &self.zone))
    }
}

impl Addr for UDPAddr {
    fn network(&self) -> String {
        "udp".into()
    }
}
