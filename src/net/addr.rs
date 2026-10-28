//! Go's socket address types: [`TCPAddr`], [`UDPAddr`], [`IPAddr`], [`UnixAddr`],
//! and `SplitHostPort`/`JoinHostPort`, ported from `net/ipsock.go`, `tcpsock.go`,
//! `udpsock.go`, `unixsock.go` and `iprawsock.go` (see NOTICE).
use super::error::{Addr, AddrError, NetError, ParseError};
use super::ip::IP;
use super::netip::{self, AddrPort};
use std::fmt;
use std::net::{IpAddr, SocketAddr};

/// `net.JoinHostPort`: `host:port`, bracketing a host that contains a colon.
pub fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// `net.SplitHostPort`: splits `host:port`, `[host]:port` and `host%zone:port`.
pub fn split_host_port(hostport: &str) -> Result<(String, String), NetError> {
    const MISSING_PORT: &str = "missing port in address";
    const TOO_MANY_COLONS: &str = "too many colons in address";
    let fail = |why: &str| -> NetError {
        AddrError {
            err: why.into(),
            addr: hostport.to_owned(),
        }
        .into()
    };
    let (mut j, mut k) = (0usize, 0usize);
    let i = hostport.rfind(':').ok_or_else(|| fail(MISSING_PORT))?;
    let host;
    if hostport.starts_with('[') {
        let end = hostport
            .find(']')
            .ok_or_else(|| fail("missing ']' in address"))?;
        if end + 1 == hostport.len() {
            return Err(fail(MISSING_PORT));
        } else if end + 1 != i {
            if hostport.as_bytes()[end + 1] == b':' {
                return Err(fail(TOO_MANY_COLONS));
            }
            return Err(fail(MISSING_PORT));
        }
        host = &hostport[1..end];
        j = 1;
        k = end + 1;
    } else {
        host = &hostport[..i];
        if host.contains(':') {
            return Err(fail(TOO_MANY_COLONS));
        }
    }
    if hostport[j..].contains('[') {
        return Err(fail("unexpected '[' in address"));
    }
    if hostport[k..].contains(']') {
        return Err(fail("unexpected ']' in address"));
    }
    Ok((host.to_owned(), hostport[i + 1..].to_owned()))
}

// `host%zone` into (host, zone), splitting at the last '%' after position 0.
pub(crate) fn split_host_zone(s: &str) -> (&str, &str) {
    match s.rfind('%') {
        Some(i) if i > 0 => (&s[..i], &s[i + 1..]),
        _ => (s, ""),
    }
}

fn addr_port_of(ip: &IP, zone: &str, port: i32) -> AddrPort {
    let a = netip::Addr::try_from(ip.0.as_slice())
        .ok()
        .unwrap_or_default()
        .with_zone(zone);
    netip::AddrPort::new(a, port as u16)
}

fn from_addr_port(a: &AddrPort) -> (IP, String, i32) {
    (
        IP(a.addr().as_slice()),
        a.addr().zone().to_owned(),
        a.port() as i32,
    )
}

macro_rules! inet_addr {
    ($name:ident, $net:literal, $doc:literal, $from:ident) => {
        #[doc = $doc]
        #[derive(Clone, Default, PartialEq, Eq, Hash, Debug)]
        pub struct $name {
            /// The IP address.
            pub ip: IP,
            /// The port.
            pub port: i32,
            /// The IPv6 scoped addressing zone.
            pub zone: String,
        }

        impl $name {
            /// The address as a `netip::AddrPort` (the port is truncated to 16 bits).
            pub fn addr_port(&self) -> AddrPort {
                addr_port_of(&self.ip, &self.zone, self.port)
            }

            /// `Network`: the network name.
            pub fn network(&self) -> &str {
                $net
            }

            pub(crate) fn is_wildcard(&self) -> bool {
                self.ip.0.is_empty() || self.ip.is_unspecified()
            }
        }

        /// `String`: `host:port`, bracketing IPv6 hosts.
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let ip = self.ip.empty_string();
                let text = if self.zone.is_empty() {
                    join_host_port(&ip, &self.port.to_string())
                } else {
                    join_host_port(&format!("{ip}%{}", self.zone), &self.port.to_string())
                };
                f.write_str(&text)
            }
        }

        impl Addr for $name {
            fn network(&self) -> &str {
                $net
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        /// The address of an `AddrPort`; an invalid one gives a nil IP.
        pub fn $from(addr: &AddrPort) -> $name {
            let (ip, zone, port) = from_addr_port(addr);
            $name { ip, port, zone }
        }

        impl TryFrom<&$name> for SocketAddr {
            type Error = ParseError;
            /// The `std::net` socket address (zones are not carried over).
            fn try_from(a: &$name) -> Result<SocketAddr, ParseError> {
                Ok(SocketAddr::new(IpAddr::try_from(&a.ip)?, a.port as u16))
            }
        }

        impl From<SocketAddr> for $name {
            fn from(a: SocketAddr) -> $name {
                $name {
                    ip: a.ip().into(),
                    port: a.port() as i32,
                    zone: String::new(),
                }
            }
        }
    };
}

inet_addr!(
    TCPAddr,
    "tcp",
    "`net.TCPAddr`: the address of a TCP end point.",
    tcp_addr_from_addr_port
);
inet_addr!(
    UDPAddr,
    "udp",
    "`net.UDPAddr`: the address of a UDP end point.",
    udp_addr_from_addr_port
);

/// `net.IPAddr`: the address of an IP end point.
#[derive(Clone, Default, PartialEq, Eq, Hash, Debug)]
pub struct IPAddr {
    /// The IP address.
    pub ip: IP,
    /// The IPv6 scoped addressing zone.
    pub zone: String,
}

impl IPAddr {
    /// `IPAddr.Network`: "ip".
    pub fn network(&self) -> &str {
        "ip"
    }

    pub(crate) fn is_wildcard(&self) -> bool {
        self.ip.0.is_empty() || self.ip.is_unspecified()
    }
}

/// `IPAddr.String`.
impl fmt::Display for IPAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ip = self.ip.empty_string();
        if self.zone.is_empty() {
            f.write_str(&ip)
        } else {
            write!(f, "{ip}%{}", self.zone)
        }
    }
}

impl From<IpAddr> for IPAddr {
    fn from(ip: IpAddr) -> IPAddr {
        IPAddr {
            ip: ip.into(),
            zone: String::new(),
        }
    }
}

impl TryFrom<&IPAddr> for IpAddr {
    type Error = ParseError;
    /// The `std::net` address (the zone is dropped); see [`IP`]'s `TryFrom`.
    fn try_from(a: &IPAddr) -> Result<IpAddr, ParseError> {
        IpAddr::try_from(&a.ip)
    }
}

impl Addr for IPAddr {
    fn network(&self) -> &str {
        "ip"
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// `net.UnixAddr`: the address of a Unix domain socket end point.
#[derive(Clone, Default, PartialEq, Eq, Hash, Debug)]
pub struct UnixAddr {
    /// The socket path (a leading `@` is a Linux abstract socket).
    pub name: String,
    /// "unix", "unixgram" or "unixpacket".
    pub net: String,
}

impl UnixAddr {
    /// `UnixAddr.Network`.
    pub fn network(&self) -> &str {
        &self.net
    }

    pub(crate) fn is_wildcard(&self) -> bool {
        self.name.is_empty()
    }
}

impl fmt::Display for UnixAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

impl Addr for UnixAddr {
    fn network(&self) -> &str {
        &self.net
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
