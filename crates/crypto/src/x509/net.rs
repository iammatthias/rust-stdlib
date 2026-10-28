//! `net.IP` and `net.IPNet` as `crypto/x509` uses them.
//!
//! This crate has no dependency on the root crate's `net` package
//! (docs/adr/0003), so Go's `net.IP` (a byte slice of 4 or 16 bytes) is [`Ip`]
//! and `*net.IPNet` is [`IpNet`], with the methods of Go's that the package
//! needs.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Go's `net.IP`: an IPv4 (4 bytes) or IPv6 (16 bytes) address. Other
/// lengths are representable, like in Go, and print as `?` and hex.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Ip(pub Vec<u8>);

const V4_IN_V6_PREFIX: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];

impl Ip {
    /// Go's `net.IPv4(a, b, c, d)`: the 16-byte form.
    pub fn v4(a: u8, b: u8, c: u8, d: u8) -> Ip {
        let mut v = V4_IN_V6_PREFIX.to_vec();
        v.extend_from_slice(&[a, b, c, d]);
        Ip(v)
    }

    /// Go's `IP.To4`: the 4-byte form of an IPv4 address.
    pub fn to4(&self) -> Option<[u8; 4]> {
        match self.0.len() {
            4 => Some([self.0[0], self.0[1], self.0[2], self.0[3]]),
            16 if self.0[..12] == V4_IN_V6_PREFIX => {
                Some([self.0[12], self.0[13], self.0[14], self.0[15]])
            }
            _ => None,
        }
    }

    /// Go's `IP.Equal`.
    pub fn equal(&self, x: &Ip) -> bool {
        let (a, b) = (&self.0, &x.0);
        if a.len() == b.len() {
            return a == b;
        }
        if a.len() == 4 && b.len() == 16 {
            return b[..12] == V4_IN_V6_PREFIX && a[..] == b[12..];
        }
        if a.len() == 16 && b.len() == 4 {
            return a[..12] == V4_IN_V6_PREFIX && a[12..] == b[..];
        }
        false
    }

    /// Go's `IP.Mask`; `None` is Go's nil result.
    pub fn mask(&self, mask: &[u8]) -> Option<Ip> {
        let mut ip: &[u8] = &self.0;
        let mut mask = mask;
        if mask.len() == 16 && ip.len() == 4 && mask[..12].iter().all(|&b| b == 0xff) {
            mask = &mask[12..];
        }
        if mask.len() == 4 && ip.len() == 16 && ip[..12] == V4_IN_V6_PREFIX {
            ip = &ip[12..];
        }
        if ip.len() != mask.len() {
            return None;
        }
        Some(Ip(ip.iter().zip(mask).map(|(a, m)| a & m).collect()))
    }

    /// Go's `IP.String`.
    fn string(&self) -> String {
        if self.0.is_empty() {
            return "<nil>".to_string();
        }
        if let Some(p4) = self.to4() {
            return Ipv4Addr::from(p4).to_string();
        }
        if self.0.len() == 16 {
            let mut b = [0u8; 16];
            b.copy_from_slice(&self.0);
            return Ipv6Addr::from(b).to_string();
        }
        format!("?{}", super::asn1::hex(&self.0))
    }
}

impl fmt::Display for Ip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string())
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string())
    }
}

impl From<std::net::IpAddr> for Ip {
    fn from(addr: std::net::IpAddr) -> Ip {
        match addr {
            std::net::IpAddr::V4(a) => Ip(a.octets().to_vec()),
            std::net::IpAddr::V6(a) => Ip(a.octets().to_vec()),
        }
    }
}

/// Go's `net.IPNet`: an IP network with a mask.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct IpNet {
    /// The network number.
    pub ip: Ip,
    /// The network mask (Go's `net.IPMask`).
    pub mask: Vec<u8>,
}

impl IpNet {
    /// Go's `IPNet.String`.
    fn string(&self) -> String {
        let Some((nn, m)) = self.network_number_and_mask() else {
            return "<nil>".to_string();
        };
        let nn = Ip(nn);
        // simpleMaskLength
        let mut n: i64 = 0;
        let mut length: i64 = -1;
        let mut i = 0;
        let mut done = false;
        while i < m.len() && !done {
            let mut v = m[i];
            if v == 0xff {
                n += 8;
                i += 1;
                continue;
            }
            while v & 0x80 != 0 {
                n += 1;
                v <<= 1;
            }
            if v != 0 {
                length = -1;
                n = -1;
                done = true;
            } else {
                if m[i + 1..].iter().any(|&b| b != 0) {
                    n = -1;
                }
                done = true;
            }
        }
        if length == -1 && n >= 0 {
            length = n;
        } else if n < 0 {
            length = -1;
        } else if !done {
            length = n;
        }
        if length == -1 {
            return format!("{}/{}", nn.string(), super::asn1::hex(&m));
        }
        format!("{}/{}", nn.string(), length)
    }

    /// Go's `IPNet.Contains`.
    pub fn contains(&self, ip: &Ip) -> bool {
        let Some((nn, m)) = self.network_number_and_mask() else {
            return false;
        };
        let target: Vec<u8> = match ip.to4() {
            Some(v4) => v4.to_vec(),
            None => ip.0.clone(),
        };
        if target.len() != nn.len() {
            return false;
        }
        nn.iter()
            .zip(&m)
            .zip(&target)
            .all(|((n, m), t)| n & m == t & m)
    }

    fn network_number_and_mask(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        let ip: Vec<u8> = match self.ip.to4() {
            Some(v4) => v4.to_vec(),
            None => {
                if self.ip.0.len() != 16 {
                    return None;
                }
                self.ip.0.clone()
            }
        };
        let mut m = self.mask.clone();
        match m.len() {
            4 => {
                if ip.len() != 4 {
                    return None;
                }
            }
            16 => {
                if ip.len() == 4 {
                    m = m[12..].to_vec();
                }
            }
            _ => return None,
        }
        Some((ip, m))
    }
}

/// Go's `net.ParseIP`: `None` for Go's nil result. IPv4 addresses are
/// returned in the 16-byte form.
pub fn parse_ip(s: &str) -> Option<Ip> {
    let (bytes, zone) = parse_addr(s)?;
    if zone.is_some() {
        return None;
    }
    Some(match bytes.len() {
        4 => Ip::v4(bytes[0], bytes[1], bytes[2], bytes[3]),
        _ => Ip(bytes),
    })
}

/// `netip.ParseAddr`: the address bytes (4 or 16) and the IPv6 zone.
pub(crate) fn parse_addr(s: &str) -> Option<(Vec<u8>, Option<String>)> {
    if s.is_empty() {
        return None;
    }
    if s.contains(':') {
        let (addr, zone) = match s.split_once('%') {
            Some((a, z)) => {
                if z.is_empty() {
                    return None;
                }
                (a, Some(z.to_string()))
            }
            None => (s, None),
        };
        if addr.contains('%') {
            return None;
        }
        let v6 = Ipv6Addr::from_str(addr).ok()?;
        Some((v6.octets().to_vec(), zone))
    } else {
        if s.contains('%') {
            return None;
        }
        let v4 = Ipv4Addr::from_str(s).ok()?;
        Some((v4.octets().to_vec(), None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_print() {
        assert_eq!(parse_ip("1.2.3.4").unwrap().string(), "1.2.3.4");
        assert_eq!(parse_ip("::ffff:1.2.3.4").unwrap().string(), "1.2.3.4");
        assert_eq!(parse_ip("2001:db8::1").unwrap().string(), "2001:db8::1");
        assert!(parse_ip("fe80::1%eth0").is_none());
        assert!(parse_ip("01.2.3.4").is_none());
        let net = IpNet {
            ip: Ip(vec![10, 0, 0, 0]),
            mask: vec![255, 0, 0, 0],
        };
        assert!(net.contains(&Ip(vec![10, 1, 2, 3])));
        assert!(!net.contains(&Ip(vec![11, 1, 2, 3])));
    }
}
