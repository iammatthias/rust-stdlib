//! Go's `net` IP address types: [`IP`], [`IPMask`], [`IPNet`], [`HardwareAddr`]
//! and their parsers, ported from `net/ip.go` and `net/mac.go` (see NOTICE).
//!
//! An `IP` is a byte vector of 4 or 16 bytes (other lengths are representable,
//! as in Go, and print as `?hex`). Go's `nil` slice is the empty vector;
//! functions that return `nil` return `None`.
use super::error::{Addr, AddrError, AddrRef, NetError, ParseError};
use super::netip;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

/// `net.IPv4len`.
pub const IPV4LEN: usize = 4;
/// `net.IPv6len`.
pub const IPV6LEN: usize = 16;

const V4_IN_V6_PREFIX: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];

/// `net.IP`: a single IP address, a slice of bytes.
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Default, PartialEq, Eq, Hash, Debug)]
pub struct IP(pub Vec<u8>);

/// `net.IPMask`: a bitmask for IP addressing and routing.
#[derive(Clone, Default, PartialEq, Eq, Hash, Debug)]
pub struct IPMask(pub Vec<u8>);

/// `net.IPNet`: an IP network.
#[derive(Clone, Default, PartialEq, Eq, Hash, Debug)]
pub struct IPNet {
    /// The network number.
    pub ip: IP,
    /// The network mask.
    pub mask: IPMask,
}

/// `net.HardwareAddr`: a physical hardware address.
#[derive(Clone, Default, PartialEq, Eq, Hash, Debug)]
pub struct HardwareAddr(pub Vec<u8>);

fn hex_string(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

/// `net.IPv4`: the 16-byte form of a.b.c.d.
pub fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IP {
    let mut p = V4_IN_V6_PREFIX.to_vec();
    p.extend_from_slice(&[a, b, c, d]);
    IP(p)
}

/// `net.IPv4Mask`: the 4-byte mask a.b.c.d.
pub fn ipv4_mask(a: u8, b: u8, c: u8, d: u8) -> IPMask {
    IPMask(vec![a, b, c, d])
}

/// `net.CIDRMask`: `ones` 1 bits then 0s up to `bits` (32 or 128), else `None`.
pub fn cidr_mask(ones: isize, bits: isize) -> Option<IPMask> {
    if bits != 32 && bits != 128 {
        return None;
    }
    if ones < 0 || ones > bits {
        return None;
    }
    let mut n = ones as usize;
    let mut m = vec![0u8; bits as usize / 8];
    for b in m.iter_mut() {
        if n >= 8 {
            *b = 0xff;
            n -= 8;
        } else {
            *b = !(0xffu8 >> n);
            n = 0;
        }
    }
    Some(IPMask(m))
}

/// `net.IPv4bcast`.
pub fn ipv4_bcast() -> IP {
    ipv4(255, 255, 255, 255)
}
/// `net.IPv4allsys`.
pub fn ipv4_allsys() -> IP {
    ipv4(224, 0, 0, 1)
}
/// `net.IPv4allrouter`.
pub fn ipv4_allrouter() -> IP {
    ipv4(224, 0, 0, 2)
}
/// `net.IPv4zero`.
pub fn ipv4_zero() -> IP {
    ipv4(0, 0, 0, 0)
}
/// `net.IPv6zero`.
pub fn ipv6_zero() -> IP {
    IP(vec![0; 16])
}
/// `net.IPv6unspecified`.
pub fn ipv6_unspecified() -> IP {
    IP(vec![0; 16])
}
/// `net.IPv6loopback`.
pub fn ipv6_loopback() -> IP {
    let mut b = vec![0; 16];
    b[15] = 1;
    IP(b)
}
/// `net.IPv6interfacelocalallnodes`.
pub fn ipv6_interface_local_all_nodes() -> IP {
    let mut b = vec![0; 16];
    b[0] = 0xff;
    b[1] = 0x01;
    b[15] = 0x01;
    IP(b)
}
/// `net.IPv6linklocalallnodes`.
pub fn ipv6_link_local_all_nodes() -> IP {
    let mut b = vec![0; 16];
    b[0] = 0xff;
    b[1] = 0x02;
    b[15] = 0x01;
    IP(b)
}
/// `net.IPv6linklocalallrouters`.
pub fn ipv6_link_local_all_routers() -> IP {
    let mut b = vec![0; 16];
    b[0] = 0xff;
    b[1] = 0x02;
    b[15] = 0x02;
    IP(b)
}

impl IP {
    /// `IP.IsUnspecified`: `0.0.0.0` or `::`.
    pub fn is_unspecified(&self) -> bool {
        self.equal(&ipv4_zero()) || self.equal(&ipv6_unspecified())
    }

    /// `IP.IsLoopback`.
    pub fn is_loopback(&self) -> bool {
        if let Some(ip4) = self.to4() {
            return ip4.0[0] == 127;
        }
        self.equal(&ipv6_loopback())
    }

    /// `IP.IsPrivate`: RFC 1918 and RFC 4193.
    pub fn is_private(&self) -> bool {
        if let Some(ip4) = self.to4() {
            let b = &ip4.0;
            return b[0] == 10
                || (b[0] == 172 && b[1] & 0xf0 == 16)
                || (b[0] == 192 && b[1] == 168);
        }
        self.0.len() == IPV6LEN && self.0[0] & 0xfe == 0xfc
    }

    /// `IP.IsMulticast`.
    pub fn is_multicast(&self) -> bool {
        if let Some(ip4) = self.to4() {
            return ip4.0[0] & 0xf0 == 0xe0;
        }
        self.0.len() == IPV6LEN && self.0[0] == 0xff
    }

    /// `IP.IsInterfaceLocalMulticast`.
    pub fn is_interface_local_multicast(&self) -> bool {
        self.0.len() == IPV6LEN && self.0[0] == 0xff && self.0[1] & 0x0f == 0x01
    }

    /// `IP.IsLinkLocalMulticast`.
    pub fn is_link_local_multicast(&self) -> bool {
        if let Some(ip4) = self.to4() {
            return ip4.0[0] == 224 && ip4.0[1] == 0 && ip4.0[2] == 0;
        }
        self.0.len() == IPV6LEN && self.0[0] == 0xff && self.0[1] & 0x0f == 0x02
    }

    /// `IP.IsLinkLocalUnicast`.
    pub fn is_link_local_unicast(&self) -> bool {
        if let Some(ip4) = self.to4() {
            return ip4.0[0] == 169 && ip4.0[1] == 254;
        }
        self.0.len() == IPV6LEN && self.0[0] == 0xfe && self.0[1] & 0xc0 == 0x80
    }

    /// `IP.IsGlobalUnicast`.
    pub fn is_global_unicast(&self) -> bool {
        (self.0.len() == IPV4LEN || self.0.len() == IPV6LEN)
            && !self.equal(&ipv4_bcast())
            && !self.is_unspecified()
            && !self.is_loopback()
            && !self.is_multicast()
            && !self.is_link_local_unicast()
    }

    /// `IP.To4`: the 4-byte form of an IPv4 address, else `None`.
    pub fn to4(&self) -> Option<IP> {
        if self.0.len() == IPV4LEN {
            return Some(self.clone());
        }
        if self.0.len() == IPV6LEN
            && self.0[..10].iter().all(|&b| b == 0)
            && self.0[10] == 0xff
            && self.0[11] == 0xff
        {
            return Some(IP(self.0[12..16].to_vec()));
        }
        None
    }

    /// `IP.To16`: the 16-byte form, or `None` for a wrong length.
    pub fn to16(&self) -> Option<IP> {
        match self.0.len() {
            IPV4LEN => Some(ipv4(self.0[0], self.0[1], self.0[2], self.0[3])),
            IPV6LEN => Some(self.clone()),
            _ => None,
        }
    }

    /// `IP.DefaultMask`: the classful mask of an IPv4 address, else `None`.
    pub fn default_mask(&self) -> Option<IPMask> {
        let ip = self.to4()?;
        Some(if ip.0[0] < 0x80 {
            ipv4_mask(0xff, 0, 0, 0)
        } else if ip.0[0] < 0xC0 {
            ipv4_mask(0xff, 0xff, 0, 0)
        } else {
            ipv4_mask(0xff, 0xff, 0xff, 0)
        })
    }

    /// `IP.Mask`: the address masked by `mask`, or `None` on a length mismatch.
    pub fn mask(&self, mask: &IPMask) -> Option<IP> {
        let mut mask: &[u8] = &mask.0;
        let mut ip: &[u8] = &self.0;
        if mask.len() == IPV6LEN && ip.len() == IPV4LEN && mask[..12].iter().all(|&b| b == 0xff) {
            mask = &mask[12..];
        }
        if mask.len() == IPV4LEN && ip.len() == IPV6LEN && ip[..12] == V4_IN_V6_PREFIX {
            ip = &ip[12..];
        }
        if ip.len() != mask.len() {
            return None;
        }
        Some(IP(ip.iter().zip(mask).map(|(a, b)| a & b).collect()))
    }

    /// `IP.Equal`: an IPv4 address equals its IPv4-mapped IPv6 form.
    pub fn equal(&self, x: &IP) -> bool {
        let (a, b) = (&self.0, &x.0);
        if a.len() == b.len() {
            return a == b;
        }
        if a.len() == IPV4LEN && b.len() == IPV6LEN {
            return b[..12] == V4_IN_V6_PREFIX && a[..] == b[12..];
        }
        if a.len() == IPV6LEN && b.len() == IPV4LEN {
            return a[..12] == V4_IN_V6_PREFIX && a[12..] == b[..];
        }
        false
    }

    /// `IP.AppendText`.
    pub fn append_text(&self, mut b: Vec<u8>) -> Result<Vec<u8>, NetError> {
        if self.0.is_empty() {
            return Ok(b);
        }
        if self.0.len() != IPV4LEN && self.0.len() != IPV6LEN {
            return Err(AddrError {
                err: "invalid IP address".into(),
                addr: hex_string(&self.0),
            }
            .into());
        }
        b.extend_from_slice(self.append_string().as_bytes());
        Ok(b)
    }

    /// `IP.MarshalText`: the string form, or empty for an empty IP.
    pub fn marshal_text(&self) -> Result<Vec<u8>, NetError> {
        self.append_text(Vec::new())
    }

    /// `IP.UnmarshalText`: accepts what [`parse_ip`] accepts; empty text clears.
    pub fn unmarshal_text(&mut self, text: &[u8]) -> Result<(), NetError> {
        if text.is_empty() {
            self.0.clear();
            return Ok(());
        }
        let s = String::from_utf8_lossy(text);
        match parse_ip(&s) {
            Some(x) => {
                *self = x;
                Ok(())
            }
            None => Err(ParseError {
                type_: "IP address".into(),
                text: s.into_owned(),
            }
            .into()),
        }
    }

    // The netip text form of a 4- or 16-byte IP (IPv4-mapped prints dotted).
    fn append_string(&self) -> String {
        let ip = self.to4().unwrap_or_else(|| self.clone());
        netip::Addr::try_from(ip.0.as_slice())
            .ok()
            .map(|a| a.to_string())
            .unwrap_or_default()
    }

    // Like `string` but empty when unset.
    pub(crate) fn empty_string(&self) -> String {
        if self.0.is_empty() {
            String::new()
        } else {
            self.to_string()
        }
    }

    pub(crate) fn match_addr_family(&self, x: &IP) -> bool {
        (self.to4().is_some() && x.to4().is_some())
            || (self.to16().is_some()
                && self.to4().is_none()
                && x.to16().is_some()
                && x.to4().is_none())
    }
}

/// `IP.String`: dotted decimal, RFC 5952 IPv6, `<nil>` or `?hex`.
impl fmt::Display for IP {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str("<nil>");
        }
        if self.0.len() != IPV4LEN && self.0.len() != IPV6LEN {
            return write!(f, "?{}", hex_string(&self.0));
        }
        f.write_str(&self.append_string())
    }
}

impl From<IpAddr> for IP {
    fn from(a: IpAddr) -> IP {
        match a {
            IpAddr::V4(a) => IP(a.octets().to_vec()),
            IpAddr::V6(a) => IP(a.octets().to_vec()),
        }
    }
}

impl From<Ipv4Addr> for IP {
    fn from(a: Ipv4Addr) -> IP {
        IP(a.octets().to_vec())
    }
}

impl From<Ipv6Addr> for IP {
    fn from(a: Ipv6Addr) -> IP {
        IP(a.octets().to_vec())
    }
}

impl TryFrom<&IP> for IpAddr {
    type Error = ParseError;
    /// The `std::net` address of a 4- or 16-byte IP; the nil IP and odd
    /// lengths (which Go's `IP` can hold but `IpAddr` cannot) fail.
    fn try_from(ip: &IP) -> Result<IpAddr, ParseError> {
        match ip.0.len() {
            IPV4LEN => Ok(IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(&ip.0[..]).unwrap(),
            ))),
            IPV6LEN => Ok(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&ip.0[..]).unwrap(),
            ))),
            _ => Err(ParseError {
                type_: "IP address".into(),
                text: ip.to_string(),
            }),
        }
    }
}

impl IPMask {
    /// `IPMask.Size`: the leading ones and total bits, or `(0, 0)` if not canonical.
    pub fn size(&self) -> (usize, usize) {
        match simple_mask_length(&self.0) {
            Some(ones) => (ones, self.0.len() * 8),
            None => (0, 0),
        }
    }
}

/// `IPMask.String`: lower-case hex, or `<nil>` when empty.
impl fmt::Display for IPMask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            f.write_str("<nil>")
        } else {
            f.write_str(&hex_string(&self.0))
        }
    }
}

// The number of leading 1 bits if mask is ones followed by zeros.
fn simple_mask_length(mask: &[u8]) -> Option<usize> {
    let mut n = 0;
    for (i, &v) in mask.iter().enumerate() {
        if v == 0xff {
            n += 8;
            continue;
        }
        let mut v = v;
        while v & 0x80 != 0 {
            n += 1;
            v <<= 1;
        }
        if v != 0 {
            return None;
        }
        if mask[i + 1..].iter().any(|&b| b != 0) {
            return None;
        }
        break;
    }
    Some(n)
}

impl IPNet {
    fn network_number_and_mask(&self) -> Option<(IP, IPMask)> {
        let ip = match self.ip.to4() {
            Some(ip) => ip,
            None => {
                if self.ip.0.len() != IPV6LEN {
                    return None;
                }
                self.ip.clone()
            }
        };
        let mut m = self.mask.clone();
        match m.0.len() {
            IPV4LEN => {
                if ip.0.len() != IPV4LEN {
                    return None;
                }
            }
            IPV6LEN => {
                if ip.0.len() == IPV4LEN {
                    m = IPMask(m.0[12..].to_vec());
                }
            }
            _ => return None,
        }
        Some((ip, m))
    }

    /// `IPNet.Contains`: whether the network includes `ip`.
    pub fn contains(&self, ip: &IP) -> bool {
        // Go reads a nil network number and mask as empty slices.
        let (nn, m) = self.network_number_and_mask().unwrap_or_default();
        let ip = ip.to4().unwrap_or_else(|| ip.clone());
        if ip.0.len() != nn.0.len() {
            return false;
        }
        (0..ip.0.len()).all(|i| nn.0[i] & m.0[i] == ip.0[i] & m.0[i])
    }

    /// `IPNet.Network`: "ip+net".
    pub fn network(&self) -> &str {
        "ip+net"
    }
}

/// `IPNet.String`: CIDR notation, `ip/hexmask` for a non-canonical mask, or `<nil>`.
impl fmt::Display for IPNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some((nn, m)) = self.network_number_and_mask() else {
            return f.write_str("<nil>");
        };
        match simple_mask_length(&m.0) {
            None => write!(f, "{nn}/{m}"),
            Some(l) => write!(f, "{nn}/{l}"),
        }
    }
}

impl Addr for IPNet {
    fn network(&self) -> &str {
        "ip+net"
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl IPNet {
    /// This network as a shared [`AddrRef`].
    pub fn to_addr(&self) -> AddrRef {
        Arc::new(self.clone())
    }
}

/// `net.ParseIP`: the 16-byte form of a textual address without a zone, else `None`.
pub fn parse_ip(s: &str) -> Option<IP> {
    let ip = s.parse::<netip::Addr>().ok()?;
    if !ip.zone().is_empty() {
        return None;
    }
    Some(IP(ip.as16().to_vec()))
}

// Go's dtoi: decimal digits, saturating at 0xFFFFFF.
pub(crate) fn dtoi(s: &str) -> (i32, usize, bool) {
    const BIG: i32 = 0xFFFFFF;
    let mut n = 0i32;
    let mut i = 0;
    let b = s.as_bytes();
    while i < b.len() && b[i].is_ascii_digit() {
        n = n * 10 + (b[i] - b'0') as i32;
        if n >= BIG {
            return (BIG, i, false);
        }
        i += 1;
    }
    if i == 0 {
        return (0, 0, false);
    }
    (n, i, true)
}

/// `net.ParseCIDR`: the address and the network it implies.
pub fn parse_cidr(s: &str) -> Result<(IP, IPNet), NetError> {
    let err = || -> NetError {
        ParseError {
            type_: "CIDR address".into(),
            text: s.to_owned(),
        }
        .into()
    };
    let (addr, mask) = s.split_once('/').ok_or_else(err)?;
    let ip = addr.parse::<netip::Addr>().map_err(|_| err())?;
    if !ip.zone().is_empty() {
        return Err(err());
    }
    let (n, i, ok) = dtoi(mask);
    if !ok || i != mask.len() || n < 0 || n as usize > ip.bit_len() {
        return Err(err());
    }
    let m = cidr_mask(n as isize, ip.bit_len() as isize).unwrap();
    let addr16 = IP(ip.as16().to_vec());
    let masked = addr16.mask(&m).unwrap();
    Ok((
        addr16,
        IPNet {
            ip: masked,
            mask: m,
        },
    ))
}

/// `HardwareAddr.String`: colon-separated lower-case hex.
impl fmt::Display for HardwareAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

fn xtoi(s: &[u8]) -> (i32, usize, bool) {
    const BIG: i32 = 0xFFFFFF;
    let mut n = 0i32;
    let mut i = 0;
    while i < s.len() {
        let d = match s[i] {
            c @ b'0'..=b'9' => c - b'0',
            c @ b'a'..=b'f' => c - b'a' + 10,
            c @ b'A'..=b'F' => c - b'A' + 10,
            _ => break,
        };
        n = n * 16 + d as i32;
        if n >= BIG {
            return (0, i, false);
        }
        i += 1;
    }
    if i == 0 {
        return (0, i, false);
    }
    (n, i, true)
}

// Go's xtoi2: two hex digits; if longer, the third byte must be `e`.
fn xtoi2(s: &[u8], e: u8) -> Option<u8> {
    if s.len() > 2 && s[2] != e {
        return None;
    }
    let head = &s[..s.len().min(2)];
    let (n, ei, ok) = xtoi(head);
    if ok && ei == 2 {
        Some(n as u8)
    } else {
        None
    }
}

/// `net.ParseMAC`: MAC-48, EUI-48, EUI-64 or 20-octet InfiniBand addresses.
pub fn parse_mac(s: &str) -> Result<HardwareAddr, NetError> {
    let fail = || -> NetError {
        AddrError {
            err: "invalid MAC address".into(),
            addr: s.to_owned(),
        }
        .into()
    };
    let b = s.as_bytes();
    if b.len() < 12 {
        return Err(fail());
    }
    let valid = |n: usize| n == 6 || n == 8 || n == 20;
    let mut hw;
    if b[2] == b':' || b[2] == b'-' {
        if !(b.len() + 1).is_multiple_of(3) {
            return Err(fail());
        }
        let n = (b.len() + 1) / 3;
        if !valid(n) {
            return Err(fail());
        }
        hw = vec![0u8; n];
        let mut x = 0;
        for h in hw.iter_mut() {
            *h = xtoi2(&b[x..], b[2]).ok_or_else(fail)?;
            x += 3;
        }
    } else if b[4] == b'.' {
        if !(b.len() + 1).is_multiple_of(5) {
            return Err(fail());
        }
        let n = 2 * (b.len() + 1) / 5;
        if !valid(n) {
            return Err(fail());
        }
        hw = vec![0u8; n];
        let mut x = 0;
        let mut i = 0;
        while i < n {
            hw[i] = xtoi2(&b[x..x + 2], 0).ok_or_else(fail)?;
            hw[i + 1] = xtoi2(&b[x + 2..], b[4]).ok_or_else(fail)?;
            x += 5;
            i += 2;
        }
    } else {
        if !b.len().is_multiple_of(2) {
            return Err(fail());
        }
        let n = b.len() / 2;
        if !valid(n) {
            return Err(fail());
        }
        hw = vec![0u8; n];
        let mut x = 0;
        for h in hw.iter_mut() {
            *h = xtoi2(&b[x..x + 2], 0).ok_or_else(fail)?;
            x += 2;
        }
    }
    Ok(HardwareAddr(hw))
}
