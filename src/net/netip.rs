//! Go's `net/netip`: [`Addr`], [`AddrPort`] and [`Prefix`] value types.
//!
//! Parsing follows Go's grammar and error texts exactly (the grammar is ported
//! from `net/netip/netip.go`; see NOTICE). Addresses convert to and from
//! `std::net::{Ipv4Addr, Ipv6Addr, IpAddr, SocketAddr}`. The zero [`Addr`]
//! (`Addr::default()`) is the invalid address, distinct from `0.0.0.0` and `::`.
//!
//! ```
//! use rust_stdlib::net::netip::{Addr, Prefix};
//! let ip: Addr = "2001:db8::1%eth0".parse()?;
//! assert_eq!(ip.zone(), "eth0");
//! assert!("10.0.0.0/8".parse::<Prefix>()?.contains(&"10.1.2.3".parse()?));
//! # Ok::<(), rust_stdlib::net::netip::Error>(())
//! ```
use crate::strconv;
use std::cmp::Ordering;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;
use std::sync::Arc;

/// A parse failure of `Addr::from_str` (Go's unexported `parseAddrError`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseAddrError {
    /// The string given to `Addr::from_str`.
    pub input: String,
    /// An explanation of the failure.
    pub msg: String,
    /// The unparsed portion of `input` at which the error occurred, or empty.
    pub at: String,
}

impl fmt::Display for ParseAddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ParseAddr({}): {}",
            strconv::quote(&self.input),
            self.msg
        )?;
        if !self.at.is_empty() {
            write!(f, " (at {})", strconv::quote(&self.at))?;
        }
        Ok(())
    }
}

/// A parse failure of `Prefix::from_str` (Go's unexported `parsePrefixError`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsePrefixError {
    /// The string given to `Prefix::from_str`.
    pub input: String,
    /// An explanation of the failure.
    pub msg: String,
}

impl fmt::Display for ParsePrefixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "netip.ParsePrefix({}): {}",
            strconv::quote(&self.input),
            self.msg
        )
    }
}

/// Every error this module returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A `Addr::from_str` failure.
    ParseAddr(ParseAddrError),
    /// A `Prefix::from_str` failure.
    ParsePrefix(ParsePrefixError),
    /// A plain `errors.New` message.
    Message(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ParseAddr(e) => e.fmt(f),
            Error::ParsePrefix(e) => e.fmt(f),
            Error::Message(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {}

fn msg(m: impl Into<String>) -> Error {
    Error::Message(m.into())
}

fn addr_err(input: &str, m: &str, at: &str) -> Error {
    Error::ParseAddr(ParseAddrError {
        input: input.to_owned(),
        msg: m.to_owned(),
        at: at.to_owned(),
    })
}

/// An IPv6 zone; only ever set on an IPv6 address.
type Zone = Arc<str>;

/// An IPv4 or IPv6 address, with an optional IPv6 zone. Comparable, hashable
/// and ordered like Go's `netip.Addr`: the invalid address first, then IPv4,
/// then IPv6 by value and zone. The zero [`Addr`] is `ip: None`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Addr {
    ip: Option<IpAddr>,
    zone: Option<Zone>,
    // Go's `Next` on the zero `Addr` yields an invalid address holding the
    // value 1 (and so on); kept so equality and ordering match. Zero otherwise.
    stray: u128,
}

/// `netip.IPv6LinkLocalAllNodes`: `ff02::1`.
pub const IPV6_LINK_LOCAL_ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// `netip.IPv6LinkLocalAllRouters`: `ff02::2`.
pub const IPV6_LINK_LOCAL_ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);

/// `netip.AddrFrom4`.
fn addr_from4(a: [u8; 4]) -> Addr {
    Addr::from(Ipv4Addr::from(a))
}

/// `netip.AddrFrom16`: an IPv4-mapped address stays IPv6 (see [`Addr::unmap`]).
fn addr_from16(a: [u8; 16]) -> Addr {
    Addr::from(Ipv6Addr::from(a))
}

/// `netip.ParseAddr`.
fn parse_addr(s: &str) -> Result<Addr, Error> {
    for &c in s.as_bytes() {
        match c {
            b'.' => return parse_ipv4(s),
            b':' => return parse_ipv6(s),
            b'%' => return Err(addr_err(s, "missing IPv6 address", "")),
            _ => {}
        }
    }
    Err(addr_err(s, "unable to parse IP", ""))
}

fn parse_ipv4_fields(input: &str, off: usize, end: usize, fields: &mut [u8]) -> Result<(), Error> {
    let s = &input[off..end];
    let b = s.as_bytes();
    let (mut val, mut pos, mut dig_len) = (0u32, 0usize, 0usize);
    for i in 0..b.len() {
        if b[i].is_ascii_digit() {
            if dig_len == 1 && val == 0 {
                return Err(addr_err(
                    input,
                    "IPv4 field has octet with leading zero",
                    "",
                ));
            }
            val = val * 10 + (b[i] - b'0') as u32;
            dig_len += 1;
            if val > 255 {
                return Err(addr_err(input, "IPv4 field has value >255", ""));
            }
        } else if b[i] == b'.' {
            if i == 0 || i == b.len() - 1 || b[i - 1] == b'.' {
                return Err(addr_err(
                    input,
                    "IPv4 field must have at least one digit",
                    &s[i..],
                ));
            }
            if pos == 3 {
                return Err(addr_err(input, "IPv4 address too long", ""));
            }
            fields[pos] = val as u8;
            pos += 1;
            val = 0;
            dig_len = 0;
        } else {
            return Err(addr_err(input, "unexpected character", &s[i..]));
        }
    }
    if pos < 3 {
        return Err(addr_err(input, "IPv4 address too short", ""));
    }
    fields[3] = val as u8;
    Ok(())
}

fn parse_ipv4(s: &str) -> Result<Addr, Error> {
    let mut f = [0u8; 4];
    parse_ipv4_fields(s, 0, s.len(), &mut f)?;
    Ok(addr_from4(f))
}

fn parse_ipv6(input: &str) -> Result<Addr, Error> {
    let mut s = input;
    let mut zone = "";
    if let Some(i) = s.find('%') {
        zone = &s[i + 1..];
        s = &s[..i];
        if zone.is_empty() {
            return Err(addr_err(input, "zone must be a non-empty string", ""));
        }
    }
    let mut ip = [0u8; 16];
    let mut ellipsis: isize = -1;
    if s.len() >= 2 && s.starts_with("::") {
        ellipsis = 0;
        s = &s[2..];
        if s.is_empty() {
            return Ok(Addr::from(Ipv6Addr::UNSPECIFIED).with_zone(zone));
        }
    }
    let mut i = 0usize;
    while i < 16 {
        let sb = s.as_bytes();
        let mut off = 0;
        let mut acc = 0u32;
        while off < sb.len() {
            let c = sb[off];
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => break,
            };
            acc = (acc << 4) + d as u32;
            if off > 3 {
                return Err(addr_err(input, "each group must have 4 or less digits", s));
            }
            if acc > 0xffff {
                return Err(addr_err(input, "IPv6 field has value >=2^16", s));
            }
            off += 1;
        }
        if off == 0 {
            return Err(addr_err(
                input,
                "each colon-separated field must have at least one digit",
                s,
            ));
        }
        if off < sb.len() && sb[off] == b'.' {
            if ellipsis < 0 && i != 12 {
                return Err(addr_err(
                    input,
                    "embedded IPv4 address must replace the final 2 fields of the address",
                    s,
                ));
            }
            if i + 4 > 16 {
                return Err(addr_err(
                    input,
                    "too many hex fields to fit an embedded IPv4 at the end of the address",
                    s,
                ));
            }
            let mut end = input.len();
            if !zone.is_empty() {
                end -= zone.len() + 1;
            }
            parse_ipv4_fields(input, end - s.len(), end, &mut ip[i..i + 4])?;
            s = "";
            i += 4;
            break;
        }
        ip[i] = (acc >> 8) as u8;
        ip[i + 1] = acc as u8;
        i += 2;
        s = &s[off..];
        if s.is_empty() {
            break;
        }
        if !s.starts_with(':') {
            return Err(addr_err(input, "unexpected character, want colon", s));
        } else if s.len() == 1 {
            return Err(addr_err(
                input,
                "colon must be followed by more characters",
                s,
            ));
        }
        s = &s[1..];
        if s.starts_with(':') {
            if ellipsis >= 0 {
                return Err(addr_err(input, "multiple :: in address", s));
            }
            ellipsis = i as isize;
            s = &s[1..];
            if s.is_empty() {
                break;
            }
        }
    }
    if !s.is_empty() {
        return Err(addr_err(input, "trailing garbage after address", s));
    }
    if i < 16 {
        if ellipsis < 0 {
            return Err(addr_err(input, "address string too short", ""));
        }
        let ell = ellipsis as usize;
        let n = 16 - i;
        for j in (ell..i).rev() {
            ip[j + n] = ip[j];
        }
        ip[ell..ell + n].fill(0);
    } else if ellipsis >= 0 {
        return Err(addr_err(
            input,
            "the :: must expand to at least one field of zeros",
            "",
        ));
    }
    Ok(addr_from16(ip).with_zone(zone))
}

// The top `n` bits set.
fn mask6(n: usize) -> u128 {
    if n == 0 {
        0
    } else {
        !0u128 << (128 - n)
    }
}

impl Addr {
    fn v6u16(&self, i: u32) -> u16 {
        Ipv6Addr::from(self.as16()).segments()[i as usize]
    }

    // The 128-bit value; an IPv4 address is IPv4-mapped.
    fn bits(&self) -> u128 {
        u128::from_be_bytes(self.as16())
    }

    // `ip` with an IPv4-mapped IPv6 address turned into IPv4 (`to_canonical`).
    fn canon(&self) -> Option<IpAddr> {
        self.ip.map(|a| a.to_canonical())
    }

    /// `Addr.IsValid`: false only for the zero `Addr`.
    pub fn is_valid(&self) -> bool {
        self.ip.is_some()
    }

    /// `Addr.BitLen`: 32, 128, or 0 for the zero `Addr`.
    pub fn bit_len(&self) -> usize {
        match self.ip {
            None => 0,
            Some(IpAddr::V4(_)) => 32,
            Some(IpAddr::V6(_)) => 128,
        }
    }

    /// `Addr.Zone`: the IPv6 zone, or "".
    pub fn zone(&self) -> &str {
        self.zone.as_deref().unwrap_or("")
    }

    /// `Addr.Is4`: false for IPv4-mapped IPv6.
    pub fn is4(&self) -> bool {
        self.ip.is_some_and(|a| a.is_ipv4())
    }

    /// `Addr.Is4In6`: in `::ffff:0:0/96`.
    pub fn is4in6(&self) -> bool {
        matches!(self.ip, Some(IpAddr::V6(a)) if a.to_ipv4_mapped().is_some())
    }

    /// `Addr.Is6`: includes IPv4-mapped IPv6.
    pub fn is6(&self) -> bool {
        self.ip.is_some_and(|a| a.is_ipv6())
    }

    /// `Addr.Unmap`: strips the IPv4-mapped prefix.
    pub fn unmap(&self) -> Addr {
        if self.is4in6() {
            return Addr {
                ip: self.canon(),
                ..Addr::default()
            };
        }
        self.clone()
    }

    /// `Addr.WithZone`: a no-op for IPv4 and the zero `Addr`.
    pub fn with_zone(&self, zone: &str) -> Addr {
        let mut ip = self.clone();
        if ip.is6() {
            ip.zone = (!zone.is_empty()).then(|| Zone::from(zone));
        }
        ip
    }

    fn without_zone(&self) -> Addr {
        self.with_zone("")
    }

    fn has_zone(&self) -> bool {
        self.zone.is_some()
    }

    /// `Addr.IsLinkLocalUnicast`.
    pub fn is_link_local_unicast(&self) -> bool {
        match self.canon() {
            Some(IpAddr::V4(a)) => a.is_link_local(),
            // std's `Ipv6Addr::is_unicast_link_local` is unstable.
            Some(IpAddr::V6(a)) => a.segments()[0] & 0xffc0 == 0xfe80,
            None => false,
        }
    }

    /// `Addr.IsLoopback`.
    pub fn is_loopback(&self) -> bool {
        self.canon().is_some_and(|a| a.is_loopback())
    }

    /// `Addr.IsMulticast`.
    pub fn is_multicast(&self) -> bool {
        self.canon().is_some_and(|a| a.is_multicast())
    }

    /// `Addr.IsInterfaceLocalMulticast`.
    pub fn is_interface_local_multicast(&self) -> bool {
        // std's `Ipv6Addr::multicast_scope` is unstable.
        matches!(self.ip, Some(IpAddr::V6(a)) if a.to_ipv4_mapped().is_none()
            && a.segments()[0] & 0xff0f == 0xff01)
    }

    /// `Addr.IsLinkLocalMulticast`.
    pub fn is_link_local_multicast(&self) -> bool {
        match self.canon() {
            Some(IpAddr::V4(a)) => a.octets()[..3] == [224, 0, 0],
            Some(IpAddr::V6(a)) => a.segments()[0] & 0xff0f == 0xff02,
            None => false,
        }
    }

    /// `Addr.IsGlobalUnicast`.
    pub fn is_global_unicast(&self) -> bool {
        let ip = self.unmap();
        match ip.ip {
            None => return false,
            Some(IpAddr::V4(a)) if a.is_unspecified() || a.is_broadcast() => return false,
            _ => {}
        }
        // `Addr::is_unspecified` is zone-aware, so `::%zone` counts as global
        // unicast exactly as in Go.
        !ip.is_unspecified()
            && !ip.is_loopback()
            && !ip.is_multicast()
            && !ip.is_link_local_unicast()
    }

    /// `Addr.IsPrivate`: RFC 1918 and RFC 4193.
    pub fn is_private(&self) -> bool {
        match self.canon() {
            Some(IpAddr::V4(a)) => a.is_private(),
            // std's `Ipv6Addr::is_unique_local` is unstable.
            Some(IpAddr::V6(a)) => a.octets()[0] & 0xfe == 0xfc,
            None => false,
        }
    }

    /// `Addr.IsUnspecified`: `0.0.0.0` or `::` (a zoned `::` is not).
    pub fn is_unspecified(&self) -> bool {
        self.zone.is_none() && self.ip.is_some_and(|a| a.is_unspecified())
    }

    /// `Addr.Prefix`: keeps the top `b` bits.
    pub fn prefix(&self, b: isize) -> Result<Prefix, Error> {
        if b < 0 {
            return Err(msg("negative Prefix bits"));
        }
        let bits = b as usize;
        let ip = match self.ip {
            None => return Ok(Prefix::default()),
            Some(IpAddr::V4(a)) => {
                if bits > 32 {
                    return Err(msg(format!("prefix length {b} too large for IPv4")));
                }
                IpAddr::V4(Ipv4Addr::from(a.to_bits() & (mask6(bits + 96) as u32)))
            }
            Some(IpAddr::V6(a)) => {
                if bits > 128 {
                    return Err(msg(format!("prefix length {b} too large for IPv6")));
                }
                IpAddr::V6(Ipv6Addr::from(a.to_bits() & mask6(bits)))
            }
        };
        Ok(Prefix::new(
            Addr {
                ip: Some(ip),
                zone: self.zone.clone(),
                ..Addr::default()
            },
            b,
        ))
    }

    /// `Addr.As16`: IPv4 as IPv4-mapped; zeros for the zero `Addr`.
    pub fn as16(&self) -> [u8; 16] {
        match self.ip {
            None => [0; 16],
            Some(IpAddr::V4(a)) => a.to_ipv6_mapped().octets(),
            Some(IpAddr::V6(a)) => a.octets(),
        }
    }

    /// `Addr.As4`: panics (like Go) for the zero `Addr` and for IPv6.
    pub fn as4(&self) -> [u8; 4] {
        match self.ip {
            Some(IpAddr::V4(a)) => a.octets(),
            Some(IpAddr::V6(a)) => match a.to_ipv4_mapped() {
                Some(a) => a.octets(),
                None => panic!("As4 called on IPv6 address"),
            },
            None => panic!("As4 called on IP zero value"),
        }
    }

    /// `Addr.AsSlice`: 4 or 16 bytes, empty for the zero `Addr`.
    pub fn as_slice(&self) -> Vec<u8> {
        match self.ip {
            None => Vec::new(),
            Some(IpAddr::V4(a)) => a.octets().to_vec(),
            Some(IpAddr::V6(a)) => a.octets().to_vec(),
        }
    }

    /// `Addr.Next`: the following address, or the zero `Addr` on overflow.
    pub fn next(&self) -> Addr {
        let ip = match self.ip {
            Some(IpAddr::V4(a)) => a.to_bits().checked_add(1).map(|b| IpAddr::V4(b.into())),
            Some(IpAddr::V6(a)) => a.to_bits().checked_add(1).map(|b| IpAddr::V6(b.into())),
            None => {
                return Addr {
                    stray: self.stray.wrapping_add(1),
                    ..Addr::default()
                }
            }
        };
        match ip {
            Some(ip) => Addr {
                ip: Some(ip),
                zone: self.zone.clone(),
                ..Addr::default()
            },
            None => Addr::default(),
        }
    }

    /// `Addr.Prev`: the preceding address, or the zero `Addr` at the start.
    pub fn prev(&self) -> Addr {
        let ip = match self.ip {
            Some(IpAddr::V4(a)) => a.to_bits().checked_sub(1).map(|b| IpAddr::V4(b.into())),
            Some(IpAddr::V6(a)) => a.to_bits().checked_sub(1).map(|b| IpAddr::V6(b.into())),
            None => {
                return Addr {
                    stray: self.stray.saturating_sub(1),
                    ..Addr::default()
                }
            }
        };
        match ip {
            Some(ip) => Addr {
                ip: Some(ip),
                zone: self.zone.clone(),
                ..Addr::default()
            },
            None => Addr::default(),
        }
    }

    fn append4(&self, out: &mut String) {
        use std::fmt::Write;
        let _ = write!(out, "{}", Ipv4Addr::from(self.as4()));
    }

    fn append4in6(&self, out: &mut String) {
        out.push_str("::ffff:");
        self.unmap().append4(out);
        if let Some(z) = &self.zone {
            out.push('%');
            out.push_str(z);
        }
    }

    fn append6(&self, out: &mut String) {
        use std::fmt::Write;
        let (mut zs, mut ze) = (255u32, 255u32);
        for i in 0..8 {
            let mut j = i;
            while j < 8 && self.v6u16(j) == 0 {
                j += 1;
            }
            let l = j - i;
            if l >= 2 && l > ze.wrapping_sub(zs) & 0xff {
                zs = i;
                ze = j;
            }
        }
        let mut i = 0;
        while i < 8 {
            if i == zs {
                out.push_str("::");
                i = ze;
                if i >= 8 {
                    break;
                }
            } else if i > 0 {
                out.push(':');
            }
            let _ = write!(out, "{:x}", self.v6u16(i));
            i += 1;
        }
        if let Some(z) = &self.zone {
            out.push('%');
            out.push_str(z);
        }
    }

    /// `Addr.AppendTo`: the `marshal_text` encoding appended to `b`.
    pub fn append_to(&self, mut b: Vec<u8>) -> Vec<u8> {
        if self.is_valid() {
            b.extend_from_slice(self.to_string().as_bytes());
        }
        b
    }

    /// `Addr.StringExpanded`: IPv6 with leading zeros and no `::`.
    pub fn string_expanded(&self) -> String {
        match self.ip {
            None | Some(IpAddr::V4(_)) => self.to_string(),
            Some(IpAddr::V6(_)) => {
                let mut out = String::new();
                for i in 0..8 {
                    if i > 0 {
                        out.push(':');
                    }
                    out.push_str(&format!("{:04x}", self.v6u16(i)));
                }
                if let Some(z) = &self.zone {
                    out.push('%');
                    out.push_str(z);
                }
                out
            }
        }
    }

    /// `Addr.AppendText`.
    pub fn append_text(&self, b: Vec<u8>) -> Result<Vec<u8>, Error> {
        Ok(self.append_to(b))
    }

    /// `Addr.MarshalText`: the string form, or empty for the zero `Addr`.
    pub fn marshal_text(&self) -> Result<Vec<u8>, Error> {
        self.append_text(Vec::new())
    }

    /// `Addr.UnmarshalText`: empty text yields the zero `Addr`.
    pub fn unmarshal_text(&mut self, text: &[u8]) -> Result<(), Error> {
        if text.is_empty() {
            *self = Addr::default();
            return Ok(());
        }
        *self = parse_addr(&String::from_utf8_lossy(text))?;
        Ok(())
    }

    /// `Addr.AppendBinary`: 4 bytes (IPv4) or 16 bytes plus the zone (IPv6).
    pub fn append_binary(&self, mut b: Vec<u8>) -> Result<Vec<u8>, Error> {
        match self.ip {
            None => {}
            Some(IpAddr::V4(a)) => b.extend_from_slice(&a.octets()),
            Some(IpAddr::V6(_)) => {
                b.extend_from_slice(&self.as16());
                b.extend_from_slice(self.zone().as_bytes());
            }
        }
        Ok(b)
    }

    /// `Addr.MarshalBinary`.
    pub fn marshal_binary(&self) -> Result<Vec<u8>, Error> {
        self.append_binary(Vec::new())
    }

    /// `Addr.UnmarshalBinary`.
    pub fn unmarshal_binary(&mut self, b: &[u8]) -> Result<(), Error> {
        match b.len() {
            0 => *self = Addr::default(),
            4 => *self = addr_from4(b.try_into().unwrap()),
            16 => *self = addr_from16(b.try_into().unwrap()),
            n if n > 16 => {
                *self = addr_from16(b[..16].try_into().unwrap())
                    .with_zone(&String::from_utf8_lossy(&b[16..]))
            }
            _ => return Err(msg("unexpected slice size")),
        }
        Ok(())
    }
}

impl fmt::Display for Addr {
    /// `Addr.String`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();
        match self.ip {
            None => s.push_str("invalid IP"),
            Some(IpAddr::V4(_)) => self.append4(&mut s),
            Some(IpAddr::V6(_)) if self.is4in6() => self.append4in6(&mut s),
            Some(IpAddr::V6(_)) => self.append6(&mut s),
        }
        f.write_str(&s)
    }
}

impl FromStr for Addr {
    type Err = Error;
    fn from_str(s: &str) -> Result<Addr, Error> {
        parse_addr(s)
    }
}

impl From<[u8; 4]> for Addr {
    /// `AddrFrom4`.
    fn from(a: [u8; 4]) -> Addr {
        addr_from4(a)
    }
}

impl From<[u8; 16]> for Addr {
    /// `AddrFrom16`: an IPv4-mapped address stays IPv6 (see [`Addr::unmap`]).
    fn from(a: [u8; 16]) -> Addr {
        addr_from16(a)
    }
}

impl TryFrom<&[u8]> for Addr {
    type Error = Error;
    /// `AddrFromSlice`: a 4- or 16-byte slice.
    fn try_from(s: &[u8]) -> Result<Addr, Error> {
        match s.len() {
            4 => Ok(addr_from4(s.try_into().unwrap())),
            16 => Ok(addr_from16(s.try_into().unwrap())),
            _ => Err(msg("unexpected slice size")),
        }
    }
}

impl TryFrom<&Addr> for IpAddr {
    type Error = Error;
    /// The `std::net` address (the zone is dropped); the zero `Addr` fails.
    fn try_from(a: &Addr) -> Result<IpAddr, Error> {
        a.ip.ok_or_else(|| msg("invalid IP"))
    }
}

impl From<Ipv4Addr> for Addr {
    fn from(a: Ipv4Addr) -> Addr {
        IpAddr::V4(a).into()
    }
}

impl From<Ipv6Addr> for Addr {
    fn from(a: Ipv6Addr) -> Addr {
        IpAddr::V6(a).into()
    }
}

impl From<IpAddr> for Addr {
    fn from(a: IpAddr) -> Addr {
        Addr {
            ip: Some(a),
            ..Addr::default()
        }
    }
}

/// An IP address and a port.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct AddrPort {
    ip: Addr,
    port: u16,
}

fn split_addr_port(s: &str) -> Result<(&str, &str, bool), Error> {
    let i = s.rfind(':').ok_or_else(|| msg("not an ip:port"))?;
    let (mut ip, port) = (&s[..i], &s[i + 1..]);
    if ip.is_empty() {
        return Err(msg("no IP"));
    }
    if port.is_empty() {
        return Err(msg("no port"));
    }
    let mut v6 = false;
    if ip.starts_with('[') {
        if ip.len() < 2 || !ip.ends_with(']') {
            return Err(msg("missing ]"));
        }
        ip = &ip[1..ip.len() - 1];
        v6 = true;
    }
    Ok((ip, port, v6))
}

/// `netip.ParseAddrPort`.
fn parse_addr_port(s: &str) -> Result<AddrPort, Error> {
    let (ip, port, v6) = split_addr_port(s)?;
    let port = match port.parse::<u16>() {
        Ok(p) if port.bytes().all(|c| c.is_ascii_digit()) => p,
        _ => {
            return Err(msg(format!(
                "invalid port {} parsing {}",
                strconv::quote(port),
                strconv::quote(s)
            )))
        }
    };
    let ip = parse_addr(ip)?;
    if v6 && ip.is4() {
        return Err(msg(format!(
            "invalid ip:port {}, square brackets can only be used with IPv6 addresses",
            strconv::quote(s)
        )));
    } else if !v6 && ip.is6() {
        return Err(msg(format!(
            "invalid ip:port {}, IPv6 addresses must be surrounded by square brackets",
            strconv::quote(s)
        )));
    }
    Ok(AddrPort { ip, port })
}

impl AddrPort {
    /// `AddrPortFrom`: the address and port as given.
    pub fn new(ip: Addr, port: u16) -> AddrPort {
        AddrPort { ip, port }
    }

    /// `AddrPort.Addr`.
    pub fn addr(&self) -> &Addr {
        &self.ip
    }

    /// `AddrPort.Port`.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// `AddrPort.IsValid`: the address is valid (any port).
    pub fn is_valid(&self) -> bool {
        self.ip.is_valid()
    }

    /// `AddrPort.AppendTo`.
    pub fn append_to(&self, mut b: Vec<u8>) -> Vec<u8> {
        if self.ip.is_valid() {
            b.extend_from_slice(self.to_string().as_bytes());
        }
        b
    }

    /// `AddrPort.AppendText`.
    pub fn append_text(&self, b: Vec<u8>) -> Result<Vec<u8>, Error> {
        Ok(self.append_to(b))
    }

    /// `AddrPort.MarshalText`.
    pub fn marshal_text(&self) -> Result<Vec<u8>, Error> {
        self.append_text(Vec::new())
    }

    /// `AddrPort.UnmarshalText`.
    pub fn unmarshal_text(&mut self, text: &[u8]) -> Result<(), Error> {
        if text.is_empty() {
            *self = AddrPort::default();
            return Ok(());
        }
        *self = parse_addr_port(&String::from_utf8_lossy(text))?;
        Ok(())
    }

    /// `AddrPort.AppendBinary`: the address encoding plus the port, little-endian.
    pub fn append_binary(&self, b: Vec<u8>) -> Result<Vec<u8>, Error> {
        let mut b = self.ip.append_binary(b)?;
        b.extend_from_slice(&self.port.to_le_bytes());
        Ok(b)
    }

    /// `AddrPort.MarshalBinary`.
    pub fn marshal_binary(&self) -> Result<Vec<u8>, Error> {
        self.append_binary(Vec::new())
    }

    /// `AddrPort.UnmarshalBinary`.
    pub fn unmarshal_binary(&mut self, b: &[u8]) -> Result<(), Error> {
        if b.len() < 2 {
            return Err(msg("unexpected slice size"));
        }
        let mut addr = Addr::default();
        addr.unmarshal_binary(&b[..b.len() - 2])?;
        *self = AddrPort {
            ip: addr,
            port: u16::from_le_bytes([b[b.len() - 2], b[b.len() - 1]]),
        };
        Ok(())
    }
}

impl TryFrom<&AddrPort> for SocketAddr {
    type Error = Error;
    /// The `std::net` socket address (the zone is dropped); an invalid one fails.
    fn try_from(a: &AddrPort) -> Result<SocketAddr, Error> {
        Ok(match IpAddr::try_from(&a.ip)? {
            IpAddr::V4(ip) => SocketAddr::V4(SocketAddrV4::new(ip, a.port)),
            IpAddr::V6(ip) => SocketAddr::V6(SocketAddrV6::new(ip, a.port, 0, 0)),
        })
    }
}

impl fmt::Display for AddrPort {
    /// `AddrPort.String`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ip.ip {
            None => f.write_str("invalid AddrPort"),
            Some(IpAddr::V4(_)) => write!(f, "{}:{}", self.ip, self.port),
            Some(IpAddr::V6(_)) => write!(f, "[{}]:{}", self.ip, self.port),
        }
    }
}

impl PartialOrd for AddrPort {
    fn partial_cmp(&self, other: &AddrPort) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AddrPort {
    fn cmp(&self, other: &AddrPort) -> Ordering {
        self.ip.cmp(&other.ip).then(self.port.cmp(&other.port))
    }
}

impl FromStr for AddrPort {
    type Err = Error;
    fn from_str(s: &str) -> Result<AddrPort, Error> {
        parse_addr_port(s)
    }
}

impl From<SocketAddr> for AddrPort {
    fn from(a: SocketAddr) -> AddrPort {
        AddrPort {
            ip: a.ip().into(),
            port: a.port(),
        }
    }
}

/// An IP address prefix (CIDR), whose zone is always stripped.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Prefix {
    ip: Addr,
    // The bit length plus one; zero means invalid.
    bits_plus_one: u8,
}

/// `netip.ParsePrefix`.
fn parse_prefix(s: &str) -> Result<Prefix, Error> {
    let perr = |m: String| {
        Error::ParsePrefix(ParsePrefixError {
            input: s.to_owned(),
            msg: m,
        })
    };
    let i = s.rfind('/').ok_or_else(|| perr("no '/'".into()))?;
    let ip = parse_addr(&s[..i]).map_err(|e| perr(e.to_string()))?;
    if ip.has_zone() {
        return Err(perr("IPv6 zones cannot be present in a prefix".into()));
    }
    let bits_str = &s[i + 1..];
    let bad = || {
        perr(format!(
            "bad bits after slash: {}",
            strconv::quote(bits_str)
        ))
    };
    if bits_str.len() > 1 && !matches!(bits_str.as_bytes()[0], b'1'..=b'9') {
        return Err(bad());
    }
    let bits = strconv::atoi(bits_str).map_err(|_| bad())?;
    let max = if ip.is6() { 128 } else { 32 };
    if bits < 0 || bits > max {
        return Err(perr("prefix length out of range".into()));
    }
    Ok(Prefix::new(ip, bits))
}

impl Prefix {
    /// `PrefixFrom`: does not mask host bits; out-of-range `bits` make an
    /// invalid prefix whose [`Prefix::bits`] is -1.
    pub fn new(ip: Addr, bits: isize) -> Prefix {
        let mut bits_plus_one = 0u8;
        if ip.is_valid() && bits >= 0 && bits as usize <= ip.bit_len() {
            bits_plus_one = bits as u8 + 1;
        }
        Prefix {
            ip: ip.without_zone(),
            bits_plus_one,
        }
    }

    /// `Prefix.Addr`.
    pub fn addr(&self) -> &Addr {
        &self.ip
    }

    /// `Prefix.Bits`: -1 if invalid.
    pub fn bits(&self) -> isize {
        self.bits_plus_one as isize - 1
    }

    /// `Prefix.IsValid`.
    pub fn is_valid(&self) -> bool {
        self.bits_plus_one > 0
    }

    fn is_zero(&self) -> bool {
        *self == Prefix::default()
    }

    /// `Prefix.IsSingleIP`.
    pub fn is_single_ip(&self) -> bool {
        self.is_valid() && self.bits() == self.ip.bit_len() as isize
    }

    /// `Prefix.Masked`: host bits cleared; the zero `Prefix` if invalid.
    pub fn masked(&self) -> Prefix {
        self.ip.prefix(self.bits()).unwrap_or_default()
    }

    /// `Prefix.Contains`.
    pub fn contains(&self, ip: &Addr) -> bool {
        if !self.is_valid() || ip.has_zone() {
            return false;
        }
        let (f1, f2) = (self.ip.bit_len(), ip.bit_len());
        if f1 == 0 || f2 == 0 || f1 != f2 {
            return false;
        }
        let eff = self.bits() as usize + if ip.is4() { 96 } else { 0 };
        (ip.bits() ^ self.ip.bits()) & mask6(eff) == 0
    }

    /// `Prefix.Overlaps`.
    pub fn overlaps(&self, o: &Prefix) -> bool {
        if !self.is_valid() || !o.is_valid() {
            return false;
        }
        if self == o {
            return true;
        }
        if self.ip.is4() != o.ip.is4() {
            return false;
        }
        let min_bits = self.bits().min(o.bits());
        if min_bits == 0 {
            return true;
        }
        match (self.ip.prefix(min_bits), o.ip.prefix(min_bits)) {
            (Ok(p), Ok(q)) => p.ip == q.ip,
            _ => false,
        }
    }

    /// `Prefix.AppendTo`.
    pub fn append_to(&self, mut b: Vec<u8>) -> Vec<u8> {
        if !self.is_zero() {
            b.extend_from_slice(self.to_string().as_bytes());
        }
        b
    }

    /// `Prefix.AppendText`.
    pub fn append_text(&self, b: Vec<u8>) -> Result<Vec<u8>, Error> {
        Ok(self.append_to(b))
    }

    /// `Prefix.MarshalText`: empty for the zero `Prefix`.
    pub fn marshal_text(&self) -> Result<Vec<u8>, Error> {
        self.append_text(Vec::new())
    }

    /// `Prefix.UnmarshalText`.
    pub fn unmarshal_text(&mut self, text: &[u8]) -> Result<(), Error> {
        if text.is_empty() {
            *self = Prefix::default();
            return Ok(());
        }
        *self = parse_prefix(&String::from_utf8_lossy(text))?;
        Ok(())
    }

    /// `Prefix.AppendBinary`: the address encoding plus the bits byte.
    pub fn append_binary(&self, b: Vec<u8>) -> Result<Vec<u8>, Error> {
        let mut b = self.ip.without_zone().append_binary(b)?;
        b.push(self.bits() as u8);
        Ok(b)
    }

    /// `Prefix.MarshalBinary`.
    pub fn marshal_binary(&self) -> Result<Vec<u8>, Error> {
        self.append_binary(Vec::new())
    }

    /// `Prefix.UnmarshalBinary`.
    pub fn unmarshal_binary(&mut self, b: &[u8]) -> Result<(), Error> {
        let Some((&bits, rest)) = b.split_last() else {
            return Err(msg("unexpected slice size"));
        };
        let mut addr = Addr::default();
        addr.unmarshal_binary(rest)?;
        *self = Prefix::new(addr, bits as isize);
        Ok(())
    }
}

impl fmt::Display for Prefix {
    /// `Prefix.String`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.is_valid() {
            return f.write_str("invalid Prefix");
        }
        let mut s = String::new();
        match self.ip.ip {
            Some(IpAddr::V4(_)) => self.ip.append4(&mut s),
            _ if self.ip.is4in6() => {
                s.push_str("::ffff:");
                self.ip.unmap().append4(&mut s);
            }
            _ => self.ip.append6(&mut s),
        }
        write!(f, "{s}/{}", self.bits())
    }
}

impl PartialOrd for Prefix {
    fn partial_cmp(&self, other: &Prefix) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Prefix {
    fn cmp(&self, other: &Prefix) -> Ordering {
        self.masked()
            .ip
            .cmp(&other.masked().ip)
            .then(self.bits().cmp(&other.bits()))
            .then_with(|| self.ip.cmp(&other.ip))
    }
}

impl FromStr for Prefix {
    type Err = Error;
    fn from_str(s: &str) -> Result<Prefix, Error> {
        parse_prefix(s)
    }
}
