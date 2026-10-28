//! `net.LookupAddr`, `net.LookupCNAME`, `Resolver.LookupAddr` and
//! `Resolver.LookupCNAME` through the C library, the way Go's cgo resolver
//! does it: `getnameinfo` with `NI_NAMEREQD` for addresses and `res_search`
//! (a CNAME query whose answer is parsed here) for names.
//!
//! The resolver is chosen as Go chooses it (`conf.go`): `PreferGo`, the
//! `GODEBUG=netdns=` setting, the platform default (macOS always prefers the
//! C library), `LOCALDOMAIN`/`RES_OPTIONS`/`HOSTALIASES`, and what
//! `/etc/resolv.conf` and `/etc/nsswitch.conf` ask for. When the choice is
//! Go's own resolver, or when the C library fails for a CNAME lookup (Go then
//! falls back to its resolver), the work is handed to the [`PureResolver`]
//! set on the [`Resolver`]: the pure DNS client lives in the root crate,
//! which this crate cannot depend on. A [`Resolver`] without one always asks
//! the C library, and a failed CNAME lookup reports the C library's error.
use crate::errno::{Errno, EMFILE};
use crate::ffi::{dns, SockAddr};
use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;

/// `net.DNSError`.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct DnsError {
    /// Description of the error.
    pub err: String,
    /// The name looked for.
    pub name: String,
    /// The server used.
    pub server: String,
    /// If true, timed out.
    pub is_timeout: bool,
    /// If true, the error is temporary.
    pub is_temporary: bool,
    /// The name or its records were not found.
    pub is_not_found: bool,
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "lookup {}", self.name)?;
        if !self.server.is_empty() {
            write!(f, " on {}", self.server)?;
        }
        write!(f, ": {}", self.err)
    }
}

impl std::error::Error for DnsError {}

impl From<DnsError> for std::io::Error {
    fn from(e: DnsError) -> std::io::Error {
        std::io::Error::other(e)
    }
}

impl DnsError {
    fn new(err: &str, name: &str) -> DnsError {
        DnsError {
            err: err.into(),
            name: name.into(),
            ..DnsError::default()
        }
    }

    fn no_such_host(name: &str) -> DnsError {
        DnsError {
            is_not_found: true,
            ..DnsError::new("no such host", name)
        }
    }
}

/// The pure-Go-style resolver, supplied by the caller (the root crate's
/// `Resolver`): used when Go's own resolver is the selected one.
pub trait PureResolver: Send + Sync {
    /// `goLookupPTR`.
    fn lookup_addr(&self, addr: &str) -> Result<Vec<String>, DnsError>;
    /// `goLookupCNAME`.
    fn lookup_cname(&self, host: &str) -> Result<String, DnsError>;
}

/// Which implementation answers a lookup.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LookupOrder {
    /// The C library's resolver (Go's `hostLookupCgo`).
    Cgo,
    /// Go's own resolver (any of its files/DNS orders).
    Go,
}

/// `net.Resolver`, for the lookups that can use the C library.
#[derive(Clone, Default)]
pub struct Resolver {
    /// `Resolver.PreferGo`.
    pub prefer_builtin: bool,
    /// Go's own resolver for when it is selected or needed as a fallback.
    pub pure: Option<Arc<dyn PureResolver>>,
}

impl fmt::Debug for Resolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Resolver")
            .field("prefer_builtin", &self.prefer_builtin)
            .field("pure", &self.pure.is_some())
            .finish()
    }
}

/// `net.LookupAddr`: the host names for an address, with the default resolver.
pub fn lookup_addr(addr: &str) -> Result<Vec<String>, DnsError> {
    Resolver::default().lookup_addr(addr)
}

/// `net.LookupCNAME`: the canonical name of a host, with the default resolver.
pub fn lookup_cname(host: &str) -> Result<String, DnsError> {
    Resolver::default().lookup_cname(host)
}

impl Resolver {
    /// `Resolver.LookupAddr`.
    pub fn lookup_addr(&self, addr: &str) -> Result<Vec<String>, DnsError> {
        // Without a PureResolver the C library answers whatever the choice.
        if self.lookup_order("") == LookupOrder::Cgo || self.pure.is_none() {
            return cgo_lookup_ptr(addr);
        }
        self.pure_addr(addr)
    }

    /// `Resolver.LookupCNAME`.
    pub fn lookup_cname(&self, host: &str) -> Result<String, DnsError> {
        if self.lookup_order(host) == LookupOrder::Cgo || self.pure.is_none() {
            return match cgo_lookup_cname(host) {
                Ok(c) => Ok(c),
                // Go falls back to its own resolver.
                Err(e) => self.pure_cname(host, e),
            };
        }
        self.pure_cname(host, DnsError::default())
    }

    fn pure_addr(&self, addr: &str) -> Result<Vec<String>, DnsError> {
        match &self.pure {
            Some(p) => p.lookup_addr(addr),
            None => cgo_lookup_ptr(addr),
        }
    }

    fn pure_cname(&self, host: &str, cgo_err: DnsError) -> Result<String, DnsError> {
        // goLookupIPCNAMEOrder rejects names that are not domain names before
        // any query is sent.
        if !is_domain_name(host) {
            return Err(DnsError::no_such_host(host));
        }
        match &self.pure {
            Some(p) => p.lookup_cname(host),
            None => Err(cgo_err),
        }
    }

    /// Go's `conf.lookupOrder`: whether `hostname` (empty for an address
    /// lookup) is resolved by the C library or by Go's resolver.
    pub fn lookup_order(&self, hostname: &str) -> LookupOrder {
        lookup_order(self.prefer_builtin, hostname)
    }
}

// ---- the C library path -----------------------------------------------------

/// Go's `absDomainName`: names with a dot get a trailing dot.
fn abs_domain_name(s: &str) -> String {
    if s.contains('.') && !s.ends_with('.') {
        format!("{s}.")
    } else {
        s.to_string()
    }
}

/// An address with an optional IPv6 zone, as `netip.ParseAddr` reads it.
fn parse_addr(s: &str) -> Option<(IpAddr, String)> {
    if let Some((ip, zone)) = s.split_once('%') {
        let v6: Ipv6Addr = ip.parse().ok()?;
        if zone.is_empty() {
            return None;
        }
        return Some((IpAddr::V6(v6), zone.to_string()));
    }
    s.parse::<IpAddr>().ok().map(|ip| (ip, String::new()))
}

/// Go's `cgoSockaddr`: IPv4 (including IPv4-mapped IPv6) or IPv6 with a zone.
fn sockaddr(ip: IpAddr, zone: &str) -> SockAddr {
    let v4 = match ip {
        IpAddr::V4(a) => Some(a),
        IpAddr::V6(a) => a.to_ipv4_mapped(),
    };
    if let Some(a) = v4 {
        return SockAddr::from_inet(SocketAddr::new(IpAddr::V4(a), 0));
    }
    let IpAddr::V6(a) = ip else {
        return SockAddr::from_inet(SocketAddr::new(ip, 0));
    };
    let scope = if zone.is_empty() {
        0
    } else {
        // Go's zoneCache: an interface name, or a number.
        match dns::nametoindex(zone) {
            0 => zone.parse::<u32>().unwrap_or(0),
            n => n,
        }
    };
    SockAddr::from_inet(SocketAddr::V6(SocketAddrV6::new(a, 0, 0, scope)))
}

/// Go's `cgoLookupPTR`.
fn cgo_lookup_ptr(addr: &str) -> Result<Vec<String>, DnsError> {
    let Some((ip, zone)) = parse_addr(addr) else {
        return Err(DnsError::new("invalid address", addr));
    };
    let sa = sockaddr(ip, &zone);
    match dns::nameinfo_ptr(sa.bytes()) {
        Ok(name) => Ok(vec![abs_domain_name(&String::from_utf8_lossy(&name))]),
        Err(e) if e.code == libc_eai_system() => {
            // golang.org/issue/6232: EAI_SYSTEM without an errno means EMFILE.
            let errno = e.errno.filter(|n| n.0 != 0).unwrap_or(EMFILE);
            Err(system_error(errno, addr))
        }
        Err(e) if e.code == dns::EAI_NONAME => Err(DnsError::no_such_host(addr)),
        Err(e) => Err(DnsError {
            // addrinfoErrno: Temporary only for EAI_AGAIN.
            is_temporary: e.code == dns::EAI_AGAIN,
            ..DnsError::new(&e.text, addr)
        }),
    }
}

fn libc_eai_system() -> i32 {
    if cfg!(target_os = "macos") {
        11
    } else {
        -11
    }
}

fn system_error(errno: Errno, name: &str) -> DnsError {
    DnsError {
        is_timeout: errno.timeout(),
        is_temporary: errno.temporary(),
        ..DnsError::new(&errno.to_string(), name)
    }
}

/// Go's `cgoLookupCNAME`: a CNAME query through `res_search`; the first
/// answer must be a CNAME record.
fn cgo_lookup_cname(name: &str) -> Result<String, DnsError> {
    let packet = dns::res_search(name, 5).map_err(|e| DnsError::new(&e, name))?;
    parse_cname_answer(&packet).map_err(|e| DnsError::new(&e, name))
}

/// Go's `parseCNAMEFromResources` over a DNS response packet: the target of
/// the first answer, as a fully qualified name.
pub fn parse_cname_answer(packet: &[u8]) -> Result<String, String> {
    let bad = || "dns: invalid message".to_string();
    if packet.len() < 12 {
        return Err(bad());
    }
    let qd = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let an = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut off = 12;
    for _ in 0..qd {
        off = skip_name(packet, off).ok_or_else(bad)?;
        off += 4;
        if off > packet.len() {
            return Err(bad());
        }
    }
    if an == 0 {
        return Err("no CNAME record received".into());
    }
    off = skip_name(packet, off).ok_or_else(bad)?;
    if off + 10 > packet.len() {
        return Err(bad());
    }
    let typ = u16::from_be_bytes([packet[off], packet[off + 1]]);
    let rdlen = u16::from_be_bytes([packet[off + 8], packet[off + 9]]) as usize;
    off += 10;
    if off + rdlen > packet.len() {
        return Err(bad());
    }
    if typ != 5 {
        return Err("could not parse CNAME record".into());
    }
    read_name(packet, off).ok_or_else(bad)
}

/// The offset after the (possibly compressed) name at `off`.
fn skip_name(p: &[u8], mut off: usize) -> Option<usize> {
    loop {
        let len = *p.get(off)? as usize;
        match len & 0xc0 {
            0 if len == 0 => return Some(off + 1),
            0 => off += 1 + len,
            0xc0 => {
                p.get(off + 1)?;
                return Some(off + 2);
            }
            _ => return None,
        }
    }
}

/// Decodes the name at `off`, following compression pointers.
fn read_name(p: &[u8], mut off: usize) -> Option<String> {
    let mut out = String::new();
    let mut hops = 0;
    loop {
        let len = *p.get(off)? as usize;
        match len & 0xc0 {
            0 if len == 0 => {
                if out.is_empty() {
                    out.push('.');
                }
                return Some(out);
            }
            0 => {
                let label = p.get(off + 1..off + 1 + len)?;
                for &b in label {
                    match b {
                        b'.' | b'\\' => {
                            out.push('\\');
                            out.push(b as char);
                        }
                        0x20..=0x7e => out.push(b as char),
                        _ => out.push_str(&format!("\\{b:03}")),
                    }
                }
                out.push('.');
                off += 1 + len;
            }
            0xc0 => {
                hops += 1;
                if hops > 10 {
                    return None;
                }
                off = ((len & 0x3f) << 8) | *p.get(off + 1)? as usize;
            }
            _ => return None,
        }
    }
}

/// Go's `isDomainName`.
pub fn is_domain_name(s: &str) -> bool {
    if s == "." {
        return true;
    }
    let b = s.as_bytes();
    let l = b.len();
    if l == 0 || l > 254 || (l == 254 && b[l - 1] != b'.') {
        return false;
    }
    let mut last = b'.';
    let mut non_numeric = false;
    let mut partlen = 0;
    for &c in b {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                non_numeric = true;
                partlen += 1;
            }
            b'0'..=b'9' => partlen += 1,
            b'-' => {
                if last == b'.' {
                    return false;
                }
                partlen += 1;
                non_numeric = true;
            }
            b'.' => {
                if last == b'.' || last == b'-' {
                    return false;
                }
                if partlen > 63 || partlen == 0 {
                    return false;
                }
                partlen = 0;
            }
            _ => return false,
        }
        last = c;
    }
    !(last == b'-' || partlen > 63) && non_numeric
}

// ---- choosing the resolver (conf.go) ------------------------------------------

/// `GODEBUG=netdns=` as (mode, debug level).
fn godebug_netdns() -> String {
    let godebug = std::env::var("GODEBUG").unwrap_or_default();
    let mut value = "";
    for kv in godebug.split(',') {
        if let Some(v) = kv.strip_prefix("netdns=") {
            value = v;
        }
    }
    let mut mode = String::new();
    let parts: Vec<&str> = if let Some((a, b)) = value.split_once('+') {
        vec![a, b]
    } else {
        vec![value]
    };
    for p in parts {
        if p.is_empty() || p.as_bytes()[0].is_ascii_digit() {
            continue;
        }
        mode = p.to_string();
    }
    mode
}

/// Whether the platform or environment prefers the C library.
fn prefers_cgo() -> bool {
    if cfg!(target_os = "macos") {
        return true;
    }
    std::env::var_os("LOCALDOMAIN").is_some()
        || std::env::var("RES_OPTIONS").is_ok_and(|v| !v.is_empty())
        || std::env::var("HOSTALIASES").is_ok_and(|v| !v.is_empty())
}

/// What `/etc/resolv.conf` tells `lookupOrder`: whether reading failed in a
/// way that is neither "missing" nor "permission denied", and whether it holds
/// something Go does not understand.
fn resolv_conf_asks_for_cgo() -> bool {
    let text = match std::fs::read_to_string("/etc/resolv.conf") {
        Ok(t) => t,
        Err(e) => {
            return !matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            )
        }
    };
    for line in text.lines() {
        if line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        let Some(first) = f.first() else { continue };
        match *first {
            "nameserver" | "domain" | "search" | "lookup" => {}
            "options" => {
                for s in &f[1..] {
                    let known = s.starts_with("ndots:")
                        || s.starts_with("timeout:")
                        || s.starts_with("attempts:")
                        || matches!(
                            *s,
                            "rotate"
                                | "single-request"
                                | "single-request-reopen"
                                | "use-vc"
                                | "usevc"
                                | "tcp"
                                | "trust-ad"
                                | "edns0"
                                | "no-reload"
                        );
                    if !known {
                        return true;
                    }
                }
            }
            _ => return true,
        }
    }
    false
}

/// One `hosts:` source of `/etc/nsswitch.conf` with its criteria.
struct NssSource {
    source: String,
    criteria: Vec<(bool, String, String)>,
}

impl NssSource {
    fn standard_criteria(&self) -> bool {
        let n = self.criteria.len();
        self.criteria.iter().enumerate().all(|(i, (negate, status, action))| {
            if *negate {
                return false;
            }
            let def = match status.as_str() {
                "success" => "return",
                "notfound" | "unavail" | "tryagain" => "continue",
                _ => return false,
            };
            (i == n - 1 && action == "return") || action == def
        })
    }
}

/// The `hosts` sources of nsswitch.conf: `Err(true)` when the file is missing,
/// `Err(false)` when it cannot be read or parsed.
fn nss_hosts() -> Result<Vec<NssSource>, bool> {
    let text = match std::fs::read_to_string("/etc/nsswitch.conf") {
        Ok(t) => t,
        Err(e) => return Err(e.kind() == std::io::ErrorKind::NotFound),
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((db, mut srcs)) = line.split_once(':') else {
            return Err(false);
        };
        let is_hosts = db.trim() == "hosts";
        loop {
            srcs = srcs.trim();
            if srcs.is_empty() {
                break;
            }
            let (src, rest) = match srcs.split_once(' ') {
                Some((s, r)) => (s, r.trim()),
                None => (srcs, ""),
            };
            srcs = rest;
            let mut criteria = Vec::new();
            if srcs.starts_with('[') {
                let Some(close) = srcs.find(']') else {
                    return Err(false);
                };
                for f in srcs[1..close].split_whitespace() {
                    let (negate, f) = match f.strip_prefix('!') {
                        Some(r) => (true, r),
                        None => (false, f),
                    };
                    if f.len() < 3 {
                        return Err(false);
                    }
                    let Some((status, action)) = f.to_lowercase().split_once('=').map(|(a, b)| (a.to_string(), b.to_string())) else {
                        return Err(false);
                    };
                    criteria.push((negate, status, action));
                }
                srcs = &srcs[close + 1..];
            }
            if is_hosts {
                out.push(NssSource {
                    source: src.to_string(),
                    criteria,
                });
            }
        }
    }
    Ok(out)
}

fn is_localhost(h: &str) -> bool {
    let h = h.to_lowercase();
    h == "localhost"
        || h == "localhost.localdomain"
        || h.ends_with(".localhost")
        || h.ends_with(".localhost.localdomain")
}

/// Go's `conf.lookupOrder`.
pub fn lookup_order(prefer_builtin: bool, hostname: &str) -> LookupOrder {
    let dns_mode = godebug_netdns();
    let net_go = dns_mode == "go";
    let net_cgo = dns_mode == "cgo";
    let (fallback, can_use_cgo);
    if net_go || prefer_builtin {
        fallback = LookupOrder::Go;
        can_use_cgo = false;
    } else if net_cgo || prefers_cgo() {
        return LookupOrder::Cgo;
    } else {
        if hostname.contains('\\') || hostname.contains('%') {
            return LookupOrder::Cgo;
        }
        fallback = LookupOrder::Cgo;
        can_use_cgo = true;
    }
    if can_use_cgo && resolv_conf_asks_for_cgo() {
        return LookupOrder::Cgo;
    }
    let hostname = hostname.strip_suffix('.').unwrap_or(hostname);
    let srcs = match nss_hosts() {
        // No file, or no sources for hosts: Go's DNS will work fine.
        Err(true) => return LookupOrder::Go,
        Err(false) => return fallback,
        Ok(s) if s.is_empty() => return LookupOrder::Go,
        Ok(s) => s,
    };
    let (mut files, mut dns_source, mut has_dns, mut checked) = (false, false, false, false);
    for (i, src) in srcs.iter().enumerate() {
        if src.source == "files" || src.source == "dns" {
            if can_use_cgo && !src.standard_criteria() {
                return LookupOrder::Cgo;
            }
            if src.source == "files" {
                files = true;
            } else {
                has_dns = true;
                checked = true;
                dns_source = true;
            }
            continue;
        }
        if can_use_cgo {
            if !hostname.is_empty() && src.source == "myhostname" {
                let hn = crate::os::hostname().unwrap_or_default();
                if is_localhost(hostname)
                    || hostname.eq_ignore_ascii_case("_gateway")
                    || hostname.eq_ignore_ascii_case("_outbound")
                    || hn.is_empty()
                    || hostname.eq_ignore_ascii_case(&hn)
                {
                    return LookupOrder::Cgo;
                }
                continue;
            } else if !hostname.is_empty() && src.source.starts_with("mdns") {
                if hostname.to_lowercase().ends_with(".local") {
                    return LookupOrder::Cgo;
                }
                match std::fs::metadata("/etc/mdns.allow") {
                    Ok(_) => return LookupOrder::Cgo,
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => return LookupOrder::Cgo,
                    Err(_) => continue,
                }
            }
            return LookupOrder::Cgo;
        }
        if !checked {
            checked = true;
            has_dns = srcs[i + 1..].iter().any(|s| s.source == "dns");
        }
        if !has_dns {
            dns_source = true;
        }
    }
    if files || dns_source {
        LookupOrder::Go
    } else {
        fallback
    }
}
