//! Go's `Resolver` and the package-level lookup functions, ported from
//! `net/lookup.go`, `dnsclient_unix.go`, `ipsock.go` and `dial.go` (see
//! NOTICE).
//!
//! Without `prefer_builtin`, host and IP lookups use the operating system's
//! `getaddrinfo` through `std::net::ToSocketAddrs`, like Go's cgo resolver.
//! With `prefer_builtin` every lookup uses the pure resolver implemented here: it
//! reads `/etc/resolv.conf`, `/etc/hosts` and `/etc/nsswitch.conf` and speaks
//! DNS over UDP, falling back to TCP, through [`Resolver::dial`]. SRV, MX, NS
//! and TXT lookups and `LookupCNAME` always use the pure resolver, as in Go.
use super::addr::{split_host_port, split_host_zone, TCPAddr, UDPAddr, UnixAddr};
use super::conn::Conn;
use super::dial::{parse_network, Dialer};
use super::dnsconf::{
    is_domain_name, lookup_order, lookup_port_map, lookup_static_addr, lookup_static_host,
    reverse_addr, sort_by_rfc6724, system_dns_config, DnsConfig, HostLookupOrder, IpZone,
    PortError,
};
use super::dnsmsg::{self as wire, MsgError, Parser, Question};
use super::error::{Addr, AddrError, AddrRef, DNSError, NetError, UnknownNetworkError};
use super::ip::{parse_ip, IP};
use super::netip;
use crate::context::{self, Context};
use crate::time::Time;
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Condvar, LazyLock, Mutex};
use std::time::{Duration as StdDuration, Instant};

/// An address produced by name resolution.
#[derive(Clone, Debug)]
pub(crate) enum ResolvedAddr {
    Tcp(TCPAddr),
    Udp(UDPAddr),
    Ip(super::addr::IPAddr),
    Unix(UnixAddr),
}

impl ResolvedAddr {
    pub(crate) fn to_addr(&self) -> AddrRef {
        match self {
            ResolvedAddr::Tcp(a) => Arc::new(a.clone()),
            ResolvedAddr::Udp(a) => Arc::new(a.clone()),
            ResolvedAddr::Ip(a) => Arc::new(a.clone()),
            ResolvedAddr::Unix(a) => Arc::new(a.clone()),
        }
    }

    pub(crate) fn is_ipv4(&self) -> bool {
        match self {
            ResolvedAddr::Tcp(a) => a.ip.to4().is_some(),
            ResolvedAddr::Udp(a) => a.ip.to4().is_some(),
            ResolvedAddr::Ip(a) => a.ip.to4().is_some(),
            ResolvedAddr::Unix(_) => false,
        }
    }

    pub(crate) fn first(
        addrs: &[ResolvedAddr],
        strategy: fn(&ResolvedAddr) -> bool,
    ) -> ResolvedAddr {
        addrs
            .iter()
            .find(|a| strategy(a))
            .unwrap_or(&addrs[0])
            .clone()
    }

    fn network(&self) -> &str {
        match self {
            ResolvedAddr::Tcp(_) => "tcp",
            ResolvedAddr::Udp(_) => "udp",
            ResolvedAddr::Ip(_) => "ip",
            ResolvedAddr::Unix(u) => &u.net,
        }
    }

    fn is_wildcard(&self) -> bool {
        match self {
            ResolvedAddr::Tcp(a) => a.is_wildcard(),
            ResolvedAddr::Udp(a) => a.is_wildcard(),
            ResolvedAddr::Ip(a) => a.is_wildcard(),
            ResolvedAddr::Unix(a) => a.is_wildcard(),
        }
    }

    fn ip(&self) -> Option<&IP> {
        match self {
            ResolvedAddr::Tcp(a) => Some(&a.ip),
            ResolvedAddr::Udp(a) => Some(&a.ip),
            ResolvedAddr::Ip(a) => Some(&a.ip),
            ResolvedAddr::Unix(_) => None,
        }
    }
}

fn for_resolve(addrs: &[ResolvedAddr], network: &str, addr: &str) -> ResolvedAddr {
    let want6 = match network {
        "ip" => addr.contains(':'),
        "tcp" | "udp" => addr.contains('['),
        _ => false,
    };
    if want6 {
        ResolvedAddr::first(addrs, |a| !a.is_ipv4())
    } else {
        ResolvedAddr::first(addrs, ResolvedAddr::is_ipv4)
    }
}

/// `net.SRV`: a DNS SRV record.
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SRV {
    /// The target host name.
    pub target: String,
    /// The port.
    pub port: u16,
    /// The priority.
    pub priority: u16,
    /// The weight.
    pub weight: u16,
}

/// `net.MX`: a DNS MX record.
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MX {
    /// The mail server host name.
    pub host: String,
    /// The preference.
    pub pref: u16,
}

/// `net.NS`: a DNS NS record.
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NS {
    /// The name server host name.
    pub host: String,
}

/// The signature of [`Resolver::dial`]: connects to a DNS server given as a
/// literal `host:port`.
pub type DialFunc =
    Arc<dyn Fn(&Context, &str, &str) -> Result<Box<dyn Conn>, NetError> + Send + Sync>;

/// `net.Resolver`: looks up names and numbers.
#[derive(Clone, Default)]
pub struct Resolver {
    /// Prefer the pure-Go style resolver over the operating system's.
    pub prefer_builtin: bool,
    /// Make temporary errors abort multi-query lookups.
    pub strict_errors: bool,
    /// An alternate dialer for the pure resolver's DNS connections.
    pub dial: Option<DialFunc>,
}

/// `net.DefaultResolver`.
pub static DEFAULT_RESOLVER: Resolver = Resolver {
    prefer_builtin: false,
    strict_errors: false,
    dial: None,
};

const ERR_MALFORMED: &str = "DNS response contained records which contain invalid names";

fn rand_u64() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static STATE: AtomicU64 = AtomicU64::new(0);
    let mut x = STATE.load(Ordering::Relaxed);
    if x == 0 {
        x = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E3779B97F4A7C15)
            | 1;
    }
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    STATE.store(x, Ordering::Relaxed);
    x
}

fn rand_intn(n: usize) -> usize {
    (rand_u64() >> 1) as usize % n
}

fn dns_error(err: &str, name: &str, server: &str) -> NetError {
    DNSError {
        unwrap_err: None,
        err: err.into(),
        name: name.into(),
        server: server.into(),
        is_timeout: false,
        is_temporary: false,
        is_not_found: false,
    }
    .into()
}

fn no_such_host(name: &str, server: &str) -> NetError {
    new_dns_error(
        NetError::Other {
            text: "no such host".into(),
            temporary: false,
            not_found: true,
        },
        name,
        server,
    )
}

/// `newDNSError`.
fn new_dns_error(err: NetError, name: &str, server: &str) -> NetError {
    use super::error::Error as _;
    let unwrap_err = if err.is_deadline_exceeded() || matches!(err, NetError::Canceled) {
        Some(Box::new(err.clone()))
    } else {
        None
    };
    let is_not_found = matches!(
        err,
        NetError::Other {
            not_found: true,
            ..
        }
    );
    NetError::Dns(Box::new(DNSError {
        unwrap_err,
        err: err.to_string(),
        name: name.into(),
        server: server.into(),
        is_timeout: err.timeout(),
        is_temporary: err.temporary(),
        is_not_found,
    }))
}

fn cannot_unmarshal(name: &str, server: &str) -> NetError {
    dns_error("cannot unmarshal DNS message", name, server)
}

fn set_dns_name(err: &mut NetError, name: &str) {
    if let NetError::Dns(d) = err {
        d.name = name.into();
    }
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// `parsePort`: `(port, needs_lookup)`.
fn parse_port(service: &str) -> (i32, bool) {
    if service.is_empty() {
        return (0, false);
    }
    const MAX: u32 = u32::MAX;
    const CUTOFF: u32 = 1 << 30;
    let mut s = service;
    let mut neg = false;
    if let Some(r) = s.strip_prefix('+') {
        s = r;
    } else if let Some(r) = s.strip_prefix('-') {
        neg = true;
        s = r;
    }
    let mut n: u32 = 0;
    for d in s.chars() {
        let Some(d) = d.to_digit(10).filter(|_| d.is_ascii_digit()) else {
            return (0, true);
        };
        if n >= CUTOFF {
            n = MAX;
            break;
        }
        n *= 10;
        match n.checked_add(d) {
            Some(nn) => n = nn,
            None => {
                n = MAX;
                break;
            }
        }
    }
    let port = if !neg && n >= CUTOFF {
        (CUTOFF - 1) as i32
    } else if neg && n > CUTOFF {
        CUTOFF as i32
    } else {
        n as i32
    };
    (if neg { -port } else { port }, false)
}

struct Answer {
    p: Parser,
    server: String,
}

impl Resolver {
    fn mk_dial(
        &self,
        ctx: &Context,
        network: &str,
        server: &str,
    ) -> Result<Box<dyn Conn>, NetError> {
        match &self.dial {
            Some(f) => f(ctx, network, server),
            None => Dialer::default().dial_context(ctx, network, server),
        }
    }

    // ---- public lookups ----

    /// `Resolver.LookupHost`: the addresses of `host` as strings.
    pub fn lookup_host(&self, ctx: &Context, host: &str) -> Result<Vec<String>, NetError> {
        if host.is_empty() {
            return Err(no_such_host(host, ""));
        }
        if host.parse::<netip::Addr>().is_ok() {
            return Ok(vec![host.to_owned()]);
        }
        if self.prefer_builtin {
            return self.go_lookup_host_order(ctx, host, lookup_order());
        }
        self.system_lookup(host).map(|ips| {
            ips.into_iter()
                .map(|(ip, zone)| with_zone(&ip, &zone))
                .collect()
        })
    }

    /// `Resolver.LookupIPAddr`: the IPv4 and IPv6 addresses of `host`.
    pub fn lookup_ip_addr(
        &self,
        ctx: &Context,
        host: &str,
    ) -> Result<Vec<super::addr::IPAddr>, NetError> {
        self.lookup_ip_addr_net(ctx, "ip", host)
    }

    /// `Resolver.LookupIP`: the addresses of `host` for `network` ("ip", "ip4" or "ip6").
    pub fn lookup_ip(&self, ctx: &Context, network: &str, host: &str) -> Result<Vec<IP>, NetError> {
        let (afnet, _) = parse_network(network, false)?;
        if !matches!(afnet.as_str(), "ip" | "ip4" | "ip6") {
            return Err(UnknownNetworkError(network.into()).into());
        }
        if host.is_empty() {
            return Err(no_such_host(host, ""));
        }
        let addrs = self.internet_addr_list(ctx, &afnet, host)?;
        Ok(addrs
            .into_iter()
            .filter_map(|a| match a {
                ResolvedAddr::Ip(i) => Some(i.ip),
                _ => None,
            })
            .collect())
    }

    /// `Resolver.LookupNetIP`: like [`lookup_ip`](Self::lookup_ip) as `netip::Addr`.
    pub fn lookup_net_ip(
        &self,
        ctx: &Context,
        network: &str,
        host: &str,
    ) -> Result<Vec<netip::Addr>, NetError> {
        Ok(self
            .lookup_ip(ctx, network, host)?
            .iter()
            .filter_map(|ip| netip::Addr::try_from(ip.0.as_slice()).ok())
            .collect())
    }

    /// `Resolver.LookupPort`: the port of `service` on `network`.
    pub fn lookup_port(
        &self,
        _ctx: &Context,
        network: &str,
        service: &str,
    ) -> Result<i32, NetError> {
        let (mut port, needs_lookup) = parse_port(service);
        if needs_lookup {
            let network = match network {
                "tcp" | "tcp4" | "tcp6" | "udp" | "udp4" | "udp6" | "ip" => network,
                "" => "ip",
                _ => {
                    return Err(AddrError {
                        err: "unknown network".into(),
                        addr: network.into(),
                    }
                    .into())
                }
            };
            port = match lookup_port_map(network, service) {
                Ok(p) => p,
                Err(PortError::Unknown) => {
                    let en = if network == "ip" {
                        "ip"
                    } else if network.starts_with("tcp") {
                        "tcp"
                    } else {
                        "udp"
                    };
                    return Err(new_dns_error(
                        NetError::Other {
                            text: "unknown port".into(),
                            temporary: false,
                            not_found: true,
                        },
                        &format!("{en}/{service}"),
                        "",
                    ));
                }
                Err(PortError::UnknownNetwork) => {
                    return Err(dns_error(
                        "unknown network",
                        &format!("{network}/{service}"),
                        "",
                    ))
                }
            };
        }
        if !(0..=65535).contains(&port) {
            return Err(AddrError {
                err: "invalid port".into(),
                addr: service.into(),
            }
            .into());
        }
        Ok(port)
    }

    /// `Resolver.LookupCNAME`: the canonical name for `host`.
    pub fn lookup_cname(&self, ctx: &Context, host: &str) -> Result<String, NetError> {
        let order = if self.prefer_builtin {
            lookup_order()
        } else {
            HostLookupOrder::FilesDns
        };
        let (_, cname) = self.go_lookup_ip_cname_order(ctx, "CNAME", host, order)?;
        if !is_domain_name(&cname) {
            return Err(dns_error(ERR_MALFORMED, host, ""));
        }
        Ok(cname)
    }

    /// `Resolver.LookupSRV`: the SRV records of `_service._proto.name`. The
    /// last element is the error Go returns alongside filtered results.
    pub fn lookup_srv(
        &self,
        ctx: &Context,
        service: &str,
        proto: &str,
        name: &str,
    ) -> Result<(String, Vec<SRV>, Option<NetError>), NetError> {
        let (cname, addrs) = self.go_lookup_srv(ctx, service, proto, name)?;
        if !cname.is_empty() && !is_domain_name(&cname) {
            return Err(dns_error("SRV header name is invalid", name, ""));
        }
        let filtered: Vec<SRV> = addrs
            .iter()
            .filter(|a| is_domain_name(&a.target))
            .cloned()
            .collect();
        let err = (filtered.len() != addrs.len()).then(|| dns_error(ERR_MALFORMED, name, ""));
        Ok((cname, filtered, err))
    }

    /// `Resolver.LookupMX`: the MX records of `name`, sorted by preference.
    pub fn lookup_mx(
        &self,
        ctx: &Context,
        name: &str,
    ) -> Result<(Vec<MX>, Option<NetError>), NetError> {
        let records = self.go_lookup_mx(ctx, name)?;
        let filtered: Vec<MX> = records
            .iter()
            .filter(|mx| {
                is_domain_name(&mx.host)
                    || mx
                        .host
                        .strip_suffix('.')
                        .unwrap_or(&mx.host)
                        .parse::<netip::Addr>()
                        .is_ok_and(|ip| ip.zone().is_empty())
            })
            .cloned()
            .collect();
        let err = (filtered.len() != records.len()).then(|| dns_error(ERR_MALFORMED, name, ""));
        Ok((filtered, err))
    }

    /// `Resolver.LookupNS`: the NS records of `name`.
    pub fn lookup_ns(
        &self,
        ctx: &Context,
        name: &str,
    ) -> Result<(Vec<NS>, Option<NetError>), NetError> {
        let records = self.go_lookup_ns(ctx, name)?;
        let filtered: Vec<NS> = records
            .iter()
            .filter(|ns| is_domain_name(&ns.host))
            .cloned()
            .collect();
        let err = (filtered.len() != records.len()).then(|| dns_error(ERR_MALFORMED, name, ""));
        Ok((filtered, err))
    }

    /// `Resolver.LookupTXT`: the TXT records of `name`.
    pub fn lookup_txt(&self, ctx: &Context, name: &str) -> Result<Vec<String>, NetError> {
        self.go_lookup_txt(ctx, name)
    }

    /// `Resolver.LookupAddr`: reverse lookup of `addr`.
    pub fn lookup_addr(
        &self,
        ctx: &Context,
        addr: &str,
    ) -> Result<(Vec<String>, Option<NetError>), NetError> {
        let order = if self.prefer_builtin {
            lookup_order()
        } else {
            HostLookupOrder::FilesDns
        };
        let names = self.go_lookup_ptr(ctx, addr, order)?;
        let filtered: Vec<String> = names
            .iter()
            .filter(|n| is_domain_name(n))
            .cloned()
            .collect();
        let err = (filtered.len() != names.len()).then(|| dns_error(ERR_MALFORMED, addr, ""));
        Ok((filtered, err))
    }

    // ---- address lists ----

    pub(crate) fn lookup_ip_addr_net(
        &self,
        ctx: &Context,
        network: &str,
        host: &str,
    ) -> Result<Vec<super::addr::IPAddr>, NetError> {
        if host.is_empty() {
            return Err(no_such_host(host, ""));
        }
        if let Ok(ip) = host.parse::<netip::Addr>() {
            let ip16 = IP(ip.as_slice()).to16().unwrap_or_default();
            return Ok(vec![super::addr::IPAddr {
                ip: ip16,
                zone: ip.zone().to_owned(),
            }]);
        }
        let trace = super::nettrace::from_context(ctx);
        if let Some(start) = trace.as_ref().and_then(|t| t.dns_start.as_ref()) {
            start(host);
        }
        let done = |addrs: &[super::addr::IPAddr], shared: bool, err: Option<&NetError>| {
            if let Some(done) = trace.as_ref().and_then(|t| t.dns_done.as_ref()) {
                done(addrs, shared, err);
            }
        };
        let (res, shared) = match self.lookup_flight(ctx, network, host) {
            Ok(r) => r,
            Err(err) => {
                done(&[], false, Some(&err));
                return Err(err);
            }
        };
        match res {
            Ok(v) => {
                let addrs: Vec<super::addr::IPAddr> = v
                    .into_iter()
                    .map(|(ip, zone)| super::addr::IPAddr { ip, zone })
                    .collect();
                done(&addrs, shared, None);
                Ok(addrs)
            }
            Err(e) => {
                let err = match e {
                    NetError::Dns(_) => e,
                    other => new_dns_error(other, host, ""),
                };
                done(&[], shared, Some(&err));
                Err(err)
            }
        }
    }

    /// Go's `singleflight` around the lookup: concurrent lookups of the same
    /// `network` and `host` share one query. Returns the shared outcome and
    /// whether this caller's result was shared; an `Err` is this caller's
    /// context ending first, already a DNS error.
    #[allow(clippy::type_complexity)]
    fn lookup_flight(
        &self,
        ctx: &Context,
        network: &str,
        host: &str,
    ) -> Result<(Result<Vec<IpZone>, NetError>, bool), NetError> {
        let key = format!("{network}\0{host}");
        let (flight, leader) = {
            let mut flights = FLIGHTS.lock().unwrap_or_else(|e| e.into_inner());
            match flights.get(&key) {
                Some(f) => {
                    f.shared.store(true, std::sync::atomic::Ordering::SeqCst);
                    (f.clone(), false)
                }
                None => {
                    let f = Arc::new(Flight::default());
                    flights.insert(key.clone(), f.clone());
                    (f, true)
                }
            }
        };
        if leader {
            let me = self.clone();
            // The shared query must not die with its first caller's context.
            let (c, n, h) = (ctx.without_cancel(), network.to_owned(), host.to_owned());
            let fl = flight.clone();
            let work = move || {
                let r = me.lookup_ip_impl(&c, &n, &h);
                FLIGHTS
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&key);
                *fl.result.lock().unwrap_or_else(|e| e.into_inner()) = Some(r);
                fl.done.notify_all();
            };
            if ctx.done().is_never() {
                work();
            } else {
                std::thread::spawn(work);
            }
        }
        let mut guard = flight.result.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(r) = guard.as_ref() {
                let shared = flight.shared.load(std::sync::atomic::Ordering::SeqCst);
                return Ok((r.clone(), shared));
            }
            if let Some(e) = ctx.err() {
                let ne = match e {
                    context::Error::Canceled => NetError::Canceled,
                    context::Error::DeadlineExceeded => NetError::Timeout,
                };
                return Err(new_dns_error(ne, host, ""));
            }
            let (g, _) = flight
                .done
                .wait_timeout(guard, StdDuration::from_millis(2))
                .unwrap_or_else(|e| e.into_inner());
            guard = g;
        }
    }

    fn lookup_ip_impl(
        &self,
        ctx: &Context,
        network: &str,
        host: &str,
    ) -> Result<Vec<IpZone>, NetError> {
        if self.prefer_builtin {
            let (ips, _) = self.go_lookup_ip_cname_order(ctx, network, host, lookup_order())?;
            return Ok(ips);
        }
        let mut ips = self.system_lookup(host)?;
        match network.chars().last() {
            Some('4') => ips.retain(|(ip, _)| ip.to4().is_some()),
            Some('6') => ips.retain(|(ip, _)| ip.to4().is_none()),
            _ => {}
        }
        if ips.is_empty() {
            return Err(no_such_host(host, ""));
        }
        Ok(ips)
    }

    /// The operating system's resolver (`getaddrinfo`).
    fn system_lookup(&self, host: &str) -> Result<Vec<IpZone>, NetError> {
        use std::net::ToSocketAddrs;
        match (host, 0u16).to_socket_addrs() {
            Ok(it) => {
                let mut out: Vec<IpZone> = Vec::new();
                for a in it {
                    let ip: IP = a.ip().into();
                    let zone = match a {
                        std::net::SocketAddr::V6(v6) if v6.scope_id() != 0 => {
                            v6.scope_id().to_string()
                        }
                        _ => String::new(),
                    };
                    let ip = ip.to16().unwrap_or(ip);
                    if !out.iter().any(|(i, z)| *i == ip && *z == zone) {
                        out.push((ip, zone));
                    }
                }
                if out.is_empty() {
                    return Err(no_such_host(host, ""));
                }
                Ok(out)
            }
            Err(_) => Err(no_such_host(host, "")),
        }
    }

    pub(crate) fn internet_addr_list(
        &self,
        ctx: &Context,
        net: &str,
        addr: &str,
    ) -> Result<Vec<ResolvedAddr>, NetError> {
        let (mut host, mut portnum) = (String::new(), 0);
        match net {
            "tcp" | "tcp4" | "tcp6" | "udp" | "udp4" | "udp6" => {
                if !addr.is_empty() {
                    let (h, port) = split_host_port(addr)?;
                    host = h;
                    portnum = self.lookup_port(ctx, net, &port)?;
                }
            }
            "ip" | "ip4" | "ip6" => {
                if !addr.is_empty() {
                    host = addr.to_owned();
                }
            }
            _ => return Err(UnknownNetworkError(net.into()).into()),
        }
        let inetaddr = |ip: IP, zone: String| -> ResolvedAddr {
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
                _ => ResolvedAddr::Ip(super::addr::IPAddr { ip, zone }),
            }
        };
        if host.is_empty() {
            return Ok(vec![inetaddr(IP::default(), String::new())]);
        }
        let mut ips = self.lookup_ip_addr_net(ctx, net, &host)?;
        if ips.len() == 1 && ips[0].ip.equal(&super::ip::ipv6_unspecified()) {
            ips.push(super::addr::IPAddr {
                ip: super::ip::ipv4_zero(),
                zone: String::new(),
            });
        }
        let ipv4only = |a: &super::addr::IPAddr| a.ip.to4().is_some();
        let ipv6only = |a: &super::addr::IPAddr| a.ip.0.len() == 16 && a.ip.to4().is_none();
        let filter: Option<&dyn Fn(&super::addr::IPAddr) -> bool> = match net.chars().last() {
            Some('4') => Some(&ipv4only),
            Some('6') => Some(&ipv6only),
            _ => None,
        };
        let out: Vec<ResolvedAddr> = ips
            .into_iter()
            .filter(|a| filter.is_none_or(|f| f(a)))
            .map(|a| inetaddr(a.ip, a.zone))
            .collect();
        if out.is_empty() {
            return Err(AddrError {
                err: "no suitable address found".into(),
                addr: host,
            }
            .into());
        }
        Ok(out)
    }

    pub(crate) fn resolve_addr_list(
        &self,
        ctx: &Context,
        op: &str,
        network: &str,
        addr: &str,
        hint: Option<&dyn Addr>,
    ) -> Result<Vec<ResolvedAddr>, NetError> {
        let (afnet, _) = parse_network(network, true)?;
        if op == "dial" && addr.is_empty() {
            return Err(NetError::other("missing address"));
        }
        if matches!(afnet.as_str(), "unix" | "unixgram" | "unixpacket") {
            let a = resolve_unix(&afnet, addr)?;
            if op == "dial" {
                if let Some(h) = hint {
                    if a.net != h.network() {
                        return Err(AddrError {
                            err: "mismatched local address type".into(),
                            addr: h.to_string(),
                        }
                        .into());
                    }
                }
            }
            return Ok(vec![ResolvedAddr::Unix(a)]);
        }
        let addrs = self.internet_addr_list(ctx, &afnet, addr)?;
        let Some(hint) = hint.filter(|_| op == "dial") else {
            return Ok(addrs);
        };
        let (hint_ip, wildcard) = if let Some(t) = hint.as_any().downcast_ref::<TCPAddr>() {
            (Some(t.ip.clone()), t.is_wildcard())
        } else if let Some(u) = hint.as_any().downcast_ref::<UDPAddr>() {
            (Some(u.ip.clone()), u.is_wildcard())
        } else if let Some(i) = hint.as_any().downcast_ref::<super::addr::IPAddr>() {
            (Some(i.ip.clone()), i.is_wildcard())
        } else {
            (None, false)
        };
        let mut out = Vec::new();
        for a in addrs {
            if a.network() != hint.network() {
                return Err(AddrError {
                    err: "mismatched local address type".into(),
                    addr: hint.to_string(),
                }
                .into());
            }
            if let (Some(hip), Some(aip)) = (&hint_ip, a.ip()) {
                if !wildcard && !a.is_wildcard() && !aip.match_addr_family(hip) {
                    continue;
                }
            }
            out.push(a);
        }
        if out.is_empty() {
            return Err(AddrError {
                err: "no suitable address found".into(),
                addr: hint.to_string(),
            }
            .into());
        }
        Ok(out)
    }

    // ---- the pure resolver ----

    fn exchange(
        &self,
        ctx: &Context,
        server: &str,
        q: &Question,
        timeout: StdDuration,
        use_tcp: bool,
        ad: bool,
    ) -> Result<(Parser, wire::Header), NetError> {
        let q = Question {
            class: wire::CLASS_INET,
            ..q.clone()
        };
        let id = rand_u64() as u16;
        let (udp_req, tcp_req) = wire::request(id, &q, ad, true)
            .map_err(|_| NetError::other("cannot marshal DNS message"))?;
        let networks: &[&str] = if use_tcp { &["tcp"] } else { &["udp", "tcp"] };
        for network in networks {
            let (ctx, cancel) = ctx.with_deadline(Instant::now() + timeout);
            let r = (|| -> Result<(Parser, wire::Header), NetError> {
                let c = self.mk_dial(&ctx, network, server)?;
                if let Some(d) = ctx.deadline() {
                    let rem = d.saturating_duration_since(Instant::now());
                    let t = crate::time::now()
                        .add(crate::time::Duration::from_nanos(rem.as_nanos() as i64));
                    let _ = c.set_deadline(&t);
                } else {
                    let _ = c.set_deadline(&Time::default());
                }
                let res = if c.as_packet_conn().is_some() {
                    packet_round_trip(&*c, id, &q, &udp_req)
                } else {
                    stream_round_trip(&*c, id, &q, &tcp_req)
                };
                let _ = c.close();
                res
            })();
            cancel();
            let (mut p, h) = r?;
            if p.skip_question() != Err(MsgError::SectionDone) {
                return Err(NetError::other("invalid DNS response"));
            }
            if h.truncated && *network == "udp" {
                continue;
            }
            return Ok((p, h));
        }
        Err(NetError::other("no answer from DNS server"))
    }

    fn try_one_name(
        &self,
        ctx: &Context,
        cfg: &DnsConfig,
        name: &str,
        qtype: u16,
    ) -> Result<Answer, NetError> {
        let mut last_err: Option<NetError> = None;
        let offset = cfg.server_offset();
        let s_len = cfg.servers.len() as u32;
        if name.len() > 255 || !is_packable(name) {
            return Err(dns_error("cannot marshal DNS message", name, ""));
        }
        let q = Question {
            name: name.as_bytes().to_vec(),
            typ: qtype,
            class: wire::CLASS_INET,
        };
        for _ in 0..cfg.attempts {
            for j in 0..s_len {
                let server = &cfg.servers[((offset + j) % s_len) as usize];
                let (mut p, h) =
                    match self.exchange(ctx, server, &q, cfg.timeout, cfg.use_tcp, cfg.trust_ad) {
                        Ok(v) => v,
                        Err(err) => {
                            let mut de = new_dns_error(err.clone(), name, server);
                            if matches!(err, NetError::Op(_)) {
                                if let NetError::Dns(d) = &mut de {
                                    d.is_temporary = true;
                                }
                            }
                            last_err = Some(de);
                            continue;
                        }
                    };
                match check_header(&mut p, &h) {
                    Ok(()) => {}
                    Err(HeaderError::NoSuchHost) => return Err(no_such_host(name, server)),
                    Err(e) => {
                        last_err = Some(new_dns_error(e.into_net(), name, server));
                        continue;
                    }
                }
                match skip_to_answer(&mut p, qtype) {
                    Ok(()) => {}
                    Err(HeaderError::NoSuchHost) => return Err(no_such_host(name, server)),
                    Err(e) => {
                        last_err = Some(new_dns_error(e.into_net(), name, server));
                        continue;
                    }
                }
                return Ok(Answer {
                    p,
                    server: server.clone(),
                });
            }
        }
        Err(last_err.unwrap_or_else(|| dns_error("no answer from DNS server", name, "")))
    }

    fn lookup(&self, ctx: &Context, name: &str, qtype: u16) -> Result<Answer, NetError> {
        if !is_domain_name(name) {
            return Err(no_such_host(name, ""));
        }
        let conf = system_dns_config();
        // With no names to try Go returns the zero parser and no error.
        let mut result: Result<Answer, NetError> = Ok(Answer {
            p: Parser::unstarted(),
            server: String::new(),
        });
        for fqdn in conf.name_list(name) {
            result = self.try_one_name(ctx, &conf, &fqdn, qtype);
            if result.is_ok() {
                break;
            }
            if let Err(e) = &result {
                use super::error::Error as _;
                if e.temporary() && self.strict_errors {
                    break;
                }
            }
        }
        match result {
            Err(mut e) => {
                set_dns_name(&mut e, name);
                Err(e)
            }
            ok => ok,
        }
    }

    fn go_lookup_host_order(
        &self,
        ctx: &Context,
        name: &str,
        order: HostLookupOrder,
    ) -> Result<Vec<String>, NetError> {
        if matches!(order, HostLookupOrder::FilesDns | HostLookupOrder::Files) {
            let (addrs, _) = lookup_static_host(name);
            if !addrs.is_empty() {
                return Ok(addrs);
            }
            if order == HostLookupOrder::Files {
                return Err(no_such_host(name, ""));
            }
        }
        let (ips, _) = self.go_lookup_ip_cname_order(ctx, "ip", name, order)?;
        Ok(ips
            .into_iter()
            .map(|(ip, zone)| with_zone(&ip, &zone))
            .collect())
    }

    fn go_lookup_ip_files(name: &str) -> (Vec<IpZone>, String) {
        let (addr, canonical) = lookup_static_host(name);
        let mut out = Vec::new();
        for h in addr {
            let (host, zone) = split_host_zone(&h);
            if let Some(ip) = parse_ip(host) {
                out.push((ip, zone.to_owned()));
            }
        }
        sort_by_rfc6724(&mut out);
        (out, canonical)
    }

    fn go_lookup_ip_cname_order(
        &self,
        ctx: &Context,
        network: &str,
        name: &str,
        order: HostLookupOrder,
    ) -> Result<(Vec<IpZone>, String), NetError> {
        if matches!(order, HostLookupOrder::FilesDns | HostLookupOrder::Files) {
            let (addrs, canonical) = Self::go_lookup_ip_files(name);
            if !addrs.is_empty() {
                return Ok((addrs, canonical));
            }
            if order == HostLookupOrder::Files {
                return Err(no_such_host(name, ""));
            }
        }
        if !is_domain_name(name) {
            return Err(no_such_host(name, ""));
        }
        let conf = system_dns_config();
        let mut qtypes: Vec<u16> = vec![wire::TYPE_A, wire::TYPE_AAAA];
        if network == "CNAME" {
            qtypes.push(wire::TYPE_CNAME);
        }
        match network.chars().last() {
            Some('4') => qtypes = vec![wire::TYPE_A],
            Some('6') => qtypes = vec![wire::TYPE_AAAA],
            _ => {}
        }
        let mut addrs: Vec<IpZone> = Vec::new();
        let mut cname = String::new();
        let mut last_err: Option<NetError> = None;
        for fqdn in conf.name_list(name) {
            let results: Vec<Result<Answer, NetError>> = if conf.single_request {
                qtypes
                    .iter()
                    .map(|&qt| self.try_one_name(ctx, &conf, &fqdn, qt))
                    .collect()
            } else {
                std::thread::scope(|s| {
                    let hs: Vec<_> = qtypes
                        .iter()
                        .map(|&qt| {
                            let (conf, fqdn) = (&conf, &fqdn);
                            s.spawn(move || self.try_one_name(ctx, conf, fqdn, qt))
                        })
                        .collect();
                    hs.into_iter().map(|h| h.join().unwrap()).collect()
                })
            };
            let mut hit_strict = false;
            for res in results {
                let mut ans = match res {
                    Err(e) => {
                        use super::error::Error as _;
                        if e.temporary() && self.strict_errors {
                            hit_strict = true;
                            last_err = Some(e);
                        } else if last_err.is_none() || fqdn == format!("{name}.") {
                            last_err = Some(e);
                        }
                        continue;
                    }
                    Ok(a) => a,
                };
                loop {
                    let h = match ans.p.answer_header() {
                        Ok(h) => h,
                        Err(MsgError::SectionDone) => break,
                        Err(MsgError::Bad) => {
                            last_err = Some(cannot_unmarshal(name, &ans.server));
                            break;
                        }
                    };
                    let bad = |s: &Answer| cannot_unmarshal(name, &s.server);
                    match h.typ {
                        wire::TYPE_A => match ans.p.a_resource() {
                            Ok(a) => {
                                addrs.push((IP(a.to_vec()), String::new()));
                                if cname.is_empty() && h.name.as_slice() != b"" {
                                    cname = lossy(&h.name);
                                }
                            }
                            Err(_) => {
                                last_err = Some(bad(&ans));
                                break;
                            }
                        },
                        wire::TYPE_AAAA => match ans.p.aaaa_resource() {
                            Ok(a) => {
                                addrs.push((IP(a.to_vec()), String::new()));
                                if cname.is_empty() && !h.name.is_empty() {
                                    cname = lossy(&h.name);
                                }
                            }
                            Err(_) => {
                                last_err = Some(bad(&ans));
                                break;
                            }
                        },
                        wire::TYPE_CNAME => match ans.p.name_resource() {
                            Ok(c) => {
                                if cname.is_empty() && !c.is_empty() {
                                    cname = lossy(&c);
                                }
                            }
                            Err(_) => {
                                last_err = Some(bad(&ans));
                                break;
                            }
                        },
                        _ => {
                            if ans.p.skip_answer().is_err() {
                                last_err = Some(bad(&ans));
                                break;
                            }
                        }
                    }
                }
            }
            if hit_strict {
                addrs.clear();
                break;
            }
            if !addrs.is_empty() || (network == "CNAME" && !cname.is_empty()) {
                break;
            }
        }
        if let Some(e) = &mut last_err {
            set_dns_name(e, name);
        }
        sort_by_rfc6724(&mut addrs);
        if addrs.is_empty() && !(network == "CNAME" && !cname.is_empty()) {
            if order == HostLookupOrder::DnsFiles {
                let (a, canonical) = Self::go_lookup_ip_files(name);
                if !a.is_empty() {
                    return Ok((a, canonical));
                }
            }
            if let Some(e) = last_err {
                return Err(e);
            }
        }
        Ok((addrs, cname))
    }

    fn go_lookup_ptr(
        &self,
        ctx: &Context,
        addr: &str,
        order: HostLookupOrder,
    ) -> Result<Vec<String>, NetError> {
        if matches!(order, HostLookupOrder::Files | HostLookupOrder::FilesDns) {
            let names = lookup_static_addr(addr);
            if !names.is_empty() {
                return Ok(names);
            }
            if order == HostLookupOrder::Files {
                return Err(no_such_host(addr, ""));
            }
        }
        let arpa = reverse_addr(addr).ok_or_else(|| dns_error("unrecognized address", addr, ""))?;
        let mut ans = match self.lookup(ctx, &arpa, wire::TYPE_PTR) {
            Ok(a) => a,
            Err(e) => {
                if let NetError::Dns(d) = &e {
                    if d.is_not_found && order == HostLookupOrder::DnsFiles {
                        let names = lookup_static_addr(addr);
                        if !names.is_empty() {
                            return Ok(names);
                        }
                    }
                }
                return Err(e);
            }
        };
        let mut ptrs = Vec::new();
        loop {
            let h = match ans.p.answer_header() {
                Ok(h) => h,
                Err(MsgError::SectionDone) => break,
                Err(_) => return Err(cannot_unmarshal(addr, &ans.server)),
            };
            if h.typ != wire::TYPE_PTR {
                if ans.p.skip_answer().is_err() {
                    return Err(cannot_unmarshal(addr, &ans.server));
                }
                continue;
            }
            match ans.p.name_resource() {
                Ok(n) => ptrs.push(lossy(&n)),
                Err(_) => return Err(cannot_unmarshal(addr, &ans.server)),
            }
        }
        Ok(ptrs)
    }

    fn collect<T>(
        &self,
        ctx: &Context,
        name: &str,
        qtype: u16,
        mut body: impl FnMut(&mut Parser) -> Result<T, MsgError>,
    ) -> Result<Vec<T>, NetError> {
        let mut ans = self.lookup(ctx, name, qtype)?;
        let mut out = Vec::new();
        loop {
            let h = match ans.p.answer_header() {
                Ok(h) => h,
                Err(MsgError::SectionDone) => break,
                Err(_) => return Err(cannot_unmarshal(name, &ans.server)),
            };
            if h.typ != qtype {
                if ans.p.skip_answer().is_err() {
                    return Err(cannot_unmarshal(name, &ans.server));
                }
                continue;
            }
            match body(&mut ans.p) {
                Ok(v) => out.push((h.name, v)),
                Err(_) => return Err(cannot_unmarshal(name, &ans.server)),
            }
        }
        // The first owner name is returned through the closure-free path below.
        Ok(out.into_iter().map(|(_, v)| v).collect())
    }

    fn go_lookup_srv(
        &self,
        ctx: &Context,
        service: &str,
        proto: &str,
        name: &str,
    ) -> Result<(String, Vec<SRV>), NetError> {
        let target = if service.is_empty() && proto.is_empty() {
            name.to_owned()
        } else {
            format!("_{service}._{proto}.{name}")
        };
        let mut ans = self.lookup(ctx, &target, wire::TYPE_SRV)?;
        let mut cname = String::new();
        let mut srvs = Vec::new();
        loop {
            let h = match ans.p.answer_header() {
                Ok(h) => h,
                Err(MsgError::SectionDone) => break,
                Err(_) => return Err(cannot_unmarshal(name, &ans.server)),
            };
            if h.typ != wire::TYPE_SRV {
                if ans.p.skip_answer().is_err() {
                    return Err(cannot_unmarshal(name, &ans.server));
                }
                continue;
            }
            if cname.is_empty() && !h.name.is_empty() {
                cname = lossy(&h.name);
            }
            match ans.p.srv_resource() {
                Ok((priority, weight, port, t)) => srvs.push(SRV {
                    target: lossy(&t),
                    port,
                    priority,
                    weight,
                }),
                Err(_) => return Err(cannot_unmarshal(name, &ans.server)),
            }
        }
        sort_srv(&mut srvs);
        Ok((cname, srvs))
    }

    fn go_lookup_mx(&self, ctx: &Context, name: &str) -> Result<Vec<MX>, NetError> {
        let v = self.collect(ctx, name, wire::TYPE_MX, |p| p.mx_resource())?;
        let mut mxs: Vec<MX> = v
            .into_iter()
            .map(|(pref, h)| MX {
                host: lossy(&h),
                pref,
            })
            .collect();
        for i in 0..mxs.len() {
            let j = rand_intn(i + 1);
            mxs.swap(i, j);
        }
        mxs.sort_by_key(|m| m.pref);
        Ok(mxs)
    }

    fn go_lookup_ns(&self, ctx: &Context, name: &str) -> Result<Vec<NS>, NetError> {
        let v = self.collect(ctx, name, wire::TYPE_NS, |p| p.name_resource())?;
        Ok(v.into_iter().map(|h| NS { host: lossy(&h) }).collect())
    }

    fn go_lookup_txt(&self, ctx: &Context, name: &str) -> Result<Vec<String>, NetError> {
        let v = self.collect(ctx, name, wire::TYPE_TXT, |p| p.txt_resource())?;
        Ok(v.into_iter().map(|parts| lossy(&parts.concat())).collect())
    }
}

fn is_packable(name: &str) -> bool {
    let mut v = Vec::new();
    wire_pack_check(&mut v, name.as_bytes())
}

fn wire_pack_check(_v: &mut Vec<u8>, name: &[u8]) -> bool {
    if name.len() > 254 || name.last() != Some(&b'.') {
        return false;
    }
    if name == b"." {
        return true;
    }
    let mut begin = 0;
    for (i, &c) in name.iter().enumerate() {
        if c == b'.' {
            if i - begin >= 64 || i == begin {
                return false;
            }
            begin = i + 1;
        }
    }
    true
}

fn with_zone(ip: &IP, zone: &str) -> String {
    let s = ip.to_string();
    if zone.is_empty() {
        s
    } else {
        format!("{s}%{zone}")
    }
}

fn sort_srv(srvs: &mut [SRV]) {
    srvs.sort_by(|a, b| a.priority.cmp(&b.priority).then(a.weight.cmp(&b.weight)));
    let mut i = 0;
    for j in 1..srvs.len() {
        if srvs[i].priority != srvs[j].priority {
            shuffle_by_weight(&mut srvs[i..j]);
            i = j;
        }
    }
    shuffle_by_weight(&mut srvs[i..]);
}

fn shuffle_by_weight(mut addrs: &mut [SRV]) {
    let mut sum: usize = addrs.iter().map(|a| a.weight as usize).sum();
    while sum > 0 && addrs.len() > 1 {
        let n = rand_intn(sum);
        let mut s = 0;
        for i in 0..addrs.len() {
            s += addrs[i].weight as usize;
            if s > n {
                if i > 0 {
                    addrs.swap(0, i);
                }
                break;
            }
        }
        sum -= addrs[0].weight as usize;
        addrs = &mut addrs[1..];
    }
}

enum HeaderError {
    NoSuchHost,
    LameReferral,
    CannotUnmarshal,
    ServerMisbehaving,
    ServerTemporarilyMisbehaving,
}

impl HeaderError {
    fn into_net(self) -> NetError {
        match self {
            HeaderError::NoSuchHost => NetError::Other {
                text: "no such host".into(),
                temporary: false,
                not_found: true,
            },
            HeaderError::LameReferral => NetError::other("lame referral"),
            HeaderError::CannotUnmarshal => NetError::other("cannot unmarshal DNS message"),
            HeaderError::ServerMisbehaving => NetError::other("server misbehaving"),
            HeaderError::ServerTemporarilyMisbehaving => NetError::Other {
                text: "server misbehaving".into(),
                temporary: true,
                not_found: false,
            },
        }
    }
}

fn extract_extended_rcode(p: &Parser, h: &wire::Header) -> (u16, bool) {
    let mut p = p.clone();
    p.skip_all_answers();
    p.skip_all_authorities();
    let mut has_add = false;
    loop {
        let Ok(ah) = p.additional_header() else {
            return (h.rcode, has_add);
        };
        has_add = true;
        if ah.typ == wire::TYPE_OPT {
            return (ah.extended_rcode(h.rcode), has_add);
        }
        if p.skip_additional().is_err() {
            return (h.rcode, has_add);
        }
    }
}

fn check_header(p: &mut Parser, h: &wire::Header) -> Result<(), HeaderError> {
    let (rcode, has_add) = extract_extended_rcode(p, h);
    if rcode == wire::RCODE_NAME_ERROR {
        return Err(HeaderError::NoSuchHost);
    }
    let r = p.answer_header();
    if let Err(MsgError::Bad) = r {
        return Err(HeaderError::CannotUnmarshal);
    }
    if rcode == wire::RCODE_SUCCESS
        && !h.authoritative
        && !h.recursion_available
        && matches!(r, Err(MsgError::SectionDone))
        && !has_add
    {
        return Err(HeaderError::LameReferral);
    }
    if rcode != wire::RCODE_SUCCESS && rcode != wire::RCODE_NAME_ERROR {
        if rcode == wire::RCODE_SERVER_FAILURE {
            return Err(HeaderError::ServerTemporarilyMisbehaving);
        }
        return Err(HeaderError::ServerMisbehaving);
    }
    Ok(())
}

fn skip_to_answer(p: &mut Parser, qtype: u16) -> Result<(), HeaderError> {
    loop {
        match p.answer_header() {
            Err(MsgError::SectionDone) => return Err(HeaderError::NoSuchHost),
            Err(MsgError::Bad) => return Err(HeaderError::CannotUnmarshal),
            Ok(h) => {
                if h.typ == qtype {
                    return Ok(());
                }
                if p.skip_answer().is_err() {
                    return Err(HeaderError::CannotUnmarshal);
                }
            }
        }
    }
}

fn eq_ascii_name(x: &[u8], y: &[u8]) -> bool {
    x.eq_ignore_ascii_case(y)
}

fn check_response(req_id: u16, req: &Question, h: &wire::Header, q: &Question) -> bool {
    h.response
        && req_id == h.id
        && req.typ == q.typ
        && req.class == q.class
        && eq_ascii_name(&req.name, &q.name)
}

fn packet_round_trip(
    c: &dyn Conn,
    id: u16,
    query: &Question,
    b: &[u8],
) -> Result<(Parser, wire::Header), NetError> {
    c.write(b)?;
    let mut buf = vec![0u8; 1232];
    loop {
        let n = c.read(&mut buf)?;
        let Ok((mut p, h)) = Parser::start(&buf[..n]) else {
            continue;
        };
        let Ok(q) = p.question() else {
            continue;
        };
        if !check_response(id, query, &h, &q) {
            continue;
        }
        return Ok((p, h));
    }
}

fn read_full(c: &dyn Conn, buf: &mut [u8]) -> Result<(), NetError> {
    let mut off = 0;
    while off < buf.len() {
        let n = c.read(&mut buf[off..])?;
        if n == 0 {
            return Err(NetError::other(if off == 0 {
                "EOF"
            } else {
                "unexpected EOF"
            }));
        }
        off += n;
    }
    Ok(())
}

fn stream_round_trip(
    c: &dyn Conn,
    id: u16,
    query: &Question,
    b: &[u8],
) -> Result<(Parser, wire::Header), NetError> {
    c.write(b)?;
    let mut hdr = [0u8; 2];
    read_full(c, &mut hdr)?;
    let l = (hdr[0] as usize) << 8 | hdr[1] as usize;
    let mut buf = vec![0u8; l];
    read_full(c, &mut buf)?;
    let unm = || NetError::other("cannot unmarshal DNS message");
    let (mut p, h) = Parser::start(&buf).map_err(|_| unm())?;
    let q = p.question().map_err(|_| unm())?;
    if !check_response(id, query, &h, &q) {
        return Err(NetError::other("invalid DNS response"));
    }
    Ok((p, h))
}

fn resolve_unix(network: &str, address: &str) -> Result<UnixAddr, NetError> {
    match network {
        "unix" | "unixgram" | "unixpacket" => Ok(UnixAddr {
            name: address.into(),
            net: network.into(),
        }),
        _ => Err(UnknownNetworkError(network.into()).into()),
    }
}

// ---- package-level functions ----

fn bg() -> Context {
    Context::background()
}

/// `net.LookupHost`.
pub fn lookup_host(host: &str) -> Result<Vec<String>, NetError> {
    DEFAULT_RESOLVER.lookup_host(&bg(), host)
}

/// `net.LookupIP`.
pub fn lookup_ip(host: &str) -> Result<Vec<IP>, NetError> {
    Ok(DEFAULT_RESOLVER
        .lookup_ip_addr(&bg(), host)?
        .into_iter()
        .map(|a| a.ip)
        .collect())
}

/// `net.LookupPort`.
pub fn lookup_port(network: &str, service: &str) -> Result<i32, NetError> {
    DEFAULT_RESOLVER.lookup_port(&bg(), network, service)
}

/// `net.LookupCNAME`.
pub fn lookup_cname(host: &str) -> Result<String, NetError> {
    DEFAULT_RESOLVER.lookup_cname(&bg(), host)
}

/// `net.LookupSRV`.
pub fn lookup_srv(
    service: &str,
    proto: &str,
    name: &str,
) -> Result<(String, Vec<SRV>, Option<NetError>), NetError> {
    DEFAULT_RESOLVER.lookup_srv(&bg(), service, proto, name)
}

/// `net.LookupMX`.
pub fn lookup_mx(name: &str) -> Result<(Vec<MX>, Option<NetError>), NetError> {
    DEFAULT_RESOLVER.lookup_mx(&bg(), name)
}

/// `net.LookupNS`.
pub fn lookup_ns(name: &str) -> Result<(Vec<NS>, Option<NetError>), NetError> {
    DEFAULT_RESOLVER.lookup_ns(&bg(), name)
}

/// `net.LookupTXT`.
pub fn lookup_txt(name: &str) -> Result<Vec<String>, NetError> {
    DEFAULT_RESOLVER.lookup_txt(&bg(), name)
}

/// `net.LookupAddr`.
pub fn lookup_addr(addr: &str) -> Result<(Vec<String>, Option<NetError>), NetError> {
    DEFAULT_RESOLVER.lookup_addr(&bg(), addr)
}

/// `net.ResolveTCPAddr`.
pub fn resolve_tcp_addr(network: &str, address: &str) -> Result<TCPAddr, NetError> {
    let network = match network {
        "tcp" | "tcp4" | "tcp6" => network,
        "" => "tcp",
        _ => return Err(UnknownNetworkError(network.into()).into()),
    };
    let addrs = DEFAULT_RESOLVER.internet_addr_list(&bg(), network, address)?;
    match for_resolve(&addrs, network, address) {
        ResolvedAddr::Tcp(a) => Ok(a),
        _ => unreachable!("internet_addr_list returns the requested family"),
    }
}

/// `net.ResolveUDPAddr`.
pub fn resolve_udp_addr(network: &str, address: &str) -> Result<UDPAddr, NetError> {
    let network = match network {
        "udp" | "udp4" | "udp6" => network,
        "" => "udp",
        _ => return Err(UnknownNetworkError(network.into()).into()),
    };
    let addrs = DEFAULT_RESOLVER.internet_addr_list(&bg(), network, address)?;
    match for_resolve(&addrs, network, address) {
        ResolvedAddr::Udp(a) => Ok(a),
        _ => unreachable!("internet_addr_list returns the requested family"),
    }
}

/// `net.ResolveIPAddr`.
pub fn resolve_ip_addr(network: &str, address: &str) -> Result<super::addr::IPAddr, NetError> {
    let network = if network.is_empty() { "ip" } else { network };
    let (afnet, _) = parse_network(network, false)?;
    if !matches!(afnet.as_str(), "ip" | "ip4" | "ip6") {
        return Err(UnknownNetworkError(network.into()).into());
    }
    let addrs = DEFAULT_RESOLVER.internet_addr_list(&bg(), &afnet, address)?;
    match for_resolve(&addrs, network, address) {
        ResolvedAddr::Ip(a) => Ok(a),
        _ => unreachable!("internet_addr_list returns the requested family"),
    }
}

/// `net.ResolveUnixAddr`.
pub fn resolve_unix_addr(network: &str, address: &str) -> Result<UnixAddr, NetError> {
    resolve_unix(network, address)
}

/// One in-flight lookup shared by concurrent callers (Go's `singleflight`).
#[derive(Default)]
struct Flight {
    result: Mutex<Option<Result<Vec<IpZone>, NetError>>>,
    done: Condvar,
    shared: AtomicBool,
}

static FLIGHTS: LazyLock<Mutex<HashMap<String, Arc<Flight>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
