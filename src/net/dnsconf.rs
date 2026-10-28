//! Name-service configuration files for the pure resolver, ported from
//! `net/dnsconfig_unix.go`, `hosts.go`, `port_unix.go`, `lookup_unix.go`,
//! `conf.go` and `addrselect.go` (see NOTICE): `/etc/resolv.conf`,
//! `/etc/hosts`, `/etc/services`, `/etc/protocols`, `/etc/nsswitch.conf`
//! and RFC 6724 destination ordering.
use super::addr::join_host_port;
use super::ip::{dtoi, parse_ip, IP};
use super::netip;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

/// The parsed `/etc/resolv.conf`.
#[derive(Debug)]
pub(crate) struct DnsConfig {
    pub servers: Vec<String>,
    pub search: Vec<String>,
    pub ndots: usize,
    pub timeout: Duration,
    pub attempts: usize,
    pub rotate: bool,
    pub single_request: bool,
    pub use_tcp: bool,
    pub trust_ad: bool,
    pub unknown_opt: bool,
    pub mtime: Option<SystemTime>,
    pub err: Option<std::io::ErrorKind>,
    pub no_reload: bool,
    server_offset: AtomicU32,
}

fn default_ns() -> Vec<String> {
    vec!["127.0.0.1:53".into(), "[::1]:53".into()]
}

fn hostname() -> Option<String> {
    if let Ok(h) = std::env::var("HOSTNAME") {
        if !h.is_empty() {
            return Some(h);
        }
    }
    for f in ["/proc/sys/kernel/hostname", "/etc/hostname"] {
        if let Ok(s) = std::fs::read_to_string(f) {
            let s = s.trim();
            if !s.is_empty() {
                return Some(s.to_owned());
            }
        }
    }
    None
}

fn dns_default_search() -> Vec<String> {
    match hostname() {
        Some(hn) => match hn.find('.') {
            Some(i) if i < hn.len() - 1 => vec![ensure_rooted(&hn[i + 1..])],
            _ => Vec::new(),
        },
        None => Vec::new(),
    }
}

fn ensure_rooted(s: &str) -> String {
    if s.ends_with('.') {
        s.to_owned()
    } else {
        format!("{s}.")
    }
}

/// Splits at any of ` \r\t\n`, dropping empty fields (Go's `getFields`).
pub(crate) fn get_fields(s: &str) -> Vec<&str> {
    s.split([' ', '\r', '\t', '\n'])
        .filter(|f| !f.is_empty())
        .collect()
}

// Lines as Go's file.readLine yields them: split at '\n', trailing '\r' kept
// out by `getFields` anyway.
fn lines(data: &str) -> impl Iterator<Item = &str> {
    data.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l))
}

impl DnsConfig {
    /// `dnsReadConfig`.
    pub(crate) fn read(path: &str) -> DnsConfig {
        let mut conf = DnsConfig {
            servers: Vec::new(),
            search: Vec::new(),
            ndots: 1,
            timeout: Duration::from_secs(5),
            attempts: 2,
            rotate: false,
            single_request: false,
            use_tcp: false,
            trust_ad: false,
            unknown_opt: false,
            mtime: None,
            err: None,
            no_reload: false,
            server_offset: AtomicU32::new(0),
        };
        let data = match std::fs::read(path) {
            Ok(d) => String::from_utf8_lossy(&d).into_owned(),
            Err(e) => {
                conf.servers = default_ns();
                conf.search = dns_default_search();
                conf.err = Some(e.kind());
                return conf;
            }
        };
        conf.mtime = std::fs::metadata(path).and_then(|m| m.modified()).ok();
        for line in lines(&data) {
            if line.starts_with(';') || line.starts_with('#') {
                continue;
            }
            let f = get_fields(line);
            if f.is_empty() {
                continue;
            }
            match f[0] {
                "nameserver" => {
                    if f.len() > 1 && conf.servers.len() < 3 && f[1].parse::<netip::Addr>().is_ok()
                    {
                        conf.servers.push(join_host_port(f[1], "53"));
                    }
                }
                "domain" => {
                    if f.len() > 1 {
                        conf.search = vec![ensure_rooted(f[1])];
                    }
                }
                "search" => {
                    conf.search = f[1..]
                        .iter()
                        .map(|n| ensure_rooted(n))
                        .filter(|n| n != ".")
                        .collect();
                }
                "options" => {
                    for s in &f[1..] {
                        if let Some(r) = s.strip_prefix("ndots:") {
                            conf.ndots = dtoi(r).0.clamp(0, 15) as usize;
                        } else if let Some(r) = s.strip_prefix("timeout:") {
                            conf.timeout = Duration::from_secs(dtoi(r).0.max(1) as u64);
                        } else if let Some(r) = s.strip_prefix("attempts:") {
                            conf.attempts = dtoi(r).0.max(1) as usize;
                        } else {
                            match *s {
                                "rotate" => conf.rotate = true,
                                "single-request" | "single-request-reopen" => {
                                    conf.single_request = true
                                }
                                "use-vc" | "usevc" | "tcp" => conf.use_tcp = true,
                                "trust-ad" => conf.trust_ad = true,
                                "edns0" => {}
                                "no-reload" => conf.no_reload = true,
                                _ => conf.unknown_opt = true,
                            }
                        }
                    }
                }
                "lookup" => {}
                _ => conf.unknown_opt = true,
            }
        }
        if conf.servers.is_empty() {
            conf.servers = default_ns();
        }
        if conf.search.is_empty() {
            conf.search = dns_default_search();
        }
        conf
    }

    /// `dnsConfig.nameList`: the names to query in order.
    pub(crate) fn name_list(&self, name: &str) -> Vec<String> {
        let rooted = name.ends_with('.');
        if name.len() > 254 || (name.len() == 254 && !rooted) {
            return Vec::new();
        }
        if rooted {
            if avoid_dns(name) {
                return Vec::new();
            }
            return vec![name.to_owned()];
        }
        let has_ndots = name.matches('.').count() >= self.ndots;
        let name = format!("{name}.");
        let mut names = Vec::new();
        if has_ndots && !avoid_dns(&name) {
            names.push(name.clone());
        }
        for suffix in &self.search {
            let fqdn = format!("{name}{suffix}");
            if !avoid_dns(&fqdn) && fqdn.len() <= 254 {
                names.push(fqdn);
            }
        }
        if !has_ndots && !avoid_dns(&name) {
            names.push(name);
        }
        names
    }

    /// `dnsConfig.serverOffset`.
    pub(crate) fn server_offset(&self) -> u32 {
        if self.rotate {
            self.server_offset
                .fetch_add(1, Ordering::SeqCst)
                .wrapping_add(1)
                - 1
        } else {
            0
        }
    }

    pub(crate) fn is_default_ns(&self) -> bool {
        self.servers == default_ns()
    }
}

fn avoid_dns(name: &str) -> bool {
    if name.is_empty() {
        return true;
    }
    let name = name.strip_suffix('.').unwrap_or(name);
    name.len() >= 6 && name[name.len() - 6..].eq_ignore_ascii_case(".onion")
}

static CONF: Mutex<Option<(Instant, Arc<DnsConfig>)>> = Mutex::new(None);

/// The system DNS configuration, re-read at most every five seconds when the
/// file changed.
pub(crate) fn system_dns_config() -> Arc<DnsConfig> {
    let path = "/etc/resolv.conf";
    let mut g = CONF.lock().unwrap();
    if let Some((checked, c)) = g.as_ref() {
        let expired = checked.elapsed() > Duration::from_secs(5);
        if c.no_reload || !(expired || c.is_default_ns()) {
            return c.clone();
        }
        let mtime = std::fs::metadata(path).and_then(|m| m.modified()).ok();
        if mtime == c.mtime {
            let c = c.clone();
            *g = Some((Instant::now(), c.clone()));
            return c;
        }
    }
    let c = Arc::new(DnsConfig::read(path));
    *g = Some((Instant::now(), c.clone()));
    c
}

/// `isDomainName`: a presentation-format domain name.
pub(crate) fn is_domain_name(s: &str) -> bool {
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
    if last == b'-' || partlen > 63 {
        return false;
    }
    non_numeric
}

/// `absDomainName`: add a trailing dot to names that contain a dot.
pub(crate) fn abs_domain_name(s: &str) -> String {
    if s.contains('.') && !s.ends_with('.') {
        format!("{s}.")
    } else {
        s.to_owned()
    }
}

/// `reverseaddr`: the in-addr.arpa. or ip6.arpa. name of `addr`.
pub(crate) fn reverse_addr(addr: &str) -> Option<String> {
    let ip = parse_ip(addr)?;
    if ip.to4().is_some() {
        let b = &ip.0;
        return Some(format!(
            "{}.{}.{}.{}.in-addr.arpa.",
            b[15], b[14], b[13], b[12]
        ));
    }
    let mut s = String::new();
    for v in ip.0.iter().rev() {
        s.push_str(&format!("{:x}.{:x}.", v & 0xF, v >> 4));
    }
    s.push_str("ip6.arpa.");
    Some(s)
}

#[derive(Default)]
struct Hosts {
    by_name: HashMap<String, (Vec<String>, String)>,
    by_addr: HashMap<String, Vec<String>>,
}

fn parse_literal_ip(addr: &str) -> String {
    addr.parse::<netip::Addr>()
        .map(|a| a.to_string())
        .unwrap_or_default()
}

fn read_hosts() -> Hosts {
    let mut h = Hosts::default();
    let Ok(data) = std::fs::read("/etc/hosts") else {
        return h;
    };
    let data = String::from_utf8_lossy(&data).into_owned();
    for line in lines(&data) {
        let line = line.split('#').next().unwrap_or("");
        let f = get_fields(line);
        if f.len() < 2 {
            continue;
        }
        let addr = parse_literal_ip(f[0]);
        if addr.is_empty() {
            continue;
        }
        let mut canonical = String::new();
        for (i, name) in f.iter().enumerate().skip(1) {
            let shown = abs_domain_name(name);
            let key = abs_domain_name(&name.to_ascii_lowercase());
            if i == 1 {
                canonical = key.clone();
            }
            h.by_addr.entry(addr.clone()).or_default().push(shown);
            match h.by_name.get_mut(&key) {
                Some(v) => v.0.push(addr.clone()),
                None => {
                    h.by_name
                        .insert(key, (vec![addr.clone()], canonical.clone()));
                }
            }
        }
    }
    h
}

/// `lookupStaticHost`: addresses and canonical name from `/etc/hosts`.
pub(crate) fn lookup_static_host(host: &str) -> (Vec<String>, String) {
    let h = read_hosts();
    if !h.by_name.is_empty() {
        if let Some((a, c)) = h.by_name.get(&abs_domain_name(&host.to_ascii_lowercase())) {
            return (a.clone(), c.clone());
        }
    }
    (Vec::new(), String::new())
}

/// `lookupStaticAddr`: host names for `addr` from `/etc/hosts`.
pub(crate) fn lookup_static_addr(addr: &str) -> Vec<String> {
    let h = read_hosts();
    let addr = parse_literal_ip(addr);
    if addr.is_empty() {
        return Vec::new();
    }
    h.by_addr.get(&addr).cloned().unwrap_or_default()
}

type Services = HashMap<String, HashMap<String, i32>>;

fn services() -> &'static Mutex<Services> {
    static S: OnceLock<Mutex<Services>> = OnceLock::new();
    S.get_or_init(|| {
        let mut m: Services = HashMap::new();
        m.insert(
            "udp".into(),
            [("domain".to_owned(), 53)].into_iter().collect(),
        );
        m.insert(
            "tcp".into(),
            [
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
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect(),
        );
        if let Ok(data) = std::fs::read("/etc/services") {
            let data = String::from_utf8_lossy(&data).into_owned();
            for line in lines(&data) {
                let line = line.split('#').next().unwrap_or("");
                let f = get_fields(line);
                if f.len() < 2 {
                    continue;
                }
                let portnet = f[1];
                let (port, j, ok) = dtoi(portnet);
                if !ok || port <= 0 || j >= portnet.len() || portnet.as_bytes()[j] != b'/' {
                    continue;
                }
                let netw = &portnet[j + 1..];
                let entry = m.entry(netw.to_owned()).or_default();
                for (i, name) in f.iter().enumerate() {
                    if i != 1 {
                        entry.insert((*name).to_owned(), port);
                    }
                }
            }
        }
        Mutex::new(m)
    })
}

/// `goLookupPort`: the port of a service name, or `None`.
/// The error cases are built by the caller from the network name.
pub(crate) fn lookup_port_map(network: &str, service: &str) -> Result<i32, PortError> {
    let lookup = |net: &str| -> Result<i32, PortError> {
        let s = services().lock().unwrap();
        match s.get(net) {
            Some(m) => {
                if service.len() <= "mobility-header".len() + 10 {
                    if let Some(p) = m.get(&service.to_ascii_lowercase()) {
                        return Ok(*p);
                    }
                }
                Err(PortError::Unknown)
            }
            None => Err(PortError::UnknownNetwork),
        }
    };
    match network {
        "ip" => lookup("tcp").or_else(|_| lookup("udp")),
        "tcp" | "tcp4" | "tcp6" => lookup("tcp"),
        "udp" | "udp4" | "udp6" => lookup("udp"),
        _ => Err(PortError::UnknownNetwork),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PortError {
    Unknown,
    UnknownNetwork,
}

fn protocols() -> &'static Mutex<HashMap<String, i32>> {
    static P: OnceLock<Mutex<HashMap<String, i32>>> = OnceLock::new();
    P.get_or_init(|| {
        let mut m: HashMap<String, i32> = [
            ("icmp", 1),
            ("igmp", 2),
            ("tcp", 6),
            ("udp", 17),
            ("ipv6-icmp", 58),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
        if let Ok(data) = std::fs::read("/etc/protocols") {
            let data = String::from_utf8_lossy(&data).into_owned();
            for line in lines(&data) {
                let line = line.split('#').next().unwrap_or("");
                let f = get_fields(line);
                if f.len() < 2 {
                    continue;
                }
                let (proto, _, ok) = dtoi(f[1]);
                if ok {
                    m.entry(f[0].to_owned()).or_insert(proto);
                    for alias in &f[2..] {
                        m.entry((*alias).to_owned()).or_insert(proto);
                    }
                }
            }
        }
        Mutex::new(m)
    })
}

/// `lookupProtocol`: the protocol number of `name`.
pub(crate) fn lookup_protocol(name: &str) -> Option<i32> {
    if name.len() > "RSVP-E2E-IGNORE".len() + 10 {
        return None;
    }
    protocols()
        .lock()
        .unwrap()
        .get(&name.to_ascii_lowercase())
        .copied()
}

/// The order of host lookup strategies for the pure resolver.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum HostLookupOrder {
    FilesDns,
    DnsFiles,
    Files,
    Dns,
}

/// `conf.lookupOrder` when the Go resolver is forced: `/etc/nsswitch.conf`
/// decides, defaulting to files then DNS.
pub(crate) fn lookup_order() -> HostLookupOrder {
    let Ok(data) = std::fs::read("/etc/nsswitch.conf") else {
        return HostLookupOrder::FilesDns;
    };
    let data = String::from_utf8_lossy(&data).into_owned();
    let mut srcs: Option<Vec<String>> = None;
    for line in lines(&data) {
        let line = line.split('#').next().unwrap_or("").trim();
        if let Some((k, v)) = line.split_once(':') {
            if k.trim() == "hosts" {
                // Drop "[STATUS=action]" criteria.
                let mut out = Vec::new();
                let mut depth = false;
                for w in v.split_whitespace() {
                    if w.starts_with('[') {
                        depth = true;
                    }
                    if !depth {
                        out.push(w.to_owned());
                    }
                    if w.ends_with(']') {
                        depth = false;
                    }
                }
                srcs = Some(out);
            }
        }
    }
    let srcs = match srcs {
        Some(s) if !s.is_empty() => s,
        _ => return HostLookupOrder::FilesDns,
    };
    let (mut files, mut dns, mut first) = (false, false, "");
    let has_dns = srcs.iter().any(|s| s == "dns");
    for s in &srcs {
        match s.as_str() {
            "files" => {
                files = true;
                if first.is_empty() {
                    first = "files";
                }
            }
            "dns" => {
                dns = true;
                if first.is_empty() {
                    first = "dns";
                }
            }
            _ => {
                if !has_dns {
                    dns = true;
                    if first.is_empty() {
                        first = "dns";
                    }
                }
            }
        }
    }
    match (files, dns) {
        (true, true) if first == "files" => HostLookupOrder::FilesDns,
        (true, true) => HostLookupOrder::DnsFiles,
        (true, false) => HostLookupOrder::Files,
        (false, true) => HostLookupOrder::Dns,
        _ => HostLookupOrder::FilesDns,
    }
}

/// A resolved address with its IPv6 zone (`net.IPAddr` without the type).
pub(crate) type IpZone = (IP, String);

// --- RFC 6724 destination address selection (net/addrselect.go) ---

#[derive(Clone, Copy, PartialEq, Eq, Default)]
struct IpAttr {
    scope: u8,
    precedence: u8,
    label: u8,
}

fn policy(ip: &netip::Addr) -> (u8, u8) {
    let ip = if ip.is4() {
        netip::Addr::from(ip.as16())
    } else {
        ip.clone()
    };
    let table: [(&str, u8, u8); 9] = [
        ("::1/128", 50, 0),
        ("::ffff:0:0/96", 35, 4),
        ("::/96", 1, 3),
        ("2001::/32", 5, 5),
        ("2002::/16", 30, 2),
        ("3ffe::/16", 1, 12),
        ("fec0::/10", 1, 11),
        ("fc00::/7", 3, 13),
        ("::/0", 40, 1),
    ];
    for (p, prec, label) in table {
        if p.parse::<netip::Prefix>()
            .expect("valid prefix")
            .contains(&ip)
        {
            return (prec, label);
        }
    }
    (0, 0)
}

fn classify_scope(ip: &netip::Addr) -> u8 {
    if ip.is_loopback() || ip.is_link_local_unicast() {
        return 0x2;
    }
    let v6 = ip.is6() && !ip.is4in6();
    let b = ip.as16();
    if v6 && ip.is_multicast() {
        return b[1] & 0xf;
    }
    if v6 && b[0] == 0xfe && b[1] & 0xc0 == 0xc0 {
        return 0x5;
    }
    0xe
}

fn ip_attr_of(ip: &netip::Addr) -> IpAttr {
    if !ip.is_valid() {
        return IpAttr::default();
    }
    let (precedence, label) = policy(ip);
    IpAttr {
        scope: classify_scope(ip),
        precedence,
        label,
    }
}

fn common_prefix_len(a: &netip::Addr, b: &IP) -> usize {
    let b = b.to4().unwrap_or_else(|| b.clone());
    let a_s = a.as_slice();
    if a_s.len() != b.0.len() {
        return 0;
    }
    let (a_s, b_s) = if a_s.len() > 8 {
        (&a_s[..8], &b.0[..8])
    } else {
        (&a_s[..], &b.0[..])
    };
    let mut cpl = 0;
    for (x, y) in a_s.iter().zip(b_s) {
        if x == y {
            cpl += 8;
            continue;
        }
        cpl += (x ^ y).leading_zeros() as usize;
        break;
    }
    cpl
}

/// Tries to UDP-connect to each address to see which source Go would use.
fn src_addrs(addrs: &[IpZone]) -> Vec<netip::Addr> {
    addrs
        .iter()
        .map(|(ip, _)| {
            // Go dials by address family: IPv4-mapped addresses use an IPv4 socket.
            let Some(dst) =
                std::net::IpAddr::try_from(&ip.to4().unwrap_or_else(|| ip.clone())).ok()
            else {
                return netip::Addr::default();
            };
            let bind = if dst.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
            let Ok(s) = std::net::UdpSocket::bind(bind) else {
                return netip::Addr::default();
            };
            if s.connect((dst, 53)).is_err() {
                return netip::Addr::default();
            }
            match s.local_addr() {
                Ok(a) => netip::Addr::from(a.ip()),
                Err(_) => netip::Addr::default(),
            }
        })
        .collect()
}

/// `sortByRFC6724`.
pub(crate) fn sort_by_rfc6724(addrs: &mut Vec<IpZone>) {
    if addrs.len() < 2 {
        return;
    }
    let srcs = src_addrs(addrs);
    sort_by_rfc6724_with_srcs(addrs, &srcs);
}

pub(crate) fn sort_by_rfc6724_with_srcs(addrs: &mut Vec<IpZone>, srcs: &[netip::Addr]) {
    struct Info {
        addr: IpZone,
        addr_attr: IpAttr,
        src: netip::Addr,
        src_attr: IpAttr,
    }
    let mut infos: Vec<Info> = addrs
        .iter()
        .zip(srcs)
        .map(|(a, s)| {
            let a_addr = netip::Addr::try_from(a.0 .0.as_slice())
                .ok()
                .unwrap_or_default();
            Info {
                addr: a.clone(),
                addr_attr: ip_attr_of(&a_addr),
                src: s.clone(),
                src_attr: ip_attr_of(s),
            }
        })
        .collect();
    // Go's SortStableFunc is an insertion sort for short slices; the
    // comparator is not a strict weak order, so keep the same algorithm.
    let less = |a: &Info, b: &Info| {
        compare_rfc6724(
            a.addr.0.clone(),
            a.addr_attr,
            &a.src,
            a.src_attr,
            b.addr.0.clone(),
            b.addr_attr,
            &b.src,
            b.src_attr,
        ) < 0
    };
    for i in 1..infos.len() {
        let mut j = i;
        while j > 0 && less(&infos[j], &infos[j - 1]) {
            infos.swap(j, j - 1);
            j -= 1;
        }
    }
    *addrs = infos.into_iter().map(|i| i.addr).collect();
}

#[allow(clippy::too_many_arguments)]
fn compare_rfc6724(
    da: IP,
    attr_da: IpAttr,
    src_a: &netip::Addr,
    attr_src_a: IpAttr,
    db: IP,
    attr_db: IpAttr,
    src_b: &netip::Addr,
    attr_src_b: IpAttr,
) -> i32 {
    const PREFER_DA: i32 = -1;
    const PREFER_DB: i32 = 1;
    if !src_a.is_valid() && !src_b.is_valid() {
        return 0;
    }
    if !src_b.is_valid() {
        return PREFER_DA;
    }
    if !src_a.is_valid() {
        return PREFER_DB;
    }
    if attr_da.scope == attr_src_a.scope && attr_db.scope != attr_src_b.scope {
        return PREFER_DA;
    }
    if attr_da.scope != attr_src_a.scope && attr_db.scope == attr_src_b.scope {
        return PREFER_DB;
    }
    if attr_src_a.label == attr_da.label && attr_src_b.label != attr_db.label {
        return PREFER_DA;
    }
    if attr_src_a.label != attr_da.label && attr_src_b.label == attr_db.label {
        return PREFER_DB;
    }
    if attr_da.precedence > attr_db.precedence {
        return PREFER_DA;
    }
    if attr_da.precedence < attr_db.precedence {
        return PREFER_DB;
    }
    if attr_da.scope < attr_db.scope {
        return PREFER_DA;
    }
    if attr_da.scope > attr_db.scope {
        return PREFER_DB;
    }
    if da.to4().is_none() && db.to4().is_none() {
        let ca = common_prefix_len(src_a, &da);
        let cb = common_prefix_len(src_b, &db);
        if ca > cb {
            return PREFER_DA;
        }
        if ca < cb {
            return PREFER_DB;
        }
    }
    0
}
