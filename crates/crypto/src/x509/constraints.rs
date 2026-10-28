//! Name constraint checking, a port of Go's `constraints.go`.
//!
//! Constraints describe possibly overlapping subtrees. Sorted lexicographically
//! and pruned of subtrees that overlap preceding subtrees, a binary search
//! finds the nearest matching prefix, which makes the check log-linear.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use super::error::quote;
use super::net::{Ip, IpNet};
use super::parser::domain_name_valid;
use super::url::Url;
use super::verify::{parse_rfc2821_mailbox, Rfc2821Mailbox};
use super::{Certificate, Error};

struct ConstraintSet<T> {
    set: Vec<T>,
}

impl<T: Clone> ConstraintSet<T> {
    /// Sorts the constraints with `cmp`, then prunes any that are subsets of
    /// preceding constraints according to `subset`.
    fn sort_and_prune(&mut self, cmp: fn(&T, &T) -> Ordering, subset: fn(&T, &T) -> bool) {
        if self.set.len() < 2 {
            return;
        }
        self.set.sort_by(cmp);
        let mut write_index = 1;
        for read_index in 1..self.set.len() {
            if !subset(&self.set[write_index - 1], &self.set[read_index]) {
                self.set[write_index] = self.set[read_index].clone();
                write_index += 1;
            }
        }
        self.set.truncate(write_index);
    }

    /// A binary search for the lower bound of `s`, then `match_fn` on the
    /// nearest constraint.
    fn search<V: ?Sized>(
        &self,
        s: &V,
        cmp: fn(&T, &V) -> Ordering,
        match_fn: fn(&T, &V) -> bool,
    ) -> Option<&T> {
        if self.set.is_empty() {
            return None;
        }
        // Lower bound, as slices.BinarySearchFunc.
        let mut lo = 0;
        let mut hi = self.set.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if cmp(&self.set[mid], s) == Ordering::Less {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        let i = lo;
        if i < self.set.len() && cmp(&self.set[i], s) == Ordering::Equal {
            return Some(&self.set[i]);
        }
        let constraint = if i == 0 {
            &self.set[0]
        } else {
            &self.set[i - 1]
        };
        if match_fn(constraint, s) {
            return Some(constraint);
        }
        None
    }
}

fn ip_network_subset(a: &IpNet, b: &IpNet) -> bool {
    if !a.contains(&b.ip) {
        return false;
    }
    let broadcast: Vec<u8> = (0..b.ip.0.len())
        .map(|i| b.ip.0[i] | !b.mask.get(i).copied().unwrap_or(0))
        .collect();
    a.contains(&Ip(broadcast))
}

fn ip_network_compare(a: &IpNet, b: &IpNet) -> Ordering {
    a.ip.0.cmp(&b.ip.0).then_with(|| a.mask.cmp(&b.mask))
}

fn ip_binary_search(constraint: &IpNet, target: &Ip) -> Ordering {
    constraint.ip.0.cmp(&target.0)
}

fn ip_match(constraint: &IpNet, target: &Ip) -> bool {
    constraint.contains(target)
}

struct IpConstraints {
    ipv4: Option<ConstraintSet<IpNet>>,
    ipv6: Option<ConstraintSet<IpNet>>,
}

fn new_ip_net_constraints(l: &[IpNet]) -> Option<IpConstraints> {
    if l.is_empty() {
        return None;
    }
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    for n in l {
        // Subtrees may carry non-zero host bits. Sort and search need the
        // masked network address, so use a copy.
        let mut n = n.clone();
        if let Some(masked) = n.ip.mask(&n.mask) {
            if !masked.equal(&n.ip) {
                n = IpNet {
                    ip: masked,
                    mask: n.mask.clone(),
                };
            }
        }
        if n.ip.0.len() == 4 {
            ipv4.push(n);
        } else {
            ipv6.push(n);
        }
    }
    let build = |v: Vec<IpNet>| {
        if v.is_empty() {
            None
        } else {
            let mut set = ConstraintSet { set: v };
            set.sort_and_prune(ip_network_compare, ip_network_subset);
            Some(set)
        }
    };
    Some(IpConstraints {
        ipv4: build(ipv4),
        ipv6: build(ipv6),
    })
}

impl IpConstraints {
    fn query(&self, ip: &Ip) -> Option<IpNet> {
        let c = if ip.0.len() == 4 {
            self.ipv4.as_ref()
        } else {
            self.ipv6.as_ref()
        };
        c?.search(ip, ip_binary_search, ip_match).cloned()
    }
}

/// Go's `dnsHasSuffix`: case-insensitively checks if DNS name `b` is a label
/// suffix of DNS name `a`, with the URI "leading period" semantics.
fn dns_has_suffix(a: &String, b: &String) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (len_a, len_b) = (a.len(), b.len());
    if len_a > len_b {
        return false;
    }
    let offset = len_b - len_a;
    for i in (0..len_a).rev() {
        let (mut ar, mut br) = (a[i], b[i + offset]);
        if ar == br {
            continue;
        }
        if br < ar {
            std::mem::swap(&mut ar, &mut br);
        }
        if ar.is_ascii_uppercase() && br == ar + b'a' - b'A' {
            continue;
        }
        return false;
    }
    if a[0] != b'.' && len_b > len_a && b[len_b - len_a - 1] != b'.' {
        return false;
    }
    true
}

fn dns_compare_byte(c: u8) -> u8 {
    if c == b'.' {
        // The period sorts before the hyphen so that "a.a.com" sorts before
        // "a-a.com".
        0
    } else {
        c.to_ascii_lowercase()
    }
}

/// Go's `dnsCompare`: a case-insensitive reversed comparison that treats the
/// period as sorting below every other character.
fn dns_compare(a: &String, b: &String) -> Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut idx_a = a.len() as isize - 1;
    let mut idx_b = b.len() as isize - 1;
    while idx_a >= 0 && idx_b >= 0 {
        let byte_a = dns_compare_byte(a[idx_a as usize]);
        let byte_b = dns_compare_byte(b[idx_b as usize]);
        if byte_a == byte_b {
            idx_a -= 1;
            idx_b -= 1;
            continue;
        }
        return if byte_a < byte_b {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    if idx_a < idx_b {
        Ordering::Less
    } else if idx_b < idx_a {
        Ordering::Greater
    } else {
        Ordering::Equal
    }
}

fn dns_search_match(c: &String, s: &String) -> bool {
    dns_has_suffix(c, s)
}

struct DnsConstraints {
    /// A zero length constraint permits or excludes everything.
    all: bool,
    permitted: bool,
    constraints: Option<ConstraintSet<String>>,
    /// Constraints with their first label removed, for wildcard queries; only
    /// for excluded constraints.
    parent_constraints: HashMap<String, String>,
}

fn new_dns_constraints(l: &[String], permitted: bool) -> Option<DnsConstraints> {
    if l.is_empty() {
        return None;
    }
    if l.iter().any(|n| n.is_empty()) {
        return Some(DnsConstraints {
            all: true,
            permitted,
            constraints: None,
            parent_constraints: HashMap::new(),
        });
    }
    let mut set = ConstraintSet { set: l.to_vec() };
    set.sort_and_prune(dns_compare, dns_has_suffix);
    let mut parent_constraints = HashMap::new();
    if !permitted {
        for name in &set.set {
            let name = name.to_lowercase();
            let trimmed = trim_first_label(&name);
            if trimmed.is_empty() {
                continue;
            }
            parent_constraints.insert(trimmed, name);
        }
    }
    Some(DnsConstraints {
        all: false,
        permitted,
        constraints: Some(set),
        parent_constraints,
    })
}

impl DnsConstraints {
    fn query(&self, s: &str) -> Option<String> {
        if self.all {
            return Some(String::new());
        }
        let s_owned = s.to_string();
        if let Some(constraint) = self
            .constraints
            .as_ref()
            .and_then(|c| c.search(&s_owned, dns_compare, dns_search_match))
        {
            return Some(constraint.clone());
        }
        if !self.permitted && s.starts_with('*') {
            let lowered = s.to_lowercase();
            let trimmed = trim_first_label(&lowered);
            if let Some(constraint) = self.parent_constraints.get(&trimmed) {
                return Some(constraint.clone());
            }
        }
        None
    }
}

struct EmailConstraints {
    dns: Option<DnsConstraints>,
    /// Fully specified mailboxes, with the domain lowercased.
    full_emails: HashSet<(String, String)>,
}

fn new_email_constraints(l: &[String], permitted: bool) -> Option<EmailConstraints> {
    if l.is_empty() {
        return None;
    }
    let mut exact = HashSet::new();
    let mut domains = Vec::new();
    for c in l {
        if !c.contains('@') {
            domains.push(c.clone());
            continue;
        }
        let Some(parsed) = parse_rfc2821_mailbox(c) else {
            // Already rejected when parsing; only reachable if the caller
            // mutated the certificate since.
            continue;
        };
        exact.insert((parsed.local, parsed.domain.to_lowercase()));
    }
    let dns = if domains.is_empty() {
        None
    } else {
        new_dns_constraints(&domains, permitted)
    };
    Some(EmailConstraints {
        dns,
        full_emails: exact,
    })
}

impl EmailConstraints {
    fn query(&self, s: &Rfc2821Mailbox) -> Option<String> {
        if !self.full_emails.is_empty()
            && self
                .full_emails
                .contains(&(s.local.clone(), s.domain.clone()))
        {
            return Some(format!("{}@{}", s.local, s.domain));
        }
        self.dns.as_ref()?.query(&s.domain)
    }
}

struct ChainConstraints {
    ip_permitted: Option<IpConstraints>,
    ip_excluded: Option<IpConstraints>,
    dns_permitted: Option<DnsConstraints>,
    dns_excluded: Option<DnsConstraints>,
    uri_permitted: Option<DnsConstraints>,
    uri_excluded: Option<DnsConstraints>,
    email_permitted: Option<EmailConstraints>,
    email_excluded: Option<EmailConstraints>,
    index: usize,
}

struct ParsedUri<'a> {
    uri: &'a Url,
    domain: String,
}

impl ChainConstraints {
    fn check(
        &self,
        dns: &[String],
        uris: &[ParsedUri<'_>],
        emails: &[Rfc2821Mailbox],
        ips: &[Ip],
    ) -> Result<(), Error> {
        for ip in ips {
            let p = quote(&ip.to_string());
            if let Some(permitted) = &self.ip_permitted {
                if permitted.query(ip).is_none() {
                    return Err(Error::new(format!(
                        "IP address {p} is not permitted by any constraint"
                    )));
                }
            }
            if let Some(excluded) = &self.ip_excluded {
                if let Some(constraint) = excluded.query(ip) {
                    return Err(Error::new(format!(
                        "IP address {p} is excluded by constraint {}",
                        quote(&constraint.to_string())
                    )));
                }
            }
        }
        for d in dns {
            if !domain_name_valid(d, false) {
                return Err(Error::new(format!(
                    "x509: cannot parse dnsName {}",
                    quote(d)
                )));
            }
            check_dns("DNS name", &self.dns_permitted, &self.dns_excluded, d, d)?;
        }
        for u in uris {
            if !domain_name_valid(&u.domain, false) {
                return Err(Error::new(format!(
                    "x509: internal error: URI SAN {} failed to parse",
                    quote(&u.uri.to_string())
                )));
            }
            check_dns(
                "URI",
                &self.uri_permitted,
                &self.uri_excluded,
                &u.domain,
                &u.uri.to_string(),
            )?;
        }
        for e in emails {
            if !domain_name_valid(&e.domain, false) {
                return Err(Error::new(format!(
                    "x509: cannot parse rfc822Name {}",
                    quote(&e.to_string())
                )));
            }
            let p = quote(&e.to_string());
            if let Some(permitted) = &self.email_permitted {
                if permitted.query(e).is_none() {
                    return Err(Error::new(format!(
                        "email address {p} is not permitted by any constraint"
                    )));
                }
            }
            if let Some(excluded) = &self.email_excluded {
                if let Some(constraint) = excluded.query(e) {
                    return Err(Error::new(format!(
                        "email address {p} is excluded by constraint {}",
                        quote(&constraint)
                    )));
                }
            }
        }
        Ok(())
    }
}

fn check_dns(
    constraint_type: &str,
    permitted: &Option<DnsConstraints>,
    excluded: &Option<DnsConstraints>,
    s: &str,
    p: &str,
) -> Result<(), Error> {
    if let Some(permitted) = permitted {
        if permitted.query(s).is_none() {
            return Err(Error::new(format!(
                "{constraint_type} {} is not permitted by any constraint",
                quote(p)
            )));
        }
    }
    if let Some(excluded) = excluded {
        if let Some(constraint) = excluded.query(s) {
            return Err(Error::new(format!(
                "{constraint_type} {} is excluded by constraint {}",
                quote(p),
                quote(&constraint)
            )));
        }
    }
    Ok(())
}

/// Go's `checkChainConstraints`: checks every name in the chain against the
/// name constraints of the certificates above it.
pub(crate) fn check_chain_constraints<C: AsRef<Certificate>>(chain: &[C]) -> Result<(), Error> {
    let mut all: Vec<ChainConstraints> = Vec::new();
    for (i, c) in chain.iter().enumerate() {
        let c = c.as_ref();
        if !c.has_name_constraints() {
            continue;
        }
        all.push(ChainConstraints {
            ip_permitted: new_ip_net_constraints(&c.permitted_ip_ranges),
            ip_excluded: new_ip_net_constraints(&c.excluded_ip_ranges),
            dns_permitted: new_dns_constraints(&c.permitted_dns_domains, true),
            dns_excluded: new_dns_constraints(&c.excluded_dns_domains, false),
            uri_permitted: new_dns_constraints(&c.permitted_uri_domains, true),
            uri_excluded: new_dns_constraints(&c.excluded_uri_domains, false),
            email_permitted: new_email_constraints(&c.permitted_email_addresses, true),
            email_excluded: new_email_constraints(&c.excluded_email_addresses, false),
            index: i,
        });
    }
    if all.is_empty() {
        return Ok(());
    }

    let mut current = 0usize;
    for (i, c) in chain.iter().enumerate() {
        let c = c.as_ref();
        if !c.has_san_extension() {
            continue;
        }
        if i >= all[current].index {
            while all[current].index <= i {
                if current + 1 >= all.len() {
                    return Ok(());
                }
                current += 1;
            }
        }

        let uris = parse_uris(&c.uris)?;
        let emails = parse_mailboxes(&c.email_addresses)?;

        for n in &all[current..] {
            n.check(&c.dns_names, &uris, &emails, &c.ip_addresses)?;
        }
    }

    Ok(())
}

fn parse_uris(uris: &[Url]) -> Result<Vec<ParsedUri<'_>>, Error> {
    let mut parsed = Vec::with_capacity(uris.len());
    for uri in uris {
        let mut host = uri.host.to_lowercase();
        if host.is_empty() {
            return Err(Error::new(format!(
                "URI with empty host ({}) cannot be matched against constraints",
                quote(&uri.to_string())
            )));
        }
        if host.contains(':') && !host.ends_with(']') {
            match split_host_port(&uri.host) {
                Ok((h, _)) => host = h,
                Err(e) => {
                    return Err(Error::new(format!(
                        "cannot parse URI host {}: {e}",
                        quote(&uri.host)
                    )))
                }
            }
        }

        // netip.ParseAddr rejects the URI IPv6 literal form "[...]", so check
        // if either the string parses as an IP, or if it is enclosed in square
        // brackets.
        if super::net::parse_addr(&host).is_some() || (host.starts_with('[') && host.ends_with(']'))
        {
            return Err(Error::new(format!(
                "URI with IP ({}) cannot be matched against constraints",
                quote(&uri.to_string())
            )));
        }

        parsed.push(ParsedUri { uri, domain: host });
    }
    Ok(parsed)
}

/// Go's `net.SplitHostPort`, with its error texts.
fn split_host_port(hostport: &str) -> Result<(String, String), String> {
    const MISSING_PORT: &str = "missing port in address";
    const TOO_MANY_COLONS: &str = "too many colons in address";
    let err = |addr: &str, why: &str| format!("address {addr}: {why}");
    let (host, port);
    let i = hostport
        .rfind(':')
        .ok_or_else(|| err(hostport, MISSING_PORT))?;
    if hostport.starts_with('[') {
        let end = hostport
            .find(']')
            .ok_or_else(|| err(hostport, "missing ']' in address"))?;
        if end + 1 == hostport.len() {
            return Err(err(hostport, MISSING_PORT));
        } else if end + 1 == i {
            // Expected.
        } else if hostport.as_bytes()[end + 1] == b':' {
            return Err(err(hostport, TOO_MANY_COLONS));
        } else {
            return Err(err(hostport, MISSING_PORT));
        }
        host = &hostport[1..end];
        port = &hostport[i + 1..];
        if host.contains('[') || host.contains(']') {
            return Err(err(hostport, "unexpected '[' in address"));
        }
        if port.contains('[') {
            return Err(err(hostport, "unexpected '[' in address"));
        }
        if port.contains(']') {
            return Err(err(hostport, "unexpected ']' in address"));
        }
    } else {
        host = &hostport[..i];
        if host.contains(':') {
            return Err(err(hostport, TOO_MANY_COLONS));
        }
        port = &hostport[i + 1..];
        if host.contains('[') {
            return Err(err(hostport, "unexpected '[' in address"));
        }
        if host.contains(']') {
            return Err(err(hostport, "unexpected ']' in address"));
        }
        if port.contains('[') {
            return Err(err(hostport, "unexpected '[' in address"));
        }
        if port.contains(']') {
            return Err(err(hostport, "unexpected ']' in address"));
        }
    }
    Ok((host.to_string(), port.to_string()))
}

fn parse_mailboxes(emails: &[String]) -> Result<Vec<Rfc2821Mailbox>, Error> {
    let mut parsed = Vec::with_capacity(emails.len());
    for email in emails {
        let Some(mut mailbox) = parse_rfc2821_mailbox(email) else {
            return Err(Error::new(format!(
                "cannot parse rfc822Name {}",
                quote(email)
            )));
        };
        mailbox.domain = mailbox.domain.to_lowercase();
        parsed.push(mailbox);
    }
    Ok(parsed)
}

fn trim_first_label(dns_name: &str) -> String {
    match dns_name.find('.') {
        // The constraint is a single label, which cannot be trimmed.
        None => String::new(),
        Some(i) => dns_name[i..].to_string(),
    }
}
