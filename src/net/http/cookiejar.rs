//! Go's `net/http/cookiejar`: an RFC 6265 cookie jar keyed by the eTLD+1 of
//! each host, with the same storage, matching and ordering rules as Go.
//!
//! The jar is safe for concurrent use. Times are nanoseconds since the Unix
//! epoch, compared as Go compares `time.Time`. Cookies are
//! [`Cookie`] values; the jar stores a cookie's name,
//! value, `quoted` flag, domain, path, expiry and `secure` flag, as Go does.
//!
//! Hosts with non-ASCII labels are converted with Punycode (RFC 3492) as Go
//! does. The IDNA mapping that Go's `golang.org/x/net/idna` applies is not
//! performed, so case folding of non-ASCII labels is not done.
use crate::net::http::Cookie;
use crate::net::url::Url;
use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt;
use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

/// Public suffix lookup that determines whether a server may set a cookie for
/// a domain. Implementations must be safe for concurrent use.
///
/// An implementation that always returns "" is valid for testing, but it lets
/// a server for `foo.com` set a cookie for `bar.com`.
pub trait PublicSuffixList: fmt::Display + Send + Sync {
    /// Returns the public suffix of `domain`, for example "co.uk" for
    /// "foo1.foo2.foo3.co.uk".
    fn public_suffix(&self, domain: &str) -> String;
}

/// Options for [`Jar::new`]. The default has no public suffix list, which
/// lets any server set a cookie for any domain it can name.
#[derive(Default)]
pub struct Options {
    /// The public suffix list that determines whether a server can set a
    /// cookie for a domain.
    pub public_suffix_list: Option<Box<dyn PublicSuffixList>>,
}

/// Go's `entry`: one stored cookie.
#[derive(Clone, Debug)]
struct Entry {
    name: String,
    value: String,
    quoted: bool,
    domain: String,
    path: String,
    secure: bool,
    host_only: bool,
    persistent: bool,
    /// Nanoseconds since the Unix epoch.
    expires: i128,
    creation: i128,
    seq: u64,
}

impl Entry {
    /// The domain;path;name triple that identifies a cookie.
    fn id(&self) -> String {
        format!("{};{};{}", self.domain, self.path, self.name)
    }

    fn should_send(&self, https: bool, host: &str, path: &str) -> bool {
        self.domain_match(host) && self.path_match(path) && self.secure_match(https)
    }

    fn domain_match(&self, host: &str) -> bool {
        self.domain == host || (!self.host_only && has_dot_suffix(host, &self.domain))
    }

    fn path_match(&self, request_path: &str) -> bool {
        if request_path == self.path {
            return true;
        }
        request_path.starts_with(&self.path)
            && (self.path.ends_with('/')
                || request_path.as_bytes().get(self.path.len()) == Some(&b'/'))
    }

    fn secure_match(&self, https: bool) -> bool {
        !self.secure || https || is_localhost(&self.domain) || is_loopback(&self.domain)
    }
}

#[derive(Default)]
struct State {
    /// Entries keyed by jar key, then by [`Entry::id`].
    entries: HashMap<String, HashMap<String, Entry>>,
    next_seq: u64,
}

/// A cookie jar that implements `http.CookieJar` with Go's semantics.
#[derive(Default)]
pub struct Jar {
    psl: Option<Box<dyn PublicSuffixList>>,
    state: Mutex<State>,
}

/// Unix nanoseconds of 9999-12-31T23:59:59Z, Go's `endOfTime`.
const END_OF_TIME: i128 = 253_402_300_799 * NANOS;

const NANOS: i128 = 1_000_000_000;

impl Jar {
    /// Returns a new jar. `None` is equivalent to the default [`Options`].
    pub fn new(options: Option<Options>) -> Result<Self, Infallible> {
        Ok(Self {
            psl: options.and_then(|options| options.public_suffix_list),
            state: Mutex::default(),
        })
    }

    /// Returns the cookies to send with a request to `url`, longest path
    /// first, then by creation time.
    pub fn cookies(&self, url: &Url) -> Vec<Cookie> {
        self.cookies_at(url, now_nanos())
    }

    /// Stores the cookies that `url` sets. Invalid cookies are ignored, as in
    /// Go.
    pub fn set_cookies(&self, url: &Url, cookies: &[Cookie]) {
        self.set_cookies_at(url, cookies, now_nanos());
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// [`Jar::cookies`] at an explicit time, in nanoseconds since the Unix
    /// epoch (Go's unexported `cookies(u, now)`).
    #[doc(hidden)]
    pub fn cookies_at(&self, url: &Url, now: i128) -> Vec<Cookie> {
        if url.scheme != "http" && url.scheme != "https" {
            return Vec::new();
        }
        let Some(host) = canonical_host(&url.host) else {
            return Vec::new();
        };
        let key = self.jar_key(&host);
        let https = url.scheme == "https";
        let path = if url.path.is_empty() {
            "/"
        } else {
            url.path.as_str()
        };

        let mut guard = self.lock();
        let state = &mut *guard;
        let Some(submap) = state.entries.get_mut(&key) else {
            return Vec::new();
        };
        submap.retain(|_, entry| !(entry.persistent && entry.expires <= now));
        let mut selected: Vec<&Entry> = submap
            .values()
            .filter(|entry| entry.should_send(https, &host, path))
            .collect();
        selected.sort_by(|a, b| {
            b.path
                .cmp(&a.path)
                .then(a.creation.cmp(&b.creation))
                .then(a.seq.cmp(&b.seq))
        });
        let cookies = selected
            .into_iter()
            .map(|entry| Cookie {
                name: entry.name.clone(),
                value: entry.value.clone(),
                quoted: entry.quoted,
                ..Cookie::default()
            })
            .collect();
        if submap.is_empty() {
            state.entries.remove(&key);
        }
        cookies
    }

    /// [`Jar::set_cookies`] at an explicit time, in nanoseconds since the Unix
    /// epoch (Go's unexported `setCookies(u, cookies, now)`).
    #[doc(hidden)]
    pub fn set_cookies_at(&self, url: &Url, cookies: &[Cookie], now: i128) {
        if cookies.is_empty() || (url.scheme != "http" && url.scheme != "https") {
            return;
        }
        let Some(host) = canonical_host(&url.host) else {
            return;
        };
        let key = self.jar_key(&host);
        let def_path = default_path(&url.path);

        let mut guard = self.lock();
        let state = &mut *guard;
        for cookie in cookies {
            let Ok((mut entry, remove)) = self.new_entry(cookie, now, def_path, &host) else {
                continue;
            };
            let id = entry.id();
            if remove {
                if let Some(submap) = state.entries.get_mut(&key) {
                    submap.remove(&id);
                }
                continue;
            }
            let submap = state.entries.entry(key.clone()).or_default();
            match submap.get(&id) {
                Some(old) => {
                    entry.creation = old.creation;
                    entry.seq = old.seq;
                }
                None => {
                    entry.creation = now;
                    entry.seq = state.next_seq;
                    state.next_seq += 1;
                }
            }
            submap.insert(id, entry);
        }
        if state.entries.get(&key).is_some_and(HashMap::is_empty) {
            state.entries.remove(&key);
        }
    }

    /// Go's `newEntry`. Returns the entry and whether it deletes an existing
    /// cookie; `Err` means the cookie is ignored.
    fn new_entry(
        &self,
        cookie: &Cookie,
        now: i128,
        def_path: &str,
        host: &str,
    ) -> Result<(Entry, bool), ()> {
        let path = if cookie.path.starts_with('/') {
            cookie.path.as_str()
        } else {
            def_path
        };
        let (domain, host_only) = self.domain_and_type(host, &cookie.domain)?;
        let (expires, persistent, remove) = match cookie.max_age {
            age if age < 0 => (0, false, true),
            age if age > 0 => (now.saturating_add(i128::from(age) * NANOS), true, false),
            _ if cookie.expires.is_zero() => (END_OF_TIME, false, false),
            _ => {
                let expiry = i128::from(cookie.expires.unix()) * NANOS
                    + i128::from(cookie.expires.nanosecond());
                (expiry, true, expiry <= now)
            }
        };
        let entry = Entry {
            name: cookie.name.clone(),
            value: cookie.value.clone(),
            quoted: cookie.quoted,
            domain,
            path: path.to_owned(),
            secure: cookie.secure,
            host_only,
            persistent,
            expires,
            creation: 0,
            seq: 0,
        };
        Ok((entry, remove))
    }

    /// Go's `domainAndType`: the cookie domain and whether it is host-only.
    fn domain_and_type(&self, host: &str, domain: &str) -> Result<(String, bool), ()> {
        if domain.is_empty() {
            return Ok((host.to_owned(), true));
        }
        if is_ip(host) {
            return if host == domain {
                Ok((host.to_owned(), true))
            } else {
                Err(())
            };
        }
        let domain = domain.strip_prefix('.').unwrap_or(domain);
        if domain.is_empty() || domain.starts_with('.') || !domain.is_ascii() {
            return Err(());
        }
        let domain = domain.to_ascii_lowercase();
        if domain.ends_with('.') {
            return Err(());
        }
        if let Some(psl) = &self.psl {
            let suffix = psl.public_suffix(&domain);
            if !suffix.is_empty() && !has_dot_suffix(&domain, &suffix) {
                return if host == domain {
                    Ok((host.to_owned(), true))
                } else {
                    Err(())
                };
            }
        }
        if host != domain && !has_dot_suffix(host, &domain) {
            return Err(());
        }
        Ok((domain, false))
    }

    /// Go's `jarKey`: the eTLD+1 of `host`, or the host itself for IP
    /// addresses and public suffixes.
    fn jar_key(&self, host: &str) -> String {
        if is_ip(host) {
            return host.to_owned();
        }
        let dot = match &self.psl {
            None => match host.rfind('.') {
                Some(dot) if dot > 0 => dot,
                _ => return host.to_owned(),
            },
            Some(psl) => {
                let suffix = psl.public_suffix(host);
                if suffix == host {
                    return host.to_owned();
                }
                match host.len().checked_sub(suffix.len()) {
                    Some(start) if start > 0 && host.as_bytes()[start - 1] == b'.' => start,
                    _ => return host.to_owned(),
                }
            }
        };
        let prev_dot = host[..dot - 1].rfind('.').map_or(0, |index| index + 1);
        host[prev_dot..].to_owned()
    }
}

impl fmt::Debug for Jar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Jar").finish_non_exhaustive()
    }
}

fn now_nanos() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos() as i128)
}

/// Go's `hasDotSuffix`: `s` ends in "." followed by `suffix`.
fn has_dot_suffix(s: &str, suffix: &str) -> bool {
    s.len() > suffix.len()
        && s.strip_suffix(suffix)
            .is_some_and(|rest| rest.ends_with('.'))
}

fn is_localhost(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    let label = host.rsplit_once('.').map_or(host, |(_, label)| label);
    label.eq_ignore_ascii_case("localhost")
}

fn is_loopback(host: &str) -> bool {
    let address = match host.split_once('%') {
        Some((address, _zone)) if address.contains(':') => address,
        Some(_) => return false,
        None => host,
    };
    match address.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => ip.is_loopback(),
        Ok(IpAddr::V6(ip)) => ip
            .to_ipv4_mapped()
            .map_or_else(|| ip.is_loopback(), |mapped| mapped.is_loopback()),
        Err(_) => false,
    }
}

fn is_ip(host: &str) -> bool {
    host.contains([':', '%']) || host.parse::<IpAddr>().is_ok()
}

/// Go's `defaultPath`: the directory of the request path.
fn default_path(path: &str) -> &str {
    if !path.starts_with('/') {
        return "/";
    }
    match path.rfind('/') {
        None | Some(0) => "/",
        Some(index) => &path[..index],
    }
}

/// Go's `hasPort`.
fn has_port(host: &str) -> bool {
    match host.matches(':').count() {
        0 => false,
        1 => true,
        _ => host.starts_with('[') && host.contains("]:"),
    }
}

/// Go's `net.SplitHostPort`, restricted to the forms `has_port` accepts.
fn split_host_port(hostport: &str) -> Option<&str> {
    let colon = hostport.rfind(':')?;
    let host = if hostport.starts_with('[') {
        let end = hostport.find(']')?;
        let rest = hostport.strip_prefix('[').unwrap_or(hostport);
        if end + 1 != colon || rest.contains('[') || hostport[end + 1..].contains(']') {
            return None;
        }
        &hostport[1..end]
    } else {
        let host = &hostport[..colon];
        if host.contains(':') || hostport.contains(['[', ']']) {
            return None;
        }
        host
    };
    Some(host)
}

/// Go's `canonicalHost`: the lower-case ASCII host without port or trailing dot.
fn canonical_host(host: &str) -> Option<String> {
    let host = if has_port(host) {
        split_host_port(host)?
    } else {
        host
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    let encoded = to_ascii(host)?;
    Some(encoded.to_ascii_lowercase())
}

/// Go's `toASCII`: converts each non-ASCII label to its Punycode form.
pub(crate) fn to_ascii(s: &str) -> Option<String> {
    if s.is_ascii() {
        return Some(s.to_owned());
    }
    let labels: Option<Vec<String>> = s
        .split('.')
        .map(|label| {
            if label.is_ascii() {
                Some(label.to_owned())
            } else {
                punycode_encode(label)
            }
        })
        .collect();
    labels.map(|labels| labels.join("."))
}

const BASE: i32 = 36;
const DAMP: i32 = 700;
const INITIAL_BIAS: i32 = 72;
const INITIAL_N: i32 = 128;
const SKEW: i32 = 38;
const TMAX: i32 = 26;
const TMIN: i32 = 1;

/// RFC 3492 section 6.3 with Go's 32-bit arithmetic, so overflow behaves the
/// same way: a negative delta is an error.
fn punycode_encode(label: &str) -> Option<String> {
    let mut output = String::from("xn--");
    let basic = label.chars().filter(char::is_ascii).count() as i32;
    let mut remaining = label.chars().filter(|c| !c.is_ascii()).count() as i32;
    output.extend(label.chars().filter(char::is_ascii));
    if basic > 0 {
        output.push('-');
    }
    let code_points: Vec<i32> = label.chars().map(|c| c as i32).collect();
    let (mut delta, mut n, mut bias, mut h) = (0i32, INITIAL_N, INITIAL_BIAS, basic);
    while remaining != 0 {
        let m = code_points
            .iter()
            .copied()
            .filter(|&r| r >= n)
            .min()
            .unwrap_or(i32::MAX);
        delta = delta.wrapping_add(m.wrapping_sub(n).wrapping_mul(h.wrapping_add(1)));
        if delta < 0 {
            return None;
        }
        n = m;
        for &r in &code_points {
            if r < n {
                delta = delta.wrapping_add(1);
                if delta < 0 {
                    return None;
                }
            } else if r == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = (k - bias).clamp(TMIN, TMAX);
                    if q < t {
                        break;
                    }
                    output.push(encode_digit(t + (q - t) % (BASE - t)));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                output.push(encode_digit(q));
                bias = adapt(delta, h + 1, h == basic);
                delta = 0;
                h += 1;
                remaining -= 1;
            }
        }
        delta = delta.wrapping_add(1);
        n = n.wrapping_add(1);
    }
    Some(output)
}

fn encode_digit(digit: i32) -> char {
    if digit < 26 {
        (b'a' + digit as u8) as char
    } else {
        (b'0' + (digit - 26) as u8) as char
    }
}

/// RFC 3492 section 6.1 bias adaptation.
fn adapt(delta: i32, num_points: i32, first_time: bool) -> i32 {
    let mut delta = if first_time { delta / DAMP } else { delta / 2 };
    delta += delta / num_points;
    let mut k = 0;
    while delta > ((BASE - TMIN) * TMAX) / 2 {
        delta /= BASE - TMIN;
        k += BASE;
    }
    k + (BASE - TMIN + 1) * delta / (delta + SKEW)
}
