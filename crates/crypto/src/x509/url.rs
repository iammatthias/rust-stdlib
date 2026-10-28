//! A trimmed copy of the root crate's `net/url` for SAN URIs.
//!
//! `crypto/x509` parses `uniformResourceIdentifier` names with `url.Parse` and
//! prints them with `URL.String`. This crate cannot depend on the root crate
//! (docs/adr/0003), so the parsing and printing code of the root crate's
//! `net::url` is reproduced here without resolution, queries, joins and binary
//! marshaling.
//!
//! Strings are Rust `String`s, so a percent-decoded component that is not valid
//! UTF-8 is stored with U+FFFD replacement characters.
#![allow(dead_code)]

use std::{error, fmt};

/// Go's `%q`.
fn quote_bytes<T: AsRef<[u8]>>(s: T) -> String {
    super::error::quote_bytes(s.as_ref())
}

/// Boxed error value standing in for Go's `error` interface.
pub type BoxError = Box<dyn error::Error + Send + Sync>;

/// Go's `errors.New`.
#[derive(Debug)]
struct Msg(String);
impl fmt::Display for Msg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl error::Error for Msg {}
fn msg(text: impl Into<String>) -> BoxError {
    Box::new(Msg(text.into()))
}

/// Go's `url.Error`: the failing operation, the URL and the underlying error.
#[derive(Debug)]
pub struct Error {
    pub op: String,
    pub url: String,
    pub err: BoxError,
}
impl Error {
    /// Go's `Unwrap`.
    pub fn unwrap(&self) -> &(dyn error::Error + 'static) {
        &*self.err
    }
    /// Go's `Timeout`. The errors this module produces are never timeouts.
    pub fn timeout(&self) -> bool {
        false
    }
    /// Go's `Temporary`. The errors this module produces are never temporary.
    pub fn temporary(&self) -> bool {
        false
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.op, quote_bytes(&self.url), self.err)
    }
}
impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(&*self.err)
    }
}
fn parse_error(url: &str, err: BoxError) -> Error {
    Error {
        op: "parse".into(),
        url: url.into(),
        err,
    }
}

/// Go's `url.EscapeError`: the offending escape sequence. Go's value is a
/// string that may be cut inside a multi-byte character, hence the bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EscapeError(pub Vec<u8>);
impl fmt::Display for EscapeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid URL escape {}", quote_bytes(&self.0))
    }
}
impl error::Error for EscapeError {}

/// Go's `url.InvalidHostError`: the offending character.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidHostError(pub String);
impl fmt::Display for InvalidHostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid character {} in host name", quote_bytes(&self.0))
    }
}
impl error::Error for InvalidHostError {}

enum Unescape {
    Escape(EscapeError),
    Host(InvalidHostError),
}
impl From<Unescape> for BoxError {
    fn from(e: Unescape) -> BoxError {
        match e {
            Unescape::Escape(e) => Box::new(e),
            Unescape::Host(e) => Box::new(e),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Path,
    PathSegment,
    Host,
    Zone,
    UserPassword,
    QueryComponent,
    Fragment,
}

/// Go's `shouldEscape` (RFC 3986 with Go's per-component allowances).
fn should_escape(c: u8, mode: Mode) -> bool {
    if c.is_ascii_alphanumeric() {
        return false;
    }
    if matches!(mode, Mode::Host | Mode::Zone)
        && matches!(
            c,
            b'!' | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'['
                | b']'
                | b'<'
                | b'>'
                | b'"'
        )
    {
        return false;
    }
    match c {
        b'-' | b'_' | b'.' | b'~' => return false,
        b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'?' | b'@' => match mode {
            Mode::Path => return c == b'?',
            Mode::PathSegment => return matches!(c, b'/' | b';' | b',' | b'?'),
            Mode::UserPassword => return matches!(c, b'@' | b'/' | b'?' | b':'),
            Mode::QueryComponent => return true,
            Mode::Fragment => return false,
            Mode::Host | Mode::Zone => {}
        },
        _ => {}
    }
    if mode == Mode::Fragment && matches!(c, b'!' | b'(' | b')' | b'*') {
        return false;
    }
    true
}

fn is_hex(c: u8) -> bool {
    c.is_ascii_hexdigit()
}
fn unhex(c: u8) -> u8 {
    9 * (c >> 6) + (c & 15)
}

/// Go's `unescape`; the decoded bytes are not necessarily UTF-8.
fn unescape_bytes(s: &str, mode: Mode) -> Result<Vec<u8>, Unescape> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                if i + 2 >= b.len() || !is_hex(b[i + 1]) || !is_hex(b[i + 2]) {
                    let end = (i + 3).min(b.len());
                    return Err(Unescape::Escape(EscapeError(b[i..end].to_vec())));
                }
                if mode == Mode::Host && unhex(b[i + 1]) < 8 && &b[i..i + 3] != b"%25" {
                    return Err(Unescape::Escape(EscapeError(b[i..i + 3].to_vec())));
                }
                if mode == Mode::Zone {
                    let v = (unhex(b[i + 1]) << 4) | unhex(b[i + 2]);
                    if &b[i..i + 3] != b"%25" && v != b' ' && should_escape(v, Mode::Host) {
                        return Err(Unescape::Escape(EscapeError(b[i..i + 3].to_vec())));
                    }
                }
                i += 3;
            }
            c => {
                if matches!(mode, Mode::Host | Mode::Zone) && c < 0x80 && should_escape(c, mode) {
                    return Err(Unescape::Host(InvalidHostError((c as char).to_string())));
                }
                i += 1;
            }
        }
    }
    let plus = if mode == Mode::QueryComponent {
        b' '
    } else {
        b'+'
    };
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                out.push((unhex(b[i + 1]) << 4) | unhex(b[i + 2]));
                i += 3;
            }
            b'+' => {
                out.push(plus);
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Ok(out)
}
fn lossy(bytes: Vec<u8>) -> String {
    match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    }
}
fn unescape(s: &str, mode: Mode) -> Result<String, Unescape> {
    unescape_bytes(s, mode).map(lossy)
}
fn public_unescape(s: &str, mode: Mode) -> Result<String, EscapeError> {
    unescape(s, mode).map_err(|e| match e {
        Unescape::Escape(e) => e,
        Unescape::Host(h) => EscapeError(h.0.into_bytes()),
    })
}

/// Go's `QueryUnescape`: `%XX` escapes and `+` as space.
pub fn query_unescape(s: &str) -> Result<String, EscapeError> {
    public_unescape(s, Mode::QueryComponent)
}
/// Go's `PathUnescape`: like [`query_unescape`] but `+` stays a plus.
pub fn path_unescape(s: &str) -> Result<String, EscapeError> {
    public_unescape(s, Mode::PathSegment)
}

fn escape(s: &str, mode: Mode) -> String {
    const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Vec::with_capacity(s.len());
    for &c in s.as_bytes() {
        if c == b' ' && mode == Mode::QueryComponent {
            out.push(b'+');
        } else if should_escape(c, mode) {
            out.push(b'%');
            out.push(UPPER_HEX[(c >> 4) as usize]);
            out.push(UPPER_HEX[(c & 15) as usize]);
        } else {
            out.push(c);
        }
    }
    lossy(out)
}
/// Go's `QueryEscape`: for use in a query string, space becomes `+`.
pub fn query_escape(s: &str) -> String {
    escape(s, Mode::QueryComponent)
}
/// Go's `PathEscape`: for use as one path segment.
pub fn path_escape(s: &str) -> String {
    escape(s, Mode::PathSegment)
}

/// Go's `url.Userinfo`: username and optional password.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Userinfo {
    username: String,
    password: String,
    password_set: bool,
}
/// Go's `url.User`: a [`Userinfo`] without a password.
pub fn user(username: &str) -> Userinfo {
    Userinfo {
        username: username.into(),
        password: String::new(),
        password_set: false,
    }
}
/// Go's `url.UserPassword`.
pub fn user_password(username: &str, password: &str) -> Userinfo {
    Userinfo {
        username: username.into(),
        password: password.into(),
        password_set: true,
    }
}
impl Userinfo {
    pub fn username(&self) -> &str {
        &self.username
    }
    /// The password and whether it was set (Go's `(string, bool)`).
    pub fn password(&self) -> Option<&str> {
        self.password_set.then_some(self.password.as_str())
    }
}
impl fmt::Display for Userinfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&escape(&self.username, Mode::UserPassword))?;
        if self.password_set {
            write!(f, ":{}", escape(&self.password, Mode::UserPassword))?;
        }
        Ok(())
    }
}

/// Go's `url.URL`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Url {
    pub scheme: String,
    /// Encoded opaque data.
    pub opaque: String,
    pub user: Option<Userinfo>,
    /// `host` or `host:port` (see [`Url::hostname`] and [`Url::port`]).
    pub host: String,
    /// Path (relative paths may omit the leading slash).
    pub path: String,
    /// Encoded path hint (see [`Url::escaped_path`]).
    pub raw_path: String,
    /// Do not emit an empty host (authority) for `scheme:///path`.
    pub omit_host: bool,
    /// Append a query (`?`) even if `raw_query` is empty.
    pub force_query: bool,
    /// Encoded query values, without `?`.
    pub raw_query: String,
    /// Fragment for references, without `#`.
    pub fragment: String,
    /// Encoded fragment hint (see [`Url::escaped_fragment`]).
    pub raw_fragment: String,
}

/// Go's `getScheme`: split `scheme:` off the front of `raw`.
fn get_scheme(raw: &str) -> Result<(&str, &str), BoxError> {
    for (i, c) in raw.bytes().enumerate() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                if i == 0 {
                    return Ok(("", raw));
                }
            }
            b':' => {
                if i == 0 {
                    return Err(msg("missing protocol scheme"));
                }
                return Ok((&raw[..i], &raw[i + 1..]));
            }
            _ => return Ok(("", raw)),
        }
    }
    Ok(("", raw))
}

/// Go's `Parse`: a URL, possibly with a `#fragment`, possibly relative.
pub fn parse(raw: &str) -> Result<Url, Error> {
    let (u, frag) = raw.split_once('#').unwrap_or((raw, ""));
    let mut url = parse_inner(u, false).map_err(|e| parse_error(u, e))?;
    if frag.is_empty() {
        return Ok(url);
    }
    url.set_fragment(frag)
        .map_err(|e| parse_error(raw, e.into()))?;
    Ok(url)
}

/// Go's `ParseRequestURI`: an absolute URI or an absolute path, no fragment.
pub fn parse_request_uri(raw: &str) -> Result<Url, Error> {
    parse_inner(raw, true).map_err(|e| parse_error(raw, e))
}

fn parse_inner(raw: &str, via_request: bool) -> Result<Url, BoxError> {
    if raw.bytes().any(|b| b < b' ' || b == 0x7f) {
        return Err(msg("net/url: invalid control character in URL"));
    }
    if raw.is_empty() && via_request {
        return Err(msg("empty url"));
    }
    let mut url = Url::default();
    if raw == "*" {
        url.path = "*".into();
        return Ok(url);
    }
    let (scheme, mut rest) = get_scheme(raw)?;
    url.scheme = scheme.to_ascii_lowercase();
    if rest.ends_with('?') && rest.matches('?').count() == 1 {
        url.force_query = true;
        rest = &rest[..rest.len() - 1];
    } else {
        let (r, q) = rest.split_once('?').unwrap_or((rest, ""));
        rest = r;
        url.raw_query = q.into();
    }
    if !rest.starts_with('/') {
        if !url.scheme.is_empty() {
            url.opaque = rest.into();
            return Ok(url);
        }
        if via_request {
            return Err(msg("invalid URI for request"));
        }
        let segment = rest.split_once('/').map_or(rest, |(s, _)| s);
        if segment.contains(':') {
            return Err(msg("first path segment in URL cannot contain colon"));
        }
    }
    if (!url.scheme.is_empty() || (!via_request && !rest.starts_with("///")))
        && rest.starts_with("//")
    {
        let mut authority = &rest[2..];
        rest = "";
        if let Some(i) = authority.find('/') {
            rest = &authority[i..];
            authority = &authority[..i];
        }
        let (user, host) = parse_authority(&url.scheme, authority)?;
        url.user = user;
        url.host = host;
    } else if !url.scheme.is_empty() && rest.starts_with('/') {
        url.omit_host = true;
    }
    url.set_path(rest)?;
    Ok(url)
}

fn parse_authority(scheme: &str, authority: &str) -> Result<(Option<Userinfo>, String), BoxError> {
    let at = authority.rfind('@');
    let host = parse_host(scheme, at.map_or(authority, |i| &authority[i + 1..]))?;
    let Some(i) = at else {
        return Ok((None, host));
    };
    let userinfo = &authority[..i];
    if !valid_userinfo(userinfo) {
        return Err(msg("net/url: invalid userinfo"));
    }
    let user = match userinfo.split_once(':') {
        None => user(&unescape(userinfo, Mode::UserPassword)?),
        Some((name, password)) => user_password(
            &unescape(name, Mode::UserPassword)?,
            &unescape(password, Mode::UserPassword)?,
        ),
    };
    Ok((Some(user), host))
}

/// The error text and position of `netip.ParseAddr`.
#[derive(Debug)]
struct AddrError {
    input: Vec<u8>,
    msg: &'static str,
    at: Vec<u8>,
}
impl fmt::Display for AddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ParseAddr({}): {}", quote_bytes(&self.input), self.msg)?;
        if !self.at.is_empty() {
            write!(f, " (at {})", quote_bytes(&self.at))?;
        }
        Ok(())
    }
}
impl error::Error for AddrError {}
fn addr_error(input: &[u8], msg: &'static str, at: &[u8]) -> AddrError {
    AddrError {
        input: input.to_vec(),
        msg,
        at: at.to_vec(),
    }
}

/// Go's `parseIPv4Fields`: validates `input[off..end]` as dotted decimal.
fn check_ipv4_fields(input: &[u8], off: usize, end: usize) -> Result<(), AddrError> {
    let s = &input[off..end];
    let (mut val, mut pos, mut dig_len) = (0u32, 0, 0);
    for (i, &c) in s.iter().enumerate() {
        if c.is_ascii_digit() {
            if dig_len == 1 && val == 0 {
                return Err(addr_error(
                    input,
                    "IPv4 field has octet with leading zero",
                    b"",
                ));
            }
            val = val * 10 + u32::from(c - b'0');
            dig_len += 1;
            if val > 255 {
                return Err(addr_error(input, "IPv4 field has value >255", b""));
            }
        } else if c == b'.' {
            if i == 0 || i == s.len() - 1 || s[i - 1] == b'.' {
                return Err(addr_error(
                    input,
                    "IPv4 field must have at least one digit",
                    &s[i..],
                ));
            }
            if pos == 3 {
                return Err(addr_error(input, "IPv4 address too long", b""));
            }
            pos += 1;
            val = 0;
            dig_len = 0;
        } else {
            return Err(addr_error(input, "unexpected character", &s[i..]));
        }
    }
    if pos < 3 {
        return Err(addr_error(input, "IPv4 address too short", b""));
    }
    Ok(())
}

/// Go's `netip.ParseAddr`; returns whether the address is a plain IPv4 one.
fn parse_addr(input: &[u8]) -> Result<bool, AddrError> {
    for &c in input {
        match c {
            b'.' => return check_ipv4_fields(input, 0, input.len()).map(|()| true),
            b':' => return check_ipv6(input).map(|()| false),
            b'%' => return Err(addr_error(input, "missing IPv6 address", b"")),
            _ => {}
        }
    }
    Err(addr_error(input, "unable to parse IP", b""))
}

fn check_ipv6(input: &[u8]) -> Result<(), AddrError> {
    let mut s = input;
    let mut zone_len = 0;
    if let Some(i) = s.iter().position(|&c| c == b'%') {
        zone_len = s.len() - i - 1;
        if zone_len == 0 {
            return Err(addr_error(input, "zone must be a non-empty string", b""));
        }
        s = &s[..i];
    }
    let mut ellipsis: Option<usize> = None;
    if s.len() >= 2 && s[0] == b':' && s[1] == b':' {
        ellipsis = Some(0);
        s = &s[2..];
        if s.is_empty() {
            return Ok(());
        }
    }
    let mut i = 0;
    while i < 16 {
        let mut off = 0;
        let mut acc = 0u32;
        while off < s.len() {
            let c = s[off];
            if !c.is_ascii_hexdigit() {
                break;
            }
            acc = (acc << 4) + u32::from(unhex(c));
            if off > 3 {
                return Err(addr_error(
                    input,
                    "each group must have 4 or less digits",
                    s,
                ));
            }
            if acc > 0xffff {
                return Err(addr_error(input, "IPv6 field has value >=2^16", s));
            }
            off += 1;
        }
        if off == 0 {
            return Err(addr_error(
                input,
                "each colon-separated field must have at least one digit",
                s,
            ));
        }
        if off < s.len() && s[off] == b'.' {
            if ellipsis.is_none() && i != 12 {
                return Err(addr_error(
                    input,
                    "embedded IPv4 address must replace the final 2 fields of the address",
                    s,
                ));
            }
            if i + 4 > 16 {
                return Err(addr_error(
                    input,
                    "too many hex fields to fit an embedded IPv4 at the end of the address",
                    s,
                ));
            }
            let mut end = input.len();
            if zone_len > 0 {
                end -= zone_len + 1;
            }
            check_ipv4_fields(input, end - s.len(), end)?;
            s = b"";
            i += 4;
            break;
        }
        i += 2;
        s = &s[off..];
        if s.is_empty() {
            break;
        }
        if s[0] != b':' {
            return Err(addr_error(input, "unexpected character, want colon", s));
        } else if s.len() == 1 {
            return Err(addr_error(
                input,
                "colon must be followed by more characters",
                s,
            ));
        }
        s = &s[1..];
        if s[0] == b':' {
            if ellipsis.is_some() {
                return Err(addr_error(input, "multiple :: in address", s));
            }
            ellipsis = Some(i);
            s = &s[1..];
            if s.is_empty() {
                break;
            }
        }
    }
    if !s.is_empty() {
        return Err(addr_error(input, "trailing garbage after address", s));
    }
    if i < 16 && ellipsis.is_none() {
        return Err(addr_error(input, "address string too short", b""));
    }
    Ok(())
}

#[derive(Debug)]
struct InvalidHost(AddrError);
impl fmt::Display for InvalidHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid host: {}", self.0)
    }
}
impl error::Error for InvalidHost {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Go's `parseHost`: validates and unescapes `host[:port]` or `[ipv6]:port`.
fn parse_host(scheme: &str, host: &str) -> Result<String, BoxError> {
    if let Some(open) = host.rfind('[') {
        if open > 0 {
            return Err(msg("invalid IP-literal"));
        }
        let close = host.rfind(']').ok_or_else(|| msg("missing ']' in host"))?;
        let colon_port = &host[close + 1..];
        if !valid_optional_port(colon_port) {
            return Err(msg(format!(
                "invalid port {} after host",
                quote_bytes(colon_port)
            )));
        }
        let unescaped_colon_port = unescape_bytes(colon_port, Mode::Host)?;
        let hostname = &host[open + 1..close];
        let unescaped = if let Some(zone) = hostname.find("%25") {
            let mut v = unescape_bytes(&hostname[..zone], Mode::Host)?;
            v.extend(unescape_bytes(&hostname[zone..], Mode::Zone)?);
            v
        } else {
            unescape_bytes(hostname, Mode::Host)?
        };
        let is4 = parse_addr(&unescaped).map_err(|e| Box::new(InvalidHost(e)) as BoxError)?;
        if is4 {
            return Err(msg("invalid IP-literal"));
        }
        let mut out = b"[".to_vec();
        out.extend(unescaped);
        out.push(b']');
        out.extend(unescaped_colon_port);
        return Ok(lossy(out));
    }
    if let Some(first) = host.find(':') {
        let last = host.rfind(':').unwrap_or(first);
        let mut i = first;
        if last != first && scheme != "http" && scheme != "https" {
            // Go's urlstrictcolons=1 default applies to http(s) only.
            i = last;
        }
        let colon_port = &host[i..];
        if !valid_optional_port(colon_port) {
            return Err(msg(format!(
                "invalid port {} after host",
                quote_bytes(colon_port)
            )));
        }
    }
    Ok(unescape(host, Mode::Host)?)
}
impl Url {
    /// Go's unexported `setPath`: decode `p` into `path` and keep `p` in
    /// `raw_path` when the default encoding of `path` would differ.
    fn set_path(&mut self, p: &str) -> Result<(), BoxError> {
        let path = unescape(p, Mode::Path)?;
        self.raw_path = if escape(&path, Mode::Path) == p {
            String::new()
        } else {
            p.into()
        };
        self.path = path;
        Ok(())
    }

    /// The encoded form of `path`, preferring `raw_path` when it is a valid
    /// encoding of it.
    pub fn escaped_path(&self) -> String {
        if !self.raw_path.is_empty() && valid_encoded(&self.raw_path, Mode::Path) {
            if let Ok(p) = unescape(&self.raw_path, Mode::Path) {
                if p == self.path {
                    return self.raw_path.clone();
                }
            }
        }
        if self.path == "*" {
            return "*".into();
        }
        escape(&self.path, Mode::Path)
    }

    fn set_fragment(&mut self, f: &str) -> Result<(), EscapeError> {
        let frag = public_unescape(f, Mode::Fragment)?;
        self.raw_fragment = if escape(&frag, Mode::Fragment) == f {
            String::new()
        } else {
            f.into()
        };
        self.fragment = frag;
        Ok(())
    }

    /// The encoded form of `fragment`, preferring `raw_fragment`.
    pub fn escaped_fragment(&self) -> String {
        if !self.raw_fragment.is_empty() && valid_encoded(&self.raw_fragment, Mode::Fragment) {
            if let Ok(f) = unescape(&self.raw_fragment, Mode::Fragment) {
                if f == self.fragment {
                    return self.raw_fragment.clone();
                }
            }
        }
        escape(&self.fragment, Mode::Fragment)
    }

    /// Go's `IsAbs`: whether the URL has a scheme.
    pub fn is_abs(&self) -> bool {
        !self.scheme.is_empty()
    }

    /// Go's `Hostname`: the host without port and without IPv6 brackets.
    pub fn hostname(&self) -> String {
        split_host_port(&self.host).0.into()
    }

    /// Go's `Port`: the port of `host`, or the empty string.
    pub fn port(&self) -> String {
        split_host_port(&self.host).1.into()
    }
}

impl fmt::Display for Url {
    /// Go's `String`: reassemble the URL.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = String::new();
        if !self.scheme.is_empty() {
            buf.push_str(&self.scheme);
            buf.push(':');
        }
        if !self.opaque.is_empty() {
            buf.push_str(&self.opaque);
        } else {
            if (!self.scheme.is_empty() || !self.host.is_empty() || self.user.is_some())
                && (!self.omit_host || !self.host.is_empty() || self.user.is_some())
            {
                if !self.host.is_empty() || !self.path.is_empty() || self.user.is_some() {
                    buf.push_str("//");
                }
                if let Some(ui) = &self.user {
                    buf.push_str(&ui.to_string());
                    buf.push('@');
                }
                if !self.host.is_empty() {
                    buf.push_str(&escape(&self.host, Mode::Host));
                }
            }
            let mut path = self.escaped_path();
            if self.omit_host
                && self.host.is_empty()
                && self.user.is_none()
                && path.starts_with("//")
            {
                buf.push_str("%2F");
                path.remove(0);
            }
            if !path.is_empty() && !path.starts_with('/') && !self.host.is_empty() {
                buf.push('/');
            }
            if buf.is_empty() {
                let segment = path.split_once('/').map_or(path.as_str(), |(s, _)| s);
                if segment.contains(':') {
                    buf.push_str("./");
                }
            }
            buf.push_str(&path);
        }
        if self.force_query || !self.raw_query.is_empty() {
            buf.push('?');
            buf.push_str(&self.raw_query);
        }
        if !self.fragment.is_empty() {
            buf.push('#');
            buf.push_str(&self.escaped_fragment());
        }
        f.write_str(&buf)
    }
}

/// Go's `validEncoded`: whether `s` contains only characters allowed
/// unescaped in `mode`, plus the sub-delimiters Go accepts in `RawPath`.
fn valid_encoded(s: &str, mode: Mode) -> bool {
    s.bytes().all(|c| match c {
        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' | b':'
        | b'@' | b'[' | b']' | b'%' => true,
        _ => !should_escape(c, mode),
    })
}

/// Go's `validOptionalPort`: empty, or `:` followed by digits.
fn valid_optional_port(port: &str) -> bool {
    match port.strip_prefix(':') {
        None => port.is_empty(),
        Some(digits) => digits.bytes().all(|b| b.is_ascii_digit()),
    }
}

fn split_host_port(host_port: &str) -> (&str, &str) {
    let mut host = host_port;
    let mut port = "";
    if let Some(colon) = host.rfind(':') {
        if valid_optional_port(&host[colon..]) {
            port = &host[colon + 1..];
            host = &host[..colon];
        }
    }
    if host.starts_with('[') && host.ends_with(']') && host.len() >= 2 {
        host = &host[1..host.len() - 1];
    }
    (host, port)
}

fn valid_userinfo(s: &str) -> bool {
    s.bytes().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                b'-' | b'.'
                    | b'_'
                    | b':'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b'%'
                    | b'@'
            )
    })
}
