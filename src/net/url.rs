//! Go's `net/url`: generic URI parsing, resolution and escaping.
//!
//! The behaviour (field splitting, `RawPath`/`RawFragment` bookkeeping, error
//! texts, the `urlstrictcolons` default and the 10000 query-parameter limit) is
//! Go's. Strings are Rust `String`s, so a percent-decoded component that is not
//! valid UTF-8 (for example `%ff` in a path) is stored with U+FFFD replacement
//! characters. The path, fragment and query keep their raw encoded form in
//! `raw_path`, `raw_fragment` and `raw_query`, so `Display` round-trips them;
//! host and userinfo have no raw field, so `http://a%ffb/` prints as
//! `http://a%EF%BF%BDb/` where Go prints `http://a%FFb/`.
//!
//! ```
//! use rust_stdlib::net::url;
//! let u = url::parse("https://user:pw@example.com:8443/a%2Fb?q=x%20y#frag")?;
//! assert_eq!(u.hostname(), "example.com");
//! assert_eq!(u.port(), "8443");
//! assert_eq!(u.escaped_path(), "/a%2Fb");
//! assert_eq!(u.query().get("q"), "x y");
//! assert_eq!(u.redacted(), "https://user:xxxxx@example.com:8443/a%2Fb?q=x%20y#frag");
//! # Ok::<(), url::Error>(())
//! ```
use crate::{
    encoding::{BinaryAppender, BinaryMarshaler, BinaryUnmarshaler},
    path,
    strconv::quote,
};
use std::{collections::BTreeMap, error, fmt};

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
    /// Go's `Timeout`: the wrapped error's `Timeout`, false when it has none.
    /// The wrapped error is classified when it is one of this crate's error
    /// types (`net`, `context`, `url`) or an `io::Error`; an arbitrary user
    /// type with a `timeout` method cannot be found by a downcast.
    pub fn timeout(&self) -> bool {
        classify(&*self.err).is_some_and(|(timeout, _)| timeout)
    }
    /// Go's `Temporary`: the wrapped error's `Temporary`, false when it has
    /// none (see [`timeout`](Self::timeout)).
    pub fn temporary(&self) -> bool {
        classify(&*self.err).is_some_and(|(_, temporary)| temporary)
    }
}

/// `(Timeout(), Temporary())` of `err` when its type has those methods.
fn classify(err: &(dyn error::Error + 'static)) -> Option<(bool, bool)> {
    use crate::net::{DNSError, Error as _, NetError, OpError};
    if let Some(e) = err.downcast_ref::<NetError>() {
        return Some((e.timeout(), e.temporary()));
    }
    if let Some(e) = err.downcast_ref::<OpError>() {
        return Some((e.timeout(), e.temporary()));
    }
    if let Some(e) = err.downcast_ref::<DNSError>() {
        return Some((e.timeout(), e.temporary()));
    }
    if let Some(e) = err.downcast_ref::<Error>() {
        return Some((e.timeout(), e.temporary()));
    }
    if let Some(e) = err.downcast_ref::<crate::context::Error>() {
        return Some((e.timeout(), e.temporary()));
    }
    err.downcast_ref::<std::io::Error>().map(|e| {
        let timeout = e.kind() == std::io::ErrorKind::TimedOut;
        (
            timeout,
            timeout || e.kind() == std::io::ErrorKind::Interrupted,
        )
    })
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.op, quote(&self.url), self.err)
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
        write!(f, "invalid URL escape {}", quote(&self.0))
    }
}
impl error::Error for EscapeError {}

/// Go's `url.InvalidHostError`: the offending character.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidHostError(pub String);
impl fmt::Display for InvalidHostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid character {} in host name", quote(&self.0))
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
    escape_bytes(s.as_bytes(), mode)
}
fn escape_bytes(s: &[u8], mode: Mode) -> String {
    const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Vec::with_capacity(s.len());
    for &c in s {
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
    // The unescaped bytes when they are not valid UTF-8 (Go strings hold any
    // bytes); `username`/`password` then hold the lossy text, and String()
    // re-escapes the original bytes.
    username_raw: Option<Vec<u8>>,
    password_raw: Option<Vec<u8>>,
}
/// Go's `url.User`: a [`Userinfo`] without a password.
pub fn user(username: &str) -> Userinfo {
    Userinfo {
        username: username.into(),
        password: String::new(),
        password_set: false,
        username_raw: None,
        password_raw: None,
    }
}
/// Go's `url.UserPassword`.
pub fn user_password(username: &str, password: &str) -> Userinfo {
    Userinfo {
        username: username.into(),
        password: password.into(),
        password_set: true,
        username_raw: None,
        password_raw: None,
    }
}
/// A user name or password from `bytes`, keeping them when not valid UTF-8.
fn raw_part(bytes: Vec<u8>) -> (String, Option<Vec<u8>>) {
    match String::from_utf8(bytes) {
        Ok(s) => (s, None),
        Err(e) => {
            let text = String::from_utf8_lossy(e.as_bytes()).into_owned();
            (text, Some(e.into_bytes()))
        }
    }
}
impl Userinfo {
    /// The user name; bytes that are not valid UTF-8 read as U+FFFD (see
    /// [`username_bytes`](Self::username_bytes)).
    pub fn username(&self) -> &str {
        &self.username
    }
    /// The exact bytes of the user name.
    pub fn username_bytes(&self) -> &[u8] {
        self.username_raw
            .as_deref()
            .filter(|b| String::from_utf8_lossy(b) == self.username)
            .unwrap_or(self.username.as_bytes())
    }
    /// The exact bytes of the password, if set.
    pub fn password_bytes(&self) -> Option<&[u8]> {
        self.password_set.then(|| {
            self.password_raw
                .as_deref()
                .filter(|b| String::from_utf8_lossy(b) == self.password)
                .unwrap_or(self.password.as_bytes())
        })
    }
    /// The password and whether it was set (Go's `(string, bool)`).
    pub fn password(&self) -> Option<&str> {
        self.password_set.then_some(self.password.as_str())
    }
}
impl fmt::Display for Userinfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&escape_bytes(self.username_bytes(), Mode::UserPassword))?;
        if let Some(password) = self.password_bytes() {
            write!(f, ":{}", escape_bytes(password, Mode::UserPassword))?;
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
    ///
    /// Go strings hold any bytes; a percent-escaped host byte that is not
    /// valid UTF-8 reads here as U+FFFD, while [`Url::host_bytes`] and
    /// `String()` keep the original byte.
    pub host: String,
    /// The unescaped host bytes when they are not valid UTF-8 (used only
    /// while `host` is still their lossy text). Construct with
    /// `..Url::default()`; set `host` and leave this `None`.
    #[doc(hidden)]
    pub host_raw: Option<Vec<u8>>,
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

impl std::str::FromStr for Url {
    type Err = Error;

    /// Go's `Parse`; [`parse`] is the same function.
    fn from_str(raw: &str) -> Result<Url, Error> {
        parse(raw)
    }
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
        (url.host, url.host_raw) = raw_part(host);
    } else if !url.scheme.is_empty() && rest.starts_with('/') {
        url.omit_host = true;
    }
    url.set_path(rest)?;
    Ok(url)
}

type Authority = (Option<Userinfo>, Vec<u8>);

fn parse_authority(scheme: &str, authority: &str) -> Result<Authority, BoxError> {
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
        None => {
            let (username, username_raw) = raw_part(unescape_bytes(userinfo, Mode::UserPassword)?);
            Userinfo {
                username,
                password: String::new(),
                password_set: false,
                username_raw,
                password_raw: None,
            }
        }
        Some((name, password)) => {
            let (username, username_raw) = raw_part(unescape_bytes(name, Mode::UserPassword)?);
            let (password, password_raw) = raw_part(unescape_bytes(password, Mode::UserPassword)?);
            Userinfo {
                username,
                password,
                password_set: true,
                username_raw,
                password_raw,
            }
        }
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
        write!(f, "ParseAddr({}): {}", quote(&self.input), self.msg)?;
        if !self.at.is_empty() {
            write!(f, " (at {})", quote(&self.at))?;
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
fn parse_host(scheme: &str, host: &str) -> Result<Vec<u8>, BoxError> {
    if let Some(open) = host.rfind('[') {
        if open > 0 {
            return Err(msg("invalid IP-literal"));
        }
        let close = host.rfind(']').ok_or_else(|| msg("missing ']' in host"))?;
        let colon_port = &host[close + 1..];
        if !valid_optional_port(colon_port) {
            return Err(msg(format!(
                "invalid port {} after host",
                quote(colon_port)
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
        return Ok(out);
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
                quote(colon_port)
            )));
        }
    }
    Ok(unescape_bytes(host, Mode::Host)?)
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

    /// Go's `URL.Parse`: parse `reference` relative to this URL.
    pub fn parse(&self, reference: &str) -> Result<Url, Error> {
        Ok(self.resolve_reference(&parse(reference)?))
    }

    /// Go's `ResolveReference` (RFC 3986 section 5.2).
    pub fn resolve_reference(&self, reference: &Url) -> Url {
        let mut url = reference.clone();
        if reference.scheme.is_empty() {
            url.scheme = self.scheme.clone();
        }
        if !reference.scheme.is_empty() || !reference.host.is_empty() || reference.user.is_some() {
            let _ = url.set_path(&resolve_path(&reference.escaped_path(), ""));
            return url;
        }
        if !reference.opaque.is_empty() {
            url.user = None;
            url.host.clear();
            url.path.clear();
            return url;
        }
        if reference.path.is_empty() && !reference.force_query && reference.raw_query.is_empty() {
            url.raw_query = self.raw_query.clone();
            if reference.fragment.is_empty() {
                url.fragment = self.fragment.clone();
                url.raw_fragment = self.raw_fragment.clone();
            }
        }
        if reference.path.is_empty() && !self.opaque.is_empty() {
            url.opaque = self.opaque.clone();
            url.user = None;
            url.host.clear();
            url.path.clear();
            return url;
        }
        url.host = self.host.clone();
        url.user = self.user.clone();
        let _ = url.set_path(&resolve_path(
            &self.escaped_path(),
            &reference.escaped_path(),
        ));
        url
    }

    /// Go's `Query`: the parsed `raw_query`, ignoring malformed pairs.
    pub fn query(&self) -> Values {
        parse_query(&self.raw_query).0
    }

    /// Go's `RequestURI`: what goes in an HTTP request line.
    pub fn request_uri(&self) -> String {
        let mut result = self.opaque.clone();
        if result.is_empty() {
            result = self.escaped_path();
            if result.is_empty() {
                result = "/".into();
            }
        } else if result.starts_with("//") {
            result = format!("{}:{result}", self.scheme);
        }
        if self.force_query || !self.raw_query.is_empty() {
            result.push('?');
            result.push_str(&self.raw_query);
        }
        result
    }

    /// Go's `Hostname`: the host without port and without IPv6 brackets.
    pub fn hostname(&self) -> String {
        split_host_port(&self.host).0.into()
    }

    /// Go's `Port`: the port of `host`, or the empty string.
    pub fn port(&self) -> String {
        split_host_port(&self.host).1.into()
    }

    /// Go's `Redacted`: like `to_string` with the password replaced by `xxxxx`.
    pub fn redacted(&self) -> String {
        let mut ru = self.clone();
        if let Some(u) = &self.user {
            if u.password().is_some() {
                let mut redacted = u.clone();
                redacted.password = "xxxxx".into();
                redacted.password_set = true;
                redacted.password_raw = None;
                ru.user = Some(redacted);
            }
        }
        ru.to_string()
    }

    /// Go's `JoinPath`: a copy with `elems` appended to the path. When the
    /// result cannot be re-parsed the path is left unchanged, as in Go.
    pub fn join_path(&self, elems: &[&str]) -> Url {
        self.join_path_checked(elems).0
    }

    fn join_path_checked(&self, elems: &[&str]) -> (Url, Result<(), BoxError>) {
        let mut parts: Vec<String> = vec![self.escaped_path()];
        parts.extend(elems.iter().map(|e| (*e).to_owned()));
        let mut p;
        if !parts[0].starts_with('/') {
            parts[0].insert(0, '/');
            p = path::join(&parts)[1..].to_owned();
        } else {
            p = path::join(&parts);
        }
        if parts.last().is_some_and(|l| l.ends_with('/')) && !p.ends_with('/') {
            p.push('/');
        }
        let mut url = self.clone();
        let result = url.set_path(&p);
        (url, result)
    }

    /// Go's `MarshalBinary`.
    pub fn marshal_binary(&self) -> Result<Vec<u8>, Error> {
        Ok(self.to_string().into_bytes())
    }
    /// Go's `AppendBinary`.
    pub fn append_binary(&self, b: &mut Vec<u8>) -> Result<(), Error> {
        b.extend_from_slice(self.to_string().as_bytes());
        Ok(())
    }
    /// Go's `UnmarshalBinary`: replaces `self` with the parsed text.
    pub fn unmarshal_binary(&mut self, text: &[u8]) -> Result<(), Error> {
        *self = parse(&String::from_utf8_lossy(text))?;
        Ok(())
    }
}

impl BinaryMarshaler for Url {
    fn marshal_binary(&self) -> Result<Vec<u8>, Box<dyn error::Error>> {
        Ok(Url::marshal_binary(self)?)
    }
}
impl BinaryAppender for Url {
    fn append_binary(&self, out: &mut Vec<u8>) -> Result<(), Box<dyn error::Error>> {
        Ok(Url::append_binary(self, out)?)
    }
}
impl BinaryUnmarshaler for Url {
    fn unmarshal_binary(&mut self, data: &[u8]) -> Result<(), Box<dyn error::Error>> {
        Ok(Url::unmarshal_binary(self, data)?)
    }
}

impl Url {
    /// The exact bytes of `host`, including a parsed byte that is not valid
    /// UTF-8.
    pub fn host_bytes(&self) -> &[u8] {
        self.host_raw
            .as_deref()
            .filter(|b| String::from_utf8_lossy(b) == self.host)
            .unwrap_or(self.host.as_bytes())
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
                && !(self.omit_host && self.host.is_empty() && self.user.is_none())
            {
                if !self.host.is_empty() || !self.path.is_empty() || self.user.is_some() {
                    buf.push_str("//");
                }
                if let Some(ui) = &self.user {
                    buf.push_str(&ui.to_string());
                    buf.push('@');
                }
                if !self.host.is_empty() {
                    buf.push_str(&escape_bytes(self.host_bytes(), Mode::Host));
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

/// Go's `resolvePath`: apply `reference` to `base` and remove dot segments.
fn resolve_path(base: &str, reference: &str) -> String {
    let full = if reference.is_empty() {
        base.to_owned()
    } else if !reference.starts_with('/') {
        let i = base.rfind('/').map_or(0, |i| i + 1);
        format!("{}{reference}", &base[..i])
    } else {
        reference.to_owned()
    };
    if full.is_empty() {
        return String::new();
    }
    let mut dst = String::with_capacity(full.len() + 1);
    dst.push('/');
    let mut elem = "";
    let mut remaining = full.as_str();
    let mut found = true;
    let mut first = true;
    while found {
        match remaining.split_once('/') {
            Some((e, r)) => {
                elem = e;
                remaining = r;
            }
            None => {
                elem = remaining;
                remaining = "";
                found = false;
            }
        }
        match elem {
            "." => {
                first = false;
            }
            ".." => {
                match dst[1..].rfind('/') {
                    Some(i) => dst.truncate(i + 1),
                    None => dst.truncate(1),
                }
                first = dst.len() == 1;
            }
            _ => {
                if !first {
                    dst.push('/');
                }
                dst.push_str(elem);
                first = false;
            }
        }
    }
    if elem == "." || elem == ".." {
        dst.push('/');
    }
    if dst.len() > 1 && dst.as_bytes()[1] == b'/' {
        return dst[1..].to_owned();
    }
    dst
}

/// Go's `url.JoinPath`: parse `base` and append `elems` to its path. Parse
/// failures are [`Error`]s; a path that cannot be re-encoded is the bare error.
pub fn join_path(base: &str, elems: &[&str]) -> Result<String, BoxError> {
    let url = parse(base)?;
    match url.join_path_checked(elems) {
        (u, Ok(())) => Ok(u.to_string()),
        (_, Err(e)) => Err(e),
    }
}

/// Go's `url.Values`: query parameters; `encode` sorts by key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Values(pub BTreeMap<String, Vec<String>>);
impl Values {
    pub fn new() -> Self {
        Self::default()
    }
    /// The first value for `key`, or the empty string.
    pub fn get(&self, key: &str) -> &str {
        self.0
            .get(key)
            .and_then(|v| v.first())
            .map_or("", String::as_str)
    }
    /// Replace the values of `key` with `value`.
    pub fn set(&mut self, key: &str, value: &str) {
        self.0.insert(key.into(), vec![value.into()]);
    }
    /// Append `value` to the values of `key`.
    pub fn add(&mut self, key: &str, value: &str) {
        self.0.entry(key.into()).or_default().push(value.into());
    }
    pub fn del(&mut self, key: &str) {
        self.0.remove(key);
    }
    pub fn has(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }
    /// URL-encode as `key=value&...` sorted by key.
    pub fn encode(&self) -> String {
        let mut buf = String::new();
        for (k, vs) in &self.0 {
            let key = query_escape(k);
            for v in vs {
                if !buf.is_empty() {
                    buf.push('&');
                }
                buf.push_str(&key);
                buf.push('=');
                buf.push_str(&query_escape(v));
            }
        }
        buf
    }
}

/// Go's default for the `urlmaxqueryparams` setting.
pub const DEFAULT_MAX_QUERY_PARAMS: usize = 10000;

/// Go's `ParseQuery`: always returns the pairs that could be decoded, plus
/// the first error encountered (see Go for which error wins).
pub fn parse_query(query: &str) -> (Values, Option<BoxError>) {
    parse_query_with_max(query, None)
}

/// [`parse_query`] with Go's `urlmaxqueryparams` budget made explicit: `None`
/// is Go's default (at most [`DEFAULT_MAX_QUERY_PARAMS`] pairs), `Some(0)` is
/// unlimited and `Some(n)` requires fewer than `n` pairs.
pub fn parse_query_with_max(query: &str, max_params: Option<usize>) -> (Values, Option<BoxError>) {
    let mut m = Values::new();
    let params = query.matches('&').count() + 1;
    let within = match max_params {
        None => params <= DEFAULT_MAX_QUERY_PARAMS,
        Some(n) => n == 0 || params < n,
    };
    if !within {
        return (
            m,
            Some(msg("number of URL query parameters exceeded limit")),
        );
    }
    let mut err: Option<BoxError> = None;
    let mut query = query;
    while !query.is_empty() {
        let (key, rest) = query.split_once('&').unwrap_or((query, ""));
        query = rest;
        if key.contains(';') {
            err = Some(msg("invalid semicolon separator in query"));
            continue;
        }
        if key.is_empty() {
            continue;
        }
        let (key, value) = key.split_once('=').unwrap_or((key, ""));
        let key = match query_unescape(key) {
            Ok(k) => k,
            Err(e) => {
                err.get_or_insert(Box::new(e));
                continue;
            }
        };
        let value = match query_unescape(value) {
            Ok(v) => v,
            Err(e) => {
                err.get_or_insert(Box::new(e));
                continue;
            }
        };
        m.0.entry(key).or_default().push(value);
    }
    (m, err)
}
