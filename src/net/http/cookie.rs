//! Go's `http.Cookie`: parsing and formatting of `Cookie` and `Set-Cookie`
//! lines, `SameSite`, `ParseCookie`, `ParseSetCookie` and `SetCookie`.
use super::handler::ResponseWriter;
use super::header::{valid_header_field_name, BoxError, ErrorString, Header};
use crate::net::textproto::trim_string;
use crate::time::{self, Time};

/// Go's `http.SameSite`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SameSite(pub i32);
pub const SAME_SITE_DEFAULT_MODE: SameSite = SameSite(1);
pub const SAME_SITE_LAX_MODE: SameSite = SameSite(2);
pub const SAME_SITE_STRICT_MODE: SameSite = SameSite(3);
pub const SAME_SITE_NONE_MODE: SameSite = SameSite(4);

/// Go's `http.Cookie`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    /// Whether the value was originally quoted.
    pub quoted: bool,
    pub path: String,
    pub domain: String,
    pub expires: Time,
    pub raw_expires: String,
    /// 0 is unset, negative is "Max-Age: 0", positive is seconds.
    pub max_age: i64,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: SameSite,
    pub partitioned: bool,
    pub raw: String,
    pub unparsed: Vec<String>,
}

const ERR_BLANK_COOKIE: ErrorString = ErrorString("http: blank cookie");
const ERR_EQUAL_NOT_FOUND: ErrorString = ErrorString("http: '=' not found in cookie");
const ERR_INVALID_NAME: ErrorString = ErrorString("http: invalid cookie name");
const ERR_INVALID_VALUE: ErrorString = ErrorString("http: invalid cookie value");
const ERR_NUM_LIMIT: ErrorString = ErrorString("http: number of cookies exceeded limit");
const DEFAULT_COOKIE_MAX_NUM: usize = 3000;

fn is_token(v: &str) -> bool {
    valid_header_field_name(v)
}
fn within_max(n: usize) -> bool {
    n <= DEFAULT_COOKIE_MAX_NUM
}

/// Go's `ParseCookie`: a `Cookie` header line (`a=b; c=d`).
pub fn parse_cookie(line: &str) -> Result<Vec<Cookie>, BoxError> {
    let nparts = line.matches(';').count() + 1;
    if !within_max(nparts) {
        return Err(Box::new(ERR_NUM_LIMIT));
    } else if nparts == 1 && trim_string(line).is_empty() {
        return Err(Box::new(ERR_BLANK_COOKIE));
    }
    let mut cookies = Vec::with_capacity(nparts);
    for s in line.split(';') {
        let s = trim_string(s);
        let Some((name, value)) = s.split_once('=') else {
            return Err(Box::new(ERR_EQUAL_NOT_FOUND));
        };
        if !is_token(name) {
            return Err(Box::new(ERR_INVALID_NAME));
        }
        let Some((value, quoted)) = parse_cookie_value(value, true) else {
            return Err(Box::new(ERR_INVALID_VALUE));
        };
        cookies.push(Cookie {
            name: name.to_owned(),
            value,
            quoted,
            ..Cookie::default()
        });
    }
    Ok(cookies)
}

/// Go's `ParseSetCookie`: one `Set-Cookie` header line.
pub fn parse_set_cookie(line: &str) -> Result<Cookie, BoxError> {
    let mut parts: Vec<String> = trim_string(line).split(';').map(str::to_owned).collect();
    if parts.len() == 1 && parts[0].is_empty() {
        return Err(Box::new(ERR_BLANK_COOKIE));
    }
    parts[0] = trim_string(&parts[0]).to_owned();
    let Some((name, value)) = parts[0].split_once('=') else {
        return Err(Box::new(ERR_EQUAL_NOT_FOUND));
    };
    let name = trim_string(name);
    if !is_token(name) {
        return Err(Box::new(ERR_INVALID_NAME));
    }
    let Some((value, quoted)) = parse_cookie_value(value, true) else {
        return Err(Box::new(ERR_INVALID_VALUE));
    };
    let mut c = Cookie {
        name: name.to_owned(),
        value,
        quoted,
        raw: line.to_owned(),
        ..Cookie::default()
    };
    for part in parts.iter_mut().skip(1) {
        *part = trim_string(part).to_owned();
        if part.is_empty() {
            continue;
        }
        let (attr, val) = part.split_once('=').unwrap_or((part.as_str(), ""));
        if !attr.is_ascii() {
            continue;
        }
        let lower_attr = attr.to_ascii_lowercase();
        let Some((val, _)) = parse_cookie_value(val, false) else {
            c.unparsed.push(part.clone());
            continue;
        };
        match lower_attr.as_str() {
            "samesite" => {
                c.same_site = if !val.is_ascii() {
                    SAME_SITE_DEFAULT_MODE
                } else {
                    match val.to_ascii_lowercase().as_str() {
                        "lax" => SAME_SITE_LAX_MODE,
                        "strict" => SAME_SITE_STRICT_MODE,
                        "none" => SAME_SITE_NONE_MODE,
                        _ => SAME_SITE_DEFAULT_MODE,
                    }
                };
                continue;
            }
            "secure" => {
                c.secure = true;
                continue;
            }
            "httponly" => {
                c.http_only = true;
                continue;
            }
            "domain" => {
                c.domain = val;
                continue;
            }
            "max-age" => {
                let secs = atoi(&val);
                match secs {
                    Some(s) if !(s != 0 && val.starts_with('0')) => {
                        c.max_age = if s <= 0 { -1 } else { s };
                        continue;
                    }
                    _ => {}
                }
            }
            "expires" => {
                c.raw_expires = val.clone();
                let parsed = time::Time::parse(time::RFC1123, &val)
                    .or_else(|_| time::Time::parse("Mon, 02-Jan-2006 15:04:05 MST", &val));
                match parsed {
                    Ok(t) => {
                        c.expires = t.utc();
                        continue;
                    }
                    Err(_) => c.expires = Time::default(),
                }
            }
            "path" => {
                c.path = val;
                continue;
            }
            "partitioned" => {
                c.partitioned = true;
                continue;
            }
            _ => {}
        }
        c.unparsed.push(part.clone());
    }
    Ok(c)
}

/// Go's `strconv.Atoi` on a cookie attribute (64-bit int).
fn atoi(s: &str) -> Option<i64> {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<i64>().ok()
}

/// Go's `readSetCookies`.
pub(crate) fn read_set_cookies(h: &Header) -> Vec<Cookie> {
    let Some(lines) = h.0.get("Set-Cookie") else {
        return Vec::new();
    };
    if !within_max(lines.len()) {
        return Vec::new();
    }
    lines
        .iter()
        .filter_map(|line| parse_set_cookie(line).ok())
        .collect()
}

/// Go's `http.SetCookie`: adds a `Set-Cookie` header when the cookie is valid.
pub fn set_cookie(w: &mut dyn ResponseWriter, cookie: &Cookie) {
    let v = cookie.to_string();
    if !v.is_empty() {
        w.header().add("Set-Cookie", &v);
    }
}

/// Go's `String`: the `Cookie` header form for a request, or the `Set-Cookie`
/// form when attributes are set; "" for an invalid name.
impl std::fmt::Display for Cookie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !is_token(&self.name) {
            return Ok(());
        }
        let mut b = String::with_capacity(self.name.len() + self.value.len() + 110);
        b.push_str(&self.name);
        b.push('=');
        b.push_str(&sanitize_cookie_value(&self.value, self.quoted));
        if !self.path.is_empty() {
            b.push_str("; Path=");
            b.push_str(&sanitize_cookie_path(&self.path));
        }
        if !self.domain.is_empty() {
            if valid_cookie_domain(&self.domain) {
                let d = self.domain.strip_prefix('.').unwrap_or(&self.domain);
                b.push_str("; Domain=");
                b.push_str(d);
            } else {
                crate::log::printf(format_args!(
                    "net/http: invalid Cookie.Domain {:?}; dropping domain attribute",
                    self.domain
                ));
            }
        }
        if valid_cookie_expires(&self.expires) {
            b.push_str("; Expires=");
            b.push_str(&self.expires.utc().format(super::TIME_FORMAT));
        }
        if self.max_age > 0 {
            b.push_str("; Max-Age=");
            b.push_str(&self.max_age.to_string());
        } else if self.max_age < 0 {
            b.push_str("; Max-Age=0");
        }
        if self.http_only {
            b.push_str("; HttpOnly");
        }
        if self.secure {
            b.push_str("; Secure");
        }
        match self.same_site {
            SAME_SITE_NONE_MODE => b.push_str("; SameSite=None"),
            SAME_SITE_LAX_MODE => b.push_str("; SameSite=Lax"),
            SAME_SITE_STRICT_MODE => b.push_str("; SameSite=Strict"),
            _ => {}
        }
        if self.partitioned {
            b.push_str("; Partitioned");
        }
        f.write_str(&b)
    }
}

impl Cookie {
    /// Go's `Valid`.
    pub fn valid(&self) -> Result<(), BoxError> {
        fn err(s: String) -> Result<(), BoxError> {
            Err(s.into())
        }
        if !is_token(&self.name) {
            return err("http: invalid Cookie.Name".into());
        }
        if !self.expires.is_zero() && !valid_cookie_expires(&self.expires) {
            return err("http: invalid Cookie.Expires".into());
        }
        if let Some(b) = self.value.bytes().find(|&b| !valid_cookie_value_byte(b)) {
            return err(format!(
                "http: invalid byte {} in Cookie.Value",
                quote_byte(b)
            ));
        }
        if let Some(b) = self.path.bytes().find(|&b| !valid_cookie_path_byte(b)) {
            return err(format!(
                "http: invalid byte {} in Cookie.Path",
                quote_byte(b)
            ));
        }
        if !self.domain.is_empty() && !valid_cookie_domain(&self.domain) {
            return err("http: invalid Cookie.Domain".into());
        }
        if self.partitioned && !self.secure {
            return err("http: partitioned cookies must be set with Secure".into());
        }
        Ok(())
    }
}

/// Go's `%q` of a byte (a rune formatted as a quoted char).
fn quote_byte(b: u8) -> String {
    match b {
        b'\'' => "'\\''".into(),
        b'\\' => "'\\\\'".into(),
        b'\n' => "'\\n'".into(),
        b'\r' => "'\\r'".into(),
        b'\t' => "'\\t'".into(),
        0x20..=0x7e => format!("'{}'", b as char),
        0..=0x7f => format!("'\\x{b:02x}'"),
        _ => format!("'{}'", char::from(b)),
    }
}

/// Go's `readCookies`: the cookies of every `Cookie` header, optionally only
/// those named `filter`.
pub(crate) fn read_cookies(h: &Header, filter: &str) -> Vec<Cookie> {
    let Some(lines) = h.0.get("Cookie") else {
        return Vec::new();
    };
    if lines.is_empty() {
        return Vec::new();
    }
    let count: usize = lines.iter().map(|l| l.matches(';').count() + 1).sum();
    if !within_max(count) {
        return Vec::new();
    }
    let mut cookies = Vec::new();
    for line in lines {
        let mut line = trim_string(line);
        while !line.is_empty() {
            let (part, rest) = line.split_once(';').unwrap_or((line, ""));
            line = rest;
            let part = trim_string(part);
            if part.is_empty() {
                continue;
            }
            let (name, val) = part.split_once('=').unwrap_or((part, ""));
            let name = trim_string(name);
            if !is_token(name) {
                continue;
            }
            if !filter.is_empty() && filter != name {
                continue;
            }
            let Some((val, quoted)) = parse_cookie_value(val, true) else {
                continue;
            };
            cookies.push(Cookie {
                name: name.to_owned(),
                value: val,
                quoted,
                ..Cookie::default()
            });
        }
    }
    cookies
}

fn valid_cookie_domain(v: &str) -> bool {
    if is_cookie_domain_name(v) {
        return true;
    }
    crate::net::ip::parse_ip(v).is_some() && !v.contains(':')
}

fn valid_cookie_expires(t: &Time) -> bool {
    t.year() >= 1601
}

fn is_cookie_domain_name(s: &str) -> bool {
    if s.is_empty() || s.len() > 255 {
        return false;
    }
    let s = s.strip_prefix('.').unwrap_or(s);
    let mut last = b'.';
    let mut ok = false;
    let mut partlen = 0;
    for c in s.bytes() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' => {
                ok = true;
                partlen += 1;
            }
            b'0'..=b'9' => partlen += 1,
            b'-' => {
                if last == b'.' {
                    return false;
                }
                partlen += 1;
            }
            b'.' => {
                if last == b'.' || last == b'-' || partlen > 63 || partlen == 0 {
                    return false;
                }
                partlen = 0;
            }
            _ => return false,
        }
        last = c;
    }
    !(last == b'-' || partlen > 63) && ok
}

pub(crate) fn sanitize_cookie_name(n: &str) -> String {
    n.replace(['\n', '\r'], "-")
}

pub(crate) fn sanitize_cookie_value(v: &str, quoted: bool) -> String {
    let v = sanitize_or_warn("Cookie.Value", valid_cookie_value_byte, v);
    if v.contains([' ', ',']) || quoted {
        format!("\"{v}\"")
    } else {
        v
    }
}

fn valid_cookie_value_byte(b: u8) -> bool {
    (0x20..0x7f).contains(&b) && b != b'"' && b != b';' && b != b'\\'
}

fn sanitize_cookie_path(v: &str) -> String {
    sanitize_or_warn("Cookie.Path", valid_cookie_path_byte, v)
}

fn valid_cookie_path_byte(b: u8) -> bool {
    (0x20..0x7f).contains(&b) && b != b';'
}

fn sanitize_or_warn(field: &str, valid: fn(u8) -> bool, v: &str) -> String {
    match v.bytes().find(|&b| !valid(b)) {
        None => v.to_owned(),
        Some(b) => {
            crate::log::printf(format_args!(
                "net/http: invalid byte {} in {field}; dropping invalid bytes",
                quote_byte(b)
            ));
            // Only ASCII is kept, so the result stays valid UTF-8.
            v.bytes().filter(|&b| valid(b)).map(char::from).collect()
        }
    }
}

fn parse_cookie_value(raw: &str, allow_double_quote: bool) -> Option<(String, bool)> {
    let mut raw = raw;
    let mut quoted = false;
    if allow_double_quote && raw.len() > 1 && raw.starts_with('"') && raw.ends_with('"') {
        raw = &raw[1..raw.len() - 1];
        quoted = true;
    }
    if !raw.bytes().all(valid_cookie_value_byte) {
        return None;
    }
    Some((raw.to_owned(), quoted))
}

/// Go's `http.CookieJar`.
pub trait CookieJar: Send + Sync {
    /// Handles the cookies a server sent in a reply for `u`.
    fn set_cookies(&self, u: &crate::net::url::Url, cookies: &[Cookie]);
    /// The cookies to send with a request to `u`.
    fn cookies(&self, u: &crate::net::url::Url) -> Vec<Cookie>;
}

impl CookieJar for super::cookiejar::Jar {
    fn set_cookies(&self, u: &crate::net::url::Url, cookies: &[Cookie]) {
        super::cookiejar::Jar::set_cookies(self, u, cookies);
    }
    fn cookies(&self, u: &crate::net::url::Url) -> Vec<Cookie> {
        super::cookiejar::Jar::cookies(self, u)
    }
}
