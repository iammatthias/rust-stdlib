//! Go's `http.Transport`: connection pooling, proxies (HTTP, CONNECT and
//! SOCKS5), TLS through a backend hook, `Expect: 100-continue`, transparent
//! gzip, cancellation, retries of replayable requests, `ClientConn`, and the
//! file transport.
//!
//! One request is in flight per HTTP/1.1 connection. Request bodies are
//! written by a helper thread while the caller reads the response, as Go's
//! write and read loops do. HTTP/2 connections (negotiated with ALPN `h2`,
//! or used directly with prior knowledge when `Protocols` asks for
//! unencrypted HTTP/2 without HTTP/1) multiplex requests through
//! `super::h2::transport`; `ForceAttemptHTTP2`, `HTTP2`, `Protocols` and
//! `TLSNextProto` select and configure them as in Go.
#![allow(clippy::type_complexity)]
use super::body::{Body, NoBody, ReadCloser};
use super::client::{basic_auth, RoundTripper, TimeoutError};
use super::fs::FileSystem;
use super::handler::{Handler, ResponseWriter};
use super::header::{
    has_token, valid_header_field_name, valid_header_field_value, BoxError, ErrorString, Header,
    Http2Config, Protocols, ERR_SKIP_ALT_PROTOCOL,
};
use super::httptrace::{self, ClientTrace};
use super::request::Request;
use super::response::{is_protocol_switch_header, read_response, Response};
use super::server::SharedConn;
use super::status::*;
use super::tlsstate::{ConnectionState, TlsConfig};
use super::transfer::BufioReader;
use crate::context::{self, CancelCauseFunc, Context};
use crate::net::url::{self, Url};
use crate::net::{self, Conn, Dialer};
use crate::time::{self, Duration, Time};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    fmt,
    io::{self, Read, Write},
    sync::{
        atomic::{AtomicBool, AtomicI64, Ordering},
        mpsc::{channel, Receiver, RecvTimeoutError, Sender},
        Arc, Condvar, LazyLock, Mutex, MutexGuard, OnceLock, RwLock, Weak,
    },
    time::{Duration as StdDuration, Instant},
};

/// Go's `DefaultMaxIdleConnsPerHost`.
pub const DEFAULT_MAX_IDLE_CONNS_PER_HOST: i64 = 2;

pub type ProxyFn = Arc<dyn Fn(&Request) -> Result<Option<Url>, BoxError> + Send + Sync>;
pub type DialContextFn =
    Arc<dyn Fn(&Context, &str, &str) -> Result<Box<dyn Conn>, BoxError> + Send + Sync>;
pub type DialFn = Arc<dyn Fn(&str, &str) -> Result<Box<dyn Conn>, BoxError> + Send + Sync>;
pub type OnProxyConnectResponseFn =
    Arc<dyn Fn(&Context, &Url, &Request, &Response) -> Result<(), BoxError> + Send + Sync>;
pub type GetProxyConnectHeaderFn =
    Arc<dyn Fn(&Context, &Url, &str) -> Result<Header, BoxError> + Send + Sync>;
/// `Transport.TLSNextProto` values: given the authority and the negotiated
/// connection, the `RoundTripper` that serves requests on it.
pub type TlsNextProtoRtFn = Arc<dyn Fn(&str, Box<dyn Conn>) -> Arc<dyn RoundTripper> + Send + Sync>;

const ERR_REQUEST_CANCELED: ErrorString = ErrorString("net/http: request canceled");
const ERR_REQUEST_CANCELED_CONN: ErrorString =
    ErrorString("net/http: request canceled while waiting for connection");
pub(crate) const ERR_TIMEOUT: &str = "net/http: timeout awaiting response headers";
const ERR_CANNOT_REWIND: ErrorString =
    ErrorString("net/http: cannot rewind body after connection loss");
const ERR_KEEP_ALIVES_DISABLED: &str = "http: putIdleConn: keep alives disabled";
const ERR_TLS_BACKEND: ErrorString = ErrorString(
    "http: https requests need Transport.TLSClientConfig from a TLS backend (rust-stdlib-tls)",
);

/// Go's `http.Transport`.
///
/// # TCP keep-alive
///
/// Go's `DefaultTransport` dials with `KeepAlive: 30 * time.Second`. Setting
/// `SO_KEEPALIVE` needs a system call `std` lacks, so the root crate's
/// [`Dialer`] has no keep-alive option and the default transport dials
/// without one. The `rust-stdlib-sysnet` crate (`backends/sysnet`, ADR 0006)
/// provides this: its `default_transport()` and `default_client()` mirror Go's
/// defaults with the 30 s keep-alive, and its `dial_context` wraps any sys
/// `Dialer`. To do it by hand, plug a
/// `rust_stdlib_sys::net::Dialer` into [`Transport::dial_context`] (Go's
/// `Transport.DialContext`), wrapping the connection it returns in a type
/// that implements [`Conn`] (the sys crate's connection types do not; the
/// adapter maps read/write/close/deadlines and `OpError` to `NetError`, as
/// `rust-stdlib-tls`'s connection does for its TLS type):
///
/// ```ignore
/// use rust_stdlib_sys::net::Dialer as SysDialer;
///
/// let sys = SysDialer {
///     timeout: 30_000_000_000,
///     keep_alive: 30_000_000_000, // Go's DefaultTransport value, in ns
///     ..SysDialer::default()
/// };
/// let transport = Transport {
///     dial_context: Some(Arc::new(move |_ctx, network, addr| {
///         let conn = sys.dial(network, addr).map_err(|e| Box::new(e) as BoxError)?;
///         // `SysConn` stands for that adapter, written by the caller.
///         Ok(Box::new(SysConn::new(conn)) as Box<dyn Conn>)
///     })),
///     ..Transport::default()
/// };
/// ```
#[derive(Clone)]
pub struct Transport {
    pub proxy: Option<ProxyFn>,
    pub on_proxy_connect_response: Option<OnProxyConnectResponseFn>,
    pub dial_context: Option<DialContextFn>,
    pub dial: Option<DialFn>,
    pub dial_tls_context: Option<DialContextFn>,
    pub dial_tls: Option<DialFn>,
    pub tls_client_config: Option<Arc<dyn TlsConfig>>,
    pub tls_handshake_timeout: Duration,
    pub disable_keep_alives: bool,
    pub disable_compression: bool,
    pub max_idle_conns: i64,
    pub max_idle_conns_per_host: i64,
    pub max_conns_per_host: i64,
    pub idle_conn_timeout: Duration,
    pub response_header_timeout: Duration,
    pub expect_continue_timeout: Duration,
    pub tls_next_proto: Option<BTreeMap<String, TlsNextProtoRtFn>>,
    pub proxy_connect_header: Header,
    pub get_proxy_connect_header: Option<GetProxyConnectHeaderFn>,
    pub max_response_header_bytes: i64,
    pub write_buffer_size: i64,
    pub read_buffer_size: i64,
    pub force_attempt_http2: bool,
    pub http2: Option<Http2Config>,
    pub protocols: Option<Protocols>,
    /// Connection pool and registered protocols, shared by clones; leave it
    /// at its default (`..Transport::default()`).
    pub state: Arc<TransportState>,
}

/// The pool and alternate protocols behind a [`Transport`]. Opaque: it
/// exists so every `Transport` field is public and struct-update syntax
/// works.
#[derive(Default)]
pub struct TransportState {
    core: OnceLock<Arc<Core>>,
    alt_proto: Mutex<HashMap<String, Arc<dyn RoundTripper>>>,
}

impl Default for Transport {
    fn default() -> Self {
        Self {
            proxy: None,
            on_proxy_connect_response: None,
            dial_context: None,
            dial: None,
            dial_tls_context: None,
            dial_tls: None,
            tls_client_config: None,
            tls_handshake_timeout: Duration::default(),
            disable_keep_alives: false,
            disable_compression: false,
            max_idle_conns: 0,
            max_idle_conns_per_host: 0,
            max_conns_per_host: 0,
            idle_conn_timeout: Duration::default(),
            response_header_timeout: Duration::default(),
            expect_continue_timeout: Duration::default(),
            tls_next_proto: None,
            proxy_connect_header: Header::new(),
            get_proxy_connect_header: None,
            max_response_header_bytes: 0,
            write_buffer_size: 0,
            read_buffer_size: 0,
            force_attempt_http2: false,
            http2: None,
            protocols: None,
            state: Arc::new(TransportState::default()),
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}
/// Go's `DefaultTransport`.
static DEFAULT_TRANSPORT: LazyLock<RwLock<Arc<dyn RoundTripper>>> = LazyLock::new(|| {
    let dialer = Dialer {
        timeout: time::SECOND * 30,
        ..Dialer::default()
    };
    let dial_context: DialContextFn = Arc::new(move |ctx, network, addr| {
        dialer
            .dial_context(ctx, network, addr)
            .map_err(|e| Box::new(e) as BoxError)
    });
    let t = Transport {
        proxy: Some(Arc::new(proxy_from_environment)),
        dial_context: Some(dial_context),
        force_attempt_http2: true,
        max_idle_conns: 100,
        idle_conn_timeout: time::SECOND * 90,
        tls_handshake_timeout: time::SECOND * 10,
        expect_continue_timeout: time::SECOND,
        ..Transport::default()
    };
    RwLock::new(Arc::new(t))
});

/// Go's `DefaultTransport` value.
pub fn default_transport() -> Arc<dyn RoundTripper> {
    DEFAULT_TRANSPORT
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}
/// Replaces `DefaultTransport` (Go: assigning the package variable).
pub fn set_default_transport(rt: Arc<dyn RoundTripper>) {
    *DEFAULT_TRANSPORT.write().unwrap_or_else(|e| e.into_inner()) = rt;
}

// ----------------------------------------------------------------- proxies

/// Go's `ProxyURL`: a proxy function that always returns `fixed_url`.
pub fn proxy_url(fixed_url: Url) -> ProxyFn {
    Arc::new(move |_| Ok(Some(fixed_url.clone())))
}

struct EnvProxy {
    http_proxy: Option<Url>,
    https_proxy: Option<Url>,
    cgi: bool,
    all: bool,
    ip_matchers: Vec<IpMatcher>,
    domain_matchers: Vec<DomainMatcher>,
}
enum IpMatcher {
    Cidr(net::IPNet),
    Ip(net::IP, String),
}
struct DomainMatcher {
    host: String,
    port: String,
    match_host: bool,
}

fn get_env_any(names: &[&str]) -> String {
    for n in names {
        if let Ok(v) = std::env::var(n) {
            if !v.is_empty() {
                return v;
            }
        }
    }
    String::new()
}

fn parse_proxy(proxy: &str) -> Option<Url> {
    if proxy.is_empty() {
        return None;
    }
    let first = url::parse(proxy);
    let ok = matches!(&first, Ok(u) if !u.scheme.is_empty() && !u.host.is_empty());
    if !ok {
        if let Ok(u) = url::parse(&format!("http://{proxy}")) {
            return Some(u);
        }
    }
    first.ok()
}

fn canonical_proxy_addr(u: &Url) -> String {
    let mut addr = u.hostname();
    if !addr.is_ascii() {
        if let Some(v) = super::cookiejar::to_ascii(&addr) {
            addr = v;
        }
    }
    let mut port = u.port();
    if port.is_empty() {
        port = match u.scheme.as_str() {
            "http" => "80",
            "https" => "443",
            "socks5" => "1080",
            _ => "",
        }
        .to_owned();
    }
    net::join_host_port(&addr, &port)
}

impl EnvProxy {
    fn from(http: &str, https: &str, no_proxy: &str, cgi: bool) -> Self {
        let mut c = EnvProxy {
            http_proxy: parse_proxy(http),
            https_proxy: parse_proxy(https),
            cgi,
            all: false,
            ip_matchers: Vec::new(),
            domain_matchers: Vec::new(),
        };
        for p in no_proxy.split(',') {
            let p = p.trim().to_lowercase();
            if p.is_empty() {
                continue;
            }
            if p == "*" {
                c.all = true;
                c.ip_matchers.clear();
                c.domain_matchers.clear();
                return c;
            }
            if let Ok((_, pnet)) = net::parse_cidr(&p) {
                c.ip_matchers.push(IpMatcher::Cidr(pnet));
                continue;
            }
            let (mut phost, pport) = match net::split_host_port(&p) {
                Ok((h, port)) => {
                    if h.is_empty() {
                        continue;
                    }
                    (h, port)
                }
                Err(_) => (p.clone(), String::new()),
            };
            if phost.starts_with('[') && phost.ends_with(']') {
                phost = phost[1..phost.len() - 1].to_owned();
            }
            if let Some(pip) = net::parse_ip(&phost) {
                c.ip_matchers.push(IpMatcher::Ip(pip, pport));
                continue;
            }
            if phost.is_empty() {
                continue;
            }
            if let Some(rest) = phost.strip_prefix("*.") {
                phost = format!(".{rest}");
            }
            let mut match_host = false;
            if !phost.starts_with('.') {
                match_host = true;
                phost.insert(0, '.');
            }
            if !phost.is_ascii() {
                if let Some(v) = super::cookiejar::to_ascii(&phost) {
                    phost = v;
                }
            }
            c.domain_matchers.push(DomainMatcher {
                host: phost,
                port: pport,
                match_host,
            });
        }
        c
    }

    fn use_proxy(&self, addr: &str) -> bool {
        if addr.is_empty() {
            return true;
        }
        let Ok((host, port)) = net::split_host_port(addr) else {
            return false;
        };
        if host == "localhost" {
            return false;
        }
        let ip = net::parse_ip(&host);
        if let Some(ip) = &ip {
            if ip.is_loopback() {
                return false;
            }
        }
        if self.all {
            return false;
        }
        let host = host.trim().to_lowercase();
        if let Some(ip) = &ip {
            for m in &self.ip_matchers {
                let hit = match m {
                    IpMatcher::Cidr(n) => n.contains(ip),
                    IpMatcher::Ip(mip, mport) => {
                        mip.equal(ip) && (mport.is_empty() || *mport == port)
                    }
                };
                if hit {
                    return false;
                }
            }
        }
        if ip.is_none() {
            for m in &self.domain_matchers {
                if (host.ends_with(&m.host) || (m.match_host && host == m.host[1..]))
                    && (m.port.is_empty() || m.port == port)
                {
                    return false;
                }
            }
        }
        true
    }

    fn proxy_for_url(&self, req_url: &Url) -> Result<Option<Url>, BoxError> {
        let proxy = match req_url.scheme.as_str() {
            "https" => self.https_proxy.clone(),
            "http" => {
                let p = self.http_proxy.clone();
                if p.is_some() && self.cgi {
                    return Err("refusing to use HTTP_PROXY value in CGI environment; see golang.org/s/cgihttpproxy".into());
                }
                p
            }
            _ => None,
        };
        let Some(proxy) = proxy else {
            return Ok(None);
        };
        if !self.use_proxy(&canonical_proxy_addr(req_url)) {
            return Ok(None);
        }
        Ok(Some(proxy))
    }
}

static ENV_PROXY: OnceLock<EnvProxy> = OnceLock::new();

/// Go's `ProxyFromEnvironment`: `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY`
/// (and their lower-case forms), read once per process.
pub fn proxy_from_environment(req: &Request) -> Result<Option<Url>, BoxError> {
    let cfg = ENV_PROXY.get_or_init(|| {
        EnvProxy::from(
            &get_env_any(&["HTTP_PROXY", "http_proxy"]),
            &get_env_any(&["HTTPS_PROXY", "https_proxy"]),
            &get_env_any(&["NO_PROXY", "no_proxy"]),
            std::env::var("REQUEST_METHOD").is_ok_and(|v| !v.is_empty()),
        )
    });
    cfg.proxy_for_url(&req.url)
}

/// `ProxyFromEnvironment` over an explicit configuration (for tests).
pub fn proxy_func_for(
    http_proxy: &str,
    https_proxy: &str,
    no_proxy: &str,
    cgi: bool,
) -> impl Fn(&Url) -> Result<Option<Url>, BoxError> {
    let cfg = EnvProxy::from(http_proxy, https_proxy, no_proxy, cgi);
    move |u| cfg.proxy_for_url(u)
}

// -------------------------------------------------------------- core state

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct ConnKey {
    proxy: String,
    scheme: String,
    addr: String,
    only_h1: bool,
}
impl fmt::Display for ConnKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let h1 = if self.only_h1 { ",h1" } else { "" };
        write!(f, "{}|{}{}|{}", self.proxy, self.scheme, h1, self.addr)
    }
}

struct ConnectMethod {
    proxy_url: Option<Url>,
    target_scheme: String,
    target_addr: String,
    only_h1: bool,
}
impl ConnectMethod {
    fn key(&self) -> ConnKey {
        let mut proxy = String::new();
        let mut target_addr = self.target_addr.clone();
        if let Some(p) = &self.proxy_url {
            proxy = p.to_string();
            if (p.scheme == "http" || p.scheme == "https") && self.target_scheme == "http" {
                target_addr.clear();
            }
        }
        ConnKey {
            proxy,
            scheme: self.target_scheme.clone(),
            addr: target_addr,
            only_h1: self.only_h1,
        }
    }
    fn scheme(&self) -> &str {
        match &self.proxy_url {
            Some(p) => &p.scheme,
            None => &self.target_scheme,
        }
    }
    fn addr(&self) -> String {
        match &self.proxy_url {
            Some(p) => canonical_addr(p),
            None => self.target_addr.clone(),
        }
    }
    fn tls_host(&self) -> String {
        super::header::remove_port(&self.target_addr).to_owned()
    }
    fn proxy_auth(&self) -> String {
        if let Some(p) = &self.proxy_url {
            if let Some(u) = &p.user {
                return format!(
                    "Basic {}",
                    basic_auth(u.username(), u.password().unwrap_or(""))
                );
            }
        }
        String::new()
    }
}

fn scheme_port(scheme: &str) -> &'static str {
    match scheme {
        "http" => "80",
        "https" => "443",
        "socks5" | "socks5h" => "1080",
        _ => "",
    }
}

fn canonical_addr(u: &Url) -> String {
    let mut port = u.port();
    if port.is_empty() {
        port = scheme_port(&u.scheme).to_owned();
    }
    let mut host = u.hostname();
    if !host.is_ascii() {
        if let Some(v) = super::cookiejar::to_ascii(&host) {
            host = v;
        }
    }
    net::join_host_port(&host, &port)
}

#[derive(Default)]
struct Pool {
    close_idle: bool,
    idle: HashMap<ConnKey, Vec<Arc<PersistConn>>>,
    lru: VecDeque<Arc<PersistConn>>,
    conns_per_host: HashMap<ConnKey, i64>,
}

struct Core {
    cfg: Cfg,
    h2_pool: Arc<super::h2::transport::Pool>,
    alt_conns: Mutex<HashMap<String, Arc<dyn RoundTripper>>>,
    pool: Mutex<Pool>,
    slot_cv: Condvar,
    req_canceler: Mutex<HashMap<u64, CancelCauseFunc>>,
    reaper: Once,
}

struct Once(Mutex<bool>);
impl Default for Once {
    fn default() -> Self {
        Once(Mutex::new(false))
    }
}
impl Core {
    fn new_reaper() -> Once {
        Once::default()
    }
}

/// An immutable snapshot of the `Transport` fields, taken at first use.
#[derive(Clone)]
struct Cfg {
    proxy: Option<ProxyFn>,
    on_proxy_connect_response: Option<OnProxyConnectResponseFn>,
    dial_context: Option<DialContextFn>,
    dial: Option<DialFn>,
    dial_tls_context: Option<DialContextFn>,
    dial_tls: Option<DialFn>,
    tls_client_config: Option<Arc<dyn TlsConfig>>,
    tls_handshake_timeout: Duration,
    disable_keep_alives: bool,
    disable_compression: bool,
    max_idle_conns: i64,
    max_idle_conns_per_host: i64,
    max_conns_per_host: i64,
    idle_conn_timeout: Duration,
    response_header_timeout: Duration,
    expect_continue_timeout: Duration,
    proxy_connect_header: Header,
    get_proxy_connect_header: Option<GetProxyConnectHeaderFn>,
    max_response_header_bytes: i64,
    write_buffer_size: i64,
    read_buffer_size: i64,
    /// The effective `Protocols` (Go's `Transport.protocols`).
    protocols: Protocols,
    /// True when `Protocols` was set explicitly.
    protocols_explicit: bool,
    /// The built-in HTTP/2 serves this transport (no user `TLSNextProto["h2"]`).
    builtin_h2: bool,
    tls_next_proto: BTreeMap<String, TlsNextProtoRtFn>,
    h2: Arc<super::h2::transport::TransportConfig>,
}

impl Cfg {
    /// Prior-knowledge HTTP/2 over plain TCP for `http` URLs.
    fn unencrypted_h2_only(&self) -> bool {
        self.builtin_h2
            && self.protocols_explicit
            && self.protocols.unencrypted_http2()
            && !self.protocols.http1()
    }

    /// The ALPN list to offer (Go's `adjustNextProtos` on the TLS config).
    fn next_protos(&self, only_h1: bool) -> Vec<String> {
        if only_h1 {
            return Vec::new();
        }
        let mut v = Vec::new();
        if self.builtin_h2 && self.protocols.http2() {
            v.push("h2".to_owned());
            if self.protocols.http1() {
                v.push("http/1.1".to_owned());
            }
        }
        for k in self.tls_next_proto.keys() {
            if k != "h2" && k != "http/1.1" && !v.contains(k) {
                v.push(k.clone());
            }
        }
        if self.tls_next_proto.contains_key("h2") && !v.iter().any(|p| p == "h2") {
            v.insert(0, "h2".to_owned());
        }
        v
    }

    fn max_header_response_size(&self) -> i64 {
        if self.max_response_header_bytes > 0 {
            self.max_response_header_bytes
        } else {
            10 << 20
        }
    }
    fn max_idle_conns_per_host(&self) -> i64 {
        if self.max_idle_conns_per_host != 0 {
            self.max_idle_conns_per_host
        } else {
            DEFAULT_MAX_IDLE_CONNS_PER_HOST
        }
    }
    fn has_custom_tls_dialer(&self) -> bool {
        self.dial_tls.is_some() || self.dial_tls_context.is_some()
    }
}

impl Transport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Go's `Transport.protocols`.
    fn effective_protocols(&self) -> Protocols {
        if let Some(p) = self.protocols {
            return p;
        }
        let mut p = Protocols::default();
        p.set_http1(true);
        match &self.tls_next_proto {
            Some(m) => {
                if m.contains_key("h2") {
                    p.set_http2(true);
                }
            }
            None => {
                let custom = self.tls_client_config.is_some()
                    || self.dial.is_some()
                    || self.dial_context.is_some()
                    || self.dial_tls.is_some()
                    || self.dial_tls_context.is_some();
                if self.force_attempt_http2 || !custom {
                    p.set_http2(true);
                }
            }
        }
        p
    }

    fn core(&self) -> &Arc<Core> {
        self.state.core.get_or_init(|| {
            let protocols = self.effective_protocols();
            let tls_next_proto = self.tls_next_proto.clone().unwrap_or_default();
            let builtin_h2 = (protocols.http2() || protocols.unencrypted_http2())
                && !tls_next_proto.contains_key("h2");
            let h2_conf = super::h2::Config::from_http2(self.http2.as_ref(), false);
            Arc::new(Core {
                h2_pool: super::h2::transport::Pool::new(),
                alt_conns: Mutex::new(HashMap::new()),
                cfg: Cfg {
                    protocols,
                    protocols_explicit: self.protocols.is_some(),
                    builtin_h2,
                    tls_next_proto,
                    h2: Arc::new(super::h2::transport::TransportConfig {
                        conf: h2_conf,
                        disable_compression: self.disable_compression,
                        disable_keep_alives: self.disable_keep_alives,
                        expect_continue_timeout: self.expect_continue_timeout.to_std(),
                        response_header_timeout: self.response_header_timeout.to_std(),
                        idle_conn_timeout: self.idle_conn_timeout.to_std(),
                        max_response_header_bytes: self.max_response_header_bytes,
                    }),
                    proxy: self.proxy.clone(),
                    on_proxy_connect_response: self.on_proxy_connect_response.clone(),
                    dial_context: self.dial_context.clone(),
                    dial: self.dial.clone(),
                    dial_tls_context: self.dial_tls_context.clone(),
                    dial_tls: self.dial_tls.clone(),
                    tls_client_config: self.tls_client_config.clone(),
                    tls_handshake_timeout: self.tls_handshake_timeout,
                    disable_keep_alives: self.disable_keep_alives,
                    disable_compression: self.disable_compression,
                    max_idle_conns: self.max_idle_conns,
                    max_idle_conns_per_host: self.max_idle_conns_per_host,
                    max_conns_per_host: self.max_conns_per_host,
                    idle_conn_timeout: self.idle_conn_timeout,
                    response_header_timeout: self.response_header_timeout,
                    expect_continue_timeout: self.expect_continue_timeout,
                    proxy_connect_header: self.proxy_connect_header.clone(),
                    get_proxy_connect_header: self.get_proxy_connect_header.clone(),
                    max_response_header_bytes: self.max_response_header_bytes,
                    write_buffer_size: self.write_buffer_size,
                    read_buffer_size: self.read_buffer_size,
                },
                pool: Mutex::new(Pool::default()),
                slot_cv: Condvar::new(),
                req_canceler: Mutex::new(HashMap::new()),
                reaper: Core::new_reaper(),
            })
        })
    }

    /// Go's `Clone`: a copy with its own (empty) connection pool.
    pub fn clone_transport(&self) -> Transport {
        let mut t2 = self.clone();
        t2.state = Arc::new(TransportState::default());
        t2
    }

    /// Go's `RegisterProtocol`. Go panics when the scheme is already
    /// registered; here the error is returned.
    pub fn register_protocol(
        &self,
        scheme: &str,
        rt: Arc<dyn RoundTripper>,
    ) -> Result<(), BoxError> {
        let mut m = lock(&self.state.alt_proto);
        if m.contains_key(scheme) {
            return Err(format!("protocol {scheme} already registered").into());
        }
        m.insert(scheme.to_owned(), rt);
        Ok(())
    }

    fn alternate_round_tripper(&self, req: &Request) -> Option<Arc<dyn RoundTripper>> {
        if req.url.scheme == "https" && req.requires_http1() {
            return None;
        }
        lock(&self.state.alt_proto).get(&req.url.scheme).cloned()
    }

    /// Go's `CloseIdleConnections`.
    pub fn close_idle_connections_now(&self) {
        let core = self.core();
        let conns: Vec<Arc<PersistConn>> = {
            let mut pool = lock(&core.pool);
            pool.close_idle = true;
            pool.lru.clear();
            pool.idle.drain().flat_map(|(_, v)| v).collect()
        };
        for pc in conns {
            pc.close("http: CloseIdleConnections called");
        }
        core.h2_pool.close_idle_connections();
    }

    /// Go's `CancelRequest` (deprecated).
    pub fn cancel_request_now(&self, req: &Request) {
        let core = self.core();
        let c = lock(&core.req_canceler).get(&req.id()).cloned();
        if let Some(c) = c {
            c(Some(Arc::new(ERR_REQUEST_CANCELED)));
        }
    }

    /// Go's `Transport.NewClientConn`: a dedicated connection outside the pool.
    pub fn client_conn(
        &self,
        ctx: &Context,
        scheme: &str,
        address: &str,
    ) -> Result<ClientConn, BoxError> {
        let core = self.core().clone();
        match scheme {
            "http" | "https" => {}
            _ => {
                return Err(
                    format!("net/http: invalid scheme {}", crate::strconv::quote(scheme)).into(),
                )
            }
        }
        let (host, mut port) = net::split_host_port(address)?;
        if port.is_empty() {
            port = scheme_port(scheme).to_owned();
        }
        let mut proxy_url = None;
        if let Some(p) = &core.cfg.proxy {
            let mut req = Request::default();
            req.set_context(ctx.clone());
            req.method = "GET".into();
            req.url = Url {
                scheme: scheme.to_owned(),
                host: host.clone(),
                path: "/".into(),
                ..Url::default()
            };
            req.proto = "HTTP/1.1".into();
            req.proto_major = 1;
            req.proto_minor = 1;
            req.body = Some(Body::from(NoBody));
            req.host = host.clone();
            proxy_url = p(&req)?;
        }
        let cm = ConnectMethod {
            proxy_url,
            target_scheme: scheme.to_owned(),
            target_addr: net::join_host_port(&host, &port),
            only_h1: false,
        };
        let inner = match core.dial_conn(ctx, &cm, true)? {
            Dialed::H1(pc) => ClientConnInner::H1(pc),
            Dialed::H2(cc) => ClientConnInner::H2(cc),
            Dialed::Alt(_) => {
                return Err("net/http: ClientConn needs HTTP/1 or HTTP/2".into());
            }
        };
        Ok(ClientConn {
            inner,
            core,
            hook: Arc::new(Mutex::new(HookState::default())),
        })
    }
}

impl RoundTripper for Transport {
    fn round_trip(&self, req: &Request) -> Result<Response, BoxError> {
        self.round_trip_impl(req)
    }
    fn close_idle_connections(&self) {
        self.close_idle_connections_now();
    }
    fn cancel_request(&self, req: &Request) {
        self.cancel_request_now(req);
    }
    fn is_known_impl(&self) -> bool {
        true
    }
}

fn validate_headers(h: &Header) -> String {
    for (k, vv) in &h.0 {
        if !valid_header_field_name(k) {
            return format!("field name {}", crate::strconv::quote(k));
        }
        for v in vv {
            if !valid_header_field_value(v) {
                return format!("field value for {}", crate::strconv::quote(k));
            }
        }
    }
    String::new()
}

/// Internal round-trip failures, mirroring Go's wrapper error types.
enum RtError {
    NothingWritten(BoxError),
    ReadFromServer(BoxError),
    Other(BoxError),
}
impl RtError {
    fn into_box(self) -> BoxError {
        match self {
            RtError::NothingWritten(e) | RtError::Other(e) => e,
            RtError::ReadFromServer(e) => e,
        }
    }
}
impl fmt::Display for RtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RtError::NothingWritten(e) | RtError::Other(e) | RtError::ReadFromServer(e) => e.fmt(f),
        }
    }
}

/// A request body that remembers whether it was read or closed, so a retry
/// knows whether it must rewind (Go's `readTrackingBody`).
struct ReadTrackingBody {
    inner: Body,
    did_read: Arc<AtomicBool>,
    did_close: Arc<AtomicBool>,
}
impl Read for ReadTrackingBody {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.did_read.store(true, Ordering::SeqCst);
        self.inner.read(buf)
    }
}
impl ReadCloser for ReadTrackingBody {
    fn close(&mut self) -> io::Result<()> {
        if self.did_close.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        self.inner.close()
    }
}

struct Tracked {
    req: Request,
    did_read: Option<Arc<AtomicBool>>,
    did_close: Option<Arc<AtomicBool>>,
}

fn setup_rewind_body(req: &Request) -> Tracked {
    match &req.body {
        Some(b) if !b.is_no_body() => {
            let did_read = Arc::new(AtomicBool::new(false));
            let did_close = Arc::new(AtomicBool::new(false));
            let mut r = req.clone();
            r.body = Some(Body::new(ReadTrackingBody {
                inner: b.clone(),
                did_read: did_read.clone(),
                did_close: did_close.clone(),
            }));
            Tracked {
                req: r,
                did_read: Some(did_read),
                did_close: Some(did_close),
            }
        }
        _ => Tracked {
            req: req.clone(),
            did_read: None,
            did_close: None,
        },
    }
}

fn rewind_body(t: Tracked) -> Result<Tracked, BoxError> {
    let (Some(read), Some(close)) = (&t.did_read, &t.did_close) else {
        return Ok(t);
    };
    if !read.load(Ordering::SeqCst) && !close.load(Ordering::SeqCst) {
        return Ok(t);
    }
    if !close.load(Ordering::SeqCst) {
        let _ = t.req.close_body();
    }
    let Some(gb) = t.req.get_body.clone() else {
        return Err(Box::new(ERR_CANNOT_REWIND));
    };
    let body = gb()?;
    let did_read = Arc::new(AtomicBool::new(false));
    let did_close = Arc::new(AtomicBool::new(false));
    let mut r = t.req.clone();
    r.body = Some(Body::new(ReadTrackingBody {
        inner: body,
        did_read: did_read.clone(),
        did_close: did_close.clone(),
    }));
    Ok(Tracked {
        req: r,
        did_read: Some(did_read),
        did_close: Some(did_close),
    })
}

impl Transport {
    fn round_trip_impl(&self, orig: &Request) -> Result<Response, BoxError> {
        let core = self.core().clone();
        let url_missing = orig.url == Url::default();
        if url_missing {
            let _ = orig.close_body();
            return Err("http: nil Request.URL".into());
        }
        let scheme = orig.url.scheme.clone();
        let is_http = scheme == "http" || scheme == "https";
        if is_http {
            let e = validate_headers(&orig.header);
            if !e.is_empty() {
                let _ = orig.close_body();
                return Err(format!("net/http: invalid header {e}").into());
            }
            if let Some(tr) = orig.trailer.get() {
                let e = validate_headers(&tr);
                if !e.is_empty() {
                    let _ = orig.close_body();
                    return Err(format!("net/http: invalid trailer {e}").into());
                }
            }
        }
        let mut tracked = setup_rewind_body(orig);
        if let Some(alt) = self.alternate_round_tripper(&tracked.req) {
            match alt.round_trip(&tracked.req) {
                Err(e) if e.downcast_ref::<ErrorString>() == Some(&ERR_SKIP_ALT_PROTOCOL) => {
                    tracked = rewind_body(tracked)?;
                }
                other => return other,
            }
        }
        if !is_http {
            let _ = tracked.req.close_body();
            return Err(format!(
                "unsupported protocol scheme {}",
                crate::strconv::quote(&scheme)
            )
            .into());
        }
        if !tracked.req.method.is_empty() && !super::token(&tracked.req.method) {
            let _ = tracked.req.close_body();
            return Err(format!(
                "net/http: invalid method {}",
                crate::strconv::quote(&tracked.req.method)
            )
            .into());
        }
        if tracked.req.url.host.is_empty() {
            let _ = tracked.req.close_body();
            return Err("http: no Host in request URL".into());
        }

        let (ctx, cancel) = tracked.req.context().with_cancel_cause();
        if let Some(done) = orig.cancel.clone() {
            // awaitLegacyCancel
            let ctx2 = ctx.clone();
            let cancel2 = cancel.clone();
            std::thread::spawn(move || loop {
                if done.wait_timeout(Duration::from_millis(20)) {
                    cancel2(Some(Arc::new(ERR_REQUEST_CANCELED)));
                    return;
                }
                if ctx2.err().is_some() {
                    return;
                }
            });
        }
        let id = orig.id();
        lock(&core.req_canceler).insert(id, cancel.clone());
        let finish_cancel = {
            let core = core.clone();
            let cancel = cancel.clone();
            move |err: Option<context::CauseError>| {
                cancel(err);
                lock(&core.req_canceler).remove(&id);
            }
        };

        let (mut h2_attempts, mut h2_retries) = (0u32, 0u32);
        loop {
            if ctx.err().is_some() {
                let _ = tracked.req.close_body();
                finish_cancel(None);
                return Err(cause_error(&ctx));
            }
            let treq = TransportRequest {
                req: tracked.req.clone(),
                ctx: ctx.clone(),
                cancel: cancel.clone(),
                extra: Mutex::new(Header::new()),
                trace: httptrace::context_client_trace(&ctx),
            };
            let cm = match core.connect_method_for_request(&treq) {
                Ok(cm) => cm,
                Err(e) => {
                    let _ = tracked.req.close_body();
                    finish_cancel(None);
                    return Err(e);
                }
            };
            // Multiplexed HTTP/2 connections that already exist come first.
            let mut dialed = None;
            if core.h2_eligible(&cm, &tracked.req) {
                if let Some(cc) = core.h2_pool.get_cached(&h2_pool_key(&cm)) {
                    // A cached connection skips get_conn, which reports this.
                    // Go reports it a second time for unencrypted HTTP/2: the
                    // idle connection net/http hands out is not registered as
                    // an alternate round tripper, so the HTTP/2 pool reports
                    // the request's GetConn again.
                    if let Some(hook) = treq.trace.as_ref().and_then(|t| t.get_conn.as_ref()) {
                        hook(&cm.addr());
                        if cm.target_scheme == "http" {
                            hook(&cm.addr());
                        }
                    }
                    dialed = Some(Dialed::H2(cc));
                }
            }
            let dialed = match dialed {
                Some(d) => d,
                None => match core.get_conn(&treq, &cm) {
                    Ok(d) => d,
                    Err(e) => {
                        let _ = tracked.req.close_body();
                        finish_cancel(None);
                        return Err(e);
                    }
                },
            };
            match dialed {
                Dialed::H1(pc) => match pc.round_trip(&treq) {
                    Ok(mut resp) => {
                        resp.request = Some(Box::new(orig.clone()));
                        return Ok(resp);
                    }
                    Err(e) => {
                        if !pc.should_retry_request(&tracked.req, &e) {
                            if let Some(c) = &tracked.did_close {
                                if !c.load(Ordering::SeqCst) {
                                    let _ = tracked.req.close_body();
                                }
                            }
                            finish_cancel(Some(Arc::new(ErrorString(
                                "net/http: request completed",
                            ))));
                            return Err(e.into_box());
                        }
                    }
                },
                Dialed::Alt(rt) => {
                    return match rt.round_trip(&treq.req) {
                        Ok(mut resp) => {
                            resp.request = Some(Box::new(orig.clone()));
                            Ok(resp)
                        }
                        Err(e) => {
                            let _ = tracked.req.close_body();
                            finish_cancel(None);
                            Err(e)
                        }
                    };
                }
                Dialed::H2(dialed_cc) => {
                    // Go hands the request to the HTTP/2 pool, which may pick
                    // any usable connection to the host (not only the new one).
                    let cc = match core.h2_pool.get_cached(&h2_pool_key(&cm)) {
                        Some(cc) => cc,
                        None => {
                            h2_attempts += 1;
                            if h2_attempts > 4 {
                                let _ = tracked.req.close_body();
                                finish_cancel(None);
                                return Err("http2: no cached connection was available".into());
                            }
                            let _ = dialed_cc;
                            continue;
                        }
                    };
                    let reused = cc.mark_reused();
                    // Go's http2 transport reports GotConn itself; its stream
                    // level hooks are fired by the h2 client stream.
                    if let Some(hook) = treq.trace.as_ref().and_then(|t| t.got_conn.as_ref()) {
                        let (was_idle, idle_time) = cc.idle_info(reused);
                        hook(httptrace::GotConnInfo {
                            conn: cc.conn(),
                            reused,
                            was_idle,
                            idle_time: idle_time.into(),
                        });
                    }
                    let fc = finish_cancel.clone();
                    let on_done: Box<dyn FnOnce() + Send> = Box::new(move || {
                        fc(Some(Arc::new(ErrorString("net/http: request completed"))));
                    });
                    match cc.round_trip(&treq.req, &ctx, Some(on_done)) {
                        Ok(mut resp) => {
                            resp.request = Some(Box::new(orig.clone()));
                            return Ok(resp);
                        }
                        Err(e) => {
                            if super::h2::transport::can_retry_error(&e) && h2_retries < 6 {
                                h2_retries += 1;
                                if h2_retries > 1 {
                                    let backoff = 1u64 << (h2_retries - 2);
                                    std::thread::sleep(StdDuration::from_millis(100 * backoff));
                                }
                                if ctx.err().is_none() {
                                    tracked = rewind_body(tracked)?;
                                    continue;
                                }
                            }
                            if let Some(c) = &tracked.did_close {
                                if !c.load(Ordering::SeqCst) {
                                    let _ = tracked.req.close_body();
                                }
                            }
                            let boxed = h2_error_to_box(&ctx, e);
                            finish_cancel(Some(Arc::new(ErrorString(
                                "net/http: request completed",
                            ))));
                            return Err(boxed);
                        }
                    }
                }
            }
            tracked = rewind_body(tracked)?;
        }
    }
}

/// Maps an HTTP/2 client error to the error `RoundTrip` returns.
fn h2_error_to_box(ctx: &Context, e: super::h2::H2Error) -> BoxError {
    if ctx.err().is_some() {
        return cause_error(ctx);
    }
    if e.is_msg(super::h2::transport::ERR_TIMEOUT) {
        return Box::new(TimeoutError(e.to_string()));
    }
    Box::new(e)
}

impl Core {
    /// Whether a request may use (or create) an HTTP/2 connection.
    fn h2_eligible(&self, cm: &ConnectMethod, req: &Request) -> bool {
        if !self.cfg.builtin_h2 {
            return false;
        }
        if cm.target_scheme == "https" {
            self.cfg.protocols.http2() && !req.requires_http1()
        } else {
            cm.proxy_url.is_none() && self.cfg.unencrypted_h2_only()
        }
    }
}

fn cause_error(ctx: &Context) -> BoxError {
    if let Some(c) = ctx.cause() {
        return Box::new(ArcError(c));
    }
    match ctx.err() {
        Some(e) => Box::new(e),
        None => Box::new(ERR_REQUEST_CANCELED),
    }
}

/// An `Arc<dyn Error>` as a `Box<dyn Error + Send + Sync>`.
#[derive(Debug)]
struct ArcError(context::CauseError);
impl fmt::Display for ArcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for ArcError {}

/// A request-writer failure shared by the several places that report it.
/// It reads as the original error and keeps it as its `source`, so
/// `errors.As`-style walks reach the body's own error type.
#[derive(Clone, Debug)]
struct SharedError(Arc<dyn std::error::Error + Send + Sync>);
impl fmt::Display for SharedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for SharedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}

/// Go's `fmt.Errorf("net/http: HTTP/1.x transport connection broken: %w", err)`.
#[derive(Debug)]
struct ConnectionBroken(BoxError);
impl fmt::Display for ConnectionBroken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "net/http: HTTP/1.x transport connection broken: {}",
            self.0
        )
    }
}
impl std::error::Error for ConnectionBroken {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}

struct TransportRequest {
    req: Request,
    ctx: Context,
    cancel: CancelCauseFunc,
    extra: Mutex<Header>,
    /// The request context's `httptrace.ClientTrace`, if any.
    trace: Option<Arc<ClientTrace>>,
}

// -------------------------------------------------------------- persistConn

#[derive(Default)]
struct PcMut {
    closed: Option<String>,
    canceled_err: Option<BoxedCause>,
    reused: bool,
    idle_at: Option<Instant>,
    reserved: bool,
    in_flight: bool,
}
type BoxedCause = Arc<dyn std::error::Error + Send + Sync>;

struct PersistConn {
    core: Arc<Core>,
    key: ConnKey,
    conn: Arc<dyn Conn>,
    tls_state: Option<Arc<ConnectionState>>,
    br: BufioReader,
    is_proxy: bool,
    mutate_header: Option<Box<dyn Fn(&mut Header) + Send + Sync>>,
    mu: Mutex<PcMut>,
    nwrite: Arc<AtomicI64>,
    saw_eof: Arc<AtomicBool>,
    read_limit: Arc<AtomicI64>,
    write_err: Mutex<Option<Receiver<Result<(), SharedError>>>>,
    is_client_conn: bool,
}

struct PcReader {
    conn: Arc<dyn Conn>,
    limit: Arc<AtomicI64>,
    saw_eof: Arc<AtomicBool>,
    max: i64,
}
impl Read for PcReader {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        let limit = self.limit.load(Ordering::SeqCst);
        if limit <= 0 {
            return Err(io::Error::other(format!(
                "read limit of {} bytes exhausted",
                self.max
            )));
        }
        let want = usize::try_from(limit).unwrap_or(usize::MAX).min(p.len());
        let n = self
            .conn
            .read(&mut p[..want])
            .map_err(net::NetError::into_io)?;
        if n == 0 {
            self.saw_eof.store(true, Ordering::SeqCst);
        }
        self.limit.fetch_sub(n as i64, Ordering::SeqCst);
        Ok(n)
    }
}

struct PcWriter {
    conn: Arc<dyn Conn>,
    nwrite: Arc<AtomicI64>,
}
impl Write for PcWriter {
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        let n = self.conn.write(p).map_err(net::NetError::into_io)?;
        self.nwrite.fetch_add(n as i64, Ordering::SeqCst);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl PersistConn {
    fn is_broken(&self) -> bool {
        lock(&self.mu).closed.is_some()
    }
    fn is_reused(&self) -> bool {
        lock(&self.mu).reused
    }
    fn mark_reused(&self) {
        lock(&self.mu).reused = true;
    }
    fn canceled(&self) -> Option<BoxedCause> {
        lock(&self.mu).canceled_err.clone()
    }

    fn close(&self, reason: &str) {
        let mut g = lock(&self.mu);
        self.close_locked(&mut g, reason);
    }
    fn close_locked(&self, g: &mut PcMut, reason: &str) {
        if g.closed.is_none() {
            g.closed = Some(reason.to_owned());
            let _ = self.conn.close();
            self.core.dec_conns_per_host(&self.key);
        }
    }
    fn cancel_request(&self, err: BoxedCause) {
        let mut g = lock(&self.mu);
        g.canceled_err = Some(err);
        self.close_locked(&mut g, "net/http: request canceled");
    }

    /// Go's `wroteRequest`: did the writer finish successfully? Waits a
    /// short while for a writer that is still finishing.
    fn wrote_request(&self) -> bool {
        let rx = lock(&self.write_err).take();
        match rx {
            None => true,
            Some(rx) => match rx.recv_timeout(StdDuration::from_millis(50)) {
                Ok(r) => r.is_ok(),
                Err(_) => false,
            },
        }
    }

    fn should_retry_request(&self, req: &Request, err: &RtError) -> bool {
        if !self.is_reused() {
            return false;
        }
        if matches!(err, RtError::NothingWritten(_)) {
            return req.outgoing_length() == 0 || req.get_body.is_some();
        }
        if !req.is_replayable() {
            return false;
        }
        matches!(err, RtError::ReadFromServer(_))
    }

    fn map_error(&self, start_written: i64, err: RtError) -> RtError {
        if let Some(c) = self.canceled() {
            return RtError::Other(Box::new(ArcError(c)));
        }
        match err {
            // Go reports the underlying error of a failed read from the server.
            RtError::ReadFromServer(e) => {
                if self.nwrite.load(Ordering::SeqCst) == start_written {
                    RtError::NothingWritten(e)
                } else {
                    RtError::ReadFromServer(e)
                }
            }
            other => {
                if self.is_broken() {
                    if self.nwrite.load(Ordering::SeqCst) == start_written {
                        return RtError::NothingWritten(other.into_box());
                    }
                    return RtError::Other(Box::new(ConnectionBroken(other.into_box())));
                }
                other
            }
        }
    }

    fn round_trip(self: &Arc<Self>, treq: &TransportRequest) -> Result<Response, RtError> {
        // Reserve a ClientConn slot.
        if self.is_client_conn {
            let mut g = lock(&self.mu);
            if g.closed.is_some() {
                return Err(RtError::Other(g.closed.clone().unwrap_or_default().into()));
            }
            g.reserved = false;
            g.in_flight = true;
        }
        let cfg = &self.core.cfg;
        let mut extra = lock(&treq.extra).clone();
        if let Some(f) = &self.mutate_header {
            f(&mut extra);
        }
        let req = &treq.req;
        let mut requested_gzip = false;
        if !cfg.disable_compression
            && req.header.get_str("Accept-Encoding").is_empty()
            && req.header.get_str("Range").is_empty()
            && req.method != "HEAD"
        {
            requested_gzip = true;
            extra.set("Accept-Encoding", "gzip");
        }
        let has_body = req.body.as_ref().is_some_and(|b| !b.is_no_body());
        let mut continue_tx: Option<Sender<bool>> = None;
        let mut continue_rx: Option<Receiver<bool>> = None;
        if req.proto_at_least(1, 1) && req.body.is_some() && req.expects_continue() {
            let (tx, rx) = channel();
            continue_tx = Some(tx);
            continue_rx = Some(rx);
        }
        if cfg.disable_keep_alives && !req.wants_close() && !is_protocol_switch_header(&req.header)
        {
            extra.set("Connection", "close");
        }

        let start_written = self.nwrite.load(Ordering::SeqCst);
        // Cancellation: closing the connection unblocks the read below.
        let pc_for_cancel = self.clone();
        let stop = treq.ctx.after_func({
            let ctx = treq.ctx.clone();
            move || {
                let cause: BoxedCause = match ctx.cause() {
                    Some(c) => c,
                    None => match ctx.err() {
                        Some(e) => Arc::new(e),
                        None => Arc::new(ERR_REQUEST_CANCELED),
                    },
                };
                pc_for_cancel.cancel_request(cause);
            }
        });

        // Write the request.
        let (wtx, wrx) = channel::<Result<(), SharedError>>();
        let (wdone_tx, wdone_rx) = channel::<Result<(), SharedError>>();
        let write_job = {
            let pc = self.clone();
            let req = req.clone();
            let extra = extra.clone();
            let header_timeout = cfg.response_header_timeout;
            let expect_timeout = cfg.expect_continue_timeout;
            let treq_err = Arc::new(Mutex::new(None::<String>));
            let treq_err2 = treq_err.clone();
            move || {
                let mut bw = io::BufWriter::with_capacity(
                    usize::try_from(pc.core.cfg.write_buffer_size)
                        .ok()
                        .filter(|n| *n > 0)
                        .unwrap_or(4 << 10),
                    PcWriter {
                        conn: pc.conn.clone(),
                        nwrite: pc.nwrite.clone(),
                    },
                );
                let mut wait_fn: Option<Box<dyn FnMut() -> bool>> = continue_rx.map(|rx| {
                    Box::new(move || match rx.recv_timeout(expect_timeout.to_std()) {
                        Ok(v) => v,
                        Err(RecvTimeoutError::Timeout) => true,
                        Err(RecvTimeoutError::Disconnected) => false,
                    }) as Box<dyn FnMut() -> bool>
                });
                let wait_ref: Option<&mut dyn FnMut() -> bool> = match wait_fn.as_mut() {
                    Some(b) => Some(&mut **b),
                    None => None,
                };
                let res = req.write_impl(&mut bw, pc.is_proxy, Some(&extra), wait_ref);
                let res = match res {
                    Ok(()) => bw.flush().map_err(|e| Box::new(e) as BoxError),
                    Err(e) => Err(e),
                };
                let outcome = res.map_err(|e| SharedError(Arc::from(e)));
                if let Err(e) = &outcome {
                    *lock(&treq_err2) = Some(e.to_string());
                }
                if outcome.is_ok() && header_timeout.as_nanos() > 0 {
                    let _ = pc.conn.set_read_deadline(&time::now().add(header_timeout));
                }
                if let Err(e) = &outcome {
                    pc.close(&format!("write error: {e}"));
                }
                let _ = wtx.send(outcome.clone());
                let _ = wdone_tx.send(outcome);
            }
        };
        *lock(&self.write_err) = Some(wdone_rx);
        let mut writer_thread = None;
        if has_body {
            writer_thread = Some(std::thread::spawn(write_job));
        } else {
            write_job();
        }

        // Read the response head (skipping 1xx).
        self.core_set_read_limit();
        let head = self.read_response_head(treq, continue_tx);
        self.read_limit.store(i64::MAX, Ordering::SeqCst);
        let _ = self.conn.set_read_deadline(&Time::default());
        let mut resp = match head {
            Ok(r) => r,
            Err(e) => {
                stop();
                if let Some(t) = writer_thread {
                    let _ = t.join();
                }
                // Prefer the write error when the write failed first.
                if let Ok(Err(werr)) = wrx.try_recv() {
                    self.close(&format!("write error: {werr}"));
                    return Err(self.map_error(start_written, RtError::Other(Box::new(werr))));
                }
                if self.core.cfg.response_header_timeout.as_nanos() > 0 && rt_error_is_timeout(&e) {
                    self.close(ERR_TIMEOUT);
                    return Err(RtError::Other(Box::new(TimeoutError(ERR_TIMEOUT.into()))));
                }
                return Err(self.map_error(start_written, e));
            }
        };

        let body_writable = resp.status_code == 101 && is_protocol_switch_header(&resp.header);
        if body_writable {
            resp.body = Some(
                Body::new(SwitchedBody {
                    br: self.br.clone(),
                    conn: self.conn.clone(),
                })
                .with_writer(Arc::new(SwitchedWriter {
                    conn: self.conn.clone(),
                })),
            );
        }
        let has_resp_body = req.method != "HEAD" && resp.content_length != 0;
        let mut alive = true;
        if resp.close || req.close || resp.status_code <= 199 || body_writable {
            alive = false;
        }
        let state = Arc::new(BodyState {
            pc: self.clone(),
            alive: AtomicBool::new(alive),
            content_length: resp.content_length,
            stop: Mutex::new(Some(stop)),
            cancel: treq.cancel.clone(),
            writer: Mutex::new(writer_thread),
            done: AtomicBool::new(false),
            trace: treq.trace.clone(),
        });
        resp.tls = self.tls_state.clone();

        if !has_resp_body || body_writable {
            let ok = alive
                && !self.saw_eof.load(Ordering::SeqCst)
                && self.wrote_request()
                && self.try_put_idle(treq.trace.as_deref());
            state.finish_conn(ok, body_writable);
            return Ok(resp);
        }
        let inner = resp.body.take().unwrap_or_else(|| Body::from(NoBody));
        let sig = Body::new(BodyEofSignal {
            body: inner.clone(),
            state: state.clone(),
            closed: false,
            rerr: None,
            fired: false,
            inner_for_drain: inner,
        });
        resp.body = Some(sig.clone());
        if requested_gzip
            && resp
                .header
                .get_str("Content-Encoding")
                .eq_ignore_ascii_case("gzip")
        {
            resp.body = Some(Body::new(GzipReader {
                body: sig,
                zr: None,
                init_err: None,
                closed: false,
            }));
            resp.header.del("Content-Encoding");
            resp.header.del("Content-Length");
            resp.content_length = -1;
            resp.uncompressed = true;
        }
        Ok(resp)
    }

    fn core_set_read_limit(&self) {
        self.read_limit
            .store(self.core.cfg.max_header_response_size(), Ordering::SeqCst);
    }

    fn read_response_head(
        &self,
        treq: &TransportRequest,
        mut continue_tx: Option<Sender<bool>>,
    ) -> Result<Response, RtError> {
        // Peek the first byte so an idle-connection EOF is told apart from a
        // malformed response.
        {
            let mut br = self.br.lock();
            let (buf, err) = br.peek_available(1);
            if buf.is_empty() {
                let e: BoxError = match err {
                    Some(e) if !crate::io::is_eof(&e) => Box::new(e),
                    _ => Box::new(super::header::ERR_EOF),
                };
                return Err(RtError::ReadFromServer(e));
            }
        }
        if let Some(hook) = treq
            .trace
            .as_ref()
            .and_then(|t| t.got_first_response_byte.as_ref())
        {
            hook();
        }
        let mut resp;
        loop {
            resp = read_response(&self.br, Some(&treq.req)).map_err(|e| {
                if self.read_limit.load(Ordering::SeqCst) <= 0 {
                    return RtError::Other(
                        format!(
                            "net/http: server response headers exceeded {} bytes; aborted",
                            self.core.cfg.max_header_response_size()
                        )
                        .into(),
                    );
                }
                RtError::ReadFromServer(e)
            })?;
            let code = resp.status_code;
            if let Some(tx) = &continue_tx {
                if code == STATUS_CONTINUE {
                    if let Some(hook) = treq
                        .trace
                        .as_ref()
                        .and_then(|t| t.got_100_continue.as_ref())
                    {
                        hook();
                    }
                    let _ = tx.send(true);
                    continue_tx = None;
                }
            }
            let is_1xx = (100..=199).contains(&code);
            let non_terminal = is_1xx && code != STATUS_SWITCHING_PROTOCOLS;
            if non_terminal {
                if let Some(hook) = treq
                    .trace
                    .as_ref()
                    .and_then(|t| t.got_1xx_response.as_ref())
                {
                    hook(code, &resp.header).map_err(RtError::Other)?;
                    // The user is responsible for limiting the number of 1xx
                    // responses they were shown: reset the header limit.
                    self.core_set_read_limit();
                }
                continue;
            }
            break;
        }
        if let Some(tx) = continue_tx {
            if resp.close || treq.req.close {
                drop(tx);
            } else {
                let _ = tx.send(true);
            }
        }
        Ok(resp)
    }

    /// Go's `tryPutIdleConn` for the pool; `ClientConn`s just become free.
    ///
    /// Reports the outcome to the `PutIdleConn` trace hook, except when keep-alives
    /// are disabled, as Go's read loop does.
    fn try_put_idle(self: &Arc<Self>, trace: Option<&ClientTrace>) -> bool {
        let result = self.try_put_idle_err();
        let hook = trace.and_then(|t| t.put_idle_conn.as_ref());
        match result {
            Ok(()) => {
                if let Some(hook) = hook {
                    hook(None);
                }
                true
            }
            Err(e) => {
                if let Some(hook) = hook {
                    if e != ERR_KEEP_ALIVES_DISABLED {
                        hook(Some(&ErrorString(e)));
                    }
                }
                false
            }
        }
    }

    fn try_put_idle_err(self: &Arc<Self>) -> Result<(), &'static str> {
        if self.core.cfg.disable_keep_alives || self.core.cfg.max_idle_conns_per_host < 0 {
            return Err(ERR_KEEP_ALIVES_DISABLED);
        }
        if self.is_broken() {
            return Err("http: putIdleConn: connection is in bad state");
        }
        self.mark_reused();
        if self.is_client_conn {
            let mut g = lock(&self.mu);
            g.in_flight = false;
            return Ok(());
        }
        self.core.put_idle(self.clone())
    }
}

struct BodyState {
    pc: Arc<PersistConn>,
    alive: AtomicBool,
    content_length: i64,
    stop: Mutex<Option<context::StopFunc>>,
    cancel: CancelCauseFunc,
    writer: Mutex<Option<std::thread::JoinHandle<()>>>,
    done: AtomicBool,
    trace: Option<Arc<ClientTrace>>,
}
const MAX_POST_CLOSE_READ_BYTES: i64 = 256 << 10;

impl BodyState {
    /// What Go's read loop does after the body ends: pool or close the
    /// connection, stop watching the context.
    fn finish_conn(&self, reusable: bool, caller_owns_conn: bool) {
        if self.done.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Some(stop) = lock(&self.stop).take() {
            stop();
        }
        if let Some(t) = lock(&self.writer).take() {
            let _ = t.join();
        }
        if caller_owns_conn {
            // The Response body owns the connection (protocol switch).
            return;
        }
        if !reusable {
            let reason = "http: persistConn.readLoop exiting";
            self.pc.close(reason);
        }
        (self.cancel)(Some(Arc::new(ErrorString("net/http: request completed"))));
    }
}

/// Go's `bodyEOFSignal`: tells the connection when its response body ends.
struct BodyEofSignal {
    body: Body,
    state: Arc<BodyState>,
    closed: bool,
    rerr: Option<(io::ErrorKind, String)>,
    fired: bool,
    inner_for_drain: Body,
}
impl BodyEofSignal {
    fn fire(&mut self, body_eof: bool) {
        if self.fired {
            return;
        }
        self.fired = true;
        let st = self.state.clone();
        let mut ok_eof = body_eof;
        let try_drain = !body_eof && st.content_length <= MAX_POST_CLOSE_READ_BYTES;
        if try_drain {
            ok_eof = maybe_drain_body(&mut self.inner_for_drain, &st.pc.conn);
        }
        let alive = st.alive.load(Ordering::SeqCst)
            && ok_eof
            && !st.pc.saw_eof.load(Ordering::SeqCst)
            && st.pc.wrote_request()
            && st.pc.try_put_idle(st.trace.as_deref());
        st.finish_conn(alive, false);
    }
}
impl Read for BodyEofSignal {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        if self.closed {
            return Err(io::Error::other("http: read on closed response body"));
        }
        if let Some((k, m)) = &self.rerr {
            if m == "EOF" {
                return Ok(0);
            }
            return Err(io::Error::new(*k, m.clone()));
        }
        match self.body.read(p) {
            Ok(0) if !p.is_empty() => {
                self.rerr = Some((io::ErrorKind::UnexpectedEof, "EOF".into()));
                self.fire(true);
                Ok(0)
            }
            Ok(n) => Ok(n),
            Err(e) => {
                self.rerr = Some((e.kind(), e.to_string()));
                let canceled = self.state.pc.canceled();
                self.fire(false);
                if let Some(c) = canceled {
                    return Err(io::Error::other(ArcError(c)));
                }
                Err(e)
            }
        }
    }
}
impl ReadCloser for BodyEofSignal {
    fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let saw_eof = matches!(&self.rerr, Some((_, m)) if m == "EOF");
        if !saw_eof {
            self.fire(false);
            return Ok(());
        }
        let r = self.body.close();
        self.fire(true);
        r
    }
}

/// The read half of a switched-protocol body: buffered bytes, then the conn.
struct SwitchedBody {
    br: BufioReader,
    conn: Arc<dyn Conn>,
}
impl Read for SwitchedBody {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        if self.br.buffered() > 0 {
            let n = self.br.buffered().min(p.len());
            return self.br.read(&mut p[..n]);
        }
        self.conn.read(p).map_err(net::NetError::into_io)
    }
}
impl ReadCloser for SwitchedBody {
    fn close(&mut self) -> io::Result<()> {
        self.conn.close().map_err(net::NetError::into_io)
    }
}
struct SwitchedWriter {
    conn: Arc<dyn Conn>,
}
impl super::body::BodyWriter for SwitchedWriter {
    fn write(&self, data: &[u8]) -> io::Result<usize> {
        self.conn.write(data).map_err(net::NetError::into_io)
    }
    fn close_write(&self) -> io::Result<()> {
        match self.conn.as_any().downcast_ref::<net::TCPConn>() {
            Some(t) => t.close_write().map_err(net::NetError::into_io),
            None => Err(io::Error::other("CloseWrite: feature not supported")),
        }
    }
}

/// Whether a failure came from an expired read deadline.
fn rt_error_is_timeout(e: &RtError) -> bool {
    let inner: &BoxError = match e {
        RtError::NothingWritten(e) | RtError::ReadFromServer(e) | RtError::Other(e) => e,
    };
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(&**inner);
    while let Some(err) = cur {
        if let Some(io) = err.downcast_ref::<io::Error>() {
            if io.kind() == io::ErrorKind::TimedOut {
                return true;
            }
        }
        if let Some(n) = err.downcast_ref::<net::NetError>() {
            if net::error::Error::timeout(n) {
                return true;
            }
        }
        cur = err.source();
    }
    false
}

/// Go's `maybeDrainBody`: read up to 256 KB within 50 ms to reuse the conn.
fn maybe_drain_body(body: &mut Body, conn: &Arc<dyn Conn>) -> bool {
    let _ = conn.set_read_deadline(&time::now().add(time::MILLISECOND * 50));
    let mut left = MAX_POST_CLOSE_READ_BYTES + 1;
    let mut buf = [0u8; 8192];
    let drained = loop {
        let want = usize::try_from(left).unwrap_or(buf.len()).min(buf.len());
        match body.read(&mut buf[..want]) {
            Ok(0) => break left > 0,
            Ok(n) => {
                left -= n as i64;
                if left <= 0 {
                    break false;
                }
            }
            Err(_) => break false,
        }
    };
    let _ = conn.set_read_deadline(&Time::default());
    drained
}

/// Transparent gzip decoding (Go's `gzipReader`).
struct GzipReader {
    body: Body,
    zr: Option<crate::compress::gzip::Reader<io::BufReader<Body>>>,
    init_err: Option<(io::ErrorKind, String)>,
    closed: bool,
}
impl Read for GzipReader {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        if self.closed {
            return Err(io::Error::other("http: read on closed response body"));
        }
        if let Some((k, m)) = &self.init_err {
            return Err(io::Error::new(*k, m.clone()));
        }
        if self.zr.is_none() {
            match crate::compress::gzip::Reader::new(self.body.clone()) {
                Ok(z) => self.zr = Some(z),
                Err(e) => {
                    self.init_err = Some((e.kind(), e.to_string()));
                    return Err(e);
                }
            }
        }
        self.zr.as_mut().map_or(Ok(0), |z| z.read(p))
    }
}
impl ReadCloser for GzipReader {
    fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        self.zr = None;
        self.body.close()
    }
}

/// Wraps `body` in transparent gzip decoding (used by the HTTP/2 client).
pub(crate) fn gzip_body(body: Body) -> Body {
    Body::new(GzipReader {
        body,
        zr: None,
        init_err: None,
        closed: false,
    })
}

/// What dialing produced (Go's `persistConn` with or without `alt`).
enum Dialed {
    H1(Arc<PersistConn>),
    /// A built-in HTTP/2 connection (already in the HTTP/2 pool, unless it is
    /// a dedicated `ClientConn`).
    H2(super::h2::transport::ClientConn),
    /// A `TLSNextProto` round tripper bound to the connection.
    Alt(Arc<dyn RoundTripper>),
}

fn h2_pool_key(cm: &ConnectMethod) -> String {
    format!("{}|{}", cm.target_scheme, cm.target_addr)
}

// ---------------------------------------------------------------- Core ops

impl Core {
    fn connect_method_for_request(
        &self,
        treq: &TransportRequest,
    ) -> Result<ConnectMethod, BoxError> {
        let mut cm = ConnectMethod {
            proxy_url: None,
            target_scheme: treq.req.url.scheme.clone(),
            target_addr: canonical_addr(&treq.req.url),
            only_h1: treq.req.requires_http1(),
        };
        if let Some(p) = &self.cfg.proxy {
            cm.proxy_url = p(&treq.req)?;
        }
        Ok(cm)
    }

    fn dec_conns_per_host(&self, key: &ConnKey) {
        if self.cfg.max_conns_per_host <= 0 {
            return;
        }
        let mut pool = lock(&self.pool);
        if let Some(n) = pool.conns_per_host.get_mut(key) {
            *n -= 1;
            if *n <= 0 {
                pool.conns_per_host.remove(key);
            }
        }
        drop(pool);
        self.slot_cv.notify_all();
    }

    fn take_idle(&self, key: &ConnKey) -> Option<Arc<PersistConn>> {
        let mut pool = lock(&self.pool);
        pool.close_idle = false;
        if self.cfg.disable_keep_alives {
            return None;
        }
        let old_time = if self.cfg.idle_conn_timeout.as_nanos() > 0 {
            Instant::now().checked_sub(self.cfg.idle_conn_timeout.to_std())
        } else {
            None
        };
        loop {
            let pc = {
                let list = pool.idle.get_mut(key)?;
                let pc = list.pop();
                if list.is_empty() {
                    pool.idle.remove(key);
                }
                pc?
            };
            pool.lru.retain(|c| !Arc::ptr_eq(c, &pc));
            let too_old = match (old_time, lock(&pc.mu).idle_at) {
                (Some(old), Some(at)) => at < old,
                _ => false,
            };
            if too_old {
                drop(pool);
                pc.close("http: idle connection timeout");
                pool = lock(&self.pool);
                continue;
            }
            if pc.is_broken() || !idle_conn_healthy(&pc) {
                drop(pool);
                pc.close("http: server closed idle connection");
                pool = lock(&self.pool);
                continue;
            }
            return Some(pc);
        }
    }

    fn put_idle(self: &Arc<Self>, pc: Arc<PersistConn>) -> Result<(), &'static str> {
        let mut pool = lock(&self.pool);
        if pool.close_idle {
            return Err("http: putIdleConn: CloseIdleConnections was called");
        }
        let key = pc.key.clone();
        let max_host = usize::try_from(self.cfg.max_idle_conns_per_host()).unwrap_or(0);
        if pool.idle.get(&key).map_or(0, Vec::len) >= max_host {
            return Err("http: putIdleConn: too many idle connections for host");
        }
        lock(&pc.mu).idle_at = Some(Instant::now());
        pool.idle.entry(key.clone()).or_default().push(pc.clone());
        pool.lru.push_back(pc);
        if self.cfg.max_idle_conns != 0 && pool.lru.len() as i64 > self.cfg.max_idle_conns {
            if let Some(oldest) = pool.lru.pop_front() {
                if let Some(l) = pool.idle.get_mut(&oldest.key) {
                    l.retain(|c| !Arc::ptr_eq(c, &oldest));
                    if l.is_empty() {
                        let k = oldest.key.clone();
                        pool.idle.remove(&k);
                    }
                }
                drop(pool);
                oldest.close("http: putIdleConn: too many idle connections");
                self.start_reaper();
                return Ok(());
            }
        }
        drop(pool);
        self.start_reaper();
        Ok(())
    }

    /// One thread per transport closes idle connections after
    /// `IdleConnTimeout` (Go uses a timer per connection).
    fn start_reaper(self: &Arc<Self>) {
        if self.cfg.idle_conn_timeout.as_nanos() <= 0 {
            return;
        }
        let mut started = lock(&self.reaper.0);
        if *started {
            return;
        }
        *started = true;
        let weak: Weak<Core> = Arc::downgrade(self);
        let timeout = self.cfg.idle_conn_timeout.to_std();
        std::thread::spawn(move || loop {
            std::thread::sleep(
                (timeout / 4).clamp(StdDuration::from_millis(5), StdDuration::from_secs(5)),
            );
            let Some(core) = weak.upgrade() else { return };
            let expired: Vec<Arc<PersistConn>> = {
                let mut pool = lock(&core.pool);
                let now = Instant::now();
                let mut out = Vec::new();
                pool.lru.retain(|pc| {
                    let at = lock(&pc.mu).idle_at;
                    if at.is_some_and(|a| now.duration_since(a) >= timeout) {
                        out.push(pc.clone());
                        false
                    } else {
                        true
                    }
                });
                for pc in &out {
                    if let Some(l) = pool.idle.get_mut(&pc.key) {
                        l.retain(|c| !Arc::ptr_eq(c, pc));
                    }
                }
                pool.idle.retain(|_, v| !v.is_empty());
                out
            };
            for pc in expired {
                pc.close("http: idle connection timeout");
            }
        });
    }

    fn get_conn(
        self: &Arc<Self>,
        treq: &TransportRequest,
        cm: &ConnectMethod,
    ) -> Result<Dialed, BoxError> {
        let key = cm.key();
        if let Some(hook) = treq.trace.as_ref().and_then(|t| t.get_conn.as_ref()) {
            hook(&cm.addr());
        }
        let got_conn = |pc: &Arc<PersistConn>, idle_at: Option<Instant>| {
            if let Some(hook) = treq.trace.as_ref().and_then(|t| t.got_conn.as_ref()) {
                hook(httptrace::GotConnInfo {
                    conn: pc.conn.clone(),
                    reused: pc.is_reused(),
                    was_idle: idle_at.is_some(),
                    idle_time: idle_at.map_or(Duration::ZERO, |at| at.elapsed().into()),
                });
            }
        };
        loop {
            if treq.ctx.err().is_some() {
                let e = cause_error(&treq.ctx);
                return Err(
                    if e.downcast_ref::<ErrorString>() == Some(&ERR_REQUEST_CANCELED) {
                        Box::new(ERR_REQUEST_CANCELED_CONN)
                    } else {
                        e
                    },
                );
            }
            if let Some(pc) = self.take_idle(&key) {
                let idle_at = lock(&pc.mu).idle_at;
                got_conn(&pc, idle_at);
                return Ok(Dialed::H1(pc));
            }
            if let Some(alt) = lock(&self.alt_conns).get(&key.to_string()).cloned() {
                return Ok(Dialed::Alt(alt));
            }
            if self.cfg.max_conns_per_host > 0 {
                let mut pool = lock(&self.pool);
                let n = pool.conns_per_host.get(&key).copied().unwrap_or(0);
                if n >= self.cfg.max_conns_per_host {
                    // Wait for a slot or an idle connection, polling the context.
                    let (g, _) = self
                        .slot_cv
                        .wait_timeout(pool, StdDuration::from_millis(10))
                        .unwrap_or_else(|e| e.into_inner());
                    drop(g);
                    continue;
                }
                pool.conns_per_host.insert(key.clone(), n + 1);
            }
            return match self.dial_conn(&treq.ctx, cm, false) {
                Ok(d) => {
                    if let Dialed::H1(pc) = &d {
                        got_conn(pc, None);
                    }
                    if !matches!(d, Dialed::H1(_)) {
                        // Multiplexed connections are not counted per host.
                        self.dec_conns_per_host(&key);
                    }
                    if let Dialed::Alt(rt) = &d {
                        lock(&self.alt_conns).insert(key.to_string(), rt.clone());
                    }
                    Ok(d)
                }
                Err(e) => {
                    self.dec_conns_per_host(&key);
                    Err(e)
                }
            };
        }
    }

    fn dial(&self, ctx: &Context, network: &str, addr: &str) -> Result<Box<dyn Conn>, BoxError> {
        if let Some(f) = &self.cfg.dial_context {
            return f(ctx, network, addr);
        }
        if let Some(f) = &self.cfg.dial {
            return f(network, addr);
        }
        Dialer::default()
            .dial_context(ctx, network, addr)
            .map_err(|e| Box::new(e) as BoxError)
    }

    fn add_tls(
        &self,
        conn: Arc<dyn Conn>,
        name: &str,
        only_h1: bool,
        trace: Option<&ClientTrace>,
    ) -> Result<(Arc<dyn Conn>, Option<Arc<ConnectionState>>), BoxError> {
        let Some(cfg) = self.cfg.tls_client_config.clone() else {
            let _ = conn.close();
            return Err(Box::new(ERR_TLS_BACKEND));
        };
        let next_protos = self.cfg.next_protos(only_h1);
        let name = name.to_owned();
        let timeout = self.cfg.tls_handshake_timeout;
        let (tx, rx) = channel();
        let plain = conn.clone();
        let start = trace.and_then(|t| t.tls_handshake_start.clone());
        std::thread::spawn(move || {
            if let Some(start) = start {
                start();
            }
            let res = cfg.client_conn(Box::new(SharedConn(plain)), &name, &next_protos);
            let _ = tx.send(res);
        });
        let done = |state: &ConnectionState, err: Option<&BoxError>| {
            if let Some(hook) = trace.and_then(|t| t.tls_handshake_done.as_ref()) {
                hook(state, err.map(|e| &**e as &httptrace::HookError));
            }
        };
        let res = if timeout.as_nanos() > 0 {
            match rx.recv_timeout(timeout.to_std()) {
                Ok(r) => r,
                Err(_) => {
                    let _ = conn.close();
                    let err: BoxError =
                        Box::new(TimeoutError("net/http: TLS handshake timeout".into()));
                    done(&ConnectionState::default(), Some(&err));
                    return Err(err);
                }
            }
        } else {
            rx.recv()
                .map_err(|_| -> BoxError { "tls handshake aborted".into() })?
        };
        match res {
            Ok(tls) => {
                let state = tls.tls_connection_state().map(Arc::new);
                done(
                    state.as_deref().unwrap_or(&ConnectionState::default()),
                    None,
                );
                Ok((Arc::from(tls), state))
            }
            Err(e) => {
                let _ = conn.close();
                done(&ConnectionState::default(), Some(&e));
                Err(e)
            }
        }
    }

    fn dial_conn(
        self: &Arc<Self>,
        ctx: &Context,
        cm: &ConnectMethod,
        is_client_conn: bool,
    ) -> Result<Dialed, BoxError> {
        let wrap_err = |e: BoxError| -> BoxError {
            if cm.proxy_url.is_some() {
                return Box::new(ProxyConnectError(e.to_string()));
            }
            e
        };
        let trace = httptrace::context_client_trace(ctx);
        let mut tls_state: Option<Arc<ConnectionState>> = None;
        let mut conn: Arc<dyn Conn>;
        if cm.scheme() == "https" && self.cfg.has_custom_tls_dialer() {
            let c = if let Some(f) = &self.cfg.dial_tls_context {
                f(ctx, "tcp", &cm.addr())
            } else if let Some(f) = &self.cfg.dial_tls {
                f("tcp", &cm.addr())
            } else {
                Err("net/http: Transport.DialTLS or DialTLSContext returned (nil, nil)".into())
            }
            .map_err(wrap_err)?;
            conn = Arc::from(c);
            if let Some(st) = conn.tls_connection_state() {
                if let Some(hook) = trace
                    .as_deref()
                    .and_then(|t| t.tls_handshake_start.as_ref())
                {
                    hook();
                }
                if let Err(e) = conn.handshake() {
                    let _ = conn.close();
                    if let Some(hook) = trace.as_deref().and_then(|t| t.tls_handshake_done.as_ref())
                    {
                        hook(&ConnectionState::default(), Some(&e));
                    }
                    return Err(Box::new(e));
                }
                if let Some(hook) = trace.as_deref().and_then(|t| t.tls_handshake_done.as_ref()) {
                    hook(&st, None);
                }
                tls_state = Some(Arc::new(st));
            }
        } else {
            let c = self.dial(ctx, "tcp", &cm.addr()).map_err(wrap_err)?;
            conn = Arc::from(c);
            if cm.scheme() == "https" {
                let (first_tls_host, _) =
                    net::split_host_port(&cm.addr()).map_err(|e| wrap_err(Box::new(e)))?;
                let (c2, st) = self
                    .add_tls(conn, &first_tls_host, cm.only_h1, trace.as_deref())
                    .map_err(wrap_err)?;
                conn = c2;
                tls_state = st;
            }
        }

        let mut is_proxy = false;
        let mut mutate: Option<Box<dyn Fn(&mut Header) + Send + Sync>> = None;
        match &cm.proxy_url {
            None => {}
            Some(p) if p.scheme == "socks5" || p.scheme == "socks5h" => {
                let auth = p.user.as_ref().map(|u| {
                    (
                        u.username().to_owned(),
                        u.password().unwrap_or("").to_owned(),
                    )
                });
                if let Err(e) = socks5_connect(&*conn, &cm.target_addr, auth.as_ref()) {
                    let _ = conn.close();
                    return Err(e);
                }
            }
            Some(_) if cm.target_scheme == "http" => {
                is_proxy = true;
                let pa = cm.proxy_auth();
                if !pa.is_empty() {
                    mutate = Some(Box::new(move |h: &mut Header| {
                        h.set("Proxy-Authorization", &pa)
                    }));
                }
            }
            Some(p) if cm.target_scheme == "https" => {
                let mut hdr = if let Some(f) = &self.cfg.get_proxy_connect_header {
                    match f(ctx, p, &cm.target_addr) {
                        Ok(h) => h,
                        Err(e) => {
                            let _ = conn.close();
                            return Err(e);
                        }
                    }
                } else {
                    self.cfg.proxy_connect_header.clone()
                };
                let pa = cm.proxy_auth();
                if !pa.is_empty() {
                    hdr.set("Proxy-Authorization", &pa);
                }
                let mut connect_req = Request::default();
                connect_req.method = "CONNECT".into();
                connect_req.url = Url {
                    opaque: cm.target_addr.clone(),
                    ..Url::default()
                };
                connect_req.host = cm.target_addr.clone();
                connect_req.header = hdr;
                let resp = match connect_tunnel(
                    &conn,
                    &connect_req,
                    self.cfg.max_header_response_size(),
                    ctx,
                ) {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = conn.close();
                        return Err(e);
                    }
                };
                if let Some(f) = &self.cfg.on_proxy_connect_response {
                    if let Err(e) = f(ctx, p, &connect_req, &resp) {
                        let _ = conn.close();
                        return Err(e);
                    }
                }
                if resp.status_code != 200 {
                    let _ = conn.close();
                    return Err(match resp.status.split_once(' ') {
                        Some((_, text)) => text.to_owned().into(),
                        None => "unknown status code".into(),
                    });
                }
            }
            Some(_) => {}
        }
        if cm.proxy_url.is_some() && cm.target_scheme == "https" {
            let (c2, st) = self.add_tls(conn, &cm.tls_host(), cm.only_h1, trace.as_deref())?;
            conn = c2;
            tls_state = st;
        }

        // HTTP/2, or a TLSNextProto handler for the negotiated protocol.
        let negotiated = tls_state
            .as_ref()
            .map(|s| s.negotiated_protocol.clone())
            .unwrap_or_default();
        let h2c_requested = tls_state.is_none()
            && cm.proxy_url.is_none()
            && cm.target_scheme == "http"
            && self.cfg.protocols_explicit
            && self.cfg.protocols.unencrypted_http2()
            && !self.cfg.protocols.http1();
        if self.cfg.builtin_h2 && (negotiated == "h2" || h2c_requested) {
            let cc = super::h2::transport::ClientConn::new(
                self.cfg.h2.clone(),
                conn.clone(),
                tls_state.clone(),
                self.cfg.disable_keep_alives,
                is_client_conn,
                None,
            )
            .map_err(|e| Box::new(e) as BoxError)?;
            if !is_client_conn {
                let used = self
                    .h2_pool
                    .add_conn_if_needed(&h2_pool_key(cm), cc.clone());
                if !used {
                    cc.close();
                }
            }
            return Ok(Dialed::H2(cc));
        }
        if h2c_requested {
            let Some(next) = self
                .cfg
                .tls_next_proto
                .get(super::h2::NEXT_PROTO_UNENCRYPTED_HTTP2)
            else {
                let _ = conn.close();
                return Err("http: Transport does not support unencrypted HTTP/2".into());
            };
            let alt = next(&cm.target_addr, Box::new(SharedConn(conn)));
            return Ok(Dialed::Alt(alt));
        }
        if !negotiated.is_empty() && negotiated != "http/1.1" {
            if let Some(next) = self.cfg.tls_next_proto.get(&negotiated) {
                let alt = next(&cm.target_addr, Box::new(SharedConn(conn)));
                return Ok(Dialed::Alt(alt));
            }
        }

        let nwrite = Arc::new(AtomicI64::new(0));
        let saw_eof = Arc::new(AtomicBool::new(false));
        let read_limit = Arc::new(AtomicI64::new(self.cfg.max_header_response_size()));
        let size = usize::try_from(self.cfg.read_buffer_size)
            .ok()
            .filter(|n| *n > 0)
            .unwrap_or(4 << 10);
        let br = BufioReader::with_size(
            PcReader {
                conn: conn.clone(),
                limit: read_limit.clone(),
                saw_eof: saw_eof.clone(),
                max: self.cfg.max_header_response_size(),
            },
            size,
        );
        Ok(Dialed::H1(Arc::new(PersistConn {
            core: self.clone(),
            key: cm.key(),
            conn,
            tls_state,
            br,
            is_proxy,
            mutate_header: mutate,
            mu: Mutex::new(PcMut {
                reserved: false,
                ..PcMut::default()
            }),
            nwrite,
            saw_eof,
            read_limit,
            write_err: Mutex::new(None),
            is_client_conn,
        })))
    }
}

/// Go's `&net.OpError{Op: "proxyconnect", Net: "tcp", Err: err}`.
#[derive(Debug)]
struct ProxyConnectError(String);
impl fmt::Display for ProxyConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "proxyconnect tcp: {}", self.0)
    }
}
impl std::error::Error for ProxyConnectError {}

/// A pooled connection must have nothing buffered and not be at EOF.
fn idle_conn_healthy(pc: &PersistConn) -> bool {
    if pc.br.buffered() > 0 {
        return false;
    }
    if pc.saw_eof.load(Ordering::SeqCst) {
        return false;
    }
    // A zero-length deadline makes a healthy idle socket report a timeout.
    let _ = pc.conn.set_read_deadline(&time::unix(1, 0));
    let mut b = [0u8; 1];
    let res = pc.conn.read(&mut b);
    let _ = pc.conn.set_read_deadline(&Time::default());
    match res {
        Err(e) => net::error::Error::timeout(&e),
        Ok(_) => false,
    }
}

fn connect_tunnel(
    conn: &Arc<dyn Conn>,
    connect_req: &Request,
    max_header: i64,
    ctx: &Context,
) -> Result<Response, BoxError> {
    let deadline = std::time::Duration::from_secs(60);
    let (ctx2, cancel) = ctx.with_timeout(deadline.into());
    let conn2 = conn.clone();
    let stop = ctx2.after_func(move || {
        let _ = conn2.close();
    });
    let result = (|| -> Result<Response, BoxError> {
        let mut w = PcWriter {
            conn: conn.clone(),
            nwrite: Arc::new(AtomicI64::new(0)),
        };
        connect_req.write(&mut w)?;
        let limit = Arc::new(AtomicI64::new(max_header));
        let br = BufioReader::new(PcReader {
            conn: conn.clone(),
            limit,
            saw_eof: Arc::new(AtomicBool::new(false)),
            max: max_header,
        });
        read_response(&br, Some(connect_req))
    })();
    stop();
    cancel();
    if ctx2.err().is_some() && result.is_err() {
        return Err(Box::new(
            ctx2.err().unwrap_or(context::Error::DeadlineExceeded),
        ));
    }
    result
}

/// SOCKS5 CONNECT (RFC 1928) with optional username/password (RFC 1929).
fn socks5_connect(
    conn: &dyn Conn,
    target: &str,
    auth: Option<&(String, String)>,
) -> Result<(), BoxError> {
    fn write_all(conn: &dyn Conn, b: &[u8]) -> Result<(), BoxError> {
        let mut off = 0;
        while off < b.len() {
            off += conn.write(&b[off..])?;
        }
        Ok(())
    }
    fn read_full(conn: &dyn Conn, n: usize) -> Result<Vec<u8>, BoxError> {
        let mut out = vec![0u8; n];
        let mut off = 0;
        while off < n {
            let k = conn.read(&mut out[off..])?;
            if k == 0 {
                return Err("unexpected EOF".into());
            }
            off += k;
        }
        Ok(out)
    }
    let werr = |what: &str, e: BoxError| -> BoxError {
        format!("socks connect tcp {target}: {what}: {e}").into()
    };
    let mut hello = vec![5u8];
    if auth.is_some() {
        hello.extend_from_slice(&[2, 0, 2]);
    } else {
        hello.extend_from_slice(&[1, 0]);
    }
    write_all(conn, &hello).map_err(|e| werr("write", e))?;
    let reply = read_full(conn, 2).map_err(|e| werr("read", e))?;
    if reply[0] != 5 {
        return Err(format!("unexpected protocol version {}", reply[0]).into());
    }
    match reply[1] {
        0 => {}
        2 => {
            let (u, p) =
                auth.ok_or_else(|| -> BoxError { "no acceptable authentication methods".into() })?;
            if u.is_empty() || u.len() > 255 || p.is_empty() || p.len() > 255 {
                return Err("invalid username/password".into());
            }
            let mut b = vec![1u8, u.len() as u8];
            b.extend_from_slice(u.as_bytes());
            b.push(p.len() as u8);
            b.extend_from_slice(p.as_bytes());
            write_all(conn, &b).map_err(|e| werr("write", e))?;
            let r = read_full(conn, 2).map_err(|e| werr("read", e))?;
            if r[0] != 1 {
                return Err(format!("invalid username/password version {}", r[0]).into());
            }
            if r[1] != 0 {
                return Err("authentication failed".into());
            }
        }
        0xff => return Err("no acceptable authentication methods".into()),
        m => return Err(format!("unsupported authentication method {m:#x}").into()),
    }
    let (host, port) = net::split_host_port(target)?;
    let port: u16 = port
        .parse()
        .map_err(|_| -> BoxError { "invalid port".into() })?;
    let mut req = vec![5u8, 1, 0];
    match net::parse_ip(&host).and_then(|ip| std::net::IpAddr::try_from(&ip).ok()) {
        Some(std::net::IpAddr::V4(a)) => {
            req.push(1);
            req.extend_from_slice(&a.octets());
        }
        Some(std::net::IpAddr::V6(a)) => {
            req.push(4);
            req.extend_from_slice(&a.octets());
        }
        None => {
            if host.len() > 255 {
                return Err("name too long".into());
            }
            req.push(3);
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    write_all(conn, &req).map_err(|e| werr("write", e))?;
    let head = read_full(conn, 4).map_err(|e| werr("read", e))?;
    if head[0] != 5 {
        return Err(format!("unexpected protocol version {}", head[0]).into());
    }
    if head[1] != 0 {
        return Err(format!(
            "socks connect tcp {target}: unknown error (code {})",
            head[1]
        )
        .into());
    }
    let skip = match head[3] {
        1 => 4,
        4 => 16,
        3 => usize::from(read_full(conn, 1)?[0]),
        t => return Err(format!("unknown address type {t}").into()),
    };
    read_full(conn, skip + 2)?;
    Ok(())
}

// --------------------------------------------------------------- ClientConn

#[derive(Default)]
struct HookState {
    user_hook: Option<Arc<dyn Fn(&ClientConn) + Send + Sync>>,
    running: bool,
    last_available: i64,
    last_in_flight: i64,
    last_closed: bool,
}

/// Go 1.27's `http.ClientConn`: one dedicated connection managed by the
/// caller, HTTP/1.1 or (when negotiated) HTTP/2.
pub struct ClientConn {
    inner: ClientConnInner,
    core: Arc<Core>,
    hook: Arc<Mutex<HookState>>,
}

#[derive(Clone)]
enum ClientConnInner {
    H1(Arc<PersistConn>),
    H2(super::h2::transport::ClientConn),
}

impl ClientConn {
    pub fn close(&self) -> Result<(), BoxError> {
        match &self.inner {
            ClientConnInner::H1(pc) => pc.close("ClientConn closed"),
            ClientConnInner::H2(cc) => cc.close(),
        }
        self.maybe_run_state_hook();
        Ok(())
    }
    pub fn err(&self) -> Option<String> {
        match &self.inner {
            ClientConnInner::H1(pc) => lock(&pc.mu).closed.clone(),
            ClientConnInner::H2(cc) => cc.err(),
        }
    }
    pub fn available(&self) -> i64 {
        match &self.inner {
            ClientConnInner::H1(pc) => {
                let g = lock(&pc.mu);
                if g.closed.is_some() || g.reserved || g.in_flight {
                    0
                } else {
                    1
                }
            }
            ClientConnInner::H2(cc) => cc.available(),
        }
    }
    pub fn in_flight(&self) -> i64 {
        match &self.inner {
            ClientConnInner::H1(pc) => {
                let g = lock(&pc.mu);
                i64::from(g.closed.is_none() && (g.reserved || g.in_flight))
            }
            ClientConnInner::H2(cc) => cc.in_flight(),
        }
    }
    pub fn reserve(&self) -> Result<(), BoxError> {
        let r: Result<(), BoxError> = match &self.inner {
            ClientConnInner::H1(pc) => {
                let mut g = lock(&pc.mu);
                if let Some(c) = &g.closed {
                    Err(c.clone().into())
                } else if g.reserved || g.in_flight {
                    Err("connection is unavailable".into())
                } else {
                    g.reserved = true;
                    Ok(())
                }
            }
            ClientConnInner::H2(cc) => cc.reserve().map_err(|e| Box::new(e) as BoxError),
        };
        self.maybe_run_state_hook();
        r
    }
    pub fn release(&self) {
        match &self.inner {
            ClientConnInner::H1(pc) => {
                lock(&pc.mu).reserved = false;
            }
            ClientConnInner::H2(cc) => cc.release(),
        }
        self.maybe_run_state_hook();
    }
    pub fn round_trip(&self, req: &Request) -> Result<Response, BoxError> {
        let r = self.round_trip_inner(req);
        self.maybe_run_state_hook();
        r
    }
    fn round_trip_inner(&self, req: &Request) -> Result<Response, BoxError> {
        if req.url == Url::default() {
            self.release();
            return Err("http: nil Request.URL".into());
        }
        let e = validate_headers(&req.header);
        if !e.is_empty() {
            self.release();
            return Err(format!("http: invalid header {e}").into());
        }
        if let Some(t) = req.trailer.get() {
            let e = validate_headers(&t);
            if !e.is_empty() {
                self.release();
                return Err(format!("http: invalid trailer {e}").into());
            }
        }
        if !req.method.is_empty() && !super::token(&req.method) {
            self.release();
            return Err(format!(
                "http: invalid method {}",
                crate::strconv::quote(&req.method)
            )
            .into());
        }
        if req.url.host.is_empty() {
            self.release();
            return Err("http: no Host in request URL".into());
        }
        let (ctx, cancel) = req.context().with_cancel_cause();
        let trace = httptrace::context_client_trace(&ctx);
        match &self.inner {
            ClientConnInner::H1(pc) => {
                let treq = TransportRequest {
                    req: req.clone(),
                    ctx,
                    cancel,
                    extra: Mutex::new(Header::new()),
                    trace,
                };
                match pc.round_trip(&treq) {
                    Ok(mut resp) => {
                        resp.request = Some(Box::new(req.clone()));
                        Ok(resp)
                    }
                    Err(e) => Err(e.into_box()),
                }
            }
            ClientConnInner::H2(cc) => {
                // The caller reserved a slot (or round_trip takes one).
                let c2 = cancel.clone();
                let on_done: Box<dyn FnOnce() + Send> = Box::new(move || {
                    c2(Some(Arc::new(ErrorString("net/http: request completed"))));
                });
                match cc.round_trip(req, &ctx, Some(on_done)) {
                    Ok(mut resp) => {
                        resp.request = Some(Box::new(req.clone()));
                        Ok(resp)
                    }
                    Err(e) => {
                        let boxed = h2_error_to_box(&ctx, e);
                        cancel(Some(Arc::new(ErrorString("net/http: request completed"))));
                        Err(boxed)
                    }
                }
            }
        }
    }
    /// Go's `SetStateHook`.
    pub fn set_state_hook<F: Fn(&ClientConn) + Send + Sync + 'static>(&self, f: F) {
        lock(&self.hook).user_hook = Some(Arc::new(f));
        if let ClientConnInner::H2(cc) = &self.inner {
            let inner = self.inner.clone();
            let core = self.core.clone();
            let hook = self.hook.clone();
            cc.set_state_hook(Some(Arc::new(move || {
                let c = ClientConn {
                    inner: inner.clone(),
                    core: core.clone(),
                    hook: hook.clone(),
                };
                c.maybe_run_state_hook();
            })));
        }
        self.maybe_run_state_hook();
    }
    fn maybe_run_state_hook(&self) {
        let hook = {
            let mut st = lock(&self.hook);
            let Some(h) = st.user_hook.clone() else {
                return;
            };
            if st.running {
                return;
            }
            let available = self.available();
            let in_flight = self.in_flight();
            let closed = self.err().is_some();
            let fire = available > st.last_available
                || in_flight < st.last_in_flight
                || closed != st.last_closed;
            st.last_available = available;
            st.last_in_flight = in_flight;
            st.last_closed = closed;
            if !fire {
                return;
            }
            st.running = true;
            h
        };
        hook(self);
        lock(&self.hook).running = false;
    }
}

impl Drop for ClientConn {
    fn drop(&mut self) {
        let _ = &self.core;
    }
}

// ------------------------------------------------------------ file transport

/// Go's `http.NewFileTransport` result: a [`RoundTripper`] that serves
/// `file:` URLs from a file system.
pub struct FileTransport {
    handler: Arc<dyn Handler>,
}

impl FileTransport {
    /// Go's `NewFileTransport`.
    pub fn new(fs: Arc<dyn FileSystem>) -> Self {
        Self {
            handler: super::fs::file_server(fs),
        }
    }

    /// Go's `NewFileTransportFS`.
    pub fn from_fs(fsys: Arc<dyn crate::io::fs::FS + Send + Sync>) -> Self {
        Self::new(super::fs::fs_adapter(fsys))
    }
}

impl RoundTripper for FileTransport {
    fn round_trip(&self, req: &Request) -> Result<Response, BoxError> {
        let (resp_tx, resp_rx) = channel::<Response>();
        let (data_tx, data_rx) = channel::<Vec<u8>>();
        let handler = self.handler.clone();
        let mut r2 = req.clone();
        let template = Response {
            proto: "HTTP/1.0".into(),
            proto_major: 1,
            header: Header::new(),
            close: true,
            body: Some(Body::new(ChannelBody {
                rx: Mutex::new(data_rx),
                pending: Vec::new(),
            })),
            request: Some(Box::new(req.clone())),
            ..Response::default()
        };
        std::thread::spawn(move || {
            let mut w = PopulateResponse {
                res: Some(template),
                tx: Some(resp_tx),
                data: Some(data_tx),
                wrote_header: false,
                has_content: false,
                sent: false,
            };
            handler.serve_http(&mut w, &mut r2);
            w.finish();
        });
        resp_rx
            .recv()
            .map_err(|_| -> BoxError { "net/http: file transport handler exited".into() })
    }
}

struct ChannelBody {
    rx: Mutex<Receiver<Vec<u8>>>,
    pending: Vec<u8>,
}
impl Read for ChannelBody {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        if self.pending.is_empty() {
            match lock(&self.rx).recv() {
                Ok(v) => self.pending = v,
                Err(_) => return Ok(0),
            }
        }
        let n = self.pending.len().min(p.len());
        p[..n].copy_from_slice(&self.pending[..n]);
        self.pending.drain(..n);
        Ok(n)
    }
}
impl ReadCloser for ChannelBody {}

struct PopulateResponse {
    res: Option<Response>,
    tx: Option<Sender<Response>>,
    data: Option<Sender<Vec<u8>>>,
    wrote_header: bool,
    has_content: bool,
    sent: bool,
}
impl PopulateResponse {
    fn send_response(&mut self) {
        if self.sent {
            return;
        }
        self.sent = true;
        if let (Some(mut res), Some(tx)) = (self.res.take(), self.tx.take()) {
            if self.has_content {
                res.content_length = -1;
            }
            let _ = tx.send(res);
        }
    }
    fn finish(&mut self) {
        if !self.wrote_header {
            self.write_header(500);
        }
        if !self.sent {
            self.send_response();
        }
        self.data = None;
    }
}
impl std::io::Write for PopulateResponse {
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        if !self.wrote_header {
            self.write_header(200);
        }
        self.has_content = true;
        if !self.sent {
            self.send_response();
        }
        if let Some(d) = &self.data {
            let _ = d.send(p.to_vec());
        }
        Ok(p.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl ResponseWriter for PopulateResponse {
    fn header(&mut self) -> &mut Header {
        // Before the response is sent the header lives in the template.
        &mut self.res.as_mut().expect("header after send").header
    }
    fn write_header(&mut self, code: u16) {
        if self.wrote_header {
            return;
        }
        self.wrote_header = true;
        if let Some(r) = self.res.as_mut() {
            r.status_code = code;
            r.status = format!("{} {}", code, super::status_text(code));
        }
    }
}

#[allow(dead_code)]
fn _unused(_: &Url, _: Option<Mutex<()>>, _: Option<&Header>, _: bool) {
    let _ = has_token;
    let _ = basic_auth;
    let _ = time::SECOND;
}
