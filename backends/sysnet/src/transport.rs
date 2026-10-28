//! Go's `http.DefaultTransport` and `http.DefaultClient` over sys sockets.
use crate::dial_context;
use rust_stdlib::net::http::client::Client;
use rust_stdlib::net::http::proxy_from_environment;
use rust_stdlib::net::http::transport::Transport;
use rust_stdlib::time::{Duration, SECOND};
use rust_stdlib_sys::net::Dialer;
use std::sync::{Arc, LazyLock};

/// `net.Dialer.Timeout` of Go's `DefaultTransport`: 30 s.
pub const TIMEOUT: Duration = Duration::from_secs(30);
/// `net.Dialer.KeepAlive` of Go's `DefaultTransport`: 30 s.
pub const KEEP_ALIVE: Duration = Duration::from_secs(30);

/// A new transport with the settings of Go's `http.DefaultTransport`
/// (`net/http/transport.go`), and its own connection pool:
///
/// | Go field | value |
/// | --- | --- |
/// | `Proxy` | `ProxyFromEnvironment` |
/// | `DialContext` | `net.Dialer{Timeout: 30s, KeepAlive: 30s}` |
/// | `ForceAttemptHTTP2` | `true` |
/// | `MaxIdleConns` | `100` |
/// | `IdleConnTimeout` | `90s` |
/// | `TLSHandshakeTimeout` | `10s` |
/// | `ExpectContinueTimeout` | `1s` |
///
/// Like `DefaultTransport.(*http.Transport).Clone()`, adjust the result with
/// struct-update syntax (`Transport { max_idle_conns_per_host: 8, ..transport() }`).
///
/// # HTTPS
///
/// With the `tls` feature (on by default) the transport does HTTPS the way
/// Go's does. `TLSClientConfig` is nil in Go, which means the `crypto/tls`
/// defaults: the system root pool (as `x509.SystemCertPool` loads it), the
/// default minimum version, certificate and host name verification, and
/// `h2` then `http/1.1` through ALPN (`ForceAttemptHTTP2`). Here the same
/// defaults are a `rust_stdlib_tls::tls::Config::new()`, set as
/// `tls_client_config`. Verification cannot be disabled by this crate; to
/// trust other roots, replace `tls_client_config` with a `Config` that sets
/// `root_cas`.
///
/// Without the `tls` feature (`default-features = false`) this crate has no
/// third-party dependencies and the transport is **http-only**:
/// `tls_client_config` stays `None` and an `https` request fails with the
/// root crate's "https requests need Transport.TLSClientConfig from a TLS
/// backend" error, rather than silently downgrading. Set `tls_client_config`
/// yourself to enable HTTPS.
pub fn transport() -> Transport {
    let dialer = Dialer {
        timeout: TIMEOUT.nanoseconds(),
        keep_alive: KEEP_ALIVE.nanoseconds(),
        ..Dialer::default()
    };
    Transport {
        proxy: Some(Arc::new(proxy_from_environment)),
        dial_context: Some(dial_context(dialer)),
        force_attempt_http2: true,
        max_idle_conns: 100,
        idle_conn_timeout: Duration::from_secs(90),
        tls_handshake_timeout: Duration::from_secs(10),
        expect_continue_timeout: SECOND,
        tls_client_config: tls_client_config(),
        ..Transport::default()
    }
}

/// Go's nil `TLSClientConfig`: the TLS defaults, with system roots. Every
/// transport built here shares this one value, so
/// [`uses_default_tls`] can tell it apart from a caller's own config.
#[cfg(feature = "tls")]
static DEFAULT_TLS: LazyLock<Arc<dyn rust_stdlib::net::http::TlsConfig>> =
    LazyLock::new(|| Arc::new(rust_stdlib_tls::tls::Config::new()));

#[cfg(feature = "tls")]
fn tls_client_config() -> Option<Arc<dyn rust_stdlib::net::http::TlsConfig>> {
    Some(Arc::clone(&DEFAULT_TLS))
}

#[cfg(not(feature = "tls"))]
fn tls_client_config() -> Option<Arc<dyn rust_stdlib::net::http::TlsConfig>> {
    None
}

/// Whether `transport` uses the TLS defaults, the equivalent of Go's
/// `TLSClientConfig == nil`: no config at all, or the shared default config
/// this crate installs. A caller-supplied config returns `false`.
pub fn uses_default_tls(transport: &Transport) -> bool {
    match &transport.tls_client_config {
        None => true,
        #[cfg(feature = "tls")]
        Some(config) => Arc::ptr_eq(config, &DEFAULT_TLS),
        #[cfg(not(feature = "tls"))]
        Some(_) => false,
    }
}

static DEFAULT_TRANSPORT: LazyLock<Arc<Transport>> = LazyLock::new(|| Arc::new(transport()));

/// Go's `http.DefaultTransport`: one process-wide [`transport`], so every
/// client built from it shares a connection pool.
pub fn default_transport() -> Arc<Transport> {
    DEFAULT_TRANSPORT.clone()
}

/// Go's `http.DefaultClient`, using [`default_transport`] (so, with 30 s TCP
/// keep-alive) rather than the root crate's keep-alive-less default.
///
/// **HTTPS needs the `tls` feature, which is on by default.** With
/// `default-features = false` this client is http-only and every `https`
/// request fails with an error. See [`transport`].
pub fn default_client() -> Client {
    Client {
        transport: Some(default_transport()),
        ..Client::default()
    }
}
