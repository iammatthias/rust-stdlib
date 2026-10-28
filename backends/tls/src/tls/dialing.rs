//! `tls.Dial`, `tls.DialWithDialer`, `tls.Dialer`, `tls.Listen` and `tls.NewListener`.
use super::config::Config;
use super::conn::{client, server, Conn};
use super::error::Error;
use rust_stdlib::{
    context::{self, Context},
    net::{AddrRef, Conn as NetConn, Dialer as NetDialer, Listener as NetListener, NetError},
};
use std::any::Any;
use std::sync::Arc;

fn dial_inner(
    dialer: &NetDialer,
    ctx: &Context,
    network: &str,
    addr: &str,
    config: Option<Arc<Config>>,
) -> Result<Conn, Error> {
    let raw = dialer.dial_context(ctx, network, addr)?;
    let hostname = match addr.rfind(':') {
        Some(i) => &addr[..i],
        None => addr,
    };
    let mut config = config.unwrap_or_default();
    if config.server_name.is_empty() {
        let mut c = (*config).clone();
        c.server_name = hostname
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        config = Arc::new(c);
    }
    let conn = client(raw, config);
    if let Err(e) = conn.handshake_context(ctx) {
        let _ = conn.net_conn().close();
        return Err(e);
    }
    Ok(conn)
}

/// Go's `tls.Dial`: connects to `addr` and performs the TLS handshake.
/// `config` `None` is Go's nil config.
pub fn dial(network: &str, addr: &str, config: Option<Arc<Config>>) -> Result<Conn, Error> {
    dial_with_dialer(&NetDialer::default(), network, addr, config)
}

/// Go's `tls.DialWithDialer`: the dialer's timeout and deadline bound the
/// connect and the handshake together.
pub fn dial_with_dialer(
    dialer: &NetDialer,
    network: &str,
    addr: &str,
    config: Option<Arc<Config>>,
) -> Result<Conn, Error> {
    let mut ctx = Context::background();
    let mut cancels: Vec<context::CancelFunc> = Vec::new();
    if dialer.timeout.as_nanos() > 0 {
        let (c, f) = ctx.with_timeout(dialer.timeout);
        ctx = c;
        cancels.push(f);
    }
    if !dialer.deadline.is_zero() {
        let remaining = dialer.deadline.unix() - rust_stdlib::time::now().unix();
        let remaining = std::time::Duration::from_secs(remaining.max(0) as u64);
        let (c, f) = ctx.with_deadline(std::time::Instant::now() + remaining);
        ctx = c;
        cancels.push(f);
    }
    let r = dial_inner(dialer, &ctx, network, addr, config);
    for c in cancels {
        c();
    }
    r
}

/// Go's `tls.Dialer`: dial options and a TLS configuration.
#[derive(Clone, Default)]
pub struct Dialer {
    /// The dialer for the underlying connection; the zero value if `None`.
    pub net_dialer: Option<NetDialer>,
    /// The TLS configuration; defaults if `None`.
    pub config: Option<Arc<Config>>,
}

impl Dialer {
    /// Go's `Dialer.Dial`.
    pub fn dial(&self, network: &str, addr: &str) -> Result<Conn, Error> {
        self.dial_context(&Context::background(), network, addr)
    }
    /// Go's `Dialer.DialContext`: the handshake is bound to `ctx` too.
    pub fn dial_context(&self, ctx: &Context, network: &str, addr: &str) -> Result<Conn, Error> {
        let nd = self.net_dialer.clone().unwrap_or_default();
        dial_inner(&nd, ctx, network, addr, self.config.clone())
    }
}

/// The listener returned by [`listen`] and [`Listener::new`].
pub struct Listener {
    inner: Box<dyn NetListener>,
    config: Arc<Config>,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener")
            .field("addr", &self.inner.addr().map(|a| a.to_string()))
            .finish()
    }
}

impl NetListener for Listener {
    fn accept(&self) -> Result<Box<dyn NetConn>, NetError> {
        let c = self.inner.accept()?;
        Ok(Box::new(server(c, self.config.clone())))
    }
    fn close(&self) -> Result<(), NetError> {
        self.inner.close()
    }
    fn addr(&self) -> Option<AddrRef> {
        self.inner.addr()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Listener {
    /// Go's `tls.NewListener`: a listener whose accepted connections are TLS
    /// servers.
    pub fn new(inner: Box<dyn NetListener>, config: Arc<Config>) -> Self {
        Self { inner, config }
    }
}

/// Go's `tls.Listen`: listens on `laddr` for TLS connections. The config must
/// provide a certificate, `get_certificate` or `get_config_for_client`.
pub fn listen(network: &str, laddr: &str, config: Arc<Config>) -> Result<Listener, Error> {
    if config.certificates.is_empty()
        && config.get_certificate.is_none()
        && config.get_config_for_client.is_none()
    {
        return Err(Error::new(
            "tls: neither Certificates, GetCertificate, nor GetConfigForClient set in Config",
        ));
    }
    let l = rust_stdlib::net::listen(network, laddr)?;
    Ok(Listener::new(l, config))
}
