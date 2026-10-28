//! Go's `Dial`, `Dialer`, `Listen` and `ListenConfig` over `std::net`,
//! ported from `net/dial.go` and the socket-type constructors (see NOTICE):
//! deadline splitting across addresses, RFC 6555 "Happy Eyeballs" fallback and
//! context cancellation.
//!
//! `std` cannot bind a socket before connecting, set socket options before
//! `bind`/`connect`, or open raw (`ip:`) and `unixpacket` sockets, so a
//! `LocalAddr` on TCP/Unix dials, `Control`, IP networks and `unixpacket`
//! report an error or are absent; each is recorded in `docs/api/net.json`.
//!
//! # Keep-alive
//!
//! Go's `Dialer.KeepAlive`, `Dialer.KeepAliveConfig` and the matching
//! `ListenConfig` fields set `SO_KEEPALIVE` and its timers, which needs a
//! system call `std` lacks and this crate (`forbid(unsafe_code)`) cannot make.
//! They are therefore not fields here: an option that is silently ignored
//! would be a trap. Use `rust_stdlib_sys::net::Dialer` (or `ListenConfig`)
//! from the `rust-stdlib-sys` crate, which applies Go's defaults (15 s idle,
//! 15 s interval, 9 probes) and accepts both options:
//!
//! ```ignore
//! use rust_stdlib_sys::net::Dialer;
//!
//! let dialer = Dialer {
//!     timeout: 30_000_000_000,   // nanoseconds, like Go's time.Duration
//!     keep_alive: 30_000_000_000, // negative disables keep-alive
//!     ..Dialer::default()
//! };
//! let conn = dialer.dial("tcp", "example.com:80")?;
//! # Ok::<(), rust_stdlib_sys::net::OpError>(())
//! ```
//!
//! To give an [`http::transport::Transport`](crate::net::http::transport::Transport)
//! keep-alive connections, set its `dial_context` to a closure that calls the
//! sys dialer and wraps the result in a type implementing [`Conn`]; see the
//! `Transport` documentation.
use super::addr::{TCPAddr, UDPAddr, UnixAddr};
use super::conn::{op_error, Conn, Listener, PacketConn};
use super::error::{AddrError, AddrRef, NetError, UnknownNetworkError};
use super::netip::AddrPort;
use super::resolver::{ResolvedAddr, Resolver, DEFAULT_RESOLVER};
use super::sock::{TCPConn, TCPListener, UDPConn};
use crate::context::{self, Context};
use crate::time::{now, Duration, Time};
use std::net::{IpAddr, SocketAddr, SocketAddrV6, TcpListener, TcpStream, UdpSocket};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Instant;

const SANE_MINIMUM: std::time::Duration = std::time::Duration::from_secs(2);

/// `net.KeepAliveConfig`: TCP keep-alive options. This crate cannot apply
/// them (see the module notes); use `rust_stdlib_sys::net::KeepAliveConfig`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeepAliveConfig {
    /// Whether keep-alive probes are enabled.
    pub enable: bool,
    /// Idle time before the first probe.
    pub idle: Duration,
    /// Time between probes.
    pub interval: Duration,
    /// Unanswered probes before the connection is dropped.
    pub count: i32,
}

/// `net.Dialer`: options for connecting to an address.
#[derive(Clone, Default)]
pub struct Dialer {
    /// Maximum time a dial waits for a connect to complete; zero is none.
    pub timeout: Duration,
    /// Absolute time after which dials fail; the zero `Time` is none.
    pub deadline: Time,
    /// The local address to dial from (UDP only; see the module notes).
    pub local_addr: Option<AddrRef>,
    /// Deprecated; fast fallback is on unless `fallback_delay` is negative.
    pub dual_stack: bool,
    /// Wait before starting the fallback connection; zero means 300ms and a
    /// negative value disables fast fallback.
    pub fallback_delay: Duration,
    /// An alternate resolver.
    pub resolver: Option<Arc<Resolver>>,
    /// A context whose cancellation cancels the dial (Go's `Cancel` channel).
    pub cancel: Option<Context>,
    /// Go's `Control`: setting it makes dials fail (see `unsupported`).
    pub control: Option<super::unsupported::ControlFn>,
    /// Go's `ControlContext`: setting it makes dials fail.
    pub control_context: Option<super::unsupported::ControlFn>,
    /// Go's `SetMultipathTCP`/`MultipathTCP`: recorded only; connections use
    /// plain TCP.
    pub multipath_tcp: bool,
}

fn ctx_error(ctx: &Context) -> NetError {
    match ctx.err() {
        Some(context::Error::Canceled) => NetError::Canceled,
        _ => NetError::Timeout,
    }
}

fn partial_deadline(
    now: Instant,
    deadline: Instant,
    addrs_remaining: usize,
) -> Result<Instant, NetError> {
    if deadline <= now {
        return Err(NetError::Timeout);
    }
    let remaining = deadline - now;
    let mut timeout = remaining / addrs_remaining as u32;
    if timeout < SANE_MINIMUM {
        timeout = if remaining < SANE_MINIMUM {
            remaining
        } else {
            SANE_MINIMUM
        };
    }
    Ok(now + timeout)
}

/// `parseNetwork`: the address family part of `network` and the IP protocol.
pub(crate) fn parse_network(network: &str, needs_proto: bool) -> Result<(String, i32), NetError> {
    match network.rfind(':') {
        None => {
            match network {
                "tcp" | "tcp4" | "tcp6" | "udp" | "udp4" | "udp6" | "unix" | "unixgram"
                | "unixpacket" => {}
                "ip" | "ip4" | "ip6" => {
                    if needs_proto {
                        return Err(UnknownNetworkError(network.into()).into());
                    }
                }
                _ => return Err(UnknownNetworkError(network.into()).into()),
            }
            Ok((network.into(), 0))
        }
        Some(i) => {
            let afnet = &network[..i];
            match afnet {
                "ip" | "ip4" | "ip6" => {
                    let protostr = &network[i + 1..];
                    let (proto, n, ok) = super::ip::dtoi(protostr);
                    if ok && n == protostr.len() {
                        return Ok((afnet.into(), proto));
                    }
                    match super::dnsconf::lookup_protocol(protostr) {
                        Some(p) => Ok((afnet.into(), p)),
                        None => Err(AddrError {
                            err: "unknown IP protocol specified".into(),
                            addr: protostr.into(),
                        }
                        .into()),
                    }
                }
                _ => Err(UnknownNetworkError(network.into()).into()),
            }
        }
    }
}

fn zone_index(zone: &str) -> u32 {
    if zone.is_empty() {
        return 0;
    }
    zone.parse().unwrap_or_else(|_| {
        super::interface::interface_by_name(zone)
            .map(|i| i.index as u32)
            .unwrap_or(0)
    })
}

fn ip6_supported() -> bool {
    static V6: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *V6.get_or_init(|| UdpSocket::bind("[::1]:0").is_ok())
}

fn to_sock_addr(ip: &super::ip::IP, port: i32, zone: &str) -> Option<SocketAddr> {
    let ip = IpAddr::try_from(ip).ok()?;
    Some(match ip {
        IpAddr::V4(a) => SocketAddr::new(IpAddr::V4(a), port as u16),
        IpAddr::V6(a) => SocketAddr::V6(SocketAddrV6::new(a, port as u16, 0, zone_index(zone))),
    })
}

fn is_wild(ip: &super::ip::IP) -> bool {
    ip.0.is_empty() || ip.is_unspecified()
}

fn loopback_for(net: &str) -> IpAddr {
    if net.ends_with('6') {
        IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
    } else {
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    }
}

/// The address to bind to for a listen on `net` with `laddr`.
fn listen_sock_addr(net: &str, ip: &super::ip::IP, port: i32, zone: &str) -> Option<SocketAddr> {
    if is_wild(ip) {
        let v6 = match net.chars().last() {
            Some('4') => false,
            Some('6') => true,
            _ => ip6_supported(),
        };
        let unspec = if v6 {
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        };
        return Some(SocketAddr::new(unspec, port as u16));
    }
    to_sock_addr(ip, port, zone)
}

fn unsupported(what: &str) -> NetError {
    NetError::other(format!("{what} is not supported (std has no equivalent)"))
}

impl Dialer {
    fn resolver(&self) -> &Resolver {
        self.resolver.as_deref().unwrap_or(&DEFAULT_RESOLVER)
    }

    fn dual_stack(&self) -> bool {
        self.fallback_delay.as_nanos() >= 0
    }

    fn fallback_delay(&self) -> std::time::Duration {
        if self.fallback_delay.as_nanos() > 0 {
            self.fallback_delay.to_std()
        } else {
            std::time::Duration::from_millis(300)
        }
    }

    fn deadline_of(&self, ctx: &Context, nowi: Instant) -> Option<Instant> {
        let mut earliest: Option<Instant> = None;
        let min = |a: Option<Instant>, b: Option<Instant>| match (a, b) {
            (None, b) => b,
            (a, None) => a,
            (Some(a), Some(b)) => Some(a.min(b)),
        };
        if self.timeout.as_nanos() != 0 {
            let d = self.timeout.as_nanos();
            earliest = Some(if d > 0 {
                nowi + std::time::Duration::from_nanos(d as u64)
            } else {
                nowi - std::time::Duration::from_nanos(d.unsigned_abs())
            });
        }
        earliest = min(earliest, ctx.deadline());
        if !self.deadline.is_zero() {
            let rem = self.deadline.sub(&now()).as_nanos();
            let d = if rem >= 0 {
                nowi + std::time::Duration::from_nanos(rem as u64)
            } else {
                nowi - std::time::Duration::from_nanos(rem.unsigned_abs())
            };
            earliest = min(earliest, Some(d));
        }
        earliest
    }

    fn dial_ctx(&self, ctx: &Context) -> (Context, Box<dyn FnOnce() + Send>) {
        let mut ctx = ctx.clone();
        let mut cancels: Vec<context::CancelFunc> = Vec::new();
        if let Some(d) = self.deadline_of(&ctx, Instant::now()) {
            if ctx.deadline().is_none_or(|cd| d < cd) {
                let (sub, c) = ctx.with_deadline(d);
                ctx = sub;
                cancels.push(c);
            }
        }
        if let Some(old) = &self.cancel {
            let (sub, c) = ctx.with_cancel();
            let c2 = c.clone();
            let old = old.clone();
            let subc = sub.clone();
            std::thread::spawn(move || loop {
                if old
                    .done()
                    .wait_timeout(crate::time::Duration::from_millis(10))
                {
                    c2();
                    return;
                }
                if subc.done().is_done() {
                    return;
                }
            });
            ctx = sub;
            cancels.push(c);
        }
        (
            ctx,
            Box::new(move || {
                for c in cancels {
                    c();
                }
            }),
        )
    }

    /// `Dialer.Dial`: connects to `address` on `network`.
    pub fn dial(&self, network: &str, address: &str) -> Result<Box<dyn Conn>, NetError> {
        self.dial_context(&Context::background(), network, address)
    }

    /// `Dialer.DialContext`: connects using `ctx`.
    pub fn dial_context(
        &self,
        ctx: &Context,
        network: &str,
        address: &str,
    ) -> Result<Box<dyn Conn>, NetError> {
        let (ctx, cancel) = self.dial_ctx(ctx);
        let res = self.dial_inner(&ctx, network, address);
        cancel();
        res
    }

    fn dial_inner(
        &self,
        ctx: &Context,
        network: &str,
        address: &str,
    ) -> Result<Box<dyn Conn>, NetError> {
        if self.control.is_some() || self.control_context.is_some() {
            return Err(op_error(
                "dial",
                network,
                None,
                None,
                super::unsupported::needs_sys("Dialer.Control"),
            ));
        }
        let addrs = self
            .resolver()
            .resolve_addr_list(ctx, "dial", network, address, self.local_addr.as_deref())
            .map_err(|e| op_error("dial", network, None, None, e))?;
        let sd = SysDialer {
            d: self.clone(),
            network: network.into(),
            address: address.into(),
        };
        let (primaries, fallbacks) = if self.dual_stack() && network == "tcp" {
            partition(addrs)
        } else {
            (addrs, Vec::new())
        };
        sd.dial_parallel(ctx, primaries, fallbacks)
    }

    /// `Dialer.DialTCP`.
    pub fn dial_tcp(
        &self,
        ctx: &Context,
        network: &str,
        laddr: &AddrPort,
        raddr: &AddrPort,
    ) -> Result<TCPConn, NetError> {
        let (ctx, cancel) = self.dial_ctx(ctx);
        let l = super::addr::tcp_addr_from_addr_port(laddr);
        let r = super::addr::tcp_addr_from_addr_port(raddr);
        let res = dial_tcp_with(&ctx, Some(self), network, Some(&l), Some(&r));
        cancel();
        res
    }

    /// `Dialer.DialUDP`.
    pub fn dial_udp(
        &self,
        ctx: &Context,
        network: &str,
        laddr: &AddrPort,
        raddr: &AddrPort,
    ) -> Result<UDPConn, NetError> {
        let (ctx, cancel) = self.dial_ctx(ctx);
        let l = super::addr::udp_addr_from_addr_port(laddr);
        let r = super::addr::udp_addr_from_addr_port(raddr);
        let res = dial_udp_with(&ctx, Some(self), network, Some(&l), Some(&r));
        cancel();
        res
    }

    /// `Dialer.DialUnix`.
    #[cfg(unix)]
    pub fn dial_unix(
        &self,
        ctx: &Context,
        network: &str,
        laddr: Option<&UnixAddr>,
        raddr: Option<&UnixAddr>,
    ) -> Result<super::sock::UnixConn, NetError> {
        let (ctx, cancel) = self.dial_ctx(ctx);
        let res = dial_unix_with(&ctx, network, laddr, raddr);
        cancel();
        res
    }
}

/// An address list entry that can be dialed.
fn partition(addrs: Vec<ResolvedAddr>) -> (Vec<ResolvedAddr>, Vec<ResolvedAddr>) {
    let (mut primaries, mut fallbacks) = (Vec::new(), Vec::new());
    let mut primary_label = false;
    for (i, a) in addrs.into_iter().enumerate() {
        let label = a.is_ipv4();
        if i == 0 || label == primary_label {
            primary_label = label;
            primaries.push(a);
        } else {
            fallbacks.push(a);
        }
    }
    (primaries, fallbacks)
}

struct SysDialer {
    d: Dialer,
    network: String,
    address: String,
}

impl SysDialer {
    fn dial_parallel(
        &self,
        ctx: &Context,
        primaries: Vec<ResolvedAddr>,
        fallbacks: Vec<ResolvedAddr>,
    ) -> Result<Box<dyn Conn>, NetError> {
        if fallbacks.is_empty() {
            return self.dial_serial(ctx, &primaries);
        }
        type Res = (bool, Result<Box<dyn Conn>, NetError>);
        let (tx, rx) = mpsc::channel::<Res>();
        let spawn = |primary: bool, list: Vec<ResolvedAddr>| -> context::CancelFunc {
            let (rctx, cancel) = ctx.with_cancel();
            let tx = tx.clone();
            let sd = SysDialer {
                d: self.d.clone(),
                network: self.network.clone(),
                address: self.address.clone(),
            };
            std::thread::spawn(move || {
                let r = sd.dial_serial(&rctx, &list);
                if let Err(mpsc::SendError((_, Ok(c)))) = tx.send((primary, r)) {
                    let _ = c.close();
                }
            });
            cancel
        };
        let primary_cancel = spawn(true, primaries);
        let mut fallback_cancel: Option<context::CancelFunc> = None;
        let mut fallbacks = Some(fallbacks);
        let fb_at = Instant::now() + self.d.fallback_delay();
        let (mut primary, mut fallback): (Option<NetError>, Option<NetError>) = (None, None);
        let finish = |winner: Box<dyn Conn>| {
            primary_cancel();
            Ok(winner)
        };
        loop {
            let wait = if fallbacks.is_some() {
                fb_at.saturating_duration_since(Instant::now())
            } else {
                std::time::Duration::from_secs(3600)
            };
            match rx.recv_timeout(wait) {
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if let Some(list) = fallbacks.take() {
                        fallback_cancel = Some(spawn(false, list));
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(primary
                        .or(fallback)
                        .unwrap_or_else(|| NetError::other("no suitable address found")));
                }
                Ok((is_primary, Ok(c))) => {
                    if let Some(f) = &fallback_cancel {
                        f();
                    }
                    let _ = is_primary;
                    return finish(c);
                }
                Ok((is_primary, Err(e))) => {
                    if is_primary {
                        primary = Some(e);
                    } else {
                        fallback = Some(e);
                    }
                    if primary.is_some() && fallback.is_some() {
                        primary_cancel();
                        if let Some(f) = &fallback_cancel {
                            f();
                        }
                        return Err(primary.take().unwrap());
                    }
                    if is_primary {
                        if let Some(list) = fallbacks.take() {
                            fallback_cancel = Some(spawn(false, list));
                        }
                    }
                }
            }
        }
    }

    fn dial_serial(&self, ctx: &Context, ras: &[ResolvedAddr]) -> Result<Box<dyn Conn>, NetError> {
        let mut first_err: Option<NetError> = None;
        for (i, ra) in ras.iter().enumerate() {
            if ctx.err().is_some() {
                return Err(op_error(
                    "dial",
                    &self.network,
                    self.d.local_addr.clone(),
                    Some(ra.to_addr()),
                    ctx_error(ctx),
                ));
            }
            let mut dial_ctx = ctx.clone();
            let mut cancel: Option<context::CancelFunc> = None;
            if let Some(deadline) = ctx.deadline() {
                match partial_deadline(Instant::now(), deadline, ras.len() - i) {
                    Err(e) => {
                        if first_err.is_none() {
                            first_err = Some(op_error(
                                "dial",
                                &self.network,
                                self.d.local_addr.clone(),
                                Some(ra.to_addr()),
                                e,
                            ));
                        }
                        break;
                    }
                    Ok(pd) => {
                        if pd < deadline {
                            let (sub, c) = ctx.with_deadline(pd);
                            dial_ctx = sub;
                            cancel = Some(c);
                        }
                    }
                }
            }
            let r = self.dial_single(&dial_ctx, ra);
            if let Some(c) = cancel {
                c();
            }
            match r {
                Ok(c) => return Ok(c),
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }
        Err(first_err.unwrap_or_else(|| {
            op_error(
                "dial",
                &self.network,
                None,
                None,
                NetError::other("missing address"),
            )
        }))
    }

    fn dial_single(&self, ctx: &Context, ra: &ResolvedAddr) -> Result<Box<dyn Conn>, NetError> {
        let trace = super::nettrace::from_context(ctx);
        let ra_text = trace.as_ref().map(|_| ra.to_addr().to_string());
        if let (Some(t), Some(text)) = (trace.as_ref(), ra_text.as_ref()) {
            if let Some(start) = &t.connect_start {
                start(&self.network, text);
            }
        }
        let result = self.dial_single_inner(ctx, ra);
        if let (Some(t), Some(text)) = (trace.as_ref(), ra_text.as_ref()) {
            if let Some(done) = &t.connect_done {
                done(&self.network, text, result.as_ref().err());
            }
        }
        result
    }

    fn dial_single_inner(
        &self,
        ctx: &Context,
        ra: &ResolvedAddr,
    ) -> Result<Box<dyn Conn>, NetError> {
        let la = self.d.local_addr.clone();
        let wrap = |e: NetError| op_error("dial", &self.network, la.clone(), Some(ra.to_addr()), e);
        match ra {
            ResolvedAddr::Tcp(r) => {
                let l = la
                    .as_deref()
                    .and_then(|a| a.as_any().downcast_ref::<TCPAddr>());
                connect_tcp(ctx, &self.network, l, r)
                    .map(|c| Box::new(c) as Box<dyn Conn>)
                    .map_err(wrap)
            }
            ResolvedAddr::Udp(r) => {
                let l = la
                    .as_deref()
                    .and_then(|a| a.as_any().downcast_ref::<UDPAddr>());
                connect_udp(&self.network, l, r)
                    .map(|c| Box::new(c) as Box<dyn Conn>)
                    .map_err(wrap)
            }
            #[cfg(unix)]
            ResolvedAddr::Unix(r) => {
                let l = la
                    .as_deref()
                    .and_then(|a| a.as_any().downcast_ref::<UnixAddr>());
                connect_unix(ctx, &self.network, l, r)
                    .map(|c| Box::new(c) as Box<dyn Conn>)
                    .map_err(wrap)
            }
            _ => Err(wrap(unsupported("dialing an IP network"))),
        }
    }
}

fn connect_with_ctx(ctx: &Context, addr: SocketAddr) -> Result<TcpStream, NetError> {
    let timeout = ctx
        .deadline()
        .map(|d| d.saturating_duration_since(Instant::now()));
    if ctx.err().is_some() {
        return Err(ctx_error(ctx));
    }
    if let Some(t) = timeout {
        if t.is_zero() {
            return Err(NetError::Timeout);
        }
    }
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let r = match timeout {
            Some(t) => TcpStream::connect_timeout(&addr, t),
            None => TcpStream::connect(addr),
        };
        let _ = tx.send(r);
    });
    loop {
        match rx.recv_timeout(std::time::Duration::from_millis(5)) {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => {
                if e.kind() == std::io::ErrorKind::TimedOut {
                    return Err(NetError::Timeout);
                }
                return Err(NetError::from_io("connect", &e));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if ctx.err().is_some() {
                    return Err(ctx_error(ctx));
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(NetError::Canceled),
        }
    }
}

fn connect_tcp(
    ctx: &Context,
    network: &str,
    laddr: Option<&TCPAddr>,
    raddr: &TCPAddr,
) -> Result<TCPConn, NetError> {
    if let Some(l) = laddr {
        if !(is_wild(&l.ip) && l.port == 0) {
            return Err(unsupported("dialing from a TCP local address"));
        }
    }
    let addr = if is_wild(&raddr.ip) {
        SocketAddr::new(loopback_for(network), raddr.port as u16)
    } else {
        to_sock_addr(&raddr.ip, raddr.port, &raddr.zone).ok_or_else(|| {
            NetError::from(AddrError {
                err: "invalid IP address".into(),
                addr: raddr.ip.to_string(),
            })
        })?
    };
    let stream = connect_with_ctx(ctx, addr)?;
    Ok(TCPConn::new(stream, network))
}

fn connect_udp(
    network: &str,
    laddr: Option<&UDPAddr>,
    raddr: &UDPAddr,
) -> Result<UDPConn, NetError> {
    let dest = if is_wild(&raddr.ip) {
        SocketAddr::new(loopback_for(network), raddr.port as u16)
    } else {
        to_sock_addr(&raddr.ip, raddr.port, &raddr.zone).ok_or_else(|| {
            NetError::from(AddrError {
                err: "invalid IP address".into(),
                addr: raddr.ip.to_string(),
            })
        })?
    };
    let bind = match laddr {
        Some(l) if !(is_wild(&l.ip) && l.port == 0) => {
            listen_sock_addr(network, &l.ip, l.port, &l.zone)
                .ok_or_else(|| NetError::other("invalid local address"))?
        }
        _ => {
            if dest.is_ipv4() {
                "0.0.0.0:0".parse().unwrap()
            } else {
                "[::]:0".parse().unwrap()
            }
        }
    };
    let s = UdpSocket::bind(bind).map_err(|e| NetError::from_io("bind", &e))?;
    s.connect(dest)
        .map_err(|e| NetError::from_io("connect", &e))?;
    Ok(UDPConn::new(s, network, true))
}

#[cfg(unix)]
fn unix_path_addr(name: &str) -> Result<std::os::unix::net::SocketAddr, NetError> {
    use std::os::unix::net::SocketAddr as USA;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(abs) = name.strip_prefix('@') {
        use std::os::linux::net::SocketAddrExt;
        return USA::from_abstract_name(abs.as_bytes()).map_err(|e| NetError::from_io("bind", &e));
    }
    USA::from_pathname(name).map_err(|e| NetError::from_io("bind", &e))
}

#[cfg(unix)]
fn connect_unix(
    ctx: &Context,
    network: &str,
    laddr: Option<&UnixAddr>,
    raddr: &UnixAddr,
) -> Result<super::sock::UnixConn, NetError> {
    use super::sock::UnixConn;
    use std::os::unix::net::{UnixDatagram, UnixStream};
    if ctx.err().is_some() {
        return Err(ctx_error(ctx));
    }
    if laddr.is_some_and(|l| !l.name.is_empty()) && network != "unixgram" {
        return Err(unsupported("dialing from a Unix local address"));
    }
    let target = unix_path_addr(&raddr.name)?;
    match network {
        "unix" => {
            let s =
                UnixStream::connect_addr(&target).map_err(|e| NetError::from_io("connect", &e))?;
            Ok(UnixConn::from_stream(s, network))
        }
        "unixgram" => {
            let s = match laddr {
                Some(l) if !l.name.is_empty() => UnixDatagram::bind_addr(&unix_path_addr(&l.name)?)
                    .map_err(|e| NetError::from_io("bind", &e))?,
                _ => UnixDatagram::unbound().map_err(|e| NetError::from_io("socket", &e))?,
            };
            s.connect_addr(&target)
                .map_err(|e| NetError::from_io("connect", &e))?;
            let l = s
                .local_addr()
                .ok()
                .map(|a| super::sock::unix_addr_for(&a, network));
            let r = Some(Arc::new(raddr.clone()) as AddrRef);
            Ok(UnixConn::datagram(s, network, true, l, r))
        }
        _ => Err(unsupported("unixpacket sockets")),
    }
}

fn dial_tcp_with(
    ctx: &Context,
    d: Option<&Dialer>,
    network: &str,
    laddr: Option<&TCPAddr>,
    raddr: Option<&TCPAddr>,
) -> Result<TCPConn, NetError> {
    let l_shown = || laddr.map(|a| Arc::new(a.clone()) as AddrRef);
    let r_shown = || raddr.map(|a| Arc::new(a.clone()) as AddrRef);
    if !matches!(network, "tcp" | "tcp4" | "tcp6") {
        return Err(op_error(
            "dial",
            network,
            l_shown(),
            r_shown(),
            UnknownNetworkError(network.into()).into(),
        ));
    }
    let Some(r) = raddr else {
        return Err(op_error(
            "dial",
            network,
            l_shown(),
            None,
            NetError::other("missing address"),
        ));
    };
    let _ = d;
    connect_tcp(ctx, network, laddr, r)
        .map_err(|e| op_error("dial", network, l_shown(), r_shown(), e))
}

fn dial_udp_with(
    _ctx: &Context,
    _d: Option<&Dialer>,
    network: &str,
    laddr: Option<&UDPAddr>,
    raddr: Option<&UDPAddr>,
) -> Result<UDPConn, NetError> {
    let l_shown = || laddr.map(|a| Arc::new(a.clone()) as AddrRef);
    let r_shown = || raddr.map(|a| Arc::new(a.clone()) as AddrRef);
    if !matches!(network, "udp" | "udp4" | "udp6") {
        return Err(op_error(
            "dial",
            network,
            l_shown(),
            r_shown(),
            UnknownNetworkError(network.into()).into(),
        ));
    }
    let Some(r) = raddr else {
        return Err(op_error(
            "dial",
            network,
            l_shown(),
            None,
            NetError::other("missing address"),
        ));
    };
    connect_udp(network, laddr, r).map_err(|e| op_error("dial", network, l_shown(), r_shown(), e))
}

#[cfg(unix)]
fn dial_unix_with(
    ctx: &Context,
    network: &str,
    laddr: Option<&UnixAddr>,
    raddr: Option<&UnixAddr>,
) -> Result<super::sock::UnixConn, NetError> {
    let l_shown = || laddr.map(|a| Arc::new(a.clone()) as AddrRef);
    let r_shown = || raddr.map(|a| Arc::new(a.clone()) as AddrRef);
    if !matches!(network, "unix" | "unixgram" | "unixpacket") {
        return Err(op_error(
            "dial",
            network,
            l_shown(),
            r_shown(),
            UnknownNetworkError(network.into()).into(),
        ));
    }
    let Some(r) = raddr else {
        return Err(op_error(
            "dial",
            network,
            l_shown(),
            None,
            NetError::other("missing address"),
        ));
    };
    connect_unix(ctx, network, laddr, r)
        .map_err(|e| op_error("dial", network, l_shown(), r_shown(), e))
}

/// `net.Dial`.
pub fn dial(network: &str, address: &str) -> Result<Box<dyn Conn>, NetError> {
    Dialer::default().dial(network, address)
}

/// `net.DialTimeout`: like [`dial`] with a timeout covering name resolution.
pub fn dial_timeout(
    network: &str,
    address: &str,
    timeout: Duration,
) -> Result<Box<dyn Conn>, NetError> {
    Dialer {
        timeout,
        ..Dialer::default()
    }
    .dial(network, address)
}

/// `net.DialTCP`.
pub fn dial_tcp(
    network: &str,
    laddr: Option<&TCPAddr>,
    raddr: Option<&TCPAddr>,
) -> Result<TCPConn, NetError> {
    dial_tcp_with(&Context::background(), None, network, laddr, raddr)
}

/// `net.DialUDP`.
pub fn dial_udp(
    network: &str,
    laddr: Option<&UDPAddr>,
    raddr: Option<&UDPAddr>,
) -> Result<UDPConn, NetError> {
    dial_udp_with(&Context::background(), None, network, laddr, raddr)
}

/// `net.DialUnix`.
#[cfg(unix)]
pub fn dial_unix(
    network: &str,
    laddr: Option<&UnixAddr>,
    raddr: Option<&UnixAddr>,
) -> Result<super::sock::UnixConn, NetError> {
    dial_unix_with(&Context::background(), network, laddr, raddr)
}

/// `net.ListenConfig`: options for listening to an address.
#[derive(Clone, Default)]
pub struct ListenConfig {
    /// Go's `Control`: setting it makes listens fail (see `unsupported`).
    pub control: Option<super::unsupported::ControlFn>,
    /// Go's `SetMultipathTCP`/`MultipathTCP`: recorded only; connections use
    /// plain TCP.
    pub multipath_tcp: bool,
}

fn listen_tcp_on(network: &str, laddr: &TCPAddr) -> Result<TCPListener, NetError> {
    let a = listen_sock_addr(network, &laddr.ip, laddr.port, &laddr.zone).ok_or_else(|| {
        NetError::from(AddrError {
            err: "invalid IP address".into(),
            addr: laddr.ip.to_string(),
        })
    })?;
    let l = TcpListener::bind(a).map_err(|e| NetError::from_io("bind", &e))?;
    TCPListener::new(l, network).map_err(|e| NetError::from_io("listen", &e))
}

fn listen_udp_on(network: &str, laddr: &UDPAddr) -> Result<UDPConn, NetError> {
    let a = listen_sock_addr(network, &laddr.ip, laddr.port, &laddr.zone).ok_or_else(|| {
        NetError::from(AddrError {
            err: "invalid IP address".into(),
            addr: laddr.ip.to_string(),
        })
    })?;
    let s = UdpSocket::bind(a).map_err(|e| NetError::from_io("bind", &e))?;
    Ok(UDPConn::new(s, network, false))
}

#[cfg(unix)]
fn listen_unix_on(network: &str, laddr: &UnixAddr) -> Result<super::sock::UnixListener, NetError> {
    if network != "unix" {
        return Err(unsupported("unixpacket sockets"));
    }
    let a = unix_path_addr(&laddr.name)?;
    let l = std::os::unix::net::UnixListener::bind_addr(&a)
        .map_err(|e| NetError::from_io("bind", &e))?;
    let path = if laddr.name.starts_with('@') {
        None
    } else {
        Some(laddr.name.clone())
    };
    super::sock::UnixListener::new(l, network, path).map_err(|e| NetError::from_io("listen", &e))
}

#[cfg(unix)]
fn listen_unixgram_on(network: &str, laddr: &UnixAddr) -> Result<super::sock::UnixConn, NetError> {
    let a = unix_path_addr(&laddr.name)?;
    let s = std::os::unix::net::UnixDatagram::bind_addr(&a)
        .map_err(|e| NetError::from_io("bind", &e))?;
    let l = s
        .local_addr()
        .ok()
        .map(|a| super::sock::unix_addr_for(&a, network));
    Ok(super::sock::UnixConn::datagram(s, network, false, l, None))
}

impl ListenConfig {
    /// `ListenConfig.Listen`: announces on the local network address.
    pub fn listen(
        &self,
        ctx: &Context,
        network: &str,
        address: &str,
    ) -> Result<Box<dyn Listener>, NetError> {
        if self.control.is_some() {
            return Err(op_error(
                "listen",
                network,
                None,
                None,
                super::unsupported::needs_sys("ListenConfig.Control"),
            ));
        }
        let addrs = DEFAULT_RESOLVER
            .resolve_addr_list(ctx, "listen", network, address, None)
            .map_err(|e| op_error("listen", network, None, None, e))?;
        let la = ResolvedAddr::first(&addrs, ResolvedAddr::is_ipv4);
        let shown = Some(la.to_addr());
        let wrap = |e: NetError| op_error("listen", network, None, shown.clone(), e);
        match &la {
            ResolvedAddr::Tcp(a) => listen_tcp_on(network, a)
                .map(|l| Box::new(l) as Box<dyn Listener>)
                .map_err(wrap),
            #[cfg(unix)]
            ResolvedAddr::Unix(a) => listen_unix_on(network, a)
                .map(|l| Box::new(l) as Box<dyn Listener>)
                .map_err(wrap),
            _ => Err(wrap(NetError::Addr(AddrError {
                err: "unexpected address type".into(),
                addr: address.into(),
            }))),
        }
    }

    /// `ListenConfig.ListenPacket`: announces on the local network address.
    pub fn listen_packet(
        &self,
        ctx: &Context,
        network: &str,
        address: &str,
    ) -> Result<Box<dyn PacketConn>, NetError> {
        if self.control.is_some() {
            return Err(op_error(
                "listen",
                network,
                None,
                None,
                super::unsupported::needs_sys("ListenConfig.Control"),
            ));
        }
        let addrs = DEFAULT_RESOLVER
            .resolve_addr_list(ctx, "listen", network, address, None)
            .map_err(|e| op_error("listen", network, None, None, e))?;
        let la = ResolvedAddr::first(&addrs, ResolvedAddr::is_ipv4);
        let shown = Some(la.to_addr());
        let wrap = |e: NetError| op_error("listen", network, None, shown.clone(), e);
        match &la {
            ResolvedAddr::Udp(a) => listen_udp_on(network, a)
                .map(|c| Box::new(c) as Box<dyn PacketConn>)
                .map_err(wrap),
            #[cfg(unix)]
            ResolvedAddr::Unix(a) if network == "unixgram" => listen_unixgram_on(network, a)
                .map(|c| Box::new(c) as Box<dyn PacketConn>)
                .map_err(wrap),
            ResolvedAddr::Ip(_) => Err(wrap(unsupported("listening on an IP network"))),
            _ => Err(wrap(NetError::Addr(AddrError {
                err: "unexpected address type".into(),
                addr: address.into(),
            }))),
        }
    }
}

/// `net.Listen`.
pub fn listen(network: &str, address: &str) -> Result<Box<dyn Listener>, NetError> {
    ListenConfig::default().listen(&Context::background(), network, address)
}

/// `net.ListenPacket`.
pub fn listen_packet(network: &str, address: &str) -> Result<Box<dyn PacketConn>, NetError> {
    ListenConfig::default().listen_packet(&Context::background(), network, address)
}

/// `net.ListenTCP`.
pub fn listen_tcp(network: &str, laddr: Option<&TCPAddr>) -> Result<TCPListener, NetError> {
    let shown = laddr.map(|a| Arc::new(a.clone()) as AddrRef);
    if !matches!(network, "tcp" | "tcp4" | "tcp6") {
        return Err(op_error(
            "listen",
            network,
            None,
            shown,
            UnknownNetworkError(network.into()).into(),
        ));
    }
    let default = TCPAddr::default();
    listen_tcp_on(network, laddr.unwrap_or(&default))
        .map_err(|e| op_error("listen", network, None, shown, e))
}

/// `net.ListenUDP`.
pub fn listen_udp(network: &str, laddr: Option<&UDPAddr>) -> Result<UDPConn, NetError> {
    let shown = laddr.map(|a| Arc::new(a.clone()) as AddrRef);
    if !matches!(network, "udp" | "udp4" | "udp6") {
        return Err(op_error(
            "listen",
            network,
            None,
            shown,
            UnknownNetworkError(network.into()).into(),
        ));
    }
    let default = UDPAddr::default();
    listen_udp_on(network, laddr.unwrap_or(&default))
        .map_err(|e| op_error("listen", network, None, shown, e))
}

/// `net.ListenUnix`.
#[cfg(unix)]
pub fn listen_unix(
    network: &str,
    laddr: Option<&UnixAddr>,
) -> Result<super::sock::UnixListener, NetError> {
    let shown = laddr.map(|a| Arc::new(a.clone()) as AddrRef);
    if !matches!(network, "unix" | "unixpacket") {
        return Err(op_error(
            "listen",
            network,
            None,
            shown,
            UnknownNetworkError(network.into()).into(),
        ));
    }
    let Some(l) = laddr else {
        return Err(op_error(
            "listen",
            network,
            None,
            None,
            NetError::other("missing address"),
        ));
    };
    listen_unix_on(network, l).map_err(|e| op_error("listen", network, None, shown, e))
}

/// `net.ListenUnixgram`.
#[cfg(unix)]
pub fn listen_unixgram(
    network: &str,
    laddr: Option<&UnixAddr>,
) -> Result<super::sock::UnixConn, NetError> {
    let shown = laddr.map(|a| Arc::new(a.clone()) as AddrRef);
    if network != "unixgram" {
        return Err(op_error(
            "listen",
            network,
            None,
            shown,
            UnknownNetworkError(network.into()).into(),
        ));
    }
    let Some(l) = laddr else {
        return Err(op_error(
            "listen",
            network,
            None,
            None,
            NetError::other("missing address"),
        ));
    };
    listen_unixgram_on(network, l).map_err(|e| op_error("listen", network, None, shown, e))
}
