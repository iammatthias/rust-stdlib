//! Go's `net.Dialer`, `net.ListenConfig` and the `Dial*` / `Listen*` family,
//! including the networks std cannot open: `ip:*`, `unixpacket`, a local
//! address on TCP and Unix dials, `Control` hooks and TCP keep-alive options.
use super::addr::{Addr, IPAddr, TCPAddr, UDPAddr, UnixAddr};
use super::error::{Cause, OpError};
use super::ipconn::IPConn;
use super::listener::{configure_tcp, TCPListener};
use super::resolve::{parse_network, resolve_addr_list, ResolvedAddr};
use super::socket::{
    internet_socket, resolved_from, syscall_cause, unix_socket, Background, Context, ControlContextFn,
    ControlFn, Ctx, Hook, NetFd,
};
use super::sockopt::KeepAliveConfig;
use super::tcpconn::TCPConn;
use super::udpconn::UDPConn;
use super::unixsock::{UnixConn, UnixListener};
use crate::errno::EADDRNOTAVAIL;
use crate::ffi::{self, k};
use std::net::IpAddr;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime};

/// `net.Conn`: a generic stream- or datagram-oriented network connection.
pub enum Conn {
    /// A TCP connection.
    Tcp(TCPConn),
    /// A UDP socket (connected when dialed).
    Udp(UDPConn),
    /// A Unix-domain connection.
    Unix(UnixConn),
    /// A raw IP connection.
    Ip(IPConn),
}

/// `net.PacketConn`: a packet-oriented network connection.
pub enum PacketConn {
    /// A UDP socket.
    Udp(UDPConn),
    /// A Unix datagram socket.
    Unix(UnixConn),
    /// A raw IP socket.
    Ip(IPConn),
}

/// `net.Listener`: a generic network listener for stream-oriented protocols.
pub enum Listener {
    /// A TCP listener.
    Tcp(TCPListener),
    /// A Unix-domain listener.
    Unix(UnixListener),
}

impl AsRawFd for Conn {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            Conn::Tcp(c) => c.as_raw_fd(),
            Conn::Udp(c) => c.as_raw_fd(),
            Conn::Unix(c) => c.as_raw_fd(),
            Conn::Ip(c) => c.as_raw_fd(),
        }
    }
}

impl AsRawFd for PacketConn {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            PacketConn::Udp(c) => c.as_raw_fd(),
            PacketConn::Unix(c) => c.as_raw_fd(),
            PacketConn::Ip(c) => c.as_raw_fd(),
        }
    }
}

impl AsRawFd for Listener {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            Listener::Tcp(l) => l.as_raw_fd(),
            Listener::Unix(l) => l.as_raw_fd(),
        }
    }
}

fn describe_fd(fd: RawFd, remote: bool) -> Option<ResolvedAddr> {
    let mut ty = [0u8; 4];
    ffi::getsockopt(fd, k::SOL_SOCKET, k::SO_TYPE, &mut ty).ok()?;
    let sotype = i32::from_ne_bytes(ty);
    let sa = if remote { ffi::getpeername(fd) } else { ffi::getsockname(fd) }.ok()?;
    resolved_from(&sa, sa.raw_family(), sotype)
}

impl Conn {
    /// `Conn.LocalAddr`: the local network address.
    pub fn local_addr(&self) -> Option<ResolvedAddr> {
        match self {
            Conn::Tcp(c) => c.local_addr().map(ResolvedAddr::Tcp),
            Conn::Udp(c) => c.local_addr().map(ResolvedAddr::Udp),
            Conn::Unix(c) => c.local_addr().map(ResolvedAddr::Unix),
            Conn::Ip(_) => describe_fd(self.as_raw_fd(), false),
        }
    }

    /// `Conn.RemoteAddr`: the remote network address, if connected.
    pub fn remote_addr(&self) -> Option<ResolvedAddr> {
        match self {
            Conn::Tcp(c) => c.remote_addr().map(ResolvedAddr::Tcp),
            Conn::Udp(c) => c.remote_addr().map(ResolvedAddr::Udp),
            Conn::Unix(c) => c.remote_addr().map(ResolvedAddr::Unix),
            Conn::Ip(_) => describe_fd(self.as_raw_fd(), true),
        }
    }

    /// `Conn.Read`.
    pub fn read(&self, b: &mut [u8]) -> Result<usize, OpError> {
        match self {
            Conn::Tcp(c) => c.read(b),
            Conn::Udp(c) => c.read(b),
            Conn::Unix(c) => c.read(b),
            Conn::Ip(c) => c.read(b),
        }
    }

    /// `Conn.Write`.
    pub fn write(&self, b: &[u8]) -> Result<usize, OpError> {
        match self {
            Conn::Tcp(c) => c.write(b),
            Conn::Udp(c) => c.write(b),
            Conn::Unix(c) => c.write(b),
            Conn::Ip(c) => c.write(b),
        }
    }

    /// `Conn.Close`.
    pub fn close(&self) -> Result<(), OpError> {
        match self {
            Conn::Tcp(c) => c.close(),
            Conn::Udp(c) => c.close(),
            Conn::Unix(c) => c.close(),
            Conn::Ip(c) => c.close(),
        }
    }

    /// `Conn.SetDeadline`.
    pub fn set_deadline(&self, t: Option<SystemTime>) -> Result<(), OpError> {
        match self {
            Conn::Tcp(c) => c.set_deadline(t),
            Conn::Udp(c) => c.set_deadline(t),
            Conn::Unix(c) => c.set_deadline(t),
            Conn::Ip(c) => c.set_deadline(t),
        }
    }

    /// `Conn.SetReadDeadline`.
    pub fn set_read_deadline(&self, t: Option<SystemTime>) -> Result<(), OpError> {
        match self {
            Conn::Tcp(c) => c.set_read_deadline(t),
            Conn::Udp(c) => c.set_read_deadline(t),
            Conn::Unix(c) => c.set_read_deadline(t),
            Conn::Ip(c) => c.set_read_deadline(t),
        }
    }

    /// `Conn.SetWriteDeadline`.
    pub fn set_write_deadline(&self, t: Option<SystemTime>) -> Result<(), OpError> {
        match self {
            Conn::Tcp(c) => c.set_write_deadline(t),
            Conn::Udp(c) => c.set_write_deadline(t),
            Conn::Unix(c) => c.set_write_deadline(t),
            Conn::Ip(c) => c.set_write_deadline(t),
        }
    }
}

impl PacketConn {
    /// `PacketConn.LocalAddr`: the local network address.
    pub fn local_addr(&self) -> Option<ResolvedAddr> {
        match self {
            PacketConn::Udp(c) => c.local_addr().map(ResolvedAddr::Udp),
            PacketConn::Unix(c) => c.local_addr().map(ResolvedAddr::Unix),
            PacketConn::Ip(_) => describe_fd(self.as_raw_fd(), false),
        }
    }

    /// `PacketConn.ReadFrom`: reads a packet and its sender.
    pub fn read_from(&self, b: &mut [u8]) -> Result<(usize, Option<ResolvedAddr>), OpError> {
        match self {
            PacketConn::Udp(c) => c
                .read_from(b)
                .map(|(n, a)| (n, a.map(ResolvedAddr::Udp))),
            PacketConn::Unix(c) => c
                .read_from(b)
                .map(|(n, a)| (n, a.map(ResolvedAddr::Unix))),
            PacketConn::Ip(c) => c
                .read_from(b)
                .map(|(n, a)| (n, a.map(ResolvedAddr::Ip))),
        }
    }

    /// `PacketConn.Close`.
    pub fn close(&self) -> Result<(), OpError> {
        match self {
            PacketConn::Udp(c) => c.close(),
            PacketConn::Unix(c) => c.close(),
            PacketConn::Ip(c) => c.close(),
        }
    }

    /// `PacketConn.SetDeadline`.
    pub fn set_deadline(&self, t: Option<SystemTime>) -> Result<(), OpError> {
        match self {
            PacketConn::Udp(c) => c.set_deadline(t),
            PacketConn::Unix(c) => c.set_deadline(t),
            PacketConn::Ip(c) => c.set_deadline(t),
        }
    }

    /// `PacketConn.SetReadDeadline`.
    pub fn set_read_deadline(&self, t: Option<SystemTime>) -> Result<(), OpError> {
        match self {
            PacketConn::Udp(c) => c.set_read_deadline(t),
            PacketConn::Unix(c) => c.set_read_deadline(t),
            PacketConn::Ip(c) => c.set_read_deadline(t),
        }
    }

    /// `PacketConn.SetWriteDeadline`.
    pub fn set_write_deadline(&self, t: Option<SystemTime>) -> Result<(), OpError> {
        match self {
            PacketConn::Udp(c) => c.set_write_deadline(t),
            PacketConn::Unix(c) => c.set_write_deadline(t),
            PacketConn::Ip(c) => c.set_write_deadline(t),
        }
    }
}

impl Listener {
    /// `Listener.Addr`: the listener's network address.
    pub fn addr(&self) -> Option<ResolvedAddr> {
        match self {
            Listener::Tcp(l) => l.addr().map(ResolvedAddr::Tcp),
            Listener::Unix(l) => l.addr().map(ResolvedAddr::Unix),
        }
    }

    /// `Listener.Accept`: waits for and returns the next connection.
    pub fn accept(&self) -> Result<Conn, OpError> {
        match self {
            Listener::Tcp(l) => l.accept_tcp().map(Conn::Tcp),
            Listener::Unix(l) => l.accept_unix().map(Conn::Unix),
        }
    }

    /// `Listener.Close`: stops listening; a blocked `accept` fails at once.
    pub fn close(&self) -> Result<(), OpError> {
        match self {
            Listener::Tcp(l) => l.close(),
            Listener::Unix(l) => l.close(),
        }
    }

    /// `TCPListener.SetDeadline` and `UnixListener.SetDeadline`: the deadline
    /// for `accept`.
    pub fn set_deadline(&self, t: Option<SystemTime>) -> Result<(), OpError> {
        match self {
            Listener::Tcp(l) => l.set_deadline(t),
            Listener::Unix(l) => l.set_deadline(t),
        }
    }
}

/// Go's `mptcpStatus`: whether to use Multipath TCP.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum Mptcp {
    /// The system default: off for dialers, on for listeners.
    #[default]
    Default,
    /// Use Multipath TCP when the operating system supports it.
    Enabled,
    /// Never use Multipath TCP.
    Disabled,
}

/// `net.Dialer`: options for connecting to an address. The zero value (via
/// `Dialer::default()`) dials without any option.
#[derive(Default)]
pub struct Dialer {
    /// `Dialer.Timeout`, in nanoseconds: the maximum a dial waits for a
    /// connect; zero means none (a negative value is already expired).
    pub timeout: i64,
    /// `Dialer.Deadline`: the absolute time after which dials fail.
    pub deadline: Option<SystemTime>,
    /// `Dialer.LocalAddr`: the local address to dial from.
    pub local_addr: Option<ResolvedAddr>,
    /// `Dialer.FallbackDelay`, in nanoseconds: how long to wait before
    /// racing the other address family; zero is 300 ms, negative disables it.
    pub fallback_delay: i64,
    /// `Dialer.KeepAlive`, in nanoseconds: the keep-alive idle time; zero is
    /// 15 s, negative disables keep-alive.
    pub keep_alive: i64,
    /// `Dialer.KeepAliveConfig`: the keep-alive probe configuration.
    pub keep_alive_config: KeepAliveConfig,
    /// `Dialer.Control`: called after creating the socket and before dialing.
    pub control: Option<ControlFn>,
    /// `Dialer.ControlContext`: like `control`, with the dial's context; it
    /// takes precedence.
    pub control_context: Option<ControlContextFn>,
    /// Multipath TCP choice; see [`Dialer::multipath_tcp`].
    pub mptcp: Mptcp,
}

/// `net.ListenConfig`: options for listening on an address.
#[derive(Default)]
pub struct ListenConfig {
    /// `ListenConfig.Control`: called after creating the socket and before
    /// binding.
    pub control: Option<ControlFn>,
    /// `ListenConfig.KeepAlive`, in nanoseconds: the keep-alive idle time of
    /// accepted connections; zero is 15 s, negative disables it.
    pub keep_alive: i64,
    /// `ListenConfig.KeepAliveConfig`: the keep-alive probe configuration.
    pub keep_alive_config: KeepAliveConfig,
    /// Multipath TCP choice; see [`ListenConfig::multipath_tcp`].
    pub mptcp: Mptcp,
}

#[cfg(target_os = "linux")]
fn supports_multipath_tcp() -> bool {
    use std::sync::OnceLock;
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| ffi::socket(k::AF_INET, k::SOCK_STREAM, k::IPPROTO_MPTCP).is_ok())
}

#[cfg(not(target_os = "linux"))]
fn supports_multipath_tcp() -> bool {
    false
}

#[cfg(target_os = "linux")]
const IPPROTO_MPTCP: i32 = k::IPPROTO_MPTCP;
#[cfg(not(target_os = "linux"))]
const IPPROTO_MPTCP: i32 = 0;

fn mptcp_get(status: Mptcp, default: bool) -> bool {
    match status {
        Mptcp::Enabled => true,
        Mptcp::Disabled => false,
        Mptcp::Default => default,
    }
}

fn op_error(op: &str, net: &str, source: Option<String>, addr: Option<String>, err: Cause) -> OpError {
    OpError {
        op: op.into(),
        net: net.into(),
        source,
        addr,
        err,
    }
}

fn addr_text<A: Addr>(a: Option<&A>) -> Option<String> {
    a.map(|a| a.to_string())
}

fn first_addr(addrs: &[ResolvedAddr]) -> Option<&ResolvedAddr> {
    addrs
        .iter()
        .find(|a| a.ip().is_some_and(|ip| is_ipv4(&ip)))
        .or_else(|| addrs.first())
}

fn is_ipv4(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(_) => true,
        IpAddr::V6(a) => a.to_ipv4_mapped().is_some(),
    }
}

/// Go's `partialDeadline`.
fn partial_deadline(now: Instant, deadline: Instant, remaining: usize) -> Result<Instant, Cause> {
    if deadline <= now {
        return Err(Cause::Timeout);
    }
    let left = deadline - now;
    let mut timeout = left / remaining as u32;
    let sane = Duration::from_secs(2);
    if timeout < sane {
        timeout = if left < sane { left } else { sane };
    }
    Ok(now + timeout)
}

/// Go's `selfConnect`: a TCP dial that connected to itself.
fn self_connect(nfd: &NetFd) -> bool {
    match (&nfd.laddr, &nfd.raddr) {
        (Some(ResolvedAddr::Tcp(l)), Some(ResolvedAddr::Tcp(r))) => l.port == r.port && l.ip == r.ip,
        _ => true,
    }
}

fn spurious_enotavail(err: &Cause) -> bool {
    match err {
        Cause::Syscall(s) => s.err == EADDRNOTAVAIL,
        Cause::Errno(e) => *e == EADDRNOTAVAIL,
        _ => false,
    }
}

fn wrap_tcp(
    nfd: NetFd,
    keep_alive: i64,
    config: &KeepAliveConfig,
) -> Result<TCPConn, Cause> {
    let conn = TCPConn::from_fd(nfd).map_err(|e| e.err)?;
    configure_tcp(&conn, keep_alive, config).map_err(|e| e.err)?;
    Ok(conn)
}

impl Dialer {
    /// `Dialer.MultipathTCP`: whether Multipath TCP will be used.
    pub fn multipath_tcp(&self) -> bool {
        mptcp_get(self.mptcp, false)
    }

    /// `Dialer.SetMultipathTCP`: use, or not use, Multipath TCP when the
    /// operating system supports it; otherwise dials fall back to TCP.
    pub fn set_multipath_tcp(&mut self, use_it: bool) {
        self.mptcp = if use_it { Mptcp::Enabled } else { Mptcp::Disabled };
    }

    fn hook(&self) -> Hook<'_> {
        Hook {
            control: self.control.as_ref(),
            control_context: self.control_context.as_ref(),
        }
    }

    fn fallback(&self) -> Duration {
        if self.fallback_delay > 0 {
            Duration::from_nanos(self.fallback_delay as u64)
        } else {
            Duration::from_millis(300)
        }
    }

    /// Go's `Dialer.deadline`: the earliest of now+Timeout and Deadline.
    fn own_deadline(&self, now: Instant) -> Option<Instant> {
        let mut earliest = None;
        if self.timeout != 0 {
            earliest = Some(if self.timeout > 0 {
                now + Duration::from_nanos(self.timeout as u64)
            } else {
                now - Duration::from_nanos(self.timeout.unsigned_abs())
            });
        }
        if let Some(d) = self.deadline {
            let d = match d.duration_since(SystemTime::now()) {
                Ok(ahead) => now + ahead,
                Err(behind) => now - behind.duration(),
            };
            earliest = Some(earliest.map_or(d, |e: Instant| e.min(d)));
        }
        earliest
    }

    /// `Dialer.Dial`: connects to `address` on `network`.
    pub fn dial(&self, network: &str, address: &str) -> Result<Conn, OpError> {
        self.dial_context(&Background, network, address)
    }

    /// `Dialer.DialContext`: connects to `address` on `network`, giving up
    /// when `ctx` is done.
    pub fn dial_context(
        &self,
        ctx: &dyn Context,
        network: &str,
        address: &str,
    ) -> Result<Conn, OpError> {
        let ctx = Ctx::new(ctx, self.own_deadline(Instant::now()));
        let addrs = resolve_addr_list("dial", network, address, self.local_addr.as_ref())
            .map_err(|e| op_error("dial", network, None, None, e))?;
        let ipv4 = |a: &&ResolvedAddr| a.ip().is_some_and(|ip| is_ipv4(&ip));
        let (primaries, fallbacks): (Vec<ResolvedAddr>, Vec<ResolvedAddr>) =
            if self.fallback_delay >= 0 && network == "tcp" {
                let first_v4 = addrs.first().is_some_and(|a| ipv4(&a));
                let (a, b): (Vec<_>, Vec<_>) = addrs
                    .into_iter()
                    .partition(|x| ipv4(&x) == first_v4);
                (a, b)
            } else {
                (addrs, Vec::new())
            };
        self.dial_parallel(&ctx, network, address, &primaries, &fallbacks)
    }

    fn dial_parallel(
        &self,
        ctx: &Ctx<'_>,
        network: &str,
        address: &str,
        primaries: &[ResolvedAddr],
        fallbacks: &[ResolvedAddr],
    ) -> Result<Conn, OpError> {
        if fallbacks.is_empty() {
            return self.dial_serial(ctx, network, address, primaries);
        }
        enum Event {
            Result {
                primary: bool,
                result: Result<Conn, OpError>,
            },
        }
        let primary_cancel = AtomicBool::new(false);
        let fallback_cancel = AtomicBool::new(false);
        let (tx, rx) = mpsc::channel::<Event>();
        let outcome = std::thread::scope(|scope| {
            let start = |primary: bool| {
                let tx = tx.clone();
                let ras = if primary { primaries } else { fallbacks };
                let cancel = if primary { &primary_cancel } else { &fallback_cancel };
                let racer_ctx = ctx.with_cancel(cancel);
                scope.spawn(move || {
                    let result = self.dial_serial(&racer_ctx, network, address, ras);
                    let _ = tx.send(Event::Result { primary, result });
                });
            };
            start(true);
            let mut fallback_started = false;
            let mut fallback_deadline = Some(Instant::now() + self.fallback());
            let mut primary_err: Option<OpError> = None;
            let mut fallback_done = false;
            let mut primary_done = false;
            let outcome = loop {
                let wait = fallback_deadline.map(|d| d.saturating_duration_since(Instant::now()));
                let event = match wait {
                    Some(w) => match rx.recv_timeout(w) {
                        Ok(e) => Some(e),
                        Err(mpsc::RecvTimeoutError::Timeout) => None,
                        Err(mpsc::RecvTimeoutError::Disconnected) => None,
                    },
                    None => rx.recv().ok(),
                };
                match event {
                    None => {
                        if fallback_deadline.is_some() && !fallback_started {
                            fallback_started = true;
                            fallback_deadline = None;
                            start(false);
                        } else if fallback_deadline.is_none() && !fallback_started {
                            break Err(op_error("dial", network, None, None, Cause::MissingAddress));
                        } else {
                            break Err(primary_err
                                .take()
                                .unwrap_or_else(|| op_error("dial", network, None, None, Cause::MissingAddress)));
                        }
                    }
                    Some(Event::Result { primary, result }) => match result {
                        Ok(conn) => break Ok(conn),
                        Err(e) => {
                            if primary {
                                primary_done = true;
                                primary_err = Some(e);
                            } else {
                                fallback_done = true;
                            }
                            if primary_done && fallback_done {
                                break Err(primary_err.take().unwrap());
                            }
                            // An error on the primary starts the fallback at once.
                            if primary && !fallback_started {
                                fallback_started = true;
                                fallback_deadline = None;
                                start(false);
                            }
                        }
                    },
                }
            };
            primary_cancel.store(true, Ordering::SeqCst);
            fallback_cancel.store(true, Ordering::SeqCst);
            drop(tx);
            outcome
        });
        outcome
    }

    fn dial_serial(
        &self,
        ctx: &Ctx<'_>,
        network: &str,
        address: &str,
        ras: &[ResolvedAddr],
    ) -> Result<Conn, OpError> {
        let local = || self.local_addr.as_ref().map(|a| a.to_string());
        let mut first_err: Option<OpError> = None;
        for (i, ra) in ras.iter().enumerate() {
            if let Some(cause) = ctx.err() {
                return Err(op_error("dial", network, local(), Some(ra.to_string()), cause));
            }
            let mut dial_ctx = *ctx;
            if let Some(deadline) = ctx.deadline {
                match partial_deadline(Instant::now(), deadline, ras.len() - i) {
                    Err(cause) => {
                        if first_err.is_none() {
                            first_err =
                                Some(op_error("dial", network, local(), Some(ra.to_string()), cause));
                        }
                        break;
                    }
                    Ok(partial) => {
                        if partial < deadline {
                            dial_ctx = dial_ctx.with_deadline(partial);
                        }
                    }
                }
            }
            match self.dial_single(&dial_ctx, network, address, ra) {
                Ok(c) => return Ok(c),
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }
        Err(first_err
            .unwrap_or_else(|| op_error("dial", network, None, None, Cause::MissingAddress)))
    }

    fn dial_single(
        &self,
        ctx: &Ctx<'_>,
        network: &str,
        _address: &str,
        ra: &ResolvedAddr,
    ) -> Result<Conn, OpError> {
        let la = self.local_addr.as_ref();
        let result = match ra {
            ResolvedAddr::Tcp(r) => {
                let l = match la {
                    Some(ResolvedAddr::Tcp(l)) => Some(l),
                    _ => None,
                };
                self.sys_dial_tcp(ctx, network, l, r).map(Conn::Tcp)
            }
            ResolvedAddr::Udp(r) => {
                let l = match la {
                    Some(ResolvedAddr::Udp(l)) => Some(l),
                    _ => None,
                };
                self.sys_dial_udp(ctx, network, l, r).map(Conn::Udp)
            }
            ResolvedAddr::Ip(r) => {
                let l = match la {
                    Some(ResolvedAddr::Ip(l)) => Some(l),
                    _ => None,
                };
                self.sys_dial_ip(ctx, network, l, r).map(Conn::Ip)
            }
            ResolvedAddr::Unix(r) => {
                let l = match la {
                    Some(ResolvedAddr::Unix(l)) => Some(l),
                    _ => None,
                };
                self.sys_dial_unix(ctx, network, l, r).map(Conn::Unix)
            }
        };
        result.map_err(|err| op_error("dial", network, la.map(|a| a.to_string()), Some(ra.to_string()), err))
    }

    fn sys_dial_tcp(
        &self,
        ctx: &Ctx<'_>,
        network: &str,
        laddr: Option<&TCPAddr>,
        raddr: &TCPAddr,
    ) -> Result<TCPConn, Cause> {
        if self.multipath_tcp() && supports_multipath_tcp() {
            if let Ok(c) = self.do_dial_tcp(ctx, network, laddr, raddr, IPPROTO_MPTCP) {
                return Ok(c);
            }
        }
        self.do_dial_tcp(ctx, network, laddr, raddr, 0)
    }

    fn do_dial_tcp(
        &self,
        ctx: &Ctx<'_>,
        network: &str,
        laddr: Option<&TCPAddr>,
        raddr: &TCPAddr,
        proto: i32,
    ) -> Result<TCPConn, Cause> {
        let l = laddr.cloned().map(ResolvedAddr::Tcp);
        let r = ResolvedAddr::Tcp(raddr.clone());
        let open = || {
            internet_socket(ctx, network, l.as_ref(), Some(&r), k::SOCK_STREAM, proto, "dial", self.hook())
        };
        let mut result = open();
        // A simultaneous connection to ourselves, or a spurious EADDRNOTAVAIL
        // on a loopback dial, is retried twice.
        let mut tries = 0;
        while tries < 2
            && laddr.is_none_or(|a| a.port == 0)
            && match &result {
                Ok(nfd) => self_connect(nfd),
                Err(e) => spurious_enotavail(e),
            }
        {
            result = open();
            tries += 1;
        }
        wrap_tcp(result?, self.keep_alive, &self.keep_alive_config)
    }

    fn sys_dial_udp(
        &self,
        ctx: &Ctx<'_>,
        network: &str,
        laddr: Option<&UDPAddr>,
        raddr: &UDPAddr,
    ) -> Result<UDPConn, Cause> {
        let l = laddr.cloned().map(ResolvedAddr::Udp);
        let r = ResolvedAddr::Udp(raddr.clone());
        let nfd = internet_socket(ctx, network, l.as_ref(), Some(&r), k::SOCK_DGRAM, 0, "dial", self.hook())?;
        UDPConn::from_fd(nfd).map_err(|e| e.err)
    }

    fn sys_dial_ip(
        &self,
        ctx: &Ctx<'_>,
        network: &str,
        laddr: Option<&IPAddr>,
        raddr: &IPAddr,
    ) -> Result<IPConn, Cause> {
        let (afnet, proto) = parse_network(network, true)?;
        if !matches!(afnet.as_str(), "ip" | "ip4" | "ip6") {
            return Err(Cause::UnknownNetwork(network.into()));
        }
        let l = laddr.cloned().map(ResolvedAddr::Ip);
        let r = ResolvedAddr::Ip(raddr.clone());
        let nfd = internet_socket(ctx, &afnet, l.as_ref(), Some(&r), k::SOCK_RAW, proto, "dial", self.hook())?;
        IPConn::from_fd(nfd).map_err(|e| e.err)
    }

    fn sys_dial_unix(
        &self,
        ctx: &Ctx<'_>,
        network: &str,
        laddr: Option<&UnixAddr>,
        raddr: &UnixAddr,
    ) -> Result<UnixConn, Cause> {
        let l = laddr.cloned().map(ResolvedAddr::Unix);
        let r = ResolvedAddr::Unix(raddr.clone());
        let nfd = unix_socket(ctx, network, l.as_ref(), Some(&r), "dial", self.hook())?;
        new_unix_conn(nfd)
    }

    /// `Dialer.DialTCP`: connects to a TCP address, optionally from a local one.
    pub fn dial_tcp(
        &self,
        network: &str,
        laddr: Option<&TCPAddr>,
        raddr: Option<&TCPAddr>,
    ) -> Result<TCPConn, OpError> {
        let source = addr_text(laddr);
        if !matches!(network, "tcp" | "tcp4" | "tcp6") {
            return Err(op_error(
                "dial",
                network,
                source,
                addr_text(raddr),
                Cause::UnknownNetwork(network.into()),
            ));
        }
        let Some(raddr) = raddr else {
            return Err(op_error("dial", network, source, None, Cause::MissingAddress));
        };
        let ctx = Ctx::new(&Background, self.own_deadline(Instant::now()));
        self.sys_dial_tcp(&ctx, network, laddr, raddr).map_err(|e| {
            op_error("dial", network, source, Some(raddr.to_string()), e)
        })
    }

    /// `Dialer.DialUnix`: connects to a Unix socket address.
    pub fn dial_unix(
        &self,
        network: &str,
        laddr: Option<&UnixAddr>,
        raddr: Option<&UnixAddr>,
    ) -> Result<UnixConn, OpError> {
        let source = addr_text(laddr);
        if !matches!(network, "unix" | "unixgram" | "unixpacket") {
            return Err(op_error(
                "dial",
                network,
                source,
                addr_text(raddr),
                Cause::UnknownNetwork(network.into()),
            ));
        }
        let ctx = Ctx::new(&Background, self.own_deadline(Instant::now()));
        let l = laddr.cloned().map(ResolvedAddr::Unix);
        let r = raddr.cloned().map(ResolvedAddr::Unix);
        let result = unix_socket(&ctx, network, l.as_ref(), r.as_ref(), "dial", self.hook())
            .and_then(new_unix_conn);
        result.map_err(|e| op_error("dial", network, source, addr_text(raddr), e))
    }

    /// `Dialer.DialIP`: connects to an IP address on a raw IP network such as
    /// "ip4:icmp" (usually needs privileges).
    pub fn dial_ip(
        &self,
        network: &str,
        laddr: Option<&IPAddr>,
        raddr: Option<&IPAddr>,
    ) -> Result<IPConn, OpError> {
        let source = addr_text(laddr);
        let Some(raddr) = raddr else {
            return Err(op_error("dial", network, source, None, Cause::MissingAddress));
        };
        let ctx = Ctx::new(&Background, self.own_deadline(Instant::now()));
        self.sys_dial_ip(&ctx, network, laddr, raddr)
            .map_err(|e| op_error("dial", network, source, Some(raddr.to_string()), e))
    }
}

fn new_unix_conn(nfd: NetFd) -> Result<UnixConn, Cause> {
    UnixConn::from_fd(nfd).map_err(|e| e.err)
}

/// `net.Dial`: connects to `address` on `network` ("tcp", "udp", "ip4:icmp",
/// "unix", ...).
pub fn dial(network: &str, address: &str) -> Result<Conn, OpError> {
    Dialer::default().dial(network, address)
}

/// `net.DialTimeout`: like [`dial`] with a timeout in nanoseconds.
pub fn dial_timeout(network: &str, address: &str, timeout: i64) -> Result<Conn, OpError> {
    Dialer {
        timeout,
        ..Dialer::default()
    }
    .dial(network, address)
}

/// `net.DialTCP`: connects to `raddr`, optionally from `laddr`.
pub fn dial_tcp(
    network: &str,
    laddr: Option<&TCPAddr>,
    raddr: Option<&TCPAddr>,
) -> Result<TCPConn, OpError> {
    Dialer::default().dial_tcp(network, laddr, raddr)
}

/// `net.DialUnix`: connects to a Unix socket.
pub fn dial_unix(
    network: &str,
    laddr: Option<&UnixAddr>,
    raddr: Option<&UnixAddr>,
) -> Result<UnixConn, OpError> {
    Dialer::default().dial_unix(network, laddr, raddr)
}

/// `net.DialIP`: connects to an IP address on a raw IP network.
pub fn dial_ip(
    network: &str,
    laddr: Option<&IPAddr>,
    raddr: Option<&IPAddr>,
) -> Result<IPConn, OpError> {
    Dialer::default().dial_ip(network, laddr, raddr)
}

impl ListenConfig {
    /// `ListenConfig.MultipathTCP`: whether Multipath TCP will be used (the
    /// default is on, where the operating system supports it).
    pub fn multipath_tcp(&self) -> bool {
        mptcp_get(self.mptcp, true)
    }

    /// `ListenConfig.SetMultipathTCP`.
    pub fn set_multipath_tcp(&mut self, use_it: bool) {
        self.mptcp = if use_it { Mptcp::Enabled } else { Mptcp::Disabled };
    }

    fn hook(&self) -> Hook<'_> {
        Hook {
            control: self.control.as_ref(),
            control_context: None,
        }
    }

    fn listen_tcp(&self, ctx: &Ctx<'_>, network: &str, laddr: &TCPAddr) -> Result<TCPListener, Cause> {
        let l = ResolvedAddr::Tcp(laddr.clone());
        let open = |proto: i32| {
            internet_socket(ctx, network, Some(&l), None, k::SOCK_STREAM, proto, "listen", self.hook())
        };
        let nfd = if self.multipath_tcp() && supports_multipath_tcp() {
            open(IPPROTO_MPTCP).or_else(|_| open(0))?
        } else {
            open(0)?
        };
        TCPListener::from_fd(nfd, self.keep_alive, self.keep_alive_config).map_err(|e| e.err)
    }

    /// `ListenConfig.Listen`: announces on the local `address` of `network`
    /// ("tcp", "tcp4", "tcp6", "unix" or "unixpacket").
    pub fn listen(&self, ctx: &dyn Context, network: &str, address: &str) -> Result<Listener, OpError> {
        let ctx = Ctx::new(ctx, None);
        let addrs = resolve_addr_list("listen", network, address, None)
            .map_err(|e| op_error("listen", network, None, None, e))?;
        let la = first_addr(&addrs).cloned();
        let la = la.ok_or_else(|| op_error("listen", network, None, None, Cause::MissingAddress))?;
        let result = match &la {
            ResolvedAddr::Tcp(a) => self.listen_tcp(&ctx, network, a).map(Listener::Tcp),
            ResolvedAddr::Unix(a) => self.listen_unix(&ctx, network, a).map(Listener::Unix),
            ResolvedAddr::Udp(_) | ResolvedAddr::Ip(_) => Err(Cause::Address(format!(
                "address {address}: unexpected address type"
            ))),
        };
        result.map_err(|e| op_error("listen", network, None, Some(la.to_string()), e))
    }

    fn listen_unix(&self, ctx: &Ctx<'_>, network: &str, laddr: &UnixAddr) -> Result<UnixListener, Cause> {
        let l = ResolvedAddr::Unix(laddr.clone());
        let nfd = unix_socket(ctx, network, Some(&l), None, "listen", self.hook())?;
        UnixListener::from_fd(nfd).map_err(|e| e.err)
    }

    /// `ListenConfig.ListenPacket`: announces on the local `address` of a
    /// packet `network` ("udp", "ip4:icmp", "unixgram", ...).
    pub fn listen_packet(
        &self,
        ctx: &dyn Context,
        network: &str,
        address: &str,
    ) -> Result<PacketConn, OpError> {
        let ctx = Ctx::new(ctx, None);
        let addrs = resolve_addr_list("listen", network, address, None)
            .map_err(|e| op_error("listen", network, None, None, e))?;
        let la = first_addr(&addrs)
            .cloned()
            .ok_or_else(|| op_error("listen", network, None, None, Cause::MissingAddress))?;
        let result = match &la {
            ResolvedAddr::Udp(a) => self.listen_udp(&ctx, network, a).map(PacketConn::Udp),
            ResolvedAddr::Ip(a) => self.listen_ip(&ctx, network, a).map(PacketConn::Ip),
            ResolvedAddr::Unix(a) => self.listen_unixgram(&ctx, network, a).map(PacketConn::Unix),
            ResolvedAddr::Tcp(_) => Err(Cause::Address(format!(
                "address {address}: unexpected address type"
            ))),
        };
        result.map_err(|e| op_error("listen", network, None, Some(la.to_string()), e))
    }

    fn listen_udp(&self, ctx: &Ctx<'_>, network: &str, laddr: &UDPAddr) -> Result<UDPConn, Cause> {
        let l = ResolvedAddr::Udp(laddr.clone());
        let nfd = internet_socket(ctx, network, Some(&l), None, k::SOCK_DGRAM, 0, "listen", self.hook())?;
        UDPConn::from_fd(nfd).map_err(|e| e.err)
    }

    fn listen_ip(&self, ctx: &Ctx<'_>, network: &str, laddr: &IPAddr) -> Result<IPConn, Cause> {
        let (afnet, proto) = parse_network(network, true)?;
        if !matches!(afnet.as_str(), "ip" | "ip4" | "ip6") {
            return Err(Cause::UnknownNetwork(network.into()));
        }
        let l = ResolvedAddr::Ip(laddr.clone());
        let nfd = internet_socket(ctx, &afnet, Some(&l), None, k::SOCK_RAW, proto, "listen", self.hook())?;
        IPConn::from_fd(nfd).map_err(|e| e.err)
    }

    fn listen_unixgram(&self, ctx: &Ctx<'_>, network: &str, laddr: &UnixAddr) -> Result<UnixConn, Cause> {
        let l = ResolvedAddr::Unix(laddr.clone());
        let nfd = unix_socket(ctx, network, Some(&l), None, "listen", self.hook())?;
        new_unix_conn(nfd)
    }
}

/// `net.Listen`: announces on the local network address.
pub fn listen(network: &str, address: &str) -> Result<Listener, OpError> {
    ListenConfig::default().listen(&Background, network, address)
}

/// `net.ListenPacket`: announces on the local network address.
pub fn listen_packet(network: &str, address: &str) -> Result<PacketConn, OpError> {
    ListenConfig::default().listen_packet(&Background, network, address)
}

/// `net.ListenUnix`: announces on a Unix socket ("unix" or "unixpacket").
pub fn listen_unix(network: &str, laddr: Option<&UnixAddr>) -> Result<UnixListener, OpError> {
    if !matches!(network, "unix" | "unixpacket") {
        return Err(op_error(
            "listen",
            network,
            None,
            addr_text(laddr),
            Cause::UnknownNetwork(network.into()),
        ));
    }
    let Some(laddr) = laddr else {
        return Err(op_error("listen", network, None, None, Cause::MissingAddress));
    };
    let lc = ListenConfig::default();
    let ctx = Ctx::new(&Background, None);
    lc.listen_unix(&ctx, network, laddr)
        .map_err(|e| op_error("listen", network, None, Some(laddr.to_string()), e))
}

/// `net.ListenIP`: announces on an IP address of a raw IP network such as
/// "ip4:icmp" (usually needs privileges).
pub fn listen_ip(network: &str, laddr: Option<&IPAddr>) -> Result<IPConn, OpError> {
    let default = IPAddr {
        ip: None,
        zone: String::new(),
    };
    let laddr = laddr.unwrap_or(&default);
    let lc = ListenConfig::default();
    let ctx = Ctx::new(&Background, None);
    lc.listen_ip(&ctx, network, laddr)
        .map_err(|e| op_error("listen", network, None, Some(laddr.to_string()), e))
}

/// `net.ListenMulticastUDP`: announces on a multicast UDP group address,
/// joined on `ifi` (any interface when `None`).
pub fn listen_multicast_udp(
    network: &str,
    ifi: Option<&super::iface::Interface>,
    gaddr: Option<&UDPAddr>,
) -> Result<UDPConn, OpError> {
    let addr_str = addr_text(gaddr);
    if !matches!(network, "udp" | "udp4" | "udp6") {
        return Err(op_error(
            "listen",
            network,
            None,
            addr_str,
            Cause::UnknownNetwork(network.into()),
        ));
    }
    let Some(gaddr) = gaddr.filter(|g| g.ip.is_some()) else {
        return Err(op_error("listen", network, None, addr_str, Cause::MissingAddress));
    };
    let ctx = Ctx::new(&Background, None);
    let l = ResolvedAddr::Udp(gaddr.clone());
    let result = (|| -> Result<UDPConn, Cause> {
        let nfd = internet_socket(&ctx, network, Some(&l), None, k::SOCK_DGRAM, 0, "listen", Hook::default())?;
        let fd = nfd.raw();
        let ip = gaddr.ip.unwrap();
        match ip {
            IpAddr::V4(v4) => {
                super::multicast::listen_ipv4(fd, ifi, v4)?;
            }
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => super::multicast::listen_ipv4(fd, ifi, v4)?,
                None => super::multicast::listen_ipv6(fd, ifi, v6)?,
            },
        }
        UDPConn::from_fd(nfd).map_err(|e| e.err)
    })();
    result.map_err(|e| op_error("listen", network, None, Some(gaddr.to_string()), e))
}

/// `net.FileConn`: a copy of the connection held open by file `f`.
pub fn file_conn(f: &crate::os::File) -> Result<Conn, OpError> {
    let file_error = |err: Cause| OpError {
        op: "file".into(),
        net: "file+net".into(),
        source: None,
        addr: Some(f.name().to_string()),
        err,
    };
    let (nfd, _) = dup_socket(f).map_err(file_error)?;
    let kind = nfd.laddr.clone();
    match kind {
        Some(ResolvedAddr::Tcp(_)) => {
            let stream = wrap_tcp(nfd, 15_000_000_000, &KeepAliveConfig::default())
                .map_err(file_error)?;
            Ok(Conn::Tcp(stream))
        }
        Some(ResolvedAddr::Udp(_)) => {
            UDPConn::from_fd(nfd).map(Conn::Udp).map_err(|e| file_error(e.err))
        }
        Some(ResolvedAddr::Ip(_)) => IPConn::from_fd(nfd).map(Conn::Ip).map_err(|e| file_error(e.err)),
        Some(ResolvedAddr::Unix(_)) => new_unix_conn(nfd).map(Conn::Unix).map_err(file_error),
        None => Err(file_error(Cause::Errno(crate::errno::EPROTONOSUPPORT))),
    }
}

/// `net.FilePacketConn`: a copy of the packet connection held open by file `f`.
pub fn file_packet_conn(f: &crate::os::File) -> Result<PacketConn, OpError> {
    let file_error = |err: Cause| OpError {
        op: "file".into(),
        net: "file+net".into(),
        source: None,
        addr: Some(f.name().to_string()),
        err,
    };
    match file_conn(f)? {
        Conn::Udp(c) => Ok(PacketConn::Udp(c)),
        Conn::Ip(c) => Ok(PacketConn::Ip(c)),
        Conn::Unix(c) if c.network() == "unixgram" => Ok(PacketConn::Unix(c)),
        _ => Err(file_error(Cause::Errno(crate::errno::ENOTSOCK))),
    }
}

/// `net.FileListener`: a copy of the listener held open by file `f`.
pub fn file_listener(f: &crate::os::File) -> Result<Listener, OpError> {
    let file_error = |err: Cause| OpError {
        op: "file".into(),
        net: "file+net".into(),
        source: None,
        addr: Some(f.name().to_string()),
        err,
    };
    let (nfd, _) = dup_socket(f).map_err(file_error)?;
    match nfd.laddr.clone() {
        Some(ResolvedAddr::Tcp(_)) => TCPListener::from_fd(nfd, 15_000_000_000, KeepAliveConfig::default())
            .map(Listener::Tcp)
            .map_err(|e| file_error(e.err)),
        Some(ResolvedAddr::Unix(_)) => {
            let l = UnixListener::from_fd(nfd).map_err(|e| file_error(e.err))?;
            // A listener inherited from a file does not own the socket file.
            l.set_unlink_on_close(false);
            Ok(Listener::Unix(l))
        }
        _ => Err(file_error(Cause::Errno(crate::errno::EPROTONOSUPPORT))),
    }
}

/// Go's `dupSocket` and `fileConn` front half: duplicates the descriptor of
/// `f` and describes the socket.
fn dup_socket(f: &crate::os::File) -> Result<(NetFd, ()), Cause> {
    use std::os::fd::AsRawFd;
    let raw = f.as_raw_fd();
    if raw < 0 {
        return Err(Cause::Closed);
    }
    let dup = ffi::dup(raw).map_err(|e| syscall_cause("dup", e))?;
    let mut ty = [0u8; 4];
    ffi::getsockopt(dup.raw(), k::SOL_SOCKET, k::SO_TYPE, &mut ty)
        .map_err(|e| syscall_cause("getsockopt", e))?;
    let sotype = i32::from_ne_bytes(ty);
    let lsa = ffi::getsockname(dup.raw()).ok();
    let rsa = ffi::getpeername(dup.raw()).ok();
    let family = match lsa.as_ref().map(|a| a.raw_family()) {
        Some(f) if f == k::AF_INET || f == k::AF_INET6 || f == k::AF_UNIX => f,
        _ => return Err(Cause::Errno(crate::errno::EPROTONOSUPPORT)),
    };
    let laddr = lsa.as_ref().and_then(|a| resolved_from(a, family, sotype));
    let raddr = rsa.as_ref().and_then(|a| resolved_from(a, family, sotype));
    let net = laddr.as_ref().map(|a| a.network()).unwrap_or_default();
    ffi::set_nonblocking(dup.raw(), true).map_err(Cause::Errno)?;
    Ok((
        NetFd {
            fd: dup,
            family,
            sotype,
            net,
            connected: raddr.is_some(),
            laddr,
            raddr,
        },
        (),
    ))
}
