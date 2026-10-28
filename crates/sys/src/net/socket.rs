//! Socket creation: Go's `internetSocket`, `unixSocket`, `socket`,
//! `netFD.dial`, `netFD.listenStream` and `netFD.listenDatagram`.
use super::addr::{IPAddr, TCPAddr, UDPAddr, UnixAddr};
use super::error::{Cause, OpError};
use super::resolve::ResolvedAddr;
use super::sockopt::{AsSocket, RawConn};
use crate::errno::{Errno, EALREADY, EINPROGRESS, EINTR, EISCONN};
use crate::ffi::{self, k, Fd, SockAddr};
use crate::os::SyscallError;
use crate::poll::Core;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Instant, SystemTime};

/// Why a [`Context`] ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ContextError {
    /// `context.Canceled`: "context canceled".
    Canceled,
    /// `context.DeadlineExceeded`: "context deadline exceeded".
    DeadlineExceeded,
}

impl std::fmt::Display for ContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ContextError::Canceled => "context canceled",
            ContextError::DeadlineExceeded => "context deadline exceeded",
        })
    }
}

impl std::error::Error for ContextError {}

/// The part of Go's `context.Context` that dialing uses: a deadline and
/// cancellation. Implement it for your own context type; [`Background`] is
/// the context that never ends.
pub trait Context: Sync {
    /// `Context.Deadline`: when the context expires, if it does.
    fn deadline(&self) -> Option<SystemTime>;
    /// `Context.Err`: why the context is done, or `None` while it is live.
    fn err(&self) -> Option<ContextError>;
    /// Whether [`Context::err`] can ever turn non-`None` before the deadline;
    /// a context that cannot lets a dial sleep until its deadline.
    fn can_cancel(&self) -> bool {
        true
    }
}

/// `context.Background`: no deadline, never canceled.
#[derive(Clone, Copy, Default, Debug)]
pub struct Background;

impl Context for Background {
    fn deadline(&self) -> Option<SystemTime> {
        None
    }
    fn err(&self) -> Option<ContextError> {
        None
    }
    fn can_cancel(&self) -> bool {
        false
    }
}

/// A dial's working context: the user's context, the dialer's own deadline,
/// and an optional racer cancellation flag.
#[derive(Clone, Copy)]
pub(crate) struct Ctx<'a> {
    pub deadline: Option<Instant>,
    pub user: &'a dyn Context,
    pub canceled: Option<&'a AtomicBool>,
}

fn to_instant(t: SystemTime) -> Instant {
    let now = Instant::now();
    match t.duration_since(SystemTime::now()) {
        Ok(ahead) => now + ahead,
        Err(behind) => now.checked_sub(behind.duration()).unwrap_or(now),
    }
}

fn to_system_time(i: Instant) -> SystemTime {
    let now = Instant::now();
    if i >= now {
        SystemTime::now() + (i - now)
    } else {
        SystemTime::now() - (now - i)
    }
}

impl<'a> Ctx<'a> {
    pub fn new(user: &'a dyn Context, deadline: Option<Instant>) -> Ctx<'a> {
        let user_deadline = user.deadline().map(to_instant);
        let deadline = match (deadline, user_deadline) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        Ctx {
            deadline,
            user,
            canceled: None,
        }
    }

    pub fn with_deadline(self, deadline: Instant) -> Ctx<'a> {
        Ctx {
            deadline: Some(self.deadline.map_or(deadline, |d| d.min(deadline))),
            ..self
        }
    }

    pub fn with_cancel(self, flag: &'a AtomicBool) -> Ctx<'a> {
        Ctx {
            canceled: Some(flag),
            ..self
        }
    }

    /// Go's `mapErr(ctx.Err())`: the cause once the context is done.
    pub fn err(&self) -> Option<Cause> {
        if self.canceled.is_some_and(|f| f.load(Ordering::SeqCst)) {
            return Some(Cause::Canceled);
        }
        match self.user.err() {
            Some(ContextError::Canceled) => return Some(Cause::Canceled),
            Some(ContextError::DeadlineExceeded) => return Some(Cause::Timeout),
            None => {}
        }
        if self.deadline.is_some_and(|d| Instant::now() >= d) {
            return Some(Cause::Timeout);
        }
        None
    }

    fn cancellable(&self) -> bool {
        self.canceled.is_some() || self.user.can_cancel()
    }
}

impl Context for Ctx<'_> {
    fn deadline(&self) -> Option<SystemTime> {
        self.deadline.map(to_system_time)
    }
    fn err(&self) -> Option<ContextError> {
        match Ctx::err(self) {
            Some(Cause::Timeout) => Some(ContextError::DeadlineExceeded),
            Some(_) => Some(ContextError::Canceled),
            None => None,
        }
    }
}

/// A `Control` hook: called with the network ("tcp4", "udp6", "unix", ...),
/// the address and the new socket before it is bound or connected.
pub type ControlFn =
    Box<dyn Fn(&str, &str, &RawConn<'_>) -> std::io::Result<()> + Send + Sync + 'static>;

/// A `ControlContext` hook: [`ControlFn`] with the dial's context.
pub type ControlContextFn = Box<
    dyn Fn(&dyn Context, &str, &str, &RawConn<'_>) -> std::io::Result<()> + Send + Sync + 'static,
>;

/// The control hook that applies to one operation.
#[derive(Clone, Copy, Default)]
pub(crate) struct Hook<'a> {
    pub control: Option<&'a ControlFn>,
    pub control_context: Option<&'a ControlContextFn>,
}

impl Hook<'_> {
    fn is_set(&self) -> bool {
        self.control.is_some() || self.control_context.is_some()
    }

    fn call(&self, ctx: &Ctx<'_>, network: &str, address: &str, fd: i32) -> Result<(), Cause> {
        struct Raw(i32);
        impl AsSocket for Raw {
            fn socket_fd(&self) -> i32 {
                self.0
            }
        }
        let raw = Raw(fd);
        let rc = super::sockopt::syscall_conn(&raw).map_err(Cause::Errno)?;
        // ControlContext wins over Control.
        let result = if let Some(f) = self.control_context {
            f(ctx, network, address, &rc)
        } else if let Some(f) = self.control {
            f(network, address, &rc)
        } else {
            Ok(())
        };
        result.map_err(|e| Cause::Other(e.to_string()))
    }
}

/// A socket that has been created and is on its way to becoming a connection.
pub(crate) struct NetFd {
    pub fd: Fd,
    pub family: i32,
    pub sotype: i32,
    /// The network name as given: "tcp", "udp4", "ip4:icmp", "unix", ...
    pub net: String,
    pub laddr: Option<ResolvedAddr>,
    pub raddr: Option<ResolvedAddr>,
    pub connected: bool,
}

pub(crate) fn syscall_cause(syscall: &str, err: Errno) -> Cause {
    Cause::Syscall(SyscallError {
        syscall: syscall.into(),
        err,
    })
}

/// Go's `ctrlNetwork`: the network name a control hook sees.
fn ctrl_network(net: &str, family: i32) -> String {
    if matches!(net, "unix" | "unixgram" | "unixpacket") {
        return net.to_string();
    }
    if net.ends_with('4') || net.ends_with('6') {
        return net.to_string();
    }
    if family == k::AF_INET {
        format!("{net}4")
    } else {
        format!("{net}6")
    }
}

fn is_v4(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(_) => true,
        IpAddr::V6(a) => a.to_ipv4_mapped().is_some(),
    }
}

fn family_of(addr: &ResolvedAddr) -> i32 {
    match addr.ip() {
        Some(ip) if !is_v4(&ip) => k::AF_INET6,
        _ => k::AF_INET,
    }
}

/// Go's `favoriteAddrFamily`: the socket family and whether it is IPv6-only.
fn favorite_family(
    network: &str,
    laddr: Option<&ResolvedAddr>,
    raddr: Option<&ResolvedAddr>,
    mode: &str,
) -> (i32, bool) {
    match network.as_bytes().last() {
        Some(b'4') => return (k::AF_INET, false),
        Some(b'6') => return (k::AF_INET6, true),
        _ => {}
    }
    if mode == "listen" && laddr.is_none_or(|a| a.is_wildcard()) {
        // Dual-stack sockets are available on Linux and macOS.
        return (k::AF_INET6, false);
    }
    if laddr.is_none_or(|a| family_of(a) == k::AF_INET)
        && raddr.is_none_or(|a| family_of(a) == k::AF_INET)
    {
        return (k::AF_INET, false);
    }
    (k::AF_INET6, false)
}

fn zone_index(zone: &str) -> u32 {
    if zone.is_empty() {
        return 0;
    }
    match super::iface::interface_by_name(zone) {
        Ok(ifi) => ifi.index as u32,
        Err(_) => zone.parse().unwrap_or(0),
    }
}

/// Go's `ipToSockaddr` for an internet address of the given family.
fn ip_sockaddr(family: i32, ip: Option<IpAddr>, port: u16, zone: &str) -> Result<SockAddr, Cause> {
    if family == k::AF_INET {
        let ip = match ip {
            None => Ipv4Addr::UNSPECIFIED,
            Some(IpAddr::V4(a)) => a,
            Some(IpAddr::V6(a)) => a.to_ipv4_mapped().ok_or_else(|| {
                Cause::Address(format!(
                    "address {}: non-IPv4 address",
                    super::addr::ip_string(&IpAddr::V6(a))
                ))
            })?,
        };
        Ok(SockAddr::from_inet(SocketAddr::V4(SocketAddrV4::new(ip, port))))
    } else {
        let ip = match ip {
            None => Ipv6Addr::UNSPECIFIED,
            Some(IpAddr::V4(a)) if a.is_unspecified() => Ipv6Addr::UNSPECIFIED,
            Some(IpAddr::V4(a)) => a.to_ipv6_mapped(),
            Some(IpAddr::V6(a)) => a,
        };
        Ok(SockAddr::from_inet(SocketAddr::V6(SocketAddrV6::new(
            ip,
            port,
            0,
            zone_index(zone),
        ))))
    }
}

fn sockaddr_of(addr: &ResolvedAddr, family: i32) -> Result<SockAddr, Cause> {
    match addr {
        ResolvedAddr::Tcp(a) => ip_sockaddr(family, a.ip, a.port, &a.zone),
        ResolvedAddr::Udp(a) => ip_sockaddr(family, a.ip, a.port, &a.zone),
        ResolvedAddr::Ip(a) => ip_sockaddr(family, a.ip, 0, &a.zone),
        ResolvedAddr::Unix(a) => {
            let mut raw = a.name.clone().into_bytes();
            if raw.first() == Some(&b'@') && cfg!(target_os = "linux") {
                raw[0] = 0;
            }
            SockAddr::from_unix(&raw).map_err(Cause::Errno)
        }
    }
}

fn zone_name(index: u32) -> String {
    if index == 0 {
        return String::new();
    }
    super::iface::interface_by_index(i64::from(index))
        .map(|i| i.name)
        .unwrap_or_else(|_| index.to_string())
}

/// Go's `addrFunc`: the address type for a socket's family and type.
pub(crate) fn resolved_from(sa: &SockAddr, family: i32, sotype: i32) -> Option<ResolvedAddr> {
    if family == k::AF_UNIX {
        let mut path = sa.to_unix()?;
        if path.first() == Some(&0) {
            path[0] = b'@';
        }
        let net = match sotype {
            t if t == k::SOCK_STREAM => "unix",
            t if t == k::SOCK_DGRAM => "unixgram",
            t if t == k::SOCK_SEQPACKET => "unixpacket",
            _ => return None,
        };
        return Some(ResolvedAddr::Unix(UnixAddr {
            name: String::from_utf8_lossy(&path).into_owned(),
            net: net.into(),
        }));
    }
    let inet = sa.to_inet()?;
    let (ip, port, zone) = match inet {
        SocketAddr::V4(a) => (IpAddr::V4(*a.ip()), a.port(), String::new()),
        SocketAddr::V6(a) => (IpAddr::V6(*a.ip()), a.port(), zone_name(a.scope_id())),
    };
    let ip = Some(ip);
    Some(match sotype {
        t if t == k::SOCK_STREAM => ResolvedAddr::Tcp(TCPAddr { ip, port, zone }),
        t if t == k::SOCK_DGRAM => ResolvedAddr::Udp(UDPAddr { ip, port, zone }),
        _ => ResolvedAddr::Ip(IPAddr { ip, zone }),
    })
}

/// Go's `setDefaultSockopts`.
fn default_sockopts(fd: i32, family: i32, sotype: i32, ipv6only: bool) -> Result<(), Cause> {
    if family == k::AF_INET6 && sotype != k::SOCK_RAW {
        let _ = ffi::setsockopt(
            fd,
            k::IPPROTO_IPV6,
            k::IPV6_V6ONLY,
            &(ipv6only as i32).to_ne_bytes(),
        );
    }
    if (sotype == k::SOCK_DGRAM || sotype == k::SOCK_RAW) && family != k::AF_UNIX {
        ffi::setsockopt(fd, k::SOL_SOCKET, k::SO_BROADCAST, &1i32.to_ne_bytes())
            .map_err(|e| syscall_cause("setsockopt", e))?;
    }
    Ok(())
}

fn sockopt_one(fd: i32, level: i32, name: i32) -> Result<(), Cause> {
    ffi::setsockopt(fd, level, name, &1i32.to_ne_bytes()).map_err(|e| syscall_cause("setsockopt", e))
}

/// The listen backlog Go uses: the system's `somaxconn`.
fn listener_backlog() -> i32 {
    ffi::somaxconn()
}

impl NetFd {
    fn name_text(addr: &Option<ResolvedAddr>) -> Option<String> {
        addr.as_ref().map(|a| a.to_string())
    }

    pub fn op_error(&self, op: &str, err: Cause) -> OpError {
        OpError {
            op: op.into(),
            net: self.net.clone(),
            source: Self::name_text(&self.laddr),
            addr: Self::name_text(&self.raddr),
            err,
        }
    }

    pub fn raw(&self) -> i32 {
        self.fd.raw()
    }

    pub fn into_core(self) -> Result<(Core, NetFdInfo), Errno> {
        let core = Core::new(self.fd, true)?;
        Ok((
            core,
            NetFdInfo {
                family: self.family,
                sotype: self.sotype,
                net: self.net,
                laddr: self.laddr,
                raddr: self.raddr,
                connected: self.connected,
            },
        ))
    }
}

/// What remains of a [`NetFd`] once its descriptor moves into a `Core`.
#[derive(Clone, Debug)]
pub(crate) struct NetFdInfo {
    pub family: i32,
    pub sotype: i32,
    pub net: String,
    pub laddr: Option<ResolvedAddr>,
    pub raddr: Option<ResolvedAddr>,
    pub connected: bool,
}

/// Waits for a non-blocking connect to finish (Go's `netFD.connect`).
fn connect(fd: i32, ra: &SockAddr, ctx: &Ctx<'_>) -> Result<(), Cause> {
    ffi::set_nonblocking(fd, true).map_err(Cause::Errno)?;
    match ffi::connect(fd, ra) {
        Ok(()) => return Ok(()),
        Err(e) if e == EINPROGRESS || e == EALREADY || e == EINTR => {}
        Err(e) if e == EISCONN => return Ok(()),
        Err(e) => return Err(syscall_cause("connect", e)),
    }
    loop {
        if let Some(c) = ctx.err() {
            return Err(c);
        }
        let mut timeout_ms = -1i32;
        if let Some(d) = ctx.deadline {
            let left = d.saturating_duration_since(Instant::now());
            timeout_ms = (left.as_millis() + u128::from(left.subsec_nanos() % 1_000_000 != 0))
                .min(i32::MAX as u128) as i32;
        }
        if ctx.cancellable() {
            timeout_ms = if timeout_ms < 0 { 10 } else { timeout_ms.min(10) };
        }
        let ready = match ffi::poll(&[(fd, true)], timeout_ms) {
            Ok(r) => r[0],
            Err(e) if e == EINTR => continue,
            Err(e) => return Err(Cause::Errno(e)),
        };
        if !(ready.writable || ready.error || ready.hangup) {
            continue;
        }
        let mut buf = [0u8; 4];
        ffi::getsockopt(fd, k::SOL_SOCKET, k::SO_ERROR, &mut buf)
            .map_err(|e| syscall_cause("getsockopt", e))?;
        let err = Errno(i32::from_ne_bytes(buf));
        if err == EINPROGRESS || err == EALREADY || err == EINTR {
            continue;
        }
        if err == EISCONN {
            return Ok(());
        }
        if err.0 == 0 {
            // The poller can wake spuriously: make sure we are connected.
            if ffi::getpeername(fd).is_ok() {
                return Ok(());
            }
            continue;
        }
        return Err(syscall_cause("connect", err));
    }
}

/// Go's `socket`: creates the socket and, depending on the addresses,
/// dials, listens or binds a datagram socket.
#[allow(clippy::too_many_arguments)]
pub(crate) fn socket(
    ctx: &Ctx<'_>,
    net: &str,
    family: i32,
    sotype: i32,
    proto: i32,
    ipv6only: bool,
    laddr: Option<&ResolvedAddr>,
    raddr: Option<&ResolvedAddr>,
    hook: Hook<'_>,
) -> Result<NetFd, Cause> {
    let fd = ffi::socket(family, sotype, proto).map_err(|e| syscall_cause("socket", e))?;
    default_sockopts(fd.raw(), family, sotype, ipv6only)?;
    let mut nfd = NetFd {
        fd,
        family,
        sotype,
        net: net.to_string(),
        laddr: None,
        raddr: None,
        connected: false,
    };
    if let (Some(local), None) = (laddr, raddr) {
        if sotype == k::SOCK_STREAM || sotype == k::SOCK_SEQPACKET {
            listen_stream(ctx, &mut nfd, local, listener_backlog(), hook)?;
            return Ok(nfd);
        }
        if sotype == k::SOCK_DGRAM {
            listen_datagram(ctx, &mut nfd, local, hook)?;
            return Ok(nfd);
        }
    }
    dial_fd(ctx, &mut nfd, laddr, raddr, hook)?;
    Ok(nfd)
}

fn dial_fd(
    ctx: &Ctx<'_>,
    nfd: &mut NetFd,
    laddr: Option<&ResolvedAddr>,
    raddr: Option<&ResolvedAddr>,
    hook: Hook<'_>,
) -> Result<(), Cause> {
    let fd = nfd.raw();
    if hook.is_set() {
        let address = raddr
            .map(|a| a.to_string())
            .or_else(|| laddr.map(|a| a.to_string()))
            .unwrap_or_default();
        hook.call(ctx, &ctrl_network(&nfd.net, nfd.family), &address, fd)?;
    }
    let mut lsa_present = false;
    if let Some(l) = laddr {
        let lsa = sockaddr_of(l, nfd.family)?;
        lsa_present = true;
        ffi::bind(fd, &lsa).map_err(|e| syscall_cause("bind", e))?;
    }
    let _ = lsa_present;
    let mut connected_to = None;
    if let Some(r) = raddr {
        let rsa = sockaddr_of(r, nfd.family)?;
        connect(fd, &rsa, ctx)?;
        nfd.connected = true;
        connected_to = ffi::getpeername(fd).ok();
    } else {
        ffi::set_nonblocking(fd, true).map_err(Cause::Errno)?;
    }
    let lsa = ffi::getsockname(fd).ok();
    nfd.laddr = lsa
        .as_ref()
        .and_then(|a| resolved_from(a, nfd.family, nfd.sotype));
    nfd.raddr = match connected_to.or_else(|| ffi::getpeername(fd).ok()) {
        Some(a) => resolved_from(&a, nfd.family, nfd.sotype),
        None => raddr.cloned(),
    };
    Ok(())
}

fn listen_stream(
    ctx: &Ctx<'_>,
    nfd: &mut NetFd,
    laddr: &ResolvedAddr,
    backlog: i32,
    hook: Hook<'_>,
) -> Result<(), Cause> {
    let fd = nfd.raw();
    if nfd.family != k::AF_UNIX {
        sockopt_one(fd, k::SOL_SOCKET, k::SO_REUSEADDR)?;
    }
    let lsa = sockaddr_of(laddr, nfd.family)?;
    if hook.is_set() {
        hook.call(ctx, &ctrl_network(&nfd.net, nfd.family), &laddr.to_string(), fd)?;
    }
    ffi::bind(fd, &lsa).map_err(|e| syscall_cause("bind", e))?;
    ffi::listen(fd, backlog).map_err(|e| syscall_cause("listen", e))?;
    ffi::set_nonblocking(fd, true).map_err(Cause::Errno)?;
    nfd.laddr = ffi::getsockname(fd)
        .ok()
        .and_then(|a| resolved_from(&a, nfd.family, nfd.sotype));
    Ok(())
}

fn listen_datagram(
    ctx: &Ctx<'_>,
    nfd: &mut NetFd,
    laddr: &ResolvedAddr,
    hook: Hook<'_>,
) -> Result<(), Cause> {
    let fd = nfd.raw();
    let mut laddr = laddr.clone();
    if let ResolvedAddr::Udp(a) = &laddr {
        if a.ip.is_some_and(|ip| ip.is_multicast()) {
            sockopt_one(fd, k::SOL_SOCKET, k::SO_REUSEADDR)?;
            #[cfg(target_os = "macos")]
            sockopt_one(fd, k::SOL_SOCKET, k::SO_REUSEPORT)?;
            let mut bind_to = a.clone();
            bind_to.ip = Some(if nfd.family == k::AF_INET {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            });
            laddr = ResolvedAddr::Udp(bind_to);
        }
    }
    let lsa = sockaddr_of(&laddr, nfd.family)?;
    if hook.is_set() {
        hook.call(ctx, &ctrl_network(&nfd.net, nfd.family), &laddr.to_string(), fd)?;
    }
    ffi::bind(fd, &lsa).map_err(|e| syscall_cause("bind", e))?;
    ffi::set_nonblocking(fd, true).map_err(Cause::Errno)?;
    nfd.laddr = ffi::getsockname(fd)
        .ok()
        .and_then(|a| resolved_from(&a, nfd.family, nfd.sotype));
    Ok(())
}

/// Go's `internetSocket`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn internet_socket(
    ctx: &Ctx<'_>,
    net: &str,
    laddr: Option<&ResolvedAddr>,
    raddr: Option<&ResolvedAddr>,
    sotype: i32,
    proto: i32,
    mode: &str,
    hook: Hook<'_>,
) -> Result<NetFd, Cause> {
    let (family, ipv6only) = favorite_family(net, laddr, raddr, mode);
    socket(ctx, net, family, sotype, proto, ipv6only, laddr, raddr, hook)
}

/// Go's `unixSocket`.
pub(crate) fn unix_socket(
    ctx: &Ctx<'_>,
    net: &str,
    laddr: Option<&ResolvedAddr>,
    raddr: Option<&ResolvedAddr>,
    mode: &str,
    hook: Hook<'_>,
) -> Result<NetFd, Cause> {
    let sotype = match net {
        "unix" => k::SOCK_STREAM,
        "unixgram" => k::SOCK_DGRAM,
        "unixpacket" => k::SOCK_SEQPACKET,
        _ => return Err(Cause::UnknownNetwork(net.into())),
    };
    let wildcard = |a: &ResolvedAddr| matches!(a, ResolvedAddr::Unix(u) if u.name.is_empty());
    let (mut laddr, mut raddr) = (laddr, raddr);
    match mode {
        "dial" => {
            if laddr.is_some_and(wildcard) {
                laddr = None;
            }
            if raddr.is_some_and(wildcard) {
                raddr = None;
            }
            if raddr.is_none() && (sotype != k::SOCK_DGRAM || laddr.is_none()) {
                return Err(Cause::MissingAddress);
            }
        }
        "listen" => {}
        other => return Err(Cause::Other(format!("unknown mode: {other}"))),
    }
    socket(ctx, net, k::AF_UNIX, sotype, 0, false, laddr, raddr, hook)
}
