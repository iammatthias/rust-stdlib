//! Socket options and raw descriptor access: `SetLinger`, `SetReadBuffer`,
//! `SetWriteBuffer`, the TCP keep-alive family, `syscall.RawConn` and the
//! `syscall.Getsockopt*` / `Setsockopt*` calls behind them.
//!
//! The functions take any socket (`std::net::TcpStream`, `UdpSocket`,
//! `std::os::unix::net::UnixStream`, the connections of this crate, ...)
//! through [`AsSocket`].
use super::addr::hostport_string;
use super::error::{Cause, OpError};
use crate::errno::{Errno, EINVAL};
use crate::ffi::{self, k, SockAddr};
use crate::os::SyscallError;
use std::marker::PhantomData;

/// A value that owns an operating-system socket descriptor.
pub trait AsSocket {
    /// The raw descriptor.
    fn socket_fd(&self) -> i32;
}

#[cfg(unix)]
impl<T: std::os::fd::AsRawFd + ?Sized> AsSocket for T {
    fn socket_fd(&self) -> i32 {
        self.as_raw_fd()
    }
}

/// `syscall.SOL_SOCKET`, `IPPROTO_TCP`, ... for use with [`getsockopt_int`].
pub mod level {
    use crate::ffi::k;
    /// `syscall.SOL_SOCKET`.
    pub const SOL_SOCKET: i32 = k::SOL_SOCKET;
    /// `syscall.IPPROTO_TCP`.
    pub const IPPROTO_TCP: i32 = k::IPPROTO_TCP;
    /// `syscall.IPPROTO_IP`.
    pub const IPPROTO_IP: i32 = k::IPPROTO_IP;
    /// `syscall.IPPROTO_IPV6`.
    pub const IPPROTO_IPV6: i32 = k::IPPROTO_IPV6;
}

/// Option names for [`getsockopt_int`] and [`setsockopt_int`].
pub mod opt {
    use crate::ffi::k;
    /// `syscall.IP_RECVTTL`.
    pub const IP_RECVTTL: i32 = k::IP_RECVTTL;
    /// `syscall.SO_REUSEADDR`.
    pub const SO_REUSEADDR: i32 = k::SO_REUSEADDR;
    /// `syscall.SO_BROADCAST`.
    pub const SO_BROADCAST: i32 = k::SO_BROADCAST;
    /// `syscall.SO_KEEPALIVE`.
    pub const SO_KEEPALIVE: i32 = k::SO_KEEPALIVE;
    /// `syscall.SO_SNDBUF`.
    pub const SO_SNDBUF: i32 = k::SO_SNDBUF;
    /// `syscall.SO_RCVBUF`.
    pub const SO_RCVBUF: i32 = k::SO_RCVBUF;
    /// `syscall.SO_TYPE`.
    pub const SO_TYPE: i32 = k::SO_TYPE;
    /// `syscall.SO_ERROR`.
    pub const SO_ERROR: i32 = k::SO_ERROR;
    /// `syscall.TCP_NODELAY`.
    pub const TCP_NODELAY: i32 = k::TCP_NODELAY;
    /// `TCP_KEEPIDLE` (`TCP_KEEPALIVE` on macOS).
    pub const TCP_KEEPIDLE: i32 = k::TCP_KEEPIDLE;
    /// `TCP_KEEPINTVL`.
    pub const TCP_KEEPINTVL: i32 = k::TCP_KEEPINTVL;
    /// `TCP_KEEPCNT`.
    pub const TCP_KEEPCNT: i32 = k::TCP_KEEPCNT;
}

fn syscall_error(syscall: &str, err: Errno) -> SyscallError {
    SyscallError {
        syscall: syscall.into(),
        err,
    }
}

/// `syscall.SetsockoptInt` on a socket, wrapped like `os.NewSyscallError`.
pub fn setsockopt_int<S: AsSocket + ?Sized>(
    s: &S,
    level: i32,
    name: i32,
    value: i32,
) -> Result<(), SyscallError> {
    ffi::setsockopt(s.socket_fd(), level, name, &value.to_ne_bytes())
        .map_err(|e| syscall_error("setsockopt", e))
}

/// `syscall.GetsockoptInt` on a socket.
pub fn getsockopt_int<S: AsSocket + ?Sized>(
    s: &S,
    level: i32,
    name: i32,
) -> Result<i32, SyscallError> {
    let mut buf = [0u8; 4];
    ffi::getsockopt(s.socket_fd(), level, name, &mut buf)
        .map_err(|e| syscall_error("getsockopt", e))?;
    Ok(i32::from_ne_bytes(buf))
}

/// `syscall.Linger`: the `SO_LINGER` option value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Linger {
    /// Non-zero when lingering is on.
    pub onoff: i32,
    /// The linger time.
    pub linger: i32,
}

/// `syscall.GetsockoptLinger`.
pub fn getsockopt_linger<S: AsSocket + ?Sized>(s: &S) -> Result<Linger, SyscallError> {
    let mut buf = [0u8; 8];
    ffi::getsockopt(s.socket_fd(), k::SOL_SOCKET, k::SO_LINGER, &mut buf)
        .map_err(|e| syscall_error("getsockopt", e))?;
    Ok(Linger {
        onoff: i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]),
        linger: i32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]),
    })
}

/// Describes a socket end point the way Go's address types print: `host:port`
/// for IP sockets, the path for Unix sockets ("@" when unnamed on Linux).
pub(crate) fn describe(sa: &SockAddr) -> Option<String> {
    if let Some(inet) = sa.to_inet() {
        Some(hostport_string(&inet, ""))
    } else {
        sa.to_unix().map(|mut p| {
            // Go prints a Linux abstract name with a leading '@'.
            if p.first() == Some(&0) {
                p[0] = b'@';
            }
            String::from_utf8_lossy(&p).into_owned()
        })
    }
}

/// The `OpError` Go wraps socket-option failures in: op "set" and the
/// network name. `SetReadBuffer` and `SetWriteBuffer` report only the local
/// address (as `Addr`); the TCP options report local and remote.
fn set_error<S: AsSocket + ?Sized>(s: &S, err: SyscallError, buffer: bool) -> OpError {
    let fd = s.socket_fd();
    let local = ffi::getsockname(fd).ok();
    let remote = ffi::getpeername(fd).ok();
    let (source, addr) = if buffer {
        (None, local.as_ref().and_then(describe))
    } else {
        (
            local.as_ref().and_then(describe),
            remote.as_ref().and_then(describe),
        )
    };
    OpError {
        op: "set".into(),
        net: network_name(fd, local.as_ref()),
        source,
        addr,
        err: Cause::Syscall(err),
    }
}

/// The network name Go would use for the socket: "tcp", "udp", "ip",
/// "unix", ... as far as the descriptor reveals it.
pub(crate) fn network_name(fd: i32, local: Option<&SockAddr>) -> String {
    let Some(local) = local else {
        return String::new();
    };
    let mut ty = [0u8; 4];
    if ffi::getsockopt(fd, k::SOL_SOCKET, k::SO_TYPE, &mut ty).is_err() {
        return String::new();
    }
    let ty = i32::from_ne_bytes(ty);
    match (local.raw_family(), ty) {
        (f, t) if f == k::AF_UNIX && t == k::SOCK_STREAM => "unix".into(),
        (f, t) if f == k::AF_UNIX && t == k::SOCK_DGRAM => "unixgram".into(),
        (f, t) if f == k::AF_UNIX && t == k::SOCK_SEQPACKET => "unixpacket".into(),
        (_, t) if t == k::SOCK_STREAM => "tcp".into(),
        (_, t) if t == k::SOCK_DGRAM => "udp".into(),
        (_, t) if t == k::SOCK_RAW => "ip".into(),
        _ => String::new(),
    }
}

/// `TCPConn.SetLinger`: with `sec >= 0` a close blocks up to `sec` seconds
/// while data is sent; with `sec < 0` (the default) it returns at once.
pub fn set_linger<S: AsSocket + ?Sized>(s: &S, sec: i64) -> Result<(), OpError> {
    let (onoff, linger) = if sec >= 0 { (1i32, sec as i32) } else { (0, 0) };
    let mut buf = [0u8; 8];
    buf[..4].copy_from_slice(&onoff.to_ne_bytes());
    buf[4..].copy_from_slice(&linger.to_ne_bytes());
    ffi::setsockopt(s.socket_fd(), k::SOL_SOCKET, k::SO_LINGER, &buf)
        .map_err(|e| set_error(s, syscall_error("setsockopt", e), false))
}

/// `SetReadBuffer`: the size of the operating system's receive buffer.
pub fn set_read_buffer<S: AsSocket + ?Sized>(s: &S, bytes: i64) -> Result<(), OpError> {
    setsockopt_int(s, k::SOL_SOCKET, k::SO_RCVBUF, bytes as i32).map_err(|e| set_error(s, e, true))
}

/// `SetWriteBuffer`: the size of the operating system's transmit buffer.
pub fn set_write_buffer<S: AsSocket + ?Sized>(s: &S, bytes: i64) -> Result<(), OpError> {
    setsockopt_int(s, k::SOL_SOCKET, k::SO_SNDBUF, bytes as i32).map_err(|e| set_error(s, e, true))
}

/// `TCPConn.SetNoDelay`.
pub fn set_no_delay<S: AsSocket + ?Sized>(s: &S, no_delay: bool) -> Result<(), OpError> {
    setsockopt_int(s, k::IPPROTO_TCP, k::TCP_NODELAY, no_delay as i32).map_err(|e| set_error(s, e, false))
}

/// `TCPConn.SetKeepAlive`: turns keep-alive messages on or off.
pub fn set_keep_alive<S: AsSocket + ?Sized>(s: &S, keepalive: bool) -> Result<(), OpError> {
    setsockopt_int(s, k::SOL_SOCKET, k::SO_KEEPALIVE, keepalive as i32).map_err(|e| set_error(s, e, false))
}

/// Default idle time, probe interval (15 s) and probe count (9) Go picks for
/// a zero field of [`KeepAliveConfig`].
pub const DEFAULT_KEEP_ALIVE_IDLE: i64 = 15_000_000_000;
/// See [`DEFAULT_KEEP_ALIVE_IDLE`].
pub const DEFAULT_KEEP_ALIVE_INTERVAL: i64 = 15_000_000_000;
/// See [`DEFAULT_KEEP_ALIVE_IDLE`].
pub const DEFAULT_KEEP_ALIVE_COUNT: i64 = 9;

/// `net.KeepAliveConfig`: TCP keep-alive options. A zero `idle`, `interval`
/// or `count` selects Go's default; a negative one leaves the socket option
/// unchanged. Durations are nanoseconds (Go's `time.Duration`).
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct KeepAliveConfig {
    /// Whether keep-alive probes are enabled.
    pub enable: bool,
    /// Idle time before the first probe, in nanoseconds.
    pub idle: i64,
    /// Time between probes, in nanoseconds.
    pub interval: i64,
    /// Unanswered probes before the connection drops.
    pub count: i64,
}

/// Go's `roundDurationUp(d, time.Second)`.
fn whole_seconds_up(d_nanos: i64) -> i32 {
    ((d_nanos + 999_999_999) / 1_000_000_000) as i32
}

fn set_seconds<S: AsSocket + ?Sized>(
    s: &S,
    name: i32,
    d: i64,
    default: i64,
) -> Result<(), OpError> {
    let d = match d {
        0 => default,
        d if d < 0 => return Ok(()),
        d => d,
    };
    setsockopt_int(s, k::IPPROTO_TCP, name, whole_seconds_up(d)).map_err(|e| set_error(s, e, false))
}

/// `TCPConn.SetKeepAlivePeriod`: the idle time before keep-alive probes
/// start, in nanoseconds (rounded up to whole seconds).
pub fn set_keep_alive_period<S: AsSocket + ?Sized>(s: &S, d: i64) -> Result<(), OpError> {
    set_seconds(s, k::TCP_KEEPIDLE, d, DEFAULT_KEEP_ALIVE_IDLE)
}

/// `TCPConn.SetKeepAliveConfig`.
pub fn set_keep_alive_config<S: AsSocket + ?Sized>(
    s: &S,
    config: &KeepAliveConfig,
) -> Result<(), OpError> {
    set_keep_alive(s, config.enable)?;
    set_seconds(s, k::TCP_KEEPIDLE, config.idle, DEFAULT_KEEP_ALIVE_IDLE)?;
    set_seconds(
        s,
        k::TCP_KEEPINTVL,
        config.interval,
        DEFAULT_KEEP_ALIVE_INTERVAL,
    )?;
    let count = match config.count {
        0 => DEFAULT_KEEP_ALIVE_COUNT,
        n if n < 0 => return Ok(()),
        n => n,
    };
    setsockopt_int(s, k::IPPROTO_TCP, k::TCP_KEEPCNT, count as i32).map_err(|e| set_error(s, e, false))
}

/// The error from a [`RawConn`] method: Go returns `EINVAL` itself for the
/// unsupported listener calls and an `OpError` otherwise.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RawError {
    /// A bare error number.
    Errno(Errno),
    /// A wrapped network error, e.g. "raw-read tcp ...: ...".
    Op(OpError),
}

impl std::fmt::Display for RawError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RawError::Errno(e) => e.fmt(f),
            RawError::Op(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for RawError {}

/// `syscall.RawConn`: direct access to a socket's descriptor, from
/// `TCPConn.SyscallConn` and friends. It borrows the socket, so the
/// descriptor stays open for as long as the `RawConn` lives.
#[derive(Clone, Copy, Debug)]
pub struct RawConn<'a> {
    fd: i32,
    listener: bool,
    _socket: PhantomData<&'a ()>,
}

/// `TCPConn.SyscallConn`, `UDPConn.SyscallConn`, `UnixConn.SyscallConn` and
/// `IPConn.SyscallConn`: a raw connection whose `read` and `write` wait for
/// the descriptor to become ready.
pub fn syscall_conn<S: AsSocket + ?Sized>(s: &S) -> Result<RawConn<'_>, Errno> {
    raw_conn(s, false)
}

/// `TCPListener.SyscallConn` and `UnixListener.SyscallConn`: the returned
/// raw connection supports only `control`; `read` and `write` return `EINVAL`.
pub fn syscall_listener<S: AsSocket + ?Sized>(s: &S) -> Result<RawConn<'_>, Errno> {
    raw_conn(s, true)
}

fn raw_conn<S: AsSocket + ?Sized>(s: &S, listener: bool) -> Result<RawConn<'_>, Errno> {
    let fd = s.socket_fd();
    if fd < 0 {
        return Err(EINVAL);
    }
    Ok(RawConn {
        fd,
        listener,
        _socket: PhantomData,
    })
}

impl<'a> RawConn<'a> {
    fn error(&self, op: &str, err: Cause) -> OpError {
        let local = ffi::getsockname(self.fd).ok();
        let remote = ffi::getpeername(self.fd).ok();
        let net = network_name(self.fd, local.as_ref());
        OpError {
            op: op.into(),
            net,
            source: local.as_ref().and_then(describe),
            addr: if op == "raw-control" {
                None
            } else {
                remote.as_ref().and_then(describe)
            },
            err,
        }
    }

    /// `RawConn.Control`: calls `f` with the descriptor.
    pub fn control<F: FnOnce(i32)>(&self, f: F) -> Result<(), RawError> {
        f(self.fd);
        Ok(())
    }

    /// `RawConn.Read`: calls `f` with the descriptor, waiting until it is
    /// readable between calls, until `f` returns true.
    pub fn read<F: FnMut(i32) -> bool>(&self, f: F) -> Result<(), RawError> {
        if self.listener {
            return Err(RawError::Errno(EINVAL));
        }
        self.wait_loop("raw-read", false, f)
    }

    /// `RawConn.Write`: calls `f` with the descriptor, waiting until it is
    /// writable between calls, until `f` returns true.
    pub fn write<F: FnMut(i32) -> bool>(&self, f: F) -> Result<(), RawError> {
        if self.listener {
            return Err(RawError::Errno(EINVAL));
        }
        self.wait_loop("raw-write", true, f)
    }

    fn wait_loop<F: FnMut(i32) -> bool>(
        &self,
        op: &str,
        write: bool,
        mut f: F,
    ) -> Result<(), RawError> {
        loop {
            if f(self.fd) {
                return Ok(());
            }
            loop {
                match ffi::poll(&[(self.fd, write)], -1) {
                    Ok(ready) => {
                        if ready[0].invalid {
                            return Err(RawError::Op(self.error(op, Cause::Errno(crate::errno::EBADF))));
                        }
                        break;
                    }
                    Err(e) if e == crate::errno::EINTR => continue,
                    Err(e) => return Err(RawError::Op(self.error(op, Cause::Errno(e)))),
                }
            }
        }
    }
}
