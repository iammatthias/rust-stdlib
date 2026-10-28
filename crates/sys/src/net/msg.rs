//! Message I/O with ancillary data: `UDPConn.ReadMsgUDP`, `WriteMsgUDP`, their
//! `AddrPort` forms and `UnixConn.ReadMsgUnix` / `WriteMsgUnix`, plus the
//! control-message helper `syscall.UnixRights`.
use super::addr::{addr_string, UDPAddr, UnixAddr};
use super::error::{Cause, OpError};
use super::sockopt::{describe, network_name, AsSocket};
use crate::errno::{Errno, EAFNOSUPPORT, EAGAIN, EINTR, EINVAL};
use crate::ffi::{self, k, SockAddr};
use crate::os::SyscallError;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};

/// What `ReadMsgUDP` and `ReadMsgUnix` return besides the error.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MsgRead<A> {
    /// Bytes of payload read.
    pub n: usize,
    /// Bytes of ancillary data read.
    pub oobn: usize,
    /// The `MSG_*` flags the kernel reported (`MSG_TRUNC`, `MSG_CTRUNC`, ...).
    pub flags: i32,
    /// The sender, when the kernel reports one.
    pub addr: Option<A>,
}

/// `net.ErrWriteToConnected`.
const WRITE_TO_CONNECTED: &str = "use of WriteTo with pre-connected connection";

fn wrap<S: AsSocket + ?Sized>(s: &S, op: &str, to: Option<String>, err: Cause) -> OpError {
    let fd = s.socket_fd();
    let local = ffi::getsockname(fd).ok();
    let remote = ffi::getpeername(fd).ok();
    OpError {
        op: op.into(),
        net: network_name(fd, local.as_ref()),
        source: local.as_ref().and_then(describe),
        addr: to.or_else(|| remote.as_ref().and_then(describe)),
        err,
    }
}

/// Waits for a non-blocking socket. A blocking socket's `EAGAIN` is its
/// `SO_RCVTIMEO` / `SO_SNDTIMEO` expiring, which Go reports as a timeout.
fn wait<S: AsSocket + ?Sized>(s: &S, write: bool) -> Result<(), Cause> {
    let fd = s.socket_fd();
    if !ffi::is_nonblocking(fd).unwrap_or(false) {
        return Err(Cause::Timeout);
    }
    loop {
        match ffi::poll(&[(fd, write)], -1) {
            Ok(_) => return Ok(()),
            Err(e) if e == EINTR => continue,
            Err(e) => return Err(Cause::Errno(e)),
        }
    }
}

/// Go's `wrapSyscallError`: an errno from a named call.
fn syscall_cause(syscall: &str, err: Errno) -> Cause {
    Cause::Syscall(SyscallError {
        syscall: syscall.into(),
        err,
    })
}

fn zone_name(index: u32) -> String {
    if index == 0 {
        return String::new();
    }
    match super::iface::interface_by_index(i64::from(index)) {
        Ok(ifi) => ifi.name,
        Err(_) => index.to_string(),
    }
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

fn recv<S: AsSocket + ?Sized>(
    s: &S,
    b: &mut [u8],
    oob: &mut [u8],
    flags: i32,
) -> Result<ffi::Received, Cause> {
    loop {
        match ffi::recvmsg(s.socket_fd(), b, oob, flags) {
            Ok(r) => return Ok(r),
            Err(e) if e == EINTR => continue,
            Err(e) if e == EAGAIN => wait(s, false)?,
            Err(e) => return Err(syscall_cause("recvmsg", e)),
        }
    }
}

fn send<S: AsSocket + ?Sized>(
    s: &S,
    b: &[u8],
    oob: &[u8],
    to: Option<&SockAddr>,
) -> Result<usize, Cause> {
    loop {
        match ffi::sendmsg(s.socket_fd(), b, oob, to, k::MSG_NOSIGNAL) {
            Ok(n) => return Ok(n),
            Err(e) if e == EINTR => continue,
            Err(e) if e == EAGAIN => wait(s, true)?,
            Err(e) => return Err(syscall_cause("sendmsg", e)),
        }
    }
}

pub(crate) fn udp_from(sa: &SockAddr) -> Option<UDPAddr> {
    let inet = sa.to_inet()?;
    Some(match inet {
        SocketAddr::V4(a) => UDPAddr {
            ip: Some(IpAddr::V4(*a.ip())),
            port: a.port(),
            zone: String::new(),
        },
        SocketAddr::V6(a) => UDPAddr {
            ip: Some(IpAddr::V6(*a.ip())),
            port: a.port(),
            zone: zone_name(a.scope_id()),
        },
    })
}

/// `UDPConn.ReadMsgUDP`: reads a datagram and its ancillary data.
pub fn read_msg_udp<S: AsSocket + ?Sized>(
    s: &S,
    b: &mut [u8],
    oob: &mut [u8],
) -> Result<MsgRead<UDPAddr>, OpError> {
    match recv(s, b, oob, 0) {
        Ok(r) => Ok(MsgRead {
            n: r.n,
            oobn: r.oobn,
            flags: r.flags,
            addr: r.from.as_ref().and_then(udp_from),
        }),
        Err(c) => Err(wrap(s, "read", None, c)),
    }
}

/// `UDPConn.ReadMsgUDPAddrPort`: like [`read_msg_udp`]; the sender is the same
/// address type, which carries Go's `netip.AddrPort` fields.
pub fn read_msg_udp_addr_port<S: AsSocket + ?Sized>(
    s: &S,
    b: &mut [u8],
    oob: &mut [u8],
) -> Result<MsgRead<UDPAddr>, OpError> {
    read_msg_udp(s, b, oob)
}

pub(crate) fn udp_sockaddr(local_family: i32, addr: &UDPAddr) -> Result<SockAddr, Cause> {
    let v6_socket = local_family == k::AF_INET6;
    let unspecified = if v6_socket {
        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    };
    Ok(match (&addr.ip.unwrap_or(unspecified), v6_socket) {
        (IpAddr::V4(ip), false) => SockAddr::from_inet(SocketAddr::V4(SocketAddrV4::new(
            *ip, addr.port,
        ))),
        (IpAddr::V4(ip), true) => SockAddr::from_inet(SocketAddr::V6(SocketAddrV6::new(
            ip.to_ipv6_mapped(),
            addr.port,
            0,
            0,
        ))),
        (IpAddr::V6(ip), true) => SockAddr::from_inet(SocketAddr::V6(SocketAddrV6::new(
            *ip,
            addr.port,
            0,
            zone_index(&addr.zone),
        ))),
        (IpAddr::V6(_), false) => {
            return Err(Cause::Address(
                "non-IPv4 address".to_string(),
            ))
        }
    })
}

/// `UDPConn.WriteMsgUDP`: writes a datagram with ancillary data to `addr`, or
/// on a connected socket (`addr` is `None`) to its peer.
pub fn write_msg_udp<S: AsSocket + ?Sized>(
    s: &S,
    b: &[u8],
    oob: &[u8],
    addr: Option<&UDPAddr>,
) -> Result<(usize, usize), OpError> {
    let fd = s.socket_fd();
    let to_text = addr.map(|a| addr_string(&a.ip, a.port, &a.zone));
    let connected = ffi::getpeername(fd).is_ok();
    if connected && addr.is_some() {
        return Err(wrap(s, "write", to_text, Cause::Other(WRITE_TO_CONNECTED.into())));
    }
    if !connected && addr.is_none() {
        return Err(wrap(s, "write", to_text, Cause::MissingAddress));
    }
    let family = ffi::getsockname(fd).map(|a| a.raw_family()).unwrap_or(k::AF_INET);
    let sa = match addr {
        Some(a) => Some(udp_sockaddr(family, a).map_err(|c| wrap(s, "write", to_text.clone(), c))?),
        None => None,
    };
    match send(s, b, oob, sa.as_ref()) {
        Ok(n) => Ok((n, oob.len())),
        Err(c) => Err(wrap(s, "write", to_text, c)),
    }
}

/// `UDPConn.WriteMsgUDPAddrPort`: like [`write_msg_udp`].
pub fn write_msg_udp_addr_port<S: AsSocket + ?Sized>(
    s: &S,
    b: &[u8],
    oob: &[u8],
    addr: Option<&UDPAddr>,
) -> Result<(usize, usize), OpError> {
    write_msg_udp(s, b, oob, addr)
}

fn unix_from(sa: &SockAddr, net: &str) -> Option<UnixAddr> {
    let mut path = sa.to_unix()?;
    if path.is_empty() {
        return None;
    }
    if path.first() == Some(&0) {
        path[0] = b'@';
    }
    Some(UnixAddr {
        name: String::from_utf8_lossy(&path).into_owned(),
        net: net.into(),
    })
}

/// `UnixConn.ReadMsgUnix`: reads a message and its ancillary data (such as
/// passed descriptors) from a Unix socket. Received descriptors are
/// close-on-exec.
pub fn read_msg_unix<S: AsSocket + ?Sized>(
    s: &S,
    b: &mut [u8],
    oob: &mut [u8],
) -> Result<MsgRead<UnixAddr>, OpError> {
    let fd = s.socket_fd();
    match recv(s, b, oob, k::MSG_CMSG_CLOEXEC) {
        Ok(r) => {
            // Linux marks the descriptors itself (MSG_CMSG_CLOEXEC); elsewhere
            // do it after the fact, as Go does.
            if k::MSG_CMSG_CLOEXEC == 0 && r.oobn > 0 {
                for passed in parse_unix_rights(&oob[..r.oobn]).unwrap_or_default() {
                    let _ = ffi::set_cloexec(passed);
                }
            }
            let local = ffi::getsockname(fd).ok();
            let net = network_name(fd, local.as_ref());
            Ok(MsgRead {
                n: r.n,
                oobn: r.oobn,
                flags: r.flags,
                addr: r.from.as_ref().and_then(|a| unix_from(a, &net)),
            })
        }
        Err(c) => Err(wrap(s, "read", None, c)),
    }
}

/// `UnixConn.WriteMsgUnix`: writes a message with ancillary data to `addr`,
/// or to the peer of a connected socket (`addr` is `None`).
pub fn write_msg_unix<S: AsSocket + ?Sized>(
    s: &S,
    b: &[u8],
    oob: &[u8],
    addr: Option<&UnixAddr>,
) -> Result<(usize, usize), OpError> {
    let fd = s.socket_fd();
    let to_text = addr.map(|a| a.name.clone());
    let local = ffi::getsockname(fd).ok();
    let net = network_name(fd, local.as_ref());
    if net == "unixgram" && ffi::getpeername(fd).is_ok() {
        return Err(wrap(s, "write", to_text, Cause::Other(WRITE_TO_CONNECTED.into())));
    }
    let sa = match addr {
        Some(a) => {
            if a.net != net {
                return Err(wrap(s, "write", to_text, Cause::Errno(EAFNOSUPPORT)));
            }
            let mut raw = a.name.clone().into_bytes();
            if raw.first() == Some(&b'@') {
                raw[0] = 0;
            }
            Some(
                SockAddr::from_unix(&raw)
                    .map_err(|e| wrap(s, "write", to_text.clone(), Cause::Errno(e)))?,
            )
        }
        None => None,
    };
    match send(s, b, oob, sa.as_ref()) {
        Ok(n) => Ok((n, oob.len())),
        Err(c) => Err(wrap(s, "write", to_text, c)),
    }
}

/// `syscall.UnixRights`: the ancillary data that passes descriptors with
/// `WriteMsgUnix` (`SCM_RIGHTS`).
pub fn unix_rights(fds: &[i32]) -> Vec<u8> {
    const SCM_RIGHTS: i32 = 1;
    #[cfg(target_os = "linux")]
    const ALIGN: usize = 8;
    #[cfg(not(target_os = "linux"))]
    const ALIGN: usize = 4;
    let align = |n: usize| (n + ALIGN - 1) & !(ALIGN - 1);
    let header = align(if cfg!(target_os = "linux") { 16 } else { 12 });
    let data_len = fds.len() * 4;
    let mut out = vec![0u8; header + align(data_len)];
    let cmsg_len = header + data_len;
    if cfg!(target_os = "linux") {
        out[..8].copy_from_slice(&(cmsg_len as u64).to_ne_bytes());
        out[8..12].copy_from_slice(&k::SOL_SOCKET.to_ne_bytes());
        out[12..16].copy_from_slice(&SCM_RIGHTS.to_ne_bytes());
    } else {
        out[..4].copy_from_slice(&(cmsg_len as u32).to_ne_bytes());
        out[4..8].copy_from_slice(&k::SOL_SOCKET.to_ne_bytes());
        out[8..12].copy_from_slice(&SCM_RIGHTS.to_ne_bytes());
    }
    for (i, fd) in fds.iter().enumerate() {
        out[header + 4 * i..header + 4 * i + 4].copy_from_slice(&fd.to_ne_bytes());
    }
    out
}

/// `syscall.ParseUnixRights` for the first control message of `oob`: the
/// descriptors it carries.
pub fn parse_unix_rights(oob: &[u8]) -> Result<Vec<i32>, Errno> {
    let header = if cfg!(target_os = "linux") { 16 } else { 12 };
    if oob.len() < header {
        return Err(EINVAL);
    }
    let (len, level, kind) = if cfg!(target_os = "linux") {
        (
            u64::from_ne_bytes(oob[..8].try_into().unwrap()) as usize,
            i32::from_ne_bytes(oob[8..12].try_into().unwrap()),
            i32::from_ne_bytes(oob[12..16].try_into().unwrap()),
        )
    } else {
        (
            u32::from_ne_bytes(oob[..4].try_into().unwrap()) as usize,
            i32::from_ne_bytes(oob[4..8].try_into().unwrap()),
            i32::from_ne_bytes(oob[8..12].try_into().unwrap()),
        )
    };
    if level != k::SOL_SOCKET || kind != 1 || len < header || len > oob.len() {
        return Err(EINVAL);
    }
    Ok(oob[header..len]
        .chunks_exact(4)
        .map(|c| i32::from_ne_bytes(c.try_into().unwrap()))
        .collect())
}
