//! `net` operations that need system calls `std` does not expose (raw sockets,
//! socket options, ancillary data, `getifaddrs`, descriptor adoption).
//!
//! Each is present with Go's shape and returns an explicit supported-boundary
//! error, and is recorded with `differs: needs-sys` in `docs/api/net.json`
//! until the system interface crate approved by ADR 0004 exists.
use super::addr::{IPAddr, UDPAddr};
use super::conn::{Conn, Listener, PacketConn};
use super::dial::{Dialer, KeepAliveConfig};
use super::error::{Addr, AddrRef, NetError};
use super::interface::Interface;
use super::netip::{Addr as NetipAddr, AddrPort};
use super::sock::{TCPConn, TCPListener, UDPConn};
use crate::context::Context;
use crate::time::{Duration, Time};

/// The error every unsupported operation returns.
pub(crate) fn needs_sys(what: &str) -> NetError {
    NetError::other(format!(
        "{what} is not supported: it needs the system interface crate (ADR 0004)"
    ))
}

fn op(op: &str, net: &str, what: &str) -> NetError {
    super::conn::op_error(op, net, None, None, needs_sys(what))
}

/// A callback invoked before a socket is bound or connected (Go's `Control`).
/// It is never called: setting it makes dialing and listening fail.
pub type ControlFn = std::sync::Arc<dyn Fn(&str, &str) -> Result<(), NetError> + Send + Sync>;

/// `net.RawConn`: access to a connection's descriptor. Not constructible
/// without the system interface crate.
#[derive(Debug)]
pub struct RawConn(());

impl TCPConn {
    /// `TCPConn.SetLinger` (`SO_LINGER`): unsupported.
    pub fn set_linger(&self, _sec: i32) -> Result<(), NetError> {
        Err(op("set", "tcp", "SetLinger"))
    }
    /// `TCPConn.SetKeepAlive` (`SO_KEEPALIVE`): unsupported.
    pub fn set_keep_alive(&self, _keepalive: bool) -> Result<(), NetError> {
        Err(op("set", "tcp", "SetKeepAlive"))
    }
    /// `TCPConn.SetKeepAliveConfig`: unsupported.
    pub fn set_keep_alive_config(&self, _config: KeepAliveConfig) -> Result<(), NetError> {
        Err(op("set", "tcp", "SetKeepAliveConfig"))
    }
    /// `TCPConn.SetKeepAlivePeriod`: unsupported.
    pub fn set_keep_alive_period(&self, _d: Duration) -> Result<(), NetError> {
        Err(op("set", "tcp", "SetKeepAlivePeriod"))
    }
    /// `TCPConn.SetReadBuffer` (`SO_RCVBUF`): unsupported.
    pub fn set_read_buffer(&self, _bytes: i32) -> Result<(), NetError> {
        Err(op("set", "tcp", "SetReadBuffer"))
    }
    /// `TCPConn.SetWriteBuffer` (`SO_SNDBUF`): unsupported.
    pub fn set_write_buffer(&self, _bytes: i32) -> Result<(), NetError> {
        Err(op("set", "tcp", "SetWriteBuffer"))
    }
    /// `TCPConn.SyscallConn`: unsupported (`AsRawFd` via `as_std` gives the descriptor).
    pub fn syscall_conn(&self) -> Result<RawConn, NetError> {
        Err(op("syscallconn", "tcp", "SyscallConn"))
    }
}

impl TCPListener {
    /// `TCPListener.SyscallConn`: unsupported.
    pub fn syscall_conn(&self) -> Result<RawConn, NetError> {
        Err(op("syscallconn", "tcp", "SyscallConn"))
    }
}

impl UDPConn {
    /// `UDPConn.SetReadBuffer`: unsupported.
    pub fn set_read_buffer(&self, _bytes: i32) -> Result<(), NetError> {
        Err(op("set", "udp", "SetReadBuffer"))
    }
    /// `UDPConn.SetWriteBuffer`: unsupported.
    pub fn set_write_buffer(&self, _bytes: i32) -> Result<(), NetError> {
        Err(op("set", "udp", "SetWriteBuffer"))
    }
    /// `UDPConn.SyscallConn`: unsupported.
    pub fn syscall_conn(&self) -> Result<RawConn, NetError> {
        Err(op("syscallconn", "udp", "SyscallConn"))
    }
    /// `UDPConn.ReadMsgUDP` (ancillary data): unsupported.
    pub fn read_msg_udp(
        &self,
        _b: &mut [u8],
        _oob: &mut [u8],
    ) -> Result<(usize, usize, i32, UDPAddr), NetError> {
        Err(op("read", "udp", "ReadMsgUDP"))
    }
    /// `UDPConn.ReadMsgUDPAddrPort`: unsupported.
    pub fn read_msg_udp_addr_port(
        &self,
        _b: &mut [u8],
        _oob: &mut [u8],
    ) -> Result<(usize, usize, i32, AddrPort), NetError> {
        Err(op("read", "udp", "ReadMsgUDPAddrPort"))
    }
    /// `UDPConn.WriteMsgUDP`: unsupported.
    pub fn write_msg_udp(
        &self,
        _b: &[u8],
        _oob: &[u8],
        _addr: Option<&UDPAddr>,
    ) -> Result<(usize, usize), NetError> {
        Err(op("write", "udp", "WriteMsgUDP"))
    }
    /// `UDPConn.WriteMsgUDPAddrPort`: unsupported.
    pub fn write_msg_udp_addr_port(
        &self,
        _b: &[u8],
        _oob: &[u8],
        _addr: &AddrPort,
    ) -> Result<(usize, usize), NetError> {
        Err(op("write", "udp", "WriteMsgUDPAddrPort"))
    }
}

#[cfg(unix)]
impl super::sock::UnixConn {
    /// `UnixConn.SetReadBuffer`: unsupported.
    pub fn set_read_buffer(&self, _bytes: i32) -> Result<(), NetError> {
        Err(op("set", "unix", "SetReadBuffer"))
    }
    /// `UnixConn.SetWriteBuffer`: unsupported.
    pub fn set_write_buffer(&self, _bytes: i32) -> Result<(), NetError> {
        Err(op("set", "unix", "SetWriteBuffer"))
    }
    /// `UnixConn.SyscallConn`: unsupported.
    pub fn syscall_conn(&self) -> Result<RawConn, NetError> {
        Err(op("syscallconn", "unix", "SyscallConn"))
    }
    /// `UnixConn.ReadMsgUnix` (ancillary data): unsupported.
    pub fn read_msg_unix(
        &self,
        _b: &mut [u8],
        _oob: &mut [u8],
    ) -> Result<(usize, usize, i32, Option<super::addr::UnixAddr>), NetError> {
        Err(op("read", "unix", "ReadMsgUnix"))
    }
    /// `UnixConn.WriteMsgUnix`: unsupported.
    pub fn write_msg_unix(
        &self,
        _b: &[u8],
        _oob: &[u8],
        _addr: Option<&super::addr::UnixAddr>,
    ) -> Result<(usize, usize), NetError> {
        Err(op("write", "unix", "WriteMsgUnix"))
    }
}

#[cfg(unix)]
impl super::sock::UnixListener {
    /// `UnixListener.SyscallConn`: unsupported.
    pub fn syscall_conn(&self) -> Result<RawConn, NetError> {
        Err(op("syscallconn", "unix", "SyscallConn"))
    }
}

/// `net.IPConn`: a raw IP connection. It cannot be created without raw
/// sockets, so no value of this type exists; every method reports so.
pub struct IPConn {
    never: std::convert::Infallible,
}

impl IPConn {
    /// `IPConn.Close`.
    pub fn close(&self) -> Result<(), NetError> {
        match self.never {}
    }
    /// `IPConn.File`.
    pub fn file(&self) -> Result<std::fs::File, NetError> {
        match self.never {}
    }
    /// `IPConn.LocalAddr`.
    pub fn local_addr(&self) -> Option<AddrRef> {
        match self.never {}
    }
    /// `IPConn.Read`.
    pub fn read(&self, _b: &mut [u8]) -> Result<usize, NetError> {
        match self.never {}
    }
    /// `IPConn.ReadFrom`.
    pub fn read_from(&self, _b: &mut [u8]) -> Result<(usize, Option<AddrRef>), NetError> {
        match self.never {}
    }
    /// `IPConn.ReadFromIP`.
    pub fn read_from_ip(&self, _b: &mut [u8]) -> Result<(usize, IPAddr), NetError> {
        match self.never {}
    }
    /// `IPConn.ReadMsgIP`.
    pub fn read_msg_ip(
        &self,
        _b: &mut [u8],
        _oob: &mut [u8],
    ) -> Result<(usize, usize, i32, IPAddr), NetError> {
        match self.never {}
    }
    /// `IPConn.RemoteAddr`.
    pub fn remote_addr(&self) -> Option<AddrRef> {
        match self.never {}
    }
    /// `IPConn.SetDeadline`.
    pub fn set_deadline(&self, _t: &Time) -> Result<(), NetError> {
        match self.never {}
    }
    /// `IPConn.SetReadBuffer`.
    pub fn set_read_buffer(&self, _bytes: i32) -> Result<(), NetError> {
        match self.never {}
    }
    /// `IPConn.SetReadDeadline`.
    pub fn set_read_deadline(&self, _t: &Time) -> Result<(), NetError> {
        match self.never {}
    }
    /// `IPConn.SetWriteBuffer`.
    pub fn set_write_buffer(&self, _bytes: i32) -> Result<(), NetError> {
        match self.never {}
    }
    /// `IPConn.SetWriteDeadline`.
    pub fn set_write_deadline(&self, _t: &Time) -> Result<(), NetError> {
        match self.never {}
    }
    /// `IPConn.SyscallConn`.
    pub fn syscall_conn(&self) -> Result<RawConn, NetError> {
        match self.never {}
    }
    /// `IPConn.Write`.
    pub fn write(&self, _b: &[u8]) -> Result<usize, NetError> {
        match self.never {}
    }
    /// `IPConn.WriteMsgIP`.
    pub fn write_msg_ip(
        &self,
        _b: &[u8],
        _oob: &[u8],
        _addr: Option<&IPAddr>,
    ) -> Result<(usize, usize), NetError> {
        match self.never {}
    }
    /// `IPConn.WriteTo`.
    pub fn write_to(&self, _b: &[u8], _addr: &dyn Addr) -> Result<usize, NetError> {
        match self.never {}
    }
    /// `IPConn.WriteToIP`.
    pub fn write_to_ip(&self, _b: &[u8], _addr: Option<&IPAddr>) -> Result<usize, NetError> {
        match self.never {}
    }
}

/// `net.DialIP`: unsupported (raw sockets).
pub fn dial_ip(
    network: &str,
    _laddr: Option<&IPAddr>,
    _raddr: Option<&IPAddr>,
) -> Result<IPConn, NetError> {
    Err(op("dial", network, "DialIP"))
}

/// `net.ListenIP`: unsupported (raw sockets).
pub fn listen_ip(network: &str, _laddr: Option<&IPAddr>) -> Result<IPConn, NetError> {
    Err(op("listen", network, "ListenIP"))
}

/// `net.ListenMulticastUDP`: unsupported (needs `SO_REUSEADDR` before bind).
pub fn listen_multicast_udp(
    network: &str,
    _ifi: Option<&Interface>,
    _gaddr: Option<&UDPAddr>,
) -> Result<UDPConn, NetError> {
    Err(op("listen", network, "ListenMulticastUDP"))
}

/// `net.FileConn`: unsupported (socket type detection needs `getsockopt`).
pub fn file_conn(_f: std::fs::File) -> Result<Box<dyn Conn>, NetError> {
    Err(op("file", "", "FileConn"))
}

/// `net.FileListener`: unsupported.
pub fn file_listener(_f: std::fs::File) -> Result<Box<dyn Listener>, NetError> {
    Err(op("file", "", "FileListener"))
}

/// `net.FilePacketConn`: unsupported.
pub fn file_packet_conn(_f: std::fs::File) -> Result<Box<dyn PacketConn>, NetError> {
    Err(op("file", "", "FilePacketConn"))
}

/// `net.InterfaceAddrs`: unsupported (needs `getifaddrs`).
pub fn interface_addrs() -> Result<Vec<AddrRef>, NetError> {
    Err(op("route", "ip+net", "InterfaceAddrs"))
}

impl Interface {
    /// `Interface.Addrs`: unsupported (needs `getifaddrs`).
    pub fn addrs(&self) -> Result<Vec<AddrRef>, NetError> {
        Err(op("route", "ip+net", "Interface.Addrs"))
    }
    /// `Interface.MulticastAddrs`: unsupported.
    pub fn multicast_addrs(&self) -> Result<Vec<AddrRef>, NetError> {
        Err(op("route", "ip+net", "Interface.MulticastAddrs"))
    }
}

impl Dialer {
    /// `Dialer.DialIP`: unsupported (raw sockets).
    pub fn dial_ip(
        &self,
        _ctx: &Context,
        network: &str,
        _laddr: &NetipAddr,
        _raddr: &NetipAddr,
    ) -> Result<IPConn, NetError> {
        Err(op("dial", network, "DialIP"))
    }
}
