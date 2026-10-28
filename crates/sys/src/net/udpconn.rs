//! Go's `net.UDPConn`, built on a deadline-capable descriptor so that
//! deadline changes and `Close` from another thread wake a blocked call at
//! once.
use super::addr::{addr_string, UDPAddr};
use super::error::{Cause, OpError};
use super::msg::{udp_sockaddr, MsgRead};
use super::resolve::ResolvedAddr;
use super::sockconn::SockConn;
use super::socket::NetFd;
use super::sockopt::{self, RawConn};
use crate::errno::Errno;
use crate::ffi::SockAddr;
use std::os::fd::{AsRawFd, RawFd};
use std::time::SystemTime;

/// Go's `net.ErrWriteToConnected`.
const WRITE_TO_CONNECTED: &str = "use of WriteTo with pre-connected connection";

/// `net.UDPConn`: a UDP socket, connected when dialed.
pub struct UDPConn {
    inner: Box<SockConn>,
}

fn udp_addr(a: &Option<ResolvedAddr>) -> Option<UDPAddr> {
    match a {
        Some(ResolvedAddr::Udp(u)) => Some(u.clone()),
        _ => None,
    }
}

impl UDPConn {
    pub(crate) fn from_fd(nfd: NetFd) -> Result<UDPConn, OpError> {
        Ok(UDPConn {
            inner: Box::new(SockConn::new(nfd)?),
        })
    }

    /// `Conn.Read`: reads one datagram.
    pub fn read(&self, b: &mut [u8]) -> Result<usize, OpError> {
        self.inner.read(b)
    }

    /// `Conn.Write`: writes one datagram to the connected peer.
    pub fn write(&self, b: &[u8]) -> Result<usize, OpError> {
        self.inner.write(b)
    }

    /// `UDPConn.ReadFromUDP`: reads a datagram and its sender.
    pub fn read_from_udp(&self, b: &mut [u8]) -> Result<(usize, Option<UDPAddr>), OpError> {
        let r = self.inner.read_msg(b, &mut [])?;
        Ok((r.n, udp_addr(&r.addr)))
    }

    /// `UDPConn.ReadFromUDPAddrPort`: like [`UDPConn::read_from_udp`].
    pub fn read_from_udp_addr_port(
        &self,
        b: &mut [u8],
    ) -> Result<(usize, Option<UDPAddr>), OpError> {
        self.read_from_udp(b)
    }

    /// `PacketConn.ReadFrom`: like [`UDPConn::read_from_udp`].
    pub fn read_from(&self, b: &mut [u8]) -> Result<(usize, Option<UDPAddr>), OpError> {
        self.read_from_udp(b)
    }

    /// `UDPConn.ReadMsgUDP`: reads a datagram with its ancillary data.
    pub fn read_msg_udp(&self, b: &mut [u8], oob: &mut [u8]) -> Result<MsgRead<UDPAddr>, OpError> {
        let r = self.inner.read_msg(b, oob)?;
        Ok(MsgRead {
            n: r.n,
            oobn: r.oobn,
            flags: r.flags,
            addr: udp_addr(&r.addr),
        })
    }

    /// `UDPConn.WriteMsgUDP`: writes a datagram with ancillary data to
    /// `addr`, or to the peer of a connected socket (`addr` is `None`).
    pub fn write_msg_udp(
        &self,
        b: &[u8],
        oob: &[u8],
        addr: Option<&UDPAddr>,
    ) -> Result<(usize, usize), OpError> {
        let to_text = addr.map(|a| addr_string(&a.ip, a.port, &a.zone));
        let fail = |cause: Cause| {
            let mut e = self.inner.op_error("write", cause);
            if to_text.is_some() {
                e.addr = to_text.clone();
            }
            e
        };
        let connected = self.inner.info.connected;
        if connected && addr.is_some() {
            return Err(fail(Cause::Other(WRITE_TO_CONNECTED.into())));
        }
        if !connected && addr.is_none() {
            return Err(fail(Cause::MissingAddress));
        }
        let sa: Option<SockAddr> = match addr {
            Some(a) => Some(udp_sockaddr(self.inner.info.family, a).map_err(fail)?),
            None => None,
        };
        let n = self.inner.write_msg(b, oob, sa.as_ref()).map_err(fail)?;
        Ok((n, oob.len()))
    }

    /// `UDPConn.WriteToUDP`: writes a datagram to `addr`.
    pub fn write_to_udp(&self, b: &[u8], addr: Option<&UDPAddr>) -> Result<usize, OpError> {
        match addr {
            Some(_) => self.write_msg_udp(b, &[], addr).map(|(n, _)| n),
            None => Err(OpError {
                addr: None,
                ..self.inner.op_error("write", Cause::MissingAddress)
            }),
        }
    }

    /// `UDPConn.WriteToUDPAddrPort`: like [`UDPConn::write_to_udp`].
    pub fn write_to_udp_addr_port(&self, b: &[u8], addr: &UDPAddr) -> Result<usize, OpError> {
        self.write_to_udp(b, Some(addr))
    }

    /// `PacketConn.WriteTo`: like [`UDPConn::write_to_udp`].
    pub fn write_to(&self, b: &[u8], addr: &UDPAddr) -> Result<usize, OpError> {
        self.write_to_udp(b, Some(addr))
    }

    /// `Conn.Close`: closes the socket; a blocked call on another thread
    /// fails with a closed-connection error at once.
    pub fn close(&self) -> Result<(), OpError> {
        self.inner.close()
    }

    /// `Conn.LocalAddr`.
    pub fn local_addr(&self) -> Option<UDPAddr> {
        udp_addr(&self.inner.info.laddr)
    }

    /// `Conn.RemoteAddr`: the peer of a connected socket.
    pub fn remote_addr(&self) -> Option<UDPAddr> {
        udp_addr(&self.inner.info.raddr)
    }

    /// `Conn.SetDeadline`: sets the read and write deadlines (`None` clears).
    pub fn set_deadline(&self, t: Option<SystemTime>) -> Result<(), OpError> {
        self.inner.set_deadline(true, true, t)
    }

    /// `Conn.SetReadDeadline`.
    pub fn set_read_deadline(&self, t: Option<SystemTime>) -> Result<(), OpError> {
        self.inner.set_deadline(true, false, t)
    }

    /// `Conn.SetWriteDeadline`.
    pub fn set_write_deadline(&self, t: Option<SystemTime>) -> Result<(), OpError> {
        self.inner.set_deadline(false, true, t)
    }

    /// `UDPConn.SetReadBuffer`.
    pub fn set_read_buffer(&self, bytes: i64) -> Result<(), OpError> {
        sockopt::set_read_buffer(self, bytes)
    }

    /// `UDPConn.SetWriteBuffer`.
    pub fn set_write_buffer(&self, bytes: i64) -> Result<(), OpError> {
        sockopt::set_write_buffer(self, bytes)
    }

    /// `UDPConn.SyscallConn`.
    pub fn syscall_conn(&self) -> Result<RawConn<'_>, Errno> {
        sockopt::syscall_conn(self)
    }

    /// `UDPConn.File`: a duplicate of the socket as a file.
    pub fn file(&self) -> Result<crate::os::File, OpError> {
        self.inner.file()
    }
}

impl std::fmt::Debug for UDPConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UDPConn")
            .field("local", &self.inner.info.laddr)
            .field("remote", &self.inner.info.raddr)
            .finish()
    }
}

impl AsRawFd for UDPConn {
    /// The descriptor, or -1 once the socket is closed.
    fn as_raw_fd(&self) -> RawFd {
        self.inner.raw_fd()
    }
}
