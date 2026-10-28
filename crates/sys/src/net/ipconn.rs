//! Go's `net.IPConn`: a raw IP socket (`ip`, `ip4`, `ip6` networks).
use super::addr::IPAddr;
use super::error::{Cause, OpError};
use super::msg::MsgRead;
use super::resolve::ResolvedAddr;
use super::sockconn::SockConn;
use super::socket::NetFd;
use super::sockopt::{self, RawConn};
use crate::errno::{Errno, EINVAL};
use crate::ffi::{self, k, SockAddr};
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, RawFd};
use std::time::SystemTime;

/// Go's `net.ErrWriteToConnected`.
const WRITE_TO_CONNECTED: &str = "use of WriteTo with pre-connected connection";

/// `net.IPConn`: the implementation of the `Conn` and `PacketConn` interfaces
/// for IP network connections. Reads from IPv4 sockets deliver the packet
/// without its IP header when read with `read_from*`.
pub struct IPConn {
    inner: Box<SockConn>,
}

/// Go's `stripIPv4Header`: removes the IPv4 header a raw socket delivers.
pub fn strip_ipv4_header(n: usize, b: &mut [u8]) -> usize {
    if b.len() < 20 {
        return n;
    }
    let l = usize::from(b[0] & 0x0f) << 2;
    if l < 20 || l > b.len() {
        return n;
    }
    if b[0] >> 4 != 4 {
        return n;
    }
    b.copy_within(l.., 0);
    n - l
}

fn ip_addr(sa: &SockAddr) -> Option<IPAddr> {
    match sa.to_inet()? {
        SocketAddr::V4(a) => Some(IPAddr::new(IpAddr::V4(*a.ip()))),
        SocketAddr::V6(a) => {
            let mut out = IPAddr::new(IpAddr::V6(*a.ip()));
            if a.scope_id() != 0 {
                out.zone = super::iface::interface_by_index(i64::from(a.scope_id()))
                    .map(|i| i.name)
                    .unwrap_or_else(|_| a.scope_id().to_string());
            }
            Some(out)
        }
    }
}

impl IPConn {
    pub(crate) fn from_fd(nfd: NetFd) -> Result<IPConn, OpError> {
        Ok(IPConn {
            inner: Box::new(SockConn::new(nfd)?),
        })
    }

    /// `Conn.Read`: reads a packet, IP header included on IPv4.
    pub fn read(&self, b: &mut [u8]) -> Result<usize, OpError> {
        self.inner.read(b)
    }

    /// `Conn.Write`: writes a packet to the connected peer.
    pub fn write(&self, b: &[u8]) -> Result<usize, OpError> {
        self.inner.write(b)
    }

    /// `IPConn.ReadFromIP`: reads a packet and its sender; an IPv4 header is
    /// removed.
    pub fn read_from_ip(&self, b: &mut [u8]) -> Result<(usize, Option<IPAddr>), OpError> {
        let r = self.inner.core.read_with(|fd| ffi::recvmsg(fd, b, &mut [], 0));
        let r = r.map_err(|e| {
            self.inner.op_error(
                "read",
                match e {
                    crate::poll::IoError::Timeout => Cause::Timeout,
                    crate::poll::IoError::Closed => Cause::Closed,
                    crate::poll::IoError::Errno(n) => super::socket::syscall_cause("recvfrom", n),
                },
            )
        })?;
        let from = r.from.as_ref().and_then(ip_addr);
        let mut n = r.n;
        if r.from
            .as_ref()
            .is_some_and(|a| a.raw_family() == k::AF_INET)
        {
            n = strip_ipv4_header(n, b);
        }
        Ok((n, from))
    }

    /// `PacketConn.ReadFrom`: like [`IPConn::read_from_ip`].
    pub fn read_from(&self, b: &mut [u8]) -> Result<(usize, Option<IPAddr>), OpError> {
        self.read_from_ip(b)
    }

    /// `IPConn.ReadMsgIP`: reads a packet with ancillary data.
    pub fn read_msg_ip(&self, b: &mut [u8], oob: &mut [u8]) -> Result<MsgRead<IPAddr>, OpError> {
        let r = self.inner.read_msg(b, oob)?;
        Ok(MsgRead {
            n: r.n,
            oobn: r.oobn,
            flags: r.flags,
            addr: r.addr.and_then(|a| match a {
                ResolvedAddr::Ip(i) => Some(i),
                _ => None,
            }),
        })
    }

    fn target(&self, addr: Option<&IPAddr>) -> Result<SockAddr, Cause> {
        if self.inner.info.connected {
            return Err(Cause::Other(WRITE_TO_CONNECTED.into()));
        }
        let Some(addr) = addr else {
            return Err(Cause::MissingAddress);
        };
        let family = self.inner.info.family;
        let ip = addr.ip;
        let sa = match (family == k::AF_INET, ip) {
            (true, Some(IpAddr::V6(a))) => match a.to_ipv4_mapped() {
                Some(v4) => SocketAddr::V4(SocketAddrV4::new(v4, 0)),
                None => {
                    return Err(Cause::Address(format!(
                        "address {}: non-IPv4 address",
                        super::addr::ip_string(&IpAddr::V6(a))
                    )))
                }
            },
            (true, Some(IpAddr::V4(a))) => SocketAddr::V4(SocketAddrV4::new(a, 0)),
            (true, None) => SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0)),
            (false, Some(IpAddr::V4(a))) => {
                SocketAddr::V6(SocketAddrV6::new(a.to_ipv6_mapped(), 0, 0, 0))
            }
            (false, Some(IpAddr::V6(a))) => SocketAddr::V6(SocketAddrV6::new(a, 0, 0, 0)),
            (false, None) => SocketAddr::V6(SocketAddrV6::new(
                std::net::Ipv6Addr::UNSPECIFIED,
                0,
                0,
                0,
            )),
        };
        Ok(SockAddr::from_inet(sa))
    }

    /// `IPConn.WriteToIP`: writes a packet to `addr`.
    pub fn write_to_ip(&self, b: &[u8], addr: Option<&IPAddr>) -> Result<usize, OpError> {
        let fail = |cause: Cause| OpError {
            addr: addr.map(|a| a.to_string()),
            ..self.inner.op_error("write", cause)
        };
        let sa = self.target(addr).map_err(fail)?;
        self.inner.write_to(b, &sa).map_err(fail)
    }

    /// `PacketConn.WriteTo`: writes a packet to `addr`, which must be an IP
    /// address of this network.
    pub fn write_to(&self, b: &[u8], addr: &ResolvedAddr) -> Result<usize, OpError> {
        match addr {
            ResolvedAddr::Ip(a) => self.write_to_ip(b, Some(a)),
            other => Err(OpError {
                addr: Some(other.to_string()),
                ..self.inner.op_error("write", Cause::Errno(EINVAL))
            }),
        }
    }

    /// `IPConn.WriteMsgIP`: writes a packet with ancillary data to `addr`.
    pub fn write_msg_ip(
        &self,
        b: &[u8],
        oob: &[u8],
        addr: Option<&IPAddr>,
    ) -> Result<(usize, usize), OpError> {
        let fail = |cause: Cause| OpError {
            addr: addr.map(|a| a.to_string()),
            ..self.inner.op_error("write", cause)
        };
        let sa = self.target(addr).map_err(fail)?;
        let n = self.inner.write_msg(b, oob, Some(&sa)).map_err(fail)?;
        Ok((n, oob.len()))
    }

    /// `Conn.Close`: closes the connection; blocked calls fail.
    pub fn close(&self) -> Result<(), OpError> {
        self.inner.close()
    }

    /// `Conn.LocalAddr`.
    pub fn local_addr(&self) -> Option<IPAddr> {
        match &self.inner.info.laddr {
            Some(ResolvedAddr::Ip(a)) => Some(a.clone()),
            _ => None,
        }
    }

    /// `Conn.RemoteAddr`: the peer of a connected socket.
    pub fn remote_addr(&self) -> Option<IPAddr> {
        match &self.inner.info.raddr {
            Some(ResolvedAddr::Ip(a)) => Some(a.clone()),
            _ => None,
        }
    }

    /// `Conn.SetDeadline`: sets the read and write deadlines; `None` clears them.
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

    /// `IPConn.SetReadBuffer`: the size of the operating system's receive buffer.
    pub fn set_read_buffer(&self, bytes: i64) -> Result<(), OpError> {
        sockopt::set_read_buffer(self, bytes)
    }

    /// `IPConn.SetWriteBuffer`: the size of the operating system's transmit buffer.
    pub fn set_write_buffer(&self, bytes: i64) -> Result<(), OpError> {
        sockopt::set_write_buffer(self, bytes)
    }

    /// `IPConn.SyscallConn`: raw access to the descriptor.
    pub fn syscall_conn(&self) -> Result<RawConn<'_>, Errno> {
        sockopt::syscall_conn(self)
    }

    /// `IPConn.File`: a duplicate of the socket as a file.
    pub fn file(&self) -> Result<crate::os::File, OpError> {
        self.inner.file()
    }
}

impl AsRawFd for IPConn {
    /// The descriptor, or -1 once the connection is closed.
    fn as_raw_fd(&self) -> RawFd {
        self.inner.raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::Fd;
    use std::net::UdpSocket;
    use std::os::fd::OwnedFd;
    use std::time::Duration;

    /// Raw sockets need privileges, so exercise the connection logic over
    /// datagram sockets dressed as IP connections.
    fn ip_conn(socket: UdpSocket, connected: bool) -> IPConn {
        let fd = Fd::from_owned(OwnedFd::from(socket));
        let laddr = ffi::getsockname(fd.raw())
            .ok()
            .and_then(|a| super::super::socket::resolved_from(&a, k::AF_INET, k::SOCK_RAW));
        let raddr = ffi::getpeername(fd.raw())
            .ok()
            .and_then(|a| super::super::socket::resolved_from(&a, k::AF_INET, k::SOCK_RAW));
        IPConn::from_fd(NetFd {
            fd,
            family: k::AF_INET,
            sotype: k::SOCK_RAW,
            net: "ip4:icmp".into(),
            laddr,
            raddr,
            connected,
        })
        .unwrap()
    }

    #[test]
    fn reads_strip_the_ipv4_header_and_name_the_sender() {
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        b.connect(a.local_addr().unwrap()).unwrap();
        let reader = ip_conn(a, false);
        let mut packet = vec![0x45u8];
        packet.extend_from_slice(&[0; 19]);
        packet.extend_from_slice(b"body");
        b.send(&packet).unwrap();
        let mut buf = [0u8; 64];
        reader
            .set_read_deadline(Some(SystemTime::now() + Duration::from_secs(2)))
            .unwrap();
        let (n, from) = reader.read_from_ip(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"body");
        assert_eq!(from.unwrap().to_string(), "127.0.0.1");
        assert_eq!(reader.local_addr().unwrap().to_string(), "127.0.0.1");
        assert!(reader.remote_addr().is_none());
    }

    #[test]
    fn writes_follow_the_connected_rules() {
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        b.connect(a.local_addr().unwrap()).unwrap();
        let writer = ip_conn(b, true);
        assert_eq!(writer.write(b"hi").unwrap(), 2);
        let target = IPAddr::new("127.0.0.1".parse().unwrap());
        assert_eq!(
            writer
                .write_to_ip(b"x", Some(&target))
                .unwrap_err()
                .to_string(),
            "write ip4:icmp 127.0.0.1->127.0.0.1: use of WriteTo with pre-connected connection"
        );
        let loose = ip_conn(UdpSocket::bind("127.0.0.1:0").unwrap(), false);
        let err = loose.write_to_ip(b"x", None).unwrap_err();
        assert!(err.to_string().ends_with(": missing address"), "{err}");
        let unix = ResolvedAddr::Unix(super::super::addr::UnixAddr {
            name: "/x".into(),
            net: "unix".into(),
        });
        let err = loose.write_to(b"x", &unix).unwrap_err();
        assert_eq!(err.errno(), Some(EINVAL));
        let six = IPAddr::new("::1".parse().unwrap());
        let err = loose.write_to_ip(b"x", Some(&six)).unwrap_err();
        assert!(
            err.to_string().ends_with("address ::1: non-IPv4 address"),
            "{err}"
        );
    }

    #[test]
    fn deadlines_and_close_wake_reads() {
        let conn = ip_conn(UdpSocket::bind("127.0.0.1:0").unwrap(), false);
        conn.set_read_deadline(Some(SystemTime::now() + Duration::from_millis(40)))
            .unwrap();
        let err = conn.read(&mut [0u8; 8]).unwrap_err();
        assert!(err.timeout());
        assert!(err.to_string().ends_with(": i/o timeout"), "{err}");
        conn.set_read_deadline(None).unwrap();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(60));
                conn.close().unwrap();
            });
            let err = conn.read(&mut [0u8; 8]).unwrap_err();
            assert!(
                err.to_string()
                    .ends_with(": use of closed network connection"),
                "{err}"
            );
        });
        assert!(conn.close().is_err());
        assert!(conn.set_deadline(None).is_err());
        assert_eq!(conn.as_raw_fd(), -1);
    }

    #[test]
    fn buffers_and_raw_access_use_the_descriptor() {
        let conn = ip_conn(UdpSocket::bind("127.0.0.1:0").unwrap(), false);
        conn.set_read_buffer(65536).unwrap();
        conn.set_write_buffer(32768).unwrap();
        let mut seen = -1;
        conn.syscall_conn().unwrap().control(|fd| seen = fd).unwrap();
        assert_eq!(seen, conn.as_raw_fd());
        let file = conn.file().unwrap();
        assert!(file.name().starts_with("ip4:icmp:127.0.0.1->"));
    }
}
