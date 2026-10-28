//! Go's socket types over `std::net` and `std::os::unix::net`: [`TCPConn`],
//! [`TCPListener`], [`UDPConn`], [`UnixConn`] and [`UnixListener`].
//!
//! Operations that need socket options or system calls `std` does not expose
//! (`SO_LINGER`, keep-alive, buffer sizes, out-of-band messages, raw sockets)
//! are recorded as `differs: needs-sys` or deviations in `docs/api/net.json`.
use super::addr::{TCPAddr, UDPAddr, UnixAddr};
use super::conn::{op_error, Conn, Deadlines, Dir, Listener, PacketConn, Slot};
use super::error::{Addr, AddrRef, NetError};
use super::netip::AddrPort;
use crate::time::Time;
use std::any::Any;
use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::Duration as StdDuration;

pub(crate) trait SockOps: Send + Sync + 'static {
    fn set_rt(&self, d: Option<StdDuration>) -> io::Result<()>;
    fn set_wt(&self, d: Option<StdDuration>) -> io::Result<()>;
    fn shutdown_all(&self) {}
}

impl SockOps for TcpStream {
    fn set_rt(&self, d: Option<StdDuration>) -> io::Result<()> {
        self.set_read_timeout(d)
    }
    fn set_wt(&self, d: Option<StdDuration>) -> io::Result<()> {
        self.set_write_timeout(d)
    }
    fn shutdown_all(&self) {
        let _ = self.shutdown(Shutdown::Both);
    }
}

impl SockOps for UdpSocket {
    fn set_rt(&self, d: Option<StdDuration>) -> io::Result<()> {
        self.set_read_timeout(d)
    }
    fn set_wt(&self, d: Option<StdDuration>) -> io::Result<()> {
        self.set_write_timeout(d)
    }
}

/// State shared by every connection type.
pub(crate) struct ConnCore<S: SockOps> {
    slot: Slot<S>,
    dl: Deadlines,
    net: String,
    laddr: Option<AddrRef>,
    raddr: Option<AddrRef>,
}

impl<S: SockOps> ConnCore<S> {
    pub(crate) fn new(s: S, net: &str, laddr: Option<AddrRef>, raddr: Option<AddrRef>) -> Self {
        ConnCore {
            slot: Slot::new(s),
            dl: Deadlines::default(),
            net: net.into(),
            laddr,
            raddr,
        }
    }

    pub(crate) fn net(&self) -> &str {
        &self.net
    }

    pub(crate) fn laddr(&self) -> Option<AddrRef> {
        self.laddr.clone()
    }

    pub(crate) fn raddr(&self) -> Option<AddrRef> {
        self.raddr.clone()
    }

    pub(crate) fn err(&self, op: &str, e: NetError) -> NetError {
        op_error(op, &self.net, self.laddr.clone(), self.raddr.clone(), e)
    }

    pub(crate) fn sock(&self, op: &str) -> Result<Arc<S>, NetError> {
        self.slot.get().map_err(|e| self.err(op, e))
    }

    pub(crate) fn read_op<T>(
        &self,
        syscall: &str,
        mut f: impl FnMut(&S) -> io::Result<T>,
    ) -> Result<T, NetError> {
        let s = self.sock("read")?;
        self.dl
            .run(Dir::Read, syscall, |d| s.set_rt(d), || f(&s))
            .map_err(|e| self.err("read", e))
    }

    pub(crate) fn write_op<T>(
        &self,
        syscall: &str,
        mut f: impl FnMut(&S) -> io::Result<T>,
    ) -> Result<T, NetError> {
        let s = self.sock("write")?;
        self.dl
            .run(Dir::Write, syscall, |d| s.set_wt(d), || f(&s))
            .map_err(|e| self.err("write", e))
    }

    pub(crate) fn close(&self) -> Result<(), NetError> {
        if !self.dl.mark_closed() {
            return Err(self.err("close", NetError::Closed));
        }
        if let Some(s) = self.slot.take() {
            s.shutdown_all();
        }
        Ok(())
    }

    pub(crate) fn set_deadline(&self, dir: Option<Dir>, t: &Time) -> Result<(), NetError> {
        if self.dl.is_closed() {
            return Err(op_error(
                "set",
                &self.net,
                None,
                self.laddr.clone(),
                NetError::Closed,
            ));
        }
        self.dl.set(dir, t);
        Ok(())
    }

    /// Whether `close` has been called.
    pub(crate) fn is_closed(&self) -> bool {
        self.dl.is_closed()
    }
}

/// Reads until the buffer is full or the stream ends, writing every byte of `b`.
fn write_all<S: SockOps>(
    core: &ConnCore<S>,
    b: &[u8],
    mut f: impl FnMut(&S, &[u8]) -> io::Result<usize>,
) -> Result<usize, NetError> {
    if core.is_closed() {
        return Err(core.err("write", NetError::Closed));
    }
    let mut off = 0;
    while off < b.len() {
        let n = core.write_op("write", |s| f(s, &b[off..]))?;
        if n == 0 {
            return Err(core.err("write", NetError::other("short write")));
        }
        off += n;
    }
    Ok(off)
}

pub(crate) fn tcp_addr_of(a: SocketAddr) -> AddrRef {
    Arc::new(TCPAddr::from(a))
}

pub(crate) fn udp_addr_of(a: SocketAddr) -> AddrRef {
    Arc::new(UDPAddr::from(a))
}

/// `net.TCPConn`: a TCP network connection.
pub struct TCPConn {
    core: ConnCore<TcpStream>,
}

impl TCPConn {
    pub(crate) fn new(stream: TcpStream, net: &str) -> TCPConn {
        let laddr = stream.local_addr().ok().map(tcp_addr_of);
        let raddr = stream.peer_addr().ok().map(tcp_addr_of);
        let _ = stream.set_nodelay(true);
        TCPConn {
            core: ConnCore::new(stream, net, laddr, raddr),
        }
    }

    /// `TCPConn.Read`; `Ok(0)` at end of stream.
    pub fn read(&self, b: &mut [u8]) -> Result<usize, NetError> {
        if self.core.is_closed() {
            return Err(self.core.err("read", NetError::Closed));
        }
        if b.is_empty() {
            return Ok(0);
        }
        let n = self
            .core
            .read_op("read", |mut s| io::Read::read(&mut s, b))?;
        if n == 0 && self.core.is_closed() {
            return Err(self.core.err("read", NetError::Closed));
        }
        Ok(n)
    }

    /// `TCPConn.Write`.
    pub fn write(&self, b: &[u8]) -> Result<usize, NetError> {
        write_all(&self.core, b, |mut s, p| io::Write::write(&mut s, p))
    }

    /// `TCPConn.Close`.
    pub fn close(&self) -> Result<(), NetError> {
        self.core.close()
    }

    /// `TCPConn.CloseRead`: shuts down the reading side.
    pub fn close_read(&self) -> Result<(), NetError> {
        let s = self.core.sock("close")?;
        s.shutdown(Shutdown::Read)
            .map_err(|e| self.core.err("close", NetError::from_io("shutdown", &e)))
    }

    /// `TCPConn.CloseWrite`: shuts down the writing side.
    pub fn close_write(&self) -> Result<(), NetError> {
        let s = self.core.sock("close")?;
        s.shutdown(Shutdown::Write)
            .map_err(|e| self.core.err("close", NetError::from_io("shutdown", &e)))
    }

    /// `TCPConn.LocalAddr`.
    pub fn local_addr(&self) -> Option<AddrRef> {
        self.core.laddr()
    }

    /// `TCPConn.RemoteAddr`.
    pub fn remote_addr(&self) -> Option<AddrRef> {
        self.core.raddr()
    }

    /// `TCPConn.SetDeadline`.
    pub fn set_deadline(&self, t: &Time) -> Result<(), NetError> {
        self.core.set_deadline(None, t)
    }

    /// `TCPConn.SetReadDeadline`.
    pub fn set_read_deadline(&self, t: &Time) -> Result<(), NetError> {
        self.core.set_deadline(Some(Dir::Read), t)
    }

    /// `TCPConn.SetWriteDeadline`.
    pub fn set_write_deadline(&self, t: &Time) -> Result<(), NetError> {
        self.core.set_deadline(Some(Dir::Write), t)
    }

    /// `TCPConn.SetNoDelay`.
    pub fn set_no_delay(&self, no_delay: bool) -> Result<(), NetError> {
        let s = self.core.sock("set")?;
        s.set_nodelay(no_delay)
            .map_err(|e| self.core.err("set", NetError::from_io("setsockopt", &e)))
    }

    /// `TCPConn.MultipathTCP`: always `false`; `std` cannot open MPTCP sockets.
    pub fn multipath_tcp(&self) -> Result<bool, NetError> {
        self.core.sock("read").map(|_| false)
    }

    /// `TCPConn.ReadFrom`: copies from `r` until it ends.
    pub fn read_from(&self, r: &mut dyn io::Read) -> Result<u64, NetError> {
        let mut buf = [0u8; 32 * 1024];
        let mut total = 0u64;
        loop {
            let n = match r.read(&mut buf) {
                Ok(0) => return Ok(total),
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    return Err(self.core.err("readfrom", NetError::from_io("read", &e)));
                }
            };
            self.write(&buf[..n])
                .map_err(|e| self.core.err("readfrom", e))?;
            total += n as u64;
        }
    }

    /// `TCPConn.WriteTo`: copies everything received to `w`.
    pub fn write_to(&self, w: &mut dyn io::Write) -> Result<u64, NetError> {
        let mut buf = [0u8; 32 * 1024];
        let mut total = 0u64;
        loop {
            let n = self
                .read(&mut buf)
                .map_err(|e| self.core.err("writeto", e))?;
            if n == 0 {
                return Ok(total);
            }
            w.write_all(&buf[..n])
                .map_err(|e| self.core.err("writeto", NetError::from_io("write", &e)))?;
            total += n as u64;
        }
    }

    /// `TCPConn.File`: a duplicate of the socket as a file.
    #[cfg(unix)]
    pub fn file(&self) -> Result<std::fs::File, NetError> {
        let s = self.core.sock("file")?;
        let dup = s
            .try_clone()
            .map_err(|e| self.core.err("file", NetError::from_io("dup", &e)))?;
        Ok(std::fs::File::from(std::os::fd::OwnedFd::from(dup)))
    }

    /// The standard-library stream behind this connection.
    pub fn as_std(&self) -> Result<Arc<TcpStream>, NetError> {
        self.core.sock("read")
    }
}

impl Conn for TCPConn {
    fn read(&self, b: &mut [u8]) -> Result<usize, NetError> {
        TCPConn::read(self, b)
    }
    fn write(&self, b: &[u8]) -> Result<usize, NetError> {
        TCPConn::write(self, b)
    }
    fn close(&self) -> Result<(), NetError> {
        TCPConn::close(self)
    }
    fn local_addr(&self) -> Option<AddrRef> {
        TCPConn::local_addr(self)
    }
    fn remote_addr(&self) -> Option<AddrRef> {
        TCPConn::remote_addr(self)
    }
    fn set_deadline(&self, t: &Time) -> Result<(), NetError> {
        TCPConn::set_deadline(self, t)
    }
    fn set_read_deadline(&self, t: &Time) -> Result<(), NetError> {
        TCPConn::set_read_deadline(self, t)
    }
    fn set_write_deadline(&self, t: &Time) -> Result<(), NetError> {
        TCPConn::set_write_deadline(self, t)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl io::Read for &TCPConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        TCPConn::read(self, buf).map_err(NetError::into_io)
    }
}

impl io::Write for &TCPConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        TCPConn::write(self, buf).map_err(NetError::into_io)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl io::Read for TCPConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        TCPConn::read(self, buf).map_err(NetError::into_io)
    }
}

impl io::Write for TCPConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        TCPConn::write(self, buf).map_err(NetError::into_io)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A polling accept loop shared by the stream listeners: the listening
/// socket is non-blocking, so deadlines and `close` are honoured.
fn accept_loop<T>(
    dl: &Deadlines,
    mut try_accept: impl FnMut() -> io::Result<T>,
) -> Result<T, NetError> {
    let mut sleep = StdDuration::from_micros(50);
    loop {
        if dl.is_closed() {
            return Err(NetError::Closed);
        }
        if let Some(d) = dl.remaining(Dir::Read) {
            if d.as_nanos() <= 0 {
                return Err(NetError::IoTimeout);
            }
        }
        match try_accept() {
            Ok(v) => return Ok(v),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                let mut nap = sleep;
                if let Some(d) = dl.remaining(Dir::Read) {
                    nap = nap.min(StdDuration::from_nanos(d.as_nanos().max(1) as u64));
                }
                std::thread::sleep(nap);
                sleep = (sleep * 2).min(StdDuration::from_millis(2));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                if dl.is_closed() {
                    return Err(NetError::Closed);
                }
                return Err(NetError::from_io("accept", &e));
            }
        }
    }
}

/// `net.TCPListener`: a TCP network listener.
pub struct TCPListener {
    slot: Slot<TcpListener>,
    dl: Deadlines,
    net: String,
    laddr: AddrRef,
}

impl TCPListener {
    pub(crate) fn new(l: TcpListener, net: &str) -> io::Result<TCPListener> {
        l.set_nonblocking(true)?;
        let laddr = tcp_addr_of(l.local_addr()?);
        Ok(TCPListener {
            slot: Slot::new(l),
            dl: Deadlines::default(),
            net: net.into(),
            laddr,
        })
    }

    fn err(&self, op: &str, e: NetError) -> NetError {
        op_error(op, &self.net, None, Some(self.laddr.clone()), e)
    }

    /// `TCPListener.AcceptTCP`.
    pub fn accept_tcp(&self) -> Result<TCPConn, NetError> {
        let l = self.slot.get().map_err(|e| self.err("accept", e))?;
        let (stream, _) =
            accept_loop(&self.dl, || l.accept()).map_err(|e| self.err("accept", e))?;
        stream
            .set_nonblocking(false)
            .map_err(|e| self.err("accept", NetError::from_io("accept", &e)))?;
        Ok(TCPConn::new(stream, &self.net))
    }

    /// `TCPListener.Accept`.
    pub fn accept(&self) -> Result<Box<dyn Conn>, NetError> {
        Ok(Box::new(self.accept_tcp()?))
    }

    /// `TCPListener.Close`: already accepted connections stay open.
    pub fn close(&self) -> Result<(), NetError> {
        if !self.dl.mark_closed() {
            return Err(self.err("close", NetError::Closed));
        }
        self.slot.take();
        Ok(())
    }

    /// `TCPListener.Addr`.
    pub fn addr(&self) -> Option<AddrRef> {
        Some(self.laddr.clone())
    }

    /// `TCPListener.SetDeadline`: bounds the next `accept` calls.
    pub fn set_deadline(&self, t: &Time) -> Result<(), NetError> {
        if self.dl.is_closed() {
            return Err(op_error(
                "set",
                &self.net,
                None,
                Some(self.laddr.clone()),
                NetError::Closed,
            ));
        }
        self.dl.set(None, t);
        Ok(())
    }

    /// `TCPListener.File`: a duplicate of the listening socket as a file.
    #[cfg(unix)]
    pub fn file(&self) -> Result<std::fs::File, NetError> {
        let l = self.slot.get().map_err(|e| self.err("file", e))?;
        let dup = l
            .try_clone()
            .map_err(|e| self.err("file", NetError::from_io("dup", &e)))?;
        Ok(std::fs::File::from(std::os::fd::OwnedFd::from(dup)))
    }
}

impl Listener for TCPListener {
    fn accept(&self) -> Result<Box<dyn Conn>, NetError> {
        TCPListener::accept(self)
    }
    fn close(&self) -> Result<(), NetError> {
        TCPListener::close(self)
    }
    fn addr(&self) -> Option<AddrRef> {
        TCPListener::addr(self)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// `net.UDPConn`: a UDP network connection.
pub struct UDPConn {
    core: ConnCore<UdpSocket>,
    connected: bool,
    v6: bool,
}

fn to_socket_addr(a: &UDPAddr) -> Option<SocketAddr> {
    let ip = if a.ip.0.is_empty() {
        std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    } else {
        std::net::IpAddr::try_from(&a.ip).ok()?
    };
    Some(SocketAddr::new(ip, a.port as u16))
}

impl UDPConn {
    pub(crate) fn new(s: UdpSocket, net: &str, connected: bool) -> UDPConn {
        let local = s.local_addr().ok();
        let laddr = local.map(udp_addr_of);
        let raddr = if connected {
            s.peer_addr().ok().map(udp_addr_of)
        } else {
            None
        };
        UDPConn {
            core: ConnCore::new(s, net, laddr, raddr),
            connected,
            v6: local.is_some_and(|a| a.is_ipv6()),
        }
    }

    /// `UDPConn.Read`.
    pub fn read(&self, b: &mut [u8]) -> Result<usize, NetError> {
        if self.core.is_closed() {
            return Err(self.core.err("read", NetError::Closed));
        }
        self.core.read_op("recvfrom", |s| s.recv(b))
    }

    /// `UDPConn.Write`: needs a connected socket.
    pub fn write(&self, b: &[u8]) -> Result<usize, NetError> {
        if self.core.is_closed() {
            return Err(self.core.err("write", NetError::Closed));
        }
        self.core.write_op("write", |s| s.send(b))
    }

    /// `UDPConn.ReadFromUDP`.
    pub fn read_from_udp(&self, b: &mut [u8]) -> Result<(usize, UDPAddr), NetError> {
        if self.core.is_closed() {
            return Err(self.core.err("read", NetError::Closed));
        }
        let (n, a) = self.core.read_op("recvfrom", |s| s.recv_from(b))?;
        Ok((n, UDPAddr::from(a)))
    }

    /// `UDPConn.ReadFromUDPAddrPort`.
    pub fn read_from_udp_addr_port(&self, b: &mut [u8]) -> Result<(usize, AddrPort), NetError> {
        let (n, a) = self.read_from_udp(b)?;
        Ok((n, a.addr_port()))
    }

    /// `UDPConn.ReadFrom`.
    pub fn read_from(&self, b: &mut [u8]) -> Result<(usize, Option<AddrRef>), NetError> {
        let (n, a) = self.read_from_udp(b)?;
        Ok((n, Some(Arc::new(a))))
    }

    fn send_to(
        &self,
        b: &[u8],
        dest: Option<SocketAddr>,
        shown: Option<AddrRef>,
    ) -> Result<usize, NetError> {
        let fail = |e: NetError| {
            op_error(
                "write",
                self.core.net(),
                self.core.laddr(),
                shown.clone(),
                e,
            )
        };
        if self.core.is_closed() {
            return Err(fail(NetError::Closed));
        }
        if self.connected {
            return Err(fail(NetError::WriteToConnected));
        }
        let Some(mut dest) = dest else {
            return Err(fail(NetError::other("missing address")));
        };
        if self.v6 {
            if let SocketAddr::V4(v4) = dest {
                dest = SocketAddr::new(std::net::IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port());
            }
        }
        let s = self
            .core
            .sock("write")
            .map_err(|_| fail(NetError::Closed))?;
        let dl = &self.core.dl_ref();
        dl.run(Dir::Write, "sendto", |d| s.set_wt(d), || s.send_to(b, dest))
            .map_err(fail)
    }

    /// `UDPConn.WriteToUDP`.
    pub fn write_to_udp(&self, b: &[u8], addr: Option<&UDPAddr>) -> Result<usize, NetError> {
        match addr {
            Some(a) => self.send_to(b, to_socket_addr(a), Some(Arc::new(a.clone()))),
            None => self.send_to(b, None, None),
        }
    }

    /// `UDPConn.WriteToUDPAddrPort`.
    pub fn write_to_udp_addr_port(&self, b: &[u8], addr: &AddrPort) -> Result<usize, NetError> {
        let a = super::addr::udp_addr_from_addr_port(addr);
        self.send_to(b, SocketAddr::try_from(addr).ok(), Some(Arc::new(a)))
    }

    /// `UDPConn.WriteTo`: `addr` must be a [`UDPAddr`].
    pub fn write_to(&self, b: &[u8], addr: &dyn Addr) -> Result<usize, NetError> {
        match addr.as_any().downcast_ref::<UDPAddr>() {
            Some(a) => self.write_to_udp(b, Some(a)),
            None => Err(op_error(
                "write",
                self.core.net(),
                self.core.laddr(),
                Some(Arc::new(AddrString(
                    addr.network().to_owned(),
                    addr.to_string(),
                ))),
                NetError::Sys(super::error::SyscallError {
                    syscall: String::new(),
                    text: "invalid argument".into(),
                    kind: io::ErrorKind::InvalidInput,
                    errno: Some(22),
                }),
            )),
        }
    }

    /// `UDPConn.Close`.
    pub fn close(&self) -> Result<(), NetError> {
        self.core.close()
    }

    /// `UDPConn.LocalAddr`.
    pub fn local_addr(&self) -> Option<AddrRef> {
        self.core.laddr()
    }

    /// `UDPConn.RemoteAddr`: `None` when unconnected.
    pub fn remote_addr(&self) -> Option<AddrRef> {
        self.core.raddr()
    }

    /// `UDPConn.SetDeadline`.
    pub fn set_deadline(&self, t: &Time) -> Result<(), NetError> {
        self.core.set_deadline(None, t)
    }

    /// `UDPConn.SetReadDeadline`.
    pub fn set_read_deadline(&self, t: &Time) -> Result<(), NetError> {
        self.core.set_deadline(Some(Dir::Read), t)
    }

    /// `UDPConn.SetWriteDeadline`.
    pub fn set_write_deadline(&self, t: &Time) -> Result<(), NetError> {
        self.core.set_deadline(Some(Dir::Write), t)
    }

    /// `UDPConn.File`: a duplicate of the socket as a file.
    #[cfg(unix)]
    pub fn file(&self) -> Result<std::fs::File, NetError> {
        let s = self.core.sock("file")?;
        let dup = s
            .try_clone()
            .map_err(|e| self.core.err("file", NetError::from_io("dup", &e)))?;
        Ok(std::fs::File::from(std::os::fd::OwnedFd::from(dup)))
    }

    /// The standard-library socket behind this connection.
    pub fn as_std(&self) -> Result<Arc<UdpSocket>, NetError> {
        self.core.sock("read")
    }
}

/// An `Addr` that only carries its two strings.
#[derive(Debug)]
pub(crate) struct AddrString(pub String, pub String);

impl std::fmt::Display for AddrString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.1)
    }
}

impl Addr for AddrString {
    fn network(&self) -> &str {
        &self.0
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl<S: SockOps> ConnCore<S> {
    pub(crate) fn dl_ref(&self) -> &Deadlines {
        &self.dl
    }
}

impl Conn for UDPConn {
    fn read(&self, b: &mut [u8]) -> Result<usize, NetError> {
        UDPConn::read(self, b)
    }
    fn write(&self, b: &[u8]) -> Result<usize, NetError> {
        UDPConn::write(self, b)
    }
    fn close(&self) -> Result<(), NetError> {
        UDPConn::close(self)
    }
    fn local_addr(&self) -> Option<AddrRef> {
        UDPConn::local_addr(self)
    }
    fn remote_addr(&self) -> Option<AddrRef> {
        UDPConn::remote_addr(self)
    }
    fn set_deadline(&self, t: &Time) -> Result<(), NetError> {
        UDPConn::set_deadline(self, t)
    }
    fn set_read_deadline(&self, t: &Time) -> Result<(), NetError> {
        UDPConn::set_read_deadline(self, t)
    }
    fn set_write_deadline(&self, t: &Time) -> Result<(), NetError> {
        UDPConn::set_write_deadline(self, t)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_packet_conn(&self) -> Option<&dyn PacketConn> {
        Some(self)
    }
}

impl PacketConn for UDPConn {
    fn read_from(&self, b: &mut [u8]) -> Result<(usize, Option<AddrRef>), NetError> {
        UDPConn::read_from(self, b)
    }
    fn write_to(&self, b: &[u8], addr: &dyn Addr) -> Result<usize, NetError> {
        UDPConn::write_to(self, b, addr)
    }
    fn close(&self) -> Result<(), NetError> {
        UDPConn::close(self)
    }
    fn local_addr(&self) -> Option<AddrRef> {
        UDPConn::local_addr(self)
    }
    fn set_deadline(&self, t: &Time) -> Result<(), NetError> {
        UDPConn::set_deadline(self, t)
    }
    fn set_read_deadline(&self, t: &Time) -> Result<(), NetError> {
        UDPConn::set_read_deadline(self, t)
    }
    fn set_write_deadline(&self, t: &Time) -> Result<(), NetError> {
        UDPConn::set_write_deadline(self, t)
    }
}

#[cfg(all(unix, feature = "net"))]
pub(crate) use unix_socks::stdin_listener;
#[cfg(unix)]
pub(crate) use unix_socks::unix_addr_for;
#[cfg(unix)]
pub use unix_socks::{UnixConn, UnixListener};

#[cfg(unix)]
mod unix_socks {
    use super::*;
    use std::os::unix::net::{
        SocketAddr as UnixSockAddr, UnixDatagram, UnixListener as StdUnixListener, UnixStream,
    };

    pub(crate) enum UnixSock {
        Stream(UnixStream),
        Dgram(UnixDatagram),
    }

    impl SockOps for UnixSock {
        fn set_rt(&self, d: Option<StdDuration>) -> io::Result<()> {
            match self {
                UnixSock::Stream(s) => s.set_read_timeout(d),
                UnixSock::Dgram(s) => s.set_read_timeout(d),
            }
        }
        fn set_wt(&self, d: Option<StdDuration>) -> io::Result<()> {
            match self {
                UnixSock::Stream(s) => s.set_write_timeout(d),
                UnixSock::Dgram(s) => s.set_write_timeout(d),
            }
        }
        fn shutdown_all(&self) {
            match self {
                UnixSock::Stream(s) => {
                    let _ = s.shutdown(Shutdown::Both);
                }
                UnixSock::Dgram(_) => {}
            }
        }
    }

    pub(crate) fn unix_name(a: &UnixSockAddr) -> String {
        match a.as_pathname() {
            Some(p) => p.to_string_lossy().into_owned(),
            None => unnamed_or_abstract(a),
        }
    }

    /// Go's Linux anyToSockaddr shows the leading NUL of an abstract name,
    /// and the zeroed path of an unnamed address, as "@".
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn unnamed_or_abstract(a: &UnixSockAddr) -> String {
        use std::os::linux::net::SocketAddrExt;
        let n = a.as_abstract_name().unwrap_or_default();
        format!("@{}", String::from_utf8_lossy(n))
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn unnamed_or_abstract(_: &UnixSockAddr) -> String {
        String::new()
    }

    pub(crate) fn unix_addr_for(a: &UnixSockAddr, net: &str) -> AddrRef {
        unix_addr_of(a, net)
    }

    pub(crate) fn unix_addr_of(a: &UnixSockAddr, net: &str) -> AddrRef {
        Arc::new(UnixAddr {
            name: unix_name(a),
            net: net.into(),
        })
    }

    /// `net.UnixConn`: a Unix domain socket connection.
    pub struct UnixConn {
        core: ConnCore<UnixSock>,
        connected: bool,
        unet: String,
    }

    impl UnixConn {
        pub(crate) fn new(
            s: UnixSock,
            net: &str,
            connected: bool,
            local: Option<AddrRef>,
            remote: Option<AddrRef>,
        ) -> UnixConn {
            UnixConn {
                core: ConnCore::new(s, net, local, remote),
                connected,
                unet: net.into(),
            }
        }

        pub(crate) fn datagram(
            s: UnixDatagram,
            net: &str,
            connected: bool,
            local: Option<AddrRef>,
            remote: Option<AddrRef>,
        ) -> UnixConn {
            UnixConn::new(UnixSock::Dgram(s), net, connected, local, remote)
        }

        pub(crate) fn from_stream(s: UnixStream, net: &str) -> UnixConn {
            let l = s.local_addr().ok().map(|a| unix_addr_of(&a, net));
            let r = s.peer_addr().ok().map(|a| unix_addr_of(&a, net));
            UnixConn::new(UnixSock::Stream(s), net, true, l, r)
        }

        /// `UnixConn.Read`; `Ok(0)` at end of stream.
        pub fn read(&self, b: &mut [u8]) -> Result<usize, NetError> {
            if self.core.is_closed() {
                return Err(self.core.err("read", NetError::Closed));
            }
            if b.is_empty() {
                return Ok(0);
            }
            let n = self.core.read_op("read", |s| match s {
                UnixSock::Stream(st) => io::Read::read(&mut { st }, b),
                UnixSock::Dgram(d) => d.recv(b),
            })?;
            if n == 0 && self.core.is_closed() {
                return Err(self.core.err("read", NetError::Closed));
            }
            Ok(n)
        }

        /// `UnixConn.Write`.
        pub fn write(&self, b: &[u8]) -> Result<usize, NetError> {
            write_all(&self.core, b, |s, p| match s {
                UnixSock::Stream(st) => io::Write::write(&mut { st }, p),
                UnixSock::Dgram(d) => d.send(p),
            })
        }

        /// `UnixConn.ReadFromUnix`.
        pub fn read_from_unix(&self, b: &mut [u8]) -> Result<(usize, Option<UnixAddr>), NetError> {
            if self.core.is_closed() {
                return Err(self.core.err("read", NetError::Closed));
            }
            let net = self.unet.clone();
            self.core.read_op("recvfrom", |s| match s {
                UnixSock::Stream(st) => {
                    let n = io::Read::read(&mut { st }, b)?;
                    Ok((n, None))
                }
                UnixSock::Dgram(d) => {
                    // An unnamed sender has no address (Go's nil); std
                    // reports it as unnamed.
                    let (n, a) = d.recv_from(b)?;
                    let name = unix_name(&a);
                    Ok((
                        n,
                        (!a.is_unnamed() && !name.is_empty()).then(|| UnixAddr {
                            name,
                            net: net.clone(),
                        }),
                    ))
                }
            })
        }

        /// `UnixConn.ReadFrom`.
        pub fn read_from(&self, b: &mut [u8]) -> Result<(usize, Option<AddrRef>), NetError> {
            let (n, a) = self.read_from_unix(b)?;
            Ok((n, a.map(|a| Arc::new(a) as AddrRef)))
        }

        /// `UnixConn.WriteToUnix`.
        pub fn write_to_unix(&self, b: &[u8], addr: &UnixAddr) -> Result<usize, NetError> {
            let shown: AddrRef = Arc::new(addr.clone());
            let fail = |e: NetError| {
                op_error(
                    "write",
                    self.core.net(),
                    self.core.laddr(),
                    Some(shown.clone()),
                    e,
                )
            };
            if self.core.is_closed() {
                return Err(fail(NetError::Closed));
            }
            if self.connected {
                return Err(fail(NetError::WriteToConnected));
            }
            if addr.net != self.unet {
                return Err(fail(NetError::Sys(super::super::error::SyscallError {
                    syscall: String::new(),
                    text: "address family not supported by protocol".into(),
                    kind: io::ErrorKind::Unsupported,
                    errno: Some(97),
                })));
            }
            let s = self
                .core
                .sock("write")
                .map_err(|_| fail(NetError::Closed))?;
            let UnixSock::Dgram(d) = &*s else {
                return Err(fail(NetError::WriteToConnected));
            };
            self.core
                .dl_ref()
                .run(
                    Dir::Write,
                    "sendto",
                    |t| d.set_write_timeout(t),
                    || d.send_to(b, &addr.name),
                )
                .map_err(fail)
        }

        /// `UnixConn.WriteTo`: `addr` must be a [`UnixAddr`].
        pub fn write_to(&self, b: &[u8], addr: &dyn Addr) -> Result<usize, NetError> {
            match addr.as_any().downcast_ref::<UnixAddr>() {
                Some(a) => self.write_to_unix(b, a),
                None => Err(op_error(
                    "write",
                    self.core.net(),
                    self.core.laddr(),
                    Some(Arc::new(AddrString(
                        addr.network().to_owned(),
                        addr.to_string(),
                    ))),
                    NetError::Sys(super::super::error::SyscallError {
                        syscall: String::new(),
                        text: "invalid argument".into(),
                        kind: io::ErrorKind::InvalidInput,
                        errno: Some(22),
                    }),
                )),
            }
        }

        /// `UnixConn.Close`.
        pub fn close(&self) -> Result<(), NetError> {
            self.core.close()
        }

        /// `UnixConn.CloseRead`.
        pub fn close_read(&self) -> Result<(), NetError> {
            let s = self.core.sock("close")?;
            let r = match &*s {
                UnixSock::Stream(st) => st.shutdown(Shutdown::Read),
                UnixSock::Dgram(d) => d.shutdown(Shutdown::Read),
            };
            r.map_err(|e| self.core.err("close", NetError::from_io("shutdown", &e)))
        }

        /// `UnixConn.CloseWrite`.
        pub fn close_write(&self) -> Result<(), NetError> {
            let s = self.core.sock("close")?;
            let r = match &*s {
                UnixSock::Stream(st) => st.shutdown(Shutdown::Write),
                UnixSock::Dgram(d) => d.shutdown(Shutdown::Write),
            };
            r.map_err(|e| self.core.err("close", NetError::from_io("shutdown", &e)))
        }

        /// `UnixConn.LocalAddr`.
        pub fn local_addr(&self) -> Option<AddrRef> {
            self.core.laddr()
        }

        /// `UnixConn.RemoteAddr`.
        pub fn remote_addr(&self) -> Option<AddrRef> {
            self.core.raddr()
        }

        /// `UnixConn.SetDeadline`.
        pub fn set_deadline(&self, t: &Time) -> Result<(), NetError> {
            self.core.set_deadline(None, t)
        }

        /// `UnixConn.SetReadDeadline`.
        pub fn set_read_deadline(&self, t: &Time) -> Result<(), NetError> {
            self.core.set_deadline(Some(Dir::Read), t)
        }

        /// `UnixConn.SetWriteDeadline`.
        pub fn set_write_deadline(&self, t: &Time) -> Result<(), NetError> {
            self.core.set_deadline(Some(Dir::Write), t)
        }

        /// `UnixConn.File`: a duplicate of the socket as a file.
        pub fn file(&self) -> Result<std::fs::File, NetError> {
            let s = self.core.sock("file")?;
            let fd = match &*s {
                UnixSock::Stream(st) => st.try_clone().map(std::os::fd::OwnedFd::from),
                UnixSock::Dgram(d) => d.try_clone().map(std::os::fd::OwnedFd::from),
            }
            .map_err(|e| self.core.err("file", NetError::from_io("dup", &e)))?;
            Ok(std::fs::File::from(fd))
        }
    }

    impl Conn for UnixConn {
        fn read(&self, b: &mut [u8]) -> Result<usize, NetError> {
            UnixConn::read(self, b)
        }
        fn write(&self, b: &[u8]) -> Result<usize, NetError> {
            UnixConn::write(self, b)
        }
        fn close(&self) -> Result<(), NetError> {
            UnixConn::close(self)
        }
        fn local_addr(&self) -> Option<AddrRef> {
            UnixConn::local_addr(self)
        }
        fn remote_addr(&self) -> Option<AddrRef> {
            UnixConn::remote_addr(self)
        }
        fn set_deadline(&self, t: &Time) -> Result<(), NetError> {
            UnixConn::set_deadline(self, t)
        }
        fn set_read_deadline(&self, t: &Time) -> Result<(), NetError> {
            UnixConn::set_read_deadline(self, t)
        }
        fn set_write_deadline(&self, t: &Time) -> Result<(), NetError> {
            UnixConn::set_write_deadline(self, t)
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
        fn as_packet_conn(&self) -> Option<&dyn PacketConn> {
            if self.unet == "unix" {
                None
            } else {
                Some(self)
            }
        }
    }

    impl PacketConn for UnixConn {
        fn read_from(&self, b: &mut [u8]) -> Result<(usize, Option<AddrRef>), NetError> {
            UnixConn::read_from(self, b)
        }
        fn write_to(&self, b: &[u8], addr: &dyn Addr) -> Result<usize, NetError> {
            UnixConn::write_to(self, b, addr)
        }
        fn close(&self) -> Result<(), NetError> {
            UnixConn::close(self)
        }
        fn local_addr(&self) -> Option<AddrRef> {
            UnixConn::local_addr(self)
        }
        fn set_deadline(&self, t: &Time) -> Result<(), NetError> {
            UnixConn::set_deadline(self, t)
        }
        fn set_read_deadline(&self, t: &Time) -> Result<(), NetError> {
            UnixConn::set_read_deadline(self, t)
        }
        fn set_write_deadline(&self, t: &Time) -> Result<(), NetError> {
            UnixConn::set_write_deadline(self, t)
        }
    }

    impl io::Read for &UnixConn {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            UnixConn::read(self, buf).map_err(NetError::into_io)
        }
    }

    impl io::Write for &UnixConn {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            UnixConn::write(self, buf).map_err(NetError::into_io)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// `net.UnixListener`: a Unix domain socket listener.
    pub struct UnixListener {
        slot: Slot<StdUnixListener>,
        dl: Deadlines,
        net: String,
        laddr: AddrRef,
        path: Option<String>,
        unlink: std::sync::atomic::AtomicBool,
    }

    impl UnixListener {
        pub(crate) fn new(
            l: StdUnixListener,
            net: &str,
            path: Option<String>,
        ) -> io::Result<UnixListener> {
            l.set_nonblocking(true)?;
            let laddr = unix_addr_of(&l.local_addr()?, net);
            let unlink = path.is_some();
            Ok(UnixListener {
                slot: Slot::new(l),
                dl: Deadlines::default(),
                net: net.into(),
                laddr,
                path,
                unlink: std::sync::atomic::AtomicBool::new(unlink),
            })
        }

        fn err(&self, op: &str, e: NetError) -> NetError {
            op_error(op, &self.net, None, Some(self.laddr.clone()), e)
        }

        /// `UnixListener.AcceptUnix`.
        pub fn accept_unix(&self) -> Result<UnixConn, NetError> {
            let l = self.slot.get().map_err(|e| self.err("accept", e))?;
            let (stream, _) =
                accept_loop(&self.dl, || l.accept()).map_err(|e| self.err("accept", e))?;
            stream
                .set_nonblocking(false)
                .map_err(|e| self.err("accept", NetError::from_io("accept", &e)))?;
            let local = Some(self.laddr.clone());
            let remote = stream.peer_addr().ok().map(|a| unix_addr_of(&a, &self.net));
            Ok(UnixConn::new(
                UnixSock::Stream(stream),
                &self.net,
                true,
                local,
                remote,
            ))
        }

        /// `UnixListener.Accept`.
        pub fn accept(&self) -> Result<Box<dyn Conn>, NetError> {
            Ok(Box::new(self.accept_unix()?))
        }

        /// `UnixListener.Close`: removes the socket file unless
        /// [`set_unlink_on_close`](Self::set_unlink_on_close) said otherwise.
        pub fn close(&self) -> Result<(), NetError> {
            if !self.dl.mark_closed() {
                return Err(self.err("close", NetError::Closed));
            }
            self.slot.take();
            if self.unlink.load(std::sync::atomic::Ordering::SeqCst) {
                if let Some(p) = &self.path {
                    let _ = std::fs::remove_file(p);
                }
            }
            Ok(())
        }

        /// `UnixListener.Addr`.
        pub fn addr(&self) -> Option<AddrRef> {
            Some(self.laddr.clone())
        }

        /// `UnixListener.SetDeadline`.
        pub fn set_deadline(&self, t: &Time) -> Result<(), NetError> {
            if self.dl.is_closed() {
                return Err(op_error(
                    "set",
                    &self.net,
                    None,
                    Some(self.laddr.clone()),
                    NetError::Closed,
                ));
            }
            self.dl.set(None, t);
            Ok(())
        }

        /// `UnixListener.SetUnlinkOnClose`.
        pub fn set_unlink_on_close(&self, unlink: bool) {
            self.unlink
                .store(unlink, std::sync::atomic::Ordering::SeqCst);
        }

        /// `UnixListener.File`: a duplicate of the listening socket as a file.
        pub fn file(&self) -> Result<std::fs::File, NetError> {
            let l = self.slot.get().map_err(|e| self.err("file", e))?;
            let dup = l
                .try_clone()
                .map_err(|e| self.err("file", NetError::from_io("dup", &e)))?;
            Ok(std::fs::File::from(std::os::fd::OwnedFd::from(dup)))
        }
    }

    impl Listener for UnixListener {
        fn accept(&self) -> Result<Box<dyn Conn>, NetError> {
            UnixListener::accept(self)
        }
        fn close(&self) -> Result<(), NetError> {
            UnixListener::close(self)
        }
        fn addr(&self) -> Option<AddrRef> {
            UnixListener::addr(self)
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    /// `net.FileListener(os.Stdin)`: a copy of the listening socket on
    /// standard input. std offers no socket-type query, so the family comes
    /// from `getsockname`: a TCP wrapper rejects a non-IP address without an
    /// OS error, and the Unix wrapper does the same for a non-Unix one.
    #[cfg(feature = "net")]
    pub(crate) fn stdin_listener() -> Result<Box<dyn Listener>, NetError> {
        use std::os::fd::AsFd;
        let name: AddrRef = Arc::new(AddrString("file+net".into(), "/dev/stdin".into()));
        let file_err = |e: NetError| op_error("file", "file+net", None, Some(name.clone()), e);
        let fd = std::io::stdin()
            .as_fd()
            .try_clone_to_owned()
            .map_err(|e| file_err(NetError::from_io("dup", &e)))?;
        let tcp = std::net::TcpListener::from(fd);
        match tcp.local_addr() {
            Ok(_) => {
                return Ok(Box::new(
                    TCPListener::new(tcp, "tcp")
                        .map_err(|e| file_err(NetError::from_io("listen", &e)))?,
                ))
            }
            Err(e) if e.raw_os_error().is_some() => {
                return Err(file_err(NetError::from_io("getsockopt", &e)))
            }
            Err(_) => {}
        }
        let unix = StdUnixListener::from(std::os::fd::OwnedFd::from(tcp));
        match unix.local_addr() {
            Ok(_) => Ok(Box::new(
                UnixListener::new(unix, "unix", None)
                    .map_err(|e| file_err(NetError::from_io("listen", &e)))?,
            )),
            Err(e) if e.raw_os_error().is_some() => {
                Err(file_err(NetError::from_io("getsockopt", &e)))
            }
            Err(_) => Err(file_err(NetError::other("protocol not supported"))),
        }
    }
}
