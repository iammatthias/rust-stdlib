//! Unix-domain sockets beyond what std offers: `unixpacket`
//! (`SOCK_SEQPACKET`) connections and listeners, and the listener that
//! unlinks its socket file on close like Go's `net.UnixListener`.
use super::addr::UnixAddr;
use super::error::{Cause, OpError};
use super::msg::{parse_unix_rights, MsgRead};
use super::resolve::ResolvedAddr;
use super::sockconn::SockConn;
use super::socket::{resolved_from, syscall_cause, NetFd, NetFdInfo};
use super::sockopt::{self, RawConn};
use crate::errno::Errno;
use crate::ffi::{self, k, SockAddr};
use crate::poll::{Core, IoError};
use std::os::fd::{AsRawFd, RawFd};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

/// Go's `net.ErrWriteToConnected`.
const WRITE_TO_CONNECTED: &str = "use of WriteTo with pre-connected connection";

fn unix_addr(a: &Option<ResolvedAddr>) -> Option<UnixAddr> {
    match a {
        Some(ResolvedAddr::Unix(u)) => Some(u.clone()),
        _ => None,
    }
}

fn sockaddr_for(addr: &UnixAddr) -> Result<SockAddr, Errno> {
    let mut raw = addr.name.clone().into_bytes();
    if raw.first() == Some(&b'@') && cfg!(target_os = "linux") {
        raw[0] = 0;
    }
    SockAddr::from_unix(&raw)
}

/// `net.UnixConn`: a Unix-domain connection of any of the three networks
/// ("unix", "unixgram" or "unixpacket"). Deadline changes and `close` from
/// another thread wake a blocked call at once.
pub struct UnixConn {
    inner: Box<SockConn>,
}

impl UnixConn {
    pub(crate) fn from_fd(nfd: NetFd) -> Result<UnixConn, OpError> {
        Ok(UnixConn {
            inner: Box::new(SockConn::new(nfd)?),
        })
    }

    /// The network name: "unix", "unixgram" or "unixpacket".
    pub fn network(&self) -> &str {
        &self.inner.info.net
    }

    /// `Conn.Read`: reads bytes (a stream) or one message (0 at end of stream).
    pub fn read(&self, b: &mut [u8]) -> Result<usize, OpError> {
        self.inner.read(b)
    }

    /// `Conn.Write`: writes all of `b` (a stream) or one message.
    pub fn write(&self, b: &[u8]) -> Result<usize, OpError> {
        self.inner.write(b)
    }

    /// `UnixConn.ReadFromUnix`: reads a message and its sender.
    pub fn read_from_unix(&self, b: &mut [u8]) -> Result<(usize, Option<UnixAddr>), OpError> {
        let r = self.read_msg_unix(b, &mut [])?;
        Ok((r.n, r.addr))
    }

    /// `PacketConn.ReadFrom`: like [`UnixConn::read_from_unix`].
    pub fn read_from(&self, b: &mut [u8]) -> Result<(usize, Option<UnixAddr>), OpError> {
        self.read_from_unix(b)
    }

    /// `UnixConn.ReadMsgUnix`: reads a message and its ancillary data.
    pub fn read_msg_unix(
        &self,
        b: &mut [u8],
        oob: &mut [u8],
    ) -> Result<MsgRead<UnixAddr>, OpError> {
        let r = self.inner.read_msg_flags(b, oob, k::MSG_CMSG_CLOEXEC)?;
        // Linux marks received descriptors itself; elsewhere do it afterwards.
        if k::MSG_CMSG_CLOEXEC == 0 && r.oobn > 0 {
            for passed in parse_unix_rights(&oob[..r.oobn]).unwrap_or_default() {
                let _ = ffi::set_cloexec(passed);
            }
        }
        Ok(MsgRead {
            n: r.n,
            oobn: r.oobn,
            flags: r.flags,
            addr: unix_addr(&r.addr).filter(|a| !a.name.is_empty()),
        })
    }

    /// `UnixConn.WriteMsgUnix`: writes a message with ancillary data to
    /// `addr`, or to the peer of a connected socket (`addr` is `None`).
    pub fn write_msg_unix(
        &self,
        b: &[u8],
        oob: &[u8],
        addr: Option<&UnixAddr>,
    ) -> Result<(usize, usize), OpError> {
        let fail = |cause: Cause| OpError {
            addr: addr.map(|a| a.name.clone()),
            ..self.inner.op_error("write", cause)
        };
        if self.inner.info.net == "unixgram" && self.inner.info.connected {
            return Err(fail(Cause::Other(WRITE_TO_CONNECTED.into())));
        }
        let sa = match addr {
            Some(a) => {
                if a.net != self.inner.info.net {
                    return Err(fail(Cause::Errno(crate::errno::EAFNOSUPPORT)));
                }
                Some(sockaddr_for(a).map_err(|e| fail(Cause::Errno(e)))?)
            }
            None => None,
        };
        let n = self.inner.write_msg(b, oob, sa.as_ref()).map_err(fail)?;
        Ok((n, oob.len()))
    }

    /// `UnixConn.WriteToUnix`: writes a message to `addr`.
    pub fn write_to_unix(&self, b: &[u8], addr: &UnixAddr) -> Result<usize, OpError> {
        if self.inner.info.connected {
            return Err(OpError {
                addr: Some(addr.name.clone()),
                ..self
                    .inner
                    .op_error("write", Cause::Other(WRITE_TO_CONNECTED.into()))
            });
        }
        self.write_msg_unix(b, &[], Some(addr)).map(|(n, _)| n)
    }

    /// `PacketConn.WriteTo`: like [`UnixConn::write_to_unix`].
    pub fn write_to(&self, b: &[u8], addr: &UnixAddr) -> Result<usize, OpError> {
        self.write_to_unix(b, addr)
    }

    /// `UnixConn.CloseRead`: shuts down the reading side.
    pub fn close_read(&self) -> Result<(), OpError> {
        self.inner.shutdown(k::SHUT_RD)
    }

    /// `UnixConn.CloseWrite`: shuts down the writing side.
    pub fn close_write(&self) -> Result<(), OpError> {
        self.inner.shutdown(k::SHUT_WR)
    }

    /// `Conn.Close`: closes the connection; a blocked call on another thread
    /// fails with a closed-connection error at once.
    pub fn close(&self) -> Result<(), OpError> {
        self.inner.close()
    }

    /// `Conn.LocalAddr`.
    pub fn local_addr(&self) -> Option<UnixAddr> {
        unix_addr(&self.inner.info.laddr)
    }

    /// `Conn.RemoteAddr`.
    pub fn remote_addr(&self) -> Option<UnixAddr> {
        unix_addr(&self.inner.info.raddr)
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

    /// `UnixConn.SetReadBuffer`.
    pub fn set_read_buffer(&self, bytes: i64) -> Result<(), OpError> {
        sockopt::set_read_buffer(self, bytes)
    }

    /// `UnixConn.SetWriteBuffer`.
    pub fn set_write_buffer(&self, bytes: i64) -> Result<(), OpError> {
        sockopt::set_write_buffer(self, bytes)
    }

    /// `UnixConn.SyscallConn`.
    pub fn syscall_conn(&self) -> Result<RawConn<'_>, Errno> {
        sockopt::syscall_conn(self)
    }

    /// `UnixConn.File`: a duplicate of the socket as a file.
    pub fn file(&self) -> Result<crate::os::File, OpError> {
        self.inner.file()
    }
}

impl std::fmt::Debug for UnixConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnixConn")
            .field("local", &self.inner.info.laddr)
            .field("remote", &self.inner.info.raddr)
            .finish()
    }
}

impl AsRawFd for UnixConn {
    /// The descriptor, or -1 once the connection is closed.
    fn as_raw_fd(&self) -> RawFd {
        self.inner.raw_fd()
    }
}

impl io::Read for &UnixConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        UnixConn::read(self, buf).map_err(Into::into)
    }
}

impl io::Write for &UnixConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        UnixConn::write(self, buf).map_err(Into::into)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl io::Read for UnixConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        UnixConn::read(self, buf).map_err(Into::into)
    }
}

impl io::Write for UnixConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        UnixConn::write(self, buf).map_err(Into::into)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// `net.UnixListener`: a Unix-domain stream or sequenced-packet listener that
/// removes its socket file when closed.
pub struct UnixListener {
    core: Core,
    info: NetFdInfo,
    path: String,
    unlink: AtomicBool,
}

impl UnixListener {
    pub(crate) fn from_fd(nfd: NetFd) -> Result<UnixListener, OpError> {
        let template = nfd.op_error("listen", Cause::Unsupported);
        let (core, info) = nfd.into_core().map_err(|e| OpError {
            err: Cause::Errno(e),
            ..template
        })?;
        let path = info.laddr.as_ref().map(|a| a.to_string()).unwrap_or_default();
        Ok(UnixListener {
            core,
            info,
            path,
            unlink: AtomicBool::new(true),
        })
    }

    fn error(&self, op: &str, cause: Cause) -> OpError {
        OpError {
            op: op.into(),
            net: self.info.net.clone(),
            source: None,
            addr: self.info.laddr.as_ref().map(|a| a.to_string()),
            err: cause,
        }
    }

    /// `UnixListener.AcceptUnix`: waits for and returns the next connection.
    pub fn accept_unix(&self) -> Result<UnixConn, OpError> {
        let (fd, peer) = self.core.read_with(ffi::accept).map_err(|e| {
            self.error(
                "accept",
                match e {
                    IoError::Timeout => Cause::Timeout,
                    IoError::Closed => Cause::Closed,
                    IoError::Errno(n) => syscall_cause("accept", n),
                },
            )
        })?;
        let sotype = self.info.sotype;
        let laddr = ffi::getsockname(fd.raw())
            .ok()
            .and_then(|a| resolved_from(&a, k::AF_UNIX, sotype));
        let nfd = NetFd {
            fd,
            family: k::AF_UNIX,
            sotype,
            net: self.info.net.clone(),
            laddr,
            raddr: resolved_from(&peer, k::AF_UNIX, sotype),
            connected: true,
        };
        UnixConn::from_fd(nfd)
    }

    /// `UnixListener.Close`: closes the listener and removes its socket file.
    pub fn close(&self) -> Result<(), OpError> {
        if !self.core.close() {
            return Err(self.error("close", Cause::Closed));
        }
        self.unlink_file();
        Ok(())
    }

    fn unlink_file(&self) {
        if !self.path.is_empty()
            && !self.path.starts_with('@')
            && self.unlink.load(Ordering::SeqCst)
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// `UnixListener.Addr`.
    pub fn addr(&self) -> Option<UnixAddr> {
        unix_addr(&self.info.laddr)
    }

    /// `UnixListener.SetUnlinkOnClose`.
    pub fn set_unlink_on_close(&self, unlink: bool) {
        self.unlink.store(unlink, Ordering::SeqCst);
    }

    /// `UnixListener.SetDeadline`: the deadline for `accept_unix`.
    pub fn set_deadline(&self, t: Option<SystemTime>) -> Result<(), OpError> {
        if self.core.raw().is_none() {
            // Go returns the bare closed error here, without an OpError.
            return Err(OpError::new("", Cause::Closed));
        }
        self.core
            .set_deadline(true, false, t)
            .map_err(|()| self.error("set", Cause::Unsupported))
    }

    /// `UnixListener.SyscallConn`: only `control` is supported.
    pub fn syscall_conn(&self) -> Result<RawConn<'_>, Errno> {
        sockopt::syscall_listener(self)
    }

    /// `UnixListener.File`: a duplicate of the socket as a file.
    pub fn file(&self) -> Result<crate::os::File, OpError> {
        let fd = self
            .core
            .raw()
            .ok_or_else(|| self.error("file", Cause::Closed))?;
        let dup = ffi::dup(fd).map_err(|e| self.error("file", syscall_cause("dup", e)))?;
        crate::os::File::new(
            std::fs::File::from(dup.into_owned()),
            &format!("{}:{}->", self.info.net, self.path),
            crate::os::FileKind::NewFile,
        )
        .map_err(|e| self.error("file", Cause::Errno(Errno::from(e))))
    }
}

impl Drop for UnixListener {
    fn drop(&mut self) {
        if self.core.close() {
            self.unlink_file();
        }
    }
}

impl AsRawFd for UnixListener {
    /// The descriptor, or -1 once the listener is closed.
    fn as_raw_fd(&self) -> RawFd {
        self.core.raw().unwrap_or(-1)
    }
}
