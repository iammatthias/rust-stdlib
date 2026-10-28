//! Go's `net.TCPConn`, built on a deadline-capable descriptor so that
//! `SetDeadline`, `SetReadDeadline`, `SetWriteDeadline` and `Close` called
//! from another thread wake a blocked `read` or `write` at once.
use super::addr::TCPAddr;
use super::error::{Cause, OpError};
use super::resolve::ResolvedAddr;
use super::sockconn::SockConn;
use super::socket::NetFd;
use super::sockopt::{self, KeepAliveConfig, RawConn};
use crate::errno::Errno;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::time::SystemTime;

/// `net.TCPConn`: a TCP connection. Methods take `&self`, so a connection can
/// be shared between threads (for example in an `Arc`) and closed or given a
/// new deadline while another thread is blocked in `read`.
pub struct TCPConn {
    inner: Box<SockConn>,
}

impl TCPConn {
    pub(crate) fn from_fd(nfd: NetFd) -> Result<TCPConn, OpError> {
        Ok(TCPConn {
            inner: Box::new(SockConn::new(nfd)?),
        })
    }

    /// `Conn.Read`: reads up to `b.len()` bytes; 0 means end of stream.
    pub fn read(&self, b: &mut [u8]) -> Result<usize, OpError> {
        self.inner.read(b)
    }

    /// `Conn.Write`: writes all of `b`.
    pub fn write(&self, b: &[u8]) -> Result<usize, OpError> {
        self.inner.write(b)
    }

    /// `TCPConn.ReadFrom`: copies from `r` until it is exhausted.
    pub fn read_from(&self, r: &mut dyn io::Read) -> Result<u64, OpError> {
        let mut buf = vec![0u8; 32 * 1024];
        let mut total = 0u64;
        loop {
            let n = match r.read(&mut buf) {
                Ok(0) => return Ok(total),
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(self.inner.op_error("readfrom", Cause::Other(e.to_string()))),
            };
            self.write(&buf[..n])?;
            total += n as u64;
        }
    }

    /// `TCPConn.WriteTo`: copies everything read from the connection to `w`.
    pub fn write_to(&self, w: &mut dyn io::Write) -> Result<u64, OpError> {
        let mut buf = vec![0u8; 32 * 1024];
        let mut total = 0u64;
        loop {
            let n = self.read(&mut buf)?;
            if n == 0 {
                return Ok(total);
            }
            w.write_all(&buf[..n])
                .map_err(|e| self.inner.op_error("writeto", Cause::Other(e.to_string())))?;
            total += n as u64;
        }
    }

    /// `Conn.Close`: closes the connection; a blocked `read` or `write` on
    /// another thread fails with a closed-connection error at once.
    pub fn close(&self) -> Result<(), OpError> {
        self.inner.close()
    }

    /// `TCPConn.CloseRead`: shuts down the reading side.
    pub fn close_read(&self) -> Result<(), OpError> {
        self.inner.shutdown(crate::ffi::k::SHUT_RD)
    }

    /// `TCPConn.CloseWrite`: shuts down the writing side.
    pub fn close_write(&self) -> Result<(), OpError> {
        self.inner.shutdown(crate::ffi::k::SHUT_WR)
    }

    /// `Conn.LocalAddr`.
    pub fn local_addr(&self) -> Option<TCPAddr> {
        tcp_addr(&self.inner.info.laddr)
    }

    /// `Conn.RemoteAddr`.
    pub fn remote_addr(&self) -> Option<TCPAddr> {
        tcp_addr(&self.inner.info.raddr)
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

    /// `TCPConn.SetNoDelay`.
    pub fn set_no_delay(&self, no_delay: bool) -> Result<(), OpError> {
        sockopt::set_no_delay(self, no_delay)
    }

    /// `TCPConn.SetLinger`.
    pub fn set_linger(&self, sec: i64) -> Result<(), OpError> {
        sockopt::set_linger(self, sec)
    }

    /// `TCPConn.SetKeepAlive`.
    pub fn set_keep_alive(&self, keepalive: bool) -> Result<(), OpError> {
        sockopt::set_keep_alive(self, keepalive)
    }

    /// `TCPConn.SetKeepAlivePeriod`.
    pub fn set_keep_alive_period(&self, d: i64) -> Result<(), OpError> {
        sockopt::set_keep_alive_period(self, d)
    }

    /// `TCPConn.SetKeepAliveConfig`.
    pub fn set_keep_alive_config(&self, config: &KeepAliveConfig) -> Result<(), OpError> {
        sockopt::set_keep_alive_config(self, config)
    }

    /// `TCPConn.SetReadBuffer`.
    pub fn set_read_buffer(&self, bytes: i64) -> Result<(), OpError> {
        sockopt::set_read_buffer(self, bytes)
    }

    /// `TCPConn.SetWriteBuffer`.
    pub fn set_write_buffer(&self, bytes: i64) -> Result<(), OpError> {
        sockopt::set_write_buffer(self, bytes)
    }

    /// `TCPConn.SyscallConn`.
    pub fn syscall_conn(&self) -> Result<RawConn<'_>, Errno> {
        sockopt::syscall_conn(self)
    }

    /// `TCPConn.File`: a duplicate of the socket as a file.
    pub fn file(&self) -> Result<crate::os::File, OpError> {
        self.inner.file()
    }
}

fn tcp_addr(a: &Option<ResolvedAddr>) -> Option<TCPAddr> {
    match a {
        Some(ResolvedAddr::Tcp(t)) => Some(t.clone()),
        _ => None,
    }
}

impl std::fmt::Debug for TCPConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TCPConn")
            .field("local", &self.inner.info.laddr)
            .field("remote", &self.inner.info.raddr)
            .finish()
    }
}

impl AsRawFd for TCPConn {
    /// The descriptor, or -1 once the connection is closed.
    fn as_raw_fd(&self) -> RawFd {
        self.inner.raw_fd()
    }
}

impl io::Read for &TCPConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        TCPConn::read(self, buf).map_err(Into::into)
    }
}

impl io::Write for &TCPConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        TCPConn::write(self, buf).map_err(Into::into)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl io::Read for TCPConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        TCPConn::read(self, buf).map_err(Into::into)
    }
}

impl io::Write for TCPConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        TCPConn::write(self, buf).map_err(Into::into)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
