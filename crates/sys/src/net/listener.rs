//! Go's `net.TCPListener`, built on a deadline-capable descriptor so that
//! `SetDeadline` and `Close` wake a blocked `Accept` at once, and so that
//! accepted connections get the listener's keep-alive settings.
use super::error::{Cause, OpError};
use super::resolve::ResolvedAddr;
use super::addr::TCPAddr;
use super::socket::{resolved_from, syscall_cause, NetFd, NetFdInfo};
use super::tcpconn::TCPConn;
use super::sockopt::{self, AsSocket, KeepAliveConfig, RawConn};
use crate::errno::Errno;
use crate::ffi::{self, k};
use crate::poll::{Core, IoError};
use std::os::fd::{AsRawFd, RawFd};
use std::time::SystemTime;

/// `net.TCPListener`: a TCP network listener.
pub struct TCPListener {
    core: Core,
    info: NetFdInfo,
    keep_alive: i64,
    keep_alive_config: KeepAliveConfig,
}

/// Go's `newTCPConn` settings for an established connection: no delay and
/// the keep-alive configuration (an enabled config, else the idle time unless
/// negative).
pub(crate) fn configure_tcp<S: AsSocket + ?Sized>(
    stream: &S,
    keep_alive: i64,
    config: &KeepAliveConfig,
) -> Result<(), OpError> {
    let _ = sockopt::set_no_delay(stream, true);
    let mut config = *config;
    if !config.enable && keep_alive >= 0 {
        config = KeepAliveConfig {
            enable: true,
            idle: keep_alive,
            ..KeepAliveConfig::default()
        };
    }
    if config.enable {
        sockopt::set_keep_alive_config(stream, &config)?;
    }
    Ok(())
}

impl TCPListener {
    pub(crate) fn from_fd(
        nfd: NetFd,
        keep_alive: i64,
        keep_alive_config: KeepAliveConfig,
    ) -> Result<TCPListener, OpError> {
        let template = nfd.op_error("listen", Cause::Unsupported);
        let (core, info) = nfd.into_core().map_err(|e| OpError {
            err: Cause::Errno(e),
            ..template
        })?;
        Ok(TCPListener {
            core,
            info,
            keep_alive,
            keep_alive_config,
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

    /// `TCPListener.AcceptTCP`: waits for and returns the next connection.
    pub fn accept_tcp(&self) -> Result<TCPConn, OpError> {
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
        let family = self.info.family;
        let laddr = ffi::getsockname(fd.raw())
            .ok()
            .and_then(|a| resolved_from(&a, family, sotype));
        let nfd = NetFd {
            fd,
            family,
            sotype: k::SOCK_STREAM,
            net: self.info.net.clone(),
            laddr,
            raddr: resolved_from(&peer, family, sotype),
            connected: true,
        };
        let conn = TCPConn::from_fd(nfd)?;
        configure_tcp(&conn, self.keep_alive, &self.keep_alive_config)?;
        Ok(conn)
    }

    /// `Listener.Close`: stops listening; a blocked `accept_tcp` fails.
    pub fn close(&self) -> Result<(), OpError> {
        if self.core.close() {
            Ok(())
        } else {
            Err(self.error("close", Cause::Closed))
        }
    }

    /// `Listener.Addr`: the listener's address.
    pub fn addr(&self) -> Option<TCPAddr> {
        match &self.info.laddr {
            Some(ResolvedAddr::Tcp(a)) => Some(a.clone()),
            _ => None,
        }
    }

    /// `TCPListener.SetDeadline`: the deadline for `accept_tcp`.
    pub fn set_deadline(&self, t: Option<SystemTime>) -> Result<(), OpError> {
        if self.core.raw().is_none() {
            // Go returns the bare closed error here, without an OpError.
            return Err(OpError::new("", Cause::Closed));
        }
        self.core
            .set_deadline(true, false, t)
            .map_err(|()| self.error("set", Cause::Unsupported))
    }

    /// `TCPListener.SyscallConn`: only `control` is supported.
    pub fn syscall_conn(&self) -> Result<RawConn<'_>, Errno> {
        sockopt::syscall_listener(self)
    }

    /// `TCPListener.File`: a duplicate of the socket as a file.
    pub fn file(&self) -> Result<crate::os::File, OpError> {
        let fd = self
            .core
            .raw()
            .ok_or_else(|| self.error("file", Cause::Closed))?;
        let dup = ffi::dup(fd).map_err(|e| self.error("file", syscall_cause("dup", e)))?;
        let name = format!(
            "{}:{}->",
            self.info.net,
            self.info.laddr.as_ref().map(|a| a.to_string()).unwrap_or_default()
        );
        crate::os::File::new(
            std::fs::File::from(dup.into_owned()),
            &name,
            crate::os::FileKind::NewFile,
        )
        .map_err(|e| self.error("file", Cause::Errno(Errno::from(e))))
    }
}

impl AsRawFd for TCPListener {
    /// The descriptor, or -1 once the listener is closed.
    fn as_raw_fd(&self) -> RawFd {
        self.core.raw().unwrap_or(-1)
    }
}
