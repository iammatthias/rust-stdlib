//! The connection core shared by [`IPConn`](super::IPConn) and
//! [`UnixPacketConn`](super::UnixPacketConn): Go's `net.conn` over a
//! `netFD` with deadlines and close-wakes-blocked-calls semantics.
use super::error::{Cause, OpError};
use super::msg::MsgRead;
use super::resolve::ResolvedAddr;
use super::socket::{resolved_from, syscall_cause, NetFd, NetFdInfo};
use crate::errno::Errno;
use crate::ffi::{self, k, SockAddr};
use crate::poll::{Core, IoError};
use std::time::SystemTime;

pub(crate) struct SockConn {
    pub core: Core,
    pub info: NetFdInfo,
}

impl SockConn {
    pub fn new(nfd: NetFd) -> Result<SockConn, OpError> {
        let template = nfd.op_error("dial", Cause::Unsupported);
        let (core, info) = nfd.into_core().map_err(|e| OpError {
            err: Cause::Errno(e),
            ..template
        })?;
        Ok(SockConn { core, info })
    }

    pub fn op_error(&self, op: &str, err: Cause) -> OpError {
        OpError {
            op: op.into(),
            net: self.info.net.clone(),
            source: self.info.laddr.as_ref().map(|a| a.to_string()),
            addr: self.info.raddr.as_ref().map(|a| a.to_string()),
            err,
        }
    }

    fn cause(&self, e: IoError, syscall: &str) -> Cause {
        match e {
            IoError::Timeout => Cause::Timeout,
            IoError::Closed => Cause::Closed,
            IoError::Errno(n) => syscall_cause(syscall, n),
        }
    }

    pub fn read(&self, b: &mut [u8]) -> Result<usize, OpError> {
        if b.is_empty() && self.core.raw().is_some() {
            return Ok(0);
        }
        self.core
            .read_with(|fd| ffi::read(fd, b))
            .map_err(|e| self.op_error("read", self.cause(e, "read")))
    }

    pub fn write(&self, b: &[u8]) -> Result<usize, OpError> {
        // A stream or packet write sends everything; a datagram write is one packet.
        let mut done = 0;
        loop {
            let n = self
                .core
                .write_with(|fd| ffi::write(fd, &b[done..]))
                .map_err(|e| self.op_error("write", self.cause(e, "write")))?;
            done += n;
            if done >= b.len() || self.info.sotype != k::SOCK_STREAM {
                return Ok(done);
            }
        }
    }

    pub fn read_msg(&self, b: &mut [u8], oob: &mut [u8]) -> Result<MsgRead<ResolvedAddr>, OpError> {
        self.read_msg_flags(b, oob, 0)
    }

    pub fn read_msg_flags(
        &self,
        b: &mut [u8],
        oob: &mut [u8],
        flags: i32,
    ) -> Result<MsgRead<ResolvedAddr>, OpError> {
        let r = self
            .core
            .read_with(|fd| ffi::recvmsg(fd, b, oob, flags))
            .map_err(|e| self.op_error("read", self.cause(e, "recvmsg")))?;
        Ok(MsgRead {
            n: r.n,
            oobn: r.oobn,
            flags: r.flags,
            addr: r
                .from
                .as_ref()
                .and_then(|a| resolved_from(a, self.info.family, self.info.sotype)),
        })
    }

    pub fn write_to(&self, b: &[u8], to: &SockAddr) -> Result<usize, Cause> {
        self.core
            .write_with(|fd| ffi::sendmsg(fd, b, &[], Some(to), k::MSG_NOSIGNAL))
            .map_err(|e| self.cause(e, "sendto"))
    }

    pub fn write_msg(&self, b: &[u8], oob: &[u8], to: Option<&SockAddr>) -> Result<usize, Cause> {
        self.core
            .write_with(|fd| ffi::sendmsg(fd, b, oob, to, k::MSG_NOSIGNAL))
            .map_err(|e| self.cause(e, "sendmsg"))
    }

    pub fn close(&self) -> Result<(), OpError> {
        if self.core.close() {
            Ok(())
        } else {
            Err(self.op_error("close", Cause::Closed))
        }
    }

    pub fn shutdown(&self, how: i32) -> Result<(), OpError> {
        match self.core.raw() {
            None => Err(self.op_error("close", Cause::Closed)),
            Some(fd) => ffi::shutdown(fd, how)
                .map_err(|e| self.op_error("close", syscall_cause("shutdown", e))),
        }
    }

    pub fn set_deadline(
        &self,
        read: bool,
        write: bool,
        t: Option<SystemTime>,
    ) -> Result<(), OpError> {
        let fail = |cause: Cause| OpError {
            op: "set".into(),
            net: self.info.net.clone(),
            source: None,
            addr: self.info.laddr.as_ref().map(|a| a.to_string()),
            err: cause,
        };
        if self.core.raw().is_none() {
            return Err(fail(Cause::Closed));
        }
        self.core
            .set_deadline(read, write, t)
            .map_err(|()| fail(Cause::Unsupported))
    }

    pub fn raw_fd(&self) -> i32 {
        self.core.raw().unwrap_or(-1)
    }

    /// `conn.File`: a duplicate of the socket as a file.
    pub fn file(&self) -> Result<crate::os::File, OpError> {
        let fail = |e: Errno| self.op_error("file", syscall_cause("dup", e));
        let fd = self.core.raw().ok_or_else(|| self.op_error("file", Cause::Closed))?;
        let dup = ffi::dup(fd).map_err(fail)?;
        let name = format!(
            "{}:{}->{}",
            self.info.net,
            self.info.laddr.as_ref().map(|a| a.to_string()).unwrap_or_default(),
            self.info.raddr.as_ref().map(|a| a.to_string()).unwrap_or_default()
        );
        crate::os::File::new(
            std::fs::File::from(dup.into_owned()),
            &name,
            crate::os::FileKind::NewFile,
        )
        .map_err(|e| self.op_error("file", Cause::Errno(Errno::from(e))))
    }
}
