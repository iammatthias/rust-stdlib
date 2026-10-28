//! A sys connection as the root crate's `net::Conn`.
use crate::error::net_error;
use rust_stdlib::net::{AddrRef, Conn as NetConn, IPAddr, NetError, TCPAddr, UDPAddr, UnixAddr};
use rust_stdlib::time::Time;
use rust_stdlib_sys::net::{Conn as SysConn, ResolvedAddr};
use std::any::Any;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A `rust_stdlib_sys::net::Conn` (TCP, Unix, UDP or IP) implementing the root
/// crate's [`net::Conn`](rust_stdlib::net::Conn): read, write, close, local
/// and remote address, and deadlines, with errors mapped by [`net_error`].
pub struct Conn(SysConn);

impl std::fmt::Debug for Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conn")
            .field("local", &self.0.local_addr().map(|a| a.to_string()))
            .field("remote", &self.0.remote_addr().map(|a| a.to_string()))
            .finish()
    }
}

impl Conn {
    /// Wraps a connection returned by a sys `Dialer`, `dial_tcp`, `dial_unix`
    /// or a listener's `accept`.
    pub fn new(conn: SysConn) -> Conn {
        Conn(conn)
    }

    /// The wrapped sys connection, for socket options such as
    /// `set_keep_alive_config`, `set_no_delay` or `syscall_conn`.
    pub fn sys(&self) -> &SysConn {
        &self.0
    }

    /// Unwraps the sys connection.
    pub fn into_sys(self) -> SysConn {
        self.0
    }
}

fn addr(a: ResolvedAddr) -> AddrRef {
    match a {
        ResolvedAddr::Tcp(a) => Arc::new(TCPAddr {
            ip: a.ip.map(Into::into).unwrap_or_default(),
            port: i32::from(a.port),
            zone: a.zone,
        }),
        ResolvedAddr::Udp(a) => Arc::new(UDPAddr {
            ip: a.ip.map(Into::into).unwrap_or_default(),
            port: i32::from(a.port),
            zone: a.zone,
        }),
        ResolvedAddr::Ip(a) => Arc::new(IPAddr {
            ip: a.ip.map(Into::into).unwrap_or_default(),
            zone: a.zone,
        }),
        ResolvedAddr::Unix(a) => Arc::new(UnixAddr {
            name: a.name,
            net: a.net,
        }),
    }
}

/// Go's zero `time.Time` means no deadline.
fn deadline(t: &Time) -> Option<SystemTime> {
    if t.is_zero() {
        return None;
    }
    let nanos = t.unix_nano();
    Some(if nanos >= 0 {
        UNIX_EPOCH + Duration::from_nanos(nanos as u64)
    } else {
        UNIX_EPOCH - Duration::from_nanos(nanos.unsigned_abs())
    })
}

impl NetConn for Conn {
    fn read(&self, b: &mut [u8]) -> Result<usize, NetError> {
        self.0.read(b).map_err(net_error)
    }
    fn write(&self, b: &[u8]) -> Result<usize, NetError> {
        self.0.write(b).map_err(net_error)
    }
    fn close(&self) -> Result<(), NetError> {
        self.0.close().map_err(net_error)
    }
    fn local_addr(&self) -> Option<AddrRef> {
        self.0.local_addr().map(addr)
    }
    fn remote_addr(&self) -> Option<AddrRef> {
        self.0.remote_addr().map(addr)
    }
    fn set_deadline(&self, t: &Time) -> Result<(), NetError> {
        self.0.set_deadline(deadline(t)).map_err(net_error)
    }
    fn set_read_deadline(&self, t: &Time) -> Result<(), NetError> {
        self.0.set_read_deadline(deadline(t)).map_err(net_error)
    }
    fn set_write_deadline(&self, t: &Time) -> Result<(), NetError> {
        self.0.set_write_deadline(deadline(t)).map_err(net_error)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
