//! Go's `Conn`, `PacketConn` and `Listener` interfaces, the deadline machinery
//! shared by the socket types, and [`Buffers`].
//!
//! `std` sockets have only per-call read/write timeouts, so a deadline is
//! enforced by running each blocking call in slices of at most 50 ms and
//! re-checking the deadline and the closed flag between slices. A deadline
//! change or `close` from another thread therefore takes effect within about
//! 50 ms rather than instantly as in Go.
use super::error::{Addr, AddrRef, NetError, OpError};
use crate::time::{now, Duration, Time};
use std::any::Any;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// The TLS facts of a connection: a subset of Go's `tls.ConnectionState`.
/// The core crate has no TLS stack; the `rust-stdlib-tls` backend fills this in.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TlsConnectionState {
    /// Negotiated protocol version (`0x0303` is TLS 1.2, `0x0304` TLS 1.3).
    pub version: u16,
    pub handshake_complete: bool,
    pub did_resume: bool,
    /// Negotiated cipher suite identifier.
    pub cipher_suite: u16,
    /// ALPN protocol, empty when none was negotiated.
    pub negotiated_protocol: String,
    /// The SNI name the client sent, or the name the client verified.
    pub server_name: String,
    /// DER certificates presented by the peer, leaf first.
    pub peer_certificates: Vec<Vec<u8>>,
}

/// Go's `net.Conn`: a generic stream-oriented network connection.
///
/// `read` returns `Ok(0)` at end of file (Go's `io.EOF`). The deadline
/// arguments are Go `time.Time` values; the zero `Time` means no deadline.
pub trait Conn: Send + Sync {
    /// `Conn.Read`.
    fn read(&self, b: &mut [u8]) -> Result<usize, NetError>;
    /// `Conn.Write`.
    fn write(&self, b: &[u8]) -> Result<usize, NetError>;
    /// `Conn.Close`.
    fn close(&self) -> Result<(), NetError>;
    /// `Conn.LocalAddr`.
    fn local_addr(&self) -> Option<AddrRef>;
    /// `Conn.RemoteAddr`.
    fn remote_addr(&self) -> Option<AddrRef>;
    /// `Conn.SetDeadline`.
    fn set_deadline(&self, t: &Time) -> Result<(), NetError>;
    /// `Conn.SetReadDeadline`.
    fn set_read_deadline(&self, t: &Time) -> Result<(), NetError>;
    /// `Conn.SetWriteDeadline`.
    fn set_write_deadline(&self, t: &Time) -> Result<(), NetError>;
    /// Downcasting hook to the concrete connection type.
    fn as_any(&self) -> &dyn Any;
    /// Go's `c.(PacketConn)` type assertion.
    fn as_packet_conn(&self) -> Option<&dyn PacketConn> {
        None
    }
    /// Go's `c.(interface{ ConnectionState() tls.ConnectionState })`
    /// assertion: the TLS state when this is a TLS connection.
    fn tls_connection_state(&self) -> Option<TlsConnectionState> {
        None
    }
    /// Go's `HandshakeContext` for TLS connections; plain connections have
    /// nothing to do.
    fn handshake(&self) -> Result<(), NetError> {
        Ok(())
    }
}

/// Go's `net.PacketConn`: a packet-oriented network connection.
pub trait PacketConn: Send + Sync {
    /// `PacketConn.ReadFrom`.
    fn read_from(&self, b: &mut [u8]) -> Result<(usize, Option<AddrRef>), NetError>;
    /// `PacketConn.WriteTo`.
    fn write_to(&self, b: &[u8], addr: &dyn Addr) -> Result<usize, NetError>;
    /// `PacketConn.Close`.
    fn close(&self) -> Result<(), NetError>;
    /// `PacketConn.LocalAddr`.
    fn local_addr(&self) -> Option<AddrRef>;
    /// `PacketConn.SetDeadline`.
    fn set_deadline(&self, t: &Time) -> Result<(), NetError>;
    /// `PacketConn.SetReadDeadline`.
    fn set_read_deadline(&self, t: &Time) -> Result<(), NetError>;
    /// `PacketConn.SetWriteDeadline`.
    fn set_write_deadline(&self, t: &Time) -> Result<(), NetError>;
}

/// Go's `net.Listener`: a generic stream-oriented network listener.
pub trait Listener: Send + Sync {
    /// `Listener.Accept`.
    fn accept(&self) -> Result<Box<dyn Conn>, NetError>;
    /// `Listener.Close`.
    fn close(&self) -> Result<(), NetError>;
    /// `Listener.Addr`.
    fn addr(&self) -> Option<AddrRef>;
    /// Downcasting hook to the concrete listener type.
    fn as_any(&self) -> &dyn Any;
}

fn addr_text(a: Option<AddrRef>) -> String {
    a.map(|a| a.to_string()).unwrap_or_default()
}

impl std::fmt::Debug for dyn Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Conn({}->{})",
            addr_text(self.local_addr()),
            addr_text(self.remote_addr())
        )
    }
}

impl std::fmt::Debug for dyn PacketConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PacketConn({})", addr_text(self.local_addr()))
    }
}

impl std::fmt::Debug for dyn Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Listener({})", addr_text(self.addr()))
    }
}

impl io::Read for &dyn Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Conn::read(*self, buf).map_err(NetError::into_io)
    }
}

impl io::Write for &dyn Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Conn::write(*self, buf).map_err(NetError::into_io)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) const POLL: std::time::Duration = std::time::Duration::from_millis(50);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dir {
    Read,
    Write,
}

/// Per-connection deadline and closed state.
#[derive(Default)]
pub(crate) struct Deadlines {
    read: Mutex<Time>,
    write: Mutex<Time>,
    closed: AtomicBool,
}

impl Deadlines {
    pub(crate) fn set(&self, dir: Option<Dir>, t: &Time) {
        if dir != Some(Dir::Write) {
            *self.read.lock().unwrap() = t.clone();
        }
        if dir != Some(Dir::Read) {
            *self.write.lock().unwrap() = t.clone();
        }
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Marks closed; true for the first caller.
    pub(crate) fn mark_closed(&self) -> bool {
        !self.closed.swap(true, Ordering::SeqCst)
    }

    /// The time left before the deadline: `None` for no deadline, a
    /// non-positive duration once it has passed.
    pub(crate) fn remaining(&self, dir: Dir) -> Option<Duration> {
        let t = match dir {
            Dir::Read => self.read.lock().unwrap().clone(),
            Dir::Write => self.write.lock().unwrap().clone(),
        };
        if t.is_zero() {
            None
        } else {
            Some(t.sub(&now()))
        }
    }

    /// Runs `op` until it completes, slicing the socket timeout so deadlines
    /// and `close` are honoured. `syscall` names the call in error texts.
    pub(crate) fn run<T>(
        &self,
        dir: Dir,
        syscall: &str,
        mut set_timeout: impl FnMut(Option<std::time::Duration>) -> io::Result<()>,
        mut op: impl FnMut() -> io::Result<T>,
    ) -> Result<T, NetError> {
        loop {
            if self.is_closed() {
                return Err(NetError::Closed);
            }
            let slice = match self.remaining(dir) {
                None => POLL,
                Some(d) if d.as_nanos() <= 0 => return Err(NetError::IoTimeout),
                Some(d) => std::time::Duration::from_nanos(d.as_nanos() as u64)
                    .clamp(std::time::Duration::from_millis(1), POLL),
            };
            // macOS rejects SO_RCVTIMEO/SO_SNDTIMEO on a shut-down socket; the
            // operation below then fails or ends immediately, so carry on.
            let _ = set_timeout(Some(slice));
            match op() {
                Ok(v) => return Ok(v),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue
                }
                Err(e) => {
                    if self.is_closed() {
                        return Err(NetError::Closed);
                    }
                    return Err(NetError::from_io(syscall, &e));
                }
            }
        }
    }
}

/// Wraps `err` in an `OpError` for a connection-level operation.
pub(crate) fn op_error(
    op: &str,
    net: &str,
    source: Option<AddrRef>,
    addr: Option<AddrRef>,
    err: NetError,
) -> NetError {
    NetError::Op(OpError {
        op: op.into(),
        net: net.into(),
        source,
        addr,
        err: Box::new(err),
    })
}

/// A socket whose close slot can be emptied: operations clone the `Arc`, so
/// the descriptor really closes once in-flight calls return.
pub(crate) struct Slot<S>(Mutex<Option<Arc<S>>>);

impl<S> Slot<S> {
    pub(crate) fn new(s: S) -> Slot<S> {
        Slot(Mutex::new(Some(Arc::new(s))))
    }
    pub(crate) fn get(&self) -> Result<Arc<S>, NetError> {
        self.0.lock().unwrap().clone().ok_or(NetError::Closed)
    }
    pub(crate) fn take(&self) -> Option<Arc<S>> {
        self.0.lock().unwrap().take()
    }
}

/// `net.Buffers`: runs of bytes to write.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Buffers(pub Vec<Vec<u8>>);

impl Buffers {
    /// `Buffers.WriteTo`: writes the contents to `w`, consuming what was written.
    pub fn write_to(&mut self, w: &mut dyn io::Write) -> io::Result<u64> {
        let mut n = 0u64;
        for i in 0..self.0.len() {
            let chunk = std::mem::take(&mut self.0[i]);
            match w.write(&chunk) {
                Ok(k) => {
                    n += k as u64;
                    if k < chunk.len() {
                        self.0[i] = chunk[k..].to_vec();
                        self.0.drain(..i);
                        return Err(io::ErrorKind::WriteZero.into());
                    }
                }
                Err(e) => {
                    self.0[i] = chunk;
                    self.0.drain(..i);
                    return Err(e);
                }
            }
        }
        self.0.clear();
        Ok(n)
    }

    fn consume(&mut self, mut n: usize) {
        while let Some(first) = self.0.first_mut() {
            if first.len() > n {
                first.drain(..n);
                return;
            }
            n -= first.len();
            self.0.remove(0);
        }
    }
}

impl io::Read for Buffers {
    /// `Buffers.Read`: `Ok(0)` once drained (Go's `io.EOF`).
    fn read(&mut self, mut p: &mut [u8]) -> io::Result<usize> {
        let mut n = 0;
        while !p.is_empty() && !self.0.is_empty() {
            let k = p.len().min(self.0[0].len());
            p[..k].copy_from_slice(&self.0[0][..k]);
            self.consume(k);
            p = &mut p[k..];
            n += k;
        }
        Ok(n)
    }
}
