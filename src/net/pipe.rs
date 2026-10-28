//! `net.Pipe`: a synchronous, in-memory, full duplex connection, ported from
//! `net/pipe.go` (see NOTICE). Reads on one end are matched with writes on the
//! other with no internal buffering.
use super::conn::Conn;
use super::error::{Addr, AddrRef, NetError, OpError};
use crate::time::{now, Time};
use std::any::Any;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration as StdDuration;

#[derive(Debug)]
struct PipeAddr;

impl std::fmt::Display for PipeAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("pipe")
    }
}

impl Addr for PipeAddr {
    fn network(&self) -> &str {
        "pipe"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Default)]
struct State {
    // flow[i]: bytes offered by side i's writer, awaiting side 1-i's reader.
    flow: [Option<Vec<u8>>; 2],
    closed: [bool; 2],
    rd: [Time; 2],
    wr: [Time; 2],
}

struct Shared {
    st: Mutex<State>,
    cv: Condvar,
    wr_mu: [Mutex<()>; 2],
}

/// One end of a [`pipe`].
pub struct PipeConn {
    shared: Arc<Shared>,
    side: usize,
}

/// `net.Pipe`: both ends of a synchronous in-memory connection.
pub fn pipe() -> (PipeConn, PipeConn) {
    let shared = Arc::new(Shared {
        st: Mutex::new(State::default()),
        cv: Condvar::new(),
        wr_mu: [Mutex::new(()), Mutex::new(())],
    });
    (
        PipeConn {
            shared: shared.clone(),
            side: 0,
        },
        PipeConn { shared, side: 1 },
    )
}

fn op_err(op: &str, e: NetError) -> NetError {
    NetError::Op(OpError {
        op: op.into(),
        net: "pipe".into(),
        source: None,
        addr: None,
        err: Box::new(e),
    })
}

// Remaining time before `t`: `None` for no deadline, `Some(zero)` once passed.
fn until(t: &Time) -> Option<StdDuration> {
    if t.is_zero() {
        return None;
    }
    let d = t.sub(&now()).as_nanos();
    Some(StdDuration::from_nanos(d.max(0) as u64))
}

impl PipeConn {
    fn wait<'a>(
        &'a self,
        g: MutexGuard<'a, State>,
        limit: Option<StdDuration>,
    ) -> MutexGuard<'a, State> {
        match limit {
            Some(d) => {
                self.shared
                    .cv
                    .wait_timeout(g, d.max(StdDuration::from_micros(50)))
                    .unwrap()
                    .0
            }
            None => self.shared.cv.wait(g).unwrap(),
        }
    }

    fn read_inner(&self, b: &mut [u8]) -> Result<usize, NetError> {
        let (me, other) = (self.side, 1 - self.side);
        let mut g = self.shared.st.lock().unwrap();
        loop {
            if g.closed[me] {
                return Err(NetError::ClosedPipe);
            }
            if g.closed[other] {
                return Ok(0);
            }
            let remaining = until(&g.rd[me]);
            if remaining == Some(StdDuration::ZERO) {
                return Err(NetError::IoTimeout);
            }
            if let Some(offer) = g.flow[other].as_mut() {
                let n = b.len().min(offer.len());
                b[..n].copy_from_slice(&offer[..n]);
                offer.drain(..n);
                if offer.is_empty() {
                    g.flow[other] = None;
                }
                self.shared.cv.notify_all();
                return Ok(n);
            }
            g = self.wait(g, remaining);
        }
    }

    fn write_inner(&self, b: &[u8]) -> (usize, Result<(), NetError>) {
        let (me, other) = (self.side, 1 - self.side);
        {
            let g = self.shared.st.lock().unwrap();
            if g.closed[me] || g.closed[other] {
                return (0, Err(NetError::ClosedPipe));
            }
            if until(&g.wr[me]) == Some(StdDuration::ZERO) {
                return (0, Err(NetError::IoTimeout));
            }
        }
        let _wr = self.shared.wr_mu[me].lock().unwrap();
        let total = b.len();
        let mut g = self.shared.st.lock().unwrap();
        g.flow[me] = Some(b.to_vec());
        self.shared.cv.notify_all();
        loop {
            let sent = |g: &State| total - g.flow[me].as_ref().map_or(0, |o| o.len());
            if g.flow[me].is_none() {
                return (total, Ok(()));
            }
            if g.closed[me] || g.closed[other] {
                let n = sent(&g);
                g.flow[me] = None;
                return (n, Err(NetError::ClosedPipe));
            }
            let remaining = until(&g.wr[me]);
            if remaining == Some(StdDuration::ZERO) {
                let n = sent(&g);
                g.flow[me] = None;
                return (n, Err(NetError::IoTimeout));
            }
            g = self.wait(g, remaining);
        }
    }

    fn set(&self, f: impl FnOnce(&mut State, usize)) -> Result<(), NetError> {
        let mut g = self.shared.st.lock().unwrap();
        if g.closed[self.side] || g.closed[1 - self.side] {
            return Err(NetError::ClosedPipe);
        }
        f(&mut g, self.side);
        self.shared.cv.notify_all();
        Ok(())
    }

    /// `Read`; `Ok(0)` when the other end is closed (Go's `io.EOF`).
    pub fn read(&self, b: &mut [u8]) -> Result<usize, NetError> {
        match self.read_inner(b) {
            Err(e) if !matches!(e, NetError::ClosedPipe) => Err(op_err("read", e)),
            r => r,
        }
    }

    /// `Write`: blocks until the other end has read all of `b`.
    pub fn write(&self, b: &[u8]) -> Result<usize, NetError> {
        match self.write_inner(b) {
            (n, Ok(())) => Ok(n),
            (_, Err(NetError::ClosedPipe)) => Err(NetError::ClosedPipe),
            (_, Err(e)) => Err(op_err("write", e)),
        }
    }

    /// `Close`.
    pub fn close(&self) -> Result<(), NetError> {
        let mut g = self.shared.st.lock().unwrap();
        g.closed[self.side] = true;
        self.shared.cv.notify_all();
        Ok(())
    }

    /// `SetDeadline`.
    pub fn set_deadline(&self, t: &Time) -> Result<(), NetError> {
        let t = t.clone();
        self.set(move |g, s| {
            g.rd[s] = t.clone();
            g.wr[s] = t;
        })
    }

    /// `SetReadDeadline`.
    pub fn set_read_deadline(&self, t: &Time) -> Result<(), NetError> {
        let t = t.clone();
        self.set(move |g, s| g.rd[s] = t)
    }

    /// `SetWriteDeadline`.
    pub fn set_write_deadline(&self, t: &Time) -> Result<(), NetError> {
        let t = t.clone();
        self.set(move |g, s| g.wr[s] = t)
    }
}

impl Conn for PipeConn {
    fn read(&self, b: &mut [u8]) -> Result<usize, NetError> {
        PipeConn::read(self, b)
    }
    fn write(&self, b: &[u8]) -> Result<usize, NetError> {
        PipeConn::write(self, b)
    }
    fn close(&self) -> Result<(), NetError> {
        PipeConn::close(self)
    }
    fn local_addr(&self) -> Option<AddrRef> {
        Some(Arc::new(PipeAddr))
    }
    fn remote_addr(&self) -> Option<AddrRef> {
        Some(Arc::new(PipeAddr))
    }
    fn set_deadline(&self, t: &Time) -> Result<(), NetError> {
        PipeConn::set_deadline(self, t)
    }
    fn set_read_deadline(&self, t: &Time) -> Result<(), NetError> {
        PipeConn::set_read_deadline(self, t)
    }
    fn set_write_deadline(&self, t: &Time) -> Result<(), NetError> {
        PipeConn::set_write_deadline(self, t)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl std::io::Read for &PipeConn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        PipeConn::read(self, buf).map_err(NetError::into_io)
    }
}

impl std::io::Write for &PipeConn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        PipeConn::write(self, buf).map_err(NetError::into_io)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
