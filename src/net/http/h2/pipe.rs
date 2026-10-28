//! A flow-controlled byte pipe between the frame reader and a body reader
//! (Go's `pipe.go` with its `dataBuffer`).
use super::H2Error;
use crate::time::Duration;
use std::{
    collections::VecDeque,
    sync::{Condvar, Mutex, MutexGuard},
};

type ReadFn = Box<dyn FnOnce() + Send>;

#[derive(Default)]
struct State {
    /// `None` until a buffer is installed and again once reading is over.
    b: Option<VecDeque<u8>>,
    /// Bytes left unread when the pipe was broken.
    unread: usize,
    /// Read error once the buffer is empty; non-`None` means closed.
    err: Option<H2Error>,
    /// Immediate read error: the reader does not see the rest of the buffer.
    break_err: Option<H2Error>,
    /// Runs once on the read that reports `err` (copies trailers).
    read_fn: Option<ReadFn>,
}

/// Go's `pipe`.
#[derive(Default)]
pub struct Pipe {
    m: Mutex<State>,
    cv: Condvar,
}

impl Pipe {
    /// A pipe ready to receive data.
    pub fn with_buffer() -> Self {
        let p = Self::default();
        p.set_buffer();
        p
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.m.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Go's `setBuffer`.
    pub fn set_buffer(&self) {
        let mut s = self.lock();
        if s.err.is_some() || s.break_err.is_some() {
            return;
        }
        s.b = Some(VecDeque::new());
    }

    /// Go's `Len`: bytes buffered (or left unread after a break).
    pub fn len(&self) -> usize {
        let s = self.lock();
        match &s.b {
            None => s.unread,
            Some(b) => b.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Go's `Read`: blocks until data, a break or a close. `Err(H2Error::Eof)`
    /// is a clean end of data.
    pub fn read(&self, d: &mut [u8]) -> Result<usize, H2Error> {
        self.read_deadline(d, None)
    }

    /// `read` that gives up with [`H2Error::DeadlineExceeded`] after `timeout`.
    pub fn read_deadline(&self, d: &mut [u8], timeout: Option<Duration>) -> Result<usize, H2Error> {
        let timeout = timeout.map(Duration::to_std);
        let start = std::time::Instant::now();
        let mut s = self.lock();
        loop {
            if let Some(e) = &s.break_err {
                return Err(e.clone());
            }
            if let Some(b) = s.b.as_mut() {
                if !b.is_empty() {
                    let n = d.len().min(b.len());
                    for (i, byte) in b.drain(..n).enumerate() {
                        d[i] = byte;
                    }
                    return Ok(n);
                }
            }
            if let Some(e) = s.err.clone() {
                if let Some(f) = s.read_fn.take() {
                    drop(s);
                    f();
                    s = self.lock();
                }
                s.b = None;
                return Err(e);
            }
            match timeout {
                None => s = self.cv.wait(s).unwrap_or_else(|e| e.into_inner()),
                Some(t) => {
                    let Some(left) = t.checked_sub(start.elapsed()) else {
                        return Err(H2Error::DeadlineExceeded);
                    };
                    s = self
                        .cv
                        .wait_timeout(s, left)
                        .unwrap_or_else(|e| e.into_inner())
                        .0;
                }
            }
        }
    }

    /// Go's `Write`: appends to the buffer.
    pub fn write(&self, d: &[u8]) -> Result<usize, H2Error> {
        let mut s = self.lock();
        if s.err.is_some() || s.break_err.is_some() {
            self.cv.notify_one();
            return Err(H2Error::msg("write on closed buffer"));
        }
        let Some(b) = s.b.as_mut() else {
            self.cv.notify_one();
            return Err(H2Error::msg("write on uninitialized buffer"));
        };
        b.extend(d.iter().copied());
        self.cv.notify_one();
        Ok(d.len())
    }

    /// Go's `CloseWithError`: readers see the buffered data, then `err`.
    pub fn close_with_error(&self, err: H2Error) {
        self.close_inner(false, err, None);
    }

    /// Go's `BreakWithError`: readers see `err` immediately.
    pub fn break_with_error(&self, err: H2Error) {
        self.close_inner(true, err, None);
    }

    /// Go's `closeWithErrorAndCode`: like `close_with_error`, running `f`
    /// when a reader consumes the error.
    pub fn close_with_error_and_code(&self, err: H2Error, f: impl FnOnce() + Send + 'static) {
        self.close_inner(false, err, Some(Box::new(f)));
    }

    fn close_inner(&self, is_break: bool, err: H2Error, f: Option<ReadFn>) {
        let mut s = self.lock();
        let already = if is_break {
            s.break_err.is_some()
        } else {
            s.err.is_some()
        };
        if already {
            self.cv.notify_all();
            return;
        }
        s.read_fn = f;
        if is_break {
            if let Some(b) = &s.b {
                s.unread += b.len();
            }
            s.b = None;
            s.break_err = Some(err);
        } else {
            s.err = Some(err);
        }
        self.cv.notify_all();
    }

    /// Go's `Err`: the error the pipe was closed with, if any.
    pub fn err(&self) -> Option<H2Error> {
        let s = self.lock();
        s.break_err.clone().or_else(|| s.err.clone())
    }
}
