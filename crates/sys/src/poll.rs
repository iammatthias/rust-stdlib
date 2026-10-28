//! The descriptor core shared by [`crate::os::File`] and the network
//! connections of this crate: Go's `internal/poll.FD`.
//!
//! A pollable descriptor is non-blocking. An operation that would block waits
//! in `poll(2)` on the descriptor and on a private wake-up pipe, so that
//! `SetDeadline` and `Close` called from another thread take effect at once
//! rather than at the next timer tick.
use crate::errno::{Errno, EAGAIN, EINTR};
use crate::ffi::{self, Fd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

/// Why a descriptor operation failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum IoError {
    /// The deadline passed (`os.ErrDeadlineExceeded`).
    Timeout,
    /// The descriptor was closed (`os.ErrClosed`).
    Closed,
    /// A system call failed.
    Errno(Errno),
}

struct State {
    fd: Option<Fd>,
    closed: bool,
    operations: usize,
}

struct Waiter {
    id: u64,
    wake: Fd,
}

pub(crate) struct Core {
    state: Mutex<State>,
    waiters: Mutex<Vec<Waiter>>,
    next_waiter: AtomicU64,
    read_deadline: Mutex<Option<Instant>>,
    write_deadline: Mutex<Option<Instant>>,
    pollable: bool,
}

/// Go converts a wall-clock deadline to the monotonic clock when it is set.
fn to_instant(t: SystemTime) -> Instant {
    let now = Instant::now();
    match t.duration_since(SystemTime::now()) {
        Ok(ahead) => now + ahead,
        Err(behind) => now
            .checked_sub(behind.duration())
            .unwrap_or_else(|| now - Duration::from_secs(1)),
    }
}

impl Core {
    /// Wraps `fd`. A pollable descriptor is switched to non-blocking mode.
    pub fn new(fd: Fd, pollable: bool) -> Result<Core, Errno> {
        if pollable {
            ffi::set_nonblocking(fd.raw(), true)?;
        }
        Ok(Core {
            state: Mutex::new(State {
                fd: Some(fd),
                closed: false,
                operations: 0,
            }),
            waiters: Mutex::new(Vec::new()),
            next_waiter: AtomicU64::new(0),
            read_deadline: Mutex::new(None),
            write_deadline: Mutex::new(None),
            pollable,
        })
    }

    /// The descriptor number while the descriptor is open.
    pub fn raw(&self) -> Option<i32> {
        let state = self.state.lock().unwrap();
        if state.closed {
            return None;
        }
        state.fd.as_ref().map(|fd| fd.raw())
    }

    fn begin(&self) -> Result<i32, IoError> {
        let mut state = self.state.lock().unwrap();
        match (&state.fd, state.closed) {
            (Some(fd), false) => {
                let raw = fd.raw();
                state.operations += 1;
                Ok(raw)
            }
            _ => Err(IoError::Closed),
        }
    }

    fn end(&self) {
        let mut state = self.state.lock().unwrap();
        state.operations -= 1;
        if state.closed && state.operations == 0 {
            state.fd = None;
        }
    }

    fn deadline(&self, write: bool) -> Option<Instant> {
        *if write {
            self.write_deadline.lock().unwrap()
        } else {
            self.read_deadline.lock().unwrap()
        }
    }

    fn is_closed(&self) -> bool {
        self.state.lock().unwrap().closed
    }

    fn wake_all(&self) {
        for waiter in self.waiters.lock().unwrap().iter() {
            // A full pipe already holds a pending wake-up.
            let _ = ffi::write(waiter.wake.raw(), &[1]);
        }
    }

    /// Waits until `fd` is ready for reading or writing, the deadline passes
    /// or the descriptor is closed.
    fn wait(&self, fd: i32, write: bool) -> Result<(), IoError> {
        let (wake_read, wake_write) = ffi::pipe().map_err(IoError::Errno)?;
        ffi::set_nonblocking(wake_read.raw(), true).map_err(IoError::Errno)?;
        ffi::set_nonblocking(wake_write.raw(), true).map_err(IoError::Errno)?;
        let id = self.next_waiter.fetch_add(1, Ordering::Relaxed);
        self.waiters.lock().unwrap().push(Waiter {
            id,
            wake: wake_write,
        });
        let result = self.wait_registered(fd, write, &wake_read);
        self.waiters.lock().unwrap().retain(|w| w.id != id);
        result
    }

    fn wait_registered(&self, fd: i32, write: bool, wake: &Fd) -> Result<(), IoError> {
        loop {
            if self.is_closed() {
                return Err(IoError::Closed);
            }
            let timeout_ms = match self.deadline(write) {
                None => -1,
                Some(deadline) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(IoError::Timeout);
                    }
                    // Round up so the wait never ends before the deadline.
                    let left = deadline - now;
                    (left.as_millis() + u128::from(!left.subsec_nanos().is_multiple_of(1_000_000)))
                        .min(i32::MAX as u128) as i32
                }
            };
            match ffi::poll(&[(fd, write), (wake.raw(), false)], timeout_ms) {
                Ok(ready) => {
                    if ready[1].readable {
                        let mut drain = [0u8; 16];
                        while matches!(ffi::read(wake.raw(), &mut drain), Ok(n) if n > 0) {}
                        continue;
                    }
                    if ready[0].readable
                        || ready[0].writable
                        || ready[0].error
                        || ready[0].hangup
                        || ready[0].invalid
                    {
                        return Ok(());
                    }
                }
                Err(e) if e == EINTR => {}
                Err(e) => return Err(IoError::Errno(e)),
            }
        }
    }

    /// Runs `op` on the descriptor until it stops reporting "would block".
    fn run<T>(
        &self,
        write: bool,
        mut op: impl FnMut(i32) -> Result<T, Errno>,
    ) -> Result<T, IoError> {
        let fd = self.begin()?;
        let result = (|| loop {
            if self.pollable {
                if self.is_closed() {
                    return Err(IoError::Closed);
                }
                if let Some(deadline) = self.deadline(write) {
                    if Instant::now() >= deadline {
                        return Err(IoError::Timeout);
                    }
                }
            }
            match op(fd) {
                Ok(v) => return Ok(v),
                Err(e) if e == EINTR => continue,
                Err(e) if e == EAGAIN && self.pollable => self.wait(fd, write)?,
                Err(e) => return Err(IoError::Errno(e)),
            }
        })();
        self.end();
        result
    }

    pub fn read_with<T>(&self, op: impl FnMut(i32) -> Result<T, Errno>) -> Result<T, IoError> {
        self.run(false, op)
    }

    pub fn write_with<T>(&self, op: impl FnMut(i32) -> Result<T, Errno>) -> Result<T, IoError> {
        self.run(true, op)
    }

    /// Sets the read and/or write deadline (`None` clears it). Returns
    /// `false` when the descriptor does not support deadlines.
    pub fn set_deadline(&self, read: bool, write: bool, t: Option<SystemTime>) -> Result<(), ()> {
        if !self.pollable {
            return Err(());
        }
        let deadline = t.map(to_instant);
        if read {
            *self.read_deadline.lock().unwrap() = deadline;
        }
        if write {
            *self.write_deadline.lock().unwrap() = deadline;
        }
        self.wake_all();
        Ok(())
    }

    /// Closes the descriptor; blocked operations fail with `Closed`. Returns
    /// `false` if it was already closed.
    pub fn close(&self) -> bool {
        {
            let mut state = self.state.lock().unwrap();
            if state.closed {
                return false;
            }
            state.closed = true;
            if state.operations == 0 {
                state.fd = None;
            }
        }
        self.wake_all();
        true
    }
}
