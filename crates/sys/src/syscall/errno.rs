//! `syscall.Errno` and `syscall.Signal` with the Linux numbers and message
//! tables of Go's `zerrors_linux_amd64.go` on every host.
use crate::errno_table::{ERRORS_DARWIN, ERRORS_LINUX_AMD64, SIGNALS_LINUX_AMD64};
use std::fmt;
use std::io;

/// `syscall.Errno`: an operating-system error number (Linux numbering).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord, Default)]
pub struct Errno(pub usize);

impl Errno {
    /// `Errno.Error`: Go's message text for the number, or `errno N`.
    pub fn error(&self) -> String {
        match ERRORS_LINUX_AMD64.get(self.0) {
            Some(text) if !text.is_empty() => (*text).to_string(),
            _ => format!("errno {}", self.0),
        }
    }

    /// `Errno.Is` against Go's `oserror` sentinels, named `permission`,
    /// `exist`, `not-exist` or `unsupported`.
    pub fn is(&self, target: &str) -> bool {
        match target {
            "permission" => *self == super::EACCES || *self == super::EPERM,
            "exist" => *self == super::EEXIST || *self == super::ENOTEMPTY,
            "not-exist" => *self == super::ENOENT,
            "unsupported" => {
                *self == super::ENOSYS || *self == super::ENOTSUP || *self == super::EOPNOTSUPP
            }
            _ => false,
        }
    }

    /// `Errno.Temporary`: the condition is expected to be transient.
    pub fn temporary(&self) -> bool {
        *self == super::EINTR
            || *self == super::EMFILE
            || *self == super::ENFILE
            || self.timeout()
    }

    /// `Errno.Timeout`: the operation timed out.
    pub fn timeout(&self) -> bool {
        *self == super::EAGAIN || *self == super::EWOULDBLOCK || *self == super::ETIMEDOUT
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.error())
    }
}

impl std::error::Error for Errno {}

impl From<Errno> for io::Error {
    /// The host's error with this Linux number; only meaningful on Linux.
    fn from(e: Errno) -> io::Error {
        io::Error::from_raw_os_error(e.0 as i32)
    }
}

impl From<crate::errno::Errno> for Errno {
    /// A host error number as the Linux `Errno` with the same meaning.
    fn from(e: crate::errno::Errno) -> Errno {
        from_host(e.0)
    }
}

/// The Linux `Errno` for a number from the host's C library.
pub(crate) fn from_host(n: i32) -> Errno {
    if n <= 0 {
        return Errno(0);
    }
    if cfg!(target_os = "linux") {
        return Errno(n as usize);
    }
    // Other hosts number errors differently: find the Linux number whose
    // message is the same.
    let text = ERRORS_DARWIN.get(n as usize).copied().unwrap_or("");
    if !text.is_empty() {
        if let Some(i) = ERRORS_LINUX_AMD64.iter().position(|t| *t == text) {
            return Errno(i);
        }
    }
    super::EIO
}

/// A Linux signal number for the host's signal number `n`.
#[cfg_attr(all(target_os = "linux", target_arch = "x86_64"), allow(dead_code))]
fn signal_from_host(n: i32) -> i32 {
    // Darwin signal numbers 1..=31 in Linux numbering (EMT has no equivalent).
    const MAP: [i32; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 7, 11, 31, 13, 14, 15, 23, 19, 20, 18, 17, 21, 22, 29, 24, 25,
        26, 27, 28, 30, 10, 12,
    ];
    MAP.get(n as usize).copied().unwrap_or(n)
}

/// A wait status in Linux's encoding from the host's `wait4`.
#[cfg_attr(all(target_os = "linux", target_arch = "x86_64"), allow(dead_code))]
pub(crate) fn wait_status_from_host(status: std::os::raw::c_int) -> std::os::raw::c_int {
    if cfg!(target_os = "linux") {
        return status;
    }
    let low = status & 0x7f;
    if low == 0 {
        status
    } else if low == 0x7f {
        let sig = (status >> 8) & 0xff;
        if sig == 0x13 {
            // Darwin reports a continued child as "stopped by SIGCONT".
            return 0xffff;
        }
        0x7f | (signal_from_host(sig) << 8)
    } else {
        (status & !0x7f) | signal_from_host(low)
    }
}

/// `syscall.Signal`: a signal number (Linux numbering).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord, Default)]
pub struct Signal(pub isize);

impl Signal {
    /// `Signal.Signal`: a marker method with no behaviour.
    pub fn signal(&self) {}

    /// `Signal.String`: Go's message text for the number, or `signal N`.
    fn string(&self) -> String {
        match usize::try_from(self.0).ok().and_then(|n| SIGNALS_LINUX_AMD64.get(n)) {
            Some(text) if !text.is_empty() => (*text).to_string(),
            _ => format!("signal {}", self.0),
        }
    }
}

impl fmt::Display for Signal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string())
    }
}
