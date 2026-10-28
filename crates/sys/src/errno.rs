//! Go's `syscall.Errno` and `syscall.Signal`: numbers with the exact message
//! text Go prints, per target.
use crate::errno_table;
use std::fmt;
use std::io;

#[cfg(target_os = "macos")]
use errno_table::{ERRORS_DARWIN as ERRORS, SIGNALS_DARWIN as SIGNALS};
#[cfg(not(target_os = "macos"))]
use errno_table::{ERRORS_LINUX as ERRORS, SIGNALS_LINUX as SIGNALS};

/// `syscall.Errno`: an operating-system error number.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Errno(pub i32);

macro_rules! errnos {
    ($($name:ident = $linux:expr, $darwin:expr;)*) => {
        $(
            #[cfg(target_os = "macos")]
            #[doc = concat!("`syscall.", stringify!($name), "`.")]
            pub const $name: Errno = Errno($darwin);
            #[cfg(not(target_os = "macos"))]
            #[doc = concat!("`syscall.", stringify!($name), "`.")]
            pub const $name: Errno = Errno($linux);
        )*
    };
}

errnos! {
    EPERM = 1, 1;
    ENOENT = 2, 2;
    ESRCH = 3, 3;
    EINTR = 4, 4;
    EIO = 5, 5;
    EBADF = 9, 9;
    ECHILD = 10, 10;
    EAGAIN = 11, 35;
    ENOMEM = 12, 12;
    EACCES = 13, 13;
    EEXIST = 17, 17;
    EXDEV = 18, 18;
    ENOTDIR = 20, 20;
    EISDIR = 21, 21;
    EINVAL = 22, 22;
    ENFILE = 23, 23;
    EMFILE = 24, 24;
    ENOTTY = 25, 25;
    EMLINK = 31, 31;
    EPIPE = 32, 32;
    ERANGE = 34, 34;
    ENAMETOOLONG = 36, 63;
    ENOSYS = 38, 78;
    ELOOP = 40, 62;
    ENOTSOCK = 88, 38;
    EDESTADDRREQ = 89, 39;
    EPROTONOSUPPORT = 93, 43;
    EOPNOTSUPP = 95, 102;
    EAFNOSUPPORT = 97, 47;
    EADDRINUSE = 98, 48;
    EADDRNOTAVAIL = 99, 49;
    ENETUNREACH = 101, 51;
    ECONNABORTED = 103, 53;
    ECONNRESET = 104, 54;
    ENOBUFS = 105, 55;
    EISCONN = 106, 56;
    ENOTCONN = 107, 57;
    ETIMEDOUT = 110, 60;
    ECONNREFUSED = 111, 61;
    EHOSTUNREACH = 113, 65;
    EINPROGRESS = 115, 36;
    EALREADY = 114, 37;
}

/// `syscall.EWOULDBLOCK`: the same number as [`EAGAIN`].
pub const EWOULDBLOCK: Errno = EAGAIN;

impl Errno {
    /// The calling thread's most recent operating-system error.
    pub fn last() -> Errno {
        Errno(io::Error::last_os_error().raw_os_error().unwrap_or(0))
    }

    /// `Errno.Timeout`: the operation timed out.
    pub fn timeout(&self) -> bool {
        *self == EAGAIN || *self == ETIMEDOUT
    }

    /// `Errno.Temporary`: the condition is expected to be transient.
    pub fn temporary(&self) -> bool {
        *self == EINTR || *self == EMFILE || *self == ENFILE || self.timeout()
    }

    /// `Errno.Is` against Go's `oserror` sentinels: `permission`, `exist`,
    /// `not-exist` or `unsupported`.
    pub fn is(&self, target: &str) -> bool {
        match target {
            "permission" => *self == EACCES || *self == EPERM,
            "exist" => *self == EEXIST || *self == ENOTEMPTY,
            "not-exist" => *self == ENOENT,
            "unsupported" => *self == ENOSYS || *self == ENOTSUP || *self == EOPNOTSUPP,
            _ => false,
        }
    }
}

/// `syscall.ENOTEMPTY`.
#[cfg(target_os = "macos")]
pub const ENOTEMPTY: Errno = Errno(66);
/// `syscall.ENOTEMPTY`.
#[cfg(not(target_os = "macos"))]
pub const ENOTEMPTY: Errno = Errno(39);
/// `syscall.ENOTSUP`.
#[cfg(target_os = "macos")]
pub const ENOTSUP: Errno = Errno(45);
/// `syscall.ENOTSUP`.
#[cfg(not(target_os = "macos"))]
pub const ENOTSUP: Errno = Errno(95);

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match usize::try_from(self.0).ok().and_then(|n| ERRORS.get(n)) {
            Some(text) if !text.is_empty() => f.write_str(text),
            _ => write!(f, "errno {}", self.0),
        }
    }
}

impl std::error::Error for Errno {}

impl From<Errno> for io::Error {
    fn from(e: Errno) -> io::Error {
        io::Error::from_raw_os_error(e.0)
    }
}

impl From<io::Error> for Errno {
    fn from(e: io::Error) -> Errno {
        match e.raw_os_error() {
            Some(n) => Errno(n),
            None => match e.kind() {
                io::ErrorKind::NotFound => ENOENT,
                io::ErrorKind::PermissionDenied => EACCES,
                io::ErrorKind::TimedOut => ETIMEDOUT,
                io::ErrorKind::WouldBlock => EAGAIN,
                io::ErrorKind::InvalidInput => EINVAL,
                _ => EIO,
            },
        }
    }
}

/// `syscall.Signal`: a signal number.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Signal(pub i32);

macro_rules! signals {
    ($($name:ident = $linux:expr, $darwin:expr;)*) => {
        $(
            #[cfg(target_os = "macos")]
            #[doc = concat!("`syscall.", stringify!($name), "`.")]
            pub const $name: Signal = Signal($darwin);
            #[cfg(not(target_os = "macos"))]
            #[doc = concat!("`syscall.", stringify!($name), "`.")]
            pub const $name: Signal = Signal($linux);
        )*
    };
}

signals! {
    SIGHUP = 1, 1;
    SIGINT = 2, 2;
    SIGQUIT = 3, 3;
    SIGABRT = 6, 6;
    SIGKILL = 9, 9;
    SIGUSR1 = 10, 30;
    SIGSEGV = 11, 11;
    SIGUSR2 = 12, 31;
    SIGPIPE = 13, 13;
    SIGALRM = 14, 14;
    SIGTERM = 15, 15;
    SIGCHLD = 17, 20;
    SIGCONT = 18, 19;
    SIGSTOP = 19, 17;
}

impl Signal {
    /// `Signal.Signal`: a marker method with no behaviour.
    pub fn signal(&self) {}
}

impl fmt::Display for Signal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match usize::try_from(self.0).ok().and_then(|n| SIGNALS.get(n)) {
            Some(text) if !text.is_empty() => f.write_str(text),
            _ => write!(f, "signal {}", self.0),
        }
    }
}
