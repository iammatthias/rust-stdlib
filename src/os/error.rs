//! Errors of the `os` package: operating system error numbers with Go's
//! message text, `LinkError`, `SyscallError`, the package sentinels and the
//! `Is*` predicates.

use crate::io::fs::{self, path_error, PathError};
use std::fmt;
use std::io;

/// Operating system error numbers used by this package, per target.
pub(crate) mod errno {
    pub const EPERM: i32 = 1;
    pub const ENOENT: i32 = 2;
    pub const ESRCH: i32 = 3;
    pub const ECHILD: i32 = 10;
    pub const EACCES: i32 = 13;
    pub const EEXIST: i32 = 17;
    pub const ENOTDIR: i32 = 20;
    pub const EISDIR: i32 = 21;
    pub const EINVAL: i32 = 22;
    pub const EMLINK: i32 = 31;
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    pub const ENAMETOOLONG: i32 = 63;
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd")))]
    pub const ENAMETOOLONG: i32 = 36;
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    pub const ELOOP: i32 = 62;
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd")))]
    pub const ELOOP: i32 = 40;
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    pub const ENOTEMPTY: i32 = 66;
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd")))]
    pub const ENOTEMPTY: i32 = 39;
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    pub const EAGAIN: i32 = 35;
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd")))]
    pub const EAGAIN: i32 = 11;
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    pub const ETIMEDOUT: i32 = 60;
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd")))]
    pub const ETIMEDOUT: i32 = 110;
}

/// An operating system error number (`syscall.Errno`) with Go's message
/// text: `std` prints `No such file or directory (os error 2)` where Go
/// prints `no such file or directory`. `os` functions return `io::Error`s
/// that carry an `Errno` (the `io::Error::kind` is the standard one).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Errno(pub i32);

impl Errno {
    /// Go's message text for this error number.
    pub fn message(self) -> String {
        let s = io::Error::from_raw_os_error(self.0).to_string();
        let s = match s.rfind(" (os error ") {
            Some(i) => &s[..i],
            None => &s,
        };
        let mut chars = s.chars();
        match chars.next() {
            Some(c) if !chars.clone().next().is_some_and(|d| d.is_uppercase()) => {
                c.to_lowercase().chain(chars).collect()
            }
            _ => s.to_string(),
        }
    }

    /// `Errno.Timeout`.
    pub fn timeout(self) -> bool {
        self.0 == errno::EAGAIN || self.0 == errno::ETIMEDOUT
    }

    /// `Errno.Temporary`.
    pub fn temporary(self) -> bool {
        self.timeout() || self.0 == 4 // EINTR
    }

    /// `Errno.Is`: whether this number matches one of the `fs` sentinels.
    pub fn is(self, target: fs::Error) -> bool {
        match target {
            fs::Error::Permission => self.0 == errno::EACCES || self.0 == errno::EPERM,
            fs::Error::Exist => self.0 == errno::EEXIST || self.0 == errno::ENOTEMPTY,
            fs::Error::NotExist => self.0 == errno::ENOENT,
            _ => false,
        }
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for Errno {}

impl From<Errno> for io::Error {
    /// The `io::ErrorKind` is the standard one for the number, except that
    /// `EINVAL` is `Other`: Go's `errors.Is(syscall.EINVAL, ErrInvalid)` is
    /// false, and `fs::ERR_INVALID.is` matches `InvalidInput` errors.
    fn from(e: Errno) -> io::Error {
        let kind = match io::Error::from_raw_os_error(e.0).kind() {
            io::ErrorKind::InvalidInput => io::ErrorKind::Other,
            k => k,
        };
        io::Error::new(kind, e)
    }
}

/// The error number inside `err`, if any (`errors.As(err, &syscall.Errno)`).
pub fn errno_of(err: &io::Error) -> Option<Errno> {
    if let Some(c) = err.raw_os_error() {
        return Some(Errno(c));
    }
    let mut cur: Option<&(dyn std::error::Error + 'static)> = err.get_ref().map(|e| e as _);
    while let Some(e) = cur {
        if let Some(n) = e.downcast_ref::<Errno>() {
            return Some(*n);
        }
        if let Some(inner) = e.downcast_ref::<io::Error>() {
            if let Some(n) = errno_of(inner) {
                return Some(n);
            }
        }
        cur = e.source();
    }
    None
}

/// Rewrites a `std` error so that it prints with Go's text. Errors that
/// already carry a payload are returned unchanged.
pub(crate) fn os_error(err: io::Error) -> io::Error {
    if err.get_ref().is_some() {
        return err;
    }
    if let Some(c) = err.raw_os_error() {
        return Errno(c).into();
    }
    match err.kind() {
        io::ErrorKind::InvalidInput => Errno(errno::EINVAL).into(),
        io::ErrorKind::UnexpectedEof => crate::io::eof(),
        _ => err,
    }
}

/// An `io::Error` for an error number.
pub(crate) fn from_errno(code: i32) -> io::Error {
    Errno(code).into()
}

/// A `PathError` with Go's text for `err`.
pub(crate) fn path_err(op: &str, path: &str, err: io::Error) -> io::Error {
    PathError::new(op, path, os_error(err)).into()
}

/// Errors that `os` adds to the `io/fs` set (`ErrNoDeadline`,
/// `ErrDeadlineExceeded`, `ErrProcessDone`, `ErrNoHandle`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// `os.ErrNoDeadline`: the file type does not support deadlines.
    NoDeadline,
    /// `os.ErrDeadlineExceeded`: an I/O operation timed out.
    DeadlineExceeded,
    /// `os.ErrProcessDone`: the process has already finished.
    ProcessDone,
    /// `os.ErrNoHandle`: the process handle is not available.
    NoHandle,
}

impl Error {
    /// Reports whether `err` is, or wraps, this sentinel (`errors.Is`).
    pub fn is(self, err: &io::Error) -> bool {
        crate::io::chain_has(err, &self)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::NoDeadline => "file type does not support deadline",
            Error::DeadlineExceeded => "i/o timeout",
            Error::ProcessDone => "os: process already finished",
            Error::NoHandle => "os: process handle not available",
        })
    }
}

impl std::error::Error for Error {}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        let kind = match e {
            Error::DeadlineExceeded => io::ErrorKind::TimedOut,
            _ => io::ErrorKind::Other,
        };
        io::Error::new(kind, e)
    }
}

/// An error from `Link`, `Symlink` and `Rename` (`os.LinkError`).
#[derive(Debug)]
pub struct LinkError {
    /// The operation (`LinkError.Op`).
    pub op: String,
    /// The old path (`LinkError.Old`).
    pub old: String,
    /// The new path (`LinkError.New`).
    pub new: String,
    /// The underlying error (`LinkError.Err`).
    pub err: io::Error,
}

impl LinkError {
    /// The underlying error (`LinkError.Unwrap`).
    pub fn unwrap(&self) -> &io::Error {
        &self.err
    }
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}: {}", self.op, self.old, self.new, self.err)
    }
}

impl std::error::Error for LinkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.err)
    }
}

impl From<LinkError> for io::Error {
    fn from(e: LinkError) -> io::Error {
        io::Error::new(e.err.kind(), e)
    }
}

pub(crate) fn link_err(op: &str, old: &str, new: &str, err: io::Error) -> io::Error {
    LinkError {
        op: op.to_string(),
        old: old.to_string(),
        new: new.to_string(),
        err: os_error(err),
    }
    .into()
}

/// Returns the [`LinkError`] inside `err`, if any.
pub fn link_error(err: &io::Error) -> Option<&LinkError> {
    err.get_ref().and_then(|e| e.downcast_ref::<LinkError>())
}

/// An error from a named system call (`os.SyscallError`).
#[derive(Debug)]
pub struct SyscallError {
    /// The failing call (`SyscallError.Syscall`).
    pub syscall: String,
    /// The underlying error (`SyscallError.Err`).
    pub err: io::Error,
}

impl SyscallError {
    /// The underlying error (`SyscallError.Unwrap`).
    pub fn unwrap(&self) -> &io::Error {
        &self.err
    }

    /// Reports whether the error is a timeout (`SyscallError.Timeout`).
    pub fn timeout(&self) -> bool {
        is_timeout_leaf(&self.err)
    }
}

impl fmt::Display for SyscallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.syscall, self.err)
    }
}

impl std::error::Error for SyscallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.err)
    }
}

impl From<SyscallError> for io::Error {
    fn from(e: SyscallError) -> io::Error {
        io::Error::new(e.err.kind(), e)
    }
}

impl SyscallError {
    /// Wraps `err` as a `SyscallError` for `syscall` (`os.NewSyscallError`).
    pub fn new(syscall: &str, err: io::Error) -> SyscallError {
        SyscallError {
            syscall: syscall.to_string(),
            err: os_error(err),
        }
    }
}

/// Returns the [`SyscallError`] inside `err`, if any.
pub fn syscall_error(err: &io::Error) -> Option<&SyscallError> {
    err.get_ref().and_then(|e| e.downcast_ref::<SyscallError>())
}

/// Strips every `PathError`, `LinkError` and `SyscallError` layer from `err`
/// and returns the underlying error.
pub(crate) fn unwrap_layers(mut err: io::Error) -> io::Error {
    loop {
        let wrapped = path_error(&err).is_some()
            || link_error(&err).is_some()
            || syscall_error(&err).is_some();
        if !wrapped {
            return err;
        }
        let Some(inner) = err.into_inner() else {
            return io::Error::other("os: malformed error");
        };
        err = match inner.downcast::<fs::PathError>() {
            Ok(p) => p.err,
            Err(inner) => match inner.downcast::<LinkError>() {
                Ok(l) => l.err,
                Err(inner) => match inner.downcast::<SyscallError>() {
                    Ok(s) => s.err,
                    Err(_) => return io::Error::other("os: malformed error"),
                },
            },
        };
    }
}

/// Rewrites the operation, path and error of the `PathError` in `err`;
/// other errors are returned unchanged.
pub(crate) fn map_path_error(
    err: io::Error,
    f: impl FnOnce(String, String, io::Error) -> (String, String, io::Error),
) -> io::Error {
    if path_error(&err).is_none() {
        return err;
    }
    match err.into_inner().map(|b| b.downcast::<fs::PathError>()) {
        Some(Ok(p)) => {
            let p = *p;
            let (op, path, e) = f(p.op, p.path, p.err);
            PathError::new(&op, &path, e).into()
        }
        _ => io::Error::other("os: malformed path error"),
    }
}

/// A copy of an error made by this module (an `Errno` payload).
pub(crate) fn clone_errno_error(err: &io::Error) -> io::Error {
    match errno_of(err) {
        Some(n) => n.into(),
        None => io::Error::new(err.kind(), err.to_string()),
    }
}

/// Go's `underlyingError`: strips one `PathError`, `LinkError` or
/// `SyscallError` layer.
fn underlying(err: &io::Error) -> &io::Error {
    if let Some(p) = path_error(err) {
        &p.err
    } else if let Some(l) = link_error(err) {
        &l.err
    } else if let Some(s) = syscall_error(err) {
        &s.err
    } else {
        err
    }
}

fn is_timeout_leaf(err: &io::Error) -> bool {
    if let Some(n) = errno_of(err) {
        return n.timeout();
    }
    let sentinel = err
        .get_ref()
        .and_then(|e| e.downcast_ref::<Error>())
        .is_some_and(|e| *e == Error::DeadlineExceeded);
    sentinel
        || matches!(
            err.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        )
}

fn leaf_is(err: &io::Error, target: fs::Error) -> bool {
    let err = underlying(err);
    if err.get_ref().and_then(|e| e.downcast_ref::<fs::Error>()) == Some(&target) {
        return true;
    }
    if let Some(n) = errno_of(err) {
        return n.is(target);
    }
    match target {
        fs::Error::Permission => err.kind() == io::ErrorKind::PermissionDenied,
        fs::Error::Exist => matches!(
            err.kind(),
            io::ErrorKind::AlreadyExists | io::ErrorKind::DirectoryNotEmpty
        ),
        fs::Error::NotExist => err.kind() == io::ErrorKind::NotFound,
        _ => false,
    }
}

/// Reports whether `err` says that a file or directory already exists
/// (`os.IsExist`).
pub fn is_exist(err: &io::Error) -> bool {
    leaf_is(err, fs::Error::Exist)
}

/// Reports whether `err` says that a file or directory does not exist
/// (`os.IsNotExist`).
pub fn is_not_exist(err: &io::Error) -> bool {
    leaf_is(err, fs::Error::NotExist)
}

/// Reports whether `err` says that permission is denied (`os.IsPermission`).
pub fn is_permission(err: &io::Error) -> bool {
    leaf_is(err, fs::Error::Permission)
}

/// Reports whether `err` is a timeout (`os.IsTimeout`).
pub fn is_timeout(err: &io::Error) -> bool {
    is_timeout_leaf(underlying(err))
}
