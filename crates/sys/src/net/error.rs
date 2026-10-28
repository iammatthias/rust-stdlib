//! Go's `net.OpError` and the error values it wraps.
use crate::errno::Errno;
use crate::os::SyscallError;
use std::fmt;

/// The cause inside an [`OpError`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Cause {
    /// A bare operating-system error number.
    Errno(Errno),
    /// A failed system call, `setsockopt: bad file descriptor`.
    Syscall(SyscallError),
    /// `os.ErrDeadlineExceeded`: "i/o timeout".
    Timeout,
    /// `net.ErrClosed`: "use of closed network connection".
    Closed,
    /// Go's `errCanceled`: "operation was canceled".
    Canceled,
    /// `os.ErrClosed`: "file already closed".
    FileClosed,
    /// "no such network interface".
    NoSuchInterface,
    /// "invalid network interface".
    InvalidInterface,
    /// "invalid network interface index".
    InvalidInterfaceIndex,
    /// "invalid network interface name".
    InvalidInterfaceName,
    /// "missing address".
    MissingAddress,
    /// "unknown network `<name>`" (`net.UnknownNetworkError`).
    UnknownNetwork(String),
    /// "invalid address" with detail, e.g. `address x: missing port in address`.
    Address(String),
    /// `net.DNSError`: `"lookup <name>: <err>"`.
    Dns {
        /// The name or service that was looked up.
        name: String,
        /// The failure, e.g. "no such host".
        err: String,
    },
    /// "operation not supported" on this target or socket type.
    Unsupported,
    /// Any other message.
    Other(String),
}

impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Cause::Errno(e) => e.fmt(f),
            Cause::Syscall(e) => e.fmt(f),
            Cause::Timeout => f.write_str("i/o timeout"),
            Cause::Closed => f.write_str("use of closed network connection"),
            Cause::Canceled => f.write_str("operation was canceled"),
            Cause::FileClosed => f.write_str("file already closed"),
            Cause::NoSuchInterface => f.write_str("no such network interface"),
            Cause::InvalidInterface => f.write_str("invalid network interface"),
            Cause::InvalidInterfaceIndex => f.write_str("invalid network interface index"),
            Cause::InvalidInterfaceName => f.write_str("invalid network interface name"),
            Cause::MissingAddress => f.write_str("missing address"),
            Cause::UnknownNetwork(n) => write!(f, "unknown network {n}"),
            Cause::Address(s) => f.write_str(s),
            Cause::Dns { name, err } => write!(f, "lookup {name}: {err}"),
            Cause::Unsupported => f.write_str("operation not supported"),
            Cause::Other(s) => f.write_str(s),
        }
    }
}

/// `net.OpError`: an error from a network operation.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OpError {
    /// The operation, e.g. "dial", "read", "set"; empty for a bare error.
    pub op: String,
    /// The network type, e.g. "tcp", "ip+net"; may be empty.
    pub net: String,
    /// The local address, if known.
    pub source: Option<String>,
    /// The remote address, if known.
    pub addr: Option<String>,
    /// What went wrong.
    pub err: Cause,
}

impl OpError {
    /// An error with no network or addresses.
    pub fn new(op: &str, err: Cause) -> OpError {
        OpError {
            op: op.into(),
            net: String::new(),
            source: None,
            addr: None,
            err,
        }
    }

    /// `OpError.Timeout`: the operation timed out.
    pub fn timeout(&self) -> bool {
        match &self.err {
            Cause::Timeout => true,
            Cause::Errno(e) => e.timeout(),
            Cause::Syscall(e) => e.err.timeout(),
            _ => false,
        }
    }

    /// `OpError.Temporary`: the condition is expected to be transient.
    pub fn temporary(&self) -> bool {
        match &self.err {
            Cause::Timeout => true,
            Cause::Errno(e) => e.temporary(),
            Cause::Syscall(e) => e.err.temporary(),
            _ => false,
        }
    }

    /// The underlying error number, if the cause is one.
    pub fn errno(&self) -> Option<Errno> {
        match &self.err {
            Cause::Errno(e) => Some(*e),
            Cause::Syscall(e) => Some(e.err),
            _ => None,
        }
    }
}

impl fmt::Display for OpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // An empty operation is a bare error, as Go's listeners return from
        // `SetDeadline` on a closed listener.
        if self.op.is_empty() {
            return write!(f, "{}", self.err);
        }
        f.write_str(&self.op)?;
        if !self.net.is_empty() {
            write!(f, " {}", self.net)?;
        }
        if let Some(source) = &self.source {
            write!(f, " {source}")?;
        }
        if let Some(addr) = &self.addr {
            f.write_str(if self.source.is_some() { "->" } else { " " })?;
            f.write_str(addr)?;
        }
        write!(f, ": {}", self.err)
    }
}

impl std::error::Error for OpError {}

impl From<OpError> for std::io::Error {
    fn from(e: OpError) -> std::io::Error {
        let kind = match &e.err {
            Cause::Timeout => std::io::ErrorKind::TimedOut,
            Cause::Closed => std::io::ErrorKind::NotConnected,
            Cause::Errno(n) => std::io::Error::from_raw_os_error(n.0).kind(),
            Cause::Syscall(s) => std::io::Error::from_raw_os_error(s.err.0).kind(),
            _ => std::io::ErrorKind::Other,
        };
        std::io::Error::new(kind, e)
    }
}
