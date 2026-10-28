//! Go's `net` error types: [`OpError`], [`AddrError`], [`ParseError`],
//! [`DNSError`] and friends, unified in [`NetError`], plus the [`Addr`] and
//! [`Error`] interfaces.
//!
//! Go returns `error` interface values. Here every fallible `net` function
//! returns [`NetError`], an enum over the concrete Go error types, and the
//! `std::io` trait implementations wrap a `NetError` inside the `io::Error`
//! (`io::Error::get_ref().downcast_ref::<NetError>()` recovers it).
use std::fmt;
use std::io;
use std::sync::Arc;

/// Go's `net.Addr`: a network end point address.
pub trait Addr: fmt::Debug + fmt::Display + Send + Sync {
    /// `Addr.Network`: the name of the network ("tcp", "udp").
    fn network(&self) -> &str;
    /// Downcasting hook for the concrete address types ([`TCPAddr`](super::TCPAddr), ...).
    fn as_any(&self) -> &dyn std::any::Any;
}

/// A shared, dynamically typed [`Addr`] (Go's interface value).
pub type AddrRef = Arc<dyn Addr>;

/// Go's `net.Error` interface.
pub trait Error: std::error::Error {
    /// `Error.Timeout`: is the error a timeout?
    fn timeout(&self) -> bool;
    /// `Error.Temporary`: deprecated in Go, kept for parity.
    fn temporary(&self) -> bool;
}

/// `net.ParseError`: a literal network address that failed to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// The kind of string expected: "IP address", "CIDR address".
    pub type_: String,
    /// The malformed text.
    pub text: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid {}: {}", self.type_, self.text)
    }
}

/// `net.AddrError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrError {
    /// The problem.
    pub err: String,
    /// The offending address, if any.
    pub addr: String,
}

impl fmt::Display for AddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.addr.is_empty() {
            f.write_str(&self.err)
        } else {
            write!(f, "address {}: {}", self.addr, self.err)
        }
    }
}

/// `net.UnknownNetworkError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownNetworkError(pub String);

impl fmt::Display for UnknownNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown network {}", self.0)
    }
}

/// `net.InvalidAddrError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidAddrError(pub String);

impl fmt::Display for InvalidAddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// `net.DNSConfigError`: an error reading the machine's DNS configuration.
#[derive(Debug, Clone)]
pub struct DNSConfigError {
    /// The underlying error.
    pub err: Box<NetError>,
}

impl fmt::Display for DNSConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error reading DNS config: {}", self.err)
    }
}

impl DNSConfigError {
    /// `DNSConfigError.Unwrap`.
    pub fn unwrap(&self) -> &NetError {
        &self.err
    }
}

/// `net.DNSError`: a DNS lookup error.
#[derive(Debug, Clone)]
pub struct DNSError {
    /// Error returned by [`DNSError::unwrap`], if any.
    pub unwrap_err: Option<Box<NetError>>,
    /// Description of the error.
    pub err: String,
    /// The name looked for.
    pub name: String,
    /// The server used.
    pub server: String,
    /// True if the lookup timed out.
    pub is_timeout: bool,
    /// True if the error is temporary.
    pub is_temporary: bool,
    /// True when the name or the record type was not found.
    pub is_not_found: bool,
}

impl fmt::Display for DNSError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "lookup {}", self.name)?;
        if !self.server.is_empty() {
            write!(f, " on {}", self.server)?;
        }
        write!(f, ": {}", self.err)
    }
}

impl DNSError {
    /// `DNSError.Unwrap`.
    pub fn unwrap(&self) -> Option<&NetError> {
        self.unwrap_err.as_deref()
    }
    /// `DNSError.Timeout`.
    pub fn timeout(&self) -> bool {
        self.is_timeout
    }
    /// `DNSError.Temporary`.
    pub fn temporary(&self) -> bool {
        self.is_timeout || self.is_temporary
    }
}

/// `net.OpError`: the operation, network and addresses of a failure.
#[derive(Debug, Clone)]
pub struct OpError {
    /// The operation: "read", "write", "dial", ...
    pub op: String,
    /// The network type: "tcp", "udp6", ...
    pub net: String,
    /// The local address of a remote operation.
    pub source: Option<AddrRef>,
    /// The address the error concerns.
    pub addr: Option<AddrRef>,
    /// The underlying error.
    pub err: Box<NetError>,
}

impl fmt::Display for OpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.op)?;
        if !self.net.is_empty() {
            write!(f, " {}", self.net)?;
        }
        if let Some(s) = &self.source {
            write!(f, " {}", s)?;
        }
        if let Some(a) = &self.addr {
            f.write_str(if self.source.is_some() { "->" } else { " " })?;
            f.write_str(&a.to_string())?;
        }
        write!(f, ": {}", self.err)
    }
}

impl OpError {
    /// `OpError.Unwrap`.
    pub fn unwrap(&self) -> &NetError {
        &self.err
    }
    /// `OpError.Timeout`.
    pub fn timeout(&self) -> bool {
        self.err.timeout()
    }
    /// `OpError.Temporary`: ECONNRESET and ECONNABORTED from accept count.
    pub fn temporary(&self) -> bool {
        if self.op == "accept" && self.err.is_conn_error() {
            return true;
        }
        self.err.temporary()
    }
}

/// A failed system call, Go's `*os.SyscallError` around an `Errno`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallError {
    /// The call: "connect", "bind", "read", ...
    pub syscall: String,
    /// The operating system's error text, Go-style (lower case).
    pub text: String,
    /// The `std::io` classification.
    pub kind: io::ErrorKind,
    /// The raw errno, when known.
    pub errno: Option<i32>,
}

/// Every error value the `net` package returns.
#[derive(Debug, Clone)]
pub enum NetError {
    /// `*net.OpError`.
    Op(OpError),
    /// `*net.AddrError`.
    Addr(AddrError),
    /// `*net.ParseError`.
    Parse(ParseError),
    /// `net.UnknownNetworkError`.
    UnknownNetwork(UnknownNetworkError),
    /// `net.InvalidAddrError`.
    InvalidAddr(InvalidAddrError),
    /// `*net.DNSError`.
    Dns(Box<DNSError>),
    /// `*net.DNSConfigError`.
    DnsConfig(DNSConfigError),
    /// `net.ErrClosed`: "use of closed network connection".
    Closed,
    /// `net.ErrWriteToConnected`.
    WriteToConnected,
    /// Go's "i/o timeout" as `errTimeout`: a dial deadline, which is
    /// `errors.Is(err, context.DeadlineExceeded)`.
    Timeout,
    /// Go's "i/o timeout" as `os.ErrDeadlineExceeded`: a connection deadline.
    IoTimeout,
    /// Go's "operation was canceled" (`context.Canceled`).
    Canceled,
    /// Go's `io.ErrClosedPipe`: "io: read/write on closed pipe".
    ClosedPipe,
    /// A failed system call.
    Sys(SyscallError),
    /// A plain `errors.New` value; `temporary` is Go's `temporaryError`.
    Other {
        /// The message.
        text: String,
        /// Whether `Temporary()` reports true.
        temporary: bool,
        /// Whether it is Go's `notFoundError`.
        not_found: bool,
    },
}

impl NetError {
    /// An `errors.New(text)` value.
    pub fn other(text: impl Into<String>) -> NetError {
        NetError::Other {
            text: text.into(),
            temporary: false,
            not_found: false,
        }
    }

    /// Whether this is (or wraps) [`NetError::Closed`]: `errors.Is(err, net.ErrClosed)`.
    pub fn is_closed(&self) -> bool {
        match self {
            NetError::Closed => true,
            NetError::Op(o) => o.err.is_closed(),
            _ => false,
        }
    }

    /// Whether this is (or wraps) `errTimeout`: `errors.Is(err, context.DeadlineExceeded)`.
    pub fn is_deadline_exceeded(&self) -> bool {
        match self {
            NetError::Timeout => true,
            NetError::Op(o) => o.err.is_deadline_exceeded(),
            NetError::Dns(d) => d
                .unwrap_err
                .as_deref()
                .is_some_and(|e| e.is_deadline_exceeded()),
            _ => false,
        }
    }

    /// Whether this is (or wraps) a connection deadline error:
    /// `errors.Is(err, os.ErrDeadlineExceeded)`.
    pub fn is_io_timeout(&self) -> bool {
        match self {
            NetError::IoTimeout => true,
            NetError::Op(o) => o.err.is_io_timeout(),
            _ => false,
        }
    }

    pub(crate) fn is_conn_error(&self) -> bool {
        matches!(
            self,
            NetError::Sys(SyscallError {
                kind: io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted,
                ..
            })
        )
    }

    /// Converts an `io::Error`, recovering an embedded `NetError` and naming
    /// the failed system call otherwise.
    pub fn from_io(syscall: &str, e: &io::Error) -> NetError {
        if let Some(inner) = e.get_ref().and_then(|r| r.downcast_ref::<NetError>()) {
            return inner.clone();
        }
        if matches!(
            e.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ) && e
            .raw_os_error()
            .is_none_or(|n| n == 11 || n == 35 || n == 60 || n == 110)
        {
            return NetError::IoTimeout;
        }
        let mut text = e.to_string();
        if let Some(at) = text.rfind(" (os error ") {
            text.truncate(at);
        }
        if let Some(c) = text.chars().next() {
            if c.is_ascii_uppercase()
                && !text.chars().nth(1).is_some_and(|d| d.is_ascii_uppercase())
            {
                text = format!("{}{}", c.to_ascii_lowercase(), &text[1..]);
            }
        }
        NetError::Sys(SyscallError {
            syscall: syscall.to_owned(),
            text,
            kind: e.kind(),
            errno: e.raw_os_error(),
        })
    }

    /// Wraps this error in an `io::Error` for `std::io` trait methods.
    pub fn into_io(self) -> io::Error {
        let kind = match &self {
            NetError::Timeout | NetError::IoTimeout => io::ErrorKind::TimedOut,
            NetError::Op(o) if o.err.timeout() => io::ErrorKind::TimedOut,
            NetError::Op(OpError { err, .. }) => match &**err {
                NetError::Sys(s) => s.kind,
                NetError::Closed => io::ErrorKind::NotConnected,
                _ => io::ErrorKind::Other,
            },
            NetError::Sys(s) => s.kind,
            _ => io::ErrorKind::Other,
        };
        io::Error::new(kind, self)
    }
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetError::Op(e) => e.fmt(f),
            NetError::Addr(e) => e.fmt(f),
            NetError::Parse(e) => e.fmt(f),
            NetError::UnknownNetwork(e) => e.fmt(f),
            NetError::InvalidAddr(e) => e.fmt(f),
            NetError::Dns(e) => e.fmt(f),
            NetError::DnsConfig(e) => e.fmt(f),
            NetError::Closed => f.write_str("use of closed network connection"),
            NetError::WriteToConnected => {
                f.write_str("use of WriteTo with pre-connected connection")
            }
            NetError::Timeout | NetError::IoTimeout => f.write_str("i/o timeout"),
            NetError::Canceled => f.write_str("operation was canceled"),
            NetError::ClosedPipe => f.write_str("io: read/write on closed pipe"),
            NetError::Sys(s) if s.syscall.is_empty() => f.write_str(&s.text),
            NetError::Sys(s) => write!(f, "{}: {}", s.syscall, s.text),
            NetError::Other { text, .. } => f.write_str(text),
        }
    }
}

impl std::error::Error for NetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NetError::Op(o) => Some(&*o.err),
            NetError::Dns(d) => d.unwrap_err.as_deref().map(|e| e as _),
            NetError::DnsConfig(d) => Some(&*d.err),
            _ => None,
        }
    }
}

impl Error for NetError {
    fn timeout(&self) -> bool {
        match self {
            NetError::Op(o) => o.timeout(),
            NetError::Dns(d) => d.timeout(),
            NetError::Timeout | NetError::IoTimeout => true,
            NetError::Sys(s) => s.kind == io::ErrorKind::TimedOut,
            _ => false,
        }
    }

    fn temporary(&self) -> bool {
        match self {
            NetError::Op(o) => o.temporary(),
            NetError::Dns(d) => d.temporary(),
            NetError::Timeout | NetError::IoTimeout => true,
            NetError::Sys(s) => {
                s.kind == io::ErrorKind::TimedOut
                    || s.kind == io::ErrorKind::Interrupted
                    || matches!(s.errno, Some(23 | 24))
            }
            NetError::Other { temporary, .. } => *temporary,
            _ => false,
        }
    }
}

macro_rules! plain_error {
    ($($t:ident => $variant:ident),*) => {$(
        impl std::error::Error for $t {}
        impl Error for $t {
            fn timeout(&self) -> bool { false }
            fn temporary(&self) -> bool { false }
        }
        impl From<$t> for NetError {
            fn from(e: $t) -> NetError { NetError::$variant(e) }
        }
    )*};
}

plain_error!(
    ParseError => Parse,
    AddrError => Addr,
    UnknownNetworkError => UnknownNetwork,
    InvalidAddrError => InvalidAddr
);

impl std::error::Error for DNSConfigError {}
impl Error for DNSConfigError {
    fn timeout(&self) -> bool {
        false
    }
    fn temporary(&self) -> bool {
        false
    }
}

impl std::error::Error for DNSError {}
impl Error for DNSError {
    fn timeout(&self) -> bool {
        DNSError::timeout(self)
    }
    fn temporary(&self) -> bool {
        DNSError::temporary(self)
    }
}

impl std::error::Error for OpError {}
impl Error for OpError {
    fn timeout(&self) -> bool {
        OpError::timeout(self)
    }
    fn temporary(&self) -> bool {
        OpError::temporary(self)
    }
}

impl From<OpError> for NetError {
    fn from(e: OpError) -> NetError {
        NetError::Op(e)
    }
}

impl From<DNSError> for NetError {
    fn from(e: DNSError) -> NetError {
        NetError::Dns(Box::new(e))
    }
}

impl From<NetError> for io::Error {
    fn from(e: NetError) -> io::Error {
        e.into_io()
    }
}

/// `net.ErrClosed`.
pub const ERR_CLOSED: NetError = NetError::Closed;
/// `net.ErrWriteToConnected`.
pub const ERR_WRITE_TO_CONNECTED: NetError = NetError::WriteToConnected;
