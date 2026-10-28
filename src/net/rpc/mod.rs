//! Go's `net/rpc`: access to the exported methods of an object across a
//! network or other I/O connection.
//!
//! A server registers an object, making it visible as a service with the
//! name of the type of the object. After registration, exported methods of
//! the object are accessible remotely. Only methods that satisfy Go's
//! criteria are made available; the others are ignored:
//!
//! - the method's type is exported;
//! - the method is exported;
//! - the method has two arguments, both exported (or builtin) types;
//! - the method's second argument is a pointer;
//! - the method has return type error.
//!
//! In Go the method looks like
//! `func (t *T) MethodName(argType T1, replyType *T2) error`. Methods come
//! from [`crate::reflect`] here, so the object's type registers them with
//! `#[reflect_methods]` (`rust-stdlib-derive`), where Go's pointer is
//! `&mut`, Go's `error` is `Result<(), String>`, and the receiver is
//! `&mut self` for a pointer receiver:
//!
//! ```ignore
//! #[derive(Reflect, Default)]
//! pub struct Arith {}
//!
//! #[reflect_methods]
//! impl Arith {
//!     pub fn Multiply(&mut self, args: Args, reply: &mut isize) -> Result<(), String> {
//!         *reply = args.A * args.B;
//!         Ok(())
//!     }
//! }
//!
//! let server = rpc::Server::new();
//! server.register(&Some(Arith {}))?; // Go's pointer receiver: an Option
//! ```
//!
//! The server may handle requests on a single connection by calling
//! [`Server::serve_conn`]; more typically it creates a listener and calls
//! [`Server::accept`] or, for HTTP, [`Server::handle_http`]. A client
//! establishes a connection and calls [`NewClient`](Client::new); [`dial`]
//! ([`dial_http`]) does both. [`Client::call`] waits for the remote call to
//! complete while [`Client::call_async`] launches it asynchronously and signals
//! completion on the call's `done` channel. Unless an explicit codec is set
//! up, `encoding/gob` transports the data; see [`jsonrpc`] for JSON-RPC 1.0.
//!
//! # Deviations from Go
//!
//! - Arguments and replies are [`reflect::Value`]s (or
//!   [`Reflect`] types in the typed `call`).
//!   Registered receivers are copied into the dynamic store, so state a
//!   `&mut self` method keeps lives in the server's copy; calls to such
//!   methods of one service run one at a time, because the method reads
//!   the receiver, changes it and writes it back.
//! - Errors are the cloneable [`Error`] enum.
//! - A `done` channel is a `std::sync::mpsc::SyncSender`, whose capacity
//!   cannot be queried, so Go's panic for an unbuffered `done` is not raised;
//!   a call whose `done` channel is full is dropped, as in Go.

use std::io;
use std::sync::{Arc, LazyLock};

use crate::reflect::{self, Kind, Reflect, ReflectType, Type, Value};

mod client;
mod debug;
mod gobcodec;
pub mod jsonrpc;
mod server;

pub use client::{dial, Call, Client};
#[cfg(feature = "net")]
pub use client::{dial_http, dial_http_path};
pub use server::{accept, register, register_name, serve_codec, serve_conn, serve_request};
#[cfg(feature = "net")]
pub use server::{handle_http, ServerHandler};
pub use server::{Server, DEFAULT_SERVER};

/// Can connect to RPC service using HTTP CONNECT to rpcPath.
#[cfg(feature = "net")]
pub(crate) const CONNECTED: &str = "200 Connected to Go RPC";

/// Defaults used by [`handle_http`].
pub const DEFAULT_RPC_PATH: &str = "/_goRPC_";
/// Defaults used by [`handle_http`].
pub const DEFAULT_DEBUG_PATH: &str = "/debug/rpc";

/// A header written before every RPC call (Go `rpc.Request`). It is used
/// internally but documented here as an aid to debugging, such as when
/// analyzing network traffic.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Request {
    /// Format: `"Service.Method"`.
    pub service_method: String,
    /// Sequence number chosen by client.
    pub seq: u64,
}

/// A header written before every RPC return (Go `rpc.Response`). It is used
/// internally but documented here as an aid to debugging, such as when
/// analyzing network traffic.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Response {
    /// Echoes that of the [`Request`].
    pub service_method: String,
    /// Echoes that of the request.
    pub seq: u64,
    /// Error, if any.
    pub error: String,
}

static REQUEST_TYPE: LazyLock<Type> = LazyLock::new(|| {
    Type::named(
        "net/rpc",
        "Request",
        &reflect::struct_of(&[
            reflect::StructField::new("ServiceMethod", Type::basic(Kind::String)),
            reflect::StructField::new("Seq", Type::basic(Kind::Uint64)),
        ]),
        Vec::new(),
    )
});

static RESPONSE_TYPE: LazyLock<Type> = LazyLock::new(|| {
    Type::named(
        "net/rpc",
        "Response",
        &reflect::struct_of(&[
            reflect::StructField::new("ServiceMethod", Type::basic(Kind::String)),
            reflect::StructField::new("Seq", Type::basic(Kind::Uint64)),
            reflect::StructField::new("Error", Type::basic(Kind::String)),
        ]),
        Vec::new(),
    )
});

impl ReflectType for Request {
    fn reflect_type() -> Type {
        REQUEST_TYPE.clone()
    }
}

impl Reflect for Request {
    fn to_value(&self) -> Value {
        Value::from_parts(
            &REQUEST_TYPE,
            &[
                Value::from_string(&Type::basic(Kind::String), self.service_method.as_bytes()),
                Value::from_uint(&Type::basic(Kind::Uint64), self.seq),
            ],
        )
    }
    fn from_value(v: &Value) -> Result<Self, reflect::Error> {
        Ok(Request {
            service_method: String::from_utf8_lossy(&v.field(0).string_bytes()).into_owned(),
            seq: v.field(1).uint(),
        })
    }
}

impl ReflectType for Response {
    fn reflect_type() -> Type {
        RESPONSE_TYPE.clone()
    }
}

impl Reflect for Response {
    fn to_value(&self) -> Value {
        Value::from_parts(
            &RESPONSE_TYPE,
            &[
                Value::from_string(&Type::basic(Kind::String), self.service_method.as_bytes()),
                Value::from_uint(&Type::basic(Kind::Uint64), self.seq),
                Value::from_string(&Type::basic(Kind::String), self.error.as_bytes()),
            ],
        )
    }
    fn from_value(v: &Value) -> Result<Self, reflect::Error> {
        Ok(Response {
            service_method: String::from_utf8_lossy(&v.field(0).string_bytes()).into_owned(),
            seq: v.field(1).uint(),
            error: String::from_utf8_lossy(&v.field(2).string_bytes()).into_owned(),
        })
    }
}

/// An error that has been returned from the remote side of the RPC
/// connection (Go `rpc.ServerError`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerError(pub String);

impl ServerError {
    /// Go `ServerError.Error`.
    pub fn error(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ServerError {}

/// The errors of this package. They are cloneable because a connection
/// failure is delivered to every pending call.
#[derive(Clone, Debug)]
pub enum Error {
    /// An error returned by the remote side ([`ServerError`]).
    Server(ServerError),
    /// `rpc.ErrShutdown`: the connection is shut down.
    Shutdown,
    /// An I/O or codec error.
    Io(Arc<io::Error>),
    /// Any other error, by its text (Go's `errors.New`).
    Message(String),
}

impl Error {
    /// An error with this text.
    pub fn new(text: impl Into<String>) -> Error {
        Error::Message(text.into())
    }

    /// Whether this is `io.EOF`.
    pub fn is_eof(&self) -> bool {
        matches!(self, Error::Io(e) if crate::io::is_eof(e))
    }

    /// Whether this is `io.ErrUnexpectedEOF`.
    pub fn is_unexpected_eof(&self) -> bool {
        matches!(self, Error::Io(e) if crate::io::is_unexpected_eof(e))
    }

    /// Whether this is [`ERR_SHUTDOWN`].
    pub fn is_shutdown(&self) -> bool {
        matches!(self, Error::Shutdown)
    }

    /// The [`ServerError`], if the remote side returned this error.
    pub fn as_server_error(&self) -> Option<&ServerError> {
        match self {
            Error::Server(e) => Some(e),
            _ => None,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Server(e) => e.fmt(f),
            Error::Shutdown => f.write_str("connection is shut down"),
            Error::Io(e) => e.fmt(f),
            Error::Message(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(Arc::new(e))
    }
}

impl From<crate::net::NetError> for Error {
    fn from(e: crate::net::NetError) -> Error {
        Error::Io(Arc::new(e.into_io()))
    }
}

/// Go `rpc.ErrShutdown`.
pub const ERR_SHUTDOWN: Error = Error::Shutdown;

/// Go's `io.ReadWriteCloser` as the rpc package uses it: the read and write
/// halves are serialized independently, so no interlocking is required, but
/// each half may be accessed concurrently, so the implementation should
/// protect against concurrent reads or concurrent writes.
pub trait ReadWriteCloser: Send + Sync {
    /// Reads into `buf`; `Ok(0)` is end of file.
    fn read(&self, buf: &mut [u8]) -> io::Result<usize>;
    /// Writes `buf`.
    fn write(&self, buf: &[u8]) -> io::Result<usize>;
    /// Closes the connection.
    fn close(&self) -> io::Result<()>;
}

impl<T: crate::net::Conn + ?Sized> ReadWriteCloser for T {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        crate::net::Conn::read(self, buf).map_err(crate::net::NetError::into_io)
    }
    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        crate::net::Conn::write(self, buf).map_err(crate::net::NetError::into_io)
    }
    fn close(&self) -> io::Result<()> {
        crate::net::Conn::close(self).map_err(crate::net::NetError::into_io)
    }
}

impl<T: ReadWriteCloser + ?Sized> ReadWriteCloser for Arc<T> {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        (**self).read(buf)
    }
    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        (**self).write(buf)
    }
    fn close(&self) -> io::Result<()> {
        (**self).close()
    }
}

impl ReadWriteCloser for Box<dyn crate::net::Conn> {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        ReadWriteCloser::read(&**self, buf)
    }
    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        ReadWriteCloser::write(&**self, buf)
    }
    fn close(&self) -> io::Result<()> {
        ReadWriteCloser::close(&**self)
    }
}

impl ReadWriteCloser for std::net::TcpStream {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        io::Read::read(&mut &*self, buf)
    }
    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        io::Write::write(&mut &*self, buf)
    }
    fn close(&self) -> io::Result<()> {
        self.shutdown(std::net::Shutdown::Both)
    }
}

#[cfg(unix)]
impl ReadWriteCloser for std::os::unix::net::UnixStream {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        io::Read::read(&mut &*self, buf)
    }
    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        io::Write::write(&mut &*self, buf)
    }
    fn close(&self) -> io::Result<()> {
        self.shutdown(std::net::Shutdown::Both)
    }
}

/// A `ClientCodec` implements writing of RPC requests and reading of RPC
/// responses for the client side of an RPC session (Go `rpc.ClientCodec`).
/// The client calls `write_request` to write a request to the connection and
/// calls `read_response_header` and `read_response_body` in pairs to read
/// responses. The client calls `close` when finished with the connection.
/// `read_response_body` may be called with an invalid [`Value`] (Go's nil
/// argument) to force the body of the response to be read and then discarded.
pub trait ClientCodec: Send + Sync {
    /// Go `WriteRequest`: `body` is the argument value.
    fn write_request(&self, r: &Request, body: &Value) -> Result<(), Error>;
    /// Go `ReadResponseHeader`.
    fn read_response_header(&self, r: &mut Response) -> Result<(), Error>;
    /// Go `ReadResponseBody`: `body` is a pointer to the reply, or invalid.
    fn read_response_body(&self, body: &Value) -> Result<(), Error>;
    /// Go `Close`.
    fn close(&self) -> Result<(), Error>;
}

/// A `ServerCodec` implements reading of RPC requests and writing of RPC
/// responses for the server side of an RPC session (Go `rpc.ServerCodec`).
/// The server calls `read_request_header` and `read_request_body` in pairs to
/// read requests from the connection, and it calls `write_response` to write
/// a response back. The server calls `close` when finished with the
/// connection. `read_request_body` may be called with an invalid [`Value`]
/// (Go's nil argument) to force the body of the request to be read and
/// discarded.
pub trait ServerCodec: Send + Sync {
    /// Go `ReadRequestHeader`.
    fn read_request_header(&self, r: &mut Request) -> Result<(), Error>;
    /// Go `ReadRequestBody`: `body` is a pointer to the argument, or invalid.
    fn read_request_body(&self, body: &Value) -> Result<(), Error>;
    /// Go `WriteResponse`: `body` is the reply value.
    fn write_response(&self, r: &Response, body: &Value) -> Result<(), Error>;
    /// Go `Close`; it can be called multiple times and must be idempotent.
    fn close(&self) -> Result<(), Error>;
}

/// Adapts a [`ReadWriteCloser`] to `std::io`.
#[derive(Clone)]
pub(crate) struct ConnIo(pub(crate) Arc<dyn ReadWriteCloser>);

impl io::Read for ConnIo {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl io::Write for ConnIo {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// If set, print log statements for internal and I/O errors.
pub(crate) const DEBUG_LOG: bool = false;
