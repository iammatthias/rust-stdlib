//! The error value shared by `database/sql` and `database/sql/driver`.
//!
//! Go compares sentinel errors by identity and wraps them with `%w`;
//! [`Error::is`] is `errors.Is`. Sentinels are constants compared by their
//! unique text, errors made by [`Error::new`] compare by allocation, so two
//! errors with equal text stay distinct as with `errors.New`.
use crate::context;
use std::{error, fmt, sync::Arc};

/// An error value with Go's identity and wrapping semantics.
#[derive(Clone)]
pub struct Error(Repr);

#[derive(Clone)]
enum Repr {
    Sentinel(&'static str),
    Context(context::Error),
    Dyn(Arc<Node>),
}

struct Node {
    msg: String,
    source: Option<Error>,
}

/// `std::result::Result<T, Error>`: the return type of the [`driver`](super::driver)
/// traits, exported there as `driver::Res` because `driver::Result` is Go's
/// result trait.
pub type Res<T> = std::result::Result<T, Error>;

impl Error {
    /// A package-level error variable such as `driver.ErrBadConn`.
    pub(crate) const fn sentinel(text: &'static str) -> Error {
        Error(Repr::Sentinel(text))
    }

    /// Go's `errors.New`: a new error that equals only itself and its clones.
    pub fn new(msg: impl Into<String>) -> Error {
        Error(Repr::Dyn(Arc::new(Node {
            msg: msg.into(),
            source: None,
        })))
    }

    /// Go's `fmt.Errorf("...%w", source)`: `msg` is the complete text and
    /// `source` is reachable through [`Error::unwrap`] and [`Error::is`].
    pub fn wrap(msg: impl Into<String>, source: Error) -> Error {
        Error(Repr::Dyn(Arc::new(Node {
            msg: msg.into(),
            source: Some(source),
        })))
    }

    /// Go's `errors.Unwrap`.
    pub fn unwrap(&self) -> Option<&Error> {
        match &self.0 {
            Repr::Dyn(node) => node.source.as_ref(),
            _ => None,
        }
    }

    /// Go's `errors.Is`: whether `target` is this error or any error it wraps.
    pub fn is(&self, target: &Error) -> bool {
        let mut current = Some(self);
        while let Some(err) = current {
            if err == target {
                return true;
            }
            current = err.unwrap();
        }
        false
    }

    /// The context error this error is or wraps, if any.
    pub fn context_error(&self) -> Option<context::Error> {
        let mut current = Some(self);
        while let Some(err) = current {
            if let Repr::Context(e) = &err.0 {
                return Some(*e);
            }
            current = err.unwrap();
        }
        None
    }
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (Repr::Sentinel(a), Repr::Sentinel(b)) => a == b,
            (Repr::Context(a), Repr::Context(b)) => a == b,
            (Repr::Dyn(a), Repr::Dyn(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Repr::Sentinel(text) => f.write_str(text),
            // Go's texts, not this crate's `context::Error` Display.
            Repr::Context(context::Error::Canceled) => f.write_str("context canceled"),
            Repr::Context(context::Error::DeadlineExceeded) => {
                f.write_str("context deadline exceeded")
            }
            Repr::Dyn(node) => f.write_str(&node.msg),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error({:?})", self.to_string())
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        self.unwrap().map(|e| e as &(dyn error::Error + 'static))
    }
}

impl From<context::Error> for Error {
    fn from(e: context::Error) -> Self {
        Error(Repr::Context(e))
    }
}

/// Go's `io.EOF` as returned by `driver.Rows.Next` and `NextResultSet`.
pub const EOF: Error = Error::sentinel("EOF");

/// Go's `driver.ErrSkip`.
pub const ERR_SKIP: Error = Error::sentinel("driver: skip fast-path; continue as if unimplemented");
/// Go's `driver.ErrBadConn`.
pub const ERR_BAD_CONN: Error = Error::sentinel("driver: bad connection");
/// Go's `driver.ErrRemoveArgument`.
pub const ERR_REMOVE_ARGUMENT: Error = Error::sentinel("driver: remove argument from query");
/// Go's `sql.ErrNoRows`.
pub const ERR_NO_ROWS: Error = Error::sentinel("sql: no rows in result set");
/// Go's `sql.ErrConnDone`.
pub const ERR_CONN_DONE: Error = Error::sentinel("sql: connection is already closed");
/// Go's `sql.ErrTxDone`.
pub const ERR_TX_DONE: Error =
    Error::sentinel("sql: transaction has already been committed or rolled back");
pub(crate) const ERR_DB_CLOSED: Error = Error::sentinel("sql: database is closed");
pub(crate) const ERR_ROWS_CLOSED: Error = Error::sentinel("sql: Rows are closed");
