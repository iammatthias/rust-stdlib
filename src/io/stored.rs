//! A cloneable snapshot of an `io::Error`.
//!
//! Go stores an error value and returns the same value from every later call
//! (a pipe's close error, a `bufio.Writer`'s sticky error). `io::Error` is not
//! `Clone`, so the first error is kept and each retrieval builds a new
//! `io::Error` with the same kind and text that still matches sentinels
//! ([`Error::is`]) and keeps the original reachable through `source`.

use super::Error;
use std::fmt;
use std::io;
use std::sync::Arc;

/// A stored error that can be returned any number of times.
#[derive(Clone, Debug)]
pub(crate) enum Stored {
    Sentinel(Error),
    Other(io::ErrorKind, Arc<io::Error>),
}

#[derive(Debug)]
struct Shared(Arc<io::Error>);

impl fmt::Display for Shared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl std::error::Error for Shared {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}

impl Stored {
    pub(crate) fn new(err: io::Error) -> Stored {
        for s in [
            Error::Eof,
            Error::ClosedPipe,
            Error::NoProgress,
            Error::ShortBuffer,
            Error::ShortWrite,
            Error::UnexpectedEof,
        ] {
            if s.is(&err) {
                return Stored::Sentinel(s);
            }
        }
        Stored::Other(err.kind(), Arc::new(err))
    }

    pub(crate) fn get(&self) -> io::Error {
        match self {
            Stored::Sentinel(s) => (*s).into(),
            Stored::Other(kind, e) => io::Error::new(*kind, Shared(e.clone())),
        }
    }
}
