//! CGI (Common Gateway Interface, RFC 3875), after Go's `net/http/cgi`.
//!
//! The [`Handler`] runs an executable in a subprocess for each request; the
//! child-side functions [`request`], [`request_from_map`] and [`serve`] let a
//! program run as a CGI script. Note that CGI starts a new process for every
//! request, which is typically less efficient than a long-running server; the
//! package is intended for compatibility with existing systems.
mod child;
mod host;

pub use child::{request, request_from_map, serve, serve_with};
pub use host::Handler;
