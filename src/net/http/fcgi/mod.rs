//! FastCGI (responder role only), after Go's `net/http/fcgi`.
//!
//! See <https://fast-cgi.github.io/> for the protocol. [`serve`] accepts
//! connections from a web server and runs an [`http::Handler`](super::Handler)
//! on each request; [`process_env`] returns the FastCGI variables the request
//! itself does not carry.
mod child;
mod records;

pub use child::{process_env, serve, ERR_CONN_CLOSED, ERR_REQUEST_ABORTED};
