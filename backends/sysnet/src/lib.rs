//! Runs `rust-stdlib`'s `net/http` over `rust-stdlib-sys` sockets.
//!
//! The root crate forbids unsafe code and `std` cannot set `SO_KEEPALIVE`, so
//! its default transport dials without TCP keep-alive, while Go's
//! `http.DefaultTransport` dials with `KeepAlive: 30 * time.Second`.
//! `rust_stdlib_sys::net::Dialer` can set it, but the sys crate may not depend
//! on the root crate (ADR 0004) and its connections do not implement the root
//! [`net::Conn`](rust_stdlib::net::Conn). This crate is the glue (ADR 0006):
//!
//! - [`Conn`] wraps a sys connection as a root `net::Conn`;
//! - [`dial_context`] turns a sys `Dialer` into a `Transport::dial_context`
//!   hook;
//! - [`transport`], [`default_transport`] and [`default_client`] mirror Go's
//!   `http.DefaultTransport` and `http.DefaultClient`, field by field, with the
//!   30 s keep-alive.
//!
//! # HTTPS and the `tls` feature
//!
//! Go's `DefaultTransport` does HTTPS, so with the `tls` feature (on by
//! default) [`transport`], [`default_transport`] and [`default_client`] set
//! `tls_client_config` to the `rust-stdlib-tls` defaults: system roots,
//! verification, `h2` through ALPN, 10 s handshake timeout. The TLS backend
//! handshakes on top of the [`Conn`] the sys dialer returns.
//!
//! With `default-features = false` the crate depends only on first-party code
//! and is **http-only**: an `https` request returns an error. Set
//! `tls_client_config` on the transport yourself to enable HTTPS.
#![forbid(unsafe_code)]

mod conn;
mod dial;
mod error;
mod transport;

pub use conn::Conn;
pub use dial::{dial_context, ContextAdapter};
pub use error::net_error;
pub use transport::{
    default_client, default_transport, transport, uses_default_tls, KEEP_ALIVE, TIMEOUT,
};
