//! The Simple Mail Transfer Protocol client of Go's `net/smtp` (RFC 5321),
//! with the 8BITMIME, AUTH and STARTTLS extensions.
//!
//! The commands the [`Client`] sends, and the error texts it returns, are
//! Go's, checked byte for byte against Go with scripted servers.
//!
//! Differences from Go, all inexpressible without a TLS stack or crypto in the
//! root crate:
//!
//! - [`Client::start_tls`] and [`send_mail`] take a [`TlsConfig`]
//!   (the hook the `rust-stdlib-tls` backend implements) instead of
//!   `*tls.Config`, and [`Client::tls_connection_state`] returns the crate's
//!   [`TlsConnectionState`](crate::net::TlsConnectionState).
//! - [`cram_md5_auth`] takes the HMAC-MD5 function as an argument; pass one
//!   built on `rust_stdlib_crypto`.
//!
//! ```
//! use rust_stdlib::net::smtp::{plain_auth, Auth, ServerInfo};
//! let mut auth = plain_auth("", "user", "pass", "localhost");
//! let info = ServerInfo { name: "localhost".into(), tls: false, auth: vec![] };
//! let (mech, first) = auth.start(&info)?;
//! assert_eq!((mech.as_str(), first), ("PLAIN", b"\0user\0pass".to_vec()));
//! # Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
//! ```
mod auth;
mod client;

pub use crate::net::http::TlsConfig;
pub use auth::{
    cram_md5_auth, plain_auth, Auth, AuthError, CramMd5Auth, HmacMd5, PlainAuth, ServerInfo,
};
pub use client::{dial, send_mail, Client, DataWriter, Error, SharedConn};
