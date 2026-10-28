//! Go's `crypto/tls` over Rustls.
//!
//! The record layer, handshake, key schedule, session resumption and QUIC
//! handshake belong to Rustls (docs/adr/0002); there is no first-party TLS
//! state machine and no first-party cryptography here. This module is the Go
//! API shape: [`Config`] (every field), [`Conn`], [`ConnectionState`],
//! [`client`]/[`server`]/[`dial`]/[`listen`], the certificate and session types,
//! [`QUICConn`], and Go's constants, `String` tables and error texts.
//!
//! Options Rustls refuses on purpose are rejected with explicit errors, never
//! silently ignored (TLS 1.0/1.1, renegotiation, static-RSA and CBC/RC4/3DES
//! suites, Encrypted Client Hello with the ring provider, externally supplied
//! session ticket keys). `Config::insecure_skip_verify` exists only because
//! Go exposes it; see its documentation before using it.
#[macro_use]
mod consts;
mod config;
mod conn;
mod dialing;
mod error;
mod glue;
mod hook;
mod quic;
mod session;
mod system_roots;
mod tables;
pub mod x509;

pub use config::*;
pub use conn::*;
pub use consts::*;
pub use dialing::*;
pub use error::*;
pub use quic::*;
pub use session::*;
