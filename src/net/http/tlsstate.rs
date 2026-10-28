//! The TLS connection facts `Request.TLS` and `Response.TLS` carry. The core
//! crate has no TLS stack; the `rust-stdlib-tls` backend fills this in.

/// A subset of Go's `tls.ConnectionState`.
pub use crate::net::TlsConnectionState as ConnectionState;

use super::header::BoxError;
use crate::net::{Conn, Listener};

/// The TLS configuration hook for `Server.TLSConfig` and
/// `Transport.TLSClientConfig`. The core crate has no TLS stack; the
/// `rust-stdlib-tls` backend implements this trait.
pub trait TlsConfig: Send + Sync {
    /// Server side: wraps `l` so accepted connections run the TLS handshake
    /// (Go's `setupTLSConfig` plus `tls.NewListener`). `cert_file` and
    /// `key_file` may be empty when the configuration already holds a
    /// certificate. `next_protos` lists the ALPN protocols to offer.
    fn server_listener(
        &self,
        l: Box<dyn Listener>,
        cert_file: &str,
        key_file: &str,
        next_protos: &[String],
    ) -> Result<Box<dyn Listener>, BoxError>;

    /// Client side: performs the TLS handshake over `conn`, verifying
    /// `server_name` (Go's `tls.Client` plus `HandshakeContext`).
    fn client_conn(
        &self,
        conn: Box<dyn Conn>,
        server_name: &str,
        next_protos: &[String],
    ) -> Result<Box<dyn Conn>, BoxError>;
}
