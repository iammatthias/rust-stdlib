//! [`Config`] as the `net::http` TLS hook: `Transport::tls_client_config`,
//! `Server::tls_config`, `Server::serve_tls` and `httptest` all take a
//! [`TlsConfig`], and a [`Config`] serves as both the client and the server
//! configuration, as Go's `tls.Config` does.
use super::config::{load_x509_key_pair, Config};
use super::conn::client;
use super::dialing::Listener as TlsListener;
use rust_stdlib::net::{
    http::{BoxError, TlsConfig},
    Conn as NetConn, Listener,
};
use std::sync::Arc;

impl TlsConfig for Config {
    /// Go's `setupTLSConfig` plus `tls.NewListener`. Non-empty `cert_file` and
    /// `key_file` replace the certificates; a configuration that holds none
    /// needs them. A non-empty `next_protos` replaces `Config::next_protos`.
    fn server_listener(
        &self,
        l: Box<dyn Listener>,
        cert_file: &str,
        key_file: &str,
        next_protos: &[String],
    ) -> Result<Box<dyn Listener>, BoxError> {
        let mut config = self.clone();
        let has_certificate = !config.certificates.is_empty()
            || config.get_certificate.is_some()
            || config.get_config_for_client.is_some();
        if !cert_file.is_empty() || !key_file.is_empty() || !has_certificate {
            config.certificates = vec![load_x509_key_pair(cert_file, key_file)?];
        }
        if !next_protos.is_empty() {
            config.next_protos = next_protos.to_vec();
        }
        Ok(Box::new(TlsListener::new(l, Arc::new(config))))
    }

    /// Go's `tls.Client` plus `HandshakeContext`. The configuration's own
    /// `server_name` wins; `server_name` fills it in when empty.
    fn client_conn(
        &self,
        conn: Box<dyn NetConn>,
        server_name: &str,
        next_protos: &[String],
    ) -> Result<Box<dyn NetConn>, BoxError> {
        let mut config = self.clone();
        if config.server_name.is_empty() {
            config.server_name = server_name.to_owned();
        }
        if !next_protos.is_empty() {
            config.next_protos = next_protos.to_vec();
        }
        let conn = client(conn, Arc::new(config));
        if let Err(e) = conn.handshake() {
            let _ = conn.net_conn().close();
            return Err(Box::new(e));
        }
        Ok(Box::new(conn))
    }
}
