//! TLS test servers for `net::http::httptest`: Go's `httptest.NewTLSServer`
//! and `Server.StartTLS`, serving with a [`tls::Config`](crate::tls::Config).
use crate::tls::{x509, Certificate, Config, PrivateKey};
use rust_stdlib::{
    encoding::hex,
    net::http::{httptest, BoxError, Handler, Protocols, TlsConfig},
};
use std::sync::Arc;

const LOCALHOST_CERT: &str = include_str!("httptest_cert.hex");
const LOCALHOST_KEY: &str = include_str!("httptest_key.hex");

/// Go's `httptest.NewTLSServer`: a started HTTPS test server presenting the
/// public, test-only certificate for 127.0.0.1, ::1, example.com and
/// *.example.com.
pub fn tls_server(handler: Arc<dyn Handler>) -> Result<httptest::Server, BoxError> {
    let mut s = httptest::Server::unstarted(handler)?;
    start_tls(&mut s)?;
    Ok(s)
}

/// Go's `Server.StartTLS`. Go panics when the server was already started;
/// here that is an error. `Server::client` trusts exactly the certificate.
pub fn start_tls(s: &mut httptest::Server) -> Result<(), BoxError> {
    if !s.url.is_empty() {
        return Err("httptest: StartTLS called on a started server".into());
    }
    if s.enable_http2 && s.config.protocols.is_none() {
        // Go sets TLS.NextProtos to just "h2".
        let mut p = Protocols::default();
        p.set_http2(true);
        s.config.protocols = Some(p);
    }
    let cert = hex::decode(LOCALHOST_CERT.trim())?;
    let key = hex::decode(LOCALHOST_KEY.trim())?;
    let mut server_cfg = Config::new();
    server_cfg.certificates = vec![Certificate {
        certificate: vec![cert.clone()],
        private_key: Some(PrivateKey::Pkcs8(key)),
        ..Certificate::default()
    }];
    let mut roots = x509::CertPool::new();
    roots.add_cert(x509::parse_certificate(&cert)?);
    let mut client_cfg = Config::new();
    client_cfg.root_cas = Some(roots);
    let Some(ln) = s.listener.take() else {
        return Err("httptest: Server has no Listener".into());
    };
    let addr = ln.addr().map(|a| a.to_string()).unwrap_or_default();
    let alpn: Vec<String> = if s.enable_http2 {
        vec!["h2".to_owned()]
    } else {
        Vec::new()
    };
    let tls_ln = server_cfg.server_listener(ln, "", "", &alpn)?;
    s.url = format!("https://{addr}");
    s.certificate = Some(cert);
    s.tls = Some(Arc::new(server_cfg));
    s.set_client_tls(Arc::new(client_cfg));
    s.start_common(tls_ln);
    Ok(())
}
