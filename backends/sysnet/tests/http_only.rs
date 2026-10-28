//! Without the `tls` feature the crate is http-only and says so.
#![cfg(not(feature = "tls"))]
use rust_stdlib_sysnet::{default_client, transport};

#[test]
fn https_is_an_explicit_error() {
    assert!(transport().tls_client_config.is_none());
    // The error comes after the dial, so give it something to connect to.
    let ln = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let err = default_client()
        .get(&format!("https://{}/", ln.local_addr().unwrap()))
        .unwrap_err()
        .to_string();
    assert!(err.contains("TLS backend"), "{err}");
}
