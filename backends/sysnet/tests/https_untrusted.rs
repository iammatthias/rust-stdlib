//! Certificate validation fails closed: with the default configuration the
//! system roots are used, so a certificate they do not vouch for is rejected.
//! Own process, so no other test has pointed the system roots at the cert.
#![cfg(feature = "tls")]
use rust_stdlib::net::http::{handler::write_string, handler_func};
use rust_stdlib_sysnet::default_client;

#[test]
fn default_client_rejects_an_untrusted_certificate() {
    std::env::remove_var("SSL_CERT_FILE");
    std::env::remove_var("SSL_CERT_DIR");
    let server = rust_stdlib_tls::httptest::tls_server(handler_func(|w, _| {
        let _ = write_string(w, "must not be served");
    }))
    .unwrap();
    let err = default_client()
        .get(&format!("{}/x", server.url))
        .expect_err("self-signed certificate must be rejected");
    let text = err.to_string();
    assert!(
        text.contains("x509") && text.contains("certificate"),
        "{text}"
    );
}
