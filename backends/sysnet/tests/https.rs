//! HTTPS with the `tls` feature: Go's `DefaultClient` semantics.
//!
//! The system roots load once per process and honour `SSL_CERT_FILE` (as in
//! Go), so this file trusts the public httptest certificate that way, before
//! any TLS use. `https_untrusted.rs` covers the fail-closed case in its own
//! process.
#![cfg(feature = "tls")]
use rust_stdlib::encoding::base64;
use rust_stdlib::net::http::{handler::write_string, handler_func, httptest};
use rust_stdlib_sysnet::{default_client, default_transport, transport};
use std::sync::Once;

fn trust(server: &httptest::Server) {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let der = server.certificate.as_ref().expect("certificate");
        let b64 = base64::STANDARD.encode(der);
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        let path = std::env::temp_dir().join(format!("sysnet-https-{}.pem", std::process::id()));
        std::fs::write(&path, pem).unwrap();
        std::env::set_var("SSL_CERT_FILE", &path);
        std::env::remove_var("SSL_CERT_DIR");
    });
}

fn proto_handler() -> std::sync::Arc<dyn rust_stdlib::net::http::Handler> {
    handler_func(|w, r| {
        let _ = write_string(w, &format!("proto={} tls={}", r.proto, r.tls.is_some()));
    })
}

#[test]
fn default_client_does_https_with_system_roots() {
    let server = rust_stdlib_tls::httptest::tls_server(proto_handler()).unwrap();
    trust(&server);
    let resp = default_client().get(&format!("{}/x", server.url)).unwrap();
    assert_eq!(resp.status_code, 200);
    // No h2 on the server: ALPN falls back to HTTP/1.1.
    assert_eq!(resp.proto, "HTTP/1.1");
    assert_eq!(
        resp.body.unwrap().read_all().unwrap(),
        b"proto=HTTP/1.1 tls=true"
    );
}

#[test]
fn default_transport_negotiates_http2() {
    let mut server = httptest::Server::unstarted(proto_handler()).unwrap();
    server.enable_http2 = true;
    rust_stdlib_tls::httptest::start_tls(&mut server).unwrap();
    trust(&server);
    let client = rust_stdlib::net::http::client::Client {
        transport: Some(default_transport()),
        ..Default::default()
    };
    let resp = client.get(&format!("{}/x", server.url)).unwrap();
    assert_eq!(resp.proto, "HTTP/2.0");
    assert_eq!(
        resp.body.unwrap().read_all().unwrap(),
        b"proto=HTTP/2.0 tls=true"
    );
}

#[test]
fn transport_sets_go_tls_settings() {
    let t = transport();
    assert!(t.tls_client_config.is_some());
    assert!(t.force_attempt_http2);
    assert_eq!(
        t.tls_handshake_timeout,
        rust_stdlib::time::Duration::from_secs(10)
    );
}

#[test]
fn custom_root_config_replaces_the_defaults() {
    use rust_stdlib_tls::tls::{x509, Config};
    let server = rust_stdlib_tls::httptest::tls_server(proto_handler()).unwrap();
    let mut roots = x509::CertPool::new();
    roots.add_cert(x509::parse_certificate(server.certificate.as_ref().unwrap()).unwrap());
    let mut config = Config::new();
    config.root_cas = Some(roots);
    let client = rust_stdlib::net::http::client::Client {
        transport: Some(std::sync::Arc::new(
            rust_stdlib::net::http::transport::Transport {
                tls_client_config: Some(std::sync::Arc::new(config)),
                ..transport()
            },
        )),
        ..Default::default()
    };
    let resp = client.get(&format!("{}/x", server.url)).unwrap();
    assert_eq!(resp.status_code, 200);
}

#[test]
fn uses_default_tls_tells_defaults_from_a_caller_config() {
    assert!(rust_stdlib_sysnet::uses_default_tls(&transport()));
    let custom = rust_stdlib::net::http::transport::Transport {
        tls_client_config: Some(std::sync::Arc::new(rust_stdlib_tls::tls::Config::new())),
        ..transport()
    };
    assert!(!rust_stdlib_sysnet::uses_default_tls(&custom));
}
