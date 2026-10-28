//! HTTP/2 over TLS (ALPN `h2`) interop server for `tools/h2_interop.py`.
//! Run: cargo run --offline --example h2_interop_server -- 127.0.0.1:0
//! Prints `listening ADDRESS`; exits when stdin reaches end of file.
#[path = "../../../examples/h2_interop_server/handlers.rs"]
mod handlers;

use rust_stdlib::{
    encoding::hex,
    net::{self, http::server::Server},
};
use rust_stdlib_tls::tls::{Certificate, Config, PrivateKey};
use std::{io::Read, sync::Arc};

fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:0".into());
    let cert = hex::decode(include_str!("../tests/fixtures/server.hex").trim()).unwrap();
    let key = hex::decode(include_str!("../tests/fixtures/server-key.hex").trim()).unwrap();
    let mut server = Server {
        handler: Some(handlers::mux()),
        ..Server::default()
    };
    let mut config = Config::new();
    config.certificates = vec![Certificate {
        certificate: vec![cert],
        private_key: Some(PrivateKey::Pkcs8(key)),
        ..Certificate::default()
    }];
    server.tls_config = Some(Arc::new(config));
    let ln = net::listen("tcp", &addr).expect("listen");
    println!("listening {}", ln.addr().unwrap());
    let s2 = server.clone();
    std::thread::spawn(move || {
        let _ = s2.serve_tls(ln, "", "");
    });
    let mut sink = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut sink);
    let _ = server.close();
}
