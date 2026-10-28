//! HTTP/2 interop server (h2c with prior knowledge) for `tools/h2_interop.py`.
//! Run: cargo run --offline --example h2_interop_server -- 127.0.0.1:0
//! Prints `listening ADDRESS`; exits when stdin reaches end of file.
mod handlers;

use rust_stdlib::net::{
    self,
    http::{header::Protocols, server::Server},
};
use std::{io::Read, sync::Arc};

fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:0".into());
    let ln = net::listen("tcp", &addr).expect("listen");
    let mut p = Protocols::default();
    p.set_http1(true);
    p.set_unencrypted_http2(true);
    let server = Server {
        handler: Some(handlers::mux()),
        protocols: Some(p),
        ..Server::default()
    };
    println!("listening {}", ln.addr().unwrap());
    let s2 = server.clone();
    std::thread::spawn(move || {
        let _ = s2.serve(ln);
    });
    let mut sink = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut sink);
    let _ = server.close();
    let _ = Arc::new(());
}
