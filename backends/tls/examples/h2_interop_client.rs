//! HTTP/2 over TLS (ALPN `h2`) interop client for `tools/h2_interop.py`.
//! Run: cargo run --offline --example h2_interop_client -- 127.0.0.1:PORT CA.HEX
//! Prints `ok NAME` or `FAIL NAME: reason` per scenario.
#[path = "../../../examples/h2_interop_client/scenarios.rs"]
mod scenarios;

use rust_stdlib::{
    encoding::hex,
    net::{
        http::{client::Client, transport::Transport},
        Dialer,
    },
};
use rust_stdlib_tls::tls::{x509, Config};
use std::sync::{
    atomic::{AtomicI64, Ordering},
    Arc,
};

fn main() {
    let mut args = std::env::args().skip(1);
    let addr = args.next().expect("address");
    let ca_path = args.next().expect("CA hex file");
    let ca = hex::decode(std::fs::read_to_string(ca_path).unwrap().trim()).unwrap();
    let port = addr.rsplit(':').next().unwrap().to_owned();
    let dials = Arc::new(AtomicI64::new(0));
    let d2 = dials.clone();
    let dialer = Dialer::default();
    let mut t = Transport::default();
    let mut roots = x509::CertPool::new();
    roots.add_cert(x509::parse_certificate(&ca).unwrap());
    let mut tls = Config::new();
    tls.root_cas = Some(roots);
    t.tls_client_config = Some(Arc::new(tls));
    t.force_attempt_http2 = true;
    t.dial_context = Some(Arc::new(move |ctx, network, address| {
        d2.fetch_add(1, Ordering::SeqCst);
        dialer
            .dial_context(ctx, network, address)
            .map_err(|e| Box::new(e) as _)
    }));
    let client = Client {
        transport: Some(Arc::new(t)),
        timeout: rust_stdlib::time::SECOND * 60,
        ..Client::default()
    };
    let env = scenarios::Env {
        client,
        base: format!("https://localhost:{port}"),
        dials,
    };
    let failed = scenarios::run_all(&env);
    std::process::exit(i32::from(failed > 0));
}
