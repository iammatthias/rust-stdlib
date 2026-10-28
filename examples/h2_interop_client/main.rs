//! HTTP/2 interop client (h2c with prior knowledge) for `tools/h2_interop.py`.
//! Run: cargo run --offline --example h2_interop_client -- 127.0.0.1:PORT
//! Prints `ok NAME` or `FAIL NAME: reason` per scenario.
mod scenarios;

use rust_stdlib::net::{
    http::{client::Client, header::Protocols, transport::Transport},
    Dialer,
};
use std::sync::{
    atomic::{AtomicI64, Ordering},
    Arc,
};

fn main() {
    let addr = std::env::args().nth(1).expect("address");
    let dials = Arc::new(AtomicI64::new(0));
    let d2 = dials.clone();
    let dialer = Dialer::default();
    let mut p = Protocols::default();
    p.set_unencrypted_http2(true);
    let t = Transport {
        protocols: Some(p),
        dial_context: Some(Arc::new(move |ctx, network, address| {
            d2.fetch_add(1, Ordering::SeqCst);
            dialer
                .dial_context(ctx, network, address)
                .map_err(|e| Box::new(e) as _)
        })),
        ..Transport::default()
    };
    let client = Client {
        transport: Some(Arc::new(t)),
        timeout: rust_stdlib::time::SECOND * 60,
        ..Client::default()
    };
    let env = scenarios::Env {
        client,
        base: format!("http://{addr}"),
        dials,
    };
    let failed = scenarios::run_all(&env);
    std::process::exit(i32::from(failed > 0));
}
