//! Go-shaped `net/http` client for `tools/gohttp_interop.go`.
//! Run: cargo run --offline --example http_client -- URL
//! Follows redirects with a cookie jar, then prints the status line and body
//! of the final response (`STATUS BODY`), decoding gzip transparently.
use rust_stdlib::net::http::{client::Client, cookiejar::Jar};
use std::sync::Arc;

fn main() {
    let url = std::env::args().nth(1).expect("usage: http_client URL");
    let client = Client {
        jar: Some(Arc::new(Jar::new(None).expect("jar"))),
        ..Client::default()
    };
    let mut last = String::new();
    for _ in 0..2 {
        let resp = match client.get(&url) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        };
        let body = resp
            .body
            .as_ref()
            .expect("body")
            .read_all()
            .unwrap_or_default();
        last = format!("{} {}", resp.status_code, String::from_utf8_lossy(&body));
    }
    print!("{last}");
}
