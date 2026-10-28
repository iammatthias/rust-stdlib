//! Line-oriented differential probe for Go-compatible time durations.
//! Run with: cargo run --offline --locked --example duration_probe
use rust_stdlib::time::Duration;
use std::io::{self, BufRead};

fn main() -> io::Result<()> {
    for line in io::stdin().lock().lines() {
        let input = line?;
        let input = input.trim_end_matches('\r');
        match input.parse::<Duration>() {
            Ok(duration) => println!(
                "{{\"ok\":true,\"nanos\":{},\"string\":\"{}\"}}",
                duration.as_nanos(),
                duration
            ),
            Err(_) => println!("{{\"ok\":false}}"),
        }
    }
    Ok(())
}
