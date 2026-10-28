//! Line protocol used by `tools/jsonv2_check.py` for the Go differential of
//! `encoding/json/v2`.
mod protocol;

use std::io::{self, BufRead, Write};

fn main() -> io::Result<()> {
    std::panic::set_hook(Box::new(|_| {}));
    let stdin = io::stdin();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        writeln!(out, "{}", protocol::respond(&line?))?;
    }
    Ok(())
}
