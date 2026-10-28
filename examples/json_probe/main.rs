//! Line protocol used by `tools/json_check.py` for Go differential checks.
mod protocol;

use std::io::{self, BufRead, Write};

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        writeln!(out, "{}", protocol::respond(&line?))?;
    }
    Ok(())
}
