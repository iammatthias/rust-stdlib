//! Line protocol used by `tools/jsontext_check.py` for the Go differential of
//! `encoding/json/jsontext`.
mod protocol;

use std::io::{self, BufRead, Write};

fn main() -> io::Result<()> {
    // Documents nested to Go's depth limit of 10000 need more than the
    // default stack of a spawned thread.
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(run)
        .expect("spawn")
        .join()
        .expect("probe thread")
}

fn run() -> io::Result<()> {
    std::panic::set_hook(Box::new(|_| {}));
    let stdin = io::stdin();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        writeln!(out, "{}", protocol::respond_safely(&line?))?;
    }
    Ok(())
}
