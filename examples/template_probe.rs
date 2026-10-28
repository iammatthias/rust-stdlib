//! Line protocol used by `tools/template_check.py` for Go differential checks.
#[path = "common/template_harness.rs"]
mod harness;

use std::io::{self, BufRead, Write};

fn main() -> io::Result<()> {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        writeln!(out, "{}", harness::handle_line(&line?))?;
    }
    out.flush()
}
