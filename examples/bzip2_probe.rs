//! Line protocol used by `tools/bzip2_check.py` for Go differential checks.
//! Each input line is a hex-encoded compressed stream; each output line is
//! `ok <hex>` or `err <hex> 0 <structural>`, where the first hex holds every
//! byte delivered before the error and `<structural>` is hex for the
//! `StructuralError` message, or `-` when the error is not structural (see
//! `tools/bzip2_oracle.go`).
use rust_stdlib::compress::bzip2::{Limits, Reader, StructuralError};
use std::io::{self, BufRead, BufWriter, Read, Write};

fn from_hex(text: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !text.len().is_multiple_of(2) {
        return Err("odd-length hex input".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&text[i..i + 2], 16)?))
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn run(input: &[u8]) -> String {
    let limits = Limits {
        max_output: 1 << 30,
        ..Limits::default()
    };
    let mut reader = Reader::with_limits(input, limits);
    let mut output = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return format!("ok {}", to_hex(&output)),
            Ok(count) => output.extend_from_slice(&buffer[..count]),
            Err(error) => {
                let structural = error
                    .get_ref()
                    .and_then(|inner| inner.downcast_ref::<StructuralError>())
                    .map_or_else(|| "-".to_string(), |e| to_hex(e.to_string().as_bytes()));
                return format!("err {} 0 {structural}", to_hex(&output));
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut out = BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let input = from_hex(line?.trim())?;
        writeln!(out, "{}", run(&input))?;
    }
    out.flush()?;
    Ok(())
}
