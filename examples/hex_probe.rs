//! Line protocol used by `tools/hex_check.py` for Go differential checks.
use rust_stdlib::encoding::hex;
use std::io::{self, BufRead, Write};

fn from_hex(text: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut out = Vec::with_capacity(text.len() / 2);
    if text.len() & 1 != 0 {
        return Err("odd-length hex input".into());
    }
    for i in (0..text.len()).step_by(2) {
        let pair = &text.as_bytes()[i..i + 2];
        out.push(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?);
    }
    Ok(out)
}

fn status<E: std::fmt::Display>(result: &Result<(), E>) -> String {
    match result {
        Ok(()) => "ok".to_string(),
        Err(e) => e.to_string(),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line?;
        let (op, payload) = line.split_at(1);
        let payload = from_hex(payload)?;
        match op {
            "E" => {
                let encoded = hex::encode(&payload);
                assert_eq!(encoded.len(), hex::encoded_len(payload.len()));
                writeln!(out, "{}\t{}", encoded, encoded.len())?;
            }
            "D" => {
                let mut dst = Vec::new();
                let result = hex::decode_into(&payload, &mut dst);
                writeln!(
                    out,
                    "{}\t{}\t{}",
                    dst.len(),
                    hex::encode(&dst),
                    status(&result)
                )?;
            }
            "A" => {
                let mut dst = vec![0x7f];
                let result = hex::decode_into(&payload, &mut dst);
                writeln!(out, "{}\t{}", hex::encode(&dst), status(&result))?;
            }
            "S" => match std::str::from_utf8(&payload) {
                Err(_) => writeln!(out, "skip")?,
                Ok(text) => {
                    let mut bytes = Vec::new();
                    match hex::decode_into(text, &mut bytes) {
                        Ok(()) => writeln!(out, "ok\t{}", hex::encode(&bytes))?,
                        Err(e) => writeln!(out, "err\t{}\t{e}", hex::encode(&bytes))?,
                    }
                }
            },
            "P" => writeln!(out, "{}", hex::encode(hex::dump(&payload)))?,
            "W" => {
                let mut buf = Vec::new();
                let mut dumper = hex::Dumper::new(&mut buf);
                for chunk in payload.chunks(7) {
                    io::Write::write_all(&mut dumper, chunk)?;
                }
                dumper.close()?;
                writeln!(out, "{}", hex::encode(&buf))?;
            }
            _ => return Err("unknown operation".into()),
        }
    }
    Ok(())
}
