//! Line protocol used by `tools/uuid_check.py`; mirrors `tools/uuid_oracle.go`.
//! Requests are `U:<hex>`, `M:<hex>`, `C:<hex>:<hex>`, `P:<hex>`, `G4:<n>` and
//! `G7:<n>`, and each answer is one line with the same format as the Go oracle.
use rust_stdlib::uuid::{self, UUID};
use std::io::{self, BufRead, Write};

fn from_hex(text: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !text.len().is_multiple_of(2) {
        return Err("odd-length hex input".into());
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for i in (0..text.len()).step_by(2) {
        out.push(u8::from_str_radix(&text[i..i + 2], 16)?);
    }
    Ok(out)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Copies up to 16 bytes into a UUID, as the Go oracle's toUUID does.
fn to_uuid(bytes: &[u8]) -> UUID {
    let mut u = [0u8; 16];
    let n = bytes.len().min(16);
    u[..n].copy_from_slice(&bytes[..n]);
    UUID(u)
}

fn process(line: &str) -> Result<String, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = line.split(':').collect();
    match parts[0] {
        "U" => {
            let mut u = UUID::default();
            match u.unmarshal_text(&from_hex(parts[1])?) {
                Ok(()) => Ok(to_hex(&u.0)),
                Err(_) => Ok("err".to_string()),
            }
        }
        "M" => {
            let u = to_uuid(&from_hex(parts[1])?);
            let marshaled = u.marshal_text();
            let mut appended = b"pre:".to_vec();
            u.append_text(&mut appended);
            Ok(format!(
                "s:{}|m:{}|a:{}",
                u,
                to_hex(&marshaled),
                to_hex(&appended)
            ))
        }
        "C" => {
            let a = to_uuid(&from_hex(parts[1])?);
            let b = to_uuid(&from_hex(parts[2])?);
            Ok(a.compare(b).to_string())
        }
        "P" => {
            let text = String::from_utf8(from_hex(parts[1])?);
            let parsed = match text {
                Ok(text) => std::panic::catch_unwind(|| uuid::must_parse(&text).to_string()).ok(),
                Err(_) => None,
            };
            Ok(parsed.unwrap_or_else(|| "panic".to_string()))
        }
        "G4" | "G7" => {
            let n: usize = parts[1].parse()?;
            let items: Vec<String> = (0..n)
                .map(|_| {
                    let u = if parts[0] == "G4" {
                        uuid::new_v4()
                    } else {
                        uuid::new_v7()
                    };
                    to_hex(&u.0)
                })
                .collect();
            Ok(items.join(","))
        }
        op => Err(format!("bad op {op}").into()),
    }
}

fn main() -> io::Result<()> {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let answer = match process(&line?) {
            Ok(answer) => answer,
            Err(e) => format!("error:{e}"),
        };
        writeln!(out, "{answer}")?;
    }
    Ok(())
}
