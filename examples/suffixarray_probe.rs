//! Line protocol used by `tools/suffixarray_check.py`; mirrors `tools/suffixarray_oracle.go`.
//! Requests are `W:<hex>`, `R:<hex>`, `L:<hex>:<hex>:<n>` and `F:<hex>:<hex>:<n>`,
//! and each answer is one line with the same format as the Go oracle.
use rust_stdlib::index::suffixarray::Index;
use rust_stdlib::regexp;
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

/// Serializes `index` as the oracle does for a read index.
fn written(index: &Index) -> String {
    let mut buf = Vec::new();
    match index.write(&mut buf) {
        Ok(()) => to_hex(&buf),
        Err(e) => format!("err:{e}"),
    }
}

fn process(line: &str) -> Result<String, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = line.split(':').collect();
    match parts[0] {
        "W" => {
            let index = Index::new(from_hex(parts[1])?);
            Ok(written(&index))
        }
        "R" => {
            let data = from_hex(parts[1])?;
            let mut index = Index::default();
            match index.read(&mut data.as_slice()) {
                Err(e) => Ok(format!("err:{e}")),
                Ok(()) => {
                    let mut buf = Vec::new();
                    index.write(&mut buf)?;
                    Ok(format!("ok:{}", to_hex(&buf)))
                }
            }
        }
        "L" => {
            let n: isize = parts[3].parse()?;
            let index = Index::new(from_hex(parts[1])?);
            let found = index.lookup(&from_hex(parts[2])?, n);
            if found.is_empty() {
                return Ok("none".to_string());
            }
            Ok(found
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(","))
        }
        "F" => {
            let n: isize = parts[3].parse()?;
            let Ok(pattern) = String::from_utf8(from_hex(parts[2])?) else {
                return Ok("regex-error".to_string());
            };
            let Ok(re) = regexp::compile(&pattern) else {
                return Ok("regex-error".to_string());
            };
            let index = Index::new(from_hex(parts[1])?);
            let found = index.find_all_index(&re, n);
            if found.is_empty() {
                return Ok("none".to_string());
            }
            Ok(found
                .iter()
                .map(|(s, e)| format!("{s}-{e}"))
                .collect::<Vec<_>>()
                .join(","))
        }
        op => Err(format!("bad op {op}").into()),
    }
}

fn main() -> io::Result<()> {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line?;
        let answer = match process(&line) {
            Ok(answer) => answer,
            Err(e) => format!("error:{e}"),
        };
        writeln!(out, "{answer}")?;
    }
    Ok(())
}
