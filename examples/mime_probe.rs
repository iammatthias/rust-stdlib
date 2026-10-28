//! Line protocol used by `tools/mime_check.py` for Go differential checks.
//! Requests are `MODE:hex`; responses match `tools/mime_oracle.go`.
use rust_stdlib::mime::{
    add_extension_type, extensions_by_type, format_media_type, parse_media_type, type_by_extension,
    ERR_INVALID_MEDIA_PARAMETER,
};
use std::collections::BTreeMap;
use std::error::Error;
use std::io::{self, BufRead, Write};

fn from_hex(text: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if !text.len().is_multiple_of(2) {
        return Err("odd-length hex input".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&text[i..i + 2], 16)?))
        .collect()
}

fn hex(text: &str) -> String {
    text.bytes().map(|b| format!("{b:02x}")).collect()
}

fn handle(mode: &str, data: &[u8]) -> Result<String, Box<dyn Error>> {
    let text = std::str::from_utf8(data)?;
    Ok(match mode {
        "P" => match parse_media_type(text) {
            (media_type, Ok(params)) => {
                let parts: Vec<String> = params
                    .iter()
                    .map(|(key, value)| format!("{}={}", hex(key), hex(value)))
                    .collect();
                format!("ok\t{}\t{}", hex(&media_type), parts.join(";"))
            }
            (media_type, Err(error)) if error == ERR_INVALID_MEDIA_PARAMETER => {
                format!("invalid\t{}", hex(&media_type))
            }
            (_, Err(_)) => "err".into(),
        },
        "F" => {
            let fields: Vec<&str> = text.split('\0').collect();
            let mut params = BTreeMap::new();
            for pair in fields[1..].chunks_exact(2) {
                params.insert(pair[0].to_owned(), pair[1].to_owned());
            }
            hex(&format_media_type(fields[0], &params).unwrap_or_default())
        }
        "T" => hex(&type_by_extension(text).unwrap_or_default()),
        "E" => match extensions_by_type(text) {
            Ok(list) => {
                let parts: Vec<String> = list.iter().map(|ext| hex(ext)).collect();
                format!("ok\t{}", parts.join(","))
            }
            Err(_) => "err".into(),
        },
        "A" => {
            let (extension, media_type) = text.split_once('\0').unwrap_or((text, ""));
            match add_extension_type(extension, media_type) {
                Ok(()) => "ok".into(),
                Err(_) => "err".into(),
            }
        }
        _ => return Err(format!("unknown mode {mode}").into()),
    })
}

fn main() -> Result<(), Box<dyn Error>> {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line?;
        let (mode, payload) = line.split_once(':').ok_or("bad request")?;
        writeln!(out, "{}", handle(mode, &from_hex(payload)?)?)?;
    }
    out.flush()?;
    Ok(())
}
