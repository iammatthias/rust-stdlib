//! Line protocol used by `tools/mail_check.py` for Go differential checks.
//! Requests are `MODE:hex`; responses match `tools/mail_oracle.go`.
use rust_stdlib::mime::{WordDecoder, WordEncoder};
use rust_stdlib::net::mail::{self, Address, Error};
use std::io::{self, BufRead, Read, Write};

fn from_hex(text: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !text.len().is_multiple_of(2) {
        return Err("odd-length hex input".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&text[i..i + 2], 16)?))
        .collect()
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

fn address(a: &Address) -> String {
    format!(
        "{},{},{}",
        hex(&a.name),
        hex(&a.address),
        hex(a.to_string())
    )
}

fn handle(mode: &str, data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    if mode == "M" {
        return Ok(match mail::read_message(data) {
            Ok(mut message) => {
                let mut body = Vec::new();
                message.body.read_to_end(&mut body)?;
                let fields: Vec<String> = message
                    .header
                    .iter()
                    .map(|(key, values)| {
                        let values: Vec<String> = values.iter().map(hex).collect();
                        format!("{}={}", hex(key), values.join(","))
                    })
                    .collect();
                format!("ok\t{}\t{}", fields.join(";"), hex(body))
            }
            Err(_) => "err".into(),
        });
    }
    let text = std::str::from_utf8(data)?;
    Ok(match mode {
        "A" => match mail::parse_address(text) {
            Ok(a) => format!("ok\t{}", address(&a)),
            Err(_) => "err".into(),
        },
        "L" => match mail::parse_address_list(text) {
            Ok(list) => {
                let list: Vec<String> = list.iter().map(address).collect();
                format!("ok\t{}", list.join(";"))
            }
            Err(_) => "err".into(),
        },
        "F" => {
            let (name, address) = text.split_once('\0').unwrap_or((text, ""));
            let a = Address {
                name: name.into(),
                address: address.into(),
            };
            hex(a.to_string())
        }
        "D" => match mail::parse_date(text) {
            Ok(date) => format!(
                "ok\t{}\t{}\t{}",
                date.unix(),
                date.nanosecond(),
                date.zone().1
            ),
            Err(_) => "err".into(),
        },
        "G" | "H" | "T" => {
            let (key, raw) = text.split_once('\0').unwrap_or((text, ""));
            let message = match mail::read_message(raw.as_bytes()) {
                Ok(message) => message,
                Err(_) => return Ok("err".into()),
            };
            match mode {
                "G" => match message.header.get(key) {
                    None | Some("") => "none".into(),
                    Some(value) => format!("ok\t{}", hex(value)),
                },
                "T" => match message.header.date() {
                    Ok(date) => format!(
                        "ok\t{}\t{}\t{}",
                        date.unix(),
                        date.nanosecond(),
                        date.zone().1
                    ),
                    Err(Error::HeaderNotPresent) => "missing".into(),
                    Err(_) => "err".into(),
                },
                _ => match message.header.address_list(key) {
                    Ok(list) => {
                        let list: Vec<String> = list.iter().map(address).collect();
                        format!("ok\t{}", list.join(";"))
                    }
                    Err(Error::HeaderNotPresent) => "missing".into(),
                    Err(_) => "err".into(),
                },
            }
        }
        "W" => match WordDecoder::new().decode_header(text) {
            Ok(decoded) => format!("ok\t{}", hex(decoded)),
            Err(_) => "err".into(),
        },
        "B" => hex(WordEncoder::B.encode("utf-8", text)),
        "Q" => hex(WordEncoder::Q.encode("utf-8", text)),
        _ => return Err(format!("unknown mode {mode}").into()),
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
