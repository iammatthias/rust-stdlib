//! Hex/tab line driver for the Go base64 parity checker.
use rust_stdlib::encoding::base64;
use std::io::{self, BufRead};

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let encodings = [
        base64::STANDARD,
        base64::URL_SAFE,
        base64::STANDARD_NO_PAD,
        base64::URL_SAFE_NO_PAD,
        base64::STANDARD.strict(),
        base64::STANDARD.with_padding(None)?,
    ];
    for line in io::stdin().lock().lines() {
        let line = line?;
        if let Some(request) = line.strip_prefix('N') {
            let (index, n) = request.split_once(':').ok_or("bad length request")?;
            let encoding = encodings[index.parse::<usize>()?];
            let n: usize = n.parse()?;
            println!("{}\t{}", encoding.encoded_len(n), encoding.decoded_len(n));
            continue;
        }
        if let Some(request) = line.strip_prefix('P') {
            let (index, encoded_hex) = request.split_once(':').ok_or("bad partial request")?;
            let encoding = encodings[index.parse::<usize>()?];
            let input = from_hex(encoded_hex)?;
            let mut out = Vec::new();
            let status = match encoding.decode_into(&input, &mut out) {
                Ok(()) => "ok".to_string(),
                Err(error) => format!("err:{}", error.offset()),
            };
            let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
            println!("{}:{hex}:{status}", out.len());
            continue;
        }
        if let Some(request) = line.strip_prefix('D') {
            let (index, encoded_hex) = request.split_once(':').ok_or("bad decode request")?;
            let index: usize = index.parse()?;
            let mut bytes = Vec::new();
            let result = encodings[index].decode_into(from_hex(encoded_hex)?, &mut bytes);
            let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            match result {
                Ok(()) => println!("ok:{hex}"),
                Err(error) => println!("err:{}:{hex}", error.offset()),
            }
            continue;
        }
        if let Some(request) = line.strip_prefix('Q') {
            let (pad, plain) = request.split_once(':').ok_or("bad padding request")?;
            let plain = from_hex(plain)?;
            let pad = u32::from_str_radix(pad, 16)?;
            let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
            let padded = u8::try_from(pad)
                .map_err(|_| ())
                .and_then(|b| base64::STANDARD.with_padding(Some(b)).map_err(|_| ()));
            match padded {
                Err(()) => println!("panic"),
                Ok(encoding) => {
                    let text = encoding.encode_to_vec(&plain);
                    let mut decoded = Vec::new();
                    let status = match encoding.decode_into(&text, &mut decoded) {
                        Ok(()) => "<nil>".to_string(),
                        Err(e) => e.to_string(),
                    };
                    println!("{}\t{}\t{status}", hex(&text), hex(&decoded));
                }
            }
            continue;
        }
        let input = from_hex(&line)?;
        for (index, encoding) in encodings.iter().enumerate() {
            if index > 0 {
                print!("\t");
            }
            print!("{}", encoding.encode(&input));
        }
        println!();
    }
    Ok(())
}
