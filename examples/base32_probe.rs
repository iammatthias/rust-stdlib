//! Line protocol used by `tools/base32_check.py`; mirrors `tools/base32_oracle.go`.
//! Requests are `<op><cfg>:<hex>`, or `N:<alphabet hex>|<padding>`, and each
//! answer is one line. Go's constructor panics are reported as "panic", and a
//! padding outside `Option<u8>` (which Go would also reject) is "panic".
use rust_stdlib::encoding::base32::{self, Engine};
use std::io::{self, BufRead, Read, Write};

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

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn configs() -> Vec<Engine> {
    let reversed = b"ZYXWVUTSRQPONMLKJIHGFEDCBA765432";
    let high = |from: u8| -> [u8; 32] { std::array::from_fn(|i| from + i as u8) };
    vec![
        base32::STANDARD,
        base32::HEX,
        base32::STANDARD_NO_PAD,
        base32::HEX_NO_PAD,
        Engine::new(b"abcdefghijklmnopqrstuvwxyz234567")
            .and_then(|e| e.with_padding(Some(b'-')))
            .unwrap(),
        Engine::new(&high(0x80))
            .and_then(|e| e.with_padding(Some(0xff)))
            .unwrap(),
        Engine::new(&high(0xe0))
            .and_then(|e| e.with_padding(None))
            .unwrap(),
        Engine::new(reversed).unwrap(),
    ]
}

fn configure(alphabet: &[u8], padding: i64) -> String {
    // Go panics on an alphabet that is not 32 bytes; here the type forbids it.
    let Ok(alphabet) = <&[u8; 32]>::try_from(alphabet) else {
        return "panic".into();
    };
    let Ok(encoding) = Engine::new(alphabet) else {
        return "panic".into();
    };
    let padding = match padding {
        -1 => None,
        0..=255 => Some(padding as u8),
        _ => return "panic".into(),
    };
    match encoding.with_padding(padding) {
        Ok(e) => format!("ok:{}", to_hex(&e.encode_to_vec(b"foobar"))),
        Err(_) => "panic".into(),
    }
}

fn handle(line: &str, encodings: &[Engine]) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(rest) = line.strip_prefix("N:") {
        let (alphabet, padding) = rest.split_once('|').ok_or("bad configure request")?;
        return Ok(configure(&from_hex(alphabet)?, padding.parse()?));
    }
    let op = line.as_bytes().first().copied().ok_or("empty request")?;
    let (index, payload) = line[1..].split_once(':').ok_or("bad request")?;
    let encoding = encodings[index.parse::<usize>()?];
    Ok(match op {
        b'L' => {
            let n: usize = payload.parse()?;
            format!("{} {}", encoding.encoded_len(n), encoding.decoded_len(n))
        }
        b'E' => {
            let plain = from_hex(payload)?;
            let dst = encoding.encode_to_vec(&plain);
            let mut appended = b"x".to_vec();
            encoding.encode_into(&plain, &mut appended);
            assert_eq!(&appended[1..], dst);
            if dst.is_ascii() {
                assert_eq!(encoding.encode(&plain).as_bytes(), dst);
            }
            to_hex(&dst)
        }
        b'A' | b'B' | b'S' => {
            let mut out = Vec::new();
            match encoding.decode_into(from_hex(payload)?, &mut out) {
                Ok(()) if op == b'A' || op == b'S' => format!("ok:{}", to_hex(&out)),
                Ok(()) => format!("ok:{}:{}", out.len(), to_hex(&out)),
                Err(e) if op == b'B' => {
                    format!("err:{}:{}:{}", out.len(), e.offset(), to_hex(&out))
                }
                Err(e) => format!("err:{}:{}", e.offset(), to_hex(&out)),
            }
        }
        b'W' => {
            let plain = from_hex(payload)?;
            let mut encoder = encoding.encoder(Vec::new());
            for chunk in plain.chunks(3) {
                encoder.write_all(chunk)?;
            }
            to_hex(&encoder.finish()?)
        }
        b'R' => {
            let src = from_hex(payload)?;
            let mut out = Vec::new();
            // Streaming output before an error depends on read chunking in Go too,
            // so only the outcome is compared.
            match encoding.decoder(&src[..]).read_to_end(&mut out) {
                Ok(_) => format!("ok:{}", to_hex(&out)),
                Err(_) => "err".into(),
            }
        }
        b'C' => {
            let (sizes, data) = payload.split_once('|').ok_or("missing |")?;
            let (read, chunk) = sizes.split_once(',').ok_or("missing ,")?;
            let src = from_hex(data)?;
            let chunk: usize = chunk.parse()?;
            let mut p = vec![0; read.parse()?];
            let mut r = encoding.decoder(ChunkReader { data: &src, chunk });
            let mut parts: Vec<String> = Vec::new();
            let status = loop {
                match r.read(&mut p) {
                    Ok(0) => break "EOF".to_string(),
                    Ok(n) => parts.push(to_hex(&p[..n])),
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break "UEOF".to_string(),
                    Err(e) => match e.get_ref().and_then(|e| e.downcast_ref::<base32::Error>()) {
                        Some(e) => break format!("corrupt:{}", e.offset()),
                        None => break format!("{e}"),
                    },
                }
            };
            format!("{}|{status}", parts.join(";"))
        }
        _ => return Err(format!("unknown op {}", op as char).into()),
    })
}

/// Returns at most `chunk` bytes per read.
struct ChunkReader<'a> {
    data: &'a [u8],
    chunk: usize,
}

impl Read for ChunkReader<'_> {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        let n = p.len().min(self.chunk).min(self.data.len());
        p[..n].copy_from_slice(&self.data[..n]);
        self.data = &self.data[n..];
        Ok(n)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let encodings = configs();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        writeln!(out, "{}", handle(&line?, &encodings)?)?;
    }
    Ok(())
}
