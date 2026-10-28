use rust_stdlib::quotedprintable::{Reader, Writer};
use std::io::{Read, Write};

fn hex_decode(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn hex_encode(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &v in b {
        s.push(H[(v >> 4) as usize] as char);
        s.push(H[(v & 15) as usize] as char);
    }
    s
}
fn main() {
    for line in std::io::stdin().lines() {
        let line = line.unwrap();
        let (op, raw) = line.split_once(' ').unwrap();
        let input = hex_decode(raw);
        let (output, error) = if op.starts_with("decode") {
            let mut r = Reader::new(input.as_slice());
            let mut out = Vec::new();
            let e = r.read_to_end(&mut out).err();
            (out, e.map(|e| e.to_string()))
        } else {
            let mut w = Writer::new(Vec::new());
            w.binary = op.ends_with("binary");
            let e = w.write_all(&input).and_then(|_| w.close());
            let out = w.into_inner().unwrap_or_default();
            (out, e.err().map(|e| e.to_string()))
        };
        println!(
            "{}\t{}",
            hex_encode(&output),
            hex_encode(error.as_deref().unwrap_or("-").as_bytes())
        );
    }
}
