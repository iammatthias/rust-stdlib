use rust_stdlib::tabwriter::{TabWriter, FILTER_HTML};
use std::io::Write;
fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut o = String::new();
    for &x in b {
        o.push(H[(x >> 4) as usize] as char);
        o.push(H[(x & 15) as usize] as char)
    }
    o
}
fn main() {
    for l in std::io::stdin().lines() {
        let l = l.unwrap();
        let p: Vec<_> = l.split_whitespace().collect();
        let n: usize = p[0].parse().unwrap();
        let t: usize = p[1].parse().unwrap();
        let pad: usize = p[2].parse().unwrap();
        let pc = u8::from_str_radix(p[3], 16).unwrap();
        let flags: u32 = p[4].parse().unwrap();
        let input = unhex(p[5]);
        let mut w = match p.get(6) {
            // A reused writer: unflushed text and configuration must not survive init.
            Some(reuse) => {
                let mut stale = TabWriter::new(Vec::new(), 0, 8, 3, b'#', FILTER_HTML).unwrap();
                stale.write_all(&unhex(reuse)).unwrap();
                stale.init(Vec::new(), n, t, pad, pc, flags).unwrap();
                stale
            }
            None => TabWriter::new(Vec::new(), n, t, pad, pc, flags).unwrap(),
        };
        let e = w.write_all(&input).and_then(|_| w.flush());
        let out = w.into_inner().unwrap_or_default();
        let err = e.err().map(|e| e.to_string()).unwrap_or_else(|| "-".into());
        println!("{}\t{}", hex(&out), hex(err.as_bytes()));
    }
}
