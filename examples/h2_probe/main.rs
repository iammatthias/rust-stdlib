//! Line protocol used by `tools/h2_check.py`; mirrors `tools/h2_oracle.go`
//! (HPACK and frame sections). One request per line, one answer per line.
use rust_stdlib::net::http::h2::hpack::{
    append_huffman_string, huffman_decode, huffman_encode_length, Decoder, Encoder, HeaderField,
};
use std::io::{self, BufRead, Write};

mod frames;

pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn fields_text(fs: &[HeaderField]) -> String {
    fs.iter()
        .map(|f| {
            format!(
                "{}/{}/{}",
                hex(&f.name),
                hex(&f.value),
                u8::from(f.sensitive)
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn hpack_encode(req: &str) -> String {
    let mut enc = Encoder::new();
    let mut out = Vec::new();
    for block in req.split(';') {
        let mut buf = Vec::new();
        if !block.is_empty() {
            for op in block.split(',') {
                let rest = &op[1..];
                match op.as_bytes()[0] {
                    b'f' => {
                        let p: Vec<&str> = rest.split('/').collect();
                        let mut f = HeaderField::new(unhex(p[0]), unhex(p[1]));
                        f.sensitive = p[2] == "1";
                        enc.write_field(&f, &mut buf);
                    }
                    b't' => enc.set_max_dynamic_table_size(rest.parse().unwrap()),
                    b'l' => enc.set_max_dynamic_table_size_limit(rest.parse().unwrap()),
                    _ => {}
                }
            }
        }
        out.push(hex(&buf));
    }
    out.join(";")
}

fn hpack_decode(head: &str, body: &str) -> String {
    let p: Vec<&str> = head.split(',').collect();
    let mut dec = Decoder::new(p[0].parse().unwrap());
    dec.set_max_string_length(p[1].parse().unwrap());
    let mut out = Vec::new();
    for block in body.split(';') {
        let mut got = Vec::new();
        let b = unhex(block);
        let r = dec
            .write(&b, &mut |f| {
                got.push(f);
                true
            })
            .and_then(|_| dec.close());
        if let Err(e) = r {
            out.push(format!("err:{e}"));
            break;
        }
        out.push(fields_text(&got));
    }
    out.join(";")
}

fn hpack_partial(head: &str, rest: &str) -> String {
    let p: Vec<&str> = head.split(',').collect();
    let mut dec = Decoder::new(p[0].parse().unwrap());
    dec.set_max_string_length(p[1].parse().unwrap());
    dec.set_emit_enabled(p[2] == "1");
    let (split, hexblock) = rest.split_once(':').unwrap();
    let block = unhex(hexblock);
    let split = split.parse::<usize>().unwrap().min(block.len());
    let mut got = Vec::new();
    let r = dec
        .write(&block[..split], &mut |f| {
            got.push(f);
            true
        })
        .and_then(|_| {
            dec.write(&block[split..], &mut |f| {
                got.push(f);
                true
            })
        })
        .and_then(|_| dec.close());
    match r {
        Err(e) => format!("err:{e}|{}", fields_text(&got)),
        Ok(()) => fields_text(&got),
    }
}

fn huff_decode(h: &str) -> String {
    let mut out = Vec::new();
    match huffman_decode(&mut out, 0, &unhex(h)) {
        Err(e) => format!("err:{e}"),
        Ok(()) => format!("{} {}", hex(&out), huffman_encode_length(&out)),
    }
}

fn huff_encode(h: &str) -> String {
    let input = unhex(h);
    let mut out = Vec::new();
    append_huffman_string(&mut out, &input);
    format!("{} {}", hex(&out), huffman_encode_length(&input))
}

fn main() {
    let stdin = io::stdin();
    let mut w = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let (head, rest) = line.split_once(':').unwrap();
        let out = match head {
            "E" => hpack_encode(rest),
            "H" => huff_decode(rest),
            "J" => huff_encode(rest),
            h if h.starts_with('D') => hpack_decode(&h[1..], rest),
            h if h.starts_with('P') => hpack_partial(&h[1..], rest),
            h => frames::frame_request(h, rest),
        };
        writeln!(w, "{out}").unwrap();
    }
}
