//! Deterministic mutation campaign against public decoder APIs.
use rust_stdlib::encoding::{csv, json, xml};
use std::time::Instant;
fn main() {
    let started = Instant::now();
    let count = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(100000);
    let seeds: &[&[u8]] = &[
        r#"{"key":[1,true,"雪",null]}"#.as_bytes(),
        b"a,b\r\n\"c\"\"d\",e\r\n",
        b"<r a='b'><!--x-->&amp;<![CDATA[<>]]><child/></r>",
        b"[[[[[]]]]]",
        b"<?xml version='1.0'?><root/>",
        b"<p:r xmlns:p='urn:r' xmlns='urn:d' p:a='1'><x xmlns=''/></p:r>",
    ];
    let mut state = 0x891527u64;
    let mut accepted = [0usize; 3];
    for i in 0..count {
        let mut bytes = seeds[i % seeds.len()].to_vec();
        for _ in 0..1 + i % 7 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let position = (state as usize) % (bytes.len() + 1);
            let value = (state >> 32) as u8;
            match (state >> 16) % 3 {
                0 => {
                    bytes.insert(position, value);
                }
                1 if position < bytes.len() => {
                    bytes[position] = value;
                }
                _ if position < bytes.len() => {
                    bytes.remove(position);
                }
                _ => {}
            }
        }
        if let Ok(value) = json::Value::try_from(&bytes[..]) {
            let encoded = json::marshal(&value).unwrap();
            assert_eq!(json::Value::try_from(&encoded[..]).unwrap(), value);
            accepted[0] += 1;
        }
        if let Ok(rows) = csv::Reader::new(&bytes[..]).read_all() {
            let mut writer = csv::Writer::new(Vec::new());
            writer.write_all(&rows).unwrap();
            let encoded = writer.into_inner().unwrap();
            let decoded = csv::Reader::new(&encoded[..]).read_all().unwrap();
            assert_eq!(decoded, rows);
            accepted[1] += 1;
        }
        let mut decoder = xml::Decoder::new(&bytes[..]);
        let complete = loop {
            match decoder.token() {
                Ok(_) => {}
                Err(xml::Error::Eof) => break true,
                Err(_) => break false,
            }
        };
        if complete {
            accepted[2] += 1;
        }
    }
    println!("deterministic decoder mutations: {count} inputs x 3 decoders, seed=0x891527, elapsed={:.3}s accepted(json,csv,xml)={accepted:?}",started.elapsed().as_secs_f64());
}
