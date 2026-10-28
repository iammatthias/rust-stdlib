use rust_stdlib::encoding::ascii85;
use std::io::{self, BufRead, Read, Write};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex input"))
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.expect("stdin");
        let mut fields = line.split('\t');
        let op = fields.next().unwrap_or("");
        let input = unhex(fields.next().unwrap_or(""));
        match op {
            "E" => println!("E|{}", hex(&ascii85::encode_to_vec(&input))),
            "S" => {
                let mut encoder = ascii85::Encoder::new(Vec::new());
                encoder.write_all(&input).expect("write to vector");
                let encoded = encoder.finish().expect("finish vector");
                println!("E|{}", hex(&encoded));
            }
            "R" => {
                let mut output = Vec::new();
                let message = match ascii85::Decoder::new(&input[..]).read_to_end(&mut output) {
                    Ok(_) => "-".to_owned(),
                    Err(error) => error.to_string(),
                };
                println!("R|{}|{message}", hex(&output));
            }
            "D" => {
                let flush = fields.next() == Some("1");
                let mut output = vec![0; 16 * 1024];
                let (n, consumed, result) = ascii85::decode(&mut output, &input, flush);
                let message = result
                    .as_ref()
                    .err()
                    .map_or_else(|| "-".to_owned(), |e| e.to_string());
                let error = result
                    .err()
                    .map_or_else(|| "-".to_owned(), |e| e.0.to_string());
                println!("D|{n}|{consumed}|{}|{error}|{message}", hex(&output[..n]));
            }
            _ => panic!("unknown operation"),
        }
    }
}
