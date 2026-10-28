use rust_stdlib::path;
use std::io::{self, BufRead};

fn decode(value: &str) -> String {
    let bytes: Vec<u8> = (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("hex"))
        .collect();
    String::from_utf8(bytes).expect("UTF-8 path input")
}
fn hex(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.expect("stdin");
        let mut fields = line.split('\t');
        let op = fields.next().unwrap_or("");
        let a = decode(fields.next().unwrap_or(""));
        let result = match op {
            "C" => format!("C|{}", hex(&path::clean(&a))),
            "S" => {
                let (d, f) = path::split(&a);
                format!("S|{}|{}", hex(d), hex(f))
            }
            "B" => format!("B|{}", hex(path::base(&a))),
            "D" => format!("D|{}", hex(&path::dir(&a))),
            "E" => format!("E|{}", hex(path::ext(&a))),
            "A" => format!("A|{}", path::is_abs(&a)),
            "J" => {
                let mut elements = vec![a];
                elements.extend(fields.map(decode));
                format!("J|{}", hex(&path::join(&elements)))
            }
            "M" => {
                let name = decode(fields.next().unwrap_or(""));
                match path::matches(&a, &name) {
                    Ok(value) => format!("M|{value}"),
                    Err(_) => "M|error".to_owned(),
                }
            }
            _ => panic!("unknown operation"),
        };
        println!("{result}");
    }
}
