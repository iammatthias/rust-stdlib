use rust_stdlib::{
    compress::lzw::{self, Order, Reader},
    encoding::json::{self, Value},
};
use std::io::{self, BufRead, Read, Write};

fn bytes(value: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    value
        .as_array()
        .ok_or("byte array missing")?
        .iter()
        .map(|item| {
            item.as_number()
                .ok_or("byte is not a number")?
                .as_str()
                .parse::<u8>()
                .map_err(Into::into)
        })
        .collect()
}
fn byte_values(input: &[u8]) -> Value {
    Value::Array(input.iter().copied().map(Value::from).collect())
}
fn order(value: &Value) -> Result<Order, Box<dyn std::error::Error>> {
    match value.as_str() {
        Some("LSB") => Ok(Order::Lsb),
        Some("MSB") => Ok(Order::Msb),
        _ => Err("unknown bit order".into()),
    }
}
fn run(value: Value) -> Result<Value, Box<dyn std::error::Error>> {
    let op = value
        .get("op")
        .and_then(Value::as_str)
        .ok_or("op missing")?;
    let order = order(value.get("order").ok_or("order missing")?)?;
    let lit_width: u8 = value
        .get("lit_width")
        .and_then(Value::as_number)
        .ok_or("lit_width missing")?
        .as_str()
        .parse()?;
    if op == "encode_close" {
        let input = bytes(value.get("bytes").ok_or("bytes missing")?)?;
        let mut writer = lzw::Writer::new(Vec::new(), order, lit_width);
        let ok = writer.write_all(&input).is_ok()
            && writer.close().is_ok()
            && writer.close().is_ok()
            && writer.write(&[0]).is_err();
        return Ok(Value::object([
            ("ok", Value::Bool(ok)),
            ("bytes", byte_values(writer.get_ref())),
        ]));
    }
    if op == "encode_reset" {
        let input = bytes(value.get("bytes").ok_or("bytes missing")?)?;
        let mut writer = lzw::Writer::new(Vec::new(), order, lit_width);
        let mut ok = writer.write_all(&input).is_ok() && writer.close().is_ok();
        let mut output = writer.get_ref().clone();
        writer.reset(Vec::new(), order, lit_width);
        let reversed: Vec<u8> = input.iter().rev().copied().collect();
        ok = ok && writer.write_all(&reversed).is_ok() && writer.close().is_ok();
        output.extend_from_slice(writer.get_ref());
        return Ok(Value::object([
            ("ok", Value::Bool(ok)),
            ("bytes", byte_values(&output)),
        ]));
    }
    if op == "decode_close" {
        let input = bytes(value.get("bytes").ok_or("bytes missing")?)?;
        let mut reader = Reader::new(input.as_slice(), order, lit_width);
        reader.close()?;
        let mut buffer = [0u8; 16];
        let ok = reader.read(&mut buffer).is_err();
        return Ok(Value::object([
            ("ok", Value::Bool(ok)),
            ("bytes", byte_values(&[])),
        ]));
    }
    if op == "encode" {
        let input = bytes(value.get("bytes").ok_or("bytes missing")?)?;
        return Ok(match lzw::encode(&input, order, lit_width) {
            Ok(output) => {
                Value::object([("ok", Value::Bool(true)), ("bytes", byte_values(&output))])
            }
            Err(_) => Value::object([("ok", Value::Bool(false)), ("bytes", byte_values(&[]))]),
        });
    }
    let input = bytes(value.get("bytes").ok_or("bytes missing")?)?;
    let mut output = Vec::new();
    // No output budget, as Go has none.
    let mut decoder = Reader::new(input.as_slice(), order, lit_width);
    let mut buffer = [0u8; 4096];
    let ok = loop {
        match decoder.read(&mut buffer) {
            Ok(0) => break true,
            Ok(count) => output.extend_from_slice(&buffer[..count]),
            Err(_) => break false,
        }
    };
    Ok(Value::object([
        ("ok", Value::Bool(ok)),
        ("bytes", byte_values(&output)),
    ]))
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    for line in io::stdin().lock().lines() {
        let value = line?.parse::<json::Value>()?;
        let result = run(value).unwrap_or_else(|_| {
            Value::object([("ok", Value::Bool(false)), ("bytes", byte_values(&[]))])
        });
        println!("{}", result);
    }
    Ok(())
}
