use rust_stdlib::encoding::{
    json::{self, Value},
    pem,
};
use std::collections::BTreeMap;
use std::io::{self, BufRead};

fn string_field<'a>(value: &'a Value, name: &str) -> Result<&'a str, Box<dyn std::error::Error>> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{name} missing").into())
}

fn bytes_array(value: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    value
        .as_array()
        .ok_or("bytes missing")?
        .iter()
        .map(|v| {
            v.as_number()
                .ok_or("byte is not a number")?
                .as_str()
                .parse::<u8>()
                .map_err(Into::into)
        })
        .collect()
}

fn from_hex(text: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(Into::into))
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn run(value: Value) -> Result<Value, Box<dyn std::error::Error>> {
    let op = string_field(&value, "op")?;
    if op == "encode" {
        let type_ = string_field(&value, "type")?.to_owned();
        let bytes = bytes_array(value.get("bytes").ok_or("bytes missing")?)?;
        let mut headers = BTreeMap::new();
        if let Some(Value::Object(fields)) = value.get("headers") {
            for (key, field) in fields {
                let field = field.as_str().ok_or("header value is not text")?;
                headers.insert(key.clone(), field.to_owned());
            }
        }
        let block = pem::Block {
            type_,
            headers,
            bytes,
        };
        let encoded = pem::encode(&block);
        let mut written = Vec::new();
        let writer_result = pem::encode_to_writer(&block, &mut written);
        if writer_result.is_ok() != encoded.is_ok()
            || encoded.as_ref().is_ok_and(|bytes| *bytes != written)
        {
            return Err("encode_to_writer disagrees with encode".into());
        }
        return Ok(match encoded {
            Ok(encoded) => Value::from(String::from_utf8(encoded)?),
            Err(_) => Value::Null,
        });
    }

    if op == "decode_raw" {
        // Input and output strings are hex so arbitrary bytes in types and headers survive JSON.
        let input = from_hex(string_field(&value, "input_hex")?)?;
        let Some((block, remainder)) = pem::decode_raw(&input) else {
            return Ok(Value::Null);
        };
        let headers = Value::Object(
            block
                .headers
                .into_iter()
                .map(|(k, v)| (to_hex(&k), Value::from(to_hex(&v))))
                .collect(),
        );
        let bytes = Value::Array(block.bytes.into_iter().map(Value::from).collect());
        return Ok(Value::object([
            ("type", Value::from(to_hex(&block.type_))),
            ("headers", headers),
            ("bytes", bytes),
            ("remainder", Value::from(to_hex(remainder))),
        ]));
    }
    let input = string_field(&value, "input")?;
    let Some((block, remainder)) = pem::decode(input.as_bytes()) else {
        return Ok(Value::Null);
    };
    let headers = Value::Object(
        block
            .headers
            .into_iter()
            .map(|(k, v)| (k, Value::from(v)))
            .collect(),
    );
    let bytes = Value::Array(block.bytes.into_iter().map(Value::from).collect());
    Ok(Value::object([
        ("type", Value::from(block.type_)),
        ("headers", headers),
        ("bytes", bytes),
        (
            "remainder",
            Value::from(String::from_utf8_lossy(remainder).into_owned()),
        ),
    ]))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    for line in io::stdin().lock().lines() {
        let value = line?.parse::<json::Value>()?;
        let response = run(value).unwrap_or(Value::Null);
        println!("{}", response);
    }
    Ok(())
}
