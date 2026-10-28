//! Line-oriented driver used by tools/conformance.py. All application and
//! parsing code in this executable uses the first-party crate.
use rust_stdlib::{
    encoding::{
        base64, hex,
        json::{self, Value},
    },
    net::url,
};
use std::io::{self, BufRead};
fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field: {key}"))
}
fn run(value: &Value) -> Result<String, String> {
    let input = field(value, "input")?;
    match field(value, "op")? {
        "hex" => hex::decode(input)
            .map(|v| hex::encode(&v))
            .map_err(|e| e.to_string()),
        "base64" | "base64-decode" => {
            let encoding = match field(value, "variant")? {
                "standard" => base64::STANDARD,
                "url" => base64::URL_SAFE,
                "raw-standard" => base64::STANDARD_NO_PAD,
                "raw-url" => base64::URL_SAFE_NO_PAD,
                _ => return Err("invalid variant".to_owned()),
            };
            if field(value, "op")? == "base64" {
                Ok(encoding.encode(&hex::decode(input).map_err(|e| e.to_string())?))
            } else {
                encoding
                    .decode(input)
                    .map(|v| hex::encode(&v))
                    .map_err(|e| e.to_string())
            }
        }
        "query-escape" => Ok(url::query_escape(input)),
        "json" => input
            .parse::<json::Value>()
            .map(|v| v.to_string())
            .map_err(|e| e.to_string()),
        other => Err(format!("unknown operation: {other}")),
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    for line in io::stdin().lock().lines() {
        let result = line?
            .parse::<json::Value>()
            .map_err(|e| e.to_string())
            .and_then(|v| run(&v));
        let value = match result {
            Ok(s) => Value::object([("ok", Value::from(s))]),
            Err(s) => Value::object([("error", Value::from(s))]),
        };
        println!("{}", value);
    }
    Ok(())
}
