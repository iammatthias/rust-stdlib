use rust_stdlib::encoding::json::{self, Value};
use std::io::{self, BufRead};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    for line in io::stdin().lock().lines() {
        let value = line?.parse::<json::Value>()?;
        let input = value
            .get("input")
            .and_then(Value::as_str)
            .ok_or("input missing")?;
        let output = match value.get("op").and_then(Value::as_str) {
            Some("escape") => rust_stdlib::html::escape(input),
            Some("unescape") => rust_stdlib::html::unescape(input),
            _ => return Err("unknown or missing op".into()),
        };
        println!("{}", Value::from(output));
    }
    Ok(())
}
