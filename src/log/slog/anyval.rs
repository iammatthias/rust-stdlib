//! Built-in [`Dynamic`] values and Go's `encoding/json` / `fmt` renderings used by them.
use super::value::{Dynamic, TextValue};
use crate::{
    encoding::{base64, json},
    strconv,
};
use std::{any::Any, fmt::Write as _};

/// A Go `error` value: JSON handlers print the message as a plain string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorValue(pub String);

impl ErrorValue {
    /// Captures the `Display` text of an error.
    pub fn new(err: &dyn std::error::Error) -> Self {
        Self(err.to_string())
    }
}

impl Dynamic for ErrorValue {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn text(&self) -> Result<TextValue, String> {
        Ok(TextValue::Plain(self.0.clone()))
    }
    fn json(&self) -> Result<String, String> {
        Ok(json_string(&self.0))
    }
    fn error_message(&self) -> Option<String> {
        Some(self.0.clone())
    }
    fn dyn_eq(&self, other: &dyn Dynamic) -> bool {
        other.as_any().downcast_ref::<Self>() == Some(self)
    }
}

/// A Go `[]byte`: text handlers print it quoted, JSON handlers as base64.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bytes(pub Vec<u8>);

impl Dynamic for Bytes {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn text(&self) -> Result<TextValue, String> {
        Ok(TextValue::Literal(strconv::quote(&self.0)))
    }
    fn json(&self) -> Result<String, String> {
        Ok(format!("\"{}\"", base64::STANDARD.encode(&self.0)))
    }
    fn dyn_eq(&self, other: &dyn Dynamic) -> bool {
        other.as_any().downcast_ref::<Self>() == Some(self)
    }
}

/// A Go value built from `nil`, booleans, `float64`, strings, `[]any` and
/// `map[string]any`, i.e. what `encoding/json` decodes into `any`. Text
/// handlers render it like `fmt` `%+v`, JSON handlers like `json.Marshal`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonAny(pub json::Value);

impl Dynamic for JsonAny {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn text(&self) -> Result<TextValue, String> {
        let mut s = String::new();
        plus_v(&self.0, &mut s);
        Ok(TextValue::Plain(s))
    }
    fn json(&self) -> Result<String, String> {
        let mut s = String::new();
        marshal(&self.0, &mut s)?;
        Ok(s)
    }
    fn dyn_eq(&self, other: &dyn Dynamic) -> bool {
        other.as_any().downcast_ref::<Self>() == Some(self)
    }
}

fn number_f64(n: &json::Number) -> f64 {
    strconv::parse_float(n.as_str(), 64).unwrap_or(f64::NAN)
}

/// `fmt.Sprintf("%+v")` of a decoded JSON value.
fn plus_v(v: &json::Value, out: &mut String) {
    match v {
        json::Value::Null => out.push_str("<nil>"),
        json::Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        json::Value::Number(n) => out.push_str(&strconv::format_float(number_f64(n), b'g', -1, 64)),
        json::Value::String(s) => out.push_str(s),
        json::Value::Array(a) => {
            out.push('[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(' ');
                }
                plus_v(e, out);
            }
            out.push(']');
        }
        json::Value::Object(m) => {
            out.push_str("map[");
            for (i, (k, e)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(' ');
                }
                out.push_str(k);
                out.push(':');
                plus_v(e, out);
            }
            out.push(']');
        }
    }
}

/// `json.Marshal` of a `float64` (no HTML escaping).
pub(crate) fn json_float(f: f64) -> Result<String, String> {
    if f.is_nan() || f.is_infinite() {
        return Err(format!(
            "json: unsupported value: {}",
            strconv::format_float(f, b'g', -1, 64)
        ));
    }
    let abs = f.abs();
    let fmt = if abs != 0.0 && !(1e-6..1e21).contains(&abs) {
        b'e'
    } else {
        b'f'
    };
    let mut s = strconv::format_float(f, fmt, -1, 64);
    if fmt == b'e' {
        // Clean up e-09 to e-9.
        let b = s.as_bytes();
        let n = b.len();
        if n >= 4 && b[n - 4] == b'e' && b[n - 3] == b'-' && b[n - 2] == b'0' {
            let last = s.pop().expect("non-empty");
            s.pop();
            s.push(last);
        }
    }
    Ok(s)
}

/// `json.Marshal` of a string with HTML escaping disabled.
pub(crate) fn json_string(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let b = c as u8;
                out.push_str("\\u00");
                out.push(HEX[usize::from(b >> 4)] as char);
                out.push(HEX[usize::from(b & 0xf)] as char);
            }
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn marshal(v: &json::Value, out: &mut String) -> Result<(), String> {
    match v {
        json::Value::Null => out.push_str("null"),
        json::Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        json::Value::Number(n) => out.push_str(&json_float(number_f64(n))?),
        json::Value::String(s) => out.push_str(&json_string(s)),
        json::Value::Array(a) => {
            out.push('[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                marshal(e, out)?;
            }
            out.push(']');
        }
        json::Value::Object(m) => {
            out.push('{');
            for (i, (k, e)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&json_string(k));
                out.push(':');
                marshal(e, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

pub(crate) fn write_panic_message(out: &mut String, payload: &(dyn Any + Send)) {
    if let Some(s) = payload.downcast_ref::<&str>() {
        out.push_str(s);
    } else if let Some(s) = payload.downcast_ref::<String>() {
        out.push_str(s);
    } else {
        let _ = write!(out, "unknown panic");
    }
}
