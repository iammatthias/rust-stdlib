//! Line-oriented conformance driver; input is a JSON {format,input} object.
use rust_stdlib::encoding::binary::{
    self, ByteOrder, FixedSize, BIG_ENDIAN, LITTLE_ENDIAN, NATIVE_ENDIAN,
};
use rust_stdlib::encoding::{
    csv,
    json::{self, Value},
    xml,
};
use std::io::{self, BufRead};
fn invalid() -> io::Error {
    io::Error::from(io::ErrorKind::InvalidData)
}
fn unhex(text: &str) -> io::Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err(invalid());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| invalid()))
        .collect()
}
fn byte_order(name: &str) -> &'static dyn ByteOrder {
    match name {
        "BE" => &BIG_ENDIAN,
        "LE" => &LITTLE_ENDIAN,
        _ => &NATIVE_ENDIAN,
    }
}
fn parse<T: std::str::FromStr>(text: &str) -> io::Result<T> {
    text.parse().map_err(|_| invalid())
}
fn parse_hex<T: TryFrom<u64>>(text: &str) -> io::Result<T> {
    let bits = u64::from_str_radix(text, 16).map_err(|_| invalid())?;
    T::try_from(bits).map_err(|_| invalid())
}
/// Repr renders a value the way the Go oracle does: decimal integers, hex bit
/// patterns for floats and true or false for bool.
trait Repr {
    fn repr(&self) -> String;
}
macro_rules! repr_display {
    ($($t:ty),*) => {$(
        impl Repr for $t {
            fn repr(&self) -> String {
                self.to_string()
            }
        }
    )*};
}
repr_display!(u8, i8, u16, i16, u32, i32, u64, i64, bool);
impl Repr for f32 {
    fn repr(&self) -> String {
        format!("{:x}", self.to_bits())
    }
}
impl Repr for f64 {
    fn repr(&self) -> String {
        format!("{:x}", self.to_bits())
    }
}
fn encode_as<T: FixedSize>(value: T, order: &dyn ByteOrder, size: usize) -> io::Result<Value> {
    let mut buf = vec![0u8; size];
    let n = binary::encode(&mut buf, order, &value)?;
    Ok(Value::Array(
        buf[..n].iter().copied().map(Value::from).collect(),
    ))
}
fn write_as<T: FixedSize>(value: T, order: &dyn ByteOrder) -> io::Result<Value> {
    let mut out = Vec::new();
    binary::write(&mut out, order, &value)?;
    Ok(Value::Array(out.into_iter().map(Value::from).collect()))
}
fn typed_encode(typ: &str, text: &str, order: &dyn ByteOrder, size: usize) -> io::Result<Value> {
    match typ {
        "u8" => encode_as(parse::<u8>(text)?, order, size),
        "i8" => encode_as(parse::<i8>(text)?, order, size),
        "u16" => encode_as(parse::<u16>(text)?, order, size),
        "i16" => encode_as(parse::<i16>(text)?, order, size),
        "u32" => encode_as(parse::<u32>(text)?, order, size),
        "i32" => encode_as(parse::<i32>(text)?, order, size),
        "u64" => encode_as(parse::<u64>(text)?, order, size),
        "i64" => encode_as(parse::<i64>(text)?, order, size),
        "f32" => encode_as(f32::from_bits(parse_hex::<u32>(text)?), order, size),
        "f64" => encode_as(f64::from_bits(parse_hex::<u64>(text)?), order, size),
        "bool" => encode_as(text == "true", order, size),
        _ => Err(invalid()),
    }
}
fn typed_write(typ: &str, text: &str, order: &dyn ByteOrder) -> io::Result<Value> {
    match typ {
        "u8" => write_as(parse::<u8>(text)?, order),
        "i8" => write_as(parse::<i8>(text)?, order),
        "u16" => write_as(parse::<u16>(text)?, order),
        "i16" => write_as(parse::<i16>(text)?, order),
        "u32" => write_as(parse::<u32>(text)?, order),
        "i32" => write_as(parse::<i32>(text)?, order),
        "u64" => write_as(parse::<u64>(text)?, order),
        "i64" => write_as(parse::<i64>(text)?, order),
        "f32" => write_as(f32::from_bits(parse_hex::<u32>(text)?), order),
        "f64" => write_as(f64::from_bits(parse_hex::<u64>(text)?), order),
        "bool" => write_as(text == "true", order),
        _ => Err(invalid()),
    }
}
/// `read` selects Go's Read (value only) over Decode (value and count).
fn decode_as<T: FixedSize + Default + Repr>(
    buf: &[u8],
    order: &dyn ByteOrder,
    read: bool,
) -> io::Result<Value> {
    let mut value = T::default();
    if read {
        binary::read(&mut &buf[..], order, &mut value)?;
        return Ok(Value::from(value.repr()));
    }
    let n = binary::decode(buf, order, &mut value)?;
    Ok(Value::Array(vec![
        Value::from(value.repr()),
        Value::from(n),
    ]))
}
fn typed_decode(typ: &str, buf: &[u8], order: &dyn ByteOrder, read: bool) -> io::Result<Value> {
    match typ {
        "u8" => decode_as::<u8>(buf, order, read),
        "i8" => decode_as::<i8>(buf, order, read),
        "u16" => decode_as::<u16>(buf, order, read),
        "i16" => decode_as::<i16>(buf, order, read),
        "u32" => decode_as::<u32>(buf, order, read),
        "i32" => decode_as::<i32>(buf, order, read),
        "u64" => decode_as::<u64>(buf, order, read),
        "i64" => decode_as::<i64>(buf, order, read),
        "f32" => decode_as::<f32>(buf, order, read),
        "f64" => decode_as::<f64>(buf, order, read),
        "bool" => decode_as::<bool>(buf, order, read),
        _ => Err(invalid()),
    }
}
/// Fixed-size, byte-order and varint formats; `None` leaves the format to `run`.
fn binary_run(format: &str, input: &str) -> Option<io::Result<Value>> {
    let result = match format {
        "binary_encode" => {
            let parts: Vec<&str> = input.split('|').collect();
            let size = parts.get(3).and_then(|s| s.parse().ok());
            match (parts.as_slice(), size) {
                ([order, typ, value, _], Some(size)) => {
                    typed_encode(typ, value, byte_order(order), size)
                }
                _ => Err(invalid()),
            }
        }
        "binary_write" | "binary_decode" | "binary_read" => {
            let parts: Vec<&str> = input.split('|').collect();
            match parts.as_slice() {
                [order, typ, text] if format == "binary_write" => {
                    typed_write(typ, text, byte_order(order))
                }
                [order, typ, hex] => unhex(hex).and_then(|buf| {
                    typed_decode(typ, &buf, byte_order(order), format == "binary_read")
                }),
                _ => Err(invalid()),
            }
        }
        "append_uvarint" => parse::<u64>(input).map(|value| {
            let mut out = Vec::new();
            binary::append_uvarint(&mut out, value);
            Value::Array(out.into_iter().map(Value::from).collect())
        }),
        "append_varint" => parse::<i64>(input).map(|value| {
            let mut out = Vec::new();
            binary::append_varint(&mut out, value);
            Value::Array(out.into_iter().map(Value::from).collect())
        }),
        "uvarint_get" => unhex(input).and_then(|buf| {
            binary::uvarint(&buf)
                .map(|(v, n)| Value::Array(vec![Value::from(v.to_string()), Value::from(n)]))
        }),
        "varint_get" => unhex(input).and_then(|buf| {
            binary::varint(&buf)
                .map(|(v, n)| Value::Array(vec![Value::from(v.to_string()), Value::from(n)]))
        }),
        "read_uvarint" => unhex(input)
            .and_then(|buf| binary::read_uvarint(&mut &buf[..]))
            .map(|v| Value::from(v.to_string())),
        "read_varint" => unhex(input)
            .and_then(|buf| binary::read_varint(&mut &buf[..]))
            .map(|v| Value::from(v.to_string())),
        _ => return None,
    };
    Some(result)
}
/// Reader and Writer settings from a vector's `options` object. Missing keys
/// take Go's zero values.
struct CsvOptions {
    comma: char,
    comment: Option<char>,
    fields: isize,
    lazy: bool,
    trim: bool,
    crlf: bool,
    fail_at: Option<usize>,
}
fn csv_options(options: Option<&Value>) -> CsvOptions {
    let text = |key: &str| {
        options
            .and_then(|o| o.get(key))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned()
    };
    let flag = |key: &str| matches!(options.and_then(|o| o.get(key)), Some(Value::Bool(true)));
    CsvOptions {
        comma: match options.and_then(|o| o.get("comma")).and_then(Value::as_str) {
            Some(text) => text.chars().next().unwrap_or('\0'),
            None => ',',
        },
        comment: text("comment").chars().next(),
        fields: text("fields").parse().unwrap_or(0),
        lazy: flag("lazy"),
        trim: flag("trim"),
        crlf: flag("crlf"),
        fail_at: text("fail_at").parse().ok(),
    }
}
fn csv_record(fields: Vec<String>) -> Value {
    Value::Array(fields.into_iter().map(Value::from).collect())
}
fn csv_run(format: &str, input: &str, o: &CsvOptions) -> io::Result<Value> {
    match format {
        "csv" => csv::Reader::new(input.as_bytes())
            .read_all()
            .map(|rows| Value::Array(rows.into_iter().map(csv_record).collect()))
            .map_err(|_| invalid()),
        "csv_write" => {
            let Value::Array(rows) = input.parse::<json::Value>().map_err(|_| invalid())? else {
                return Err(invalid());
            };
            let mut records = Vec::new();
            for row in rows {
                let Value::Array(fields) = row else {
                    return Err(invalid());
                };
                let mut record = Vec::new();
                for field in fields {
                    let Value::String(text) = field else {
                        return Err(invalid());
                    };
                    record.push(text);
                }
                records.push(record);
            }
            let mut writer = csv::Writer::new(Vec::new());
            writer.comma = o.comma;
            writer.use_crlf = o.crlf;
            writer.write_all(&records).map_err(|_| invalid())?;
            let out = writer.into_inner()?;
            Ok(Value::from(String::from_utf8(out).map_err(|_| invalid())?))
        }
        _ => {
            let (raw, fail_at) = if format == "csv_raw_read" {
                (unhex(input)?, o.fail_at)
            } else {
                (input.as_bytes().to_vec(), None)
            };
            let hex_fields = format == "csv_raw_read";
            let show = |record: Vec<Vec<u8>>| {
                Value::Array(
                    record
                        .into_iter()
                        .map(|field| {
                            if hex_fields {
                                Value::from(
                                    field.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                                )
                            } else {
                                Value::from(String::from_utf8_lossy(&field).into_owned())
                            }
                        })
                        .collect(),
                )
            };
            let source: Box<dyn io::Read> = match fail_at {
                Some(n) => Box::new(FailingReader {
                    data: raw,
                    fail_at: n,
                    pos: 0,
                }),
                None => Box::new(io::Cursor::new(raw)),
            };
            let mut reader = csv::Reader::new(source);
            reader.comma = o.comma;
            reader.comment = o.comment;
            reader.fields_per_record = o.fields;
            reader.lazy_quotes = o.lazy;
            reader.trim_leading_space = o.trim;
            let mut events = Vec::new();
            while events.len() < 1000 {
                match reader.read_raw() {
                    (_, Some(csv::Error::Eof)) => {
                        events.push(Value::Array(vec![Value::from("eof")]));
                        break;
                    }
                    (record, None) => {
                        let positions = (0..record.len())
                            .map(|j| {
                                let (line, col) = reader.field_pos(j);
                                Value::Array(vec![Value::from(line), Value::from(col)])
                            })
                            .collect();
                        events.push(Value::Array(vec![
                            Value::from("record"),
                            show(record),
                            Value::Array(positions),
                            Value::from(reader.input_offset()),
                        ]));
                    }
                    (record, Some(csv::Error::Parse(e))) => events.push(Value::Array(vec![
                        Value::from("parse"),
                        Value::from(e.start_line),
                        Value::from(e.line),
                        Value::from(e.column),
                        Value::from(e.err.to_string()),
                        Value::from(e.to_string()),
                        show(record),
                    ])),
                    (record, Some(e)) => {
                        events.push(Value::Array(vec![
                            Value::from("error"),
                            Value::from(e.to_string()),
                            show(record),
                        ]));
                        break;
                    }
                }
            }
            Ok(Value::Array(events))
        }
    }
}
/// Yields `data[..fail_at]` and then an I/O error, like the Go oracle's failingReader.
struct FailingReader {
    data: Vec<u8>,
    fail_at: usize,
    pos: usize,
}
impl io::Read for FailingReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.fail_at {
            return Err(io::Error::other("injected read failure"));
        }
        let end = self.fail_at.min(self.data.len());
        if self.pos >= end {
            return Ok(0);
        }
        let n = buf.len().min(end - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}
/// Tokens of `input` through the Go-compatible decoder, in the oracle's shape:
/// local names only for `xml`, `[space, local]` pairs without `xmlns`
/// declarations for `xmlns`.
fn xml_tokens(input: &str, namespaces: bool) -> io::Result<Value> {
    let name = |n: xml::Name| {
        if namespaces {
            Value::Array(vec![Value::from(n.space), Value::from(n.local)])
        } else {
            Value::from(n.local)
        }
    };
    let mut decoder = xml::Decoder::new(input.as_bytes());
    let mut out = Vec::new();
    loop {
        let token = match decoder.token() {
            Ok(token) => token,
            Err(xml::Error::Eof) => return Ok(Value::Array(out)),
            Err(e) => return Err(io::Error::other(e.to_string())),
        };
        match token {
            xml::Token::StartElement(start) => {
                let attributes = start
                    .attr
                    .into_iter()
                    .filter(|a| {
                        !(namespaces
                            && (a.name.space == "xmlns"
                                || (a.name.space.is_empty() && a.name.local == "xmlns")))
                    })
                    .map(|a| Value::Array(vec![name(a.name), Value::from(a.value)]))
                    .collect();
                out.push(Value::Array(vec![
                    Value::from("start"),
                    name(start.name),
                    Value::Array(attributes),
                ]));
            }
            xml::Token::EndElement(end) => {
                out.push(Value::Array(vec![Value::from("end"), name(end.name)]));
            }
            xml::Token::CharData(t) => out.push(Value::Array(vec![
                Value::from("text"),
                Value::from(String::from_utf8_lossy(&t.0).into_owned()),
            ])),
            xml::Token::Comment(t) => out.push(Value::Array(vec![
                Value::from("comment"),
                Value::from(String::from_utf8_lossy(&t.0).into_owned()),
            ])),
            xml::Token::ProcInst(t) => out.push(Value::Array(vec![
                Value::from("pi"),
                Value::from(t.target),
                Value::from(String::from_utf8_lossy(&t.inst).into_owned()),
            ])),
            xml::Token::Directive(_) => {}
        }
    }
}
fn run(format: &str, input: &str, options: Option<&Value>) -> io::Result<Value> {
    if let Some(result) = binary_run(format, input) {
        return result;
    }
    if matches!(format, "csv" | "csv_read" | "csv_write" | "csv_raw_read") {
        return csv_run(format, input, &csv_options(options));
    }
    match format {
        "uvarint" | "varint" => {
            let mut output = [0u8; 10];
            let n = if format == "uvarint" {
                let value = input
                    .parse::<u64>()
                    .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
                rust_stdlib::encoding::binary::put_uvarint(&mut output, value)?
            } else {
                let value = input
                    .parse::<i64>()
                    .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
                rust_stdlib::encoding::binary::put_varint(&mut output, value)?
            };
            Ok(Value::Array(
                output[..n].iter().copied().map(Value::from).collect(),
            ))
        }
        "xml" | "xmlns" => xml_tokens(input, format == "xmlns"),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported format",
        )),
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    for line in io::stdin().lock().lines() {
        let v = line?.parse::<json::Value>()?;
        let format = v
            .get("format")
            .and_then(Value::as_str)
            .ok_or("format missing")?;
        let input = v
            .get("input")
            .and_then(Value::as_str)
            .ok_or("input missing")?;
        let response = match run(format, input, v.get("options")) {
            Ok(value) => Value::object([("ok", Value::Bool(true)), ("value", value)]),
            Err(_) => Value::object([("ok", Value::Bool(false))]),
        };
        println!("{}", response);
    }
    Ok(())
}
