//! Differential probe for `encoding::asn1`, driven by tools/asn1_check.py.
//!
//! Requests carry a schema tree (the same one tools/asn1_oracle.go turns into
//! Go struct types). Marshaling converts the JSON value into typed values that
//! implement `Marshal`; unmarshaling implements `Decode` for the schema so the
//! library's field logic produces JSON directly. Unmarshal requests are run in
//! the default (Go) explicit-tag mode (compared with Go) and in `strict_explicit`
//! mode (reported separately).
use rust_stdlib::encoding::asn1::{
    self, Any, Asn1Type, BitString, Class, Decode, Decoder, Element, Encoder, Enumerated, Error,
    ErrorKind, Flag, Integer, Marshal, ObjectIdentifier, Options, Params, RawValue, Typed,
};
use rust_stdlib::encoding::json::{self, Value};
use rust_stdlib::time::DateTime;
use std::io::{self, BufRead, Write};

type BoxError = Box<dyn std::error::Error>;

struct Schema {
    kind: String,
    params: Params,
    fields: Vec<Schema>,
    elem: Option<Box<Schema>>,
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value, BoxError> {
    value
        .get(name)
        .ok_or_else(|| format!("{name} missing").into())
}

fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str, BoxError> {
    field(value, name)?
        .as_str()
        .ok_or_else(|| format!("{name} is not text").into())
}

fn int(value: &Value) -> Result<i64, BoxError> {
    value
        .as_number()
        .and_then(|n| n.as_i64())
        .ok_or_else(|| "not an integer".into())
}

fn items(value: &Value) -> Result<&[Value], BoxError> {
    value.as_array().ok_or_else(|| "not an array".into())
}

fn unhex(s: &str) -> Result<Vec<u8>, BoxError> {
    if !s.len().is_multiple_of(2) {
        return Err("odd hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(Into::into))
        .collect()
}

fn tohex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

impl Schema {
    fn parse(value: &Value) -> Result<Self, BoxError> {
        let fields = match value.get("f") {
            Some(Value::Array(fs)) => fs.iter().map(Schema::parse).collect::<Result<_, _>>()?,
            _ => Vec::new(),
        };
        let elem = match value.get("e") {
            Some(e @ Value::Object(_)) => Some(Box::new(Schema::parse(e)?)),
            _ => None,
        };
        Ok(Schema {
            kind: text(value, "k")?.to_owned(),
            params: Params::parse(text(value, "p")?),
            fields,
            elem,
        })
    }
}

// Decoding: the schema is a `Decode` producing JSON.

fn time_json(t: &DateTime) -> Value {
    Value::Array(vec![
        t.year().into(),
        t.month().into(),
        t.day().into(),
        t.hour().into(),
        t.minute().into(),
        t.second().into(),
        t.nanosecond().into(),
        t.offset().into(),
    ])
}

fn bits_json(b: &BitString) -> Value {
    Value::object([("b", tohex(&b.bytes).into()), ("n", b.bit_length.into())])
}

fn oid_json(o: &ObjectIdentifier) -> Value {
    Value::Array(o.arcs().iter().map(|&a| a.into()).collect())
}

fn any_json(a: &Any) -> Value {
    match a {
        Any::Bool(b) => Value::object([("bool", (*b).into())]),
        Any::Integer(i) => Value::object([("int", (*i).into())]),
        Any::BitString(b) => Value::object([("bits", bits_json(b))]),
        Any::ObjectIdentifier(o) => Value::object([("oid", oid_json(o))]),
        Any::Time(t) => Value::object([("time", time_json(t))]),
        Any::String(s) => Value::object([("string", s.as_str().into())]),
        Any::OctetString(o) => Value::object([("octets", tohex(o).into())]),
        Any::Other => Value::Null,
    }
}

fn raw_json(r: &RawValue) -> Value {
    Value::object([
        ("c", r.class.bits().into()),
        ("t", r.tag.into()),
        ("x", r.is_compound.into()),
        ("b", tohex(&r.bytes).into()),
        ("f", tohex(&r.full_bytes).into()),
    ])
}

fn typed<T: asn1::Unmarshal>(
    e: &Element<'_>,
    to_json: impl Fn(T) -> Value,
) -> Result<Value, Error> {
    Typed::<T>::new().decode(e).map(to_json)
}

/// Reads one field: OPTIONAL big integers are presence-driven (Go's nil
/// `*big.Int`); everything else uses Go's zero/default rules.
fn read_field(d: &mut Decoder<'_>, schema: &Schema) -> Result<Value, Error> {
    if schema.kind == "big" && schema.params.optional {
        return Ok(d
            .optional_with(schema, &schema.params)?
            .unwrap_or(Value::Null));
    }
    d.field_with(schema, &schema.params)
}

impl Decode for Schema {
    type Output = Value;
    fn asn1_type(&self) -> Asn1Type {
        match self.kind.as_str() {
            "bool" => Typed::<bool>::new().asn1_type(),
            "int" | "int32" | "big" => Asn1Type::universal(asn1::TAG_INTEGER),
            "enum" => Typed::<Enumerated>::new().asn1_type(),
            "flag" => Typed::<Flag>::new().asn1_type(),
            "bits" => Typed::<BitString>::new().asn1_type(),
            "octets" => Typed::<Vec<u8>>::new().asn1_type(),
            "oid" => Typed::<ObjectIdentifier>::new().asn1_type(),
            "string" => Typed::<String>::new().asn1_type(),
            "time" => Typed::<DateTime>::new().asn1_type(),
            "raw" => Typed::<RawValue>::new().asn1_type(),
            "any" => Typed::<Any>::new().asn1_type(),
            _ => Asn1Type::SEQUENCE,
        }
    }
    fn decode(&self, e: &Element<'_>) -> Result<Value, Error> {
        match self.kind.as_str() {
            "bool" => typed::<bool>(e, Value::from),
            "int" => typed::<i64>(e, Value::from),
            "int32" => typed::<i32>(e, Value::from),
            "big" => typed::<Integer>(e, |i| tohex(i.as_twos_complement()).into()),
            "enum" => typed::<Enumerated>(e, |v| v.0.into()),
            "flag" => typed::<Flag>(e, |v| v.0.into()),
            "bits" => typed::<BitString>(e, |b| bits_json(&b)),
            "octets" => typed::<Vec<u8>>(e, |b| tohex(&b).into()),
            "oid" => typed::<ObjectIdentifier>(e, |o| oid_json(&o)),
            "string" => typed::<String>(e, Value::from),
            "time" => typed::<DateTime>(e, |t| time_json(&t)),
            "raw" => typed::<RawValue>(e, |r| raw_json(&r)),
            "any" => typed::<Any>(e, |a| any_json(&a)),
            "seq" => {
                let mut d = e.contents();
                let mut out = Vec::with_capacity(self.fields.len());
                for f in &self.fields {
                    out.push(read_field(&mut d, f)?);
                }
                Ok(Value::Array(out))
            }
            _ => {
                let elem = self.elem.as_deref().ok_or_else(schema_error)?;
                asn1::decode_sequence_of(elem, e).map(Value::Array)
            }
        }
    }
    fn zero(&self) -> Value {
        match self.kind.as_str() {
            "bool" | "flag" => false.into(),
            "int" | "int32" | "enum" => 0i64.into(),
            "big" | "any" => Value::Null,
            "bits" => bits_json(&BitString::default()),
            "octets" => "".into(),
            "oid" => Value::Array(Vec::new()),
            "string" => "".into(),
            "time" => time_json(&<DateTime as asn1::Unmarshal>::zero()),
            "raw" => raw_json(&RawValue::default()),
            "seq" => Value::Array(self.fields.iter().map(|f| f.zero()).collect()),
            _ => Value::Array(Vec::new()),
        }
    }
    fn default_value(&self, value: i64) -> Option<Value> {
        match self.kind.as_str() {
            "int" => Typed::<i64>::new().default_value(value).map(Value::from),
            "int32" => Typed::<i32>::new().default_value(value).map(Value::from),
            "enum" => Typed::<Enumerated>::new()
                .default_value(value)
                .map(|v| v.0.into()),
            _ => None,
        }
    }
    fn empty_explicit(&self) -> Option<Value> {
        (self.kind == "flag").then(|| true.into())
    }
}

fn schema_error() -> Error {
    Error::new(ErrorKind::Structural, "probe schema error")
}

// Encoding: JSON values become typed values implementing `Marshal`.

enum Owned {
    Bool(bool),
    Int(i64),
    Int32(i32),
    Big(Option<Integer>),
    Enum(Enumerated),
    Flag(Flag),
    Bits(BitString),
    Octets(Vec<u8>),
    Oid(ObjectIdentifier),
    Str(String),
    Time(DateTime),
    Raw(RawValue),
    Seq(Vec<(Owned, Params)>),
    SeqOf(Vec<Owned>),
}

fn owned(schema: &Schema, v: &Value) -> Result<Owned, BoxError> {
    Ok(match schema.kind.as_str() {
        "bool" => Owned::Bool(matches!(v, Value::Bool(true))),
        "flag" => Owned::Flag(Flag(matches!(v, Value::Bool(true)))),
        "int" => Owned::Int(int(v)?),
        "int32" => Owned::Int32(i32::try_from(int(v)?)?),
        "enum" => Owned::Enum(Enumerated(int(v)?)),
        "big" => Owned::Big(match v.as_str() {
            Some(h) => Some(Integer::from_twos_complement(&unhex(h)?)?),
            None => None,
        }),
        "bits" => Owned::Bits(BitString::new(
            unhex(text(v, "b")?)?,
            usize::try_from(int(field(v, "n")?)?)?,
        )),
        "octets" => Owned::Octets(unhex(v.as_str().ok_or("octets")?)?),
        "oid" => Owned::Oid(ObjectIdentifier::new(
            items(v)?.iter().map(int).collect::<Result<Vec<_>, _>>()?,
        )),
        "string" => Owned::Str(v.as_str().ok_or("string")?.to_owned()),
        "time" => {
            let f = items(v)?.iter().map(int).collect::<Result<Vec<_>, _>>()?;
            Owned::Time(DateTime::new(
                u16::try_from(f[0])?,
                u8::try_from(f[1])?,
                u8::try_from(f[2])?,
                u8::try_from(f[3])?,
                u8::try_from(f[4])?,
                u8::try_from(f[5])?,
                u32::try_from(f[6])?,
                i32::try_from(f[7])?,
            )?)
        }
        "raw" => Owned::Raw(RawValue {
            class: match int(field(v, "c")?)? {
                0 => Class::Universal,
                1 => Class::Application,
                2 => Class::ContextSpecific,
                _ => Class::Private,
            },
            tag: u32::try_from(int(field(v, "t")?)?)?,
            is_compound: matches!(field(v, "x")?, Value::Bool(true)),
            bytes: unhex(text(v, "b")?)?,
            full_bytes: unhex(text(v, "f")?)?,
        }),
        "seq" => Owned::Seq(
            schema
                .fields
                .iter()
                .zip(items(v)?)
                .map(|(f, v)| Ok((owned(f, v)?, f.params)))
                .collect::<Result<_, BoxError>>()?,
        ),
        "seqof" => {
            let elem = schema.elem.as_deref().ok_or("seqof element")?;
            Owned::SeqOf(
                items(v)?
                    .iter()
                    .map(|v| owned(elem, v))
                    .collect::<Result<_, _>>()?,
            )
        }
        other => return Err(format!("cannot marshal {other}").into()),
    })
}

macro_rules! delegate {
    ($self:ident, $v:ident => $body:expr, nil => $nil:expr) => {
        match $self {
            Owned::Bool($v) => $body,
            Owned::Int($v) => $body,
            Owned::Int32($v) => $body,
            Owned::Big(Some($v)) => $body,
            Owned::Big(None) => $nil,
            Owned::Enum($v) => $body,
            Owned::Flag($v) => $body,
            Owned::Bits($v) => $body,
            Owned::Octets($v) => $body,
            Owned::Oid($v) => $body,
            Owned::Str($v) => $body,
            Owned::Time($v) => $body,
            Owned::Raw($v) => $body,
            Owned::SeqOf($v) => $body,
            Owned::Seq(_) => unreachable!("handled by caller"),
        }
    };
}

impl Marshal for Owned {
    fn asn1_type(&self) -> Asn1Type {
        if let Owned::Seq(_) = self {
            return Asn1Type::SEQUENCE;
        }
        delegate!(self, v => Marshal::asn1_type(v), nil => Asn1Type::universal(asn1::TAG_INTEGER))
    }
    fn marshal_body(&self, params: &Params, out: &mut Vec<u8>) -> Result<(), Error> {
        if let Owned::Seq(fields) = self {
            let mut e = Encoder::new(out);
            for (value, params) in fields {
                e.field(value, params)?;
            }
            return Ok(());
        }
        // Go: marshaling a nil *big.Int fails with "empty integer".
        delegate!(self, v => Marshal::marshal_body(v, params, out), nil => Err(Error::new(ErrorKind::Structural, "empty integer")))
    }
    fn universal_tag(&self, params: &Params) -> u32 {
        if let Owned::Seq(_) = self {
            return asn1::TAG_SEQUENCE;
        }
        delegate!(self, v => Marshal::universal_tag(v, params), nil => asn1::TAG_INTEGER)
    }
    fn is_zero(&self) -> bool {
        if let Owned::Seq(fields) = self {
            return fields.iter().all(|(v, _)| v.is_zero());
        }
        delegate!(self, v => Marshal::is_zero(v), nil => true)
    }
    fn equals_default(&self, default: i64) -> Option<bool> {
        if let Owned::Seq(_) = self {
            return None;
        }
        delegate!(self, v => Marshal::equals_default(v, default), nil => None)
    }
    fn is_empty_slice(&self) -> bool {
        if let Owned::Seq(_) = self {
            return false;
        }
        delegate!(self, v => Marshal::is_empty_slice(v), nil => false)
    }
}

fn error_kind(e: &Error) -> &'static str {
    match e.kind() {
        ErrorKind::Syntax => "syntax",
        ErrorKind::Structural => "structural",
        ErrorKind::String => "string",
        ErrorKind::Time => "time",
        ErrorKind::ExplicitLength => "explicit_length",
        ErrorKind::Limit => "limit",
    }
}

fn unmarshal(schema: &Schema, der: &[u8], options: Options) -> Result<(Value, Vec<u8>), Error> {
    let mut d = Decoder::with_options(der, options)?;
    let value = read_field(&mut d, schema)?;
    Ok((value, d.remaining().to_vec()))
}

fn run(request: &Value) -> Result<Value, BoxError> {
    let schema = Schema::parse(field(request, "s")?)?;
    if text(request, "op")? == "marshal" {
        let value = owned(&schema, field(request, "v")?)?;
        return Ok(match asn1::marshal_with_params(&value, &schema.params) {
            Ok(der) => Value::object([("ok", true.into()), ("der", tohex(&der).into())]),
            Err(_) => Value::object([("ok", false.into())]),
        });
    }
    let der = unhex(text(request, "d")?)?;
    let mut out = match unmarshal(&schema, &der, Options::default()) {
        Ok((v, rest)) => {
            Value::object([("ok", true.into()), ("v", v), ("rest", tohex(&rest).into())])
        }
        Err(e) => Value::object([("ok", false.into()), ("err", error_kind(&e).into())]),
    };
    let strict_options = Options {
        strict_explicit: true,
        ..Options::default()
    };
    let strict = match unmarshal(&schema, &der, strict_options) {
        Ok((v, rest)) => {
            Value::object([("ok", true.into()), ("v", v), ("rest", tohex(&rest).into())])
        }
        Err(e) => Value::object([("ok", false.into()), ("err", error_kind(&e).into())]),
    };
    if let Value::Object(map) = &mut out {
        map.insert("strict".into(), strict);
    }
    Ok(out)
}

fn main() -> Result<(), BoxError> {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let request = line?.parse::<json::Value>()?;
        let response = run(&request)?;
        writeln!(out, "{}", response)?;
    }
    Ok(())
}
