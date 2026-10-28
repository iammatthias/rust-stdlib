//! Typed half of the Go differential in `tools/json_check.py`: marshals the
//! values described by atoms (see `tools/json_oracle.go`) into the derived
//! types below, which mirror the Go types of the oracle field for field.
//! Lives here because it needs the derive crate, which the root crate cannot
//! depend on.
#![allow(non_snake_case, dead_code)]
use rust_stdlib::encoding::json::{self, Error, Value};
use rust_stdlib_derive::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{self, BufRead, Write},
};

fn dec(field: &str) -> Vec<u8> {
    if field == "-" {
        return Vec::new();
    }
    (0..field.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&field[i..i + 2], 16).expect("hex field"))
        .collect()
}

fn enc(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".into();
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn ok(bytes: &[u8]) -> String {
    format!("ok {}", enc(bytes))
}

fn fail(err: &Error) -> String {
    let offset = match err {
        Error::SyntaxError(e) => e.offset.to_string(),
        Error::UnmarshalType(e) => format!("t{}", e.offset),
        Error::Marshaler(e) => e
            .err
            .downcast_ref::<json::SyntaxError>()
            .map_or("-".into(), |s| s.offset.to_string()),
        _ => "-".into(),
    };
    format!("err {} {offset}", enc(err.to_string().as_bytes()))
}

// ---- Marshal differential: mirrors the Go types in tools/json_oracle.go ----

struct Atoms<'a> {
    toks: &'a [&'a str],
    i: usize,
}
impl<'a> Atoms<'a> {
    fn next(&mut self) -> &'a str {
        let t = self.toks[self.i];
        self.i += 1;
        t
    }
}

trait Fill: Sized {
    fn fill(a: &mut Atoms<'_>) -> Self;
}
macro_rules! fill_int {
    ($($t:ty),+) => { $(
        impl Fill for $t {
            fn fill(a: &mut Atoms<'_>) -> Self { a.next()[1..].parse().expect("integer atom") }
        }
    )+ };
}
fill_int!(i8, i16, i32, i64, u8, u16, u32, u64);
impl Fill for f64 {
    fn fill(a: &mut Atoms<'_>) -> Self {
        f64::from_bits(u64::from_str_radix(&a.next()[1..], 16).expect("f64 atom"))
    }
}
impl Fill for f32 {
    fn fill(a: &mut Atoms<'_>) -> Self {
        f32::from_bits(u32::from_str_radix(&a.next()[1..], 16).expect("f32 atom"))
    }
}
impl Fill for bool {
    fn fill(a: &mut Atoms<'_>) -> Self {
        a.next() == "b1"
    }
}
impl Fill for String {
    fn fill(a: &mut Atoms<'_>) -> Self {
        String::from_utf8(dec(&a.next()[1..])).expect("utf-8 string atom")
    }
}
impl<T: Fill> Fill for Option<T> {
    fn fill(a: &mut Atoms<'_>) -> Self {
        (a.next() == "p").then(|| T::fill(a))
    }
}
impl<T: Fill> Fill for Vec<T> {
    fn fill(a: &mut Atoms<'_>) -> Self {
        let n: usize = a.next()[1..].parse().expect("length atom");
        (0..n).map(|_| T::fill(a)).collect()
    }
}
impl<T: Fill, const N: usize> Fill for [T; N] {
    fn fill(a: &mut Atoms<'_>) -> Self {
        std::array::from_fn(|_| T::fill(a))
    }
}
impl<K: Fill + Ord + json::MapKey, V: Fill> Fill for BTreeMap<K, V> {
    fn fill(a: &mut Atoms<'_>) -> Self {
        let n: usize = a.next()[1..].parse().expect("length atom");
        (0..n).map(|_| (K::fill(a), V::fill(a))).collect()
    }
}
impl Fill for Value {
    fn fill(a: &mut Atoms<'_>) -> Self {
        json::unmarshal(&dec(&a.next()[1..])).expect("value atom")
    }
}
/// Go's `json.Number` holds any text and only fails when marshaled. A
/// `json::Number` cannot hold invalid text, so this keeps the text and
/// builds the `Number` while marshaling, where the same error appears at the
/// same point of the output as in Go.
#[derive(Default)]
struct GoNumber(String);
impl json::Serialize for GoNumber {
    fn to_json(&self) -> Result<Value, Error> {
        json::Number::new(self.0.as_str())?.to_json()
    }
    fn serialize(&self, s: &mut json::Serializer) -> Result<(), Error> {
        json::Number::new(self.0.as_str())?.serialize(s)
    }
    fn serialize_quoted(&self, s: &mut json::Serializer) -> Result<(), Error> {
        json::Number::new(self.0.as_str())?.serialize_quoted(s)
    }
    fn is_empty_value(&self) -> bool {
        self.0.is_empty()
    }
    fn is_zero_value(&self) -> bool {
        self.0.is_empty()
    }
    fn is_json_number(&self) -> bool {
        true
    }
}
impl json::Deserialize for GoNumber {
    fn from_json(value: &Value) -> Result<Self, Error> {
        json::Number::from_json(value).map(|n| GoNumber(n.to_string()))
    }
    fn unmarshal_json(node: &json::Node<'_>, cx: &mut json::DecodeState) -> Result<Self, Error> {
        json::Number::unmarshal_json(node, cx).map(|n| GoNumber(n.to_string()))
    }
    fn json_zero() -> Result<Self, Error> {
        Ok(GoNumber::default())
    }
    const JSON_QUOTABLE: bool = true;
    const JSON_NUMBER: bool = true;
    fn json_type_name() -> String {
        json::Number::json_type_name()
    }
}
impl Fill for GoNumber {
    fn fill(a: &mut Atoms<'_>) -> Self {
        GoNumber(String::from_utf8(dec(&a.next()[1..])).expect("number atom"))
    }
}
impl Fill for json::RawMessage {
    fn fill(a: &mut Atoms<'_>) -> Self {
        json::RawMessage(dec(&a.next()[1..]))
    }
}
impl Fill for json::Bytes {
    fn fill(a: &mut Atoms<'_>) -> Self {
        json::Bytes(dec(&a.next()[1..]))
    }
}

/// Mirrors the Go type of the same name: it supplies its own JSON text.
#[derive(Default)]
struct Custom {
    Raw: String,
}
impl json::Marshaler for Custom {
    fn marshal_json(&self) -> Result<Vec<u8>, Error> {
        if self.Raw == "ERR" {
            Err(Error::Other("boom".into()))
        } else {
            Ok(self.Raw.clone().into_bytes())
        }
    }
}
impl json::Unmarshaler for Custom {
    fn unmarshal_json(&mut self, data: &[u8]) -> Result<(), Error> {
        if data == b"\"ERRDEC\"" {
            return Err(Error::Other("bad decode".into()));
        }
        self.Raw = String::from_utf8_lossy(data).into_owned();
        Ok(())
    }
}
impl json::Serialize for Custom {
    fn to_json(&self) -> Result<Value, Error> {
        json::serialize_to_value(self)
    }
    fn serialize(&self, s: &mut json::Serializer) -> Result<(), Error> {
        s.marshaler("Custom", json::Marshaler::marshal_json(self))
    }
    fn is_zero_value(&self) -> bool {
        self.Raw.is_empty()
    }
}
impl json::Deserialize for Custom {
    fn from_json(v: &Value) -> Result<Self, Error> {
        json::deserialize_from_value(v)
    }
    fn unmarshal_json(node: &json::Node<'_>, _: &mut json::DecodeState) -> Result<Self, Error> {
        let mut c = Custom::default();
        node.unmarshal_into(&mut c)?;
        Ok(c)
    }
    fn json_zero() -> Result<Self, Error> {
        Ok(Custom::default())
    }
}
impl Fill for Custom {
    fn fill(a: &mut Atoms<'_>) -> Self {
        Custom {
            Raw: String::fill(a),
        }
    }
}

macro_rules! types {
    ($($(#[$sm:meta])* struct $name:ident { $($(#[$fm:meta])* $f:ident : $t:ty),* $(,)? })+) => {
        $(
            #[derive(Serialize, Deserialize)]
            $(#[$sm])*
            struct $name { $($(#[$fm])* $f: $t),* }
            impl Fill for $name {
                fn fill(a: &mut Atoms<'_>) -> Self { $name { $($f: <$t as Fill>::fill(a)),* } }
            }
        )+
        fn unmarshal_typed(name: &str, mode: &str, data: &[u8]) -> String {
            match name {
                $(stringify!($name) => match json::unmarshal_with_options::<$name>(data, options(mode)) {
                    // Only the decode is under test here; marshal errors are
                    // covered by `marshal_typed`.
                    Ok(v) => match json::marshal(&v) {
                        Ok(b) => ok(&b),
                        Err(_) => format!("err {} -", enc(b"remarshal")),
                    },
                    Err(e) => fail(&e),
                },)+
                other => format!("err {} -", enc(format!("unknown type {other}").as_bytes())),
            }
        }
        fn marshal_typed(name: &str, mode: &str, toks: &[&str]) -> String {
            match name {
                $(stringify!($name) => {
                    let mut a = Atoms { toks, i: 0 };
                    let v = <$name as Fill>::fill(&mut a);
                    assert_eq!(a.i, toks.len(), "atoms left over");
                    marshal_mode(&v, mode)
                })+
                other => format!("err {} -", enc(format!("unknown type {other}").as_bytes())),
            }
        }
    };
}

/// Maps the letters of an "o..." mode to option switches, like the oracle.
fn options(mode: &str) -> json::Options {
    let mut out = json::Options::default();
    for c in mode.chars().skip(1) {
        out = out.join(match c {
            'e' => json::omit_empty_with_legacy_semantics(false),
            's' => json::stringify_with_legacy_semantics(false),
            'a' => json::unmarshal_array_from_any_length(false),
            'd' => json::match_case_sensitive_delimiter(false),
            'b' => json::parse_bytes_with_loose_rfc4648(false),
            'y' => json::format_bytes_with_legacy_semantics(false),
            _ => json::Options::default(),
        });
    }
    out
}

fn marshal_mode<T: json::Serialize>(v: &T, mode: &str) -> String {
    let result = match mode {
        "h" => json::marshal(v),
        "i" => json::marshal_indent(v, "> ", "  "),
        m if m.starts_with('o') => json::marshal_with_options(v, options(m)),
        _ => {
            let mut s = json::Serializer::new(false);
            v.serialize(&mut s).map(|()| s.into_bytes())
        }
    };
    match result {
        Ok(b) => ok(&b),
        Err(e) => fail(&e),
    }
}

types! {
    struct Inner {
        #[json("x,omitempty")] X: i64,
        #[json("y")] Y: String,
        #[json("z,omitempty")] Z: Vec<i64>,
    }
    struct Inner2 {
        #[json("x,omitempty")] X: i64,
        #[json("y")] Y: String,
    }
    struct Basic {
        #[json("a")] A: i64,
        #[json("b,omitempty")] B: String,
        #[json("c,omitempty")] C: bool,
        #[json("d")] D: f64,
        #[json("e,omitempty")] E: f32,
        #[json("f,string")] F: u8,
        #[json(",string")] G: i32,
        #[json("h,string")] H: String,
        #[json("i,string,omitempty")] I: bool,
        #[json("j,string")] J: f64,
        #[json("-")] Skip: i64,
        #[json("-,")] Dash: i64,
        Plain: i64,
        #[json("a'b")] Bad: i64,
        #[json("a b")] Space: i64,
        #[json("é,omitempty")] Uni: String,
        #[json("<&>")] Html: i64,
        #[json("opt,string")] Opt: Option<i64>,
        #[json("in")] In: Inner,
    }
    struct Opts {
        #[json("p1,omitempty")] P1: Option<i64>,
        #[json("p2,omitzero")] P2: Option<i64>,
        #[json("p3")] P3: Option<i64>,
        #[json("s1,omitempty")] S1: Vec<i64>,
        #[json("m1,omitempty")] M1: BTreeMap<String, i64>,
        #[json("z1,omitzero")] Z1: String,
        #[json("z2,omitzero")] Z2: i64,
        #[json("z3,omitzero")] Z3: bool,
        #[json("z4,omitzero")] Z4: f64,
        #[json("z5,omitzero")] Z5: [i64; 2],
        #[json("z6,omitzero")] Z6: Inner2,
        #[json("i1,omitempty")] I1: Value,
        #[json("r1,omitempty")] R1: json::RawMessage,
        #[json("b1,omitempty")] B1: bool,
        #[json("f1,omitempty")] F1: f64,
        #[json("a1,omitempty")] A1: [i64; 0],
        #[json("n1,omitempty")] N1: GoNumber,
        #[json("q1,omitempty,string")] Q1: Option<String>,
    }
    struct Containers {
        Ints: BTreeMap<i64, String>,
        Uints: BTreeMap<u8, bool>,
        Strs: BTreeMap<String, Vec<String>>,
        Arr: [String; 3],
        Nested: Vec<Vec<i64>>,
        Ptrs: Vec<Option<String>>,
        Bytes: json::Bytes,
        Num: GoNumber,
        Any: Value,
        Raw: json::RawMessage,
        MapAny: BTreeMap<String, Value>,
        I64s: BTreeMap<i64, i8>,
    }
    struct Base {
        #[json("id")] ID: i64,
        #[json("name,omitempty")] Name: String,
        #[json("-")] Hidden: i64,
    }
    struct Base2 {
        #[json("id")] ID: i64,
        Z: i64,
    }
    struct L2 { Deep: i64 }
    struct L1 {
        #[json(embedded)] L2: L2,
        Mid: i64,
    }
    struct A1 { V: i64 }
    struct A2 {
        V: i64,
        #[json("w")] W: i64,
    }
    struct A3 { #[json("V")] V: i64 }
    struct Embed1 {
        #[json(embedded)] Base: Base,
        Name: String,
        Own: i64,
    }
    struct Embed2 {
        #[json(embedded)] Base: Base,
        #[json(embedded)] Base2: Base2,
        Last: i64,
    }
    struct Embed3 {
        #[json(embedded)] Base: Base,
        #[json("nested")] X: Base2,
    }
    struct Embed4 {
        #[json(embedded)] A1: A1,
        #[json(embedded)] A2: A2,
        End: i64,
    }
    struct Embed5 {
        #[json(embedded)] A1: A1,
        #[json(embedded)] A3: A3,
    }
    struct Embed6 {
        Top: i64,
        #[json(embedded)] L1: L1,
    }
    struct Embed7 {
        #[json(embedded)] Base: Option<Base>,
        #[json("tail,omitempty")] Tail: String,
    }
    struct Embed8 {
        #[json("b8")] Base: Base,
        #[json(embedded)] Base2: Base2,
    }
    struct Customs {
        #[json("a")] A: Custom,
        #[json("b")] B: Option<Custom>,
        #[json("c")] C: Vec<Custom>,
        #[json("d")] D: BTreeMap<String, Custom>,
        #[json("e,omitempty")] E: Custom,
        #[json("f,omitzero")] F: Custom,
        #[json(",string")] G: Custom,
    }
    struct Floats {
        F1: f64, F2: f64, F3: f64, F4: f64,
        G1: f32, G2: f32, G3: f32,
        #[json(",string")] S1: f64,
        #[json(",string")] S2: f32,
    }
    struct Strings {
        S1: String,
        S2: String,
        #[json(",omitempty")] S3: String,
        M: BTreeMap<String, i64>,
        #[json("<k>&")] K: BTreeMap<String, String>,
        #[json(",string")] Q: String,
    }
}

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line?;
        let f: Vec<&str> = line.split_whitespace().collect();
        let res = match f[0] {
            "marshal" => marshal_typed(f[1], f[2], &f[3..]),
            "unmarshaltyped" => unmarshal_typed(f[1], f[2], &dec(f[3])),
            other => format!("err {} -", enc(format!("unknown op {other}").as_bytes())),
        };
        writeln!(out, "{res}")?;
    }
    Ok(())
}
