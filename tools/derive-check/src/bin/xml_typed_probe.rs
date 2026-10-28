//! Rust twin of `tools/xml_typed.go`: typed Marshal/Unmarshal through the
//! `Marshal`/`Unmarshal` derives, driven by `tools/xml_check.py`.
//!
//! Requests (tab separated, byte strings as hex):
//!   M <struct|bare:kind> <prefix> <indent> <json value>
//!   U <struct|bare:kind> <input>
#![allow(non_snake_case)]
use rust_stdlib::encoding::{
    base64, json,
    xml::{
        self, Attr, Encoder, Error, Kind, Marshal as MarshalTrait, Marshaler, MarshalerAttr, Name,
        StartElement, TextMarshaler, TextUnmarshaler, Token, Unmarshal as UnmarshalTrait,
        Unmarshaler, UnmarshalerAttr, View,
    },
};
use rust_stdlib_derive::{Marshal, Unmarshal};
use std::{
    collections::BTreeMap,
    io::{self, BufRead, Write},
};

fn hx(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn err_text(e: &Error) -> String {
    e.to_string()
}

fn result(r: Result<Vec<u8>, Error>) -> String {
    match r {
        Ok(out) => format!("OK {}", hx(&out)),
        Err(e) => format!("ERR {}", hx(err_text(&e).as_bytes())),
    }
}

// ---- JSON to typed values --------------------------------------------------

trait FromValue: Sized {
    fn from_value(v: &json::Value) -> Self;
}

fn field<T: FromValue + Default>(v: &json::Value, key: &str) -> T {
    match v.get(key) {
        Some(x) => T::from_value(x),
        None => T::default(),
    }
}

macro_rules! from_int {
    ($($t:ty),*) => {$(
        impl FromValue for $t {
            fn from_value(v: &json::Value) -> Self {
                match v {
                    json::Value::Number(n) => n.as_str().parse().expect("integer"),
                    _ => Self::default(),
                }
            }
        }
    )*};
}
from_int!(i8, i16, i32, i64, isize, u8, u16, u32, u64, usize);

impl FromValue for f32 {
    fn from_value(v: &json::Value) -> Self {
        match v {
            json::Value::Number(n) => n.as_str().parse().expect("float"),
            _ => 0.0,
        }
    }
}
impl FromValue for f64 {
    fn from_value(v: &json::Value) -> Self {
        match v {
            json::Value::Number(n) => n.as_str().parse().expect("float"),
            _ => 0.0,
        }
    }
}
impl FromValue for bool {
    fn from_value(v: &json::Value) -> Self {
        matches!(v, json::Value::Bool(true))
    }
}
impl FromValue for String {
    fn from_value(v: &json::Value) -> Self {
        v.as_str().unwrap_or_default().to_string()
    }
}
impl<T: FromValue> FromValue for Option<T> {
    fn from_value(v: &json::Value) -> Self {
        match v {
            json::Value::Null => None,
            other => Some(T::from_value(other)),
        }
    }
}
impl<T: FromValue + UnmarshalTrait> FromValue for Vec<T> {
    fn from_value(v: &json::Value) -> Self {
        match v {
            json::Value::Array(items) => items.iter().map(T::from_value).collect(),
            // []byte travels as base64, as Go's encoding/json writes it.
            json::Value::String(s) => base64::STANDARD
                .decode(s)
                .expect("base64")
                .into_iter()
                .filter_map(T::xml_from_byte)
                .collect(),
            _ => Vec::new(),
        }
    }
}
impl<T: FromValue + Default + Copy, const N: usize> FromValue for [T; N] {
    fn from_value(v: &json::Value) -> Self {
        let mut out = [T::default(); N];
        if let json::Value::Array(items) = v {
            for (slot, item) in out.iter_mut().zip(items) {
                *slot = T::from_value(item);
            }
        }
        out
    }
}
impl<T: FromValue> FromValue for BTreeMap<String, T> {
    fn from_value(v: &json::Value) -> Self {
        match v {
            json::Value::Object(m) => m
                .iter()
                .map(|(k, x)| (k.clone(), T::from_value(x)))
                .collect(),
            _ => BTreeMap::new(),
        }
    }
}
impl FromValue for Name {
    fn from_value(v: &json::Value) -> Self {
        Name {
            space: field(v, "Space"),
            local: field(v, "Local"),
        }
    }
}
impl FromValue for Attr {
    fn from_value(v: &json::Value) -> Self {
        Attr {
            name: field(v, "Name"),
            value: field(v, "Value"),
        }
    }
}

macro_rules! menu {
    ($($(#[$sm:meta])* struct $name:ident { $($(#[$fm:meta])* $f:ident : $t:ty,)* })*) => {
        $(
            $(#[$sm])*
            #[allow(non_snake_case)]
            #[derive(Debug, Default)]
            struct $name { $($(#[$fm])* $f: $t,)* }
            impl FromValue for $name {
                fn from_value(v: &json::Value) -> Self {
                    Self { $($f: field(v, stringify!($f)),)* }
                }
            }
        )*
        fn marshal_named(name: &str, spec: &str, prefix: &str, indent: &str) -> Option<String> {
            if let Some((mode, rest)) = name.split_once(':') {
                if mode.starts_with("el") {
                    return match rest {
                        $(stringify!($name) => Some(marshal_el_case::<$name>(spec, prefix, indent, &start_template(mode))),)*
                        _ => None,
                    };
                }
            }
            match name {
                $(stringify!($name) => Some(marshal_case::<$name>(spec, prefix, indent)),)*
                _ => None,
            }
        }
        fn unmarshal_named(name: &str, input: &[u8]) -> Option<String> {
            match name {
                $(stringify!($name) => Some(unmarshal_case::<$name>(input)),)*
                _ => None,
            }
        }
    };
}

fn marshal_case<T: FromValue + MarshalTrait>(spec: &str, prefix: &str, indent: &str) -> String {
    let v = T::from_value(&(spec).parse::<json::Value>().expect("json spec"));
    format!(
        "{} | {}",
        result(xml::marshal(&v)),
        result(xml::marshal_indent(&v, prefix, indent))
    )
}

/// The start templates Go's oracle uses for `Encoder::encode_element`.
fn start_template(mode: &str) -> StartElement {
    match mode {
        "el" => StartElement {
            name: Name::new("urn:s", "wrap"),
            attr: vec![
                Attr {
                    name: Name::new("", "k"),
                    value: "v<&>".into(),
                },
                Attr {
                    name: Name::new("urn:q", "q"),
                    value: "w".into(),
                },
                Attr {
                    name: Name::new("urn:s", "s"),
                    value: "x".into(),
                },
            ],
        },
        "elplain" => StartElement {
            name: Name::new("", "wrap"),
            attr: Vec::new(),
        },
        "elbad" => StartElement {
            name: Name::new("urn:s", ""),
            attr: Vec::new(),
        },
        other => panic!("unknown start template {other}"),
    }
}

fn encode_el<T: MarshalTrait>(
    v: &T,
    prefix: &str,
    indent: &str,
    start: &StartElement,
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    {
        let mut enc = Encoder::new(&mut out);
        enc.indent(prefix, indent);
        enc.encode_element(v, start.clone())?;
        enc.close()?;
    }
    Ok(out)
}

fn marshal_el_case<T: FromValue + MarshalTrait>(
    spec: &str,
    prefix: &str,
    indent: &str,
    start: &StartElement,
) -> String {
    let v = T::from_value(&(spec).parse::<json::Value>().expect("json spec"));
    format!(
        "{} | {}",
        result(encode_el(&v, "", "", start)),
        result(encode_el(&v, prefix, indent, start))
    )
}

fn unmarshal_case<T: Default + MarshalTrait + UnmarshalTrait>(input: &[u8]) -> String {
    let mut v = T::default();
    let status = match xml::unmarshal_into(input, &mut v) {
        Ok(()) => "OK".to_string(),
        Err(e) => format!("ERR {}", hx(err_text(&e).as_bytes())),
    };
    format!("U {} | {}", status, result(xml::marshal(&v)))
}

// ---- custom marshalers --------------------------------------------------------

#[derive(Debug, Default, Clone)]
struct Upper(String);

impl MarshalTrait for Upper {
    fn xml_view(&self) -> View<'_> {
        View::Str(&self.0)
    }
    fn xml_type_name(&self) -> &'static str {
        "Upper"
    }
    fn xml_type_string(&self) -> String {
        "Upper".into()
    }
    fn xml_elem_type_string() -> String {
        "Upper".into()
    }
    fn xml_marshaler(&self) -> Option<&dyn Marshaler> {
        Some(self)
    }
}
impl Marshaler for Upper {
    fn marshal_xml(&self, e: &mut Encoder<'_>, start: StartElement) -> Result<(), Error> {
        e.encode_element(&self.0.to_uppercase(), start)
    }
}
impl UnmarshalTrait for Upper {
    fn xml_kind(&self) -> Kind {
        Kind::Scalar
    }
    fn xml_type_string(&self) -> String {
        "Upper".into()
    }
    fn xml_elem_type_string() -> String {
        "Upper".into()
    }
    fn xml_unmarshaler(&mut self) -> Option<&mut dyn Unmarshaler> {
        Some(self)
    }
}
impl Unmarshaler for Upper {
    fn unmarshal_xml(
        &mut self,
        d: &mut xml::Decoder<'_>,
        start: StartElement,
    ) -> Result<(), Error> {
        let mut s = String::new();
        d.decode_element_into(&mut s, Some(&start))?;
        self.0 = s.to_lowercase();
        Ok(())
    }
}
impl FromValue for Upper {
    fn from_value(v: &json::Value) -> Self {
        Upper(String::from_value(v))
    }
}

#[derive(Debug, Default, Clone)]
struct Pair {
    A: String,
    B: String,
}

impl MarshalTrait for Pair {
    fn xml_view(&self) -> View<'_> {
        View::Unsupported
    }
    fn xml_type_name(&self) -> &'static str {
        "Pair"
    }
    fn xml_type_string(&self) -> String {
        "Pair".into()
    }
    fn xml_elem_type_string() -> String {
        "Pair".into()
    }
    fn xml_marshaler(&self) -> Option<&dyn Marshaler> {
        Some(self)
    }
}
impl Marshaler for Pair {
    fn marshal_xml(&self, e: &mut Encoder<'_>, mut start: StartElement) -> Result<(), Error> {
        start.attr.push(Attr {
            name: Name::new("", "a"),
            value: self.A.clone(),
        });
        e.encode_token(Token::StartElement(start.clone()))?;
        e.encode_token(Token::CharData(xml::CharData(self.B.clone().into_bytes())))?;
        e.encode_token(Token::Comment(xml::Comment(b"pair".to_vec())))?;
        e.encode_token(Token::EndElement(start.end()))
    }
}
impl UnmarshalTrait for Pair {
    fn xml_kind(&self) -> Kind {
        Kind::Unknown
    }
    fn xml_type_string(&self) -> String {
        "Pair".into()
    }
    fn xml_elem_type_string() -> String {
        "Pair".into()
    }
    fn xml_unmarshaler(&mut self) -> Option<&mut dyn Unmarshaler> {
        Some(self)
    }
}
impl Unmarshaler for Pair {
    fn unmarshal_xml(
        &mut self,
        d: &mut xml::Decoder<'_>,
        start: StartElement,
    ) -> Result<(), Error> {
        for a in &start.attr {
            if a.name.local == "a" {
                self.A = a.value.clone();
            }
        }
        loop {
            match d.token()? {
                Token::CharData(t) => self.B.push_str(&String::from_utf8_lossy(&t.0)),
                Token::EndElement(_) => return Ok(()),
                Token::StartElement(_) => d.skip()?,
                _ => {}
            }
        }
    }
}
impl FromValue for Pair {
    fn from_value(v: &json::Value) -> Self {
        Pair {
            A: field(v, "A"),
            B: field(v, "B"),
        }
    }
}

macro_rules! plain_marshaler {
    ($name:ident, $body:expr) => {
        impl MarshalTrait for $name {
            fn xml_view(&self) -> View<'_> {
                View::Unsupported
            }
            fn xml_type_name(&self) -> &'static str {
                stringify!($name)
            }
            fn xml_type_string(&self) -> String {
                stringify!($name).into()
            }
            fn xml_elem_type_string() -> String {
                stringify!($name).into()
            }
            fn xml_marshaler(&self) -> Option<&dyn Marshaler> {
                Some(self)
            }
        }
        impl Marshaler for $name {
            fn marshal_xml(&self, e: &mut Encoder<'_>, start: StartElement) -> Result<(), Error> {
                let f: fn(&$name, &mut Encoder<'_>, StartElement) -> Result<(), Error> = $body;
                f(self, e, start)
            }
        }
        impl FromValue for $name {
            fn from_value(v: &json::Value) -> Self {
                $name { V: field(v, "V") }
            }
        }
    };
}

#[derive(Debug, Default, Unmarshal)]
struct Leaky {
    V: String,
}
plain_marshaler!(Leaky, |_l, e, start| e
    .encode_token(Token::StartElement(start)));

#[derive(Debug, Default, Unmarshal)]
struct Overclose {
    V: String,
}
plain_marshaler!(Overclose, |_o, e, start| {
    e.encode_token(Token::StartElement(start.clone()))?;
    e.encode_token(Token::EndElement(start.end()))?;
    e.encode_token(Token::EndElement(start.end()))
});

#[derive(Debug, Default)]
struct Failing {
    V: String,
}
plain_marshaler!(Failing, |f, _e, _start| Err(Error::msg(format!(
    "marshal failed: {}",
    f.V
))));
impl UnmarshalTrait for Failing {
    fn xml_kind(&self) -> Kind {
        Kind::Unknown
    }
    fn xml_type_string(&self) -> String {
        "Failing".into()
    }
    fn xml_elem_type_string() -> String {
        "Failing".into()
    }
    fn xml_unmarshaler(&mut self) -> Option<&mut dyn Unmarshaler> {
        Some(self)
    }
}
impl Unmarshaler for Failing {
    fn unmarshal_xml(&mut self, _d: &mut xml::Decoder<'_>, _s: StartElement) -> Result<(), Error> {
        Err(Error::msg("unmarshal failed"))
    }
}

#[derive(Debug, Default, Marshal)]
struct Lazy {
    V: String,
}
impl UnmarshalTrait for Lazy {
    fn xml_kind(&self) -> Kind {
        Kind::Unknown
    }
    fn xml_type_string(&self) -> String {
        "Lazy".into()
    }
    fn xml_elem_type_string() -> String {
        "Lazy".into()
    }
    fn xml_unmarshaler(&mut self) -> Option<&mut dyn Unmarshaler> {
        Some(self)
    }
}
impl Unmarshaler for Lazy {
    fn unmarshal_xml(&mut self, _d: &mut xml::Decoder<'_>, _s: StartElement) -> Result<(), Error> {
        Ok(())
    }
}
impl FromValue for Lazy {
    fn from_value(v: &json::Value) -> Self {
        Lazy { V: field(v, "V") }
    }
}

#[derive(Debug, Default, Marshal)]
struct RawUser {
    V: String,
}
impl UnmarshalTrait for RawUser {
    fn xml_kind(&self) -> Kind {
        Kind::Unknown
    }
    fn xml_type_string(&self) -> String {
        "RawUser".into()
    }
    fn xml_elem_type_string() -> String {
        "RawUser".into()
    }
    fn xml_unmarshaler(&mut self) -> Option<&mut dyn Unmarshaler> {
        Some(self)
    }
}
impl Unmarshaler for RawUser {
    fn unmarshal_xml(&mut self, d: &mut xml::Decoder<'_>, _s: StartElement) -> Result<(), Error> {
        d.raw_token().map(|_| ())
    }
}
impl FromValue for RawUser {
    fn from_value(v: &json::Value) -> Self {
        RawUser { V: field(v, "V") }
    }
}

#[derive(Debug, Default, Clone)]
struct Txt(String);

impl MarshalTrait for Txt {
    fn xml_view(&self) -> View<'_> {
        View::Str(&self.0)
    }
    fn xml_type_name(&self) -> &'static str {
        "Txt"
    }
    fn xml_type_string(&self) -> String {
        "Txt".into()
    }
    fn xml_elem_type_string() -> String {
        "Txt".into()
    }
    fn xml_text_marshaler(&self) -> Option<&dyn TextMarshaler> {
        Some(self)
    }
}
impl TextMarshaler for Txt {
    fn marshal_text(&self) -> Result<Vec<u8>, Error> {
        if self.0 == "fail" {
            return Err(Error::msg("text marshal failed"));
        }
        Ok(format!("txt:{}", self.0).into_bytes())
    }
}
impl UnmarshalTrait for Txt {
    fn xml_kind(&self) -> Kind {
        Kind::Scalar
    }
    fn xml_type_string(&self) -> String {
        "Txt".into()
    }
    fn xml_elem_type_string() -> String {
        "Txt".into()
    }
    fn xml_text_unmarshaler(&mut self) -> Option<&mut dyn TextUnmarshaler> {
        Some(self)
    }
}
impl TextUnmarshaler for Txt {
    fn unmarshal_text(&mut self, b: &[u8]) -> Result<(), Error> {
        let s = String::from_utf8_lossy(b).into_owned();
        if s == "fail" {
            return Err(Error::msg("text unmarshal failed"));
        }
        self.0 = s.strip_prefix("txt:").unwrap_or(&s).to_string();
        Ok(())
    }
}
impl FromValue for Txt {
    fn from_value(v: &json::Value) -> Self {
        Txt(String::from_value(v))
    }
}

#[derive(Debug, Default, Clone)]
struct AttrVal(String);

impl MarshalTrait for AttrVal {
    fn xml_view(&self) -> View<'_> {
        View::Str(&self.0)
    }
    fn xml_type_name(&self) -> &'static str {
        "AttrVal"
    }
    fn xml_type_string(&self) -> String {
        "AttrVal".into()
    }
    fn xml_elem_type_string() -> String {
        "AttrVal".into()
    }
    fn xml_attr_marshaler(&self) -> Option<&dyn MarshalerAttr> {
        Some(self)
    }
}
impl MarshalerAttr for AttrVal {
    fn marshal_xml_attr(&self, name: Name) -> Result<Attr, Error> {
        match self.0.as_str() {
            "skip" => Ok(Attr::default()),
            "fail" => Err(Error::msg("attr marshal failed")),
            s => Ok(Attr {
                name,
                value: format!("A-{s}"),
            }),
        }
    }
}
impl UnmarshalTrait for AttrVal {
    fn xml_kind(&self) -> Kind {
        Kind::Scalar
    }
    fn xml_type_string(&self) -> String {
        "AttrVal".into()
    }
    fn xml_elem_type_string() -> String {
        "AttrVal".into()
    }
    fn xml_attr_unmarshaler(&mut self) -> Option<&mut dyn UnmarshalerAttr> {
        Some(self)
    }
}
impl UnmarshalerAttr for AttrVal {
    fn unmarshal_xml_attr(&mut self, attr: Attr) -> Result<(), Error> {
        if attr.value == "fail" {
            return Err(Error::msg("attr unmarshal failed"));
        }
        self.0 = attr
            .value
            .strip_prefix("A-")
            .unwrap_or(&attr.value)
            .to_string();
        Ok(())
    }
}
impl FromValue for AttrVal {
    fn from_value(v: &json::Value) -> Self {
        AttrVal(String::from_value(v))
    }
}

// ---- the struct menu ----------------------------------------------------------

menu! {
    #[derive(Marshal, Unmarshal)]
    struct Scalars {
        #[xml("scalars")] XMLName: Name,
        #[xml("b")] B: bool,
        #[xml("i")] I: isize,
        #[xml("i8")] I8: i8,
        #[xml("i16")] I16: i16,
        #[xml("i32")] I32: i32,
        #[xml("i64")] I64: i64,
        #[xml("u")] U: usize,
        #[xml("u8")] U8: u8,
        #[xml("u16")] U16: u16,
        #[xml("u32")] U32: u32,
        #[xml("u64")] U64: u64,
        #[xml("f32")] F32: f32,
        #[xml("f64")] F64: f64,
        #[xml("s")] S: String,
    }
    #[derive(Marshal, Unmarshal)]
    struct Attrs {
        #[xml("attrs")] XMLName: Name,
        #[xml("s,attr")] S: String,
        #[xml("i,attr")] I: isize,
        #[xml("b,attr")] B: bool,
        #[xml("f,attr")] F: f64,
        #[xml("e,attr,omitempty")] E: String,
        #[xml("n,attr,omitempty")] N: isize,
        #[xml("p,attr")] P: Option<String>,
        #[xml("q,attr,omitempty")] Q: Option<isize>,
        #[xml("urn:x ns,attr")] Ns: String,
        #[xml("urn:y ns2,attr")] Ns2: String,
        #[xml("http://www.w3.org/XML/1998/namespace lang,attr,omitempty")] Xl: String,
        #[xml("l,attr")] L: Vec<String>,
        #[xml(",chardata")] Text: String,
    }
    #[derive(Marshal, Unmarshal)]
    struct Paths {
        #[xml("paths")] XMLName: Name,
        #[xml("x>y>a")] A: String,
        #[xml("x>y>b")] B: String,
        #[xml("x>c")] C: String,
        #[xml("x>d")] D: Vec<String>,
        #[xml("z")] E: String,
        #[xml("x>y>f")] F: String,
        #[xml("p>q")] G: Option<String>,
        #[xml("p>r")] H: Vec<isize>,
        #[xml("x>y>z>i,omitempty")] I: String,
    }
    #[derive(Marshal, Unmarshal)]
    struct Content {
        #[xml("content")] XMLName: Name,
        #[xml("id,attr")] ID: String,
        #[xml(",chardata")] Text: String,
        #[xml(",comment")] Note: String,
        #[xml("item")] Items: Vec<String>,
    }
    #[derive(Marshal, Unmarshal)]
    struct Cdata {
        #[xml("cdata")] XMLName: Name,
        #[xml(",cdata")] Data: String,
        #[xml("o")] Other: String,
    }
    #[derive(Marshal, Unmarshal)]
    struct Inner {
        #[xml("inner")] XMLName: Name,
        #[xml(",innerxml")] Raw: String,
        #[xml("a,attr")] Attr: String,
    }
    #[derive(Marshal, Unmarshal)]
    struct InnerBytes {
        #[xml("innerbytes")] XMLName: Name,
        #[xml(",innerxml")] Raw: Vec<u8>,
        #[xml("t")] T: String,
    }
    #[derive(Marshal, Unmarshal)]
    struct Comments {
        #[xml("comments")] XMLName: Name,
        #[xml(",comment")] C1: String,
        #[xml("e")] E: String,
        #[xml(",comment")] C2: Vec<u8>,
    }
    #[derive(Marshal, Unmarshal)]
    struct Child {
        XMLName: Name,
        #[xml("name,attr")] Name: String,
        #[xml(",chardata")] Value: String,
    }
    #[derive(Marshal, Unmarshal)]
    struct Anys {
        #[xml("anys")] XMLName: Name,
        #[xml("name")] Name: String,
        #[xml(",any")] Rest: Vec<Child>,
        #[xml(",any,attr")] Extra: Vec<Attr>,
    }
    #[derive(Marshal, Unmarshal)]
    struct Leaf {
        #[xml("v")] V: String,
        #[xml("n,attr")] N: isize,
    }
    #[derive(Marshal, Unmarshal)]
    struct Ptrs {
        #[xml("ptrs")] XMLName: Name,
        #[xml("p")] P: Option<String>,
        #[xml("q")] Q: Option<Leaf>,
        #[xml("r")] R: Vec<Option<Leaf>>,
        #[xml("l")] L: Vec<isize>,
        #[xml("b")] B: Vec<u8>,
        #[xml("a")] A: [isize; 3],
        #[xml("o,omitempty")] O: Option<isize>,
    }
    #[derive(Marshal, Unmarshal)]
    struct Tree {
        #[xml("tree")] XMLName: Name,
        #[xml("v,attr")] Value: String,
        #[xml("tree")] Kids: Vec<Tree>,
    }
    #[derive(Marshal, Unmarshal)]
    struct Base {
        #[xml("id,attr,omitempty")] ID: String,
        #[xml("title")] Title: String,
    }
    #[derive(Marshal, Unmarshal)]
    struct Derived {
        #[xml(embed)] Base: Base,
        #[xml("derived")] XMLName: Name,
        #[xml("title2")] Title2: String,
        #[xml("extra")] Extra: String,
    }
    #[derive(Marshal, Unmarshal)]
    struct Shadow {
        #[xml(embed)] Base: Base,
        #[xml("shadow")] XMLName: Name,
        #[xml("title")] Title: String,
    }
    #[derive(Marshal, Unmarshal)]
    struct PtrEmbed {
        #[xml(embed)] Base: Option<Base>,
        #[xml("ptrembed")] XMLName: Name,
        #[xml("extra")] Extra: String,
    }
    #[derive(Marshal, Unmarshal)]
    struct BaseEl {
        #[xml("title")] Title: String,
        #[xml("note,omitempty")] Note: String,
    }
    #[derive(Marshal, Unmarshal)]
    struct PtrEmbedEl {
        #[xml(embed)] BaseEl: Option<BaseEl>,
        #[xml("ptrembedel")] XMLName: Name,
        #[xml("extra")] Extra: String,
    }
    #[derive(Marshal, Unmarshal)]
    struct Conflict {
        #[xml("x")] A: String,
        #[xml("x")] B: String,
    }
    #[derive(Marshal, Unmarshal)]
    struct ConflictPath {
        #[xml("x>y")] A: String,
        #[xml("x")] B: String,
    }
    #[derive(Marshal, Unmarshal)]
    struct BadFlags {
        #[xml("a,attr,chardata")] A: String,
    }
    #[derive(Marshal, Unmarshal)]
    struct BadChain {
        #[xml("a>b,attr")] A: String,
    }
    #[derive(Marshal, Unmarshal)]
    struct Trailing {
        #[xml("a>")] A: String,
    }
    #[derive(Marshal, Unmarshal)]
    struct NsNoName {
        #[xml("urn:x ,attr")] A: String,
    }
    #[derive(Marshal, Unmarshal)]
    struct OmitBad {
        #[xml(",chardata,omitempty")] A: String,
    }
    #[derive(Marshal, Unmarshal)]
    struct Named {
        #[xml("real")] XMLName: Name,
        #[xml("v")] V: String,
    }
    #[derive(Marshal, Unmarshal)]
    struct UsesNamed {
        #[xml("other")] N: Named,
    }
    #[derive(Marshal, Unmarshal)]
    struct UsesNamedOK {
        #[xml("usesnamedok")] XMLName: Name,
        #[xml("real")] N: Named,
        M: Named,
        L: Vec<Named>,
    }
    #[derive(Marshal, Unmarshal)]
    struct NsItem {
        XMLName: Name,
        #[xml(",chardata")] V: String,
        #[xml("http://x.org/p/k,attr")] K: String,
    }
    #[derive(Marshal, Unmarshal)]
    struct Nss {
        #[xml("urn:a root")] XMLName: Name,
        #[xml("urn:b child")] A: String,
        #[xml("urn:b child2,attr")] B: String,
        #[xml("urn:c c")] C: String,
        #[xml("d")] D: String,
        #[xml("urn:a item")] L: Vec<NsItem>,
    }
    #[derive(Marshal, Unmarshal)]
    struct NoNs {
        #[xml("")] XMLName: Name,
        #[xml("v")] V: String,
    }
    #[derive(Marshal, Unmarshal)]
    struct Omit {
        #[xml("omit")] XMLName: Name,
        #[xml("s,omitempty")] S: String,
        #[xml("i,omitempty")] I: isize,
        #[xml("b,omitempty")] B: bool,
        #[xml("f,omitempty")] F: f64,
        #[xml("l,omitempty")] L: Vec<String>,
        #[xml("p,omitempty")] P: Option<String>,
        #[xml("q,omitempty")] Q: Option<Leaf>,
        #[xml("st,omitempty")] St: Leaf,
        #[xml("by,omitempty")] By: Vec<u8>,
        #[xml("m,omitempty")] M: BTreeMap<String, isize>,
    }
    #[derive(Marshal, Unmarshal)]
    struct Maps {
        #[xml("maps")] XMLName: Name,
        #[xml("m")] M: BTreeMap<String, isize>,
    }
    #[derive(Marshal, Unmarshal)]
    struct Defaults {
        Title: String,
        #[xml(",attr")] Count: isize,
        #[xml(",chardata")] Body: String,
    }
    #[derive(Marshal, Unmarshal)]
    struct BadComment {
        #[xml("badcomment")] XMLName: Name,
        #[xml(",comment")] C: String,
    }
    #[derive(Marshal, Unmarshal)]
    struct BadCommentType {
        #[xml("badcommenttype")] XMLName: Name,
        #[xml(",comment")] C: isize,
    }
    #[derive(Marshal, Unmarshal)]
    struct Chars {
        #[xml("chars")] XMLName: Name,
        #[xml(",chardata")] I: isize,
        #[xml(",cdata")] U: usize,
        #[xml(",chardata")] F: f32,
        #[xml(",chardata")] B: bool,
        #[xml(",chardata")] Y: Vec<u8>,
        #[xml(",chardata")] S: Option<String>,
    }
    #[derive(Marshal, Unmarshal)]
    struct Customs {
        #[xml("customs")] XMLName: Name,
        #[xml("u")] U: Upper,
        #[xml("us")] Us: Vec<Upper>,
        #[xml("up")] Up: Option<Upper>,
        #[xml("p")] P: Pair,
        #[xml("t")] T: Txt,
        #[xml("ts")] Ts: Vec<Txt>,
        #[xml("ta,attr")] TA: Txt,
        #[xml(",chardata")] TC: Txt,
        #[xml("av,attr")] AV: AttrVal,
        #[xml("avs,attr")] AVs: Vec<AttrVal>,
        #[xml("avp,attr")] AVp: Option<AttrVal>,
    }
    #[derive(Marshal, Unmarshal)]
    struct LeakyHolder {
        #[xml("leakyholder")] XMLName: Name,
        #[xml("l")] L: Leaky,
    }
    #[derive(Marshal, Unmarshal)]
    struct OverHolder {
        #[xml("overholder")] XMLName: Name,
        #[xml("o")] O: Overclose,
    }
    #[derive(Marshal, Unmarshal)]
    struct FailHolder {
        #[xml("failholder")] XMLName: Name,
        #[xml("f")] F: Failing,
    }
    #[derive(Marshal, Unmarshal)]
    struct LazyHolder {
        #[xml("lazyholder")] XMLName: Name,
        #[xml("l")] L: Lazy,
    }
    #[derive(Marshal, Unmarshal)]
    struct RawHolder {
        #[xml("rawholder")] XMLName: Name,
        #[xml("r")] R: RawUser,
    }
    #[derive(Marshal, Unmarshal)]
    struct NameHolder {
        #[xml("nameholder")] XMLName: Name,
        #[xml("n")] N: Name,
        #[xml("a,attr")] A: Attr,
    }
}

// ---- bare values ----------------------------------------------------------------

fn bare_value<T: FromValue>(spec: &str) -> T {
    T::from_value(&(spec).parse::<json::Value>().expect("json spec"))
}

fn bare_marshal(name: &str, spec: &str, prefix: &str, indent: &str) -> String {
    fn both<T: MarshalTrait>(v: &T, prefix: &str, indent: &str) -> String {
        format!(
            "{} | {}",
            result(xml::marshal(v)),
            result(xml::marshal_indent(v, prefix, indent))
        )
    }
    match name {
        "int" => both(&bare_value::<isize>(spec), prefix, indent),
        "int8" => both(&bare_value::<i8>(spec), prefix, indent),
        "uint16" => both(&bare_value::<u16>(spec), prefix, indent),
        "uint64" => both(&bare_value::<u64>(spec), prefix, indent),
        "float32" => both(&bare_value::<f32>(spec), prefix, indent),
        "float64" => both(&bare_value::<f64>(spec), prefix, indent),
        "f32bits" => both(&f32::from_bits(spec.parse().expect("bits")), prefix, indent),
        "f64bits" => both(&f64::from_bits(spec.parse().expect("bits")), prefix, indent),
        "bool" => both(&bare_value::<bool>(spec), prefix, indent),
        "string" => both(&bare_value::<String>(spec), prefix, indent),
        "strings" => both(&bare_value::<Vec<String>>(spec), prefix, indent),
        "ints" => both(&bare_value::<Vec<isize>>(spec), prefix, indent),
        "bytes" => both(&bare_value::<Vec<u8>>(spec), prefix, indent),
        "bytearr" => both(&bare_value::<[u8; 2]>(spec), prefix, indent),
        "optstr" => both(&bare_value::<Option<String>>(spec), prefix, indent),
        "map" => both(&bare_value::<BTreeMap<String, isize>>(spec), prefix, indent),
        "nil" => both(&(), prefix, indent),
        "upper" => both(&bare_value::<Upper>(spec), prefix, indent),
        "txt" => both(&bare_value::<Txt>(spec), prefix, indent),
        "name" => both(&bare_value::<Name>(spec), prefix, indent),
        other => panic!("unknown bare kind {other}"),
    }
}

fn bare_unmarshal(name: &str, input: &[u8]) -> String {
    fn run<T: Default + MarshalTrait + UnmarshalTrait>(input: &[u8]) -> String {
        unmarshal_case::<T>(input)
    }
    match name {
        "int" => run::<isize>(input),
        "int8" => run::<i8>(input),
        "uint16" => run::<u16>(input),
        "uint64" => run::<u64>(input),
        "float32" => run::<f32>(input),
        "float64" => run::<f64>(input),
        "bool" => run::<bool>(input),
        "string" => run::<String>(input),
        "strings" => run::<Vec<String>>(input),
        "ints" => run::<Vec<isize>>(input),
        "bytes" => run::<Vec<u8>>(input),
        "optstr" => run::<Option<String>>(input),
        "name" => run::<Name>(input),
        "upper" => run::<Upper>(input),
        "txt" => run::<Txt>(input),
        "bytearr" => run::<[u8; 2]>(input),
        other => panic!("unknown bare kind {other}"),
    }
}

fn main() {
    let stdout = io::stdout();
    let mut w = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let f: Vec<&str> = line.split('\t').collect();
        let resp = match f[0] {
            "M" => {
                let prefix = String::from_utf8(unhex(f[2])).unwrap();
                let indent = String::from_utf8(unhex(f[3])).unwrap();
                match f[1].strip_prefix("bare:") {
                    Some(kind) => bare_marshal(kind, f[4], &prefix, &indent),
                    None => marshal_named(f[1], f[4], &prefix, &indent)
                        .unwrap_or_else(|| panic!("unknown struct {}", f[1])),
                }
            }
            "U" => {
                let input = unhex(f[2]);
                match f[1].strip_prefix("bare:") {
                    Some(kind) => bare_unmarshal(kind, &input),
                    None => unmarshal_named(f[1], &input)
                        .unwrap_or_else(|| panic!("unknown struct {}", f[1])),
                }
            }
            other => format!("bad request {other:?}"),
        };
        writeln!(w, "{resp}").unwrap();
    }
}
