//! The request/response protocol shared by the Go differential
//! (`tools/jsonv2_check.py`) and the golden vectors in
//! `tools/derive-check/tests/jsonv2.rs`: marshals and unmarshals the values
//! described by atoms (see `tools/jsonv2_oracle.go`) with
//! `encoding/json/v2`, using the derived types below, which mirror the Go
//! types of the oracle field for field. Lives here because it needs the
//! derive crate, which the root crate cannot depend on.
#![allow(non_snake_case, dead_code, unused_variables, clippy::all)]
use rust_stdlib::encoding::json::jsontext::{self, Decoder, Encoder, Error, Value};
use rust_stdlib::encoding::json::v2::{
    self, Any, EmbedAccess, EmbedAccessMut, FieldDesc, FieldValue, FieldValueMut, MarshalTo,
    Marshaler, MarshalerTo, StructDesc, StructMarshal, StructUnmarshal, TextMarshaler,
    TextUnmarshaler, TypeInfo, TypeKind, UnmarshalFrom, Unmarshaler, UnmarshalerFrom,
};
use rust_stdlib::encoding::json::Bytes;
use rust_stdlib::time::{self, Duration, Location, Time};
use rust_stdlib_derive::{MarshalTo, UnmarshalFrom};
use std::{
    collections::BTreeMap,
    panic::{catch_unwind, AssertUnwindSafe},
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

fn normalize_message(s: &str) -> String {
    s.replace("main.", "").replace("unable to", "cannot")
}

fn kind_char(k: jsontext::Kind) -> String {
    if k.0 == 0 {
        "_".into()
    } else {
        (k.0 as char).to_string()
    }
}

fn err_info(err: &Error) -> String {
    match err {
        Error::Semantic(se) => {
            let typ = match &se.type_info {
                Some(t) => enc(normalize_message(&t.name).as_bytes()),
                None => "-".into(),
            };
            format!(
                "s{}@{}@{}@{}@{}",
                se.byte_offset,
                enc(se.json_pointer.as_str().as_bytes()),
                kind_char(se.json_kind),
                enc(&se.json_value.0),
                typ
            )
        }
        Error::Syntactic(sy) => format!(
            "y{}@{}",
            sy.byte_offset,
            enc(sy.json_pointer.as_str().as_bytes())
        ),
        _ => "-".into(),
    }
}

fn fail(err: &Error) -> String {
    format!(
        "err {} {}",
        enc(normalize_message(&err.to_string()).as_bytes()),
        err_info(err)
    )
}

// ---- atoms

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
fill_int!(i8, i16, i32, i64, isize, u8, u16, u32, u64, usize);
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
impl Fill for () {
    fn fill(_: &mut Atoms<'_>) -> Self {}
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
impl<K: Fill + Ord, V: Fill> Fill for BTreeMap<K, V> {
    fn fill(a: &mut Atoms<'_>) -> Self {
        let n: usize = a.next()[1..].parse().expect("length atom");
        (0..n).map(|_| (K::fill(a), V::fill(a))).collect()
    }
}
impl Fill for Any {
    fn fill(a: &mut Atoms<'_>) -> Self {
        let mut v = Any::Null;
        v2::unmarshal(&dec(&a.next()[1..]), &mut v, &[]).expect("any atom");
        v
    }
}
impl Fill for Value {
    fn fill(a: &mut Atoms<'_>) -> Self {
        Value(dec(&a.next()[1..]))
    }
}
impl Fill for Duration {
    fn fill(a: &mut Atoms<'_>) -> Self {
        Duration::from_nanos(i64::fill(a))
    }
}
/// `t-` is the zero time, `t<sec>.<nsec>.<zone>` a Unix time in UTC (`u`)
/// or a fixed offset of `zone` seconds.
impl Fill for Time {
    fn fill(a: &mut Atoms<'_>) -> Self {
        let tok = a.next();
        if tok == "t-" {
            return Time::default();
        }
        let f: Vec<&str> = tok[1..].split('.').collect();
        let t = time::unix(f[0].parse().expect("sec"), f[1].parse().expect("nsec")).utc();
        match f[2] {
            "u" => t,
            off => t.in_location(&Location::fixed("", off.parse().expect("offset"))),
        }
    }
}
impl Fill for Bytes {
    fn fill(a: &mut Atoms<'_>) -> Self {
        Bytes(dec(&a.next()[1..]))
    }
}

// ---- hand-written types with methods

macro_rules! hand_struct {
    ($name:ident, $field:ident) => {
        #[derive(Default, Clone)]
        struct $name {
            $field: String,
        }
        impl Fill for $name {
            fn fill(a: &mut Atoms<'_>) -> Self {
                $name {
                    $field: String::fill(a),
                }
            }
        }
        impl StructMarshal for $name {
            fn with_field<R>(
                &self,
                path: &[usize],
                f: impl FnOnce(&dyn FieldValue) -> R,
            ) -> Option<R> {
                match path[0] {
                    0 => Some(f(&self.$field)),
                    _ => None,
                }
            }
        }
        impl StructUnmarshal for $name {
            fn with_field_mut<R>(
                &mut self,
                path: &[usize],
                _may_alloc: bool,
                f: impl FnOnce(&mut dyn FieldValueMut) -> R,
            ) -> Option<R> {
                match path[0] {
                    0 => Some(f(&mut self.$field)),
                    _ => None,
                }
            }
        }
        impl EmbedAccess for $name {
            fn with_embedded<R>(
                &self,
                path: &[usize],
                f: impl FnOnce(&dyn FieldValue) -> R,
            ) -> Option<R> {
                self.with_field(path, f)
            }
        }
        impl EmbedAccessMut for $name {
            fn with_embedded_mut<R>(
                &mut self,
                path: &[usize],
                may_alloc: bool,
                f: impl FnOnce(&mut dyn FieldValueMut) -> R,
            ) -> Option<R> {
                self.with_field_mut(path, may_alloc, f)
            }
        }
    };
}

fn struct_desc_of<T: 'static>(name: &'static str, field: &'static str) -> StructDesc {
    StructDesc {
        type_info: TypeInfo::of::<T>(name, TypeKind::Struct),
        fields: vec![FieldDesc {
            name: field,
            tag: "",
            has_tag: false,
            anonymous: false,
            exported: true,
            type_info: TypeInfo::of::<String>("string", TypeKind::String),
            struct_desc: || None,
        }],
    }
}

hand_struct!(Cust, Raw);
impl Marshaler for Cust {
    fn marshal_json(&self) -> Result<Vec<u8>, Error> {
        if self.Raw == "ERR" {
            return Err(Error::msg("boom"));
        }
        if self.Raw == "UNSUP" {
            return Err(Error::other(rust_stdlib::error::Message::unsupported()));
        }
        Ok(self.Raw.clone().into_bytes())
    }
}
impl Unmarshaler for Cust {
    fn unmarshal_json(&mut self, data: &[u8]) -> Result<(), Error> {
        if data == b"\"ERRDEC\"" {
            return Err(Error::msg("bad decode"));
        }
        self.Raw = String::from_utf8_lossy(data).into_owned();
        Ok(())
    }
}
impl MarshalTo for Cust {
    fn type_info() -> TypeInfo {
        TypeInfo::of::<Cust>("Cust", TypeKind::Struct)
    }
    fn marshal_default(&self, enc: &mut Encoder<'_>) -> Result<(), Error> {
        v2::marshal_struct(self, enc)
    }
    fn is_zero_value(&self) -> bool {
        self.Raw.is_empty()
    }
    fn struct_desc() -> Option<StructDesc> {
        Some(struct_desc_of::<Cust>("Cust", "Raw"))
    }
    fn as_marshaler(&self) -> Option<&dyn Marshaler> {
        Some(self)
    }
}
impl UnmarshalFrom for Cust {
    fn type_info() -> TypeInfo {
        TypeInfo::of::<Cust>("Cust", TypeKind::Struct)
    }
    fn zero() -> Self {
        Cust::default()
    }
    fn set_zero(&mut self) {
        self.Raw.clear();
    }
    fn unmarshal_default(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error> {
        v2::unmarshal_struct(self, dec)
    }
    fn struct_desc() -> Option<StructDesc> {
        Some(struct_desc_of::<Cust>("Cust", "Raw"))
    }
    fn as_unmarshaler(&mut self) -> Option<&mut dyn Unmarshaler> {
        Some(self)
    }
}

hand_struct!(To, S);
impl MarshalerTo for To {
    fn marshal_json_to(&self, e: &mut Encoder<'_>) -> Result<(), Error> {
        match self.S.as_str() {
            "unsupported" => Err(Error::other(rust_stdlib::error::Message::unsupported())),
            "err" => Err(Error::msg("custom failure")),
            "two" => {
                e.write_token(&jsontext::string("a"))?;
                e.write_token(&jsontext::string("b"))
            }
            "none" => Ok(()),
            "obj" => {
                for tok in [
                    jsontext::begin_object(),
                    jsontext::string("k"),
                    jsontext::int(1),
                    jsontext::end_object(),
                ] {
                    e.write_token(&tok)?;
                }
                Ok(())
            }
            "dup" => {
                for tok in [
                    jsontext::begin_object(),
                    jsontext::string("k"),
                    jsontext::int(1),
                    jsontext::string("k"),
                ] {
                    e.write_token(&tok)?;
                }
                Ok(())
            }
            s => e.write_token(&jsontext::string(&format!("<{s}>"))),
        }
    }
}
impl UnmarshalerFrom for To {
    fn unmarshal_json_from(&mut self, d: &mut Decoder<'_>) -> Result<(), Error> {
        if d.peek_kind() == jsontext::KIND_BEGIN_ARRAY {
            return Err(Error::other(rust_stdlib::error::Message::unsupported()));
        }
        let tok = d.read_token()?;
        match tok.kind() {
            jsontext::KIND_STRING => {
                if tok.to_string() == "bad" {
                    return Err(Error::msg("bad value"));
                }
                self.S = tok.to_string();
                Ok(())
            }
            jsontext::KIND_NUMBER => {
                self.S = tok.to_string();
                Ok(())
            }
            jsontext::KIND_BEGIN_OBJECT => d.skip_value(),
            k => Err(Error::msg(&format!("unexpected token {}", k))),
        }
    }
}
impl MarshalTo for To {
    fn type_info() -> TypeInfo {
        TypeInfo::of::<To>("To", TypeKind::Struct)
    }
    fn marshal_default(&self, enc: &mut Encoder<'_>) -> Result<(), Error> {
        v2::marshal_struct(self, enc)
    }
    fn is_zero_value(&self) -> bool {
        self.S.is_empty()
    }
    fn struct_desc() -> Option<StructDesc> {
        Some(struct_desc_of::<To>("To", "S"))
    }
    fn as_marshaler_to(&self) -> Option<&dyn MarshalerTo> {
        Some(self)
    }
}
impl UnmarshalFrom for To {
    fn type_info() -> TypeInfo {
        TypeInfo::of::<To>("To", TypeKind::Struct)
    }
    fn zero() -> Self {
        To::default()
    }
    fn set_zero(&mut self) {
        self.S.clear();
    }
    fn unmarshal_default(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error> {
        v2::unmarshal_struct(self, dec)
    }
    fn struct_desc() -> Option<StructDesc> {
        Some(struct_desc_of::<To>("To", "S"))
    }
    fn as_unmarshaler_from(&mut self) -> Option<&mut dyn UnmarshalerFrom> {
        Some(self)
    }
}

hand_struct!(Txt, S);
impl TextMarshaler for Txt {
    fn marshal_text(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if self.S == "ERR" {
            return Err("text failure".into());
        }
        Ok(format!("t:{}", self.S).into_bytes())
    }
}
impl TextUnmarshaler for Txt {
    fn unmarshal_text(&mut self, text: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        match text.strip_prefix(b"t:") {
            Some(s) => {
                self.S = String::from_utf8_lossy(s).into_owned();
                Ok(())
            }
            None => Err("missing prefix".into()),
        }
    }
}
impl MarshalTo for Txt {
    fn type_info() -> TypeInfo {
        TypeInfo::of::<Txt>("Txt", TypeKind::Struct)
    }
    fn marshal_default(&self, enc: &mut Encoder<'_>) -> Result<(), Error> {
        v2::marshal_struct(self, enc)
    }
    fn is_zero_value(&self) -> bool {
        self.S.is_empty()
    }
    fn struct_desc() -> Option<StructDesc> {
        Some(struct_desc_of::<Txt>("Txt", "S"))
    }
    fn as_text_marshaler(&self) -> Option<&dyn TextMarshaler> {
        Some(self)
    }
}
impl UnmarshalFrom for Txt {
    fn type_info() -> TypeInfo {
        TypeInfo::of::<Txt>("Txt", TypeKind::Struct)
    }
    fn zero() -> Self {
        Txt::default()
    }
    fn set_zero(&mut self) {
        self.S.clear();
    }
    fn unmarshal_default(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error> {
        v2::unmarshal_struct(self, dec)
    }
    fn struct_desc() -> Option<StructDesc> {
        Some(struct_desc_of::<Txt>("Txt", "S"))
    }
    fn as_text_unmarshaler(&mut self) -> Option<&mut dyn TextUnmarshaler> {
        Some(self)
    }
}

// ---- options

fn options(letters: &str) -> Vec<v2::Options> {
    let mut opts = vec![v2::deterministic(true)];
    if letters == "-" {
        return opts;
    }
    for c in letters.chars() {
        opts.push(match c {
            'n' => v2::stringify_numbers(true),
            'o' => v2::omit_zero_struct_fields(true),
            'i' => v2::match_case_insensitive_names(true),
            'r' => v2::reject_unknown_members(true),
            'h' => jsontext::escape_for_html(true),
            'j' => jsontext::escape_for_js(true),
            'm' => jsontext::multiline(true),
            'x' => jsontext::with_indent("  "),
            'c' => jsontext::space_after_colon(true),
            'k' => jsontext::space_after_comma(true),
            'a' => jsontext::allow_duplicate_names(true),
            'v' => jsontext::allow_invalid_utf8(true),
            'p' => v2::format_nil_slice_as_null(true),
            'q' => v2::format_nil_map_as_null(true),
            'D' => v2::deterministic(false),
            't' => v2::experimental_support_format_tag(true),
            'F' => v2::with_marshalers(v2::join_marshalers(&[
                v2::marshal_func::<i64, _>(|v| match *v {
                    13 => Err(Error::msg("unlucky")),
                    14 => Ok(b"nope".to_vec()),
                    15 => Err(Error::other(rust_stdlib::error::Message::unsupported())),
                    v => Ok(rust_stdlib::strconv::quote(format!("n{v}")).into_bytes()),
                }),
                v2::marshal_to_func::<String, _>(|e, s| match s.as_str() {
                    "" => Err(Error::other(rust_stdlib::error::Message::unsupported())),
                    "two" => {
                        e.write_token(&jsontext::string("a"))?;
                        e.write_token(&jsontext::string("b"))
                    }
                    "err" => Err(Error::msg("string failure")),
                    s => e.write_token(&jsontext::string(&s.to_uppercase())),
                }),
            ])),
            'G' => v2::with_unmarshalers(v2::join_unmarshalers(&[
                v2::unmarshal_func::<i64, _>(|b, v| {
                    let text = String::from_utf8_lossy(b).into_owned();
                    let Ok(s) = rust_stdlib::strconv::unquote(&text) else {
                        return Err(Error::msg("not a string"));
                    };
                    let s = String::from_utf8_lossy(&s).into_owned();
                    match s.strip_prefix('n').unwrap_or(&s).parse::<i64>() {
                        Ok(n) => {
                            *v = n;
                            Ok(())
                        }
                        Err(_) => Err(Error::msg("not a number")),
                    }
                }),
                v2::unmarshal_from_func::<String, _>(|d, v| {
                    if d.peek_kind() == jsontext::KIND_NULL {
                        return Err(Error::other(rust_stdlib::error::Message::unsupported()));
                    }
                    let tok = d.read_token()?;
                    if tok.kind() != jsontext::KIND_STRING {
                        return Err(Error::msg("want string"));
                    }
                    *v = tok.to_string().to_uppercase();
                    Ok(())
                }),
            ])),
            other => panic!("unknown option letter {other}"),
        });
    }
    opts
}

macro_rules! types {
    ($($(#[$sm:meta])* struct $name:ident { $($(#[$fm:meta])* $f:ident : $t:ty),* $(,)? })+) => {
        $(
            #[derive(MarshalTo, UnmarshalFrom)]
            $(#[$sm])*
            struct $name { $($(#[$fm])* $f: $t),* }
            impl Fill for $name {
                fn fill(a: &mut Atoms<'_>) -> Self {
                    $name { $($f: <$t as Fill>::fill(a)),* }
                }
            }
        )+
        fn marshal_typed(name: &str, opts: &str, toks: &[&str]) -> String {
            match name {
                $(stringify!($name) => {
                    let mut a = Atoms { toks, i: 0 };
                    let v = <$name as Fill>::fill(&mut a);
                    assert_eq!(a.i, toks.len(), "atoms left over");
                    match v2::marshal(&v, &options(opts)) {
                        Ok(b) => format!("ok {}", enc(&b)),
                        Err(e) => fail(&e),
                    }
                })+
                other => format!("err {} -", enc(format!("unknown type {other}").as_bytes())),
            }
        }
        fn unmarshal_typed(name: &str, opts: &str, data: &[u8], toks: &[&str]) -> String {
            match name {
                $(stringify!($name) => {
                    let mut a = Atoms { toks, i: 0 };
                    let mut v = if toks.is_empty() {
                        <$name as UnmarshalFrom>::zero()
                    } else {
                        <$name as Fill>::fill(&mut a)
                    };
                    assert_eq!(a.i, toks.len(), "atoms left over");
                    let res = match v2::unmarshal(data, &mut v, &options(opts)) {
                        Ok(()) => "ok".to_string(),
                        Err(e) => fail(&e),
                    };
                    let remarshal = [v2::deterministic(true), v2::experimental_support_format_tag(true)];
                    match v2::marshal(&v, &remarshal) {
                        Ok(b) => format!("{res} | {}", enc(&b)),
                        Err(_) => format!("{res} remarshal-error"),
                    }
                })+
                other => format!("err {} -", enc(format!("unknown type {other}").as_bytes())),
            }
        }
    };
}

types! {
    struct Inner {
        #[json("x,omitempty")] X: i64,
        #[json("y")] Y: String,
        #[json("z,omitempty")] Z: Vec<i64>,
    }
    struct Scalars {
        B: bool, I8: i8, I16: i16, I32: i32, I64: i64, I: isize,
        U8: u8, U16: u16, U32: u32, U64: u64, U: usize,
        F32: f32, F64: f64, S: String,
    }
    struct Tags {
        #[json("a")] A: i64,
        #[json("b,omitempty")] B: String,
        #[json("c,omitzero")] C: i64,
        #[json(",string")] D: f64,
        #[json("e,string")] E: i32,
        #[json("f,omitempty")] F: u8,
        #[json("g,omitempty,omitzero")] G: bool,
        #[json("h,omitempty")] H: Option<i64>,
        #[json("i,omitzero")] I: Option<i64>,
        #[json("j,omitempty")] J: Vec<i64>,
        #[json("k,omitempty")] K: BTreeMap<String, i64>,
        #[json("l,omitzero")] L: Inner,
        #[json("m,omitempty")] M: [i64; 2],
        #[json("-")] Skip: i64,
        #[json("-,")] Dash: i64,
        Plain: i64,
        #[json("é,omitempty")] Uni: String,
        #[json("<&>")] Html: i64,
        #[json("ign,case:ignore")] Ign: String,
        #[json("str,case:strict")] Str: String,
        #[json("a\"b")] Quo: String,
    }
    struct Omit {
        #[json("p1,omitempty")] P1: Option<i64>,
        #[json("s1,omitempty")] S1: Vec<i64>,
        #[json("m1,omitempty")] M1: BTreeMap<String, i64>,
        #[json("z1,omitempty")] Z1: String,
        #[json("z2,omitempty")] Z2: i64,
        #[json("b1,omitempty")] B1: bool,
        #[json("f1,omitempty")] F1: f64,
        #[json("a1,omitempty")] A1: [i64; 0],
        #[json("a2,omitempty")] A2: [i64; 2],
        #[json("i1,omitempty")] I1: Any,
        #[json("r1,omitempty")] R1: Value,
        #[json("y1,omitempty")] Y1: Bytes,
        #[json("q1,omitempty")] Q1: Option<String>,
        #[json("in,omitempty")] In: Inner,
        #[json("n1,omitempty")] N1: Option<Inner>,
        #[json("z3,omitzero")] Z3: bool,
        #[json("z4,omitzero")] Z4: f64,
        #[json("z5,omitzero")] Z5: [i64; 2],
        #[json("z6,omitzero")] Z6: Inner,
        #[json("z7,omitzero")] Z7: Vec<i64>,
        #[json("z8,omitzero")] Z8: Any,
    }
    struct Containers {
        Ints: BTreeMap<i64, String>,
        Uints: BTreeMap<u8, bool>,
        Strs: BTreeMap<String, Vec<String>>,
        Arr: [String; 3],
        Nested: Vec<Vec<i64>>,
        Ptrs: Vec<Option<String>>,
        Bytes: Bytes,
        Any: Any,
        MapAny: BTreeMap<String, Any>,
        I64s: BTreeMap<i64, i8>,
        Raw: Value,
        Obj: BTreeMap<String, Inner>,
    }
    struct BoolKeys { M: BTreeMap<bool, i64> }
    struct Floats {
        F1: f64, F2: f64, F3: f64, G1: f32, G2: f32,
        #[json(",string")] S1: f64,
        #[json(",string")] S2: f32,
        #[json(",omitempty")] N1: f64,
    }
    struct StrTags {
        #[json(",string")] A: i64,
        #[json(",string")] B: u16,
        #[json(",string")] C: f64,
        #[json(",string")] D: Option<i64>,
        #[json("e,string,omitempty")] E: Vec<i64>,
    }
    struct StrErr { #[json(",string")] S: String }
    struct BoolErr { #[json(",string")] B: bool }
    struct MapErr { #[json(",string")] M: BTreeMap<String, i64> }
    struct Names {
        S1: String,
        #[json(",omitempty")] S2: String,
        M: BTreeMap<String, i64>,
        #[json("<k>&")] K: BTreeMap<String, String>,
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
    struct Embed9 {
        #[json(inline, ",embed")] X: Base,
        Y: i64,
    }
    struct Embed10 {
        #[json(embedded, ",omitempty")] Base: Base,
        Other: i64,
    }
    struct Conflict {
        #[json("x")] A: i64,
        #[json("x")] B: i64,
    }
    struct BadTag1 { #[json("a,omitempty,omitempty")] A: i64 }
    struct BadTag2 { #[json("a,case:ignore,case:strict")] A: i64 }
    struct BadTag3 { #[json("a,format")] A: i64 }
    struct BadTag4 {
        #[json(",bogus")] A: i64,
        #[json("b,omitEmpty")] B: i64,
    }
    struct BadTag5 { #[json("a,")] A: i64 }
    struct BadTag6 { #[json("'a'")] A: i64 }
    struct BadTag7 {
        #[json("a,case")] A: i64,
        #[json("b,case:wrong")] B: i64,
    }
    struct Fmt {
        #[json("a,format:hex")] A: i64,
        #[json("b,format:base64url")] B: Bytes,
    }
    struct Empty {}
    struct NoFields { #[json(unexported)] a: () }
    struct Fall1 {
        A: i64,
        #[json(unknown)] Rest: BTreeMap<String, Any>,
    }
    struct Fall2 {
        #[json("a")] A: i64,
        #[json(",embed")] Rest: Value,
    }
    struct Fall3 {
        #[json(embedded)] Base: Base,
        #[json(",embed")] Rest: BTreeMap<String, i64>,
    }
    struct Fall4 {
        #[json(embedded)] Inner: Option<Inner>,
        #[json(",embed")] Rest: BTreeMap<String, String>,
    }
    struct FallBad {
        #[json(",embed")] R1: BTreeMap<String, Any>,
        #[json(",embed")] R2: Value,
    }
    struct Customs {
        #[json("a")] A: Cust,
        #[json("b")] B: Option<Cust>,
        #[json("c")] C: Vec<Cust>,
        #[json("d")] D: BTreeMap<String, Cust>,
        #[json("e,omitempty")] E: Cust,
        #[json("f,omitzero")] F: Cust,
        #[json("t")] T: To,
        #[json("u")] U: Vec<To>,
        #[json("x")] X: Txt,
        #[json("y")] Y: BTreeMap<String, Txt>,
        #[json("z,omitempty")] Z: Option<Txt>,
    }
    struct Times {
        #[json("a")] A: Time,
        #[json("b,omitzero")] B: Time,
        #[json("c,omitempty")] C: Option<Time>,
        #[json("d")] D: Vec<Time>,
        #[json("e")] E: BTreeMap<String, Time>,
        #[json("f,omitempty")] F: Time,
    }
    struct TimeFmts {
        #[json("u,format:unix")] U: Time,
        #[json("um,format:unixmilli")] UM: Time,
        #[json("uu,format:unixmicro")] UU: Time,
        #[json("un,format:unixnano")] UN: Time,
        #[json("us,string,format:unixmilli")] US: Time,
        #[json("r,format:RFC3339")] R: Time,
        #[json("rn,format:RFC3339Nano")] RN: Time,
        #[json("an,format:ANSIC")] AN: Time,
        #[json("ud,format:UnixDate")] UD: Time,
        #[json("rb,format:RubyDate")] RB: Time,
        #[json("r8,format:RFC822")] R8: Time,
        #[json("rz,format:RFC822Z")] RZ: Time,
        #[json("r5,format:RFC850")] R5: Time,
        #[json("r1,format:RFC1123")] R1: Time,
        #[json("ry,format:RFC1123Z")] RY: Time,
        #[json("k,format:Kitchen")] K: Time,
        #[json("sn,format:StampNano")] SN: Time,
        #[json("dt,format:DateTime")] DT: Time,
        #[json("do,format:DateOnly")] DO: Time,
        #[json("to,format:TimeOnly")] TO: Time,
        #[json("cu,format:'2006/01/02 15h04.000 -0700'")] CU: Time,
    }
    struct TimeBad {
        #[json("a,string")] A: Time,
        #[json("b,format:Bogus")] B: Time,
    }
    struct Durs {
        #[json("d")] D: Duration,
        #[json("p")] P: Option<Duration>,
    }
    struct DurFmts {
        #[json("u,format:units")] U: Duration,
        #[json("s,format:sec")] S: Duration,
        #[json("ss,string,format:sec")] SS: Duration,
        #[json("m,format:milli")] M: Duration,
        #[json("mi,format:micro")] MI: Duration,
        #[json("n,format:nano")] N: Duration,
        #[json("i,format:iso8601")] I: Duration,
        #[json("iz,omitzero,format:iso8601")] IZ: Duration,
    }
    struct DurBad {
        #[json("a,string,format:units")] A: Duration,
        #[json("b,format:hours")] B: Duration,
    }
}

/// Answers one request; a panic becomes a `panic <hex message>` record.
pub fn respond(line: &str) -> String {
    let f: Vec<&str> = line.split_whitespace().collect();
    let res = catch_unwind(AssertUnwindSafe(|| match f[0] {
        "marshal" => marshal_typed(f[1], f[2], &f[3..]),
        "unmarshal" => unmarshal_typed(f[1], f[2], &dec(f[3]), &f[4..]),
        other => format!("err {} -", enc(format!("unknown op {other}").as_bytes())),
    }));
    match res {
        Ok(t) => t,
        Err(p) => {
            let msg = p
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default();
            format!("panic {}", enc(msg.as_bytes()))
        }
    }
}
