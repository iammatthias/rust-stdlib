//! `encoding/json/v2` with the `MarshalTo` and `UnmarshalFrom` derives: the
//! examples of Go's `example_test.go` and `example_marshaljson_test.go`
//! (without the `net/netip` types), option and error behaviour, the
//! `time.Time` and `time.Duration` arshalers,
//! and golden vectors recorded from Go 1.27.1 by `tools/jsonv2_golden.py`
//! (`tools/jsonv2_check.py` compares a much larger generated menu with Go).
#![allow(non_snake_case, dead_code)]
use rust_stdlib::encoding::json::jsontext::{self, Decoder, Encoder, Error};
use rust_stdlib::encoding::json::v2::{
    self, Any, MarshalTo, MarshalerTo, TypeInfo, TypeKind, UnmarshalFrom, UnmarshalerFrom,
};
use rust_stdlib::time::{self, Duration, Location, Time};
use rust_stdlib_derive::{MarshalTo, UnmarshalFrom};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

#[path = "../examples/jsonv2_probe/protocol.rs"]
mod protocol;

#[test]
fn golden_vectors_recorded_from_go() {
    let golden = include_str!("../../../tests/fixtures/jsonv2_golden.txt");
    let mut count = 0;
    for line in golden.lines() {
        let (request, want) = line.split_once('\t').expect("request and response");
        let got = protocol::respond(request);
        let shown: String = request.chars().take(160).collect();
        assert_eq!(got, want, "request {shown}");
        count += 1;
    }
    assert!(count > 1500, "{count} vectors");
}

fn marshal_text<T: MarshalTo>(v: &T, opts: &[v2::Options]) -> String {
    String::from_utf8(v2::marshal(v, opts).expect("marshal")).expect("UTF-8")
}

// ---- Example_fieldNames

#[derive(MarshalTo)]
struct FieldNames {
    #[json("-")]
    Ignored: Any,
    GoName: Any,
    #[json("jsonName")]
    JSONName: Any,
    #[json(",case:ignore")]
    Option: Any,
    #[json(unexported)]
    unexported: Any,
}

#[test]
fn example_field_names() {
    let value = FieldNames {
        Ignored: Any::Null,
        GoName: Any::Null,
        JSONName: Any::Null,
        Option: Any::Null,
        unexported: Any::Null,
    };
    assert_eq!(
        marshal_text(&value, &[]),
        r#"{"GoName":null,"jsonName":null,"Option":null}"#
    );
}

// ---- Example_caseSensitivity

#[derive(UnmarshalFrom)]
struct CaseStrict {
    #[json("firstName")]
    X: bool,
}

#[derive(UnmarshalFrom)]
struct CaseIgnore {
    #[json("firstName,case:ignore")]
    X: bool,
}

#[test]
fn example_case_sensitivity() {
    let input = br#"[
		{"firstname": true},
		{"firstName": true},
		{"FirstName": true},
		{"FIRSTNAME": true},
		{"first_name": true},
		{"FIRST_NAME": true},
		{"first-name": true},
		{"FIRST-NAME": true},
		{"unknown": true}
	]"#;
    let mut strict: Vec<CaseStrict> = Vec::new();
    v2::unmarshal(input, &mut strict, &[]).expect("unmarshal");
    let got: Vec<bool> = strict.iter().map(|c| c.X).collect();
    assert_eq!(
        got,
        [false, true, false, false, false, false, false, false, false]
    );
    let mut ignore: Vec<CaseIgnore> = Vec::new();
    v2::unmarshal(input, &mut ignore, &[]).expect("unmarshal");
    let got: Vec<bool> = ignore.iter().map(|c| c.X).collect();
    assert_eq!(got, [true, true, true, true, true, true, true, true, false]);
}

// ---- Example_omitFields

#[derive(Default, MarshalTo)]
struct MyStruct {
    #[json(",omitzero")]
    Foo: String,
    #[json(",omitempty")]
    Bar: Vec<i64>,
    #[json(",omitzero,omitempty")]
    Baz: Option<Box<MyStruct>>,
}

#[derive(MarshalTo)]
struct OmitZero {
    #[json(",omitzero")]
    Bool: bool,
    #[json(",omitzero")]
    Int: i64,
    #[json(",omitzero")]
    String: String,
    #[json(",omitzero")]
    Time: Time,
    #[json(",omitzero")]
    Struct: MyStruct,
    #[json(",omitzero")]
    PointerNil: Option<String>,
    #[json(",omitzero")]
    Pointer: Option<String>,
    #[json(",omitzero")]
    InterfaceNil: Any,
}

#[derive(MarshalTo)]
struct OmitEmpty {
    #[json(",omitempty")]
    Bool: bool,
    #[json(",omitempty")]
    Int: i64,
    #[json(",omitempty")]
    String: String,
    #[json(",omitempty")]
    Time: Time,
    #[json(",omitempty")]
    Struct: MyStruct,
    #[json(",omitempty")]
    PointerNil: Option<String>,
    #[json(",omitempty")]
    Pointer: Option<String>,
    #[json(",omitempty")]
    InterfaceNil: Any,
}

#[test]
fn example_omit_fields() {
    let my = || MyStruct {
        Foo: String::new(),
        Bar: Vec::new(),
        Baz: Some(Box::new(MyStruct::default())),
    };
    let year1 = || time::date(1, time::JANUARY, 1, 0, 0, 0, 0, &Location::utc());
    let zero = OmitZero {
        Bool: false,
        Int: 0,
        String: String::new(),
        // Omitted since time.Time.IsZero reports true.
        Time: year1(),
        Struct: my(),
        PointerNil: None,
        Pointer: Some(String::new()),
        InterfaceNil: Any::Null,
    };
    // Struct and Pointer are not zero; the others are.
    assert_eq!(marshal_text(&zero, &[]), r#"{"Struct":{},"Pointer":""}"#);
    let empty = OmitEmpty {
        Bool: false,
        Int: 0,
        String: String::new(),
        // Not omitted since it encodes as a non-empty JSON string.
        Time: year1(),
        Struct: my(),
        PointerNil: None,
        Pointer: Some(String::new()),
        InterfaceNil: Any::Null,
    };
    // Only Bool, Int and Time do not encode as empty JSON values.
    assert_eq!(
        marshal_text(&empty, &[]),
        r#"{"Bool":false,"Int":0,"Time":"0001-01-01T00:00:00Z"}"#
    );
}

// ---- Example_embeddedFields

#[derive(Default, MarshalTo, UnmarshalFrom)]
struct EmbBase {
    ID: String,
    Type: String,
    Time: Time,
}

#[derive(Default, MarshalTo, UnmarshalFrom)]
struct EmbOther {
    Cost: f64,
}

#[derive(Default, MarshalTo, UnmarshalFrom)]
struct EmbInner {
    User: String,
    Time: String,
}

#[derive(Default, MarshalTo, UnmarshalFrom)]
struct Container {
    #[json(embedded)]
    Base: EmbBase,
    Type: i64,
    #[json(inline, ",embed")]
    Embed: EmbInner,
    #[json("uuid")]
    ID: String,
    #[json("other")]
    Other: EmbOther,
}

#[test]
fn example_embedded_fields() {
    let input = Container::default();
    assert_eq!(
        marshal_text(&input, &[]),
        r#"{"ID":"","Type":0,"User":"","uuid":"","other":{"Cost":0}}"#
    );
    let mut got = Container::default();
    v2::unmarshal(
        br#"{"ID":"i","Type":3,"User":"u","uuid":"x","other":{"Cost":1.5},"Time":"t"}"#,
        &mut got,
        &[],
    )
    .expect("unmarshal");
    assert_eq!(got.Base.ID, "i");
    assert_eq!(got.Embed.User, "u");
    assert_eq!((got.Type, got.ID.as_str(), got.Other.Cost), (3, "x", 1.5));
    assert!(got.Base.Time.is_zero(), "Time cancels out");
}

// ---- ExampleMarshalerTo / ExampleUnmarshalerFrom

#[derive(Default, PartialEq, Debug)]
struct IntSet(BTreeSet<i64>);

impl MarshalerTo for IntSet {
    fn marshal_json_to(&self, enc: &mut Encoder<'_>) -> Result<(), Error> {
        enc.write_token(&jsontext::begin_array())?;
        // The set is ordered already, so Deterministic needs no extra work;
        // GetOption shows how a marshaler learns about the options.
        let (_deterministic, _) =
            v2::get_option(&enc.options(), v2::deterministic as fn(bool) -> _);
        for k in &self.0 {
            v2::marshal_encode(enc, k, &[])?;
        }
        enc.write_token(&jsontext::end_array())
    }
}

impl UnmarshalerFrom for IntSet {
    fn unmarshal_json_from(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error> {
        let k = dec.peek_kind();
        if k != jsontext::KIND_BEGIN_ARRAY {
            let mut err = v2::SemanticError::default();
            err.json_kind = k;
            return Err(err.into());
        }
        dec.read_token()?;
        while dec.peek_kind() != jsontext::KIND_END_ARRAY {
            let mut v = 0i64;
            v2::unmarshal_decode(dec, &mut v, &[])?;
            self.0.insert(v);
        }
        dec.read_token()?;
        Ok(())
    }
}

impl MarshalTo for IntSet {
    fn type_info() -> TypeInfo {
        TypeInfo::of::<IntSet>("json_test.IntSet", TypeKind::Map)
    }
    fn marshal_default(&self, enc: &mut Encoder<'_>) -> Result<(), Error> {
        self.marshal_json_to(enc)
    }
    fn is_zero_value(&self) -> bool {
        self.0.is_empty()
    }
    fn as_marshaler_to(&self) -> Option<&dyn MarshalerTo> {
        Some(self)
    }
}

impl UnmarshalFrom for IntSet {
    fn type_info() -> TypeInfo {
        TypeInfo::of::<IntSet>("json_test.IntSet", TypeKind::Map)
    }
    fn zero() -> Self {
        IntSet::default()
    }
    fn set_zero(&mut self) {
        self.0.clear();
    }
    fn unmarshal_default(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error> {
        self.unmarshal_json_from(dec)
    }
    fn as_unmarshaler_from(&mut self) -> Option<&mut dyn UnmarshalerFrom> {
        Some(self)
    }
}

#[test]
fn example_marshaler_to_and_unmarshaler_from() {
    let set = IntSet([1, 2, 3].into());
    assert_eq!(marshal_text(&set, &[v2::deterministic(true)]), "[1,2,3]");
    let mut got = IntSet::default();
    v2::unmarshal(b"[1,2,3]", &mut got, &[]).expect("unmarshal");
    assert_eq!(got, set);
    let err = v2::unmarshal(b"{}", &mut got, &[]).expect_err("an object is not a set");
    assert_eq!(
        err.to_string(),
        "json: cannot unmarshal JSON object into Go json_test.IntSet"
    );
}

// ---- ExampleUnmarshalDecode_stream and ExampleMarshal_multiline

#[derive(Default, MarshalTo, UnmarshalFrom)]
struct Animal {
    Name: String,
    Order: String,
}

#[test]
fn example_unmarshal_decode_stream() {
    let stream = br#"
	{"Name": "Platypus", "Order": "Monotremata"}
	{"Name": "Quoll",    "Order": "Dasyuromorphia"}
	{"Name": "Gopher",   "Order": "Rodentia"}
"#;
    let mut dec = Decoder::new(Cursor::new(stream.to_vec()), &[]);
    let mut got = Vec::new();
    loop {
        let mut a = Animal::default();
        match v2::unmarshal_decode(&mut dec, &mut a, &[]) {
            Ok(()) => got.push(format!("{}: {}", a.Name, a.Order)),
            Err(Error::Eof) => break,
            Err(e) => panic!("{e}"),
        }
    }
    assert_eq!(
        got,
        [
            "Platypus: Monotremata",
            "Quoll: Dasyuromorphia",
            "Gopher: Rodentia"
        ]
    );
}

#[test]
fn example_marshal_multiline() {
    let p = Animal {
        Name: "Oliver".into(),
        Order: "Dog".into(),
    };
    assert_eq!(
        marshal_text(&p, &[jsontext::multiline(true)]),
        "{\n\t\"Name\": \"Oliver\",\n\t\"Order\": \"Dog\"\n}"
    );
}

// ---- options, errors and merging

#[test]
fn options_join_and_get() {
    let o = v2::join_options(&[v2::deterministic(true), v2::deterministic(false)]);
    assert_eq!(
        v2::get_option(&o, v2::deterministic as fn(bool) -> _),
        (false, true)
    );
    assert_eq!(
        v2::get_option(&o, v2::reject_unknown_members as fn(bool) -> _),
        (false, false)
    );
    let o = v2::join_options(&[jsontext::with_indent("  ")]);
    assert_eq!(
        v2::get_option(&o, jsontext::with_indent as fn(&str) -> _),
        ("  ".to_string(), true)
    );
}

#[derive(Default, Debug, MarshalTo, UnmarshalFrom)]
struct Merged {
    A: i64,
    B: Vec<i64>,
    M: BTreeMap<String, i64>,
    P: Option<Box<Merged>>,
}

#[test]
fn unmarshal_merges_into_existing_values() {
    let mut v = Merged {
        A: 1,
        B: vec![9, 9, 9],
        M: [("keep".to_string(), 1), ("over".to_string(), 2)].into(),
        P: None,
    };
    v2::unmarshal(
        br#"{"B":[1],"M":{"over":3,"new":4},"P":{"A":7}}"#,
        &mut v,
        &[],
    )
    .expect("unmarshal");
    assert_eq!(v.A, 1, "absent members keep their value");
    assert_eq!(v.B, [1], "slices are replaced");
    assert_eq!(v.M["keep"], 1);
    assert_eq!((v.M["over"], v.M["new"]), (3, 4), "maps are merged");
    assert_eq!(v.P.as_ref().map(|p| p.A), Some(7));
}

#[test]
fn errors_carry_position() {
    let mut v = Merged::default();
    let err = v2::unmarshal(br#"{"A":1,"M":{"x":"s"}}"#, &mut v, &[]).expect_err("type error");
    assert_eq!(
        err.to_string(),
        r#"json: cannot unmarshal JSON string into Go int64 within "/M/x""#
    );
    let se = err.as_semantic().expect("SemanticError");
    assert_eq!(se.json_pointer.as_str(), "/M/x");
    assert_eq!(se.json_kind, jsontext::KIND_STRING);
    assert_eq!(v.A, 1, "the value keeps what was read before the error");
    let err = v2::unmarshal(br#"{"A":1} x"#, &mut v, &[]).expect_err("trailing data");
    assert!(err.as_syntactic().is_some());
    let err = v2::unmarshal(br#"{"A":1,"A":2}"#, &mut v, &[]).expect_err("duplicate");
    assert!(
        err.to_string().contains("duplicate object member name"),
        "{err}"
    );
    let mut strict = Merged::default();
    let err = v2::unmarshal(
        br#"{"Z":1}"#,
        &mut strict,
        &[v2::reject_unknown_members(true)],
    )
    .expect_err("unknown member");
    assert_eq!(
        err.to_string(),
        r#"json: cannot unmarshal JSON string into Go Merged: unknown object member name "Z""#
    );
    assert!(err.has(&v2::ERR_UNKNOWN_NAME));
}

#[test]
fn marshal_funcs() {
    let opts = [v2::with_marshalers(v2::join_marshalers(&[
        v2::marshal_to_func::<String, _>(|enc, s| {
            if s.is_empty() {
                return Err(Error::other(rust_stdlib::error::Message::unsupported()));
            }
            enc.write_token(&jsontext::string(&s.to_uppercase()))
        }),
        v2::marshal_func::<i64, _>(|n| Ok(format!("\"#{n}\"").into_bytes())),
    ]))];
    let animal = Animal {
        Name: "kiwi".into(),
        Order: String::new(),
    };
    assert_eq!(
        marshal_text(&animal, &opts),
        r#"{"Name":"KIWI","Order":""}"#
    );
    assert_eq!(marshal_text(&vec![1i64, 2], &opts), r##"["#1","#2"]"##);
}

#[test]
fn unmarshal_funcs() {
    let opts = [v2::with_unmarshalers(v2::join_unmarshalers(&[
        v2::unmarshal_from_func::<String, _>(|dec, s| {
            let tok = dec.read_token()?;
            *s = tok.to_string().to_lowercase();
            Ok(())
        }),
    ]))];
    let mut a = Animal::default();
    v2::unmarshal(
        br#"{"Name":"KIWI","Order":"Apterygiformes"}"#,
        &mut a,
        &opts,
    )
    .expect("unmarshal");
    assert_eq!(
        (a.Name.as_str(), a.Order.as_str()),
        ("kiwi", "apterygiformes")
    );
}

#[test]
fn nil_vs_empty_options() {
    let v: Vec<i64> = Vec::new();
    assert_eq!(marshal_text(&v, &[]), "[]");
    // Rust has no nil slice: an empty Vec is the one nil-or-empty value.
    assert_eq!(
        marshal_text(&v, &[v2::format_nil_slice_as_null(true)]),
        "null"
    );
}

#[test]
fn format_tag_is_unsupported_by_default() {
    #[derive(MarshalTo)]
    struct F {
        #[json(format = "hex")]
        A: i64,
    }
    let err = v2::marshal(&F { A: 1 }, &[]).expect_err("format is experimental");
    assert_eq!(
        err.to_string(),
        "json: cannot marshal from Go F: Go struct field A has unsupported `format` tag option"
    );
}

#[derive(Debug, Default, PartialEq, MarshalTo)]
struct SkippedString {
    #[json("name")]
    name: String,
    #[json(skip)]
    origin: String,
}

#[test]
fn skipped_string_field_counts_towards_zero() {
    let zero = SkippedString::default();
    assert!(MarshalTo::is_zero_value(&zero));
    let bound = SkippedString {
        origin: "https://example.com".into(),
        ..SkippedString::default()
    };
    assert!(!MarshalTo::is_zero_value(&bound));
    assert_eq!(v2::marshal(&bound, &[]).unwrap(), br#"{"name":""}"#);
}

// ---- time.Time and time.Duration (expected values from Go 1.27.1)

fn utc_date(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64, ns: i64) -> Time {
    time::date(y, time::Month(mo), d, h, mi, s, ns, &Location::utc())
}

fn error_text<T: MarshalTo>(v: &T, opts: &[v2::Options]) -> String {
    v2::marshal(v, opts).expect_err("marshal fails").to_string()
}

fn unmarshal_error<T: UnmarshalFrom>(input: &[u8], v: &mut T, opts: &[v2::Options]) -> String {
    v2::unmarshal(input, v, opts)
        .expect_err("unmarshal fails")
        .to_string()
}

#[derive(Default, MarshalTo, UnmarshalFrom)]
struct Until {
    #[json("until,omitzero")]
    until: Time,
}

#[test]
fn time_is_rfc3339_with_nanoseconds() {
    let t = utc_date(2026, 10, 27, 1, 2, 3, 4);
    let out = v2::marshal(&t, &[]).expect("marshal");
    assert_eq!(out, br#""2026-10-27T01:02:03.000000004Z""#);
    let mut back = Time::default();
    v2::unmarshal(&out, &mut back, &[]).expect("unmarshal");
    assert!(back.equal(&t));
    assert_eq!(
        marshal_text(&Time::default(), &[]),
        r#""0001-01-01T00:00:00Z""#
    );
    let offset = t.in_location(&Location::fixed("", 19800));
    assert_eq!(
        marshal_text(&offset, &[]),
        r#""2026-10-27T06:32:03.000000004+05:30""#
    );
}

#[test]
fn time_field_omitzero_uses_is_zero() {
    assert_eq!(marshal_text(&Until::default(), &[]), "{}");
    let set = Until {
        until: utc_date(2026, 10, 27, 1, 2, 3, 4),
    };
    assert_eq!(
        marshal_text(&set, &[]),
        r#"{"until":"2026-10-27T01:02:03.000000004Z"}"#
    );
    // A non-nil pointer to the zero time is omitted too: Go calls IsZero
    // through the pointer.
    #[derive(MarshalTo)]
    struct P {
        #[json("p,omitzero")]
        p: Option<Time>,
        #[json("q,omitzero")]
        q: Option<i64>,
        #[json("b,omitzero")]
        b: Box<Time>,
        #[json("bb,omitzero")]
        bb: Option<Box<Time>>,
    }
    let v = P {
        p: Some(Time::default()),
        q: Some(0),
        b: Box::default(),
        bb: Some(Box::default()),
    };
    assert_eq!(
        marshal_text(&v, &[]),
        r#"{"q":0,"bb":"0001-01-01T00:00:00Z"}"#
    );
    // A struct holding the zero instant in another zone is not Go's zero
    // struct, though the field itself is omitted by IsZero.
    #[derive(MarshalTo)]
    struct Inner {
        T: Time,
    }
    #[derive(MarshalTo)]
    struct Outer {
        #[json("i,omitzero")]
        i: Inner,
        #[json("t,omitzero")]
        t: Time,
    }
    let zone = Time::default().in_location(&Location::fixed("", 3600));
    let v = Outer {
        i: Inner { T: zone.clone() },
        t: zone,
    };
    assert_eq!(
        marshal_text(&v, &[]),
        r#"{"i":{"T":"0001-01-01T01:00:00+01:00"}}"#
    );
}

#[test]
fn time_unmarshal_null_and_errors() {
    let mut t = utc_date(2026, 10, 27, 1, 2, 3, 4);
    v2::unmarshal(b"null", &mut t, &[]).expect("null");
    assert!(t.is_zero(), "null sets the zero time");
    v2::unmarshal(br#""2026-10-27T01:02:03+05:30""#, &mut t, &[]).expect("offset");
    assert_eq!(t.unix(), utc_date(2026, 10, 26, 19, 32, 3, 0).unix());
    assert_eq!(
        unmarshal_error(b"5", &mut t, &[]),
        "json: cannot unmarshal JSON number into Go time.Time"
    );
    assert_eq!(
        unmarshal_error(br#""2026-10-27T1:02:03Z""#, &mut t, &[]),
        r#"json: cannot unmarshal JSON string into Go time.Time: parsing time "2026-10-27T1:02:03Z" as "2006-01-02T15:04:05Z07:00": cannot parse "1" as "15""#
    );
    assert_eq!(
        error_text(&utc_date(10000, 1, 1, 0, 0, 0, 0), &[]),
        "json: cannot marshal from Go time.Time: year outside of range [0,9999]"
    );
}

#[test]
fn duration_has_no_default_representation() {
    assert_eq!(
        error_text(&time::SECOND, &[]),
        "json: cannot marshal from Go time.Duration: no default representation"
    );
    let mut d = Duration::default();
    assert_eq!(
        unmarshal_error(b"1", &mut d, &[]),
        "json: cannot unmarshal into Go time.Duration: no default representation"
    );
    #[derive(MarshalTo)]
    struct D {
        #[json("d")]
        d: Duration,
    }
    assert_eq!(
        error_text(
            &D { d: time::SECOND },
            &[v2::experimental_support_format_tag(true)]
        ),
        r#"json: cannot marshal from Go time.Duration within "/d": no default representation; specify an explicit format"#
    );
}

#[derive(Default, MarshalTo, UnmarshalFrom)]
struct DurationFormats {
    #[json("u,format:units")]
    u: Duration,
    #[json("s,format:sec")]
    s: Duration,
    #[json("ss,string,format:sec")]
    ss: Duration,
    #[json("m,format:milli")]
    m: Duration,
    #[json("n,format:nano")]
    n: Duration,
    #[json("i,format:iso8601")]
    i: Duration,
}

#[test]
fn duration_formats() {
    let opts = [v2::experimental_support_format_tag(true)];
    let d = 3 * time::HOUR + 25 * time::MINUTE + time::SECOND / 2;
    let v = DurationFormats {
        u: d,
        s: d,
        ss: -d,
        m: time::NANOSECOND,
        n: d,
        i: -d,
    };
    let out = marshal_text(&v, &opts);
    assert_eq!(
        out,
        r#"{"u":"3h25m0.5s","s":12300.5,"ss":"-12300.5","m":0.000001,"n":12300500000000,"i":"-PT3H25M0.5S"}"#
    );
    let mut back = DurationFormats::default();
    v2::unmarshal(out.as_bytes(), &mut back, &opts).expect("round trip");
    assert_eq!(
        (back.u, back.s, back.ss, back.m, back.n, back.i),
        (d, d, -d, time::NANOSECOND, d, -d)
    );
    assert_eq!(
        unmarshal_error(br#"{"i":"P1D"}"#, &mut back, &opts),
        r#"json: cannot unmarshal JSON string into Go time.Duration within "/i": invalid ISO 8601 duration "P1D": inaccurate year, month, week, or day units"#
    );
    assert_eq!(
        unmarshal_error(br#"{"s":9223372036.854775808}"#, &mut back, &opts),
        r#"json: cannot unmarshal JSON number into Go time.Duration within "/s": invalid duration "9223372036.854775808": value out of range"#
    );
}

#[derive(Default, MarshalTo, UnmarshalFrom)]
struct TimeFormats {
    #[json("u,format:unix")]
    u: Time,
    #[json("um,format:unixmilli")]
    um: Time,
    #[json("r,format:RFC3339")]
    r: Time,
    #[json("do,format:DateOnly")]
    date: Time,
    #[json("cu,format:'2006/01/02 15h04'")]
    custom: Time,
}

#[test]
fn time_formats() {
    let opts = [v2::experimental_support_format_tag(true)];
    let t = utc_date(2026, 10, 27, 1, 2, 3, 500_000_000);
    let v = TimeFormats {
        u: t.clone(),
        um: t.clone(),
        r: t.clone(),
        date: t.clone(),
        custom: t,
    };
    assert_eq!(
        marshal_text(&v, &opts),
        r#"{"u":1793062923.5,"um":1793062923500,"r":"2026-10-27T01:02:03Z","do":"2026-10-27","cu":"2026/10/27 01h02"}"#
    );
    let mut back = TimeFormats::default();
    v2::unmarshal(br#"{"u":-1.5,"um":"1"}"#, &mut back, &opts).expect_err("um is a number");
    v2::unmarshal(br#"{"u":-1.5,"do":"2026-10-27"}"#, &mut back, &opts).expect("unmarshal");
    assert_eq!((back.u.unix(), back.u.nanosecond()), (-2, 500_000_000));
    assert_eq!(back.date.unix(), utc_date(2026, 10, 27, 0, 0, 0, 0).unix());
}
