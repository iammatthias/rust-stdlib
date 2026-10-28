//! `#[derive(Marshal, Unmarshal)]` for `rust_stdlib::encoding::xml`: the struct
//! tables of Go's example_test.go, marshal_test.go and read_test.go, tag errors,
//! embedding and the unmarshal recursion budget. `tools/xml_check.py` compares a
//! much larger generated menu with Go itself.
#![allow(non_snake_case)]
use rust_stdlib::encoding::{
    json,
    xml::{self, Attr, Error, Name},
};
use rust_stdlib_derive::{Deserialize, Marshal, Serialize, Unmarshal};

fn encode<T: json::Serialize + ?Sized>(value: &T) -> Result<String, json::Error> {
    Ok(String::from_utf8_lossy(&json::marshal(value)?).into_owned())
}

fn text(r: Result<Vec<u8>, Error>) -> String {
    String::from_utf8(r.unwrap()).unwrap()
}

// ---- Go's ExampleMarshalIndent / ExampleEncoder ------------------------------------

#[derive(Debug, Default, PartialEq, Marshal, Unmarshal)]
struct Address {
    City: String,
    State: String,
}

#[derive(Debug, Default, PartialEq, Marshal, Unmarshal)]
struct Person {
    #[xml("person")]
    XMLName: Name,
    #[xml("id,attr")]
    Id: isize,
    #[xml("name>first")]
    FirstName: String,
    #[xml("name>last")]
    LastName: String,
    #[xml("age")]
    Age: isize,
    #[xml("height,omitempty")]
    Height: f32,
    Married: bool,
    #[xml(embed)]
    Address: Address,
    #[xml(",comment")]
    Comment: String,
}

fn john() -> Person {
    Person {
        Id: 13,
        FirstName: "John".into(),
        LastName: "Doe".into(),
        Age: 42,
        Comment: " Need more details. ".into(),
        Address: Address {
            City: "Hanga Roa".into(),
            State: "Easter Island".into(),
        },
        ..Person::default()
    }
}

#[test]
fn example_marshal_indent() {
    let want = "  <person id=\"13\">\n      <name>\n          <first>John</first>\n          <last>Doe</last>\n      </name>\n      <age>42</age>\n      <Married>false</Married>\n      <City>Hanga Roa</City>\n      <State>Easter Island</State>\n      <!-- Need more details. -->\n  </person>";
    assert_eq!(text(xml::marshal_indent(&john(), "  ", "    ")), want);
    let mut out = Vec::new();
    {
        let mut enc = xml::Encoder::new(&mut out);
        enc.indent("  ", "    ");
        enc.encode(&john()).unwrap();
    }
    assert_eq!(String::from_utf8(out).unwrap(), want);
}

#[test]
fn marshal_then_unmarshal_round_trips() {
    let bytes = xml::marshal(&john()).unwrap();
    let mut back = Person::default();
    xml::unmarshal_into(&bytes, &mut back).unwrap();
    assert_eq!(back.XMLName, Name::new("", "person"));
    assert_eq!(back.FirstName, "John");
    assert_eq!(back.Address, john().Address);
    assert_eq!(back.Comment, " Need more details. ");
}

// ---- Go's ExampleUnmarshal ------------------------------------------------------------

#[derive(Debug, Default, PartialEq, Marshal, Unmarshal)]
struct Email {
    #[xml("where,attr")]
    Where: String,
    Addr: String,
}

#[derive(Debug, Default, PartialEq, Marshal, Unmarshal)]
struct Contact {
    #[xml("Person")]
    XMLName: Name,
    #[xml("FullName")]
    Name: String,
    Phone: String,
    Email: Vec<Email>,
    #[xml("Group>Value")]
    Groups: Vec<String>,
    #[xml(embed)]
    Address: Address,
}

#[test]
fn example_unmarshal() {
    let mut v = Contact {
        Name: "none".into(),
        Phone: "none".into(),
        ..Contact::default()
    };
    let data = "\n\t\t<Person>\n\t\t\t<FullName>Grace R. Emlin</FullName>\n\t\t\t<Company>Example Inc.</Company>\n\t\t\t<Email where=\"home\">\n\t\t\t\t<Addr>gre@example.com</Addr>\n\t\t\t</Email>\n\t\t\t<Email where='work'>\n\t\t\t\t<Addr>gre@work.com</Addr>\n\t\t\t</Email>\n\t\t\t<Group>\n\t\t\t\t<Value>Friends</Value>\n\t\t\t\t<Value>Squash</Value>\n\t\t\t</Group>\n\t\t\t<City>Hanga Roa</City>\n\t\t\t<State>Easter Island</State>\n\t\t</Person>\n\t";
    xml::unmarshal_into(data.as_bytes(), &mut v).unwrap();
    assert_eq!(v.XMLName, Name::new("", "Person"));
    assert_eq!(v.Name, "Grace R. Emlin");
    assert_eq!(v.Phone, "none");
    assert_eq!(
        v.Email,
        vec![
            Email {
                Where: "home".into(),
                Addr: "gre@example.com".into()
            },
            Email {
                Where: "work".into(),
                Addr: "gre@work.com".into()
            }
        ]
    );
    assert_eq!(v.Groups, vec!["Friends", "Squash"]);
    assert_eq!(
        v.Address,
        Address {
            City: "Hanga Roa".into(),
            State: "Easter Island".into()
        }
    );
}

// ---- Go's pathTests / badPathTests -------------------------------------------------------

const PATH_TEST: &str = "\n<Result>\n    <Before>1</Before>\n    <Items>\n        <Item1>\n            <Value>A</Value>\n        </Item1>\n        <Item2>\n            <Value>B</Value>\n        </Item2>\n        <Item1>\n            <Value>C</Value>\n            <Value>D</Value>\n        </Item1>\n        <_>\n            <Value>E</Value>\n        </_>\n    </Items>\n    <After>2</After>\n</Result>\n";

#[derive(Debug, Default, PartialEq, Marshal, Unmarshal)]
struct PathTestItem {
    Value: String,
}

#[derive(Debug, Default, PartialEq, Marshal, Unmarshal)]
struct PathTestA {
    #[xml(">Item1")]
    Items: Vec<PathTestItem>,
    Before: String,
    After: String,
}

#[derive(Debug, Default, PartialEq, Marshal, Unmarshal)]
struct PathTestB {
    #[xml("Items>Item1")]
    Other: Vec<PathTestItem>,
    Before: String,
    After: String,
}

#[derive(Debug, Default, PartialEq, Marshal, Unmarshal)]
struct PathTestC {
    #[xml("Items>Item1>Value")]
    Values1: Vec<String>,
    #[xml("Items>Item2>Value")]
    Values2: Vec<String>,
    Before: String,
    After: String,
}

#[derive(Debug, Default, PartialEq, Marshal, Unmarshal)]
struct PathTestSet {
    Item1: Vec<PathTestItem>,
}

#[derive(Debug, Default, PartialEq, Marshal, Unmarshal)]
struct PathTestD {
    #[xml("Items")]
    Other: PathTestSet,
    Before: String,
    After: String,
}

#[derive(Debug, Default, PartialEq, Marshal, Unmarshal)]
struct PathTestE {
    #[xml("Items>_>Value")]
    Underline: String,
    Before: String,
    After: String,
}

fn items(values: &[&str]) -> Vec<PathTestItem> {
    values
        .iter()
        .map(|v| PathTestItem { Value: (*v).into() })
        .collect()
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).to_string()).collect()
}

#[test]
fn unmarshal_paths() {
    let (before, after) = ("1".to_string(), "2".to_string());
    let mut a = PathTestA::default();
    xml::unmarshal_into(PATH_TEST.as_bytes(), &mut a).unwrap();
    assert_eq!(
        a,
        PathTestA {
            Items: items(&["A", "D"]),
            Before: before.clone(),
            After: after.clone()
        }
    );
    let mut b = PathTestB::default();
    xml::unmarshal_into(PATH_TEST.as_bytes(), &mut b).unwrap();
    assert_eq!(
        b,
        PathTestB {
            Other: items(&["A", "D"]),
            Before: before.clone(),
            After: after.clone()
        }
    );
    let mut c = PathTestC::default();
    xml::unmarshal_into(PATH_TEST.as_bytes(), &mut c).unwrap();
    assert_eq!(
        c,
        PathTestC {
            Values1: strings(&["A", "C", "D"]),
            Values2: strings(&["B"]),
            Before: before.clone(),
            After: after.clone()
        }
    );
    let mut d = PathTestD::default();
    xml::unmarshal_into(PATH_TEST.as_bytes(), &mut d).unwrap();
    assert_eq!(
        d,
        PathTestD {
            Other: PathTestSet {
                Item1: items(&["A", "D"])
            },
            Before: before.clone(),
            After: after.clone()
        }
    );
    let mut e = PathTestE::default();
    xml::unmarshal_into(PATH_TEST.as_bytes(), &mut e).unwrap();
    assert_eq!(
        e,
        PathTestE {
            Underline: "E".into(),
            Before: before,
            After: after
        }
    );
}

#[derive(Debug, Default, Marshal, Unmarshal)]
struct BadPathTestA {
    #[xml("items>item1")]
    First: String,
    #[xml("items>item2")]
    Other: String,
    #[xml("items")]
    Second: String,
}

#[derive(Debug, Default, Marshal, Unmarshal)]
struct BadPathTestB {
    #[xml("items>item2>value")]
    Other: String,
    #[xml("items>item1")]
    First: String,
    #[xml("items>item1>value")]
    Second: String,
}

#[derive(Debug, Default, Marshal, Unmarshal)]
struct BadPathTestC {
    First: String,
    #[xml("First")]
    Second: String,
}

#[derive(Debug, Default, Marshal, Unmarshal)]
struct BadPathEmbeddedA {
    First: String,
}

#[derive(Debug, Default, Marshal, Unmarshal)]
struct BadPathEmbeddedB {
    #[xml("First")]
    Second: String,
}

#[derive(Debug, Default, Marshal, Unmarshal)]
struct BadPathTestD {
    #[xml(embed)]
    A: BadPathEmbeddedA,
    #[xml(embed)]
    B: BadPathEmbeddedB,
}

fn tag_path<T: Default + xml::Unmarshal>() -> xml::TagPathError {
    match xml::unmarshal_into(PATH_TEST.as_bytes(), &mut T::default()) {
        Err(Error::TagPath(e)) => e,
        other => panic!("expected TagPathError, got {other:?}"),
    }
}

#[test]
fn unmarshal_bad_paths() {
    let e = tag_path::<BadPathTestA>();
    assert_eq!(
        (
            e.struct_type.as_str(),
            e.field1.as_str(),
            e.tag1.as_str(),
            e.field2.as_str(),
            e.tag2.as_str()
        ),
        ("BadPathTestA", "First", "items>item1", "Second", "items")
    );
    assert_eq!(
        e.to_string(),
        "BadPathTestA field \"First\" with tag \"items>item1\" conflicts with field \"Second\" with tag \"items\""
    );
    let e = tag_path::<BadPathTestB>();
    assert_eq!(
        (e.field1.as_str(), e.tag2.as_str()),
        ("First", "items>item1>value")
    );
    let e = tag_path::<BadPathTestC>();
    assert_eq!(
        (
            e.field1.as_str(),
            e.tag1.as_str(),
            e.field2.as_str(),
            e.tag2.as_str()
        ),
        ("First", "", "Second", "First")
    );
    let e = tag_path::<BadPathTestD>();
    assert_eq!(
        (e.struct_type.as_str(), e.field1.as_str(), e.field2.as_str()),
        ("BadPathTestD", "First", "Second")
    );
}

// ---- Go's TestEncodeXMLNS, TestMarshalZeroValue, Issue 7113, 20953 -------------------------

#[derive(Default, Marshal)]
struct XmlNs1 {
    #[xml("Test")]
    XMLName: Name,
    #[xml("xmlns,attr")]
    Ns: String,
    Body: String,
}

#[derive(Default, Marshal)]
struct XmlNs2 {
    #[xml("http://example.com/ns body")]
    Body: String,
}

#[derive(Default, Marshal)]
struct XmlNs3 {
    #[xml("http://example.com/ns Test")]
    XMLName: Name,
    Body: String,
}

#[derive(Default, Marshal)]
struct XmlNs4 {
    #[xml("xmlns,attr")]
    Ns: String,
    Body: String,
}

#[test]
fn encode_xmlns() {
    let ns = "http://example.com/ns".to_string();
    assert_eq!(
        text(xml::marshal(&XmlNs1 {
            Ns: ns.clone(),
            Body: "hello world".into(),
            ..XmlNs1::default()
        })),
        "<Test xmlns=\"http://example.com/ns\"><Body>hello world</Body></Test>"
    );
    assert_eq!(
        text(xml::marshal(&XmlNs2 {
            Body: "hello world".into()
        })),
        "<XmlNs2><body xmlns=\"http://example.com/ns\">hello world</body></XmlNs2>"
    );
    assert_eq!(
        text(xml::marshal(&XmlNs3 {
            Body: "hello world".into(),
            ..XmlNs3::default()
        })),
        "<Test xmlns=\"http://example.com/ns\"><Body>hello world</Body></Test>"
    );
    // Go's fourth case documents a known mismatch: the default name is the type.
    assert_eq!(
        text(xml::marshal(&XmlNs4 {
            Ns: ns,
            Body: "hello world".into()
        })),
        "<XmlNs4 xmlns=\"http://example.com/ns\"><Body>hello world</Body></XmlNs4>"
    );
}

#[derive(Debug, Default, Marshal, Unmarshal)]
struct LayerTwo {
    #[xml("value_two,attr,omitempty")]
    ValueTwo: Option<isize>,
}

#[derive(Debug, Default, Marshal, Unmarshal)]
struct LayerOne {
    #[xml("l1")]
    XMLName: Name,
    #[xml("value,omitempty")]
    Value: Option<f64>,
    #[xml(embed, ",omitempty")]
    LayerTwo: Option<LayerTwo>,
}

#[test]
fn marshal_zero_value_behind_nil_embedded_pointer() {
    let proof = "<l1><value>1.2345</value></l1>";
    let mut l1 = LayerOne::default();
    xml::unmarshal_into(proof.as_bytes(), &mut l1).unwrap();
    assert_eq!(l1.Value, Some(1.2345));
    assert_eq!(text(xml::marshal(&l1)), proof);
}

#[derive(Default, Marshal)]
struct InvalidInner {
    #[xml("type,attr")]
    XMLName: Name,
}

#[derive(Default, Marshal)]
struct InvalidXMLName {
    #[xml("error")]
    XMLName: Name,
    Type: InvalidInner,
}

#[test]
fn invalid_xml_name_tag_is_reported() {
    let e = xml::marshal(&InvalidXMLName::default()).unwrap_err();
    assert!(e.to_string().contains("invalid tag"), "{e}");
}

#[derive(Default, Marshal)]
struct EmptyNs {
    #[xml("")]
    XMLName: Name,
}

#[test]
fn xml_name_with_empty_tag_uses_the_type_name() {
    let v = EmptyNs::default();
    assert_eq!(text(xml::marshal(&v)), "<EmptyNs></EmptyNs>");
}

// ---- attributes, chardata and the attribute hooks ------------------------------------------------

#[derive(Debug, Default, PartialEq, Marshal, Unmarshal)]
struct ParamPtr {
    #[xml("int,attr")]
    Int: Option<isize>,
}

#[derive(Debug, Default, PartialEq, Marshal, Unmarshal)]
struct ParamVal {
    #[xml("int,attr")]
    Int: isize,
}

#[derive(Debug, Default, PartialEq, Marshal, Unmarshal)]
struct ParamStringPtr {
    #[xml("int,attr")]
    Int: Option<String>,
}

#[test]
fn unmarshal_attr_into_values_and_pointers() {
    let x = b"<Param int=\"1\" />";
    let mut p = ParamPtr::default();
    xml::unmarshal_into(x, &mut p).unwrap();
    assert_eq!(p.Int, Some(1));
    let mut v = ParamVal::default();
    xml::unmarshal_into(x, &mut v).unwrap();
    assert_eq!(v.Int, 1);
    let mut s = ParamStringPtr::default();
    xml::unmarshal_into(x, &mut s).unwrap();
    assert_eq!(s.Int.as_deref(), Some("1"));
}

#[derive(Debug, Default, Marshal, Unmarshal)]
struct TestThree {
    #[xml("Test3")]
    XMLName: Name,
    #[xml(",attr")]
    Attr: String,
}

#[test]
fn unmarshal_without_name_type_ignores_the_charset_pseudo_attribute() {
    let mut x = TestThree::default();
    xml::unmarshal_into(
        b"\n<?xml version=\"1.0\" charset=\"utf-8\"?>\n<Test3 Attr=\"OK\" />",
        &mut x,
    )
    .unwrap();
    assert_eq!(x.Attr, "OK");
    let mut x = TestThree::default();
    let e = xml::unmarshal_into(b"<Other/>", &mut x).unwrap_err();
    assert_eq!(
        e.to_string(),
        "expected element type <Test3> but have <Other>"
    );
}

#[derive(Debug, Default, Marshal, Unmarshal)]
struct Item {
    FieldA: String,
}

#[test]
fn unmarshal_matches_field_names_case_sensitively() {
    let mut i = Item::default();
    xml::unmarshal_into(
        b"<item><FieldA>abcd</FieldA><fielda>no</fielda></item>",
        &mut i,
    )
    .unwrap();
    assert_eq!(i.FieldA, "abcd");
}

#[derive(Debug, Default, Marshal, Unmarshal)]
struct AllScalars {
    True1: bool,
    True2: bool,
    False1: bool,
    False2: bool,
    Int: isize,
    Int8: i8,
    Int16: i16,
    Int32: i32,
    Int64: i64,
    Uint: usize,
    Uint8: u8,
    Uint16: u16,
    Uint32: u32,
    Uint64: u64,
    Float32: f32,
    Float64: f64,
    String: String,
    PtrString: Option<String>,
}

#[test]
fn all_scalars() {
    let input = "<allscalars>\n\t<True1>true</True1>\n\t<True2>1</True2>\n\t<False1>false</False1>\n\t<False2>0</False2>\n\t<Int>1</Int>\n\t<Int8>-2</Int8>\n\t<Int16>3</Int16>\n\t<Int32>-4</Int32>\n\t<Int64>5</Int64>\n\t<Uint>6</Uint>\n\t<Uint8>7</Uint8>\n\t<Uint16>8</Uint16>\n\t<Uint32>9</Uint32>\n\t<Uint64>10</Uint64>\n\t<Float>12.0</Float>\n\t<Float32>13.0</Float32>\n\t<Float64>14.0</Float64>\n\t<String>15</String>\n\t<PtrString>16</PtrString>\n</allscalars>";
    let mut a = AllScalars::default();
    xml::unmarshal_into(input.as_bytes(), &mut a).unwrap();
    assert!(a.True1 && a.True2 && !a.False1 && !a.False2);
    assert_eq!(
        (a.Int, a.Int8, a.Int16, a.Int32, a.Int64),
        (1, -2, 3, -4, 5)
    );
    assert_eq!(
        (a.Uint, a.Uint8, a.Uint16, a.Uint32, a.Uint64),
        (6, 7, 8, 9, 10)
    );
    assert_eq!((a.Float32, a.Float64), (13.0, 14.0));
    assert_eq!(a.String, "15");
    assert_eq!(a.PtrString.as_deref(), Some("16"));
}

#[derive(Default, Marshal, Unmarshal)]
struct Byte {
    #[xml("b,attr,omitempty")]
    B: u8,
}

#[test]
fn attribute_conversion_errors_are_returned() {
    // Go issue 16158: unmarshalAttr used to ignore copyValue's error.
    let e = xml::unmarshal_into(b"<foo b=\"HELLOWORLD\"></foo>", &mut Byte::default()).unwrap_err();
    assert!(e.to_string().contains("ParseUint"), "{e}");
}

// ---- tag validation ------------------------------------------------------------------------------

#[derive(Default, Marshal, Unmarshal)]
struct BadChars {
    #[xml(",attr,chardata")]
    A: String,
}

#[derive(Default, Marshal, Unmarshal)]
struct BadOmit {
    #[xml(",chardata,omitempty")]
    A: String,
}

#[derive(Default, Marshal, Unmarshal)]
struct Trailing {
    #[xml("a>")]
    A: String,
}

#[derive(Default, Marshal, Unmarshal)]
struct Skipped {
    A: String,
    #[xml("-")]
    B: String,
}

#[test]
fn tag_errors_have_gos_texts() {
    assert_eq!(
        xml::marshal(&BadChars::default()).unwrap_err().to_string(),
        "xml: invalid tag in field A of type BadChars: \",attr,chardata\""
    );
    assert_eq!(
        xml::marshal(&BadOmit::default()).unwrap_err().to_string(),
        "xml: invalid tag in field A of type BadOmit: \",chardata,omitempty\""
    );
    assert_eq!(
        xml::marshal(&Trailing::default()).unwrap_err().to_string(),
        "xml: trailing '>' in field A of type Trailing"
    );
    // A field tagged "-" is omitted.
    let s = Skipped {
        A: "a".into(),
        B: "b".into(),
    };
    assert_eq!(text(xml::marshal(&s)), "<Skipped><A>a</A></Skipped>");
    let mut back = Skipped::default();
    xml::unmarshal_into(b"<Skipped><A>x</A><B>y</B></Skipped>", &mut back).unwrap();
    assert_eq!((back.A.as_str(), back.B.as_str()), ("x", ""));
}

// ---- the unmarshal recursion budget ----------------------------------------------------------------

#[derive(Debug, Default, PartialEq, Marshal, Unmarshal)]
struct Tree {
    #[xml("tree")]
    xml_name: Name,
    #[xml("v,attr")]
    value: String,
    #[xml("tree")]
    kids: Vec<Tree>,
}

fn nested(depth: usize) -> String {
    format!("{}{}", "<tree>".repeat(depth), "</tree>".repeat(depth))
}

#[test]
fn deep_documents_stop_at_the_stack_budget_not_the_stack() {
    // 2 MiB is a typical spawned-thread stack; the default 1 MiB budget makes
    // hostile nesting an error instead of an abort.
    let handle = std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(|| {
            let mut v = Tree::default();
            xml::unmarshal_into(nested(10_000).as_bytes(), &mut v)
        })
        .unwrap();
    let e = handle.join().unwrap().unwrap_err();
    assert_eq!(e.to_string(), "exceeded max depth");
}

#[test]
fn deep_documents_decode_up_to_gos_limit_with_a_matching_stack() {
    let handle = std::thread::Builder::new()
        .stack_size(1 << 30)
        .spawn(|| {
            let doc = nested(10_000);
            let mut d = xml::Decoder::new(doc.as_bytes());
            d.max_unmarshal_stack = usize::MAX;
            let mut v = Tree::default();
            d.decode_into(&mut v).unwrap();
            let doc = nested(10_001);
            let mut d = xml::Decoder::new(doc.as_bytes());
            d.max_unmarshal_stack = usize::MAX;
            let e = d.decode_into(&mut Tree::default()).unwrap_err();
            assert_eq!(e.to_string(), "exceeded max depth");
            // Dropping the 10000-deep value recurses too.
            drop(v);
        })
        .unwrap();
    handle.join().unwrap();
}

#[test]
fn shallow_nesting_round_trips() {
    let mut v = Tree::default();
    xml::unmarshal_into(nested(50).as_bytes(), &mut v).unwrap();
    assert_eq!(text(xml::marshal(&v)).replace(" v=\"\"", ""), nested(50));
    let _ = Attr::default();
}

#[derive(Debug, Default, PartialEq, Serialize, Deserialize, Marshal, Unmarshal)]
struct Both {
    #[xml("a,attr")]
    a: String,
    #[xml("b>c")]
    b: u8,
}

#[test]
fn one_struct_can_derive_json_and_xml() {
    let v = Both {
        a: "x".into(),
        b: 7,
    };
    assert_eq!(
        text(xml::marshal(&v)),
        "<Both a=\"x\"><b><c>7</c></b></Both>"
    );
    assert_eq!(encode(&v).unwrap(), "{\"a\":\"x\",\"b\":7}");
    let mut back = Both::default();
    xml::unmarshal_into(b"<Both a='x'><b><c>7</c></b></Both>", &mut back).unwrap();
    assert_eq!(back, v);
}
