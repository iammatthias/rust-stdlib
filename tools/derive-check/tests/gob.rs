//! encoding/gob on `#[derive(Reflect)]` types, after Go's codec_test.go,
//! encoder_test.go and gobencdec_test.go: end-to-end values, overflow,
//! nesting and auto-indirection, ignored and reordered fields, interfaces,
//! GobEncoder/BinaryMarshaler types and the error cases.
#![allow(non_snake_case, dead_code, clippy::type_complexity)]
use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Read, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

use rust_stdlib::encoding::gob::{self, Decoder, Encoder};
use rust_stdlib::reflect::{self, Reflect, Value};
use rust_stdlib::strconv::Complex;
use rust_stdlib_derive::{reflect_methods, Reflect};

/// A byte queue that is both the encoder's writer and the decoder's reader
/// (Go's `bytes.Buffer`).
#[derive(Clone, Default)]
struct Buf(Arc<Mutex<VecDeque<u8>>>);

impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend(b.iter().copied());
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for Buf {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut q = self.0.lock().unwrap();
        let n = out.len().min(q.len());
        for slot in out.iter_mut().take(n) {
            *slot = q.pop_front().unwrap();
        }
        Ok(n)
    }
}

impl Buf {
    fn reset(&self) {
        self.0.lock().unwrap().clear();
    }
    fn bytes(&self) -> Vec<u8> {
        self.0.lock().unwrap().iter().copied().collect()
    }
}

fn pair() -> (Buf, Encoder, Decoder) {
    let b = Buf::default();
    (
        b.clone(),
        Encoder::new(b.clone()),
        Decoder::from_byte_reader(b),
    )
}

fn panic_text<R>(f: impl FnOnce() -> R) -> String {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(_) => panic!("expected a panic"),
        Err(e) => e
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default(),
    }
}

// ---- TestEndToEnd ----

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
struct T2 {
    pub T: String,
}

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
struct T3 {
    pub X: f64,
    pub Z: Option<isize>,
}

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
struct EndToEnd {
    pub A: isize,
    pub B: isize,
    pub C: isize,
    pub M: BTreeMap<String, Option<f64>>,
    pub M2: BTreeMap<isize, T3>,
    pub Mstring: BTreeMap<String, String>,
    pub Mintptr: BTreeMap<isize, Option<isize>>,
    pub Marr: BTreeMap<[String; 2], [Option<f64>; 2]>,
    pub EmptyMap: BTreeMap<String, isize>,
    pub N: Option<[f64; 3]>,
    pub Strs: Option<[String; 2]>,
    pub Int64s: Option<Vec<i64>>,
    pub S: String,
    pub Y: Vec<u8>,
    pub T: Option<T2>,
}

#[test]
fn end_to_end() {
    let (pi, e) = (3.14159, 2.71828);
    let (meaning, fingers) = (42isize, 5isize);
    let t1 = EndToEnd {
        A: 17,
        B: 18,
        C: -5,
        M: BTreeMap::from([("pi".into(), Some(pi)), ("e".into(), Some(e))]),
        M2: BTreeMap::from([
            (
                4,
                T3 {
                    X: pi,
                    Z: Some(meaning),
                },
            ),
            (
                10,
                T3 {
                    X: e,
                    Z: Some(fingers),
                },
            ),
        ]),
        Mstring: BTreeMap::from([("pi".into(), "3.14".into()), ("e".into(), "2.71".into())]),
        Mintptr: BTreeMap::from([(meaning, Some(fingers)), (fingers, Some(meaning))]),
        Marr: BTreeMap::from([
            (["string1".into(), "string2".into()], [Some(pi), Some(e)]),
            (["string2".into(), "string1".into()], [Some(e), Some(2.0)]),
        ]),
        EmptyMap: BTreeMap::new(),
        N: Some([1.5, 2.5, 3.5]),
        Strs: Some(["string1".into(), "string2".into()]),
        Int64s: Some(vec![77, 89, 123412342134]),
        S: "Now is the time".into(),
        Y: b"hello, sailor".to_vec(),
        T: Some(T2 {
            T: "this is T2".into(),
        }),
    };
    let (_b, enc, dec) = pair();
    enc.encode(&t1).expect("encode");
    let mut back = EndToEnd::default();
    dec.decode(&mut back).expect("decode");
    assert_eq!(back, t1);
}

// ---- TestOverflow ----

#[derive(Reflect, Clone, Default)]
#[reflect(pkg = "main")]
struct InputT {
    pub Maxi: i64,
    pub Mini: i64,
    pub Maxu: u64,
    pub Maxf: f64,
    pub Minf: f64,
    pub Maxc: Complex,
    pub Minc: Complex,
}

#[derive(Reflect, Clone, Default)]
#[reflect(pkg = "main")]
struct OutI8 {
    pub Maxi: i8,
    pub Mini: i8,
}
#[derive(Reflect, Clone, Default)]
#[reflect(pkg = "main")]
struct OutI16 {
    pub Maxi: i16,
    pub Mini: i16,
}
#[derive(Reflect, Clone, Default)]
#[reflect(pkg = "main")]
struct OutI32 {
    pub Maxi: i32,
    pub Mini: i32,
}
#[derive(Reflect, Clone, Default)]
#[reflect(pkg = "main")]
struct OutU8 {
    pub Maxu: u8,
}
#[derive(Reflect, Clone, Default)]
#[reflect(pkg = "main")]
struct OutU16 {
    pub Maxu: u16,
}
#[derive(Reflect, Clone, Default)]
#[reflect(pkg = "main")]
struct OutU32 {
    pub Maxu: u32,
}
#[derive(Reflect, Clone, Default)]
#[reflect(pkg = "main")]
struct OutF32 {
    pub Maxf: f32,
    pub Minf: f32,
}

#[test]
fn overflow() {
    fn check<T: Reflect>(it: InputT, want: &str, label: &str) {
        let (_b, enc, dec) = pair();
        enc.encode(&it).unwrap();
        let mut out = reflect::zero(&T::reflect_type());
        let p = reflect::new(&T::reflect_type());
        let err = dec.decode_value(&p).expect_err(label);
        assert_eq!(err.to_string(), want, "{label}");
        out = p.elem();
        let _ = out;
    }
    let i = |f: fn(&mut InputT)| {
        let mut it = InputT::default();
        f(&mut it);
        it
    };
    let ovf = |n: &str| format!("value for \"{n}\" out of range");
    check::<OutI8>(
        i(|t| t.Maxi = i8::MAX as i64 + 1),
        &ovf("Maxi"),
        "int8 over",
    );
    check::<OutI8>(
        i(|t| t.Mini = i8::MIN as i64 - 1),
        &ovf("Mini"),
        "int8 under",
    );
    check::<OutI16>(
        i(|t| t.Maxi = i16::MAX as i64 + 1),
        &ovf("Maxi"),
        "int16 over",
    );
    check::<OutI16>(
        i(|t| t.Mini = i16::MIN as i64 - 1),
        &ovf("Mini"),
        "int16 under",
    );
    check::<OutI32>(
        i(|t| t.Maxi = i32::MAX as i64 + 1),
        &ovf("Maxi"),
        "int32 over",
    );
    check::<OutI32>(
        i(|t| t.Mini = i32::MIN as i64 - 1),
        &ovf("Mini"),
        "int32 under",
    );
    check::<OutU8>(i(|t| t.Maxu = u8::MAX as u64 + 1), &ovf("Maxu"), "uint8");
    check::<OutU16>(i(|t| t.Maxu = u16::MAX as u64 + 1), &ovf("Maxu"), "uint16");
    check::<OutU32>(i(|t| t.Maxu = u32::MAX as u64 + 1), &ovf("Maxu"), "uint32");
    check::<OutF32>(
        i(|t| t.Maxf = f32::MAX as f64 * 2.0),
        &ovf("Maxf"),
        "float32",
    );
}

// ---- TestNesting, TestAutoIndirection ----

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
struct RT {
    pub A: String,
    pub Next: Option<Box<RT>>,
}

#[test]
fn nesting() {
    let rt = RT {
        A: "level1".into(),
        Next: Some(Box::new(RT {
            A: "level2".into(),
            Next: None,
        })),
    };
    let (_b, enc, dec) = pair();
    enc.encode(&rt).unwrap();
    let mut d = RT::default();
    dec.decode(&mut d).unwrap();
    assert_eq!(d, rt);
}

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
struct A0 {
    pub A: isize,
    pub B: isize,
    pub C: isize,
    pub D: isize,
}
#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
struct A1 {
    pub A: isize,
    pub B: Option<isize>,
    pub C: Option<Option<isize>>,
    pub D: Option<Option<Option<isize>>>,
}
#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
struct A2 {
    pub A: Option<Option<Option<isize>>>,
    pub B: Option<Option<isize>>,
    pub C: Option<isize>,
    pub D: isize,
}

#[test]
fn auto_indirection() {
    let (b, enc, dec) = pair();
    let t1 = A1 {
        A: 17,
        B: Some(177),
        C: Some(Some(1777)),
        D: Some(Some(Some(17777))),
    };
    enc.encode(&t1).unwrap();
    let mut t0 = A0::default();
    dec.decode(&mut t0).unwrap();
    assert_eq!(
        t0,
        A0 {
            A: 17,
            B: 177,
            C: 1777,
            D: 17777
        }
    );
    let t2 = A2 {
        A: Some(Some(Some(17))),
        B: Some(Some(177)),
        C: Some(1777),
        D: 17777,
    };
    b.reset();
    enc.encode(&t2).unwrap();
    t0 = A0::default();
    dec.decode(&mut t0).unwrap();
    assert_eq!(
        t0,
        A0 {
            A: 17,
            B: 177,
            C: 1777,
            D: 17777
        }
    );
    b.reset();
    enc.encode(&A0 {
        A: 17,
        B: 177,
        C: 1777,
        D: 17777,
    })
    .unwrap();
    let mut t1b = A1::default();
    dec.decode(&mut t1b).unwrap();
    assert_eq!(t1b, t1);
}

// ---- TestReorderedFields, TestIgnoredFields, TestUnexportedFields ----

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
struct Reordered1 {
    pub A: isize,
    pub B: f64,
    pub C: String,
}
#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
struct Reordered2 {
    pub C: String,
    pub B: f64,
    pub A: isize,
}

#[test]
fn reordered_fields() {
    let (_b, enc, dec) = pair();
    enc.encode(&Reordered1 {
        A: 23,
        B: 7.25,
        C: "hi".into(),
    })
    .unwrap();
    let mut o = Reordered2::default();
    dec.decode(&mut o).unwrap();
    assert_eq!(
        o,
        Reordered2 {
            C: "hi".into(),
            B: 7.25,
            A: 23
        }
    );
}

#[derive(Reflect, Clone, Default)]
#[reflect(pkg = "main")]
struct IgnoredFull {
    pub A: isize,
    pub B: Vec<String>,
    pub C: BTreeMap<String, isize>,
    pub D: T3,
    pub E: [isize; 3],
    pub F: Value,
}
#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
struct IgnoredFew {
    pub A: isize,
}

#[test]
fn ignored_fields() {
    let (_b, enc, dec) = pair();
    enc.encode(&IgnoredFull {
        A: 9,
        B: vec!["x".into()],
        C: BTreeMap::from([("k".into(), 1)]),
        D: T3 { X: 1.0, Z: Some(2) },
        E: [1, 2, 3],
        F: Value::default(),
    })
    .unwrap();
    let mut o = IgnoredFew::default();
    dec.decode(&mut o).unwrap();
    assert_eq!(o, IgnoredFew { A: 9 });
}

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
struct Unexp {
    pub A: isize,
    b: isize,
    pub C: isize,
}

#[test]
fn unexported_fields_are_not_sent() {
    let (_b, enc, dec) = pair();
    enc.encode(&Unexp { A: 1, b: 2, C: 3 }).unwrap();
    let mut o = Unexp { A: 0, b: 99, C: 0 };
    dec.decode(&mut o).unwrap();
    assert_eq!(o, Unexp { A: 1, b: 99, C: 3 });
}

// ---- merge semantics: fields not sent keep their values ----

#[test]
fn zero_fields_keep_the_destination() {
    let (_b, enc, dec) = pair();
    enc.encode(&A0 {
        A: 0,
        B: 5,
        C: 0,
        D: 0,
    })
    .unwrap();
    let mut o = A0 {
        A: 1,
        B: 2,
        C: 3,
        D: 4,
    };
    dec.decode(&mut o).unwrap();
    assert_eq!(
        o,
        A0 {
            A: 1,
            B: 5,
            C: 3,
            D: 4
        }
    );
}

// ---- interfaces: TestInterface, TestInterfaceBasic, TestIgnoreInterface ----

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
struct Square {
    pub Side: f64,
}
#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
struct Circle {
    pub Radius: f64,
}

#[derive(Reflect, Clone, Default)]
#[reflect(pkg = "main")]
struct Drawing {
    pub Name: String,
    pub Shapes: Vec<Value>,
    pub Main: Value,
}

#[derive(Reflect, Clone, Default)]
#[reflect(pkg = "main")]
struct NameOnly {
    pub Name: String,
}

#[test]
fn interface_values() {
    gob::register(&Square::default());
    gob::register(&Circle::default());
    let d = Drawing {
        Name: "d".into(),
        Shapes: vec![
            Square { Side: 2.0 }.to_value(),
            Circle { Radius: 1.5 }.to_value(),
            5i64.to_value(),
            "str".to_string().to_value(),
        ],
        Main: Square { Side: 9.0 }.to_value(),
    };
    let (_b, enc, dec) = pair();
    enc.encode(&d).unwrap();
    let mut o = Drawing::default();
    dec.decode(&mut o).unwrap();
    assert_eq!(o.Name, "d");
    assert_eq!(o.Shapes.len(), 4);
    assert_eq!(
        Square::from_value(&o.Shapes[0]).unwrap(),
        Square { Side: 2.0 }
    );
    assert_eq!(
        Circle::from_value(&o.Shapes[1]).unwrap(),
        Circle { Radius: 1.5 }
    );
    assert_eq!(o.Shapes[2].int(), 5);
    assert_eq!(o.Shapes[3].text(), "str");
    assert_eq!(Square::from_value(&o.Main).unwrap(), Square { Side: 9.0 });
}

#[test]
fn ignore_interface_field() {
    // Go's encoder rejects an unregistered concrete type in an interface
    // field even when the receiver ignores that field.
    gob::register(&Square::default());
    gob::register(&Circle::default());
    let (_b, enc, dec) = pair();
    enc.encode(&Drawing {
        Name: "keep".into(),
        Shapes: vec![Square { Side: 1.0 }.to_value()],
        Main: Circle { Radius: 3.0 }.to_value(),
    })
    .unwrap();
    let mut o = NameOnly::default();
    dec.decode(&mut o).unwrap();
    assert_eq!(o.Name, "keep");
}

#[test]
fn nil_pointer_inside_interface() {
    let d = Drawing {
        Name: "d".into(),
        Shapes: vec![],
        Main: reflect::zero(&reflect::pointer_to(&reflect::type_for::<Circle>())),
    };
    let (_b, enc, _dec) = pair();
    let err = enc.encode(&d).unwrap_err();
    assert_eq!(
        err.to_string(),
        "gob: gob: cannot encode nil pointer of type *main.Circle inside interface"
    );
}

#[test]
fn unregistered_name_is_an_error() {
    // A stream naming a type this process never registered.
    #[derive(Reflect, Clone, Default)]
    #[reflect(pkg = "main")]
    struct Unregistered {
        pub A: isize,
    }
    let d = Drawing {
        Name: "d".into(),
        Shapes: vec![],
        Main: Unregistered { A: 1 }.to_value(),
    };
    let (_b, enc, _dec) = pair();
    let err = enc.encode(&d).unwrap_err();
    assert_eq!(
        err.to_string(),
        "gob: type not registered for interface: main.Unregistered"
    );
}

// ---- recursion ----

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
struct RecMap {
    pub M: BTreeMap<String, RecMapElem>,
}
#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
struct RecMapElem {
    pub Inner: Option<Box<RecMap>>,
    pub N: isize,
}

#[test]
fn recursive_map_type() {
    let inner = RecMap {
        M: BTreeMap::from([("b".to_string(), RecMapElem { Inner: None, N: 2 })]),
    };
    let top = RecMap {
        M: BTreeMap::from([(
            "a".to_string(),
            RecMapElem {
                Inner: Some(Box::new(inner)),
                N: 1,
            },
        )]),
    };
    let (_b, enc, dec) = pair();
    enc.encode(&top).unwrap();
    let mut o = RecMap::default();
    dec.decode(&mut o).unwrap();
    assert_eq!(o, top);
}

// ---- GobEncoder / BinaryMarshaler (gobencdec_test.go) ----

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
struct ByteStruct {
    pub a: u8,
}

/// GobEncoder with a value receiver, as `StringStruct`.
#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
struct StringStruct {
    pub s: String,
}

#[reflect_methods]
impl StringStruct {
    pub fn GobEncode(&self) -> (Vec<u8>, Result<(), String>) {
        (self.s.clone().into_bytes(), Ok(()))
    }
    pub fn GobDecode(&mut self, data: &[u8]) -> Result<(), String> {
        self.s = String::from_utf8_lossy(data).into_owned();
        Ok(())
    }
}

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
struct GobTest0 {
    pub X: isize,
    pub G: StringStruct,
}

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
struct GobTest1 {
    pub X: isize,
    pub G: Option<StringStruct>,
}

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
struct GobTest2 {
    pub X: isize,
    pub G: String,
}

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
struct GobTest3 {
    pub X: isize,
    pub G: Vec<StringStruct>,
}

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
struct GobTestArr {
    pub X: isize,
    pub G: [StringStruct; 2],
}

#[test]
fn gob_encoder_field_and_value() {
    let (_b, enc, dec) = pair();
    enc.encode(&GobTest0 {
        X: 17,
        G: StringStruct { s: "HIJKL".into() },
    })
    .unwrap();
    let mut o = GobTest0::default();
    dec.decode(&mut o).unwrap();
    assert_eq!(o.X, 17);
    assert_eq!(o.G.s, "HIJKL");

    // A pointer to the type on the receiving side.
    let (_b, enc, dec) = pair();
    enc.encode(&GobTest0 {
        X: 1,
        G: StringStruct { s: "xyz".into() },
    })
    .unwrap();
    let mut p = GobTest1::default();
    dec.decode(&mut p).unwrap();
    assert_eq!(p.G.unwrap().s, "xyz");

    // The same type as a slice and an array element.
    let (_b, enc, dec) = pair();
    enc.encode(&GobTest3 {
        X: 5,
        G: vec![
            StringStruct { s: "a".into() },
            StringStruct { s: "b".into() },
        ],
    })
    .unwrap();
    let mut s = GobTest3::default();
    dec.decode(&mut s).unwrap();
    assert_eq!(
        s.G.iter().map(|g| g.s.as_str()).collect::<Vec<_>>(),
        ["a", "b"]
    );
    let (_b, enc, dec) = pair();
    let arr = GobTestArr {
        X: 5,
        G: [
            StringStruct { s: "p".into() },
            StringStruct { s: "q".into() },
        ],
    };
    enc.encode(&arr).unwrap();
    let mut a = GobTestArr::default();
    dec.decode(&mut a).unwrap();
    assert_eq!(a, arr);
}

#[test]
fn gob_encoder_fields_of_different_type() {
    // A GobEncoder field cannot be decoded into a plain string, nor the
    // converse.
    let (_b, enc, dec) = pair();
    enc.encode(&GobTest0 {
        X: 1,
        G: StringStruct { s: "x".into() },
    })
    .unwrap();
    let mut o = GobTest2::default();
    let err = dec.decode(&mut o).unwrap_err();
    assert_eq!(
        err.to_string(),
        "gob: wrong type (string) for received field GobTest0.G"
    );
}

#[test]
fn gob_encoder_ignored_field() {
    #[derive(Reflect, Clone, Default)]
    #[reflect(pkg = "main")]
    struct OnlyX {
        pub X: isize,
    }
    let (_b, enc, dec) = pair();
    enc.encode(&GobTest0 {
        X: 17,
        G: StringStruct {
            s: "skip me".into(),
        },
    })
    .unwrap();
    let mut o = OnlyX::default();
    dec.decode(&mut o).unwrap();
    assert_eq!(o.X, 17);
}

/// BinaryMarshaler, as Go's `Gobber`-free `BinaryGobber`.
#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
struct BinaryGobber {
    pub n: i64,
}

#[reflect_methods]
impl BinaryGobber {
    pub fn MarshalBinary(&self) -> (Vec<u8>, Result<(), String>) {
        (self.n.to_be_bytes().to_vec(), Ok(()))
    }
    pub fn UnmarshalBinary(&mut self, data: &[u8]) -> Result<(), String> {
        let a: [u8; 8] = data.try_into().map_err(|_| "short".to_string())?;
        self.n = i64::from_be_bytes(a);
        Ok(())
    }
}

#[test]
fn binary_marshaler_top_level() {
    let (_b, enc, dec) = pair();
    enc.encode(&BinaryGobber { n: -123456789 }).unwrap();
    let mut o = BinaryGobber::default();
    dec.decode(&mut o).unwrap();
    assert_eq!(o.n, -123456789);
}

#[derive(Reflect, Clone, Default)]
#[reflect(pkg = "main")]
struct ErrGobber {
    pub n: i64,
}

#[reflect_methods]
impl ErrGobber {
    pub fn GobEncode(&self) -> (Vec<u8>, Result<(), String>) {
        (Vec::new(), Err("encode failed".into()))
    }
    pub fn GobDecode(&mut self, _data: &[u8]) -> Result<(), String> {
        Err("decode failed".into())
    }
}

#[test]
fn gob_encoder_errors_are_returned() {
    let (_b, enc, _dec) = pair();
    let err = enc.encode(&ErrGobber { n: 1 }).unwrap_err();
    assert_eq!(err.to_string(), "encode failed");
    // A stream from a type that encodes fine, decoded into the failing type.
    let (_b, enc, dec) = pair();
    #[derive(Reflect, Clone, Default)]
    #[reflect(pkg = "main")]
    struct OkGobber {
        pub n: i64,
    }
    #[reflect_methods]
    impl OkGobber {
        pub fn GobEncode(&self) -> (Vec<u8>, Result<(), String>) {
            (vec![1, 2, 3], Ok(()))
        }
    }
    enc.encode(&OkGobber { n: 1 }).unwrap();
    // The names differ but both are GobEncoders on the wire.
    let mut o = ErrGobber::default();
    let err = dec.decode(&mut o).unwrap_err();
    assert_eq!(err.to_string(), "decode failed");
}

// ---- decode type errors ----

#[test]
fn local_remote_types_mismatch() {
    let (_b, enc, dec) = pair();
    enc.encode(&vec![1i64, 2]).unwrap();
    let mut o = BTreeMap::<String, isize>::new();
    let err = dec.decode(&mut o).unwrap_err();
    assert_eq!(
        err.to_string(),
        "gob: decoding into local type *map[string]int, received remote type []int"
    );
    let (_b, enc, dec) = pair();
    enc.encode(&5i64).unwrap();
    let mut v = Value::default();
    let err = dec.decode(&mut v).unwrap_err();
    assert_eq!(
        err.to_string(),
        "gob: local interface type *interface {} can only be decoded from remote interface type; received concrete type int"
    );
}

#[test]
fn slice_incompatibility() {
    let (_b, enc, dec) = pair();
    enc.encode(&vec![1.5f64, 2.5]).unwrap();
    let mut o = Vec::<String>::new();
    let err = dec.decode(&mut o).unwrap_err();
    assert!(
        err.to_string()
            .starts_with("gob: decoding into local type *[]string, received remote type []float"),
        "{err}"
    );
}

#[test]
fn large_slice_and_huge_slice_error() {
    let (_b, enc, dec) = pair();
    let big: Vec<u8> = (0..1_500_000u32).map(|i| i as u8).collect();
    enc.encode(&big).unwrap();
    let mut o = Vec::<u8>::new();
    dec.decode(&mut o).unwrap();
    assert_eq!(o, big);
    // A claimed length far beyond the data.
    let stream = [
        0x0e, 0x00, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];
    let d = Decoder::new(io::Cursor::new(stream.to_vec()));
    let mut o = Vec::<String>::new();
    assert!(d.decode(&mut o).is_err());
}

#[test]
fn registration_panics() {
    let text = panic_text(|| gob::register_name("main.Square", &Circle::default()));
    assert!(
        text.starts_with("gob: registering duplicate types for \"main.Square\""),
        "{text}"
    );
    let text = panic_text(|| gob::register_name("Other", &Square::default()));
    assert_eq!(
        text,
        "gob: registering duplicate names for main.Square: \"main.Square\" != \"Other\""
    );
    gob::register_name("main.Circle", &Circle::default());
}
