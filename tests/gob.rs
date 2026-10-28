//! encoding/gob against the tables of Go's codec_test.go, encoder_test.go and
//! type_test.go that do not need struct types declared with the derive macro
//! (tools/derive-check/tests/gob.rs has those). Values are built with
//! `rust_stdlib::reflect`.
use std::io::{self, Cursor, Read, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

use rust_stdlib::encoding::gob::{self, Decoder, Encoder};
use rust_stdlib::reflect::{self, Kind, Reflect, StructField, Type, Value};

#[derive(Clone, Default)]
struct Shared(Arc<Mutex<Vec<u8>>>);

impl Write for Shared {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Shared {
    fn bytes(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }
}

/// The bytes `Encode` writes for one value on a fresh encoder.
fn encode_one<T: Reflect>(x: &T) -> Vec<u8> {
    let w = Shared::default();
    Encoder::new(w.clone()).encode(x).expect("encode");
    w.bytes()
}

fn decoder(b: Vec<u8>) -> Decoder {
    Decoder::new(Cursor::new(b))
}

/// Splits a stream into its messages' bodies (Go's count-prefixed items).
fn messages(mut b: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let (n, rest) = if b[0] <= 0x7f {
            (b[0] as usize, &b[1..])
        } else {
            let k = 256 - b[0] as usize;
            let n = b[1..1 + k]
                .iter()
                .fold(0usize, |x, &c| (x << 8) | c as usize);
            (n, &b[1 + k..])
        };
        out.push(rest[..n].to_vec());
        b = &rest[n..];
    }
    out
}

// ---- codec_test.go: encodeT, TestUintCodec, TestIntCodec ----

const ENCODE_T: &[(u64, &[u8])] = &[
    (0x00, &[0x00]),
    (0x0F, &[0x0F]),
    (0xFF, &[0xFF, 0xFF]),
    (0xFFFF, &[0xFE, 0xFF, 0xFF]),
    (0xFFFFFF, &[0xFD, 0xFF, 0xFF, 0xFF]),
    (0xFFFFFFFF, &[0xFC, 0xFF, 0xFF, 0xFF, 0xFF]),
    (0xFFFFFFFFFF, &[0xFB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
    (0xFFFFFFFFFFFF, &[0xFA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
    (
        0xFFFFFFFFFFFFFF,
        &[0xF9, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
    ),
    (
        0xFFFFFFFFFFFFFFFF,
        &[0xF8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
    ),
    (0x1111, &[0xFE, 0x11, 0x11]),
    (
        0x1111111111111111,
        &[0xF8, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11],
    ),
    (
        0x8888888888888888,
        &[0xF8, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88],
    ),
    (
        1 << 63,
        &[0xF8, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    ),
];

#[test]
fn uint_codec() {
    for &(x, want) in ENCODE_T {
        // A top-level uint is its type id (3, sent as 6), the singleton
        // delta 0 and the value.
        let got = encode_one(&x);
        let mut expect = vec![(2 + want.len()) as u8, 0x06, 0x00];
        expect.extend_from_slice(want);
        assert_eq!(got, expect, "encodeUint: {x:#x}");
        let mut back = 0u64;
        decoder(got).decode(&mut back).expect("decode");
        assert_eq!(back, x);
    }
    let mut u = 0u64;
    loop {
        let mut back = 0u64;
        decoder(encode_one(&u)).decode(&mut back).expect("decode");
        assert_eq!(u, back, "Encode/Decode: sent {u:#x} received {back:#x}");
        if u & (1 << 63) != 0 {
            break;
        }
        u = (u + 1).wrapping_mul(7);
    }
}

fn verify_int(i: i64) {
    let mut back = 0i64;
    decoder(encode_one(&i)).decode(&mut back).expect("decode");
    assert_eq!(i, back, "Encode/Decode: sent {i:#x} received {back:#x}");
}

#[test]
fn int_codec() {
    let mut u = 0u64;
    loop {
        let i = u as i64;
        verify_int(i);
        verify_int(i.wrapping_neg());
        verify_int(!i);
        if u & (1 << 63) != 0 {
            break;
        }
        u = (u + 1).wrapping_mul(7);
    }
    verify_int(i64::MIN); // a tricky case
}

// ---- codec_test.go: TestScalarEncInstructions / TestScalarDecInstructions ----

/// A struct whose seven fields are `int`, except field 6, which has type `t`.
fn struct_with_field6(t: &Type) -> Type {
    let int = Type::basic(Kind::Int);
    let mut fields: Vec<StructField> = (0..6)
        .map(|i| StructField::new(&format!("F{i}"), int.clone()))
        .collect();
    fields.push(StructField::new("F6", t.clone()));
    reflect::struct_of(&fields)
}

const BOOL_RESULT: &[u8] = &[0x07, 0x01];
const SIGNED_RESULT: &[u8] = &[0x07, 2 * 17];
const UNSIGNED_RESULT: &[u8] = &[0x07, 17];
const FLOAT_RESULT: &[u8] = &[0x07, 0xFE, 0x31, 0x40];
const COMPLEX_RESULT: &[u8] = &[0x07, 0xFE, 0x31, 0x40, 0xFE, 0x33, 0x40];
const BYTES_RESULT: &[u8] = &[0x07, 0x05, b'h', b'e', b'l', b'l', b'o'];

fn scalar_cases() -> Vec<(&'static str, Type, Value, &'static [u8])> {
    let b = Type::basic;
    let i = |k, x: i64| Value::from_int(&b(k), x);
    let u = |k, x: u64| Value::from_uint(&b(k), x);
    let f = |k, x: f64| Value::from_float(&b(k), x);
    vec![
        (
            "bool",
            b(Kind::Bool),
            Value::from_bool(&b(Kind::Bool), true),
            BOOL_RESULT,
        ),
        ("int", b(Kind::Int), i(Kind::Int, 17), SIGNED_RESULT),
        ("uint", b(Kind::Uint), u(Kind::Uint, 17), UNSIGNED_RESULT),
        ("int8", b(Kind::Int8), i(Kind::Int8, 17), SIGNED_RESULT),
        ("uint8", b(Kind::Uint8), u(Kind::Uint8, 17), UNSIGNED_RESULT),
        ("int16", b(Kind::Int16), i(Kind::Int16, 17), SIGNED_RESULT),
        (
            "uint16",
            b(Kind::Uint16),
            u(Kind::Uint16, 17),
            UNSIGNED_RESULT,
        ),
        ("int32", b(Kind::Int32), i(Kind::Int32, 17), SIGNED_RESULT),
        (
            "uint32",
            b(Kind::Uint32),
            u(Kind::Uint32, 17),
            UNSIGNED_RESULT,
        ),
        ("int64", b(Kind::Int64), i(Kind::Int64, 17), SIGNED_RESULT),
        (
            "uint64",
            b(Kind::Uint64),
            u(Kind::Uint64, 17),
            UNSIGNED_RESULT,
        ),
        (
            "uintptr",
            b(Kind::Uintptr),
            u(Kind::Uintptr, 17),
            UNSIGNED_RESULT,
        ),
        (
            "float32",
            b(Kind::Float32),
            f(Kind::Float32, 17.0),
            FLOAT_RESULT,
        ),
        (
            "float64",
            b(Kind::Float64),
            f(Kind::Float64, 17.0),
            FLOAT_RESULT,
        ),
        (
            "complex64",
            b(Kind::Complex64),
            Value::from_complex(
                &b(Kind::Complex64),
                rust_stdlib::strconv::Complex { re: 17.0, im: 19.0 },
            ),
            COMPLEX_RESULT,
        ),
        (
            "complex128",
            b(Kind::Complex128),
            Value::from_complex(
                &b(Kind::Complex128),
                rust_stdlib::strconv::Complex { re: 17.0, im: 19.0 },
            ),
            COMPLEX_RESULT,
        ),
        (
            "bytes",
            reflect::slice_of(&b(Kind::Uint8)),
            b"hello".to_vec().to_value(),
            BYTES_RESULT,
        ),
        (
            "string",
            b(Kind::String),
            Value::from_string(&b(Kind::String), "hello"),
            BYTES_RESULT,
        ),
    ]
}

#[test]
fn scalar_enc_and_dec_instructions() {
    for (name, t, v, want) in scalar_cases() {
        let st = struct_with_field6(&t);
        let data = reflect::new(&st).elem();
        data.field(6).set(&v);
        let w = Shared::default();
        let enc = Encoder::new(w.clone());
        enc.encode_value(&data).expect("encode");
        let msgs = messages(&w.bytes());
        // The type definition, then the value: type id, the field, the
        // terminator.
        assert_eq!(msgs.len(), 2, "{name}");
        let body = &msgs[1];
        let mut expect = want.to_vec();
        expect.push(0x00);
        assert!(
            body.ends_with(&expect),
            "{name} enc: expected {expect:02x?} at the end of {body:02x?}"
        );
        // And back.
        let out = reflect::new(&st);
        decoder(w.bytes()).decode_value(&out).expect("decode");
        assert!(
            reflect::deep_equal_values(&out.elem().field(6), &v),
            "{name} dec"
        );
    }
}

// ---- encoder_test.go ----

#[test]
fn bad_count() {
    let b = vec![0xfb, 0xa5, 0x82, 0x2f, 0xca, 0x1];
    let err = decoder(b).decode_discard().expect_err("bad count");
    assert_eq!(err.to_string(), "invalid message length");
}

#[test]
fn bad_data() {
    let cases: &[(&str, &str)] = &[
        ("", "EOF"),
        ("7F6869", "unexpected EOF"),
        ("05100028557b02027f8302", "interface encoding"),
        ("130a00fb5dad0bf8ff020263e70002fa28020202a89859", "slice length too large"),
        ("0f1000fb285d003316020735ff023a65c5", "interface encoding"),
        (
            "03fffb0616fffc00f902ff02ff03bf005d02885802a311a8120228022c028ee7",
            "GobDecoder",
        ),
        (
            "10fe010f020102fe01100001fe010e000016fe010d030102fe010e00010101015801fe01100000000bfe011000f85555555555555555",
            "exceeds input size",
        ),
    ];
    for (i, (input, want)) in cases.iter().enumerate() {
        let data: Vec<u8> = (0..input.len() / 2)
            .map(|k| u8::from_str_radix(&input[2 * k..2 * k + 2], 16).unwrap())
            .collect();
        let err = decoder(data).decode_discard().expect_err("no error");
        assert!(
            err.to_string().contains(want),
            "#{i}: expected {want:?} error, got {err}"
        );
    }
}

#[test]
fn eof_is_io_eof() {
    let err = decoder(Vec::new()).decode_discard().expect_err("eof");
    assert!(rust_stdlib::io::is_eof(&err));
    // A type definition without the value that follows it.
    let mut b = Vec::new();
    {
        let w = Shared::default();
        Encoder::new(w.clone()).encode(&vec![1i64]).unwrap();
        b.extend_from_slice(&messages_prefix(&w.bytes(), 1));
    }
    let err = decoder(b).decode_discard().expect_err("short");
    assert!(rust_stdlib::io::is_unexpected_eof(&err), "{err}");
}

/// The first `n` messages of a stream, framing included.
fn messages_prefix(b: &[u8], n: usize) -> Vec<u8> {
    let mut at = 0;
    for _ in 0..n {
        let (len, rest) = if b[at] <= 0x7f {
            (b[at] as usize, at + 1)
        } else {
            let k = 256 - b[at] as usize;
            let len = b[at + 1..at + 1 + k]
                .iter()
                .fold(0usize, |x, &c| (x << 8) | c as usize);
            (len, at + 1 + k)
        };
        at = rest + len;
    }
    b[..at].to_vec()
}

#[test]
fn top_level_nil_pointer_panics() {
    let nil: Option<i64> = None;
    let enc = Encoder::new(io::sink());
    let r = catch_unwind(AssertUnwindSafe(|| enc.encode(&nil)));
    let msg = r.expect_err("did not panic");
    let msg = msg.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(msg.contains("nil pointer"), "{msg}");
    assert_eq!(msg, "gob: cannot encode nil pointer of type *int64");
}

#[test]
fn nil_value_is_an_error() {
    let err = Encoder::new(io::sink())
        .encode_value(&Value::default())
        .expect_err("nil value");
    assert!(err.to_string().contains("nil value"), "{err}");
}

#[test]
fn decode_non_settable_value_is_an_error() {
    let v = 5i64.to_value();
    let err = decoder(encode_one(&7i64))
        .decode_value(&v)
        .expect_err("unassignable");
    assert_eq!(err.to_string(), "gob: DecodeValue of unassignable value");
}

/// A reader that hands out one shared buffer, as `bytes.Buffer` does, so
/// decoders created one after another see the rest of the input.
#[derive(Clone)]
struct SharedCursor(Arc<Mutex<Cursor<Vec<u8>>>>);

impl Read for SharedCursor {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.lock().unwrap().read(buf)
    }
}

#[test]
fn sequential_decoders_share_an_unbuffered_reader() {
    let w = Shared::default();
    let enc = Encoder::new(w.clone());
    for i in 0..10 {
        enc.encode(&format!("{i}")).unwrap();
    }
    let shared = SharedCursor(Arc::new(Mutex::new(Cursor::new(w.bytes()))));
    for i in 0..10 {
        let dec = Decoder::from_byte_reader(shared.clone());
        let mut s = String::new();
        dec.decode(&mut s).expect("decode");
        assert_eq!(s, format!("{i}"));
    }
}

#[test]
fn sequence_of_values_then_eof() {
    let w = Shared::default();
    let enc = Encoder::new(w.clone());
    enc.encode(&7i64).unwrap();
    enc.encode(&"str".to_string()).unwrap();
    enc.encode(&vec!["a".to_string(), "b".to_string()]).unwrap();
    let dec = decoder(w.bytes());
    let (mut a, mut b, mut c) = (0i64, String::new(), Vec::<String>::new());
    dec.decode(&mut a).unwrap();
    dec.decode(&mut b).unwrap();
    dec.decode(&mut c).unwrap();
    assert_eq!((a, b.as_str(), c.len()), (7, "str", 2));
    assert!(rust_stdlib::io::is_eof(&dec.decode_discard().unwrap_err()));
}

#[test]
fn duplicate_type_received() {
    // Go's TestDecodeErrorMultipleTypes: a second stream with its own type
    // definition on the same decoder.
    let st = reflect::struct_of(&[StructField::new("A", Type::basic(Kind::String))]);
    let make = |s: &str| {
        let v = reflect::new(&st).elem();
        v.field(0).set_string(s);
        let w = Shared::default();
        Encoder::new(w.clone()).encode_value(&v).unwrap();
        w.bytes()
    };
    let mut stream = make("one");
    let second = make("two");
    let dec = decoder({
        stream.extend_from_slice(&second);
        stream
    });
    let out = reflect::new(&st);
    dec.decode_value(&out).expect("first");
    let err = dec.decode_value(&out).expect_err("duplicate");
    assert!(err.to_string().contains("duplicate type"), "{err}");
}

#[test]
fn decode_into_nothing() {
    let w = Shared::default();
    let enc = Encoder::new(w.clone());
    enc.encode(&vec![1i64, 2, 3]).unwrap();
    enc.encode(&"after".to_string()).unwrap();
    let dec = decoder(w.bytes());
    dec.decode_discard().expect("discard");
    let mut s = String::new();
    dec.decode(&mut s).expect("decode");
    assert_eq!(s, "after");
}

#[test]
fn singletons_and_defaults_in_arrays() {
    // Zero values are sent inside arrays and slices, and singletons are sent
    // even when zero.
    let mut z = 5i64;
    decoder(encode_one(&0i64)).decode(&mut z).unwrap();
    assert_eq!(z, 0);
    let mut a = [7i64; 4];
    decoder(encode_one(&[0i64, 1, 0, 2]))
        .decode(&mut a)
        .unwrap();
    assert_eq!(a, [0, 1, 0, 2]);
    let mut v = vec![9i64; 2];
    decoder(encode_one(&vec![0i64, 0, 3]))
        .decode(&mut v)
        .unwrap();
    assert_eq!(v, [0, 0, 3]);
}

#[test]
fn maps_round_trip_and_nil_map_is_not_sent() {
    let mut m = std::collections::BTreeMap::new();
    m.insert("a".to_string(), 1.5f64);
    m.insert("b".to_string(), -2.0);
    let mut back = std::collections::BTreeMap::<String, f64>::new();
    decoder(encode_one(&m)).decode(&mut back).unwrap();
    assert_eq!(back, m);
}

#[test]
fn pointers_flatten() {
    // *int, **int and int are the same on the wire.
    let a = encode_one(&Some(17i64));
    assert_eq!(a, encode_one(&17i64));
    let mut p: Option<i64> = None;
    decoder(a).decode(&mut p).unwrap();
    assert_eq!(p, Some(17));
}

#[test]
fn type_mismatch_errors() {
    let mut s = String::new();
    let err = decoder(encode_one(&17i64)).decode(&mut s).unwrap_err();
    assert_eq!(
        err.to_string(),
        "gob: decoding into local type *string, received remote type int"
    );
    let mut small = 0i8;
    let err = decoder(encode_one(&1000i64))
        .decode(&mut small)
        .unwrap_err();
    assert_eq!(err.to_string(), "value for \"*int8\" out of range");
}

// ---- type_test.go: registration ----

#[test]
fn registration_naming_and_idempotence() {
    let int_slice: Vec<i32> = vec![1];
    gob::register(&int_slice);
    gob::register(&int_slice);
    // Registering a name for a second type panics, as Go's does.
    let r = catch_unwind(AssertUnwindSafe(|| {
        gob::register_name("[]int32", &vec![1.5f64]);
    }));
    let msg = r
        .expect_err("expected a panic")
        .downcast_ref::<String>()
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        msg,
        "gob: registering duplicate types for \"[]int32\": []int32 != []float64"
    );
    let r = catch_unwind(AssertUnwindSafe(|| gob::register_name("", &5i64)));
    assert!(r.is_err());
}

#[test]
fn interface_values_carry_registered_names() {
    // []any holding registered basics round trips.
    let items: Vec<Value> = vec![
        Value::from_interface(&Type::any_type(), &5i64.to_value()),
        Value::from_interface(&Type::any_type(), &"x".to_string().to_value()),
        reflect::zero(&Type::any_type()),
    ];
    let v = Value::from_items(&reflect::slice_of(&Type::any_type()), &items);
    let w = Shared::default();
    Encoder::new(w.clone()).encode_value(&v).unwrap();
    let out = reflect::new(&reflect::slice_of(&Type::any_type()));
    decoder(w.bytes()).decode_value(&out).unwrap();
    let got = out.elem();
    assert_eq!(got.len(), 3);
    assert_eq!(got.index(0).elem().int(), 5);
    assert_eq!(got.index(1).elem().text(), "x");
    assert!(got.index(2).is_nil());

    // An unregistered type is an error.
    let unreg = reflect::struct_of(&[StructField::new("A", Type::basic(Kind::Int))]);
    let bad = Value::from_items(
        &reflect::slice_of(&Type::any_type()),
        &[Value::from_interface(
            &Type::any_type(),
            &reflect::new(&unreg).elem(),
        )],
    );
    let err = Encoder::new(io::sink()).encode_value(&bad).unwrap_err();
    assert!(
        err.to_string()
            .starts_with("gob: type not registered for interface: struct {"),
        "{err}"
    );
}

#[test]
fn struct_without_exported_fields_is_an_error() {
    let st =
        reflect::struct_of(&[StructField::new("a", Type::basic(Kind::Int)).with_pkg_path("main")]);
    let err = Encoder::new(io::sink())
        .encode_value(&reflect::new(&st).elem())
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "gob: type struct { a int } has no exported fields"
    );
}
