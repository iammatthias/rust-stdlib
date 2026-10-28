//! encoding/asn1 tests. Table vectors come from Go's asn1_test.go through
//! tools/asn1_vectors.go; struct-based Go tests are ported by hand below.
use rust_stdlib::encoding::asn1::{
    self, Any, Asn1Type, BitString, Class, Decoder, Element, Encoder, Enumerated, Error, ErrorKind,
    Flag, Integer, Marshal, Null, ObjectIdentifier, Options, Params, RawValue, SetOf, StringType,
    TimeType, Unmarshal,
};
use rust_stdlib::time::DateTime;

mod golden {
    include!("fixtures/asn1_golden.rs");
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if content.len() < 128 {
        out.push(content.len() as u8);
    } else if content.len() < 256 {
        out.extend_from_slice(&[0x81, content.len() as u8]);
    } else {
        out.extend_from_slice(&[0x82, (content.len() >> 8) as u8, content.len() as u8]);
    }
    out.extend_from_slice(content);
    out
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn decode<T: Unmarshal>(der: &[u8]) -> Result<T, Error> {
    asn1::unmarshal::<T>(der).map(|(v, _)| v)
}

fn time(t: golden::Time) -> DateTime {
    DateTime::new(t.0, t.1, t.2, t.3, t.4, t.5, t.6, t.7).unwrap()
}

fn utc(y: u16, mo: u8, d: u8, h: u8, mi: u8, s: u8) -> DateTime {
    DateTime::new(y, mo, d, h, mi, s, 0, 0).unwrap()
}

// Go table tests (generated fixtures).

#[test]
fn go_parse_bool() {
    for (i, &(input, ok, out)) in golden::BOOL.iter().enumerate() {
        let got = decode::<bool>(&tlv(1, input));
        assert_eq!(got.is_ok(), ok, "#{i}");
        if ok {
            assert_eq!(got.unwrap(), out, "#{i}");
        }
    }
}

#[test]
fn go_parse_int64_int32_and_big_int() {
    for (i, &(input, ok, out)) in golden::INT64.iter().enumerate() {
        let got = decode::<i64>(&tlv(2, input));
        assert_eq!(got.is_ok(), ok, "int64 #{i}");
        if ok {
            assert_eq!(got.unwrap(), out, "int64 #{i}");
        }
    }
    for (i, &(input, ok, out)) in golden::INT32.iter().enumerate() {
        let got = decode::<i32>(&tlv(2, input));
        assert_eq!(got.is_ok(), ok, "int32 #{i}");
        if ok {
            assert_eq!(got.unwrap(), out, "int32 #{i}");
        }
    }
    for (i, &(input, ok, out)) in golden::BIG_INT.iter().enumerate() {
        let got = decode::<Integer>(&tlv(2, input));
        assert_eq!(got.is_ok(), ok, "big #{i}");
        if ok {
            let got = got.unwrap();
            assert_eq!(got.as_twos_complement(), out, "big #{i}");
            let der = asn1::marshal(&got).unwrap();
            assert_eq!(der, tlv(2, out), "big round trip #{i}");
        }
    }
}

#[test]
fn go_bit_strings() {
    for (i, &(input, ok, out, bits)) in golden::BIT_STRING.iter().enumerate() {
        let got = decode::<BitString>(&tlv(3, input));
        assert_eq!(got.is_ok(), ok, "#{i}");
        if ok {
            assert_eq!(got.unwrap(), BitString::new(out.to_vec(), bits), "#{i}");
        }
    }
    let bs = BitString::new(vec![0x82, 0x40], 16);
    for (index, bit) in [(0, 1), (1, 0), (6, 1), (9, 1), (17, 0), (usize::MAX, 0)] {
        assert_eq!(bs.at(index), bit, "At({index})");
    }
    for (i, &(input, len, out)) in golden::BIT_STRING_RIGHT_ALIGN.iter().enumerate() {
        assert_eq!(
            BitString::new(input.to_vec(), len).right_align(),
            out,
            "#{i}"
        );
    }
}

#[test]
fn go_object_identifiers() {
    for (i, &(input, ok, arcs)) in golden::OBJECT_IDENTIFIER.iter().enumerate() {
        let got = decode::<ObjectIdentifier>(&tlv(6, input));
        assert_eq!(got.is_ok(), ok, "#{i}");
        if ok {
            assert_eq!(got.unwrap().arcs(), arcs, "#{i}");
        }
    }
    // TestObjectIdentifierEqual and String.
    let a = ObjectIdentifier::new([1, 2, 3]);
    assert_eq!(a, ObjectIdentifier::new([1, 2, 3]));
    assert_ne!(ObjectIdentifier::new([1]), a);
    assert_ne!(ObjectIdentifier::new([10, 11, 12]), a);
    assert_eq!(
        ObjectIdentifier::new([1, 2, 840, 113549, 1, 1, 1]).to_string(),
        "1.2.840.113549.1.1.1"
    );
    assert_eq!(
        "2.5.4.3".parse::<ObjectIdentifier>().unwrap().arcs(),
        [2, 5, 4, 3]
    );
    assert!("2..5".parse::<ObjectIdentifier>().is_err());
    assert!("2.-5".parse::<ObjectIdentifier>().is_err());
    // TestNonMinimalEncodedOID.
    assert!(decode::<ObjectIdentifier>(&hex("060a2a80864886f70d01010b")).is_err());
}

#[test]
fn go_utc_and_generalized_time() {
    for (name, tag, table) in [
        ("utc", 23u8, golden::UTC_TIME),
        ("generalized", 24, golden::GENERALIZED_TIME),
    ] {
        for (i, &(input, ok, out)) in table.iter().enumerate() {
            let got = decode::<DateTime>(&tlv(tag, input.as_bytes()));
            assert_eq!(got.is_ok(), ok, "{name} #{i} {input}");
            if ok {
                assert_eq!(got.unwrap(), time(out), "{name} #{i}");
            }
        }
    }
}

#[test]
fn go_tag_and_length() {
    for (i, &(input, ok, (class, tag, length, compound))) in
        golden::TAG_AND_LENGTH.iter().enumerate()
    {
        let mut der = input.to_vec();
        let padded = ok && length < 1024;
        if padded {
            der.extend(std::iter::repeat_n(0, length));
        }
        match asn1::parse_raw(&der) {
            Ok((raw, rest)) => {
                assert!(ok, "#{i} accepted");
                assert!(rest.is_empty(), "#{i}");
                assert_eq!(
                    (raw.class.bits(), raw.tag, raw.bytes.len(), raw.is_compound),
                    (class, tag, length, compound),
                    "#{i}"
                );
            }
            Err(e) => {
                // Large valid lengths fail only on the missing contents.
                let truncated = e.message() == "data truncated";
                assert_eq!(ok && !padded, truncated, "#{i}: {e}");
                assert!(!ok || truncated, "#{i}: {e}");
            }
        }
    }
}

#[test]
fn go_bmp_strings() {
    for &(name, decoded, encoded, invalid) in golden::BMP_STRING {
        let got = decode::<String>(&tlv(30, &hex(encoded)));
        assert_eq!(got.is_err(), invalid, "{name}");
        if !invalid {
            assert_eq!(got.unwrap(), decoded, "{name}");
        }
    }
}

// Go's TestUnmarshal table, ported by hand.

#[derive(Debug, PartialEq)]
struct ContextSpecificTags {
    a: i64,
}
impl Unmarshal for ContextSpecificTags {
    fn asn1_type() -> Asn1Type {
        Asn1Type::SEQUENCE
    }
    fn decode(e: &Element<'_>) -> Result<Self, Error> {
        Ok(Self {
            a: e.contents().field(&Params::parse("tag:1"))?,
        })
    }
    fn zero() -> Self {
        Self { a: 0 }
    }
}

#[test]
fn go_unmarshal_table() {
    assert_eq!(decode::<i64>(&[0x02, 0x01, 0x42]).unwrap(), 0x42);
    let raw = decode::<RawValue>(&[0x05, 0x00]).unwrap();
    assert_eq!(
        raw,
        RawValue {
            tag: 5,
            full_bytes: vec![5, 0],
            ..RawValue::default()
        }
    );
    let oid: Vec<ObjectIdentifier> = decode(&hex("300806062a864886f70d")).unwrap();
    assert_eq!(oid, [ObjectIdentifier::new([1, 2, 840, 113549])]);
    assert_eq!(
        decode::<BitString>(&[0x03, 0x04, 0x06, 0x6e, 0x5d, 0xc0]).unwrap(),
        BitString::new(vec![110, 93, 192], 18)
    );
    assert_eq!(
        decode::<Vec<i64>>(&hex("3009020101020102020103")).unwrap(),
        [1, 2, 3]
    );
    assert_eq!(decode::<String>(b"\x13\x04test").unwrap(), "test");
    assert_eq!(decode::<String>(b"\x16\x04test").unwrap(), "test");
    assert_eq!(decode::<String>(b"\x13\x05test&").unwrap(), "test&");
    assert_eq!(
        decode::<RawValue>(b"\x16\x04test").unwrap(),
        RawValue {
            tag: 22,
            bytes: b"test".to_vec(),
            full_bytes: b"\x16\x04test".to_vec(),
            ..RawValue::default()
        }
    );
    assert_eq!(
        decode::<ContextSpecificTags>(&[0x30, 0x03, 0x81, 0x01, 0x01]).unwrap(),
        ContextSpecificTags { a: 1 }
    );
    let (a, b) = {
        let der = hex("3008a103020101020102");
        let (raw, _) = asn1::parse_raw(&der).unwrap();
        let mut d = Decoder::new(&raw.bytes).unwrap();
        (
            d.field::<i64>(&Params::parse("explicit,tag:1")).unwrap(),
            d.field::<i64>(&Params::NONE).unwrap(),
        )
    };
    assert_eq!((a, b), (1, 2));
    let mut d = Decoder::new(&[0x81, 0x01, b'@']).unwrap();
    assert_eq!(
        d.field::<String>(&Params::parse("tag:1,utf8")).unwrap(),
        "@"
    );
    assert!(!decode::<bool>(&[0x01, 0x01, 0x00]).unwrap());
    assert!(decode::<bool>(&[0x01, 0x01, 0xff]).unwrap());
    // TestElementsAfterString.
    let (raw, _) = asn1::parse_raw(&hex("300b13036f6f6f020122020133")).unwrap();
    let mut d = Decoder::new(&raw.bytes).unwrap();
    assert_eq!(d.field::<String>(&Params::NONE).unwrap(), "ooo");
    assert_eq!(d.field::<i64>(&Params::NONE).unwrap(), 0x22);
    assert_eq!(d.field::<i64>(&Params::NONE).unwrap(), 0x33);
    // TestBigInt.
    let mut d = Decoder::new(&[0x02, 0x03, 0x12, 0x34, 0x56]).unwrap();
    assert_eq!(
        d.field::<Integer>(&Params::NONE).unwrap().to_i64(),
        Some(0x123456)
    );
    // TestSet.
    let input = hex("3109020101020102020103");
    let mut d = Decoder::new(&input).unwrap();
    assert_eq!(
        d.field::<Vec<i64>>(&Params::parse("set")).unwrap(),
        [1, 2, 3]
    );
    assert_eq!(
        decode::<SetOf<i64>>(&hex("3109020101020102020103")).unwrap(),
        SetOf(vec![1, 2, 3])
    );
    assert_eq!(
        decode::<String>(b"\x12\x0b0123456789 ").unwrap(),
        "0123456789 "
    );
    assert_eq!(decode::<String>(b"\x14\x03\xbfa?").unwrap(), "\u{bf}a?");
}

// Go's Certificate structures.

#[derive(Debug, Clone, PartialEq)]
struct AlgorithmIdentifier {
    algorithm: ObjectIdentifier,
}

#[derive(Debug, Clone, PartialEq)]
struct AttributeTypeAndValue {
    type_: ObjectIdentifier,
    value: Any,
}

#[derive(Debug, Clone, PartialEq)]
struct Validity {
    not_before: DateTime,
    not_after: DateTime,
}

#[derive(Debug, Clone, PartialEq)]
struct PublicKeyInfo {
    algorithm: AlgorithmIdentifier,
    public_key: BitString,
}

#[derive(Debug, Clone, PartialEq)]
struct TbsCertificate {
    version: i64,
    serial_number: RawValue,
    signature_algorithm: AlgorithmIdentifier,
    issuer: Vec<SetOf<AttributeTypeAndValue>>,
    validity: Validity,
    subject: Vec<SetOf<AttributeTypeAndValue>>,
    public_key: PublicKeyInfo,
}

#[derive(Debug, Clone, PartialEq)]
struct Certificate {
    tbs: TbsCertificate,
    signature_algorithm: AlgorithmIdentifier,
    signature_value: BitString,
}

macro_rules! sequence {
    ($ty:ty, |$e:ident| $decode:expr, $zero:expr) => {
        impl Unmarshal for $ty {
            fn asn1_type() -> Asn1Type {
                Asn1Type::SEQUENCE
            }
            fn decode($e: &Element<'_>) -> Result<Self, Error> {
                $decode
            }
            fn zero() -> Self {
                $zero
            }
        }
    };
}

sequence!(
    AlgorithmIdentifier,
    |e| Ok(AlgorithmIdentifier {
        algorithm: e.contents().field(&Params::NONE)?
    }),
    AlgorithmIdentifier {
        algorithm: ObjectIdentifier::default()
    }
);
sequence!(
    AttributeTypeAndValue,
    |e| {
        let mut d = e.contents();
        Ok(AttributeTypeAndValue {
            type_: d.field(&Params::NONE)?,
            value: d.field(&Params::NONE)?,
        })
    },
    AttributeTypeAndValue {
        type_: ObjectIdentifier::default(),
        value: Any::Other
    }
);
sequence!(
    Validity,
    |e| {
        let mut d = e.contents();
        Ok(Validity {
            not_before: d.field(&Params::NONE)?,
            not_after: d.field(&Params::NONE)?,
        })
    },
    Validity {
        not_before: <DateTime as Unmarshal>::zero(),
        not_after: <DateTime as Unmarshal>::zero()
    }
);
sequence!(
    PublicKeyInfo,
    |e| {
        let mut d = e.contents();
        Ok(PublicKeyInfo {
            algorithm: d.field(&Params::NONE)?,
            public_key: d.field(&Params::NONE)?,
        })
    },
    PublicKeyInfo {
        algorithm: AlgorithmIdentifier::zero(),
        public_key: BitString::default()
    }
);
sequence!(
    TbsCertificate,
    |e| {
        let mut d = e.contents();
        Ok(TbsCertificate {
            version: d.field(&Params::parse("optional,explicit,default:0,tag:0"))?,
            serial_number: d.field(&Params::NONE)?,
            signature_algorithm: d.field(&Params::NONE)?,
            issuer: d.field(&Params::NONE)?,
            validity: d.field(&Params::NONE)?,
            subject: d.field(&Params::NONE)?,
            public_key: d.field(&Params::NONE)?,
        })
    },
    unreachable!()
);
sequence!(
    Certificate,
    |e| {
        let mut d = e.contents();
        Ok(Certificate {
            tbs: d.field(&Params::NONE)?,
            signature_algorithm: d.field(&Params::NONE)?,
            signature_value: d.field(&Params::NONE)?,
        })
    },
    unreachable!()
);

fn rdn(oid: &[i64], value: &str) -> SetOf<AttributeTypeAndValue> {
    SetOf(vec![AttributeTypeAndValue {
        type_: ObjectIdentifier::new(oid),
        value: Any::String(value.into()),
    }])
}

#[test]
fn go_certificate() {
    let cert: Certificate = decode(golden::SELF_SIGNED_CERT).unwrap();
    let names = vec![
        rdn(&[2, 5, 4, 6], "XX"),
        rdn(&[2, 5, 4, 8], "Some-State"),
        rdn(&[2, 5, 4, 7], "City"),
        rdn(&[2, 5, 4, 10], "Internet Widgits Pty Ltd"),
        rdn(&[2, 5, 4, 3], "false.example.com"),
        rdn(&[1, 2, 840, 113549, 1, 9, 1], "false@example.com"),
    ];
    let sha1_rsa = AlgorithmIdentifier {
        algorithm: ObjectIdentifier::new([1, 2, 840, 113549, 1, 1, 5]),
    };
    assert_eq!(cert.tbs.version, 0);
    assert_eq!(
        cert.tbs.serial_number,
        RawValue {
            tag: 2,
            bytes: vec![0x0, 0x8c, 0xc3, 0x37, 0x92, 0x10, 0xec, 0x2c, 0x98],
            full_bytes: vec![2, 9, 0x0, 0x8c, 0xc3, 0x37, 0x92, 0x10, 0xec, 0x2c, 0x98],
            ..RawValue::default()
        }
    );
    assert_eq!(cert.tbs.signature_algorithm, sha1_rsa);
    assert_eq!(cert.tbs.issuer, names);
    assert_eq!(cert.tbs.subject, names);
    assert_eq!(
        cert.tbs.validity,
        Validity {
            not_before: utc(2009, 10, 8, 0, 25, 53),
            not_after: utc(2010, 10, 8, 0, 25, 53),
        }
    );
    assert_eq!(
        cert.tbs.public_key.algorithm.algorithm,
        ObjectIdentifier::new([1, 2, 840, 113549, 1, 1, 1])
    );
    assert_eq!(cert.tbs.public_key.public_key.bit_length, 592);
    assert_eq!(
        cert.tbs.public_key.public_key.bytes[..4],
        [0x30, 0x48, 0x2, 0x41]
    );
    assert_eq!(cert.signature_algorithm, sha1_rsa);
    assert_eq!(cert.signature_value.bit_length, 512);
    assert_eq!(cert.signature_value.bytes[..3], [0xa6, 0x7b, 0x6]);
    // TestCertificateWithNUL: NUL is not allowed in PrintableString.
    assert!(decode::<Certificate>(golden::PAYPAL_NUL_CERT).is_err());
}

// Go's TestMarshal table, ported by hand.

struct Seq<'a>(Vec<(&'a dyn Marshal, Params)>);

impl Marshal for Seq<'_> {
    fn asn1_type(&self) -> Asn1Type {
        Asn1Type::SEQUENCE
    }
    fn marshal_body(&self, _: &Params, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut e = Encoder::new(out);
        for (value, params) in &self.0 {
            e.field(*value, params)?;
        }
        Ok(())
    }
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

fn check_marshal(value: &dyn Marshal, want: &str) {
    assert_eq!(hexs(&asn1::marshal(value).unwrap()), want);
}

fn one<'a>(value: &'a dyn Marshal, params: &str) -> Seq<'a> {
    Seq(vec![(value, Params::parse(params))])
}

#[test]
fn go_marshal_table() {
    check_marshal(&10i64, "02010a");
    check_marshal(&127i64, "02017f");
    check_marshal(&128i64, "02020080");
    check_marshal(&-128i64, "020180");
    check_marshal(&-129i64, "0202ff7f");
    check_marshal(&one(&64i64, ""), "3003020140");
    check_marshal(&one(&Integer::from_i64(0x123456), ""), "30050203123456");
    check_marshal(
        &Seq(vec![(&64i64, Params::NONE), (&65i64, Params::NONE)]),
        "3006020140020141",
    );
    check_marshal(&one(&one(&127i64, ""), ""), "3005300302017f");
    check_marshal(&vec![1u8, 2, 3], "0403010203");
    check_marshal(&one(&64i64, "implicit,tag:5"), "3003850140");
    check_marshal(&one(&64i64, "explicit,tag:5"), "3005a503020140");
    check_marshal(&one(&Flag(true), "tag:0,optional"), "30028000");
    check_marshal(&one(&Flag(false), "tag:0,optional"), "3000");
    check_marshal(&utc(1970, 1, 1, 0, 0, 0), "170d3730303130313030303030305a");
    check_marshal(
        &utc(2009, 11, 15, 22, 56, 16),
        "170d3039313131353232353631365a",
    );
    let pst = DateTime::new(2009, 11, 15, 14, 56, 16, 0, -8 * 3600).unwrap();
    check_marshal(&pst, "17113039313131353134353631362d30383030");
    check_marshal(
        &utc(2100, 4, 5, 12, 1, 1),
        "180f32313030303430353132303130315a",
    );
    check_marshal(
        &one(&utc(2009, 11, 15, 22, 56, 16), "generalized"),
        "3011180f32303039313131353232353631365a",
    );
    check_marshal(&BitString::new(vec![0x80], 1), "03020780");
    check_marshal(&BitString::new(vec![0x81, 0xf0], 12), "03030481f0");
    check_marshal(&ObjectIdentifier::new([1, 2, 3, 4]), "06032a0304");
    check_marshal(
        &ObjectIdentifier::new([1, 2, 840, 133549, 1, 1, 5]),
        "06092a864888932d010105",
    );
    check_marshal(&ObjectIdentifier::new([2, 100, 3]), "0603813403");
    check_marshal(&"test", "130474657374");
    let x127 = "x".repeat(127);
    check_marshal(&x127, &format!("137f{}", "78".repeat(127)));
    let x128 = "x".repeat(128);
    check_marshal(&x128, &format!("138180{}", "78".repeat(128)));
    check_marshal(&one(&"test", "ia5"), "3006160474657374");
    check_marshal(&one(&RawValue::default(), "optional"), "3000");
    check_marshal(&one(&"test", "printable"), "3006130474657374");
    check_marshal(&one(&"test*", "printable"), "30071305746573742a");
    check_marshal(&one(&"test", ""), "3006130474657374");
    check_marshal(&one(&"test*", ""), "30070c05746573742a");
    check_marshal(&one(&"test&", ""), "30070c057465737426");
    check_marshal(
        &RawValue {
            class: Class::ContextSpecific,
            tag: 1,
            bytes: vec![1, 2, 3],
            ..RawValue::default()
        },
        "8103010203",
    );
    check_marshal(&SetOf(vec![10i64]), "310302010a");
    let empty: Vec<String> = vec![];
    check_marshal(&one(&empty, "omitempty"), "3000");
    check_marshal(&one(&vec!["1".to_owned()], "omitempty"), "30053003130131");
    check_marshal(&"Σ", "0c02cea3");
    check_marshal(&one(&0i64, "optional,default:1"), "3003020100");
    check_marshal(&one(&1i64, "optional,default:1"), "3000");
    check_marshal(&one(&2i64, "optional,default:1"), "3003020102");
    check_marshal(
        &Seq(vec![
            (&1i64, Params::parse("application,tag:0")),
            (&2i64, Params::parse("application,tag:1,explicit")),
        ]),
        "30084001016103020102",
    );
    check_marshal(
        &Seq(vec![
            (&1i64, Params::parse("private,tag:0")),
            (&2i64, Params::parse("private,tag:1,explicit")),
            (&3i64, Params::parse("private,tag:31")),
            (&4i64, Params::parse("private,tag:128")),
        ]),
        "3011c00101e103020102df1f0103df81000104",
    );
    check_marshal(&one(&"1 9", "numeric"), "30051203312039");
    // TestMarshalWithParams.
    let int_struct = one(&10i64, "");
    for (params, want) in [
        ("set", "310302010a"),
        ("application", "600302010a"),
        ("private", "e00302010a"),
    ] {
        let der = asn1::marshal_with_params(&int_struct, &Params::parse(params)).unwrap();
        assert_eq!(hexs(&der), want, "{params}");
    }
    // TestMarshalOID.
    check_marshal(&b"\x06\x01\x30".to_vec(), "0403060130");
    check_marshal(&ObjectIdentifier::new([2, 999, 3]), "0603883703");
    check_marshal(&ObjectIdentifier::new([0, 0]), "060100");
    // TestNull.
    assert_eq!(asn1::marshal(&RawValue::null()).unwrap(), asn1::NULL_BYTES);
    assert_eq!(asn1::marshal(&Null).unwrap(), asn1::NULL_BYTES);
    assert_eq!(decode::<Null>(&asn1::NULL_BYTES).unwrap(), Null);
    assert!(decode::<Null>(&[5, 1, 0]).is_err());
}

#[test]
fn go_marshal_errors() {
    for (value, params, needle) in [
        ("a", "numeric", "invalid character"),
        ("\u{b0}", "ia5", "invalid character"),
        ("!", "printable", "invalid character"),
        ("&", "printable", "invalid character"),
    ] {
        let err = asn1::marshal(&one(&value, params)).unwrap_err();
        assert!(err.message().contains(needle), "{value}: {err}");
    }
    let err = asn1::marshal_with_params(&5i64, &Params::parse("utf8")).unwrap_err();
    assert_eq!(
        err.message(),
        "explicit string type given to non-string member"
    );
    let err = asn1::marshal_with_params(&5i64, &Params::parse("utc")).unwrap_err();
    assert_eq!(err.message(), "explicit time type given to non-time member");
    let err = asn1::marshal_with_params(&5i64, &Params::parse("set")).unwrap_err();
    assert_eq!(err.message(), "non sequence tagged as set");
    for oid in [vec![1], vec![3, 1], vec![1, 40], vec![1, 2, -1]] {
        assert!(asn1::marshal(&ObjectIdentifier::new(oid)).is_err());
    }
    assert!(asn1::marshal(&utc(2050, 1, 1, 0, 0, 0)).is_ok());
    assert!(
        asn1::marshal_with_params(&"\u{1F600}", &Params::NONE.string_type(StringType::Bmp))
            .is_err()
    );
    assert!(
        asn1::marshal_with_params(&"\u{100}", &Params::NONE.string_type(StringType::T61)).is_err()
    );
}

#[test]
fn go_issue_11130_and_68241_any_round_trip() {
    let (v, _) = asn1::unmarshal::<Any>(b"\x06\x010").unwrap();
    assert_eq!(v, Any::ObjectIdentifier(ObjectIdentifier::new([1, 8])));
    for want in [false, true] {
        let der = asn1::marshal(&want).unwrap();
        assert_eq!(decode::<Any>(&der).unwrap(), Any::Bool(want));
    }
    // Compound, non-universal and unrecognized elements are consumed as nil.
    assert_eq!(decode::<Any>(&[0x30, 0x00]).unwrap(), Any::Other);
    assert_eq!(decode::<Any>(&[0x80, 0x01, 0x00]).unwrap(), Any::Other);
    assert_eq!(decode::<Any>(&[0x0a, 0x01, 0x00]).unwrap(), Any::Other);
}

#[test]
fn go_set_encoder_sorts_by_encoding() {
    let strings: Vec<String> = ["a", "aa", "b", "bb", "c", "cc"].map(String::from).to_vec();
    let der = asn1::marshal(&one(&strings, "set")).unwrap();
    let (raw, rest) = asn1::parse_raw(&der).unwrap();
    assert!(rest.is_empty());
    let mut d = Decoder::new(&raw.bytes).unwrap();
    assert_eq!(
        d.field::<Vec<String>>(&Params::parse("set")).unwrap(),
        ["a", "b", "c", "aa", "bb", "cc"]
    );
    let der = asn1::marshal(&SetOf(strings)).unwrap();
    let set: SetOf<String> = decode(&der).unwrap();
    assert_eq!(set.0, ["a", "b", "c", "aa", "bb", "cc"]);
}

#[test]
fn go_string_slice_and_tagged_times() {
    for test in [
        ["foo", "bar"],
        ["foo", "\\bar"],
        ["foo", "\"bar\""],
        ["foo", "åäö"],
    ] {
        let v: Vec<String> = test.map(String::from).to_vec();
        assert_eq!(
            decode::<Vec<String>>(&asn1::marshal(&v).unwrap()).unwrap(),
            v
        );
    }
    let explicit = [
        (
            hex("3011a00f170d3931303530363136343534305a"),
            utc(1991, 5, 6, 16, 45, 40),
        ),
        (
            hex("3017a015181332303130303130323033303430352b30363037"),
            DateTime::new(2010, 1, 2, 3, 4, 5, 0, 6 * 3600 + 7 * 60).unwrap(),
        ),
    ];
    for (der, want) in explicit {
        let (raw, _) = asn1::parse_raw(&der).unwrap();
        let mut d = Decoder::new(&raw.bytes).unwrap();
        assert_eq!(
            d.field::<DateTime>(&Params::parse("explicit,tag:0"))
                .unwrap(),
            want
        );
    }
    // An implicit tag 24 still parses as UTCTime without a time parameter.
    let input = hex("980d3931303530363136343534305a");
    let mut d = Decoder::new(&input).unwrap();
    assert_eq!(
        d.field::<DateTime>(&Params::parse("tag:24")).unwrap(),
        utc(1991, 5, 6, 16, 45, 40)
    );
}

#[test]
fn go_truncated_explicit_tag_and_invalid_utf8() {
    let mut d = Decoder::new(&[0xa0, 0x30]).unwrap();
    assert!(d.field::<i64>(&Params::parse("explicit,tag:0")).is_err());
    assert!(asn1::unmarshal::<i64>(&[0x30, 0x02, 0xa0, 0x30]).is_err());
    let err = decode::<String>(b"\x0c\x03a\xc9c").unwrap_err();
    assert!(err.to_string().contains("UTF"));
}

#[test]
fn go_explicit_raw_value_and_tagged_raw_value() {
    // TestExplicitTagRawValueStruct: A absent, B present.
    let der = asn1::marshal(&Seq(vec![
        (
            &RawValue::default(),
            Params::parse("optional,explicit,tag:5"),
        ),
        (&vec![1u8, 2, 3], Params::parse("optional,explicit,tag:6")),
    ]))
    .unwrap();
    let (raw, _) = asn1::parse_raw(&der).unwrap();
    let mut d = Decoder::new(&raw.bytes).unwrap();
    assert_eq!(
        d.field::<RawValue>(&Params::parse("optional,explicit,tag:5"))
            .unwrap(),
        RawValue::default()
    );
    assert_eq!(
        d.field::<Vec<u8>>(&Params::parse("optional,explicit,tag:6"))
            .unwrap(),
        [1, 2, 3]
    );
    assert!(d.is_empty());
    // TestTaggedRawValue.
    for (should_match, first) in [
        (false, 0x02),
        (true, 0x85),
        (true, 0xa5),
        (false, 0x65),
        (false, 0xe5),
    ] {
        let input = [first, 1, 1];
        let mut d = Decoder::new(&input).unwrap();
        assert_eq!(
            d.field::<RawValue>(&Params::parse("tag:5")).is_ok(),
            should_match,
            "{first:x}"
        );
        let mut d = Decoder::new(&input).unwrap();
        assert!(d.field::<RawValue>(&Params::NONE).is_ok());
    }
}

#[test]
fn go_implicit_type_round_trip() {
    struct Tagged {
        ia5: String,
        printable: String,
        utf8: String,
        numeric: String,
        utc: DateTime,
        generalized: DateTime,
    }
    const P: [&str; 6] = [
        "tag:1,ia5",
        "tag:2,printable",
        "tag:3,utf8",
        "tag:4,numeric",
        "tag:5,utc",
        "tag:6,generalized",
    ];
    let a = Tagged {
        ia5: "ia5".into(),
        printable: "printable".into(),
        utf8: "utf8".into(),
        numeric: "123 456".into(),
        utc: utc(2024, 2, 29, 12, 0, 1),
        generalized: utc(2024, 2, 29, 12, 0, 1),
    };
    let der = asn1::marshal(&Seq(vec![
        (&a.ia5, Params::parse(P[0])),
        (&a.printable, Params::parse(P[1])),
        (&a.utf8, Params::parse(P[2])),
        (&a.numeric, Params::parse(P[3])),
        (&a.utc, Params::parse(P[4])),
        (&a.generalized, Params::parse(P[5])),
    ]))
    .unwrap();
    let (raw, _) = asn1::parse_raw(&der).unwrap();
    let mut d = Decoder::new(&raw.bytes).unwrap();
    assert_eq!(d.field::<String>(&Params::parse(P[0])).unwrap(), a.ia5);
    assert_eq!(
        d.field::<String>(&Params::parse(P[1])).unwrap(),
        a.printable
    );
    assert_eq!(d.field::<String>(&Params::parse(P[2])).unwrap(), a.utf8);
    assert_eq!(d.field::<String>(&Params::parse(P[3])).unwrap(), a.numeric);
    assert_eq!(d.field::<DateTime>(&Params::parse(P[4])).unwrap(), a.utc);
    assert_eq!(
        d.field::<DateTime>(&Params::parse(P[5])).unwrap(),
        a.generalized
    );
}

#[test]
fn go_parse_field_parameters() {
    let p = Params::parse(
        "optional,explicit,default:42,tag:17,set,application,omitempty,utf8,generalized",
    );
    assert!(p.optional && p.explicit && p.set && p.application && p.omit_empty);
    assert_eq!((p.default, p.tag), (Some(42), Some(17)));
    assert_eq!(p.string_type, Some(StringType::Utf8));
    assert_eq!(p.time_type, Some(TimeType::Generalized));
    assert_eq!(Params::parse(""), Params::NONE);
    assert_eq!(Params::parse("explicit").tag, Some(0));
    assert_eq!(Params::parse("tag:3,explicit").tag, Some(3));
    assert_eq!(Params::parse("private").tag, Some(0));
    assert_eq!(Params::parse("unknown,default:x,tag:y"), Params::NONE);
    assert_eq!(
        Params::parse("optional,explicit,tag:3,default:7"),
        Params::NONE.optional().explicit(3).default_value(7)
    );
}

// Strictness beyond the Go tables.

#[test]
fn rejects_non_der_lengths_tags_and_integers() {
    for input in [
        &[0x02, 0x81, 0x01, 0x05][..],   // long form for short length
        &[0x02, 0x80, 0x05, 0x00, 0x00], // indefinite length
        &[0x02, 0x82, 0x00, 0x01, 0x05], // leading zero length octet
        &[0x1f, 0x05, 0x00],             // high tag form for low tag
        &[0x1f, 0x80, 0x1f, 0x00],       // non-minimal high tag
        &[0x02, 0x02, 0x00, 0x05],       // non-minimal positive integer
        &[0x02, 0x02, 0xff, 0x80],       // non-minimal negative integer
        &[0x02, 0x00],                   // empty integer
        &[0x02, 0x05, 0x01],             // truncated contents
        &[0x02],                         // truncated header
        &[],                             // empty input
    ] {
        assert!(decode::<i64>(input).is_err(), "{input:02x?}");
        assert!(asn1::parse_raw(input).is_err() || decode::<i64>(input).is_err());
    }
    assert!(decode::<bool>(&[0x01, 0x01, 0x01]).is_err());
    assert!(decode::<BitString>(&[0x03, 0x02, 0x01, 0x01]).is_err());
    assert!(decode::<i32>(&[0x02, 0x05, 0x00, 0x80, 0x00, 0x00, 0x00]).is_err());
    assert!(decode::<Enumerated>(&[0x0a, 0x05, 0x00, 0x80, 0x00, 0x00, 0x00]).is_err());
    assert_eq!(
        decode::<Enumerated>(&[0x0a, 0x01, 0x07]).unwrap(),
        Enumerated(7)
    );
    // Wrong universal tag or constructed flag.
    assert!(decode::<i64>(&[0x22, 0x01, 0x05]).is_err());
    assert!(decode::<i64>(&[0x0a, 0x01, 0x05]).is_err());
}

#[test]
fn rejects_bad_string_alphabets() {
    assert!(decode::<String>(b"\x13\x01@").is_err());
    assert!(decode::<String>(b"\x13\x01\x00").is_err());
    assert_eq!(decode::<String>(b"\x13\x01*").unwrap(), "*");
    assert!(decode::<String>(b"\x16\x01\x80").is_err());
    assert!(decode::<String>(b"\x12\x01a").is_err());
    assert!(decode::<String>(b"\x0c\x02\xc3\x28").is_err());
    assert_eq!(decode::<String>(b"\x1b\x01\xe9").unwrap(), "é");
    assert_eq!(decode::<String>(b"\x1e\x02\x00\xe9").unwrap(), "é");
    // A string tag that is not a string type.
    let mut d = Decoder::new(b"\x91\x01a").unwrap();
    assert!(d.field::<String>(&Params::parse("set")).is_err());
}

#[test]
fn time_strictness_matches_go_round_trip_rule() {
    let gt = |s: &str| decode::<DateTime>(&tlv(24, s.as_bytes()));
    let ut = |s: &str| decode::<DateTime>(&tlv(23, s.as_bytes()));
    assert!(gt("20000101000000.1Z").is_ok());
    assert_eq!(gt("20000101000000.000000001Z").unwrap().nanosecond(), 1);
    for bad in [
        "20000101000000.10Z",
        "20000101000000.0Z",
        "20000101000000.1234567891Z",
        "20000101000000,1Z",
        "20000101000000+0000",
        "20000101000000-0000",
        "20000101000000+0060",
        "20000101000000+2500",
        "20000229000000z",
        "20010229000000Z",
        // Accepted by Go but not representable by time::DateTime.
        "00000101000000Z",
        "20000101000000+2400",
    ] {
        assert!(gt(bad).is_err(), "{bad}");
    }
    assert!(gt("20000229000000Z").is_ok());
    assert_eq!(ut("4912312359Z").unwrap(), utc(2049, 12, 31, 23, 59, 0));
    assert_eq!(ut("500101000000Z").unwrap(), utc(1950, 1, 1, 0, 0, 0));
    for bad in [
        "4912312359",
        "491231235960Z",
        "4912312359.5Z",
        "49123123595Z",
        "000229000000Z+",
    ] {
        assert!(ut(bad).is_err(), "{bad}");
    }
    // Offsets that truncate to zero minutes are written as Z.
    let t = DateTime::new(2001, 2, 3, 4, 5, 6, 0, -30).unwrap();
    assert_eq!(asn1::marshal(&t).unwrap(), tlv(23, b"010203040506Z"));
    let t = DateTime::new(2001, 2, 3, 4, 5, 6, 0, -90).unwrap();
    assert_eq!(asn1::marshal(&t).unwrap(), tlv(23, b"010203040506-0001"));
}

#[test]
fn explicit_wrapper_follows_go_unless_strict() {
    let explicit = Params::parse("explicit,tag:0");
    let strict = Options {
        strict_explicit: true,
        ..Options::default()
    };
    // Over-long wrapper (Go reads the inner element and continues inside).
    for input in [
        &[0xa0, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07][..],
        &[0xa0, 0x05, 0x02, 0x01, 0x05],
        &[0xa0, 0x01, 0x02, 0x01, 0x05],
    ] {
        let err = Decoder::with_options(input, strict)
            .unwrap()
            .field::<i64>(&explicit)
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ExplicitLength, "{input:02x?}");
        let mut d = Decoder::new(input).unwrap();
        assert_eq!(d.field::<i64>(&explicit).unwrap(), 5);
    }
    // A compliant wrapper decodes identically in both modes.
    let input = [0xa0, 0x03, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07];
    for options in [Options::default(), strict] {
        let mut d = Decoder::with_options(&input, options).unwrap();
        assert_eq!(d.field::<i64>(&explicit).unwrap(), 5);
        assert_eq!(d.field::<i64>(&Params::NONE).unwrap(), 7);
    }
    // Go: an explicit field at the very end of its container has no child,
    // even when OPTIONAL or a zero-length Flag.
    let mut d = Decoder::new(&[0x05, 0x00]).unwrap();
    assert!(d
        .field::<i64>(&Params::parse("optional,explicit,tag:0"))
        .is_err());
    let mut d = Decoder::new(&[0xa0, 0x00]).unwrap();
    assert!(d
        .field::<Flag>(&Params::parse("optional,explicit,tag:0"))
        .is_err());
    let mut d = Decoder::new(&[0xa0, 0x00, 0x05, 0x00]).unwrap();
    assert_eq!(
        d.field::<Flag>(&Params::parse("optional,explicit,tag:0"))
            .unwrap(),
        Flag(true)
    );
    let mut d = Decoder::new(&[0xa0, 0x00, 0x05, 0x00]).unwrap();
    assert!(d.field::<i64>(&Params::parse("explicit,tag:0")).is_err());
    // Go's decoder expects CONTEXT-SPECIFIC for private explicit tags.
    let der = asn1::marshal_with_params(&5i64, &Params::parse("private,explicit,tag:1")).unwrap();
    assert_eq!(der, [0xe1, 0x03, 0x02, 0x01, 0x05]);
    assert!(
        asn1::unmarshal_with_params::<i64>(&der, &Params::parse("private,explicit,tag:1")).is_err()
    );
}

#[test]
fn optional_default_and_option_semantics() {
    let p = Params::parse("optional,default:9");
    let mut d = Decoder::new(&[0x04, 0x00]).unwrap();
    assert_eq!(d.field::<i64>(&p).unwrap(), 9);
    assert_eq!(d.field::<i32>(&p).unwrap(), 9);
    assert_eq!(d.field::<Enumerated>(&p).unwrap(), Enumerated(9));
    assert_eq!(d.field::<String>(&p).unwrap(), "");
    assert_eq!(d.optional::<i64>(&Params::NONE).unwrap(), None);
    assert_eq!(d.field::<Vec<u8>>(&Params::NONE).unwrap(), Vec::<u8>::new());
    assert!(d.is_empty());
    assert_eq!(d.optional::<i64>(&Params::NONE).unwrap(), None);
    // Top-level optional mismatch returns the whole input as rest.
    let (v, rest) =
        asn1::unmarshal_with_params::<i64>(&[4, 0], &Params::parse("optional")).unwrap();
    assert_eq!((v, rest), (0, &[4u8, 0][..]));
    // Encoder::optional encodes a present zero value; field() omits it.
    let mut out = Vec::new();
    Encoder::new(&mut out)
        .optional(Some(&0i64), &Params::parse("optional"))
        .unwrap()
        .field(&0i64, &Params::parse("optional"))
        .unwrap()
        .optional(None::<&i64>, &Params::NONE)
        .unwrap();
    assert_eq!(out, [0x02, 0x01, 0x00]);
    // Trailing elements inside a SEQUENCE are left for the caller.
    let (raw, _) = asn1::parse_raw(&hex("3006020101020102")).unwrap();
    let mut d = Decoder::new(&raw.bytes).unwrap();
    assert_eq!(d.field::<i64>(&Params::NONE).unwrap(), 1);
    assert_eq!(d.remaining(), [0x02, 0x01, 0x02]);
}

#[test]
fn integer_helpers() {
    assert_eq!(
        Integer::from_unsigned_bytes(&[0, 0, 0x80]).as_twos_complement(),
        [0, 0x80]
    );
    assert_eq!(Integer::from_unsigned_bytes(&[]).as_twos_complement(), [0]);
    assert_eq!(Integer::from_i64(0).as_twos_complement(), [0]);
    assert!(Integer::from_i64(-1).is_negative());
    assert_eq!(Integer::from_i64(i64::MIN).to_i64(), Some(i64::MIN));
    assert!(Integer::from_twos_complement(&[0, 1]).is_err());
    let big = Integer::from_twos_complement(&[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
    assert_eq!(big.to_i64(), None);
    assert_eq!(asn1::marshal(&big).unwrap()[..2], [0x02, 0x09]);
}

// Budgets.

#[test]
fn nesting_depth_budget() {
    // Recursive SEQUENCE OF SEQUENCE OF ... like Go's TestUnmarshalNestingLimitSlice.
    #[derive(Debug)]
    struct Recursive(#[allow(dead_code)] Vec<Recursive>);
    impl Unmarshal for Recursive {
        fn asn1_type() -> Asn1Type {
            Asn1Type::SEQUENCE
        }
        fn decode(e: &Element<'_>) -> Result<Self, Error> {
            Ok(Recursive(asn1::decode_sequence_of(
                &asn1::Typed::<Recursive>::new(),
                e,
            )?))
        }
        fn zero() -> Self {
            Recursive(Vec::new())
        }
    }
    fn nested(depth: usize) -> Vec<u8> {
        let mut der = vec![0x30, 0x00];
        for _ in 1..depth {
            der = tlv(0x30, &der);
        }
        der
    }
    let limit = Options::default().max_depth;
    assert!(decode::<Recursive>(&nested(limit)).is_ok());
    let err = decode::<Recursive>(&nested(limit + 1)).unwrap_err();
    assert_eq!(err.message(), "nesting depth exceeded");
    let small = Options {
        max_depth: 3,
        ..Options::default()
    };
    assert!(Decoder::with_options(&nested(3), small)
        .unwrap()
        .field::<Recursive>(&Params::NONE)
        .is_ok());
    assert!(Decoder::with_options(&nested(4), small)
        .unwrap()
        .field::<Recursive>(&Params::NONE)
        .is_err());
}

#[test]
fn input_and_element_budgets() {
    let limits = Options {
        max_input_bytes: 4,
        ..Options::default()
    };
    assert_eq!(
        Decoder::with_options(&[0x30, 0x03, 0x02, 0x01, 0x00], limits)
            .unwrap_err()
            .kind(),
        ErrorKind::Limit
    );
    let limits = Options {
        max_elements: 2,
        ..Options::default()
    };
    let three = hex("3009020101020102020103");
    let err = Decoder::with_options(&three, limits)
        .unwrap()
        .field::<Vec<i64>>(&Params::NONE)
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Limit);
    // Go's TestParsingMemoryConsumption: a ~10 MB empty-SEQUENCE bomb fails on
    // contents without allocating per counted element.
    let mut bomb = vec![0x30, 0x83, 0x98, 0x96, 0x80];
    bomb.extend(std::iter::repeat_n(0x30, 10_000_000));
    #[derive(Debug)]
    struct Entry;
    impl Unmarshal for Entry {
        fn asn1_type() -> Asn1Type {
            Asn1Type::SEQUENCE
        }
        fn decode(e: &Element<'_>) -> Result<Self, Error> {
            let mut d = e.contents();
            d.field::<Vec<i64>>(&Params::NONE)?;
            d.field::<bool>(&Params::parse("optional"))?;
            d.field::<Vec<u8>>(&Params::NONE)?;
            Ok(Entry)
        }
        fn zero() -> Self {
            Entry
        }
    }
    let err = decode::<Vec<Entry>>(&bomb).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Syntax);
}

#[test]
fn marshal_trait_objects_and_set_of_sorting_match_der() {
    // A SET OF sorts by full encodings: shorter lengths first.
    let der = asn1::marshal(&SetOf(vec![vec![1u8, 2], vec![9u8], vec![]])).unwrap();
    assert_eq!(
        der,
        [0x31, 0x09, 0x04, 0x00, 0x04, 0x01, 0x09, 0x04, 0x02, 0x01, 0x02]
    );
    // BIT STRING padding bits are written as stored, as in Go.
    assert_eq!(
        asn1::marshal(&BitString::new(vec![0xff], 4)).unwrap(),
        [0x03, 0x02, 0x04, 0xff]
    );
    // RawValue full_bytes is emitted verbatim and ignores parameters.
    let raw = RawValue {
        full_bytes: vec![0x05, 0x00],
        ..RawValue::default()
    };
    assert_eq!(
        asn1::marshal_with_params(&raw, &Params::parse("explicit,tag:3")).unwrap(),
        [5, 0]
    );
    // T61 and BMP encoders round-trip through the decoders.
    for st in [StringType::T61, StringType::Bmp] {
        let der = asn1::marshal_with_params(&"café", &Params::NONE.string_type(st)).unwrap();
        assert_eq!(decode::<String>(&der).unwrap(), "café");
    }
    // High tag numbers and long lengths.
    let der = asn1::marshal_with_params(&vec![7u8; 300], &Params::parse("tag:200")).unwrap();
    assert_eq!(der[..5], [0x9f, 0x81, 0x48, 0x82, 0x01]);
    let mut d = Decoder::new(&der).unwrap();
    assert_eq!(
        d.field::<Vec<u8>>(&Params::parse("tag:200")).unwrap(),
        vec![7u8; 300]
    );
}

#[test]
fn class_constants_and_object_identifier_helpers_match_go() {
    // Go: ClassUniversal..ClassPrivate are 0..3; String is dotted decimal and
    // Equal compares the arcs (negative arcs print as Go prints them).
    assert_eq!(Class::Universal.bits(), 0);
    assert_eq!(Class::Application.bits(), 1);
    assert_eq!(Class::ContextSpecific.bits(), 2);
    assert_eq!(Class::Private.bits(), 3);
    let oid = ObjectIdentifier::new(vec![1, 2, 840, 113549]);
    assert_eq!(oid.to_string(), "1.2.840.113549");
    assert_eq!(ObjectIdentifier::new(vec![2, -5]).to_string(), "2.-5");
    assert_eq!(ObjectIdentifier::new(Vec::new()).to_string(), "");
    assert!(oid == ObjectIdentifier::new(vec![1, 2, 840, 113549]));
    assert!(oid != ObjectIdentifier::new(vec![1, 2]));
    // Go NullRawValue is {Tag: TagNull}; NullBytes is its DER encoding.
    let null = RawValue::null();
    assert_eq!(
        (null.tag, null.class, null.is_compound),
        (asn1::TAG_NULL, Class::Universal, false)
    );
    assert_eq!(asn1::marshal(&Null).unwrap(), asn1::NULL_BYTES.to_vec());
}
