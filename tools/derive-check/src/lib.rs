#![forbid(unsafe_code)]
#[cfg(test)]
fn encode<T: rust_stdlib::encoding::json::Serialize + ?Sized>(
    value: &T,
) -> Result<String, rust_stdlib::encoding::json::Error> {
    Ok(String::from_utf8_lossy(&rust_stdlib::encoding::json::marshal(value)?).into_owned())
}
#[cfg(test)]
fn decode<T: rust_stdlib::encoding::json::Deserialize>(
    text: &str,
) -> Result<T, rust_stdlib::encoding::json::Error> {
    rust_stdlib::encoding::json::unmarshal(text.as_bytes())
}
#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::{decode, encode};
    use rust_stdlib::encoding::json::{self, Deserialize as _, Serialize as _};
    use rust_stdlib_derive::{Deserialize, Serialize};
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Named {
        pub(crate) r#type: String,
        nested: Vec<Option<Vec<u64>>>,
    }
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Tuple(String, u64);
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Unit;
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Empty {}
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    enum Event {
        Idle,
        Message { r#type: String, count: u64 },
        Coordinates(i64, i64),
        Empty(),
        Object {},
    }
    fn roundtrip<T: json::Serialize + json::Deserialize + std::fmt::Debug + PartialEq>(value: T) {
        let encoded = encode(&value).unwrap();
        assert_eq!(decode::<T>(&encoded).unwrap(), value);
    }
    #[test]
    fn structs() {
        roundtrip(Named {
            r#type: "photo".into(),
            nested: vec![None, Some(vec![u64::MAX])],
        });
        roundtrip(Tuple("x".into(), 42));
        roundtrip(Unit);
        roundtrip(Empty {});
        assert_eq!(encode(&Unit).unwrap(), "null");
    }
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Declared {
        b: i32,
        a: i32,
    }
    #[derive(Serialize)]
    struct Outer {
        z: Declared,
        by_name: std::collections::HashMap<String, Declared>,
        a: Vec<Declared>,
    }
    #[test]
    fn struct_field_order_survives_value() {
        let s = Declared { b: 1, a: 2 };
        let v = s.to_json().unwrap();
        assert_eq!(v.to_string(), r#"{"b":1,"a":2}"#);
        assert_eq!(
            v.as_object().unwrap().keys().collect::<Vec<_>>(),
            ["b", "a"]
        );
        assert_eq!(encode(&v).unwrap(), r#"{"b":1,"a":2}"#);
        // A struct inside a map keeps its order; the map's keys are sorted.
        let mut m = std::collections::HashMap::new();
        m.insert("current".to_string(), Declared { b: 3, a: 4 });
        m.insert("alpha".to_string(), Declared { b: 5, a: 6 });
        let want = r#"{"alpha":{"b":5,"a":6},"current":{"b":3,"a":4}}"#;
        assert_eq!(m.to_json().unwrap().to_string(), want);
        assert_eq!(encode(&m).unwrap(), want);
        let outer = Outer {
            z: Declared { b: 7, a: 8 },
            by_name: m,
            a: vec![Declared { b: 9, a: 10 }],
        };
        let want = concat!(
            r#"{"z":{"b":7,"a":8},"by_name":{"alpha":{"b":5,"a":6},"current":{"b":3,"a":4}},"#,
            r#""a":[{"b":9,"a":10}]}"#
        );
        assert_eq!(outer.to_json().unwrap().to_string(), want);
        assert_eq!(encode(&outer).unwrap(), want);
    }
    #[test]
    fn enum_variant_fields_keep_declared_order() {
        let e = Event::Message {
            r#type: "t".into(),
            count: 2,
        };
        assert_eq!(
            e.to_json().unwrap().to_string(),
            r#"{"Message":{"type":"t","count":2}}"#
        );
    }
    #[test]
    fn decoding_into_value_sorts_keys() {
        // Go decodes into map[string]any, which marshals sorted.
        let v: json::Value = decode(r#"{"b":1,"a":{"d":1,"c":2}}"#).unwrap();
        assert_eq!(v.to_string(), r#"{"a":{"c":2,"d":1},"b":1}"#);
    }
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct Inner {
        #[json(rename = "X")]
        x: i64,
        #[json(rename = "Y")]
        y: String,
    }
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct Emb {
        #[json(rename = "E1")]
        e1: i64,
        #[json(rename = "E2")]
        e2: i64,
    }
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct Existing {
        #[json(rename = "A")]
        a: i64,
        #[json(rename = "B")]
        b: String,
        #[json(rename = "In")]
        inner: Inner,
        #[json(rename = "P")]
        p: Option<Box<Inner>>,
        #[json(rename = "M")]
        m: std::collections::BTreeMap<String, Inner>,
        #[json(rename = "L")]
        l: Vec<Inner>,
        #[json(rename = "Ar")]
        ar: [i64; 3],
        #[json(embedded)]
        emb: Emb,
        #[json(rename = "Q", string)]
        q: i64,
        #[json(skip)]
        skipped: i64,
    }
    fn inner(x: i64, y: &str) -> Inner {
        Inner { x, y: y.into() }
    }
    fn existing() -> Existing {
        Existing {
            a: 1,
            b: "b".into(),
            inner: inner(1, "y"),
            p: Some(Box::new(inner(2, "p"))),
            m: [
                ("k".to_string(), inner(1, "k")),
                ("j".to_string(), inner(2, "j")),
            ]
            .into(),
            l: vec![inner(1, "a"), inner(2, "b")],
            ar: [7, 8, 9],
            emb: Emb { e1: 5, e2: 6 },
            q: 4,
            skipped: 99,
        }
    }
    fn merged(input: &str) -> (Result<(), json::Error>, Existing) {
        let mut e = existing();
        (json::unmarshal_into(input.as_bytes(), &mut e), e)
    }
    // The expectations below were produced by Go's `json.Unmarshal` into the
    // equivalent struct.
    #[test]
    fn unmarshal_into_keeps_unnamed_fields() {
        let (r, e) = merged(r#"{"A":10}"#);
        r.unwrap();
        assert_eq!(
            e,
            Existing {
                a: 10,
                ..existing()
            }
        );
        let (r, e) = merged(r#"{"In":{"X":9}}"#);
        r.unwrap();
        assert_eq!(e.inner, inner(9, "y"));
        let (r, e) = merged(r#"{"P":{"X":9}}"#);
        r.unwrap();
        assert_eq!(e.p, Some(Box::new(inner(9, "p"))));
        let (r, e) = merged(r#"{"E1":50}"#);
        r.unwrap();
        assert_eq!(e.emb, Emb { e1: 50, e2: 6 });
        let (r, e) = merged(r#"{"In":{"X":9},"In":{"Y":"z"}}"#);
        r.unwrap();
        assert_eq!(e.inner, inner(9, "z"));
        // Unnamed or unknown members change nothing.
        let (r, e) = merged(r#"{"nope":1}"#);
        r.unwrap();
        assert_eq!(e, existing());
    }
    #[test]
    fn unmarshal_into_null_rules() {
        let (r, e) = merged(r#"{"A":null,"B":null,"In":null,"Ar":null,"Q":null}"#);
        r.unwrap();
        assert_eq!(e, existing());
        let (r, e) = merged(r#"{"P":null,"M":null,"L":null}"#);
        r.unwrap();
        assert_eq!(
            e,
            Existing {
                p: None,
                m: Default::default(),
                l: vec![],
                ..existing()
            }
        );
        let (r, e) = merged(r#"{"Q":"null"}"#);
        r.unwrap();
        assert_eq!(e, existing());
        let (r, e) = merged("null");
        r.unwrap();
        assert_eq!(e, existing());
    }
    #[test]
    fn unmarshal_into_containers() {
        // Map entries named are replaced by fresh values, others kept.
        let (r, e) = merged(r#"{"M":{"k":{"X":9},"n":{"Y":"n"}}}"#);
        r.unwrap();
        assert_eq!(
            e.m,
            [
                ("j".to_string(), inner(2, "j")),
                ("k".to_string(), inner(9, "")),
                ("n".to_string(), inner(0, "n")),
            ]
            .into()
        );
        // A slice takes the JSON length; elements already there are merged.
        let (r, e) = merged(r#"{"L":[{"X":9}]}"#);
        r.unwrap();
        assert_eq!(e.l, vec![inner(9, "a")]);
        let (r, e) = merged(r#"{"L":[{"X":9},{},{"Y":"c"}]}"#);
        r.unwrap();
        assert_eq!(e.l, vec![inner(9, "a"), inner(2, "b"), inner(0, "c")]);
        // An array is decoded in place and the rest zeroed.
        let (r, e) = merged(r#"{"Ar":[1]}"#);
        r.unwrap();
        assert_eq!(e.ar, [1, 0, 0]);
        // A nil pointer is allocated.
        let mut e = existing();
        e.p = None;
        json::unmarshal_into(br#"{"P":{"X":9}}"#, &mut e).unwrap();
        assert_eq!(e.p, Some(Box::new(inner(9, ""))));
    }
    #[derive(Debug, Default, Deserialize)]
    struct FlagHolder {
        #[json("flag")]
        flag: bool,
    }

    #[derive(Debug, Default)]
    struct Custom(bool);

    impl json::Unmarshaler for Custom {
        fn unmarshal_json(&mut self, data: &[u8]) -> Result<(), json::Error> {
            self.0 = json::unmarshal::<FlagHolder>(data)?.flag;
            Ok(())
        }
    }

    impl json::Deserialize for Custom {
        fn from_json(_: &json::Value) -> Result<Self, json::Error> {
            unreachable!("decoded through unmarshal_json")
        }
        fn unmarshal_json(
            node: &json::Node<'_>,
            _: &mut json::DecodeState,
        ) -> Result<Self, json::Error> {
            let mut out = Custom::default();
            node.unmarshal_into(&mut out)?;
            Ok(out)
        }
    }

    #[derive(Debug, Default, Deserialize)]
    struct CustomHolder {
        #[json("custom")]
        custom: Custom,
    }

    #[test]
    fn unmarshaler_type_errors_keep_their_own_path() {
        // Go returns an UnmarshalJSON error as the method made it: the
        // fields around the value add nothing to its path.
        let err = json::unmarshal::<CustomHolder>(br#"{"custom":{"flag":"yes"}}"#).unwrap_err();
        assert_eq!(
            err.to_string(),
            "json: cannot unmarshal string into Go struct field FlagHolder.flag of type bool"
        );
        let err = json::unmarshal::<CustomHolder>(br#"{"custom":[1]}"#).unwrap_err();
        assert_eq!(
            err.to_string(),
            "json: cannot unmarshal array into Go value of type FlagHolder"
        );
    }

    #[test]
    fn unmarshal_into_errors() {
        // A type error is returned, but the other fields are still set.
        let (r, e) = merged(r#"{"A":"s","B":"new"}"#);
        let err = r.unwrap_err();
        assert_eq!(
            err.to_string(),
            "json: cannot unmarshal string into Go struct field Existing.A of type int64"
        );
        assert_eq!(
            e,
            Existing {
                b: "new".into(),
                ..existing()
            }
        );
        let (r, e) = merged("[1]");
        assert!(matches!(r, Err(json::Error::UnmarshalType(_))));
        assert_eq!(e, existing());
        // Syntax errors leave the value untouched.
        let (r, e) = merged(r#"{"A":10"#);
        assert!(r.is_err());
        assert_eq!(e, existing());
    }
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Lists {
        #[json(rename = "L")]
        l: Vec<Inner>,
        #[json(rename = "N")]
        n: Vec<i64>,
    }
    // Go keeps decoding after an element's type error: the bad element keeps
    // its old value (zero when new), the length follows the JSON array and the
    // first error is returned.
    #[test]
    fn unmarshal_into_vec_continues_after_element_error() {
        let mut v = Lists {
            l: vec![inner(1, "a"), inner(2, "b"), inner(3, "c")],
            n: vec![7, 8],
        };
        let err = json::unmarshal_into(
            br#"{"L":[{"X":9},{"X":"bad"},{"X":5},{"X":6}],"N":[1,"x",3]}"#,
            &mut v,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "json: cannot unmarshal string into Go struct field Lists.L.1.X of type int64"
        );
        assert_eq!(
            v,
            Lists {
                l: vec![inner(9, "a"), inner(2, "b"), inner(5, "c"), inner(6, "")],
                n: vec![1, 8, 3],
            }
        );
        // Shorter JSON truncates even when the element failed.
        let mut v = Lists {
            l: vec![inner(1, "a"), inner(2, "b")],
            n: vec![],
        };
        assert!(json::unmarshal_into(br#"{"L":[{"X":"bad"}]}"#, &mut v).is_err());
        assert_eq!(v.l, vec![inner(1, "a")]);
        // A fresh value reports the same first error.
        let fresh = json::unmarshal::<Lists>(br#"{"L":[{"X":9},{"X":"bad"}],"N":[1,"x",3]}"#);
        assert!(fresh.unwrap_err().to_string().contains("Lists.L.1.X"));
    }
    #[test]
    fn decoder_decode_into_merges() {
        let mut dec = json::Decoder::new(std::io::Cursor::new(br#"{"A":10} {"B":"two"}"#.to_vec()));
        let mut e = existing();
        dec.decode_into(&mut e).unwrap();
        dec.decode_into(&mut e).unwrap();
        assert_eq!(
            e,
            Existing {
                a: 10,
                b: "two".into(),
                ..existing()
            }
        );
    }
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    enum Hygiene {
        Fields {
            object: String,
            __rust_stdlib_object: String,
            value: u64,
            payload: bool,
        },
    }
    #[test]
    fn binding_hygiene() {
        roundtrip(Hygiene::Fields {
            object: "a".into(),
            __rust_stdlib_object: "b".into(),
            value: 42,
            payload: true,
        });
    }
    #[test]
    fn enum_payloads() {
        for value in [
            Event::Idle,
            Event::Message {
                r#type: "rename".into(),
                count: 2,
            },
            Event::Coordinates(-4, 8),
            Event::Empty(),
            Event::Object {},
        ] {
            roundtrip(value);
        }
        assert_eq!(encode(&Event::Idle).unwrap(), "{\"Idle\":null}");
    }
    #[test]
    fn rejects_shape_errors() {
        for s in [
            "{}",
            "{\"Idle\":null,\"Empty\":[]}",
            "{\"Unknown\":null}",
            "{\"Idle\":[]}",
            "{\"Coordinates\":[1]}",
            "{\"Message\":{\"type\":\"x\"}}",
        ] {
            assert!(decode::<Event>(s).is_err());
        }
        // Go semantics: unknown members are ignored and absent ones are zero.
        let loose = Named::from_json(
            &("{\"type\":\"x\",\"nested\":[],\"extra\":0}")
                .parse::<json::Value>()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(loose.r#type, "x");
        assert!(Named::from_json(&("[]").parse::<json::Value>().unwrap()).is_err());
        assert!(Tuple::from_json(&json::Value::Null).is_err());
        assert!(Unit.to_json().is_ok());
    }
}

#[cfg(test)]
mod generic_tests {
    #![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]
    #[allow(unused_imports)]
    use super::{decode, encode};
    use rust_stdlib::encoding::json::{self, Deserialize as _, Serialize as _};
    use rust_stdlib_derive::{Deserialize, Serialize};
    use std::marker::PhantomData;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Defaults<T: Clone = String, const N: usize = 3>
    where
        T: PartialEq,
    {
        value: T,
        fixed: Fixed<N>,
    }
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Fixed<const N: usize> {
        values: Vec<u64>,
    }
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TupleWhere<T>(T)
    where
        T: Clone + PartialEq;
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    enum GenericEvent<T, const N: usize>
    where
        T: Clone,
    {
        Empty,
        Tuple(T, Fixed<N>),
        Named { value: T },
    }
    #[derive(Debug, PartialEq)]
    struct Marker<'a>(PhantomData<&'a ()>);
    impl json::Serialize for Marker<'_> {
        fn to_json(&self) -> Result<json::Value, json::Error> {
            Ok(json::Value::Null)
        }
    }
    impl json::Deserialize for Marker<'_> {
        fn from_json(value: &json::Value) -> Result<Self, json::Error> {
            if *value == json::Value::Null {
                Ok(Self(PhantomData))
            } else {
                Err(json::Error::Type("expected marker null"))
            }
        }
    }
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Lifetimes<'a: 'b, 'b, T: Clone + 'a>
    where
        T: PartialEq,
    {
        first: Marker<'a>,
        second: Marker<'b>,
        value: T,
    }
    trait Associated {
        type Value: Clone + PartialEq;
    }
    struct Provider;
    impl Associated for Provider {
        type Value = String;
    }
    #[derive(Serialize, Deserialize)]
    struct Projection<T: Associated>
    where
        T::Value: std::fmt::Debug,
    {
        value: T::Value,
    }
    trait Shared<'a> {}
    impl<'a> Shared<'a> for String {}
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct HigherRanked<T>
    where
        for<'any> T: Shared<'any>,
        T: Clone,
    {
        value: T,
    }
    // Generated result types/locals must remain hygienic with user names.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Names<Result, Value, Error, const value: usize> {
        object: Result,
        tag: Value,
        payload: Error,
        __rust_stdlib_value: String,
    }
    #[derive(Serialize, Deserialize)]
    enum EmptyEnum {}
    fn roundtrip<T: json::Serialize + json::Deserialize + std::fmt::Debug + PartialEq>(value: T) {
        let encoded = encode(&value).unwrap();
        assert_eq!(decode::<T>(&encoded).unwrap(), value);
    }
    #[test]
    fn type_defaults_const_params_and_where_clauses() {
        let defaults: Defaults = Defaults {
            value: "name".into(),
            fixed: Fixed {
                values: vec![1, 2, 3],
            },
        };
        roundtrip(defaults);
        roundtrip(Defaults::<u64, 4> {
            value: u64::MAX,
            fixed: Fixed {
                values: vec![1, 2, 3, 4],
            },
        });
        roundtrip(TupleWhere(vec![1u64, 2, 3]));
        roundtrip(GenericEvent::<String, 2>::Tuple(
            "hello".into(),
            Fixed { values: vec![7, 8] },
        ));
        roundtrip(GenericEvent::<u64, 1>::Named { value: 42 });
        roundtrip(GenericEvent::<bool, 0>::Empty);
    }
    #[test]
    fn lifetime_and_higher_ranked_bounds() {
        roundtrip(Lifetimes {
            first: Marker(PhantomData),
            second: Marker(PhantomData),
            value: "owned".to_string(),
        });
        roundtrip(HigherRanked {
            value: "trait".to_string(),
        });
    }
    #[test]
    fn associated_projection_and_name_hygiene() {
        let value = Projection::<Provider> {
            value: "projected".into(),
        };
        let encoded = value.to_json().unwrap();
        assert_eq!(
            Projection::<Provider>::from_json(&encoded).unwrap().value,
            value.value
        );
        roundtrip(Names::<String, u64, bool, 7> {
            object: "object".into(),
            tag: 5,
            payload: true,
            __rust_stdlib_value: "private".into(),
        });
    }
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Recursive<T> {
        value: T,
        next: Option<Box<Recursive<T>>>,
    }
    #[test]
    fn recursive_generic_roundtrip() {
        roundtrip(Recursive {
            value: 1u64,
            next: Some(Box::new(Recursive {
                value: 2,
                next: None,
            })),
        });
    }
    #[derive(Serialize, Deserialize)]
    enum GenericNames<Result, const object: usize> {
        Fields {
            Ok: Result,
            Err: u64,
            __rust_stdlib_field_0: bool,
        },
    }
    #[test]
    fn enum_generic_binding_hygiene() {
        let value = GenericNames::<String, 3>::Fields {
            Ok: "success".into(),
            Err: 7,
            __rust_stdlib_field_0: true,
        };
        let encoded = value.to_json().unwrap();
        let GenericNames::<String, 3>::Fields {
            Ok: ok,
            Err: err,
            __rust_stdlib_field_0,
        } = GenericNames::from_json(&encoded).unwrap();
        assert_eq!(ok, "success");
        assert_eq!(err, 7);
        assert!(__rust_stdlib_field_0);
    }
    struct LifetimeValue<'a, T>(T, PhantomData<&'a ()>);
    impl<T: json::Serialize> json::Serialize for LifetimeValue<'_, T> {
        fn to_json(&self) -> Result<json::Value, json::Error> {
            self.0.to_json()
        }
    }
    impl<T: json::Deserialize> json::Deserialize for LifetimeValue<'_, T> {
        fn from_json(value: &json::Value) -> Result<Self, json::Error> {
            Ok(Self(T::from_json(value)?, PhantomData))
        }
    }
    #[derive(Serialize, Deserialize)]
    struct LifetimeGeneric<'a: 'b, 'b, T> {
        first: LifetimeValue<'a, T>,
        second: LifetimeValue<'b, T>,
    }
    #[test]
    fn lifetime_bearing_generic_fields() {
        let value = LifetimeGeneric {
            first: LifetimeValue(1u64, PhantomData),
            second: LifetimeValue(2u64, PhantomData),
        };
        let decoded: LifetimeGeneric<u64> =
            LifetimeGeneric::from_json(&value.to_json().unwrap()).unwrap();
        assert_eq!(decoded.first.0, 1);
        assert_eq!(decoded.second.0, 2);
    }
    trait GenericAssociated {
        type Value<'a>: Clone
        where
            Self: 'a;
    }
    impl GenericAssociated for Provider {
        type Value<'a> = String;
    }
    #[derive(Serialize, Deserialize)]
    struct GenericProjection<'a, T: GenericAssociated + 'a> {
        value: T::Value<'a>,
        marker: Marker<'a>,
    }
    #[test]
    fn lifetime_associated_projection() {
        let value = GenericProjection::<Provider> {
            value: "GAT".into(),
            marker: Marker(PhantomData),
        };
        let encoded = value.to_json().unwrap();
        assert_eq!(
            GenericProjection::<Provider>::from_json(&encoded)
                .unwrap()
                .value,
            "GAT"
        );
    }
    #[test]
    fn empty_enum_rejects_all_values() {
        for value in [json::Value::Null, json::Value::object([])] {
            assert!(EmptyEnum::from_json(&value).is_err());
        }
    }
}

#[cfg(test)]
mod syntax_tests {
    #[allow(unused_imports)]
    use super::{decode, encode};
    use rust_stdlib::encoding::json::{self, Deserialize as _, Serialize as _};
    use rust_stdlib_derive::{Deserialize, Serialize};
    use std::marker::PhantomData;
    #[derive(Serialize)]
    struct Borrowed<'a> {
        text: &'a str,
        values: &'a [u64],
    }
    #[derive(Serialize, Deserialize)]
    struct Unsized<T: ?Sized = str> {
        value: T,
    }
    #[derive(Serialize, Deserialize)]
    struct Tag<T>(OwnedTag<T>);
    // Trait support is implemented explicitly for PhantomData below through a
    // local wrapper; generic bounds must target field types without overbinding T.
    struct OwnedTag<T>(PhantomData<T>);
    impl<T> json::Serialize for OwnedTag<T> {
        fn to_json(&self) -> Result<json::Value, json::Error> {
            Ok(json::Value::Null)
        }
    }
    impl<T> json::Deserialize for OwnedTag<T> {
        fn from_json(value: &json::Value) -> Result<Self, json::Error> {
            if *value == json::Value::Null {
                Ok(Self(PhantomData))
            } else {
                Err(json::Error::Type("expected null"))
            }
        }
    }
    #[derive(Serialize, Deserialize)]
    struct Callback<T> {
        callback: OwnedTag<fn() -> T>,
        value: T,
    }
    #[derive(Serialize, Deserialize)]
    struct ComplexDefaults<T = Vec<Option<Vec<u64>>>, const N: usize = { 1 << 2 }> {
        value: T,
        fixed: [u64; N],
    }
    #[test]
    fn borrowed_serialize_and_unsized_bound() {
        let value = Borrowed {
            text: "text",
            values: &[1, 2, 3],
        };
        assert_eq!(
            encode(&value).unwrap(),
            "{\"text\":\"text\",\"values\":[1,2,3]}"
        );
        let value = Unsized {
            value: "owned".to_string(),
        };
        let encoded = value.to_json().unwrap();
        assert_eq!(
            Unsized::<String>::from_json(&encoded).unwrap().value,
            "owned"
        );
    }
    struct Unserializable;
    #[test]
    fn bounds_target_fields_instead_of_unrelated_parameters() {
        let value = Tag::<Unserializable>(OwnedTag(PhantomData));
        assert_eq!(encode(&value).unwrap(), "[null]");
        assert!(Tag::<Unserializable>::from_json(&value.to_json().unwrap()).is_ok());
    }
    #[test]
    fn function_arrows_and_nested_default_generics() {
        let value = Callback {
            callback: OwnedTag(PhantomData),
            value: 42u64,
        };
        let encoded = value.to_json().unwrap();
        assert_eq!(Callback::<u64>::from_json(&encoded).unwrap().value, 42);
        let value: ComplexDefaults = ComplexDefaults {
            value: vec![Some(vec![7]), None],
            fixed: [1, 2, 3, 4],
        };
        let encoded = value.to_json().unwrap();
        let decoded: ComplexDefaults = ComplexDefaults::from_json(&encoded).unwrap();
        assert_eq!(decoded.fixed, [1, 2, 3, 4]);
    }

    #[test]
    fn embed_directories_and_patterns() {
        use rust_stdlib::io::fs;
        // Directory: names starting with '.' or '_' are skipped.
        static DIR: rust_stdlib::embed::FS = rust_stdlib_derive::embed!("embed-fixture");
        let mut seen = Vec::new();
        fs::walk_dir(&DIR, ".", |p, _, e| {
            assert!(e.is_none());
            seen.push(p.to_string());
            Ok(())
        })
        .unwrap();
        assert_eq!(
            seen,
            [
                ".",
                "embed-fixture",
                "embed-fixture/a.txt",
                "embed-fixture/c.md",
                "embed-fixture/sub",
                "embed-fixture/sub/b.txt",
            ]
        );
        assert_eq!(
            DIR.read_file("embed-fixture/sub/b.txt").unwrap(),
            b"bravo\n"
        );
        assert!(DIR.open("embed-fixture/.hidden").is_err());
        // all: prefix includes them.
        static ALL: rust_stdlib::embed::FS = rust_stdlib_derive::embed!("all:embed-fixture");
        assert_eq!(ALL.read_file("embed-fixture/.hidden").unwrap(), b"hidden\n");
        assert_eq!(ALL.read_file("embed-fixture/sub/_x.txt").unwrap(), b"x\n");
        // Explicit files and wildcards embed hidden names too; several patterns merge.
        static MIX: rust_stdlib::embed::FS = rust_stdlib_derive::embed!(
            "embed-fixture/*.md",
            "embed-fixture/.hidden",
            "embed-fixture/sub/_?.txt"
        );
        let names = fs::glob(&MIX, "embed-fixture/*").unwrap();
        assert_eq!(
            names,
            [
                "embed-fixture/.hidden",
                "embed-fixture/c.md",
                "embed-fixture/sub"
            ]
        );
        assert_eq!(MIX.read_file("embed-fixture/sub/_x.txt").unwrap(), b"x\n");
    }
}

/// Go's struct tag rules: renames, options, embedding, name matching and
/// error paths. Expected outputs were checked against Go 1.27.1 by
/// `tools/json_check.py`; these tests keep them without needing Go.
#[cfg(test)]
mod go_semantics {
    #![allow(non_snake_case)]
    #[allow(unused_imports)]
    use super::{decode, encode};
    use rust_stdlib::encoding::json::{self, Decoder, Error, Value};
    use rust_stdlib_derive::{Deserialize, Serialize};
    use std::collections::BTreeMap;

    fn text<T: json::Serialize>(v: &T) -> String {
        String::from_utf8(json::marshal(v).unwrap()).unwrap()
    }

    macro_rules! tag_struct {
        ($name:ident, $tag:literal) => {
            #[derive(Serialize)]
            struct $name {
                #[json($tag)]
                V: String,
            }
        };
    }
    tag_struct!(Latin2, "$%-/");
    tag_struct!(Latin3, "0123456789");
    tag_struct!(Latin4, "ABCDEFGHIJKLMO");
    tag_struct!(Latin6, "abcdefghijklmno");
    tag_struct!(Misc, "色は匂へど");
    tag_struct!(PercentSlash, "text/html%");
    tag_struct!(Punctuation, "!#$%&()*+-./:;<=>?@[]^_{|}~ ");
    tag_struct!(Dash, "-,");
    tag_struct!(SpaceTag, "With space");
    tag_struct!(UnicodeTag, "Ελλάδα");
    tag_struct!(BadCode, "a\\b");
    tag_struct!(BadQuote, "a'b");

    #[test]
    fn tag_names_are_taken_verbatim_up_to_reserved_characters() {
        let v = || "v".to_string();
        assert_eq!(text(&Latin2 { V: v() }), r#"{"$%-/":"v"}"#);
        assert_eq!(text(&Latin3 { V: v() }), r#"{"0123456789":"v"}"#);
        assert_eq!(text(&Latin4 { V: v() }), r#"{"ABCDEFGHIJKLMO":"v"}"#);
        assert_eq!(text(&Latin6 { V: v() }), r#"{"abcdefghijklmno":"v"}"#);
        assert_eq!(text(&Misc { V: v() }), r#"{"色は匂へど":"v"}"#);
        assert_eq!(text(&PercentSlash { V: v() }), r#"{"text/html%":"v"}"#);
        assert_eq!(text(&Dash { V: v() }), r#"{"-":"v"}"#);
        assert_eq!(text(&SpaceTag { V: v() }), r#"{"With space":"v"}"#);
        assert_eq!(text(&UnicodeTag { V: v() }), r#"{"Ελλάδα":"v"}"#);
        // HTML characters in names are escaped like everything else.
        assert_eq!(
            text(&Punctuation { V: v() }),
            r#"{"!#$%\u0026()*+-./:;\u003c=\u003e?@[]^_{|}~ ":"v"}"#
        );
        // A backslash or quote ends the name; what is left of it is used.
        assert_eq!(text(&BadCode { V: v() }), r#"{"a":"v"}"#);
        assert_eq!(text(&BadQuote { V: v() }), r#"{"a":"v"}"#);
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
    struct Options {
        #[json(rename = "renamed")]
        a: i32,
        #[json(omitempty)]
        b: String,
        #[json(omitzero)]
        c: Option<u8>,
        #[json("d,omitempty,string")]
        d: u16,
        #[json(skip)]
        hidden: i64,
        #[json("-")]
        also_hidden: i64,
        #[json("-,")]
        dash: i64,
        #[json(string)]
        e: f64,
        #[json(",omitempty")]
        f: Vec<u8>,
        #[json(omitzero, omitempty)]
        g: bool,
        plain: bool,
    }

    #[test]
    fn field_options_follow_go() {
        let v = Options {
            hidden: 5,
            also_hidden: 6,
            dash: 7,
            e: 1.5,
            ..Options::default()
        };
        assert_eq!(text(&v), r#"{"renamed":0,"-":7,"e":"1.5","plain":false}"#);
        let v = Options {
            a: -1,
            b: "x".into(),
            c: Some(0),
            d: 3,
            f: vec![1],
            g: true,
            plain: true,
            ..Options::default()
        };
        assert_eq!(
            text(&v),
            r#"{"renamed":-1,"b":"x","c":0,"d":"3","-":0,"e":"0","f":[1],"g":true,"plain":true}"#
        );
        // Decoding: names match exactly or, failing that, ignoring case; skipped
        // fields keep their default and unknown members are ignored.
        let d: Options = json::unmarshal(
            br#"{"RENAMED":4,"B":"y","c":null,"d":"9","hidden":3,"-":8,"E":"2.5","extra":[1],"Plain":true}"#,
        )
        .unwrap();
        assert_eq!(
            d,
            Options {
                a: 4,
                b: "y".into(),
                d: 9,
                dash: 8,
                e: 2.5,
                plain: true,
                ..Options::default()
            }
        );
        // The last of several matching members wins.
        let d: Options = json::unmarshal(br#"{"renamed":1,"Renamed":2}"#).unwrap();
        assert_eq!(d.a, 2);
    }

    #[test]
    fn string_option_errors_follow_go() {
        for (doc, want) in [
            (
                r#"{"d":5}"#,
                "json: cannot unmarshal number into Go struct field Options.d of type uint16",
            ),
            (
                r#"{"d":"abc"}"#,
                "json: cannot unmarshal number abc into Go struct field Options.d of type uint16",
            ),
            (
                r#"{"d":"70000"}"#,
                "json: cannot unmarshal number 70000 into Go struct field Options.d of type uint16",
            ),
            (
                r#"{"e":"x"}"#,
                "json: cannot unmarshal number x into Go struct field Options.e of type float64",
            ),
            (
                r#"{"renamed":"1"}"#,
                "json: cannot unmarshal string into Go struct field Options.renamed of type int32",
            ),
            (
                r#"{"b":[]}"#,
                "json: cannot unmarshal array into Go struct field Options.b of type string",
            ),
        ] {
            assert_eq!(
                json::unmarshal::<Options>(doc.as_bytes())
                    .unwrap_err()
                    .to_string(),
                want,
                "{doc}"
            );
        }
        // null and "null" leave the zero value.
        let d: Options = json::unmarshal(br#"{"d":null,"e":"null"}"#).unwrap();
        assert_eq!((d.d, d.e), (0, 0.0));
    }

    #[test]
    fn type_errors_are_saved_in_document_order_and_carry_paths() {
        #[derive(Deserialize, Debug)]
        struct Inner {
            #[allow(dead_code)]
            n: i8,
        }
        #[derive(Deserialize, Debug)]
        struct Outer {
            #[allow(dead_code)]
            a: u8,
            #[allow(dead_code)]
            inner: Vec<Inner>,
            #[allow(dead_code)]
            m: BTreeMap<String, Inner>,
        }
        // The earliest error in the document wins, not the first field's.
        let e =
            json::unmarshal::<Outer>(br#"{"m":{"k":{"n":1000}},"a":-1,"inner":[]}"#).unwrap_err();
        let Error::UnmarshalType(t) = &e else {
            panic!("{e}")
        };
        assert_eq!(
            (
                t.struct_name.as_str(),
                t.field.as_str(),
                t.type_name.as_str(),
                t.offset
            ),
            ("Outer", "m.k.n", "int8", 19)
        );
        let e = json::unmarshal::<Outer>(br#"{"inner":[{"n":1},{"n":"x"}]}"#).unwrap_err();
        assert_eq!(
            e.to_string(),
            "json: cannot unmarshal string into Go struct field Outer.inner.1.n of type int8"
        );
        // Syntax errors are reported before any type error.
        assert!(matches!(
            json::unmarshal::<Outer>(br#"{"a":"x",}"#),
            Err(Error::SyntaxError(_))
        ));
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
    struct Base {
        #[json("id")]
        ID: i64,
        #[json("name,omitempty")]
        Name: String,
        #[json("-")]
        Hidden: i64,
    }
    #[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
    struct Base2 {
        #[json("id")]
        ID: i64,
        Z: i64,
    }
    #[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
    struct A1 {
        V: i64,
    }
    #[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
    struct A3 {
        #[json("V")]
        V: i64,
    }
    #[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
    struct L2 {
        Deep: i64,
    }
    #[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
    struct L1 {
        #[json(embedded)]
        L2: L2,
        Mid: i64,
    }
    #[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
    struct Shadow {
        #[json(embedded)]
        Base: Base,
        Name: String,
        Own: i64,
    }
    #[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
    struct Clash {
        #[json(embedded)]
        Base: Base,
        #[json(embedded)]
        Base2: Base2,
        Last: i64,
    }
    #[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
    struct Tagged {
        #[json(embedded)]
        A1: A1,
        #[json(embedded)]
        A3: A3,
    }
    #[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
    struct Deep {
        Top: i64,
        #[json(embedded)]
        L1: L1,
    }
    #[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
    struct Pointer {
        #[json(embedded)]
        Base: Option<Base>,
        #[json("tail,omitempty")]
        Tail: String,
    }
    #[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
    struct Named {
        #[json("b8")]
        Base: Base,
        #[json(embedded)]
        Base2: Base2,
    }

    #[test]
    fn embedded_fields_are_promoted_with_go_precedence() {
        let b = || Base {
            ID: 1,
            Name: "n".into(),
            Hidden: 9,
        };
        assert_eq!(
            text(&Shadow {
                Base: b(),
                Name: "outer".into(),
                Own: 2
            }),
            r#"{"id":1,"name":"n","Name":"outer","Own":2}"#
        );
        // Two tagged `id` fields at the same depth cancel out.
        assert_eq!(
            text(&Clash {
                Base: b(),
                Base2: Base2 { ID: 5, Z: 6 },
                Last: 7
            }),
            r#"{"name":"n","Z":6,"Last":7}"#
        );
        // A tagged field beats an untagged one at the same depth.
        assert_eq!(
            text(&Tagged {
                A1: A1 { V: 1 },
                A3: A3 { V: 2 }
            }),
            r#"{"V":2}"#
        );
        assert_eq!(
            text(&Deep {
                Top: 1,
                L1: L1 {
                    L2: L2 { Deep: 2 },
                    Mid: 3
                }
            }),
            r#"{"Top":1,"Deep":2,"Mid":3}"#
        );
        assert_eq!(
            text(&Pointer {
                Base: None,
                Tail: "t".into()
            }),
            r#"{"tail":"t"}"#
        );
        assert_eq!(
            text(&Pointer {
                Base: Some(b()),
                Tail: String::new()
            }),
            r#"{"id":1,"name":"n"}"#
        );
        assert_eq!(
            text(&Named {
                Base: b(),
                Base2: Base2 { ID: 5, Z: 6 }
            }),
            r#"{"b8":{"id":1,"name":"n"},"id":5,"Z":6}"#
        );

        // Decoding fills the promoted fields, allocating a pointer only when
        // one of its members is present.
        let d: Shadow = json::unmarshal(br#"{"id":4,"NAME":"x","Name":"y","own":3}"#).unwrap();
        assert_eq!(
            d,
            Shadow {
                Base: Base {
                    ID: 4,
                    ..Base::default()
                },
                Name: "y".into(),
                Own: 3
            }
        );
        let d: Pointer = json::unmarshal(br#"{"tail":"t"}"#).unwrap();
        assert_eq!(
            d,
            Pointer {
                Base: None,
                Tail: "t".into()
            }
        );
        let d: Pointer = json::unmarshal(br#"{"id":3}"#).unwrap();
        assert_eq!(
            d.Base,
            Some(Base {
                ID: 3,
                ..Base::default()
            })
        );
        let d: Deep = json::unmarshal(br#"{"deep":1,"MID":2}"#).unwrap();
        assert_eq!(
            d,
            Deep {
                Top: 0,
                L1: L1 {
                    L2: L2 { Deep: 1 },
                    Mid: 2
                }
            }
        );
        let d: Clash = json::unmarshal(br#"{"id":4,"Z":1}"#).unwrap();
        assert_eq!(
            d,
            Clash {
                Base2: Base2 { ID: 0, Z: 1 },
                ..Clash::default()
            }
        );
        // The folded name picks the shallowest field: "NAME" is Shadow.Name.
        let e = json::unmarshal::<Shadow>(br#"{"NAME":0}"#).unwrap_err();
        assert_eq!(
            e.to_string(),
            "json: cannot unmarshal number into Go struct field Shadow.NAME of type string"
        );
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
    struct Strict {
        #[json("a,case:strict")]
        a: i32,
        b: i32,
    }

    #[test]
    fn case_matching_and_unknown_fields() {
        let d: Strict = json::unmarshal(br#"{"A":1,"B":2}"#).unwrap();
        assert_eq!(d, Strict { a: 0, b: 2 });
        let mut dec = Decoder::new(&br#"{"a":1,"zzz":2} {"A":3}"#[..]);
        dec.disallow_unknown_fields();
        let e = dec.decode::<Strict>().unwrap_err();
        assert_eq!(e.to_string(), "json: unknown field \"zzz\"");
        let e = dec.decode::<Strict>().unwrap_err();
        assert_eq!(e.to_string(), "json: unknown field \"A\"");
        // Without the option unknown members are ignored.
        let mut dec = Decoder::new(&br#"{"zzz":2,"b":5}"#[..]);
        assert_eq!(dec.decode::<Strict>().unwrap(), Strict { a: 0, b: 5 });
        // v2's looser matching ignores `-` and `_`.
        #[derive(Deserialize, Debug, PartialEq)]
        struct Delims {
            user_name: String,
        }
        assert!(json::unmarshal::<Delims>(br#"{"user-name":"x"}"#)
            .unwrap()
            .user_name
            .is_empty());
        let loose = json::match_case_sensitive_delimiter(false);
        assert_eq!(
            json::unmarshal_with_options::<Delims>(br#"{"user-name":"x"}"#, loose)
                .unwrap()
                .user_name,
            "x"
        );
    }

    #[derive(Serialize)]
    struct Quoting {
        #[json("n,string")]
        n: Option<i32>,
        #[json("s,string")]
        s: String,
        #[json("b,string")]
        b: bool,
        #[json("v,omitempty")]
        v: Value,
        #[json("e,omitempty")]
        e: Vec<u8>,
    }

    #[test]
    fn v2_forms_of_the_options_are_available() {
        let q = || Quoting {
            n: Some(1),
            s: "x".into(),
            b: true,
            v: Value::Null,
            e: vec![],
        };
        assert_eq!(text(&q()), r#"{"n":"1","s":"\"x\"","b":"true"}"#);
        let stringify = json::stringify_with_legacy_semantics(false);
        assert_eq!(
            String::from_utf8(json::marshal_with_options(&q(), stringify).unwrap()).unwrap(),
            r#"{"n":"1","s":"x","b":true}"#
        );
        // omitempty omits empty JSON values instead of Go's empty values.
        #[derive(Serialize)]
        struct Empty {
            #[json("z,omitempty")]
            z: i32,
            #[json("o,omitempty")]
            o: Option<i32>,
            #[json("q,omitempty,string")]
            q: Option<String>,
        }
        let e = Empty {
            z: 0,
            o: None,
            q: Some(String::new()),
        };
        assert_eq!(text(&e), r#"{"q":"\"\""}"#);
        let v2 = json::omit_empty_with_legacy_semantics(false);
        assert_eq!(
            String::from_utf8(json::marshal_with_options(&e, v2).unwrap()).unwrap(),
            r#"{"z":0,"q":"\"\""}"#
        );
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Generic<T> {
        #[json("value,omitempty")]
        value: T,
        #[json(embedded)]
        base: Base,
    }

    #[test]
    fn generic_structs_with_options() {
        let g = Generic {
            value: 3u8,
            base: Base::default(),
        };
        assert_eq!(text(&g), r#"{"value":3,"id":0}"#);
        assert_eq!(
            json::unmarshal::<Generic<u8>>(br#"{"value":3,"ID":2}"#)
                .unwrap()
                .base
                .ID,
            2
        );
        assert_eq!(
            text(&Generic {
                value: 0u8,
                base: Base::default()
            }),
            r#"{"id":0}"#
        );
    }

    #[test]
    fn dynamic_value_conversion_keeps_struct_semantics() {
        use json::{Deserialize as _, Serialize as _};
        let v = Options {
            a: 3,
            e: 0.5,
            ..Options::default()
        }
        .to_json()
        .unwrap();
        assert_eq!(
            v.get("renamed")
                .and_then(Value::as_number)
                .map(json::Number::as_str),
            Some("3")
        );
        assert_eq!(Options::from_json(&v).unwrap().a, 3);
        // `encode`/`decode` keep working on derived structs.
        let text = encode(&Options::default()).unwrap();
        assert_eq!(decode::<Options>(&text).unwrap(), Options::default());
    }
}
