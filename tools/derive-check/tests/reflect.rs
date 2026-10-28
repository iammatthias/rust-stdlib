//! `#[derive(Reflect)]`, `#[reflect_methods]` and `#[reflect_trait]` against
//! Go's `reflect` tests: field lookup through embedding (`fieldTests`),
//! `VisibleFields` (`fieldsTests`), `FieldByIndexErr`, method sets and calls,
//! recursive `DeepEqual` and the derive's attributes.
#![allow(
    non_snake_case,
    non_camel_case_types,
    dead_code,
    clippy::type_complexity
)]
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

use rust_stdlib::reflect::{self, Kind, Reflect, ReflectType, Type};
use rust_stdlib_derive::{reflect_methods, reflect_trait, Reflect};

fn panic_message<R>(f: impl FnOnce() -> R) -> String {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(_) => panic!("expected a panic"),
        Err(e) => {
            if let Some(v) = e.downcast_ref::<reflect::ValueError>() {
                v.error()
            } else if let Some(s) = e.downcast_ref::<String>() {
                s.clone()
            } else if let Some(s) = e.downcast_ref::<&str>() {
                s.to_string()
            } else {
                "?".into()
            }
        }
    }
}

fn ty<T: ReflectType>() -> Type {
    reflect::type_for::<T>()
}

// ---- the types of visiblefields_test.go ----

#[derive(Reflect, Default, Clone)]
pub struct SFG {
    pub F: isize,
    pub G: isize,
}
#[derive(Reflect, Default, Clone)]
pub struct SFG1 {
    #[reflect(embed)]
    pub SFG: SFG,
}
#[derive(Reflect, Default, Clone)]
pub struct SFG2 {
    #[reflect(embed)]
    pub SFG1: SFG1,
}
#[derive(Reflect, Default, Clone)]
pub struct SFGH {
    pub F: isize,
    pub G: isize,
    pub H: isize,
}
#[derive(Reflect, Default, Clone)]
pub struct SFGH1 {
    #[reflect(embed)]
    pub SFGH: SFGH,
}
#[derive(Reflect, Default, Clone)]
pub struct SFGH2 {
    #[reflect(embed)]
    pub SFGH1: SFGH1,
}
#[derive(Reflect, Default, Clone)]
pub struct SFGH3 {
    #[reflect(embed)]
    pub SFGH2: SFGH2,
}
#[derive(Reflect, Default, Clone)]
pub struct SF {
    pub F: isize,
}
#[derive(Reflect, Default, Clone)]
pub struct SF1 {
    #[reflect(embed)]
    pub SF: SF,
}
#[derive(Reflect, Default, Clone)]
pub struct SF2 {
    #[reflect(embed)]
    pub SF1: SF1,
}
#[derive(Reflect, Default, Clone)]
pub struct SG {
    pub G: isize,
}
#[derive(Reflect, Default, Clone)]
pub struct SG1 {
    #[reflect(embed)]
    pub SG: SG,
}
#[derive(Reflect, Default, Clone)]
pub struct sFG {
    pub F: isize,
    pub G: isize,
}
#[derive(Reflect, Default, Clone)]
pub struct RS1 {
    i: isize,
}
#[derive(Reflect, Default, Clone)]
pub struct RS2 {
    #[reflect(embed)]
    pub RS1: RS1,
}
#[derive(Reflect, Default, Clone)]
pub struct RS3 {
    #[reflect(embed)]
    pub RS2: RS2,
    #[reflect(embed)]
    pub RS1: RS1,
}
/// Go's `type M map[string]any`: embedding a non-struct adds no fields.
#[derive(Reflect, Default, Clone, Copy)]
pub enum M {
    #[default]
    One,
}
#[derive(Reflect, Default, Clone)]
pub struct Rec1 {
    #[reflect(embed)]
    pub Rec2: Option<Box<Rec2>>,
}
#[derive(Reflect, Default, Clone)]
pub struct Rec2 {
    pub F: String,
    #[reflect(embed)]
    pub Rec1: Option<Box<Rec1>>,
}

// Anonymous struct types of the table, spelled out.
#[derive(Reflect, Default, Clone)]
pub struct T_Simple {
    pub A: isize,
    pub B: String,
    pub C: bool,
}
#[derive(Reflect, Default, Clone)]
pub struct T_Inner {
    pub X: isize,
}
#[derive(Reflect, Default, Clone)]
pub struct T_NonEmbedded {
    pub A: T_Inner,
}
#[derive(Reflect, Default, Clone)]
pub struct T_EmbSFG {
    #[reflect(embed)]
    pub SFG: SFG,
}
#[derive(Reflect, Default, Clone)]
pub struct T_EmbsFG {
    #[reflect(embed)]
    sFG: sFG,
}
#[derive(Reflect, Default, Clone)]
pub struct T_Cancel {
    #[reflect(embed)]
    pub SFG: SFG,
    #[reflect(embed)]
    pub SF: SF,
}
#[derive(Reflect, Default, Clone)]
pub struct T_Depths {
    #[reflect(embed)]
    pub SFGH3: SFGH3,
    #[reflect(embed)]
    pub SG1: SG1,
    #[reflect(embed)]
    pub SFG2: SFG2,
    #[reflect(embed)]
    pub SF2: SF2,
    pub L: isize,
}
#[derive(Reflect, Default, Clone)]
pub struct T_EmbPtr {
    #[reflect(embed)]
    pub SF: Option<SF>,
}
#[derive(Reflect, Default, Clone)]
pub struct T_EmbM {
    #[reflect(embed)]
    pub M: M,
}

fn idx_names(t: &Type) -> Vec<(String, Vec<usize>)> {
    reflect::visible_fields(t)
        .into_iter()
        .map(|f| (f.name, f.index))
        .collect()
}

fn sfs(v: &[(&str, &[usize])]) -> Vec<(String, Vec<usize>)> {
    v.iter().map(|(n, i)| (n.to_string(), i.to_vec())).collect()
}

#[test]
fn visible_fields_table() {
    let cases: Vec<(&str, Type, Vec<(String, Vec<usize>)>)> = vec![
        (
            "SimpleStruct",
            ty::<T_Simple>(),
            sfs(&[("A", &[0]), ("B", &[1]), ("C", &[2])]),
        ),
        (
            "NonEmbeddedStructMember",
            ty::<T_NonEmbedded>(),
            sfs(&[("A", &[0])]),
        ),
        (
            "EmbeddedExportedStruct",
            ty::<T_EmbSFG>(),
            sfs(&[("SFG", &[0]), ("F", &[0, 0]), ("G", &[0, 1])]),
        ),
        (
            "EmbeddedUnexportedStruct",
            ty::<T_EmbsFG>(),
            sfs(&[("sFG", &[0]), ("F", &[0, 0]), ("G", &[0, 1])]),
        ),
        (
            "TwoEmbeddedStructsWithCancelingMembers",
            ty::<T_Cancel>(),
            sfs(&[("SFG", &[0]), ("G", &[0, 1]), ("SF", &[1])]),
        ),
        (
            "EmbeddedStructsWithSameFieldsAtDifferentDepths",
            ty::<T_Depths>(),
            sfs(&[
                ("SFGH3", &[0]),
                ("SFGH2", &[0, 0]),
                ("SFGH1", &[0, 0, 0]),
                ("SFGH", &[0, 0, 0, 0]),
                ("H", &[0, 0, 0, 0, 2]),
                ("SG1", &[1]),
                ("SG", &[1, 0]),
                ("G", &[1, 0, 0]),
                ("SFG2", &[2]),
                ("SFG1", &[2, 0]),
                ("SFG", &[2, 0, 0]),
                ("SF2", &[3]),
                ("SF1", &[3, 0]),
                ("SF", &[3, 0, 0]),
                ("L", &[4]),
            ]),
        ),
        (
            "EmbeddedPointerStruct",
            ty::<T_EmbPtr>(),
            sfs(&[("SF", &[0]), ("F", &[0, 0])]),
        ),
        ("EmbeddedNotAPointer", ty::<T_EmbM>(), sfs(&[("M", &[0])])),
        (
            "RecursiveEmbedding",
            ty::<Rec1>(),
            sfs(&[("Rec2", &[0]), ("F", &[0, 0]), ("Rec1", &[0, 1])]),
        ),
        (
            "RecursiveEmbedding2",
            ty::<Rec2>(),
            sfs(&[("F", &[0]), ("Rec1", &[1]), ("Rec2", &[1, 0])]),
        ),
        (
            "RecursiveEmbedding3",
            ty::<RS3>(),
            sfs(&[("RS2", &[0]), ("RS1", &[1]), ("i", &[1, 0])]),
        ),
    ];
    for (name, t, expect) in cases {
        let fields = reflect::visible_fields(&t);
        assert_eq!(fields.len(), expect.len(), "{name}");
        for (field, (ename, eindex)) in fields.iter().zip(&expect) {
            let got = t.field_by_index(&field.index);
            let want = t.field_by_index(eindex);
            assert_eq!(&got.name, ename, "{name}");
            assert_eq!(got.type_, want.type_, "{name}");
            assert_eq!(got.offset, want.offset, "{name}");
            assert_eq!(got.anonymous, want.anonymous, "{name}");
            // Accessible by the expected name.
            let by_name = t
                .field_by_name(ename)
                .unwrap_or_else(|| panic!("{name}: {ename}"));
            assert_eq!(&by_name.name, ename);
            assert_eq!(&by_name.index, eindex, "{name}: {ename}");
        }
        assert_eq!(idx_names(&t), expect, "{name}");
    }
}

#[test]
fn field_by_index_err() {
    #[derive(Reflect, Default, Clone)]
    struct A {
        pub S: String,
    }
    #[derive(Reflect, Default, Clone)]
    struct B {
        #[reflect(embed)]
        pub A: Option<A>,
    }
    let v = B::default().to_value();
    let err = v.field_by_index_err(&[0, 0]).unwrap_err();
    assert!(err.to_string().contains("embedded struct field A"), "{err}");
    assert!(panic_message(|| v.field_by_index(&[0, 0]))
        .contains("indirection through nil pointer to embedded struct"));
}

// ---- fieldTests ----

#[derive(Reflect, Default, Clone)]
pub struct D1 {
    d: isize,
}
#[derive(Reflect, Default, Clone)]
pub struct D2 {
    d: isize,
}
#[derive(Reflect, Default, Clone)]
pub struct S0 {
    pub A: isize,
    pub B: isize,
    pub C: isize,
    #[reflect(embed)]
    pub D1: D1,
    #[reflect(embed)]
    pub D2: D2,
}
#[derive(Reflect, Default, Clone)]
pub struct S1 {
    pub B: isize,
    #[reflect(embed)]
    pub S0: S0,
}
#[derive(Reflect, Default, Clone)]
pub struct S2 {
    pub A: isize,
    #[reflect(embed)]
    pub S1: Option<S1>,
}
#[derive(Reflect, Default, Clone)]
pub struct S1x {
    #[reflect(embed)]
    pub S1: S1,
}
#[derive(Reflect, Default, Clone)]
pub struct S1y {
    #[reflect(embed)]
    pub S1: S1,
}
#[derive(Reflect, Default, Clone)]
pub struct S3 {
    #[reflect(embed)]
    pub S1x: S1x,
    #[reflect(embed)]
    pub S2: S2,
    pub D: isize,
    pub E: isize,
    #[reflect(embed)]
    pub S1y: Option<S1y>,
}
#[derive(Reflect, Default, Clone)]
pub struct S4 {
    #[reflect(embed)]
    pub S4: Option<Box<S4>>,
    pub A: isize,
}
#[derive(Reflect, Default, Clone)]
pub struct S5 {
    #[reflect(embed)]
    pub S6: S6,
    #[reflect(embed)]
    pub S7: S7,
    #[reflect(embed)]
    pub S8: S8,
}
#[derive(Reflect, Default, Clone)]
pub struct S6 {
    pub X: isize,
}
#[derive(Reflect, Default, Clone)]
pub struct S7 {
    pub X: isize,
}
#[derive(Reflect, Default, Clone)]
pub struct S8 {
    #[reflect(embed)]
    pub S9: S9,
}
#[derive(Reflect, Default, Clone)]
pub struct S9 {
    pub X: isize,
    pub Y: isize,
}
#[derive(Reflect, Default, Clone)]
pub struct S10 {
    #[reflect(embed)]
    pub S11: S11,
    #[reflect(embed)]
    pub S12: S12,
    #[reflect(embed)]
    pub S13: S13,
}
#[derive(Reflect, Default, Clone)]
pub struct S11 {
    #[reflect(embed)]
    pub S6: S6,
}
#[derive(Reflect, Default, Clone)]
pub struct S12 {
    #[reflect(embed)]
    pub S6: S6,
}
#[derive(Reflect, Default, Clone)]
pub struct S13 {
    #[reflect(embed)]
    pub S8: S8,
}
#[derive(Reflect, Default, Clone)]
pub struct S14 {
    #[reflect(embed)]
    pub S15: S15,
    #[reflect(embed)]
    pub S16: S16,
}
#[derive(Reflect, Default, Clone)]
pub struct S15 {
    #[reflect(embed)]
    pub S11: S11,
}
#[derive(Reflect, Default, Clone)]
pub struct S16 {
    #[reflect(embed)]
    pub S11: S11,
}

#[test]
fn field_by_name_and_index_table() {
    // (type, name, index, value) as in fieldTests; value 0 means unchecked.
    let ty_s0 = ty::<S0>();
    let none: &[usize] = &[];
    let cases: Vec<(Type, &str, &[usize])> = vec![
        (reflect::struct_of(&[]), "", none),
        (reflect::struct_of(&[]), "Foo", none),
        (ty_s0.clone(), "A", &[0]),
        (ty_s0.clone(), "D", none),
        (ty::<S1>(), "A", &[1, 0]),
        (ty::<S1>(), "B", &[0]),
        (ty::<S1>(), "S0", &[1]),
        (ty::<S1>(), "C", &[1, 2]),
        (ty::<S2>(), "A", &[0]),
        (ty::<S2>(), "S1", &[1]),
        (ty::<S2>(), "B", &[1, 0]),
        (ty::<S2>(), "C", &[1, 1, 2]),
        (ty::<S2>(), "D", none),
        (ty::<S3>(), "S1", none),
        (ty::<S3>(), "A", &[1, 0]),
        (ty::<S3>(), "B", none),
        (ty::<S3>(), "D", &[2]),
        (ty::<S3>(), "E", &[3]),
        (ty::<S4>(), "A", &[1]),
        (ty::<S4>(), "B", none),
        (ty::<S5>(), "X", none),
        (ty::<S5>(), "Y", &[2, 0, 1]),
        (ty::<S10>(), "X", none),
        (ty::<S10>(), "Y", &[2, 0, 0, 1]),
        (ty::<S14>(), "X", none),
    ];
    for (t, name, index) in cases {
        let got = t.field_by_name(name);
        match (got, index.is_empty()) {
            (Some(f), true) => panic!("{t}.{name} found as {:?}", f.index),
            (None, false) => panic!("{t}.{name} not found"),
            (Some(f), false) => assert_eq!(f.index, index, "{t}.{name}"),
            (None, true) => {}
        }
        // FieldByIndex round trip.
        if !index.is_empty() {
            let f = t.field_by_index(index);
            if name != "D" {
                assert_eq!(f.name, name, "{t}{index:?}");
            }
        }
    }
    // Values: S1{S0{A: 'a'}}.A, S2{S1: &S1{S0: S0{C: 'c'}}}.C.
    let mut s1 = S1::default();
    s1.S0.A = 97;
    assert_eq!(s1.to_value().field_by_index(&[1, 0]).int(), 97);
    assert_eq!(s1.to_value().field_by_name("A").int(), 97);
    let s2 = S2 {
        S1: Some(S1 {
            B: 0,
            S0: S0 {
                C: 99,
                ..S0::default()
            },
        }),
        ..S2::default()
    };
    assert_eq!(s2.to_value().field_by_name("C").int(), 99);
    assert_eq!(s2.to_value().field_by_index(&[1, 1, 2]).int(), 99);
    // S3.A resolves through S2 (depth 1) and S1x (depth 3): S2 wins.
    let mut s3 = S3::default();
    s3.S2.A = 97;
    assert_eq!(s3.to_value().field_by_name("A").int(), 97);
    // Anonymous field named after an unexported primitive type.
    assert!(!s2.to_value().field_by_name("Nope").is_valid());
}

// ---- recursive DeepEqual ----

#[derive(Reflect, Default, Clone)]
pub struct Recursive {
    pub x: isize,
    pub r: Option<Box<Recursive>>,
}

#[test]
fn deep_equal_recursive_struct() {
    let make = || {
        let t = ty::<Recursive>();
        let p = reflect::new(&t);
        p.elem().field(0).set_int(12);
        p.elem().field(1).set(&p);
        p
    };
    let (a, b) = (make(), make());
    assert!(reflect::deep_equal_values(&a, &b));
    b.elem().field(0).set_int(13);
    assert!(!reflect::deep_equal_values(&a, &b));
    // Walking the cycle converges: pointer equals itself.
    assert!(reflect::deep_equal_values(&a, &a));
}

#[derive(Reflect, Default, Clone)]
pub struct Complex_ {
    pub a: isize,
    pub b: [Option<Box<Complex_>>; 3],
    pub c: Option<String>,
    pub d: BTreeMap<String, String>,
}

#[test]
fn deep_equal_complex_struct() {
    let build = |s1: &str, s2: &str| {
        let t = ty::<Complex_>();
        let a = reflect::new(&t);
        let b = reflect::new(&t);
        let m = reflect::make_map(&ty::<BTreeMap<String, String>>());
        let s = |x: &str| Some(x.to_string()).to_value();
        for (p, other, str_) in [(&a, &b, s(s1)), (&b, &a, s(s2))] {
            let e = p.elem();
            e.field(0).set_int(5);
            let arr = e.field(1);
            let pair = if std::ptr::eq(p, &a) {
                [p, other, p]
            } else {
                [other, p, p]
            };
            for (i, x) in pair.iter().enumerate() {
                arr.index(i).set(x);
            }
            e.field(2).set(&str_);
            e.field(3).set(&m);
        }
        (a, b)
    };
    let (a, b) = build("hello", "hello");
    assert!(reflect::deep_equal_values(&a, &b));
    let (a, b) = build("hello", "helloo");
    assert!(!reflect::deep_equal_values(&a, &b));
}

#[derive(Reflect, Default, Clone)]
pub struct UnexpT {
    m: BTreeMap<isize, isize>,
}

#[test]
fn deep_equal_unexported_map() {
    let x1 = UnexpT {
        m: BTreeMap::from([(1, 2)]),
    };
    let x2 = x1.clone();
    assert!(reflect::deep_equal(&x1, &x2));
    let y1 = UnexpT {
        m: BTreeMap::from([(2, 3)]),
    };
    assert!(!reflect::deep_equal(&x1, &y1));
}

// ---- derive attributes ----

#[derive(Reflect, Default, Clone, PartialEq, Debug)]
#[reflect(pkg = "example.com/pkg/sub")]
pub struct Tagged {
    #[reflect("json:\"id,omitempty\" db:\"pk\"")]
    pub id: u64,
    #[reflect(name = "Display")]
    pub display_name: String,
    private: bool,
    #[reflect(export)]
    forced: u8,
    #[reflect(skip)]
    skipped: Vec<u8>,
    pub(crate) crate_only: i8,
}

#[test]
fn derive_attributes() {
    let t = ty::<Tagged>();
    assert_eq!(t.to_string(), "sub.Tagged");
    assert_eq!(t.name(), "Tagged");
    assert_eq!(t.pkg_path(), "example.com/pkg/sub");
    assert_eq!(t.num_field(), 5);
    let f = t.field(0);
    assert_eq!(f.tag.get("json"), "id,omitempty");
    assert_eq!(f.tag.get("db"), "pk");
    assert_eq!(f.tag.lookup("nope"), None);
    assert!(f.is_exported());
    assert_eq!(t.field(1).name, "Display");
    let private = t.field(2);
    assert_eq!(private.name, "private");
    assert!(!private.is_exported());
    assert_eq!(private.pkg_path, "example.com/pkg/sub");
    assert!(t.field(3).is_exported(), "#[reflect(export)] forces export");
    assert!(!t.field(4).is_exported(), "pub(crate) is not exported");
    assert!(t.field_by_name("skipped").is_none());
    let v = Tagged {
        id: 7,
        display_name: "x".into(),
        private: true,
        forced: 2,
        skipped: vec![1],
        crate_only: -3,
    }
    .to_value();
    assert_eq!(v.field(0).uint(), 7);
    assert!(v.field(2).bool());
    assert!(!v.field(2).can_interface());
    assert!(v.field(3).can_interface());
    // Go layout, not Rust layout.
    assert_eq!(t.size(), 32);
    assert_eq!(t.field(2).offset, 24);
    // Round trip; the skipped field takes its default.
    let back = Tagged::from_value(&v).unwrap();
    assert_eq!(back.id, 7);
    assert!(back.skipped.is_empty());
    assert_eq!(back.crate_only, -3);
}

#[derive(Reflect, Default, Clone, PartialEq, Debug)]
#[reflect(pkg = "main")]
pub struct Pair<A, B> {
    pub First: A,
    pub Second: B,
}

#[derive(Reflect, Default, Clone, PartialEq, Debug)]
#[reflect(pkg = "main")]
pub struct Tuple2(pub i32, pub String);

#[derive(Reflect, Default, Clone, PartialEq, Debug)]
#[reflect(pkg = "main")]
pub struct Unit;

#[derive(Reflect, Default, Clone, Copy, PartialEq, Debug)]
#[reflect(pkg = "main", name = "Colour")]
pub enum Color {
    #[default]
    Red,
    Green,
    Blue,
}

#[test]
fn derive_shapes() {
    let t = ty::<Pair<isize, String>>();
    assert_eq!(t.to_string(), "main.Pair[int,string]");
    assert_eq!(t.name(), "Pair[int,string]");
    assert_ne!(t, ty::<Pair<String, isize>>());
    let nested = ty::<Pair<Pair<u8, bool>, Vec<Tuple2>>>();
    assert_eq!(
        nested.to_string(),
        "main.Pair[main.Pair[uint8,bool],[]main.Tuple2]"
    );
    let p = Pair {
        First: 1isize,
        Second: "s".to_string(),
    };
    assert_eq!(Pair::<isize, String>::from_value(&p.to_value()).unwrap(), p);
    // Tuple structs get fields F0, F1; unit structs are empty.
    let t = ty::<Tuple2>();
    assert_eq!(t.to_string(), "main.Tuple2");
    assert_eq!(t.field(1).name, "F1");
    let v = Tuple2(3, "x".into());
    assert_eq!(Tuple2::from_value(&v.to_value()).unwrap(), v);
    assert_eq!(ty::<Unit>().num_field(), 0);
    assert_eq!(ty::<Unit>().size(), 0);
    assert_eq!(Unit::from_value(&Unit.to_value()).unwrap(), Unit);
    // Unit-only enums are named ints.
    let t = ty::<Color>();
    assert_eq!(t.to_string(), "main.Colour");
    assert_eq!(t.kind(), Kind::Int);
    assert_eq!(Color::Blue.to_value().int(), 2);
    assert_eq!(
        Color::from_value(&1isize.to_value().convert(&t)).unwrap(),
        Color::Green
    );
    assert!(Color::from_value(&7isize.to_value().convert(&t)).is_err());
    assert!(Color::from_value(&"x".to_string().to_value()).is_err());
    // Conversion between a named int and its underlying type.
    assert!(t.convertible_to(&ty::<isize>()));
    assert!(!t.assignable_to(&ty::<isize>()));
    assert_eq!(Color::Green.to_value().convert(&ty::<isize>()).int(), 1);
}

#[test]
fn from_value_errors() {
    let v = 5isize.to_value();
    assert!(Tagged::from_value(&v).is_err());
    assert!(Pair::<u8, u8>::from_value(&Unit.to_value()).is_err());
    let e = Tagged::from_value(&v).unwrap_err();
    assert!(
        e.to_string()
            .contains("cannot use a value of type int as a struct"),
        "{e}"
    );
}

// ---- methods ----

#[derive(Reflect, Default, Clone, PartialEq, Debug)]
#[reflect(pkg = "main")]
pub struct Counter {
    pub N: i64,
    step: i64,
}

#[reflect_methods]
impl Counter {
    pub fn Inc(&mut self) {
        self.N += self.step;
    }
    pub fn Add(&mut self, k: i64) -> i64 {
        self.N += k;
        self.N
    }
    pub fn Get(&self) -> i64 {
        self.N
    }
    pub fn Name(&self, prefix: &str) -> String {
        format!("{prefix}{}", self.N)
    }
    pub fn DivMod(&self, d: i64) -> (i64, i64) {
        (self.N / d, self.N % d)
    }
    pub fn Both(&self, names: Vec<String>, flag: bool) -> (String, bool) {
        (names.join(","), !flag)
    }
    fn hidden(&self) -> i64 {
        1
    }
    #[reflect(skip)]
    pub fn Skipped(&self) {}
    pub fn generic<T>(&self, _x: T) {}
    pub fn by_value(self) -> i64 {
        self.N
    }
    pub fn new() -> Counter {
        Counter::default()
    }
}

#[test]
fn methods_and_method_sets() {
    let t = ty::<Counter>();
    let pt = reflect::pointer_to(&t);
    // Value method set: &self methods only; pointer set adds &mut self.
    let names = |t: &Type| t.methods().map(|m| m.name).collect::<Vec<_>>();
    assert_eq!(names(&t), ["Both", "DivMod", "Get", "Name"]);
    assert_eq!(names(&pt), ["Add", "Both", "DivMod", "Get", "Inc", "Name"]);
    assert_eq!(t.num_method(), 4);
    assert_eq!(pt.num_method(), 6);
    let m = t.method_by_name("Name").unwrap();
    assert_eq!(m.index, 3);
    assert_eq!(m.type_.to_string(), "func(main.Counter, string) string");
    assert!(m.is_exported());
    assert!(t.method_by_name("hidden").is_none());
    assert!(t.method_by_name("Skipped").is_none());
    assert!(t.method_by_name("Inc").is_none());
    assert_eq!(
        pt.method_by_name("Inc").unwrap().type_.to_string(),
        "func(*main.Counter)"
    );
    assert_eq!(
        pt.method_by_name("DivMod").unwrap().type_.to_string(),
        "func(*main.Counter, int64) (int64, int64)"
    );
    // Method.Func takes the receiver first.
    let out = m.func.call(&[
        Counter { N: 41, step: 1 }.to_value(),
        "n=".to_string().to_value(),
    ]);
    assert_eq!(out[0].text(), "n=41");
    assert!(panic_message(|| t.method(9)).contains("Method index out of range"));
}

#[test]
fn value_methods_call_and_write_back() {
    let c = Counter { N: 10, step: 5 };
    let v = c.to_value();
    assert_eq!(v.num_method(), 4);
    assert_eq!(v.method_by_name("Get").call(&[])[0].int(), 10);
    assert_eq!(
        v.method_by_name("Name").call(&["#".to_string().to_value()])[0].text(),
        "#10"
    );
    let dm = v.method_by_name("DivMod").call(&[3i64.to_value()]);
    assert_eq!((dm[0].int(), dm[1].int()), (3, 1));
    let both = v.method_by_name("Both").call(&[
        vec!["a".to_string(), "b".to_string()].to_value(),
        true.to_value(),
    ]);
    assert_eq!(both[0].text(), "a,b");
    assert!(!both[1].bool());
    assert!(!v.method_by_name("Inc").is_valid());
    assert_eq!(
        v.method(0).type_().to_string(),
        "func([]string, bool) (string, bool)"
    );
    // Pointer receivers mutate the pointee.
    let p = reflect::new(&ty::<Counter>());
    p.elem().field(0).set_int(1);
    p.method_by_name("Add").call(&[4i64.to_value()]);
    assert_eq!(p.elem().field(0).int(), 5);
    let r = p.method_by_name("Add").call(&[1i64.to_value()]);
    assert_eq!(r[0].int(), 6);
    // The unexported field was copied through the receiver round trip.
    let mut copy = Counter { N: 0, step: 7 };
    reflect::edit(&mut copy, |ptr| {
        ptr.method_by_name("Inc").call(&[]);
        ptr.method_by_name("Inc").call(&[]);
    })
    .unwrap();
    assert_eq!(copy.N, 14);
    assert_eq!(copy.step, 7);
    // Argument checks.
    let get = v.method_by_name("Name");
    assert_eq!(
        panic_message(|| get.call(&[])),
        "reflect: Call with too few input arguments"
    );
    assert_eq!(
        panic_message(|| get.call(&[1i64.to_value()])),
        "reflect: Call using int64 as type string"
    );
    // Methods of a method value set.
    let all: Vec<String> = v
        .methods()
        .map(|(m, f)| format!("{}:{}", m.name, f.kind()))
        .collect();
    assert_eq!(all[0], "Both:func");
    assert_eq!(
        panic_message(|| v.method(10)),
        "reflect: Method index out of range"
    );
    assert_eq!(1i64.to_value().num_method(), 0);
}

#[reflect_trait(pkg = "main")]
pub trait Getter {
    fn Get(&self) -> i64;
}

#[reflect_trait(pkg = "main")]
pub trait Adder {
    fn Add(&mut self, k: i64) -> i64;
}

#[reflect_trait(pkg = "main")]
pub trait Namer {
    fn Name(&self, prefix: &str) -> String;
    fn Get(&self) -> i64;
}

#[reflect_trait(pkg = "main")]
pub trait Wrong {
    fn Get(&self) -> i32;
}

#[test]
fn implements_and_interfaces() {
    let c = ty::<Counter>();
    let pc = reflect::pointer_to(&c);
    let getter = reflect::type_for::<dyn Getter>();
    let adder = reflect::type_for::<dyn Adder>();
    let namer = reflect::type_for::<dyn Namer>();
    let wrong = reflect::type_for::<dyn Wrong>();
    assert_eq!(getter.to_string(), "main.Getter");
    assert_eq!(getter.kind(), Kind::Interface);
    assert_eq!(getter.num_method(), 1);
    assert_eq!(getter.method(0).type_.to_string(), "func() int64");
    assert!(c.implements(&getter));
    assert!(!c.implements(&adder));
    assert!(pc.implements(&adder));
    assert!(pc.implements(&getter));
    assert!(c.implements(&namer));
    assert!(!c.implements(&wrong));
    assert!(c.assignable_to(&getter));
    assert!(!c.assignable_to(&adder));
    assert!(c.convertible_to(&getter));
    assert!(namer.implements(&getter));
    assert!(!getter.implements(&namer));
    // Assigning to an interface-typed variable and calling through it.
    let slot = reflect::new(&getter).elem();
    slot.set(&Counter { N: 3, step: 0 }.to_value());
    assert_eq!(slot.kind(), Kind::Interface);
    assert_eq!(slot.num_method(), 1);
    assert_eq!(slot.method_by_name("Get").call(&[])[0].int(), 3);
    assert_eq!(slot.elem().type_(), c);
    assert!(
        panic_message(|| slot.method_by_name("Get").call(&[1i64.to_value()]))
            .contains("too many input arguments")
    );
    // A nil interface has no callable methods.
    let nil = reflect::zero(&getter);
    assert!(panic_message(|| nil.method(0)).contains("Method on nil interface value"));
    let wslot = reflect::new(&wrong).elem();
    assert!(panic_message(|| wslot.set(&Counter::default().to_value()))
        .contains("not assignable to type main.Wrong"));
    // Interface-to-interface conversion.
    let nslot = reflect::new(&namer).elem();
    nslot.set(&Counter { N: 9, step: 0 }.to_value());
    let as_getter = nslot.convert(&getter);
    assert_eq!(as_getter.type_(), getter);
    assert_eq!(as_getter.method_by_name("Get").call(&[])[0].int(), 9);
    // Interface method sets are sorted by name.
    assert_eq!(namer.method(0).name, "Get");
    assert_eq!(namer.method(1).name, "Name");
}

// ---- promoted methods and shadowing ----

#[derive(Reflect, Default, Clone)]
#[reflect(pkg = "main")]
pub struct Animal {
    pub Legs: i64,
}

#[reflect_methods]
impl Animal {
    pub fn Speak(&self) -> String {
        "...".into()
    }
    pub fn Hurt(&mut self) {
        self.Legs -= 1;
    }
}

#[derive(Reflect, Default, Clone)]
#[reflect(pkg = "main")]
pub struct Dog {
    #[reflect(embed)]
    pub Animal: Animal,
    pub Name: String,
}

#[reflect_methods]
impl Dog {
    pub fn Speak(&self) -> String {
        format!("{} says woof", self.Name)
    }
}

#[derive(Reflect, Default, Clone)]
#[reflect(pkg = "main")]
pub struct Puppy {
    #[reflect(embed)]
    pub Dog: Option<Dog>,
}

#[test]
fn promoted_methods() {
    let dog = reflect::pointer_to(&ty::<Dog>());
    let d = ty::<Dog>();
    // Dog.Speak shadows Animal.Speak; Hurt is promoted to *Dog only.
    assert_eq!(d.methods().map(|m| m.name).collect::<Vec<_>>(), ["Speak"]);
    assert_eq!(
        dog.methods().map(|m| m.name).collect::<Vec<_>>(),
        ["Hurt", "Speak"]
    );
    let p = reflect::new(&ty::<Dog>());
    p.elem().field(1).set_string("Rex");
    p.elem().field(0).field(0).set_int(4);
    assert_eq!(
        p.method_by_name("Speak").call(&[])[0].text(),
        "Rex says woof"
    );
    p.method_by_name("Hurt").call(&[]);
    assert_eq!(p.elem().field(0).field(0).int(), 3);
    // Puppy embeds *Dog: its value method set includes pointer methods.
    let pup = ty::<Puppy>();
    assert_eq!(
        pup.methods().map(|m| m.name).collect::<Vec<_>>(),
        ["Hurt", "Speak"]
    );
    let v = reflect::new(&pup).elem();
    assert!(panic_message(|| v.method_by_name("Speak").call(&[]))
        .contains("indirection through nil pointer to embedded struct"));
    v.field(0).set(&reflect::new(&ty::<Dog>()));
    v.field(0).elem().field(1).set_string("Bit");
    assert_eq!(
        v.method_by_name("Speak").call(&[])[0].text(),
        "Bit says woof"
    );
    v.method_by_name("Hurt").call(&[]);
    assert_eq!(v.field(0).elem().field(0).field(0).int(), -1);
    // Method values of Type.Method take the receiver.
    let speak = pup.method_by_name("Speak").unwrap();
    assert_eq!(speak.type_.to_string(), "func(main.Puppy) string");
    assert_eq!(
        speak.func.call(std::slice::from_ref(&v))[0].text(),
        "Bit says woof"
    );
}
