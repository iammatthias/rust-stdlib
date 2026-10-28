//! Tests for `rust_stdlib::reflect`, ported from the tables and assertions of
//! Go's `reflect/all_test.go`, `visiblefields_test.go` and `iter_test.go` where
//! they can be expressed without Go's compiler-built types. Tests that need
//! `#[derive(Reflect)]` (embedding, methods, recursive types) are in
//! `tools/derive-check/tests/reflect.rs`.
#![allow(clippy::cloned_ref_to_slice_refs)]
use std::collections::{BTreeMap, HashMap};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Once;

use rust_stdlib::reflect::{
    self, ChanDir, Kind, Reflect, ReflectType, SelectCase, SelectDir, StructField, StructTag, Type,
    Value,
};
use rust_stdlib::strconv::Complex;

thread_local! {
    static SILENT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Silences the panic hook while a test deliberately provokes a panic.
fn quiet() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !SILENT.with(|s| s.get()) {
                prev(info);
            }
        }));
    });
}

/// Runs `f`, which must panic, and returns the panic message (a `ValueError`'s
/// text for kind errors).
fn panic_message<R>(f: impl FnOnce() -> R) -> String {
    quiet();
    SILENT.with(|s| s.set(true));
    let r = catch_unwind(AssertUnwindSafe(f));
    SILENT.with(|s| s.set(false));
    match r {
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

fn should_panic<R>(what: &str, f: impl FnOnce() -> R) {
    quiet();
    SILENT.with(|s| s.set(true));
    let r = catch_unwind(AssertUnwindSafe(f));
    SILENT.with(|s| s.set(false));
    assert!(r.is_err(), "{what}: expected a panic");
}

fn ty<T: ReflectType>() -> Type {
    reflect::type_for::<T>()
}

fn basic(k: Kind) -> Type {
    Type::basic(k)
}

fn any() -> Type {
    Type::any_type()
}

/// A value of interface type `any` holding `x`.
fn boxed<T: Reflect>(x: T) -> Value {
    x.to_value().to_value()
}

fn ints(xs: &[isize]) -> Value {
    xs.to_vec().to_value()
}

fn sf(name: &str, t: Type) -> StructField {
    StructField::new(name, t)
}

// ---------------------------------------------------------------------------
// StructTag (tagGetTests and Lookup).

#[test]
fn tag_get() {
    let tests = [
        (r#"protobuf:"PB(1,2)""#, "protobuf", "PB(1,2)"),
        (r#"protobuf:"PB(1,2)""#, "foo", ""),
        (r#"protobuf:"PB(1,2)""#, "rotobuf", ""),
        (r#"protobuf:"PB(1,2)" json:"name""#, "json", "name"),
        (r#"protobuf:"PB(1,2)" json:"name""#, "protobuf", "PB(1,2)"),
        (
            r#"k0:"values contain spaces" k1:"and\ttabs""#,
            "k0",
            "values contain spaces",
        ),
        (
            r#"k0:"values contain spaces" k1:"and\ttabs""#,
            "k1",
            "and\ttabs",
        ),
    ];
    for (tag, key, want) in tests {
        assert_eq!(StructTag::new(tag).get(key), want, "{tag} {key}");
    }
}

#[test]
fn tag_lookup() {
    let tag = StructTag::new(r#"a:"" b:"x y" c:"\u00e9\"" d:"unterminated"#);
    assert_eq!(tag.lookup("a"), Some(String::new()));
    assert_eq!(tag.lookup("b"), Some("x y".into()));
    assert_eq!(tag.lookup("c"), Some("é\"".into()));
    assert_eq!(tag.lookup("d"), None);
    assert_eq!(tag.lookup("zz"), None);
    // Malformed: no colon, bad quote, control byte.
    for bad in ["a", "a:b", "a: \"b\"", ":\"b\"", "a\x7f:\"b\""] {
        assert_eq!(StructTag::new(bad).lookup("a"), None, "{bad:?}");
    }
    // A bad escape in the wanted pair gives up.
    assert_eq!(StructTag::new(r#"a:"\q" b:"c""#).lookup("a"), None);
    assert_eq!(
        StructTag::new(r#"a:"\q" b:"c""#).lookup("b"),
        Some("c".into())
    );
}

// ---------------------------------------------------------------------------
// Kinds, directions and type strings.

#[test]
fn kind_strings() {
    let want = [
        (Kind::Invalid, "invalid"),
        (Kind::Bool, "bool"),
        (Kind::Int, "int"),
        (Kind::Uintptr, "uintptr"),
        (Kind::Complex128, "complex128"),
        (Kind::Array, "array"),
        (Kind::Chan, "chan"),
        (Kind::Func, "func"),
        (Kind::Interface, "interface"),
        (Kind::Map, "map"),
        (Kind::Pointer, "ptr"),
        (Kind::Slice, "slice"),
        (Kind::String, "string"),
        (Kind::Struct, "struct"),
        (Kind::UnsafePointer, "unsafe.Pointer"),
    ];
    for (k, s) in want {
        assert_eq!(k.to_string(), s);
        assert_eq!(k.to_string(), s);
    }
    assert_eq!(Kind::Ptr, Kind::Pointer);
    assert_eq!(Kind::from_u8(24), Some(Kind::String));
    assert_eq!(Kind::from_u8(27), None);
    assert_eq!(ChanDir::Recv.to_string(), "<-chan");
    assert_eq!(ChanDir::Send.to_string(), "chan<-");
    assert_eq!(ChanDir::Both.to_string(), "chan");
    assert_eq!(ChanDir::Both as i32, 3);
}

#[test]
fn type_strings_and_kinds() {
    let tests: Vec<(Type, &str, Kind)> = vec![
        (ty::<bool>(), "bool", Kind::Bool),
        (ty::<isize>(), "int", Kind::Int),
        (ty::<u8>(), "uint8", Kind::Uint8),
        (ty::<usize>(), "uint", Kind::Uint),
        (ty::<f32>(), "float32", Kind::Float32),
        (ty::<Complex>(), "complex128", Kind::Complex128),
        (ty::<String>(), "string", Kind::String),
        (ty::<Vec<isize>>(), "[]int", Kind::Slice),
        (ty::<[u8; 4]>(), "[4]uint8", Kind::Array),
        (ty::<Option<String>>(), "*string", Kind::Pointer),
        (ty::<Box<i64>>(), "int64", Kind::Int64),
        (ty::<Option<Vec<Option<i8>>>>(), "*[]*int8", Kind::Pointer),
        (
            ty::<BTreeMap<String, Vec<u8>>>(),
            "map[string][]uint8",
            Kind::Map,
        ),
        (
            ty::<HashMap<i32, [bool; 2]>>(),
            "map[int32][2]bool",
            Kind::Map,
        ),
        (
            ty::<(i32, String)>(),
            "struct { F0 int32; F1 string }",
            Kind::Struct,
        ),
        (ty::<char>(), "int32", Kind::Int32),
        (Value::reflect_type(), "interface {}", Kind::Interface),
        (Type::error_type(), "error", Kind::Interface),
        (
            reflect::chan_of(ChanDir::Both, &ty::<isize>()),
            "chan int",
            Kind::Chan,
        ),
        (
            reflect::chan_of(ChanDir::Recv, &ty::<isize>()),
            "<-chan int",
            Kind::Chan,
        ),
        (
            reflect::chan_of(ChanDir::Send, &ty::<String>()),
            "chan<- string",
            Kind::Chan,
        ),
        (
            reflect::chan_of(
                ChanDir::Both,
                &reflect::chan_of(ChanDir::Recv, &ty::<isize>()),
            ),
            "chan (<-chan int)",
            Kind::Chan,
        ),
        (
            reflect::chan_of(
                ChanDir::Both,
                &reflect::chan_of(ChanDir::Both, &ty::<isize>()),
            ),
            "chan chan int",
            Kind::Chan,
        ),
    ];
    for (t, s, k) in tests {
        assert_eq!(t.to_string(), s);
        assert_eq!(t.to_string(), s);
        assert_eq!(t.kind(), k, "{s}");
    }
}

#[test]
fn type_identity_and_interning() {
    assert_eq!(ty::<Vec<isize>>(), reflect::slice_of(&ty::<isize>()));
    assert_eq!(
        reflect::pointer_to(&ty::<isize>()),
        reflect::ptr_to(&ty::<isize>())
    );
    assert_eq!(ty::<[u8; 3]>(), reflect::array_of(3, &ty::<u8>()));
    assert_ne!(ty::<[u8; 3]>(), reflect::array_of(4, &ty::<u8>()));
    assert_eq!(
        ty::<BTreeMap<String, isize>>(),
        reflect::map_of(&ty::<String>(), &ty::<isize>())
    );
    assert_eq!(
        ty::<HashMap<String, isize>>(),
        ty::<BTreeMap<String, isize>>()
    );
    let f1 = reflect::func_of(&[ty::<isize>()], &[ty::<String>()], false);
    let f2 = reflect::func_of(&[ty::<isize>()], &[ty::<String>()], false);
    assert_eq!(f1, f2);
    assert_ne!(
        f1,
        reflect::func_of(&[ty::<isize>()], &[ty::<String>()], false).elem_or(&f2)
    );
    let s1 = reflect::struct_of(&[sf("A", ty::<isize>()), sf("B", ty::<String>())]);
    let s2 = reflect::struct_of(&[sf("A", ty::<isize>()), sf("B", ty::<String>())]);
    assert_eq!(s1, s2);
    let s3 = reflect::struct_of(&[
        sf("A", ty::<isize>()).with_tag("x"),
        sf("B", ty::<String>()),
    ]);
    assert_ne!(s1, s3);
    // Types are hashable.
    let mut m = HashMap::new();
    m.insert(s1.clone(), 1);
    assert_eq!(m.get(&s2), Some(&1));
    assert_eq!(m.get(&s3), None);
}

trait ElemOr {
    fn elem_or(&self, other: &Type) -> Type;
}

impl ElemOr for Type {
    fn elem_or(&self, other: &Type) -> Type {
        // A different function type to compare against.
        let _ = other;
        reflect::func_of(&[ty::<isize>(), ty::<isize>()], &[], false)
    }
}

#[test]
fn func_types() {
    let cases: Vec<(Vec<Type>, Vec<Type>, bool, &str)> = vec![
        (vec![], vec![], false, "func()"),
        (vec![ty::<isize>()], vec![], false, "func(int)"),
        (vec![], vec![ty::<isize>()], false, "func() int"),
        (
            vec![ty::<isize>(), ty::<String>()],
            vec![ty::<bool>(), Type::error_type()],
            false,
            "func(int, string) (bool, error)",
        ),
        (
            vec![ty::<String>(), ty::<Vec<isize>>()],
            vec![],
            true,
            "func(string, ...int)",
        ),
    ];
    for (ins, outs, variadic, s) in cases {
        let t = reflect::func_of(&ins, &outs, variadic);
        assert_eq!(t.to_string(), s);
        assert_eq!(t.kind(), Kind::Func);
        assert_eq!(t.num_in(), ins.len());
        assert_eq!(t.num_out(), outs.len());
        assert_eq!(t.is_variadic(), variadic);
        for (i, x) in ins.iter().enumerate() {
            assert_eq!(&t.in_(i), x);
        }
        assert_eq!(t.ins().collect::<Vec<_>>(), ins);
        assert_eq!(t.outs().collect::<Vec<_>>(), outs);
    }
    assert!(
        panic_message(|| reflect::func_of(&[ty::<isize>()], &[], true))
            .contains("last arg of variadic func must be slice")
    );
    assert!(panic_message(|| reflect::func_of(&[], &[], true))
        .contains("last arg of variadic func must be slice"));
    assert!(panic_message(|| ty::<isize>().num_in()).contains("NumIn of non-func type int"));
}

#[test]
fn type_accessors_panic_like_go() {
    assert_eq!(
        panic_message(|| ty::<isize>().elem()),
        "reflect: Elem of invalid type int"
    );
    assert_eq!(
        panic_message(|| ty::<isize>().key()),
        "reflect: Key of non-map type int"
    );
    assert_eq!(
        panic_message(|| ty::<isize>().len()),
        "reflect: Len of non-array type int"
    );
    assert_eq!(
        panic_message(|| ty::<isize>().num_field()),
        "reflect: NumField of non-struct type int"
    );
    assert_eq!(
        panic_message(|| ty::<isize>().chan_dir()),
        "reflect: ChanDir of non-chan type int"
    );
    assert_eq!(
        panic_message(|| ty::<String>().bits()),
        "reflect: Bits of non-arithmetic Type string"
    );
    assert_eq!(
        panic_message(|| reflect::struct_of(&[sf("A", ty::<isize>())]).field(3)),
        "reflect: Field index out of bounds"
    );
    assert_eq!(ty::<i16>().bits(), 16);
    assert_eq!(ty::<Complex>().bits(), 128);
    assert_eq!(ty::<usize>().bits(), 64);
}

#[test]
fn array_slice_map_chan_of() {
    assert_eq!(reflect::array_of(5, &ty::<isize>()).to_string(), "[5]int");
    assert_eq!(reflect::array_of(5, &ty::<isize>()).len(), 5);
    assert_eq!(reflect::slice_of(&ty::<String>()).to_string(), "[]string");
    assert_eq!(
        reflect::map_of(&ty::<String>(), &ty::<Vec<u8>>()).to_string(),
        "map[string][]uint8"
    );
    assert_eq!(
        panic_message(|| reflect::array_of(-1, &ty::<isize>())),
        "reflect: negative length passed to ArrayOf"
    );
    // Invalid key types.
    assert_eq!(
        panic_message(|| reflect::map_of(&ty::<Vec<u8>>(), &ty::<isize>())),
        "reflect.MapOf: invalid key type []uint8"
    );
    assert_eq!(
        panic_message(|| reflect::map_of(&reflect::func_of(&[], &[], false), &ty::<isize>())),
        "reflect.MapOf: invalid key type func()"
    );
    // Interface and struct keys are fine.
    reflect::map_of(&any(), &ty::<isize>());
    reflect::map_of(&ty::<(isize, String)>(), &ty::<isize>());
    let c = reflect::chan_of(ChanDir::Recv, &ty::<isize>());
    assert_eq!(c.chan_dir(), ChanDir::Recv);
    assert_eq!(c.elem(), ty::<isize>());
}

// ---------------------------------------------------------------------------
// Layout (Go's amd64/arm64 sizes and alignments).

#[test]
fn sizes_and_offsets() {
    let sizes = [
        (ty::<bool>(), 1, 1),
        (ty::<i16>(), 2, 2),
        (ty::<i32>(), 4, 4),
        (ty::<isize>(), 8, 8),
        (ty::<f32>(), 4, 4),
        (basic(Kind::Complex64), 8, 4),
        (basic(Kind::Complex128), 16, 8),
        (basic(Kind::Uintptr), 8, 8),
        (ty::<String>(), 16, 8),
        (ty::<Vec<u8>>(), 24, 8),
        (ty::<Option<u8>>(), 8, 8),
        (ty::<BTreeMap<u8, u8>>(), 8, 8),
        (any(), 16, 8),
        (ty::<[u16; 5]>(), 10, 2),
        (ty::<[String; 2]>(), 32, 8),
        (reflect::chan_of(ChanDir::Both, &ty::<u8>()), 8, 8),
        (reflect::func_of(&[], &[], false), 8, 8),
    ];
    for (t, size, align) in sizes {
        assert_eq!(t.size(), size, "{t} size");
        assert_eq!(t.align(), align, "{t} align");
        assert_eq!(t.field_align(), align);
    }
    // struct { a bool; b int32; c int8; d int64 }
    let s = reflect::struct_of(&[
        sf("A", ty::<bool>()),
        sf("B", ty::<i32>()),
        sf("C", ty::<i8>()),
        sf("D", ty::<i64>()),
    ]);
    assert_eq!(s.size(), 24);
    assert_eq!(s.align(), 8);
    let offsets: Vec<usize> = (0..4).map(|i| s.field(i).offset).collect();
    assert_eq!(offsets, vec![0, 4, 8, 16]);
    // A trailing zero-size field adds a byte of padding, rounded up.
    let z = reflect::struct_of(&[sf("A", ty::<i64>()), sf("Z", reflect::struct_of(&[]))]);
    assert_eq!(z.size(), 16);
    assert_eq!(reflect::struct_of(&[]).size(), 0);
    assert_eq!(
        reflect::struct_of(&[sf("A", ty::<u8>()), sf("B", ty::<u8>())]).size(),
        2
    );
}

// ---------------------------------------------------------------------------
// StructOf validation, strings, fields.

#[test]
fn struct_of_strings_and_fields() {
    let t = reflect::struct_of(&[
        sf("A", ty::<isize>()).with_tag(r#"json:"a""#),
        sf("B", ty::<Vec<String>>()),
        sf("Embedded", reflect::struct_of(&[sf("X", ty::<u8>())])).embedded(),
    ]);
    assert_eq!(
        t.to_string(),
        r#"struct { A int "json:\"a\""; B []string; struct { X uint8 } }"#
    );
    assert_eq!(t.num_field(), 3);
    let f = t.field(0);
    assert_eq!(f.name, "A");
    assert_eq!(f.tag.get("json"), "a");
    assert_eq!(f.index, vec![0]);
    assert!(f.is_exported());
    assert!(t.field(2).anonymous);
    assert_eq!(
        t.fields().map(|f| f.name).collect::<Vec<_>>(),
        ["A", "B", "Embedded"]
    );
    assert_eq!(reflect::struct_of(&[]).to_string(), "struct {}");
    assert_eq!(t.field_by_index(&[2, 0]).name, "X");
    assert_eq!(t.field_by_name("X").map(|f| f.index), Some(vec![2, 0]));
    assert!(t.field_by_name("Nope").is_none());
    assert_eq!(
        t.field_by_name_func(|s| s.starts_with('B')).map(|f| f.name),
        Some("B".into())
    );
}

#[test]
fn struct_of_panics() {
    let m = |fields: Vec<StructField>| panic_message(|| reflect::struct_of(&fields));
    assert_eq!(
        m(vec![sf("", ty::<isize>())]),
        "reflect.StructOf: field 0 has no name"
    );
    assert_eq!(
        m(vec![sf("1x", ty::<isize>())]),
        "reflect.StructOf: field 0 has invalid name"
    );
    assert_eq!(
        m(vec![sf("a b", ty::<isize>())]),
        "reflect.StructOf: field 0 has invalid name"
    );
    assert_eq!(
        m(vec![sf("x", ty::<isize>())]),
        "reflect.StructOf: field \"x\" is unexported but missing PkgPath"
    );
    assert_eq!(
        m(vec![sf("A", ty::<isize>()), sf("A", ty::<isize>())]),
        "reflect.StructOf: duplicate field A"
    );
    assert_eq!(
        m(vec![sf("A", ty::<isize>()).embedded().with_pkg_path("p")]),
        "reflect.StructOf: field \"A\" is anonymous but has PkgPath set"
    );
    assert_eq!(
        m(vec![
            sf("x", ty::<isize>()).with_pkg_path("p"),
            sf("y", ty::<isize>()).with_pkg_path("q")
        ]),
        "reflect.StructOf: fields with different PkgPath p and q"
    );
    assert_eq!(
        m(vec![sf(
            "A",
            reflect::pointer_to(&reflect::pointer_to(&ty::<isize>()))
        )
        .embedded()]),
        "reflect.StructOf: illegal embedded field type **int"
    );
    // Blank fields may repeat.
    reflect::struct_of(&[
        sf("_", ty::<isize>()).with_pkg_path("p"),
        sf("_", ty::<isize>()).with_pkg_path("p"),
    ]);
}

#[test]
fn unexported_fields_have_pkg_path() {
    let t = reflect::struct_of(&[
        sf("A", ty::<isize>()),
        sf("b", ty::<isize>()).with_pkg_path("example.com/p"),
    ]);
    assert!(t.field(0).is_exported());
    assert!(!t.field(1).is_exported());
    assert_eq!(t.field(1).pkg_path, "example.com/p");
    let v = reflect::new(&t).elem();
    assert!(v.field(0).can_set());
    assert!(!v.field(1).can_set());
    assert!(v.field(1).can_addr());
    assert!(!v.field(1).can_interface());
    assert!(panic_message(|| v.field(1).set_int(1))
        .contains("reflect.Value.SetInt using value obtained using unexported field"));
    assert!(panic_message(|| v.field(1).interface::<isize>())
        .contains("cannot return value obtained from unexported field or method"));
    assert_eq!(v.field(1).int(), 0);
}

// ---------------------------------------------------------------------------
// VisibleFields (visiblefields_test.go cases built with StructOf).

fn names(t: &Type) -> Vec<(String, Vec<usize>)> {
    reflect::visible_fields(t)
        .into_iter()
        .map(|f| (f.name, f.index))
        .collect()
}

#[test]
fn visible_fields_embedding_and_shadowing() {
    let a = reflect::struct_of(&[sf("A", ty::<isize>()), sf("B", ty::<isize>())]);
    // struct { A int; B int } has no embedded fields.
    assert_eq!(
        names(&a),
        vec![("A".into(), vec![0]), ("B".into(), vec![1])]
    );
    // Embedded struct fields are promoted; shadowed ones are hidden.
    let inner = reflect::struct_of(&[sf("A", ty::<String>()), sf("C", ty::<isize>())]);
    let outer = reflect::struct_of(&[
        sf("Inner", inner.clone()).embedded(),
        sf("A", ty::<isize>()),
    ]);
    assert_eq!(
        names(&outer),
        vec![
            ("Inner".into(), vec![0]),
            ("C".into(), vec![0, 1]),
            ("A".into(), vec![1]),
        ]
    );
    // Same name at the same depth through two embedded structs cancels.
    let e1 = reflect::struct_of(&[sf("X", ty::<isize>()), sf("P", ty::<isize>())]);
    let e2 = reflect::struct_of(&[sf("X", ty::<isize>()), sf("Q", ty::<isize>())]);
    let both = reflect::struct_of(&[sf("E1", e1.clone()).embedded(), sf("E2", e2).embedded()]);
    assert_eq!(
        names(&both),
        vec![
            ("E1".into(), vec![0]),
            ("P".into(), vec![0, 1]),
            ("E2".into(), vec![1]),
            ("Q".into(), vec![1, 1]),
        ]
    );
    // A deeper field is shadowed by a shallower one even if it comes first.
    let deep = reflect::struct_of(&[
        sf("D", reflect::struct_of(&[sf("Y", e1.clone()).embedded()])).embedded(),
        sf("X", ty::<String>()),
    ]);
    let got = names(&deep);
    assert!(got.contains(&("X".into(), vec![1])));
    assert!(!got.contains(&("X".into(), vec![0, 0, 0])));
    // Pointer-embedded structs are walked too.
    let ptr = reflect::struct_of(&[sf("E", reflect::pointer_to(&e1)).embedded()]);
    assert_eq!(
        names(&ptr),
        vec![
            ("E".into(), vec![0]),
            ("X".into(), vec![0, 0]),
            ("P".into(), vec![0, 1]),
        ]
    );
    assert_eq!(
        panic_message(|| reflect::visible_fields(&ty::<isize>())),
        "reflect.VisibleFields of non-struct type"
    );
}

#[test]
fn field_by_name_breadth_first() {
    let x = reflect::struct_of(&[sf("N", ty::<isize>())]);
    let y = reflect::struct_of(&[sf("X", x.clone()).embedded(), sf("M", ty::<u8>())]);
    let z = reflect::struct_of(&[sf("Y", y).embedded(), sf("N", ty::<String>())]);
    // N at depth 0 wins over N at depth 2.
    assert_eq!(z.field_by_name("N").unwrap().index, vec![1]);
    assert_eq!(z.field_by_name("M").unwrap().index, vec![0, 1]);
    let w = reflect::struct_of(&[sf("Y", z.clone()).embedded()]);
    assert_eq!(w.field_by_name("N").unwrap().index, vec![0, 1]);
    // Ambiguity at one depth finds nothing.
    let amb = reflect::struct_of(&[sf("A", x.clone()).embedded(), sf("B", x).embedded()]);
    assert!(amb.field_by_name("N").is_none());
}

// ---------------------------------------------------------------------------
// DeepEqual (deepEqualTests).

fn deq<A: Reflect, B: Reflect>(a: &A, b: &B) -> bool {
    reflect::deep_equal(a, b)
}

#[derive(Clone)]
struct Pt {
    a: isize,
    b: f64,
}

fn pt_type() -> Type {
    reflect::struct_of(&[sf("A", ty::<isize>()), sf("B", ty::<f64>())])
}

impl ReflectType for Pt {
    fn reflect_type() -> Type {
        pt_type()
    }
}

impl Reflect for Pt {
    fn to_value(&self) -> Value {
        Value::from_parts(&pt_type(), &[self.a.to_value(), self.b.to_value()])
    }
    fn from_value(v: &Value) -> Result<Self, reflect::Error> {
        Ok(Pt {
            a: isize::from_value(&v.field(0))?,
            b: f64::from_value(&v.field(1))?,
        })
    }
}

#[test]
fn deep_equal_table() {
    // Equalities.
    assert!(deq(&1isize, &1isize));
    assert!(deq(&1i32, &1i32));
    assert!(deq(&0.5f64, &0.5f64));
    assert!(deq(&0.5f32, &0.5f32));
    assert!(deq(&"hello".to_string(), &"hello".to_string()));
    assert!(deq(&vec![0isize; 10], &vec![0isize; 10]));
    assert!(deq(&Some([1isize, 2, 3]), &Some([1isize, 2, 3])));
    assert!(deq(&Pt { a: 1, b: 0.5 }, &Pt { a: 1, b: 0.5 }));
    let mut m1 = BTreeMap::new();
    m1.insert(1isize, "one".to_string());
    m1.insert(2, "two".to_string());
    let mut m2 = BTreeMap::new();
    m2.insert(2isize, "two".to_string());
    m2.insert(1, "one".to_string());
    assert!(deq(&m1, &m2));
    assert!(deq(&vec![1u8, 2, 3], &vec![1u8, 2, 3]));
    // Inequalities.
    assert!(!deq(&1isize, &2isize));
    assert!(!deq(&0.5f64, &0.6f64));
    assert!(!deq(&"hello".to_string(), &"hey".to_string()));
    assert!(!deq(&vec![0isize; 10], &vec![0isize; 11]));
    assert!(!deq(&Some([1isize, 2, 3]), &Some([1isize, 2, 4])));
    assert!(!deq(&Pt { a: 1, b: 0.5 }, &Pt { a: 1, b: 0.6 }));
    assert!(!deq(&Pt { a: 1, b: 0.0 }, &Pt { a: 2, b: 0.0 }));
    m1.insert(3, "three".to_string());
    assert!(!deq(&m1, &m2));
    m2.insert(3, "xxx".to_string());
    assert!(!deq(&m1, &m2));
    assert!(!deq(&vec![vec![1isize]], &vec![vec![2isize]]));
    // Floating point.
    assert!(!deq(&f64::NAN, &f64::NAN));
    assert!(!deq(&[f64::NAN], &[f64::NAN]));
    assert!(!deq(&vec![f64::NAN], &vec![f64::NAN]));
    let nan_slice = vec![f64::NAN].to_value();
    // The same slice is deeply equal to itself even with NaN (same pointer).
    assert!(reflect::deep_equal_values(&nan_slice, &nan_slice));
    let nan_ptr = Some(f64::NAN).to_value();
    assert!(reflect::deep_equal_values(&nan_ptr, &nan_ptr));
    // Nil versus empty.
    let nil_s = reflect::zero(&ty::<Vec<isize>>());
    let empty_s = reflect::make_slice(&ty::<Vec<isize>>(), 0, 0);
    assert!(!reflect::deep_equal_values(&nil_s, &empty_s));
    assert!(reflect::deep_equal_values(&empty_s, &empty_s));
    assert!(reflect::deep_equal_values(&nil_s, &nil_s));
    let mt = ty::<BTreeMap<isize, isize>>();
    let nil_m = reflect::zero(&mt);
    let empty_m = reflect::make_map(&mt);
    assert!(!reflect::deep_equal_values(&nil_m, &empty_m));
    assert!(reflect::deep_equal_values(
        &empty_m,
        &reflect::make_map(&mt)
    ));
    assert!(reflect::deep_equal_values(&nil_m, &nil_m));
    // Mismatched types.
    assert!(!deq(&1isize, &1.0f64));
    assert!(!deq(&1i32, &1i64));
    assert!(!deq(&0.5f64, &"hello".to_string()));
    assert!(!deq(&vec![1isize, 2, 3], &[1isize, 2, 3]));
    assert!(!deq(&Pt { a: 1, b: 0.5 }, &(1isize, 0.5f64)));
    let mut u: BTreeMap<usize, String> = BTreeMap::new();
    u.insert(1, "one".into());
    let mut i: BTreeMap<isize, String> = BTreeMap::new();
    i.insert(1, "one".into());
    assert!(!deq(&u, &i));
    // nil on either side.
    let nil = Value::default();
    assert!(reflect::deep_equal_values(&nil, &nil));
    assert!(!reflect::deep_equal_values(&nil, &1isize.to_value()));
    assert!(!reflect::deep_equal_values(&1isize.to_value(), &nil));
    assert!(deq(&Value::default(), &Value::default()));
    assert!(!deq(&Value::default(), &1isize));
}

#[test]
fn deep_equal_interfaces_and_functions() {
    let a = boxed(1isize);
    let b = boxed(1isize);
    assert!(deq(&[a.clone()], &[b]));
    assert!(!deq(&[a.clone()], &[boxed(2isize)]));
    assert!(!deq(&[a.clone()], &[boxed(1i64)]));
    assert!(!deq(&[a], &[Value::default()]));
    // Funcs are equal only if both nil.
    let ft = reflect::func_of(&[], &[], false);
    let nil_f = reflect::zero(&ft);
    let f = reflect::make_func(&ft, |_| vec![]);
    assert!(reflect::deep_equal_values(&nil_f, &nil_f));
    assert!(!reflect::deep_equal_values(&f, &f));
    assert!(!reflect::deep_equal_values(&nil_f, &f));
}

#[test]
fn deep_equal_cycles() {
    // type L *L cannot be written, so use pointers through a struct.
    let node = {
        // struct { P *?; S string } needs a self reference; model it with
        // map[string]any cycles as Go's cycleMap tests do.
        reflect::map_of(&ty::<String>(), &any())
    };
    let mk = |key: &str| {
        let m = reflect::make_map(&node);
        m.set_map_index(&key.to_string().to_value(), &m);
        let p = reflect::new(&node);
        p.elem().set(&m);
        p
    };
    let (c1, c2, c3) = (mk("cycle"), mk("cycle"), mk("different"));
    assert!(reflect::deep_equal_values(&c1, &c2));
    assert!(!reflect::deep_equal_values(&c1, &c3));
    // A slice that contains itself through an interface.
    let st = reflect::slice_of(&any());
    let s = reflect::make_slice(&st, 1, 1);
    let sp = reflect::new(&st);
    sp.elem().set(&s);
    s.index(0).set(&sp.elem());
    let s2 = reflect::make_slice(&st, 1, 1);
    let sp2 = reflect::new(&st);
    sp2.elem().set(&s2);
    s2.index(0).set(&sp2.elem());
    assert!(reflect::deep_equal_values(&sp, &sp2));
}

// ---------------------------------------------------------------------------
// IsZero (TestIsZero), IsNil, Comparable, Equal.

#[test]
fn is_zero() {
    let cases: Vec<(Value, bool)> = vec![
        (true.to_value(), false),
        (false.to_value(), true),
        (0isize.to_value(), true),
        (1isize.to_value(), false),
        (0u8.to_value(), true),
        (1u64.to_value(), false),
        (0.0f32.to_value(), true),
        (1.2f32.to_value(), false),
        ((-0.0f64).to_value(), true),
        (f64::NAN.to_value(), false),
        (Complex { re: 0.0, im: 0.0 }.to_value(), true),
        (Complex { re: -0.0, im: -0.0 }.to_value(), true),
        (Complex { re: 0.0, im: 1.2 }.to_value(), false),
        (reflect::zero(&basic(Kind::Uintptr)), true),
        (reflect::zero(&ty::<[String; 5]>()), true),
        (
            [
                String::new(),
                String::new(),
                String::new(),
                "a".into(),
                String::new(),
            ]
            .to_value(),
            false,
        ),
        (reflect::zero(&ty::<[Option<u8>; 1]>()), true),
        ([Some(1u8)].to_value(), false),
        (
            reflect::zero(&reflect::chan_of(ChanDir::Both, &ty::<String>())),
            true,
        ),
        (
            reflect::make_chan(&reflect::chan_of(ChanDir::Both, &ty::<String>()), 0),
            false,
        ),
        (reflect::zero(&reflect::func_of(&[], &[], false)), true),
        (
            reflect::make_func(&reflect::func_of(&[], &[], false), |_| vec![]),
            false,
        ),
        (reflect::zero(&any()), true),
        (boxed(0isize), false),
        (reflect::zero(&ty::<Vec<u8>>()), true),
        (Vec::<u8>::new().to_value(), false),
        (reflect::make_slice(&ty::<Vec<u8>>(), 0, 0), false),
        (reflect::zero(&ty::<BTreeMap<u8, u8>>()), true),
        (reflect::make_map(&ty::<BTreeMap<u8, u8>>()), false),
        (None::<u8>.to_value(), true),
        (Some(0u8).to_value(), false),
        (String::new().to_value(), true),
        ("a".to_string().to_value(), false),
        (Pt { a: 0, b: 0.0 }.to_value(), true),
        (Pt { a: 0, b: 1.0 }.to_value(), false),
        (().to_owned_unit(), true),
    ];
    for (i, (v, want)) in cases.iter().enumerate() {
        assert_eq!(v.is_zero(), *want, "case {i}: {v:?}");
    }
    // A struct with a blank field ignores it.
    let t = reflect::struct_of(&[
        sf("A", ty::<isize>()),
        sf("_", ty::<isize>()).with_pkg_path("p"),
    ]);
    let v = reflect::new(&t).elem();
    assert!(v.is_zero());
    assert_eq!(
        panic_message(|| Value::default().is_zero()),
        "reflect: call of reflect.Value.IsZero on zero Value"
    );
}

trait UnitValue {
    fn to_owned_unit(&self) -> Value;
}

impl UnitValue for () {
    fn to_owned_unit(&self) -> Value {
        reflect::zero(&reflect::struct_of(&[]))
    }
}

#[test]
fn is_nil() {
    assert!(reflect::zero(&ty::<Vec<u8>>()).is_nil());
    assert!(!Vec::<u8>::new().to_value().is_nil());
    assert!(None::<u8>.to_value().is_nil());
    assert!(!Some(1u8).to_value().is_nil());
    assert!(reflect::zero(&any()).is_nil());
    assert!(!boxed(1isize).is_nil());
    assert!(reflect::zero(&ty::<BTreeMap<u8, u8>>()).is_nil());
    assert!(reflect::zero(&basic(Kind::UnsafePointer)).is_nil());
    assert_eq!(
        panic_message(|| 1isize.to_value().is_nil()),
        "reflect: call of reflect.Value.IsNil on int Value"
    );
    assert_eq!(
        panic_message(|| Value::default().is_nil()),
        "reflect: call of reflect.Value.IsNil on zero Value"
    );
}

#[test]
fn comparable_types() {
    let c = |t: Type| t.comparable();
    assert!(c(ty::<isize>()));
    assert!(c(ty::<String>()));
    assert!(c(ty::<Option<u8>>()));
    assert!(!c(reflect::func_of(&[], &[], false)));
    assert!(!c(ty::<Vec<u8>>()));
    assert!(!c(ty::<BTreeMap<String, isize>>()));
    assert!(c(reflect::chan_of(ChanDir::Both, &ty::<isize>())));
    assert!(c(ty::<f64>()));
    assert!(c(ty::<bool>()));
    assert!(c(ty::<Complex>()));
    assert!(c(pt_type()));
    assert!(!c(reflect::struct_of(&[sf("A", ty::<Vec<u8>>())])));
    assert!(!c(ty::<[BTreeMap<String, isize>; 10]>()));
    assert!(c(ty::<[String; 10]>()));
    assert!(c(any()));
}

#[test]
fn value_comparable_and_equal() {
    // Interface values holding incomparable dynamic types.
    let ok = boxed(1isize);
    let bad = boxed(vec![1u8]);
    assert!(ok.comparable());
    assert!(!bad.comparable());
    assert!(reflect::zero(&any()).comparable());
    assert!(!Value::default().comparable());
    let arr = [boxed(1isize), boxed(2isize)].to_value();
    assert!(arr.comparable());
    let arr_bad = [boxed(1isize), boxed(vec![1u8])].to_value();
    assert!(!arr_bad.comparable());

    assert!(1isize.to_value().equal(&1isize.to_value()));
    assert!(!1isize.to_value().equal(&2isize.to_value()));
    assert!(!1isize.to_value().equal(&1i64.to_value()));
    assert!(!f64::NAN.to_value().equal(&f64::NAN.to_value()));
    assert!("a"
        .to_string()
        .to_value()
        .equal(&"a".to_string().to_value()));
    // Invalid values are equal to each other only.
    assert!(Value::default().equal(&Value::default()));
    assert!(!Value::default().equal(&1isize.to_value()));
    // Interface values compare their dynamic values.
    assert!(ok.equal(&1isize.to_value()));
    assert!(ok.equal(&boxed(1isize)));
    assert!(!ok.equal(&boxed(1i64)));
    // Pointers compare by identity.
    let p = reflect::new(&ty::<isize>());
    assert!(p.equal(&p.clone()));
    assert!(!p.equal(&reflect::new(&ty::<isize>())));
    // Structs and arrays compare elementwise.
    assert!(Pt { a: 1, b: 2.0 }
        .to_value()
        .equal(&Pt { a: 1, b: 2.0 }.to_value()));
    assert!(![1u8, 2].to_value().equal(&[1u8, 3].to_value()));
    assert!(
        panic_message(|| vec![1u8].to_value().equal(&vec![1u8].to_value()))
            .contains("reflect.Value.Equal: values of type []uint8 are not comparable")
    );
    assert!(panic_message(|| bad.equal(&bad.clone())).contains("are not comparable"));
}

// ---------------------------------------------------------------------------
// Overflow.

#[test]
fn overflow() {
    let max_f32 = ((1u64 << 24) - 1) as f64 * 2f64.powi(127 - 23);
    let ovf_f32 = max_f32 + 2f64.powi(127 - 52);
    for t in [true, false] {
        let f64v = |x: f64| {
            if t {
                ty::<f64>().overflow_float(x)
            } else {
                0.0f64.to_value().overflow_float(x)
            }
        };
        let f32v = |x: f64| {
            if t {
                ty::<f32>().overflow_float(x)
            } else {
                0.0f32.to_value().overflow_float(x)
            }
        };
        assert!(!f64v(1e300));
        assert!(!f32v(max_f32));
        assert!(f32v(ovf_f32));
        assert!(f32v(-ovf_f32));
        let i32v = |x: i64| {
            if t {
                ty::<i32>().overflow_int(x)
            } else {
                0i32.to_value().overflow_int(x)
            }
        };
        assert!(!i32v(0x7fff_ffff));
        assert!(!i32v(-1 << 31));
        assert!(i32v(1 << 31));
        let u32v = |x: u64| {
            if t {
                ty::<u32>().overflow_uint(x)
            } else {
                0u32.to_value().overflow_uint(x)
            }
        };
        assert!(!u32v(0xffff_ffff));
        assert!(u32v(1 << 32));
    }
    assert!(ty::<i8>().overflow_int(128));
    assert!(!ty::<i8>().overflow_int(-128));
    assert!(ty::<i8>().overflow_int(-129));
    assert!(!ty::<isize>().overflow_int(i64::MIN));
    assert!(ty::<u8>().overflow_uint(256));
    assert!(!basic(Kind::Uintptr).overflow_uint(u64::MAX));
    assert!(basic(Kind::Complex64).overflow_complex(1e300, 0.0));
    assert!(!basic(Kind::Complex128).overflow_complex(1e300, 1e300));
    assert!(panic_message(|| ty::<String>().overflow_int(1))
        .contains("reflect: OverflowInt of non-int type string"));
    assert!(panic_message(|| ty::<u8>().overflow_int(1)).contains("non-int type uint8"));
    assert_eq!(
        panic_message(|| "x".to_string().to_value().overflow_uint(1)),
        "reflect: call of reflect.Value.OverflowUint on string Value"
    );
}

// ---------------------------------------------------------------------------
// Scalars: Can*, getters, setters.

#[test]
fn can_int_uint_float_complex() {
    let v = 1i8.to_value();
    assert!(v.can_int() && !v.can_uint() && !v.can_float() && !v.can_complex());
    let v = 1u16.to_value();
    assert!(!v.can_int() && v.can_uint());
    assert!(1.5f32.to_value().can_float());
    assert!(Complex { re: 1.0, im: 2.0 }.to_value().can_complex());
    assert!(!"s".to_string().to_value().can_int());
    assert!(!Value::default().can_int());
}

#[test]
fn getters_and_kind_panics() {
    assert_eq!(7isize.to_value().int(), 7);
    assert_eq!(7u8.to_value().uint(), 7);
    assert_eq!(1.5f32.to_value().float(), 1.5);
    assert!(true.to_value().bool());
    assert_eq!(
        Complex { re: 1.0, im: -2.0 }.to_value().complex(),
        Complex { re: 1.0, im: -2.0 }
    );
    assert_eq!("héllo".to_string().to_value().text(), "héllo");
    assert_eq!("abc".to_string().to_value().len(), 3);
    assert_eq!(
        panic_message(|| "s".to_string().to_value().int()),
        "reflect: call of reflect.Value.Int on string Value"
    );
    assert_eq!(
        panic_message(|| 1isize.to_value().bool()),
        "reflect: call of reflect.Value.Bool on int Value"
    );
    assert_eq!(
        panic_message(|| 1isize.to_value().uint()),
        "reflect: call of reflect.Value.Uint on int Value"
    );
    assert_eq!(
        panic_message(|| 1isize.to_value().float()),
        "reflect: call of reflect.Value.Float on int Value"
    );
    assert_eq!(
        panic_message(|| 1isize.to_value().complex()),
        "reflect: call of reflect.Value.Complex on int Value"
    );
    assert_eq!(
        panic_message(|| Value::default().int()),
        "reflect: call of reflect.Value.Int on zero Value"
    );
    assert_eq!(
        panic_message(|| Value::default().type_()),
        "reflect: call of reflect.Value.Type on zero Value"
    );
    // Value.String of non-strings.
    assert_eq!(1isize.to_value().text(), "<int Value>");
    assert_eq!(Value::default().text(), "<invalid Value>");
    assert_eq!(vec![1u8].to_value().text(), "<[]uint8 Value>");
}

#[test]
fn set_scalars_wrap_like_go() {
    let p = reflect::new(&ty::<i8>());
    p.elem().set_int(300);
    assert_eq!(p.elem().int(), 44);
    let p = reflect::new(&ty::<u8>());
    p.elem().set_uint(300);
    assert_eq!(p.elem().uint(), 44);
    let p = reflect::new(&ty::<f32>());
    p.elem().set_float(0.1);
    assert_eq!(p.elem().float(), 0.1f32 as f64);
    let p = reflect::new(&basic(Kind::Complex64));
    p.elem().set_complex(Complex { re: 0.1, im: 0.2 });
    assert_eq!(p.elem().complex().re, 0.1f32 as f64);
    let p = reflect::new(&ty::<String>());
    p.elem().set_string("hi");
    assert_eq!(p.elem().text(), "hi");
    let p = reflect::new(&ty::<bool>());
    p.elem().set_bool(true);
    assert!(p.elem().bool());
    p.elem().set_zero();
    assert!(!p.elem().bool());
}

#[test]
fn set_panics_like_go() {
    let v = 1isize.to_value();
    assert_eq!(
        panic_message(|| v.set_int(2)),
        "reflect: reflect.Value.SetInt using unaddressable value"
    );
    assert_eq!(
        panic_message(|| v.set(&2isize.to_value())),
        "reflect: reflect.Value.Set using unaddressable value"
    );
    let p = reflect::new(&ty::<isize>());
    assert_eq!(
        panic_message(|| p.elem().set_string("x")),
        "reflect: call of reflect.Value.SetString on int Value"
    );
    assert_eq!(
        panic_message(|| p.elem().set(&"x".to_string().to_value())),
        "reflect.Set: value of type string is not assignable to type int"
    );
    assert_eq!(
        panic_message(|| p.elem().set(&Value::default())),
        "reflect: call of reflect.Value.Set on zero Value"
    );
    assert_eq!(
        panic_message(|| Value::default().set_int(1)),
        "reflect: call of reflect.Value.SetInt on zero Value"
    );
    assert_eq!(
        panic_message(|| 1isize.to_value().addr()),
        "reflect.Value.Addr of unaddressable value"
    );
}

#[test]
fn addr_elem_and_pointers() {
    let p = reflect::new(&ty::<isize>());
    let e = p.elem();
    assert!(e.can_addr() && e.can_set());
    e.set_int(5);
    let a = e.addr();
    assert_eq!(a.type_().to_string(), "*int");
    assert_eq!(a.elem().int(), 5);
    assert!(a.equal(&p));
    a.elem().set_int(6);
    assert_eq!(e.int(), 6);
    // Pointers to struct fields and slice elements alias.
    let t = reflect::struct_of(&[sf("A", ty::<isize>()), sf("B", ty::<Vec<isize>>())]);
    let s = reflect::new(&t).elem();
    s.field(1).set(&ints(&[1, 2, 3]));
    let pa = s.field(0).addr();
    pa.elem().set_int(9);
    assert_eq!(s.field(0).int(), 9);
    let pe = s.field(1).index(2).addr();
    pe.elem().set_int(33);
    assert_eq!(s.field(1).index(2).int(), 33);
    // Elem of a nil pointer is invalid; of a non-pointer panics.
    assert!(!reflect::zero(&ty::<Option<u8>>()).elem().is_valid());
    assert_eq!(
        panic_message(|| 1isize.to_value().elem()),
        "reflect: call of reflect.Value.Elem on int Value"
    );
    assert_eq!(reflect::indirect(&p).int(), 6);
    assert_eq!(reflect::indirect(&1isize.to_value()).int(), 1);
    // Non-addressable values: map elements and copies.
    let m = BTreeMap::from([(1isize, 2isize)]).to_value();
    assert!(!m.map_index(&1isize.to_value()).can_addr());
}

#[test]
fn interface_values() {
    let mut x = 0isize;
    let var = reflect::new(&any());
    let iv = var.elem();
    assert_eq!(iv.kind(), Kind::Interface);
    assert!(iv.is_nil());
    iv.set(&7isize.to_value());
    assert!(!iv.is_nil());
    assert_eq!(iv.elem().int(), 7);
    assert_eq!(iv.elem().type_().to_string(), "int");
    x += iv.interface::<isize>();
    assert_eq!(x, 7);
    iv.set_zero();
    assert!(iv.is_nil());
    assert!(!iv.elem().is_valid());
    // Interface() wrong type.
    iv.set(&7isize.to_value());
    assert!(panic_message(|| iv.interface::<String>())
        .contains("interface conversion: interface {} is int, not string"));
    assert_eq!(iv.try_interface::<String>(), None);
    assert_eq!(iv.try_interface::<isize>(), Some(7));
    assert_eq!(reflect::type_assert::<isize>(&iv), Some(7));
    assert_eq!(reflect::type_assert::<isize>(&1u8.to_value()), None);
    // Assigning to an error interface requires the method set.
    let err = reflect::new(&Type::error_type()).elem();
    assert!(panic_message(|| err.set(&1isize.to_value()))
        .contains("value of type int is not assignable to type error"));
}

// ---------------------------------------------------------------------------
// Slices: Slice, Slice3, SetLen, SetCap, Grow, Append, Copy, Clear, Swapper.

#[test]
fn slice_and_slice3() {
    let xs = ints(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let v = xs.slice(3, 5);
    assert_eq!((v.len(), v.cap()), (2, 5));
    assert_eq!(v.slice(0, 5).interface::<Vec<isize>>(), vec![4, 5, 6, 7, 8]);
    let v3 = xs.slice3(3, 5, 7);
    assert_eq!((v3.len(), v3.cap()), (2, 4));
    assert_eq!(v3.slice(0, 4).interface::<Vec<isize>>(), vec![4, 5, 6, 7]);
    assert!(panic_message(|| xs.slice3(1, 2, 1)).contains("Slice3: slice index out of bounds"));
    assert!(panic_message(|| xs.slice3(1, 1, 11)).contains("Slice3: slice index out of bounds"));
    assert!(panic_message(|| xs.slice3(2, 2, 1)).contains("Slice3: slice index out of bounds"));
    assert!(panic_message(|| xs.slice(2, 1)).contains("Slice: slice index out of bounds"));
    assert!(panic_message(|| xs.slice(0, 9)).contains("Slice: slice index out of bounds"));
    assert!(panic_message(|| xs.slice(-1, 2)).contains("Slice: slice index out of bounds"));
    // Arrays must be addressable.
    let arr = [10isize, 20, 30, 40, 50, 60, 70, 80].to_value();
    assert_eq!(
        panic_message(|| arr.slice(2, 5)),
        "reflect.Value.Slice: slice of unaddressable array"
    );
    let pa = reflect::new(&ty::<[isize; 8]>());
    pa.elem().set(&arr);
    let sa = pa.elem().slice(2, 5);
    assert_eq!((sa.len(), sa.cap()), (3, 6));
    // The slice aliases the array.
    sa.index(0).set_int(99);
    assert_eq!(pa.elem().index(2).int(), 99);
    let sa3 = pa.elem().slice3(2, 5, 6);
    assert_eq!((sa3.len(), sa3.cap()), (3, 4));
    assert_eq!(
        panic_message(|| arr.slice3(0, 1, 2)),
        "reflect.Value.Slice3: slice of unaddressable array"
    );
    // Strings.
    let s = "0123456789".to_string().to_value();
    assert_eq!(s.slice(3, 5).text(), "34");
    assert!(panic_message(|| s.slice(3, 11)).contains("string slice index out of bounds"));
    assert!(panic_message(|| s.slice3(1, 2, 3)).contains("reflect.Value.Slice3 on string Value"));
    // Empty-capacity slices keep the base pointer.
    let p = reflect::new(&ty::<Vec<isize>>());
    p.elem().set(&xs);
    let r1 = p.elem().slice(3, 4);
    let ptr2 = r1.unsafe_pointer();
    let r2 = r1.slice(5, 5);
    assert_eq!(r2.unsafe_pointer(), ptr2);
}

#[test]
fn set_len_cap() {
    let p = reflect::new(&ty::<Vec<isize>>());
    p.elem().set(&ints(&[1, 2, 3, 4, 5, 6, 7, 8]));
    let vs = p.elem();
    should_panic("SetLen(10)", || vs.set_len(10));
    should_panic("SetCap(10)", || vs.set_cap(10));
    should_panic("SetLen(-1)", || vs.set_len(-1));
    should_panic("SetCap(-1)", || vs.set_cap(-1));
    vs.set_len(5);
    assert_eq!((vs.len(), vs.cap()), (5, 8));
    vs.set_cap(6);
    assert_eq!((vs.len(), vs.cap()), (5, 6));
    vs.set_cap(5);
    assert_eq!((vs.len(), vs.cap()), (5, 5));
    should_panic("SetCap(4)", || vs.set_cap(4));
    should_panic("SetLen(6)", || vs.set_len(6));
    let pa = reflect::new(&ty::<[isize; 8]>());
    should_panic("array SetLen", || pa.elem().set_len(8));
    should_panic("array SetCap", || pa.elem().set_cap(8));
}

#[test]
fn append_table() {
    let st = ty::<Vec<isize>>();
    let none = || reflect::zero(&st);
    let empty = || reflect::make_slice(&st, 0, 0);
    let two_of_four = || reflect::make_slice(&st, 2, 4);
    let cases: Vec<(Value, Vec<isize>)> = vec![
        (none(), vec![]),
        (empty(), vec![]),
        (none(), vec![22]),
        (empty(), vec![22]),
        (two_of_four(), vec![]),
        (two_of_four(), vec![22]),
        (two_of_four(), vec![22, 33, 44]),
    ];
    for (i, (orig, extra)) in cases.into_iter().enumerate() {
        let (orig_len, extra_len) = (orig.len(), extra.len());
        let xs: Vec<Value> = extra.iter().map(|x| x.to_value()).collect();
        let app = reflect::append(&orig, &xs);
        assert_eq!(app.len(), orig_len + extra_len, "case {i}");
        assert!(app.cap() >= app.len());
        for (k, x) in extra.iter().enumerate() {
            assert_eq!(app.index(orig_len + k).int(), *x as i64, "case {i}");
        }
        let both = reflect::append_slice(&orig, &extra.to_value());
        assert_eq!(both.len(), orig_len + extra_len, "case {i}");
        // Within capacity the result shares storage with orig.
        if orig_len + extra_len <= orig.cap() && extra_len > 0 {
            app.index(orig_len).set_int(1000);
            assert_eq!(
                orig.slice(0, (orig_len + 1) as isize).index(orig_len).int(),
                1000
            );
        }
    }
    assert!(panic_message(|| reflect::append(&1isize.to_value(), &[]))
        .contains("call of reflect.Append on int Value"));
    assert!(
        panic_message(|| reflect::append_slice(&ints(&[]), &vec![1u8].to_value()))
            .contains("reflect.AppendSlice: int != uint8")
    );
}

#[test]
fn grow_and_clear() {
    let p = reflect::new(&ty::<Vec<isize>>());
    let s = p.elem();
    s.grow(10);
    assert!(s.cap() >= 10);
    assert_eq!(s.len(), 0);
    assert!(panic_message(|| s.grow(-1)).contains("negative len"));
    s.set(&ints(&[1, 2, 3]));
    let old_cap = s.cap();
    s.grow(1);
    assert!(s.cap() >= 4 || s.cap() == old_cap);
    assert_eq!(s.interface::<Vec<isize>>(), vec![1, 2, 3]);
    s.clear();
    assert_eq!(s.interface::<Vec<isize>>(), vec![0, 0, 0]);
    let m = BTreeMap::from([(1isize, 2isize), (3, 4)]).to_value();
    assert_eq!(m.len(), 2);
    m.clear();
    assert_eq!(m.len(), 0);
    assert_eq!(
        panic_message(|| 1isize.to_value().clear()),
        "reflect: call of reflect.Value.Clear on int Value"
    );
}

#[test]
fn copy_values() {
    let st = ty::<Vec<isize>>();
    let dst = reflect::make_slice(&st, 3, 3);
    let n = reflect::copy(&dst, &ints(&[1, 2]));
    assert_eq!(n, 2);
    assert_eq!(dst.interface::<Vec<isize>>(), vec![1, 2, 0]);
    // Overlapping copy behaves like memmove.
    let s = ints(&[1, 2, 3, 4]);
    let n = reflect::copy(&s.slice(1, 4), &s.slice(0, 3));
    assert_eq!(n, 3);
    assert_eq!(s.interface::<Vec<isize>>(), vec![1, 1, 2, 3]);
    // String into []byte.
    let b = reflect::make_slice(&ty::<Vec<u8>>(), 5, 5);
    assert_eq!(reflect::copy(&b, &"héy".to_string().to_value()), 4);
    assert_eq!(b.bytes(), vec![b'h', 0xc3, 0xa9, b'y', 0]);
    // Arrays must be addressable to be a destination.
    let pa = reflect::new(&ty::<[isize; 3]>());
    assert_eq!(reflect::copy(&pa.elem(), &ints(&[7, 8, 9, 10])), 3);
    assert_eq!(pa.elem().index(2).int(), 9);
    assert!(
        panic_message(|| reflect::copy(&[1isize, 2, 3].to_value(), &ints(&[1])))
            .contains("reflect.Copy using unaddressable value")
    );
    assert!(
        panic_message(|| reflect::copy(&ints(&[1]), &vec![1u8].to_value()))
            .contains("reflect.Copy: int != uint8")
    );
    assert!(
        panic_message(|| reflect::copy(&1isize.to_value(), &ints(&[1])))
            .contains("call of reflect.Copy on int Value")
    );
}

#[test]
fn swapper() {
    let cases: Vec<(Value, Vec<usize>)> = vec![
        (vec![1isize, 20, 300].to_value(), vec![300, 20, 1]),
        (vec![1i8, 20, 100].to_value(), vec![100, 20, 1]),
        (
            vec!["eric".to_string(), "sergey".into(), "larry".into()].to_value(),
            vec![],
        ),
    ];
    for (v, _) in &cases {
        let before: Vec<Value> = v.items();
        reflect::swapper(v)(0, 2);
        let after: Vec<Value> = v.items();
        assert!(before[0].equal(&after[2]) && before[2].equal(&after[0]));
        assert!(before[1].equal(&after[1]));
    }
    let one = vec![1isize].to_value();
    reflect::swapper(&one)(0, 0);
    assert!(panic_message(|| reflect::swapper(&one)(0, 1)).contains("slice index out of range"));
    let empty = Vec::<isize>::new().to_value();
    assert!(panic_message(|| reflect::swapper(&empty)(0, 0)).contains("slice index out of range"));
    let v = vec![1isize, 2, 3].to_value();
    assert!(panic_message(|| reflect::swapper(&v)(0, 5)).contains("slice index out of range"));
    assert_eq!(
        panic_message(|| reflect::swapper(&1isize.to_value())),
        "reflect: call of Swapper on int Value"
    );
    let s = vec![Pt { a: 1, b: 2.0 }, Pt { a: 3, b: 4.0 }].to_value();
    reflect::swapper(&s)(0, 1);
    assert_eq!(s.index(0).field(0).int(), 3);
}

#[test]
fn index_and_bytes() {
    let v = ints(&[1, 2, 3]);
    assert_eq!(v.index(2).int(), 3);
    assert!(v.index(0).can_addr());
    assert_eq!(
        panic_message(|| v.index(3)),
        "reflect: slice index out of range"
    );
    let a = [1isize, 2].to_value();
    assert!(!a.index(0).can_addr());
    assert_eq!(
        panic_message(|| a.index(2)),
        "reflect: array index out of range"
    );
    let s = "héy".to_string().to_value();
    assert_eq!(s.index(1).uint(), 0xc3);
    assert_eq!(s.index(1).type_().to_string(), "uint8");
    assert_eq!(
        panic_message(|| s.index(4)),
        "reflect: string index out of range"
    );
    assert_eq!(
        panic_message(|| 1isize.to_value().index(0)),
        "reflect: call of reflect.Value.Index on int Value"
    );
    // Bytes / SetBytes.
    let bs = vec![1u8, 2, 3].to_value();
    assert_eq!(bs.bytes(), vec![1, 2, 3]);
    assert!(panic_message(|| ints(&[1]).bytes()).contains("Bytes of non-byte slice"));
    assert!(panic_message(|| [1u8].to_value().bytes()).contains("unaddressable byte array"));
    let p = reflect::new(&ty::<Vec<u8>>());
    p.elem().set_bytes(&[9, 8]);
    assert_eq!(p.elem().bytes(), vec![9, 8]);
    assert!(
        panic_message(|| reflect::new(&ty::<Vec<isize>>()).elem().set_bytes(&[1]))
            .contains("SetBytes of non-byte slice")
    );
}

// ---------------------------------------------------------------------------
// Maps and MapIter.

#[test]
fn map_basics() {
    let mt = ty::<BTreeMap<String, isize>>();
    let m = reflect::make_map(&mt);
    let k = |s: &str| s.to_string().to_value();
    assert_eq!(m.len(), 0);
    m.set_map_index(&k("a"), &1isize.to_value());
    m.set_map_index(&k("b"), &2isize.to_value());
    assert_eq!(m.len(), 2);
    assert_eq!(m.map_index(&k("a")).int(), 1);
    assert!(!m.map_index(&k("zz")).is_valid());
    m.set_map_index(&k("a"), &10isize.to_value());
    assert_eq!(m.map_index(&k("a")).int(), 10);
    let mut keys: Vec<String> = m.map_keys().iter().map(|k| k.text()).collect();
    keys.sort();
    assert_eq!(keys, ["a", "b"]);
    // Deleting with an invalid element.
    m.set_map_index(&k("a"), &Value::default());
    assert_eq!(m.len(), 1);
    assert!(!m.map_index(&k("a")).is_valid());
    // Deleting a missing key is fine.
    m.set_map_index(&k("nope"), &Value::default());
    // Values obtained from a map are not addressable or settable.
    assert!(!m.map_index(&k("b")).can_set());
    // Maps are references.
    let alias = m.clone();
    alias.set_map_index(&k("c"), &3isize.to_value());
    assert_eq!(m.len(), 2);
    // Nil map.
    let nil = reflect::zero(&mt);
    assert_eq!(nil.len(), 0);
    assert!(!nil.map_index(&k("a")).is_valid());
    assert!(nil.map_keys().is_empty());
    assert_eq!(
        panic_message(|| nil.set_map_index(&k("a"), &1isize.to_value())),
        "assignment to entry in nil map"
    );
    nil.set_map_index(&k("a"), &Value::default());
    // Type errors.
    assert!(
        panic_message(|| m.set_map_index(&1isize.to_value(), &1isize.to_value()))
            .contains("value of type int is not assignable to type string")
    );
    assert!(panic_message(|| m.map_index(&1isize.to_value()))
        .contains("reflect.Value.MapIndex: value of type int is not assignable to type string"));
    assert_eq!(
        panic_message(|| 1isize.to_value().map_index(&1isize.to_value())),
        "reflect: call of reflect.Value.MapIndex on int Value"
    );
}

#[test]
fn map_nan_and_interface_keys() {
    let mt = ty::<BTreeMap<u64, isize>>();
    let ft = reflect::map_of(&ty::<f64>(), &ty::<isize>());
    let m = reflect::make_map(&ft);
    m.set_map_index(&f64::NAN.to_value(), &1isize.to_value());
    m.set_map_index(&f64::NAN.to_value(), &2isize.to_value());
    assert_eq!(m.len(), 2, "NaN keys are never equal");
    assert!(!m.map_index(&f64::NAN.to_value()).is_valid());
    m.set_map_index(&0.0f64.to_value(), &3isize.to_value());
    assert_eq!(m.map_index(&(-0.0f64).to_value()).int(), 3);
    let _ = mt;
    // Interface keys hash by dynamic value; incomparable ones panic.
    let it = reflect::map_of(&any(), &ty::<isize>());
    let m = reflect::make_map(&it);
    m.set_map_index(&boxed(1isize), &1isize.to_value());
    m.set_map_index(&boxed(1i64), &2isize.to_value());
    assert_eq!(m.len(), 2);
    assert_eq!(m.map_index(&boxed(1isize)).int(), 1);
    assert!(
        panic_message(|| m.set_map_index(&boxed(vec![1u8]), &1isize.to_value()))
            .contains("hash of unhashable type []uint8")
    );
}

#[test]
fn map_iter() {
    let mt = ty::<BTreeMap<isize, String>>();
    let m = BTreeMap::from([
        (1isize, "one".to_string()),
        (2, "two".into()),
        (3, "three".into()),
    ])
    .to_value();
    let mut it = m.map_range();
    let mut seen = Vec::new();
    while it.next() {
        seen.push((it.key().int(), it.value().text()));
    }
    seen.sort();
    assert_eq!(
        seen,
        [(1, "one".into()), (2, "two".into()), (3, "three".into())]
    );
    assert!(panic_message(|| it.next()).contains("MapIter.Next called on exhausted iterator"));
    assert!(panic_message(|| it.key()).contains("MapIter.Key called on exhausted iterator"));
    assert!(panic_message(|| it.value()).contains("MapIter.Value called on exhausted iterator"));
    // Before Next.
    let it2 = m.map_range();
    assert!(panic_message(|| it2.key()).contains("MapIter.Key called before Next"));
    assert!(panic_message(|| it2.value()).contains("MapIter.Value called before Next"));
    // Reset and nil maps.
    let mut it3 = reflect::zero(&mt).map_range();
    assert!(!it3.next());
    it3.reset(&m);
    assert!(it3.next());
    it3.reset(&Value::default());
    assert!(panic_message(|| it3.next()).contains("does not have an associated map Value"));
    assert!(panic_message(|| it3.reset(&1isize.to_value()))
        .contains("call of reflect.MapIter.Reset on int Value"));
    // Deleting an entry during iteration skips it.
    let m =
        BTreeMap::from([(1isize, "a".to_string()), (2, "b".into()), (3, "c".into())]).to_value();
    let mut it = m.map_range();
    assert!(it.next());
    let first = it.key().int();
    for k in m.map_keys() {
        if k.int() != first {
            m.set_map_index(&k, &Value::default());
        }
    }
    assert!(!it.next());
    // SetIterKey / SetIterValue.
    let m = BTreeMap::from([(7isize, "seven".to_string())]).to_value();
    let mut it = m.map_range();
    assert!(it.next());
    let k = reflect::new(&ty::<isize>()).elem();
    let v = reflect::new(&any()).elem();
    k.set_iter_key(&it);
    v.set_iter_value(&it);
    assert_eq!(k.int(), 7);
    assert_eq!(v.elem().text(), "seven");
    assert!(
        panic_message(|| reflect::new(&ty::<String>()).elem().set_iter_key(&it))
            .contains("MapIter.SetKey: value of type int is not assignable to type string")
    );
    assert!(panic_message(|| reflect::new(&ty::<isize>())
        .elem()
        .set_iter_key(&m.map_range()))
    .contains("reflect: Value.SetIterKey called before Next"));
}

// ---------------------------------------------------------------------------
// Channels and select.

#[test]
fn channels() {
    let ct = reflect::chan_of(ChanDir::Both, &ty::<isize>());
    let c = reflect::make_chan(&ct, 2);
    assert_eq!((c.len(), c.cap()), (0, 2));
    c.send(&1isize.to_value());
    assert!(c.try_send(&2isize.to_value()));
    assert!(!c.try_send(&3isize.to_value()));
    assert_eq!(c.len(), 2);
    let (x, ok) = c.recv();
    assert!(ok);
    assert_eq!(x.int(), 1);
    let (x, ok) = c.try_recv();
    assert!(ok);
    assert_eq!(x.int(), 2);
    let (x, ok) = c.try_recv();
    assert!(!x.is_valid() && !ok);
    c.close();
    let (x, ok) = c.recv();
    assert!(!ok);
    assert_eq!(x.int(), 0);
    let (x, ok) = c.try_recv();
    assert!(x.is_valid() && !ok);
    assert!(panic_message(|| c.send(&1isize.to_value())).contains("send on closed channel"));
    assert!(panic_message(|| c.close()).contains("close of closed channel"));
    // Direction checks.
    let r = reflect::chan_of(ChanDir::Recv, &ty::<isize>());
    let rc = reflect::zero(&r);
    assert!(panic_message(|| rc.close()).contains("close of receive-only channel"));
    assert!(panic_message(|| rc.send(&1isize.to_value())).contains("send on recv-only channel"));
    let s = reflect::zero(&reflect::chan_of(ChanDir::Send, &ty::<isize>()));
    assert!(panic_message(|| s.recv()).contains("recv on send-only channel"));
    assert!(panic_message(|| s.try_recv()).contains("recv on send-only channel"));
    assert!(panic_message(|| reflect::make_chan(&r, 0)).contains("unidirectional channel type"));
    assert!(panic_message(|| reflect::make_chan(&ty::<isize>(), 0))
        .contains("MakeChan of non-chan type"));
    assert!(panic_message(|| reflect::make_chan(&ct, -1)).contains("negative buffer size"));
    assert!(panic_message(|| c.send(&"x".to_string().to_value()))
        .contains("value of type string is not assignable to type int"));
    // Nil channel: TryRecv/TrySend never proceed.
    let nil = reflect::zero(&ct);
    assert!(!nil.try_send(&1isize.to_value()));
    let (x, ok) = nil.try_recv();
    assert!(!x.is_valid() && !ok);
}

#[test]
fn unbuffered_channel_rendezvous() {
    let ct = reflect::chan_of(ChanDir::Both, &ty::<isize>());
    let c = reflect::make_chan(&ct, 0);
    assert!(!c.try_send(&1isize.to_value()), "no receiver is waiting");
    let c2 = c.clone();
    let h = std::thread::spawn(move || {
        for i in 0..5isize {
            c2.send(&i.to_value());
        }
        c2.close();
    });
    let mut got = Vec::new();
    loop {
        let (x, ok) = c.recv();
        if !ok {
            break;
        }
        got.push(x.int());
    }
    h.join().unwrap();
    assert_eq!(got, vec![0, 1, 2, 3, 4]);
    // Value::seq drains a channel.
    let c = reflect::make_chan(&ct, 3);
    for i in 0..3isize {
        c.send(&i.to_value());
    }
    c.close();
    assert_eq!(c.seq().map(|v| v.int()).collect::<Vec<_>>(), vec![0, 1, 2]);
}

fn case(dir: SelectDir, chan: &Value, send: Option<Value>) -> SelectCase {
    SelectCase {
        dir,
        chan: chan.clone(),
        send: send.unwrap_or_default(),
    }
}

#[test]
fn select_cases() {
    let ct = reflect::chan_of(ChanDir::Both, &ty::<isize>());
    let c1 = reflect::make_chan(&ct, 1);
    let c2 = reflect::make_chan(&ct, 1);
    // Only the default is ready.
    let (i, v, ok) = reflect::select(&[
        case(SelectDir::Recv, &c1, None),
        case(SelectDir::Recv, &c2, None),
        case(SelectDir::Default, &Value::default(), None),
    ]);
    assert_eq!(i, 2);
    assert!(!v.is_valid() && !ok);
    // A send on a buffered channel is ready.
    let (i, _, _) = reflect::select(&[
        case(SelectDir::Recv, &c1, None),
        case(SelectDir::Send, &c2, Some(5isize.to_value())),
    ]);
    assert_eq!(i, 1);
    assert_eq!(c2.len(), 1);
    // A receive.
    let (i, v, ok) = reflect::select(&[
        case(SelectDir::Recv, &c1, None),
        case(SelectDir::Recv, &c2, None),
    ]);
    assert_eq!((i, v.int(), ok), (1, 5, true));
    // Closed channel yields the zero value with ok = false.
    c1.close();
    let (i, v, ok) = reflect::select(&[case(SelectDir::Recv, &c1, None)]);
    assert_eq!((i, v.int(), ok), (0, 0, false));
    // Blocking select woken by another thread.
    let c3 = reflect::make_chan(&ct, 0);
    let c4 = reflect::make_chan(&ct, 0);
    let c3b = c3.clone();
    let h = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(30));
        c3b.send(&42isize.to_value());
    });
    let (i, v, ok) = reflect::select(&[
        case(SelectDir::Recv, &c4, None),
        case(SelectDir::Recv, &c3, None),
    ]);
    h.join().unwrap();
    assert_eq!((i, v.int(), ok), (1, 42, true));
    // Two selects rendezvous with each other.
    let c5 = reflect::make_chan(&ct, 0);
    let c5b = c5.clone();
    let h = std::thread::spawn(move || {
        let never = reflect::make_chan(&reflect::chan_of(ChanDir::Both, &basic(Kind::Int)), 0);
        reflect::select(&[
            case(SelectDir::Recv, &never, None),
            case(SelectDir::Send, &c5b, Some(7isize.to_value())),
        ])
        .0
    });
    let never = reflect::make_chan(&ct, 0);
    let (i, v, _) = reflect::select(&[
        case(SelectDir::Recv, &never, None),
        case(SelectDir::Recv, &c5, None),
    ]);
    assert_eq!((i, v.int()), (1, 7));
    assert_eq!(h.join().unwrap(), 1);
    // Validation.
    assert!(panic_message(|| reflect::select(&[
        case(SelectDir::Default, &Value::default(), None),
        case(SelectDir::Default, &Value::default(), None),
    ]))
    .contains("multiple default cases"));
    assert!(
        panic_message(|| reflect::select(&[case(SelectDir::Default, &c1, None)]))
            .contains("default case has Chan value")
    );
    assert!(
        panic_message(|| reflect::select(&[case(SelectDir::Send, &c2, None)]))
            .contains("SendDir case missing Send value")
    );
    assert!(panic_message(|| reflect::select(&[case(
        SelectDir::Recv,
        &c2,
        Some(1isize.to_value())
    )]))
    .contains("RecvDir case has Send value"));
}

// ---------------------------------------------------------------------------
// Functions: Call, CallSlice, MakeFunc, variadics.

#[test]
fn call_and_variadic() {
    let add = reflect::func(|(a, b): (isize, isize)| reflect::One(a + b));
    let out = add.call(&[3isize.to_value(), 4isize.to_value()]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].int(), 7);
    assert_eq!(add.type_().to_string(), "func(int, int) int");
    // Argument errors.
    assert_eq!(
        panic_message(|| add.call(&[1isize.to_value()])),
        "reflect: Call with too few input arguments"
    );
    assert_eq!(
        panic_message(|| add.call(&[1isize.to_value(), 2isize.to_value(), 3isize.to_value()])),
        "reflect: Call with too many input arguments"
    );
    assert_eq!(
        panic_message(|| add.call(&[1isize.to_value(), "x".to_string().to_value()])),
        "reflect: Call using string as type int"
    );
    assert_eq!(
        panic_message(|| add.call(&[1isize.to_value(), Value::default()])),
        "reflect: Call using zero Value argument"
    );
    assert_eq!(
        panic_message(|| 1isize.to_value().call(&[])),
        "reflect: call of reflect.Value.Call on int Value"
    );
    assert_eq!(
        panic_message(|| reflect::zero(&add.type_()).call(&[1isize.to_value(), 2isize.to_value()])),
        "reflect.Value.Call: call of nil function"
    );
    // Multiple results and no results.
    let divmod = reflect::func(|(a, b): (isize, isize)| reflect::Multi((a / b, a % b)));
    let out = divmod.call(&[17isize.to_value(), 5isize.to_value()]);
    assert_eq!((out[0].int(), out[1].int()), (3, 2));
    assert_eq!(divmod.type_().to_string(), "func(int, int) (int, int)");
    let nothing = reflect::func(|(): ()| ());
    assert!(nothing.call(&[]).is_empty());
    // Variadic.
    let sum = reflect::func_variadic(|(base, xs): (isize, Vec<isize>)| {
        reflect::One(base + xs.iter().sum::<isize>())
    });
    assert_eq!(sum.type_().to_string(), "func(int, ...int) int");
    assert!(sum.type_().is_variadic());
    let out = sum.call(&[1isize.to_value(), 2isize.to_value(), 3isize.to_value()]);
    assert_eq!(out[0].int(), 6);
    let out = sum.call(&[1isize.to_value()]);
    assert_eq!(out[0].int(), 1);
    let out = sum.call_slice(&[10isize.to_value(), ints(&[1, 2])]);
    assert_eq!(out[0].int(), 13);
    assert_eq!(
        panic_message(|| sum.call(&[])),
        "reflect: Call with too few input arguments"
    );
    assert_eq!(
        panic_message(|| add.call_slice(&[1isize.to_value(), ints(&[1])])),
        "reflect: CallSlice of non-variadic function"
    );
    assert_eq!(
        panic_message(|| sum.call(&[1isize.to_value(), "x".to_string().to_value()])),
        "reflect: cannot use string as type int in Call"
    );
    // Assignability of arguments to interface parameters.
    let describe = reflect::func(|(v,): (Value,)| reflect::One(v.type_().to_string()));
    let out = describe.call(&[3u8.to_value()]);
    assert_eq!(out[0].text(), "uint8");
}

#[test]
fn make_func_values() {
    let ft = reflect::func_of(
        &[ty::<isize>(), ty::<isize>()],
        &[ty::<isize>(), ty::<String>()],
        false,
    );
    let f = reflect::make_func(&ft, |args| {
        vec![
            ((args[0].int() * args[1].int()) as isize).to_value(),
            "done".to_string().to_value(),
        ]
    });
    assert_eq!(f.type_(), ft);
    let out = f.call(&[6isize.to_value(), 7isize.to_value()]);
    assert_eq!(out[0].int(), 42);
    assert_eq!(out[1].text(), "done");
    assert!(!f.is_nil());
    assert!(
        panic_message(|| reflect::make_func(&ty::<isize>(), |_| vec![]))
            .contains("MakeFunc with non-Func type")
    );
    // Results are checked and assigned.
    let bad_count = reflect::make_func(&ft, |_| vec![]);
    assert!(
        panic_message(|| bad_count.call(&[1isize.to_value(), 2isize.to_value()]))
            .contains("wrong return count from function created by MakeFunc")
    );
    let bad_type = reflect::make_func(&ft, |_| {
        vec!["x".to_string().to_value(), "y".to_string().to_value()]
    });
    assert!(
        panic_message(|| bad_type.call(&[1isize.to_value(), 2isize.to_value()]))
            .contains("reflect.MakeFunc: value of type string is not assignable to type int")
    );
    let zero = reflect::make_func(&ft, |_| vec![Value::default(), Value::default()]);
    assert!(
        panic_message(|| zero.call(&[1isize.to_value(), 2isize.to_value()]))
            .contains("returned zero Value")
    );
    // A result assignable to an interface type is converted.
    let it = reflect::func_of(&[], &[any()], false);
    let g = reflect::make_func(&it, |_| vec![5isize.to_value()]);
    let r = g.call(&[]);
    assert_eq!(r[0].kind(), Kind::Interface);
    assert_eq!(r[0].elem().int(), 5);
}

#[test]
fn seq_and_seq2() {
    // Integers.
    let v: Vec<i64> = 4isize.to_value().seq().map(|v| v.int()).collect();
    assert_eq!(v, [0, 1, 2, 3]);
    let v: Vec<u64> = 3u8.to_value().seq().map(|v| v.uint()).collect();
    assert_eq!(v, [0, 1, 2]);
    assert_eq!(0isize.to_value().seq().count(), 0);
    assert_eq!((-3isize).to_value().seq().count(), 0);
    // Slices and arrays yield indices; Seq2 pairs them with values.
    let s = vec!["a".to_string(), "b".into()].to_value();
    assert_eq!(s.seq().map(|v| v.int()).collect::<Vec<_>>(), [0, 1]);
    let pairs: Vec<(i64, String)> = s.seq2().map(|(i, v)| (i.int(), v.text())).collect();
    assert_eq!(pairs, [(0, "a".into()), (1, "b".into())]);
    let arr = [5u8, 6].to_value();
    assert_eq!(
        arr.seq2().map(|(_, v)| v.uint()).collect::<Vec<_>>(),
        [5, 6]
    );
    // Pointer to array.
    let pa = reflect::new(&ty::<[isize; 3]>());
    assert_eq!(pa.seq().count(), 3);
    assert_eq!(pa.seq2().count(), 3);
    // Strings yield byte offsets and runes.
    let s = "aé😀".to_string().to_value();
    assert_eq!(s.seq().map(|v| v.int()).collect::<Vec<_>>(), [0, 1, 3]);
    let runes: Vec<(i64, i64)> = s.seq2().map(|(i, r)| (i.int(), r.int())).collect();
    assert_eq!(runes, [(0, 97), (1, 233), (3, 0x1f600)]);
    assert_eq!(s.seq2().next().unwrap().1.type_().to_string(), "int32");
    // Maps.
    let m = BTreeMap::from([(1isize, 10isize), (2, 20)]).to_value();
    let mut ks: Vec<i64> = m.seq().map(|k| k.int()).collect();
    ks.sort();
    assert_eq!(ks, [1, 2]);
    let mut kv: Vec<(i64, i64)> = m.seq2().map(|(k, v)| (k.int(), v.int())).collect();
    kv.sort();
    assert_eq!(kv, [(1, 10), (2, 20)]);
    // Functions (iter.Seq / iter.Seq2 shapes), stopping early stops the producer.
    let yield_t = reflect::func_of(&[ty::<isize>()], &[ty::<bool>()], false);
    let seq_t = reflect::func_of(&[yield_t.clone()], &[], false);
    let stopped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = stopped.clone();
    let f = reflect::make_func(&seq_t, move |args| {
        for i in 0..100isize {
            let r = args[0].call(&[i.to_value()]);
            if !r[0].bool() {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
                break;
            }
        }
        vec![]
    });
    assert!(seq_t.can_seq());
    assert!(!seq_t.can_seq2());
    let got: Vec<i64> = f.seq().take(3).map(|v| v.int()).collect();
    assert_eq!(got, [0, 1, 2]);
    assert!(stopped.load(std::sync::atomic::Ordering::SeqCst));
    let y2 = reflect::func_of(&[ty::<isize>(), ty::<String>()], &[ty::<bool>()], false);
    let seq2_t = reflect::func_of(&[y2], &[], false);
    let g = reflect::make_func(&seq2_t, |args| {
        for (i, s) in ["x", "y"].iter().enumerate() {
            if !args[0].call(&[(i as isize).to_value(), s.to_string().to_value()])[0].bool() {
                break;
            }
        }
        vec![]
    });
    let pairs: Vec<(i64, String)> = g.seq2().map(|(a, b)| (a.int(), b.text())).collect();
    assert_eq!(pairs, [(0, "x".into()), (1, "y".into())]);
    // Types that cannot be ranged.
    assert!(!ty::<f64>().can_seq());
    assert!(ty::<isize>().can_seq() && !ty::<isize>().can_seq2());
    assert!(ty::<Vec<u8>>().can_seq2());
    assert!(reflect::pointer_to(&ty::<[u8; 2]>()).can_seq());
    assert!(!reflect::pointer_to(&ty::<Vec<u8>>()).can_seq());
    assert!(panic_message(|| 1.5f64.to_value().seq())
        .contains("float64 cannot produce iter.Seq[Value]"));
    assert!(panic_message(|| 3isize.to_value().seq2())
        .contains("int cannot produce iter.Seq2[Value, Value]"));
}

// ---------------------------------------------------------------------------
// Convert (convertTests subset).

fn conv(v: Value, t: &Type) -> Value {
    v.convert(t)
}

#[test]
fn convert_integers() {
    assert_eq!(conv(300isize.to_value(), &ty::<u8>()).uint(), 44);
    assert_eq!(conv((-1isize).to_value(), &ty::<u8>()).uint(), 255);
    assert_eq!(conv((-1isize).to_value(), &ty::<u64>()).uint(), u64::MAX);
    assert_eq!(conv(200u8.to_value(), &ty::<i8>()).int(), -56);
    assert_eq!(conv(u64::MAX.to_value(), &ty::<i64>()).int(), -1);
    assert_eq!(conv(u64::MAX.to_value(), &ty::<i32>()).int(), -1);
    assert_eq!(conv(0x1_0000_0001u64.to_value(), &ty::<u32>()).uint(), 1);
    assert_eq!(conv(5i8.to_value(), &basic(Kind::Uintptr)).uint(), 5);
    // Integer to float, rounding to float32.
    assert_eq!(
        conv(16_777_217isize.to_value(), &ty::<f32>()).float(),
        16_777_216.0
    );
    assert_eq!(
        conv(u64::MAX.to_value(), &ty::<f64>()).float(),
        u64::MAX as f64
    );
    // Float to integer truncates toward zero.
    assert_eq!(conv(1.9f64.to_value(), &ty::<isize>()).int(), 1);
    assert_eq!(conv((-1.9f64).to_value(), &ty::<isize>()).int(), -1);
    assert_eq!(conv(300.5f64.to_value(), &ty::<u8>()).uint(), 44);
    assert_eq!(
        conv(1e10f64.to_value(), &ty::<u64>()).uint(),
        10_000_000_000
    );
    // Float conversions.
    assert_eq!(conv(0.1f64.to_value(), &ty::<f32>()).float(), 0.1f32 as f64);
    assert!(conv(f64::NAN.to_value(), &ty::<f32>()).float().is_nan());
    assert_eq!(
        conv(1e300f64.to_value(), &ty::<f32>()).float(),
        f64::INFINITY
    );
    assert_eq!(conv(0.5f32.to_value(), &ty::<f64>()).float(), 0.5);
    // Complex.
    let c = conv(
        Complex { re: 0.1, im: 0.2 }.to_value(),
        &basic(Kind::Complex64),
    )
    .complex();
    assert_eq!((c.re, c.im), (0.1f32 as f64, 0.2f32 as f64));
    assert!(!1isize
        .to_value()
        .type_()
        .convertible_to(&basic(Kind::Complex128)));
    assert!(
        panic_message(|| conv(1isize.to_value(), &basic(Kind::Complex128))).contains(
            "reflect.Value.Convert: value of type int cannot be converted to type complex128"
        )
    );
    assert!(!1.5f64.to_value().type_().convertible_to(&ty::<bool>()));
}

#[test]
fn convert_strings_and_slices() {
    let s = |v: Value| v.text();
    assert_eq!(s(conv(65isize.to_value(), &ty::<String>())), "A");
    assert_eq!(s(conv(0x1F600u32.to_value(), &ty::<String>())), "😀");
    assert_eq!(s(conv((-1isize).to_value(), &ty::<String>())), "\u{FFFD}");
    assert_eq!(s(conv(0xD800isize.to_value(), &ty::<String>())), "\u{FFFD}");
    assert_eq!(
        s(conv(0x110000isize.to_value(), &ty::<String>())),
        "\u{FFFD}"
    );
    assert_eq!(s(conv(u64::MAX.to_value(), &ty::<String>())), "\u{FFFD}");
    assert_eq!(
        s(conv((1i64 << 32).to_value(), &ty::<String>())),
        "\u{FFFD}"
    );
    assert_eq!(s(conv(vec![104u8, 105].to_value(), &ty::<String>())), "hi");
    assert_eq!(
        s(conv(vec![0x68i32, 0x1F600, -1].to_value(), &ty::<String>())),
        "h😀\u{FFFD}"
    );
    let bytes = conv("hé".to_string().to_value(), &ty::<Vec<u8>>());
    assert_eq!(bytes.bytes(), vec![0x68, 0xc3, 0xa9]);
    let runes = conv("hé😀".to_string().to_value(), &ty::<Vec<i32>>());
    assert_eq!(runes.interface::<Vec<i32>>(), vec![0x68, 0xe9, 0x1F600]);
    // Invalid UTF-8 becomes one U+FFFD per bad byte.
    let bad = Value::from_string(&ty::<String>(), [0x61u8, 0xff, 0xe1, 0x80, 0x62]);
    let r = conv(bad, &ty::<Vec<i32>>());
    assert_eq!(
        r.interface::<Vec<i32>>(),
        vec![0x61, 0xFFFD, 0xFFFD, 0xFFFD, 0x62]
    );
    // Not convertible.
    assert!(!"x"
        .to_string()
        .to_value()
        .type_()
        .convertible_to(&ty::<isize>()));
    assert!(!ints(&[]).type_().convertible_to(&ty::<String>()));
    // Slice to array.
    let arr = conv(ints(&[1, 2, 3, 4]), &ty::<[isize; 3]>());
    assert_eq!(arr.interface::<[isize; 3]>(), [1, 2, 3]);
    assert!(panic_message(|| conv(ints(&[1]), &ty::<[isize; 3]>()))
        .contains("cannot convert slice with length 1 to array with length 3"));
    assert!(ints(&[1, 2]).can_convert(&ty::<[isize; 2]>()));
    assert!(!ints(&[1, 2]).can_convert(&ty::<[isize; 3]>()));
    assert!(ints(&[1, 2]).type_().convertible_to(&ty::<[isize; 3]>()));
    let p = conv(ints(&[1, 2, 3]), &reflect::pointer_to(&ty::<[isize; 2]>()));
    assert_eq!(p.elem().index(1).int(), 2);
    assert!(!ints(&[1]).can_convert(&reflect::pointer_to(&ty::<[isize; 2]>())));
}

#[test]
fn convert_between_identical_underlying_types() {
    let a = reflect::struct_of(&[sf("A", ty::<isize>()), sf("B", ty::<String>())]);
    let tagged = reflect::struct_of(&[
        sf("A", ty::<isize>()).with_tag("x"),
        sf("B", ty::<String>()).with_tag("y"),
    ]);
    // Tags are ignored for conversion, but not for assignability.
    assert!(a.convertible_to(&tagged));
    assert!(!a.assignable_to(&tagged));
    let v = reflect::new(&a).elem();
    v.field(0).set_int(5);
    let c = v.convert(&tagged);
    assert_eq!(c.type_(), tagged);
    assert_eq!(c.field(0).int(), 5);
    // Conversion copies; it does not alias.
    v.field(0).set_int(6);
    assert_eq!(c.field(0).int(), 5);
    assert!(!c.can_addr());
    // *a -> *tagged.
    assert!(reflect::pointer_to(&a).convertible_to(&reflect::pointer_to(&tagged)));
    // Different shapes are not convertible.
    assert!(!a.convertible_to(&reflect::struct_of(&[sf("A", ty::<isize>())])));
    // To interfaces.
    let to_any = 5isize.to_value().convert(&any());
    assert_eq!(to_any.kind(), Kind::Interface);
    assert_eq!(to_any.elem().int(), 5);
    let back = to_any.convert(&any());
    assert_eq!(back.elem().int(), 5);
    let err = Type::error_type();
    assert!(!ty::<isize>().convertible_to(&err));
    assert!(any().convertible_to(&any()));
    // Channels of differing direction.
    let both = reflect::chan_of(ChanDir::Both, &ty::<isize>());
    let recv = reflect::chan_of(ChanDir::Recv, &ty::<isize>());
    assert!(both.convertible_to(&recv));
    assert!(both.assignable_to(&recv));
    assert!(!recv.convertible_to(&both));
}

#[test]
fn assignability() {
    let named_like = reflect::struct_of(&[sf("A", ty::<isize>())]);
    assert!(named_like.assignable_to(&named_like));
    assert!(ty::<isize>().assignable_to(&any()));
    assert!(!ty::<isize>().assignable_to(&Type::error_type()));
    assert!(!ty::<isize>().assignable_to(&ty::<i64>()));
    assert!(any().assignable_to(&any()));
    assert!(ty::<Vec<isize>>().assignable_to(&reflect::slice_of(&ty::<isize>())));
    assert!(Type::error_type().assignable_to(&any()));
    assert!(ty::<isize>().implements(&any()));
    assert!(!ty::<isize>().implements(&Type::error_type()));
    assert!(Type::error_type().implements(&Type::error_type()));
    assert!(panic_message(|| ty::<isize>().implements(&ty::<isize>()))
        .contains("non-interface type passed to Type.Implements"));
}

// ---------------------------------------------------------------------------
// New, Zero, MakeSlice, MakeMap, Value-of-Rust round trips.

#[test]
fn constructors() {
    let z = reflect::zero(&pt_type());
    assert!(z.is_zero());
    assert!(!z.can_addr());
    assert_eq!(z.field(1).float(), 0.0);
    assert!(panic_message(|| z.field(0).set_int(1)).contains("unaddressable"));
    let s = reflect::make_slice(&ty::<Vec<String>>(), 2, 5);
    assert_eq!((s.len(), s.cap()), (2, 5));
    assert_eq!(s.index(1).text(), "");
    assert!(!s.is_nil());
    assert!(panic_message(|| reflect::make_slice(&ty::<isize>(), 1, 1))
        .contains("MakeSlice of non-slice type"));
    assert!(
        panic_message(|| reflect::make_slice(&ty::<Vec<u8>>(), -1, 1)).contains("negative len")
    );
    assert!(
        panic_message(|| reflect::make_slice(&ty::<Vec<u8>>(), 1, -1)).contains("negative cap")
    );
    assert!(panic_message(|| reflect::make_slice(&ty::<Vec<u8>>(), 2, 1)).contains("len > cap"));
    assert!(panic_message(|| reflect::make_map(&ty::<isize>()))
        .contains("MakeMapWithSize of non-map type"));
    reflect::make_map_with_size(&ty::<BTreeMap<u8, u8>>(), 100);
    let p = reflect::new(&pt_type());
    assert_eq!(p.type_().to_string(), "*struct { A int; B float64 }");
    assert!(p.elem().can_set());
    p.elem().field(0).set_int(4);
    assert_eq!(Pt::from_value(&p.elem()).unwrap().a, 4);
}

#[test]
fn rust_round_trips() {
    let m: HashMap<String, Vec<Option<u8>>> =
        HashMap::from([("a".to_string(), vec![Some(1), None]), ("b".into(), vec![])]);
    let v = m.to_value();
    let back = HashMap::<String, Vec<Option<u8>>>::from_value(&v).unwrap();
    assert_eq!(back, m);
    let tup = (1u8, "x".to_string(), vec![1.5f64]);
    assert_eq!(
        <(u8, String, Vec<f64>)>::from_value(&tup.to_value()).unwrap(),
        tup
    );
    let arr = [Some(1i16), None];
    assert_eq!(
        <[Option<i16>; 2]>::from_value(&arr.to_value()).unwrap(),
        arr
    );
    assert_eq!(char::from_value(&'é'.to_value()).unwrap(), 'é');
    assert_eq!(
        Box::<isize>::from_value(&5isize.to_value()).unwrap(),
        Box::new(5)
    );
    // Mismatches are errors, not panics.
    assert!(isize::from_value(&"x".to_string().to_value()).is_err());
    assert!(u8::from_value(&300u16.to_value()).is_err());
    assert!(<[u8; 3]>::from_value(&[1u8, 2].to_value()).is_err());
    assert!(char::from_value(&0xD800i32.to_value()).is_err());
    assert!(String::from_value(&Value::default()).is_err());
    // Values read through any are unwrapped.
    assert_eq!(
        isize::from_value(&boxed(9isize).elem().to_value().elem()).unwrap(),
        9
    );
}

#[test]
fn edit_copies_back() {
    let mut v = vec![1u8, 2, 3];
    reflect::edit(&mut v, |p| {
        p.elem().index(0).set_uint(9);
        let grown = reflect::append(&p.elem(), &[4u8.to_value()]);
        p.elem().set(&grown);
    })
    .unwrap();
    assert_eq!(v, vec![9, 2, 3, 4]);
    let mut s = (1isize, "a".to_string());
    reflect::edit(&mut s, |p| {
        p.elem().field(1).set_string("zz");
    })
    .unwrap();
    assert_eq!(s.1, "zz");
}

// ---------------------------------------------------------------------------
// ValueError, Kind-based panics, misc Value behaviour.

#[test]
fn value_error_payload() {
    quiet();
    let e = catch_unwind(|| 1isize.to_value().bool()).unwrap_err();
    let ve = e
        .downcast_ref::<reflect::ValueError>()
        .expect("ValueError payload");
    assert_eq!(ve.method, "reflect.Value.Bool");
    assert_eq!(ve.kind, Kind::Int);
    assert_eq!(
        ve.error(),
        "reflect: call of reflect.Value.Bool on int Value"
    );
    assert_eq!(ve.to_string(), ve.error());
    let e = catch_unwind(|| Value::default().len()).unwrap_err();
    let ve = e.downcast_ref::<reflect::ValueError>().unwrap();
    assert_eq!(
        ve.error(),
        "reflect: call of reflect.Value.Len on zero Value"
    );
}

#[test]
fn len_and_cap() {
    assert_eq!(vec![1u8, 2].to_value().len(), 2);
    assert_eq!([0u8; 5].to_value().len(), 5);
    assert_eq!("héllo".to_string().to_value().len(), 6);
    assert_eq!(BTreeMap::from([(1u8, 1u8)]).to_value().len(), 1);
    assert_eq!(reflect::new(&ty::<[u8; 7]>()).len(), 7);
    assert_eq!(reflect::new(&ty::<[u8; 7]>()).cap(), 7);
    assert!(panic_message(|| reflect::new(&ty::<u8>()).len())
        .contains("call of reflect.Value.Len on ptr to non-array Value"));
    assert_eq!(
        panic_message(|| 1isize.to_value().len()),
        "reflect: call of reflect.Value.Len on int Value"
    );
    assert_eq!(
        panic_message(|| "x".to_string().to_value().cap()),
        "reflect: call of reflect.Value.Cap on string Value"
    );
    let ct = reflect::chan_of(ChanDir::Both, &ty::<u8>());
    assert_eq!(reflect::make_chan(&ct, 4).cap(), 4);
    assert_eq!(reflect::zero(&ct).cap(), 0);
    assert_eq!(reflect::make_slice(&ty::<Vec<u8>>(), 1, 9).cap(), 9);
}

#[test]
fn fields_and_field_by_index() {
    let inner = reflect::struct_of(&[sf("N", ty::<isize>())]);
    let outer = reflect::struct_of(&[
        sf("I", inner.clone()).embedded(),
        sf("P", reflect::pointer_to(&inner)),
        sf("S", ty::<String>()),
    ]);
    let v = reflect::new(&outer).elem();
    assert_eq!(v.num_field(), 3);
    assert_eq!(v.field_by_index(&[0, 0]).int(), 0);
    v.field_by_index(&[0, 0]).set_int(8);
    assert_eq!(v.field_by_name("N").int(), 8);
    assert!(!v.field_by_name("Nope").is_valid());
    assert!(v.field_by_name_func(|s| s == "S").is_valid());
    // Nil pointer on the index path.
    let outer2 = reflect::struct_of(&[sf("P", reflect::pointer_to(&inner)).embedded()]);
    let v2 = reflect::new(&outer2).elem();
    assert!(panic_message(|| v2.field_by_index(&[0, 0]))
        .contains("indirection through nil pointer to embedded struct"));
    let err = v2.field_by_index_err(&[0, 0]).unwrap_err();
    assert_eq!(
        err.to_string(),
        "reflect: indirection through nil pointer to embedded struct field "
    );
    assert!(v.field_by_index_err(&[0, 0]).is_ok());
    assert_eq!(
        panic_message(|| v.field(9)),
        "reflect: Field index out of range"
    );
    assert_eq!(
        panic_message(|| 1isize.to_value().field(0)),
        "reflect: call of reflect.Value.Field on int Value"
    );
    let names: Vec<String> = v.fields().map(|(f, _)| f.name).collect();
    assert_eq!(names, ["I", "P", "S"]);
}

#[test]
fn unsafe_pointer_identity() {
    let p = reflect::new(&ty::<isize>());
    let q = p.clone();
    assert_eq!(p.pointer(), q.pointer());
    assert_ne!(p.pointer(), reflect::new(&ty::<isize>()).pointer());
    assert_eq!(p.unsafe_pointer(), q.unsafe_pointer());
    assert_eq!(reflect::zero(&ty::<Option<u8>>()).pointer(), 0);
    assert!(reflect::zero(&ty::<Option<u8>>()).unsafe_pointer().is_nil());
    assert_eq!(p.elem().unsafe_addr(), p.pointer());
    assert!(panic_message(|| 1isize.to_value().unsafe_addr()).contains("unaddressable"));
    // value_at reinterprets a pointer obtained from this package.
    p.elem().set_int(11);
    let again = reflect::value_at(&ty::<isize>(), &p.unsafe_pointer());
    assert_eq!(again.elem().int(), 11);
    again.elem().set_int(12);
    assert_eq!(p.elem().int(), 12);
    // slice_at views elements of an existing slice.
    let s = ints(&[1, 2, 3, 4]);
    let up = s.slice(1, 4).unsafe_pointer();
    let t = reflect::slice_at(&ty::<isize>(), &up, 2);
    assert_eq!(t.interface::<Vec<isize>>(), vec![2, 3]);
    t.index(0).set_int(20);
    assert_eq!(s.index(1).int(), 20);
    // Maps, channels and funcs have identities too.
    let m = reflect::make_map(&ty::<BTreeMap<u8, u8>>());
    assert_ne!(m.pointer(), 0);
    assert_eq!(m.pointer(), m.clone().pointer());
    // SetPointer stores an UnsafePointer value.
    let v = reflect::new(&basic(Kind::UnsafePointer));
    v.elem().set_pointer(&p.unsafe_pointer());
    assert_eq!(v.elem().unsafe_pointer(), p.unsafe_pointer());
}

#[test]
fn value_to_string_table() {
    // Value.String for scalars and the `<T Value>` form for the rest
    // (valueToStringTests format through fmt; here only String is checked).
    assert_eq!("abc".to_string().to_value().text(), "abc");
    assert_eq!(123isize.to_value().text(), "<int Value>");
    assert_eq!(123.5f64.to_value().text(), "<float64 Value>");
    assert_eq!(123u8.to_value().text(), "<uint8 Value>");
    assert_eq!(
        Pt { a: 1, b: 2.0 }.to_value().text(),
        "<struct { A int; B float64 } Value>"
    );
    assert_eq!(
        reflect::new(&ty::<[isize; 10]>()).text(),
        "<*[10]int Value>"
    );
    assert_eq!(Value::default().text(), "<invalid Value>");
}

// ---------------------------------------------------------------------------
// Interop with the fmt and text/template value models.

#[test]
fn fmt_operands_from_reflect_values() {
    use rust_stdlib::printf as fmt;
    let p = Pt { a: 1, b: 0.5 }.to_value();
    let arg = fmt::Value::from(&p);
    assert_eq!(
        fmt::sprintf("%v|%+v|%T", &[arg.clone(), arg.clone(), arg.clone()]),
        "{1 0.5}|{A:1 B:0.5}|struct { A int; B float64 }"
    );
    assert_eq!(
        fmt::sprintf("%#v", &[arg]),
        "struct { A int; B float64 }{A:1, B:0.5}"
    );
    // The same output as a hand-built operand.
    let hand = fmt::Value::strukt(
        "struct { A int; B float64 }",
        vec![("A", fmt::Value::int(1)), ("B", fmt::Value::Float64(0.5))],
    );
    for verb in ["%v", "%+v", "%#v", "%T"] {
        assert_eq!(
            fmt::sprintf(verb, &[fmt::Value::from(&p)]),
            fmt::sprintf(verb, &[hand.clone()]),
            "{verb}"
        );
    }
    let cases: Vec<(Value, &str, &str)> = vec![
        (vec![1u8, 2].to_value(), "%v %x %T", "[1 2] 0102 []uint8"),
        (
            BTreeMap::from([("b".to_string(), 2i32), ("a".into(), 1)]).to_value(),
            "%v %#v",
            "map[a:1 b:2] map[string]int32{\"a\":1, \"b\":2}",
        ),
        (Some(3isize).to_value(), "%T", "*int"),
        (None::<isize>.to_value(), "%v %#v", "<nil> (*int)(nil)"),
        ([1i8, 2].to_value(), "%v %#v", "[1 2] [2]int8{1, 2}"),
        ("héy".to_string().to_value(), "%q %v", "\"héy\" héy"),
        (Complex { re: 1.0, im: -2.0 }.to_value(), "%v", "(1-2i)"),
        (boxed(7isize), "%v", "7"),
        (reflect::zero(&any()), "%v", "<nil>"),
        (Value::default(), "%v", "<invalid reflect.Value>"),
    ];
    for (v, verb, want) in cases {
        let args: Vec<fmt::Value> = verb.split(' ').map(|_| fmt::Value::from(&v)).collect();
        assert_eq!(fmt::sprintf(verb, &args), want, "{verb}");
    }
    // Debug renders the value like %v.
    assert_eq!(
        format!("{:?}", Pt { a: 1, b: 0.5 }.to_value()),
        "struct { A int; B float64 }({1 0.5})"
    );
    assert_eq!(format!("{:?}", Value::default()), "<invalid Value>");
}

#[test]
fn template_values_from_reflect_values() {
    use rust_stdlib::text::template;
    let data = (
        Pt { a: 3, b: 1.5 },
        vec!["x".to_string(), "y".into()],
        BTreeMap::from([("k".to_string(), 9i32)]),
    );
    let v = data.to_value();
    let tv = template::Value::from(&v);
    let t = template::new("t")
        .parse("{{.F0.A}} {{.F0.B}} {{range .F1}}[{{.}}]{{end}} {{index .F2 \"k\"}} {{len .F1}}")
        .unwrap();
    let mut out = Vec::new();
    t.execute_value(&mut out, tv).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "3 1.5 [x][y] 9 2");
    // Types convert too.
    let tt = template::value::Type::from(&pt_type());
    assert_eq!(tt.type_string(), "struct { A int; B float64 }");
}

#[test]
fn pointers_into_the_same_object_do_not_deadlock() {
    let t = reflect::struct_of(&[
        sf("A", ty::<isize>()),
        sf("P", reflect::pointer_to(&ty::<isize>())),
    ]);
    let p = reflect::new(&t);
    p.elem().field(0).set_int(5);
    p.elem().field(1).set(&p.elem().field(0).addr());
    assert_eq!(p.elem().field(1).elem().int(), 5);
    p.elem().field(1).elem().set_int(6);
    assert_eq!(p.elem().field(0).int(), 6);
    assert!(reflect::deep_equal_values(&p, &p));
    assert_eq!(
        Value::clone(&p).elem().field(1).pointee().map(|v| v.int()),
        Some(6)
    );
}

#[test]
fn cyclic_values_convert_to_other_models() {
    use rust_stdlib::printf as fmt;
    use rust_stdlib::text::template;
    // type N struct { V int; Next *N } with a node pointing at itself, built
    // from a named type so the cycle is expressible.
    fn n_type() -> Type {
        static T: std::sync::OnceLock<Type> = std::sync::OnceLock::new();
        T.get_or_init(|| {
            fn init() -> reflect::__private::Body {
                let n = n_type();
                reflect::__private::struct_body(
                    vec![
                        reflect::__private::field("V", ty::<isize>(), "", false, ""),
                        reflect::__private::field("Next", reflect::pointer_to(&n), "", false, ""),
                    ],
                    "main",
                )
            }
            Type::declare("main", "N", init, None)
        })
        .clone()
    }
    let p = reflect::new(&n_type());
    p.elem().field(0).set_int(1);
    p.elem().field(1).set(&p);
    // fmt prints the nested pointer as an address, so this terminates.
    let s = fmt::sprintf("%v", &[fmt::Value::from(&p)]);
    assert!(s.starts_with("&{1 0x"), "{s}");
    assert_eq!(fmt::sprintf("%T", &[fmt::Value::from(&p)]), "*main.N");
    // The template conversion cuts the cycle off instead of overflowing.
    let tv = template::Value::from(&p);
    let t = template::new("t").parse("{{.V}} {{.Next.V}}").unwrap();
    let mut out = Vec::new();
    t.execute_value(&mut out, tv).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "1 1");
    // Debug is finite too.
    assert!(format!("{p:?}").starts_with("*main.N(&{1 0x"));
}
