//! `reflect.Append` and `Value.Grow` capacities against Go's `growslice`,
//! including the runtime's malloc size-class rounding. The fixture was
//! produced by running `reflect.Append` on Go 1.27 (darwin/arm64; the 64-bit
//! size classes are the same on every 64-bit Go target): each line is
//! `type len add cap`.
use rust_stdlib::reflect::{self, Kind, StructField, Type};

fn elem(name: &str) -> Type {
    let int64 = Type::basic(Kind::Int64);
    let ptr = reflect::pointer_to(&Type::basic(Kind::Int));
    let field = |n: &str, t: &Type| StructField::new(n, t.clone());
    match name {
        "u8" => Type::basic(Kind::Uint8),
        "i16" => Type::basic(Kind::Int16),
        "i32" => Type::basic(Kind::Int32),
        "i64" => int64,
        "str" => Type::basic(Kind::String),
        "ptr" => ptr,
        "s24" => reflect::struct_of(&[field("A", &int64), field("B", &int64), field("C", &int64)]),
        "p24" => reflect::struct_of(&[field("A", &int64), field("B", &ptr), field("C", &int64)]),
        "b3" => reflect::array_of(3, &Type::basic(Kind::Uint8)),
        "unit" => reflect::struct_of(&[]),
        other => panic!("unknown element type {other}"),
    }
}

#[test]
fn append_and_grow_capacity_match_go() {
    let mut checked = 0;
    for line in include_str!("fixtures/reflect_growslice_caps.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let (et, len, add, want): (Type, isize, usize, usize) = (
            elem(f[0]),
            f[1].parse().unwrap(),
            f[2].parse().unwrap(),
            f[3].parse().unwrap(),
        );
        let st = reflect::slice_of(&et);
        let s = reflect::make_slice(&st, len, len);
        let xs: Vec<_> = (0..add).map(|_| reflect::zero(&et)).collect();
        let a = reflect::append(&s, &xs);
        assert_eq!(a.cap(), want, "Append {line}");
        assert_eq!(a.len(), len as usize + add, "Append len {line}");
        let p = reflect::new(&st).elem();
        p.set(&s);
        p.grow(add as isize);
        assert_eq!(p.cap(), want, "Grow {line}");
        checked += 1;
    }
    assert_eq!(checked, 480);
}
