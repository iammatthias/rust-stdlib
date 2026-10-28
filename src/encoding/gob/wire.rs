//! The wire form of type descriptors: Go's `wireType` and the structs it
//! holds, described to the generic encoder and decoder as ordinary reflect
//! types (as Go does) so that they travel with the standard struct rules.

use std::sync::LazyLock;

use crate::reflect::{self, Kind, StructField, Type, Value};

/// Go's `CommonType`: the name and id every type descriptor starts with. It
/// is a historical artifact, kept for binary compatibility and exported only
/// for the benefit of the package's encoding of type descriptors.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommonType {
    /// The type's name (Go `CommonType.Name`).
    pub name: String,
    /// The type's id (Go `CommonType.Id`, a `typeId`).
    pub id: i32,
}

#[derive(Clone, Debug)]
pub(crate) struct ArrayT {
    pub common: CommonType,
    pub elem: i32,
    pub len: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct SliceT {
    pub common: CommonType,
    pub elem: i32,
}

#[derive(Clone, Debug)]
pub(crate) struct StructT {
    pub common: CommonType,
    pub fields: Vec<(String, i32)>,
}

#[derive(Clone, Debug)]
pub(crate) struct MapT {
    pub common: CommonType,
    pub key: i32,
    pub elem: i32,
}

/// Go `wireType`: exactly one member is set.
#[derive(Clone, Debug, Default)]
pub(crate) struct WireType {
    pub array_t: Option<ArrayT>,
    pub slice_t: Option<SliceT>,
    pub struct_t: Option<StructT>,
    pub map_t: Option<MapT>,
    pub gob_encoder_t: Option<CommonType>,
    pub binary_marshaler_t: Option<CommonType>,
    pub text_marshaler_t: Option<CommonType>,
}

impl WireType {
    /// Go `wireType.string`.
    pub(crate) fn string(&self) -> String {
        if let Some(a) = &self.array_t {
            a.common.name.clone()
        } else if let Some(s) = &self.slice_t {
            s.common.name.clone()
        } else if let Some(s) = &self.struct_t {
            s.common.name.clone()
        } else if let Some(m) = &self.map_t {
            m.common.name.clone()
        } else if let Some(g) = &self.gob_encoder_t {
            g.name.clone()
        } else if let Some(g) = &self.binary_marshaler_t {
            g.name.clone()
        } else if let Some(g) = &self.text_marshaler_t {
            g.name.clone()
        } else {
            "unknown type".to_string()
        }
    }
}

pub(crate) struct WireTypes {
    pub wire_type: Type,
    pub type_id: Type,
    pub string: Type,
    pub int: Type,
    pub common: Type,
    pub array: Type,
    pub slice: Type,
    pub struct_: Type,
    pub field: Type,
    pub map: Type,
    pub gob_encoder: Type,
}

const PKG: &str = "encoding/gob";

fn named_struct(name: &str, fields: &[StructField]) -> Type {
    Type::named(PKG, name, &reflect::struct_of(fields), Vec::new())
}

static TYPES: LazyLock<WireTypes> = LazyLock::new(|| {
    let type_id = Type::named(PKG, "typeId", &Type::basic(Kind::Int32), Vec::new());
    let string = Type::basic(Kind::String);
    let int = Type::basic(Kind::Int);
    let f = StructField::new;
    let common = named_struct(
        "CommonType",
        &[f("Name", string.clone()), f("Id", type_id.clone())],
    );
    let embed = || f("CommonType", common.clone()).embedded();
    let array = named_struct(
        "arrayType",
        &[embed(), f("Elem", type_id.clone()), f("Len", int.clone())],
    );
    let gob_encoder = named_struct("gobEncoderType", &[embed()]);
    let slice = named_struct("sliceType", &[embed(), f("Elem", type_id.clone())]);
    let field = named_struct(
        "fieldType",
        &[f("Name", string.clone()), f("Id", type_id.clone())],
    );
    let struct_ = named_struct(
        "structType",
        &[embed(), f("Field", reflect::slice_of(&field))],
    );
    let map = named_struct(
        "mapType",
        &[
            embed(),
            f("Key", type_id.clone()),
            f("Elem", type_id.clone()),
        ],
    );
    let p = |t: &Type| reflect::pointer_to(t);
    let wire_type = named_struct(
        "wireType",
        &[
            f("ArrayT", p(&array)),
            f("SliceT", p(&slice)),
            f("StructT", p(&struct_)),
            f("MapT", p(&map)),
            f("GobEncoderT", p(&gob_encoder)),
            f("BinaryMarshalerT", p(&gob_encoder)),
            f("TextMarshalerT", p(&gob_encoder)),
        ],
    );
    WireTypes {
        wire_type,
        type_id,
        string,
        int,
        common,
        array,
        slice,
        struct_,
        field,
        map,
        gob_encoder,
    }
});

pub(crate) fn types() -> &'static WireTypes {
    &TYPES
}

fn common_value(t: &WireTypes, c: &CommonType) -> Value {
    Value::from_parts(
        &t.common,
        &[
            Value::from_string(&t.string, c.name.as_bytes()),
            Value::from_int(&t.type_id, c.id as i64),
        ],
    )
}

fn boxed(t: &Type, v: Value) -> Value {
    let p = reflect::new(t);
    p.elem().overwrite(&v);
    p
}

/// The reflect value of a wire type, for the generic encoder.
pub(crate) fn to_value(w: &WireType) -> Value {
    let t = types();
    let id = |x: i32| Value::from_int(&t.type_id, x as i64);
    let nil = |ty: &Type| reflect::zero(&reflect::pointer_to(ty));
    let array = match &w.array_t {
        Some(a) => boxed(
            &t.array,
            Value::from_parts(
                &t.array,
                &[
                    common_value(t, &a.common),
                    id(a.elem),
                    Value::from_int(&t.int, a.len),
                ],
            ),
        ),
        None => nil(&t.array),
    };
    let slice = match &w.slice_t {
        Some(s) => boxed(
            &t.slice,
            Value::from_parts(&t.slice, &[common_value(t, &s.common), id(s.elem)]),
        ),
        None => nil(&t.slice),
    };
    let struct_ = match &w.struct_t {
        Some(s) => {
            let fields: Vec<Value> = s
                .fields
                .iter()
                .map(|(n, i)| {
                    Value::from_parts(
                        &t.field,
                        &[Value::from_string(&t.string, n.as_bytes()), id(*i)],
                    )
                })
                .collect();
            boxed(
                &t.struct_,
                Value::from_parts(
                    &t.struct_,
                    &[
                        common_value(t, &s.common),
                        Value::from_items(&reflect::slice_of(&t.field), &fields),
                    ],
                ),
            )
        }
        None => nil(&t.struct_),
    };
    let map = match &w.map_t {
        Some(m) => boxed(
            &t.map,
            Value::from_parts(&t.map, &[common_value(t, &m.common), id(m.key), id(m.elem)]),
        ),
        None => nil(&t.map),
    };
    let gob = |c: &Option<CommonType>| match c {
        Some(c) => boxed(
            &t.gob_encoder,
            Value::from_parts(&t.gob_encoder, &[common_value(t, c)]),
        ),
        None => nil(&t.gob_encoder),
    };
    Value::from_parts(
        &t.wire_type,
        &[
            array,
            slice,
            struct_,
            map,
            gob(&w.gob_encoder_t),
            gob(&w.binary_marshaler_t),
            gob(&w.text_marshaler_t),
        ],
    )
}

fn common_of(v: &Value) -> CommonType {
    CommonType {
        name: v.field(0).text(),
        id: v.field(1).int() as i32,
    }
}

/// Reads a decoded wire type back out of its reflect value.
pub(crate) fn from_value(v: &Value) -> WireType {
    let target = |i: usize| {
        let f = v.field(i);
        if f.is_nil() {
            None
        } else {
            Some(f.elem())
        }
    };
    WireType {
        array_t: target(0).map(|a| ArrayT {
            common: common_of(&a.field(0)),
            elem: a.field(1).int() as i32,
            len: a.field(2).int(),
        }),
        slice_t: target(1).map(|s| SliceT {
            common: common_of(&s.field(0)),
            elem: s.field(1).int() as i32,
        }),
        struct_t: target(2).map(|s| {
            let fields = s.field(1);
            StructT {
                common: common_of(&s.field(0)),
                fields: (0..fields.len())
                    .map(|i| {
                        let f = fields.index(i);
                        (f.field(0).text(), f.field(1).int() as i32)
                    })
                    .collect(),
            }
        }),
        map_t: target(3).map(|m| MapT {
            common: common_of(&m.field(0)),
            key: m.field(1).int() as i32,
            elem: m.field(2).int() as i32,
        }),
        gob_encoder_t: target(4).map(|g| common_of(&g.field(0))),
        binary_marshaler_t: target(5).map(|g| common_of(&g.field(0))),
        text_marshaler_t: target(6).map(|g| common_of(&g.field(0))),
    }
}
