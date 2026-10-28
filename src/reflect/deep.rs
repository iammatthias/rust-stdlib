//! `DeepEqual` and `VisibleFields`, ported from Go's `deepequal.go` and
//! `visiblefields.go`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use super::data::Data;
use super::kind::Kind;
use super::traits::Reflect;
use super::typ::{StructField, Type};
use super::value::{panic_msg, Value};

type Ident = (usize, Vec<u32>);

fn ident(v: &Value) -> Ident {
    match v.kind() {
        Kind::Pointer => match v.data() {
            Data::Ptr(Some(p)) => (Arc::as_ptr(&p.cell) as usize, p.path.to_vec()),
            _ => (0, Vec::new()),
        },
        Kind::Map => match v.data() {
            Data::Map(Some(m)) => (Arc::as_ptr(&m) as usize, Vec::new()),
            _ => (0, Vec::new()),
        },
        _ => {
            let p = v.pl();
            (Arc::as_ptr(&p.cell) as usize, p.path.to_vec())
        }
    }
}

type Visited = HashSet<(Ident, Ident, usize)>;

fn deep_value_equal(v1: &Value, v2: &Value, visited: &mut Visited) -> bool {
    if !v1.is_valid() || !v2.is_valid() {
        return v1.is_valid() == v2.is_valid();
    }
    if v1.type_() != v2.type_() {
        return false;
    }
    let hard = matches!(
        v1.kind(),
        Kind::Pointer | Kind::Map | Kind::Slice | Kind::Interface
    ) && !v1.is_nil()
        && !v2.is_nil();
    if hard {
        let (mut a1, mut a2) = (ident(v1), ident(v2));
        if a1 > a2 {
            std::mem::swap(&mut a1, &mut a2);
        }
        if !visited.insert((a1, a2, v1.type_().addr())) {
            return true;
        }
    }
    match v1.kind() {
        Kind::Array => (0..v1.len()).all(|i| deep_value_equal(&v1.index(i), &v2.index(i), visited)),
        Kind::Slice => {
            if v1.is_nil() != v2.is_nil() {
                return false;
            }
            if v1.len() != v2.len() {
                return false;
            }
            if v1.unsafe_pointer() == v2.unsafe_pointer() {
                return true;
            }
            (0..v1.len()).all(|i| deep_value_equal(&v1.index(i), &v2.index(i), visited))
        }
        Kind::Interface => {
            if v1.is_nil() || v2.is_nil() {
                return v1.is_nil() == v2.is_nil();
            }
            deep_value_equal(&v1.elem(), &v2.elem(), visited)
        }
        Kind::Pointer => {
            if v1.unsafe_pointer() == v2.unsafe_pointer() {
                return true;
            }
            deep_value_equal(&v1.elem(), &v2.elem(), visited)
        }
        Kind::Struct => {
            (0..v1.num_field()).all(|i| deep_value_equal(&v1.field(i), &v2.field(i), visited))
        }
        Kind::Map => {
            if v1.is_nil() != v2.is_nil() {
                return false;
            }
            if v1.len() != v2.len() {
                return false;
            }
            if ident(v1) == ident(v2) {
                return true;
            }
            let mut it = v1.map_range();
            while it.next() {
                let val1 = it.value();
                let val2 = v2.map_index(&it.key());
                if !val1.is_valid() || !val2.is_valid() || !deep_value_equal(&val1, &val2, visited)
                {
                    return false;
                }
            }
            true
        }
        Kind::Func => v1.is_nil() && v2.is_nil(),
        k if k.is_int() => v1.int() == v2.int(),
        k if k.is_uint() => v1.uint() == v2.uint(),
        Kind::String => v1.string_bytes() == v2.string_bytes(),
        Kind::Bool => v1.bool() == v2.bool(),
        k if k.is_float() => v1.float() == v2.float(),
        k if k.is_complex() => v1.complex() == v2.complex(),
        _ => v1.equal(v2),
    }
}

/// Go `reflect.DeepEqual`: whether `x` and `y` are deeply equal. Values of
/// different types are never equal; NaN differs from itself; pointers are
/// equal if equal or if they point to deeply equal values; cycles are
/// handled; functions are equal only if both nil; a nil slice or map differs
/// from an empty one.
pub fn deep_equal<X: Reflect, Y: Reflect>(x: &X, y: &Y) -> bool {
    deep_equal_values(&x.to_value(), &y.to_value())
}

/// [`deep_equal`] on two dynamic values; an invalid `Value` is Go's untyped
/// `nil`.
pub fn deep_equal_values(x: &Value, y: &Value) -> bool {
    if !x.is_valid() || !y.is_valid() {
        return x.is_valid() == y.is_valid();
    }
    if x.type_() != y.type_() {
        return false;
    }
    deep_value_equal(x, y, &mut HashSet::new())
}

/// Go `reflect.VisibleFields`: all visible fields of struct type `t`,
/// including fields inside anonymous struct members, in index order.
/// Shadowed and ambiguous names are omitted, as Go's selector rules require.
pub fn visible_fields(t: &Type) -> Vec<StructField> {
    if t.kind() != Kind::Struct {
        panic_msg("reflect.VisibleFields of non-struct type");
    }
    struct Walker {
        by_name: HashMap<String, usize>,
        visiting: HashSet<Type>,
        fields: Vec<StructField>,
        index: Vec<usize>,
    }
    impl Walker {
        fn walk(&mut self, t: &Type) {
            if self.visiting.contains(t) {
                return;
            }
            self.visiting.insert(t.clone());
            for i in 0..t.num_field() {
                let mut f = t.field(i);
                self.index.push(i);
                let mut add = true;
                if let Some(&old_index) = self.by_name.get(&f.name) {
                    let old_len = self.fields[old_index].index.len();
                    if self.index.len() == old_len {
                        // Fields with the same name at the same depth cancel
                        // each other out.
                        self.fields[old_index].name.clear();
                        add = false;
                    } else if self.index.len() < old_len {
                        // The old field loses to the shallower one.
                        self.fields[old_index].name.clear();
                    } else {
                        // The old field shadows the new one.
                        add = false;
                    }
                }
                if add {
                    f.index = self.index.clone();
                    self.by_name.insert(f.name.clone(), self.fields.len());
                    self.fields.push(f.clone());
                }
                if f.anonymous {
                    let mut ft = f.type_.clone();
                    if ft.kind() == Kind::Pointer {
                        ft = ft.elem();
                    }
                    if ft.kind() == Kind::Struct {
                        self.walk(&ft);
                    }
                }
                self.index.pop();
            }
            self.visiting.remove(t);
        }
    }
    let mut w = Walker {
        by_name: HashMap::new(),
        visiting: HashSet::new(),
        fields: Vec::with_capacity(t.num_field()),
        index: Vec::with_capacity(2),
    };
    w.walk(t);
    w.fields
        .into_iter()
        .filter(|f| !f.name.is_empty())
        .collect()
}
