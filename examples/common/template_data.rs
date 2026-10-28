//! The Go exec_test.go data types (T, U, V, W, S, I, ...) and helper functions
//! rebuilt on the template value model, mirroring tools/template_oracle_data.go.
#![allow(dead_code)]

use rust_stdlib::text::template::value::{
    CallError, ChanDir, Field, FuncError, FuncSig, Kind, Method, Type, Value,
};
use rust_stdlib::text::template::verbs;
use rust_stdlib::text::template::FuncMap;
use std::sync::{Arc, Mutex, OnceLock};

pub fn int() -> Type {
    Type::int()
}
pub fn string() -> Type {
    Type::string()
}
pub fn any() -> Type {
    Type::any()
}

fn sig(ins: Vec<Type>, outs: Vec<Type>) -> FuncSig {
    FuncSig::new(ins, outs, false)
}

fn vsig(ins: Vec<Type>, outs: Vec<Type>) -> FuncSig {
    FuncSig::new(ins, outs, true)
}

pub fn nil_deref() -> CallError {
    CallError::Panic("runtime error: invalid memory address or nil pointer dereference".to_owned())
}

pub fn my_error() -> FuncError {
    FuncError::new("my error")
}

/// `*T` receiver helper: the struct a method receiver points at.
fn recv_struct(recv: &Value) -> Option<Value> {
    if recv.kind() == Kind::Pointer {
        if recv.is_nil() {
            None
        } else {
            Some(recv.elem())
        }
    } else {
        Some(recv.clone())
    }
}

pub fn type_v() -> Type {
    static T: OnceLock<Type> = OnceLock::new();
    T.get_or_init(|| {
        Type::named(
            "main",
            "V",
            Type::struct_of(vec![Field::new("j", int())]),
            vec![Method::new(
                "String",
                true,
                sig(vec![], vec![string()]),
                |recv, _| match recv_struct(recv) {
                    None => Ok(Value::string("nilV")),
                    Some(v) => Ok(Value::string(format!("<{}>", v.field(0).as_int()))),
                },
            )],
        )
    })
    .clone()
}

pub fn type_w() -> Type {
    static T: OnceLock<Type> = OnceLock::new();
    T.get_or_init(|| {
        Type::named(
            "main",
            "W",
            Type::struct_of(vec![Field::new("k", int())]),
            vec![Method::new(
                "Error",
                true,
                sig(vec![], vec![string()]),
                |recv, _| match recv_struct(recv) {
                    None => Ok(Value::string("nilW")),
                    Some(v) => Ok(Value::string(format!("[{}]", v.field(0).as_int()))),
                },
            )],
        )
    })
    .clone()
}

pub fn type_u() -> Type {
    static T: OnceLock<Type> = OnceLock::new();
    T.get_or_init(|| {
        Type::named(
            "main",
            "U",
            Type::struct_of(vec![Field::new("V", string())]),
            vec![Method::new(
                "TrueFalse",
                true,
                sig(vec![Type::bool_()], vec![string()]),
                |_, args| Ok(Value::string(if args[0].as_bool() { "true" } else { "" })),
            )],
        )
    })
    .clone()
}

pub fn type_s() -> Type {
    static T: OnceLock<Type> = OnceLock::new();
    T.get_or_init(|| {
        Type::named(
            "main",
            "S",
            Type::slice_of(string()),
            vec![Method::new(
                "Method0",
                false,
                sig(vec![], vec![string()]),
                |_, _| Ok(Value::string("M0")),
            )],
        )
    })
    .clone()
}

pub fn type_i() -> Type {
    static T: OnceLock<Type> = OnceLock::new();
    T.get_or_init(|| {
        Type::named(
            "main",
            "I",
            Type::interface_of(vec![("Method0".to_owned(), sig(vec![], vec![string()]))]),
            vec![],
        )
    })
    .clone()
}

pub fn type_buffer() -> Type {
    static T: OnceLock<Type> = OnceLock::new();
    T.get_or_init(|| {
        Type::named(
            "bytes",
            "Buffer",
            Type::struct_of(vec![Field::new("buf", string())]),
            vec![Method::new(
                "String",
                true,
                sig(vec![], vec![string()]),
                |recv, _| match recv_struct(recv) {
                    None => Ok(Value::string("<nil>")),
                    Some(v) => Ok(v.field(0)),
                },
            )],
        )
    })
    .clone()
}

pub fn type_error_string() -> Type {
    static T: OnceLock<Type> = OnceLock::new();
    T.get_or_init(|| {
        Type::named(
            "errors",
            "errorString",
            Type::struct_of(vec![Field::new("s", string())]),
            vec![Method::new(
                "Error",
                true,
                sig(vec![], vec![string()]),
                |recv, _| match recv_struct(recv) {
                    None => Err(nil_deref()),
                    Some(v) => Ok(v.field(0)),
                },
            )],
        )
    })
    .clone()
}

pub fn type_template() -> Type {
    static T: OnceLock<Type> = OnceLock::new();
    T.get_or_init(|| {
        Type::named(
            "template",
            "Template",
            Type::struct_of(vec![Field::new("name", string())]),
            vec![],
        )
    })
    .clone()
}

pub fn type_t() -> Type {
    static T: OnceLock<Type> = OnceLock::new();
    T.get_or_init(|| {
        let t = Type::named_deferred("main", "T");
        let pt = Type::ptr_to(t.clone());
        let ptr_u = Type::ptr_to(type_u());
        let str_t = string();
        let strs = Type::slice_of(str_t.clone());
        let fields = vec![
            Field::new("True", Type::bool_()),
            Field::new("I", int()),
            Field::new("U16", Type::uint16()),
            Field::new("X", str_t.clone()),
            Field::new("S", str_t.clone()),
            Field::new("FloatZero", Type::float64()),
            Field::new("ComplexZero", Type::complex128()),
            Field::new("U", ptr_u.clone()),
            Field::new("V0", type_v()),
            Field::new("V1", Type::ptr_to(type_v())),
            Field::new("V2", Type::ptr_to(type_v())),
            Field::new("W0", type_w()),
            Field::new("W1", Type::ptr_to(type_w())),
            Field::new("W2", Type::ptr_to(type_w())),
            Field::new("SI", Type::slice_of(int())),
            Field::new("SICap", Type::slice_of(int())),
            Field::new("SIEmpty", Type::slice_of(int())),
            Field::new("SB", Type::slice_of(Type::bool_())),
            Field::new("AI", Type::array_of(3, int())),
            Field::new("PAI", Type::ptr_to(Type::array_of(3, int()))),
            Field::new("MSI", Type::map_of(str_t.clone(), int())),
            Field::new("MSIone", Type::map_of(str_t.clone(), int())),
            Field::new("MSIEmpty", Type::map_of(str_t.clone(), int())),
            Field::new("MXI", Type::map_of(any(), int())),
            Field::new("MII", Type::map_of(int(), int())),
            Field::new("MI32S", Type::map_of(Type::int32(), str_t.clone())),
            Field::new("MI64S", Type::map_of(Type::int64(), str_t.clone())),
            Field::new("MUI32S", Type::map_of(Type::uint32(), str_t.clone())),
            Field::new("MUI64S", Type::map_of(Type::uint64(), str_t.clone())),
            Field::new("MI8S", Type::map_of(Type::int8(), str_t.clone())),
            Field::new("MUI8S", Type::map_of(Type::uint8(), str_t.clone())),
            Field::new("SMSI", Type::slice_of(Type::map_of(str_t.clone(), int()))),
            Field::new("Empty0", any()),
            Field::new("Empty1", any()),
            Field::new("Empty2", any()),
            Field::new("Empty3", any()),
            Field::new("Empty4", any()),
            Field::new("NonEmptyInterface", type_i()),
            Field::new("NonEmptyInterfacePtS", Type::ptr_to(type_i())),
            Field::new("NonEmptyInterfaceNil", type_i()),
            Field::new("NonEmptyInterfaceTypedNil", type_i()),
            Field::new("Str", Type::stringer()),
            Field::new("Err", Type::error()),
            Field::new("PI", Type::ptr_to(int())),
            Field::new("PS", Type::ptr_to(str_t.clone())),
            Field::new("PSI", Type::ptr_to(Type::slice_of(int()))),
            Field::new("NIL", Type::ptr_to(int())),
            Field::new("UPI", Type::unsafe_pointer()),
            Field::new("EmptyUPI", Type::unsafe_pointer()),
            Field::new(
                "BinaryFunc",
                Type::func_of(sig(vec![str_t.clone(), str_t.clone()], vec![str_t.clone()])),
            ),
            Field::new(
                "VariadicFunc",
                Type::func_of(vsig(vec![strs.clone()], vec![str_t.clone()])),
            ),
            Field::new(
                "VariadicFuncInt",
                Type::func_of(vsig(vec![int(), strs.clone()], vec![str_t.clone()])),
            ),
            Field::new(
                "NilOKFunc",
                Type::func_of(sig(vec![Type::ptr_to(int())], vec![Type::bool_()])),
            ),
            Field::new(
                "ErrFunc",
                Type::func_of(sig(vec![], vec![str_t.clone(), Type::error()])),
            ),
            Field::new("PanicFunc", Type::func_of(sig(vec![], vec![str_t.clone()]))),
            Field::new("TooFewReturnCountFunc", Type::func_of(sig(vec![], vec![]))),
            Field::new(
                "TooManyReturnCountFunc",
                Type::func_of(sig(vec![], vec![str_t.clone(), Type::error(), int()])),
            ),
            Field::new(
                "InvalidReturnTypeFunc",
                Type::func_of(sig(vec![], vec![str_t.clone(), Type::bool_()])),
            ),
            Field::new("Tmpl", Type::ptr_to(type_template())),
            Field::new("unexported", int()),
        ];
        t.set_underlying(Type::struct_of(fields));
        let pt2 = pt.clone();
        let methods =
            vec![
                Method::new("Method0", true, sig(vec![], vec![str_t.clone()]), |_, _| {
                    Ok(Value::string("M0"))
                }),
                Method::new("Method1", true, sig(vec![int()], vec![int()]), |_, a| {
                    Ok(a[0].clone())
                }),
                Method::new(
                    "Method2",
                    true,
                    sig(vec![Type::uint16(), str_t.clone()], vec![str_t.clone()]),
                    |_, a| {
                        Ok(Value::string(format!(
                            "Method2: {} {}",
                            a[0].as_uint(),
                            a[1].as_string()
                        )))
                    },
                ),
                Method::new(
                    "Method3",
                    true,
                    sig(vec![any()], vec![str_t.clone()]),
                    |_, a| {
                        Ok(Value::string(format!(
                            "Method3: {}",
                            verbs::sprintf("%v", &a[..1])
                        )))
                    },
                ),
                Method::new(
                    "Copy",
                    true,
                    sig(vec![], vec![pt2.clone()]),
                    move |recv, _| match recv_struct(recv) {
                        None => Err(nil_deref()),
                        Some(v) => Ok(Value::ptr(v)),
                    },
                ),
                Method::new(
                    "MAdd",
                    true,
                    sig(
                        vec![int(), Type::slice_of(int())],
                        vec![Type::slice_of(int())],
                    ),
                    |_, a| {
                        let add = a[0].as_int();
                        let items: Vec<Value> = a[1]
                            .items()
                            .iter()
                            .map(|x| Value::int(x.as_int() + add))
                            .collect();
                        Ok(Value::slice(&int(), items))
                    },
                ),
                Method::new(
                    "MyError",
                    true,
                    sig(vec![Type::bool_()], vec![Type::bool_(), Type::error()]),
                    |_, a| {
                        if a[0].as_bool() {
                            Err(CallError::Error(my_error()))
                        } else {
                            Ok(Value::bool_(false))
                        }
                    },
                ),
                Method::new("GetU", true, sig(vec![], vec![ptr_u.clone()]), |recv, _| {
                    match recv_struct(recv) {
                        None => Err(nil_deref()),
                        Some(v) => Ok(v.field(7)),
                    }
                }),
            ];
        t.set_methods(methods);
        t
    })
    .clone()
}

fn zero_t() -> Vec<Value> {
    type_t()
        .fields()
        .iter()
        .map(|f| Value::zero(&f.ty))
        .collect()
}

pub fn error_value(msg: &str) -> Value {
    Value::iface(
        &Type::error(),
        Some(Value::ptr_typed(
            &Type::ptr_to(type_error_string()),
            Value::struct_(&type_error_string(), vec![Value::string(msg)]),
        )),
    )
}

fn field_index(name: &str) -> usize {
    type_t()
        .fields()
        .iter()
        .position(|f| f.name == name)
        .expect("field")
}

fn set(fields: &mut [Value], name: &str, v: Value) {
    let i = field_index(name);
    let ty = type_t().fields()[i].ty.clone();
    fields[i] = v.assign_to(&ty);
}

fn int_slice(v: &[i64]) -> Value {
    Value::slice(&int(), v.iter().map(|&x| Value::int(x)).collect())
}

fn map_of(kt: Type, et: Type, entries: Vec<(Value, Value)>) -> Value {
    Value::map(&Type::map_of(kt, et), entries)
}

fn ptr_to_u(v: &str) -> Value {
    Value::ptr(Value::struct_(&type_u(), vec![Value::string(v)]))
}

fn func_val(
    ins: Vec<Type>,
    outs: Vec<Type>,
    variadic: bool,
    f: fn(&[Value]) -> Result<Value, CallError>,
) -> Value {
    Value::func_of(FuncSig::new(ins, outs, variadic), f)
}

/// The T value `tVal` of exec_test.go (a `*T`).
pub fn t_val() -> Value {
    let strs = Type::slice_of(string());
    let mut f = zero_t();
    set(&mut f, "True", Value::bool_(true));
    set(&mut f, "I", Value::int(17));
    set(&mut f, "U16", Value::uint_of(&Type::uint16(), 16));
    set(&mut f, "X", Value::string("x"));
    set(&mut f, "S", Value::string("xyz"));
    set(&mut f, "U", ptr_to_u("v"));
    set(
        &mut f,
        "V0",
        Value::struct_(&type_v(), vec![Value::int(6666)]),
    );
    set(
        &mut f,
        "V1",
        Value::ptr(Value::struct_(&type_v(), vec![Value::int(7777)])),
    );
    set(
        &mut f,
        "W0",
        Value::struct_(&type_w(), vec![Value::int(888)]),
    );
    set(
        &mut f,
        "W1",
        Value::ptr(Value::struct_(&type_w(), vec![Value::int(999)])),
    );
    set(&mut f, "SI", int_slice(&[3, 4, 5]));
    set(
        &mut f,
        "SICap",
        Value::slice_with_cap(&int(), vec![Value::int(0); 5], 10),
    );
    set(
        &mut f,
        "SB",
        Value::slice(
            &Type::bool_(),
            vec![Value::bool_(true), Value::bool_(false)],
        ),
    );
    set(
        &mut f,
        "AI",
        Value::array(
            &Type::array_of(3, int()),
            vec![Value::int(3), Value::int(4), Value::int(5)],
        ),
    );
    set(
        &mut f,
        "PAI",
        Value::ptr(Value::array(
            &Type::array_of(3, int()),
            vec![Value::int(3), Value::int(4), Value::int(5)],
        )),
    );
    let msi = |pairs: &[(&str, i64)]| {
        map_of(
            string(),
            int(),
            pairs
                .iter()
                .map(|(k, v)| (Value::string(k), Value::int(*v)))
                .collect(),
        )
    };
    set(&mut f, "MSI", msi(&[("one", 1), ("two", 2), ("three", 3)]));
    set(&mut f, "MSIone", msi(&[("one", 1)]));
    set(
        &mut f,
        "MXI",
        map_of(any(), int(), vec![(Value::string("one"), Value::int(1))]),
    );
    set(
        &mut f,
        "MII",
        map_of(int(), int(), vec![(Value::int(1), Value::int(1))]),
    );
    let ms = |kt: Type, pairs: &[(i64, &str)]| {
        map_of(
            kt.clone(),
            string(),
            pairs
                .iter()
                .map(|(k, v)| {
                    let key = if kt.kind().is_int() {
                        Value::int_of(&kt, *k)
                    } else {
                        Value::uint_of(&kt, *k as u64)
                    };
                    (key, Value::string(v))
                })
                .collect(),
        )
    };
    set(
        &mut f,
        "MI32S",
        ms(Type::int32(), &[(1, "one"), (2, "two")]),
    );
    set(
        &mut f,
        "MI64S",
        ms(Type::int64(), &[(2, "i642"), (3, "i643")]),
    );
    set(
        &mut f,
        "MUI32S",
        ms(Type::uint32(), &[(2, "u322"), (3, "u323")]),
    );
    set(
        &mut f,
        "MUI64S",
        ms(Type::uint64(), &[(2, "ui642"), (3, "ui643")]),
    );
    set(&mut f, "MI8S", ms(Type::int8(), &[(2, "i82"), (3, "i83")]));
    set(
        &mut f,
        "MUI8S",
        ms(Type::uint8(), &[(2, "u82"), (3, "u83")]),
    );
    set(
        &mut f,
        "SMSI",
        Value::slice(
            &Type::map_of(string(), int()),
            vec![
                msi(&[("one", 1), ("two", 2)]),
                msi(&[("eleven", 11), ("twelve", 12)]),
            ],
        ),
    );
    set(&mut f, "Empty1", Value::int(3));
    set(&mut f, "Empty2", Value::string("empty2"));
    set(&mut f, "Empty3", int_slice(&[7, 8]));
    set(&mut f, "Empty4", ptr_to_u("UinEmpty"));
    // NonEmptyInterface: &T{X: "x"}
    let mut inner = zero_t();
    set(&mut inner, "X", Value::string("x"));
    set(
        &mut f,
        "NonEmptyInterface",
        Value::ptr(Value::struct_(&type_t(), inner)),
    );
    // NonEmptyInterfacePtS: &siVal, where siVal is I(S{"a","b"}).
    let si_val = Value::iface(
        &type_i(),
        Some(Value::slice_typed(
            &type_s(),
            vec![Value::string("a"), Value::string("b")],
            0,
        )),
    );
    f[field_index("NonEmptyInterfacePtS")] = Value::ptr_typed(&Type::ptr_to(type_i()), si_val);
    // NonEmptyInterfaceTypedNil: (*T)(nil)
    f[field_index("NonEmptyInterfaceTypedNil")] =
        Value::iface(&type_i(), Some(Value::nil_ptr(&Type::ptr_to(type_t()))));
    // Str: bytes.NewBuffer("foozle")
    set(
        &mut f,
        "Str",
        Value::ptr(Value::struct_(
            &type_buffer(),
            vec![Value::string("foozle")],
        )),
    );
    set(&mut f, "Err", error_value("erroozle"));
    set(&mut f, "PI", Value::ptr(Value::int(23)));
    set(&mut f, "PS", Value::ptr(Value::string("a string")));
    set(
        &mut f,
        "PSI",
        Value::ptr(Value::slice(
            &int(),
            vec![Value::int(21), Value::int(22), Value::int(23)],
        )),
    );
    f[field_index("UPI")] = Value::unsafe_pointer(Some(0xc000_0100));
    f[field_index("BinaryFunc")] = func_val(vec![string(), string()], vec![string()], false, |a| {
        Ok(Value::string(format!(
            "[{}={}]",
            a[0].as_string(),
            a[1].as_string()
        )))
    });
    f[field_index("VariadicFunc")] = func_val(vec![strs.clone()], vec![string()], true, |a| {
        let parts: Vec<String> = a.iter().map(Value::as_string).collect();
        Ok(Value::string(format!("<{}>", parts.join("+"))))
    });
    f[field_index("VariadicFuncInt")] =
        func_val(vec![int(), strs.clone()], vec![string()], true, |a| {
            let parts: Vec<String> = a[1..].iter().map(Value::as_string).collect();
            Ok(Value::string(format!(
                "{}=<{}>",
                a[0].as_int(),
                parts.join("+")
            )))
        });
    f[field_index("NilOKFunc")] =
        func_val(vec![Type::ptr_to(int())], vec![Type::bool_()], false, |a| {
            Ok(Value::bool_(a[0].is_nil()))
        });
    f[field_index("ErrFunc")] = func_val(vec![], vec![string(), Type::error()], false, |_| {
        Ok(Value::string("bla"))
    });
    f[field_index("PanicFunc")] = func_val(vec![], vec![string()], false, |_| {
        Err(CallError::Panic("test panic".to_owned()))
    });
    f[field_index("TooFewReturnCountFunc")] = func_val(vec![], vec![], false, |_| Ok(Value::nil()));
    f[field_index("TooManyReturnCountFunc")] =
        func_val(vec![], vec![string(), Type::error(), int()], false, |_| {
            Ok(Value::string(""))
        });
    f[field_index("InvalidReturnTypeFunc")] =
        func_val(vec![], vec![string(), Type::bool_()], false, |_| {
            Ok(Value::string(""))
        });
    set(
        &mut f,
        "Tmpl",
        Value::ptr(Value::struct_(&type_template(), vec![Value::string("x")])),
    );
    Value::ptr(Value::struct_(&type_t(), f))
}

pub fn t_zero() -> Value {
    Value::struct_(&type_t(), zero_t())
}

pub fn i_val() -> Value {
    Value::iface(&type_i(), Some(t_val()))
}

fn panic_msg(s: &str) -> CallError {
    CallError::Panic(s.to_owned())
}

fn ints(args: &[Value]) -> i64 {
    args.iter().map(Value::as_int).sum()
}

/// The functions every differential template can call (tools/template_oracle_data.go).
pub fn std_funcs() -> FuncMap {
    let mut m = FuncMap::new();
    let strs = Type::slice_of(string());
    let ints_t = Type::slice_of(int());
    let mut add = |name: &str,
                   ins: Vec<Type>,
                   outs: Vec<Type>,
                   variadic: bool,
                   f: fn(&[Value]) -> Result<Value, CallError>| {
        m.insert(
            name.to_owned(),
            Value::func_of(FuncSig::new(ins, outs, variadic), f),
        );
    };
    add("add", vec![ints_t], vec![int()], true, |a| {
        Ok(Value::int(ints(a)))
    });
    add(
        "count",
        vec![int()],
        vec![Type::chan_of(ChanDir::Both, string())],
        false,
        |a| {
            let n = a[0].as_int();
            let ct = Type::chan_of(ChanDir::Both, string());
            if n == 0 {
                return Ok(Value::nil_chan(&ct));
            }
            let state = Arc::new(Mutex::new(0i64));
            Ok(Value::chan(&ct, move || {
                let mut i = state.lock().expect("lock");
                if *i >= n {
                    return None;
                }
                let s = &"abcdefghijklmnop"[*i as usize..*i as usize + 1];
                *i += 1;
                Some(Value::string(s))
            }))
        },
    );
    add(
        "dddArg",
        vec![int(), strs.clone()],
        vec![string()],
        true,
        |a| {
            let rest = Value::slice(&string(), a[1..].to_vec());
            Ok(Value::string(verbs::sprintln(&[a[0].clone(), rest])))
        },
    );
    add("die", vec![], vec![Type::bool_()], false, |_| {
        Err(panic_msg("die"))
    });
    add(
        "echo",
        vec![any()],
        vec![any()],
        false,
        |a| Ok(a[0].clone()),
    );
    add(
        "makemap",
        vec![strs.clone()],
        vec![Type::map_of(string(), string())],
        true,
        |a| {
            if a.len() % 2 != 0 {
                return Err(panic_msg("bad makemap"));
            }
            let entries = a.chunks(2).map(|p| (p[0].clone(), p[1].clone())).collect();
            Ok(Value::map(&Type::map_of(string(), string()), entries))
        },
    );
    add("mapOfThree", vec![], vec![any()], false, |_| {
        Ok(Value::map(
            &Type::map_of(string(), int()),
            vec![(Value::string("three"), Value::int(3))],
        ))
    });
    add("oneArg", vec![string()], vec![string()], false, |a| {
        Ok(Value::string(format!("oneArg={}", a[0].as_string())))
    });
    add("returnInt", vec![], vec![int()], false, |_| {
        Ok(Value::int(7))
    });
    add(
        "stringer",
        vec![Type::stringer()],
        vec![string()],
        false,
        |a| {
            let s = a[0].interface().method_by_name("String");
            if !s.is_valid() {
                return Err(nil_deref());
            }
            s.call(&[])
        },
    );
    add(
        "twoArgs",
        vec![string(), string()],
        vec![string()],
        false,
        |a| {
            Ok(Value::string(format!(
                "twoArgs={}{}",
                a[0].as_string(),
                a[1].as_string()
            )))
        },
    );
    add("typeOf", vec![any()], vec![string()], false, |a| {
        let v = a[0].interface();
        Ok(Value::string(
            v.type_()
                .map(Type::type_string)
                .unwrap_or_else(|| "<nil>".to_owned()),
        ))
    });
    add("valueString", vec![string()], vec![string()], false, |_| {
        Ok(Value::string("value is ignored"))
    });
    add(
        "vfunc",
        vec![type_v(), Type::ptr_to(type_v())],
        vec![string()],
        false,
        |_| Ok(Value::string("vfunc")),
    );
    add("zeroArgs", vec![], vec![string()], false, |_| {
        Ok(Value::string("zeroArgs"))
    });
    add("doPanic", vec![], vec![string()], false, |_| {
        Err(panic_msg("custom panic string"))
    });
    add("upper", vec![string()], vec![string()], false, |a| {
        Ok(Value::string(a[0].as_string().to_uppercase()))
    });
    add("join", vec![string(), strs], vec![string()], true, |a| {
        let parts: Vec<String> = a[1..].iter().map(Value::as_string).collect();
        Ok(Value::string(parts.join(&a[0].as_string())))
    });
    add("dbl", vec![int()], vec![int()], false, |a| {
        Ok(Value::int(2 * a[0].as_int()))
    });
    add(
        "fail",
        vec![string()],
        vec![string(), Type::error()],
        false,
        |a| {
            Err(CallError::Error(FuncError::new(format!(
                "fail: {}",
                a[0].as_string()
            ))))
        },
    );
    add(
        "pair",
        vec![any(), any()],
        vec![Type::slice_of(any())],
        false,
        |a| Ok(Value::slice(&any(), vec![a[0].clone(), a[1].clone()])),
    );
    add("nilf", vec![], vec![any()], false, |_| Ok(Value::nil()));
    add(
        "seq",
        vec![int()],
        vec![Type::slice_of(int())],
        false,
        |a| {
            Ok(Value::slice(
                &int(),
                (0..a[0].as_int()).map(Value::int).collect(),
            ))
        },
    );
    m
}

// ---- other reference values -------------------------------------------------

pub fn type_tree() -> Type {
    static T: OnceLock<Type> = OnceLock::new();
    T.get_or_init(|| {
        let t = Type::named_deferred("main", "Tree");
        let pt = Type::ptr_to(t.clone());
        t.set_underlying(Type::struct_of(vec![
            Field::new("Val", int()),
            Field::new("Left", pt.clone()),
            Field::new("Right", pt),
        ]));
        t.set_methods(vec![]);
        t
    })
    .clone()
}

fn tree(val: i64, left: Option<Value>, right: Option<Value>) -> Value {
    let pt = Type::ptr_to(type_tree());
    let l = left.unwrap_or_else(|| Value::nil_ptr(&pt));
    let r = right.unwrap_or_else(|| Value::nil_ptr(&pt));
    Value::ptr(Value::struct_(&type_tree(), vec![Value::int(val), l, r]))
}

pub fn tree_ref() -> Value {
    tree(
        1,
        Some(tree(
            2,
            Some(tree(3, Some(tree(4, None, None)), None)),
            Some(tree(5, Some(tree(6, None, None)), None)),
        )),
        Some(tree(
            7,
            Some(tree(8, Some(tree(9, None, None)), None)),
            Some(tree(10, Some(tree(11, None, None)), None)),
        )),
    )
}

pub fn type_cmp_struct() -> Type {
    static T: OnceLock<Type> = OnceLock::new();
    T.get_or_init(|| {
        Type::named(
            "main",
            "cmpStruct",
            Type::struct_of(vec![
                Field::new("Uthree", Type::uint()),
                Field::new("Ufour", Type::uint()),
                Field::new("NegOne", int()),
                Field::new("Three", int()),
                Field::new("Ptr", Type::ptr_to(int())),
                Field::new("NilPtr", Type::ptr_to(int())),
                Field::new("NonNilMap", Type::map_of(int(), int())),
                Field::new("Map", Type::map_of(int(), int())),
                Field::new("V1", type_v()),
                Field::new("V2", type_v()),
                Field::new("Iface1", Type::stringer()),
                Field::new("NilIface", Type::stringer()),
            ]),
            vec![],
        )
    })
    .clone()
}

pub fn cmp_ref() -> Value {
    let mm = Type::map_of(int(), int());
    let buf = Value::ptr(Value::struct_(&type_buffer(), vec![Value::string("")]));
    Value::ptr(Value::struct_(
        &type_cmp_struct(),
        vec![
            Value::uint(3),
            Value::uint(4),
            Value::int(-1),
            Value::int(3),
            Value::ptr(Value::int(0)),
            Value::nil_ptr(&Type::ptr_to(int())),
            Value::map(&mm, vec![]),
            Value::nil_map(&mm),
            Value::struct_(&type_v(), vec![Value::int(0)]),
            Value::struct_(&type_v(), vec![Value::int(0)]),
            buf,
            Value::zero(&Type::stringer()),
        ],
    ))
}

pub fn type_base() -> Type {
    static T: OnceLock<Type> = OnceLock::new();
    T.get_or_init(|| {
        Type::named(
            "main",
            "Base",
            Type::struct_of(vec![Field::new("ID", int())]),
            vec![
                Method::new("Describe", false, sig(vec![], vec![string()]), |recv, _| {
                    let v = if recv.kind() == Kind::Pointer {
                        recv.elem()
                    } else {
                        recv.clone()
                    };
                    Ok(Value::string(format!("base#{}", v.field(0).as_int())))
                }),
                Method::new("PtrMethod", true, sig(vec![], vec![string()]), |_, _| {
                    Ok(Value::string("ptr"))
                }),
            ],
        )
    })
    .clone()
}

pub fn type_embedded() -> Type {
    static T: OnceLock<Type> = OnceLock::new();
    T.get_or_init(|| {
        Type::named(
            "main",
            "Embedded",
            Type::struct_of(vec![
                Field::embedded(type_base()),
                Field::new("Name", string()),
            ]),
            vec![],
        )
    })
    .clone()
}

pub fn type_a() -> Type {
    static T: OnceLock<Type> = OnceLock::new();
    T.get_or_init(|| {
        Type::named(
            "main",
            "A",
            Type::struct_of(vec![Field::new("S", string())]),
            vec![],
        )
    })
    .clone()
}

pub fn type_b() -> Type {
    static T: OnceLock<Type> = OnceLock::new();
    T.get_or_init(|| {
        Type::named(
            "main",
            "B",
            Type::struct_of(vec![Field::embedded(Type::ptr_to(type_a()))]),
            vec![],
        )
    })
    .clone()
}

pub fn type_named_int() -> Type {
    static T: OnceLock<Type> = OnceLock::new();
    T.get_or_init(|| {
        Type::named(
            "main",
            "namedInt",
            int(),
            vec![Method::new(
                "String",
                false,
                sig(vec![], vec![string()]),
                |recv, _| Ok(Value::string(format!("namedInt({})", recv.as_int()))),
            )],
        )
    })
    .clone()
}

pub fn type_named_str() -> Type {
    static T: OnceLock<Type> = OnceLock::new();
    T.get_or_init(|| Type::named("main", "namedStr", string(), vec![]))
        .clone()
}

pub fn fval1(n: i64) -> Value {
    Value::seq(&int(), move |y| {
        for v in 0..n {
            if !y(Value::int(v)) {
                break;
            }
        }
    })
}

pub fn fval2(n: i64) -> Value {
    Value::seq2(&int(), &int(), move |y| {
        for v in 0..n {
            if !y(Value::int(v), Value::int(v + 1)) {
                break;
            }
        }
    })
}

/// A named reference value ("$ref" in data specs).
pub fn reference(name: &str) -> Value {
    if let Some(content) = name.strip_prefix("buf:") {
        return Value::ptr(Value::struct_(&type_buffer(), vec![Value::string(content)]));
    }
    match name {
        "anon_ab" => Value::struct_(
            &Type::struct_of(vec![Field::new("a", int()), Field::new("b", string())]),
            vec![Value::int(7), Value::string("seven")],
        ),
        "tVal" => t_val(),
        "tSliceOfNil" => Value::slice(
            &Type::ptr_to(type_t()),
            vec![Value::nil_ptr(&Type::ptr_to(type_t()))],
        ),
        "iVal" => t_val(),
        "&iVal" => Value::ptr_typed(&Type::ptr_to(type_i()), i_val()),
        "T{}" => t_zero(),
        "&T{}" => Value::ptr(t_zero()),
        "nilT" => Value::nil_ptr(&Type::ptr_to(type_t())),
        "cmp" => cmp_ref(),
        "tree" => tree_ref(),
        "B{}" => Value::struct_(&type_b(), vec![]),
        "fVal1(2)" => fval1(2),
        "fVal2(2)" => fval2(2),
        "fVal1(0)" => fval1(0),
        "fVal2(0)" => fval2(0),
        "nilchan" => Value::nil_chan(&Type::chan_of(ChanDir::Both, int())),
        "sendchan" => Value::chan(&Type::chan_of(ChanDir::Send, int()), || None),
        "embedded" => Value::struct_(
            &type_embedded(),
            vec![
                Value::struct_(&type_base(), vec![Value::int(7)]),
                Value::string("emb"),
            ],
        ),
        "&embedded" => Value::ptr(Value::struct_(
            &type_embedded(),
            vec![
                Value::struct_(&type_base(), vec![Value::int(8)]),
                Value::string("pemb"),
            ],
        )),
        "namedInt" => Value::named(&type_named_int(), Value::int(5)),
        "mapPtr" => Value::ptr(Value::map(&Type::map_of(string(), string()), vec![])),
        "nilMapPtr" => Value::nil_ptr(&Type::ptr_to(Type::map_of(string(), string()))),
        "unsafe" => Value::unsafe_pointer(Some(0xc000_0200)),
        other => panic!("unknown ref {other}"),
    }
}
