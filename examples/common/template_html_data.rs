//! Data for the html/template tests, mirroring tools/template_oracle_html.go.
#![allow(dead_code)]

use super::data;
use rust_stdlib::html::template::{html_type, Html};
use rust_stdlib::text::template::value::{
    CallError, Field, FuncError, FuncSig, Kind, Method, ToValue, Type, Value,
};
use rust_stdlib::text::template::verbs;
use rust_stdlib::text::template::FuncMap;
use std::sync::OnceLock;

fn sig(ins: Vec<Type>, outs: Vec<Type>) -> FuncSig {
    FuncSig::new(ins, outs, false)
}

fn bytes_value(b: &[u8]) -> Value {
    Value::slice(
        &Type::uint8(),
        b.iter()
            .map(|&x| Value::uint_of(&Type::uint8(), u64::from(x)))
            .collect(),
    )
}

fn marshaler_sig() -> FuncSig {
    sig(vec![], vec![Type::slice_of(Type::uint8()), Type::error()])
}

pub fn json_marshaler() -> Type {
    static T: OnceLock<Type> = OnceLock::new();
    T.get_or_init(|| {
        Type::named(
            "json",
            "Marshaler",
            Type::interface_of(vec![("MarshalJSON".to_owned(), marshaler_sig())]),
            vec![],
        )
    })
    .clone()
}

fn marshaler_type(name: &str, body: fn() -> Result<Value, CallError>) -> Type {
    let m = Method::new("MarshalJSON", true, marshaler_sig(), move |_, _| body());
    Type::named("main", name, Type::struct_of(vec![]), vec![m])
}

pub fn bad_marshaler() -> Type {
    static T: OnceLock<Type> = OnceLock::new();
    T.get_or_init(|| {
        marshaler_type("badMarshaler", || {
            Ok(bytes_value(b"{ foo: 'not quite valid JSON' }"))
        })
    })
    .clone()
}

pub fn good_marshaler() -> Type {
    static T: OnceLock<Type> = OnceLock::new();
    T.get_or_init(|| {
        marshaler_type("goodMarshaler", || {
            Ok(bytes_value(br#"{ "<foo>": "O'Reilly" }"#))
        })
    })
    .clone()
}

pub fn json_err_type() -> Type {
    static T: OnceLock<Type> = OnceLock::new();
    T.get_or_init(|| {
        marshaler_type("jsonErrType", || {
            Err(CallError::Error(FuncError::new(
                "a */ b <script c </script d <!-- e <sCrIpT f </sCrIpT",
            )))
        })
    })
    .clone()
}

fn string_method(name: &'static str, fmt_prefix: &'static str) -> Type {
    let m = Method::new(
        name,
        true,
        sig(vec![], vec![Type::string()]),
        move |recv, _| {
            let v = if recv.kind() == Kind::Pointer {
                recv.elem()
            } else {
                recv.clone()
            };
            Ok(Value::string(format!(
                "{fmt_prefix}={}",
                v.field(0).as_int()
            )))
        },
    );
    Type::named(
        "main",
        if name == "String" {
            "myStringer"
        } else {
            "errorer"
        },
        Type::struct_of(vec![Field::new("v", Type::int())]),
        vec![m],
    )
}

pub fn my_stringer() -> Type {
    static T: OnceLock<Type> = OnceLock::new();
    T.get_or_init(|| string_method("String", "string")).clone()
}

pub fn errorer() -> Type {
    static T: OnceLock<Type> = OnceLock::new();
    T.get_or_init(|| string_method("Error", "error")).clone()
}

pub fn escape_data_type() -> Type {
    static T: OnceLock<Type> = OnceLock::new();
    T.get_or_init(|| {
        let s = Type::string();
        let ss = Type::slice_of(s.clone());
        Type::named(
            "main",
            "escapeDataT",
            Type::struct_of(vec![
                Field::new("F", Type::bool_()),
                Field::new("T", Type::bool_()),
                Field::new("C", s.clone()),
                Field::new("G", s.clone()),
                Field::new("H", s.clone()),
                Field::new("I", s.clone()),
                Field::new("A", ss.clone()),
                Field::new("E", ss),
                Field::new("B", json_marshaler()),
                Field::new("M", json_marshaler()),
                Field::new("N", Type::int()),
                Field::new("U", Type::any()),
                Field::new("Z", Type::ptr_to(Type::int())),
                Field::new("W", html_type()),
            ]),
            vec![],
        )
    })
    .clone()
}

pub fn escape_data() -> Value {
    let s = Type::string();
    let strs = |v: &[&str]| Value::slice(&s, v.iter().map(Value::string).collect());
    Value::struct_(
        &escape_data_type(),
        vec![
            Value::bool_(false),
            Value::bool_(true),
            Value::string("<Cincinnati>"),
            Value::string("<Goodbye>"),
            Value::string("<Hello>"),
            Value::string("${ asd `` }"),
            strs(&["<a>", "<b>"]),
            strs(&[]),
            Value::ptr(Value::struct_(&bad_marshaler(), vec![])),
            Value::ptr(Value::struct_(&good_marshaler(), vec![])),
            Value::int(42),
            Value::nil(),
            Value::nil_ptr(&Type::ptr_to(Type::int())),
            Html(r#"&iexcl;<b class="foo">Hello</b>, <textarea>O'World</textarea>!"#.to_owned())
                .to_value(),
        ],
    )
}

pub fn data_item_type() -> Type {
    static T: OnceLock<Type> = OnceLock::new();
    T.get_or_init(|| {
        let t = Type::named_deferred("main", "dataItem");
        t.set_underlying(Type::struct_of(vec![
            Field::new("Children", Type::slice_of(Type::ptr_to(t.clone()))),
            Field::new("X", Type::string()),
        ]));
        t.set_methods(vec![]);
        t
    })
    .clone()
}

fn item(x: &str, children: Vec<Value>) -> Value {
    let pt = Type::ptr_to(data_item_type());
    let kids = if children.is_empty() {
        Value::nil_slice(&Type::slice_of(pt.clone()))
    } else {
        Value::slice(&pt, children)
    };
    Value::struct_(&data_item_type(), vec![kids, Value::string(x)])
}

pub fn data_items() -> Value {
    let pt = Type::ptr_to(data_item_type());
    let kids = Value::slice(
        &pt,
        vec![
            Value::ptr(item("foo", vec![])),
            Value::ptr(item("<bar>", vec![])),
            Value::ptr(item("", vec![Value::ptr(item("baz", vec![]))])),
        ],
    );
    Value::struct_(&data_item_type(), vec![kids, Value::string("")])
}

/// html references ("$ref" names), if `name` is one.
pub fn html_ref(name: &str) -> Option<Value> {
    Some(match name {
        "escapeData" => escape_data(),
        "&escapeData" => Value::ptr(escape_data()),
        "dataItem" => data_items(),
        "jsonErr" => Value::ptr(Value::struct_(&json_err_type(), vec![])),
        "stringer3" => Value::ptr(Value::struct_(&my_stringer(), vec![Value::int(3)])),
        "errorer7" => Value::ptr(Value::struct_(&errorer(), vec![Value::int(7)])),
        "xyStruct" => Value::struct_(
            &Type::struct_of(vec![
                Field::new("X", Type::int()),
                Field::new("Y", Type::int()),
            ]),
            vec![Value::int(1), Value::int(2)],
        ),
        "errIface" => Value::struct_(
            &Type::struct_of(vec![Field::new("E", Type::error())]),
            vec![Value::zero(&Type::error())],
        ),
        "anyIface" => Value::struct_(
            &Type::struct_of(vec![Field::new("E", Type::any())]),
            vec![Value::zero(&Type::any())],
        ),
        "stringsAngle" => Value::slice(
            &Type::string(),
            vec![
                Value::string("<!--"),
                Value::string("</script>"),
                Value::string("-->"),
            ],
        ),
        "anySlice" => Value::slice(
            &Type::any(),
            vec![Value::int(42), Value::string("foo"), Value::nil()],
        ),
        "emptyAnySlice" => Value::slice(&Type::any(), vec![]),
        _ => return None,
    })
}

/// A typed content value ("$t": "html" and friends), if `t` names one.
pub fn html_typed(t: &str, v: &str) -> Option<Value> {
    use rust_stdlib::html::template::{Css, HtmlAttr, Js, JsStr, Srcset, Url};
    Some(match t {
        "html" => Html(v.to_owned()).to_value(),
        "css" => Css(v.to_owned()).to_value(),
        "js" => Js(v.to_owned()).to_value(),
        "jsstr" => JsStr(v.to_owned()).to_value(),
        "url" => Url(v.to_owned()).to_value(),
        "srcset" => Srcset(v.to_owned()).to_value(),
        "htmlattr" => HtmlAttr(v.to_owned()).to_value(),
        _ => return None,
    })
}

/// The function map every html differential template gets.
pub fn html_funcs() -> FuncMap {
    let mut m = data::std_funcs();
    m.insert(
        "pred".to_owned(),
        Value::func_of(
            FuncSig::new(
                vec![Type::slice_of(Type::any())],
                vec![Type::any(), Type::error()],
                true,
            ),
            |a| {
                if a.len() == 1 {
                    let v = a[0].interface();
                    if v.type_() == Some(&Type::int()) && v.as_int() > 0 {
                        return Ok(Value::int(v.as_int() - 1));
                    }
                }
                let list = Value::slice(&Type::any(), a.to_vec());
                Err(CallError::Error(FuncError::new(format!(
                    "undefined pred({})",
                    verbs::sprintf("%v", &[list])
                ))))
            },
        ),
    );
    m
}
