//! Request handler shared by `examples/template_probe.rs` (the Go differential)
//! and the fixture-driven tests. A request is a JSON object; the reply is
//! `OK <hex output>` or `ERR <hex error text> <hex partial output>`, mirroring
//! `tools/template_oracle.go`.
#![allow(dead_code)]

#[path = "template_data.rs"]
pub mod data;
#[path = "template_html_data.rs"]
pub mod html_data;

use rust_stdlib::encoding::json::{self, Value as Json};
use rust_stdlib::html::template as html;
use rust_stdlib::strconv;
use rust_stdlib::text::template::parse;
use rust_stdlib::text::template::value::{ChanDir, Field, FuncSig, Type, Value};
use rust_stdlib::text::template::Template;

fn field<'a>(req: &'a Json, key: &str) -> Option<&'a Json> {
    req.get(key)
}

fn text(req: &Json, key: &str) -> String {
    field(req, key)
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned()
}

fn strings(req: &Json, key: &str) -> Vec<String> {
    field(req, key)
        .and_then(Json::as_array)
        .unwrap_or(&[])
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect()
}

pub fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

pub fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A reply: Ok(output) or Err((error text, partial output)).
pub type Reply = Result<String, (String, String)>;

/// Handles one hex-encoded request line and returns the reply line.
pub fn handle_line(line: &str) -> String {
    let raw = from_hex(line.trim());
    let req = json::Value::try_from(&raw[..]).expect("request json");
    format_reply(&handle(&req))
}

/// Replaces pointer-like numbers (`0x` and six or more hex digits), which differ
/// between runs, with a fixed token.
pub fn normalize_addresses(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    let mut last = 0;
    while i + 1 < b.len() {
        if b[i] == b'0' && b[i + 1] == b'x' {
            let mut j = i + 2;
            while j < b.len() && (b[j].is_ascii_digit() || (b'a'..=b'f').contains(&b[j])) {
                j += 1;
            }
            if j - (i + 2) >= 6 {
                out.push_str(&s[last..i]);
                out.push_str("0xADDR");
                last = j;
                i = j;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&s[last..]);
    out
}

/// Replays a fixture file generated from Go (`tools/template_fixtures.py`),
/// asserting that every request gets Go's reply. Returns the request count.
pub fn replay(file: &str) -> usize {
    let path = format!(
        "{}/tests/fixtures/template/{file}",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).expect("fixture file");
    let mut n = 0;
    for line in text.lines() {
        let rec = line.parse::<json::Value>().expect("fixture json");
        let req = rec.get("req").expect("req");
        let ok = matches!(rec.get("ok"), Some(Json::Bool(true)));
        let out = rec.get("out").and_then(Json::as_str).unwrap_or("");
        let partial = rec.get("partial").and_then(Json::as_str).unwrap_or("");
        let got = handle(req);
        let (got_ok, got_out, got_partial) = match got {
            Ok(o) => (true, o, String::new()),
            Err((e, p)) => (false, e, p),
        };
        let origin = req.get("origin").and_then(Json::as_str).unwrap_or("");
        assert_eq!(
            ok, got_ok,
            "{file} #{n} [{origin}] ok flag for {req:?}\nwant {out:?}\ngot {got_out:?}"
        );
        assert_eq!(
            normalize_addresses(&got_out),
            normalize_addresses(out),
            "{file} #{n} [{origin}] output for {req:?}"
        );
        if !ok {
            assert_eq!(
                normalize_addresses(&got_partial),
                normalize_addresses(partial),
                "{file} #{n} [{origin}] partial output for {req:?}"
            );
        }
        n += 1;
    }
    n
}

pub fn format_reply(r: &Reply) -> String {
    match r {
        Ok(out) => format!("OK {}", to_hex(out.as_bytes())),
        Err((e, out)) => format!("ERR {} {}", to_hex(e.as_bytes()), to_hex(out.as_bytes())),
    }
}

pub fn handle(req: &Json) -> Reply {
    match text(req, "mode").as_str() {
        "parse" => do_parse(req).map_err(|e| (e, String::new())),
        "text" => do_text(req),
        "html" => do_html(req),
        other => Err((format!("unknown mode {other:?}"), String::new())),
    }
}

fn do_parse(req: &Json) -> Result<String, String> {
    let funcs: std::collections::BTreeMap<String, ()> =
        strings(req, "funcs").into_iter().map(|s| (s, ())).collect();
    let pmode = field(req, "pmode")
        .and_then(Json::as_number)
        .and_then(|n| n.to_string().parse::<u32>().ok())
        .unwrap_or(0);
    let mut tr = parse::Tree::new(&text(req, "name"));
    tr.mode = parse::Mode(pmode);
    let mut set = std::collections::BTreeMap::new();
    tr.parse(
        &text(req, "src"),
        &text(req, "ld"),
        &text(req, "rd"),
        &mut set,
        &[&funcs],
    )
    .map_err(|e| e.to_string())?;
    let mut sb = String::new();
    for (n, t) in &set {
        let root = t.root.as_ref().expect("root");
        sb.push_str(&format!(
            "{} parse={} root={}\n",
            strconv::quote(n),
            strconv::quote(&t.parse_name),
            root
        ));
        if let Some(first) = root.nodes.first() {
            let (loc, ctx) = t.error_context(first);
            sb.push_str(&format!("  ctx {loc} | {ctx}\n"));
        }
    }
    let cp = tr.copy();
    sb.push_str(&format!("copy {}\n", cp.root.as_ref().expect("root")));
    Ok(sb)
}

fn do_text(req: &Json) -> Reply {
    let tmpl = Template::new(&text(req, "name"));
    let opts = strings(req, "opts");
    if !opts.is_empty() {
        let o: Vec<&str> = opts.iter().map(String::as_str).collect();
        tmpl.option(&o);
    }
    tmpl.delims(&text(req, "ld"), &text(req, "rd"));
    if !matches!(field(req, "nofuncs"), Some(Json::Bool(true))) {
        tmpl.funcs(&data::std_funcs());
    }
    tmpl.parse(&text(req, "src"))
        .map_err(|e| (e.to_string(), String::new()))?;
    if let Some(defs) = field(req, "defs").and_then(Json::as_array) {
        for d in defs {
            let pair = d.as_array().expect("def pair");
            let name = pair[0].as_str().expect("name");
            let src = pair[1].as_str().expect("src");
            tmpl.associated(name)
                .parse(src)
                .map_err(|e| (e.to_string(), String::new()))?;
        }
    }
    let value = match field(req, "data") {
        Some(spec) => build(spec),
        None => Value::nil(),
    };
    let mut out: Vec<u8> = Vec::new();
    let exec = text(req, "exec");
    let r = if exec.is_empty() {
        tmpl.execute_value(&mut out, value)
    } else {
        match tmpl.lookup(&exec) {
            Some(t) => t.execute_value(&mut out, value),
            None => Err(rust_stdlib::text::template::Error::Msg(format!(
                "template: no template {} associated with template {}",
                strconv::quote(&exec),
                strconv::quote(tmpl.name())
            ))),
        }
    };
    let out = String::from_utf8_lossy(&out).into_owned();
    match r {
        Ok(()) => Ok(out),
        Err(e) => Err((e.to_string(), out)),
    }
}

fn do_html(req: &Json) -> Reply {
    let tmpl = html::Template::new(&text(req, "name"));
    let opts = strings(req, "opts");
    if !opts.is_empty() {
        let o: Vec<&str> = opts.iter().map(String::as_str).collect();
        tmpl.option(&o);
    }
    tmpl.delims(&text(req, "ld"), &text(req, "rd"));
    if !matches!(field(req, "nofuncs"), Some(Json::Bool(true))) {
        tmpl.funcs(&html_data::html_funcs());
    }
    tmpl.parse(&text(req, "src"))
        .map_err(|e| (e.to_string(), String::new()))?;
    if let Some(defs) = field(req, "defs").and_then(Json::as_array) {
        for d in defs {
            let pair = d.as_array().expect("def pair");
            let name = pair[0].as_str().expect("name");
            let src = pair[1].as_str().expect("src");
            tmpl.associated(name)
                .parse(src)
                .map_err(|e| (e.to_string(), String::new()))?;
        }
    }
    let value = match field(req, "data") {
        Some(spec) => build(spec),
        None => Value::nil(),
    };
    let exec = text(req, "exec");
    let run = |out: &mut Vec<u8>| {
        if exec.is_empty() {
            tmpl.execute_value(out, value.clone())
        } else {
            tmpl.execute_template_value(out, &exec, value.clone())
        }
    };
    if matches!(field(req, "twice"), Some(Json::Bool(true))) {
        let mut all = String::new();
        for i in 0..2 {
            let mut out = Vec::new();
            match run(&mut out) {
                Ok(()) => all.push_str(&format!("[{i} OK {}]", String::from_utf8_lossy(&out))),
                Err(e) => all.push_str(&format!(
                    "[{i} ERR {e} | {}]",
                    String::from_utf8_lossy(&out)
                )),
            }
        }
        if let Some(t) = tmpl.lookup(&text(req, "name")).and_then(|t| t.tree()) {
            if let Some(root) = &t.root {
                all.push_str(&format!("\ntree: {root}"));
            }
        }
        return Ok(all);
    }
    let mut out = Vec::new();
    let r = run(&mut out);
    let out = String::from_utf8_lossy(&out).into_owned();
    match r {
        Ok(()) => Ok(out),
        Err(e) => Err((e.to_string(), out)),
    }
}

// ---- data specs -------------------------------------------------------------

fn num(spec: &Json, key: &str) -> f64 {
    spec.get(key)
        .and_then(Json::as_number)
        .and_then(|n| n.as_f64())
        .unwrap_or(0.0)
}

fn type_named(name: &str) -> Type {
    match name {
        "int" => Type::int(),
        "int8" => Type::int8(),
        "int16" => Type::int16(),
        "int32" => Type::int32(),
        "int64" => Type::int64(),
        "uint" => Type::uint(),
        "uint8" => Type::uint8(),
        "uint16" => Type::uint16(),
        "uint32" => Type::uint32(),
        "uint64" => Type::uint64(),
        "float32" => Type::float32(),
        "float64" => Type::float64(),
        "bool" => Type::bool_(),
        "string" => Type::string(),
        "any" => Type::any(),
        "V" => data::type_v(),
        other => panic!("unknown type name {other}"),
    }
}

/// Builds a data value from a spec; plain JSON decodes like Go's
/// `encoding/json` into `any`.
pub fn build(spec: &Json) -> Value {
    match spec {
        Json::Null => Value::nil(),
        Json::Bool(b) => Value::bool_(*b),
        Json::Number(n) => Value::float64(n.as_f64().unwrap_or(f64::INFINITY)),
        Json::String(s) => Value::string(s),
        Json::Array(items) => Value::slice(&Type::any(), items.iter().map(build).collect()),
        Json::Object(m) => {
            if let Some(r) = m.get("$ref").and_then(Json::as_str) {
                return html_data::html_ref(r).unwrap_or_else(|| data::reference(r));
            }
            if m.contains_key("$t") {
                return build_typed(spec);
            }
            Value::map(
                &Type::map_of(Type::string(), Type::any()),
                m.iter()
                    .map(|(k, v)| (Value::string(k), build(v)))
                    .collect(),
            )
        }
    }
}

fn coerce(v: Value, ty: &Type) -> Value {
    let numeric = |k: rust_stdlib::text::template::value::Kind| {
        k.is_int()
            || k.is_uint()
            || matches!(
                k,
                rust_stdlib::text::template::value::Kind::Float32
                    | rust_stdlib::text::template::value::Kind::Float64
            )
    };
    if v.is_valid() && v.kind() != ty.kind() && numeric(v.kind()) && numeric(ty.kind()) {
        return v.convert(ty);
    }
    v
}

fn build_typed(spec: &Json) -> Value {
    let t = spec.get("$t").and_then(Json::as_str).unwrap_or("");
    let v = || spec.get("v").map(build).unwrap_or_else(Value::nil);
    match t {
        "int" | "int8" | "int16" | "int32" | "int64" => {
            Value::int_of(&type_named(t), num(spec, "v") as i64)
        }
        "uint" | "uint8" | "uint16" | "uint32" | "uint64" | "uintptr" => {
            let ty = if t == "uintptr" {
                Type::uintptr()
            } else {
                type_named(t)
            };
            Value::uint_of(&ty, num(spec, "v") as u64)
        }
        "float32" => Value::float_of(&Type::float32(), num(spec, "v")),
        "float64" => Value::float64(num(spec, "v")),
        "complex64" => Value::complex_of(&Type::complex64(), num(spec, "re"), num(spec, "im")),
        "complex128" => Value::complex128(num(spec, "re"), num(spec, "im")),
        "bool" => Value::bool_(matches!(spec.get("v"), Some(Json::Bool(true)))),
        "string" => Value::string(spec.get("v").and_then(Json::as_str).unwrap_or("")),
        "inf" => Value::float64(if num(spec, "v") < 0.0 {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        }),
        "nan" => Value::float64(f64::NAN),
        "negzero" => Value::float64(-0.0),
        "slice" => {
            let et = type_named(spec.get("e").and_then(Json::as_str).unwrap_or("any"));
            let items = spec
                .get("v")
                .and_then(Json::as_array)
                .unwrap_or(&[])
                .iter()
                .map(|x| coerce(build(x), &et))
                .collect();
            Value::slice(&et, items)
        }
        "array" => {
            let et = type_named(spec.get("e").and_then(Json::as_str).unwrap_or("any"));
            let items: Vec<Value> = spec
                .get("v")
                .and_then(Json::as_array)
                .unwrap_or(&[])
                .iter()
                .map(|x| coerce(build(x), &et))
                .collect();
            Value::array(&Type::array_of(items.len(), et), items)
        }
        "map" => {
            let kt = type_named(spec.get("k").and_then(Json::as_str).unwrap_or("string"));
            let et = type_named(spec.get("e").and_then(Json::as_str).unwrap_or("any"));
            let entries = spec
                .get("v")
                .and_then(Json::as_array)
                .unwrap_or(&[])
                .iter()
                .map(|p| {
                    let p = p.as_array().expect("pair");
                    (coerce(build(&p[0]), &kt), coerce(build(&p[1]), &et))
                })
                .collect();
            Value::map(&Type::map_of(kt, et), entries)
        }
        "ptr" => Value::ptr(v()),
        "nilptr" => Value::nil_ptr(&Type::ptr_to(type_named(
            spec.get("e").and_then(Json::as_str).unwrap_or("int"),
        ))),
        "nilmap" => Value::nil_map(&Type::map_of(
            type_named(spec.get("k").and_then(Json::as_str).unwrap_or("string")),
            type_named(spec.get("e").and_then(Json::as_str).unwrap_or("int")),
        )),
        "nilslice" => Value::nil_slice(&Type::slice_of(type_named(
            spec.get("e").and_then(Json::as_str).unwrap_or("int"),
        ))),
        "nilany" => Value::nil(),
        "html" | "css" | "js" | "jsstr" | "url" | "srcset" | "htmlattr" => {
            html_data::html_typed(t, spec.get("v").and_then(Json::as_str).unwrap_or(""))
                .expect("typed content")
        }
        "func" => match spec.get("n").and_then(Json::as_str) {
            Some("plusone") => Value::func_of(
                FuncSig::new(vec![Type::int()], vec![Type::int()], false),
                |a| Ok(Value::int(a[0].as_int() + 1)),
            ),
            Some("result") => {
                Value::func_of(FuncSig::new(vec![], vec![Type::string()], false), |_| {
                    Ok(Value::string("result"))
                })
            }
            other => panic!("unknown func {other:?}"),
        },
        "struct" => {
            let fields = spec.get("fields").and_then(Json::as_array).unwrap_or(&[]);
            let mut defs = Vec::new();
            let mut vals = Vec::new();
            for f in fields {
                let f = f.as_array().expect("field triple");
                let val = build(&f[1]);
                let as_any = f.get(2).and_then(Json::as_str) == Some("any");
                let ty = if as_any || !val.is_valid() {
                    Type::any()
                } else {
                    val.type_().expect("valid").clone()
                };
                defs.push(Field::new(f[0].as_str().expect("name"), ty));
                vals.push(val);
            }
            Value::struct_(&Type::struct_of(defs), vals)
        }
        "named" => match spec.get("n").and_then(Json::as_str) {
            Some("namedInt") => {
                Value::named(&data::type_named_int(), Value::int(num(spec, "v") as i64))
            }
            Some("namedStr") => Value::named(
                &data::type_named_str(),
                Value::string(spec.get("v").and_then(Json::as_str).unwrap_or("")),
            ),
            other => panic!("unknown named type {other:?}"),
        },
        other => panic!("unknown typed spec {other}"),
    }
}

#[allow(unused)]
fn unused(_: ChanDir) {}
