//! Line protocol used by `tools/expvar_check.py`; mirrors `tools/expvar_oracle.go`.
//! Each request is `<prefix>|<op>|<op>|...` and each answer is one line of
//! records in the same format as the Go oracle.
use rust_stdlib::encoding::json::{Number, Value};
use rust_stdlib::expvar::{self, Float, Func, Int, KeyValue, Map, String as StringVar, Var};
use rust_stdlib::strconv;
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

enum Obj {
    Int(Arc<Int>),
    Float(Arc<Float>),
    Map(Arc<Map>),
    Str(Arc<StringVar>),
    Func(Arc<Func>),
}

impl Obj {
    fn var(&self) -> Arc<dyn Var> {
        match self {
            Obj::Int(v) => Arc::clone(v) as Arc<dyn Var>,
            Obj::Float(v) => Arc::clone(v) as Arc<dyn Var>,
            Obj::Map(v) => Arc::clone(v) as Arc<dyn Var>,
            Obj::Str(v) => Arc::clone(v) as Arc<dyn Var>,
            Obj::Func(v) => Arc::clone(v) as Arc<dyn Var>,
        }
    }
}

fn hex(text: &str) -> String {
    text.bytes().map(|b| format!("{b:02x}")).collect()
}

fn decode(text: &str) -> String {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex operand"))
        .collect();
    String::from_utf8(bytes).expect("UTF-8 operand")
}

/// The functions shared with `funcs` in the Go oracle. Go's NaN result is
/// not used: a JSON value cannot hold it (see `Func`).
fn func(kind: usize) -> Func {
    Func::new(move || match kind {
        0 => Value::Array(vec![Value::from("a"), Value::from("b<>&\u{2028}")]),
        1 => Value::Object(
            BTreeMap::from([
                ("z".to_string(), Value::Number(Number::new("1").unwrap())),
                ("a".to_string(), Value::Number(Number::new("2").unwrap())),
            ])
            .into(),
        ),
        2 => Value::Null,
        _ => Value::Number(Number::new("3.5").unwrap()),
    })
}

fn some(v: Option<Arc<dyn Var>>) -> String {
    match v {
        None => "nil".to_string(),
        Some(v) => format!("some:{}", hex(&v.to_string())),
    }
}

fn run(prefix: &str, env: &mut BTreeMap<String, Obj>, f: &[&str]) -> String {
    let published = |name: &str| format!("{prefix}{name}");
    let int = |env: &BTreeMap<String, Obj>, n: &str| match env.get(n) {
        Some(Obj::Int(v)) => Arc::clone(v),
        _ => panic!("not an Int: {n}"),
    };
    let float = |env: &BTreeMap<String, Obj>, n: &str| match env.get(n) {
        Some(Obj::Float(v)) => Arc::clone(v),
        _ => panic!("not a Float: {n}"),
    };
    let map = |env: &BTreeMap<String, Obj>, n: &str| match env.get(n) {
        Some(Obj::Map(v)) => Arc::clone(v),
        _ => panic!("not a Map: {n}"),
    };
    match f[0] {
        "ni" => {
            env.insert(
                f[1].to_string(),
                Obj::Int(expvar::Int::published(&published(f[1]))),
            );
            "ok".to_string()
        }
        "nf" => {
            env.insert(
                f[1].to_string(),
                Obj::Float(expvar::Float::published(&published(f[1]))),
            );
            "ok".to_string()
        }
        "nm" => {
            env.insert(
                f[1].to_string(),
                Obj::Map(expvar::Map::published(&published(f[1]))),
            );
            "ok".to_string()
        }
        "ns" => {
            env.insert(
                f[1].to_string(),
                Obj::Str(expvar::String::published(&published(f[1]))),
            );
            "ok".to_string()
        }
        "si" => {
            env.insert(f[1].to_string(), Obj::Int(Arc::new(Int::default())));
            "ok".to_string()
        }
        "sf" => {
            env.insert(f[1].to_string(), Obj::Float(Arc::new(Float::default())));
            "ok".to_string()
        }
        "sm" => {
            let m = Arc::new(Map::default());
            m.init();
            env.insert(f[1].to_string(), Obj::Map(m));
            "ok".to_string()
        }
        "ss" => {
            env.insert(f[1].to_string(), Obj::Str(Arc::new(StringVar::default())));
            "ok".to_string()
        }
        "fn" => {
            let kind: usize = f[2].parse().expect("func kind");
            env.insert(f[1].to_string(), Obj::Func(Arc::new(func(kind))));
            "ok".to_string()
        }
        "pub" => {
            let v = env.get(f[1]).expect("published object").var();
            expvar::publish(&published(&decode(f[2])), v);
            "ok".to_string()
        }
        "get" => some(expvar::get(&published(&decode(f[1])))),
        "add" => {
            int(env, f[1]).add(f[2].parse().expect("int"));
            "ok".to_string()
        }
        "addf" => {
            float(env, f[1]).add(f[2].parse().expect("float"));
            "ok".to_string()
        }
        "set" => {
            match env.get(f[1]).expect("object") {
                Obj::Int(v) => v.set(f[2].parse().expect("int")),
                Obj::Float(v) => v.set(f[2].parse().expect("float")),
                Obj::Str(v) => v.set(&decode(f[2])),
                _ => {}
            }
            "ok".to_string()
        }
        "mset" => {
            let value = env.get(f[3]).expect("object").var();
            map(env, f[1]).set(&decode(f[2]), value);
            "ok".to_string()
        }
        "madd" => {
            map(env, f[1]).add(&decode(f[2]), f[3].parse().expect("int"));
            "ok".to_string()
        }
        "maddf" => {
            map(env, f[1]).add_float(&decode(f[2]), f[3].parse().expect("float"));
            "ok".to_string()
        }
        "mdel" => {
            map(env, f[1]).delete(&decode(f[2]));
            "ok".to_string()
        }
        "minit" => {
            map(env, f[1]).init();
            "ok".to_string()
        }
        "mget" => some(map(env, f[1]).get(&decode(f[2]))),
        "mdo" => {
            let items: Vec<String> = map(env, f[1])
                .iter()
                .map(|KeyValue { key, value }| format!("{}={}", hex(&key), hex(&value.to_string())))
                .collect();
            items.join(";")
        }
        "str" => {
            let v = env.get(f[1]).expect("object").var();
            hex(&v.to_string())
        }
        "val" => match env.get(f[1]).expect("object") {
            Obj::Int(v) => v.value().to_string(),
            Obj::Float(v) => strconv::format_float(v.value(), b'g', -1, 64),
            Obj::Str(v) => hex(&v.value()),
            _ => "-".to_string(),
        },
        op => panic!("bad op {op}"),
    }
}

fn process(line: &str) -> String {
    let parts: Vec<&str> = line.split('|').collect();
    let prefix = parts[0];
    let mut env = BTreeMap::new();
    let mut records = Vec::new();
    for op in &parts[1..] {
        let fields: Vec<&str> = op.split(':').collect();
        let record = catch_unwind(AssertUnwindSafe(|| run(prefix, &mut env, &fields)));
        records.push(record.unwrap_or_else(|_| "panic".to_string()));
    }
    records.join(" ")
}

fn main() -> std::io::Result<()> {
    use std::io::{BufRead, Write};
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    for line in std::io::stdin().lock().lines() {
        writeln!(out, "{}", process(&line?))?;
    }
    Ok(())
}
