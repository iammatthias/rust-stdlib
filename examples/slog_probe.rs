//! Line protocol used by `tools/log_check.py` for the log/slog Go differential.
//! Each stdin line is a JSON scenario; each stdout line is `hex(markers):hex(output)`.
use rust_stdlib::{
    context::Context,
    encoding::json::{self, Value as J},
    log::slog::{
        self, Arg, Attr, Bytes, ErrorValue, Handler, HandlerOptions, JSONHandler, JsonAny, Level,
        LogValuer, MultiHandler, ReplaceAttr, Source, TextHandler, Value,
    },
    strconv,
    time::{DateTime, Duration},
};
use std::{
    io::{self, BufRead, Write},
    sync::{Arc, Mutex},
};

type R<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Clone)]
struct Shared(Arc<Mutex<Vec<u8>>>);

impl Write for Shared {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Lv(Value);

impl LogValuer for Lv {
    fn log_value(&self) -> Value {
        self.0.clone()
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn get<'a>(m: &'a J, k: &str) -> Option<&'a J> {
    m.get(k).filter(|v| !matches!(v, J::Null))
}

fn text<'a>(m: &'a J, k: &str) -> &'a str {
    match m.get(k) {
        Some(J::String(s)) => s,
        _ => "",
    }
}

fn list(v: Option<&J>) -> &[J] {
    match v {
        Some(J::Array(a)) => a,
        _ => &[],
    }
}

fn dec(v: &J) -> i64 {
    match v {
        J::String(s) => s.parse().unwrap(),
        _ => panic!("expected decimal string"),
    }
}

fn int_field(v: &J) -> i64 {
    match v {
        J::Number(n) => n.as_i64().unwrap(),
        _ => panic!("expected number"),
    }
}

fn time_of(v: &J) -> DateTime {
    DateTime::from_unix(
        int_field(v.get("s").unwrap()),
        int_field(v.get("n").unwrap()) as u32,
        int_field(v.get("off").unwrap()) as i32,
    )
    .unwrap()
}

fn any_of(v: &J) -> Value {
    match v {
        J::Null => Value::default(),
        J::Bool(b) => Value::Bool(*b),
        J::Number(n) => Value::Float64(strconv::parse_float(n.as_str(), 64).unwrap()),
        J::String(s) => Value::String(s.clone()),
        other => Value::dynamic(JsonAny(other.clone())),
    }
}

fn to_value(spec: &J) -> Value {
    let v = spec.get("v").unwrap_or(&J::Null);
    match text(spec, "t") {
        "str" => slog::string_value(match v {
            J::String(s) => s,
            _ => panic!("str"),
        }),
        "int" => Value::Int64(dec(v)),
        "uint" => Value::Uint64(match v {
            J::String(s) => s.parse().unwrap(),
            _ => panic!("uint"),
        }),
        "f64" => Value::Float64(f64::from_bits(match v {
            J::String(s) => u64::from_str_radix(s, 16).unwrap(),
            _ => panic!("f64"),
        })),
        "bool" => Value::Bool(matches!(v, J::Bool(true))),
        "dur" => Value::Duration(Duration::from_nanos(dec(v))),
        "time" => slog::time_value(time_of(v)),
        "group" => slog::group_value(to_attrs(list(Some(v)))),
        "nil" => Value::default(),
        "any" => any_of(v),
        "err" => Value::dynamic(ErrorValue(match v {
            J::String(s) => s.clone(),
            _ => panic!("err"),
        })),
        "bytes" => Value::dynamic(Bytes(match v {
            J::String(s) => unhex(s),
            _ => panic!("bytes"),
        })),
        "level" => Value::dynamic(Level(dec(v))),
        "valuer" => Value::log_valuer_value(Lv(to_value(v))),
        other => panic!("unknown value type {other}"),
    }
}

fn to_attr(spec: &J) -> Attr {
    Attr::new(text(spec, "k"), to_value(spec))
}

fn to_attrs(l: &[J]) -> Vec<Attr> {
    l.iter().map(to_attr).collect()
}

fn to_args(l: &[J]) -> Vec<Arg> {
    let mut args = Vec::new();
    for a in l {
        if let Some(at) = get(a, "attr") {
            args.push(Arg::Attr(to_attr(at)));
        } else if let Some(bad) = get(a, "bad") {
            args.push(Arg::Value(to_value(bad)));
        } else if let Some(val) = get(a, "val") {
            args.push(Arg::Key(text(a, "key").to_owned()));
            args.push(Arg::Value(to_value(val)));
        } else {
            args.push(Arg::Key(text(a, "key").to_owned()));
        }
    }
    args
}

fn upper_ascii(s: &str) -> String {
    s.to_ascii_uppercase()
}

fn apply_mode(mode: &str, groups: &[String], mut a: Attr) -> Attr {
    match mode {
        "drop_time" => {
            if groups.is_empty() && a.key == "time" {
                return Attr::default();
            }
        }
        "rename" => {
            if groups.is_empty() {
                match a.key.as_str() {
                    "time" => a.key = "ts".into(),
                    "msg" => a.key = "message".into(),
                    "level" => a.key = "lvl".into(),
                    "source" => a.key = "src".into(),
                    _ => {}
                }
            }
        }
        "drop_key" => {
            if a.key == "drop" {
                return Attr::default();
            }
        }
        "upper" => {
            if let Value::String(s) = &a.value {
                a.value = Value::String(upper_ascii(s));
            }
        }
        "level_num" => {
            if groups.is_empty() && a.key == "level" {
                if let Some(d) = a.value.any() {
                    if let Some(l) = d.as_any().downcast_ref::<Level>() {
                        a.value = Value::Int64(l.0);
                    }
                }
            }
        }
        "group_aware" => {
            if !groups.is_empty() {
                a.key = format!("{}/{}", groups.join("/"), a.key);
            }
        }
        "to_group" => {
            if a.key == "g" {
                if let Value::Int64(n) = a.value {
                    return slog::group_attrs(
                        "g",
                        vec![slog::int64("a", n), slog::int64("b", n.wrapping_add(1))],
                    );
                }
            }
            if a.key == "emptyg" {
                return Attr::new("emptyg", Value::Group(Vec::new()));
            }
            if a.key == "inl" {
                return slog::group_attrs("", vec![slog::int("p", 1), slog::string("q", "x")]);
            }
        }
        "zero_all" => return Attr::default(),
        "fixsrc" => {
            if a.key == "source" {
                if let Some(d) = a.value.any() {
                    if let Some(s) = d.as_any().downcast_ref::<Source>() {
                        if *s != Source::default() {
                            return Attr::new(
                                "source",
                                Value::dynamic(Source {
                                    function: "pkg.fn".into(),
                                    file: "x/y.go".into(),
                                    line: 7,
                                }),
                            );
                        }
                    }
                }
            }
        }
        "time_unix" => {
            if let Value::Time(t) = &a.value {
                return slog::int64(&a.key, t.unix_seconds());
            }
        }
        "lv_ret" => {
            if a.key == "lv" {
                return Attr::new(
                    "lv2",
                    Value::log_valuer_value(Lv(slog::string_value("late"))),
                );
            }
        }
        "empty_str_drop" => {
            if matches!(&a.value, Value::String(s) if s.is_empty()) {
                return Attr::default();
            }
        }
        other => panic!("unknown rep mode {other}"),
    }
    a
}

fn options(spec: &J) -> HandlerOptions {
    let mut opts = HandlerOptions {
        add_source: matches!(spec.get("add_source"), Some(J::Bool(true))),
        ..Default::default()
    };
    if let Some(l) = get(spec, "level") {
        opts.level = Some(Arc::new(Level(dec(l))));
    }
    let modes: Vec<String> = list(spec.get("rep"))
        .iter()
        .map(|m| match m {
            J::String(s) => s.clone(),
            _ => panic!("mode"),
        })
        .collect();
    if !modes.is_empty() {
        let rep: ReplaceAttr = Arc::new(move |groups: &[String], mut a: Attr| {
            for m in &modes {
                a = apply_mode(m, groups, a);
                if a.equal(&Attr::default()) {
                    return a;
                }
            }
            a
        });
        opts.replace_attr = Some(rep);
    }
    opts
}

fn new_handler(kind: &str, spec: &J, w: &Shared) -> Arc<dyn Handler> {
    match kind {
        "text" => Arc::new(TextHandler::new(w.clone(), Some(options(spec)))),
        "json" => Arc::new(JSONHandler::new(w.clone(), Some(options(spec)))),
        "multi" => {
            let hs = list(spec.get("subs"))
                .iter()
                .map(|s| new_handler(text(s, "h"), s, w))
                .collect();
            let m: MultiHandler = MultiHandler::new(hs);
            Arc::new(m)
        }
        "discard" => Arc::new(slog::DISCARD_HANDLER),
        other => panic!("unknown handler {other}"),
    }
}

fn run(spec: &J) -> String {
    let buf = Shared(Arc::new(Mutex::new(Vec::new())));
    let ctx = Context::background();
    let mut h = new_handler(text(spec, "h"), spec, &buf);
    let via_logger = get(spec, "via").is_some();
    let mut logger = slog::Logger::new(h.clone());
    for op in list(spec.get("ops")) {
        if via_logger {
            if let Some(J::String(g)) = op.get("group") {
                logger = logger.with_group(g);
            } else {
                logger = logger.with(&to_args(list(op.get("args"))));
            }
        } else if let Some(J::String(g)) = op.get("group") {
            h = h.with_group(g);
        } else {
            h = h.with_attrs(to_attrs(list(op.get("attrs"))));
        }
    }
    let mut markers = String::new();
    for rm in list(spec.get("recs")) {
        let level = Level(dec(rm.get("lvl").unwrap()));
        let msg = text(rm, "msg");
        if via_logger {
            markers.push_str(if logger.enabled(&ctx, level) {
                "E1"
            } else {
                "E0"
            });
            let args = to_args(list(rm.get("args")));
            match text(rm, "api") {
                "attrs" => {
                    let attrs: Vec<Attr> = args
                        .iter()
                        .filter_map(|a| match a {
                            Arg::Attr(at) => Some(at.clone()),
                            _ => None,
                        })
                        .collect();
                    logger.log_attrs(&ctx, level, msg, &attrs);
                }
                "debug" => logger.debug(msg, &args),
                "info" => logger.info(msg, &args),
                "warn" => logger.warn(msg, &args),
                "error" => logger.error(msg, &args),
                _ => logger.log(&ctx, level, msg, &args),
            }
            continue;
        }
        let t = match get(rm, "t") {
            Some(t) => time_of(t),
            None => slog::zero_time(),
        };
        let pc = matches!(rm.get("pc"), Some(J::Bool(true)));
        let mut rec = slog::Record::new(
            t,
            level,
            msg,
            if pc {
                Some(std::panic::Location::caller())
            } else {
                None
            },
        );
        if let Some(a) = get(rm, "attrs") {
            rec.add_attrs(&to_attrs(list(Some(a))));
        }
        if h.enabled(&ctx, level) {
            markers.push_str("E1");
            h.handle(&ctx, rec).expect("handle");
        } else {
            markers.push_str("E0");
        }
    }
    let out = buf.0.lock().unwrap().clone();
    format!("{}:{}", hex(markers.as_bytes()), hex(&out))
}

fn main() -> R<()> {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let spec = line?.parse::<json::Value>()?;
        writeln!(out, "{}", run(&spec))?;
    }
    Ok(())
}
