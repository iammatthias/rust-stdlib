//! Line protocol used by `tools/flag_check.py` for Go differential checks. See
//! `tools/flag_oracle.go` for the request and reply format.
use rust_stdlib::{
    encoding::{TextMarshaler, TextUnmarshaler},
    flag::{BoxError, ErrorHandling, FlagSet, Ptr, Value},
    strconv::{self, NumError},
    time::Duration,
};
use std::{
    error::Error,
    io::{self, BufRead, Write},
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{Arc, Mutex},
};

/// Go's `(value, error)` pair: the value that comes with an error.
fn pair<T>(r: Result<T, NumError>, partial: impl FnOnce(&NumError) -> T) -> (T, Option<NumError>) {
    match r {
        Ok(v) => (v, None),
        Err(e) => (partial(&e), Some(e)),
    }
}

fn enc(s: &str) -> String {
    if s.is_empty() {
        return "_".into();
    }
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

fn dec(s: &str) -> String {
    if s == "_" {
        return String::new();
    }
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex argument"))
        .collect();
    String::from_utf8(bytes).expect("UTF-8 argument")
}

fn flag01(b: bool) -> String {
    if b { "1" } else { "0" }.into()
}

#[derive(Clone, Default)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);
impl SharedBuf {
    fn take(&self) -> String {
        let mut guard = self.0.lock().unwrap();
        let text = String::from_utf8_lossy(&guard).into_owned();
        guard.clear();
        text
    }
}
impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Joins its values with commas; the zero value prints as "".
struct ListValue(Ptr<Vec<String>>);
impl std::fmt::Display for ListValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&{ self.0.with(|l| l.join(",")) })
    }
}
impl Value for ListValue {
    fn set(&mut self, s: &str) -> Result<(), BoxError> {
        self.0.with(|l| l.push(s.to_owned()));
        Ok(())
    }
}

/// A boolean flag that counts its uses; the zero value prints "0".
struct CountValue(Ptr<isize>);
impl std::fmt::Display for CountValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&{ self.0.get().to_string() })
    }
}
impl Value for CountValue {
    fn set(&mut self, _: &str) -> Result<(), BoxError> {
        self.0.with(|c| *c += 1);
        Ok(())
    }
    fn is_bool_flag(&self) -> bool {
        true
    }
    fn zero_string(&self) -> Option<String> {
        Some("0".into())
    }
}

#[derive(Default)]
struct UpperText {
    s: String,
}
impl TextMarshaler for UpperText {
    fn marshal_text(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(self.s.clone().into_bytes())
    }
}
impl TextUnmarshaler for UpperText {
    fn unmarshal_text(&mut self, text: &[u8]) -> Result<(), Box<dyn Error>> {
        if text == b"bad" {
            return Err("bad text".into());
        }
        self.s = String::from_utf8_lossy(text).to_uppercase();
        Ok(())
    }
}

fn type_name(value: &dyn std::any::Any) -> &'static str {
    if value.is::<bool>() {
        "bool"
    } else if value.is::<isize>() {
        "int"
    } else if value.is::<i64>() {
        "int64"
    } else if value.is::<usize>() {
        "uint"
    } else if value.is::<u64>() {
        "uint64"
    } else if value.is::<String>() {
        "string"
    } else if value.is::<f64>() {
        "float64"
    } else if value.is::<Duration>() {
        "time.Duration"
    } else if value.is::<Ptr<UpperText>>() {
        "*main.upperText"
    } else {
        "?"
    }
}

fn run(tok: &[&str]) -> Vec<String> {
    let mut pos = 0;
    let mut next = || {
        let s = dec(tok[pos]);
        pos += 1;
        s
    };
    let set_name = next();
    let usage_mode: usize = next().parse().unwrap_or(0);
    let nflags: usize = next().parse().unwrap_or(0);
    let defs: Vec<[String; 4]> = (0..nflags)
        .map(|_| [next(), next(), next(), next()])
        .collect();
    let nargs: usize = next().parse().unwrap_or(0);
    let args: Vec<String> = (0..nargs).map(|_| next()).collect();
    let nsets: usize = next().parse().unwrap_or(0);
    let sets: Vec<[String; 2]> = (0..nsets).map(|_| [next(), next()]).collect();

    let buf = SharedBuf::default();
    let log = Arc::new(Mutex::new(Vec::<String>::new()));
    let mut fs = FlagSet::new(&set_name, ErrorHandling::ContinueOnError);
    fs.set_output(buf.clone());
    if usage_mode == 1 {
        fs.usage = Some(Box::new(|f| {
            let _ = writeln!(f.output(), "CUSTOM USAGE");
        }));
    }

    let defined = catch_unwind(AssertUnwindSafe(|| {
        for [kind, name, def, usage] in &defs {
            match kind.as_str() {
                "bool" => {
                    fs.bool(name, strconv::parse_bool(def).unwrap_or(false), usage);
                }
                "int" => {
                    fs.int(
                        name,
                        pair(strconv::atoi(def), |e| e.int_value() as isize).0,
                        usage,
                    );
                }
                "int64" => {
                    fs.int64(
                        name,
                        pair(strconv::parse_int(def, 10, 64), |e| e.int_value()).0,
                        usage,
                    );
                }
                "uint" => {
                    fs.uint(
                        name,
                        pair(strconv::parse_uint(def, 10, 64), |e| e.uint_value()).0 as usize,
                        usage,
                    );
                }
                "uint64" => {
                    fs.uint64(
                        name,
                        pair(strconv::parse_uint(def, 10, 64), |e| e.uint_value()).0,
                        usage,
                    );
                }
                "string" => {
                    fs.string(name, def.clone(), usage);
                }
                "float64" => {
                    fs.float64(
                        name,
                        pair(strconv::parse_float(def, 64), |e| e.float_value()).0,
                        usage,
                    );
                }
                "duration" => {
                    fs.duration(
                        name,
                        def.parse::<Duration>().unwrap_or(Duration::from_nanos(0)),
                        usage,
                    );
                }
                "list" => {
                    let items = if def.is_empty() {
                        Vec::new()
                    } else {
                        def.split(',').map(str::to_owned).collect()
                    };
                    fs.var(ListValue(Ptr::new(items)), name, usage);
                }
                "count" => {
                    let n = pair(strconv::atoi(def), |e| e.int_value() as isize).0;
                    fs.var(CountValue(Ptr::new(n)), name, usage);
                }
                "text" => {
                    fs.text_var(
                        Ptr::new(UpperText::default()),
                        name,
                        UpperText { s: def.clone() },
                        usage,
                    );
                }
                "func" | "boolfunc" => {
                    let log = Arc::clone(&log);
                    let n = name.clone();
                    let callback = move |s: &str| -> Result<(), BoxError> {
                        log.lock().unwrap().push(format!("{n}={s}"));
                        if s == "bad" {
                            return Err("bad func value".into());
                        }
                        Ok(())
                    };
                    if kind == "func" {
                        fs.func(name, usage, callback);
                    } else {
                        fs.bool_func(name, usage, callback);
                    }
                }
                other => panic!("unknown kind {other}"),
            }
        }
    }));
    if let Err(payload) = defined {
        let text = payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
            .unwrap_or_default();
        return vec!["PANIC".into(), enc(&text), enc(&buf.take())];
    }

    let mut reply = vec!["OK".to_owned()];
    if let Err(err) = fs.parse(&args) {
        reply = vec![
            "ERR".into(),
            enc(&err.to_string()),
            flag01(err == rust_stdlib::flag::ERR_HELP),
        ];
    }
    reply.push(flag01(fs.parsed()));
    reply.push(fs.nflag().to_string());
    reply.push(fs.narg().to_string());
    reply.extend(fs.args().iter().map(|a| enc(a)));
    reply.extend([enc(fs.arg(0)), enc(fs.arg(1)), enc(fs.name())]);

    let mut all = Vec::new();
    fs.visit_all(|f| {
        all.extend([
            enc(&f.name),
            enc(&f.value.to_string()),
            enc(&f.def_value),
            enc(&f.usage),
        ]);
    });
    reply.extend(["ALL".to_owned(), (all.len() / 4).to_string()]);
    reply.extend(all);
    let mut visited = Vec::new();
    fs.visit(|f| visited.push(enc(&f.name)));
    reply.extend(["SET".to_owned(), visited.len().to_string()]);
    reply.extend(visited);

    reply.extend(["OUT".to_owned(), enc(&buf.take())]);
    fs.print_defaults();
    reply.extend(["DEFAULTS".to_owned(), enc(&buf.take())]);
    reply.extend(["LOG".to_owned(), enc(&log.lock().unwrap().join("|"))]);

    reply.push("SETS".into());
    for [name, value] in &sets {
        let msg = fs.set(name, value).err().map(|e| e.to_string());
        reply.push(enc(&msg.unwrap_or_default()));
    }
    let mut after = Vec::new();
    fs.visit(|f| {
        after.extend([enc(&f.name), enc(&f.value.to_string())]);
    });
    reply.push((after.len() / 2).to_string());
    reply.extend(after);
    for [_, name, _, _] in &defs {
        if let Some(f) = fs.lookup(name) {
            reply.push(match f.value.as_getter() {
                Some(g) => enc(type_name(&*g.get())),
                None => "_".into(),
            });
        }
    }
    reply
}

fn main() -> io::Result<()> {
    std::panic::set_hook(Box::new(|_| {}));
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line?;
        let tok: Vec<&str> = line.split_whitespace().collect();
        if tok.is_empty() {
            continue;
        }
        writeln!(out, "{}", run(&tok).join(" "))?;
    }
    Ok(())
}
