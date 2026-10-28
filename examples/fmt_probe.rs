//! Line protocol used by `tools/fmt_check.py` for Go differential checks;
//! see the header of `tools/fmt_oracle.go` for the request language.
use rust_stdlib::printf::{
    self as fmt, format_string, Formatter, ScanArg, ScanErrorKind, ScanState, Scanner, State, Value,
};
use rust_stdlib::strconv::Complex;
use std::io::{self, BufRead, Write};

// ---- catalog of named types (mirrored in tools/fmt_oracle.go)

struct SIntS(i64);
impl std::fmt::Display for SIntS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("SInt({})", self.0))
    }
}
struct SStrS(Vec<u8>);
impl std::fmt::Display for SStrS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("<{}>", String::from_utf8_lossy(&self.0)))
    }
}
#[derive(Debug)]
struct ErrT(i64);
impl std::fmt::Display for ErrT {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "E{}", self.0)
    }
}
impl std::error::Error for ErrT {}
struct GoS(i64);
impl std::fmt::Display for GoS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("S{}", self.0))
    }
}
impl std::fmt::Debug for GoS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("GoS!{}", self.0))
    }
}
struct FmtN(i64);
impl Formatter for FmtN {
    fn format(&self, f: &mut dyn State, verb: char) {
        let fs = format_string(&*f, verb);
        let (w, p) = (f.width(), f.precision());
        let args = [
            Value::from(fs.as_str()),
            Value::int(self.0),
            Value::from(w.is_some()),
            Value::int(w.unwrap_or(0) as i64),
            Value::from(p.is_some()),
            Value::int(p.unwrap_or(0) as i64),
            Value::from(f.flag('+')),
            Value::from(f.flag('-')),
            Value::from(f.flag('#')),
            Value::from(f.flag(' ')),
            Value::from(f.flag('0')),
        ];
        let mut out = Vec::new();
        fmt::appendf(&mut out, "<%s|%d|%v %d|%v %d|%v%v%v%v%v>", &args);
        let _ = f.write_all(&out);
    }
}
struct PanicS;
impl std::fmt::Display for PanicS {
    fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        panic!("boom")
    }
}
#[derive(Debug)]
struct PanicE;
impl std::fmt::Display for PanicE {
    fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        panic!("bad")
    }
}
impl std::error::Error for PanicE {}
struct NpS(Option<Vec<u8>>);
impl std::fmt::Display for NpS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s: String = {
            match &self.0 {
                Some(s) => format!("np{}", String::from_utf8_lossy(s)),
                None => panic!("nil pointer dereference"),
            }
        };
        f.write_str(&s)
    }
}
struct PtrSS(i64);
impl std::fmt::Display for PtrSS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("PtrS{}", self.0))
    }
}
#[derive(Debug)]
struct PlainErr(String);
impl std::fmt::Display for PlainErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for PlainErr {}

const ADDR: usize = 0xc0_0004_0000;

// ---- values

struct Toks<'a> {
    t: Vec<&'a str>,
    i: usize,
}

impl<'a> Toks<'a> {
    fn next(&mut self) -> &'a str {
        let s = self.t[self.i];
        self.i += 1;
        s
    }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn unhex_str(s: &str) -> String {
    String::from_utf8(unhex(s)).unwrap()
}

fn sint(n: i64) -> Value {
    Value::named("main.SInt", Value::int(n)).with_display(SIntS(n))
}

fn is_iface(t: &str) -> bool {
    matches!(t, "interface {}" | "error" | "fmt.Stringer")
}

fn nil_for(ctx: Option<&str>) -> Value {
    match ctx {
        Some(t) if is_iface(t) => Value::NilIface(t.to_string()),
        _ => Value::Nil,
    }
}

fn value(k: &mut Toks, ctx: Option<&str>) -> Value {
    let tok = k.next();
    if tok == "nil" {
        return nil_for(ctx);
    }
    let p: Vec<&str> = tok.split(':').collect();
    match p[0] {
        "bool" => Value::Bool(p[1] == "1"),
        "int" => Value::int(p[1].parse().unwrap()),
        "int8" => Value::from(p[1].parse::<i8>().unwrap()),
        "int16" => Value::from(p[1].parse::<i16>().unwrap()),
        "int32" => Value::from(p[1].parse::<i32>().unwrap()),
        "int64" => Value::from(p[1].parse::<i64>().unwrap()),
        "uint" => Value::uint(p[1].parse().unwrap()),
        "uint8" => Value::from(p[1].parse::<u8>().unwrap()),
        "uint16" => Value::from(p[1].parse::<u16>().unwrap()),
        "uint32" => Value::from(p[1].parse::<u32>().unwrap()),
        "uint64" => Value::from(p[1].parse::<u64>().unwrap()),
        "uintptr" => Value::Uint(p[1].parse().unwrap(), fmt::UintKind::Uintptr),
        "float32" => Value::Float32(f32::from_bits(u32::from_str_radix(p[1], 16).unwrap())),
        "float64" => Value::Float64(f64::from_bits(u64::from_str_radix(p[1], 16).unwrap())),
        "complex64" => {
            let q: Vec<&str> = p[1].split(',').collect();
            Value::Complex64(
                f32::from_bits(u32::from_str_radix(q[0], 16).unwrap()),
                f32::from_bits(u32::from_str_radix(q[1], 16).unwrap()),
            )
        }
        "complex128" => {
            let q: Vec<&str> = p[1].split(',').collect();
            Value::Complex128(
                f64::from_bits(u64::from_str_radix(q[0], 16).unwrap()),
                f64::from_bits(u64::from_str_radix(q[1], 16).unwrap()),
            )
        }
        "string" => Value::String(unhex(p[1])),
        "slice" => {
            let et = unhex_str(p[1]);
            let n: usize = p[2].parse().unwrap();
            if p[3] == "1" {
                return Value::nil_slice(&et);
            }
            let items = (0..n).map(|_| value(k, Some(&et))).collect();
            Value::slice(&et, items)
        }
        "array" => {
            let et = unhex_str(p[1]);
            let n: usize = p[2].parse().unwrap();
            let items = (0..n).map(|_| value(k, Some(&et))).collect();
            Value::array(&et, items)
        }
        "map" => {
            let (kt, vt) = (unhex_str(p[1]), unhex_str(p[2]));
            let n: usize = p[3].parse().unwrap();
            if p[4] == "1" {
                return Value::nil_map(&kt, &vt);
            }
            let entries = (0..n)
                .map(|_| {
                    let a = value(k, Some(&kt));
                    let b = value(k, Some(&vt));
                    (a, b)
                })
                .collect();
            Value::map(&kt, &vt, entries)
        }
        "struct" => {
            let n: usize = p[1].parse().unwrap();
            let mut fields = Vec::new();
            let mut ty = String::from("struct {");
            for i in 0..n {
                let name = unhex_str(k.next());
                let ft = unhex_str(k.next());
                ty.push_str(if i == 0 { " " } else { "; " });
                ty.push_str(&format!("{name} {ft}"));
                let v = value(k, Some(&ft));
                fields.push((name, v));
            }
            ty.push_str(if n == 0 { "}" } else { " }" });
            let fields = fields
                .iter()
                .map(|(n, v)| (n.as_str(), v.clone()))
                .collect();
            Value::strukt(&ty, fields)
        }
        "ptr" => {
            let et = unhex_str(p[1]);
            let name = format!("*{et}");
            if p[2] == "0" {
                return Value::nil_pointer(&name);
            }
            let e = value(k, Some(&et));
            Value::pointer(&name, ADDR, e)
        }
        "raw" => {
            let t = unhex_str(p[1]);
            Value::raw_pointer(&t, if p[2] == "0" { 0 } else { ADDR })
        }
        "named" => named(&p, k),
        _ => panic!("bad token {tok}"),
    }
}

fn pt(name: &str, x: i64, y: i64) -> Value {
    Value::strukt(name, vec![("X", Value::int(x)), ("Y", Value::int(y))])
}

fn named(p: &[&str], k: &mut Toks) -> Value {
    let int = || p[2].parse::<i64>().unwrap();
    match p[1] {
        "MyInt" => Value::named("main.MyInt", Value::int(int())),
        "MyUint" => Value::named("main.MyUint", Value::uint(p[2].parse().unwrap())),
        "MyFloat" => Value::named(
            "main.MyFloat",
            Value::Float64(f64::from_bits(u64::from_str_radix(p[2], 16).unwrap())),
        ),
        "MyStr" => Value::named("main.MyStr", Value::String(unhex(p[2]))),
        "MyBool" => Value::named("main.MyBool", Value::Bool(p[2] == "1")),
        "MyBytes" => Value::named(
            "main.MyBytes",
            if p[2] == "nil" {
                let mut v = Value::nil_slice("uint8");
                if let Value::Slice(s) = &mut v {
                    s.type_name = "main.MyBytes".into();
                }
                v
            } else {
                let mut v = Value::bytes(unhex(p[2]));
                if let Value::Slice(s) = &mut v {
                    s.type_name = "main.MyBytes".into();
                }
                v
            },
        ),
        "MyC" => {
            let q: Vec<&str> = p[2].split(',').collect();
            Value::named(
                "main.MyC",
                Value::Complex128(
                    f64::from_bits(u64::from_str_radix(q[0], 16).unwrap()),
                    f64::from_bits(u64::from_str_radix(q[1], 16).unwrap()),
                ),
            )
        }
        "SInt" => sint(int()),
        "SStr" => {
            Value::named("main.SStr", Value::String(unhex(p[2]))).with_display(SStrS(unhex(p[2])))
        }
        "ErrT" => {
            Value::strukt("main.ErrT", vec![("Code", Value::int(int()))]).with_error(ErrT(int()))
        }
        "GoS" => Value::strukt("main.GoS", vec![("A", Value::int(int()))])
            .with_display(GoS(int()))
            .with_debug(GoS(int())),
        "Fmt" => {
            Value::strukt("main.Fmt", vec![("N", Value::int(int()))]).with_formatter(FmtN(int()))
        }
        "PanicS" => Value::named("main.PanicS", Value::int(int())).with_display(PanicS),
        "PanicE" => Value::strukt("main.PanicE", vec![]).with_error(PanicE),
        "NilPS" => {
            if p[2] == "0" {
                Value::named("*main.NP", Value::nil_pointer("*main.NP")).with_display(NpS(None))
            } else {
                let s = unhex(p[3]);
                let inner = Value::pointer(
                    "*main.NP",
                    ADDR,
                    Value::strukt("main.NP", vec![("s", Value::String(s.clone()))]),
                );
                Value::named("*main.NP", inner).with_display(NpS(Some(s)))
            }
        }
        "PtrS" => Value::strukt("main.PtrS", vec![("A", Value::int(int()))]),
        "PtrSP" => {
            let inner = Value::pointer(
                "*main.PtrS",
                ADDR,
                Value::strukt("main.PtrS", vec![("A", Value::int(int()))]),
            );
            Value::named("*main.PtrS", inner).with_display(PtrSS(int()))
        }
        "Pt" => pt("main.Pt", int(), p[3].parse().unwrap()),
        "PtP" => Value::pointer(
            "*main.Pt",
            ADDR,
            pt("main.Pt", int(), p[3].parse().unwrap()),
        ),
        "Mixed" => {
            let d = value(k, Some("interface {}"));
            let e = value(k, Some("interface {}"));
            Value::strukt(
                "main.Mixed",
                vec![
                    ("A", Value::int(int())),
                    ("b", sint(p[3].parse().unwrap())),
                    ("C", sint(p[4].parse().unwrap())),
                    ("d", d),
                    ("E", e),
                ],
            )
        }
        "Wrap" => {
            let pp = if p[2] == "1" {
                Value::pointer(
                    "*main.Pt",
                    ADDR,
                    pt("main.Pt", p[3].parse().unwrap(), p[4].parse().unwrap()),
                )
            } else {
                Value::nil_pointer("*main.Pt")
            };
            let i = value(k, Some("interface {}"));
            let n: usize = p[5].parse().unwrap();
            let s: Vec<Value> = (0..n)
                .map(|_| sint(k.next().split(':').nth(1).unwrap().parse().unwrap()))
                .collect();
            let s = if s.is_empty() {
                Value::nil_slice("main.SInt")
            } else {
                Value::slice("main.SInt", s)
            };
            Value::strukt("main.Wrap", vec![("P", pp), ("I", i), ("S", s)])
        }
        "Gen" => {
            let v = value(k, Some("interface {}"));
            Value::strukt("main.Gen", vec![("V", v)])
        }
        "ErrNew" => {
            let msg = unhex_str(p[2]);
            let inner = Value::pointer(
                "*errors.errorString",
                ADDR,
                Value::strukt("errors.errorString", vec![("s", Value::from(msg.as_str()))]),
            );
            Value::named("*errors.errorString", inner).with_error(PlainErr(msg))
        }
        "ErrWrap" => Value::from(fmt::errorf("w:%w", &[named(&["named", "ErrT", p[2]], k)])),
        _ => panic!("bad named {}", p[1]),
    }
}

fn args(fields: &[&str]) -> Vec<Value> {
    fields
        .iter()
        .map(|f| {
            let mut k = Toks {
                t: f.split_whitespace().collect(),
                i: 0,
            };
            value(&mut k, None)
        })
        .collect()
}

// ---- scanning

struct Cs(String);
impl Scanner for Cs {
    fn scan(&mut self, state: &mut dyn ScanState, _verb: char) -> Result<(), ScanErrorKind> {
        let w = state.width();
        let tok = state.token(true, None)?;
        self.0 = String::from_utf8_lossy(&tok).to_uppercase();
        if let Some(w) = w {
            self.0.push_str(&format!("/{w}"));
        }
        Ok(())
    }
}

enum Dest {
    Bool(bool),
    Int(isize),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    Uint(usize),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    Uptr(u64),
    F32(f32),
    F64(f64),
    C64((f32, f32)),
    C128(Complex),
    Bytes(Vec<u8>),
    Scanner(Cs),
}

fn dest(kind: &str) -> Dest {
    match kind {
        "bool" => Dest::Bool(false),
        "int" => Dest::Int(0),
        "int8" => Dest::I8(0),
        "int16" => Dest::I16(0),
        "int32" => Dest::I32(0),
        "int64" => Dest::I64(0),
        "uint" => Dest::Uint(0),
        "uint8" => Dest::U8(0),
        "uint16" => Dest::U16(0),
        "uint32" => Dest::U32(0),
        "uint64" => Dest::U64(0),
        "uintptr" => Dest::Uptr(0),
        "float32" => Dest::F32(0.0),
        "float64" => Dest::F64(0.0),
        "complex64" => Dest::C64((0.0, 0.0)),
        "complex128" => Dest::C128(Complex::default()),
        // Go strings may hold invalid UTF-8; scan into bytes to compare exactly.
        "string" => Dest::Bytes(Vec::new()),
        "bytes" => Dest::Bytes(Vec::new()),
        "scanner" => Dest::Scanner(Cs(String::new())),
        _ => panic!("dest {kind}"),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}

fn canon(d: &Dest) -> String {
    match d {
        Dest::Bool(v) => v.to_string(),
        Dest::Int(v) => v.to_string(),
        Dest::I8(v) => v.to_string(),
        Dest::I16(v) => v.to_string(),
        Dest::I32(v) => v.to_string(),
        Dest::I64(v) => v.to_string(),
        Dest::Uint(v) => v.to_string(),
        Dest::U8(v) => v.to_string(),
        Dest::U16(v) => v.to_string(),
        Dest::U32(v) => v.to_string(),
        Dest::U64(v) | Dest::Uptr(v) => v.to_string(),
        Dest::F32(v) => format!("{:08x}", v.to_bits()),
        Dest::F64(v) => format!("{:016x}", v.to_bits()),
        Dest::C64((r, i)) => format!("{:08x},{:08x}", r.to_bits(), i.to_bits()),
        Dest::C128(c) => format!("{:016x},{:016x}", c.re.to_bits(), c.im.to_bits()),
        Dest::Bytes(b) => hex(b),
        Dest::Scanner(c) => hex(c.0.as_bytes()),
    }
}

fn scan_line(f: &[&str]) -> String {
    let (mode, input, format) = (f[1], unhex(f[2]), unhex(f[3]));
    let mut dests: Vec<Dest> = if f[4].is_empty() {
        Vec::new()
    } else {
        f[4].split(',').map(dest).collect()
    };
    let res = {
        let mut sa: Vec<ScanArg> = dests
            .iter_mut()
            .map(|d| match d {
                Dest::Bool(v) => ScanArg::Bool(v),
                Dest::Int(v) => ScanArg::Int(v),
                Dest::I8(v) => ScanArg::Int8(v),
                Dest::I16(v) => ScanArg::Int16(v),
                Dest::I32(v) => ScanArg::Int32(v),
                Dest::I64(v) => ScanArg::Int64(v),
                Dest::Uint(v) => ScanArg::Uint(v),
                Dest::U8(v) => ScanArg::Uint8(v),
                Dest::U16(v) => ScanArg::Uint16(v),
                Dest::U32(v) => ScanArg::Uint32(v),
                Dest::U64(v) => ScanArg::Uint64(v),
                Dest::Uptr(v) => ScanArg::Uintptr(v),
                Dest::F32(v) => ScanArg::Float32(v),
                Dest::F64(v) => ScanArg::Float64(v),
                Dest::C64(v) => ScanArg::Complex64(v),
                Dest::C128(v) => ScanArg::Complex128(v),
                Dest::Bytes(v) => ScanArg::Bytes(v),
                Dest::Scanner(v) => ScanArg::Scanner(v),
            })
            .collect();
        match mode {
            "f" => fmt::sscanf(&input, &format, &mut sa),
            "s" => fmt::sscan(&input, &mut sa),
            _ => fmt::sscanln(&input, &mut sa),
        }
    };
    let (n, es) = match res {
        Ok(n) => (n, "-".to_string()),
        Err(e) => (e.n, format!("e{}", hex(e.to_string().as_bytes()))),
    };
    let vals: Vec<String> = dests.iter().map(canon).collect();
    format!("{n}|{es}|{}", vals.join(","))
}

fn run(f: &[&str]) -> String {
    match f[0] {
        "P" => {
            let mut b = Vec::new();
            fmt::appendf(&mut b, unhex(f[1]), &args(&f[2..]));
            hex(&b)
        }
        "S" => {
            let mut b = Vec::new();
            fmt::append(&mut b, &args(&f[1..]));
            hex(&b)
        }
        "L" => {
            let mut b = Vec::new();
            fmt::appendln(&mut b, &args(&f[1..]));
            hex(&b)
        }
        "E" => {
            let err = fmt::errorf(unhex(f[1]), &args(&f[2..]));
            let mut res = format!(
                "{}:{}",
                hex(err.to_string().as_bytes()),
                err.sources().len()
            );
            for e in err.sources() {
                res.push(':');
                let t = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| e.to_string()))
                    .unwrap_or_else(|_| "PANIC".into());
                res.push_str(&hex(t.as_bytes()));
            }
            res
        }
        "Z" => scan_line(f),
        _ => panic!("bad request"),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Panicking String/Error methods are part of the test; keep stderr quiet.
    std::panic::set_hook(Box::new(|_| {}));
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line?;
        let fields: Vec<&str> = line.split('\t').collect();
        let r = std::panic::catch_unwind(|| run(&fields));
        match r {
            Ok(s) => writeln!(out, "{s}")?,
            Err(_) => writeln!(out, "RUSTPANIC")?,
        }
    }
    Ok(())
}
