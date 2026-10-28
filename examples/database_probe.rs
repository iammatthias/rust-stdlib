//! Line protocol used by `tools/database_check.py` for Go differential checks:
//! `C` Scan conversions, `V` driver value converters, and `BEGIN`...`END`
//! scripts of pool and transaction operations on the fake driver.
//! `tools/database_oracle.go` answers the same protocol with Go's package.
#[path = "common/fakedb.rs"]
mod fakedb;

use rust_stdlib::context::Context;
use rust_stdlib::database::sql::driver::{self, Arg, Decimal, Form, Value, ValueConverter};
use rust_stdlib::database::sql::{
    self, convert_assign, Error, Null, NullBool, NullByte, NullFloat64, NullInt16, NullInt32,
    NullInt64, NullString, NullTime, RawBytes, Scanner, TxOptions,
};
use rust_stdlib::strconv;
use rust_stdlib::time::{self, Time};
use rust_stdlib::uuid::UUID;
use std::io::{self, BufRead, Write};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

fn must<T, E: std::fmt::Debug>(r: Result<T, E>) -> T {
    r.unwrap_or_else(|e| panic!("{e:?}"))
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex");
    (0..s.len())
        .step_by(2)
        .map(|i| must(u8::from_str_radix(&s[i..i + 2], 16)))
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn fmt_float(f: f64, bits: i32) -> String {
    strconv::format_float(f, b'g', -1, bits)
}

fn parse_time(spec: &str) -> Time {
    if spec == "zero" {
        return Time::default();
    }
    let p: Vec<&str> = spec.split(':').collect();
    let sec: i64 = must(p[0].parse());
    let nsec: i64 = must(p[1].parse());
    let off: i32 = must(p[2].parse());
    time::unix(sec, nsec).in_location(&time::Location::fixed("X", off))
}

/// A decimal from `form:neg:coefhex:exp`.
fn parse_dec(spec: &str) -> Decimal {
    let p: Vec<&str> = spec.split(':').collect();
    let form = match p[0] {
        "0" => Form::Finite,
        "1" => Form::Infinite,
        "2" => Form::NaN,
        f => panic!("bad decimal form {f}"),
    };
    Decimal {
        form,
        negative: must(strconv::parse_bool(p[1])),
        coefficient: unhex(p[2]),
        exponent: must(p[3].parse()),
    }
}

fn show_dec(d: &Decimal) -> String {
    let form = match d.form {
        Form::Finite => 0,
        Form::Infinite => 1,
        Form::NaN => 2,
    };
    format!(
        "dec:{form}:{}:{}:{}",
        d.negative,
        hex(&d.coefficient),
        d.exponent
    )
}

fn parse_uuid(rest: &str) -> UUID {
    UUID(unhex(rest).try_into().expect("16-byte uuid"))
}

fn parse_src(tok: &str) -> Value {
    if tok == "nil" {
        return Value::Null;
    }
    let (kind, rest) = tok.split_once(':').unwrap_or((tok, ""));
    match kind {
        "i" => Value::Int64(must(rest.parse())),
        "f" => Value::Float64(must(strconv::parse_float(rest, 64))),
        "b" => Value::Bytes(unhex(rest)),
        "s" => Value::String(String::from_utf8(unhex(rest)).expect("utf-8 string source")),
        "B" => Value::Bool(must(strconv::parse_bool(rest))),
        "t" => Value::Time(parse_time(rest)),
        "d" => Value::Decimal(parse_dec(rest)),
        _ => panic!("bad value token {tok}"),
    }
}

fn show_value(v: &Value) -> String {
    match v {
        Value::Null => "nil".into(),
        Value::Int64(i) => format!("i64:{i}"),
        Value::Float64(f) => format!("f64:{}", fmt_float(*f, 64)),
        Value::Bool(b) => format!("bool:{b}"),
        Value::Bytes(b) => format!("bytes:{}", hex(b)),
        Value::String(s) => format!("str:{}", hex(s.as_bytes())),
        Value::Time(t) => format!("time:{}", t.format(time::RFC3339_NANO)),
        Value::Decimal(d) => show_dec(d),
    }
}

fn show_str(s: &str) -> String {
    format!("str:{}", hex(s.as_bytes()))
}

fn show_bytes(b: &[u8]) -> String {
    format!("bytes:{}", hex(b))
}

fn show_time(t: &Time) -> String {
    format!("time:{}", t.format(time::RFC3339_NANO))
}

fn show_null<T>(valid: bool, v: &T, show: impl Fn(&T) -> String) -> String {
    format!("valid={valid} v={}", show(v))
}

/// A destination with Go's initial sentinel and the shared text form.
struct Dest {
    scanner: Box<dyn DestObj>,
}

trait DestObj {
    fn scanner(&mut self) -> &mut dyn Scanner;
    fn show(&self) -> String;
}

struct D<T> {
    v: T,
    show: Box<dyn Fn(&T) -> String>,
}

impl<T: Scanner> DestObj for D<T> {
    fn scanner(&mut self) -> &mut dyn Scanner {
        &mut self.v
    }
    fn show(&self) -> String {
        (self.show)(&self.v)
    }
}

fn d<T: Scanner + 'static>(v: T, show: impl Fn(&T) -> String + 'static) -> Box<dyn DestObj> {
    Box::new(D {
        v,
        show: Box::new(show),
    })
}

fn sentinel_time() -> Time {
    time::unix(1000, 0).utc()
}

fn pointer_dest(rest: &str) -> Box<dyn DestObj> {
    fn ptr<T: Scanner + Default + 'static>(
        v: T,
        show: impl Fn(&T) -> String + 'static,
    ) -> Box<dyn DestObj> {
        d(Some(v), move |p: &Option<T>| match p {
            None => "nil".to_string(),
            Some(x) => format!("&{}", show(x)),
        })
    }
    match rest {
        "i64" => ptr(77i64, |v| format!("i:{v}")),
        "string" => ptr("init".to_string(), |v| show_str(v)),
        "bytes" => ptr(b"init".to_vec(), |v| show_bytes(v)),
        "time" => ptr(sentinel_time(), show_time),
        "bool" => ptr(true, |v| format!("bool:{v}")),
        "f64" => ptr(7.5f64, |v| format!("f64:{}", fmt_float(*v, 64))),
        "ns" => ptr(
            NullString {
                string: "init".into(),
                valid: true,
            },
            |n| show_null(n.valid, &n.string, |s| show_str(s)),
        ),
        _ => panic!("bad pointer dest {rest}"),
    }
}

fn null_dest(rest: &str) -> Box<dyn DestObj> {
    match rest {
        "i64" => d(
            Null {
                v: 77i64,
                valid: true,
            },
            |n| show_null(n.valid, &n.v, |v| format!("i:{v}")),
        ),
        "string" => d(
            Null {
                v: "init".to_string(),
                valid: true,
            },
            |n| show_null(n.valid, &n.v, |s| show_str(s)),
        ),
        "bytes" => d(
            Null {
                v: b"init".to_vec(),
                valid: true,
            },
            |n| show_null(n.valid, &n.v, |s| show_bytes(s)),
        ),
        "time" => d(
            Null {
                v: sentinel_time(),
                valid: true,
            },
            |n| show_null(n.valid, &n.v, show_time),
        ),
        "bool" => d(
            Null {
                v: true,
                valid: true,
            },
            |n| show_null(n.valid, &n.v, |v| format!("bool:{v}")),
        ),
        "f64" => d(
            Null {
                v: 7.5f64,
                valid: true,
            },
            |n| show_null(n.valid, &n.v, |v| format!("f64:{}", fmt_float(*v, 64))),
        ),
        "u8" => d(
            Null {
                v: 77u8,
                valid: true,
            },
            |n| show_null(n.valid, &n.v, |v| format!("u:{v}")),
        ),
        "any" => d(
            Null {
                v: Value::String("init".into()),
                valid: true,
            },
            |n| show_null(n.valid, &n.v, show_value),
        ),
        _ => panic!("bad Null dest {rest}"),
    }
}

fn new_dest(kind: &str) -> Dest {
    let scanner = if let Some(rest) = kind.strip_prefix("p:") {
        pointer_dest(rest)
    } else if let Some(rest) = kind.strip_prefix("N:") {
        null_dest(rest)
    } else {
        match kind {
            "string" => d("init".to_string(), |v| show_str(v)),
            "bytes" => d(b"init".to_vec(), |v| show_bytes(v)),
            "raw" => d(RawBytes(b"init".to_vec()), |v| format!("raw:{}", hex(&v.0))),
            "bool" => d(true, |v| format!("bool:{v}")),
            "any" => d(Value::String("init".into()), show_value),
            "time" => d(sentinel_time(), show_time),
            "dec" => d(
                Decimal {
                    form: Form::NaN,
                    negative: true,
                    coefficient: vec![9],
                    exponent: 9,
                },
                show_dec,
            ),
            "i8" => d(77i8, |v| format!("i:{v}")),
            "i16" => d(77i16, |v| format!("i:{v}")),
            "i32" => d(77i32, |v| format!("i:{v}")),
            "i64" => d(77i64, |v| format!("i:{v}")),
            "int" => d(77isize, |v| format!("i:{v}")),
            "u8" => d(77u8, |v| format!("u:{v}")),
            "u16" => d(77u16, |v| format!("u:{v}")),
            "u32" => d(77u32, |v| format!("u:{v}")),
            "u64" => d(77u64, |v| format!("u:{v}")),
            "uint" => d(77usize, |v| format!("u:{v}")),
            "f32" => d(7.5f32, |v| format!("f32:{}", fmt_float(f64::from(*v), 32))),
            "f64" => d(7.5f64, |v| format!("f64:{}", fmt_float(*v, 64))),
            "ns" => d(
                NullString {
                    string: "init".into(),
                    valid: true,
                },
                |n| show_null(n.valid, &n.string, |s| show_str(s)),
            ),
            "ni64" => d(
                NullInt64 {
                    int64: 77,
                    valid: true,
                },
                |n| show_null(n.valid, &n.int64, |v| format!("i:{v}")),
            ),
            "ni32" => d(
                NullInt32 {
                    int32: 77,
                    valid: true,
                },
                |n| show_null(n.valid, &n.int32, |v| format!("i:{v}")),
            ),
            "ni16" => d(
                NullInt16 {
                    int16: 77,
                    valid: true,
                },
                |n| show_null(n.valid, &n.int16, |v| format!("i:{v}")),
            ),
            "nbyte" => d(
                NullByte {
                    byte: 77,
                    valid: true,
                },
                |n| show_null(n.valid, &n.byte, |v| format!("u:{v}")),
            ),
            "nf64" => d(
                NullFloat64 {
                    float64: 7.5,
                    valid: true,
                },
                |n| {
                    show_null(n.valid, &n.float64, |v| {
                        format!("f64:{}", fmt_float(*v, 64))
                    })
                },
            ),
            "nbool" => d(
                NullBool {
                    bool: true,
                    valid: true,
                },
                |n| show_null(n.valid, &n.bool, |v| format!("bool:{v}")),
            ),
            "ntime" => d(
                NullTime {
                    time: sentinel_time(),
                    valid: true,
                },
                |n| show_null(n.valid, &n.time, show_time),
            ),
            _ => panic!("bad dest {kind}"),
        }
    };
    Dest { scanner }
}

fn new_dests(spec: &str) -> Vec<Dest> {
    if spec == "-" {
        return Vec::new();
    }
    spec.split(',').map(new_dest).collect()
}

fn shows(ds: &[Dest]) -> String {
    ds.iter()
        .map(|d| d.scanner.show())
        .collect::<Vec<_>>()
        .join(";")
}

fn scan_all(
    ds: &mut [Dest],
    f: impl FnOnce(&mut [&mut dyn Scanner]) -> Result<(), Error>,
) -> String {
    let result = {
        let mut refs: Vec<&mut dyn Scanner> = ds.iter_mut().map(|d| d.scanner.scanner()).collect();
        f(&mut refs)
    };
    match result {
        Ok(()) => format!("ok {}", shows(ds)),
        Err(e) => format!("err {e} | {}", shows(ds)),
    }
}

fn err_text(e: &Error) -> String {
    format!("err {e}")
}

fn convert_request(f: &[&str]) -> String {
    let src = parse_src(f[1]);
    let mut dest = new_dest(f[2]);
    let r = convert_assign(driver::ScanContext::default(), dest.scanner.scanner(), &src);
    match r {
        Ok(()) => format!("ok {}", dest.scanner.show()),
        Err(e) => format!("err {e} | {}", dest.scanner.show()),
    }
}

// --------------------------------------------------------------- converters

struct UserValuer {
    v: Value,
    err: Option<&'static str>,
}

impl driver::Valuer for UserValuer {
    fn value(&self) -> Result<Value, Error> {
        match self.err {
            Some(m) => Err(Error::new(m)),
            None => Ok(self.v.clone()),
        }
    }
}

fn unsupported(type_name: &str, kind: &str, repr: &str) -> Arg {
    Arg::Unsupported {
        type_name: type_name.into(),
        kind: kind.into(),
        repr: repr.into(),
    }
}

fn parse_arg(tok: &str) -> Arg {
    if tok == "nil" {
        return Arg::Nil;
    }
    let (kind, rest) = tok.split_once(':').unwrap_or((tok, ""));
    match kind {
        "bool" => Arg::Bool(must(strconv::parse_bool(rest))),
        "int" => Arg::Int(must(rest.parse())),
        "i8" => Arg::Int8(must(rest.parse())),
        "i16" => Arg::Int16(must(rest.parse())),
        "i32" => Arg::Int32(must(rest.parse())),
        "i64" => Arg::Int64(must(rest.parse())),
        "uint" => Arg::Uint(must(rest.parse())),
        "u8" => Arg::Uint8(must(rest.parse())),
        "u16" => Arg::Uint16(must(rest.parse())),
        "u32" => Arg::Uint32(must(rest.parse())),
        "u64" => Arg::Uint64(must(rest.parse())),
        "f32" => Arg::Float32(must(strconv::parse_float(rest, 32)) as f32),
        "f64" => Arg::Float64(must(strconv::parse_float(rest, 64))),
        "str" => Arg::String(String::from_utf8(unhex(rest)).expect("utf-8 string")),
        "bytes" => Arg::Bytes(unhex(rest)),
        "time" => Arg::Time(parse_time(rest)),
        "ptrnil" => Arg::Pointer(None),
        "ptr" => Arg::Pointer(Some(Box::new(Arg::Int(must(rest.parse()))))),
        "slice" => {
            if rest == "int" {
                Arg::UnsupportedSlice {
                    type_name: "[]int".into(),
                    elem_kind: "int".into(),
                    repr: "[1 2]".into(),
                }
            } else {
                Arg::UnsupportedSlice {
                    type_name: "[]string".into(),
                    elem_kind: "string".into(),
                    repr: "[a]".into(),
                }
            }
        }
        "struct" => unsupported("struct { A int }", "struct", "{1}"),
        "map" => unsupported("map[string]int", "map", "map[]"),
        "func" => unsupported("func()", "func", "0x0"),
        "complex" => unsupported("complex128", "complex128", "(1+2i)"),
        "uintptr" => unsupported("uintptr", "uintptr", "5"),
        "array" => unsupported("[2]int", "array", "[1 2]"),
        "ns" => {
            if rest == "null" {
                Arg::from(NullString::default())
            } else {
                Arg::from(NullString {
                    string: String::from_utf8(unhex(rest)).expect("utf-8"),
                    valid: true,
                })
            }
        }
        "ni" => {
            if rest == "null" {
                Arg::from(NullInt64::default())
            } else {
                Arg::from(NullInt64 {
                    int64: must(rest.parse()),
                    valid: true,
                })
            }
        }
        "valuererr" => Arg::valuer(UserValuer {
            v: Value::Null,
            err: Some("boom"),
        }),
        "valuernil" => Arg::valuer(UserValuer {
            v: Value::Null,
            err: None,
        }),
        "valuerstr" => Arg::valuer(UserValuer {
            v: Value::String("v".into()),
            err: None,
        }),
        "dec" => Arg::Decimal(parse_dec(rest)),
        "ptrdec" => Arg::Pointer(Some(Box::new(Arg::Decimal(parse_dec(rest))))),
        "uuid" => Arg::Uuid(parse_uuid(rest)),
        "ptruuid" => Arg::Pointer(Some(Box::new(Arg::Uuid(parse_uuid(rest))))),
        _ => panic!("bad arg token {tok}"),
    }
}

fn converter_by_name(name: &str) -> Box<dyn ValueConverter> {
    if let Some(rest) = name.strip_prefix("null:") {
        return Box::new(driver::Null {
            converter: converter_by_name(rest),
        });
    }
    if let Some(rest) = name.strip_prefix("notnull:") {
        return Box::new(driver::NotNull {
            converter: converter_by_name(rest),
        });
    }
    match name {
        "default" => Box::new(driver::DEFAULT_PARAMETER_CONVERTER),
        "bool" => Box::new(driver::BOOL),
        "int32" => Box::new(driver::INT32),
        "string" => Box::new(driver::STRING),
        _ => panic!("bad converter {name}"),
    }
}

fn converter_request(f: &[&str]) -> String {
    let arg = parse_arg(f[2]);
    if f[1] == "isvalue" {
        return format!("bool:{}", driver::is_value(&arg));
    }
    match converter_by_name(f[1]).convert_value(&arg) {
        Ok(v) => format!("ok {}", show_value(&v)),
        Err(e) => err_text(&e),
    }
}

// ------------------------------------------------------------------ scripts

enum Cx {
    Bg,
    Ctx(Context),
}

impl Cx {
    fn ctx(&self) -> Context {
        match self {
            Cx::Bg => Context::background(),
            Cx::Ctx(c) => c.clone(),
        }
    }
}

#[derive(Clone, Copy)]
enum Target {
    Db,
    Conn(usize),
    Tx(usize),
}

fn slot(tok: &str, prefix: char) -> usize {
    let b = tok.as_bytes();
    assert!(
        b.len() == 2 && b[0] == prefix as u8 && (b'0'..=b'3').contains(&b[1]),
        "bad slot {tok}"
    );
    usize::from(b[1] - b'0')
}

fn parse_args(toks: &[&str]) -> Vec<Arg> {
    toks.iter()
        .map(|t| {
            let (kind, rest) = t.split_once(':').unwrap_or((t, ""));
            match kind {
                "n" if *t == "n" => Arg::Nil,
                "i" => Arg::Int64(must(rest.parse())),
                "i32" => Arg::Int32(must(rest.parse())),
                "f" => Arg::Float64(must(strconv::parse_float(rest, 64))),
                "s" => Arg::String(rest.to_string()),
                "b" => Arg::Bytes(unhex(rest)),
                "B" => Arg::Bool(must(strconv::parse_bool(rest))),
                "t" => Arg::Time(time::unix(must(rest.parse()), 0).utc()),
                "ns" => {
                    if rest == "null" {
                        Arg::from(NullString::default())
                    } else {
                        Arg::from(NullString {
                            string: rest.to_string(),
                            valid: true,
                        })
                    }
                }
                "named" => {
                    let (name, val) = rest.split_once('=').unwrap_or((rest, ""));
                    let inner = parse_args(&[val]).remove(0);
                    Arg::from(sql::named(name, inner))
                }
                _ => panic!("bad arg {t}"),
            }
        })
        .collect()
}

fn result_text(r: Result<Box<dyn sql::Result>, Error>) -> String {
    match r {
        Err(e) => err_text(&e),
        Ok(res) => {
            let a = match res.last_insert_id() {
                Ok(v) => v.to_string(),
                Err(e) => format!("err:{e}"),
            };
            let b = match res.rows_affected() {
                Ok(v) => v.to_string(),
                Err(e) => format!("err:{e}"),
            };
            format!("ok li={a} ra={b}")
        }
    }
}

#[derive(Default)]
struct Script {
    which: bool,
    db: Option<sql::DB>,
    conns: [Option<sql::Conn>; 4],
    txs: [Option<sql::Tx>; 4],
    tx_owner: [String; 4],
    stmts: [Option<sql::Stmt>; 4],
    stmt_bound: [bool; 4],
    stmt_owner: [String; 4],
    rows: [Option<sql::Rows>; 4],
    /// The row `next_row` last yielded, and the error it last returned: Go's
    /// separate Scan and Err calls are replayed from these.
    cur: [Option<sql::CurrentRow>; 4],
    advanced: [bool; 4],
    next_err: [Option<Error>; 4],
    row_owner: [String; 4],
    open_base: i64,
    close_base: i64,
}

impl Script {
    fn pool_exhausted(&self) -> bool {
        let st = self.db.as_ref().expect("db").stats();
        st.max_open_connections > 0
            && st.open_connections >= st.max_open_connections
            && st.idle == 0
    }

    fn ctx_for(&self, cancelled: bool, needs_pool: bool) -> Cx {
        if cancelled {
            let (c, cancel) = Context::background().with_cancel();
            cancel();
            return Cx::Ctx(c);
        }
        if needs_pool && self.db.is_some() && self.pool_exhausted() {
            let (c, _cancel) = Context::background().with_timeout(POOL_WAIT.into());
            return Cx::Ctx(c);
        }
        Cx::Bg
    }

    fn target(&self, tok: &str) -> Option<(Target, bool)> {
        match tok.as_bytes()[0] {
            b'd' => Some((Target::Db, true)),
            b'c' => {
                let i = slot(tok, 'c');
                self.conns[i].as_ref().map(|_| (Target::Conn(i), false))
            }
            b't' => {
                let i = slot(tok, 't');
                self.txs[i].as_ref().map(|_| (Target::Tx(i), false))
            }
            _ => panic!("bad target {tok}"),
        }
    }

    fn close_owned_rows(&mut self, owner: &str) {
        for i in 0..4 {
            if self.row_owner[i] == owner {
                if let Some(r) = self.rows[i].as_mut() {
                    let _ = r.close();
                }
            }
        }
    }

    fn do_exec(&self, t: Target, cx: &Cx, q: &str, args: &[Arg]) -> String {
        let r = match (t, cx) {
            (Target::Db, Cx::Bg) => self.db.as_ref().unwrap().exec(q, args),
            (Target::Db, Cx::Ctx(c)) => self.db.as_ref().unwrap().exec_context(c, q, args),
            (Target::Conn(i), cx) => {
                self.conns[i]
                    .as_ref()
                    .unwrap()
                    .exec_context(&cx.ctx(), q, args)
            }
            (Target::Tx(i), Cx::Bg) => self.txs[i].as_ref().unwrap().exec(q, args),
            (Target::Tx(i), Cx::Ctx(c)) => self.txs[i].as_ref().unwrap().exec_context(c, q, args),
        };
        result_text(r)
    }

    fn do_query(&self, t: Target, cx: &Cx, q: &str, args: &[Arg]) -> Result<sql::Rows, Error> {
        match (t, cx) {
            (Target::Db, Cx::Bg) => self.db.as_ref().unwrap().query(q, args),
            (Target::Db, Cx::Ctx(c)) => self.db.as_ref().unwrap().query_context(c, q, args),
            (Target::Conn(i), cx) => {
                self.conns[i]
                    .as_ref()
                    .unwrap()
                    .query_context(&cx.ctx(), q, args)
            }
            (Target::Tx(i), Cx::Bg) => self.txs[i].as_ref().unwrap().query(q, args),
            (Target::Tx(i), Cx::Ctx(c)) => self.txs[i].as_ref().unwrap().query_context(c, q, args),
        }
    }

    fn do_query_row(&self, t: Target, cx: &Cx, q: &str, args: &[Arg]) -> sql::Row {
        match (t, cx) {
            (Target::Db, Cx::Bg) => self.db.as_ref().unwrap().query_row(q, args),
            (Target::Db, Cx::Ctx(c)) => self.db.as_ref().unwrap().query_row_context(c, q, args),
            (Target::Conn(i), cx) => {
                self.conns[i]
                    .as_ref()
                    .unwrap()
                    .query_row_context(&cx.ctx(), q, args)
            }
            (Target::Tx(i), Cx::Bg) => self.txs[i].as_ref().unwrap().query_row(q, args),
            (Target::Tx(i), Cx::Ctx(c)) => {
                self.txs[i].as_ref().unwrap().query_row_context(c, q, args)
            }
        }
    }

    fn do_prepare(&self, t: Target, cx: &Cx, q: &str) -> Result<sql::Stmt, Error> {
        match (t, cx) {
            (Target::Db, Cx::Bg) => self.db.as_ref().unwrap().prepare(q),
            (Target::Db, Cx::Ctx(c)) => self.db.as_ref().unwrap().prepare_context(c, q),
            (Target::Conn(i), cx) => self.conns[i]
                .as_ref()
                .unwrap()
                .prepare_context(&cx.ctx(), q),
            (Target::Tx(i), Cx::Bg) => self.txs[i].as_ref().unwrap().prepare(q),
            (Target::Tx(i), Cx::Ctx(c)) => self.txs[i].as_ref().unwrap().prepare_context(c, q),
        }
    }

    fn run(&mut self, line: &str) -> String {
        let mut f: Vec<&str> = line.split_whitespace().collect();
        let mut cancelled = false;
        if f[0] == "@cancelled" {
            cancelled = true;
            f.remove(0);
        }
        let cmd = f[0];
        if self.db.is_none() && cmd != "open" {
            return "skip nodb".into();
        }
        match cmd {
            "open" => {
                self.which = f[1] == "testctx";
                match sql::DB::open(f[1], f[2]) {
                    Err(e) => err_text(&e),
                    Ok(db) => {
                        self.db = Some(db);
                        let drv = fakedb::fdriver(self.which);
                        self.open_base = drv.open_count();
                        self.close_base = drv.close_count();
                        "ok".into()
                    }
                }
            }
            "maxopen" => {
                self.db
                    .as_ref()
                    .unwrap()
                    .set_max_open_conns(must(f[1].parse()));
                "ok".into()
            }
            "maxidle" => {
                self.db
                    .as_ref()
                    .unwrap()
                    .set_max_idle_conns(must(f[1].parse()));
                "ok".into()
            }
            "stats" => {
                let st = self.db.as_ref().unwrap().stats();
                format!(
                    "ok max={} open={} inuse={} idle={} wait={} idleclosed={} idletimeclosed={} lifetimeclosed={}",
                    st.max_open_connections,
                    st.open_connections,
                    st.in_use,
                    st.idle,
                    st.wait_count,
                    st.max_idle_closed,
                    st.max_idle_time_closed,
                    st.max_lifetime_closed
                )
            }
            "fake" => {
                let drv = fakedb::fdriver(self.which);
                format!(
                    "ok open={} close={}",
                    drv.open_count() - self.open_base,
                    drv.close_count() - self.close_base
                )
            }
            "dbclose" => match self.db.as_ref().unwrap().close() {
                Ok(()) => "ok".into(),
                Err(e) => err_text(&e),
            },
            "exec" => {
                let Some((t, needs)) = self.target(f[1]) else {
                    return "skip".into();
                };
                let cx = self.ctx_for(cancelled, needs);
                self.do_exec(t, &cx, f[2], &parse_args(&f[3..]))
            }
            "query" => {
                let Some((t, needs)) = self.target(f[1]) else {
                    return "skip".into();
                };
                let i = slot(f[2], 'r');
                if self.rows[i].is_some() {
                    return "skip busy".into();
                }
                let cx = self.ctx_for(cancelled, needs);
                match self.do_query(t, &cx, f[3], &parse_args(&f[4..])) {
                    Err(e) => err_text(&e),
                    Ok(r) => {
                        self.rows[i] = Some(r);
                        self.cur[i] = None;
                        self.advanced[i] = false;
                        self.next_err[i] = None;
                        self.row_owner[i] = f[1].to_string();
                        "ok".into()
                    }
                }
            }
            "queryrow" => {
                let Some((t, needs)) = self.target(f[1]) else {
                    return "skip".into();
                };
                let cx = self.ctx_for(cancelled, needs);
                let mut ds = new_dests(f[2]);
                let mut row = self.do_query_row(t, &cx, f[3], &parse_args(&f[4..]));
                scan_all(&mut ds, |refs| row.scan(refs))
            }
            "next" | "scan" | "cols" | "coltypes" | "nextset" | "rerr" | "rclose" => {
                self.rows_op(cmd, &f)
            }
            "begin" => self.begin(&f, cancelled),
            "commit" | "rollback" => {
                let i = slot(f[1], 't');
                let Some(tx) = self.txs[i].as_ref() else {
                    return "skip".into();
                };
                let r = if cmd == "commit" {
                    tx.commit()
                } else {
                    tx.rollback()
                };
                match r {
                    Ok(()) => "ok".into(),
                    Err(e) => err_text(&e),
                }
            }
            "prepare" => {
                let Some((t, needs)) = self.target(f[1]) else {
                    return "skip".into();
                };
                let i = slot(f[2], 's');
                if self.stmts[i].is_some() {
                    return "skip busy".into();
                }
                let cx = self.ctx_for(cancelled, needs);
                match self.do_prepare(t, &cx, f[3]) {
                    Err(e) => err_text(&e),
                    Ok(st) => {
                        self.stmts[i] = Some(st);
                        self.stmt_bound[i] = !f[1].starts_with('d');
                        self.stmt_owner[i] = f[1].to_string();
                        "ok".into()
                    }
                }
            }
            "txstmt" => {
                let ti = slot(f[1], 't');
                let si = slot(f[2], 's');
                let j = slot(f[3], 's');
                if self.txs[ti].is_none() || self.stmts[si].is_none() || self.stmts[j].is_some() {
                    return "skip".into();
                }
                let st = self.txs[ti]
                    .as_ref()
                    .unwrap()
                    .stmt(self.stmts[si].as_ref().unwrap());
                self.stmts[j] = Some(st);
                self.stmt_bound[j] = true;
                self.stmt_owner[j] = f[1].to_string();
                "ok".into()
            }
            "stmtexec" | "stmtquery" | "stmtqueryrow" => self.stmt_op(cmd, &f, cancelled),
            "stmtclose" => {
                let i = slot(f[1], 's');
                let Some(st) = self.stmts[i].take() else {
                    return "skip".into();
                };
                match st.close() {
                    Ok(()) => "ok".into(),
                    Err(e) => err_text(&e),
                }
            }
            "conn" => {
                let i = slot(f[1], 'c');
                if self.conns[i].is_some() {
                    return "skip busy".into();
                }
                let cx = self.ctx_for(false, true);
                let conn = match self.db.as_ref().unwrap().conn(&cx.ctx()) {
                    Ok(c) => c,
                    Err(e) => return err_text(&e),
                };
                let r = conn.raw(|ci| {
                    fakedb::with_fake_conn(ci, |fc| fc.set_skip_dirty_session(true));
                    Ok(())
                });
                if let Err(e) = r {
                    return err_text(&e);
                }
                self.conns[i] = Some(conn);
                "ok".into()
            }
            "stickybad" => {
                let Some(c) = self.conns[slot(f[1], 'c')].as_ref() else {
                    return "skip".into();
                };
                let r = c.raw(|ci| {
                    fakedb::with_fake_conn(ci, |fc| fc.set_sticky_bad(true));
                    Ok(())
                });
                match r {
                    Ok(()) => "ok".into(),
                    Err(e) => err_text(&e),
                }
            }
            "connclose" => {
                let i = slot(f[1], 'c');
                if self.conns[i].is_none() {
                    return "skip".into();
                }
                self.close_owned_rows(f[1]);
                for j in 0..4 {
                    if self.tx_owner[j] == f[1] {
                        if let Some(t) = self.txs[j].as_ref() {
                            let _ = t.rollback();
                        }
                    }
                }
                let c = self.conns[i].take().unwrap();
                match c.close() {
                    Ok(()) => "ok".into(),
                    Err(e) => err_text(&e),
                }
            }
            "ping" => {
                let r = if f[1] == "d" {
                    let cx = self.ctx_for(cancelled, true);
                    match cx {
                        Cx::Bg => self.db.as_ref().unwrap().ping(),
                        Cx::Ctx(c) => self.db.as_ref().unwrap().ping_context(&c),
                    }
                } else {
                    let Some(c) = self.conns[slot(f[1], 'c')].as_ref() else {
                        return "skip".into();
                    };
                    let cx = self.ctx_for(cancelled, false);
                    c.ping_context(&cx.ctx())
                };
                match r {
                    Ok(()) => "ok".into(),
                    Err(e) => err_text(&e),
                }
            }
            _ => panic!("bad command {line}"),
        }
    }

    fn begin(&mut self, f: &[&str], cancelled: bool) -> String {
        let i = slot(f[2], 't');
        if self.txs[i].is_some() {
            return "skip busy".into();
        }
        let mut opts: Option<TxOptions> = None;
        for o in &f[3..] {
            let opts = opts.get_or_insert_with(TxOptions::default);
            if *o == "ro" {
                opts.read_only = true;
            } else if let Some(v) = o.strip_prefix("iso=") {
                opts.isolation = sql::IsolationLevel(must(v.parse()));
            }
        }
        let r = if f[1] == "d" {
            let cx = self.ctx_for(cancelled, true);
            match cx {
                Cx::Bg => match opts {
                    None => self.db.as_ref().unwrap().begin(),
                    Some(_) => self
                        .db
                        .as_ref()
                        .unwrap()
                        .begin_tx(&Context::background(), opts),
                },
                Cx::Ctx(c) => self.db.as_ref().unwrap().begin_tx(&c, opts),
            }
        } else {
            let Some(c) = self.conns[slot(f[1], 'c')].as_ref() else {
                return "skip".into();
            };
            let cx = self.ctx_for(cancelled, false);
            c.begin_tx(&cx.ctx(), opts)
        };
        match r {
            Ok(tx) => {
                self.txs[i] = Some(tx);
                self.tx_owner[i] = f[1].to_string();
                "ok".into()
            }
            Err(e) => err_text(&e),
        }
    }

    fn rows_op(&mut self, cmd: &str, f: &[&str]) -> String {
        let i = slot(f[1], 'r');
        let Some(r) = self.rows[i].as_mut() else {
            return "skip".into();
        };
        match cmd {
            "next" => {
                self.advanced[i] = true;
                self.next_err[i] = None;
                match r.next_row() {
                    Ok(Some(row)) => {
                        self.cur[i] = Some(row);
                        "ok true".into()
                    }
                    Ok(None) => "ok false".into(),
                    Err(e) => {
                        self.next_err[i] = Some(e);
                        "ok false".into()
                    }
                }
            }
            "scan" => {
                let mut ds = new_dests(f[2]);
                match self.cur[i].as_mut() {
                    // The last row stays bound to the cursor, so scanning it
                    // after the rows moved on reports Go's state error.
                    Some(row) => scan_all(&mut ds, |refs| row.scan(refs)),
                    // Go scans before any Next; a Rust row exists only after
                    // next_row, so replay Go's two possible answers.
                    None => {
                        let n = ds.len();
                        let advanced = self.advanced[i];
                        scan_all(&mut ds, |refs| {
                            let cols = r.columns()?;
                            if !advanced {
                                return Err(Error::new("sql: Scan called without calling Next"));
                            }
                            if cols.len() != n {
                                return Err(Error::new(format!(
                                    "sql: expected {} destination arguments in Scan, not {n}",
                                    cols.len()
                                )));
                            }
                            // Next found no row yet kept the rows open for a
                            // later result set: Go scans the still-NULL buffer.
                            for (k, d) in refs.iter_mut().enumerate() {
                                if let Err(e) = d.scan(&Value::Null) {
                                    return Err(Error::new(format!(
                                        "sql: Scan error on column index {k}, name {}: {e}",
                                        strconv::quote(&cols[k])
                                    )));
                                }
                            }
                            Ok(())
                        })
                    }
                }
            }
            "cols" => match r.columns() {
                Ok(c) => format!("ok {}", c.join(",")),
                Err(e) => err_text(&e),
            },
            "coltypes" => match r.column_types() {
                Err(e) => err_text(&e),
                Ok(cts) => {
                    let parts: Vec<String> = cts
                        .iter()
                        .map(|ct| {
                            let nullable = ct.nullable();
                            let length = ct.length();
                            let ps = ct.decimal_size();
                            format!(
                                "{}:{}:{}:{}/{}:{}/{}:{},{}/{}",
                                ct.name(),
                                ct.database_type_name(),
                                ct.scan_type(),
                                nullable.unwrap_or(false),
                                nullable.is_some(),
                                length.unwrap_or(0),
                                length.is_some(),
                                ps.map_or(0, |p| p.0),
                                ps.map_or(0, |p| p.1),
                                ps.is_some()
                            )
                        })
                        .collect();
                    format!("ok {}", parts.join(";"))
                }
            },
            "nextset" => {
                self.cur[i] = None;
                self.advanced[i] = false;
                self.next_err[i] = None;
                format!("ok {}", r.next_result_set())
            }
            "rerr" => match &self.next_err[i] {
                Some(e) => err_text(e),
                // Closed rows have nothing left to advance, so next_row only
                // reports why they ended.
                None if r.columns().is_err() => match r.next_row() {
                    Err(e) => err_text(&e),
                    Ok(_) => "ok".into(),
                },
                None => "ok".into(),
            },
            "rclose" => {
                let res = r.close();
                self.rows[i] = None;
                self.cur[i] = None;
                match res {
                    Ok(()) => "ok".into(),
                    Err(e) => err_text(&e),
                }
            }
            _ => unreachable!(),
        }
    }

    fn stmt_op(&mut self, cmd: &str, f: &[&str], cancelled: bool) -> String {
        let i = slot(f[1], 's');
        if self.stmts[i].is_none() {
            return "skip".into();
        }
        let cx = self.ctx_for(cancelled, !self.stmt_bound[i]);
        let st = self.stmts[i].as_ref().unwrap();
        match cmd {
            "stmtexec" => {
                let args = parse_args(&f[2..]);
                result_text(match &cx {
                    Cx::Bg => st.exec(&args),
                    Cx::Ctx(c) => st.exec_context(c, &args),
                })
            }
            "stmtquery" => {
                let j = slot(f[2], 'r');
                if self.rows[j].is_some() {
                    return "skip busy".into();
                }
                let args = parse_args(&f[3..]);
                let r = match &cx {
                    Cx::Bg => st.query(&args),
                    Cx::Ctx(c) => st.query_context(c, &args),
                };
                match r {
                    Err(e) => err_text(&e),
                    Ok(rows) => {
                        self.rows[j] = Some(rows);
                        self.cur[j] = None;
                        self.advanced[j] = false;
                        self.next_err[j] = None;
                        self.row_owner[j] = self.stmt_owner[i].clone();
                        "ok".into()
                    }
                }
            }
            _ => {
                let mut ds = new_dests(f[2]);
                let args = parse_args(&f[3..]);
                let mut row = match &cx {
                    Cx::Bg => st.query_row(&args),
                    Cx::Ctx(c) => st.query_row_context(c, &args),
                };
                scan_all(&mut ds, |refs| row.scan(refs))
            }
        }
    }

    fn finish(&mut self) {
        self.rows = Default::default();
        self.stmts = Default::default();
        self.txs = Default::default();
        self.conns = Default::default();
        if let Some(db) = self.db.take() {
            let _ = db.close();
        }
    }
}

/// Bounds one scripted operation. Go's closemu waits for open rows, so a
/// failed operation on a Conn that still has rows can wait forever; the Go
/// oracle then hangs too, and both report "hang" and drop the script.
const OP_TIMEOUT: Duration = Duration::from_millis(250);

/// How long an operation that needs a connection from an exhausted pool
/// waits before giving up.
const POOL_WAIT: Duration = Duration::from_millis(10);

fn run_bounded(script: &Arc<Mutex<Script>>, line: &str) -> Option<String> {
    let (tx, rx) = mpsc::channel();
    let script = script.clone();
    let line = line.to_string();
    std::thread::spawn(move || {
        let mut s = script.lock().unwrap_or_else(|e| e.into_inner());
        let reply = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| s.run(&line)))
            .unwrap_or_else(|_| "panic".to_string());
        let _ = tx.send(reply);
    });
    rx.recv_timeout(OP_TIMEOUT).ok()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    fakedb::register_drivers();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    let mut cur: Option<Arc<Mutex<Script>>> = None;
    let mut hung = false;
    let mut n = 0;
    for line in stdin.lock().lines() {
        let line = line?;
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        match f[0] {
            "C" => writeln!(out, "{}", convert_request(&f))?,
            "V" => writeln!(out, "{}", converter_request(&f))?,
            "BEGIN" => {
                cur = Some(Arc::new(Mutex::new(Script::default())));
                hung = false;
                n = 0;
            }
            "END" => {
                if let Some(s) = cur.take() {
                    if !hung {
                        s.lock().unwrap_or_else(|e| e.into_inner()).finish();
                    }
                }
                writeln!(out, "END")?;
            }
            _ if hung => {}
            _ => {
                n += 1;
                match run_bounded(cur.as_ref().expect("script started"), line) {
                    Some(reply) => writeln!(out, "{n} {reply}")?,
                    None => {
                        writeln!(out, "{n} hang")?;
                        hung = true;
                    }
                }
                out.flush()?;
            }
        }
    }
    Ok(())
}
