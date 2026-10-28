//! The Rust side of the encoding/gob differential (see tools/gob_oracle.go,
//! tools/gob_check.py): one request per line on stdin, one answer per line.
//!
//!   ENC (key literal)...     encode the values with one Encoder: OK hex | ERR msg hex
//!   DEC hex key[=init]...    decode the stream into the types: printed values | ERR msg
#![allow(non_snake_case, dead_code, non_camel_case_types)]
use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

use rust_stdlib::encoding::gob;
use rust_stdlib::reflect::{self, Kind, Type, Value};
use rust_stdlib::strconv::Complex;
use rust_stdlib_derive::{reflect_methods, Reflect};

/// GobEncoder with a value receiver.
#[derive(Reflect)]
#[reflect(pkg = "main")]
pub struct GE {
    pub A: isize,
    pub B: Vec<u8>,
}

#[reflect_methods]
impl GE {
    pub fn GobEncode(&self) -> (Vec<u8>, Result<(), String>) {
        if self.A < 0 {
            return (Vec::new(), Err("negative A".into()));
        }
        let mut out = format!("{}|", self.A).into_bytes();
        out.extend_from_slice(&self.B);
        (out, Ok(()))
    }
    pub fn GobDecode(&mut self, b: &[u8]) -> Result<(), String> {
        let Some(i) = b.iter().position(|&c| c == b'|') else {
            return Err("bad GE".into());
        };
        let n = std::str::from_utf8(&b[..i])
            .ok()
            .and_then(|s| s.parse::<isize>().ok());
        let Some(n) = n else {
            return Err("bad GE number".into());
        };
        self.A = n;
        self.B = b[i + 1..].to_vec();
        Ok(())
    }
}

/// BinaryMarshaler.
#[derive(Reflect)]
#[reflect(pkg = "main")]
pub struct BM {
    pub N: u16,
    pub S: Vec<u8>,
}

#[reflect_methods]
impl BM {
    pub fn MarshalBinary(&self) -> (Vec<u8>, Result<(), String>) {
        let mut out = vec![(self.N >> 8) as u8, self.N as u8];
        out.extend_from_slice(&self.S);
        (out, Ok(()))
    }
    pub fn UnmarshalBinary(&mut self, d: &[u8]) -> Result<(), String> {
        if d.len() < 2 {
            return Err("short BM".into());
        }
        self.N = (d[0] as u16) << 8 | d[1] as u16;
        self.S = d[2..].to_vec();
        Ok(())
    }
}

/// GobEncoder with a pointer receiver.
#[derive(Reflect)]
#[reflect(pkg = "main")]
pub struct GP {
    pub A: isize,
    pub B: Vec<u8>,
}

#[reflect_methods]
impl GP {
    pub fn GobEncode(&mut self) -> (Vec<u8>, Result<(), String>) {
        if self.A < 0 {
            return (Vec::new(), Err("negative A".into()));
        }
        let mut out = format!("{}|", self.A).into_bytes();
        out.extend_from_slice(&self.B);
        (out, Ok(()))
    }
    pub fn GobDecode(&mut self, b: &[u8]) -> Result<(), String> {
        let Some(i) = b.iter().position(|&c| c == b'|') else {
            return Err("bad GP".into());
        };
        let n = std::str::from_utf8(&b[..i])
            .ok()
            .and_then(|s| s.parse::<isize>().ok());
        let Some(n) = n else {
            return Err("bad GP number".into());
        };
        self.A = n;
        self.B = b[i + 1..].to_vec();
        Ok(())
    }
}

include!("../gob_types_gen.rs");

struct Env {
    table: HashMap<&'static str, Type>,
    key_of: HashMap<Type, &'static str>,
}

struct Scan {
    s: Vec<u8>,
    i: usize,
}

impl Scan {
    fn new(s: &str) -> Scan {
        Scan {
            s: s.as_bytes().to_vec(),
            i: 0,
        }
    }
    fn peek(&self) -> u8 {
        self.s.get(self.i).copied().unwrap_or(0)
    }
    fn eat(&mut self, c: u8) -> bool {
        if self.peek() == c {
            self.i += 1;
            true
        } else {
            false
        }
    }
    fn must(&mut self, c: u8) {
        assert!(
            self.eat(c),
            "literal: expected {:?} at {}",
            c as char,
            self.i
        );
    }
    fn atom(&mut self) -> String {
        let j = self.i;
        while self.i < self.s.len() && !b",]};=:)".contains(&self.s[self.i]) {
            self.i += 1;
        }
        String::from_utf8_lossy(&self.s[j..self.i]).into_owned()
    }
}

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("bad hex"))
        .collect()
}

fn hx(b: &[u8]) -> String {
    if b.is_empty() {
        return "-".into();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn fill(env: &Env, p: &mut Scan, v: &Value) {
    let t = v.type_();
    match t.kind() {
        Kind::Bool => v.set_bool(p.atom() == "t"),
        Kind::Int | Kind::Int8 | Kind::Int16 | Kind::Int32 | Kind::Int64 => {
            v.set_int(p.atom().parse().expect("int"))
        }
        Kind::Uint | Kind::Uint8 | Kind::Uint16 | Kind::Uint32 | Kind::Uint64 => {
            v.set_uint(p.atom().parse().expect("uint"))
        }
        Kind::Float32 => {
            let n: u32 = p.atom().parse().expect("f32 bits");
            v.set_float(f32::from_bits(n) as f64)
        }
        Kind::Float64 => {
            let n: u64 = p.atom().parse().expect("f64 bits");
            v.set_float(f64::from_bits(n))
        }
        Kind::Complex128 => {
            let re: u64 = p.atom().parse().expect("bits");
            p.must(b':');
            let im: u64 = p.atom().parse().expect("bits");
            v.set_complex(Complex {
                re: f64::from_bits(re),
                im: f64::from_bits(im),
            })
        }
        Kind::String => v.set_string(unhex(&p.atom())),
        Kind::Slice => {
            if t.elem().kind() == Kind::Uint8 {
                let a = p.atom();
                if a != "n" {
                    v.set_bytes(&unhex(&a));
                }
                return;
            }
            if p.peek() == b'n' {
                p.atom();
                return;
            }
            p.must(b'[');
            let mut items = Vec::new();
            while !p.eat(b']') {
                let e = reflect::new(&t.elem()).elem();
                fill(env, p, &e);
                items.push(e);
                p.eat(b',');
            }
            let s = reflect::make_slice(&t, items.len() as isize, items.len() as isize);
            for (i, e) in items.iter().enumerate() {
                s.index(i).set(e);
            }
            v.set(&s);
        }
        Kind::Array => {
            p.must(b'[');
            for i in 0..t.len() {
                fill(env, p, &v.index(i));
                p.eat(b',');
            }
            p.must(b']');
        }
        Kind::Map => {
            if p.peek() == b'n' {
                p.atom();
                return;
            }
            p.must(b'm');
            p.must(b'[');
            let m = reflect::make_map(&t);
            while !p.eat(b']') {
                let k = reflect::new(&t.key()).elem();
                fill(env, p, &k);
                p.must(b'=');
                let e = reflect::new(&t.elem()).elem();
                fill(env, p, &e);
                m.set_map_index(&k, &e);
                p.eat(b';');
            }
            v.set(&m);
        }
        Kind::Pointer => {
            if p.peek() == b'n' {
                p.atom();
                return;
            }
            p.must(b'&');
            let n = reflect::new(&t.elem());
            fill(env, p, &n.elem());
            v.set(&n);
        }
        Kind::Interface => {
            if p.peek() == b'n' {
                p.atom();
                return;
            }
            p.must(b'@');
            let j = p.s[p.i..].iter().position(|&c| c == b':').expect("colon");
            let key = String::from_utf8_lossy(&p.s[p.i..p.i + j]).into_owned();
            p.i += j;
            p.must(b':');
            let ct = env
                .table
                .get(key.as_str())
                .unwrap_or_else(|| panic!("unknown interface key {key}"));
            let c = reflect::new(ct).elem();
            fill(env, p, &c);
            v.set(&c);
        }
        Kind::Struct => {
            p.must(b'{');
            for i in 0..t.num_field() {
                if t.field(i).is_exported() {
                    fill(env, p, &v.field(i));
                } else {
                    p.must(b'_');
                }
                p.eat(b',');
            }
            p.must(b'}');
        }
        k => panic!("cannot fill {k}"),
    }
}

fn pv(env: &Env, v: &Value) -> String {
    let t = v.type_();
    match t.kind() {
        Kind::Bool => (if v.bool() { "t" } else { "f" }).into(),
        Kind::Int | Kind::Int8 | Kind::Int16 | Kind::Int32 | Kind::Int64 => v.int().to_string(),
        Kind::Uint | Kind::Uint8 | Kind::Uint16 | Kind::Uint32 | Kind::Uint64 => {
            v.uint().to_string()
        }
        Kind::Float32 => (v.float() as f32).to_bits().to_string(),
        Kind::Float64 => v.float().to_bits().to_string(),
        Kind::Complex128 => {
            let c = v.complex();
            format!("{}:{}", c.re.to_bits(), c.im.to_bits())
        }
        Kind::String => hx(&v.string_bytes()),
        Kind::Slice => {
            if t.elem().kind() == Kind::Uint8 {
                return hx(&v.bytes());
            }
            if v.is_nil() {
                return "n".into();
            }
            let parts: Vec<String> = (0..v.len()).map(|i| pv(env, &v.index(i))).collect();
            format!("[{}]", parts.join(","))
        }
        Kind::Array => {
            let parts: Vec<String> = (0..v.len()).map(|i| pv(env, &v.index(i))).collect();
            format!("[{}]", parts.join(","))
        }
        Kind::Map => {
            if v.is_nil() {
                return "n".into();
            }
            let mut items: Vec<String> = v
                .entries()
                .iter()
                .map(|(k, e)| format!("{}={}", pv(env, k), pv(env, e)))
                .collect();
            items.sort();
            format!("m[{}]", items.join(";"))
        }
        Kind::Pointer => {
            if v.is_nil() {
                "n".into()
            } else {
                format!("&{}", pv(env, &v.elem()))
            }
        }
        Kind::Interface => {
            if v.is_nil() {
                return "n".into();
            }
            let e = v.elem();
            let key = match env.key_of.get(&e.type_()) {
                Some(k) => k.to_string(),
                None => format!("?{}", e.type_()),
            };
            format!("@{}:{}", key, pv(env, &e))
        }
        Kind::Struct => {
            let parts: Vec<String> = (0..t.num_field())
                .map(|i| {
                    if t.field(i).is_exported() {
                        pv(env, &v.field(i))
                    } else {
                        "_".into()
                    }
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        k => format!("?{k}"),
    }
}

#[derive(Clone, Default)]
struct Shared(Arc<Mutex<Vec<u8>>>);

impl Write for Shared {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn encode(env: &Env, f: &[&str]) -> String {
    let buf = Shared::default();
    let enc = gob::Encoder::new(buf.clone());
    let mut i = 0;
    while i + 1 < f.len() {
        let Some(typ) = env.table.get(f[i]) else {
            return format!("unknown type {}", f[i]);
        };
        let v = reflect::new(typ).elem();
        fill(env, &mut Scan::new(f[i + 1]), &v);
        if let Err(e) = enc.encode_value(&v) {
            return format!("ERR {} {}", e, hx(&buf.0.lock().unwrap()));
        }
        i += 2;
    }
    format!("OK {}", hx(&buf.0.lock().unwrap()))
}

fn decode(env: &Env, f: &[&str]) -> String {
    let dec = gob::Decoder::new(std::io::Cursor::new(unhex(f[0])));
    let mut outs: Vec<String> = Vec::new();
    for spec in &f[1..] {
        let (key, init) = spec.split_once('=').unwrap_or((spec, ""));
        let Some(typ) = env.table.get(key) else {
            return format!("unknown type {key}");
        };
        let p = reflect::new(typ);
        if !init.is_empty() {
            fill(env, &mut Scan::new(init), &p.elem());
        }
        if let Err(e) = dec.decode_value(&p) {
            outs.push(format!("ERR {e}"));
            return outs.join(" ");
        }
        outs.push(pv(env, &p.elem()));
    }
    match dec.decode_discard() {
        Err(e) if rust_stdlib::io::is_eof(&e) => outs.push("EOF".into()),
        Err(e) => outs.push(format!("ERR {e}")),
        Ok(()) => outs.push("MORE".into()),
    }
    outs.join(" ")
}

fn handle(env: &Env, f: &[&str]) -> String {
    match catch_unwind(AssertUnwindSafe(|| match f[0] {
        "ENC" => encode(env, &f[1..]),
        "DEC" => decode(env, &f[1..]),
        other => format!("unknown request {other}"),
    })) {
        Ok(s) => s,
        Err(e) => {
            let msg = if let Some(v) = e.downcast_ref::<reflect::ValueError>() {
                v.error()
            } else if let Some(s) = e.downcast_ref::<String>() {
                s.clone()
            } else if let Some(s) = e.downcast_ref::<&str>() {
                s.to_string()
            } else {
                "?".into()
            };
            format!("PANIC {msg}")
        }
    }
}

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let (table, ifaces) = gen_types();
    let mut env = Env {
        table: HashMap::new(),
        key_of: HashMap::new(),
    };
    for (k, t) in &table {
        env.table.insert(k, t.clone());
    }
    for k in &ifaces {
        let t = env.table[k].clone();
        env.key_of.entry(t).or_insert(*k);
    }
    for k in &ifaces {
        gob::register_value(&reflect::zero(&env.table[k]));
    }
    let stdin = std::io::stdin();
    let mut out = std::io::BufWriter::new(std::io::stdout());
    for line in stdin.lock().lines() {
        let line = line.expect("read");
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.is_empty() {
            continue;
        }
        writeln!(out, "{}", handle(&env, &f)).expect("write");
        out.flush().expect("flush");
    }
}
