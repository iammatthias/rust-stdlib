//! Line protocol for `tools/reflect_typed_check.py`: `#[derive(Reflect)]` types
//! mirroring the Go types in `tools/reflect_typed_oracle.go` (embedding,
//! shadowing, promoted methods, interfaces, generics, recursion).
#![allow(non_snake_case, dead_code)]
use rust_stdlib::reflect::{self, Kind, Type, Value};
use rust_stdlib_derive::{reflect_methods, reflect_trait, Reflect};
use std::io::{self, BufRead, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};

#[derive(Reflect, Clone, Default)]
#[reflect(pkg = "main")]
pub struct Base {
    pub ID: i64,
    #[reflect("json:\"name\"")]
    pub Name: String,
    secret: bool,
}

#[reflect_methods]
impl Base {
    pub fn Describe(&self) -> String {
        format!("base {} {}", self.ID, self.Name)
    }
    pub fn Rename(&mut self, n: &str) {
        self.Name = n.to_string();
    }
}

#[derive(Reflect, Clone, Default)]
#[reflect(pkg = "main")]
pub struct Named {
    pub Name: String,
    pub Extra: i32,
}

#[reflect_methods]
impl Named {
    pub fn Label(&self) -> String {
        format!("named {}", self.Name)
    }
}

#[derive(Reflect, Clone, Default)]
#[reflect(pkg = "main")]
pub struct Mid {
    #[reflect(embed)]
    pub Base: Base,
    #[reflect(embed)]
    pub Named: Named,
    pub Level: i32,
}

#[derive(Reflect, Clone, Default)]
#[reflect(pkg = "main")]
pub struct Top {
    #[reflect(embed)]
    pub Mid: Option<Box<Mid>>,
    pub Level: i8,
    pub Tags: Vec<String>,
}

#[derive(Reflect, Clone, Default)]
#[reflect(pkg = "main")]
pub struct Point {
    #[reflect("json:\"x\" xml:\"px\"")]
    pub X: i32,
    pub Y: i32,
    name: String,
}

#[reflect_methods]
impl Point {
    pub fn Sum(&self) -> i32 {
        self.X + self.Y
    }
    pub fn Scale(&mut self, k: i32) {
        self.X *= k;
        self.Y *= k;
    }
    pub fn Greet(&self, who: &str, n: i64) -> String {
        format!("{} {} {}", self.name, who, n)
    }
}

#[derive(Reflect, Clone, Default)]
#[reflect(pkg = "main")]
pub struct Pair<A, B> {
    pub First: A,
    pub Second: B,
}

#[derive(Reflect, Clone, Copy, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
pub enum Color {
    #[default]
    Red,
    Green,
    Blue,
}

#[derive(Reflect, Clone, Default)]
#[reflect(pkg = "main")]
pub struct Node {
    pub Val: isize,
    pub Next: Option<Box<Node>>,
    pub Kids: Vec<Node>,
}

#[derive(Reflect, Clone, Default)]
#[reflect(pkg = "main")]
pub struct Wrap {
    #[reflect(embed)]
    pub Node: Node,
    #[reflect(embed)]
    pub Base: Base,
}

#[reflect_trait(pkg = "main")]
pub trait Shape {
    fn Sum(&self) -> i32;
}

#[reflect_trait(pkg = "main")]
pub trait Scaler {
    fn Scale(&mut self, k: i32);
}

#[reflect_trait(pkg = "main")]
pub trait Describer {
    fn Describe(&self) -> String;
}

fn type_of(name: &str) -> Type {
    if let Some(rest) = name.strip_prefix('*') {
        return reflect::pointer_to(&type_of(rest));
    }
    if let Some(rest) = name.strip_prefix("[]") {
        return reflect::slice_of(&type_of(rest));
    }
    match name {
        "Base" => reflect::type_for::<Base>(),
        "Named" => reflect::type_for::<Named>(),
        "Mid" => reflect::type_for::<Mid>(),
        "Top" => reflect::type_for::<Top>(),
        "Point" => reflect::type_for::<Point>(),
        "Pair" => reflect::type_for::<Pair<isize, String>>(),
        "Pair2" => reflect::type_for::<Pair<Point, Vec<Base>>>(),
        "Color" => reflect::type_for::<Color>(),
        "Node" => reflect::type_for::<Node>(),
        "Wrap" => reflect::type_for::<Wrap>(),
        "Shape" => reflect::type_for::<dyn Shape>(),
        "Scaler" => reflect::type_for::<dyn Scaler>(),
        "Describer" => reflect::type_for::<dyn Describer>(),
        "int" => reflect::type_for::<isize>(),
        "string" => reflect::type_for::<String>(),
        "int32" => reflect::type_for::<i32>(),
        "any" => Type::any_type(),
        "error" => Type::error_type(),
        _ => panic!("unknown type {name}"),
    }
}

struct Scan<'a> {
    s: &'a str,
    i: usize,
}

impl Scan<'_> {
    fn has(&self, p: &str) -> bool {
        self.s[self.i..].starts_with(p)
    }
    fn eat(&mut self, p: &str) -> bool {
        if self.has(p) {
            self.i += p.len();
            true
        } else {
            false
        }
    }
    fn must(&mut self, p: &str) {
        assert!(self.eat(p), "expected {p}");
    }
    fn until(&mut self, stops: &str) -> &str {
        let rest = &self.s[self.i..];
        let n = rest.find(|c| stops.contains(c)).unwrap_or(rest.len());
        self.i += n;
        &rest[..n]
    }
}

enum Node_ {
    Atom(String),
    List(Vec<Node_>),
}

fn parse_node(p: &mut Scan) -> Node_ {
    if p.eat("[") {
        let mut v = Vec::new();
        while !p.has("]") {
            v.push(parse_node(p));
            p.eat(",");
        }
        p.must("]");
        return Node_::List(v);
    }
    Node_::Atom(p.until(",]").to_string())
}

fn atom(n: &Node_) -> &str {
    match n {
        Node_::Atom(a) => a,
        Node_::List(_) => panic!("expected atom"),
    }
}

fn list(n: &Node_) -> &[Node_] {
    match n {
        Node_::List(l) => l,
        Node_::Atom(_) => panic!("expected list"),
    }
}

fn from_hex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("bad hex"))
        .collect()
}

fn hx(s: impl AsRef<[u8]>) -> String {
    let s = s.as_ref();
    if s.is_empty() {
        return "-".into();
    }
    s.iter().map(|b| format!("{b:02x}")).collect()
}

fn fill(v: &Value, n: &Node_) {
    if matches!(n, Node_::Atom(a) if a == "n") {
        return;
    }
    match v.kind() {
        Kind::Bool => v.set_bool(atom(n) == "t"),
        Kind::Int | Kind::Int8 | Kind::Int16 | Kind::Int32 | Kind::Int64 => {
            v.set_int(atom(n).parse().expect("bad int"))
        }
        Kind::String => v.set_string(from_hex(atom(n))),
        Kind::Slice => {
            let l = list(n);
            let s = reflect::make_slice(&v.type_(), l.len() as isize, l.len() as isize);
            for (i, e) in l.iter().enumerate() {
                fill(&s.index(i), e);
            }
            v.set(&s);
        }
        Kind::Struct => {
            for (i, e) in list(n).iter().enumerate() {
                fill(&v.field(i), e);
            }
        }
        Kind::Pointer => {
            let p = reflect::new(&v.type_().elem());
            fill(&p.elem(), &list(n)[0]);
            v.set(&p);
        }
        k => panic!("cannot fill {k}"),
    }
}

fn pv(v: &Value) -> String {
    if !v.is_valid() {
        return "inv".into();
    }
    let k = v.kind();
    match k {
        Kind::Bool => (if v.bool() { "t" } else { "f" }).into(),
        Kind::Int | Kind::Int8 | Kind::Int16 | Kind::Int32 | Kind::Int64 => format!("i{}", v.int()),
        Kind::String => format!("s{}", hx(v.string_bytes())),
        Kind::Slice => {
            if v.is_nil() {
                return "S-".into();
            }
            let parts: Vec<String> = (0..v.len()).map(|i| pv(&v.index(i))).collect();
            format!("{}[{}]", k, parts.join(","))
        }
        Kind::Struct => {
            let parts: Vec<String> = (0..v.num_field()).map(|i| pv(&v.field(i))).collect();
            format!("{{{}}}", parts.join(","))
        }
        Kind::Pointer => {
            if v.is_nil() {
                "P-".into()
            } else {
                format!("&{}", pv(&v.elem()))
            }
        }
        _ => format!("?{k}"),
    }
}

fn b2s(b: bool) -> &'static str {
    if b {
        "1"
    } else {
        "0"
    }
}

fn idx(ix: &[usize]) -> String {
    ix.iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

fn info(t: &Type) -> String {
    let mut s = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        hx(t.to_string()),
        t.kind(),
        hx(t.name()),
        hx(t.pkg_path()),
        t.size(),
        t.align(),
        t.num_method()
    );
    if t.kind() == Kind::Struct {
        for i in 0..t.num_field() {
            let f = t.field(i);
            s += &format!(
                ";{},{},{},{},{},{},{}",
                hx(&f.name),
                hx(&f.pkg_path),
                b2s(f.anonymous),
                b2s(f.is_exported()),
                f.offset,
                hx(f.tag.as_str()),
                hx(f.type_.to_string())
            );
        }
    }
    s.push('|');
    for i in 0..t.num_method() {
        let m = t.method(i);
        s += &format!("{}:{};", hx(&m.name), hx(m.type_.to_string()));
    }
    s
}

fn handle(f: &[&str]) -> String {
    match f[0] {
        "T" => info(&type_of(f[1])),
        "V" => reflect::visible_fields(&type_of(f[1]))
            .iter()
            .map(|vf| format!("{}:{}", hx(&vf.name), idx(&vf.index)))
            .collect::<Vec<_>>()
            .join(" "),
        "N" => match type_of(f[1]).field_by_name(&String::from_utf8_lossy(&from_hex(f[2]))) {
            None => "none".into(),
            Some(sf) => format!("{} {}", idx(&sf.index), hx(sf.type_.to_string())),
        },
        "R" => {
            let a = type_of(f[1]);
            let b = type_of(f[2]);
            let mut out = format!(
                "{}{}{}",
                b2s(a.assignable_to(&b)),
                b2s(a.convertible_to(&b)),
                b2s(a.comparable())
            );
            if b.kind() == Kind::Interface {
                out += b2s(a.implements(&b));
            }
            out
        }
        "CALL" => {
            let t = type_of(f[1]);
            let p = reflect::new(&t);
            fill(&p.elem(), &parse_node(&mut Scan { s: f[3], i: 0 }));
            let recv = if f[2] == "ptr" { p.clone() } else { p.elem() };
            let m = recv.method_by_name(f[4]);
            if !m.is_valid() {
                return "nomethod".into();
            }
            let mut args = Vec::new();
            for (i, lit) in f[5..].iter().enumerate() {
                let a = reflect::new(&m.type_().in_(i)).elem();
                fill(&a, &parse_node(&mut Scan { s: lit, i: 0 }));
                args.push(a);
            }
            let outs: Vec<String> = m.call(&args).iter().map(pv).collect();
            format!("{} {}", outs.join(";"), pv(&p.elem()))
        }
        "IFACE" => {
            let t = type_of(f[1]);
            let p = reflect::new(&t);
            fill(&p.elem(), &parse_node(&mut Scan { s: f[2], i: 0 }));
            let it = type_of(f[3]);
            let v = reflect::new(&it).elem();
            if !p.type_().implements(&it) && !t.implements(&it) {
                return "noimpl".into();
            }
            if t.implements(&it) {
                v.set(&p.elem());
            } else {
                v.set(&p);
            }
            let m = v.method_by_name(f[4]);
            let outs: Vec<String> = m.call(&[]).iter().map(pv).collect();
            format!(
                "{} {} {}",
                outs.join(";"),
                b2s(v.num_method() > 0),
                v.num_method()
            )
        }
        "D" => {
            let a = reflect::new(&type_of(f[1])).elem();
            let b = reflect::new(&type_of(f[1])).elem();
            fill(&a, &parse_node(&mut Scan { s: f[2], i: 0 }));
            fill(&b, &parse_node(&mut Scan { s: f[3], i: 0 }));
            b2s(reflect::deep_equal_values(&a, &b)).into()
        }
        "CONV" => {
            let a = reflect::new(&type_of(f[1])).elem();
            fill(&a, &parse_node(&mut Scan { s: f[3], i: 0 }));
            let dt = type_of(f[2]);
            let ok = a.type_().convertible_to(&dt);
            let mut out = b2s(ok).to_string();
            if ok {
                out += &format!(" {}", pv(&a.convert(&dt)));
            }
            out
        }
        "SET" => {
            let t = type_of(f[1]);
            let p = reflect::new(&t);
            fill(&p.elem(), &parse_node(&mut Scan { s: f[2], i: 0 }));
            let mut cur = p.elem();
            for s in f[3].split('.') {
                let n: usize = s.parse().unwrap();
                if cur.kind() == Kind::Pointer {
                    cur = cur.elem();
                }
                cur = cur.field(n);
            }
            let nv = reflect::new(&cur.type_()).elem();
            fill(&nv, &parse_node(&mut Scan { s: f[4], i: 0 }));
            let out = format!(
                "{}{}{}",
                b2s(cur.can_set()),
                b2s(cur.can_interface()),
                b2s(cur.can_addr())
            );
            cur.set(&nv);
            format!("{out} {}", pv(&p.elem()))
        }
        other => format!("unknown request {other}"),
    }
}

fn safe(f: &[&str]) -> String {
    match catch_unwind(AssertUnwindSafe(|| handle(f))) {
        Ok(s) => s,
        Err(e) => {
            let msg = if let Some(v) = e.downcast_ref::<reflect::ValueError>() {
                v.error()
            } else if let Some(s) = e.downcast_ref::<String>() {
                s.clone()
            } else if let Some(s) = e.downcast_ref::<&str>() {
                s.to_string()
            } else {
                "unknown panic".into()
            };
            format!("panic:{}", hx(msg))
        }
    }
}

fn main() -> io::Result<()> {
    std::panic::set_hook(Box::new(|_| {}));
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line?;
        let f: Vec<&str> = line.split(' ').collect();
        writeln!(out, "{}", safe(&f))?;
    }
    Ok(())
}
