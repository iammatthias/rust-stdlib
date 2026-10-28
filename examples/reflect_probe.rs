//! Line protocol used by `tools/reflect_check.py` for Go differential checks.
//! Mirrors `tools/reflect_oracle.go`: types come from a spec language built
//! with `slice_of`, `struct_of`, ...; values from a bracketed literal syntax.
use rust_stdlib::reflect::{self, ChanDir, Kind, StructField, StructTag, Type, Value};
use rust_stdlib::strconv::Complex;
use std::io::{self, BufRead, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};

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
        if !self.eat(p) {
            panic!("spec: expected {p} at {} in {}", self.i, self.s);
        }
    }
    fn until(&mut self, stops: &str) -> &str {
        let rest = &self.s[self.i..];
        let n = rest.find(|c| stops.contains(c)).unwrap_or(rest.len());
        self.i += n;
        &rest[..n]
    }
}

fn basic_type(name: &str) -> Type {
    let k = match name {
        "bool" => Kind::Bool,
        "int" => Kind::Int,
        "int8" => Kind::Int8,
        "int16" => Kind::Int16,
        "int32" => Kind::Int32,
        "int64" => Kind::Int64,
        "uint" => Kind::Uint,
        "uint8" => Kind::Uint8,
        "uint16" => Kind::Uint16,
        "uint32" => Kind::Uint32,
        "uint64" => Kind::Uint64,
        "uintptr" => Kind::Uintptr,
        "float32" => Kind::Float32,
        "float64" => Kind::Float64,
        "complex64" => Kind::Complex64,
        "complex128" => Kind::Complex128,
        "string" => Kind::String,
        "any" => return Type::any_type(),
        "error" => return Type::error_type(),
        _ => panic!("spec: unknown type {name}"),
    };
    Type::basic(k)
}

fn from_hex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("bad hex"))
        .collect()
}

fn unhex(s: &str) -> String {
    String::from_utf8_lossy(&from_hex(s)).into_owned()
}

fn parse_type(p: &mut Scan) -> Type {
    if p.eat("[]") {
        return reflect::slice_of(&parse_type(p));
    }
    if p.eat("[") {
        let n: isize = p.until("]").parse().expect("bad array length");
        p.must("]");
        return reflect::array_of(n, &parse_type(p));
    }
    if p.eat("*") {
        return reflect::pointer_to(&parse_type(p));
    }
    if p.eat("map[") {
        let k = parse_type(p);
        p.must("]");
        return reflect::map_of(&k, &parse_type(p));
    }
    for (prefix, dir) in [
        ("chan:", ChanDir::Both),
        ("rchan:", ChanDir::Recv),
        ("schan:", ChanDir::Send),
    ] {
        if p.eat(prefix) {
            return reflect::chan_of(dir, &parse_type(p));
        }
    }
    if p.eat("func(") {
        let (mut ins, mut outs, mut variadic) = (Vec::new(), Vec::new(), false);
        while !p.has(")") {
            if p.eat("...") {
                variadic = true;
            }
            ins.push(parse_type(p));
            p.eat(",");
        }
        p.must(")(");
        while !p.has(")") {
            outs.push(parse_type(p));
            p.eat(",");
        }
        p.must(")");
        return reflect::func_of(&ins, &outs, variadic);
    }
    if p.eat("{") {
        let mut fields = Vec::new();
        while !p.has("}") {
            let anonymous = p.eat("@");
            let name = p.until("^:").to_string();
            let unexported = p.eat("^");
            p.must(":");
            let ty = parse_type(p);
            let mut f = StructField::new(&name, ty);
            f.anonymous = anonymous;
            if unexported {
                f.pkg_path = "main".into();
            }
            if p.eat("|") {
                f.tag = StructTag::new(unhex(p.until(";}")));
            }
            fields.push(f);
            p.eat(";");
        }
        p.must("}");
        return reflect::struct_of(&fields);
    }
    let name = p.until(";,)}]|").to_string();
    basic_type(&name)
}

fn type_of(spec: &str) -> Type {
    parse_type(&mut Scan { s: spec, i: 0 })
}

enum Node {
    Atom(String),
    List(Vec<Node>),
}

fn parse_node(p: &mut Scan) -> Node {
    if p.eat("[") {
        let mut v = Vec::new();
        while !p.has("]") {
            v.push(parse_node(p));
            p.eat(",");
        }
        p.must("]");
        return Node::List(v);
    }
    Node::Atom(p.until(",]").to_string())
}

fn atom(n: &Node) -> &str {
    match n {
        Node::Atom(a) => a,
        Node::List(_) => panic!("expected atom"),
    }
}

fn list(n: &Node) -> &[Node] {
    match n {
        Node::List(l) => l,
        Node::Atom(_) => panic!("expected list"),
    }
}

fn fill(v: &Value, n: &Node) {
    if matches!(n, Node::Atom(a) if a == "n") {
        return;
    }
    match v.kind() {
        Kind::Bool => v.set_bool(atom(n) == "t"),
        Kind::Int | Kind::Int8 | Kind::Int16 | Kind::Int32 | Kind::Int64 => {
            v.set_int(atom(n).parse().expect("bad int"))
        }
        Kind::Uint | Kind::Uint8 | Kind::Uint16 | Kind::Uint32 | Kind::Uint64 | Kind::Uintptr => {
            v.set_uint(atom(n).parse().expect("bad uint"))
        }
        Kind::Float32 => {
            v.set_float(f32::from_bits(u32::from_str_radix(atom(n), 16).unwrap()) as f64)
        }
        Kind::Float64 => v.set_float(f64::from_bits(u64::from_str_radix(atom(n), 16).unwrap())),
        Kind::Complex64 => {
            let l = list(n);
            let f = |x: &Node| f32::from_bits(u32::from_str_radix(atom(x), 16).unwrap()) as f64;
            v.set_complex(Complex {
                re: f(&l[0]),
                im: f(&l[1]),
            });
        }
        Kind::Complex128 => {
            let l = list(n);
            let f = |x: &Node| f64::from_bits(u64::from_str_radix(atom(x), 16).unwrap());
            v.set_complex(Complex {
                re: f(&l[0]),
                im: f(&l[1]),
            });
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
        Kind::Array => {
            for (i, e) in list(n).iter().enumerate() {
                fill(&v.index(i), e);
            }
        }
        Kind::Struct => {
            for (i, e) in list(n).iter().enumerate() {
                fill(&v.field(i), e);
            }
        }
        Kind::Map => {
            let m = reflect::make_map(&v.type_());
            for e in list(n) {
                let l = list(e);
                let k = reflect::new(&v.type_().key()).elem();
                fill(&k, &l[0]);
                let x = reflect::new(&v.type_().elem()).elem();
                fill(&x, &l[1]);
                m.set_map_index(&k, &x);
            }
            v.set(&m);
        }
        Kind::Pointer => {
            let p = reflect::new(&v.type_().elem());
            fill(&p.elem(), &list(n)[0]);
            v.set(&p);
        }
        Kind::Interface => {
            let l = list(n);
            let t = type_of(&unhex(atom(&l[0])));
            let x = reflect::new(&t).elem();
            fill(&x, &l[1]);
            v.set(&x);
        }
        k => panic!("cannot fill {k}"),
    }
}

fn make_val(spec: &str, lit: &str) -> Value {
    let t = type_of(spec);
    let v = reflect::new(&t).elem();
    fill(&v, &parse_node(&mut Scan { s: lit, i: 0 }));
    v
}

fn hx(s: impl AsRef<[u8]>) -> String {
    let s = s.as_ref();
    if s.is_empty() {
        return "-".into();
    }
    s.iter().map(|b| format!("{b:02x}")).collect()
}

fn pf(k: Kind, f: f64) -> String {
    if k == Kind::Float32 || k == Kind::Complex64 {
        format!("{:08x}", (f as f32).to_bits())
    } else {
        format!("{:016x}", f.to_bits())
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
        Kind::Uint | Kind::Uint8 | Kind::Uint16 | Kind::Uint32 | Kind::Uint64 | Kind::Uintptr => {
            format!("u{}", v.uint())
        }
        Kind::Float32 | Kind::Float64 => format!("f{}", pf(k, v.float())),
        Kind::Complex64 | Kind::Complex128 => {
            let c = v.complex();
            format!("c({},{})", pf(k, c.re), pf(k, c.im))
        }
        Kind::String => format!("s{}", hx(v.string_bytes())),
        Kind::Slice | Kind::Array => {
            if k == Kind::Slice && v.is_nil() {
                return "S-".into();
            }
            let parts: Vec<String> = (0..v.len()).map(|i| pv(&v.index(i))).collect();
            format!("{}[{}]", k, parts.join(","))
        }
        Kind::Struct => {
            let parts: Vec<String> = (0..v.num_field()).map(|i| pv(&v.field(i))).collect();
            format!("{{{}}}", parts.join(","))
        }
        Kind::Map => {
            if v.is_nil() {
                return "M-".into();
            }
            let mut parts: Vec<String> = v
                .map_keys()
                .iter()
                .map(|k| format!("{}={}", pv(k), pv(&v.map_index(k))))
                .collect();
            parts.sort();
            format!("M{{{}}}", parts.join(","))
        }
        Kind::Pointer => {
            if v.is_nil() {
                "P-".into()
            } else {
                format!("&{}", pv(&v.elem()))
            }
        }
        Kind::Interface => {
            if v.is_nil() {
                "I-".into()
            } else {
                format!("I({}:{})", v.elem().type_(), pv(&v.elem()))
            }
        }
        Kind::Chan => (if v.is_nil() { "C-" } else { "C+" }).into(),
        Kind::Func => (if v.is_nil() { "F-" } else { "F+" }).into(),
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

fn idx_v(ix: &[usize]) -> String {
    format!(
        "[{}]",
        ix.iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(" ")
    )
}

fn go_type(t: &Type) -> String {
    let mut s = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}",
        hx(t.to_string()),
        t.kind(),
        hx(t.name()),
        hx(t.pkg_path()),
        b2s(t.comparable()),
        t.size(),
        t.align(),
        t.field_align(),
        t.num_method()
    );
    match t.kind() {
        Kind::Struct => {
            s += &format!("|{}", t.num_field());
            for i in 0..t.num_field() {
                let f = t.field(i);
                s += &format!(
                    ";{},{},{},{},{},{},{},{}",
                    hx(&f.name),
                    hx(&f.pkg_path),
                    b2s(f.anonymous),
                    b2s(f.is_exported()),
                    f.offset,
                    idx_v(&f.index),
                    hx(f.tag.as_str()),
                    hx(f.type_.to_string())
                );
            }
        }
        Kind::Array => s += &format!("|{},{}", t.len(), hx(t.elem().to_string())),
        Kind::Slice | Kind::Pointer => s += &format!("|{}", hx(t.elem().to_string())),
        Kind::Chan => s += &format!("|{},{}", t.chan_dir(), hx(t.elem().to_string())),
        Kind::Map => s += &format!("|{},{}", hx(t.key().to_string()), hx(t.elem().to_string())),
        Kind::Func => {
            s += &format!(
                "|{},{},{}",
                t.num_in(),
                t.num_out(),
                if t.is_variadic() { 1 } else { 0 }
            );
            for i in 0..t.num_in() {
                s += &format!(",{}", hx(t.in_(i).to_string()));
            }
            for i in 0..t.num_out() {
                s += &format!(",{}", hx(t.out(i).to_string()));
            }
        }
        Kind::Interface => s += &format!("|{}", t.num_method()),
        _ => {}
    }
    let k = t.kind();
    if (Kind::Int..=Kind::Complex128).contains(&k) {
        s += &format!("|bits{}", t.bits());
    }
    s
}

fn handle(f: &[&str]) -> String {
    match f[0] {
        "T" => go_type(&type_of(f[1])),
        "V" => reflect::visible_fields(&type_of(f[1]))
            .iter()
            .map(|vf| format!("{}:{}", hx(&vf.name), idx(&vf.index)))
            .collect::<Vec<_>>()
            .join(" "),
        "N" => {
            let t = type_of(f[1]);
            let name = unhex(f[2]);
            match t.field_by_name(&name) {
                None => "none".into(),
                Some(sf) => format!(
                    "{} {} {}",
                    idx(&sf.index),
                    hx(sf.type_.to_string()),
                    sf.offset
                ),
            }
        }
        "NF" => {
            let t = type_of(f[1]);
            let prefix = unhex(f[2]);
            match t.field_by_name_func(|s| s.starts_with(&prefix)) {
                None => "none".into(),
                Some(sf) => format!("{} {}", idx(&sf.index), hx(sf.type_.to_string())),
            }
        }
        "G" => {
            let tag = StructTag::new(unhex(f[1]));
            let key = unhex(f[2]);
            let l = tag.lookup(&key);
            format!(
                "{} {} {}",
                hx(tag.get(&key)),
                hx(l.clone().unwrap_or_default()),
                b2s(l.is_some())
            )
        }
        "D" => {
            let a = make_val(f[1], f[2]);
            let b = make_val(f[1], f[3]);
            let ai = a.dynamic();
            let bi = b.dynamic();
            let mut out = b2s(reflect::deep_equal_values(&ai, &bi)).to_string();
            if a.type_().comparable() && a.comparable() && b.comparable() {
                out += &format!(" eq={}", b2s(a.equal(&b)));
            }
            out
        }
        "C" => {
            let src = make_val(f[1], f[3]);
            let dt = type_of(f[2]);
            let mut out = format!(
                "{} {}",
                b2s(src.type_().convertible_to(&dt)),
                b2s(src.can_convert(&dt))
            );
            if src.can_convert(&dt) {
                out += &format!(" {}", pv(&src.convert(&dt)));
            }
            out
        }
        "S" => {
            let v = make_val(f[1], f[2]);
            format!(
                "{} {} {} zero={}",
                hx(if v.kind() == Kind::String {
                    v.string_bytes()
                } else {
                    v.text().into_bytes()
                }),
                v.kind(),
                pv(&v),
                b2s(v.is_zero())
            )
        }
        "R" => {
            let a = type_of(f[1]);
            let b = type_of(f[2]);
            format!(
                "{}{}{}{}{}",
                b2s(a.assignable_to(&b)),
                b2s(a.convertible_to(&b)),
                b2s(a.comparable()),
                b2s(a.implements(&Type::any_type())),
                b2s(a.implements(&Type::error_type()))
            )
        }
        "O" => {
            let t = type_of(f[1]);
            let v = reflect::new(&t).elem();
            let k = t.kind();
            if (Kind::Int..=Kind::Int64).contains(&k) {
                let x: i64 = f[2].parse().unwrap();
                format!("{}{}", b2s(t.overflow_int(x)), b2s(v.overflow_int(x)))
            } else if (Kind::Uint..=Kind::Uintptr).contains(&k) {
                let x: u64 = f[2].parse().unwrap();
                format!("{}{}", b2s(t.overflow_uint(x)), b2s(v.overflow_uint(x)))
            } else {
                let fl = f64::from_bits(u64::from_str_radix(f[2], 16).unwrap());
                if k == Kind::Complex64 || k == Kind::Complex128 {
                    format!(
                        "{}{}",
                        b2s(t.overflow_complex(fl, fl)),
                        b2s(v.overflow_complex(Complex { re: fl, im: 1.0 }))
                    )
                } else {
                    format!("{}{}", b2s(t.overflow_float(fl)), b2s(v.overflow_float(fl)))
                }
            }
        }
        "L" => {
            let v = make_val(f[1], f[2]);
            let i: isize = f[3].parse().unwrap();
            let j: isize = f[4].parse().unwrap();
            let s = if f.len() > 5 {
                v.slice3(i, j, f[5].parse().unwrap())
            } else {
                v.slice(i, j)
            };
            format!("{} {} {}", s.len(), s.cap(), pv(&s))
        }
        "A" => {
            let v = make_val(f[1], f[2]);
            let mut xs = Vec::new();
            for lit in f[3..].iter().filter(|l| !l.is_empty()) {
                let x = reflect::new(&v.type_().elem()).elem();
                fill(&x, &parse_node(&mut Scan { s: lit, i: 0 }));
                xs.push(x);
            }
            let s = reflect::append(&v, &xs);
            format!("{} {} {}", s.len(), b2s(s.cap() >= s.len()), pv(&s))
        }
        "M" => {
            let v = make_val(f[1], f[2]);
            let k = reflect::new(&v.type_().key()).elem();
            fill(&k, &parse_node(&mut Scan { s: f[3], i: 0 }));
            format!(
                "{} {} {}",
                pv(&v.map_index(&k)),
                v.len(),
                v.map_keys().len()
            )
        }
        "Z" => {
            let v = reflect::zero(&type_of(f[1]));
            format!("{} {}", pv(&v), b2s(v.is_zero()))
        }
        "E" => {
            let t = type_of(f[1]);
            let p = reflect::new(&t);
            fill(&p.elem(), &parse_node(&mut Scan { s: f[2], i: 0 }));
            let mut cur = p.elem();
            for step in f[3].split('.') {
                if step.is_empty() {
                    continue;
                }
                let n: usize = step.parse().unwrap();
                if cur.kind() == Kind::Pointer {
                    cur = cur.elem();
                }
                cur = if cur.kind() == Kind::Struct {
                    cur.field(n)
                } else {
                    cur.index(n)
                };
            }
            let nv = reflect::new(&cur.type_()).elem();
            fill(&nv, &parse_node(&mut Scan { s: f[4], i: 0 }));
            cur.set(&nv);
            format!(
                "{} {}{}",
                pv(&p.elem()),
                b2s(cur.can_set()),
                b2s(cur.can_addr())
            )
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
