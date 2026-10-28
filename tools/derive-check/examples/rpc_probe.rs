//! The Rust side of the net/rpc interop test (tools/rpc_check.py); see
//! tools/rpc_interop.go for the protocol. Modes: `server <gob|json|http>`
//! and `client <gob|json|http> <port>`.
#![allow(non_snake_case, dead_code)]
use std::collections::BTreeMap;
use std::io::Read;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use rust_stdlib::net::rpc::{self, jsonrpc, Server};
use rust_stdlib::reflect::{self, Reflect, ReflectType};
use rust_stdlib_derive::{reflect_methods, Reflect};

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
pub struct Args {
    pub A: isize,
    pub B: isize,
}

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
pub struct Reply {
    pub C: isize,
}

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
pub struct Quotient {
    pub Quo: isize,
    pub Rem: isize,
}

#[derive(Reflect, Clone, Default)]
#[reflect(pkg = "main")]
pub struct Inner {
    pub X: isize,
}

#[derive(Reflect, Clone, Default)]
#[reflect(pkg = "main")]
pub struct Rich {
    #[reflect("json:\"s\"")]
    pub S: String,
    pub F: f64,
    pub B: Vec<u8>,
    pub M: BTreeMap<String, isize>,
    pub P: Option<isize>,
    #[reflect("json:\"l,omitempty\"")]
    pub L: Vec<String>,
    pub N: i8,
    pub In: Inner,
    pub Any: reflect::Value,
}

#[derive(Reflect, Clone, Default)]
#[reflect(pkg = "main")]
pub struct Arith {
    calls: isize,
}

#[reflect_methods]
impl Arith {
    pub fn Add(&mut self, args: Option<Args>, reply: &mut Reply) -> Result<(), String> {
        let args = args.unwrap_or_default();
        self.calls += 1;
        reply.C = args.A.wrapping_add(args.B);
        Ok(())
    }
    pub fn Mul(&self, args: Option<Args>, reply: &mut Reply) -> Result<(), String> {
        let args = args.unwrap_or_default();
        reply.C = args.A.wrapping_mul(args.B);
        Ok(())
    }
    pub fn Div(&self, args: Option<Args>, q: &mut Quotient) -> Result<(), String> {
        let args = args.unwrap_or_default();
        if args.B == 0 {
            return Err("divide by zero".into());
        }
        q.Quo = args.A / args.B;
        q.Rem = args.A % args.B;
        Ok(())
    }
    pub fn Error(&self, _args: Option<Args>, _reply: &mut Reply) -> Result<(), String> {
        Err("ERROR".into())
    }
    pub fn Count(&mut self, _args: Option<Args>, reply: &mut isize) -> Result<(), String> {
        *reply = self.calls;
        Ok(())
    }
    pub fn Names(
        &self,
        _args: Option<Args>,
        reply: &mut BTreeMap<String, isize>,
    ) -> Result<(), String> {
        reply.insert("x".into(), 1);
        Ok(())
    }
    pub fn Echo(&self, args: Option<Rich>, reply: &mut Rich) -> Result<(), String> {
        *reply = args.unwrap_or_default();
        Ok(())
    }
    pub fn Sleep(&self, args: Option<Args>, reply: &mut Reply) -> Result<(), String> {
        let args = args.unwrap_or_default();
        std::thread::sleep(Duration::from_millis(args.A as u64));
        reply.C = args.A;
        Ok(())
    }
}

/// The `([]byte, error)` result of `MarshalJSON`. An alias keeps the derive's
/// comma split of the result tuple intact.
type GoErr = Result<(), String>;

/// `Money` as `"$d.cc"`: `MarshalJSON` takes `&self`, `UnmarshalJSON` `&mut self`.
#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
pub struct Money {
    pub Cents: isize,
}

#[reflect_methods]
impl Money {
    pub fn MarshalJSON(&self) -> (Vec<u8>, GoErr) {
        let text = format!("\"${}.{:02}\"", self.Cents / 100, self.Cents % 100);
        (text.into_bytes(), Ok(()))
    }
    pub fn UnmarshalJSON(&mut self, data: &[u8]) -> Result<(), String> {
        let bad = || Err(format!("bad money {}", String::from_utf8_lossy(data)));
        if data.len() < 4 || data[0] != b'"' || data[1] != b'$' || data[data.len() - 1] != b'"' {
            return bad();
        }
        let body = match std::str::from_utf8(&data[2..data.len() - 1]) {
            Ok(body) => body,
            Err(_) => return bad(),
        };
        let Some((d, c)) = body.split_once('.') else {
            return bad();
        };
        match (d.parse::<isize>(), c.parse::<isize>()) {
            (Ok(d), Ok(c)) => {
                self.Cents = d * 100 + c;
                Ok(())
            }
            _ => bad(),
        }
    }
}

/// `Stamp` marshals and unmarshals through pointer receivers.
#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
pub struct Stamp {
    pub N: isize,
}

#[reflect_methods]
impl Stamp {
    pub fn MarshalJSON(&mut self) -> (Vec<u8>, GoErr) {
        (format!("\"stamp-{}\"", self.N).into_bytes(), Ok(()))
    }
    pub fn UnmarshalJSON(&mut self, data: &[u8]) -> Result<(), String> {
        let n = data
            .strip_prefix(b"\"stamp-")
            .and_then(|b| b.strip_suffix(b"\""))
            .and_then(|b| std::str::from_utf8(b).ok())
            .and_then(|b| b.parse::<isize>().ok());
        match n {
            Some(n) => {
                self.N = n;
                Ok(())
            }
            None => Err(format!("bad stamp {}", String::from_utf8_lossy(data))),
        }
    }
}

/// `Sealed` marshals through a pointer receiver and has no `UnmarshalJSON`.
#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
pub struct Sealed {
    pub N: isize,
}

#[reflect_methods]
impl Sealed {
    pub fn MarshalJSON(&mut self) -> (Vec<u8>, GoErr) {
        (format!("\"sealed-{}\"", self.N).into_bytes(), Ok(()))
    }
}

/// `Verbatim` keeps the JSON text it was decoded from; `null` when it has none.
#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
pub struct Verbatim {
    pub Text: String,
}

#[reflect_methods]
impl Verbatim {
    pub fn MarshalJSON(&self) -> (Vec<u8>, GoErr) {
        let text = if self.Text.is_empty() {
            "null"
        } else {
            self.Text.as_str()
        };
        (text.as_bytes().to_vec(), Ok(()))
    }
    pub fn UnmarshalJSON(&mut self, data: &[u8]) -> Result<(), String> {
        self.Text = String::from_utf8_lossy(data).into_owned();
        Ok(())
    }
}

/// `Faulty` fails to marshal with an error; `Broken` marshals invalid JSON.
#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
pub struct Faulty {
    pub Code: isize,
}

#[reflect_methods]
impl Faulty {
    pub fn MarshalJSON(&self) -> (Vec<u8>, GoErr) {
        (Vec::new(), Err("boom".into()))
    }
}

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
pub struct Broken {
    pub Code: isize,
}

#[reflect_methods]
impl Broken {
    pub fn MarshalJSON(&self) -> (Vec<u8>, GoErr) {
        (b"{".to_vec(), Ok(()))
    }
}

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
pub struct Entry {
    pub Amount: Money,
    pub Ptr: Option<Money>,
    pub List: Vec<Money>,
    pub Map: BTreeMap<String, Money>,
    pub Raw: Verbatim,
    pub Stamp: Option<Stamp>,
    pub Hidden: Stamp,
    pub Sealed: BTreeMap<String, Sealed>,
}

/// `Tier` is a Go int on the wire as `tier-N` (0 to 3): `MarshalText` takes
/// `&self`, `UnmarshalText` `&mut self`.
#[derive(Reflect, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[reflect(pkg = "main")]
pub enum Tier {
    #[default]
    T0,
    T1,
    T2,
    T3,
}

#[reflect_methods]
impl Tier {
    pub fn MarshalText(&self) -> (Vec<u8>, GoErr) {
        (format!("tier-{}", *self as isize).into_bytes(), Ok(()))
    }
    pub fn UnmarshalText(&mut self, data: &[u8]) -> Result<(), String> {
        let n = data
            .strip_prefix(b"tier-")
            .and_then(|b| std::str::from_utf8(b).ok())
            .and_then(|b| b.parse::<isize>().ok())
            .filter(|n| (0..=3).contains(n));
        *self = match n {
            Some(0) => Tier::T0,
            Some(1) => Tier::T1,
            Some(2) => Tier::T2,
            Some(3) => Tier::T3,
            _ => return Err(format!("bad tier {}", String::from_utf8_lossy(data))),
        };
        Ok(())
    }
}

/// `Region` is a Go string type: `MarshalText` writes `r:NAME` and
/// `UnmarshalText` reads it back. Rust's derive has no string kind, so the
/// named type is declared here by hand, as the derive would declare it.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Region(pub String);

impl reflect::ReflectType for Region {
    fn reflect_type() -> reflect::Type {
        reflect::__private::named_type::<Self>(
            "main",
            || "Region".to_string(),
            || reflect::__private::basic_body(reflect::Kind::String),
            Some(<Region as reflect::__private::ReflectMethods>::reflect_methods),
        )
    }
}

impl Reflect for Region {
    fn to_value(&self) -> reflect::Value {
        reflect::Value::from_string(&Self::reflect_type(), self.0.as_bytes())
    }
    fn from_value(v: &reflect::Value) -> Result<Self, reflect::Error> {
        if v.kind() != reflect::Kind::String {
            return Err(reflect::__private::mismatch(v, "string"));
        }
        Ok(Region(
            String::from_utf8_lossy(&v.string_bytes()).into_owned(),
        ))
    }
}

#[reflect_methods]
impl Region {
    pub fn MarshalText(&self) -> (Vec<u8>, GoErr) {
        (format!("r:{}", self.0).into_bytes(), Ok(()))
    }
    pub fn UnmarshalText(&mut self, data: &[u8]) -> Result<(), String> {
        match data.strip_prefix(b"r:") {
            Some(name) => {
                self.0 = String::from_utf8_lossy(name).into_owned();
                Ok(())
            }
            None => Err(format!("bad region {}", String::from_utf8_lossy(data))),
        }
    }
}

/// `Code` marshals and unmarshals through pointer receivers: a `Code` that is
/// not addressable is an object.
#[derive(Reflect, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[reflect(pkg = "main")]
pub struct Code {
    pub N: isize,
}

#[reflect_methods]
impl Code {
    pub fn MarshalText(&mut self) -> (Vec<u8>, GoErr) {
        (format!("code-{}", self.N).into_bytes(), Ok(()))
    }
    pub fn UnmarshalText(&mut self, data: &[u8]) -> Result<(), String> {
        let n = data
            .strip_prefix(b"code-")
            .and_then(|b| std::str::from_utf8(b).ok())
            .and_then(|b| b.parse::<isize>().ok());
        match n {
            Some(n) => {
                self.N = n;
                Ok(())
            }
            None => Err(format!("bad code {}", String::from_utf8_lossy(data))),
        }
    }
}

/// `Mixed` marshals as JSON through a pointer receiver and as text through a
/// value receiver: the JSON method applies to addressable values only.
#[derive(Reflect, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[reflect(pkg = "main")]
pub struct Mixed {
    pub N: isize,
}

#[reflect_methods]
impl Mixed {
    pub fn MarshalJSON(&mut self) -> (Vec<u8>, GoErr) {
        (format!("{{\"mixed\":{}}}", self.N).into_bytes(), Ok(()))
    }
    pub fn MarshalText(&self) -> (Vec<u8>, GoErr) {
        (format!("mixed-{}", self.N).into_bytes(), Ok(()))
    }
}

/// `Torn` fails to marshal as text when `N` is negative.
#[derive(Reflect, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[reflect(pkg = "main")]
pub struct Torn {
    pub N: isize,
}

#[reflect_methods]
impl Torn {
    pub fn MarshalText(&self) -> (Vec<u8>, GoErr) {
        if self.N < 0 {
            return (Vec::new(), Err(format!("torn {}", self.N)));
        }
        (format!("torn-{}", self.N).into_bytes(), Ok(()))
    }
    pub fn UnmarshalText(&mut self, data: &[u8]) -> Result<(), String> {
        let n = data
            .strip_prefix(b"torn-")
            .and_then(|b| std::str::from_utf8(b).ok())
            .and_then(|b| b.parse::<isize>().ok());
        match n {
            Some(n) => {
                self.N = n;
                Ok(())
            }
            None => Err(format!("bad torn {}", String::from_utf8_lossy(data))),
        }
    }
}

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
pub struct Torns {
    pub One: Torn,
    pub Keys: BTreeMap<Torn, isize>,
}

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
pub struct Labels {
    pub Tier: Tier,
    pub TierPtr: Option<Tier>,
    pub Tiers: Vec<Tier>,
    pub ByTier: BTreeMap<Tier, String>,
    pub ByRegion: BTreeMap<Region, isize>,
    pub Code: Code,
    pub Codes: Vec<Code>,
    pub Mixed: Vec<Mixed>,
    pub MixedMap: BTreeMap<String, Mixed>,
}

/// `PKey` has `MarshalText` and `UnmarshalText` on its pointer only.
#[derive(Reflect, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[reflect(pkg = "main")]
pub struct PKey {
    pub N: isize,
}

#[reflect_methods]
impl PKey {
    pub fn MarshalText(&mut self) -> (Vec<u8>, GoErr) {
        (format!("pk-{}", self.N).into_bytes(), Ok(()))
    }
    pub fn UnmarshalText(&mut self, data: &[u8]) -> Result<(), String> {
        let n = data
            .strip_prefix(b"pk-")
            .and_then(|b| std::str::from_utf8(b).ok())
            .and_then(|b| b.parse::<isize>().ok());
        match n {
            Some(n) => {
                self.N = n;
                Ok(())
            }
            None => Err(format!("bad pkey {}", String::from_utf8_lossy(data))),
        }
    }
}

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
pub struct PKeysDeep {
    pub M: BTreeMap<PKey, isize>,
}

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
pub struct PKeys {
    pub Pad: isize,
    pub M: BTreeMap<PKey, isize>,
    pub Deep: Vec<PKeysDeep>,
}

/// `JKey` is a Go string with both `UnmarshalJSON` and `UnmarshalText`.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct JKey(pub String);

impl reflect::ReflectType for JKey {
    fn reflect_type() -> reflect::Type {
        reflect::__private::named_type::<Self>(
            "main",
            || "JKey".to_string(),
            || reflect::__private::basic_body(reflect::Kind::String),
            Some(<JKey as reflect::__private::ReflectMethods>::reflect_methods),
        )
    }
}

impl Reflect for JKey {
    fn to_value(&self) -> reflect::Value {
        reflect::Value::from_string(&Self::reflect_type(), self.0.as_bytes())
    }
    fn from_value(v: &reflect::Value) -> Result<Self, reflect::Error> {
        if v.kind() != reflect::Kind::String {
            return Err(reflect::__private::mismatch(v, "string"));
        }
        Ok(JKey(
            String::from_utf8_lossy(&v.string_bytes()).into_owned(),
        ))
    }
}

#[reflect_methods]
impl JKey {
    pub fn MarshalText(&self) -> (Vec<u8>, GoErr) {
        (self.0.clone().into_bytes(), Ok(()))
    }
    pub fn UnmarshalJSON(&mut self, data: &[u8]) -> Result<(), String> {
        self.0 = format!("J{}", String::from_utf8_lossy(data));
        Ok(())
    }
    pub fn UnmarshalText(&mut self, data: &[u8]) -> Result<(), String> {
        self.0 = format!("T{}", String::from_utf8_lossy(data));
        Ok(())
    }
}

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
pub struct JKeys {
    pub M: BTreeMap<JKey, isize>,
}

/// A Go byte kind with the methods given: `Octets` holds slices and arrays of
/// them, which are base64 or arrays depending on the methods.
macro_rules! byte_kind {
    ($name:ident, $($methods:tt)*) => {
        #[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Debug)]
        pub struct $name(pub u8);

        impl reflect::ReflectType for $name {
            fn reflect_type() -> reflect::Type {
                reflect::__private::named_type::<Self>(
                    "main",
                    || stringify!($name).to_string(),
                    || reflect::__private::basic_body(reflect::Kind::Uint8),
                    Some(<$name as reflect::__private::ReflectMethods>::reflect_methods),
                )
            }
        }

        impl Reflect for $name {
            fn to_value(&self) -> reflect::Value {
                reflect::Value::from_uint(&Self::reflect_type(), u64::from(self.0))
            }
            fn from_value(v: &reflect::Value) -> Result<Self, reflect::Error> {
                if v.kind() != reflect::Kind::Uint8 {
                    return Err(reflect::__private::mismatch(v, "uint8"));
                }
                Ok($name(v.uint() as u8))
            }
        }

        #[reflect_methods]
        impl $name {
            $($methods)*
        }
    };
}

byte_kind!(
    MJV,
    pub fn MarshalJSON(&self) -> (Vec<u8>, GoErr) {
        (b"7".to_vec(), Ok(()))
    }
);
byte_kind!(
    MJP,
    pub fn MarshalJSON(&mut self) -> (Vec<u8>, GoErr) {
        (b"7".to_vec(), Ok(()))
    }
);
byte_kind!(
    MTV,
    pub fn MarshalText(&self) -> (Vec<u8>, GoErr) {
        (b"t".to_vec(), Ok(()))
    }
);
byte_kind!(
    MTP,
    pub fn MarshalText(&mut self) -> (Vec<u8>, GoErr) {
        (b"t".to_vec(), Ok(()))
    }
);
byte_kind!(
    UJP,
    pub fn UnmarshalJSON(&mut self, data: &[u8]) -> Result<(), String> {
        self.0 = data.len() as u8;
        Ok(())
    }
);
byte_kind!(
    UTP,
    pub fn UnmarshalText(&mut self, data: &[u8]) -> Result<(), String> {
        self.0 = data.len() as u8;
        Ok(())
    }
);

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
pub struct Octets {
    pub A: Vec<MJV>,
    pub B: Vec<MJP>,
    pub C: Vec<MTV>,
    pub D: Vec<MTP>,
    pub E: Vec<UJP>,
    pub F: Vec<UTP>,
    pub G: [MJP; 2],
    pub H: [UTP; 2],
}

/// Text-typed fields with the `,string` option, which does not apply to them.
#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
pub struct Quoted {
    #[reflect("json:\",string\"")]
    pub A: Region,
    #[reflect("json:\",string\"")]
    pub B: Tier,
    #[reflect("json:\",string\"")]
    pub C: Option<Tier>,
    #[reflect("json:\",string\"")]
    pub D: Vec<Tier>,
    #[reflect("json:\",string\"")]
    pub F: isize,
    #[reflect("json:\",string\"")]
    pub G: Vec<isize>,
    #[reflect("json:\",string\"")]
    pub H: Option<Code>,
}

#[derive(Reflect, Clone, Default)]
#[reflect(pkg = "main")]
pub struct Ledger {
    posted: isize,
}

#[reflect_methods]
impl Ledger {
    pub fn Post(&self, args: Option<Entry>, reply: &mut Entry) -> Result<(), String> {
        *reply = args.unwrap_or_default();
        Ok(())
    }
    pub fn Labels(&self, args: Option<Labels>, reply: &mut Labels) -> Result<(), String> {
        *reply = args.unwrap_or_default();
        Ok(())
    }
    pub fn Torns(&self, args: Option<Torns>, reply: &mut Torns) -> Result<(), String> {
        *reply = args.unwrap_or_default();
        Ok(())
    }
    pub fn PKeys(&self, args: Option<PKeys>, reply: &mut PKeys) -> Result<(), String> {
        *reply = args.unwrap_or_default();
        Ok(())
    }
    pub fn JKeys(&self, args: Option<JKeys>, reply: &mut JKeys) -> Result<(), String> {
        *reply = args.unwrap_or_default();
        Ok(())
    }
    pub fn Octets(&self, args: Option<Octets>, reply: &mut Octets) -> Result<(), String> {
        *reply = args.unwrap_or_default();
        Ok(())
    }
    pub fn Quoted(&self, args: Option<Quoted>, reply: &mut Quoted) -> Result<(), String> {
        *reply = args.unwrap_or_default();
        Ok(())
    }
    pub fn Faulty(&self, args: Option<Faulty>, reply: &mut Faulty) -> Result<(), String> {
        *reply = args.unwrap_or_default();
        Ok(())
    }
    pub fn Broken(&self, args: Option<Broken>, reply: &mut Broken) -> Result<(), String> {
        *reply = args.unwrap_or_default();
        Ok(())
    }
}

fn serve(mode: &str) {
    let server = Server::new();
    server.register(&Some(Arith::default())).expect("register");
    server.register(&Some(Ledger::default())).expect("register");
    let lis = rust_stdlib::net::listen("tcp", "127.0.0.1:0").expect("listen");
    let port = lis.addr().map(|a| a.to_string()).unwrap_or_default();
    let port = port.rsplit(':').next().unwrap_or("0").to_string();
    println!("PORT {port}");
    let mode = mode.to_string();
    let s = server.clone();
    std::thread::spawn(move || match mode.as_str() {
        "http" => {
            s.handle_http(rpc::DEFAULT_RPC_PATH, rpc::DEFAULT_DEBUG_PATH);
            let _ = rust_stdlib::net::http::serve(lis, None);
        }
        "json" => loop {
            let Ok(conn) = lis.accept() else { return };
            let s = s.clone();
            std::thread::spawn(move || s.serve_codec(jsonrpc::JsonServerCodec::new(conn)));
        },
        _ => s.accept(&*lis),
    });
    let mut sink = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut sink);
}

fn report<T: std::fmt::Debug>(
    name: &str,
    v: Option<T>,
    r: Result<(), rpc::Error>,
    show: impl Fn(&T) -> String,
) {
    match r {
        Ok(()) => println!("{name}: ok {}", v.map(|v| show(&v)).unwrap_or_default()),
        Err(e) => match e.as_server_error() {
            Some(se) => println!("{name}: servererror {}", quote(se.error())),
            None => println!("{name}: error {}", quote(&e.to_string())),
        },
    }
}

fn quote(s: &str) -> String {
    rust_stdlib::strconv::quote(s)
}

fn client(mode: &str, port: &str) {
    let addr = format!("127.0.0.1:{port}");
    let c = match mode {
        "http" => rpc::dial_http("tcp", &addr),
        "json" => jsonrpc::dial("tcp", &addr),
        _ => rpc::dial("tcp", &addr),
    };
    let c = match c {
        Ok(c) => c,
        Err(e) => {
            println!("dial error: {e}");
            std::process::exit(1);
        }
    };
    let mut r = Reply::default();
    let c_of = |r: &Reply| r.C.to_string();
    let res = c.call("Arith.Add", &Args { A: 7, B: 8 }, &mut r);
    report("add", Some(r.clone()), res, c_of);
    let res = c.call("Arith.Mul", &Args { A: 7, B: 8 }, &mut r);
    report("mul", Some(r.clone()), res, c_of);
    let mut q = Quotient::default();
    let res = c.call("Arith.Div", &Args { A: 7, B: 2 }, &mut q);
    report("div", Some(q.clone()), res, |q| {
        format!("{{{} {}}}", q.Quo, q.Rem)
    });
    let res = c.call("Arith.Div", &Args { A: 7, B: 0 }, &mut q);
    report::<Reply>("div0", None, res, c_of);
    let res = c.call("Arith.Error", &Args::default(), &mut r);
    report::<Reply>("error", None, res, c_of);
    let res = c.call("Arith.Add", &Args { A: 1, B: 2 }, &mut r);
    report("after-error", Some(r.clone()), res, c_of);
    let res = c.call("Arith.Unknown", &Args::default(), &mut r);
    report::<Reply>("unknown-method", None, res, c_of);
    let res = c.call("Nope.Add", &Args::default(), &mut r);
    report::<Reply>("unknown-service", None, res, c_of);
    let res = c.call("Add", &Args::default(), &mut r);
    report::<Reply>("ill-formed", None, res, c_of);
    let mut m: BTreeMap<String, isize> = BTreeMap::new();
    let res = c.call("Arith.Names", &Args::default(), &mut m);
    report("names", Some(m.clone()), res, |m| {
        format!(
            "map[{}]",
            m.iter()
                .map(|(k, v)| format!("{k}:{v}"))
                .collect::<Vec<_>>()
                .join(" ")
        )
    });
    let mut n = 0isize;
    let res = c.call("Arith.Count", &Args::default(), &mut n);
    report("count", Some(n), res, |n| n.to_string());
    let post = Entry {
        Amount: Money { Cents: 150 },
        Ptr: Some(Money { Cents: 205 }),
        List: vec![Money { Cents: 1 }],
        Map: BTreeMap::from([("a".to_string(), Money { Cents: 300 })]),
        Raw: Verbatim {
            Text: "{\"x\": [1, 2]}".into(),
        },
        Stamp: Some(Stamp { N: 4 }),
        Hidden: Stamp { N: 9 },
        Sealed: BTreeMap::new(),
    };
    // A pointer argument, as the Go client's `post` is, so its fields are addressable.
    let post_ptr = reflect::new(&Entry::reflect_type());
    post_ptr.elem().set(&post.to_value());
    let pr_ptr = reflect::new(&Entry::reflect_type());
    let res = c.call_value("Ledger.Post", &post_ptr, &pr_ptr);
    let pr = Entry::from_value(&pr_ptr.elem()).unwrap_or_default();
    report("post", Some(pr.Amount.Cents), res, |v| v.to_string());
    let ptr = pr.Ptr.as_ref().map_or(-1, |m| m.Cents);
    let first = pr.List.first().map_or(-1, |m| m.Cents);
    let stamp = pr.Stamp.as_ref().map_or(-1, |s| s.N);
    let map_a = pr.Map.get("a").map_or(0, |m| m.Cents);
    println!(
        "post-fields: ptr={ptr} list={first} map={map_a} raw={} stamp={stamp} hidden={}",
        quote(&pr.Raw.Text),
        pr.Hidden.N
    );
    let mut fa = Faulty::default();
    let res = c.call("Ledger.Faulty", &Faulty { Code: 1 }, &mut fa);
    report("faulty", Some(fa.Code), res, |v| v.to_string());
    let mut br = Broken::default();
    let res = c.call("Ledger.Broken", &Broken { Code: 2 }, &mut br);
    report("broken", Some(br.Code), res, |v| v.to_string());
    let labels = Labels {
        Tier: Tier::T2,
        TierPtr: Some(Tier::T3),
        Tiers: vec![Tier::T0, Tier::T1],
        ByTier: BTreeMap::from([
            (Tier::T3, "three".to_string()),
            (Tier::T1, "one<&>".to_string()),
        ]),
        ByRegion: BTreeMap::from([(Region("north".into()), 1), (Region("south".into()), 2)]),
        Code: Code { N: 4 },
        Codes: vec![Code { N: 5 }],
        Mixed: vec![Mixed { N: 7 }],
        MixedMap: BTreeMap::new(),
    };
    // A pointer argument, as the Go client's `labels` is, so its fields are addressable.
    let labels_ptr = reflect::new(&Labels::reflect_type());
    labels_ptr.elem().set(&labels.to_value());
    let lb_ptr = reflect::new(&Labels::reflect_type());
    let res = c.call_value("Ledger.Labels", &labels_ptr, &lb_ptr);
    let ok = res.is_ok();
    report("labels", Some(()), res, |_| "<nil>".to_string());
    if ok {
        let lb = Labels::from_value(&lb_ptr.elem()).unwrap_or_default();
        let ptr = lb.TierPtr.map_or(-1, |t| t as isize);
        println!(
            "labels-fields: tier={} ptr={ptr} tiers={},{} bytier={} {} {} region={},{} code={} codes={} mixed={} mixedmap={}",
            lb.Tier as isize,
            lb.Tiers[0] as isize,
            lb.Tiers[1] as isize,
            lb.ByTier.len(),
            quote(&lb.ByTier[&Tier::T3]),
            quote(&lb.ByTier[&Tier::T1]),
            lb.ByRegion[&Region("north".into())],
            lb.ByRegion[&Region("south".into())],
            lb.Code.N,
            lb.Codes[0].N,
            lb.Mixed.len(),
            lb.MixedMap.len()
        );
    }
    let mut tn = Torns::default();
    let res = c.call(
        "Ledger.Torns",
        &Torns {
            One: Torn { N: -1 },
            Keys: BTreeMap::new(),
        },
        &mut tn,
    );
    report("torn-value", Some(()), res, |_| "<nil>".to_string());
    let res = c.call(
        "Ledger.Torns",
        &Torns {
            One: Torn { N: 1 },
            Keys: BTreeMap::from([(Torn { N: -2 }, 1)]),
        },
        &mut tn,
    );
    report("torn-key", Some(()), res, |_| "<nil>".to_string());
    let res = c.call(
        "Ledger.Torns",
        &Torns {
            One: Torn { N: 1 },
            Keys: BTreeMap::from([(Torn { N: 2 }, 3)]),
        },
        &mut tn,
    );
    let ok = res.is_ok();
    report("torns", Some(()), res, |_| "<nil>".to_string());
    if ok {
        println!(
            "torns-fields: one={} key2={} keys={}",
            tn.One.N,
            tn.Keys[&Torn { N: 2 }],
            tn.Keys.len()
        );
    }

    if mode == "json" {
        // A pointer-only MarshalText key fails when the request is written,
        // with the offset and path of jsontext's error.
        let mut pk = PKeys::default();
        let res = c.call(
            "Ledger.PKeys",
            &PKeys {
                Pad: 1,
                M: BTreeMap::from([(PKey { N: 1 }, 2)]),
                Deep: Vec::new(),
            },
            &mut pk,
        );
        report("pkeys", Some(()), res, |_| "<nil>".to_string());
        let res = c.call(
            "Ledger.PKeys",
            &PKeys {
                Pad: 0,
                M: BTreeMap::new(),
                Deep: vec![
                    PKeysDeep::default(),
                    PKeysDeep {
                        M: BTreeMap::from([(PKey { N: 1 }, 2)]),
                    },
                ],
            },
            &mut pk,
        );
        report("pkeys-deep", Some(()), res, |_| "<nil>".to_string());
        let res = c.call("Ledger.PKeys", &PKeys::default(), &mut pk);
        report("pkeys-empty", Some(()), res, |_| "<nil>".to_string());
    }

    let c = Arc::new(c);
    let handles: Vec<_> = (0..20isize)
        .map(|i| {
            let c = c.clone();
            std::thread::spawn(move || {
                let mut rr = Reply::default();
                match c.call("Arith.Mul", &Args { A: i, B: 3 }, &mut rr) {
                    Ok(()) => rr.C,
                    Err(_) => -1,
                }
            })
        })
        .collect();
    let results: Vec<String> = handles
        .into_iter()
        .map(|h| h.join().unwrap().to_string())
        .collect();
    println!("concurrent: [{}]", results.join(" "));

    let t0 = Instant::now();
    let (tx, rx) = mpsc::sync_channel(2);
    let mk = || {
        c.call_async(
            "Arith.Sleep",
            Args { A: 150, B: 0 }.to_value(),
            reflect::new(&Reply::reflect_type()),
            Some(tx.clone()),
        )
    };
    let (d1, d2) = (mk(), mk());
    rx.recv().unwrap();
    rx.recv().unwrap();
    let c1 = Reply::from_value(&d1.reply.elem()).unwrap().C;
    let c2 = Reply::from_value(&d2.reply.elem()).unwrap().C;
    let none = |c: &Arc<rpc::Call>| c.error().map(|e| e.to_string()).unwrap_or("<nil>".into());
    println!(
        "async: {c1} {c2} {} {} {}",
        none(&d1),
        none(&d2),
        t0.elapsed() < Duration::from_millis(280)
    );

    println!(
        "close: {}",
        c.close()
            .map(|_| "<nil>".to_string())
            .unwrap_or_else(|e| e.to_string())
    );
    println!(
        "close-again: {}",
        c.close()
            .map(|_| "<nil>".to_string())
            .unwrap_or_else(|e| e.to_string())
    );
    let res = c.call("Arith.Add", &Args { A: 1, B: 2 }, &mut r);
    report::<Reply>("after-close", None, res, c_of);
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a[1].as_str() {
        "server" => serve(&a[2]),
        "client" => client(&a[2], &a[3]),
        other => panic!("unknown mode {other}"),
    }
}
