//! `F` and the fuzz-target runner (Go's `testing/fuzz.go`).
//!
//! Only the seed corpus mode of Go's `F.Fuzz` is implemented: the entries
//! added with [`F::add`] and the files of `testdata/fuzz/<Name>` run as
//! subtests. Coverage-guided input generation (`go test -fuzz`) needs the
//! compiler's instrumentation and a worker protocol; for that, use the
//! `cargo fuzz` targets under `fuzz/` in this repository.

use std::{fmt, path::Path, sync::Arc, time::Instant};

use super::{
    common::{impl_tb, Common, CommonSpec, TB},
    matcher::MatchFn,
    t::{make_tstate, matcher_or_exit, root_common, t_runner, RunEnv, T},
};

/// A value of one of the types that can be fuzzed: Go's `[]byte`, `string`,
/// `bool`, `byte`, `rune`, `float32`, `float64`, `int*` and `uint*`.
#[derive(Clone, Debug, PartialEq)]
pub enum FuzzValue {
    /// `[]byte`
    Bytes(Vec<u8>),
    /// `string`
    String(String),
    /// `bool`
    Bool(bool),
    /// `float32`
    F32(f32),
    /// `float64`
    F64(f64),
    /// `int`
    Int(isize),
    /// `int8`
    I8(i8),
    /// `int16`
    I16(i16),
    /// `int32` (and `rune`)
    I32(i32),
    /// `int64`
    I64(i64),
    /// `uint`
    Uint(usize),
    /// `uint8` (and `byte`)
    U8(u8),
    /// `uint16`
    U16(u16),
    /// `uint32`
    U32(u32),
    /// `uint64`
    U64(u64),
}

impl FuzzValue {
    /// Go's name of the value's type, as `reflect.Type.String` prints it.
    pub fn type_name(&self) -> &'static str {
        match self {
            FuzzValue::Bytes(_) => "[]uint8",
            FuzzValue::String(_) => "string",
            FuzzValue::Bool(_) => "bool",
            FuzzValue::F32(_) => "float32",
            FuzzValue::F64(_) => "float64",
            FuzzValue::Int(_) => "int",
            FuzzValue::I8(_) => "int8",
            FuzzValue::I16(_) => "int16",
            FuzzValue::I32(_) => "int32",
            FuzzValue::I64(_) => "int64",
            FuzzValue::Uint(_) => "uint",
            FuzzValue::U8(_) => "uint8",
            FuzzValue::U16(_) => "uint16",
            FuzzValue::U32(_) => "uint32",
            FuzzValue::U64(_) => "uint64",
        }
    }
}

/// A Rust type that can be an argument of a fuzz target.
pub trait FuzzType: Sized + Send + 'static {
    /// Go's name for the type.
    const GO_TYPE: &'static str;
    /// Converts to a corpus value.
    fn to_value(self) -> FuzzValue;
    /// Converts from a corpus value of the same type.
    fn from_value(v: &FuzzValue) -> Option<Self>;
}

macro_rules! fuzz_type {
    ($ty:ty, $variant:ident, $go:expr) => {
        impl FuzzType for $ty {
            const GO_TYPE: &'static str = $go;
            fn to_value(self) -> FuzzValue {
                FuzzValue::$variant(self)
            }
            fn from_value(v: &FuzzValue) -> Option<Self> {
                match v {
                    FuzzValue::$variant(x) => Some(x.clone()),
                    _ => None,
                }
            }
        }
    };
}
fuzz_type!(Vec<u8>, Bytes, "[]uint8");
fuzz_type!(String, String, "string");
fuzz_type!(bool, Bool, "bool");
fuzz_type!(f32, F32, "float32");
fuzz_type!(f64, F64, "float64");
fuzz_type!(isize, Int, "int");
fuzz_type!(i8, I8, "int8");
fuzz_type!(i16, I16, "int16");
fuzz_type!(i32, I32, "int32");
fuzz_type!(i64, I64, "int64");
fuzz_type!(usize, Uint, "uint");
fuzz_type!(u8, U8, "uint8");
fuzz_type!(u16, U16, "uint16");
fuzz_type!(u32, U32, "uint32");
fuzz_type!(u64, U64, "uint64");

/// The argument list of a fuzz target: a tuple of [`FuzzType`]s.
pub trait FuzzArgs: Sized + Send + 'static {
    /// Go's type names of the arguments.
    fn types() -> Vec<&'static str>;
    /// Converts to corpus values.
    fn into_values(self) -> Vec<FuzzValue>;
    /// Converts from corpus values; `None` on a count or type mismatch.
    fn from_values(v: &[FuzzValue]) -> Option<Self>;
}

macro_rules! fuzz_args {
    ($($name:ident $idx:tt),+) => {
        impl<$($name: FuzzType),+> FuzzArgs for ($($name,)+) {
            fn types() -> Vec<&'static str> {
                vec![$($name::GO_TYPE),+]
            }
            fn into_values(self) -> Vec<FuzzValue> {
                vec![$(self.$idx.to_value()),+]
            }
            fn from_values(v: &[FuzzValue]) -> Option<Self> {
                let mut it = v.iter();
                let out = ($($name::from_value(it.next()?)?,)+);
                if it.next().is_some() { None } else { Some(out) }
            }
        }
    };
}
fuzz_args!(A 0);
fuzz_args!(A 0, B 1);
fuzz_args!(A 0, B 1, C 2);
fuzz_args!(A 0, B 1, C 2, D 3);
fuzz_args!(A 0, B 1, C 2, D 3, E 4);
fuzz_args!(A 0, B 1, C 2, D 3, E 4, G 5);
fuzz_args!(A 0, B 1, C 2, D 3, E 4, G 5, H 6);
fuzz_args!(A 0, B 1, C 2, D 3, E 4, G 5, H 6, I 7);

struct CorpusEntry {
    path: String,
    values: Vec<FuzzValue>,
}

/// Go's `testing.F`: passed to fuzz tests.
pub struct F {
    pub(crate) c: Common,
    corpus: Vec<CorpusEntry>,
    fuzz_called: bool,
    corpus_dir: String,
}

impl_tb!(F);

impl F {
    /// Go's `Cleanup` with a plain closure.
    pub fn cleanup<G: FnOnce() + Send + 'static>(&self, f: G) {
        self.c.cleanup(Box::new(f));
    }

    pub(crate) fn setenv_impl(&self, key: &str, value: &str) {
        self.c.tb_setenv(key, value);
    }

    pub(crate) fn chdir_impl(&self, dir: &str) {
        self.c.tb_chdir(dir);
    }

    /// Go's `Add`: adds the arguments to the seed corpus. The arguments must
    /// match the fuzz target's.
    pub fn add<A: FuzzArgs>(&mut self, args: A) {
        let path = format!("seed#{}", self.corpus.len());
        self.corpus.push(CorpusEntry {
            path,
            values: args.into_values(),
        });
    }

    /// Go's `Fuzz`: runs the fuzz target `ff` on every entry of the seed
    /// corpus (added with [`add`](F::add) and read from
    /// `testdata/fuzz/<Name>`) as a subtest named `<Name>/<entry>`.
    ///
    /// # Panics
    ///
    /// If called more than once.
    #[track_caller]
    pub fn fuzz<A: FuzzArgs, G: Fn(&T, A)>(&mut self, ff: G) {
        if self.fuzz_called {
            panic!("testing: F.Fuzz called more than once");
        }
        self.fuzz_called = true;
        if self.c.failed() {
            return;
        }
        let types = A::types();
        match read_corpus(&Path::new(&self.corpus_dir).join(&self.c.name), &types) {
            Ok(entries) => self.corpus.extend(entries),
            Err(e) => self.c.tb_fatal(&[&e]),
        }
        let entries = std::mem::take(&mut self.corpus);
        for e in entries {
            let base = e.path.rsplit('/').next().unwrap_or(&e.path).to_string();
            let name = format!("{}/{}", self.c.name, base);
            let (_, ok, _) = self.c.tstate.matcher.full_name(None, &name);
            if !ok {
                continue;
            }
            if self.c.tstate.should_fail_fast() {
                break;
            }
            let Some(args) = A::from_values(&e.values) else {
                self.c.tb_fatal(&[&format!(
                    "mismatched types in corpus entry {}: want {:?}",
                    e.path, types
                )]);
            };
            let child = Common::new(CommonSpec {
                name: name.clone(),
                parent: Some(self.c.clone()),
                level: self.c.level + 1,
                chatty: self.c.chatty.clone(),
                sink: self.c.sink.clone(),
                bench: false,
                tstate: self.c.tstate.clone(),
                module_path: self.c.module_path.clone(),
                import_path: self.c.import_path.clone(),
            });
            if let Some(ch) = &child.chatty {
                ch.updatef(&child.name, &format!("=== RUN   {}\n", child.name));
            }
            let t = T::from_common(child);
            t_runner(&t, |t| ff(t, args));
            t.c.recv_signal();
        }
    }
}

impl fmt::Debug for F {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("F").field("name", &self.c.name).finish()
    }
}

/// A fuzz test function: Go's `func(*testing.F)`.
pub type FuzzFn = Arc<dyn Fn(&mut F) + Send + Sync + 'static>;

/// Go's `testing.InternalFuzzTarget`.
#[derive(Clone)]
pub struct InternalFuzzTarget {
    /// Go's `Name`.
    pub name: String,
    /// Go's `Fn`.
    pub fn_: FuzzFn,
}

impl InternalFuzzTarget {
    /// Builds a fuzz target from a name and function.
    pub fn new(name: &str, f: impl Fn(&mut F) + Send + Sync + 'static) -> InternalFuzzTarget {
        InternalFuzzTarget {
            name: name.to_string(),
            fn_: Arc::new(f),
        }
    }
}

/// Go's `runFuzzTests`: runs the seed corpus of the matching fuzz targets.
pub(crate) fn run_fuzz_tests(
    env: &RunEnv,
    match_fn: &MatchFn,
    targets: &[InternalFuzzTarget],
) -> (bool, bool) {
    let (mut ran, mut ok) = (false, true);
    if targets.is_empty() {
        return (ran, ok);
    }
    let m = matcher_or_exit(match_fn.clone(), &env.run, "-test.run", &env.skip);
    let tstate = make_tstate(env, m);
    for i in 0..env.count {
        if tstate.should_fail_fast() {
            break;
        }
        let root = root_common(env, tstate.clone());
        for ft in targets {
            if tstate.should_fail_fast() {
                break;
            }
            let (test_name, matched, _) = tstate.matcher.full_name(None, &ft.name);
            if !matched {
                continue;
            }
            let c = Common::new(CommonSpec {
                name: test_name,
                parent: Some(root.clone()),
                level: 1,
                chatty: root.chatty.clone(),
                sink: env.sink.clone(),
                bench: false,
                tstate: tstate.clone(),
                module_path: env.module_path.clone(),
                import_path: env.import_path.clone(),
            });
            if let Some(ch) = &c.chatty {
                ch.updatef(&c.name, &format!("=== RUN   {}\n", c.name));
            }
            let t = T::from_common(c.clone());
            let target = ft.fn_.clone();
            t_runner(&t, |_| {
                let mut f = F {
                    c: c.clone(),
                    corpus: Vec::new(),
                    fuzz_called: false,
                    corpus_dir: "testdata/fuzz".to_string(),
                };
                target(&mut f);
                if !f.fuzz_called && !c.skipped() && !c.failed() {
                    c.log_plain("returned without calling F.Fuzz, F.Fail, or F.Skip");
                    c.fail();
                }
            });
            t.c.recv_signal();
            ok = ok && !c.failed();
            ran = ran || c.lock().ran;
        }
        if !ran {
            break;
        }
        let _ = (i, Instant::now());
    }
    (ran, ok)
}

// ----- the "go test fuzz v1" corpus format -----

fn read_corpus(dir: &Path, types: &[&'static str]) -> Result<Vec<CorpusEntry>, String> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("reading seed corpus from testdata: {e}")),
    };
    let mut files: Vec<_> = rd.filter_map(Result::ok).collect();
    files.sort_by_key(|f| f.file_name());
    let mut out = Vec::new();
    let mut errs = Vec::new();
    for f in files {
        if f.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let path = dir.join(f.file_name()).display().to_string();
        let data =
            std::fs::read(f.path()).map_err(|e| format!("failed to read corpus file: {e}"))?;
        match read_corpus_data(&data, types) {
            Ok(values) => out.push(CorpusEntry { path, values }),
            Err(e) => errs.push(format!("{}: {e}", crate::strconv::quote(&path))),
        }
    }
    if errs.is_empty() {
        Ok(out)
    } else {
        Err(errs.join("\n"))
    }
}

fn read_corpus_data(data: &[u8], types: &[&'static str]) -> Result<Vec<FuzzValue>, String> {
    let vals = unmarshal_corpus_file(data).map_err(|e| format!("unmarshal: {e}"))?;
    if vals.len() != types.len() {
        return Err(format!(
            "wrong number of values in corpus file: {}, want {}",
            vals.len(),
            types.len()
        ));
    }
    let got: Vec<&str> = vals.iter().map(FuzzValue::type_name).collect();
    if got != types {
        return Err(format!(
            "mismatched types in corpus file: [{}], want [{}]",
            got.join(" "),
            types.join(" ")
        ));
    }
    Ok(vals)
}

/// Decodes the `go test fuzz v1` corpus encoding.
pub fn unmarshal_corpus_file(b: &[u8]) -> Result<Vec<FuzzValue>, String> {
    if b.is_empty() {
        return Err("cannot unmarshal empty string".to_string());
    }
    let text = String::from_utf8_lossy(b);
    let lines: Vec<&str> = text.split('\n').collect();
    if lines.len() < 2 {
        return Err("must include version and at least one value".to_string());
    }
    let version = lines[0].strip_suffix('\r').unwrap_or(lines[0]);
    if version != "go test fuzz v1" {
        return Err(format!("unknown encoding version: {version}"));
    }
    let mut vals = Vec::new();
    for line in &lines[1..] {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v = parse_corpus_value(line)
            .map_err(|e| format!("malformed line {}: {e}", crate::strconv::quote(line)))?;
        vals.push(v);
    }
    Ok(vals)
}

fn parse_int_literal(val: &str) -> Result<i128, String> {
    let (neg, rest) = match val.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, val.strip_prefix('+').unwrap_or(val)),
    };
    let clean: String = rest.chars().filter(|&c| c != '_').collect();
    let (radix, digits) = if let Some(r) = clean.strip_prefix("0x").or(clean.strip_prefix("0X")) {
        (16, r.to_string())
    } else if let Some(r) = clean.strip_prefix("0b").or(clean.strip_prefix("0B")) {
        (2, r.to_string())
    } else if let Some(r) = clean.strip_prefix("0o").or(clean.strip_prefix("0O")) {
        (8, r.to_string())
    } else if clean.len() > 1 && clean.starts_with('0') {
        (8, clean[1..].to_string())
    } else {
        (10, clean.clone())
    };
    let n = i128::from_str_radix(&digits, radix).map_err(|_| {
        format!(
            "strconv.ParseInt: parsing {}: invalid syntax",
            crate::strconv::quote(val)
        )
    })?;
    Ok(if neg { -n } else { n })
}

fn range_err(val: &str, ty: &str) -> String {
    format!(
        "strconv.Parse{}: parsing {}: value out of range",
        if ty.starts_with('u') { "Uint" } else { "Int" },
        crate::strconv::quote(val)
    )
}

fn parse_corpus_value(line: &str) -> Result<FuzzValue, String> {
    let open = line
        .find('(')
        .ok_or_else(|| "expected call expression".to_string())?;
    if !line.ends_with(')') {
        return Err("expected call expression".to_string());
    }
    let fun = line[..open].trim();
    let arg = line[open + 1..line.len() - 1].trim();
    if fun.starts_with("[]") {
        if fun != "[]byte" {
            return Err("expected []byte".to_string());
        }
        if !(arg.starts_with('"') || arg.starts_with('`')) {
            return Err("string literal required for type []byte".to_string());
        }
        let b = crate::strconv::unquote(arg).map_err(|e| e.to_string())?;
        return Ok(FuzzValue::Bytes(b));
    }
    let typ = match fun {
        "math.Float64frombits" => "float64-bits",
        "math.Float32frombits" => "float32-bits",
        f if f.contains('.') => return Err("invalid selector type".to_string()),
        f => f,
    };
    if typ == "bool" {
        return match arg {
            "true" => Ok(FuzzValue::Bool(true)),
            "false" => Ok(FuzzValue::Bool(false)),
            _ if arg.chars().all(|c| c.is_alphanumeric() || c == '_') => {
                Err("true or false required for type bool".to_string())
            }
            _ => Err("malformed bool".to_string()),
        };
    }
    #[derive(PartialEq)]
    enum Kind {
        Int,
        Float,
        Str,
        Char,
    }
    let (val, kind): (String, Kind) = if arg.starts_with('"') || arg.starts_with('`') {
        (arg.to_string(), Kind::Str)
    } else if arg.starts_with('\'') {
        (arg.to_string(), Kind::Char)
    } else if arg == "NaN" {
        ("NaN".to_string(), Kind::Float)
    } else if arg == "-Inf" || arg == "+Inf" {
        (arg.to_string(), Kind::Float)
    } else if arg.starts_with('-')
        || arg.starts_with('+')
        || arg.starts_with(|c: char| c.is_ascii_digit())
        || arg.starts_with('.')
    {
        if arg.starts_with('+') {
            return Err("unsupported operation on int/float: +".to_string());
        }
        let body = arg.trim_start_matches('-');
        let is_int = body.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !body.contains(['.', 'e', 'E', 'p', 'P'])
            || body.starts_with("0x") && !body.contains(['.', 'p', 'P']);
        (
            arg.to_string(),
            if is_int { Kind::Int } else { Kind::Float },
        )
    } else {
        return Err("literal value required for primitive type".to_string());
    };
    match typ {
        "string" => {
            if kind != Kind::Str {
                return Err("string literal value required for type string".to_string());
            }
            let b = crate::strconv::unquote(&val).map_err(|e| e.to_string())?;
            String::from_utf8(b)
                .map(FuzzValue::String)
                .map_err(|e| e.to_string())
        }
        "byte" | "rune" => {
            if kind == Kind::Int {
                let n = parse_int_literal(&val)?;
                return if typ == "rune" {
                    i32::try_from(n)
                        .map(FuzzValue::I32)
                        .map_err(|_| range_err(&val, "int32"))
                } else {
                    u8::try_from(n)
                        .map(FuzzValue::U8)
                        .map_err(|_| range_err(&val, "uint8"))
                };
            }
            if kind != Kind::Char {
                return Err("character literal required for byte/rune types".to_string());
            }
            if val.len() < 2 {
                return Err("malformed character literal, missing single quotes".to_string());
            }
            let inner = &val.as_bytes()[1..val.len() - 1];
            let (code, _, _) =
                crate::strconv::unquote_char(inner, b'\'').map_err(|e| e.to_string())?;
            if typ == "rune" {
                Ok(FuzzValue::I32(code as i32))
            } else if code >= 256 {
                Err("can only encode single byte to a byte type".to_string())
            } else {
                Ok(FuzzValue::U8(code as u8))
            }
        }
        "int" | "int8" | "int16" | "int32" | "int64" => {
            if kind != Kind::Int {
                return Err("integer literal required for int types".to_string());
            }
            let n = parse_int_literal(&val)?;
            let bad = || range_err(&val, "int");
            Ok(match typ {
                "int" => FuzzValue::Int(isize::try_from(n).map_err(|_| bad())?),
                "int8" => FuzzValue::I8(i8::try_from(n).map_err(|_| bad())?),
                "int16" => FuzzValue::I16(i16::try_from(n).map_err(|_| bad())?),
                "int32" => FuzzValue::I32(i32::try_from(n).map_err(|_| bad())?),
                _ => FuzzValue::I64(i64::try_from(n).map_err(|_| bad())?),
            })
        }
        "uint" | "uint8" | "uint16" | "uint32" | "uint64" => {
            if kind != Kind::Int {
                return Err("integer literal required for uint types".to_string());
            }
            let n = parse_int_literal(&val)?;
            let bad = || range_err(&val, "uint");
            Ok(match typ {
                "uint" => FuzzValue::Uint(usize::try_from(n).map_err(|_| bad())?),
                "uint8" => FuzzValue::U8(u8::try_from(n).map_err(|_| bad())?),
                "uint16" => FuzzValue::U16(u16::try_from(n).map_err(|_| bad())?),
                "uint32" => FuzzValue::U32(u32::try_from(n).map_err(|_| bad())?),
                _ => FuzzValue::U64(u64::try_from(n).map_err(|_| bad())?),
            })
        }
        "float32" | "float64" => {
            if kind != Kind::Float && kind != Kind::Int {
                return Err(format!("float or integer literal required for {typ} type"));
            }
            let s = val.replace('_', "");
            let f: f64 = match s.as_str() {
                "NaN" => f64::NAN,
                "+Inf" => f64::INFINITY,
                "-Inf" => f64::NEG_INFINITY,
                _ => s.parse().map_err(|_| {
                    format!(
                        "strconv.ParseFloat: parsing {}: invalid syntax",
                        crate::strconv::quote(&val)
                    )
                })?,
            };
            Ok(if typ == "float32" {
                FuzzValue::F32(f as f32)
            } else {
                FuzzValue::F64(f)
            })
        }
        "float32-bits" => {
            if kind != Kind::Int {
                return Err("integer literal required for math.Float32frombits type".to_string());
            }
            let n = parse_int_literal(&val)?;
            let bits = u32::try_from(n).map_err(|_| range_err(&val, "uint32"))?;
            Ok(FuzzValue::F32(f32::from_bits(bits)))
        }
        "float64-bits" => {
            if kind == Kind::Str || kind == Kind::Char {
                return Err("integer literal required for math.Float64frombits type".to_string());
            }
            let n = parse_int_literal(&val)?;
            let bits = u64::try_from(n).map_err(|_| range_err(&val, "uint64"))?;
            Ok(FuzzValue::F64(f64::from_bits(bits)))
        }
        _ => Err("expected []byte or primitive type".to_string()),
    }
}

#[allow(dead_code)]
fn _assert_tb(_: &dyn TB) {}
