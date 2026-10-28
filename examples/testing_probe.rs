//! Rust side of `tools/testing_check.py`; mirrors `tools/testing_oracle.go`.
//!
//! `ORACLE_MODE` selects the mode and `ORACLE_INPUT` names the JSON scenario
//! file. The "tests" and "bench" modes run a test binary through
//! `testing::main_start`, so `-test.*` flags select verbose output and
//! benchmark settings exactly as for Go; the other modes print one line per
//! scenario.
#![allow(clippy::collapsible_match)]
use std::{
    collections::BTreeMap,
    fmt::Display,
    io::{self, Read, Write},
    sync::{Arc, Mutex},
};

use rust_stdlib::{
    encoding::json::{self, Value as J},
    io::fs::{
        self, DirEntry, File, FileInfo, FileMode, GlobFS, MapFS, MapFile, ReadDirFS, ReadDirFile,
        ReadFileFS, FS,
    },
    log::slog::{self, Handler, HandlerOptions, JSONHandler},
    strconv,
    testing::{
        self,
        fstest::test_fs,
        iotest,
        quick::{self, Generator},
        slogtest, synctest, InternalBenchmark, InternalTest, RegexpDeps, B, T, TB,
    },
};

// ----------------------------------------------------------------- JSON

fn load() -> J {
    let path = std::env::var("ORACLE_INPUT").expect("ORACLE_INPUT");
    let text = std::fs::read_to_string(path).expect("scenario file");
    text.parse::<json::Value>().expect("scenario JSON")
}

fn s(v: &J, key: &str) -> String {
    v.get(key).and_then(J::as_str).unwrap_or("").to_string()
}

fn num(v: &J, key: &str) -> f64 {
    v.get(key)
        .and_then(J::as_number)
        .and_then(|n| n.to_string().parse().ok())
        .unwrap_or(0.0)
}

fn int(v: &J, key: &str) -> i64 {
    v.get(key)
        .and_then(J::as_number)
        .and_then(|n| n.to_string().parse::<i64>().ok())
        .unwrap_or(0)
}

fn list<'a>(v: &'a J, key: &str) -> &'a [J] {
    v.get(key).and_then(J::as_array).unwrap_or(&[])
}

fn strings(v: &J, key: &str) -> Vec<String> {
    list(v, key)
        .iter()
        .map(|x| x.as_str().unwrap_or("").to_string())
        .collect()
}

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn go_quote(s: &str) -> String {
    strconv::quote(s)
}

// ------------------------------------------------------------- test ops

#[derive(Clone)]
struct Op {
    op: String,
    args: Vec<String>,
    msg: String,
    name: String,
    ops: Arc<Vec<Op>>,
    text: String,
    key: String,
    value: String,
    n: i64,
    f: f64,
}

fn parse_ops(v: &[J]) -> Arc<Vec<Op>> {
    Arc::new(
        v.iter()
            .map(|o| Op {
                op: s(o, "op"),
                args: strings(o, "args"),
                msg: s(o, "msg"),
                name: s(o, "name"),
                ops: parse_ops(list(o, "ops")),
                text: s(o, "text"),
                key: s(o, "key"),
                value: s(o, "value"),
                n: int(o, "n"),
                f: num(o, "f"),
            })
            .collect(),
    )
}

fn displays(args: &[String]) -> Vec<&dyn Display> {
    args.iter().map(|a| a as &dyn Display).collect()
}

fn run_test_ops(t: &T, ops: &Arc<Vec<Op>>) {
    for op in ops.iter() {
        match op.op.as_str() {
            "log" => t.log(&displays(&op.args)),
            "logf" => t.logf(format_args!("{}", op.msg)),
            "error" => t.error(&displays(&op.args)),
            "errorf" => t.errorf(format_args!("{}", op.msg)),
            "fatal" => t.fatal(&displays(&op.args)),
            "fatalf" => t.fatalf(format_args!("{}", op.msg)),
            "skip" => t.skip(&displays(&op.args)),
            "skipf" => t.skipf(format_args!("{}", op.msg)),
            "skipnow" => t.skip_now(),
            "fail" => t.fail(),
            "failnow" => t.fail_now(),
            "sub" => {
                t.run(&op.name, |t| run_test_ops(t, &op.ops));
            }
            "psub" => {
                let ops = op.ops.clone();
                t.run_static(&op.name, move |t| {
                    t.parallel();
                    run_test_ops(t, &ops);
                });
            }
            "cleanup" => {
                let tt = t.clone();
                let ops = op.ops.clone();
                t.cleanup(move || run_test_ops(&tt, &ops));
            }
            "write" => {
                let _ = t.output().write_all(op.text.as_bytes());
            }
            "attr" => t.attr(&op.key, &op.value),
            "name" => t.log(&[&t.name()]),
            "failed" => t.logf(format_args!(
                "failed={} skipped={}",
                t.failed(),
                t.skipped()
            )),
            other => panic!("unknown op {other}"),
        }
    }
}

fn run_bench_ops(b: &mut B, ops: &Arc<Vec<Op>>) {
    for _ in 0..b.n {}
    for op in ops.iter() {
        match op.op.as_str() {
            "log" => b.log(&displays(&op.args)),
            "logf" => b.logf(format_args!("{}", op.msg)),
            "error" => b.error(&displays(&op.args)),
            "fatal" => b.fatal(&displays(&op.args)),
            "skip" => b.skip(&displays(&op.args)),
            "skipnow" => b.skip_now(),
            "fail" => b.fail(),
            "failnow" => b.fail_now(),
            "sub" => {
                b.run(&op.name, |b| run_bench_ops(b, &op.ops));
            }
            "metric" => b.report_metric(op.f, &op.key),
            "bytes" => b.set_bytes(op.n),
            "write" => {
                let _ = b.output().write_all(op.text.as_bytes());
            }
            "name" => {
                let n = b.name();
                b.log(&[&n]);
            }
            other => panic!("unknown op {other}"),
        }
    }
}

fn exit_with(code: i32) -> ! {
    let _ = io::stdout().flush();
    std::process::exit(code)
}

// ---------------------------------------------------------------- result

fn run_result() {
    let cases = load();
    for c in cases.as_array().unwrap() {
        let mut r = testing::BenchmarkResult {
            n: int(c, "n") as usize,
            t: (std::time::Duration::from_nanos(int(c, "t") as u64)).into(),
            bytes: int(c, "bytes"),
            mem_allocs: int(c, "mem_allocs") as u64,
            mem_bytes: int(c, "mem_bytes") as u64,
            extra: BTreeMap::new(),
        };
        if let Some(J::Object(o)) = c.get("extra") {
            for (k, v) in o {
                let f: f64 = v.as_number().unwrap().to_string().parse().unwrap();
                r.extra.insert(k.clone(), f);
            }
        }
        println!(
            "{}|{}|{}|{}|{}",
            go_quote(&r.to_string()),
            go_quote(&r.mem_string()),
            r.ns_per_op(),
            r.allocs_per_op(),
            r.alloced_bytes_per_op()
        );
    }
}

// ---------------------------------------------------------------- iotest

struct ErrAfter<R> {
    r: R,
}

impl<R: Read> Read for ErrAfter<R> {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        match self.r.read(p) {
            Ok(0) if !p.is_empty() => Err(io::Error::other("tail error")),
            other => other,
        }
    }
}

fn err_string(e: &io::Error) -> String {
    if rust_stdlib::io::is_eof(e) {
        "EOF".to_string()
    } else {
        format!("E:{e}")
    }
}

fn run_iotest() {
    let cases = load();
    for c in cases.as_array().unwrap() {
        let data = from_hex(&s(c, "data"));
        let mut r: Box<dyn Read> = Box::new(io::Cursor::new(data));
        for w in strings(c, "wrap") {
            r = match w.as_str() {
                "onebyte" => Box::new(iotest::one_byte_reader(r)),
                "half" => Box::new(iotest::half_reader(r)),
                "dataerr" => Box::new(iotest::data_err_reader(r)),
                "timeout" => Box::new(iotest::timeout_reader(r)),
                "errtail" => Box::new(ErrAfter { r }),
                "err" => Box::new(iotest::err_reader(io::Error::other("boom"))),
                _ => r,
            };
        }
        let reads: Vec<usize> = list(c, "reads")
            .iter()
            .map(|x| x.as_number().unwrap().to_string().parse().unwrap())
            .collect();
        let mut out = Vec::new();
        for &n in &reads {
            let mut buf = vec![0u8; n];
            match r.read(&mut buf) {
                Ok(0) if n > 0 => out.push("0::EOF".to_string()),
                Ok(got) => out.push(format!("{got}:{}:nil", to_hex(&buf[..got]))),
                Err(e) => out.push(format!("0::{}", err_string(&e))),
            }
        }
        let at = int(c, "err_at");
        let mut sink: Vec<u8> = Vec::new();
        let mut wl = Vec::new();
        {
            let mut tw = iotest::truncate_writer(&mut sink, at);
            for &n in &reads {
                let chunk = vec![b'x'; n];
                match tw.write(&chunk) {
                    Ok(wn) => wl.push(format!("{wn}:nil")),
                    Err(e) => wl.push(format!("0:{}", err_string(&e))),
                }
            }
        }
        println!("{}|{}|{}", out.join(","), wl.join(","), to_hex(&sink));
    }
}

// A reader that misbehaves as selected by `kind`.
struct Broken {
    kind: String,
    content: Vec<u8>,
    off: i64,
    seek: bool,
    at: bool,
}

impl Read for Broken {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        if p.is_empty() {
            return Ok(if self.kind == "read0" { 1 } else { 0 });
        }
        if self.off >= self.content.len() as i64 {
            if self.kind == "noeof" {
                return Ok(1);
            }
            return Ok(0);
        }
        let src = &self.content[self.off as usize..];
        let n = p.len().min(src.len());
        p[..n].copy_from_slice(&src[..n]);
        if self.kind == "shortcorrupt" && self.off == 0 {
            p[0] ^= 0xff;
        }
        self.off += n as i64;
        if self.kind == "readerr" && self.off > 3 {
            // Go returns (n, err); Rust cannot, so the data is dropped: the
            // scenario only compares the reported error text.
            return Err(io::Error::other("synthetic failure"));
        }
        Ok(n)
    }
}

impl io::Seek for Broken {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let mut offset = match pos {
            io::SeekFrom::Start(o) => o as i64,
            io::SeekFrom::Current(o) => o + self.off,
            io::SeekFrom::End(o) => o + self.content.len() as i64,
        };
        if self.kind == "seekoff" {
            offset += 1;
        }
        if offset < 0 || offset > self.content.len() as i64 {
            return Err(io::Error::other("bad seek"));
        }
        self.off = offset;
        Ok(offset as u64)
    }
}

impl rust_stdlib::io::ReadAt for Broken {
    fn read_at(&self, p: &mut [u8], off: u64) -> Result<usize, rust_stdlib::io::ReadError> {
        use rust_stdlib::io::ReadError;
        // Offsets above i64::MAX are Go's negative ones.
        if off > self.content.len() as u64 {
            return Err(ReadError::new(0, io::Error::other("bad readat")));
        }
        let src = &self.content[off as usize..];
        let mut n = p.len().min(src.len());
        p[..n].copy_from_slice(&src[..n]);
        if self.kind == "readatshort" && n > 0 {
            n -= 1;
        }
        if self.kind == "readatnoeof" {
            return Ok(n);
        }
        if n < p.len() {
            return Err(ReadError::new(n, rust_stdlib::io::eof()));
        }
        Ok(n)
    }
}

impl iotest::TestableReader for Broken {
    fn as_seek(&mut self) -> Option<&mut dyn io::Seek> {
        self.seek.then_some(self as &mut dyn io::Seek)
    }
    fn as_read_at(&self) -> Option<&dyn rust_stdlib::io::ReadAt> {
        self.at.then_some(self as &dyn rust_stdlib::io::ReadAt)
    }
}

fn run_testreader() {
    let cases = load();
    for c in cases.as_array().unwrap() {
        let content = from_hex(&s(c, "content"));
        let kind = s(c, "kind");
        let res = match s(c, "caps").as_str() {
            "bytes" => iotest::test_reader(&mut rust_stdlib::text::Reader::new(&content), &content),
            "strings" => {
                let text = String::from_utf8_lossy(&content).into_owned();
                if text.as_bytes() == content.as_slice() {
                    iotest::test_reader(&mut rust_stdlib::text::Reader::new(&text), &content)
                } else {
                    // Not valid UTF-8: Go's strings.Reader would hold the raw bytes.
                    Ok(())
                }
            }
            caps => {
                let mut b = Broken {
                    kind,
                    content: content.clone(),
                    off: 0,
                    seek: caps != "plain",
                    at: caps == "seekat",
                };
                iotest::test_reader(&mut b, &content)
            }
        };
        match res {
            Ok(()) => println!("nil"),
            Err(e) => println!("{}", go_quote(&e.to_string())),
        }
    }
}

// ---------------------------------------------------------------- fstest

#[derive(Debug)]
struct Corrupt {
    m: MapFS,
    kind: String,
    opens: Mutex<BTreeMap<String, usize>>,
}

#[derive(Debug)]
struct SizeInfo(Box<dyn FileInfo>);

impl FileInfo for SizeInfo {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn size(&self) -> i64 {
        self.0.size() + 1
    }
    fn mode(&self) -> FileMode {
        self.0.mode()
    }
    fn mod_time(&self) -> rust_stdlib::time::Time {
        self.0.mod_time()
    }
}

#[derive(Debug)]
struct Renamed(Box<dyn DirEntry>, String);

impl DirEntry for Renamed {
    fn name(&self) -> &str {
        &self.1
    }
    fn is_dir(&self) -> bool {
        self.0.is_dir()
    }
    fn file_type(&self) -> FileMode {
        self.0.file_type()
    }
    fn info(&self) -> io::Result<Box<dyn FileInfo>> {
        self.0.info()
    }
}

struct BadFile {
    inner: Box<dyn File>,
    c: Arc<Corrupt>,
    name: String,
}

impl std::fmt::Debug for BadFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BadFile {{ {} }}", self.name)
    }
}

impl Read for BadFile {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        self.inner.read(p)
    }
}

impl File for BadFile {
    fn stat(&self) -> io::Result<Box<dyn FileInfo>> {
        let info = self.inner.stat()?;
        if self.c.kind == "wrongsize" && !info.is_dir() {
            return Ok(Box::new(SizeInfo(info)));
        }
        Ok(info)
    }
    fn close(&mut self) -> io::Result<()> {
        self.inner.close()
    }
    fn as_read_dir_file(&mut self) -> Option<&mut dyn ReadDirFile> {
        // Go's wrapper has a ReadDir method on every file.
        Some(self)
    }
}

impl ReadDirFile for BadFile {
    fn read_dir(&mut self, n: i32) -> Result<Vec<Box<dyn DirEntry>>, fs::ReadDirError> {
        let Some(rd) = self.inner.as_read_dir_file() else {
            return Err(io::Error::other("not a directory").into());
        };
        let mut list = rd.read_dir(n)?;
        match self.c.kind.as_str() {
            "dropentry" => {
                if list.len() > 1 && n <= 0 {
                    let mut opens = self.c.opens.lock().unwrap();
                    let k = opens.entry(self.name.clone()).or_insert(0);
                    *k += 1;
                    if *k == 2 {
                        list.remove(0);
                    }
                }
            }
            "dupentry" => {
                if !list.is_empty() && n <= 0 {
                    let first = &list[0];
                    let dup = Copy(
                        first.name().to_string(),
                        first.is_dir(),
                        first.file_type(),
                        first.info().unwrap(),
                    );
                    list.push(Box::new(dup));
                }
            }
            "badname" => {
                if !list.is_empty() && n <= 0 {
                    let first = list.remove(0);
                    let nn = format!("{}x", first.name());
                    list.insert(0, Box::new(Renamed(first, nn)));
                }
            }
            _ => {}
        }
        Ok(list)
    }
}

/// A copy of a directory entry (an `fs.DirEntry` is a shared interface value in Go).
#[derive(Debug)]
struct Copy(String, bool, FileMode, Box<dyn FileInfo>);

impl DirEntry for Copy {
    fn name(&self) -> &str {
        &self.0
    }
    fn is_dir(&self) -> bool {
        self.1
    }
    fn file_type(&self) -> FileMode {
        self.2
    }
    fn info(&self) -> io::Result<Box<dyn FileInfo>> {
        Ok(Box::new(Snapshot {
            name: self.3.name().to_string(),
            size: self.3.size(),
            mode: self.3.mode(),
            mod_time: self.3.mod_time(),
        }))
    }
}

#[derive(Debug)]
struct Snapshot {
    name: String,
    size: i64,
    mode: FileMode,
    mod_time: rust_stdlib::time::Time,
}

impl FileInfo for Snapshot {
    fn name(&self) -> &str {
        &self.name
    }
    fn size(&self) -> i64 {
        self.size
    }
    fn mode(&self) -> FileMode {
        self.mode
    }
    fn mod_time(&self) -> rust_stdlib::time::Time {
        self.mod_time.clone()
    }
}

#[derive(Debug)]
struct CorruptFS(Arc<Corrupt>);

impl FS for CorruptFS {
    fn open(&self, name: &str) -> io::Result<Box<dyn File>> {
        let f = self.0.m.open(name)?;
        Ok(Box::new(BadFile {
            inner: f,
            c: self.0.clone(),
            name: name.to_string(),
        }))
    }
    fn as_read_file_fs(&self) -> Option<&dyn ReadFileFS> {
        Some(self)
    }
    fn as_read_dir_fs(&self) -> Option<&dyn ReadDirFS> {
        Some(self)
    }
    fn as_glob_fs(&self) -> Option<&dyn GlobFS> {
        Some(self)
    }
}

impl ReadFileFS for CorruptFS {
    fn read_file(&self, name: &str) -> io::Result<Vec<u8>> {
        let mut data = fs::read_file(&self.0.m, name)?;
        if self.0.kind == "readfile" && !data.is_empty() {
            data[0] ^= 1;
        }
        Ok(data)
    }
}

impl ReadDirFS for CorruptFS {
    fn read_dir(&self, name: &str) -> Result<Vec<Box<dyn DirEntry>>, fs::ReadDirError> {
        let mut list = fs::read_dir(&self.0.m, name)?;
        if self.0.kind == "unsorted" && list.len() > 1 {
            list.swap(0, 1);
        }
        Ok(list)
    }
}

impl GlobFS for CorruptFS {
    fn glob(&self, pattern: &str) -> io::Result<Vec<String>> {
        let result = fs::glob(&self.0.m, pattern);
        if self.0.kind == "globnoerr" && pattern.contains("[]") {
            return Ok(Vec::new());
        }
        let mut names = result?;
        if self.0.kind == "badglob" && !names.is_empty() {
            let x = format!("{}x", names[0]);
            names.push(x);
        }
        Ok(names)
    }
}

#[derive(Debug)]
struct PlainOpenFS(Arc<Corrupt>);

impl FS for PlainOpenFS {
    fn open(&self, name: &str) -> io::Result<Box<dyn File>> {
        if let Some(rest) = name.strip_prefix('/') {
            return self.0.m.open(rest);
        }
        CorruptFS(self.0.clone()).open(name)
    }
}

fn build_map(files: &[J]) -> MapFS {
    let mut m = MapFS::new();
    for f in files {
        let data = from_hex(&s(f, "data"));
        let mut mode = f
            .get("mode")
            .and_then(J::as_number)
            .map_or(0, |n| n.to_string().parse::<u32>().unwrap());
        if f.get("dir").is_some_and(|v| matches!(v, J::Bool(true))) {
            mode |= fs::MODE_DIR.0;
        }
        if f.get("link").is_some_and(|v| matches!(v, J::Bool(true))) {
            mode |= fs::MODE_SYMLINK.0;
        }
        m.insert(s(f, "name"), MapFile::new(data, FileMode(mode)));
    }
    m
}

fn normalize_fs_err(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("File type ") {
        out.push_str(&rest[..i]);
        out.push_str("File type T,");
        let after = &rest[i + "File type ".len()..];
        match after.find(',') {
            Some(j) => rest = &after[j + 1..],
            None => {
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

fn run_fstest() {
    let cases = load();
    for c in cases.as_array().unwrap() {
        let m = build_map(list(c, "files"));
        let kind = s(c, "corrupt");
        let expected = strings(c, "expected");
        let exp: Vec<&str> = expected.iter().map(String::as_str).collect();
        let corrupt = Arc::new(Corrupt {
            m: m.clone(),
            kind: kind.clone(),
            opens: Mutex::new(BTreeMap::new()),
        });
        let res = match kind.as_str() {
            "none" => test_fs(&m, &exp),
            "openbad" => test_fs(&PlainOpenFS(corrupt), &exp),
            _ => test_fs(&CorruptFS(corrupt), &exp),
        };
        match res {
            Ok(()) => println!("nil"),
            Err(e) => println!("{}", go_quote(&normalize_fs_err(&e.to_string()))),
        }
    }
}

// ----------------------------------------------------------------- quick

trait Fmt {
    fn fmt_val(&self) -> String;
}

macro_rules! fmt_int {
    ($($t:ty => $n:expr),+) => {$(
        impl Fmt for $t {
            fn fmt_val(&self) -> String { format!("{}:{}", $n, self) }
        }
    )+};
}
fmt_int!(i8 => "int8", i16 => "int16", i32 => "int32", i64 => "int64", u8 => "uint8",
    u16 => "uint16", u32 => "uint32", u64 => "uint64");

impl Fmt for bool {
    fn fmt_val(&self) -> String {
        format!("bool:{self}")
    }
}
impl Fmt for f32 {
    fn fmt_val(&self) -> String {
        format!("f32:{:08x}", self.to_bits())
    }
}
impl Fmt for f64 {
    fn fmt_val(&self) -> String {
        format!("f64:{:016x}", self.to_bits())
    }
}
impl Fmt for String {
    fn fmt_val(&self) -> String {
        format!("s:{}", to_hex(self.as_bytes()))
    }
}
impl<T: Fmt> Fmt for Vec<T> {
    fn fmt_val(&self) -> String {
        format!(
            "[{}]",
            self.iter().map(Fmt::fmt_val).collect::<Vec<_>>().join(",")
        )
    }
}
impl<T: Fmt, const N: usize> Fmt for [T; N] {
    fn fmt_val(&self) -> String {
        format!(
            "[{}]",
            self.iter().map(Fmt::fmt_val).collect::<Vec<_>>().join(",")
        )
    }
}
impl<T: Fmt> Fmt for Option<T> {
    fn fmt_val(&self) -> String {
        match self {
            None => "nil".to_string(),
            Some(v) => format!("&{}", v.fmt_val()),
        }
    }
}
impl<K: Fmt, V: Fmt> Fmt for BTreeMap<K, V> {
    fn fmt_val(&self) -> String {
        let mut parts: Vec<String> = self
            .iter()
            .map(|(k, v)| format!("{}={}", k.fmt_val(), v.fmt_val()))
            .collect();
        parts.sort();
        format!("{{{}}}", parts.join(","))
    }
}

/// `struct { A int8; B string; C []bool }` generated like a Go struct: the
/// size hint is divided among the fields.
struct Tuple3(i8, String, Vec<bool>);

impl Generator for Tuple3 {
    fn generate(rand: &mut quick::Rand, size: usize) -> Self {
        let n = 3;
        let size_left = if n > size { 1 } else { size / n };
        Tuple3(
            i8::generate(rand, size_left),
            String::generate(rand, size_left),
            Vec::<bool>::generate(rand, size_left),
        )
    }
}

impl Fmt for Tuple3 {
    fn fmt_val(&self) -> String {
        // Go formats a struct with %T:%v; the harness prints the fields.
        [self.0.fmt_val(), self.1.fmt_val(), self.2.fmt_val()].join(",")
    }
}

fn gen_kind(kind: &str, r: &mut quick::Rand) -> String {
    macro_rules! g {
        ($t:ty) => {
            quick::value::<$t>(r).fmt_val()
        };
    }
    match kind {
        "int8" => g!(i8),
        "int16" => g!(i16),
        "int32" => g!(i32),
        "int64" => g!(i64).replacen("int64:", "int64:", 1),
        "int" => g!(i64).replacen("int64:", "int:", 1),
        "uint8" => g!(u8),
        "uint16" => g!(u16),
        "uint32" => g!(u32),
        "uint64" => g!(u64),
        "uint" => g!(u64).replacen("uint64:", "uint:", 1),
        "bool" => g!(bool),
        "float32" => g!(f32),
        "float64" => g!(f64),
        "string" => g!(String),
        "slice_i16" => g!(Vec<i16>),
        "array_u8" => g!([u8; 4]),
        "ptr_i32" => g!(Option<i32>),
        "map_u8_string" => g!(BTreeMap<u8, String>),
        "nested" => g!(Vec<Vec<String>>),
        "tuple3" => {
            let t = quick::value::<Tuple3>(r);
            t.fmt_val()
        }
        other => panic!("unknown kind {other}"),
    }
}

fn err_text(r: Result<(), quick::Error>) -> String {
    match r {
        Ok(()) => "nil".to_string(),
        Err(quick::Error::Check(e)) => format!("check:{}:[{}]", e.count, e.in_.join(" ")),
        Err(quick::Error::CheckEqual(e)) => format!(
            "equal:{}:[{}]:[{}]:[{}]",
            e.check_error.count,
            e.check_error.in_.join(" "),
            e.out1.join(" "),
            e.out2.join(" ")
        ),
        Err(e) => format!("other:{e}"),
    }
}

fn run_quick() {
    let cases = load();
    for c in cases.as_array().unwrap() {
        let kind = s(c, "kind");
        let n = int(c, "n") as usize;
        let mut r = quick::seeded_rand(int(c, "seed"));
        let mut parts = Vec::new();
        let cfg = |r: quick::Rand| quick::Config {
            max_count: n,
            rand: Some(r),
            ..quick::Config::default()
        };
        match kind.as_str() {
            "check_fail_i8" => {
                let mut c = cfg(r);
                parts.push(err_text(quick::check(
                    |x: i8| x != 17 && x != -3,
                    Some(&mut c),
                )));
            }
            "check_ok_i16" => {
                let mut c = cfg(r);
                parts.push(err_text(quick::check(
                    |x: i16, y: i16| i32::from(x) + i32::from(y) == i32::from(y) + i32::from(x),
                    Some(&mut c),
                )));
            }
            "check_fail_bool" => {
                let mut c = cfg(r);
                parts.push(err_text(quick::check(
                    |a: bool, b: bool, c: u8| a || b || c > 3,
                    Some(&mut c),
                )));
            }
            "equal_fail" => {
                let mut c = cfg(r);
                parts.push(err_text(quick::check_equal(
                    |x: i8| x.wrapping_mul(2),
                    |x: i8| if x == 77 { 0 } else { x.wrapping_add(x) },
                    Some(&mut c),
                )));
            }
            "equal_ok" => {
                let mut c = cfg(r);
                parts.push(err_text(quick::check_equal(
                    |x: u16| x & !1,
                    |x: u16| x & 0xfffe,
                    Some(&mut c),
                )));
            }
            _ => {
                for _ in 0..n {
                    parts.push(gen_kind(&kind, &mut r));
                }
            }
        }
        println!("{}", parts.join(";"));
    }
}

// -------------------------------------------------------------- slogtest

fn replace_for(transform: String, key: String, key2: String) -> slog::ReplaceAttr {
    Arc::new(move |groups: &[String], mut a: slog::Attr| {
        match transform.as_str() {
            "drop" => {
                if a.key == key {
                    return slog::Attr::default();
                }
            }
            "rename" => {
                if a.key == key {
                    a.key = key2.clone();
                }
            }
            "setvalue" => {
                if a.key == key {
                    a.value = slog::string_value("zzz");
                }
            }
            "dropgroup" => {
                if !groups.is_empty() {
                    return slog::Attr::default();
                }
            }
            _ => {}
        }
        a
    })
}

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

fn strip_source(s: &str) -> String {
    // Remove " (file:line)" explanations' source positions.
    let mut out = String::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b' ' && i + 1 < b.len() && b[i + 1] == b'(' {
            if let Some(j) = s[i + 2..].find(')') {
                let inner = &s[i + 2..i + 2 + j];
                if !inner.contains(['(', ')']) {
                    if let Some(k) = inner.rfind(':') {
                        if !inner[k + 1..].is_empty()
                            && inner[k + 1..].bytes().all(|c| c.is_ascii_digit())
                        {
                            i += 2 + j + 1;
                            continue;
                        }
                    }
                }
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

fn run_slogtest() {
    let cases = load();
    for c in cases.as_array().unwrap() {
        let buf = Shared(Arc::new(Mutex::new(Vec::new())));
        let opts = HandlerOptions {
            replace_attr: Some(replace_for(s(c, "transform"), s(c, "key"), s(c, "key2"))),
            ..HandlerOptions::default()
        };
        let h: Arc<dyn Handler> = Arc::new(JSONHandler::new(buf.clone(), Some(opts)));
        let b2 = buf.clone();
        let res = slogtest::test_handler(h, move || {
            let text = String::from_utf8(b2.0.lock().unwrap().clone()).unwrap();
            text.lines()
                .filter(|l| !l.is_empty())
                .map(|l| l.parse::<json::Value>().unwrap())
                .collect()
        });
        match res {
            Ok(()) => println!("nil"),
            Err(e) => println!("{}", go_quote(&strip_source(&e.to_string()))),
        }
    }
}

// -------------------------------------------------------------- synctest

#[derive(Clone)]
struct SOp {
    op: String,
    ms: i64,
    ch: usize,
    v: i64,
    ops: Arc<Vec<SOp>>,
    tag: String,
}

fn parse_sops(v: &[J]) -> Arc<Vec<SOp>> {
    Arc::new(
        v.iter()
            .map(|o| SOp {
                op: s(o, "op"),
                ms: int(o, "ms"),
                ch: int(o, "ch") as usize,
                v: int(o, "v"),
                ops: parse_sops(list(o, "ops")),
                tag: s(o, "tag"),
            })
            .collect(),
    )
}

type Trace = Arc<Mutex<Vec<String>>>;

fn elapsed_ms(start: &rust_stdlib::time::Time) -> i64 {
    synctest::now().unix_milli() - start.unix_milli()
}

fn run_sops(
    trace: &Trace,
    start: &rust_stdlib::time::Time,
    chans: &Arc<Vec<synctest::Chan<i64>>>,
    ops: &Arc<Vec<SOp>>,
) {
    for op in ops.iter() {
        match op.op.as_str() {
            "sleep" => {
                synctest::time_sleep((std::time::Duration::from_millis(op.ms as u64)).into())
            }
            "wait" => synctest::wait(),
            "ssleep" => synctest::sleep((std::time::Duration::from_millis(op.ms as u64)).into()),
            "now" => trace
                .lock()
                .unwrap()
                .push(format!("{} now={}", op.tag, elapsed_ms(start))),
            "send" => chans[op.ch].send(op.v),
            "recv" => {
                let v = chans[op.ch].recv().unwrap();
                trace.lock().unwrap().push(format!(
                    "{} recv ch{}={} at {}",
                    op.tag,
                    op.ch,
                    v,
                    elapsed_ms(start)
                ));
            }
            "go" => {
                let (trace, start, chans, ops) =
                    (trace.clone(), start.clone(), chans.clone(), op.ops.clone());
                synctest::spawn(move || run_sops(&trace, &start, &chans, &ops));
            }
            "stamp" => {
                trace
                    .lock()
                    .unwrap()
                    .push(format!("{} stamp {}", op.tag, elapsed_ms(start)))
            }
            other => panic!("unknown op {other}"),
        }
    }
}

fn run_synctest() {
    let cases = load();
    let cases: Vec<Arc<Vec<SOp>>> = cases
        .as_array()
        .unwrap()
        .iter()
        .map(|c| parse_sops(list(c, "ops")))
        .collect();
    let results: Arc<Mutex<Vec<Vec<String>>>> = Arc::new(Mutex::new(vec![Vec::new(); cases.len()]));
    let mut tests = Vec::new();
    for (i, ops) in cases.iter().cloned().enumerate() {
        let results = results.clone();
        tests.push(InternalTest::new(&format!("C{i}"), move |t| {
            let results = results.clone();
            let ops = ops.clone();
            synctest::test(t, move |_t| {
                let start = synctest::now();
                let trace: Trace = Arc::new(Mutex::new(vec![format!(
                    "start {}",
                    "2000-01-01T00:00:00Z"
                )]));
                let chans: Arc<Vec<synctest::Chan<i64>>> =
                    Arc::new((0..4).map(|_| synctest::Chan::new()).collect());
                run_sops(&trace, &start, &chans, &ops);
                results.lock().unwrap()[i] = trace.lock().unwrap().clone();
            });
        }));
    }
    let ok = testing::run_tests(
        |p, s| rust_stdlib::regexp::match_string(p, s).map_err(|e| e.to_string()),
        &tests,
    );
    if !ok {
        println!("FAIL");
    }
    for r in results.lock().unwrap().iter() {
        println!("R:{}", r.join(";"));
    }
}

// ------------------------------------------------------------------ main

fn main() {
    match std::env::var("ORACLE_MODE").unwrap_or_default().as_str() {
        "tests" => {
            let scripts = load();
            let mut tests = Vec::new();
            for sc in scripts.as_array().unwrap() {
                let ops = parse_ops(list(sc, "ops"));
                tests.push(InternalTest::new(&s(sc, "name"), move |t| {
                    run_test_ops(t, &ops)
                }));
            }
            let mut m = testing::main_start(RegexpDeps, tests, Vec::new(), Vec::new(), Vec::new());
            exit_with(m.run());
        }
        "bench" => {
            let scripts = load();
            let mut benches = Vec::new();
            for sc in scripts.as_array().unwrap() {
                let ops = parse_ops(list(sc, "ops"));
                benches.push(InternalBenchmark::new(&s(sc, "name"), move |b| {
                    run_bench_ops(b, &ops)
                }));
            }
            let mut m =
                testing::main_start(RegexpDeps, Vec::new(), benches, Vec::new(), Vec::new());
            exit_with(m.run());
        }
        "result" => run_result(),
        "iotest" => run_iotest(),
        "testreader" => run_testreader(),
        "fstest" => run_fstest(),
        "quick" => run_quick(),
        "slogtest" => run_slogtest(),
        "synctest" => run_synctest(),
        other => {
            eprintln!("unknown ORACLE_MODE {other:?}");
            std::process::exit(2);
        }
    }
}
