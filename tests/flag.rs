//! Ports Go's flag/flag_test.go and the package examples. Tests that touch the
//! process-wide command-line set serialise on `GLOBAL` and use unique names.
use rust_stdlib::{
    encoding::{TextMarshaler, TextUnmarshaler},
    flag::{self, BoxError, ErrorHandling, Flag, FlagSet, Getter, Ptr, Value, ValueKind, ERR_HELP},
    time::{self, Duration},
};
use std::{
    error::Error,
    io::{self, Write},
    sync::{Arc, Mutex},
};

static GLOBAL: Mutex<()> = Mutex::new(());

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);
impl Buf {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}
impl Write for Buf {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn quiet(name: &str) -> FlagSet {
    let mut fs = FlagSet::new(name, ErrorHandling::ContinueOnError);
    fs.set_output(io::sink());
    fs
}

fn bool_string(s: &str) -> &str {
    if s == "0" {
        "false"
    } else {
        "true"
    }
}

#[test]
fn everything() {
    let mut fs = quiet("everything");
    fs.bool("test_bool", false, "bool value");
    fs.int("test_int", 0, "int value");
    fs.int64("test_int64", 0, "int64 value");
    fs.uint("test_uint", 0, "uint value");
    fs.uint64("test_uint64", 0, "uint64 value");
    fs.string("test_string", "0", "string value");
    fs.float64("test_float64", 0.0, "float64 value");
    fs.duration(
        "test_duration",
        Duration::from_nanos(0),
        "time.Duration value",
    );
    fs.func("test_func", "func value", |_| Ok(()));
    fs.bool_func("test_boolfunc", "func", |_| Ok(()));

    let check = |fs: &FlagSet, desired: &str, expect_visited: usize, visit_all: bool| {
        let mut seen = 0;
        let mut visitor = |f: &Flag| {
            seen += 1;
            let got = f.value.to_string();
            let ok = got == desired
                || (f.name == "test_bool" && got == bool_string(desired))
                || (f.name == "test_duration" && got == format!("{desired}s"))
                || ((f.name == "test_func" || f.name == "test_boolfunc") && got.is_empty());
            assert!(ok, "bad value {got:?} for {}", f.name);
        };
        if visit_all {
            fs.visit_all(&mut visitor);
        } else {
            fs.visit(&mut visitor);
        }
        assert_eq!(seen, expect_visited);
    };
    check(&fs, "0", 10, true);
    check(&fs, "0", 0, false);
    for (name, value) in [
        ("test_bool", "true"),
        ("test_int", "1"),
        ("test_int64", "1"),
        ("test_uint", "1"),
        ("test_uint64", "1"),
        ("test_string", "1"),
        ("test_float64", "1"),
        ("test_duration", "1s"),
        ("test_func", "1"),
        ("test_boolfunc", ""),
    ] {
        fs.set(name, value).unwrap();
    }
    check(&fs, "1", 10, false);
    let mut names = Vec::new();
    fs.visit(|f| names.push(f.name.clone()));
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted);
}

#[test]
fn get() {
    let mut fs = quiet("get");
    fs.bool("test_bool", true, "bool value");
    fs.int("test_int", 1, "int value");
    fs.int64("test_int64", 2, "int64 value");
    fs.uint("test_uint", 3, "uint value");
    fs.uint64("test_uint64", 4, "uint64 value");
    fs.string("test_string", "5", "string value");
    fs.float64("test_float64", 6.0, "float64 value");
    fs.duration(
        "test_duration",
        Duration::from_nanos(7),
        "time.Duration value",
    );
    let mut count = 0;
    fs.visit_all(|f| {
        let g = f.value.as_getter().expect("value is a Getter").get();
        let ok = match f.name.as_str() {
            "test_bool" => g.downcast_ref::<bool>() == Some(&true),
            "test_int" => g.downcast_ref::<isize>() == Some(&1),
            "test_int64" => g.downcast_ref::<i64>() == Some(&2),
            "test_uint" => g.downcast_ref::<usize>() == Some(&3),
            "test_uint64" => g.downcast_ref::<u64>() == Some(&4),
            "test_string" => g.downcast_ref::<String>().map(String::as_str) == Some("5"),
            "test_float64" => g.downcast_ref::<f64>() == Some(&6.0),
            "test_duration" => g.downcast_ref::<Duration>() == Some(&Duration::from_nanos(7)),
            other => panic!("unexpected flag {other}"),
        };
        assert!(ok, "bad Get for {}", f.name);
        count += 1;
    });
    assert_eq!(count, 8);
}

#[test]
fn usage_called_for_unknown_flag() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let called = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&called);
    let mut fs = quiet("usage");
    fs.usage = Some(Box::new(move |_| seen.store(true, Ordering::SeqCst)));
    assert!(fs.parse(&["-x"]).is_err());
    assert!(called.load(Ordering::SeqCst));
}

fn test_parse(f: &mut FlagSet) {
    assert!(!f.parsed(), "Parsed() = true before Parse");
    let bool_flag = f.bool("bool", false, "bool value");
    let bool2_flag = f.bool("bool2", false, "bool2 value");
    let int_flag = f.int("int", 0, "int value");
    let int64_flag = f.int64("int64", 0, "int64 value");
    let uint_flag = f.uint("uint", 0, "uint value");
    let uint64_flag = f.uint64("uint64", 0, "uint64 value");
    let string_flag = f.string("string", "0", "string value");
    let float64_flag = f.float64("float64", 0.0, "float64 value");
    let duration_flag = f.duration("duration", 5 * time::SECOND, "time.Duration value");
    let extra = "one-extra-argument";
    let args = [
        "-bool",
        "-bool2=true",
        "--int",
        "22",
        "--int64",
        "0x23",
        "-uint",
        "24",
        "--uint64",
        "25",
        "-string",
        "hello",
        "-float64",
        "2718e28",
        "-duration",
        "2m",
        extra,
    ];
    f.parse(&args).unwrap();
    assert!(f.parsed());
    assert!(bool_flag.get());
    assert!(bool2_flag.get());
    assert_eq!(int_flag.get(), 22);
    assert_eq!(int64_flag.get(), 0x23);
    assert_eq!(uint_flag.get(), 24);
    assert_eq!(uint64_flag.get(), 25);
    assert_eq!(string_flag.get(), "hello");
    assert_eq!(float64_flag.get(), 2718e28);
    assert_eq!(duration_flag.get(), 2 * time::MINUTE);
    assert_eq!(f.args(), [extra]);
}

#[test]
fn parse_flag_set() {
    test_parse(&mut quiet("test"));
}

#[test]
fn parse_command_line() {
    let _guard = GLOBAL.lock().unwrap_or_else(|e| e.into_inner());
    *flag::command_line() = quiet("cmd");
    // The package-level functions define on the command-line set.
    let b = flag::bool("cl_bool", false, "bool value");
    let n = flag::int("cl_int", 0, "int value");
    let s = flag::string("cl_string", "x", "string value");
    let d = flag::duration("cl_duration", Duration::from_nanos(0), "duration");
    flag::int64("cl_int64", 0, "");
    flag::uint("cl_uint", 0, "");
    flag::uint64("cl_uint64", 0, "");
    flag::float64("cl_float64", 0.0, "");
    let var = Ptr::new(0isize);
    flag::int_var(var.clone(), "cl_var", 3, "bound");
    assert_eq!(var.get(), 3);
    command_line_parse(&[
        "-cl_bool",
        "-cl_int=5",
        "-cl_string",
        "str",
        "-cl_duration=1h",
        "-cl_var=9",
        "rest",
        "-x",
    ]);
    assert!(flag::parsed());
    assert!(b.get() && n.get() == 5 && s.get() == "str" && var.get() == 9);
    assert_eq!(d.get(), time::HOUR);
    assert_eq!(flag::args(), ["rest", "-x"]);
    assert_eq!(
        (flag::narg(), flag::arg(0), flag::arg(1), flag::arg(2)),
        (2, "rest".to_owned(), "-x".to_owned(), String::new())
    );
    assert_eq!(flag::nflag(), 5);
    let mut visited = Vec::new();
    flag::visit(|f| visited.push(f.name.clone()));
    assert_eq!(
        visited,
        ["cl_bool", "cl_duration", "cl_int", "cl_string", "cl_var"]
    );
    let mut all = 0;
    flag::visit_all(|_| all += 1);
    assert_eq!(all, 9);
    assert_eq!(
        flag::lookup("cl_int", |f| f.value.to_string()),
        Some("5".to_owned())
    );
    assert!(flag::lookup("nope", |_| ()).is_none());
    flag::set("cl_int", "6").unwrap();
    assert_eq!(n.get(), 6);
    assert_eq!(
        flag::set("cl_nope", "1").unwrap_err().to_string(),
        "no such flag -cl_nope"
    );
    *flag::command_line() = quiet("cmd");
}

fn command_line_parse(args: &[&str]) {
    flag::command_line().parse(args).unwrap();
}

/// A user-defined value that collects every `-v` occurrence.
struct FlagVar(Ptr<Vec<String>>);
impl std::fmt::Display for FlagVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&{ format!("[{}]", self.0.with(|v| v.join(" "))) })
    }
}
impl Value for FlagVar {
    fn set(&mut self, value: &str) -> Result<(), BoxError> {
        self.0.with(|v| v.push(value.to_owned()));
        Ok(())
    }
}

#[test]
fn user_defined() {
    let mut flags = quiet("test");
    let v = Ptr::new(Vec::new());
    flags.var(FlagVar(v.clone()), "v", "usage");
    flags.parse(&["-v", "1", "-v", "2", "-v=3"]).unwrap();
    assert_eq!(v.get(), ["1", "2", "3"]);
    assert_eq!(flags.lookup("v").unwrap().value.to_string(), "[1 2 3]");
}

#[test]
fn user_defined_func() {
    let mut flags = quiet("test");
    let ss = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&ss);
    flags.func("v", "usage", move |s| {
        sink.lock().unwrap().push(s.to_owned());
        Ok(())
    });
    flags.parse(&["-v", "1", "-v", "2", "-v=3"]).unwrap();
    assert_eq!(*ss.lock().unwrap(), ["1", "2", "3"]);
    let buf = Buf::default();
    flags.set_output(buf.clone());
    let _ = flags.parse(&["-h"]);
    assert!(buf.text().contains("usage"), "{:?}", buf.text());

    let mut flags = quiet("test");
    flags.func("v", "usage", |_| Err("test error".into()));
    flags.parse::<&str>(&[]).unwrap();
    let err = flags.parse(&["-v", "1"]).unwrap_err();
    assert!(err.to_string().contains("test error"), "{err}");
}

#[test]
fn user_defined_for_command_line() {
    let _guard = GLOBAL.lock().unwrap_or_else(|e| e.into_inner());
    let result = Arc::new(Mutex::new(String::new()));
    let sink = Arc::clone(&result);
    flag::set_usage(move |_| *sink.lock().unwrap() = "HELP".into());
    flag::usage();
    assert_eq!(*result.lock().unwrap(), "HELP");
    // Restore Go's default message.
    flag::set_usage(|f| f.print_defaults());
}

/// Go's boolFlagVar: a boolean flag until it has seen four trues.
struct BoolFlagVar(Ptr<usize>);
impl std::fmt::Display for BoolFlagVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&{ self.0.get().to_string() })
    }
}
impl Value for BoolFlagVar {
    fn set(&mut self, value: &str) -> Result<(), BoxError> {
        if value == "true" {
            self.0.with(|c| *c += 1);
        }
        Ok(())
    }
    fn is_bool_flag(&self) -> bool {
        self.0.get() < 4
    }
    fn zero_string(&self) -> Option<String> {
        Some("0".into())
    }
}

#[test]
fn user_defined_bool() {
    let mut flags = quiet("test");
    let count = Ptr::new(0usize);
    flags.var(BoolFlagVar(count.clone()), "b", "usage");
    let err = flags
        .parse(&["-b", "-b", "-b", "-b=true", "-b=false", "-b", "barg", "-b"])
        .unwrap_err();
    assert_eq!(count.get(), 4, "{err}");
}

#[test]
fn user_defined_bool_usage() {
    let mut flags = FlagSet::new("test", ErrorHandling::ContinueOnError);
    let buf = Buf::default();
    flags.set_output(buf.clone());
    let count = Ptr::new(0usize);
    flags.var(BoolFlagVar(count.clone()), "b", "X");
    flags.print_defaults();
    assert_eq!(buf.text(), "  -b\tX\n");
    count.set(4);
    flags.print_defaults();
    assert_eq!(buf.text(), "  -b\tX\n  -b value\n    \tX\n");
}

#[test]
fn set_output_and_getters() {
    let mut flags = FlagSet::new("", ErrorHandling::ContinueOnError);
    let buf = Buf::default();
    flags.set_output(buf.clone());
    flags.init("test", ErrorHandling::ContinueOnError);
    let _ = flags.parse(&["-unknown"]);
    assert!(buf.text().contains("-unknown"), "{:?}", buf.text());

    let mut fs = flag::FlagSet::new("flag set", ErrorHandling::ContinueOnError);
    assert_eq!(fs.name(), "flag set");
    assert_eq!(fs.error_handling(), ErrorHandling::ContinueOnError);
    fs.init("gopher", ErrorHandling::ExitOnError);
    assert_eq!(fs.name(), "gopher");
    assert_eq!(fs.error_handling(), ErrorHandling::ExitOnError);
    let buf = Buf::default();
    fs.set_output(buf.clone());
    write!(fs.output(), "hi").unwrap();
    assert_eq!(buf.text(), "hi");
}

#[test]
fn changing_args() {
    let mut fs = quiet("cmd");
    let before = fs.bool("before", false, "");
    fs.parse(&["-before", "subcmd", "-after", "args"]).unwrap();
    let cmd = fs.arg(0).to_owned();
    let rest = fs.args().to_vec();
    let mut fs = quiet("cmd");
    let after = fs.bool("after", false, "");
    fs.parse(&rest[1..]).unwrap();
    assert!(before.get() && cmd == "subcmd" && after.get());
    assert_eq!(fs.args(), ["args"]);
}

#[test]
fn help() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let called = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&called);
    let mut fs = FlagSet::new("help test", ErrorHandling::ContinueOnError);
    fs.set_output(io::sink());
    fs.usage = Some(Box::new(move |_| seen.store(true, Ordering::SeqCst)));
    let flag_var = fs.bool("flag", false, "regular flag");
    fs.parse(&["-flag=true"]).unwrap();
    assert!(flag_var.get());
    assert!(!called.swap(false, Ordering::SeqCst));
    assert_eq!(fs.parse(&["-help"]), Err(ERR_HELP));
    assert!(called.load(Ordering::SeqCst));
    let help_var = fs.bool("help", false, "help flag");
    called.store(false, Ordering::SeqCst);
    fs.parse(&["-help"]).unwrap();
    assert!(help_var.get());
    assert!(!called.load(Ordering::SeqCst));
}

const DEFAULT_OUTPUT: &str = "  -A\tfor bootstrapping, allow 'any' type
  -Alongflagname
    \tdisable bounds checking
  -C\ta boolean defaulting to true (default true)
  -D path
    \tset relative path for local imports
  -E string
    \tissue 23543 (default \"0\")
  -F number
    \ta non-zero number (default 2.7)
  -G float
    \ta float that defaults to zero
  -M string
    \ta multiline
    \thelp
    \tstring
  -N int
    \ta non-zero int (default 27)
  -O\ta flag
    \tmultiline help string (default true)
  -V list
    \ta list of strings (default [a b])
  -Z int
    \tan int that defaults to zero
  -maxT timeout
    \tset timeout for dial
";

#[test]
fn print_defaults() {
    let mut fs = FlagSet::new("print defaults test", ErrorHandling::ContinueOnError);
    let buf = Buf::default();
    fs.set_output(buf.clone());
    fs.bool("A", false, "for bootstrapping, allow 'any' type");
    fs.bool("Alongflagname", false, "disable bounds checking");
    fs.bool("C", true, "a boolean defaulting to true");
    fs.string("D", String::new(), "set relative `path` for local imports");
    fs.string("E", "0", "issue 23543");
    fs.float64("F", 2.7, "a non-zero `number`");
    fs.float64("G", 0.0, "a float that defaults to zero");
    fs.string("M", String::new(), "a multiline\nhelp\nstring");
    fs.int("N", 27, "a non-zero int");
    fs.bool("O", true, "a flag\nmultiline help string");
    fs.var(
        FlagVar(Ptr::new(vec!["a".into(), "b".into()])),
        "V",
        "a `list` of strings",
    );
    fs.int("Z", 0, "an int that defaults to zero");
    fs.duration("maxT", Duration::from_nanos(0), "set `timeout` for dial");
    fs.print_defaults();
    assert_eq!(buf.text(), DEFAULT_OUTPUT);
}

/// A value whose zero-value text panics, like Go's `zeroPanicker`.
struct ZeroPanicker;
impl std::fmt::Display for ZeroPanicker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("")
    }
}
impl Value for ZeroPanicker {
    fn set(&mut self, _: &str) -> Result<(), BoxError> {
        Ok(())
    }
    fn zero_string(&self) -> Option<String> {
        panic!("panic!")
    }
}

#[test]
fn print_defaults_reports_panicking_zero_string() {
    let mut fs = FlagSet::new("zp", ErrorHandling::ContinueOnError);
    let buf = Buf::default();
    fs.set_output(buf.clone());
    fs.int("A", 0, "an int");
    fs.var(ZeroPanicker, "ZP0", "a flag whose String method panics");
    fs.var(ZeroPanicker, "ZP1", "another one");
    fs.int("Z", 1, "an int");
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    fs.print_defaults();
    std::panic::set_hook(hook);
    let ty = std::any::type_name::<ZeroPanicker>();
    assert_eq!(
        buf.text(),
        format!(
            "  -A int\n    \tan int\n  -Z int\n    \tan int (default 1)\n  -ZP0 value\n    \ta flag whose String method panics\n  -ZP1 value\n    \tanother one\n\n\
             panic calling String method on zero {ty} for flag ZP0: panic!\n\
             panic calling String method on zero {ty} for flag ZP1: panic!\n"
        )
    );
}

#[test]
fn usage_output_names_the_set() {
    let mut fs = FlagSet::new("app", ErrorHandling::ContinueOnError);
    let buf = Buf::default();
    fs.set_output(buf.clone());
    assert!(fs.parse(&["-i=1", "-unknown"]).is_err());
    assert_eq!(
        buf.text(),
        "flag provided but not defined: -i\nUsage of app:\n"
    );
    let mut anonymous = FlagSet::new("", ErrorHandling::ContinueOnError);
    let buf = Buf::default();
    anonymous.set_output(buf.clone());
    anonymous.int("n", 0, "");
    anonymous.print_defaults();
    let _ = anonymous.parse(&["-bad"]);
    assert!(buf.text().contains("Usage:\n"));
}

#[test]
fn parse_and_range_errors() {
    for typ in [
        "bool", "int", "int64", "uint", "uint64", "float64", "duration",
    ] {
        let mut fs = quiet("parse error test");
        fs.bool("bool", false, "");
        fs.int("int", 0, "");
        fs.int64("int64", 0, "");
        fs.uint("uint", 0, "");
        fs.uint64("uint64", 0, "");
        fs.float64("float64", 0.0, "");
        fs.duration("duration", Duration::from_nanos(0), "");
        let err = fs.parse(&[format!("-{typ}=x")]).unwrap_err().to_string();
        assert!(
            err.contains("invalid") && err.contains("parse error"),
            "{err}"
        );
    }
    for arg in [
        "-int=123456789012345678901",
        "-int64=123456789012345678901",
        "-uint=123456789012345678901",
        "-uint64=123456789012345678901",
        "-float64=1e1000",
    ] {
        let mut fs = quiet("range error test");
        fs.int("int", 0, "");
        fs.int64("int64", 0, "");
        fs.uint("uint", 0, "");
        fs.uint64("uint64", 0, "");
        fs.float64("float64", 0.0, "");
        let err = fs.parse(&[arg]).unwrap_err().to_string();
        assert!(
            err.contains("invalid") && err.contains("value out of range"),
            "{err}"
        );
    }
}

fn must_panic(test: &str, expected: &str, f: impl FnOnce() + std::panic::UnwindSafe) {
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(f);
    std::panic::set_hook(hook);
    let payload = result.expect_err(test);
    let msg = payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .unwrap_or_default();
    assert!(
        msg.contains(expected),
        "{test}: want {expected:?}, got {msg:?}"
    );
}

#[test]
fn invalid_and_redefined_flags() {
    for (name, msg) in [
        ("-foo", "flag \"-foo\" begins with -"),
        ("foo=bar", "flag \"foo=bar\" contains ="),
    ] {
        let mut fs = FlagSet::new("", ErrorHandling::ContinueOnError);
        let buf = Buf::default();
        fs.set_output(buf.clone());
        must_panic(
            name,
            msg,
            std::panic::AssertUnwindSafe(|| {
                fs.var(FlagVar(Ptr::new(Vec::new())), name, "");
            }),
        );
        assert_eq!(buf.text(), format!("{msg}\n"));
    }
    for (set_name, msg) in [
        ("", "flag redefined: foo"),
        ("fs", "fs flag redefined: foo"),
    ] {
        let mut fs = FlagSet::new(set_name, ErrorHandling::ContinueOnError);
        let buf = Buf::default();
        fs.set_output(buf.clone());
        fs.var(FlagVar(Ptr::new(Vec::new())), "foo", "");
        must_panic(
            set_name,
            msg,
            std::panic::AssertUnwindSafe(|| {
                fs.var(FlagVar(Ptr::new(Vec::new())), "foo", "");
            }),
        );
        assert_eq!(buf.text(), format!("{msg}\n"));
    }
}

#[test]
fn define_after_set() {
    let mut flags = FlagSet::new("test", ErrorHandling::ContinueOnError);
    assert!(flags.set("myFlag", "value").is_err());
    must_panic(
        "DefineAfterSet",
        "flag myFlag set at ",
        std::panic::AssertUnwindSafe(|| {
            flags.string("myFlag", "default", "usage");
        }),
    );
    let mut flags = FlagSet::new("test", ErrorHandling::ContinueOnError);
    let _ = flags.set("other", "value");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        flags.string("other", String::new(), "");
    }));
    let msg = result.unwrap_err();
    let msg = msg.downcast_ref::<String>().unwrap();
    assert!(
        msg.contains("before being defined") && msg.contains("flag.rs:"),
        "{msg}"
    );
}

#[test]
fn user_defined_bool_func() {
    let mut flags = quiet("test");
    let ss = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&ss);
    flags.bool_func("v", "usage", move |s| {
        sink.lock().unwrap().push(s.to_owned());
        Ok(())
    });
    flags.parse(&["-v", "", "-v", "1", "-v=2"]).unwrap();
    assert_eq!(*ss.lock().unwrap(), ["true"]);
    let buf = Buf::default();
    flags.set_output(buf.clone());
    let _ = flags.parse(&["-h"]);
    assert!(buf.text().contains("usage"));

    let mut flags = quiet("test");
    flags.bool_func("v", "usage", |_| Err("test error".into()));
    flags.parse::<&str>(&[]).unwrap();
    let err = flags.parse(&["-v", ""]).unwrap_err();
    assert!(err.to_string().contains("test error"), "{err}");
}

/// Go's example_textvar_test.go with a small upper-casing text type.
#[derive(Default)]
struct Word(String);
impl TextMarshaler for Word {
    fn marshal_text(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(self.0.clone().into_bytes())
    }
}
impl TextUnmarshaler for Word {
    fn unmarshal_text(&mut self, text: &[u8]) -> Result<(), Box<dyn Error>> {
        let s = std::str::from_utf8(text)?;
        if s.contains('!') {
            return Err(format!("invalid word: {s}").into());
        }
        self.0 = s.to_uppercase();
        Ok(())
    }
}

#[test]
fn text_var() {
    let mut fs = FlagSet::new("ExampleTextVar", ErrorHandling::ContinueOnError);
    let buf = Buf::default();
    fs.set_output(buf.clone());
    let word = Ptr::new(Word::default());
    fs.text_var(
        word.clone(),
        "word",
        Word("start".into()),
        "`word` to shout",
    );
    assert_eq!(word.with(|w| w.0.clone()), "start");
    fs.parse(&["-word", "hello"]).unwrap();
    assert_eq!(word.with(|w| w.0.clone()), "HELLO");
    let err = fs.parse(&["-word", "no!"]).unwrap_err().to_string();
    assert_eq!(
        err,
        "invalid value \"no!\" for flag -word: invalid word: no!"
    );
    assert_eq!(
        buf.text(),
        "invalid value \"no!\" for flag -word: invalid word: no!\nUsage of ExampleTextVar:\n  -word word\n    \tword to shout (default start)\n"
    );
    let g = fs.lookup("word").unwrap().value.as_getter().unwrap().get();
    assert!(g.downcast_ref::<Ptr<Word>>().is_some());
}

#[test]
fn func_example_output() {
    let mut fs = FlagSet::new("ExampleFunc", ErrorHandling::ContinueOnError);
    let buf = Buf::default();
    fs.set_output(buf.clone());
    let ip = Arc::new(Mutex::new(None::<String>));
    let sink = Arc::clone(&ip);
    fs.func("ip", "`IP address` to parse", move |s| {
        let valid = s.split('.').count() == 4 && s.split('.').all(|p| p.parse::<u8>().is_ok());
        *sink.lock().unwrap() = valid.then(|| s.to_owned());
        if valid {
            Ok(())
        } else {
            Err("could not parse IP".into())
        }
    });
    fs.parse(&["-ip", "127.0.0.1"]).unwrap();
    assert_eq!(ip.lock().unwrap().as_deref(), Some("127.0.0.1"));
    assert!(fs.parse(&["-ip", "256.0.0.1"]).is_err());
    assert_eq!(
        buf.text(),
        "invalid value \"256.0.0.1\" for flag -ip: could not parse IP\nUsage of ExampleFunc:\n  -ip IP address\n    \tIP address to parse\n"
    );
}

#[test]
fn flagset_subcommands_example() {
    fn start(args: &[&str]) -> String {
        let mut fs = quiet("start");
        let addr = fs.string("addr", ":8080", "`address` to listen on");
        match fs.parse(args) {
            Ok(()) => format!("starting server on {}\n", addr.get()),
            Err(e) => format!("error: {e}"),
        }
    }
    fn stop(args: &[&str]) -> String {
        let mut fs = quiet("stop");
        let timeout = fs.duration("timeout", time::SECOND, "stop timeout duration");
        match fs.parse(args) {
            Ok(()) => format!("stopping server (timeout={})\n", timeout.get()),
            Err(e) => format!("error: {e}"),
        }
    }
    assert_eq!(start(&["-addr", ":9999"]), "starting server on :9999\n");
    assert_eq!(stop(&[]), "stopping server (timeout=1s)\n");
    assert_eq!(
        start(&["-log-level", "verbose"]),
        "error: flag provided but not defined: -log-level"
    );
}

#[test]
fn grammar_edge_cases() {
    let mut fs = quiet("g");
    let s = fs.string("s", String::new(), "");
    let b = fs.bool("b", false, "");
    // A string flag consumes the next argument even if it looks like a flag.
    fs.parse(&["-s", "-b", "x"]).unwrap();
    assert_eq!(s.get(), "-b");
    assert!(!b.get());
    assert_eq!(fs.args(), ["x"]);
    for bad in ["---b", "-=x", "--=x", "-s", "-"] {
        let mut fs = quiet("g");
        fs.string("s", String::new(), "");
        let r = fs.parse(&[bad]);
        match bad {
            "-" => {
                r.unwrap();
                assert_eq!(fs.args(), ["-"]);
            }
            "-s" => assert_eq!(r.unwrap_err().to_string(), "flag needs an argument: -s"),
            _ => assert_eq!(
                r.unwrap_err().to_string(),
                format!("bad flag syntax: {bad}")
            ),
        }
    }
    let mut fs = quiet("g");
    let n = fs.int("n", 0, "");
    fs.parse(&["-n=", "--", "-n=1"]).unwrap_err();
    fs.parse(&["--", "-n=1"]).unwrap();
    assert_eq!(fs.args(), ["-n=1"]);
    assert_eq!(n.get(), 0);
    assert_eq!(fs.nflag(), 0);
    let kind = fs.lookup("n").unwrap().value.kind();
    assert_eq!(kind, ValueKind::Int);
    assert_eq!(flag::unquote_usage(fs.lookup("n").unwrap()).0, "int");
    let g: &dyn Getter = fs.lookup("n").unwrap().value.as_getter().unwrap();
    assert_eq!(*g.get().downcast_ref::<isize>().unwrap(), 0);
}

#[test]
fn usage_may_call_package_level_readers() {
    let _guard = GLOBAL.lock().unwrap_or_else(|e| e.into_inner());
    *flag::command_line() = quiet("cmd");
    let out = Buf::default();
    flag::command_line().set_output(out.clone());
    flag::string("reent_name", "dflt", "the `name` to use");
    flag::int("reent_n", 0, "a count");
    flag::set_usage(|_| {
        // Go's usual shape: print a header, then the package-level
        // PrintDefaults, NFlag, Args and Lookup.
        let mut w = io::stderr();
        let _ = w.flush();
        flag::print_defaults();
        let mut names = Vec::new();
        flag::visit_all(|f| names.push(f.name.clone()));
        assert_eq!(names, ["reent_n", "reent_name"]);
        assert_eq!(flag::nflag(), 0);
        assert_eq!(
            flag::lookup("reent_name", |f| f.def_value.clone()),
            Some("dflt".to_owned())
        );
    });
    let err = flag::command_line().parse(&["-reent_bogus"]).unwrap_err();
    assert_eq!(
        err.to_string(),
        "flag provided but not defined: -reent_bogus"
    );
    let text = out.text();
    assert!(text.contains("-reent_name name\n"), "{text}");
    assert!(text.contains("(default \"dflt\")"), "{text}");
    // The snapshot is gone afterwards, so the real set is locked normally.
    assert_eq!(flag::nflag(), 0);
    flag::set_usage(|f| f.print_defaults());
    *flag::command_line() = quiet("cmd");
}

#[test]
fn usage_snapshot_reports_panicking_zero_string() {
    let _guard = GLOBAL.lock().unwrap_or_else(|e| e.into_inner());
    *flag::command_line() = quiet("cmd");
    let out = Buf::default();
    flag::command_line().set_output(out.clone());
    flag::var(ZeroPanicker, "snap_zp", "u");
    flag::set_usage(|_| flag::print_defaults());
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let _ = flag::command_line().parse(&["-snap_bogus"]);
    std::panic::set_hook(hook);
    assert!(
        out.text().ends_with("for flag snap_zp: panic!\n"),
        "{}",
        out.text()
    );
    flag::set_usage(|f| f.print_defaults());
    *flag::command_line() = quiet("cmd");
}
