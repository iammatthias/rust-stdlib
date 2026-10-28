//! Ports of Go's fmt tests: the `fmtTests`, `reorderTests` and `startests`
//! tables and the scan tables (`scanTests`, `scanfTests`, `overflowTests`,
//! `multiTests`, `eofTests`) are generated from Go's sources by
//! `tools/gen_fmt_fixtures.py` (tests/fixtures/fmt_tests.rs); the other tests
//! of fmt_test.go, scan_test.go, errors_test.go, stringer_test.go and
//! state_test.go are ported by hand.
//!
//! Not ported: entries with reflect.Value operands, functions, channels and
//! unsafe pointers (no Rust counterpart), entries whose expected output holds
//! a heap address, benchmarks, TestCountMallocs and TestIsSpace/TestParsenum
//! (internals).

use rust_stdlib::printf::{
    self as fmt, format_string, Formatter, IntKind, ScanArg, ScanErrorKind, ScanState, Scanner,
    State, StateRunes, UintKind, Value,
};
use rust_stdlib::strconv::Complex;
use std::io::{self, Read, Write};

// ---- constructors used by the generated tables

fn seq(
    type_name: &str,
    elem: &str,
    bytes: bool,
    array: bool,
    nil: bool,
    items: Vec<Value>,
) -> Value {
    Value::Slice(Box::new(fmt::Seq {
        type_name: type_name.into(),
        elem: elem.into(),
        items,
        bytes,
        array,
        nil,
        addr: if nil { 0 } else { 0xc000010000 },
    }))
}

fn mapv(type_name: &str, nil: bool, entries: Vec<(Value, Value)>) -> Value {
    Value::Map(Box::new(fmt::MapV {
        type_name: type_name.into(),
        entries,
        nil,
        addr: if nil { 0 } else { 0xc000020000 },
    }))
}

fn strukt(type_name: &str, fields: Vec<(&str, Value)>) -> Value {
    Value::strukt(type_name, fields)
}

// ---- the methods of the named types in fmt_test.go

struct Str(String);
impl std::fmt::Display for Str {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0.clone())
    }
}
impl std::fmt::Debug for Str {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0.clone())
    }
}

type FormatBody = Box<dyn Fn(&mut dyn State, char) + Send + Sync>;
struct FormatFn(FormatBody);
impl Formatter for FormatFn {
    fn format(&self, f: &mut dyn State, verb: char) {
        (self.0)(f, verb)
    }
}

const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

fn meth(ty: &str, base: Value) -> Value {
    let n = match base.underlying() {
        Value::Int(n, _) => *n,
        Value::Uint(u, _) => *u as i64,
        _ => 0,
    };
    let text = match base.underlying() {
        Value::String(s) => s.clone(),
        _ => Vec::new(),
    };
    let v = Value::named(ty, base);
    match ty {
        "fmt_test.I" => v.with_display(Str(format!("<{n}>"))),
        "fmt_test.F" => v.with_formatter(FormatFn(Box::new(move |f, c| {
            let mut out = Vec::new();
            fmt::appendf(
                &mut out,
                "<%c=F(%d)>",
                &[Value::from(c), Value::Int(n, IntKind::Int)],
            );
            let _ = f.write_all(&out);
        }))),
        "fmt_test.G" => v.with_debug(Str(format!("GoString({n})"))),
        "*fmt_test.P" => v.with_display(Str("String(p)".into())),
        "fmt_test.Fn" => v.with_display(Str("String(fn)".into())),
        "fmt_test.byteStringer" => v.with_display(Str("X".into())),
        "fmt_test.byteFormatter" => v.with_formatter(FormatFn(Box::new(|f, _| {
            let mut out = Vec::new();
            fmt::append(&mut out, &[Value::from("X")]);
            let _ = f.write_all(&out);
        }))),
        "fmt_test.writeStringFormatter" => v.with_formatter(FormatFn(Box::new(move |f, _| {
            let _ = f.write_all(b"***");
            let _ = f.write_all(&text);
            let _ = f.write_all(b"***");
        }))),
        "time.Month" => v.with_display(Str(if (1..=12).contains(&n) {
            MONTHS[n as usize - 1].to_string()
        } else {
            format!("%!Month({n})")
        })),
        _ => panic!("no methods known for {ty}"),
    }
}

include!("fixtures/fmt_tests.rs");

fn show(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn appendf(format: &[u8], args: &[Value]) -> Vec<u8> {
    let mut b = Vec::new();
    fmt::appendf(&mut b, format, args);
    b
}

#[test]
fn fmt_tests_table() {
    let tests = fmt_tests();
    assert!(tests.len() >= 700, "fixture shrank to {}", tests.len());
    let mut bad = Vec::new();
    for (format, val, out) in tests {
        let got = appendf(format, std::slice::from_ref(&val));
        if got != out {
            bad.push(format!(
                "Sprintf({:?}, {:?}) = {:?} want {:?}",
                show(format),
                val,
                show(&got),
                show(out)
            ));
        }
    }
    assert!(
        bad.is_empty(),
        "{} failures:\n{}",
        bad.len(),
        bad.join("\n")
    );
}

#[test]
fn reorder_and_star_tables() {
    let mut bad = Vec::new();
    for (format, args, out) in reorder_tests().into_iter().chain(star_tests()) {
        let got = appendf(format, &args);
        if got != out {
            bad.push(format!(
                "Sprintf({:?}, {:?}) = {:?} want {:?}",
                show(format),
                args,
                show(&got),
                show(out)
            ));
        }
    }
    assert!(
        bad.is_empty(),
        "{} failures:\n{}",
        bad.len(),
        bad.join("\n")
    );
}

#[test]
fn complex_formatting() {
    // A complex always formats to the same thing as two singleton prints.
    let values = [1.0, 0.0, -1.0, f64::INFINITY, f64::NEG_INFINITY, f64::NAN];
    for plus in [true, false] {
        for zero in [true, false] {
            for space in [true, false] {
                for ch in "fFeEgG".chars() {
                    let mut real_fmt = String::from("%");
                    if zero {
                        real_fmt.push('0');
                    }
                    if space {
                        real_fmt.push(' ');
                    }
                    if plus {
                        real_fmt.push('+');
                    }
                    real_fmt.push_str("10.2");
                    real_fmt.push(ch);
                    // Imaginary part always has a sign, so force + and ignore space.
                    let mut imag_fmt = String::from("%");
                    if zero {
                        imag_fmt.push('0');
                    }
                    imag_fmt.push_str("+10.2");
                    imag_fmt.push(ch);
                    for &re in &values {
                        for &im in &values {
                            let one = fmt::sprintf(&real_fmt, &[Value::Complex128(re, im)]);
                            let two = fmt::sprintf(
                                format!("({real_fmt}{imag_fmt}i)"),
                                &[Value::from(re), Value::from(im)],
                            );
                            assert_eq!(one, two, "{real_fmt} {re} {im}");
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn fmt_interface() {
    assert_eq!(fmt::sprintf("%s", &[Value::from("abc")]), "abc");
}

struct FlagPrinter;
impl Formatter for FlagPrinter {
    fn format(&self, f: &mut dyn State, c: char) {
        let mut s = String::from("%");
        for i in 0..128u8 {
            if f.flag(i as char) {
                s.push(i as char);
            }
        }
        if let Some(w) = f.width() {
            s.push_str(&w.to_string());
        }
        if let Some(p) = f.precision() {
            s.push_str(&format!(".{p}"));
        }
        s.push(c);
        let _ = f.write_all(format!("[{s}]").as_bytes());
    }
}

fn flag_printer() -> Value {
    Value::strukt("fmt_test.flagPrinter", vec![]).with_formatter(FlagPrinter)
}

#[test]
fn flag_parser() {
    let tests = [
        ("%a", "[%a]"),
        ("%-a", "[%-a]"),
        ("%+a", "[%+a]"),
        ("%#a", "[%#a]"),
        ("% a", "[% a]"),
        ("%0a", "[%0a]"),
        ("%1.2a", "[%1.2a]"),
        ("%-1.2a", "[%-1.2a]"),
        ("%+1.2a", "[%+1.2a]"),
        ("%-+1.2a", "[%+-1.2a]"),
        ("%-+1.2abc", "[%+-1.2a]bc"),
        ("%-1.2abc", "[%-1.2a]bc"),
        ("%-0abc", "[%-0a]bc"),
    ];
    for (input, out) in tests {
        assert_eq!(fmt::sprintf(input, &[flag_printer()]), out, "{input}");
    }
}

#[test]
fn formatter_flags() {
    let wrap = |inner: &str| -> String { format!("[{inner}]") };
    let one = |v: Value| Value::array("fmt_test.flagPrinter", vec![v]);
    for verb in ["a", "v"] {
        for flags in ["", "-", "+", "#", " ", "0", "1.2", "-1.2", "+1.2", "-+1.2"] {
            let spec = format!("%{flags}{verb}");
            let canon = if flags == "-+1.2" {
                format!("%+-1.2{verb}")
            } else {
                spec.clone()
            };
            assert_eq!(
                fmt::sprintf(&spec, &[flag_printer()]),
                wrap(&canon),
                "{spec}"
            );
            let got = fmt::sprintf(&spec, &[one(flag_printer())]);
            if spec == "%#v" {
                assert_eq!(got, "[1]fmt_test.flagPrinter{[%#v]}");
            } else {
                assert_eq!(got, wrap(&wrap(&canon)), "{spec}");
            }
        }
    }
}

#[test]
fn struct_printer() {
    let t = || {
        strukt(
            "fmt_test.T",
            vec![
                ("a", Value::from("abc")),
                ("b", Value::from("def")),
                ("c", Value::int(123)),
            ],
        )
    };
    let tests = [
        ("%v", "{abc def 123}"),
        ("%+v", "{a:abc b:def c:123}"),
        ("%#v", "fmt_test.T{a:\"abc\", b:\"def\", c:123}"),
    ];
    for (format, out) in tests {
        assert_eq!(fmt::sprintf(format, &[t()]), out);
        let p = Value::pointer("*fmt_test.T", 0xc000010000, t());
        assert_eq!(fmt::sprintf(format, &[p]), format!("&{out}"));
    }
}

#[test]
fn slice_and_map_printers() {
    assert_eq!(fmt::sprint(&[Value::slice("int", vec![])]), "[]");
    let s = Value::slice("int", (1..=3).map(Value::int).collect());
    assert_eq!(fmt::sprint(std::slice::from_ref(&s)), "[1 2 3]");
    let p = Value::pointer("*[]int", 0xc000010000, s);
    assert_eq!(fmt::sprint(&[p]), "&[1 2 3]");

    assert_eq!(fmt::sprint(&[Value::map("int", "string", vec![])]), "map[]");
    let m = Value::map(
        "int",
        "string",
        vec![
            (Value::int(3), Value::from("three")),
            (Value::int(1), Value::from("one")),
            (Value::int(2), Value::from("two")),
        ],
    );
    assert_eq!(
        fmt::sprint(std::slice::from_ref(&m)),
        "map[1:one 2:two 3:three]"
    );
    let p = Value::pointer("*map[int]string", 0xc000010000, m);
    assert_eq!(fmt::sprint(&[p]), "&map[1:one 2:two 3:three]");
    assert_eq!(fmt::sprint(&[Value::nil_map("string", "int")]), "map[]");
    assert_eq!(fmt::sprint(&[Value::map("string", "int", vec![])]), "map[]");
}

#[test]
fn blank_and_blankln() {
    let args = || {
        vec![
            Value::from("<"),
            Value::int(1),
            Value::from(">:"),
            Value::int(1),
            Value::int(2),
            Value::int(3),
            Value::from("!"),
        ]
    };
    assert_eq!(fmt::sprint(&args()), "<1>:1 2 3!");
    assert_eq!(fmt::sprintln(&args()), "< 1 >: 1 2 3 !\n");
}

#[test]
fn formatter_println() {
    let f = || meth("fmt_test.F", Value::int(1));
    let expect = "<v=F(1)>\n";
    assert_eq!(fmt::sprint(&[f(), Value::from("\n")]), expect);
    assert_eq!(fmt::sprintln(&[f()]), expect);
    assert_eq!(fmt::sprintf("%v\n", &[f()]), expect);
}

struct PanicWith(Value);

fn panic_s(msg: Value) -> Value {
    struct P(Value);
    impl std::fmt::Display for P {
        fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            std::panic::panic_any(self.0.clone())
        }
    }
    Value::strukt("fmt_test.PanicS", vec![("message", msg.clone())]).with_display(P(msg))
}

fn panic_go(msg: Value) -> Value {
    struct P(Value);
    impl std::fmt::Debug for P {
        fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            std::panic::panic_any(self.0.clone())
        }
    }
    Value::strukt("fmt_test.PanicGo", vec![("message", msg.clone())]).with_debug(P(msg))
}

fn panic_f(msg: Value) -> Value {
    let m = PanicWith(msg.clone());
    Value::strukt("fmt_test.PanicF", vec![("message", msg)]).with_formatter(FormatFn(Box::new(
        move |_, _| std::panic::panic_any(m.0.clone()),
    )))
}

#[test]
fn panics() {
    let eof = || Value::from_error(std::io::Error::from(rust_stdlib::io::Error::UnexpectedEof));
    struct Boom;
    impl std::fmt::Display for Boom {
        fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("nil pointer dereference")
        }
    }
    impl std::fmt::Debug for Boom {
        fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("nil pointer dereference")
        }
    }
    let nil_ptr = |name: &str| -> Value {
        Value::named(name, Value::nil_pointer(name))
            .with_display(Boom)
            .with_debug(Boom)
            .with_formatter(FormatFn(Box::new(|_, _| panic!("nil pointer dereference"))))
    };
    let tests: Vec<(&str, Value, String)> = vec![
        ("%s", nil_ptr("*fmt_test.PanicS"), "<nil>".into()),
        (
            "%s",
            panic_s(eof()),
            "%!s(PANIC=String method: unexpected EOF)".into(),
        ),
        (
            "%s",
            panic_s(Value::int(3)),
            "%!s(PANIC=String method: 3)".into(),
        ),
        ("%#v", nil_ptr("*fmt_test.PanicGo"), "<nil>".into()),
        (
            "%#v",
            panic_go(eof()),
            "%!v(PANIC=GoString method: unexpected EOF)".into(),
        ),
        (
            "%#v",
            panic_go(Value::int(3)),
            "%!v(PANIC=GoString method: 3)".into(),
        ),
        // Issue 18282. catchPanic should not clear fmtFlags permanently.
        (
            "%#v",
            Value::slice(
                "interface {}",
                vec![panic_go(Value::int(3)), panic_go(Value::int(3))],
            ),
            "[]interface {}{%!v(PANIC=GoString method: 3), %!v(PANIC=GoString method: 3)}".into(),
        ),
        ("%s", nil_ptr("*fmt_test.PanicF"), "<nil>".into()),
        (
            "%s",
            panic_f(eof()),
            "%!s(PANIC=Format method: unexpected EOF)".into(),
        ),
        (
            "%s",
            panic_f(Value::int(3)),
            "%!s(PANIC=Format method: 3)".into(),
        ),
    ];
    for (i, (format, val, out)) in tests.into_iter().enumerate() {
        assert_eq!(fmt::sprintf(format, &[val]), out, "#{i} {format}");
    }
}

#[test]
fn nil_does_not_become_typed() {
    let a = Value::nil_pointer("*fmt_test.A");
    let b = Value::strukt("fmt_test.B", vec![]);
    let got = fmt::sprintf(
        "%s %s %s %s %s",
        &[Value::Nil, a, Value::Nil, b, Value::Nil],
    );
    assert_eq!(
        got,
        "%!s(<nil>) %!s(*fmt_test.A=<nil>) %!s(<nil>) {} %!s(<nil>)"
    );
}

#[test]
fn append_functions() {
    let mut b = b"hello ".to_vec();
    fmt::appendf(&mut b, "world, %d", &[Value::int(23)]);
    assert_eq!(b, b"hello world, 23");
    let mut b = b"hello ".to_vec();
    fmt::append(
        &mut b,
        &[Value::from("world"), Value::from(", "), Value::int(23)],
    );
    assert_eq!(b, b"hello world, 23");
    let mut b = b"hello ".to_vec();
    fmt::appendln(&mut b, &[Value::from("world,"), Value::int(23)]);
    assert_eq!(b, b"hello world, 23\n");
}

#[test]
fn append_variants_extend_the_buffer() {
    let mut out = Vec::new();
    fmt::appendf(&mut out, "%d-%s", &[Value::int(7), Value::from("x")]);
    assert_eq!(out, b"7-x");
    fmt::append(&mut out, &[Value::int(1), Value::int(2)]);
    fmt::appendln(&mut out, &[Value::int(1), Value::from("a")]);
    assert_eq!(out, b"7-x1 21 a\n");
}

// ---- stringer_test.go

#[test]
fn stringer_on_every_kind() {
    fn s(ty: &str, v: Value, text: String) -> Value {
        Value::named(ty, v).with_display(Str(text))
    }
    let got = fmt::sprintf(
        "%v %v %v %v %v",
        &[
            s("fmt_test.TI", Value::int(0), "I: 0".into()),
            s("fmt_test.TI8", Value::from(1i8), "I8: 1".into()),
            s("fmt_test.TI16", Value::from(2i16), "I16: 2".into()),
            s("fmt_test.TI32", Value::from(3i32), "I32: 3".into()),
            s("fmt_test.TI64", Value::from(4i64), "I64: 4".into()),
        ],
    );
    assert_eq!(got, "I: 0 I8: 1 I16: 2 I32: 3 I64: 4");
    let got = fmt::sprintf(
        "%v %v",
        &[
            s("fmt_test.TB", Value::Bool(true), "B: true".into()),
            s("fmt_test.TS", Value::from("x"), "S: \"x\"".into()),
        ],
    );
    assert_eq!(got, "B: true S: \"x\"");
}

// ---- state_test.go

struct TestState {
    width: Option<isize>,
    prec: Option<isize>,
    flags: String,
}
impl Write for TestState {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other(
            "state_test.go's testState.Write panics: not implemented",
        ))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl State for TestState {
    fn width(&self) -> Option<isize> {
        self.width
    }
    fn precision(&self) -> Option<isize> {
        self.prec
    }
    fn flag(&self, c: char) -> bool {
        self.flags.contains(c)
    }
}

#[test]
fn format_string_reconstructs_directive() {
    let tests: [(Option<isize>, Option<isize>, &str, &str); 10] = [
        (None, None, "", "%x"),
        (None, Some(3), "", "%.3x"),
        (Some(3), None, "", "%3x"),
        (Some(7), Some(3), "", "%7.3x"),
        (None, None, " +-#0", "% +-#0x"),
        (Some(7), Some(3), "+", "%+7.3x"),
        (Some(7), Some(-3), "-", "%-7.-3x"),
        (Some(7), Some(3), " ", "% 7.3x"),
        (Some(7), Some(3), "#", "%#7.3x"),
        (Some(7), Some(3), "0", "%07.3x"),
    ];
    for (width, prec, flags, result) in tests {
        let st = TestState {
            width,
            prec,
            flags: flags.into(),
        };
        assert_eq!(format_string(&st, 'x'), result);
    }
}

// ---- errors_test.go

#[derive(Debug)]
struct ErrString(&'static str);
impl std::fmt::Display for ErrString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ErrString {}

fn err_value(e: &std::sync::Arc<dyn std::error::Error + Send + Sync>) -> Value {
    Value::from_dyn_error(e.clone(), "fmt_test.errString")
}

#[test]
fn errorf_wrapping() {
    use std::error::Error;
    use std::sync::Arc;
    let wrapped: Arc<dyn Error + Send + Sync> = Arc::new(ErrString("inner error"));
    let w = || err_value(&wrapped);
    let es = |s: &'static str| err_value(&(Arc::new(ErrString(s)) as Arc<dyn Error + Send + Sync>));
    let same = |e: &fmt::WrapError, want: &Arc<dyn Error + Send + Sync>| -> bool {
        match e.source() {
            Some(s) => std::ptr::eq(
                s as *const dyn Error as *const (),
                Arc::as_ptr(want) as *const (),
            ),
            None => false,
        }
    };
    let cases: Vec<(fmt::WrapError, &str, bool)> = vec![
        (fmt::errorf("%w", &[w()]), "inner error", true),
        (
            fmt::errorf("added context: %w", &[w()]),
            "added context: inner error",
            true,
        ),
        (
            fmt::errorf("%w with added context", &[w()]),
            "inner error with added context",
            true,
        ),
        (
            fmt::errorf(
                "%s %w %v",
                &[Value::from("prefix"), w(), Value::from("suffix")],
            ),
            "prefix inner error suffix",
            true,
        ),
        (
            fmt::errorf("%[2]s: %[1]w", &[w(), Value::from("positional verb")]),
            "positional verb: inner error",
            true,
        ),
        (fmt::errorf("%v", &[w()]), "inner error", false),
        (
            fmt::errorf("added context: %v", &[w()]),
            "added context: inner error",
            false,
        ),
        (
            fmt::errorf("%v with added context", &[w()]),
            "inner error with added context",
            false,
        ),
        (
            fmt::errorf("%w is not an error", &[Value::from("not-an-error")]),
            "%!w(string=not-an-error) is not an error",
            false,
        ),
        (fmt::errorf("no verbs", &[]), "no verbs", false),
        (
            fmt::errorf("no verbs with extra arg", &[Value::from("extra")]),
            "no verbs with extra arg%!(EXTRA string=extra)",
            false,
        ),
        (
            fmt::errorf("too many verbs: %w %v", &[]),
            "too many verbs: %!w(MISSING) %!v(MISSING)",
            false,
        ),
        (fmt::errorf("%w", &[Value::Nil]), "%!w(<nil>)", false),
    ];
    for (err, text, unwrap) in &cases {
        assert_eq!(&err.to_string(), text);
        assert_eq!(same(err, &wrapped), *unwrap, "{text}");
    }
    assert!(cases[0].0.sources().len() == 1);

    let split =
        |e: &fmt::WrapError| -> Vec<String> { e.sources().iter().map(|e| e.to_string()).collect() };
    let e = fmt::errorf("wrapped two errors: %w %w", &[es("1"), es("2")]);
    assert_eq!(e.to_string(), "wrapped two errors: 1 2");
    assert_eq!(split(&e), ["1", "2"]);
    let e = fmt::errorf(
        "wrapped three errors: %w %w %w",
        &[es("1"), es("2"), es("3")],
    );
    assert_eq!(e.to_string(), "wrapped three errors: 1 2 3");
    assert_eq!(split(&e), ["1", "2", "3"]);
    let e = fmt::errorf(
        "wrapped nil error: %w %w %w",
        &[es("1"), Value::Nil, es("2")],
    );
    assert_eq!(e.to_string(), "wrapped nil error: 1 %!w(<nil>) 2");
    assert_eq!(split(&e), ["1", "2"]);
    let e = fmt::errorf(
        "wrapped one non-error: %w %w %w",
        &[es("1"), Value::from("not-an-error"), es("3")],
    );
    assert_eq!(
        e.to_string(),
        "wrapped one non-error: 1 %!w(string=not-an-error) 3"
    );
    assert_eq!(split(&e), ["1", "3"]);
    let e = fmt::errorf(
        "wrapped errors out of order: %[3]w %[2]w %[1]w",
        &[es("1"), es("2"), es("3")],
    );
    assert_eq!(e.to_string(), "wrapped errors out of order: 3 2 1");
    assert_eq!(split(&e), ["1", "2", "3"]);
    let e = fmt::errorf(
        "wrapped several times: %[1]w %[1]w %[2]w %[1]w",
        &[es("1"), es("2")],
    );
    assert_eq!(e.to_string(), "wrapped several times: 1 1 2 1");
    assert_eq!(split(&e), ["1", "2"]);
}

#[test]
fn from_impls_name_go_types() {
    use std::collections::BTreeMap;
    let m: BTreeMap<&str, i32> = [("b", 2), ("a", 1)].into_iter().collect();
    assert_eq!(
        fmt::sprintf("%v %T", &[Value::from(m.clone()), Value::from(m)]),
        "map[a:1 b:2] map[string]int32"
    );
    assert_eq!(
        fmt::sprintf("%v %T", &[Value::from([1u16, 2]), Value::from([1u16, 2])]),
        "[1 2] [2]uint16"
    );
    assert_eq!(
        fmt::sprintf(
            "%v %T",
            &[Value::from(None::<i32>), Value::from(None::<i32>)]
        ),
        "<nil> *int32"
    );
    assert_eq!(
        fmt::sprintf("%#v", &[Value::from(vec!["a", "b"])]),
        "[]string{\"a\", \"b\"}"
    );
    assert_eq!(fmt::sprintf("%v", &[Value::from(())]), "{}");
}

// ---- scan_test.go

struct OneByte<'a>(&'a [u8]);
impl Read for OneByte<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.0.is_empty() || buf.is_empty() {
            return Ok(0);
        }
        buf[0] = self.0[0];
        self.0 = &self.0[1..];
        Ok(1)
    }
}

/// Accepts any non-empty run of the verb character.
#[derive(Default)]
struct Xs(String);
impl Scanner for Xs {
    fn scan(&mut self, state: &mut dyn ScanState, verb: char) -> Result<(), ScanErrorKind> {
        let tok = state.token(true, Some(&|r| r == verb))?;
        let s = String::from_utf8_lossy(&tok).into_owned();
        if s.is_empty() || !s.chars().all(|c| c == verb) {
            return Err(ScanErrorKind::msg("syntax error for xs"));
        }
        self.0 = s;
        Ok(())
    }
}

/// Accepts an integer followed immediately by a string; tests the embedding of
/// a scan within a scan.
#[derive(Default)]
struct IntString {
    i: isize,
    s: String,
}
impl Scanner for IntString {
    fn scan(&mut self, state: &mut dyn ScanState, _verb: char) -> Result<(), ScanErrorKind> {
        fmt::fscan_runes(
            &mut StateRunes(&mut *state),
            &mut [ScanArg::Int(&mut self.i)],
        )
        .map_err(|e| e.kind)?;
        let tok = state.token(true, None)?;
        self.s = String::from_utf8_lossy(&tok).into_owned();
        Ok(())
    }
}

enum D {
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
    Str(String),
    Bytes(Vec<u8>),
    Xs(Xs),
    IntString(IntString),
}

fn dest(kind: &str) -> D {
    match kind {
        "bool" => D::Bool(false),
        "int" => D::Int(0),
        "int8" => D::I8(0),
        "int16" => D::I16(0),
        "int32" => D::I32(0),
        "int64" => D::I64(0),
        "uint" => D::Uint(0),
        "uint8" => D::U8(0),
        "uint16" => D::U16(0),
        "uint32" => D::U32(0),
        "uint64" => D::U64(0),
        "uintptr" => D::Uptr(0),
        "float32" => D::F32(0.0),
        "float64" => D::F64(0.0),
        "complex64" => D::C64((0.0, 0.0)),
        "complex128" => D::C128(Complex::default()),
        "string" => D::Str(String::new()),
        "bytes" => D::Bytes(Vec::new()),
        "Xs" => D::Xs(Xs::default()),
        "IntString" => D::IntString(IntString::default()),
        _ => panic!("dest kind {kind}"),
    }
}

fn scan_args(ds: &mut [D]) -> Vec<ScanArg<'_>> {
    ds.iter_mut()
        .map(|d| match d {
            D::Bool(v) => ScanArg::Bool(v),
            D::Int(v) => ScanArg::Int(v),
            D::I8(v) => ScanArg::Int8(v),
            D::I16(v) => ScanArg::Int16(v),
            D::I32(v) => ScanArg::Int32(v),
            D::I64(v) => ScanArg::Int64(v),
            D::Uint(v) => ScanArg::Uint(v),
            D::U8(v) => ScanArg::Uint8(v),
            D::U16(v) => ScanArg::Uint16(v),
            D::U32(v) => ScanArg::Uint32(v),
            D::U64(v) => ScanArg::Uint64(v),
            D::Uptr(v) => ScanArg::Uintptr(v),
            D::F32(v) => ScanArg::Float32(v),
            D::F64(v) => ScanArg::Float64(v),
            D::C64(v) => ScanArg::Complex64(v),
            D::C128(v) => ScanArg::Complex128(v),
            D::Str(v) => ScanArg::String(v),
            D::Bytes(v) => ScanArg::Bytes(v),
            D::Xs(v) => ScanArg::Scanner(v),
            D::IntString(v) => ScanArg::Scanner(v),
        })
        .collect()
}

/// The scanned value in the shape the generated tables use, for comparing
/// through `%v` (which ignores renamed type names).
fn dvalue(d: &D) -> Value {
    match d {
        D::Bool(v) => Value::Bool(*v),
        D::Int(v) => Value::int(*v as i64),
        D::I8(v) => Value::from(*v),
        D::I16(v) => Value::from(*v),
        D::I32(v) => Value::from(*v),
        D::I64(v) => Value::from(*v),
        D::Uint(v) => Value::uint(*v as u64),
        D::U8(v) => Value::from(*v),
        D::U16(v) => Value::from(*v),
        D::U32(v) => Value::from(*v),
        D::U64(v) => Value::from(*v),
        D::Uptr(v) => Value::Uint(*v, UintKind::Uintptr),
        D::F32(v) => Value::Float32(*v),
        D::F64(v) => Value::Float64(*v),
        D::C64((r, i)) => Value::Complex64(*r, *i),
        D::C128(c) => Value::Complex128(c.re, c.im),
        D::Str(v) => Value::from(v.as_str()),
        D::Bytes(v) => Value::bytes(v),
        D::Xs(v) => Value::named("fmt_test.Xs", Value::from(v.0.as_str())),
        D::IntString(v) => Value::strukt(
            "fmt_test.IntString",
            vec![
                ("i", Value::int(v.i as i64)),
                ("s", Value::from(v.s.as_str())),
            ],
        ),
    }
}

fn same(a: &Value, b: &Value) -> bool {
    fmt::sprintf("%v", std::slice::from_ref(a)) == fmt::sprintf("%v", std::slice::from_ref(b))
}

#[derive(Clone, Copy, Debug)]
enum Reader {
    Slice,
    OneByte,
}

fn fscan_with(
    r: Reader,
    text: &[u8],
    mode: char,
    format: &[u8],
    args: &mut [ScanArg],
) -> Result<usize, fmt::ScanError> {
    match (r, mode) {
        (Reader::Slice, 's') => fmt::sscan(text, args),
        (Reader::Slice, 'l') => fmt::sscanln(text, args),
        (Reader::Slice, _) => fmt::sscanf(text, format, args),
        (Reader::OneByte, 's') => fmt::fscan(&mut OneByte(text), args),
        (Reader::OneByte, 'l') => fmt::fscanln(&mut OneByte(text), args),
        (Reader::OneByte, _) => fmt::fscanf(&mut OneByte(text), format, args),
    }
}

#[test]
fn scan_and_scanln_tables() {
    let tests = scan_tests();
    assert!(tests.len() > 80, "{}", tests.len());
    for r in [Reader::Slice, Reader::OneByte] {
        for mode in ['s', 'l'] {
            for (text, kind, want) in &tests {
                let mut d = [dest(kind)];
                let n = fscan_with(r, text, mode, b"", &mut scan_args(&mut d));
                match n {
                    Err(e) => panic!("{r:?} {mode}: error scanning {:?}: {e}", show(text)),
                    Ok(n) => assert_eq!(n, 1, "{:?}", show(text)),
                }
                assert!(
                    same(&dvalue(&d[0]), want),
                    "{r:?} {mode}: scanning {:?}: expected {want:?} got {:?}",
                    show(text),
                    dvalue(&d[0])
                );
            }
        }
    }
}

#[test]
fn scanf_table() {
    let tests = scanf_tests();
    assert!(tests.len() > 150);
    for (format, text, kind, want) in tests {
        let mut d = [dest(kind)];
        let res = fmt::sscanf(text, format, &mut scan_args(&mut d));
        match (res, want) {
            (Err(_), None) => {}
            (Err(e), Some(_)) => panic!(
                "Sscanf({:?}, {:?}): unexpected error: {e}",
                show(text),
                show(format)
            ),
            (Ok(_), None) => panic!(
                "Sscanf({:?}, {:?}): unexpected success",
                show(text),
                show(format)
            ),
            (Ok(n), Some(want)) => {
                assert_eq!(n, 1, "Sscanf({:?}, {:?})", show(text), show(format));
                assert!(
                    same(&dvalue(&d[0]), &want),
                    "Sscanf({:?}, {:?}): parsed {:?}, want {want:?}",
                    show(text),
                    show(format),
                    dvalue(&d[0])
                );
            }
        }
    }
}

#[test]
fn scan_overflow() {
    for (text, kind) in overflow_tests() {
        let mut d = [dest(kind)];
        let err = fmt::sscan(text, &mut scan_args(&mut d))
            .expect_err(&format!("expected overflow scanning {:?}", show(text)));
        let m = err.to_string();
        assert!(
            ["overflow", "too large", "out of range", "not representable"]
                .iter()
                .any(|p| m.contains(p)),
            "{text:?}: {m}",
            text = show(text)
        );
    }
}

#[test]
fn nan_and_inf() {
    for s in ["nan", "NAN", "NaN"] {
        let text = format!("{s} {s} {s}");
        let (mut f, mut f32v, mut f64v) = (0.0f64, 0.0f32, 0.0f64);
        let n = fmt::fscan(
            &mut text.as_bytes(),
            &mut [(&mut f).into(), (&mut f32v).into(), (&mut f64v).into()],
        )
        .unwrap();
        assert_eq!(n, 3);
        assert!(f.is_nan() && f32v.is_nan() && f64v.is_nan(), "{text}");
    }
    for s in [
        "inf", "+inf", "-inf", "INF", "-INF", "+INF", "Inf", "-Inf", "+Inf",
    ] {
        let text = format!("{s} {s} {s}");
        let (mut f, mut f32v, mut f64v) = (0.0f64, 0.0f32, 0.0f64);
        let n = fmt::fscan(
            &mut text.as_bytes(),
            &mut [(&mut f).into(), (&mut f32v).into(), (&mut f64v).into()],
        )
        .unwrap();
        assert_eq!(n, 3);
        let neg = s.starts_with('-');
        assert!(
            f.is_infinite() && f32v.is_infinite() && f64v.is_infinite(),
            "{text}"
        );
        assert!(f.is_sign_negative() == neg && f32v.is_sign_negative() == neg);
    }
}

#[test]
fn scanf_multi_table() {
    let tests = multi_tests();
    for r in [Reader::Slice, Reader::OneByte] {
        for (format, text, kinds, out, err) in &tests {
            let mut d: Vec<D> = kinds.iter().map(|k| dest(k)).collect();
            let res = fscan_with(r, text, 'f', format, &mut scan_args(&mut d));
            let ctx = format!("{r:?} ({:?}, {:?})", show(format), show(text));
            match res {
                Err(e) => {
                    assert!(!err.is_empty(), "{ctx}: got error {e}");
                    assert!(e.to_string().contains(err), "{ctx}: error {e}, want {err}");
                    continue;
                }
                Ok(n) => {
                    assert!(err.is_empty(), "{ctx}: expected error {err}");
                    let out = out.as_ref().unwrap();
                    assert_eq!(n, out.len(), "{ctx}");
                    for (got, want) in d.iter().zip(out) {
                        assert!(
                            same(&dvalue(got), want),
                            "{ctx}: {:?} vs {want:?}",
                            dvalue(got)
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn scan_multiple_and_empty() {
    let (mut a, mut s) = (0isize, String::new());
    let n = fmt::sscan("123abc", &mut [(&mut a).into(), (&mut s).into()]).unwrap();
    assert_eq!((n, a, s.as_str()), (2, 123, "abc"));
    let e = fmt::sscan("asdf", &mut [(&mut s).into(), (&mut a).into()]).unwrap_err();
    assert_eq!((e.n, s.as_str()), (1, "asdf"));

    let (mut s1, mut s2) = (String::new(), String::new());
    let e = fmt::sscan("abc", &mut [(&mut s1).into(), (&mut s2).into()]).unwrap_err();
    assert_eq!((e.n, s1.as_str()), (1, "abc"));
    let e = fmt::sscan("", &mut [(&mut s1).into(), (&mut s2).into()]).unwrap_err();
    assert_eq!(e.n, 0);
    // Quoted empty string is OK.
    let n = fmt::sscanf("\"\"", "%q", &mut [(&mut s1).into()]).unwrap();
    assert_eq!(n, 1);
}

#[test]
fn scanln_newline_handling() {
    let mut a = 0isize;
    let e = fmt::sscanln("1 x\n", &mut [(&mut a).into()]).unwrap_err();
    assert!(e.to_string().contains("newline"), "{e}");

    let mut r = "123\n456\n".as_bytes();
    let (mut a, mut b) = (0isize, 0isize);
    let e = fmt::fscanln(&mut r, &mut [(&mut a).into(), (&mut b).into()]).unwrap_err();
    assert!(e.to_string().contains("newline"), "{e}");
}

/// A reader that counts reads at end of file.
struct EofCounter<'a> {
    data: &'a [u8],
    eof_count: usize,
}
impl Read for EofCounter<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.data.len().min(buf.len());
        buf[..n].copy_from_slice(&self.data[..n]);
        self.data = &self.data[n..];
        if n == 0 {
            self.eof_count += 1;
        }
        Ok(n)
    }
}

#[test]
fn eof_is_seen_at_most_once_per_call() {
    let mut ec = EofCounter {
        data: b"123\n",
        eof_count: 0,
    };
    let mut a = 0isize;
    let n = fmt::fscanln(&mut ec, &mut [(&mut a).into()]).unwrap();
    assert_eq!(n, 1);
    assert_eq!(ec.eof_count, 0);
    let e = fmt::fscanln(&mut ec, &mut [(&mut a).into()]).unwrap_err();
    assert_eq!(e.n, 0);
    assert_eq!(ec.eof_count, 1);
}

#[test]
fn eof_at_end_of_input() {
    let (mut i, mut j) = (0isize, 0isize);
    let e = fmt::sscanf("23", "%d %d", &mut [(&mut i).into(), (&mut j).into()]).unwrap_err();
    assert_eq!((e.n, i), (1, 23));
    assert!(e.kind.is_eof(), "{e}");
    let e = fmt::sscan("234", &mut [(&mut i).into(), (&mut j).into()]).unwrap_err();
    assert_eq!((e.n, i), (1, 234));
    assert!(e.kind.is_eof());
    // Trailing space is tougher.
    let e = fmt::sscan("234 ", &mut [(&mut i).into(), (&mut j).into()]).unwrap_err();
    assert_eq!((e.n, i), (1, 234));
    assert!(e.kind.is_eof());
}

#[test]
fn eof_for_all_types() {
    for (i, (format, kind)) in eof_kinds().into_iter().enumerate() {
        for input in ["", "   "] {
            let mut d = [dest(kind)];
            let e = fmt::sscanf(input, format, &mut scan_args(&mut d)).unwrap_err();
            assert!(e.kind.is_eof(), "#{i}: {format} {kind} {input:?}: {e}");
        }
    }
}

#[test]
fn unread_rune_with_rune_scanner() {
    // Successive calls over a rune scanner do not lose runes.
    let mut r = rust_stdlib::text::Reader::new("123αb");
    let mut i = 0isize;
    let n = fmt::fscanf_runes(&mut r, "%d", &mut [(&mut i).into()]).unwrap();
    assert_eq!((n, i), (1, 123));
    let mut a = String::new();
    let n = fmt::fscanf_runes(&mut r, "%s", &mut [(&mut a).into()]).unwrap();
    assert_eq!((n, a.as_str()), (1, "αb"));
}

/// Attempts to read two lines; Scanln should prevent that, Scan and Scanf not.
#[derive(Default)]
struct TwoLines(String);
impl Scanner for TwoLines {
    fn scan(&mut self, state: &mut dyn ScanState, _verb: char) -> Result<(), ScanErrorKind> {
        let mut chars = String::new();
        let mut nl = 0;
        while nl < 2 {
            let (c, _) = state.read_rune()?;
            chars.push(c);
            if c == '\n' {
                nl += 1;
            }
        }
        self.0 = chars;
        Ok(())
    }
}

#[test]
fn multi_line_scanner() {
    let input = "abc\ndef\n";
    let mut t = TwoLines::default();
    let n = fmt::sscan(input, &mut [ScanArg::Scanner(&mut t)]).unwrap();
    assert_eq!((n, t.0.as_str()), (1, input));
    let mut t = TwoLines::default();
    let n = fmt::sscanf(input, "%s", &mut [ScanArg::Scanner(&mut t)]).unwrap();
    assert_eq!((n, t.0.as_str()), (1, input));
    let mut t = TwoLines::default();
    let e = fmt::sscanln(input, &mut [ScanArg::Scanner(&mut t)]).unwrap_err();
    assert_eq!(e.n, 0);
    assert!(matches!(e.kind, ScanErrorKind::UnexpectedEof), "{e}");
}

#[test]
fn fscanf_does_not_read_past_newline() {
    // Issue 3481.
    let mut r = "1\n2\n".as_bytes();
    let (mut i, mut j) = (0isize, 0isize);
    let n = fmt::fscanf(&mut r, "%v\n", &mut [(&mut i).into()]).unwrap();
    assert_eq!(n, 1);
    let n = fmt::fscanf(&mut r, "%v\n", &mut [(&mut j).into()]).unwrap();
    assert_eq!((n, i, j), (1, 1, 2));
}

#[derive(Default)]
struct RuneScan {
    rune: char,
    size: usize,
}
impl Scanner for RuneScan {
    fn scan(&mut self, state: &mut dyn ScanState, _verb: char) -> Result<(), ScanErrorKind> {
        let (r, size) = state.read_rune()?;
        self.rune = r;
        self.size = size;
        Ok(())
    }
}

#[test]
fn scan_state_count() {
    // Issue 8512.
    let (mut a, mut b, mut c) = (
        RuneScan::default(),
        RuneScan::default(),
        RuneScan::default(),
    );
    let n = fmt::sscanf(
        "12➂",
        "%c%c%c",
        &mut [
            ScanArg::Scanner(&mut a),
            ScanArg::Scanner(&mut b),
            ScanArg::Scanner(&mut c),
        ],
    )
    .unwrap();
    assert_eq!(n, 3);
    assert_eq!((a.rune, b.rune, c.rune), ('1', '2', '➂'));
    assert_eq!((a.size, b.size, c.size), (1, 1, 3));
}

/// Accepts a string matching %d.%d.%d... and parses it into a linked list.
#[derive(Default)]
struct RecursiveInt {
    i: isize,
    next: Option<Box<RecursiveInt>>,
}
impl Scanner for RecursiveInt {
    fn scan(&mut self, state: &mut dyn ScanState, _verb: char) -> Result<(), ScanErrorKind> {
        fmt::fscan_runes(
            &mut StateRunes(&mut *state),
            &mut [ScanArg::Int(&mut self.i)],
        )
        .map_err(|e| e.kind)?;
        let mut next = Box::<RecursiveInt>::default();
        match fmt::fscanf_runes(
            &mut StateRunes(&mut *state),
            ".%v",
            &mut [ScanArg::Scanner(&mut *next)],
        ) {
            Ok(_) => {
                self.next = Some(next);
                Ok(())
            }
            Err(e) if matches!(e.kind, ScanErrorKind::UnexpectedEof) => Ok(()),
            Err(e) => Err(e.kind),
        }
    }
}

#[test]
fn scan_recursive_ints() {
    // Deep recursion needs more stack than the default test thread has.
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(|| {
            const COUNT: usize = 800;
            let mut text = String::from("1");
            for i in 1..COUNT {
                text.push_str(&format!(".{}", i + 1));
            }
            let mut r = RecursiveInt::default();
            fmt::fscan(&mut text.as_bytes(), &mut [ScanArg::Scanner(&mut r)]).unwrap();
            let mut cur = Some(&r);
            let mut want = 1;
            while let Some(n) = cur {
                assert_eq!(n.i, want);
                want += 1;
                cur = n.next.as_deref();
            }
            assert_eq!(want - 1, COUNT as isize);
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn hex_bytes() {
    // Issue 9124: %x on bytes couldn't handle non-space bytes terminating the scan.
    let check = |msg: &str, x: &[u8]| {
        assert_eq!(x, [0, 1, 2, 3], "{msg}");
    };
    let (mut a, mut b) = (Vec::new(), Vec::new());
    let n = fmt::sscanf("00010203", "%x", &mut [(&mut a).into()]).unwrap();
    assert_eq!(n, 1);
    check("simple", &a);
    a.clear();
    let n = fmt::sscanf(
        "00010203 00010203",
        "%x %x",
        &mut [(&mut a).into(), (&mut b).into()],
    )
    .unwrap();
    assert_eq!(n, 2);
    check("simple pair a", &a);
    check("simple pair b", &b);
    let n = fmt::sscanf("00010203:", "%x", &mut [(&mut a).into()]).unwrap();
    assert_eq!(n, 1);
    check("colon", &a);
    let n = fmt::sscanf(
        "00010203:00010203",
        "%x:%x",
        &mut [(&mut a).into(), (&mut b).into()],
    )
    .unwrap();
    assert_eq!(n, 2);
    check("colon pair a", &a);
    check("colon pair b", &b);
    // Fails: a hex byte after the data, an odd number of hex input bytes.
    let e = fmt::sscanf("000102034:", "%x", &mut [(&mut a).into()]).unwrap_err();
    assert_eq!(e.n, 0);
}

#[test]
fn scan_newlines_are_spaces() {
    for (name, text, count) in [
        ("newlines", "1\n2\n", 2),
        ("no final newline", "1\n2", 2),
        ("newlines with spaces ", "1  \n  2  \n", 2),
        ("no final newline with spaces", "1  \n  2", 2),
    ] {
        let (mut a, mut b) = (0isize, 0isize);
        let n = fmt::sscan(text, &mut [(&mut a).into(), (&mut b).into()]).unwrap();
        assert_eq!(n, count, "{name}");
    }
}

#[test]
fn scanln_newlines_terminate() {
    for (name, text, count, ok) in [
        ("one line one item", "1\n", 1, false),
        ("one line two items with spaces ", "   1 2    \n", 2, true),
        ("one line two items no newline", "   1 2", 2, true),
        ("two lines two items", "1\n2\n", 1, false),
    ] {
        let (mut a, mut b) = (0isize, 0isize);
        let r = fmt::sscanln(text, &mut [(&mut a).into(), (&mut b).into()]);
        let n = match &r {
            Ok(n) => *n,
            Err(e) => e.n,
        };
        assert_eq!(n, count, "{name}");
        assert_eq!(r.is_ok(), ok, "{name}");
    }
}

#[test]
fn scanf_newline_match_format() {
    let mut tests: Vec<(String, &str, &str, usize, bool)> = vec![
        ("newline in both".into(), "1\n2", "%d\n%d\n", 2, true),
        ("newline in input".into(), "1\n2", "%d %d", 1, false),
        ("space-newline in input".into(), "1 \n2", "%d %d", 1, false),
        ("newline in format".into(), "1 2", "%d\n%d", 1, false),
        ("space-newline in format".into(), "1 2", "%d \n%d", 1, false),
        ("space-newline in both".into(), "1 \n2", "%d \n%d", 2, true),
        ("extra space in format".into(), "1\n2", "%d\n %d", 2, true),
        (
            "two extra spaces in format".into(),
            "1\n2",
            "%d \n %d",
            2,
            true,
        ),
    ];
    let spaces: [(&str, &str, &str, bool); 16] = [
        ("0000", "1\n2", "%d\n%d", true),
        ("0001", "1\n2", "%d\n %d", true),
        ("0010", "1\n2", "%d \n%d", true),
        ("0011", "1\n2", "%d \n %d", true),
        ("0100", "1\n 2", "%d\n%d", true),
        ("0101", "1\n 2", "%d\n%d ", true),
        ("0110", "1\n 2", "%d \n%d", true),
        ("0111", "1\n 2", "%d \n %d", true),
        ("1000", "1 \n2", "%d\n%d", true),
        ("1001", "1 \n2", "%d\n %d", true),
        ("1010", "1 \n2", "%d \n%d", true),
        ("1011", "1 \n2", "%d \n %d", true),
        ("1100", "1 \n 2", "%d\n%d", true),
        ("1101", "1 \n 2", "%d\n %d", true),
        ("1110", "1 \n 2", "%d \n%d", true),
        ("1111", "1 \n 2", "%d \n %d", true),
    ];
    for (n, t, f, ok) in spaces {
        tests.push((format!("space vs newline {n}"), t, f, 2, ok));
    }
    let nopct: [(&str, &str, &str, bool); 16] = [
        ("0000", "1\n2", "1\n2", true),
        ("0001", "1\n2", "1\n 2", true),
        ("0010", "1\n2", "1 \n2", true),
        ("0011", "1\n2", "1 \n 2", true),
        ("0100", "1\n 2", "1\n2", false),
        ("0101", "1\n 2", "1\n2 ", false),
        ("0110", "1\n 2", "1 \n2", false),
        ("0111", "1\n 2", "1 \n 2", true),
        ("1000", "1 \n2", "1\n2", true),
        ("1001", "1 \n2", "1\n 2", true),
        ("1010", "1 \n2", "1 \n2", true),
        ("1011", "1 \n2", "1 \n 2", true),
        ("1100", "1 \n 2", "1\n2", false),
        ("1101", "1 \n 2", "1\n 2", true),
        ("1110", "1 \n 2", "1 \n2", false),
        ("1111", "1 \n 2", "1 \n 2", true),
    ];
    for (n, t, f, ok) in nopct {
        tests.push((format!("space vs newline no-percent {n}"), t, f, 0, ok));
    }
    for (name, text, format, count, ok) in tests {
        let (mut a, mut b) = (0isize, 0isize);
        let r = if format.contains('%') {
            fmt::sscanf(text, format, &mut [(&mut a).into(), (&mut b).into()])
        } else {
            fmt::sscanf(text, format, &mut [])
        };
        let n = match &r {
            Ok(n) => *n,
            Err(e) => e.n,
        };
        assert_eq!(n, count, "{name}");
        assert_eq!(r.is_ok(), ok, "{name}: {r:?}");
    }
}

struct HexBytes([u8; 2]);
impl Scanner for HexBytes {
    fn scan(&mut self, state: &mut dyn ScanState, _verb: char) -> Result<(), ScanErrorKind> {
        let mut b = Vec::new();
        fmt::fscanf_runes(&mut StateRunes(&mut *state), "%4x", &mut [(&mut b).into()])
            .map_err(|e| e.kind)?;
        self.0.copy_from_slice(&b[..2]);
        Ok(())
    }
}

#[test]
fn hex_byte_scanner() {
    // Issue 12090: was unreading at EOF, double-scanning a byte.
    let mut h = HexBytes([0; 2]);
    let n = fmt::sscanln("0123\n", &mut [ScanArg::Scanner(&mut h)]).unwrap();
    assert_eq!((n, h.0), (1, [0x01, 0x23]));
}

#[test]
fn scan_into_every_destination() {
    let mut b = false;
    let (mut i, mut i8v, mut u16v, mut up) = (0isize, 0i8, 0u16, 0u64);
    let (mut f, mut c64, mut c128) = (0f32, (0f32, 0f32), Complex::default());
    let mut s = String::new();
    let mut bytes = Vec::new();
    let n = fmt::sscan(
        "true -5 -128 65535 7 1.5 (1+2i) (3-4i) word bytes",
        &mut [
            (&mut b).into(),
            (&mut i).into(),
            (&mut i8v).into(),
            (&mut u16v).into(),
            ScanArg::Uintptr(&mut up),
            (&mut f).into(),
            (&mut c64).into(),
            (&mut c128).into(),
            (&mut s).into(),
            (&mut bytes).into(),
        ],
    )
    .unwrap();
    assert_eq!(n, 10);
    assert_eq!(
        (
            b,
            i,
            i8v,
            u16v,
            up,
            f,
            c64,
            c128.re,
            c128.im,
            s.as_str(),
            bytes.as_slice()
        ),
        (
            true,
            -5,
            -128,
            65535,
            7,
            1.5,
            (1.0, 2.0),
            3.0,
            -4.0,
            "word",
            &b"bytes"[..]
        )
    );
    // Errors carry Go's text and the count of items scanned.
    let mut i2 = 0isize;
    let e = fmt::sscan("12 x", &mut [(&mut i).into(), (&mut i2).into()]).unwrap_err();
    assert_eq!((e.n, e.to_string().as_str()), (1, "expected integer"));
    let e = fmt::sscan("300", &mut [(&mut i8v).into()]).unwrap_err();
    assert_eq!(e.to_string(), "integer overflow on token 300");
    let e = fmt::sscan("99999999999999999999", &mut [(&mut i).into()]).unwrap_err();
    assert_eq!(
        e.to_string(),
        "strconv.ParseInt: parsing \"99999999999999999999\": value out of range"
    );
    let e = fmt::sscanf("1", "%d %d", &mut [(&mut i).into()]).unwrap_err();
    assert_eq!(e.to_string(), "too few operands for format '%d'");
    let e = fmt::sscanf("1 2", "%d", &mut [(&mut i).into(), (&mut i2).into()]).unwrap_err();
    assert_eq!(e.to_string(), "too many operands");
    let e = fmt::sscanf("1", "%z", &mut [(&mut i).into()]).unwrap_err();
    assert_eq!(e.to_string(), "bad verb '%z' for integer");
}
