//! Tests for `log`, `log/slog` and `log/syslog`, ported from Go's `log_test.go`,
//! `slog/{level,value,record,handler,text_handler,json_handler,logger}_test.go`
//! and `syslog_test.go`. The Go differential (tools/log_check.py) covers
//! generated inputs; these are the fixed tables and the Rust-specific parts.
use rust_stdlib::{
    context::Context,
    encoding::json,
    log::{
        self,
        slog::{
            self, Arg, Attr, Dynamic, ErrorValue, Handler, HandlerOptions, JSONHandler, JsonAny,
            Kind, Level, LevelVar, Leveler, LogValuer, MultiHandler, Source, TextHandler, Value,
            LEVEL_DEBUG, LEVEL_ERROR, LEVEL_INFO, LEVEL_WARN,
        },
        Logger,
    },
    time::{DateTime, Duration},
};
use std::{
    io::{self, Write},
    panic::{catch_unwind, Location},
    sync::{Arc, Mutex},
};

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl Buf {
    fn string(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn t(y: u16, mo: u8, d: u8, h: u8, mi: u8, s: u8, ns: u32, off: i32) -> DateTime {
    DateTime::new(y, mo, d, h, mi, s, ns, off).unwrap()
}

// ------------------------------------------------------------------ log

#[test]
fn flag_constants_match_go() {
    assert_eq!(
        [
            log::LDATE,
            log::LTIME,
            log::LMICROSECONDS,
            log::LLONGFILE,
            log::LSHORTFILE,
            log::LUTC,
            log::LMSGPREFIX,
            log::LSTD_FLAGS
        ],
        [1, 2, 4, 8, 16, 32, 64, 3]
    );
}

#[test]
fn headers_for_every_flag_combination() {
    // Go's TestAll builds the expected header from the flags the same way. The
    // instant is UTC, so every case adds LUTC; the local zone is covered by
    // tests/log_local.rs, as Go's tests pin LUTC for fixed instants too.
    let when = t(2009, 1, 23, 1, 23, 23, 123_123_456, 0);
    for flags in 0..128 {
        let buf = Buf::default();
        let l = Logger::new(buf.clone(), "pfx:", flags | log::LUTC);
        l.output_at(&when, None, "hello").unwrap();
        let mut want = String::new();
        if flags & log::LMSGPREFIX == 0 {
            want += "pfx:";
        }
        if flags & log::LDATE != 0 {
            want += "2009/01/23 ";
        }
        if flags & (log::LTIME | log::LMICROSECONDS) != 0 {
            want += "01:23:23";
            if flags & log::LMICROSECONDS != 0 {
                want += ".123123";
            }
            want += " ";
        }
        if flags & (log::LSHORTFILE | log::LLONGFILE) != 0 {
            want += "???:0: ";
        }
        if flags & log::LMSGPREFIX != 0 {
            want += "pfx:";
        }
        want += "hello\n";
        assert_eq!(buf.string(), want, "flags {flags}");
    }
}

#[test]
fn prefix_and_flags_round_trip() {
    let l = Logger::new(Buf::default(), "a", log::LSTD_FLAGS);
    assert_eq!((l.prefix().as_str(), l.flags()), ("a", 3));
    l.set_prefix("b");
    l.set_flags(log::LUTC);
    assert_eq!((l.prefix().as_str(), l.flags()), ("b", 32));
}

#[test]
fn output_adds_one_newline_only_when_missing() {
    let buf = Buf::default();
    let l = Logger::new(buf.clone(), "", 0);
    l.print(format_args!("no newline"));
    l.print(format_args!("with newline\n"));
    l.println(format_args!("println"));
    l.printf(format_args!("{}-{}", 1, "x"));
    l.print(format_args!(""));
    l.output(2, "out").unwrap();
    assert_eq!(
        buf.string(),
        "no newline\nwith newline\nprintln\n1-x\n\nout\n"
    );
}

#[test]
fn shortfile_and_longfile_report_the_calling_line() {
    let buf = Buf::default();
    let l = Logger::new(buf.clone(), "", log::LSHORTFILE);
    l.print(format_args!("short"));
    let line = line!() - 1;
    l.set_flags(log::LLONGFILE);
    l.print(format_args!("long"));
    let line2 = line!() - 1;
    l.set_flags(log::LSHORTFILE | log::LLONGFILE);
    l.output(1, "both").unwrap();
    let line3 = line!() - 1;
    let out = buf.string();
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], format!("log.rs:{line}: short"));
    assert!(lines[1].starts_with("tests/log.rs:") || lines[1].contains("/tests/log.rs:"));
    assert!(
        lines[1].ends_with(&format!(":{line2}: long")),
        "{}",
        lines[1]
    );
    assert_eq!(lines[2], format!("log.rs:{line3}: both"));
}

#[test]
fn panic_writes_then_panics_with_the_message() {
    let buf = Buf::default();
    let l = Logger::new(buf.clone(), "", 0);
    let err = catch_unwind(std::panic::AssertUnwindSafe(|| {
        l.panicf(format_args!("boom {}", 7))
    }))
    .unwrap_err();
    assert_eq!(err.downcast_ref::<String>().unwrap(), "boom 7");
    assert_eq!(buf.string(), "boom 7\n");
    let err = catch_unwind(std::panic::AssertUnwindSafe(|| {
        l.panicln(format_args!("x"))
    }))
    .unwrap_err();
    assert_eq!(err.downcast_ref::<String>().unwrap(), "x\n");
}

#[test]
fn fatal_exits_with_status_one() {
    if std::env::var("LOG_TEST_FATAL").is_ok() {
        let l = Logger::new(io::stdout(), "fatal: ", 0);
        l.fatalf(format_args!("bye {}", 1));
    }
    let exe = std::env::current_exe().unwrap();
    let out = std::process::Command::new(exe)
        .args(["--exact", "fatal_exits_with_status_one", "--nocapture"])
        .env("LOG_TEST_FATAL", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).contains("fatal: bye 1\n"));
}

#[test]
fn set_output_and_writer_handle() {
    let a = Buf::default();
    let b = Buf::default();
    let l = Logger::new(a.clone(), "", 0);
    let mut w = l.writer();
    l.set_output(b.clone());
    w.write_all(b"via handle").unwrap();
    l.print(format_args!("x"));
    assert_eq!(a.string(), "");
    assert_eq!(b.string(), "via handlex\n");
}

#[test]
fn concurrent_lines_stay_whole() {
    let buf = Buf::default();
    let l = Arc::new(Logger::new(buf.clone(), "p ", 0));
    let handles: Vec<_> = (0..8)
        .map(|i| {
            let l = l.clone();
            std::thread::spawn(move || {
                for j in 0..100 {
                    l.printf(format_args!("{i}-{j}"));
                }
            })
        })
        .collect();
    handles.into_iter().for_each(|h| h.join().unwrap());
    let out = buf.string();
    assert_eq!(out.lines().count(), 800);
    assert!(out.lines().all(|l| l.starts_with("p ") && l.contains('-')));
}

// ---------------------------------------------------------------- slog

fn ctx() -> Context {
    Context::background()
}

fn test_time() -> DateTime {
    t(2000, 1, 2, 3, 4, 5, 0, 0)
}

#[test]
fn level_string_table() {
    for (level, want) in [
        (Level(0), "INFO"),
        (LEVEL_ERROR, "ERROR"),
        (Level(LEVEL_ERROR.0 + 2), "ERROR+2"),
        (Level(LEVEL_ERROR.0 - 2), "WARN+2"),
        (LEVEL_WARN, "WARN"),
        (Level(LEVEL_WARN.0 - 1), "INFO+3"),
        (LEVEL_INFO, "INFO"),
        (Level(1), "INFO+1"),
        (Level(-3), "DEBUG+1"),
        (LEVEL_DEBUG, "DEBUG"),
        (Level(LEVEL_DEBUG.0 - 2), "DEBUG-2"),
    ] {
        assert_eq!(level.to_string(), want, "{}", level.0);
        assert_eq!(level.to_string(), want);
    }
}

#[test]
fn level_var_and_leveler() {
    let v = LevelVar::new();
    assert_eq!(v.level(), LEVEL_INFO);
    v.set(LEVEL_WARN);
    assert_eq!(Leveler::level(&v), LEVEL_WARN);
    assert_eq!(v.to_string(), "LevelVar(WARN)");
    v.unmarshal_text(b"debug-2").unwrap();
    assert_eq!(v.level(), Level(-6));
    assert_eq!(v.marshal_text(), b"DEBUG-2");
    let mut b = b"x".to_vec();
    v.append_text(&mut b);
    assert_eq!(b, b"xDEBUG-2");
    assert_eq!(Leveler::level(&LEVEL_ERROR), LEVEL_ERROR);
}

#[test]
fn level_marshal_round_trips() {
    let want = Level(LEVEL_WARN.0 - 3);
    assert_eq!(want.marshal_json(), br#""INFO+1""#);
    let mut got = Level::default();
    got.unmarshal_json(br#""INFO+1""#).unwrap();
    assert_eq!(got, want);
    assert_eq!(want.marshal_text(), b"INFO+1");
    let mut got = Level::default();
    got.unmarshal_text(b"INFO+1").unwrap();
    assert_eq!(got, want);
    let mut buf = vec![0, 0, 0, 0];
    want.append_text(&mut buf);
    assert_eq!(buf, b"\0\0\0\0INFO+1");
}

#[test]
fn level_parse_table_and_errors() {
    for (input, want) in [
        ("DEBUG", LEVEL_DEBUG),
        ("INFO", LEVEL_INFO),
        ("WARN", LEVEL_WARN),
        ("ERROR", LEVEL_ERROR),
        ("debug", LEVEL_DEBUG),
        ("iNfo", LEVEL_INFO),
        ("INFO+87", Level(87)),
        ("Error-18", Level(-10)),
        ("Error-8", LEVEL_INFO),
    ] {
        let mut got = Level::default();
        got.unmarshal_text(input.as_bytes()).unwrap();
        assert_eq!(got, want, "{input}");
    }
    for (input, want) in [
        ("", "unknown name"),
        ("dbg", "unknown name"),
        ("INFO+", "invalid syntax"),
        ("INFO-", "invalid syntax"),
        ("ERROR+23x", "invalid syntax"),
    ] {
        let err = Level::default()
            .unmarshal_text(input.as_bytes())
            .unwrap_err();
        assert!(err.to_string().contains(want), "{input}: {err}");
        assert!(
            err.to_string()
                .starts_with(&format!("slog: level string {:?}", input)),
            "{err}"
        );
    }
    assert_eq!(
        Level::default()
            .unmarshal_json(b"INFO")
            .unwrap_err()
            .to_string(),
        "invalid syntax"
    );
}

#[test]
fn kind_strings() {
    let names = [
        "Any",
        "Bool",
        "Duration",
        "Float64",
        "Int64",
        "String",
        "Time",
        "Uint64",
        "Group",
        "LogValuer",
    ];
    for (k, n) in [
        Kind::Any,
        Kind::Bool,
        Kind::Duration,
        Kind::Float64,
        Kind::Int64,
        Kind::String,
        Kind::Time,
        Kind::Uint64,
        Kind::Group,
        Kind::LogValuer,
    ]
    .into_iter()
    .zip(names)
    {
        assert_eq!(k.to_string(), n);
    }
}

#[test]
fn value_kinds_and_accessors() {
    let when = t(2020, 5, 6, 7, 8, 9, 10, 3600);
    let cases: Vec<(Value, Kind)> = vec![
        (slog::int_value(-3), Kind::Int64),
        (slog::int64_value(-3), Kind::Int64),
        (slog::uint64_value(3), Kind::Uint64),
        (slog::float64_value(1.5), Kind::Float64),
        (slog::bool_value(true), Kind::Bool),
        (slog::string_value("s"), Kind::String),
        (slog::time_value(when), Kind::Time),
        (
            slog::duration_value(Duration::from_nanos(5)),
            Kind::Duration,
        ),
        (slog::group_value(vec![slog::int("a", 1)]), Kind::Group),
        (slog::any_value(7u8), Kind::Uint64),
        (slog::any_value(7i16), Kind::Int64),
        (slog::any_value(1.5f32), Kind::Float64),
        (slog::any_value("x"), Kind::String),
        (slog::any_value(Level(3)), Kind::Any),
        (Value::default(), Kind::Any),
    ];
    for (v, k) in &cases {
        assert_eq!(v.kind(), *k, "{v:?}");
    }
    assert_eq!(cases[0].0.int64(), -3);
    assert_eq!(cases[2].0.uint64(), 3);
    assert_eq!(cases[3].0.float64(), 1.5);
    assert!(cases[4].0.bool());
    assert_eq!(cases[5].0.to_string(), "s");
    assert_eq!(cases[6].0.time(), when);
    assert_eq!(cases[7].0.duration().as_nanos(), 5);
    assert_eq!(cases[8].0.group().len(), 1);
    assert!(Value::default().any().is_none());
    let lvl = cases[13].0.any().unwrap();
    assert_eq!(lvl.as_any().downcast_ref::<Level>(), Some(&Level(3)));
    // Wrong-kind accessors panic like Go.
    let e = catch_unwind(|| slog::int_value(1).bool()).unwrap_err();
    assert_eq!(
        e.downcast_ref::<String>().unwrap(),
        "Value kind is Int64, not Bool"
    );
}

#[test]
fn value_string_forms() {
    assert_eq!(slog::float64_value(1e21).to_string(), "1e+21");
    assert_eq!(slog::float64_value(0.1).to_string(), "0.1");
    assert_eq!(
        slog::duration_value(Duration::from_nanos(3_661_000_000_000)).to_string(),
        "1h1m1s"
    );
    assert_eq!(
        slog::uint64_value(u64::MAX).to_string(),
        "18446744073709551615"
    );
    assert_eq!(
        slog::time_value(t(2000, 1, 2, 3, 4, 5, 123_000_000, 0)).to_string(),
        "2000-01-02 03:04:05.123 +0000 UTC"
    );
    assert_eq!(
        slog::time_value(t(2000, 1, 2, 3, 4, 5, 0, 19800)).to_string(),
        "2000-01-02 03:04:05 +0530 +0530"
    );
    assert_eq!(
        slog::group_value(vec![slog::int("a", 1), slog::string("b", "x")]).to_string(),
        "[a=1 b=x]"
    );
    assert_eq!(slog::string("k", "v").to_string(), "k=v");
    assert_eq!(Value::default().to_string(), "<nil>");
}

#[test]
fn value_equality() {
    assert!(slog::int_value(1).equal(&slog::int_value(1)));
    assert!(!slog::int_value(1).equal(&slog::uint64_value(1)));
    assert!(slog::float64_value(0.0).equal(&slog::float64_value(-0.0)));
    assert!(!slog::float64_value(f64::NAN).equal(&slog::float64_value(f64::NAN)));
    let a = slog::time_value(t(2000, 1, 1, 1, 0, 0, 0, 3600));
    let b = slog::time_value(t(2000, 1, 1, 0, 0, 0, 0, 0));
    assert!(a.equal(&b));
    let g1 = slog::group_value(vec![slog::int("a", 1)]);
    let g2 = slog::group_value(vec![slog::int("a", 1)]);
    let g3 = slog::group_value(vec![slog::int("a", 2)]);
    assert!(g1.equal(&g2) && !g1.equal(&g3));
    assert!(slog::any_value(Level(1)).equal(&slog::any_value(Level(1))));
    assert!(Value::default().equal(&Value::default()));
    assert!(slog::string("a", "b").equal(&slog::string("a", "b")));
    assert!(!slog::string("a", "b").equal(&slog::string("c", "b")));
}

#[test]
fn group_value_drops_empty_groups() {
    let v = slog::group_value(vec![
        slog::group_attrs("e", vec![]),
        slog::int("a", 1),
        slog::group_attrs("f", vec![slog::group_attrs("g", vec![])]),
    ]);
    // Groups are built bottom-up, so "f" (whose only child is empty) is empty too.
    assert_eq!(v.group().len(), 1);
    assert_eq!(v.group()[0].key, "a");
}

struct Secret;

impl LogValuer for Secret {
    fn log_value(&self) -> Value {
        slog::string_value("REDACTED")
    }
}

struct Chain(usize);

impl LogValuer for Chain {
    fn log_value(&self) -> Value {
        if self.0 == 0 {
            slog::int_value(42)
        } else {
            Value::log_valuer_value(Chain(self.0 - 1))
        }
    }
}

struct Forever;

impl LogValuer for Forever {
    fn log_value(&self) -> Value {
        Value::log_valuer_value(Forever)
    }
}

struct Panics;

impl LogValuer for Panics {
    fn log_value(&self) -> Value {
        panic!("oops")
    }
}

#[test]
fn resolve_follows_chains_and_stops_at_100() {
    assert_eq!(
        Value::log_valuer_value(Secret).resolve().to_string(),
        "REDACTED"
    );
    assert_eq!(Value::log_valuer_value(Chain(98)).resolve().int64(), 42);
    // Go calls LogValue at most maxLogValues (100) times.
    let v = Value::log_valuer_value(Chain(100)).resolve();
    assert_eq!(v.kind(), Kind::Any);
    assert!(v
        .to_string()
        .starts_with("LogValue called too many times on Value of type"));
    assert!(Value::log_valuer_value(Forever)
        .resolve()
        .to_string()
        .contains("too many times"));
    let p = Value::log_valuer_value(Panics).resolve();
    assert!(
        p.to_string().starts_with("LogValue panicked\noops"),
        "{}",
        p.to_string()
    );
    // Non-LogValuer values resolve to themselves.
    assert_eq!(slog::int_value(3).resolve().int64(), 3);
}

#[test]
fn attr_constructors_and_equality() {
    let a = slog::any("k", 1u32);
    assert_eq!(a.key, "k");
    assert_eq!(a.value.kind(), Kind::Uint64);
    assert!(slog::int("a", 1).equal(&slog::int64("a", 1)));
    assert!(slog::bool("a", true).equal(&slog::bool("a", true)));
    assert_eq!(slog::float64("f", 2.5).value.float64(), 2.5);
    assert_eq!(slog::uint64("u", 9).value.uint64(), 9);
    assert_eq!(
        slog::duration("d", Duration::from_nanos(1)).value.kind(),
        Kind::Duration
    );
    assert_eq!(slog::time("t", test_time()).value.kind(), Kind::Time);
    let g = slog::group("g", &["x".into(), 1i64.into(), slog::int("y", 2).into()]);
    assert_eq!(g.value.group().len(), 2);
    assert_eq!(g.value.group()[1].key, "y");
}

#[test]
fn record_attrs_and_clone() {
    let mut r = slog::Record::new(test_time(), LEVEL_INFO, "msg", None);
    assert_eq!(r.num_attrs(), 0);
    r.add_attrs(&[slog::int("a", 1), slog::group_attrs("empty", vec![])]);
    r.add(&["b".into(), 2i64.into(), "dangling".into()]);
    r.add(&[slog::int("c", 3).into(), 5i64.into()]);
    assert_eq!(r.num_attrs(), 5);
    let mut keys = vec![];
    r.attrs(|a| {
        keys.push(a.key.clone());
        true
    });
    assert_eq!(keys, ["a", "b", "!BADKEY", "c", "!BADKEY"]);
    let mut n = 0;
    r.attrs(|_| {
        n += 1;
        n < 2
    });
    assert_eq!(n, 2);
    let mut c = r.clone();
    c.add_attrs(&[slog::int("d", 4)]);
    assert_eq!((r.num_attrs(), c.num_attrs()), (5, 6));
    assert!(r.source().is_none());
}

#[test]
fn record_source_comes_from_the_call_site() {
    let r = slog::Record::new(test_time(), LEVEL_INFO, "m", Some(Location::caller()));
    let line = line!() - 1;
    let src = r.source().unwrap();
    assert_eq!(src.line, i64::from(line));
    assert!(src.file.ends_with("tests/log.rs"), "{}", src.file);
    assert_eq!(src.function, "");
}

fn handler_output(
    json_handler: bool,
    opts: HandlerOptions,
    with: impl Fn(Arc<dyn Handler>) -> Arc<dyn Handler>,
    attrs: Vec<Attr>,
) -> String {
    let buf = Buf::default();
    let h: Arc<dyn Handler> = if json_handler {
        Arc::new(JSONHandler::new(buf.clone(), Some(opts)))
    } else {
        Arc::new(TextHandler::new(buf.clone(), Some(opts)))
    };
    let h = with(h);
    let mut r = slog::Record::new(test_time(), LEVEL_INFO, "message", None);
    r.add_attrs(&attrs);
    h.handle(&ctx(), r).unwrap();
    let out = buf.string();
    out.strip_suffix('\n').unwrap().to_owned()
}

fn remove_keys(keys: &'static [&'static str]) -> HandlerOptions {
    HandlerOptions {
        replace_attr: Some(Arc::new(move |groups: &[String], a: Attr| {
            if groups.is_empty() && keys.contains(&a.key.as_str()) {
                Attr::default()
            } else {
                a
            }
        })),
        ..Default::default()
    }
}

fn upper_key() -> HandlerOptions {
    HandlerOptions {
        replace_attr: Some(Arc::new(|_: &[String], mut a: Attr| {
            a.key = a.key.to_uppercase();
            a
        })),
        ..Default::default()
    }
}

struct LogName(&'static str, &'static str);

impl LogValuer for LogName {
    fn log_value(&self) -> Value {
        slog::group_value(vec![
            slog::string("first", self.0),
            slog::string("last", self.1),
        ])
    }
}

struct Case {
    name: &'static str,
    opts: fn() -> HandlerOptions,
    with: fn(Arc<dyn Handler>) -> Arc<dyn Handler>,
    attrs: fn() -> Vec<Attr>,
    text: &'static str,
    json: &'static str,
}

fn std_attrs() -> Vec<Attr> {
    vec![
        slog::string("a", "one"),
        slog::int("b", 2),
        Attr::new("", Value::default()),
    ]
}

fn pre(h: Arc<dyn Handler>) -> Arc<dyn Handler> {
    h.with_attrs(vec![slog::int("pre", 3), slog::string("x", "y")])
}

fn nothing(h: Arc<dyn Handler>) -> Arc<dyn Handler> {
    h
}

fn no_time_level() -> HandlerOptions {
    remove_keys(&["time", "level"])
}

#[test]
fn text_and_json_handler_table() {
    let cases = [
        Case {
            name: "basic",
            opts: HandlerOptions::default,
            with: nothing,
            attrs: std_attrs,
            text: "time=2000-01-02T03:04:05.000Z level=INFO msg=message a=one b=2",
            json: r#"{"time":"2000-01-02T03:04:05Z","level":"INFO","msg":"message","a":"one","b":2}"#,
        },
        Case {
            name: "empty key",
            opts: HandlerOptions::default,
            with: nothing,
            attrs: || {
                let mut a = std_attrs();
                a.push(slog::any("", "v"));
                a
            },
            text: r#"time=2000-01-02T03:04:05.000Z level=INFO msg=message a=one b=2 ""=v"#,
            json: r#"{"time":"2000-01-02T03:04:05Z","level":"INFO","msg":"message","a":"one","b":2,"":"v"}"#,
        },
        Case {
            name: "cap keys",
            opts: upper_key,
            with: nothing,
            attrs: std_attrs,
            text: "TIME=2000-01-02T03:04:05.000Z LEVEL=INFO MSG=message A=one B=2",
            json: r#"{"TIME":"2000-01-02T03:04:05Z","LEVEL":"INFO","MSG":"message","A":"one","B":2}"#,
        },
        Case {
            name: "remove all",
            opts: || HandlerOptions {
                replace_attr: Some(Arc::new(|_: &[String], _a: Attr| Attr::default())),
                ..Default::default()
            },
            with: nothing,
            attrs: std_attrs,
            text: "",
            json: "{}",
        },
        Case {
            name: "preformatted",
            opts: HandlerOptions::default,
            with: pre,
            attrs: std_attrs,
            text: "time=2000-01-02T03:04:05.000Z level=INFO msg=message pre=3 x=y a=one b=2",
            json: r#"{"time":"2000-01-02T03:04:05Z","level":"INFO","msg":"message","pre":3,"x":"y","a":"one","b":2}"#,
        },
        Case {
            name: "preformatted cap keys",
            opts: upper_key,
            with: pre,
            attrs: std_attrs,
            text: "TIME=2000-01-02T03:04:05.000Z LEVEL=INFO MSG=message PRE=3 X=y A=one B=2",
            json: r#"{"TIME":"2000-01-02T03:04:05Z","LEVEL":"INFO","MSG":"message","PRE":3,"X":"y","A":"one","B":2}"#,
        },
        Case {
            name: "remove built-in",
            opts: || remove_keys(&["time", "level", "msg"]),
            with: nothing,
            attrs: std_attrs,
            text: "a=one b=2",
            json: r#"{"a":"one","b":2}"#,
        },
        Case {
            name: "preformatted remove built-in",
            opts: || remove_keys(&["time", "level", "msg"]),
            with: pre,
            attrs: std_attrs,
            text: "pre=3 x=y a=one b=2",
            json: r#"{"pre":3,"x":"y","a":"one","b":2}"#,
        },
        Case {
            name: "groups",
            opts: no_time_level,
            with: nothing,
            attrs: || {
                vec![
                    slog::int("a", 1),
                    slog::group_attrs(
                        "g",
                        vec![
                            slog::int("b", 2),
                            slog::group_attrs("h", vec![slog::int("c", 3)]),
                            slog::int("d", 4),
                        ],
                    ),
                    slog::int("e", 5),
                ]
            },
            text: "msg=message a=1 g.b=2 g.h.c=3 g.d=4 e=5",
            json: r#"{"msg":"message","a":1,"g":{"b":2,"h":{"c":3},"d":4},"e":5}"#,
        },
        Case {
            name: "empty group",
            opts: no_time_level,
            with: nothing,
            attrs: || {
                vec![
                    slog::group_attrs("g", vec![]),
                    slog::group_attrs("h", vec![slog::int("a", 1)]),
                ]
            },
            text: "msg=message h.a=1",
            json: r#"{"msg":"message","h":{"a":1}}"#,
        },
        Case {
            name: "nested empty group",
            opts: no_time_level,
            with: nothing,
            attrs: || {
                vec![slog::group_attrs(
                    "g",
                    vec![slog::group_attrs(
                        "h",
                        vec![
                            slog::group_attrs("i", vec![]),
                            slog::group_attrs("j", vec![]),
                        ],
                    )],
                )]
            },
            text: "msg=message",
            json: r#"{"msg":"message"}"#,
        },
        Case {
            name: "nested non-empty group",
            opts: no_time_level,
            with: nothing,
            attrs: || {
                vec![slog::group_attrs(
                    "g",
                    vec![slog::group_attrs(
                        "h",
                        vec![
                            slog::group_attrs("i", vec![]),
                            slog::group_attrs("j", vec![slog::int("a", 1)]),
                        ],
                    )],
                )]
            },
            text: "msg=message g.h.j.a=1",
            json: r#"{"msg":"message","g":{"h":{"j":{"a":1}}}}"#,
        },
        Case {
            name: "escapes",
            opts: no_time_level,
            with: nothing,
            attrs: || {
                vec![
                    slog::string("a b", "x\t\n\0y"),
                    slog::group_attrs(
                        " b.c=\"\\x2E\t",
                        vec![slog::string("d=e", "f.g\""), slog::int("m.d", 1)],
                    ),
                ]
            },
            text: r#"msg=message "a b"="x\t\n\x00y" " b.c=\"\\x2E\t.d=e"="f.g\"" " b.c=\"\\x2E\t.m.d"=1"#,
            json: r#"{"msg":"message","a b":"x\t\n\u0000y"," b.c=\"\\x2E\t":{"d=e":"f.g\"","m.d":1}}"#,
        },
        Case {
            name: "LogValuer",
            opts: no_time_level,
            with: nothing,
            attrs: || {
                vec![
                    slog::int("a", 1),
                    Attr::new("name", Value::log_valuer_value(LogName("Ren", "Hoek"))),
                    slog::int("b", 2),
                ]
            },
            text: "msg=message a=1 name.first=Ren name.last=Hoek b=2",
            json: r#"{"msg":"message","a":1,"name":{"first":"Ren","last":"Hoek"},"b":2}"#,
        },
        Case {
            name: "with-group",
            opts: no_time_level,
            with: |h| pre(h).with_group("s"),
            attrs: std_attrs,
            text: "msg=message pre=3 x=y s.a=one s.b=2",
            json: r#"{"msg":"message","pre":3,"x":"y","s":{"a":"one","b":2}}"#,
        },
        Case {
            name: "preformatted with-groups",
            opts: no_time_level,
            with: |h| {
                h.with_attrs(vec![slog::int("p1", 1)])
                    .with_group("s1")
                    .with_attrs(vec![slog::int("p2", 2)])
                    .with_group("s2")
            },
            attrs: std_attrs,
            text: "msg=message p1=1 s1.p2=2 s1.s2.a=one s1.s2.b=2",
            json: r#"{"msg":"message","p1":1,"s1":{"p2":2,"s2":{"a":"one","b":2}}}"#,
        },
        Case {
            name: "two with-groups",
            opts: no_time_level,
            with: |h| {
                h.with_attrs(vec![slog::int("p1", 1)])
                    .with_group("s1")
                    .with_group("s2")
            },
            attrs: std_attrs,
            text: "msg=message p1=1 s1.s2.a=one s1.s2.b=2",
            json: r#"{"msg":"message","p1":1,"s1":{"s2":{"a":"one","b":2}}}"#,
        },
        Case {
            name: "empty with-groups",
            opts: no_time_level,
            with: |h| h.with_group("x").with_group("y"),
            attrs: Vec::new,
            text: "msg=message",
            json: r#"{"msg":"message"}"#,
        },
        Case {
            name: "empty-key group inlines",
            opts: no_time_level,
            with: nothing,
            attrs: || {
                vec![slog::group_attrs(
                    "",
                    vec![slog::int("a", 1), slog::int("b", 2)],
                )]
            },
            text: "msg=message a=1 b=2",
            json: r#"{"msg":"message","a":1,"b":2}"#,
        },
    ];
    for c in &cases {
        assert_eq!(
            handler_output(false, (c.opts)(), c.with, (c.attrs)()),
            c.text,
            "text {}",
            c.name
        );
        assert_eq!(
            handler_output(true, (c.opts)(), c.with, (c.attrs)()),
            c.json,
            "json {}",
            c.name
        );
        // Every JSON line must be valid JSON.
        c.json.parse::<json::Value>().unwrap();
    }
}

#[test]
fn text_handler_value_forms() {
    let line = |a: Attr| handler_output(false, no_time_level(), nothing, vec![a]);
    assert_eq!(line(slog::int("a", 1)), "msg=message a=1");
    assert_eq!(
        line(slog::string("x = y", "qu\"o")),
        r#"msg=message "x = y"="qu\"o""#
    );
    assert_eq!(
        line(slog::any("a", Value::default())),
        "msg=message a=<nil>"
    );
    assert_eq!(
        line(slog::any("e", Value::error(&io::Error::other("bad")))),
        "msg=message e=bad"
    );
    assert_eq!(
        line(Attr::new(
            "b",
            Value::dynamic(slog::Bytes(b"a\"b".to_vec()))
        )),
        r#"msg=message b="a\"b""#
    );
    assert_eq!(line(slog::float64("f", f64::NAN)), "msg=message f=NaN");
    assert_eq!(line(slog::float64("f", 1e21)), "msg=message f=1e+21");
    assert_eq!(
        line(slog::duration("d", Duration::from_nanos(1_500_000_000))),
        "msg=message d=1.5s"
    );
    assert_eq!(
        line(slog::uint64("u", u64::MAX)),
        "msg=message u=18446744073709551615"
    );
    assert_eq!(
        line(slog::time("t", t(2000, 1, 2, 3, 4, 5, 678_999_999, 19800))),
        "msg=message t=2000-01-02T03:04:05.678+05:30"
    );
    assert_eq!(line(slog::string("s", "")), r#"msg=message s="""#);
    assert_eq!(line(slog::string("s", "a=b")), r#"msg=message s="a=b""#);
    assert_eq!(line(slog::string("s", "é")), "msg=message s=é");
    assert_eq!(
        line(slog::string("s", "a\u{2003}b")),
        r#"msg=message s="a\u2003b""#
    );
    assert_eq!(line(slog::any("l", Level(2))), "msg=message l=INFO+2");
    assert_eq!(
        line(slog::any(
            "m",
            (r#"{"b":[1,"x",null],"a":true}"#)
                .parse::<json::Value>()
                .unwrap()
        )),
        "msg=message m=\"map[a:true b:[1 x <nil>]]\""
    );
}

#[test]
fn json_handler_value_forms() {
    let line = |a: Attr| handler_output(true, no_time_level(), nothing, vec![a]);
    assert_eq!(
        line(slog::float64("f", f64::NAN)),
        r#"{"msg":"message","f":"!ERROR:json: unsupported value: NaN"}"#
    );
    assert_eq!(
        line(slog::float64("f", f64::INFINITY)),
        r#"{"msg":"message","f":"!ERROR:json: unsupported value: +Inf"}"#
    );
    assert_eq!(
        line(slog::float64("f", 1e21)),
        r#"{"msg":"message","f":1e+21}"#
    );
    assert_eq!(
        line(slog::float64("f", 1e-7)),
        r#"{"msg":"message","f":1e-7}"#
    );
    assert_eq!(
        line(slog::float64("f", -0.0)),
        r#"{"msg":"message","f":-0}"#
    );
    assert_eq!(
        line(slog::duration("d", Duration::from_nanos(1_500_000_000))),
        r#"{"msg":"message","d":1500000000}"#
    );
    assert_eq!(
        line(slog::any("n", Value::default())),
        r#"{"msg":"message","n":null}"#
    );
    assert_eq!(
        line(slog::any("e", Value::error(&io::Error::other("bad \"x\"")))),
        r#"{"msg":"message","e":"bad \"x\""}"#
    );
    assert_eq!(
        line(Attr::new("b", Value::dynamic(slog::Bytes(vec![0, 1, 2])))),
        r#"{"msg":"message","b":"AAEC"}"#
    );
    assert_eq!(
        line(slog::any(
            "m",
            (r#"{"b":[1,"x<>&",null],"a":true}"#)
                .parse::<json::Value>()
                .unwrap()
        )),
        r#"{"msg":"message","m":{"a":true,"b":[1,"x<>&",null]}}"#
    );
    assert_eq!(
        line(slog::any("l", Level(8))),
        r#"{"msg":"message","l":"ERROR"}"#
    );
    assert_eq!(
        line(slog::string("s", "\u{2028}\u{7f}\u{1f}")),
        "{\"msg\":\"message\",\"s\":\"\\u2028\u{7f}\\u001f\"}"
    );
}

struct BadText;

impl Dynamic for BadText {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn text(&self) -> Result<slog::TextValue, String> {
        Err("text: empty string".into())
    }
    fn json(&self) -> Result<String, String> {
        panic!("json exploded")
    }
}

#[test]
fn dynamic_failures_are_reported_inline() {
    let line_text = handler_output(
        false,
        no_time_level(),
        nothing,
        vec![Attr::new("t", Value::dynamic(BadText))],
    );
    assert_eq!(line_text, r#"msg=message t="!ERROR:text: empty string""#);
    let line_json = handler_output(
        true,
        no_time_level(),
        nothing,
        vec![Attr::new("t", Value::dynamic(BadText))],
    );
    assert_eq!(
        line_json,
        r#"{"msg":"message","t":"!PANIC: json exploded"}"#
    );
}

#[test]
fn source_in_text_and_json() {
    let r = slog::Record::new(test_time(), LEVEL_INFO, "m", Some(Location::caller()));
    let line = line!() - 1;
    let buf = Buf::default();
    let opts = HandlerOptions {
        add_source: true,
        ..Default::default()
    };
    TextHandler::new(buf.clone(), Some(opts.clone()))
        .handle(&ctx(), r.clone())
        .unwrap();
    JSONHandler::new(buf.clone(), Some(opts))
        .handle(&ctx(), r)
        .unwrap();
    let out = buf.string();
    let mut lines = out.lines();
    let text = lines.next().unwrap();
    assert!(
        text.starts_with("time=2000-01-02T03:04:05.000Z level=INFO source=")
            && text.ends_with(&format!("tests/log.rs:{line} msg=m")),
        "{text}"
    );
    let js = lines.next().unwrap().parse::<json::Value>().unwrap();
    let src = js.get("source").unwrap();
    assert_eq!(
        src.get("line").and_then(|v| match v {
            json::Value::Number(n) => n.as_i64(),
            _ => None,
        }),
        Some(i64::from(line))
    );
    assert!(src.get("function").is_none(), "empty function is omitted");
    assert!(matches!(src.get("file"), Some(json::Value::String(f)) if f.ends_with("tests/log.rs")));
}

#[test]
fn replace_attr_sees_groups_and_never_group_attrs() {
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let s2 = seen.clone();
    let opts = HandlerOptions {
        replace_attr: Some(Arc::new(move |groups: &[String], a: Attr| {
            s2.lock().unwrap().push(format!("{:?}:{}", groups, a.key));
            a
        })),
        ..Default::default()
    };
    let out = handler_output(
        false,
        opts,
        |h| h.with_group("w"),
        vec![
            slog::int("a", 1),
            slog::group_attrs("g", vec![slog::int("b", 2)]),
            slog::int("c", 3),
        ],
    );
    assert!(out.ends_with("w.a=1 w.g.b=2 w.c=3"), "{out}");
    let seen = seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        [
            "[]:time",
            "[]:level",
            "[]:msg",
            r#"["w"]:a"#,
            r#"["w", "g"]:b"#,
            r#"["w"]:c"#
        ]
    );
}

#[test]
fn handler_levels_and_enabled() {
    let lv = Arc::new(LevelVar::new());
    let opts = HandlerOptions {
        level: Some(lv.clone()),
        ..Default::default()
    };
    let h = TextHandler::new(Buf::default(), Some(opts));
    let c = ctx();
    assert!(h.enabled(&c, LEVEL_INFO) && !h.enabled(&c, LEVEL_DEBUG));
    lv.set(LEVEL_ERROR);
    assert!(!h.enabled(&c, LEVEL_WARN) && h.enabled(&c, LEVEL_ERROR));
    assert!(!slog::DISCARD_HANDLER.enabled(&c, Level(1000)));
    slog::DISCARD_HANDLER
        .handle(&c, slog::Record::default())
        .unwrap();
    assert!(!slog::DISCARD_HANDLER
        .with_group("g")
        .enabled(&c, LEVEL_ERROR));
    assert!(!slog::DISCARD_HANDLER
        .with_attrs(vec![])
        .enabled(&c, LEVEL_ERROR));
}

#[test]
fn zero_time_is_omitted() {
    let buf = Buf::default();
    let h = TextHandler::new(buf.clone(), None);
    h.handle(&ctx(), slog::Record::default()).unwrap();
    assert_eq!(buf.string(), "level=INFO msg=\"\"\n");
}

#[test]
fn logger_methods_and_args() {
    let buf = Buf::default();
    let h = TextHandler::new(buf.clone(), Some(remove_keys(&["time"])));
    let l = slog::Logger::new(Arc::new(h));
    l.info(
        "hello",
        &["a".into(), 1i64.into(), slog::bool("ok", true).into()],
    );
    l.debug("hidden", &[]);
    l.warn("w", &["dangling".into()]);
    l.error("e", &[7i64.into(), "k".into(), "v".into()]);
    l.with(&["base".into(), "x".into()])
        .with_group("grp")
        .log_attrs(&ctx(), Level(2), "attrs", &[slog::int("n", 1)]);
    l.with_group("").info("same", &[]);
    assert!(l.enabled(&ctx(), LEVEL_INFO) && !l.enabled(&ctx(), LEVEL_DEBUG));
    l.log(&ctx(), LEVEL_ERROR, "logged", &[]);
    l.error_context(&ctx(), "ec", &[]);
    assert_eq!(
        buf.string(),
        "level=INFO msg=hello a=1 ok=true\n\
         level=WARN msg=w !BADKEY=dangling\n\
         level=ERROR msg=e !BADKEY=7 k=v\n\
         level=INFO+2 msg=attrs base=x grp.n=1\n\
         level=INFO msg=same\n\
         level=ERROR msg=logged\n\
         level=ERROR msg=ec\n"
    );
}

#[test]
fn multi_handler_fans_out_and_joins_errors() {
    let a = Buf::default();
    let b = Buf::default();
    let ha: Arc<dyn Handler> = Arc::new(TextHandler::new(
        a.clone(),
        Some(HandlerOptions {
            level: Some(Arc::new(LEVEL_DEBUG)),
            replace_attr: remove_keys(&["time"]).replace_attr,
            ..Default::default()
        }),
    ));
    let hb: Arc<dyn Handler> = Arc::new(JSONHandler::new(b.clone(), Some(remove_keys(&["time"]))));
    let m: MultiHandler = MultiHandler::new(vec![ha, hb]);
    let l = slog::Logger::new(Arc::new(m)).with(&["k".into(), 1i64.into()]);
    l.debug("d", &[]);
    l.info("i", &[]);
    assert_eq!(a.string(), "level=DEBUG msg=d k=1\nlevel=INFO msg=i k=1\n");
    assert_eq!(b.string(), "{\"level\":\"INFO\",\"msg\":\"i\",\"k\":1}\n");

    struct Failing;
    impl Write for Failing {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("disk full"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let bad: Arc<dyn Handler> = Arc::new(TextHandler::new(Failing, None));
    let m = MultiHandler::new(vec![bad.clone(), bad]);
    let err = m.handle(&ctx(), slog::Record::default()).unwrap_err();
    assert_eq!(err.to_string(), "disk full\ndisk full");
    assert!(!MultiHandler::new(vec![]).enabled(&ctx(), LEVEL_ERROR));
}

#[test]
fn error_value_and_json_any_dynamic_forms() {
    let e = ErrorValue::new(&io::Error::other("x"));
    assert_eq!(e.error_message().as_deref(), Some("x"));
    assert_eq!(e.json().unwrap(), "\"x\"");
    let j = JsonAny((r#"[1.5,{"a":null}]"#).parse::<json::Value>().unwrap());
    assert_eq!(j.json().unwrap(), r#"[1.5,{"a":null}]"#);
    assert!(j.dyn_eq(&JsonAny(
        (r#"[1.5,{"a":null}]"#).parse::<json::Value>().unwrap()
    )));
}

// The default logger and `log` bridge touch process-wide state; keep them in
// one test so parallel tests do not interleave.
#[test]
fn default_logger_and_log_bridge() {
    let std_buf = Buf::default();
    log::set_output(std_buf.clone());
    log::set_flags(log::LSHORTFILE);
    slog::info("hello", &["a".into(), 1i64.into()]);
    let line = line!() - 1;
    assert_eq!(std_buf.string(), format!("log.rs:{line}: INFO hello a=1\n"));
    slog::debug("hidden", &[]);
    assert_eq!(std_buf.string().lines().count(), 1);
    let old = slog::set_log_logger_level(LEVEL_DEBUG);
    assert_eq!(old, LEVEL_INFO);
    slog::debug("shown", &[]);
    assert!(std_buf.string().contains(" DEBUG shown\n"));
    slog::set_log_logger_level(old);

    // SetDefault redirects the log package into the new handler.
    let out = Buf::default();
    let h = TextHandler::new(out.clone(), Some(remove_keys(&["time"])));
    let previous = slog::default();
    slog::set_default(slog::Logger::new(Arc::new(h)));
    slog::info("structured", &["k".into(), "v".into()]);
    log::print(format_args!("from log"));
    assert_eq!(log::flags(), 0);
    assert_eq!(
        out.string(),
        "level=INFO msg=structured k=v\nlevel=INFO msg=\"from log\"\n"
    );
    // with() and with_group on the default logger.
    slog::with(&["w".into(), 1i64.into()]).info("m", &[]);
    assert!(out.string().ends_with("level=INFO msg=m w=1\n"));
    slog::set_default(previous);
    log::set_output(io::stderr());
    log::set_flags(log::LSTD_FLAGS);
}

#[test]
fn log_logger_feeds_the_handler() {
    let out = Buf::default();
    let h = Arc::new(JSONHandler::new(out.clone(), Some(remove_keys(&["time"]))));
    let l = slog::log_logger(h, LEVEL_WARN);
    l.print(format_args!("careful\n"));
    assert_eq!(out.string(), "{\"level\":\"WARN\",\"msg\":\"careful\"}\n");
    let disabled = slog::log_logger(Arc::new(slog::DISCARD_HANDLER), LEVEL_ERROR);
    disabled.print(format_args!("nothing"));
}

#[test]
fn source_type_is_comparable_and_dynamic() {
    let s = Source {
        function: "f".into(),
        file: "x.go".into(),
        line: 3,
    };
    assert_eq!(
        s.json().unwrap(),
        r#"{"function":"f","file":"x.go","line":3}"#
    );
    assert_eq!(
        s.text().unwrap(),
        slog::TextValue::Plain("&{Function:f File:x.go Line:3}".into())
    );
    let _: Arg = Arg::from(slog::int("a", 1));
}

#[test]
fn value_in_key_position_is_badkey_but_string_is_a_key() {
    let attrs = |args: &[Arg]| {
        slog::group("g", args)
            .value
            .group()
            .iter()
            .map(|a| format!("{}={}", a.key, a.value))
            .collect::<Vec<_>>()
    };
    // A Go string starts a pair; a slog.Value of string kind does not.
    assert_eq!(attrs(&["k".into(), 1.into()]), ["k=1"]);
    assert_eq!(
        attrs(&[slog::string_value("k").into(), 1.into()]),
        ["!BADKEY=k", "!BADKEY=1"]
    );
    assert_eq!(attrs(&["lone".into()]), ["!BADKEY=lone"]);
}

// -------------------------------------------------------------- syslog

#[cfg(unix)]
mod syslog_tests {
    use rust_stdlib::log::syslog::{self, Priority};
    use std::net::UdpSocket;
    use std::os::unix::net::UnixDatagram;
    use std::time::Duration;

    #[test]
    fn priority_constants_match_go() {
        assert_eq!(syslog::LOG_EMERG.0, 0);
        assert_eq!(syslog::LOG_DEBUG.0, 7);
        assert_eq!(syslog::LOG_USER.0, 8);
        assert_eq!(syslog::LOG_DAEMON.0, 24);
        assert_eq!(syslog::LOG_FTP.0, 88);
        assert_eq!(syslog::LOG_LOCAL0.0, 128);
        assert_eq!(syslog::LOG_LOCAL7.0, 184);
        assert_eq!((syslog::LOG_LOCAL7 | syslog::LOG_DEBUG).0, 191);
    }

    #[test]
    fn invalid_priority_is_rejected() {
        for p in [-1, 192] {
            let e = syslog::dial("udp", "127.0.0.1:1", Priority(p), "t").unwrap_err();
            assert_eq!(e.to_string(), "log/syslog: invalid priority");
        }
    }

    #[test]
    fn udp_messages_use_the_rfc3339_format() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let addr = server.local_addr().unwrap().to_string();
        let w = syslog::dial("udp", &addr, syslog::LOG_USER | syslog::LOG_INFO, "tagx").unwrap();
        let mut buf = [0u8; 1024];
        w.err("oops").unwrap();
        let n = server.recv(&mut buf).unwrap();
        let msg = String::from_utf8_lossy(&buf[..n]).into_owned();
        // <PRI>TIMESTAMP HOST TAG[PID]: MSG\n with the severity replaced.
        assert!(msg.starts_with("<11>"), "{msg}");
        let rest = msg.strip_prefix("<11>").unwrap();
        let (ts, rest) = rest.split_once(' ').unwrap();
        // Go's RFC 3339 stamp in the local zone: `Z` at offset zero, else `±hh:mm`.
        let stamp = rust_stdlib::time::DateTime::parse_rfc3339(ts).unwrap();
        let (_, local_offset) = rust_stdlib::time::now().zone();
        assert_eq!(stamp.offset(), local_offset, "{ts}");
        assert!(ts.len() == 20 || ts.len() == 25, "{ts}");
        assert!(
            rest.ends_with(&format!("tagx[{}]: oops\n", std::process::id())),
            "{msg}"
        );
        // Write uses the dial priority; a trailing newline is not doubled.
        use std::io::Write;
        let mut w2 = w;
        w2.write_all(b"raw\n").unwrap();
        let n = server.recv(&mut buf).unwrap();
        let msg = String::from_utf8_lossy(&buf[..n]).into_owned();
        assert!(
            msg.starts_with("<14>") && msg.ends_with("]: raw\n"),
            "{msg}"
        );
        w2.close().unwrap();
    }

    #[test]
    fn unix_datagram_messages_omit_the_hostname() {
        let dir = std::env::temp_dir().join(format!("syslog-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sock");
        let server = UnixDatagram::bind(&path).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let w = syslog::dial(
            "unixgram",
            path.to_str().unwrap(),
            syslog::LOG_LOCAL3,
            "loc",
        )
        .unwrap();
        w.warning("careful").unwrap();
        let mut buf = [0u8; 1024];
        let n = server.recv(&mut buf).unwrap();
        let msg = String::from_utf8_lossy(&buf[..n]).into_owned();
        assert!(msg.starts_with("<156>"), "{msg}"); // 152 | 4
                                                    // BSD timestamp "Jan _2 15:04:05" is 15 bytes, then " tag[pid]: msg".
        let body = &msg[5..];
        assert_eq!(body.as_bytes()[15], b' ', "{msg}");
        assert!(
            body[16..].starts_with(&format!("loc[{}]: careful", std::process::id())),
            "{msg}"
        );
        let logger = {
            let w =
                syslog::dial("unixgram", path.to_str().unwrap(), syslog::LOG_USER, "lg").unwrap();
            rust_stdlib::log::Logger::new(w, "", 0)
        };
        logger.print(format_args!("through log"));
        let n = server.recv(&mut buf).unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).ends_with("]: through log\n"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_reconnects_after_close_and_reports_dial_errors() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let addr = server.local_addr().unwrap().to_string();
        let w = syslog::dial("udp", &addr, syslog::LOG_USER, "re").unwrap();
        w.close().unwrap();
        w.info("again").unwrap();
        let mut buf = [0u8; 256];
        let n = server.recv(&mut buf).unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).contains("again"));
        assert!(syslog::dial("bogus", "x", syslog::LOG_USER, "t").is_err());
    }
}
