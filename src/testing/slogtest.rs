//! Go's `testing/slogtest`: support for testing implementations of
//! [`slog::Handler`].
//!
//! Go's `map[string]any` results are [`json::Value`] objects: parse the
//! handler's JSON output with `json::Value`'s `FromStr` to build them.

use std::{fmt, sync::Arc};

use crate::{
    context::Context,
    encoding::json,
    log::slog::{
        self, any_value, group, Arg, Attr, Handler, Level, LogValuer, Logger, Record, Value,
    },
    strconv,
};

use super::common::TB;
use super::T;

/// Appends the source position of the check, like Go's `withSource`.
macro_rules! with_source {
    ($s:expr) => {
        concat!($s, " (", file!(), ":", line!(), ")")
    };
}

type Check = Box<dyn Fn(&json::Value) -> String + Send + Sync>;
type Case = fn(&Logger);
type Mod = fn(&mut Record);

struct TestCase {
    name: &'static str,
    explanation: &'static str,
    f: Case,
    mod_: Option<Mod>,
    checks: Vec<Check>,
}

/// A value that `Resolve`s to another one (Go's test helper `replace`).
struct Replace(&'static str);

impl LogValuer for Replace {
    fn log_value(&self) -> Value {
        any_value(self.0)
    }
}

fn s(v: &str) -> Arg {
    Arg::from(v)
}

fn has_key(key: &'static str) -> Check {
    Box::new(move |m| match m {
        json::Value::Object(o) if o.contains_key(key) => String::new(),
        _ => format!("missing key {}", strconv::quote(key)),
    })
}

fn missing_key(key: &'static str) -> Check {
    Box::new(move |m| match m {
        json::Value::Object(o) if o.contains_key(key) => {
            format!("unexpected key {}", strconv::quote(key))
        }
        _ => String::new(),
    })
}

fn has_attr(key: &'static str, want: &'static str) -> Check {
    Box::new(move |m| {
        let problem = has_key(key)(m);
        if !problem.is_empty() {
            return problem;
        }
        let got = m.get(key).expect("checked above");
        if !matches!(got, json::Value::String(g) if g == want) {
            return format!(
                "{}: got {}, want {}",
                strconv::quote(key),
                go_syntax(got),
                strconv::quote(want)
            );
        }
        String::new()
    })
}

fn in_group(name: &'static str, c: Check) -> Check {
    Box::new(move |m| match m.get(name) {
        None => format!("missing group {}", strconv::quote(name)),
        Some(g @ json::Value::Object(_)) => c(g),
        Some(_) => format!(
            "value for group {} is not map[string]any",
            strconv::quote(name)
        ),
    })
}

/// Go's `%#v` of a decoded JSON value.
fn go_syntax(v: &json::Value) -> String {
    match v {
        json::Value::Null => "interface {}(nil)".to_string(),
        json::Value::Bool(b) => b.to_string(),
        json::Value::Number(n) => match n.float64() {
            Ok(f) => strconv::format_float(f, b'g', -1, 64),
            Err(_) => n.to_string(),
        },
        json::Value::String(s) => strconv::quote(s),
        json::Value::Array(a) => {
            let items: Vec<String> = a.iter().map(go_syntax).collect();
            format!("[]interface {{}}{{{}}}", items.join(", "))
        }
        json::Value::Object(o) => {
            let items: Vec<String> = o
                .iter()
                .map(|(k, v)| format!("{}:{}", strconv::quote(k), go_syntax(v)))
                .collect();
            format!("map[string]interface {{}}{{{}}}", items.join(", "))
        }
    }
}

fn cases() -> Vec<TestCase> {
    let time = slog::TIME_KEY;
    let level = slog::LEVEL_KEY;
    let message = slog::MESSAGE_KEY;
    let source = slog::SOURCE_KEY;
    vec![
        TestCase {
            name: "built-ins",
            explanation: with_source!(
                "this test expects slog.TimeKey, slog.LevelKey and slog.MessageKey"
            ),
            f: |l| l.info("message", &[]),
            mod_: None,
            checks: vec![has_key(time), has_key(level), has_attr(message, "message")],
        },
        TestCase {
            name: "attrs",
            explanation: with_source!(
                "a Handler should output attributes passed to the logging function"
            ),
            f: |l| l.info("message", &[s("k"), s("v")]),
            mod_: None,
            checks: vec![has_attr("k", "v")],
        },
        TestCase {
            name: "empty-attr",
            explanation: with_source!("a Handler should ignore an empty Attr"),
            f: |l| {
                l.info(
                    "msg",
                    &[
                        s("a"),
                        s("b"),
                        s(""),
                        Arg::Value(Value::Any(None)),
                        s("c"),
                        s("d"),
                    ],
                )
            },
            mod_: None,
            checks: vec![has_attr("a", "b"), missing_key(""), has_attr("c", "d")],
        },
        TestCase {
            name: "zero-time",
            explanation: with_source!("a Handler should ignore a zero Record.Time"),
            f: |l| l.info("msg", &[s("k"), s("v")]),
            mod_: Some(|r| r.time = slog::zero_time()),
            checks: vec![missing_key(time)],
        },
        TestCase {
            name: "WithAttrs",
            explanation: with_source!(
                "a Handler should include the attributes from the WithAttrs method"
            ),
            f: |l| l.with(&[s("a"), s("b")]).info("msg", &[s("k"), s("v")]),
            mod_: None,
            checks: vec![has_attr("a", "b"), has_attr("k", "v")],
        },
        TestCase {
            name: "groups",
            explanation: with_source!("a Handler should handle Group attributes"),
            f: |l| {
                l.info(
                    "msg",
                    &[
                        s("a"),
                        s("b"),
                        Arg::from(group("G", &[Arg::from(slog::string("c", "d"))])),
                        s("e"),
                        s("f"),
                    ],
                )
            },
            mod_: None,
            checks: vec![
                has_attr("a", "b"),
                in_group("G", has_attr("c", "d")),
                has_attr("e", "f"),
            ],
        },
        TestCase {
            name: "empty-group",
            explanation: with_source!("a Handler should ignore an empty group"),
            f: |l| {
                l.info(
                    "msg",
                    &[s("a"), s("b"), Arg::from(group("G", &[])), s("e"), s("f")],
                )
            },
            mod_: None,
            checks: vec![has_attr("a", "b"), missing_key("G"), has_attr("e", "f")],
        },
        TestCase {
            name: "inline-group",
            explanation: with_source!(
                "a Handler should inline the Attrs of a group with an empty key"
            ),
            f: |l| {
                l.info(
                    "msg",
                    &[
                        s("a"),
                        s("b"),
                        Arg::from(group("", &[Arg::from(slog::string("c", "d"))])),
                        s("e"),
                        s("f"),
                    ],
                )
            },
            mod_: None,
            checks: vec![has_attr("a", "b"), has_attr("c", "d"), has_attr("e", "f")],
        },
        TestCase {
            name: "WithGroup",
            explanation: with_source!("a Handler should handle the WithGroup method"),
            f: |l| l.with_group("G").info("msg", &[s("a"), s("b")]),
            mod_: None,
            checks: vec![
                has_key(time),
                has_key(level),
                has_attr(message, "msg"),
                missing_key("a"),
                in_group("G", has_attr("a", "b")),
            ],
        },
        TestCase {
            name: "multi-With",
            explanation: with_source!(
                "a Handler should handle multiple WithGroup and WithAttr calls"
            ),
            f: |l| {
                l.with(&[s("a"), s("b")])
                    .with_group("G")
                    .with(&[s("c"), s("d")])
                    .with_group("H")
                    .info("msg", &[s("e"), s("f")])
            },
            mod_: None,
            checks: vec![
                has_key(time),
                has_key(level),
                has_attr(message, "msg"),
                has_attr("a", "b"),
                in_group("G", has_attr("c", "d")),
                in_group("G", in_group("H", has_attr("e", "f"))),
            ],
        },
        TestCase {
            name: "empty-group-record",
            explanation: with_source!(
                "a Handler should not output groups if there are no attributes"
            ),
            f: |l| {
                l.with(&[s("a"), s("b")])
                    .with_group("G")
                    .with(&[s("c"), s("d")])
                    .with_group("H")
                    .info("msg", &[])
            },
            mod_: None,
            checks: vec![
                has_key(time),
                has_key(level),
                has_attr(message, "msg"),
                has_attr("a", "b"),
                in_group("G", has_attr("c", "d")),
                in_group("G", missing_key("H")),
            ],
        },
        TestCase {
            name: "nested-empty-group-record",
            explanation: with_source!(
                "a Handler should not output nested groups if there are no attributes"
            ),
            f: |l| {
                l.with(&[s("a"), s("b")])
                    .with_group("G")
                    .with(&[s("c"), s("d")])
                    .with_group("H")
                    .with_group("I")
                    .info("msg", &[])
            },
            mod_: None,
            checks: vec![
                has_key(time),
                has_key(level),
                has_attr(message, "msg"),
                has_attr("a", "b"),
                in_group("G", has_attr("c", "d")),
                in_group("G", missing_key("H")),
                in_group("G", missing_key("I")),
            ],
        },
        TestCase {
            name: "resolve",
            explanation: with_source!("a Handler should call Resolve on attribute values"),
            f: |l| {
                l.info(
                    "msg",
                    &[
                        s("k"),
                        Arg::Value(Value::log_valuer_value(Replace("replaced"))),
                    ],
                )
            },
            mod_: None,
            checks: vec![has_attr("k", "replaced")],
        },
        TestCase {
            name: "resolve-groups",
            explanation: with_source!(
                "a Handler should call Resolve on attribute values in groups"
            ),
            f: |l| {
                l.info(
                    "msg",
                    &[Arg::from(group(
                        "G",
                        &[
                            Arg::from(slog::string("a", "v1")),
                            Arg::from(slog::any("b", Value::log_valuer_value(Replace("v2")))),
                        ],
                    ))],
                )
            },
            mod_: None,
            checks: vec![
                in_group("G", has_attr("a", "v1")),
                in_group("G", has_attr("b", "v2")),
            ],
        },
        TestCase {
            name: "resolve-WithAttrs",
            explanation: with_source!(
                "a Handler should call Resolve on attribute values from WithAttrs"
            ),
            f: |l| {
                let l = l.with(&[
                    s("k"),
                    Arg::Value(Value::log_valuer_value(Replace("replaced"))),
                ]);
                l.info("msg", &[]);
            },
            mod_: None,
            checks: vec![has_attr("k", "replaced")],
        },
        TestCase {
            name: "resolve-WithAttrs-groups",
            explanation: with_source!(
                "a Handler should call Resolve on attribute values in groups from WithAttrs"
            ),
            f: |l| {
                let l = l.with(&[Arg::from(group(
                    "G",
                    &[
                        Arg::from(slog::string("a", "v1")),
                        Arg::from(slog::any("b", Value::log_valuer_value(Replace("v2")))),
                    ],
                ))]);
                l.info("msg", &[]);
            },
            mod_: None,
            checks: vec![
                in_group("G", has_attr("a", "v1")),
                in_group("G", has_attr("b", "v2")),
            ],
        },
        TestCase {
            name: "empty-PC",
            explanation: with_source!("a Handler should not output SourceKey if the PC is zero"),
            f: |l| l.info("message", &[]),
            mod_: Some(|r| r.pc = None),
            checks: vec![missing_key(source)],
        },
    ]
}

/// A handler that modifies each record before passing it on. As in Go (the
/// embedded `Handler`), `with_attrs` and `with_group` return the wrapped
/// handler's results unwrapped.
struct Wrapper {
    h: Arc<dyn Handler>,
    mod_: Mod,
}

impl Handler for Wrapper {
    fn enabled(&self, ctx: &Context, level: Level) -> bool {
        self.h.enabled(ctx, level)
    }

    fn handle(&self, ctx: &Context, mut r: Record) -> std::io::Result<()> {
        (self.mod_)(&mut r);
        self.h.handle(ctx, r)
    }

    fn with_attrs(&self, attrs: Vec<Attr>) -> Arc<dyn Handler> {
        self.h.with_attrs(attrs)
    }

    fn with_group(&self, name: &str) -> Arc<dyn Handler> {
        self.h.with_group(name)
    }
}

/// The problems found by [`test_handler`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestHandlerError {
    /// One message per misbehaviour, in test order.
    pub errors: Vec<String>,
}

impl fmt::Display for TestHandlerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.errors.join("\n"))
    }
}

impl std::error::Error for TestHandlerError {}

/// Go's `slogtest.TestHandler`: tests a [`Handler`].
///
/// It installs the handler in a [`Logger`] and makes several calls to the
/// logger's output methods. The handler should be enabled for levels Info
/// and above. `results` is called after all such calls and must return one
/// JSON object per call, whose keys and values correspond to the handler's
/// output; each group is its own nested object, and the standard keys
/// [`slog::TIME_KEY`], [`slog::LEVEL_KEY`] and [`slog::MESSAGE_KEY`] are
/// used. If the handler outputs JSON, `json::Value`'s `FromStr` creates the right
/// structure. If a handler intentionally drops an attribute that is checked,
/// `results` should check for its absence and add it to the object.
pub fn test_handler(
    h: Arc<dyn Handler>,
    results: impl FnOnce() -> Vec<json::Value>,
) -> Result<(), TestHandlerError> {
    let cases = cases();
    for c in &cases {
        let ht: Arc<dyn Handler> = match c.mod_ {
            Some(m) => Arc::new(Wrapper {
                h: h.clone(),
                mod_: m,
            }),
            None => h.clone(),
        };
        (c.f)(&Logger::new(ht));
    }
    let res = results();
    if res.len() != cases.len() {
        return Err(TestHandlerError {
            errors: vec![format!("got {} results, want {}", res.len(), cases.len())],
        });
    }
    let mut errs = Vec::new();
    for (got, c) in res.iter().zip(&cases) {
        for check in &c.checks {
            let problem = check(got);
            if !problem.is_empty() {
                errs.push(format!("{problem}: {}", c.explanation));
            }
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(TestHandlerError { errors: errs })
    }
}

/// Go's `slogtest.Run`: exercises a handler on the same test cases as
/// [`test_handler`], running each case in a subtest. For each case it calls
/// `new_handler` to get an instance of the handler under test, runs the case,
/// then calls `result` to get the output as a JSON object. If the case fails
/// it calls `t.error`.
pub fn run(
    t: &T,
    new_handler: impl Fn(&T) -> Arc<dyn Handler>,
    result: impl Fn(&T) -> json::Value,
) {
    for c in cases() {
        t.run(c.name, |t| {
            let mut h = new_handler(t);
            if let Some(m) = c.mod_ {
                h = Arc::new(Wrapper { h, mod_: m });
            }
            (c.f)(&Logger::new(h));
            let got = result(t);
            for check in &c.checks {
                let p = check(&got);
                if !p.is_empty() {
                    t.errorf(format_args!("{p}: {}", c.explanation));
                }
            }
        });
    }
}
