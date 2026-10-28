//! Go's `slog.Value`, `Kind`, `Attr`, `LogValuer` and the dynamic (`any`) value trait.
use super::{
    anyval::{write_panic_message, ErrorValue, JsonAny},
    level::Level,
};
use crate::{
    encoding::json,
    strconv,
    time::{DateTime, Duration},
};
use std::{
    any::Any,
    fmt,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::Arc,
};

/// How a text handler prints a dynamic value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextValue {
    /// Printed like a string attribute: quoted only when it needs quoting.
    Plain(String),
    /// Written as is. Used for values already quoted, like Go's `[]byte`.
    Literal(String),
}

/// A Go `any` payload of a [`Value`] of kind [`Kind::Any`].
///
/// Rust has no reflection, so each dynamic type states how Go's handlers would
/// render it: `text` is `fmt` `%+v` (or `encoding.TextMarshaler`), `json` is
/// `json.Marshal`, and `error_message` marks Go `error` values.
pub trait Dynamic: Send + Sync + 'static {
    /// Returns `self` for downcasting, the Rust counterpart of a type assertion.
    fn as_any(&self) -> &dyn Any;
    /// Text-handler rendering. An `Err` prints as `!ERROR:<message>`.
    fn text(&self) -> Result<TextValue, String>;
    /// JSON-handler rendering as one complete JSON value. An `Err` prints as
    /// `!ERROR:<message>`.
    fn json(&self) -> Result<String, String>;
    /// For Go `error` values, the `Error()` text. JSON handlers print it as a
    /// plain string instead of calling `json`.
    fn error_message(&self) -> Option<String> {
        None
    }
    /// Go interface equality, used by [`Value::equal`].
    fn dyn_eq(&self, other: &dyn Dynamic) -> bool {
        let _ = other;
        false
    }
    /// The type name used in Go's `%T` messages.
    fn type_name(&self) -> &'static str {
        std::any::type_name_of_val(self)
    }
}

/// Provides a way for a value to resolve itself into another [`Value`]
/// before logging, for example to hide sensitive data or defer expensive work.
pub trait LogValuer: Send + Sync + 'static {
    /// Returns the replacement value.
    fn log_value(&self) -> Value;
    /// The type name used in Go's `%T` messages.
    fn type_name(&self) -> &'static str {
        std::any::type_name_of_val(self)
    }
}

/// The kind of a [`Value`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Any = 0,
    Bool = 1,
    Duration = 2,
    Float64 = 3,
    Int64 = 4,
    String = 5,
    Time = 6,
    Uint64 = 7,
    Group = 8,
    LogValuer = 9,
}

/// Go's `KindAny`.
pub const KIND_ANY: Kind = Kind::Any;
/// Go's `KindBool`.
pub const KIND_BOOL: Kind = Kind::Bool;
/// Go's `KindDuration`.
pub const KIND_DURATION: Kind = Kind::Duration;
/// Go's `KindFloat64`.
pub const KIND_FLOAT64: Kind = Kind::Float64;
/// Go's `KindInt64`.
pub const KIND_INT64: Kind = Kind::Int64;
/// Go's `KindString`.
pub const KIND_STRING: Kind = Kind::String;
/// Go's `KindTime`.
pub const KIND_TIME: Kind = Kind::Time;
/// Go's `KindUint64`.
pub const KIND_UINT64: Kind = Kind::Uint64;
/// Go's `KindGroup`.
pub const KIND_GROUP: Kind = Kind::Group;
/// Go's `KindLogValuer`.
pub const KIND_LOG_VALUER: Kind = Kind::LogValuer;

impl Kind {
    /// The kind's name, e.g. `Int64`.
    fn render(self) -> &'static str {
        const NAMES: [&str; 10] = [
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
        NAMES[self as usize]
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.render())
    }
}

impl Dynamic for Kind {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn text(&self) -> Result<TextValue, String> {
        Ok(TextValue::Plain(self.to_string()))
    }
    fn json(&self) -> Result<String, String> {
        Ok((*self as i32).to_string())
    }
    fn dyn_eq(&self, other: &dyn Dynamic) -> bool {
        other.as_any().downcast_ref::<Self>() == Some(self)
    }
}

/// The zero `time.Time`: January 1, year 1, 00:00:00 UTC.
pub fn zero_time() -> DateTime {
    DateTime::new(1, 1, 1, 0, 0, 0, 0, 0).expect("valid zero time")
}

/// Reports whether `t` is the zero `time.Time` instant.
pub fn is_zero_time(t: &DateTime) -> bool {
    t.unix_seconds() == -62_135_596_800 && t.nanosecond() == 0
}

/// A value that can represent any Go value, but unlike `any`, it can
/// represent most small values without an allocation. The zero `Value`
/// corresponds to `nil`.
#[derive(Clone)]
pub enum Value {
    /// A dynamic value; `None` is Go's `nil` (the zero `Value`).
    Any(Option<Arc<dyn Dynamic>>),
    Bool(bool),
    Duration(Duration),
    Float64(f64),
    Int64(i64),
    String(String),
    Time(DateTime),
    Uint64(u64),
    Group(Vec<Attr>),
    LogValuer(Arc<dyn LogValuer>),
}

impl Default for Value {
    fn default() -> Self {
        Value::Any(None)
    }
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Value({}: {})", self.kind(), self)
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

/// Returns a [`Value`] for a string.
pub fn string_value(value: &str) -> Value {
    Value::String(value.to_owned())
}
/// Returns a [`Value`] for an int.
pub fn int_value(v: isize) -> Value {
    Value::Int64(v as i64)
}
/// Returns a [`Value`] for an `i64`.
pub fn int64_value(v: i64) -> Value {
    Value::Int64(v)
}
/// Returns a [`Value`] for a `u64`.
pub fn uint64_value(v: u64) -> Value {
    Value::Uint64(v)
}
/// Returns a [`Value`] for a floating-point number.
pub fn float64_value(v: f64) -> Value {
    Value::Float64(v)
}
/// Returns a [`Value`] for a bool.
pub fn bool_value(v: bool) -> Value {
    Value::Bool(v)
}
/// Returns a [`Value`] for a time. The zero time loses its zone, as in Go.
pub fn time_value(v: DateTime) -> Value {
    Value::Time(if is_zero_time(&v) { zero_time() } else { v })
}
/// Returns a [`Value`] for a duration.
pub fn duration_value(v: Duration) -> Value {
    Value::Duration(v)
}
/// Returns a [`Value`] for a list of attributes. Empty groups are removed.
pub fn group_value(attrs: Vec<Attr>) -> Value {
    Value::Group(
        attrs
            .into_iter()
            .filter(|a| !a.value.is_empty_group())
            .collect(),
    )
}

/// Returns a [`Value`] for any convertible Rust value, choosing the most
/// specific kind (Go's `AnyValue` type switch).
pub fn any_value(v: impl Into<Value>) -> Value {
    v.into()
}

macro_rules! from_int {
    ($($t:ty => $v:ident as $c:ty),* $(,)?) => {$(
        impl From<$t> for Value {
            fn from(v: $t) -> Value {
                Value::$v(v as $c)
            }
        }
    )*};
}
from_int!(i8 => Int64 as i64, i16 => Int64 as i64, i32 => Int64 as i64, i64 => Int64 as i64,
    isize => Int64 as i64, u8 => Uint64 as u64, u16 => Uint64 as u64, u32 => Uint64 as u64,
    u64 => Uint64 as u64, usize => Uint64 as u64, f64 => Float64 as f64);

impl From<f32> for Value {
    fn from(v: f32) -> Value {
        Value::Float64(f64::from(v))
    }
}
impl From<bool> for Value {
    fn from(v: bool) -> Value {
        Value::Bool(v)
    }
}
impl From<&str> for Value {
    fn from(v: &str) -> Value {
        Value::String(v.to_owned())
    }
}
impl From<String> for Value {
    fn from(v: String) -> Value {
        Value::String(v)
    }
}
impl From<Duration> for Value {
    fn from(v: Duration) -> Value {
        Value::Duration(v)
    }
}
impl From<DateTime> for Value {
    fn from(v: DateTime) -> Value {
        time_value(v)
    }
}
impl From<Vec<Attr>> for Value {
    fn from(v: Vec<Attr>) -> Value {
        group_value(v)
    }
}
impl From<Level> for Value {
    fn from(v: Level) -> Value {
        Value::dynamic(v)
    }
}
impl From<Kind> for Value {
    fn from(v: Kind) -> Value {
        Value::dynamic(v)
    }
}
impl From<Arc<dyn LogValuer>> for Value {
    fn from(v: Arc<dyn LogValuer>) -> Value {
        Value::LogValuer(v)
    }
}
impl From<Arc<dyn Dynamic>> for Value {
    fn from(v: Arc<dyn Dynamic>) -> Value {
        Value::Any(Some(v))
    }
}
impl From<json::Value> for Value {
    fn from(v: json::Value) -> Value {
        Value::dynamic(JsonAny(v))
    }
}

impl Value {
    /// Wraps a [`Dynamic`] value as a [`Kind::Any`] value.
    pub fn dynamic<T: Dynamic>(v: T) -> Value {
        Value::Any(Some(Arc::new(v)))
    }

    /// Wraps a [`LogValuer`] as a [`Kind::LogValuer`] value.
    pub fn log_valuer_value<T: LogValuer>(v: T) -> Value {
        Value::LogValuer(Arc::new(v))
    }

    /// Wraps an error as a [`Kind::Any`] value whose JSON form is its message.
    pub fn error(err: &dyn std::error::Error) -> Value {
        Value::dynamic(ErrorValue::new(err))
    }

    /// Returns the kind of the value.
    pub fn kind(&self) -> Kind {
        match self {
            Value::Any(_) => Kind::Any,
            Value::Bool(_) => Kind::Bool,
            Value::Duration(_) => Kind::Duration,
            Value::Float64(_) => Kind::Float64,
            Value::Int64(_) => Kind::Int64,
            Value::String(_) => Kind::String,
            Value::Time(_) => Kind::Time,
            Value::Uint64(_) => Kind::Uint64,
            Value::Group(_) => Kind::Group,
            Value::LogValuer(_) => Kind::LogValuer,
        }
    }

    /// Returns the dynamic payload of a [`Kind::Any`] value (`None` is Go's
    /// `nil`). Other kinds have typed accessors.
    pub fn any(&self) -> Option<Arc<dyn Dynamic>> {
        match self {
            Value::Any(a) => a.clone(),
            _ => None,
        }
    }

    fn wrong_kind(&self, want: Kind) -> ! {
        panic!("Value kind is {}, not {}", self.kind(), want)
    }

    /// Returns the value as an `i64`, panicking if it is not [`Kind::Int64`].
    pub fn int64(&self) -> i64 {
        match self {
            Value::Int64(v) => *v,
            _ => self.wrong_kind(Kind::Int64),
        }
    }

    /// Returns the value as a `u64`, panicking if it is not [`Kind::Uint64`].
    pub fn uint64(&self) -> u64 {
        match self {
            Value::Uint64(v) => *v,
            _ => self.wrong_kind(Kind::Uint64),
        }
    }

    /// Returns the value as a bool, panicking if it is not [`Kind::Bool`].
    pub fn bool(&self) -> bool {
        match self {
            Value::Bool(v) => *v,
            _ => self.wrong_kind(Kind::Bool),
        }
    }

    /// Returns the value as a duration, panicking if it is not [`Kind::Duration`].
    pub fn duration(&self) -> Duration {
        match self {
            Value::Duration(v) => *v,
            _ => self.wrong_kind(Kind::Duration),
        }
    }

    /// Returns the value as a float, panicking if it is not [`Kind::Float64`].
    pub fn float64(&self) -> f64 {
        match self {
            Value::Float64(v) => *v,
            _ => self.wrong_kind(Kind::Float64),
        }
    }

    /// Returns the value as a time, panicking if it is not [`Kind::Time`].
    pub fn time(&self) -> DateTime {
        match self {
            Value::Time(v) => *v,
            _ => self.wrong_kind(Kind::Time),
        }
    }

    /// Returns the value as a [`LogValuer`], panicking if it is not [`Kind::LogValuer`].
    pub fn log_valuer(&self) -> Arc<dyn LogValuer> {
        match self {
            Value::LogValuer(v) => v.clone(),
            _ => self.wrong_kind(Kind::LogValuer),
        }
    }

    /// Returns the value as a list of attributes, panicking if it is not [`Kind::Group`].
    pub fn group(&self) -> &[Attr] {
        match self {
            Value::Group(v) => v,
            _ => panic!("Group: bad kind"),
        }
    }

    /// Reports whether two values are equal. Any values compare by
    /// [`Dynamic::dyn_eq`] (or pointer identity).
    pub fn equal(&self, w: &Value) -> bool {
        match (self, w) {
            (Value::Int64(a), Value::Int64(b)) => a == b,
            (Value::Uint64(a), Value::Uint64(b)) => a == b,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Duration(a), Value::Duration(b)) => a == b,
            (Value::String(a), Value::String(b)) => a == b,
            (Value::Float64(a), Value::Float64(b)) => a == b,
            (Value::Time(a), Value::Time(b)) => {
                a.unix_seconds() == b.unix_seconds() && a.nanosecond() == b.nanosecond()
            }
            (Value::Any(None), Value::Any(None)) => true,
            (Value::Any(Some(a)), Value::Any(Some(b))) => Arc::ptr_eq(a, b) || a.dyn_eq(b.as_ref()),
            (Value::LogValuer(a), Value::LogValuer(b)) => Arc::ptr_eq(a, b),
            (Value::Group(a), Value::Group(b)) => {
                a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.equal(y))
            }
            _ => false,
        }
    }

    pub(crate) fn is_empty_group(&self) -> bool {
        matches!(self, Value::Group(g) if g.is_empty())
    }

    /// Returns the value formatted as a string, without quoting.
    fn render(&self) -> String {
        match self {
            Value::String(s) => s.clone(),
            Value::Int64(v) => v.to_string(),
            Value::Uint64(v) => v.to_string(),
            Value::Float64(v) => strconv::format_float(*v, b'g', -1, 64),
            Value::Bool(v) => v.to_string(),
            Value::Duration(v) => v.to_string(),
            Value::Time(t) => format_time_string(t),
            Value::Group(g) => {
                let parts: Vec<String> = g.iter().map(ToString::to_string).collect();
                format!("[{}]", parts.join(" "))
            }
            Value::Any(None) => "<nil>".to_owned(),
            Value::Any(Some(a)) => match a.text() {
                Ok(TextValue::Plain(s) | TextValue::Literal(s)) => s,
                Err(e) => format!("%!v(PANIC=String method: {e})"),
            },
            Value::LogValuer(v) => v.type_name().to_owned(),
        }
    }

    /// Repeatedly calls [`LogValuer::log_value`] until the result is not a
    /// `LogValuer`. After 100 calls it returns an error value. A panic in
    /// `log_value` is converted to an error value.
    pub fn resolve(&self) -> Value {
        const MAX_LOG_VALUES: usize = 100;
        let mut v = self.clone();
        let orig = self.clone();
        let result = catch_unwind(AssertUnwindSafe(|| {
            for _ in 0..MAX_LOG_VALUES {
                match &v {
                    Value::LogValuer(lv) => v = lv.log_value(),
                    _ => return v.clone(),
                }
            }
            let name = match &orig {
                Value::LogValuer(lv) => lv.type_name(),
                _ => "?",
            };
            error_value(format!(
                "LogValue called too many times on Value of type {name}"
            ))
        }));
        match result {
            Ok(v) => v,
            Err(payload) => {
                let mut msg = String::from("LogValue panicked\n");
                write_panic_message(&mut msg, payload.as_ref());
                error_value(msg)
            }
        }
    }
}

fn error_value(msg: String) -> Value {
    Value::dynamic(ErrorValue(msg))
}

/// Go's `"2006-01-02 15:04:05.999999999 -0700 MST"` layout.
fn format_time_string(t: &DateTime) -> String {
    let mut s = format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        t.year(),
        t.month(),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    );
    if t.nanosecond() != 0 {
        s.push('.');
        s.push_str(format!("{:09}", t.nanosecond()).trim_end_matches('0'));
    }
    let minutes = t.offset() / 60;
    let zone = format!(
        "{}{:02}{:02}",
        if t.offset() < 0 { '-' } else { '+' },
        minutes.abs() / 60,
        minutes.abs() % 60
    );
    s.push(' ');
    s.push_str(&zone);
    s.push(' ');
    s.push_str(&if t.offset() == 0 {
        "UTC".to_owned()
    } else {
        zone
    });
    s
}

/// A key-value pair.
#[derive(Clone, Debug, Default)]
pub struct Attr {
    pub key: String,
    pub value: Value,
}

impl Attr {
    /// Returns an `Attr` for the given key and value.
    pub fn new(key: &str, value: Value) -> Attr {
        Attr {
            key: key.to_owned(),
            value,
        }
    }

    /// Reports whether two attributes have equal keys and values.
    pub fn equal(&self, b: &Attr) -> bool {
        self.key == b.key && self.value.equal(&b.value)
    }

    /// Returns `key=value`.
    fn render(&self) -> String {
        format!("{}={}", self.key, self.value)
    }

    /// Reports whether the key and value are both the zero value.
    pub(crate) fn is_empty(&self) -> bool {
        self.key.is_empty() && matches!(self.value, Value::Any(None))
    }
}

impl fmt::Display for Attr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

impl Dynamic for Attr {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn text(&self) -> Result<TextValue, String> {
        Ok(TextValue::Plain(format!(
            "{{Key:{} Value:{}}}",
            self.key, self.value
        )))
    }
    fn json(&self) -> Result<String, String> {
        Ok(format!(
            "{{\"Key\":{},\"Value\":{}}}",
            super::anyval::json_string(&self.key),
            super::anyval::json_string(&self.value.to_string())
        ))
    }
}

/// Returns an `Attr` for a string value.
pub fn string(key: &str, value: &str) -> Attr {
    Attr::new(key, string_value(value))
}
/// Converts an int to an `i64` and returns an `Attr` with that value.
pub fn int(key: &str, value: isize) -> Attr {
    Attr::new(key, int_value(value))
}
/// Returns an `Attr` for an `i64`.
pub fn int64(key: &str, value: i64) -> Attr {
    Attr::new(key, int64_value(value))
}
/// Returns an `Attr` for a `u64`.
pub fn uint64(key: &str, v: u64) -> Attr {
    Attr::new(key, uint64_value(v))
}
/// Returns an `Attr` for a floating-point number.
pub fn float64(key: &str, v: f64) -> Attr {
    Attr::new(key, float64_value(v))
}
/// Returns an `Attr` for a bool.
pub fn bool(key: &str, v: bool) -> Attr {
    Attr::new(key, bool_value(v))
}
/// Returns an `Attr` for a time.
pub fn time(key: &str, v: DateTime) -> Attr {
    Attr::new(key, time_value(v))
}
/// Returns an `Attr` for a duration.
pub fn duration(key: &str, v: Duration) -> Attr {
    Attr::new(key, duration_value(v))
}
/// Returns an `Attr` for any convertible value, see [`any_value`].
pub fn any(key: &str, value: impl Into<Value>) -> Attr {
    Attr::new(key, any_value(value))
}
/// Returns an `Attr` for a group of attributes built from alternating
/// key/value arguments, see [`Arg`].
pub fn group(key: &str, args: &[Arg]) -> Attr {
    Attr::new(key, group_value(args_to_attr_slice(args)))
}
/// Returns an `Attr` for a group of attributes.
pub fn group_attrs(key: &str, attrs: Vec<Attr>) -> Attr {
    Attr::new(key, group_value(attrs))
}

/// The key used for an argument without a key.
pub(crate) const BAD_KEY: &str = "!BADKEY";

/// One element of Go's `...any` attribute argument lists: an [`Attr`], a Go
/// `string` ([`Arg::Key`]: a key when it starts a pair, otherwise the value
/// for the previous key), or a [`Value`].
///
/// Go tells a `string` from a `slog.Value` of string kind by dynamic type: the
/// first can be a key, the second cannot (it becomes `!BADKEY`). `&str` and
/// `String` convert to [`Arg::Key`], a [`Value`] (including
/// [`string_value`]) to [`Arg::Value`]. Use [`Arg::value`] for other types
/// that convert into a [`Value`].
#[derive(Clone, Debug)]
pub enum Arg {
    Attr(Attr),
    Key(String),
    Value(Value),
}

impl Arg {
    /// An argument holding `v` as a [`Value`] (never a key).
    pub fn value(v: impl Into<Value>) -> Arg {
        Arg::Value(v.into())
    }
}

impl From<Attr> for Arg {
    fn from(a: Attr) -> Arg {
        Arg::Attr(a)
    }
}
impl From<&str> for Arg {
    fn from(s: &str) -> Arg {
        Arg::Key(s.to_owned())
    }
}
impl From<String> for Arg {
    fn from(s: String) -> Arg {
        Arg::Key(s)
    }
}
macro_rules! arg_from_value {
    ($($t:ty),* $(,)?) => {$(
        impl From<$t> for Arg {
            fn from(v: $t) -> Arg {
                Arg::Value(v.into())
            }
        }
    )*};
}
arg_from_value!(
    Value,
    i8,
    i16,
    i32,
    i64,
    isize,
    u8,
    u16,
    u32,
    u64,
    usize,
    f32,
    f64,
    bool,
    Duration,
    DateTime,
    Vec<Attr>,
    Level,
    Kind,
    Arc<dyn LogValuer>,
    Arc<dyn Dynamic>,
    json::Value,
);

impl Arg {
    fn into_value(self) -> Value {
        match self {
            Arg::Value(v) => v,
            Arg::Key(s) => Value::String(s),
            Arg::Attr(a) => Value::dynamic(a),
        }
    }
}

/// Turns the first one or two arguments into an `Attr` and returns the rest:
/// a string key takes the next argument as value, an `Attr` is used as is, and
/// anything else (including a `Value` of string kind) gets the key `!BADKEY`.
pub(crate) fn args_to_attr(args: &[Arg]) -> (Attr, &[Arg]) {
    match &args[0] {
        Arg::Key(key) => {
            if args.len() == 1 {
                (string(BAD_KEY, key), &[])
            } else {
                (Attr::new(key, args[1].clone().into_value()), &args[2..])
            }
        }
        Arg::Attr(a) => (a.clone(), &args[1..]),
        Arg::Value(v) => (Attr::new(BAD_KEY, v.clone()), &args[1..]),
    }
}

pub(crate) fn args_to_attr_slice(mut args: &[Arg]) -> Vec<Attr> {
    let mut attrs = Vec::new();
    while !args.is_empty() {
        let (a, rest) = args_to_attr(args);
        attrs.push(a);
        args = rest;
    }
    attrs
}

pub(crate) fn count_empty_groups(attrs: &[Attr]) -> usize {
    attrs.iter().filter(|a| a.value.is_empty_group()).count()
}
