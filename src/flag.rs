//! Go's `flag` package: command-line flag definition and parsing.
//!
//! The grammar, error texts and `PrintDefaults` layout are Go's. Flags are
//! defined on a [`FlagSet`] (or the process-wide one behind
//! [`command_line`]) and write into shared [`Ptr`] handles, the Rust
//! counterpart of Go's `*int`, `*string`, ... variables.
//!
//! ```
//! use rust_stdlib::flag::{ErrorHandling, FlagSet};
//! let mut flags = FlagSet::new("demo", ErrorHandling::ContinueOnError);
//! let port = flags.int("port", 8080, "listening `port`");
//! let verbose = flags.bool("v", false, "verbose output");
//! flags.parse(&["-port=9000", "-v", "serve", "-x"])?;
//! assert_eq!(port.get(), 9000);
//! assert!(verbose.get());
//! assert_eq!(flags.args(), ["serve", "-x"]);
//! # Ok::<(), rust_stdlib::flag::Error>(())
//! ```
//!
//! Syntax: `-flag`, `--flag`, `-flag=x` and (non-boolean flags only)
//! `-flag x`. Parsing stops before the first non-flag argument (`-` is one)
//! or after the terminator `--`. Integer flags accept Go syntax (`0x1f`,
//! `0o17`, `1_000`, negative values); boolean flags accept
//! `1 0 t f T F true false TRUE FALSE True False`; duration flags accept
//! [`Duration`]'s `FromStr`.
//!
//! Rust substitutions for Go features that need reflection or untyped values:
//!
//! * [`Value`] has provided methods ([`Value::is_bool_flag`], [`Value::kind`],
//!   [`Value::zero_string`], [`Value::as_getter`]) that replace Go's `boolFlag`
//!   interface, `UnquoteUsage`'s type switch and `isZeroValue`'s reflective
//!   zero value. A custom value without `zero_string` is treated as zero when
//!   its default text is empty.
//! * Usage callbacks receive the [`FlagSet`] (`Fn(&FlagSet)`) instead of
//!   closing over it, and the global `Usage` variable is [`set_usage`] /
//!   [`usage`]. While the command-line set's usage message runs, the
//!   package-level readers ([`print_defaults`], [`nflag`], [`arg`], [`args`],
//!   [`narg`], [`parsed`], [`lookup`], [`visit`], [`visit_all`]) work on a
//!   frozen snapshot of the set, so `flag.Usage = func() { ...;
//!   flag.PrintDefaults() }` behaves as in Go. Modifying the set from inside
//!   the callback (defining or setting flags, parsing) is not possible: the
//!   set is borrowed for the whole parse, so those calls panic with an
//!   explanatory message instead of deadlocking.
//! * Invalid flag definitions panic with Go's message after printing it to the
//!   set's output, as in Go.
use crate::{
    encoding::{TextMarshaler, TextUnmarshaler},
    strconv::{self, quote},
    time::Duration,
};
use std::{
    any::Any,
    collections::{BTreeMap, BTreeSet},
    error, fmt,
    io::{self, Write},
    ops::{Deref, DerefMut},
    panic::Location,
    sync::{Arc, Mutex, MutexGuard},
};

/// Boxed error returned by [`Value::set`] and flag functions.
pub type BoxError = Box<dyn error::Error + Send + Sync>;

/// The errors returned by [`FlagSet::parse`] and [`FlagSet::set`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Go's `flag.ErrHelp`: `-h` or `-help` was given but not defined.
    Help,
    /// Any other failure, with Go's message.
    Other(String),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Help => f.write_str("flag: help requested"),
            Error::Other(text) => f.write_str(text),
        }
    }
}
impl error::Error for Error {}
/// Go's `flag.ErrHelp`.
pub const ERR_HELP: Error = Error::Help;

#[derive(Debug)]
struct Text(String);
impl fmt::Display for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl error::Error for Text {}
fn err_text(text: impl Into<String>) -> BoxError {
    Box::new(Text(text.into()))
}
fn err_parse() -> BoxError {
    err_text("parse error")
}

/// Go's `numError`: syntax and range failures get the short flag texts.
fn num_error(e: strconv::NumError) -> BoxError {
    match e.err {
        strconv::Error::Syntax => err_parse(),
        strconv::Error::Range => err_text("value out of range"),
        _ => Box::new(e),
    }
}

/// A shared, lockable variable: the Rust counterpart of Go's `*T` that flag
/// definitions write into. Cloning shares the same storage.
#[derive(Debug, Default)]
pub struct Ptr<T>(Arc<Mutex<T>>);
impl<T> Clone for Ptr<T> {
    fn clone(&self) -> Self {
        Ptr(Arc::clone(&self.0))
    }
}
impl<T> Ptr<T> {
    pub fn new(value: T) -> Self {
        Ptr(Arc::new(Mutex::new(value)))
    }
    fn lock(&self) -> MutexGuard<'_, T> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn set(&self, value: T) {
        *self.lock() = value;
    }
    /// Run `f` with exclusive access to the value.
    pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        f(&mut self.lock())
    }
}
impl<T: Clone> Ptr<T> {
    pub fn get(&self) -> T {
        self.lock().clone()
    }
}

/// The kind of a built-in flag value, used by [`unquote_usage`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueKind {
    /// Custom values and functions.
    Other,
    Bool,
    Duration,
    Float,
    Int,
    String,
    Uint,
}

/// Go's `flag.Value`: the dynamic value stored in a flag.
pub trait Value: fmt::Display + Send {
    /// Go's `Set`.
    fn set(&mut self, s: &str) -> Result<(), BoxError>;
    /// Go's `IsBoolFlag`: the flag may appear without a value.
    fn is_bool_flag(&self) -> bool {
        false
    }
    /// Stands in for the type switch of `UnquoteUsage`.
    fn kind(&self) -> ValueKind {
        ValueKind::Other
    }
    /// Stands in for `isZeroValue`: the `Display` text of a zero value of this type,
    /// or `None` when unknown (then an empty default text counts as zero).
    fn zero_string(&self) -> Option<String> {
        None
    }
    /// The name of the concrete type, which Go prints with `%v` of the
    /// reflected type in the report of a panicking
    /// [`zero_string`](Value::zero_string). The default is right for every
    /// implementation.
    fn type_name(&self) -> &'static str {
        std::any::type_name::<Self>()
    }
    /// Stands in for the `Value.(Getter)` type assertion.
    fn as_getter(&self) -> Option<&dyn Getter> {
        None
    }
}

/// Go's `flag.Getter`: a [`Value`] that can return its contents.
pub trait Getter: Value {
    fn get(&self) -> Box<dyn Any>;
}

macro_rules! scalar_value {
    ($name:ident($t:ty), bool_flag $bool_flag:expr, kind $kind:expr, zero $zero:expr,
     string |$v:ident| $string:expr, set |$p:ident, $s:ident| $set:expr) => {
        struct $name(Ptr<$t>);
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&{ self.0.with(|$v| $string) })
            }
        }
        impl Value for $name {
            fn set(&mut self, $s: &str) -> Result<(), BoxError> {
                let $p = &self.0;
                $set
            }
            fn is_bool_flag(&self) -> bool {
                $bool_flag
            }
            fn kind(&self) -> ValueKind {
                $kind
            }
            fn zero_string(&self) -> Option<String> {
                Some($zero.to_owned())
            }
            fn as_getter(&self) -> Option<&dyn Getter> {
                Some(self)
            }
        }
        impl Getter for $name {
            fn get(&self) -> Box<dyn Any> {
                Box::new(self.0.get())
            }
        }
    };
}

scalar_value!(BoolValue(bool), bool_flag true, kind ValueKind::Bool, zero "false",
string |v| v.to_string(),
set |p, s| match strconv::parse_bool(s) {
    Ok(v) => {
        p.set(v);
        Ok(())
    }
    Err(_) => {
        p.set(false);
        Err(err_parse())
    }
});
scalar_value!(IntValue(isize), bool_flag false, kind ValueKind::Int, zero "0",
string |v| v.to_string(),
set |p, s| {
    let (v, err) = match strconv::parse_int(s, 0, strconv::INT_SIZE as i32) {
        Ok(v) => (v, None),
        Err(e) => (e.int_value(), Some(e)),
    };
    p.set(v as isize);
    err.map_or(Ok(()), |e| Err(num_error(e)))
});
scalar_value!(Int64Value(i64), bool_flag false, kind ValueKind::Int, zero "0",
string |v| v.to_string(),
set |p, s| {
    let (v, err) = match strconv::parse_int(s, 0, 64) {
        Ok(v) => (v, None),
        Err(e) => (e.int_value(), Some(e)),
    };
    p.set(v);
    err.map_or(Ok(()), |e| Err(num_error(e)))
});
scalar_value!(UintValue(usize), bool_flag false, kind ValueKind::Uint, zero "0",
string |v| v.to_string(),
set |p, s| {
    let (v, err) = match strconv::parse_uint(s, 0, strconv::INT_SIZE as i32) {
        Ok(v) => (v, None),
        Err(e) => (e.uint_value(), Some(e)),
    };
    p.set(v as usize);
    err.map_or(Ok(()), |e| Err(num_error(e)))
});
scalar_value!(Uint64Value(u64), bool_flag false, kind ValueKind::Uint, zero "0",
string |v| v.to_string(),
set |p, s| {
    let (v, err) = match strconv::parse_uint(s, 0, 64) {
        Ok(v) => (v, None),
        Err(e) => (e.uint_value(), Some(e)),
    };
    p.set(v);
    err.map_or(Ok(()), |e| Err(num_error(e)))
});
scalar_value!(StringValue(String), bool_flag false, kind ValueKind::String, zero "",
string |v| v.clone(),
set |p, s| {
    p.set(s.to_owned());
    Ok(())
});
scalar_value!(Float64Value(f64), bool_flag false, kind ValueKind::Float, zero "0",
string |v| strconv::format_float(*v, b'g', -1, 64),
set |p, s| {
    let (v, err) = match strconv::parse_float(s, 64) {
        Ok(v) => (v, None),
        Err(e) => (e.float_value(), Some(e)),
    };
    p.set(v);
    err.map_or(Ok(()), |e| Err(num_error(e)))
});
scalar_value!(DurationValue(Duration), bool_flag false, kind ValueKind::Duration, zero "0s",
string |v| v.to_string(),
set |p, s| match s.parse::<Duration>() {
    Ok(v) => {
        p.set(v);
        Ok(())
    }
    Err(_) => {
        p.set(Duration::from_nanos(0));
        Err(err_parse())
    }
});

struct TextValue<T>(Ptr<T>);
impl<T: TextMarshaler + TextUnmarshaler + Send + 'static> fmt::Display for TextValue<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&{
            self.0.with(|v| match v.marshal_text() {
                Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                Err(_) => String::new(),
            })
        })
    }
}
impl<T: TextMarshaler + TextUnmarshaler + Send + 'static> Value for TextValue<T> {
    fn set(&mut self, s: &str) -> Result<(), BoxError> {
        self.0
            .with(|v| v.unmarshal_text(s.as_bytes()))
            .map_err(|e| err_text(e.to_string()))
    }
    fn zero_string(&self) -> Option<String> {
        Some(String::new())
    }
    fn as_getter(&self) -> Option<&dyn Getter> {
        Some(self)
    }
}
/// `get` returns the [`Ptr`] the flag writes into, as Go returns the pointer.
impl<T: TextMarshaler + TextUnmarshaler + Send + 'static> Getter for TextValue<T> {
    fn get(&self) -> Box<dyn Any> {
        Box::new(self.0.clone())
    }
}

type FuncCallback = Box<dyn FnMut(&str) -> Result<(), BoxError> + Send>;
struct FuncValue(FuncCallback, bool);
impl fmt::Display for FuncValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&{ String::new() })
    }
}
impl Value for FuncValue {
    fn set(&mut self, s: &str) -> Result<(), BoxError> {
        (self.0)(s)
    }
    fn is_bool_flag(&self) -> bool {
        self.1
    }
    fn zero_string(&self) -> Option<String> {
        Some(String::new())
    }
}

/// Go's `flag.ErrorHandling`: what [`FlagSet::parse`] does on failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorHandling {
    /// Return a descriptive error.
    ContinueOnError,
    /// Call `std::process::exit(2)`, or `exit(0)` for `-h`/`-help`.
    ExitOnError,
    /// Panic with the error text.
    PanicOnError,
}

/// Go's `flag.Flag`: the state of one defined flag.
pub struct Flag {
    /// Name as it appears on the command line.
    pub name: String,
    /// Help message.
    pub usage: String,
    /// Value as set.
    pub value: Box<dyn Value>,
    /// Default value as text, for the usage message.
    pub def_value: String,
}
impl fmt::Debug for Flag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Flag")
            .field("name", &self.name)
            .field("usage", &self.usage)
            .field("value", &self.value.to_string())
            .field("def_value", &self.def_value)
            .finish()
    }
}

/// Callback type of [`FlagSet::usage`].
pub type UsageFn = Box<dyn Fn(&FlagSet) + Send>;

/// Go's `flag.FlagSet`: a set of defined flags.
pub struct FlagSet {
    /// Go's `Usage` field; `None` selects the default usage message.
    pub usage: Option<UsageFn>,
    name: String,
    parsed: bool,
    actual: BTreeSet<String>,
    formal: BTreeMap<String, Flag>,
    args: Vec<String>,
    error_handling: ErrorHandling,
    output: Arc<Mutex<Option<Box<dyn Write + Send>>>>,
    undef: BTreeMap<String, String>,
    command_line: bool,
    // Set whenever the set is reached through `command_line()`, including
    // after the caller replaced it, so its usage message gets a frozen view.
    is_current: bool,
}

impl fmt::Debug for FlagSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlagSet")
            .field("name", &self.name)
            .field("parsed", &self.parsed)
            .field("flags", &self.formal.keys().collect::<Vec<_>>())
            .field("args", &self.args)
            .finish()
    }
}

/// The writer returned by [`FlagSet::output`].
pub struct Output<'a>(&'a FlagSet);
impl Write for Output<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write_bytes(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        let mut guard = self.0.output.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_mut() {
            Some(w) => w.flush(),
            None => io::stderr().flush(),
        }
    }
}

/// Go's `UnquoteUsage`: extract a back-quoted name from the usage string, or
/// infer one from the value's type. Returns `(name, usage)`.
pub fn unquote_usage(flag: &Flag) -> (String, String) {
    let usage = &flag.usage;
    if let Some(i) = usage.find('`') {
        if let Some(len) = usage[i + 1..].find('`') {
            let name = &usage[i + 1..i + 1 + len];
            let usage = format!("{}{}{}", &usage[..i], name, &usage[i + 2 + len..]);
            return (name.to_owned(), usage);
        }
    }
    let name = if flag.value.is_bool_flag() {
        ""
    } else {
        match flag.value.kind() {
            ValueKind::Duration => "duration",
            ValueKind::Float => "float",
            ValueKind::Int => "int",
            ValueKind::String => "string",
            ValueKind::Uint => "uint",
            ValueKind::Bool | ValueKind::Other => "value",
        }
    };
    (name.to_owned(), usage.clone())
}

fn program_name() -> String {
    std::env::args_os()
        .next()
        .map(|a| a.to_string_lossy().into_owned())
        .unwrap_or_default()
}

macro_rules! typed_flags {
    ($(($var:ident, $new:ident, $value:ident, $t:ty, $arg:ty, $go:literal)),* $(,)?) => {
        impl FlagSet {
            $(
                #[doc = concat!("Go's `FlagSet.", $go, "Var`: bind `p` to a new flag with default `value`.")]
                pub fn $var(&mut self, p: Ptr<$t>, name: &str, value: $arg, usage: &str) {
                    p.set(value.into());
                    self.var($value(p), name, usage);
                }
                #[doc = concat!("Go's `FlagSet.", $go, "`: define a flag and return its variable.")]
                pub fn $new(&mut self, name: &str, value: $arg, usage: &str) -> Ptr<$t> {
                    let p = Ptr::new(<$t>::default());
                    self.$var(p.clone(), name, value, usage);
                    p
                }
            )*
        }
        $(
            #[doc = concat!("Go's `flag.", $go, "Var` on the command-line set.")]
            pub fn $var(p: Ptr<$t>, name: &str, value: $arg, usage: &str) {
                command_line().$var(p, name, value, usage);
            }
            #[doc = concat!("Go's `flag.", $go, "` on the command-line set.")]
            pub fn $new(name: &str, value: $arg, usage: &str) -> Ptr<$t> {
                command_line().$new(name, value, usage)
            }
        )*
    };
}

typed_flags!(
    (bool_var, bool, BoolValue, bool, bool, "Bool"),
    (int_var, int, IntValue, isize, isize, "Int"),
    (int64_var, int64, Int64Value, i64, i64, "Int64"),
    (uint_var, uint, UintValue, usize, usize, "Uint"),
    (uint64_var, uint64, Uint64Value, u64, u64, "Uint64"),
    (string_var, string, StringValue, String, impl Into<String>, "String"),
    (float64_var, float64, Float64Value, f64, f64, "Float64"),
    (duration_var, duration, DurationValue, Duration, Duration, "Duration"),
);

impl FlagSet {
    /// Go's `NewFlagSet`.
    pub fn new(name: &str, error_handling: ErrorHandling) -> Self {
        FlagSet {
            usage: None,
            name: name.into(),
            parsed: false,
            actual: BTreeSet::new(),
            formal: BTreeMap::new(),
            args: Vec::new(),
            error_handling,
            output: Arc::new(Mutex::new(None)),
            undef: BTreeMap::new(),
            command_line: false,
            is_current: false,
        }
    }

    /// Go's `Init`: set the name and error handling of an existing set.
    pub fn init(&mut self, name: &str, error_handling: ErrorHandling) {
        self.name = name.into();
        self.error_handling = error_handling;
    }

    /// Go's `Output`: the destination of usage and error messages (stderr by
    /// default).
    pub fn output(&self) -> Output<'_> {
        Output(self)
    }
    /// Go's `SetOutput`.
    pub fn set_output<W: Write + Send + 'static>(&mut self, w: W) {
        *self.output.lock().unwrap_or_else(|e| e.into_inner()) = Some(Box::new(w));
    }
    /// Go's `SetOutput(nil)`: send messages to stderr again.
    pub fn reset_output(&mut self) {
        *self.output.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
    fn write_bytes(&self, buf: &[u8]) -> io::Result<usize> {
        let mut guard = self.output.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_mut() {
            Some(w) => w.write(buf),
            None => io::stderr().write(buf),
        }
    }
    fn write_str(&self, text: &str) {
        let mut guard = self.output.lock().unwrap_or_else(|e| e.into_inner());
        let _ = match guard.as_mut() {
            Some(w) => w.write_all(text.as_bytes()),
            None => io::stderr().write_all(text.as_bytes()),
        };
    }

    /// Go's `Name`.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Go's `ErrorHandling`.
    pub fn error_handling(&self) -> ErrorHandling {
        self.error_handling
    }

    /// Go's `VisitAll`: visit every defined flag in lexical order.
    pub fn visit_all(&self, mut f: impl FnMut(&Flag)) {
        for flag in self.formal.values() {
            f(flag);
        }
    }
    /// Go's `Visit`: visit the flags that have been set, in lexical order.
    pub fn visit(&self, mut f: impl FnMut(&Flag)) {
        for name in &self.actual {
            if let Some(flag) = self.formal.get(name) {
                f(flag);
            }
        }
    }
    /// Go's `Lookup`.
    pub fn lookup(&self, name: &str) -> Option<&Flag> {
        self.formal.get(name)
    }

    /// Go's `Set`: set the value of a defined flag. Records the caller so a
    /// later definition of an unknown name can report where it was set.
    #[track_caller]
    pub fn set(&mut self, name: &str, value: &str) -> Result<(), Error> {
        let at = Location::caller();
        self.set_at(name, value, at)
    }
    fn set_at(&mut self, name: &str, value: &str, at: &Location<'_>) -> Result<(), Error> {
        let Some(flag) = self.formal.get_mut(name) else {
            self.undef
                .insert(name.to_owned(), format!("{}:{}", at.file(), at.line()));
            return Err(Error::Other(format!("no such flag -{name}")));
        };
        flag.value
            .set(value)
            .map_err(|e| Error::Other(e.to_string()))?;
        self.actual.insert(name.to_owned());
        Ok(())
    }

    /// Go's `PrintDefaults`: print every flag's usage to [`FlagSet::output`].
    ///
    /// A panic in [`Value::zero_string`] (Go: in `String` on the zero value)
    /// does not stop the listing; it is reported after the last flag.
    pub fn print_defaults(&self) {
        let mut zero_errs: Vec<String> = Vec::new();
        self.visit_all(|flag| {
            let mut b = format!("  -{}", flag.name);
            let (name, usage) = unquote_usage(flag);
            if !name.is_empty() {
                b.push(' ');
                b.push_str(&name);
            }
            if b.len() <= 4 {
                b.push('\t');
            } else {
                b.push_str("\n    \t");
            }
            b.push_str(&usage.replace('\n', "\n    \t"));
            let zero =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| flag.value.zero_string()));
            let is_zero = match zero {
                Ok(Some(zero)) => Some(flag.def_value == zero),
                Ok(None) => Some(flag.def_value.is_empty()),
                Err(payload) => {
                    let msg = panic_message(payload);
                    zero_errs.push(format!(
                        "panic calling String method on zero {} for flag {}: {msg}",
                        flag.value.type_name(),
                        flag.name
                    ));
                    None
                }
            };
            if is_zero == Some(false) {
                if flag.value.kind() == ValueKind::String {
                    b.push_str(&format!(" (default {})", quote(&flag.def_value)));
                } else {
                    b.push_str(&format!(" (default {})", flag.def_value));
                }
            }
            b.push('\n');
            self.write_str(&b);
        });
        // Print the messages after the full set of defaults so that the
        // programmer knows to fix the panic.
        if !zero_errs.is_empty() {
            self.write_str("\n");
            for err in zero_errs {
                self.write_str(&format!("{err}\n"));
            }
        }
    }

    fn default_usage(&self) {
        if self.name.is_empty() {
            self.write_str("Usage:\n");
        } else {
            self.write_str(&format!("Usage of {}:\n", self.name));
        }
        self.print_defaults();
    }
    fn run_usage(&self) {
        // The command-line set is locked by whoever is parsing; package-level
        // readers called from the usage message use this snapshot instead.
        let _view =
            (self.command_line || self.is_current).then(|| ViewGuard::install(self.frozen()));
        match &self.usage {
            Some(f) => f(self),
            None if self.command_line => run_global_usage(self),
            None => self.default_usage(),
        }
    }

    /// A read-only copy of the set that shares its output, for package-level
    /// calls made from a usage message (see the module documentation).
    fn frozen(&self) -> FlagSet {
        let formal = self
            .formal
            .iter()
            .map(|(name, flag)| {
                let value = Frozen {
                    text: flag.value.to_string(),
                    bool_flag: flag.value.is_bool_flag(),
                    kind: flag.value.kind(),
                    zero: std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        flag.value.zero_string()
                    }))
                    .map_err(panic_message),
                    type_name: flag.value.type_name(),
                };
                let copy = Flag {
                    name: flag.name.clone(),
                    usage: flag.usage.clone(),
                    value: Box::new(value),
                    def_value: flag.def_value.clone(),
                };
                (name.clone(), copy)
            })
            .collect();
        FlagSet {
            usage: None,
            name: self.name.clone(),
            parsed: self.parsed,
            actual: self.actual.clone(),
            formal,
            args: self.args.clone(),
            error_handling: self.error_handling,
            output: Arc::clone(&self.output),
            undef: self.undef.clone(),
            command_line: true,
            is_current: true,
        }
    }

    /// Go's `NFlag`: the number of flags that have been set.
    pub fn nflag(&self) -> usize {
        self.actual.len()
    }
    /// Go's `Arg`: the i-th argument after the flags, or "" if out of range.
    pub fn arg(&self, i: usize) -> &str {
        self.args.get(i).map_or("", String::as_str)
    }
    /// Go's `NArg`.
    pub fn narg(&self) -> usize {
        self.args.len()
    }
    /// Go's `Args`: the arguments after the flags.
    pub fn args(&self) -> &[String] {
        &self.args
    }
    /// Go's `Parsed`.
    pub fn parsed(&self) -> bool {
        self.parsed
    }

    /// Go's `Func`: a flag that calls `f` with its value.
    pub fn func(
        &mut self,
        name: &str,
        usage: &str,
        f: impl FnMut(&str) -> Result<(), BoxError> + Send + 'static,
    ) {
        self.var(FuncValue(Box::new(f), false), name, usage);
    }
    /// Go's `BoolFunc`: like [`FlagSet::func`] but the flag needs no value
    /// (`f` receives "true").
    pub fn bool_func(
        &mut self,
        name: &str,
        usage: &str,
        f: impl FnMut(&str) -> Result<(), BoxError> + Send + 'static,
    ) {
        self.var(FuncValue(Box::new(f), true), name, usage);
    }
    /// Go's `TextVar`: a flag backed by a text-marshalling type; `p` is set to
    /// `value` first.
    pub fn text_var<T: TextMarshaler + TextUnmarshaler + Send + 'static>(
        &mut self,
        p: Ptr<T>,
        name: &str,
        value: T,
        usage: &str,
    ) {
        p.set(value);
        self.var(TextValue(p), name, usage);
    }

    /// Go's `Var`: define a flag with a custom [`Value`]; its current text is
    /// the default. Panics, after printing the message to the set's output,
    /// if `name` starts with `-`, contains `=`, or is already defined.
    pub fn var(&mut self, value: impl Value + 'static, name: &str, usage: &str) {
        self.var_boxed(Box::new(value), name, usage);
    }
    fn var_boxed(&mut self, value: Box<dyn Value>, name: &str, usage: &str) {
        if name.starts_with('-') {
            let msg = self.sprintf(format!("flag {} begins with -", quote(name)));
            panic!("{msg}");
        } else if name.contains('=') {
            let msg = self.sprintf(format!("flag {} contains =", quote(name)));
            panic!("{msg}");
        }
        let flag = Flag {
            name: name.into(),
            usage: usage.into(),
            def_value: value.to_string(),
            value,
        };
        if self.formal.contains_key(name) {
            let msg = if self.name.is_empty() {
                self.sprintf(format!("flag redefined: {name}"))
            } else {
                self.sprintf(format!("{} flag redefined: {name}", self.name))
            };
            panic!("{msg}");
        }
        if let Some(pos) = self.undef.get(name) {
            panic!("flag {name} set at {pos} before being defined");
        }
        self.formal.insert(name.into(), flag);
    }

    fn sprintf(&self, msg: String) -> String {
        self.write_str(&format!("{msg}\n"));
        msg
    }
    fn failf(&self, msg: String) -> Error {
        self.write_str(&format!("{msg}\n"));
        self.run_usage();
        Error::Other(msg)
    }

    /// Go's `parseOne`: returns whether a flag was consumed.
    fn parse_one(&mut self) -> Result<bool, Error> {
        let Some(s) = self.args.first().cloned() else {
            return Ok(false);
        };
        if s.len() < 2 || !s.starts_with('-') {
            return Ok(false);
        }
        let mut minuses = 1;
        if s.as_bytes()[1] == b'-' {
            minuses += 1;
            if s.len() == 2 {
                self.args.remove(0);
                return Ok(false);
            }
        }
        let mut name = s[minuses..].to_owned();
        if name.is_empty() || name.starts_with('-') || name.starts_with('=') {
            return Err(self.failf(format!("bad flag syntax: {s}")));
        }
        self.args.remove(0);
        let mut value = None;
        if let Some(i) = name.as_bytes()[1..].iter().position(|&b| b == b'=') {
            value = Some(name[i + 2..].to_owned());
            name.truncate(i + 1);
        }
        if !self.formal.contains_key(&name) {
            if name == "help" || name == "h" {
                self.run_usage();
                return Err(Error::Help);
            }
            return Err(self.failf(format!("flag provided but not defined: -{name}")));
        }
        let is_bool = self.formal[&name].value.is_bool_flag();
        if is_bool {
            let (arg, message) = match &value {
                Some(v) => (v.as_str(), "invalid boolean value"),
                None => ("true", "invalid boolean flag"),
            };
            let result = self.formal.get_mut(&name).map(|f| f.value.set(arg));
            if let Some(Err(e)) = result {
                let msg = if value.is_some() {
                    format!("{message} {} for -{name}: {e}", quote(arg))
                } else {
                    format!("{message} {name}: {e}")
                };
                return Err(self.failf(msg));
            }
        } else {
            if value.is_none() && !self.args.is_empty() {
                value = Some(self.args.remove(0));
            }
            let Some(value) = value else {
                return Err(self.failf(format!("flag needs an argument: -{name}")));
            };
            let result = self.formal.get_mut(&name).map(|f| f.value.set(&value));
            if let Some(Err(e)) = result {
                return Err(self.failf(format!(
                    "invalid value {} for flag -{name}: {e}",
                    quote(&value)
                )));
            }
        }
        self.actual.insert(name);
        Ok(true)
    }

    /// Go's `Parse`: parse `arguments` (without the program name). On error
    /// the behaviour follows [`FlagSet::error_handling`].
    pub fn parse<S: AsRef<str>>(&mut self, arguments: &[S]) -> Result<(), Error> {
        self.parsed = true;
        self.args = arguments.iter().map(|a| a.as_ref().to_owned()).collect();
        loop {
            match self.parse_one() {
                Ok(true) => continue,
                Ok(false) => return Ok(()),
                Err(err) => match self.error_handling {
                    ErrorHandling::ContinueOnError => return Err(err),
                    ErrorHandling::ExitOnError => {
                        std::process::exit(if err == Error::Help { 0 } else { 2 })
                    }
                    ErrorHandling::PanicOnError => panic!("{err}"),
                },
            }
        }
    }
}

/// The text of a panic payload, as Go prints a recovered value with `%v`.
fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    match payload.downcast::<String>() {
        Ok(s) => *s,
        Err(p) => match p.downcast::<&str>() {
            Ok(s) => (*s).to_owned(),
            Err(_) => "Box<dyn Any>".to_owned(),
        },
    }
}

/// The value of a flag in a frozen snapshot: its text and behaviour at the
/// time the usage message started.
struct Frozen {
    text: String,
    bool_flag: bool,
    kind: ValueKind,
    /// The zero text, or the message of the panic that computing it raised.
    zero: Result<Option<String>, String>,
    type_name: &'static str,
}
impl fmt::Display for Frozen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&{ self.text.clone() })
    }
}
impl Value for Frozen {
    fn set(&mut self, _: &str) -> Result<(), BoxError> {
        Err("flag: the set is read-only while its usage message runs".into())
    }
    fn is_bool_flag(&self) -> bool {
        self.bool_flag
    }
    fn kind(&self) -> ValueKind {
        self.kind
    }
    fn zero_string(&self) -> Option<String> {
        match &self.zero {
            Ok(zero) => zero.clone(),
            Err(msg) => panic!("{msg}"),
        }
    }
    fn type_name(&self) -> &'static str {
        self.type_name
    }
}

thread_local! {
    static VIEW: std::cell::RefCell<Option<std::rc::Rc<FlagSet>>> =
        const { std::cell::RefCell::new(None) };
}

/// Installs a frozen snapshot as the target of package-level readers on this
/// thread until dropped.
struct ViewGuard(Option<std::rc::Rc<FlagSet>>);
impl ViewGuard {
    fn install(view: FlagSet) -> ViewGuard {
        let previous = VIEW.with(|v| v.borrow_mut().replace(std::rc::Rc::new(view)));
        ViewGuard(previous)
    }
}
impl Drop for ViewGuard {
    fn drop(&mut self) {
        VIEW.with(|v| *v.borrow_mut() = self.0.take());
    }
}

/// Run a read-only operation on the command-line set, or on the snapshot when
/// called from its usage message.
fn read_command_line<R>(f: impl FnOnce(&FlagSet) -> R) -> R {
    let view = VIEW.with(|v| v.borrow().clone());
    match view {
        Some(view) => f(&view),
        None => f(&command_line()),
    }
}

type GlobalUsage = Arc<dyn Fn(&FlagSet) + Send + Sync>;
static USAGE: Mutex<Option<GlobalUsage>> = Mutex::new(None);

fn run_global_usage(f: &FlagSet) {
    let custom = USAGE.lock().unwrap_or_else(|e| e.into_inner()).clone();
    match custom {
        Some(usage) => usage(f),
        None => default_global_usage(f),
    }
}
fn default_global_usage(f: &FlagSet) {
    f.write_str(&format!("Usage of {}:\n", program_name()));
    f.print_defaults();
}
/// Go's `flag.Usage = f`: replace the usage message of the command-line set.
pub fn set_usage(f: impl Fn(&FlagSet) + Send + Sync + 'static) {
    *USAGE.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(f));
}
/// Go's `flag.Usage()`: print the usage message of the command-line set.
pub fn usage() {
    let view = VIEW.with(|v| v.borrow().clone());
    match view {
        Some(view) => run_global_usage(&view),
        None => run_global_usage(&command_line()),
    }
}

static COMMAND_LINE: Mutex<Option<FlagSet>> = Mutex::new(None);

/// Exclusive access to Go's `flag.CommandLine`; hold it briefly. Assign
/// through it (`*command_line() = FlagSet::new(...)`) to replace the set.
pub struct CommandLine(MutexGuard<'static, Option<FlagSet>>);
impl Deref for CommandLine {
    type Target = FlagSet;
    fn deref(&self) -> &FlagSet {
        self.0.as_ref().expect("command-line set is initialized")
    }
}
impl DerefMut for CommandLine {
    fn deref_mut(&mut self) -> &mut FlagSet {
        self.0.as_mut().expect("command-line set is initialized")
    }
}
/// Go's `flag.CommandLine`: the default set, named after the program and using
/// [`ErrorHandling::ExitOnError`].
///
/// Panics when called from inside the command-line set's own usage message,
/// where the set is already borrowed; use the package-level readers there.
pub fn command_line() -> CommandLine {
    assert!(
        VIEW.with(|v| v.borrow().is_none()),
        "flag: the command-line set cannot be modified while its usage message runs"
    );
    let mut guard = COMMAND_LINE.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        let mut set = FlagSet::new(&program_name(), ErrorHandling::ExitOnError);
        set.command_line = true;
        *guard = Some(set);
    }
    if let Some(set) = guard.as_mut() {
        set.is_current = true;
    }
    CommandLine(guard)
}

/// Go's `flag.Parse`: parse the process arguments with the command-line set.
pub fn parse() {
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let _ = command_line().parse(&args);
}
/// Go's `flag.Parsed`.
pub fn parsed() -> bool {
    read_command_line(FlagSet::parsed)
}
/// Go's `flag.Var`.
pub fn var(value: impl Value + 'static, name: &str, usage: &str) {
    command_line().var(value, name, usage);
}
/// Go's `flag.Func`.
pub fn func(name: &str, usage: &str, f: impl FnMut(&str) -> Result<(), BoxError> + Send + 'static) {
    command_line().func(name, usage, f);
}
/// Go's `flag.BoolFunc`.
pub fn bool_func(
    name: &str,
    usage: &str,
    f: impl FnMut(&str) -> Result<(), BoxError> + Send + 'static,
) {
    command_line().bool_func(name, usage, f);
}
/// Go's `flag.TextVar`.
pub fn text_var<T: TextMarshaler + TextUnmarshaler + Send + 'static>(
    p: Ptr<T>,
    name: &str,
    value: T,
    usage: &str,
) {
    command_line().text_var(p, name, value, usage);
}
/// Go's `flag.Set`.
#[track_caller]
pub fn set(name: &str, value: &str) -> Result<(), Error> {
    let at = Location::caller();
    command_line().set_at(name, value, at)
}
/// Go's `flag.Lookup`: run `f` on the named flag of the command-line set.
pub fn lookup<R>(name: &str, f: impl FnOnce(&Flag) -> R) -> Option<R> {
    read_command_line(|set| set.lookup(name).map(f))
}
/// Go's `flag.Visit`.
pub fn visit(f: impl FnMut(&Flag)) {
    read_command_line(|set| set.visit(f));
}
/// Go's `flag.VisitAll`.
pub fn visit_all(f: impl FnMut(&Flag)) {
    read_command_line(|set| set.visit_all(f));
}
/// Go's `flag.PrintDefaults`.
pub fn print_defaults() {
    read_command_line(FlagSet::print_defaults);
}
/// Go's `flag.NFlag`.
pub fn nflag() -> usize {
    read_command_line(FlagSet::nflag)
}
/// Go's `flag.Arg`.
pub fn arg(i: usize) -> String {
    read_command_line(|set| set.arg(i).to_owned())
}
/// Go's `flag.NArg`.
pub fn narg() -> usize {
    read_command_line(FlagSet::narg)
}
/// Go's `flag.Args`.
pub fn args() -> Vec<String> {
    read_command_line(|set| set.args().to_vec())
}
