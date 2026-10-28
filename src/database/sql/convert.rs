//! Type conversions for `Scan` (Go's `convert.go`) and query-argument
//! conversion for drivers.
//!
//! Ported from Go's `database/sql/convert.go`. Go decides conversions with
//! `reflect`; Rust decides them by the destination type implementing
//! [`Scanner`], with the same rules and the same error texts:
//!
//! * `string`, `[]byte` and [`RawBytes`] destinations take strings, byte
//!   slices, times (RFC 3339 with nanoseconds), numbers and booleans.
//! * `bool` converts with [`driver::BOOL`].
//! * Numeric destinations convert the source to its string form and parse it,
//!   so `float64(3)` scans into an `int64` but `float64(3.5)` does not.
//! * `Option<T>` is a pointer to `T`: `nil` becomes `None`.
//! * [`driver::Value`] is `*any`.
use super::driver::{
    self, Arg, Compose, Conn, NamedValue, Stmt, Value, ValueConverter, DEFAULT_PARAMETER_CONVERTER,
};
use super::error::{Error, Res, ERR_REMOVE_ARGUMENT, ERR_SKIP};
use crate::{
    strconv,
    time::{self, Time},
    unicode,
    uuid::{self, UUID},
};

/// Go's `sql.Scanner`: a destination `Rows::scan` can store a column value in.
///
/// Implemented for `String`, `Vec<u8>`, [`RawBytes`], `bool`, every integer
/// and float width, [`Time`], [`driver::Value`], `Option<T>` and the `Null*`
/// types. Implement it for your own types as Go programs implement
/// `sql.Scanner`.
pub trait Scanner {
    /// Stores `src`, a value of one of the types in [`driver::Value`].
    fn scan(&mut self, src: &Value) -> Res<()>;

    /// Whether this destination is a [`RawBytes`]; `Row::scan` rejects them.
    #[doc(hidden)]
    fn is_raw_bytes(&self) -> bool {
        false
    }
}

/// Go's `sql.RawBytes`. Go aliases driver memory; Rust copies the bytes, so
/// the value stays valid after the next call to `Next`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RawBytes(pub Vec<u8>);

/// Go's `sql.NamedArg`.
#[derive(Debug, Clone)]
pub struct NamedArg {
    pub name: String,
    pub value: Arg,
}

/// Go's `sql.Named`: a named argument for `Exec`/`Query`.
pub fn named(name: impl Into<String>, value: impl Into<Arg>) -> NamedArg {
    NamedArg {
        name: name.into(),
        value: value.into(),
    }
}

impl std::fmt::Debug for Arg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Arg({}: {})", self.type_name(), self.format_v())
    }
}

/// Go's `sql.Out`: an output parameter. `dest` is shared so the caller can
/// read what a driver stored in it.
#[derive(Clone)]
pub struct Out {
    pub dest: std::sync::Arc<std::sync::Mutex<dyn Scanner + Send>>,
    /// Whether the parameter is also an input.
    pub in_: bool,
}

impl std::fmt::Debug for Out {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Out").field("in", &self.in_).finish()
    }
}

/// Go's `sql.ConvertAssign`: copies `src` into `dest`, converting as
/// `Rows::scan` does. Pass `ScanContext::default()` outside a
/// [`driver::RowsColumnScanner`].
pub fn convert_assign(
    _scan_ctx: driver::ScanContext,
    dest: &mut dyn Scanner,
    src: &Value,
) -> Res<()> {
    dest.scan(src)
}

fn arg_of(src: &Value) -> Arg {
    src.clone().into()
}

fn rfc3339_nano(t: &Time) -> String {
    t.format(time::RFC3339_NANO)
}

/// Go's `asString`; a decimal prints as Go's `%v` of it would.
fn as_string(src: &Value) -> Vec<u8> {
    match src {
        Value::String(s) => s.clone().into_bytes(),
        Value::Bytes(b) => b.clone(),
        Value::Int64(i) => strconv::format_int(*i, 10).into_bytes(),
        Value::Float64(f) => strconv::format_float(*f, b'g', -1, 64).into_bytes(),
        Value::Bool(b) => b.to_string().into_bytes(),
        Value::Null => b"<nil>".to_vec(),
        Value::Time(t) => t.to_string().into_bytes(),
        Value::Decimal(d) => d.to_string().into_bytes(),
    }
}

/// Go's `asBytes` for the kinds a `driver.Value` can have.
fn as_bytes(src: &Value) -> Option<Vec<u8>> {
    match src {
        Value::Int64(_) | Value::Float64(_) | Value::Bool(_) | Value::String(_) => {
            Some(as_string(src))
        }
        _ => None,
    }
}

fn null_unsupported(kind: &str) -> Error {
    Error::new(format!("converting NULL to {kind} is unsupported"))
}

fn parse_failure(src: &Value, s: &[u8], kind: &str, reason: &str) -> Error {
    Error::new(format!(
        "converting driver.Value type {} ({}) to a {}: {}",
        src.type_name(),
        strconv::quote(s),
        kind,
        reason
    ))
}

fn syntax_text() -> String {
    strconv::ERR_SYNTAX.to_string()
}

fn scan_signed(src: &Value, bits: i32, kind: &str) -> Res<i64> {
    if matches!(src, Value::Null) {
        return Err(null_unsupported(kind));
    }
    let s = as_string(src);
    match std::str::from_utf8(&s) {
        Ok(text) => strconv::parse_int(text, 10, bits)
            .map_err(|e| parse_failure(src, &s, kind, &e.err.to_string())),
        Err(_) => Err(parse_failure(src, &s, kind, &syntax_text())),
    }
}

fn scan_unsigned(src: &Value, bits: i32, kind: &str) -> Res<u64> {
    if matches!(src, Value::Null) {
        return Err(null_unsupported(kind));
    }
    let s = as_string(src);
    match std::str::from_utf8(&s) {
        Ok(text) => strconv::parse_uint(text, 10, bits)
            .map_err(|e| parse_failure(src, &s, kind, &e.err.to_string())),
        Err(_) => Err(parse_failure(src, &s, kind, &syntax_text())),
    }
}

fn scan_float(src: &Value, bits: i32, kind: &str) -> Res<f64> {
    if matches!(src, Value::Null) {
        return Err(null_unsupported(kind));
    }
    let s = as_string(src);
    match std::str::from_utf8(&s) {
        Ok(text) => strconv::parse_float(text, bits)
            .map_err(|e| parse_failure(src, &s, kind, &e.err.to_string())),
        Err(_) => Err(parse_failure(src, &s, kind, &syntax_text())),
    }
}

macro_rules! scan_signed_impl {
    ($($t:ty, $bits:expr, $kind:expr);* $(;)?) => {$(
        impl Scanner for $t {
            fn scan(&mut self, src: &Value) -> Res<()> {
                *self = scan_signed(src, $bits, $kind)? as $t;
                Ok(())
            }
        }
    )*};
}
scan_signed_impl!(i8, 8, "int8"; i16, 16, "int16"; i32, 32, "int32"; i64, 64, "int64";
    isize, 64, "int");

macro_rules! scan_unsigned_impl {
    ($($t:ty, $bits:expr, $kind:expr);* $(;)?) => {$(
        impl Scanner for $t {
            fn scan(&mut self, src: &Value) -> Res<()> {
                *self = scan_unsigned(src, $bits, $kind)? as $t;
                Ok(())
            }
        }
    )*};
}
scan_unsigned_impl!(u8, 8, "uint8"; u16, 16, "uint16"; u32, 32, "uint32"; u64, 64, "uint64";
    usize, 64, "uint");

impl Scanner for f64 {
    fn scan(&mut self, src: &Value) -> Res<()> {
        if let Value::Float64(f) = src {
            *self = *f;
            return Ok(());
        }
        *self = scan_float(src, 64, "float64")?;
        Ok(())
    }
}

impl Scanner for f32 {
    fn scan(&mut self, src: &Value) -> Res<()> {
        *self = scan_float(src, 32, "float32")? as f32;
        Ok(())
    }
}

impl Scanner for String {
    fn scan(&mut self, src: &Value) -> Res<()> {
        match src {
            Value::String(s) => *self = s.clone(),
            // Go strings may hold any bytes; Rust's must be UTF-8.
            Value::Bytes(b) => *self = String::from_utf8_lossy(b).into_owned(),
            Value::Time(t) => *self = rfc3339_nano(t),
            Value::Null => return Err(null_unsupported("string")),
            Value::Decimal(_) => return Err(unreachable_scan(src, "*string")),
            _ => *self = String::from_utf8_lossy(&as_string(src)).into_owned(),
        }
        Ok(())
    }
}

fn scan_bytes(src: &Value, dest: &str) -> Res<Vec<u8>> {
    match src {
        Value::String(s) => Ok(s.clone().into_bytes()),
        Value::Bytes(b) => Ok(b.clone()),
        Value::Time(t) => Ok(rfc3339_nano(t).into_bytes()),
        Value::Null => Ok(Vec::new()),
        _ => as_bytes(src).ok_or_else(|| unreachable_scan(src, dest)),
    }
}

fn unreachable_scan(src: &Value, dest: &str) -> Error {
    Error::new(format!(
        "unsupported Scan, storing driver.Value type {} into type {}",
        src.type_name(),
        dest
    ))
}

impl Scanner for Vec<u8> {
    fn scan(&mut self, src: &Value) -> Res<()> {
        *self = scan_bytes(src, "*[]uint8")?;
        Ok(())
    }
}

impl Scanner for RawBytes {
    fn scan(&mut self, src: &Value) -> Res<()> {
        self.0 = scan_bytes(src, "*sql.RawBytes")?;
        Ok(())
    }
    fn is_raw_bytes(&self) -> bool {
        true
    }
}

impl Scanner for bool {
    fn scan(&mut self, src: &Value) -> Res<()> {
        match driver::BOOL.convert_value(&arg_of(src))? {
            Value::Bool(b) => *self = b,
            _ => unreachable!("driver.Bool returns a bool"),
        }
        Ok(())
    }
}

/// `*any`.
impl Scanner for Value {
    fn scan(&mut self, src: &Value) -> Res<()> {
        *self = src.clone();
        Ok(())
    }
}

impl Scanner for Time {
    fn scan(&mut self, src: &Value) -> Res<()> {
        match src {
            Value::Time(t) => {
                *self = t.clone();
                Ok(())
            }
            _ => Err(unreachable_scan(src, "*time.Time")),
        }
    }
}

/// Go's `decimalCompose` destination: a decimal source composes into it and
/// every other source is unsupported.
impl<T: Compose> Scanner for T {
    fn scan(&mut self, src: &Value) -> Res<()> {
        match src {
            Value::Decimal(d) => self.compose(d),
            _ => Err(unreachable_scan(
                src,
                &format!("*{}", std::any::type_name::<T>()),
            )),
        }
    }
}

/// `*uuid.UUID`: a string is parsed, a 16-byte slice is copied as is, any
/// other byte slice is parsed as text; other sources are unsupported.
impl Scanner for UUID {
    fn scan(&mut self, src: &Value) -> Res<()> {
        match src {
            Value::String(s) => match uuid::parse(s) {
                Ok(u) => *self = u,
                Err(e) => {
                    return Err(parse_uuid_failure("string", s.as_bytes(), &e));
                }
            },
            Value::Bytes(b) if b.len() == self.0.len() => self.0.copy_from_slice(b),
            Value::Bytes(b) => {
                let mut u = UUID::default();
                u.unmarshal_text(b)
                    .map_err(|e| parse_uuid_failure("[]byte", b, &e))?;
                *self = u;
            }
            _ => return Err(unreachable_scan(src, "*uuid.UUID")),
        }
        Ok(())
    }
}

fn parse_uuid_failure(kind: &str, text: &[u8], err: &uuid::ParseError) -> Error {
    Error::new(format!(
        "converting driver.Value type {kind} ({}) to a UUID: {err}",
        strconv::quote(text)
    ))
}

/// A pointer to `T` (`**T` in Go): `nil` becomes `None`, anything else
/// allocates a new `T` and scans into it.
impl<T: Scanner + Default> Scanner for Option<T> {
    fn scan(&mut self, src: &Value) -> Res<()> {
        if matches!(src, Value::Null) {
            *self = None;
            return Ok(());
        }
        self.insert(T::default()).scan(src)
    }
}

// ------------------------------------------------------------ query arguments

fn describe_named_value(nv: &NamedValue) -> String {
    if nv.name.is_empty() {
        format!("${}", nv.ordinal)
    } else {
        format!("with name {}", strconv::quote(&nv.name))
    }
}

fn validate_named_value_name(name: &str) -> Res<()> {
    match name.chars().next() {
        None => Ok(()),
        Some(r) if unicode::is_letter(r as i32) => Ok(()),
        Some(_) => Err(Error::new(format!(
            "name {} does not begin with a letter",
            strconv::quote(name)
        ))),
    }
}

fn default_check_named_value(nv: &mut NamedValue, arg: &Arg) -> Res<()> {
    nv.value = DEFAULT_PARAMETER_CONVERTER.convert_value(arg)?;
    Ok(())
}

/// Go's `ccChecker.CheckNamedValue`.
fn cc_check_named_value(
    si: Option<&mut dyn Stmt>,
    want: i64,
    nv: &mut NamedValue,
    arg: &Arg,
) -> Res<()> {
    let Some(cc) = si.and_then(|s| s.as_column_converter()) else {
        return Err(ERR_SKIP);
    };
    let index = nv.ordinal - 1;
    if want >= 0 && want <= index as i64 {
        return Ok(());
    }
    // A Valuer converts itself first (a NullString becomes a string or nil).
    let valued;
    let arg = if let Arg::Valuer(vr) = arg {
        let sv = vr.value()?;
        nv.value = sv.clone();
        valued = Arg::from(sv);
        &valued
    } else {
        arg
    };
    // Then the column sanity-checks the value.
    nv.value = cc.column_converter(index).convert_value(arg)?;
    Ok(())
}

/// Shortens the lifetime of a statement reference without moving it.
fn reborrow<'a>(s: &'a mut Option<&mut dyn Stmt>) -> Option<&'a mut dyn Stmt> {
    match s {
        Some(x) => Some(&mut **x),
        None => None,
    }
}

#[derive(Clone, Copy)]
enum Route {
    Default,
    Nvc,
    Cc,
}

/// Converts the arguments of `Stmt::exec` and `Stmt::query` into driver
/// values (Go's `driverArgsConnLocked`). `si` is `None` when no statement is
/// available. The connection must be locked.
pub(crate) fn driver_args_conn_locked(
    ci: &mut dyn Conn,
    mut si: Option<&mut dyn Stmt>,
    args: &[Arg],
) -> Res<Vec<NamedValue>> {
    let mut nvargs: Vec<NamedValue> = args
        .iter()
        .map(|_| NamedValue {
            name: String::new(),
            ordinal: 0,
            value: Value::Null,
        })
        .collect();

    // -1 means the driver does not know how to count placeholders.
    let mut want: i64 = -1;
    if let Some(s) = reborrow(&mut si) {
        want = s.num_input();
    }
    // The statement's checker wins over the connection's.
    let si_nvc = si
        .as_deref_mut()
        .is_some_and(|s| s.as_named_value_checker().is_some());
    let ci_nvc = !si_nvc && ci.as_named_value_checker().is_some();
    let has_nvc = si_nvc || ci_nvc;
    let cci = si
        .as_deref_mut()
        .is_some_and(|s| s.as_column_converter().is_some());

    let mut n = 0;
    for arg in args {
        let mut a = arg;
        let mut name = String::new();
        if let Arg::Named(np) = arg {
            validate_named_value_name(&np.name)?;
            a = &np.value;
            name = np.name.clone();
        }
        nvargs[n].name = name;
        nvargs[n].ordinal = n + 1;
        nvargs[n].value = Value::Null;

        // Routes: A default; B checker, column converter, default;
        // C checker, default; D column converter, default.
        let mut route = Route::Default;
        let mut next_cc = false;
        if has_nvc {
            next_cc = cci;
            route = Route::Nvc;
        } else if cci {
            route = Route::Cc;
        }
        loop {
            let nv = &mut nvargs[n];
            let result = match route {
                Route::Default => default_check_named_value(nv, a),
                Route::Nvc => {
                    let checker = if si_nvc {
                        reborrow(&mut si).and_then(|s| s.as_named_value_checker())
                    } else {
                        ci.as_named_value_checker()
                    };
                    match checker {
                        Some(c) => c.check_named_value(nv, a),
                        None => Err(ERR_SKIP),
                    }
                }
                Route::Cc => cc_check_named_value(reborrow(&mut si), want, nv, a),
            };
            match result {
                Ok(()) => {
                    n += 1;
                    break;
                }
                Err(e) if e == ERR_REMOVE_ARGUMENT => {
                    nvargs.pop();
                    break;
                }
                Err(e) if e == ERR_SKIP => {
                    if next_cc {
                        next_cc = false;
                        route = Route::Cc;
                    } else {
                        route = Route::Default;
                    }
                }
                Err(e) => {
                    return Err(Error::wrap(
                        format!(
                            "sql: converting argument {} type: {}",
                            describe_named_value(&nvargs[n]),
                            e
                        ),
                        e,
                    ));
                }
            }
        }
    }

    // Check the length after conversion to allow for omitted arguments.
    if want != -1 && nvargs.len() as i64 != want {
        return Err(Error::new(format!(
            "sql: expected {} arguments, got {}",
            want,
            nvargs.len()
        )));
    }
    Ok(nvargs)
}
