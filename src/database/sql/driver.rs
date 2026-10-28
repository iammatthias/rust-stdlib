//! Go's `database/sql/driver`: the interfaces a database driver implements and
//! the value converters shared by drivers.
//!
//! Go detects optional driver interfaces (`ExecerContext`, `Pinger`,
//! `RowsNextResultSet`, ...) by type assertion. Rust has no such downcast, so
//! the base traits [`Conn`], [`Stmt`] and [`Rows`] carry `as_*` accessors that
//! return `None` by default; a driver implements the optional trait and
//! overrides the accessor with `Some(self)`.
//!
//! Go's `driver.Value` is `any` restricted to `int64`, `float64`, `bool`,
//! `[]byte`, `string`, `time.Time`, `nil` and any type with a `Decompose`
//! method; [`Value`] is that set, with [`Decimal`] for the last. The
//! unrestricted `any` that callers pass to `Exec`/`Query` and to a
//! [`ValueConverter`] is [`Arg`].
//!
//! # Drivers over borrowing bindings
//!
//! [`Stmt`] and [`Rows`] are owned, `'static` boxes, as in Go. A binding whose
//! statement borrows its connection (rusqlite's `Statement<'conn>` and
//! `Rows<'stmt>`) cannot hand those out without `unsafe`. The safe pattern:
//!
//! * the [`Stmt`] stores the SQL text and a shared handle to the connection
//!   (`Arc<Mutex<..>>`) and prepares on every `exec`/`query`, using the
//!   binding's statement cache (`prepare_cached`) so that this stays cheap;
//! * `query` runs the cursor to the end and returns the result as
//!   [`BufferedRows`], which is a [`Rows`].
//!
//! [`BufferedRows`] is a Rust addition with no Go counterpart; drivers that
//! can stream should still implement [`Rows`] themselves.
//!
//! ```
//! use rust_stdlib::database::sql::{self, driver::{self, BufferedRows, Res, Value}};
//! use std::sync::{Arc, Mutex};
//!
//! type Table = Arc<Mutex<Vec<(i64, String)>>>;
//!
//! struct Toy(Table);
//! struct ToyConn(Table);
//! struct ToyStmt { sql: String, table: Table }
//! struct ToyTx;
//!
//! impl driver::Driver for Toy {
//!     fn open(&self, _name: &str) -> Res<Box<dyn driver::Conn>> {
//!         Ok(Box::new(ToyConn(self.0.clone())))
//!     }
//! }
//! impl driver::Conn for ToyConn {
//!     fn prepare(&mut self, query: &str) -> Res<Box<dyn driver::Stmt>> {
//!         // Keep the text and the shared handle; prepare at execution time.
//!         Ok(Box::new(ToyStmt { sql: query.to_string(), table: self.0.clone() }))
//!     }
//!     fn close(&mut self) -> Res<()> { Ok(()) }
//!     fn begin(&mut self) -> Res<Box<dyn driver::Tx>> { Ok(Box::new(ToyTx)) }
//! }
//! impl driver::Tx for ToyTx {
//!     fn commit(&mut self) -> Res<()> { Ok(()) }
//!     fn rollback(&mut self) -> Res<()> { Ok(()) }
//! }
//! impl driver::Stmt for ToyStmt {
//!     fn close(&mut self) -> Res<()> { Ok(()) }
//!     fn num_input(&mut self) -> i64 { if self.sql == "insert" { 2 } else { 0 } }
//!     fn exec(&mut self, args: &[Value]) -> Res<Box<dyn driver::Result>> {
//!         match args {
//!             [Value::Int64(id), Value::String(name)] => {
//!                 self.table.lock().unwrap().push((*id, name.clone()));
//!                 Ok(Box::new(driver::RowsAffected(1)))
//!             }
//!             _ => Err(driver::Error::new("toy: want (int, string)")),
//!         }
//!     }
//!     fn query(&mut self, _args: &[Value]) -> Res<Box<dyn driver::Rows>> {
//!         // Collect the borrowing cursor eagerly while the lock is held.
//!         let rows = self.table.lock().unwrap().iter()
//!             .map(|(id, name)| vec![Value::Int64(*id), Value::String(name.clone())])
//!             .collect();
//!         Ok(Box::new(BufferedRows::new(vec!["id".into(), "name".into()], rows)))
//!     }
//! }
//!
//! sql::register("toy-doc", Arc::new(Toy(Table::default())));
//! let db = sql::DB::open("toy-doc", "").unwrap();
//! db.exec("insert", &[1i64.into(), "ann".into()]).unwrap();
//! db.exec("insert", &[2i64.into(), "bob".into()]).unwrap();
//! let mut rows = db.query("select", &[]).unwrap();
//! let mut names = Vec::new();
//! while let Some(mut row) = rows.next_row().unwrap() {
//!     let (mut id, mut name) = (0i64, String::new());
//!     row.scan(&mut [&mut id, &mut name]).unwrap();
//!     names.push((id, name));
//! }
//! assert_eq!(names, [(1, "ann".to_string()), (2, "bob".to_string())]);
//! ```
use super::{NamedArg, Out, Scanner};
use crate::{context::Context, math::big, strconv, time::Time, uuid::UUID};
use std::fmt;

pub use super::error::{Error, Res, EOF, ERR_BAD_CONN, ERR_REMOVE_ARGUMENT, ERR_SKIP};

/// Go's `driver.Value`.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum Value {
    /// `nil`.
    #[default]
    Null,
    Int64(i64),
    Float64(f64),
    Bool(bool),
    Bytes(Vec<u8>),
    String(String),
    Time(Time),
    /// A decimal, as Go passes any value with a `Decompose` method.
    Decimal(Decimal),
}

impl Value {
    /// Go's `%T` of the value held in an `any`.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "<nil>",
            Value::Int64(_) => "int64",
            Value::Float64(_) => "float64",
            Value::Bool(_) => "bool",
            Value::Bytes(_) => "[]uint8",
            Value::String(_) => "string",
            Value::Time(_) => "time.Time",
            Value::Decimal(_) => "driver.Decimal",
        }
    }
}

/// The form of a [`Decimal`]: Go's `form` byte (finite 0, infinite 1, NaN 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Form {
    #[default]
    Finite,
    Infinite,
    NaN,
}

/// A decimal in the parts Go's `database/sql` decimal interfaces exchange:
/// `(negative) coefficient * 10^exponent` when `form` is [`Form::Finite`].
///
/// `coefficient` is a big-endian base-2 integer, most significant byte
/// first; an empty coefficient is zero. For the other forms `coefficient`
/// and `exponent` are ignored. Drivers receive one as [`Value::Decimal`];
/// [`Decompose`] and [`Compose`] connect it to an application's own type.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Decimal {
    pub form: Form,
    pub negative: bool,
    pub coefficient: Vec<u8>,
    pub exponent: i32,
}

/// Go's unexported `decimalDecompose`: a type a decimal argument is built
/// from with [`Arg::decimal`].
pub trait Decompose {
    fn decompose(&self) -> Decimal;
}

/// Go's unexported `decimalCompose`: a `Scan` destination that takes a
/// decimal source. Every `Compose` type is a [`Scanner`] that accepts only
/// [`Value::Decimal`], so it cannot also implement `Scanner` itself.
pub trait Compose {
    /// Sets the value from `d`, or fails if the value cannot be represented.
    fn compose(&mut self, d: &Decimal) -> Res<()>;
}

impl Decompose for Decimal {
    fn decompose(&self) -> Decimal {
        self.clone()
    }
}

impl Compose for Decimal {
    fn compose(&mut self, d: &Decimal) -> Res<()> {
        self.clone_from(d);
        Ok(())
    }
}

/// The General Decimal Arithmetic to-scientific-string: plain notation
/// unless the exponent is positive or the adjusted exponent is below -6, and
/// `Infinity` or `NaN` for the other forms. This text stands in for Go's `%v`
/// of a decimal, which is the application type's own.
impl fmt::Display for Decimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.negative {
            f.write_str("-")?;
        }
        match self.form {
            Form::Infinite => return f.write_str("Infinity"),
            Form::NaN => return f.write_str("NaN"),
            Form::Finite => {}
        }
        let digits = big::Int::from_bytes(&self.coefficient).text(10);
        let exp = i64::from(self.exponent);
        let adjusted = exp + digits.len() as i64 - 1;
        if exp <= 0 && adjusted >= -6 {
            let point = digits.len() as i64 + exp;
            return match point {
                _ if exp == 0 => f.write_str(&digits),
                p if p > 0 => {
                    let (int, frac) = digits.split_at(p as usize);
                    write!(f, "{int}.{frac}")
                }
                p => write!(f, "0.{}{digits}", "0".repeat((-p) as usize)),
            };
        }
        let (lead, rest) = digits.split_at(1);
        f.write_str(lead)?;
        if !rest.is_empty() {
            write!(f, ".{rest}")?;
        }
        write!(f, "E{}{adjusted}", if adjusted >= 0 { "+" } else { "" })
    }
}

/// Go's `any` as passed to `Exec`/`Query` and to [`ValueConverter`]: every
/// Go kind that `DefaultParameterConverter` distinguishes.
#[derive(Clone)]
pub enum Arg {
    /// An untyped `nil`.
    Nil,
    Bool(bool),
    /// Go's `int`.
    Int(i64),
    Int8(i8),
    Int16(i16),
    Int32(i32),
    Int64(i64),
    /// Go's `uint`.
    Uint(u64),
    Uint8(u8),
    Uint16(u16),
    Uint32(u32),
    Uint64(u64),
    Float32(f32),
    Float64(f64),
    String(String),
    Bytes(Vec<u8>),
    Time(Time),
    /// A decimal: Go's argument with a `Decompose` method.
    Decimal(Decimal),
    /// A `uuid.UUID`.
    Uuid(UUID),
    /// A [`Valuer`], shared so the argument stays `Clone`.
    Valuer(std::sync::Arc<dyn Valuer>),
    /// A pointer: `None` is a nil pointer.
    Pointer(Option<Box<Arg>>),
    /// A [`NamedArg`].
    Named(Box<NamedArg>),
    /// An [`Out`] parameter.
    Out(Out),
    /// A Go type no converter supports, with its `%T` name, `Kind` and the
    /// text `%v` prints for the value.
    Unsupported {
        type_name: String,
        kind: String,
        repr: String,
    },
    /// A slice other than `[]byte`, with its `%T` name, element `Kind` and
    /// the text `%v` prints for the value.
    UnsupportedSlice {
        type_name: String,
        elem_kind: String,
        repr: String,
    },
}

impl Arg {
    /// Wrap a [`Valuer`] (Go passes it as an `any`).
    pub fn valuer(v: impl Valuer + 'static) -> Arg {
        Arg::Valuer(std::sync::Arc::new(v))
    }

    /// A decimal argument from any [`Decompose`] type.
    pub fn decimal(v: &impl Decompose) -> Arg {
        Arg::Decimal(v.decompose())
    }

    /// Go's `%T` of the argument.
    pub fn type_name(&self) -> String {
        match self {
            Arg::Nil => "<nil>".into(),
            Arg::Bool(_) => "bool".into(),
            Arg::Int(_) => "int".into(),
            Arg::Int8(_) => "int8".into(),
            Arg::Int16(_) => "int16".into(),
            Arg::Int32(_) => "int32".into(),
            Arg::Int64(_) => "int64".into(),
            Arg::Uint(_) => "uint".into(),
            Arg::Uint8(_) => "uint8".into(),
            Arg::Uint16(_) => "uint16".into(),
            Arg::Uint32(_) => "uint32".into(),
            Arg::Uint64(_) => "uint64".into(),
            Arg::Float32(_) => "float32".into(),
            Arg::Float64(_) => "float64".into(),
            Arg::String(_) => "string".into(),
            Arg::Bytes(_) => "[]uint8".into(),
            Arg::Time(_) => "time.Time".into(),
            Arg::Decimal(_) => "driver.Decimal".into(),
            Arg::Uuid(_) => "uuid.UUID".into(),
            Arg::Valuer(_) => "driver.Valuer".into(),
            Arg::Pointer(None) => "*interface {}".into(),
            Arg::Pointer(Some(inner)) => format!("*{}", inner.type_name()),
            Arg::Named(_) => "sql.NamedArg".into(),
            Arg::Out(_) => "sql.Out".into(),
            Arg::Unsupported { type_name, .. } => type_name.clone(),
            Arg::UnsupportedSlice { type_name, .. } => type_name.clone(),
        }
    }

    /// Go's `%v` of the argument.
    pub fn format_v(&self) -> String {
        match self {
            Arg::Nil => "<nil>".into(),
            Arg::Bool(b) => b.to_string(),
            Arg::Int(v) | Arg::Int64(v) => v.to_string(),
            Arg::Int8(v) => v.to_string(),
            Arg::Int16(v) => v.to_string(),
            Arg::Int32(v) => v.to_string(),
            Arg::Uint(v) | Arg::Uint64(v) => v.to_string(),
            Arg::Uint8(v) => v.to_string(),
            Arg::Uint16(v) => v.to_string(),
            Arg::Uint32(v) => v.to_string(),
            Arg::Float32(f) => strconv::format_float(f64::from(*f), b'g', -1, 32),
            Arg::Float64(f) => strconv::format_float(*f, b'g', -1, 64),
            Arg::String(s) => s.clone(),
            Arg::Bytes(b) => {
                let parts: Vec<String> = b.iter().map(|x| x.to_string()).collect();
                format!("[{}]", parts.join(" "))
            }
            Arg::Time(t) => t.to_string(),
            Arg::Decimal(d) => d.to_string(),
            Arg::Uuid(u) => u.to_string(),
            Arg::Pointer(None) => "<nil>".into(),
            Arg::Pointer(Some(inner)) => inner.format_v(),
            Arg::Valuer(_) | Arg::Named(_) | Arg::Out(_) => "{}".into(),
            Arg::Unsupported { repr, .. } | Arg::UnsupportedSlice { repr, .. } => repr.clone(),
        }
    }

    fn signed(&self) -> Option<i64> {
        match self {
            Arg::Int(v) | Arg::Int64(v) => Some(*v),
            Arg::Int8(v) => Some(i64::from(*v)),
            Arg::Int16(v) => Some(i64::from(*v)),
            Arg::Int32(v) => Some(i64::from(*v)),
            _ => None,
        }
    }

    fn unsigned(&self) -> Option<u64> {
        match self {
            Arg::Uint(v) | Arg::Uint64(v) => Some(*v),
            Arg::Uint8(v) => Some(u64::from(*v)),
            Arg::Uint16(v) => Some(u64::from(*v)),
            Arg::Uint32(v) => Some(u64::from(*v)),
            _ => None,
        }
    }
}

impl From<Value> for Arg {
    fn from(v: Value) -> Arg {
        match v {
            Value::Null => Arg::Nil,
            Value::Int64(v) => Arg::Int64(v),
            Value::Float64(v) => Arg::Float64(v),
            Value::Bool(v) => Arg::Bool(v),
            Value::Bytes(v) => Arg::Bytes(v),
            Value::String(v) => Arg::String(v),
            Value::Time(v) => Arg::Time(v),
            Value::Decimal(v) => Arg::Decimal(v),
        }
    }
}

macro_rules! arg_from {
    ($($t:ty => $v:ident),* $(,)?) => {$(
        impl From<$t> for Arg {
            fn from(x: $t) -> Arg {
                Arg::$v(x.into())
            }
        }
    )*};
}
arg_from!(bool => Bool, i8 => Int8, i16 => Int16, i32 => Int32, i64 => Int64,
    u8 => Uint8, u16 => Uint16, u32 => Uint32, u64 => Uint64, f32 => Float32,
    f64 => Float64, String => String, Vec<u8> => Bytes, Time => Time,
    Decimal => Decimal, UUID => Uuid);

impl From<isize> for Arg {
    fn from(x: isize) -> Arg {
        Arg::Int(x as i64)
    }
}
impl From<usize> for Arg {
    fn from(x: usize) -> Arg {
        Arg::Uint(x as u64)
    }
}
impl From<&str> for Arg {
    fn from(x: &str) -> Arg {
        Arg::String(x.to_string())
    }
}
impl From<&[u8]> for Arg {
    fn from(x: &[u8]) -> Arg {
        Arg::Bytes(x.to_vec())
    }
}
/// `Option<T>` is a Go pointer to `T`: `None` is a nil pointer.
impl<T: Into<Arg>> From<Option<T>> for Arg {
    fn from(x: Option<T>) -> Arg {
        Arg::Pointer(x.map(|v| Box::new(v.into())))
    }
}
impl From<NamedArg> for Arg {
    fn from(x: NamedArg) -> Arg {
        Arg::Named(Box::new(x))
    }
}
impl From<Out> for Arg {
    fn from(x: Out) -> Arg {
        Arg::Out(x)
    }
}

/// Go's `driver.NamedValue`: a query argument after conversion to a [`Value`].
#[derive(Debug, Clone, PartialEq)]
pub struct NamedValue {
    /// The name of the parameter, empty for ordinal parameters.
    pub name: String,
    /// The 1-based ordinal position of the parameter.
    pub ordinal: usize,
    pub value: Value,
}

/// Go's `driver.IsolationLevel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IsolationLevel(pub i64);

/// Go's `driver.TxOptions`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TxOptions {
    pub isolation: IsolationLevel,
    pub read_only: bool,
}

/// Go's `driver.ScanContext`: opaque context a [`RowsColumnScanner`] passes
/// through to [`super::convert_assign`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ScanContext {
    _private: (),
}

/// Go's `reflect.Type` as reported by `ColumnTypeScanType`: the name of the Go
/// type a column scans into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanType(std::borrow::Cow<'static, str>);

impl ScanType {
    pub const ANY: ScanType = ScanType::new("interface {}");
    pub const BOOL: ScanType = ScanType::new("bool");
    pub const INT16: ScanType = ScanType::new("int16");
    pub const INT32: ScanType = ScanType::new("int32");
    pub const INT64: ScanType = ScanType::new("int64");
    pub const FLOAT64: ScanType = ScanType::new("float64");
    pub const STRING: ScanType = ScanType::new("string");
    pub const BYTES: ScanType = ScanType::new("[]uint8");
    pub const TIME: ScanType = ScanType::new("time.Time");
    pub const NULL_BOOL: ScanType = ScanType::new("sql.NullBool");
    pub const NULL_INT16: ScanType = ScanType::new("sql.NullInt16");
    pub const NULL_INT32: ScanType = ScanType::new("sql.NullInt32");
    pub const NULL_INT64: ScanType = ScanType::new("sql.NullInt64");
    pub const NULL_FLOAT64: ScanType = ScanType::new("sql.NullFloat64");
    pub const NULL_STRING: ScanType = ScanType::new("sql.NullString");

    /// A scan type with Go's name for it.
    pub const fn new(name: &'static str) -> ScanType {
        ScanType(std::borrow::Cow::Borrowed(name))
    }

    /// Go's `Type.String`.
    pub fn name(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ScanType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------- interfaces

/// Go's `driver.Driver`.
pub trait Driver: Send + Sync {
    /// Returns a new connection to the database.
    fn open(&self, name: &str) -> Res<Box<dyn Conn>>;
    /// Go's `DriverContext` assertion: `Some(self)` for drivers that also
    /// implement [`DriverContext`].
    fn as_driver_context(&self) -> Option<&dyn DriverContext> {
        None
    }
}

/// Go's `driver.DriverContext`.
pub trait DriverContext {
    fn open_connector(&self, name: &str) -> Res<Box<dyn Connector>>;
}

/// Go's `driver.Connector`. Go's optional `io.Closer` is [`Connector::close`].
pub trait Connector: Send + Sync {
    fn connect(&self, ctx: &Context) -> Res<Box<dyn Conn>>;
    fn driver(&self) -> std::sync::Arc<dyn Driver>;
    /// Called by `DB::close`; Go calls it when the connector implements
    /// `io.Closer`.
    fn close(&self) -> Res<()> {
        Ok(())
    }
}

/// Go's `driver.Conn`.
pub trait Conn: Send {
    fn prepare(&mut self, query: &str) -> Res<Box<dyn Stmt>>;
    fn close(&mut self) -> Res<()>;
    /// Deprecated in Go in favour of [`ConnBeginTx`].
    fn begin(&mut self) -> Res<Box<dyn Tx>>;

    fn as_execer(&mut self) -> Option<&mut dyn Execer> {
        None
    }
    fn as_execer_context(&mut self) -> Option<&mut dyn ExecerContext> {
        None
    }
    fn as_queryer(&mut self) -> Option<&mut dyn Queryer> {
        None
    }
    fn as_queryer_context(&mut self) -> Option<&mut dyn QueryerContext> {
        None
    }
    fn as_conn_prepare_context(&mut self) -> Option<&mut dyn ConnPrepareContext> {
        None
    }
    fn as_conn_begin_tx(&mut self) -> Option<&mut dyn ConnBeginTx> {
        None
    }
    fn as_pinger(&mut self) -> Option<&mut dyn Pinger> {
        None
    }
    fn as_session_resetter(&mut self) -> Option<&mut dyn SessionResetter> {
        None
    }
    fn as_validator(&mut self) -> Option<&mut dyn Validator> {
        None
    }
    fn as_named_value_checker(&mut self) -> Option<&mut dyn NamedValueChecker> {
        None
    }
    /// What `Conn::raw` callers use to recover the concrete connection, the
    /// Rust form of Go's `driverConn.(*myConn)` assertion: return `Some(self)`.
    fn as_any(&mut self) -> Option<&mut dyn std::any::Any> {
        None
    }
}

/// Go's `driver.Pinger`.
pub trait Pinger {
    fn ping(&mut self, ctx: &Context) -> Res<()>;
}

/// Go's `driver.Execer` (deprecated).
pub trait Execer {
    fn exec(&mut self, query: &str, args: &[Value]) -> Res<Box<dyn Result>>;
}

/// Go's `driver.ExecerContext`.
pub trait ExecerContext {
    fn exec_context(
        &mut self,
        ctx: &Context,
        query: &str,
        args: &[NamedValue],
    ) -> Res<Box<dyn Result>>;
}

/// Go's `driver.Queryer` (deprecated).
pub trait Queryer {
    fn query(&mut self, query: &str, args: &[Value]) -> Res<Box<dyn Rows>>;
}

/// Go's `driver.QueryerContext`.
pub trait QueryerContext {
    fn query_context(
        &mut self,
        ctx: &Context,
        query: &str,
        args: &[NamedValue],
    ) -> Res<Box<dyn Rows>>;
}

/// Go's `driver.ConnPrepareContext`.
pub trait ConnPrepareContext {
    fn prepare_context(&mut self, ctx: &Context, query: &str) -> Res<Box<dyn Stmt>>;
}

/// Go's `driver.ConnBeginTx`.
pub trait ConnBeginTx {
    fn begin_tx(&mut self, ctx: &Context, opts: TxOptions) -> Res<Box<dyn Tx>>;
}

/// Go's `driver.SessionResetter`.
pub trait SessionResetter {
    fn reset_session(&mut self, ctx: &Context) -> Res<()>;
}

/// Go's `driver.Validator`.
pub trait Validator {
    fn is_valid(&mut self) -> bool;
}

/// Go's `driver.Result`.
pub trait Result: Send {
    fn last_insert_id(&self) -> Res<i64>;
    fn rows_affected(&self) -> Res<i64>;
}

/// Go's `driver.Stmt`.
pub trait Stmt: Send {
    fn close(&mut self) -> Res<()>;
    /// The number of placeholders, or -1 if unknown.
    fn num_input(&mut self) -> i64;
    /// Deprecated in Go in favour of [`StmtExecContext`].
    fn exec(&mut self, args: &[Value]) -> Res<Box<dyn Result>>;
    /// Deprecated in Go in favour of [`StmtQueryContext`].
    fn query(&mut self, args: &[Value]) -> Res<Box<dyn Rows>>;

    fn as_stmt_exec_context(&mut self) -> Option<&mut dyn StmtExecContext> {
        None
    }
    fn as_stmt_query_context(&mut self) -> Option<&mut dyn StmtQueryContext> {
        None
    }
    fn as_named_value_checker(&mut self) -> Option<&mut dyn NamedValueChecker> {
        None
    }
    fn as_column_converter(&mut self) -> Option<&mut dyn ColumnConverter> {
        None
    }
}

/// Go's `driver.StmtExecContext`.
pub trait StmtExecContext {
    fn exec_context(&mut self, ctx: &Context, args: &[NamedValue]) -> Res<Box<dyn Result>>;
}

/// Go's `driver.StmtQueryContext`.
pub trait StmtQueryContext {
    fn query_context(&mut self, ctx: &Context, args: &[NamedValue]) -> Res<Box<dyn Rows>>;
}

/// Go's `driver.NamedValueChecker`.
///
/// Go passes the raw argument in `nv.Value` and the checker overwrites it with
/// the converted value. A [`NamedValue`] can only hold a [`Value`], so Rust
/// passes the raw argument separately and the checker stores its result in
/// `nv.value`. Return [`ERR_SKIP`] to fall back to the next converter.
pub trait NamedValueChecker {
    fn check_named_value(&mut self, nv: &mut NamedValue, arg: &Arg) -> Res<()>;
}

/// Go's `driver.ColumnConverter` (deprecated).
pub trait ColumnConverter {
    fn column_converter(&mut self, idx: usize) -> Box<dyn ValueConverter>;
}

/// Go's `driver.Rows`.
pub trait Rows: Send {
    fn columns(&self) -> Vec<String>;
    fn close(&mut self) -> Res<()>;
    /// Fills `dest` with the next row or returns [`EOF`].
    fn next(&mut self, dest: &mut [Value]) -> Res<()>;

    fn as_rows_column_scanner(&mut self) -> Option<&mut dyn RowsColumnScanner> {
        None
    }
    fn as_rows_next_result_set(&mut self) -> Option<&mut dyn RowsNextResultSet> {
        None
    }
    fn as_rows_column_type_scan_type(&self) -> Option<&dyn RowsColumnTypeScanType> {
        None
    }
    fn as_rows_column_type_database_type_name(
        &self,
    ) -> Option<&dyn RowsColumnTypeDatabaseTypeName> {
        None
    }
    fn as_rows_column_type_length(&self) -> Option<&dyn RowsColumnTypeLength> {
        None
    }
    fn as_rows_column_type_nullable(&self) -> Option<&dyn RowsColumnTypeNullable> {
        None
    }
    fn as_rows_column_type_precision_scale(&self) -> Option<&dyn RowsColumnTypePrecisionScale> {
        None
    }
}

/// Go's `driver.RowsColumnScanner`.
pub trait RowsColumnScanner: Rows {
    fn next_row(&mut self) -> Res<()>;
    fn scan_column(
        &mut self,
        scan_ctx: ScanContext,
        index: usize,
        dest: &mut dyn Scanner,
    ) -> Res<()>;
}

/// Go's `driver.RowsNextResultSet`.
pub trait RowsNextResultSet: Rows {
    fn has_next_result_set(&self) -> bool;
    fn next_result_set(&mut self) -> Res<()>;
}

/// Go's `driver.RowsColumnTypeScanType`.
pub trait RowsColumnTypeScanType: Rows {
    fn column_type_scan_type(&self, index: usize) -> ScanType;
}

/// Go's `driver.RowsColumnTypeDatabaseTypeName`.
pub trait RowsColumnTypeDatabaseTypeName: Rows {
    fn column_type_database_type_name(&self, index: usize) -> String;
}

/// Go's `driver.RowsColumnTypeLength`.
pub trait RowsColumnTypeLength: Rows {
    fn column_type_length(&self, index: usize) -> Option<i64>;
}

/// Go's `driver.RowsColumnTypeNullable`.
pub trait RowsColumnTypeNullable: Rows {
    fn column_type_nullable(&self, index: usize) -> Option<bool>;
}

/// Go's `driver.RowsColumnTypePrecisionScale`.
pub trait RowsColumnTypePrecisionScale: Rows {
    /// The precision and scale of a decimal type.
    fn column_type_precision_scale(&self, index: usize) -> Option<(i64, i64)>;
}

/// Go's `driver.Tx`.
pub trait Tx: Send {
    fn commit(&mut self) -> Res<()>;
    fn rollback(&mut self) -> Res<()>;
}

// Boxed trait objects appear in the `Ok` side of public results, so they need
// `Debug` for `unwrap_err`. Implemented on the object type so that driver
// types need not be `Debug`.
macro_rules! opaque_debug {
    ($($t:ident),*) => {$(
        impl fmt::Debug for dyn $t + '_ {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!("dyn driver::", stringify!($t)))
            }
        }
    )*};
}
opaque_debug!(Conn, Connector, Stmt, Rows, Tx, Result);

// ------------------------------------------------------------- buffered rows

/// Optional metadata of one [`BufferedRows`] column, reported through the
/// `RowsColumnType*` traits.
#[derive(Debug, Clone, PartialEq)]
pub struct ColumnInfo {
    /// What [`RowsColumnTypeScanType`] reports; [`ScanType::ANY`] by default.
    pub scan_type: ScanType,
    /// What [`RowsColumnTypeDatabaseTypeName`] reports, such as `"INTEGER"`.
    pub database_type_name: String,
    /// [`RowsColumnTypeLength`]: the length of a variable-length type.
    pub length: Option<i64>,
    /// [`RowsColumnTypeNullable`]: whether the column may be NULL, if known.
    pub nullable: Option<bool>,
}

impl Default for ColumnInfo {
    fn default() -> ColumnInfo {
        ColumnInfo {
            scan_type: ScanType::ANY,
            database_type_name: String::new(),
            length: None,
            nullable: None,
        }
    }
}

/// A Rust addition: [`Rows`] over a fully collected result, for drivers whose
/// binding cannot hand out an owned streaming cursor safely (see the
/// [module documentation](self)). Rows are yielded in order, then [`EOF`].
#[derive(Debug, Clone)]
pub struct BufferedRows {
    columns: Vec<String>,
    rows: std::vec::IntoIter<Vec<Value>>,
    info: Option<Vec<ColumnInfo>>,
}

impl BufferedRows {
    /// Rows with the given column names. Every row should have one value per
    /// column; [`Rows::next`] fails on a row of another width.
    pub fn new(columns: Vec<String>, rows: Vec<Vec<Value>>) -> BufferedRows {
        BufferedRows {
            columns,
            rows: rows.into_iter(),
            info: None,
        }
    }

    /// Reports `info`, one entry per column, through the `RowsColumnType*`
    /// traits; without it they are not offered.
    ///
    /// # Panics
    /// If `info` does not have one entry per column.
    pub fn with_column_info(mut self, info: Vec<ColumnInfo>) -> BufferedRows {
        assert_eq!(info.len(), self.columns.len(), "one ColumnInfo per column");
        self.info = Some(info);
        self
    }

    fn info(&self, index: usize) -> &ColumnInfo {
        &self.info.as_ref().expect("column info")[index]
    }
}

impl Rows for BufferedRows {
    fn columns(&self) -> Vec<String> {
        self.columns.clone()
    }
    fn close(&mut self) -> Res<()> {
        self.rows = Vec::new().into_iter();
        Ok(())
    }
    fn next(&mut self, dest: &mut [Value]) -> Res<()> {
        let Some(row) = self.rows.next() else {
            return Err(EOF);
        };
        if row.len() != dest.len() {
            return Err(Error::new(format!(
                "driver: row has {} values for {} columns",
                row.len(),
                dest.len()
            )));
        }
        for (d, v) in dest.iter_mut().zip(row) {
            *d = v;
        }
        Ok(())
    }
    fn as_rows_column_type_scan_type(&self) -> Option<&dyn RowsColumnTypeScanType> {
        self.info.is_some().then_some(self)
    }
    fn as_rows_column_type_database_type_name(
        &self,
    ) -> Option<&dyn RowsColumnTypeDatabaseTypeName> {
        self.info.is_some().then_some(self)
    }
    fn as_rows_column_type_length(&self) -> Option<&dyn RowsColumnTypeLength> {
        self.info.is_some().then_some(self)
    }
    fn as_rows_column_type_nullable(&self) -> Option<&dyn RowsColumnTypeNullable> {
        self.info.is_some().then_some(self)
    }
}

impl RowsColumnTypeScanType for BufferedRows {
    fn column_type_scan_type(&self, index: usize) -> ScanType {
        self.info(index).scan_type.clone()
    }
}
impl RowsColumnTypeDatabaseTypeName for BufferedRows {
    fn column_type_database_type_name(&self, index: usize) -> String {
        self.info(index).database_type_name.clone()
    }
}
impl RowsColumnTypeLength for BufferedRows {
    fn column_type_length(&self, index: usize) -> Option<i64> {
        self.info(index).length
    }
}
impl RowsColumnTypeNullable for BufferedRows {
    fn column_type_nullable(&self, index: usize) -> Option<bool> {
        self.info(index).nullable
    }
}

// ------------------------------------------------------------------- results

/// Go's `driver.RowsAffected`: a [`Result`] that only knows the row count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowsAffected(pub i64);

impl Result for RowsAffected {
    fn last_insert_id(&self) -> Res<i64> {
        Err(Error::new("LastInsertId is not supported by this driver"))
    }
    fn rows_affected(&self) -> Res<i64> {
        Ok(self.0)
    }
}

/// The type of Go's `driver.ResultNoRows`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoRows;

/// Go's `driver.ResultNoRows`: the result of a DDL statement.
pub const RESULT_NO_ROWS: NoRows = NoRows;

impl Result for NoRows {
    fn last_insert_id(&self) -> Res<i64> {
        Err(Error::new("no LastInsertId available after DDL statement"))
    }
    fn rows_affected(&self) -> Res<i64> {
        Err(Error::new("no RowsAffected available after DDL statement"))
    }
}

// ---------------------------------------------------------------- converters

/// Go's `driver.Valuer`.
pub trait Valuer: Send + Sync {
    fn value(&self) -> Res<Value>;
}

impl Valuer for Value {
    fn value(&self) -> Res<Value> {
        Ok(self.clone())
    }
}

/// Go's `driver.ValueConverter`.
pub trait ValueConverter: Send + Sync {
    fn convert_value(&self, v: &Arg) -> Res<Value>;
}

fn conv_err<T>(msg: String) -> Res<T> {
    Err(Error::new(msg))
}

/// Go's `driver.IsValue`: whether `v` is one of the types a [`Value`] holds.
pub fn is_value(v: &Arg) -> bool {
    match v {
        Arg::Nil
        | Arg::Bytes(_)
        | Arg::Bool(_)
        | Arg::Float64(_)
        | Arg::Int64(_)
        | Arg::String(_)
        | Arg::Time(_)
        | Arg::Decimal(_) => true,
        // A pointer to a decimal has its `Decompose` method too.
        Arg::Pointer(Some(inner)) => matches!(**inner, Arg::Decimal(_)),
        _ => false,
    }
}

/// Go's `driver.IsScanValue`.
pub fn is_scan_value(v: &Arg) -> bool {
    is_value(v)
}

/// The type of [`BOOL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoolType;
/// Go's `driver.Bool`: converts to `bool` using `strconv.ParseBool` for
/// strings and 0/1 for integers.
pub const BOOL: BoolType = BoolType;

impl fmt::Display for BoolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Bool")
    }
}

impl ValueConverter for BoolType {
    fn convert_value(&self, src: &Arg) -> Res<Value> {
        match src {
            Arg::Bool(b) => return Ok(Value::Bool(*b)),
            Arg::String(s) => {
                return match strconv::parse_bool(s) {
                    Ok(b) => Ok(Value::Bool(b)),
                    Err(_) => conv_err(format!(
                        "sql/driver: couldn't convert {} into type bool",
                        strconv::quote(s)
                    )),
                }
            }
            Arg::Bytes(s) => {
                return match std::str::from_utf8(s)
                    .ok()
                    .and_then(|t| strconv::parse_bool(t).ok())
                {
                    Some(b) => Ok(Value::Bool(b)),
                    None => conv_err(format!(
                        "sql/driver: couldn't convert {} into type bool",
                        strconv::quote(s)
                    )),
                }
            }
            _ => {}
        }
        if let Some(iv) = src.signed() {
            return if iv == 1 || iv == 0 {
                Ok(Value::Bool(iv == 1))
            } else {
                conv_err(format!("sql/driver: couldn't convert {iv} into type bool"))
            };
        }
        if let Some(uv) = src.unsigned() {
            return if uv == 1 || uv == 0 {
                Ok(Value::Bool(uv == 1))
            } else {
                conv_err(format!("sql/driver: couldn't convert {uv} into type bool"))
            };
        }
        conv_err(format!(
            "sql/driver: couldn't convert {} ({}) into type bool",
            src.format_v(),
            src.type_name()
        ))
    }
}

/// The type of [`INT32`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Int32Type;
/// Go's `driver.Int32`: converts to an `int32`-range `int64`.
pub const INT32: Int32Type = Int32Type;

impl ValueConverter for Int32Type {
    fn convert_value(&self, v: &Arg) -> Res<Value> {
        if let Some(i64v) = v.signed() {
            if i64v > i64::from(i32::MAX) || i64v < i64::from(i32::MIN) {
                return conv_err(format!("sql/driver: value {i64v} overflows int32"));
            }
            return Ok(Value::Int64(i64v));
        }
        if let Some(u64v) = v.unsigned() {
            if u64v > i32::MAX as u64 {
                return conv_err(format!("sql/driver: value {u64v} overflows int32"));
            }
            return Ok(Value::Int64(u64v as i64));
        }
        if let Arg::String(s) = v {
            return match strconv::atoi(s) {
                Ok(i) => Ok(Value::Int64(i as i64)),
                Err(_) => conv_err(format!(
                    "sql/driver: value {} can't be converted to int32",
                    strconv::quote(s)
                )),
            };
        }
        conv_err(format!(
            "sql/driver: unsupported value {} (type {}) converting to int32",
            v.format_v(),
            v.type_name()
        ))
    }
}

/// The type of [`STRING`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StringType;
/// Go's `driver.String`: converts to a string or `[]byte` using `%v`.
pub const STRING: StringType = StringType;

impl ValueConverter for StringType {
    fn convert_value(&self, v: &Arg) -> Res<Value> {
        match v {
            Arg::String(s) => Ok(Value::String(s.clone())),
            Arg::Bytes(b) => Ok(Value::Bytes(b.clone())),
            _ => Ok(Value::String(v.format_v())),
        }
    }
}

/// Go's `driver.Null`: a converter that passes `nil` and otherwise delegates.
pub struct Null {
    pub converter: Box<dyn ValueConverter>,
}

impl ValueConverter for Null {
    fn convert_value(&self, v: &Arg) -> Res<Value> {
        if matches!(v, Arg::Nil) {
            return Ok(Value::Null);
        }
        self.converter.convert_value(v)
    }
}

/// Go's `driver.NotNull`: a converter that rejects `nil` and otherwise
/// delegates.
pub struct NotNull {
    pub converter: Box<dyn ValueConverter>,
}

impl ValueConverter for NotNull {
    fn convert_value(&self, v: &Arg) -> Res<Value> {
        if matches!(v, Arg::Nil) {
            return conv_err("nil value not allowed".into());
        }
        self.converter.convert_value(v)
    }
}

/// The type of [`DEFAULT_PARAMETER_CONVERTER`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefaultConverter;
/// Go's `driver.DefaultParameterConverter`.
pub const DEFAULT_PARAMETER_CONVERTER: DefaultConverter = DefaultConverter;

impl ValueConverter for DefaultConverter {
    fn convert_value(&self, v: &Arg) -> Res<Value> {
        match v {
            Arg::Nil => Ok(Value::Null),
            Arg::Bytes(b) => Ok(Value::Bytes(b.clone())),
            Arg::Bool(b) => Ok(Value::Bool(*b)),
            Arg::Float64(f) => Ok(Value::Float64(*f)),
            Arg::Int64(i) => Ok(Value::Int64(*i)),
            Arg::String(s) => Ok(Value::String(s.clone())),
            Arg::Time(t) => Ok(Value::Time(t.clone())),
            Arg::Decimal(d) => Ok(Value::Decimal(d.clone())),
            Arg::Uuid(u) => Ok(Value::String(u.to_string())),
            Arg::Valuer(vr) => vr.value(),
            Arg::Pointer(None) => Ok(Value::Null),
            Arg::Pointer(Some(inner)) => self.convert_value(inner),
            Arg::Int(i) => Ok(Value::Int64(*i)),
            Arg::Int8(i) => Ok(Value::Int64(i64::from(*i))),
            Arg::Int16(i) => Ok(Value::Int64(i64::from(*i))),
            Arg::Int32(i) => Ok(Value::Int64(i64::from(*i))),
            Arg::Uint(u) => Ok(Value::Int64(*u as i64)),
            Arg::Uint8(u) => Ok(Value::Int64(i64::from(*u))),
            Arg::Uint16(u) => Ok(Value::Int64(i64::from(*u))),
            Arg::Uint32(u) => Ok(Value::Int64(i64::from(*u))),
            Arg::Uint64(u) => {
                if *u >= 1 << 63 {
                    conv_err("uint64 values with high bit set are not supported".into())
                } else {
                    Ok(Value::Int64(*u as i64))
                }
            }
            Arg::Float32(f) => Ok(Value::Float64(f64::from(*f))),
            Arg::UnsupportedSlice {
                type_name,
                elem_kind,
                ..
            } => conv_err(format!(
                "unsupported type {type_name}, a slice of {elem_kind}"
            )),
            Arg::Unsupported {
                type_name, kind, ..
            } => conv_err(format!("unsupported type {type_name}, a {kind}")),
            Arg::Named(_) => conv_err("unsupported type sql.NamedArg, a struct".into()),
            Arg::Out(_) => conv_err("unsupported type sql.Out, a struct".into()),
        }
    }
}
