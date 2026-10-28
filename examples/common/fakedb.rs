//! An in-memory driver for tests and the Go differential, ported from Go's
//! `database/sql/fakedb_test.go`.
//!
//! Commands are `|`-separated (statements are `;`-separated):
//!
//! * `WIPE`
//! * `CREATE|<table>|<col>=<type>,...`
//! * `INSERT|<table>|<col>=<value>,...` and `NOSERT|...` (insert nothing)
//! * `SELECT|<table>|<col>,...|<col>=?,<col>=?name,...`
//!
//! A value starting with `?` is a placeholder; any other value is bound at
//! prepare time and must suit the column type (`string`, `blob`, `int32`).
//! A DSN is `<database name>[;badConn]`; `badConn` makes every other health
//! check of a connection fail with `driver.ErrBadConn`.
//!
//! Omitted from Go's fakedb: the `PANIC` and `WAIT` statement prefixes, the
//! `table` cursor column type, `magicquery`, the memory-poisoning of
//! `RawBytes` and the test hooks. `tests/database_oracle.go` omits the same.
#![allow(dead_code)]
use rust_stdlib::context::Context;
use rust_stdlib::database::sql::driver::{
    self, Arg, ColumnConverter, ConnPrepareContext, Connector, DriverContext, ExecerContext,
    NamedValue, QueryerContext, RowsColumnTypeScanType, RowsNextResultSet, ScanType,
    SessionResetter, StmtExecContext, StmtQueryContext, Validator, Value, ValueConverter,
    DEFAULT_PARAMETER_CONVERTER,
};
use rust_stdlib::database::sql::{self, Error};
use rust_stdlib::strconv;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

type Res<T> = std::result::Result<T, Error>;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn errf(msg: String) -> Error {
    Error::new(format!("fakedb: {msg}"))
}

/// Go's `fakeError`: a message that wraps another error.
fn fake_error(message: &str, wrapped: Error) -> Error {
    Error::wrap(message, wrapped)
}

fn fmt_v(v: &Value) -> String {
    Arg::from(v.clone()).format_v()
}

#[derive(Default)]
struct DrvData {
    open_count: i64,
    close_count: i64,
    dbs: HashMap<String, Arc<FakeDb>>,
}

/// Go's `fakeDriver` (and, with `ctx_variant`, `fakeDriverCtx`).
#[derive(Clone, Default)]
pub struct FakeDriver {
    data: Arc<Mutex<DrvData>>,
    ctx_variant: bool,
}

/// The process-wide drivers registered as "test" and "testctx".
pub fn fdriver(ctx_variant: bool) -> &'static FakeDriver {
    static PLAIN: OnceLock<FakeDriver> = OnceLock::new();
    static CTX: OnceLock<FakeDriver> = OnceLock::new();
    if ctx_variant {
        CTX.get_or_init(|| FakeDriver {
            data: Arc::default(),
            ctx_variant: true,
        })
    } else {
        PLAIN.get_or_init(FakeDriver::default)
    }
}

/// Registers the drivers as "test" and "testctx" (once per process).
pub fn register_drivers() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        sql::register("test", Arc::new(fdriver(false).clone()));
        sql::register("testctx", Arc::new(fdriver(true).clone()));
    });
}

impl FakeDriver {
    pub fn open_count(&self) -> i64 {
        lock(&self.data).open_count
    }

    pub fn close_count(&self) -> i64 {
        lock(&self.data).close_count
    }

    fn get_db(&self, name: &str) -> Arc<FakeDb> {
        lock(&self.data)
            .dbs
            .entry(name.to_string())
            .or_insert_with(|| {
                Arc::new(FakeDb {
                    name: name.to_string(),
                    m: Mutex::default(),
                })
            })
            .clone()
    }
}

impl driver::Driver for FakeDriver {
    fn open(&self, dsn: &str) -> Res<Box<dyn driver::Conn>> {
        let parts: Vec<&str> = dsn.split(';').collect();
        let db = self.get_db(parts[0]);
        lock(&self.data).open_count += 1;
        let conn = FakeConn {
            c: Arc::new(Mutex::new(ConnData {
                db: Some(db),
                ..ConnData::default()
            })),
            drv: self.clone(),
        };
        if parts.len() >= 2 && parts[1] == "badConn" {
            lock(&conn.c).bad = true;
        }
        Ok(Box::new(conn))
    }

    fn as_driver_context(&self) -> Option<&dyn DriverContext> {
        if self.ctx_variant {
            Some(self)
        } else {
            None
        }
    }
}

impl DriverContext for FakeDriver {
    fn open_connector(&self, name: &str) -> Res<Box<dyn Connector>> {
        Ok(Box::new(FakeConnector {
            name: name.to_string(),
            drv: self.clone(),
            closed: Mutex::new(false),
        }))
    }
}

/// Go's `fakeConnector`.
pub struct FakeConnector {
    name: String,
    drv: FakeDriver,
    closed: Mutex<bool>,
}

impl Connector for FakeConnector {
    fn connect(&self, _ctx: &Context) -> Res<Box<dyn driver::Conn>> {
        driver::Driver::open(&self.drv, &self.name)
    }

    fn driver(&self) -> Arc<dyn driver::Driver> {
        Arc::new(self.drv.clone())
    }

    fn close(&self) -> Res<()> {
        let mut closed = lock(&self.closed);
        if *closed {
            return Err(Error::new("fakedb: connector is closed"));
        }
        *closed = true;
        Ok(())
    }
}

#[derive(Default)]
struct DbData {
    tables: HashMap<String, Arc<Table>>,
    bad_conn: bool,
}

pub struct FakeDb {
    name: String,
    m: Mutex<DbData>,
}

struct Table {
    m: Mutex<TableData>,
}

struct TableData {
    colname: Vec<String>,
    coltype: Vec<String>,
    rows: Vec<Vec<Value>>,
}

impl TableData {
    fn column_index(&self, name: &str) -> Option<usize> {
        self.colname.iter().position(|c| c == name)
    }
}

impl FakeDb {
    fn wipe(&self) {
        lock(&self.m).tables.clear();
    }

    fn create_table(
        &self,
        name: &str,
        column_names: &[String],
        column_types: &[String],
    ) -> Res<()> {
        let mut d = lock(&self.m);
        if d.tables.contains_key(name) {
            return Err(errf(format!(
                "table {} already exists",
                strconv::quote(name)
            )));
        }
        if column_names.len() != column_types.len() {
            return Err(errf(format!(
                "create table of {} len(names) != len(types): {} vs {}",
                strconv::quote(name),
                column_names.len(),
                column_types.len()
            )));
        }
        d.tables.insert(
            name.to_string(),
            Arc::new(Table {
                m: Mutex::new(TableData {
                    colname: column_names.to_vec(),
                    coltype: column_types.to_vec(),
                    rows: Vec::new(),
                }),
            }),
        );
        Ok(())
    }

    fn table(&self, name: &str) -> Option<Arc<Table>> {
        lock(&self.m).tables.get(name).cloned()
    }

    fn column_type(&self, table: &str, column: &str) -> Option<String> {
        let t = self.table(table)?;
        let t = lock(&t.m);
        t.column_index(column).map(|i| t.coltype[i].clone())
    }
}

#[derive(Default)]
struct ConnData {
    db: Option<Arc<FakeDb>>,
    curr_tx: bool,
    stmts_made: i64,
    stmts_closed: i64,
    num_prepare: i64,
    bad: bool,
    sticky_bad: bool,
    skip_dirty_session: bool,
    dirty_session: bool,
}

/// Go's `fakeConn`.
pub struct FakeConn {
    c: Arc<Mutex<ConnData>>,
    drv: FakeDriver,
}

/// Go's `getFakeConn` and the fields tests poke at.
impl FakeConn {
    pub fn set_skip_dirty_session(&self, v: bool) {
        lock(&self.c).skip_dirty_session = v;
    }

    pub fn set_sticky_bad(&self, v: bool) {
        lock(&self.c).sticky_bad = v;
    }

    pub fn num_prepare(&self) -> i64 {
        lock(&self.c).num_prepare
    }

    pub fn stmts_made_closed(&self) -> (i64, i64) {
        let d = lock(&self.c);
        (d.stmts_made, d.stmts_closed)
    }
}

/// Reaches the `FakeConn` behind `Conn::raw`'s `&mut dyn driver::Conn`.
pub fn with_fake_conn<R>(ci: &mut dyn driver::Conn, f: impl FnOnce(&FakeConn) -> R) -> R {
    let fc = ci
        .as_any()
        .and_then(|a| a.downcast_ref::<FakeConn>())
        .expect("a fakedb connection");
    f(fc)
}

fn is_bad(c: &Arc<Mutex<ConnData>>) -> bool {
    let d = lock(c);
    if d.sticky_bad {
        true
    } else if d.bad {
        match &d.db {
            None => false,
            Some(db) => {
                let mut dd = lock(&db.m);
                dd.bad_conn = !dd.bad_conn;
                dd.bad_conn
            }
        }
    } else {
        false
    }
}

fn is_dirty_and_mark(c: &Arc<Mutex<ConnData>>) -> bool {
    let mut d = lock(c);
    if d.skip_dirty_session {
        return false;
    }
    if d.curr_tx {
        d.dirty_session = true;
        return false;
    }
    if d.dirty_session {
        return true;
    }
    d.dirty_session = true;
    false
}

struct FakeTx {
    c: Arc<Mutex<ConnData>>,
}

impl driver::Tx for FakeTx {
    fn commit(&mut self) -> Res<()> {
        lock(&self.c).curr_tx = false;
        Ok(())
    }

    fn rollback(&mut self) -> Res<()> {
        lock(&self.c).curr_tx = false;
        Ok(())
    }
}

impl driver::Conn for FakeConn {
    fn prepare(&mut self, _query: &str) -> Res<Box<dyn driver::Stmt>> {
        panic!("use PrepareContext")
    }

    fn close(&mut self) -> Res<()> {
        let result = {
            let mut d = lock(&self.c);
            if d.curr_tx {
                Err(Error::new("fakedb: can't close fakeConn; in a Transaction"))
            } else if d.db.is_none() {
                Err(Error::new("fakedb: can't close fakeConn; already closed"))
            } else if d.stmts_made > d.stmts_closed {
                Err(Error::new("fakedb: can't close; dangling statement(s)"))
            } else {
                d.db = None;
                Ok(())
            }
        };
        if result.is_ok() {
            lock(&self.drv.data).close_count += 1;
        }
        result
    }

    fn begin(&mut self) -> Res<Box<dyn driver::Tx>> {
        if is_bad(&self.c) {
            return Err(fake_error("", driver::ERR_BAD_CONN));
        }
        let mut d = lock(&self.c);
        if d.curr_tx {
            return Err(Error::new("fakedb: already in a transaction"));
        }
        d.curr_tx = true;
        Ok(Box::new(FakeTx { c: self.c.clone() }))
    }

    fn as_execer_context(&mut self) -> Option<&mut dyn ExecerContext> {
        Some(self)
    }

    fn as_queryer_context(&mut self) -> Option<&mut dyn QueryerContext> {
        Some(self)
    }

    fn as_conn_prepare_context(&mut self) -> Option<&mut dyn ConnPrepareContext> {
        Some(self)
    }

    fn as_session_resetter(&mut self) -> Option<&mut dyn SessionResetter> {
        Some(self)
    }

    fn as_validator(&mut self) -> Option<&mut dyn Validator> {
        Some(self)
    }

    fn as_any(&mut self) -> Option<&mut dyn std::any::Any> {
        Some(self)
    }
}

impl SessionResetter for FakeConn {
    fn reset_session(&mut self, _ctx: &Context) -> Res<()> {
        {
            let mut d = lock(&self.c);
            d.dirty_session = false;
            d.curr_tx = false;
        }
        if is_bad(&self.c) {
            return Err(fake_error("Reset Session: bad conn", driver::ERR_BAD_CONN));
        }
        Ok(())
    }
}

impl Validator for FakeConn {
    fn is_valid(&mut self) -> bool {
        !is_bad(&self.c)
    }
}

impl ExecerContext for FakeConn {
    fn exec_context(
        &mut self,
        _ctx: &Context,
        _query: &str,
        _args: &[NamedValue],
    ) -> Res<Box<dyn driver::Result>> {
        Err(driver::ERR_SKIP)
    }
}

impl QueryerContext for FakeConn {
    fn query_context(
        &mut self,
        _ctx: &Context,
        _query: &str,
        _args: &[NamedValue],
    ) -> Res<Box<dyn driver::Rows>> {
        Err(driver::ERR_SKIP)
    }
}

#[derive(Clone)]
struct BoundCol {
    column: String,
    placeholder: String,
    ordinal: usize,
}

#[derive(Clone)]
enum ColVal {
    /// A `?` or `?name` placeholder.
    Placeholder(String),
    Bound(Value),
}

struct FakeStmt {
    c: Arc<Mutex<ConnData>>,
    cmd: String,
    table: String,
    next: Option<Box<FakeStmt>>,
    closed: bool,
    col_name: Vec<String>,
    col_type: Vec<String>,
    col_value: Vec<ColVal>,
    placeholders: usize,
    where_col: Vec<BoundCol>,
    placeholder_converter: Vec<String>,
}

impl FakeStmt {
    fn db(&self) -> Arc<FakeDb> {
        lock(&self.c).db.clone().expect("conn's db is nil")
    }

    fn close_stmt(&mut self) {
        {
            let mut d = lock(&self.c);
            assert!(
                d.db.is_some(),
                "in fakeStmt.Close, conn's db is nil (already closed)"
            );
            if !self.closed {
                d.stmts_closed += 1;
                self.closed = true;
            }
        }
        if let Some(n) = &mut self.next {
            n.close_stmt();
        }
    }
}

impl FakeConn {
    fn db(&self) -> Arc<FakeDb> {
        lock(&self.c).db.clone().expect("conn's db is nil")
    }

    fn prepare_select(&self, stmt: &mut FakeStmt, parts: &[&str]) -> Res<()> {
        if parts.len() != 3 {
            stmt.close_stmt();
            return Err(errf(format!(
                "invalid SELECT syntax with {} parts; want 3",
                parts.len()
            )));
        }
        stmt.table = parts[0].to_string();
        stmt.col_name = parts[1].split(',').map(String::from).collect();
        for (n, colspec) in parts[2].split(',').enumerate() {
            if colspec.is_empty() {
                continue;
            }
            let name_val: Vec<&str> = colspec.split('=').collect();
            if name_val.len() != 2 {
                stmt.close_stmt();
                return Err(errf(format!(
                    "SELECT on table {} has invalid column spec of {} (index {})",
                    strconv::quote(&stmt.table),
                    strconv::quote(colspec),
                    n
                )));
            }
            let (column, value) = (name_val[0], name_val[1]);
            if self.db().column_type(&stmt.table, column).is_none() {
                stmt.close_stmt();
                return Err(errf(format!(
                    "SELECT on table {} references non-existent column {}",
                    strconv::quote(&stmt.table),
                    strconv::quote(column)
                )));
            }
            if !value.starts_with('?') {
                stmt.close_stmt();
                return Err(errf(format!(
                    "SELECT on table {} has pre-bound value for where column {}; need a question mark",
                    strconv::quote(&stmt.table),
                    strconv::quote(column)
                )));
            }
            stmt.placeholders += 1;
            stmt.where_col.push(BoundCol {
                column: column.to_string(),
                placeholder: value.to_string(),
                ordinal: stmt.placeholders,
            });
        }
        Ok(())
    }

    fn prepare_create(&self, stmt: &mut FakeStmt, parts: &[&str]) -> Res<()> {
        if parts.len() != 2 {
            stmt.close_stmt();
            return Err(errf(format!(
                "invalid CREATE syntax with {} parts; want 2",
                parts.len()
            )));
        }
        stmt.table = parts[0].to_string();
        for (n, colspec) in parts[1].split(',').enumerate() {
            let name_type: Vec<&str> = colspec.split('=').collect();
            if name_type.len() != 2 {
                stmt.close_stmt();
                return Err(errf(format!(
                    "CREATE table {} has invalid column spec of {} (index {})",
                    strconv::quote(&stmt.table),
                    strconv::quote(colspec),
                    n
                )));
            }
            stmt.col_name.push(name_type[0].to_string());
            stmt.col_type.push(name_type[1].to_string());
        }
        Ok(())
    }

    fn prepare_insert(&self, stmt: &mut FakeStmt, parts: &[&str]) -> Res<()> {
        if parts.len() != 2 {
            stmt.close_stmt();
            return Err(errf(format!(
                "invalid INSERT syntax with {} parts; want 2",
                parts.len()
            )));
        }
        stmt.table = parts[0].to_string();
        for (n, colspec) in parts[1].split(',').enumerate() {
            let name_val: Vec<&str> = colspec.split('=').collect();
            if name_val.len() != 2 {
                stmt.close_stmt();
                return Err(errf(format!(
                    "INSERT table {} has invalid column spec of {} (index {})",
                    strconv::quote(&stmt.table),
                    strconv::quote(colspec),
                    n
                )));
            }
            let (column, value) = (name_val[0], name_val[1]);
            let Some(ctype) = self.db().column_type(&stmt.table, column) else {
                stmt.close_stmt();
                return Err(errf(format!(
                    "INSERT table {} references non-existent column {}",
                    strconv::quote(&stmt.table),
                    strconv::quote(column)
                )));
            };
            stmt.col_name.push(column.to_string());
            if !value.starts_with('?') {
                let subset_val = match ctype.as_str() {
                    "string" | "blob" => Value::Bytes(value.as_bytes().to_vec()),
                    "int32" => match strconv::atoi(value) {
                        Ok(i) => Value::Int64(i as i64),
                        Err(_) => {
                            stmt.close_stmt();
                            return Err(errf(format!(
                                "invalid conversion to int32 from {}",
                                strconv::quote(value)
                            )));
                        }
                    },
                    _ => {
                        stmt.close_stmt();
                        return Err(errf(format!(
                            "unsupported conversion for pre-bound parameter {} to type {}",
                            strconv::quote(value),
                            strconv::quote(&ctype)
                        )));
                    }
                };
                stmt.col_value.push(ColVal::Bound(subset_val));
            } else {
                stmt.placeholders += 1;
                stmt.placeholder_converter.push(ctype);
                stmt.col_value.push(ColVal::Placeholder(value.to_string()));
            }
        }
        Ok(())
    }
}

impl ConnPrepareContext for FakeConn {
    fn prepare_context(&mut self, _ctx: &Context, query: &str) -> Res<Box<dyn driver::Stmt>> {
        {
            let mut d = lock(&self.c);
            d.num_prepare += 1;
            assert!(d.db.is_some(), "nil c.db");
        }
        if lock(&self.c).sticky_bad {
            return Err(fake_error("Prepare: Sticky Bad", driver::ERR_BAD_CONN));
        }
        let mut stmts: Vec<FakeStmt> = Vec::new();
        for q in query.split(';') {
            let mut parts: Vec<&str> = q.split('|').collect();
            let mut stmt = FakeStmt {
                c: self.c.clone(),
                cmd: String::new(),
                table: String::new(),
                next: None,
                closed: false,
                col_name: Vec::new(),
                col_type: Vec::new(),
                col_value: Vec::new(),
                placeholders: 0,
                where_col: Vec::new(),
                placeholder_converter: Vec::new(),
            };
            let cmd = parts.remove(0);
            stmt.cmd = cmd.to_string();
            lock(&self.c).stmts_made += 1;
            let result = match cmd {
                "WIPE" => Ok(()),
                "SELECT" => self.prepare_select(&mut stmt, &parts),
                "CREATE" => self.prepare_create(&mut stmt, &parts),
                "INSERT" | "NOSERT" => self.prepare_insert(&mut stmt, &parts),
                _ => {
                    stmt.close_stmt();
                    Err(errf(format!(
                        "unsupported command type {}",
                        strconv::quote(cmd)
                    )))
                }
            };
            result?;
            stmts.push(stmt);
        }
        // Chain the statements: each one's `next` is the one after it.
        let mut chain = stmts.pop().expect("split yields at least one statement");
        while let Some(mut prev) = stmts.pop() {
            prev.next = Some(Box::new(chain));
            chain = prev;
        }
        Ok(Box::new(chain))
    }
}

struct FakeDriverString;

impl ValueConverter for FakeDriverString {
    fn convert_value(&self, v: &Arg) -> Res<Value> {
        match v {
            Arg::String(s) => Ok(Value::String(s.clone())),
            Arg::Bytes(b) => Ok(Value::Bytes(b.clone())),
            Arg::Pointer(None) => Ok(Value::Null),
            Arg::Pointer(Some(inner)) if matches!(**inner, Arg::String(_)) => {
                self.convert_value(inner)
            }
            _ => Ok(Value::String(v.format_v())),
        }
    }
}

struct AnyTypeConverter;

impl ValueConverter for AnyTypeConverter {
    fn convert_value(&self, v: &Arg) -> Res<Value> {
        if driver::is_value(v) {
            return DEFAULT_PARAMETER_CONVERTER.convert_value(v);
        }
        Err(errf(format!(
            "invalid argument: {}, type {}",
            v.format_v(),
            v.type_name()
        )))
    }
}

fn boxed(c: impl ValueConverter + 'static) -> Box<dyn ValueConverter> {
    Box::new(c)
}

fn converter_for_type(typ: &str) -> Box<dyn ValueConverter> {
    let not_null = |c: Box<dyn ValueConverter>| boxed(driver::NotNull { converter: c });
    let null = |c: Box<dyn ValueConverter>| boxed(driver::Null { converter: c });
    match typ {
        "bool" => boxed(driver::BOOL),
        "nullbool" => null(boxed(driver::BOOL)),
        "byte" | "int16" | "int64" | "float64" | "datetime" | "uuid" => {
            not_null(boxed(DEFAULT_PARAMETER_CONVERTER))
        }
        "int32" => boxed(driver::INT32),
        "nullbyte" | "nullint32" | "nullint16" | "nullint64" | "nullfloat64" | "nulldatetime"
        | "nulluuid" | "nulltable" => null(boxed(DEFAULT_PARAMETER_CONVERTER)),
        "string" => not_null(boxed(FakeDriverString)),
        "nullstring" => null(boxed(FakeDriverString)),
        "any" => boxed(AnyTypeConverter),
        _ => panic!("invalid fakedb column type of {typ}"),
    }
}

fn col_type_to_scan_type(typ: &str) -> ScanType {
    match typ {
        "bool" => ScanType::BOOL,
        "nullbool" => ScanType::NULL_BOOL,
        "int16" => ScanType::INT16,
        "nullint16" => ScanType::NULL_INT16,
        "int32" => ScanType::INT32,
        "nullint32" => ScanType::NULL_INT32,
        "string" => ScanType::STRING,
        "nullstring" => ScanType::NULL_STRING,
        "int64" => ScanType::INT64,
        "nullint64" => ScanType::NULL_INT64,
        "float64" => ScanType::FLOAT64,
        "nullfloat64" => ScanType::NULL_FLOAT64,
        "datetime" => ScanType::TIME,
        "any" => ScanType::ANY,
        _ => panic!("invalid fakedb column type of {typ}"),
    }
}

impl ColumnConverter for FakeStmt {
    fn column_converter(&mut self, idx: usize) -> Box<dyn ValueConverter> {
        if self.placeholder_converter.is_empty() {
            return boxed(DEFAULT_PARAMETER_CONVERTER);
        }
        converter_for_type(&self.placeholder_converter[idx])
    }
}

fn value_from_placeholder_name(args: &[NamedValue], name: &str) -> Value {
    args.iter()
        .find(|a| a.name == name)
        .map_or(Value::Null, |a| a.value.clone())
}

impl FakeStmt {
    fn exec_insert(&self, args: &[NamedValue], do_insert: bool) -> Res<Box<dyn driver::Result>> {
        let db = self.db();
        assert!(
            args.len() == self.placeholders,
            "error in pkg db; should only get here if size is correct"
        );
        let Some(t) = db.table(&self.table) else {
            return Err(errf(format!(
                "table {} doesn't exist",
                strconv::quote(&self.table)
            )));
        };
        let mut t = lock(&t.m);
        let mut cols: Vec<Value> = if do_insert {
            vec![Value::Null; t.colname.len()]
        } else {
            Vec::new()
        };
        let mut arg_pos = 0;
        for (n, colname) in self.col_name.iter().enumerate() {
            let Some(colidx) = t.column_index(colname) else {
                return Err(errf(format!(
                    "column {} doesn't exist or dropped since prepared statement was created",
                    strconv::quote(colname)
                )));
            };
            let val = match &self.col_value[n] {
                ColVal::Placeholder(p) => {
                    let v = if p == "?" {
                        args[arg_pos].value.clone()
                    } else {
                        value_from_placeholder_name(args, &p[1..])
                    };
                    arg_pos += 1;
                    v
                }
                ColVal::Bound(v) => v.clone(),
            };
            if do_insert {
                cols[colidx] = val;
            }
        }
        if do_insert {
            t.rows.push(cols);
        }
        Ok(Box::new(driver::RowsAffected(1)))
    }
}

impl driver::Stmt for FakeStmt {
    fn close(&mut self) -> Res<()> {
        self.close_stmt();
        Ok(())
    }

    fn num_input(&mut self) -> i64 {
        self.placeholders as i64
    }

    fn exec(&mut self, _args: &[Value]) -> Res<Box<dyn driver::Result>> {
        panic!("Using ExecContext")
    }

    fn query(&mut self, _args: &[Value]) -> Res<Box<dyn driver::Rows>> {
        panic!("Use QueryContext")
    }

    fn as_stmt_exec_context(&mut self) -> Option<&mut dyn StmtExecContext> {
        Some(self)
    }

    fn as_stmt_query_context(&mut self) -> Option<&mut dyn StmtQueryContext> {
        Some(self)
    }

    fn as_column_converter(&mut self) -> Option<&mut dyn ColumnConverter> {
        Some(self)
    }
}

impl StmtExecContext for FakeStmt {
    fn exec_context(&mut self, ctx: &Context, args: &[NamedValue]) -> Res<Box<dyn driver::Result>> {
        if self.closed {
            return Err(Error::new("fakedb: statement has been closed"));
        }
        if lock(&self.c).sticky_bad {
            return Err(fake_error("Exec: Sticky Bad", driver::ERR_BAD_CONN));
        }
        if is_dirty_and_mark(&self.c) {
            return Err(Error::new("fakedb: session is dirty"));
        }
        ctx.check().map_err(Error::from)?;
        let db = self.db();
        match self.cmd.as_str() {
            "WIPE" => {
                db.wipe();
                Ok(Box::new(driver::RESULT_NO_ROWS))
            }
            "CREATE" => {
                db.create_table(&self.table, &self.col_name, &self.col_type)?;
                Ok(Box::new(driver::RESULT_NO_ROWS))
            }
            "INSERT" => self.exec_insert(args, true),
            "NOSERT" => self.exec_insert(args, false),
            cmd => Err(Error::new(format!(
                "fakedb: unimplemented statement Exec command type of {}",
                strconv::quote(cmd)
            ))),
        }
    }
}

impl StmtQueryContext for FakeStmt {
    fn query_context(&mut self, _ctx: &Context, args: &[NamedValue]) -> Res<Box<dyn driver::Rows>> {
        if self.closed {
            return Err(Error::new("fakedb: statement has been closed"));
        }
        if lock(&self.c).sticky_bad {
            return Err(fake_error("Query: Sticky Bad", driver::ERR_BAD_CONN));
        }
        if is_dirty_and_mark(&self.c) {
            return Err(Error::new("fakedb: session is dirty"));
        }
        let db = self.db();
        assert!(
            args.len() == self.placeholders,
            "error in pkg db; should only get here if size is correct"
        );
        let mut set_rows: Vec<Vec<Vec<Value>>> = Vec::new();
        let mut set_cols: Vec<Vec<String>> = Vec::new();
        let mut set_types: Vec<Vec<String>> = Vec::new();
        let mut s: &FakeStmt = self;
        loop {
            let Some(t) = db.table(&s.table) else {
                return Err(errf(format!(
                    "table {} doesn't exist",
                    strconv::quote(&s.table)
                )));
            };
            if s.table == "tx_status" && s.col_name[0] == "tx_status" {
                let status = if lock(&s.c).curr_tx {
                    "transaction"
                } else {
                    "autocommit"
                };
                return Ok(Box::new(RowsCursor {
                    rows: vec![vec![vec![Value::String(status.to_string())]]],
                    cols: vec![vec!["tx_status".to_string()]],
                    col_type: vec![vec!["string".to_string()]],
                    pos_set: 0,
                    pos_row: -1,
                    closed: false,
                    err_pos: -1,
                    err: None,
                }));
            }
            let t = lock(&t.m);
            let mut col_idx: HashMap<&str, usize> = HashMap::new();
            for name in &s.col_name {
                let Some(idx) = t.column_index(name) else {
                    return Err(errf(format!(
                        "unknown column name {}",
                        strconv::quote(name)
                    )));
                };
                col_idx.insert(name, idx);
            }
            let mut mrows: Vec<Vec<Value>> = Vec::new();
            'rows: for trow in &t.rows {
                for wcol in &s.where_col {
                    let Some(idx) = t.column_index(&wcol.column) else {
                        return Err(errf(format!(
                            "invalid where clause column {{{} {} {}}}",
                            wcol.column, wcol.placeholder, wcol.ordinal
                        )));
                    };
                    let tcol = match &trow[idx] {
                        Value::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
                        other => fmt_v(other),
                    };
                    let arg_value = if wcol.placeholder == "?" {
                        args[wcol.ordinal - 1].value.clone()
                    } else {
                        value_from_placeholder_name(args, &wcol.placeholder[1..])
                    };
                    if tcol != fmt_v(&arg_value) {
                        continue 'rows;
                    }
                }
                mrows.push(
                    s.col_name
                        .iter()
                        .map(|n| trow[col_idx[n.as_str()]].clone())
                        .collect(),
                );
            }
            let col_type: Vec<String> = s
                .col_name
                .iter()
                .map(|c| t.coltype[t.column_index(c).expect("checked above")].clone())
                .collect();
            set_rows.push(mrows);
            set_cols.push(s.col_name.clone());
            set_types.push(col_type);
            match &s.next {
                None => break,
                Some(n) => s = n,
            }
        }
        Ok(Box::new(RowsCursor {
            rows: set_rows,
            cols: set_cols,
            col_type: set_types,
            pos_set: 0,
            pos_row: -1,
            closed: false,
            err_pos: -1,
            err: None,
        }))
    }
}

/// Go's `rowsCursor`.
pub struct RowsCursor {
    cols: Vec<Vec<String>>,
    col_type: Vec<Vec<String>>,
    pos_set: usize,
    pos_row: isize,
    rows: Vec<Vec<Vec<Value>>>,
    closed: bool,
    err_pos: isize,
    err: Option<Error>,
}

impl driver::Rows for RowsCursor {
    fn columns(&self) -> Vec<String> {
        self.cols[self.pos_set].clone()
    }

    fn close(&mut self) -> Res<()> {
        self.closed = true;
        Ok(())
    }

    fn next(&mut self, dest: &mut [Value]) -> Res<()> {
        if self.closed {
            return Err(Error::new("fakedb: cursor is closed"));
        }
        self.pos_row += 1;
        if self.pos_row == self.err_pos {
            return Err(self.err.clone().expect("error position set with error"));
        }
        let set = &self.rows[self.pos_set];
        if self.pos_row as usize >= set.len() {
            return Err(driver::EOF);
        }
        for (i, v) in set[self.pos_row as usize].iter().enumerate() {
            dest[i] = v.clone();
        }
        Ok(())
    }

    fn as_rows_next_result_set(&mut self) -> Option<&mut dyn RowsNextResultSet> {
        Some(self)
    }

    fn as_rows_column_type_scan_type(&self) -> Option<&dyn RowsColumnTypeScanType> {
        Some(self)
    }
}

impl RowsNextResultSet for RowsCursor {
    fn has_next_result_set(&self) -> bool {
        self.pos_set + 1 < self.rows.len()
    }

    fn next_result_set(&mut self) -> Res<()> {
        if self.has_next_result_set() {
            self.pos_set += 1;
            self.pos_row = -1;
            return Ok(());
        }
        Err(driver::EOF)
    }
}

impl RowsColumnTypeScanType for RowsCursor {
    fn column_type_scan_type(&self, index: usize) -> ScanType {
        col_type_to_scan_type(&self.col_type[self.pos_set][index])
    }
}
