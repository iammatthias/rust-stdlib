//! `Rows`, `Row` and `ColumnType` (Go's `sql.Rows`, `sql.Row`,
//! `sql.ColumnType`).
use super::convert::Scanner;
use super::ctxutil::Ctx;
use super::db::{lock, DriverConn, DriverStmt, ReleaseConn};
use super::driver::{self, ScanContext, ScanType, Value};
use super::error::{Error, Res, EOF, ERR_NO_ROWS, ERR_ROWS_CLOSED};
use super::tx::TxInner;
use crate::strconv;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

struct RowsState {
    rowsi: Box<dyn driver::Rows>,
    /// Go's `cancel`: ends the context watcher when the rows close.
    cancel: Option<crate::context::CancelFunc>,
    /// The statement to close on close, for rows from a one-shot query.
    close_stmt: Option<Arc<DriverStmt>>,
    /// Non-nil only if `closed` is true, except [`EOF`] during iteration.
    lasterr: Option<Error>,
    closed: bool,
    /// Go's `closemuScanHold`: a `RawBytes` scan is outstanding.
    scan_hold: bool,
    next_called: bool,
    lastcols: Option<Vec<Value>>,
    num_cols: usize,
}

impl RowsState {
    /// Go's `lasterrOrErrLocked`.
    fn lasterr_or(&self, err: Option<Error>) -> Option<Error> {
        match &self.lasterr {
            Some(e) if *e != EOF => Some(e.clone()),
            _ => err,
        }
    }
}

pub(crate) struct RowsShared {
    dc: Arc<DriverConn>,
    release_conn: ReleaseConn,
    /// The error the context watcher saw, set before it closes the rows.
    context_done: Mutex<Option<Error>>,
    hit_eof: AtomicBool,
    /// Go's `closemu` and the fields it guards.
    state: Mutex<RowsState>,
}

/// Go's `sql.Rows`: the result of a query. Iterate with
/// `while let Some(mut row) = rows.next_row()? { row.scan(..)?; }`; close it
/// (or drop it) to release the connection. [`Rows::next_row`] folds Go's
/// `Next` and `Err` together: `Ok(None)` is a clean end, `Err` a failed one.
pub struct Rows {
    shared: Arc<RowsShared>,
}

impl Rows {
    pub(crate) fn new(
        _id: u64,
        dc: Arc<DriverConn>,
        release_conn: ReleaseConn,
        rowsi: Box<dyn driver::Rows>,
        close_stmt: Option<Arc<DriverStmt>>,
    ) -> Rows {
        Rows {
            shared: Arc::new(RowsShared {
                dc,
                release_conn,
                context_done: Mutex::new(None),
                hit_eof: AtomicBool::new(false),
                state: Mutex::new(RowsState {
                    rowsi,
                    cancel: None,
                    close_stmt,
                    lasterr: None,
                    closed: false,
                    scan_hold: false,
                    next_called: false,
                    lastcols: None,
                    num_cols: 0,
                }),
            }),
        }
    }
}

impl RowsShared {
    pub(crate) fn set_context_done(&self, err: Error) {
        *lock(&self.context_done) = Some(err);
    }

    pub(crate) fn is_closed(&self) -> bool {
        lock(&self.state).closed
    }

    pub(crate) fn close(&self, err: Option<Error>) -> Res<()> {
        let mut st = lock(&self.state);
        if st.closed {
            return Ok(());
        }
        st.closed = true;
        if st.lasterr.is_none() {
            st.lasterr = err;
        }
        let close_err = {
            let _g = lock(&self.dc.state);
            st.rowsi.close().err()
        };
        if let Some(cancel) = &st.cancel {
            cancel();
        }
        if let Some(ds) = st.close_stmt.take() {
            let _ = ds.close();
        }
        (self.release_conn)(close_err.clone());
        st.lasterr = st.lasterr_or(close_err.clone());
        match close_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Returns (do_close, ok).
    fn next_locked(&self, st: &mut RowsState) -> (bool, bool) {
        if st.closed {
            return (false, false);
        }
        let _g = lock(&self.dc.state);
        if !st.next_called {
            st.num_cols = st.rowsi.columns().len();
            st.next_called = true;
        }
        let err = if let Some(rscan) = st.rowsi.as_rows_column_scanner() {
            rscan.next_row().err()
        } else {
            let num_cols = st.num_cols;
            let cols = st
                .lastcols
                .get_or_insert_with(|| vec![Value::Null; num_cols]);
            st.rowsi.next(cols).err()
        };
        st.lasterr = err;
        if let Some(e) = &st.lasterr {
            if *e != EOF {
                return (true, false);
            }
            // EOF: if there are more result sets, keep the rows open.
            let Some(nrs) = st.rowsi.as_rows_next_result_set() else {
                return (true, false);
            };
            return (!nrs.has_next_result_set(), false);
        }
        (false, true)
    }
}

impl Rows {
    /// Starts the watcher that closes the rows when `ctx` is done and
    /// registers them with their transaction.
    pub(crate) fn init_context_close(&self, ctx: Ctx<'_>, tx: Option<&Arc<TxInner>>) {
        if let Some(c) = ctx {
            let (closectx, cancel) = c.with_cancel();
            lock(&self.shared.state).cancel = Some(cancel);
            let shared = self.shared.clone();
            let ctx = c.clone();
            let _ = std::thread::Builder::new()
                .name("sql-rows-await".into())
                .spawn(move || {
                    closectx.done().wait();
                    let err = ctx.check().err().map(Error::from);
                    if let Some(e) = &err {
                        shared.set_context_done(e.clone());
                    }
                    let _ = shared.close(err);
                });
        }
        if let Some(tx) = tx {
            tx.register_rows(&self.shared);
        }
    }

    /// The next result row, ready to [`scan`](CurrentRow::scan); `Ok(None)`
    /// when the rows are exhausted and `Err` when iteration failed (what Go
    /// reports through `Err` after `Next` returns false). Rows closes itself
    /// at the end.
    pub fn next_row(&mut self) -> Res<Option<CurrentRow>> {
        if self.advance() {
            Ok(Some(CurrentRow {
                shared: self.shared.clone(),
            }))
        } else {
            self.iteration_err().map(|()| None)
        }
    }

    /// Go's `Next`: prepares the next result row for reading.
    fn advance(&mut self) -> bool {
        let sh = &self.shared;
        self.release_scan_hold();
        if lock(&sh.context_done).is_some() {
            return false;
        }
        let (do_close, ok) = {
            let mut st = lock(&sh.state);
            sh.next_locked(&mut st)
        };
        if do_close {
            let _ = sh.close(None);
        }
        if do_close && !ok {
            sh.hit_eof.store(true, Ordering::Relaxed);
        }
        ok
    }

    fn release_scan_hold(&self) {
        lock(&self.shared.state).scan_hold = false;
    }

    /// Go's `NextResultSet`: advances to the next result set, if any.
    pub fn next_result_set(&mut self) -> bool {
        let sh = &self.shared;
        let mut st = lock(&sh.state);
        st.scan_hold = false;
        if st.closed {
            return false;
        }
        st.next_called = false;
        st.lastcols = None;
        if st.rowsi.as_rows_next_result_set().is_none() {
            drop(st);
            let _ = sh.close(None);
            return false;
        }
        let _g = lock(&sh.dc.state);
        let err = st
            .rowsi
            .as_rows_next_result_set()
            .and_then(|n| n.next_result_set().err());
        st.lasterr = err;
        let failed = st.lasterr.is_some();
        drop(_g);
        drop(st);
        if failed {
            let _ = sh.close(None);
            return false;
        }
        true
    }

    /// Go's `Err`: the error, if any, encountered during iteration.
    fn iteration_err(&self) -> Res<()> {
        let sh = &self.shared;
        if !sh.hit_eof.load(Ordering::Relaxed) {
            if let Some(e) = lock(&sh.context_done).clone() {
                return Err(e);
            }
        }
        let st = lock(&sh.state);
        match st.lasterr_or(None) {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Go's `Columns`: the column names.
    pub fn columns(&self) -> Res<Vec<String>> {
        self.shared.columns()
    }

    /// Go's `ColumnTypes`: column information such as names and types.
    pub fn column_types(&self) -> Res<Vec<ColumnType>> {
        let st = lock(&self.shared.state);
        if st.closed {
            return Err(st
                .lasterr_or(Some(ERR_ROWS_CLOSED))
                .unwrap_or(ERR_ROWS_CLOSED));
        }
        let _g = lock(&self.shared.dc.state);
        Ok(column_info(&*st.rowsi))
    }

    /// Go's `Close`: prevents further enumeration and releases the
    /// connection. It is idempotent and does not change the error [`Rows::next_row`] reports.
    pub fn close(&mut self) -> Res<()> {
        self.release_scan_hold();
        self.shared.close(None)
    }
}

impl RowsShared {
    fn columns(&self) -> Res<Vec<String>> {
        let st = lock(&self.state);
        if st.closed {
            return Err(st
                .lasterr_or(Some(ERR_ROWS_CLOSED))
                .unwrap_or(ERR_ROWS_CLOSED));
        }
        let _g = lock(&self.dc.state);
        Ok(st.rowsi.columns())
    }

    fn scan(&self, dest: &mut [&mut dyn Scanner]) -> Res<()> {
        let mut st = lock(&self.state);
        if st.scan_hold {
            return Err(Error::new(
                "sql: Scan called without calling Next (closemuScanHold)",
            ));
        }
        let result = self.scan_locked(&mut st, dest);
        if result.is_ok() && dest.iter().any(|d| d.is_raw_bytes()) {
            st.scan_hold = true;
        }
        result
    }

    fn scan_locked(&self, st: &mut RowsState, dest: &mut [&mut dyn Scanner]) -> Res<()> {
        if let Some(e) = &st.lasterr {
            if *e != EOF {
                return Err(e.clone());
            }
        }
        if st.closed {
            return Err(st
                .lasterr_or(Some(ERR_ROWS_CLOSED))
                .unwrap_or(ERR_ROWS_CLOSED));
        }
        if !st.next_called {
            return Err(Error::new("sql: Scan called without calling Next"));
        }
        if dest.len() != st.num_cols {
            return Err(Error::new(format!(
                "sql: expected {} destination arguments in Scan, not {}",
                st.num_cols,
                dest.len()
            )));
        }
        let column_error = |st: &RowsState, i: usize, e: Error| {
            let name = st.rowsi.columns().get(i).cloned().unwrap_or_default();
            Error::wrap(
                format!(
                    "sql: Scan error on column index {}, name {}: {}",
                    i,
                    strconv::quote(&name),
                    e
                ),
                e,
            )
        };
        if st.rowsi.as_rows_column_scanner().is_some() {
            let _g = lock(&self.dc.state);
            for (i, d) in dest.iter_mut().enumerate() {
                let r = st
                    .rowsi
                    .as_rows_column_scanner()
                    .map(|s| s.scan_column(ScanContext::default(), i, &mut **d));
                if let Some(Err(e)) = r {
                    return Err(column_error(st, i, e));
                }
            }
            return Ok(());
        }
        let cols = st.lastcols.clone().unwrap_or_default();
        for (i, sv) in cols.iter().enumerate() {
            if let Err(e) = dest[i].scan(sv) {
                return Err(column_error(st, i, e));
            }
        }
        Ok(())
    }
}

impl Drop for Rows {
    fn drop(&mut self) {
        let _ = self.shared.close(None);
    }
}

// ------------------------------------------------------------------ Row

/// The current row of a [`Rows`], as [`Rows::next_row`] yields it. It stays
/// bound to the cursor: once the rows advance or close, scanning reports
/// Go's errors for that state.
pub struct CurrentRow {
    shared: Arc<RowsShared>,
}

impl CurrentRow {
    /// Go's `Rows.Scan`: copies the columns of this row into `dest`,
    /// converting as [`super::convert_assign`] describes.
    pub fn scan(&mut self, dest: &mut [&mut dyn Scanner]) -> Res<()> {
        self.shared.scan(dest)
    }

    /// Go's `Rows.Columns`: the column names.
    pub fn columns(&self) -> Res<Vec<String>> {
        self.shared.columns()
    }
}

/// Go's `sql.Row`: the result of [`super::DB::query_row`]. Errors are
/// deferred until [`Row::scan`].
pub struct Row {
    err: Option<Error>,
    rows: Option<Rows>,
}

impl Row {
    pub(crate) fn from_result(r: Res<Rows>) -> Row {
        match r {
            Ok(rows) => Row {
                err: None,
                rows: Some(rows),
            },
            Err(e) => Row {
                err: Some(e),
                rows: None,
            },
        }
    }

    /// Go's `Scan`: copies the columns of the first matching row into `dest`.
    /// If there is no row it returns [`ERR_NO_ROWS`]. The rows are closed.
    pub fn scan(&mut self, dest: &mut [&mut dyn Scanner]) -> Res<()> {
        if let Some(e) = &self.err {
            return Err(e.clone());
        }
        let Some(rows) = self.rows.as_mut() else {
            return Err(ERR_NO_ROWS);
        };
        let result = (|| {
            if dest.iter().any(|d| d.is_raw_bytes()) {
                return Err(Error::new("sql: RawBytes isn't allowed on Row.Scan"));
            }
            let Some(mut row) = rows.next_row()? else {
                return Err(ERR_NO_ROWS);
            };
            row.scan(dest)?;
            rows.close()
        })();
        let _ = rows.close();
        result
    }

    /// Go's `Err`: the error, if any, encountered while running the query.
    pub fn err(&self) -> Res<()> {
        match &self.err {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }
}

// ------------------------------------------------------------ ColumnType

/// Go's `sql.ColumnType`: column metadata. Some information may not be
/// available from some drivers.
#[derive(Debug, Clone, PartialEq)]
pub struct ColumnType {
    name: String,
    nullable: Option<bool>,
    length: Option<i64>,
    precision_scale: Option<(i64, i64)>,
    database_type: String,
    scan_type: ScanType,
}

impl ColumnType {
    /// Go's `Name`: the name or alias of the column.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Go's `Length`: the column type length for variable-length types, or
    /// `None` if the type has no length or the driver does not report one.
    pub fn length(&self) -> Option<i64> {
        self.length
    }

    /// Go's `DecimalSize`: the precision and scale of decimal types.
    pub fn decimal_size(&self) -> Option<(i64, i64)> {
        self.precision_scale
    }

    /// Go's `ScanType`: a type suitable for scanning into with
    /// [`CurrentRow::scan`]. [`ScanType::ANY`] when the driver does not say.
    pub fn scan_type(&self) -> &ScanType {
        &self.scan_type
    }

    /// Go's `Nullable`: whether the column may be null, or `None` if the
    /// driver does not say.
    pub fn nullable(&self) -> Option<bool> {
        self.nullable
    }

    /// Go's `DatabaseTypeName`: the database system name of the column type,
    /// or the empty string if unsupported.
    pub fn database_type_name(&self) -> &str {
        &self.database_type
    }
}

/// Go's `rowsColumnInfoSetupConnLocked`.
fn column_info(rowsi: &dyn driver::Rows) -> Vec<ColumnType> {
    rowsi
        .columns()
        .into_iter()
        .enumerate()
        .map(|(i, name)| ColumnType {
            name,
            scan_type: rowsi
                .as_rows_column_type_scan_type()
                .map_or(ScanType::ANY, |p| p.column_type_scan_type(i)),
            database_type: rowsi
                .as_rows_column_type_database_type_name()
                .map(|p| p.column_type_database_type_name(i))
                .unwrap_or_default(),
            length: rowsi
                .as_rows_column_type_length()
                .and_then(|p| p.column_type_length(i)),
            nullable: rowsi
                .as_rows_column_type_nullable()
                .and_then(|p| p.column_type_nullable(i)),
            precision_scale: rowsi
                .as_rows_column_type_precision_scale()
                .and_then(|p| p.column_type_precision_scale(i)),
        })
        .collect()
}

impl std::fmt::Debug for Rows {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rows").finish_non_exhaustive()
    }
}
