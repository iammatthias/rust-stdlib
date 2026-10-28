//! `Stmt`: a prepared statement (Go's `sql.Stmt`).
use super::closemu::{ClosingMutex, ReadGuard};
use super::ctxutil::Ctx;
use super::db::{
    dc_release, lock, next_id, result_from_statement, rowsi_from_statement, DbInner, DbState,
    DriverConn, DriverStmt, FinalCloser, ReleaseConn, Strategy,
};
use super::error::{Error, Res};
use super::rows::{Row, Rows};
use super::tx::TxInner;
use super::{driver::Arg, Result as SqlResult};
use crate::context::Context;
use std::sync::{atomic::Ordering, Arc, Mutex};

/// What a statement bound to a `Tx` or `Conn` uses to get its connection
/// (Go's `stmtConnGrabber`).
pub(crate) trait StmtConnGrabber: Send + Sync {
    /// Returns the bound connection, blocking while it is busy with a
    /// closing operation.
    fn grab_conn(&self, ctx: Ctx<'_>) -> Res<(Arc<DriverConn>, ReleaseConn)>;
    /// The transaction, if this is one; rows of its statements close with it.
    fn tx(&self) -> Option<Arc<TxInner>>;
}

/// A statement prepared on one connection.
pub(crate) struct ConnStmt {
    pub(crate) dc: Arc<DriverConn>,
    pub(crate) ds: Arc<DriverStmt>,
}

pub(crate) struct StmtState {
    pub(crate) closed: bool,
    /// The statement of a `Tx` or `Conn` statement.
    cgds: Option<Arc<DriverStmt>>,
    /// The statement on each pool connection it has been prepared on.
    pub(crate) css: Vec<ConnStmt>,
    pub(crate) last_num_closed: u64,
}

pub(crate) struct StmtInner {
    pub(crate) id: u64,
    pub(crate) db: Arc<DbInner>,
    /// The text that created the statement.
    pub(crate) query: String,
    /// If set, returned by every operation.
    sticky_err: Option<Error>,
    /// Held for reading during operations and for writing during close.
    closemu: ClosingMutex,
    /// The `Tx` or `Conn` the statement is bound to, if any.
    pub(crate) cg: Option<Arc<dyn StmtConnGrabber>>,
    /// For a `Tx::stmt` statement, the statement it was derived from.
    parent_stmt: Option<Arc<StmtInner>>,
    pub(crate) mu: Mutex<StmtState>,
}

impl StmtInner {
    pub(crate) fn new(
        db: &Arc<DbInner>,
        query: &str,
        sticky_err: Option<Error>,
        cg: Option<Arc<dyn StmtConnGrabber>>,
        parent_stmt: Option<Arc<StmtInner>>,
        cgds: Option<Arc<DriverStmt>>,
    ) -> Arc<StmtInner> {
        Arc::new(StmtInner {
            id: next_id(),
            db: db.clone(),
            query: query.to_string(),
            sticky_err,
            closemu: ClosingMutex::new(),
            cg,
            parent_stmt,
            mu: Mutex::new(StmtState {
                closed: false,
                cgds,
                css: Vec::new(),
                last_num_closed: 0,
            }),
        })
    }

    /// Go's `removeClosedStmtLocked`: drops statements on closed connections
    /// once enough connections have closed.
    pub(crate) fn remove_closed_stmt_locked(&self, st: &mut StmtState) {
        let t = (st.css.len() / 2 + 1).min(10);
        let db_closed = self.db.num_closed.load(Ordering::Relaxed);
        if db_closed - st.last_num_closed < t as u64 {
            return;
        }
        let _db: std::sync::MutexGuard<'_, DbState> = self.db.lock();
        let mut i = 0;
        while i < st.css.len() {
            if lock(&st.css[i].dc.dbmu).dbmu_closed {
                st.css.swap_remove(i);
            } else {
                i += 1;
            }
        }
        st.last_num_closed = db_closed;
    }

    /// Prepares the statement on `dc`, whose lock the caller holds as `g`.
    pub(crate) fn prepare_on_conn_locked(
        &self,
        g: &mut super::db::DcState,
        ctx: Ctx<'_>,
        dc: &Arc<DriverConn>,
    ) -> Res<Arc<DriverStmt>> {
        let ds = dc.prepare_locked(g, ctx, self.cg.is_some(), &self.query)?;
        lock(&self.mu).css.push(ConnStmt {
            dc: dc.clone(),
            ds: ds.clone(),
        });
        Ok(ds)
    }

    /// Go's `connStmt`: a connection and the statement prepared on it.
    fn conn_stmt(
        &self,
        ctx: Ctx<'_>,
        strategy: Strategy,
    ) -> Res<(Arc<DriverConn>, ReleaseConn, Arc<DriverStmt>)> {
        if let Some(e) = &self.sticky_err {
            return Err(e.clone());
        }
        let mut st = lock(&self.mu);
        if st.closed {
            return Err(Error::new("sql: statement is closed"));
        }
        // In a transaction or connection, we always use the connection that
        // the stmt was created on.
        if let Some(cg) = &self.cg {
            let cgds = st.cgds.clone();
            drop(st);
            let (dc, release) = cg.grab_conn(ctx)?;
            return match cgds {
                Some(ds) => Ok((dc, release, ds)),
                None => {
                    release(None);
                    Err(Error::new("sql: statement is closed"))
                }
            };
        }
        self.remove_closed_stmt_locked(&mut st);
        drop(st);

        let dc = self.db.conn(ctx, strategy)?;

        // Prefer a statement already prepared on this connection.
        {
            let st = lock(&self.mu);
            if let Some(v) = st.css.iter().find(|v| Arc::ptr_eq(&v.dc, &dc)) {
                return Ok((dc.clone(), dc_release(&dc), v.ds.clone()));
            }
        }

        // No luck; we need to prepare the statement on this connection.
        let ds = {
            let mut g = lock(&dc.state);
            self.prepare_on_conn_locked(&mut g, ctx, &dc)
        };
        match ds {
            Ok(ds) => Ok((dc.clone(), dc_release(&dc), ds)),
            Err(e) => {
                dc.release_conn(Some(e.clone()));
                Err(e)
            }
        }
    }
}

impl FinalCloser for StmtInner {
    fn final_close(&self) -> Res<()> {
        let mut st = lock(&self.mu);
        for v in st.css.drain(..) {
            self.db.note_unused_driver_statement(&v.dc, &v.ds);
            v.dc.remove_open_stmt(v.ds.id);
        }
        Ok(())
    }
}

/// Go's `sql.Stmt`: a prepared statement, safe for use by several threads
/// through `&Stmt`. It is closed by [`Stmt::close`] or by dropping it.
pub struct Stmt {
    inner: Arc<StmtInner>,
}

impl Stmt {
    pub(crate) fn from_inner(inner: Arc<StmtInner>) -> Stmt {
        Stmt { inner }
    }

    pub(crate) fn sticky(db: &Arc<DbInner>, err: Error) -> Stmt {
        Stmt {
            inner: StmtInner::new(db, "", Some(err), None, None, None),
        }
    }

    pub(crate) fn inner(&self) -> &Arc<StmtInner> {
        &self.inner
    }

    /// Go's `ExecContext`: executes the prepared statement.
    pub fn exec_context(&self, ctx: &Context, args: &[Arg]) -> Res<Box<dyn SqlResult>> {
        self.exec_impl(Some(ctx), args)
    }

    /// Go's `Exec`.
    pub fn exec(&self, args: &[Arg]) -> Res<Box<dyn SqlResult>> {
        self.exec_impl(None, args)
    }

    fn exec_impl(&self, ctx: Ctx<'_>, args: &[Arg]) -> Res<Box<dyn SqlResult>> {
        let s = &self.inner;
        s.closemu.rlock();
        let _guard = ReadGuard(&s.closemu);
        s.db.retry(|strategy| {
            let (_dc, release, ds) = s.conn_stmt(ctx, strategy)?;
            let res = result_from_statement(ctx, &ds, args);
            release(res.as_ref().err().cloned());
            res
        })
    }

    /// Go's `QueryContext`: executes the prepared statement as a query.
    pub fn query_context(&self, ctx: &Context, args: &[Arg]) -> Res<Rows> {
        self.query_impl(Some(ctx), args)
    }

    /// Go's `Query`.
    pub fn query(&self, args: &[Arg]) -> Res<Rows> {
        self.query_impl(None, args)
    }

    fn query_impl(&self, ctx: Ctx<'_>, args: &[Arg]) -> Res<Rows> {
        let s = &self.inner;
        s.closemu.rlock();
        let _guard = ReadGuard(&s.closemu);
        s.db.retry(|strategy| {
            let (dc, release, ds) = s.conn_stmt(ctx, strategy)?;
            match rowsi_from_statement(ctx, &ds, args) {
                Ok(rowsi) => {
                    let rows_id = next_id();
                    s.db.add_dep(s.id, s.clone(), rows_id);
                    let db = s.db.clone();
                    let stmt_id = s.id;
                    let rel: ReleaseConn = Arc::new(move |err| {
                        release(err);
                        let _ = db.remove_dep(stmt_id, rows_id);
                    });
                    let rows = Rows::new(rows_id, dc, rel, rowsi, None);
                    let tx = s.cg.as_ref().and_then(|cg| cg.tx());
                    rows.init_context_close(ctx, tx.as_ref());
                    Ok(rows)
                }
                Err(e) => {
                    release(Some(e.clone()));
                    Err(e)
                }
            }
        })
    }

    /// Go's `QueryRowContext`: executes the statement expecting one row.
    pub fn query_row_context(&self, ctx: &Context, args: &[Arg]) -> Row {
        Row::from_result(self.query_context(ctx, args))
    }

    /// Go's `QueryRow`.
    pub fn query_row(&self, args: &[Arg]) -> Row {
        Row::from_result(self.query(args))
    }

    /// Go's `Close`: closes the statement.
    pub fn close(&self) -> Res<()> {
        self.inner.close()
    }
}

impl StmtInner {
    /// Closes the statement once operations in progress have finished.
    pub(crate) fn close(self: &Arc<Self>) -> Res<()> {
        self.closemu.lock();
        let result = self.close_locked();
        self.closemu.unlock();
        result
    }

    fn close_locked(self: &Arc<Self>) -> Res<()> {
        if let Some(e) = &self.sticky_err {
            return Err(e.clone());
        }
        let txds = {
            let mut st = lock(&self.mu);
            if st.closed {
                return Ok(());
            }
            st.closed = true;
            st.cgds.take()
        };
        if self.cg.is_none() {
            return self.db.remove_dep(self.id, self.id);
        }
        if let Some(parent) = &self.parent_stmt {
            // Statements derived from a parent are closed with the parent's
            // connection statement, not here.
            return self.db.remove_dep(parent.id, self.id);
        }
        match txds {
            Some(ds) => ds.close(),
            None => Ok(()),
        }
    }
}

impl Drop for Stmt {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

impl std::fmt::Debug for Stmt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stmt").finish_non_exhaustive()
    }
}
