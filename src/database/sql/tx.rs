//! `Tx`: an in-progress transaction (Go's `sql.Tx`).
use super::closemu::ClosingMutex;
use super::ctxutil::{self, Ctx};
use super::db::{lock, DbInner, DriverConn, DriverStmt, FinalCloser, ReleaseConn};
use super::driver::{self, Arg};
use super::error::{Error, Res, ERR_BAD_CONN, ERR_TX_DONE};
use super::rows::{Row, Rows, RowsShared};
use super::stmt::{Stmt, StmtConnGrabber, StmtInner};
use super::{Result as SqlResult, TxOptions};
use crate::context::Context;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, Weak,
};

pub(crate) struct TxInner {
    db: Arc<DbInner>,
    /// Held for reading by every operation and for writing by commit and
    /// rollback, which wait for them.
    closemu: ClosingMutex,
    dc: Arc<DriverConn>,
    txi: Mutex<Box<dyn driver::Tx>>,
    release_conn: ReleaseConn,
    done: AtomicBool,
    /// Whether the connection survives a context-cancelled rollback.
    keep_conn_on_rollback: bool,
    /// Statements prepared in the transaction, closed when it ends.
    stmts: Mutex<Vec<Arc<StmtInner>>>,
    /// Cancelled when the transaction ends or the caller's context is done.
    ctx: Context,
    cancel_ctx: crate::context::CancelFunc,
    /// Rows of the transaction that must close when it ends.
    rows: Mutex<Vec<Weak<RowsShared>>>,
}

/// Go's `Tx.beginDC`: starts a transaction on a checked-out connection and
/// the thread that rolls it back when its context ends.
pub(crate) fn begin_dc(
    db: &Arc<DbInner>,
    ctx: Ctx<'_>,
    dc: &Arc<DriverConn>,
    release: ReleaseConn,
    opts: Option<&TxOptions>,
) -> Res<Tx> {
    let (txi, keep_conn_on_rollback) = {
        let mut g = lock(&dc.state);
        let ci = g.ci_mut();
        let keep = ci.as_session_resetter().is_some() && ci.as_validator().is_some();
        (ctxutil::ctx_driver_begin(ctx, opts, ci), keep)
    };
    let txi = match txi {
        Ok(t) => t,
        Err(e) => {
            release(Some(e.clone()));
            return Err(e);
        }
    };
    let (txctx, tx_cancel) = (ctx.unwrap_or_else(|| ctxutil::background())).with_cancel();
    let inner = Arc::new(TxInner {
        db: db.clone(),
        closemu: ClosingMutex::new(),
        dc: dc.clone(),
        txi: Mutex::new(txi),
        release_conn: release,
        done: AtomicBool::new(false),
        keep_conn_on_rollback,
        stmts: Mutex::new(Vec::new()),
        ctx: txctx,
        cancel_ctx: tx_cancel,
        rows: Mutex::new(Vec::new()),
    });
    let watcher = inner.clone();
    let spawned = std::thread::Builder::new()
        .name("sql-tx-await".into())
        .spawn(move || watcher.await_done());
    if spawned.is_err() {
        // Without the watcher the transaction can still be finished by hand.
    }
    Ok(Tx { inner })
}

impl TxInner {
    /// Rolls the transaction back when its context is done.
    fn await_done(&self) {
        self.ctx.done().wait();
        let err = self.ctx.err().unwrap_or(crate::context::Error::Canceled);
        self.close_registered_rows(Error::from(err));
        // Discard the connection if it cannot be reset after a rollback.
        let discard = !self.keep_conn_on_rollback;
        let _ = self.rollback(discard);
    }

    pub(crate) fn register_rows(&self, rows: &Arc<RowsShared>) {
        let already = {
            let mut v = lock(&self.rows);
            v.retain(|w| w.strong_count() > 0);
            v.push(Arc::downgrade(rows));
            self.ctx.check().err()
        };
        if let Some(e) = already {
            rows.set_context_done(e.into());
            let _ = rows.close(None);
        }
    }

    fn close_registered_rows(&self, err: Error) {
        let open: Vec<Arc<RowsShared>> = lock(&self.rows)
            .drain(..)
            .filter_map(|w| w.upgrade())
            .collect();
        for r in open {
            if !r.is_closed() {
                r.set_context_done(err.clone());
                let _ = r.close(None);
            }
        }
    }

    /// Go's `tx.cancel` and the rows watchers it wakes.
    fn cancel(&self) {
        (self.cancel_ctx)();
        let err = self
            .ctx
            .check()
            .err()
            .map_or_else(|| Error::new("sql: transaction ended"), Error::from);
        self.close_registered_rows(err);
    }

    fn is_done(&self) -> bool {
        self.done.load(Ordering::SeqCst)
    }

    fn grab(self: &Arc<Self>, ctx: Ctx<'_>) -> Res<(Arc<DriverConn>, ReleaseConn)> {
        ctxutil::check(ctx)?;
        self.closemu.rlock();
        if self.is_done() {
            self.closemu.runlock();
            return Err(ERR_TX_DONE);
        }
        let me = self.clone();
        Ok((self.dc.clone(), Arc::new(move |_| me.closemu.runlock())))
    }

    fn close(&self, err: Option<Error>) {
        (self.release_conn)(err);
    }

    fn close_prepared(&self) {
        let stmts = std::mem::take(&mut *lock(&self.stmts));
        for stmt in stmts {
            let _ = stmt.close();
        }
    }

    fn commit(&self) -> Res<()> {
        // Check context first to avoid transaction leak. If put it behind
        // the done flag, the transaction could be left open.
        if let Err(e) = self.ctx.check() {
            if self.is_done() {
                return Err(ERR_TX_DONE);
            }
            return Err(e.into());
        }
        if self
            .done
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(ERR_TX_DONE);
        }
        // Cancel the Tx to release any active R-closemu locks, which would
        // otherwise block the closemu write lock below.
        self.cancel();
        self.closemu.lock();
        self.closemu.unlock();
        let err = {
            let _g = lock(&self.dc.state);
            lock(&self.txi).commit().err()
        };
        if !err.as_ref().is_some_and(|e| e.is(&ERR_BAD_CONN)) {
            self.close_prepared();
        }
        self.close(err.clone());
        match err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn rollback(&self, discard_conn: bool) -> Res<()> {
        if self
            .done
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(ERR_TX_DONE);
        }
        self.cancel();
        self.closemu.lock();
        self.closemu.unlock();
        let mut err = {
            let _g = lock(&self.dc.state);
            lock(&self.txi).rollback().err()
        };
        if !err.as_ref().is_some_and(|e| e.is(&ERR_BAD_CONN)) {
            self.close_prepared();
        }
        if discard_conn {
            err = Some(ERR_BAD_CONN);
        }
        self.close(err.clone());
        match err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl StmtConnGrabber for Arc<TxInner> {
    fn grab_conn(&self, ctx: Ctx<'_>) -> Res<(Arc<DriverConn>, ReleaseConn)> {
        self.grab(ctx)
    }

    fn tx(&self) -> Option<Arc<TxInner>> {
        Some(self.clone())
    }
}

/// Go's `sql.Tx`: an in-progress database transaction. A transaction must end
/// with [`Tx::commit`] or [`Tx::rollback`]; dropping an unfinished one rolls
/// it back.
pub struct Tx {
    inner: Arc<TxInner>,
}

impl Tx {
    /// Go's `Commit`: commits the transaction.
    pub fn commit(&self) -> Res<()> {
        self.inner.commit()
    }

    /// Go's `Rollback`: aborts the transaction.
    pub fn rollback(&self) -> Res<()> {
        self.inner.rollback(false)
    }

    /// Go's `PrepareContext`: a prepared statement for use within the
    /// transaction. It is closed when the transaction ends.
    pub fn prepare_context(&self, ctx: &Context, query: &str) -> Res<Stmt> {
        self.prepare_impl(Some(ctx), query)
    }

    /// Go's `Prepare`.
    pub fn prepare(&self, query: &str) -> Res<Stmt> {
        self.prepare_impl(None, query)
    }

    fn prepare_impl(&self, ctx: Ctx<'_>, query: &str) -> Res<Stmt> {
        let tx = &self.inner;
        let (dc, release) = tx.grab(ctx)?;
        let cg: Arc<dyn StmtConnGrabber> = Arc::new(tx.clone());
        let stmt = tx.db.prepare_dc(ctx, &dc, &release, Some(cg), query)?;
        lock(&tx.stmts).push(stmt.inner().clone());
        Ok(stmt)
    }

    /// Go's `StmtContext`: a transaction-specific prepared statement from an
    /// existing statement.
    pub fn stmt_context(&self, ctx: &Context, stmt: &Stmt) -> Stmt {
        self.stmt_impl(Some(ctx), stmt)
    }

    /// Go's `Stmt`.
    pub fn stmt(&self, stmt: &Stmt) -> Stmt {
        self.stmt_impl(None, stmt)
    }

    fn stmt_impl(&self, ctx: Ctx<'_>, stmt: &Stmt) -> Stmt {
        let tx = &self.inner;
        let (dc, release) = match tx.grab(ctx) {
            Ok(x) => x,
            Err(e) => return Stmt::sticky(&tx.db, e),
        };
        let out = self.stmt_on_conn(ctx, stmt, &dc);
        release(None);
        out
    }

    fn stmt_on_conn(&self, ctx: Ctx<'_>, stmt: &Stmt, dc: &Arc<DriverConn>) -> Stmt {
        let tx = &self.inner;
        let orig = stmt.inner();
        if !Arc::ptr_eq(&tx.db, &orig.db) {
            return Stmt::sticky(
                &tx.db,
                Error::new("sql: Tx.Stmt: statement from different database used"),
            );
        }
        let mut parent: Option<Arc<StmtInner>> = None;
        let si;
        let mut st = lock(&orig.mu);
        if st.closed || orig.cg.is_some() {
            // The original statement is closed or bound elsewhere; prepare
            // the query again on this transaction's connection.
            drop(st);
            let r = {
                let mut g = lock(&dc.state);
                ctxutil::ctx_driver_prepare(ctx, g.ci_mut(), &orig.query)
            };
            match r {
                Ok(b) => si = Arc::new(Mutex::new(b)),
                Err(e) => return Stmt::sticky(&tx.db, e),
            }
        } else {
            orig.remove_closed_stmt_locked(&mut st);
            let found = st
                .css
                .iter()
                .find(|v| Arc::ptr_eq(&v.dc, dc))
                .map(|v| v.ds.si.clone());
            drop(st);
            si = match found {
                Some(s) => s,
                None => {
                    let ds = {
                        let mut g = lock(&dc.state);
                        orig.prepare_on_conn_locked(&mut g, ctx, dc)
                    };
                    match ds {
                        Ok(ds) => ds.si.clone(),
                        Err(e) => return Stmt::sticky(&tx.db, e),
                    }
                }
            };
            parent = Some(orig.clone());
        }
        let cg: Arc<dyn StmtConnGrabber> = Arc::new(tx.clone());
        let txs = StmtInner::new(
            &tx.db,
            &orig.query,
            None,
            Some(cg),
            parent.clone(),
            Some(DriverStmt::new(dc, si)),
        );
        if let Some(p) = &parent {
            tx.db
                .add_dep(p.id, p.clone() as Arc<dyn FinalCloser>, txs.id);
        }
        lock(&tx.stmts).push(txs.clone());
        Stmt::from_inner(txs)
    }

    /// Go's `ExecContext`: executes a query that doesn't return rows.
    pub fn exec_context(
        &self,
        ctx: &Context,
        query: &str,
        args: &[Arg],
    ) -> Res<Box<dyn SqlResult>> {
        self.exec_impl(Some(ctx), query, args)
    }

    /// Go's `Exec`.
    pub fn exec(&self, query: &str, args: &[Arg]) -> Res<Box<dyn SqlResult>> {
        self.exec_impl(None, query, args)
    }

    fn exec_impl(&self, ctx: Ctx<'_>, query: &str, args: &[Arg]) -> Res<Box<dyn SqlResult>> {
        let (dc, release) = self.inner.grab(ctx)?;
        self.inner.db.exec_dc(ctx, &dc, &release, query, args)
    }

    /// Go's `QueryContext`: executes a query that returns rows.
    pub fn query_context(&self, ctx: &Context, query: &str, args: &[Arg]) -> Res<Rows> {
        self.query_impl(Some(ctx), query, args)
    }

    /// Go's `Query`.
    pub fn query(&self, query: &str, args: &[Arg]) -> Res<Rows> {
        self.query_impl(None, query, args)
    }

    fn query_impl(&self, ctx: Ctx<'_>, query: &str, args: &[Arg]) -> Res<Rows> {
        let (dc, release) = self.inner.grab(ctx)?;
        self.inner
            .db
            .query_dc(ctx, Some(&self.inner), &dc, release, query, args)
    }

    /// Go's `QueryRowContext`: executes a query expected to return one row.
    pub fn query_row_context(&self, ctx: &Context, query: &str, args: &[Arg]) -> Row {
        Row::from_result(self.query_context(ctx, query, args))
    }

    /// Go's `QueryRow`.
    pub fn query_row(&self, query: &str, args: &[Arg]) -> Row {
        Row::from_result(self.query(query, args))
    }
}

impl Drop for Tx {
    fn drop(&mut self) {
        if !self.inner.is_done() {
            let _ = self.inner.rollback(false);
        }
    }
}

impl std::fmt::Debug for Tx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tx").finish_non_exhaustive()
    }
}
