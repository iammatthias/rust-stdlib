//! `Conn`: a single connection checked out of the pool (Go's `sql.Conn`).
use super::closemu::ClosingMutex;
use super::ctxutil::Ctx;
use super::db::{lock, DbInner, DriverConn, ReleaseConn};
use super::driver::{self, Arg};
use super::error::{Error, Res, ERR_BAD_CONN, ERR_CONN_DONE};
use super::rows::{Row, Rows};
use super::stmt::{Stmt, StmtConnGrabber};
use super::tx::{self, Tx, TxInner};
use super::{Result as SqlResult, TxOptions};
use crate::context::Context;
use std::{
    panic::{catch_unwind, resume_unwind, AssertUnwindSafe},
    sync::{atomic::AtomicBool, atomic::Ordering, Arc},
};

pub(crate) struct ConnInner {
    db: Arc<DbInner>,
    /// Held for reading by every operation in progress and for writing by
    /// `close`, which waits for them.
    closemu: ClosingMutex,
    dc: Arc<DriverConn>,
    done: AtomicBool,
}

impl ConnInner {
    pub(crate) fn new(db: &Arc<DbInner>, dc: Arc<DriverConn>) -> Arc<ConnInner> {
        Arc::new(ConnInner {
            db: db.clone(),
            closemu: ClosingMutex::new(),
            dc,
            done: AtomicBool::new(false),
        })
    }

    fn grab(self: &Arc<Self>) -> Res<(Arc<DriverConn>, ReleaseConn)> {
        if self.done.load(Ordering::SeqCst) {
            return Err(ERR_CONN_DONE);
        }
        self.closemu.rlock();
        let me = self.clone();
        Ok((
            self.dc.clone(),
            Arc::new(move |err| me.closemu_runlock_cond_release_conn(err)),
        ))
    }

    fn closemu_runlock_cond_release_conn(self: &Arc<Self>, err: Option<Error>) {
        self.closemu.runlock();
        if err.as_ref().is_some_and(|e| e.is(&ERR_BAD_CONN)) {
            let _ = self.close(err);
        }
    }

    fn close(&self, err: Option<Error>) -> Res<()> {
        if self
            .done
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(ERR_CONN_DONE);
        }
        self.closemu.lock();
        self.dc.release_conn(err.clone());
        self.closemu.unlock();
        match err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl StmtConnGrabber for Arc<ConnInner> {
    fn grab_conn(&self, _ctx: Ctx<'_>) -> Res<(Arc<DriverConn>, ReleaseConn)> {
        self.grab()
    }

    fn tx(&self) -> Option<Arc<TxInner>> {
        None
    }
}

/// Go's `sql.Conn`: a single connection to the database, returned by
/// [`super::DB::conn`]. Close it (or drop it) to return it to the pool.
pub struct Conn {
    inner: Arc<ConnInner>,
}

impl Conn {
    pub(crate) fn from_inner(inner: Arc<ConnInner>) -> Conn {
        Conn { inner }
    }

    /// Go's `PingContext`: verifies the connection to the database is still
    /// alive.
    pub fn ping_context(&self, ctx: &Context) -> Res<()> {
        let (dc, release) = self.inner.grab()?;
        let err = {
            let mut g = lock(&dc.state);
            g.ci_mut().as_pinger().and_then(|p| p.ping(ctx).err())
        };
        release(err.clone());
        match err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Go's `ExecContext`: executes a query without returning rows.
    pub fn exec_context(
        &self,
        ctx: &Context,
        query: &str,
        args: &[Arg],
    ) -> Res<Box<dyn SqlResult>> {
        let (dc, release) = self.inner.grab()?;
        self.inner.db.exec_dc(Some(ctx), &dc, &release, query, args)
    }

    /// Go's `QueryContext`: executes a query that returns rows.
    pub fn query_context(&self, ctx: &Context, query: &str, args: &[Arg]) -> Res<Rows> {
        let (dc, release) = self.inner.grab()?;
        self.inner
            .db
            .query_dc(Some(ctx), None, &dc, release, query, args)
    }

    /// Go's `QueryRowContext`: executes a query expected to return at most
    /// one row.
    pub fn query_row_context(&self, ctx: &Context, query: &str, args: &[Arg]) -> Row {
        Row::from_result(self.query_context(ctx, query, args))
    }

    /// Go's `PrepareContext`: a prepared statement bound to this connection.
    pub fn prepare_context(&self, ctx: &Context, query: &str) -> Res<Stmt> {
        let (dc, release) = self.inner.grab()?;
        let cg: Arc<dyn StmtConnGrabber> = Arc::new(self.inner.clone());
        self.inner
            .db
            .prepare_dc(Some(ctx), &dc, &release, Some(cg), query)
    }

    /// Go's `Raw`: runs `f` with the underlying driver connection. The
    /// connection must not be used after `f` returns. If `f` panics the
    /// connection is discarded.
    pub fn raw(&self, f: impl FnOnce(&mut dyn driver::Conn) -> Res<()>) -> Res<()> {
        let (dc, release) = self.inner.grab()?;
        let mut g = lock(&dc.state);
        let r = catch_unwind(AssertUnwindSafe(|| f(g.ci_mut())));
        drop(g);
        match r {
            Ok(res) => {
                release(res.as_ref().err().cloned());
                res
            }
            Err(panic) => {
                release(Some(ERR_BAD_CONN));
                resume_unwind(panic)
            }
        }
    }

    /// Go's `BeginTx`: starts a transaction on this connection.
    pub fn begin_tx(&self, ctx: &Context, opts: Option<TxOptions>) -> Res<Tx> {
        let (dc, release) = self.inner.grab()?;
        tx::begin_dc(&self.inner.db, Some(ctx), &dc, release, opts.as_ref())
    }

    /// Go's `Close`: returns the connection to the pool. Operations in
    /// progress finish first. A second close returns [`ERR_CONN_DONE`].
    pub fn close(&self) -> Res<()> {
        self.inner.close(None)
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        if self.inner.done.load(Ordering::SeqCst) {
            return;
        }
        if self.inner.closemu.is_busy() {
            // Open rows or a statement call still hold the connection; wait
            // for them on another thread rather than blocking the dropper.
            let inner = self.inner.clone();
            let spawned = std::thread::Builder::new()
                .name("sql-conn-close".into())
                .spawn(move || {
                    let _ = inner.close(None);
                });
            if spawned.is_ok() {
                return;
            }
        }
        let _ = self.inner.close(None);
    }
}

impl std::fmt::Debug for Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conn").finish_non_exhaustive()
    }
}
