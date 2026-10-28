//! Context-aware wrappers around the driver interfaces (Go's `ctxutil.go`).
use super::driver::{self, Conn, NamedValue, Stmt, Value};
use super::error::{Error, Res};
use super::TxOptions;
use crate::context::Context;
use std::sync::OnceLock;

/// An optional context: `None` is `context.Background()`, which can never be
/// done, so no watcher is needed for it.
pub(crate) type Ctx<'a> = Option<&'a Context>;

pub(crate) fn background() -> &'static Context {
    static BACKGROUND: OnceLock<Context> = OnceLock::new();
    BACKGROUND.get_or_init(crate::context::Context::background)
}

pub(crate) fn cx<'a>(ctx: Ctx<'a>) -> &'a Context {
    match ctx {
        Some(c) => c,
        None => background(),
    }
}

/// `select { default: case <-ctx.Done(): return ctx.Err() }`.
pub(crate) fn check(ctx: Ctx<'_>) -> Res<()> {
    match ctx {
        Some(c) => c.check().map_err(Error::from),
        None => Ok(()),
    }
}

pub(crate) fn ctx_driver_prepare(
    ctx: Ctx<'_>,
    ci: &mut dyn Conn,
    query: &str,
) -> Res<Box<dyn Stmt>> {
    if let Some(c) = ci.as_conn_prepare_context() {
        return c.prepare_context(cx(ctx), query);
    }
    let mut si = ci.prepare(query)?;
    if let Err(e) = check(ctx) {
        let _ = si.close();
        return Err(e);
    }
    Ok(si)
}

fn named_value_to_value(named: &[NamedValue]) -> Res<Vec<Value>> {
    named
        .iter()
        .map(|p| {
            if p.name.is_empty() {
                Ok(p.value.clone())
            } else {
                Err(Error::new(
                    "sql: driver does not support the use of Named Parameters",
                ))
            }
        })
        .collect()
}

pub(crate) fn has_execer(ci: &mut dyn Conn) -> bool {
    ci.as_execer_context().is_some() || ci.as_execer().is_some()
}

pub(crate) fn has_queryer(ci: &mut dyn Conn) -> bool {
    ci.as_queryer_context().is_some() || ci.as_queryer().is_some()
}

pub(crate) fn ctx_driver_exec(
    ctx: Ctx<'_>,
    ci: &mut dyn Conn,
    query: &str,
    nvdargs: &[NamedValue],
) -> Res<Box<dyn driver::Result>> {
    if let Some(e) = ci.as_execer_context() {
        return e.exec_context(cx(ctx), query, nvdargs);
    }
    let dargs = named_value_to_value(nvdargs)?;
    check(ctx)?;
    match ci.as_execer() {
        Some(e) => e.exec(query, &dargs),
        None => Err(driver::ERR_SKIP),
    }
}

pub(crate) fn ctx_driver_query(
    ctx: Ctx<'_>,
    ci: &mut dyn Conn,
    query: &str,
    nvdargs: &[NamedValue],
) -> Res<Box<dyn driver::Rows>> {
    if let Some(q) = ci.as_queryer_context() {
        return q.query_context(cx(ctx), query, nvdargs);
    }
    let dargs = named_value_to_value(nvdargs)?;
    check(ctx)?;
    match ci.as_queryer() {
        Some(q) => q.query(query, &dargs),
        None => Err(driver::ERR_SKIP),
    }
}

pub(crate) fn ctx_driver_stmt_exec(
    ctx: Ctx<'_>,
    si: &mut dyn Stmt,
    nvdargs: &[NamedValue],
) -> Res<Box<dyn driver::Result>> {
    if let Some(s) = si.as_stmt_exec_context() {
        return s.exec_context(cx(ctx), nvdargs);
    }
    let dargs = named_value_to_value(nvdargs)?;
    check(ctx)?;
    si.exec(&dargs)
}

pub(crate) fn ctx_driver_stmt_query(
    ctx: Ctx<'_>,
    si: &mut dyn Stmt,
    nvdargs: &[NamedValue],
) -> Res<Box<dyn driver::Rows>> {
    if let Some(s) = si.as_stmt_query_context() {
        return s.query_context(cx(ctx), nvdargs);
    }
    let dargs = named_value_to_value(nvdargs)?;
    check(ctx)?;
    si.query(&dargs)
}

pub(crate) fn ctx_driver_begin(
    ctx: Ctx<'_>,
    opts: Option<&TxOptions>,
    ci: &mut dyn Conn,
) -> Res<Box<dyn driver::Tx>> {
    if let Some(c) = ci.as_conn_begin_tx() {
        let dopts = opts.map_or_else(driver::TxOptions::default, |o| driver::TxOptions {
            isolation: driver::IsolationLevel(o.isolation.0),
            read_only: o.read_only,
        });
        return c.begin_tx(cx(ctx), dopts);
    }
    if let Some(o) = opts {
        if o.isolation != super::LEVEL_DEFAULT {
            return Err(Error::new(
                "sql: driver does not support non-default isolation level",
            ));
        }
        if o.read_only {
            return Err(Error::new(
                "sql: driver does not support read-only transactions",
            ));
        }
    }
    let mut txi = ci.begin()?;
    if ctx.is_some() {
        if let Err(e) = check(ctx) {
            let _ = txi.rollback();
            return Err(e);
        }
    }
    Ok(txi)
}
