//! Go's `database/sql`: a generic interface around SQL (or SQL-like) databases.
//!
//! [`DB::open`] returns a [`DB`], a pool of connections that is safe for use by
//! several threads. A [`DB`] is a cheap handle: clones share the pool. Like
//! Go, the pool keeps connections open until [`DB::close`]; unlike Go,
//! dropping a [`Rows`], [`Conn`], [`Stmt`] or [`Tx`] releases it (a dropped
//! [`Tx`] rolls back).
//!
//! The package follows Go's `database/sql` source: the same pool limits and
//! retry rules on [`driver::ERR_BAD_CONN`], the same statement re-preparation
//! on other connections, the same error texts, and the same `Scan`
//! conversions ([`convert_assign`]). Notable Rust differences:
//!
//! * Go's `any` arguments are [`driver::Arg`] and destinations are
//!   `&mut dyn` [`Scanner`]; `driver.Value` is the enum [`driver::Value`].
//! * `context.Context` is [`crate::context::Context`]; the methods without a
//!   `_context` suffix use `context.Background()`. A context cancels
//!   cooperatively: waiting for a free connection, a transaction and open
//!   rows all end when it is done, but a driver call in progress is not
//!   interrupted. Waiting on a context starts a helper thread only while the
//!   caller would block; rows started without a context have no watcher,
//!   while every [`Tx`] has one thread that rolls it back when its context ends.
//! * Optional driver interfaces are the `as_*` accessors on [`driver::Conn`],
//!   [`driver::Stmt`] and [`driver::Rows`].
//! * [`RawBytes`] copies instead of aliasing driver memory; Go strings that
//!   hold invalid UTF-8 scan into `String` with U+FFFD replacement; `uuid`
//!   destinations and driver-returned cursors (`driver.Rows` as a column
//!   value) are not supported.
//! * `Rows::scan(&mut [&mut dyn Scanner])`, `Row::scan`, `Rows::err`
//!   and similar return `Result`.
mod closemu;
mod conn;
mod convert;
mod ctxutil;
mod db;
pub mod driver;
mod error;
mod null;
mod rows;
mod stmt;
mod tx;

pub use conn::Conn;
pub use convert::{convert_assign, named, NamedArg, Out, RawBytes, Scanner};
pub use db::{drivers, register, DBStats, DB};
pub use driver::Arg;
pub use error::{Error, ERR_CONN_DONE, ERR_NO_ROWS, ERR_TX_DONE};
pub use null::{
    Null, NullBool, NullByte, NullFloat64, NullInt16, NullInt32, NullInt64, NullString, NullTime,
};
pub use rows::{ColumnType, CurrentRow, Row, Rows};
pub use stmt::Stmt;
pub use tx::Tx;

use std::fmt;

/// Go's `sql.Result`: the summary of an executed statement.
pub trait Result: Send + Sync {
    fn last_insert_id(&self) -> std::result::Result<i64, Error>;
    fn rows_affected(&self) -> std::result::Result<i64, Error>;
}

impl fmt::Debug for dyn Result + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("dyn sql::Result")
    }
}

/// Go's `sql.IsolationLevel`: the transaction isolation level in
/// [`TxOptions`]. Drivers may support only some levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IsolationLevel(pub i64);

pub const LEVEL_DEFAULT: IsolationLevel = IsolationLevel(0);
pub const LEVEL_READ_UNCOMMITTED: IsolationLevel = IsolationLevel(1);
pub const LEVEL_READ_COMMITTED: IsolationLevel = IsolationLevel(2);
pub const LEVEL_WRITE_COMMITTED: IsolationLevel = IsolationLevel(3);
pub const LEVEL_REPEATABLE_READ: IsolationLevel = IsolationLevel(4);
pub const LEVEL_SNAPSHOT: IsolationLevel = IsolationLevel(5);
pub const LEVEL_SERIALIZABLE: IsolationLevel = IsolationLevel(6);
pub const LEVEL_LINEARIZABLE: IsolationLevel = IsolationLevel(7);

impl fmt::Display for IsolationLevel {
    /// Go's `IsolationLevel.String`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => f.write_str("Default"),
            1 => f.write_str("Read Uncommitted"),
            2 => f.write_str("Read Committed"),
            3 => f.write_str("Write Committed"),
            4 => f.write_str("Repeatable Read"),
            5 => f.write_str("Snapshot"),
            6 => f.write_str("Serializable"),
            7 => f.write_str("Linearizable"),
            n => write!(f, "IsolationLevel({n})"),
        }
    }
}

/// Go's `sql.TxOptions`: the options passed to [`DB::begin_tx`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TxOptions {
    /// Zero means the driver's default isolation level.
    pub isolation: IsolationLevel,
    pub read_only: bool,
}
