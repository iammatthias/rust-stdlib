//! Go's `database/sql` and `database/sql/driver`.
//!
//! [`sql`] holds the database handle, connection pool, transactions,
//! statements, rows and Go's `Scan` conversion rules; [`sql::driver`] holds the
//! interfaces a database driver implements. No database driver is bundled:
//! Rust's standard library has none, so tests use an in-memory driver that
//! ports Go's `fakedb_test.go` command language.
//!
//! This module replaces the earlier first-party `Pool`/`Connection` subset,
//! which had no Go counterpart.
pub mod sql;
