//! Go's `plugin` package: loading Go-built shared objects at run time.
//!
//! A Go plugin is a shared object built by the Go toolchain with
//! `-buildmode=plugin` and loaded into a Go runtime that shares its type and
//! symbol tables with the host program. A Rust program has neither, so this
//! module has the package's surface but no behaviour beyond what Go itself
//! does on a platform without plugin support (`plugin_stubs.go`): [`open`]
//! fails with "plugin: not implemented", so no [`Plugin`] ever exists to be
//! looked up. The mapping is recorded as the permanent deviation
//! `go-runtime-plugin` (ADR 0004).
//!
//! ```
//! let err = rust_stdlib::plugin::open("example.so").unwrap_err();
//! assert_eq!(err.to_string(), "plugin: not implemented");
//! ```
use std::any::Any;
use std::error::Error as StdError;
use std::fmt;

/// The error of this package: Go's `errors.New("plugin: not implemented")`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(&'static str);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl StdError for Error {}

const NOT_IMPLEMENTED: Error = Error("plugin: not implemented");

/// Go's `plugin.Plugin`: a loaded Go plugin. It cannot be constructed here.
#[derive(Debug)]
pub struct Plugin(());

/// Go's `plugin.Symbol`: a pointer to a variable or function in a plugin
/// (`any` in Go).
pub type Symbol = Box<dyn Any + Send + Sync>;

/// Go's `plugin.Open`: opens a Go plugin. Always fails with
/// "plugin: not implemented".
pub fn open(path: &str) -> Result<Plugin, Error> {
    let _ = path;
    Err(NOT_IMPLEMENTED)
}

impl Plugin {
    /// Go's `Plugin.Lookup`: searches for a symbol named `sym_name`. Always
    /// fails with "plugin: not implemented" (Go's stub panics instead; no
    /// `Plugin` exists to call it on).
    pub fn lookup(&self, sym_name: &str) -> Result<Symbol, Error> {
        let _ = sym_name;
        Err(NOT_IMPLEMENTED)
    }
}
