//! `plugin` is the permanent deviation `go-runtime-plugin`: the package's
//! surface exists, and opening fails as Go's stub does.
use rust_stdlib::plugin::{open, Plugin, Symbol};

#[test]
fn open_reports_not_implemented() {
    let err = open("/no/such/plugin.so").unwrap_err();
    assert_eq!(err.to_string(), "plugin: not implemented");
    assert_eq!(err, open("").unwrap_err());
}

#[test]
fn surface_compiles() {
    fn takes(_: Option<Plugin>, _: Option<Symbol>) {}
    takes(None, None);
}
