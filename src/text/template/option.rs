//! Template options (Go `text/template` `option.go`).

use super::Template;

/// What to do when a map is indexed with a key it does not hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MissingKey {
    /// Return an invalid value (printed as `<no value>`).
    Invalid,
    /// Return the zero value for the map element.
    ZeroValue,
    /// Error out.
    Error,
}

/// Applies one option string; panics on an unrecognized one, as Go does.
pub(crate) fn set_option(t: &Template, opt: &str) {
    assert!(!opt.is_empty(), "empty option string");
    // key=value
    if let Some((key, value)) = opt.split_once('=') {
        if key == "missingkey" {
            match value {
                "invalid" | "default" => {
                    t.set_missing_key(MissingKey::Invalid);
                    return;
                }
                "zero" => {
                    t.set_missing_key(MissingKey::ZeroValue);
                    return;
                }
                "error" => {
                    t.set_missing_key(MissingKey::Error);
                    return;
                }
                _ => {}
            }
        }
    }
    panic!("unrecognized option: {opt}");
}
