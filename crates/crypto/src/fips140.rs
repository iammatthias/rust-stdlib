//! Go's `crypto/fips140`.
//!
//! Go's FIPS 140-3 mode switches the standard library to a validated
//! cryptographic module. The reviewed RustCrypto crates behind this crate are
//! not a validated module, so FIPS 140-3 mode cannot be enabled: [`enabled`]
//! and [`enforced`] are always false (even when `GODEBUG=fips140=on` or
//! `only` is set), [`version`] is Go's `"latest"` for a build without a frozen
//! module, and [`without_enforcement`] simply runs its function.

/// Go's `fips140.Enabled`: reports whether the module is in FIPS 140-3
/// mode. Always false here.
pub fn enabled() -> bool {
    false
}

/// Go's `fips140.Enforced`: reports whether the module is enforcing FIPS
/// 140-3 only mode (`GODEBUG=fips140=only`). Always false here.
pub fn enforced() -> bool {
    false
}

/// Go's `fips140.Version`: the version of the FIPS 140-3 module, `"latest"`
/// for a build against the current sources.
pub fn version() -> &'static str {
    "latest"
}

/// Go's `fips140.WithoutEnforcement`: runs `f` with FIPS 140-3 enforcement
/// disabled. Since enforcement is never on, it only calls `f`.
pub fn without_enforcement<F: FnOnce()>(f: F) {
    f();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        assert!(!enabled());
        assert!(!enforced());
        assert_eq!(version(), "latest");
        let mut ran = false;
        without_enforcement(|| ran = true);
        assert!(ran);
    }
}
