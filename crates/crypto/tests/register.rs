//! crypto.RegisterHash mutates process-global state, so it has its own test binary.

use rust_stdlib_crypto::{register_hash, sha256, Hash};
use std::io::Write;

#[test]
fn register_hash_replaces_constructor() {
    // BLAKE2s-256 is unavailable until something registers it, like importing its package in Go.
    assert!(!Hash::Blake2s256.available());
    assert!(Hash::Blake2s256.new().is_err());
    register_hash(Hash::Blake2s256, || Box::new(sha256::new()));
    assert!(Hash::Blake2s256.available());
    let mut digest = Hash::Blake2s256.new().unwrap();
    digest.write_all(b"abc").unwrap();
    let mut out = Vec::new();
    digest.sum(&mut out);
    assert_eq!(out, sha256::sum256(b"abc"));

    // A registration also overrides an implemented hash.
    register_hash(Hash::Md5, || Box::new(sha256::new()));
    assert_eq!(Hash::Md5.new().unwrap().size(), 32);
}
