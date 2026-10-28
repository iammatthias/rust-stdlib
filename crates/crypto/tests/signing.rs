//! crypto.Signer, MessageSigner, SignerOpts and SignMessage, from Go's
//! crypto.go: SignMessage hashes with the options' hash unless the signer can
//! sign whole messages.

use rust_stdlib_crypto::{
    sha256, sign_message, BoxError, Hash, MessageSigner, PublicKey, Signer, SignerOpts,
};
use std::io::Read;
use std::sync::Mutex;

/// Records what `Sign` receives and returns it as the "signature".
struct Recording {
    seen: Mutex<Vec<Vec<u8>>>,
    public: u8,
}

impl Recording {
    fn new(public: u8) -> Self {
        Recording {
            seen: Mutex::new(Vec::new()),
            public,
        }
    }
}

impl Signer for Recording {
    fn public(&self) -> &PublicKey {
        &self.public
    }

    fn sign(&self, digest: &[u8], _opts: &dyn SignerOpts) -> Result<Vec<u8>, BoxError> {
        self.seen.lock().unwrap().push(digest.to_vec());
        Ok(digest.to_vec())
    }

    fn sign_with_rng(
        &self,
        _rng: &mut dyn Read,
        digest: &[u8],
        opts: &dyn SignerOpts,
    ) -> Result<Vec<u8>, BoxError> {
        self.sign(digest, opts)
    }
}

/// A signer that also signs whole messages, found through the upgrade hook.
struct Upgrading(Recording);

impl Signer for Upgrading {
    fn public(&self) -> &PublicKey {
        self.0.public()
    }

    fn sign(&self, digest: &[u8], opts: &dyn SignerOpts) -> Result<Vec<u8>, BoxError> {
        self.0.sign(digest, opts)
    }

    fn sign_with_rng(
        &self,
        rng: &mut dyn Read,
        digest: &[u8],
        opts: &dyn SignerOpts,
    ) -> Result<Vec<u8>, BoxError> {
        self.0.sign_with_rng(rng, digest, opts)
    }

    fn as_message_signer(&self) -> Option<&dyn MessageSigner> {
        Some(self)
    }
}

impl MessageSigner for Upgrading {
    fn sign_message(&self, msg: &[u8], _opts: &dyn SignerOpts) -> Result<Vec<u8>, BoxError> {
        Ok([b"message:".as_slice(), msg].concat())
    }

    fn sign_message_with_rng(
        &self,
        _rng: &mut dyn Read,
        msg: &[u8],
        opts: &dyn SignerOpts,
    ) -> Result<Vec<u8>, BoxError> {
        self.sign_message(msg, opts)
    }
}

/// Options that say the message is not hashed (Go's zero Hash).
struct Unhashed;

impl SignerOpts for Unhashed {
    fn hash_func(&self) -> Option<Hash> {
        None
    }
}

#[test]
fn sign_message_hashes_with_the_options_hash() {
    let signer = Recording::new(7);
    let signature = sign_message(&signer, b"hello", &Hash::Sha256).unwrap();
    assert_eq!(signature, sha256::sum256(b"hello"));
    assert_eq!(signer.seen.lock().unwrap().len(), 1);
    assert_eq!(signer.public().downcast_ref::<u8>(), Some(&7));

    // Without a hash the message is signed as it is.
    let signature = sign_message(&signer, b"hello", &Unhashed).unwrap();
    assert_eq!(signature, b"hello");
}

#[test]
fn sign_message_prefers_a_message_signer() {
    let signer = Upgrading(Recording::new(1));
    let signature = sign_message(&signer, b"hello", &Hash::Sha256).unwrap();
    assert_eq!(signature, b"message:hello");
    assert!(signer.0.seen.lock().unwrap().is_empty());
}

#[test]
fn sign_message_reports_unavailable_hashes() {
    let signer = Recording::new(0);
    let error = sign_message(&signer, b"hello", &Hash::Md4).unwrap_err();
    assert_eq!(
        error.to_string(),
        "crypto: requested hash function unavailable: MD4"
    );
    assert!(signer.seen.lock().unwrap().is_empty());
}
