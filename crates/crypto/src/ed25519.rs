//! Ed25519 signatures, compatible with Go's `crypto/ed25519`.
//!
//! The curve arithmetic and hashing are the reviewed `ed25519-dalek` and
//! `sha2` crates; this module adds Go's key encodings, option handling and
//! error messages only.
//!
//! Two documented limits come from the dependency: RFC 8032's Ed25519ctx
//! (a context without prehashing, `Options { hash: None, context: non-empty }`)
//! is not exposed by `ed25519-dalek`, so signing and verifying with it return
//! an error; and a private key whose public half does not match its seed is
//! rejected instead of signing with the mismatched half as Go does.
//!
//! `ed25519-dalek` pulls the proc-macro crate `curve25519-dalek-derive` on
//! x86-64 (see docs/adr/0003-vendored-cryptography.md).

use std::any::Any;
use std::fmt;
use std::io;

use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::digest::array::Array;
use sha2::digest::typenum::U64;
use sha2::digest::{FixedOutput, HashMarker, OutputSizeUser, Update};

use crate::{BoxError, Hash, PublicKey as AnyPublicKey, Signer, SignerOpts};

/// Size of an Ed25519 public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 32;
/// Size of an Ed25519 private key (seed followed by public key) in bytes.
pub const PRIVATE_KEY_SIZE: usize = 64;
/// Size of an Ed25519 signature in bytes.
pub const SIGNATURE_SIZE: usize = 64;
/// Size of an Ed25519 seed in bytes.
pub const SEED_SIZE: usize = 32;

/// An error with one of Go's `crypto/ed25519` messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error(String);

impl Error {
    fn new(message: impl Into<String>) -> Error {
        Error(message.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// Go's `ed25519.PublicKey`: the 32-byte encoding of the public key point.
///
/// Like Go's slice type the length is not enforced on construction; the
/// functions that use the key report a bad length.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct PublicKey(pub Vec<u8>);

impl PublicKey {
    /// Go's `PublicKey.Equal`: compares with another key of this type.
    pub fn equal(&self, other: &dyn Any) -> bool {
        other
            .downcast_ref::<PublicKey>()
            .is_some_and(|other| crate::subtle::constant_time_compare(&self.0, &other.0) == 1)
    }

    /// The key as a PKIX (SubjectPublicKeyInfo) DER document, the encoding
    /// `x509.MarshalPKIXPublicKey` uses.
    pub fn to_pkix_der(&self) -> Result<Vec<u8>, Error> {
        let key = verifying_key(&self.0)?;
        key.to_public_key_der()
            .map(|document| document.as_bytes().to_vec())
            .map_err(|error| Error::new(format!("ed25519: {error}")))
    }

    /// Parses a PKIX DER public key, as `x509.ParsePKIXPublicKey` does.
    pub fn from_pkix_der(der: &[u8]) -> Result<PublicKey, Error> {
        VerifyingKey::from_public_key_der(der)
            .map(|key| PublicKey(key.to_bytes().to_vec()))
            .map_err(|error| Error::new(format!("ed25519: {error}")))
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Go's `ed25519.PrivateKey`: the 32-byte seed followed by the 32-byte
/// public key.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PrivateKey {
    bytes: Vec<u8>,
    public: PublicKey,
}

impl PrivateKey {
    /// Wraps the bytes of a private key without checking them, like the
    /// conversion `ed25519.PrivateKey(b)` in Go.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> PrivateKey {
        let bytes = bytes.into();
        let public = PublicKey(bytes.get(32..).unwrap_or_default().to_vec());
        PrivateKey { bytes, public }
    }

    /// The 64 bytes of the key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Go's `PrivateKey.Public`: a copy of the public half.
    pub fn public_key(&self) -> PublicKey {
        self.public.clone()
    }

    /// Go's `PrivateKey.Equal`: compares with another key of this type.
    pub fn equal(&self, other: &dyn Any) -> bool {
        other.downcast_ref::<PrivateKey>().is_some_and(|other| {
            crate::subtle::constant_time_compare(&self.bytes, &other.bytes) == 1
        })
    }

    /// Go's `PrivateKey.Seed`: a copy of the first 32 bytes.
    ///
    /// # Panics
    ///
    /// Panics if the key is shorter than 32 bytes, as Go's slice expression does.
    pub fn seed(&self) -> Vec<u8> {
        self.bytes[..SEED_SIZE].to_vec()
    }

    /// Go's `PrivateKey.Sign` with a message that has been hashed as `opts`
    /// says: Ed25519 (`opts.hash_func()` is `None`) or Ed25519ph (SHA-512).
    ///
    /// Go ignores the reader it is given (Ed25519 signing is deterministic),
    /// so there is no `rng` parameter.
    pub fn sign(&self, message: &[u8], opts: &dyn SignerOpts) -> Result<Vec<u8>, Error> {
        let key = signing_key(&self.bytes)?;
        let context = opts_context(opts);
        match opts.hash_func() {
            Some(Hash::Sha512) => {
                if message.len() != 64 {
                    return Err(Error::new(format!(
                        "ed25519: bad Ed25519ph message hash length: {}",
                        message.len()
                    )));
                }
                if context.len() > 255 {
                    return Err(Error::new(format!(
                        "ed25519: bad Ed25519ph context length: {}",
                        context.len()
                    )));
                }
                key.sign_prehashed(Precomputed::new(message), Some(context.as_bytes()))
                    .map(|signature| signature.to_bytes().to_vec())
                    .map_err(|error| Error::new(format!("ed25519: {error}")))
            }
            None if !context.is_empty() => Err(ctx_unsupported(context.len())),
            None => Ok(ed25519_dalek::Signer::sign(&key, message).to_bytes().to_vec()),
            Some(_) => Err(Error::new(
                "ed25519: expected opts.HashFunc() zero (unhashed message, for standard Ed25519) or SHA-512 (for Ed25519ph)",
            )),
        }
    }

    /// The key as a PKCS #8 DER document, the encoding
    /// `x509.MarshalPKCS8PrivateKey` uses.
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>, Error> {
        let key = signing_key(&self.bytes)?;
        key.to_pkcs8_der()
            .map(|document| document.as_bytes().to_vec())
            .map_err(|error| Error::new(format!("ed25519: {error}")))
    }

    /// Parses a PKCS #8 DER private key, as `x509.ParsePKCS8PrivateKey` does.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<PrivateKey, Error> {
        let key = SigningKey::from_pkcs8_der(der)
            .map_err(|error| Error::new(format!("ed25519: {error}")))?;
        Ok(PrivateKey::from_bytes(key.to_keypair_bytes().to_vec()))
    }
}

impl AsRef<[u8]> for PrivateKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Signer for PrivateKey {
    fn public(&self) -> &AnyPublicKey {
        &self.public
    }

    fn sign(&self, digest: &[u8], opts: &dyn SignerOpts) -> Result<Vec<u8>, BoxError> {
        PrivateKey::sign(self, digest, opts).map_err(Into::into)
    }

    /// Go ignores the reader, so this is [`Signer::sign`].
    fn sign_with_rng(
        &self,
        _rng: &mut dyn io::Read,
        digest: &[u8],
        opts: &dyn SignerOpts,
    ) -> Result<Vec<u8>, BoxError> {
        Signer::sign(self, digest, opts)
    }
}

/// Go's `ed25519.Options`: how a message was prepared for signing.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Options {
    /// `None` for pure Ed25519 (or Ed25519ctx with a context), or SHA-512
    /// for Ed25519ph.
    pub hash: Option<Hash>,
    /// The context string (empty for none).
    pub context: String,
}

impl SignerOpts for Options {
    /// Go's `Options.HashFunc`.
    fn hash_func(&self) -> Option<Hash> {
        self.hash
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}

/// The context carried by Go's `*ed25519.Options`, which a [`SignerOpts`]
/// trait object can expose only through downcasting.
fn opts_context(opts: &dyn SignerOpts) -> &str {
    opts.as_any()
        .and_then(|any| any.downcast_ref::<Options>())
        .map_or("", |options| options.context.as_str())
}

fn ctx_unsupported(length: usize) -> Error {
    if length > 255 {
        Error::new(format!("ed25519: bad Ed25519ctx context length: {length}"))
    } else {
        Error::new(
            "ed25519: Ed25519ctx is not supported (the reviewed ed25519-dalek crate does not expose it)",
        )
    }
}

fn signing_key(private_key: &[u8]) -> Result<SigningKey, Error> {
    if private_key.len() != PRIVATE_KEY_SIZE {
        return Err(Error::new(format!(
            "ed25519: bad private key length: {}",
            private_key.len()
        )));
    }
    let seed: [u8; SEED_SIZE] = private_key[..SEED_SIZE].try_into().expect("32 bytes");
    let key = SigningKey::from_bytes(&seed);
    if key.verifying_key().as_bytes()[..] != private_key[SEED_SIZE..] {
        return Err(Error::new(
            "ed25519: bad private key: public key does not match seed",
        ));
    }
    Ok(key)
}

fn verifying_key(public_key: &[u8]) -> Result<VerifyingKey, Error> {
    let bytes: [u8; PUBLIC_KEY_SIZE] = public_key.try_into().map_err(|_| {
        Error::new(format!(
            "ed25519: bad public key length: {}",
            public_key.len()
        ))
    })?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| Error::new("ed25519: bad public key"))
}

/// A 512-bit "hash" whose output is a value that has already been computed:
/// Go passes Ed25519ph the hash of the message, while `ed25519-dalek` wants
/// the hash state to finalize.
#[derive(Clone, Default)]
struct Precomputed(Array<u8, U64>);

impl Precomputed {
    fn new(hash: &[u8]) -> Precomputed {
        let mut value = Array::<u8, U64>::default();
        value.copy_from_slice(hash);
        Precomputed(value)
    }
}

impl HashMarker for Precomputed {}

impl OutputSizeUser for Precomputed {
    type OutputSize = U64;
}

impl Update for Precomputed {
    fn update(&mut self, _data: &[u8]) {}
}

impl FixedOutput for Precomputed {
    fn finalize_into(self, out: &mut sha2::digest::Output<Self>) {
        *out = self.0;
    }
}

/// Generates a public and private key pair from the system random source,
/// like `ed25519.GenerateKey(nil)`.
pub fn generate_key() -> Result<(PublicKey, PrivateKey), io::Error> {
    generate_key_with_rng(&mut crate::rand::Reader)
}

/// [`generate_key`] reading the 32-byte seed from `rng`, like
/// `ed25519.GenerateKey(rng)`; Go always honours the reader here.
pub fn generate_key_with_rng(rng: &mut dyn io::Read) -> Result<(PublicKey, PrivateKey), io::Error> {
    let mut seed = [0u8; SEED_SIZE];
    rng.read_exact(&mut seed)?;
    let private_key = PrivateKey::from_seed(&seed).expect("32-byte seed");
    Ok((private_key.public_key(), private_key))
}

impl PrivateKey {
    /// Calculates a private key from a seed, like `ed25519.NewKeyFromSeed`. Go
    /// panics when the seed is not 32 bytes; this is an error.
    pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        let seed: [u8; SEED_SIZE] = seed
            .try_into()
            .map_err(|_| Error::new(format!("ed25519: bad seed length: {}", seed.len())))?;
        let key = SigningKey::from_bytes(&seed);
        Ok(Self::from_bytes(key.to_keypair_bytes().to_vec()))
    }
}

/// Signs the message with the private key and returns the signature, like
/// `ed25519.Sign`. Go panics on a bad private key; this is an error.
pub fn sign(private_key: &PrivateKey, message: &[u8]) -> Result<Vec<u8>, Error> {
    let key = signing_key(&private_key.bytes)?;
    Ok(ed25519_dalek::Signer::sign(&key, message)
        .to_bytes()
        .to_vec())
}

/// Reports whether `sig` is a valid signature of `message` by `public_key`,
/// like `ed25519.Verify`. Go panics when the public key is not 32 bytes; this
/// is an error.
pub fn verify(public_key: &PublicKey, message: &[u8], sig: &[u8]) -> Result<bool, Error> {
    if public_key.0.len() != PUBLIC_KEY_SIZE {
        return Err(Error::new(format!(
            "ed25519: bad public key length: {}",
            public_key.0.len()
        )));
    }
    Ok(verify_with_options(public_key, message, sig, &Options::default()).is_ok())
}

/// Verifies a signature made as `opts` says, like `ed25519.VerifyWithOptions`.
pub fn verify_with_options(
    public_key: &PublicKey,
    message: &[u8],
    sig: &[u8],
    opts: &Options,
) -> Result<(), Error> {
    if public_key.0.len() != PUBLIC_KEY_SIZE {
        return Err(Error::new(format!(
            "ed25519: bad public key length: {}",
            public_key.0.len()
        )));
    }
    let key = verifying_key(&public_key.0)?;
    let signature_of = |sig: &[u8]| -> Result<Signature, Error> {
        if sig.len() != SIGNATURE_SIZE {
            return Err(Error::new(format!(
                "ed25519: bad signature length: {}",
                sig.len()
            )));
        }
        Signature::from_slice(sig).map_err(|_| Error::new("ed25519: invalid signature"))
    };
    let invalid = |_| Error::new("ed25519: invalid signature");
    match opts.hash {
        Some(Hash::Sha512) => {
            if message.len() != 64 {
                return Err(Error::new(format!(
                    "ed25519: bad Ed25519ph message hash length: {}",
                    message.len()
                )));
            }
            if opts.context.len() > 255 {
                return Err(Error::new(format!(
                    "ed25519: bad Ed25519ph context length: {}",
                    opts.context.len()
                )));
            }
            let signature = signature_of(sig)?;
            key.verify_prehashed(
                Precomputed::new(message),
                Some(opts.context.as_bytes()),
                &signature,
            )
            .map_err(invalid)
        }
        None if !opts.context.is_empty() => Err(ctx_unsupported(opts.context.len())),
        None => {
            let signature = signature_of(sig)?;
            ed25519_dalek::Verifier::verify(&key, message, &signature).map_err(invalid)
        }
        Some(_) => Err(Error::new(
            "ed25519: expected opts.Hash zero (unhashed message, for standard Ed25519) or SHA-512 (for Ed25519ph)",
        )),
    }
}
