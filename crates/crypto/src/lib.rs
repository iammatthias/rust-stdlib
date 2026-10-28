#![forbid(unsafe_code)]
//! Go's `crypto/*` packages with Go-shaped APIs over reviewed RustCrypto crates.
//!
//! No primitive is implemented in this repository (docs/adr/0003). Hash state
//! types implement [`std::io::Write`] for input and Go's `hash.Hash` surface
//! through [`hash::Hash`]. The module names follow the Go import paths.
//!
//! Each package is a Cargo feature of the same name, enabled by the default
//! `full` feature. A package's feature enables the packages its module uses,
//! so `default-features = false, features = ["sha256", "hmac"]` compiles only
//! those two and their dependencies (docs/adr/0003).

#[cfg(feature = "cipher")]
pub mod aes;
#[cfg(all(doc, feature = "full"))]
mod api_surface;
pub mod bigint;
#[cfg(feature = "cipher")]
pub mod cipher;
#[cfg(feature = "des")]
pub mod des;
#[cfg(feature = "dsa")]
pub mod dsa;
#[cfg(feature = "ecdh")]
pub mod ecdh;
#[cfg(feature = "ecdsa")]
pub mod ecdsa;
#[cfg(feature = "ed25519")]
pub mod ed25519;
#[cfg(feature = "elliptic")]
pub mod elliptic;
#[cfg(any(
    feature = "md5",
    feature = "sha1",
    feature = "sha256",
    feature = "sha512",
    feature = "sha3"
))]
mod engine;
pub mod fips140;
pub mod hash;
#[cfg(feature = "hkdf")]
pub mod hkdf;
#[cfg(feature = "hmac")]
pub mod hmac;
#[cfg(feature = "hpke")]
pub mod hpke;
#[cfg(feature = "md5")]
pub mod md5;
#[cfg(feature = "mldsa")]
pub mod mldsa;
#[cfg(feature = "mlkem")]
pub mod mlkem;
#[cfg(feature = "nistec")]
mod nistec;
#[cfg(feature = "pbkdf2")]
pub mod pbkdf2;
#[cfg(feature = "rand")]
pub mod rand;
#[cfg(feature = "rc4")]
pub mod rc4;
#[cfg(feature = "rsa")]
pub mod rsa;
#[cfg(feature = "sha1")]
pub mod sha1;
#[cfg(feature = "sha256")]
pub mod sha256;
#[cfg(feature = "sha3")]
pub mod sha3;
#[cfg(feature = "sha512")]
pub mod sha512;
#[cfg(feature = "subtle")]
pub mod subtle;
#[cfg(feature = "rand")]
mod sysrng;
#[cfg(feature = "ecdh")]
mod x25519_der;
#[cfg(feature = "x509")]
pub mod x509;

use std::any::Any;
use std::error::Error;
use std::fmt;
use std::io;
use std::sync::RwLock;

/// Go's `crypto.Hash`: an identifier for a cryptographic hash function.
///
/// Every Go constant exists. [`Hash::available`] is true only for the hash
/// functions this crate implements (MD5, SHA-1, SHA-2 and SHA-3) and whose
/// package feature is enabled (`md5`, `sha1`, `sha256`, `sha512`, `sha3`); the
/// others (MD4, RIPEMD-160, BLAKE2 and the sentinels) are unregistered,
/// exactly as in a Go program that does not import their packages.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Hash {
    /// MD4, `golang.org/x/crypto/md4` in Go; not implemented here.
    Md4 = 1,
    /// MD5 (`crypto/md5`).
    Md5,
    /// SHA-1 (`crypto/sha1`).
    Sha1,
    /// SHA-224 (`crypto/sha256`).
    Sha224,
    /// SHA-256 (`crypto/sha256`).
    Sha256,
    /// SHA-384 (`crypto/sha512`).
    Sha384,
    /// SHA-512 (`crypto/sha512`).
    Sha512,
    /// MD5+SHA1 as used by TLS RSA; Go has no implementation either.
    Md5Sha1,
    /// RIPEMD-160, `golang.org/x/crypto/ripemd160` in Go; not implemented here.
    Ripemd160,
    /// SHA3-224 (`crypto/sha3`).
    Sha3_224,
    /// SHA3-256 (`crypto/sha3`).
    Sha3_256,
    /// SHA3-384 (`crypto/sha3`).
    Sha3_384,
    /// SHA3-512 (`crypto/sha3`).
    Sha3_512,
    /// SHA-512/224 (`crypto/sha512`).
    Sha512_224,
    /// SHA-512/256 (`crypto/sha512`).
    Sha512_256,
    /// BLAKE2s-256; not implemented here.
    Blake2s256,
    /// BLAKE2b-256; not implemented here.
    Blake2b256,
    /// BLAKE2b-384; not implemented here.
    Blake2b384,
    /// BLAKE2b-512; not implemented here.
    Blake2b512,
    /// Sentinel for a pre-hashed ML-DSA mu message representative; it has no
    /// implementation in Go either.
    MlDsaMu,
}

impl Hash {
    /// Every constant in Go's declaration order, from `MD4` to the `MLDSAMu`
    /// sentinel.
    pub const ALL: [Hash; 20] = [
        Hash::Md4,
        Hash::Md5,
        Hash::Sha1,
        Hash::Sha224,
        Hash::Sha256,
        Hash::Sha384,
        Hash::Sha512,
        Hash::Md5Sha1,
        Hash::Ripemd160,
        Hash::Sha3_224,
        Hash::Sha3_256,
        Hash::Sha3_384,
        Hash::Sha3_512,
        Hash::Sha512_224,
        Hash::Sha512_256,
        Hash::Blake2s256,
        Hash::Blake2b256,
        Hash::Blake2b384,
        Hash::Blake2b512,
        Hash::MlDsaMu,
    ];
}

/// Constructor stored by [`register_hash`].
pub type HashFactory = fn() -> Box<dyn hash::Hash>;

static REGISTRY: RwLock<[Option<HashFactory>; 20]> = RwLock::new([None; 20]);

/// Error returned by [`Hash::new`] when the hash function is not registered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnavailableError(Hash);

impl UnavailableError {
    /// The hash function that was requested.
    pub const fn hash(self) -> Hash {
        self.0
    }
}

impl fmt::Display for UnavailableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "crypto: requested hash function #{} is unavailable",
            self.0 as u8
        )
    }
}

impl std::error::Error for UnavailableError {}

impl Hash {
    /// Returns a fresh hash computation, like `Hash.New`.
    ///
    /// Go panics when the hash function is unavailable; here that is an
    /// [`UnavailableError`].
    #[allow(clippy::new_ret_no_self)] // Go's Hash.New, a factory for the hash this identifies
    pub fn new(self) -> Result<Box<dyn hash::Hash>, UnavailableError> {
        if let Some(factory) = REGISTRY.read().unwrap_or_else(|e| e.into_inner())[self as usize - 1]
        {
            return Ok(factory());
        }
        match self {
            #[cfg(feature = "md5")]
            Hash::Md5 => Ok(Box::new(md5::new())),
            #[cfg(feature = "sha1")]
            Hash::Sha1 => Ok(Box::new(sha1::new())),
            #[cfg(feature = "sha256")]
            Hash::Sha224 => Ok(Box::new(sha256::new224())),
            #[cfg(feature = "sha256")]
            Hash::Sha256 => Ok(Box::new(sha256::new())),
            #[cfg(feature = "sha512")]
            Hash::Sha384 => Ok(Box::new(sha512::new384())),
            #[cfg(feature = "sha512")]
            Hash::Sha512 => Ok(Box::new(sha512::new())),
            #[cfg(feature = "sha512")]
            Hash::Sha512_224 => Ok(Box::new(sha512::new512_224())),
            #[cfg(feature = "sha512")]
            Hash::Sha512_256 => Ok(Box::new(sha512::new512_256())),
            #[cfg(feature = "sha3")]
            Hash::Sha3_224 => Ok(Box::new(sha3::new224())),
            #[cfg(feature = "sha3")]
            Hash::Sha3_256 => Ok(Box::new(sha3::new256())),
            #[cfg(feature = "sha3")]
            Hash::Sha3_384 => Ok(Box::new(sha3::new384())),
            #[cfg(feature = "sha3")]
            Hash::Sha3_512 => Ok(Box::new(sha3::new512())),
            _ => Err(UnavailableError(self)),
        }
    }

    /// Reports whether the hash function is implemented or registered.
    pub fn available(self) -> bool {
        self.new().is_ok()
    }

    /// Returns the digest length in bytes. Unlike [`Hash::available`], it does
    /// not require that the function is implemented. Go panics for values
    /// outside its constant range, which this enum cannot represent.
    pub const fn size(self) -> usize {
        match self {
            Hash::Md4 | Hash::Md5 => 16,
            Hash::Sha1 | Hash::Ripemd160 => 20,
            Hash::Sha224 | Hash::Sha512_224 | Hash::Sha3_224 => 28,
            Hash::Sha256
            | Hash::Sha512_256
            | Hash::Sha3_256
            | Hash::Blake2s256
            | Hash::Blake2b256 => 32,
            Hash::Md5Sha1 => 36,
            Hash::Sha384 | Hash::Sha3_384 | Hash::Blake2b384 => 48,
            Hash::Sha512 | Hash::Sha3_512 | Hash::Blake2b512 | Hash::MlDsaMu => 64,
        }
    }

    /// Returns the hash itself, so that `Hash` can serve as signer options.
    pub const fn hash_func(self) -> Hash {
        self
    }
}

impl fmt::Display for Hash {
    /// Go's `Hash.String`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Hash::Md4 => "MD4",
            Hash::Md5 => "MD5",
            Hash::Sha1 => "SHA-1",
            Hash::Sha224 => "SHA-224",
            Hash::Sha256 => "SHA-256",
            Hash::Sha384 => "SHA-384",
            Hash::Sha512 => "SHA-512",
            Hash::Md5Sha1 => "MD5+SHA1",
            Hash::Ripemd160 => "RIPEMD-160",
            Hash::Sha3_224 => "SHA3-224",
            Hash::Sha3_256 => "SHA3-256",
            Hash::Sha3_384 => "SHA3-384",
            Hash::Sha3_512 => "SHA3-512",
            Hash::Sha512_224 => "SHA-512/224",
            Hash::Sha512_256 => "SHA-512/256",
            Hash::Blake2s256 => "BLAKE2s-256",
            Hash::Blake2b256 => "BLAKE2b-256",
            Hash::Blake2b384 => "BLAKE2b-384",
            Hash::Blake2b512 => "BLAKE2b-512",
            Hash::MlDsaMu => "ML-DSA \u{3bc} message representative",
        })
    }
}

/// Registers a constructor for a hash function, like `crypto.RegisterHash`.
///
/// The functions this crate implements are registered from the start; a later
/// registration replaces the constructor used by [`Hash::new`].
pub fn register_hash(hash: Hash, factory: HashFactory) {
    REGISTRY.write().unwrap_or_else(|e| e.into_inner())[hash as usize - 1] = Some(factory);
}

/// Go's `crypto.PublicKey`: a public key of an unspecified algorithm.
///
/// Go's type is the empty interface; use `Any` to recover the concrete key.
pub type PublicKey = dyn Any;

/// Go's `crypto.PrivateKey`: a private key of an unspecified algorithm.
///
/// Go's type is the empty interface; use `Any` to recover the concrete key.
pub type PrivateKey = dyn Any;

/// Go's `crypto.DecrypterOpts`: options for decryption, of an unspecified type.
pub type DecrypterOpts = dyn Any;

/// The error type of the signing, decryption and decapsulation interfaces.
pub type BoxError = Box<dyn Error + Send + Sync>;

/// Go's `crypto.SignerOpts`: options for signing with a [`Signer`].
pub trait SignerOpts {
    /// Returns the hash function that produced the digest passed to
    /// [`Signer::sign`], or [`None`] if the message was not hashed (Go's zero
    /// `crypto.Hash`).
    fn hash_func(&self) -> Option<Hash>;

    /// Go's `opts.(*Options)` type assertion, which a trait object cannot
    /// express: options with algorithm-specific fields (an Ed25519 context,
    /// an RSA salt length) return themselves here so that the algorithm's
    /// signer can read them.
    fn as_any(&self) -> Option<&dyn Any> {
        None
    }
}

impl SignerOpts for Hash {
    /// A [`enum@Hash`] is its own signer options, as in Go.
    fn hash_func(&self) -> Option<Hash> {
        Some(*self)
    }
}

/// Go's `crypto.Signer`: an opaque private key that can sign.
pub trait Signer {
    /// Returns the public key corresponding to the private key.
    fn public(&self) -> &PublicKey;

    /// Signs `digest`, which was hashed as `opts` says, with no caller
    /// supplied random source: Go's `Sign(nil, digest, opts)`. Algorithms that
    /// need randomness use the system source; ECDSA signs deterministically
    /// (RFC 6979).
    fn sign(&self, digest: &[u8], opts: &dyn SignerOpts) -> Result<Vec<u8>, BoxError>;

    /// [`Signer::sign`] reading randomness from `rng`, Go's
    /// `Sign(rng, digest, opts)`. Algorithms decide whether they honour the
    /// reader, as in Go.
    fn sign_with_rng(
        &self,
        rng: &mut dyn io::Read,
        digest: &[u8],
        opts: &dyn SignerOpts,
    ) -> Result<Vec<u8>, BoxError>;

    /// Go's `signer.(MessageSigner)` interface upgrade, which a trait object
    /// cannot express: a signer that is also a [`MessageSigner`] returns
    /// itself here so that [`sign_message`] can use it.
    fn as_message_signer(&self) -> Option<&dyn MessageSigner> {
        None
    }
}

/// Go's `crypto.MessageSigner`: a [`Signer`] that signs whole messages.
pub trait MessageSigner: Signer {
    /// Signs `msg`, hashing it as `opts` says if the algorithm requires, with
    /// no caller supplied random source (Go's nil reader).
    fn sign_message(&self, msg: &[u8], opts: &dyn SignerOpts) -> Result<Vec<u8>, BoxError>;

    /// [`MessageSigner::sign_message`] reading randomness from `rng`.
    fn sign_message_with_rng(
        &self,
        rng: &mut dyn io::Read,
        msg: &[u8],
        opts: &dyn SignerOpts,
    ) -> Result<Vec<u8>, BoxError>;
}

/// Go's `crypto.Decrypter`: an opaque private key that can decrypt.
pub trait Decrypter {
    /// Returns the public key corresponding to the private key.
    fn public(&self) -> &PublicKey;

    /// Decrypts `msg`, using `opts` (of a type the algorithm defines) if
    /// given, with no caller supplied random source (Go's nil reader).
    fn decrypt(&self, msg: &[u8], opts: Option<&DecrypterOpts>) -> Result<Vec<u8>, BoxError>;

    /// [`Decrypter::decrypt`] reading randomness (for blinding) from `rng`.
    fn decrypt_with_rng(
        &self,
        rng: &mut dyn io::Read,
        msg: &[u8],
        opts: Option<&DecrypterOpts>,
    ) -> Result<Vec<u8>, BoxError>;
}

/// Go's `crypto.Encapsulator`: a public key-encapsulation key.
pub trait Encapsulator {
    /// Returns the encoding of the public key.
    fn bytes(&self) -> Vec<u8>;

    /// Returns a fresh shared key and the ciphertext that encapsulates it, in
    /// that order.
    fn encapsulate(&self) -> (Vec<u8>, Vec<u8>);
}

/// Go's `crypto.Decapsulator`: an opaque private key-encapsulation key.
pub trait Decapsulator {
    /// Returns the public key corresponding to the private key.
    fn encapsulator(&self) -> Box<dyn Encapsulator>;

    /// Recovers the shared key from `ciphertext`.
    fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, BoxError>;
}

/// Error returned by [`sign_message`] when `opts` names a hash function that
/// is not available.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HashUnavailableError(Hash);

impl HashUnavailableError {
    /// The hash function that was requested.
    pub const fn hash(self) -> Hash {
        self.0
    }
}

impl fmt::Display for HashUnavailableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "crypto: requested hash function unavailable: {}", self.0)
    }
}

impl Error for HashUnavailableError {}

/// Signs `msg` with `signer`, like `crypto.SignMessage(signer, nil, msg,
/// opts)`. If the signer implements [`MessageSigner`] (through
/// [`Signer::as_message_signer`]), [`MessageSigner::sign_message`] is called
/// directly. Otherwise `msg` is hashed with `opts.hash_func()`, when there is
/// one, and signed with [`Signer::sign`].
pub fn sign_message(
    signer: &dyn Signer,
    msg: &[u8],
    opts: &dyn SignerOpts,
) -> Result<Vec<u8>, BoxError> {
    sign_message_in(signer, None, msg, opts)
}

/// [`sign_message`] reading randomness from `rng`, like Go's
/// `crypto.SignMessage(signer, rng, msg, opts)`.
pub fn sign_message_with_rng(
    signer: &dyn Signer,
    rng: &mut dyn io::Read,
    msg: &[u8],
    opts: &dyn SignerOpts,
) -> Result<Vec<u8>, BoxError> {
    sign_message_in(signer, Some(rng), msg, opts)
}

pub(crate) fn sign_message_in(
    signer: &dyn Signer,
    rand: Option<&mut dyn io::Read>,
    msg: &[u8],
    opts: &dyn SignerOpts,
) -> Result<Vec<u8>, BoxError> {
    if let Some(message_signer) = signer.as_message_signer() {
        return match rand {
            Some(rng) => message_signer.sign_message_with_rng(rng, msg, opts),
            None => message_signer.sign_message(msg, opts),
        };
    }
    match opts.hash_func() {
        Some(hash) => {
            let mut digest = hash.new().map_err(|_| HashUnavailableError(hash))?;
            io::Write::write_all(&mut digest, msg)?;
            let mut sum = Vec::with_capacity(digest.size());
            digest.sum(&mut sum);
            sign_digest(signer, rand, &sum, opts)
        }
        None => sign_digest(signer, rand, msg, opts),
    }
}

fn sign_digest(
    signer: &dyn Signer,
    rand: Option<&mut dyn io::Read>,
    digest: &[u8],
    opts: &dyn SignerOpts,
) -> Result<Vec<u8>, BoxError> {
    match rand {
        Some(rng) => signer.sign_with_rng(rng, digest, opts),
        None => signer.sign(digest, opts),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_constant_is_listed_in_order() {
        for (index, hash) in Hash::ALL.iter().enumerate() {
            assert_eq!(*hash as usize, index + 1);
        }
    }
}
