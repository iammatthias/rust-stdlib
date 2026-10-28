//! Elliptic Curve Diffie-Hellman, compatible with Go's `crypto/ecdh`.
//!
//! P-256, P-384 and P-521 come from the reviewed RustCrypto `p256`, `p384`
//! and `p521` crates and X25519 from `x25519-dalek`; this module adds Go's
//! key encodings, validation order and error messages. Like Go 1.26 and later
//! (without `GODEBUG=cryptocustomrand=1`), [`Curve::generate_key`] ignores the
//! random reader it is given and draws from [`crate::rand`], which honours
//! `testing/cryptotest.SetGlobalRandom`'s replacement.

use std::any::Any;
use std::fmt;
use std::io;

use x25519_dalek::{PublicKey as XPublic, StaticSecret};

use crate::nistec::{self, Backend};
use crate::sysrng::Source;
use crate::PublicKey as AnyPublicKey;

/// An error with one of Go's `crypto/ecdh` messages.
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

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        Error(error.to_string())
    }
}

mod sealed {
    pub trait Sealed {}
}

/// Go's `ecdh.Curve`: a elliptic curve with an ECDH function. The only
/// values are [`fn@p256`], [`fn@p384`], [`fn@p521`] and [`x25519`].
pub trait Curve: sealed::Sealed + fmt::Display + Send + Sync {
    /// Generates a random [`PrivateKey`] with randomness from
    /// [`crate::rand`].
    fn generate_key(&self) -> Result<PrivateKey, Error> {
        self.generate_key_in(None)
    }

    /// [`Curve::generate_key`] with a caller's reader. As in Go 1.26+, the
    /// reader is ignored by default and randomness comes from
    /// [`crate::rand`] (the reader is used with `GODEBUG=cryptocustomrand=1`).
    fn generate_key_with_rng(&self, rng: &mut dyn io::Read) -> Result<PrivateKey, Error> {
        self.generate_key_in(Some(rng))
    }

    #[doc(hidden)]
    fn generate_key_in(&self, rand: Option<&mut dyn io::Read>) -> Result<PrivateKey, Error>;

    /// Checks that `key` is valid for the curve and returns a [`PrivateKey`].
    fn private_key_from_bytes(&self, key: &[u8]) -> Result<PrivateKey, Error>;

    /// Checks that `key` is valid for the curve and returns a [`PublicKey`].
    fn public_key_from_bytes(&self, key: &[u8]) -> Result<PublicKey, Error>;

    /// The curve name, `P-256`, `P-384`, `P-521` or `X25519`.
    fn name(&self) -> &'static str;

    #[doc(hidden)]
    fn nist(&self) -> Option<nistec::Id>;
}

struct NistCurve(nistec::Id, &'static str);

struct X25519Curve;

static P256: NistCurve = NistCurve(nistec::Id::P256, "P-256");
static P384: NistCurve = NistCurve(nistec::Id::P384, "P-384");
static P521: NistCurve = NistCurve(nistec::Id::P521, "P-521");
static X25519: X25519Curve = X25519Curve;

/// Go's `ecdh.P256`.
pub fn p256() -> &'static dyn Curve {
    &P256
}

/// Go's `ecdh.P384`.
pub fn p384() -> &'static dyn Curve {
    &P384
}

/// Go's `ecdh.P521`.
pub fn p521() -> &'static dyn Curve {
    &P521
}

/// Go's `ecdh.X25519`.
pub fn x25519() -> &'static dyn Curve {
    &X25519
}

impl sealed::Sealed for NistCurve {}
impl sealed::Sealed for X25519Curve {}

impl fmt::Display for NistCurve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.1)
    }
}

impl fmt::Display for X25519Curve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("X25519")
    }
}

impl NistCurve {
    fn backend(&self) -> &'static dyn Backend {
        nistec::backend(self.0)
    }
}

impl Curve for NistCurve {
    fn generate_key_in(&self, rand: Option<&mut dyn io::Read>) -> Result<PrivateKey, Error> {
        let backend = self.backend();
        let order = backend.order();
        let mut source = Source::custom(rand);
        loop {
            let mut key = vec![0u8; order.len()];
            source.fill(&mut key);
            // In tests the reader returns all zeros, which NewPrivateKey
            // rejects; this also matches elliptic.GenerateKey.
            key[1] ^= 0x42;
            // Mask off any excess bits if the size of the underlying field
            // is not a whole number of bytes, which is only the case for P-521.
            if self.0 == nistec::Id::P521 {
                key[0] &= 0b0000_0001;
            }
            if let Ok(private) = self.private_key_from_bytes(&key) {
                source.finish()?;
                return Ok(private);
            }
        }
    }

    fn private_key_from_bytes(&self, key: &[u8]) -> Result<PrivateKey, Error> {
        let backend = self.backend();
        if !backend.valid_scalar(key) {
            return Err(Error::new("crypto/ecdh: invalid private key"));
        }
        let public = backend
            .public_from_scalar(key)
            .ok_or_else(|| Error::new("crypto/ecdh: invalid private key"))?;
        Ok(PrivateKey {
            curve: self.as_curve(),
            private: key.to_vec(),
            public: PublicKey {
                curve: self.as_curve(),
                bytes: public,
            },
        })
    }

    fn public_key_from_bytes(&self, key: &[u8]) -> Result<PublicKey, Error> {
        if key.is_empty() || key[0] != 4 {
            return Err(Error::new("crypto/ecdh: invalid public key"));
        }
        let backend = self.backend();
        if backend.point(key).is_none() || key.len() != 1 + 2 * backend.len() {
            return Err(Error::new(format!(
                "invalid {} point encoding",
                self.1.replace('-', "")
            )));
        }
        Ok(PublicKey {
            curve: self.as_curve(),
            bytes: key.to_vec(),
        })
    }

    fn name(&self) -> &'static str {
        self.1
    }

    fn nist(&self) -> Option<nistec::Id> {
        Some(self.0)
    }
}

impl NistCurve {
    fn as_curve(&self) -> &'static dyn Curve {
        match self.0 {
            nistec::Id::P256 => &P256,
            nistec::Id::P384 => &P384,
            _ => &P521,
        }
    }
}

impl Curve for X25519Curve {
    fn generate_key_in(&self, rand: Option<&mut dyn io::Read>) -> Result<PrivateKey, Error> {
        let mut key = [0u8; 32];
        let mut source = Source::custom(rand);
        source.fill(&mut key);
        source.finish()?;
        self.private_key_from_bytes(&key)
    }

    fn private_key_from_bytes(&self, key: &[u8]) -> Result<PrivateKey, Error> {
        let bytes: [u8; 32] = key
            .try_into()
            .map_err(|_| Error::new("crypto/ecdh: invalid private key size"))?;
        let public = XPublic::from(&StaticSecret::from(bytes));
        Ok(PrivateKey {
            curve: &X25519,
            private: key.to_vec(),
            public: PublicKey {
                curve: &X25519,
                bytes: public.as_bytes().to_vec(),
            },
        })
    }

    fn public_key_from_bytes(&self, key: &[u8]) -> Result<PublicKey, Error> {
        if key.len() != 32 {
            return Err(Error::new("crypto/ecdh: invalid public key"));
        }
        Ok(PublicKey {
            curve: &X25519,
            bytes: key.to_vec(),
        })
    }

    fn name(&self) -> &'static str {
        "X25519"
    }

    fn nist(&self) -> Option<nistec::Id> {
        None
    }
}

fn same_curve(a: &dyn Curve, b: &dyn Curve) -> bool {
    a.name() == b.name()
}

/// Go's `ecdh.PublicKey`: an ECDH public key (an uncompressed SEC 1 point for
/// the NIST curves, the 32-byte u-coordinate for X25519).
#[derive(Clone)]
pub struct PublicKey {
    curve: &'static dyn Curve,
    bytes: Vec<u8>,
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("curve", &self.curve.name())
            .field("bytes", &self.bytes)
            .finish()
    }
}

impl PublicKey {
    /// Go's `PublicKey.Bytes`.
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Go's `PublicKey.Curve`.
    pub fn curve(&self) -> &'static dyn Curve {
        self.curve
    }

    /// Go's `PublicKey.Equal`.
    pub fn equal(&self, other: &dyn Any) -> bool {
        other.downcast_ref::<PublicKey>().is_some_and(|other| {
            same_curve(self.curve, other.curve)
                && crate::subtle::constant_time_compare(&self.bytes, &other.bytes) == 1
        })
    }

    /// The key as a PKIX (SubjectPublicKeyInfo) DER document, the encoding
    /// `x509.MarshalPKIXPublicKey` uses.
    pub fn to_pkix_der(&self) -> Result<Vec<u8>, Error> {
        match self.curve.nist() {
            Some(id) => nistec::backend(id).public_to_pkix(&self.bytes),
            None => crate::x25519_der::public_to_pkix(&self.bytes),
        }
        .ok_or_else(|| Error::new("crypto/ecdh: cannot encode public key"))
    }

    /// Parses a PKIX DER public key of P-256, P-384, P-521 or X25519, as
    /// `x509.ParsePKIXPublicKey` does for `*ecdh.PublicKey`.
    pub fn from_pkix_der(der: &[u8]) -> Result<PublicKey, Error> {
        for curve in [p256(), p384(), p521()] {
            let backend = nistec::backend(curve.nist().expect("NIST curve"));
            if let Some(point) = backend.public_from_pkix(der) {
                return Ok(PublicKey {
                    curve,
                    bytes: point,
                });
            }
        }
        match crate::x25519_der::public_from_pkix(der) {
            Some(bytes) => Ok(PublicKey {
                curve: x25519(),
                bytes,
            }),
            None => Err(Error::new("crypto/ecdh: invalid public key")),
        }
    }
}

/// Go's `ecdh.PrivateKey`.
#[derive(Clone)]
pub struct PrivateKey {
    curve: &'static dyn Curve,
    private: Vec<u8>,
    public: PublicKey,
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("curve", &self.curve.name())
            .finish_non_exhaustive()
    }
}

impl PrivateKey {
    /// Go's `PrivateKey.ECDH`: performs the ECDH exchange with `remote`.
    pub fn ecdh(&self, remote: &PublicKey) -> Result<Vec<u8>, Error> {
        if !same_curve(self.curve, remote.curve) {
            return Err(Error::new(
                "crypto/ecdh: private key and public key curves do not match",
            ));
        }
        match self.curve.nist() {
            Some(id) => {
                let backend = nistec::backend(id);
                backend.ecdh(&self.private, &remote.bytes).ok_or_else(|| {
                    Error::new(format!(
                        "invalid {} point encoding",
                        self.curve.name().replace('-', "")
                    ))
                })
            }
            None => {
                let secret: [u8; 32] = self.private.as_slice().try_into().expect("32 bytes");
                let peer: [u8; 32] = remote.bytes.as_slice().try_into().expect("32 bytes");
                let shared = StaticSecret::from(secret).diffie_hellman(&XPublic::from(peer));
                if !shared.was_contributory() {
                    return Err(Error::new(
                        "crypto/ecdh: bad X25519 remote ECDH input: low order point",
                    ));
                }
                Ok(shared.as_bytes().to_vec())
            }
        }
    }

    /// Go's `PrivateKey.Bytes`.
    pub fn bytes(&self) -> Vec<u8> {
        self.private.clone()
    }

    /// Go's `PrivateKey.Curve`.
    pub fn curve(&self) -> &'static dyn Curve {
        self.curve
    }

    /// Go's `PrivateKey.Equal`.
    pub fn equal(&self, other: &dyn Any) -> bool {
        other.downcast_ref::<PrivateKey>().is_some_and(|other| {
            same_curve(self.curve, other.curve)
                && crate::subtle::constant_time_compare(&self.private, &other.private) == 1
        })
    }

    /// Go's `PrivateKey.PublicKey`.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Go's `PrivateKey.Public`: the public key as `crypto.PublicKey`.
    pub fn public(&self) -> &AnyPublicKey {
        &self.public
    }

    /// The key as a PKCS #8 DER document, the encoding
    /// `x509.MarshalPKCS8PrivateKey` uses.
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>, Error> {
        match self.curve.nist() {
            Some(id) => nistec::backend(id).private_to_pkcs8(&self.private),
            None => crate::x25519_der::private_to_pkcs8(&self.private),
        }
        .ok_or_else(|| Error::new("crypto/ecdh: cannot encode private key"))
    }

    /// Parses a PKCS #8 DER private key of P-256, P-384, P-521 or X25519, as
    /// `x509.ParsePKCS8PrivateKey` does for `*ecdh.PrivateKey`.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<PrivateKey, Error> {
        for curve in [p256(), p384(), p521()] {
            let backend = nistec::backend(curve.nist().expect("NIST curve"));
            if let Some(scalar) = backend.private_from_pkcs8(der) {
                return curve.private_key_from_bytes(&scalar);
            }
        }
        match crate::x25519_der::private_from_pkcs8(der) {
            Some(key) => x25519().private_key_from_bytes(&key),
            None => Err(Error::new("crypto/ecdh: invalid private key")),
        }
    }
}

/// Go's `ecdh.KeyExchanger`: an ECDH private key, possibly held by hardware.
pub trait KeyExchanger {
    /// Go's `KeyExchanger.PublicKey`.
    fn public_key(&self) -> &PublicKey;
    /// Go's `KeyExchanger.Curve`.
    fn curve(&self) -> &'static dyn Curve;
    /// Go's `KeyExchanger.ECDH`.
    fn ecdh(&self, remote: &PublicKey) -> Result<Vec<u8>, Error>;
}

impl KeyExchanger for PrivateKey {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn curve(&self) -> &'static dyn Curve {
        self.curve
    }

    fn ecdh(&self, remote: &PublicKey) -> Result<Vec<u8>, Error> {
        PrivateKey::ecdh(self, remote)
    }
}
