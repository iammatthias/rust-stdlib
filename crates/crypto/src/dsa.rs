//! The Digital Signature Algorithm, compatible with Go's `crypto/dsa`
//! (deprecated in Go).
//!
//! Parameter generation, key generation, signing and verification come from
//! the reviewed RustCrypto `dsa` crate. Differences from Go:
//!
//! * The crate accepts the FIPS 186-3 parameter sizes only (L/N of 1024/160,
//!   2048/224, 2048/256 and 3072/256); other sizes return an error.
//! * Like the crate (and FIPS 186-3 section 4.6) signing and verifying use the
//!   leftmost `N/8` bytes of a longer hash; Go leaves that truncation to the
//!   caller and reduces a longer hash modulo `Q`.
//! * Signing uses the crate's random nonce, drawn from [`crate::rand`] (the
//!   reader is ignored unless `GODEBUG=cryptocustomrand=1`, like Go 1.26+).

use std::any::Any;
use std::fmt;
use std::io;

use dsa::pkcs8::spki::{DecodePublicKey, EncodePublicKey};
use dsa::signature::hazmat::{PrehashVerifier, RandomizedPrehashSigner};
use dsa::{BoxedUint, Components, KeySize, Signature, SigningKey, VerifyingKey};

use crate::bigint::Int;
use crate::sysrng::Source;

/// Go's `dsa.ErrInvalidPublicKey`: `crypto/dsa: invalid public key`.
pub const ERR_INVALID_PUBLIC_KEY: &str = "crypto/dsa: invalid public key";

/// An error with one of Go's `crypto/dsa` messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error(String);

impl Error {
    fn new(message: impl Into<String>) -> Error {
        Error(message.into())
    }

    /// Go's `ErrInvalidPublicKey`.
    pub fn invalid_public_key() -> Error {
        Error::new(ERR_INVALID_PUBLIC_KEY)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// Go's `dsa.ParameterSizes`: the sizes of `L` (the bit length of `P`) and
/// `N` (the bit length of `Q`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParameterSizes {
    /// L = 1024, N = 160.
    L1024N160,
    /// L = 2048, N = 224.
    L2048N224,
    /// L = 2048, N = 256.
    L2048N256,
    /// L = 3072, N = 256.
    L3072N256,
}

/// Go's `dsa.L1024N160`.
pub const L1024N160: ParameterSizes = ParameterSizes::L1024N160;
/// Go's `dsa.L2048N224`.
pub const L2048N224: ParameterSizes = ParameterSizes::L2048N224;
/// Go's `dsa.L2048N256`.
pub const L2048N256: ParameterSizes = ParameterSizes::L2048N256;
/// Go's `dsa.L3072N256`.
pub const L3072N256: ParameterSizes = ParameterSizes::L3072N256;

/// Go's `dsa.Parameters`: the domain parameters of a key.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Parameters {
    /// The prime modulus.
    pub p: Int,
    /// The prime order of the subgroup.
    pub q: Int,
    /// The generator.
    pub g: Int,
}

/// Go's `dsa.PublicKey`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PublicKey {
    /// Go's embedded `Parameters`.
    pub parameters: Parameters,
    /// The public value.
    pub y: Int,
}

/// Go's `dsa.PrivateKey`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PrivateKey {
    /// Go's embedded `PublicKey`.
    pub public_key: PublicKey,
    /// The private value.
    pub x: Int,
}

impl std::ops::Deref for PrivateKey {
    type Target = PublicKey;

    /// Go promotes the fields of the embedded `PublicKey`.
    fn deref(&self) -> &PublicKey {
        &self.public_key
    }
}

impl std::ops::Deref for PublicKey {
    type Target = Parameters;

    /// Go promotes the fields of the embedded `Parameters`.
    fn deref(&self) -> &Parameters {
        &self.parameters
    }
}

fn key_size(parameters: &Parameters) -> Result<KeySize, Error> {
    let l = parameters.p.bit_len();
    let n = parameters.q.bit_len();
    #[allow(deprecated)]
    let size = match (l, n) {
        (769..=1024, 1..=160) => KeySize::DSA_1024_160,
        (1537..=2048, 161..=224) => KeySize::DSA_2048_224,
        (1537..=2048, 225..=256) => KeySize::DSA_2048_256,
        (2561..=3072, 225..=256) => KeySize::DSA_3072_256,
        _ => return Err(Error::new("crypto/dsa: unsupported parameter sizes")),
    };
    Ok(size)
}

/// The precisions of `P` and `Q` that the crate expects: the bit lengths
/// rounded up to whole 64-bit limbs.
fn precision(size: KeySize) -> (u32, u32) {
    #[allow(deprecated)]
    if size == KeySize::DSA_1024_160 {
        (1024, 192)
    } else if size == KeySize::DSA_2048_224 || size == KeySize::DSA_2048_256 {
        (2048, 256)
    } else {
        (3072, 256)
    }
}

fn uint(value: &Int, bits: u32) -> Result<BoxedUint, Error> {
    BoxedUint::from_be_slice(value.as_be_bytes(), bits)
        .map_err(|_| Error::new("crypto/dsa: unsupported parameter sizes"))
}

fn to_int(value: &BoxedUint) -> Int {
    Int::from_be_bytes(&value.to_be_bytes_trimmed_vartime())
}

fn components(parameters: &Parameters) -> Result<Components, Error> {
    let (l, n) = precision(key_size(parameters)?);
    Components::from_components(
        uint(&parameters.p, l)?,
        uint(&parameters.q, n)?,
        uint(&parameters.g, l)?,
    )
    .map_err(|_| Error::invalid_public_key())
}

fn parameters_of(components: &Components) -> Parameters {
    Parameters {
        p: to_int(components.p()),
        q: to_int(components.q()),
        g: to_int(components.g()),
    }
}

fn verifying_key(public: &PublicKey) -> Result<VerifyingKey, Error> {
    let components = components(&public.parameters)?;
    let (l, _) = precision(key_size(&public.parameters)?);
    VerifyingKey::from_components(components, uint(&public.y, l)?)
        .map_err(|_| Error::invalid_public_key())
}

impl PublicKey {
    /// The key as a PKIX (SubjectPublicKeyInfo) DER document, the encoding
    /// `x509.MarshalPKIXPublicKey` would use for a DSA key.
    pub fn to_pkix_der(&self) -> Result<Vec<u8>, Error> {
        verifying_key(self)?
            .to_public_key_der()
            .map(|document| document.as_bytes().to_vec())
            .map_err(|error| Error::new(format!("crypto/dsa: {error}")))
    }

    /// Parses a PKIX DER DSA public key, as `x509.ParsePKIXPublicKey` does.
    pub fn from_pkix_der(der: &[u8]) -> Result<PublicKey, Error> {
        let key = VerifyingKey::from_public_key_der(der)
            .map_err(|error| Error::new(format!("crypto/dsa: {error}")))?;
        Ok(PublicKey {
            parameters: parameters_of(key.components()),
            y: to_int(key.y()),
        })
    }

    /// Reports whether `other` is the same key (not part of Go's API, which
    /// has no `Equal` for DSA keys).
    pub fn equal(&self, other: &dyn Any) -> bool {
        other.downcast_ref::<PublicKey>() == Some(self)
    }
}

/// Go's `dsa.GenerateParameters` with the system random source: sets `params`
/// to randomly chosen domain parameters of the given sizes.
pub fn generate_parameters(params: &mut Parameters, sizes: ParameterSizes) -> Result<(), Error> {
    generate_parameters_in(params, None, sizes)
}

/// [`generate_parameters`] reading from `rng`, which the reviewed crate uses
/// as its random source (Go always honours the reader here).
pub fn generate_parameters_with_rng(
    rng: &mut dyn io::Read,
    params: &mut Parameters,
    sizes: ParameterSizes,
) -> Result<(), Error> {
    generate_parameters_in(params, Some(rng), sizes)
}

fn generate_parameters_in(
    params: &mut Parameters,
    rand: Option<&mut dyn io::Read>,
    sizes: ParameterSizes,
) -> Result<(), Error> {
    #[allow(deprecated)]
    let size = match sizes {
        ParameterSizes::L1024N160 => KeySize::DSA_1024_160,
        ParameterSizes::L2048N224 => KeySize::DSA_2048_224,
        ParameterSizes::L2048N256 => KeySize::DSA_2048_256,
        ParameterSizes::L3072N256 => KeySize::DSA_3072_256,
    };
    let mut source = Source::explicit(rand);
    #[allow(deprecated)]
    let generated = Components::try_generate_from_rng_with_key_size(&mut source, size);
    source
        .finish()
        .map_err(|error| Error::new(error.to_string()))?;
    let components = generated.map_err(|_| Error::new("crypto/dsa: invalid ParameterSizes"))?;
    *params = parameters_of(&components);
    Ok(())
}

/// Go's `dsa.GenerateKey` with the system random source: generates a public
/// and private key pair for the parameters already set in `priv_key`.
pub fn generate_key(priv_key: &mut PrivateKey) -> Result<(), Error> {
    generate_key_in(priv_key, None)
}

/// [`generate_key`] reading from `rng`, which Go always honours here.
pub fn generate_key_with_rng(
    rng: &mut dyn io::Read,
    priv_key: &mut PrivateKey,
) -> Result<(), Error> {
    generate_key_in(priv_key, Some(rng))
}

fn generate_key_in(
    priv_key: &mut PrivateKey,
    rand: Option<&mut dyn io::Read>,
) -> Result<(), Error> {
    let parameters = &priv_key.public_key.parameters;
    if parameters.p.is_zero() || parameters.q.is_zero() || parameters.g.is_zero() {
        return Err(Error::new(
            "crypto/dsa: parameters not set up before generating key",
        ));
    }
    let components = components(parameters)?;
    let mut source = Source::explicit(rand);
    let key = SigningKey::try_generate_from_rng_with_components(&mut source, components);
    source
        .finish()
        .map_err(|error| Error::new(error.to_string()))?;
    let key = key.map_err(|_| Error::invalid_public_key())?;
    priv_key.x = to_int(key.x());
    priv_key.public_key.y = to_int(key.verifying_key().y());
    Ok(())
}

fn signing_key(priv_key: &PrivateKey) -> Result<SigningKey, Error> {
    let verifying = verifying_key(&priv_key.public_key)?;
    let (_, n) = precision(key_size(&priv_key.public_key.parameters)?);
    SigningKey::from_components(verifying, uint(&priv_key.x, n)?)
        .map_err(|_| Error::invalid_public_key())
}

/// Go's `dsa.Sign` with the system random source: signs `hash` (which should
/// be the result of hashing a larger message) and returns the signature as
/// `(r, s)`.
pub fn sign(priv_key: &PrivateKey, hash: &[u8]) -> Result<(Int, Int), Error> {
    sign_in(None, priv_key, hash)
}

/// [`sign`] reading from `rng`. As in Go 1.26+, the reader is honoured only
/// with `GODEBUG=cryptocustomrand=1`.
pub fn sign_with_rng(
    rng: &mut dyn io::Read,
    priv_key: &PrivateKey,
    hash: &[u8],
) -> Result<(Int, Int), Error> {
    sign_in(Some(rng), priv_key, hash)
}

fn sign_in(
    rand: Option<&mut dyn io::Read>,
    priv_key: &PrivateKey,
    hash: &[u8],
) -> Result<(Int, Int), Error> {
    let key = signing_key(priv_key)?;
    let mut source = Source::custom(rand);
    let signature = key.sign_prehash_with_rng(&mut source, hash);
    source
        .finish()
        .map_err(|error| Error::new(error.to_string()))?;
    let signature = signature.map_err(|_| Error::invalid_public_key())?;
    Ok((to_int(signature.r()), to_int(signature.s())))
}

/// Go's `dsa.Verify`: verifies the signature `(r, s)` of `hash` using the
/// public key. Go panics on invalid parameters in some cases; this returns
/// false.
pub fn verify(public_key: &PublicKey, hash: &[u8], r: &Int, s: &Int) -> bool {
    let Ok(key) = verifying_key(public_key) else {
        return false;
    };
    let q = &public_key.parameters.q;
    if r.is_zero() || r >= q || s.is_zero() || s >= q {
        return false;
    }
    if !q.bit_len().is_multiple_of(8) {
        return false;
    }
    let Ok((_, n)) = key_size(&public_key.parameters).map(precision) else {
        return false;
    };
    let (Ok(r), Ok(s)) = (uint(r, n), uint(s, n)) else {
        return false;
    };
    let Some(signature) = Signature::from_components(r, s) else {
        return false;
    };
    key.verify_prehash(hash, &signature).is_ok()
}
