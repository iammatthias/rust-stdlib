//! ML-DSA (FIPS 204), compatible with Go's `crypto/mldsa`.
//!
//! Key generation, signing and verification come from the reviewed RustCrypto
//! `ml-dsa` crate; this module adds Go's seed-based private keys, sizes,
//! options and error messages. Private keys are the 32-byte seed, as in Go.

use std::any::Any;
use std::fmt;
use std::io;

use ml_dsa::common::array::typenum::U64;
use ml_dsa::common::array::Array;
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, Signature, SigningKey, VerifyingKey};

use crate::sysrng::Source;
use crate::{BoxError, Hash, PublicKey as AnyPublicKey, Signer, SignerOpts};

/// Size of a private key (the seed) in bytes.
pub const PRIVATE_KEY_SIZE: usize = 32;
/// Size of an ML-DSA-44 public key in bytes.
pub const MLDSA44_PUBLIC_KEY_SIZE: usize = 1312;
/// Size of an ML-DSA-65 public key in bytes.
pub const MLDSA65_PUBLIC_KEY_SIZE: usize = 1952;
/// Size of an ML-DSA-87 public key in bytes.
pub const MLDSA87_PUBLIC_KEY_SIZE: usize = 2592;
/// Size of an ML-DSA-44 signature in bytes.
pub const MLDSA44_SIGNATURE_SIZE: usize = 2420;
/// Size of an ML-DSA-65 signature in bytes.
pub const MLDSA65_SIGNATURE_SIZE: usize = 3309;
/// Size of an ML-DSA-87 signature in bytes.
pub const MLDSA87_SIGNATURE_SIZE: usize = 4627;

/// An error with one of Go's `crypto/mldsa` messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error(String);

impl Error {
    fn new(message: &str) -> Error {
        Error(message.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    K44,
    K65,
    K87,
}

/// Go's `mldsa.Parameters`: an ML-DSA parameter set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Parameters {
    kind: Kind,
}

/// Go's `mldsa.MLDSA44`.
pub const fn mldsa44() -> Parameters {
    Parameters { kind: Kind::K44 }
}

/// Go's `mldsa.MLDSA65`.
pub const fn mldsa65() -> Parameters {
    Parameters { kind: Kind::K65 }
}

/// Go's `mldsa.MLDSA87`.
pub const fn mldsa87() -> Parameters {
    Parameters { kind: Kind::K87 }
}

impl Parameters {
    /// Go's `Parameters.PublicKeySize`.
    pub const fn public_key_size(&self) -> usize {
        match self.kind {
            Kind::K44 => MLDSA44_PUBLIC_KEY_SIZE,
            Kind::K65 => MLDSA65_PUBLIC_KEY_SIZE,
            Kind::K87 => MLDSA87_PUBLIC_KEY_SIZE,
        }
    }

    /// Go's `Parameters.SignatureSize`.
    pub const fn signature_size(&self) -> usize {
        match self.kind {
            Kind::K44 => MLDSA44_SIGNATURE_SIZE,
            Kind::K65 => MLDSA65_SIGNATURE_SIZE,
            Kind::K87 => MLDSA87_SIGNATURE_SIZE,
        }
    }
}

impl fmt::Display for Parameters {
    /// Go's `Parameters.String`: `ML-DSA-44`, `ML-DSA-65` or `ML-DSA-87`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.kind {
            Kind::K44 => "ML-DSA-44",
            Kind::K65 => "ML-DSA-65",
            Kind::K87 => "ML-DSA-87",
        })
    }
}

/// Go's `mldsa.Options`: the signing options. A [`Hash::MlDsaMu`] hash
/// function selects external-μ signing of a 64-byte μ.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Options {
    /// The context string, at most 255 bytes.
    pub context: String,
    /// `None` signs the message; `Some(Hash::MlDsaMu)` signs a precomputed μ.
    pub hash: Option<Hash>,
}

impl SignerOpts for Options {
    /// Go's `Options.HashFunc`: zero.
    fn hash_func(&self) -> Option<Hash> {
        self.hash
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}

enum SigningInner {
    K44(Box<SigningKey<MlDsa44>>),
    K65(Box<SigningKey<MlDsa65>>),
    K87(Box<SigningKey<MlDsa87>>),
}

enum VerifyingInner {
    K44(Box<VerifyingKey<MlDsa44>>),
    K65(Box<VerifyingKey<MlDsa65>>),
    K87(Box<VerifyingKey<MlDsa87>>),
}

impl Clone for SigningInner {
    fn clone(&self) -> SigningInner {
        let seed = self.seed();
        match self {
            SigningInner::K44(_) => SigningInner::K44(Box::new(SigningKey::from_seed(&seed))),
            SigningInner::K65(_) => SigningInner::K65(Box::new(SigningKey::from_seed(&seed))),
            SigningInner::K87(_) => SigningInner::K87(Box::new(SigningKey::from_seed(&seed))),
        }
    }
}

impl SigningInner {
    fn seed(&self) -> ml_dsa::B32 {
        match self {
            SigningInner::K44(k) => k.to_seed(),
            SigningInner::K65(k) => k.to_seed(),
            SigningInner::K87(k) => k.to_seed(),
        }
    }
}

impl Clone for VerifyingInner {
    fn clone(&self) -> VerifyingInner {
        match self {
            VerifyingInner::K44(k) => VerifyingInner::K44(k.clone()),
            VerifyingInner::K65(k) => VerifyingInner::K65(k.clone()),
            VerifyingInner::K87(k) => VerifyingInner::K87(k.clone()),
        }
    }
}

/// Go's `mldsa.PublicKey`.
#[derive(Clone)]
pub struct PublicKey {
    inner: VerifyingInner,
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.parameters())
    }
}

/// Go's `mldsa.PrivateKey`, held as its 32-byte seed.
#[derive(Clone)]
pub struct PrivateKey {
    inner: SigningInner,
    public: PublicKey,
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrivateKey({})", self.public.parameters())
    }
}

fn seed_array(seed: &[u8]) -> Result<ml_dsa::B32, Error> {
    ml_dsa::B32::try_from(seed).map_err(|_| Error::new("mldsa: invalid seed length"))
}

/// Go's `mldsa.GenerateKey`: generates a new private key from the system's
/// random source.
pub fn generate_key(params: Parameters) -> Result<PrivateKey, Error> {
    let mut seed = [0u8; PRIVATE_KEY_SIZE];
    Source::System.fill(&mut seed);
    PrivateKey::from_seed(params, &seed)
}

impl PrivateKey {
    /// Go's `mldsa.NewPrivateKey`: expands a private key from its 32-byte seed.
    pub fn from_seed(params: Parameters, seed: &[u8]) -> Result<Self, Error> {
        let seed = seed_array(seed)?;
        let (inner, public) = match params.kind {
            Kind::K44 => {
                let key = Box::new(SigningKey::<MlDsa44>::from_seed(&seed));
                let public = VerifyingInner::K44(Box::new(key.expanded_key().verifying_key()));
                (SigningInner::K44(key), public)
            }
            Kind::K65 => {
                let key = Box::new(SigningKey::<MlDsa65>::from_seed(&seed));
                let public = VerifyingInner::K65(Box::new(key.expanded_key().verifying_key()));
                (SigningInner::K65(key), public)
            }
            Kind::K87 => {
                let key = Box::new(SigningKey::<MlDsa87>::from_seed(&seed));
                let public = VerifyingInner::K87(Box::new(key.expanded_key().verifying_key()));
                (SigningInner::K87(key), public)
            }
        };
        Ok(Self {
            inner,
            public: PublicKey { inner: public },
        })
    }
}

impl PublicKey {
    /// Go's `mldsa.NewPublicKey`: parses an encoded public key.
    pub fn from_bytes(params: Parameters, encoding: &[u8]) -> Result<Self, Error> {
        if encoding.len() != params.public_key_size() {
            return Err(Error::new("mldsa: invalid public key length"));
        }
        let bad = || Error::new("mldsa: invalid public key length");
        let inner = match params.kind {
            Kind::K44 => VerifyingInner::K44(Box::new(VerifyingKey::decode(
                &encoding.try_into().map_err(|_| bad())?,
            ))),
            Kind::K65 => VerifyingInner::K65(Box::new(VerifyingKey::decode(
                &encoding.try_into().map_err(|_| bad())?,
            ))),
            Kind::K87 => VerifyingInner::K87(Box::new(VerifyingKey::decode(
                &encoding.try_into().map_err(|_| bad())?,
            ))),
        };
        Ok(Self { inner })
    }

    /// Go's `PublicKey.Bytes`.
    pub fn bytes(&self) -> Vec<u8> {
        match &self.inner {
            VerifyingInner::K44(k) => k.encode().to_vec(),
            VerifyingInner::K65(k) => k.encode().to_vec(),
            VerifyingInner::K87(k) => k.encode().to_vec(),
        }
    }

    /// Go's `PublicKey.Parameters`.
    pub fn parameters(&self) -> Parameters {
        match &self.inner {
            VerifyingInner::K44(_) => mldsa44(),
            VerifyingInner::K65(_) => mldsa65(),
            VerifyingInner::K87(_) => mldsa87(),
        }
    }

    /// Go's `PublicKey.Equal`.
    pub fn equal(&self, other: &dyn Any) -> bool {
        other.downcast_ref::<PublicKey>().is_some_and(|other| {
            self.parameters() == other.parameters()
                && crate::subtle::constant_time_compare(&self.bytes(), &other.bytes()) == 1
        })
    }
}

/// A 64-byte μ as the crate's byte array.
fn mu_array(message: &[u8]) -> Result<Array<u8, U64>, Error> {
    Array::<u8, U64>::try_from(message)
        .map_err(|_| Error::new("mldsa: invalid message hash length"))
}

impl PrivateKey {
    /// Go's `PrivateKey.Public`.
    pub fn public(&self) -> &AnyPublicKey {
        &self.public
    }

    /// Go's `PrivateKey.PublicKey`.
    pub fn public_key(&self) -> PublicKey {
        self.public.clone()
    }

    /// Go's `PrivateKey.Equal`.
    pub fn equal(&self, other: &dyn Any) -> bool {
        other.downcast_ref::<PrivateKey>().is_some_and(|other| {
            self.public.parameters() == other.public.parameters()
                && crate::subtle::constant_time_compare(&self.bytes(), &other.bytes()) == 1
        })
    }

    /// Go's `PrivateKey.Bytes`: the 32-byte seed.
    pub fn bytes(&self) -> Vec<u8> {
        self.inner.seed().to_vec()
    }

    /// Go's `PrivateKey.Sign`. With `opts` of [`Options`] the message is
    /// signed with its context; with [`Hash::MlDsaMu`] it is a 64-byte μ. Go
    /// ignores the reader it is given, so there is no `rng` parameter;
    /// randomness comes from [`crate::rand`].
    pub fn sign(&self, message: &[u8], opts: Option<&dyn SignerOpts>) -> Result<Vec<u8>, Error> {
        self.sign_with(message, opts, false)
    }

    /// Go's `PrivateKey.SignDeterministic`.
    pub fn sign_deterministic(
        &self,
        message: &[u8],
        opts: Option<&dyn SignerOpts>,
    ) -> Result<Vec<u8>, Error> {
        self.sign_with(message, opts, true)
    }

    fn sign_with(
        &self,
        message: &[u8],
        opts: Option<&dyn SignerOpts>,
        deterministic: bool,
    ) -> Result<Vec<u8>, Error> {
        let hash = opts.and_then(|opts| opts.hash_func());
        let context = opts
            .and_then(|opts| opts.as_any())
            .and_then(|any| any.downcast_ref::<Options>())
            .map_or("", |options| options.context.as_str());
        let external_mu = match hash {
            None => false,
            Some(Hash::MlDsaMu) => true,
            Some(_) => return Err(Error::new("mldsa: invalid SignerOpts")),
        };
        if !external_mu && context.len() > 255 {
            return Err(Error::new("mldsa: context too long"));
        }
        let mu = if external_mu {
            Some(mu_array(message)?)
        } else {
            None
        };
        macro_rules! sign {
            ($key:expr) => {{
                let expanded = $key.expanded_key();
                let signature = match (&mu, deterministic) {
                    (None, true) => expanded.sign_deterministic(message, context.as_bytes()),
                    (None, false) => {
                        expanded.sign_randomized(message, context.as_bytes(), &mut Source::System)
                    }
                    (Some(mu), true) => Ok(expanded.sign_mu_deterministic(mu)),
                    (Some(mu), false) => expanded.sign_mu_randomized(mu, &mut Source::System),
                };
                signature
                    .map(|signature| signature.encode().to_vec())
                    .map_err(|_| Error::new("mldsa: signing failed"))
            }};
        }
        match &self.inner {
            SigningInner::K44(key) => sign!(key),
            SigningInner::K65(key) => sign!(key),
            SigningInner::K87(key) => sign!(key),
        }
    }
}

impl Signer for PrivateKey {
    fn public(&self) -> &AnyPublicKey {
        &self.public
    }

    fn sign(&self, digest: &[u8], opts: &dyn SignerOpts) -> Result<Vec<u8>, BoxError> {
        PrivateKey::sign(self, digest, Some(opts)).map_err(Into::into)
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

/// Go's `mldsa.Verify`: reports whether `signature` is a valid signature of
/// `message` by `public_key`.
pub fn verify(
    public_key: &PublicKey,
    message: &[u8],
    signature: &[u8],
    opts: Option<&Options>,
) -> Result<(), Error> {
    let context = opts.map_or("", |options| options.context.as_str());
    if context.len() > 255 {
        return Err(Error::new("mldsa: context too long"));
    }
    if signature.len() != public_key.parameters().signature_size() {
        return Err(Error::new("mldsa: invalid signature length"));
    }
    macro_rules! verify {
        ($key:expr) => {{
            let encoded = signature
                .try_into()
                .map_err(|_| Error::new("mldsa: invalid signature length"))?;
            let signature = Signature::decode(&encoded)
                .ok_or_else(|| Error::new(decode_error_text(signature, public_key.parameters())))?;
            if $key.verify_with_context(message, context.as_bytes(), &signature) {
                Ok(())
            } else {
                Err(Error::new("mldsa: invalid signature"))
            }
        }};
    }
    match &public_key.inner {
        VerifyingInner::K44(key) => verify!(key),
        VerifyingInner::K65(key) => verify!(key),
        VerifyingInner::K87(key) => verify!(key),
    }
}

/// Go's text for a signature the decoder rejects. Go checks the hint section
/// while decoding ("mldsa: invalid signature encoding") and the response
/// coefficient bounds only after recomputing the challenge ("mldsa: invalid
/// signature"); the reviewed decoder reports both as `None`. This repeats
/// Go's `hintDecode` format checks on the raw bytes to pick the text. It is
/// input-format validation only; acceptance is still the decoder's.
fn decode_error_text(signature: &[u8], parameters: Parameters) -> &'static str {
    // (k, ω) for ML-DSA-44, -65, -87 (FIPS 204, table 1).
    let (k, omega) = match parameters.kind {
        Kind::K44 => (4usize, 80usize),
        Kind::K65 => (6, 55),
        Kind::K87 => (8, 75),
    };
    if signature.len() < omega + k {
        return "mldsa: invalid signature encoding";
    }
    let y = &signature[signature.len() - (omega + k)..];
    let mut idx = 0usize;
    for i in 0..k {
        let limit = y[omega + i] as usize;
        if limit < idx || limit > omega {
            return "mldsa: invalid signature encoding";
        }
        let first = idx;
        while idx < limit {
            if idx > first && y[idx - 1] >= y[idx] {
                return "mldsa: invalid signature encoding";
            }
            idx += 1;
        }
    }
    if y[idx..omega].iter().any(|&b| b != 0) {
        return "mldsa: invalid signature encoding";
    }
    "mldsa: invalid signature"
}
