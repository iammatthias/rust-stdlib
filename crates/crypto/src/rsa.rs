//! RSA encryption and signatures, compatible with Go's `crypto/rsa`.
//!
//! Key generation, the private-key operation, PKCS #1 v1.5, PSS and OAEP all
//! come from the reviewed RustCrypto `rsa` crate (with `crypto-bigint` and
//! `crypto-primes` underneath); this module adds Go's key structure, option
//! handling, hash selection and error values.
//!
//! # Security advisory
//!
//! The `rsa` crate is affected by RUSTSEC-2023-0071, the "Marvin Attack":
//! potential key recovery through timing side channels in private-key
//! operations (decryption and signing) when an attacker can measure many
//! operations. The crate has no patched release; this project records the
//! advisory in docs/crypto-dependencies.json and docs/adr/0003, and the
//! private-key operations of this module (`decrypt_*`, `sign_*`,
//! [`PrivateKey`]'s [`crate::Signer`] and [`crate::Decrypter`]
//! implementations) inherit it. Do not expose them to remote callers that can
//! time them. Public-key operations are not affected.
//!
//! # Differences from Go
//!
//! * `hash.Hash` arguments (OAEP) are [`crate::Hash`] identifiers: the
//!   reviewed crate selects the digest by type, so the hash is chosen by
//!   name. MD5, SHA-1, SHA-2 and SHA-3 are supported for PKCS #1 v1.5 and PSS;
//!   OAEP supports any of SHA-1, SHA-224, SHA-256, SHA-384, SHA-512,
//!   SHA-512/224 and SHA-512/256 for the label hash paired with any of those
//!   for MGF1, and MD5 or SHA-3 only with the same hash for both.
//! * Like Go 1.26+ without `GODEBUG=cryptocustomrand=1`, the random reader
//!   arguments are ignored; randomness comes from [`crate::rand`].
//! * [`generate_multi_prime_key`] generates two-prime keys only: the `rsa`
//!   crate can load and use multi-prime keys but not generate them.
//! * [`decrypt_pkcs1v15_session_key`] does not run in constant time (Go's
//!   Bleichenbacher countermeasure is a first-party construction, ADR 0003);
//!   it is deprecated in Go and here.
//! * `PrecomputedValues.CRTValues` is computed for keys with more than two
//!   primes, as in Go.
//! * Keys below 1024 bits are rejected, as in Go without
//!   `GODEBUG=rsa1024min=0`.

use std::any::Any;
use std::fmt;
use std::io;
use std::ops::Deref;
use std::sync::Arc;

use ::rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey};
use ::rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
use ::rsa::traits::{PrivateKeyParts, PublicKeyParts};
use ::rsa::{BoxedUint, Oaep, Pkcs1v15Encrypt, Pkcs1v15Sign, Pss, RsaPrivateKey, RsaPublicKey};
use crypto_bigint::ConcatenatingMul;
use sha2::digest::{Digest, FixedOutputReset};

use crate::bigint::Int;
use crate::sysrng::{godebug, Source};
use crate::{BoxError, DecrypterOpts, Hash, PublicKey as AnyPublicKey, Signer, SignerOpts};

/// Go's `rsa.PSSSaltLengthAuto`: the longest salt when signing, and detect
/// the salt length when verifying.
pub const PSS_SALT_LENGTH_AUTO: i64 = 0;
/// Go's `rsa.PSSSaltLengthEqualsHash`: the salt is as long as the hash.
pub const PSS_SALT_LENGTH_EQUALS_HASH: i64 = -1;

/// The errors of `crypto/rsa`. Go's `ErrDecryption`, `ErrMessageTooLong` and
/// `ErrVerification` are the first three variants; other errors carry Go's
/// message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Go's `rsa.ErrDecryption`: `crypto/rsa: decryption error`.
    Decryption,
    /// Go's `rsa.ErrMessageTooLong`: `crypto/rsa: message too long for RSA key size`.
    MessageTooLong,
    /// Go's `rsa.ErrVerification`: `crypto/rsa: verification error`.
    Verification,
    /// Any other error.
    Other(String),
}

impl Error {
    fn other(message: impl Into<String>) -> Error {
        Error::Other(message.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Decryption => f.write_str("crypto/rsa: decryption error"),
            Error::MessageTooLong => f.write_str("crypto/rsa: message too long for RSA key size"),
            Error::Verification => f.write_str("crypto/rsa: verification error"),
            Error::Other(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for Error {}

fn from_crate(error: ::rsa::errors::Error) -> Error {
    use ::rsa::errors::Error as E;
    match error {
        E::Decryption => Error::Decryption,
        E::MessageTooLong => Error::MessageTooLong,
        E::Verification => Error::Verification,
        other => Error::other(format!("crypto/rsa: {other}")),
    }
}

/// Go's `rsa.PublicKey`: an RSA public key.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PublicKey {
    /// The modulus.
    pub n: Int,
    /// The public exponent.
    pub e: i64,
}

impl PublicKey {
    /// Go's `PublicKey.Size`: the modulus size in bytes.
    pub fn size(&self) -> usize {
        self.n.bit_len().div_ceil(8)
    }

    /// Go's `PublicKey.Equal`.
    pub fn equal(&self, other: &dyn Any) -> bool {
        other.downcast_ref::<PublicKey>().is_some_and(|other| {
            crate::subtle::constant_time_compare(self.n.as_be_bytes(), other.n.as_be_bytes()) == 1
                && self.e == other.e
        })
    }

    /// The key as a PKCS #1 `RSAPublicKey` DER document, the encoding
    /// `x509.MarshalPKCS1PublicKey` uses.
    pub fn to_pkcs1_der(&self) -> Result<Vec<u8>, Error> {
        let key = self.to_crate()?;
        key.to_pkcs1_der()
            .map(|document| document.as_bytes().to_vec())
            .map_err(|error| Error::other(format!("crypto/rsa: {error}")))
    }

    /// Parses a PKCS #1 `RSAPublicKey`, as `x509.ParsePKCS1PublicKey` does.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<PublicKey, Error> {
        RsaPublicKey::from_pkcs1_der(der)
            .map(|key| PublicKey::from_crate(&key))
            .map_err(|error| Error::other(format!("crypto/rsa: {error}")))
    }

    /// The key as a PKIX (SubjectPublicKeyInfo) DER document, the encoding
    /// `x509.MarshalPKIXPublicKey` uses.
    pub fn to_pkix_der(&self) -> Result<Vec<u8>, Error> {
        let key = self.to_crate()?;
        key.to_public_key_der()
            .map(|document| document.as_bytes().to_vec())
            .map_err(|error| Error::other(format!("crypto/rsa: {error}")))
    }

    /// Parses a PKIX DER RSA public key, as `x509.ParsePKIXPublicKey` does.
    pub fn from_pkix_der(der: &[u8]) -> Result<PublicKey, Error> {
        RsaPublicKey::from_public_key_der(der)
            .map(|key| PublicKey::from_crate(&key))
            .map_err(|error| Error::other(format!("crypto/rsa: {error}")))
    }

    fn from_crate(key: &RsaPublicKey) -> PublicKey {
        PublicKey {
            n: Int::from_be_bytes(&key.n().as_ref().to_be_bytes_trimmed_vartime()),
            e: i64::try_from(
                key.e()
                    .to_be_bytes_trimmed_vartime()
                    .iter()
                    .fold(0u128, |acc, &b| (acc << 8) | u128::from(b)),
            )
            .unwrap_or(i64::MAX),
        }
    }

    /// Go's `fipsPublicKey`: validates the key as Go does and converts it.
    fn to_crate(&self) -> Result<RsaPublicKey, Error> {
        if self.n.is_zero() {
            return Err(Error::other("crypto/rsa: missing public modulus"));
        }
        if self.n.bit(0) == 0 {
            return Err(Error::other("crypto/rsa: public modulus is even"));
        }
        if self.e < 2 {
            return Err(Error::other(
                "crypto/rsa: public exponent too small or negative",
            ));
        }
        if self.e & 1 == 0 {
            return Err(Error::other("crypto/rsa: public exponent is even"));
        }
        if self.e > i64::from(i32::MAX) {
            return Err(Error::other("crypto/rsa: public exponent too large"));
        }
        // The crate's default modulus limit is 8192 bits; Go has none (X.509
        // certificates with larger moduli exist in its test data).
        RsaPublicKey::new_with_max_size(boxed(&self.n), BoxedUint::from(self.e as u64), 1 << 20)
            .map_err(|error| Error::other(format!("crypto/rsa: {error}")))
    }
}

/// A DER INTEGER view of an [`Int`].
fn uint(value: &Int) -> Result<::rsa::pkcs1::UintRef<'_>, Error> {
    ::rsa::pkcs1::UintRef::new(value.as_be_bytes())
        .map_err(|error| Error::other(format!("crypto/rsa: {error}")))
}

fn boxed(value: &Int) -> BoxedUint {
    BoxedUint::from_be_slice_vartime(value.as_be_bytes())
}

fn unboxed(value: &BoxedUint) -> Int {
    Int::from_be_bytes(&value.to_be_bytes_trimmed_vartime())
}

/// `(a * b) mod m` for `m` greater than zero.
#[cfg(feature = "x509")]
fn mul_mod(a: &Int, b: &Int, m: &Int) -> Int {
    if a.is_zero() || b.is_zero() {
        return Int::zero();
    }
    let modulus = boxed(m).to_nz().into_option().expect("non-zero modulus");
    unboxed(&(&boxed(a).concatenating_mul(&boxed(b)) % &modulus))
}

/// `a mod m` for `m` greater than zero.
#[cfg(feature = "x509")]
fn rem(a: &Int, m: &Int) -> Int {
    if a.is_zero() {
        return Int::zero();
    }
    let modulus = boxed(m).to_nz().into_option().expect("non-zero modulus");
    unboxed(&(&boxed(a) % &modulus))
}

/// `a⁻¹ mod m` for `m` greater than one, if `a` is invertible.
#[cfg(feature = "x509")]
fn inverse(a: &Int, m: &Int) -> Option<Int> {
    if a.is_zero() {
        return None;
    }
    let modulus = boxed(m).to_nz().into_option()?;
    let reduced = &boxed(a) % &modulus;
    reduced
        .invert_mod(&modulus)
        .into_option()
        .map(|v| unboxed(&v))
}

/// Whether `a` has an inverse modulo `m`, like `big.Int.ModInverse` not
/// returning nil.
#[cfg(feature = "x509")]
fn invertible(a: &Int, m: &Int) -> bool {
    inverse(a, m).is_some()
}

/// `a - 1` for `a` greater than zero.
#[cfg(feature = "x509")]
fn sub_one(a: &Int) -> Int {
    unboxed(&boxed(a).wrapping_sub(BoxedUint::one()))
}

/// `|a - b|`.
#[cfg(feature = "x509")]
fn abs_diff(a: &Int, b: &Int) -> Int {
    let (high, low) = if a >= b { (a, b) } else { (b, a) };
    if low.is_zero() {
        return high.clone();
    }
    unboxed(&boxed(high).wrapping_sub(boxed(low)))
}

/// Go's `fips140/rsa.checkPublicKey` errors.
#[cfg(feature = "x509")]
fn go_check_public_key(n: &Int, e: i64) -> Option<String> {
    if n.bit(0) == 0 {
        return Some("crypto/rsa: public modulus is even".into());
    }
    if e < 2 {
        return Some("crypto/rsa: public exponent too small or negative".into());
    }
    if e & 1 == 0 {
        return Some("crypto/rsa: public exponent is even".into());
    }
    if e > i64::from(i32::MAX) {
        return Some("crypto/rsa: public exponent too large".into());
    }
    None
}

/// The message Go's `crypto/rsa` gives a private key that it rejects when it
/// builds the key from `n`, `e`, `d`, the primes and, if the encoding
/// carries them, the CRT values `(dP, dQ, qInv)`: `PrivateKey.Precompute` and
/// `Validate` run `fips140/rsa` `NewPrivateKey`,
/// `NewPrivateKeyWithPrecomputation` or `NewPrivateKeyWithoutCRT` and
/// `checkPrivateKey`, whose first failing check names the error.
///
/// This only chooses the text of a rejection that the reviewed `rsa` crate
/// already made; it returns `None` when none of Go's checks fails, and the
/// caller then keeps the crate's message.
#[cfg(feature = "x509")]
pub(crate) fn validation_error_text(
    n: &Int,
    e: i64,
    d: &Int,
    primes: &[Int],
    crt: Option<(&Int, &Int, &Int)>,
) -> Option<String> {
    const MODULUS: &str = "modulus must be > 1";
    let one = Int::from_u64(1);
    let at_most_one = |x: &Int| *x <= one;
    if primes.len() < 2 {
        // Go's Validate reports missing primes before building the key.
        return None;
    }
    if at_most_one(n) {
        return Some(MODULUS.into());
    }
    if primes.len() != 2 {
        // NewPrivateKeyWithoutCRT, then precomputeLegacy.
        if let Some(message) = set_bytes_error(d, n) {
            return Some(message.into());
        }
        if let Some(message) = go_check_public_key(n, e) {
            return Some(message);
        }
        if primes.iter().any(at_most_one) {
            return Some("crypto/rsa: prime factor is <= 1".into());
        }
        // The first two primes must be relatively prime, then each further
        // prime to the product of those before it.
        let mut product = primes[0].clone();
        for (i, prime) in primes.iter().enumerate().skip(1) {
            let (value, modulus) = if i == 1 {
                (prime, &primes[0])
            } else {
                (&product, prime)
            };
            if !invertible(value, modulus) {
                return Some("crypto/rsa: prime factors are not relatively prime".into());
            }
            product = unboxed(&boxed(&product).concatenating_mul(&boxed(prime)));
        }
        return None;
    }
    let (p, q) = (&primes[0], &primes[1]);
    if at_most_one(p) || at_most_one(q) {
        return Some(MODULUS.into());
    }
    if let Some(message) = set_bytes_error(d, n) {
        return Some(message.into());
    }
    let (dp, dq, qinv) = match crt {
        Some((dp, dq, qinv)) => {
            if let Some(message) = set_bytes_error(qinv, p) {
                return Some(message.into());
            }
            (dp.clone(), dq.clone(), qinv.clone())
        }
        None => {
            // newPrivateKey derives the CRT values from d, p and q.
            let (pm1, qm1) = (sub_one(p), sub_one(q));
            if at_most_one(&pm1) || at_most_one(&qm1) {
                return Some(MODULUS.into());
            }
            if p.bit(0) == 0 {
                return Some("crypto/rsa: p is even".into());
            }
            let qinv = inverse(q, p).unwrap_or_default();
            (rem(d, &pm1), rem(d, &qm1), qinv)
        }
    };
    // checkPrivateKey.
    if let Some(message) = go_check_public_key(n, e) {
        return Some(message);
    }
    if p >= n || q >= n {
        return Some("crypto/rsa: invalid prime".into());
    }
    if !mul_mod(p, q, n).is_zero() {
        return Some("crypto/rsa: p * q != n".into());
    }
    let exponent = Int::from_u64(e as u64);
    let pm1 = sub_one(p);
    if at_most_one(&pm1) {
        return Some("crypto/rsa: invalid prime".into());
    }
    if dp >= pm1 || mul_mod(&exponent, &dp, &pm1) != one {
        return Some("crypto/rsa: invalid CRT exponent".into());
    }
    let qm1 = sub_one(q);
    if at_most_one(&qm1) {
        return Some("crypto/rsa: invalid prime".into());
    }
    if dq >= qm1 || mul_mod(&exponent, &dq, &qm1) != one {
        return Some("crypto/rsa: invalid CRT exponent".into());
    }
    if mul_mod(&rem(q, p), &qinv, p) != one {
        return Some("crypto/rsa: invalid CRT coefficient".into());
    }
    if rem(d, &pm1) != dp {
        return Some("crypto/rsa: d does not match dP".into());
    }
    if rem(d, &qm1) != dq {
        return Some("crypto/rsa: d does not match dQ".into());
    }
    if p == q {
        return Some("crypto/rsa: p == q".into());
    }
    let half = n.bit_len() / 2;
    if abs_diff(p, q).bit_len() as i64 <= half as i64 - 100 {
        return Some("crypto/rsa: |p - q| too small".into());
    }
    if d.bit_len() <= half {
        return Some("crypto/rsa: d too small".into());
    }
    None
}

/// The error of Go's `bigmod.Nat.SetBytes(x.Bytes(), m)`, which rejects `x`
/// when its bytes do not fit the limbs of `m` (words of the host's size, as
/// in Go) before it compares the value with `m`.
#[cfg(feature = "x509")]
fn set_bytes_error(x: &Int, m: &Int) -> Option<&'static str> {
    if x < m {
        return None;
    }
    let word_bits = usize::BITS as usize;
    let limb_bytes = m.bit_len().div_ceil(word_bits) * (word_bits / 8);
    if x.bit_len().div_ceil(8) > limb_bytes {
        Some("input overflows the modulus size")
    } else {
        Some("input overflows the modulus")
    }
}

/// Go's `rsa.CRTValue`: contains precomputed parameters that speed up private
/// operations for keys with more than two primes (deprecated in Go).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CRTValue {
    /// `D mod (prime - 1)`.
    pub exp: Int,
    /// `R * Coeff ≡ 1 mod prime`.
    pub coeff: Int,
    /// The product of the primes before this one (including `P` and `Q`).
    pub r: Int,
}

/// Go's `rsa.PrecomputedValues`.
#[derive(Clone, Default)]
pub struct PrecomputedValues {
    /// `D mod (P - 1)`.
    pub dp: Option<Int>,
    /// `D mod (Q - 1)`.
    pub dq: Option<Int>,
    /// `Q⁻¹ mod P`.
    pub qinv: Option<Int>,
    /// Values for the primes beyond `P` and `Q` (deprecated in Go).
    pub crt_values: Vec<CRTValue>,
    /// The validated key of the `rsa` crate, like Go's unexported `fips`.
    cache: Option<Arc<RsaPrivateKey>>,
}

impl fmt::Debug for PrecomputedValues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrecomputedValues")
            .field("dp", &self.dp)
            .field("dq", &self.dq)
            .field("qinv", &self.qinv)
            .field("crt_values", &self.crt_values)
            .finish_non_exhaustive()
    }
}

/// Go's `rsa.PrivateKey`: an RSA private key.
#[derive(Clone, Debug, Default)]
pub struct PrivateKey {
    /// Go's embedded `PublicKey`.
    pub public_key: PublicKey,
    /// The private exponent.
    pub d: Int,
    /// The prime factors of `N`, at least two.
    pub primes: Vec<Int>,
    /// Precomputed values; see [`PrivateKey::precompute`].
    pub precomputed: PrecomputedValues,
}

impl Deref for PrivateKey {
    type Target = PublicKey;

    /// Go promotes the fields and methods of the embedded `PublicKey`.
    fn deref(&self) -> &PublicKey {
        &self.public_key
    }
}

fn big_int_equal(a: &Int, b: &Int) -> bool {
    crate::subtle::constant_time_compare(a.as_be_bytes(), b.as_be_bytes()) == 1
}

/// Go's `checkKeySize`.
fn check_key_size(size: usize) -> Result<(), Error> {
    if size >= 1024 || godebug("rsa1024min").as_deref() == Some("0") {
        return Ok(());
    }
    Err(Error::other(format!(
        "crypto/rsa: {size}-bit keys are insecure (see https://go.dev/pkg/crypto/rsa#hdr-Minimum_key_size)"
    )))
}

/// Go's `checkPublicKeySize`.
fn check_public_key_size(key: &PublicKey) -> Result<(), Error> {
    if key.n.is_zero() {
        return Err(Error::other("crypto/rsa: missing public modulus"));
    }
    check_key_size(key.n.bit_len())
}

impl PrivateKey {
    /// Go's `PrivateKey.Public`.
    pub fn public(&self) -> &AnyPublicKey {
        &self.public_key
    }

    /// Go's `PrivateKey.Equal`.
    pub fn equal(&self, other: &dyn Any) -> bool {
        let Some(other) = other.downcast_ref::<PrivateKey>() else {
            return false;
        };
        self.public_key.equal(&other.public_key)
            && big_int_equal(&self.d, &other.d)
            && self.primes.len() == other.primes.len()
            && self
                .primes
                .iter()
                .zip(&other.primes)
                .all(|(a, b)| big_int_equal(a, b))
    }

    /// Go's `PrivateKey.Precompute`: performs some calculations that speed up
    /// private key operations. Called automatically by [`generate_key`].
    pub fn precompute(&mut self) {
        if self.precomputed_is_consistent() {
            return;
        }
        match self.compute_precomputed() {
            Ok(precomputed) => self.precomputed = precomputed,
            Err(_) => self.precomputed.cache = None,
        }
    }

    /// Go's `PrivateKey.Validate`: performs basic sanity checks on the key.
    pub fn validate(&mut self) -> Result<(), Error> {
        if self.primes.len() < 2 {
            return Err(Error::other("crypto/rsa: missing primes"));
        }
        if self.precomputed_is_consistent() {
            return Ok(());
        }
        if self.precomputed.cache.is_some() {
            return Err(Error::other(
                "crypto/rsa: precomputed values are inconsistent with the key",
            ));
        }
        self.compute_precomputed().map(|_| ())
    }

    fn precomputed_is_consistent(&self) -> bool {
        let Some(cache) = &self.precomputed.cache else {
            return false;
        };
        let n = unboxed(cache.n().as_ref());
        let d = unboxed(cache.d());
        if n != self.public_key.n || self.public_key.e != e_of(cache.as_ref()) || d != self.d {
            return false;
        }
        let primes = cache.primes();
        if self.primes.len() != primes.len() {
            return false;
        }
        if !self
            .primes
            .iter()
            .zip(primes)
            .all(|(a, b)| *a == unboxed(b))
        {
            return false;
        }
        if primes.len() != 2 {
            return true;
        }
        let dp = cache.dp().map(unboxed);
        let dq = cache.dq().map(unboxed);
        let qinv = cache.qinv().map(|q| unboxed(&q.retrieve()));
        self.precomputed.dp == dp && self.precomputed.dq == dq && self.precomputed.qinv == qinv
    }

    /// Go's `precompute`: builds and validates the key in the `rsa` crate.
    fn compute_precomputed(&self) -> Result<PrecomputedValues, Error> {
        if self.public_key.n.is_zero() {
            return Err(Error::other("crypto/rsa: missing public modulus"));
        }
        if self.d.is_zero() {
            return Err(Error::other("crypto/rsa: missing private exponent"));
        }
        let key = self.build_crate_key()?;
        let mut precomputed = PrecomputedValues {
            dp: key.dp().map(unboxed),
            dq: key.dq().map(unboxed),
            qinv: key.qinv().map(|q| unboxed(&q.retrieve())),
            crt_values: Vec::new(),
            cache: Some(Arc::new(key)),
        };
        if self.primes.len() > 2 {
            precomputed.crt_values = self.crt_values()?;
        }
        Ok(precomputed)
    }

    /// Go's `precomputeLegacy` values for the primes beyond the second.
    fn crt_values(&self) -> Result<Vec<CRTValue>, Error> {
        use ::rsa::BoxedUint as U;
        let d = boxed(&self.d);
        let mut r = boxed(&self.primes[0]).concatenating_mul(&boxed(&self.primes[1]));
        let mut values = Vec::new();
        for prime in &self.primes[2..] {
            let prime = boxed(prime);
            let minus_one = prime.wrapping_sub(U::one());
            let exp = d.rem_vartime(
                &minus_one
                    .to_nz()
                    .into_option()
                    .ok_or_else(|| Error::other("crypto/rsa: prime factor is <= 1"))?,
            );
            let nonzero = prime
                .to_nz()
                .into_option()
                .ok_or_else(|| Error::other("crypto/rsa: prime factor is <= 1"))?;
            let r_mod = &r % &nonzero;
            let coeff = r_mod.invert_mod(&nonzero).into_option().ok_or_else(|| {
                Error::other("crypto/rsa: prime factors are not relatively prime")
            })?;
            values.push(CRTValue {
                exp: unboxed(&exp),
                coeff: unboxed(&coeff),
                r: unboxed(&r),
            });
            r = r.concatenating_mul(&prime);
        }
        Ok(values)
    }

    fn build_crate_key(&self) -> Result<RsaPrivateKey, Error> {
        let public = self.public_key.to_crate()?;
        let primes: Vec<BoxedUint> = self.primes.iter().map(boxed).collect();
        let mut key = RsaPrivateKey::from_components(
            public.n().as_ref().clone(),
            public.e().clone(),
            boxed(&self.d),
            primes,
        )
        .map_err(|error| Error::other(format!("crypto/rsa: {error}")))?;
        key.precompute().ok();
        Ok(key)
    }

    /// Go's `fipsPrivateKey`: the cached crate key or a freshly built one.
    fn crate_key(&self) -> Result<Arc<RsaPrivateKey>, Error> {
        match &self.precomputed.cache {
            Some(cache) => Ok(cache.clone()),
            None => Ok(Arc::new(self.build_crate_key()?)),
        }
    }

    /// Go's `PrivateKey.Sign(nil, digest, opts)`: PSS when `opts` is
    /// [`PSSOptions`] (salt from the system source), PKCS #1 v1.5 otherwise.
    pub fn sign(&self, digest: &[u8], opts: &dyn SignerOpts) -> Result<Vec<u8>, Error> {
        self.sign_in(None, digest, opts)
    }

    /// [`PrivateKey::sign`] reading the PSS salt from `rng`, like Go's
    /// `PrivateKey.Sign(rng, digest, opts)`. PKCS #1 v1.5 signing ignores the
    /// reader, as in Go.
    pub fn sign_with_rng(
        &self,
        rng: &mut dyn io::Read,
        digest: &[u8],
        opts: &dyn SignerOpts,
    ) -> Result<Vec<u8>, Error> {
        self.sign_in(Some(rng), digest, opts)
    }

    fn sign_in(
        &self,
        rand: Option<&mut dyn io::Read>,
        digest: &[u8],
        opts: &dyn SignerOpts,
    ) -> Result<Vec<u8>, Error> {
        if let Some(pss) = opts
            .as_any()
            .and_then(|any| any.downcast_ref::<PSSOptions>())
        {
            let hash = pss.hash.ok_or_else(|| unavailable_hash(None))?;
            return sign_pss_in(rand, self, hash, digest, Some(pss));
        }
        sign_pkcs1v15(self, opts.hash_func(), digest)
    }

    /// Go's `PrivateKey.Decrypt`: PKCS #1 v1.5 with no options, OAEP or
    /// PKCS #1 v1.5 with a session key length otherwise. Go ignores the
    /// reader it is given, so there is no `rng` parameter.
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        opts: Option<&DecrypterOpts>,
    ) -> Result<Vec<u8>, Error> {
        let Some(opts) = opts else {
            return decrypt_pkcs1v15(self, ciphertext);
        };
        if let Some(oaep) = opts.downcast_ref::<OAEPOptions>() {
            // Go's PrivateKey.Decrypt words this error without "crypto/".
            let unavailable = |hash: Option<Hash>| {
                Error::other(format!(
                    "rsa: requested hash function unavailable: {}",
                    hash.map_or("unknown hash value 0".into(), |hash| hash.to_string())
                ))
            };
            let hash = oaep.hash.ok_or_else(|| unavailable(None))?;
            if !hash.available() {
                return Err(unavailable(Some(hash)));
            }
            if let Some(mgf) = oaep.mgf_hash {
                if !mgf.available() {
                    return Err(unavailable(Some(mgf)));
                }
            }
            return decrypt_oaep_inner(
                hash,
                oaep.mgf_hash.unwrap_or(hash),
                self,
                ciphertext,
                &oaep.label,
            );
        }
        if let Some(pkcs) = opts.downcast_ref::<PKCS1v15DecryptOptions>() {
            if pkcs.session_key_len > 0 {
                let mut plaintext = vec![0u8; pkcs.session_key_len];
                crate::rand::read(&mut plaintext);
                decrypt_pkcs1v15_session_key(self, ciphertext, &mut plaintext)?;
                return Ok(plaintext);
            }
            return decrypt_pkcs1v15(self, ciphertext);
        }
        Err(Error::other("crypto/rsa: invalid options for Decrypt"))
    }

    /// The key as a PKCS #1 `RSAPrivateKey` DER document, the encoding
    /// `x509.MarshalPKCS1PrivateKey` uses. Keys with more than two primes use
    /// the multi-prime form. The structure is encoded with the reviewed
    /// `pkcs1` crate from the key's own values (the `rsa` crate's encoder
    /// handles two primes of equal size only).
    pub fn to_pkcs1_der(&self) -> Result<Vec<u8>, Error> {
        use ::rsa::pkcs1::{OtherPrimeInfo, RsaPrivateKeyRef};
        use ::rsa::pkcs8::der::Encode;

        let mut key = self.clone();
        key.precompute();
        let missing = || Error::other("crypto/rsa: key has no precomputed values");
        if key.primes.len() < 2 || key.d.is_zero() || key.public_key.n.is_zero() {
            return Err(Error::other("crypto/rsa: invalid private key"));
        }
        let (dp, dq, qinv) = (
            key.precomputed.dp.as_ref().ok_or_else(missing)?,
            key.precomputed.dq.as_ref().ok_or_else(missing)?,
            key.precomputed.qinv.as_ref().ok_or_else(missing)?,
        );
        let e = Int::from_u64(key.public_key.e as u64);
        let mut others = Vec::new();
        for (prime, crt) in key.primes[2..].iter().zip(&key.precomputed.crt_values) {
            others.push(OtherPrimeInfo {
                prime: uint(prime)?,
                exponent: uint(&crt.exp)?,
                coefficient: uint(&crt.coeff)?,
            });
        }
        if others.len() != key.primes.len() - 2 {
            return Err(missing());
        }
        let document = RsaPrivateKeyRef {
            modulus: uint(&key.public_key.n)?,
            public_exponent: uint(&e)?,
            private_exponent: uint(&key.d)?,
            prime1: uint(&key.primes[0])?,
            prime2: uint(&key.primes[1])?,
            exponent1: uint(dp)?,
            exponent2: uint(dq)?,
            coefficient: uint(qinv)?,
            other_prime_infos: (!others.is_empty()).then_some(others),
        };
        document
            .to_der()
            .map_err(|error| Error::other(format!("crypto/rsa: {error}")))
    }

    /// Parses a PKCS #1 `RSAPrivateKey`, as `x509.ParsePKCS1PrivateKey` does:
    /// the key is validated and precomputed.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<PrivateKey, Error> {
        use ::rsa::pkcs1::RsaPrivateKeyRef;
        use ::rsa::pkcs8::der::Decode;

        let parsed = RsaPrivateKeyRef::from_der(der)
            .map_err(|error| Error::other(format!("crypto/rsa: {error}")))?;
        let int = |value: ::rsa::pkcs1::UintRef<'_>| Int::from_be_bytes(value.as_bytes());
        let e = int(parsed.public_exponent)
            .to_u64()
            .and_then(|e| i64::try_from(e).ok())
            .ok_or_else(|| Error::other("crypto/rsa: public exponent too large"))?;
        let mut primes = vec![int(parsed.prime1), int(parsed.prime2)];
        if let Some(others) = &parsed.other_prime_infos {
            primes.extend(others.iter().map(|info| int(info.prime)));
        }
        let mut key = PrivateKey {
            public_key: PublicKey {
                n: int(parsed.modulus),
                e,
            },
            d: int(parsed.private_exponent),
            primes,
            precomputed: PrecomputedValues::default(),
        };
        if key.public_key.n.is_zero() || key.d.is_zero() || key.primes.iter().any(Int::is_zero) {
            return Err(Error::other(
                "crypto/rsa: private key contains zero or negative value",
            ));
        }
        key.validate()?;
        key.precompute();
        Ok(key)
    }

    /// The key as a PKCS #8 DER document, the encoding
    /// `x509.MarshalPKCS8PrivateKey` uses.
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>, Error> {
        use ::rsa::pkcs8::der::asn1::OctetStringRef;
        use ::rsa::pkcs8::der::Encode;
        use ::rsa::pkcs8::PrivateKeyInfoRef;

        let inner = self.to_pkcs1_der()?;
        let wrap = |error: ::rsa::pkcs8::der::Error| Error::other(format!("crypto/rsa: {error}"));
        PrivateKeyInfoRef::new(
            ::rsa::pkcs1::ALGORITHM_ID,
            OctetStringRef::new(&inner).map_err(wrap)?,
        )
        .to_der()
        .map_err(wrap)
    }

    /// Parses a PKCS #8 DER RSA private key, as `x509.ParsePKCS8PrivateKey`
    /// does for `*rsa.PrivateKey`.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<PrivateKey, Error> {
        use ::rsa::pkcs8::der::Decode;
        use ::rsa::pkcs8::PrivateKeyInfoRef;

        let info = PrivateKeyInfoRef::from_der(der)
            .map_err(|error| Error::other(format!("crypto/rsa: {error}")))?;
        if info.algorithm.oid != ::rsa::pkcs1::ALGORITHM_OID {
            return Err(Error::other(
                "crypto/rsa: PKCS #8 key is not an rsaEncryption key",
            ));
        }
        PrivateKey::from_pkcs1_der(info.private_key.as_bytes())
    }

    fn from_crate(key: RsaPrivateKey) -> PrivateKey {
        let mut private = PrivateKey {
            public_key: PublicKey::from_crate(&key.to_public_key()),
            d: unboxed(key.d()),
            primes: key.primes().iter().map(unboxed).collect(),
            precomputed: PrecomputedValues::default(),
        };
        private.precompute();
        private
    }
}

fn e_of(key: &RsaPrivateKey) -> i64 {
    PublicKey::from_crate(&key.to_public_key()).e
}

impl Signer for PrivateKey {
    fn public(&self) -> &AnyPublicKey {
        &self.public_key
    }

    fn sign(&self, digest: &[u8], opts: &dyn SignerOpts) -> Result<Vec<u8>, BoxError> {
        PrivateKey::sign(self, digest, opts).map_err(Into::into)
    }

    fn sign_with_rng(
        &self,
        rng: &mut dyn io::Read,
        digest: &[u8],
        opts: &dyn SignerOpts,
    ) -> Result<Vec<u8>, BoxError> {
        PrivateKey::sign_with_rng(self, rng, digest, opts).map_err(Into::into)
    }
}

impl crate::Decrypter for PrivateKey {
    fn public(&self) -> &AnyPublicKey {
        &self.public_key
    }

    fn decrypt(&self, msg: &[u8], opts: Option<&DecrypterOpts>) -> Result<Vec<u8>, BoxError> {
        PrivateKey::decrypt(self, msg, opts).map_err(Into::into)
    }

    /// Go ignores the reader, so this is [`crate::Decrypter::decrypt`].
    fn decrypt_with_rng(
        &self,
        _rng: &mut dyn io::Read,
        msg: &[u8],
        opts: Option<&DecrypterOpts>,
    ) -> Result<Vec<u8>, BoxError> {
        PrivateKey::decrypt(self, msg, opts).map_err(Into::into)
    }
}

/// Go's `rsa.OAEPOptions`: options for OAEP encryption and decryption.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OAEPOptions {
    /// The hash used to hash the label (and, by default, for MGF1).
    pub hash: Option<Hash>,
    /// The hash for MGF1; `None` uses [`OAEPOptions::hash`].
    pub mgf_hash: Option<Hash>,
    /// The label, empty for none.
    pub label: Vec<u8>,
}

/// Go's `rsa.PKCS1v15DecryptOptions` (deprecated): options for PKCS #1 v1.5
/// decryption.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PKCS1v15DecryptOptions {
    /// When positive, decryption replaces a failed decryption by a random
    /// session key of this length.
    pub session_key_len: usize,
}

/// Go's `rsa.PSSOptions`: options for PSS signatures.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PSSOptions {
    /// [`PSS_SALT_LENGTH_AUTO`], [`PSS_SALT_LENGTH_EQUALS_HASH`] or the length.
    pub salt_length: i64,
    /// The hash that was used to hash the message; `None` is Go's zero hash.
    pub hash: Option<Hash>,
}

impl SignerOpts for PSSOptions {
    /// Go's `PSSOptions.HashFunc`.
    fn hash_func(&self) -> Option<Hash> {
        self.hash
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}

fn unavailable_hash(hash: Option<Hash>) -> Error {
    match hash {
        Some(hash) => Error::other(format!(
            "crypto/rsa: requested hash function unavailable: {hash}"
        )),
        None => {
            Error::other("crypto/rsa: requested hash function unavailable: unknown hash value 0")
        }
    }
}

fn unsupported_hash(hash: Hash) -> Error {
    Error::other(format!(
        "crypto/rsa: hash function {hash} is not supported by the reviewed rsa crate"
    ))
}

/// Runs `$body` with the type alias `$d` bound to the digest type of `$hash`;
/// `$otherwise` for hashes this crate has no implementation of.
macro_rules! with_hash {
    ($hash:expr, $d:ident => $body:expr, $otherwise:expr) => {
        match $hash {
            Hash::Md5 => {
                type $d = ::md5::Md5;
                $body
            }
            Hash::Sha1 => {
                type $d = ::sha1::Sha1;
                $body
            }
            Hash::Sha224 => {
                type $d = ::sha2::Sha224;
                $body
            }
            Hash::Sha256 => {
                type $d = ::sha2::Sha256;
                $body
            }
            Hash::Sha384 => {
                type $d = ::sha2::Sha384;
                $body
            }
            Hash::Sha512 => {
                type $d = ::sha2::Sha512;
                $body
            }
            Hash::Sha512_224 => {
                type $d = ::sha2::Sha512_224;
                $body
            }
            Hash::Sha512_256 => {
                type $d = ::sha2::Sha512_256;
                $body
            }
            Hash::Sha3_224 => {
                type $d = ::sha3::Sha3_224;
                $body
            }
            Hash::Sha3_256 => {
                type $d = ::sha3::Sha3_256;
                $body
            }
            Hash::Sha3_384 => {
                type $d = ::sha3::Sha3_384;
                $body
            }
            Hash::Sha3_512 => {
                type $d = ::sha3::Sha3_512;
                $body
            }
            _ => $otherwise,
        }
    };
}

/// The SHA-1 and SHA-2 digests, which OAEP supports in every combination.
macro_rules! with_sha {
    ($hash:expr, $d:ident => $body:expr, $otherwise:expr) => {
        match $hash {
            Hash::Sha1 => {
                type $d = ::sha1::Sha1;
                $body
            }
            Hash::Sha224 => {
                type $d = ::sha2::Sha224;
                $body
            }
            Hash::Sha256 => {
                type $d = ::sha2::Sha256;
                $body
            }
            Hash::Sha384 => {
                type $d = ::sha2::Sha384;
                $body
            }
            Hash::Sha512 => {
                type $d = ::sha2::Sha512;
                $body
            }
            Hash::Sha512_224 => {
                type $d = ::sha2::Sha512_224;
                $body
            }
            Hash::Sha512_256 => {
                type $d = ::sha2::Sha512_256;
                $body
            }
            _ => $otherwise,
        }
    };
}

fn oaep_encrypt<D, M>(
    key: &RsaPublicKey,
    rng: &mut Source<'_>,
    msg: &[u8],
    label: &[u8],
) -> Result<Vec<u8>, Error>
where
    D: Digest + FixedOutputReset,
    M: Digest + FixedOutputReset,
{
    let padding = Oaep::<D, M>::new_with_mgf_hash_and_label(label.to_vec());
    key.encrypt(rng, padding, msg).map_err(from_crate)
}

fn oaep_decrypt<D, M>(
    key: &RsaPrivateKey,
    ciphertext: &[u8],
    label: &[u8],
) -> Result<Vec<u8>, Error>
where
    D: Digest + FixedOutputReset,
    M: Digest + FixedOutputReset,
{
    let padding = Oaep::<D, M>::new_with_mgf_hash_and_label(label.to_vec());
    key.decrypt_blinded(&mut Source::System, padding, ciphertext)
        .map_err(from_crate)
}

fn pss_sign<D>(
    key: &RsaPrivateKey,
    rng: &mut Source<'_>,
    salt: usize,
    hashed: &[u8],
) -> Result<Vec<u8>, Error>
where
    D: Digest + FixedOutputReset,
{
    key.sign_with_rng(rng, Pss::<D>::new_with_salt(salt), hashed)
        .map_err(from_crate)
}

fn pss_verify<D>(
    key: &RsaPublicKey,
    salt: Option<usize>,
    hashed: &[u8],
    sig: &[u8],
) -> Result<(), Error>
where
    D: Digest + FixedOutputReset,
{
    let mut padding = Pss::<D>::new();
    padding.salt_len = salt;
    key.verify(padding, hashed, sig).map_err(from_crate)
}

/// Go's `rsa.GenerateKey`: generates a random RSA private key of the given
/// bit size from the system random source.
pub fn generate_key(bits: usize) -> Result<PrivateKey, Error> {
    generate_key_in(None, bits)
}

/// [`generate_key`] with a caller's reader. Like Go 1.26+, the reader is
/// ignored by default and the system source is used, unless
/// `GODEBUG=cryptocustomrand=1`.
pub fn generate_key_with_rng(rng: &mut dyn io::Read, bits: usize) -> Result<PrivateKey, Error> {
    generate_key_in(Some(rng), bits)
}

fn generate_key_in(rand: Option<&mut dyn io::Read>, bits: usize) -> Result<PrivateKey, Error> {
    check_key_size(bits)?;
    let mut source = Source::custom(rand);
    let key = RsaPrivateKey::new(&mut source, bits).map_err(from_crate);
    source.finish().map_err(io_error)?;
    Ok(PrivateKey::from_crate(key?))
}

fn io_error(error: io::Error) -> Error {
    Error::other(error.to_string())
}

/// Go's `rsa.GenerateMultiPrimeKey` (deprecated). Only two-prime keys can be
/// generated: the reviewed `rsa` crate does not expose multi-prime key
/// generation, and doing it here would be a first-party key-generation
/// implementation (docs/adr/0003).
pub fn generate_multi_prime_key(nprimes: usize, bits: usize) -> Result<PrivateKey, Error> {
    generate_multi_prime_key_in(None, nprimes, bits)
}

/// [`generate_multi_prime_key`] with a caller's reader, which is ignored like
/// [`generate_key_with_rng`] does.
pub fn generate_multi_prime_key_with_rng(
    rng: &mut dyn io::Read,
    nprimes: usize,
    bits: usize,
) -> Result<PrivateKey, Error> {
    generate_multi_prime_key_in(Some(rng), nprimes, bits)
}

fn generate_multi_prime_key_in(
    rand: Option<&mut dyn io::Read>,
    nprimes: usize,
    bits: usize,
) -> Result<PrivateKey, Error> {
    if nprimes == 2 {
        return generate_key_in(rand, bits);
    }
    if nprimes < 2 {
        return Err(Error::other(
            "crypto/rsa: GenerateMultiPrimeKey: nprimes must be >= 2",
        ));
    }
    Err(Error::other(
        "crypto/rsa: GenerateMultiPrimeKey: the reviewed rsa crate cannot generate multi-prime keys",
    ))
}

/// Go's `rsa.EncryptPKCS1v15` (deprecated): encrypts with PKCS #1 v1.5 padding.
pub fn encrypt_pkcs1v15(public_key: &PublicKey, msg: &[u8]) -> Result<Vec<u8>, Error> {
    encrypt_pkcs1v15_in(None, public_key, msg)
}

/// [`encrypt_pkcs1v15`] with a caller's reader, ignored by default like Go
/// 1.26+ (used with `GODEBUG=cryptocustomrand=1`).
pub fn encrypt_pkcs1v15_with_rng(
    rng: &mut dyn io::Read,
    public_key: &PublicKey,
    msg: &[u8],
) -> Result<Vec<u8>, Error> {
    encrypt_pkcs1v15_in(Some(rng), public_key, msg)
}

fn encrypt_pkcs1v15_in(
    rand: Option<&mut dyn io::Read>,
    public_key: &PublicKey,
    msg: &[u8],
) -> Result<Vec<u8>, Error> {
    check_public_key_size(public_key)?;
    if msg.len() + 11 > public_key.size() {
        return Err(Error::MessageTooLong);
    }
    let key = public_key.to_crate()?;
    let mut source = Source::custom(rand);
    let result = key
        .encrypt(&mut source, Pkcs1v15Encrypt, msg)
        .map_err(from_crate);
    source.finish().map_err(io_error)?;
    result
}

/// Go's `rsa.DecryptPKCS1v15` (deprecated): decrypts with PKCS #1 v1.5 padding.
/// Go ignores the reader it is given, so there is no `rng` parameter.
pub fn decrypt_pkcs1v15(private_key: &PrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    check_public_key_size(&private_key.public_key)?;
    if private_key.public_key.size() < 11 {
        return Err(Error::Decryption);
    }
    let key = private_key.crate_key()?;
    key.decrypt_blinded(&mut Source::System, Pkcs1v15Encrypt, ciphertext)
        .map_err(|error| match from_crate(error) {
            Error::Other(_) | Error::MessageTooLong | Error::Verification => Error::Decryption,
            other => other,
        })
}

/// Go's `rsa.DecryptPKCS1v15SessionKey` (deprecated): decrypts with PKCS #1
/// v1.5 padding and, when the plaintext has the length of `key`, copies it
/// into `key`; otherwise `key` is left unchanged and no error is reported.
///
/// Unlike Go this does not run in constant time (see the module notes).
pub fn decrypt_pkcs1v15_session_key(
    private_key: &PrivateKey,
    ciphertext: &[u8],
    key: &mut [u8],
) -> Result<(), Error> {
    check_public_key_size(&private_key.public_key)?;
    let k = private_key.public_key.size();
    if k < key.len() + 3 + 8 {
        return Err(Error::Decryption);
    }
    // Go reports ciphertexts the RSA operation itself rejects.
    if ciphertext.len() != k || Int::from_be_bytes(ciphertext) >= private_key.public_key.n {
        return Err(Error::Decryption);
    }
    if let Ok(plaintext) = decrypt_pkcs1v15(private_key, ciphertext) {
        if plaintext.len() == key.len() {
            key.copy_from_slice(&plaintext);
        }
    }
    Ok(())
}

/// Go's `rsa.EncryptOAEP`: encrypts with RSA-OAEP, using `hash` for the label
/// and MGF1.
pub fn encrypt_oaep(
    hash: Hash,
    public_key: &PublicKey,
    msg: &[u8],
    label: &[u8],
) -> Result<Vec<u8>, Error> {
    encrypt_oaep_inner(hash, hash, None, public_key, msg, label)
}

/// [`encrypt_oaep`] reading the OAEP seed from `rng`, which Go always
/// honours here.
pub fn encrypt_oaep_with_rng(
    rng: &mut dyn io::Read,
    hash: Hash,
    public_key: &PublicKey,
    msg: &[u8],
    label: &[u8],
) -> Result<Vec<u8>, Error> {
    encrypt_oaep_inner(hash, hash, Some(rng), public_key, msg, label)
}

/// Go's `rsa.EncryptOAEPWithOptions`: encrypts with RSA-OAEP using separate
/// hashes for the label and MGF1.
pub fn encrypt_oaep_with_options(
    public_key: &PublicKey,
    msg: &[u8],
    opts: &OAEPOptions,
) -> Result<Vec<u8>, Error> {
    encrypt_oaep_with_options_in(None, public_key, msg, opts)
}

/// [`encrypt_oaep_with_options`] reading the OAEP seed from `rng`, which Go
/// always honours here.
pub fn encrypt_oaep_with_options_and_rng(
    rng: &mut dyn io::Read,
    public_key: &PublicKey,
    msg: &[u8],
    opts: &OAEPOptions,
) -> Result<Vec<u8>, Error> {
    encrypt_oaep_with_options_in(Some(rng), public_key, msg, opts)
}

fn encrypt_oaep_with_options_in(
    rand: Option<&mut dyn io::Read>,
    public_key: &PublicKey,
    msg: &[u8],
    opts: &OAEPOptions,
) -> Result<Vec<u8>, Error> {
    let hash = opts.hash.ok_or_else(|| unavailable_hash(None))?;
    if !hash.available() {
        return Err(unavailable_hash(Some(hash)));
    }
    if let Some(mgf) = opts.mgf_hash {
        if !mgf.available() {
            return Err(unavailable_hash(Some(mgf)));
        }
    }
    encrypt_oaep_inner(
        hash,
        opts.mgf_hash.unwrap_or(hash),
        rand,
        public_key,
        msg,
        &opts.label,
    )
}

fn encrypt_oaep_inner(
    hash: Hash,
    mgf_hash: Hash,
    rand: Option<&mut dyn io::Read>,
    public_key: &PublicKey,
    msg: &[u8],
    label: &[u8],
) -> Result<Vec<u8>, Error> {
    check_public_key_size(public_key)?;
    oaep_check_pair(hash, mgf_hash)?;
    let key = public_key.to_crate()?;
    let mut source = Source::explicit(rand);
    let result = oaep_run(
        hash,
        mgf_hash,
        &mut OaepOp::Encrypt(&key, &mut source, msg),
        label,
    );
    source.finish().map_err(io_error)?;
    result
}

enum OaepOp<'a, 'b> {
    Encrypt(&'a RsaPublicKey, &'a mut Source<'b>, &'a [u8]),
    Decrypt(&'a RsaPrivateKey, &'a [u8]),
}

/// Checks that the `(hash, mgf)` pair is one the generic dispatch covers.
fn oaep_check_pair(hash: Hash, mgf: Hash) -> Result<(), Error> {
    let sha = |h: Hash| {
        matches!(
            h,
            Hash::Sha1
                | Hash::Sha224
                | Hash::Sha256
                | Hash::Sha384
                | Hash::Sha512
                | Hash::Sha512_224
                | Hash::Sha512_256
        )
    };
    let any = |h: Hash| {
        sha(h)
            || matches!(
                h,
                Hash::Md5 | Hash::Sha3_224 | Hash::Sha3_256 | Hash::Sha3_384 | Hash::Sha3_512
            )
    };
    if (sha(hash) && sha(mgf)) || (hash == mgf && any(hash)) {
        Ok(())
    } else if !any(hash) {
        Err(unsupported_hash(hash))
    } else if !any(mgf) {
        Err(unsupported_hash(mgf))
    } else {
        Err(Error::other(format!(
            "crypto/rsa: OAEP with {hash} and {mgf} for MGF1 is not supported by this build"
        )))
    }
}

fn oaep_run(
    hash: Hash,
    mgf: Hash,
    op: &mut OaepOp<'_, '_>,
    label: &[u8],
) -> Result<Vec<u8>, Error> {
    macro_rules! run {
        ($d:ty, $m:ty) => {
            match op {
                OaepOp::Encrypt(key, rng, msg) => oaep_encrypt::<$d, $m>(key, rng, msg, label),
                OaepOp::Decrypt(key, ct) => oaep_decrypt::<$d, $m>(key, ct, label),
            }
        };
    }
    if hash == mgf {
        return with_hash!(hash, D => run!(D, D), Err(unsupported_hash(hash)));
    }
    with_sha!(
        hash,
        D => with_sha!(mgf, M => run!(D, M), Err(unsupported_hash(mgf))),
        Err(unsupported_hash(hash))
    )
}

/// Go's `rsa.DecryptOAEP`: decrypts RSA-OAEP, using `hash` for the label and
/// MGF1. Go ignores the reader it is given, so there is no `rng` parameter.
pub fn decrypt_oaep(
    hash: Hash,
    private_key: &PrivateKey,
    ciphertext: &[u8],
    label: &[u8],
) -> Result<Vec<u8>, Error> {
    decrypt_oaep_inner(hash, hash, private_key, ciphertext, label)
}

fn decrypt_oaep_inner(
    hash: Hash,
    mgf_hash: Hash,
    private_key: &PrivateKey,
    ciphertext: &[u8],
    label: &[u8],
) -> Result<Vec<u8>, Error> {
    check_public_key_size(&private_key.public_key)?;
    oaep_check_pair(hash, mgf_hash)?;
    let key = private_key.crate_key()?;
    oaep_run(
        hash,
        mgf_hash,
        &mut OaepOp::Decrypt(&key, ciphertext),
        label,
    )
}

/// The PKCS #1 v1.5 signature scheme for `hash` (`None` for an unprefixed
/// signature of the data as given).
fn pkcs1v15_scheme(hash: Option<Hash>) -> Result<Pkcs1v15Sign, Error> {
    match hash {
        None => Ok(Pkcs1v15Sign::new_unprefixed()),
        Some(Hash::Md5Sha1) => Ok(Pkcs1v15Sign {
            hash_len: Some(36),
            prefix: Box::new([]),
        }),
        Some(hash) => with_hash!(
            hash,
            D => Ok(Pkcs1v15Sign::new::<D>()),
            Err(Error::other("crypto/rsa: unsupported hash function"))
        ),
    }
}

/// Go's `rsa.SignPKCS1v15`: calculates the signature of `hashed` using
/// RSASSA-PKCS1-V1_5-SIGN. `hash` is `None` for Go's zero `crypto.Hash`
/// (sign the data as given, without a DigestInfo prefix). Go ignores the
/// reader it is given, so there is no `rng` parameter.
pub fn sign_pkcs1v15(
    private_key: &PrivateKey,
    hash: Option<Hash>,
    hashed: &[u8],
) -> Result<Vec<u8>, Error> {
    if let Some(hash) = hash {
        if hashed.len() != hash.size() {
            return Err(Error::other("crypto/rsa: input must be hashed message"));
        }
    }
    check_public_key_size(&private_key.public_key)?;
    let scheme = pkcs1v15_scheme(hash)?;
    let key = private_key.crate_key()?;
    key.sign_with_rng(&mut Source::System, scheme, hashed)
        .map_err(from_crate)
}

/// Go's `rsa.VerifyPKCS1v15`: verifies an RSA PKCS #1 v1.5 signature.
pub fn verify_pkcs1v15(
    public_key: &PublicKey,
    hash: Option<Hash>,
    hashed: &[u8],
    sig: &[u8],
) -> Result<(), Error> {
    if let Some(hash) = hash {
        if hashed.len() != hash.size() {
            return Err(Error::other("crypto/rsa: input must be hashed message"));
        }
    }
    check_public_key_size(public_key)?;
    // Go rejects a signature that is not exactly the modulus size; the rsa
    // crate would left-pad a short one (e.g. with a leading zero byte dropped).
    if sig.len() != public_key.size() {
        return Err(Error::Verification);
    }
    let scheme = pkcs1v15_scheme(hash)?;
    let key = public_key.to_crate()?;
    key.verify(scheme, hashed, sig)
        .map_err(|error| match from_crate(error) {
            Error::Other(_) => Error::Verification,
            other => other,
        })
}

/// Go's `rsa.SignPSS`: calculates the signature of `digest` using RSASSA-PSS.
/// A `hash` of `opts` takes precedence over the `hash` argument. The salt
/// comes from the system random source.
pub fn sign_pss(
    private_key: &PrivateKey,
    hash: Hash,
    digest: &[u8],
    opts: Option<&PSSOptions>,
) -> Result<Vec<u8>, Error> {
    sign_pss_in(None, private_key, hash, digest, opts)
}

/// [`sign_pss`] reading the salt from `rng`, which Go always honours here.
pub fn sign_pss_with_rng(
    rng: &mut dyn io::Read,
    private_key: &PrivateKey,
    hash: Hash,
    digest: &[u8],
    opts: Option<&PSSOptions>,
) -> Result<Vec<u8>, Error> {
    sign_pss_in(Some(rng), private_key, hash, digest, opts)
}

fn sign_pss_in(
    rand: Option<&mut dyn io::Read>,
    private_key: &PrivateKey,
    hash: Hash,
    digest: &[u8],
    opts: Option<&PSSOptions>,
) -> Result<Vec<u8>, Error> {
    check_public_key_size(&private_key.public_key)?;
    let hash = opts.and_then(|opts| opts.hash).unwrap_or(hash);
    if !hash.available() {
        return Err(unavailable_hash(Some(hash)));
    }
    let key = private_key.crate_key()?;
    let hash_size = hash.size();
    let salt = match opts.map_or(PSS_SALT_LENGTH_AUTO, |opts| opts.salt_length) {
        PSS_SALT_LENGTH_AUTO => {
            // Go's rsa.PSSMaxSaltLength: emLen - 2 - hLen.
            let em_len = (private_key.public_key.n.bit_len() - 1).div_ceil(8);
            match em_len.checked_sub(2 + hash_size) {
                Some(salt) => salt,
                None => return Err(Error::MessageTooLong),
            }
        }
        PSS_SALT_LENGTH_EQUALS_HASH => hash_size,
        length if length <= 0 => return Err(Error::other("crypto/rsa: invalid PSS salt length")),
        length => length as usize,
    };
    let mut source = Source::explicit(rand);
    let result = with_hash!(
        hash,
        D => pss_sign::<D>(&key, &mut source, salt, digest),
        Err(unsupported_hash(hash))
    );
    source.finish().map_err(io_error)?;
    result
}

/// Go's `rsa.VerifyPSS`: verifies a PSS signature.
pub fn verify_pss(
    public_key: &PublicKey,
    hash: Hash,
    digest: &[u8],
    sig: &[u8],
    opts: Option<&PSSOptions>,
) -> Result<(), Error> {
    check_public_key_size(public_key)?;
    if !hash.available() {
        return Err(unavailable_hash(Some(hash)));
    }
    // As for PKCS #1 v1.5, Go requires a signature of exactly the modulus size.
    if sig.len() != public_key.size() {
        return Err(Error::Verification);
    }
    let key = public_key.to_crate()?;
    let salt = match opts.map_or(PSS_SALT_LENGTH_AUTO, |opts| opts.salt_length) {
        PSS_SALT_LENGTH_AUTO => None,
        PSS_SALT_LENGTH_EQUALS_HASH => Some(hash.size()),
        length if length < 0 => Some(0),
        length => Some(length as usize),
    };
    with_hash!(
        hash,
        D => pss_verify::<D>(&key, salt, digest, sig),
        Err(unsupported_hash(hash))
    )
}

// Go makes a hash available only to a program that imports its package
// (`Hash.Available`). PSS and OAEP with options need it; PKCS #1 v1.5 names
// the hash by its DigestInfo prefix and plain OAEP is handed the hash, so
// neither does. The expected results are a Go 1.27 program's that imports
// crypto/rsa and, for the second test, crypto/sha512. Go's crypto/rsa also
// imports crypto/sha3 through its FIPS module, and the `rsa` feature enables
// `sha3` to match, so SHA3-256 is available here.
#[cfg(test)]
mod hash_availability_tests {
    use super::*;

    fn key() -> PrivateKey {
        generate_key(1024).unwrap()
    }

    #[cfg(not(any(
        feature = "md5",
        feature = "sha1",
        feature = "sha256",
        feature = "sha512"
    )))]
    #[test]
    fn rsa_alone_has_no_hash_for_pss_or_oaep_options() {
        let key = key();
        let digest = [1u8; 32];
        // Go's crypto/rsa imports crypto/sha3 (through fips140hash), so SHA-3
        // is available to PSS with crypto/rsa alone; the SHA-2 family is not.
        let sig = sign_pss(&key, Hash::Sha3_256, &digest, None).unwrap();
        verify_pss(&key.public_key, Hash::Sha3_256, &digest, &sig, None).unwrap();
        for hash in [Hash::Sha256] {
            let unavailable = format!("crypto/rsa: requested hash function unavailable: {hash}");
            assert_eq!(
                sign_pss(&key, hash, &digest, None).unwrap_err().to_string(),
                unavailable
            );
            assert_eq!(
                verify_pss(&key.public_key, hash, &digest, &[0; 128], None)
                    .unwrap_err()
                    .to_string(),
                unavailable
            );
            let opts = OAEPOptions {
                hash: Some(hash),
                ..OAEPOptions::default()
            };
            assert_eq!(
                encrypt_oaep_with_options(&key.public_key, b"m", &opts)
                    .unwrap_err()
                    .to_string(),
                unavailable
            );
            assert_eq!(
                key.decrypt(&[0; 128], Some(&opts)).unwrap_err().to_string(),
                format!("rsa: requested hash function unavailable: {hash}")
            );
        }
        assert_eq!(
            sign_pss(&key, Hash::Sha384, &[1; 48], None)
                .unwrap_err()
                .to_string(),
            "crypto/rsa: requested hash function unavailable: SHA-384"
        );
        assert!(!Hash::Sha256.available());
    }

    #[test]
    fn pkcs1v15_and_plain_oaep_work_without_the_hash_package() {
        let key = key();
        for hash in [
            Hash::Md5,
            Hash::Sha1,
            Hash::Sha256,
            Hash::Sha384,
            Hash::Sha3_256,
        ] {
            let digest = vec![7u8; hash.size()];
            let sig = sign_pkcs1v15(&key, Some(hash), &digest).unwrap();
            assert_eq!(
                verify_pkcs1v15(&key.public_key, Some(hash), &digest, &sig),
                Ok(())
            );
        }
        let ciphertext = encrypt_oaep(Hash::Sha256, &key.public_key, b"message", b"label").unwrap();
        assert_eq!(
            decrypt_oaep(Hash::Sha256, &key, &ciphertext, b"label").unwrap(),
            b"message"
        );
    }

    #[cfg(all(feature = "sha512", not(feature = "sha256")))]
    #[test]
    fn the_sha512_package_makes_sha384_available_to_pss_and_oaep() {
        let key = key();
        let digest = [3u8; 48];
        let sig = sign_pss(&key, Hash::Sha384, &digest, None).unwrap();
        assert_eq!(
            verify_pss(&key.public_key, Hash::Sha384, &digest, &sig, None),
            Ok(())
        );
        let opts = OAEPOptions {
            hash: Some(Hash::Sha384),
            ..OAEPOptions::default()
        };
        let ciphertext = encrypt_oaep_with_options(&key.public_key, b"m", &opts).unwrap();
        assert_eq!(key.decrypt(&ciphertext, Some(&opts)).unwrap(), b"m");
        assert_eq!(
            sign_pss(&key, Hash::Sha256, &[1; 32], None)
                .unwrap_err()
                .to_string(),
            "crypto/rsa: requested hash function unavailable: SHA-256"
        );
    }
}
