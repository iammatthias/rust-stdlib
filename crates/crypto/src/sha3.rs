//! SHA-3, SHAKE and cSHAKE, compatible with Go's `crypto/sha3`.
//!
//! [`Sha3`] is the fixed-output hash and implements Go's `hash.Hash` surface
//! with `marshal_binary` in Go's `sha\x08` format. [`Shake`] is the
//! extendable-output function: write input, then read any amount of output
//! through [`std::io::Read`] or [`Shake::read`].
//!
//! Go marshals SHAKE and cSHAKE state, but the reviewed `cshake` crate keeps
//! its sponge state private and offers no serialization, so those methods are
//! a recorded deviation (docs/api/crypto_sha3.json) and are not provided.

use std::io;

use ::cshake::digest::{ExtendableOutput, Update, XofReader};
use ::cshake::{CShake128, CShake128Reader, CShake256, CShake256Reader};

use crate::engine::{digest_type, Fixed, Messages};
use crate::Hash;

static MESSAGES: Messages = Messages {
    identifier: "sha3: invalid hash state identifier",
    size: "sha3: invalid hash state",
    state: "sha3: invalid hash state",
};

digest_type!(
    /// A running SHA-3 computation (Go's `sha3.SHA3`).
    Sha3
);

impl Default for Sha3 {
    /// Go's zero `SHA3` behaves as SHA3-256.
    fn default() -> Self {
        new256()
    }
}

/// Returns a new SHA3-224 computation.
pub fn new224() -> Sha3 {
    Sha3 {
        inner: Fixed::new(Hash::Sha3_224, &MESSAGES),
    }
}

/// Returns a new SHA3-256 computation.
pub fn new256() -> Sha3 {
    Sha3 {
        inner: Fixed::new(Hash::Sha3_256, &MESSAGES),
    }
}

/// Returns a new SHA3-384 computation.
pub fn new384() -> Sha3 {
    Sha3 {
        inner: Fixed::new(Hash::Sha3_384, &MESSAGES),
    }
}

/// Returns a new SHA3-512 computation.
pub fn new512() -> Sha3 {
    Sha3 {
        inner: Fixed::new(Hash::Sha3_512, &MESSAGES),
    }
}

fn sum_with<const N: usize>(mut digest: Sha3, data: &[u8]) -> [u8; N] {
    digest.update(data);
    let mut out = Vec::with_capacity(N);
    digest.sum(&mut out);
    out.try_into()
        .expect("digest length matches the requested array")
}

/// Returns the SHA3-224 hash of the data.
pub fn sum224(data: &[u8]) -> [u8; 28] {
    sum_with(new224(), data)
}

/// Returns the SHA3-256 hash of the data.
pub fn sum256(data: &[u8]) -> [u8; 32] {
    sum_with(new256(), data)
}

/// Returns the SHA3-384 hash of the data.
pub fn sum384(data: &[u8]) -> [u8; 48] {
    sum_with(new384(), data)
}

/// Returns the SHA3-512 hash of the data.
pub fn sum512(data: &[u8]) -> [u8; 64] {
    sum_with(new512(), data)
}

#[derive(Clone)]
enum Sponge {
    Absorb128(CShake128),
    Absorb256(CShake256),
    Squeeze128(CShake128Reader),
    Squeeze256(CShake256Reader),
}

/// A running SHAKE128, SHAKE256, cSHAKE128 or cSHAKE256 computation (Go's
/// `sha3.SHAKE`).
#[derive(Clone)]
pub struct Shake {
    sponge: Sponge,
    name: Vec<u8>,
    customization: Vec<u8>,
}

impl std::fmt::Debug for Shake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shake")
            .field("block_size", &self.block_size())
            .finish_non_exhaustive()
    }
}

fn fresh(rate: usize, name: &[u8], customization: &[u8]) -> Sponge {
    if rate == 168 {
        Sponge::Absorb128(CShake128::new_with_function_name(name, customization))
    } else {
        Sponge::Absorb256(CShake256::new_with_function_name(name, customization))
    }
}

/// Returns a new SHAKE128 computation.
pub fn shake128() -> Shake {
    cshake128(&[], &[])
}

/// Returns a new SHAKE256 computation.
pub fn shake256() -> Shake {
    cshake256(&[], &[])
}

/// Returns a new cSHAKE128 computation with the function name `name` and the
/// customization string. With both empty it is SHAKE128, as in Go.
pub fn cshake128(name: &[u8], customization: &[u8]) -> Shake {
    Shake {
        sponge: fresh(168, name, customization),
        name: name.to_vec(),
        customization: customization.to_vec(),
    }
}

/// Returns a new cSHAKE256 computation; see [`cshake128`].
pub fn cshake256(name: &[u8], customization: &[u8]) -> Shake {
    Shake {
        sponge: fresh(136, name, customization),
        name: name.to_vec(),
        customization: customization.to_vec(),
    }
}

/// Returns `length` bytes of SHAKE128 output for the data.
pub fn sum_shake128(data: &[u8], length: usize) -> Vec<u8> {
    let mut shake = shake128();
    shake.update(data).expect("a fresh SHAKE accepts input");
    shake.output(length)
}

/// Returns `length` bytes of SHAKE256 output for the data.
pub fn sum_shake256(data: &[u8], length: usize) -> Vec<u8> {
    let mut shake = shake256();
    shake.update(data).expect("a fresh SHAKE accepts input");
    shake.output(length)
}

impl Shake {
    /// Absorbs more input. Fails after output has been read, where Go panics
    /// with `sha3: Write after Read`.
    pub fn update(&mut self, bytes: &[u8]) -> io::Result<()> {
        match &mut self.sponge {
            Sponge::Absorb128(core) => Update::update(core, bytes),
            Sponge::Absorb256(core) => Update::update(core, bytes),
            _ => return Err(io::Error::other("sha3: Write after Read")),
        }
        Ok(())
    }

    /// Reads output bytes, switching the sponge to squeezing. It fills `out`
    /// completely and never fails, like Go's `SHAKE.Read`.
    pub fn read(&mut self, out: &mut [u8]) -> usize {
        let sponge =
            match std::mem::replace(&mut self.sponge, Sponge::Absorb128(CShake128::default())) {
                Sponge::Absorb128(core) => Sponge::Squeeze128(core.finalize_xof()),
                Sponge::Absorb256(core) => Sponge::Squeeze256(core.finalize_xof()),
                squeezing => squeezing,
            };
        self.sponge = sponge;
        match &mut self.sponge {
            Sponge::Squeeze128(reader) => reader.read(out),
            Sponge::Squeeze256(reader) => reader.read(out),
            _ => unreachable!("the sponge was just switched to squeezing"),
        }
        out.len()
    }

    fn output(&mut self, length: usize) -> Vec<u8> {
        let mut out = vec![0; length];
        self.read(&mut out);
        out
    }

    /// Returns the sponge rate in bytes: 168 for SHAKE128, 136 for SHAKE256.
    pub fn block_size(&self) -> usize {
        match self.sponge {
            Sponge::Absorb128(_) | Sponge::Squeeze128(_) => 168,
            Sponge::Absorb256(_) | Sponge::Squeeze256(_) => 136,
        }
    }

    /// Returns to the freshly constructed state, including the function name
    /// and customization string given to the constructor.
    pub fn reset(&mut self) {
        self.sponge = fresh(self.block_size(), &self.name, &self.customization);
    }
}

impl io::Write for Shake {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl io::Read for Shake {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Ok(Shake::read(self, buf))
    }
}
