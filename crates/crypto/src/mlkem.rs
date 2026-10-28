//! ML-KEM (FIPS 203), compatible with Go's `crypto/mlkem`.
//!
//! The lattice arithmetic, sampling and hashing come from the reviewed
//! RustCrypto `ml-kem` crate; this module adds Go's seed-based key handling,
//! sizes, error messages and the `crypto.Encapsulator`/`crypto.Decapsulator`
//! implementations. Decapsulation keys are the 64-byte seeds, as in Go.

use std::fmt;

use ml_kem::{
    Ciphertext, DecapsulationKey, EncapsulationKey, KeyExport, MlKem1024, MlKem768, Seed,
};

use crate::sysrng::Source;
use crate::{BoxError, Decapsulator, Encapsulator};

/// Size of the shared key in bytes.
pub const SHARED_KEY_SIZE: usize = 32;
/// Size of a decapsulation key (the seed) in bytes.
pub const SEED_SIZE: usize = 64;
/// Size of an ML-KEM-768 ciphertext in bytes.
pub const CIPHERTEXT_SIZE_768: usize = 1088;
/// Size of an ML-KEM-768 encapsulation key in bytes.
pub const ENCAPSULATION_KEY_SIZE_768: usize = 1184;
/// Size of an ML-KEM-1024 ciphertext in bytes.
pub const CIPHERTEXT_SIZE_1024: usize = 1568;
/// Size of an ML-KEM-1024 encapsulation key in bytes.
pub const ENCAPSULATION_KEY_SIZE_1024: usize = 1568;

/// An error with one of Go's `crypto/mlkem` messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

fn error(message: &str) -> Error {
    Error(message.to_string())
}

macro_rules! parameter_set {
    ($dk:ident, $ek:ident, $param:ty, $ek_size:expr, $ct_size:expr, $generate:ident, $new_dk:ident, $new_ek:ident) => {
        /// An ML-KEM decapsulation key, held as its 64-byte seed.
        #[derive(Clone, PartialEq)]
        pub struct $dk {
            key: DecapsulationKey<$param>,
            seed: [u8; SEED_SIZE],
        }

        impl fmt::Debug for $dk {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($dk)).finish_non_exhaustive()
            }
        }

        /// An ML-KEM encapsulation key.
        #[derive(Clone, Debug, PartialEq)]
        pub struct $ek {
            key: EncapsulationKey<$param>,
        }

        /// Generates a new decapsulation key from the system's random source.
        pub fn $generate() -> Result<$dk, Error> {
            let mut seed = [0u8; SEED_SIZE];
            Source::System.fill(&mut seed);
            $new_dk(&seed)
        }

        /// Expands a decapsulation key from a 64-byte seed.
        pub fn $new_dk(seed: &[u8]) -> Result<$dk, Error> {
            let seed: [u8; SEED_SIZE] = seed
                .try_into()
                .map_err(|_| error("mlkem: invalid seed length"))?;
            Ok($dk {
                key: DecapsulationKey::<$param>::from_seed(Seed::from(seed)),
                seed,
            })
        }

        /// Parses an encapsulation key, checking its encoding.
        pub fn $new_ek(bytes: &[u8]) -> Result<$ek, Error> {
            if bytes.len() != $ek_size {
                return Err(error("mlkem: invalid encapsulation key length"));
            }
            let key = ml_kem::Key::<EncapsulationKey<$param>>::try_from(bytes)
                .map_err(|_| error("mlkem: invalid encapsulation key length"))?;
            EncapsulationKey::<$param>::new(&key)
                .map(|key| $ek { key })
                .map_err(|_| error("mlkem: invalid polynomial encoding"))
        }

        impl $dk {
            /// The 64-byte seed.
            pub fn bytes(&self) -> Vec<u8> {
                self.seed.to_vec()
            }

            /// Recovers the shared key from a ciphertext. Invalid but
            /// well-formed ciphertexts yield a pseudorandom key (implicit
            /// rejection); only a wrong length is an error.
            pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
                if ciphertext.len() != $ct_size {
                    return Err(error("mlkem: invalid ciphertext length"));
                }
                let ciphertext = Ciphertext::<$param>::try_from(ciphertext)
                    .map_err(|_| error("mlkem: invalid ciphertext length"))?;
                Ok(ml_kem::Decapsulate::decapsulate(&self.key, &ciphertext).to_vec())
            }

            /// The matching encapsulation key.
            pub fn encapsulation_key(&self) -> $ek {
                $ek {
                    key: self.key.encapsulation_key().clone(),
                }
            }

            /// Go's `DecapsulationKey.Encapsulator`.
            pub fn encapsulator(&self) -> Box<dyn Encapsulator> {
                Box::new(self.encapsulation_key())
            }
        }

        impl $ek {
            /// The encoded key.
            pub fn bytes(&self) -> Vec<u8> {
                self.key.to_bytes().to_vec()
            }

            /// Returns a fresh shared key and the ciphertext that encapsulates
            /// it, in that order.
            pub fn encapsulate(&self) -> (Vec<u8>, Vec<u8>) {
                let (ciphertext, shared) =
                    ml_kem::Encapsulate::encapsulate_with_rng(&self.key, &mut Source::System);
                (shared.to_vec(), ciphertext.to_vec())
            }

            fn encapsulate_with(&self, random: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
                let (ciphertext, shared) = self.key.encapsulate_deterministic(&(*random).into());
                (shared.to_vec(), ciphertext.to_vec())
            }
        }

        impl Encapsulator for $ek {
            fn bytes(&self) -> Vec<u8> {
                $ek::bytes(self)
            }

            fn encapsulate(&self) -> (Vec<u8>, Vec<u8>) {
                $ek::encapsulate(self)
            }
        }

        impl Decapsulator for $dk {
            fn encapsulator(&self) -> Box<dyn Encapsulator> {
                $dk::encapsulator(self)
            }

            fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, BoxError> {
                $dk::decapsulate(self, ciphertext).map_err(Into::into)
            }
        }
    };
}

parameter_set!(
    DecapsulationKey768,
    EncapsulationKey768,
    MlKem768,
    ENCAPSULATION_KEY_SIZE_768,
    CIPHERTEXT_SIZE_768,
    generate_key768,
    new_decapsulation_key768,
    new_encapsulation_key768
);

parameter_set!(
    DecapsulationKey1024,
    EncapsulationKey1024,
    MlKem1024,
    ENCAPSULATION_KEY_SIZE_1024,
    CIPHERTEXT_SIZE_1024,
    generate_key1024,
    new_decapsulation_key1024,
    new_encapsulation_key1024
);

/// Go's `crypto/mlkem/mlkemtest`: derandomized encapsulation for known-answer
/// tests.
pub mod mlkemtest {
    use super::{error, EncapsulationKey1024, EncapsulationKey768, Error};

    /// Go's `mlkemtest.Encapsulate768`: encapsulates with the given 32 bytes
    /// of randomness. Returns the shared key and the ciphertext.
    pub fn encapsulate768(
        key: &EncapsulationKey768,
        random: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let random: [u8; 32] = random
            .try_into()
            .map_err(|_| error("mlkemtest: Encapsulate768: random must be 32 bytes"))?;
        Ok(key.encapsulate_with(&random))
    }

    /// Go's `mlkemtest.Encapsulate1024`: encapsulates with the given 32 bytes
    /// of randomness. Returns the shared key and the ciphertext.
    pub fn encapsulate1024(
        key: &EncapsulationKey1024,
        random: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let random: [u8; 32] = random
            .try_into()
            .map_err(|_| error("mlkemtest: Encapsulate1024: random must be 32 bytes"))?;
        Ok(key.encapsulate_with(&random))
    }
}
