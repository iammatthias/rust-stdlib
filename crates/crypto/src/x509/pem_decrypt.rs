//! Legacy PEM encryption (RFC 1423), Go's `pem_decrypt.go`.
//!
//! Only the header inspection is provided. `DecryptPEMBlock` and
//! `EncryptPEMBlock` derive the cipher key with an iterated MD5 construction
//! (OpenSSL's `EVP_BytesToKey`). ADR 0003 forbids first-party cryptographic
//! constructions even over reviewed primitives, so those two functions are
//! recorded as deviations instead of being written here.

use std::fmt;

use super::pem::Block;

/// Go's `x509.PEMCipher`: the encryption algorithm of a legacy encrypted PEM
/// block.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PEMCipher(pub i32);

impl PEMCipher {
    pub const DES: PEMCipher = PEMCipher(1);
    pub const TRIPLE_DES: PEMCipher = PEMCipher(2);
    pub const AES128: PEMCipher = PEMCipher(3);
    pub const AES192: PEMCipher = PEMCipher(4);
    pub const AES256: PEMCipher = PEMCipher(5);
}

impl fmt::Display for PEMCipher {
    /// The `DEK-Info` algorithm name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => f.write_str("DES-CBC"),
            2 => f.write_str("DES-EDE3-CBC"),
            3 => f.write_str("AES-128-CBC"),
            4 => f.write_str("AES-192-CBC"),
            5 => f.write_str("AES-256-CBC"),
            n => write!(f, "PEMCipher({n})"),
        }
    }
}

/// Go's `IsEncryptedPEMBlock`: reports whether the PEM block is password
/// encrypted according to RFC 1423.
///
/// Deprecated in Go: legacy PEM encryption as specified in RFC 1423 is
/// insecure by design.
pub fn is_encrypted_pem_block(b: &Block) -> bool {
    b.headers.contains_key("DEK-Info")
}
