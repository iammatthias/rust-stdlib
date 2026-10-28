//! The enumerations of `crypto/x509`.
//!
//! Go declares these as `int` types with named constants, and any `int` is a
//! valid value (`SignatureAlgorithm(99).String()` is `"99"`), so each is a
//! newtype with associated constants.

use std::fmt;

use super::asn1::{ObjectIdentifier, RawValue};
use super::oid::Oid;
use crate::Hash;

/// Go's `x509.SignatureAlgorithm`.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SignatureAlgorithm(pub i32);

impl SignatureAlgorithm {
    pub const UNKNOWN_SIGNATURE_ALGORITHM: SignatureAlgorithm = SignatureAlgorithm(0);
    /// Unsupported.
    pub const MD2_WITH_RSA: SignatureAlgorithm = SignatureAlgorithm(1);
    /// Only supported for signing, not verification.
    pub const MD5_WITH_RSA: SignatureAlgorithm = SignatureAlgorithm(2);
    /// Only supported for signing, and verification of CRLs, CSRs, and OCSP
    /// responses.
    pub const SHA1_WITH_RSA: SignatureAlgorithm = SignatureAlgorithm(3);
    pub const SHA256_WITH_RSA: SignatureAlgorithm = SignatureAlgorithm(4);
    pub const SHA384_WITH_RSA: SignatureAlgorithm = SignatureAlgorithm(5);
    pub const SHA512_WITH_RSA: SignatureAlgorithm = SignatureAlgorithm(6);
    /// Unsupported.
    pub const DSA_WITH_SHA1: SignatureAlgorithm = SignatureAlgorithm(7);
    /// Unsupported.
    pub const DSA_WITH_SHA256: SignatureAlgorithm = SignatureAlgorithm(8);
    /// Only supported for signing, and verification of CRLs, CSRs, and OCSP
    /// responses.
    pub const ECDSA_WITH_SHA1: SignatureAlgorithm = SignatureAlgorithm(9);
    pub const ECDSA_WITH_SHA256: SignatureAlgorithm = SignatureAlgorithm(10);
    pub const ECDSA_WITH_SHA384: SignatureAlgorithm = SignatureAlgorithm(11);
    pub const ECDSA_WITH_SHA512: SignatureAlgorithm = SignatureAlgorithm(12);
    pub const SHA256_WITH_RSAPSS: SignatureAlgorithm = SignatureAlgorithm(13);
    pub const SHA384_WITH_RSAPSS: SignatureAlgorithm = SignatureAlgorithm(14);
    pub const SHA512_WITH_RSAPSS: SignatureAlgorithm = SignatureAlgorithm(15);
    pub const PURE_ED25519: SignatureAlgorithm = SignatureAlgorithm(16);
    pub const MLDSA44: SignatureAlgorithm = SignatureAlgorithm(17);
    pub const MLDSA65: SignatureAlgorithm = SignatureAlgorithm(18);
    pub const MLDSA87: SignatureAlgorithm = SignatureAlgorithm(19);

    pub(crate) fn details(self) -> Option<&'static SignatureAlgorithmDetails> {
        SIGNATURE_ALGORITHM_DETAILS.iter().find(|d| d.algo == self)
    }

    pub(crate) fn is_rsa_pss(self) -> bool {
        self.details().is_some_and(|d| d.is_rsa_pss)
    }

    /// The hash function of the algorithm, `None` for Go's `crypto.Hash(0)`.
    pub(crate) fn hash_func(self) -> Option<Hash> {
        self.details().and_then(|d| d.hash)
    }
}

impl fmt::Display for SignatureAlgorithm {
    /// Go's `SignatureAlgorithm.String`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.details() {
            Some(d) => f.write_str(d.name),
            None => write!(f, "{}", self.0),
        }
    }
}

/// Go's `x509.PublicKeyAlgorithm`.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PublicKeyAlgorithm(pub i32);

impl PublicKeyAlgorithm {
    pub const UNKNOWN_PUBLIC_KEY_ALGORITHM: PublicKeyAlgorithm = PublicKeyAlgorithm(0);
    pub const RSA: PublicKeyAlgorithm = PublicKeyAlgorithm(1);
    /// Only supported for parsing.
    pub const DSA: PublicKeyAlgorithm = PublicKeyAlgorithm(2);
    pub const ECDSA: PublicKeyAlgorithm = PublicKeyAlgorithm(3);
    pub const ED25519: PublicKeyAlgorithm = PublicKeyAlgorithm(4);
    pub const MLDSA: PublicKeyAlgorithm = PublicKeyAlgorithm(5);
}

impl fmt::Display for PublicKeyAlgorithm {
    /// Go's `PublicKeyAlgorithm.String`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => f.write_str("RSA"),
            2 => f.write_str("DSA"),
            3 => f.write_str("ECDSA"),
            4 => f.write_str("Ed25519"),
            5 => f.write_str("ML-DSA"),
            n => write!(f, "{n}"),
        }
    }
}

/// Go's `x509.KeyUsage`: a bitmap of the `KeyUsage*` constants.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyUsage(pub i32);

impl KeyUsage {
    pub const DIGITAL_SIGNATURE: KeyUsage = KeyUsage(1);
    pub const CONTENT_COMMITMENT: KeyUsage = KeyUsage(2);
    pub const KEY_ENCIPHERMENT: KeyUsage = KeyUsage(4);
    pub const DATA_ENCIPHERMENT: KeyUsage = KeyUsage(8);
    pub const KEY_AGREEMENT: KeyUsage = KeyUsage(16);
    pub const CERT_SIGN: KeyUsage = KeyUsage(32);
    pub const CRL_SIGN: KeyUsage = KeyUsage(64);
    pub const ENCIPHER_ONLY: KeyUsage = KeyUsage(128);
    pub const DECIPHER_ONLY: KeyUsage = KeyUsage(256);
}

impl std::ops::BitAnd for KeyUsage {
    type Output = KeyUsage;
    fn bitand(self, rhs: KeyUsage) -> KeyUsage {
        KeyUsage(self.0 & rhs.0)
    }
}

impl std::ops::BitOr for KeyUsage {
    type Output = KeyUsage;
    fn bitor(self, rhs: KeyUsage) -> KeyUsage {
        KeyUsage(self.0 | rhs.0)
    }
}

impl fmt::Display for KeyUsage {
    /// Go's `KeyUsage.String`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self.0 {
            1 => "digitalSignature",
            2 => "contentCommitment",
            4 => "keyEncipherment",
            8 => "dataEncipherment",
            16 => "keyAgreement",
            32 => "keyCertSign",
            64 => "cRLSign",
            128 => "encipherOnly",
            256 => "decipherOnly",
            n => return write!(f, "KeyUsage({n})"),
        };
        f.write_str(name)
    }
}

/// Go's `x509.ExtKeyUsage`: an extended set of actions that are valid for a
/// key.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExtKeyUsage(pub i32);

impl ExtKeyUsage {
    pub const ANY: ExtKeyUsage = ExtKeyUsage(0);
    pub const SERVER_AUTH: ExtKeyUsage = ExtKeyUsage(1);
    pub const CLIENT_AUTH: ExtKeyUsage = ExtKeyUsage(2);
    pub const CODE_SIGNING: ExtKeyUsage = ExtKeyUsage(3);
    pub const EMAIL_PROTECTION: ExtKeyUsage = ExtKeyUsage(4);
    pub const IPSEC_END_SYSTEM: ExtKeyUsage = ExtKeyUsage(5);
    pub const IPSEC_TUNNEL: ExtKeyUsage = ExtKeyUsage(6);
    pub const IPSEC_USER: ExtKeyUsage = ExtKeyUsage(7);
    pub const TIME_STAMPING: ExtKeyUsage = ExtKeyUsage(8);
    pub const OCSP_SIGNING: ExtKeyUsage = ExtKeyUsage(9);
    pub const MICROSOFT_SERVER_GATED_CRYPTO: ExtKeyUsage = ExtKeyUsage(10);
    pub const NETSCAPE_SERVER_GATED_CRYPTO: ExtKeyUsage = ExtKeyUsage(11);
    pub const MICROSOFT_COMMERCIAL_CODE_SIGNING: ExtKeyUsage = ExtKeyUsage(12);
    pub const MICROSOFT_KERNEL_CODE_SIGNING: ExtKeyUsage = ExtKeyUsage(13);

    /// Go's `ExtKeyUsage.OID`. Go panics for a value that is not one of the
    /// constants; here that is `None`.
    pub fn oid(self) -> Option<Oid> {
        let arcs = ext_key_usage_arcs(self)?;
        super::oid::oid_from_asn1_oid(&ObjectIdentifier(arcs.to_vec())).ok()
    }
}

impl fmt::Display for ExtKeyUsage {
    /// Go's `ExtKeyUsage.String`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const NAMES: [&str; 14] = [
            "anyExtendedKeyUsage",
            "serverAuth",
            "clientAuth",
            "codeSigning",
            "emailProtection",
            "ipsecEndSystem",
            "ipsecTunnel",
            "ipsecUser",
            "timeStamping",
            "OCSPSigning",
            "msSGC",
            "nsSGC",
            "msCodeCom",
            "msKernelCode",
        ];
        match usize::try_from(self.0).ok().and_then(|i| NAMES.get(i)) {
            Some(name) => f.write_str(name),
            None => write!(f, "ExtKeyUsage({})", self.0),
        }
    }
}

/// Go's `x509.InvalidReason`: why a certificate is invalid.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InvalidReason(pub i32);

impl InvalidReason {
    /// A certificate is signed by another which isn't marked as a CA.
    pub const NOT_AUTHORIZED_TO_SIGN: InvalidReason = InvalidReason(0);
    /// A certificate has expired, based on the time in the `VerifyOptions`.
    pub const EXPIRED: InvalidReason = InvalidReason(1);
    /// A name constraint doesn't permit a name in the leaf certificate.
    pub const CA_NOT_AUTHORIZED_FOR_THIS_NAME: InvalidReason = InvalidReason(2);
    /// A path length constraint is violated.
    pub const TOO_MANY_INTERMEDIATES: InvalidReason = InvalidReason(3);
    /// The key usage indicates a different purpose.
    pub const INCOMPATIBLE_USAGE: InvalidReason = InvalidReason(4);
    /// The subject name of a parent does not match the issuer in the child.
    pub const NAME_MISMATCH: InvalidReason = InvalidReason(5);
    /// A legacy error that is no longer returned.
    pub const NAME_CONSTRAINTS_WITHOUT_SANS: InvalidReason = InvalidReason(6);
    /// A CA has permitted name constraints but the leaf has a name of an
    /// unsupported or unconstrained type.
    pub const UNCONSTRAINED_NAME: InvalidReason = InvalidReason(7);
    /// Checking name constraints needed too many comparisons.
    pub const TOO_MANY_CONSTRAINTS: InvalidReason = InvalidReason(8);
    /// A CA does not permit a requested extended key usage.
    pub const CA_NOT_AUTHORIZED_FOR_EXT_KEY_USAGE: InvalidReason = InvalidReason(9);
    /// There are no valid chains to return.
    pub const NO_VALID_CHAINS: InvalidReason = InvalidReason(10);
}

pub(crate) struct SignatureAlgorithmDetails {
    pub algo: SignatureAlgorithm,
    pub name: &'static str,
    pub oid: &'static [i64],
    pub params: ParamsKind,
    pub pub_key_algo: PublicKeyAlgorithm,
    pub hash: Option<Hash>,
    pub is_rsa_pss: bool,
}

/// The AlgorithmIdentifier parameters of a signature algorithm.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParamsKind {
    Null,
    Empty,
    PssSha256,
    PssSha384,
    PssSha512,
}

impl ParamsKind {
    pub fn raw_value(self) -> RawValue {
        match self {
            ParamsKind::Null => RawValue::null(),
            ParamsKind::Empty => RawValue::default(),
            ParamsKind::PssSha256 => RawValue::from_full_bytes(PSS_PARAMETERS_SHA256.to_vec()),
            ParamsKind::PssSha384 => RawValue::from_full_bytes(PSS_PARAMETERS_SHA384.to_vec()),
            ParamsKind::PssSha512 => RawValue::from_full_bytes(PSS_PARAMETERS_SHA512.to_vec()),
        }
    }
}

/// DER encoded RSA PSS parameters for SHA-256, SHA-384 and SHA-512 (RFC 3447,
/// Appendix A.2.3): the hash with NULL parameters, the default MGF1 with the
/// same hash, a salt length equal to the hash length and the default trailer.
pub(crate) const PSS_PARAMETERS_SHA256: [u8; 54] = [
    48, 52, 160, 15, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1, 5, 0, 161, 28, 48, 26, 6, 9,
    42, 134, 72, 134, 247, 13, 1, 1, 8, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1, 5, 0, 162,
    3, 2, 1, 32,
];
pub(crate) const PSS_PARAMETERS_SHA384: [u8; 54] = [
    48, 52, 160, 15, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 2, 5, 0, 161, 28, 48, 26, 6, 9,
    42, 134, 72, 134, 247, 13, 1, 1, 8, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 2, 5, 0, 162,
    3, 2, 1, 48,
];
pub(crate) const PSS_PARAMETERS_SHA512: [u8; 54] = [
    48, 52, 160, 15, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 3, 5, 0, 161, 28, 48, 26, 6, 9,
    42, 134, 72, 134, 247, 13, 1, 1, 8, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 3, 5, 0, 162,
    3, 2, 1, 64,
];

pub(crate) const OID_SIGNATURE_MD5_WITH_RSA: [i64; 7] = [1, 2, 840, 113549, 1, 1, 4];
pub(crate) const OID_SIGNATURE_SHA1_WITH_RSA: [i64; 7] = [1, 2, 840, 113549, 1, 1, 5];
pub(crate) const OID_SIGNATURE_SHA256_WITH_RSA: [i64; 7] = [1, 2, 840, 113549, 1, 1, 11];
pub(crate) const OID_SIGNATURE_SHA384_WITH_RSA: [i64; 7] = [1, 2, 840, 113549, 1, 1, 12];
pub(crate) const OID_SIGNATURE_SHA512_WITH_RSA: [i64; 7] = [1, 2, 840, 113549, 1, 1, 13];
pub(crate) const OID_SIGNATURE_RSA_PSS: [i64; 7] = [1, 2, 840, 113549, 1, 1, 10];
pub(crate) const OID_SIGNATURE_DSA_WITH_SHA1: [i64; 6] = [1, 2, 840, 10040, 4, 3];
pub(crate) const OID_SIGNATURE_DSA_WITH_SHA256: [i64; 9] = [2, 16, 840, 1, 101, 3, 4, 3, 2];
pub(crate) const OID_SIGNATURE_ECDSA_WITH_SHA1: [i64; 6] = [1, 2, 840, 10045, 4, 1];
pub(crate) const OID_SIGNATURE_ECDSA_WITH_SHA256: [i64; 7] = [1, 2, 840, 10045, 4, 3, 2];
pub(crate) const OID_SIGNATURE_ECDSA_WITH_SHA384: [i64; 7] = [1, 2, 840, 10045, 4, 3, 3];
pub(crate) const OID_SIGNATURE_ECDSA_WITH_SHA512: [i64; 7] = [1, 2, 840, 10045, 4, 3, 4];
pub(crate) const OID_SIGNATURE_ED25519: [i64; 4] = [1, 3, 101, 112];
pub(crate) const OID_ISO_SIGNATURE_SHA1_WITH_RSA: [i64; 6] = [1, 3, 14, 3, 2, 29];
pub(crate) const OID_SHA256: [i64; 9] = [2, 16, 840, 1, 101, 3, 4, 2, 1];
pub(crate) const OID_SHA384: [i64; 9] = [2, 16, 840, 1, 101, 3, 4, 2, 2];
pub(crate) const OID_SHA512: [i64; 9] = [2, 16, 840, 1, 101, 3, 4, 2, 3];
pub(crate) const OID_MGF1: [i64; 7] = [1, 2, 840, 113549, 1, 1, 8];

pub(crate) const OID_PUBLIC_KEY_RSA: [i64; 7] = [1, 2, 840, 113549, 1, 1, 1];
pub(crate) const OID_PUBLIC_KEY_DSA: [i64; 6] = [1, 2, 840, 10040, 4, 1];
pub(crate) const OID_PUBLIC_KEY_ECDSA: [i64; 6] = [1, 2, 840, 10045, 2, 1];
pub(crate) const OID_PUBLIC_KEY_X25519: [i64; 4] = [1, 3, 101, 110];
pub(crate) const OID_PUBLIC_KEY_ED25519: [i64; 4] = [1, 3, 101, 112];
pub(crate) const OID_PUBLIC_KEY_MLDSA44: [i64; 9] = [2, 16, 840, 1, 101, 3, 4, 3, 17];
pub(crate) const OID_PUBLIC_KEY_MLDSA65: [i64; 9] = [2, 16, 840, 1, 101, 3, 4, 3, 18];
pub(crate) const OID_PUBLIC_KEY_MLDSA87: [i64; 9] = [2, 16, 840, 1, 101, 3, 4, 3, 19];

pub(crate) const OID_NAMED_CURVE_P224: [i64; 5] = [1, 3, 132, 0, 33];
pub(crate) const OID_NAMED_CURVE_P256: [i64; 7] = [1, 2, 840, 10045, 3, 1, 7];
pub(crate) const OID_NAMED_CURVE_P384: [i64; 5] = [1, 3, 132, 0, 34];
pub(crate) const OID_NAMED_CURVE_P521: [i64; 5] = [1, 3, 132, 0, 35];

pub(crate) static SIGNATURE_ALGORITHM_DETAILS: &[SignatureAlgorithmDetails] = &[
    SignatureAlgorithmDetails {
        algo: SignatureAlgorithm::MD5_WITH_RSA,
        name: "MD5-RSA",
        oid: &OID_SIGNATURE_MD5_WITH_RSA,
        params: ParamsKind::Null,
        pub_key_algo: PublicKeyAlgorithm::RSA,
        hash: Some(Hash::Md5),
        is_rsa_pss: false,
    },
    SignatureAlgorithmDetails {
        algo: SignatureAlgorithm::SHA1_WITH_RSA,
        name: "SHA1-RSA",
        oid: &OID_SIGNATURE_SHA1_WITH_RSA,
        params: ParamsKind::Null,
        pub_key_algo: PublicKeyAlgorithm::RSA,
        hash: Some(Hash::Sha1),
        is_rsa_pss: false,
    },
    SignatureAlgorithmDetails {
        algo: SignatureAlgorithm::SHA1_WITH_RSA,
        name: "SHA1-RSA",
        oid: &OID_ISO_SIGNATURE_SHA1_WITH_RSA,
        params: ParamsKind::Null,
        pub_key_algo: PublicKeyAlgorithm::RSA,
        hash: Some(Hash::Sha1),
        is_rsa_pss: false,
    },
    SignatureAlgorithmDetails {
        algo: SignatureAlgorithm::SHA256_WITH_RSA,
        name: "SHA256-RSA",
        oid: &OID_SIGNATURE_SHA256_WITH_RSA,
        params: ParamsKind::Null,
        pub_key_algo: PublicKeyAlgorithm::RSA,
        hash: Some(Hash::Sha256),
        is_rsa_pss: false,
    },
    SignatureAlgorithmDetails {
        algo: SignatureAlgorithm::SHA384_WITH_RSA,
        name: "SHA384-RSA",
        oid: &OID_SIGNATURE_SHA384_WITH_RSA,
        params: ParamsKind::Null,
        pub_key_algo: PublicKeyAlgorithm::RSA,
        hash: Some(Hash::Sha384),
        is_rsa_pss: false,
    },
    SignatureAlgorithmDetails {
        algo: SignatureAlgorithm::SHA512_WITH_RSA,
        name: "SHA512-RSA",
        oid: &OID_SIGNATURE_SHA512_WITH_RSA,
        params: ParamsKind::Null,
        pub_key_algo: PublicKeyAlgorithm::RSA,
        hash: Some(Hash::Sha512),
        is_rsa_pss: false,
    },
    SignatureAlgorithmDetails {
        algo: SignatureAlgorithm::SHA256_WITH_RSAPSS,
        name: "SHA256-RSAPSS",
        oid: &OID_SIGNATURE_RSA_PSS,
        params: ParamsKind::PssSha256,
        pub_key_algo: PublicKeyAlgorithm::RSA,
        hash: Some(Hash::Sha256),
        is_rsa_pss: true,
    },
    SignatureAlgorithmDetails {
        algo: SignatureAlgorithm::SHA384_WITH_RSAPSS,
        name: "SHA384-RSAPSS",
        oid: &OID_SIGNATURE_RSA_PSS,
        params: ParamsKind::PssSha384,
        pub_key_algo: PublicKeyAlgorithm::RSA,
        hash: Some(Hash::Sha384),
        is_rsa_pss: true,
    },
    SignatureAlgorithmDetails {
        algo: SignatureAlgorithm::SHA512_WITH_RSAPSS,
        name: "SHA512-RSAPSS",
        oid: &OID_SIGNATURE_RSA_PSS,
        params: ParamsKind::PssSha512,
        pub_key_algo: PublicKeyAlgorithm::RSA,
        hash: Some(Hash::Sha512),
        is_rsa_pss: true,
    },
    SignatureAlgorithmDetails {
        algo: SignatureAlgorithm::DSA_WITH_SHA1,
        name: "DSA-SHA1",
        oid: &OID_SIGNATURE_DSA_WITH_SHA1,
        params: ParamsKind::Empty,
        pub_key_algo: PublicKeyAlgorithm::DSA,
        hash: Some(Hash::Sha1),
        is_rsa_pss: false,
    },
    SignatureAlgorithmDetails {
        algo: SignatureAlgorithm::DSA_WITH_SHA256,
        name: "DSA-SHA256",
        oid: &OID_SIGNATURE_DSA_WITH_SHA256,
        params: ParamsKind::Empty,
        pub_key_algo: PublicKeyAlgorithm::DSA,
        hash: Some(Hash::Sha256),
        is_rsa_pss: false,
    },
    SignatureAlgorithmDetails {
        algo: SignatureAlgorithm::ECDSA_WITH_SHA1,
        name: "ECDSA-SHA1",
        oid: &OID_SIGNATURE_ECDSA_WITH_SHA1,
        params: ParamsKind::Empty,
        pub_key_algo: PublicKeyAlgorithm::ECDSA,
        hash: Some(Hash::Sha1),
        is_rsa_pss: false,
    },
    SignatureAlgorithmDetails {
        algo: SignatureAlgorithm::ECDSA_WITH_SHA256,
        name: "ECDSA-SHA256",
        oid: &OID_SIGNATURE_ECDSA_WITH_SHA256,
        params: ParamsKind::Empty,
        pub_key_algo: PublicKeyAlgorithm::ECDSA,
        hash: Some(Hash::Sha256),
        is_rsa_pss: false,
    },
    SignatureAlgorithmDetails {
        algo: SignatureAlgorithm::ECDSA_WITH_SHA384,
        name: "ECDSA-SHA384",
        oid: &OID_SIGNATURE_ECDSA_WITH_SHA384,
        params: ParamsKind::Empty,
        pub_key_algo: PublicKeyAlgorithm::ECDSA,
        hash: Some(Hash::Sha384),
        is_rsa_pss: false,
    },
    SignatureAlgorithmDetails {
        algo: SignatureAlgorithm::ECDSA_WITH_SHA512,
        name: "ECDSA-SHA512",
        oid: &OID_SIGNATURE_ECDSA_WITH_SHA512,
        params: ParamsKind::Empty,
        pub_key_algo: PublicKeyAlgorithm::ECDSA,
        hash: Some(Hash::Sha512),
        is_rsa_pss: false,
    },
    SignatureAlgorithmDetails {
        algo: SignatureAlgorithm::PURE_ED25519,
        name: "Ed25519",
        oid: &OID_SIGNATURE_ED25519,
        params: ParamsKind::Empty,
        pub_key_algo: PublicKeyAlgorithm::ED25519,
        hash: None,
        is_rsa_pss: false,
    },
    SignatureAlgorithmDetails {
        algo: SignatureAlgorithm::MLDSA44,
        name: "ML-DSA-44",
        oid: &OID_PUBLIC_KEY_MLDSA44,
        params: ParamsKind::Empty,
        pub_key_algo: PublicKeyAlgorithm::MLDSA,
        hash: None,
        is_rsa_pss: false,
    },
    SignatureAlgorithmDetails {
        algo: SignatureAlgorithm::MLDSA65,
        name: "ML-DSA-65",
        oid: &OID_PUBLIC_KEY_MLDSA65,
        params: ParamsKind::Empty,
        pub_key_algo: PublicKeyAlgorithm::MLDSA,
        hash: None,
        is_rsa_pss: false,
    },
    SignatureAlgorithmDetails {
        algo: SignatureAlgorithm::MLDSA87,
        name: "ML-DSA-87",
        oid: &OID_PUBLIC_KEY_MLDSA87,
        params: ParamsKind::Empty,
        pub_key_algo: PublicKeyAlgorithm::MLDSA,
        hash: None,
        is_rsa_pss: false,
    },
];

const EXT_KEY_USAGE_OIDS: [(ExtKeyUsage, &[i64]); 14] = [
    (ExtKeyUsage::ANY, &[2, 5, 29, 37, 0]),
    (ExtKeyUsage::SERVER_AUTH, &[1, 3, 6, 1, 5, 5, 7, 3, 1]),
    (ExtKeyUsage::CLIENT_AUTH, &[1, 3, 6, 1, 5, 5, 7, 3, 2]),
    (ExtKeyUsage::CODE_SIGNING, &[1, 3, 6, 1, 5, 5, 7, 3, 3]),
    (ExtKeyUsage::EMAIL_PROTECTION, &[1, 3, 6, 1, 5, 5, 7, 3, 4]),
    (ExtKeyUsage::IPSEC_END_SYSTEM, &[1, 3, 6, 1, 5, 5, 7, 3, 5]),
    (ExtKeyUsage::IPSEC_TUNNEL, &[1, 3, 6, 1, 5, 5, 7, 3, 6]),
    (ExtKeyUsage::IPSEC_USER, &[1, 3, 6, 1, 5, 5, 7, 3, 7]),
    (ExtKeyUsage::TIME_STAMPING, &[1, 3, 6, 1, 5, 5, 7, 3, 8]),
    (ExtKeyUsage::OCSP_SIGNING, &[1, 3, 6, 1, 5, 5, 7, 3, 9]),
    (
        ExtKeyUsage::MICROSOFT_SERVER_GATED_CRYPTO,
        &[1, 3, 6, 1, 4, 1, 311, 10, 3, 3],
    ),
    (
        ExtKeyUsage::NETSCAPE_SERVER_GATED_CRYPTO,
        &[2, 16, 840, 1, 113730, 4, 1],
    ),
    (
        ExtKeyUsage::MICROSOFT_COMMERCIAL_CODE_SIGNING,
        &[1, 3, 6, 1, 4, 1, 311, 2, 1, 22],
    ),
    (
        ExtKeyUsage::MICROSOFT_KERNEL_CODE_SIGNING,
        &[1, 3, 6, 1, 4, 1, 311, 61, 1, 1],
    ),
];

pub(crate) fn ext_key_usage_from_oid(oid: &ObjectIdentifier) -> Option<ExtKeyUsage> {
    EXT_KEY_USAGE_OIDS
        .iter()
        .find(|(_, arcs)| oid.0 == *arcs)
        .map(|(eku, _)| *eku)
}

pub(crate) fn ext_key_usage_arcs(eku: ExtKeyUsage) -> Option<&'static [i64]> {
    EXT_KEY_USAGE_OIDS
        .iter()
        .find(|(e, _)| *e == eku)
        .map(|(_, arcs)| *arcs)
}

pub(crate) fn oid_from_ext_key_usage(eku: ExtKeyUsage) -> Option<ObjectIdentifier> {
    ext_key_usage_arcs(eku).map(|a| ObjectIdentifier(a.to_vec()))
}
