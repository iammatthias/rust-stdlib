//! Go's `crypto/x509`: parsing and generating certificates, certificate
//! requests and revocation lists, encoded keys, and a certificate verifier
//! with a chain builder.
//!
//! The package follows Go's pure implementation (`parser.go`, `x509.go`,
//! `verify.go`, `constraints.go`, `cert_pool.go`). No cryptographic primitive
//! is implemented here: signatures are verified and produced through the
//! reviewed key types of this crate, the DER layer is plain encoding, and the
//! chain builder is X.509 path logic (docs/adr/0003, "x509 increment").
//!
//! Go's `encoding/asn1`, `net`, `net/url`, `time`, `math/big` and
//! `encoding/pem` types that appear in the API are stand-ins defined in this
//! module: [`ObjectIdentifier`], [`pkix::BitString`], [`pkix::RawValue`],
//! [`Ip`]/[`IpNet`], [`url::Url`], [`Time`], [`BigInt`] and [`pem::Block`].

mod asn1;
mod asn1_time;
mod asn1_unmarshal;
mod cert;
mod constraints;
mod create;
mod error;
mod keys;
mod net;
mod oid;
mod parser;
#[cfg(test)]
mod parser_tests;
pub mod pem;
mod pem_decrypt;
pub mod pkix;
#[cfg(test)]
mod policy_tests;
mod pool;
mod time;
mod types;
pub mod url;
mod verify;

pub use asn1::{BigInt, BitString, ObjectIdentifier, RawValue};
pub use cert::{
    Certificate, CertificateRequest, PolicyMapping, RevocationList, RevocationListEntry,
};
pub use create::{
    create_certificate, create_certificate_request, create_certificate_request_with_rng,
    create_certificate_with_rng, create_revocation_list, create_revocation_list_with_rng,
};
pub use error::{
    CertificateInvalidError, ConstraintViolationError, Error, HostnameError,
    InsecureAlgorithmError, SystemRootsError, UnhandledCriticalExtension, UnknownAuthorityError,
};
pub use keys::{
    marshal_ec_private_key, marshal_pkcs1_private_key, marshal_pkcs1_public_key,
    marshal_pkcs8_private_key, marshal_pkix_public_key, parse_ec_private_key,
    parse_pkcs1_private_key, parse_pkcs1_public_key, parse_pkcs8_private_key,
    parse_pkix_public_key, PrivateKey, PublicKey,
};
pub use net::{parse_ip, Ip, IpNet};
pub use oid::{oid_from_asn1_oid, oid_from_ints, parse_oid, Oid};
pub use parser::{
    parse_certificate, parse_certificate_request, parse_certificates, parse_crl, parse_der_crl,
    parse_revocation_list,
};
pub use pem_decrypt::{is_encrypted_pem_block, PEMCipher};
pub use pool::{set_fallback_roots, system_cert_pool, CertPool, Constraint};
pub use time::Time;
pub use types::{ExtKeyUsage, InvalidReason, KeyUsage, PublicKeyAlgorithm, SignatureAlgorithm};
pub use verify::VerifyOptions;

/// Go's `ErrUnsupportedAlgorithm`: results from attempting to perform an
/// operation that involves algorithms that are not currently implemented.
pub const ERR_UNSUPPORTED_ALGORITHM: Error = Error::UnsupportedAlgorithm;

/// Go's `IncorrectPasswordError`: returned when an incorrect password is
/// detected while decrypting a legacy PEM block.
pub const INCORRECT_PASSWORD_ERROR: Error = Error::IncorrectPassword;
