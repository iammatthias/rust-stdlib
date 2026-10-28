//! The certificate, certificate request and revocation list types.

use super::asn1::{BigInt, ObjectIdentifier};
use super::keys::PublicKey;
use super::net::{Ip, IpNet};
use super::oid::Oid;
use super::pkix::{self, Extension};
use super::time::Time;
use super::types::*;
use super::url::Url;
use super::{ConstraintViolationError, Error, InsecureAlgorithmError};
use crate::{ecdsa, ed25519, mldsa, rsa, Hash};

/// Go's `x509.Certificate`: an X.509 certificate.
#[derive(Clone, Debug, Default)]
pub struct Certificate {
    /// Complete ASN.1 DER content (certificate, signature algorithm and
    /// signature).
    pub raw: Vec<u8>,
    /// Certificate part of the raw ASN.1 DER content.
    pub raw_tbs_certificate: Vec<u8>,
    /// DER encoded SubjectPublicKeyInfo.
    pub raw_subject_public_key_info: Vec<u8>,
    /// DER encoded Subject.
    pub raw_subject: Vec<u8>,
    /// DER encoded Issuer.
    pub raw_issuer: Vec<u8>,
    /// DER encoded AlgorithmIdentifier.
    pub raw_signature_algorithm: Vec<u8>,

    pub signature: Vec<u8>,
    pub signature_algorithm: SignatureAlgorithm,

    pub public_key_algorithm: PublicKeyAlgorithm,
    /// Go's `PublicKey any`; `None` is nil.
    pub public_key: Option<PublicKey>,

    pub version: i64,
    /// Go's `*big.Int`; `None` is nil.
    pub serial_number: Option<BigInt>,
    pub issuer: pkix::Name,
    pub subject: pkix::Name,
    /// Validity bounds.
    pub not_before: Time,
    pub not_after: Time,
    pub key_usage: KeyUsage,

    /// Raw X.509 extensions. When parsing certificates, this can be used to
    /// extract non-critical extensions that are not parsed by this package.
    /// When marshaling certificates, the field is ignored, see
    /// `extra_extensions`.
    pub extensions: Vec<Extension>,

    /// Extensions to be copied, raw, into any marshaled certificates. Values
    /// override any extensions that would otherwise be produced based on the
    /// other fields. The field is not populated when parsing certificates, see
    /// `extensions`.
    pub extra_extensions: Vec<Extension>,

    /// Extension IDs that were not (fully) processed when parsing. Verify will
    /// fail if this is non-empty.
    pub unhandled_critical_extensions: Vec<ObjectIdentifier>,

    /// Sequence of extended key usages.
    pub ext_key_usage: Vec<ExtKeyUsage>,
    /// Encountered extended key usages unknown to this package.
    pub unknown_ext_key_usage: Vec<ObjectIdentifier>,

    /// Whether `is_ca`, `max_path_len` and `max_path_len_zero` are valid.
    pub basic_constraints_valid: bool,
    pub is_ca: bool,

    /// The presence and value of the BasicConstraints' "pathLenConstraint".
    ///
    /// When parsing a certificate, a positive non-zero value means that the
    /// field was specified, -1 means it was unset, and `max_path_len_zero`
    /// being true means that the field was explicitly set to zero. The case of
    /// 0 with `max_path_len_zero` false should be treated equivalent to -1
    /// (unset).
    ///
    /// When generating a certificate, an unset pathLenConstraint can be
    /// requested with either -1 or using the zero value for both fields.
    pub max_path_len: i64,
    /// Indicates that `basic_constraints_valid` and `max_path_len == 0`
    /// should be interpreted as an actual maximum path length of zero.
    pub max_path_len_zero: bool,

    pub subject_key_id: Vec<u8>,
    pub authority_key_id: Vec<u8>,

    /// RFC 5280, 4.2.2.1 (Authority Information Access).
    pub ocsp_server: Vec<String>,
    pub issuing_certificate_url: Vec<String>,

    /// Subject Alternate Name values. (These values may not be valid if
    /// invalid values were contained within a parsed certificate.)
    pub dns_names: Vec<String>,
    pub email_addresses: Vec<String>,
    pub ip_addresses: Vec<Ip>,
    pub uris: Vec<Url>,

    /// Name constraints. If true, the constraints are marked critical.
    pub permitted_dns_domains_critical: bool,
    pub permitted_dns_domains: Vec<String>,
    pub excluded_dns_domains: Vec<String>,
    pub permitted_ip_ranges: Vec<IpNet>,
    pub excluded_ip_ranges: Vec<IpNet>,
    pub permitted_email_addresses: Vec<String>,
    pub excluded_email_addresses: Vec<String>,
    pub permitted_uri_domains: Vec<String>,
    pub excluded_uri_domains: Vec<String>,

    /// CRL Distribution Points.
    pub crl_distribution_points: Vec<String>,

    /// Policy identifiers whose components are limited to 31 bits. A policy
    /// that an [`ObjectIdentifier`] cannot represent is only in `policies`.
    pub policy_identifiers: Vec<ObjectIdentifier>,

    /// All policy identifiers included in the certificate.
    pub policies: Vec<Oid>,

    /// The presence and value of the inhibitAnyPolicy extension: the number of
    /// additional certificates in the path after this one that may use the
    /// anyPolicy policy OID to indicate a match with any other policy.
    ///
    /// When parsing a certificate, a positive non-zero value means that the
    /// field was specified, -1 means it was unset, and
    /// `inhibit_any_policy_zero` being true means explicitly zero.
    pub inhibit_any_policy: i64,
    pub inhibit_any_policy_zero: bool,

    /// The inhibitPolicyMapping field of the policyConstraints extension.
    pub inhibit_policy_mapping: i64,
    pub inhibit_policy_mapping_zero: bool,

    /// The requireExplicitPolicy field of the policyConstraints extension.
    pub require_explicit_policy: i64,
    pub require_explicit_policy_zero: bool,

    /// The policy mappings included in the certificate.
    pub policy_mappings: Vec<PolicyMapping>,
}

/// Go's `x509.PolicyMapping`: an entry in the policyMappings extension.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PolicyMapping {
    /// A policy OID the issuing certificate considers equivalent to
    /// `subject_domain_policy` in the subject certificate.
    pub issuer_domain_policy: Oid,
    /// A policy OID the issuing certificate considers equivalent to
    /// `issuer_domain_policy`.
    pub subject_domain_policy: Oid,
}

/// Go's `x509.CertificateRequest`: a PKCS #10 certificate signature request.
#[derive(Clone, Debug, Default)]
pub struct CertificateRequest {
    /// Complete ASN.1 DER content (CSR, signature algorithm and signature).
    pub raw: Vec<u8>,
    /// Certificate request info part of the raw ASN.1 DER content.
    pub raw_tbs_certificate_request: Vec<u8>,
    /// DER encoded SubjectPublicKeyInfo.
    pub raw_subject_public_key_info: Vec<u8>,
    /// DER encoded Subject.
    pub raw_subject: Vec<u8>,
    /// DER encoded AlgorithmIdentifier.
    pub raw_signature_algorithm: Vec<u8>,

    pub version: i64,
    pub signature: Vec<u8>,
    pub signature_algorithm: SignatureAlgorithm,

    pub public_key_algorithm: PublicKeyAlgorithm,
    pub public_key: Option<PublicKey>,

    pub subject: pkix::Name,

    /// The CSR attributes that can parse as
    /// [`pkix::AttributeTypeAndValueSET`].
    ///
    /// Deprecated in Go: use `extensions` and `extra_extensions` instead.
    pub attributes: Vec<pkix::AttributeTypeAndValueSET>,

    /// All requested extensions, in raw form.
    pub extensions: Vec<Extension>,

    /// Extensions to be copied, raw, into any CSR marshaled by
    /// `create_certificate_request`. Not populated by parsing.
    pub extra_extensions: Vec<Extension>,

    /// Subject Alternate Name values.
    pub dns_names: Vec<String>,
    pub email_addresses: Vec<String>,
    pub ip_addresses: Vec<Ip>,
    pub uris: Vec<Url>,
}

/// Go's `x509.RevocationListEntry`: an entry in the revokedCertificates
/// sequence of a CRL.
#[derive(Clone, Debug, Default)]
pub struct RevocationListEntry {
    /// The raw bytes of the revokedCertificates entry. Set when parsing a
    /// CRL; ignored when generating one.
    pub raw: Vec<u8>,

    /// The serial number of a revoked certificate. It must not be nil when
    /// creating a CRL.
    pub serial_number: Option<BigInt>,
    /// The time at which the certificate was revoked. It must not be the zero
    /// time when creating a CRL.
    pub revocation_time: Time,
    /// The reason for revocation (RFC 5280 Section 5.3.1). When creating a
    /// CRL, zero omits the reasonCode extension.
    pub reason_code: i64,

    /// Raw X.509 extensions. When marshaling, ignored; see `extra_extensions`.
    pub extensions: Vec<Extension>,
    /// Extensions to be copied, raw, into any marshaled CRL entries.
    pub extra_extensions: Vec<Extension>,
}

/// Go's `x509.RevocationList`: a Certificate Revocation List (RFC 5280).
#[derive(Clone, Debug, Default)]
pub struct RevocationList {
    /// The complete ASN.1 DER content of the CRL (tbsCertList,
    /// signatureAlgorithm, and signatureValue).
    pub raw: Vec<u8>,
    /// Just the tbsCertList portion of the ASN.1 DER.
    pub raw_tbs_revocation_list: Vec<u8>,
    /// The DER encoded Issuer.
    pub raw_issuer: Vec<u8>,
    /// The DER encoded signature algorithm as a PKIX AlgorithmIdentifier.
    pub raw_signature_algorithm: Vec<u8>,

    /// The DN of the issuing certificate.
    pub issuer: pkix::Name,
    /// Populated from the authorityKeyIdentifier extension when parsing a
    /// CRL; ignored when creating one.
    pub authority_key_id: Vec<u8>,

    pub signature: Vec<u8>,
    /// The algorithm used when signing the CRL. If 0 the default algorithm for
    /// the signing key is used.
    pub signature_algorithm: SignatureAlgorithm,

    /// The revokedCertificates sequence in the CRL. Used when creating a CRL
    /// and populated when parsing one.
    pub revoked_certificate_entries: Vec<RevocationListEntry>,

    /// Used to populate the revokedCertificates sequence in the CRL if
    /// `revoked_certificate_entries` is empty.
    ///
    /// Deprecated in Go: use `revoked_certificate_entries` instead.
    pub revoked_certificates: Vec<pkix::RevokedCertificate>,

    /// The X.509 v2 cRLNumber extension. It is also populated from the
    /// extension when parsing a CRL.
    pub number: Option<BigInt>,

    /// The issuance date of the CRL.
    pub this_update: Time,
    /// The date by which the next CRL will be issued.
    pub next_update: Time,

    /// Raw X.509 extensions. When creating a CRL, ignored; see
    /// `extra_extensions`.
    pub extensions: Vec<Extension>,
    /// Additional extensions to add directly to the CRL.
    pub extra_extensions: Vec<Extension>,
}

pub(crate) const OID_EXTENSION_SUBJECT_KEY_ID: [i64; 4] = [2, 5, 29, 14];
pub(crate) const OID_EXTENSION_KEY_USAGE: [i64; 4] = [2, 5, 29, 15];
pub(crate) const OID_EXTENSION_EXTENDED_KEY_USAGE: [i64; 4] = [2, 5, 29, 37];
pub(crate) const OID_EXTENSION_AUTHORITY_KEY_ID: [i64; 4] = [2, 5, 29, 35];
pub(crate) const OID_EXTENSION_BASIC_CONSTRAINTS: [i64; 4] = [2, 5, 29, 19];
pub(crate) const OID_EXTENSION_SUBJECT_ALT_NAME: [i64; 4] = [2, 5, 29, 17];
pub(crate) const OID_EXTENSION_CERTIFICATE_POLICIES: [i64; 4] = [2, 5, 29, 32];
pub(crate) const OID_EXTENSION_NAME_CONSTRAINTS: [i64; 4] = [2, 5, 29, 30];
pub(crate) const OID_EXTENSION_CRL_DISTRIBUTION_POINTS: [i64; 4] = [2, 5, 29, 31];
pub(crate) const OID_EXTENSION_AUTHORITY_INFO_ACCESS: [i64; 9] = [1, 3, 6, 1, 5, 5, 7, 1, 1];
pub(crate) const OID_EXTENSION_CRL_NUMBER: [i64; 4] = [2, 5, 29, 20];
pub(crate) const OID_EXTENSION_REASON_CODE: [i64; 4] = [2, 5, 29, 21];
pub(crate) const OID_AUTHORITY_INFO_ACCESS_OCSP: [i64; 9] = [1, 3, 6, 1, 5, 5, 7, 48, 1];
pub(crate) const OID_AUTHORITY_INFO_ACCESS_ISSUERS: [i64; 9] = [1, 3, 6, 1, 5, 5, 7, 48, 2];
pub(crate) const OID_EXTENSION_REQUEST: [i64; 7] = [1, 2, 840, 113549, 1, 9, 14];

/// Go's `oidInExtensions`.
pub(crate) fn oid_in_extensions(oid: &[i64], extensions: &[Extension]) -> bool {
    extensions.iter().any(|e| e.id.0 == oid)
}

impl Certificate {
    /// Go's `Certificate.Equal`: whether the raw encodings are equal.
    pub fn equal(&self, other: &Certificate) -> bool {
        self.raw == other.raw
    }

    pub(crate) fn has_san_extension(&self) -> bool {
        oid_in_extensions(&OID_EXTENSION_SUBJECT_ALT_NAME, &self.extensions)
    }

    pub(crate) fn has_name_constraints(&self) -> bool {
        oid_in_extensions(&OID_EXTENSION_NAME_CONSTRAINTS, &self.extensions)
    }

    /// Go's `Certificate.CheckSignatureFrom`: verifies that the signature on
    /// `self` is a valid signature from `parent`.
    ///
    /// This is a low-level API that performs very limited checks, and not a
    /// full path verifier. Most users should use [`Certificate::verify`].
    pub fn check_signature_from(&self, parent: &Certificate) -> Result<(), Error> {
        // RFC 5280, 4.2.1.9: "If the basic constraints extension is not present
        // in a version 3 certificate, or the extension is present but the cA
        // boolean is not asserted, then the certified public key MUST NOT be
        // used to verify certificate signatures."
        if parent.version == 3 && !parent.basic_constraints_valid
            || parent.basic_constraints_valid && !parent.is_ca
        {
            return Err(ConstraintViolationError.into());
        }

        if parent.key_usage.0 != 0 && (parent.key_usage & KeyUsage::CERT_SIGN).0 == 0 {
            return Err(ConstraintViolationError.into());
        }

        if parent.public_key_algorithm == PublicKeyAlgorithm::UNKNOWN_PUBLIC_KEY_ALGORITHM {
            return Err(Error::UnsupportedAlgorithm);
        }

        check_signature(
            self.signature_algorithm,
            &self.raw_tbs_certificate,
            &self.signature,
            parent.public_key.as_ref(),
            false,
        )
    }

    /// Go's `Certificate.CheckSignature`: verifies that `signature` is a valid
    /// signature over `signed` from the public key of `self`.
    ///
    /// This is a low-level API that performs no validity checks on the
    /// certificate. `MD5WithRSA` signatures are rejected, while
    /// `SHA1WithRSA` and `ECDSAWithSHA1` signatures are currently accepted.
    pub fn check_signature(
        &self,
        algo: SignatureAlgorithm,
        signed: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        check_signature(algo, signed, signature, self.public_key.as_ref(), true)
    }

    /// Go's `Certificate.CheckCRLSignature`: checks that the signature in
    /// `crl` is from `self`.
    ///
    /// Deprecated in Go: use [`RevocationList::check_signature_from`].
    pub fn check_crl_signature(&self, crl: &pkix::CertificateList) -> Result<(), Error> {
        let algo = super::parser::signature_algorithm_from_ai(&crl.signature_algorithm);
        self.check_signature(
            algo,
            &crl.tbs_cert_list.raw,
            &crl.signature_value.right_align(),
        )
    }
}

impl CertificateRequest {
    /// Go's `CertificateRequest.CheckSignature`: reports whether the signature
    /// on the request is valid.
    pub fn check_signature(&self) -> Result<(), Error> {
        check_signature(
            self.signature_algorithm,
            &self.raw_tbs_certificate_request,
            &self.signature,
            self.public_key.as_ref(),
            true,
        )
    }
}

impl RevocationList {
    /// Go's `RevocationList.CheckSignatureFrom`: verifies that the signature
    /// on the list is a valid signature from `parent`.
    pub fn check_signature_from(&self, parent: &Certificate) -> Result<(), Error> {
        if parent.version == 3 && !parent.basic_constraints_valid
            || parent.basic_constraints_valid && !parent.is_ca
        {
            return Err(ConstraintViolationError.into());
        }

        if parent.key_usage.0 != 0 && (parent.key_usage & KeyUsage::CRL_SIGN).0 == 0 {
            return Err(ConstraintViolationError.into());
        }

        if parent.public_key_algorithm == PublicKeyAlgorithm::UNKNOWN_PUBLIC_KEY_ALGORITHM {
            return Err(Error::UnsupportedAlgorithm);
        }

        parent.check_signature(
            self.signature_algorithm,
            &self.raw_tbs_revocation_list,
            &self.signature,
        )
    }
}

fn signature_public_key_algo_mismatch_error(
    expected: PublicKeyAlgorithm,
    pub_key: &PublicKey,
) -> Error {
    Error::new(format!(
        "x509: signature algorithm specifies an {expected} public key, but have public key of type {}",
        pub_key.type_name()
    ))
}

fn signature_mldsa_parameters_mismatch_error(
    expected: SignatureAlgorithm,
    pub_key: &mldsa::PublicKey,
) -> Error {
    Error::new(format!(
        "x509: signature algorithm specifies an ML-DSA public key with {expected} parameters, but have a public key with {} parameters",
        pub_key.parameters()
    ))
}

/// Go's `checkSignature`: verifies that `signature` is a valid signature over
/// `signed` from a public key.
pub(crate) fn check_signature(
    algo: SignatureAlgorithm,
    signed: &[u8],
    signature: &[u8],
    public_key: Option<&PublicKey>,
    allow_sha1: bool,
) -> Result<(), Error> {
    let (hash_type, pub_key_algo) = match algo.details() {
        Some(d) => (d.hash, d.pub_key_algo),
        None => (None, PublicKeyAlgorithm::UNKNOWN_PUBLIC_KEY_ALGORITHM),
    };

    let mut digest;
    let mut signed = signed;
    match hash_type {
        None => {
            if pub_key_algo != PublicKeyAlgorithm::ED25519
                && pub_key_algo != PublicKeyAlgorithm::MLDSA
            {
                return Err(Error::UnsupportedAlgorithm);
            }
        }
        Some(Hash::Md5) => return Err(InsecureAlgorithmError(algo).into()),
        Some(hash) => {
            // SHA-1 signatures are only allowed for CRLs and CSRs.
            if hash == Hash::Sha1 && !allow_sha1 {
                return Err(InsecureAlgorithmError(algo).into());
            }
            let Ok(mut h) = hash.new() else {
                return Err(Error::UnsupportedAlgorithm);
            };
            std::io::Write::write_all(&mut h, signed).expect("hash writes do not fail");
            digest = Vec::new();
            h.sum(&mut digest);
            signed = &digest;
        }
    }

    match public_key {
        Some(PublicKey::Rsa(pub_key)) => {
            if pub_key_algo != PublicKeyAlgorithm::RSA {
                return Err(signature_public_key_algo_mismatch_error(
                    pub_key_algo,
                    public_key.expect("matched"),
                ));
            }
            let hash = hash_type.expect("RSA signatures are hashed");
            let result = if algo.is_rsa_pss() {
                rsa::verify_pss(
                    pub_key,
                    hash,
                    signed,
                    signature,
                    Some(&rsa::PSSOptions {
                        salt_length: rsa::PSS_SALT_LENGTH_EQUALS_HASH,
                        hash: None,
                    }),
                )
            } else {
                rsa::verify_pkcs1v15(pub_key, Some(hash), signed, signature)
            };
            result.map_err(|e| Error::new(e.to_string()))
        }
        Some(PublicKey::Ecdsa(pub_key)) => {
            if pub_key_algo != PublicKeyAlgorithm::ECDSA {
                return Err(signature_public_key_algo_mismatch_error(
                    pub_key_algo,
                    public_key.expect("matched"),
                ));
            }
            if !ecdsa::verify_asn1(pub_key, signed, signature) {
                return Err(Error::new("x509: ECDSA verification failure"));
            }
            Ok(())
        }
        Some(PublicKey::Ed25519(pub_key)) => {
            if pub_key_algo != PublicKeyAlgorithm::ED25519 {
                return Err(signature_public_key_algo_mismatch_error(
                    pub_key_algo,
                    public_key.expect("matched"),
                ));
            }
            if !matches!(ed25519::verify(pub_key, signed, signature), Ok(true)) {
                return Err(Error::new("x509: Ed25519 verification failure"));
            }
            Ok(())
        }
        Some(PublicKey::Mldsa(pub_key)) => {
            if pub_key_algo != PublicKeyAlgorithm::MLDSA {
                return Err(signature_public_key_algo_mismatch_error(
                    pub_key_algo,
                    public_key.expect("matched"),
                ));
            }
            let params = pub_key.parameters();
            let expected = if params == mldsa::mldsa44() {
                SignatureAlgorithm::MLDSA44
            } else if params == mldsa::mldsa65() {
                SignatureAlgorithm::MLDSA65
            } else if params == mldsa::mldsa87() {
                SignatureAlgorithm::MLDSA87
            } else {
                return Err(Error::new(format!(
                    "x509: unknown ML-DSA parameters: {params}"
                )));
            };
            if algo != expected {
                return Err(signature_mldsa_parameters_mismatch_error(algo, pub_key));
            }
            mldsa::verify(pub_key, signed, signature, None)
                .map_err(|e| Error::new(format!("x509: ML-DSA verification failure: {e}")))
        }
        _ => Err(Error::UnsupportedAlgorithm),
    }
}
