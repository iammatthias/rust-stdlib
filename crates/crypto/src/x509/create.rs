//! Creating certificates, certificate requests and revocation lists, a port of
//! the marshaling half of Go's `x509.go`.
//!
//! Signing goes through the key's [`Signer`] implementation (the reviewed
//! crates) and every signature is verified again before it is returned, as in
//! Go.

use std::any::Any;
use std::io;

use super::asn1::{self, BigInt, BitString, ObjectIdentifier};
use super::cert::*;
use super::keys::{self, PublicKey};
use super::net::IpNet;
use super::oid::Oid;
use super::parser::is_ia5_string;
use super::pkix::{self, AlgorithmIdentifier, AttributeTypeAndValue, Extension};
use super::time::Time;
use super::types::*;
use super::url::Url;
use super::Error;
use crate::{ecdsa, elliptic, mldsa, rsa, Hash, Signer};

fn reverse_bits_in_a_byte(input: u8) -> u8 {
    input.reverse_bits()
}

/// Go's `asn1BitLength`: the bit length of a bit string, considering the
/// most-significant bit in a byte to be the "first" bit.
fn asn1_bit_length(bit_string: &[u8]) -> usize {
    let mut bit_len = bit_string.len() * 8;
    for i in 0..bit_string.len() {
        let b = bit_string[bit_string.len() - i - 1];
        for bit in 0..8 {
            if (b >> bit) & 1 == 1 {
                return bit_len;
            }
            bit_len -= 1;
        }
    }
    0
}

/// Go's `marshalSANs`: the contents of a SubjectAlternativeName extension.
pub(crate) fn marshal_sans(
    dns_names: &[String],
    email_addresses: &[String],
    ip_addresses: &[super::net::Ip],
    uris: &[Url],
) -> Result<Vec<u8>, Error> {
    let mut raw_values = Vec::new();
    for name in dns_names {
        is_ia5_string(name)?;
        raw_values.extend(asn1::tlv(asn1::context(2), name.as_bytes()));
    }
    for email in email_addresses {
        is_ia5_string(email)?;
        raw_values.extend(asn1::tlv(asn1::context(1), email.as_bytes()));
    }
    for raw_ip in ip_addresses {
        // If possible, IPv4 addresses are always encoded in 4 bytes.
        let ip: Vec<u8> = match raw_ip.to4() {
            Some(v4) => v4.to_vec(),
            None => raw_ip.0.clone(),
        };
        raw_values.extend(asn1::tlv(asn1::context(7), &ip));
    }
    for uri in uris {
        let uri_str = uri.to_string();
        is_ia5_string(&uri_str)?;
        raw_values.extend(asn1::tlv(asn1::context(6), uri_str.as_bytes()));
    }
    Ok(asn1::tlv(asn1::SEQUENCE, &raw_values))
}

fn marshal_key_usage(ku: KeyUsage) -> Extension {
    let a = [
        reverse_bits_in_a_byte(ku.0 as u8),
        reverse_bits_in_a_byte((ku.0 >> 8) as u8),
    ];
    let l = if a[1] != 0 { 2 } else { 1 };
    let bit_string = &a[..l];
    Extension {
        id: ObjectIdentifier(OID_EXTENSION_KEY_USAGE.to_vec()),
        critical: true,
        value: asn1::bit_string(bit_string, asn1_bit_length(bit_string)),
    }
}

fn marshal_ext_key_usage(
    ext_usages: &[ExtKeyUsage],
    unknown_usages: &[ObjectIdentifier],
) -> Result<Extension, Error> {
    let mut oids: Vec<ObjectIdentifier> = Vec::new();
    for &u in ext_usages {
        match oid_from_ext_key_usage(u) {
            Some(oid) => oids.push(oid),
            None => return Err(Error::new("x509: unknown extended key usage")),
        }
    }
    oids.extend(unknown_usages.iter().cloned());
    let mut content = Vec::new();
    for oid in &oids {
        content.extend(asn1::oid(&oid.0).ok_or_else(asn1::err_oid)?);
    }
    Ok(Extension {
        id: ObjectIdentifier(OID_EXTENSION_EXTENDED_KEY_USAGE.to_vec()),
        critical: false,
        value: asn1::tlv(asn1::SEQUENCE, &content),
    })
}

fn marshal_basic_constraints(is_ca: bool, max_path_len: i64, max_path_len_zero: bool) -> Extension {
    let mut max_path_len = max_path_len;
    // Leaving MaxPathLen as zero indicates that no maximum path length is
    // desired, unless MaxPathLenZero is set. A value of -1 causes the value to
    // be omitted.
    if max_path_len == 0 && !max_path_len_zero {
        max_path_len = -1;
    }
    let mut content = Vec::new();
    if is_ca {
        content.extend(asn1::boolean(true));
    }
    if max_path_len != -1 {
        content.extend(asn1::integer_i64(max_path_len));
    }
    Extension {
        id: ObjectIdentifier(OID_EXTENSION_BASIC_CONSTRAINTS.to_vec()),
        critical: true,
        value: asn1::tlv(asn1::SEQUENCE, &content),
    }
}

fn use_policies() -> bool {
    crate::sysrng::godebug("x509usepolicies").as_deref() != Some("0")
}

fn marshal_certificate_policies(
    policies: &[Oid],
    policy_identifiers: &[ObjectIdentifier],
) -> Result<Extension, Error> {
    let mut content = Vec::new();
    if use_policies() {
        for v in policies {
            if v.der().is_empty() {
                return Err(Error::new("invalid policy object identifier"));
            }
            content.extend(asn1::tlv(
                asn1::SEQUENCE,
                &asn1::tlv(asn1::OBJECT_IDENTIFIER, v.der()),
            ));
        }
    } else {
        for v in policy_identifiers {
            content.extend(asn1::tlv(
                asn1::SEQUENCE,
                &asn1::oid(&v.0).ok_or_else(|| Error::new("cryptobyte: invalid OID"))?,
            ));
        }
    }
    Ok(Extension {
        id: ObjectIdentifier(OID_EXTENSION_CERTIFICATE_POLICIES.to_vec()),
        critical: false,
        value: asn1::tlv(asn1::SEQUENCE, &content),
    })
}

fn ip_and_mask(ip_net: &IpNet) -> Result<Vec<u8>, Error> {
    let masked_ip = ip_net
        .ip
        .mask(&ip_net.mask)
        .map(|i| i.0)
        .unwrap_or_default();
    // Extremely unlikely, but this saves people from doing something they
    // probably shouldn't.
    if masked_ip.len() == 16 && super::net::Ip(masked_ip.clone()).to4().is_some() {
        return Err(Error::new(
            "x509: IP constraint contained IPv4-mapped IPv6 address with a IPv6 mask",
        ));
    }
    let mut out = masked_ip;
    out.extend_from_slice(&ip_net.mask);
    Ok(out)
}

fn serialise_constraints(
    dns: &[String],
    ips: &[IpNet],
    emails: &[String],
    uri_domains: &[String],
) -> Result<Vec<u8>, Error> {
    let mut b = Vec::new();
    for name in dns {
        is_ia5_string(name)?;
        b.extend(asn1::tlv(
            asn1::SEQUENCE,
            &asn1::tlv(asn1::context(2), name.as_bytes()),
        ));
    }
    for ip_net in ips {
        let encoded = ip_and_mask(ip_net)?;
        b.extend(asn1::tlv(
            asn1::SEQUENCE,
            &asn1::tlv(asn1::context(7), &encoded),
        ));
    }
    for email in emails {
        is_ia5_string(email)?;
        b.extend(asn1::tlv(
            asn1::SEQUENCE,
            &asn1::tlv(asn1::context(1), email.as_bytes()),
        ));
    }
    for uri_domain in uri_domains {
        is_ia5_string(uri_domain)?;
        b.extend(asn1::tlv(
            asn1::SEQUENCE,
            &asn1::tlv(asn1::context(6), uri_domain.as_bytes()),
        ));
    }
    Ok(b)
}

fn build_cert_extensions(
    template: &Certificate,
    subject_is_empty: bool,
    authority_key_id: &[u8],
    subject_key_id: &[u8],
) -> Result<Vec<Extension>, Error> {
    let mut ret: Vec<Extension> = Vec::with_capacity(10);
    let extra = &template.extra_extensions;
    let ext = |id: &[i64], critical: bool, value: Vec<u8>| Extension {
        id: ObjectIdentifier(id.to_vec()),
        critical,
        value,
    };

    if template.key_usage.0 != 0 && !oid_in_extensions(&OID_EXTENSION_KEY_USAGE, extra) {
        ret.push(marshal_key_usage(template.key_usage));
    }

    if (!template.ext_key_usage.is_empty() || !template.unknown_ext_key_usage.is_empty())
        && !oid_in_extensions(&OID_EXTENSION_EXTENDED_KEY_USAGE, extra)
    {
        ret.push(marshal_ext_key_usage(
            &template.ext_key_usage,
            &template.unknown_ext_key_usage,
        )?);
    }

    if template.basic_constraints_valid
        && !oid_in_extensions(&OID_EXTENSION_BASIC_CONSTRAINTS, extra)
    {
        ret.push(marshal_basic_constraints(
            template.is_ca,
            template.max_path_len,
            template.max_path_len_zero,
        ));
    }

    if !subject_key_id.is_empty() && !oid_in_extensions(&OID_EXTENSION_SUBJECT_KEY_ID, extra) {
        ret.push(ext(
            &OID_EXTENSION_SUBJECT_KEY_ID,
            false,
            asn1::octet_string(subject_key_id),
        ));
    }

    if !authority_key_id.is_empty() && !oid_in_extensions(&OID_EXTENSION_AUTHORITY_KEY_ID, extra) {
        ret.push(ext(
            &OID_EXTENSION_AUTHORITY_KEY_ID,
            false,
            asn1::tlv(
                asn1::SEQUENCE,
                &asn1::tlv(asn1::context(0), authority_key_id),
            ),
        ));
    }

    if (!template.ocsp_server.is_empty() || !template.issuing_certificate_url.is_empty())
        && !oid_in_extensions(&OID_EXTENSION_AUTHORITY_INFO_ACCESS, extra)
    {
        let mut values = Vec::new();
        for name in &template.ocsp_server {
            let mut item = asn1::oid(&OID_AUTHORITY_INFO_ACCESS_OCSP).expect("valid OID");
            item.extend(asn1::tlv(asn1::context(6), name.as_bytes()));
            values.extend(asn1::tlv(asn1::SEQUENCE, &item));
        }
        for name in &template.issuing_certificate_url {
            let mut item = asn1::oid(&OID_AUTHORITY_INFO_ACCESS_ISSUERS).expect("valid OID");
            item.extend(asn1::tlv(asn1::context(6), name.as_bytes()));
            values.extend(asn1::tlv(asn1::SEQUENCE, &item));
        }
        ret.push(ext(
            &OID_EXTENSION_AUTHORITY_INFO_ACCESS,
            false,
            asn1::tlv(asn1::SEQUENCE, &values),
        ));
    }

    if (!template.dns_names.is_empty()
        || !template.email_addresses.is_empty()
        || !template.ip_addresses.is_empty()
        || !template.uris.is_empty())
        && !oid_in_extensions(&OID_EXTENSION_SUBJECT_ALT_NAME, extra)
    {
        // From RFC 5280, Section 4.2.1.6: "If the subject field contains an
        // empty sequence ... then subjectAltName extension ... is marked as
        // critical".
        ret.push(ext(
            &OID_EXTENSION_SUBJECT_ALT_NAME,
            subject_is_empty,
            marshal_sans(
                &template.dns_names,
                &template.email_addresses,
                &template.ip_addresses,
                &template.uris,
            )?,
        ));
    }

    let policies = use_policies();
    if ((!policies && !template.policy_identifiers.is_empty())
        || (policies && !template.policies.is_empty()))
        && !oid_in_extensions(&OID_EXTENSION_CERTIFICATE_POLICIES, extra)
    {
        ret.push(marshal_certificate_policies(
            &template.policies,
            &template.policy_identifiers,
        )?);
    }

    if (!template.permitted_dns_domains.is_empty()
        || !template.excluded_dns_domains.is_empty()
        || !template.permitted_ip_ranges.is_empty()
        || !template.excluded_ip_ranges.is_empty()
        || !template.permitted_email_addresses.is_empty()
        || !template.excluded_email_addresses.is_empty()
        || !template.permitted_uri_domains.is_empty()
        || !template.excluded_uri_domains.is_empty())
        && !oid_in_extensions(&OID_EXTENSION_NAME_CONSTRAINTS, extra)
    {
        let permitted = serialise_constraints(
            &template.permitted_dns_domains,
            &template.permitted_ip_ranges,
            &template.permitted_email_addresses,
            &template.permitted_uri_domains,
        )?;
        let excluded = serialise_constraints(
            &template.excluded_dns_domains,
            &template.excluded_ip_ranges,
            &template.excluded_email_addresses,
            &template.excluded_uri_domains,
        )?;
        let mut content = Vec::new();
        if !permitted.is_empty() {
            content.extend(asn1::tlv(asn1::context_constructed(0), &permitted));
        }
        if !excluded.is_empty() {
            content.extend(asn1::tlv(asn1::context_constructed(1), &excluded));
        }
        ret.push(ext(
            &OID_EXTENSION_NAME_CONSTRAINTS,
            template.permitted_dns_domains_critical,
            asn1::tlv(asn1::SEQUENCE, &content),
        ));
    }

    if !template.crl_distribution_points.is_empty()
        && !oid_in_extensions(&OID_EXTENSION_CRL_DISTRIBUTION_POINTS, extra)
    {
        let mut crl_dp = Vec::new();
        for name in &template.crl_distribution_points {
            // distributionPoint [0] { fullName [0] { uniformResourceIdentifier } }
            let full_name = asn1::tlv(asn1::context(6), name.as_bytes());
            let dp_name = asn1::tlv(asn1::context_constructed(0), &full_name);
            let dp = asn1::tlv(asn1::context_constructed(0), &dp_name);
            crl_dp.extend(asn1::tlv(asn1::SEQUENCE, &dp));
        }
        ret.push(ext(
            &OID_EXTENSION_CRL_DISTRIBUTION_POINTS,
            false,
            asn1::tlv(asn1::SEQUENCE, &crl_dp),
        ));
    }

    ret.extend(extra.iter().cloned());
    Ok(ret)
}

fn build_csr_extensions(template: &CertificateRequest) -> Result<Vec<Extension>, Error> {
    let mut ret = Vec::new();

    if (!template.dns_names.is_empty()
        || !template.email_addresses.is_empty()
        || !template.ip_addresses.is_empty()
        || !template.uris.is_empty())
        && !oid_in_extensions(&OID_EXTENSION_SUBJECT_ALT_NAME, &template.extra_extensions)
    {
        let san_bytes = marshal_sans(
            &template.dns_names,
            &template.email_addresses,
            &template.ip_addresses,
            &template.uris,
        )?;
        ret.push(Extension {
            id: ObjectIdentifier(OID_EXTENSION_SUBJECT_ALT_NAME.to_vec()),
            critical: false,
            value: san_bytes,
        });
    }

    ret.extend(template.extra_extensions.iter().cloned());
    Ok(ret)
}

fn marshal_name(name: &pkix::Name) -> Result<Vec<u8>, Error> {
    name.to_rdn_sequence().marshal()
}

fn subject_bytes_from(raw_subject: &[u8], subject: &pkix::Name) -> Result<Vec<u8>, Error> {
    if !raw_subject.is_empty() {
        return Ok(raw_subject.to_vec());
    }
    marshal_name(subject)
}

/// Go's `signingParamsForKey`: the signature algorithm and its
/// AlgorithmIdentifier to use for signing, based on the key type. If
/// `sig_algo` is not zero it overrides the default.
fn signing_params_for_key(
    key: &dyn Signer,
    sig_algo: SignatureAlgorithm,
) -> Result<(SignatureAlgorithm, AlgorithmIdentifier), Error> {
    let public = key.public();
    let (pub_type, default_algo);
    if public.is::<rsa::PublicKey>() {
        pub_type = PublicKeyAlgorithm::RSA;
        default_algo = SignatureAlgorithm::SHA256_WITH_RSA;
    } else if let Some(pub_key) = public.downcast_ref::<ecdsa::PublicKey>() {
        pub_type = PublicKeyAlgorithm::ECDSA;
        let curve = &pub_key.curve;
        if elliptic::same_curve(curve, &elliptic::p224())
            || elliptic::same_curve(curve, &elliptic::p256())
        {
            default_algo = SignatureAlgorithm::ECDSA_WITH_SHA256;
        } else if elliptic::same_curve(curve, &elliptic::p384()) {
            default_algo = SignatureAlgorithm::ECDSA_WITH_SHA384;
        } else if elliptic::same_curve(curve, &elliptic::p521()) {
            default_algo = SignatureAlgorithm::ECDSA_WITH_SHA512;
        } else {
            return Err(Error::new("x509: unsupported elliptic curve"));
        }
    } else if public.is::<crate::ed25519::PublicKey>() {
        pub_type = PublicKeyAlgorithm::ED25519;
        default_algo = SignatureAlgorithm::PURE_ED25519;
    } else if let Some(pub_key) = public.downcast_ref::<mldsa::PublicKey>() {
        pub_type = PublicKeyAlgorithm::MLDSA;
        let params = pub_key.parameters();
        if params == mldsa::mldsa44() {
            default_algo = SignatureAlgorithm::MLDSA44;
        } else if params == mldsa::mldsa65() {
            default_algo = SignatureAlgorithm::MLDSA65;
        } else if params == mldsa::mldsa87() {
            default_algo = SignatureAlgorithm::MLDSA87;
        } else {
            return Err(Error::new(format!(
                "x509: unsupported ML-DSA parameters: {params}"
            )));
        }
    } else {
        return Err(Error::new(
            "x509: only RSA, ECDSA, ML-DSA and Ed25519 keys supported",
        ));
    }

    let sig_algo = if sig_algo.0 == 0 {
        default_algo
    } else {
        sig_algo
    };

    for details in SIGNATURE_ALGORITHM_DETAILS {
        if details.algo == sig_algo {
            if details.pub_key_algo != pub_type {
                return Err(Error::new(
                    "x509: requested SignatureAlgorithm does not match private key type",
                ));
            }
            if pub_type == PublicKeyAlgorithm::MLDSA && sig_algo != default_algo {
                return Err(Error::new(
                    "x509: requested SignatureAlgorithm does not match ML-DSA parameters",
                ));
            }
            if details.hash == Some(Hash::Md5) {
                return Err(Error::new("x509: signing with MD5 is not supported"));
            }

            return Ok((
                sig_algo,
                AlgorithmIdentifier {
                    algorithm: ObjectIdentifier(details.oid.to_vec()),
                    parameters: details.params.raw_value(),
                },
            ));
        }
    }

    Err(Error::new("x509: unknown SignatureAlgorithm"))
}

fn sign_tbs(
    tbs: &[u8],
    key: &dyn Signer,
    sig_alg: SignatureAlgorithm,
    rand: Option<&mut dyn io::Read>,
) -> Result<Vec<u8>, Error> {
    let hash_func = sig_alg.hash_func();

    let pss_opts;
    let hash_opts;
    let signer_opts: &dyn crate::SignerOpts = if sig_alg.is_rsa_pss() {
        pss_opts = rsa::PSSOptions {
            salt_length: rsa::PSS_SALT_LENGTH_EQUALS_HASH,
            hash: hash_func,
        };
        &pss_opts
    } else {
        hash_opts = HashOpts(hash_func);
        &hash_opts
    };

    let signature = crate::sign_message_in(key, rand, tbs, signer_opts)
        .map_err(|e| Error::new(e.to_string()))?;

    // Check the signature to ensure the Signer behaved correctly.
    let public = PublicKey::from_any(key.public());
    super::cert::check_signature(sig_alg, tbs, &signature, public.as_ref(), true).map_err(|e| {
        Error::new(format!(
            "x509: signature returned by signer is invalid: {e}"
        ))
    })?;

    Ok(signature)
}

/// Signer options that name a hash function, or none (Go's `crypto.Hash(0)`).
struct HashOpts(Option<Hash>);

impl crate::SignerOpts for HashOpts {
    fn hash_func(&self) -> Option<Hash> {
        self.0
    }
}

fn new_serial_number(rand: Option<&mut dyn io::Read>) -> Result<BigInt, Error> {
    // Generate a serial number following RFC 5280, Section 4.1.2.2: positive
    // and at most 20 octets when encoded.
    let mut serial_bytes = [0u8; 20];
    match rand {
        Some(r) => r
            .read_exact(&mut serial_bytes)
            .map_err(|e| Error::new(e.to_string()))?,
        None => {
            crate::rand::read(&mut serial_bytes);
        }
    }
    // If the top bit is set, the serial will be padded with a leading zero
    // byte during encoding; clearing it keeps the serial within 20 octets.
    serial_bytes[0] &= 0b0111_1111;
    Ok(BigInt::from_be_bytes(&serial_bytes))
}

fn subject_key_id_of(public_key_bytes: &[u8]) -> Vec<u8> {
    if crate::sysrng::godebug("x509sha256skid").as_deref() == Some("0") {
        // Method 1 in RFC 5280, Section 4.2.1.2: the 160-bit SHA-1 hash of the
        // value of the BIT STRING subjectPublicKey.
        crate::sha1::sum(public_key_bytes).to_vec()
    } else {
        // Method 1 in RFC 7093, Section 2: the leftmost 160 bits of the
        // SHA-256 hash.
        crate::sha256::sum256(public_key_bytes)[..20].to_vec()
    }
}

const EMPTY_ASN1_SUBJECT: [u8; 2] = [0x30, 0];

/// Go's `CreateCertificate`: creates a new X.509 v3 certificate based on a
/// template, signed by `parent` (if `parent` equals `template` the
/// certificate is self-signed). `pub_key` is the public key of the
/// certificate to be generated and `priv_key` the key of the signer.
///
/// The template fields used are listed in Go's documentation: AuthorityKeyId,
/// BasicConstraintsValid, CRLDistributionPoints, DNSNames, EmailAddresses,
/// the excluded and permitted name constraints, ExtKeyUsage, ExtraExtensions,
/// IPAddresses, IsCA, IssuingCertificateURL, KeyUsage, MaxPathLen,
/// MaxPathLenZero, NotAfter, NotBefore, OCSPServer, PermittedDNSDomainsCritical,
/// PolicyIdentifiers and Policies, SerialNumber, SignatureAlgorithm, Subject,
/// SubjectKeyId, URIs and UnknownExtKeyUsage.
///
/// The returned vector is the certificate in DER encoding. `pub_key` is one of
/// the key types of [`PublicKey`] (as `&dyn Any`) and `priv_key` is a
/// [`Signer`] with a supported public key.
///
/// The AuthorityKeyId is taken from the SubjectKeyId of `parent`, if any,
/// unless the resulting certificate is self-signed. If SubjectKeyId from
/// `template` is empty and the template is a CA, SubjectKeyId is generated
/// from the hash of the public key. If `template.serial_number` is `None`, a
/// serial number is generated using entropy from the system source.
pub fn create_certificate(
    template: &Certificate,
    parent: &Certificate,
    pub_key: &dyn Any,
    priv_key: &dyn Signer,
) -> Result<Vec<u8>, Error> {
    create_certificate_in(None, template, parent, pub_key, priv_key)
}

/// [`create_certificate`] with a caller's reader: it supplies the serial
/// number and is passed to [`Signer::sign_with_rng`], like Go's
/// `CreateCertificate(rng, ...)`.
pub fn create_certificate_with_rng(
    rng: &mut dyn io::Read,
    template: &Certificate,
    parent: &Certificate,
    pub_key: &dyn Any,
    priv_key: &dyn Signer,
) -> Result<Vec<u8>, Error> {
    create_certificate_in(Some(rng), template, parent, pub_key, priv_key)
}

fn create_certificate_in(
    rand: Option<&mut dyn io::Read>,
    template: &Certificate,
    parent: &Certificate,
    pub_key: &dyn Any,
    priv_key: &dyn Signer,
) -> Result<Vec<u8>, Error> {
    let mut rand = rand;
    let serial_number = match &template.serial_number {
        Some(s) => s.clone(),
        None => new_serial_number(rand.as_mut().map(|r| &mut **r as &mut dyn io::Read))?,
    };

    // RFC 5280 Section 4.1.2.2: serial number must be positive.
    if serial_number.sign() == -1 {
        return Err(Error::new("x509: serial number must be positive"));
    }

    if template.basic_constraints_valid && template.max_path_len < -1 {
        return Err(Error::new(
            "x509: invalid MaxPathLen, must be greater or equal to -1",
        ));
    }

    if template.basic_constraints_valid
        && !template.is_ca
        && template.max_path_len != -1
        && (template.max_path_len != 0 || template.max_path_len_zero)
    {
        return Err(Error::new(
            "x509: only CAs are allowed to specify MaxPathLen",
        ));
    }

    let (signature_algorithm, algorithm_identifier) =
        signing_params_for_key(priv_key, template.signature_algorithm)?;

    let Some(pub_enum) = PublicKey::from_any(pub_key) else {
        return Err(Error::new("x509: unsupported public key type: unknown"));
    };
    let (public_key_bytes, public_key_algorithm) = keys::marshal_public_key(&pub_enum)?;
    if keys::public_key_algorithm_from_oid(&public_key_algorithm.algorithm)
        == PublicKeyAlgorithm::UNKNOWN_PUBLIC_KEY_ALGORITHM
    {
        return Err(Error::new(format!(
            "x509: unsupported public key type: {}",
            pub_enum.type_name()
        )));
    }

    let asn1_issuer = subject_bytes_from(&parent.raw_subject, &parent.subject)?;
    let asn1_subject = subject_bytes_from(&template.raw_subject, &template.subject)?;

    let mut authority_key_id = template.authority_key_id.clone();
    if asn1_issuer != asn1_subject && !parent.subject_key_id.is_empty() {
        authority_key_id = parent.subject_key_id.clone();
    }

    let mut subject_key_id = template.subject_key_id.clone();
    if subject_key_id.is_empty() && template.is_ca {
        subject_key_id = subject_key_id_of(&public_key_bytes);
    }

    // Check that the signer's public key matches the private key, if
    // available.
    let signer_public = PublicKey::from_any(priv_key.public()).ok_or_else(|| {
        Error::new("x509: internal error: supported public key does not implement Equal")
    })?;
    if let Some(parent_key) = &parent.public_key {
        if !signer_public.equal(parent_key) {
            return Err(Error::new(
                "x509: provided PrivateKey doesn't match parent's PublicKey",
            ));
        }
    }

    let extensions = build_cert_extensions(
        template,
        asn1_subject == EMPTY_ASN1_SUBJECT,
        &authority_key_id,
        &subject_key_id,
    )?;

    // tbsCertificate
    let mut tbs = asn1::tlv(asn1::context_constructed(0), &asn1::integer_i64(2));
    tbs.extend(asn1::integer_big(&serial_number));
    tbs.extend(algorithm_identifier.marshal()?);
    tbs.extend_from_slice(&asn1_issuer);
    let mut validity = asn1::time(&template.not_before.utc()).ok_or_else(asn1::err_time)?;
    validity.extend(asn1::time(&template.not_after.utc()).ok_or_else(asn1::err_time)?);
    tbs.extend(asn1::tlv(asn1::SEQUENCE, &validity));
    tbs.extend_from_slice(&asn1_subject);
    let mut spki = public_key_algorithm.marshal()?;
    spki.extend(asn1::bit_string(
        &public_key_bytes,
        public_key_bytes.len() * 8,
    ));
    tbs.extend(asn1::tlv(asn1::SEQUENCE, &spki));
    if !extensions.is_empty() {
        let mut exts = Vec::new();
        for e in &extensions {
            exts.extend(e.marshal()?);
        }
        tbs.extend(asn1::tlv(
            asn1::context_constructed(3),
            &asn1::tlv(asn1::SEQUENCE, &exts),
        ));
    }
    let tbs_cert_contents = asn1::tlv(asn1::SEQUENCE, &tbs);

    let signature = sign_tbs(
        &tbs_cert_contents,
        priv_key,
        signature_algorithm,
        rand.as_mut().map(|r| &mut **r as &mut dyn io::Read),
    )?;

    let mut cert = tbs_cert_contents;
    cert.extend(algorithm_identifier.marshal()?);
    cert.extend(asn1::bit_string(&signature, signature.len() * 8));
    Ok(asn1::tlv(asn1::SEQUENCE, &cert))
}

/// Go's `CreateCertificateRequest`: creates a new certificate request based on
/// a template. The following members of `template` are used:
/// SignatureAlgorithm, Subject, DNSNames, EmailAddresses, IPAddresses, URIs,
/// ExtraExtensions and Attributes (deprecated).
///
/// `priv_key` is the private key to sign the CSR with, and the corresponding
/// public key is included in the CSR. Its public key must be an RSA, ECDSA,
/// Ed25519 or ML-DSA key. The returned vector is the request in DER encoding.
pub fn create_certificate_request(
    template: &CertificateRequest,
    priv_key: &dyn Signer,
) -> Result<Vec<u8>, Error> {
    create_certificate_request_in(None, template, priv_key)
}

/// [`create_certificate_request`] with a caller's reader, passed to
/// [`Signer::sign_with_rng`].
pub fn create_certificate_request_with_rng(
    rng: &mut dyn io::Read,
    template: &CertificateRequest,
    priv_key: &dyn Signer,
) -> Result<Vec<u8>, Error> {
    create_certificate_request_in(Some(rng), template, priv_key)
}

fn create_certificate_request_in(
    rand: Option<&mut dyn io::Read>,
    template: &CertificateRequest,
    priv_key: &dyn Signer,
) -> Result<Vec<u8>, Error> {
    let (signature_algorithm, algorithm_identifier) =
        signing_params_for_key(priv_key, template.signature_algorithm)?;

    let pub_enum = PublicKey::from_any(priv_key.public())
        .ok_or_else(|| Error::new("x509: unsupported public key type: unknown"))?;
    let (public_key_bytes, public_key_algorithm) = keys::marshal_public_key(&pub_enum)?;

    let extensions = build_csr_extensions(template)?;

    // Make a copy of template.Attributes because it may be altered below.
    let mut attributes: Vec<pkix::AttributeTypeAndValueSET> = template
        .attributes
        .iter()
        .map(|attr| pkix::AttributeTypeAndValueSET {
            type_: attr.type_.clone(),
            value: attr.value.clone(),
        })
        .collect();

    let mut extensions_appended = false;
    if !extensions.is_empty() {
        // Append the extensions to an existing attribute if possible.
        for atv_set in attributes.iter_mut() {
            if atv_set.type_.0 != OID_EXTENSION_REQUEST || atv_set.value.is_empty() {
                continue;
            }

            // The extensions found specified via template.Attributes.
            let mut specified_extensions: std::collections::HashSet<String> = Default::default();
            for atvs in &atv_set.value {
                for atv in atvs {
                    specified_extensions.insert(atv.type_.to_string());
                }
            }

            let mut new_value: Vec<AttributeTypeAndValue> = atv_set.value[0].clone();
            for e in &extensions {
                if specified_extensions.contains(&e.id.to_string()) {
                    // Attributes already contained a value for this extension
                    // and it takes priority.
                    continue;
                }
                new_value.push(AttributeTypeAndValue {
                    // There is no place for the critical flag in an
                    // AttributeTypeAndValue.
                    type_: e.id.clone(),
                    value: pkix::Value::Bytes(e.value.clone()),
                });
            }

            atv_set.value[0] = new_value;
            extensions_appended = true;
            break;
        }
    }

    let mut raw_attributes: Vec<Vec<u8>> = Vec::new();
    for attr in &attributes {
        raw_attributes.push(attr.marshal()?);
    }

    // If not included in attributes, add a new attribute for the extensions.
    if !extensions.is_empty() && !extensions_appended {
        let mut exts = Vec::new();
        for e in &extensions {
            exts.extend(e.marshal().map_err(|err| {
                Error::new(format!(
                    "x509: failed to serialise extensions attribute: {err}"
                ))
            })?);
        }
        let mut attr = asn1::oid(&OID_EXTENSION_REQUEST).expect("valid OID");
        attr.extend(asn1::tlv(asn1::SET, &asn1::tlv(asn1::SEQUENCE, &exts)));
        raw_attributes.push(asn1::tlv(asn1::SEQUENCE, &attr));
    }

    let asn1_subject = subject_bytes_from(&template.raw_subject, &template.subject)?;

    // tbsCertificateRequest
    let mut tbs = asn1::integer_i64(0); // PKCS #10, RFC 2986
    tbs.extend_from_slice(&asn1_subject);
    let mut spki = public_key_algorithm.marshal()?;
    spki.extend(asn1::bit_string(
        &public_key_bytes,
        public_key_bytes.len() * 8,
    ));
    tbs.extend(asn1::tlv(asn1::SEQUENCE, &spki));
    tbs.extend(asn1::tlv(
        asn1::context_constructed(0),
        &raw_attributes.concat(),
    ));
    let tbs_csr_contents = asn1::tlv(asn1::SEQUENCE, &tbs);

    let signature = sign_tbs(&tbs_csr_contents, priv_key, signature_algorithm, rand)?;

    let mut cr = tbs_csr_contents;
    cr.extend(algorithm_identifier.marshal()?);
    cr.extend(asn1::bit_string(&signature, signature.len() * 8));
    Ok(asn1::tlv(asn1::SEQUENCE, &cr))
}

/// Go's `CreateRevocationList`: creates a new X.509 v2 Certificate Revocation
/// List, according to RFC 5280, based on `template`.
///
/// The CRL is signed by `priv_key`, which should be associated with the public
/// key in the issuer certificate. The issuer may not be `None`, and the
/// crlSign bit must be set in its KeyUsage. The issuer distinguished name CRL
/// field and authority key identifier extension are populated using the issuer
/// certificate, which must have SubjectKeyId set.
pub fn create_revocation_list(
    template: Option<&RevocationList>,
    issuer: Option<&Certificate>,
    priv_key: &dyn Signer,
) -> Result<Vec<u8>, Error> {
    create_revocation_list_in(None, template, issuer, priv_key)
}

/// [`create_revocation_list`] with a caller's reader, passed to
/// [`Signer::sign_with_rng`].
pub fn create_revocation_list_with_rng(
    rng: &mut dyn io::Read,
    template: Option<&RevocationList>,
    issuer: Option<&Certificate>,
    priv_key: &dyn Signer,
) -> Result<Vec<u8>, Error> {
    create_revocation_list_in(Some(rng), template, issuer, priv_key)
}

fn create_revocation_list_in(
    rand: Option<&mut dyn io::Read>,
    template: Option<&RevocationList>,
    issuer: Option<&Certificate>,
    priv_key: &dyn Signer,
) -> Result<Vec<u8>, Error> {
    let Some(template) = template else {
        return Err(Error::new("x509: template can not be nil"));
    };
    let Some(issuer) = issuer else {
        return Err(Error::new("x509: issuer can not be nil"));
    };
    if (issuer.key_usage & KeyUsage::CRL_SIGN).0 == 0 {
        return Err(Error::new(
            "x509: issuer must have the crlSign key usage bit set",
        ));
    }
    if issuer.subject_key_id.is_empty() {
        return Err(Error::new(
            "x509: issuer certificate doesn't contain a subject key identifier",
        ));
    }
    if template.next_update.before(&template.this_update) {
        return Err(Error::new(
            "x509: template.ThisUpdate is after template.NextUpdate",
        ));
    }
    let Some(number) = &template.number else {
        return Err(Error::new("x509: template contains nil Number field"));
    };

    let (signature_algorithm, algorithm_identifier) =
        signing_params_for_key(priv_key, template.signature_algorithm)?;

    // Only process the deprecated RevokedCertificates field if it is populated
    // and the new RevokedCertificateEntries field is not populated.
    let revoked_certs: Vec<pkix::RevokedCertificate> = if !template.revoked_certificates.is_empty()
        && template.revoked_certificate_entries.is_empty()
    {
        // Force revocation times to UTC per RFC 5280.
        template
            .revoked_certificates
            .iter()
            .map(|rc| {
                let mut rc = rc.clone();
                rc.revocation_time = rc.revocation_time.utc();
                rc
            })
            .collect()
    } else {
        // Convert the ReasonCode field to a proper extension, and force
        // revocation times to UTC per RFC 5280.
        let mut out = Vec::new();
        for rce in &template.revoked_certificate_entries {
            let Some(serial) = &rce.serial_number else {
                return Err(Error::new(
                    "x509: template contains entry with nil SerialNumber field",
                ));
            };
            if rce.revocation_time.is_zero() {
                return Err(Error::new(
                    "x509: template contains entry with zero RevocationTime field",
                ));
            }

            let mut rc = pkix::RevokedCertificate {
                serial_number: serial.clone(),
                revocation_time: rce.revocation_time.utc(),
                extensions: Vec::new(),
            };

            // Copy over any extra extensions, except for a Reason Code
            // extension, which is synthesized to ensure it is correct.
            let mut exts: Vec<Extension> = Vec::with_capacity(rce.extra_extensions.len());
            for ext in &rce.extra_extensions {
                if ext.id.0 == OID_EXTENSION_REASON_CODE {
                    return Err(Error::new(
                        "x509: template contains entry with ReasonCode ExtraExtension; use ReasonCode field instead",
                    ));
                }
                exts.push(ext.clone());
            }

            // Only add a reasonCode extension if the reason is non-zero, as per
            // RFC 5280 Section 5.3.1.
            if rce.reason_code != 0 {
                exts.push(Extension {
                    id: ObjectIdentifier(OID_EXTENSION_REASON_CODE.to_vec()),
                    critical: false,
                    value: asn1::enumerated(rce.reason_code),
                });
            }

            if !exts.is_empty() {
                rc.extensions = exts;
            }
            out.push(rc);
        }
        out
    };

    let aki = asn1::tlv(
        asn1::SEQUENCE,
        &asn1::tlv(asn1::context(0), &issuer.subject_key_id),
    );

    let num_bytes = number.bytes();
    if num_bytes.len() > 20 || (num_bytes.len() == 20 && num_bytes[0] & 0x80 != 0) {
        return Err(Error::new("x509: CRL number exceeds 20 octets"));
    }
    let crl_num = asn1::integer_big(number);

    // Correctly use the issuer's subject sequence if one is specified.
    let issuer_subject = subject_bytes_from(&issuer.raw_subject, &issuer.subject)?;

    let mut extensions = vec![
        Extension {
            id: ObjectIdentifier(OID_EXTENSION_AUTHORITY_KEY_ID.to_vec()),
            critical: false,
            value: aki,
        },
        Extension {
            id: ObjectIdentifier(OID_EXTENSION_CRL_NUMBER.to_vec()),
            critical: false,
            value: crl_num,
        },
    ];
    extensions.extend(template.extra_extensions.iter().cloned());

    let mut tbs = asn1::integer_i64(1); // v2
    tbs.extend(algorithm_identifier.marshal()?);
    tbs.extend_from_slice(&issuer_subject);
    tbs.extend(asn1::time(&template.this_update.utc()).ok_or_else(asn1::err_time)?);
    if !template.next_update.is_zero() {
        tbs.extend(asn1::time(&template.next_update.utc()).ok_or_else(asn1::err_time)?);
    }
    if !revoked_certs.is_empty() {
        let mut revoked = Vec::new();
        for rc in &revoked_certs {
            revoked.extend(rc.marshal()?);
        }
        tbs.extend(asn1::tlv(asn1::SEQUENCE, &revoked));
    }
    let mut exts = Vec::new();
    for e in &extensions {
        exts.extend(e.marshal()?);
    }
    tbs.extend(asn1::tlv(
        asn1::context_constructed(0),
        &asn1::tlv(asn1::SEQUENCE, &exts),
    ));
    let tbs_cert_list_contents = asn1::tlv(asn1::SEQUENCE, &tbs);

    let signature = sign_tbs(&tbs_cert_list_contents, priv_key, signature_algorithm, rand)?;

    let mut crl = tbs_cert_list_contents;
    crl.extend(algorithm_identifier.marshal()?);
    crl.extend(asn1::bit_string(&signature, signature.len() * 8));
    Ok(asn1::tlv(asn1::SEQUENCE, &crl))
}

impl Certificate {
    /// Go's `Certificate.CreateCRL`: returns a DER encoded CRL, signed by this
    /// certificate, that contains the given list of revoked certificates.
    ///
    /// Deprecated in Go: this method does not generate an RFC 5280 conformant
    /// X.509 v2 CRL. Use [`create_revocation_list`] instead.
    pub fn create_crl(
        &self,
        priv_key: &dyn Signer,
        revoked_certs: &[pkix::RevokedCertificate],
        now: Time,
        expiry: Time,
    ) -> Result<Vec<u8>, Error> {
        self.create_crl_in(None, priv_key, revoked_certs, now, expiry)
    }

    /// [`Certificate::create_crl`] with a caller's reader, passed to
    /// [`Signer::sign_with_rng`].
    pub fn create_crl_with_rng(
        &self,
        rng: &mut dyn io::Read,
        priv_key: &dyn Signer,
        revoked_certs: &[pkix::RevokedCertificate],
        now: Time,
        expiry: Time,
    ) -> Result<Vec<u8>, Error> {
        self.create_crl_in(Some(rng), priv_key, revoked_certs, now, expiry)
    }

    fn create_crl_in(
        &self,
        rand: Option<&mut dyn io::Read>,
        priv_key: &dyn Signer,
        revoked_certs: &[pkix::RevokedCertificate],
        now: Time,
        expiry: Time,
    ) -> Result<Vec<u8>, Error> {
        let (signature_algorithm, algorithm_identifier) =
            signing_params_for_key(priv_key, SignatureAlgorithm::UNKNOWN_SIGNATURE_ALGORITHM)?;

        // Force revocation times to UTC per RFC 5280.
        let revoked_utc: Vec<pkix::RevokedCertificate> = revoked_certs
            .iter()
            .map(|rc| {
                let mut rc = rc.clone();
                rc.revocation_time = rc.revocation_time.utc();
                rc
            })
            .collect();

        let mut extensions = Vec::new();
        // Authority Key Id
        if !self.subject_key_id.is_empty() {
            extensions.push(Extension {
                id: ObjectIdentifier(OID_EXTENSION_AUTHORITY_KEY_ID.to_vec()),
                critical: false,
                value: asn1::tlv(
                    asn1::SEQUENCE,
                    &asn1::tlv(asn1::context(0), &self.subject_key_id),
                ),
            });
        }

        let mut tbs = asn1::integer_i64(1);
        tbs.extend(algorithm_identifier.marshal()?);
        tbs.extend(self.subject.to_rdn_sequence().marshal()?);
        tbs.extend(asn1::time(&now.utc()).ok_or_else(asn1::err_time)?);
        tbs.extend(asn1::time(&expiry.utc()).ok_or_else(asn1::err_time)?);
        // Go passes a non-nil (possibly empty) slice, which is encoded.
        let mut revoked = Vec::new();
        for rc in &revoked_utc {
            revoked.extend(rc.marshal()?);
        }
        tbs.extend(asn1::tlv(asn1::SEQUENCE, &revoked));
        if !extensions.is_empty() {
            let mut exts = Vec::new();
            for e in &extensions {
                exts.extend(e.marshal()?);
            }
            tbs.extend(asn1::tlv(
                asn1::context_constructed(0),
                &asn1::tlv(asn1::SEQUENCE, &exts),
            ));
        }
        let tbs_cert_list_contents = asn1::tlv(asn1::SEQUENCE, &tbs);

        let signature = sign_tbs(&tbs_cert_list_contents, priv_key, signature_algorithm, rand)?;

        let mut crl = tbs_cert_list_contents;
        crl.extend(algorithm_identifier.marshal()?);
        crl.extend(asn1::bit_string(&signature, signature.len() * 8));
        Ok(asn1::tlv(asn1::SEQUENCE, &crl))
    }
}

#[allow(dead_code)]
fn _unused(_: BitString) {}
