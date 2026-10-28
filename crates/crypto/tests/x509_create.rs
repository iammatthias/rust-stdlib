//! crypto/x509 creation of revocation lists, certificate requests and
//! certificates, ported from Go's x509_test.go.

mod common;

use rust_stdlib_crypto::x509::{
    self, create_certificate, create_certificate_request, create_revocation_list,
    parse_certificate, parse_certificate_request, parse_pkcs8_private_key, parse_revocation_list,
    pem, pkix, BigInt, Certificate, CertificateRequest, ExtKeyUsage, Ip, KeyUsage,
    ObjectIdentifier, PrivateKey, RevocationList, RevocationListEntry, SignatureAlgorithm, Time,
};
use rust_stdlib_crypto::{ecdsa, ed25519, elliptic, mldsa, rsa, Signer};

fn fixture_lines(path: &str) -> Vec<Vec<String>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/x509")
        .join(path);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .lines()
        .map(|l| l.split('\t').map(str::to_string).collect())
        .collect()
}

fn const_der(name: &str) -> Vec<u8> {
    for row in fixture_lines("certs.tsv") {
        if row[0] == name {
            let wrapped = format!("-----BEGIN X-----\n{}\n-----END X-----\n", row[2]);
            return pem::decode(wrapped.as_bytes()).0.unwrap().bytes;
        }
    }
    panic!("no PEM constant {name}");
}

fn zero_plus_hours(h: i64) -> Time {
    Time::ZERO.add_secs(h * 3600)
}

fn big(v: i64) -> Option<BigInt> {
    Some(BigInt::from_i64(v))
}

fn ext(id: &[i64], value: &[u8]) -> pkix::Extension {
    pkix::Extension {
        id: ObjectIdentifier(id.to_vec()),
        critical: false,
        value: value.to_vec(),
    }
}

fn issuer() -> Certificate {
    Certificate {
        key_usage: KeyUsage::CRL_SIGN,
        subject: pkix::Name {
            common_name: "testing".to_string(),
            ..pkix::Name::default()
        },
        subject_key_id: vec![1, 2, 3],
        ..Certificate::default()
    }
}

fn entry(serial: i64) -> RevocationListEntry {
    RevocationListEntry {
        serial_number: big(serial),
        revocation_time: zero_plus_hours(1),
        ..RevocationListEntry::default()
    }
}

fn list(entries: Vec<RevocationListEntry>) -> RevocationList {
    RevocationList {
        revoked_certificate_entries: entries,
        number: big(5),
        this_update: zero_plus_hours(24),
        next_update: zero_plus_hours(48),
        ..RevocationList::default()
    }
}

fn auth_key_id(id: &[u8]) -> Vec<u8> {
    // SEQUENCE { [0] IMPLICIT OCTET STRING }
    let mut inner = vec![0x80, id.len() as u8];
    inner.extend_from_slice(id);
    let mut out = vec![0x30, inner.len() as u8];
    out.extend(inner);
    out
}

#[test]
fn create_revocation_list_table() {
    let ec256 = ecdsa::generate_key(elliptic::p256()).unwrap();
    let (_, ed_key) = ed25519::generate_key().unwrap();
    let mldsa_key = mldsa::generate_key(mldsa::mldsa44()).unwrap();

    // A CA with UTF-8 subject fields, including the email address
    // (`utf8CAStr` and `utf8KeyStr` of Go's test).
    let utf8_ca = parse_certificate(&base64_of(UTF8_CA)).unwrap();
    let utf8_key = match parse_pkcs8_private_key(&base64_of(UTF8_KEY)).unwrap() {
        PrivateKey::Rsa(k) => k,
        other => panic!("{other:?}"),
    };

    struct Case<'a> {
        name: &'a str,
        key: &'a dyn Signer,
        issuer: Option<Certificate>,
        template: Option<RevocationList>,
        err: &'a str,
    }
    let long_number = |first: u8, zeros: usize| {
        let mut bytes = vec![first];
        bytes.extend(vec![0u8; zeros]);
        Some(BigInt::from_be_bytes(&bytes))
    };
    let dated = |number: Option<BigInt>| RevocationList {
        this_update: zero_plus_hours(24),
        next_update: zero_plus_hours(48),
        number,
        ..RevocationList::default()
    };
    let cases = vec![
        Case {
            name: "nil template",
            key: &ec256,
            issuer: None,
            template: None,
            err: "x509: template can not be nil",
        },
        Case {
            name: "nil issuer",
            key: &ec256,
            issuer: None,
            template: Some(RevocationList::default()),
            err: "x509: issuer can not be nil",
        },
        Case {
            name: "issuer doesn't have crlSign key usage bit set",
            key: &ec256,
            issuer: Some(Certificate {
                key_usage: KeyUsage::CERT_SIGN,
                ..Certificate::default()
            }),
            template: Some(RevocationList::default()),
            err: "x509: issuer must have the crlSign key usage bit set",
        },
        Case {
            name: "issuer missing SubjectKeyId",
            key: &ec256,
            issuer: Some(Certificate {
                key_usage: KeyUsage::CRL_SIGN,
                ..Certificate::default()
            }),
            template: Some(RevocationList::default()),
            err: "x509: issuer certificate doesn't contain a subject key identifier",
        },
        Case {
            name: "nextUpdate before thisUpdate",
            key: &ec256,
            issuer: Some(issuer()),
            template: Some(RevocationList {
                this_update: zero_plus_hours(1),
                next_update: Time::ZERO,
                ..RevocationList::default()
            }),
            err: "x509: template.ThisUpdate is after template.NextUpdate",
        },
        Case {
            name: "nil Number",
            key: &ec256,
            issuer: Some(issuer()),
            template: Some(dated(None)),
            err: "x509: template contains nil Number field",
        },
        Case {
            name: "long Number",
            key: &ec256,
            issuer: Some(issuer()),
            template: Some(dated(long_number(1, 20))),
            err: "x509: CRL number exceeds 20 octets",
        },
        Case {
            name: "long Number (20 bytes, MSB set)",
            key: &ec256,
            issuer: Some(issuer()),
            template: Some(dated(long_number(255, 19))),
            err: "x509: CRL number exceeds 20 octets",
        },
        Case {
            name: "invalid signature algorithm",
            key: &ec256,
            issuer: Some(issuer()),
            template: Some(RevocationList {
                signature_algorithm: SignatureAlgorithm::SHA256_WITH_RSA,
                revoked_certificates: vec![pkix::RevokedCertificate {
                    serial_number: BigInt::from_i64(2),
                    revocation_time: zero_plus_hours(1),
                    extensions: vec![],
                }],
                ..list(vec![])
            }),
            err: "x509: requested SignatureAlgorithm does not match private key type",
        },
        Case {
            name: "valid",
            key: &ec256,
            issuer: Some(issuer()),
            template: Some(list(vec![entry(2)])),
            err: "",
        },
        Case {
            name: "valid, reason code",
            key: &ec256,
            issuer: Some(issuer()),
            template: Some(list(vec![RevocationListEntry {
                reason_code: 1,
                ..entry(2)
            }])),
            err: "",
        },
        Case {
            name: "valid, extra entry extension",
            key: &ec256,
            issuer: Some(issuer()),
            template: Some(list(vec![RevocationListEntry {
                extra_extensions: vec![ext(&[2, 5, 29, 99], &[5, 0])],
                ..entry(2)
            }])),
            err: "",
        },
        Case {
            name: "valid, Ed25519 key",
            key: &ed_key,
            issuer: Some(issuer()),
            template: Some(list(vec![entry(2)])),
            err: "",
        },
        Case {
            name: "valid, non-default signature algorithm",
            key: &ec256,
            issuer: Some(issuer()),
            template: Some(RevocationList {
                signature_algorithm: SignatureAlgorithm::ECDSA_WITH_SHA512,
                ..list(vec![entry(2)])
            }),
            err: "",
        },
        Case {
            name: "valid, extra extension",
            key: &ec256,
            issuer: Some(issuer()),
            template: Some(RevocationList {
                extra_extensions: vec![ext(&[2, 5, 29, 99], &[5, 0])],
                ..list(vec![entry(2)])
            }),
            err: "",
        },
        Case {
            name: "valid, deprecated entries with extension",
            key: &ec256,
            issuer: Some(issuer()),
            template: Some(RevocationList {
                revoked_certificates: vec![pkix::RevokedCertificate {
                    serial_number: BigInt::from_i64(2),
                    revocation_time: zero_plus_hours(1),
                    extensions: vec![ext(&[2, 5, 29, 99], &[5, 0])],
                }],
                ..list(vec![])
            }),
            err: "",
        },
        Case {
            name: "valid, empty list",
            key: &ec256,
            issuer: Some(issuer()),
            template: Some(list(vec![])),
            err: "",
        },
        Case {
            name: "valid CA with utf8 Subject fields including Email, empty list",
            key: &utf8_key,
            issuer: Some(utf8_ca),
            template: Some(list(vec![])),
            err: "",
        },
        Case {
            name: "valid, ML-DSA-44 key",
            key: &mldsa_key,
            issuer: Some(issuer()),
            template: Some(list(vec![entry(2)])),
            err: "",
        },
    ];
    for case in cases {
        let result = create_revocation_list(case.template.as_ref(), case.issuer.as_ref(), case.key);
        let crl = match result {
            Err(e) => {
                assert!(
                    !case.err.is_empty(),
                    "{}: failed unexpectedly: {e}",
                    case.name
                );
                assert_eq!(e.to_string(), case.err, "{}", case.name);
                continue;
            }
            Ok(crl) => {
                assert!(
                    case.err.is_empty(),
                    "{}: didn't fail, expected: {}",
                    case.name,
                    case.err
                );
                crl
            }
        };
        let template = case.template.unwrap();
        let issuer = case.issuer.unwrap();
        let parsed = parse_revocation_list(&crl).unwrap_or_else(|e| panic!("{}: {e}", case.name));
        if template.signature_algorithm != SignatureAlgorithm::UNKNOWN_SIGNATURE_ALGORITHM {
            assert_eq!(
                parsed.signature_algorithm, template.signature_algorithm,
                "{}",
                case.name
            );
        }
        if !template.revoked_certificates.is_empty() {
            assert_eq!(
                parsed.revoked_certificates, template.revoked_certificates,
                "{}",
                case.name
            );
        } else {
            assert_eq!(
                parsed.revoked_certificate_entries.len(),
                template.revoked_certificate_entries.len(),
                "{}",
                case.name
            );
            for (rce, expected) in parsed
                .revoked_certificate_entries
                .iter()
                .zip(&template.revoked_certificate_entries)
            {
                assert_eq!(rce.serial_number, expected.serial_number, "{}", case.name);
                assert!(
                    rce.revocation_time.equal(&expected.revocation_time),
                    "{}",
                    case.name
                );
                assert_eq!(rce.reason_code, expected.reason_code, "{}", case.name);
            }
        }
        assert_eq!(
            parsed.extensions.len(),
            2 + template.extra_extensions.len(),
            "{}",
            case.name
        );
        assert_eq!(
            parsed.extensions[0],
            ext(&[2, 5, 29, 35], &auth_key_id(&issuer.subject_key_id)),
            "{}",
            case.name
        );
        let number = template.number.as_ref().unwrap();
        let mut number_der = vec![0x02];
        let mut bytes = number.bytes();
        if bytes.is_empty() || bytes[0] & 0x80 != 0 {
            bytes.insert(0, 0);
        }
        number_der.push(bytes.len() as u8);
        number_der.extend(bytes);
        assert_eq!(
            parsed.extensions[1],
            ext(&[2, 5, 29, 20], &number_der),
            "{}",
            case.name
        );
        if !issuer.raw_subject.is_empty() {
            assert_eq!(parsed.raw_issuer, issuer.raw_subject, "{}", case.name);
        } else {
            let mut want = pkix::Name::default();
            want.fill_from_rdn_sequence(&issuer.subject.to_rdn_sequence());
            assert_eq!(parsed.issuer, want, "{}", case.name);
        }
        assert_eq!(
            &parsed.extensions[2..],
            template.extra_extensions.as_slice(),
            "{}",
            case.name
        );
        assert_eq!(parsed.number.as_ref(), Some(number), "{}", case.name);
        assert_eq!(
            parsed.authority_key_id, issuer.subject_key_id,
            "{}",
            case.name
        );
    }
}

// The CA and key of Go's TestCreateRevocationList: UTF-8 Subject fields,
// including the email address.
const UTF8_CA: &str = "MIIEITCCAwmgAwIBAgIUXHXy7NdtDv+ClaHvIvlwCYiI4a4wDQYJKoZIhvcNAQELBQAwgZoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMR8wHQYDVQQKDBZJbnRlcm5ldCBXaWRnZXRzLCBJbmMuMQwwCgYDVQQLDANXV1cxDTALBgNVBAMMBFJvb3QxIDAeBgkqhkiG9w0BCQEWEWFkbWluQGV4YW1wbGUuY29tMB4XDTIyMDcwODE1MzgyMFoXDTIzMDcwODE1MzgyMFowgZoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMR8wHQYDVQQKDBZJbnRlcm5ldCBXaWRnZXRzLCBJbmMuMQwwCgYDVQQLDANXV1cxDTALBgNVBAMMBFJvb3QxIDAeBgkqhkiG9w0BCQEWEWFkbWluQGV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmXvp0WNjsZzySWT7Ce5zewQNKq8ujeZGphJ44Vdrwut/b6TcC4iYENds5+7/3PYwBllp3K5TRpCcafSxdhJsvA7/zWlHHNRcJhJLNt9qsKWP6ukI2Iw6OmFMg6kJQ8f67RXkT8HR3v0UqE+lWrA0g+oRuj4erLtfOtSpnl4nsE/Rs2qxbELFWAf7F5qMqH4dUyveWKrNT8eI6YQN+wBg0MAjoKRvDJnBhuo+IvvXX8Aq1QWUcBGPK3or/Ehxy5f/gEmSUXyEU1Ht/vATt2op+eRaEEpBdGRvO+DrKjlcQV2XMN18A9LAX6hCzH43sGye87dj7RZ9yj+waOYNaM7kFQIDAQABo10wWzAdBgNVHQ4EFgQUtbSlrW4hGL2kNjviM6wcCRwvOEEwHwYDVR0jBBgwFoAUtbSlrW4hGL2kNjviM6wcCRwvOEEwDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAbYwDQYJKoZIhvcNAQELBQADggEBAAko82YNNI2n/45L3ya21vufP6nZihIOIxgcRPUMX+IDJZk16qsFdcLgH3KAP8uiVLn8sULuCj35HpViR4IcAk2d+DqfG11l8kY+e5P7nYsViRfy0AatF59/sYlWf+3RdmPXfL70x4mE9OqlMdDm0kR2obps8rng83VLDNvj3R5sBnQwdw6LKLGzaE+RiCTmkH0+P6vnbOJ33su9+9al1+HvJUg3UM1Xq5Bw7TE8DQTetMV3c2Q35RQaJB9pQ4blJOnW9hfnt8yQzU6TU1bU4mRctTm1o1f8btPqUpi+/blhi5MUJK0/myj1XD00pmyfp8QAFl1EfqmTMIBMLg633A0=";
const UTF8_KEY: &str = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCZe+nRY2OxnPJJZPsJ7nN7BA0qry6N5kamEnjhV2vC639vpNwLiJgQ12zn7v/c9jAGWWncrlNGkJxp9LF2Emy8Dv/NaUcc1FwmEks232qwpY/q6QjYjDo6YUyDqQlDx/rtFeRPwdHe/RSoT6VasDSD6hG6Ph6su1861KmeXiewT9GzarFsQsVYB/sXmoyofh1TK95Yqs1Px4jphA37AGDQwCOgpG8MmcGG6j4i+9dfwCrVBZRwEY8reiv8SHHLl/+ASZJRfIRTUe3+8BO3ain55FoQSkF0ZG874OsqOVxBXZcw3XwD0sBfqELMfjewbJ7zt2PtFn3KP7Bo5g1ozuQVAgMBAAECggEAIscjKiD9PAe2Fs9c2tk/LYazfRKI1/pv072nylfGwToffCq8+ZgP7PEDamKLc4QNScME685MbFbkOlYJyBlQriQv7lmGlY/A+Zd3l410XWaGf9IiAP91Sjk13zd0M/micApf23qtlXt/LMwvSadXnvRw4+SjirxCTdBWRt5K2/ZAN550v7bHFk1EZc3UBF6sOoNsjQWh9Ek79UmQYJBPiZDBHO7O2fh2GSIbUutTma+Tb2i1QUZzg+AG3cseF3p1i3uhNrCh+p+01bJSzGTQsRod2xpD1tpWwR3kIftCOmD1XnhpaBQi7PXjEuNbfucaftnoYj2ShDdmgD5RkkbTAQKBgQC8Ghu5MQ/yIeqXg9IpcSxuWtUEAEfK33/cC/IvuntgbNEnWQm5Lif4D6a9zjkxiCS+9HhrUu5U2EV8NxOyaqmtub3Np1Z5mPuI9oiZ119bjUJd4X+jKOTaePWvOv/rL/pTHYqzXohVMrXy+DaTIq4lOcv3n72SuhuTcKU95rhKtQKBgQDQ4t+HsRZd5fJzoCgRQhlNK3EbXQDv2zXqMW3GfpF7GaDP18I530inRURSJa++rvi7/MCFg/TXVS3QC4HXtbzTYTqhE+VHzSr+/OcsqpLE8b0jKBDv/SBkz811PUJDs3LsX31DT3K0zUpMpNSd/5SYTyJKef9L6mxmwlC1S2Yv4QKBgQC57SiYDdnQIRwrtZ2nXvlm/xttAAX2jqJoU9qIuNA4yHaYaRcGVowlUvsiw9OelQ6VPTpGA0wWy0src5lhkrKzSFRHEe+U89U1VVJCljLoYKFIAJvUH5jOJh/am/vYca0COMIfeAJUDHLyfcwb9XyiyRVGZzvP62tUelSq8gIZvQKBgCAHeaDzzWsudCO4ngwvZ3PGwnwgoaElqrmzRJLYG3SVtGvKOJTpINnNLDGwZ6dEaw1gLyEJ38QY4oJxEULDMiXzVasXQuPkmMAqhUP7D7A1JPw8C4TQ+mOa3XUppHx/CpMl/S4SA5OnmsnvyE5Fv0IveCGVXUkFtAN5rihuXEfhAoGANUkuGU3A0Upk2mzv0JTGP4H95JFG93cqnyPNrYs30M6RkZNgTW27yyr+Nhs4/cMdrg1AYTB0+6ItQWSDmYLs7JEbBE/8L8fdD1irIcygjIHE9nJh96TgZCt61kVGLE8758lOdmoB2rZOpGwi16QIhdQb+IyozYqfX+lQUojL/W0=";

fn base64_of(text: &str) -> Vec<u8> {
    let wrapped = format!("-----BEGIN X-----\n{text}\n-----END X-----\n");
    pem::decode(wrapped.as_bytes()).0.unwrap().bytes
}

fn test_key_rsa() -> rsa::PrivateKey {
    match parse_pkcs8_private_key(&base64_of(UTF8_KEY)).unwrap() {
        PrivateKey::Rsa(k) => k,
        other => panic!("{other:?}"),
    }
}

#[test]
fn create_certificate_request_for_every_key_type() {
    let rsa_key = test_key_rsa();
    let ec256 = ecdsa::generate_key(elliptic::p256()).unwrap();
    let ec384 = ecdsa::generate_key(elliptic::p384()).unwrap();
    let ec521 = ecdsa::generate_key(elliptic::p521()).unwrap();
    let (_, ed) = ed25519::generate_key().unwrap();
    let ml = mldsa::generate_key(mldsa::mldsa44()).unwrap();
    let tests: Vec<(&str, &dyn Signer, SignatureAlgorithm)> = vec![
        ("RSA", &rsa_key, SignatureAlgorithm::SHA256_WITH_RSA),
        (
            "RSA-PSS-SHA256",
            &rsa_key,
            SignatureAlgorithm::SHA256_WITH_RSAPSS,
        ),
        ("ECDSA-256", &ec256, SignatureAlgorithm::ECDSA_WITH_SHA256),
        ("ECDSA-384", &ec384, SignatureAlgorithm::ECDSA_WITH_SHA256),
        ("ECDSA-521", &ec521, SignatureAlgorithm::ECDSA_WITH_SHA256),
        ("Ed25519", &ed, SignatureAlgorithm::PURE_ED25519),
        ("ML-DSA-44", &ml, SignatureAlgorithm::MLDSA44),
    ];
    for (name, key, sig_algo) in tests {
        let template = CertificateRequest {
            subject: pkix::Name {
                common_name: "test.example.com".to_string(),
                organization: vec!["\u{3a3} Acme Co".to_string()],
                ..pkix::Name::default()
            },
            signature_algorithm: sig_algo,
            dns_names: vec!["test.example.com".to_string()],
            email_addresses: vec!["gopher@golang.org".to_string()],
            ip_addresses: vec![
                Ip(vec![127, 0, 0, 1]),
                x509::parse_ip("2001:4860:0:2001::68").unwrap(),
            ],
            ..CertificateRequest::default()
        };
        let der = create_certificate_request(&template, key)
            .unwrap_or_else(|e| panic!("{name}: failed to create certificate request: {e}"));
        let out = parse_certificate_request(&der).unwrap_or_else(|e| panic!("{name}: {e}"));
        out.check_signature()
            .unwrap_or_else(|e| panic!("{name}: signature: {e}"));
        assert_eq!(
            out.subject.common_name, template.subject.common_name,
            "{name}"
        );
        assert_eq!(
            out.subject.organization, template.subject.organization,
            "{name}"
        );
        assert_eq!(out.dns_names, template.dns_names, "{name}");
        assert_eq!(out.email_addresses, template.email_addresses, "{name}");
        assert_eq!(
            out.ip_addresses.len(),
            template.ip_addresses.len(),
            "{name}"
        );
    }
}

fn marshal_and_parse_csr(template: &CertificateRequest) -> CertificateRequest {
    let key = test_key_rsa();
    let der = create_certificate_request(template, &key).unwrap();
    parse_certificate_request(&der).unwrap()
}

/// `marshalSANs` for DNS names.
fn san_contents(names: &[&str]) -> Vec<u8> {
    let mut inner = Vec::new();
    for n in names {
        inner.push(0x82);
        inner.push(n.len() as u8);
        inner.extend_from_slice(n.as_bytes());
    }
    let mut out = vec![0x30, inner.len() as u8];
    out.extend(inner);
    out
}

#[test]
fn certificate_request_overrides() {
    let san_oid = [2, 5, 29, 17];
    let mut template = CertificateRequest {
        subject: pkix::Name {
            common_name: "test.example.com".to_string(),
            organization: vec!["\u{3a3} Acme Co".to_string()],
            ..pkix::Name::default()
        },
        dns_names: vec!["test.example.com".to_string()],
        // An explicit extension overrides the DNSNames of the template.
        extra_extensions: vec![pkix::Extension {
            id: ObjectIdentifier(san_oid.to_vec()),
            value: san_contents(&["foo.example.com"]),
            critical: true,
        }],
        ..CertificateRequest::default()
    };
    let csr = marshal_and_parse_csr(&template);
    assert_eq!(csr.dns_names, vec!["foo.example.com".to_string()]);
    assert!(
        csr.extensions.len() == 1
            && csr.extensions[0].id.0 == san_oid
            && csr.extensions[0].critical
    );

    // If an attribute already holds X.509 extensions the extra extensions are
    // added to it instead of creating a CSR with two extension attributes.
    let ext_request = ObjectIdentifier(vec![1, 2, 840, 113549, 1, 9, 14]);
    template.attributes = vec![pkix::AttributeTypeAndValueSET {
        type_: ext_request.clone(),
        value: vec![vec![pkix::AttributeTypeAndValue {
            type_: ObjectIdentifier(vec![1, 3, 6, 1, 5, 5, 7, 1, 1]),
            value: pkix::Value::Bytes(b"foo".to_vec()),
        }]],
    }];
    let csr = marshal_and_parse_csr(&template);
    assert_eq!(csr.attributes.len(), 1);
    assert!(csr.attributes[0].type_.equal(&ext_request));
    assert_eq!(csr.attributes[0].value.len(), 1);
    assert_eq!(csr.attributes[0].value[0].len(), 2);

    // Extensions in Attributes override those in ExtraExtensions.
    template.attributes[0].value[0].push(pkix::AttributeTypeAndValue {
        type_: ObjectIdentifier(san_oid.to_vec()),
        value: pkix::Value::Bytes(san_contents(&["foo2.example.com"])),
    });
    let csr = marshal_and_parse_csr(&template);
    assert_eq!(csr.dns_names, vec!["foo2.example.com".to_string()]);
}

#[test]
fn parse_certificate_request_from_openssl() {
    for index in 0..2 {
        let csr =
            parse_certificate_request(&const_der(&format!("csrBase64Array.{index}"))).unwrap();
        assert_eq!(csr.email_addresses, vec!["gopher@golang.org".to_string()]);
        assert_eq!(csr.dns_names, vec!["test.example.com".to_string()]);
        assert_eq!(csr.subject.country, vec!["AU".to_string()]);
        assert!(
            csr.extensions.iter().any(|e| e.id.0 == [2, 5, 29, 19]),
            "basic constraints extension not found in CSR"
        );
    }
}

#[test]
fn max_path_len() {
    let k = ecdsa::generate_key(elliptic::p256()).unwrap();
    let base = Certificate {
        serial_number: big(1),
        subject: pkix::Name {
            common_name: "Root".to_string(),
            ..pkix::Name::default()
        },
        not_before: Time::unix(0, 0),
        not_after: Time::unix(1 << 33, 0),
        basic_constraints_valid: true,
        is_ca: true,
        ..Certificate::default()
    };
    // (maxPathLen, maxPathLenZero, expected parsed maxPathLen, expected zero)
    for (len, zero, want_len, want_zero) in [
        (-1, false, -1, false),
        (0, false, -1, false),
        (0, true, 0, true),
        (1, false, 1, false),
        (3, false, 3, false),
    ] {
        let tmpl = Certificate {
            max_path_len: len,
            max_path_len_zero: zero,
            ..base.clone()
        };
        let der = create_certificate(&tmpl, &tmpl, &k.public_key, &k).unwrap();
        let cert = parse_certificate(&der).unwrap();
        assert_eq!(
            (cert.max_path_len, cert.max_path_len_zero),
            (want_len, want_zero),
            "{len} {zero}"
        );
    }

    // Only CAs may specify MaxPathLen.
    let not_ca = Certificate {
        is_ca: false,
        max_path_len: 1,
        ..base.clone()
    };
    let err = create_certificate(&not_ca, &not_ca, &k.public_key, &k).unwrap_err();
    assert_eq!(
        err.to_string(),
        "x509: only CAs are allowed to specify MaxPathLen"
    );

    let negative = Certificate {
        max_path_len: -2,
        ..base
    };
    let err = create_certificate(&negative, &negative, &k.public_key, &k).unwrap_err();
    assert_eq!(
        err.to_string(),
        "x509: invalid MaxPathLen, must be greater or equal to -1"
    );
}

#[test]
fn create_certificate_with_every_key_type() {
    let rsa_key = test_key_rsa();
    let ec = ecdsa::generate_key(elliptic::p256()).unwrap();
    let (_, ed) = ed25519::generate_key().unwrap();
    let ml = mldsa::generate_key(mldsa::mldsa65()).unwrap();
    let keys: Vec<(&str, &dyn Signer, &dyn std::any::Any)> = vec![
        ("RSA", &rsa_key, &rsa_key.public_key),
        ("ECDSA", &ec, &ec.public_key),
        ("Ed25519", &ed, ed.public()),
        ("ML-DSA", &ml, ml.public()),
    ];
    for (name, signer, public) in keys {
        let tmpl = Certificate {
            serial_number: big(7),
            subject: pkix::Name {
                common_name: "self".to_string(),
                ..pkix::Name::default()
            },
            not_before: Time::unix(1000, 0),
            not_after: Time::unix(2000, 0),
            key_usage: KeyUsage::CERT_SIGN | KeyUsage::DIGITAL_SIGNATURE,
            ext_key_usage: vec![ExtKeyUsage::SERVER_AUTH],
            basic_constraints_valid: true,
            is_ca: true,
            dns_names: vec!["example.com".to_string()],
            ..Certificate::default()
        };
        let der = create_certificate(&tmpl, &tmpl, public, signer)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let cert = parse_certificate(&der).unwrap();
        cert.check_signature_from(&cert)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(cert.subject_key_id.len(), 20, "{name}");
    }
}

#[test]
fn create_certificate_rejects_mismatched_signer() {
    let a = ecdsa::generate_key(elliptic::p256()).unwrap();
    let b = ecdsa::generate_key(elliptic::p256()).unwrap();
    let parent_der = {
        let tmpl = Certificate {
            serial_number: big(1),
            subject: pkix::Name {
                common_name: "parent".to_string(),
                ..pkix::Name::default()
            },
            not_before: Time::unix(0, 0),
            not_after: Time::unix(1 << 33, 0),
            basic_constraints_valid: true,
            is_ca: true,
            ..Certificate::default()
        };
        create_certificate(&tmpl, &tmpl, &a.public_key, &a).unwrap()
    };
    let parent = parse_certificate(&parent_der).unwrap();
    let child = Certificate {
        serial_number: big(2),
        not_before: Time::unix(0, 0),
        not_after: Time::unix(1 << 33, 0),
        ..Certificate::default()
    };
    let err = create_certificate(&child, &parent, &b.public_key, &b).unwrap_err();
    assert_eq!(
        err.to_string(),
        "x509: provided PrivateKey doesn't match parent's PublicKey"
    );
}
