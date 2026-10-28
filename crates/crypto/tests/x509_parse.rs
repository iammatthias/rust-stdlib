//! crypto/x509 parsing and pkix names, ported from Go's x509_test.go. The PEM
//! constants are extracted from Go's source by tools/x509_vectors_gen.py.

mod common;

use rust_stdlib_crypto::x509::{
    self, create_certificate, parse_certificate, parse_certificate_request, parse_certificates,
    pem, pkix, BigInt, Certificate, ExtKeyUsage, InsecureAlgorithmError, Ip, KeyUsage,
    ObjectIdentifier, PublicKey, PublicKeyAlgorithm, SignatureAlgorithm, Time,
};
use rust_stdlib_crypto::{ecdsa, elliptic};

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

fn parse_const(name: &str) -> Certificate {
    parse_certificate(&const_der(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn atv(type_: &[i64], value: pkix::Value) -> pkix::AttributeTypeAndValue {
    pkix::AttributeTypeAndValue {
        type_: ObjectIdentifier(type_.to_vec()),
        value,
    }
}

fn s(text: &str) -> pkix::Value {
    pkix::Value::String(text.to_string())
}

#[test]
fn pkix_name_string() {
    let certs = parse_certificates(&const_der("certBytes")).unwrap();

    // Parsed non-standard attributes are printed.
    let rdns = pkix::Name {
        locality: vec!["Gophertown".to_string()],
        extra_names: Some(vec![atv(&[1, 2, 3, 4, 5], s("golang.org"))]),
        ..pkix::Name::default()
    }
    .to_rdn_sequence();
    let mut nn = pkix::Name::default();
    nn.fill_from_rdn_sequence(&rdns);

    // Zero-length non-nil ExtraNames hide Names.
    let extra_not_nil = pkix::Name {
        locality: vec!["Gophertown".to_string()],
        extra_names: Some(vec![]),
        names: vec![atv(&[1, 2, 3, 4, 5], s("golang.org"))],
        ..pkix::Name::default()
    };

    let extra = |oid: &[i64], v: pkix::Value| Some(vec![atv(oid, v)]);
    let tests: Vec<(pkix::Name, &str)> = vec![
        (nn, "L=Gophertown,1.2.3.4.5=golang.org"),
        (extra_not_nil, "L=Gophertown"),
        (
            pkix::Name {
                common_name: "Steve Kille".to_string(),
                organization: vec!["Isode Limited".to_string()],
                organizational_unit: vec!["RFCs".to_string()],
                locality: vec!["Richmond".to_string()],
                province: vec!["Surrey".to_string()],
                street_address: vec!["The Square".to_string()],
                postal_code: vec!["TW9 1DT".to_string()],
                serial_number: "RFC 2253".to_string(),
                country: vec!["GB".to_string()],
                ..pkix::Name::default()
            },
            "SERIALNUMBER=RFC 2253,CN=Steve Kille,OU=RFCs,O=Isode Limited,POSTALCODE=TW9 1DT,STREET=The Square,L=Richmond,ST=Surrey,C=GB",
        ),
        (
            certs[0].subject.clone(),
            "CN=mail.google.com,O=Google LLC,L=Mountain View,ST=California,C=US",
        ),
        (
            pkix::Name {
                organization: vec!["#Google, Inc. \n-> 'Alphabet\" ".to_string()],
                country: vec!["US".to_string()],
                ..pkix::Name::default()
            },
            "O=\\#Google\\, Inc. \n-\\> 'Alphabet\\\"\\ ,C=US",
        ),
        (
            pkix::Name {
                common_name: "foo.com".to_string(),
                organization: vec!["Gopher Industries".to_string()],
                extra_names: extra(&[2, 5, 4, 3], s("bar.com")),
                ..pkix::Name::default()
            },
            "CN=bar.com,O=Gopher Industries",
        ),
        (
            pkix::Name {
                locality: vec!["Gophertown".to_string()],
                extra_names: extra(&[1, 2, 3, 4, 5], s("golang.org")),
                ..pkix::Name::default()
            },
            "1.2.3.4.5=golang.org,L=Gophertown",
        ),
        // If there are no ExtraNames, the Names are printed instead.
        (
            pkix::Name {
                locality: vec!["Gophertown".to_string()],
                names: vec![atv(&[1, 2, 3, 4, 5], s("golang.org"))],
                ..pkix::Name::default()
            },
            "L=Gophertown,1.2.3.4.5=golang.org",
        ),
        // If there are both, print only the ExtraNames.
        (
            pkix::Name {
                locality: vec!["Gophertown".to_string()],
                extra_names: extra(&[1, 2, 3, 4, 5], s("golang.org")),
                names: vec![atv(&[1, 2, 3, 4, 6], s("example.com"))],
                ..pkix::Name::default()
            },
            "1.2.3.4.5=golang.org,L=Gophertown",
        ),
        // A non-string value falls back to hex-encoded DER (issue 33093).
        (
            pkix::Name {
                common_name: "foobar".to_string(),
                extra_names: extra(&[1, 2, 3, 4], pkix::Value::Int(42)),
                ..pkix::Name::default()
            },
            "1.2.3.4=#02012a,CN=foobar",
        ),
        // A UTF-8 string is rendered as a string per RFC 2253 section 2.4.
        (
            pkix::Name {
                common_name: "foobar".to_string(),
                extra_names: extra(&[2, 3, 4, 5], s("Lu\u{10d}i\u{107}")),
                ..pkix::Name::default()
            },
            "2.3.4.5=Lu\u{10d}i\u{107},CN=foobar",
        ),
        // A string beginning with '#' has the '#' escaped.
        (
            pkix::Name {
                common_name: "foobar".to_string(),
                extra_names: extra(&[2, 3, 4, 5], s("#abcdef")),
                ..pkix::Name::default()
            },
            "2.3.4.5=\\#abcdef,CN=foobar",
        ),
        (
            pkix::Name {
                common_name: "foobar".to_string(),
                extra_names: extra(&[2, 3, 4, 5], s("abcdef,GHI")),
                ..pkix::Name::default()
            },
            "2.3.4.5=abcdef\\,GHI,CN=foobar",
        ),
        // Leading and trailing space gets escaped.
        (
            pkix::Name {
                common_name: "foobar".to_string(),
                extra_names: extra(&[2, 3, 4, 5], s("   abcdef ")),
                ..pkix::Name::default()
            },
            "2.3.4.5=\\   abcdef\\ ,CN=foobar",
        ),
    ];
    for (i, (dn, want)) in tests.iter().enumerate() {
        assert_eq!(&dn.to_string(), want, "#{i}");
    }
}

#[test]
fn rdn_sequence_string() {
    // Multi-valued attributes get lost in pkix.Name conversions.
    let seq = pkix::RDNSequence(vec![
        pkix::RelativeDistinguishedNameSET(vec![atv(&[2, 5, 4, 6], s("US"))]),
        pkix::RelativeDistinguishedNameSET(vec![atv(&[2, 5, 4, 10], s("Widget Inc."))]),
        pkix::RelativeDistinguishedNameSET(vec![
            atv(&[2, 5, 4, 11], s("Sales")),
            atv(&[2, 5, 4, 3], s("J. Smith")),
        ]),
    ]);
    assert_eq!(seq.to_string(), "OU=Sales+CN=J. Smith,O=Widget Inc.,C=US");
}

#[test]
fn multiple_rdn() {
    let cert = parse_const("certMultipleRDN");
    assert_eq!(cert.subject.common_name, "eportal.mss.edus.si");
    assert_eq!(cert.subject.serial_number, "1236484010010");
}

#[test]
fn certificate_equal_and_raw() {
    let cert = parse_const("pemCertificate");
    assert_eq!(cert.raw, const_der("pemCertificate"));
    assert!(cert.equal(&parse_const("pemCertificate")));
    assert!(!cert.equal(&Certificate::default()));
}

#[test]
fn mismatched_signature_algorithm() {
    let cert = parse_const("rsaPSSSelfSignedPEM");
    let err = cert
        .check_signature(SignatureAlgorithm::ECDSA_WITH_SHA256, &[], &[])
        .unwrap_err();
    assert!(
        err.to_string().contains(" but have public key of type "),
        "{err}"
    );
}

#[test]
fn ecdsa_certificates() {
    for (name, algo) in [
        (
            "ecdsaSHA256p256CertPem",
            SignatureAlgorithm::ECDSA_WITH_SHA256,
        ),
        (
            "ecdsaSHA256p384CertPem",
            SignatureAlgorithm::ECDSA_WITH_SHA256,
        ),
        (
            "ecdsaSHA384p521CertPem",
            SignatureAlgorithm::ECDSA_WITH_SHA384,
        ),
    ] {
        let cert = parse_const(name);
        assert_eq!(cert.signature_algorithm, algo, "{name}");
        assert!(
            matches!(cert.public_key, Some(PublicKey::Ecdsa(_))),
            "{name}"
        );
        assert_eq!(
            cert.public_key_algorithm,
            PublicKeyAlgorithm::ECDSA,
            "{name}"
        );
        cert.check_signature_from(&cert)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    // The SHA-1 certificate parses, but its signature is insecure.
    let cert = parse_const("ecdsaSHA1CertPem");
    assert_eq!(
        cert.signature_algorithm,
        SignatureAlgorithm::ECDSA_WITH_SHA1
    );
    assert!(matches!(
        cert.check_signature_from(&cert).unwrap_err(),
        x509::Error::InsecureAlgorithm(_)
    ));
}

#[test]
fn md5_and_sha1_are_insecure() {
    let cert = parse_const("md5cert");
    assert_eq!(cert.signature_algorithm, SignatureAlgorithm::MD5_WITH_RSA);
    assert!(matches!(
        cert.check_signature_from(&cert).unwrap_err(),
        x509::Error::InsecureAlgorithm(_)
    ));
}

#[test]
fn insecure_algorithm_error_string() {
    let tests = [
        (
            SignatureAlgorithm::MD5_WITH_RSA,
            "x509: cannot verify signature: insecure algorithm MD5-RSA",
        ),
        (
            SignatureAlgorithm::SHA1_WITH_RSA,
            "x509: cannot verify signature: insecure algorithm SHA1-RSA",
        ),
        (
            SignatureAlgorithm::ECDSA_WITH_SHA1,
            "x509: cannot verify signature: insecure algorithm ECDSA-SHA1",
        ),
        (
            SignatureAlgorithm::MD2_WITH_RSA,
            "x509: cannot verify signature: insecure algorithm 1",
        ),
        (
            SignatureAlgorithm(-1),
            "x509: cannot verify signature: insecure algorithm -1",
        ),
        (
            SignatureAlgorithm(0),
            "x509: cannot verify signature: insecure algorithm 0",
        ),
        (
            SignatureAlgorithm(9999),
            "x509: cannot verify signature: insecure algorithm 9999",
        ),
    ];
    for (i, (sa, want)) in tests.into_iter().enumerate() {
        assert_eq!(InsecureAlgorithmError(sa).to_string(), want, "{i}");
    }
}

#[test]
fn dsa_certificate() {
    let cert = parse_const("dsaCertPem");
    assert_eq!(cert.public_key_algorithm, PublicKeyAlgorithm::DSA);
    assert_eq!(cert.signature_algorithm, SignatureAlgorithm::DSA_WITH_SHA1);
    let Some(PublicKey::Dsa(key)) = &cert.public_key else {
        panic!("parsed key was not a DSA key");
    };
    let hex = |text: &str| rust_stdlib_crypto::bigint::Int::from_hex(text).unwrap();
    assert_eq!(key.y, hex("59A27C269FCDE45AA2160A5C980C19211A820095091AB9C5DC8309AB7EC1B3A48C2E267C6D35FEE9B71BCBB92F16AC8E559129347FB5C00BEEDD10BA8915C90698755CA965735A32DC7575BED806E1E38F768FFBC24E41123DC73F1C6E9E4D0C9E692128853AFE29DC665FA993DCA9C903B7BF00B6442B9A76A5DADC6186317A"));
    assert_eq!(
        key.parameters.q,
        hex("009A67067F66A323F5D4EC7902C73FE5D9E36FA74F")
    );
    // Verification of DSA signatures is not supported.
    assert!(cert.check_signature_from(&cert).is_err());
}

#[test]
fn rsa_pss_self_signed() {
    for name in ["rsaPSSSelfSignedPEM", "rsaPSSSelfSignedOpenSSL110PEM"] {
        let cert = parse_const(name);
        cert.check_signature_from(&cert)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

#[test]
fn ed25519_self_signed() {
    let cert = parse_const("ed25519Certificate");
    assert_eq!(cert.public_key_algorithm, PublicKeyAlgorithm::ED25519);
    let Some(PublicKey::Ed25519(key)) = &cert.public_key else {
        panic!("parsed key was not Ed25519");
    };
    assert_eq!(
        key.0,
        common::unhex("3629c56c0d4f146c81d0ff75d36a705f69cd0f4d66d5da987e824989a38a3cfa")
    );
    assert_eq!(cert.signature_algorithm, SignatureAlgorithm::PURE_ED25519);
    cert.check_signature_from(&cert).unwrap();
}

#[test]
fn rsa_missing_null_parameters() {
    let err = parse_certificate(&const_der("certMissingRSANULL")).unwrap_err();
    assert!(err.to_string().contains("missing NULL"), "{err}");
}

#[test]
fn iso_oid_in_certificate() {
    let cert = parse_const("certISOOID");
    assert_ne!(
        cert.signature_algorithm,
        SignatureAlgorithm::UNKNOWN_SIGNATURE_ALGORITHM
    );
}

#[test]
fn empty_name_constraints() {
    let err = parse_certificate(&const_der("emptyNameConstraintsPEM")).unwrap_err();
    assert!(err.to_string().contains("empty name constraints"), "{err}");
}

#[test]
fn critical_name_constraint_with_unknown_type() {
    let cert = parse_const("criticalNameConstraintWithUnknownTypePEM");
    assert_eq!(cert.unhandled_critical_extensions.len(), 1);
}

#[test]
fn bad_ip_mask() {
    let err = parse_certificate(&const_der("badIPMaskPEM")).unwrap_err();
    assert!(err.to_string().contains("contained invalid mask"), "{err}");
}

#[test]
fn additional_fields_in_general_subtree() {
    parse_certificate(&const_der("additionalGeneralSubtreePEM")).unwrap();
}

#[test]
fn multiple_urls_in_crldp() {
    let cert = parse_const("multipleURLsInCRLDPPEM");
    assert_eq!(
        cert.crl_distribution_points,
        vec![
            "http://epscd.catcert.net/crl/ec-acc.crl".to_string(),
            "http://epscd2.catcert.net/crl/ec-acc.crl".to_string()
        ]
    );
}

#[test]
fn sig_alg_mismatch() {
    for name in ["mismatchingSigAlgIDPEM", "mismatchingSigAlgParamPEM"] {
        let err = parse_certificate(&const_der(name)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "x509: inner and outer signature algorithm identifiers don't match",
            "{name}"
        );
    }
}

#[test]
fn auth_key_id_optional() {
    parse_certificate(&const_der("optionalAuthKeyIDPEM")).unwrap();
}

#[test]
fn large_oid() {
    // See Go issue 49678.
    let cert = parse_certificate(&const_der("largeOIDPEM")).unwrap();
    assert_eq!(cert.policies.len(), 1);
    assert_eq!(
        cert.policies[0].to_string(),
        "1.3.6.1.4.1.311.21.8.1492336001"
    );
    assert!(cert.policy_identifiers.is_empty() || cert.policy_identifiers.len() == 1);
}

#[test]
fn parse_unique_id() {
    let cert = parse_const("uniqueIDPEM");
    assert_eq!(cert.extensions.len(), 7);
}

#[test]
fn parse_negative_serial() {
    assert!(parse_certificate(&const_der("negativeSerialCert")).is_err());
}

#[test]
fn create_negative_serial() {
    let k = ecdsa::generate_key(elliptic::p256()).unwrap();
    let tmpl = Certificate {
        serial_number: Some(BigInt::from_i64(-1)),
        subject: pkix::Name {
            common_name: ":)".to_string(),
            ..pkix::Name::default()
        },
        not_after: Time::unix(Time::now().unix_secs() + 3600, 0),
        not_before: Time::unix(Time::now().unix_secs() - 3600, 0),
        ..Certificate::default()
    };
    let err = create_certificate(&tmpl, &tmpl, &k.public_key, &k).unwrap_err();
    assert_eq!(err.to_string(), "x509: serial number must be positive");
}

#[test]
fn duplicate_extensions_and_attributes() {
    assert!(parse_certificate(&const_der("dupExtCert")).is_err());
    assert!(parse_certificate_request(&const_der("dupExtCSR")).is_err());
    parse_certificate_request(&const_der("dupAttCSR")).expect("duplicate attributes parse");
}

#[test]
fn ipv4_mapped_ips_parse() {
    for name in ["ipv4MappedSANCert", "ipv4MappedConstraintCert"] {
        let der = fixture_lines("hex_consts.tsv")
            .into_iter()
            .find(|r| r[0] == name)
            .map(|r| common::unhex(&r[1]))
            .unwrap();
        let err = parse_certificate(&der).unwrap_err();
        assert!(
            err.to_string().contains("IPv4-mapped IPv6 address"),
            "{name}: {err}"
        );
    }
}

fn rsa_template(serial: i64) -> Certificate {
    Certificate {
        serial_number: Some(BigInt::from_i64(serial)),
        not_before: Time::unix(Time::now().unix_secs() - 86400, 0),
        not_after: Time::unix(Time::now().unix_secs() + 86400, 0),
        dns_names: vec!["localhost".to_string()],
        ..Certificate::default()
    }
}

#[test]
fn ipv4_mapped_ips_san_create() {
    let k = ecdsa::generate_key(elliptic::p256()).unwrap();
    let mut tmpl = rsa_template(1);
    tmpl.ip_addresses = vec![x509::parse_ip("::ffff:192.0.2.1").unwrap()];
    let der = create_certificate(&tmpl, &tmpl, &k.public_key, &k).unwrap();
    let cert = parse_certificate(&der).unwrap();
    assert_eq!(cert.ip_addresses.len(), 1);
    assert_eq!(cert.ip_addresses[0].0.len(), 4);
}

#[test]
fn ipv4_mapped_ips_constraint_create() {
    let k = ecdsa::generate_key(elliptic::p256()).unwrap();
    let mut tmpl = rsa_template(1);
    let mut ip = vec![0u8; 10];
    ip.extend([0xff, 0xff, 192, 0, 2, 1]);
    tmpl.permitted_ip_ranges = vec![x509::IpNet {
        ip: Ip(ip),
        mask: vec![0xff; 16],
    }];
    assert!(create_certificate(&tmpl, &tmpl, &k.public_key, &k).is_err());
}

#[test]
fn rfc9881_example_certificates() {
    for (name, algo) in [
        (
            "rfc9881ExampleCertificateMLDSA44",
            SignatureAlgorithm::MLDSA44,
        ),
        (
            "rfc9881ExampleCertificateMLDSA65",
            SignatureAlgorithm::MLDSA65,
        ),
        (
            "rfc9881ExampleCertificateMLDSA87",
            SignatureAlgorithm::MLDSA87,
        ),
    ] {
        let cert = parse_const(name);
        assert_eq!(
            cert.public_key_algorithm,
            PublicKeyAlgorithm::MLDSA,
            "{name}"
        );
        assert_eq!(cert.signature_algorithm, algo, "{name}");
        assert!(
            matches!(cert.public_key, Some(PublicKey::Mldsa(_))),
            "{name}"
        );
        // The examples are signed by the key they certify.
        cert.check_signature_from(&cert)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

#[test]
fn key_usage_strings() {
    assert_eq!(KeyUsage::DIGITAL_SIGNATURE.to_string(), "digitalSignature");
    assert_eq!(KeyUsage::DECIPHER_ONLY.to_string(), "decipherOnly");
    assert_eq!(KeyUsage(3).to_string(), "KeyUsage(3)");
    assert_eq!(ExtKeyUsage::SERVER_AUTH.to_string(), "serverAuth");
    assert_eq!(ExtKeyUsage(99).to_string(), "ExtKeyUsage(99)");
    assert_eq!(
        ExtKeyUsage::MICROSOFT_KERNEL_CODE_SIGNING.to_string(),
        "msKernelCode"
    );
    assert_eq!(PublicKeyAlgorithm::MLDSA.to_string(), "ML-DSA");
    assert_eq!(PublicKeyAlgorithm(9).to_string(), "9");
    assert_eq!(
        SignatureAlgorithm::SHA256_WITH_RSAPSS.to_string(),
        "SHA256-RSAPSS"
    );
    assert_eq!(SignatureAlgorithm(99).to_string(), "99");
    assert_eq!(
        ExtKeyUsage::SERVER_AUTH.oid().unwrap().to_string(),
        "1.3.6.1.5.5.7.3.1"
    );
    assert!(ExtKeyUsage(99).oid().is_none());
}

/// A small self-signed certificate (`tools/x509_check.py`'s shapes) with one
/// byte of a URI or name constraint replaced by a byte that is not UTF-8.
fn invalid_utf8_cert(name: &str) -> Vec<u8> {
    let row = fixture_lines("invalid_utf8_certs.tsv")
        .into_iter()
        .find(|row| row[0] == name)
        .unwrap_or_else(|| panic!("no invalid_utf8_certs.tsv row {name}"));
    common::unhex(&row[1])
}

/// Go 1.27 keeps the raw byte of a CRL distribution point, OCSP server or
/// issuing certificate URL (it never validates them). A Rust `String` holds
/// U+FFFD in its place: deviation `go-string-invalid-utf8` of ParseCertificate.
#[test]
fn invalid_utf8_uris_parse_with_replacement_character() {
    let cert = parse_certificate(&invalid_utf8_cert("crldp")).unwrap();
    assert_eq!(
        cert.crl_distribution_points,
        vec!["http://crl.\u{FFFD}xample/a.crl"]
    );
    let cert = parse_certificate(&invalid_utf8_cert("ocsp")).unwrap();
    assert_eq!(cert.ocsp_server, vec!["\u{FFFD}ttp://ocsp.example/"]);
    let cert = parse_certificate(&invalid_utf8_cert("issuing")).unwrap();
    assert_eq!(
        cert.issuing_certificate_url,
        vec!["http://ca.\u{FFFD}xample/ca.crt"]
    );
}

/// Go rejects a name constraint that is not IA5 and quotes the raw string with
/// `%q`, which prints an invalid byte as `\xNN`.
#[test]
fn invalid_utf8_name_constraint_error_quotes_the_byte() {
    let err = parse_certificate(&invalid_utf8_cert("dns_constraint")).unwrap_err();
    assert_eq!(
        err.to_string(),
        "x509: invalid constraint value: x509: \"exam\\xf4le.com\" cannot be encoded as an IA5String"
    );
}
