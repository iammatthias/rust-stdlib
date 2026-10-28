//! Tests of the parser internals, ported from Go's parser_test.go and
//! verify_test.go (`TestValidHostname`) and name_constraints_test.go
//! (`TestRFC2821Parsing`), which call unexported functions.

use std::path::PathBuf;

use super::asn1;
use super::parser::{domain_name_valid, parse_asn1_string};
use super::pkix::{self, Value};
use super::verify::{parse_rfc2821_mailbox, valid_hostname_input, valid_hostname_pattern};
use super::{
    create_certificate, parse_certificate, pem, BitString, Certificate, ObjectIdentifier, RawValue,
    Time,
};

fn fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/x509")
        .join(path)
}

/// The DER of a PEM constant of Go's tests, by name.
fn const_der(name: &str) -> Vec<u8> {
    let text = std::fs::read_to_string(fixture("certs.tsv")).unwrap();
    for line in text.lines() {
        let mut parts = line.split('\t');
        if parts.next() == Some(name) {
            parts.next();
            return pem::base64_decode(parts.next().unwrap().as_bytes()).unwrap();
        }
    }
    panic!("no constant {name}");
}

fn pem_der(text: &str) -> Vec<u8> {
    pem::decode(text.as_bytes()).0.expect("PEM block").bytes
}

#[test]
#[allow(clippy::type_complexity)] // a table of heterogeneous cases
fn parse_asn1_string_table() {
    let bmp = asn1::BMP_STRING;
    let cases: Vec<(&str, u8, Vec<u8>, Result<&str, &str>)> = vec![
        (
            "T61String",
            asn1::T61_STRING,
            vec![0xbf, 0x61, 0x3f],
            Ok("\u{bf}a?"),
        ),
        (
            "PrintableString",
            asn1::PRINTABLE_STRING,
            vec![80, 81, 82],
            Ok("PQR"),
        ),
        (
            "PrintableString (invalid)",
            asn1::PRINTABLE_STRING,
            vec![1, 2, 3],
            Err("invalid PrintableString"),
        ),
        ("UTF8String", asn1::UTF8_STRING, vec![80, 81, 82], Ok("PQR")),
        (
            "UTF8String (invalid)",
            asn1::UTF8_STRING,
            vec![255],
            Err("invalid UTF-8 string"),
        ),
        ("BMPString", bmp, vec![80, 81], Ok("\u{5051}")),
        (
            "BMPString (invalid length)",
            bmp,
            vec![255],
            Err("invalid BMPString"),
        ),
        (
            "BMPString (invalid surrogate)",
            bmp,
            vec![80, 81, 216, 1],
            Err("invalid BMPString"),
        ),
        (
            "BMPString (invalid noncharacter 0xfdd1)",
            bmp,
            vec![80, 81, 253, 209],
            Err("invalid BMPString"),
        ),
        (
            "BMPString (invalid noncharacter 0xffff)",
            bmp,
            vec![80, 81, 255, 255],
            Err("invalid BMPString"),
        ),
        (
            "BMPString (invalid noncharacter 0xfffe)",
            bmp,
            vec![80, 81, 255, 254],
            Err("invalid BMPString"),
        ),
        ("IA5String", asn1::IA5_STRING, vec![80, 81], Ok("PQ")),
        (
            "IA5String (invalid)",
            asn1::IA5_STRING,
            vec![255],
            Err("invalid IA5String"),
        ),
        (
            "NumericString",
            asn1::NUMERIC_STRING,
            vec![49, 50],
            Ok("12"),
        ),
        (
            "NumericString (invalid)",
            asn1::NUMERIC_STRING,
            vec![80],
            Err("invalid NumericString"),
        ),
    ];
    for (name, tag, value, expected) in cases {
        let got = parse_asn1_string(tag, &value);
        let got = got.as_deref().map_err(String::as_str);
        assert_eq!(got, expected, "{name}");
    }
}

#[test]
fn policy_parse() {
    let c = parse_certificate(&const_der("policyPEM")).unwrap();
    assert_eq!(c.policies.len(), 9);
    assert_eq!(c.policy_mappings.len(), 9);
    assert!(c.require_explicit_policy_zero);
    assert!(c.inhibit_policy_mapping_zero);
    assert!(c.inhibit_any_policy_zero);
}

#[test]
fn parse_policies() {
    for name in ["policy_leaf_duplicate.pem", "policy_leaf_invalid.pem"] {
        let data = std::fs::read(fixture(&format!("policy/{name}"))).unwrap();
        let der = pem::decode(&data).0.unwrap().bytes;
        assert!(parse_certificate(&der).is_err(), "{name} should not parse");
    }
}

#[test]
fn parse_certificate_negative_max_path_length() {
    let certs = [
        // MaxPathLen set to -1.
        "-----BEGIN CERTIFICATE-----
MIIByTCCATKgAwIBAgIBATANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDEwRURVNU
MB4XDTcwMDEwMTAwMTY0MFoXDTcwMDEwMjAzNDY0MFowDzENMAsGA1UEAxMEVEVT
VDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAsaHglFuSicTT8TKfipgsSi3N
Wb/TcvuAhanFF1VGB+vS95kO7yFqyfRgX3GgOwT0KlJVsVjPjghEGR9RGTSLqkTD
UFbiBgm8+VEPMOrUtIHIHXhl+ye44AkOEStxfz7gjN/EAS2h8ffPKhvDTHOlShKw
Y3LQlxR0LdeJXq3eSqUCAwEAAaM1MDMwEgYDVR0TAQH/BAgwBgEB/wIB/zAdBgNV
HQ4EFgQUrbrk0tqQAEsce8uYifP0BIVhuFAwDQYJKoZIhvcNAQELBQADgYEAIkhV
ZBj1ThT+eyh50XsoU570NUysTg3Nj/3lbkEolzdcE+wu0CPXvgxLRM6Y62u1ey82
8d5VQHstzF4dXgc3W+O9UySa+CKdcHx/q7o7seOGXdysT0IJtAY3w66mFkuF7PIn
y9b7M5t6pmWjb7N0QqGuWeNqi4ZvS8gLKmVEgGY=
-----END CERTIFICATE-----
",
        // MaxPathLen set to -2.
        "-----BEGIN CERTIFICATE-----
MIIByTCCATKgAwIBAgIBATANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDEwRURVNU
MB4XDTcwMDEwMTAwMTY0MFoXDTcwMDEwMjAzNDY0MFowDzENMAsGA1UEAxMEVEVT
VDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAsaHglFuSicTT8TKfipgsSi3N
Wb/TcvuAhanFF1VGB+vS95kO7yFqyfRgX3GgOwT0KlJVsVjPjghEGR9RGTSLqkTD
UFbiBgm8+VEPMOrUtIHIHXhl+ye44AkOEStxfz7gjN/EAS2h8ffPKhvDTHOlShKw
Y3LQlxR0LdeJXq3eSqUCAwEAAaM1MDMwEgYDVR0TAQH/BAgwBgEB/wIB/jAdBgNV
HQ4EFgQUrbrk0tqQAEsce8uYifP0BIVhuFAwDQYJKoZIhvcNAQELBQADgYEAGjIr
YGQc7Ods+BuKck7p+vpAMONM8SLEuUtKorCP3ecsO51MoA4/niLbgMHaOGNHwzMp
ajg0zLbY0Dj6Ml0VZ+lS3rjgTEhYXc626eZkoQqgUzL1jhe3S0ZbSxxmHMBKjJFl
d5l1tRhScKu2NBgm74nYmJxJYgvuTA38wGhRrGU=
-----END CERTIFICATE-----
",
    ];
    for cert in certs {
        let err = parse_certificate(&pem_der(cert)).unwrap_err();
        assert_eq!(err.to_string(), "x509: invalid basic constraints");
    }
}

#[test]
fn domain_name_validity() {
    let a = |n: usize| "a".repeat(n);
    let cases: Vec<(&str, String, bool, bool)> = vec![
        // Go disabled the stricter label length checks; see TODO(#75835).
        (
            "254 char label, name",
            "a.a".repeat(84) + "aaa",
            false,
            true,
        ),
        (
            "254 char label, constraint",
            "a.a".repeat(84) + "aaa",
            true,
            true,
        ),
        ("253 char label, name", "a.a".repeat(84) + "aa", false, true),
        (
            "253 char label, constraint",
            "a.a".repeat(84) + "aa",
            true,
            true,
        ),
        ("64 char single label, name", a(64), false, true),
        ("64 char single label, constraint", a(64), true, true),
        ("64 char label, name", format!("a.{}", a(64)), false, true),
        (
            "64 char label, constraint",
            format!("a.{}", a(64)),
            true,
            true,
        ),
        ("empty name, constraint", String::new(), true, true),
        ("empty label, name", "a..a".to_string(), false, false),
        ("empty label, constraint", "a..a".to_string(), true, false),
        ("period, name", ".".to_string(), false, false),
        ("period, constraint", ".".to_string(), true, false),
        ("valid, name", "a.b.c".to_string(), false, true),
        ("valid, constraint", "a.b.c".to_string(), true, true),
        ("leading period, name", ".a.b.c".to_string(), false, false),
        (
            "leading period, constraint",
            ".a.b.c".to_string(),
            true,
            true,
        ),
        ("trailing period, name", "a.".to_string(), false, false),
        ("trailing period, constraint", "a.".to_string(), true, false),
        ("bare label, name", "a".to_string(), false, true),
        ("bare label, constraint", "a".to_string(), true, true),
        ("63 char single label, name", a(63), false, true),
        ("63 char single label, constraint", a(63), true, true),
        ("63 char label, name", format!("a.{}", a(63)), false, true),
        (
            "63 char label, constraint",
            format!("a.{}", a(63)),
            true,
            true,
        ),
    ];
    for (name, dns_name, constraint, valid) in cases {
        assert_eq!(domain_name_valid(&dns_name, constraint), valid, "{name}");
    }
}

#[test]
fn roundtrip_weird_sans() {
    // Certificates created with malformed SAN values must still parse.
    let k = crate::ecdsa::generate_key(crate::elliptic::p256()).unwrap();
    let bad_names: Vec<String> = vec![
        "baredomain".to_string(),
        "baredomain.".to_string(),
        "a".repeat(255),
        format!("{}.com", "a".repeat(65)),
    ];
    let tmpl = Certificate {
        email_addresses: bad_names.clone(),
        dns_names: bad_names,
        ..Certificate::default()
    };
    let der = create_certificate(&tmpl, &tmpl, &k.public_key, &k).unwrap();
    parse_certificate(&der).unwrap();
}

#[test]
fn parse_name_types() {
    let der = pem_der(
        "
-----BEGIN CERTIFICATE-----
MIICGzCCAcGgAwIBAgIJAIZft7jy3RcpMAoGCCqGSM49BAMCMA8xDTALBgNVBAMM
BFRlc3QwHhcNMjUwOTAyMTg0MzE3WhcNMjUxMDAyMTg0MzE3WjCCARUxIjAgBg0q
hkiG9xIEAYS3CQIBDA91dGY4LXN0cmluZ/CfpooxHzAdBg0qhkiG9xIEAYS3CQIC
BAxvY3RldC1zdHJpbmcxGDAWBg0qhkiG9xIEAYS3CQIDDQUBAgMEBTETMBEGDSqG
SIb3EgQBhLcJAgQFADEVMBMGDSqGSIb3EgQBhLcJAgUwAgECMRQwEgYNKoZIhvcS
BAGEtwkCBgIBKjEgMB4GDSqGSIb3EgQBhLcJAgcGDSqGSIb3EgQBhLcJAgcxGDAW
Bg0qhkiG9xIEAYS3CQIIAwUAqrvM3TEgMB4GDSqGSIb3EgQBhLcJAgkXDTI1MDkw
MjE4NDMxN1oxFDASBg0qhkiG9xIEAYS3CQIKAQH/MFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAE7M4zoqQtXbvGsudKaM5gd8emxyk68AFTjIYU4PO1AtiYX3wyL89k
wbHjxgvmh/9aBg1LOj6kfsJIxULUmUpdzTAKBggqhkjOPQQDAgNIADBFAiBvKz3o
ALhCqKrRFLUbax6+tI1s1B14IPVk2ZHbBEou5gIhAOpvJRNj5qluPXKLXmZvIK8u
OjUhiZoowYvborSS1EBK
-----END CERTIFICATE-----
	",
    );
    let base = "1.2.840.113554.4.1.72585.2.";
    let expected: Vec<(u32, Value)> = vec![
        (1, Value::String("utf8-string\u{1f98a}".to_string())),
        (2, Value::Bytes(b"octet-string".to_vec())),
        (
            3,
            Value::Raw(RawValue {
                class: 0,
                tag: 13,
                is_compound: false,
                bytes: vec![1, 2, 3, 4, 5],
                full_bytes: vec![13, 5, 1, 2, 3, 4, 5],
            }),
        ),
        (4, Value::Nil),
        (
            5,
            Value::Raw(RawValue {
                class: 0,
                tag: 16,
                is_compound: true,
                bytes: vec![1, 2],
                full_bytes: vec![0x30, 2, 1, 2],
            }),
        ),
        (6, Value::Int(42)),
        (
            7,
            Value::ObjectIdentifier(ObjectIdentifier(vec![1, 2, 840, 113554, 4, 1, 72585, 2, 7])),
        ),
        (
            8,
            Value::BitString(BitString {
                bytes: vec![0xaa, 0xbb, 0xcc, 0xdd],
                bit_length: 32,
            }),
        ),
        (9, Value::Time(Time::date(2025, 9, 2, 18, 43, 17).unwrap())),
        (10, Value::Bool(true)),
    ];
    let cert = parse_certificate(&der).unwrap();
    assert_eq!(cert.subject.names.len(), expected.len());
    for attr in &cert.subject.names {
        let want = expected
            .iter()
            .find(|(n, _)| attr.type_.to_string() == format!("{base}{n}"))
            .unwrap_or_else(|| panic!("unexpected attribute type: {}", attr.type_));
        assert_eq!(attr.value, want.1, "{}", attr.type_);
    }
    // asn1.Marshal does not encode NULL, so Go substitutes NullRawValue.
    let mut extra = pkix::Name {
        extra_names: Some(cert.subject.names.clone()),
        ..pkix::Name::default()
    };
    for atv in extra.extra_names.as_mut().unwrap() {
        if atv.value == Value::Nil {
            atv.value = Value::Raw(RawValue::null());
        }
    }
    let got = extra.to_rdn_sequence().marshal().unwrap();
    assert_eq!(got, cert.raw_subject);
}

#[test]
fn valid_hostname() {
    // (host, valid input, valid pattern)
    let tests: &[(&str, bool, bool)] = &[
        ("example.com", true, true),
        ("eXample123-.com", true, true),
        ("-eXample123-.com", false, false),
        ("", false, false),
        (".", false, false),
        ("example..com", false, false),
        (".example.com", false, false),
        ("example.com.", true, false),
        ("*.example.com.", false, false),
        ("*.example.com", false, true),
        ("*foo.example.com", false, false),
        ("foo.*.example.com", false, false),
        ("exa_mple.com", true, true),
        ("foo,bar", false, false),
        ("project-dev:us-central1:main", false, false),
    ];
    for &(host, input, pattern) in tests {
        assert_eq!(valid_hostname_pattern(host), pattern, "pattern {host:?}");
        assert_eq!(valid_hostname_input(host), input, "input {host:?}");
    }
}

#[test]
fn rfc2821_parsing() {
    // (input, local part, domain); empty both means failure.
    let tests: &[(&str, &str, &str)] = &[
        ("foo@example.com", "foo", "example.com"),
        ("@example.com", "", ""),
        ("\"@example.com", "", ""),
        ("\"\"@example.com", "", "example.com"),
        ("\"a\"@example.com", "a", "example.com"),
        ("\"\\a\"@example.com", "a", "example.com"),
        ("a\"@example.com", "", ""),
        ("foo..bar@example.com", "", ""),
        (".foo.bar@example.com", "", ""),
        ("foo.bar.@example.com", "", ""),
        ("|{}?'@example.com", "|{}?'", "example.com"),
        ("a@b@c.com", "", ""),
        // Examples from RFC 3696.
        ("Abc\\@def@example.com", "Abc@def", "example.com"),
        ("Fred\\ Bloggs@example.com", "Fred Bloggs", "example.com"),
        ("Joe.\\\\Blow@example.com", "Joe.\\Blow", "example.com"),
        ("\"Abc@def\"@example.com", "Abc@def", "example.com"),
        ("\"Fred Bloggs\"@example.com", "Fred Bloggs", "example.com"),
        (
            "customer/department=shipping@example.com",
            "customer/department=shipping",
            "example.com",
        ),
        ("$A12345@example.com", "$A12345", "example.com"),
        ("!def!xyz%abc@example.com", "!def!xyz%abc", "example.com"),
        ("_somename@example.com", "_somename", "example.com"),
    ];
    for (i, (input, local, domain)) in tests.iter().enumerate() {
        let expected_failure = local.is_empty() && domain.is_empty();
        match parse_rfc2821_mailbox(input) {
            Some(m) => {
                assert!(!expected_failure, "#{i}: {input:?} unexpectedly parsed");
                assert_eq!(
                    (m.local.as_str(), m.domain.as_str()),
                    (*local, *domain),
                    "#{i}: {input:?}"
                );
            }
            None => assert!(expected_failure, "#{i}: unexpected failure for {input:?}"),
        }
    }
}
