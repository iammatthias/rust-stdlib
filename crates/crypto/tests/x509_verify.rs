//! crypto/x509 verification, ported from Go's verify_test.go: the `verifyTests`
//! table (dumped from Go's source by tools/x509_vectors_gen.py), hostname
//! matching, EKU enforcement and path building.

mod common;

use std::sync::Arc;

use common::json::Json;
use rust_stdlib_crypto::ecdsa::{self, PrivateKey};
use rust_stdlib_crypto::elliptic;
use rust_stdlib_crypto::x509::{
    create_certificate, parse_certificate, parse_ip, pem, pkix, BigInt, CertPool, Certificate,
    Error, ExtKeyUsage, InvalidReason, KeyUsage, ObjectIdentifier, SystemRootsError, Time,
    VerifyOptions,
};

fn fixture(path: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/x509")
        .join(path);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The PEM constants of Go's tests, by name.
fn const_pem(name: &str) -> Vec<u8> {
    for line in fixture("certs.tsv").lines() {
        let mut parts = line.split('\t');
        if parts.next() == Some(name) {
            let label = parts.next().unwrap();
            let body = parts.next().unwrap();
            let mut out = format!("-----BEGIN {label}-----\n");
            for chunk in body.as_bytes().chunks(64) {
                out.push_str(std::str::from_utf8(chunk).unwrap());
                out.push('\n');
            }
            out.push_str(&format!("-----END {label}-----\n"));
            return out.into_bytes();
        }
    }
    panic!("no PEM constant {name}");
}

fn certificate_from_pem(name: &str) -> Certificate {
    let pem = const_pem(name);
    let block = pem::decode(&pem).0.expect("PEM block");
    parse_certificate(&block.bytes).unwrap()
}

/// Go's `nameToKey`.
fn name_to_key(name: &pkix::Name) -> String {
    format!(
        "{}/{}/{}/{}",
        name.country.join(","),
        name.organization.join(","),
        name.organizational_unit.join(","),
        name.common_name
    )
}

fn eku_by_name(name: &str) -> ExtKeyUsage {
    match name {
        "ServerAuth" => ExtKeyUsage::SERVER_AUTH,
        "ClientAuth" => ExtKeyUsage::CLIENT_AUTH,
        "EmailProtection" => ExtKeyUsage::EMAIL_PROTECTION,
        "Any" => ExtKeyUsage::ANY,
        other => panic!("unknown EKU {other}"),
    }
}

/// Go's error callbacks of the table.
fn check_error(callback: &str, arg: &str, err: Error) {
    match callback {
        "expectHostnameError" => {
            let Error::Hostname(_) = &err else {
                panic!("error was not a HostnameError: {err}");
            };
            assert!(
                err.to_string().contains(arg),
                "HostnameError did not contain {arg:?}: {err}"
            );
        }
        "expectExpired" => match &err {
            Error::CertificateInvalid(e) if e.reason == InvalidReason::EXPIRED => {}
            _ => panic!("error was not Expired: {err}"),
        },
        "expectUsageError" => match &err {
            Error::CertificateInvalid(e) if e.reason == InvalidReason::INCOMPATIBLE_USAGE => {}
            _ => panic!("error was not IncompatibleUsage: {err}"),
        },
        "expectAuthorityUnknown" => match &err {
            Error::UnknownAuthority(e) => assert!(!e.cert.raw.is_empty(), "missing Cert: {err}"),
            _ => panic!("error was not UnknownAuthorityError: {err}"),
        },
        "expectHashError" => {
            assert!(
                err.to_string().contains("algorithm unimplemented"),
                "error resulting from invalid hash didn't contain 'algorithm unimplemented': {err}"
            );
        }
        "expectNameConstraintsError" => match &err {
            Error::CertificateInvalid(e)
                if e.reason == InvalidReason::CA_NOT_AUTHORIZED_FOR_THIS_NAME => {}
            _ => panic!("error was not a CANotAuthorizedForThisName: {err}"),
        },
        "expectNotAuthorizedError" => match &err {
            Error::CertificateInvalid(e) if e.reason == InvalidReason::NOT_AUTHORIZED_TO_SIGN => {}
            _ => panic!("error was not a NotAuthorizedToSign: {err}"),
        },
        "expectUnhandledCriticalExtension" => match &err {
            Error::UnhandledCriticalExtension(_) => {}
            _ => panic!("error was not an UnhandledCriticalExtension: {err}"),
        },
        other => panic!("unknown callback {other}"),
    }
}

#[test]
fn go_verify() {
    let table = Json::parse(&fixture("verify_tests.json"));
    assert_eq!(table.as_array().len(), 24);
    for test in table.as_array() {
        let name = test.get("name").as_str();
        let mut roots = CertPool::new();
        for root in test.get("roots").strings() {
            assert!(
                roots.append_certs_from_pem(&const_pem(&root)),
                "{name}: failed to parse root {root}"
            );
        }
        let mut intermediates = CertPool::new();
        for inter in test.get("intermediates").strings() {
            assert!(
                intermediates.append_certs_from_pem(&const_pem(&inter)),
                "{name}: failed to parse intermediate {inter}"
            );
        }
        let leaf = certificate_from_pem(test.get("leaf").as_str());
        let opts = VerifyOptions {
            intermediates: Some(&intermediates),
            roots: Some(&roots),
            dns_name: test.get("dns").as_str().to_string(),
            current_time: Time::unix(test.get("time").as_i64(), 0),
            key_usages: test
                .get("ekus")
                .strings()
                .iter()
                .map(|e| eku_by_name(e))
                .collect(),
            ..VerifyOptions::default()
        };
        let result = leaf.verify(&opts);
        let callback = test.get("callback").as_str();
        let chains = match (callback.is_empty(), result) {
            (true, Err(e)) => panic!("{name}: unexpected error: {e}"),
            (true, Ok(chains)) => chains,
            (false, Ok(_)) => panic!("{name}: expected an error from {callback}"),
            (false, Err(e)) => {
                check_error(callback, test.get("callback_arg").as_str(), e);
                Vec::new()
            }
        };

        let expected: Vec<Vec<String>> = test
            .get("chains")
            .as_array()
            .iter()
            .map(Json::strings)
            .collect();
        let matches = |expected_chain: &[String], chain: &[Arc<Certificate>]| {
            chain.len() == expected_chain.len()
                && chain
                    .iter()
                    .zip(expected_chain)
                    .all(|(cert, want)| name_to_key(&cert.subject).contains(want.as_str()))
        };
        // Every expected chain matches one of the returned chains...
        for want in &expected {
            assert!(
                chains.iter().any(|c| matches(want, c)),
                "{name}: no match found for {want:?}"
            );
        }
        // ...and every returned chain matches exactly one expected chain.
        for chain in &chains {
            let n = expected.iter().filter(|w| matches(w, chain)).count();
            assert_eq!(
                n,
                1,
                "{name}: got {n} matches for a chain of {} certificates",
                chain.len()
            );
        }
    }
}

fn p256() -> PrivateKey {
    ecdsa::generate_key(elliptic::p256()).unwrap()
}

/// Go's `generatePEMCertWithRepeatSAN`, with a P-256 key (an RSA 4096 key
/// makes no difference to what the test checks).
fn cert_with_repeat_san(current_time: i64, count: usize, san: &str) -> Certificate {
    let mut cert = Certificate {
        not_before: Time::unix(current_time, 0),
        not_after: Time::unix(current_time, 0),
        ..Certificate::default()
    };
    match parse_ip(san) {
        Some(ip) => cert.ip_addresses = vec![ip; count],
        None => cert.dns_names = vec![san.to_string(); count],
    }
    let key = p256();
    let der = create_certificate(&cert, &cert, &key.public_key, &key).unwrap();
    parse_certificate(&der).unwrap()
}

#[test]
fn too_many_names_in_hostname_error() {
    for (san, count, host, want) in [
        (
            "fake.dns",
            200,
            "www.example.com",
            "certificate is valid for 200 names, but none matched",
        ),
        (
            "4.3.2.1",
            150,
            "1.2.3.4",
            "certificate is valid for 150 IP SANs, but none matched",
        ),
    ] {
        let leaf = cert_with_repeat_san(1677615892, count, san);
        let mut roots = CertPool::new();
        roots.add_cert(&cert_with_repeat_san(1677615892, count, san));
        let err = leaf
            .verify(&VerifyOptions {
                roots: Some(&roots),
                dns_name: host.to_string(),
                current_time: Time::unix(1677615892, 0),
                ..VerifyOptions::default()
            })
            .unwrap_err();
        check_error("expectHostnameError", want, err);
    }
}

#[test]
fn match_hostnames() {
    let tests: &[(&str, &str, bool)] = &[
        ("a.b.c", "a.b.c", true),
        ("a.b.c", "b.b.c", false),
        ("", "b.b.c", false),
        ("a.b.c", "", false),
        ("example.com", "example.com", true),
        ("example.com", "www.example.com", false),
        ("*.example.com", "example.com", false),
        ("*.example.com", "www.example.com", true),
        ("*.example.com", "www.example.com.", true),
        ("*.example.com", "xyz.www.example.com", false),
        ("*.example.com", "https://www.example.com", false), // Issue 27591
        ("*.example..com", "www.example..com", false),
        ("www.example..com", "www.example..com", true),
        ("*.*.example.com", "xyz.www.example.com", false),
        ("*.www.*.com", "xyz.www.example.com", false),
        ("*bar.example.com", "foobar.example.com", false),
        ("f*.example.com", "foobar.example.com", false),
        ("www.example.com", "*.example.com", false),
        ("", ".", false),
        (".", "", false),
        (".", ".", false),
        ("example.com", "example.com.", true),
        ("example.com.", "example.com", false),
        ("example.com.", "example.com.", true), // perfect matches allow trailing dots in patterns
        ("*.com.", "example.com.", false),
        ("*.com.", "example.com", false),
        ("*.com", "example.com", true),
        ("*.com", "example.com.", true),
        ("foo:bar", "foo:bar", true),
        ("*.foo:bar", "xxx.foo:bar", false),
        ("*.2.3.4", "1.2.3.4", false),
        ("*.2.3.4", "[1.2.3.4]", false),
        ("*:4860:4860::8888", "2001:4860:4860::8888", false),
        ("*:4860:4860::8888", "[2001:4860:4860::8888]", false),
        ("2001:4860:4860::8888", "2001:4860:4860::8888", false),
        ("2001:4860:4860::8888", "[2001:4860:4860::8888]", false),
        ("[2001:4860:4860::8888]", "2001:4860:4860::8888", false),
        ("[2001:4860:4860::8888]", "[2001:4860:4860::8888]", false),
    ];
    for (i, &(pattern, host, ok)) in tests.iter().enumerate() {
        let c = Certificate {
            dns_names: vec![pattern.to_string()],
            ..Certificate::default()
        };
        assert_eq!(
            c.verify_hostname(host).is_ok(),
            ok,
            "#{i}: matching {host:?} against {pattern:?}"
        );
    }
}

#[test]
fn match_ip() {
    // Pattern matching works...
    let c = Certificate {
        dns_names: vec!["*.foo.bar.baz".to_string()],
        subject: pkix::Name {
            common_name: "*.foo.bar.baz".to_string(),
            ..pkix::Name::default()
        },
        ..Certificate::default()
    };
    c.verify_hostname("quux.foo.bar.baz").unwrap();

    // ...but not against an IP address.
    let c = Certificate {
        dns_names: vec!["*.2.3.4".to_string()],
        subject: pkix::Name {
            common_name: "*.2.3.4".to_string(),
            ..pkix::Name::default()
        },
        ..Certificate::default()
    };
    assert!(c.verify_hostname("1.2.3.4").is_err());

    let c = Certificate {
        ip_addresses: vec![parse_ip("127.0.0.1").unwrap(), parse_ip("::1").unwrap()],
        ..Certificate::default()
    };
    c.verify_hostname("127.0.0.1").unwrap();
    c.verify_hostname("::1").unwrap();
    c.verify_hostname("[::1]").unwrap();
}

#[test]
fn verify_hostname_ip_addresses() {
    let cert = Certificate {
        ip_addresses: vec![parse_ip("192.0.2.1").unwrap(), parse_ip("fe80::1").unwrap()],
        ..Certificate::default()
    };
    let tests: &[(&str, &str, bool)] = &[
        ("IPv4", "192.0.2.1", true),
        ("IPv4 bracketed", "[192.0.2.1]", true),
        ("IPv4 mismatch", "192.0.2.2", false),
        ("IPv6", "fe80::1", true),
        ("IPv6 bracketed", "[fe80::1]", true),
        ("IPv6 with zone", "fe80::1%eth0", true),
        ("IPv6 with zone bracketed", "[fe80::1%eth0]", true),
        ("IPv6 mismatch", "fe80::2", false),
        ("IPv6 with zone mismatch", "fe80::2%eth0", false),
    ];
    for &(name, host, matches) in tests {
        assert_eq!(
            cert.verify_hostname(host).is_ok(),
            matches,
            "{name}: {host:?}"
        );
    }
}

#[test]
fn verify_bare_wildcard() {
    let tmpl = Certificate {
        serial_number: Some(BigInt::from_i64(1)),
        subject: pkix::Name {
            common_name: "test".to_string(),
            ..pkix::Name::default()
        },
        not_before: Time::unix(0, 0),
        not_after: Time::unix(1 << 33, 0),
        dns_names: vec!["*".to_string()],
        ..Certificate::default()
    };
    let k = p256();
    let der = create_certificate(&tmpl, &tmpl, &k.public_key, &k).unwrap();
    let c = parse_certificate(&der).unwrap();
    assert!(
        c.verify_hostname("label").is_err(),
        "unexpected success with a bare wildcard SAN"
    );
}

#[test]
fn verify_empty_certificate() {
    let err = Certificate::default()
        .verify(&VerifyOptions::default())
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "x509: missing ASN.1 contents; use ParseCertificate"
    );
}

#[test]
fn system_roots_error_unwrap() {
    let inner: Arc<dyn std::error::Error + Send + Sync> = Arc::new(std::io::Error::other("err1"));
    let err = SystemRootsError { err: Some(inner) };
    assert_eq!(err.unwrap_err().unwrap().to_string(), "err1");
    assert_eq!(
        err.to_string(),
        "x509: failed to load system roots and no roots provided; err1"
    );
    assert_eq!(
        SystemRootsError { err: None }.to_string(),
        "x509: failed to load system roots and no roots provided"
    );
}

#[derive(Clone, Copy, PartialEq)]
enum CertType {
    Leaf,
    Intermediate,
    Root,
}

/// Go's `genCertEdge`.
fn gen_cert_edge(
    subject: &str,
    key: &PrivateKey,
    mutate: impl Fn(&mut Certificate),
    cert_type: CertType,
    issuer: Option<&Certificate>,
    signer: &PrivateKey,
) -> Certificate {
    let mut serial = [0u8; 1];
    rust_stdlib_crypto::rand::read(&mut serial);
    let mut tmpl = Certificate {
        serial_number: Some(BigInt::from_i64(i64::from(serial[0] % 100))),
        subject: pkix::Name {
            common_name: subject.to_string(),
            ..pkix::Name::default()
        },
        not_before: Time::unix(Time::now().unix_secs() - 3600, 0),
        not_after: Time::unix(Time::now().unix_secs() + 3600, 0),
        ..Certificate::default()
    };
    match cert_type {
        CertType::Root | CertType::Intermediate => {
            tmpl.is_ca = true;
            tmpl.basic_constraints_valid = true;
            tmpl.key_usage = KeyUsage::CERT_SIGN;
        }
        CertType::Leaf => tmpl.dns_names = vec!["localhost".to_string()],
    }
    mutate(&mut tmpl);
    let (der, _) = if cert_type == CertType::Root {
        (
            create_certificate(&tmpl, &tmpl, &key.public_key, key).unwrap(),
            (),
        )
    } else {
        (
            create_certificate(&tmpl, issuer.unwrap(), &key.public_key, signer).unwrap(),
            (),
        )
    };
    parse_certificate(&der).unwrap()
}

#[test]
#[allow(clippy::type_complexity)] // a table of heterogeneous cases
fn eku_enforcement() {
    struct Eku {
        ekus: Vec<ExtKeyUsage>,
        unknown: Vec<ObjectIdentifier>,
    }
    let e = |ekus: &[ExtKeyUsage]| Eku {
        ekus: ekus.to_vec(),
        unknown: vec![],
    };
    let s = ExtKeyUsage::SERVER_AUTH;
    let c = ExtKeyUsage::CLIENT_AUTH;
    const INCOMPATIBLE: &str = "x509: certificate specifies an incompatible key usage";
    let tests: Vec<(&str, Eku, Vec<Eku>, Eku, Vec<ExtKeyUsage>, &str)> = vec![
        (
            "valid, full chain",
            e(&[s]),
            vec![e(&[s])],
            e(&[s]),
            vec![s],
            "",
        ),
        (
            "valid, only leaf has EKU",
            e(&[]),
            vec![e(&[])],
            e(&[s]),
            vec![s],
            "",
        ),
        (
            "invalid, serverAuth not nested",
            e(&[c]),
            vec![e(&[s, c])],
            e(&[s, c]),
            vec![s],
            INCOMPATIBLE,
        ),
        (
            "valid, two EKUs, one path",
            e(&[s]),
            vec![e(&[s, c])],
            e(&[s, c]),
            vec![s, c],
            "",
        ),
        (
            "invalid, ladder",
            e(&[s]),
            vec![e(&[s, c]), e(&[c]), e(&[s, c]), e(&[s])],
            e(&[s]),
            vec![s, c],
            INCOMPATIBLE,
        ),
        (
            "valid, intermediate has no EKU",
            e(&[s]),
            vec![e(&[])],
            e(&[s]),
            vec![s],
            "",
        ),
        (
            "invalid, intermediate has no EKU and no nested path",
            e(&[c]),
            vec![e(&[])],
            e(&[s]),
            vec![s, c],
            INCOMPATIBLE,
        ),
        (
            "invalid, intermediate has unknown EKU",
            e(&[s]),
            vec![Eku {
                ekus: vec![],
                unknown: vec![ObjectIdentifier(vec![1, 2, 3])],
            }],
            e(&[s]),
            vec![s],
            INCOMPATIBLE,
        ),
    ];
    let k = p256();
    for (name, root_ekus, inters, leaf_ekus, verify_ekus, want_err) in tests {
        let mut root_pool = CertPool::new();
        let root = gen_cert_edge(
            "root",
            &k,
            |c| {
                c.ext_key_usage = root_ekus.ekus.clone();
                c.unknown_ext_key_usage = root_ekus.unknown.clone();
            },
            CertType::Root,
            None,
            &k,
        );
        root_pool.add_cert(&root);
        let mut parent = root;
        let mut inter_pool = CertPool::new();
        for (i, inter_ekus) in inters.iter().enumerate() {
            let inter = gen_cert_edge(
                &format!("inter {i}"),
                &k,
                |c| {
                    c.ext_key_usage = inter_ekus.ekus.clone();
                    c.unknown_ext_key_usage = inter_ekus.unknown.clone();
                },
                CertType::Intermediate,
                Some(&parent),
                &k,
            );
            inter_pool.add_cert(&inter);
            parent = inter;
        }
        let leaf = gen_cert_edge(
            "leaf",
            &k,
            |c| {
                c.ext_key_usage = leaf_ekus.ekus.clone();
                c.unknown_ext_key_usage = leaf_ekus.unknown.clone();
            },
            CertType::Intermediate,
            Some(&parent),
            &k,
        );
        let result = leaf.verify(&VerifyOptions {
            roots: Some(&root_pool),
            intermediates: Some(&inter_pool),
            key_usages: verify_ekus,
            ..VerifyOptions::default()
        });
        match (result, want_err) {
            (Ok(_), "") => {}
            (Ok(_), _) => panic!("{name}: expected error"),
            (Err(e), want) => assert_eq!(e.to_string(), want, "{name}"),
        }
    }
}

#[test]
fn verify_eku_root_as_leaf() {
    let k = p256();
    let s = ExtKeyUsage::SERVER_AUTH;
    let cases: Vec<(Vec<ExtKeyUsage>, Vec<ExtKeyUsage>, bool)> = vec![
        (vec![], vec![s], true),
        (vec![s], vec![], true),
        (vec![s], vec![s], true),
        (vec![s], vec![ExtKeyUsage::ANY], true),
        (vec![ExtKeyUsage::ANY], vec![s], true),
        (vec![ExtKeyUsage::CLIENT_AUTH], vec![s], false),
    ];
    for (root_ekus, verify_ekus, succeed) in cases {
        let tmpl = Certificate {
            serial_number: Some(BigInt::from_i64(1)),
            subject: pkix::Name {
                common_name: "root".to_string(),
                ..pkix::Name::default()
            },
            not_before: Time::unix(Time::now().unix_secs() - 3600, 0),
            not_after: Time::unix(Time::now().unix_secs() + 3600, 0),
            dns_names: vec!["localhost".to_string()],
            ext_key_usage: root_ekus.clone(),
            ..Certificate::default()
        };
        let der = create_certificate(&tmpl, &tmpl, &k.public_key, &k).unwrap();
        let root = parse_certificate(&der).unwrap();
        let mut roots = CertPool::new();
        roots.add_cert(&root);
        let result = root.verify(&VerifyOptions {
            roots: Some(&roots),
            key_usages: verify_ekus.clone(),
            ..VerifyOptions::default()
        });
        assert_eq!(
            result.is_ok(),
            succeed,
            "root EKUs {root_ekus:?}, verify EKUs {verify_ekus:?}"
        );
    }
}

/// An edge of the trust graphs of Go's `TestPathBuilding`.
struct Edge {
    issuer: &'static str,
    subject: &'static str,
    cert_type: CertType,
    mutate: Option<fn(&mut Certificate)>,
}

fn edge(issuer: &'static str, subject: &'static str, cert_type: CertType) -> Edge {
    Edge {
        issuer,
        subject,
        cert_type,
        mutate: None,
    }
}

/// Go's `buildTrustGraph` for roots without mutation.
fn build_trust_graph(
    roots: &[&str],
    leaf: &str,
    edges: &[Edge],
) -> (CertPool, CertPool, Certificate) {
    use std::collections::HashMap;
    let mut certs: HashMap<String, Certificate> = HashMap::new();
    let mut keys: HashMap<String, PrivateKey> = HashMap::new();
    let mut root_pool = CertPool::new();
    for r in roots {
        let k = p256();
        let root = gen_cert_edge(r, &k, |_| {}, CertType::Root, None, &k);
        root_pool.add_cert(&root);
        certs.insert((*r).to_string(), root);
        keys.insert((*r).to_string(), k);
    }
    let mut inter_pool = CertPool::new();
    for e in edges {
        let k = keys
            .entry(e.subject.to_string())
            .or_insert_with(p256)
            .clone();
        let issuer = certs
            .get(e.issuer)
            .unwrap_or_else(|| panic!("issuer {} not created yet", e.issuer))
            .clone();
        let issuer_key = keys[e.issuer].clone();
        let mutate = e.mutate;
        let cert = gen_cert_edge(
            e.subject,
            &k,
            |c| {
                if let Some(m) = mutate {
                    m(c)
                }
            },
            e.cert_type,
            Some(&issuer),
            &issuer_key,
        );
        if e.cert_type == CertType::Intermediate {
            inter_pool.add_cert(&cert);
        }
        certs.entry(e.subject.to_string()).or_insert(cert);
    }
    (root_pool, inter_pool, certs[leaf].clone())
}

fn chain_to_debug_string(chain: &[Arc<Certificate>]) -> String {
    chain
        .iter()
        .map(|c| format!("CN={}", c.subject.common_name))
        .collect::<Vec<_>>()
        .join(" -> ")
}

/// The first case of Go's `TestPathBuilding` (RFC 4158, figure 7): the edge
/// C -> B has an unusable EKU, so two of the three paths remain.
#[test]
fn path_building_bad_eku() {
    let edges = vec![
        edge("root", "inter a", CertType::Intermediate),
        edge("root", "inter c", CertType::Intermediate),
        edge("inter c", "inter a", CertType::Intermediate),
        edge("inter a", "inter c", CertType::Intermediate),
        Edge {
            issuer: "inter c",
            subject: "inter b",
            cert_type: CertType::Intermediate,
            mutate: Some(|c| c.ext_key_usage = vec![ExtKeyUsage::CODE_SIGNING]),
        },
        edge("inter a", "inter b", CertType::Intermediate),
        edge("inter b", "leaf", CertType::Leaf),
    ];
    let (roots, inters, leaf) = build_trust_graph(&["root"], "leaf", &edges);
    let chains = leaf
        .verify(&VerifyOptions {
            roots: Some(&roots),
            intermediates: Some(&inters),
            ..VerifyOptions::default()
        })
        .unwrap();
    let mut got: Vec<String> = chains.iter().map(|c| chain_to_debug_string(c)).collect();
    got.sort();
    let mut want = vec![
        "CN=leaf -> CN=inter b -> CN=inter a -> CN=inter c -> CN=root".to_string(),
        "CN=leaf -> CN=inter b -> CN=inter a -> CN=root".to_string(),
    ];
    want.sort();
    assert_eq!(got, want);
}

#[test]
fn pathological_chains_hit_the_signature_limit() {
    // Intermediates that all share a subject and a key appear to have signed
    // each other; without a root no chain can be built and the number of
    // signature checks is bounded.
    let key = p256();
    let mut intermediates = CertPool::new();
    let mut parent: Option<Certificate> = None;
    let mut signer = key.clone();
    for _ in 0..100 {
        let cert = gen_cert_edge(
            "Intermediate CA",
            &key,
            |_| {},
            if parent.is_none() {
                CertType::Root
            } else {
                CertType::Intermediate
            },
            parent.as_ref(),
            &signer,
        );
        intermediates.add_cert(&cert);
        parent = Some(cert);
        signer = key.clone();
    }
    let leaf = gen_cert_edge(
        "Leaf",
        &p256(),
        |_| {},
        CertType::Leaf,
        parent.as_ref(),
        &key,
    );
    let err = leaf
        .verify(&VerifyOptions {
            roots: Some(&CertPool::new()),
            intermediates: Some(&intermediates),
            ..VerifyOptions::default()
        })
        .unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("signature check attempts limit reached")
            || text.contains("unknown authority"),
        "{text}"
    );
}
