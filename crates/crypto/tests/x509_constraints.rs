//! crypto/x509 name constraints, ported from Go's name_constraints_test.go: the
//! `nameConstraintsTests` table (dumped from Go's source by
//! tools/x509_vectors_gen.py), the RFC 2821 mailbox table and the checks for
//! bad names in constraints and SANs.

mod common;

use std::sync::Arc;

use common::json::Json;
use rust_stdlib_crypto::ecdsa::{self, PrivateKey};
use rust_stdlib_crypto::elliptic;
use rust_stdlib_crypto::x509::{
    self, create_certificate, parse_certificate, parse_ip, pkix, url, BigInt, CertPool,
    Certificate, ExtKeyUsage, Ip, IpNet, KeyUsage, ObjectIdentifier, Time, VerifyOptions,
};

fn fixture(path: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/x509")
        .join(path);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn new_key() -> PrivateKey {
    ecdsa::generate_key(elliptic::p256()).expect("key")
}

fn serial() -> BigInt {
    let mut bytes = [0u8; 16];
    rust_stdlib_crypto::rand::read(&mut bytes);
    BigInt::from_be_bytes(&bytes)
}

/// Go's `parseEKUs`.
fn parse_ekus(ekus: &[String]) -> Result<(Vec<ExtKeyUsage>, Vec<ObjectIdentifier>), String> {
    let mut known = Vec::new();
    let mut unknown = Vec::new();
    for s in ekus {
        match s.as_str() {
            "serverAuth" => known.push(ExtKeyUsage::SERVER_AUTH),
            "clientAuth" => known.push(ExtKeyUsage::CLIENT_AUTH),
            "email" => known.push(ExtKeyUsage::EMAIL_PROTECTION),
            "netscapeSGC" => known.push(ExtKeyUsage::NETSCAPE_SERVER_GATED_CRYPTO),
            "msSGC" => known.push(ExtKeyUsage::MICROSOFT_SERVER_GATED_CRYPTO),
            "any" => known.push(ExtKeyUsage::ANY),
            "other" => unknown.push(ObjectIdentifier(vec![2, 4, 1, 2, 3])),
            other => return Err(format!("unknown EKU {other:?}")),
        }
    }
    Ok((known, unknown))
}

/// `net.ParseCIDR`: the network address and mask.
fn parse_cidr(s: &str) -> Result<IpNet, String> {
    let (addr, bits) = s.split_once('/').ok_or("no slash")?;
    let ip = parse_ip(addr).ok_or_else(|| format!("invalid CIDR address: {s}"))?;
    let bits: usize = bits
        .parse()
        .map_err(|_| format!("invalid CIDR address: {s}"))?;
    // net.ParseCIDR keeps IPv4 networks in the 4 byte form.
    let ip_bytes: Vec<u8> = match ip.to4() {
        Some(v4) if !addr.contains(':') => v4.to_vec(),
        _ => ip.0.clone(),
    };
    let total = ip_bytes.len() * 8;
    if bits > total {
        return Err(format!("invalid CIDR address: {s}"));
    }
    let mut mask = vec![0u8; ip_bytes.len()];
    for i in 0..bits {
        mask[i / 8] |= 0x80 >> (i % 8);
    }
    let masked: Vec<u8> = ip_bytes.iter().zip(&mask).map(|(a, m)| a & m).collect();
    Ok(IpNet {
        ip: Ip(masked),
        mask,
    })
}

struct Spec {
    ok: Vec<String>,
    bad: Vec<String>,
    ekus: Vec<String>,
}

impl Spec {
    fn from_json(j: &Json) -> Spec {
        Spec {
            ok: j.get("ok").strings(),
            bad: j.get("bad").strings(),
            ekus: j.get("ekus").strings(),
        }
    }
}

type Constraints = (Vec<String>, Vec<IpNet>, Vec<String>, Vec<String>);

fn custom_constraints_extension(
    type_num: u8,
    constraint: &[u8],
    is_excluded: bool,
) -> pkix::Extension {
    let tag = if is_excluded { 1u8 } else { 0u8 };
    let mut contents = vec![
        tag | 32 | 0x80,
        (4 + constraint.len()) as u8,
        0x30,
        (2 + constraint.len()) as u8,
        type_num,
        constraint.len() as u8,
    ];
    contents.extend_from_slice(constraint);
    let mut value = vec![0x30, contents.len() as u8];
    value.extend(contents);
    pkix::Extension {
        id: ObjectIdentifier(vec![2, 5, 29, 30]),
        critical: false,
        value,
    }
}

fn add_constraints_to_template(spec: &Spec, template: &mut Certificate) -> Result<(), String> {
    let parse = |constraints: &[String]| -> Result<Constraints, String> {
        let (mut dns, mut ips, mut emails, mut uris) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for c in constraints {
            if let Some(v) = c.strip_prefix("dns:") {
                dns.push(v.to_string());
            } else if let Some(v) = c.strip_prefix("ip:") {
                ips.push(parse_cidr(v)?);
            } else if let Some(v) = c.strip_prefix("email:") {
                emails.push(v.to_string());
            } else if let Some(v) = c.strip_prefix("uri:") {
                uris.push(v.to_string());
            } else {
                return Err(format!("unknown constraint {c:?}"));
            }
        }
        Ok((dns, ips, emails, uris))
    };

    let special = |constraint: &str, excluded: bool, template: &mut Certificate| -> bool {
        if constraint == "unknown:" {
            template
                .extra_extensions
                .push(custom_constraints_extension(9, &[1], excluded));
            true
        } else {
            false
        }
    };
    if spec.ok.len() == 1 && spec.bad.is_empty() && special(&spec.ok[0], false, template) {
        return Ok(());
    }
    if spec.bad.len() == 1 && spec.ok.is_empty() && special(&spec.bad[0], true, template) {
        return Ok(());
    }

    (
        template.permitted_dns_domains,
        template.permitted_ip_ranges,
        template.permitted_email_addresses,
        template.permitted_uri_domains,
    ) = parse(&spec.ok)?;
    (
        template.excluded_dns_domains,
        template.excluded_ip_ranges,
        template.excluded_email_addresses,
        template.excluded_uri_domains,
    ) = parse(&spec.bad)?;
    let (known, unknown) = parse_ekus(&spec.ekus)?;
    template.ext_key_usage = known;
    template.unknown_ext_key_usage = unknown;
    Ok(())
}

fn make_constraints_ca_cert(
    spec: &Spec,
    name: &str,
    key: &PrivateKey,
    parent: Option<&Certificate>,
    parent_key: &PrivateKey,
) -> Result<Certificate, String> {
    let mut template = Certificate {
        serial_number: Some(serial()),
        subject: pkix::Name {
            common_name: name.to_string(),
            ..pkix::Name::default()
        },
        not_before: Time::unix(1000, 0),
        not_after: Time::unix(2000, 0),
        key_usage: KeyUsage::CERT_SIGN,
        basic_constraints_valid: true,
        is_ca: true,
        ..Certificate::default()
    };
    add_constraints_to_template(spec, &mut template)?;
    let der = {
        let parent_ref = parent.unwrap_or(&template);
        create_certificate(&template, parent_ref, &key.public_key, parent_key)
            .map_err(|e| e.to_string())?
    };
    parse_certificate(&der).map_err(|e| e.to_string())
}

struct Leaf {
    sans: Vec<String>,
    ekus: Vec<String>,
    cn: String,
}

fn make_constraints_leaf_cert(
    leaf: &Leaf,
    key: &PrivateKey,
    parent: Option<&Certificate>,
    parent_key: &PrivateKey,
) -> Result<Certificate, String> {
    let mut template = Certificate {
        serial_number: Some(serial()),
        subject: pkix::Name {
            organizational_unit: vec!["Leaf".to_string()],
            common_name: leaf.cn.clone(),
            ..pkix::Name::default()
        },
        not_before: Time::unix(1000, 0),
        not_after: Time::unix(2000, 0),
        key_usage: KeyUsage::DIGITAL_SIGNATURE,
        basic_constraints_valid: true,
        is_ca: false,
        ..Certificate::default()
    };
    for name in &leaf.sans {
        if let Some(v) = name.strip_prefix("dns:") {
            template.dns_names.push(v.to_string());
        } else if let Some(v) = name.strip_prefix("ip:") {
            let ip = parse_ip(v).ok_or_else(|| format!("cannot parse IP {v:?}"))?;
            template.ip_addresses.push(ip);
        } else if let Some(v) = name.strip_prefix("invalidip:") {
            template.ip_addresses.push(Ip(common::unhex(v)));
        } else if let Some(v) = name.strip_prefix("email:") {
            template.email_addresses.push(v.to_string());
        } else if let Some(v) = name.strip_prefix("uri:") {
            let uri = url::parse(v).map_err(|e| format!("cannot parse URI {v:?}: {e}"))?;
            template.uris.push(uri);
        } else if name.starts_with("unknown:") {
            // A custom SAN extension with an undefined GeneralName type.
            assert_eq!(leaf.sans.len(), 1, "unknown names must be the sole name");
            template.extra_extensions.push(pkix::Extension {
                id: ObjectIdentifier(vec![2, 5, 29, 17]),
                critical: false,
                value: vec![0x30, 3, 9, 1, 1],
            });
        } else {
            return Err(format!("unknown name type {name:?}"));
        }
    }
    let (known, unknown) = parse_ekus(&leaf.ekus)?;
    template.ext_key_usage = known;
    template.unknown_ext_key_usage = unknown;
    let der = {
        let parent_ref = parent.unwrap_or(&template);
        create_certificate(&template, parent_ref, &key.public_key, parent_key)
            .map_err(|e| e.to_string())?
    };
    parse_certificate(&der).map_err(|e| e.to_string())
}

#[test]
fn constraint_cases() {
    let table = Json::parse(&fixture("name_constraints.json"));
    assert_eq!(table.as_array().len(), 107);
    for (i, test) in table.as_array().iter().enumerate() {
        let name = test.get("name").as_str();
        let mut root_pool = CertPool::new();
        let root_key = new_key();
        let root_name = format!("Root {i}");
        let mut parent: Option<Certificate> = None;
        let mut parent_key = root_key.clone();

        for root in test.get("roots").as_array() {
            let cert = make_constraints_ca_cert(
                &Spec::from_json(root),
                &root_name,
                &root_key,
                None,
                &root_key,
            )
            .unwrap_or_else(|e| panic!("{name}: failed to create root: {e}"));
            root_pool.add_cert(&cert);
            parent = Some(cert);
        }

        let mut intermediate_pool = CertPool::new();
        for (level, intermediates) in test.get("intermediates").as_array().iter().enumerate() {
            let level_key = new_key();
            let level_name = format!("Intermediate level {level}");
            let mut last = None;
            for intermediate in intermediates.as_array() {
                let cert = make_constraints_ca_cert(
                    &Spec::from_json(intermediate),
                    &level_name,
                    &level_key,
                    parent.as_ref(),
                    &parent_key,
                )
                .unwrap_or_else(|e| panic!("{name}: failed to create {level_name:?}: {e}"));
                intermediate_pool.add_cert(&cert);
                last = Some(cert);
            }
            parent = last;
            parent_key = level_key;
        }

        let leaf_key = new_key();
        let leaf_json = test.get("leaf");
        let leaf = Leaf {
            sans: leaf_json.get("sans").strings(),
            ekus: leaf_json.get("ekus").strings(),
            cn: leaf_json.get("cn").as_str().to_string(),
        };
        let leaf_cert = make_constraints_leaf_cert(&leaf, &leaf_key, parent.as_ref(), &parent_key)
            .unwrap_or_else(|e| panic!("{name}: cannot create leaf: {e}"));

        let opts = VerifyOptions {
            roots: Some(&root_pool),
            intermediates: Some(&intermediate_pool),
            current_time: Time::unix(1500, 0),
            key_usages: test
                .get("requested_ekus")
                .as_array()
                .iter()
                .map(|e| ExtKeyUsage(e.as_i64() as i32))
                .collect(),
            ..VerifyOptions::default()
        };
        let result = leaf_cert.verify(&opts);
        let expected = test.get("expected_error").as_str();
        if expected.is_empty() {
            if let Err(e) = result {
                panic!("{name}: unexpected failure: {e}");
            }
        } else {
            match result {
                Ok(_) => panic!("{name}: unexpected success"),
                Err(e) => assert!(
                    e.to_string().contains(expected),
                    "{name}: expected error containing {expected:?}, but got: {e}"
                ),
            }
        }
    }
}

#[test]
fn name_constraint_ip_non_zero_host_bits() {
    let root_key = new_key();
    let leaf_key = new_key();

    // Two excluded iPAddress subtrees: a lower-addressed range that takes the
    // binary-search neighbor slot, and one whose address has host bits set
    // (10.10.10.10/16, i.e. network 10.10.0.0/16).
    let subtree = |b: &[u8]| -> Vec<u8> {
        let mut gn = vec![0x87, b.len() as u8];
        gn.extend_from_slice(b);
        let mut out = vec![0x30, gn.len() as u8];
        out.extend(gn);
        out
    };
    let mut subtrees = subtree(&[10, 0, 0, 0, 255, 255, 255, 252]);
    subtrees.extend(subtree(&[10, 10, 10, 10, 255, 255, 0, 0]));
    let mut excluded = vec![0xa1, subtrees.len() as u8];
    excluded.extend(subtrees);
    let mut nc_value = vec![0x30, excluded.len() as u8];
    nc_value.extend(excluded);

    let root_tmpl = Certificate {
        serial_number: Some(serial()),
        subject: pkix::Name {
            common_name: "Root".to_string(),
            ..pkix::Name::default()
        },
        not_before: Time::unix(1000, 0),
        not_after: Time::unix(2000, 0),
        key_usage: KeyUsage::CERT_SIGN,
        basic_constraints_valid: true,
        is_ca: true,
        extra_extensions: vec![pkix::Extension {
            id: ObjectIdentifier(vec![2, 5, 29, 30]),
            critical: true,
            value: nc_value,
        }],
        ..Certificate::default()
    };
    let root_der =
        create_certificate(&root_tmpl, &root_tmpl, &root_key.public_key, &root_key).unwrap();
    let root = parse_certificate(&root_der).unwrap();

    // The parsed range keeps the address as encoded, host bits and all.
    assert_eq!(root.excluded_ip_ranges.len(), 2);
    assert!(root.excluded_ip_ranges[1]
        .ip
        .equal(&Ip(vec![10, 10, 10, 10])));

    let leaf = make_constraints_leaf_cert(
        &Leaf {
            sans: vec!["ip:10.10.0.1".to_string()],
            ekus: vec![],
            cn: String::new(),
        },
        &leaf_key,
        Some(&root),
        &root_key,
    )
    .unwrap();

    let mut roots = CertPool::new();
    roots.add_cert(&root);
    let err = leaf
        .verify(&VerifyOptions {
            roots: Some(&roots),
            current_time: Time::unix(1500, 0),
            ..VerifyOptions::default()
        })
        .expect_err("leaf with IP SAN inside excluded range was accepted");
    assert!(err.to_string().contains("excluded by constraint"), "{err}");
}

#[test]
#[allow(clippy::type_complexity)] // a table of matcher closures
fn bad_names_in_constraints() {
    let constraint_parse_error =
        |e: &str| e.contains("failed to parse ") && e.contains("constraint");
    let encoding_error = |e: &str| e.contains("cannot be encoded as an IA5String");
    let bad_names: Vec<(&str, &dyn Fn(&str) -> bool)> = vec![
        ("dns:foo.com.", &constraint_parse_error),
        ("email:abc@foo.com.", &constraint_parse_error),
        ("email:foo.com.", &constraint_parse_error),
        ("uri:example.com.", &constraint_parse_error),
        ("uri:1.2.3.4", &constraint_parse_error),
        ("uri:ffff::1", &constraint_parse_error),
        ("dns:not\u{2013}hyphen.com", &encoding_error),
        ("email:foo@not\u{2013}hyphen.com", &encoding_error),
        ("uri:not\u{2013}hyphen.com", &encoding_error),
    ];
    let priv_key = new_key();
    for (name, matcher) in bad_names {
        // Creating the certificate rejects non-IA5 names; parsing it rejects
        // the others.
        let spec = Spec {
            ok: vec![name.to_string()],
            bad: vec![],
            ekus: vec![],
        };
        match make_constraints_ca_cert(
            &spec,
            "TestAbsoluteNamesInConstraints",
            &priv_key,
            None,
            &priv_key,
        ) {
            Ok(_) => panic!("bad name {name:?} unexpectedly accepted in name constraint"),
            Err(e) => assert!(
                matcher(&e),
                "bad name {name:?} triggered unrecognised error: {e}"
            ),
        }
    }
}

#[test]
fn bad_names_in_sans() {
    // Bad names in URI and IP SANs should not parse. Bad DNS and email SANs
    // parse and are tested in the name constraint cases.
    let priv_key = new_key();
    for bad_name in [
        "uri:https://example.com./dsf",
        "invalidip:0102",
        "invalidip:0102030405",
    ] {
        let leaf = Leaf {
            sans: vec![bad_name.to_string()],
            ekus: vec![],
            cn: String::new(),
        };
        match make_constraints_leaf_cert(&leaf, &priv_key, None, &priv_key) {
            Ok(_) => panic!("bad name {bad_name:?} unexpectedly accepted in SAN"),
            Err(e) => assert!(
                e.contains("cannot parse "),
                "bad name {bad_name:?} triggered unrecognised error: {e}"
            ),
        }
    }
}

#[allow(dead_code)]
fn _arc(_: Arc<Certificate>, _: x509::Error) {}
