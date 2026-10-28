//! Tests of the policy graph (`policies_valid`), ported from Go's
//! verify_test.go (`TestPoliciesValid`) and pkits_test.go
//! (`TestNISTPKITSPolicy`). They live inside the crate because Go's tests call
//! the unexported `policiesValid`.

#[path = "../../tests/common/json.rs"]
mod json;

use std::path::PathBuf;
use std::sync::Arc;

use super::oid::{oid_from_ints, Oid};
use super::verify::{policies_valid, VerifyOptions};
use super::{parse_certificate, pem, Certificate};
use json::Json;

fn fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/x509")
        .join(path)
}

fn policy_cert(name: &str) -> Arc<Certificate> {
    let path = fixture(&format!("policy/policy_{name}.pem"));
    let data = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let (block, _) = pem::decode(&data);
    Arc::new(parse_certificate(&block.expect("PEM block").bytes).expect("certificate"))
}

fn test_oid(n: u64) -> Oid {
    oid_from_ints(&[1, 2, 840, 113554, 4, 1, 72585, 2, n]).unwrap()
}

fn options(
    policies: Vec<Oid>,
    require_explicit_policy: bool,
    inhibit_policy_mapping: bool,
    inhibit_any_policy: bool,
) -> VerifyOptions<'static> {
    VerifyOptions {
        certificate_policies: policies,
        require_explicit_policy,
        inhibit_policy_mapping,
        inhibit_any_policy,
        ..VerifyOptions::default()
    }
}

#[test]
fn policies_valid_table() {
    let table = Json::parse(&std::fs::read_to_string(fixture("policies_valid.json")).unwrap());
    let mut count = 0;
    for (i, case) in table.as_array().iter().enumerate() {
        let chain: Vec<Arc<Certificate>> = case
            .get("chain")
            .strings()
            .iter()
            .map(|n| policy_cert(n))
            .collect();
        let policies: Vec<Oid> = case
            .get("policies")
            .strings()
            .iter()
            .map(|p| test_oid(p.trim_start_matches("testOID").parse().unwrap()))
            .collect();
        let opts = options(
            policies,
            case.get("require_explicit_policy").as_bool(),
            case.get("inhibit_policy_mapping").as_bool(),
            case.get("inhibit_any_policy").as_bool(),
        );
        assert_eq!(
            policies_valid(&chain, &opts),
            case.get("valid").as_bool(),
            "case {i}: {:?}",
            case.get("chain").strings()
        );
        count += 1;
    }
    assert_eq!(count, 31);
}

/// The second half of Go's `TestPoliciesValid`, which runs once with
/// `policy_intermediate_mapped` and once with `policy_intermediate_mapped_any`.
#[test]
fn policies_valid_mapped_intermediates() {
    let root = policy_cert("root");
    let leaf = policy_cert("leaf");
    for use_any in [false, true] {
        let intermediate = policy_cert(if use_any {
            "intermediate_mapped_any"
        } else {
            "intermediate_mapped"
        });
        let cases: Vec<(&str, u64, bool)> = vec![
            ("leaf", 3, true),
            ("leaf_oid1", 3, true),
            ("leaf_oid2", 3, true),
            ("leaf_oid3", 3, use_any),
            ("leaf_oid1", 1, !use_any),
            ("leaf_oid4", 4, true),
            ("leaf_oid4", 5, true),
            ("leaf_oid5", 4, true),
            ("leaf_oid5", 5, true),
        ];
        for (leaf_name, policy, valid) in cases {
            let leaf_cert = if leaf_name == "leaf" {
                leaf.clone()
            } else {
                policy_cert(leaf_name)
            };
            let chain = vec![leaf_cert, intermediate.clone(), root.clone()];
            let opts = options(vec![test_oid(policy)], true, false, false);
            assert_eq!(
                policies_valid(&chain, &opts),
                valid,
                "{leaf_name} with policy {policy} (use_any={use_any})"
            );
        }
        let chain = vec![policy_cert("leaf_oid4"), intermediate.clone(), root.clone()];
        let opts = options(vec![test_oid(4), test_oid(5)], true, false, false);
        assert!(policies_valid(&chain, &opts), "use_any={use_any}");
    }
}

fn nist_policy(name: &str) -> Oid {
    match name {
        "anyPolicy" => oid_from_ints(&[2, 5, 29, 32, 0]).unwrap(),
        "NIST-test-policy-1" => oid_from_ints(&[2, 16, 840, 1, 101, 3, 2, 1, 48, 1]).unwrap(),
        "NIST-test-policy-2" => oid_from_ints(&[2, 16, 840, 1, 101, 3, 2, 1, 48, 2]).unwrap(),
        "NIST-test-policy-3" => oid_from_ints(&[2, 16, 840, 1, 101, 3, 2, 1, 48, 3]).unwrap(),
        "NIST-test-policy-6" => oid_from_ints(&[2, 16, 840, 1, 101, 3, 2, 1, 48, 6]).unwrap(),
        other => panic!("unknown test policy: {other}"),
    }
}

#[test]
fn nist_pkits_policy() {
    let vectors = Json::parse(&std::fs::read_to_string(fixture("pkits/vectors.json")).unwrap());
    let mut count = 0;
    for tc in vectors.as_array() {
        let mut chain: Vec<Arc<Certificate>> = tc
            .get("CertPath")
            .strings()
            .iter()
            .map(|c| {
                let der = std::fs::read(fixture(&format!("pkits/{c}"))).unwrap();
                Arc::new(parse_certificate(&der).unwrap_or_else(|e| panic!("{c}: {e}")))
            })
            .collect();
        chain.reverse();
        let initial: Vec<Oid> = tc
            .get("InitialPolicySet")
            .strings()
            .iter()
            .map(|p| nist_policy(p))
            .collect();
        let opts = options(
            initial,
            tc.get("InitialExplicitPolicy").as_bool(),
            tc.get("InitialPolicyMappingInhibit").as_bool(),
            tc.get("InitialAnyPolicyInhibit").as_bool(),
        );
        assert_eq!(
            policies_valid(&chain, &opts),
            tc.get("ShouldValidate").as_bool(),
            "{}",
            tc.get("Name").as_str()
        );
        count += 1;
    }
    assert!(count >= 80, "{count} PKITS policy vectors");
}
