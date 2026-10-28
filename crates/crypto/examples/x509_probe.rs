//! Rust probe for tools/x509_check.py: the same line protocol and text dump as
//! tools/x509_oracle.go, so that equal output lines mean every field matched.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{self, BufRead, Write};

use rust_stdlib_crypto::x509::pkix::{self, Value};
use rust_stdlib_crypto::x509::{self, Certificate, Error};

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for v in b {
        let _ = write!(s, "{v:02x}");
    }
    s
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

struct Fields(HashMap<String, String>);

impl Fields {
    fn get(&self, key: &str) -> &str {
        self.0.get(key).map(String::as_str).unwrap_or("")
    }
    fn b(&self, key: &str) -> Vec<u8> {
        unhex(self.get(key))
    }
    fn list(&self, key: &str) -> Vec<Vec<u8>> {
        if self.get(key).is_empty() {
            return Vec::new();
        }
        self.get(key).split(',').map(unhex).collect()
    }
}

#[derive(Default)]
struct Dump(String);

impl Dump {
    fn w(&mut self, k: &str, v: impl std::fmt::Display) {
        let _ = writeln!(self.0, "{k}={v}");
    }
    fn h(&mut self, k: &str, v: &[u8]) {
        let _ = writeln!(self.0, "{k}={}", hex(v));
    }
    fn strs(&mut self, k: &str, v: &[String]) {
        self.w(&format!("{k}.len"), v.len());
        for (i, s) in v.iter().enumerate() {
            self.h(&format!("{k}[{i}]"), s.as_bytes());
        }
    }
}

/// Like Go's `t.UTC().Format(time.RFC3339Nano)`.
fn fmt_time(t: &x509::Time) -> String {
    let text = t.format_rfc3339();
    match t.nanosecond() {
        0 => text,
        nanos => {
            let fraction = format!("{nanos:09}");
            let (seconds, zone) = text.split_at(text.len() - 1);
            format!("{seconds}.{}{zone}", fraction.trim_end_matches('0'))
        }
    }
}

fn oids(v: &[x509::ObjectIdentifier]) -> String {
    v.iter()
        .map(|o| o.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn val_dump(v: &Value) -> String {
    match v {
        Value::Nil => "nil".to_string(),
        Value::String(s) => format!("s:{}", hex(s.as_bytes())),
        Value::Int(i) => format!("i:{i}"),
        Value::Bool(b) => format!("b:{b}"),
        Value::Bytes(b) => format!("o:{}", hex(b)),
        Value::BitString(b) => format!("bs:{}/{}", hex(&b.bytes), b.bit_length),
        Value::ObjectIdentifier(o) => format!("oid:{}", o),
        Value::Time(t) => format!("t:{}", fmt_time(t)),
        Value::Raw(r) => format!(
            "raw:{},{},{},{},{}",
            r.class,
            r.tag,
            r.is_compound,
            hex(&r.bytes),
            hex(&r.full_bytes)
        ),
    }
}

fn dump_name(d: &mut Dump, p: &str, n: &pkix::Name) {
    d.w(&format!("{p}.string"), hex(n.to_string().as_bytes()));
    d.strs(&format!("{p}.country"), &n.country);
    d.strs(&format!("{p}.organization"), &n.organization);
    d.strs(&format!("{p}.ou"), &n.organizational_unit);
    d.strs(&format!("{p}.locality"), &n.locality);
    d.strs(&format!("{p}.province"), &n.province);
    d.strs(&format!("{p}.street"), &n.street_address);
    d.strs(&format!("{p}.postal"), &n.postal_code);
    d.h(&format!("{p}.serial"), n.serial_number.as_bytes());
    d.h(&format!("{p}.cn"), n.common_name.as_bytes());
    d.w(&format!("{p}.names.len"), n.names.len());
    for (i, a) in n.names.iter().enumerate() {
        d.w(
            &format!("{p}.names[{i}]"),
            format!("{}|{}", a.type_, val_dump(&a.value)),
        );
    }
    match n.to_rdn_sequence().marshal() {
        Ok(b) => d.h(&format!("{p}.rdn"), &b),
        Err(_) => d.w(&format!("{p}.rdn"), "err"),
    }
}

fn dump_exts(d: &mut Dump, p: &str, exts: &[pkix::Extension]) {
    d.w(&format!("{p}.len"), exts.len());
    for (i, e) in exts.iter().enumerate() {
        d.w(
            &format!("{p}[{i}]"),
            format!("{}|{}|{}", e.id, e.critical, hex(&e.value)),
        );
    }
}

fn ips(v: &[x509::Ip]) -> String {
    v.iter().map(|i| hex(&i.0)).collect::<Vec<_>>().join(",")
}

fn ipnets(v: &[x509::IpNet]) -> String {
    v.iter()
        .map(|n| format!("{}/{}", hex(&n.ip.0), hex(&n.mask)))
        .collect::<Vec<_>>()
        .join(",")
}

fn urls(v: &[x509::url::Url]) -> String {
    v.iter()
        .map(|u| hex(u.to_string().as_bytes()))
        .collect::<Vec<_>>()
        .join(",")
}

fn dump_public_key(d: &mut Dump, p: &str, k: Option<&x509::PublicKey>) {
    let Some(k) = k else {
        d.w(p, "nil");
        return;
    };
    d.w(
        &format!("{p}.type"),
        match k {
            x509::PublicKey::Rsa(_) => "*rsa.PublicKey",
            x509::PublicKey::Dsa(_) => "*dsa.PublicKey",
            x509::PublicKey::Ecdsa(_) => "*ecdsa.PublicKey",
            x509::PublicKey::Ed25519(_) => "ed25519.PublicKey",
            x509::PublicKey::Mldsa(_) => "*mldsa.PublicKey",
            x509::PublicKey::Ecdh(_) => "*ecdh.PublicKey",
        },
    );
    match x509::marshal_pkix_public_key(k.as_any()) {
        Ok(b) => d.h(&format!("{p}.pkix"), &b),
        Err(e) => d.h(&format!("{p}.pkix_err"), e.to_string().as_bytes()),
    }
    if let x509::PublicKey::Rsa(rk) = k {
        d.h(&format!("{p}.pkcs1"), &x509::marshal_pkcs1_public_key(rk));
    }
}

fn sig_alg(a: x509::SignatureAlgorithm) -> String {
    format!("{}:{}", a.0, a)
}

fn check_line(d: &mut Dump, key: &str, r: Result<(), Error>) {
    match r {
        Ok(()) => d.w(key, "ok"),
        Err(e) => d.h(key, e.to_string().as_bytes()),
    }
}

fn dump_cert(c: &Certificate) -> String {
    let mut d = Dump::default();
    d.h("raw", &c.raw);
    d.h("raw_tbs", &c.raw_tbs_certificate);
    d.h("raw_spki", &c.raw_subject_public_key_info);
    d.h("raw_subject", &c.raw_subject);
    d.h("raw_issuer", &c.raw_issuer);
    d.h("raw_sigalg", &c.raw_signature_algorithm);
    d.h("signature", &c.signature);
    d.w("sigalg", sig_alg(c.signature_algorithm));
    d.w(
        "pkalg",
        format!("{}:{}", c.public_key_algorithm.0, c.public_key_algorithm),
    );
    dump_public_key(&mut d, "pk", c.public_key.as_ref());
    d.w("version", c.version);
    d.w(
        "serial",
        c.serial_number
            .as_ref()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "<nil>".to_string()),
    );
    dump_name(&mut d, "issuer", &c.issuer);
    dump_name(&mut d, "subject", &c.subject);
    d.w("not_before", fmt_time(&c.not_before));
    d.w("not_after", fmt_time(&c.not_after));
    d.w("key_usage", c.key_usage.0);
    dump_exts(&mut d, "ext", &c.extensions);
    d.w("unhandled", oids(&c.unhandled_critical_extensions));
    d.w(
        "eku",
        c.ext_key_usage
            .iter()
            .map(|e| format!("{}:{}", e.0, e))
            .collect::<Vec<_>>()
            .join(","),
    );
    d.w("unknown_eku", oids(&c.unknown_ext_key_usage));
    d.w(
        "bc",
        format!(
            "{}|{}|{}|{}",
            c.basic_constraints_valid, c.is_ca, c.max_path_len, c.max_path_len_zero
        ),
    );
    d.h("skid", &c.subject_key_id);
    d.h("akid", &c.authority_key_id);
    d.strs("ocsp", &c.ocsp_server);
    d.strs("issuing", &c.issuing_certificate_url);
    d.strs("dns", &c.dns_names);
    d.strs("email", &c.email_addresses);
    d.w("ips", ips(&c.ip_addresses));
    d.w("uris", urls(&c.uris));
    d.w("pdc", c.permitted_dns_domains_critical);
    d.strs("pdns", &c.permitted_dns_domains);
    d.strs("edns", &c.excluded_dns_domains);
    d.w("pip", ipnets(&c.permitted_ip_ranges));
    d.w("eip", ipnets(&c.excluded_ip_ranges));
    d.strs("pemail", &c.permitted_email_addresses);
    d.strs("eemail", &c.excluded_email_addresses);
    d.strs("puri", &c.permitted_uri_domains);
    d.strs("euri", &c.excluded_uri_domains);
    d.strs("crldp", &c.crl_distribution_points);
    d.w("policy_ids", oids(&c.policy_identifiers));
    d.w(
        "policies",
        c.policies
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(","),
    );
    d.w(
        "inhibit_any",
        format!("{}|{}", c.inhibit_any_policy, c.inhibit_any_policy_zero),
    );
    d.w(
        "inhibit_map",
        format!(
            "{}|{}",
            c.inhibit_policy_mapping, c.inhibit_policy_mapping_zero
        ),
    );
    d.w(
        "require_explicit",
        format!(
            "{}|{}",
            c.require_explicit_policy, c.require_explicit_policy_zero
        ),
    );
    d.w(
        "policy_mappings",
        c.policy_mappings
            .iter()
            .map(|m| format!("{}>{}", m.issuer_domain_policy, m.subject_domain_policy))
            .collect::<Vec<_>>()
            .join(","),
    );
    check_line(&mut d, "selfsig", c.check_signature_from(c));
    check_line(
        &mut d,
        "sigcheck",
        c.check_signature(c.signature_algorithm, &c.raw_tbs_certificate, &c.signature),
    );
    d.0
}

fn dump_csr(c: &x509::CertificateRequest) -> String {
    let mut d = Dump::default();
    d.h("raw", &c.raw);
    d.h("raw_tbs", &c.raw_tbs_certificate_request);
    d.h("raw_spki", &c.raw_subject_public_key_info);
    d.h("raw_subject", &c.raw_subject);
    d.h("raw_sigalg", &c.raw_signature_algorithm);
    d.w("version", c.version);
    d.h("signature", &c.signature);
    d.w("sigalg", sig_alg(c.signature_algorithm));
    d.w(
        "pkalg",
        format!("{}:{}", c.public_key_algorithm.0, c.public_key_algorithm),
    );
    dump_public_key(&mut d, "pk", c.public_key.as_ref());
    dump_name(&mut d, "subject", &c.subject);
    d.w("attrs.len", c.attributes.len());
    for (i, a) in c.attributes.iter().enumerate() {
        let vs: Vec<String> = a
            .value
            .iter()
            .map(|set| {
                set.iter()
                    .map(|atv| format!("{}={}", atv.type_, val_dump(&atv.value)))
                    .collect::<Vec<_>>()
                    .join(";")
            })
            .collect();
        d.w(
            &format!("attr[{i}]"),
            format!("{}|{}", a.type_, vs.join("/")),
        );
    }
    dump_exts(&mut d, "ext", &c.extensions);
    d.strs("dns", &c.dns_names);
    d.strs("email", &c.email_addresses);
    d.w("ips", ips(&c.ip_addresses));
    d.w("uris", urls(&c.uris));
    check_line(&mut d, "sigcheck", c.check_signature());
    d.0
}

fn dump_rl(rl: &x509::RevocationList) -> String {
    let mut d = Dump::default();
    d.h("raw", &rl.raw);
    d.h("raw_tbs", &rl.raw_tbs_revocation_list);
    d.h("raw_issuer", &rl.raw_issuer);
    d.h("raw_sigalg", &rl.raw_signature_algorithm);
    dump_name(&mut d, "issuer", &rl.issuer);
    d.h("akid", &rl.authority_key_id);
    d.h("signature", &rl.signature);
    d.w("sigalg", sig_alg(rl.signature_algorithm));
    d.w(
        "number",
        rl.number
            .as_ref()
            .map(|n| n.to_string())
            .unwrap_or_else(|| "<nil>".to_string()),
    );
    d.w("this_update", fmt_time(&rl.this_update));
    d.w("next_update", fmt_time(&rl.next_update));
    d.w("entries.len", rl.revoked_certificate_entries.len());
    for (i, e) in rl.revoked_certificate_entries.iter().enumerate() {
        d.w(
            &format!("entry[{i}]"),
            format!(
                "{}|{}|{}|{}",
                e.serial_number
                    .as_ref()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "<nil>".to_string()),
                fmt_time(&e.revocation_time),
                e.reason_code,
                hex(&e.raw)
            ),
        );
        dump_exts(&mut d, &format!("entry[{i}].ext"), &e.extensions);
    }
    d.w("revoked.len", rl.revoked_certificates.len());
    for (i, e) in rl.revoked_certificates.iter().enumerate() {
        d.w(
            &format!("revoked[{i}]"),
            format!("{}|{}", e.serial_number, fmt_time(&e.revocation_time)),
        );
    }
    dump_exts(&mut d, "ext", &rl.extensions);
    d.0
}

fn dump_cert_list(cl: &pkix::CertificateList) -> String {
    let mut d = Dump::default();
    let t = &cl.tbs_cert_list;
    d.h("raw", &t.raw);
    d.w("version", t.version);
    d.w("sigalg", t.signature.algorithm.to_string());
    d.h("sigparams", &t.signature.parameters.full_bytes);
    d.w("issuer", hex(t.issuer.to_string().as_bytes()));
    d.w("this_update", fmt_time(&t.this_update));
    d.w("next_update", fmt_time(&t.next_update));
    d.w("revoked.len", t.revoked_certificates.len());
    for (i, e) in t.revoked_certificates.iter().enumerate() {
        d.w(
            &format!("revoked[{i}]"),
            format!("{}|{}", e.serial_number, fmt_time(&e.revocation_time)),
        );
        dump_exts(&mut d, &format!("revoked[{i}].ext"), &e.extensions);
    }
    dump_exts(&mut d, "ext", &t.extensions);
    d.w("outer_sigalg", cl.signature_algorithm.algorithm.to_string());
    d.h("sigvalue", &cl.signature_value.right_align());
    d.0
}

fn dump_private(k: &x509::PrivateKey) -> String {
    let mut d = Dump::default();
    let (type_name, public): (&str, Option<x509::PublicKey>) = match k {
        x509::PrivateKey::Rsa(k) => {
            d.h("pkcs1", &x509::marshal_pkcs1_private_key(k));
            (
                "*rsa.PrivateKey",
                Some(x509::PublicKey::Rsa(k.public_key.clone())),
            )
        }
        x509::PrivateKey::Ecdsa(k) => {
            match x509::marshal_ec_private_key(k) {
                Ok(b) => d.h("sec1", &b),
                Err(e) => d.h("sec1_err", e.to_string().as_bytes()),
            }
            (
                "*ecdsa.PrivateKey",
                Some(x509::PublicKey::Ecdsa(k.public_key.clone())),
            )
        }
        x509::PrivateKey::Ed25519(k) => (
            "ed25519.PrivateKey",
            Some(x509::PublicKey::Ed25519(k.public_key())),
        ),
        x509::PrivateKey::Mldsa(k) => (
            "*mldsa.PrivateKey",
            Some(x509::PublicKey::Mldsa(k.public_key())),
        ),
        x509::PrivateKey::Ecdh(k) => (
            "*ecdh.PrivateKey",
            Some(x509::PublicKey::Ecdh(k.public_key().clone())),
        ),
    };
    let mut head = Dump::default();
    head.w("type", type_name);
    head.0.push_str(&d.0);
    let mut d = head;
    match x509::marshal_pkcs8_private_key(k.as_any()) {
        Ok(b) => d.h("pkcs8", &b),
        Err(e) => d.h("pkcs8_err", e.to_string().as_bytes()),
    }
    dump_public_key(&mut d, "pub", public.as_ref());
    d.0
}

fn asn1_oid(o: &x509::Oid) -> (String, bool) {
    for p in o.to_string().split('.') {
        match p.parse::<i64>() {
            Ok(v) if v <= i64::from(i32::MAX) => {}
            _ => return (String::new(), false),
        }
    }
    (o.to_string(), true)
}

// ---- names ---------------------------------------------------------------

impl Fields {
    fn i(&self, key: &str) -> i64 {
        self.get(key).parse().unwrap_or(0)
    }
    fn strs(&self, key: &str) -> Vec<String> {
        self.list(key)
            .into_iter()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .collect()
    }
    fn text(&self, key: &str) -> String {
        String::from_utf8_lossy(&self.b(key)).into_owned()
    }
}

fn dotted(s: &str) -> x509::ObjectIdentifier {
    x509::ObjectIdentifier(s.split('.').map(|p| p.parse().unwrap_or(0)).collect())
}

fn dotted_list(f: &Fields, key: &str) -> Vec<x509::ObjectIdentifier> {
    if f.get(key).is_empty() {
        return Vec::new();
    }
    f.get(key).split(',').map(dotted).collect()
}

fn parse_atv(s: &str) -> pkix::AttributeTypeAndValue {
    let mut parts = s.splitn(3, ':');
    let oid = dotted(parts.next().unwrap_or(""));
    let kind = parts.next().unwrap_or("");
    let data = unhex(parts.next().unwrap_or(""));
    let text = || String::from_utf8_lossy(&data).into_owned();
    let value = match kind {
        "s" => Value::String(text()),
        "i" => Value::Int(text().parse().unwrap_or(0)),
        "b" => Value::Bool(text() == "true"),
        "o" => Value::Bytes(data.clone()),
        "n" => Value::Nil,
        "oid" => Value::ObjectIdentifier(dotted(&text())),
        "bs" => Value::BitString(x509::BitString {
            bytes: data[1..].to_vec(),
            bit_length: data[0] as usize,
        }),
        "t" => Value::Time(x509::Time::unix(text().parse().unwrap_or(0), 0)),
        "raw" => Value::Raw(x509::RawValue::from_full_bytes(data.clone())),
        _ => Value::Nil,
    };
    pkix::AttributeTypeAndValue { type_: oid, value }
}

fn parse_rdns(spec: &str) -> pkix::RDNSequence {
    let mut seq = pkix::RDNSequence::default();
    if spec.is_empty() {
        return seq;
    }
    for set in spec.split(';') {
        let mut rdn = pkix::RelativeDistinguishedNameSET::default();
        if set != "-" {
            for a in set.split('|') {
                rdn.0.push(parse_atv(a));
            }
        }
        seq.0.push(rdn);
    }
    seq
}

fn name_op(f: &Fields) -> Result<String, Error> {
    let seq = parse_rdns(f.get("rdns"));
    let mut d = Dump::default();
    d.h("seq.string", seq.to_string().as_bytes());
    match seq.marshal() {
        Ok(b) => d.h("seq.marshal", &b),
        Err(_) => d.w("seq.marshal", "err"),
    }
    let mut n = pkix::Name::default();
    n.fill_from_rdn_sequence(&seq);
    dump_name(&mut d, "filled", &n);
    let mut extra = Vec::new();
    for rdn in &seq.0 {
        extra.extend(rdn.0.iter().cloned());
    }
    let mut en = pkix::Name {
        common_name: "cn".to_string(),
        country: vec!["US".to_string()],
        organization: vec!["o1".to_string(), "o2".to_string()],
        extra_names: Some(extra),
        ..pkix::Name::default()
    };
    if f.get("noextra") == "1" {
        en.extra_names = None;
    }
    if f.get("empty_extra") == "1" {
        en.extra_names = Some(Vec::new());
    }
    dump_name(&mut d, "extra", &en);
    Ok(d.0)
}

// ---- creating ------------------------------------------------------------

fn signer_of(k: &x509::PrivateKey) -> Result<&dyn rust_stdlib_crypto::Signer, Error> {
    match k {
        x509::PrivateKey::Rsa(k) => Ok(k),
        x509::PrivateKey::Ecdsa(k) => Ok(k),
        x509::PrivateKey::Ed25519(k) => Ok(k),
        x509::PrivateKey::Mldsa(k) => Ok(k),
        x509::PrivateKey::Ecdh(_) => Err(Error::new("not a signer")),
    }
}

fn ip_net_list(f: &Fields, key: &str) -> Vec<x509::IpNet> {
    if f.get(key).is_empty() {
        return Vec::new();
    }
    f.get(key)
        .split(',')
        .map(|item| {
            let (ip, mask) = item.split_once('/').unwrap_or((item, ""));
            x509::IpNet {
                ip: x509::Ip(unhex(ip)),
                mask: unhex(mask),
            }
        })
        .collect()
}

fn ext_list(f: &Fields, key: &str) -> Vec<pkix::Extension> {
    if f.get(key).is_empty() {
        return Vec::new();
    }
    f.get(key)
        .split(',')
        .map(|item| {
            let mut parts = item.splitn(3, '|');
            let id = dotted(parts.next().unwrap_or(""));
            let critical = parts.next() == Some("true");
            let value = unhex(parts.next().unwrap_or(""));
            pkix::Extension {
                id,
                critical,
                value,
            }
        })
        .collect()
}

fn url_list(f: &Fields, key: &str) -> Vec<x509::url::Url> {
    f.strs(key)
        .iter()
        .map(|s| x509::url::parse(s).expect("generated URL parses"))
        .collect()
}

fn subject_from_spec(f: &Fields) -> pkix::Name {
    let mut n = pkix::Name {
        common_name: f.text("cn"),
        serial_number: f.text("sn"),
        country: f.strs("c"),
        organization: f.strs("o"),
        organizational_unit: f.strs("ou"),
        locality: f.strs("l"),
        province: f.strs("st"),
        street_address: f.strs("street"),
        postal_code: f.strs("postal"),
        ..pkix::Name::default()
    };
    if !f.get("xnames").is_empty() {
        n.extra_names = Some(f.get("xnames").split('|').map(parse_atv).collect());
    }
    n
}

fn template_from_spec(f: &Fields) -> Certificate {
    let mut t = Certificate::default();
    if !f.get("serial").is_empty() {
        t.serial_number = x509::BigInt::from_decimal(f.get("serial"));
    }
    t.not_before = x509::Time::unix(f.i("nb"), 0);
    t.not_after = x509::Time::unix(f.i("na"), 0);
    t.subject = subject_from_spec(f);
    t.raw_subject = f.b("rawsubject");
    t.key_usage = x509::KeyUsage(f.i("ku") as i32);
    if !f.get("eku").is_empty() {
        t.ext_key_usage = f
            .get("eku")
            .split(',')
            .map(|p| x509::ExtKeyUsage(p.parse().unwrap_or(0)))
            .collect();
    }
    t.unknown_ext_key_usage = dotted_list(f, "ueku");
    if !f.get("bc").is_empty() {
        let p: Vec<&str> = f.get("bc").split(':').collect();
        t.basic_constraints_valid = p[0] == "true";
        t.is_ca = p[1] == "true";
        t.max_path_len = p[2].parse().unwrap_or(0);
        t.max_path_len_zero = p[3] == "true";
    }
    t.subject_key_id = f.b("skid");
    t.authority_key_id = f.b("akid");
    t.ocsp_server = f.strs("ocsp");
    t.issuing_certificate_url = f.strs("issuing");
    t.dns_names = f.strs("dns");
    t.email_addresses = f.strs("email");
    t.ip_addresses = f.list("ip").into_iter().map(x509::Ip).collect();
    t.uris = url_list(f, "uri");
    t.permitted_dns_domains_critical = f.get("pdc") == "true";
    t.permitted_dns_domains = f.strs("pdns");
    t.excluded_dns_domains = f.strs("edns");
    t.permitted_ip_ranges = ip_net_list(f, "pip");
    t.excluded_ip_ranges = ip_net_list(f, "eip");
    t.permitted_email_addresses = f.strs("pemail");
    t.excluded_email_addresses = f.strs("eemail");
    t.permitted_uri_domains = f.strs("puri");
    t.excluded_uri_domains = f.strs("euri");
    t.crl_distribution_points = f.strs("crldp");
    t.policy_identifiers = dotted_list(f, "polids");
    if !f.get("pols").is_empty() {
        t.policies = f
            .get("pols")
            .split(',')
            .map(|p| x509::parse_oid(p).expect("policy OID"))
            .collect();
    }
    t.extra_extensions = ext_list(f, "extra");
    t.signature_algorithm = x509::SignatureAlgorithm(f.i("sigalg") as i32);
    t
}

fn create_op(f: &Fields) -> Result<String, Error> {
    let key = x509::parse_pkcs8_private_key(&f.b("key"))?;
    match f.get("what") {
        "cert" => {
            let signer = signer_of(&key)?;
            let tmpl = template_from_spec(f);
            let parent_cert;
            let parent = if f.get("parent").is_empty() {
                &tmpl
            } else {
                parent_cert = x509::parse_certificate(&f.b("parent"))?;
                &parent_cert
            };
            let pub_key;
            let pub_any: &dyn std::any::Any = if f.get("pub").is_empty() {
                signer.public()
            } else {
                pub_key = x509::parse_pkix_public_key(&f.b("pub"))?;
                &pub_key
            };
            let der = x509::create_certificate(&tmpl, parent, pub_any, signer)?;
            let c = x509::parse_certificate(&der)
                .map_err(|e| Error::new(format!("created certificate does not parse: {e}")))?;
            let mut d = Dump::default();
            d.h("der", &der);
            d.h("tbs", &c.raw_tbs_certificate);
            Ok(d.0)
        }
        "csr" => {
            let signer = signer_of(&key)?;
            let mut t = x509::CertificateRequest {
                subject: subject_from_spec(f),
                dns_names: f.strs("dns"),
                email_addresses: f.strs("email"),
                ip_addresses: f.list("ip").into_iter().map(x509::Ip).collect(),
                uris: url_list(f, "uri"),
                extra_extensions: ext_list(f, "extra"),
                signature_algorithm: x509::SignatureAlgorithm(f.i("sigalg") as i32),
                ..x509::CertificateRequest::default()
            };
            t.raw_subject = f.b("rawsubject");
            if !f.get("attrs").is_empty() {
                for a in f.get("attrs").split('+') {
                    let (oid, rest) = a.split_once(';').unwrap_or((a, ""));
                    let mut attr = pkix::AttributeTypeAndValueSET {
                        type_: dotted(oid),
                        value: Vec::new(),
                    };
                    for set in rest.split('/') {
                        attr.value.push(set.split('|').map(parse_atv).collect());
                    }
                    t.attributes.push(attr);
                }
            }
            let der = x509::create_certificate_request(&t, signer)?;
            let c = x509::parse_certificate_request(&der)
                .map_err(|e| Error::new(format!("created request does not parse: {e}")))?;
            let mut d = Dump::default();
            d.h("der", &der);
            d.h("tbs", &c.raw_tbs_certificate_request);
            Ok(d.0)
        }
        "crl" => {
            let signer = signer_of(&key)?;
            let issuer = x509::parse_certificate(&f.b("issuer"))?;
            let mut t = x509::RevocationList {
                number: x509::BigInt::from_decimal(f.get("number")),
                this_update: x509::Time::unix(f.i("this"), 0),
                next_update: x509::Time::unix(f.i("next"), 0),
                extra_extensions: ext_list(f, "extra"),
                signature_algorithm: x509::SignatureAlgorithm(f.i("sigalg") as i32),
                ..x509::RevocationList::default()
            };
            if !f.get("entries").is_empty() {
                for e in f.get("entries").split(',') {
                    let p: Vec<&str> = e.split(':').collect();
                    t.revoked_certificate_entries
                        .push(x509::RevocationListEntry {
                            serial_number: x509::BigInt::from_decimal(p[0]),
                            revocation_time: x509::Time::unix(p[1].parse().unwrap_or(0), 0),
                            reason_code: p[2].parse().unwrap_or(0),
                            ..x509::RevocationListEntry::default()
                        });
                }
            }
            if f.get("dep") == "1" {
                for e in std::mem::take(&mut t.revoked_certificate_entries) {
                    t.revoked_certificates.push(pkix::RevokedCertificate {
                        serial_number: e.serial_number.unwrap_or_default(),
                        revocation_time: e.revocation_time,
                        extensions: Vec::new(),
                    });
                }
            }
            let der = x509::create_revocation_list(Some(&t), Some(&issuer), signer)?;
            let rl = x509::parse_revocation_list(&der)
                .map_err(|e| Error::new(format!("created list does not parse: {e}")))?;
            let mut d = Dump::default();
            d.h("der", &der);
            d.h("tbs", &rl.raw_tbs_revocation_list);
            d.w("sigcheck", rl.check_signature_from(&issuer).is_ok());
            Ok(d.0)
        }
        "old_crl" => {
            let signer = signer_of(&key)?;
            let issuer = x509::parse_certificate(&f.b("issuer"))?;
            let mut revoked = Vec::new();
            if !f.get("entries").is_empty() {
                for e in f.get("entries").split(',') {
                    let p: Vec<&str> = e.split(':').collect();
                    revoked.push(pkix::RevokedCertificate {
                        serial_number: x509::BigInt::from_decimal(p[0]).unwrap_or_default(),
                        revocation_time: x509::Time::unix(p[1].parse().unwrap_or(0), 0),
                        extensions: Vec::new(),
                    });
                }
            }
            let der = issuer.create_crl(
                signer,
                &revoked,
                x509::Time::unix(f.i("this"), 0),
                x509::Time::unix(f.i("next"), 0),
            )?;
            let cl = x509::parse_der_crl(&der)
                .map_err(|e| Error::new(format!("created old list does not parse: {e}")))?;
            let mut d = Dump::default();
            d.h("der", &der);
            d.h("tbs", &cl.tbs_cert_list.raw);
            Ok(d.0)
        }
        "key" => Ok(dump_private(&key)),
        other => Err(Error::new(format!("unknown create target {other:?}"))),
    }
}

// ---- verification --------------------------------------------------------

fn verify_op(f: &Fields) -> Result<String, Error> {
    let leaf = x509::parse_certificate(&f.b("leaf"))?;
    let mut inters = x509::CertPool::new();
    let mut all: Vec<Vec<u8>> = vec![leaf.raw.clone()];
    for der in f.list("inter") {
        let c = x509::parse_certificate(&der)?;
        inters.add_cert(&c);
        all.push(c.raw.clone());
    }
    let mut roots = x509::CertPool::new();
    for der in f.list("roots") {
        let c = x509::parse_certificate(&der)?;
        roots.add_cert(&c);
        all.push(c.raw.clone());
    }
    let mut opts = x509::VerifyOptions {
        dns_name: f.text("dns"),
        intermediates: Some(&inters),
        roots: Some(&roots),
        current_time: x509::Time::unix(f.i("time"), 0),
        ..x509::VerifyOptions::default()
    };
    if !f.get("ekus").is_empty() {
        opts.key_usages = f
            .get("ekus")
            .split(',')
            .map(|p| x509::ExtKeyUsage(p.parse().unwrap_or(0)))
            .collect();
    }
    for p in f.get("policies").split(',') {
        if p.is_empty() {
            continue;
        }
        opts.certificate_policies.push(x509::parse_oid(p)?);
    }
    let mut d = Dump::default();
    match leaf.verify(&opts) {
        Err(e) => {
            d.h("err", e.to_string().as_bytes());
            d.w(
                "errtype",
                match e {
                    Error::CertificateInvalid(_) => "x509.CertificateInvalidError",
                    Error::Hostname(_) => "x509.HostnameError",
                    Error::UnknownAuthority(_) => "x509.UnknownAuthorityError",
                    Error::UnhandledCriticalExtension(_) => "x509.UnhandledCriticalExtension",
                    Error::SystemRoots(_) => "x509.SystemRootsError",
                    _ => "other",
                },
            );
        }
        Ok(chains) => {
            d.w("chains", chains.len());
            for (i, chain) in chains.iter().enumerate() {
                let idx: Vec<String> = chain
                    .iter()
                    .map(|c| {
                        all.iter()
                            .position(|raw| *raw == c.raw)
                            .map(|n| n as i64)
                            .unwrap_or(-1)
                            .to_string()
                    })
                    .collect();
                d.w(&format!("chain[{i}]"), idx.join(","));
            }
        }
    }
    Ok(d.0)
}

fn run(f: &Fields) -> Result<String, Error> {
    match f.get("op") {
        "name" => name_op(f),
        "create" => create_op(f),
        "verify" => verify_op(f),
        "parse_cert" => Ok(dump_cert(&x509::parse_certificate(&f.b("der"))?)),
        "parse_certs" => {
            let cs = x509::parse_certificates(&f.b("der"))?;
            let mut d = Dump::default();
            d.w("count", cs.len());
            for (i, c) in cs.iter().enumerate() {
                d.h(&format!("raw[{i}]"), &c.raw);
            }
            Ok(d.0)
        }
        "parse_csr" => Ok(dump_csr(&x509::parse_certificate_request(&f.b("der"))?)),
        "parse_crl" => Ok(dump_rl(&x509::parse_revocation_list(&f.b("der"))?)),
        "parse_der_crl" => Ok(dump_cert_list(&x509::parse_der_crl(&f.b("der"))?)),
        "parse_crl_any" => Ok(dump_cert_list(&x509::parse_crl(&f.b("der"))?)),
        "parse_key" => {
            let der = f.b("der");
            match f.get("kind") {
                "pkcs1" => Ok(dump_private(&x509::PrivateKey::Rsa(
                    x509::parse_pkcs1_private_key(&der)?,
                ))),
                "pkcs8" => Ok(dump_private(&x509::parse_pkcs8_private_key(&der)?)),
                "ec" => Ok(dump_private(&x509::PrivateKey::Ecdsa(
                    x509::parse_ec_private_key(&der)?,
                ))),
                "pkix" => {
                    let pk = x509::parse_pkix_public_key(&der)?;
                    let mut d = Dump::default();
                    dump_public_key(&mut d, "pub", Some(&pk));
                    Ok(d.0)
                }
                "pkcs1pub" => {
                    let pk = x509::PublicKey::Rsa(x509::parse_pkcs1_public_key(&der)?);
                    let mut d = Dump::default();
                    dump_public_key(&mut d, "pub", Some(&pk));
                    Ok(d.0)
                }
                other => Err(Error::new(format!("unknown kind {other}"))),
            }
        }
        "oid" => {
            let text = String::from_utf8_lossy(&f.b("text")).into_owned();
            let o = x509::parse_oid(&text)?;
            let mut d = Dump::default();
            d.w("string", o.to_string());
            d.h("binary", &o.marshal_binary()?);
            d.h("text", &o.marshal_text()?);
            let (a, ok) = asn1_oid(&o);
            d.w("asn1", format!("{a}|{ok}"));
            Ok(d.0)
        }
        "oid_der" => {
            let mut o = x509::Oid::default();
            o.unmarshal_binary(&f.b("der"))?;
            let mut d = Dump::default();
            d.w("string", o.to_string());
            let (a, ok) = asn1_oid(&o);
            d.w("asn1", format!("{a}|{ok}"));
            let ints: Vec<i64> = if ok {
                o.to_string()
                    .split('.')
                    .map(|p| p.parse().unwrap_or(0))
                    .collect()
            } else {
                Vec::new()
            };
            d.w("eq_asn1", o.equal_asn1_oid(&x509::ObjectIdentifier(ints)));
            Ok(d.0)
        }
        "oid_ints" => {
            let ints: Vec<u64> = f
                .get("ints")
                .split(',')
                .map(|p| p.parse().unwrap_or(0))
                .collect();
            let o = x509::oid_from_ints(&ints)?;
            let mut d = Dump::default();
            d.w("string", o.to_string());
            d.h("binary", &o.marshal_binary()?);
            Ok(d.0)
        }
        "pem_certs" => {
            let mut pool = x509::CertPool::new();
            let ok = pool.append_certs_from_pem(&f.b("pem"));
            let mut d = Dump::default();
            d.w("ok", ok);
            let subs = pool.subjects();
            d.w("subjects.len", subs.len());
            for (i, s) in subs.iter().enumerate() {
                d.h(&format!("subject[{i}]"), s);
            }
            Ok(d.0)
        }
        "hostname" => {
            let c = x509::parse_certificate(&f.b("der"))?;
            let mut d = Dump::default();
            for (i, h) in f.list("hosts").iter().enumerate() {
                let host = String::from_utf8_lossy(h).into_owned();
                match c.verify_hostname(&host) {
                    Ok(()) => d.w(&format!("host[{i}]"), "ok"),
                    Err(e) => d.w(
                        &format!("host[{i}]"),
                        format!("err:{}", hex(e.to_string().as_bytes())),
                    ),
                }
            }
            Ok(d.0)
        }
        other => Err(Error::new(format!("unknown op {other:?}"))),
    }
}

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in stdin.lock().lines() {
        let line = line.expect("stdin");
        let mut map = HashMap::new();
        for token in line.split(' ') {
            let (k, v) = token.split_once('=').unwrap_or((token, ""));
            map.insert(k.to_string(), v.to_string());
        }
        let fields = Fields(map);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&fields)));
        match result {
            Ok(Ok(text)) => writeln!(out, "dump={}", hex(text.as_bytes())).expect("stdout"),
            Ok(Err(e)) => writeln!(out, "err={}", hex(e.to_string().as_bytes())).expect("stdout"),
            Err(_) => writeln!(out, "err={}", hex(b"panic")).expect("stdout"),
        }
    }
}
