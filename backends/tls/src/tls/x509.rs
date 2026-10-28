//! The slice of Go's `crypto/x509` that the `crypto/tls` API exposes:
//! `*x509.Certificate` fields read by TLS code, `*x509.CertPool`, and the
//! hostname and unknown-authority errors with Go's messages.
//!
//! Chain building, validity and signature checks belong to Rustls/webpki
//! (docs/adr/0002); this module only reads DER structure (names, validity,
//! public key type) so that Go-shaped values and error texts can be produced.
//! `crates/crypto` holds the complete `crypto/x509`; the TLS adapter does not
//! depend on it because the two reviewed lock graphs resolve `getrandom` and
//! `zeroize` at different versions and the dependency policy forbids duplicate
//! package names (docs/adr/0002).
use rust_stdlib::encoding::pem;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

/// A DER element: tag, content and the bytes after it.
fn tlv(d: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *d.first()?;
    let l = *d.get(1)?;
    let (len, hdr) = if l < 0x80 {
        (l as usize, 2)
    } else {
        let n = (l & 0x7f) as usize;
        if n == 0 || n > 4 || d.len() < 2 + n {
            return None;
        }
        let mut len = 0usize;
        for b in &d[2..2 + n] {
            len = (len << 8) | *b as usize;
        }
        (len, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    if d.len() < end {
        return None;
    }
    Some((tag, &d[hdr..end], &d[end..]))
}

/// The element including its header, so raw names can be compared.
type Whole<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);
fn whole(d: &[u8]) -> Option<Whole<'_>> {
    let (tag, content, rest) = tlv(d)?;
    let used = d.len() - rest.len();
    Some((tag, content, &d[..used], rest))
}

/// Go's `x509.PublicKeyAlgorithm` for the key types TLS can sign with.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum PublicKeyAlgorithm {
    #[default]
    Unknown,
    Rsa,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    EcdsaOther,
    Ed25519,
}

/// The parts of Go's `*x509.Certificate` that `crypto/tls` reads.
#[derive(Clone, Debug, Default)]
pub struct Certificate {
    /// Complete ASN.1 DER content.
    pub raw: Vec<u8>,
    /// DER encoded Subject.
    pub raw_subject: Vec<u8>,
    /// DER encoded Issuer.
    pub raw_issuer: Vec<u8>,
    /// DER encoded SubjectPublicKeyInfo.
    pub raw_subject_public_key_info: Vec<u8>,
    /// The subject's common name.
    pub subject_common_name: String,
    /// SAN dNSName entries.
    pub dns_names: Vec<String>,
    /// SAN iPAddress entries.
    pub ip_addresses: Vec<IpAddr>,
    /// Whether a subjectAltName extension is present.
    pub has_san_extension: bool,
    /// Seconds since the Unix epoch.
    pub not_before: i64,
    /// Seconds since the Unix epoch.
    pub not_after: i64,
    /// The type of the certificate's public key.
    pub public_key_algorithm: PublicKeyAlgorithm,
}

const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];
const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_P521: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn parse_time(tag: u8, c: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(c).ok()?;
    let (year, rest) = match tag {
        0x17 => {
            let yy: i64 = s.get(0..2)?.parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, s.get(2..)?)
        }
        0x18 => (s.get(0..4)?.parse().ok()?, s.get(4..)?),
        _ => return None,
    };
    let n = |i: usize| -> Option<i64> { rest.get(i..i + 2)?.parse().ok() };
    let (mo, d, h, mi) = (n(0)?, n(2)?, n(4)?, n(6)?);
    let sec = if rest.get(8..9) == Some("Z") {
        0
    } else {
        n(8)?
    };
    Some(days_from_civil(year, mo, d) * 86400 + h * 3600 + mi * 60 + sec)
}

/// Go's `x509.ParseCertificate`, reduced to the fields in [`Certificate`].
pub fn parse_certificate(der: &[u8]) -> Result<Certificate, String> {
    let bad = |what: &str| format!("x509: malformed {what}");
    let (tag, cert, rest) = tlv(der).ok_or_else(|| bad("certificate"))?;
    if tag != 0x30 {
        return Err(bad("certificate"));
    }
    if !rest.is_empty() {
        return Err("x509: trailing data".into());
    }
    let (tag, tbs, _) = tlv(cert).ok_or_else(|| bad("certificate"))?;
    if tag != 0x30 {
        return Err(bad("tbs certificate"));
    }
    let mut d = tbs;
    if d.first() == Some(&0xa0) {
        d = tlv(d).ok_or_else(|| bad("version"))?.2;
    }
    d = tlv(d).ok_or_else(|| bad("serial number"))?.2;
    d = tlv(d).ok_or_else(|| bad("signature algorithm"))?.2;
    let (_, _, raw_issuer, d) = whole(d).ok_or_else(|| bad("issuer"))?;
    let (_, validity, d) = tlv(d).ok_or_else(|| bad("validity"))?;
    let (nbt, nb, v) = tlv(validity).ok_or_else(|| bad("validity"))?;
    let (nat, na, _) = tlv(v).ok_or_else(|| bad("validity"))?;
    let (_, subject, raw_subject, d) = whole(d).ok_or_else(|| bad("subject"))?;
    let (_, spki, raw_spki, mut d) = whole(d).ok_or_else(|| bad("subject public key info"))?;
    let mut c = Certificate {
        raw: der.to_vec(),
        raw_subject: raw_subject.to_vec(),
        raw_issuer: raw_issuer.to_vec(),
        raw_subject_public_key_info: raw_spki.to_vec(),
        not_before: parse_time(nbt, nb).ok_or_else(|| bad("validity"))?,
        not_after: parse_time(nat, na).ok_or_else(|| bad("validity"))?,
        ..Certificate::default()
    };
    let mut rdns = subject;
    while let Some((_, set, rest)) = tlv(rdns) {
        let mut atvs = set;
        while let Some((_, atv, r)) = tlv(atvs) {
            if let Some((_, oid, v)) = tlv(atv) {
                if oid == OID_CN {
                    if let Some((_, val, _)) = tlv(v) {
                        c.subject_common_name = String::from_utf8_lossy(val).into_owned();
                    }
                }
            }
            atvs = r;
        }
        rdns = rest;
    }
    if let Some((_, alg, _)) = tlv(spki) {
        if let Some((_, oid, params)) = tlv(alg) {
            c.public_key_algorithm = if oid == OID_RSA {
                PublicKeyAlgorithm::Rsa
            } else if oid == OID_ED25519 {
                PublicKeyAlgorithm::Ed25519
            } else if oid == OID_EC {
                match tlv(params) {
                    Some((_, curve, _)) if curve == OID_P256 => PublicKeyAlgorithm::EcdsaP256,
                    Some((_, curve, _)) if curve == OID_P384 => PublicKeyAlgorithm::EcdsaP384,
                    Some((_, curve, _)) if curve == OID_P521 => PublicKeyAlgorithm::EcdsaP521,
                    _ => PublicKeyAlgorithm::EcdsaOther,
                }
            } else {
                PublicKeyAlgorithm::Unknown
            };
        }
    }
    // Extensions are [3] EXPLICIT; the optional [1]/[2] unique ids come first.
    while let Some((t, content, rest)) = tlv(d) {
        if t == 0xa3 {
            let mut exts = tlv(content).map(|x| x.1).unwrap_or(&[]);
            while let Some((_, ext, rest)) = tlv(exts) {
                if let Some((_, oid, mut e)) = tlv(ext) {
                    if oid == OID_SAN {
                        c.has_san_extension = true;
                        if let Some((0x01, _, r)) = tlv(e) {
                            e = r; // the critical flag
                        }
                        if let Some((_, os, _)) = tlv(e) {
                            let mut g = tlv(os).map(|x| x.1).unwrap_or(&[]);
                            while let Some((gt, gv, gr)) = tlv(g) {
                                match gt {
                                    0x82 => {
                                        c.dns_names.push(String::from_utf8_lossy(gv).into_owned())
                                    }
                                    0x87 if gv.len() == 4 => {
                                        let o: [u8; 4] = gv.try_into().expect("length checked");
                                        c.ip_addresses.push(IpAddr::from(o));
                                    }
                                    0x87 if gv.len() == 16 => {
                                        let o: [u8; 16] = gv.try_into().expect("length checked");
                                        c.ip_addresses.push(IpAddr::from(o));
                                    }
                                    _ => {}
                                }
                                g = gr;
                            }
                        }
                    }
                }
                exts = rest;
            }
        }
        d = rest;
    }
    Ok(c)
}

impl Certificate {
    /// Go's `Certificate.Equal`.
    pub fn equal(&self, other: &Certificate) -> bool {
        self.raw == other.raw
    }

    /// Go's `Certificate.VerifyHostname`: whether the certificate is valid for
    /// `h`. IP literals (optionally in brackets) match IP SANs; names match
    /// DNS SANs case-insensitively with a left-most `*` wildcard label.
    pub fn verify_hostname(&self, h: &str) -> Result<(), HostnameError> {
        let mut candidate_ip = h;
        if h.len() >= 3 && h.starts_with('[') && h.ends_with(']') {
            candidate_ip = &h[1..h.len() - 1];
        }
        let ip_text = candidate_ip.split('%').next().unwrap_or(candidate_ip);
        if let Ok(ip) = ip_text.parse::<IpAddr>() {
            if self.ip_addresses.contains(&ip) {
                return Ok(());
            }
            return Err(HostnameError {
                certificate: Arc::new(self.clone()),
                host: ip.to_string(),
            });
        }
        let candidate = h.to_ascii_lowercase();
        let valid_candidate = valid_hostname(&candidate, false);
        let host_parts = split_hostname(&candidate);
        for m in &self.dns_names {
            if valid_candidate && valid_hostname(m, true) {
                if match_hostnames(m, &host_parts) {
                    return Ok(());
                }
            } else if match_exactly(m, &candidate) {
                return Ok(());
            }
        }
        Err(HostnameError {
            certificate: Arc::new(self.clone()),
            host: h.to_string(),
        })
    }
}

fn split_hostname(host: &str) -> Vec<String> {
    host.strip_suffix('.')
        .unwrap_or(host)
        .to_ascii_lowercase()
        .split('.')
        .map(str::to_string)
        .collect()
}

/// Go's `matchHostnames`.
pub(crate) fn match_hostnames(pattern: &str, host_parts: &[String]) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    if pattern.is_empty() || host_parts.is_empty() {
        return false;
    }
    let parts: Vec<&str> = pattern.split('.').collect();
    if parts.len() != host_parts.len() {
        return false;
    }
    parts
        .iter()
        .enumerate()
        .all(|(i, p)| (i == 0 && *p == "*") || *p == host_parts[i])
}

fn match_exactly(host_a: &str, host_b: &str) -> bool {
    if host_a.is_empty() || host_a == "." || host_b.is_empty() || host_b == "." {
        return false;
    }
    host_a.eq_ignore_ascii_case(host_b)
}

/// Go's `validHostnamePattern` / `validHostnameInput`.
fn valid_hostname(host: &str, is_pattern: bool) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() {
        return false;
    }
    for (i, part) in host.split('.').enumerate() {
        if part.is_empty() {
            return false;
        }
        if is_pattern && i == 0 && part == "*" {
            continue;
        }
        let ok = part
            .bytes()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == b'_' || ch == b'-');
        if !ok {
            return false;
        }
    }
    true
}

/// Go's `x509.HostnameError`.
#[derive(Clone, Debug)]
pub struct HostnameError {
    /// The certificate that was checked.
    pub certificate: Arc<Certificate>,
    /// The requested host.
    pub host: String,
}

impl fmt::Display for HostnameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c = &self.certificate;
        let max_names_included = 100;
        if !c.has_san_extension
            && match_hostnames(&c.subject_common_name, &split_hostname(&self.host))
        {
            return f.write_str(
                "x509: certificate relies on legacy Common Name field, use SANs instead",
            );
        }
        let mut valid = String::new();
        if self.host.parse::<IpAddr>().is_ok() {
            if c.ip_addresses.is_empty() {
                return write!(
                    f,
                    "x509: cannot validate certificate for {} because it doesn't contain any IP SANs",
                    self.host
                );
            }
            if c.ip_addresses.len() >= max_names_included {
                return write!(
                    f,
                    "x509: certificate is valid for {} IP SANs, but none matched {}",
                    c.ip_addresses.len(),
                    self.host
                );
            }
            valid = c
                .ip_addresses
                .iter()
                .map(IpAddr::to_string)
                .collect::<Vec<_>>()
                .join(", ");
        } else {
            if c.dns_names.len() >= max_names_included {
                return write!(
                    f,
                    "x509: certificate is valid for {} names, but none matched {}",
                    c.dns_names.len(),
                    self.host
                );
            }
            valid.push_str(&c.dns_names.join(", "));
        }
        if valid.is_empty() {
            return write!(
                f,
                "x509: certificate is not valid for any names, but wanted to match {}",
                self.host
            );
        }
        write!(
            f,
            "x509: certificate is valid for {valid}, not {}",
            self.host
        )
    }
}
impl std::error::Error for HostnameError {}

/// Go's `x509.UnknownAuthorityError`: "certificate signed by unknown authority".
#[derive(Clone, Debug)]
pub struct UnknownAuthorityError {
    /// The certificate whose issuer is unknown.
    pub cert: Arc<Certificate>,
}
impl fmt::Display for UnknownAuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("x509: certificate signed by unknown authority")
    }
}
impl std::error::Error for UnknownAuthorityError {}

/// Go's `x509.CertPool`: a set of certificates.
#[derive(Clone, Debug, Default)]
pub struct CertPool {
    certs: Vec<Arc<Certificate>>,
}

impl CertPool {
    /// Go's `NewCertPool`.
    pub fn new() -> CertPool {
        CertPool::default()
    }
    /// Go's `CertPool.AddCert`.
    pub fn add_cert(&mut self, cert: Certificate) {
        if !self.certs.iter().any(|c| c.equal(&cert)) {
            self.certs.push(Arc::new(cert));
        }
    }
    /// Go's `CertPool.AppendCertsFromPEM`: true when at least one certificate
    /// was added. Blocks that are not `CERTIFICATE` or that do not parse are
    /// skipped, as in Go.
    pub fn append_certs_from_pem(&mut self, pem_certs: &[u8]) -> bool {
        let mut ok = false;
        let mut rest = pem_certs;
        while let Some((block, tail)) = pem::decode(rest) {
            rest = tail;
            if block.type_ != "CERTIFICATE" || !block.headers.is_empty() {
                continue;
            }
            if let Ok(cert) = parse_certificate(&block.bytes) {
                self.add_cert(cert);
                ok = true;
            }
        }
        ok
    }
    /// Go's `CertPool.Subjects` (deprecated): DER subjects.
    pub fn subjects(&self) -> Vec<Vec<u8>> {
        self.certs.iter().map(|c| c.raw_subject.clone()).collect()
    }
    /// Go's `CertPool.Equal`.
    pub fn equal(&self, other: &CertPool) -> bool {
        self.certs.len() == other.certs.len()
            && self
                .certs
                .iter()
                .all(|c| other.certs.iter().any(|o| o.equal(c)))
    }
    /// Go's `CertPool.Clone`.
    pub fn clone_pool(&self) -> CertPool {
        self.clone()
    }
    /// Number of certificates.
    pub fn len(&self) -> usize {
        self.certs.len()
    }
    /// Whether the pool holds no certificates.
    pub fn is_empty(&self) -> bool {
        self.certs.is_empty()
    }
    /// The certificates, in insertion order.
    pub fn certificates(&self) -> &[Arc<Certificate>] {
        &self.certs
    }
}
