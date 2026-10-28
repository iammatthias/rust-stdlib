//! Certificate path building and verification, a port of Go's `verify.go`.
//!
//! This is X.509 path logic, not a cryptographic primitive: every signature
//! check goes through [`Certificate::check_signature_from`], which uses the
//! reviewed crates. Go's algorithm is reproduced rather than delegated to a
//! single-path validator because it returns every valid chain, selects
//! candidate parents by key identifier, applies name constraints and policy
//! graphs, and nests extended key usages.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use super::cert::OID_EXTENSION_SUBJECT_ALT_NAME;
use super::constraints::check_chain_constraints;
use super::oid::{oid_from_ints, Oid};
use super::parser::domain_name_valid;
use super::pool::{system_roots_error, system_roots_pool, CertPool};
use super::time::Time;
use super::types::*;
use super::{
    Certificate, CertificateInvalidError, Error, HostnameError, SystemRootsError,
    UnhandledCriticalExtension, UnknownAuthorityError,
};

/// Go's `x509.VerifyOptions`: parameters for [`Certificate::verify`].
#[derive(Clone, Default)]
pub struct VerifyOptions<'a> {
    /// If set, checked against the leaf certificate with
    /// [`Certificate::verify_hostname`].
    pub dns_name: String,

    /// An optional pool of certificates that are not trust anchors, but can be
    /// used to form a chain from the leaf certificate to a root certificate.
    pub intermediates: Option<&'a CertPool>,
    /// The set of trusted root certificates the leaf certificate needs to
    /// chain up to. If `None`, the system roots are used.
    pub roots: Option<&'a CertPool>,

    /// Used to check the validity of all certificates in the chain. If zero,
    /// the current time is used.
    pub current_time: Time,

    /// Which Extended Key Usage values are acceptable. A chain is accepted if
    /// it allows any of the listed values. An empty list means
    /// [`ExtKeyUsage::SERVER_AUTH`]. To accept any key usage, include
    /// [`ExtKeyUsage::ANY`].
    pub key_usages: Vec<ExtKeyUsage>,

    /// The maximum number of comparisons to perform when checking a given
    /// certificate's name constraints. If zero, a sensible default is used.
    /// Go's name constraint checker no longer needs the limit, so it is
    /// accepted and not used.
    pub max_constraint_comparisions: i64,

    /// Which certificate policy OIDs are acceptable during policy validation.
    /// An empty list implies any valid policy is acceptable.
    pub certificate_policies: Vec<Oid>,

    /// Whether policy mapping should be inhibited during path validation.
    /// Unexported in Go; public here so struct update syntax works.
    #[doc(hidden)]
    pub inhibit_policy_mapping: bool,
    /// Whether explicit policies must be present for each certificate.
    /// Unexported in Go.
    #[doc(hidden)]
    pub require_explicit_policy: bool,
    /// Whether the anyPolicy policy should be ignored. Unexported in Go.
    #[doc(hidden)]
    pub inhibit_any_policy: bool,
}

impl fmt::Debug for VerifyOptions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyOptions")
            .field("dns_name", &self.dns_name)
            .field("current_time", &self.current_time)
            .field("key_usages", &self.key_usages)
            .finish_non_exhaustive()
    }
}

const LEAF_CERTIFICATE: i32 = 0;
const INTERMEDIATE_CERTIFICATE: i32 = 1;
const ROOT_CERTIFICATE: i32 = 2;

/// Go's `rfc2821Mailbox`: a "mailbox" broken into the local (before the '@')
/// and domain parts.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) struct Rfc2821Mailbox {
    pub local: String,
    pub domain: String,
}

impl fmt::Display for Rfc2821Mailbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.local, self.domain)
    }
}

/// Go's `parseRFC2821Mailbox`: parses an email address into local and domain
/// parts, based on the ABNF for a "Mailbox" from RFC 2821.
pub(crate) fn parse_rfc2821_mailbox(input: &str) -> Option<Rfc2821Mailbox> {
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let mut inp = bytes;
    let mut local_part: Vec<u8> = Vec::with_capacity(inp.len() / 2);

    if inp[0] == b'"' {
        // Quoted-string = DQUOTE *qcontent DQUOTE
        inp = &inp[1..];
        loop {
            if inp.is_empty() {
                return None;
            }
            let c = inp[0];
            inp = &inp[1..];
            if c == b'"' {
                break;
            } else if c == b'\\' {
                // quoted-pair
                if inp.is_empty() {
                    return None;
                }
                if inp[0] == 11
                    || inp[0] == 12
                    || (1..=9).contains(&inp[0])
                    || (14..=127).contains(&inp[0])
                {
                    local_part.push(inp[0]);
                    inp = &inp[1..];
                } else {
                    return None;
                }
            } else if c == 11
                || c == 12
                // Space is not allowed by the BNF, but RFC 3696 gives an
                // example that assumes it is; we accept it.
                || c == 32
                || c == 33
                || c == 127
                || (1..=8).contains(&c)
                || (14..=31).contains(&c)
                || (35..=91).contains(&c)
                || (93..=126).contains(&c)
            {
                // qtext
                local_part.push(c);
            } else {
                return None;
            }
        }
    } else {
        // Atom ("." Atom)*
        while !inp.is_empty() {
            // atext from RFC 2822, Section 3.2.4
            let mut c = inp[0];
            if c == b'\\' {
                // Examples in RFC 3696 suggest that escaped characters can
                // appear outside of a quoted string; we accept it.
                inp = &inp[1..];
                if inp.is_empty() {
                    return None;
                }
                c = inp[0];
                local_part.push(c);
                inp = &inp[1..];
                continue;
            }
            if c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'/'
                        | b'='
                        | b'?'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'{'
                        | b'|'
                        | b'}'
                        | b'~'
                        | b'.'
                )
            {
                local_part.push(c);
                inp = &inp[1..];
            } else {
                break;
            }
        }

        if local_part.is_empty() {
            return None;
        }

        // From RFC 3696, Section 3: a period may not be used to start or end
        // the local part, nor may two or more consecutive periods appear.
        if local_part[0] == b'.'
            || local_part[local_part.len() - 1] == b'.'
            || local_part.windows(2).any(|w| w == b"..")
        {
            return None;
        }
    }

    if inp.is_empty() || inp[0] != b'@' {
        return None;
    }
    inp = &inp[1..];

    // The RFC specifies a format for domains, but that's known to be violated
    // in practice so anything after an '@' is the domain part.
    let domain = std::str::from_utf8(inp).ok()?;
    if !domain_name_valid(domain, false) {
        return None;
    }

    // Reject domain names containing @.
    if domain.contains('@') {
        return None;
    }

    Some(Rfc2821Mailbox {
        local: String::from_utf8_lossy(&local_part).into_owned(),
        domain: domain.to_string(),
    })
}

type Chain = Vec<Arc<Certificate>>;

impl Certificate {
    /// Go's `isValid`: performs validity checks on `self` given that it is a
    /// candidate to append to the chain in `current_chain`.
    fn is_valid(
        &self,
        self_arc: &Arc<Certificate>,
        cert_type: i32,
        current_chain: &[Arc<Certificate>],
        opts: &VerifyOptions<'_>,
    ) -> Result<(), Error> {
        if !self.unhandled_critical_extensions.is_empty() {
            return Err(UnhandledCriticalExtension.into());
        }

        if let Some(child) = current_chain.last() {
            if child.raw_issuer != self.raw_subject {
                return Err(invalid(self_arc, InvalidReason::NAME_MISMATCH, ""));
            }
        }

        let now = if opts.current_time.is_zero() {
            Time::now()
        } else {
            opts.current_time
        };
        if now.before(&self.not_before) {
            return Err(invalid(
                self_arc,
                InvalidReason::EXPIRED,
                &format!(
                    "current time {} is before {}",
                    now.format_rfc3339(),
                    self.not_before.format_rfc3339()
                ),
            ));
        } else if now.after(&self.not_after) {
            return Err(invalid(
                self_arc,
                InvalidReason::EXPIRED,
                &format!(
                    "current time {} is after {}",
                    now.format_rfc3339(),
                    self.not_after.format_rfc3339()
                ),
            ));
        }

        if (cert_type == INTERMEDIATE_CERTIFICATE || cert_type == ROOT_CERTIFICATE)
            && current_chain.is_empty()
        {
            return Err(Error::new(
                "x509: internal error: empty chain when appending CA cert",
            ));
        }

        // KeyUsage status flags are ignored. (See the notes in Go's source:
        // CAs mark keys with the wrong usages often enough that enforcing them
        // breaks real chains.)

        if cert_type == INTERMEDIATE_CERTIFICATE && (!self.basic_constraints_valid || !self.is_ca) {
            return Err(invalid(self_arc, InvalidReason::NOT_AUTHORIZED_TO_SIGN, ""));
        }

        if self.basic_constraints_valid && self.max_path_len >= 0 {
            let num_intermediates = current_chain.len() as i64 - 1;
            if num_intermediates > self.max_path_len {
                return Err(invalid(self_arc, InvalidReason::TOO_MANY_INTERMEDIATES, ""));
            }
        }

        Ok(())
    }

    /// Go's `Certificate.Verify`: attempts to verify `self` by building one or
    /// more chains from `self` to a certificate in `opts.roots`, using
    /// certificates in `opts.intermediates` if needed. If successful, it
    /// returns one or more chains where the first element of the chain is
    /// `self` and the last element is from `opts.roots`.
    ///
    /// If `opts.roots` is `None`, the system roots are used. If system roots
    /// are unavailable the returned error is a [`SystemRootsError`].
    ///
    /// Name constraints in the intermediates are applied to all names claimed
    /// in the chain, not just `opts.dns_name`. Directory name constraints are
    /// not supported. Extended Key Usage values are enforced nested down a
    /// chain, so an intermediate or root that enumerates EKUs prevents a leaf
    /// from asserting an EKU not in that list. Certificates that use
    /// `SHA1WithRSA` and `ECDSAWithSHA1` signatures are not supported, and
    /// will not be used to build chains.
    ///
    /// WARNING: this function doesn't do any revocation checking.
    pub fn verify(&self, opts: &VerifyOptions<'_>) -> Result<Vec<Vec<Arc<Certificate>>>, Error> {
        let mut opts = opts.clone();
        // Platform-specific verification needs the ASN.1 contents so this
        // makes the behavior consistent across platforms.
        if self.raw.is_empty() {
            return Err(Error::new(
                "x509: missing ASN.1 contents; use ParseCertificate",
            ));
        }
        if let Some(inter) = opts.intermediates {
            for i in 0..inter.len() {
                let (c, _) = inter.cert(i);
                if c.raw.is_empty() {
                    return Err(Error::new(
                        "x509: missing ASN.1 contents; use ParseCertificate",
                    ));
                }
            }
        }

        let system_roots;
        let roots: &CertPool = match opts.roots {
            Some(r) => r,
            None => {
                system_roots = match system_roots_pool() {
                    Some(p) => p,
                    None => {
                        return Err(SystemRootsError {
                            err: system_roots_error(),
                        }
                        .into())
                    }
                };
                &system_roots
            }
        };

        let c = Arc::new(self.clone());

        self.is_valid(&c, LEAF_CERTIFICATE, &[], &opts)?;

        if !opts.dns_name.is_empty() {
            self.verify_hostname_arc(&c, &opts.dns_name)?;
        }

        let mut candidate_chains: Vec<Chain>;
        if roots.contains(self) {
            candidate_chains = vec![vec![c.clone()]];
        } else {
            let (chains, err) = build_chains(&c, std::slice::from_ref(&c), &mut 0, &opts, roots);
            if let Some(err) = err {
                return Err(err);
            }
            candidate_chains = chains;
        }

        let any_key_usage = opts.key_usages.contains(&ExtKeyUsage::ANY);

        if opts.key_usages.is_empty() {
            opts.key_usages = vec![ExtKeyUsage::SERVER_AUTH];
        }

        let mut invalid_policies_chains = 0;
        let mut incompatible_key_usage_chains = 0;
        let mut constraints_hint_err: Option<Error> = None;
        candidate_chains.retain(|chain| {
            if !policies_valid(chain, &opts) {
                invalid_policies_chains += 1;
                return false;
            }
            // If any key usage is acceptable, no need to check the chain for
            // key usages.
            if !any_key_usage && !check_chain_for_key_usage(chain, &opts.key_usages) {
                incompatible_key_usage_chains += 1;
                return false;
            }
            if let Err(err) = check_chain_constraints(chain) {
                if constraints_hint_err.is_none() {
                    constraints_hint_err = Some(
                        CertificateInvalidError {
                            cert: c.clone(),
                            reason: InvalidReason::CA_NOT_AUTHORIZED_FOR_THIS_NAME,
                            detail: err.to_string(),
                        }
                        .into(),
                    );
                }
                return false;
            }
            true
        });

        if candidate_chains.is_empty() {
            if let Some(err) = constraints_hint_err {
                // Preserve previous constraint behavior.
                return Err(err);
            }
            let mut details: Vec<String> = Vec::new();
            if incompatible_key_usage_chains > 0 {
                if invalid_policies_chains == 0 {
                    return Err(invalid(&c, InvalidReason::INCOMPATIBLE_USAGE, ""));
                }
                details.push(format!(
                    "{incompatible_key_usage_chains} candidate chains with incompatible key usage"
                ));
            }
            if invalid_policies_chains > 0 {
                details.push(format!(
                    "{invalid_policies_chains} candidate chains with invalid policies"
                ));
            }
            return Err(invalid(
                &c,
                InvalidReason::NO_VALID_CHAINS,
                &details.join(", "),
            ));
        }

        Ok(candidate_chains)
    }

    /// Go's `Certificate.VerifyHostname`: returns `Ok` if `self` is a valid
    /// certificate for the named host. Otherwise it returns an error
    /// describing the mismatch.
    ///
    /// IP addresses can be optionally enclosed in square brackets and are
    /// checked against the IP SANs. Other names are checked case
    /// insensitively against the DNS names. If the names are valid hostnames,
    /// the certificate fields can have a wildcard as the complete left-most
    /// label (for example `*.example.com`). The legacy Common Name field is
    /// ignored.
    pub fn verify_hostname(&self, h: &str) -> Result<(), Error> {
        self.verify_hostname_arc(&Arc::new(self.clone()), h)
    }

    fn verify_hostname_arc(&self, arc: &Arc<Certificate>, h: &str) -> Result<(), Error> {
        // IP addresses may be written in [ ].
        let mut candidate_ip = h;
        if h.len() >= 3 && h.starts_with('[') && h.ends_with(']') {
            candidate_ip = &h[1..h.len() - 1];
        }
        // netip.ParseAddr is used to allow IPv6 scoped addresses.
        if let Some((bytes, _zone)) = super::net::parse_addr(candidate_ip) {
            // Only match IP addresses against IP SANs. See RFC 6125,
            // Appendix B.2.
            let ip = super::net::Ip(bytes);
            for candidate in &self.ip_addresses {
                if ip.equal(candidate) {
                    return Ok(());
                }
            }
            return Err(HostnameError {
                certificate: arc.clone(),
                host: ip.to_string(),
            }
            .into());
        }

        let candidate_name = to_lower_case_ascii(h);
        let valid_candidate_name = valid_hostname_input(&candidate_name);
        let host_parts = split_hostname(&candidate_name);

        for m in &self.dns_names {
            // Ideally, only valid hostnames according to RFC 6125 would match,
            // like browsers do, but Go is used in a wider array of contexts:
            // always allow perfect matches, and only apply wildcard and
            // trailing dot processing to valid hostnames.
            if valid_candidate_name && valid_hostname_pattern(m) {
                if match_hostnames(m, &host_parts) {
                    return Ok(());
                }
            } else if match_exactly(m, &candidate_name) {
                return Ok(());
            }
        }

        Err(HostnameError {
            certificate: arc.clone(),
            host: h.to_string(),
        }
        .into())
    }
}

fn invalid(cert: &Arc<Certificate>, reason: InvalidReason, detail: &str) -> Error {
    CertificateInvalidError {
        cert: cert.clone(),
        reason,
        detail: detail.to_string(),
    }
    .into()
}

/// Go's `alreadyInChain`: whether a candidate certificate is present in a
/// chain. The subject, public key and SAN, if present, are compared instead of
/// the raw bytes, which prevents loops created by mutual cross-signatures.
fn already_in_chain(candidate: &Certificate, chain: &[Arc<Certificate>]) -> bool {
    let san = |c: &Certificate| {
        c.extensions
            .iter()
            .find(|e| e.id.0 == OID_EXTENSION_SUBJECT_ALT_NAME)
            .map(|e| e.value.clone())
    };
    let candidate_san = san(candidate);

    for cert in chain {
        if candidate.raw_subject != cert.raw_subject {
            continue;
        }
        // The canonical encoding of SPKI is enforced (by only allowing the
        // correct AI parameter encodings when parsing), so the raw bytes can
        // be compared directly.
        if candidate.raw_subject_public_key_info != cert.raw_subject_public_key_info {
            continue;
        }
        let cert_san = san(cert);
        match (&candidate_san, &cert_san) {
            (None, None) => return true,
            (None, _) | (_, None) => return false,
            (Some(a), Some(b)) => {
                if a == b {
                    return true;
                }
            }
        }
    }
    false
}

/// The maximum number of `check_signature_from` calls that building chains
/// will make.
const MAX_CHAIN_SIGNATURE_CHECKS: usize = 100;

const ERR_SIGNATURE_LIMIT: &str =
    "x509: signature check attempts limit reached while verifying certificate chain";

fn is_signature_limit(err: &Option<Error>) -> bool {
    matches!(err, Some(Error::Message(m)) if m == ERR_SIGNATURE_LIMIT)
}

/// Go's `buildChains`. The error is Go's named result, which candidates may
/// set and a later candidate may overwrite.
fn build_chains(
    c: &Arc<Certificate>,
    current_chain: &[Arc<Certificate>],
    sig_checks: &mut usize,
    opts: &VerifyOptions<'_>,
    roots: &CertPool,
) -> (Vec<Chain>, Option<Error>) {
    let mut chains: Vec<Chain> = Vec::new();
    let mut err: Option<Error> = None;
    let mut hint_err: Option<Error> = None;
    let mut hint_cert: Option<Arc<Certificate>> = None;

    let mut parent_groups: Vec<(i32, Vec<super::pool::PotentialParent>)> =
        vec![(ROOT_CERTIFICATE, roots.find_potential_parents(c))];
    parent_groups.push((
        INTERMEDIATE_CERTIFICATE,
        opts.intermediates
            .map(|p| p.find_potential_parents(c))
            .unwrap_or_default(),
    ));

    'candidates: for (cert_type, potentials) in parent_groups {
        for candidate in potentials {
            // Go's considerCandidate closure.
            *sig_checks += 1;
            if *sig_checks > MAX_CHAIN_SIGNATURE_CHECKS {
                err = Some(Error::new(ERR_SIGNATURE_LIMIT));
            } else if candidate.cert.public_key.is_none()
                || already_in_chain(&candidate.cert, current_chain)
            {
                // skip
            } else if let Err(e) = c.check_signature_from(&candidate.cert) {
                if hint_err.is_none() {
                    hint_err = Some(e);
                    hint_cert = Some(candidate.cert.clone());
                }
            } else {
                err = candidate
                    .cert
                    .is_valid(&candidate.cert, cert_type, current_chain, opts)
                    .err();
                if let Some(e) = &err {
                    if hint_err.is_none() {
                        hint_err = Some(e.clone());
                        hint_cert = Some(candidate.cert.clone());
                    }
                } else {
                    let mut constraint_failed = false;
                    if let Some(constraint) = &candidate.constraint {
                        if let Err(e) = constraint(current_chain) {
                            if hint_err.is_none() {
                                hint_err = Some(e);
                                hint_cert = Some(candidate.cert.clone());
                            }
                            constraint_failed = true;
                        }
                    }
                    if !constraint_failed {
                        match cert_type {
                            ROOT_CERTIFICATE => {
                                chains.push(append_to_fresh_chain(current_chain, &candidate.cert));
                            }
                            INTERMEDIATE_CERTIFICATE => {
                                let next = append_to_fresh_chain(current_chain, &candidate.cert);
                                let (child_chains, child_err) =
                                    build_chains(&candidate.cert, &next, sig_checks, opts, roots);
                                err = child_err;
                                chains.extend(child_chains);
                            }
                            _ => {}
                        }
                    }
                }
            }
            if is_signature_limit(&err) {
                break 'candidates;
            }
        }
    }

    if !chains.is_empty() {
        err = None;
    }
    if chains.is_empty() && err.is_none() {
        err = Some(
            UnknownAuthorityError {
                cert: c.clone(),
                hint_err: hint_err.map(Box::new),
                hint_cert,
            }
            .into(),
        );
    }

    (chains, err)
}

fn append_to_fresh_chain(chain: &[Arc<Certificate>], cert: &Arc<Certificate>) -> Chain {
    let mut n = Vec::with_capacity(chain.len() + 1);
    n.extend_from_slice(chain);
    n.push(cert.clone());
    n
}

pub(crate) fn valid_hostname_pattern(host: &str) -> bool {
    valid_hostname(host, true)
}

pub(crate) fn valid_hostname_input(host: &str) -> bool {
    valid_hostname(host, false)
}

/// Go's `validHostname`: whether `host` is a valid hostname that can be
/// matched or matched against according to RFC 6125 2.2, with some leniency to
/// accommodate legacy values.
fn valid_hostname(host: &str, is_pattern: bool) -> bool {
    let mut host = host;
    if !is_pattern {
        host = host.strip_suffix('.').unwrap_or(host);
    }
    if host.is_empty() {
        return false;
    }
    if host == "*" {
        // Bare wildcards are not allowed.
        return false;
    }

    for (i, part) in host.split('.').enumerate() {
        if part.is_empty() {
            // Empty label.
            return false;
        }
        if is_pattern && i == 0 && part == "*" {
            // Only allow full left-most wildcards, as those are the only ones
            // that are matched.
            continue;
        }
        for (j, c) in part.char_indices() {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c.is_ascii_uppercase() {
                continue;
            }
            if c == '-' && j != 0 {
                continue;
            }
            if c == '_' {
                // Not a valid character in hostnames, but commonly found in
                // deployments outside the WebPKI.
                continue;
            }
            return false;
        }
    }

    true
}

fn match_exactly(host_a: &str, host_b: &str) -> bool {
    if host_a.is_empty() || host_a == "." || host_b.is_empty() || host_b == "." {
        return false;
    }
    to_lower_case_ascii(host_a) == to_lower_case_ascii(host_b)
}

/// Go's `matchHostnames`.
pub(crate) fn match_hostnames(pattern: &str, host_parts: &[String]) -> bool {
    let pattern = to_lower_case_ascii(pattern);

    if pattern.is_empty() || host_parts.is_empty() {
        return false;
    }

    let pattern_parts: Vec<&str> = pattern.split('.').collect();

    if pattern_parts.len() != host_parts.len() {
        return false;
    }

    for (i, pattern_part) in pattern_parts.iter().enumerate() {
        if i == 0 && *pattern_part == "*" {
            continue;
        }
        if *pattern_part != host_parts[i] {
            return false;
        }
    }

    true
}

/// Go's `toLowerCaseASCII`: lower-cases only ASCII letters (RFC 6125 6.4.1).
pub(crate) fn to_lower_case_ascii(input: &str) -> String {
    input.to_ascii_lowercase()
}

/// Go's `splitHostname`.
pub(crate) fn split_hostname(host: &str) -> Vec<String> {
    to_lower_case_ascii(host.strip_suffix('.').unwrap_or(host))
        .split('.')
        .map(str::to_string)
        .collect()
}

/// Go's `checkChainForKeyUsage`.
fn check_chain_for_key_usage(chain: &[Arc<Certificate>], key_usages: &[ExtKeyUsage]) -> bool {
    let mut usages: Vec<i32> = key_usages.iter().map(|u| u.0).collect();

    if chain.is_empty() {
        return false;
    }

    let mut usages_remaining = usages.len();

    // Walk down the list and cross out any usages that aren't supported by
    // each certificate. If all usages are crossed out, the chain is
    // unacceptable.
    const INVALID_USAGE: i32 = -1;
    'next_cert: for cert in chain.iter().rev() {
        if cert.ext_key_usage.is_empty() && cert.unknown_ext_key_usage.is_empty() {
            // The certificate doesn't have any extended key usage specified.
            continue;
        }

        if cert.ext_key_usage.contains(&ExtKeyUsage::ANY) {
            // The certificate is explicitly good for any usage.
            continue 'next_cert;
        }

        for slot in usages.iter_mut() {
            let requested = *slot;
            if requested == INVALID_USAGE {
                continue;
            }
            if cert.ext_key_usage.iter().any(|u| u.0 == requested) {
                continue;
            }
            *slot = INVALID_USAGE;
            usages_remaining -= 1;
            if usages_remaining == 0 {
                return false;
            }
        }
    }

    true
}

fn must_new_oid_from_ints(ints: &[u64]) -> Oid {
    oid_from_ints(ints).expect("valid OID")
}

fn any_policy_oid() -> Oid {
    must_new_oid_from_ints(&[2, 5, 29, 32, 0])
}

struct PolicyNode {
    valid_policy: Oid,
    expected_policy_set: Vec<Oid>,
    // Qualifiers are not implemented, so there is no qualifier_set.
    parents: HashSet<usize>,
    children: HashSet<usize>,
}

struct PolicyGraph {
    nodes: Vec<PolicyNode>,
    strata: Vec<HashMap<Vec<u8>, usize>>,
    /// OID -> nodes at `strata[depth-1]` with OID in their expected set.
    parent_index: HashMap<Vec<u8>, Vec<usize>>,
    depth: usize,
}

impl PolicyGraph {
    fn new() -> PolicyGraph {
        let any = any_policy_oid();
        let root = PolicyNode {
            valid_policy: any.clone(),
            expected_policy_set: vec![any.clone()],
            parents: HashSet::new(),
            children: HashSet::new(),
        };
        let mut level = HashMap::new();
        level.insert(any.der().to_vec(), 0);
        PolicyGraph {
            nodes: vec![root],
            strata: vec![level],
            parent_index: HashMap::new(),
            depth: 0,
        }
    }

    fn new_node(&mut self, valid: Oid, parents: &[usize]) -> usize {
        let id = self.nodes.len();
        self.nodes.push(PolicyNode {
            valid_policy: valid.clone(),
            expected_policy_set: vec![valid],
            parents: HashSet::new(),
            children: HashSet::new(),
        });
        for &p in parents {
            self.nodes[p].children.insert(id);
            self.nodes[id].parents.insert(p);
        }
        id
    }

    fn insert(&mut self, n: usize) {
        let key = self.nodes[n].valid_policy.der().to_vec();
        self.strata[self.depth].insert(key, n);
    }

    fn parents_with_expected(&self, expected: &Oid) -> Vec<usize> {
        if self.depth == 0 {
            return Vec::new();
        }
        self.parent_index
            .get(expected.der())
            .cloned()
            .unwrap_or_default()
    }

    fn parent_with_any_policy(&self) -> Option<usize> {
        if self.depth == 0 {
            return None;
        }
        self.strata[self.depth - 1]
            .get(any_policy_oid().der())
            .copied()
    }

    fn parents(&self) -> Vec<usize> {
        if self.depth == 0 {
            return Vec::new();
        }
        self.strata[self.depth - 1].values().copied().collect()
    }

    fn leaf_with_policy(&self, policy: &Oid) -> Option<usize> {
        self.strata[self.depth].get(policy.der()).copied()
    }

    fn delete_leaf(&mut self, policy: &Oid) {
        let Some(n) = self.strata[self.depth].get(policy.der()).copied() else {
            return;
        };
        let parents: Vec<usize> = self.nodes[n].parents.iter().copied().collect();
        for p in parents {
            self.nodes[p].children.remove(&n);
        }
        let children: Vec<usize> = self.nodes[n].children.iter().copied().collect();
        for c in children {
            self.nodes[c].parents.remove(&n);
        }
        self.strata[self.depth].remove(policy.der());
    }

    fn valid_policy_nodes(&self) -> Vec<usize> {
        let any = any_policy_oid();
        let mut valid_nodes = Vec::new();
        for i in (0..=self.depth).rev() {
            for &n in self.strata[i].values() {
                if self.nodes[n].valid_policy.equal(&any) {
                    continue;
                }
                if self.nodes[n].parents.len() == 1 {
                    for &p in &self.nodes[n].parents {
                        if self.nodes[p].valid_policy.equal(&any) {
                            valid_nodes.push(n);
                        }
                    }
                }
            }
        }
        valid_nodes
    }

    fn prune(&mut self) {
        for i in (1..self.depth).rev() {
            let level: Vec<usize> = self.strata[i].values().copied().collect();
            for n in level {
                if self.nodes[n].children.is_empty() {
                    let parents: Vec<usize> = self.nodes[n].parents.iter().copied().collect();
                    for p in parents {
                        self.nodes[p].children.remove(&n);
                    }
                    let key = self.nodes[n].valid_policy.der().to_vec();
                    self.strata[i].remove(&key);
                }
            }
        }
    }

    fn incr_depth(&mut self) {
        self.parent_index = HashMap::new();
        let level: Vec<usize> = self.strata[self.depth].values().copied().collect();
        for n in level {
            for e in &self.nodes[n].expected_policy_set {
                self.parent_index
                    .entry(e.der().to_vec())
                    .or_default()
                    .push(n);
            }
        }
        self.depth += 1;
        self.strata.push(HashMap::new());
    }
}

/// Go's `policiesValid`: the policy verification algorithm of RFC 5280 as
/// updated by RFC 9618.
pub(crate) fn policies_valid(chain: &[Arc<Certificate>], opts: &VerifyOptions<'_>) -> bool {
    if chain.len() == 1 {
        return true;
    }

    // n is the length of the chain minus the trust anchor.
    let n = chain.len() as i64 - 1;

    let any = any_policy_oid();
    let mut pg: Option<PolicyGraph> = Some(PolicyGraph::new());
    let mut inhibit_any_policy: i64 = 0;
    let mut explicit_policy: i64 = 0;
    let mut policy_mapping: i64 = 0;
    if !opts.inhibit_any_policy {
        inhibit_any_policy = n + 1;
    }
    if !opts.require_explicit_policy {
        explicit_policy = n + 1;
    }
    if !opts.inhibit_policy_mapping {
        policy_mapping = n + 1;
    }

    let mut initial_user_policy_set: HashSet<Vec<u8>> = opts
        .certificate_policies
        .iter()
        .map(|p| p.der().to_vec())
        .collect();
    // If the user does not pass any policies, that is equivalent to passing
    // anyPolicyOID.
    if initial_user_policy_set.is_empty() {
        initial_user_policy_set.insert(any.der().to_vec());
    }

    for i in (0..n).rev() {
        let cert = &chain[i as usize];

        let is_self_signed = cert.raw_issuer == cert.raw_subject;

        // 6.1.3 (e)
        if cert.policies.is_empty() {
            pg = None;
        }

        // 6.1.3 (f)
        if explicit_policy == 0 && pg.is_none() {
            return false;
        }

        if let Some(graph) = pg.as_mut() {
            graph.incr_depth();

            let mut policies: HashSet<Vec<u8>> = HashSet::new();

            // 6.1.3 (d) (1)
            for policy in &cert.policies {
                policies.insert(policy.der().to_vec());

                if policy.equal(&any) {
                    continue;
                }

                // 6.1.3 (d) (1) (i)
                let mut parents = graph.parents_with_expected(policy);
                if parents.is_empty() {
                    // 6.1.3 (d) (1) (ii)
                    if let Some(any_parent) = graph.parent_with_any_policy() {
                        parents = vec![any_parent];
                    }
                }
                if !parents.is_empty() {
                    let node = graph.new_node(policy.clone(), &parents);
                    graph.insert(node);
                }
            }

            // 6.1.3 (d) (2). The check "n-i < n" matches "i < n" in the
            // specification, whose chains run from the trust anchor.
            if policies.contains(any.der())
                && (inhibit_any_policy > 0 || (n - i < n && is_self_signed))
            {
                let mut missing: HashMap<Vec<u8>, Vec<usize>> = HashMap::new();
                for p in graph.parents() {
                    for expected in graph.nodes[p].expected_policy_set.clone() {
                        if !graph.strata[graph.depth].contains_key(expected.der()) {
                            missing.entry(expected.der().to_vec()).or_default().push(p);
                        }
                    }
                }

                for (oid_str, parents) in missing {
                    let node = graph.new_node(Oid::from_raw(&oid_str), &parents);
                    graph.insert(node);
                }
            }

            // 6.1.3 (d) (3)
            graph.prune();

            if i != 0 {
                // 6.1.4 (b)
                if !cert.policy_mappings.is_empty() {
                    // Collect a map of issuer -> []subject.
                    let mut mappings: HashMap<Vec<u8>, Vec<Oid>> = HashMap::new();

                    for mapping in &cert.policy_mappings {
                        if policy_mapping > 0 {
                            if mapping.issuer_domain_policy.equal(&any)
                                || mapping.subject_domain_policy.equal(&any)
                            {
                                // Invalid mapping.
                                return false;
                            }
                            mappings
                                .entry(mapping.issuer_domain_policy.der().to_vec())
                                .or_default()
                                .push(mapping.subject_domain_policy.clone());
                        } else {
                            // 6.1.4 (b) (3) (i)
                            graph.delete_leaf(&mapping.issuer_domain_policy);
                        }
                    }

                    // 6.1.4 (b) (3) (ii)
                    graph.prune();

                    for (issuer_str, subject_policies) in mappings {
                        // 6.1.4 (b) (1)
                        if let Some(matching) = graph.leaf_with_policy(&Oid::from_raw(&issuer_str))
                        {
                            graph.nodes[matching].expected_policy_set = subject_policies;
                        } else if let Some(matching) = graph.leaf_with_policy(&any) {
                            // 6.1.4 (b) (2)
                            let node = graph.new_node(Oid::from_raw(&issuer_str), &[matching]);
                            graph.nodes[node].expected_policy_set = subject_policies;
                            graph.insert(node);
                        }
                    }
                }
            }
        }

        if i != 0 {
            // 6.1.4 (h)
            if !is_self_signed {
                if explicit_policy > 0 {
                    explicit_policy -= 1;
                }
                if policy_mapping > 0 {
                    policy_mapping -= 1;
                }
                if inhibit_any_policy > 0 {
                    inhibit_any_policy -= 1;
                }
            }

            // 6.1.4 (i)
            if (cert.require_explicit_policy > 0 || cert.require_explicit_policy_zero)
                && cert.require_explicit_policy < explicit_policy
            {
                explicit_policy = cert.require_explicit_policy;
            }
            if (cert.inhibit_policy_mapping > 0 || cert.inhibit_policy_mapping_zero)
                && cert.inhibit_policy_mapping < policy_mapping
            {
                policy_mapping = cert.inhibit_policy_mapping;
            }
            // 6.1.4 (j)
            if (cert.inhibit_any_policy > 0 || cert.inhibit_any_policy_zero)
                && cert.inhibit_any_policy < inhibit_any_policy
            {
                inhibit_any_policy = cert.inhibit_any_policy;
            }
        }
    }

    // 6.1.5 (a)
    if explicit_policy > 0 {
        explicit_policy -= 1;
    }

    // 6.1.5 (b)
    if chain[0].require_explicit_policy_zero {
        explicit_policy = 0;
    }

    // 6.1.5 (g) (1)
    let mut valid_policy_node_set: Vec<usize> = Vec::new();
    // 6.1.5 (g) (2)
    if let Some(graph) = &pg {
        valid_policy_node_set = graph.valid_policy_nodes();
        // 6.1.5 (g) (3)
        if let Some(current_any) = graph.leaf_with_policy(&any) {
            valid_policy_node_set.push(current_any);
        }
    }

    // 6.1.5 (g) (4)
    let mut authority_constrained_policy_set: HashSet<Vec<u8>> = HashSet::new();
    if let Some(graph) = &pg {
        for &n in &valid_policy_node_set {
            authority_constrained_policy_set.insert(graph.nodes[n].valid_policy.der().to_vec());
        }
    }
    // 6.1.5 (g) (5)
    let mut user_constrained_policy_set = authority_constrained_policy_set.clone();
    // 6.1.5 (g) (6)
    if initial_user_policy_set.len() != 1 || !initial_user_policy_set.contains(any.der()) {
        // 6.1.5 (g) (6) (i)
        user_constrained_policy_set.retain(|p| initial_user_policy_set.contains(p));
        // 6.1.5 (g) (6) (ii)
        if authority_constrained_policy_set.contains(any.der()) {
            for policy in &initial_user_policy_set {
                user_constrained_policy_set.insert(policy.clone());
            }
        }
    }

    if explicit_policy == 0 && user_constrained_policy_set.is_empty() {
        return false;
    }

    true
}
