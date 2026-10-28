//! `tls.Config`, `tls.Certificate` and the callback argument types.
use super::consts::*;
use super::error::Error;
use super::session::{ClientSessionCache, SessionState};
use super::x509::{self, PublicKeyAlgorithm};
use super::ConnectionState;
use rust_stdlib::{context::Context, encoding::pem, net::Conn as NetConn, time::Time};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};
use rustls::sign::SigningKey;
use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};

/// Go's `Certificate.PrivateKey` (a `crypto.PrivateKey` / `crypto.Signer`).
#[derive(Clone)]
pub enum PrivateKey {
    /// A DER PKCS #1 RSA private key.
    Pkcs1(Vec<u8>),
    /// A DER PKCS #8 private key (RSA, ECDSA or Ed25519).
    Pkcs8(Vec<u8>),
    /// A DER SEC 1 EC private key.
    Sec1(Vec<u8>),
    /// A custom signer, Go's arbitrary `crypto.Signer`.
    Signer(Arc<dyn SigningKey>),
}
impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PrivateKey::Pkcs1(_) => "PrivateKey::Pkcs1(..)",
            PrivateKey::Pkcs8(_) => "PrivateKey::Pkcs8(..)",
            PrivateKey::Sec1(_) => "PrivateKey::Sec1(..)",
            PrivateKey::Signer(_) => "PrivateKey::Signer(..)",
        })
    }
}

impl PrivateKey {
    pub(crate) fn signing_key(&self) -> Result<Arc<dyn SigningKey>, Error> {
        let der = match self {
            PrivateKey::Signer(s) => return Ok(s.clone()),
            PrivateKey::Pkcs1(d) => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(d.clone())),
            PrivateKey::Pkcs8(d) => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(d.clone())),
            PrivateKey::Sec1(d) => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(d.clone())),
        };
        rustls::crypto::ring::sign::any_supported_type(&der)
            .map_err(|_| Error::new("tls: failed to parse private key"))
    }
}

/// Go's `tls.Certificate`: a chain of DER certificates and a private key.
#[derive(Clone, Debug, Default)]
pub struct Certificate {
    /// DER certificates, leaf first.
    pub certificate: Vec<Vec<u8>>,
    /// The private key for the leaf (Go's `PrivateKey`).
    pub private_key: Option<PrivateKey>,
    /// Signature schemes the key may be used with; empty means any scheme the
    /// key type supports.
    pub supported_signature_algorithms: Vec<SignatureScheme>,
    /// A stapled OCSP response to send to clients that ask for one.
    pub ocsp_staple: Vec<u8>,
    /// Signed certificate timestamps (accepted for parity; Rustls does not send them).
    pub signed_certificate_timestamps: Vec<Vec<u8>>,
    /// The parsed leaf, filled in by [`x509_key_pair`]; otherwise parsed on demand.
    pub leaf: Option<Arc<x509::Certificate>>,
}

impl Certificate {
    pub(crate) fn leaf_cert(&self) -> Result<Arc<x509::Certificate>, Error> {
        if let Some(l) = &self.leaf {
            return Ok(l.clone());
        }
        let der = self
            .certificate
            .first()
            .ok_or_else(|| Error::new("tls: no certificate"))?;
        x509::parse_certificate(der)
            .map(Arc::new)
            .map_err(Error::X509)
    }

    pub(crate) fn certified_key(&self) -> Result<Arc<rustls::sign::CertifiedKey>, Error> {
        let key = self
            .private_key
            .as_ref()
            .ok_or_else(|| Error::new("tls: certificate private key is not set"))?
            .signing_key()?;
        let chain = self
            .certificate
            .iter()
            .map(|c| rustls::pki_types::CertificateDer::from(c.clone()))
            .collect();
        let mut ck = rustls::sign::CertifiedKey::new(chain, key);
        if !self.ocsp_staple.is_empty() {
            ck.ocsp = Some(self.ocsp_staple.clone());
        }
        Ok(Arc::new(ck))
    }

    /// The signature schemes this certificate can sign with, given its key type.
    pub(crate) fn key_schemes(&self) -> Vec<SignatureScheme> {
        if !self.supported_signature_algorithms.is_empty() {
            return self.supported_signature_algorithms.clone();
        }
        match self.leaf_cert().map(|l| l.public_key_algorithm) {
            Ok(PublicKeyAlgorithm::Rsa) => vec![
                PSS_WITH_SHA256,
                PSS_WITH_SHA384,
                PSS_WITH_SHA512,
                PKCS1_WITH_SHA256,
                PKCS1_WITH_SHA384,
                PKCS1_WITH_SHA512,
            ],
            Ok(PublicKeyAlgorithm::EcdsaP256) => vec![ECDSA_WITH_P256_AND_SHA256],
            Ok(PublicKeyAlgorithm::EcdsaP384) => vec![ECDSA_WITH_P384_AND_SHA384],
            Ok(PublicKeyAlgorithm::EcdsaP521) => vec![ECDSA_WITH_P521_AND_SHA512],
            Ok(PublicKeyAlgorithm::Ed25519) => vec![ED25519],
            _ => Vec::new(),
        }
    }
}

/// Go's `tls.LoadX509KeyPair`: reads PEM files and parses them with [`x509_key_pair`].
pub fn load_x509_key_pair(cert_file: &str, key_file: &str) -> Result<Certificate, Error> {
    let cert = std::fs::read(cert_file).map_err(|e| Error::new(io_text(&e, cert_file)))?;
    let key = std::fs::read(key_file).map_err(|e| Error::new(io_text(&e, key_file)))?;
    x509_key_pair(&cert, &key)
}

fn io_text(e: &std::io::Error, path: &str) -> String {
    if e.kind() == std::io::ErrorKind::NotFound {
        format!("open {path}: no such file or directory")
    } else {
        format!("open {path}: {e}")
    }
}

fn skipped(types: &[String]) -> String {
    format!("[{}]", types.join(" "))
}

/// Which key encoding `der` is, trying PKCS #8, PKCS #1 and SEC 1 as Go does.
fn classify_key(der: &[u8]) -> Option<PrivateKey> {
    // SEQUENCE { INTEGER version, <second> ... }
    let body = der_content(der, 0x30)?;
    let (v_tag, _, rest) = der_next(body)?;
    if v_tag != 0x02 {
        return None;
    }
    let (second, _, _) = der_next(rest)?;
    Some(match second {
        0x30 => PrivateKey::Pkcs8(der.to_vec()),
        0x02 => PrivateKey::Pkcs1(der.to_vec()),
        0x04 => PrivateKey::Sec1(der.to_vec()),
        _ => return None,
    })
}
fn der_next(d: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *d.first()?;
    let l = *d.get(1)?;
    let (len, hdr) = if l < 0x80 {
        (l as usize, 2)
    } else {
        let n = (l & 0x7f) as usize;
        if n == 0 || n > 4 || d.len() < 2 + n {
            return None;
        }
        (
            d[2..2 + n]
                .iter()
                .fold(0usize, |a, b| (a << 8) | *b as usize),
            2 + n,
        )
    };
    let end = hdr.checked_add(len)?;
    (d.len() >= end).then(|| (tag, &d[hdr..end], &d[end..]))
}
fn der_content(d: &[u8], tag: u8) -> Option<&[u8]> {
    let (t, c, _) = der_next(d)?;
    (t == tag).then_some(c)
}

/// Go's `tls.X509KeyPair`: parses a public/private key pair from PEM data.
pub fn x509_key_pair(cert_pem: &[u8], key_pem: &[u8]) -> Result<Certificate, Error> {
    let mut cert = Certificate::default();
    let mut skipped_types: Vec<String> = Vec::new();
    let mut rest = cert_pem;
    while let Some((block, tail)) = pem::decode(rest) {
        rest = tail;
        if block.type_ == "CERTIFICATE" {
            cert.certificate.push(block.bytes);
        } else {
            skipped_types.push(block.type_);
        }
    }
    if cert.certificate.is_empty() {
        if skipped_types.is_empty() {
            return Err(Error::new(
                "tls: failed to find any PEM data in certificate input",
            ));
        }
        if skipped_types.len() == 1 && skipped_types[0].ends_with("PRIVATE KEY") {
            return Err(Error::new("tls: failed to find certificate PEM data in certificate input, but did find a private key; PEM inputs may have been switched"));
        }
        return Err(Error::new(format!("tls: failed to find \"CERTIFICATE\" PEM block in certificate input after skipping PEM blocks of the following types: {}", skipped(&skipped_types))));
    }
    skipped_types.clear();
    let mut rest = key_pem;
    let key_der = loop {
        match pem::decode(rest) {
            None => {
                if skipped_types.is_empty() {
                    return Err(Error::new("tls: failed to find any PEM data in key input"));
                }
                if skipped_types.len() == 1 && skipped_types[0] == "CERTIFICATE" {
                    return Err(Error::new(
                        "tls: found a certificate rather than a key in the PEM for the private key",
                    ));
                }
                return Err(Error::new(format!("tls: failed to find PEM block with type ending in \"PRIVATE KEY\" in key input after skipping PEM blocks of the following types: {}", skipped(&skipped_types))));
            }
            Some((block, tail)) => {
                rest = tail;
                if block.type_ == "PRIVATE KEY" || block.type_.ends_with(" PRIVATE KEY") {
                    break block.bytes;
                }
                skipped_types.push(block.type_);
            }
        }
    };
    let leaf = x509::parse_certificate(&cert.certificate[0]).map_err(Error::X509)?;
    let key =
        classify_key(&key_der).ok_or_else(|| Error::new("tls: failed to parse private key"))?;
    let signing = key.signing_key()?;
    match leaf.public_key_algorithm {
        PublicKeyAlgorithm::Unknown | PublicKeyAlgorithm::EcdsaOther => {
            return Err(Error::new("tls: unknown public key algorithm"))
        }
        alg => {
            let scheme_alg = signing_algorithm(&signing);
            let want = match alg {
                PublicKeyAlgorithm::Rsa => rustls::SignatureAlgorithm::RSA,
                PublicKeyAlgorithm::Ed25519 => rustls::SignatureAlgorithm::ED25519,
                _ => rustls::SignatureAlgorithm::ECDSA,
            };
            if scheme_alg != Some(want) {
                return Err(Error::new(
                    "tls: private key type does not match public key type",
                ));
            }
        }
    }
    if let Some(spki) = signing.public_key() {
        if spki.as_ref() != leaf.raw_subject_public_key_info.as_slice() {
            return Err(Error::new("tls: private key does not match public key"));
        }
    }
    cert.leaf = Some(Arc::new(leaf));
    cert.private_key = Some(key);
    Ok(cert)
}

fn signing_algorithm(key: &Arc<dyn SigningKey>) -> Option<rustls::SignatureAlgorithm> {
    Some(key.algorithm())
}

/// The ClientHello fields Go passes to `GetCertificate` and `GetConfigForClient`.
#[derive(Clone, Default)]
pub struct ClientHelloInfo {
    /// The cipher suites the client supports.
    pub cipher_suites: Vec<u16>,
    /// The SNI name, lowercased with a trailing dot removed; empty if none.
    pub server_name: String,
    /// The named groups (curves) the client supports.
    pub supported_curves: Vec<CurveID>,
    /// The point formats the client supports (always uncompressed, `0`).
    pub supported_points: Vec<u8>,
    /// The signature schemes the client supports.
    pub signature_schemes: Vec<SignatureScheme>,
    /// The ALPN protocols the client offers.
    pub supported_protos: Vec<String>,
    /// The TLS versions the client supports, in the client's order.
    pub supported_versions: Vec<u16>,
    /// The extension type codes in the order the client sent them.
    pub extensions: Vec<u16>,
    /// The underlying connection.
    pub conn: Option<Arc<dyn NetConn>>,
    /// Whether a HelloRetryRequest was sent (always false at callback time).
    pub hello_retry_request: bool,
    /// Go's unexported `ctx`; public so struct update syntax works.
    #[doc(hidden)]
    pub ctx: Option<Context>,
    /// Go's unexported `config`; public so struct update syntax works.
    #[doc(hidden)]
    pub config: Option<Arc<Config>>,
}

impl ClientHelloInfo {
    /// Go's `ClientHelloInfo.Context`: the context of the handshake.
    pub fn context(&self) -> Context {
        self.ctx
            .clone()
            .unwrap_or_else(rust_stdlib::context::Context::background)
    }

    /// Go's `ClientHelloInfo.SupportsCertificate`: nil when `c` can be used
    /// with this ClientHello, otherwise an error saying why not.
    pub fn supports_certificate(&self, c: &Certificate) -> Result<(), Error> {
        let versions = self.supported_versions.clone();
        let tls13 = versions.contains(&VERSION_TLS13);
        let leaf = c.leaf_cert()?;
        // Signature scheme: any scheme both sides share for the key type.
        let schemes: Vec<SignatureScheme> = if self.signature_schemes.is_empty() {
            c.key_schemes()
        } else {
            self.signature_schemes.clone()
        };
        let mine = c.key_schemes();
        let usable = schemes.iter().any(|s| {
            mine.contains(s)
                && !(tls13
                    && versions.iter().all(|v| *v == VERSION_TLS13)
                    && matches!(
                        *s,
                        PKCS1_WITH_SHA256 | PKCS1_WITH_SHA384 | PKCS1_WITH_SHA512
                    ))
        });
        if !usable {
            return Err(Error::new(
                "tls: peer doesn't support any of the certificate's signature algorithms",
            ));
        }
        if !self.server_name.is_empty() {
            if let Err(e) = leaf.verify_hostname(&self.server_name) {
                return Err(Error::new(format!(
                    "tls: certificate is not valid for requested server name: {e}"
                )));
            }
        }
        if let Some(cfg) = &self.config {
            if let Some(max) = versions.iter().max() {
                let (lo, hi) = cfg.version_range();
                if *max < lo || versions.iter().all(|v| *v > hi) {
                    return Err(Error::new("tls: no mutually supported protocol versions"));
                }
            }
        }
        Ok(())
    }
}

/// The CertificateRequest fields Go passes to `GetClientCertificate`.
#[derive(Clone, Default)]
pub struct CertificateRequestInfo {
    /// DER encoded issuer names the server will accept; empty means any.
    pub acceptable_cas: Vec<Vec<u8>>,
    /// The signature schemes the server supports.
    pub signature_schemes: Vec<SignatureScheme>,
    /// The negotiated TLS version (best effort; see the deviation note).
    pub version: u16,
    /// Go's unexported `ctx`; public so struct update syntax works.
    #[doc(hidden)]
    pub ctx: Option<Context>,
}

impl CertificateRequestInfo {
    /// Go's `CertificateRequestInfo.Context`.
    pub fn context(&self) -> Context {
        self.ctx
            .clone()
            .unwrap_or_else(rust_stdlib::context::Context::background)
    }

    /// Go's `CertificateRequestInfo.SupportsCertificate`: nil when the
    /// certificate is acceptable to the server.
    pub fn supports_certificate(&self, c: &Certificate) -> Result<(), Error> {
        let mine = c.key_schemes();
        if !self.signature_schemes.iter().any(|s| mine.contains(s)) {
            return Err(Error::new(
                "tls: certificate used with invalid signature algorithm",
            ));
        }
        if self.acceptable_cas.is_empty() {
            return Ok(());
        }
        for der in &c.certificate {
            if let Ok(parsed) = x509::parse_certificate(der) {
                if self.acceptable_cas.contains(&parsed.raw_issuer) {
                    return Ok(());
                }
            }
        }
        Err(Error::new(
            "tls: certificate is not signed by an acceptable CA",
        ))
    }
}

/// Go's `tls.EncryptedClientHelloKey`: an ECH server key. Encrypted Client
/// Hello is not available with the ring provider (deviation `rustls-policy`).
#[derive(Clone, Debug, Default)]
pub struct EncryptedClientHelloKey {
    /// A serialized ECHConfig.
    pub config: Vec<u8>,
    /// The private key for the ECHConfig.
    pub private_key: Vec<u8>,
    /// Whether the config is sent in retry configs.
    pub send_as_retry: bool,
}

/// A Go `time.Now` replacement.
pub type TimeFn = Arc<dyn Fn() -> Time + Send + Sync>;
/// Go's `GetCertificate`. `Ok(None)` is Go's nil certificate.
pub type GetCertificateFn =
    Arc<dyn Fn(&ClientHelloInfo) -> Result<Option<Arc<Certificate>>, Error> + Send + Sync>;
/// Go's `GetClientCertificate`.
pub type GetClientCertificateFn =
    Arc<dyn Fn(&CertificateRequestInfo) -> Result<Arc<Certificate>, Error> + Send + Sync>;
/// Go's `GetConfigForClient`. `Ok(None)` keeps the original configuration.
pub type GetConfigForClientFn =
    Arc<dyn Fn(&ClientHelloInfo) -> Result<Option<Arc<Config>>, Error> + Send + Sync>;
/// Go's `VerifyPeerCertificate`: the raw DER chain and the verified chains.
pub type VerifyPeerCertificateFn =
    Arc<dyn Fn(&[Vec<u8>], &[Vec<Arc<x509::Certificate>>]) -> Result<(), Error> + Send + Sync>;
/// Go's `VerifyConnection`.
pub type VerifyConnectionFn = Arc<dyn Fn(&ConnectionState) -> Result<(), Error> + Send + Sync>;
/// Go's `WrapSession`.
pub type WrapSessionFn =
    Arc<dyn Fn(&ConnectionState, &SessionState) -> Result<Vec<u8>, Error> + Send + Sync>;
/// Go's `UnwrapSession`.
pub type UnwrapSessionFn =
    Arc<dyn Fn(&[u8], &ConnectionState) -> Result<Option<SessionState>, Error> + Send + Sync>;
/// Go's `EncryptedClientHelloRejectionVerify`.
pub type EchRejectionVerifyFn = Arc<dyn Fn(&ConnectionState) -> Result<(), Error> + Send + Sync>;
/// Go's `GetEncryptedClientHelloKeys`.
pub type GetEchKeysFn =
    Arc<dyn Fn(&ClientHelloInfo) -> Result<Vec<EncryptedClientHelloKey>, Error> + Send + Sync>;

/// State shared by clones of a [`Config`]: session ticket machinery and the
/// client resumption store, mirroring the pointers Go's `Config` shares.
#[derive(Default)]
pub(crate) struct ConfigState {
    pub(crate) ticketer: OnceLock<Arc<dyn rustls::server::ProducesTickets>>,
    pub(crate) client_store: OnceLock<Arc<rustls::client::ClientSessionMemoryCache>>,
    pub(crate) client_parts: Mutex<Option<super::glue::ClientParts>>,
}

/// Go's `tls.Config`: the configuration of a TLS client or server.
///
/// A Config may be reused by several connections. Set fields before first use.
#[derive(Clone, Default)]
pub struct Config {
    /// Returns the current time; the real time is used if `None`.
    pub time: Option<TimeFn>,
    /// Certificates presented to the peer (the first compatible one is used).
    pub certificates: Vec<Certificate>,
    /// Maps server names to certificates; see [`Config::build_name_to_certificate`].
    pub name_to_certificate: HashMap<String, Arc<Certificate>>,
    /// Called with a ClientHello to choose the server certificate.
    pub get_certificate: Option<GetCertificateFn>,
    /// Called by a client when the server requests a certificate.
    pub get_client_certificate: Option<GetClientCertificateFn>,
    /// Called on a server with each ClientHello; may return a different Config.
    pub get_config_for_client: Option<GetConfigForClientFn>,
    /// Called after the normal certificate verification.
    pub verify_peer_certificate: Option<VerifyPeerCertificateFn>,
    /// Called after certificate verification, on both client and server.
    pub verify_connection: Option<VerifyConnectionFn>,
    /// The root CAs a client uses to verify the server; `None` is the system roots.
    pub root_cas: Option<x509::CertPool>,
    /// ALPN protocols in preference order.
    pub next_protos: Vec<String>,
    /// The name verified against the server's certificate and sent as SNI.
    pub server_name: String,
    /// The server's policy for client certificates.
    pub client_auth: ClientAuthType,
    /// The CAs a server uses to verify client certificates.
    pub client_cas: Option<x509::CertPool>,
    /// Disables server certificate and host name verification.
    ///
    /// **This makes TLS insecure.** It exists only because Go exposes the
    /// field. The connection is open to active interception. Use it only
    /// together with `verify_peer_certificate` / `verify_connection` that do
    /// their own verification. Nothing in this crate sets it.
    pub insecure_skip_verify: bool,
    /// TLS 1.0-1.2 cipher suites to offer or accept (IDs); empty means the
    /// defaults. TLS 1.3 suites are not configurable, as in Go.
    pub cipher_suites: Vec<u16>,
    /// Extension beyond Go: restrict the TLS 1.3 suites (IDs); empty means all.
    pub tls13_cipher_suites: Vec<u16>,
    /// Legacy; has no effect, as in Go.
    pub prefer_server_cipher_suites: bool,
    /// Disables session ticket (resumption) support.
    pub session_tickets_disabled: bool,
    /// Deprecated session ticket key. Rustls generates and rotates its own
    /// ticket keys, so a non-zero key is rejected at handshake time.
    pub session_ticket_key: [u8; 32],
    /// The cache of client session states used to resume sessions.
    pub client_session_cache: Option<Arc<dyn ClientSessionCache>>,
    /// Go's `UnwrapSession`. Unsupported; setting it is a handshake error.
    pub unwrap_session: Option<UnwrapSessionFn>,
    /// Go's `WrapSession`. Unsupported; setting it is a handshake error.
    pub wrap_session: Option<WrapSessionFn>,
    /// The minimum TLS version; zero means TLS 1.2. Versions below TLS 1.2
    /// are not implemented by Rustls and are raised to TLS 1.2.
    pub min_version: u16,
    /// The maximum TLS version; zero means TLS 1.3.
    pub max_version: u16,
    /// Key exchange preferences (X25519, P-256, P-384 are available).
    pub curve_preferences: Vec<CurveID>,
    /// Go's record sizing option; Rustls always sends full-size records.
    pub dynamic_record_sizing_disabled: bool,
    /// Renegotiation policy; only [`RENEGOTIATE_NEVER`] is supported.
    pub renegotiation: RenegotiationSupport,
    /// Receives TLS secrets in NSS key log format (`SSLKEYLOGFILE`).
    pub key_log_writer: Option<Arc<Mutex<dyn Write + Send>>>,
    /// An ECHConfigList; ECH is unavailable with the ring provider, so setting
    /// it fails the handshake with an explicit error.
    pub encrypted_client_hello_config_list: Vec<u8>,
    /// Called when ECH is rejected.
    pub encrypted_client_hello_rejection_verify: Option<EchRejectionVerifyFn>,
    /// ECH server keys (unsupported; a handshake error when set).
    pub encrypted_client_hello_keys: Vec<EncryptedClientHelloKey>,
    /// Dynamic ECH server keys (unsupported; a handshake error when set).
    pub get_encrypted_client_hello_keys: Option<GetEchKeysFn>,
    pub(crate) state: Arc<ConfigState>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("server_name", &self.server_name)
            .field("client_auth", &self.client_auth)
            .field("min_version", &self.min_version)
            .field("max_version", &self.max_version)
            .field("insecure_skip_verify", &self.insecure_skip_verify)
            .finish_non_exhaustive()
    }
}

impl Config {
    /// An empty configuration with Go's defaults.
    pub fn new() -> Config {
        Config::default()
    }

    /// Go's `Config.Clone`: a shallow copy sharing callbacks and the session
    /// machinery. Go's Config must not be copied by value; Rust's `Clone`
    /// is that same operation.
    pub fn clone_config(&self) -> Config {
        self.clone()
    }

    /// Go's `Config.BuildNameToCertificate` (deprecated): fills
    /// `name_to_certificate` from each certificate's common name and DNS SANs.
    pub fn build_name_to_certificate(&mut self) {
        self.name_to_certificate = HashMap::new();
        for cert in &self.certificates {
            let Ok(leaf) = cert.leaf_cert() else { continue };
            let c = Arc::new(cert.clone());
            if !leaf.subject_common_name.is_empty() {
                self.name_to_certificate
                    .insert(leaf.subject_common_name.clone(), c.clone());
            }
            for san in &leaf.dns_names {
                self.name_to_certificate.insert(san.clone(), c.clone());
            }
        }
    }

    /// Go's `Config.SetSessionTicketKeys`. Rustls owns the ticket keys and
    /// offers no way to install external ones, so this always fails.
    pub fn set_session_ticket_keys(&self, keys: &[[u8; 32]]) -> Result<(), Error> {
        if keys.is_empty() {
            return Err(Error::new("tls: keys must have at least one key"));
        }
        Err(Error::new(
            "tls: externally supplied session ticket keys are not supported by the rustls adapter",
        ))
    }

    /// Go's `Config.EncryptTicket`. Unsupported: Rustls tickets are opaque.
    pub fn encrypt_ticket(
        &self,
        _cs: &ConnectionState,
        _ss: &SessionState,
    ) -> Result<Vec<u8>, Error> {
        Err(Error::new(
            "tls: EncryptTicket is not supported by the rustls adapter (tickets are opaque)",
        ))
    }

    /// Go's `Config.DecryptTicket`. Unsupported: Rustls tickets are opaque.
    pub fn decrypt_ticket(
        &self,
        _identity: &[u8],
        _cs: &ConnectionState,
    ) -> Result<Option<SessionState>, Error> {
        Err(Error::new(
            "tls: DecryptTicket is not supported by the rustls adapter (tickets are opaque)",
        ))
    }

    /// The effective inclusive version range after defaults.
    pub(crate) fn version_range(&self) -> (u16, u16) {
        let lo = if self.min_version == 0 {
            VERSION_TLS12
        } else {
            self.min_version.max(VERSION_TLS12)
        };
        let hi = if self.max_version == 0 {
            VERSION_TLS13
        } else {
            self.max_version
        };
        (lo, hi)
    }

    pub(crate) fn now(&self) -> Time {
        match &self.time {
            Some(f) => f(),
            None => rust_stdlib::time::now(),
        }
    }

    /// Go's `getCertificate`: the certificate to present to `hello`.
    pub(crate) fn pick_certificate(
        &self,
        hello: &ClientHelloInfo,
    ) -> Result<Arc<Certificate>, Error> {
        if let Some(f) = &self.get_certificate {
            if self.certificates.is_empty() || !hello.server_name.is_empty() {
                if let Some(c) = f(hello)? {
                    return Ok(c);
                }
            }
        }
        if self.certificates.is_empty() {
            return Err(Error::new("tls: no certificates configured"));
        }
        if self.certificates.len() == 1 {
            return Ok(Arc::new(self.certificates[0].clone()));
        }
        if !self.name_to_certificate.is_empty() {
            let name = hello.server_name.to_ascii_lowercase();
            if let Some(c) = self.name_to_certificate.get(&name) {
                return Ok(c.clone());
            }
            let labels: Vec<&str> = name.split('.').collect();
            for i in 0..labels.len() {
                let mut l = labels.clone();
                l[i] = "*";
                if let Some(c) = self.name_to_certificate.get(&l.join(".")) {
                    return Ok(c.clone());
                }
            }
        }
        for cert in &self.certificates {
            if hello.supports_certificate(cert).is_ok() {
                return Ok(Arc::new(cert.clone()));
            }
        }
        Ok(Arc::new(self.certificates[0].clone()))
    }
}
