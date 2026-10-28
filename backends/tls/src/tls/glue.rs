//! Maps a Go `tls.Config` onto Rustls: verifiers, certificate resolvers, the
//! crypto provider restricted to the configured suites and curves, and the
//! parsing of the raw ClientHello fields Rustls does not expose.
//!
//! Rustls owns the protocol and webpki owns chain, validity and host name
//! verification (docs/adr/0002). The verifiers here wrap webpki's and add Go's
//! callbacks, `InsecureSkipVerify`, `VerifiedChains` and Go's error texts.
use super::config::{CertificateRequestInfo, ClientHelloInfo, Config, ConfigState};
use super::consts::*;
use super::error::{CertificateVerificationError, Error};
use super::session::GatedStore;
use super::system_roots::system_roots;
use super::x509;
use rust_stdlib::context::Context;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ResolvesClientCert, WebPkiServerVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, OtherError, RootCertStore,
    SignatureScheme as RSignatureScheme, SupportedCipherSuite,
};
use rustls::{ClientConfig, ServerConfig};
use std::fmt;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

pub(crate) fn lock<T: ?Sized>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

thread_local! {
    static CURRENT: std::cell::RefCell<Vec<Arc<Shared>>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Marks the connection whose bytes the current thread is feeding to Rustls.
///
/// Rustls only resumes a client session when the *same* verifier and client
/// certificate resolver objects (by pointer) are configured, so those are
/// shared by every connection of a Config. Their per-connection results go to
/// the connection's [`Shared`], found through this scope: Rustls calls them
/// synchronously from `process_new_packets` and friends on the calling thread.
pub(crate) struct Scope;
impl Scope {
    pub fn enter(shared: &Arc<Shared>) -> Scope {
        CURRENT.with(|c| c.borrow_mut().push(shared.clone()));
        Scope
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        CURRENT.with(|c| {
            c.borrow_mut().pop();
        });
    }
}
fn current() -> Result<Arc<Shared>, rustls::Error> {
    CURRENT
        .with(|c| c.borrow().last().cloned())
        .ok_or_else(|| rustls::Error::General("tls: verification outside a handshake".into()))
}

/// What a handshake learned that Rustls does not hand back afterwards.
#[derive(Default)]
pub(crate) struct Shared {
    /// The context of the handshake (`HandshakeContext`).
    pub ctx: Mutex<Option<Context>>,
    /// DER certificates presented by the peer, leaf first.
    pub peer_certs: Mutex<Vec<Vec<u8>>>,
    pub verified_chains: Mutex<Vec<Vec<Arc<x509::Certificate>>>>,
    /// A stapled OCSP response for the leaf.
    pub ocsp: Mutex<Vec<u8>>,
    /// The exact error to report when the handshake fails because of a
    /// callback or a verification failure.
    pub error: Mutex<Option<Error>>,
    /// DER chain this side presented.
    pub local_cert: Mutex<Vec<Vec<u8>>>,
    /// Best-known protocol version for CertificateRequestInfo.
    pub version_hint: AtomicU16,
    /// Details of the ClientHello (server side).
    pub hello: Mutex<Option<ClientHelloInfo>>,
}

impl Shared {
    pub fn fail(&self, e: Error) -> rustls::Error {
        self.fail_as(e, None)
    }

    /// Records `e` as the error to report and returns the Rustls error that
    /// decides the alert sent to the peer (bad_certificate unless given).
    pub fn fail_as(&self, e: Error, alert: Option<rustls::Error>) -> rustls::Error {
        let text = e.to_string();
        let mut slot = lock(&self.error);
        if slot.is_none() {
            *slot = Some(e);
        }
        alert.unwrap_or_else(|| {
            rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(
                StringError(text),
            ))))
        })
    }
}

#[derive(Debug)]
struct StringError(String);
impl fmt::Display for StringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for StringError {}

// ------------------------------------------------------------------ providers

#[derive(Debug)]
pub(crate) struct TimeSource(pub Config);
impl rustls::time_provider::TimeProvider for TimeSource {
    fn current_time(&self) -> Option<UnixTime> {
        let t = self.0.now().unix();
        u64::try_from(t).ok().map(UnixTime::since_unix_epoch_secs)
    }
}
trait UnixTimeExt {
    fn since_unix_epoch_secs(s: u64) -> UnixTime;
}
impl UnixTimeExt for UnixTime {
    fn since_unix_epoch_secs(s: u64) -> UnixTime {
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(s))
    }
}

pub(crate) struct KeyLogAdapter(pub Arc<Mutex<dyn std::io::Write + Send>>);
impl fmt::Debug for KeyLogAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyLogAdapter")
    }
}
impl rustls::KeyLog for KeyLogAdapter {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let line = format!("{label} {} {}\n", hex(client_random), hex(secret));
        let _ = lock(&self.0).write_all(line.as_bytes());
    }
}

impl Config {
    /// The ring provider limited to the configured suites and key exchanges.
    pub(crate) fn provider(&self) -> Result<Arc<CryptoProvider>, Error> {
        let mut p = rustls::crypto::ring::default_provider();
        p.cipher_suites.retain(|s| {
            let id = u16::from(s.suite());
            match s {
                SupportedCipherSuite::Tls13(_) => {
                    self.tls13_cipher_suites.is_empty() || self.tls13_cipher_suites.contains(&id)
                }
                SupportedCipherSuite::Tls12(_) => {
                    self.cipher_suites.is_empty() || self.cipher_suites.contains(&id)
                }
            }
        });
        if !self.curve_preferences.is_empty() {
            let mut groups = Vec::new();
            for c in &self.curve_preferences {
                if let Some(g) = p
                    .kx_groups
                    .iter()
                    .find(|g| u16::from(g.name()) == c.0)
                    .copied()
                {
                    if !groups
                        .iter()
                        .any(|x: &&dyn rustls::crypto::SupportedKxGroup| x.name() == g.name())
                    {
                        groups.push(g);
                    }
                }
            }
            p.kx_groups = groups;
        }
        Ok(Arc::new(p))
    }

    /// The protocol versions allowed by MinVersion and MaxVersion.
    pub(crate) fn versions(&self) -> Result<Vec<&'static rustls::SupportedProtocolVersion>, Error> {
        let (lo, hi) = self.version_range();
        let mut v = Vec::new();
        if lo <= VERSION_TLS13 && hi >= VERSION_TLS13 {
            v.push(&rustls::version::TLS13);
        }
        if lo <= VERSION_TLS12 && hi >= VERSION_TLS12 {
            v.push(&rustls::version::TLS12);
        }
        if v.is_empty() {
            return Err(Error::new(
                "tls: no supported versions satisfy MinVersion and MaxVersion",
            ));
        }
        Ok(v)
    }

    /// Rejects options this adapter cannot honour instead of ignoring them.
    pub(crate) fn check_supported(&self) -> Result<(), Error> {
        if self.wrap_session.is_some() || self.unwrap_session.is_some() {
            return Err(Error::new("tls: WrapSession and UnwrapSession are not supported by the rustls adapter (tickets are opaque)"));
        }
        if self.session_ticket_key != [0u8; 32] {
            return Err(Error::new("tls: SessionTicketKey is not supported by the rustls adapter (ticket keys are generated by the provider)"));
        }
        if !self.encrypted_client_hello_config_list.is_empty()
            || !self.encrypted_client_hello_keys.is_empty()
            || self.get_encrypted_client_hello_keys.is_some()
            || self.encrypted_client_hello_rejection_verify.is_some()
        {
            return Err(Error::new("tls: Encrypted Client Hello is not supported by the rustls adapter (the ring provider has no HPKE)"));
        }
        if self.renegotiation != RENEGOTIATE_NEVER {
            return Err(Error::new(
                "tls: renegotiation is not supported by the rustls adapter",
            ));
        }
        Ok(())
    }

    pub(crate) fn root_store(pool: &x509::CertPool) -> Result<Arc<RootCertStore>, Error> {
        let mut store = RootCertStore::empty();
        for c in pool.certificates() {
            // Roots webpki cannot use as trust anchors are skipped, as Go
            // skips certificates it cannot use.
            let _ = store.add(CertificateDer::from(c.raw.clone()));
        }
        Ok(Arc::new(store))
    }
}

// ---------------------------------------------------------- client verification

/// The message for a chain through a root on webpki's distrust list.
pub(crate) const DISTRUSTED: &str = "x509: certificate chains to a distrusted root";

/// Go's message for each way webpki can refuse a certificate chain.
fn x509_error_text(
    e: &rustls::Error,
    leaf: &x509::Certificate,
    host: &str,
    now: &rust_stdlib::time::Time,
) -> String {
    let rfc =
        |secs: u64| rust_stdlib::time::unix(secs as i64, 0).format(rust_stdlib::time::RFC3339);
    let _ = now;
    match e {
        rustls::Error::InvalidCertificate(c) => match c {
            CertificateError::ExpiredContext { time, not_after } => format!(
                "x509: certificate has expired or is not yet valid: current time {} is after {}",
                rfc(time.as_secs()),
                rust_stdlib::time::unix(not_after.as_secs() as i64, 0)
                    .utc()
                    .format(rust_stdlib::time::RFC3339)
            ),
            CertificateError::NotValidYetContext { time, not_before } => format!(
                "x509: certificate has expired or is not yet valid: current time {} is before {}",
                rfc(time.as_secs()),
                rust_stdlib::time::unix(not_before.as_secs() as i64, 0)
                    .utc()
                    .format(rust_stdlib::time::RFC3339)
            ),
            CertificateError::Expired => {
                "x509: certificate has expired or is not yet valid".to_string()
            }
            CertificateError::NotValidYet => {
                "x509: certificate has expired or is not yet valid".to_string()
            }
            CertificateError::UnknownIssuer => {
                "x509: certificate signed by unknown authority".to_string()
            }
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                match leaf.verify_hostname(host) {
                    Err(h) => h.to_string(),
                    Ok(()) => format!("x509: certificate is not valid for {host}"),
                }
            }
            CertificateError::InvalidPurpose | CertificateError::InvalidPurposeContext { .. } => {
                "x509: certificate specifies an incompatible key usage".to_string()
            }
            CertificateError::UnhandledCriticalExtension => {
                "x509: unhandled critical extension".to_string()
            }
            CertificateError::BadEncoding => "x509: malformed certificate".to_string(),
            CertificateError::BadSignature => {
                "x509: certificate signed by unknown authority (possibly because of \"x509: invalid signature: parent certificate cannot sign this kind of certificate\")".to_string()
            }
            CertificateError::Revoked => "x509: certificate is revoked".to_string(),
            // webpki's distrust list (deviation `webpki-distrust`): Go has none.
            // rustls passes webpki's `CertDistrusted` on as `Other`, whose text
            // is the variant name.
            CertificateError::Other(e) if e.to_string() == "CertDistrusted" => {
                DISTRUSTED.to_string()
            }
            other => format!("x509: {other:?}"),
        },
        other => format!("x509: {other}"),
    }
}

/// Go's chain: the leaf, the presented certificates that issued it in order,
/// and the root from the pool that closes the path.
fn build_chain(
    peer: &[Arc<x509::Certificate>],
    roots: &x509::CertPool,
) -> Vec<Arc<x509::Certificate>> {
    let mut chain = vec![peer[0].clone()];
    loop {
        let last = chain.last().expect("non-empty").clone();
        if let Some(root) = roots
            .certificates()
            .iter()
            .find(|r| r.raw_subject == last.raw_issuer || r.equal(&last))
        {
            if !root.equal(&last) {
                chain.push(root.clone());
            }
            return chain;
        }
        match peer
            .iter()
            .find(|c| c.raw_subject == last.raw_issuer && !chain.iter().any(|x| x.equal(c)))
        {
            Some(next) => chain.push(next.clone()),
            None => return chain,
        }
    }
}

pub(crate) fn parse_chain(
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
) -> Result<Vec<Arc<x509::Certificate>>, String> {
    std::iter::once(end_entity)
        .chain(intermediates.iter())
        .map(|c| x509::parse_certificate(c.as_ref()).map(Arc::new))
        .collect()
}

/// Go's `UnknownAuthorityError` text, for a pool with no usable trust anchors
/// (webpki cannot be built for one).
const UNKNOWN_AUTHORITY: &str = "x509: certificate signed by unknown authority";

/// Go's `CertificateVerificationError` for a chain that cannot be checked
/// because there is nothing to verify against.
fn verification_failure(peer: Vec<Arc<x509::Certificate>>, text: &str) -> Error {
    Error::CertificateVerification(CertificateVerificationError {
        unverified_certificates: peer,
        err: Arc::new(Error::X509(text.to_string())),
    })
}

/// The roots Go's `Verify` uses: `pool`, or the system roots when it is nil.
/// `Err` is the error Go reports when the system roots cannot be loaded.
pub(crate) fn verify_roots(pool: Option<&x509::CertPool>) -> Result<x509::CertPool, String> {
    match pool {
        Some(pool) => Ok(pool.clone()),
        None => system_roots().map(|roots| (*roots).clone()),
    }
}

/// The webpki server verifier over `roots`. `Err` is the text Go reports when
/// there is nothing to verify against.
fn server_webpki(
    roots: &Result<x509::CertPool, String>,
    provider: &Arc<CryptoProvider>,
) -> Result<Arc<WebPkiServerVerifier>, String> {
    let pool = roots.as_ref().map_err(String::clone)?;
    let store = Config::root_store(pool).map_err(|e| e.to_string())?;
    if store.is_empty() {
        return Err(UNKNOWN_AUTHORITY.into());
    }
    WebPkiServerVerifier::builder_with_provider(store, provider.clone())
        .build()
        .map_err(|_| UNKNOWN_AUTHORITY.into())
}

pub(crate) struct CallbackServerVerifier {
    pub config: Arc<Config>,
    pub algs: WebPkiSupportedAlgorithms,
    pub webpki: Result<Arc<WebPkiServerVerifier>, String>,
    pub roots: x509::CertPool,
}
impl fmt::Debug for CallbackServerVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CallbackServerVerifier")
    }
}
impl ServerCertVerifier for CallbackServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let shared = current()?;
        let raw: Vec<Vec<u8>> = std::iter::once(end_entity.as_ref().to_vec())
            .chain(intermediates.iter().map(|c| c.as_ref().to_vec()))
            .collect();
        *lock(&shared.peer_certs) = raw.clone();
        *lock(&shared.ocsp) = ocsp_response.to_vec();
        let parsed = parse_chain(end_entity, intermediates);
        let mut verified: Vec<Vec<Arc<x509::Certificate>>> = Vec::new();
        if !self.config.insecure_skip_verify {
            let peer = parsed.clone().map_err(|e| shared.fail(Error::X509(e)))?;
            let webpki = match self.webpki.as_ref() {
                Ok(webpki) => webpki,
                Err(text) => return Err(shared.fail(verification_failure(peer, text))),
            };
            match webpki.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            ) {
                Ok(_) => verified.push(build_chain(&peer, &self.roots)),
                Err(e) => {
                    let host = server_name.to_str().into_owned();
                    let text = x509_error_text(&e, &peer[0], &host, &self.config.now());
                    let cause = Error::X509(text);
                    return Err(shared.fail(Error::CertificateVerification(
                        CertificateVerificationError {
                            unverified_certificates: peer,
                            err: Arc::new(cause),
                        },
                    )));
                }
            }
        }
        *lock(&shared.verified_chains) = verified.clone();
        if let Some(cb) = &self.config.verify_peer_certificate {
            cb(&raw, &verified).map_err(|e| shared.fail(e))?;
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }
    fn supported_verify_schemes(&self) -> Vec<RSignatureScheme> {
        self.algs.supported_schemes()
    }
}

pub(crate) struct CallbackClientCertResolver {
    pub config: Arc<Config>,
}
impl fmt::Debug for CallbackClientCertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CallbackClientCertResolver")
    }
}
impl ResolvesClientCert for CallbackClientCertResolver {
    fn resolve(
        &self,
        root_hint_subjects: &[&[u8]],
        sigschemes: &[RSignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        let shared = current().ok()?;
        let info = CertificateRequestInfo {
            acceptable_cas: root_hint_subjects.iter().map(|d| d.to_vec()).collect(),
            signature_schemes: sigschemes
                .iter()
                .map(|s| SignatureScheme(u16::from(*s)))
                .collect(),
            version: shared.version_hint.load(Ordering::Relaxed),
            ctx: lock(&shared.ctx).clone(),
        };
        let cert = if let Some(f) = &self.config.get_client_certificate {
            match f(&info) {
                Ok(c) => Some(c),
                Err(e) => {
                    let _ = shared.fail(e);
                    return None;
                }
            }
        } else {
            self.config
                .certificates
                .iter()
                .find(|c| info.supports_certificate(c).is_ok())
                .map(|c| Arc::new(c.clone()))
        }?;
        if cert.certificate.is_empty() {
            return None;
        }
        match cert.certified_key() {
            Ok(ck) => {
                *lock(&shared.local_cert) = cert.certificate.clone();
                Some(ck)
            }
            Err(e) => {
                let _ = shared.fail(e);
                None
            }
        }
    }
    fn has_certs(&self) -> bool {
        !self.config.certificates.is_empty() || self.config.get_client_certificate.is_some()
    }
}

// ---------------------------------------------------------- server verification

pub(crate) struct CallbackClientVerifier {
    pub config: Arc<Config>,
    pub shared: Arc<Shared>,
    pub algs: WebPkiSupportedAlgorithms,
    pub webpki: Result<Arc<dyn ClientCertVerifier>, String>,
    pub roots: x509::CertPool,
    pub hints: Vec<DistinguishedName>,
}
impl fmt::Debug for CallbackClientVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CallbackClientVerifier")
    }
}
impl ClientCertVerifier for CallbackClientVerifier {
    fn offer_client_auth(&self) -> bool {
        self.config.client_auth != NO_CLIENT_CERT
    }
    fn client_auth_mandatory(&self) -> bool {
        self.config.client_auth.requires_client_cert()
    }
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.hints
    }
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let raw: Vec<Vec<u8>> = std::iter::once(end_entity.as_ref().to_vec())
            .chain(intermediates.iter().map(|c| c.as_ref().to_vec()))
            .collect();
        *lock(&self.shared.peer_certs) = raw.clone();
        let mut verified = Vec::new();
        let must_verify = matches!(
            self.config.client_auth,
            VERIFY_CLIENT_CERT_IF_GIVEN | REQUIRE_AND_VERIFY_CLIENT_CERT
        );
        if must_verify {
            let peer = parse_chain(end_entity, intermediates)
                .map_err(|e| self.shared.fail(Error::X509(e)))?;
            let webpki = match self.webpki.as_ref() {
                Ok(webpki) => webpki,
                Err(text) => {
                    return Err(self.shared.fail(verification_failure(peer, text)));
                }
            };
            if let Err(e) = webpki.verify_client_cert(end_entity, intermediates, now) {
                let text = x509_error_text(&e, &peer[0], "", &self.config.now());
                // Go answers with unknown_ca or certificate_expired for those
                // causes and bad_certificate otherwise.
                let alert = match &e {
                    rustls::Error::InvalidCertificate(
                        CertificateError::UnknownIssuer
                        | CertificateError::Expired
                        | CertificateError::ExpiredContext { .. },
                    ) => Some(e.clone()),
                    _ => None,
                };
                return Err(self.shared.fail_as(
                    Error::CertificateVerification(CertificateVerificationError {
                        unverified_certificates: peer,
                        err: Arc::new(Error::X509(text)),
                    }),
                    alert,
                ));
            }
            verified.push(build_chain(&peer, &self.roots));
        }
        *lock(&self.shared.verified_chains) = verified.clone();
        if let Some(cb) = &self.config.verify_peer_certificate {
            cb(&raw, &verified).map_err(|e| self.shared.fail(e))?;
        }
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }
    fn supported_verify_schemes(&self) -> Vec<RSignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Builds the webpki client verifier over `roots` (`ClientCAs`, or the system
/// roots when it is nil). `Err` is the text Go reports when there is nothing to
/// verify against.
pub(crate) fn webpki_client_verifier(
    roots: &Result<x509::CertPool, String>,
    provider: Arc<CryptoProvider>,
) -> Result<Arc<dyn ClientCertVerifier>, String> {
    let pool = roots.as_ref().map_err(String::clone)?;
    let store = Config::root_store(pool).map_err(|e| e.to_string())?;
    if store.is_empty() {
        return Err(UNKNOWN_AUTHORITY.into());
    }
    WebPkiClientVerifier::builder_with_provider(store, provider)
        .build()
        .map_err(|_| UNKNOWN_AUTHORITY.into())
}

pub(crate) struct CallbackServerCertResolver {
    pub config: Arc<Config>,
    pub shared: Arc<Shared>,
    pub hello: ClientHelloInfo,
}
impl fmt::Debug for CallbackServerCertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CallbackServerCertResolver")
    }
}
impl ResolvesServerCert for CallbackServerCertResolver {
    fn resolve(&self, _hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let cert = match self.config.pick_certificate(&self.hello) {
            Ok(c) => c,
            Err(e) => {
                *lock(&self.shared.error) = Some(e);
                return None;
            }
        };
        match cert.certified_key() {
            Ok(ck) => {
                *lock(&self.shared.local_cert) = cert.certificate.clone();
                Some(ck)
            }
            Err(e) => {
                *lock(&self.shared.error) = Some(e);
                None
            }
        }
    }
}

// ------------------------------------------------------ raw ClientHello parsing

/// The extension codes and supported versions of a ClientHello, read from the
/// raw TLS record bytes (Rustls does not expose them).
pub(crate) struct RawHello {
    pub extensions: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub supported_points: Vec<u8>,
}

pub(crate) fn parse_raw_hello(record: &[u8]) -> Option<RawHello> {
    // record header (5), handshake header (4)
    let hs = record.get(5..)?;
    if *hs.first()? != 1 {
        return None;
    }
    let mut p = hs.get(4..)?;
    let legacy = u16::from_be_bytes([*p.first()?, *p.get(1)?]);
    p = p.get(2 + 32..)?;
    let sid = *p.first()? as usize;
    p = p.get(1 + sid..)?;
    let cs = u16::from_be_bytes([*p.first()?, *p.get(1)?]) as usize;
    p = p.get(2 + cs..)?;
    let comp = *p.first()? as usize;
    p = p.get(1 + comp..)?;
    let ext_len = u16::from_be_bytes([*p.first()?, *p.get(1)?]) as usize;
    let mut e = p.get(2..2 + ext_len)?;
    let mut out = RawHello {
        extensions: Vec::new(),
        supported_versions: Vec::new(),
        supported_points: Vec::new(),
    };
    while e.len() >= 4 {
        let t = u16::from_be_bytes([e[0], e[1]]);
        let l = u16::from_be_bytes([e[2], e[3]]) as usize;
        let body = e.get(4..4 + l)?;
        out.extensions.push(t);
        match t {
            43 => {
                let n = *body.first()? as usize;
                out.supported_versions = body
                    .get(1..1 + n)?
                    .chunks(2)
                    .filter(|c| c.len() == 2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
            }
            11 => {
                let n = *body.first()? as usize;
                out.supported_points = body.get(1..1 + n)?.to_vec();
            }
            _ => {}
        }
        e = &e[4 + l..];
    }
    if out.supported_versions.is_empty() {
        let mut v = Vec::new();
        let mut ver = legacy;
        while ver >= VERSION_TLS10 {
            v.push(ver);
            ver -= 1;
        }
        out.supported_versions = v;
    }
    Some(out)
}

fn net_err_str(e: impl ToString) -> Error {
    Error::new(e.to_string())
}

/// The client verifier and certificate resolver of a Config, created once and
/// reused (see [`Scope`]); rebuilt only if the settings they embody change.
pub(crate) struct ClientParts {
    key: Arc<Config>,
    verifier: Arc<CallbackServerVerifier>,
    resolver: Arc<CallbackClientCertResolver>,
}

fn same_arc<T: ?Sized>(a: &Option<Arc<T>>, b: &Option<Arc<T>>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => {
            std::ptr::eq(Arc::as_ptr(a) as *const (), Arc::as_ptr(b) as *const ())
        }
        _ => false,
    }
}

fn same_client_settings(a: &Config, b: &Config) -> bool {
    a.insecure_skip_verify == b.insecure_skip_verify
        && same_arc(&a.verify_peer_certificate, &b.verify_peer_certificate)
        && same_arc(&a.get_client_certificate, &b.get_client_certificate)
        && same_arc(&a.time, &b.time)
        && match (&a.root_cas, &b.root_cas) {
            (None, None) => true,
            (Some(x), Some(y)) => x.equal(y),
            _ => false,
        }
        && a.certificates.len() == b.certificates.len()
        && a.certificates
            .iter()
            .zip(&b.certificates)
            .all(|(x, y)| x.certificate == y.certificate)
}

pub(crate) fn client_parts(
    cfg: &Arc<Config>,
    provider: &Arc<CryptoProvider>,
) -> Result<(Arc<CallbackServerVerifier>, Arc<CallbackClientCertResolver>), Error> {
    let mut slot = lock(&cfg.state.client_parts);
    if let Some(p) = slot.as_ref() {
        if same_client_settings(&p.key, cfg) {
            return Ok((p.verifier.clone(), p.resolver.clone()));
        }
    }
    let algs = provider.signature_verification_algorithms;
    // A nil RootCAs verifies against the system roots, as Go's Verify does.
    let loaded = verify_roots(cfg.root_cas.as_ref());
    let webpki = server_webpki(&loaded, provider);
    let roots = loaded.unwrap_or_default();
    // The parts live in the Config's shared state, so they must not hold the
    // state themselves: a detached copy of the settings avoids a cycle.
    let mut detached = (**cfg).clone();
    detached.state = Arc::new(ConfigState::default());
    let detached = Arc::new(detached);
    let verifier = Arc::new(CallbackServerVerifier {
        config: detached.clone(),
        algs,
        webpki,
        roots,
    });
    let resolver = Arc::new(CallbackClientCertResolver {
        config: detached.clone(),
    });
    *slot = Some(ClientParts {
        key: detached,
        verifier: verifier.clone(),
        resolver: resolver.clone(),
    });
    Ok((verifier, resolver))
}

pub(crate) fn build_client_config(cfg: &Arc<Config>) -> Result<ClientConfig, Error> {
    cfg.check_supported()?;
    if cfg.server_name.is_empty() && !cfg.insecure_skip_verify {
        return Err(Error::new(
            "tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config",
        ));
    }
    let provider = cfg.provider()?;
    let (verifier, resolver) = client_parts(cfg, &provider)?;
    let time = Arc::new(TimeSource((**cfg).clone()));
    let mut rc = ClientConfig::builder_with_details(provider, time)
        .with_protocol_versions(&cfg.versions()?)
        .map_err(net_err_str)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(resolver);
    rc.alpn_protocols = cfg
        .next_protos
        .iter()
        .map(|p| p.as_bytes().to_vec())
        .collect();
    if let Some(w) = &cfg.key_log_writer {
        rc.key_log = Arc::new(KeyLogAdapter(w.clone()));
    }
    if cfg.session_tickets_disabled {
        rc.resumption = rustls::client::Resumption::disabled();
    } else if let Some(cache) = &cfg.client_session_cache {
        let inner = cfg
            .state
            .client_store
            .get_or_init(|| Arc::new(rustls::client::ClientSessionMemoryCache::new(256)))
            .clone();
        rc.resumption = rustls::client::Resumption::store(Arc::new(GatedStore {
            inner,
            cache: cache.clone(),
        }));
    } else {
        rc.resumption = rustls::client::Resumption::disabled();
    }
    Ok(rc)
}

pub(crate) fn build_server_config(
    cfg: &Arc<Config>,
    shared: &Arc<Shared>,
    hello: ClientHelloInfo,
) -> Result<ServerConfig, Error> {
    cfg.check_supported()?;
    let provider = cfg.provider()?;
    let algs = provider.signature_verification_algorithms;
    let time = Arc::new(TimeSource((**cfg).clone()));
    let builder = ServerConfig::builder_with_details(provider.clone(), time)
        .with_protocol_versions(&cfg.versions()?)
        .map_err(net_err_str)?;
    let builder = if cfg.client_auth == NO_CLIENT_CERT {
        builder.with_no_client_auth()
    } else {
        // Go lists ClientCAs in the CertificateRequest only when it is set;
        // a nil ClientCAs verifies against the system roots, and only when
        // the client certificate is verified.
        let hints = cfg
            .client_cas
            .iter()
            .flat_map(|pool| pool.certificates())
            .map(|c| rustls::DistinguishedName::from(c.raw_subject.clone()))
            .collect();
        let verifies = matches!(
            cfg.client_auth,
            VERIFY_CLIENT_CERT_IF_GIVEN | REQUIRE_AND_VERIFY_CLIENT_CERT
        );
        let loaded = if verifies {
            verify_roots(cfg.client_cas.as_ref())
        } else {
            Ok(cfg.client_cas.clone().unwrap_or_default())
        };
        let verifier = Arc::new(CallbackClientVerifier {
            config: cfg.clone(),
            shared: shared.clone(),
            algs,
            webpki: webpki_client_verifier(&loaded, provider),
            roots: loaded.unwrap_or_default(),
            hints,
        });
        builder.with_client_cert_verifier(verifier)
    };
    let resolver = Arc::new(CallbackServerCertResolver {
        config: cfg.clone(),
        shared: shared.clone(),
        hello,
    });
    let mut sc = builder.with_cert_resolver(resolver);
    sc.alpn_protocols = cfg
        .next_protos
        .iter()
        .map(|p| p.as_bytes().to_vec())
        .collect();
    if let Some(w) = &cfg.key_log_writer {
        sc.key_log = Arc::new(KeyLogAdapter(w.clone()));
    }
    if cfg.session_tickets_disabled {
        sc.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        sc.send_tls13_tickets = 0;
    } else {
        sc.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        let t = match cfg.state.ticketer.get() {
            Some(t) => t.clone(),
            None => {
                let t = rustls::crypto::ring::Ticketer::new().map_err(net_err_str)?;
                let _ = cfg.state.ticketer.set(t.clone());
                cfg.state.ticketer.get().cloned().unwrap_or(t)
            }
        };
        sc.ticketer = t;
    }
    Ok(sc)
}

#[cfg(test)]
mod distrust_tests {
    use super::*;

    #[derive(Debug)]
    struct Distrusted;
    impl std::fmt::Display for Distrusted {
        // webpki's Display for its error is the Debug name of the variant.
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("CertDistrusted")
        }
    }
    impl std::error::Error for Distrusted {}

    #[test]
    fn a_distrusted_root_reads_as_an_x509_error() {
        let e = rustls::Error::InvalidCertificate(CertificateError::Other(rustls::OtherError(
            std::sync::Arc::new(Distrusted),
        )));
        let leaf = x509::Certificate::default();
        let text = x509_error_text(&e, &leaf, "example.com", &rust_stdlib::time::now());
        assert_eq!(text, "x509: certificate chains to a distrusted root");
    }
}
