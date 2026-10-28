//! Session state and client session caches (`ticket.go`, `cache.go`).
//!
//! The wire encoding of [`SessionState`] is Go's, so bytes produced by
//! `SessionState.Bytes` in either implementation parse in the other. The
//! cryptographic session data Rustls resumes from is opaque and stays inside
//! Rustls; a [`ClientSessionState`] handed to a cache is a handle to it.
use super::consts::*;
use super::error::Error;
use super::x509;
use rustls::client::{ClientSessionMemoryCache, ClientSessionStore};
use rustls::pki_types::ServerName;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// Go's `tls.SessionState`: a resumable session.
#[derive(Clone, Debug, Default)]
pub struct SessionState {
    /// Ignored by the TLS stack but encoded by [`SessionState::bytes`].
    pub extra: Vec<Vec<u8>>,
    /// Whether the ticket can be used for 0-RTT in a QUIC connection.
    pub early_data: bool,
    #[doc(hidden)]
    pub version: u16,
    #[doc(hidden)]
    pub is_client: bool,
    #[doc(hidden)]
    pub cipher_suite: u16,
    #[doc(hidden)]
    pub created_at: u64,
    #[doc(hidden)]
    pub secret: Vec<u8>,
    #[doc(hidden)]
    pub ext_master_secret: bool,
    #[doc(hidden)]
    pub peer_certificates: Vec<Arc<x509::Certificate>>,
    #[doc(hidden)]
    pub ocsp_response: Vec<u8>,
    #[doc(hidden)]
    pub scts: Vec<Vec<u8>>,
    #[doc(hidden)]
    pub verified_chains: Vec<Vec<Arc<x509::Certificate>>>,
    #[doc(hidden)]
    pub alpn_protocol: Vec<u8>,
    #[doc(hidden)]
    pub use_by: u64,
    #[doc(hidden)]
    pub age_add: u32,
    #[doc(hidden)]
    pub ticket: Vec<u8>,
    #[doc(hidden)]
    pub curve_id: CurveID,
}

fn put_u24(b: &mut Vec<u8>, n: usize) {
    b.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]);
}
fn put_prefixed24(b: &mut Vec<u8>, f: impl FnOnce(&mut Vec<u8>)) {
    let mut inner = Vec::new();
    f(&mut inner);
    put_u24(b, inner.len());
    b.extend_from_slice(&inner);
}
fn put_prefixed16(b: &mut Vec<u8>, f: impl FnOnce(&mut Vec<u8>)) {
    let mut inner = Vec::new();
    f(&mut inner);
    b.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    b.extend_from_slice(&inner);
}

/// A cursor over bytes, with cryptobyte's read operations.
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Option<u64> {
        let hi = self.u32()? as u64;
        Some(hi << 32 | self.u32()? as u64)
    }
    fn prefixed8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    fn prefixed16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    fn prefixed24(&mut self) -> Option<&'a [u8]> {
        let b = self.take(3)?;
        self.take((b[0] as usize) << 16 | (b[1] as usize) << 8 | b[2] as usize)
    }
    fn empty(&self) -> bool {
        self.0.is_empty()
    }
}

const EXT_STATUS_REQUEST: u16 = 5;
const EXT_SCT: u16 = 18;

impl SessionState {
    /// Go's `SessionState.Bytes`: the encoded session, including private fields.
    /// The encoding contains secret values.
    pub fn bytes(&self) -> Result<Vec<u8>, Error> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.version.to_be_bytes());
        b.push(if self.is_client { 2 } else { 1 });
        b.extend_from_slice(&self.cipher_suite.to_be_bytes());
        b.extend_from_slice(&self.created_at.to_be_bytes());
        b.push(self.secret.len() as u8);
        b.extend_from_slice(&self.secret);
        put_prefixed24(&mut b, |b| {
            for extra in &self.extra {
                put_prefixed24(b, |b| b.extend_from_slice(extra));
            }
        });
        b.push(self.ext_master_secret as u8);
        b.push(self.early_data as u8);
        put_prefixed24(&mut b, |b| {
            for (i, cert) in self.peer_certificates.iter().enumerate() {
                put_prefixed24(b, |b| b.extend_from_slice(&cert.raw));
                put_prefixed16(b, |b| {
                    if i > 0 {
                        return;
                    }
                    if !self.ocsp_response.is_empty() {
                        b.extend_from_slice(&EXT_STATUS_REQUEST.to_be_bytes());
                        put_prefixed16(b, |b| {
                            b.push(1);
                            put_prefixed24(b, |b| b.extend_from_slice(&self.ocsp_response));
                        });
                    }
                    if !self.scts.is_empty() {
                        b.extend_from_slice(&EXT_SCT.to_be_bytes());
                        put_prefixed16(b, |b| {
                            put_prefixed16(b, |b| {
                                for sct in &self.scts {
                                    put_prefixed16(b, |b| b.extend_from_slice(sct));
                                }
                            });
                        });
                    }
                });
            }
        });
        let mut chain_err = None;
        put_prefixed24(&mut b, |b| {
            for chain in &self.verified_chains {
                put_prefixed24(b, |b| {
                    if chain.is_empty() {
                        chain_err = Some(Error::new("tls: internal error: empty verified chain"));
                        return;
                    }
                    for cert in &chain[1..] {
                        put_prefixed24(b, |b| b.extend_from_slice(&cert.raw));
                    }
                });
            }
        });
        if let Some(e) = chain_err {
            return Err(e);
        }
        if self.early_data {
            b.push(self.alpn_protocol.len() as u8);
            b.extend_from_slice(&self.alpn_protocol);
        }
        if self.version >= VERSION_TLS13 {
            if self.is_client {
                b.extend_from_slice(&self.use_by.to_be_bytes());
                b.extend_from_slice(&self.age_add.to_be_bytes());
            }
        } else {
            b.extend_from_slice(&self.curve_id.0.to_be_bytes());
        }
        Ok(b)
    }
}

/// Go's `tls.ParseSessionState`: parses a [`SessionState`] encoded by [`SessionState::bytes`].
pub fn parse_session_state(data: &[u8]) -> Result<SessionState, Error> {
    let invalid = || Error::new("tls: invalid session encoding");
    let mut s = Reader(data);
    let mut ss = SessionState::default();
    let version = s.u16().ok_or_else(invalid)?;
    let typ = s.u8().ok_or_else(invalid)?;
    ss.version = version;
    ss.cipher_suite = s.u16().ok_or_else(invalid)?;
    ss.created_at = s.u64().ok_or_else(invalid)?;
    ss.secret = s.prefixed8().ok_or_else(invalid)?.to_vec();
    let mut extra = Reader(s.prefixed24().ok_or_else(invalid)?);
    let ems = s.u8().ok_or_else(invalid)?;
    let early = s.u8().ok_or_else(invalid)?;
    if ss.secret.is_empty() {
        return Err(invalid());
    }
    // unmarshalCertificate
    let mut certs: Vec<Vec<u8>> = Vec::new();
    let mut cert_list = Reader(s.prefixed24().ok_or_else(invalid)?);
    while !cert_list.empty() {
        let cert = cert_list.prefixed24().ok_or_else(invalid)?.to_vec();
        let mut exts = Reader(cert_list.prefixed16().ok_or_else(invalid)?);
        certs.push(cert);
        while !exts.empty() {
            let ext = exts.u16().ok_or_else(invalid)?;
            let mut data = Reader(exts.prefixed16().ok_or_else(invalid)?);
            if certs.len() > 1 {
                continue;
            }
            match ext {
                EXT_STATUS_REQUEST => {
                    if data.u8().ok_or_else(invalid)? != 1 {
                        return Err(invalid());
                    }
                    let ocsp = data.prefixed24().ok_or_else(invalid)?;
                    if ocsp.is_empty() {
                        return Err(invalid());
                    }
                    ss.ocsp_response = ocsp.to_vec();
                }
                EXT_SCT => {
                    let mut list = Reader(data.prefixed16().ok_or_else(invalid)?);
                    if list.empty() {
                        return Err(invalid());
                    }
                    while !list.empty() {
                        let sct = list.prefixed16().ok_or_else(invalid)?;
                        if sct.is_empty() {
                            return Err(invalid());
                        }
                        ss.scts.push(sct.to_vec());
                    }
                }
                _ => continue,
            }
            if !data.empty() {
                return Err(invalid());
            }
        }
    }
    while !extra.empty() {
        ss.extra
            .push(extra.prefixed24().ok_or_else(invalid)?.to_vec());
    }
    ss.is_client = match typ {
        1 => false,
        2 => true,
        _ => return Err(Error::new("tls: unknown session encoding")),
    };
    ss.ext_master_secret = match ems {
        0 => false,
        1 => true,
        _ => return Err(invalid()),
    };
    ss.early_data = match early {
        0 => false,
        1 => true,
        _ => return Err(invalid()),
    };
    for c in certs {
        ss.peer_certificates
            .push(Arc::new(x509::parse_certificate(&c).map_err(Error::X509)?));
    }
    if ss.is_client && ss.peer_certificates.is_empty() {
        return Err(Error::new("tls: no server certificates in client session"));
    }
    let mut chain_list = Reader(s.prefixed24().ok_or_else(invalid)?);
    while !chain_list.empty() {
        let mut cl = Reader(chain_list.prefixed24().ok_or_else(invalid)?);
        if ss.peer_certificates.is_empty() {
            return Err(invalid());
        }
        let mut chain = vec![ss.peer_certificates[0].clone()];
        while !cl.empty() {
            let c = cl.prefixed24().ok_or_else(invalid)?;
            chain.push(Arc::new(x509::parse_certificate(c).map_err(Error::X509)?));
        }
        ss.verified_chains.push(chain);
    }
    if ss.early_data {
        ss.alpn_protocol = s.prefixed8().ok_or_else(invalid)?.to_vec();
    }
    if ss.version >= VERSION_TLS13 {
        if ss.is_client {
            ss.use_by = s.u64().ok_or_else(invalid)?;
            ss.age_add = s.u32().ok_or_else(invalid)?;
        }
    } else {
        ss.curve_id = CurveID(s.u16().ok_or_else(invalid)?);
    }
    Ok(ss)
}

/// Go's `tls.ClientSessionState`: the state needed to resume a previous
/// session. The resumption secrets themselves are held by Rustls.
#[derive(Clone, Debug, Default)]
pub struct ClientSessionState {
    pub(crate) session: Option<SessionState>,
}

impl ClientSessionState {
    /// Go's `ClientSessionState.ResumptionState`: the ticket and session state
    /// for [`ClientSessionState::new`]. `None` for a state without session data
    /// (the state Rustls stores is not serializable).
    pub fn resumption_state(&self) -> Result<Option<(Vec<u8>, SessionState)>, Error> {
        Ok(self.session.as_ref().map(|s| (s.ticket.clone(), s.clone())))
    }
}

impl ClientSessionState {
    /// Go's `tls.NewResumptionState`: a state value that
    /// [`ClientSessionCache::get`] can return to resume a previous session.
    pub fn new(ticket: Vec<u8>, mut state: SessionState) -> Result<Self, Error> {
        state.ticket = ticket;
        Ok(Self {
            session: Some(state),
        })
    }
}

/// Go's `tls.ClientSessionCache`: a cache of [`ClientSessionState`] values.
pub trait ClientSessionCache: Send + Sync {
    /// Returns the session cached for `session_key`, if any.
    fn get(&self, session_key: &str) -> Option<Arc<ClientSessionState>>;
    /// Adds the session for `session_key`; `None` removes the entry.
    fn put(&self, session_key: &str, cs: Option<Arc<ClientSessionState>>);
}

/// Go's `tls.NewLRUClientSessionCache`: an LRU [`ClientSessionCache`].
pub struct LruClientSessionCache {
    capacity: usize,
    /// Front is most recently used.
    entries: Mutex<VecDeque<(String, Arc<ClientSessionState>)>>,
}

impl LruClientSessionCache {
    /// An LRU cache of `capacity` entries (64 if `capacity` is not positive).
    pub fn new(capacity: i32) -> Arc<Self> {
        let capacity = if capacity <= 0 { 64 } else { capacity as usize };
        Arc::new(Self {
            capacity,
            entries: Mutex::new(VecDeque::new()),
        })
    }
}

impl ClientSessionCache for LruClientSessionCache {
    fn get(&self, session_key: &str) -> Option<Arc<ClientSessionState>> {
        let mut e = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        let i = e.iter().position(|(k, _)| k == session_key)?;
        let item = e.remove(i)?;
        let v = item.1.clone();
        e.push_front(item);
        Some(v)
    }
    fn put(&self, session_key: &str, cs: Option<Arc<ClientSessionState>>) {
        let mut e = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        let existing = e.iter().position(|(k, _)| k == session_key);
        let Some(cs) = cs else {
            if let Some(i) = existing {
                e.remove(i);
            }
            return;
        };
        if let Some(i) = existing {
            e.remove(i);
        }
        e.push_front((session_key.to_string(), cs));
        if e.len() > self.capacity {
            e.pop_back();
        }
    }
}

/// Bridges a Go [`ClientSessionCache`] to Rustls. Rustls keeps the resumption
/// secrets in an in-memory store; the Go-shaped cache decides which server
/// names are resumable (so its eviction, `put(key, None)` and sharing rules
/// apply) and observes every session the handshake stores.
pub(crate) struct GatedStore {
    pub(crate) inner: Arc<ClientSessionMemoryCache>,
    pub(crate) cache: Arc<dyn ClientSessionCache>,
}
impl std::fmt::Debug for GatedStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GatedStore")
    }
}
fn key(name: &ServerName<'_>) -> String {
    name.to_str().into_owned()
}
impl GatedStore {
    fn note(&self, name: &ServerName<'_>) {
        self.cache
            .put(&key(name), Some(Arc::new(ClientSessionState::default())));
    }
    fn allowed(&self, name: &ServerName<'_>) -> bool {
        self.cache.get(&key(name)).is_some()
    }
}
impl ClientSessionStore for GatedStore {
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: rustls::NamedGroup) {
        self.inner.set_kx_hint(server_name, group)
    }
    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<rustls::NamedGroup> {
        self.inner.kx_hint(server_name)
    }
    fn set_tls12_session(
        &self,
        server_name: ServerName<'static>,
        value: rustls::client::Tls12ClientSessionValue,
    ) {
        self.note(&server_name);
        self.inner.set_tls12_session(server_name, value)
    }
    fn tls12_session(
        &self,
        server_name: &ServerName<'_>,
    ) -> Option<rustls::client::Tls12ClientSessionValue> {
        if !self.allowed(server_name) {
            return None;
        }
        self.inner.tls12_session(server_name)
    }
    fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
        self.cache.put(&key(server_name), None);
        self.inner.remove_tls12_session(server_name)
    }
    fn insert_tls13_ticket(
        &self,
        server_name: ServerName<'static>,
        value: rustls::client::Tls13ClientSessionValue,
    ) {
        self.note(&server_name);
        self.inner.insert_tls13_ticket(server_name, value)
    }
    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<rustls::client::Tls13ClientSessionValue> {
        if !self.allowed(server_name) {
            return None;
        }
        self.inner.take_tls13_ticket(server_name)
    }
}
