//! `tls.Conn`, `ConnectionState`, `Client`/`Server`, `Dial` and `Listen`.
//!
//! The record layer and handshake belong to Rustls. This module feeds it
//! bytes from a `net::Conn` (sans-I/O, so a read
//! blocked on the network never holds the lock a concurrent write needs) and
//! translates its results and errors into Go's values.
use super::config::{ClientHelloInfo, Config};
use super::consts::*;
use super::error::{AlertError, Error, RecordHeaderError};
use super::glue::*;
use super::x509;
use rust_stdlib::{
    context::Context,
    net::{AddrRef, Conn as NetConn, NetError},
    time::Time,
};
use rustls::pki_types::ServerName;
use rustls::server::Acceptor;
use rustls::{ClientConnection, Connection, HandshakeKind};
use std::any::Any;
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// The key-exporting closure of a [`ConnectionState`].
pub type ExporterFn =
    Arc<dyn Fn(&str, Option<&[u8]>, usize) -> Result<Vec<u8>, Error> + Send + Sync>;

/// Go's `tls.ConnectionState`: details of a TLS connection.
#[derive(Clone, Default)]
pub struct ConnectionState {
    /// The TLS version used by the connection.
    pub version: u16,
    /// Whether the handshake is complete.
    pub handshake_complete: bool,
    /// Whether the connection resumed a previous session.
    pub did_resume: bool,
    /// The negotiated cipher suite.
    pub cipher_suite: u16,
    /// The key exchange used; zero if unknown.
    pub curve_id: CurveID,
    /// The ALPN protocol negotiated.
    pub negotiated_protocol: String,
    /// Deprecated; always true.
    pub negotiated_protocol_is_mutual: bool,
    /// The SNI name the client sent.
    pub server_name: String,
    /// The certificates sent by the peer, leaf first.
    pub peer_certificates: Vec<Arc<x509::Certificate>>,
    /// Verified chains from `peer_certificates[0]` to a configured root.
    pub verified_chains: Vec<Vec<Arc<x509::Certificate>>>,
    /// SCTs provided by the peer (not exposed by Rustls; always empty).
    pub signed_certificate_timestamps: Vec<Vec<u8>>,
    /// A stapled OCSP response for the leaf, if any.
    pub ocsp_response: Vec<u8>,
    /// The "tls-unique" channel binding (not exposed by Rustls; always empty).
    pub tls_unique: Vec<u8>,
    /// Whether Encrypted Client Hello was accepted (always false).
    pub ech_accepted: bool,
    /// Whether a HelloRetryRequest was sent or received.
    pub hello_retry_request: bool,
    /// The certificate chain presented to the peer, if any.
    pub local_certificate: Vec<Vec<u8>>,
    pub(crate) ekm: Option<ExporterFn>,
}

impl std::fmt::Debug for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionState")
            .field("version", &self.version)
            .field("handshake_complete", &self.handshake_complete)
            .field("did_resume", &self.did_resume)
            .field("cipher_suite", &self.cipher_suite)
            .field("negotiated_protocol", &self.negotiated_protocol)
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

impl ConnectionState {
    /// Go's `ConnectionState.ExportKeyingMaterial` (RFC 5705): `length` bytes
    /// of keying material. `None` for `context` is Go's nil context, which is
    /// not part of the seed (different from an empty context in TLS 1.2).
    pub fn export_keying_material(
        &self,
        label: &str,
        context: Option<&[u8]>,
        length: usize,
    ) -> Result<Vec<u8>, Error> {
        match &self.ekm {
            Some(f) => f(label, context, length),
            None => Err(Error::new(
                "tls: ExportKeyingMaterial is unavailable on a connection that has not completed a handshake",
            )),
        }
    }
}

struct ServerAccept {
    acceptor: Acceptor,
    raw: Vec<u8>,
}

/// Go's `tls.Conn`: a secured connection. It implements [`NetConn`].
pub struct Conn {
    inner: Arc<dyn NetConn>,
    config: Arc<Config>,
    is_client: bool,
    ctx: Mutex<Context>,
    tls: Arc<Mutex<Option<Connection>>>,
    hs_lock: Mutex<()>,
    hs_result: Mutex<Option<Result<(), Error>>>,
    /// Keeps TLS records in the order Rustls produced them when several
    /// threads flush at once.
    write_order: Mutex<()>,
    /// Decrypted bytes not yet read, and whether the stream ended.
    plain: Mutex<(VecDeque<u8>, bool)>,
    shared: Arc<Shared>,
    close_notify_sent: AtomicBool,
    closed: AtomicBool,
    read_err: Mutex<Option<Error>>,
}

/// Go's `tls.Client`: a TLS client over `conn`. The handshake runs on first use.
pub fn client(conn: Box<dyn NetConn>, config: Arc<Config>) -> Conn {
    Conn::new(conn, config, true)
}

/// Go's `tls.Server`: a TLS server over `conn`. The handshake runs on first use.
pub fn server(conn: Box<dyn NetConn>, config: Arc<Config>) -> Conn {
    Conn::new(conn, config, false)
}

/// Go's `hostnameInSNI`: the name sent as SNI (none for IP addresses).
fn hostname_in_sni(name: &str) -> String {
    let mut host = name;
    if host.len() > 1 && host.starts_with('[') && host.ends_with(']') {
        host = &host[1..host.len() - 1];
    }
    if let Some(i) = host.rfind('%') {
        if i > 0 {
            host = &host[..i];
        }
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return String::new();
    }
    name.trim_end_matches('.').to_string()
}

fn net_err(e: impl ToString) -> Error {
    Error::new(e.to_string())
}

fn alert_u8(d: rustls::AlertDescription) -> u8 {
    u8::from(d)
}

impl Conn {
    fn new(conn: Box<dyn NetConn>, config: Arc<Config>, is_client: bool) -> Conn {
        Conn {
            inner: Arc::from(conn),
            config,
            is_client,
            ctx: Mutex::new(Context::background()),
            tls: Arc::new(Mutex::new(None)),
            hs_lock: Mutex::new(()),
            hs_result: Mutex::new(None),
            write_order: Mutex::new(()),
            plain: Mutex::new((VecDeque::new(), false)),
            shared: Arc::new(Shared::default()),
            close_notify_sent: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            read_err: Mutex::new(None),
        }
    }

    // ------------------------------------------------------------- record I/O

    /// Writes any pending TLS records to the peer.
    fn flush_tls(&self) -> Result<(), Error> {
        let _order = lock(&self.write_order);
        loop {
            let mut out = Vec::new();
            {
                let mut guard = lock(&self.tls);
                if let Some(tls) = guard.as_mut() {
                    while tls.wants_write() {
                        tls.write_tls(&mut out).map_err(net_err)?;
                    }
                }
            }
            if out.is_empty() {
                return Ok(());
            }
            self.write_all_inner(&out)?;
        }
    }

    fn write_all_inner(&self, out: &[u8]) -> Result<(), Error> {
        let mut off = 0;
        while off < out.len() {
            off += self.inner.write(&out[off..])?;
        }
        Ok(())
    }

    /// Maps a Rustls failure to the error Go reports.
    fn convert(&self, e: rustls::Error) -> Error {
        if let Some(own) = lock(&self.shared.error).clone() {
            return own;
        }
        use rustls::Error as E;
        match e {
            E::AlertReceived(d) => Error::RemoteAlert(AlertError(alert_u8(d))),
            E::NoCertificatesPresented => Error::new("tls: client didn't provide a certificate"),
            E::PeerIncompatible(p) => {
                use rustls::PeerIncompatible as P;
                match p {
                    P::NoCipherSuitesInCommon => {
                        Error::new("tls: no cipher suite supported by both client and server")
                    }
                    P::Tls12NotOffered
                    | P::Tls12NotOfferedOrEnabled
                    | P::Tls13RequiredForQuic
                    | P::ServerDoesNotSupportTls12Or13 => {
                        Error::new("tls: protocol version not supported")
                    }
                    other => Error::new(format!("tls: handshake failure: {other:?}")),
                }
            }
            E::NoApplicationProtocol => {
                Error::new("tls: client requested unsupported application protocols")
            }
            E::InvalidCertificate(c) => {
                Error::new(format!("tls: failed to verify certificate: {c:?}"))
            }
            other => Error::new(format!("tls: {other}")),
        }
    }

    /// Reads one burst from the peer into Rustls. False at end of input.
    fn pump_read(&self) -> Result<bool, Error> {
        let _scope = Scope::enter(&self.shared);
        let mut buf = [0u8; 16 * 1024];
        let n = self.inner.read(&mut buf)?;
        if n == 0 {
            return Ok(false);
        }
        let mut cursor: &[u8] = &buf[..n];
        let res: Result<(), Error> = (|| {
            let mut guard = lock(&self.tls);
            let tls = guard
                .as_mut()
                .ok_or_else(|| Error::new("tls: handshake has not started"))?;
            while !cursor.is_empty() {
                tls.read_tls(&mut cursor).map_err(net_err)?;
                if let Err(e) = tls.process_new_packets() {
                    drop(guard);
                    let _ = self.flush_tls();
                    return Err(self.convert(e));
                }
                if let Some(v) = tls.protocol_version() {
                    self.shared
                        .version_hint
                        .store(u16::from(v), Ordering::Relaxed);
                }
                let mut plain = lock(&self.plain);
                let mut tmp = [0u8; 16 * 1024];
                loop {
                    match tls.reader().read(&mut tmp) {
                        Ok(0) => {
                            plain.1 = true;
                            break;
                        }
                        Ok(n) => plain.0.extend(&tmp[..n]),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                            plain.1 = true;
                            break;
                        }
                        Err(e) => return Err(net_err(e)),
                    }
                }
            }
            Ok(())
        })();
        let flushed = self.flush_tls();
        res?;
        flushed?;
        Ok(true)
    }

    // -------------------------------------------------------------- handshake

    fn build_client(&self) -> Result<ClientConnection, Error> {
        let rc = build_client_config(&self.config)?;
        let name = ServerName::try_from(self.config.server_name.clone())
            .map_err(|e| Error::new(format!("tls: invalid server name: {e}")))?;
        ClientConnection::new(Arc::new(rc), name).map_err(net_err)
    }

    /// Reads a ClientHello, runs `GetConfigForClient`, and creates the Rustls
    /// server connection.
    fn accept_server(&self) -> Result<rustls::ServerConnection, Error> {
        let mut st = ServerAccept {
            acceptor: Acceptor::default(),
            raw: Vec::new(),
        };
        let mut buf = [0u8; 16 * 1024];
        let accepted = loop {
            let n = self.inner.read(&mut buf)?;
            if n == 0 {
                return Err(Error::Net(NetError::other("EOF")));
            }
            st.raw.extend_from_slice(&buf[..n]);
            if st.raw.len() >= 5 && !self.header_ok(&st.raw) {
                let mut hdr = [0u8; 5];
                hdr.copy_from_slice(&st.raw[..5]);
                return Err(Error::RecordHeader(RecordHeaderError {
                    msg: "first record does not look like a TLS handshake".into(),
                    record_header: hdr,
                    conn: Some(self.inner.clone()),
                }));
            }
            let mut cursor: &[u8] = &buf[..n];
            while !cursor.is_empty() {
                st.acceptor.read_tls(&mut cursor).map_err(net_err)?;
            }
            match st.acceptor.accept() {
                Ok(None) => continue,
                Ok(Some(a)) => break a,
                Err((e, mut alert)) => {
                    let mut out = Vec::new();
                    let _ = alert.write_all(&mut out);
                    let _ = self.write_all_inner(&out);
                    return Err(Error::new(format!("tls: {e}")));
                }
            }
        };
        let hello = {
            let ch = accepted.client_hello();
            let raw = parse_raw_hello(&st.raw);
            let (extensions, supported_versions, points) = match raw {
                Some(r) => (r.extensions, r.supported_versions, r.supported_points),
                None => (Vec::new(), Vec::new(), Vec::new()),
            };
            ClientHelloInfo {
                cipher_suites: ch.cipher_suites().iter().map(|c| u16::from(*c)).collect(),
                server_name: ch.server_name().unwrap_or("").to_string(),
                supported_curves: ch
                    .named_groups()
                    .map(|g| g.iter().map(|g| CurveID(u16::from(*g))).collect())
                    .unwrap_or_default(),
                supported_points: if points.is_empty() { vec![0] } else { points },
                signature_schemes: ch
                    .signature_schemes()
                    .iter()
                    .map(|s| SignatureScheme(u16::from(*s)))
                    .collect(),
                supported_protos: ch
                    .alpn()
                    .map(|a| a.map(|p| String::from_utf8_lossy(p).into_owned()).collect())
                    .unwrap_or_default(),
                supported_versions,
                extensions,
                conn: Some(self.inner.clone()),
                hello_retry_request: false,
                ctx: Some(lock(&self.ctx).clone()),
                config: Some(self.config.clone()),
            }
        };
        let mut effective = self.config.clone();
        if let Some(f) = &self.config.get_config_for_client {
            if let Some(c) = f(&hello)? {
                effective = c;
            }
        }
        let mut hello = hello;
        hello.config = Some(effective.clone());
        *lock(&self.shared.hello) = Some(hello.clone());
        let sc = Arc::new(build_server_config(&effective, &self.shared, hello)?);
        match accepted.into_connection(sc) {
            Ok(c) => Ok(c),
            Err((e, mut alert)) => {
                let mut out = Vec::new();
                let _ = alert.write_all(&mut out);
                let _ = self.write_all_inner(&out);
                Err(self.convert(e))
            }
        }
    }

    fn header_ok(&self, raw: &[u8]) -> bool {
        let typ = raw[0];
        let vers = u16::from_be_bytes([raw[1], raw[2]]);
        (typ == 21 || typ == 22) && vers < 0x1000
    }

    fn run_handshake(&self) -> Result<(), Error> {
        let _scope = Scope::enter(&self.shared);
        {
            let guard = lock(&self.tls);
            if guard.is_none() {
                drop(guard);
                let conn = if self.is_client {
                    Connection::Client(self.build_client()?)
                } else {
                    Connection::Server(self.accept_server()?)
                };
                *lock(&self.tls) = Some(conn);
            }
        }
        loop {
            self.flush_tls()?;
            let handshaking = lock(&self.tls)
                .as_ref()
                .map(|t| t.is_handshaking())
                .unwrap_or(true);
            if !handshaking {
                break;
            }
            if !self.pump_read()? {
                return Err(Error::Net(NetError::other("EOF")));
            }
        }
        if let Some(e) = lock(&self.shared.error).clone() {
            return Err(e);
        }
        if let Some(cb) = &self.config.verify_connection {
            let state = self.connection_state();
            cb(&state)?;
        }
        Ok(())
    }

    fn ensure_handshake(&self) -> Result<(), Error> {
        let _g = lock(&self.hs_lock);
        if let Some(r) = lock(&self.hs_result).clone() {
            return r;
        }
        let r = self.run_handshake();
        *lock(&self.hs_result) = Some(r.clone());
        r
    }

    // ------------------------------------------------------------- public API

    /// Go's `Conn.Handshake`: runs the TLS handshake if it has not run yet.
    pub fn handshake(&self) -> Result<(), Error> {
        self.ensure_handshake()
    }

    /// Go's `Conn.HandshakeContext`: like [`Conn::handshake`], but cancelling
    /// `ctx` aborts a handshake in progress and closes the connection.
    pub fn handshake_context(&self, ctx: &Context) -> Result<(), Error> {
        *lock(&self.ctx) = ctx.clone();
        *lock(&self.shared.ctx) = Some(ctx.clone());
        if let Err(e) = ctx.check() {
            return Err(Error::new(format!("{e}")));
        }
        let done = Arc::new(AtomicBool::new(false));
        let cancelled = Arc::new(AtomicBool::new(false));
        let watcher = (!ctx.done().is_never()).then(|| {
            let (ctx, done, cancelled, inner) = (
                ctx.clone(),
                done.clone(),
                cancelled.clone(),
                self.inner.clone(),
            );
            std::thread::spawn(move || {
                while !done.load(Ordering::SeqCst) {
                    if ctx
                        .done()
                        .wait_timeout(rust_stdlib::time::Duration::from_millis(20))
                    {
                        cancelled.store(true, Ordering::SeqCst);
                        let _ = inner.close();
                        return;
                    }
                }
            })
        });
        let r = self.ensure_handshake();
        done.store(true, Ordering::SeqCst);
        if let Some(w) = watcher {
            let _ = w.join();
        }
        if cancelled.load(Ordering::SeqCst) && r.is_err() {
            if let Err(e) = ctx.check() {
                return Err(Error::new(format!("{e}")));
            }
        }
        r
    }

    /// Go's `Conn.Read`: reads decrypted data; `Ok(0)` is end of stream.
    pub fn read(&self, b: &mut [u8]) -> Result<usize, Error> {
        self.ensure_handshake()?;
        if b.is_empty() {
            return Ok(0);
        }
        loop {
            {
                let mut plain = lock(&self.plain);
                if !plain.0.is_empty() {
                    let n = b.len().min(plain.0.len());
                    for (i, byte) in plain.0.drain(..n).enumerate() {
                        b[i] = byte;
                    }
                    return Ok(n);
                }
                if plain.1 {
                    return Ok(0);
                }
            }
            if let Some(e) = lock(&self.read_err).clone() {
                return Err(e);
            }
            match self.pump_read() {
                Ok(true) => {}
                Ok(false) => return Ok(0),
                Err(e) => {
                    if !e.timeout() {
                        *lock(&self.read_err) = Some(e.clone());
                    }
                    return Err(e);
                }
            }
        }
    }

    /// Go's `Conn.Write`: encrypts and writes `b`.
    pub fn write(&self, b: &[u8]) -> Result<usize, Error> {
        self.ensure_handshake()?;
        if self.close_notify_sent.load(Ordering::SeqCst) {
            return Err(Error::Net(NetError::other("tls: protocol is shutdown")));
        }
        let mut off = 0;
        while off < b.len() {
            let n = {
                let mut guard = lock(&self.tls);
                let tls = guard
                    .as_mut()
                    .ok_or_else(|| Error::new("tls: not connected"))?;
                tls.writer().write(&b[off..]).map_err(net_err)?
            };
            off += n;
            self.flush_tls()?;
            if n == 0 {
                return Err(Error::new("tls: write made no progress"));
            }
        }
        Ok(b.len())
    }

    /// Go's `Conn.Close`: sends close_notify (best effort) and closes the connection.
    pub fn close(&self) -> Result<(), Error> {
        if self.closed.swap(true, Ordering::SeqCst) {
            return Err(Error::Net(NetError::Closed));
        }
        if lock(&self.hs_result).as_ref().is_some_and(|r| r.is_ok()) {
            let _ = self.close_write();
        }
        self.inner.close().map_err(Error::Net)
    }

    /// Go's `Conn.CloseWrite`: shuts down the writing side by sending
    /// close_notify. The handshake must have completed.
    pub fn close_write(&self) -> Result<(), Error> {
        if !lock(&self.hs_result).as_ref().is_some_and(|r| r.is_ok()) {
            return Err(Error::new("tls: handshake has not yet been performed"));
        }
        if self.close_notify_sent.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        if let Some(t) = lock(&self.tls).as_mut() {
            t.send_close_notify();
        }
        self.flush_tls()
    }

    /// Go's `Conn.LocalAddr`.
    pub fn local_addr(&self) -> Option<AddrRef> {
        self.inner.local_addr()
    }
    /// Go's `Conn.RemoteAddr`.
    pub fn remote_addr(&self) -> Option<AddrRef> {
        self.inner.remote_addr()
    }
    /// Go's `Conn.SetDeadline`.
    pub fn set_deadline(&self, t: &Time) -> Result<(), Error> {
        self.inner.set_deadline(t).map_err(Error::Net)
    }
    /// Go's `Conn.SetReadDeadline`.
    pub fn set_read_deadline(&self, t: &Time) -> Result<(), Error> {
        self.inner.set_read_deadline(t).map_err(Error::Net)
    }
    /// Go's `Conn.SetWriteDeadline`.
    pub fn set_write_deadline(&self, t: &Time) -> Result<(), Error> {
        self.inner.set_write_deadline(t).map_err(Error::Net)
    }

    /// Go's `Conn.NetConn`: the underlying connection.
    pub fn net_conn(&self) -> Arc<dyn NetConn> {
        self.inner.clone()
    }

    /// Go's `Conn.ConnectionState`.
    pub fn connection_state(&self) -> ConnectionState {
        let guard = lock(&self.tls);
        let Some(tls) = guard.as_ref() else {
            return ConnectionState::default();
        };
        let complete = !tls.is_handshaking();
        let kind = tls.handshake_kind();
        let peer_der = lock(&self.shared.peer_certs).clone();
        let peer_der = if peer_der.is_empty() {
            tls.peer_certificates()
                .map(|cs| cs.iter().map(|c| c.as_ref().to_vec()).collect())
                .unwrap_or_default()
        } else {
            peer_der
        };
        let server_name = match tls {
            Connection::Server(s) => s.server_name().unwrap_or("").to_string(),
            Connection::Client(_) => hostname_in_sni(&self.config.server_name),
        };
        let shared = self.shared.clone();
        let verified_chains = lock(&shared.verified_chains).clone();
        let ocsp_response = lock(&shared.ocsp).clone();
        let local_certificate = lock(&shared.local_cert).clone();
        ConnectionState {
            version: tls.protocol_version().map_or(0, u16::from),
            handshake_complete: complete,
            did_resume: matches!(kind, Some(HandshakeKind::Resumed)),
            cipher_suite: tls
                .negotiated_cipher_suite()
                .map_or(0, |s| u16::from(s.suite())),
            curve_id: tls
                .negotiated_key_exchange_group()
                .map_or(CurveID(0), |g| CurveID(u16::from(g.name()))),
            negotiated_protocol: tls
                .alpn_protocol()
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .unwrap_or_default(),
            negotiated_protocol_is_mutual: true,
            server_name,
            peer_certificates: peer_der
                .iter()
                .filter_map(|d| x509::parse_certificate(d).ok().map(Arc::new))
                .collect(),
            verified_chains,
            signed_certificate_timestamps: Vec::new(),
            ocsp_response,
            tls_unique: Vec::new(),
            ech_accepted: false,
            hello_retry_request: matches!(kind, Some(HandshakeKind::FullWithHelloRetryRequest)),
            local_certificate,
            ekm: None,
        }
        .with_exporter(self.exporter())
    }

    fn exporter(&self) -> ExporterFn {
        let tls = self.tls.clone();
        Arc::new(move |label, context, length| {
            let guard = lock(&tls);
            let c = guard.as_ref().ok_or_else(|| {
                Error::new("tls: ExportKeyingMaterial is unavailable before the handshake")
            })?;
            if c.is_handshaking() {
                return Err(Error::new(
                    "tls: ExportKeyingMaterial is unavailable before the handshake completes",
                ));
            }
            c.export_keying_material(vec![0u8; length], label.as_bytes(), context)
                .map_err(|e| Error::new(format!("tls: {e}")))
        })
    }

    /// Go's `Conn.OCSPResponse`: the stapled OCSP response from the server, if any.
    pub fn ocsp_response(&self) -> Result<Vec<u8>, Error> {
        self.ensure_handshake()?;
        Ok(lock(&self.shared.ocsp).clone())
    }

    /// Go's `Conn.VerifyHostname`: checks the leaf certificate against `host`.
    pub fn verify_hostname(&self, host: &str) -> Result<(), Error> {
        if !self.is_client {
            return Err(Error::new(
                "tls: VerifyHostname called on TLS server connection",
            ));
        }
        if !lock(&self.hs_result).as_ref().is_some_and(|r| r.is_ok()) {
            return Err(Error::new("tls: handshake has not yet been performed"));
        }
        if lock(&self.shared.verified_chains).is_empty() {
            return Err(Error::new(
                "tls: handshake did not verify certificate chain",
            ));
        }
        let state = self.connection_state();
        state.peer_certificates[0]
            .verify_hostname(host)
            .map_err(|e| Error::X509(e.to_string()))
    }
}

impl ConnectionState {
    fn with_exporter(mut self, f: ExporterFn) -> ConnectionState {
        self.ekm = Some(f);
        self
    }
}

impl NetConn for Conn {
    fn read(&self, b: &mut [u8]) -> Result<usize, NetError> {
        Conn::read(self, b).map_err(NetError::from)
    }
    fn write(&self, b: &[u8]) -> Result<usize, NetError> {
        Conn::write(self, b).map_err(NetError::from)
    }
    fn close(&self) -> Result<(), NetError> {
        Conn::close(self).map_err(NetError::from)
    }
    fn local_addr(&self) -> Option<AddrRef> {
        Conn::local_addr(self)
    }
    fn remote_addr(&self) -> Option<AddrRef> {
        Conn::remote_addr(self)
    }
    fn set_deadline(&self, t: &Time) -> Result<(), NetError> {
        self.inner.set_deadline(t)
    }
    fn set_read_deadline(&self, t: &Time) -> Result<(), NetError> {
        self.inner.set_read_deadline(t)
    }
    fn set_write_deadline(&self, t: &Time) -> Result<(), NetError> {
        self.inner.set_write_deadline(t)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn tls_connection_state(&self) -> Option<rust_stdlib::net::TlsConnectionState> {
        let s = self.connection_state();
        Some(rust_stdlib::net::TlsConnectionState {
            version: s.version,
            handshake_complete: s.handshake_complete,
            did_resume: s.did_resume,
            cipher_suite: s.cipher_suite,
            negotiated_protocol: s.negotiated_protocol,
            server_name: s.server_name,
            peer_certificates: s.peer_certificates.iter().map(|c| c.raw.clone()).collect(),
        })
    }
    fn handshake(&self) -> Result<(), NetError> {
        Conn::handshake(self).map_err(NetError::from)
    }
}

impl Read for &Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Conn::read(self, buf).map_err(io::Error::from)
    }
}
impl Write for &Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Conn::write(self, buf).map_err(io::Error::from)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl std::fmt::Debug for Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conn")
            .field("is_client", &self.is_client)
            .field("state", &self.connection_state())
            .finish()
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Conn::read(self, buf).map_err(io::Error::from)
    }
}
impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Conn::write(self, buf).map_err(io::Error::from)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
