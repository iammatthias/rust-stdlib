//! `QUICConn` and its events (`quic.go`) over `rustls::quic`.
//!
//! Rustls drives the QUIC handshake the same way Go does: handshake bytes in
//! per encryption level, handshake bytes and keys out. Two differences are
//! deviations: Rustls hands out packet-protection *keys* rather than raw
//! traffic secrets, so [`QUICEvent::data`] is empty for the secret events and
//! the keys are in [`QUICEvent::keys`]; and Rustls needs the transport
//! parameters before the handshake starts, so a server also emits
//! [`QUIC_TRANSPORT_PARAMETERS_REQUIRED`] at `start`.
use super::config::{ClientHelloInfo, Config};
use super::consts::*;
use super::error::{AlertError, Error};
use super::glue::*;
use super::session::SessionState;
use super::x509;
use super::ConnectionState;
use rust_stdlib::context::Context;
use rustls::pki_types::ServerName;
use rustls::quic;
use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};

newtype_consts! {
    /// Go's `tls.QUICEncryptionLevel`: a QUIC encryption level used to transmit handshake messages.
    QUICEncryptionLevel(i32) {
        QUIC_ENCRYPTION_LEVEL_INITIAL = 0;
        QUIC_ENCRYPTION_LEVEL_EARLY = 1;
        QUIC_ENCRYPTION_LEVEL_HANDSHAKE = 2;
        QUIC_ENCRYPTION_LEVEL_APPLICATION = 3;
    }
}

impl QUICEncryptionLevel {
    /// Go's `QUICEncryptionLevel.String`.
    fn string(&self) -> String {
        match self.0 {
            0 => "Initial".into(),
            1 => "Early".into(),
            2 => "Handshake".into(),
            3 => "Application".into(),
            v => format!("QUICEncryptionLevel({v})"),
        }
    }
}
impl fmt::Display for QUICEncryptionLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string())
    }
}

newtype_consts! {
    /// Go's `tls.QUICEventKind`: a type of operation on a QUIC connection.
    QUICEventKind(i32) {
        /// No events are available.
        QUIC_NO_EVENT = 0;
        /// The read secret (keys) for an encryption level.
        QUIC_SET_READ_SECRET = 1;
        /// The write secret (keys) for an encryption level.
        QUIC_SET_WRITE_SECRET = 2;
        /// Data to send to the peer in CRYPTO frames.
        QUIC_WRITE_DATA = 3;
        /// The peer's QUIC transport parameters.
        QUIC_TRANSPORT_PARAMETERS = 4;
        /// The caller must provide transport parameters.
        QUIC_TRANSPORT_PARAMETERS_REQUIRED = 5;
        /// The server rejected 0-RTT data (never produced; 0-RTT is unsupported).
        QUIC_REJECTED_EARLY_DATA = 6;
        /// The TLS handshake has completed.
        QUIC_HANDSHAKE_DONE = 7;
        /// A client is attempting to resume a session (never produced).
        QUIC_RESUME_SESSION = 8;
        /// The server provided state to resume the session (never produced).
        QUIC_STORE_SESSION = 9;
        /// A fatal error has occurred; `QUICEvent::err` is set.
        QUIC_ERROR_EVENT = 10;
    }
}

/// Go's `tls.QUICEvent`: an event occurring on a QUIC connection.
#[derive(Clone, Default)]
pub struct QUICEvent {
    pub kind: QUICEventKind,
    /// Set for the secret and write-data events.
    pub level: QUICEncryptionLevel,
    /// Write data, or the peer's transport parameters. Empty for the secret
    /// events: Rustls does not export traffic secrets (see [`QUICEvent::keys`]).
    pub data: Vec<u8>,
    /// The negotiated cipher suite for the secret events.
    pub suite: u16,
    /// Never set; session events are not produced.
    pub session_state: Option<SessionState>,
    /// Set for [`QUIC_ERROR_EVENT`].
    pub err: Option<Error>,
    /// Extension: the packet and header protection keys for a secret event.
    pub keys: Option<Arc<quic::DirectionalKeys>>,
}

impl fmt::Debug for QUICEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QUICEvent")
            .field("kind", &self.kind)
            .field("level", &self.level)
            .field("data_len", &self.data.len())
            .finish_non_exhaustive()
    }
}

/// Go's `tls.QUICSessionTicketOptions`.
#[derive(Clone, Debug, Default)]
pub struct QUICSessionTicketOptions {
    /// Whether the ticket may be used for 0-RTT.
    pub early_data: bool,
    /// Extra data stored in the ticket.
    pub extra: Vec<Vec<u8>>,
}

/// Go's `tls.QUICConfig`.
#[derive(Clone, Default)]
pub struct QUICConfig {
    pub tls_config: Option<Arc<Config>>,
    /// Session events are not supported; setting this is an error at `start`.
    pub enable_session_events: bool,
    /// The connection used for `ClientHelloInfo.Conn`.
    pub client_hello_info_conn: Option<Arc<dyn rust_stdlib::net::Conn>>,
}

struct Inner {
    cfg: QUICConfig,
    is_client: bool,
    started: bool,
    closed: bool,
    params_required_sent: bool,
    params: Option<Vec<u8>>,
    conn: Option<quic::Connection>,
    events: VecDeque<QUICEvent>,
    read_level: QUICEncryptionLevel,
    write_level: QUICEncryptionLevel,
    queued: Vec<(QUICEncryptionLevel, Vec<u8>)>,
    pending_read: Option<(Arc<quic::DirectionalKeys>, u16)>,
    peer_params_sent: bool,
    done_sent: bool,
    failed: Option<Error>,
    shared: Arc<Shared>,
}

/// Go's `tls.QUICConn`: a connection that uses a QUIC implementation as its
/// transport (RFC 9001). Methods are safe for concurrent use here, unlike Go's.
pub struct QUICConn(Mutex<Inner>);

/// Go's `tls.QUICClient`.
pub fn quic_client(config: QUICConfig) -> QUICConn {
    QUICConn::new(config, true)
}

/// Go's `tls.QUICServer`.
pub fn quic_server(config: QUICConfig) -> QUICConn {
    QUICConn::new(config, false)
}

fn alert_error(conn: &quic::Connection, e: rustls::Error) -> Error {
    if let Some(a) = conn.alert() {
        return Error::Alert(AlertError(u8::from(a)));
    }
    Error::new(format!("tls: {e}"))
}

impl QUICConn {
    fn new(config: QUICConfig, is_client: bool) -> QUICConn {
        QUICConn(Mutex::new(Inner {
            cfg: config,
            is_client,
            started: false,
            closed: false,
            params_required_sent: false,
            params: None,
            conn: None,
            events: VecDeque::new(),
            read_level: QUIC_ENCRYPTION_LEVEL_INITIAL,
            write_level: QUIC_ENCRYPTION_LEVEL_INITIAL,
            queued: Vec::new(),
            pending_read: None,
            peer_params_sent: false,
            done_sent: false,
            failed: None,
            shared: Arc::new(Shared::default()),
        }))
    }

    /// Go's `QUICConn.Start`: begins the handshake. Cancelling `ctx` is not
    /// observed after `start` returns, as the handshake is driven by the caller.
    pub fn start(&self, ctx: &Context) -> Result<(), Error> {
        let mut q = lock(&self.0);
        if q.started {
            return Err(Error::new("tls: Start called more than once"));
        }
        q.started = true;
        if q.cfg.enable_session_events {
            return Err(Error::new(
                "tls: QUIC session events are not supported by the rustls adapter",
            ));
        }
        let Some(cfg) = q.cfg.tls_config.clone() else {
            return Err(Error::new("tls: QUICConfig.TLSConfig is nil"));
        };
        if cfg.max_version != 0 && cfg.max_version < VERSION_TLS13 {
            return Err(Error::new(
                "tls: Config MaxVersion must be at least TLS 1.3",
            ));
        }
        if cfg.get_config_for_client.is_some() && !q.is_client {
            return Err(Error::new(
                "tls: GetConfigForClient is not supported over QUIC by the rustls adapter",
            ));
        }
        let _ = ctx;
        if q.params.is_none() {
            q.events.push_back(QUICEvent {
                kind: QUIC_TRANSPORT_PARAMETERS_REQUIRED,
                ..QUICEvent::default()
            });
            q.params_required_sent = true;
            return Ok(());
        }
        q.create_conn()
    }

    /// Go's `QUICConn.SetTransportParameters`: the transport parameters to send.
    /// Call before `start` or in response to [`QUIC_TRANSPORT_PARAMETERS_REQUIRED`].
    pub fn set_transport_parameters(&self, params: &[u8]) {
        let mut q = lock(&self.0);
        q.params = Some(params.to_vec());
        if q.started && q.conn.is_none() {
            if let Err(e) = q.create_conn() {
                q.fail(e);
            }
        }
    }

    /// Go's `QUICConn.NextEvent`: the next event, or [`QUIC_NO_EVENT`].
    pub fn next_event(&self) -> QUICEvent {
        let mut q = lock(&self.0);
        q.events.pop_front().unwrap_or_default()
    }

    /// Go's `QUICConn.HandleData`: handshake bytes the QUIC layer received in
    /// CRYPTO frames at `level`.
    pub fn handle_data(&self, level: QUICEncryptionLevel, data: &[u8]) -> Result<(), Error> {
        let mut q = lock(&self.0);
        if let Some(e) = q.failed.clone() {
            return Err(e);
        }
        if q.closed {
            return Err(Error::new("tls: use of closed QUIC connection"));
        }
        if level != q.read_level {
            let e = Error::new(format!(
                "tls: handshake data received at {} but expected {}",
                level.string(),
                q.read_level.string()
            ));
            q.fail(e.clone());
            return Err(e);
        }
        if q.conn.is_none() {
            q.queued.push((level, data.to_vec()));
            return Ok(());
        }
        q.read(data)
    }

    /// Go's `QUICConn.SendSessionTicket`. Rustls sends TLS 1.3 session tickets
    /// by itself after the handshake, so an application cannot trigger or
    /// shape one; this always fails.
    pub fn send_session_ticket(&self, _opts: QUICSessionTicketOptions) -> Result<(), Error> {
        Err(Error::new("tls: SendSessionTicket is not supported by the rustls adapter (tickets are sent automatically)"))
    }

    /// Go's `QUICConn.StoreSession`. Unsupported because session events are.
    pub fn store_session(&self, _session: &SessionState) -> Result<(), Error> {
        Err(Error::new(
            "tls: StoreSession is not supported by the rustls adapter",
        ))
    }

    /// Go's `QUICConn.ConnectionState`.
    pub fn connection_state(&self) -> ConnectionState {
        let q = lock(&self.0);
        let Some(c) = q.conn.as_ref() else {
            return ConnectionState::default();
        };
        let peer: Vec<Arc<x509::Certificate>> = c
            .peer_certificates()
            .map(|cs| {
                cs.iter()
                    .filter_map(|d| x509::parse_certificate(d.as_ref()).ok().map(Arc::new))
                    .collect()
            })
            .unwrap_or_default();
        let verified_chains = lock(&q.shared.verified_chains).clone();
        let ocsp_response = lock(&q.shared.ocsp).clone();
        let local_certificate = lock(&q.shared.local_cert).clone();
        ConnectionState {
            version: c.protocol_version().map_or(0, u16::from),
            handshake_complete: !c.is_handshaking(),
            did_resume: matches!(c.handshake_kind(), Some(rustls::HandshakeKind::Resumed)),
            cipher_suite: c
                .negotiated_cipher_suite()
                .map_or(0, |s| u16::from(s.suite())),
            curve_id: c
                .negotiated_key_exchange_group()
                .map_or(CurveID(0), |g| CurveID(u16::from(g.name()))),
            negotiated_protocol: c
                .alpn_protocol()
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .unwrap_or_default(),
            negotiated_protocol_is_mutual: true,
            server_name: match c {
                quic::Connection::Server(s) => s.server_name().unwrap_or("").to_string(),
                quic::Connection::Client(_) => q
                    .cfg
                    .tls_config
                    .as_ref()
                    .map(|t| t.server_name.clone())
                    .unwrap_or_default(),
            },
            peer_certificates: peer,
            verified_chains,
            ocsp_response,
            local_certificate,
            ..ConnectionState::default()
        }
    }

    /// Go's `QUICConn.Close`: closes the connection and stops the handshake.
    pub fn close(&self) -> Result<(), Error> {
        let mut q = lock(&self.0);
        q.closed = true;
        q.conn = None;
        Ok(())
    }
}

impl Inner {
    fn fail(&mut self, e: Error) {
        self.failed = Some(e.clone());
        self.events.push_back(QUICEvent {
            kind: QUIC_ERROR_EVENT,
            err: Some(e),
            ..QUICEvent::default()
        });
    }

    fn create_conn(&mut self) -> Result<(), Error> {
        let shared = self.shared.clone();
        let _scope = Scope::enter(&shared);
        let cfg = self.cfg.tls_config.clone().expect("checked at start");
        let params = self.params.clone().unwrap_or_default();
        let mut tls13 = (*cfg).clone();
        tls13.min_version = VERSION_TLS13;
        let tls13 = Arc::new(tls13);
        let conn: quic::Connection = if self.is_client {
            let rc = build_client_config(&tls13)?;
            let name = ServerName::try_from(cfg.server_name.clone())
                .map_err(|e| Error::new(format!("tls: invalid server name: {e}")))?;
            quic::ClientConnection::new(Arc::new(rc), quic::Version::V1, name, params)
                .map_err(|e| Error::new(format!("tls: {e}")))?
                .into()
        } else {
            let hello = ClientHelloInfo {
                conn: self.cfg.client_hello_info_conn.clone(),
                config: Some(tls13.clone()),
                ..ClientHelloInfo::default()
            };
            let sc = build_server_config(&tls13, &self.shared, hello)?;
            quic::ServerConnection::new(Arc::new(sc), quic::Version::V1, params)
                .map_err(|e| Error::new(format!("tls: {e}")))?
                .into()
        };
        self.conn = Some(conn);
        self.pump()?;
        let queued = std::mem::take(&mut self.queued);
        for (_, d) in queued {
            self.read(&d)?;
        }
        Ok(())
    }

    fn read(&mut self, data: &[u8]) -> Result<(), Error> {
        let shared = self.shared.clone();
        let _scope = Scope::enter(&shared);
        let conn = self.conn.as_mut().expect("connection exists");
        if let Err(e) = conn.read_hs(data) {
            let err = lock(&self.shared.error)
                .clone()
                .unwrap_or_else(|| alert_error(conn, e));
            self.fail(err.clone());
            return Err(err);
        }
        self.pump()
    }

    /// Moves everything Rustls has ready into events.
    fn pump(&mut self) -> Result<(), Error> {
        loop {
            let conn = self.conn.as_mut().expect("connection exists");
            let mut buf = Vec::new();
            let change = conn.write_hs(&mut buf);
            let progressed = !buf.is_empty() || change.is_some();
            if !buf.is_empty() {
                self.events.push_back(QUICEvent {
                    kind: QUIC_WRITE_DATA,
                    level: self.write_level,
                    data: buf,
                    ..QUICEvent::default()
                });
            }
            if let Some(change) = change {
                let suite = conn
                    .negotiated_cipher_suite()
                    .map_or(0, |s| u16::from(s.suite()));
                let (keys, level) = match change {
                    quic::KeyChange::Handshake { keys } => (keys, QUIC_ENCRYPTION_LEVEL_HANDSHAKE),
                    quic::KeyChange::OneRtt { keys, .. } => {
                        (keys, QUIC_ENCRYPTION_LEVEL_APPLICATION)
                    }
                };
                let quic::Keys { local, remote } = keys;
                let remote = Arc::new(remote);
                // Rustls hands a server its 1-RTT keys as soon as it has sent
                // its Finished, but the client's Finished still arrives at the
                // Handshake level. Go reads Application data only after that
                // Finished, so the server's Application read secret is held
                // back until the handshake completes.
                let hold_read = !self.is_client && level == QUIC_ENCRYPTION_LEVEL_APPLICATION;
                if hold_read {
                    self.pending_read = Some((remote, suite));
                } else {
                    // Go reports the read secret before the write secret.
                    self.events.push_back(QUICEvent {
                        kind: QUIC_SET_READ_SECRET,
                        level,
                        suite,
                        keys: Some(remote),
                        ..QUICEvent::default()
                    });
                    self.read_level = level;
                }
                self.events.push_back(QUICEvent {
                    kind: QUIC_SET_WRITE_SECRET,
                    level,
                    suite,
                    keys: Some(Arc::new(local)),
                    ..QUICEvent::default()
                });
                self.write_level = level;
            }
            if !progressed {
                break;
            }
        }
        let conn = self.conn.as_ref().expect("connection exists");
        if !conn.is_handshaking() {
            if let Some((keys, suite)) = self.pending_read.take() {
                self.events.push_back(QUICEvent {
                    kind: QUIC_SET_READ_SECRET,
                    level: QUIC_ENCRYPTION_LEVEL_APPLICATION,
                    suite,
                    keys: Some(keys),
                    ..QUICEvent::default()
                });
                self.read_level = QUIC_ENCRYPTION_LEVEL_APPLICATION;
            }
        }
        if !self.peer_params_sent {
            if let Some(p) = conn.quic_transport_parameters() {
                let p = p.to_vec();
                self.peer_params_sent = true;
                self.events.push_back(QUICEvent {
                    kind: QUIC_TRANSPORT_PARAMETERS,
                    data: p,
                    ..QUICEvent::default()
                });
            }
        }
        if !self.done_sent && !conn.is_handshaking() {
            self.done_sent = true;
            self.events.push_back(QUICEvent {
                kind: QUIC_HANDSHAKE_DONE,
                ..QUICEvent::default()
            });
        }
        Ok(())
    }
}
