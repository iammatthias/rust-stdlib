//! Go's `crypto/tls` API over Rustls: in-process loopback tests, tables ported
//! from Go's `tls_test.go` / `handshake_client_test.go`, and the QUIC handshake.
//! Live interop with Go is `tools/gotls_check.py`.
//!
//! The PKI in `tests/fixtures/gotls` is public, test-only material written by
//! `tools/gotls_oracle.go certs` (valid 2020-2050; `expired` and `notyet` are
//! deliberately not).
use rust_stdlib::{
    context::Context,
    net::{self, Listener as NetListener},
    time,
};
use rust_stdlib_tls::tls::{self, x509, Certificate, ClientSessionCache, Config};
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::thread;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/gotls");

fn read(name: &str) -> Vec<u8> {
    std::fs::read(format!("{DIR}/{name}")).unwrap_or_else(|e| panic!("{name}: {e}"))
}
fn pair(name: &str) -> Certificate {
    tls::load_x509_key_pair(
        &format!("{DIR}/{name}.pem"),
        &format!("{DIR}/{name}-key.pem"),
    )
    .unwrap_or_else(|e| panic!("{name}: {e}"))
}
fn pool(name: &str) -> x509::CertPool {
    let mut p = x509::CertPool::new();
    assert!(p.append_certs_from_pem(&read(&format!("{name}.pem"))));
    p
}
fn server_config(certs: &[&str]) -> Config {
    let mut c = Config::new();
    c.certificates = certs.iter().map(|n| pair(n)).collect();
    c
}
fn client_config() -> Config {
    let mut c = Config::new();
    c.root_cas = Some(pool("ca"));
    c.server_name = "localhost".into();
    c
}
/// 2026-01-01T00:00:00Z, so verification results do not depend on today.
fn fixed_time() -> time::Time {
    time::unix(1_767_225_600, 0)
}

struct Server {
    addr: String,
    ln: Arc<tls::Listener>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Server {
    /// Accepts one connection and runs `f` on it.
    fn start<F>(config: Config, f: F) -> Server
    where
        F: FnOnce(&tls::Conn) + Send + 'static,
    {
        let ln = Arc::new(tls::listen("tcp", "127.0.0.1:0", Arc::new(config)).expect("listen"));
        let addr = NetListener::addr(&*ln).expect("addr").to_string();
        let l2 = ln.clone();
        let thread = thread::spawn(move || {
            let c = NetListener::accept(&*l2).expect("accept");
            let conn = c.as_any().downcast_ref::<tls::Conn>().expect("tls conn");
            f(conn);
            let _ = conn.close();
        });
        Server {
            addr,
            ln,
            thread: Some(thread),
        }
    }
    fn finish(mut self) {
        self.thread
            .take()
            .expect("thread")
            .join()
            .expect("server thread");
        let _ = NetListener::close(&*self.ln);
    }
}

fn read_line(c: &tls::Conn) -> String {
    let mut out = Vec::new();
    let mut b = [0u8; 1];
    loop {
        match c.read(&mut b) {
            Ok(1) => {
                if b[0] == b'\n' {
                    return String::from_utf8(out).expect("utf8");
                }
                out.push(b[0]);
            }
            Ok(_) => return String::from_utf8(out).expect("utf8"),
            Err(e) => panic!("read: {e}"),
        }
    }
}

fn echo(c: &tls::Conn) {
    let line = read_line(c);
    c.write(format!("echo:{line}\n").as_bytes()).expect("write");
}

/// Connects, exchanges a line and returns both connection states.
fn roundtrip(server: Config, client: Config) -> (tls::ConnectionState, tls::ConnectionState) {
    let states = Arc::new(Mutex::new(None));
    let s2 = states.clone();
    let srv = Server::start(server, move |c| {
        echo(c);
        *s2.lock().unwrap() = Some(c.connection_state());
    });
    let c = tls::dial("tcp", &srv.addr, Some(Arc::new(client))).expect("dial");
    c.write(b"hello\n").expect("write");
    assert_eq!(read_line(&c), "echo:hello");
    let cs = c.connection_state();
    let _ = c.close();
    srv.finish();
    let ss = states.lock().unwrap().take().expect("server state");
    (cs, ss)
}

// ------------------------------------------------------------------ tables

#[test]
fn cipher_suite_tables_follow_go_invariants() {
    // Port of Go's TestCipherSuites (the parts that need no private tables).
    let secure = tls::cipher_suites();
    let insecure = tls::insecure_cipher_suites();
    assert_eq!(secure.len(), 13);
    assert_eq!(insecure.len(), 12);
    let mut last = 0;
    for c in &secure {
        assert!(c.id >= last, "CipherSuites not ordered by ID");
        last = c.id;
        assert!(!c.insecure, "{:#06x} insecure in CipherSuites", c.id);
        assert!(matches!(c.supported_versions.len(), 1 | 3));
    }
    last = 0;
    for c in &insecure {
        assert!(c.id >= last, "InsecureCipherSuites not ordered by ID");
        last = c.id;
        assert!(c.insecure, "{:#06x} secure in InsecureCipherSuites", c.id);
    }
    for c in secure.iter().chain(&insecure) {
        assert_eq!(tls::cipher_suite_name(c.id), c.name);
    }
    assert_eq!(
        tls::cipher_suite_name(tls::TLS_AES_128_GCM_SHA256),
        "TLS_AES_128_GCM_SHA256"
    );
    assert_eq!(tls::cipher_suite_name(0x1234), "0x1234");
    assert_eq!(tls::cipher_suite_name(0xabcd), "0xABCD");
}

#[test]
fn name_tables() {
    assert_eq!(tls::version_name(tls::VERSION_SSL30), "SSLv3");
    assert_eq!(tls::version_name(tls::VERSION_TLS10), "TLS 1.0");
    assert_eq!(tls::version_name(tls::VERSION_TLS13), "TLS 1.3");
    assert_eq!(tls::version_name(0x0a0b), "0x0A0B");
    assert_eq!(tls::X25519.to_string(), "X25519");
    assert_eq!(tls::CURVE_P521.to_string(), "CurveP521");
    assert_eq!(tls::CurveID(1).to_string(), "CurveID(1)");
    assert_eq!(tls::ED25519.to_string(), "Ed25519");
    assert_eq!(tls::PSS_WITH_SHA256.to_string(), "PSSWithSHA256");
    assert_eq!(tls::SignatureScheme(1).to_string(), "SignatureScheme(1)");
    assert_eq!(
        tls::REQUIRE_AND_VERIFY_CLIENT_CERT.to_string(),
        "RequireAndVerifyClientCert"
    );
    assert_eq!(tls::ClientAuthType(-1).to_string(), "ClientAuthType(-1)");
    assert_eq!(tls::QUIC_ENCRYPTION_LEVEL_EARLY.to_string(), "Early");
    assert_eq!(
        tls::QUICEncryptionLevel(7).to_string(),
        "QUICEncryptionLevel(7)"
    );
    assert_eq!(tls::AlertError(42).error(), "tls: bad certificate");
    assert_eq!(tls::AlertError(200).error(), "tls: alert(200)");
    assert_eq!(
        tls::RecordHeaderError {
            msg: "x".into(),
            record_header: [0; 5],
            conn: None
        }
        .error(),
        "tls: x"
    );
    assert_eq!(
        tls::ECHRejectionError::default().error(),
        "tls: server rejected ECH"
    );
}

// -------------------------------------------------------------- key pairs

#[test]
fn x509_key_pair_accepts_each_key_encoding() {
    // Port of Go's TestX509KeyPair loop: certificate then key, and key then
    // certificate, as both arguments. PKCS #1, SEC 1 and PKCS #8 keys.
    for name in ["rsa", "ecdsa", "ed25519"] {
        let cert = read(&format!("{name}.pem"));
        let key = read(&format!("{name}-key.pem"));
        let mut both = cert.clone();
        both.extend_from_slice(&key);
        let c = tls::x509_key_pair(&both, &both).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(c.leaf.is_some(), "Leaf is populated");
        let mut both = key.clone();
        both.extend_from_slice(&cert);
        tls::x509_key_pair(&both, &both).unwrap_or_else(|e| panic!("{name} key first: {e}"));
    }
}

#[test]
fn x509_key_pair_errors() {
    let rsa_cert = read("rsa.pem");
    let rsa_key = read("rsa-key.pem");
    let ecdsa_cert = read("ecdsa.pem");
    let ecdsa_key = read("ecdsa-key.pem");
    let err = tls::x509_key_pair(&rsa_key, &rsa_cert)
        .unwrap_err()
        .to_string();
    assert!(err.contains("been switched"), "{err}");
    assert!(err.starts_with(
        "tls: failed to find certificate PEM data in certificate input, but did find a private key"
    ));
    let err = tls::x509_key_pair(&rsa_cert, &rsa_cert)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("found a certificate rather than a key"),
        "{err}"
    );
    let nonsense = b"\n-----BEGIN NONSENSE-----\nZm9vZm9vZm9v\n-----END NONSENSE-----\n";
    let err = tls::x509_key_pair(nonsense, nonsense)
        .unwrap_err()
        .to_string();
    assert_eq!(
        err,
        "tls: failed to find \"CERTIFICATE\" PEM block in certificate input after skipping PEM blocks of the following types: [NONSENSE]"
    );
    assert_eq!(
        tls::x509_key_pair(b"", b"").unwrap_err().to_string(),
        "tls: failed to find any PEM data in certificate input"
    );
    assert_eq!(
        tls::x509_key_pair(&rsa_cert, b"").unwrap_err().to_string(),
        "tls: failed to find any PEM data in key input"
    );
    let err = tls::x509_key_pair(&rsa_cert, &ecdsa_key)
        .unwrap_err()
        .to_string();
    assert_eq!(err, "tls: private key type does not match public key type");
    let err = tls::x509_key_pair(&ecdsa_cert, &rsa_key)
        .unwrap_err()
        .to_string();
    assert_eq!(err, "tls: private key type does not match public key type");
    // Same key type, different key.
    let other = read("client-ecdsa-key.pem");
    let err = tls::x509_key_pair(&ecdsa_cert, &other)
        .unwrap_err()
        .to_string();
    assert_eq!(err, "tls: private key does not match public key");
    let e = tls::load_x509_key_pair("/nonexistent/cert.pem", "/nonexistent/key.pem")
        .unwrap_err()
        .to_string();
    assert!(e.contains("no such file or directory"), "{e}");
}

// ------------------------------------------------------- session machinery

#[test]
fn lru_client_session_cache() {
    // Port of Go's TestLRUClientSessionCache.
    let cache = tls::LruClientSessionCache::new(4);
    let cs: Vec<Arc<tls::ClientSessionState>> = (0..6).map(|_| Arc::default()).collect();
    let keys = ["0", "1", "2", "3", "4", "5", "6"];
    for i in 0..4 {
        cache.put(keys[i], Some(cs[i].clone()));
    }
    for i in 0..4 {
        let s = cache.get(keys[i]).expect("added key");
        assert!(Arc::ptr_eq(&s, &cs[i]), "lookup of {}", keys[i]);
    }
    for i in 4..6 {
        cache.put(keys[i], Some(cs[i].clone()));
    }
    for key in &keys[..2] {
        assert!(cache.get(key).is_none(), "key {key} should be evicted");
    }
    // Touch entry 2. LRU should evict 3 next.
    cache.get(keys[2]);
    cache.put(keys[0], Some(cs[0].clone()));
    assert!(cache.get(keys[3]).is_none(), "key 3 should be evicted");
    // Update entry 0 in place.
    cache.put(keys[0], Some(cs[3].clone()));
    assert!(Arc::ptr_eq(&cache.get(keys[0]).expect("key 0"), &cs[3]));
    // Putting None deletes the key.
    cache.put(keys[0], None);
    assert!(cache.get(keys[0]).is_none());
    cache.put(keys[2], None);
    assert!(cache.get(keys[2]).is_none());
    for i in 4..6 {
        assert!(Arc::ptr_eq(&cache.get(keys[i]).expect("kept"), &cs[i]));
    }
    // A non-positive capacity means 64.
    let big = tls::LruClientSessionCache::new(0);
    for i in 0..64 {
        big.put(&i.to_string(), Some(Arc::default()));
    }
    assert!(big.get("0").is_some());
    big.put("64", Some(Arc::default()));
    assert!(big.get("1").is_none() || big.get("0").is_some());
}

#[test]
fn session_state_round_trip() {
    let ss = tls::SessionState {
        extra: vec![b"one".to_vec(), vec![], b"three".to_vec()],
        early_data: false,
        ..tls::SessionState::default()
    };
    // A zero SessionState has no secret, which Go's parser rejects.
    let bytes = ss.bytes().expect("encode");
    assert_eq!(
        tls::parse_session_state(&bytes).unwrap_err().to_string(),
        "tls: invalid session encoding"
    );
    for bad in [&b""[..], &b"\x03\x04"[..], &[0u8; 40][..]] {
        assert!(tls::parse_session_state(bad).is_err());
    }
    let (ticket, state) = (
        b"ticket".to_vec(),
        tls::parse_session_state(&valid_server_session()).expect("parse"),
    );
    assert_eq!(state.extra, vec![b"x".to_vec()]);
    let cs = tls::ClientSessionState::new(ticket.clone(), state.clone()).expect("state");
    let (t, s) = cs.resumption_state().expect("ok").expect("some");
    assert_eq!(t, ticket);
    assert_eq!(s.extra, state.extra);
    assert!(tls::ClientSessionState::default()
        .resumption_state()
        .unwrap()
        .is_none());
    assert_eq!(state.bytes().unwrap(), valid_server_session());
}

/// version TLS 1.3, server, suite, time, 1-byte secret, one extra "x", no
/// ems, no early data, no certificates, no chains.
fn valid_server_session() -> Vec<u8> {
    let mut b = vec![0x03, 0x04, 0x01, 0x13, 0x01];
    b.extend_from_slice(&1_700_000_000u64.to_be_bytes());
    b.extend_from_slice(&[1, 0xaa]);
    b.extend_from_slice(&[0, 0, 4, 0, 0, 1, b'x']);
    b.extend_from_slice(&[0, 0]);
    b.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    b
}

#[test]
fn session_ticket_apis_fail_explicitly() {
    let c = Config::new();
    assert!(c
        .set_session_ticket_keys(&[])
        .unwrap_err()
        .to_string()
        .contains("at least one key"));
    assert!(c
        .set_session_ticket_keys(&[[1u8; 32]])
        .unwrap_err()
        .to_string()
        .contains("not supported"));
    let state = tls::ConnectionState::default();
    assert!(c
        .encrypt_ticket(&state, &tls::SessionState::default())
        .is_err());
    assert!(c.decrypt_ticket(b"x", &state).is_err());
}

// ---------------------------------------------------- loopback connections

#[test]
fn loopback_handshake_state_and_exported_keying_material() {
    for (min, max, version, suite) in [
        (
            tls::VERSION_TLS12,
            tls::VERSION_TLS12,
            "TLS 1.2",
            tls::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        ),
        (
            tls::VERSION_TLS13,
            tls::VERSION_TLS13,
            "TLS 1.3",
            tls::TLS_AES_128_GCM_SHA256,
        ),
    ] {
        let mut s = server_config(&["ecdsa"]);
        s.min_version = min;
        s.max_version = max;
        s.next_protos = vec!["h2".into(), "http/1.1".into()];
        let mut c = client_config();
        c.min_version = min;
        c.max_version = max;
        c.cipher_suites = vec![suite];
        c.tls13_cipher_suites = vec![suite];
        c.next_protos = vec!["http/1.1".into(), "h2".into()];
        let (cs, ss) = roundtrip(s, c);
        for st in [&cs, &ss] {
            assert_eq!(tls::version_name(st.version), version);
            assert!(st.handshake_complete);
            assert!(!st.did_resume);
            assert_eq!(st.cipher_suite, suite);
            assert_eq!(st.negotiated_protocol, "h2");
            assert!(st.negotiated_protocol_is_mutual);
            assert_eq!(st.server_name, "localhost");
            assert_ne!(st.curve_id, tls::CurveID(0));
        }
        assert_eq!(cs.peer_certificates.len(), 2, "leaf and intermediate");
        assert_eq!(cs.peer_certificates[0].subject_common_name, "ecdsa.test");
        assert_eq!(cs.verified_chains.len(), 1);
        assert_eq!(cs.verified_chains[0].len(), 3, "leaf, intermediate, root");
        assert_eq!(
            cs.verified_chains[0][2].subject_common_name,
            "gotls test CA"
        );
        assert!(ss.peer_certificates.is_empty());
        assert_eq!(ss.local_certificate.len(), 2);
        // RFC 5705 export agrees across the connection.
        let a = cs
            .export_keying_material("EXPERIMENT test", None, 32)
            .unwrap();
        let b = ss
            .export_keying_material("EXPERIMENT test", None, 32)
            .unwrap();
        assert_eq!(a, b);
        let ac = cs
            .export_keying_material("EXPERIMENT test", Some(b"ctx"), 32)
            .unwrap();
        assert_eq!(
            ac,
            ss.export_keying_material("EXPERIMENT test", Some(b"ctx"), 32)
                .unwrap()
        );
        assert_ne!(a, ac);
        let ae = cs
            .export_keying_material("EXPERIMENT test", Some(b""), 32)
            .unwrap();
        if min == tls::VERSION_TLS12 {
            assert_ne!(a, ae, "TLS 1.2: nil and empty contexts differ");
        } else {
            assert_eq!(a, ae, "TLS 1.3: nil and empty contexts are the same");
        }
        assert_eq!(a.len(), 32);
    }
    assert!(tls::ConnectionState::default()
        .export_keying_material("x", None, 1)
        .is_err());
}

#[test]
fn close_write_verify_hostname_and_conn_accessors() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s2 = seen.clone();
    let srv = Server::start(server_config(&["ecdsa"]), move |c| {
        // On a server VerifyHostname refuses, before and after the handshake.
        s2.lock()
            .unwrap()
            .push(c.verify_hostname("x").unwrap_err().to_string());
        c.handshake().expect("handshake");
        s2.lock()
            .unwrap()
            .push(c.verify_hostname("x").unwrap_err().to_string());
        // Read to EOF: the client called CloseWrite, not Close.
        let mut buf = [0u8; 8];
        let mut got = Vec::new();
        loop {
            let n = c.read(&mut buf).expect("read");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, b"ping");
        c.write(b"pong").expect("server can still write");
    });
    let c = tls::dial("tcp", &srv.addr, Some(Arc::new(client_config()))).expect("dial");
    assert!(c.verify_hostname("localhost").is_ok());
    let e = c.verify_hostname("other.test").unwrap_err().to_string();
    assert_eq!(
        e,
        "x509: certificate is valid for localhost, ecdsa.test, not other.test"
    );
    assert!(c.verify_hostname("127.0.0.1").is_ok());
    assert!(c.ocsp_response().unwrap().is_empty());
    assert_eq!(
        c.net_conn().remote_addr().expect("addr").to_string(),
        c.remote_addr().expect("addr").to_string()
    );
    assert!(c.local_addr().is_some());
    c.write(b"ping").expect("write");
    c.close_write().expect("close_write");
    let mut buf = [0u8; 8];
    let n = c.read(&mut buf).expect("read");
    assert_eq!(&buf[..n], b"pong");
    assert_eq!(c.read(&mut buf).expect("eof"), 0);
    c.close().expect("close");
    assert!(c.close().is_err(), "second Close fails");
    srv.finish();
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert!(seen
        .iter()
        .all(|e| e == "tls: VerifyHostname called on TLS server connection"));
    drop(seen);
    // On a client, VerifyHostname and CloseWrite before the handshake refuse.
    let plain = net::listen("tcp", "127.0.0.1:0").expect("listen");
    let raw = net::dial("tcp", &plain.addr().unwrap().to_string()).expect("dial");
    let idle = tls::client(raw, Arc::new(client_config()));
    for e in [
        idle.verify_hostname("localhost").unwrap_err(),
        idle.close_write().unwrap_err(),
    ] {
        assert_eq!(e.to_string(), "tls: handshake has not yet been performed");
    }
}

#[test]
fn deadlines_apply_to_reads() {
    let srv = Server::start(server_config(&["ecdsa"]), |c| {
        c.handshake().expect("handshake");
        thread::sleep(std::time::Duration::from_millis(600));
    });
    let c = tls::dial("tcp", &srv.addr, Some(Arc::new(client_config()))).expect("dial");
    c.set_read_deadline(&time::now().add(time::MILLISECOND * 100))
        .unwrap();
    let mut buf = [0u8; 4];
    let err = c.read(&mut buf).unwrap_err();
    assert!(err.timeout(), "{err}");
    assert!(err.to_string().contains("i/o timeout"), "{err}");
    c.set_deadline(&time::Time::default()).unwrap();
    c.set_write_deadline(&time::Time::default()).unwrap();
    let _ = c.close();
    srv.finish();
}

#[test]
fn handshake_context_cancel_closes_the_connection() {
    let ln = net::listen("tcp", "127.0.0.1:0").expect("listen");
    let addr = ln.addr().unwrap().to_string();
    let accept = thread::spawn(move || {
        let c = ln.accept().expect("accept");
        thread::sleep(std::time::Duration::from_millis(800));
        drop(c);
    });
    let raw = net::dial("tcp", &addr).expect("dial");
    let c = tls::client(raw, Arc::new(client_config()));
    let (ctx, cancel) = Context::background().with_cancel();
    let t = thread::spawn(move || {
        thread::sleep(std::time::Duration::from_millis(100));
        cancel();
    });
    let start = std::time::Instant::now();
    let err = c.handshake_context(&ctx).unwrap_err();
    assert!(
        start.elapsed() < std::time::Duration::from_millis(700),
        "returned late"
    );
    assert_eq!(err.to_string(), "context canceled");
    t.join().unwrap();
    accept.join().unwrap();
}

#[test]
fn dialer_and_dial_with_dialer() {
    let srv1 = Server::start(server_config(&["ecdsa"]), echo);
    let d = tls::Dialer {
        net_dialer: Some(net::Dialer {
            timeout: time::SECOND * 5,
            ..net::Dialer::default()
        }),
        config: Some(Arc::new(client_config())),
    };
    let c = d.dial("tcp", &srv1.addr).expect("dial");
    c.write(b"hi\n").unwrap();
    assert_eq!(read_line(&c), "echo:hi");
    c.close().unwrap();
    srv1.finish();
    let srv2 = Server::start(server_config(&["ecdsa"]), echo);
    let nd = net::Dialer {
        timeout: time::SECOND * 5,
        ..net::Dialer::default()
    };
    // No ServerName: Dial fills in the host part of the address.
    let mut cfg = Config::new();
    cfg.root_cas = Some(pool("ca"));
    let addr = srv2.addr.replace("127.0.0.1", "localhost");
    let c = tls::dial_with_dialer(&nd, "tcp", &addr, Some(Arc::new(cfg))).expect("dial");
    c.write(b"yo\n").unwrap();
    assert_eq!(read_line(&c), "echo:yo");
    assert_eq!(c.connection_state().server_name, "localhost");
    c.close().unwrap();
    srv2.finish();
    // A dial to a closed port reports the net error.
    let e = tls::dial("tcp", "127.0.0.1:1", Some(Arc::new(client_config()))).unwrap_err();
    assert!(e.to_string().contains("dial tcp"), "{e}");
}

#[test]
fn listen_requires_a_certificate_source() {
    let e = tls::listen("tcp", "127.0.0.1:0", Arc::new(Config::new())).expect_err("error");
    assert_eq!(
        e.to_string(),
        "tls: neither Certificates, GetCertificate, nor GetConfigForClient set in Config"
    );
}

// --------------------------------------------------------------- callbacks

#[test]
fn callbacks_see_hellos_and_chains() {
    let hello = Arc::new(Mutex::new(None));
    let h2 = hello.clone();
    let mut s = server_config(&["ecdsa", "rsa"]);
    s.get_config_for_client = Some(Arc::new(move |h| {
        *h2.lock().unwrap() = Some(h.clone());
        Ok(None)
    }));
    let raws = Arc::new(Mutex::new((0, 0)));
    let r2 = raws.clone();
    let mut c = client_config();
    c.server_name = "rsa.test".into();
    c.next_protos = vec!["h2".into()];
    c.verify_peer_certificate = Some(Arc::new(move |raw, chains| {
        *r2.lock().unwrap() = (raw.len(), chains.len());
        Ok(())
    }));
    let verified = Arc::new(Mutex::new(None));
    let v2 = verified.clone();
    c.verify_connection = Some(Arc::new(move |st| {
        *v2.lock().unwrap() = Some((st.version, st.server_name.clone(), st.verified_chains.len()));
        Ok(())
    }));
    let (cs, _) = roundtrip(s, c);
    assert_eq!(cs.peer_certificates[0].subject_common_name, "rsa.test");
    let h = hello
        .lock()
        .unwrap()
        .take()
        .expect("GetConfigForClient was called");
    assert_eq!(h.server_name, "rsa.test");
    assert_eq!(h.supported_protos, vec!["h2".to_string()]);
    assert!(h.supported_versions.contains(&tls::VERSION_TLS13));
    assert!(h.supported_versions.contains(&tls::VERSION_TLS12));
    assert!(h.cipher_suites.contains(&tls::TLS_AES_128_GCM_SHA256));
    assert!(h
        .signature_schemes
        .contains(&tls::ECDSA_WITH_P256_AND_SHA256));
    assert!(h.supported_curves.contains(&tls::X25519));
    assert_eq!(h.supported_points, vec![0]);
    assert!(h.extensions.contains(&0), "server_name extension listed");
    assert!(h.conn.is_some());
    assert_eq!(*raws.lock().unwrap(), (1, 1));
    let v = verified
        .lock()
        .unwrap()
        .take()
        .expect("VerifyConnection ran");
    assert_eq!(v, (tls::VERSION_TLS13, "rsa.test".to_string(), 1));
}

#[test]
fn callback_errors_are_returned_unchanged() {
    let srv = Server::start(server_config(&["ecdsa"]), |c| {
        let _ = c.handshake();
    });
    let mut c = client_config();
    c.verify_peer_certificate = Some(Arc::new(|_, _| Err(tls::Error::new("custom rejection"))));
    let e = tls::dial("tcp", &srv.addr, Some(Arc::new(c))).expect_err("dial fails");
    assert_eq!(e.to_string(), "custom rejection");
    srv.finish();

    let srv = Server::start(server_config(&["ecdsa"]), |c| {
        let _ = c.handshake();
    });
    let mut c = client_config();
    c.verify_connection = Some(Arc::new(|st| {
        assert!(st.handshake_complete);
        Err(tls::Error::new("no thanks"))
    }));
    let e = tls::dial("tcp", &srv.addr, Some(Arc::new(c))).expect_err("dial fails");
    assert_eq!(e.to_string(), "no thanks");
    srv.finish();
}

#[test]
fn get_config_for_client_and_get_certificate_choose_certificates() {
    let mut s = server_config(&["ecdsa"]);
    let rsa = Arc::new(pair("rsa"));
    let r2 = rsa.clone();
    s.get_certificate = Some(Arc::new(move |h| {
        Ok((h.server_name == "rsa.test").then(|| r2.clone()))
    }));
    let mut c = client_config();
    c.server_name = "rsa.test".into();
    let (cs, _) = roundtrip(s.clone(), c);
    assert_eq!(cs.peer_certificates[0].subject_common_name, "rsa.test");
    // Ok(None) falls back to Certificates.
    let (cs, _) = roundtrip(s, client_config());
    assert_eq!(cs.peer_certificates[0].subject_common_name, "ecdsa.test");
    // GetConfigForClient may replace the whole configuration.
    let mut outer = Config::new();
    let inner = Arc::new(server_config(&["rsa"]));
    outer.get_config_for_client = Some(Arc::new(move |_| Ok(Some(inner.clone()))));
    let (cs, _) = roundtrip(outer, client_config());
    assert_eq!(cs.peer_certificates[0].subject_common_name, "rsa.test");
}

#[test]
fn certificate_selection_tables() {
    // Config.Certificates + NameToCertificate, as Go's getCertificate.
    let mut cfg = server_config(&["ecdsa", "rsa", "ed25519"]);
    cfg.build_name_to_certificate();
    assert!(cfg.name_to_certificate.contains_key("rsa.test"));
    assert!(cfg.name_to_certificate.contains_key("localhost"));
    let (cs, _) = roundtrip(cfg.clone(), {
        let mut c = client_config();
        c.server_name = "ed25519.test".into();
        c
    });
    assert_eq!(cs.peer_certificates[0].subject_common_name, "ed25519.test");
    // SupportsCertificate (ported cases from Go's TestSupportsCertificate).
    let ecdsa = pair("ecdsa");
    let rsa = pair("rsa");
    let hello = tls::ClientHelloInfo {
        server_name: "ecdsa.test".into(),
        signature_schemes: vec![tls::ECDSA_WITH_P256_AND_SHA256, tls::PSS_WITH_SHA256],
        supported_versions: vec![tls::VERSION_TLS13, tls::VERSION_TLS12],
        ..tls::ClientHelloInfo::default()
    };
    assert!(hello.supports_certificate(&ecdsa).is_ok());
    assert!(hello
        .supports_certificate(&rsa)
        .unwrap_err()
        .to_string()
        .contains("not valid for requested server name"));
    let no_ecdsa = tls::ClientHelloInfo {
        signature_schemes: vec![tls::PKCS1_WITH_SHA256],
        ..hello.clone()
    };
    assert_eq!(
        no_ecdsa
            .supports_certificate(&ecdsa)
            .unwrap_err()
            .to_string(),
        "tls: peer doesn't support any of the certificate's signature algorithms"
    );
    // CertificateRequestInfo.SupportsCertificate checks schemes and CAs.
    let ca = pool("ca").certificates()[0].raw_subject.clone();
    let req = tls::CertificateRequestInfo {
        acceptable_cas: vec![ca],
        signature_schemes: vec![tls::ECDSA_WITH_P256_AND_SHA256],
        ..tls::CertificateRequestInfo::default()
    };
    // client-ecdsa is issued directly by the CA.
    assert!(req.supports_certificate(&pair("client-ecdsa")).is_ok());
    assert!(req
        .supports_certificate(&pair("client-untrusted"))
        .unwrap_err()
        .to_string()
        .contains("not signed by an acceptable CA"));
    assert!(req.supports_certificate(&rsa).is_err());
}

#[test]
fn client_certificate_request_info_and_policies() {
    let seen = Arc::new(Mutex::new(None));
    let s2 = seen.clone();
    let mut s = server_config(&["ecdsa"]);
    s.client_auth = tls::REQUIRE_AND_VERIFY_CLIENT_CERT;
    s.client_cas = Some(pool("ca"));
    let mut c = client_config();
    let cert = Arc::new(pair("client-ecdsa"));
    c.get_client_certificate = Some(Arc::new(move |info| {
        *s2.lock().unwrap() = Some(info.clone());
        Ok(cert.clone())
    }));
    let (cs, ss) = roundtrip(s, c);
    let info = seen.lock().unwrap().take().expect("callback ran");
    assert_eq!(info.acceptable_cas.len(), 1);
    assert!(info
        .signature_schemes
        .contains(&tls::ECDSA_WITH_P256_AND_SHA256));
    assert_eq!(ss.peer_certificates[0].subject_common_name, "client.test");
    assert_eq!(ss.verified_chains[0].len(), 2);
    assert_eq!(cs.local_certificate.len(), 1);
}

#[test]
fn verification_failures_carry_go_texts() {
    for (cert, expect) in [
        (
            "expired",
            "x509: certificate has expired or is not yet valid: current time ",
        ),
        (
            "notyet",
            "x509: certificate has expired or is not yet valid: current time ",
        ),
        (
            "wronghost",
            "x509: certificate is valid for other.test, second.test, not localhost",
        ),
        ("untrusted", "x509: certificate signed by unknown authority"),
    ] {
        let srv = Server::start(server_config(&[cert]), |c| {
            let _ = c.handshake();
        });
        let mut cfg = client_config();
        cfg.time = Some(Arc::new(fixed_time));
        let err = tls::dial("tcp", &srv.addr, Some(Arc::new(cfg))).expect_err(cert);
        let text = err.to_string();
        assert!(
            text.starts_with(&format!("tls: failed to verify certificate: {expect}")),
            "{cert}: {text}"
        );
        let v = err
            .as_certificate_verification()
            .expect("CertificateVerificationError");
        assert!(!v.unverified_certificates.is_empty());
        assert_eq!(
            v.unwrap().to_string(),
            text["tls: failed to verify certificate: ".len()..]
        );
        srv.finish();
    }
    // The dates in the messages are the certificates' own.
    let srv = Server::start(server_config(&["expired"]), |c| {
        let _ = c.handshake();
    });
    let mut cfg = client_config();
    cfg.time = Some(Arc::new(fixed_time));
    let text = tls::dial("tcp", &srv.addr, Some(Arc::new(cfg)))
        .err()
        .unwrap()
        .to_string();
    assert!(text.ends_with("is after 2001-01-01T00:00:00Z"), "{text}");
    srv.finish();
    // A nil RootCAs verifies against the system roots, which do not contain
    // this test CA, so Go's unknown authority error follows.
    let srv = Server::start(server_config(&["ecdsa"]), |c| {
        let _ = c.handshake();
    });
    let mut cfg = client_config();
    cfg.root_cas = None;
    let text = tls::dial("tcp", &srv.addr, Some(Arc::new(cfg)))
        .err()
        .unwrap()
        .to_string();
    assert!(
        text.ends_with("x509: certificate signed by unknown authority"),
        "{text}"
    );
    srv.finish();
}

#[test]
fn insecure_skip_verify_is_explicit_and_skips_chain_checks_only() {
    let called = Arc::new(Mutex::new(0));
    let c2 = called.clone();
    let mut cfg = client_config();
    cfg.root_cas = Some(pool("other-ca"));
    cfg.insecure_skip_verify = true;
    cfg.verify_peer_certificate = Some(Arc::new(move |raw, chains| {
        assert_eq!(raw.len(), 2);
        assert!(
            chains.is_empty(),
            "no chains are built when verification is skipped"
        );
        *c2.lock().unwrap() += 1;
        Ok(())
    }));
    let (cs, _) = roundtrip(server_config(&["ecdsa"]), cfg);
    assert!(cs.verified_chains.is_empty());
    assert_eq!(*called.lock().unwrap(), 1);
    // Without the flag the same configuration fails.
    let srv = Server::start(server_config(&["ecdsa"]), |c| {
        let _ = c.handshake();
    });
    let mut cfg = client_config();
    cfg.root_cas = Some(pool("other-ca"));
    assert!(tls::dial("tcp", &srv.addr, Some(Arc::new(cfg))).is_err());
    srv.finish();
}

#[test]
fn unsupported_options_fail_loudly() {
    let srv_cfg = server_config(&["ecdsa"]);
    let try_client = |mutate: &dyn Fn(&mut Config)| -> String {
        let srv = Server::start(srv_cfg.clone(), |c| {
            let _ = c.handshake();
        });
        let mut cfg = client_config();
        mutate(&mut cfg);
        // Not Dial: it would fill in an empty ServerName from the address.
        let raw = net::dial("tcp", &srv.addr).expect("dial");
        let conn = tls::client(raw, Arc::new(cfg));
        let e = conn.handshake().expect_err("must fail");
        let _ = conn.close();
        srv.finish();
        e.to_string()
    };
    assert_eq!(
        try_client(&|c| {
            c.min_version = tls::VERSION_TLS10;
            c.max_version = tls::VERSION_TLS11;
        }),
        "tls: no supported versions satisfy MinVersion and MaxVersion"
    );
    assert!(
        try_client(&|c| c.renegotiation = tls::RENEGOTIATE_ONCE_AS_CLIENT)
            .contains("renegotiation is not supported")
    );
    assert!(
        try_client(&|c| c.encrypted_client_hello_config_list = vec![1, 2, 3])
            .contains("Encrypted Client Hello is not supported")
    );
    assert!(try_client(&|c| c.session_ticket_key = [7; 32]).contains("SessionTicketKey"));
    assert!(
        try_client(&|c| c.wrap_session = Some(Arc::new(|_, _| Ok(vec![])))).contains("WrapSession")
    );
    assert_eq!(
        try_client(&|c| c.server_name.clear()),
        "tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config"
    );
    // MinVersion below TLS 1.2 is raised, so TLS 1.2 still works.
    let mut s = server_config(&["ecdsa"]);
    s.max_version = tls::VERSION_TLS12;
    let mut c = client_config();
    c.min_version = tls::VERSION_TLS10;
    c.max_version = tls::VERSION_TLS12;
    let (cs, _) = roundtrip(s, c);
    assert_eq!(cs.version, tls::VERSION_TLS12);
    // A cipher suite list with no usable suite fails with Go's text.
    let mut s = server_config(&["ecdsa"]);
    s.max_version = tls::VERSION_TLS12;
    let srv = Server::start(s, |c| {
        let _ = c.handshake();
    });
    let mut c = client_config();
    c.max_version = tls::VERSION_TLS12;
    c.cipher_suites = vec![
        tls::TLS_RSA_WITH_RC4_128_SHA,
        tls::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    ];
    assert!(tls::dial("tcp", &srv.addr, Some(Arc::new(c))).is_err());
    srv.finish();
}

#[test]
fn non_tls_clients_get_a_record_header_error() {
    let result = Arc::new(Mutex::new(None));
    let r2 = result.clone();
    let srv = Server::start(server_config(&["ecdsa"]), move |c| {
        *r2.lock().unwrap() = Some(c.handshake());
    });
    let mut raw = std::net::TcpStream::connect(&srv.addr).expect("connect");
    raw.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    srv.finish();
    let err = result.lock().unwrap().take().unwrap().unwrap_err();
    match err {
        tls::Error::RecordHeader(h) => {
            assert_eq!(h.msg, "first record does not look like a TLS handshake");
            assert_eq!(&h.record_header, b"GET /");
            assert!(h.conn.is_some());
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn key_log_writer_receives_nss_lines() {
    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl Write for Sink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    for (version, label) in [
        (tls::VERSION_TLS12, "CLIENT_RANDOM "),
        (tls::VERSION_TLS13, "CLIENT_TRAFFIC_SECRET_0 "),
    ] {
        let (cs, ss) = (Sink::default(), Sink::default());
        let mut s = server_config(&["ecdsa"]);
        s.max_version = version;
        s.key_log_writer = Some(Arc::new(Mutex::new(ss.clone())));
        let mut c = client_config();
        c.max_version = version;
        c.key_log_writer = Some(Arc::new(Mutex::new(cs.clone())));
        roundtrip(s, c);
        let (cl, sl) = (
            String::from_utf8(cs.0.lock().unwrap().clone()).unwrap(),
            String::from_utf8(ss.0.lock().unwrap().clone()).unwrap(),
        );
        assert!(cl.contains(label), "{cl}");
        assert!(sl.contains(label), "{sl}");
        // Both sides log the same secrets.
        let line = cl.lines().find(|l| l.starts_with(label)).unwrap();
        assert!(sl.lines().any(|l| l == line), "{line}");
        let fields: Vec<&str> = line.split(' ').collect();
        assert_eq!(fields[1].len(), 64, "client random is 32 bytes of hex");
    }
}

#[test]
fn resumption_and_ticket_policy() {
    for version in [tls::VERSION_TLS12, tls::VERSION_TLS13] {
        let mut s = server_config(&["ecdsa"]);
        s.max_version = version;
        let ln = Arc::new(tls::listen("tcp", "127.0.0.1:0", Arc::new(s)).unwrap());
        let addr = NetListener::addr(&*ln).unwrap().to_string();
        let l2 = ln.clone();
        let server = thread::spawn(move || {
            let mut resumed = Vec::new();
            for _ in 0..3 {
                let c = NetListener::accept(&*l2).unwrap();
                let conn = c.as_any().downcast_ref::<tls::Conn>().unwrap();
                echo(conn);
                resumed.push(conn.connection_state().did_resume);
                let mut b = [0u8; 4];
                let _ = conn.read(&mut b);
                let _ = conn.close();
            }
            resumed
        });
        let mut c = client_config();
        c.max_version = version;
        c.client_session_cache = Some(tls::LruClientSessionCache::new(4));
        let c = Arc::new(c);
        let mut client_side = Vec::new();
        for _ in 0..3 {
            let conn = tls::dial("tcp", &addr, Some(c.clone())).unwrap();
            conn.write(b"x\n").unwrap();
            assert_eq!(read_line(&conn), "echo:x");
            client_side.push(conn.connection_state().did_resume);
            conn.close().unwrap();
        }
        assert_eq!(client_side, vec![false, true, true], "TLS {version:#x}");
        assert_eq!(server.join().unwrap(), vec![false, true, true]);
        let _ = NetListener::close(&*ln);
    }
}

// -------------------------------------------------------------------- QUIC

/// Moves every pending event of `from` to `to`; returns the kinds seen.
fn shuttle(
    from: &tls::QUICConn,
    to: &tls::QUICConn,
    log: &mut Vec<(tls::QUICEventKind, tls::QUICEncryptionLevel)>,
) -> Vec<tls::QUICEvent> {
    let mut all = Vec::new();
    loop {
        let e = from.next_event();
        if e.kind == tls::QUIC_NO_EVENT {
            return all;
        }
        log.push((e.kind, e.level));
        match e.kind {
            tls::QUIC_WRITE_DATA => to.handle_data(e.level, &e.data).expect("handle_data"),
            tls::QUIC_ERROR_EVENT => panic!("{:?}", e.err),
            _ => {}
        }
        all.push(e);
    }
}

#[test]
fn quic_handshake_completes_in_process() {
    let mut s = server_config(&["ecdsa"]);
    s.next_protos = vec!["h3".into()];
    let mut c = client_config();
    c.next_protos = vec!["h3".into()];
    let server = tls::quic_server(tls::QUICConfig {
        tls_config: Some(Arc::new(s)),
        ..tls::QUICConfig::default()
    });
    let client = tls::quic_client(tls::QUICConfig {
        tls_config: Some(Arc::new(c)),
        ..tls::QUICConfig::default()
    });
    server.set_transport_parameters(b"server-params");
    client.set_transport_parameters(b"client-params");
    server.start(&Context::background()).unwrap();
    assert!(
        server.start(&Context::background()).is_err(),
        "Start twice fails"
    );
    client.start(&Context::background()).unwrap();
    let (mut clog, mut slog) = (Vec::new(), Vec::new());
    let (mut cevents, mut sevents) = (Vec::new(), Vec::new());
    for _ in 0..8 {
        cevents.extend(shuttle(&client, &server, &mut clog));
        sevents.extend(shuttle(&server, &client, &mut slog));
    }
    for (name, events, peer_params) in [
        ("client", &cevents, &b"server-params"[..]),
        ("server", &sevents, &b"client-params"[..]),
    ] {
        assert!(
            events.iter().any(|e| e.kind == tls::QUIC_HANDSHAKE_DONE),
            "{name} handshake done"
        );
        let p = events
            .iter()
            .find(|e| e.kind == tls::QUIC_TRANSPORT_PARAMETERS)
            .unwrap_or_else(|| panic!("{name} peer transport parameters"));
        assert_eq!(p.data, peer_params);
        // Read before write at each level; both sets of keys are delivered.
        let secrets: Vec<_> = events
            .iter()
            .filter(|e| {
                matches!(
                    e.kind,
                    tls::QUIC_SET_READ_SECRET | tls::QUIC_SET_WRITE_SECRET
                )
            })
            .collect();
        for level in [
            tls::QUIC_ENCRYPTION_LEVEL_HANDSHAKE,
            tls::QUIC_ENCRYPTION_LEVEL_APPLICATION,
        ] {
            let at: Vec<_> = secrets.iter().filter(|e| e.level == level).collect();
            assert_eq!(at.len(), 2, "{name} secrets at {level}");
            assert!(at.iter().all(|e| e.keys.is_some() && e.suite != 0));
        }
        let first_handshake = events
            .iter()
            .find(|e| {
                e.level == tls::QUIC_ENCRYPTION_LEVEL_HANDSHAKE && e.kind != tls::QUIC_WRITE_DATA
            })
            .unwrap();
        assert_eq!(
            first_handshake.kind,
            tls::QUIC_SET_READ_SECRET,
            "{name}: read secret first"
        );
    }
    // The server reads Application data only after the client's Finished.
    let done_at = sevents
        .iter()
        .position(|e| e.kind == tls::QUIC_HANDSHAKE_DONE)
        .unwrap();
    let app_read = sevents
        .iter()
        .position(|e| {
            e.kind == tls::QUIC_SET_READ_SECRET && e.level == tls::QUIC_ENCRYPTION_LEVEL_APPLICATION
        })
        .unwrap();
    assert!(app_read < done_at);
    for q in [&client, &server] {
        let st = q.connection_state();
        assert!(st.handshake_complete);
        assert_eq!(st.version, tls::VERSION_TLS13);
        assert_eq!(st.negotiated_protocol, "h3");
    }
    assert_eq!(
        client.connection_state().peer_certificates[0].subject_common_name,
        "ecdsa.test"
    );
    assert!(client
        .send_session_ticket(tls::QUICSessionTicketOptions::default())
        .is_err());
    assert!(client.store_session(&tls::SessionState::default()).is_err());
    client.close().unwrap();
    server.close().unwrap();
    assert!(client
        .handle_data(tls::QUIC_ENCRYPTION_LEVEL_INITIAL, b"x")
        .is_err());
}

#[test]
fn quic_requires_parameters_and_checks_levels() {
    let client = tls::quic_client(tls::QUICConfig {
        tls_config: Some(Arc::new(client_config())),
        ..tls::QUICConfig::default()
    });
    client.start(&Context::background()).unwrap();
    let e = client.next_event();
    assert_eq!(e.kind, tls::QUIC_TRANSPORT_PARAMETERS_REQUIRED);
    assert_eq!(client.next_event().kind, tls::QUIC_NO_EVENT);
    client.set_transport_parameters(b"p");
    let first = client.next_event();
    assert_eq!(first.kind, tls::QUIC_WRITE_DATA);
    assert_eq!(first.level, tls::QUIC_ENCRYPTION_LEVEL_INITIAL);
    // Data at the wrong level is an error.
    let err = client
        .handle_data(tls::QUIC_ENCRYPTION_LEVEL_HANDSHAKE, b"junk")
        .unwrap_err();
    assert!(err.to_string().contains("expected Initial"), "{err}");
    // Session events are not available.
    let q = tls::quic_client(tls::QUICConfig {
        tls_config: Some(Arc::new(client_config())),
        enable_session_events: true,
        ..tls::QUICConfig::default()
    });
    assert!(q.start(&Context::background()).is_err());
}
