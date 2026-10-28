//! Rust side of the crypto/tls differential (tools/gotls_check.py); mirrors
//! tools/gotls_oracle.go: `certs` is Go-only, the other modes are
//!
//!   gotls_probe tables
//!   gotls_probe session                      (hex SessionState lines on stdin)
//!   gotls_probe server DIR k=v...
//!   gotls_probe client DIR ADDR k=v...
use rust_stdlib::net;
use rust_stdlib_tls::tls::{self, Certificate, Config, ConnectionState};
use std::collections::BTreeMap;
use std::io::{BufRead, Read, Write};
use std::sync::Arc;

type Opts = BTreeMap<String, String>;

fn parse_opts(args: &[String]) -> Opts {
    args.iter()
        .map(|a| match a.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (a.clone(), String::new()),
        })
        .collect()
}

fn opt<'a>(o: &'a Opts, k: &str) -> &'a str {
    o.get(k).map(String::as_str).unwrap_or("")
}

fn ids(s: &str) -> Vec<u16> {
    s.split(',')
        .filter(|x| !x.is_empty())
        .map(|x| match x.strip_prefix("0x") {
            Some(h) => u16::from_str_radix(h, 16).expect("hex id"),
            None => x.parse().expect("decimal id"),
        })
        .collect()
}

fn version(s: &str) -> u16 {
    match s {
        "1.2" => tls::VERSION_TLS12,
        "1.3" => tls::VERSION_TLS13,
        _ => 0,
    }
}

fn load_pool(dir: &str, name: &str) -> tls::x509::CertPool {
    let mut pool = tls::x509::CertPool::new();
    let pem = std::fs::read(format!("{dir}/{name}.pem")).expect("read CA");
    assert!(pool.append_certs_from_pem(&pem), "bad CA {name}");
    pool
}

fn load_pair(dir: &str, name: &str) -> Certificate {
    tls::load_x509_key_pair(
        &format!("{dir}/{name}.pem"),
        &format!("{dir}/{name}-key.pem"),
    )
    .unwrap_or_else(|e| panic!("load {name}: {e}"))
}

fn base_config(o: &Opts) -> Config {
    let mut c = Config::new();
    c.min_version = version(opt(o, "min"));
    c.max_version = version(opt(o, "max"));
    c.cipher_suites = ids(opt(o, "suites"));
    // Go ignores TLS 1.3 suite configuration; this knob is a Rust extension.
    c.tls13_cipher_suites = ids(opt(o, "suites13"));
    c.next_protos = opt(o, "alpn")
        .split(',')
        .filter(|x| !x.is_empty())
        .map(str::to_string)
        .collect();
    c.curve_preferences = ids(opt(o, "curves"))
        .into_iter()
        .map(tls::CurveID)
        .collect();
    c
}

fn json_str(s: &str) -> String {
    let mut out = String::from("\"");
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Go's encoding/json escapes these for HTML safety.
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn ekm(st: &ConnectionState, ctx: Option<&[u8]>) -> String {
    match st.export_keying_material("EXPERIMENT gotls", ctx, 32) {
        Ok(b) => hex(&b),
        Err(e) => format!("err:{e}"),
    }
}

/// One JSON object per line, keys sorted like Go's encoding/json of a map.
fn emit(fields: BTreeMap<&str, String>) {
    let body: Vec<String> = fields
        .iter()
        .map(|(k, v)| format!("{}:{}", json_str(k), v))
        .collect();
    println!("{{{}}}", body.join(","));
    let _ = std::io::stdout().flush();
}

fn report(
    st: &ConnectionState,
    extra: &[(&'static str, String)],
) -> BTreeMap<&'static str, String> {
    let mut r = BTreeMap::new();
    r.insert("version", json_str(&tls::version_name(st.version)));
    r.insert("cipher", json_str(&tls::cipher_suite_name(st.cipher_suite)));
    r.insert("curve", json_str(&st.curve_id.to_string()));
    r.insert("alpn", json_str(&st.negotiated_protocol));
    r.insert("sni", json_str(&st.server_name));
    r.insert("resumed", st.did_resume.to_string());
    r.insert("hrr", st.hello_retry_request.to_string());
    r.insert("complete", st.handshake_complete.to_string());
    r.insert("peers", st.peer_certificates.len().to_string());
    if let Some(c) = st.peer_certificates.first() {
        r.insert("peer_cn", json_str(&c.subject_common_name));
    }
    let chains: Vec<String> = st
        .verified_chains
        .iter()
        .map(|ch| {
            let names: Vec<String> = ch
                .iter()
                .map(|c| json_str(&c.subject_common_name))
                .collect();
            format!("[{}]", names.join(","))
        })
        .collect();
    r.insert(
        "chains",
        if chains.is_empty() {
            "null".to_string()
        } else {
            format!("[{}]", chains.join(","))
        },
    );
    r.insert("ekm", json_str(&ekm(st, None)));
    r.insert("ekm_ctx", json_str(&ekm(st, Some(b"ctx"))));
    r.insert("ekm_empty", json_str(&ekm(st, Some(b""))));
    for (k, v) in extra {
        r.insert(k, json_str(v));
    }
    r
}

fn tables() {
    let list = |kind: &str, l: Vec<tls::CipherSuite>| {
        for c in l {
            let v: Vec<String> = c.supported_versions.iter().map(u16::to_string).collect();
            println!(
                "{kind} {:04x} {} [{}] {}",
                c.id,
                c.name,
                v.join(" "),
                c.insecure
            );
        }
    };
    list("secure", tls::cipher_suites());
    list("insecure", tls::insecure_cipher_suites());
    for i in 0..=65535u32 {
        let i = i as u16;
        println!(
            "n {i:04x} {}|{}|{}|{}",
            tls::cipher_suite_name(i),
            tls::version_name(i),
            tls::CurveID(i),
            tls::SignatureScheme(i)
        );
    }
    for i in -3..9 {
        println!("auth {i} {}", tls::ClientAuthType(i));
    }
    println!(
        "alert {}|{}|{}|{}",
        tls::AlertError(42).error(),
        tls::AlertError(0).error(),
        tls::AlertError(121).error(),
        tls::AlertError(200).error()
    );
    let verr = tls::CertificateVerificationError {
        unverified_certificates: vec![],
        err: Arc::new(tls::Error::new("boom")),
    };
    let rh = tls::RecordHeaderError {
        msg: "bad".into(),
        record_header: [0; 5],
        conn: None,
    };
    println!(
        "errors {}|{}|{}",
        verr.error(),
        rh.error(),
        tls::ECHRejectionError::default().error()
    );
    for i in 0..5 {
        println!("quic {i} {}", tls::QUICEncryptionLevel(i));
    }
}

fn session() {
    for line in std::io::stdin().lock().lines() {
        let line = line.expect("stdin");
        let Some(raw) = rust_stdlib::encoding::hex::decode(line.trim()).ok() else {
            println!("badhex");
            continue;
        };
        match tls::parse_session_state(&raw) {
            Err(e) => println!("err {e}"),
            Ok(ss) => match ss.bytes() {
                Err(e) => println!("encerr {e}"),
                Ok(b) => {
                    let extra: Vec<String> = ss.extra.iter().map(|e| hex(e)).collect();
                    println!("ok {} {} {}", hex(&b), ss.early_data, extra.join(","));
                }
            },
        }
    }
}

fn server_main(dir: &str, o: &Opts) {
    let mut cfg = base_config(o);
    for name in opt(o, "certs").split(',').filter(|x| !x.is_empty()) {
        cfg.certificates.push(load_pair(dir, name));
    }
    if opt(o, "getcert") == "1" {
        let all: BTreeMap<&str, Arc<Certificate>> = ["ecdsa", "rsa", "ed25519"]
            .into_iter()
            .map(|n| (n, Arc::new(load_pair(dir, n))))
            .collect();
        cfg.certificates.clear();
        cfg.get_certificate = Some(Arc::new(move |h| {
            let pick = match h.server_name.as_str() {
                "rsa.test" => "rsa",
                "ed25519.test" => "ed25519",
                _ => "ecdsa",
            };
            Ok(Some(all[pick].clone()))
        }));
    }
    cfg.client_auth = match opt(o, "clientauth") {
        "RequestClientCert" => tls::REQUEST_CLIENT_CERT,
        "RequireAnyClientCert" => tls::REQUIRE_ANY_CLIENT_CERT,
        "VerifyClientCertIfGiven" => tls::VERIFY_CLIENT_CERT_IF_GIVEN,
        "RequireAndVerifyClientCert" => tls::REQUIRE_AND_VERIFY_CLIENT_CERT,
        _ => tls::NO_CLIENT_CERT,
    };
    // clientcas=system leaves ClientCAs nil: the system roots verify clients.
    if cfg.client_auth >= tls::VERIFY_CLIENT_CERT_IF_GIVEN && opt(o, "clientcas") != "system" {
        cfg.client_cas = Some(load_pool(dir, "ca"));
    }
    cfg.session_tickets_disabled = opt(o, "tickets") == "0";
    let ln = tls::listen("tcp", "127.0.0.1:0", Arc::new(cfg)).expect("listen");
    println!("listening {}", net::Listener::addr(&ln).expect("addr"));
    let _ = std::io::stdout().flush();
    std::thread::spawn(|| {
        let mut b = [0u8; 1];
        let _ = std::io::stdin().read(&mut b);
        std::process::exit(0);
    });
    loop {
        let Ok(c) = net::Listener::accept(&ln) else {
            return;
        };
        std::thread::spawn(move || {
            let conn = c
                .as_any()
                .downcast_ref::<tls::Conn>()
                .expect("a tls connection");
            if let Err(e) = conn.handshake() {
                emit(BTreeMap::from([
                    ("role", json_str("server")),
                    ("error", json_str(&e.to_string())),
                ]));
                let _ = conn.close();
                return;
            }
            let mut line = Vec::new();
            let mut b = [0u8; 1];
            loop {
                match conn.read(&mut b) {
                    Ok(1) => {
                        line.push(b[0]);
                        if b[0] == b'\n' {
                            break;
                        }
                    }
                    Ok(_) => break,
                    Err(e) => {
                        emit(BTreeMap::from([
                            ("role", json_str("server")),
                            ("error", json_str(&e.to_string())),
                            ("stage", json_str("read")),
                        ]));
                        let _ = conn.close();
                        return;
                    }
                }
            }
            let mut reply = b"echo:".to_vec();
            reply.extend_from_slice(&line);
            let _ = conn.write(&reply);
            emit(report(
                &conn.connection_state(),
                &[("role", "server".into())],
            ));
            let mut buf = [0u8; 16];
            let _ = conn.read(&mut buf);
            let _ = conn.close();
        });
    }
}

fn client_main(dir: &str, addr: &str, o: &Opts) {
    let mut cfg = base_config(o);
    cfg.server_name = if opt(o, "sni").is_empty() {
        "localhost".into()
    } else {
        opt(o, "sni").into()
    };
    cfg.root_cas = match opt(o, "roots") {
        // roots=system leaves RootCAs nil: the system roots verify the server.
        "system" => None,
        "other" => Some(load_pool(dir, "other-ca")),
        _ => Some(load_pool(dir, "ca")),
    };
    cfg.insecure_skip_verify = opt(o, "skipverify") == "1";
    let cc = opt(o, "clientcert");
    if !cc.is_empty() && cc != "none" {
        let pair = Arc::new(load_pair(dir, &format!("client-{cc}")));
        cfg.certificates = vec![(*pair).clone()];
        if opt(o, "forcecert") == "1" {
            // Send the certificate even when the server's CA list excludes it.
            cfg.get_client_certificate = Some(Arc::new(move |_| Ok(pair.clone())));
        }
    }
    if !opt(o, "now").is_empty() {
        let t =
            rust_stdlib::time::Time::parse(rust_stdlib::time::RFC3339, opt(o, "now")).expect("now");
        cfg.time = Some(Arc::new(move || t.clone()));
    }
    if opt(o, "sessions") == "1" {
        cfg.client_session_cache = Some(tls::LruClientSessionCache::new(8));
    }
    let conns: usize = opt(o, "conns").parse().unwrap_or(1);
    let cfg = Arc::new(cfg);
    for _ in 0..conns {
        let raw = net::dial("tcp", addr).expect("dial");
        let c = tls::client(raw, cfg.clone());
        let mut stage = "handshake";
        let mut result: Result<String, tls::Error> = c.handshake().map(|_| String::new());
        if result.is_ok() {
            stage = "write";
            result = c.write(b"hello\n").map(|_| String::new());
        }
        if result.is_ok() {
            stage = "read";
            let mut line = Vec::new();
            let mut b = [0u8; 1];
            result = loop {
                match c.read(&mut b) {
                    Ok(1) => {
                        line.push(b[0]);
                        if b[0] == b'\n' {
                            break Ok(String::from_utf8_lossy(&line).trim().to_string());
                        }
                    }
                    Ok(_) => break Err(tls::Error::new("EOF")),
                    Err(e) => break Err(e),
                }
            };
        }
        match result {
            Err(e) => emit(BTreeMap::from([
                ("role", json_str("client")),
                ("error", json_str(&e.to_string())),
                ("stage", json_str(stage)),
            ])),
            Ok(echo) => emit(report(
                &c.connection_state(),
                &[("role", "client".into()), ("echo", echo)],
            )),
        }
        let _ = c.close();
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("tables") => tables(),
        Some("session") => session(),
        Some("server") => server_main(&args[1], &parse_opts(&args[2..])),
        Some("client") => client_main(&args[1], &args[2], &parse_opts(&args[3..])),
        _ => {
            eprintln!("usage: gotls_probe tables|session|server|client");
            std::process::exit(2);
        }
    }
}
