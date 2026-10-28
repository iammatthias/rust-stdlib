//! HTTPS through the Go-shaped `net/http` API: `Server::serve_tls`,
//! `Transport.tls_client_config`, `Request.tls` and `Response.tls`.
use rust_stdlib::{
    encoding::hex,
    net::{
        self,
        http::{self, client::Client, handler_func, server::Server, Transport},
    },
};
use rust_stdlib_tls::tls::{x509, Certificate, Config, PrivateKey};
use std::{sync::Arc, thread};

fn server_config(cert: Vec<u8>, key: Vec<u8>) -> Config {
    let mut config = Config::new();
    config.certificates = vec![Certificate {
        certificate: vec![cert],
        private_key: Some(PrivateKey::Pkcs8(key)),
        ..Certificate::default()
    }];
    config
}

fn client_config(roots: impl IntoIterator<Item = Vec<u8>>) -> Config {
    let mut pool = x509::CertPool::new();
    for root in roots {
        pool.add_cert(x509::parse_certificate(&root).unwrap());
    }
    let mut config = Config::new();
    config.root_cas = Some(pool);
    config
}

fn bytes(s: &str) -> Vec<u8> {
    hex::decode(s.trim()).unwrap()
}
fn ca() -> Vec<u8> {
    bytes(include_str!("fixtures/ca.hex"))
}

struct Tls {
    server: Server,
    addr: String,
    t: Option<thread::JoinHandle<()>>,
}
impl Drop for Tls {
    fn drop(&mut self) {
        let _ = self.server.close();
        if let Some(t) = self.t.take() {
            let _ = t.join();
        }
    }
}

fn start(cert: &str, key: &str) -> Tls {
    let server = Server {
        handler: Some(handler_func(|w, r| {
            let st = r.tls.clone();
            let _ = w.write_string(&format!(
                "path={} tls={} version={:#x} sni={}",
                r.url.path,
                st.is_some(),
                st.as_ref().map_or(0, |s| s.version),
                st.as_ref().map_or(String::new(), |s| s.server_name.clone()),
            ));
        })),
        error_log: Some(Arc::new(rust_stdlib::log::Logger::new(
            std::io::sink(),
            "",
            0,
        ))),
        tls_config: Some(Arc::new(server_config(bytes(cert), bytes(key)))),
        ..Server::default()
    };
    let ln = net::listen("tcp", "127.0.0.1:0").unwrap();
    let addr = ln.addr().unwrap().to_string();
    let s2 = server.clone();
    let t = thread::spawn(move || {
        let _ = s2.serve_tls(ln, "", "");
    });
    Tls {
        server,
        addr,
        t: Some(t),
    }
}

fn client(roots: Vec<Vec<u8>>) -> Client {
    let t = Transport {
        tls_client_config: Some(Arc::new(client_config(roots))),
        ..Transport::default()
    };
    Client {
        transport: Some(Arc::new(t)),
        ..Client::default()
    }
}

#[test]
fn https_round_trips_with_connection_state() {
    let srv = start(
        include_str!("fixtures/server.hex"),
        include_str!("fixtures/server-key.hex"),
    );
    let c = client(vec![ca()]);
    let url = format!(
        "https://localhost:{}/hello",
        srv.addr.rsplit(':').next().unwrap()
    );
    let resp = c.get(&url).unwrap();
    assert_eq!(resp.status_code, 200);
    let st = resp.tls.clone().expect("Response.TLS");
    assert!(st.handshake_complete);
    assert!(st.version == 0x0303 || st.version == 0x0304);
    let body = String::from_utf8(resp.body.unwrap().read_all().unwrap()).unwrap();
    assert!(
        body.starts_with("path=/hello tls=true version=0x30"),
        "{body}"
    );
    assert!(body.ends_with("sni=localhost"), "{body}");
    // The connection is pooled and reused over TLS.
    assert_eq!(c.get(&url).unwrap().status_code, 200);
}

#[test]
fn untrusted_certificate_is_rejected() {
    let srv = start(
        include_str!("fixtures/server.hex"),
        include_str!("fixtures/server-key.hex"),
    );
    let c = client(vec![bytes(include_str!("fixtures/wrong-host.hex"))]);
    let url = format!(
        "https://localhost:{}/",
        srv.addr.rsplit(':').next().unwrap()
    );
    assert!(c.get(&url).is_err());
}

#[test]
fn httptest_tls_server_trusts_its_certificate() {
    let s = rust_stdlib_tls::httptest::tls_server(handler_func(|w, r| {
        let _ = w.write_string(&format!("tls={}", r.tls.is_some()));
    }))
    .unwrap();
    assert!(s.url.starts_with("https://127.0.0.1:"));
    assert!(s.certificate().is_some());
    let resp = s.client().get(&format!("{}/x", s.url)).unwrap();
    assert!(resp.tls.is_some());
    assert_eq!(resp.body.unwrap().read_all().unwrap(), b"tls=true");
    // A client trusting another root rejects the test certificate.
    assert!(client(vec![ca()]).get(&format!("{}/x", s.url)).is_err());
}

#[test]
fn https_through_a_connect_proxy() {
    use std::io::{Read, Write};
    let srv = start(
        include_str!("fixtures/server.hex"),
        include_str!("fixtures/server-key.hex"),
    );
    let origin = srv.addr.clone();
    let ln = net::listen("tcp", "127.0.0.1:0").unwrap();
    let proxy_addr = ln.addr().unwrap().to_string();
    let seen = Arc::new(std::sync::Mutex::new(String::new()));
    let seen2 = seen.clone();
    let proxy = thread::spawn(move || {
        let conn = ln.accept().unwrap();
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if conn.read(&mut b).unwrap() == 0 {
                return;
            }
            head.push(b[0]);
        }
        *seen2.lock().unwrap() = String::from_utf8_lossy(&head).into_owned();
        let up = std::net::TcpStream::connect(&origin).unwrap();
        conn.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .unwrap();
        let conn = Arc::new(conn);
        let (mut up_r, mut up_w) = (up.try_clone().unwrap(), up);
        let c2 = conn.clone();
        let t = thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = c2.read(&mut buf) {
                if n == 0 || up_w.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            let _ = up_w.shutdown(std::net::Shutdown::Write);
        });
        let mut buf = [0u8; 4096];
        while let Ok(n) = up_r.read(&mut buf) {
            if n == 0 || conn.write(&buf[..n]).is_err() {
                break;
            }
        }
        let _ = conn.close();
        let _ = t.join();
    });
    let t = Transport {
        tls_client_config: Some(Arc::new(client_config(vec![ca()]))),
        proxy: Some(http::proxy_url(
            net::url::parse(&format!("http://user:pw@{proxy_addr}")).unwrap(),
        )),
        ..Transport::default()
    };
    let c = Client {
        transport: Some(Arc::new(t)),
        ..Client::default()
    };
    let port = srv.addr.rsplit(':').next().unwrap();
    let resp = c
        .get(&format!("https://localhost:{port}/via-proxy"))
        .unwrap();
    let body = String::from_utf8(resp.body.unwrap().read_all().unwrap()).unwrap();
    assert!(body.starts_with("path=/via-proxy tls=true"), "{body}");
    let head = seen.lock().unwrap().clone();
    assert!(
        head.starts_with(&format!(
            "CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n"
        )),
        "{head:?}"
    );
    assert!(
        head.contains("Proxy-Authorization: Basic dXNlcjpwdw==\r\n"),
        "{head:?}"
    );
    drop(c);
    drop(proxy);
}

#[test]
fn https_without_a_backend_is_an_explicit_error() {
    let c = Client {
        transport: Some(Arc::new(Transport::default())),
        ..Client::default()
    };
    let err = c.get("https://127.0.0.1:1/").unwrap_err().to_string();
    assert!(err.contains("dial") || err.contains("TLS backend"), "{err}");
    let _ = http::STATUS_OK;
}

#[test]
fn httptest_tls_server_enable_http2_speaks_h2() {
    let mut s = rust_stdlib::net::http::httptest::Server::unstarted(handler_func(|w, r| {
        let _ = w.write_string(&format!("proto={}", r.proto));
    }))
    .unwrap();
    s.enable_http2 = true;
    rust_stdlib_tls::httptest::start_tls(&mut s).unwrap();
    let resp = s.client().get(&format!("{}/x", s.url)).unwrap();
    assert_eq!(resp.proto, "HTTP/2.0");
    assert_eq!(resp.body.unwrap().read_all().unwrap(), b"proto=HTTP/2.0");
    // Without EnableHTTP2 the test server stays on HTTP/1.1.
    let s2 = rust_stdlib_tls::httptest::tls_server(handler_func(|w, r| {
        let _ = w.write_string(&format!("proto={}", r.proto));
    }))
    .unwrap();
    let resp = s2.client().get(&format!("{}/x", s2.url)).unwrap();
    assert_eq!(resp.proto, "HTTP/1.1");
}
