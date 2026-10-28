#![cfg(feature = "net")]
//! Ports of Go's `net/smtp` `smtp_test.go` auth tables and client scripts,
//! run against a scripted server on a loopback socket.
use rust_stdlib::net::http::TlsConfig;
use rust_stdlib::net::smtp::{self, Auth, ServerInfo};
use rust_stdlib::net::{Conn, Listener};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Stands in for crypto/hmac: the root crate has no cryptography.
fn fake_hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    assert_eq!(key, b"pass");
    assert_eq!(msg, b"<123456.1322876914@testserver>");
    (0..16)
        .map(|i| {
            u8::from_str_radix(&"287eb355114cf5c471c26a875f1ca4ae"[2 * i..2 * i + 2], 16).unwrap()
        })
        .collect()
}

#[test]
fn auth_table() {
    let info = ServerInfo {
        name: "testserver".into(),
        tls: true,
        auth: vec![],
    };
    let mut plain = smtp::plain_auth("", "user", "pass", "testserver");
    assert_eq!(
        plain.start(&info).unwrap(),
        ("PLAIN".into(), b"\0user\0pass".to_vec())
    );
    let mut plain = smtp::plain_auth("foo", "bar", "baz", "testserver");
    assert_eq!(
        plain.start(&info).unwrap(),
        ("PLAIN".into(), b"foo\0bar\0baz".to_vec())
    );
    let mut cram = smtp::cram_md5_auth("user", "pass", fake_hmac);
    assert_eq!(cram.start(&info).unwrap(), ("CRAM-MD5".into(), vec![]));
    assert_eq!(
        cram.next(b"<123456.1322876914@testserver>", true).unwrap(),
        Some(b"user 287eb355114cf5c471c26a875f1ca4ae".to_vec())
    );
    assert_eq!(cram.next(b"", false).unwrap(), None);
}

#[test]
fn auth_plain_conditions() {
    let cases = [
        ("servername", "servername", true, None),
        ("localhost", "localhost", false, None),
        ("127.0.0.1", "127.0.0.1", false, None),
        ("::1", "::1", false, None),
        (
            "servername",
            "servername",
            false,
            Some("unencrypted connection"),
        ),
        ("servername", "attacker", true, Some("wrong host name")),
    ];
    for (auth_name, server, tls, err) in cases {
        let mut a = smtp::plain_auth("", "user", "pass", auth_name);
        let info = ServerInfo {
            name: server.into(),
            tls,
            auth: vec![],
        };
        match (a.start(&info), err) {
            (Ok(_), None) => {}
            (Err(e), Some(want)) => assert_eq!(e.to_string(), want),
            (got, want) => panic!("{auth_name}/{server}: got {got:?}, want {want:?}"),
        }
    }
    let mut a = smtp::plain_auth("", "u", "p", "h");
    assert_eq!(
        a.next(b"x", true).unwrap_err().to_string(),
        "unexpected server challenge"
    );
}

/// Serves `script` (reply, then expected-prefix of the next client chunk)
/// and returns what the client sent.
fn serve(replies: &'static [&'static str]) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(conn.try_clone().unwrap());
        let mut sent = String::new();
        let mut data_mode = false;
        for reply in replies {
            conn.write_all(reply.as_bytes()).unwrap();
            if reply.starts_with("221") {
                break;
            }
            if reply.starts_with("354") {
                data_mode = true;
            }
            let mut line = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line).unwrap() == 0 {
                    return sent;
                }
                sent.push_str(&line);
                if !data_mode || line == ".\r\n" {
                    break;
                }
            }
            data_mode = false;
        }
        let mut rest = String::new();
        let _ = reader.read_to_string(&mut rest);
        sent.push_str(&rest);
        sent
    });
    (addr, handle)
}

#[test]
fn send_mail_transcript() {
    let (addr, server) = serve(&[
        "220 hello world\r\n",
        "250-mail.example.com\r\n250-8BITMIME\r\n250 SMTPUTF8\r\n",
        "250 ok\r\n",
        "250 ok\r\n",
        "354 go\r\n",
        "250 queued\r\n",
        "221 bye\r\n",
    ]);
    smtp::send_mail(
        &addr,
        None,
        "a@example.com",
        &["b@example.com"],
        b"Subject: x\r\n\r\n.dot\r\nbody\r\n",
        None,
    )
    .unwrap();
    assert_eq!(
        server.join().unwrap(),
        "EHLO localhost\r\nMAIL FROM:<a@example.com> BODY=8BITMIME SMTPUTF8\r\nRCPT TO:<b@example.com>\r\nDATA\r\n\
         Subject: x\r\n\r\n..dot\r\nbody\r\n.\r\nQUIT\r\n"
    );
}

#[test]
fn hello_fallback_and_errors() {
    let (addr, server) = serve(&[
        "220 hi\r\n",
        "500 no ehlo\r\n",
        "250 helo ok\r\n",
        "550 who?\r\n",
        "221 bye\r\n",
    ]);
    let mut c = smtp::dial(&addr).unwrap();
    c.hello("client.example").unwrap();
    assert_eq!(c.extension("8BITMIME"), (false, String::new()));
    let err = c.hello("again").unwrap_err();
    assert_eq!(err.to_string(), "smtp: Hello called after other methods");
    let err = c.verify("bad\nline").unwrap_err();
    assert_eq!(err.to_string(), "smtp: A line must not contain CR or LF");
    let err = c.verify("who").unwrap_err();
    assert_eq!(err.to_string(), "550 \"who?\"");
    c.quit().unwrap();
    assert_eq!(
        server.join().unwrap(),
        "EHLO client.example\r\nHELO client.example\r\nVRFY who\r\nQUIT\r\n"
    );
}

#[test]
fn auth_flow_and_failure() {
    let (addr, server) = serve(&[
        "220 hi\r\n",
        "250-x\r\n250 AUTH PLAIN\r\n",
        "334 UGFzc3dvcmQ6\r\n",
        "235 ok\r\n",
        "221 bye\r\n",
    ]);
    struct Login(u8);
    impl Auth for Login {
        fn start(&mut self, _: &ServerInfo) -> Result<(String, Vec<u8>), smtp::AuthError> {
            Ok(("LOGIN".into(), vec![]))
        }
        fn next(&mut self, from: &[u8], more: bool) -> Result<Option<Vec<u8>>, smtp::AuthError> {
            self.0 += 1;
            if more {
                assert_eq!(from, b"Password:");
                Ok(Some(b"secret".to_vec()))
            } else {
                Ok(None)
            }
        }
    }
    let mut c = smtp::dial(&addr).unwrap();
    let mut a = Login(0);
    c.auth(&mut a).unwrap();
    assert_eq!(a.0, 2);
    // A failing Start quits.
    struct Fail;
    impl Auth for Fail {
        fn start(&mut self, _: &ServerInfo) -> Result<(String, Vec<u8>), smtp::AuthError> {
            Err("nope".into())
        }
        fn next(&mut self, _: &[u8], _: bool) -> Result<Option<Vec<u8>>, smtp::AuthError> {
            Ok(None)
        }
    }
    assert_eq!(c.auth(&mut Fail).unwrap_err().to_string(), "nope");
    let sent = server.join().unwrap();
    assert!(
        sent.starts_with("EHLO localhost\r\nAUTH LOGIN\r\nc2VjcmV0\r\n"),
        "{sent:?}"
    );
    assert!(sent.ends_with("QUIT\r\n"), "{sent:?}");
}

/// A TLS hook that wraps a connection in one that reports a TLS state.
struct MarkTls {
    names: Arc<Mutex<Vec<String>>>,
}

struct TlsWrapped(Box<dyn Conn>);

impl Conn for TlsWrapped {
    fn read(&self, b: &mut [u8]) -> Result<usize, rust_stdlib::net::NetError> {
        self.0.read(b)
    }
    fn write(&self, b: &[u8]) -> Result<usize, rust_stdlib::net::NetError> {
        self.0.write(b)
    }
    fn close(&self) -> Result<(), rust_stdlib::net::NetError> {
        self.0.close()
    }
    fn local_addr(&self) -> Option<rust_stdlib::net::AddrRef> {
        self.0.local_addr()
    }
    fn remote_addr(&self) -> Option<rust_stdlib::net::AddrRef> {
        self.0.remote_addr()
    }
    fn set_deadline(&self, t: &rust_stdlib::time::Time) -> Result<(), rust_stdlib::net::NetError> {
        self.0.set_deadline(t)
    }
    fn set_read_deadline(
        &self,
        t: &rust_stdlib::time::Time,
    ) -> Result<(), rust_stdlib::net::NetError> {
        self.0.set_read_deadline(t)
    }
    fn set_write_deadline(
        &self,
        t: &rust_stdlib::time::Time,
    ) -> Result<(), rust_stdlib::net::NetError> {
        self.0.set_write_deadline(t)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn tls_connection_state(&self) -> Option<rust_stdlib::net::TlsConnectionState> {
        Some(rust_stdlib::net::TlsConnectionState {
            version: 0x0304,
            handshake_complete: true,
            ..Default::default()
        })
    }
}

impl TlsConfig for MarkTls {
    fn server_listener(
        &self,
        _: Box<dyn Listener>,
        _: &str,
        _: &str,
        _: &[String],
    ) -> Result<Box<dyn Listener>, BoxError> {
        Err("unused".into())
    }
    fn client_conn(
        &self,
        conn: Box<dyn Conn>,
        server_name: &str,
        _: &[String],
    ) -> Result<Box<dyn Conn>, BoxError> {
        self.names.lock().unwrap().push(server_name.to_owned());
        Ok(Box::new(TlsWrapped(conn)))
    }
}

#[test]
fn start_tls_through_the_hook() {
    let (addr, server) = serve(&[
        "220 hi\r\n",
        "250-mail\r\n250 STARTTLS\r\n",
        "220 ready\r\n",
        "250-mail\r\n250 AUTH PLAIN\r\n",
        "221 bye\r\n",
    ]);
    let mut c = smtp::dial(&addr).unwrap();
    assert!(c.tls_connection_state().is_none());
    let names = Arc::new(Mutex::new(Vec::new()));
    c.start_tls(&MarkTls {
        names: names.clone(),
    })
    .unwrap();
    assert_eq!(names.lock().unwrap().as_slice(), ["127.0.0.1"]);
    assert_eq!(c.tls_connection_state().unwrap().version, 0x0304);
    assert_eq!(c.extension("auth"), (true, "PLAIN".into()));
    c.quit().unwrap();
    assert_eq!(
        server.join().unwrap(),
        "EHLO localhost\r\nSTARTTLS\r\nEHLO localhost\r\nQUIT\r\n"
    );
}

#[test]
fn send_mail_refuses_to_skip_advertised_starttls() {
    let (addr, server) = serve(&["220 hi\r\n", "250-mail\r\n250 STARTTLS\r\n"]);
    let err = smtp::send_mail(&addr, None, "a@x", &["b@x"], b"m", None).unwrap_err();
    assert!(err.to_string().contains("STARTTLS"), "{err}");
    assert_eq!(server.join().unwrap(), "EHLO localhost\r\n");
}

#[test]
fn send_mail_validates_lines_before_dialing() {
    let err = smtp::send_mail("127.0.0.1:1", None, "a\r@x", &[], b"", None).unwrap_err();
    assert_eq!(err.to_string(), "smtp: A line must not contain CR or LF");
    let err = smtp::send_mail("127.0.0.1:1", None, "a@x", &["b\n"], b"", None).unwrap_err();
    assert_eq!(err.to_string(), "smtp: A line must not contain CR or LF");
}
