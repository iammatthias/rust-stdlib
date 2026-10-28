//! Line protocol used by `tools/smtp_check.py` for Go differential checks.
//! See `tools/smtp_oracle.go` for the request and response formats.
use rust_stdlib::net::http::TlsConfig;
use rust_stdlib::net::smtp::{self, Auth, AuthError, Client, ServerInfo};
use rust_stdlib::net::{Conn, Listener};
use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::sync::Mutex;

type MacTable = HashMap<(Vec<u8>, Vec<u8>), Vec<u8>>;

static MACS: Mutex<Option<MacTable>> = Mutex::new(None);

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn unhex_string(s: &str) -> String {
    String::from_utf8_lossy(&unhex(s)).into_owned()
}

/// Answers HMAC-MD5 from the table in the request; the probe has no crypto.
fn hmac_md5(key: &[u8], message: &[u8]) -> Vec<u8> {
    MACS.lock()
        .unwrap()
        .as_ref()
        .and_then(|t| t.get(&(key.to_vec(), message.to_vec())).cloned())
        .unwrap_or_else(|| b"MISSING-MAC-ENTRY".to_vec())
}

/// A TLS hook with no TLS: STARTTLS only reaches it when the server agrees,
/// which the scripts never do.
struct NoTls;

impl TlsConfig for NoTls {
    fn server_listener(
        &self,
        _: Box<dyn Listener>,
        _: &str,
        _: &str,
        _: &[String],
    ) -> Result<Box<dyn Listener>, Box<dyn std::error::Error + Send + Sync>> {
        Err("no tls".into())
    }
    fn client_conn(
        &self,
        _: Box<dyn Conn>,
        _: &str,
        _: &[String],
    ) -> Result<Box<dyn Conn>, Box<dyn std::error::Error + Send + Sync>> {
        Err("no tls".into())
    }
}

struct ScriptAuth {
    proto: String,
    initial: String,
    next: Vec<String>,
    failed: bool,
    i: usize,
}

impl Auth for ScriptAuth {
    fn start(&mut self, _: &ServerInfo) -> Result<(String, Vec<u8>), AuthError> {
        if self.failed {
            return Err("scripted start failure".into());
        }
        Ok((self.proto.clone(), self.initial.clone().into_bytes()))
    }

    fn next(&mut self, _: &[u8], more: bool) -> Result<Option<Vec<u8>>, AuthError> {
        if !more || self.i >= self.next.len() {
            return Ok(None);
        }
        let n = self.next[self.i].clone();
        self.i += 1;
        match n.as_str() {
            "nil" => Ok(None),
            "err" => Err("scripted next failure".into()),
            "empty" => Ok(Some(Vec::new())),
            _ => Ok(Some(unhex(&n))),
        }
    }
}

fn parse_auth(f: &[&str]) -> Box<dyn Auth> {
    match f[0] {
        "plain" => {
            let p: Vec<&str> = f[1].split(',').collect();
            Box::new(smtp::plain_auth(
                &unhex_string(p[0]),
                &unhex_string(p[1]),
                &unhex_string(p[2]),
                &unhex_string(p[3]),
            ))
        }
        "cram" => {
            let p: Vec<&str> = f[1].split(',').collect();
            Box::new(smtp::cram_md5_auth(
                &unhex_string(p[0]),
                &unhex_string(p[1]),
                hmac_md5,
            ))
        }
        "startfail" => Box::new(ScriptAuth {
            proto: String::new(),
            initial: String::new(),
            next: Vec::new(),
            failed: true,
            i: 0,
        }),
        "script" => {
            let p: Vec<&str> = f[1].split(',').collect();
            Box::new(ScriptAuth {
                proto: unhex_string(p[0]),
                initial: unhex_string(p[1]),
                next: p[2..].iter().map(|s| s.to_string()).collect(),
                failed: false,
                i: 0,
            })
        }
        other => panic!("bad auth {other}"),
    }
}

/// Go's port scrub: `127.0.0.1:<port>` becomes `ADDR`.
fn scrub(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(i) = rest.find("127.0.0.1:") {
        out.push_str(&rest[..i]);
        out.push_str("ADDR");
        let after = &rest[i + "127.0.0.1:".len()..];
        let digits = after.bytes().take_while(u8::is_ascii_digit).count();
        rest = &after[digits..];
    }
    out.push_str(rest);
    out
}

fn err_text(e: impl std::fmt::Display) -> String {
    format!("err {}", scrub(&e.to_string()))
}

fn load_macs(table: &str) {
    let mut map = HashMap::new();
    for entry in table.split(',').filter(|e| !e.is_empty()) {
        let p: Vec<&str> = entry.split(':').collect();
        map.insert((unhex(p[0]), unhex(p[1])), unhex(p[2]));
    }
    *MACS.lock().unwrap() = Some(map);
}

fn run_actions(port: &str, actions: &str) -> String {
    let (actions, macs) = actions.split_once(" @ ").unwrap_or((actions, ""));
    load_macs(macs);
    let mut c: Option<Client> = None;
    let mut results = Vec::new();
    for action in actions.split('|') {
        let f: Vec<&str> = action.split_whitespace().collect();
        if f[0] != "dial" && f[0] != "newclient" && c.is_none() {
            results.push("err no client".to_owned());
            continue;
        }
        let mut detail = String::new();
        let result: Result<(), String> = match f[0] {
            "dial" => match smtp::dial(&format!("127.0.0.1:{port}")) {
                Ok(client) => {
                    c = Some(client);
                    Ok(())
                }
                Err(e) => Err(err_text(e)),
            },
            "newclient" => match rust_stdlib::net::dial("tcp", &format!("127.0.0.1:{port}")) {
                Ok(conn) => match smtp::Client::new(conn, &unhex_string(f[1])) {
                    Ok(client) => {
                        c = Some(client);
                        Ok(())
                    }
                    Err(e) => Err(err_text(e)),
                },
                Err(e) => Err(err_text(e)),
            },
            _ => {
                let client = c.as_mut().unwrap();
                let r = match f[0] {
                    "hello" => client.hello(&unhex_string(f[1])),
                    "ext" => {
                        let (ok, param) = client.extension(&unhex_string(f[1]));
                        detail = format!(" {ok} {param:?}");
                        Ok(())
                    }
                    "auth" => {
                        let mut a = parse_auth(&f[1..]);
                        client.auth(a.as_mut())
                    }
                    "mail" => client.mail(&unhex_string(f[1])),
                    "rcpt" => client.rcpt(&unhex_string(f[1])),
                    "verify" => client.verify(&unhex_string(f[1])),
                    "data" | "datanoclose" => match client.data() {
                        Ok(mut w) => {
                            let written = w.write_all(&unhex(f[1]));
                            match written {
                                Err(e) => Err(smtp::Error::Io(e)),
                                Ok(()) if f[0] == "data" => w.close(),
                                Ok(()) => Ok(()),
                            }
                        }
                        Err(e) => Err(e),
                    },
                    "reset" => client.reset(),
                    "noop" => client.noop(),
                    "quit" => client.quit(),
                    "close" => client.close(),
                    "starttls" => client.start_tls(&NoTls),
                    "tlsstate" => {
                        detail = format!(" {}", client.tls_connection_state().is_some());
                        Ok(())
                    }
                    other => panic!("bad action {other}"),
                };
                r.map_err(err_text)
            }
        };
        match result {
            Ok(()) => results.push(format!("ok{detail}")),
            Err(text) => results.push(text),
        }
    }
    if let Some(mut client) = c {
        let _ = client.close();
    }
    results.join(" | ")
}

fn send_mail(f: &[&str], macs: &str) -> String {
    load_macs(macs);
    let mut a: Option<Box<dyn Auth>> = match f[1] {
        "plain" => Some(Box::new(smtp::plain_auth("", "u", "p", "127.0.0.1"))),
        "cram" => Some(Box::new(smtp::cram_md5_auth("u", "p", hmac_md5))),
        _ => None,
    };
    let to: Vec<String> = f[3]
        .split(',')
        .filter(|t| *t != "-")
        .map(unhex_string)
        .collect();
    let to_refs: Vec<&str> = to.iter().map(String::as_str).collect();
    let result = smtp::send_mail(
        &format!("127.0.0.1:{}", f[0]),
        a.as_deref_mut(),
        &unhex_string(f[2]),
        &to_refs,
        &unhex(f[4]),
        None,
    );
    match result {
        Ok(()) => "ok".to_owned(),
        Err(e) => err_text(e),
    }
}

fn handle(line: &str) -> String {
    let f: Vec<&str> = line.splitn(3, ' ').collect();
    match f[0] {
        "S" => run_actions(f[1], f[2]),
        "M" => {
            let (head, macs) = line.split_once(" @ ").unwrap_or((line, ""));
            let fields: Vec<&str> = head.split_whitespace().skip(1).collect();
            send_mail(&fields, macs)
        }
        other => panic!("bad request {other}"),
    }
}

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut out = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let text =
            std::panic::catch_unwind(|| handle(line)).unwrap_or_else(|_| "rust-panic".to_owned());
        writeln!(out, "{text}")?;
        out.flush()?;
    }
    Ok(())
}
