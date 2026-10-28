//! Cross-thread deadline and close wake-up scenarios of the Go differential;
//! see tools/sys_oracle_wake.go. A call blocks on one thread, a deadline
//! change or `close` comes from another, and the line reports the error and
//! whether the blocked call returned promptly after the change.
#![allow(clippy::result_large_err, clippy::large_enum_variant)]
use rust_stdlib_sys::net::{self, Conn, Listener, PacketConn};
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime};

type Poke = Box<dyn Fn() + Send + Sync>;

enum Subject {
    Conn { conn: Conn, write: bool },
    Packet(PacketConn),
    Listener(Listener),
}

impl Subject {
    fn block(&self) -> Result<(), net::OpError> {
        match self {
            Subject::Conn { conn, write: false } => conn.read(&mut [0u8; 8]).map(|_| ()),
            Subject::Conn { conn, write: true } => {
                let buf = vec![0u8; 1 << 20];
                loop {
                    conn.write(&buf)?;
                }
            }
            Subject::Packet(p) => p.read_from(&mut [0u8; 8]).map(|_| ()),
            Subject::Listener(l) => l.accept().map(|_| ()),
        }
    }

    fn set(&self, t: Option<SystemTime>) -> Result<(), net::OpError> {
        match self {
            Subject::Conn { conn, write: false } => conn.set_read_deadline(t),
            Subject::Conn { conn, write: true } => conn.set_write_deadline(t),
            Subject::Packet(p) => p.set_read_deadline(t),
            Subject::Listener(l) => l.set_deadline(t),
        }
    }

    fn set_both(&self, t: Option<SystemTime>) -> Result<(), net::OpError> {
        match self {
            Subject::Conn { conn, .. } => conn.set_deadline(t),
            Subject::Packet(p) => p.set_deadline(t),
            Subject::Listener(l) => l.set_deadline(t),
        }
    }

    fn close(&self) -> Result<(), net::OpError> {
        match self {
            Subject::Conn { conn, .. } => conn.close(),
            Subject::Packet(p) => p.close(),
            Subject::Listener(l) => l.close(),
        }
    }
}

/// What a scenario holds besides the blocked end, kept open until it ends.
struct Fixture {
    subject: Arc<Subject>,
    poke: Poke,
    _keep: Vec<Box<dyn std::any::Any + Send + Sync>>,
}

fn err_text(r: Result<(), net::OpError>) -> String {
    match r {
        Ok(()) => "ok".into(),
        Err(e) => format!("err {e}"),
    }
}

fn pair(network: &str, addr: &str, write: bool) -> Fixture {
    let ln = Arc::new(net::listen(network, addr).unwrap());
    let l2 = ln.clone();
    let acceptor = std::thread::spawn(move || l2.accept().unwrap());
    let target = ln.addr().unwrap().to_string();
    let conn = net::dial(network, &target).unwrap();
    let srv = Arc::new(acceptor.join().unwrap());
    let s2 = srv.clone();
    Fixture {
        subject: Arc::new(Subject::Conn { conn, write }),
        poke: Box::new(move || {
            let _ = s2.write(b"x");
        }),
        _keep: vec![Box::new(srv), Box::new(ln)],
    }
}

fn setup(kind: &str) -> Option<Fixture> {
    Some(match kind {
        "tcp_read" => pair("tcp", "127.0.0.1:0", false),
        "tcp_write" => pair("tcp", "127.0.0.1:0", true),
        "unix_read" | "unix_write" => {
            let _ = std::fs::remove_file("wk.sock");
            pair("unix", "wk.sock", kind == "unix_write")
        }
        "udp_read" => {
            let pc = net::listen_packet("udp", "127.0.0.1:0").unwrap();
            let target = pc.local_addr().unwrap().to_string();
            Fixture {
                subject: Arc::new(Subject::Packet(pc)),
                poke: Box::new(move || {
                    if let Ok(c) = net::dial("udp", &target) {
                        let _ = c.write(b"x");
                    }
                }),
                _keep: vec![],
            }
        }
        "unixgram_read" => {
            let _ = std::fs::remove_file("wg.sock");
            let pc = net::listen_packet("unixgram", "wg.sock").unwrap();
            Fixture {
                subject: Arc::new(Subject::Packet(pc)),
                poke: Box::new(|| {
                    if let Ok(c) = std::os::unix::net::UnixDatagram::unbound() {
                        let _ = c.send_to(b"x", "wg.sock");
                    }
                }),
                _keep: vec![],
            }
        }
        "tcp_accept" | "unix_accept" => {
            let (network, addr) = if kind == "tcp_accept" {
                ("tcp", "127.0.0.1:0")
            } else {
                let _ = std::fs::remove_file("wa.sock");
                ("unix", "wa.sock")
            };
            let ln = net::listen(network, addr).unwrap();
            let target = ln.addr().unwrap().to_string();
            Fixture {
                subject: Arc::new(Subject::Listener(ln)),
                poke: Box::new(move || {
                    if let Ok(c) = net::dial(network, &target) {
                        sleep(Duration::from_millis(300));
                        drop(c);
                    }
                }),
                _keep: vec![],
            }
        }
        _ => return None,
    })
}

pub fn run(f: &[&str]) -> String {
    if f[0] != "wake" {
        return format!("unknown scenario {}", f[0]);
    }
    let (kind, how) = (f[1], f[2]);
    let Some(fx) = setup(kind) else {
        return format!("no such kind {kind}");
    };
    let subject = fx.subject.clone();
    let now = SystemTime::now;
    let mut lo = 0u64;
    let mut hi = 40u64;
    let delay = if matches!(how, "extend" | "clear") { 15 } else { 50 };
    let action: Box<dyn Fn() + Send> = {
        let s = subject.clone();
        match how {
            "now" => Box::new(move || {
                let _ = s.set(Some(now()));
            }),
            "both" => Box::new(move || {
                let _ = s.set_both(Some(now()));
            }),
            "past" => Box::new(move || {
                let _ = s.set(Some(now() - Duration::from_secs(3600)));
            }),
            "shorten" => {
                let _ = subject.set(Some(now() + Duration::from_secs(10)));
                lo = 15;
                hi = 60;
                Box::new(move || {
                    let _ = s.set(Some(now() + Duration::from_millis(20)));
                })
            }
            "close" => Box::new(move || {
                let _ = s.close();
            }),
            "extend" | "clear" => {
                let _ = subject.set(Some(now() + Duration::from_millis(400)));
                let extend = how == "extend";
                Box::new(move || {
                    let _ = s.set(if extend {
                        Some(now() + Duration::from_secs(10))
                    } else {
                        None
                    });
                })
            }
            _ => return format!("no such trigger {how}"),
        }
    };
    let fx = Arc::new(fx);
    // The poke thread holds the fixture, whose drop closes (and, for a Unix
    // listener, unlinks) the socket; it is joined so that happens before the
    // next scenario binds the same path.
    let poker = matches!(how, "extend" | "clear").then(|| {
        let fx = fx.clone();
        std::thread::spawn(move || {
            sleep(Duration::from_millis(500));
            (fx.poke)();
        })
    });
    let trigger = std::thread::spawn(move || {
        sleep(Duration::from_millis(delay));
        let t0 = Instant::now();
        action();
        t0
    });
    let start = Instant::now();
    let r = subject.block();
    let t1 = Instant::now();
    let t0 = trigger.join().unwrap();
    let mut out = err_text(r);
    if let Some(poker) = poker {
        poker.join().unwrap();
        return format!("{out} waited={}", t1 - start >= Duration::from_millis(380));
    }
    let el = t1.saturating_duration_since(t0);
    out.push_str(&format!(
        " timely={}",
        t1 > t0 && el >= Duration::from_millis(lo) && el < Duration::from_millis(hi)
    ));
    if how == "close" {
        out.push_str(&format!(" close2={}", err_text(subject.close())));
        out.push_str(&format!(" after={}", err_text(subject.block())));
        out.push_str(&format!(
            " setdl={}",
            err_text(subject.set_both(Some(now() + Duration::from_secs(1))))
        ));
    }
    out
}
