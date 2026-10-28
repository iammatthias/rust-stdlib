//! Scenario interpreter used by `tools/conn_check.py`; mirrors
//! `tools/conn_oracle.go` line for line (live loopback TCP, UDP, Unix and
//! pipe scripts compared with Go).
use rust_stdlib::net::{
    self, dial, dial_timeout, dial_udp, dial_unix, listen, listen_packet, listen_udp, lookup_port,
    resolve_ip_addr, resolve_tcp_addr, resolve_udp_addr, resolve_unix_addr, Conn, Error as _,
    Listener, NetError, PacketConn, TCPAddr, TCPConn, UDPAddr, UnixAddr, UnixConn,
};
use rust_stdlib::time::{now, Duration, Time};
use std::io::{self, BufRead, Write};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration as StdDuration;
use std::time::Instant;

fn cls(e: &NetError) -> &'static str {
    let text = e.to_string();
    if e.is_closed() {
        "closed"
    } else if text == "EOF" {
        "eof"
    } else if matches!(e, NetError::ClosedPipe) {
        "closedpipe"
    } else if e.timeout() {
        "timeout"
    } else if text.contains("connection refused") {
        "refused"
    } else {
        "other"
    }
}

fn ob<T>(label: &str, r: &Result<T, NetError>) -> String {
    match r {
        Ok(_) => format!("{label}=nil"),
        Err(e) => format!("{label}={}({e})", cls(e)),
    }
}

fn obp<T>(label: &str, r: &Result<T, NetError>, path: &str) -> String {
    ob(label, r).replace(path, "PATH")
}

fn rd(r: &Result<usize, NetError>) -> String {
    match r {
        Ok(0) => "0 eof".into(),
        Ok(n) => format!("{n} nil"),
        Err(e) => format!("0 {}", cls(e)),
    }
}

fn addr_str(a: Option<net::AddrRef>) -> String {
    let a = a.expect("address");
    format!("{} {}", a.network(), a)
}

fn addrs(prefix: &str, c: &dyn Conn) -> Vec<String> {
    vec![
        format!("{prefix}.local={}", addr_str(c.local_addr())),
        format!("{prefix}.remote={}", addr_str(c.remote_addr())),
    ]
}

fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 7 + 3) as u8).collect()
}

fn ms_from_now(ms: i64) -> Time {
    now().add(Duration::from_nanos(ms * 1_000_000))
}

fn sleep(ms: u64) {
    thread::sleep(StdDuration::from_millis(ms));
}

/// `io.ReadFull`: the bytes read and the error, if any.
fn read_full(c: &dyn Conn, buf: &mut [u8]) -> (usize, Result<(), NetError>) {
    let mut off = 0;
    while off < buf.len() {
        match c.read(&mut buf[off..]) {
            Err(e) => return (off, Err(e)),
            Ok(0) => {
                return (
                    off,
                    Err(NetError::other(if off == 0 {
                        "EOF"
                    } else {
                        "unexpected EOF"
                    })),
                );
            }
            Ok(n) => off += n,
        }
    }
    (off, Ok(()))
}

fn tcp_echo(n: usize) -> Vec<String> {
    let ln = match listen("tcp", "127.0.0.1:0") {
        Ok(l) => Arc::<dyn Listener>::from(l),
        Err(e) => return vec![ob::<()>("listen", &Err(e))],
    };
    let mut tr = vec![format!("listener={}", addr_str(ln.addr()))];
    let (tx, rx) = mpsc::channel::<Vec<String>>();
    let ln2 = ln.clone();
    thread::spawn(move || {
        let mut t = Vec::new();
        let c = match ln2.accept() {
            Ok(c) => c,
            Err(e) => {
                let _ = tx.send(vec![ob::<()>("accept", &Err(e))]);
                return;
            }
        };
        t.extend(addrs("srv", &*c));
        let mut buf = vec![0u8; n];
        t.push(ob("srv.readfull", &read_full(&*c, &mut buf).1));
        t.push(ob("srv.write", &c.write(&buf)));
        let mut b8 = [0u8; 8];
        t.push(format!("srv.read={}", rd(&c.read(&mut b8))));
        t.push(ob("srv.bye", &c.write(b"bye")));
        let _ = c.close();
        let _ = tx.send(t);
    });
    let c = match dial("tcp", &ln.addr().unwrap().to_string()) {
        Ok(c) => c,
        Err(e) => {
            tr.push(ob::<()>("dial", &Err(e)));
            return tr;
        }
    };
    let tc = c.as_any().downcast_ref::<TCPConn>().unwrap();
    tr.extend(addrs("cli", &*c));
    let w = payload(n);
    tr.push(ob("cli.write", &c.write(&w)));
    let mut got = vec![0u8; n];
    tr.push(ob("cli.readfull", &read_full(&*c, &mut got).1));
    tr.push(format!("equal={}", w == got));
    tr.push(ob("closewrite", &tc.close_write()));
    let mut bye = [0u8; 8];
    let (k, r) = read_full(&*c, &mut bye);
    tr.push(format!(
        "cli.bye={} {}",
        String::from_utf8_lossy(&bye[..k]),
        r.as_ref().map(|_| "nil").unwrap_or_else(|e| cls(e))
    ));
    let mut b = [0u8; 8];
    let r = c.read(&mut b);
    tr.push(format!("cli.after={}", rd(&r)));
    tr.push(ob("nodelay", &tc.set_no_delay(false)));
    tr.extend(rx.recv().unwrap());
    let _ = c.close();
    let _ = ln.close();
    tr
}

fn tcp_deadline(ms: i64) -> Vec<String> {
    let ln = Arc::<dyn Listener>::from(listen("tcp", "127.0.0.1:0").unwrap());
    let ln2 = ln.clone();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(ln2.accept().ok());
    });
    let c = match dial("tcp", &ln.addr().unwrap().to_string()) {
        Ok(c) => c,
        Err(e) => return vec![ob::<()>("dial", &Err(e))],
    };
    let s = rx.recv().unwrap().unwrap();
    let mut tr = Vec::new();
    let start = std::time::Instant::now();
    let _ = c.set_read_deadline(&ms_from_now(ms));
    let mut b4 = [0u8; 4];
    tr.push(ob("read1", &c.read(&mut b4)));
    let el = start.elapsed();
    tr.push(format!(
        "waited={}",
        el >= StdDuration::from_millis(ms as u64) && el < StdDuration::from_millis(ms as u64 + 400)
    ));
    tr.push(ob("read2", &c.read(&mut b4)));
    let _ = c.set_read_deadline(&Time::default());
    let _ = s.write(b"hi");
    let r = c.read(&mut b4);
    let k = *r.as_ref().unwrap_or(&0);
    tr.push(format!(
        "read3={} {}",
        String::from_utf8_lossy(&b4[..k]),
        match &r {
            Ok(0) => "eof",
            Ok(_) => "nil",
            Err(e) => cls(e),
        }
    ));
    let _ = c.set_deadline(&ms_from_now(-1000));
    tr.push(ob("write-past", &c.write(b"x")));
    tr.push(ob("read-past", &c.read(&mut b4)));
    let _ = (c.close(), s.close(), ln.close());
    tr
}

fn tcp_refused() -> Vec<String> {
    let ln = listen("tcp", "127.0.0.1:0").unwrap();
    let addr = ln.addr().unwrap().to_string();
    let _ = ln.close();
    let r = dial("tcp", &addr);
    let mut tr = vec![ob("dial", &r)];
    if let Err(NetError::Op(oe)) = &r {
        tr.push(format!("op={}", oe.op));
        tr.push(format!("net={}", oe.net));
        tr.push(format!("addr={}", oe.addr.as_ref().unwrap()));
        tr.push(format!("timeout={}", oe.timeout()));
    }
    tr.push(ob(
        "dialtimeout",
        &dial_timeout("tcp", &addr, Duration::from_nanos(1_000_000_000)),
    ));
    tr
}

fn tcp_closed() -> Vec<String> {
    let ln = Arc::<dyn Listener>::from(listen("tcp", "127.0.0.1:0").unwrap());
    let ln2 = ln.clone();
    thread::spawn(move || {
        if let Ok(c) = ln2.accept() {
            let mut b = [0u8; 64];
            while matches!(c.read(&mut b), Ok(n) if n > 0) {}
            let _ = c.close();
        }
    });
    let c = match dial("tcp", &ln.addr().unwrap().to_string()) {
        Ok(c) => c,
        Err(e) => return vec![ob::<()>("dial", &Err(e))],
    };
    let mut tr = vec![ob("close1", &c.close())];
    tr.push(ob("read", &c.read(&mut [0u8; 1])));
    tr.push(ob("write", &c.write(b"x")));
    tr.push(ob("close2", &c.close()));
    tr.push(ob("setdeadline", &c.set_deadline(&now())));
    tr.push(ob(
        "closeread",
        &c.as_any().downcast_ref::<TCPConn>().unwrap().close_read(),
    ));
    let _ = ln.close();
    tr
}

fn tcp_accept_close() -> Vec<String> {
    let ln = Arc::<dyn Listener>::from(listen("tcp", "127.0.0.1:0").unwrap());
    let ln2 = ln.clone();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(ln2.accept().map(|_| ()));
    });
    sleep(50);
    let mut tr = vec![ob("close", &ln.close())];
    tr.push(ob("accept", &rx.recv().unwrap()));
    tr.push(ob("close2", &ln.close()));
    tr.push(ob("accept2", &ln.accept().map(|_| ())));
    tr
}

fn tcp_accept_deadline() -> Vec<String> {
    let ln = listen("tcp", "127.0.0.1:0").unwrap();
    let tl = ln.as_any().downcast_ref::<net::TCPListener>().unwrap();
    let _ = tl.set_deadline(&ms_from_now(60));
    let mut tr = vec![ob("accept", &ln.accept().map(|_| ()))];
    let _ = tl.set_deadline(&Time::default());
    let a = ln.addr().unwrap().to_string();
    thread::spawn(move || {
        if let Ok(c) = dial("tcp", &a) {
            sleep(100);
            let _ = c.close();
        }
    });
    let r = ln.accept();
    tr.push(ob(
        "accept2",
        &r.as_ref().map(|_| ()).map_err(|e| e.clone()),
    ));
    if let Ok(c) = r {
        let _ = c.close();
    }
    let _ = ln.close();
    tr
}

fn tcp_read_close() -> Vec<String> {
    let ln = Arc::<dyn Listener>::from(listen("tcp", "127.0.0.1:0").unwrap());
    let ln2 = ln.clone();
    thread::spawn(move || {
        if let Ok(c) = ln2.accept() {
            sleep(1000);
            let _ = c.close();
        }
    });
    let c: Arc<dyn Conn> = Arc::from(dial("tcp", &ln.addr().unwrap().to_string()).unwrap());
    let (tx, rx) = mpsc::channel();
    let c1 = c.clone();
    let tx1 = tx.clone();
    thread::spawn(move || {
        let _ = tx1.send(c1.read(&mut [0u8; 1]));
    });
    sleep(50);
    let _ = c.close();
    let mut tr = vec![ob("read", &rx.recv().unwrap())];
    let c2: Arc<dyn Conn> = Arc::from(dial("tcp", &ln.addr().unwrap().to_string()).unwrap());
    let c3 = c2.clone();
    thread::spawn(move || {
        let _ = tx.send(c3.read(&mut [0u8; 1]));
    });
    sleep(50);
    let _ = c2.set_read_deadline(&now());
    tr.push(ob("interrupted", &rx.recv().unwrap()));
    let _ = c2.close();
    let _ = ln.close();
    tr
}

/// See tcpWake in tools/conn_oracle.go: a blocked read and accept woken from
/// another thread by a deadline change or close.
fn tcp_wake(how: &str) -> Vec<String> {
    let ln = Arc::<dyn Listener>::from(listen("tcp", "127.0.0.1:0").unwrap());
    let ln1 = ln.clone();
    thread::spawn(move || {
        if let Ok(c) = ln1.accept() {
            sleep(1000);
            let _ = c.close();
        }
    });
    let c: Arc<dyn Conn> = Arc::from(dial("tcp", &ln.addr().unwrap().to_string()).unwrap());
    let ln2 = Arc::<dyn Listener>::from(listen("tcp", "127.0.0.1:0").unwrap());
    let mut tr = Vec::new();
    for label in ["read", "accept"] {
        let (c2, l2) = (c.clone(), ln2.clone());
        let set = move |t: &Time| {
            if label == "read" {
                let _ = c2.set_read_deadline(t);
            } else {
                let tl = l2.as_any().downcast_ref::<net::TCPListener>().unwrap();
                let _ = tl.set_deadline(t);
            }
        };
        if how == "shorten" {
            set(&ms_from_now(10_000));
        }
        let (c3, l3) = (c.clone(), ln2.clone());
        let how = how.to_string();
        let trigger = thread::spawn(move || {
            sleep(50);
            let t0 = Instant::now();
            match how.as_str() {
                "now" => set(&now()),
                "shorten" => set(&ms_from_now(20)),
                _ => {
                    let _ = if label == "read" {
                        c3.close()
                    } else {
                        l3.close()
                    };
                }
            }
            t0
        });
        let r = if label == "read" {
            c.read(&mut [0u8; 1]).map(|_| ())
        } else {
            ln2.accept().map(|_| ())
        };
        let t1 = Instant::now();
        let t0 = trigger.join().unwrap();
        tr.push(ob(label, &r));
        tr.push(format!(
            "{label}-timely={}",
            t1 > t0 && t1 - t0 < StdDuration::from_millis(250)
        ));
    }
    tr
}

fn tcp_in_use() -> Vec<String> {
    let ln = listen("tcp", "127.0.0.1:0").unwrap();
    let r = listen("tcp", &ln.addr().unwrap().to_string()).map(|_| ());
    let tr = vec![ob("listen2", &r)];
    let _ = ln.close();
    tr
}

fn udp_echo(n: usize) -> Vec<String> {
    let pc = match listen_packet("udp", "127.0.0.1:0") {
        Ok(p) => Arc::<dyn PacketConn>::from(p),
        Err(e) => return vec![ob::<()>("listen", &Err(e))],
    };
    let mut tr = vec![format!("local={}", addr_str(pc.local_addr()))];
    let pc2 = pc.clone();
    thread::spawn(move || {
        let mut buf = vec![0u8; 2048];
        if let Ok((k, a)) = pc2.read_from(&mut buf) {
            let _ = pc2.write_to(&buf[..k], &*a.unwrap());
        }
    });
    let c = match dial("udp", &pc.local_addr().unwrap().to_string()) {
        Ok(c) => c,
        Err(e) => {
            tr.push(ob::<()>("dial", &Err(e)));
            return tr;
        }
    };
    tr.extend(addrs("cli", &*c));
    let w = payload(n);
    tr.push(format!(
        "write={}",
        match c.write(&w) {
            Ok(n) => format!("{n} nil"),
            Err(e) => format!("0 {}", cls(&e)),
        }
    ));
    let mut buf = vec![0u8; 2048];
    let _ = c.set_read_deadline(&ms_from_now(2000));
    let r = c.read(&mut buf);
    let k = *r.as_ref().unwrap_or(&0);
    tr.push(format!(
        "read={}",
        match &r {
            Ok(n) => format!("{n} nil"),
            Err(e) => format!("0 {}", cls(e)),
        }
    ));
    tr.push(format!("equal={}", w == buf[..k]));
    let _ = c.set_read_deadline(&ms_from_now(50));
    tr.push(ob("read2", &c.read(&mut buf)));
    let _ = (c.close(), pc.close());
    tr
}

fn udp_connected() -> Vec<String> {
    let pc = listen_packet("udp", "127.0.0.1:0").unwrap();
    let ra = resolve_udp_addr("udp", &pc.local_addr().unwrap().to_string()).unwrap();
    let c = match dial_udp("udp", None, Some(&ra)) {
        Ok(c) => c,
        Err(e) => return vec![ob::<()>("dial", &Err(e))],
    };
    let mut tr = vec![ob("writeto", &c.write_to(b"x", &ra))];
    tr.push(ob("writetoudp", &c.write_to_udp(b"x", Some(&ra))));
    tr.push(ob(
        "writeto-tcpaddr",
        &c.write_to(b"x", &TCPAddr::default()),
    ));
    let lo = UDPAddr {
        ip: net::ipv4(127, 0, 0, 1),
        port: 0,
        zone: String::new(),
    };
    let u = listen_udp("udp", Some(&lo)).unwrap();
    tr.push(ob("write-unconnected", &u.write(b"x")));
    let r = u.write_to_udp(b"hello", Some(&ra));
    tr.push(format!("writetoudp-ok={}", rd(&r)));
    let mut buf = [0u8; 16];
    let _ = pc.set_read_deadline(&ms_from_now(2000));
    let r = pc.read_from(&mut buf);
    match &r {
        Ok((k, a)) => tr.push(format!(
            "readfrom={} nil ; net={}",
            String::from_utf8_lossy(&buf[..*k]),
            a.as_ref().unwrap().network()
        )),
        Err(e) => tr.push(format!("readfrom= {} ; net=", cls(e))),
    }
    tr.push(ob("writetoudp-nil", &u.write_to_udp(b"x", None)));
    let _ = (c.close(), u.close(), pc.close());
    tr
}

fn unix_path() -> String {
    let d = std::env::temp_dir().join(format!("cs{}{}", std::process::id(), now().unix_nano()));
    std::fs::create_dir_all(&d).unwrap();
    d.join("s").to_string_lossy().into_owned()
}

fn unix_echo(n: usize) -> Vec<String> {
    let path = unix_path();
    let dir = std::path::Path::new(&path).parent().unwrap().to_owned();
    let ln = match listen("unix", &path) {
        Ok(l) => Arc::<dyn Listener>::from(l),
        Err(e) => return vec![ob::<()>("listen", &Err(e))],
    };
    let mut tr = vec![format!(
        "listener={}",
        addr_str(ln.addr()).replace(&path, "PATH")
    )];
    let (tx, rx) = mpsc::channel::<Vec<String>>();
    let ln2 = ln.clone();
    let p2 = path.clone();
    thread::spawn(move || {
        let c = match ln2.accept() {
            Ok(c) => c,
            Err(e) => {
                let _ = tx.send(vec![ob::<()>("accept", &Err(e))]);
                return;
            }
        };
        let mut buf = vec![0u8; n];
        let r = read_full(&*c, &mut buf).1;
        let _ = c.write(&buf);
        let k = c.read(&mut [0u8; 4]);
        let _ = tx.send(vec![
            ob("srv.readfull", &r),
            format!("srv.read={}", rd(&k)),
            format!(
                "srv.local={}",
                c.local_addr().unwrap().to_string().replace(&p2, "PATH")
            ),
            format!("srv.remote=[{}]", c.remote_addr().unwrap().to_string()),
        ]);
    });
    let c = match dial("unix", &path) {
        Ok(c) => c,
        Err(e) => {
            tr.push(ob::<()>("dial", &Err(e)));
            return tr;
        }
    };
    let uc = c.as_any().downcast_ref::<UnixConn>().unwrap();
    tr.push(format!(
        "cli.local=[{}] {}",
        c.local_addr().unwrap(),
        c.local_addr().unwrap().network()
    ));
    tr.push(format!(
        "cli.remote={} {}",
        c.remote_addr().unwrap().to_string().replace(&path, "PATH"),
        c.remote_addr().unwrap().network()
    ));
    let w = payload(n);
    let _ = c.write(&w);
    let mut got = vec![0u8; n];
    tr.push(ob("cli.readfull", &read_full(&*c, &mut got).1));
    tr.push(format!("equal={}", w == got));
    tr.push(ob("closewrite", &uc.close_write()));
    tr.extend(rx.recv().unwrap());
    let _ = c.close();
    tr.push(ob("lnclose", &ln.close()));
    tr.push(format!(
        "unlinked={}",
        !std::path::Path::new(&path).exists()
    ));
    tr.push(obp("redial", &dial("unix", &path).map(|_| ()), &path));
    let _ = std::fs::remove_dir_all(dir);
    tr
}

fn unix_dgram() -> Vec<String> {
    let path = unix_path();
    let dir = std::path::Path::new(&path).parent().unwrap().to_owned();
    let pc = match listen_packet("unixgram", &path) {
        Ok(p) => p,
        Err(e) => return vec![ob::<()>("listen", &Err(e))],
    };
    let mut tr = vec![format!(
        "local={}",
        addr_str(pc.local_addr()).replace(&path, "PATH")
    )];
    let ra = UnixAddr {
        name: path.clone(),
        net: "unixgram".into(),
    };
    let c = match dial_unix("unixgram", None, Some(&ra)) {
        Ok(c) => c,
        Err(e) => {
            tr.push(ob::<()>("dial", &Err(e)));
            return tr;
        }
    };
    tr.push(format!("write={}", rd(&c.write(b"ping"))));
    let mut buf = [0u8; 16];
    let _ = pc.set_read_deadline(&ms_from_now(2000));
    match pc.read_from(&mut buf) {
        Ok((k, a)) => {
            tr.push(format!(
                "readfrom={} nil",
                String::from_utf8_lossy(&buf[..k])
            ));
            tr.push(match a {
                Some(a) => format!("from=[{}] {}", a, a.network()),
                None => "from=<nil>".into(),
            });
        }
        Err(e) => {
            tr.push(format!("readfrom= {}", cls(&e)));
            tr.push("from=[] ".into());
        }
    }
    tr.push(obp("writeto-connected", &c.write_to(b"x", &ra), &path));
    let _ = (c.close(), pc.close());
    let _ = std::fs::remove_dir_all(dir);
    tr
}

fn pipe_echo(n: usize) -> Vec<String> {
    let (a, b) = net::pipe();
    let (a, b) = (Arc::new(a), Arc::new(b));
    let mut tr = vec![format!(
        "addr={} {} {}",
        a.local_addr().unwrap().network(),
        a.local_addr().unwrap().to_string(),
        b.remote_addr().unwrap().to_string()
    )];
    let (tx, rx) = mpsc::channel::<Vec<String>>();
    let b2 = b.clone();
    thread::spawn(move || {
        let mut buf = vec![0u8; n];
        let r = read_full(&*b2, &mut buf).1;
        let w = b2.write(&buf);
        let _ = tx.send(vec![ob("srv.read", &r), ob("srv.write", &w)]);
    });
    let w = payload(n);
    tr.push(ob("write", &a.write(&w)));
    let mut got = vec![0u8; n];
    tr.push(ob("readfull", &read_full(&*a, &mut got).1));
    tr.push(format!("equal={}", w == got));
    tr.extend(rx.recv().unwrap());
    tr.push(ob("close-b", &b.close()));
    tr.push(format!(
        "read-after-remote-close={}",
        rd(&a.read(&mut [0u8; 4]))
    ));
    tr.push(ob("write-after-remote-close", &a.write(b"x")));
    tr.push(ob("read-local-closed", &b.read(&mut [0u8; 1])));
    tr.push(ob("setdeadline-closed", &a.set_deadline(&now())));
    tr
}

fn pipe_deadline() -> Vec<String> {
    let (a, b) = net::pipe();
    let b = Arc::new(b);
    let _ = a.set_read_deadline(&ms_from_now(30));
    let mut tr = vec![ob("read", &a.read(&mut [0u8; 1]))];
    let _ = b.set_write_deadline(&ms_from_now(30));
    match b.write(b"abc") {
        Err(e) => tr.push(format!("write=0 {} {e}", cls(&e))),
        Ok(k) => tr.push(format!("write={k} nil ")),
    }
    let _ = a.set_read_deadline(&Time::default());
    let _ = b.set_write_deadline(&Time::default());
    let b2 = b.clone();
    thread::spawn(move || {
        let _ = b2.write(b"hello");
    });
    let mut buf = [0u8; 2];
    for i in 1..=3 {
        let r = a.read(&mut buf);
        let k = *r.as_ref().unwrap_or(&0);
        tr.push(format!(
            "partial{i}={} {}",
            String::from_utf8_lossy(&buf[..k]),
            match &r {
                Ok(0) => "eof",
                Ok(_) => "nil",
                Err(e) => cls(e),
            }
        ));
    }
    tr
}

fn addr_errors() -> Vec<String> {
    let mut tr = Vec::new();
    for (n, a) in [
        ("tcp", ""),
        ("foo", "x:1"),
        ("tcp", "1.2.3.4"),
        ("tcp", "a:b:c"),
        ("tcp", "[::1]"),
        ("tcp4", "[::1]:80"),
        ("tcp6", "127.0.0.1:80"),
        ("udp", ":65536"),
        ("ip", "127.0.0.1"),
        ("unixpacket", ""),
        ("tcp", "127.0.0.1:http-nope"),
    ] {
        tr.push(ob(&format!("dial({n},{a})"), &dial(n, a).map(|_| ())));
    }
    for (n, a) in [
        ("tcp", "bad:addr:x"),
        ("foo", ":0"),
        ("tcp", "127.0.0.1:99999"),
        ("udp", "[::1"),
        ("tcp4", "[::1]:0"),
    ] {
        tr.push(ob(&format!("listen({n},{a})"), &listen(n, a).map(|_| ())));
    }
    tr.push(ob(
        "listenpacket(tcp)",
        &listen_packet("tcp", ":0").map(|_| ()),
    ));
    tr
}

fn resolve() -> Vec<String> {
    let mut tr = Vec::new();
    for (n, a) in [
        ("tcp", "127.0.0.1:80"),
        ("tcp", "[::1]:http"),
        ("tcp4", "[::1]:80"),
        ("tcp", ":0"),
        ("", "1.2.3.4:5"),
        ("tcp", "[fe80::1%eth0]:22"),
        ("udp", "0.0.0.0:domain"),
        ("udp6", "1.2.3.4:5"),
        ("x", "1.2.3.4:5"),
        ("tcp", "1.2.3.4:nosuchservice"),
        ("tcp", "1.2.3.4:-1"),
        ("tcp", "1.2.3.4:70000"),
        ("tcp", "localhost:80"),
    ] {
        match resolve_tcp_addr(n, a) {
            Err(e) => tr.push(ob::<()>(&format!("tcp({n},{a})"), &Err(e))),
            Ok(x) => tr.push(format!("tcp({n},{a})={}", x)),
        }
        match resolve_udp_addr(n, a) {
            Err(e) => tr.push(ob::<()>(&format!("udp({n},{a})"), &Err(e))),
            Ok(x) => tr.push(format!("udp({n},{a})={}", x)),
        }
    }
    for (n, a) in [
        ("ip", "1.2.3.4"),
        ("ip4", "::1"),
        ("ip6", "fe80::1%x"),
        ("ip:1", "1.2.3.4"),
        ("ip:nosuch", "1.2.3.4"),
        ("", ""),
    ] {
        match resolve_ip_addr(n, a) {
            Err(e) => tr.push(ob::<()>(&format!("ip({n},{a})"), &Err(e))),
            Ok(x) => tr.push(format!("ip({n},{a})={}", x)),
        }
    }
    for (n, a) in [("unix", "/tmp/x"), ("unixgram", "@a"), ("tcp", "x")] {
        match resolve_unix_addr(n, a) {
            Err(e) => tr.push(ob::<()>(&format!("unix({n},{a})"), &Err(e))),
            Ok(x) => tr.push(format!("unix({n},{a})={} {}", x, x.network())),
        }
    }
    for (n, s) in [
        ("tcp", "http"),
        ("tcp", "80"),
        ("udp", "domain"),
        ("tcp", "nosuch"),
        ("foo", "http"),
        ("tcp", "70000"),
        ("tcp", "-5"),
        ("", "ssh"),
        ("ip", "http"),
        ("tcp", ""),
        ("tcp", "+8"),
    ] {
        match lookup_port(n, s) {
            Err(e) => tr.push(ob::<()>(&format!("port({n},{s})"), &Err(e))),
            Ok(p) => tr.push(format!("port({n},{s})={p}")),
        }
    }
    tr
}

fn handle(line: &str) -> Vec<String> {
    let f: Vec<&str> = line.split_whitespace().collect();
    let arg = || f.get(1).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
    match f[0] {
        "tcp_echo" => tcp_echo(arg() as usize),
        "tcp_deadline" => tcp_deadline(arg()),
        "tcp_refused" => tcp_refused(),
        "tcp_closed" => tcp_closed(),
        "tcp_accept_close" => tcp_accept_close(),
        "tcp_accept_deadline" => tcp_accept_deadline(),
        "tcp_read_close" => tcp_read_close(),
        "tcp_wake" => tcp_wake(f[1]),
        "tcp_in_use" => tcp_in_use(),
        "udp_echo" => udp_echo(arg() as usize),
        "udp_connected" => udp_connected(),
        "unix_echo" => unix_echo(arg() as usize),
        "unix_dgram" => unix_dgram(),
        "pipe_echo" => pipe_echo(arg() as usize),
        "pipe_deadline" => pipe_deadline(),
        "addr_errors" => addr_errors(),
        "resolve" => resolve(),
        s => panic!("unknown scenario {s}"),
    }
}

fn main() {
    let stdin = io::stdin();
    let mut out = io::stdout().lock();
    for line in stdin.lock().lines() {
        writeln!(out, "{}", handle(&line.unwrap()).join(" ; ")).unwrap();
        out.flush().unwrap();
    }
}
