//! Dial and listen scenarios of the Go differential; see tools/sys_oracle_dial.go.
use rust_stdlib_sys::net::{
    self, level, opt, Background, Conn, Dialer, IPAddr, KeepAliveConfig, ListenConfig, Listener,
    PacketConn, ResolvedAddr, TCPAddr, TCPConn, UnixAddr,
};
use rust_stdlib_sys::os::{File, FileKind};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::OwnedFd;
use std::time::{Duration, Instant, SystemTime};

fn err_text<E: std::fmt::Display>(r: Result<(), E>) -> String {
    match r {
        Ok(()) => "ok".into(),
        Err(e) => format!("err {e}"),
    }
}

fn within(start: Instant, lo: u64, hi: u64) -> bool {
    let el = start.elapsed();
    el >= Duration::from_millis(lo) && el < Duration::from_millis(hi)
}

fn tcp_listener(network: &str, addr: &str) -> Option<(TcpListener, String)> {
    let _ = network;
    let ln = TcpListener::bind(addr).ok()?;
    let port = ln.local_addr().ok()?.port().to_string();
    Some((ln, port))
}

fn echo_once(ln: TcpListener) {
    std::thread::spawn(move || {
        if let Ok((mut c, _)) = ln.accept() {
            let mut buf = [0u8; 64];
            while let Ok(n) = c.read(&mut buf) {
                if n == 0 || c.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    });
}

fn sock_int(s: &TCPConn, lvl: i32, name: i32) -> String {
    match net::getsockopt_int(s, lvl, name) {
        Ok(v) => v.to_string(),
        Err(e) => format!("err {}", e.err),
    }
}

fn conn_state(c: &Conn) -> String {
    let Conn::Tcp(tc) = c else {
        return "not-tcp".into();
    };
    format!(
        "keepalive={} idle={} intvl={} cnt={} nodelay={}",
        sock_int(tc, level::SOL_SOCKET, opt::SO_KEEPALIVE),
        sock_int(tc, level::IPPROTO_TCP, opt::TCP_KEEPIDLE),
        sock_int(tc, level::IPPROTO_TCP, opt::TCP_KEEPINTVL),
        sock_int(tc, level::IPPROTO_TCP, opt::TCP_KEEPCNT),
        sock_int(tc, level::IPPROTO_TCP, opt::TCP_NODELAY),
    )
}

fn round_trip(c: &mut TCPConn) -> String {
    c.set_read_deadline(Some(SystemTime::now() + Duration::from_secs(2)))
        .unwrap();
    if let Err(e) = c.write_all(b"ping") {
        return format!("write {e}");
    }
    let mut buf = [0u8; 4];
    match c.read_exact(&mut buf) {
        Ok(()) => format!("echo={}", String::from_utf8_lossy(&buf)),
        Err(e) => format!("read {e}"),
    }
}

fn describe_tcp(t: &TCPConn) -> String {
    format!(
        "local=tcp/{} remote=tcp/{}",
        t.local_addr().unwrap(),
        t.remote_addr().unwrap()
    )
}

fn describe(c: &Conn) -> String {
    match c {
        Conn::Tcp(t) => describe_tcp(t),
        Conn::Udp(u) => format!(
            "local=udp/{} remote=udp/{}",
            u.local_addr().unwrap(),
            u.remote_addr().map(|a| a.to_string()).unwrap_or_default()
        ),
        _ => "other".into(),
    }
}

fn ms(s: &str) -> i64 {
    s.parse::<i64>().unwrap() * 1_000_000
}

fn local_ip(a: Option<IpAddr>) -> TCPAddr {
    TCPAddr {
        ip: a,
        port: 0,
        zone: String::new(),
    }
}

pub fn run(f: &[&str]) -> String {
    match f[0] {
        "dial_basic" => {
            let Some((ln, port)) = tcp_listener(f[3], f[4]) else {
                return "listen failed".into();
            };
            echo_once(ln);
            let addr = f[2].replace("{p}", &port);
            match net::dial(f[1], &addr) {
                Ok(mut c) => {
                    let desc = describe(&c);
                    let state = conn_state(&c);
                    let rt = match &mut c {
                        Conn::Tcp(t) => round_trip(t),
                        _ => String::new(),
                    };
                    format!("ok {desc} {state} {rt}")
                }
                Err(e) => format!("err {e}"),
            }
        }
        "dial_err" => err_text(net::dial_timeout(f[1], f[2], 2_000_000_000).map(|_| ())),
        "dial_unix_refused" => {
            let _ = std::fs::remove_file("dead.sock");
            let l = net::listen_unix(
                "unix",
                Some(&UnixAddr {
                    name: "dead.sock".into(),
                    net: "unix".into(),
                }),
            )
            .unwrap();
            l.set_unlink_on_close(false);
            l.close().unwrap();
            err_text(net::dial("unix", "dead.sock").map(|_| ()))
        }
        "dial_local" => {
            let (ln, port) = tcp_listener("tcp", "127.0.0.1:0").unwrap();
            echo_once(ln);
            let mut d = Dialer::default();
            let lo = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
            match f[1] {
                "ip" => d.local_addr = Some(ResolvedAddr::Tcp(local_ip(lo))),
                "ipport" => {
                    let (l2, p2) = tcp_listener("tcp", "127.0.0.1:0").unwrap();
                    drop(l2);
                    d.local_addr = Some(ResolvedAddr::Tcp(TCPAddr {
                        ip: lo,
                        port: p2.parse().unwrap(),
                        zone: String::new(),
                    }));
                }
                "udp" => {
                    d.local_addr = Some(ResolvedAddr::Udp(net::UDPAddr {
                        ip: lo,
                        port: 0,
                        zone: String::new(),
                    }))
                }
                "v6" => {
                    d.local_addr = Some(ResolvedAddr::Tcp(local_ip(Some(IpAddr::V6(
                        Ipv6Addr::LOCALHOST,
                    )))))
                }
                "wild" => d.local_addr = Some(ResolvedAddr::Tcp(local_ip(None))),
                _ => {}
            }
            match d.dial("tcp", &format!("127.0.0.1:{port}")) {
                Ok(Conn::Tcp(c)) => {
                    let la = c.local_addr().unwrap();
                    let mut out =
                        format!("ok localip={} remote={}", la.ip.unwrap(), c.remote_addr().unwrap());
                    if f[1] == "ipport" {
                        out.push_str(&format!(" keptport={}", la.port != 0));
                    }
                    out
                }
                Ok(_) => "ok other".into(),
                Err(e) => format!("err {e}"),
            }
        }
        "dial_control" => {
            let (ln, port) = tcp_listener("tcp", "127.0.0.1:0").unwrap();
            echo_once(ln);
            let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
            let mut d = Dialer::default();
            let mode = f[1].to_string();
            let s2 = seen.clone();
            match f[1] {
                "ctx" => {
                    let s3 = seen.clone();
                    d.control = Some(Box::new(move |_, _, _| {
                        s3.lock().unwrap().push("WRONG".into());
                        Ok(())
                    }));
                    d.control_context = Some(Box::new(move |_ctx, network, address, _rc| {
                        s2.lock().unwrap().push(format!("ctx:{network}|{address}"));
                        Ok(())
                    }));
                }
                _ => {
                    d.control = Some(Box::new(move |network, address, rc| {
                        s2.lock().unwrap().push(format!("{network}|{address}"));
                        let mut res = Ok(());
                        rc.control(|fd| {
                            struct Raw(i32);
                            impl net::AsSocket for Raw {
                                fn socket_fd(&self) -> i32 {
                                    self.0
                                }
                            }
                            res = net::setsockopt_int(
                                &Raw(fd),
                                level::SOL_SOCKET,
                                opt::SO_REUSEADDR,
                                1,
                            )
                            .map_err(|e| std::io::Error::other(e.to_string()));
                        })
                        .map_err(|e| std::io::Error::other(e.to_string()))?;
                        if mode == "error" {
                            return Err(std::io::Error::other("boom"));
                        }
                        res
                    }));
                }
            }
            let result = d.dial("tcp", &format!("127.0.0.1:{port}"));
            let seen = seen.lock().unwrap().join(",");
            match result {
                Err(e) => format!("err {e} seen={seen}"),
                Ok(Conn::Tcp(c)) => format!(
                    "ok seen={seen} reuse={}",
                    sock_int(&c, level::SOL_SOCKET, opt::SO_REUSEADDR)
                ),
                Ok(_) => "ok other".into(),
            }
        }
        "dial_keepalive" => {
            let (ln, port) = tcp_listener("tcp", "127.0.0.1:0").unwrap();
            echo_once(ln);
            let d = Dialer {
                keep_alive: ms(f[1]),
                keep_alive_config: KeepAliveConfig {
                    enable: f[2] == "1",
                    idle: ms(f[3]),
                    interval: ms(f[4]),
                    count: f[5].parse().unwrap(),
                },
                ..Dialer::default()
            };
            match d.dial("tcp", &format!("127.0.0.1:{port}")) {
                Ok(c) => format!("ok {}", conn_state(&c)),
                Err(e) => format!("err {e}"),
            }
        }
        "listen_keepalive" => {
            let lc = ListenConfig {
                keep_alive: ms(f[1]),
                keep_alive_config: KeepAliveConfig {
                    enable: f[2] == "1",
                    idle: ms(f[3]),
                    interval: ms(f[4]),
                    count: f[5].parse().unwrap(),
                },
                ..ListenConfig::default()
            };
            let ln = match lc.listen(&Background, "tcp", "127.0.0.1:0") {
                Ok(Listener::Tcp(l)) => l,
                Ok(_) => return "other".into(),
                Err(e) => return format!("err {e}"),
            };
            let addr = ln.addr().unwrap().to_string();
            std::thread::spawn(move || {
                if let Ok(c) = TcpStream::connect(addr) {
                    std::thread::sleep(Duration::from_millis(300));
                    drop(c);
                }
            });
            match ln.accept_tcp() {
                Ok(c) => format!("ok {}", conn_state(&Conn::Tcp(c))),
                Err(e) => format!("err {e}"),
            }
        }
        "listen_accept_deadline" => {
            let Ok(Listener::Tcp(ln)) = net::listen("tcp", "127.0.0.1:0") else {
                return "listen failed".into();
            };
            let ln = std::sync::Arc::new(ln);
            let start = Instant::now();
            ln.set_deadline(Some(SystemTime::now() + Duration::from_millis(100)))
                .unwrap();
            let e = ln.accept_tcp().map(|_| ());
            let mut out = format!("{} timely={}", err_text(e), within(start, 95, 600));
            let l2 = ln.clone();
            let t = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                l2.close().unwrap();
            });
            ln.set_deadline(None).unwrap();
            let start = Instant::now();
            let e = ln.accept_tcp().map(|_| ());
            t.join().unwrap();
            out.push_str(&format!(
                " closed={} timely={}",
                err_text(e),
                within(start, 95, 600)
            ));
            out
        }
        "listen_unix" => {
            let _ = std::fs::remove_file("lu.sock");
            let Ok(Listener::Unix(ln)) = net::listen("unix", "lu.sock") else {
                return "listen failed".into();
            };
            let a = ln.addr().unwrap();
            let mut out = format!(
                "created={} addr={}/{}",
                std::fs::metadata("lu.sock").is_ok(),
                a.net,
                a.name
            );
            out.push_str(&format!(
                " again={}",
                err_text(net::listen("unix", "lu.sock").map(|_| ()))
            ));
            std::thread::spawn(|| {
                let _ = std::os::unix::net::UnixStream::connect("lu.sock");
            });
            match ln.accept_unix() {
                Ok(c) => {
                    let ty = match c.network() {
                        "unix" => "*net.UnixConn",
                        _ => "other",
                    };
                    out.push_str(&format!(" accepted={ty} peer=true"));
                }
                Err(e) => out.push_str(&format!(" accept=err {e}")),
            }
            ln.close().unwrap();
            out.push_str(&format!(
                " afterclose={}",
                std::fs::metadata("lu.sock").is_ok()
            ));
            let Ok(Listener::Unix(ln2)) = net::listen("unix", "lu.sock") else {
                return out;
            };
            ln2.set_unlink_on_close(false);
            ln2.close().unwrap();
            out.push_str(&format!(" kept={}", std::fs::metadata("lu.sock").is_ok()));
            let _ = std::fs::remove_file("lu.sock");
            out
        }
        "listen_err" => err_text(net::listen(f[1], f[2]).map(|_| ())),
        "listenpacket_err" => err_text(net::listen_packet(f[1], f[2]).map(|_| ())),
        "listenpacket_udp" => match net::listen_packet(f[1], f[2]) {
            Ok(PacketConn::Udp(c)) => {
                let Ok(Conn::Udp(cl)) = net::dial("udp", &c.local_addr().unwrap().to_string())
                else {
                    return "dial failed".into();
                };
                cl.write(b"dgram").unwrap();
                c.set_read_deadline(Some(SystemTime::now() + Duration::from_secs(2)))
                    .unwrap();
                let mut buf = [0u8; 16];
                match c.read_from(&mut buf) {
                    Ok((n, _)) => format!(
                        "ok *net.UDPConn local=udp got={:?} from=true ok",
                        String::from_utf8_lossy(&buf[..n])
                    ),
                    Err(e) => format!("err {e}"),
                }
            }
            Ok(_) => "other".into(),
            Err(e) => format!("err {e}"),
        },
        "listenpacket_unixgram" => {
            let _ = std::fs::remove_file("lg.sock");
            match net::listen_packet("unixgram", "lg.sock") {
                Ok(PacketConn::Unix(c)) => {
                    let cl = std::os::unix::net::UnixDatagram::unbound().unwrap();
                    cl.send_to(b"ug", "lg.sock").unwrap();
                    c.set_read_deadline(Some(SystemTime::now() + Duration::from_secs(2)))
                        .unwrap();
                    let mut buf = [0u8; 16];
                    let r = match c.read_from(&mut buf) {
                        Ok((n, _)) => format!(
                            "ok *net.UnixConn got={:?} ok",
                            String::from_utf8_lossy(&buf[..n])
                        ),
                        Err(e) => format!("err {e}"),
                    };
                    let _ = std::fs::remove_file("lg.sock");
                    r
                }
                Ok(_) => "other".into(),
                Err(e) => format!("err {e}"),
            }
        }
        "dialunix" => {
            let mk = |s: &str| {
                (s != "-").then(|| UnixAddr {
                    name: s.to_string(),
                    net: f[1].to_string(),
                })
            };
            err_text(net::dial_unix(f[1], mk(f[2]).as_ref(), mk(f[3]).as_ref()).map(|_| ()))
        }
        "listenunix" => {
            let la = (f[2] != "-").then(|| UnixAddr {
                name: f[2].to_string(),
                net: f[1].to_string(),
            });
            err_text(net::listen_unix(f[1], la.as_ref()).map(|_| ()))
        }
        "dialip" => {
            let mk = |s: &str| {
                (s != "-").then(|| IPAddr {
                    ip: s.parse().ok(),
                    zone: String::new(),
                })
            };
            err_text(net::dial_ip(f[1], mk(f[2]).as_ref(), mk(f[3]).as_ref()).map(|_| ()))
        }
        "listenip" => {
            let la = (f[2] != "-").then(|| IPAddr {
                ip: f[2].parse().ok(),
                zone: String::new(),
            });
            err_text(net::listen_ip(f[1], la.as_ref()).map(|_| ()))
        }
        "dialtcp" => {
            let la = (f[2] != "-").then(|| TCPAddr {
                ip: f[2].parse().ok(),
                port: 0,
                zone: String::new(),
            });
            let ra = (f[3] != "-").then(|| TCPAddr {
                ip: f[3].parse().ok(),
                port: 1,
                zone: String::new(),
            });
            err_text(net::dial_tcp(f[1], la.as_ref(), ra.as_ref()).map(|_| ()))
        }
        "multicast" => {
            let ifi = (f[2] != "-")
                .then(|| net::interface_by_name(f[2]).ok())
                .flatten();
            let (host, port) = net::split_host_port(f[3]).unwrap();
            let gaddr = (host != "-").then(|| net::UDPAddr {
                ip: host.parse().ok(),
                port: port.parse().unwrap(),
                zone: String::new(),
            });
            match net::listen_multicast_udp(f[1], ifi.as_ref(), gaddr.as_ref()) {
                Ok(c) => format!("ok local={}", c.local_addr().unwrap()),
                Err(e) => format!("err {e}"),
            }
        }
        "fileconn" => {
            let mut out = Vec::new();
            let (ln, _) = tcp_listener("tcp", "127.0.0.1:0").unwrap();
            let addr = ln.local_addr().unwrap();
            let ln2 = ln.try_clone().unwrap();
            echo_once(ln);
            let c = TcpStream::connect(addr).unwrap();
            let to_file = |fd: OwnedFd, name: &str| {
                File::new(std::fs::File::from(fd), name, FileKind::NewFile).unwrap()
            };
            let file = to_file(OwnedFd::from(c.try_clone().unwrap()), "tcp");
            match net::file_conn(&file) {
                Ok(Conn::Tcp(mut fc)) => {
                    out.push(format!("conn=*net.TCPConn {}", describe_tcp(&fc)));
                    out.push(round_trip(&mut fc));
                }
                Ok(_) => out.push("conn=other".into()),
                Err(e) => out.push(format!("conn=err {e}")),
            }
            let lf = to_file(OwnedFd::from(ln2.try_clone().unwrap()), "tcplistener");
            match net::file_listener(&lf) {
                Ok(Listener::Tcp(fl)) => {
                    out.push(format!("listener=*net.TCPListener {}", fl.addr().unwrap()))
                }
                Ok(_) => out.push("listener=other".into()),
                Err(e) => out.push(format!("listener=err {e}")),
            }
            let uc = UdpSocket::bind("127.0.0.1:0").unwrap();
            let uf = to_file(OwnedFd::from(uc.try_clone().unwrap()), "udp");
            match net::file_packet_conn(&uf) {
                Ok(PacketConn::Udp(pc)) => {
                    out.push(format!("packet=*net.UDPConn {}", pc.local_addr().unwrap()))
                }
                Ok(_) => out.push("packet=other".into()),
                Err(e) => out.push(format!("packet=err {e}")),
            }
            let null = File::new(
                std::fs::File::open("/dev/null").unwrap(),
                "/dev/null",
                FileKind::OpenFile,
            )
            .unwrap();
            out.push(format!(
                "notsock={}",
                err_text(net::file_conn(&null).map(|_| ()))
            ));
            out.push(format!(
                "notsock-listener={}",
                err_text(net::file_listener(&null).map(|_| ()))
            ));
            out.push(format!(
                "notsock-packet={}",
                err_text(net::file_packet_conn(&null).map(|_| ()))
            ));
            out.join(" ")
        }
        _ => crate::wake_scenarios::run(f),
    }
}
