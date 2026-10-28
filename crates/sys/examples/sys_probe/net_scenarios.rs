//! Network scenarios of the Go differential; see tools/sys_oracle_net.go.
use rust_stdlib_sys::net::{self, level, opt, KeepAliveConfig};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::unix::net::{UnixListener, UnixStream};

fn err_text<E: std::fmt::Display>(r: Result<(), E>) -> String {
    match r {
        Ok(()) => "ok".into(),
        Err(e) => format!("err {e}"),
    }
}

fn sorted(items: impl Iterator<Item = String>) -> String {
    let mut v: Vec<String> = items.collect();
    v.sort();
    v.join(",")
}

fn iface_line(i: &net::Interface) -> String {
    format!(
        "{}/{}/{}/{}/{}",
        i.name,
        i.index,
        i.mtu,
        i.flags,
        net::hardware_addr_string(&i.hardware_addr)
    )
}

fn sock_int<S: net::AsSocket + ?Sized>(s: &S, lvl: i32, name: i32) -> String {
    match net::getsockopt_int(s, lvl, name) {
        Ok(v) => v.to_string(),
        Err(e) => format!("err {}", e.err),
    }
}

fn tcp_state(c: &TcpStream) -> String {
    let linger = match net::getsockopt_linger(c) {
        Ok(l) => format!("{},{}", l.onoff, l.linger),
        Err(e) => format!("err {}", e.err),
    };
    format!(
        "linger={} rcvbuf={} sndbuf={} keepalive={} idle={} intvl={} cnt={} nodelay={}",
        linger,
        sock_int(c, level::SOL_SOCKET, opt::SO_RCVBUF),
        sock_int(c, level::SOL_SOCKET, opt::SO_SNDBUF),
        sock_int(c, level::SOL_SOCKET, opt::SO_KEEPALIVE),
        sock_int(c, level::IPPROTO_TCP, opt::TCP_KEEPIDLE),
        sock_int(c, level::IPPROTO_TCP, opt::TCP_KEEPINTVL),
        sock_int(c, level::IPPROTO_TCP, opt::TCP_KEEPCNT),
        sock_int(c, level::IPPROTO_TCP, opt::TCP_NODELAY),
    )
}

fn ms(s: &str) -> i64 {
    s.parse::<i64>().unwrap() * 1_000_000
}

fn buffers<S: net::AsSocket>(s: &S, ops: &str) -> String {
    let mut out = Vec::new();
    for op in ops.split_whitespace() {
        let (kind, n) = op.split_once(':').unwrap();
        let n: i64 = n.parse().unwrap();
        let r = if kind == "rcvbuf" {
            net::set_read_buffer(s, n)
        } else {
            net::set_write_buffer(s, n)
        };
        out.push(format!(
            "{op}={} rcvbuf={} sndbuf={}",
            err_text(r),
            sock_int(s, level::SOL_SOCKET, opt::SO_RCVBUF),
            sock_int(s, level::SOL_SOCKET, opt::SO_SNDBUF)
        ));
    }
    out.join(" | ")
}

pub fn run(f: &[&str]) -> String {
    match f[0] {
        "ifaces" => match net::interfaces() {
            Ok(list) => format!(
                "ifaces {}",
                list.iter().map(iface_line).collect::<Vec<_>>().join(";")
            ),
            Err(e) => format!("err {e}"),
        },
        "ifaddrs" => {
            let list = match net::interfaces() {
                Ok(l) => l,
                Err(e) => return format!("err {e}"),
            };
            let mut out = Vec::new();
            for i in &list {
                let a = i.addrs().unwrap();
                let m = i.multicast_addrs().unwrap();
                out.push(format!(
                    "{}=[{}]+[{}]",
                    i.name,
                    sorted(a.iter().map(|x| x.to_string())),
                    sorted(m.iter().map(|x| x.to_string()))
                ));
            }
            let all = net::interface_addrs().unwrap();
            format!(
                "ifaddrs {} all={}",
                out.join(";"),
                sorted(all.iter().map(|x| x.to_string()))
            )
        }
        "iflookup" => {
            let list = net::interfaces().unwrap();
            let mut out = Vec::new();
            for i in &list {
                let by_name = net::interface_by_name(&i.name);
                let by_index = net::interface_by_index(i.index as i64);
                out.push(format!(
                    "{}:{}:{}:{}",
                    i.name,
                    by_name.as_ref().map(|x| x == i).unwrap_or(false),
                    by_index.as_ref().map(|x| x == i).unwrap_or(false),
                    by_name.is_ok() && by_index.is_ok()
                ));
            }
            for name in ["", "nosuch0", "lo0lo0"] {
                out.push(err_text(net::interface_by_name(name).map(|_| ())));
            }
            for idx in [0, -1, 99999] {
                out.push(err_text(net::interface_by_index(idx).map(|_| ())));
            }
            format!("iflookup {}", out.join(";"))
        }
        "tcpopts" => {
            let ln = TcpListener::bind("127.0.0.1:0").unwrap();
            let c = TcpStream::connect(ln.local_addr().unwrap()).unwrap();
            let _s = ln.accept().unwrap();
            // Go sets TCP_NODELAY on every connection it creates.
            c.set_nodelay(true).unwrap();
            // macOS re-sizes a fresh connection's receive buffer to its
            // autotuned size (265408) a few milliseconds after connect,
            // overriding a SO_RCVBUF set in that window; the Go oracle waits
            // the same time so the option results are stable.
            std::thread::sleep(std::time::Duration::from_millis(50));
            let mut out = vec![format!("base {}", tcp_state(&c))];
            for op in f[1].split_whitespace() {
                let p: Vec<&str> = op.split(':').collect();
                let r = match p[0] {
                    "linger" => net::set_linger(&c, p[1].parse().unwrap()),
                    "rcvbuf" => net::set_read_buffer(&c, p[1].parse().unwrap()),
                    "sndbuf" => net::set_write_buffer(&c, p[1].parse().unwrap()),
                    "nodelay" => net::set_no_delay(&c, p[1] == "1"),
                    "keepalive" => net::set_keep_alive(&c, p[1] == "1"),
                    "period" => net::set_keep_alive_period(&c, ms(p[1])),
                    "cfg" => net::set_keep_alive_config(
                        &c,
                        &KeepAliveConfig {
                            enable: p[1] == "1",
                            idle: ms(p[2]),
                            interval: ms(p[3]),
                            count: p[4].parse().unwrap(),
                        },
                    ),
                    _ => Ok(()),
                };
                out.push(format!("{op}={} {}", err_text(r), tcp_state(&c)));
            }
            out.join(" | ")
        }
        "udpopts" => {
            let c = UdpSocket::bind("127.0.0.1:0").unwrap();
            buffers(&c, f[1])
        }
        "unixopts" => {
            let path = "u.sock";
            let _ = std::fs::remove_file(path);
            let ln = UnixListener::bind(path).unwrap();
            let c = UnixStream::connect(path).unwrap();
            let _s = ln.accept().unwrap();
            buffers(&c, f[1])
        }
        "rawconn" => {
            let ln = TcpListener::bind("127.0.0.1:0").unwrap();
            let c = TcpStream::connect(ln.local_addr().unwrap()).unwrap();
            let (mut s, _) = ln.accept().unwrap();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(100));
                let _ = std::io::Write::write_all(&mut s, b"y");
            });
            // Go's descriptors are non-blocking; its raw read sees EAGAIN.
            c.set_nonblocking(true).unwrap();
            let mut out = vec![format!(
                "type={}",
                sock_int(&c, level::SOL_SOCKET, opt::SO_TYPE)
            )];
            let rc = net::syscall_conn(&c).unwrap();
            let mut calls = 0;
            let mut got = String::new();
            let r = rc.read(|_| {
                calls += 1;
                let mut buf = [0u8; 1];
                match std::io::Read::read(&mut &c, &mut buf) {
                    Ok(n) => {
                        got = String::from_utf8_lossy(&buf[..n]).into_owned();
                        true
                    }
                    Err(_) => false,
                }
            });
            out.push(format!("read={} calls={calls} got={got:?}", err_text(r)));
            calls = 0;
            let r = rc.write(|_| {
                calls += 1;
                true
            });
            out.push(format!("write={} calls={calls}", err_text(r)));
            let lrc = net::syscall_listener(&ln).unwrap();
            let mut ctl = false;
            let r = lrc.control(|_| ctl = true);
            out.push(format!("lctl={} {ctl}", err_text(r)));
            out.push(format!("lread={}", err_text(lrc.read(|_| true))));
            out.push(format!("lwrite={}", err_text(lrc.write(|_| true))));
            out.join(" ")
        }
        "badfd" => {
            struct Raw(i32);
            impl net::AsSocket for Raw {
                fn socket_fd(&self) -> i32 {
                    self.0
                }
            }
            let a = net::setsockopt_int(&Raw(999), level::SOL_SOCKET, opt::SO_RCVBUF, 1)
                .map_err(|e| e.err);
            // A character device is not a socket.
            let null = std::fs::File::open("/dev/null").unwrap();
            let b =
                net::setsockopt_int(&null, level::SOL_SOCKET, opt::SO_RCVBUF, 1).map_err(|e| e.err);
            format!("badfd {} | {}", err_text(a), err_text(b))
        }
        _ => crate::msg_scenarios::run(f),
    }
}
