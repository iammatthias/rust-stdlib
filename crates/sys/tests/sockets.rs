//! Loopback tests of interfaces, socket options, message I/O, dialing and
//! listening.
#![cfg(all(
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64"
))]
use rust_stdlib_sys::net::{
    self, level, opt, Addr, Background, Cause, Conn, Context, ContextError, Dialer,
    KeepAliveConfig, ListenConfig, Listener, PacketConn, ResolvedAddr, TCPAddr, UDPAddr, UnixAddr,
};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sys-net-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn tcp_pair() -> (TcpStream, TcpStream) {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let c = TcpStream::connect(ln.local_addr().unwrap()).unwrap();
    let (s, _) = ln.accept().unwrap();
    (c, s)
}

#[test]
fn interfaces_include_the_loopback() {
    let all = net::interfaces().unwrap();
    assert!(!all.is_empty());
    let lo = all
        .iter()
        .find(|i| i.flags.0 & net::FLAG_LOOPBACK.0 != 0)
        .expect("a loopback interface");
    assert!(lo.index > 0);
    assert!(lo.mtu > 0);
    assert_eq!(lo.flags.0 & net::FLAG_UP.0, net::FLAG_UP.0);
    // Lookups by name and index agree with the table.
    assert_eq!(&net::interface_by_name(&lo.name).unwrap(), lo);
    assert_eq!(&net::interface_by_index(i64::from(lo.index)).unwrap(), lo);
    // Its addresses include 127.0.0.1/8.
    let addrs: Vec<String> = lo.addrs().unwrap().iter().map(|a| a.to_string()).collect();
    assert!(addrs.iter().any(|a| a == "127.0.0.1/8"), "{addrs:?}");
    let all_addrs = net::interface_addrs().unwrap();
    assert!(all_addrs.iter().any(|a| a.to_string() == "127.0.0.1/8"));
    // Every address belongs to some interface and has a canonical or hex mask.
    for a in &all_addrs {
        assert!(a.to_string().contains('/'));
    }
    lo.multicast_addrs().unwrap();
}

#[test]
fn interface_lookup_errors_match_go() {
    assert_eq!(
        net::interface_by_name("").unwrap_err().to_string(),
        "route ip+net: invalid network interface name"
    );
    assert_eq!(
        net::interface_by_name("no-such-if0")
            .unwrap_err()
            .to_string(),
        "route ip+net: no such network interface"
    );
    assert_eq!(
        net::interface_by_index(0).unwrap_err().to_string(),
        "route ip+net: invalid network interface index"
    );
    assert_eq!(
        net::interface_by_index(-4).unwrap_err().to_string(),
        "route ip+net: invalid network interface index"
    );
    assert_eq!(
        net::interface_by_index(1 << 30).unwrap_err().to_string(),
        "route ip+net: no such network interface"
    );
}

#[test]
fn socket_options_round_trip() {
    let (c, _s) = tcp_pair();
    net::set_linger(&c, 7).unwrap();
    let l = net::getsockopt_linger(&c).unwrap();
    assert_eq!((l.onoff, l.linger), (1, 7));
    net::set_linger(&c, -1).unwrap();
    assert_eq!(net::getsockopt_linger(&c).unwrap().onoff, 0);
    net::set_read_buffer(&c, 65536).unwrap();
    net::set_write_buffer(&c, 32768).unwrap();
    assert!(net::getsockopt_int(&c, level::SOL_SOCKET, opt::SO_RCVBUF).unwrap() >= 32768);
    assert!(net::getsockopt_int(&c, level::SOL_SOCKET, opt::SO_SNDBUF).unwrap() >= 16384);
    net::set_keep_alive(&c, true).unwrap();
    assert_ne!(
        net::getsockopt_int(&c, level::SOL_SOCKET, opt::SO_KEEPALIVE).unwrap(),
        0
    );
    net::set_keep_alive_period(&c, 61_000_000_000).unwrap();
    assert_eq!(
        net::getsockopt_int(&c, level::IPPROTO_TCP, opt::TCP_KEEPIDLE).unwrap(),
        61
    );
    // Durations round up to whole seconds; zero is the default; negative leaves it alone.
    net::set_keep_alive_period(&c, 1_500_000_000).unwrap();
    assert_eq!(
        net::getsockopt_int(&c, level::IPPROTO_TCP, opt::TCP_KEEPIDLE).unwrap(),
        2
    );
    net::set_keep_alive_period(&c, 0).unwrap();
    assert_eq!(
        net::getsockopt_int(&c, level::IPPROTO_TCP, opt::TCP_KEEPIDLE).unwrap(),
        15
    );
    net::set_keep_alive_period(&c, -1).unwrap();
    assert_eq!(
        net::getsockopt_int(&c, level::IPPROTO_TCP, opt::TCP_KEEPIDLE).unwrap(),
        15
    );
    net::set_keep_alive_config(
        &c,
        &KeepAliveConfig {
            enable: true,
            idle: 3_000_000_000,
            interval: 4_000_000_000,
            count: 5,
        },
    )
    .unwrap();
    assert_eq!(
        net::getsockopt_int(&c, level::IPPROTO_TCP, opt::TCP_KEEPIDLE).unwrap(),
        3
    );
    assert_eq!(
        net::getsockopt_int(&c, level::IPPROTO_TCP, opt::TCP_KEEPINTVL).unwrap(),
        4
    );
    assert_eq!(
        net::getsockopt_int(&c, level::IPPROTO_TCP, opt::TCP_KEEPCNT).unwrap(),
        5
    );
    net::set_no_delay(&c, true).unwrap();
}

#[test]
fn socket_option_errors_name_the_call() {
    let (c, _s) = tcp_pair();
    let err = if cfg!(target_os = "linux") {
        // Linux clamps SO_RCVBUF 0 to its minimum, but caps TCP_KEEPCNT at 127.
        net::set_read_buffer(&c, 0).unwrap();
        let config = KeepAliveConfig {
            enable: true,
            idle: 0,
            interval: 0,
            count: 1000,
        };
        net::set_keep_alive_config(&c, &config).unwrap_err()
    } else {
        net::set_read_buffer(&c, 0).unwrap_err()
    };
    assert!(err.to_string().starts_with("set tcp 127.0.0.1:"), "{err}");
    assert!(
        err.to_string().ends_with("setsockopt: invalid argument"),
        "{err}"
    );
    assert_eq!(err.errno(), Some(rust_stdlib_sys::errno::EINVAL));
    let null = std::fs::File::open("/dev/null").unwrap();
    let err = net::set_linger(&null, 1).unwrap_err();
    assert_eq!(err.errno(), Some(rust_stdlib_sys::errno::ENOTSOCK));
}

#[test]
fn raw_conn_control_and_listener_restrictions() {
    let (c, _s) = tcp_pair();
    let rc = net::syscall_conn(&c).unwrap();
    let mut seen = -1;
    rc.control(|fd| seen = fd).unwrap();
    assert!(seen >= 0);
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let lrc = net::syscall_listener(&ln).unwrap();
    assert_eq!(
        lrc.read(|_| true).unwrap_err().to_string(),
        "invalid argument"
    );
    assert_eq!(
        lrc.write(|_| true).unwrap_err().to_string(),
        "invalid argument"
    );
    lrc.control(|_| {}).unwrap();
}

#[test]
fn udp_messages_carry_the_sender() {
    let a = UdpSocket::bind("127.0.0.1:0").unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").unwrap();
    a.set_nonblocking(true).unwrap();
    b.set_nonblocking(true).unwrap();
    let to = UDPAddr {
        ip: Some(a.local_addr().unwrap().ip()),
        port: a.local_addr().unwrap().port(),
        zone: String::new(),
    };
    let (n, oobn) = net::write_msg_udp(&b, b"hello", &[], Some(&to)).unwrap();
    assert_eq!((n, oobn), (5, 0));
    let mut buf = [0u8; 16];
    let got = net::read_msg_udp(&a, &mut buf, &mut []).unwrap();
    assert_eq!(&buf[..got.n], b"hello");
    assert_eq!(got.addr.unwrap().port, b.local_addr().unwrap().port());
    // A short buffer truncates and reports it.
    net::write_msg_udp(&b, b"0123456789", &[], Some(&to)).unwrap();
    let got = net::read_msg_udp(&a, &mut buf[..4], &mut []).unwrap();
    assert_eq!(got.n, 4);
    assert_ne!(got.flags, 0);
    // Connected sockets reject an explicit address; unconnected need one.
    b.connect(a.local_addr().unwrap()).unwrap();
    assert!(net::write_msg_udp(&b, b"x", &[], Some(&to))
        .unwrap_err()
        .to_string()
        .ends_with("use of WriteTo with pre-connected connection"));
    assert!(net::write_msg_udp(&a, b"x", &[], None)
        .unwrap_err()
        .to_string()
        .ends_with(": missing address"));
    net::write_msg_udp(&b, b"via-connect", &[], None).unwrap();
    let got = net::read_msg_udp(&a, &mut buf, &mut []).unwrap();
    assert_eq!(&buf[..got.n], b"via-connect");
}

#[test]
fn udp_ttl_ancillary_data() {
    let a = UdpSocket::bind("127.0.0.1:0").unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").unwrap();
    net::setsockopt_int(&a, level::IPPROTO_IP, opt::IP_RECVTTL, 1).unwrap();
    b.connect(a.local_addr().unwrap()).unwrap();
    net::write_msg_udp(&b, b"t", &[], None).unwrap();
    let mut buf = [0u8; 4];
    let mut oob = [0u8; 64];
    a.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let got = net::read_msg_udp(&a, &mut buf, &mut oob).unwrap();
    assert_eq!(got.n, 1);
    assert!(got.oobn >= 12, "control message of {} bytes", got.oobn);
}

#[test]
fn unix_messages_pass_descriptors() {
    use std::os::fd::AsRawFd;
    let dir = scratch("unixmsg");
    let server_path = dir.join("s.sock");
    let client_path = dir.join("c.sock");
    let server = UnixDatagram::bind(&server_path).unwrap();
    let client = UnixDatagram::bind(&client_path).unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    // Pass the read end of a pipe along with the datagram.
    let (r, w) = rust_stdlib_sys::os::pipe().unwrap();
    let oob = net::unix_rights(&[r.as_raw_fd()]);
    let to = UnixAddr {
        name: server_path.to_str().unwrap().to_string(),
        net: "unixgram".into(),
    };
    let (n, oobn) = net::write_msg_unix(&client, b"fd", &oob, Some(&to)).unwrap();
    assert_eq!((n, oobn), (2, oob.len()));
    let mut buf = [0u8; 8];
    let mut got_oob = [0u8; 64];
    let got = net::read_msg_unix(&server, &mut buf, &mut got_oob).unwrap();
    assert_eq!(&buf[..got.n], b"fd");
    assert_eq!(
        got.addr.as_ref().unwrap().name,
        client_path.to_str().unwrap()
    );
    assert_eq!(got.addr.unwrap().net, "unixgram");
    let fds = net::parse_unix_rights(&got_oob[..got.oobn]).unwrap();
    assert_eq!(fds.len(), 1);
    assert!(fds[0] > 2);
    // Pull data through the received descriptor.
    w.write(b"through").unwrap();
    let mut via = std::fs::File::open(format!("/dev/fd/{}", fds[0])).unwrap();
    let mut data = [0u8; 7];
    via.read_exact(&mut data).unwrap();
    assert_eq!(&data, b"through");
    // Network mismatch is EAFNOSUPPORT; an unconnected datagram needs a name,
    // which Linux reports as ENOTCONN and macOS as EDESTADDRREQ.
    let wrong = UnixAddr {
        name: to.name.clone(),
        net: "unix".into(),
    };
    assert_eq!(
        net::write_msg_unix(&client, b"x", &[], Some(&wrong))
            .unwrap_err()
            .errno(),
        Some(rust_stdlib_sys::errno::EAFNOSUPPORT)
    );
    assert_eq!(
        net::write_msg_unix(&client, b"x", &[], None)
            .unwrap_err()
            .errno(),
        Some(if cfg!(target_os = "linux") {
            rust_stdlib_sys::errno::ENOTCONN
        } else {
            rust_stdlib_sys::errno::EDESTADDRREQ
        })
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn dial_reports_go_errors() {
    let text =
        |network: &str, address: &str| net::dial(network, address).err().unwrap().to_string();
    assert_eq!(
        text("tcp", "127.0.0.1:1"),
        "dial tcp 127.0.0.1:1: connect: connection refused"
    );
    assert_eq!(text("tcp", ""), "dial tcp: missing address");
    assert_eq!(
        text("tcp", "1.2.3.4"),
        "dial tcp: address 1.2.3.4: missing port in address"
    );
    assert_eq!(text("tcpx", "1.2.3.4:1"), "dial tcpx: unknown network tcpx");
    assert_eq!(
        text("udp", "127.0.0.1:99999"),
        "dial udp: address 99999: invalid port"
    );
    assert_eq!(text("unix", ""), "dial unix: missing address");
    assert_eq!(
        text("unix", "/no/such.sock"),
        "dial unix /no/such.sock: connect: no such file or directory"
    );
    assert_eq!(
        text("tcp6", "127.0.0.1:80"),
        "dial tcp6: address 127.0.0.1: no suitable address found"
    );
    assert_eq!(
        text("ip4:foo", "127.0.0.1"),
        "dial ip4:foo: address foo: unknown IP protocol specified"
    );
    // Raw IP sockets need privileges: refused unless running as root.
    if net::interfaces().is_ok() && rust_stdlib_sys::os::geteuid() != 0 {
        assert_eq!(
            text("ip4:icmp", "127.0.0.1"),
            "dial ip4:icmp 127.0.0.1: socket: operation not permitted"
        );
    }
}

#[test]
fn dial_and_listen_over_loopback() {
    let Listener::Tcp(ln) = net::listen("tcp", "127.0.0.1:0").unwrap() else {
        panic!("not a TCP listener");
    };
    let addr = ln.addr().unwrap();
    assert_eq!(addr.network(), "tcp");
    let server = std::thread::spawn(move || {
        let mut c = ln.accept_tcp().unwrap();
        let mut buf = [0u8; 4];
        c.read_exact(&mut buf).unwrap();
        c.write_all(&buf).unwrap();
        // Accepted connections come with Go's keep-alive defaults.
        let idle = net::getsockopt_int(&c, level::IPPROTO_TCP, opt::TCP_KEEPIDLE).unwrap();
        (
            idle,
            net::getsockopt_int(&c, level::IPPROTO_TCP, opt::TCP_NODELAY).unwrap() != 0,
        )
    });
    let Conn::Tcp(mut c) = net::dial("tcp", &addr.to_string()).unwrap() else {
        panic!("not a TCP connection");
    };
    c.write_all(b"ping").unwrap();
    let mut buf = [0u8; 4];
    c.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"ping");
    assert_eq!(
        net::getsockopt_int(&c, level::IPPROTO_TCP, opt::TCP_KEEPIDLE).unwrap(),
        15
    );
    let (idle, nodelay) = server.join().unwrap();
    assert_eq!(idle, 15);
    assert!(nodelay);
}

#[test]
fn dialer_options_apply() {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = ln.local_addr().unwrap().port();
    // Disabled keep-alive.
    let d = Dialer {
        keep_alive: -1,
        ..Dialer::default()
    };
    let Conn::Tcp(c) = d.dial("tcp", &format!("127.0.0.1:{port}")).unwrap() else {
        panic!()
    };
    assert_eq!(
        net::getsockopt_int(&c, level::SOL_SOCKET, opt::SO_KEEPALIVE).unwrap(),
        0
    );
    // Explicit config.
    let d = Dialer {
        keep_alive_config: KeepAliveConfig {
            enable: true,
            idle: 9_000_000_000,
            interval: 8_000_000_000,
            count: 3,
        },
        ..Dialer::default()
    };
    let Conn::Tcp(c) = d.dial("tcp", &format!("127.0.0.1:{port}")).unwrap() else {
        panic!()
    };
    assert_eq!(
        net::getsockopt_int(&c, level::IPPROTO_TCP, opt::TCP_KEEPIDLE).unwrap(),
        9
    );
    assert_eq!(
        net::getsockopt_int(&c, level::IPPROTO_TCP, opt::TCP_KEEPINTVL).unwrap(),
        8
    );
    assert_eq!(
        net::getsockopt_int(&c, level::IPPROTO_TCP, opt::TCP_KEEPCNT).unwrap(),
        3
    );
    // A local address binds the source.
    let d = Dialer {
        local_addr: Some(ResolvedAddr::Tcp(TCPAddr {
            ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            port: 0,
            zone: String::new(),
        })),
        ..Dialer::default()
    };
    let Conn::Tcp(c) = d.dial("tcp", &format!("127.0.0.1:{port}")).unwrap() else {
        panic!()
    };
    assert_eq!(
        c.local_addr().unwrap().ip,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
    );
    // A mismatched local address type is rejected.
    let d = Dialer {
        local_addr: Some(ResolvedAddr::Udp(UDPAddr {
            ip: None,
            port: 0,
            zone: String::new(),
        })),
        ..Dialer::default()
    };
    assert_eq!(
        d.dial("tcp", &format!("127.0.0.1:{port}"))
            .err()
            .unwrap()
            .to_string(),
        "dial tcp: address :0: mismatched local address type"
    );
    // Multipath TCP is a request: dials work either way.
    let mut d = Dialer::default();
    assert!(!d.multipath_tcp());
    d.set_multipath_tcp(true);
    assert!(d.multipath_tcp());
    d.dial("tcp", &format!("127.0.0.1:{port}")).unwrap();
}

#[test]
fn control_hooks_see_the_socket_before_connect() {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = ln.local_addr().unwrap().port();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    let d = Dialer {
        control: Some(Box::new(move |network, address, rc| {
            log.lock().unwrap().push(format!("{network}|{address}"));
            rc.control(|fd| assert!(fd >= 0))
                .map_err(std::io::Error::other)
        })),
        ..Dialer::default()
    };
    d.dial("tcp", &format!("127.0.0.1:{port}")).unwrap();
    assert_eq!(
        *seen.lock().unwrap(),
        vec![format!("tcp4|127.0.0.1:{port}")]
    );
    // An error from the hook fails the dial with its text.
    let d = Dialer {
        control: Some(Box::new(|_, _, _| Err(std::io::Error::other("boom")))),
        ..Dialer::default()
    };
    assert_eq!(
        d.dial("tcp", &format!("127.0.0.1:{port}"))
            .err()
            .unwrap()
            .to_string(),
        format!("dial tcp 127.0.0.1:{port}: boom")
    );
    // ControlContext takes precedence over Control.
    let d = Dialer {
        control: Some(Box::new(|_, _, _| Err(std::io::Error::other("wrong")))),
        control_context: Some(Box::new(|ctx, network, _, _| {
            assert!(ctx.err().is_none());
            assert_eq!(network, "tcp4");
            Ok(())
        })),
        ..Dialer::default()
    };
    d.dial("tcp", &format!("127.0.0.1:{port}")).unwrap();
    // Listeners have a hook too.
    let lc = ListenConfig {
        control: Some(Box::new(|network, address, _| {
            assert_eq!(network, "tcp4");
            assert_eq!(address, "127.0.0.1:0");
            Ok(())
        })),
        ..ListenConfig::default()
    };
    lc.listen(&Background, "tcp", "127.0.0.1:0").unwrap();
}

struct Canceled(AtomicBool);

impl Context for Canceled {
    fn deadline(&self) -> Option<SystemTime> {
        None
    }
    fn err(&self) -> Option<ContextError> {
        self.0
            .load(Ordering::SeqCst)
            .then_some(ContextError::Canceled)
    }
}

#[test]
fn dial_honours_timeouts_and_cancellation() {
    // A non-routable address: the dial times out rather than failing.
    let start = Instant::now();
    let err = net::dial_timeout("tcp", "10.255.255.1:81", 150_000_000)
        .err()
        .unwrap();
    if err.timeout() {
        assert_eq!(err.to_string(), "dial tcp 10.255.255.1:81: i/o timeout");
        assert!(start.elapsed() < Duration::from_secs(5));
    }
    let ctx = std::sync::Arc::new(Canceled(AtomicBool::new(false)));
    let c2 = ctx.clone();
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        c2.0.store(true, Ordering::SeqCst);
    });
    let start = Instant::now();
    let err = Dialer::default()
        .dial_context(&*ctx, "tcp", "10.255.255.1:81")
        .err()
        .unwrap();
    t.join().unwrap();
    if start.elapsed() < Duration::from_secs(3) {
        assert_eq!(
            err.to_string(),
            "dial tcp 10.255.255.1:81: operation was canceled"
        );
    }
}

#[test]
fn listener_accept_deadline_and_close() {
    let Listener::Tcp(ln) = net::listen("tcp", "127.0.0.1:0").unwrap() else {
        panic!()
    };
    let ln = std::sync::Arc::new(ln);
    ln.set_deadline(Some(SystemTime::now() + Duration::from_millis(60)))
        .unwrap();
    let start = Instant::now();
    let err = ln.accept_tcp().unwrap_err();
    assert!(err.timeout());
    assert!(err.to_string().ends_with(": i/o timeout"), "{err}");
    assert!(start.elapsed() >= Duration::from_millis(55));
    ln.set_deadline(None).unwrap();
    let l2 = ln.clone();
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(80));
        l2.close().unwrap();
    });
    let err = ln.accept_tcp().unwrap_err();
    t.join().unwrap();
    assert!(
        err.to_string()
            .ends_with(": use of closed network connection"),
        "{err}"
    );
    assert!(ln.close().is_err());
}

/// Runs `block` on this thread while `wake` runs on another after 30 ms; the
/// blocked call must return within 40 ms of the change.
fn woken_promptly<T>(wake: impl FnOnce() + Send + 'static, block: impl FnOnce() -> T) -> T {
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(30));
        let t0 = Instant::now();
        wake();
        t0
    });
    let r = block();
    let done = Instant::now();
    let t0 = t.join().unwrap();
    assert!(
        done > t0 && done - t0 < Duration::from_millis(100),
        "woke after {:?}",
        done - t0
    );
    r
}

#[test]
fn conns_wake_on_deadline_change_and_close() {
    use std::sync::Arc;
    let Listener::Tcp(ln) = net::listen("tcp", "127.0.0.1:0").unwrap() else {
        panic!()
    };
    let addr = ln.addr().unwrap().to_string();
    let Conn::Tcp(c) = net::dial("tcp", &addr).unwrap() else {
        panic!()
    };
    let _server = ln.accept_tcp().unwrap();
    let c = Arc::new(c);
    // A new read deadline wakes a blocked read.
    let c2 = c.clone();
    let err = woken_promptly(
        move || c2.set_read_deadline(Some(SystemTime::now())).unwrap(),
        || c.read(&mut [0u8; 4]).unwrap_err(),
    );
    assert!(err.timeout(), "{err}");
    // Close wakes it with the closed-connection error.
    c.set_deadline(None).unwrap();
    let c2 = c.clone();
    let err = woken_promptly(
        move || c2.close().unwrap(),
        || c.read(&mut [0u8; 4]).unwrap_err(),
    );
    assert!(
        err.to_string()
            .ends_with(": use of closed network connection"),
        "{err}"
    );
    // UDP and listeners likewise.
    let PacketConn::Udp(u) = net::listen_packet("udp", "127.0.0.1:0").unwrap() else {
        panic!()
    };
    let u = Arc::new(u);
    let u2 = u.clone();
    let err = woken_promptly(
        move || u2.close().unwrap(),
        || u.read_from_udp(&mut [0u8; 4]).unwrap_err(),
    );
    assert!(
        err.to_string()
            .ends_with(": use of closed network connection"),
        "{err}"
    );
    let ln = Arc::new(ln);
    let l2 = ln.clone();
    let err = woken_promptly(
        move || l2.set_deadline(Some(SystemTime::now())).unwrap(),
        || ln.accept_tcp().unwrap_err(),
    );
    assert!(err.timeout(), "{err}");
}

#[test]
fn extending_a_deadline_keeps_the_call_blocked() {
    use std::sync::Arc;
    let Listener::Tcp(ln) = net::listen("tcp", "127.0.0.1:0").unwrap() else {
        panic!()
    };
    let Conn::Tcp(c) = net::dial("tcp", &ln.addr().unwrap().to_string()).unwrap() else {
        panic!()
    };
    let mut server = ln.accept_tcp().unwrap();
    let c = Arc::new(c);
    c.set_read_deadline(Some(SystemTime::now() + Duration::from_millis(40)))
        .unwrap();
    let c2 = c.clone();
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(10));
        c2.set_read_deadline(Some(SystemTime::now() + Duration::from_secs(10)))
            .unwrap();
        std::thread::sleep(Duration::from_millis(120));
        server.write_all(b"x").unwrap();
        server
    });
    let start = Instant::now();
    assert_eq!(c.read(&mut [0u8; 4]).unwrap(), 1);
    assert!(start.elapsed() >= Duration::from_millis(100));
    drop(t.join().unwrap());
}

#[test]
fn unnamed_unix_addresses_print_as_go() {
    // Go's Linux anyToSockaddr shows an unnamed address as "@"; darwin's
    // shows "". A datagram from an unnamed sender has no address on either.
    let unnamed = if cfg!(target_os = "linux") { "@" } else { "" };
    let dir = scratch("unnamed");
    let path = dir.join("s.sock").to_str().unwrap().to_string();
    let Listener::Unix(ln) = net::listen("unix", &path).unwrap() else {
        panic!()
    };
    let p2 = path.clone();
    let t = std::thread::spawn(move || net::dial("unix", &p2).unwrap());
    let accepted = ln.accept_unix().unwrap();
    assert_eq!(accepted.remote_addr().unwrap().name, unnamed);
    let Conn::Unix(c) = t.join().unwrap() else {
        panic!()
    };
    assert_eq!(c.local_addr().unwrap().name, unnamed);

    let gpath = dir.join("g.sock").to_str().unwrap().to_string();
    let net::PacketConn::Unix(pc) = net::listen_packet("unixgram", &gpath).unwrap() else {
        panic!()
    };
    let Conn::Unix(gc) = net::dial("unixgram", &gpath).unwrap() else {
        panic!()
    };
    assert_eq!(gc.local_addr().unwrap().name, unnamed);
    gc.write(b"ping").unwrap();
    let (n, from) = pc.read_from_unix(&mut [0u8; 8]).unwrap();
    assert_eq!((n, from), (4, None));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn read_msg_unix_reports_kernel_flags() {
    // Linux echoes MSG_CMSG_CLOEXEC into msg_flags and Go returns it as is.
    let want = if cfg!(target_os = "linux") {
        0x4000_0000
    } else {
        0
    };
    let (a, b) = UnixStream::pair().unwrap();
    net::write_msg_unix(&a, b"x", &[], None).unwrap();
    let got = net::read_msg_unix(&b, &mut [0u8; 4], &mut [0u8; 16]).unwrap();
    assert_eq!((got.n, got.flags), (1, want));

    let dir = scratch("msgflags");
    let path = dir.join("g.sock").to_str().unwrap().to_string();
    let net::PacketConn::Unix(pc) = net::listen_packet("unixgram", &path).unwrap() else {
        panic!()
    };
    let Conn::Unix(c) = net::dial("unixgram", &path).unwrap() else {
        panic!()
    };
    c.write(b"y").unwrap();
    let got = pc.read_msg_unix(&mut [0u8; 4], &mut [0u8; 16]).unwrap();
    assert_eq!((got.n, got.flags), (1, want));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn unix_listener_unlinks_its_socket() {
    let dir = scratch("unixlisten");
    let path = dir.join("l.sock");
    let name = path.to_str().unwrap();
    let Listener::Unix(ln) = net::listen("unix", name).unwrap() else {
        panic!()
    };
    assert!(path.exists());
    assert!(net::listen("unix", name)
        .err()
        .unwrap()
        .to_string()
        .ends_with("bind: address already in use"));
    let p2 = name.to_string();
    let t = std::thread::spawn(move || UnixStream::connect(p2).unwrap());
    let accepted = ln.accept_unix().unwrap();
    assert_eq!(accepted.network(), "unix");
    t.join().unwrap();
    ln.close().unwrap();
    assert!(!path.exists());
    // Opting out keeps the file.
    let Listener::Unix(ln) = net::listen("unix", name).unwrap() else {
        panic!()
    };
    ln.set_unlink_on_close(false);
    ln.close().unwrap();
    assert!(path.exists());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn listen_packet_networks() {
    let PacketConn::Udp(u) = net::listen_packet("udp", "127.0.0.1:0").unwrap() else {
        panic!()
    };
    let Conn::Udp(c) = net::dial("udp", &u.local_addr().unwrap().to_string()).unwrap() else {
        panic!()
    };
    c.write(b"d").unwrap();
    let mut buf = [0u8; 4];
    u.set_read_deadline(Some(SystemTime::now() + Duration::from_secs(2)))
        .unwrap();
    assert_eq!(u.read(&mut buf).unwrap(), 1);
    assert_eq!(
        net::listen_packet("tcp", ":0").err().unwrap().to_string(),
        "listen tcp :0: address :0: unexpected address type"
    );
    assert_eq!(
        net::listen("udp", ":0").err().unwrap().to_string(),
        "listen udp :0: address :0: unexpected address type"
    );
    let dir = scratch("unixgram");
    let path = dir.join("g.sock");
    let PacketConn::Unix(g) = net::listen_packet("unixgram", path.to_str().unwrap()).unwrap()
    else {
        panic!()
    };
    let cl = UnixDatagram::unbound().unwrap();
    assert_eq!(g.network(), "unixgram");
    cl.send_to(b"ug", &path).unwrap();
    g.set_read_deadline(Some(SystemTime::now() + Duration::from_secs(2)))
        .unwrap();
    assert_eq!(g.read(&mut buf).unwrap(), 2);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn unixpacket_works_or_is_unsupported() {
    let dir = scratch("unixpacket");
    let path = dir.join("p.sock");
    let name = path.to_str().unwrap();
    match net::listen("unixpacket", name) {
        Err(e) => {
            // macOS has no AF_UNIX sequenced-packet sockets; Linux never lands here.
            assert_eq!(
                e.to_string(),
                format!("listen unixpacket {name}: socket: protocol not supported")
            );
        }
        Ok(Listener::Unix(ln)) => {
            let n2 = name.to_string();
            let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
            let t = std::thread::spawn(move || {
                let Conn::Unix(c) = net::dial("unixpacket", &n2).unwrap() else {
                    panic!()
                };
                c.write(b"packet one").unwrap();
                c.write(b"two").unwrap();
                let mut buf = [0u8; 32];
                let n = c.read(&mut buf).unwrap();
                assert_eq!(&buf[..n], b"reply");
                // Stay connected until the deadline read is done; a closed
                // peer makes that read return end of file instead.
                let _ = done_rx.recv();
            });
            let s = ln.accept_unix().unwrap();
            assert_eq!(s.network(), "unixpacket");
            let mut buf = [0u8; 32];
            // Message boundaries survive: two reads, two packets.
            let n = s.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"packet one");
            let n = s.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"two");
            s.write(b"reply").unwrap();
            // Deadlines apply to packet connections.
            s.set_read_deadline(Some(SystemTime::now() + Duration::from_millis(50)))
                .unwrap();
            assert!(s.read(&mut buf).unwrap_err().timeout());
            drop(done_tx);
            t.join().unwrap();
            ln.close().unwrap();
        }
        Ok(_) => panic!("unexpected listener"),
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn file_conns_rebuild_connections() {
    use rust_stdlib_sys::os::{File, FileKind};
    use std::os::fd::OwnedFd;
    let (c, _s) = tcp_pair();
    let file = File::new(
        std::fs::File::from(OwnedFd::from(c.try_clone().unwrap())),
        "tcp",
        FileKind::NewFile,
    )
    .unwrap();
    let Conn::Tcp(copy) = net::file_conn(&file).unwrap() else {
        panic!()
    };
    assert_eq!(
        copy.remote_addr().unwrap().to_string(),
        c.peer_addr().unwrap().to_string()
    );
    let null = File::new(
        std::fs::File::open("/dev/null").unwrap(),
        "/dev/null",
        FileKind::OpenFile,
    )
    .unwrap();
    assert_eq!(
        net::file_conn(&null).err().unwrap().to_string(),
        "file file+net /dev/null: getsockopt: socket operation on non-socket"
    );
    assert!(net::file_listener(&null).is_err());
    assert!(net::file_packet_conn(&null).is_err());
}

#[test]
fn multicast_listen_errors_match_go() {
    assert_eq!(
        net::listen_multicast_udp(
            "tcp",
            None,
            Some(&UDPAddr {
                ip: Some("239.1.1.1".parse().unwrap()),
                port: 9,
                zone: String::new()
            })
        )
        .err()
        .unwrap()
        .to_string(),
        "listen tcp 239.1.1.1:9: unknown network tcp"
    );
    assert_eq!(
        net::listen_multicast_udp("udp", None, None)
            .err()
            .unwrap()
            .cause_text(),
        "missing address"
    );
}

trait CauseText {
    fn cause_text(&self) -> String;
}

impl CauseText for net::OpError {
    fn cause_text(&self) -> String {
        match &self.err {
            Cause::MissingAddress => "missing address".into(),
            other => other.to_string(),
        }
    }
}
