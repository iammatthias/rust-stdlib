//! The adapter, the dialer glue and the Go `DefaultTransport` settings.
use rust_stdlib::context::Context;
use rust_stdlib::net::http::{
    handler::write_string,
    handler_func, httptest,
    transport::{DialContextFn, Transport},
};
use rust_stdlib::net::{Conn as NetConn, NetError};
use rust_stdlib::time::{self, Duration};
use rust_stdlib_sys::net::{self as sys, level, opt};
use rust_stdlib_sysnet::{
    default_client, default_transport, dial_context, net_error, transport, Conn,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

fn dial(hook: &DialContextFn, addr: &str) -> Box<dyn NetConn> {
    hook(&Context::background(), "tcp", addr).expect("dial")
}

fn sysnet(c: &dyn NetConn) -> &Conn {
    c.as_any().downcast_ref::<Conn>().expect("sysnet::Conn")
}

fn keep_alive_state(c: &dyn NetConn) -> (i32, i32, i32) {
    let s = sysnet(c).sys();
    (
        sys::getsockopt_int(s, level::SOL_SOCKET, opt::SO_KEEPALIVE).unwrap(),
        sys::getsockopt_int(s, level::IPPROTO_TCP, opt::TCP_KEEPIDLE).unwrap(),
        sys::getsockopt_int(s, level::IPPROTO_TCP, opt::TCP_KEEPINTVL).unwrap(),
    )
}

#[test]
fn keep_alive_is_set_on_the_dialed_socket() {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = ln.local_addr().unwrap().to_string();

    // Go's DefaultTransport: KeepAlive 30s sets SO_KEEPALIVE, idle and interval.
    let t = transport();
    let c = dial(t.dial_context.as_ref().unwrap(), &addr);
    let (on, idle, interval) = keep_alive_state(&*c);
    assert_ne!(on, 0, "SO_KEEPALIVE");
    // Go sets the idle time only; the interval keeps its 15s default.
    assert_eq!((idle, interval), (30, 15));

    // A dialer with keep-alive disabled leaves it off.
    let hook = dial_context(sys::Dialer {
        keep_alive: -1,
        ..sys::Dialer::default()
    });
    assert_eq!(keep_alive_state(&*dial(&hook, &addr)).0, 0);

    // keep_alive_config is honoured too.
    let hook = dial_context(sys::Dialer {
        keep_alive_config: sys::KeepAliveConfig {
            enable: true,
            idle: 20_000_000_000,
            interval: 7_000_000_000,
            count: 3,
        },
        ..sys::Dialer::default()
    });
    let c = dial(&hook, &addr);
    let (on, idle, interval) = keep_alive_state(&*c);
    assert_ne!(on, 0);
    assert_eq!((idle, interval), (20, 7));
}

#[test]
fn transport_fields_match_go_default_transport() {
    let t = transport();
    assert!(t.proxy.is_some());
    assert!(t.dial_context.is_some());
    assert!(t.dial.is_none() && t.dial_tls_context.is_none() && t.dial_tls.is_none());
    assert!(t.force_attempt_http2);
    assert_eq!(t.max_idle_conns, 100);
    assert_eq!(t.idle_conn_timeout, Duration::from_secs(90));
    assert_eq!(t.tls_handshake_timeout, Duration::from_secs(10));
    assert_eq!(t.expect_continue_timeout, time::SECOND);
    // Everything Go leaves at zero stays at zero.
    assert_eq!(t.max_idle_conns_per_host, 0);
    assert_eq!(t.max_conns_per_host, 0);
    assert_eq!(t.response_header_timeout, Duration::default());
    assert!(!t.disable_keep_alives && !t.disable_compression);
    // Go's nil TLSClientConfig means the TLS defaults, which the `tls` feature
    // supplies; without it the transport is http-only.
    assert_eq!(t.tls_client_config.is_some(), cfg!(feature = "tls"));
    assert!(t.protocols.is_none() && t.http2.is_none());
    assert!(Arc::ptr_eq(&default_transport(), &default_transport()));
}

#[test]
fn default_client_gets_through_a_local_server() {
    let server = httptest::Server::new(handler_func(|w, r| {
        let _ = write_string(w, &format!("hello {}", r.url.path));
    }))
    .unwrap();
    let resp = default_client().get(&format!("{}/x", server.url)).unwrap();
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.body.unwrap().read_all().unwrap(), b"hello /x");
}

#[test]
fn connections_are_reused_across_requests() {
    let remotes = Arc::new(Mutex::new(Vec::new()));
    let seen = remotes.clone();
    let server = httptest::Server::new(handler_func(move |w, r| {
        seen.lock().unwrap().push(r.remote_addr.clone());
        let _ = write_string(w, "ok");
    }))
    .unwrap();

    let dials = Arc::new(AtomicUsize::new(0));
    let counted = dials.clone();
    let inner = transport().dial_context.unwrap();
    let client = rust_stdlib::net::http::client::Client {
        transport: Some(Arc::new(Transport {
            dial_context: Some(Arc::new(move |ctx, network, addr| {
                counted.fetch_add(1, Ordering::SeqCst);
                inner(ctx, network, addr)
            })),
            ..transport()
        })),
        ..Default::default()
    };
    for _ in 0..4 {
        let resp = client.get(&server.url).unwrap();
        assert_eq!(resp.body.unwrap().read_all().unwrap(), b"ok");
    }
    assert_eq!(
        dials.load(Ordering::SeqCst),
        1,
        "one connection for four requests"
    );
    let remotes = remotes.lock().unwrap();
    assert_eq!(remotes.len(), 4);
    assert!(remotes.iter().all(|r| r == &remotes[0]), "{remotes:?}");
}

#[test]
fn conn_reads_writes_and_reports_addresses() {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = ln.local_addr().unwrap();
    let echo = std::thread::spawn(move || {
        let (mut s, _) = ln.accept().unwrap();
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).unwrap();
        s.write_all(&buf).unwrap();
        // Closing sends EOF.
    });
    let c = dial(&dial_context(sys::Dialer::default()), &addr.to_string());
    assert_eq!(c.remote_addr().unwrap().to_string(), addr.to_string());
    assert_eq!(c.remote_addr().unwrap().network(), "tcp");
    assert!(c
        .local_addr()
        .unwrap()
        .to_string()
        .starts_with("127.0.0.1:"));
    assert_eq!(c.write(b"hello").unwrap(), 5);
    let mut buf = [0u8; 16];
    assert_eq!(c.read(&mut buf).unwrap(), 5);
    assert_eq!(&buf[..5], b"hello");
    echo.join().unwrap();
    assert_eq!(c.read(&mut buf).unwrap(), 0, "EOF is Ok(0)");
    c.close().unwrap();
    let err = c.read(&mut buf).unwrap_err();
    assert!(err.is_closed(), "{err}");
    assert!(
        err.to_string()
            .ends_with("use of closed network connection"),
        "{err}"
    );
}

#[test]
fn deadlines_time_out_with_go_text() {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = ln.local_addr().unwrap().to_string();
    let c = dial(&dial_context(sys::Dialer::default()), &addr);
    let _peer = ln.accept().unwrap();
    let t = time::now().add(Duration::from_secs(0) + time::MILLISECOND.mul(50));
    c.set_read_deadline(&t).unwrap();
    let mut buf = [0u8; 1];
    let err = c.read(&mut buf).unwrap_err();
    assert!(err.is_io_timeout(), "{err}");
    assert!(rust_stdlib::net::Error::timeout(&err));
    let want = format!(
        "read tcp {}->{}: i/o timeout",
        c.local_addr().unwrap(),
        addr
    );
    assert_eq!(err.to_string(), want);
    // A zero time clears the deadline.
    c.set_read_deadline(&time::Time::default()).unwrap();
}

#[test]
fn dial_errors_keep_go_texts() {
    let port = {
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        ln.local_addr().unwrap().port()
    };
    let addr = format!("127.0.0.1:{port}");
    let hook = dial_context(sys::Dialer::default());
    let err = hook(&Context::background(), "tcp", &addr).err().unwrap();
    let err = err.downcast_ref::<NetError>().expect("NetError");
    assert_eq!(
        err.to_string(),
        format!("dial tcp {addr}: connect: connection refused")
    );

    let err = hook(&Context::background(), "tcp", "127.0.0.1")
        .err()
        .unwrap();
    assert_eq!(
        err.to_string(),
        "dial tcp: address 127.0.0.1: missing port in address"
    );

    let err = hook(&Context::background(), "bogus", &addr).err().unwrap();
    assert_eq!(err.to_string(), "dial bogus: unknown network bogus");

    let sys_err = sys::OpError::new("read", sys::Cause::Timeout);
    assert!(net_error(sys_err).to_string().ends_with("i/o timeout"));
}

#[test]
fn canceled_context_stops_the_dial() {
    let (ctx, cancel) = Context::background().with_cancel();
    cancel();
    let hook = dial_context(sys::Dialer::default());
    let err = hook(&ctx, "tcp", "127.0.0.1:9").err().unwrap();
    assert!(err.to_string().contains("operation was canceled"), "{err}");
}

#[cfg(unix)]
#[test]
fn unix_connections_work() {
    let dir = std::env::temp_dir().join(format!("sysnet-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("s.sock");
    let ln = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let srv = std::thread::spawn(move || {
        let (mut s, _) = ln.accept().unwrap();
        s.write_all(b"hi").unwrap();
    });
    let c = Conn::new(sys::dial("unix", path.to_str().unwrap()).unwrap());
    let mut buf = [0u8; 2];
    assert_eq!(NetConn::read(&c, &mut buf).unwrap(), 2);
    assert_eq!(&buf, b"hi");
    assert_eq!(c.remote_addr().unwrap().network(), "unix");
    assert_eq!(c.remote_addr().unwrap().to_string(), path.to_str().unwrap());
    srv.join().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}
