//! Message I/O scenarios of the Go differential; see tools/sys_oracle_msg.go.
use rust_stdlib_sys::net::{self, level, opt, UDPAddr, UnixAddr};
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::time::Duration;

fn err_text<E: std::fmt::Display>(r: Result<(), E>) -> String {
    match r {
        Ok(()) => "ok".into(),
        Err(e) => format!("err {e}"),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn to_udp(a: SocketAddr) -> UDPAddr {
    UDPAddr {
        ip: Some(a.ip()),
        port: a.port(),
        zone: String::new(),
    }
}

/// Go's sockets are non-blocking (and the kernel reports the sender of a
/// zero-length datagram only on those).
fn udp_pair() -> (UdpSocket, UdpSocket) {
    let (a, b) = (
        UdpSocket::bind("127.0.0.1:0").unwrap(),
        UdpSocket::bind("127.0.0.1:0").unwrap(),
    );
    a.set_nonblocking(true).unwrap();
    b.set_nonblocking(true).unwrap();
    (a, b)
}

pub fn run(f: &[&str]) -> String {
    match f[0] {
        "udpmsg" => {
            let size: usize = f[1].parse().unwrap();
            let rsize: usize = f[2].parse().unwrap();
            let (server, client) = udp_pair();
            if f[3] == "ttl" {
                net::setsockopt_int(&server, level::IPPROTO_IP, opt::IP_RECVTTL, 1).unwrap();
            }
            let payload: Vec<u8> = (0..size).map(|i| i as u8).collect();
            let saddr = to_udp(server.local_addr().unwrap());
            let w = net::write_msg_udp(&client, &payload, &[], Some(&saddr));
            let mut out = match &w {
                Ok((n, oobn)) => format!("write n={n} oobn={oobn} ok"),
                Err(e) => format!("write n=0 oobn=0 err {e}"),
            };
            let mut b = vec![0u8; rsize];
            let mut oob = [0u8; 64];
            match net::read_msg_udp(&server, &mut b, &mut oob) {
                Ok(r) => {
                    let from = r
                        .addr
                        .map(|a| {
                            (a.to_string() == client.local_addr().unwrap().to_string()).to_string()
                        })
                        .unwrap_or_default();
                    out.push_str(&format!(
                        " read n={} oobn={} flags={} from={from} ok oob={}",
                        r.n,
                        r.oobn,
                        r.flags,
                        hex(&oob[..r.oobn])
                    ));
                }
                Err(e) => out.push_str(&format!(" read n=0 oobn=0 flags=0 from= err {e} oob=")),
            }
            out
        }
        "udpmsg_ap" => {
            let (server, client) = udp_pair();
            let ap = to_udp(server.local_addr().unwrap());
            let w = net::write_msg_udp_addr_port(&client, b"hello", &[], Some(&ap));
            let mut out = match &w {
                Ok((n, oobn)) => format!("write n={n} oobn={oobn} ok"),
                Err(e) => format!("write n=0 oobn=0 err {e}"),
            };
            server
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut b = [0u8; 16];
            match net::read_msg_udp_addr_port(&server, &mut b, &mut []) {
                Ok(r) => out.push_str(&format!(
                    " read n={} oobn={} flags={} from={} ok",
                    r.n,
                    r.oobn,
                    r.flags,
                    r.addr.map(|a| a.to_string()) == Some(client.local_addr().unwrap().to_string())
                )),
                Err(e) => out.push_str(&format!(" read err {e}")),
            }
            out
        }
        "udpmsg_conn" => {
            let (server, client) = udp_pair();
            client.connect(server.local_addr().unwrap()).unwrap();
            let r = net::write_msg_udp(&client, b"hi", &[], None);
            let mut out = match &r {
                Ok((n, oobn)) => format!("conn-nil n={n} oobn={oobn} ok"),
                Err(e) => format!("conn-nil n=0 oobn=0 err {e}"),
            };
            let saddr = to_udp(server.local_addr().unwrap());
            let r = net::write_msg_udp(&client, b"hi", &[], Some(&saddr)).map(|_| ());
            out.push_str(&format!(" conn-addr={}", err_text(r)));
            let r = net::write_msg_udp(&server, b"hi", &[], None).map(|_| ());
            out.push_str(&format!(" unconn-nil={}", err_text(r)));
            out
        }
        "unixmsg" => {
            let _ = std::fs::remove_file("s1.sock");
            let _ = std::fs::remove_file("c1.sock");
            let server = UnixDatagram::bind("s1.sock").unwrap();
            let client = UnixDatagram::bind("c1.sock").unwrap();
            let (pr, pw) = rust_stdlib_sys::os::pipe().unwrap();
            let oob_out = net::unix_rights(&[pw.as_raw_fd()]);
            let to = UnixAddr {
                name: "s1.sock".into(),
                net: "unixgram".into(),
            };
            let w = net::write_msg_unix(&client, b"fd", &oob_out, Some(&to));
            let mut out = match &w {
                Ok((n, oobn)) => format!("write n={n} oobn={oobn} ok"),
                Err(e) => format!("write n=0 oobn=0 err {e}"),
            };
            server
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut b = [0u8; 16];
            let mut oob = [0u8; 64];
            match net::read_msg_unix(&server, &mut b, &mut oob) {
                Ok(r) => {
                    let from = r
                        .addr
                        .map(|a| format!("{}/{}", a.name, a.net))
                        .unwrap_or_else(|| "<nil>".into());
                    out.push_str(&format!(
                        " read n={} oobn={} flags={} from={from} ok",
                        r.n, r.oobn, r.flags
                    ));
                    match net::parse_unix_rights(&oob[..r.oobn]) {
                        Ok(fds) => {
                            out.push_str(&format!(" parse=ok fds={} ok", fds.len()));
                            if fds.len() == 1 {
                                // Reopen the received descriptor by path to use it.
                                let mut got = std::fs::OpenOptions::new()
                                    .write(true)
                                    .open(format!("/dev/fd/{}", fds[0]))
                                    .unwrap();
                                std::io::Write::write_all(&mut got, b"through").unwrap();
                                drop(got);
                                pw.close().unwrap();
                                let mut buf = [0u8; 16];
                                let m = pr.read(&mut buf).unwrap();
                                out.push_str(&format!(
                                    " via={:?}",
                                    String::from_utf8_lossy(&buf[..m])
                                ));
                            }
                        }
                        Err(e) => out.push_str(&format!(" parse=err {e}")),
                    }
                }
                Err(e) => out.push_str(&format!(" read err {e}")),
            }
            let r = net::write_msg_unix(&client, b"x", &[], None).map(|_| ());
            out.push_str(&format!(" noaddr={}", err_text(r)));
            let bad = UnixAddr {
                name: "s1.sock".into(),
                net: "unix".into(),
            };
            let r = net::write_msg_unix(&client, b"x", &[], Some(&bad)).map(|_| ());
            out.push_str(&format!(" badnet={}", err_text(r)));
            out
        }
        "unixmsg_stream" => {
            let _ = std::fs::remove_file("s2.sock");
            let ln = UnixListener::bind("s2.sock").unwrap();
            let c = UnixStream::connect("s2.sock").unwrap();
            let (s, _) = ln.accept().unwrap();
            let w = net::write_msg_unix(&c, b"stream", &[], None);
            let mut out = match &w {
                Ok((n, oobn)) => format!("write n={n} oobn={oobn} ok"),
                Err(e) => format!("write n=0 oobn=0 err {e}"),
            };
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut b = [0u8; 16];
            let mut oob = [0u8; 16];
            match net::read_msg_unix(&s, &mut b, &mut oob) {
                Ok(r) => out.push_str(&format!(
                    " read n={} oobn={} flags={} addr={} ok",
                    r.n,
                    r.oobn,
                    r.flags,
                    r.addr.map(|a| a.name).unwrap_or_else(|| "<nil>".into())
                )),
                Err(e) => out.push_str(&format!(" read err {e}")),
            }
            out
        }
        _ => crate::dial_scenarios::run(f),
    }
}
