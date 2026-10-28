//! net/rpc after Go's server_test.go: registration rules, calls over a
//! connection, errors, asynchronous calls, shutdown and the debug page.
#![allow(non_snake_case, dead_code)]
use std::collections::BTreeMap;
use std::sync::mpsc;
use std::time::Duration;

use rust_stdlib::net::rpc::{self, Client, Server};
use rust_stdlib::reflect::{Reflect, ReflectType};
use rust_stdlib_derive::{reflect_methods, Reflect};

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
pub struct Args {
    pub A: isize,
    pub B: isize,
}

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
pub struct Reply {
    pub C: isize,
}

#[derive(Reflect, Clone, Default, PartialEq, Debug)]
#[reflect(pkg = "main")]
pub struct Quotient {
    pub Quo: isize,
    pub Rem: isize,
}

#[derive(Reflect, Clone, Default)]
#[reflect(pkg = "main")]
pub struct Arith {
    pub calls: isize,
}

#[reflect_methods]
impl Arith {
    pub fn Add(&mut self, args: Args, reply: &mut Reply) -> Result<(), String> {
        self.calls += 1;
        reply.C = args.A + args.B;
        Ok(())
    }
    pub fn Mul(&mut self, args: Args, reply: &mut Reply) -> Result<(), String> {
        reply.C = args.A * args.B;
        Ok(())
    }
    pub fn Div(&mut self, args: Args, reply: &mut Quotient) -> Result<(), String> {
        if args.B == 0 {
            return Err("divide by zero".into());
        }
        reply.Quo = args.A / args.B;
        reply.Rem = args.A % args.B;
        Ok(())
    }
    pub fn Error(&self, _args: Args, _reply: &mut Reply) -> Result<(), String> {
        Err("ERROR".into())
    }
    pub fn Count(&mut self, _args: Args, reply: &mut isize) -> Result<(), String> {
        *reply = self.calls;
        Ok(())
    }
    pub fn Names(&self, _args: Args, reply: &mut BTreeMap<String, isize>) -> Result<(), String> {
        reply.insert("x".into(), 1);
        Ok(())
    }
    pub fn Sleep(&self, args: Args, reply: &mut Reply) -> Result<(), String> {
        std::thread::sleep(Duration::from_millis(args.A as u64));
        reply.C = args.A;
        Ok(())
    }
    /// Not suitable: wrong arity (ignored by Register).
    pub fn Bad(&self, _args: Args) -> Result<(), String> {
        Ok(())
    }
}

fn serve() -> (Client, Server) {
    let server = Server::new();
    server.register(&Some(Arith::default())).expect("register");
    let (a, b) = rust_stdlib::net::pipe();
    let s = server.clone();
    std::thread::spawn(move || s.serve_conn(b));
    (Client::new(a), server)
}

#[test]
fn calls_and_errors() {
    let (client, _s) = serve();
    let mut reply = Reply::default();
    client
        .call("Arith.Add", &Args { A: 7, B: 8 }, &mut reply)
        .unwrap();
    assert_eq!(reply.C, 15);
    client
        .call("Arith.Mul", &Args { A: 7, B: 8 }, &mut reply)
        .unwrap();
    assert_eq!(reply.C, 56);
    let mut q = Quotient::default();
    client
        .call("Arith.Div", &Args { A: 7, B: 2 }, &mut q)
        .unwrap();
    assert_eq!(q, Quotient { Quo: 3, Rem: 1 });

    let err = client
        .call("Arith.Div", &Args { A: 7, B: 0 }, &mut q)
        .unwrap_err();
    assert_eq!(err.as_server_error().unwrap().error(), "divide by zero");
    let err = client
        .call("Arith.Error", &Args::default(), &mut reply)
        .unwrap_err();
    assert_eq!(err.to_string(), "ERROR");

    // The connection survives errors.
    client
        .call("Arith.Add", &Args { A: 1, B: 2 }, &mut reply)
        .unwrap();
    assert_eq!(reply.C, 3);

    let err = client
        .call("Arith.Unknown", &Args::default(), &mut reply)
        .unwrap_err();
    assert_eq!(err.to_string(), "rpc: can't find method Arith.Unknown");
    let err = client
        .call("Nope.Add", &Args::default(), &mut reply)
        .unwrap_err();
    assert_eq!(err.to_string(), "rpc: can't find service Nope.Add");
    let err = client
        .call("Add", &Args::default(), &mut reply)
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "rpc: service/method request ill-formed: Add"
    );
    // Arith.Bad has the wrong shape, so it is not served.
    let err = client
        .call("Arith.Bad", &Args::default(), &mut reply)
        .unwrap_err();
    assert_eq!(err.to_string(), "rpc: can't find method Arith.Bad");
}

#[test]
fn receiver_state_persists_and_maps_are_made() {
    let (client, _s) = serve();
    let mut reply = Reply::default();
    for _ in 0..3 {
        client
            .call("Arith.Add", &Args { A: 1, B: 1 }, &mut reply)
            .unwrap();
    }
    let mut n = 0isize;
    client
        .call("Arith.Count", &Args::default(), &mut n)
        .unwrap();
    assert_eq!(n, 3);
    // The server makes the map a reply needs.
    let mut m: BTreeMap<String, isize> = BTreeMap::new();
    client
        .call("Arith.Names", &Args::default(), &mut m)
        .unwrap();
    assert_eq!(m.get("x"), Some(&1));
}

#[test]
fn concurrent_calls_and_go() {
    let (client, _s) = serve();
    let client = std::sync::Arc::new(client);
    let mut handles = Vec::new();
    for i in 0..20isize {
        let c = client.clone();
        handles.push(std::thread::spawn(move || {
            let mut r = Reply::default();
            c.call("Arith.Mul", &Args { A: i, B: 3 }, &mut r).unwrap();
            assert_eq!(r.C, i * 3);
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    // Go with a Done channel: two slow calls overlap.
    let (tx, rx) = mpsc::sync_channel(2);
    let mk = |ms: isize| {
        let args = Args { A: ms, B: 0 }.to_value();
        let reply = rust_stdlib::reflect::new(&Reply::reflect_type());
        client.call_async("Arith.Sleep", args, reply, Some(tx.clone()))
    };
    let t0 = std::time::Instant::now();
    let (c1, c2) = (mk(150), mk(150));
    rx.recv().unwrap();
    rx.recv().unwrap();
    assert!(
        t0.elapsed() < Duration::from_millis(280),
        "calls ran serially"
    );
    assert!(c1.error().is_none() && c2.error().is_none());
    let r1 = Reply::from_value(&c1.reply.elem()).unwrap();
    assert_eq!(r1.C, 150);
}

#[test]
fn shutdown_and_close() {
    let (client, _s) = serve();
    let mut reply = Reply::default();
    client
        .call("Arith.Add", &Args { A: 1, B: 2 }, &mut reply)
        .unwrap();
    client.close().unwrap();
    assert!(client.close().unwrap_err().is_shutdown());
    let err = client
        .call("Arith.Add", &Args::default(), &mut reply)
        .unwrap_err();
    assert!(err.is_shutdown());
    assert_eq!(err.to_string(), "connection is shut down");
}

#[test]
fn server_hangup_fails_pending_calls() {
    let server = Server::new();
    server.register(&Some(Arith::default())).unwrap();
    let (a, b) = rust_stdlib::net::pipe();
    let client = Client::new(a);
    // Close the server end without serving.
    rust_stdlib::net::Conn::close(&b).unwrap();
    let mut reply = Reply::default();
    let err = client
        .call("Arith.Add", &Args::default(), &mut reply)
        .unwrap_err();
    assert!(!err.to_string().is_empty());
}

#[test]
fn registration_rules() {
    let server = Server::new();
    // A value receiver reaches only the &self methods.
    #[derive(Reflect, Default)]
    #[reflect(pkg = "main")]
    pub struct OnlyMut {}
    #[reflect_methods]
    impl OnlyMut {
        pub fn Add(&mut self, _args: Args, _reply: &mut Reply) -> Result<(), String> {
            Ok(())
        }
    }
    let err = server.register(&OnlyMut {}).unwrap_err();
    assert_eq!(
        err.to_string(),
        "rpc.Register: type OnlyMut has no exported methods of suitable type (hint: pass a pointer to value of that type)"
    );
    server
        .register_name("Foo", &Some(Arith::default()))
        .unwrap();
    let err = server
        .register_name("Foo", &Some(Arith::default()))
        .unwrap_err();
    assert_eq!(err.to_string(), "rpc: service already defined: Foo");
    let err = server
        .register_name("", &Some(Arith::default()))
        .unwrap_err();
    assert!(err
        .to_string()
        .starts_with("rpc.Register: no service name for type"));

    #[derive(Reflect, Default)]
    #[reflect(pkg = "main")]
    pub struct NoMethods {}
    let err = server.register(&Some(NoMethods {})).unwrap_err();
    assert_eq!(
        err.to_string(),
        "rpc.Register: type NoMethods has no exported methods of suitable type"
    );
}

#[test]
fn serve_request_is_synchronous() {
    use rust_stdlib::net::rpc::{Request, Response, ServerCodec};
    // A codec that replays one request and records the response.
    struct Mem {
        sent: std::sync::Mutex<Vec<(Response, i64)>>,
    }
    impl ServerCodec for Mem {
        fn read_request_header(&self, r: &mut Request) -> Result<(), rpc::Error> {
            r.service_method = "Arith.Mul".into();
            r.seq = 9;
            Ok(())
        }
        fn read_request_body(&self, body: &rust_stdlib::reflect::Value) -> Result<(), rpc::Error> {
            body.elem().overwrite(&Args { A: 6, B: 7 }.to_value());
            Ok(())
        }
        fn write_response(
            &self,
            r: &Response,
            body: &rust_stdlib::reflect::Value,
        ) -> Result<(), rpc::Error> {
            let c = if body.kind() == rust_stdlib::reflect::Kind::Pointer {
                body.elem().field(0).int()
            } else {
                -1
            };
            self.sent.lock().unwrap().push((r.clone(), c));
            Ok(())
        }
        fn close(&self) -> Result<(), rpc::Error> {
            Ok(())
        }
    }
    let server = Server::new();
    server.register(&Some(Arith::default())).unwrap();
    let mem = Mem {
        sent: Default::default(),
    };
    server.serve_request(&mem).unwrap();
    let sent = mem.sent.lock().unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0.seq, 9);
    assert_eq!(sent[0].0.service_method, "Arith.Mul");
    assert_eq!(sent[0].1, 42);
}

#[test]
fn http_connect_and_debug_page() {
    use std::io::{Read, Write};
    let server = Server::new();
    server.register(&Some(Arith::default())).unwrap();
    server.handle_http(rpc::DEFAULT_RPC_PATH, rpc::DEFAULT_DEBUG_PATH);
    let lis = rust_stdlib::net::listen("tcp", "127.0.0.1:0").unwrap();
    let addr = lis.addr().unwrap().to_string();
    std::thread::spawn(move || {
        let _ = rust_stdlib::net::http::serve(lis, None);
    });

    // Anything but CONNECT is refused.
    let mut s = std::net::TcpStream::connect(&addr).unwrap();
    s.write_all(b"GET /_goRPC_ HTTP/1.0\r\n\r\n").unwrap();
    let mut text = String::new();
    s.read_to_string(&mut text).unwrap();
    assert!(
        text.starts_with("HTTP/1.0 405 Method Not Allowed\r\n"),
        "{text}"
    );
    assert!(
        text.contains("Content-Type: text/plain; charset=utf-8"),
        "{text}"
    );
    assert!(text.ends_with("\r\n\r\n405 must CONNECT\n"), "{text}");

    // DialHTTP connects and calls work.
    let client = rpc::dial_http("tcp", &addr).expect("dial_http");
    let mut reply = Reply::default();
    client
        .call("Arith.Add", &Args { A: 2, B: 3 }, &mut reply)
        .unwrap();
    assert_eq!(reply.C, 5);
    // A wrong path is an HTTP error.
    let err = rpc::dial_http_path("tcp", &addr, "/nowhere").err().unwrap();
    assert!(
        err.to_string().starts_with(&format!(
            "dial-http tcp {addr}: unexpected HTTP response: 404"
        )),
        "{err}"
    );

    // The debug page counts calls.
    let mut s = std::net::TcpStream::connect(&addr).unwrap();
    s.write_all(b"GET /debug/rpc HTTP/1.0\r\n\r\n").unwrap();
    let mut page = String::new();
    s.read_to_string(&mut page).unwrap();
    assert!(page.contains("Service Arith"), "{page}");
    assert!(page.contains("Add(main.Args, *main.Reply) error"), "{page}");
}
