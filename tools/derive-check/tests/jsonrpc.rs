//! net/rpc/jsonrpc: framing, ids, errors and the reflect-to-JSON mapping,
//! after Go's jsonrpc/all_test.go.
#![allow(non_snake_case, dead_code)]
use std::io::{BufRead, BufReader, Write};

use rust_stdlib::net::rpc::{jsonrpc, Server};
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
    #[reflect("json:\"c\"")]
    pub C: isize,
    #[reflect("json:\"note,omitempty\"")]
    pub Note: String,
}

#[derive(Reflect, Default)]
#[reflect(pkg = "main")]
pub struct Arith {}

#[reflect_methods]
impl Arith {
    pub fn Add(&self, args: Args, reply: &mut Reply) -> Result<(), String> {
        reply.C = args.A + args.B;
        reply.Note = "<sum>".into();
        Ok(())
    }
    pub fn Fail(&self, _args: Args, _reply: &mut Reply) -> Result<(), String> {
        Err("it failed".into())
    }
}

fn server() -> Server {
    let s = Server::new();
    s.register(&Some(Arith {})).unwrap();
    s
}

#[test]
fn client_and_server_round_trip() {
    let s = server();
    let (a, b) = rust_stdlib::net::pipe();
    std::thread::spawn(move || s.serve_codec(jsonrpc::JsonServerCodec::new(b)));
    let c = jsonrpc::client(a);
    let mut r = Reply::default();
    c.call("Arith.Add", &Args { A: 3, B: 4 }, &mut r).unwrap();
    assert_eq!(
        r,
        Reply {
            C: 7,
            Note: "<sum>".into()
        }
    );
    let err = c.call("Arith.Fail", &Args::default(), &mut r).unwrap_err();
    assert_eq!(err.as_server_error().unwrap().error(), "it failed");
    let err = c.call("Arith.Nope", &Args::default(), &mut r).unwrap_err();
    assert_eq!(err.to_string(), "rpc: can't find method Arith.Nope");
}

fn exchange(request: &str) -> String {
    let s = server();
    let lis = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = lis.local_addr().unwrap();
    std::thread::spawn(move || {
        let (conn, _) = lis.accept().unwrap();
        s.serve_codec(jsonrpc::JsonServerCodec::new(conn));
    });
    let mut c = std::net::TcpStream::connect(addr).unwrap();
    c.write_all(request.as_bytes()).unwrap();
    let mut line = String::new();
    BufReader::new(c).read_line(&mut line).unwrap();
    line
}

#[test]
fn response_framing() {
    assert_eq!(
        exchange("{\"method\":\"Arith.Add\",\"params\":[{\"A\":1,\"B\":2}],\"id\":7}\n"),
        "{\"id\":7,\"result\":{\"c\":3,\"note\":\"\\u003csum\\u003e\"},\"error\":null}\n"
    );
    // Ids are echoed as written; errors carry a null result.
    assert_eq!(
        exchange("{\"method\":\"Arith.Fail\",\"params\":[{}],\"id\":\"x y\"}\n"),
        "{\"id\":\"x y\",\"result\":null,\"error\":\"it failed\"}\n"
    );
    assert_eq!(
        exchange("{\"method\":\"Arith.Add\",\"params\":[{}]}\n"),
        "{\"id\":null,\"result\":{\"c\":0,\"note\":\"\\u003csum\\u003e\"},\"error\":null}\n"
    );
    assert_eq!(
        exchange("{\"method\":\"Arith.Add\",\"id\":1}\n"),
        "{\"id\":1,\"result\":null,\"error\":\"jsonrpc: request body missing params\"}\n"
    );
}
