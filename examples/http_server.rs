//! Go-shaped `net/http` server for `tools/smoke.py` and `tools/gohttp_interop.go`.
//! Run: cargo run --offline --example http_server -- 127.0.0.1:0 DOCROOT
//! Prints `listening ADDRESS` on stdout; exits when stdin reaches end of file
//! or a line arrives.
use rust_stdlib::{
    context::Context,
    net::{
        self,
        http::{self, server::Server, Cookie, Dir, Handler, ServeMux},
    },
};
use std::{
    io::{self, BufRead, Read, Write},
    sync::Arc,
    thread,
    time::Duration,
};

fn mux(docroot: &str) -> Arc<http::ServeMux> {
    let mux = Arc::new(ServeMux::new());
    mux.handle_func("GET /hello/{name}", |w, r| {
        let _ = w.write_string(&format!("Hello, {}.\n", r.path_value("name")));
    })
    .unwrap();
    mux.handle_func("POST /echo", |w, r| {
        let mut body = Vec::new();
        if let Some(b) = &r.body {
            let _ = b.clone().read_to_end(&mut body);
        }
        w.header()
            .set("Content-Type", r.header.get("Content-Type").unwrap_or(""));
        let _ = w.write(&body);
    })
    .unwrap();
    mux.handle(
        "GET /files/",
        http::strip_prefix(
            "/files",
            http::file_server(Arc::new(Dir(docroot.to_owned()))),
        ),
    )
    .unwrap();
    mux.handle_func("GET /old", |w, r| {
        http::redirect(w, r, "/hello/redirected", 302)
    })
    .unwrap();
    mux.handle_func("GET /set-cookie", |w, _| {
        http::set_cookie(
            w,
            &Cookie {
                name: "session".into(),
                value: "rust-1".into(),
                path: "/".into(),
                http_only: true,
                ..Cookie::default()
            },
        );
        let _ = w.write_string("cookie set\n");
    })
    .unwrap();
    mux.handle_func("GET /whoami", |w, r| {
        let who = r
            .cookie("session")
            .map_or_else(|_| "nobody".to_owned(), |c| c.value);
        let _ = w.write_string(&format!("{who}\n"));
    })
    .unwrap();
    mux.handle_func("GET /stream", |w, _| {
        let _ = w.write_string("one,");
        let _ = http::ResponseController::new(w).flush();
        thread::sleep(Duration::from_millis(30));
        let _ = w.write_string("two\n");
    })
    .unwrap();
    mux.handle_func("GET /trailer", |w, _| {
        w.header().set("Trailer", "X-Checksum");
        let _ = w.write_string("payload\n");
        w.header().set("X-Checksum", "abc123");
    })
    .unwrap();
    mux.handle_func("GET /gzip", |w, r| {
        if r.header
            .get("Accept-Encoding")
            .unwrap_or("")
            .contains("gzip")
        {
            let mut enc = rust_stdlib::compress::gzip::Writer::new(Vec::new());
            enc.write_all(b"gzipped from rust\n").unwrap();
            enc.close().unwrap();
            w.header().set("Content-Encoding", "gzip");
            let _ = w.write(&enc.into_inner());
        } else {
            let _ = w.write_string("plain from rust\n");
        }
    })
    .unwrap();
    mux
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let addr = args.get(1).map_or("127.0.0.1:0", String::as_str);
    let docroot = args.get(2).map_or(".", String::as_str);
    let mut server = Server::default();
    let handler: Arc<dyn Handler> = mux(docroot);
    server.handler = Some(handler);
    let ln = net::listen("tcp", addr).expect("listen");
    println!("listening {}", ln.addr().expect("addr"));
    io::stdout().flush().expect("flush");
    let s2 = server.clone();
    let t = thread::spawn(move || {
        let _ = s2.serve(ln);
    });
    let mut line = String::new();
    let _ = io::stdin().lock().read_line(&mut line);
    let (ctx, cancel) = Context::background().with_timeout(Duration::from_secs(5).into());
    let _ = server.shutdown(&ctx);
    cancel();
    let _ = t.join();
}
