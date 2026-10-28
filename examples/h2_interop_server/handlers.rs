//! Request handlers shared by the HTTP/2 interop servers (h2c here, TLS in
//! `backends/tls/examples/h2_interop_server.rs`). `tools/h2_interop.go`
//! (a Go client) exercises every path; the Go server in
//! `tools/h2_interop_server.go` implements the same contract for the Rust
//! client.
use rust_stdlib::net::http::{
    self, handler::ResponseWriter, header::ERR_ABORT_HANDLER, request::Request, ServeMux,
};
use std::{
    io::Read,
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};

fn read_body(r: &Request) -> Vec<u8> {
    let mut v = Vec::new();
    if let Some(b) = &r.body {
        let _ = b.clone().read_to_end(&mut v);
    }
    v
}

fn fnv(data: &[u8], mut h: u64) -> u64 {
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn query_int(r: &Request, key: &str) -> usize {
    r.url.query().get(key).parse().unwrap_or(0)
}

struct Barrier {
    count: Mutex<usize>,
    cv: Condvar,
}

pub fn mux() -> Arc<ServeMux> {
    let mux = Arc::new(ServeMux::new());
    let barrier = Arc::new(Barrier {
        count: Mutex::new(0),
        cv: Condvar::new(),
    });

    mux.handle_func("/hello", |w: &mut dyn ResponseWriter, _r: &mut Request| {
        w.header().set("X-Hello", "world");
        let _ = w.write_string("hello");
    })
    .unwrap();

    mux.handle_func("/proto", |w: &mut dyn ResponseWriter, r: &mut Request| {
        let _ = w.write_string(&format!(
            "proto={} major={} minor={} tls={} method={} host={} uri={} remote={} ua={}",
            r.proto,
            r.proto_major,
            r.proto_minor,
            r.tls.is_some(),
            r.method,
            r.host,
            r.request_uri,
            !r.remote_addr.is_empty(),
            r.header.get("User-Agent").unwrap_or(""),
        ));
    })
    .unwrap();

    mux.handle_func("/echo", |w: &mut dyn ResponseWriter, r: &mut Request| {
        w.header()
            .set("X-Seen-Length", &r.content_length.to_string());
        let mut body = r.body.clone().unwrap();
        let mut buf = vec![0u8; 8192];
        loop {
            match body.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if w.write(&buf[..n]).is_err() {
                        return;
                    }
                    if let Some(f) = w.flusher() {
                        f.flush();
                    }
                }
            }
        }
    })
    .unwrap();

    mux.handle_func("/upload", |w: &mut dyn ResponseWriter, r: &mut Request| {
        let mut body = r.body.clone().unwrap();
        let mut buf = vec![0u8; 65536];
        let (mut n, mut h) = (0usize, 0xcbf29ce484222325u64);
        loop {
            match body.read(&mut buf) {
                Ok(0) => break,
                Ok(k) => {
                    n += k;
                    h = fnv(&buf[..k], h);
                }
                Err(e) => {
                    let _ = w.write_string(&format!("error={e}"));
                    return;
                }
            }
        }
        let _ = w.write_string(&format!("len={n} fnv={h:016x}"));
    })
    .unwrap();

    mux.handle_func("/big", |w: &mut dyn ResponseWriter, r: &mut Request| {
        let total = query_int(r, "n");
        let mut sent = 0usize;
        let mut chunk = vec![0u8; 32 << 10];
        while sent < total {
            let k = chunk.len().min(total - sent);
            for (i, b) in chunk[..k].iter_mut().enumerate() {
                *b = ((sent + i) % 251) as u8;
            }
            if w.write(&chunk[..k]).is_err() {
                return;
            }
            sent += k;
        }
    })
    .unwrap();

    mux.handle_func(
        "/trailers",
        |w: &mut dyn ResponseWriter, _r: &mut Request| {
            w.header().set("Trailer", "X-Checksum, X-Done");
            let _ = w.write_string("payload");
            w.header().set("X-Checksum", "abc123");
            w.header().set("X-Done", "yes");
            w.header().set("Trailer:X-Late", "late");
        },
    )
    .unwrap();

    mux.handle_func(
        "/reqtrailers",
        |w: &mut dyn ResponseWriter, r: &mut Request| {
            let body = read_body(r);
            let mut out = format!("body={}", String::from_utf8_lossy(&body));
            if let Some(t) = r.trailer.get() {
                for (k, vv) in &t.0 {
                    out.push_str(&format!(" {k}={}", vv.join(",")));
                }
            }
            let _ = w.write_string(&out);
        },
    )
    .unwrap();

    mux.handle_func("/headers", |w: &mut dyn ResponseWriter, r: &mut Request| {
        let mut out = String::new();
        for (k, vv) in &r.header.0 {
            if k == "User-Agent" || k == "Accept-Encoding" {
                continue;
            }
            out.push_str(&format!("{k}={}\n", vv.join("|")));
        }
        let _ = w.write_string(&out);
    })
    .unwrap();

    mux.handle_func("/status/", |w: &mut dyn ResponseWriter, r: &mut Request| {
        let code: u16 = r
            .url
            .path
            .trim_start_matches("/status/")
            .parse()
            .unwrap_or(500);
        w.header().set("Content-Type", "text/plain");
        w.write_header(code);
        if code != 204 && code != 304 {
            let _ = w.write_string(&format!("status {code}"));
        }
    })
    .unwrap();

    mux.handle_func("/panic", |_w: &mut dyn ResponseWriter, _r: &mut Request| {
        panic!("boom");
    })
    .unwrap();

    mux.handle_func("/abort", |_w: &mut dyn ResponseWriter, _r: &mut Request| {
        std::panic::panic_any(ERR_ABORT_HANDLER);
    })
    .unwrap();

    mux.handle_func("/slow", |w: &mut dyn ResponseWriter, r: &mut Request| {
        let ctx = r.context();
        let canceled = ctx.done().wait_timeout(Duration::from_secs(4).into());
        let _ = w.write_string(if canceled { "canceled" } else { "finished" });
    })
    .unwrap();

    mux.handle_func("/flush", |w: &mut dyn ResponseWriter, _r: &mut Request| {
        let _ = w.write_string("a");
        let _ = http::ResponseController::new(w).flush();
        std::thread::sleep(Duration::from_millis(100));
        let _ = w.write_string("b");
    })
    .unwrap();

    mux.handle_func("/close", |w: &mut dyn ResponseWriter, _r: &mut Request| {
        w.header().set("Connection", "close");
        let _ = w.write_string("closing");
    })
    .unwrap();

    mux.handle_func("/cookie", |w: &mut dyn ResponseWriter, r: &mut Request| {
        let _ = w.write_string(&r.header.values("Cookie").join("|"));
    })
    .unwrap();

    mux.handle_func("/push", |w: &mut dyn ResponseWriter, _r: &mut Request| {
        let res = match w.pusher() {
            Some(p) => match p.push("/pushed", None) {
                Ok(()) => "ok".to_owned(),
                Err(e) => format!("err:{e}"),
            },
            None => "no-pusher".to_owned(),
        };
        let _ = w.write_string(&format!("push={res}"));
    })
    .unwrap();

    mux.handle_func("/pushed", |w: &mut dyn ResponseWriter, _r: &mut Request| {
        let _ = w.write_string("pushed content");
    })
    .unwrap();

    let b2 = barrier.clone();
    mux.handle_func(
        "/barrier",
        move |w: &mut dyn ResponseWriter, r: &mut Request| {
            let want = query_int(r, "n");
            let start = Instant::now();
            let mut g = b2.count.lock().unwrap();
            *g += 1;
            b2.cv.notify_all();
            while *g < want && start.elapsed() < Duration::from_secs(8) {
                g = b2.cv.wait_timeout(g, Duration::from_millis(50)).unwrap().0;
            }
            let reached = *g >= want;
            drop(g);
            let _ = w.write_string(&format!("barrier reached={reached}"));
        },
    )
    .unwrap();
    let b3 = barrier;
    mux.handle_func(
        "/barrier-reset",
        move |w: &mut dyn ResponseWriter, _r: &mut Request| {
            *b3.count.lock().unwrap() = 0;
            let _ = w.write_string("reset");
        },
    )
    .unwrap();

    mux
}
