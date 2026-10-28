//! Resolver probe for `tools/dns_check.py`; mirrors `tools/dns_oracle.go`.
//! Usage: `dns_probe <fake-server host:port>`.
use rust_stdlib::context::Context;
use rust_stdlib::net::{dial, NetError, Resolver};
use rust_stdlib::strconv::quote;
use std::io::{self, BufRead, Write};
use std::sync::Arc;

fn resolver(strict: bool, fake: &str) -> Resolver {
    let fake = fake.to_owned();
    Resolver {
        prefer_builtin: true,
        strict_errors: strict,
        dial: Some(Arc::new(move |_ctx, network, _address| {
            dial(network, &fake)
        })),
    }
}

fn err_tok(e: &NetError) -> String {
    let mut s = format!("ERR {}", quote(e.to_string()));
    if let NetError::Dns(d) = e {
        s += &format!(
            " | name={} server={} timeout={} temporary={} notfound={} unwrap={}",
            quote(&d.name),
            quote(&d.server),
            d.timeout(),
            d.temporary(),
            d.is_not_found,
            d.unwrap().is_some()
        );
    }
    s
}

fn result(list: Vec<String>, err: Option<NetError>) -> String {
    let body = list.join(",");
    match err {
        Some(e) if !list.is_empty() => format!("PARTIAL {body} {}", err_tok(&e)),
        Some(e) => err_tok(&e),
        None => format!("OK {body}"),
    }
}

fn split<T>(r: Result<Vec<T>, NetError>) -> (Vec<T>, Option<NetError>) {
    match r {
        Ok(v) => (v, None),
        Err(e) => (Vec::new(), Some(e)),
    }
}

fn split2<T>(r: Result<(Vec<T>, Option<NetError>), NetError>) -> (Vec<T>, Option<NetError>) {
    match r {
        Ok(v) => v,
        Err(e) => (Vec::new(), Some(e)),
    }
}

fn handle(line: &str, fake: &str) -> String {
    let mut f: Vec<&str> = line.split_whitespace().collect();
    let strict = f.last() == Some(&"strict");
    if strict {
        f.pop();
    }
    let r = resolver(strict, fake);
    let ctx = Context::background();
    match f[0] {
        "host" => {
            let (l, e) = split(r.lookup_host(&ctx, f[1]));
            result(l, e)
        }
        "ip" => {
            let (l, e) = split(r.lookup_ip(&ctx, f[1], f[2]));
            result(l.iter().map(|i| i.to_string()).collect(), e)
        }
        "ipaddr" => {
            let (l, e) = split(r.lookup_ip_addr(&ctx, f[1]));
            result(l.iter().map(|i| i.to_string()).collect(), e)
        }
        "netip" => {
            let (l, e) = split(r.lookup_net_ip(&ctx, f[1], f[2]));
            result(l.iter().map(|i| i.to_string()).collect(), e)
        }
        "cname" => match r.lookup_cname(&ctx, f[1]) {
            Ok(c) => format!("OK {c}"),
            Err(e) => err_tok(&e),
        },
        "mx" => {
            let (m, e) = split2(r.lookup_mx(&ctx, f[1]));
            let mut l: Vec<String> = m.iter().map(|x| format!("{}:{}", x.host, x.pref)).collect();
            l.sort();
            result(l, e)
        }
        "ns" => {
            let (m, e) = split2(r.lookup_ns(&ctx, f[1]));
            result(m.into_iter().map(|x| x.host).collect(), e)
        }
        "txt" => {
            let (m, e) = split(r.lookup_txt(&ctx, f[1]));
            result(m.iter().map(quote).collect(), e)
        }
        "srv" => {
            let svc = if f[1] == "-" { "" } else { f[1] };
            let proto = if f[2] == "-" { "" } else { f[2] };
            match r.lookup_srv(&ctx, svc, proto, f[3]) {
                Ok((cname, s, e)) => {
                    let mut l: Vec<String> = s
                        .iter()
                        .map(|x| format!("{}:{}:{}:{}", x.target, x.port, x.priority, x.weight))
                        .collect();
                    l.sort();
                    format!("cname={cname} {}", result(l, e))
                }
                Err(e) => format!("cname= {}", err_tok(&e)),
            }
        }
        "addr" => {
            let (l, e) = split2(r.lookup_addr(&ctx, f[1]));
            result(l, e)
        }
        op => panic!("unknown op {op}"),
    }
}

fn main() {
    let fake = std::env::args().nth(1).expect("fake server address");
    let stdin = io::stdin();
    let mut out = io::stdout().lock();
    for line in stdin.lock().lines() {
        writeln!(out, "{}", handle(&line.unwrap(), &fake)).unwrap();
        out.flush().unwrap();
    }
}
