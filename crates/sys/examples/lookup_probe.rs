//! Rust side of the cgo-resolver differential (tools/dns_check.py): the
//! counterpart of tools/lookup_oracle.go.

#[cfg(not(all(
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64"
)))]
fn main() {}

#[cfg(all(
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64"
))]
fn main() {
    use rust_stdlib_sys::net::{self, DnsError, LookupOrder, Resolver};
    use std::io::{BufRead, Write};

    fn enc(s: &str) -> String {
        s.bytes().map(|b| format!("{b:02x}")).collect()
    }

    fn err_text(e: &Option<DnsError>) -> String {
        match e {
            None => "-".into(),
            Some(e) => {
                let mut flags = String::new();
                if e.is_timeout {
                    flags.push('T');
                }
                if e.is_temporary {
                    flags.push('t');
                }
                if e.is_not_found {
                    flags.push('N');
                }
                format!("{}:{flags}", enc(&e.to_string()))
            }
        }
    }

    let out = std::io::stdout();
    let mut w = std::io::BufWriter::new(out.lock());
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        let f: Vec<&str> = line.splitn(4, '\t').collect();
        match f[0] {
            "addr" => {
                let (names, err) = match net::lookup_addr(f[1]) {
                    Ok(n) => (n.join(","), None),
                    Err(e) => (String::new(), Some(e)),
                };
                writeln!(w, "addr|{}|{}", enc(&names), err_text(&err)).unwrap();
            }
            "cname" => {
                let (c, err) = match net::lookup_cname(f[1]) {
                    Ok(c) => (c, None),
                    Err(e) => (String::new(), Some(e)),
                };
                writeln!(w, "cname|{}|{}", enc(&c), err_text(&err)).unwrap();
            }
            "order" => {
                let r = Resolver {
                    prefer_builtin: f[1] == "1",
                    pure: None,
                };
                let name = if f[2] == "addr" { "" } else { f[3] };
                let o = match r.lookup_order(name) {
                    LookupOrder::Cgo => "cgo",
                    LookupOrder::Go => "go",
                };
                writeln!(w, "order|{o}").unwrap();
            }
            other => panic!("unknown {other}"),
        }
    }
}
