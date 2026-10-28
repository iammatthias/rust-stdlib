//! Line protocol used by `tools/url_check.py` for Go differential checks. See
//! `tools/url_oracle.go` for the request and reply format.
use rust_stdlib::net::url::{self, Url, Values};
use std::io::{self, BufRead, Write};

fn enc(s: &str) -> String {
    if s.is_empty() {
        return "_".into();
    }
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

fn enc_bytes(b: &[u8]) -> String {
    if b.is_empty() {
        return "_".into();
    }
    b.iter().map(|b| format!("{b:02x}")).collect()
}

fn dec(s: &str) -> String {
    if s == "_" {
        return String::new();
    }
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex argument"))
        .collect();
    String::from_utf8(bytes).expect("UTF-8 argument")
}

fn flag(b: bool) -> String {
    if b { "1" } else { "0" }.into()
}

fn dump_url(u: &Url) -> Vec<String> {
    let mut t = vec!["OK".to_owned(), enc(&u.scheme), enc(&u.opaque)];
    match &u.user {
        Some(user) => {
            t.push("1".into());
            t.push(enc_bytes(user.username_bytes()));
            t.push(enc_bytes(user.password_bytes().unwrap_or(b"")));
            t.push(flag(user.password().is_some()));
        }
        None => t.extend(["0".into(), "_".into(), "_".into(), "0".into()]),
    }
    t.extend([
        enc_bytes(u.host_bytes()),
        enc(&u.path),
        enc(&u.raw_path),
        flag(u.omit_host),
        flag(u.force_query),
        enc(&u.raw_query),
        enc(&u.fragment),
        enc(&u.raw_fragment),
        enc(&u.to_string()),
        enc(&u.redacted()),
        enc(&u.escaped_path()),
        enc(&u.escaped_fragment()),
        enc(&u.hostname()),
        enc(&u.port()),
        flag(u.is_abs()),
        enc(&u.request_uri()),
        enc(&u.query().encode()),
    ]);
    let binary = u.marshal_binary().expect("MarshalBinary cannot fail");
    t.push(enc(&String::from_utf8(binary.clone()).expect("UTF-8")));
    let mut back = Url::default();
    match back.unmarshal_binary(&binary) {
        Ok(()) => t.extend(["B".into(), enc(&back.to_string())]),
        Err(e) => t.extend(["E".into(), enc(&e.to_string())]),
    }
    t
}

fn result(r: Result<Url, url::Error>) -> Vec<String> {
    match r {
        Ok(u) => dump_url(&u),
        Err(e) => vec!["E".into(), enc(&e.to_string())],
    }
}

fn dump_values(v: &Values, err: Option<url::BoxError>) -> Vec<String> {
    let mut t = match err {
        Some(e) => vec!["E".to_owned(), enc(&e.to_string())],
        None => vec!["OK".to_owned()],
    };
    t.push(v.0.len().to_string());
    for (k, vs) in &v.0 {
        t.push(enc(k));
        t.push(vs.len().to_string());
        t.extend(vs.iter().map(|x| enc(x)));
    }
    t.push(enc(&v.encode()));
    t
}

fn handle(op: &str, args: &[String]) -> Vec<String> {
    let arg = |i: usize| args[i].as_str();
    match op {
        "P" => result(url::parse(arg(0))),
        "R" => result(url::parse_request_uri(arg(0))),
        "X" => {
            let base = match url::parse(arg(0)) {
                Ok(u) => u,
                Err(e) => return vec!["E1".into(), enc(&e.to_string())],
            };
            let reference = match url::parse(arg(1)) {
                Ok(u) => u,
                Err(e) => return vec!["E2".into(), enc(&e.to_string())],
            };
            let mut t = dump_url(&base.resolve_reference(&reference));
            t.extend(result(base.parse(arg(1))));
            t
        }
        "J" => {
            let elems: Vec<&str> = args[1..].iter().map(String::as_str).collect();
            let mut t = match url::join_path(arg(0), &elems) {
                Ok(out) => vec!["OK".to_owned(), enc(&out)],
                Err(e) => vec!["E".to_owned(), enc(&e.to_string())],
            };
            if let Ok(u) = url::parse(arg(0)) {
                t.push("U".into());
                t.push(enc(&u.join_path(&elems).to_string()));
            }
            t
        }
        "QE" => vec![
            "OK".into(),
            enc(&url::query_escape(arg(0))),
            enc(&url::path_escape(arg(0))),
        ],
        "QU" | "PU" => {
            let r = if op == "QU" {
                url::query_unescape(arg(0))
            } else {
                url::path_unescape(arg(0))
            };
            match r {
                Ok(s) => vec!["OK".into(), enc(&s)],
                Err(e) => vec!["E".into(), enc(&e.to_string())],
            }
        }
        "Q" => {
            let (v, err) = url::parse_query(arg(0));
            dump_values(&v, err)
        }
        "H" => {
            let u = Url {
                host: arg(0).into(),
                ..Url::default()
            };
            vec!["OK".into(), enc(&u.hostname()), enc(&u.port())]
        }
        _ => panic!("unknown op {op}"),
    }
}

fn main() -> io::Result<()> {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line?;
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some((op, rest)) = fields.split_first() else {
            continue;
        };
        let args: Vec<String> = rest.iter().map(|a| dec(a)).collect();
        writeln!(out, "{}", handle(op, &args).join(" "))?;
    }
    Ok(())
}
