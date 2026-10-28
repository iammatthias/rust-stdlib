//! Line protocol used by `tools/cookiejar_check.py` for Go differential checks.
//! Requests and responses match `tools/cookiejar_oracle.go`.
use rust_stdlib::net::http::cookiejar::{Jar, Options, PublicSuffixList};
use rust_stdlib::net::http::{Cookie, TIME_FORMAT};
use rust_stdlib::net::url;
use rust_stdlib::time;
use std::error::Error;
use std::fmt;
use std::io::{self, BufRead, Write};

/// The fixed list shared with `tools/cookiejar_oracle.go`.
const TEST_LIST: [&str; 7] = [
    "com",
    "org",
    "uk",
    "co.uk",
    "k12.ma.us",
    "ma.us",
    "github.io",
];

struct TestList;

impl fmt::Display for TestList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("test-psl")
    }
}

impl PublicSuffixList for TestList {
    fn public_suffix(&self, domain: &str) -> String {
        TEST_LIST
            .iter()
            .filter(|s| domain == **s || domain.ends_with(&format!(".{s}")))
            .max_by_key(|s| s.len())
            .map_or_else(String::new, |s| (*s).to_owned())
    }
}

fn from_hex(text: &str) -> Result<String, Box<dyn Error>> {
    if !text.len().is_multiple_of(2) {
        return Err("odd-length hex input".into());
    }
    let bytes = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()?;
    Ok(String::from_utf8(bytes)?)
}

fn hex(text: &str) -> String {
    text.bytes().map(|b| format!("{b:02x}")).collect()
}

fn cookie_from(field: &str) -> Result<Cookie, Box<dyn Error>> {
    let parts: Vec<&str> = field.split(',').collect();
    if parts.len() != 7 {
        return Err(format!("bad cookie field {field}").into());
    }
    let mut cookie = Cookie {
        name: from_hex(parts[0])?,
        value: from_hex(parts[1])?,
        quoted: parts[6] == "q",
        path: from_hex(parts[2])?,
        domain: from_hex(parts[3])?,
        max_age: parts[4].parse::<i64>()?,
        ..Cookie::default()
    };
    let expires = from_hex(parts[5])?;
    if !expires.is_empty() {
        if let Ok(t) = time::Time::parse(TIME_FORMAT, &expires) {
            cookie.expires = t;
        }
    }
    cookie.secure = parts[6] == "s";
    cookie.http_only = parts[6] == "h";
    Ok(cookie)
}

fn run(line: &str) -> Result<String, Box<dyn Error>> {
    let mut fields = line.split('\t');
    let mode = fields.next().unwrap_or("");
    let options = (mode == "t").then(|| Options {
        public_suffix_list: Some(Box::new(TestList)),
    });
    let jar = Jar::new(options)?;
    let mut batch_url: Option<url::Url> = None;
    let mut batch: Vec<Cookie> = Vec::new();
    let mut out: Vec<String> = Vec::new();
    let flush = |batch_url: &mut Option<url::Url>, batch: &mut Vec<Cookie>| {
        if let Some(u) = batch_url.take() {
            if !batch.is_empty() {
                jar.set_cookies(&u, batch);
            }
        }
        batch.clear();
    };
    for field in fields.filter(|f| !f.is_empty()) {
        let (op, rest) = field.split_at(1);
        match op {
            "S" => {
                flush(&mut batch_url, &mut batch);
                batch_url = url::parse(&from_hex(rest)?).ok();
            }
            "C" => {
                if batch_url.is_some() {
                    batch.push(cookie_from(rest)?);
                }
            }
            "G" => {
                flush(&mut batch_url, &mut batch);
                match url::parse(&from_hex(rest)?) {
                    Err(_) => out.push("urlerr".into()),
                    Ok(u) => {
                        let pairs: Vec<String> = jar
                            .cookies(&u)
                            .iter()
                            .map(|c| {
                                format!(
                                    "{}={}{}",
                                    hex(&c.name),
                                    hex(&c.value),
                                    if c.quoted { "q" } else { "" }
                                )
                            })
                            .collect();
                        out.push(pairs.join(";"));
                    }
                }
            }
            _ => return Err(format!("unknown op {op}").into()),
        }
    }
    flush(&mut batch_url, &mut batch);
    Ok(out.join("\t"))
}

fn main() -> Result<(), Box<dyn Error>> {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        writeln!(out, "{}", run(&line?)?)?;
    }
    out.flush()?;
    Ok(())
}
