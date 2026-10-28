//! Line protocol used by `tools/netip_check.py` for Go differential checks. See
//! `tools/netip_oracle.go` for the request and reply format.
use rust_stdlib::net::netip::{
    Addr, AddrPort, Prefix, IPV6_LINK_LOCAL_ALL_NODES, IPV6_LINK_LOCAL_ALL_ROUTERS,
};
use std::io::{self, BufRead, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

fn enc(s: &str) -> String {
    encb(s.as_bytes())
}

fn encb(b: &[u8]) -> String {
    if b.is_empty() {
        return "_".into();
    }
    b.iter().map(|b| format!("{b:02x}")).collect()
}

fn dec_bytes(s: &str) -> Vec<u8> {
    if s == "_" {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex argument"))
        .collect()
}

fn dec(s: &str) -> String {
    String::from_utf8(dec_bytes(s)).expect("UTF-8 argument")
}

fn flag(b: bool) -> String {
    if b { "1" } else { "0" }.into()
}

const PREFIX_BITS: [isize; 14] = [-1, 0, 1, 7, 8, 24, 31, 32, 33, 64, 96, 127, 128, 129];

fn dump_addr(ip: &Addr) -> Vec<String> {
    let mut t = vec![
        "OK".to_owned(),
        enc(&ip.to_string()),
        enc(&ip.string_expanded()),
        enc(ip.zone()),
        ip.bit_len().to_string(),
    ];
    let flags = [
        ip.is4(),
        ip.is4in6(),
        ip.is6(),
        ip.is_loopback(),
        ip.is_multicast(),
        ip.is_interface_local_multicast(),
        ip.is_link_local_multicast(),
        ip.is_link_local_unicast(),
        ip.is_global_unicast(),
        ip.is_private(),
        ip.is_unspecified(),
        ip.is_valid(),
    ];
    t.push(flags.iter().map(|b| flag(*b)).collect());
    t.push(enc(&ip.unmap().to_string()));
    t.push(enc(&ip.next().to_string()));
    t.push(enc(&ip.prev().to_string()));
    t.push(enc(&ip.with_zone("z1").to_string()));
    t.push(enc(&ip.with_zone("").to_string()));
    t.push(encb(&ip.as_slice()));
    let mt = ip.marshal_text().unwrap();
    let mb = ip.marshal_binary().unwrap();
    t.push(encb(&mt));
    t.push(encb(&mb));
    t.push(encb(&ip.append_text(b"x".to_vec()).unwrap()));
    t.push(encb(&ip.append_binary(b"y".to_vec()).unwrap()));
    t.push(encb(&ip.append_to(b"z".to_vec())));
    let mut back = Addr::default();
    match back.unmarshal_binary(&mb) {
        Err(_) => t.push("E".into()),
        Ok(()) => {
            t.push(enc(&back.to_string()));
            t.push(flag(back == *ip));
        }
    }
    let mut back_t = Addr::default();
    match back_t.unmarshal_text(&mt) {
        Err(_) => t.push("E".into()),
        Ok(()) => {
            t.push(enc(&back_t.to_string()));
            t.push(flag(back_t == *ip));
        }
    }
    if ip.is4() || ip.is4in6() {
        t.push(ip.as4().iter().map(|b| format!("{b:02x}")).collect());
    } else {
        t.push("-".into());
    }
    t.push(ip.as16().iter().map(|b| format!("{b:02x}")).collect());
    for b in PREFIX_BITS {
        match ip.prefix(b) {
            Err(e) => t.push(format!("E{}", enc(&e.to_string()))),
            Ok(p) => {
                t.push(enc(&p.to_string()));
                t.push(p.bits().to_string());
                t.push(flag(p.is_valid()));
            }
        }
        let pf = Prefix::new(ip.clone(), b);
        t.push(enc(&pf.to_string()));
        t.push(pf.bits().to_string());
        t.push(enc(&pf.masked().to_string()));
        t.push(flag(pf.is_single_ip()));
    }
    t
}

fn dump_prefix(p: &Prefix) -> Vec<String> {
    let mut t = vec![
        "OK".to_owned(),
        enc(&p.to_string()),
        p.bits().to_string(),
        enc(&p.addr().to_string()),
        flag(p.is_valid()),
        flag(p.is_single_ip()),
        enc(&p.masked().to_string()),
    ];
    let mt = p.marshal_text().unwrap();
    let mb = p.marshal_binary().unwrap();
    t.push(encb(&mt));
    t.push(encb(&mb));
    t.push(encb(&p.append_text(b"x".to_vec()).unwrap()));
    t.push(encb(&p.append_binary(b"y".to_vec()).unwrap()));
    t.push(encb(&p.append_to(b"z".to_vec())));
    let mut back = Prefix::default();
    match back.unmarshal_binary(&mb) {
        Err(_) => t.push("E".into()),
        Ok(()) => {
            t.push(enc(&back.to_string()));
            t.push(flag(back == *p));
        }
    }
    let mut back_t = Prefix::default();
    match back_t.unmarshal_text(&mt) {
        Err(_) => t.push("E".into()),
        Ok(()) => {
            t.push(enc(&back_t.to_string()));
            t.push(flag(back_t == *p));
        }
    }
    t
}

fn dump_addr_port(p: &AddrPort) -> Vec<String> {
    let mut t = vec![
        "OK".to_owned(),
        enc(&p.to_string()),
        enc(&p.addr().to_string()),
        p.port().to_string(),
        flag(p.is_valid()),
    ];
    let mt = p.marshal_text().unwrap();
    let mb = p.marshal_binary().unwrap();
    t.push(encb(&mt));
    t.push(encb(&mb));
    t.push(encb(&p.append_text(b"x".to_vec()).unwrap()));
    t.push(encb(&p.append_binary(b"y".to_vec()).unwrap()));
    t.push(encb(&p.append_to(b"z".to_vec())));
    let mut back = AddrPort::default();
    match back.unmarshal_binary(&mb) {
        Err(_) => t.push("E".into()),
        Ok(()) => {
            t.push(enc(&back.to_string()));
            t.push(flag(back == *p));
        }
    }
    let mut back_t = AddrPort::default();
    match back_t.unmarshal_text(&mt) {
        Err(_) => t.push("E".into()),
        Ok(()) => {
            t.push(enc(&back_t.to_string()));
            t.push(flag(back_t == *p));
        }
    }
    t
}

/// "~" is the zero Addr.
fn addr_arg(s: &str) -> Result<Addr, String> {
    if s == "~" {
        return Ok(Addr::default());
    }
    s.parse::<Addr>().map_err(|e| e.to_string())
}

/// "~" is the zero Prefix; "!addr/bits" is `Prefix::new`.
fn prefix_arg(s: &str) -> Prefix {
    if s == "~" {
        return Prefix::default();
    }
    if let Some(rest) = s.strip_prefix('!') {
        let i = rest.rfind('/').unwrap();
        let ip = addr_arg(&rest[..i]).unwrap_or_default();
        let bits = rest[i + 1..].parse::<isize>().unwrap_or(0);
        return Prefix::new(ip, bits);
    }
    s.parse().unwrap_or_default()
}

fn unmarshal_text(a: &str) -> Vec<String> {
    let mut t = Vec::new();
    let mut ia = Addr::default();
    t.push(match ia.unmarshal_text(a.as_bytes()) {
        Err(e) => format!("E{}", enc(&e.to_string())),
        Ok(()) => enc(&ia.to_string()),
    });
    let mut ip = AddrPort::default();
    t.push(match ip.unmarshal_text(a.as_bytes()) {
        Err(e) => format!("E{}", enc(&e.to_string())),
        Ok(()) => enc(&ip.to_string()),
    });
    let mut ix = Prefix::default();
    t.push(match ix.unmarshal_text(a.as_bytes()) {
        Err(e) => format!("E{}", enc(&e.to_string())),
        Ok(()) => enc(&ix.to_string()),
    });
    t
}

fn unmarshal_binary(b: &[u8]) -> Vec<String> {
    let mut t = Vec::new();
    t.push(match Addr::try_from(b).ok() {
        Some(ip) => enc(&ip.to_string()),
        None => "-".into(),
    });
    let mut ia = Addr::default();
    t.push(match ia.unmarshal_binary(b) {
        Err(e) => format!("E{}", enc(&e.to_string())),
        Ok(()) => enc(&ia.to_string()),
    });
    let mut ip = AddrPort::default();
    t.push(match ip.unmarshal_binary(b) {
        Err(e) => format!("E{}", enc(&e.to_string())),
        Ok(()) => enc(&ip.to_string()),
    });
    let mut ix = Prefix::default();
    match ix.unmarshal_binary(b) {
        Err(e) => t.push(format!("E{}", enc(&e.to_string()))),
        Ok(()) => {
            t.push(enc(&ix.to_string()));
            t.push(ix.bits().to_string());
        }
    }
    t
}

fn handle(line: &str) -> Vec<String> {
    let f: Vec<&str> = line.split_whitespace().collect();
    if f[0] == "B" {
        return unmarshal_binary(&dec_bytes(f[1]));
    }
    let a: Vec<String> = f[1..].iter().map(|s| dec(s)).collect();
    match f[0] {
        "A" => match addr_arg(&a[0]) {
            Err(e) => vec!["ERR".into(), enc(&e)],
            Ok(ip) => dump_addr(&ip),
        },
        "P" => match a[0].parse::<Prefix>() {
            Err(e) => vec!["ERR".into(), enc(&e.to_string())],
            Ok(p) => dump_prefix(&p),
        },
        "T" => match a[0].parse::<AddrPort>() {
            Err(e) => vec!["ERR".into(), enc(&e.to_string())],
            Ok(p) => dump_addr_port(&p),
        },
        "C" => {
            let x = addr_arg(&a[0]).unwrap_or_default();
            let y = addr_arg(&a[1]).unwrap_or_default();
            vec![(x.cmp(&y) as i32).to_string(), flag(x < y), flag(x == y)]
        }
        "K" => {
            let p = prefix_arg(&a[0]);
            let x = addr_arg(&a[1]).unwrap_or_default();
            vec![flag(p.contains(&x))]
        }
        "O" => {
            let (p, q) = (prefix_arg(&a[0]), prefix_arg(&a[1]));
            vec![
                flag(p.overlaps(&q)),
                flag(q.overlaps(&p)),
                (p.cmp(&q) as i32).to_string(),
                flag(p == q),
            ]
        }
        "N" => {
            let x = addr_arg(&a[0]).unwrap_or_default();
            let mut t = Vec::new();
            let mut cur = x.clone();
            for _ in 0..3 {
                cur = cur.next();
                t.push(enc(&cur.to_string()));
                t.push(flag(cur == Addr::default()));
            }
            cur = x;
            for _ in 0..3 {
                cur = cur.prev();
                t.push(enc(&cur.to_string()));
                t.push(flag(cur == Addr::default()));
            }
            t
        }
        "U" => unmarshal_text(&a[0]),
        "S" => [
            Addr::from(Ipv4Addr::UNSPECIFIED),
            Addr::from(Ipv6Addr::UNSPECIFIED),
            Addr::from(Ipv6Addr::LOCALHOST),
            Addr::from(IPV6_LINK_LOCAL_ALL_NODES),
            Addr::from(IPV6_LINK_LOCAL_ALL_ROUTERS),
            Addr::default(),
        ]
        .iter()
        .map(|ip| enc(&ip.to_string()))
        .collect(),
        op => panic!("unknown op {op}"),
    }
}

fn main() {
    let stdin = io::stdin();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        writeln!(out, "{}", handle(&line.unwrap()).join(" ")).unwrap();
    }
}
