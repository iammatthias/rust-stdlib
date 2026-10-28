//! Probe for the `os/user` differential (`tools/os_user_check.py`).
use rust_stdlib_sys::os::user;
use std::io::{self, BufRead};

fn enc(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

fn dec(s: &str) -> String {
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect();
    String::from_utf8(bytes).expect("UTF-8 input")
}

fn err_text(e: &io::Error) -> String {
    format!("err:{}", enc(&e.to_string()))
}

fn u(r: io::Result<user::User>) -> String {
    match r {
        Err(e) => err_text(&e),
        Ok(u) => [&u.uid, &u.gid, &u.username, &u.name, &u.home_dir]
            .iter()
            .map(|s| enc(s))
            .collect::<Vec<_>>()
            .join(","),
    }
}

fn g(r: io::Result<user::Group>) -> String {
    match r {
        Err(e) => err_text(&e),
        Ok(g) => format!("{},{}", enc(&g.gid), enc(&g.name)),
    }
}

fn ids(r: io::Result<Vec<String>>) -> String {
    match r {
        Err(e) => err_text(&e),
        Ok(v) => enc(&v.join(",")),
    }
}

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.expect("stdin");
        let f: Vec<&str> = line.split('\t').collect();
        let arg = f.get(1).map(|v| dec(v)).unwrap_or_default();
        let r = match f[0] {
            "lookup" => u(user::lookup(&arg)),
            "lookupid" => u(user::lookup_id(&arg)),
            "group" => g(user::lookup_group(&arg)),
            "groupid" => g(user::lookup_group_id(&arg)),
            "groupids" => match user::lookup(&arg) {
                Err(e) => err_text(&e),
                Ok(us) => ids(us.group_ids()),
            },
            "current" => u(user::current()),
            "groupidsfor" => {
                let (name, gid) = arg.split_once(',').unwrap();
                let us = user::User {
                    username: name.to_string(),
                    gid: gid.to_string(),
                    ..Default::default()
                };
                ids(us.group_ids())
            }
            other => panic!("unknown op {other}"),
        };
        println!("{}|{r}", f[0]);
    }
}
