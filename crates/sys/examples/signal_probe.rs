//! Line protocol used by `tools/signal_check.py` for Go differential checks.
//! See `tools/signal_oracle.go` for the commands.
use rust_stdlib_sys::errno::Signal;
use rust_stdlib_sys::os::signal;
use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::sync::mpsc::Receiver;
use std::time::Duration;

#[cfg(target_os = "linux")]
const NAMES: &[(&str, i32)] = &[
    ("HUP", 1),
    ("INT", 2),
    ("QUIT", 3),
    ("USR1", 10),
    ("USR2", 12),
    ("ALRM", 14),
    ("TERM", 15),
    ("WINCH", 28),
    ("URG", 23),
    ("CHLD", 17),
    ("KILL", 9),
    ("STOP", 19),
    ("CONT", 18),
];
#[cfg(target_os = "macos")]
const NAMES: &[(&str, i32)] = &[
    ("HUP", 1),
    ("INT", 2),
    ("QUIT", 3),
    ("USR1", 30),
    ("USR2", 31),
    ("ALRM", 14),
    ("TERM", 15),
    ("WINCH", 28),
    ("URG", 16),
    ("CHLD", 20),
    ("KILL", 9),
    ("STOP", 17),
    ("CONT", 19),
];

fn sigs(s: &str) -> Vec<Signal> {
    if s == "-" || s.is_empty() {
        return Vec::new();
    }
    s.split(',')
        .map(|n| match NAMES.iter().find(|(name, _)| *name == n) {
            Some((_, v)) => Signal(*v),
            None => Signal(n.parse().expect("signal")),
        })
        .collect()
}

fn main() {
    let mut chans: HashMap<String, (signal::Chan, Receiver<Signal>)> = HashMap::new();
    let mut ctxs: HashMap<String, (signal::NotifyContext, signal::Stop)> = HashMap::new();
    let stdin = io::stdin();
    let mut out = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.expect("stdin");
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.is_empty() {
            continue;
        }
        let reply = match f[0] {
            "pid" => std::process::id().to_string(),
            "chan" => {
                chans.insert(f[1].to_owned(), signal::channel(f[2].parse().unwrap()));
                "ok".to_owned()
            }
            "notify" => {
                signal::notify(&chans[f[1]].0, &sigs(f[2]));
                "ok".to_owned()
            }
            "stop" => {
                signal::stop(&chans[f[1]].0);
                "ok".to_owned()
            }
            "ignore" => {
                signal::ignore(&sigs(f[1]));
                "ok".to_owned()
            }
            "reset" => {
                signal::reset(&sigs(f[1]));
                "ok".to_owned()
            }
            "ignored" => signal::ignored(sigs(f[1])[0]).to_string(),
            "ctx" => {
                ctxs.insert(
                    f[1].to_owned(),
                    signal::notify_context(signal::Parent::background(), &sigs(f[2])),
                );
                "ok".to_owned()
            }
            "ctxstop" => {
                ctxs[f[1]].1.stop();
                "ok".to_owned()
            }
            "ctxinfo" => {
                let c = &ctxs[f[1]].0;
                std::thread::sleep(Duration::from_millis(40));
                let (err, cause) = match c.cause() {
                    None => ("<nil>".to_owned(), "<nil>".to_owned()),
                    Some(signal::Cause::Canceled) => {
                        ("context canceled".to_owned(), "context canceled".to_owned())
                    }
                    Some(signal::Cause::Signal(e)) => {
                        ("context canceled".to_owned(), e.to_string())
                    }
                    Some(signal::Cause::Parent) => unreachable!("the oracle has no parent"),
                };
                format!("err={err} cause={cause} str={c}")
            }
            "drain" => {
                std::thread::sleep(Duration::from_millis(40));
                let rx = &chans[f[1]].1;
                let mut got = Vec::new();
                while let Ok(s) = rx.try_recv() {
                    got.push(s.to_string());
                }
                got.join(",")
            }
            _ => "unknown command".to_owned(),
        };
        writeln!(out, "{reply}").unwrap();
        out.flush().unwrap();
    }
}
