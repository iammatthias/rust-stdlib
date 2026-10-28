//! Line protocol used by `tools/log_check.py` for the Go `log/syslog` differential.
//! Usage: syslog_probe NETWORK RADDR, scenarios as JSON lines on stdin.
use rust_stdlib::{
    encoding::json::{self, Value as J},
    log::syslog::{self, Priority},
};
use std::io::{self, BufRead};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let (network, raddr) = (&args[1], &args[2]);
    for line in io::stdin().lock().lines() {
        let spec = line?.parse::<json::Value>()?;
        let priority = match spec.get("priority") {
            Some(J::Number(n)) => n.as_i64().unwrap() as i32,
            _ => panic!("priority"),
        };
        let tag = match spec.get("tag") {
            Some(J::String(s)) => s.as_str(),
            _ => "",
        };
        let w = match syslog::dial(network, raddr, Priority(priority), tag) {
            Ok(w) => w,
            Err(e) => {
                println!("dial-error: {e}");
                continue;
            }
        };
        let ops = match spec.get("ops") {
            Some(J::Array(a)) => a,
            _ => panic!("ops"),
        };
        for op in ops {
            let J::Array(op) = op else { panic!("op") };
            let (J::String(name), J::String(msg)) = (&op[0], &op[1]) else {
                panic!("op fields")
            };
            let result = match name.as_str() {
                "emerg" => w.emerg(msg),
                "alert" => w.alert(msg),
                "crit" => w.crit(msg),
                "err" => w.err(msg),
                "warning" => w.warning(msg),
                "notice" => w.notice(msg),
                "info" => w.info(msg),
                "debug" => w.debug(msg),
                "write" => w.write(msg.as_bytes()).map(|_| ()),
                other => panic!("unknown op {other}"),
            };
            if let Err(e) = result {
                println!("op-error: {e}");
            }
            if network == "unixgram" {
                // Match the Go oracle's pacing: Unix datagram queues are tiny.
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        }
        w.close()?;
    }
    for p in [-1, 192, 1000] {
        let e = syslog::dial(network, raddr, Priority(p), "x").unwrap_err();
        println!("invalid {p} {e}");
    }
    Ok(())
}
