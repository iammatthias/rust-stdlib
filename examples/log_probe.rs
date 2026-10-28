//! Line protocol used by `tools/log_check.py` for the Go `log` differential.
//! Each stdin line is a JSON scenario; each stdout line is `R:flags|hex(prefix)|hex(output)`.
use rust_stdlib::{
    encoding::json::{self, Value as J},
    log::{self, Logger},
    time::DateTime,
};
use std::{
    io::{self, BufRead, Write},
    panic::Location,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
struct Shared(Arc<Mutex<Vec<u8>>>);

impl Write for Shared {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn field<'a>(v: &'a J, k: &str) -> &'a str {
    match v.get(k) {
        Some(J::String(s)) => s,
        _ => "",
    }
}

/// Go's fake clock starts at 2000-01-01T00:00:00Z.
const EPOCH_2000: i64 = 946_684_800;

#[track_caller]
fn run(spec: &J) -> String {
    let flags = spec.get("flags").and_then(|v| match v {
        J::Number(n) => n.as_i64(),
        _ => None,
    });
    let flags = flags.unwrap() as i32;
    let delay: i64 = field(spec, "delay").parse().unwrap();
    let t = DateTime::from_unix(
        EPOCH_2000 + delay.div_euclid(1_000_000_000),
        delay.rem_euclid(1_000_000_000) as u32,
        0,
    )
    .unwrap();
    let msg = field(spec, "msg");
    let text = if field(spec, "call") == "println" {
        format!("{msg}\n")
    } else {
        msg.to_owned()
    };
    let buf = Shared(Arc::new(Mutex::new(Vec::new())));
    let pkg = matches!(spec.get("pkg"), Some(J::Bool(true)));
    let owned;
    let logger: &Logger = if pkg {
        log::set_output(buf.clone());
        log::set_flags(flags);
        log::set_prefix(field(spec, "prefix"));
        log::default()
    } else {
        owned = Logger::new(buf.clone(), field(spec, "prefix"), flags);
        &owned
    };
    logger
        .output_at(&t, Some(Location::caller()), &text)
        .expect("write");
    let out = buf.0.lock().unwrap().clone();
    let line = format!(
        "R:{}|{}|{}",
        logger.flags(),
        hex(logger.prefix().as_bytes()),
        hex(&out)
    );
    if pkg {
        log::set_output(io::stderr());
    }
    line
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    for line in io::stdin().lock().lines() {
        let spec = line?.parse::<json::Value>()?;
        println!("{}", run(&spec));
    }
    Ok(())
}
