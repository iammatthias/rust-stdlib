//! File deadline scenarios of the Go differential; see tools/sys_oracle_file.go.
use rust_stdlib_sys::os::{pipe, File, FileKind};
use std::fs::OpenOptions;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

fn err_text<E: std::fmt::Display>(r: Result<(), E>) -> String {
    match r {
        Ok(()) => "ok".into(),
        Err(e) => format!("err {e}"),
    }
}

fn within(start: Instant, lo: u64, hi: u64) -> bool {
    let el = start.elapsed();
    el >= Duration::from_millis(lo) && el < Duration::from_millis(hi)
}

fn after(ms: u64) -> Option<SystemTime> {
    Some(SystemTime::now() + Duration::from_millis(ms))
}

fn sleep(ms: u64) {
    std::thread::sleep(Duration::from_millis(ms));
}

pub fn run(f: &[&str]) -> String {
    match f[0] {
        "fdl_timeout" => {
            let ms: u64 = f[1].parse().unwrap();
            let (r, _w) = pipe().unwrap();
            let start = Instant::now();
            r.set_read_deadline(after(ms)).unwrap();
            let res = r.read(&mut [0u8; 8]);
            let (n, e) = match res {
                Ok(n) => (n, "ok".to_string()),
                Err(e) => (0, format!("err {e}")),
            };
            format!("n={n} {e} timely={}", within(start, ms - 5, ms + 500))
        }
        "fdl_past" => {
            let (r, w) = pipe().unwrap();
            w.write(b"x").unwrap();
            let e1 = r.set_read_deadline(Some(SystemTime::now() - Duration::from_secs(1)));
            let (n, e) = match r.read(&mut [0u8; 8]) {
                Ok(n) => (n, "ok".to_string()),
                Err(e) => (0, format!("err {e}")),
            };
            let mut out = format!("set={} n={n} {e}", err_text(e1));
            let e2 = r.set_read_deadline(None);
            let (n, e) = match r.read(&mut [0u8; 8]) {
                Ok(n) => (n, "ok".to_string()),
                Err(e) => (0, format!("err {e}")),
            };
            out.push_str(&format!(" cleared={} n={n} {e}", err_text(e2)));
            out
        }
        "fdl_extend" => {
            let (r, _w) = pipe().unwrap();
            let r = Arc::new(r);
            let start = Instant::now();
            r.set_read_deadline(after(3000)).unwrap();
            let r2 = r.clone();
            let t = std::thread::spawn(move || {
                sleep(100);
                r2.set_read_deadline(after(50)).unwrap();
            });
            let e = r.read(&mut [0u8; 8]).map(|_| ());
            t.join().unwrap();
            format!("{} timely={}", err_text(e), within(start, 140, 1000))
        }
        "fdl_shorten_now" => {
            let (r, _w) = pipe().unwrap();
            let r = Arc::new(r);
            let start = Instant::now();
            let r2 = r.clone();
            let t = std::thread::spawn(move || {
                sleep(100);
                r2.set_deadline(Some(SystemTime::now() - Duration::from_secs(1)))
                    .unwrap();
            });
            let e = r.read(&mut [0u8; 8]).map(|_| ());
            t.join().unwrap();
            format!("{} timely={}", err_text(e), within(start, 95, 1000))
        }
        "fdl_cancel" => {
            let (r, w) = pipe().unwrap();
            let r = Arc::new(r);
            let start = Instant::now();
            r.set_read_deadline(after(250)).unwrap();
            let r2 = r.clone();
            let t = std::thread::spawn(move || {
                sleep(100);
                r2.set_read_deadline(None).unwrap();
                sleep(300);
                w.write(b"z").unwrap();
            });
            let (n, e) = match r.read(&mut [0u8; 8]) {
                Ok(n) => (n, "ok".to_string()),
                Err(e) => (0, format!("err {e}")),
            };
            t.join().unwrap();
            format!("n={n} {e} timely={}", within(start, 390, 1500))
        }
        "fdl_close" => {
            let (r, w) = pipe().unwrap();
            let r = Arc::new(r);
            let start = Instant::now();
            let r2 = r.clone();
            let t = std::thread::spawn(move || {
                sleep(100);
                r2.close().unwrap();
            });
            let e = r.read(&mut [0u8; 8]).map(|_| ());
            t.join().unwrap();
            let mut out = format!("{} timely={}", err_text(e), within(start, 95, 1000));
            out.push_str(&format!(" close2={}", err_text(r.close())));
            out.push_str(&format!(
                " read={}",
                err_text(r.read(&mut [0u8; 8]).map(|_| ()))
            ));
            out.push_str(&format!(" setdl={}", err_text(r.set_deadline(after(1000)))));
            // Go's write to a pipe with no reader: EPIPE.
            out.push_str(&format!(
                " wclosedpeer={}",
                err_text(w.write(b"x").map(|_| ()))
            ));
            out
        }
        "fdl_write" => {
            let (_r, w) = pipe().unwrap();
            let start = Instant::now();
            w.set_write_deadline(after(150)).unwrap();
            let chunk = vec![0u8; 65536];
            let mut total = 0usize;
            let mut res: Result<(), rust_stdlib_sys::os::FileError> = Ok(());
            while res.is_ok() && total < 64 << 20 {
                match w.write(&chunk) {
                    Ok(n) => total += n,
                    Err(e) => res = Err(e),
                }
            }
            format!(
                "{} wrote={} timely={}",
                err_text(res),
                total > 0,
                within(start, 145, 1500)
            )
        }
        "fdl_files" => {
            let mut out = Vec::new();
            for name in ["f", "d", "/dev/null", "ff"] {
                let opened = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(name)
                    .or_else(|_| OpenOptions::new().read(true).open(name));
                let file = match opened {
                    Ok(file) => file,
                    Err(e) => {
                        out.push(format!(
                            "{name}:err open {name}: {}",
                            rust_stdlib_sys::errno::Errno::from(e)
                        ));
                        continue;
                    }
                };
                let file = File::new(file, name, FileKind::OpenFile).unwrap();
                out.push(format!(
                    "{name}:{},{},{}",
                    err_text(file.set_deadline(after(1000))),
                    err_text(file.set_read_deadline(after(1000))),
                    err_text(file.set_write_deadline(None))
                ));
                file.close().unwrap();
            }
            format!("[{}]", out.join(" "))
        }
        "fdl_pipe_kind" => {
            let (r, w) = pipe().unwrap();
            let (ri, wi) = (r.stat().unwrap(), w.stat().unwrap());
            let pipe_bit = rust_stdlib_sys::os::FileMode::NAMED_PIPE;
            format!(
                "names={},{} rmode={} wmode={} named_pipe={},{} rwrite={} wread={}",
                r.name(),
                w.name(),
                ri.mode(),
                wi.mode(),
                ri.mode().0 & pipe_bit != 0,
                wi.mode().0 & pipe_bit != 0,
                err_text(r.write(b"x").map(|_| ())),
                err_text(w.read(&mut [0u8; 1]).map(|_| ()))
            )
        }
        "fdl_rw" => {
            let (r, w) = pipe().unwrap();
            let n = w.write(b"hello").unwrap();
            let mut out = format!("w={n} ok");
            let mut buf = [0u8; 3];
            let n = r.read(&mut buf).unwrap();
            out.push_str(&format!(
                " r={n} ok {:?}",
                String::from_utf8_lossy(&buf[..n])
            ));
            w.close().unwrap();
            let n = r.read(&mut buf).unwrap();
            out.push_str(&format!(" r2={n} ok"));
            let n = r.read(&mut buf).unwrap();
            out.push_str(&format!(
                " eof={n} {}",
                if n == 0 { "EOF" } else { "<nil>" }
            ));
            out
        }
        _ => crate::net_scenarios::run(f),
    }
}
