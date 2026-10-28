//! Rust side of the Go differential (tools/sys_check.py): reads one tab
//! separated scenario per line and prints one observation line per scenario,
//! matching tools/sys_oracle.go.
/// The probe needs the descriptor-based API, present on Linux and macOS only.
macro_rules! supported {
    ($($item:item)*) => {
        $(
            #[cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]
            $item
        )*
    };
}

#[cfg(not(all(
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64"
)))]
fn main() {}

supported! {
use rust_stdlib_sys::errno::{self, Errno, Signal};
use rust_stdlib_sys::os;
use std::io::{BufRead, Write};
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod dial_scenarios;
mod file_scenarios;
mod msg_scenarios;
mod net_scenarios;
mod wake_scenarios;

fn err_text<E: std::fmt::Display>(r: Result<(), E>) -> String {
    match r {
        Ok(()) => "ok".into(),
        Err(e) => format!("err {e}"),
    }
}

fn time_or_none(sec: &str, nsec: &str) -> Option<SystemTime> {
    if sec == "-" {
        return None;
    }
    let (s, n): (i64, u32) = (sec.parse().unwrap(), nsec.parse().unwrap());
    Some(if s >= 0 {
        UNIX_EPOCH + Duration::new(s as u64, n)
    } else {
        UNIX_EPOCH - Duration::from_secs((-s) as u64) + Duration::from_nanos(n as u64)
    })
}

fn stat(name: &str) -> String {
    match std::fs::metadata(name) {
        Ok(m) => format!(
            "mtime={}.{:09} atime={}.{:09} nlink={}",
            m.mtime(),
            m.mtime_nsec(),
            m.atime(),
            m.atime_nsec(),
            m.nlink()
        ),
        Err(e) => format!("err stat {name}: {}", Errno::from(e)),
    }
}

fn run(f: &[&str]) -> String {
    match f[0] {
        "ids" => format!(
            "uid={} euid={} gid={} egid={} ppid={}",
            os::getuid(),
            os::geteuid(),
            os::getgid(),
            os::getegid(),
            os::getppid()
        ),
        "groups" => match os::getgroups() {
            Ok(mut g) => {
                g.sort();
                format!("ok {g:?}").replace(", ", " ")
            }
            Err(e) => format!("err {e}"),
        },
        "hostname" => match os::hostname() {
            Ok(h) => format!("ok {h}"),
            Err(e) => format!("err {e}"),
        },
        "errno" => format!("errno {} {}", f[1], Errno(f[1].parse().unwrap())),
        "signal" => format!("signal {} {}", f[1], Signal(f[1].parse().unwrap())),
        "errnos" => {
            let all = [
                errno::EPERM,
                errno::ENOENT,
                errno::ESRCH,
                errno::EINTR,
                errno::EIO,
                errno::EBADF,
                errno::EAGAIN,
                errno::ENOMEM,
                errno::EACCES,
                errno::EEXIST,
                errno::EXDEV,
                errno::ENOTDIR,
                errno::EISDIR,
                errno::EINVAL,
                errno::ENFILE,
                errno::EMFILE,
                errno::ENOTTY,
                errno::EPIPE,
                errno::ENOSYS,
                errno::ELOOP,
                errno::ENOTSOCK,
                errno::EPROTONOSUPPORT,
                errno::EOPNOTSUPP,
                errno::EAFNOSUPPORT,
                errno::EADDRINUSE,
                errno::EADDRNOTAVAIL,
                errno::ENETUNREACH,
                errno::ECONNABORTED,
                errno::ECONNRESET,
                errno::ENOBUFS,
                errno::EISCONN,
                errno::ENOTCONN,
                errno::ETIMEDOUT,
                errno::ECONNREFUSED,
                errno::EHOSTUNREACH,
                errno::EINPROGRESS,
                errno::ENOTEMPTY,
                errno::ENOTSUP,
                errno::EWOULDBLOCK,
                errno::EDESTADDRREQ,
                errno::EALREADY,
            ];
            let signals = [
                errno::SIGHUP,
                errno::SIGINT,
                errno::SIGQUIT,
                errno::SIGABRT,
                errno::SIGKILL,
                errno::SIGUSR1,
                errno::SIGSEGV,
                errno::SIGUSR2,
                errno::SIGPIPE,
                errno::SIGALRM,
                errno::SIGTERM,
                errno::SIGCHLD,
                errno::SIGCONT,
                errno::SIGSTOP,
            ];
            let mut out: Vec<String> = all.iter().map(|e| e.0.to_string()).collect();
            out.extend(signals.iter().map(|s| s.0.to_string()));
            out.join(" ")
        }
        "errno_class" => {
            let n: i32 = f[1].parse().unwrap();
            let e = Errno(n);
            format!(
                "errno_class {} timeout={} temporary={} perm={} exist={} notexist={} unsupported={}",
                n,
                e.timeout(),
                e.temporary(),
                e.is("permission"),
                e.is("exist"),
                e.is("not-exist"),
                e.is("unsupported")
            )
        }
        "chtimes" => {
            let r = os::chtimes(f[1], time_or_none(f[2], f[3]), time_or_none(f[4], f[5]));
            format!("{} {}", err_text(r), stat(f[1]))
        }
        "link" => {
            let r = os::link(f[1], f[2]);
            let links = std::fs::metadata(f[2])
                .map(|m| m.nlink().to_string())
                .unwrap_or_default();
            format!("{} nlink={links}", err_text(r))
        }
        "kill" => {
            let pid: i64 = match f[1] {
                "self" => std::process::id() as i64,
                "ppid" => os::getppid(),
                n => n.parse().unwrap(),
            };
            err_text(os::Process::find(pid).signal(Signal(f[2].parse().unwrap())))
        }
        "child" => {
            let mut child = std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .unwrap();
            let p = os::Process::find(child.id() as i64);
            let mut out = vec![format!("zero:{}", err_text(p.signal(Signal(0))))];
            out.push(format!(
                "sig:{}",
                err_text(p.signal(Signal(f[1].parse().unwrap())))
            ));
            use std::os::unix::process::ExitStatusExt;
            let sig: i32 = f[1].parse().unwrap();
            if sig != 15 && sig != 9 && sig != 2 {
                let _ = child.kill();
            }
            let status = child.wait().unwrap();
            out.push(format!(
                "signaled={} signal={}",
                status.signal().is_some(),
                status.signal().unwrap_or(-1)
            ));
            out.push(format!("after:{}", err_text(p.signal(Signal(0)))));
            out.push(format!("kill:{}", err_text(p.kill())));
            out.join(" ")
        }
        _ => file_scenarios::run(f),
    }
}

fn main() {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        writeln!(out, "{}", run(&fields)).unwrap();
    }
}
}
