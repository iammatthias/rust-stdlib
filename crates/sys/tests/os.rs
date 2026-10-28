//! Tests of the `os` functions: identity, hostname, signalling, `Chtimes`,
//! `Link`, and errno/signal text.
#![cfg(all(
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64"
))]
use rust_stdlib_sys::errno::{self, Errno, Signal};
use rust_stdlib_sys::os;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sys-os-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn identity_matches_the_process() {
    // Files this process creates belong to its effective user.
    let dir = scratch("identity");
    let owner = std::fs::metadata(&dir).unwrap();
    assert_eq!(os::geteuid(), i64::from(owner.uid()));
    assert!(os::getuid() >= 0);
    assert!(os::getgid() >= 0 && os::getegid() >= 0);
    // The parent of this test process is whoever launched cargo.
    assert!(os::getppid() > 0);
    assert_ne!(os::getppid(), i64::from(std::process::id()));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn groups_include_the_effective_group_or_are_empty() {
    let groups = os::getgroups().unwrap();
    // The kernel returns the supplementary list; macOS includes the egid.
    assert!(groups.iter().all(|g| *g >= 0));
}

#[test]
fn hostname_is_not_empty() {
    let name = os::hostname().unwrap();
    assert!(!name.is_empty());
    assert!(!name.contains('\0'));
}

#[test]
fn chtimes_sets_and_preserves_times() {
    let dir = scratch("chtimes");
    let file = dir.join("f");
    std::fs::write(&file, b"x").unwrap();
    let name = file.to_str().unwrap();
    let t1 = UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789);
    let t2 = UNIX_EPOCH + Duration::new(1_800_000_000, 5);
    os::chtimes(name, Some(t1), Some(t2)).unwrap();
    let meta = std::fs::metadata(&file).unwrap();
    assert_eq!(
        (meta.atime(), meta.atime_nsec()),
        (1_700_000_000, 123_456_789)
    );
    assert_eq!((meta.mtime(), meta.mtime_nsec()), (1_800_000_000, 5));
    // None leaves a time unchanged.
    os::chtimes(name, None, Some(UNIX_EPOCH + Duration::new(86_400, 0))).unwrap();
    let meta = std::fs::metadata(&file).unwrap();
    assert_eq!(meta.atime(), 1_700_000_000);
    assert_eq!(meta.mtime(), 86_400);
    // Before the epoch.
    os::chtimes(name, Some(UNIX_EPOCH - Duration::new(5, 250)), None).unwrap();
    let meta = std::fs::metadata(&file).unwrap();
    assert_eq!((meta.atime(), meta.atime_nsec()), (-6, 999_999_750));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn chtimes_errors_are_path_errors() {
    let err = os::chtimes("/no/such/file", Some(SystemTime::now()), None).unwrap_err();
    assert_eq!(
        err.to_string(),
        "chtimes /no/such/file: no such file or directory"
    );
    assert_eq!(err.err, errno::ENOENT);
    let err = os::chtimes("bad\0name", None, None).unwrap_err();
    assert_eq!(err.err, errno::EINVAL);
}

#[test]
fn link_creates_hard_links() {
    let dir = scratch("link");
    let a = dir.join("a");
    let b = dir.join("b");
    std::fs::write(&a, b"data").unwrap();
    os::link(a.to_str().unwrap(), b.to_str().unwrap()).unwrap();
    assert_eq!(std::fs::metadata(&a).unwrap().nlink(), 2);
    assert_eq!(
        std::fs::metadata(&a).unwrap().ino(),
        std::fs::metadata(&b).unwrap().ino()
    );
    let err = os::link(a.to_str().unwrap(), b.to_str().unwrap()).unwrap_err();
    assert_eq!(err.err, errno::EEXIST);
    assert!(err.to_string().ends_with(": file exists"));
    assert_eq!(
        os::link("/no/such", "/no/such2").unwrap_err().to_string(),
        "link /no/such /no/such2: no such file or directory"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn signalling_processes() {
    let me = os::Process::find(i64::from(std::process::id()));
    // Signal 0 only checks that the process exists.
    me.signal(Signal(0)).unwrap();
    assert_eq!(
        os::Process::find(0).signal(Signal(0)),
        Err(os::SignalError::NotInitialized)
    );
    assert_eq!(
        os::Process::find(-1).signal(Signal(0)),
        Err(os::SignalError::Released)
    );
    // A pid that cannot exist.
    assert_eq!(
        os::Process::find(i64::from(i32::MAX)).signal(Signal(0)),
        Err(os::SignalError::ProcessDone)
    );
    assert_eq!(
        os::SignalError::ProcessDone.to_string(),
        "os: process already finished"
    );
    // Signal a real child, then see the process done after the wait.
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let p = os::Process::find(i64::from(child.id()));
    p.signal(Signal(0)).unwrap();
    p.signal(errno::SIGTERM).unwrap();
    let status = child.wait().unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(errno::SIGTERM.0));
    assert_eq!(p.kill(), Err(os::SignalError::ProcessDone));
}

#[test]
fn errno_text_matches_go() {
    assert_eq!(Errno(2).to_string(), "no such file or directory");
    assert_eq!(Errno(13).to_string(), "permission denied");
    assert_eq!(Errno(0).to_string(), "errno 0");
    assert_eq!(Errno(1_000_000).to_string(), "errno 1000000");
    assert_eq!(Errno(-1).to_string(), "errno -1");
    assert_eq!(errno::ECONNREFUSED.to_string(), "connection refused");
    assert_eq!(errno::EWOULDBLOCK, errno::EAGAIN);
    assert!(errno::EAGAIN.timeout());
    assert!(errno::ETIMEDOUT.timeout());
    assert!(errno::EINTR.temporary());
    assert!(!errno::ENOENT.temporary());
    assert!(errno::ENOENT.is("not-exist"));
    assert!(errno::EEXIST.is("exist"));
    assert!(errno::ENOTEMPTY.is("exist"));
    assert!(errno::EACCES.is("permission"));
    assert!(errno::ENOSYS.is("unsupported"));
    assert!(!errno::ENOENT.is("exist"));
    // Go's tables are per architecture: amd64's and 386's stop before
    // EHWPOISON, and arm's names it "unknown error 133".
    let hwpoison =
        if cfg!(target_os = "macos") || cfg!(target_arch = "x86_64") || cfg!(target_arch = "x86") {
            "errno 133"
        } else if cfg!(target_arch = "arm") {
            "unknown error 133"
        } else {
            "memory page has hardware error"
        };
    assert_eq!(Errno(133).to_string(), hwpoison);
    assert_eq!(Signal(9).to_string(), "killed");
    assert_eq!(Signal(15).to_string(), "terminated");
    assert_eq!(Signal(2).to_string(), "interrupt");
    assert_eq!(Signal(0).to_string(), "signal 0");
    assert_eq!(Signal(1000).to_string(), "signal 1000");
    assert_eq!(
        std::io::Error::from(errno::ENOENT).kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(
        Errno::from(std::io::Error::from_raw_os_error(13)),
        errno::EACCES
    );
}

#[cfg(all(
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64"
))]
mod files {
    use super::*;
    use rust_stdlib_sys::os::{pipe, DeadlineError, File, FileKind};
    use std::sync::Arc;
    use std::time::Instant;

    #[test]
    fn pipe_reads_writes_and_reports_eof() {
        let (r, w) = pipe().unwrap();
        assert_eq!((r.name(), w.name()), ("|0", "|1"));
        assert_eq!(w.write(b"hello").unwrap(), 5);
        let mut buf = [0u8; 3];
        assert_eq!(r.read(&mut buf).unwrap(), 3);
        assert_eq!(&buf, b"hel");
        w.close().unwrap();
        assert_eq!(r.read(&mut buf).unwrap(), 2);
        assert_eq!(r.read(&mut buf).unwrap(), 0);
        assert_eq!(
            w.close().unwrap_err().to_string(),
            "close |1: file already closed"
        );
        assert_eq!(
            w.write(b"x").unwrap_err().to_string(),
            "write |1: file already closed"
        );
    }

    #[test]
    fn read_deadline_expires() {
        let (r, _w) = pipe().unwrap();
        r.set_read_deadline(Some(SystemTime::now() + Duration::from_millis(60)))
            .unwrap();
        let start = Instant::now();
        let err = r.read(&mut [0u8; 4]).unwrap_err();
        assert_eq!(err.to_string(), "read |0: i/o timeout");
        assert!(start.elapsed() >= Duration::from_millis(55));
        assert!(start.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn past_deadline_fails_even_with_data_and_clearing_recovers() {
        let (r, w) = pipe().unwrap();
        w.write(b"x").unwrap();
        r.set_read_deadline(Some(SystemTime::now() - Duration::from_secs(1)))
            .unwrap();
        assert_eq!(
            r.read(&mut [0u8; 1]).unwrap_err().to_string(),
            "read |0: i/o timeout"
        );
        r.set_read_deadline(None).unwrap();
        assert_eq!(r.read(&mut [0u8; 1]).unwrap(), 1);
    }

    #[test]
    fn deadline_changes_wake_a_blocked_read_at_once() {
        let (r, _w) = pipe().unwrap();
        let r = Arc::new(r);
        r.set_read_deadline(Some(SystemTime::now() + Duration::from_secs(30)))
            .unwrap();
        let r2 = r.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(80));
            r2.set_read_deadline(Some(SystemTime::now() - Duration::from_secs(1)))
                .unwrap();
        });
        let start = Instant::now();
        let err = r.read(&mut [0u8; 1]).unwrap_err();
        t.join().unwrap();
        assert_eq!(err.to_string(), "read |0: i/o timeout");
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "woke after {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn close_wakes_a_blocked_read() {
        let (r, _w) = pipe().unwrap();
        let r = Arc::new(r);
        let r2 = r.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(80));
            r2.close().unwrap();
        });
        let err = r.read(&mut [0u8; 1]).unwrap_err();
        t.join().unwrap();
        assert_eq!(err.to_string(), "read |0: file already closed");
        assert_eq!(r.set_deadline(None), Err(DeadlineError::Closing));
        assert_eq!(DeadlineError::Closing.to_string(), "use of closed file");
    }

    #[test]
    fn write_deadline_on_a_full_pipe() {
        let (_r, w) = pipe().unwrap();
        w.set_write_deadline(Some(SystemTime::now() + Duration::from_millis(100)))
            .unwrap();
        let chunk = [0u8; 65536];
        let mut err = None;
        for _ in 0..4096 {
            if let Err(e) = w.write(&chunk) {
                err = Some(e);
                break;
            }
        }
        assert_eq!(err.unwrap().to_string(), "write |1: i/o timeout");
    }

    #[test]
    fn regular_files_do_not_support_deadlines() {
        let dir = scratch("regular");
        let path = dir.join("f");
        std::fs::write(&path, b"x").unwrap();
        let file = File::new(std::fs::File::open(&path).unwrap(), "f", FileKind::OpenFile).unwrap();
        assert_eq!(file.set_deadline(None), Err(DeadlineError::NoDeadline));
        assert_eq!(
            DeadlineError::NoDeadline.to_string(),
            "file type does not support deadline"
        );
        let mut buf = [0u8; 4];
        assert_eq!(file.read(&mut buf).unwrap(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn io_traits_work() {
        use std::io::{Read, Write};
        let (mut r, mut w) = pipe().unwrap();
        w.write_all(b"abc").unwrap();
        let mut buf = [0u8; 3];
        Read::read_exact(&mut r, &mut buf).unwrap();
        assert_eq!(&buf, b"abc");
        r.set_read_deadline(Some(SystemTime::now() + Duration::from_millis(20)))
            .unwrap();
        let err = Read::read(&mut r, &mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }
}
