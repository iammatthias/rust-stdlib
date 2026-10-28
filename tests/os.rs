//! Port of the portable parts of Go's `os` tests (`env_test.go`, `os_test.go`,
//! `path_test.go`, `removeall_test.go`, `root_test.go`) over `rust_stdlib::os`.
#![cfg(unix)]

use rust_stdlib::io::fs::{self, FileMode};
use rust_stdlib::io::{ReadAt, WriteAt};
use rust_stdlib::os;
use rust_stdlib::time;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::Mutex;

/// Tests that change the working directory or the environment take this lock.
static PROCESS_STATE: Mutex<()> = Mutex::new(());

fn lock() -> std::sync::MutexGuard<'static, ()> {
    PROCESS_STATE.lock().unwrap_or_else(|e| e.into_inner())
}

struct Tmp(String);

impl Tmp {
    fn new() -> Tmp {
        Tmp(os::mkdir_temp("", "ostest").expect("mkdir_temp"))
    }
    fn p(&self, name: &str) -> String {
        format!("{}/{}", self.0, name)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = os::remove_all(&self.0);
    }
}

// ---- env_test.go ------------------------------------------------------------

fn test_getenv(s: &str) -> String {
    match s {
        "*" => "all the args",
        "#" => "NARGS",
        "$" => "PID",
        "1" => "ARGUMENT1",
        "HOME" => "/usr/gopher",
        "H" => "(Value of H)",
        "home_1" => "/usr/foo",
        "_" => "underscore",
        _ => "",
    }
    .to_string()
}

#[test]
fn expand() {
    let tests = [
        ("", ""),
        ("$*", "all the args"),
        ("$$", "PID"),
        ("${*}", "all the args"),
        ("$1", "ARGUMENT1"),
        ("${1}", "ARGUMENT1"),
        ("now is the time", "now is the time"),
        ("$HOME", "/usr/gopher"),
        ("$home_1", "/usr/foo"),
        ("${HOME}", "/usr/gopher"),
        ("${H}OME", "(Value of H)OME"),
        (
            "A$$$#$1$H$home_1*B",
            "APIDNARGSARGUMENT1(Value of H)/usr/foo*B",
        ),
        ("start$+middle$^end$", "start$+middle$^end$"),
        ("mixed$|bag$$$", "mixed$|bagPID$"),
        ("$", "$"),
        ("$}", "$}"),
        ("${", ""),
        ("${}", ""),
    ];
    for (input, want) in tests {
        assert_eq!(os::expand(input, test_getenv), want, "Expand({input:?})");
    }
}

#[test]
fn env_functions() {
    let _g = lock();
    assert!(std::env::var_os("OS_TEST_NOPE")
        .map(|v| v.to_string_lossy().into_owned())
        .is_none());
    os::setenv("OS_TEST_A", "alpha").unwrap();
    os::setenv("OS_TEST_EMPTY", "").unwrap();
    assert_eq!(
        std::env::var_os("OS_TEST_A")
            .map(|v| v.to_string_lossy().into_owned())
            .unwrap_or_default(),
        "alpha"
    );
    assert_eq!(
        std::env::var_os("OS_TEST_EMPTY").map(|v| v.to_string_lossy().into_owned()),
        Some(String::new())
    );
    assert_eq!(os::expand_env("x${OS_TEST_A}y$OS_TEST_A."), "xalphayalpha.");
    assert!(std::env::vars().any(|(k, v)| k == "OS_TEST_A" && v == "alpha"));
    os::unsetenv("OS_TEST_A").unwrap();
    assert_eq!(
        std::env::var_os("OS_TEST_A").map(|v| v.to_string_lossy().into_owned()),
        None
    );
    // Invalid names and values are errors, not panics.
    for (k, v) in [("", "v"), ("a=b", "v"), ("k\0", "v"), ("k", "v\0")] {
        let err = os::setenv(k, v).unwrap_err();
        assert_eq!(
            err.to_string(),
            "setenv: invalid argument",
            "Setenv({k:?}, {v:?})"
        );
        assert!(os::syscall_error(&err).is_some());
    }
    assert_eq!(
        std::env::var_os("a=b")
            .map(|v| v.to_string_lossy().into_owned())
            .unwrap_or_default(),
        ""
    );
    assert!(os::unsetenv("a=b").is_ok());
}

// ---- errors -----------------------------------------------------------------

#[test]
fn error_text_and_classes() {
    let t = Tmp::new();
    let err = os::open(&t.p("missing")).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("open {}/missing: no such file or directory", t.0)
    );
    assert!(os::is_not_exist(&err));
    assert!(fs::ERR_NOT_EXIST.is(&err));
    assert!(!os::is_exist(&err) && !os::is_permission(&err) && !os::is_timeout(&err));
    let pe = fs::path_error(&err).expect("PathError");
    assert_eq!(pe.op, "open");
    assert_eq!(os::errno_of(&pe.err), Some(os::Errno(2)));

    os::mkdir(&t.p("d"), FileMode(0o755)).unwrap();
    let err = os::mkdir(&t.p("d"), FileMode(0o755)).unwrap_err();
    assert!(os::is_exist(&err) && fs::ERR_EXIST.is(&err));
    assert!(err.to_string().ends_with(": file exists"), "{err}");

    // ENOTEMPTY counts as "exists", as in Go.
    os::write_file(&t.p("d/f"), b"x", FileMode(0o644)).unwrap();
    let err = os::remove(&t.p("d")).unwrap_err();
    assert!(os::is_exist(&err), "{err}");
    assert!(fs::ERR_EXIST.is(&err));
    assert!(err.to_string().ends_with(": directory not empty"), "{err}");

    // EINVAL is not ErrInvalid.
    let err = os::readlink(&t.p("d")).unwrap_err();
    assert!(err.to_string().ends_with(": invalid argument"), "{err}");
    assert!(!fs::ERR_INVALID.is(&err));

    let err: io::Error = os::SyscallError::new("setenv", io::Error::from(os::Errno(22))).into();
    assert_eq!(err.to_string(), "setenv: invalid argument");
    assert_eq!(os::Error::DeadlineExceeded.to_string(), "i/o timeout");
    assert!(os::is_timeout(&io::Error::from(
        os::Error::DeadlineExceeded
    )));
    assert_eq!(
        os::Error::NoDeadline.to_string(),
        "file type does not support deadline"
    );
    assert_eq!(
        os::Error::ProcessDone.to_string(),
        "os: process already finished"
    );
    assert_eq!(
        os::Error::NoHandle.to_string(),
        "os: process handle not available"
    );
    assert_eq!(fs::ERR_CLOSED.to_string(), "file already closed");
    let le = os::link(&t.p("nosuch"), &t.p("x")).unwrap_err();
    let l = os::link_error(&le).expect("LinkError");
    assert_eq!(l.op, "link");
    assert_eq!(
        le.to_string(),
        format!(
            "link {} {}: no such file or directory",
            t.p("nosuch"),
            t.p("x")
        )
    );
}

// ---- files ------------------------------------------------------------------

#[test]
fn file_read_write_seek() {
    let t = Tmp::new();
    let name = t.p("f");
    let mut f = os::create(&name).unwrap();
    assert_eq!(f.name(), name);
    f.write_all(b"hello, world").unwrap();
    assert_eq!(f.seek(SeekFrom::Start(0)).unwrap(), 0);
    let mut buf = [0u8; 5];
    f.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"hello");
    assert_eq!(f.seek(SeekFrom::Current(2)).unwrap(), 7);
    assert_eq!(f.seek(SeekFrom::End(-5)).unwrap(), 7);
    let mut rest = String::new();
    f.read_to_string(&mut rest).unwrap();
    assert_eq!(rest, "world");
    let fi = f.stat().unwrap();
    assert_eq!(
        (fi.name(), fi.size(), fi.mode().is_regular()),
        ("f", 12, true)
    );
    f.truncate(5).unwrap();
    assert_eq!(f.stat().unwrap().size(), 5);
    f.sync().unwrap();
    assert!(f.fd() < 1 << 20);
    f.close().unwrap();
    assert_eq!(f.fd(), usize::MAX);
    assert_eq!(os::read_file(&name).unwrap(), b"hello");
}

#[test]
fn file_closed_errors() {
    let t = Tmp::new();
    let f = os::create(&t.p("f")).unwrap();
    f.close().unwrap();
    let err = f.close().unwrap_err();
    assert!(fs::ERR_CLOSED.is(&err), "{err}");
    assert_eq!(
        err.to_string(),
        format!("close {}: file already closed", t.p("f"))
    );
    let err = (&f).write(b"x").unwrap_err();
    assert!(fs::ERR_CLOSED.is(&err));
    assert_eq!(
        err.to_string(),
        format!("write {}: file already closed", t.p("f"))
    );
    let mut b = [0u8; 1];
    let err = (&f).read(&mut b).unwrap_err();
    assert!(fs::ERR_CLOSED.is(&err));
    assert!(f.stat().is_err() && f.sync().is_err() && f.chmod(FileMode(0o600)).is_err());
}

#[test]
fn file_read_at_write_at() {
    let t = Tmp::new();
    let mut f = os::open_file(&t.p("f"), os::O_RDWR | os::O_CREATE, FileMode(0o644)).unwrap();
    f.write_all(b"0123456789").unwrap();
    let mut b = [0u8; 4];
    assert_eq!(f.read_at(&mut b, 3).unwrap(), 4);
    assert_eq!(&b, b"3456");
    let err = f.read_at(&mut b, 8).unwrap_err();
    assert_eq!(err.read(), 2);
    assert!(rust_stdlib::io::is_eof(&err.into_source()));
    let err = f.read_at(&mut b, 100).unwrap_err();
    assert_eq!(err.read(), 0);
    assert!(rust_stdlib::io::is_eof(&err.into_source()));
    // Offsets above i64::MAX are Go's negative offsets.
    let err = f.read_at(&mut b, -1i64 as u64).unwrap_err();
    assert!(err.to_string().ends_with("negative offset"));
    f.write_at(b"XY", 4).unwrap();
    f.write_at(b"Z", 12).unwrap();
    f.close().unwrap();
    assert_eq!(os::read_file(&t.p("f")).unwrap(), b"0123XY6789\0\0Z");
    // WriteAt is not allowed with O_APPEND.
    let mut f = os::open_file(&t.p("f"), os::O_WRONLY | os::O_APPEND, FileMode(0)).unwrap();
    let err = f.write_at(b"x", 0).unwrap_err();
    assert_eq!(
        err.to_string(),
        "os: invalid use of WriteAt on file opened with O_APPEND"
    );
    f.write_all(b"!").unwrap();
    f.close().unwrap();
    assert!(os::read_file(&t.p("f")).unwrap().ends_with(b"Z!"));
}

#[test]
fn open_file_flags() {
    let t = Tmp::new();
    let name = t.p("f");
    // O_EXCL fails when the file exists.
    os::open_file(
        &name,
        os::O_CREATE | os::O_EXCL | os::O_WRONLY,
        FileMode(0o600),
    )
    .unwrap();
    let err = os::open_file(
        &name,
        os::O_CREATE | os::O_EXCL | os::O_WRONLY,
        FileMode(0o600),
    )
    .unwrap_err();
    assert!(os::is_exist(&err), "{err}");
    // Permission bits are honored (before umask).
    let old = os::stat(&name).unwrap();
    assert_eq!(old.mode().perm(), FileMode(0o600));
    os::write_file(&name, b"abcdef", FileMode(0o644)).unwrap();
    // O_TRUNC truncates, O_APPEND appends.
    let f = os::open_file(&name, os::O_WRONLY | os::O_APPEND, FileMode(0)).unwrap();
    (&f).write_all(b"gh").unwrap();
    f.close().unwrap();
    assert_eq!(os::read_file(&name).unwrap(), b"abcdefgh");
    let f = os::open_file(&name, os::O_WRONLY | os::O_TRUNC, FileMode(0)).unwrap();
    f.close().unwrap();
    assert_eq!(os::read_file(&name).unwrap(), b"");
    // A read-only file cannot be written.
    let f = os::open(&name).unwrap();
    assert!(!(&f).write(b"x").unwrap_err().to_string().is_empty());
    // O_RDONLY | O_CREATE creates the file.
    let n2 = t.p("g");
    os::open_file(&n2, os::O_RDONLY | os::O_CREATE, FileMode(0o644)).unwrap();
    assert!(os::stat(&n2).is_ok());
    // O_SYNC is accepted.
    os::open_file(&n2, os::O_WRONLY | os::O_SYNC, FileMode(0)).unwrap();
    assert_eq!((os::O_RDONLY, os::O_WRONLY, os::O_RDWR), (0, 1, 2));
}

#[test]
fn deadlines_unsupported_for_regular_files() {
    let t = Tmp::new();
    let f = os::create(&t.p("f")).unwrap();
    for r in [
        f.set_deadline(time::now()),
        f.set_read_deadline(time::now()),
        f.set_write_deadline(time::now()),
    ] {
        assert!(os::Error::NoDeadline.is(&r.unwrap_err()));
    }
    f.close().unwrap();
    let err = f.set_deadline(time::now()).unwrap_err();
    assert!(fs::ERR_CLOSED.is(&err));
}

#[test]
fn file_chmod_chown_chdir() {
    let _g = lock();
    let t = Tmp::new();
    let f = os::create(&t.p("f")).unwrap();
    f.chmod(FileMode(0o640)).unwrap();
    assert_eq!(f.stat().unwrap().mode().perm(), FileMode(0o640));
    f.chown(-1, -1).unwrap();
    assert!(f.chdir().is_err(), "chdir to a file fails");
    let d = os::open(&t.0).unwrap();
    let old = os::getwd().unwrap();
    d.chdir().unwrap();
    assert!(os::same_file(
        os::stat(".").unwrap().as_ref(),
        os::stat(&t.0).unwrap().as_ref()
    ));
    os::chdir(&old).unwrap();
    os::chmod(&t.p("f"), FileMode(0o755 | fs::MODE_SETUID.0)).unwrap();
    let m = os::stat(&t.p("f")).unwrap().mode();
    assert!(m.0 & fs::MODE_SETUID.0 != 0, "{m}");
    assert_eq!(m.to_string(), "urwxr-xr-x");
}

#[test]
fn read_dir_and_friends() {
    let t = Tmp::new();
    for n in ["c", "a", "b"] {
        os::write_file(&t.p(n), n.as_bytes(), FileMode(0o644)).unwrap();
    }
    os::mkdir(&t.p("sub"), FileMode(0o755)).unwrap();
    os::symlink("a", &t.p("ln")).unwrap();
    let es = os::read_dir(&t.0).unwrap();
    let names: Vec<_> = es.iter().map(|e| e.name().to_string()).collect();
    assert_eq!(names, ["a", "b", "c", "ln", "sub"]);
    let infos = os::read_dir_info(&t.0).unwrap();
    let names: Vec<_> = infos.iter().map(|i| i.name().to_string()).collect();
    assert_eq!(names, ["a", "b", "c", "ln", "sub"]);
    assert!(infos[3].mode().to_string().starts_with('L'));
    let kinds: Vec<_> = es.iter().map(|e| e.file_type().to_string()).collect();
    assert_eq!(
        kinds,
        [
            "----------",
            "----------",
            "----------",
            "L---------",
            "d---------"
        ]
    );
    assert!(es[4].is_dir() && !es[0].is_dir());
    assert_eq!(es[0].info().unwrap().size(), 1);

    // File.ReadDir / Readdirnames / Readdir with counts.
    let d = os::open(&t.0).unwrap();
    let first = d.readdirnames(2).unwrap();
    assert_eq!(first.len(), 2);
    let rest = d.readdirnames(10).unwrap();
    assert_eq!(rest.len(), 3);
    let err = d.readdirnames(1).unwrap_err();
    assert!(rust_stdlib::io::is_eof(&err));
    assert_eq!(
        d.readdirnames(-1).unwrap().len(),
        0,
        "n <= 0 at the end is not an error"
    );
    d.close().unwrap();
    let d = os::open(&t.0).unwrap();
    let infos = d.readdir(-1).unwrap();
    assert_eq!(infos.len(), 5);
    assert!(infos.iter().any(|i| i.mode().0 & fs::MODE_SYMLINK.0 != 0));
    d.close().unwrap();
    // Errors.
    let f = os::open(&t.p("a")).unwrap();
    assert!(f.readdirnames(-1).is_err());
    assert!(os::read_dir(&t.p("a")).is_err());
    assert!(os::is_not_exist(&os::read_dir(&t.p("nope")).unwrap_err()));
}

#[test]
fn remove_and_remove_all() {
    let t = Tmp::new();
    os::mkdir_all(&t.p("a/b/c"), FileMode(0o755)).unwrap();
    os::write_file(&t.p("a/b/c/f"), b"x", FileMode(0o644)).unwrap();
    os::write_file(&t.p("a/g"), b"x", FileMode(0o644)).unwrap();
    os::symlink("b", &t.p("a/l")).unwrap();
    assert!(os::remove(&t.p("a")).is_err());
    os::remove(&t.p("a/g")).unwrap();
    assert!(os::is_not_exist(&os::remove(&t.p("a/g")).unwrap_err()));
    os::remove_all(&t.p("a")).unwrap();
    assert!(os::stat(&t.p("a")).is_err());
    // RemoveAll on a missing path, on a file, on "" and invalid names.
    os::remove_all(&t.p("nothing")).unwrap();
    os::write_file(&t.p("file"), b"", FileMode(0o644)).unwrap();
    os::remove_all(&t.p("file")).unwrap();
    os::remove_all(&t.p("file/under")).unwrap();
    os::remove_all("").unwrap();
    for bad in [".", "x/.", &t.p(".")] {
        let err = os::remove_all(bad).unwrap_err();
        assert!(err.to_string().starts_with("RemoveAll "), "{err}");
        assert!(err.to_string().ends_with(": invalid argument"), "{err}");
    }
    // A directory without permission is not an obstacle for its parent.
    os::mkdir_all(&t.p("p/q"), FileMode(0o755)).unwrap();
    os::write_file(&t.p("p/q/f"), b"", FileMode(0o644)).unwrap();
    os::remove_all(&format!("{}/", t.p("p"))).unwrap();
    assert!(os::stat(&t.p("p")).is_err());
}

#[test]
fn mkdir_all_cases() {
    let t = Tmp::new();
    os::mkdir_all(&t.p("a/b/c"), FileMode(0o755)).unwrap();
    os::mkdir_all(&t.p("a/b/c"), FileMode(0o755)).unwrap();
    os::mkdir_all(&format!("{}/", t.p("a/b/d")), FileMode(0o700)).unwrap();
    assert_eq!(
        os::stat(&t.p("a/b/d")).unwrap().mode().perm(),
        FileMode(0o700)
    );
    os::write_file(&t.p("f"), b"", FileMode(0o644)).unwrap();
    let err = os::mkdir_all(&t.p("f"), FileMode(0o755)).unwrap_err();
    assert!(err.to_string().ends_with(": not a directory"), "{err}");
    assert_eq!(fs::path_error(&err).unwrap().op, "mkdir");
    let err = os::mkdir_all(&t.p("f/x/y"), FileMode(0o755)).unwrap_err();
    assert!(err.to_string().ends_with(": not a directory"), "{err}");
    // A symlink to a directory is fine.
    os::symlink("a", &t.p("link")).unwrap();
    os::mkdir_all(&t.p("link"), FileMode(0o755)).unwrap();
}

#[test]
fn rename_link_symlink_readlink() {
    let t = Tmp::new();
    os::write_file(&t.p("a"), b"data", FileMode(0o644)).unwrap();
    os::rename(&t.p("a"), &t.p("b")).unwrap();
    assert!(os::is_not_exist(&os::stat(&t.p("a")).unwrap_err()));
    os::link(&t.p("b"), &t.p("hard")).unwrap();
    assert!(os::same_file(
        os::stat(&t.p("b")).unwrap().as_ref(),
        os::stat(&t.p("hard")).unwrap().as_ref()
    ));
    os::symlink("b", &t.p("soft")).unwrap();
    assert_eq!(os::readlink(&t.p("soft")).unwrap(), "b");
    assert!(os::same_file(
        os::stat(&t.p("soft")).unwrap().as_ref(),
        os::stat(&t.p("b")).unwrap().as_ref()
    ));
    assert!(!os::same_file(
        os::lstat(&t.p("soft")).unwrap().as_ref(),
        os::stat(&t.p("b")).unwrap().as_ref()
    ));
    assert!(os::lstat(&t.p("soft")).unwrap().mode().0 & fs::MODE_SYMLINK.0 != 0);
    // Renaming over a directory is reported as a LinkError with Go's errors.
    os::mkdir(&t.p("dir"), FileMode(0o755)).unwrap();
    let err = os::rename(&t.p("b"), &t.p("dir")).unwrap_err();
    let le = os::link_error(&err).expect("LinkError");
    assert_eq!(le.op, "rename");
    assert!(os::is_exist(&err), "{err}");
    let err = os::rename(&t.p("missing"), &t.p("dir")).unwrap_err();
    assert!(os::is_not_exist(&err), "{err}");
    assert!(os::symlink("x", &t.p("soft")).is_err_and(|e| os::is_exist(&e)));
    assert_eq!(
        os::symlink("x", &t.p("soft")).unwrap_err().to_string(),
        format!("symlink x {}: file exists", t.p("soft"))
    );
}

#[test]
fn stat_info_and_chtimes_truncate() {
    let t = Tmp::new();
    os::write_file(&t.p("f"), b"0123456789", FileMode(0o640)).unwrap();
    let fi = os::stat(format!("{}/", t.p("f")).trim_end_matches('/')).unwrap();
    assert_eq!(fi.name(), "f");
    assert_eq!(fi.size(), 10);
    assert_eq!(fi.mode().to_string(), "-rw-r-----");
    assert!(!fi.is_dir());
    assert_eq!(os::stat(&t.0).unwrap().mode().to_string(), "drwx------");
    assert_eq!(os::stat("/").unwrap().name(), "/");
    assert_eq!(os::stat("/usr/").unwrap().name(), "usr");
    os::chtimes(
        &t.p("f"),
        time::unix(1_000_000_000, 0),
        time::unix(1_200_000_000, 0),
    )
    .unwrap();
    assert_eq!(
        os::stat(&t.p("f")).unwrap().mod_time().unix(),
        1_200_000_000
    );
    // A zero time leaves the corresponding time alone.
    os::chtimes(
        &t.p("f"),
        time::Time::default(),
        time::unix(1_300_000_000, 0),
    )
    .unwrap();
    assert_eq!(
        os::stat(&t.p("f")).unwrap().mod_time().unix(),
        1_300_000_000
    );
    os::truncate(&t.p("f"), 4).unwrap();
    assert_eq!(os::read_file(&t.p("f")).unwrap(), b"0123");
    os::truncate(&t.p("f"), 6).unwrap();
    assert_eq!(os::read_file(&t.p("f")).unwrap(), b"0123\0\0");
    let err = os::truncate(&t.p("f"), -1).unwrap_err();
    assert!(err.to_string().ends_with(": invalid argument"), "{err}");
    assert!(os::truncate(&t.p("nope"), 1).is_err());
}

#[test]
fn temp_files_and_dirs() {
    let t = Tmp::new();
    let f = os::create_temp(&t.0, "pre*suf").unwrap();
    let base = f.name().rsplit('/').next().unwrap().to_string();
    assert!(
        base.starts_with("pre") && base.ends_with("suf") && base.len() > 6,
        "{base}"
    );
    assert_eq!(os::stat(f.name()).unwrap().mode().perm(), FileMode(0o600));
    let g = os::create_temp(&format!("{}/", t.0), "plain").unwrap();
    assert!(g.name().starts_with(&t.p("plain")));
    let d = os::mkdir_temp(&t.0, "d*x").unwrap();
    assert!(os::stat(&d).unwrap().is_dir());
    assert_eq!(os::stat(&d).unwrap().mode().perm(), FileMode(0o700));
    let err = os::create_temp(&t.0, "a/b").unwrap_err();
    assert_eq!(
        err.to_string(),
        "createtemp a/b: pattern contains path separator"
    );
    let err = os::mkdir_temp(&t.0, "a/b").unwrap_err();
    assert_eq!(
        err.to_string(),
        "mkdirtemp a/b: pattern contains path separator"
    );
    let err = os::mkdir_temp(&t.p("missing"), "x").unwrap_err();
    assert!(os::is_not_exist(&err));
    assert!(os::create_temp(&t.p("missing"), "x").is_err());
}

#[test]
fn read_file_write_file() {
    let t = Tmp::new();
    os::write_file(&t.p("f"), b"hello", FileMode(0o600)).unwrap();
    assert_eq!(os::read_file(&t.p("f")).unwrap(), b"hello");
    os::write_file(&t.p("f"), b"x", FileMode(0o600)).unwrap();
    assert_eq!(os::read_file(&t.p("f")).unwrap(), b"x");
    let err = os::read_file(&t.0).unwrap_err();
    assert!(err.to_string().ends_with(": is a directory"), "{err}");
    assert!(os::write_file(&t.p("no/such/dir/f"), b"", FileMode(0o600)).is_err());
}

#[test]
fn dir_fs_and_copy_fs() {
    let t = Tmp::new();
    os::mkdir_all(&t.p("src/d"), FileMode(0o755)).unwrap();
    os::write_file(&t.p("src/a"), b"A", FileMode(0o644)).unwrap();
    os::write_file(&t.p("src/d/b"), b"B", FileMode(0o755)).unwrap();
    os::symlink("a", &t.p("src/ln")).unwrap();
    let fsys = os::dir_fs(&t.p("src"));
    assert_eq!(fs::read_file(&fsys, "d/b").unwrap(), b"B");
    let err = fs::read_file(&fsys, "../x").unwrap_err();
    assert_eq!(err.to_string(), "readfile ../x: invalid argument");
    let err = fs::read_file(&fsys, "missing").unwrap_err();
    assert_eq!(
        err.to_string(),
        "open missing: no such file or directory".to_string()
    );
    assert!(fs::ERR_NOT_EXIST.is(&err));
    os::copy_fs(&t.p("dst"), &fsys).unwrap();
    assert_eq!(os::read_file(&t.p("dst/d/b")).unwrap(), b"B");
    assert_eq!(os::readlink(&t.p("dst/ln")).unwrap(), "a");
    assert_eq!(
        os::stat(&t.p("dst/d/b")).unwrap().mode().perm(),
        FileMode(0o755)
    );
    // Existing files are not overwritten.
    let err = os::copy_fs(&t.p("dst"), &fsys).unwrap_err();
    assert!(os::is_exist(&err), "{err}");
    let err = os::copy_fs("", &os::dir_fs("")).unwrap_err();
    assert!(
        err.to_string().ends_with("os: DirFS with empty root"),
        "{err}"
    );
}

#[test]
fn pipe_round_trip() {
    let (r, w) = os::pipe().unwrap();
    (&w).write_all(b"through the pipe").unwrap();
    w.close().unwrap();
    let mut s = String::new();
    (&r).read_to_string(&mut s).unwrap();
    assert_eq!(s, "through the pipe");
    r.close().unwrap();
}

#[test]
fn file_write_to_read_from() {
    let t = Tmp::new();
    let mut f = os::create(&t.p("f")).unwrap();
    assert_eq!(
        f.read_from(&mut io::Cursor::new(b"abcdef".to_vec()))
            .unwrap(),
        6
    );
    f.seek(SeekFrom::Start(2)).unwrap();
    let mut out = Vec::new();
    assert_eq!(f.write_to(&mut out).unwrap(), 4);
    assert_eq!(out, b"cdef");
    f.write_all(b"gh").unwrap();
}

// ---- processes and system information -----------------------------------------

#[test]
fn process_and_system_info() {
    let _g = lock();
    assert!(os::getppid() > 0);
    assert!(os::getuid() >= 0 && os::geteuid() >= 0 && os::getgid() >= 0 && os::getegid() >= 0);
    assert!(os::getgroups().is_ok());
    let ps = os::getpagesize();
    assert!(ps >= 4096 && (ps & (ps - 1)) == 0, "{ps}");
    assert!(!os::hostname().unwrap().is_empty());
    assert_eq!(os::DEV_NULL, "/dev/null");
    let wd = os::getwd().unwrap();
    assert!(wd.starts_with('/'));
    let home = os::user_home_dir();
    assert_eq!(
        home.is_ok(),
        !std::env::var_os("HOME")
            .map(|v| v.to_string_lossy().into_owned())
            .unwrap_or_default()
            .is_empty()
    );
}

#[test]
fn user_dirs_follow_the_environment() {
    let _g = lock();
    let saved: Vec<_> = ["HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "TMPDIR"]
        .iter()
        .map(|k| {
            (
                *k,
                std::env::var_os(k).map(|v| v.to_string_lossy().into_owned()),
            )
        })
        .collect();
    os::setenv("HOME", "/home/u").unwrap();
    os::unsetenv("XDG_CACHE_HOME").unwrap();
    os::unsetenv("XDG_CONFIG_HOME").unwrap();
    os::unsetenv("TMPDIR").unwrap();
    assert_eq!(os::user_home_dir().unwrap(), "/home/u");
    assert_eq!(os::temp_dir(), "/tmp");
    let (cache, config) = (
        os::user_cache_dir().unwrap(),
        os::user_config_dir().unwrap(),
    );
    if cfg!(target_os = "macos") {
        assert_eq!(cache, "/home/u/Library/Caches");
        assert_eq!(config, "/home/u/Library/Application Support");
    } else {
        assert_eq!(cache, "/home/u/.cache");
        assert_eq!(config, "/home/u/.config");
        os::setenv("XDG_CACHE_HOME", "relative").unwrap();
        assert_eq!(
            os::user_cache_dir().unwrap_err().to_string(),
            "path in $XDG_CACHE_HOME is relative"
        );
    }
    os::unsetenv("HOME").unwrap();
    assert_eq!(
        os::user_home_dir().unwrap_err().to_string(),
        "$HOME is not defined"
    );
    os::setenv("TMPDIR", "/var/tmp").unwrap();
    assert_eq!(os::temp_dir(), "/var/tmp");
    for (k, v) in saved {
        match v {
            Some(v) => os::setenv(k, &v).unwrap(),
            None => os::unsetenv(k).unwrap(),
        }
    }
}

#[test]
fn start_process_wait_and_state() {
    let _g = lock();
    let attr = os::ProcAttr {
        files: vec![None, Some(os::stdout()), Some(os::stderr())],
        ..Default::default()
    };
    let args = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let p = os::start_process("/bin/sh", &args(&["sh", "-c", "exit 3"]), &attr).unwrap();
    let st = p.wait().unwrap();
    assert_eq!(
        (st.exit_code(), st.success(), st.exited()),
        (3, false, true)
    );
    assert_eq!(st.to_string(), "exit status 3");
    assert_eq!(st.pid(), p.pid);
    // Waiting twice, and signalling a finished process.
    assert_eq!(
        p.wait().unwrap_err().to_string(),
        "wait: no child processes"
    );
    assert!(os::Error::ProcessDone.is(&p.kill().unwrap_err()));
    // Release after Wait leaves the status done, so Wait still reports ECHILD.
    let mut p = p;
    p.release().unwrap();
    assert_eq!(
        p.wait().unwrap_err().to_string(),
        "wait: no child processes"
    );
    // A clone shares the release, as Go's *Process does.
    let mut p = os::start_process("/bin/sh", &args(&["sh", "-c", "exit 0"]), &attr).unwrap();
    let clone = p.clone();
    p.release().unwrap();
    assert_eq!(clone.wait().unwrap_err().to_string(), "invalid argument");
    // Release before Wait makes Wait the bare EINVAL, not ErrProcessDone.
    let mut p = os::start_process("/bin/sh", &args(&["sh", "-c", "exit 0"]), &attr).unwrap();
    p.release().unwrap();
    let err = p.wait().unwrap_err();
    assert_eq!(err.to_string(), "invalid argument");
    assert_eq!(os::errno_of(&err), Some(os::Errno(22)));
    assert!(!os::Error::ProcessDone.is(&err));
    assert_eq!(
        p.kill().unwrap_err().to_string(),
        "os: process already released"
    );

    let p = os::start_process("/bin/sh", &args(&["sh", "-c", "kill -9 $$"]), &attr).unwrap();
    let st = p.wait().unwrap();
    assert_eq!(
        (st.exit_code(), st.success(), st.exited()),
        (-1, false, false)
    );
    assert_eq!(st.to_string(), "signal: killed");

    let p = os::start_process("/bin/sleep", &args(&["sleep", "30"]), &attr).unwrap();
    p.kill().unwrap();
    assert_eq!(p.wait().unwrap().to_string(), "signal: killed");

    let err = os::start_process("/nonexistent/prog", &args(&["x"]), &attr).unwrap_err();
    assert_eq!(
        err.to_string(),
        "fork/exec /nonexistent/prog: no such file or directory"
    );
    let attr2 = os::ProcAttr {
        dir: "/nonexistent-dir".into(),
        ..Default::default()
    };
    let err = os::start_process("/bin/true", &args(&["true"]), &attr2).unwrap_err();
    assert_eq!(
        err.to_string(),
        "chdir /nonexistent-dir: no such file or directory"
    );

    // A process we did not start cannot be waited for; signals work.
    let child = std::process::Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let mut other = os::find_process(child.id() as i32).unwrap();
    assert_eq!(
        other.wait().unwrap_err().to_string(),
        "wait: no child processes"
    );
    other.signal(&os::Sig(0)).unwrap();
    other.signal(&os::KILL).unwrap();
    let mut child = child;
    let status = child.wait().unwrap();
    assert!(!status.success());
    other.release().unwrap();
    assert_eq!(other.pid, -1);
    assert_eq!(os::INTERRUPT.to_string(), "interrupt");
    assert_eq!(os::KILL.to_string(), "killed");
    assert_eq!(os::Sig(999).to_string(), "signal 999");
    assert!(other.with_handle(|_| ()).is_err());
}

#[test]
fn file_modes() {
    let m = FileMode(0o755 | fs::MODE_DIR.0);
    assert_eq!(m.to_string(), "drwxr-xr-x");
    assert_eq!(os::MODE_PERM, FileMode(0o777));
    assert_eq!(os::MODE_TYPE.0 & os::MODE_SYMLINK.0, os::MODE_SYMLINK.0);
}

// ---- Root --------------------------------------------------------------------

#[test]
fn root_confines_access() {
    let t = Tmp::new();
    os::mkdir(&t.p("r"), FileMode(0o755)).unwrap();
    os::mkdir(&t.p("r/sub"), FileMode(0o755)).unwrap();
    os::write_file(&t.p("out"), b"outside", FileMode(0o644)).unwrap();
    os::write_file(&t.p("r/f"), b"inside", FileMode(0o644)).unwrap();
    os::write_file(&t.p("r/sub/g"), b"gee", FileMode(0o644)).unwrap();
    os::symlink("f", &t.p("r/link")).unwrap();
    os::symlink("sub", &t.p("r/dirlink")).unwrap();
    os::symlink("../out", &t.p("r/escape")).unwrap();
    os::symlink("/etc/passwd", &t.p("r/abs")).unwrap();
    os::symlink("loop", &t.p("r/loop")).unwrap();
    let root = os::open_root(&t.p("r")).unwrap();
    assert_eq!(root.name(), t.p("r"));

    assert_eq!(root.read_file("f").unwrap(), b"inside");
    assert_eq!(root.read_file("link").unwrap(), b"inside");
    assert_eq!(root.read_file("dirlink/g").unwrap(), b"gee");
    assert_eq!(root.read_file("sub/../f").unwrap(), b"inside");
    assert_eq!(root.read_file("./sub/./g").unwrap(), b"gee");
    for bad in [
        "../out",
        "escape",
        "abs",
        "/etc/passwd",
        "sub/../../out",
        "..",
    ] {
        let err = root.read_file(bad).unwrap_err();
        assert!(
            err.to_string().ends_with("path escapes from parent"),
            "{bad}: {err}"
        );
        assert_eq!(fs::path_error(&err).unwrap().op, "openat");
    }
    assert!(root
        .read_file("loop")
        .unwrap_err()
        .to_string()
        .ends_with("too many levels of symbolic links"));
    assert!(root
        .read_file("")
        .unwrap_err()
        .to_string()
        .ends_with("empty path"));
    assert!(os::is_not_exist(&root.read_file("nope").unwrap_err()));

    // Creation and removal stay inside.
    root.write_file("new", b"n", FileMode(0o644)).unwrap();
    root.mkdir("d", FileMode(0o755)).unwrap();
    root.mkdir_all("x/y/z", FileMode(0o755)).unwrap();
    assert!(os::stat(&t.p("r/x/y/z")).unwrap().is_dir());
    root.symlink("new", "ln2").unwrap();
    assert_eq!(root.readlink("ln2").unwrap(), "new");
    root.rename("new", "d/moved").unwrap();
    assert_eq!(os::read_file(&t.p("r/d/moved")).unwrap(), b"n");
    root.link("d/moved", "hard").unwrap();
    root.chmod("hard", FileMode(0o600)).unwrap();
    assert_eq!(root.stat("hard").unwrap().mode().perm(), FileMode(0o600));
    assert!(root.lstat("link").unwrap().mode().0 & fs::MODE_SYMLINK.0 != 0);
    assert!(root.stat("link").unwrap().mode().is_regular());
    root.remove("hard").unwrap();
    root.remove_all("x").unwrap();
    assert!(os::stat(&t.p("r/x")).is_err());
    assert!(root.rename("f", "../stolen").is_err());
    assert!(os::stat(&t.p("stolen")).is_err());
    assert!(root.remove("../out").is_err());
    assert!(root.mkdir("../evil", FileMode(0o755)).is_err());
    assert!(root.symlink("target", "../evil").is_err());
    assert!(os::stat(&t.p("evil")).is_err());
    assert_eq!(
        root.mkdir("e", FileMode(0o1777 | 0o10000))
            .unwrap_err()
            .to_string(),
        "mkdirat e: unsupported file mode"
    );

    // Sub-roots and the FS view.
    let sub = root.open_root("sub").unwrap();
    assert_eq!(sub.name(), t.p("r/sub"));
    assert_eq!(sub.read_file("g").unwrap(), b"gee");
    assert!(sub.read_file("../f").is_err());
    let fsys = root.fs();
    assert_eq!(fs::read_file(&fsys, "sub/g").unwrap(), b"gee");
    assert_eq!(
        fs::read_file(&fsys, "../out").unwrap_err().to_string(),
        "readfile ../out: invalid argument"
    );
    let names: Vec<_> = fs::read_dir(&fsys, "sub")
        .unwrap()
        .iter()
        .map(|e| e.name().to_string())
        .collect();
    assert_eq!(names, ["g"]);
    assert_eq!(fs::read_link(&fsys, "link").unwrap(), "f");

    // OpenInRoot and a closed root.
    let f = os::open_in_root(&t.p("r"), "sub/g").unwrap();
    assert_eq!(f.name(), t.p("r/sub/g"));
    assert!(os::open_in_root(&t.p("r"), "../out").is_err());
    root.close().unwrap();
    let err = root.read_file("f").unwrap_err();
    assert!(fs::ERR_CLOSED.is(&err), "{err}");
    let err = os::open_root(&t.p("r/f")).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("open {}: not a directory", t.p("r/f"))
    );
}
