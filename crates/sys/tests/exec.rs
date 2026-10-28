//! `os.StartProcess`, `Process.WithHandle` and `os/exec` over fork/execve
//! (rust_stdlib_sys::os): descriptors at arbitrary numbers, Go's "exec format
//! error", process handles and `WaitDelay` interrupting copiers. The Go
//! comparison is tools/exec_check.py.
#![cfg(all(
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64"
))]

use rust_stdlib_sys::errno;
use rust_stdlib_sys::os::exec::{self, CmdError, Input, Output};
use rust_stdlib_sys::os::{self, ProcAttr, ProcessError, SignalError};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sysexec-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn capture() -> (Arc<Mutex<Vec<u8>>>, Output) {
    let b = Arc::new(Mutex::new(Vec::new()));
    (b.clone(), Output::writer(b))
}

fn text(b: &Arc<Mutex<Vec<u8>>>) -> String {
    String::from_utf8_lossy(&b.lock().unwrap()).into_owned()
}

#[test]
fn extra_files_land_at_descriptors_3_and_up() {
    let dir = scratch("extra");
    std::fs::write(dir.join("a"), "alpha\n").unwrap();
    std::fs::write(dir.join("b"), "beta\n").unwrap();
    let mut cmd = exec::command("/bin/sh", &["-c", "cat <&3; cat <&4; cat <&5"]);
    cmd.extra_files = vec![
        std::fs::File::open(dir.join("a")).unwrap(),
        std::fs::File::open(dir.join("b")).unwrap(),
        std::fs::File::open(dir.join("a")).unwrap(),
    ];
    let (out, o) = capture();
    cmd.stdout = Some(o);
    cmd.run().unwrap();
    assert_eq!(text(&out), "alpha\nbeta\nalpha\n");
}

#[test]
fn extra_files_do_not_leak_beyond_their_numbers() {
    let dir = scratch("noleak");
    std::fs::write(dir.join("a"), "alpha\n").unwrap();
    // Probe descriptors 3 to 39. The test runner may itself have inherited
    // some, so compare with a run that is given no extra files.
    let script = "for n in $(seq 3 39); do ( : <&$n ) 2>/dev/null && echo $n; done; exit 0";
    let open_in_child = |extra: Vec<std::fs::File>| -> Vec<u32> {
        let mut cmd = exec::command("/bin/sh", &["-c", script]);
        cmd.extra_files = extra;
        let (out, o) = capture();
        cmd.stdout = Some(o);
        cmd.run().unwrap();
        text(&out).lines().map(|l| l.parse().unwrap()).collect()
    };
    let mut want = open_in_child(Vec::new());
    assert!(
        !want.contains(&3),
        "descriptor 3 is open before the test: {want:?}"
    );
    want.push(3);
    want.sort_unstable();
    assert_eq!(
        open_in_child(vec![std::fs::File::open(dir.join("a")).unwrap()]),
        want
    );

    // The same through StartProcess, with a pipe on standard output.
    let run_attr = |files: Vec<Option<std::os::fd::RawFd>>, r: os::File, w: os::File| -> Vec<u32> {
        let attr = ProcAttr {
            dir: String::new(),
            env: Some(vec!["PATH=/usr/bin:/bin".into()]),
            files,
        };
        let argv: Vec<String> = ["sh", "-c", script].iter().map(|s| s.to_string()).collect();
        let p = os::start_process("/bin/sh", &argv, &attr).unwrap();
        w.close().unwrap();
        let mut data = Vec::new();
        let mut buf = [0u8; 64];
        while let Ok(n) = r.read(&mut buf) {
            if n == 0 {
                break;
            }
            data.extend_from_slice(&buf[..n]);
        }
        p.wait().unwrap();
        String::from_utf8(data)
            .unwrap()
            .lines()
            .map(|l| l.parse().unwrap())
            .collect()
    };
    let null = std::fs::File::open("/dev/null").unwrap();
    let (r, w) = os::pipe().unwrap();
    let base = run_attr(
        vec![
            Some(null.as_raw_fd()),
            Some(w.as_raw_fd()),
            Some(null.as_raw_fd()),
        ],
        r,
        w,
    );
    assert!(base.iter().all(|&n| n != 3), "{base:?}");
}

#[test]
fn file_without_shebang_is_an_exec_format_error() {
    let dir = scratch("format");
    let bad = dir.join("bad");
    std::fs::write(&bad, "echo no shebang\n").unwrap();
    std::fs::set_permissions(&bad, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let path = bad.to_str().unwrap();
    let e = exec::command(path, &[]).start().unwrap_err();
    assert_eq!(
        e.to_string(),
        format!("fork/exec {path}: exec format error")
    );
    let e = os::start_process(path, &[path.to_string()], &ProcAttr::default()).unwrap_err();
    assert_eq!(
        e.to_string(),
        format!("fork/exec {path}: exec format error")
    );
}

#[test]
fn start_errors_use_go_text() {
    let e =
        os::start_process("/nonexistent/prog", &["x".into()], &ProcAttr::default()).unwrap_err();
    assert_eq!(
        e.to_string(),
        "fork/exec /nonexistent/prog: no such file or directory"
    );
    let attr = ProcAttr {
        dir: "/nonexistent-dir".into(),
        ..ProcAttr::default()
    };
    let e = os::start_process("/bin/sh", &["sh".into()], &attr).unwrap_err();
    assert_eq!(
        e.to_string(),
        "chdir /nonexistent-dir: no such file or directory"
    );
    let e = exec::command("nosuchcmd-xyz", &[]).start().unwrap_err();
    assert!(e.is_not_found());
    assert_eq!(
        e.to_string(),
        "exec: \"nosuchcmd-xyz\": executable file not found in $PATH"
    );
}

#[test]
fn proc_attr_files_cover_any_descriptor_and_nil_closes() {
    let (r, w) = os::pipe().unwrap();
    let dir = scratch("attr");
    std::fs::write(dir.join("a"), "alpha\n").unwrap();
    let a = std::fs::File::open(dir.join("a")).unwrap();
    let null = std::fs::File::open("/dev/null").unwrap();
    let attr = ProcAttr {
        dir: String::new(),
        env: Some(vec!["PATH=/usr/bin:/bin".into()]),
        // 0 null, 1 and 2 the pipe, 3 closed, 4 the file, 5 the file again.
        files: vec![
            Some(null.as_raw_fd()),
            Some(w.as_raw_fd()),
            Some(w.as_raw_fd()),
            None,
            Some(a.as_raw_fd()),
            Some(a.as_raw_fd()),
        ],
    };
    let argv: Vec<String> = [
        "sh",
        "-c",
        "cat <&4; { cat <&3; } 2>/dev/null || echo closed3",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let p = os::start_process("/bin/sh", &argv, &attr).unwrap();
    w.close().unwrap();
    let mut data = Vec::new();
    let mut buf = [0u8; 256];
    while let Ok(n) = r.read(&mut buf) {
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
    }
    let st = p.wait().unwrap();
    assert!(st.success());
    assert_eq!(String::from_utf8(data).unwrap(), "alpha\nclosed3\n");
    assert!(p.wait().unwrap_err().to_string().starts_with("wait:"));
}

#[test]
fn process_state_text() {
    let attr = ProcAttr {
        files: vec![None, None, None],
        ..ProcAttr::default()
    };
    let p = os::start_process(
        "/bin/sh",
        &["sh".into(), "-c".into(), "exit 3".into()],
        &attr,
    )
    .unwrap();
    let st = p.wait().unwrap();
    assert_eq!(
        (st.to_string().as_str(), st.exit_code(), st.success()),
        ("exit status 3", 3, false)
    );
    let p = os::start_process(
        "/bin/sh",
        &["sh".into(), "-c".into(), "kill -9 $$".into()],
        &attr,
    )
    .unwrap();
    let st = p.wait().unwrap();
    assert_eq!(
        (st.to_string().as_str(), st.exit_code(), st.exited()),
        ("signal: killed", -1, false)
    );
}

#[test]
fn with_handle_follows_go() {
    let attr = ProcAttr {
        files: vec![None, None, None],
        ..ProcAttr::default()
    };
    let p = os::start_process(
        "/bin/sh",
        &["sh".into(), "-c".into(), "sleep 0.2".into()],
        &attr,
    )
    .unwrap();
    let mut seen = None;
    let r = p.with_handle(|h| seen = Some(h));
    if cfg!(target_os = "linux") {
        // pidfd_open needs Linux 5.3; older kernels have no handle.
        match &r {
            Ok(()) => assert!(seen.unwrap() >= 0),
            Err(e) => assert_eq!(*e, ProcessError::NoHandle),
        }
    } else {
        assert_eq!(r, Err(ProcessError::NoHandle));
        assert!(seen.is_none());
    }
    assert_eq!(
        ProcessError::NoHandle.to_string(),
        "os: process handle unavailable"
    );
    // Go decides ErrNoHandle at creation: a process that had a handle reports
    // ErrProcessDone after Wait and "already released" after Release, and one
    // that never had a handle stays ErrNoHandle.
    let (after_wait, after_release) = if r.is_ok() {
        (ProcessError::ProcessDone, ProcessError::Released)
    } else {
        (ProcessError::NoHandle, ProcessError::NoHandle)
    };
    p.wait().unwrap();
    assert_eq!(p.with_handle(|_| {}), Err(after_wait));
    let mut q = os::start_process(
        "/bin/sh",
        &["sh".into(), "-c".into(), "exit 0".into()],
        &attr,
    )
    .unwrap();
    q.release();
    assert_eq!(q.with_handle(|_| {}), Err(after_release));
}

#[test]
fn wait_and_signal_after_release_follow_go() {
    let attr = ProcAttr {
        files: vec![None, None, None],
        ..ProcAttr::default()
    };
    let start = || {
        os::start_process(
            "/bin/sh",
            &["sh".into(), "-c".into(), "exit 0".into()],
            &attr,
        )
        .unwrap()
    };
    // Release before Wait. Go's Wait returns the bare syscall.EINVAL, which
    // is not ErrProcessDone, and Signal and Kill report "already released".
    let mut p = start();
    let had_handle = p.with_handle(|_| {}).is_ok();
    p.release();
    let err = p.wait().unwrap_err();
    assert_eq!(
        (err.to_string().as_str(), err.errno()),
        ("invalid argument", Some(errno::EINVAL))
    );
    assert_ne!(err, ProcessError::ProcessDone);
    assert_eq!(p.signal(errno::SIGKILL), Err(SignalError::Released));
    assert_eq!(p.kill(), Err(SignalError::Released));

    // Wait after Wait is the wait syscall's ECHILD.
    let mut p = start();
    p.wait().unwrap();
    let err = p.wait().unwrap_err();
    assert_eq!(
        (err.to_string().as_str(), err.errno()),
        ("wait: no child processes", Some(errno::ECHILD))
    );
    assert_eq!(p.kill(), Err(SignalError::ProcessDone));
    // Release after Wait leaves the status done, so Wait still reports
    // ECHILD. Go's pidfd path checks the status before the pid and its pid
    // path the pid first, so Signal reports ErrProcessDone for a process
    // that had a handle and "already released" for one that had none.
    p.release();
    assert_eq!(p.wait().unwrap_err().errno(), Some(errno::ECHILD));
    let after_both = if had_handle {
        SignalError::ProcessDone
    } else {
        SignalError::Released
    };
    assert_eq!(p.kill(), Err(after_both));
}

#[test]
fn wait_delay_interrupts_a_blocked_stdout_copier() {
    // The background sleep keeps the stdout pipe open after the shell exits.
    let mut cmd = exec::command("/bin/sh", &["-c", "sleep 5 & echo hi"]);
    cmd.wait_delay = Duration::from_millis(200);
    let (out, o) = capture();
    cmd.stdout = Some(o);
    let t = Instant::now();
    let e = cmd.run().unwrap_err();
    assert!(e.is_wait_delay(), "{e}");
    assert_eq!(e.to_string(), "exec: WaitDelay expired before I/O complete");
    assert_eq!(text(&out), "hi\n");
    assert!(
        t.elapsed() < Duration::from_secs(3),
        "took {:?}",
        t.elapsed()
    );
}

#[test]
fn wait_delay_interrupts_a_blocked_stdin_copier() {
    // Nothing reads stdin and a background process holds the pipe open, so
    // the copier is blocked writing a full pipe.
    let mut cmd = exec::command("/bin/sh", &["-c", "exec 3<&0; sleep 5 & exit 0"]);
    cmd.wait_delay = Duration::from_millis(200);
    cmd.stdin = Some(Input::Reader(Box::new(std::io::Cursor::new(vec![
        b'x';
        1 << 20
    ]))));
    let t = Instant::now();
    let e = cmd.run().unwrap_err();
    assert!(e.is_wait_delay(), "{e}");
    assert!(
        t.elapsed() < Duration::from_secs(3),
        "took {:?}",
        t.elapsed()
    );
}

#[test]
fn exit_error_wins_over_wait_delay() {
    let mut cmd = exec::command("/bin/sh", &["-c", "sleep 5 & exit 3"]);
    cmd.wait_delay = Duration::from_millis(100);
    let (_out, o) = capture();
    cmd.stdout = Some(o);
    let e = cmd.run().unwrap_err();
    assert_eq!(e.to_string(), "exit status 3");
    assert!(e.exit_error().is_some());
}

#[test]
fn pipes_and_output_capture() {
    let mut cmd = exec::command("/bin/sh", &["-c", "cat; echo err >&2; exit 2"]);
    cmd.stdin = Some(Input::Reader(Box::new(std::io::Cursor::new(
        b"in".to_vec(),
    ))));
    let (data, r) = cmd.output();
    assert_eq!(data, b"in");
    let e = r.unwrap_err();
    assert_eq!(e.exit_error().unwrap().stderr, b"err\n");

    let mut cmd = exec::command("/bin/sh", &["-c", "cat"]);
    let w = cmd.stdin_pipe().unwrap();
    let rd = cmd.stdout_pipe().unwrap();
    cmd.start().unwrap();
    w.write(b"through a pipe").unwrap();
    w.close().unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 64];
    while let Ok(n) = rd.read(&mut buf) {
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    cmd.wait().unwrap();
    assert_eq!(got, b"through a pipe");
    let _ = std::io::sink().flush();
    assert!(matches!(cmd.wait(), Err(CmdError::Msg(_))));
}

#[test]
fn look_path_follows_go() {
    assert_eq!(exec::look_path("sh").map(|p| p.ends_with("/sh")), Ok(true));
    let e = exec::look_path("").unwrap_err();
    assert_eq!(
        e.to_string(),
        "exec: \"\": executable file not found in $PATH"
    );
    let e = exec::look_path("/nonexistent/x").unwrap_err();
    assert!(e.is_not_exist());
    assert_eq!(
        e.to_string(),
        "exec: \"/nonexistent/x\": stat /nonexistent/x: no such file or directory"
    );
    let e = exec::look_path("/tmp").unwrap_err();
    assert_eq!(e.to_string(), "exec: \"/tmp\": is a directory");
}
