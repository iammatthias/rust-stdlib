//! Port of the portable parts of Go's `os/exec` tests (`exec_test.go`,
//! `lp_test.go`, `env_test.go`) over `rust_stdlib::os::exec`.
#![cfg(unix)]

use rust_stdlib::context::Context;
use rust_stdlib::io::fs::{self, FileMode};
use rust_stdlib::os::{self, exec};
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Tests that change the working directory or `PATH` take this lock.
static PROCESS_STATE: Mutex<()> = Mutex::new(());

fn lock() -> std::sync::MutexGuard<'static, ()> {
    PROCESS_STATE.lock().unwrap_or_else(|e| e.into_inner())
}

fn sh(script: &str) -> exec::Cmd {
    exec::command("/bin/sh", &["-c", script])
}

fn buf() -> Arc<Mutex<Vec<u8>>> {
    Arc::new(Mutex::new(Vec::new()))
}

fn text(b: &Arc<Mutex<Vec<u8>>>) -> String {
    String::from_utf8(b.lock().unwrap().clone()).unwrap()
}

#[test]
fn echo() {
    let _g = lock();
    let mut c = exec::command("/bin/echo", &["foo", "bar"]);
    let (out, r) = c.output();
    r.unwrap();
    assert_eq!(out, b"foo bar\n");
    assert_eq!(c.to_string(), "/bin/echo foo bar");
    assert!(c.process_state.unwrap().success());
    assert!(c.process.is_some());
}

#[test]
fn cat_stdin() {
    let _g = lock();
    let mut c = exec::command("/bin/cat", &[]);
    c.stdin = Some(exec::Input::reader(io::Cursor::new(b"abc\ndef\n".to_vec())));
    let (out, r) = c.output();
    r.unwrap();
    assert_eq!(out, b"abc\ndef\n");
}

#[test]
fn combined_output_keeps_order_and_data_on_failure() {
    let _g = lock();
    let mut c = sh("echo out; echo err >&2; exit 4");
    let (out, r) = c.combined_output();
    assert_eq!(String::from_utf8_lossy(&out), "out\nerr\n");
    let err = r.unwrap_err();
    let ee = exec::exit_error(&err).expect("ExitError");
    assert_eq!(ee.process_state.exit_code(), 4);
    assert_eq!(err.to_string(), "exit status 4");
}

#[test]
fn output_captures_stderr_in_exit_error() {
    let _g = lock();
    let mut c = sh("echo out; echo oops >&2; exit 1");
    let (out, r) = c.output();
    assert_eq!(out, b"out\n");
    let err = r.unwrap_err();
    assert_eq!(exec::exit_error(&err).unwrap().stderr, b"oops\n");
    // A large stderr keeps its start and end.
    let mut c = sh("i=0; while [ $i -lt 5000 ]; do echo 0123456789abcdef0123456789abcdef >&2; i=$((i+1)); done; exit 1");
    let err = c.output().1.unwrap_err();
    let s = &exec::exit_error(&err).unwrap().stderr;
    let s = String::from_utf8_lossy(s);
    assert!(s.starts_with("0123456789abcdef"), "{}", &s[..40]);
    assert!(s.contains("\n... omitting "), "stderr was not abbreviated");
    assert!(s.ends_with("0123456789abcdef\n"));
    assert!(s.len() < 70_000);
}

#[test]
fn stdout_stderr_same_writer_is_serialized() {
    let _g = lock();
    let b = buf();
    let mut c = sh("echo one; echo two >&2; echo three");
    c.stdout = Some(exec::Output::writer(b.clone()));
    c.stderr = Some(exec::Output::writer(b.clone()));
    c.run().unwrap();
    assert_eq!(text(&b), "one\ntwo\nthree\n");
}

#[test]
fn exit_status() {
    let _g = lock();
    let err = exec::command("false", &[]).run().unwrap_err();
    assert_eq!(err.to_string(), "exit status 1");
    let ee = exec::exit_error(&err).unwrap();
    assert!(!ee.process_state.success());
    let mut c = sh("exit 3");
    let err = c.run().unwrap_err();
    assert_eq!(exec::exit_error(&err).unwrap().process_state.exit_code(), 3);
    assert_eq!(c.process_state.unwrap().to_string(), "exit status 3");
    let mut c = sh("kill -9 $$");
    let err = c.run().unwrap_err();
    assert_eq!(err.to_string(), "signal: killed");
    assert_eq!(c.process_state.unwrap().exit_code(), -1);
}

#[test]
fn wait_closes_the_parent_pipe_ends() {
    let _g = lock();
    let mut c = sh("cat; echo e1 >&2");
    let mut stdin = c.stdin_pipe().unwrap();
    let stdout = c.stdout_pipe().unwrap();
    let stderr = c.stderr_pipe().unwrap();
    c.start().unwrap();
    stdin.write_all(b"data").unwrap();
    stdin.close().unwrap();
    let mut out = String::new();
    (&stdout).read_to_string(&mut out).unwrap();
    assert_eq!(out, "data");
    c.wait().unwrap();
    // Go's Wait closes the parent's ends: later I/O and closes fail.
    let e = (&stdout).read(&mut [0u8; 1]).unwrap_err();
    assert_eq!(e.to_string(), "read |0: file already closed");
    let e = (&stderr).read(&mut [0u8; 1]).unwrap_err();
    assert_eq!(e.to_string(), "read |0: file already closed");
    let e = stdin.write(b"x").unwrap_err();
    assert_eq!(e.to_string(), "write |1: file already closed");
    assert_eq!(
        stdout.close().unwrap_err().to_string(),
        "close |0: file already closed"
    );
}

#[test]
fn pipes() {
    let _g = lock();
    let mut c = sh("read x; echo got:$x; echo e1 >&2");
    let mut stdin = c.stdin_pipe().unwrap();
    let stdout = c.stdout_pipe().unwrap();
    let stderr = c.stderr_pipe().unwrap();
    assert!(c.stdin_pipe().is_err(), "Stdin already set");
    c.start().unwrap();
    assert!(c.stdout_pipe().is_err(), "StdoutPipe after process started");
    stdin.write_all(b"hello\n").unwrap();
    stdin.close().unwrap();
    let mut out = String::new();
    (&stdout).read_to_string(&mut out).unwrap();
    let mut err = String::new();
    (&stderr).read_to_string(&mut err).unwrap();
    c.wait().unwrap();
    assert_eq!((out.as_str(), err.as_str()), ("got:hello\n", "e1\n"));
    // Stdout already set errors.
    let mut c = exec::command("true", &[]);
    c.stdout = Some(exec::Output::file(os::stdout()));
    assert_eq!(
        c.output().1.unwrap_err().to_string(),
        "exec: Stdout already set"
    );
    assert_eq!(
        c.combined_output().1.unwrap_err().to_string(),
        "exec: Stdout already set"
    );
    let mut c = exec::command("true", &[]);
    c.stderr = Some(exec::Output::file(os::stderr()));
    assert_eq!(
        c.combined_output().1.unwrap_err().to_string(),
        "exec: Stderr already set"
    );
}

#[test]
fn stderr_pipe_holds_many_small_writes_while_stdout_is_drained() {
    let _g = lock();
    let mut c = sh("i=0; while [ $i -lt 4000 ]; do echo xxxxxxxx >&2; i=$((i+1)); done; echo done");
    let stdout = c.stdout_pipe().unwrap();
    let stderr = c.stderr_pipe().unwrap();
    c.start().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut out = String::new();
        (&stdout).read_to_string(&mut out).unwrap();
        let mut err = String::new();
        (&stderr).read_to_string(&mut err).unwrap();
        c.wait().unwrap();
        let _ = tx.send((out, err.len()));
    });
    let (out, err_len) = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("child blocked writing stderr while stdout was read to EOF");
    assert_eq!((out.as_str(), err_len), ("done\n", 4000 * 9));
}

#[test]
fn file_stdio_is_passed_directly() {
    let _g = lock();
    let dir = os::mkdir_temp("", "exectest").unwrap();
    let path = format!("{dir}/out");
    let f = os::create(&path).unwrap();
    let mut c = sh("echo to file");
    c.stdout = Some(exec::Output::file(f));
    c.run().unwrap();
    assert_eq!(os::read_file(&path).unwrap(), b"to file\n");
    let mut c = exec::command("cat", &[]);
    c.stdin = Some(exec::Input::File(os::open(&path).unwrap()));
    let (out, r) = c.output();
    r.unwrap();
    assert_eq!(out, b"to file\n");
    os::remove_all(&dir).unwrap();
}

#[test]
fn start_wait_misuse() {
    let _g = lock();
    let mut c = exec::command("echo", &["x"]);
    assert_eq!(c.wait().unwrap_err().to_string(), "exec: not started");
    c.start().unwrap();
    assert_eq!(c.start().unwrap_err().to_string(), "exec: already started");
    c.wait().unwrap();
    assert_eq!(
        c.wait().unwrap_err().to_string(),
        "exec: Wait was already called"
    );
    let mut c = exec::command("", &[]);
    assert_eq!(c.start().unwrap_err().to_string(), "exec: no command");
}

// ---- LookPath ----------------------------------------------------------------

fn executable(dir: &str, name: &str, mode: u32) -> String {
    let p = format!("{dir}/{name}");
    os::write_file(&p, b"#!/bin/sh\necho ran $0\n", FileMode(mode)).unwrap();
    os::chmod(&p, FileMode(mode)).unwrap();
    p
}

#[test]
fn look_path_rules() {
    let _g = lock();
    let dir = os::mkdir_temp("", "lookpath").unwrap();
    let dir = rust_stdlib::path::filepath::eval_symlinks(&dir).unwrap();
    os::mkdir(&format!("{dir}/adir"), FileMode(0o755)).unwrap();
    let ok = executable(&dir, "tool", 0o755);
    executable(&dir, "plain", 0o644);
    let old_path = std::env::var_os("PATH")
        .map(|v| v.to_string_lossy().into_owned())
        .unwrap_or_default();
    let old_wd = os::getwd().unwrap();

    os::setenv("PATH", &dir).unwrap();
    assert_eq!(exec::look_path("tool").unwrap(), ok);
    let err = exec::look_path("plain").unwrap_err();
    assert_eq!(
        err.to_string(),
        "exec: \"plain\": executable file not found in $PATH"
    );
    assert!(exec::ERR_NOT_FOUND.is(&err));
    assert_eq!(
        exec::look_path("adir").unwrap_err().to_string(),
        "exec: \"adir\": executable file not found in $PATH"
    );
    for bad in ["", ".", ".."] {
        let err = exec::look_path(bad).unwrap_err();
        assert!(exec::ERR_NOT_FOUND.is(&err), "{bad:?}");
    }
    // A name with a slash is not searched.
    assert_eq!(exec::look_path(&ok).unwrap(), ok);
    let err = exec::look_path(&format!("{dir}/plain")).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("exec: \"{dir}/plain\": permission denied")
    );
    assert!(fs::ERR_PERMISSION.is(&err));
    let err = exec::look_path(&format!("{dir}/adir")).unwrap_err();
    assert!(err.to_string().ends_with(": is a directory"), "{err}");
    let err = exec::look_path(&format!("{dir}/none")).unwrap_err();
    assert!(
        fs::ERR_NOT_EXIST.is(&err) && !exec::ERR_NOT_FOUND.is(&err),
        "{err}"
    );
    let e = exec::error_of(&err).unwrap();
    assert_eq!(e.name, format!("{dir}/none"));

    // A relative PATH entry yields ErrDot and still finds the path.
    os::chdir(&dir).unwrap();
    os::setenv("PATH", ".").unwrap();
    let (p, err) = exec::look_path_dot("tool");
    assert_eq!(p, "tool");
    let err = err.expect("ErrDot");
    assert!(exec::ERR_DOT.is(&err), "{err}");
    assert_eq!(
        err.to_string(),
        "exec: \"tool\": cannot run executable found relative to current directory"
    );
    assert!(exec::look_path("tool").is_err());
    // Command stores the error; Start reports it.
    let mut c = exec::command("tool", &[]);
    assert_eq!(c.path, "tool");
    assert!(exec::ERR_DOT.is(c.err.as_ref().unwrap()));
    assert!(exec::ERR_DOT.is(&c.start().unwrap_err()));
    // An empty entry also means the current directory.
    os::setenv("PATH", "").unwrap();
    assert!(exec::ERR_NOT_FOUND.is(&exec::look_path("tool").unwrap_err()));
    os::setenv("PATH", ":/nonexistent").unwrap();
    assert!(exec::ERR_DOT.is(&exec::look_path("tool").unwrap_err()));

    os::setenv("PATH", &old_path).unwrap();
    os::chdir(&old_wd).unwrap();
    os::remove_all(&dir).unwrap();
}

#[test]
fn command_not_found_and_start_errors() {
    let _g = lock();
    let mut c = exec::command("definitely-not-a-command-xyz", &["a"]);
    let err = c.run().unwrap_err();
    assert_eq!(
        err.to_string(),
        "exec: \"definitely-not-a-command-xyz\": executable file not found in $PATH"
    );
    assert_eq!(c.to_string(), "definitely-not-a-command-xyz a");
    let mut c = exec::command("/bin/true", &[]);
    c.dir = "/nonexistent-dir".into();
    assert_eq!(
        c.run().unwrap_err().to_string(),
        "chdir /nonexistent-dir: no such file or directory"
    );
    let dir = os::mkdir_temp("", "exectest").unwrap();
    let noexec = format!("{dir}/f");
    os::write_file(&noexec, b"#!/bin/sh\n", FileMode(0o644)).unwrap();
    let err = exec::command(&noexec, &[]).run().unwrap_err();
    assert!(err.to_string().ends_with(": permission denied"), "{err}");
    if !cfg!(target_os = "macos") {
        // (macOS runs such a file through /bin/sh: std spawns with posix_spawn.)
        os::write_file(&noexec, b"\x7fELF-not-really", FileMode(0o755)).unwrap();
        os::chmod(&noexec, FileMode(0o755)).unwrap();
        let err = exec::command(&noexec, &[]).run().unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("fork/exec {noexec}: exec format error")
        );
    }
    os::remove_all(&dir).unwrap();
}

// ---- environment ----------------------------------------------------------------

#[test]
fn environment_and_dedup() {
    let _g = lock();
    let mut c = sh("echo $A:$B:${C-unset}");
    c.env = Some(vec!["A=1".into(), "B=2".into(), "A=3".into()]);
    let (out, r) = c.output();
    r.unwrap();
    assert_eq!(out, b"3:2:unset\n");
    assert_eq!(c.environ(), ["B=2", "A=3"]);

    let mut c = exec::command("true", &[]);
    c.env = Some(vec![
        "X=1".into(),
        "NOEQ".into(),
        "=Z=9".into(),
        "X=2".into(),
        "".into(),
    ]);
    assert_eq!(c.environ(), ["NOEQ", "=Z=9", "X=2"]);

    let mut c = exec::command("true", &[]);
    c.env = Some(vec!["A=1\0".into()]);
    assert_eq!(
        c.run().unwrap_err().to_string(),
        "exec: environment variable contains NUL"
    );

    // Default environment plus PWD for Dir.
    let mut c = exec::command("true", &[]);
    c.dir = "/tmp".into();
    let env = c.environ();
    assert!(env.contains(&"PWD=/tmp".to_string()), "{env:?}");
    let c = exec::command("true", &[]);
    assert_eq!(c.environ().len(), std::env::vars_os().count());
    // A child sees the environment.
    let mut c = sh("echo ${EXEC_TEST_VAR}");
    c.env = Some(vec!["EXEC_TEST_VAR=seen".into()]);
    assert_eq!(c.output().0, b"seen\n");
    let mut c = sh("pwd");
    c.dir = "/".into();
    assert_eq!(c.output().0, b"/\n");
}

// ---- contexts and delays -----------------------------------------------------------

/// The deadline starts when the context is made, before the process is spawned.
/// Under heavy load a short deadline can expire before `start`, which fails
/// with the context error instead of killing a running child, so keep it far
/// above any plausible spawn latency; the tests still finish as soon as it fires.
const CTX_TIMEOUT: Duration = Duration::from_secs(2);

#[test]
fn context_timeout_kills() {
    let _g = lock();
    let (ctx, _cancel) = Context::background().with_timeout(CTX_TIMEOUT.into());
    let mut c = exec::command_context(&ctx, "sleep", &["30"]);
    let t = Instant::now();
    let err = c.run().unwrap_err();
    assert!(t.elapsed() < Duration::from_secs(10));
    assert_eq!(err.to_string(), "signal: killed");
    assert!(exec::exit_error(&err).is_some());
}

#[test]
fn context_already_done() {
    let _g = lock();
    let (ctx, cancel) = Context::background().with_cancel();
    cancel();
    let mut c = exec::command_context(&ctx, "echo", &["x"]);
    let err = c.start().unwrap_err();
    assert_eq!(err.to_string(), "context canceled");
    assert!(c.process.is_none());
}

#[test]
fn custom_cancel_and_wait_delay() {
    let _g = lock();
    // Cancel with an ignored signal: the process survives until WaitDelay kills it.
    let (ctx, _cancel) = Context::background().with_timeout(CTX_TIMEOUT.into());
    let mut c = exec::command_context(&ctx, "/bin/sh", &["-c", "trap '' INT TERM; sleep 30"]);
    c.cancel = Some(Box::new(|p| p.signal(&os::INTERRUPT)));
    c.wait_delay = Duration::from_millis(200).into();
    let t = Instant::now();
    let err = c.run().unwrap_err();
    assert!(t.elapsed() < Duration::from_secs(20));
    assert!(
        err.to_string() == "signal: killed" || exec::ERR_WAIT_DELAY.is(&err),
        "{err}"
    );
}

#[test]
fn wait_delay_with_inherited_pipe() {
    let _g = lock();
    // A background process keeps the pipe open; WaitDelay gives up on it.
    let b = buf();
    let mut c = sh("sleep 5 & echo started");
    c.stdout = Some(exec::Output::writer(b.clone()));
    c.wait_delay = Duration::from_millis(200).into();
    // WaitDelay only applies with a context-less command too.
    let t = Instant::now();
    let err = c.run().unwrap_err();
    assert!(
        t.elapsed() < Duration::from_secs(4),
        "took {:?}",
        t.elapsed()
    );
    assert!(exec::ERR_WAIT_DELAY.is(&err), "{err}");
    assert_eq!(
        err.to_string(),
        "exec: WaitDelay expired before I/O complete"
    );
    assert_eq!(text(&b), "started\n");
}

#[test]
fn cancel_without_context_is_rejected() {
    let _g = lock();
    let mut c = exec::command("true", &[]);
    c.cancel = Some(Box::new(|p| p.kill()));
    assert_eq!(
        c.start().unwrap_err().to_string(),
        "exec: command with a non-nil Cancel was not created with CommandContext"
    );
}

#[test]
fn extra_files_are_rejected() {
    let _g = lock();
    let mut c = exec::command("true", &[]);
    c.extra_files.push(os::stdout());
    let err = c.start().unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Unsupported);
}

#[test]
fn error_types() {
    let _g = lock();
    let e = exec::Error {
        name: "x".into(),
        err: exec::ERR_NOT_FOUND.into(),
    };
    assert_eq!(
        e.to_string(),
        "exec: \"x\": executable file not found in $PATH"
    );
    assert!(exec::ERR_NOT_FOUND.is(&io::Error::from(e)));
    assert_eq!(
        exec::ERR_WAIT_DELAY.to_string(),
        "exec: WaitDelay expired before I/O complete"
    );
    assert_eq!(
        exec::ERR_DOT.to_string(),
        "cannot run executable found relative to current directory"
    );
}
