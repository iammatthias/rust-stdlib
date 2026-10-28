//! `os.Process`, `os.ProcessState`, `os.ProcAttr`, `os.StartProcess` and
//! `os.Signal`, over `std::process`.
//!
//! `std` can neither signal an arbitrary process nor wait on one it did not
//! spawn, so [`Process::signal`] shells out to the platform `kill` tool for
//! anything but a still-running child and [`Process::wait`] works only for
//! children started by [`start_process`] or `exec::Cmd` (a process found by
//! [`find_process`] fails with `ECHILD`, as Go does for non-children).

use super::error::{errno, from_errno, path_err, SyscallError};
use super::file::File;
use super::Error;
use crate::io::fs::{self, PathError};
use std::fmt;
use std::io;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};

/// A signal sent to a process (`os.Signal`). `Display` describes it
/// (`Signal.String`).
pub trait Signal: fmt::Display {
    /// The signal number, for the signals that [`Process::signal`] can send.
    fn number(&self) -> Option<i32> {
        None
    }
}

/// An operating system signal (`syscall.Signal`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Sig(pub i32);

/// `os.Interrupt`: `SIGINT`.
pub const INTERRUPT: Sig = Sig(2);
/// `os.Kill`: `SIGKILL`.
pub const KILL: Sig = Sig(9);

#[cfg(any(target_os = "linux", target_os = "android"))]
const SIGNALS: [&str; 32] = [
    "",
    "hangup",
    "interrupt",
    "quit",
    "illegal instruction",
    "trace/breakpoint trap",
    "aborted",
    "bus error",
    "floating point exception",
    "killed",
    "user defined signal 1",
    "segmentation fault",
    "user defined signal 2",
    "broken pipe",
    "alarm clock",
    "terminated",
    "stack fault",
    "child exited",
    "continued",
    "stopped (signal)",
    "stopped",
    "stopped (tty input)",
    "stopped (tty output)",
    "urgent I/O condition",
    "CPU time limit exceeded",
    "file size limit exceeded",
    "virtual timer expired",
    "profiling timer expired",
    "window changed",
    "I/O possible",
    "power failure",
    "bad system call",
];

#[cfg(not(any(target_os = "linux", target_os = "android")))]
const SIGNALS: [&str; 32] = [
    "",
    "hangup",
    "interrupt",
    "quit",
    "illegal instruction",
    "trace/BPT trap",
    "abort trap",
    "EMT trap",
    "floating point exception",
    "killed",
    "bus error",
    "segmentation fault",
    "bad system call",
    "broken pipe",
    "alarm clock",
    "terminated",
    "urgent I/O condition",
    "suspended (signal)",
    "suspended",
    "continued",
    "child exited",
    "stopped (tty input)",
    "stopped (tty output)",
    "I/O possible",
    "cputime limit exceeded",
    "filesize limit exceeded",
    "virtual timer expired",
    "profiling timer expired",
    "window size changes",
    "information request",
    "user defined signal 1",
    "user defined signal 2",
];

impl fmt::Display for Sig {
    /// `Signal.String`: Go's name of the signal, or `signal N`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match usize::try_from(self.0).ok().and_then(|i| SIGNALS.get(i)) {
            Some(s) if !s.is_empty() => f.write_str(s),
            _ => write!(f, "signal {}", self.0),
        }
    }
}

impl Signal for Sig {
    fn number(&self) -> Option<i32> {
        Some(self.0)
    }
}

/// The attributes of a new process (`os.ProcAttr`).
///
/// `Sys` (`syscall.SysProcAttr`) is not represented. `files` holds the
/// descriptors for standard input, output and error: a `None` entry (Go's
/// nil, "closed in the child") is given `/dev/null`, and descriptors beyond
/// the third are rejected, since `std` cannot place a file at an arbitrary
/// descriptor number without `unsafe`.
#[derive(Debug, Default)]
pub struct ProcAttr {
    /// The working directory of the new process; empty for the caller's.
    pub dir: String,
    /// The environment as `key=value` strings; `None` uses the caller's.
    pub env: Option<Vec<String>>,
    /// Files for descriptors 0, 1 and 2.
    pub files: Vec<Option<File>>,
}

#[derive(Debug)]
struct ProcState {
    child: Option<Child>,
    waiting: bool,
    done: bool,
    released: bool,
}

/// A process started or found by this program (`os.Process`). Clones share
/// the process (they are Go's `*Process`).
#[derive(Clone, Debug)]
pub struct Process {
    /// The process id (`Process.Pid`); -1 after [`Process::release`].
    pub pid: i32,
    state: Arc<Mutex<ProcState>>,
}

/// Reports about a finished process (`os.ProcessState`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessState {
    pid: i32,
    status: ExitStatus,
}

fn lock(m: &Mutex<ProcState>) -> MutexGuard<'_, ProcState> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Process {
    pub(crate) fn from_child(child: Child) -> Process {
        Process {
            pid: child.id() as i32,
            state: Arc::new(Mutex::new(ProcState {
                child: Some(child),
                waiting: false,
                done: false,
                released: false,
            })),
        }
    }

    /// Causes the process to exit immediately (`Process.Kill`).
    pub fn kill(&self) -> io::Result<()> {
        self.signal(&KILL)
    }

    /// Sends a signal to the process (`Process.Signal`). Only [`Sig`]
    /// values can be sent. Signalling a finished process fails with
    /// `ErrProcessDone`.
    pub fn signal(&self, sig: &dyn Signal) -> io::Result<()> {
        if self.pid == -1 {
            return Err(io::Error::other("os: process already released"));
        }
        if self.pid == 0 {
            return Err(io::Error::other("os: process not initialized"));
        }
        let Some(num) = sig.number() else {
            return Err(io::Error::other("os: unsupported signal type"));
        };
        let mut st = lock(&self.state);
        if st.done {
            return Err(Error::ProcessDone.into());
        }
        if num == KILL.0 && !st.waiting {
            if let Some(child) = st.child.as_mut() {
                // `Child::kill` is a no-op on a child that was already reaped.
                return match child.try_wait() {
                    Ok(Some(_)) => Err(Error::ProcessDone.into()),
                    _ => child.kill().map_err(super::error::os_error),
                };
            }
        }
        drop(st);
        kill_tool(self.pid, num)
    }

    /// Releases any resources associated with the process (`Process.Release`).
    /// The process can no longer be waited for or signalled.
    pub fn release(&mut self) -> io::Result<()> {
        let mut st = lock(&self.state);
        st.released = true;
        st.child = None;
        drop(st);
        self.pid = -1;
        Ok(())
    }

    /// Waits for the process to exit and returns its state (`Process.Wait`).
    /// After [`Process::release`] (on this value or a clone) it fails with the
    /// bare `EINVAL`, unless the process had already been waited for: then the
    /// status is still done and it reports `ECHILD`, as Go's pidfd path does.
    /// Go's pid path calls `wait4(-1)` there and can reap an unrelated child;
    /// this never waits again.
    pub fn wait(&self) -> io::Result<ProcessState> {
        let mut child = {
            let mut st = lock(&self.state);
            if st.done || st.waiting {
                return Err(SyscallError::new("wait", from_errno(errno::ECHILD)).into());
            }
            if self.pid == -1 || st.released {
                return Err(from_errno(errno::EINVAL));
            }
            match st.child.take() {
                Some(c) => {
                    st.waiting = true;
                    c
                }
                None => return Err(SyscallError::new("wait", from_errno(errno::ECHILD)).into()),
            }
        };
        let result = child.wait();
        let mut st = lock(&self.state);
        st.waiting = false;
        match result {
            Ok(status) => {
                st.done = true;
                Ok(ProcessState {
                    pid: self.pid,
                    status,
                })
            }
            Err(e) => {
                st.child = Some(child);
                Err(SyscallError::new("wait", e).into())
            }
        }
    }

    /// `Process.WithHandle`. `std` cannot obtain a process handle (a Linux
    /// pidfd), so this always reports [`Error::NoHandle`], which Go
    /// documents for platforms without handles.
    pub fn with_handle<F: FnOnce(usize)>(&self, f: F) -> io::Result<()> {
        let _ = f;
        Err(Error::NoHandle.into())
    }
}

/// Sends signal `num` to `pid` with the platform `kill` tool.
fn kill_tool(pid: i32, num: i32) -> io::Result<()> {
    let out = Command::new("kill")
        .arg(format!("-{num}"))
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .output()
        .map_err(super::error::os_error)?;
    if out.status.success() {
        return Ok(());
    }
    let msg = String::from_utf8_lossy(&out.stderr).to_lowercase();
    if msg.contains("no such process") {
        Err(Error::ProcessDone.into())
    } else if msg.contains("not permitted") {
        Err(from_errno(errno::EPERM))
    } else {
        Err(from_errno(errno::ESRCH))
    }
}

/// Looks for a running process by its pid (`os.FindProcess`). On Unix it
/// always succeeds; use [`Process::signal`] with signal 0 to test existence.
pub fn find_process(pid: i32) -> io::Result<Process> {
    Ok(Process {
        pid,
        state: Arc::new(Mutex::new(ProcState {
            child: None,
            waiting: false,
            done: false,
            released: false,
        })),
    })
}

/// Starts a new process with the program, arguments and attributes
/// specified by `name`, `argv` and `attr` (`os.StartProcess`). `name` is a
/// path (no `PATH` search); `argv[0]` becomes the process's `argv[0]`.
pub fn start_process(name: &str, argv: &[String], attr: &ProcAttr) -> io::Result<Process> {
    if attr.files.len() > 3 {
        return Err(path_err(
            "fork/exec",
            name,
            io::Error::new(io::ErrorKind::Unsupported, "more than 3 files unsupported"),
        ));
    }
    let stdio = |i: usize| -> io::Result<Stdio> {
        match attr.files.get(i) {
            Some(Some(f)) => Ok(Stdio::from(f.try_clone_std()?)),
            _ => Ok(Stdio::null()),
        }
    };
    let (i, o, e) = (
        stdio(0).map_err(|e| path_err("fork/exec", name, e))?,
        stdio(1).map_err(|e| path_err("fork/exec", name, e))?,
        stdio(2).map_err(|e| path_err("fork/exec", name, e))?,
    );
    spawn_process(name, argv, &attr.dir, attr.env.as_deref(), [i, o, e])
}

/// Starts `name` with the given standard streams; the shared tail of
/// [`start_process`] and `exec::Cmd::start`.
pub(crate) fn spawn_process(
    name: &str,
    argv: &[String],
    dir: &str,
    env: Option<&[String]>,
    stdio: [Stdio; 3],
) -> io::Result<Process> {
    // Like Go, report a bad working directory as a `chdir` error.
    if !dir.is_empty() {
        if let Err(e) = super::stat(dir) {
            return Err(match fs::path_error(&e) {
                Some(pe) => PathError::new(
                    "chdir",
                    &pe.path,
                    super::error::errno_of(&pe.err)
                        .map(io::Error::from)
                        .unwrap_or_else(|| io::Error::from(io::ErrorKind::NotFound)),
                )
                .into(),
                None => e,
            });
        }
    }
    let mut cmd = Command::new(name);
    if let Some(a0) = argv.first() {
        cmd.arg0(a0);
    }
    cmd.args(argv.iter().skip(1));
    if !dir.is_empty() {
        cmd.current_dir(dir);
    }
    if let Some(env) = env {
        cmd.env_clear();
        for kv in env {
            // Entries without `=` are passed as keys with empty values.
            match kv.split_once('=') {
                Some((k, v)) if !k.is_empty() => {
                    cmd.env(k, v);
                }
                None if !kv.is_empty() => {
                    cmd.env(kv, "");
                }
                _ => {}
            }
        }
    }
    let [i, o, e] = stdio;
    cmd.stdin(i).stdout(o).stderr(e);
    match cmd.spawn() {
        Ok(child) => Ok(Process::from_child(child)),
        Err(e) => Err(PathError::new("fork/exec", name, super::error::os_error(e)).into()),
    }
}

impl ProcessState {
    /// The process id of the exited process (`ProcessState.Pid`).
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// Reports whether the program has exited (`ProcessState.Exited`);
    /// false when it was terminated by a signal.
    pub fn exited(&self) -> bool {
        self.status.code().is_some()
    }

    /// Reports whether the program exited successfully
    /// (`ProcessState.Success`).
    pub fn success(&self) -> bool {
        self.status.success()
    }

    /// The exit code, or -1 if the process has not exited or was terminated
    /// by a signal (`ProcessState.ExitCode`).
    pub fn exit_code(&self) -> i32 {
        self.status.code().unwrap_or(-1)
    }

    /// The system-dependent exit information (`ProcessState.Sys`, a
    /// `syscall.WaitStatus` in Go).
    pub fn sys(&self) -> ExitStatus {
        self.status
    }
}

impl ProcessState {
    /// Go's `ProcessState.String`: `exit status N`, `signal: killed`, ...
    fn describe(&self) -> String {
        let mut res = String::new();
        if let Some(code) = self.status.code() {
            res = format!("exit status {code}");
        } else if let Some(sig) = self.status.signal() {
            res = format!("signal: {}", Sig(sig));
        } else if let Some(sig) = self.status.stopped_signal() {
            res = format!("stop signal: {}", Sig(sig));
        } else if self.status.continued() {
            res = "continued".to_string();
        }
        if self.status.core_dumped() {
            res.push_str(" (core dumped)");
        }
        res
    }
}

impl fmt::Display for ProcessState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}
