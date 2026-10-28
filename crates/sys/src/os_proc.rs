//! Go's `os.StartProcess`, `os.ProcAttr`, `Process.Wait`, `Process.Release`
//! and `Process.WithHandle`: processes started with `fork`/`execve` so that
//! descriptors can be given to the child at any number and an executable
//! without a shebang fails with "exec format error".
use crate::errno::{Errno, Signal, ECHILD, EINVAL};
use crate::ffi::spawn;
use crate::os::Process;
use std::fmt;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::sync::{Arc, Mutex};

/// The state a started [`Process`] shares between its clones: Go's
/// `processStatus`, with the pidfd (Linux 5.3 and later) open only while the
/// process runs. Whether the process ever had a handle is fixed at creation
/// and outlives the descriptor, because `WithHandle` reports `ErrNoHandle`
/// after `Wait` and `Release` only for a process that never had one.
#[derive(Debug)]
pub enum State {
    Running { handle: Option<OwnedFd> },
    Done { had_handle: bool },
    Released { had_handle: bool },
}

impl State {
    /// Go's `doRelease(statusDone)`: only a running process finishes, and
    /// finishing closes its pidfd.
    fn finish(&mut self) {
        if let State::Running { handle } = self {
            *self = State::Done {
                had_handle: handle.is_some(),
            };
        }
    }

    /// Go's `doRelease(statusReleased)`.
    fn release(&mut self) {
        if let State::Running { handle } = self {
            *self = State::Released {
                had_handle: handle.is_some(),
            };
        }
    }
}

pub(crate) fn lock(m: &Mutex<State>) -> std::sync::MutexGuard<'_, State> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// An error from starting or waiting for a process.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ProcessError {
    /// `*PathError{Op: "fork/exec"}`.
    ForkExec { path: String, err: Errno },
    /// `*PathError{Op: "chdir"}`: the working directory cannot be entered.
    Chdir { dir: String, err: Errno },
    /// `*SyscallError{Syscall: "wait"}`.
    Wait(Errno),
    /// A bare `syscall.Errno`: `Process.Wait` after `Release` is `EINVAL`.
    Errno(Errno),
    /// `os.ErrNoHandle`: "os: process handle unavailable".
    NoHandle,
    /// `os.ErrProcessDone`.
    ProcessDone,
    /// "os: process already released".
    Released,
    /// "os: process not initialized".
    NotInitialized,
}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProcessError::ForkExec { path, err } => write!(f, "fork/exec {path}: {err}"),
            ProcessError::Chdir { dir, err } => write!(f, "chdir {dir}: {err}"),
            ProcessError::Wait(err) => write!(f, "wait: {err}"),
            ProcessError::Errno(err) => err.fmt(f),
            ProcessError::NoHandle => f.write_str("os: process handle unavailable"),
            ProcessError::ProcessDone => f.write_str("os: process already finished"),
            ProcessError::Released => f.write_str("os: process already released"),
            ProcessError::NotInitialized => f.write_str("os: process not initialized"),
        }
    }
}

impl std::error::Error for ProcessError {}

impl ProcessError {
    /// The operating-system error underneath, if any.
    pub fn errno(&self) -> Option<Errno> {
        match self {
            ProcessError::ForkExec { err, .. }
            | ProcessError::Chdir { err, .. }
            | ProcessError::Wait(err)
            | ProcessError::Errno(err) => Some(*err),
            _ => None,
        }
    }
}

/// `os.ProcAttr`: the attributes of a new process.
#[derive(Debug, Default)]
pub struct ProcAttr {
    /// The working directory of the new process; empty for the caller's.
    pub dir: String,
    /// The environment as `key=value` strings; `None` uses the caller's.
    pub env: Option<Vec<String>>,
    /// `ProcAttr.Files`: the descriptors for the child's descriptors 0, 1, 2
    /// and beyond, in order. The descriptors stay owned by the caller and
    /// must stay open for the call. `None` (Go's nil) closes that descriptor
    /// in the child.
    pub files: Vec<Option<RawFd>>,
}

/// `os.ProcessState`: what `Process.Wait` reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessState {
    pid: i32,
    status: ExitStatus,
}

impl ProcessState {
    /// `ProcessState.Pid`.
    pub fn pid(&self) -> i32 {
        self.pid
    }
    /// `ProcessState.Exited`: false when a signal ended the process.
    pub fn exited(&self) -> bool {
        self.status.code().is_some()
    }
    /// `ProcessState.Success`.
    pub fn success(&self) -> bool {
        self.status.success()
    }
    /// `ProcessState.ExitCode`: -1 if the process was ended by a signal.
    pub fn exit_code(&self) -> i32 {
        self.status.code().unwrap_or(-1)
    }
    /// `ProcessState.String`: "exit status 3", "signal: killed", ...
    fn string(&self) -> String {
        let mut res = String::new();
        if let Some(code) = self.status.code() {
            res = format!("exit status {code}");
        } else if let Some(sig) = self.status.signal() {
            res = format!("signal: {}", Signal(sig));
        } else if let Some(sig) = self.status.stopped_signal() {
            res = format!("stop signal: {}", Signal(sig));
        } else if self.status.continued() {
            res = "continued".into();
        }
        if self.status.core_dumped() {
            res.push_str(" (core dumped)");
        }
        res
    }
}

impl fmt::Display for ProcessState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string())
    }
}

/// `os.StartProcess`: starts the program `name` (a path, with no `PATH`
/// search) with `argv` and the attributes `attr`.
pub fn start_process(
    name: &str,
    argv: &[String],
    attr: &ProcAttr,
) -> Result<Process, ProcessError> {
    if !attr.dir.is_empty() {
        if let Err(e) = std::fs::metadata(&attr.dir) {
            return Err(ProcessError::Chdir {
                dir: attr.dir.clone(),
                err: Errno::from(e),
            });
        }
    }
    let env: Vec<Vec<u8>> = match &attr.env {
        Some(env) => env.iter().map(|s| s.clone().into_bytes()).collect(),
        None => {
            use std::os::unix::ffi::OsStrExt;
            std::env::vars_os()
                .map(|(k, v)| {
                    let mut kv = k.as_bytes().to_vec();
                    kv.push(b'=');
                    kv.extend_from_slice(v.as_bytes());
                    kv
                })
                .collect()
        }
    };
    let argv: Vec<Vec<u8>> = argv.iter().map(|s| s.clone().into_bytes()).collect();
    let fds: Vec<RawFd> = attr.files.iter().map(|f| f.unwrap_or(-1)).collect();
    // Like Go's `File.Fd`, hand the child blocking descriptors: the
    // non-blocking flag belongs to the open file description, which the child
    // shares, and a program such as `cat` does not expect EAGAIN.
    for &fd in &fds {
        if fd >= 0 {
            let _ = crate::ffi::set_nonblocking(fd, false);
        }
    }
    let spec = spawn::Spec {
        path: name.as_bytes(),
        argv: &argv,
        envp: &env,
        dir: (!attr.dir.is_empty()).then_some(attr.dir.as_bytes()),
        fds: &fds,
        extra: spawn::Extra::default(),
    };
    match spawn::fork_exec(&spec) {
        Ok(started) => Ok(Process::started(i64::from(started.pid), started.pidfd)),
        Err(err) => Err(ProcessError::ForkExec {
            path: name.to_string(),
            err,
        }),
    }
}

impl Process {
    pub(crate) fn started(pid: i64, handle: Option<OwnedFd>) -> Process {
        Process {
            pid,
            shared: Some(Arc::new(Mutex::new(State::Running { handle }))),
        }
    }

    /// `Process.WithHandle`: calls `f` with a pidfd for the process (Linux
    /// 5.3 and later). Where the platform has no process handles it fails
    /// with [`ProcessError::NoHandle`], before and after `wait` or `release`;
    /// a process that had a handle fails with [`ProcessError::ProcessDone`]
    /// after `wait` and [`ProcessError::Released`] after `release`.
    pub fn with_handle<F: FnOnce(RawFd)>(&self, f: F) -> Result<(), ProcessError> {
        let Some(shared) = &self.shared else {
            return Err(ProcessError::NoHandle);
        };
        let guard = lock(shared);
        match &*guard {
            State::Running { handle: Some(fd) } => {
                // The lock is held while `f` runs, so `wait` cannot close the handle.
                f(fd.as_raw_fd());
                Ok(())
            }
            State::Running { handle: None }
            | State::Done { had_handle: false }
            | State::Released { had_handle: false } => Err(ProcessError::NoHandle),
            State::Done { had_handle: true } => Err(ProcessError::ProcessDone),
            State::Released { had_handle: true } => Err(ProcessError::Released),
        }
    }

    /// `Process.Wait`: waits for a child to exit. After `release` it fails
    /// with the bare `EINVAL`; after `wait` with the wait syscall's `ECHILD`,
    /// which Go's pidfd path reports without waiting again (its pid path
    /// waits on the pid, or on any child once `Release` has set it to -1).
    pub fn wait(&self) -> Result<ProcessState, ProcessError> {
        if let Some(shared) = &self.shared {
            match &*lock(shared) {
                State::Released { .. } => return Err(ProcessError::Errno(EINVAL)),
                State::Done { .. } => return Err(ProcessError::Wait(ECHILD)),
                State::Running { .. } => {}
            }
        }
        match self.pid {
            -1 => return Err(ProcessError::Errno(EINVAL)),
            0 => return Err(ProcessError::NotInitialized),
            _ => {}
        }
        let status = spawn::wait(self.pid as i32).map_err(ProcessError::Wait)?;
        if let Some(shared) = &self.shared {
            lock(shared).finish();
        }
        Ok(ProcessState {
            pid: self.pid as i32,
            status: ExitStatus::from_raw(status),
        })
    }

    /// `Process.Release`: frees the handle; the process can no longer be
    /// waited for or signalled through this value.
    pub fn release(&mut self) {
        if let Some(shared) = &self.shared {
            lock(shared).release();
        }
        self.pid = -1;
    }
}
