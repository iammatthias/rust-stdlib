//! Go's `os` functions that need operating-system calls std does not expose:
//! process and user identity, the hostname, signalling a process, `Chtimes`
//! and `Link`.
use crate::errno::{Errno, Signal, ESRCH};
use crate::ffi;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

supported! {
    pub use crate::os_file::{pipe, DeadlineError, File, FileError, FileKind};
    /// Go's `os/exec`.
    pub mod exec {
        pub use crate::os_exec::*;
    }
    /// Go's `os/signal`.
    pub mod signal {
        pub use crate::os_signal::*;
    }
    /// Go's `os/user`.
    pub mod user {
        pub use crate::os_user::*;
    }
    pub use crate::os_proc::{start_process, ProcAttr, ProcessError, ProcessState};
    pub use crate::os_root::{
        open_in_root, open_root, valid_path, Cause, DirEntry, FileInfo, FileMode, Root, RootError,
        RootFS, O_APPEND, O_CLOEXEC, O_CREATE, O_EXCL, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY,
    };
}

/// `os.SyscallError`: an error from a named system call.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SyscallError {
    /// The failing call, e.g. "getgroups".
    pub syscall: String,
    /// The underlying error number.
    pub err: Errno,
}

impl fmt::Display for SyscallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.syscall, self.err)
    }
}

impl std::error::Error for SyscallError {}

/// `os.PathError`: an error from an operation on a named file.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PathError {
    /// The operation, e.g. "chtimes".
    pub op: String,
    /// The path given to the operation.
    pub path: String,
    /// The underlying error number.
    pub err: Errno,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.op, self.path, self.err)
    }
}

impl std::error::Error for PathError {}

/// `os.LinkError`: an error from a link, symlink or rename.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LinkError {
    /// The operation, e.g. "link".
    pub op: String,
    /// The source path.
    pub old: String,
    /// The destination path.
    pub new: String,
    /// The underlying error number.
    pub err: Errno,
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}: {}", self.op, self.old, self.new, self.err)
    }
}

impl std::error::Error for LinkError {}

/// `os.Getuid`: the numeric user id of the caller.
pub fn getuid() -> i64 {
    ffi::getuid()
}

/// `os.Geteuid`: the numeric effective user id of the caller.
pub fn geteuid() -> i64 {
    ffi::geteuid()
}

/// `os.Getgid`: the numeric group id of the caller.
pub fn getgid() -> i64 {
    ffi::getgid()
}

/// `os.Getegid`: the numeric effective group id of the caller.
pub fn getegid() -> i64 {
    ffi::getegid()
}

/// `os.Getppid`: the process id of the caller's parent.
pub fn getppid() -> i64 {
    ffi::getppid()
}

/// `os.Getgroups`: the numeric ids of the groups the caller belongs to.
pub fn getgroups() -> Result<Vec<i64>, SyscallError> {
    ffi::getgroups()
        .map(|groups| groups.into_iter().map(i64::from).collect())
        .map_err(|err| SyscallError {
            syscall: "getgroups".into(),
            err,
        })
}

/// `os.Hostname`: the host name reported by the kernel.
pub fn hostname() -> Result<String, SyscallError> {
    ffi::gethostname()
        .map(|name| String::from_utf8_lossy(&name).into_owned())
        .map_err(|err| SyscallError {
            syscall: "gethostname".into(),
            err,
        })
}

/// `os.Chtimes`: changes the access and modification times of a file. `None`
/// (Go's zero `time.Time`) leaves that time unchanged.
pub fn chtimes(
    name: &str,
    atime: Option<SystemTime>,
    mtime: Option<SystemTime>,
) -> Result<(), PathError> {
    ffi::utimens(name.as_bytes(), atime.map(timespec), mtime.map(timespec)).map_err(|err| {
        PathError {
            op: "chtimes".into(),
            path: name.into(),
            err,
        }
    })
}

/// Go's `NsecToTimespec(t.UnixNano())`: whole seconds and a non-negative
/// nanosecond part.
pub(crate) fn timespec(t: SystemTime) -> (i64, i64) {
    let (secs, nanos) = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.subsec_nanos() as i64),
        Err(e) => {
            let d = e.duration();
            let (s, n) = (d.as_secs() as i64, d.subsec_nanos() as i64);
            if n == 0 {
                (-s, 0)
            } else {
                (-s - 1, 1_000_000_000 - n)
            }
        }
    };
    (secs, nanos)
}

/// `os.Link`: creates `new` as a hard link to the file `old`.
pub fn link(old: &str, new: &str) -> Result<(), LinkError> {
    ffi::link(old.as_bytes(), new.as_bytes()).map_err(|err| LinkError {
        op: "link".into(),
        old: old.into(),
        new: new.into(),
        err,
    })
}

/// The error from [`Process::signal`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SignalError {
    /// `os.ErrProcessDone`: the process has already finished.
    ProcessDone,
    /// "os: process not initialized": the pid is zero.
    NotInitialized,
    /// "os: process already released": the pid is -1.
    Released,
    /// Any other failure of `kill`.
    Errno(Errno),
}

impl fmt::Display for SignalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignalError::ProcessDone => f.write_str("os: process already finished"),
            SignalError::NotInitialized => f.write_str("os: process not initialized"),
            SignalError::Released => f.write_str("os: process already released"),
            SignalError::Errno(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for SignalError {}

#[cfg(all(
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64"
))]
pub(crate) type ProcShared = crate::os_proc::State;
#[cfg(not(all(
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64"
)))]
pub(crate) type ProcShared = ();

/// `os.Process`: a handle on a process identified by its pid. Clones share
/// the process.
#[derive(Clone, Debug)]
pub struct Process {
    /// The process id.
    pub pid: i64,
    pub(crate) shared: Option<std::sync::Arc<std::sync::Mutex<ProcShared>>>,
}

impl PartialEq for Process {
    fn eq(&self, other: &Process) -> bool {
        self.pid == other.pid
    }
}

impl Eq for Process {}

impl Process {
    /// `os.FindProcess`: on Unix this always succeeds.
    pub fn find(pid: i64) -> Process {
        // Go 1.23+ opens a pidfd here where the kernel has them.
        #[cfg(all(
            any(target_os = "linux", target_os = "macos"),
            target_pointer_width = "64"
        ))]
        if pid > 0 {
            if let Some(fd) = crate::ffi::spawn::pidfd_open(pid as i32) {
                return Process::started(pid, Some(fd));
            }
        }
        Process { pid, shared: None }
    }

    /// `Process.Signal`: sends a signal; signal 0 only checks the process exists.
    pub fn signal(&self, sig: Signal) -> Result<(), SignalError> {
        #[cfg(all(
            any(target_os = "linux", target_os = "macos"),
            target_pointer_width = "64"
        ))]
        {
            use crate::os_proc::State;
            let guard = self.shared.as_ref().map(|s| crate::os_proc::lock(s));
            // Go's pidfd path reads the status before the pid, so a finished
            // process that had a handle is "done" even once released.
            match (guard.as_deref(), self.pid) {
                (Some(State::Done { had_handle: true }), _) => {
                    return Err(SignalError::ProcessDone)
                }
                (_, -1) => return Err(SignalError::Released),
                (_, 0) => return Err(SignalError::NotInitialized),
                (Some(State::Done { .. }), _) => return Err(SignalError::ProcessDone),
                (Some(State::Released { .. }), _) => return Err(SignalError::Released),
                (Some(State::Running { .. }) | None, _) => {}
            }
        }
        #[cfg(not(all(
            any(target_os = "linux", target_os = "macos"),
            target_pointer_width = "64"
        )))]
        match self.pid {
            -1 => return Err(SignalError::Released),
            0 => return Err(SignalError::NotInitialized),
            _ => {}
        }
        ffi::kill(self.pid as i32, sig.0).map_err(|e| {
            if e == ESRCH {
                SignalError::ProcessDone
            } else {
                SignalError::Errno(e)
            }
        })
    }

    /// `Process.Kill`: sends SIGKILL.
    pub fn kill(&self) -> Result<(), SignalError> {
        self.signal(crate::errno::SIGKILL)
    }
}
