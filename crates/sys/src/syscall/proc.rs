//! `ForkExec`, `StartProcess` and `Exec`, over the fork/exec code that
//! `os.StartProcess` shares (`crate::ffi::spawn`).
use super::errno::Errno;
use super::*;
use crate::ffi::spawn;
use std::fmt;
use std::os::fd::IntoRawFd;
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::Arc;

pub use crate::ffi::FORK_LOCK;

/// `syscall.Credential`: the identities a child process assumes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Credential {
    /// User ID.
    pub uid: u32,
    /// Group ID.
    pub gid: u32,
    /// Supplementary group IDs.
    pub groups: Vec<u32>,
    /// If true, the supplementary groups are not set.
    pub no_set_groups: bool,
}

/// `syscall.SysProcIDMap`: a container-to-host id mapping for user namespaces.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SysProcIDMap {
    pub container_id: isize,
    pub host_id: isize,
    pub size: isize,
}

/// `syscall.SysProcAttr`: operating-system attributes of a new process.
#[derive(Clone, Debug, Default)]
pub struct SysProcAttr {
    pub chroot: String,
    pub credential: Option<Credential>,
    /// The child calls `ptrace(PTRACE_TRACEME)`.
    pub ptrace: bool,
    /// Create a session.
    pub setsid: bool,
    /// Set the process group to `pgid`, or to the child's pid if that is 0.
    pub setpgid: bool,
    /// Make `ctty` (a descriptor number in the child) the controlling terminal.
    pub setctty: bool,
    /// Detach descriptor 0 from its terminal.
    pub noctty: bool,
    /// The controlling terminal's descriptor.
    pub ctty: isize,
    /// Put the child's group in the foreground of the terminal `ctty` (a
    /// descriptor number in the parent); implies `setpgid`.
    pub foreground: bool,
    pub pgid: isize,
    /// A signal the kernel sends the child when the creating thread dies.
    pub pdeathsig: Signal,
    pub cloneflags: usize,
    pub unshareflags: usize,
    pub uid_mappings: Vec<SysProcIDMap>,
    pub gid_mappings: Vec<SysProcIDMap>,
    pub gid_mappings_enable_setgroups: bool,
    pub ambient_caps: Vec<usize>,
    pub use_cgroup_fd: bool,
    pub cgroup_fd: isize,
    /// If set, receives a pidfd for the child (or -1) once it has started.
    pub pid_fd: Option<Arc<AtomicIsize>>,
}

/// `syscall.ProcAttr`: attributes of a new process.
#[derive(Clone, Debug, Default)]
pub struct ProcAttr {
    /// The working directory; empty for the caller's.
    pub dir: String,
    /// The environment as `key=value` strings; empty means no variables.
    pub env: Vec<String>,
    /// The descriptors for the child's descriptors 0, 1, 2 and beyond; a
    /// value of `usize::MAX` (Go's -1) closes that descriptor in the child.
    pub files: Vec<usize>,
    pub sys: Option<SysProcAttr>,
}

/// The errors of `ForkExec`: an `Errno`, or one of Go's two plain errors for
/// inconsistent `SysProcAttr` fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForkExecError {
    Errno(Errno),
    Message(&'static str),
}

impl fmt::Display for ForkExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ForkExecError::Errno(e) => e.fmt(f),
            ForkExecError::Message(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for ForkExecError {}

impl From<Errno> for ForkExecError {
    fn from(e: Errno) -> ForkExecError {
        ForkExecError::Errno(e)
    }
}

fn format_id_mappings(maps: &[SysProcIDMap]) -> Vec<u8> {
    let mut data = String::new();
    for m in maps {
        data.push_str(&format!("{} {} {}\n", m.container_id, m.host_id, m.size));
    }
    data.into_bytes()
}

fn nul_free(s: &str) -> Result<Vec<u8>, Errno> {
    byte_ptr_from_string(s).map(|_| s.as_bytes().to_vec())
}

fn fork_exec_inner(
    argv0: &str,
    argv: &[String],
    attr: Option<&ProcAttr>,
) -> Result<isize, ForkExecError> {
    let zero = ProcAttr::default();
    let attr = attr.unwrap_or(&zero);
    let zero_sys = SysProcAttr::default();
    let sys = attr.sys.as_ref().unwrap_or(&zero_sys);

    let path = nul_free(argv0)?;
    let argv: Vec<Vec<u8>> = argv.iter().map(|s| nul_free(s)).collect::<Result<_, _>>()?;
    let env: Vec<Vec<u8>> = attr.env.iter().map(|s| nul_free(s)).collect::<Result<_, _>>()?;
    let chroot = if sys.chroot.is_empty() { None } else { Some(nul_free(&sys.chroot)?) };
    let dir = if attr.dir.is_empty() { None } else { Some(nul_free(&attr.dir)?) };

    // Both Setctty and Foreground use Ctty, with different meanings.
    if sys.setctty && sys.foreground {
        return Err(ForkExecError::Message(
            "both Setctty and Foreground set in SysProcAttr",
        ));
    }
    if sys.setctty && (sys.ctty < 0 || sys.ctty as usize >= attr.files.len()) {
        return Err(ForkExecError::Message(
            "Setctty set but Ctty not valid in child",
        ));
    }

    let fds: Vec<i32> = attr
        .files
        .iter()
        .map(|&f| if (f as isize) < 0 { -1 } else { f as i32 })
        .collect();
    let cred = sys.credential.as_ref().map(|c| spawn::Cred {
        uid: c.uid,
        gid: c.gid,
        groups: &c.groups,
        no_set_groups: c.no_set_groups,
    });
    let extra = spawn::Extra {
        chroot: chroot.as_deref(),
        setsid: sys.setsid,
        setpgid: sys.setpgid || sys.foreground,
        pgid: sys.pgid as i32,
        foreground: sys.foreground,
        setctty: sys.setctty,
        noctty: sys.noctty,
        ctty: sys.ctty as i32,
        cred,
        pdeathsig: sys.pdeathsig.0 as i32,
        ptrace: sys.ptrace,
        cloneflags: sys.cloneflags as u64,
        unshareflags: sys.unshareflags as u64,
        uid_map: (!sys.uid_mappings.is_empty()).then(|| format_id_mappings(&sys.uid_mappings)),
        gid_map: (!sys.gid_mappings.is_empty()).then(|| format_id_mappings(&sys.gid_mappings)),
        gid_setgroups_allow: sys.gid_mappings_enable_setgroups,
        ambient_caps: &sys.ambient_caps,
        cgroup_fd: sys.use_cgroup_fd.then_some(sys.cgroup_fd as i32),
    };
    let spec = spawn::Spec {
        path: &path,
        argv: &argv,
        envp: &env,
        dir: dir.as_deref(),
        fds: &fds,
        extra,
    };
    match spawn::fork_exec(&spec) {
        Ok(started) => {
            if let Some(cell) = &sys.pid_fd {
                let fd = started.pidfd.map_or(-1, |f| f.into_raw_fd() as isize);
                cell.store(fd, Ordering::SeqCst);
            }
            Ok(started.pid as isize)
        }
        Err(e) => {
            if let Some(cell) = &sys.pid_fd {
                cell.store(-1, Ordering::SeqCst);
            }
            Err(Errno::from(e).into())
        }
    }
}

/// `syscall.ForkExec`: runs the program `argv0` (a path, no `PATH` search)
/// in a new process, with the descriptors, directory, environment and
/// attributes of `attr`. Returns the child's pid.
pub fn fork_exec(
    argv0: &str,
    argv: &[String],
    attr: Option<&ProcAttr>,
) -> Result<isize, ForkExecError> {
    fork_exec_inner(argv0, argv, attr)
}

/// `syscall.StartProcess`: `ForkExec` for package os; the handle is always 0.
pub fn start_process(
    argv0: &str,
    argv: &[String],
    attr: Option<&ProcAttr>,
) -> Result<(isize, usize), ForkExecError> {
    fork_exec_inner(argv0, argv, attr).map(|pid| (pid, 0))
}

/// `syscall.Exec`: replaces the current process with `argv0`. It returns
/// only on failure, with the error.
pub fn exec(argv0: &str, argv: &[String], envv: &[String]) -> Result<(), Errno> {
    let path = nul_free(argv0)?;
    let argv: Vec<Vec<u8>> = argv.iter().map(|s| nul_free(s)).collect::<Result<_, _>>()?;
    let env: Vec<Vec<u8>> = envv.iter().map(|s| nul_free(s)).collect::<Result<_, _>>()?;
    Err(Errno::from(spawn::exec(&path, &argv, &env)))
}
