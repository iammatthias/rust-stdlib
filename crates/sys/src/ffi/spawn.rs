//! Starting and waiting for processes: `fork`, `execve`, `waitpid` and
//! `pidfd_open`, the calls behind `os.StartProcess` and `exec.Cmd`.
//!
//! Go starts a process with `fork` and a raw `execve` in the child (no
//! `PATH` search and no shell fallback for a file without a shebang), and
//! reports a failure in the child through a close-on-exec pipe. This module
//! does the same: everything the child needs is prepared before the fork, and
//! the child only calls `dup2`, `fcntl`, `chdir`, `signal`, `execve`, `write`
//! and `_exit`.
use super::proc::cstring;
use crate::errno::{Errno, EINTR, EINVAL};
use std::ffi::CString;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::raw::{c_char, c_int, c_void};

mod c {
    use super::*;

    extern "C" {
        pub fn fork() -> c_int;
        pub fn execve(
            path: *const c_char,
            argv: *const *const c_char,
            envp: *const *const c_char,
        ) -> c_int;
        pub fn _exit(status: c_int) -> !;
        pub fn dup2(old: c_int, new: c_int) -> c_int;
        pub fn close(fd: c_int) -> c_int;
        pub fn chdir(path: *const c_char) -> c_int;
        pub fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
        pub fn pipe(fds: *mut c_int) -> c_int;
        pub fn read(fd: c_int, buf: *mut c_void, len: usize) -> isize;
        pub fn write(fd: c_int, buf: *const c_void, len: usize) -> isize;
        pub fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
        pub fn signal(sig: c_int, handler: usize) -> usize;
        pub fn setsid() -> c_int;
        pub fn setpgid(pid: c_int, pgid: c_int) -> c_int;
        pub fn chroot(path: *const c_char) -> c_int;
        pub fn ioctl(fd: c_int, request: u64, ...) -> c_int;
        pub fn getpid() -> c_int;
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        pub fn getppid() -> c_int;
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        pub fn kill(pid: c_int, sig: c_int) -> c_int;
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        pub fn open(path: *const c_char, flags: c_int, ...) -> c_int;
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        pub fn setgroups(n: usize, list: *const u32) -> c_int;
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        pub fn setgid(gid: u32) -> c_int;
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        pub fn setuid(uid: u32) -> c_int;
        #[cfg(target_os = "linux")]
        pub fn syscall(num: i64, ...) -> i64;
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        pub fn unshare(flags: c_int) -> c_int;
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        pub fn mount(
            source: *const c_char,
            target: *const c_char,
            fstype: *const c_char,
            flags: u64,
            data: *const c_void,
        ) -> c_int;
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        pub fn prctl(option: c_int, ...) -> c_int;
    }
}

const F_SETFD: c_int = 2;
const F_DUPFD_CLOEXEC: c_int = if cfg!(target_os = "macos") { 67 } else { 1030 };
const SIGPIPE: c_int = 13;
const SIG_DFL: usize = 0;

/// What to run and how to wire its descriptors.
pub struct Spec<'a> {
    pub path: &'a [u8],
    pub argv: &'a [Vec<u8>],
    pub envp: &'a [Vec<u8>],
    pub dir: Option<&'a [u8]>,
    /// `fds[i]` is the parent descriptor to install as the child's descriptor
    /// `i`, or -1 to close it in the child.
    pub fds: &'a [RawFd],
    /// What `syscall.SysProcAttr` adds; `Extra::default()` for none.
    pub extra: Extra<'a>,
}

/// `syscall.Credential`.
#[derive(Clone, Copy, Default)]
pub struct Cred<'a> {
    pub uid: u32,
    pub gid: u32,
    pub groups: &'a [u32],
    pub no_set_groups: bool,
}

/// The `syscall.SysProcAttr` fields of a new process, applied in the order of
/// Go's `forkAndExecInChild`. The clone, unshare, id-map, capability and
/// cgroup fields work on linux/x86_64 only (they need its system call numbers).
#[derive(Clone, Default)]
pub struct Extra<'a> {
    pub chroot: Option<&'a [u8]>,
    pub setsid: bool,
    /// `Setpgid` (or `Foreground`, which implies it) with the group `pgid`.
    pub setpgid: bool,
    pub pgid: i32,
    /// Put the group in the foreground of the terminal `ctty` (a parent descriptor).
    pub foreground: bool,
    /// Make the child's descriptor `ctty` its controlling terminal.
    pub setctty: bool,
    pub noctty: bool,
    pub ctty: i32,
    pub cred: Option<Cred<'a>>,
    pub pdeathsig: i32,
    pub ptrace: bool,
    pub cloneflags: u64,
    pub unshareflags: u64,
    /// The formatted contents of `/proc/<pid>/uid_map` and `gid_map`.
    pub uid_map: Option<Vec<u8>>,
    pub gid_map: Option<Vec<u8>>,
    pub gid_setgroups_allow: bool,
    pub ambient_caps: &'a [usize],
    pub cgroup_fd: Option<i32>,
}

/// A started child: its pid and, where the kernel has them, a pidfd.
pub struct Started {
    pub pid: i32,
    pub pidfd: Option<OwnedFd>,
}

fn cvec(items: &[Vec<u8>]) -> Result<Vec<CString>, Errno> {
    items.iter().map(|i| cstring(i)).collect()
}

fn ptrs(items: &[CString]) -> Vec<*const c_char> {
    let mut v: Vec<*const c_char> = items.iter().map(|c| c.as_ptr()).collect();
    v.push(std::ptr::null());
    v
}

/// Reports `err` to the parent through `errpipe` and exits the child.
///
/// # Safety
/// Only for use in a forked child; calls only async-signal-safe functions.
unsafe fn child_fail(errpipe: c_int, err: Errno) -> ! {
    let bytes = err.0.to_ne_bytes();
    // SAFETY: `bytes` is readable for four bytes; a failed write is ignored
    // because the child exits either way.
    unsafe {
        c::write(errpipe, bytes.as_ptr().cast(), bytes.len());
        c::_exit(253)
    }
}

/// `fork` + `execve`. Fails with the child's `errno` if the program could not
/// be started (`ENOENT`, `EACCES`, `ENOEXEC` for a file without a shebang, a
/// bad working directory, ...).
pub fn fork_exec(spec: &Spec<'_>) -> Result<Started, Errno> {
    let path = cstring(spec.path)?;
    let argv_c = cvec(spec.argv)?;
    let envp_c = cvec(spec.envp)?;
    let dir = match spec.dir {
        Some(d) => Some(cstring(d)?),
        None => None,
    };
    let argv = ptrs(&argv_c);
    let envp = ptrs(&envp_c);
    let chroot = match spec.extra.chroot {
        Some(r) => Some(cstring(r)?),
        None => None,
    };
    let ex = &spec.extra;
    let linux_only = ex.cloneflags != 0
        || ex.unshareflags != 0
        || ex.uid_map.is_some()
        || ex.gid_map.is_some()
        || !ex.ambient_caps.is_empty()
        || ex.cgroup_fd.is_some()
        || ex.pdeathsig != 0
        || ex.ptrace;
    if linux_only && !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return Err(crate::errno::ENOSYS);
    }
    // Descriptors the child must keep out of the way of its dup2 targets.
    let mut min_free = spec.fds.len() as c_int;
    for &fd in spec.fds {
        min_free = min_free.max(fd + 1);
    }
    // No other thread may hold a descriptor that is not yet close-on-exec
    // while we fork (Go's ForkLock).
    let fork_guard = super::FORK_LOCK.write().unwrap_or_else(|e| e.into_inner());
    let mut pipefds = [0 as c_int; 2];
    // SAFETY: `pipefds` has room for the two descriptors pipe writes.
    if unsafe { c::pipe(pipefds.as_mut_ptr()) } < 0 {
        return Err(Errno::last());
    }
    // SAFETY: both descriptors were just created by pipe and are ours.
    let (rd, wr) = unsafe { (OwnedFd::from_raw_fd(pipefds[0]), OwnedFd::from_raw_fd(pipefds[1])) };
    let (rdraw, wrraw) = (raw(&rd), raw(&wr));
    // The read end must not reach the program being started.
    super::set_cloexec(rdraw)?;
    // Move the error pipe above every target and source, close-on-exec.
    // SAFETY: F_DUPFD_CLOEXEC takes two integers and returns a new descriptor.
    let ep = unsafe { c::fcntl(wrraw, F_DUPFD_CLOEXEC, min_free) };
    if ep < 0 {
        return Err(Errno::last());
    }
    // SAFETY: `ep` was just returned by fcntl and is ours.
    let ep_owned = unsafe { OwnedFd::from_raw_fd(ep) };
    drop(wr);
    let errpipe = raw(&ep_owned);
    // Sources below their target index would be clobbered by earlier dup2s:
    // move them out of the way first (in the parent: they are close-on-exec
    // duplicates that vanish at exec, and the parent closes them below).
    let mut fds: Vec<RawFd> = spec.fds.to_vec();
    let mut temps: Vec<OwnedFd> = Vec::new();
    let mut next_min = min_free.max(errpipe + 1);
    for (i, slot) in fds.iter_mut().enumerate() {
        if *slot >= 0 && (*slot as usize) < i {
            // SAFETY: as above.
            let d = unsafe { c::fcntl(*slot, F_DUPFD_CLOEXEC, next_min) };
            if d < 0 {
                return Err(Errno::last());
            }
            next_min = d + 1;
            *slot = d;
            // SAFETY: `d` was just returned by fcntl and is ours.
            temps.push(unsafe { OwnedFd::from_raw_fd(d) });
        }
    }

    let parent_pid = if ex.pdeathsig != 0 {
        // SAFETY: getpid takes no arguments and cannot fail.
        unsafe { c::getpid() }
    } else {
        0
    };
    // A pipe on which the parent releases the child once the id maps are
    // written (Go's mapPipe); close-on-exec so the program does not keep it.
    let wants_maps = ex.uid_map.is_some() || ex.gid_map.is_some();
    let mut map_fds = [-1 as c_int; 2];
    if wants_maps {
        // SAFETY: `map_fds` has room for the two descriptors pipe writes.
        if unsafe { c::pipe(map_fds.as_mut_ptr()) } < 0 {
            return Err(Errno::last());
        }
        for fd in map_fds {
            super::set_cloexec(fd)?;
        }
    }
    // SAFETY: the clone call and the fork have no preconditions; the child
    // below only calls async-signal-safe functions on data prepared before.
    let pid = unsafe { start_child(ex) };
    if pid < 0 {
        let e = Errno::last();
        close_both(map_fds);
        return Err(e);
    }
    if pid == 0 {
        // SAFETY: we are the forked child; every pointer comes from a live
        // CString or Vec of the parent's copy of memory, and only
        // async-signal-safe functions are called.
        unsafe {
            run_child(&Child {
                spec,
                fds: &fds,
                path: &path,
                argv: &argv,
                envp: &envp,
                dir: dir.as_ref(),
                errpipe,
                map_fds,
                parent_pid,
                chroot: chroot.as_ref(),
            })
        }
    }

    drop(fork_guard);
    // Parent: the child's write end must not stay open here, or the read
    // below would never see end of file after a successful exec.
    drop(ep_owned);
    drop(temps);
    if wants_maps {
        // Tell the child whether its id maps were written (an errno, or 0).
        let result = if ex.unshareflags & CLONE_NEWUSER != 0 {
            Ok(())
        } else {
            write_id_maps(pid, ex)
        };
        let code = result.err().map_or(0, |e| e.0).to_ne_bytes();
        // SAFETY: `code` is readable for four bytes and the descriptors are
        // the pipe created above, still open in the parent.
        unsafe {
            c::close(map_fds[0]);
            c::write(map_fds[1], code.as_ptr().cast(), code.len());
            c::close(map_fds[1]);
        }
    }
    let mut buf = [0u8; 4];
    let mut got = 0usize;
    loop {
        // SAFETY: `buf[got..]` is writable for the length passed.
        let n = unsafe { c::read(rdraw, buf[got..].as_mut_ptr().cast(), buf.len() - got) };
        if n < 0 {
            let e = Errno::last();
            if e == EINTR {
                continue;
            }
            let _ = wait(pid);
            return Err(e);
        }
        if n == 0 {
            break;
        }
        got += n as usize;
        if got == buf.len() {
            break;
        }
    }
    if got == buf.len() {
        let _ = wait(pid);
        return Err(Errno(i32::from_ne_bytes(buf)));
    }
    if got != 0 {
        let _ = wait(pid);
        return Err(EINVAL);
    }
    Ok(Started {
        pid,
        pidfd: pidfd_open(pid),
    })
}

fn raw(fd: &OwnedFd) -> RawFd {
    std::os::fd::AsRawFd::as_raw_fd(fd)
}

/// `execve`: replaces the process image. Returns only on failure, with the
/// error.
pub fn exec(path: &[u8], argv: &[Vec<u8>], envp: &[Vec<u8>]) -> Errno {
    let path = match cstring(path) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let (argv_c, envp_c) = match (cvec(argv), cvec(envp)) {
        (Ok(a), Ok(e)) => (a, e),
        (Err(e), _) | (_, Err(e)) => return e,
    };
    let argv = ptrs(&argv_c);
    let envp = ptrs(&envp_c);
    // SAFETY: `path`, `argv` and `envp` are NUL-terminated strings and
    // null-terminated pointer arrays that outlive the call.
    unsafe { c::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    Errno::last()
}

/// `waitpid(pid, &status, 0)`: the raw wait status.
pub fn wait(pid: i32) -> Result<i32, Errno> {
    loop {
        let mut status: c_int = 0;
        // SAFETY: `status` is writable for one int.
        let r = unsafe { c::waitpid(pid, &mut status, 0) };
        if r >= 0 {
            return Ok(status);
        }
        let e = Errno::last();
        if e != EINTR {
            return Err(e);
        }
    }
}

/// A pidfd for `pid` (Linux 5.3 and later), or `None` where the platform has
/// none.
#[cfg(target_os = "linux")]
pub fn pidfd_open(pid: i32) -> Option<OwnedFd> {
    // SAFETY: pidfd_open (syscall 434) takes a pid and flags, touches no
    // memory, and returns a new descriptor or -1.
    let fd = unsafe { c::syscall(434, i64::from(pid), 0i64) };
    if fd < 0 {
        return None;
    }
    // SAFETY: `fd` is a new descriptor owned by nobody else.
    Some(unsafe { OwnedFd::from_raw_fd(fd as c_int) })
}

#[cfg(not(target_os = "linux"))]
pub fn pidfd_open(_pid: i32) -> Option<OwnedFd> {
    None
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const CLONE_NEWNS: u64 = 0x0002_0000;
const CLONE_NEWUSER: u64 = 0x1000_0000;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const CLONE_NEWTIME: u64 = 0x80;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SIGCHLD: u64 = 17;

#[cfg(target_os = "linux")]
mod tty {
    pub const TIOCSPGRP: u64 = 0x5410;
    pub const TIOCNOTTY: u64 = 0x5422;
    pub const TIOCSCTTY: u64 = 0x540E;
}
#[cfg(target_os = "macos")]
mod tty {
    pub const TIOCSPGRP: u64 = 0x8004_7476;
    pub const TIOCNOTTY: u64 = 0x2000_7471;
    pub const TIOCSCTTY: u64 = 0x2000_7461;
}

/// Everything the child needs, prepared before the fork.
struct Child<'a> {
    spec: &'a Spec<'a>,
    fds: &'a [RawFd],
    path: &'a CString,
    argv: &'a [*const c_char],
    envp: &'a [*const c_char],
    dir: Option<&'a CString>,
    chroot: Option<&'a CString>,
    errpipe: c_int,
    map_fds: [c_int; 2],
    parent_pid: c_int,
}

fn close_both(fds: [c_int; 2]) {
    for fd in fds {
        if fd >= 0 {
            // SAFETY: closing a descriptor this function's caller created.
            unsafe { c::close(fd) };
        }
    }
}

/// `fork`, or the raw `clone`/`clone3` call when namespaces or a cgroup are
/// requested (linux/x86_64). Returns the child's pid in the parent, 0 in the
/// child, -1 on failure.
///
/// # Safety
/// As `fork`: the child may only call async-signal-safe functions.
unsafe fn start_child(ex: &Extra<'_>) -> c_int {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        use crate::syscall::consts::{SYS_CLONE, _SYS_CLONE3};
        if ex.cloneflags != 0 || ex.cgroup_fd.is_some() {
            if ex.cgroup_fd.is_some() || ex.cloneflags & CLONE_NEWTIME != 0 {
                // struct clone_args: flags, pidfd, child_tid, parent_tid,
                // exit_signal, stack, stack_size, tls, set_tid, set_tid_size, cgroup.
                let mut args = [0u64; 11];
                args[0] = ex.cloneflags;
                args[4] = SIGCHLD;
                if let Some(fd) = ex.cgroup_fd {
                    args[0] |= CLONE_INTO_CGROUP;
                    args[10] = fd as u64;
                }
                return c::syscall(_SYS_CLONE3 as i64, args.as_ptr(), std::mem::size_of_val(&args))
                    as c_int;
            }
            return c::syscall(SYS_CLONE as i64, ex.cloneflags | SIGCHLD, 0usize, 0usize, 0usize, 0usize)
                as c_int;
        }
    }
    let _ = ex;
    c::fork()
}

/// Writes `data` to the file at `path` (the id-map and setgroups files).
///
/// # Safety
/// `path` must be NUL-terminated; async-signal-safe.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe fn write_path(path: *const c_char, data: &[u8]) -> c_int {
    const O_WRONLY: c_int = 1;
    let fd = c::open(path, O_WRONLY);
    if fd < 0 {
        return -1;
    }
    let n = c::write(fd, data.as_ptr().cast(), data.len());
    c::close(fd);
    if n < 0 {
        -1
    } else {
        0
    }
}

/// The group and user identity of a child, with raw system calls on
/// linux/x86_64 (the C library's setters would try to signal sibling threads
/// that do not exist in a `clone`d child).
///
/// # Safety
/// Only for the forked child.
unsafe fn set_ids(cred: &Cred<'_>, set_groups: bool) -> c_int {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        use crate::syscall::consts::{SYS_SETGID, SYS_SETGROUPS, SYS_SETUID};
        if set_groups
            && c::syscall(SYS_SETGROUPS as i64, cred.groups.len(), cred.groups.as_ptr()) < 0
        {
            return -1;
        }
        if c::syscall(SYS_SETGID as i64, cred.gid as usize) < 0 {
            return -1;
        }
        if c::syscall(SYS_SETUID as i64, cred.uid as usize) < 0 {
            return -1;
        }
        0
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        if set_groups && c::setgroups(cred.groups.len(), cred.groups.as_ptr()) < 0 {
            return -1;
        }
        if c::setgid(cred.gid) < 0 || c::setuid(cred.uid) < 0 {
            return -1;
        }
        0
    }
}

/// The child's side of `forkAndExecInChild`: applies the attributes in Go's
/// order, then `execve`; any failure is reported on the error pipe.
///
/// # Safety
/// Only for the forked child; calls only async-signal-safe functions.
unsafe fn run_child(ch: &Child<'_>) -> ! {
    let ex = &ch.spec.extra;
    let ep = ch.errpipe;
    macro_rules! check {
        ($e:expr) => {
            if $e < 0 {
                child_fail(ep, Errno::last());
            }
        };
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        const PR_SET_KEEPCAPS: c_int = 8;
        if !ex.ambient_caps.is_empty() {
            check!(c::prctl(PR_SET_KEEPCAPS, 1usize, 0usize, 0usize, 0usize));
        }
    }
    // Wait for the parent to write the user and group id maps.
    if ch.map_fds[0] >= 0 {
        c::close(ch.map_fds[1]);
        let mut code = [0u8; 4];
        let n = c::read(ch.map_fds[0], code.as_mut_ptr().cast(), code.len());
        if n < 0 {
            child_fail(ep, Errno::last());
        }
        if n != 4 {
            child_fail(ep, EINVAL);
        }
        let e = i32::from_ne_bytes(code);
        if e != 0 {
            child_fail(ep, Errno(e));
        }
    }
    if ex.setsid {
        check!(c::setsid());
    }
    if ex.setpgid || ex.foreground {
        check!(c::setpgid(0, ex.pgid));
    }
    if ex.foreground {
        let mut pgrp: c_int = if ex.pgid == 0 { c::getpid() } else { ex.pgid };
        check!(c::ioctl(ex.ctty, tty::TIOCSPGRP, &mut pgrp as *mut c_int));
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    if ex.unshareflags != 0 {
        check!(c::unshare(ex.unshareflags as c_int));
        if ex.unshareflags & CLONE_NEWUSER != 0 {
            if let Some(gm) = &ex.gid_map {
                let sg: &[u8] = if ex.gid_setgroups_allow { b"allow\0" } else { b"deny\0" };
                check!(write_path(c"/proc/self/setgroups".as_ptr(), sg));
                check!(write_path(c"/proc/self/gid_map".as_ptr(), gm));
            }
            if let Some(um) = &ex.uid_map {
                check!(write_path(c"/proc/self/uid_map".as_ptr(), um));
            }
        }
        // Mark / private so the unshared mount namespace really is separate.
        if ex.unshareflags & CLONE_NEWNS == CLONE_NEWNS {
            const MS_REC: u64 = 0x4000;
            const MS_PRIVATE: u64 = 0x4_0000;
            check!(c::mount(
                c"none".as_ptr(),
                c"/".as_ptr(),
                std::ptr::null(),
                MS_REC | MS_PRIVATE,
                std::ptr::null()
            ));
        }
    }
    if let Some(r) = ch.chroot {
        check!(c::chroot(r.as_ptr()));
    }
    if let Some(cred) = &ex.cred {
        let skip = ex.gid_map.is_some() && !ex.gid_setgroups_allow && cred.groups.is_empty();
        check!(set_ids(cred, !skip && !cred.no_set_groups));
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    if !ex.ambient_caps.is_empty() {
        use crate::syscall::consts::{SYS_CAPGET, SYS_CAPSET};
        const PR_CAP_AMBIENT: c_int = 0x2f;
        const PR_CAP_AMBIENT_RAISE: usize = 2;
        const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
        // capHeader, then two capData words of (effective, permitted, inheritable).
        let mut hdr = [LINUX_CAPABILITY_VERSION_3, 0];
        let mut data = [0u32; 6];
        check!(c::syscall(SYS_CAPGET as i64, hdr.as_mut_ptr(), data.as_mut_ptr()));
        for &cap in ex.ambient_caps {
            let idx = cap >> 5;
            if idx >= 2 {
                child_fail(ep, EINVAL);
            }
            let mask = 1u32 << (cap & 31);
            data[idx * 3 + 1] |= mask;
            data[idx * 3 + 2] |= mask;
        }
        check!(c::syscall(SYS_CAPSET as i64, hdr.as_mut_ptr(), data.as_mut_ptr()));
        for &cap in ex.ambient_caps {
            check!(c::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0usize, 0usize));
        }
    }
    if let Some(d) = ch.dir {
        check!(c::chdir(d.as_ptr()));
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    if ex.pdeathsig != 0 {
        const PR_SET_PDEATHSIG: c_int = 1;
        check!(c::prctl(PR_SET_PDEATHSIG, ex.pdeathsig as usize, 0usize, 0usize, 0usize));
        // Signal ourselves if the parent is already dead.
        if c::getppid() != ch.parent_pid {
            check!(c::kill(c::getpid(), ex.pdeathsig));
        }
    }
    for (i, &src) in ch.fds.iter().enumerate() {
        let i = i as c_int;
        if src < 0 {
            c::close(i);
        } else if src == i {
            // Already in place: keep it across exec.
            check!(c::fcntl(i, F_SETFD, 0 as c_int));
        } else {
            check!(c::dup2(src, i));
        }
    }
    // By convention the standard descriptors the caller did not supply are closed.
    for i in ch.fds.len()..3 {
        c::close(i as c_int);
    }
    if ex.noctty {
        check!(c::ioctl(0, tty::TIOCNOTTY, 0usize));
    }
    if ex.setctty {
        check!(c::ioctl(ex.ctty, tty::TIOCSCTTY, 1usize));
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    if ex.ptrace {
        use crate::syscall::consts::SYS_PTRACE;
        const PTRACE_TRACEME: usize = 0;
        check!(c::syscall(SYS_PTRACE as i64, PTRACE_TRACEME, 0usize, 0usize));
    }
    let _ = ch.parent_pid;
    c::signal(SIGPIPE, SIG_DFL);
    c::execve(ch.path.as_ptr(), ch.argv.as_ptr(), ch.envp.as_ptr());
    child_fail(ep, Errno::last())
}

/// Writes the user and group id maps of the new process `pid`, as Go's
/// `writeUidGidMappings` does from the parent.
fn write_id_maps(pid: i32, ex: &Extra<'_>) -> Result<(), Errno> {
    let put = |name: &str, data: &[u8]| -> Result<(), Errno> {
        std::fs::write(format!("/proc/{pid}/{name}"), data).map_err(Errno::from)
    };
    if let Some(um) = &ex.uid_map {
        put("uid_map", um)?;
    }
    if let Some(gm) = &ex.gid_map {
        // A kernel without /proc/PID/setgroups reports ENOENT; that is fine.
        let sg: &[u8] = if ex.gid_setgroups_allow { b"allow" } else { b"deny" };
        match put("setgroups", sg) {
            Err(e) if e != crate::errno::ENOENT => return Err(e),
            _ => {}
        }
        put("gid_map", gm)?;
    }
    Ok(())
}
