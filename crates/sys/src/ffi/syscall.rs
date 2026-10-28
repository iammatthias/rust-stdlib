//! The raw system-call layer behind `rust_stdlib_sys::syscall`.
//!
//! On linux/x86_64 a call is the C library's `syscall(2)` wrapper with Go's
//! linux/amd64 numbers. On every other target the Linux numbers mean nothing,
//! so [`sc`] serves the small portable subset that has the same argument shape
//! in the host's C library (reporting failures with Linux errno numbers) and
//! fails everything else with `ENOSYS`.
use crate::syscall::consts::*;
use crate::syscall::errno::{self, Errno};
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
use std::ffi::c_void;
use std::os::raw::c_int;

mod c {
    use super::*;

    extern "C" {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        pub fn syscall(num: std::os::raw::c_long, ...) -> std::os::raw::c_long;
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        pub fn setuid(uid: u32) -> c_int;
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        pub fn setgid(gid: u32) -> c_int;
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        pub fn setreuid(ruid: u32, euid: u32) -> c_int;
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        pub fn setregid(rgid: u32, egid: u32) -> c_int;
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        pub fn setresuid(ruid: u32, euid: u32, suid: u32) -> c_int;
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        pub fn setresgid(rgid: u32, egid: u32, sgid: u32) -> c_int;
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        pub fn setgroups(n: usize, list: *const u32) -> c_int;

        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        pub fn getpid() -> c_int;
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        pub fn getppid() -> c_int;
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        pub fn getuid() -> u32;
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        pub fn geteuid() -> u32;
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        pub fn getgid() -> u32;
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        pub fn getegid() -> u32;
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        pub fn umask(mask: u32) -> u32;
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        pub fn read(fd: c_int, buf: *mut c_void, len: usize) -> isize;
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        pub fn write(fd: c_int, buf: *const c_void, len: usize) -> isize;
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        pub fn close(fd: c_int) -> c_int;
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        pub fn dup(fd: c_int) -> c_int;
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        pub fn dup2(old: c_int, new: c_int) -> c_int;
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        pub fn fsync(fd: c_int) -> c_int;
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        pub fn ftruncate(fd: c_int, len: i64) -> c_int;
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        pub fn fchmod(fd: c_int, mode: u32) -> c_int;
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        pub fn fchown(fd: c_int, uid: u32, gid: u32) -> c_int;
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        pub fn fchdir(fd: c_int) -> c_int;
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        pub fn getpgid(pid: c_int) -> c_int;
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        pub fn setpgid(pid: c_int, pgid: c_int) -> c_int;
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        pub fn setsid() -> c_int;
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        pub fn sync();
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        pub fn wait4(pid: c_int, status: *mut c_int, options: c_int, rusage: *mut u8) -> c_int;
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        pub fn getpagesize() -> c_int;
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        pub fn pipe(fds: *mut c_int) -> c_int;
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        pub fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    }
}

// Flag values that differ between Linux (the numbers callers pass) and the host.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
const LINUX_O_NONBLOCK: usize = 0o4000;
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
const LINUX_O_APPEND: usize = 0o2000;
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
const LINUX_O_CLOEXEC: usize = 0o2000000;
#[cfg(target_os = "macos")]
const HOST_O_NONBLOCK: c_int = 0x4;
#[cfg(target_os = "macos")]
const HOST_O_APPEND: c_int = 0x8;
#[cfg(target_os = "macos")]
const HOST_F_DUPFD_CLOEXEC: c_int = 67;
#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
const HOST_O_NONBLOCK: c_int = 0o4000;
#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
const HOST_O_APPEND: c_int = 0o2000;
#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
const HOST_F_DUPFD_CLOEXEC: c_int = 1030;

fn host_errno() -> usize {
    errno::from_host(std::io::Error::last_os_error().raw_os_error().unwrap_or(0)).0
}

/// The raw call: `(result, errno)` with a Linux errno number, 0 on success.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn raw(trap: usize, a: [usize; 6]) -> (usize, usize) {
    // SAFETY: syscall(2) takes the number and six machine words. The callers
    // in this crate build every pointer argument from a live reference or
    // slice that outlives the call, and the public entry points that accept
    // arbitrary words are themselves unsafe.
    let r = unsafe {
        c::syscall(
            trap as std::os::raw::c_long,
            a[0] as std::os::raw::c_long,
            a[1] as std::os::raw::c_long,
            a[2] as std::os::raw::c_long,
            a[3] as std::os::raw::c_long,
            a[4] as std::os::raw::c_long,
            a[5] as std::os::raw::c_long,
        )
    };
    if r == -1 {
        (usize::MAX, host_errno())
    } else {
        (r as usize, 0)
    }
}

/// Maps a C-library result of -1 to the Linux errno, else `Ok(value)`.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn lift(r: isize) -> (usize, usize) {
    if r < 0 {
        (usize::MAX, host_errno())
    } else {
        (r as usize, 0)
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn raw(trap: usize, a: [usize; 6]) -> (usize, usize) {
    // SAFETY: (every arm) each C function is called with the argument shape the
    // Linux system call has, taken from the caller's words. Pointer words come
    // from live references or slices in this crate, and the public entry
    // points that accept arbitrary words are themselves unsafe.
    unsafe {
        match trap {
            SYS_GETPID => (c::getpid() as usize, 0),
            SYS_GETPPID => (c::getppid() as usize, 0),
            SYS_GETUID => (c::getuid() as usize, 0),
            SYS_GETEUID => (c::geteuid() as usize, 0),
            SYS_GETGID => (c::getgid() as usize, 0),
            SYS_GETEGID => (c::getegid() as usize, 0),
            SYS_UMASK => (c::umask(a[0] as u32) as usize, 0),
            SYS_READ => lift(c::read(a[0] as c_int, a[1] as *mut c_void, a[2])),
            SYS_WRITE => lift(c::write(a[0] as c_int, a[1] as *const c_void, a[2])),
            SYS_CLOSE => lift(c::close(a[0] as c_int) as isize),
            SYS_DUP => lift(c::dup(a[0] as c_int) as isize),
            SYS_DUP2 => lift(c::dup2(a[0] as c_int, a[1] as c_int) as isize),
            SYS_FSYNC | SYS_FDATASYNC => lift(c::fsync(a[0] as c_int) as isize),
            SYS_FTRUNCATE => lift(c::ftruncate(a[0] as c_int, a[1] as i64) as isize),
            SYS_FCHMOD => lift(c::fchmod(a[0] as c_int, a[1] as u32) as isize),
            SYS_FCHOWN => lift(c::fchown(a[0] as c_int, a[1] as u32, a[2] as u32) as isize),
            SYS_FCHDIR => lift(c::fchdir(a[0] as c_int) as isize),
            SYS_GETPGID => lift(c::getpgid(a[0] as c_int) as isize),
            SYS_SETPGID => lift(c::setpgid(a[0] as c_int, a[1] as c_int) as isize),
            SYS_SETSID => lift(c::setsid() as isize),
            SYS_SYNC => {
                c::sync();
                (0, 0)
            }
            SYS_PIPE2 => {
                let fds = a[0] as *mut c_int;
                let r = lift(c::pipe(fds) as isize);
                if r.1 == 0 {
                    for i in 0..2 {
                        let fd = *fds.add(i);
                        if a[1] & LINUX_O_CLOEXEC != 0 {
                            c::fcntl(fd, 2, 1 as c_int);
                        }
                        if a[1] & LINUX_O_NONBLOCK != 0 {
                            let fl = c::fcntl(fd, 3);
                            c::fcntl(fd, 4, fl | HOST_O_NONBLOCK);
                        }
                    }
                }
                r
            }
            SYS_FCNTL => match a[1] {
                // F_DUPFD, F_GETFD, F_SETFD: the same numbers and meaning.
                0..=2 => lift(c::fcntl(a[0] as c_int, a[1] as c_int, a[2] as c_int) as isize),
                // F_DUPFD_CLOEXEC
                1030 => lift(c::fcntl(a[0] as c_int, HOST_F_DUPFD_CLOEXEC, a[2] as c_int) as isize),
                // F_GETFL, F_SETFL: translate the flags that differ.
                3 => {
                    let r = lift(c::fcntl(a[0] as c_int, 3) as isize);
                    if r.1 != 0 {
                        r
                    } else {
                        let host = r.0 as c_int;
                        let mut linux = host & 3;
                        if host & HOST_O_NONBLOCK != 0 {
                            linux |= LINUX_O_NONBLOCK as c_int;
                        }
                        if host & HOST_O_APPEND != 0 {
                            linux |= LINUX_O_APPEND as c_int;
                        }
                        (linux as usize, 0)
                    }
                }
                4 => {
                    let linux = a[2];
                    let mut host = (linux & 3) as c_int;
                    if linux & LINUX_O_NONBLOCK != 0 {
                        host |= HOST_O_NONBLOCK;
                    }
                    if linux & LINUX_O_APPEND != 0 {
                        host |= HOST_O_APPEND;
                    }
                    lift(c::fcntl(a[0] as c_int, 4, host) as isize)
                }
                _ => (usize::MAX, EINVAL.0),
            },
            SYS_WAIT4 => {
                // The host's rusage layout is not Go's: ask for none.
                let mut status: c_int = 0;
                let r = lift(c::wait4(a[0] as c_int, &mut status, a[2] as c_int, std::ptr::null_mut()) as isize);
                if r.1 == 0 && a[1] != 0 {
                    *(a[1] as *mut c_int) = errno::wait_status_from_host(status);
                }
                r
            }
            _ => (usize::MAX, ENOSYS.0),
        }
    }
}

/// A system call: the result, or the Linux errno.
pub fn sc(trap: usize, args: [usize; 6]) -> Result<usize, Errno> {
    match raw(trap, args) {
        (r, 0) => Ok(r),
        (_, e) => Err(Errno(e)),
    }
}

/// A system call that cannot fail (`rawSyscallNoError`).
pub fn sc_no_error(trap: usize, args: [usize; 6]) -> usize {
    raw(trap, args).0
}

/// `syscall.Syscall`: a system call with three arguments.
///
/// Returns the result, the second result register (always 0 here) and the
/// error; on failure the result is all ones, as in Go.
///
/// # Safety
/// The arguments are passed to the kernel unchecked; pointer arguments must
/// be valid for what the call does with them.
pub unsafe fn syscall(trap: usize, a1: usize, a2: usize, a3: usize) -> (usize, usize, Errno) {
    let (r, e) = raw(trap, [a1, a2, a3, 0, 0, 0]);
    (r, 0, Errno(e))
}

/// `syscall.Syscall6`: a system call with six arguments.
///
/// # Safety
/// As [`syscall`].
#[allow(clippy::too_many_arguments)]
pub unsafe fn syscall6(
    trap: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> (usize, usize, Errno) {
    let (r, e) = raw(trap, [a1, a2, a3, a4, a5, a6]);
    (r, 0, Errno(e))
}

/// `syscall.RawSyscall`: as [`syscall`]; there is no scheduler to bypass.
///
/// # Safety
/// As [`syscall`].
pub unsafe fn raw_syscall(trap: usize, a1: usize, a2: usize, a3: usize) -> (usize, usize, Errno) {
    syscall(trap, a1, a2, a3)
}

/// `syscall.RawSyscall6`: as [`syscall6`].
///
/// # Safety
/// As [`syscall`].
#[allow(clippy::too_many_arguments)]
pub unsafe fn raw_syscall6(
    trap: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> (usize, usize, Errno) {
    syscall6(trap, a1, a2, a3, a4, a5, a6)
}

/// `syscall.AllThreadsSyscall`: the identity setters go through the C
/// library, which synchronises every thread; other calls run on this thread.
///
/// # Safety
/// As [`syscall`].
pub unsafe fn all_threads_syscall(
    trap: usize,
    a1: usize,
    a2: usize,
    a3: usize,
) -> (usize, usize, Errno) {
    all_threads_syscall6(trap, a1, a2, a3, 0, 0, 0)
}

/// `syscall.AllThreadsSyscall6`.
///
/// # Safety
/// As [`syscall`].
#[allow(clippy::too_many_arguments)]
pub unsafe fn all_threads_syscall6(
    trap: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> (usize, usize, Errno) {
    match sc_all_threads(trap, [a1, a2, a3, a4, a5, a6]) {
        Ok(r) => (r, 0, Errno(0)),
        Err(e) => (usize::MAX, 0, e),
    }
}

/// A system call that changes process-wide state on every thread: the
/// user and group identity setters go through the C library, which
/// synchronises all threads; anything else runs on the calling thread.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn sc_all_threads(trap: usize, a: [usize; 6]) -> Result<usize, Errno> {
    // SAFETY: each C function takes plain integers (setgroups also a pointer
    // that callers build from a live slice of `a[0]` group ids).
    let r = unsafe {
        match trap {
            SYS_SETUID => c::setuid(a[0] as u32),
            SYS_SETGID => c::setgid(a[0] as u32),
            SYS_SETREUID => c::setreuid(a[0] as u32, a[1] as u32),
            SYS_SETREGID => c::setregid(a[0] as u32, a[1] as u32),
            SYS_SETRESUID => c::setresuid(a[0] as u32, a[1] as u32, a[2] as u32),
            SYS_SETRESGID => c::setresgid(a[0] as u32, a[1] as u32, a[2] as u32),
            SYS_SETGROUPS => c::setgroups(a[0], a[1] as *const u32),
            _ => return sc(trap, a),
        }
    };
    if r < 0 {
        Err(Errno(host_errno()))
    } else {
        Ok(r as usize)
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub fn sc_all_threads(trap: usize, a: [usize; 6]) -> Result<usize, Errno> {
    sc(trap, a)
}

/// The size of a memory page.
pub fn page_size() -> usize {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        4096
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        // SAFETY: getpagesize takes no arguments and cannot fail.
        unsafe { c::getpagesize() as usize }
    }
}

/// The memory a successful `mmap` of `len` bytes at `addr` returned.
///
/// The caller must pass the address and length of a live mapping it owns.
pub(crate) fn mapped_slice(addr: usize, len: usize) -> &'static mut [u8] {
    if len == 0 {
        return &mut [];
    }
    // SAFETY: `addr` came from a successful mmap of exactly `len` bytes that
    // stays mapped until the caller unmaps it, and nothing else aliases it.
    unsafe { std::slice::from_raw_parts_mut(addr as *mut u8, len) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_entry_points() {
        // SAFETY: SYS_GETPID takes no arguments and touches no memory.
        let (r, r2, e) = unsafe { syscall(SYS_GETPID, 0, 0, 0) };
        assert_eq!((e, r2), (Errno(0), 0));
        assert_eq!(r as u32, std::process::id());
        // SAFETY: as above.
        let (r, _, e) = unsafe { raw_syscall6(SYS_GETPID, 0, 0, 0, 0, 0, 0) };
        assert!(e.0 == 0 && r as u32 == std::process::id());
        // SAFETY: closing a descriptor number that is not open.
        let (r, _, e) = unsafe { raw_syscall(SYS_CLOSE, 1 << 20, 0, 0) };
        assert_eq!((r, e), (usize::MAX, EBADF));
        // SAFETY: an unknown system call number touches no memory.
        let (_, _, e) = unsafe { syscall6(99_999, 0, 0, 0, 0, 0, 0) };
        assert_eq!(e, ENOSYS);
        // SAFETY: as above.
        let (_, _, e) = unsafe { all_threads_syscall(99_999, 0, 0, 0) };
        assert_eq!(e, ENOSYS);
        // SAFETY: as above.
        let (r, _, e) = unsafe { all_threads_syscall6(SYS_GETPID, 0, 0, 0, 0, 0, 0) };
        assert!(e.0 == 0 && r as u32 == std::process::id());
    }
}
