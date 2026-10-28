//! Process, identity and file-time calls: the libc functions behind `os`.
use crate::errno::{Errno, EINVAL};
use std::ffi::CString;
use std::os::raw::{c_char, c_int};

mod c {
    use super::*;

    #[repr(C)]
    pub struct Timespec {
        pub tv_sec: i64,
        pub tv_nsec: i64,
    }

    extern "C" {
        pub fn getuid() -> u32;
        pub fn geteuid() -> u32;
        pub fn getgid() -> u32;
        pub fn getegid() -> u32;
        pub fn getppid() -> c_int;
        pub fn getgroups(size: c_int, list: *mut u32) -> c_int;
        pub fn gethostname(name: *mut c_char, len: usize) -> c_int;
        pub fn kill(pid: c_int, sig: c_int) -> c_int;
        pub fn link(old: *const c_char, new: *const c_char) -> c_int;
        pub fn utimensat(
            dirfd: c_int,
            path: *const c_char,
            times: *const Timespec,
            flags: c_int,
        ) -> c_int;
    }
}

#[cfg(target_os = "macos")]
const AT_FDCWD: c_int = -2;
#[cfg(target_os = "linux")]
const AT_FDCWD: c_int = -100;
#[cfg(target_os = "macos")]
const UTIME_OMIT: i64 = -2;
#[cfg(target_os = "linux")]
const UTIME_OMIT: i64 = (1 << 30) - 2;

/// A path as a C string; an embedded NUL is EINVAL, as in Go's `BytePtrFromString`.
pub fn cstring(bytes: &[u8]) -> Result<CString, Errno> {
    CString::new(bytes).map_err(|_| EINVAL)
}

fn check(r: c_int) -> Result<(), Errno> {
    if r < 0 {
        Err(Errno::last())
    } else {
        Ok(())
    }
}

pub fn getuid() -> i64 {
    // SAFETY: getuid takes no arguments, touches no memory and cannot fail.
    i64::from(unsafe { c::getuid() })
}

pub fn geteuid() -> i64 {
    // SAFETY: geteuid takes no arguments, touches no memory and cannot fail.
    i64::from(unsafe { c::geteuid() })
}

pub fn getgid() -> i64 {
    // SAFETY: getgid takes no arguments, touches no memory and cannot fail.
    i64::from(unsafe { c::getgid() })
}

pub fn getegid() -> i64 {
    // SAFETY: getegid takes no arguments, touches no memory and cannot fail.
    i64::from(unsafe { c::getegid() })
}

pub fn getppid() -> i64 {
    // SAFETY: getppid takes no arguments, touches no memory and cannot fail.
    i64::from(unsafe { c::getppid() })
}

pub fn getgroups() -> Result<Vec<u32>, Errno> {
    loop {
        // SAFETY: a zero size with a null list only asks for the count.
        let n = unsafe { c::getgroups(0, std::ptr::null_mut()) };
        if n < 0 {
            return Err(Errno::last());
        }
        let mut list = vec![0u32; n as usize];
        // SAFETY: `list` has room for `n` entries, the size passed, and stays
        // alive and unaliased for the call.
        let got = unsafe { c::getgroups(n, list.as_mut_ptr()) };
        if got < 0 {
            let e = Errno::last();
            // The group list grew between the two calls: ask again.
            if e == EINVAL {
                continue;
            }
            return Err(e);
        }
        list.truncate(got as usize);
        return Ok(list);
    }
}

pub fn gethostname() -> Result<Vec<u8>, Errno> {
    let mut buf = vec![0u8; 1024];
    // SAFETY: `buf` is writable for `buf.len()` bytes, the length passed.
    check(unsafe { c::gethostname(buf.as_mut_ptr().cast(), buf.len()) })?;
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    buf.truncate(end);
    Ok(buf)
}

pub fn kill(pid: i32, sig: i32) -> Result<(), Errno> {
    // SAFETY: kill takes two integers and touches no memory.
    check(unsafe { c::kill(pid, sig) })
}

pub fn link(old: &[u8], new: &[u8]) -> Result<(), Errno> {
    let (old, new) = (cstring(old)?, cstring(new)?);
    // SAFETY: both arguments are NUL-terminated strings that outlive the call.
    check(unsafe { c::link(old.as_ptr(), new.as_ptr()) })
}

/// `utimensat(AT_FDCWD, path, times, 0)`; `None` leaves that time unchanged.
pub fn utimens(
    path: &[u8],
    atime: Option<(i64, i64)>,
    mtime: Option<(i64, i64)>,
) -> Result<(), Errno> {
    let path = cstring(path)?;
    let spec = |t: Option<(i64, i64)>| match t {
        Some((tv_sec, tv_nsec)) => c::Timespec { tv_sec, tv_nsec },
        None => c::Timespec {
            tv_sec: UTIME_OMIT,
            tv_nsec: UTIME_OMIT,
        },
    };
    let times = [spec(atime), spec(mtime)];
    // SAFETY: `path` is a NUL-terminated string and `times` is an array of two
    // timespec structures, both alive for the call.
    check(unsafe { c::utimensat(AT_FDCWD, path.as_ptr(), times.as_ptr(), 0) })
}
