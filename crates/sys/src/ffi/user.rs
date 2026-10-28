//! The account database: `getpwuid_r`, `getpwnam_r`, `getgrgid_r`,
//! `getgrnam_r`, `getgrouplist` and `sysconf`, the libc calls behind
//! `os/user` (Go's cgo build). They go through the system's name service
//! (NSS on Linux, Open Directory on macOS).
use crate::errno::Errno;
use std::os::raw::{c_char, c_int, c_long};

mod c {
    use super::*;

    /// The C library's `struct passwd`, up to the fields `os/user` reads.
    #[repr(C)]
    pub struct Passwd {
        pub name: *mut c_char,
        pub passwd: *mut c_char,
        pub uid: u32,
        pub gid: u32,
        #[cfg(target_os = "macos")]
        pub change: i64,
        #[cfg(target_os = "macos")]
        pub class: *mut c_char,
        pub gecos: *mut c_char,
        pub dir: *mut c_char,
        pub shell: *mut c_char,
        #[cfg(target_os = "macos")]
        pub expire: i64,
    }

    /// The C library's `struct group`.
    #[repr(C)]
    pub struct Group {
        pub name: *mut c_char,
        pub passwd: *mut c_char,
        pub gid: u32,
        pub mem: *mut *mut c_char,
    }

    extern "C" {
        pub fn getpwnam_r(
            name: *const c_char,
            pwd: *mut Passwd,
            buf: *mut c_char,
            len: usize,
            result: *mut *mut Passwd,
        ) -> c_int;
        pub fn getpwuid_r(
            uid: u32,
            pwd: *mut Passwd,
            buf: *mut c_char,
            len: usize,
            result: *mut *mut Passwd,
        ) -> c_int;
        pub fn getgrnam_r(
            name: *const c_char,
            grp: *mut Group,
            buf: *mut c_char,
            len: usize,
            result: *mut *mut Group,
        ) -> c_int;
        pub fn getgrgid_r(
            gid: u32,
            grp: *mut Group,
            buf: *mut c_char,
            len: usize,
            result: *mut *mut Group,
        ) -> c_int;
        pub fn getgrouplist(
            name: *const c_char,
            gid: u32,
            groups: *mut u32,
            ngroups: *mut c_int,
        ) -> c_int;
        pub fn sysconf(name: c_int) -> c_long;
    }
}

/// `_SC_GETPW_R_SIZE_MAX`.
#[cfg(target_os = "macos")]
pub const SC_GETPW_R_SIZE_MAX: i32 = 0x47;
/// `_SC_GETGR_R_SIZE_MAX`.
#[cfg(target_os = "macos")]
pub const SC_GETGR_R_SIZE_MAX: i32 = 0x46;
/// `_SC_GETPW_R_SIZE_MAX`.
#[cfg(target_os = "linux")]
pub const SC_GETPW_R_SIZE_MAX: i32 = 70;
/// `_SC_GETGR_R_SIZE_MAX`.
#[cfg(target_os = "linux")]
pub const SC_GETGR_R_SIZE_MAX: i32 = 69;

/// A found `struct passwd`, its strings copied out of the lookup buffer.
pub struct Passwd {
    pub uid: u32,
    pub gid: u32,
    pub name: Vec<u8>,
    pub gecos: Vec<u8>,
    pub dir: Vec<u8>,
}

/// A found `struct group`.
pub struct Group {
    pub gid: u32,
    pub name: Vec<u8>,
}

/// `sysconf(name)`, or -1 on error.
pub fn sysconf(name: i32) -> i64 {
    // SAFETY: sysconf takes an integer and touches no memory.
    unsafe { c::sysconf(name) }
}

/// A NUL-terminated copy of `s`, cut at its first NUL as C would read it.
fn c_name(s: &[u8]) -> Vec<u8> {
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    let mut v = s[..end].to_vec();
    v.push(0);
    v
}

/// The string at `p`, or empty for a null pointer.
///
/// # Safety
/// A non-null `p` must point to a NUL-terminated string valid for the call.
unsafe fn string_at(p: *const c_char) -> Vec<u8> {
    if p.is_null() {
        return Vec::new();
    }
    // SAFETY: the caller guarantees a valid NUL-terminated string.
    unsafe { std::ffi::CStr::from_ptr(p) }.to_bytes().to_vec()
}

/// Turns the return value (an error number, not `errno`) and the result
/// pointer of a `*_r` call into Go's `(found, errno)`.
fn outcome(rc: c_int, found: bool) -> Result<bool, Errno> {
    if rc == 0 {
        Ok(found)
    } else {
        Err(Errno(rc))
    }
}

fn passwd_from(p: &c::Passwd) -> Passwd {
    // SAFETY: after a successful call the string fields are null or point
    // into the lookup buffer, which the caller still holds.
    unsafe {
        Passwd {
            uid: p.uid,
            gid: p.gid,
            name: string_at(p.name),
            gecos: string_at(p.gecos),
            dir: string_at(p.dir),
        }
    }
}

fn zeroed_passwd() -> c::Passwd {
    // SAFETY: `struct passwd` is plain data; all-zero (null pointers, zero
    // numbers) is a valid value.
    unsafe { std::mem::zeroed() }
}

fn zeroed_group() -> c::Group {
    // SAFETY: `struct group` is plain data; all-zero is a valid value.
    unsafe { std::mem::zeroed() }
}

/// `getpwnam_r(name, ...)` using `buf` as the string storage.
pub fn getpwnam_r(name: &[u8], buf: &mut [u8]) -> Result<Option<Passwd>, Errno> {
    let name = c_name(name);
    let mut pwd = zeroed_passwd();
    let mut result: *mut c::Passwd = std::ptr::null_mut();
    // SAFETY: `name` is NUL-terminated; `pwd` and `result` are valid for
    // writes; `buf` is writable for `buf.len()` bytes. All outlive the call.
    let rc = unsafe {
        c::getpwnam_r(
            name.as_ptr().cast(),
            &mut pwd,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    Ok(outcome(rc, !result.is_null())?.then(|| passwd_from(&pwd)))
}

/// `getpwuid_r(uid, ...)` using `buf` as the string storage.
pub fn getpwuid_r(uid: u32, buf: &mut [u8]) -> Result<Option<Passwd>, Errno> {
    let mut pwd = zeroed_passwd();
    let mut result: *mut c::Passwd = std::ptr::null_mut();
    // SAFETY: `pwd` and `result` are valid for writes; `buf` is writable for
    // `buf.len()` bytes. All outlive the call.
    let rc = unsafe {
        c::getpwuid_r(
            uid,
            &mut pwd,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    Ok(outcome(rc, !result.is_null())?.then(|| passwd_from(&pwd)))
}

/// `getgrnam_r(name, ...)` using `buf` as the string storage.
pub fn getgrnam_r(name: &[u8], buf: &mut [u8]) -> Result<Option<Group>, Errno> {
    let name = c_name(name);
    let mut grp = zeroed_group();
    let mut result: *mut c::Group = std::ptr::null_mut();
    // SAFETY: `name` is NUL-terminated; `grp` and `result` are valid for
    // writes; `buf` is writable for `buf.len()` bytes. All outlive the call.
    let rc = unsafe {
        c::getgrnam_r(
            name.as_ptr().cast(),
            &mut grp,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    Ok(outcome(rc, !result.is_null())?.then(|| group_from(&grp)))
}

/// `getgrgid_r(gid, ...)` using `buf` as the string storage.
pub fn getgrgid_r(gid: u32, buf: &mut [u8]) -> Result<Option<Group>, Errno> {
    let mut grp = zeroed_group();
    let mut result: *mut c::Group = std::ptr::null_mut();
    // SAFETY: `grp` and `result` are valid for writes; `buf` is writable for
    // `buf.len()` bytes. All outlive the call.
    let rc = unsafe {
        c::getgrgid_r(
            gid,
            &mut grp,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    Ok(outcome(rc, !result.is_null())?.then(|| group_from(&grp)))
}

fn group_from(g: &c::Group) -> Group {
    // SAFETY: after a successful call the name is null or points into the
    // lookup buffer, which the caller still holds.
    Group {
        gid: g.gid,
        name: unsafe { string_at(g.name) },
    }
}

/// `getgrouplist(name, gid, groups, ngroups)`: `n` is the capacity of
/// `groups` on entry and the group count (or the count needed) on return;
/// the result is the C return value, -1 when the buffer is too small.
pub fn getgrouplist(name: &[u8], gid: u32, groups: &mut [u32], n: &mut i32) -> i32 {
    let name = c_name(name);
    debug_assert!(usize::try_from(*n).is_ok_and(|n| n <= groups.len()));
    // SAFETY: `name` is NUL-terminated; `groups` holds at least `*n` entries
    // (the capacity the call may write); `n` is valid for reads and writes.
    unsafe { c::getgrouplist(name.as_ptr().cast(), gid, groups.as_mut_ptr(), n) }
}
