//! Directory-relative file calls (`openat`, `mkdirat`, `unlinkat`, ...) and
//! `stat`: the libc functions behind `os.Root`.
use super::proc::cstring;
use crate::errno::{Errno, EINTR, ERANGE};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::raw::{c_char, c_int, c_uint, c_void};

/// Per-target constants (values from Go's `zerrors_*` tables).
pub mod k {
    use std::os::raw::c_int;

    #[cfg(target_os = "macos")]
    pub const AT_FDCWD: c_int = -2;
    #[cfg(target_os = "linux")]
    pub const AT_FDCWD: c_int = -100;
    #[cfg(target_os = "macos")]
    pub const AT_SYMLINK_NOFOLLOW: c_int = 0x20;
    #[cfg(target_os = "linux")]
    pub const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
    #[cfg(target_os = "macos")]
    pub const AT_REMOVEDIR: c_int = 0x80;
    #[cfg(target_os = "linux")]
    pub const AT_REMOVEDIR: c_int = 0x200;
    #[cfg(target_os = "linux")]
    pub const AT_EMPTY_PATH: c_int = 0x1000;

    pub const O_RDONLY: c_int = 0;
    pub const O_WRONLY: c_int = 1;
    pub const O_RDWR: c_int = 2;
    #[cfg(target_os = "linux")]
    pub const O_APPEND: c_int = 0x400;
    #[cfg(target_os = "linux")]
    pub const O_CREATE: c_int = 0x40;
    #[cfg(target_os = "linux")]
    pub const O_EXCL: c_int = 0x80;
    #[cfg(target_os = "linux")]
    pub const O_TRUNC: c_int = 0x200;
    #[cfg(target_os = "linux")]
    pub const O_CLOEXEC: c_int = 0x80000;
    #[cfg(all(target_os = "linux", not(any(target_arch = "aarch64", target_arch = "arm"))))]
    pub const O_DIRECTORY: c_int = 0x10000;
    #[cfg(all(target_os = "linux", not(any(target_arch = "aarch64", target_arch = "arm"))))]
    pub const O_NOFOLLOW: c_int = 0x20000;
    #[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "arm")))]
    pub const O_DIRECTORY: c_int = 0x4000;
    #[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "arm")))]
    pub const O_NOFOLLOW: c_int = 0x8000;
    #[cfg(target_os = "macos")]
    pub const O_APPEND: c_int = 0x8;
    #[cfg(target_os = "macos")]
    pub const O_CREATE: c_int = 0x200;
    #[cfg(target_os = "macos")]
    pub const O_EXCL: c_int = 0x800;
    #[cfg(target_os = "macos")]
    pub const O_TRUNC: c_int = 0x400;
    #[cfg(target_os = "macos")]
    pub const O_CLOEXEC: c_int = 0x0100_0000;
    #[cfg(target_os = "macos")]
    pub const O_DIRECTORY: c_int = 0x10_0000;
    #[cfg(target_os = "macos")]
    pub const O_NOFOLLOW: c_int = 0x100;
}

mod c {
    use super::*;

    #[repr(C)]
    pub struct Timespec {
        pub tv_sec: i64,
        pub tv_nsec: i64,
    }

    #[cfg(target_os = "macos")]
    #[repr(C)]
    pub struct Stat {
        pub st_dev: i32,
        pub st_mode: u16,
        pub st_nlink: u16,
        pub st_ino: u64,
        pub st_uid: u32,
        pub st_gid: u32,
        pub st_rdev: i32,
        pub st_atime: Timespec,
        pub st_mtime: Timespec,
        pub st_ctime: Timespec,
        pub st_birthtime: Timespec,
        pub st_size: i64,
        pub st_blocks: i64,
        pub st_blksize: i32,
        pub st_flags: u32,
        pub st_gen: u32,
        pub st_lspare: i32,
        pub st_qspare: [i64; 2],
    }

    /// `struct statx` (Linux 4.11): the same layout on every architecture.
    #[cfg(target_os = "linux")]
    #[repr(C)]
    pub struct Statx {
        pub stx_mask: u32,
        pub stx_blksize: u32,
        pub stx_attributes: u64,
        pub stx_nlink: u32,
        pub stx_uid: u32,
        pub stx_gid: u32,
        pub stx_mode: u16,
        pub pad1: u16,
        pub stx_ino: u64,
        pub stx_size: u64,
        pub stx_blocks: u64,
        pub stx_attributes_mask: u64,
        pub stx_atime: StatxTimestamp,
        pub stx_btime: StatxTimestamp,
        pub stx_ctime: StatxTimestamp,
        pub stx_mtime: StatxTimestamp,
        pub stx_rdev_major: u32,
        pub stx_rdev_minor: u32,
        pub stx_dev_major: u32,
        pub stx_dev_minor: u32,
        pub spare: [u64; 14],
    }

    #[cfg(target_os = "linux")]
    #[repr(C)]
    pub struct StatxTimestamp {
        pub tv_sec: i64,
        pub tv_nsec: u32,
        pub pad: i32,
    }

    /// `struct dirent`: only the leading fields and the name are used.
    #[cfg(target_os = "linux")]
    #[repr(C)]
    pub struct Dirent {
        pub d_ino: u64,
        pub d_off: i64,
        pub d_reclen: u16,
        pub d_type: u8,
        pub d_name: [c_char; 256],
    }

    #[cfg(target_os = "macos")]
    #[repr(C)]
    pub struct Dirent {
        pub d_ino: u64,
        pub d_seekoff: u64,
        pub d_reclen: u16,
        pub d_namlen: u16,
        pub d_type: u8,
        pub d_name: [c_char; 1024],
    }

    extern "C" {
        pub fn openat(dirfd: c_int, path: *const c_char, flags: c_int, ...) -> c_int;
        pub fn mkdirat(dirfd: c_int, path: *const c_char, mode: c_uint) -> c_int;
        pub fn unlinkat(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int;
        pub fn renameat(
            olddirfd: c_int,
            old: *const c_char,
            newdirfd: c_int,
            new: *const c_char,
        ) -> c_int;
        pub fn linkat(
            olddirfd: c_int,
            old: *const c_char,
            newdirfd: c_int,
            new: *const c_char,
            flags: c_int,
        ) -> c_int;
        pub fn symlinkat(target: *const c_char, dirfd: c_int, path: *const c_char) -> c_int;
        pub fn readlinkat(
            dirfd: c_int,
            path: *const c_char,
            buf: *mut c_char,
            len: usize,
        ) -> isize;
        pub fn fchmodat(dirfd: c_int, path: *const c_char, mode: c_uint, flags: c_int) -> c_int;
        pub fn fchownat(
            dirfd: c_int,
            path: *const c_char,
            uid: u32,
            gid: u32,
            flags: c_int,
        ) -> c_int;
        pub fn utimensat(
            dirfd: c_int,
            path: *const c_char,
            times: *const Timespec,
            flags: c_int,
        ) -> c_int;
        #[cfg(target_os = "macos")]
        #[cfg_attr(target_arch = "x86_64", link_name = "fstatat$INODE64")]
        pub fn fstatat(
            dirfd: c_int,
            path: *const c_char,
            buf: *mut Stat,
            flags: c_int,
        ) -> c_int;
        #[cfg(target_os = "macos")]
        #[cfg_attr(target_arch = "x86_64", link_name = "fstat$INODE64")]
        pub fn fstat(fd: c_int, buf: *mut Stat) -> c_int;
        #[cfg(target_os = "linux")]
        pub fn statx(
            dirfd: c_int,
            path: *const c_char,
            flags: c_int,
            mask: c_uint,
            buf: *mut Statx,
        ) -> c_int;
        #[cfg_attr(
            all(target_os = "macos", target_arch = "x86_64"),
            link_name = "fdopendir$INODE64"
        )]
        pub fn fdopendir(fd: c_int) -> *mut c_void;
        #[cfg_attr(
            all(target_os = "macos", target_arch = "x86_64"),
            link_name = "readdir$INODE64"
        )]
        pub fn readdir(dir: *mut c_void) -> *mut Dirent;
        pub fn closedir(dir: *mut c_void) -> c_int;
        pub fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
        pub fn faccessat(dirfd: c_int, path: *const c_char, mode: c_int, flags: c_int) -> c_int;
    }
}

const F_DUPFD_CLOEXEC: c_int = if cfg!(target_os = "macos") { 67 } else { 1030 };

pub use k::{
    O_APPEND, O_CLOEXEC, O_CREATE, O_DIRECTORY, O_EXCL, O_NOFOLLOW, O_RDONLY, O_RDWR, O_TRUNC,
    O_WRONLY,
};

/// What `fstatat`/`fstat` report about a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stat {
    pub dev: u64,
    pub ino: u64,
    /// The raw `st_mode`: file type and permission bits.
    pub mode: u32,
    pub size: i64,
    pub mtime: (i64, i64),
}

fn check(r: c_int) -> Result<c_int, Errno> {
    if r < 0 {
        Err(Errno::last())
    } else {
        Ok(r)
    }
}

/// Repeats a call interrupted by a signal (Go's `ignoringEINTR`).
fn retry<T>(mut f: impl FnMut() -> Result<T, Errno>) -> Result<T, Errno> {
    loop {
        match f() {
            Err(e) if e == EINTR => continue,
            other => return other,
        }
    }
}

/// `openat(dirfd, path, flags | O_CLOEXEC, mode)`.
pub fn openat(dirfd: RawFd, path: &[u8], flags: i32, mode: u32) -> Result<OwnedFd, Errno> {
    let path = cstring(path)?;
    retry(|| {
        // SAFETY: `path` is a NUL-terminated string that outlives the call;
        // openat takes the mode as an unsigned integer in its variadic part.
        let fd = check(unsafe {
            c::openat(
                dirfd,
                path.as_ptr(),
                flags | k::O_CLOEXEC,
                mode as c_uint,
            )
        })?;
        // SAFETY: `fd` was just returned by a successful openat, so nothing
        // else owns it.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    })
}

/// `mkdirat`.
pub fn mkdirat(dirfd: RawFd, path: &[u8], mode: u32) -> Result<(), Errno> {
    let path = cstring(path)?;
    // SAFETY: `path` is a NUL-terminated string that outlives the call.
    retry(|| check(unsafe { c::mkdirat(dirfd, path.as_ptr(), mode as c_uint) }).map(|_| ()))
}

/// `unlinkat`; `dir` selects `AT_REMOVEDIR`.
pub fn unlinkat(dirfd: RawFd, path: &[u8], dir: bool) -> Result<(), Errno> {
    let path = cstring(path)?;
    let flags = if dir { k::AT_REMOVEDIR } else { 0 };
    // SAFETY: `path` is a NUL-terminated string that outlives the call.
    retry(|| check(unsafe { c::unlinkat(dirfd, path.as_ptr(), flags) }).map(|_| ()))
}

/// `renameat`.
pub fn renameat(olddir: RawFd, old: &[u8], newdir: RawFd, new: &[u8]) -> Result<(), Errno> {
    let (old, new) = (cstring(old)?, cstring(new)?);
    // SAFETY: both arguments are NUL-terminated strings that outlive the call.
    retry(|| check(unsafe { c::renameat(olddir, old.as_ptr(), newdir, new.as_ptr()) }).map(|_| ()))
}

/// `linkat` without `AT_SYMLINK_FOLLOW`.
pub fn linkat(olddir: RawFd, old: &[u8], newdir: RawFd, new: &[u8]) -> Result<(), Errno> {
    let (old, new) = (cstring(old)?, cstring(new)?);
    // SAFETY: both arguments are NUL-terminated strings that outlive the call.
    retry(|| {
        check(unsafe { c::linkat(olddir, old.as_ptr(), newdir, new.as_ptr(), 0) }).map(|_| ())
    })
}

/// `symlinkat(target, dirfd, path)`.
pub fn symlinkat(target: &[u8], dirfd: RawFd, path: &[u8]) -> Result<(), Errno> {
    let (target, path) = (cstring(target)?, cstring(path)?);
    // SAFETY: both arguments are NUL-terminated strings that outlive the call.
    retry(|| check(unsafe { c::symlinkat(target.as_ptr(), dirfd, path.as_ptr()) }).map(|_| ()))
}

/// `readlinkat`, growing the buffer as Go's `readlinkat` does.
pub fn readlinkat(dirfd: RawFd, path: &[u8]) -> Result<Vec<u8>, Errno> {
    let path = cstring(path)?;
    let mut len = 128usize;
    loop {
        let mut buf = vec![0u8; len];
        // SAFETY: `path` is NUL-terminated and `buf` is writable for `len` bytes.
        let n = retry(|| {
            let n = unsafe { c::readlinkat(dirfd, path.as_ptr(), buf.as_mut_ptr().cast(), len) };
            if n < 0 {
                Err(Errno::last())
            } else {
                Ok(n as usize)
            }
        });
        match n {
            Err(e) if e == ERANGE => {}
            Err(e) => return Err(e),
            Ok(n) if n < len => {
                buf.truncate(n);
                return Ok(buf);
            }
            Ok(_) => {}
        }
        len *= 2;
    }
}

/// `fchmodat(dirfd, path, mode, AT_SYMLINK_NOFOLLOW)`.
pub fn fchmodat_nofollow(dirfd: RawFd, path: &[u8], mode: u32) -> Result<(), Errno> {
    let path = cstring(path)?;
    // SAFETY: `path` is a NUL-terminated string that outlives the call.
    retry(|| {
        check(unsafe { c::fchmodat(dirfd, path.as_ptr(), mode as c_uint, k::AT_SYMLINK_NOFOLLOW) })
            .map(|_| ())
    })
}

/// `fchownat(dirfd, path, uid, gid, AT_SYMLINK_NOFOLLOW)`; -1 leaves an id alone.
pub fn fchownat_nofollow(dirfd: RawFd, path: &[u8], uid: i32, gid: i32) -> Result<(), Errno> {
    let path = cstring(path)?;
    // SAFETY: `path` is a NUL-terminated string that outlives the call; -1 as
    // an unsigned id is the "unchanged" value.
    retry(|| {
        check(unsafe {
            c::fchownat(
                dirfd,
                path.as_ptr(),
                uid as u32,
                gid as u32,
                k::AT_SYMLINK_NOFOLLOW,
            )
        })
        .map(|_| ())
    })
}

#[cfg(target_os = "macos")]
const UTIME_OMIT: i64 = -2;
#[cfg(target_os = "linux")]
const UTIME_OMIT: i64 = (1 << 30) - 2;

/// `utimensat(dirfd, path, times, AT_SYMLINK_NOFOLLOW)`; `None` leaves that
/// time unchanged.
pub fn utimensat_nofollow(
    dirfd: RawFd,
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
    retry(|| {
        check(unsafe {
            c::utimensat(dirfd, path.as_ptr(), times.as_ptr(), k::AT_SYMLINK_NOFOLLOW)
        })
        .map(|_| ())
    })
}

#[cfg(target_os = "macos")]
fn convert(st: &c::Stat) -> Stat {
    Stat {
        dev: st.st_dev as u32 as u64,
        ino: st.st_ino,
        mode: u32::from(st.st_mode),
        size: st.st_size,
        mtime: (st.st_mtime.tv_sec, st.st_mtime.tv_nsec),
    }
}

#[cfg(target_os = "macos")]
fn stat_at(dirfd: RawFd, path: &[u8], nofollow: bool) -> Result<Stat, Errno> {
    let path = cstring(path)?;
    let flags = if nofollow { k::AT_SYMLINK_NOFOLLOW } else { 0 };
    retry(|| {
        let mut st = std::mem::MaybeUninit::<c::Stat>::zeroed();
        // SAFETY: `path` is NUL-terminated and `st` is writable for a whole
        // `struct stat`, whose layout `c::Stat` mirrors.
        check(unsafe { c::fstatat(dirfd, path.as_ptr(), st.as_mut_ptr(), flags) })?;
        // SAFETY: the call succeeded, so the structure is initialised.
        Ok(convert(&unsafe { st.assume_init() }))
    })
}

/// `fstat(fd)`.
#[cfg(target_os = "macos")]
pub fn fstat(fd: RawFd) -> Result<Stat, Errno> {
    retry(|| {
        let mut st = std::mem::MaybeUninit::<c::Stat>::zeroed();
        // SAFETY: `st` is writable for a whole `struct stat`, whose layout
        // `c::Stat` mirrors.
        check(unsafe { c::fstat(fd, st.as_mut_ptr()) })?;
        // SAFETY: the call succeeded, so the structure is initialised.
        Ok(convert(&unsafe { st.assume_init() }))
    })
}

#[cfg(target_os = "linux")]
fn stat_at(dirfd: RawFd, path: &[u8], nofollow: bool) -> Result<Stat, Errno> {
    let path = cstring(path)?;
    let mut flags = if nofollow { k::AT_SYMLINK_NOFOLLOW } else { 0 };
    if path.as_bytes().is_empty() {
        flags |= k::AT_EMPTY_PATH;
    }
    // STATX_BASIC_STATS
    const MASK: c_uint = 0x7ff;
    retry(|| {
        let mut st = std::mem::MaybeUninit::<c::Statx>::zeroed();
        // SAFETY: `path` is NUL-terminated and `st` is writable for a whole
        // `struct statx`, whose layout `c::Statx` mirrors.
        check(unsafe { c::statx(dirfd, path.as_ptr(), flags, MASK, st.as_mut_ptr()) })?;
        // SAFETY: the call succeeded, so the structure is initialised.
        let st = unsafe { st.assume_init() };
        Ok(Stat {
            dev: (u64::from(st.stx_dev_major) << 32) | u64::from(st.stx_dev_minor),
            ino: st.stx_ino,
            mode: u32::from(st.stx_mode),
            size: st.stx_size as i64,
            mtime: (st.stx_mtime.tv_sec, i64::from(st.stx_mtime.tv_nsec)),
        })
    })
}

/// `fstatat(dirfd, path, AT_SYMLINK_NOFOLLOW)`.
pub fn lstatat(dirfd: RawFd, path: &[u8]) -> Result<Stat, Errno> {
    stat_at(dirfd, path, true)
}

/// `fstat(fd)`.
#[cfg(target_os = "linux")]
pub fn fstat(fd: RawFd) -> Result<Stat, Errno> {
    stat_at(fd, b"", false)
}

/// The names in the directory open on `fd`, in directory order, without `.`
/// and `..`. The descriptor is duplicated; the caller keeps its own.
pub fn read_dir_names(fd: RawFd) -> Result<Vec<Vec<u8>>, Errno> {
    // SAFETY: F_DUPFD_CLOEXEC takes two integers and returns a new descriptor.
    let dup = check(unsafe { c::fcntl(fd, F_DUPFD_CLOEXEC, 0 as c_int) })?;
    // SAFETY: `dup` is a descriptor we own; on success fdopendir takes it over.
    let dir = unsafe { c::fdopendir(dup) };
    if dir.is_null() {
        let e = Errno::last();
        // SAFETY: fdopendir failed, so `dup` is still ours to close.
        drop(unsafe { OwnedFd::from_raw_fd(dup) });
        return Err(e);
    }
    let mut names = Vec::new();
    loop {
        // SAFETY: `dir` is a live DIR* until closedir below.
        let ent = unsafe { c::readdir(dir) };
        if ent.is_null() {
            break;
        }
        // SAFETY: readdir returned a pointer to a dirent whose `d_name` is a
        // NUL-terminated string valid until the next readdir on `dir`.
        let name = unsafe { std::ffi::CStr::from_ptr((*ent).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            names.push(name.to_vec());
        }
    }
    // SAFETY: `dir` came from fdopendir and is closed exactly once; this also
    // closes `dup`.
    unsafe { c::closedir(dir) };
    Ok(names)
}

#[cfg(target_os = "macos")]
const AT_EACCESS: c_int = 0x10;
#[cfg(target_os = "linux")]
const AT_EACCESS: c_int = 0x200;

/// `faccessat(AT_FDCWD, path, X_OK, AT_EACCESS)`: whether the effective user
/// may execute the file (Go's `unix.Eaccess`).
pub fn eaccess_exec(path: &[u8]) -> Result<(), Errno> {
    let path = cstring(path)?;
    // SAFETY: `path` is a NUL-terminated string that outlives the call.
    retry(|| check(unsafe { c::faccessat(k::AT_FDCWD, path.as_ptr(), 1, AT_EACCESS) }).map(|_| ()))
}
