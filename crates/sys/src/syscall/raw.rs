//! The raw system-call entry points, the string and byte conversions Go's
//! wrappers use, and `Getpagesize`/`Exit`.
use super::errno::Errno;
use super::{EINVAL, FD_CLOEXEC, F_GETFL, F_SETFD, F_SETFL, O_NONBLOCK};
use std::ffi::CString;
use std::os::raw::c_char;

pub use crate::ffi::syscall::{
    all_threads_syscall, all_threads_syscall6, raw_syscall, raw_syscall6, syscall, syscall6,
};
pub(crate) use crate::ffi::syscall::{sc, sc_all_threads, sc_no_error};

/// `syscall.ByteSliceFromString`: the text of `s` followed by a NUL byte, or
/// `EINVAL` if `s` contains a NUL byte.
pub fn byte_slice_from_string(s: &str) -> Result<Vec<u8>, Errno> {
    if s.as_bytes().contains(&0) {
        return Err(EINVAL);
    }
    let mut a = Vec::with_capacity(s.len() + 1);
    a.extend_from_slice(s.as_bytes());
    a.push(0);
    Ok(a)
}

/// `syscall.StringByteSlice`. Deprecated. Panics if `s` contains a NUL byte.
pub fn string_byte_slice(s: &str) -> Vec<u8> {
    match byte_slice_from_string(s) {
        Ok(a) => a,
        Err(_) => panic!("syscall: string with NUL passed to StringByteSlice"),
    }
}

/// `syscall.BytePtrFromString`: an owned NUL-terminated copy of `s` (its
/// `as_ptr` is Go's `*byte`), or `EINVAL` if `s` contains a NUL byte.
pub fn byte_ptr_from_string(s: &str) -> Result<CString, Errno> {
    CString::new(s).map_err(|_| EINVAL)
}

/// `syscall.StringBytePtr`. Deprecated. Panics if `s` contains a NUL byte.
pub fn string_byte_ptr(s: &str) -> CString {
    match byte_ptr_from_string(s) {
        Ok(a) => a,
        Err(_) => panic!("syscall: string with NUL passed to StringByteSlice"),
    }
}

/// The NUL-terminated strings and the nil-terminated pointer array over
/// them that `SlicePtrFromStrings` returns (Go's `[]*byte`).
#[derive(Debug)]
pub struct CStringVec {
    strings: Vec<CString>,
    ptrs: Vec<*const c_char>,
}

impl CStringVec {
    fn new(strings: Vec<CString>) -> CStringVec {
        let mut ptrs: Vec<*const c_char> = strings.iter().map(|s| s.as_ptr()).collect();
        ptrs.push(std::ptr::null());
        CStringVec { strings, ptrs }
    }

    /// The pointer array, ending with a null pointer, valid while `self` lives.
    pub fn as_ptr(&self) -> *const *const c_char {
        self.ptrs.as_ptr()
    }

    /// The number of strings (not counting the terminating null pointer).
    pub fn len(&self) -> usize {
        self.strings.len()
    }

    /// Whether there are no strings.
    pub fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }

    /// The owned strings.
    pub fn strings(&self) -> &[CString] {
        &self.strings
    }
}

/// `syscall.SlicePtrFromStrings`: NUL-terminated copies of `ss`, or
/// `EINVAL` if any contains a NUL byte.
pub fn slice_ptr_from_strings(ss: &[String]) -> Result<CStringVec, Errno> {
    let mut v = Vec::with_capacity(ss.len());
    for s in ss {
        v.push(byte_ptr_from_string(s)?);
    }
    Ok(CStringVec::new(v))
}

/// `syscall.StringSlicePtr`. Deprecated. Panics if a string contains a NUL byte.
pub fn string_slice_ptr(ss: &[String]) -> CStringVec {
    CStringVec::new(ss.iter().map(|s| string_byte_ptr(s)).collect())
}

/// `syscall.Getpagesize`: the size of a memory page.
pub fn getpagesize() -> isize {
    crate::ffi::syscall::page_size() as isize
}

/// `syscall.Exit`: ends the process at once with `code`.
pub fn exit(code: isize) -> ! {
    std::process::exit(code as i32)
}

/// `syscall.CloseOnExec`: marks `fd` close-on-exec; errors are ignored.
pub fn close_on_exec(fd: isize) {
    let _ = super::zsyscall::fcntl(fd, F_SETFD, FD_CLOEXEC);
}

/// `syscall.SetNonblock`: sets or clears `O_NONBLOCK` on `fd`.
pub fn set_nonblock(fd: isize, nonblocking: bool) -> Result<(), Errno> {
    let mut flag = super::zsyscall::fcntl(fd, F_GETFL, 0)?;
    if (flag & O_NONBLOCK != 0) == nonblocking {
        return Ok(());
    }
    if nonblocking {
        flag |= O_NONBLOCK;
    } else {
        flag &= !O_NONBLOCK;
    }
    super::zsyscall::fcntl(fd, F_SETFL, flag)?;
    Ok(())
}
