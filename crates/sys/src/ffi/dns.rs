//! The C library's resolver entry points: `getnameinfo`, `gai_strerror`,
//! `res_search` and `if_nametoindex`, the calls behind Go's cgo resolver.
use crate::errno::Errno;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_uchar, c_uint, c_void};

// libresolv holds res_search on macOS; on Linux it is in libc (glibc 2.34 and
// later, musl).
#[cfg_attr(target_os = "macos", link(name = "resolv"))]
extern "C" {
    fn getnameinfo(
        sa: *const c_void,
        salen: u32,
        host: *mut c_char,
        hostlen: u32,
        serv: *mut c_char,
        servlen: u32,
        flags: c_int,
    ) -> c_int;
    fn gai_strerror(code: c_int) -> *const c_char;
    fn if_nametoindex(name: *const c_char) -> c_uint;
    #[cfg(target_os = "macos")]
    fn res_9_ninit(state: *mut c_void) -> c_int;
    #[cfg(target_os = "macos")]
    fn res_9_nsearch(
        state: *mut c_void,
        dname: *const c_char,
        class: c_int,
        typ: c_int,
        ans: *mut c_uchar,
        anslen: c_int,
    ) -> c_int;
    #[cfg(target_os = "macos")]
    fn res_9_nclose(state: *mut c_void);
    #[cfg(target_os = "linux")]
    #[link_name = "res_search"]
    fn c_res_search(
        dname: *const c_char,
        class: c_int,
        typ: c_int,
        ans: *mut c_uchar,
        anslen: c_int,
    ) -> c_int;
}

#[cfg(target_os = "macos")]
mod eai {
    pub const AGAIN: i32 = 2;
    pub const NONAME: i32 = 8;
    pub const OVERFLOW: i32 = 14;
    pub const SYSTEM: i32 = 11;
    pub const NI_NAMEREQD: i32 = 4;
}

#[cfg(target_os = "linux")]
mod eai {
    pub const AGAIN: i32 = -3;
    pub const NONAME: i32 = -2;
    pub const OVERFLOW: i32 = -12;
    pub const SYSTEM: i32 = -11;
    pub const NI_NAMEREQD: i32 = 8;
}

pub use eai::{AGAIN as EAI_AGAIN, NONAME as EAI_NONAME};

/// The failure of `getnameinfo`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameinfoError {
    /// The `EAI_*` code.
    pub code: i32,
    /// `errno` when the code is `EAI_SYSTEM`.
    pub errno: Option<Errno>,
    /// `gai_strerror(code)`.
    pub text: String,
}

/// `gai_strerror`.
pub fn strerror(code: i32) -> String {
    // SAFETY: gai_strerror returns a pointer to a static NUL-terminated string.
    let p = unsafe { gai_strerror(code) };
    if p.is_null() {
        return format!("error {code}");
    }
    // SAFETY: `p` is non-null and points to a NUL-terminated string.
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

/// `getnameinfo(sa, NI_NAMEREQD)` for the host name, growing the buffer on
/// `EAI_OVERFLOW` as Go does (64 bytes up to 4096).
pub fn nameinfo_ptr(sa: &[u8]) -> Result<Vec<u8>, NameinfoError> {
    let mut len = 64usize;
    loop {
        let mut buf = vec![0u8; len];
        // SAFETY: `sa` is a socket address of the given length and `buf` is
        // writable for `len` bytes; no service buffer is requested.
        let code = unsafe {
            getnameinfo(
                sa.as_ptr().cast(),
                sa.len() as u32,
                buf.as_mut_ptr().cast(),
                len as u32,
                std::ptr::null_mut(),
                0,
                eai::NI_NAMEREQD,
            )
        };
        if code == 0 {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            buf.truncate(end);
            return Ok(buf);
        }
        if code == eai::OVERFLOW && len < 4096 {
            len *= 2;
            continue;
        }
        let errno = (code == eai::SYSTEM).then(Errno::last);
        return Err(NameinfoError {
            code,
            errno,
            text: strerror(code),
        });
    }
}

/// `if_nametoindex`: 0 when there is no such interface.
pub fn nametoindex(name: &str) -> u32 {
    let Ok(c) = std::ffi::CString::new(name) else {
        return 0;
    };
    // SAFETY: `c` is a NUL-terminated string that outlives the call.
    unsafe { if_nametoindex(c.as_ptr()) }
}

/// `res_search(name, C_IN, type)`: the raw response packet, or `None` when the
/// C library reports a failure (Go's "res_nsearch failure").
pub fn res_search(name: &str, typ: i32) -> Result<Vec<u8>, String> {
    let c = std::ffi::CString::new(name).map_err(|_| "invalid argument".to_string())?;
    let mut size = 64 * 1024usize; // maxDNSPacketSize
    loop {
        let mut buf = vec![0u8; size];
        let n = search_once(&c, typ, &mut buf);
        if n <= 0 || n > 0xffff {
            return Err("res_nsearch failure".into());
        }
        let n = n as usize;
        if n <= buf.len() {
            buf.truncate(n);
            return Ok(buf);
        }
        size = n;
    }
}

#[cfg(target_os = "macos")]
fn search_once(name: &std::ffi::CStr, typ: i32, buf: &mut [u8]) -> i32 {
    // `struct __res_state` is a few hundred bytes; give it generous zeroed,
    // aligned room.
    let mut state = vec![0u64; 1024];
    // SAFETY: `state` is zeroed memory larger than `struct __res_state`;
    // res_ninit initialises it, res_nsearch uses it with `name` (NUL
    // terminated) and `buf` (writable for its length), and res_nclose frees
    // what res_ninit allocated, all before `state` is dropped.
    unsafe {
        if res_9_ninit(state.as_mut_ptr().cast()) != 0 {
            return -1;
        }
        let n = res_9_nsearch(
            state.as_mut_ptr().cast(),
            name.as_ptr(),
            1,
            typ,
            buf.as_mut_ptr(),
            buf.len() as c_int,
        );
        res_9_nclose(state.as_mut_ptr().cast());
        n
    }
}

#[cfg(target_os = "linux")]
fn search_once(name: &std::ffi::CStr, typ: i32, buf: &mut [u8]) -> i32 {
    // SAFETY: `name` is NUL-terminated and `buf` is writable for its length.
    unsafe { c_res_search(name.as_ptr(), 1, typ, buf.as_mut_ptr(), buf.len() as c_int) }
}
