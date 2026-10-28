#![deny(unsafe_code)]
//! Go-shaped operating-system interfaces for the standard library port
//! (docs/adr/0004-system-interface-crate.md).
//!
//! Functions here wrap system calls that Rust's std does not expose. They are
//! declared by hand against the platform C library, which std already links,
//! so the crate has no dependencies. The only `unsafe` lives in `ffi`
//! (private). Linux and macOS (64-bit) are supported; on other targets the
//! system-call wrappers fail with `ENOSYS` and the descriptor-based API
//! (files with deadlines, sockets, dialing) is absent.
// Go's rich error values (net.OpError and friends) are returned by value.
#![allow(clippy::result_large_err)]

/// Items that need the system-call layer, present only on supported targets.
macro_rules! supported {
    ($($item:item)*) => {
        $(
            #[cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]
            $item
        )*
    };
}

#[cfg(doc)]
mod api_surface;
pub mod errno;
mod errno_table;
#[allow(unsafe_code)]
mod ffi;
pub mod net;
pub mod os;
supported! {
    mod os_file;
    mod os_root;
    mod os_proc;
    mod os_exec;
    mod os_signal;
    mod os_user;
    mod poll;
    pub mod syscall;
}
