//! The only module that talks to the platform C library. Each file declares
//! the `extern "C"` functions it needs and wraps them in safe functions that
//! return [`crate::errno::Errno`]; nothing outside this directory uses `unsafe`.
//!
//! Linux and macOS (64-bit) are supported; `unsupported` supplies the same
//! functions for other targets, all failing with `ENOSYS`.

macro_rules! supported {
    ($($item:item)*) => {
        $(
            #[cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]
            $item
        )*
    };
}

macro_rules! unsupported {
    ($($item:item)*) => {
        $(
            #[cfg(not(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64")))]
            $item
        )*
    };
}

supported! {
    pub mod at;
    pub mod dns;
    pub mod signal;
    pub mod spawn;
    pub mod syscall;
    pub mod user;
    mod ifaddrs;
    mod proc;
    mod sock;
    pub use ifaddrs::*;
    pub use proc::*;
    pub use sock::*;
}

unsupported! {
    mod unsupported;
    pub use unsupported::*;
}
