//! Go's `os`: a portable interface to operating system functionality, built
//! on `std::fs`, `std::env` and `std::process`.
//!
//! Unix only. Errors are `io::Error`s whose payloads are Go's types:
//! [`PathError`] (shared with `io::fs`), [`LinkError`], [`SyscallError`], the
//! sentinels of [`io::fs`](crate::io::fs) and [`Error`], and [`Errno`] for
//! operating system error numbers, printed with Go's message text. Use
//! [`is_exist`], [`is_not_exist`], [`is_permission`] and [`is_timeout`] (or
//! [`Error::is`] and the `io::fs` sentinels) to classify them.
//!
//! Go's process environment functions are `std`'s: `Getenv` and `LookupEnv`
//! are `std::env::var` and `std::env::var_os`, `Environ` is `std::env::vars`,
//! `Args` is `std::env::args`, `Exit` is `std::process::exit` and `Getpid` is
//! `std::process::id`; this module adds no wrappers for them.
//!
//! Where `std` offers no safe equivalent of a system call the module either
//! shells out to the platform tool (`kill`, `id`, `ps`, `hostname`) or
//! reports the limitation; `docs/api/os.json` records each deviation.

mod error;
mod file;
mod fsops;
mod proc;
mod root;

pub mod exec;
pub(crate) mod user;

pub use crate::io::fs::{
    DirEntry, FileInfo, FileMode, PathError, ERR_CLOSED, ERR_EXIST, ERR_INVALID, ERR_NOT_EXIST,
    ERR_PERMISSION, MODE_APPEND, MODE_CHAR_DEVICE, MODE_DEVICE, MODE_DIR, MODE_EXCLUSIVE,
    MODE_IRREGULAR, MODE_NAMED_PIPE, MODE_PERM, MODE_SETGID, MODE_SETUID, MODE_SOCKET, MODE_STICKY,
    MODE_SYMLINK, MODE_TEMPORARY, MODE_TYPE,
};
pub(crate) use error::{errno, from_errno, os_error};
pub use error::{
    errno_of, is_exist, is_not_exist, is_permission, is_timeout, link_error, syscall_error, Errno,
    Error, LinkError, SyscallError,
};
pub use file::{
    create, open, open_file, pipe, stderr, stdin, stdout, File, O_APPEND, O_CREATE, O_EXCL,
    O_RDONLY, O_RDWR, O_SYNC, O_TRUNC, O_WRONLY,
};
pub use fsops::{
    chdir, chmod, chown, chtimes, copy_fs, create_temp, dir_fs, getwd, lchown, link, lstat, mkdir,
    mkdir_all, mkdir_temp, read_dir, read_dir_info, read_file, readlink, remove, remove_all,
    rename, same_file, stat, symlink, temp_dir, truncate, write_file,
};
pub use proc::{
    find_process, start_process, ProcAttr, Process, ProcessState, Sig, Signal, INTERRUPT, KILL,
};
pub use root::{open_in_root, open_root, Root};

use std::io;

/// The name of the operating system's "null device" (`os.DevNull`).
pub const DEV_NULL: &str = "/dev/null";

// ---- environment -----------------------------------------------------------

fn valid_env_key(key: &str) -> bool {
    !key.is_empty() && !key.bytes().any(|b| b == b'=' || b == 0)
}

/// The value of the environment variable `key`; empty if unset
/// (`os.Getenv`, `os.LookupEnv` is `std::env::var_os`).
pub(crate) fn getenv(key: &str) -> String {
    if !valid_env_key(key) {
        return String::new();
    }
    std::env::var_os(key)
        .map(|v| v.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Sets the environment variable `key` (`os.Setenv`). Empty keys and keys or
/// values containing NUL (or `=` in the key) fail with `EINVAL`, wrapped in
/// a [`SyscallError`] for `setenv`.
pub fn setenv(key: &str, value: &str) -> io::Result<()> {
    if !valid_env_key(key) || value.bytes().any(|b| b == 0) {
        return Err(SyscallError::new("setenv", error::from_errno(error::errno::EINVAL)).into());
    }
    std::env::set_var(key, value);
    Ok(())
}

/// Unsets the environment variable `key` (`os.Unsetenv`).
pub fn unsetenv(key: &str) -> io::Result<()> {
    if valid_env_key(key) {
        std::env::remove_var(key);
    }
    Ok(())
}

/// Deletes all environment variables (`os.Clearenv`).
pub fn clearenv() {
    let keys: Vec<_> = std::env::vars_os().map(|(k, _)| k).collect();
    for k in keys {
        if let Some(k) = k.to_str() {
            if valid_env_key(k) {
                std::env::remove_var(k);
            }
        }
    }
}

/// A copy of the environment as `key=value` strings (`os.Environ`).
pub(crate) fn environ() -> Vec<String> {
    std::env::vars_os()
        .map(|(k, v)| format!("{}={}", k.to_string_lossy(), v.to_string_lossy()))
        .collect()
}

fn is_shell_special_var(c: u8) -> bool {
    matches!(
        c,
        b'*' | b'#' | b'$' | b'@' | b'!' | b'?' | b'-' | b'0'..=b'9'
    )
}

fn is_alpha_num(c: u8) -> bool {
    c == b'_' || c.is_ascii_alphanumeric()
}

/// Extracts the name from a `$` expression; returns it with the number of
/// bytes consumed (Go's `getShellName`).
fn get_shell_name(s: &[u8]) -> (&[u8], usize) {
    if s[0] == b'{' {
        if s.len() > 2 && is_shell_special_var(s[1]) && s[2] == b'}' {
            return (&s[1..2], 3);
        }
        for i in 1..s.len() {
            if s[i] == b'}' {
                if i == 1 {
                    return (&[], 2); // Bad syntax; eat "${}"
                }
                return (&s[1..i], i + 1);
            }
        }
        return (&[], 1); // Bad syntax; eat "${"
    }
    if is_shell_special_var(s[0]) {
        return (&s[0..1], 1);
    }
    let mut i = 0;
    while i < s.len() && is_alpha_num(s[i]) {
        i += 1;
    }
    (&s[..i], i)
}

/// Replaces `${var}` or `$var` in `s` using `mapping` (`os.Expand`).
pub fn expand(s: &str, mut mapping: impl FnMut(&str) -> String) -> String {
    let b = s.as_bytes();
    let mut buf: Vec<u8> = Vec::new();
    let mut started = false;
    let mut i = 0;
    let mut j = 0;
    while j < b.len() {
        if b[j] == b'$' && j + 1 < b.len() {
            started = true;
            buf.extend_from_slice(&b[i..j]);
            let (name, w) = get_shell_name(&b[j + 1..]);
            if name.is_empty() && w > 0 {
                // Encountered invalid syntax; eat the characters.
            } else if name.is_empty() {
                buf.push(b[j]);
            } else {
                // Names are ASCII, so slicing the original keeps UTF-8 intact.
                let name = String::from_utf8_lossy(name);
                buf.extend_from_slice(mapping(&name).as_bytes());
            }
            j += w;
            i = j + 1;
        }
        j += 1;
    }
    if !started {
        return s.to_string();
    }
    buf.extend_from_slice(&b[i.min(b.len())..]);
    String::from_utf8_lossy(&buf).into_owned()
}

/// Replaces `${var}` or `$var` using the environment (`os.ExpandEnv`).
pub fn expand_env(s: &str) -> String {
    expand(s, getenv)
}

// ---- process and system information ---------------------------------------

fn run_tool(program: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// The numeric value following `key:` in `/proc/self/status`.
fn proc_status(key: &str) -> Option<String> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    s.lines()
        .find_map(|l| l.strip_prefix(key)?.strip_prefix(':'))
        .map(|v| v.trim().to_string())
}

fn first_int(s: Option<String>) -> i32 {
    s.and_then(|v| v.split_whitespace().next().and_then(|n| n.parse().ok()))
        .unwrap_or(-1)
}

/// The process ID of the caller's parent (`os.Getppid`). `-1` when it
/// cannot be determined.
pub fn getppid() -> i32 {
    if let Ok(s) = std::fs::read_to_string("/proc/self/stat") {
        // pid (comm) state ppid ...; comm may contain spaces and parentheses.
        if let Some(rest) = s.rfind(')').map(|i| &s[i + 1..]) {
            if let Some(p) = rest.split_whitespace().nth(1).and_then(|n| n.parse().ok()) {
                return p;
            }
        }
    }
    first_int(run_tool(
        "ps",
        &["-o", "ppid=", "-p", &std::process::id().to_string()],
    ))
}

/// The caller's identity: real and effective uid and gid and the
/// supplementary groups; `-1` for what cannot be determined. Read from
/// `/proc/self/status` where it exists, otherwise from the platform `id`
/// tool, once.
struct Creds {
    uid: i32,
    euid: i32,
    gid: i32,
    egid: i32,
    groups: Option<Vec<i32>>,
}

fn creds_all() -> &'static Creds {
    static CREDS: std::sync::OnceLock<Creds> = std::sync::OnceLock::new();
    CREDS.get_or_init(|| {
        let pair = |v: Option<String>| -> Option<(i32, i32)> {
            let v = v?;
            let mut it = v.split_whitespace();
            let a = it.next()?.parse().ok()?;
            let b = it.next()?.parse().ok()?;
            Some((a, b))
        };
        let num = |args: &[&str]| -> i32 { first_int(run_tool("id", args)) };
        let (uid, euid) = pair(proc_status("Uid")).unwrap_or_else(|| (num(&["-ru"]), num(&["-u"])));
        let (gid, egid) = pair(proc_status("Gid")).unwrap_or_else(|| (num(&["-rg"]), num(&["-g"])));
        let groups = match proc_status("Groups") {
            Some(v) => Some(v),
            None => run_tool("id", &["-G"]),
        }
        .map(|v| {
            v.split_whitespace()
                .filter_map(|n| n.parse().ok())
                .collect()
        });
        Creds {
            uid,
            euid,
            gid,
            egid,
            groups,
        }
    })
}

/// Effective uid, effective gid and supplementary groups (for access checks).
pub(crate) fn creds() -> (i32, i32, Vec<i32>) {
    let c = creds_all();
    (c.euid, c.egid, c.groups.clone().unwrap_or_default())
}

/// The numeric user ID of the caller (`os.Getuid`). `-1` when it cannot be
/// determined.
pub fn getuid() -> i32 {
    creds_all().uid
}

/// The numeric effective user ID of the caller (`os.Geteuid`).
pub fn geteuid() -> i32 {
    creds_all().euid
}

/// The numeric group ID of the caller (`os.Getgid`).
pub fn getgid() -> i32 {
    creds_all().gid
}

/// The numeric effective group ID of the caller (`os.Getegid`).
pub fn getegid() -> i32 {
    creds_all().egid
}

/// The numeric group IDs of the groups the caller belongs to
/// (`os.Getgroups`).
pub fn getgroups() -> io::Result<Vec<i32>> {
    match &creds_all().groups {
        Some(g) => Ok(g.clone()),
        None => {
            Err(SyscallError::new("getgroups", io::Error::from(io::ErrorKind::Unsupported)).into())
        }
    }
}

/// The underlying system's memory page size (`os.Getpagesize`).
pub fn getpagesize() -> i32 {
    // AT_PAGESZ (6) from the auxiliary vector, where /proc provides it.
    if let Ok(v) = std::fs::read("/proc/self/auxv") {
        for e in v.chunks_exact(16) {
            let key = u64::from_ne_bytes(e[..8].try_into().unwrap_or([0; 8]));
            if key == 6 {
                return u64::from_ne_bytes(e[8..].try_into().unwrap_or([0; 8])) as i32;
            }
        }
    }
    if cfg!(all(target_vendor = "apple", target_arch = "aarch64")) {
        16384
    } else {
        4096
    }
}

/// The host name reported by the kernel (`os.Hostname`).
pub fn hostname() -> io::Result<String> {
    for f in ["/proc/sys/kernel/hostname", "/etc/hostname"] {
        if let Ok(s) = std::fs::read_to_string(f) {
            let s = s.trim().to_string();
            if !s.is_empty() {
                return Ok(s);
            }
        }
    }
    for tool in ["/bin/hostname", "/usr/bin/hostname"] {
        if let Some(h) = run_tool(tool, &[]) {
            if !h.is_empty() {
                return Ok(h);
            }
        }
    }
    match std::env::var("HOSTNAME") {
        Ok(h) if !h.is_empty() => Ok(h),
        _ => Err(SyscallError::new("hostname", io::Error::from(io::ErrorKind::Unsupported)).into()),
    }
}

fn dir_error(msg: &str) -> io::Error {
    io::Error::other(msg.to_string())
}

fn is_darwin() -> bool {
    cfg!(any(target_os = "macos", target_os = "ios"))
}

/// The default root directory for user-specific cached data
/// (`os.UserCacheDir`).
pub fn user_cache_dir() -> io::Result<String> {
    if is_darwin() {
        let dir = getenv("HOME");
        if dir.is_empty() {
            return Err(dir_error("$HOME is not defined"));
        }
        return Ok(dir + "/Library/Caches");
    }
    let dir = getenv("XDG_CACHE_HOME");
    if dir.is_empty() {
        let home = getenv("HOME");
        if home.is_empty() {
            return Err(dir_error("neither $XDG_CACHE_HOME nor $HOME are defined"));
        }
        Ok(home + "/.cache")
    } else if !dir.starts_with('/') {
        Err(dir_error("path in $XDG_CACHE_HOME is relative"))
    } else {
        Ok(dir)
    }
}

/// The default root directory for user-specific configuration data
/// (`os.UserConfigDir`).
pub fn user_config_dir() -> io::Result<String> {
    if is_darwin() {
        let dir = getenv("HOME");
        if dir.is_empty() {
            return Err(dir_error("$HOME is not defined"));
        }
        return Ok(dir + "/Library/Application Support");
    }
    let dir = getenv("XDG_CONFIG_HOME");
    if dir.is_empty() {
        let home = getenv("HOME");
        if home.is_empty() {
            return Err(dir_error("neither $XDG_CONFIG_HOME nor $HOME are defined"));
        }
        Ok(home + "/.config")
    } else if !dir.starts_with('/') {
        Err(dir_error("path in $XDG_CONFIG_HOME is relative"))
    } else {
        Ok(dir)
    }
}

/// The current user's home directory (`os.UserHomeDir`).
pub fn user_home_dir() -> io::Result<String> {
    let v = getenv("HOME");
    if !v.is_empty() {
        return Ok(v);
    }
    Err(dir_error("$HOME is not defined"))
}
