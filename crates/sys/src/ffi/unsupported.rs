//! Stand-ins for targets without bindings: every call fails with `ENOSYS`.
#![allow(dead_code)]
use crate::errno::{Errno, EINVAL, ENOSYS};

pub fn cstring(bytes: &[u8]) -> Result<std::ffi::CString, Errno> {
    std::ffi::CString::new(bytes).map_err(|_| EINVAL)
}

pub fn getuid() -> i64 {
    -1
}

pub fn geteuid() -> i64 {
    -1
}

pub fn getgid() -> i64 {
    -1
}

pub fn getegid() -> i64 {
    -1
}

pub fn getppid() -> i64 {
    -1
}

pub fn getgroups() -> Result<Vec<u32>, Errno> {
    Err(ENOSYS)
}

pub fn gethostname() -> Result<Vec<u8>, Errno> {
    Err(ENOSYS)
}

pub fn kill(_pid: i32, _sig: i32) -> Result<(), Errno> {
    Err(ENOSYS)
}

pub fn link(_old: &[u8], _new: &[u8]) -> Result<(), Errno> {
    Err(ENOSYS)
}

pub fn utimens(
    _path: &[u8],
    _atime: Option<(i64, i64)>,
    _mtime: Option<(i64, i64)>,
) -> Result<(), Errno> {
    Err(ENOSYS)
}

/// A decoded interface address (never produced on this target).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IfAddr {
    V4([u8; 4]),
    V6([u8; 16]),
    Link { index: u32, hardware: Vec<u8> },
    Other,
}

/// One entry from `getifaddrs` (never produced on this target).
#[derive(Clone, Debug)]
pub struct IfEntry {
    pub name: String,
    pub flags: u32,
    pub addr: IfAddr,
    pub netmask: Option<IfAddr>,
}

pub fn getifaddrs() -> Result<Vec<IfEntry>, Errno> {
    Err(ENOSYS)
}

pub fn interface_mtu(_name: &str) -> Result<i32, Errno> {
    Err(ENOSYS)
}
