//! Environment, directory-entry parsing, time conversions and the methods of
//! the generated structs.
use super::errno::{Errno, Signal};
use super::types::*;
use super::{EINVAL, SIGTRAP};
use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};

// ---- environment ----------------------------------------------------------
//
// Go keeps its own copy of the environment; Rust's `std::env` is the process
// environment that `os`, `exec` and the C library share, so these functions
// read and write it directly.

fn valid_key(key: &str) -> bool {
    !key.is_empty() && !key.bytes().any(|b| b == b'=' || b == 0)
}

/// `syscall.Getenv`: the value of `key` and whether it is set.
pub fn getenv(key: &str) -> Option<OsString> {
    if !valid_key(key) {
        return None;
    }
    std::env::var_os(key)
}

/// `syscall.Setenv`: `EINVAL` for an empty key, a key containing `=` or NUL,
/// or a value containing NUL.
pub fn setenv(key: &str, value: &str) -> Result<(), Errno> {
    if !valid_key(key) || value.bytes().any(|b| b == 0) {
        return Err(EINVAL);
    }
    std::env::set_var(key, value);
    Ok(())
}

/// `syscall.Unsetenv`.
pub fn unsetenv(key: &str) -> Result<(), Errno> {
    if valid_key(key) {
        std::env::remove_var(key);
    }
    Ok(())
}

/// `syscall.Clearenv`: removes every variable.
pub fn clearenv() {
    let keys: Vec<OsString> = std::env::vars_os().map(|(k, _)| k).collect();
    for k in keys {
        let b = k.as_bytes();
        if !b.is_empty() && !b.contains(&b'=') && !b.contains(&0) {
            std::env::remove_var(&k);
        }
    }
}

/// `syscall.Environ`: a copy of the environment as `key=value` strings.
pub fn environ() -> Vec<OsString> {
    std::env::vars_os()
        .map(|(k, v)| {
            let mut kv = k.into_vec();
            kv.push(b'=');
            kv.extend_from_slice(v.as_bytes());
            OsString::from_vec(kv)
        })
        .collect()
}

// ---- directory entries ----------------------------------------------------

const DIRENT_INO_OFF: usize = 0;
const DIRENT_RECLEN_OFF: usize = 16;
const DIRENT_NAME_OFF: usize = 19;

fn read_int_le(b: &[u8], off: usize, size: usize) -> Option<u64> {
    let s = b.get(off..off.checked_add(size)?)?;
    let mut v = 0u64;
    for (i, byte) in s.iter().enumerate() {
        v |= u64::from(*byte) << (8 * i);
    }
    Some(v)
}

/// `syscall.ParseDirent`: appends the names of the directory entries in
/// `buf` (the output of `ReadDirent`), skipping `.` and `..`, until `max`
/// names have been added (all if `max` is negative). Returns the number of
/// bytes consumed, the number of names added and the extended list.
pub fn parse_dirent(
    buf: &[u8],
    max: isize,
    mut names: Vec<OsString>,
) -> (isize, isize, Vec<OsString>) {
    let origlen = buf.len();
    let mut buf = buf;
    let mut max = max;
    let mut count = 0isize;
    while max != 0 && !buf.is_empty() {
        let reclen = match read_int_le(buf, DIRENT_RECLEN_OFF, 2) {
            Some(r) if r as usize <= buf.len() => r as usize,
            _ => return (origlen as isize, count, names),
        };
        let rec = &buf[..reclen];
        buf = &buf[reclen..];
        if read_int_le(rec, DIRENT_INO_OFF, 8).is_none() {
            break;
        }
        // Linux reports entries with inode 0 too; they are not skipped.
        let namlen = match (reclen as u64).checked_sub(DIRENT_NAME_OFF as u64) {
            Some(n) => n as usize,
            None => break,
        };
        if DIRENT_NAME_OFF + namlen > rec.len() {
            break;
        }
        let mut name = &rec[DIRENT_NAME_OFF..DIRENT_NAME_OFF + namlen];
        if let Some(i) = name.iter().position(|&c| c == 0) {
            name = &name[..i];
        }
        if name == b"." || name == b".." {
            continue;
        }
        max -= 1;
        count += 1;
        names.push(OsString::from_vec(name.to_vec()));
    }
    ((origlen - buf.len()) as isize, count, names)
}

// ---- time -----------------------------------------------------------------

/// `syscall.TimespecToNsec`.
pub fn timespec_to_nsec(ts: Timespec) -> i64 {
    ts.nano()
}

/// `syscall.NsecToTimespec`.
pub fn nsec_to_timespec(nsec: i64) -> Timespec {
    let mut sec = nsec / 1_000_000_000;
    let mut nsec = nsec % 1_000_000_000;
    if nsec < 0 {
        nsec += 1_000_000_000;
        sec -= 1;
    }
    Timespec { sec, nsec }
}

/// `syscall.TimevalToNsec`.
pub fn timeval_to_nsec(tv: Timeval) -> i64 {
    tv.nano()
}

/// `syscall.NsecToTimeval`: rounds up to a microsecond.
pub fn nsec_to_timeval(nsec: i64) -> Timeval {
    let nsec = nsec.wrapping_add(999);
    let mut usec = nsec % 1_000_000_000 / 1000;
    let mut sec = nsec / 1_000_000_000;
    if usec < 0 {
        usec += 1_000_000;
        sec -= 1;
    }
    Timeval { sec, usec }
}

impl Timespec {
    /// `Timespec.Unix`: seconds and nanoseconds.
    pub fn unix(&self) -> (i64, i64) {
        (self.sec, self.nsec)
    }

    /// `Timespec.Nano`: nanoseconds since the epoch (wrapping, as in Go).
    pub fn nano(&self) -> i64 {
        self.sec.wrapping_mul(1_000_000_000).wrapping_add(self.nsec)
    }
}

impl Timeval {
    /// `Timeval.Unix`: seconds and microseconds.
    pub fn unix(&self) -> (i64, i64) {
        (self.sec, self.usec)
    }

    /// `Timeval.Nano`: nanoseconds since the epoch (wrapping, as in Go).
    pub fn nano(&self) -> i64 {
        self.sec
            .wrapping_mul(1_000_000_000)
            .wrapping_add(self.usec.wrapping_mul(1000))
    }
}

// ---- methods of generated structs ------------------------------------------

impl PtraceRegs {
    /// `PtraceRegs.PC`.
    pub fn pc(&self) -> u64 {
        self.rip
    }

    /// `PtraceRegs.SetPC`.
    pub fn set_pc(&mut self, pc: u64) {
        self.rip = pc;
    }
}

impl Iovec {
    /// `Iovec.SetLen`.
    pub fn set_len(&mut self, length: isize) {
        self.len = length as u64;
    }
}

impl Msghdr {
    /// `Msghdr.SetControllen`.
    pub fn set_controllen(&mut self, length: isize) {
        self.controllen = length as u64;
    }
}

impl Cmsghdr {
    /// `Cmsghdr.SetLen`.
    pub fn set_len(&mut self, length: isize) {
        self.len = length as u64;
    }
}

// ---- WaitStatus -------------------------------------------------------------

/// `syscall.WaitStatus`: a `wait4` status in Linux's encoding.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct WaitStatus(pub u32);

const MASK: u32 = 0x7F;
const CORE: u32 = 0x80;
const EXITED: u32 = 0x00;
const STOPPED: u32 = 0x7F;
const SHIFT: u32 = 8;

impl WaitStatus {
    /// `WaitStatus.Exited`.
    pub fn exited(&self) -> bool {
        self.0 & MASK == EXITED
    }

    /// `WaitStatus.Signaled`.
    pub fn signaled(&self) -> bool {
        self.0 & MASK != STOPPED && self.0 & MASK != EXITED
    }

    /// `WaitStatus.Stopped`.
    pub fn stopped(&self) -> bool {
        self.0 & 0xFF == STOPPED
    }

    /// `WaitStatus.Continued`.
    pub fn continued(&self) -> bool {
        self.0 == 0xFFFF
    }

    /// `WaitStatus.CoreDump`.
    pub fn core_dump(&self) -> bool {
        self.signaled() && self.0 & CORE != 0
    }

    /// `WaitStatus.ExitStatus`: -1 unless the process exited.
    pub fn exit_status(&self) -> isize {
        if !self.exited() {
            return -1;
        }
        ((self.0 >> SHIFT) & 0xFF) as isize
    }

    /// `WaitStatus.Signal`: the terminating signal, or -1.
    pub fn signal(&self) -> Signal {
        if !self.signaled() {
            return Signal(-1);
        }
        Signal((self.0 & MASK) as isize)
    }

    /// `WaitStatus.StopSignal`: the stopping signal, or -1.
    pub fn stop_signal(&self) -> Signal {
        if !self.stopped() {
            return Signal(-1);
        }
        Signal(((self.0 >> SHIFT) & 0xFF) as isize)
    }

    /// `WaitStatus.TrapCause`: the ptrace event of a SIGTRAP stop, or -1.
    pub fn trap_cause(&self) -> isize {
        if self.stop_signal() != SIGTRAP {
            return -1;
        }
        ((self.0 >> SHIFT) as isize) >> 8
    }
}
