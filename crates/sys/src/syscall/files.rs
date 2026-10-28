//! The file, memory, identity and ptrace wrappers of `syscall_linux.go`,
//! `syscall_linux_amd64.go` and `syscall_unix.go` that Go writes by hand on
//! top of the generated system calls.
use super::errno::Errno;
use super::types::*;
use super::zsyscall as z;
use super::*;
use std::collections::HashMap;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::sync::Mutex;

const AT_FDCWD: isize = -0x64;
const AT_REMOVEDIR: isize = 0x200;
const AT_SYMLINK_NOFOLLOW: isize = 0x100;
const AT_EACCESS: isize = 0x200;
const AT_EMPTY_PATH: isize = 0x1000;

// ---- plain I/O ----------------------------------------------------------------

/// `syscall.Read`.
pub fn read(fd: isize, p: &mut [u8]) -> Result<isize, Errno> {
    z::read(fd, p)
}

/// `syscall.Write`.
pub fn write(fd: isize, p: &[u8]) -> Result<isize, Errno> {
    z::write(fd, p)
}

/// `syscall.Pread`.
pub fn pread(fd: isize, p: &mut [u8], offset: i64) -> Result<isize, Errno> {
    z::pread(fd, p, offset)
}

/// `syscall.Pwrite`.
pub fn pwrite(fd: isize, p: &[u8], offset: i64) -> Result<isize, Errno> {
    z::pwrite(fd, p, offset)
}

/// `syscall.Stdin`, `Stdout` and `Stderr`.
pub const STDIN: isize = 0;
/// `syscall.Stdout`.
pub const STDOUT: isize = 1;
/// `syscall.Stderr`.
pub const STDERR: isize = 2;

// ---- paths -------------------------------------------------------------------

/// `syscall.Access`.
pub fn access(path: &str, mode: u32) -> Result<(), Errno> {
    faccessat(AT_FDCWD, path, mode, 0)
}

/// `syscall.Chmod`.
pub fn chmod(path: &str, mode: u32) -> Result<(), Errno> {
    fchmodat(AT_FDCWD, path, mode, 0)
}

/// `syscall.Chown`.
pub fn chown(path: &str, uid: isize, gid: isize) -> Result<(), Errno> {
    z::fchownat(AT_FDCWD, path, uid, gid, 0)
}

/// `syscall.Lchown`.
pub fn lchown(path: &str, uid: isize, gid: isize) -> Result<(), Errno> {
    z::fchownat(AT_FDCWD, path, uid, gid, AT_SYMLINK_NOFOLLOW)
}

/// `syscall.Creat`.
pub fn creat(path: &str, mode: u32) -> Result<isize, Errno> {
    open(path, O_CREAT | O_WRONLY | O_TRUNC, mode)
}

/// `syscall.EpollCreate`.
pub fn epoll_create(size: isize) -> Result<isize, Errno> {
    if size <= 0 {
        return Err(EINVAL);
    }
    z::epoll_create1(0)
}

fn is_group_member(gid: isize) -> bool {
    getgroups().is_ok_and(|groups| groups.contains(&gid))
}

fn is_cap_dac_override_set() -> bool {
    const CAP_DAC_OVERRIDE: u32 = 1;
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    // capHeader (version, pid), then two capData of (effective, permitted, inheritable).
    let mut hdr = [LINUX_CAPABILITY_VERSION_3, 0];
    let mut data = [0u32; 6];
    let r = raw::sc(
        SYS_CAPGET,
        [hdr.as_mut_ptr() as usize, data.as_mut_ptr() as usize, 0, 0, 0, 0],
    );
    r.is_ok() && data[0] & (1 << (CAP_DAC_OVERRIDE & 31)) != 0
}

/// `syscall.Faccessat`: with flags, uses `faccessat2` when the kernel has it
/// and otherwise checks the permission bits itself, as the C library does.
pub fn faccessat(dirfd: isize, path: &str, mode: u32, flags: isize) -> Result<(), Errno> {
    if flags == 0 {
        return z::faccessat(dirfd, path, mode);
    }
    match z::faccessat2(dirfd, path, mode, flags) {
        Err(e) if e == ENOSYS || e == EPERM => {}
        other => return other,
    }
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EACCESS) != 0 {
        return Err(EINVAL);
    }
    let mut st = Stat_t::default();
    z::fstatat(dirfd, path, &mut st, flags & AT_SYMLINK_NOFOLLOW)?;
    let mode = mode & 7;
    if mode == 0 {
        return Ok(());
    }
    let mut uid;
    if flags & AT_EACCESS != 0 {
        uid = geteuid();
        if uid != 0 && is_cap_dac_override_set() {
            // CAP_DAC_OVERRIDE makes the kernel check as for root.
            uid = 0;
        }
    } else {
        uid = getuid();
    }
    if uid == 0 {
        if mode & 1 == 0 {
            // Root can read and write any file.
            return Ok(());
        }
        if st.mode & 0o111 != 0 {
            // Root can execute any file that anybody can execute.
            return Ok(());
        }
        return Err(EACCES);
    }
    let fmode = if uid as u32 == st.uid {
        (st.mode >> 6) & 7
    } else {
        let gid = if flags & AT_EACCESS != 0 { getegid() } else { getgid() };
        if gid as u32 == st.gid || is_group_member(st.gid as isize) {
            (st.mode >> 3) & 7
        } else {
            st.mode & 7
        }
    };
    if fmode & mode == mode {
        return Ok(());
    }
    Err(EACCES)
}

/// `syscall.Fchmodat`.
pub fn fchmodat(dirfd: isize, path: &str, mode: u32, flags: isize) -> Result<(), Errno> {
    // Linux fchmodat takes no flags; fchmodat2 does.
    if flags != 0 {
        return match z::fchmodat2(dirfd, path, mode, flags) {
            Err(e) if e == ENOSYS => {
                if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
                    Err(EINVAL)
                } else if flags & (AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
                    Err(EOPNOTSUPP)
                } else {
                    Err(e)
                }
            }
            other => other,
        };
    }
    z::fchmodat(dirfd, path, mode)
}

/// `syscall.Link`.
pub fn link(oldpath: &str, newpath: &str) -> Result<(), Errno> {
    z::linkat(AT_FDCWD, oldpath, AT_FDCWD, newpath, 0)
}

/// `syscall.Mkdir`.
pub fn mkdir(path: &str, mode: u32) -> Result<(), Errno> {
    z::mkdirat(AT_FDCWD, path, mode)
}

/// `syscall.Mknod`.
pub fn mknod(path: &str, mode: u32, dev: isize) -> Result<(), Errno> {
    z::mknodat(AT_FDCWD, path, mode, dev)
}

/// `syscall.Mkfifo`.
pub fn mkfifo(path: &str, mode: u32) -> Result<(), Errno> {
    mknod(path, mode | S_IFIFO as u32, 0)
}

/// `syscall.Open`.
pub fn open(path: &str, mode: isize, perm: u32) -> Result<isize, Errno> {
    z::openat(AT_FDCWD, path, mode | O_LARGEFILE, perm)
}

/// `syscall.Openat`.
pub fn openat(dirfd: isize, path: &str, flags: isize, mode: u32) -> Result<isize, Errno> {
    z::openat(dirfd, path, flags | O_LARGEFILE, mode)
}

/// `syscall.Pipe`: stores the two descriptors in `p`, which must have length 2.
pub fn pipe(p: &mut [isize]) -> Result<(), Errno> {
    pipe2(p, 0)
}

/// `syscall.Pipe2`.
pub fn pipe2(p: &mut [isize], flags: isize) -> Result<(), Errno> {
    if p.len() != 2 {
        return Err(EINVAL);
    }
    let mut pp = [0i32; 2];
    z::pipe2(&mut pp, flags)?;
    p[0] = pp[0] as isize;
    p[1] = pp[1] as isize;
    Ok(())
}

/// `syscall.Readlink`.
pub fn readlink(path: &str, buf: &mut [u8]) -> Result<isize, Errno> {
    z::readlinkat(AT_FDCWD, path, buf)
}

/// `syscall.Rename`.
pub fn rename(oldpath: &str, newpath: &str) -> Result<(), Errno> {
    z::renameat(AT_FDCWD, oldpath, AT_FDCWD, newpath)
}

/// `syscall.Rmdir`.
pub fn rmdir(path: &str) -> Result<(), Errno> {
    z::unlinkat(AT_FDCWD, path, AT_REMOVEDIR)
}

/// `syscall.Symlink`.
pub fn symlink(oldpath: &str, newpath: &str) -> Result<(), Errno> {
    z::symlinkat(oldpath, AT_FDCWD, newpath)
}

/// `syscall.Unlink`.
pub fn unlink(path: &str) -> Result<(), Errno> {
    z::unlinkat(AT_FDCWD, path, 0)
}

/// `syscall.Unlinkat`.
pub fn unlinkat(dirfd: isize, path: &str) -> Result<(), Errno> {
    z::unlinkat(dirfd, path, 0)
}

/// `syscall.Stat`.
pub fn stat(path: &str, stat: &mut Stat_t) -> Result<(), Errno> {
    z::fstatat(AT_FDCWD, path, stat, 0)
}

/// `syscall.Lstat`.
pub fn lstat(path: &str, stat: &mut Stat_t) -> Result<(), Errno> {
    z::fstatat(AT_FDCWD, path, stat, AT_SYMLINK_NOFOLLOW)
}

/// `syscall.Utimes`: `tv` must have length 2.
pub fn utimes(path: &str, tv: &[Timeval]) -> Result<(), Errno> {
    if tv.len() != 2 {
        return Err(EINVAL);
    }
    z::utimes(path, tv.as_ptr() as *mut [Timeval; 2])
}

/// `syscall.UtimesNano`: `ts` must have length 2.
pub fn utimes_nano(path: &str, ts: &[Timespec]) -> Result<(), Errno> {
    if ts.len() != 2 {
        return Err(EINVAL);
    }
    z::utimensat(AT_FDCWD, path, ts.as_ptr() as *mut [Timespec; 2], 0)
}

/// `syscall.Futimesat`: `tv` must have length 2.
pub fn futimesat(dirfd: isize, path: &str, tv: &[Timeval]) -> Result<(), Errno> {
    if tv.len() != 2 {
        return Err(EINVAL);
    }
    z::futimesat(dirfd, path, tv.as_ptr() as *mut [Timeval; 2])
}

/// `syscall.Futimes`: the best Linux offers, and what the C library does.
pub fn futimes(fd: isize, tv: &[Timeval]) -> Result<(), Errno> {
    utimes(&format!("/proc/self/fd/{fd}"), tv)
}

/// `syscall.Getwd`: the working directory, which `Getcwd` writes with a
/// trailing NUL.
pub fn getwd() -> Result<OsString, Errno> {
    let mut buf = [0u8; PATH_MAX as usize];
    let n = z::getcwd(&mut buf)?;
    if n < 1 || n as usize > buf.len() || buf[n as usize - 1] != 0 {
        return Err(EINVAL);
    }
    // Linux can return an "(unreachable)" prefix; a relative path is ENOENT.
    if buf[0] != b'/' {
        return Err(ENOENT);
    }
    Ok(OsString::from_vec(buf[..n as usize - 1].to_vec()))
}

/// `syscall.Getgroups`.
pub fn getgroups() -> Result<Vec<isize>, Errno> {
    let n = z::getgroups(0, std::ptr::null_mut())?;
    if n == 0 {
        return Ok(Vec::new());
    }
    // Sanity check the group count; the maximum is 1<<16 on Linux.
    if !(0..=1 << 20).contains(&n) {
        return Err(EINVAL);
    }
    let mut a = vec![0u32; n as usize];
    let n = z::getgroups(n, a.as_mut_ptr())?;
    Ok(a[..n as usize].iter().map(|&v| v as isize).collect())
}

/// `syscall.Setgroups`: sets the supplementary groups of every thread.
pub fn setgroups(gids: &[isize]) -> Result<(), Errno> {
    let a: Vec<u32> = gids.iter().map(|&g| g as u32).collect();
    let ptr = if a.is_empty() { 0 } else { a.as_ptr() as usize };
    raw::sc_all_threads(SYS_SETGROUPS, [a.len(), ptr, 0, 0, 0, 0]).map(|_| ())
}

fn set_id(trap: usize, args: [usize; 3]) -> Result<(), Errno> {
    raw::sc_all_threads(trap, [args[0], args[1], args[2], 0, 0, 0]).map(|_| ())
}

const MINUS1: usize = usize::MAX;

/// `syscall.Setegid`: for every thread.
pub fn setegid(egid: isize) -> Result<(), Errno> {
    set_id(SYS_SETRESGID, [MINUS1, egid as usize, MINUS1])
}

/// `syscall.Seteuid`: for every thread.
pub fn seteuid(euid: isize) -> Result<(), Errno> {
    set_id(SYS_SETRESUID, [MINUS1, euid as usize, MINUS1])
}

/// `syscall.Setgid`: for every thread.
pub fn setgid(gid: isize) -> Result<(), Errno> {
    set_id(SYS_SETGID, [gid as usize, 0, 0])
}

/// `syscall.Setregid`: for every thread.
pub fn setregid(rgid: isize, egid: isize) -> Result<(), Errno> {
    set_id(SYS_SETREGID, [rgid as usize, egid as usize, 0])
}

/// `syscall.Setresgid`: for every thread.
pub fn setresgid(rgid: isize, egid: isize, sgid: isize) -> Result<(), Errno> {
    set_id(SYS_SETRESGID, [rgid as usize, egid as usize, sgid as usize])
}

/// `syscall.Setresuid`: for every thread.
pub fn setresuid(ruid: isize, euid: isize, suid: isize) -> Result<(), Errno> {
    set_id(SYS_SETRESUID, [ruid as usize, euid as usize, suid as usize])
}

/// `syscall.Setreuid`: for every thread.
pub fn setreuid(ruid: isize, euid: isize) -> Result<(), Errno> {
    set_id(SYS_SETREUID, [ruid as usize, euid as usize, 0])
}

/// `syscall.Setuid`: for every thread.
pub fn setuid(uid: isize) -> Result<(), Errno> {
    set_id(SYS_SETUID, [uid as usize, 0, 0])
}

/// `syscall.Getpgrp`.
pub fn getpgrp() -> isize {
    z::getpgid(0).unwrap_or(0)
}

/// `syscall.Wait4`.
pub fn wait4(
    pid: isize,
    wstatus: Option<&mut WaitStatus>,
    options: isize,
    rusage: Option<&mut Rusage>,
) -> Result<isize, Errno> {
    let mut status: i32 = 0;
    let ru = rusage.map_or(std::ptr::null_mut(), |r| r as *mut Rusage);
    let r = z::wait4(pid, &mut status, options, ru);
    if let Some(w) = wstatus {
        *w = WaitStatus(status as u32);
    }
    r
}

/// `syscall.Reboot`.
pub fn reboot(cmd: isize) -> Result<(), Errno> {
    z::reboot(LINUX_REBOOT_MAGIC1 as usize, LINUX_REBOOT_MAGIC2 as usize, cmd, "")
}

/// `syscall.ReadDirent`.
pub fn read_dirent(fd: isize, buf: &mut [u8]) -> Result<isize, Errno> {
    z::getdents(fd, buf)
}

/// `syscall.Mount`: an empty `data` is passed as NULL, since some file
/// systems reject an empty string.
pub fn mount(source: &str, target: &str, fstype: &str, flags: usize, data: &str) -> Result<(), Errno> {
    if data.is_empty() {
        return z::mount(source, target, fstype, flags, 0);
    }
    let datap = byte_ptr_from_string(data)?;
    z::mount(source, target, fstype, flags, datap.as_ptr() as usize)
}

/// `syscall.Gettimeofday`.
pub fn gettimeofday(tv: &mut Timeval) -> Result<(), Errno> {
    raw::sc(SYS_GETTIMEOFDAY, [tv as *mut Timeval as usize, 0, 0, 0, 0, 0]).map(|_| ())
}

/// `syscall.Time`: the seconds since the epoch, also stored in `t` if given.
pub fn time(t: Option<&mut Time_t>) -> Result<Time_t, Errno> {
    let mut tv = Timeval::default();
    gettimeofday(&mut tv)?;
    if let Some(t) = t {
        *t = tv.sec;
    }
    Ok(tv.sec)
}

/// `syscall.FcntlFlock`.
pub fn fcntl_flock(fd: usize, cmd: isize, lk: &mut Flock_t) -> Result<(), Errno> {
    raw::sc(SYS_FCNTL, [fd, cmd as usize, lk as *mut Flock_t as usize, 0, 0, 0]).map(|_| ())
}

/// `syscall.Getrlimit`.
pub fn getrlimit(resource: isize, rlim: &mut Rlimit) -> Result<(), Errno> {
    z::prlimit1(0, resource, std::ptr::null_mut(), rlim)
}

/// `syscall.Setrlimit`.
pub fn setrlimit(resource: isize, rlim: &Rlimit) -> Result<(), Errno> {
    z::prlimit1(0, resource, rlim as *const Rlimit as *mut Rlimit, std::ptr::null_mut())
}

// ---- memory mappings ----------------------------------------------------------

/// The active mappings of `Mmap`, by start address, with their lengths.
static MAPPINGS: Mutex<Option<HashMap<usize, usize>>> = Mutex::new(None);

/// `syscall.Mmap`: maps `length` bytes of `fd` at `offset`. The memory is
/// valid until [`munmap`] is called with the returned slice.
pub fn mmap(
    fd: isize,
    offset: i64,
    length: isize,
    prot: isize,
    flags: isize,
) -> Result<&'static mut [u8], Errno> {
    if length <= 0 {
        return Err(EINVAL);
    }
    let addr = z::mmap(0, length as usize, prot, flags, fd, offset)?;
    let b = crate::ffi::syscall::mapped_slice(addr, length as usize);
    let mut g = MAPPINGS.lock().unwrap_or_else(|e| e.into_inner());
    g.get_or_insert_with(HashMap::new).insert(addr, length as usize);
    Ok(b)
}

/// `syscall.Munmap`: unmaps a slice returned by [`mmap`] whole.
pub fn munmap(b: &mut [u8]) -> Result<(), Errno> {
    if b.is_empty() {
        return Err(EINVAL);
    }
    let addr = b.as_ptr() as usize;
    let mut g = MAPPINGS.lock().unwrap_or_else(|e| e.into_inner());
    let map = g.get_or_insert_with(HashMap::new);
    match map.get(&addr) {
        Some(&len) if len == b.len() => {}
        _ => return Err(EINVAL),
    }
    z::munmap(addr, b.len())?;
    map.remove(&addr);
    Ok(())
}

// ---- ptrace -----------------------------------------------------------------

const WORD: usize = 8;

fn ptrace_peek(req: isize, pid: isize, addr: usize, out: &mut [u8]) -> Result<isize, Errno> {
    // The peek requests work on machine words, and the ptrace system call
    // (unlike the C library's) stores the word at *data.
    let mut buf = [0u8; WORD];
    let mut n = 0usize;
    let mut out = out;
    // Leading edge: align the first read so it cannot straddle a page.
    if !addr.is_multiple_of(WORD) {
        z::ptrace_ptr(req, pid, addr - addr % WORD, buf.as_mut_ptr() as usize)?;
        let copied = out.len().min(WORD - addr % WORD);
        out[..copied].copy_from_slice(&buf[addr % WORD..addr % WORD + copied]);
        n += copied;
        out = &mut out[copied..];
    }
    while !out.is_empty() {
        z::ptrace_ptr(req, pid, addr + n, buf.as_mut_ptr() as usize)?;
        let copied = out.len().min(WORD);
        out[..copied].copy_from_slice(&buf[..copied]);
        n += copied;
        out = &mut out[copied..];
    }
    Ok(n as isize)
}

/// `syscall.PtracePeekText`.
pub fn ptrace_peek_text(pid: isize, addr: usize, out: &mut [u8]) -> Result<isize, Errno> {
    ptrace_peek(PTRACE_PEEKTEXT, pid, addr, out)
}

/// `syscall.PtracePeekData`.
pub fn ptrace_peek_data(pid: isize, addr: usize, out: &mut [u8]) -> Result<isize, Errno> {
    ptrace_peek(PTRACE_PEEKDATA, pid, addr, out)
}

fn ptrace_poke(
    poke_req: isize,
    peek_req: isize,
    pid: isize,
    addr: usize,
    data: &[u8],
) -> Result<isize, Errno> {
    let mut n = 0usize;
    let mut data = data;
    // Leading edge: read the word, patch it and write it back.
    if !addr.is_multiple_of(WORD) {
        let mut buf = [0u8; WORD];
        z::ptrace_ptr(peek_req, pid, addr - addr % WORD, buf.as_mut_ptr() as usize)?;
        let copied = data.len().min(WORD - addr % WORD);
        buf[addr % WORD..addr % WORD + copied].copy_from_slice(&data[..copied]);
        n += copied;
        z::ptrace(poke_req, pid, addr - addr % WORD, usize::from_ne_bytes(buf))?;
        data = &data[copied..];
    }
    // Interior whole words.
    while data.len() > WORD {
        let mut w = [0u8; WORD];
        w.copy_from_slice(&data[..WORD]);
        z::ptrace(poke_req, pid, addr + n, usize::from_ne_bytes(w))?;
        n += WORD;
        data = &data[WORD..];
    }
    // Trailing edge.
    if !data.is_empty() {
        let mut buf = [0u8; WORD];
        z::ptrace_ptr(peek_req, pid, addr + n, buf.as_mut_ptr() as usize)?;
        buf[..data.len()].copy_from_slice(data);
        z::ptrace(poke_req, pid, addr + n, usize::from_ne_bytes(buf))?;
        n += data.len();
    }
    Ok(n as isize)
}

/// `syscall.PtracePokeText`.
pub fn ptrace_poke_text(pid: isize, addr: usize, data: &[u8]) -> Result<isize, Errno> {
    ptrace_poke(PTRACE_POKETEXT, PTRACE_PEEKTEXT, pid, addr, data)
}

/// `syscall.PtracePokeData`.
pub fn ptrace_poke_data(pid: isize, addr: usize, data: &[u8]) -> Result<isize, Errno> {
    ptrace_poke(PTRACE_POKEDATA, PTRACE_PEEKDATA, pid, addr, data)
}

const NT_PRSTATUS: usize = 1;

/// `syscall.PtraceGetRegs`.
pub fn ptrace_get_regs(pid: isize, regsout: &mut PtraceRegs) -> Result<(), Errno> {
    let mut iov = Iovec {
        base: regsout as *mut PtraceRegs as *mut u8,
        ..Iovec::default()
    };
    iov.set_len(std::mem::size_of::<PtraceRegs>() as isize);
    z::ptrace_ptr(PTRACE_GETREGSET, pid, NT_PRSTATUS, &mut iov as *mut Iovec as usize)
}

/// `syscall.PtraceSetRegs`.
pub fn ptrace_set_regs(pid: isize, regs: &PtraceRegs) -> Result<(), Errno> {
    let mut iov = Iovec {
        base: regs as *const PtraceRegs as *mut u8,
        ..Iovec::default()
    };
    iov.set_len(std::mem::size_of::<PtraceRegs>() as isize);
    z::ptrace_ptr(PTRACE_SETREGSET, pid, NT_PRSTATUS, &mut iov as *mut Iovec as usize)
}

/// `syscall.PtraceSetOptions`.
pub fn ptrace_set_options(pid: isize, options: isize) -> Result<(), Errno> {
    z::ptrace(PTRACE_SETOPTIONS, pid, 0, options as usize)
}

/// `syscall.PtraceGetEventMsg`.
pub fn ptrace_get_event_msg(pid: isize) -> Result<usize, Errno> {
    let mut data: i64 = 0;
    z::ptrace_ptr(PTRACE_GETEVENTMSG, pid, 0, &mut data as *mut i64 as usize)?;
    Ok(data as usize)
}

/// `syscall.PtraceCont`.
pub fn ptrace_cont(pid: isize, signal: isize) -> Result<(), Errno> {
    z::ptrace(PTRACE_CONT, pid, 0, signal as usize)
}

/// `syscall.PtraceSyscall`.
pub fn ptrace_syscall(pid: isize, signal: isize) -> Result<(), Errno> {
    z::ptrace(PTRACE_SYSCALL, pid, 0, signal as usize)
}

/// `syscall.PtraceSingleStep`.
pub fn ptrace_single_step(pid: isize) -> Result<(), Errno> {
    z::ptrace(PTRACE_SINGLESTEP, pid, 0, 0)
}

/// `syscall.PtraceAttach`.
pub fn ptrace_attach(pid: isize) -> Result<(), Errno> {
    z::ptrace(PTRACE_ATTACH, pid, 0, 0)
}

/// `syscall.PtraceDetach`.
pub fn ptrace_detach(pid: isize) -> Result<(), Errno> {
    z::ptrace(PTRACE_DETACH, pid, 0, 0)
}
