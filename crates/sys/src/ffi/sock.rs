//! Sockets, polling and descriptors: the libc functions behind `net`.
use crate::errno::{Errno, EINVAL};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::raw::{c_int, c_void};

/// Per-target constants (values from Go's `zerrors_*` tables).
pub mod k {
    use std::os::raw::c_int;

    #[cfg(target_os = "linux")]
    pub const SOL_SOCKET: c_int = 1;
    #[cfg(target_os = "macos")]
    pub const SOL_SOCKET: c_int = 0xffff;
    #[cfg(target_os = "linux")]
    pub const SO_REUSEADDR: c_int = 2;
    #[cfg(target_os = "macos")]
    pub const SO_REUSEADDR: c_int = 4;
    #[cfg(target_os = "linux")]
    pub const SO_TYPE: c_int = 3;
    #[cfg(target_os = "macos")]
    pub const SO_TYPE: c_int = 0x1008;
    #[cfg(target_os = "linux")]
    pub const SO_ERROR: c_int = 4;
    #[cfg(target_os = "macos")]
    pub const SO_ERROR: c_int = 0x1007;
    #[cfg(target_os = "linux")]
    pub const SO_BROADCAST: c_int = 6;
    #[cfg(target_os = "macos")]
    pub const SO_BROADCAST: c_int = 0x20;
    #[cfg(target_os = "linux")]
    pub const SO_SNDBUF: c_int = 7;
    #[cfg(target_os = "macos")]
    pub const SO_SNDBUF: c_int = 0x1001;
    #[cfg(target_os = "linux")]
    pub const SO_RCVBUF: c_int = 8;
    #[cfg(target_os = "macos")]
    pub const SO_RCVBUF: c_int = 0x1002;
    #[cfg(target_os = "linux")]
    pub const SO_KEEPALIVE: c_int = 9;
    #[cfg(target_os = "macos")]
    pub const SO_KEEPALIVE: c_int = 8;
    #[cfg(target_os = "linux")]
    pub const SO_LINGER: c_int = 13;
    #[cfg(target_os = "macos")]
    pub const SO_LINGER: c_int = 0x80;

    #[cfg(target_os = "linux")]
    pub const IPV6_V6ONLY: c_int = 26;
    #[cfg(target_os = "macos")]
    pub const IPV6_V6ONLY: c_int = 27;
    #[cfg(target_os = "macos")]
    pub const SO_REUSEPORT: c_int = 0x200;

    pub const IPPROTO_IP: c_int = 0;
    pub const IPPROTO_TCP: c_int = 6;
    pub const IPPROTO_IPV6: c_int = 41;
    #[cfg(target_os = "linux")]
    pub const IPPROTO_MPTCP: c_int = 262;

    #[cfg(target_os = "linux")]
    pub const IP_RECVTTL: c_int = 12;
    #[cfg(target_os = "macos")]
    pub const IP_RECVTTL: c_int = 0x18;

    #[cfg(target_os = "linux")]
    pub const IP_MULTICAST_IF: c_int = 32;
    #[cfg(target_os = "macos")]
    pub const IP_MULTICAST_IF: c_int = 9;
    #[cfg(target_os = "linux")]
    pub const IP_MULTICAST_LOOP: c_int = 34;
    #[cfg(target_os = "macos")]
    pub const IP_MULTICAST_LOOP: c_int = 11;
    #[cfg(target_os = "linux")]
    pub const IP_ADD_MEMBERSHIP: c_int = 35;
    #[cfg(target_os = "macos")]
    pub const IP_ADD_MEMBERSHIP: c_int = 12;
    #[cfg(target_os = "linux")]
    pub const IPV6_MULTICAST_IF: c_int = 17;
    #[cfg(target_os = "macos")]
    pub const IPV6_MULTICAST_IF: c_int = 9;
    #[cfg(target_os = "linux")]
    pub const IPV6_MULTICAST_LOOP: c_int = 19;
    #[cfg(target_os = "macos")]
    pub const IPV6_MULTICAST_LOOP: c_int = 11;
    #[cfg(target_os = "linux")]
    pub const IPV6_JOIN_GROUP: c_int = 20;
    #[cfg(target_os = "macos")]
    pub const IPV6_JOIN_GROUP: c_int = 12;

    pub const TCP_NODELAY: c_int = 1;
    #[cfg(target_os = "linux")]
    pub const TCP_KEEPIDLE: c_int = 4;
    #[cfg(target_os = "macos")]
    pub const TCP_KEEPIDLE: c_int = 0x10;
    #[cfg(target_os = "linux")]
    pub const TCP_KEEPINTVL: c_int = 5;
    #[cfg(target_os = "macos")]
    pub const TCP_KEEPINTVL: c_int = 0x101;
    #[cfg(target_os = "linux")]
    pub const TCP_KEEPCNT: c_int = 6;
    #[cfg(target_os = "macos")]
    pub const TCP_KEEPCNT: c_int = 0x102;

    pub const AF_UNIX: c_int = 1;
    pub const AF_INET: c_int = 2;
    #[cfg(target_os = "linux")]
    pub const AF_INET6: c_int = 10;
    #[cfg(target_os = "macos")]
    pub const AF_INET6: c_int = 30;

    pub const SOCK_STREAM: c_int = 1;
    pub const SOCK_DGRAM: c_int = 2;
    pub const SOCK_RAW: c_int = 3;
    pub const SOCK_SEQPACKET: c_int = 5;

    pub const SHUT_RD: c_int = 0;
    pub const SHUT_WR: c_int = 1;

    pub const F_GETFD: c_int = 1;
    pub const F_SETFD: c_int = 2;
    pub const F_GETFL: c_int = 3;
    pub const F_SETFL: c_int = 4;
    pub const FD_CLOEXEC: c_int = 1;
    #[cfg(target_os = "linux")]
    pub const O_NONBLOCK: c_int = 0o4000;
    #[cfg(target_os = "macos")]
    pub const O_NONBLOCK: c_int = 4;

    pub const POLLIN: i16 = 0x1;
    pub const POLLOUT: i16 = 0x4;
    pub const POLLERR: i16 = 0x8;
    pub const POLLHUP: i16 = 0x10;
    pub const POLLNVAL: i16 = 0x20;

    #[cfg(target_os = "linux")]
    pub const MSG_CMSG_CLOEXEC: c_int = 0x4000_0000;
    #[cfg(target_os = "macos")]
    pub const MSG_CMSG_CLOEXEC: c_int = 0;
    #[cfg(target_os = "linux")]
    pub const MSG_NOSIGNAL: c_int = 0x4000;
    #[cfg(target_os = "macos")]
    pub const MSG_NOSIGNAL: c_int = 0;
}

mod c {
    use super::*;

    #[repr(C)]
    pub struct PollFd {
        pub fd: c_int,
        pub events: i16,
        pub revents: i16,
    }

    #[repr(C)]
    pub struct IoVec {
        pub base: *mut c_void,
        pub len: usize,
    }

    #[cfg(target_os = "linux")]
    #[repr(C)]
    pub struct MsgHdr {
        pub name: *mut c_void,
        pub namelen: u32,
        pub iov: *mut IoVec,
        pub iovlen: usize,
        pub control: *mut c_void,
        pub controllen: usize,
        pub flags: c_int,
    }

    #[cfg(target_os = "macos")]
    #[repr(C)]
    pub struct MsgHdr {
        pub name: *mut c_void,
        pub namelen: u32,
        pub iov: *mut IoVec,
        pub iovlen: c_int,
        pub control: *mut c_void,
        pub controllen: u32,
        pub flags: c_int,
    }

    #[cfg(target_os = "linux")]
    pub type NfdsT = std::os::raw::c_ulong;
    #[cfg(target_os = "macos")]
    pub type NfdsT = std::os::raw::c_uint;

    extern "C" {
        pub fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
        pub fn bind(fd: c_int, addr: *const c_void, len: u32) -> c_int;
        pub fn connect(fd: c_int, addr: *const c_void, len: u32) -> c_int;
        pub fn listen(fd: c_int, backlog: c_int) -> c_int;
        pub fn accept(fd: c_int, addr: *mut c_void, len: *mut u32) -> c_int;
        pub fn getsockname(fd: c_int, addr: *mut c_void, len: *mut u32) -> c_int;
        pub fn getpeername(fd: c_int, addr: *mut c_void, len: *mut u32) -> c_int;
        pub fn setsockopt(
            fd: c_int,
            level: c_int,
            name: c_int,
            value: *const c_void,
            len: u32,
        ) -> c_int;
        pub fn getsockopt(
            fd: c_int,
            level: c_int,
            name: c_int,
            value: *mut c_void,
            len: *mut u32,
        ) -> c_int;
        pub fn shutdown(fd: c_int, how: c_int) -> c_int;
        pub fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
        pub fn poll(fds: *mut PollFd, nfds: NfdsT, timeout: c_int) -> c_int;
        #[cfg(not(target_os = "linux"))]
        pub fn pipe(fds: *mut c_int) -> c_int;
        #[cfg(target_os = "linux")]
        pub fn pipe2(fds: *mut c_int, flags: c_int) -> c_int;
        pub fn dup(fd: c_int) -> c_int;
        #[cfg(target_os = "macos")]
        pub fn isatty(fd: c_int) -> c_int;
        #[cfg(target_os = "macos")]
        pub fn sysctlbyname(
            name: *const std::os::raw::c_char,
            oldp: *mut c_void,
            oldlenp: *mut usize,
            newp: *mut c_void,
            newlen: usize,
        ) -> c_int;
        pub fn sendmsg(fd: c_int, msg: *const MsgHdr, flags: c_int) -> isize;
        pub fn recvmsg(fd: c_int, msg: *mut MsgHdr, flags: c_int) -> isize;
        pub fn read(fd: c_int, buf: *mut c_void, len: usize) -> isize;
        pub fn write(fd: c_int, buf: *const c_void, len: usize) -> isize;
    }
}

pub fn check(r: c_int) -> Result<c_int, Errno> {
    if r < 0 {
        Err(Errno::last())
    } else {
        Ok(r)
    }
}

/// An owned file descriptor, closed on drop.
#[derive(Debug)]
pub struct Fd(OwnedFd);

impl Fd {
    pub fn raw(&self) -> RawFd {
        std::os::fd::AsRawFd::as_raw_fd(&self.0)
    }

    pub fn from_owned(fd: OwnedFd) -> Fd {
        Fd(fd)
    }

    pub fn into_owned(self) -> OwnedFd {
        self.0
    }

    /// A new descriptor for the same open file (`dup`).
    pub fn try_clone(&self) -> Result<Fd, Errno> {
        dup(self.raw())
    }
}

/// An owned descriptor from a successful call.
fn owned(fd: c_int) -> Fd {
    // SAFETY: `fd` was just returned by a successful call that creates a new
    // descriptor, so nothing else owns it.
    Fd(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Go's `syscall.ForkLock`: creating a descriptor and marking it close-on-exec
/// are two calls on macOS, so a `fork` in another thread must not run between
/// them. Creators hold the read side; `fork_exec` holds the write side.
pub static FORK_LOCK: std::sync::RwLock<()> = std::sync::RwLock::new(());

/// The read side of [`FORK_LOCK`].
fn creating() -> std::sync::RwLockReadGuard<'static, ()> {
    FORK_LOCK.read().unwrap_or_else(|e| e.into_inner())
}

/// Sets `FD_CLOEXEC` on a descriptor.
pub fn set_cloexec(fd: c_int) -> Result<(), Errno> {
    // SAFETY: F_GETFD/F_SETFD take only integer arguments.
    unsafe {
        let flags = check(c::fcntl(fd, k::F_GETFD))?;
        check(c::fcntl(fd, k::F_SETFD, flags | k::FD_CLOEXEC))?;
    }
    Ok(())
}

/// A socket address in the kernel's `sockaddr` form.
#[derive(Clone)]
pub struct SockAddr {
    storage: Storage,
    len: u32,
}

#[repr(C, align(8))]
#[derive(Clone)]
struct Storage([u8; 128]);

impl SockAddr {
    fn blank() -> SockAddr {
        SockAddr {
            storage: Storage([0; 128]),
            len: 128,
        }
    }

    fn set_family(&mut self, family: c_int, len: u8) {
        #[cfg(target_os = "macos")]
        {
            self.storage.0[0] = len;
            self.storage.0[1] = family as u8;
        }
        #[cfg(target_os = "linux")]
        {
            let _ = len;
            self.storage.0[..2].copy_from_slice(&(family as u16).to_ne_bytes());
        }
    }

    /// The address bytes as the kernel lays them out.
    pub fn bytes(&self) -> &[u8] {
        &self.storage.0[..self.len as usize]
    }

    /// An IPv4 or IPv6 address and port (port 0 for raw IP sockets).
    pub fn from_inet(addr: SocketAddr) -> SockAddr {
        let mut sa = SockAddr::blank();
        match addr {
            SocketAddr::V4(a) => {
                sa.set_family(k::AF_INET, 16);
                sa.storage.0[2..4].copy_from_slice(&a.port().to_be_bytes());
                sa.storage.0[4..8].copy_from_slice(&a.ip().octets());
                sa.len = 16;
            }
            SocketAddr::V6(a) => {
                sa.set_family(k::AF_INET6, 28);
                sa.storage.0[2..4].copy_from_slice(&a.port().to_be_bytes());
                sa.storage.0[4..8].copy_from_slice(&a.flowinfo().to_ne_bytes());
                sa.storage.0[8..24].copy_from_slice(&a.ip().octets());
                sa.storage.0[24..28].copy_from_slice(&a.scope_id().to_ne_bytes());
                sa.len = 28;
            }
        }
        sa
    }

    /// A Unix-domain address: a path, or on Linux an abstract name starting
    /// with a NUL byte.
    pub fn from_unix(path: &[u8]) -> Result<SockAddr, Errno> {
        #[cfg(target_os = "macos")]
        const MAX: usize = 104;
        #[cfg(target_os = "linux")]
        const MAX: usize = 108;
        let abstract_name = cfg!(target_os = "linux") && path.first() == Some(&0);
        if path.len() > MAX || (path.len() == MAX && !abstract_name) {
            return Err(EINVAL);
        }
        let mut sa = SockAddr::blank();
        sa.set_family(k::AF_UNIX, 0);
        sa.storage.0[2..2 + path.len()].copy_from_slice(path);
        let mut len = 2 + path.len();
        if !path.is_empty() && !abstract_name {
            len += 1;
        }
        #[cfg(target_os = "macos")]
        {
            sa.storage.0[0] = len as u8;
        }
        sa.len = len as u32;
        Ok(sa)
    }

    fn family(&self) -> c_int {
        #[cfg(target_os = "macos")]
        {
            self.storage.0[1] as c_int
        }
        #[cfg(target_os = "linux")]
        {
            u16::from_ne_bytes([self.storage.0[0], self.storage.0[1]]) as c_int
        }
    }

    /// The IP address and port, for AF_INET and AF_INET6 addresses.
    pub fn to_inet(&self) -> Option<SocketAddr> {
        let b = &self.storage.0;
        let port = u16::from_be_bytes([b[2], b[3]]);
        match self.family() {
            k::AF_INET => Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(b[4], b[5], b[6], b[7]),
                port,
            ))),
            k::AF_INET6 => {
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&b[8..24]);
                let flow = u32::from_ne_bytes([b[4], b[5], b[6], b[7]]);
                let scope = u32::from_ne_bytes([b[24], b[25], b[26], b[27]]);
                Some(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(ip),
                    port,
                    flow,
                    scope,
                )))
            }
            _ => None,
        }
    }

    /// The path of an AF_UNIX address. A leading NUL marks an abstract name
    /// and, on Linux, an unnamed address (Go reads the zeroed path and shows
    /// both with '@'); an unnamed address is empty elsewhere.
    pub fn to_unix(&self) -> Option<Vec<u8>> {
        if self.family() != k::AF_UNIX {
            return None;
        }
        let len = (self.len as usize).clamp(2, 128);
        if cfg!(target_os = "linux") && len == 2 {
            return Some(vec![0]);
        }
        let mut path = self.storage.0[2..len].to_vec();
        // Only Linux has abstract names, marked by a leading NUL byte; macOS
        // pads an unnamed address with NULs.
        let abstract_name = cfg!(target_os = "linux") && path.first() == Some(&0);
        if !abstract_name {
            if let Some(end) = path.iter().position(|&b| b == 0) {
                path.truncate(end);
            }
        }
        Some(path)
    }

    /// The raw `sa_family` value.
    pub fn raw_family(&self) -> i32 {
        self.family()
    }
}

pub fn socket(domain: i32, ty: i32, protocol: i32) -> Result<Fd, Errno> {
    let _fork = creating();
    // SAFETY: socket takes three integers and touches no memory.
    let fd = check(unsafe { c::socket(domain, ty, protocol) })?;
    let fd = owned(fd);
    set_cloexec(fd.raw())?;
    Ok(fd)
}

pub fn bind(fd: RawFd, addr: &SockAddr) -> Result<(), Errno> {
    // SAFETY: `addr` holds `len` initialised bytes of sockaddr data.
    check(unsafe { c::bind(fd, addr.storage.0.as_ptr().cast(), addr.len) }).map(|_| ())
}

pub fn connect(fd: RawFd, addr: &SockAddr) -> Result<(), Errno> {
    // SAFETY: `addr` holds `len` initialised bytes of sockaddr data.
    check(unsafe { c::connect(fd, addr.storage.0.as_ptr().cast(), addr.len) }).map(|_| ())
}

pub fn listen(fd: RawFd, backlog: i32) -> Result<(), Errno> {
    // SAFETY: listen takes two integers and touches no memory.
    check(unsafe { c::listen(fd, backlog) }).map(|_| ())
}

pub fn accept(fd: RawFd) -> Result<(Fd, SockAddr), Errno> {
    let mut sa = SockAddr::blank();
    // SAFETY: the address buffer is 128 writable bytes and `len` says so.
    let new = check(unsafe { c::accept(fd, sa.storage.0.as_mut_ptr().cast(), &mut sa.len) })?;
    let new = owned(new);
    set_cloexec(new.raw())?;
    Ok((new, sa))
}

pub fn getsockname(fd: RawFd) -> Result<SockAddr, Errno> {
    let mut sa = SockAddr::blank();
    // SAFETY: the address buffer is 128 writable bytes and `len` says so.
    check(unsafe { c::getsockname(fd, sa.storage.0.as_mut_ptr().cast(), &mut sa.len) })?;
    Ok(sa)
}

pub fn getpeername(fd: RawFd) -> Result<SockAddr, Errno> {
    let mut sa = SockAddr::blank();
    // SAFETY: the address buffer is 128 writable bytes and `len` says so.
    check(unsafe { c::getpeername(fd, sa.storage.0.as_mut_ptr().cast(), &mut sa.len) })?;
    Ok(sa)
}

pub fn setsockopt(fd: RawFd, level: i32, name: i32, value: &[u8]) -> Result<(), Errno> {
    // SAFETY: `value` is readable for its length, which is passed.
    check(unsafe { c::setsockopt(fd, level, name, value.as_ptr().cast(), value.len() as u32) })
        .map(|_| ())
}

/// Reads an option into `buf`, returning the number of bytes the kernel wrote.
pub fn getsockopt(fd: RawFd, level: i32, name: i32, buf: &mut [u8]) -> Result<usize, Errno> {
    let mut len = buf.len() as u32;
    // SAFETY: `buf` is writable for `len` bytes and `len` is updated in place.
    check(unsafe { c::getsockopt(fd, level, name, buf.as_mut_ptr().cast(), &mut len) })?;
    Ok(len as usize)
}

pub fn shutdown(fd: RawFd, how: i32) -> Result<(), Errno> {
    // SAFETY: shutdown takes two integers and touches no memory.
    check(unsafe { c::shutdown(fd, how) }).map(|_| ())
}

pub fn set_nonblocking(fd: RawFd, on: bool) -> Result<(), Errno> {
    // SAFETY: F_GETFL/F_SETFL take only integer arguments.
    unsafe {
        let flags = check(c::fcntl(fd, k::F_GETFL))?;
        let new = if on {
            flags | k::O_NONBLOCK
        } else {
            flags & !k::O_NONBLOCK
        };
        if new != flags {
            check(c::fcntl(fd, k::F_SETFL, new))?;
        }
    }
    Ok(())
}

pub fn is_nonblocking(fd: RawFd) -> Result<bool, Errno> {
    // SAFETY: F_GETFL takes only integer arguments.
    let flags = check(unsafe { c::fcntl(fd, k::F_GETFL) })?;
    Ok(flags & k::O_NONBLOCK != 0)
}

/// The system's listen backlog limit (`kern.ipc.somaxconn` or
/// `/proc/sys/net/core/somaxconn`), as Go's `maxListenerBacklog`; 128
/// (`SOMAXCONN`) when it cannot be read.
#[cfg(target_os = "linux")]
pub fn somaxconn() -> i32 {
    let read = || -> Option<u64> {
        let text = std::fs::read_to_string("/proc/sys/net/core/somaxconn").ok()?;
        text.split_whitespace().next()?.parse().ok()
    };
    match read() {
        None | Some(0) => 128,
        Some(n) => n.min(i32::MAX as u64) as i32,
    }
}

/// See the Linux version.
#[cfg(target_os = "macos")]
pub fn somaxconn() -> i32 {
    let Ok(name) = std::ffi::CString::new("kern.ipc.somaxconn") else {
        return 128;
    };
    let mut value: u32 = 0;
    let mut len = std::mem::size_of::<u32>();
    // SAFETY: `name` is NUL-terminated and `value` is a writable u32 of the
    // `len` bytes passed.
    let r = unsafe {
        c::sysctlbyname(
            name.as_ptr(),
            (&mut value as *mut u32).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if r < 0 || value == 0 {
        128
    } else {
        value.min(65535) as i32
    }
}

/// `isatty(3)`: whether the descriptor is a terminal.
#[cfg(target_os = "macos")]
pub fn isatty(fd: RawFd) -> bool {
    // SAFETY: isatty takes one integer and touches no memory.
    unsafe { c::isatty(fd) == 1 }
}

pub fn dup(fd: RawFd) -> Result<Fd, Errno> {
    let _fork = creating();
    // SAFETY: dup takes one integer and touches no memory.
    let new = owned(check(unsafe { c::dup(fd) })?);
    set_cloexec(new.raw())?;
    Ok(new)
}

/// A pipe: (read end, write end).
pub fn pipe() -> Result<(Fd, Fd), Errno> {
    let _fork = creating();
    let mut fds = [0 as c_int; 2];
    // Linux sets close-on-exec atomically with pipe2(2); elsewhere pipe(2)
    // is followed by fcntl while `creating` holds off concurrent spawns.
    #[cfg(target_os = "linux")]
    {
        const O_CLOEXEC: c_int = 0o2_000_000;
        // SAFETY: `fds` has room for the two descriptors pipe2 writes.
        check(unsafe { c::pipe2(fds.as_mut_ptr(), O_CLOEXEC) })?;
        Ok((owned(fds[0]), owned(fds[1])))
    }
    #[cfg(not(target_os = "linux"))]
    {
        // SAFETY: `fds` has room for the two descriptors pipe writes.
        check(unsafe { c::pipe(fds.as_mut_ptr()) })?;
        let (r, w) = (owned(fds[0]), owned(fds[1]));
        set_cloexec(r.raw())?;
        set_cloexec(w.raw())?;
        Ok((r, w))
    }
}

/// What `poll` reports for one descriptor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ready {
    pub readable: bool,
    pub writable: bool,
    pub error: bool,
    pub hangup: bool,
    pub invalid: bool,
}

/// Polls descriptors for `(fd, want_write)`; `timeout_ms < 0` waits forever.
/// EINTR is retried by the caller.
pub fn poll(fds: &[(RawFd, bool)], timeout_ms: i32) -> Result<Vec<Ready>, Errno> {
    let mut list: Vec<c::PollFd> = fds
        .iter()
        .map(|&(fd, write)| c::PollFd {
            fd,
            events: if write { k::POLLOUT } else { k::POLLIN },
            revents: 0,
        })
        .collect();
    // SAFETY: `list` is a valid array of `list.len()` pollfd structures.
    check(unsafe { c::poll(list.as_mut_ptr(), list.len() as _, timeout_ms) })?;
    Ok(list
        .iter()
        .map(|p| Ready {
            readable: p.revents & k::POLLIN != 0,
            writable: p.revents & k::POLLOUT != 0,
            error: p.revents & k::POLLERR != 0,
            hangup: p.revents & k::POLLHUP != 0,
            invalid: p.revents & k::POLLNVAL != 0,
        })
        .collect())
}

/// `read(2)`; a would-block result is the `EAGAIN` error.
pub fn read(fd: RawFd, buf: &mut [u8]) -> Result<usize, Errno> {
    // SAFETY: `buf` is writable for its length, which is passed.
    let n = unsafe { c::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        Err(Errno::last())
    } else {
        Ok(n as usize)
    }
}

/// `write(2)`; a would-block result is the `EAGAIN` error.
pub fn write(fd: RawFd, buf: &[u8]) -> Result<usize, Errno> {
    // SAFETY: `buf` is readable for its length, which is passed.
    let n = unsafe { c::write(fd, buf.as_ptr().cast(), buf.len()) };
    if n < 0 {
        Err(Errno::last())
    } else {
        Ok(n as usize)
    }
}

/// The result of [`recvmsg`].
pub struct Received {
    pub n: usize,
    pub oobn: usize,
    pub flags: i32,
    pub from: Option<SockAddr>,
}

/// Whether Go (syscall.Recvmsg / Sendmsg) moves one dummy byte so that
/// ancillary data can travel with an empty payload: always on the BSDs,
/// on Linux for everything but datagram sockets.
fn needs_dummy_byte(fd: RawFd, payload: usize, oob: usize) -> Result<bool, Errno> {
    if oob == 0 || payload != 0 {
        return Ok(false);
    }
    if cfg!(target_os = "linux") {
        let mut ty = [0u8; 4];
        getsockopt(fd, k::SOL_SOCKET, k::SO_TYPE, &mut ty)?;
        return Ok(i32::from_ne_bytes(ty) != k::SOCK_DGRAM);
    }
    Ok(true)
}

/// `recvmsg(2)` into `buf` with ancillary data into `oob`.
pub fn recvmsg(fd: RawFd, buf: &mut [u8], oob: &mut [u8], flags: i32) -> Result<Received, Errno> {
    let mut name = SockAddr::blank();
    let mut dummy = 0u8;
    let (base, len): (*mut c_void, usize) = if needs_dummy_byte(fd, buf.len(), oob.len())? {
        ((&mut dummy as *mut u8).cast(), 1)
    } else if buf.is_empty() {
        (std::ptr::null_mut(), 0)
    } else {
        (buf.as_mut_ptr().cast(), buf.len())
    };
    let mut iov = c::IoVec { base, len };
    let mut hdr = c::MsgHdr {
        name: name.storage.0.as_mut_ptr().cast(),
        namelen: 128,
        iov: &mut iov,
        iovlen: 1,
        control: if oob.is_empty() {
            std::ptr::null_mut()
        } else {
            oob.as_mut_ptr().cast()
        },
        controllen: oob.len() as _,
        flags: 0,
    };
    // SAFETY: `hdr` points at live, writable buffers (`name`, `iov` which in
    // turn points at `buf` or `dummy`, and `oob`) whose lengths it records.
    let n = unsafe { c::recvmsg(fd, &mut hdr, flags) };
    if n < 0 {
        return Err(Errno::last());
    }
    name.len = hdr.namelen;
    // Like Go, judge by the family the kernel stored, not by the length.
    let has_sender = name.family() != 0;
    Ok(Received {
        n: n as usize,
        oobn: hdr.controllen as usize,
        flags: hdr.flags,
        from: if has_sender { Some(name) } else { None },
    })
}

/// `sendmsg(2)` of `buf` and ancillary data `oob`, optionally to `to`.
/// Returns the bytes of `buf` sent.
pub fn sendmsg(
    fd: RawFd,
    buf: &[u8],
    oob: &[u8],
    to: Option<&SockAddr>,
    flags: i32,
) -> Result<usize, Errno> {
    let dummy = 0u8;
    let (base, len): (*const u8, usize) = if needs_dummy_byte(fd, buf.len(), oob.len())? {
        (&dummy, 1)
    } else if buf.is_empty() {
        (std::ptr::null(), 0)
    } else {
        (buf.as_ptr(), buf.len())
    };
    let mut iov = c::IoVec {
        base: base as *mut c_void,
        len,
    };
    let hdr = c::MsgHdr {
        name: match to {
            Some(a) => a.storage.0.as_ptr() as *mut c_void,
            None => std::ptr::null_mut(),
        },
        namelen: to.map_or(0, |a| a.len),
        iov: &mut iov,
        iovlen: 1,
        control: if oob.is_empty() {
            std::ptr::null_mut()
        } else {
            oob.as_ptr() as *mut c_void
        },
        controllen: oob.len() as _,
        flags: 0,
    };
    // SAFETY: `hdr` points at live buffers whose lengths it records; sendmsg
    // only reads through the name, iov and control pointers.
    let n = unsafe { c::sendmsg(fd, &hdr, flags) };
    if n < 0 {
        Err(Errno::last())
    } else if !oob.is_empty() && buf.is_empty() {
        Ok(0)
    } else {
        Ok(n as usize)
    }
}
