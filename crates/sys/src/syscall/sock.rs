//! Socket addresses and the socket calls of Go's `syscall_unix.go` and
//! `syscall_linux.go`: `Socket`, `Bind`, `Accept`, `Recvmsg`, the
//! `Getsockopt*`/`Setsockopt*` family and the packet-filter helpers.
use super::errno::Errno;
use super::types::*;
use super::zsyscall as z;
use super::*;
use std::any::Any;
use std::sync::atomic::{AtomicBool, Ordering};

/// `syscall.SocketDisableIPv6`: set to make `socket` fail for `AF_INET6`
/// with `EAFNOSUPPORT` (for testing).
pub static SOCKET_DISABLE_IPV6: AtomicBool = AtomicBool::new(false);

/// `syscall.Sockaddr`: a socket address that can be passed to `bind`,
/// `connect` and the send calls.
pub trait Sockaddr: Any + std::fmt::Debug {
    /// Go's unexported `sockaddr` method: the bytes of the kernel's
    /// `struct sockaddr` and the length of it that is meaningful.
    fn sockaddr(&self) -> Result<(Vec<u8>, u32), Errno>;
    /// The address as `Any`, to recover the concrete type.
    fn as_any(&self) -> &dyn Any;
}

fn put16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_ne_bytes());
}

fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_ne_bytes());
}

fn get16(b: &[u8], off: usize) -> u16 {
    u16::from_ne_bytes([b[off], b[off + 1]])
}

fn get32(b: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// `syscall.SockaddrInet4`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SockaddrInet4 {
    pub port: isize,
    pub addr: [u8; 4],
}

impl Sockaddr for SockaddrInet4 {
    fn sockaddr(&self) -> Result<(Vec<u8>, u32), Errno> {
        if self.port < 0 || self.port > 0xFFFF {
            return Err(EINVAL);
        }
        let mut raw = vec![0u8; SIZEOF_SOCKADDR_INET4 as usize];
        put16(&mut raw, 0, AF_INET as u16);
        raw[2] = (self.port >> 8) as u8;
        raw[3] = self.port as u8;
        raw[4..8].copy_from_slice(&self.addr);
        Ok((raw, SIZEOF_SOCKADDR_INET4 as u32))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// `syscall.SockaddrInet6`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SockaddrInet6 {
    pub port: isize,
    pub zone_id: u32,
    pub addr: [u8; 16],
}

impl Sockaddr for SockaddrInet6 {
    fn sockaddr(&self) -> Result<(Vec<u8>, u32), Errno> {
        if self.port < 0 || self.port > 0xFFFF {
            return Err(EINVAL);
        }
        let mut raw = vec![0u8; SIZEOF_SOCKADDR_INET6 as usize];
        put16(&mut raw, 0, AF_INET6 as u16);
        raw[2] = (self.port >> 8) as u8;
        raw[3] = self.port as u8;
        raw[8..24].copy_from_slice(&self.addr);
        put32(&mut raw, 24, self.zone_id);
        Ok((raw, SIZEOF_SOCKADDR_INET6 as u32))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// `syscall.SockaddrUnix`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SockaddrUnix {
    pub name: String,
}

impl Sockaddr for SockaddrUnix {
    fn sockaddr(&self) -> Result<(Vec<u8>, u32), Errno> {
        let name = self.name.as_bytes();
        let n = name.len();
        let path_len = 108;
        if n > path_len {
            return Err(EINVAL);
        }
        // Abstract addresses start with NUL; '@' is also accepted.
        let is_abstract = n > 0 && (name[0] == b'@' || name[0] == 0);
        // Named addresses are NUL terminated, so they cannot fill the path.
        if n == path_len && !is_abstract {
            return Err(EINVAL);
        }
        let mut raw = vec![0u8; SIZEOF_SOCKADDR_UNIX as usize];
        put16(&mut raw, 0, AF_UNIX as u16);
        raw[2..2 + n].copy_from_slice(name);
        let mut sl = (2 + n) as u32;
        if is_abstract {
            raw[2] = 0;
        } else if n > 0 {
            sl += 1;
        }
        Ok((raw, sl))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// `syscall.SockaddrLinklayer`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SockaddrLinklayer {
    pub protocol: u16,
    pub ifindex: isize,
    pub hatype: u16,
    pub pkttype: u8,
    pub halen: u8,
    pub addr: [u8; 8],
}

impl Sockaddr for SockaddrLinklayer {
    fn sockaddr(&self) -> Result<(Vec<u8>, u32), Errno> {
        if self.ifindex < 0 || self.ifindex > 0x7fff_ffff {
            return Err(EINVAL);
        }
        let mut raw = vec![0u8; SIZEOF_SOCKADDR_LINKLAYER as usize];
        put16(&mut raw, 0, AF_PACKET as u16);
        put16(&mut raw, 2, self.protocol);
        put32(&mut raw, 4, self.ifindex as u32);
        put16(&mut raw, 8, self.hatype);
        raw[10] = self.pkttype;
        raw[11] = self.halen;
        raw[12..20].copy_from_slice(&self.addr);
        Ok((raw, SIZEOF_SOCKADDR_LINKLAYER as u32))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// `syscall.SockaddrNetlink`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SockaddrNetlink {
    pub family: u16,
    pub pad: u16,
    pub pid: u32,
    pub groups: u32,
}

impl Sockaddr for SockaddrNetlink {
    fn sockaddr(&self) -> Result<(Vec<u8>, u32), Errno> {
        let mut raw = vec![0u8; SIZEOF_SOCKADDR_NETLINK as usize];
        put16(&mut raw, 0, AF_NETLINK as u16);
        put16(&mut raw, 2, self.pad);
        put32(&mut raw, 4, self.pid);
        put32(&mut raw, 8, self.groups);
        Ok((raw, SIZEOF_SOCKADDR_NETLINK as u32))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

const ANY_LEN: usize = SIZEOF_SOCKADDR_ANY as usize;

/// Go's `anyToSockaddr`: the address the kernel wrote into `rsa`.
fn any_to_sockaddr(rsa: &[u8; ANY_LEN]) -> Result<Box<dyn Sockaddr>, Errno> {
    match get16(rsa, 0) as isize {
        AF_NETLINK => Ok(Box::new(SockaddrNetlink {
            family: get16(rsa, 0),
            pad: get16(rsa, 2),
            pid: get32(rsa, 4),
            groups: get32(rsa, 8),
        })),
        AF_PACKET => {
            let mut addr = [0u8; 8];
            addr.copy_from_slice(&rsa[12..20]);
            Ok(Box::new(SockaddrLinklayer {
                protocol: get16(rsa, 2),
                ifindex: get32(rsa, 4) as i32 as isize,
                hatype: get16(rsa, 8),
                pkttype: rsa[10],
                halen: rsa[11],
                addr,
            }))
        }
        AF_UNIX => {
            let mut path = rsa[2..2 + 108].to_vec();
            if path[0] == 0 {
                // An abstract socket: a leading NUL is shown as '@'.
                path[0] = b'@';
            }
            let n = path.iter().position(|&c| c == 0).unwrap_or(path.len());
            path.truncate(n);
            Ok(Box::new(SockaddrUnix {
                name: String::from_utf8_lossy(&path).into_owned(),
            }))
        }
        AF_INET => {
            let mut addr = [0u8; 4];
            addr.copy_from_slice(&rsa[4..8]);
            Ok(Box::new(SockaddrInet4 {
                port: (isize::from(rsa[2]) << 8) + isize::from(rsa[3]),
                addr,
            }))
        }
        AF_INET6 => {
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&rsa[8..24]);
            Ok(Box::new(SockaddrInet6 {
                port: (isize::from(rsa[2]) << 8) + isize::from(rsa[3]),
                zone_id: get32(rsa, 24),
                addr,
            }))
        }
        _ => Err(EAFNOSUPPORT),
    }
}

/// Zeroed space for a socket address and the length cell the kernel updates.
fn any_buffer() -> ([u8; ANY_LEN], u32) {
    ([0u8; ANY_LEN], ANY_LEN as u32)
}

fn rsa_ptr(rsa: &mut [u8; ANY_LEN]) -> *mut RawSockaddrAny {
    rsa.as_mut_ptr().cast()
}

// ---- calls ----------------------------------------------------------------

/// `syscall.Socket`.
pub fn socket(domain: isize, typ: isize, proto: isize) -> Result<isize, Errno> {
    if domain == AF_INET6 && SOCKET_DISABLE_IPV6.load(Ordering::Relaxed) {
        return Err(EAFNOSUPPORT);
    }
    z::socket(domain, typ, proto)
}

/// `syscall.Socketpair`.
pub fn socketpair(domain: isize, typ: isize, proto: isize) -> Result<[isize; 2], Errno> {
    let mut fdx = [0i32; 2];
    z::socketpair(domain, typ, proto, &mut fdx)?;
    Ok([fdx[0] as isize, fdx[1] as isize])
}

/// `syscall.Bind`.
pub fn bind(fd: isize, sa: &dyn Sockaddr) -> Result<(), Errno> {
    let (raw, n) = sa.sockaddr()?;
    z::bind(fd, raw.as_ptr() as usize, n)
}

/// `syscall.Connect`.
pub fn connect(fd: isize, sa: &dyn Sockaddr) -> Result<(), Errno> {
    let (raw, n) = sa.sockaddr()?;
    z::connect(fd, raw.as_ptr() as usize, n)
}

/// `syscall.Accept`.
pub fn accept(fd: isize) -> Result<(isize, Box<dyn Sockaddr>), Errno> {
    accept4(fd, 0)
}

/// `syscall.Accept4`.
pub fn accept4(fd: isize, flags: isize) -> Result<(isize, Box<dyn Sockaddr>), Errno> {
    let (mut rsa, mut len) = any_buffer();
    let nfd = z::accept4(fd, rsa_ptr(&mut rsa), &mut len, flags)?;
    if len as usize > ANY_LEN {
        panic!("RawSockaddrAny too small");
    }
    match any_to_sockaddr(&rsa) {
        Ok(sa) => Ok((nfd, sa)),
        Err(e) => {
            let _ = z::close(nfd);
            Err(e)
        }
    }
}

/// `syscall.Getsockname`.
pub fn getsockname(fd: isize) -> Result<Box<dyn Sockaddr>, Errno> {
    let (mut rsa, mut len) = any_buffer();
    z::getsockname(fd, rsa_ptr(&mut rsa), &mut len)?;
    any_to_sockaddr(&rsa)
}

/// `syscall.Getpeername`.
pub fn getpeername(fd: isize) -> Result<Box<dyn Sockaddr>, Errno> {
    let (mut rsa, mut len) = any_buffer();
    z::getpeername(fd, rsa_ptr(&mut rsa), &mut len)?;
    any_to_sockaddr(&rsa)
}

/// `syscall.BindToDevice`.
pub fn bind_to_device(fd: isize, device: &str) -> Result<(), Errno> {
    setsockopt_string(fd, SOL_SOCKET, SO_BINDTODEVICE, device)
}

fn getsockopt_struct<T: Default>(fd: isize, level: isize, opt: isize) -> Result<T, Errno> {
    let mut value = T::default();
    let mut len = std::mem::size_of::<T>() as u32;
    z::getsockopt(fd, level, opt, &mut value as *mut T as usize, &mut len)?;
    Ok(value)
}

fn setsockopt_struct<T>(fd: isize, level: isize, opt: isize, value: &T) -> Result<(), Errno> {
    z::setsockopt(
        fd,
        level,
        opt,
        value as *const T as usize,
        std::mem::size_of::<T>(),
    )
}

/// `syscall.GetsockoptInt`.
pub fn getsockopt_int(fd: isize, level: isize, opt: isize) -> Result<isize, Errno> {
    getsockopt_struct::<i32>(fd, level, opt).map(|n| n as isize)
}

/// `syscall.GetsockoptInet4Addr`.
pub fn getsockopt_inet4_addr(fd: isize, level: isize, opt: isize) -> Result<[u8; 4], Errno> {
    let mut value = [0u8; 4];
    let mut len = 4u32;
    z::getsockopt(fd, level, opt, value.as_mut_ptr() as usize, &mut len)?;
    Ok(value)
}

/// `syscall.GetsockoptIPMreq`.
pub fn getsockopt_ip_mreq(fd: isize, level: isize, opt: isize) -> Result<IPMreq, Errno> {
    getsockopt_struct(fd, level, opt)
}

/// `syscall.GetsockoptIPMreqn`.
pub fn getsockopt_ip_mreqn(fd: isize, level: isize, opt: isize) -> Result<IPMreqn, Errno> {
    getsockopt_struct(fd, level, opt)
}

/// `syscall.GetsockoptIPv6Mreq`.
pub fn getsockopt_ipv6_mreq(fd: isize, level: isize, opt: isize) -> Result<IPv6Mreq, Errno> {
    getsockopt_struct(fd, level, opt)
}

/// `syscall.GetsockoptIPv6MTUInfo`.
pub fn getsockopt_ipv6_mtu_info(
    fd: isize,
    level: isize,
    opt: isize,
) -> Result<IPv6MTUInfo, Errno> {
    getsockopt_struct(fd, level, opt)
}

/// `syscall.GetsockoptICMPv6Filter`.
pub fn getsockopt_icmpv6_filter(
    fd: isize,
    level: isize,
    opt: isize,
) -> Result<ICMPv6Filter, Errno> {
    getsockopt_struct(fd, level, opt)
}

/// `syscall.GetsockoptUcred`.
pub fn getsockopt_ucred(fd: isize, level: isize, opt: isize) -> Result<Ucred, Errno> {
    getsockopt_struct(fd, level, opt)
}

/// `syscall.SetsockoptByte`.
pub fn setsockopt_byte(fd: isize, level: isize, opt: isize, value: u8) -> Result<(), Errno> {
    z::setsockopt(fd, level, opt, &value as *const u8 as usize, 1)
}

/// `syscall.SetsockoptInt`.
pub fn setsockopt_int(fd: isize, level: isize, opt: isize, value: isize) -> Result<(), Errno> {
    setsockopt_struct(fd, level, opt, &(value as i32))
}

/// `syscall.SetsockoptInet4Addr`.
pub fn setsockopt_inet4_addr(
    fd: isize,
    level: isize,
    opt: isize,
    value: [u8; 4],
) -> Result<(), Errno> {
    z::setsockopt(fd, level, opt, value.as_ptr() as usize, 4)
}

/// `syscall.SetsockoptIPMreq`.
pub fn setsockopt_ip_mreq(fd: isize, level: isize, opt: isize, mreq: &IPMreq) -> Result<(), Errno> {
    setsockopt_struct(fd, level, opt, mreq)
}

/// `syscall.SetsockoptIPMreqn`.
pub fn setsockopt_ip_mreqn(
    fd: isize,
    level: isize,
    opt: isize,
    mreq: &IPMreqn,
) -> Result<(), Errno> {
    setsockopt_struct(fd, level, opt, mreq)
}

/// `syscall.SetsockoptIPv6Mreq`.
pub fn setsockopt_ipv6_mreq(
    fd: isize,
    level: isize,
    opt: isize,
    mreq: &IPv6Mreq,
) -> Result<(), Errno> {
    setsockopt_struct(fd, level, opt, mreq)
}

/// `syscall.SetsockoptICMPv6Filter`.
pub fn setsockopt_icmpv6_filter(
    fd: isize,
    level: isize,
    opt: isize,
    filter: &ICMPv6Filter,
) -> Result<(), Errno> {
    setsockopt_struct(fd, level, opt, filter)
}

/// `syscall.SetsockoptLinger`.
pub fn setsockopt_linger(fd: isize, level: isize, opt: isize, l: &Linger) -> Result<(), Errno> {
    setsockopt_struct(fd, level, opt, l)
}

/// `syscall.SetsockoptString`.
pub fn setsockopt_string(fd: isize, level: isize, opt: isize, s: &str) -> Result<(), Errno> {
    let p = if s.is_empty() { 0 } else { s.as_ptr() as usize };
    z::setsockopt(fd, level, opt, p, s.len())
}

/// `syscall.SetsockoptTimeval`.
pub fn setsockopt_timeval(fd: isize, level: isize, opt: isize, tv: &Timeval) -> Result<(), Errno> {
    setsockopt_struct(fd, level, opt, tv)
}

/// `syscall.Recvfrom`: the byte count and, for an unconnected socket, the
/// sender's address.
pub fn recvfrom(
    fd: isize,
    p: &mut [u8],
    flags: isize,
) -> Result<(isize, Option<Box<dyn Sockaddr>>), Errno> {
    let (mut rsa, mut len) = any_buffer();
    let n = z::recvfrom(fd, p, flags, rsa_ptr(&mut rsa), &mut len)?;
    let from = if get16(&rsa, 0) as isize != AF_UNSPEC {
        Some(any_to_sockaddr(&rsa)?)
    } else {
        None
    };
    Ok((n, from))
}

/// `syscall.Sendto`.
pub fn sendto(
    fd: isize,
    p: &[u8],
    flags: isize,
    to: Option<&dyn Sockaddr>,
) -> Result<(), Errno> {
    let (raw, salen) = match to {
        Some(sa) => sa.sockaddr()?,
        None => (Vec::new(), 0),
    };
    let ptr = if raw.is_empty() { 0 } else { raw.as_ptr() as usize };
    z::sendto(fd, p, flags, ptr, salen)
}

/// The bytes read by `recvmsg`, the control bytes, the message flags and the
/// sender, from `Recvmsg`.
pub type RecvmsgResult = (isize, isize, isize, Option<Box<dyn Sockaddr>>);

fn msg_iov(fd: isize, p: &[u8], oob_len: usize, dummy: &mut u8, iov: &mut Iovec) -> Result<(), Errno> {
    if !p.is_empty() {
        iov.base = p.as_ptr() as *mut u8;
        iov.set_len(p.len() as isize);
    }
    if oob_len > 0 && p.is_empty() {
        let sock_type = getsockopt_int(fd, SOL_SOCKET, SO_TYPE)?;
        // At least one normal byte must travel with the control data.
        if sock_type != SOCK_DGRAM {
            iov.base = dummy;
            iov.set_len(1);
        }
    }
    Ok(())
}

fn recvmsg_raw(
    fd: isize,
    p: &mut [u8],
    oob: &mut [u8],
    flags: isize,
    rsa: &mut [u8; ANY_LEN],
) -> Result<(isize, isize, isize), Errno> {
    let mut msg = Msghdr {
        name: rsa.as_mut_ptr(),
        namelen: ANY_LEN as u32,
        ..Msghdr::default()
    };
    let mut iov = Iovec::default();
    let mut dummy = 0u8;
    msg_iov(fd, p, oob.len(), &mut dummy, &mut iov)?;
    if !oob.is_empty() {
        msg.control = oob.as_mut_ptr();
        msg.set_controllen(oob.len() as isize);
    }
    msg.iov = &mut iov;
    msg.iovlen = 1;
    let n = z::recvmsg(fd, &mut msg, flags)?;
    Ok((n, msg.controllen as isize, msg.flags as isize))
}

/// `syscall.Recvmsg`.
pub fn recvmsg(
    fd: isize,
    p: &mut [u8],
    oob: &mut [u8],
    flags: isize,
) -> Result<RecvmsgResult, Errno> {
    let (mut rsa, _) = any_buffer();
    let (n, oobn, recvflags) = recvmsg_raw(fd, p, oob, flags, &mut rsa)?;
    // The source address is only given for an unconnected socket.
    let from = if get16(&rsa, 0) as isize != AF_UNSPEC {
        Some(any_to_sockaddr(&rsa)?)
    } else {
        None
    };
    Ok((n, oobn, recvflags, from))
}

/// `syscall.Sendmsg`.
pub fn sendmsg(
    fd: isize,
    p: &[u8],
    oob: &[u8],
    to: Option<&dyn Sockaddr>,
    flags: isize,
) -> Result<(), Errno> {
    sendmsg_n(fd, p, oob, to, flags).map(|_| ())
}

/// `syscall.SendmsgN`.
pub fn sendmsg_n(
    fd: isize,
    p: &[u8],
    oob: &[u8],
    to: Option<&dyn Sockaddr>,
    flags: isize,
) -> Result<isize, Errno> {
    let (mut raw, salen) = match to {
        Some(sa) => sa.sockaddr()?,
        None => (Vec::new(), 0),
    };
    let mut msg = Msghdr {
        name: if raw.is_empty() { std::ptr::null_mut() } else { raw.as_mut_ptr() },
        namelen: salen,
        ..Msghdr::default()
    };
    let mut iov = Iovec::default();
    let mut dummy = 0u8;
    msg_iov(fd, p, oob.len(), &mut dummy, &mut iov)?;
    if !oob.is_empty() {
        msg.control = oob.as_ptr() as *mut u8;
        msg.set_controllen(oob.len() as isize);
    }
    msg.iov = &mut iov;
    msg.iovlen = 1;
    let mut n = z::sendmsg(fd, &mut msg, flags)?;
    if !oob.is_empty() && p.is_empty() {
        n = 0;
    }
    Ok(n)
}

/// `syscall.Sendfile`: with no `offset`, uses and advances the file position
/// of `infd`; otherwise reads from `*offset` and advances it.
pub fn sendfile(
    outfd: isize,
    infd: isize,
    offset: Option<&mut i64>,
    count: isize,
) -> Result<isize, Errno> {
    let off = offset.map_or(std::ptr::null_mut(), |o| o as *mut i64);
    z::sendfile(outfd, infd, off, count)
}

// ---- packet filters ---------------------------------------------------------

/// `syscall.LsfStmt`.
pub fn lsf_stmt(code: isize, k: isize) -> SockFilter {
    SockFilter {
        code: code as u16,
        k: k as u32,
        ..SockFilter::default()
    }
}

/// `syscall.LsfJump`.
pub fn lsf_jump(code: isize, k: isize, jt: isize, jf: isize) -> SockFilter {
    SockFilter {
        code: code as u16,
        jt: jt as u8,
        jf: jf as u8,
        k: k as u32,
    }
}

/// `syscall.LsfSocket`: a raw packet socket bound to `ifindex` for `proto`.
pub fn lsf_socket(ifindex: isize, proto: isize) -> Result<isize, Errno> {
    let s = socket(AF_PACKET, SOCK_RAW, proto)?;
    // The protocol is given in network byte order.
    let lsall = SockaddrLinklayer {
        protocol: (proto as u16).swap_bytes(),
        ifindex,
        ..SockaddrLinklayer::default()
    };
    if let Err(e) = bind(s, &lsall) {
        let _ = z::close(s);
        return Err(e);
    }
    Ok(s)
}

/// `syscall.SetLsfPromisc`: turns promiscuous mode of interface `name` on or off.
pub fn set_lsf_promisc(name: &str, m: bool) -> Result<(), Errno> {
    let s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)?;
    let result = (|| {
        // struct ifreq-like: name[IFNAMSIZ] then flags (u16).
        let mut ifl = [0u8; IFNAMSIZ as usize + 2];
        let n = name.len().min(IFNAMSIZ as usize);
        ifl[..n].copy_from_slice(&name.as_bytes()[..n]);
        let ptr = ifl.as_mut_ptr() as usize;
        raw::sc(SYS_IOCTL, [s as usize, SIOCGIFFLAGS as usize, ptr, 0, 0, 0])?;
        let off = IFNAMSIZ as usize;
        let mut flags = u16::from_ne_bytes([ifl[off], ifl[off + 1]]);
        if m {
            flags |= IFF_PROMISC as u16;
        } else {
            flags &= !(IFF_PROMISC as u16);
        }
        ifl[off..off + 2].copy_from_slice(&flags.to_ne_bytes());
        raw::sc(SYS_IOCTL, [s as usize, SIOCSIFFLAGS as usize, ptr, 0, 0, 0])?;
        Ok(())
    })();
    let _ = z::close(s);
    result
}

/// `syscall.AttachLsf`: attaches the filter program `i` to the socket.
pub fn attach_lsf(fd: isize, i: &mut [SockFilter]) -> Result<(), Errno> {
    let p = SockFprog {
        len: i.len() as u16,
        filter: i.as_mut_ptr(),
        ..SockFprog::default()
    };
    setsockopt_struct(fd, SOL_SOCKET, SO_ATTACH_FILTER, &p)
}

/// `syscall.DetachLsf`.
pub fn detach_lsf(fd: isize) -> Result<(), Errno> {
    let dummy: isize = 0;
    setsockopt_struct(fd, SOL_SOCKET, SO_DETACH_FILTER, &dummy)
}
