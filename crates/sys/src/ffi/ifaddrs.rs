//! Network interface enumeration: `getifaddrs`, the interface MTU, and on
//! macOS the routing-table sysctl that lists joined multicast groups.
use super::sock::{self, k};
use crate::errno::Errno;
use std::os::raw::{c_char, c_int, c_uint, c_void};

mod c {
    use super::*;

    /// `struct ifaddrs`: the same field order on Linux and macOS.
    #[repr(C)]
    pub struct IfAddrs {
        pub next: *mut IfAddrs,
        pub name: *const c_char,
        pub flags: c_uint,
        pub addr: *const u8,
        pub netmask: *const u8,
        pub dst: *const u8,
        pub data: *mut c_void,
    }

    extern "C" {
        pub fn getifaddrs(list: *mut *mut IfAddrs) -> c_int;
        pub fn freeifaddrs(list: *mut IfAddrs);
        pub fn ioctl(fd: c_int, request: std::os::raw::c_ulong, ...) -> c_int;
        #[cfg(target_os = "macos")]
        pub fn sysctl(
            name: *mut c_int,
            namelen: c_uint,
            oldp: *mut c_void,
            oldlenp: *mut usize,
            newp: *mut c_void,
            newlen: usize,
        ) -> c_int;
    }
}

#[cfg(target_os = "linux")]
const AF_LINK: i32 = 17; // AF_PACKET
#[cfg(target_os = "macos")]
const AF_LINK: i32 = 18;
#[cfg(target_os = "linux")]
const SIOCGIFMTU: std::os::raw::c_ulong = 0x8921;
#[cfg(target_os = "macos")]
const SIOCGIFMTU: std::os::raw::c_ulong = 0xc020_6933;

/// A decoded interface address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IfAddr {
    V4([u8; 4]),
    V6([u8; 16]),
    /// The link-layer entry: interface index and hardware address.
    Link { index: u32, hardware: Vec<u8> },
    Other,
}

/// One entry from `getifaddrs`.
#[derive(Clone, Debug)]
pub struct IfEntry {
    pub name: String,
    pub flags: u32,
    pub addr: IfAddr,
    pub netmask: Option<IfAddr>,
}

fn family_of(sa: &[u8]) -> i32 {
    #[cfg(target_os = "macos")]
    {
        sa[1] as i32
    }
    #[cfg(target_os = "linux")]
    {
        u16::from_ne_bytes([sa[0], sa[1]]) as i32
    }
}

/// Copies the `sockaddr` at `ptr` into a zero-padded buffer, reading only
/// the bytes the address itself says it has; `None` for a null pointer.
///
/// # Safety
///
/// A non-null `ptr` must point at a complete `sockaddr`: on macOS `sa_len`
/// readable bytes (at least 2); on Linux 16 bytes for AF_INET, 28 for
/// AF_INET6, 20 for AF_PACKET (the family fixes the size) and at least 2
/// bytes for any other family.
unsafe fn read_sockaddr(ptr: *const u8) -> Option<[u8; 128]> {
    if ptr.is_null() {
        return None;
    }
    let mut out = [0u8; 128];
    // SAFETY: every sockaddr has at least its two header bytes.
    let head = unsafe { std::slice::from_raw_parts(ptr, 2) };
    #[cfg(target_os = "macos")]
    let len = (head[0] as usize).clamp(2, 128);
    #[cfg(target_os = "linux")]
    let len = match family_of(head) {
        f if f == k::AF_INET => 16,
        f if f == k::AF_INET6 => 28,
        f if f == AF_LINK => 20,
        _ => 2,
    };
    // SAFETY: the caller guarantees `len` readable bytes, as derived above.
    out[..len].copy_from_slice(unsafe { std::slice::from_raw_parts(ptr, len) });
    Some(out)
}

/// Decodes a buffer filled by [`read_sockaddr`].
fn parse(sa: &[u8; 128]) -> IfAddr {
    let family = family_of(sa);
    if family == k::AF_INET {
        IfAddr::V4([sa[4], sa[5], sa[6], sa[7]])
    } else if family == k::AF_INET6 {
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&sa[8..24]);
        IfAddr::V6(ip)
    } else if family == AF_LINK {
        #[cfg(target_os = "linux")]
        {
            let index = i32::from_ne_bytes([sa[4], sa[5], sa[6], sa[7]]) as u32;
            let len = (sa[11] as usize).min(8);
            IfAddr::Link {
                index,
                hardware: sa[12..12 + len].to_vec(),
            }
        }
        #[cfg(target_os = "macos")]
        {
            let index = u16::from_ne_bytes([sa[2], sa[3]]) as u32;
            let (nlen, alen) = (sa[5] as usize, sa[6] as usize);
            let start = (8 + nlen).min(128);
            let end = (start + alen).min(128);
            IfAddr::Link {
                index,
                hardware: sa[start..end].to_vec(),
            }
        }
    } else {
        IfAddr::Other
    }
}

/// `getifaddrs(3)`: every address and link entry, in the system's order.
pub fn getifaddrs() -> Result<Vec<IfEntry>, Errno> {
    let mut list: *mut c::IfAddrs = std::ptr::null_mut();
    // SAFETY: `list` is a valid location for the head pointer.
    sock::check(unsafe { c::getifaddrs(&mut list) })?;
    let mut out = Vec::new();
    let mut cur = list;
    while !cur.is_null() {
        // SAFETY: `cur` is a node of the list getifaddrs returned, valid
        // until freeifaddrs below.
        let e = unsafe { &*cur };
        // SAFETY: ifa_name is a NUL-terminated string owned by the node.
        let name = unsafe { std::ffi::CStr::from_ptr(e.name) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: getifaddrs fills ifa_addr and ifa_netmask with complete
        // sockaddr structures, or null.
        let (addr, netmask) = unsafe { (read_sockaddr(e.addr), read_sockaddr(e.netmask)) };
        if let Some(addr) = addr {
            let addr = parse(&addr);
            // macOS leaves sa_family unset on some netmasks (aliases), so
            // read the mask by the address's own family.
            let netmask = netmask.and_then(|m| match addr {
                IfAddr::V4(_) => Some(IfAddr::V4([m[4], m[5], m[6], m[7]])),
                IfAddr::V6(_) => {
                    let mut ip = [0u8; 16];
                    ip.copy_from_slice(&m[8..24]);
                    Some(IfAddr::V6(ip))
                }
                _ => None,
            });
            out.push(IfEntry {
                name,
                flags: e.flags,
                addr,
                netmask,
            });
        }
        cur = e.next;
    }
    // SAFETY: `list` came from getifaddrs and is freed exactly once; no
    // pointer into it is used afterwards.
    unsafe { c::freeifaddrs(list) };
    Ok(out)
}

/// The MTU of the named interface (`SIOCGIFMTU`).
pub fn interface_mtu(name: &str) -> Result<i32, Errno> {
    let fd = sock::socket(k::AF_INET, k::SOCK_DGRAM, 0)?;
    // struct ifreq: a 16-byte name, then a union; the MTU is the first int.
    let mut req = [0u8; 40];
    let bytes = name.as_bytes();
    if bytes.len() >= 16 {
        return Err(crate::errno::EINVAL);
    }
    req[..bytes.len()].copy_from_slice(bytes);
    // SAFETY: `req` is at least as large as struct ifreq on both targets and
    // stays alive for the call.
    sock::check(unsafe {
        c::ioctl(fd.raw(), SIOCGIFMTU, req.as_mut_ptr())
    })?;
    Ok(i32::from_ne_bytes([req[16], req[17], req[18], req[19]]))
}

/// Joined multicast groups of interface `index`, from the routing sysctl
/// `NET_RT_IFLIST2`: (interface index, group address) per message.
#[cfg(target_os = "macos")]
pub fn multicast_groups(index: u32) -> Result<Vec<(u32, IfAddr)>, Errno> {
    const CTL_NET: c_int = 4;
    const PF_ROUTE: c_int = 17;
    const NET_RT_IFLIST2: c_int = 6;
    const RTM_NEWMADDR2: u8 = 0x13;
    const RTAX_IFA: usize = 5;
    let mut mib = [CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST2, index as c_int];
    let mut len: usize = 0;
    // SAFETY: a null output buffer asks only for the required size.
    sock::check(unsafe {
        c::sysctl(
            mib.as_mut_ptr(),
            mib.len() as c_uint,
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    })?;
    let mut buf = vec![0u8; len + len / 8 + 4096];
    let mut len = buf.len();
    // SAFETY: `buf` is writable for `len` bytes and `len` is updated in place.
    sock::check(unsafe {
        c::sysctl(
            mib.as_mut_ptr(),
            mib.len() as c_uint,
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    })?;
    buf.truncate(len);
    let mut out = Vec::new();
    let mut off = 0;
    while off + 4 <= buf.len() {
        let msglen = u16::from_ne_bytes([buf[off], buf[off + 1]]) as usize;
        if msglen < 4 || off + msglen > buf.len() {
            break;
        }
        let msg = &buf[off..off + msglen];
        if msg[3] == RTM_NEWMADDR2 && msglen >= 20 {
            // struct ifma_msghdr2: msglen u16, version u8, type u8, addrs i32,
            // flags i32, index u16, pad u16, refcount i32; sockaddrs follow.
            let addrs = i32::from_ne_bytes([msg[4], msg[5], msg[6], msg[7]]);
            let msg_index = u16::from_ne_bytes([msg[12], msg[13]]) as u32;
            let mut pos = 20;
            for bit in 0..8usize {
                if addrs & (1 << bit) == 0 {
                    continue;
                }
                if pos >= msg.len() {
                    break;
                }
                let sa_len = msg[pos] as usize;
                let step = if sa_len == 0 { 4 } else { (sa_len + 3) & !3 };
                if bit == RTAX_IFA && pos + sa_len.max(1) <= msg.len() {
                    // The kernel may drop trailing zero bytes; pad them back.
                    let mut sa = [0u8; 128];
                    let n = sa_len.min(128).min(msg.len() - pos);
                    sa[..n].copy_from_slice(&msg[pos..pos + n]);
                    let family = family_of(&sa);
                    if family == k::AF_INET || family == k::AF_INET6 {
                        out.push((msg_index, parse(&sa)));
                    }
                }
                pos += step;
            }
        }
        off += msglen;
    }
    Ok(out)
}
