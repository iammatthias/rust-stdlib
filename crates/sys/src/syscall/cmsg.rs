//! Socket control messages (`sockcmsg_unix.go`, `sockcmsg_linux.go`) and
//! netlink (`netlink_linux.go`).
use super::errno::Errno;
use super::sock::{self, SockaddrNetlink};
use super::types::*;
use super::zsyscall as z;
use super::*;

/// The alignment of control messages on linux/amd64.
const SALIGN: usize = 8;

fn cmsg_align_of(salen: usize) -> usize {
    (salen + SALIGN - 1) & !(SALIGN - 1)
}

/// `syscall.CmsgLen`: the value of `Cmsghdr.len` for `datalen` bytes of data.
pub fn cmsg_len(datalen: isize) -> isize {
    (cmsg_align_of(SIZEOF_CMSGHDR as usize) as isize).wrapping_add(datalen)
}

/// `syscall.CmsgSpace`: the space a control message with `datalen` bytes of
/// data takes in a buffer.
pub fn cmsg_space(datalen: isize) -> isize {
    (cmsg_align_of(SIZEOF_CMSGHDR as usize) + cmsg_align_of(datalen as usize)) as isize
}

/// `syscall.SocketControlMessage`: a control message and its data.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SocketControlMessage {
    pub header: Cmsghdr,
    pub data: Vec<u8>,
}

fn read_cmsghdr(b: &[u8]) -> Cmsghdr {
    let mut len = [0u8; 8];
    len.copy_from_slice(&b[0..8]);
    Cmsghdr {
        len: u64::from_ne_bytes(len),
        level: i32::from_ne_bytes([b[8], b[9], b[10], b[11]]),
        type_: i32::from_ne_bytes([b[12], b[13], b[14], b[15]]),
    }
}

fn write_cmsghdr(b: &mut [u8], len: usize, level: isize, type_: isize) {
    b[0..8].copy_from_slice(&(len as u64).to_ne_bytes());
    b[8..12].copy_from_slice(&(level as i32).to_ne_bytes());
    b[12..16].copy_from_slice(&(type_ as i32).to_ne_bytes());
}

/// `syscall.ParseSocketControlMessage`: splits the control data `b` returned
/// by `Recvmsg`.
pub fn parse_socket_control_message(b: &[u8]) -> Result<Vec<SocketControlMessage>, Errno> {
    let mut msgs = Vec::new();
    let mut i = 0usize;
    while i + cmsg_len(0) as usize <= b.len() {
        let rest = &b[i..];
        let h = read_cmsghdr(rest);
        if h.len < SIZEOF_CMSGHDR as u64 || h.len > rest.len() as u64 {
            return Err(EINVAL);
        }
        let data = rest[cmsg_align_of(SIZEOF_CMSGHDR as usize)..h.len as usize].to_vec();
        msgs.push(SocketControlMessage { header: h, data });
        i += cmsg_align_of(h.len as usize);
    }
    Ok(msgs)
}

/// `syscall.UnixRights`: the control message that passes `fds`.
pub fn unix_rights(fds: &[isize]) -> Vec<u8> {
    let datalen = fds.len() * 4;
    let mut b = vec![0u8; cmsg_space(datalen as isize) as usize];
    write_cmsghdr(&mut b, cmsg_len(datalen as isize) as usize, SOL_SOCKET, SCM_RIGHTS);
    let base = cmsg_align_of(SIZEOF_CMSGHDR as usize);
    for (i, fd) in fds.iter().enumerate() {
        b[base + 4 * i..base + 4 * i + 4].copy_from_slice(&(*fd as i32).to_ne_bytes());
    }
    b
}

/// `syscall.ParseUnixRights`: the descriptors in an `SCM_RIGHTS` message.
pub fn parse_unix_rights(m: &SocketControlMessage) -> Result<Vec<isize>, Errno> {
    if m.header.level != SOL_SOCKET as i32 || m.header.type_ != SCM_RIGHTS as i32 {
        return Err(EINVAL);
    }
    let mut fds = vec![0isize; m.data.len() >> 2];
    let mut i = 0;
    let mut j = 0;
    while i + 4 <= m.data.len() {
        fds[j] = i32::from_ne_bytes([m.data[i], m.data[i + 1], m.data[i + 2], m.data[i + 3]])
            as isize;
        j += 1;
        i += 4;
    }
    Ok(fds)
}

/// `syscall.UnixCredentials`: the control message that passes `ucred`.
pub fn unix_credentials(ucred: &Ucred) -> Vec<u8> {
    let mut b = vec![0u8; cmsg_space(SIZEOF_UCRED) as usize];
    write_cmsghdr(&mut b, cmsg_len(SIZEOF_UCRED) as usize, SOL_SOCKET, SCM_CREDENTIALS);
    let base = cmsg_align_of(SIZEOF_CMSGHDR as usize);
    b[base..base + 4].copy_from_slice(&ucred.pid.to_ne_bytes());
    b[base + 4..base + 8].copy_from_slice(&ucred.uid.to_ne_bytes());
    b[base + 8..base + 12].copy_from_slice(&ucred.gid.to_ne_bytes());
    b
}

/// `syscall.ParseUnixCredentials`: the credentials in an `SCM_CREDENTIALS` message.
pub fn parse_unix_credentials(m: &SocketControlMessage) -> Result<Ucred, Errno> {
    if m.header.level != SOL_SOCKET as i32 || m.header.type_ != SCM_CREDENTIALS as i32 {
        return Err(EINVAL);
    }
    if m.data.len() < SIZEOF_UCRED as usize {
        return Err(EINVAL);
    }
    let d = &m.data;
    Ok(Ucred {
        pid: i32::from_ne_bytes([d[0], d[1], d[2], d[3]]),
        uid: u32::from_ne_bytes([d[4], d[5], d[6], d[7]]),
        gid: u32::from_ne_bytes([d[8], d[9], d[10], d[11]]),
    })
}

// ---- netlink ----------------------------------------------------------------

fn nlm_align_of(msglen: usize) -> usize {
    (msglen + NLMSG_ALIGNTO as usize - 1) & !(NLMSG_ALIGNTO as usize - 1)
}

fn rta_align_of(attrlen: usize) -> usize {
    (attrlen + RTA_ALIGNTO as usize - 1) & !(RTA_ALIGNTO as usize - 1)
}

/// `syscall.NetlinkRouteRequest`: a route-table dump request.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct NetlinkRouteRequest {
    pub header: NlMsghdr,
    pub data: RtGenmsg,
}

impl NetlinkRouteRequest {
    fn wire_format(&self) -> Vec<u8> {
        let mut b = vec![0u8; self.header.len as usize];
        b[0..4].copy_from_slice(&self.header.len.to_ne_bytes());
        b[4..6].copy_from_slice(&self.header.type_.to_ne_bytes());
        b[6..8].copy_from_slice(&self.header.flags.to_ne_bytes());
        b[8..12].copy_from_slice(&self.header.seq.to_ne_bytes());
        b[12..16].copy_from_slice(&self.header.pid.to_ne_bytes());
        b[16] = self.data.family;
        b
    }
}

fn new_netlink_route_request(proto: isize, seq: isize, family: isize) -> Vec<u8> {
    let mut rr = NetlinkRouteRequest::default();
    rr.header.len = (NLMSG_HDRLEN + SIZEOF_RT_GENMSG) as u32;
    rr.header.type_ = proto as u16;
    rr.header.flags = (NLM_F_DUMP | NLM_F_REQUEST) as u16;
    rr.header.seq = seq as u32;
    rr.data.family = family as u8;
    rr.wire_format()
}

/// `syscall.NetlinkRIB`: the kernel's routing information base (`proto` is
/// `RTM_GETROUTE` or `RTM_GETADDR`) for an address `family`, as raw netlink messages.
pub fn netlink_rib(proto: isize, family: isize) -> Result<Vec<u8>, Errno> {
    let s = sock::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)?;
    let result = netlink_rib_on(s, proto, family);
    let _ = z::close(s);
    result
}

fn netlink_rib_on(s: isize, proto: isize, family: isize) -> Result<Vec<u8>, Errno> {
    let sa = SockaddrNetlink {
        family: AF_NETLINK as u16,
        ..SockaddrNetlink::default()
    };
    sock::bind(s, &sa)?;
    let wb = new_netlink_route_request(proto, 1, family);
    sock::sendto(s, &wb, 0, Some(&sa))?;
    let lsa = sock::getsockname(s)?;
    let lsanl = lsa
        .as_any()
        .downcast_ref::<SockaddrNetlink>()
        .ok_or(EINVAL)?;
    let mut tab = Vec::new();
    let mut rb = vec![0u8; getpagesize() as usize];
    loop {
        let (nr, _) = sock::recvfrom(s, &mut rb, 0)?;
        if nr < NLMSG_HDRLEN {
            return Err(EINVAL);
        }
        let rb = &rb[..nr as usize];
        tab.extend_from_slice(rb);
        for m in parse_netlink_message(rb)? {
            if m.header.seq != 1 || m.header.pid != lsanl.pid {
                return Err(EINVAL);
            }
            if m.header.type_ as isize == NLMSG_DONE {
                return Ok(tab);
            }
            if m.header.type_ as isize == NLMSG_ERROR {
                return Err(EINVAL);
            }
        }
    }
}

/// `syscall.NetlinkMessage`: a header and its payload.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NetlinkMessage {
    pub header: NlMsghdr,
    pub data: Vec<u8>,
}

fn read_nlmsghdr(b: &[u8]) -> NlMsghdr {
    NlMsghdr {
        len: u32::from_ne_bytes([b[0], b[1], b[2], b[3]]),
        type_: u16::from_ne_bytes([b[4], b[5]]),
        flags: u16::from_ne_bytes([b[6], b[7]]),
        seq: u32::from_ne_bytes([b[8], b[9], b[10], b[11]]),
        pid: u32::from_ne_bytes([b[12], b[13], b[14], b[15]]),
    }
}

/// `syscall.ParseNetlinkMessage`: splits a buffer of netlink messages.
pub fn parse_netlink_message(b: &[u8]) -> Result<Vec<NetlinkMessage>, Errno> {
    let mut msgs = Vec::new();
    let mut b = b;
    while b.len() >= NLMSG_HDRLEN as usize {
        let h = read_nlmsghdr(b);
        let l = nlm_align_of(h.len as usize);
        if (h.len as usize) < NLMSG_HDRLEN as usize || l > b.len() {
            return Err(EINVAL);
        }
        let data = b[NLMSG_HDRLEN as usize..h.len as usize].to_vec();
        msgs.push(NetlinkMessage { header: h, data });
        b = &b[l..];
    }
    Ok(msgs)
}

/// `syscall.NetlinkRouteAttr`: a route attribute and its value.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NetlinkRouteAttr {
    pub attr: RtAttr,
    pub value: Vec<u8>,
}

/// `syscall.ParseNetlinkRouteAttr`: the attributes of a link, address or
/// route message.
pub fn parse_netlink_route_attr(m: &NetlinkMessage) -> Result<Vec<NetlinkRouteAttr>, Errno> {
    let skip = match m.header.type_ as isize {
        RTM_NEWLINK | RTM_DELLINK => SIZEOF_IF_INFOMSG,
        RTM_NEWADDR | RTM_DELADDR => SIZEOF_IF_ADDRMSG,
        RTM_NEWROUTE | RTM_DELROUTE => SIZEOF_RT_MSG,
        _ => return Err(EINVAL),
    } as usize;
    // Go slices past the end here and panics on a short message.
    let mut b = m.data.get(skip..).ok_or(EINVAL)?;
    let hdr = SIZEOF_RT_ATTR as usize;
    let mut attrs = Vec::new();
    while b.len() >= hdr {
        let a = RtAttr {
            len: u16::from_ne_bytes([b[0], b[1]]),
            type_: u16::from_ne_bytes([b[2], b[3]]),
        };
        if (a.len as usize) < hdr || a.len as usize > b.len() {
            return Err(EINVAL);
        }
        attrs.push(NetlinkRouteAttr {
            attr: a,
            value: b[hdr..a.len as usize].to_vec(),
        });
        let alen = rta_align_of(a.len as usize);
        b = &b[alen.min(b.len())..];
    }
    Ok(attrs)
}
