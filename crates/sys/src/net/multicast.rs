//! Multicast group membership for `net.ListenMulticastUDP`.
use super::error::Cause;
use super::iface::Interface;
use super::socket::syscall_cause;
use crate::ffi::{self, k};
use std::net::{Ipv4Addr, Ipv6Addr};

fn set(fd: i32, level: i32, name: i32, value: &[u8]) -> Result<(), Cause> {
    ffi::setsockopt(fd, level, name, value).map_err(|e| syscall_cause("setsockopt", e))
}

/// Go's `interfaceToIPv4Addr`: the first IPv4 address of `ifi` (0.0.0.0 for
/// no interface).
fn interface_ipv4(ifi: Option<&Interface>) -> Result<Ipv4Addr, Cause> {
    let Some(ifi) = ifi else {
        return Ok(Ipv4Addr::UNSPECIFIED);
    };
    let addrs = ifi.addrs().map_err(|e| e.err)?;
    for a in addrs {
        match a.ip {
            std::net::IpAddr::V4(v4) => return Ok(v4),
            std::net::IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    return Ok(v4);
                }
            }
        }
    }
    Err(Cause::NoSuchInterface)
}

/// `listenIPv4MulticastUDP`: interface, loopback off, join.
pub(crate) fn listen_ipv4(fd: i32, ifi: Option<&Interface>, group: Ipv4Addr) -> Result<(), Cause> {
    if let Some(i) = ifi {
        if cfg!(target_os = "linux") {
            // struct ip_mreqn { multiaddr, address, ifindex }
            let mut mreqn = [0u8; 12];
            mreqn[8..12].copy_from_slice(&i.index.to_ne_bytes());
            set(fd, k::IPPROTO_IP, k::IP_MULTICAST_IF, &mreqn)?;
        } else {
            let addr = interface_ipv4(ifi)?;
            set(fd, k::IPPROTO_IP, k::IP_MULTICAST_IF, &addr.octets())?;
        }
    }
    if cfg!(target_os = "linux") {
        set(fd, k::IPPROTO_IP, k::IP_MULTICAST_LOOP, &0i32.to_ne_bytes())?;
    } else {
        set(fd, k::IPPROTO_IP, k::IP_MULTICAST_LOOP, &[0u8])?;
    }
    if cfg!(target_os = "linux") {
        let mut mreqn = [0u8; 12];
        mreqn[..4].copy_from_slice(&group.octets());
        if let Some(i) = ifi {
            mreqn[8..12].copy_from_slice(&i.index.to_ne_bytes());
        }
        set(fd, k::IPPROTO_IP, k::IP_ADD_MEMBERSHIP, &mreqn)
    } else {
        // struct ip_mreq { multiaddr, interface }
        let mut mreq = [0u8; 8];
        mreq[..4].copy_from_slice(&group.octets());
        if let Some(i) = ifi {
            let addrs = i.addrs().map_err(|e| e.err)?;
            for a in addrs {
                if let std::net::IpAddr::V4(v4) = a.ip {
                    mreq[4..8].copy_from_slice(&v4.octets());
                    break;
                }
            }
            if mreq[..4] == [0; 4] {
                return Err(Cause::Other("no such multicast network interface".into()));
            }
        }
        set(fd, k::IPPROTO_IP, k::IP_ADD_MEMBERSHIP, &mreq)
    }
}

/// `listenIPv6MulticastUDP`: interface, loopback off, join.
pub(crate) fn listen_ipv6(fd: i32, ifi: Option<&Interface>, group: Ipv6Addr) -> Result<(), Cause> {
    if let Some(i) = ifi {
        set(fd, k::IPPROTO_IPV6, k::IPV6_MULTICAST_IF, &i.index.to_ne_bytes())?;
    }
    set(fd, k::IPPROTO_IPV6, k::IPV6_MULTICAST_LOOP, &0i32.to_ne_bytes())?;
    // struct ipv6_mreq { multiaddr[16], interface }
    let mut mreq = [0u8; 20];
    mreq[..16].copy_from_slice(&group.octets());
    if let Some(i) = ifi {
        mreq[16..20].copy_from_slice(&(i.index as u32).to_ne_bytes());
    }
    set(fd, k::IPPROTO_IPV6, k::IPV6_JOIN_GROUP, &mreq)
}
