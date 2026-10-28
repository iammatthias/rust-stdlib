//! Go's network interface API: `net.Interfaces`, `net.InterfaceAddrs`,
//! `net.InterfaceByName`, `net.InterfaceByIndex` and the `Interface` methods.
use super::addr::{IPAddr, IPNet};
use super::error::{Cause, OpError};
use crate::errno::Errno;
use crate::ffi::{self, IfAddr};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// `net.Flags`: interface attribute bits.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, Debug)]
pub struct Flags(pub u32);

/// `net.FlagUp`: administratively up.
pub const FLAG_UP: Flags = Flags(1 << 0);
/// `net.FlagBroadcast`: supports broadcast.
pub const FLAG_BROADCAST: Flags = Flags(1 << 1);
/// `net.FlagLoopback`: a loopback interface.
pub const FLAG_LOOPBACK: Flags = Flags(1 << 2);
/// `net.FlagPointToPoint`: a point-to-point link.
pub const FLAG_POINT_TO_POINT: Flags = Flags(1 << 3);
/// `net.FlagMulticast`: supports multicast.
pub const FLAG_MULTICAST: Flags = Flags(1 << 4);
/// `net.FlagRunning`: in running state.
pub const FLAG_RUNNING: Flags = Flags(1 << 5);

const FLAG_NAMES: [&str; 6] = [
    "up",
    "broadcast",
    "loopback",
    "pointtopoint",
    "multicast",
    "running",
];

/// `Flags.String`: names joined by `|`, or "0".
impl fmt::Display for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = FLAG_NAMES
            .iter()
            .enumerate()
            .filter(|(i, _)| self.0 & (1 << i) != 0)
            .map(|(_, n)| *n)
            .collect();
        if names.is_empty() {
            f.write_str("0")
        } else {
            f.write_str(&names.join("|"))
        }
    }
}

/// Go's `HardwareAddr.String`: colon-separated lower-case hex bytes.
pub fn hardware_addr_string(hw: &[u8]) -> String {
    hw.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// `net.Interface`: a network interface and its facility information.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Interface {
    /// A positive integer that starts at one.
    pub index: i32,
    /// The maximum transmission unit.
    pub mtu: i32,
    /// The name, e.g. "eth0".
    pub name: String,
    /// The IEEE MAC-48, EUI-48 or EUI-64 form; empty when absent.
    pub hardware_addr: Vec<u8>,
    /// Attribute bits.
    pub flags: Flags,
}

fn route_error(err: Cause) -> OpError {
    OpError {
        op: "route".into(),
        net: "ip+net".into(),
        source: None,
        addr: None,
        err,
    }
}

fn syscall_cause(syscall: &str, err: Errno) -> Cause {
    Cause::Syscall(crate::os::SyscallError {
        syscall: syscall.into(),
        err,
    })
}

/// Go's `linkFlags`: from the system's `IFF_*` bits.
fn link_flags(raw: u32) -> Flags {
    #[cfg(target_os = "linux")]
    const MULTICAST: u32 = 0x1000;
    #[cfg(not(target_os = "linux"))]
    const MULTICAST: u32 = 0x8000;
    let mut flags = 0;
    for (iff, flag) in [
        (0x1, FLAG_UP),
        (0x2, FLAG_BROADCAST),
        (0x8, FLAG_LOOPBACK),
        (0x10, FLAG_POINT_TO_POINT),
        (0x40, FLAG_RUNNING),
        (MULTICAST, FLAG_MULTICAST),
    ] {
        if raw & iff != 0 {
            flags |= flag.0;
        }
    }
    Flags(flags)
}

fn interface_table() -> Result<Vec<Interface>, Errno> {
    let mut out: Vec<Interface> = Vec::new();
    for e in ffi::getifaddrs()? {
        let IfAddr::Link {
            index,
            mut hardware,
        } = e.addr
        else {
            continue;
        };
        if out.iter().any(|i| i.index == index as i32) {
            continue;
        }
        // Linux reports an all-zero address (the loopback) as absent.
        #[cfg(target_os = "linux")]
        if hardware.iter().all(|&b| b == 0) {
            hardware.clear();
        }
        #[cfg(not(target_os = "linux"))]
        let _ = &mut hardware;
        let mtu = ffi::interface_mtu(&e.name).unwrap_or(0);
        out.push(Interface {
            index: index as i32,
            mtu,
            name: e.name,
            hardware_addr: hardware,
            flags: link_flags(e.flags),
        });
    }
    Ok(out)
}

/// `net.Interfaces`: the system's network interfaces.
pub fn interfaces() -> Result<Vec<Interface>, OpError> {
    interface_table().map_err(|e| route_error(syscall_cause("getifaddrs", e)))
}

/// `net.InterfaceByIndex`: the interface with the given index.
pub fn interface_by_index(index: i64) -> Result<Interface, OpError> {
    if index <= 0 {
        return Err(route_error(Cause::InvalidInterfaceIndex));
    }
    let table = interface_table().map_err(|e| route_error(syscall_cause("getifaddrs", e)))?;
    table
        .into_iter()
        .find(|i| i64::from(i.index) == index)
        .ok_or_else(|| route_error(Cause::NoSuchInterface))
}

/// `net.InterfaceByName`: the interface with the given name.
pub fn interface_by_name(name: &str) -> Result<Interface, OpError> {
    if name.is_empty() {
        return Err(route_error(Cause::InvalidInterfaceName));
    }
    let table = interface_table().map_err(|e| route_error(syscall_cause("getifaddrs", e)))?;
    table
        .into_iter()
        .find(|i| i.name == name)
        .ok_or_else(|| route_error(Cause::NoSuchInterface))
}

fn to_ip(a: &IfAddr) -> Option<IpAddr> {
    match a {
        IfAddr::V4(o) => Some(IpAddr::V4(Ipv4Addr::from(*o))),
        IfAddr::V6(o) => {
            let mut o = *o;
            // KAME stacks embed the interface index in link-local and
            // interface/link-scope multicast addresses; Go strips it.
            if (o[0] == 0xfe && o[1] & 0xc0 == 0x80)
                || (o[0] == 0xff && (o[1] & 0x0f == 0x01 || o[1] & 0x0f == 0x02))
            {
                o[2] = 0;
                o[3] = 0;
            }
            Some(IpAddr::V6(Ipv6Addr::from(o)))
        }
        _ => None,
    }
}

fn mask_bytes(a: &IfAddr) -> Option<Vec<u8>> {
    match a {
        IfAddr::V4(o) => Some(o.to_vec()),
        IfAddr::V6(o) => Some(o.to_vec()),
        _ => None,
    }
}

fn address_table(only: Option<&Interface>) -> Result<Vec<IPNet>, OpError> {
    let entries = ffi::getifaddrs().map_err(|e| route_error(syscall_cause("getifaddrs", e)))?;
    // Interface names to indexes, so a name filter selects one interface.
    let mut out = Vec::new();
    for e in entries {
        if let Some(ifi) = only {
            if e.name != ifi.name {
                continue;
            }
        }
        let (Some(ip), Some(mask)) = (to_ip(&e.addr), e.netmask.as_ref().and_then(mask_bytes))
        else {
            continue;
        };
        out.push(IPNet { ip, mask });
    }
    Ok(out)
}

/// `net.InterfaceAddrs`: the system's unicast interface addresses.
pub fn interface_addrs() -> Result<Vec<IPNet>, OpError> {
    address_table(None)
}

impl Interface {
    /// `Interface.Addrs`: the unicast addresses of the interface.
    pub fn addrs(&self) -> Result<Vec<IPNet>, OpError> {
        address_table(Some(self))
    }

    /// `Interface.MulticastAddrs`: the multicast groups joined on the interface.
    pub fn multicast_addrs(&self) -> Result<Vec<IPAddr>, OpError> {
        multicast_table(self).map_err(route_error)
    }
}

#[cfg(target_os = "linux")]
fn multicast_table(ifi: &Interface) -> Result<Vec<IPAddr>, Cause> {
    let mut out = parse_proc_igmp(
        &std::fs::read_to_string("/proc/net/igmp").unwrap_or_default(),
        ifi,
    );
    out.extend(parse_proc_igmp6(
        &std::fs::read_to_string("/proc/net/igmp6").unwrap_or_default(),
        ifi,
    ));
    Ok(out)
}

#[cfg(target_os = "macos")]
fn multicast_table(ifi: &Interface) -> Result<Vec<IPAddr>, Cause> {
    let groups = ffi::multicast_groups(ifi.index as u32).map_err(|e| syscall_cause("sysctl", e))?;
    Ok(groups
        .iter()
        .filter(|(index, _)| i64::from(*index) == i64::from(ifi.index))
        .filter_map(|(_, a)| to_ip(a))
        .map(IPAddr::new)
        .collect())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn multicast_table(_ifi: &Interface) -> Result<Vec<IPAddr>, Cause> {
    Err(syscall_cause("route", crate::errno::ENOSYS))
}

/// Go's `parseProcNetIGMP`.
#[cfg(any(target_os = "linux", test))]
fn parse_proc_igmp(text: &str, ifi: &Interface) -> Vec<IPAddr> {
    let mut out = Vec::new();
    let mut name = "";
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line
            .split([' ', ':', '\r', '\t', '\n'])
            .filter(|s| !s.is_empty())
            .collect();
        if fields.len() < 4 {
            continue;
        }
        if !line.starts_with([' ', '\t']) {
            name = fields[1];
        } else if fields[0].len() == 8 && name == ifi.name {
            let mut b = [0u8; 4];
            for (i, byte) in b.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&fields[0][2 * i..2 * i + 2], 16).unwrap_or(0);
            }
            // The kernel prints the address in native byte order.
            let ip = u32::from_ne_bytes(b).to_be_bytes();
            out.push(IPAddr::new(IpAddr::V4(Ipv4Addr::from(ip))));
        }
    }
    out
}

/// Go's `parseProcNetIGMP6`.
#[cfg(any(target_os = "linux", test))]
fn parse_proc_igmp6(text: &str, ifi: &Interface) -> Vec<IPAddr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line
            .split([' ', '\r', '\t', '\n'])
            .filter(|s| !s.is_empty())
            .collect();
        if fields.len() < 6 || fields[1] != ifi.name {
            continue;
        }
        let mut b = [0u8; 16];
        for (i, byte) in b.iter_mut().enumerate() {
            let pair = fields[2].get(2 * i..2 * i + 2).unwrap_or("00");
            *byte = u8::from_str_radix(pair, 16).unwrap_or(0);
        }
        out.push(IPAddr::new(IpAddr::V6(Ipv6Addr::from(b))));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_string() {
        assert_eq!(Flags(0).to_string(), "0");
        assert_eq!(
            Flags(FLAG_UP.0 | FLAG_LOOPBACK.0 | FLAG_RUNNING.0).to_string(),
            "up|loopback|running"
        );
    }

    #[test]
    fn igmp_parsing() {
        let ifi = Interface {
            name: "eth0".into(),
            ..Interface::default()
        };
        let text = "Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter\n\
                    1\tlo        :     1      V3\n\
                    \t\t\t\t010000E0     1 0:00000000\t\t0\n\
                    2\teth0      :     1      V3\n\
                    \t\t\t\t010000E0     1 0:00000000\t\t0\n";
        let got = parse_proc_igmp(text, &ifi);
        assert_eq!(got.len(), 1);
        if cfg!(target_endian = "little") {
            assert_eq!(got[0].to_string(), "224.0.0.1");
        }
        let text6 = "2    eth0            ff020000000000000000000000000001     1 0000000C 0\n";
        let got6 = parse_proc_igmp6(text6, &ifi);
        assert_eq!(got6[0].to_string(), "ff02::1");
    }
}
