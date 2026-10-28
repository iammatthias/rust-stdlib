//! Go's network interface types: [`Interface`], [`Flags`], and the `Interfaces`
//! family of lookups.
//!
//! `std` has no `getifaddrs`, and FFI is not allowed, so interface discovery
//! reads `/sys/class/net` on Linux (name, index, MTU, hardware address,
//! flags). Other platforms report an unsupported-platform [`OpError`], and
//! per-interface address lists are not available anywhere (see the `net`
//! package notes in `docs/api/net.json`).
use super::error::{NetError, OpError};
#[cfg(target_os = "linux")]
use super::ip::parse_mac;
use super::ip::HardwareAddr;
use std::fmt;

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

impl std::ops::BitOr for Flags {
    type Output = Flags;
    fn bitor(self, o: Flags) -> Flags {
        Flags(self.0 | o.0)
    }
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
    /// The IEEE MAC-48, EUI-48 or EUI-64 form.
    pub hardware_addr: HardwareAddr,
    /// Attribute bits.
    pub flags: Flags,
}

fn route_error(e: NetError) -> NetError {
    OpError {
        op: "route".into(),
        net: "ip+net".into(),
        source: None,
        addr: None,
        err: Box::new(e),
    }
    .into()
}

#[cfg(target_os = "linux")]
fn interface_table() -> Result<Vec<Interface>, NetError> {
    let mut out = Vec::new();
    let dir = std::fs::read_dir("/sys/class/net").map_err(|e| NetError::from_io("open", &e))?;
    for entry in dir.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let read = |f: &str| std::fs::read_to_string(entry.path().join(f)).unwrap_or_default();
        let index = read("ifindex").trim().parse().unwrap_or(0);
        let mtu = read("mtu").trim().parse().unwrap_or(0);
        let hardware_addr = parse_mac(read("address").trim()).unwrap_or_default();
        let raw =
            u32::from_str_radix(read("flags").trim().trim_start_matches("0x"), 16).unwrap_or(0);
        let mut flags = Flags(0);
        // Linux IFF_UP, IFF_BROADCAST, IFF_LOOPBACK, IFF_POINTOPOINT, IFF_RUNNING, IFF_MULTICAST.
        for (iff, flag) in [
            (0x1, FLAG_UP),
            (0x2, FLAG_BROADCAST),
            (0x8, FLAG_LOOPBACK),
            (0x10, FLAG_POINT_TO_POINT),
            (0x40, FLAG_RUNNING),
            (0x1000, FLAG_MULTICAST),
        ] {
            if raw & iff != 0 {
                flags = flags | flag;
            }
        }
        out.push(Interface {
            index,
            mtu,
            name,
            hardware_addr,
            flags,
        });
    }
    out.sort_by_key(|i| i.index);
    Ok(out)
}

#[cfg(not(target_os = "linux"))]
fn interface_table() -> Result<Vec<Interface>, NetError> {
    Err(NetError::other(
        "network interface enumeration is not supported on this platform",
    ))
}

/// `net.Interfaces`: the system's network interfaces.
pub fn interfaces() -> Result<Vec<Interface>, NetError> {
    interface_table().map_err(route_error)
}

/// `net.InterfaceByIndex`.
pub fn interface_by_index(index: i32) -> Result<Interface, NetError> {
    if index <= 0 {
        return Err(route_error(NetError::other(
            "invalid network interface index",
        )));
    }
    interfaces()?
        .into_iter()
        .find(|i| i.index == index)
        .ok_or_else(|| route_error(NetError::other("no such network interface")))
}

/// `net.InterfaceByName`.
pub fn interface_by_name(name: &str) -> Result<Interface, NetError> {
    if name.is_empty() {
        return Err(route_error(NetError::other(
            "invalid network interface name",
        )));
    }
    interfaces()?
        .into_iter()
        .find(|i| i.name == name)
        .ok_or_else(|| route_error(NetError::other("no such network interface")))
}
