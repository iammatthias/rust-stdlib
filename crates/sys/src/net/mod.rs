//! Go's `net` package features that need operating-system calls std does not
//! expose: interface enumeration, socket options, raw descriptors, raw IP
//! and Unix packet sockets, message I/O, local-address binds and control
//! hooks.
mod addr;
mod error;
mod iface;
mod resolve;

pub use addr::*;
pub use error::*;
pub use iface::*;
pub use resolve::*;

supported! {
    mod dial;
    mod ipconn;
    mod listener;
    mod lookup;
    mod msg;
    mod multicast;
    mod sockconn;
    mod socket;
    mod sockopt;
    mod tcpconn;
    mod udpconn;
    mod unixsock;
    pub use dial::*;
    pub use ipconn::{strip_ipv4_header, IPConn};
    pub use listener::TCPListener;
    pub use lookup::*;
    pub use msg::*;
    pub use socket::{Background, Context, ContextError, ControlContextFn, ControlFn};
    pub use sockopt::*;
    pub use tcpconn::TCPConn;
    pub use udpconn::UDPConn;
    pub use unixsock::{UnixConn, UnixListener};
}
