//! URLs, cookies, text protocols, mail messages and optional native blocking
//! HTTP transport.
pub mod addr;
pub mod conn;
mod dial;
mod dnsconf;
mod dnsmsg;
pub mod error;
#[cfg(feature = "net")]
pub mod http;
pub mod interface;
pub mod ip;
pub mod mail;
pub mod netip;
pub(crate) mod nettrace;
mod pipe;
mod resolver;
pub mod rpc;
#[cfg(feature = "net")]
pub mod smtp;
pub mod sock;
pub mod textproto;
mod unsupported;
pub mod url;

pub use addr::*;
pub use conn::*;
pub use dial::*;
pub use error::*;
pub use interface::*;
pub use ip::*;
pub use pipe::{pipe, PipeConn};
pub use resolver::{
    lookup_addr, lookup_cname, lookup_host, lookup_ip, lookup_mx, lookup_ns, lookup_port,
    lookup_srv, lookup_txt, resolve_ip_addr, resolve_tcp_addr, resolve_udp_addr, resolve_unix_addr,
    DialFunc, Resolver, DEFAULT_RESOLVER, MX, NS, SRV,
};
pub use sock::*;
pub use unsupported::*;
