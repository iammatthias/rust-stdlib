//! Mapping of `rust_stdlib_sys::net::OpError` onto the root crate's `net`
//! error types, keeping Go's message texts.
use rust_stdlib::net::{Addr, AddrRef, DNSError, NetError, OpError, SyscallError};
use rust_stdlib_sys::errno::Errno;
use rust_stdlib_sys::net::{Cause, OpError as SysOpError};
use std::any::Any;
use std::fmt;
use std::io;
use std::sync::Arc;

/// An address known only by its network name and text, which is all a sys
/// `OpError` keeps of it.
#[derive(Debug)]
struct TextAddr {
    network: String,
    text: String,
}

impl fmt::Display for TextAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl Addr for TextAddr {
    fn network(&self) -> &str {
        &self.network
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn text_addr(network: &str, text: &Option<String>) -> Option<AddrRef> {
    text.as_ref().map(|text| {
        Arc::new(TextAddr {
            network: network.to_owned(),
            text: text.clone(),
        }) as AddrRef
    })
}

fn errno(syscall: &str, e: Errno) -> NetError {
    NetError::Sys(SyscallError {
        syscall: syscall.to_owned(),
        text: e.to_string(),
        kind: io::Error::from_raw_os_error(e.0).kind(),
        errno: Some(e.0),
    })
}

fn cause(op: &str, c: &Cause) -> NetError {
    match c {
        Cause::Errno(e) => errno("", *e),
        Cause::Syscall(s) => errno(&s.syscall, s.err),
        // Go's dial deadline is `errTimeout` (a `context.DeadlineExceeded`);
        // a connection deadline is `os.ErrDeadlineExceeded`.
        Cause::Timeout if op == "dial" => NetError::Timeout,
        Cause::Timeout => NetError::IoTimeout,
        Cause::Closed => NetError::Closed,
        Cause::Canceled => NetError::Canceled,
        Cause::UnknownNetwork(n) => {
            NetError::UnknownNetwork(rust_stdlib::net::UnknownNetworkError(n.clone()))
        }
        Cause::Dns { name, err } => NetError::Dns(Box::new(DNSError {
            unwrap_err: None,
            err: err.clone(),
            name: name.clone(),
            server: String::new(),
            is_timeout: err == "i/o timeout",
            is_temporary: false,
            is_not_found: err == "no such host",
        })),
        other => NetError::other(other.to_string()),
    }
}

/// Maps a sys `OpError` to the root crate's `NetError::Op`: same operation,
/// network, addresses and Go message text, with the cause converted to the
/// matching root variant (`Timeout`, `Closed`, `Sys`, `Dns`, ...).
pub fn net_error(e: SysOpError) -> NetError {
    // A bare error (empty operation) has no `OpError` wrapper in Go either.
    if e.op.is_empty() {
        return cause("", &e.err);
    }
    NetError::Op(OpError {
        source: text_addr(&e.net, &e.source),
        addr: text_addr(&e.net, &e.addr),
        err: Box::new(cause(&e.op, &e.err)),
        op: e.op,
        net: e.net,
    })
}
