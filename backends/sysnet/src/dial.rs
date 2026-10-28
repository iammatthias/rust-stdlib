//! A sys `Dialer` as a `Transport::dial_context` hook.
use crate::{error::net_error, Conn};
use rust_stdlib::context::{self, Context};
use rust_stdlib::net::http::header::BoxError;
use rust_stdlib::net::http::transport::DialContextFn;
use rust_stdlib_sys::net::{self as sys, ContextError};
use std::sync::Arc;
use std::time::SystemTime;

/// The root crate's [`Context`] seen as the sys crate's dial context
/// (deadline and cancellation).
pub struct ContextAdapter<'a>(pub &'a Context);

impl sys::Context for ContextAdapter<'_> {
    fn deadline(&self) -> Option<SystemTime> {
        let at = self.0.deadline()?;
        let now = std::time::Instant::now();
        Some(match at.checked_duration_since(now) {
            Some(ahead) => SystemTime::now() + ahead,
            None => SystemTime::now() - now.duration_since(at),
        })
    }
    fn err(&self) -> Option<ContextError> {
        self.0.err().map(|e| match e {
            context::Error::Canceled => ContextError::Canceled,
            _ => ContextError::DeadlineExceeded,
        })
    }
    fn can_cancel(&self) -> bool {
        !self.0.done().is_never()
    }
}

/// Wraps a sys `Dialer` as `Transport::dial_context` (Go's
/// `Transport.DialContext`). Connections keep whatever the dialer sets, such
/// as `keep_alive` and `keep_alive_config`; errors become the root `net`
/// error types with Go's texts.
///
/// ```no_run
/// use rust_stdlib::net::http::transport::Transport;
/// use rust_stdlib_sys::net::Dialer;
///
/// let dialer = Dialer { keep_alive: 30_000_000_000, ..Dialer::default() };
/// let t = Transport {
///     dial_context: Some(rust_stdlib_sysnet::dial_context(dialer)),
///     ..Transport::default()
/// };
/// ```
pub fn dial_context(dialer: sys::Dialer) -> DialContextFn {
    let dialer = Arc::new(dialer);
    Arc::new(move |ctx, network, addr| {
        dialer
            .dial_context(&ContextAdapter(ctx), network, addr)
            .map(|c| Box::new(Conn::new(c)) as Box<dyn rust_stdlib::net::Conn>)
            .map_err(|e| Box::new(net_error(e)) as BoxError)
    })
}
