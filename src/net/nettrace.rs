//! Go's `internal/nettrace`: the hooks `net/http/httptrace` installs in a
//! context so the resolver and the dialer can report DNS and connect events.
#![allow(clippy::type_complexity)]
use std::sync::{Arc, LazyLock};

use super::addr::IPAddr;
use super::error::NetError;
use crate::context::{self, Context};

/// Hooks called by the resolver and the dialer; each is optional.
#[derive(Clone, Default)]
pub struct Trace {
    /// Called with the host about to be looked up.
    pub dns_start: Option<Arc<dyn Fn(&str) + Send + Sync>>,
    /// Called with the addresses found, whether the lookup was shared with
    /// another caller, and the error.
    pub dns_done: Option<Arc<dyn Fn(&[IPAddr], bool, Option<&NetError>) + Send + Sync>>,
    /// Called before each connection attempt with the network and address.
    pub connect_start: Option<Arc<dyn Fn(&str, &str) + Send + Sync>>,
    /// Called after each connection attempt.
    pub connect_done: Option<Arc<dyn Fn(&str, &str, Option<&NetError>) + Send + Sync>>,
}

/// The context key holding the [`Trace`] (Go's `nettrace.TraceKey`).
pub static TRACE_KEY: LazyLock<context::Key<Trace>> =
    LazyLock::new(|| context::Key::named("net-trace"));

/// The trace installed in `ctx`, if any.
pub(crate) fn from_context(ctx: &Context) -> Option<Arc<Trace>> {
    ctx.value(&TRACE_KEY)
}
