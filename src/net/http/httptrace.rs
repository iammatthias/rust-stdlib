//! Go's `net/http/httptrace`: hooks that trace the events of an HTTP client
//! request.
//!
//! Install a [`ClientTrace`] in a request context with [`with_client_trace`];
//! the Go-shaped [`Transport`](super::transport::Transport) then reports
//! connection acquisition, DNS and TCP connects, TLS handshakes, request
//! writing and response reading in Go's order. Hooks may run on several
//! threads and must not block.
//!
//! ```
//! use rust_stdlib::context::Context;
//! use rust_stdlib::net::http::httptrace::{context_client_trace, with_client_trace, ClientTrace};
//! use std::sync::Arc;
//! let trace = ClientTrace {
//!     get_conn: Some(Arc::new(|host_port| println!("getting {host_port}"))),
//!     ..ClientTrace::default()
//! };
//! let ctx = with_client_trace(&Context::background(), trace);
//! assert!(context_client_trace(&ctx).unwrap().get_conn.is_some());
//! ```
#![allow(clippy::type_complexity)]
use crate::time::Duration;
use std::error::Error;
use std::sync::{Arc, LazyLock};

use super::header::{BoxError, Header};
use super::tlsstate::ConnectionState;
use crate::context::{self, Context};
use crate::net::nettrace;
use crate::net::{Conn, IPAddr, NetError};

/// An error as the trace hooks receive it.
pub type HookError = dyn Error + Send + Sync + 'static;
/// A shared error, as stored in [`DNSDoneInfo`] and [`WroteRequestInfo`].
pub type SharedError = Arc<HookError>;

/// Go's `httptrace.GotConnInfo`: the connection a request got.
#[derive(Clone)]
pub struct GotConnInfo {
    /// The connection (Go `Conn`).
    pub conn: Arc<dyn Conn>,
    /// Whether the connection was used for a previous request (Go `Reused`).
    pub reused: bool,
    /// Whether the connection came from the idle pool (Go `WasIdle`).
    pub was_idle: bool,
    /// How long it was idle, when `was_idle` (Go `IdleTime`).
    pub idle_time: Duration,
}

/// Go's `httptrace.DNSStartInfo`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DNSStartInfo {
    pub host: String,
}

/// Go's `httptrace.DNSDoneInfo`.
#[derive(Clone, Debug, Default)]
pub struct DNSDoneInfo {
    /// The addresses found (Go `Addrs`).
    pub addrs: Vec<IPAddr>,
    /// The lookup error (Go `Err`).
    pub err: Option<Arc<NetError>>,
    /// Whether the result was shared with another lookup (Go `Coalesced`).
    pub coalesced: bool,
}

/// Go's `httptrace.WroteRequestInfo`.
#[derive(Clone, Default)]
pub struct WroteRequestInfo {
    /// Any error encountered while writing the request (Go `Err`).
    pub err: Option<SharedError>,
}

type Hook0 = Option<Arc<dyn Fn() + Send + Sync>>;

/// Go's `httptrace.ClientTrace`: a set of hooks run at various points in an
/// HTTP request's lifecycle. Any set of hooks may be `None`.
///
/// Compared with Go, error arguments are `Option<&dyn Error>` (Go's nil is
/// `None`) and `Got1xxResponse` receives the response [`Header`].
#[derive(Clone, Default)]
pub struct ClientTrace {
    /// Called before a connection is created or retrieved from an idle pool,
    /// with the `host:port` of the target or proxy (Go `GetConn`).
    pub get_conn: Option<Arc<dyn Fn(&str) + Send + Sync>>,
    /// Called after a connection is obtained, new or idle (Go `GotConn`).
    pub got_conn: Option<Arc<dyn Fn(GotConnInfo) + Send + Sync>>,
    /// Called when a connection is returned to the idle pool, with the reason
    /// it was not, if any (Go `PutIdleConn`).
    pub put_idle_conn: Option<Arc<dyn Fn(Option<&HookError>) + Send + Sync>>,
    /// Called when the first byte of the response headers is available (Go
    /// `GotFirstResponseByte`).
    pub got_first_response_byte: Hook0,
    /// Called if the server replies with "100 Continue" (Go `Got100Continue`).
    pub got_100_continue: Hook0,
    /// Called for each 1xx informational response before the final one, except
    /// 100 (which has its own hook) and 101. An error aborts the round trip
    /// (Go `Got1xxResponse`).
    pub got_1xx_response: Option<Arc<dyn Fn(u16, &Header) -> Result<(), BoxError> + Send + Sync>>,
    /// Called when a DNS lookup begins (Go `DNSStart`).
    pub dns_start: Option<Arc<dyn Fn(DNSStartInfo) + Send + Sync>>,
    /// Called when a DNS lookup ends (Go `DNSDone`).
    pub dns_done: Option<Arc<dyn Fn(DNSDoneInfo) + Send + Sync>>,
    /// Called when a new connection's Dial begins, with the network and
    /// address (Go `ConnectStart`).
    pub connect_start: Option<Arc<dyn Fn(&str, &str) + Send + Sync>>,
    /// Called when a new connection's Dial completes (Go `ConnectDone`).
    pub connect_done: Option<Arc<dyn Fn(&str, &str, Option<&HookError>) + Send + Sync>>,
    /// Called when the TLS handshake is started (Go `TLSHandshakeStart`).
    pub tls_handshake_start: Hook0,
    /// Called after the TLS handshake with either the successful handshake's
    /// connection state or an error (Go `TLSHandshakeDone`).
    pub tls_handshake_done: Option<Arc<dyn Fn(&ConnectionState, Option<&HookError>) + Send + Sync>>,
    /// Called after the Transport has written each request header (Go
    /// `WroteHeaderField`).
    pub wrote_header_field: Option<Arc<dyn Fn(&str, &[String]) + Send + Sync>>,
    /// Called after the Transport has written all request headers (Go
    /// `WroteHeaders`).
    pub wrote_headers: Hook0,
    /// Called if the request has "Expect: 100-continue" and the Transport has
    /// written the request headers but is waiting for the server (Go
    /// `Wait100Continue`).
    pub wait_100_continue: Hook0,
    /// Called with the result of writing the request and any body (Go
    /// `WroteRequest`).
    pub wrote_request: Option<Arc<dyn Fn(WroteRequestInfo) + Send + Sync>>,
}

static CLIENT_EVENT_KEY: LazyLock<context::Key<ClientTrace>> =
    LazyLock::new(|| context::Key::named("httptrace.clientEventContextKey"));

/// Go's `httptrace.ContextClientTrace`: the [`ClientTrace`] associated with
/// `ctx`, or `None`.
pub fn context_client_trace(ctx: &Context) -> Option<Arc<ClientTrace>> {
    ctx.value(&CLIENT_EVENT_KEY)
}

/// Go's `httptrace.WithClientTrace`: a context based on `ctx` that carries
/// `trace`. If `ctx` already has a trace, the new hooks run first and the old
/// ones after them, as Go composes them.
pub fn with_client_trace(ctx: &Context, mut trace: ClientTrace) -> Context {
    if let Some(old) = context_client_trace(ctx) {
        trace.compose(&old);
    }
    let net_trace = trace.net_trace();
    let mut ctx = ctx.with_value(&CLIENT_EVENT_KEY, trace);
    if let Some(nt) = net_trace {
        ctx = ctx.with_value(&nettrace::TRACE_KEY, nt);
    }
    ctx
}

fn compose0(f1: &Hook0, f2: &Hook0) -> Hook0 {
    match (f1, f2) {
        (None, f) | (f, None) => f.clone(),
        (Some(a), Some(b)) => {
            let (a, b) = (a.clone(), b.clone());
            Some(Arc::new(move || {
                a();
                b();
            }))
        }
    }
}

/// Composes two single-argument hooks: `f1` runs first, then `f2`.
fn compose1<A: Clone + 'static>(
    f1: &Option<Arc<dyn Fn(A) + Send + Sync>>,
    f2: &Option<Arc<dyn Fn(A) + Send + Sync>>,
) -> Option<Arc<dyn Fn(A) + Send + Sync>> {
    match (f1, f2) {
        (None, f) | (f, None) => f.clone(),
        (Some(a), Some(b)) => {
            let (a, b) = (a.clone(), b.clone());
            Some(Arc::new(move |x: A| {
                a(x.clone());
                b(x);
            }))
        }
    }
}

impl ClientTrace {
    fn compose(&mut self, old: &ClientTrace) {
        self.get_conn = match (&self.get_conn, &old.get_conn) {
            (None, f) | (f, None) => f.clone(),
            (Some(f1), Some(f2)) => {
                let (f1, f2) = (f1.clone(), f2.clone());
                Some(Arc::new(move |a: &str| {
                    f1(a);
                    f2(a);
                }))
            }
        };
        self.got_conn = compose1(&self.got_conn, &old.got_conn);
        self.put_idle_conn = match (&self.put_idle_conn, &old.put_idle_conn) {
            (None, f) | (f, None) => f.clone(),
            (Some(f1), Some(f2)) => {
                let (f1, f2) = (f1.clone(), f2.clone());
                Some(Arc::new(move |a: Option<&HookError>| {
                    f1(a);
                    f2(a);
                }))
            }
        };
        self.got_first_response_byte =
            compose0(&self.got_first_response_byte, &old.got_first_response_byte);
        self.got_100_continue = compose0(&self.got_100_continue, &old.got_100_continue);
        // Go's compose2to1 runs both and returns the old hook's result.
        self.got_1xx_response = match (&self.got_1xx_response, &old.got_1xx_response) {
            (None, f) | (f, None) => f.clone(),
            (Some(a), Some(b)) => {
                let (a, b) = (a.clone(), b.clone());
                Some(Arc::new(move |code, header| {
                    let _ = a(code, header);
                    b(code, header)
                }))
            }
        };
        self.dns_start = compose1(&self.dns_start, &old.dns_start);
        self.dns_done = compose1(&self.dns_done, &old.dns_done);
        self.connect_start = match (&self.connect_start, &old.connect_start) {
            (None, f) | (f, None) => f.clone(),
            (Some(a), Some(b)) => {
                let (a, b) = (a.clone(), b.clone());
                Some(Arc::new(move |n: &str, addr: &str| {
                    a(n, addr);
                    b(n, addr);
                }))
            }
        };
        self.connect_done = match (&self.connect_done, &old.connect_done) {
            (None, f) | (f, None) => f.clone(),
            (Some(a), Some(b)) => {
                let (a, b) = (a.clone(), b.clone());
                Some(Arc::new(
                    move |n: &str, addr: &str, e: Option<&HookError>| {
                        a(n, addr, e);
                        b(n, addr, e);
                    },
                ))
            }
        };
        self.tls_handshake_start = compose0(&self.tls_handshake_start, &old.tls_handshake_start);
        self.tls_handshake_done = match (&self.tls_handshake_done, &old.tls_handshake_done) {
            (None, f) | (f, None) => f.clone(),
            (Some(a), Some(b)) => {
                let (a, b) = (a.clone(), b.clone());
                Some(Arc::new(
                    move |s: &ConnectionState, e: Option<&HookError>| {
                        a(s, e);
                        b(s, e);
                    },
                ))
            }
        };
        self.wrote_header_field = match (&self.wrote_header_field, &old.wrote_header_field) {
            (None, f) | (f, None) => f.clone(),
            (Some(a), Some(b)) => {
                let (a, b) = (a.clone(), b.clone());
                Some(Arc::new(move |k: &str, v: &[String]| {
                    a(k, v);
                    b(k, v);
                }))
            }
        };
        self.wrote_headers = compose0(&self.wrote_headers, &old.wrote_headers);
        self.wait_100_continue = compose0(&self.wait_100_continue, &old.wait_100_continue);
        self.wrote_request = compose1(&self.wrote_request, &old.wrote_request);
    }

    fn has_net_hooks(&self) -> bool {
        self.dns_start.is_some()
            || self.dns_done.is_some()
            || self.connect_start.is_some()
            || self.connect_done.is_some()
    }

    /// The resolver and dialer hooks (Go's `nettrace.Trace`).
    fn net_trace(&self) -> Option<nettrace::Trace> {
        if !self.has_net_hooks() {
            return None;
        }
        let mut nt = nettrace::Trace::default();
        if let Some(f) = self.connect_start.clone() {
            nt.connect_start = Some(Arc::new(move |n, a| f(n, a)));
        }
        if let Some(f) = self.connect_done.clone() {
            nt.connect_done = Some(Arc::new(move |n, a, e| {
                f(n, a, e.map(|e| e as &HookError));
            }));
        }
        if let Some(f) = self.dns_start.clone() {
            nt.dns_start = Some(Arc::new(move |host| {
                f(DNSStartInfo {
                    host: host.to_owned(),
                })
            }));
        }
        if let Some(f) = self.dns_done.clone() {
            nt.dns_done = Some(Arc::new(move |addrs, coalesced, err| {
                f(DNSDoneInfo {
                    addrs: addrs.to_vec(),
                    err: err.map(|e| Arc::new(e.clone())),
                    coalesced,
                })
            }));
        }
        Some(nt)
    }
}
