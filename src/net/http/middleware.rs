//! `TimeoutHandler` and `CrossOriginProtection`.
use super::handler::handler_func as handler_func_arc;
use super::handler::{Handler, ResponseWriter};
use super::header::{
    io_error, BoxError, ErrorString, Header, ERR_HANDLER_TIMEOUT, ERR_NOT_SUPPORTED,
};
use super::request::Request;
use super::servemux::ServeMux;
use super::status::*;
use super::util::error;
use crate::context;
use crate::net::url;
use crate::time::Duration;
use std::{
    collections::BTreeSet,
    io,
    sync::{
        mpsc::{channel, RecvTimeoutError},
        Arc, Mutex, RwLock,
    },
    time::Duration as StdDuration,
};

/// Go's `http.TimeoutHandler`: runs `h` with a time limit; on timeout the
/// client gets 503 and `msg` (or a default HTML body).
pub fn timeout_handler(h: Arc<dyn Handler>, dt: Duration, msg: &str) -> Arc<dyn Handler> {
    Arc::new(TimeoutHandler {
        handler: h,
        body: msg.to_owned(),
        dt,
    })
}

struct TimeoutHandler {
    handler: Arc<dyn Handler>,
    body: String,
    dt: Duration,
}

impl TimeoutHandler {
    fn error_body(&self) -> &str {
        if self.body.is_empty() {
            "<html><head><title>Timeout</title></head><body><h1>Timeout</h1></body></html>"
        } else {
            &self.body
        }
    }
}

#[derive(Default)]
struct TwShared {
    err: Option<TwErr>,
    wbuf: Vec<u8>,
    wrote_header: bool,
    code: u16,
}
#[derive(Clone)]
enum TwErr {
    Timeout,
    Other(String),
}

struct TimeoutWriter {
    h: Header,
    shared: Arc<Mutex<TwShared>>,
    inner_pusher: bool,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl std::io::Write for TimeoutWriter {
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        let mut g = lock(&self.shared);
        match &g.err {
            Some(TwErr::Timeout) => return Err(io_error(ERR_HANDLER_TIMEOUT)),
            Some(TwErr::Other(s)) => return Err(io::Error::other(s.clone())),
            None => {}
        }
        if !g.wrote_header {
            write_header_locked(&mut g, STATUS_OK);
        }
        g.wbuf.extend_from_slice(p);
        Ok(p.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl ResponseWriter for TimeoutWriter {
    fn header(&mut self) -> &mut Header {
        &mut self.h
    }
    fn write_header(&mut self, code: u16) {
        let mut g = lock(&self.shared);
        write_header_locked(&mut g, code);
    }
}

fn write_header_locked(g: &mut TwShared, code: u16) {
    if !(100..=999).contains(&code) {
        panic!("invalid WriteHeader code {code}");
    }
    if g.err.is_some() {
        return;
    }
    if !g.wrote_header {
        g.wrote_header = true;
        g.code = code;
    }
}

impl super::header::Pusher for TimeoutWriter {
    fn push(
        &mut self,
        _target: &str,
        _opts: Option<&super::header::PushOptions>,
    ) -> Result<(), BoxError> {
        let _ = self.inner_pusher;
        Err(Box::new(ERR_NOT_SUPPORTED))
    }
}

impl Handler for TimeoutHandler {
    fn serve_http(&self, w: &mut dyn ResponseWriter, r: &mut Request) {
        let (ctx, cancel) = r.context().with_timeout(self.dt);
        let mut r2 = r.with_context(&ctx);
        let shared = Arc::new(Mutex::new(TwShared::default()));
        let (tx, rx) = channel::<Result<Header, Box<dyn std::any::Any + Send>>>();
        let handler = self.handler.clone();
        let mut tw = TimeoutWriter {
            h: Header::new(),
            shared: shared.clone(),
            inner_pusher: false,
        };
        std::thread::spawn(move || {
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                handler.serve_http(&mut tw, &mut r2);
            }));
            let _ = tx.send(res.map(|()| tw.h));
        });
        let done = ctx.done();
        loop {
            match rx.recv_timeout(StdDuration::from_millis(2)) {
                Ok(Ok(h)) => {
                    let mut g = lock(&shared);
                    for (k, v) in h.0 {
                        w.header().0.insert(k, v);
                    }
                    if !g.wrote_header {
                        g.code = STATUS_OK;
                    }
                    w.write_header(g.code);
                    let _ = w.write(&g.wbuf);
                    break;
                }
                Ok(Err(p)) => {
                    cancel();
                    std::panic::resume_unwind(p);
                }
                Err(RecvTimeoutError::Timeout) => {
                    if done.is_done() {
                        let mut g = lock(&shared);
                        match ctx.err() {
                            Some(context::Error::DeadlineExceeded) => {
                                w.write_header(STATUS_SERVICE_UNAVAILABLE);
                                let _ = w.write_string(self.error_body());
                                g.err = Some(TwErr::Timeout);
                            }
                            other => {
                                w.write_header(STATUS_SERVICE_UNAVAILABLE);
                                g.err = Some(TwErr::Other(
                                    other.map_or_else(String::new, |e| e.to_string()),
                                ));
                            }
                        }
                        break;
                    }
                }
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        cancel();
    }
}

// ------------------------------------------------- CrossOriginProtection

const ERR_CROSS_ORIGIN_REQUEST: ErrorString =
    ErrorString("cross-origin request detected from Sec-Fetch-Site header");
const ERR_CROSS_ORIGIN_OLD_BROWSER: ErrorString = ErrorString(
    "cross-origin request detected, and/or browser is out of date: Sec-Fetch-Site is missing, and Origin does not match Host",
);

struct Noop;
impl Handler for Noop {
    fn serve_http(&self, _: &mut dyn ResponseWriter, _: &mut Request) {}
}

#[derive(Default)]
struct CopInner {
    bypass: RwLock<Option<ServeMux>>,
    trusted: RwLock<BTreeSet<String>>,
    deny: RwLock<Option<Arc<dyn Handler>>>,
    sentinel: RwLock<Option<Arc<dyn Handler>>>,
}

/// Go's `http.CrossOriginProtection`: rejects non-safe cross-origin browser
/// requests using `Sec-Fetch-Site` and `Origin`.
#[derive(Clone, Default)]
pub struct CrossOriginProtection {
    inner: Arc<CopInner>,
}

impl CrossOriginProtection {
    /// Go's `NewCrossOriginProtection`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Go's `AddTrustedOrigin`.
    pub fn add_trusted_origin(&self, origin: &str) -> Result<(), BoxError> {
        use crate::strconv::quote;
        let u = url::parse(origin)
            .map_err(|e| -> BoxError { format!("invalid origin {}: {e}", quote(origin)).into() })?;
        if u.scheme.is_empty() {
            return Err(format!("invalid origin {}: scheme is required", quote(origin)).into());
        }
        if u.host.is_empty() {
            return Err(format!("invalid origin {}: host is required", quote(origin)).into());
        }
        if !u.path.is_empty() || !u.raw_query.is_empty() || !u.fragment.is_empty() {
            return Err(format!(
                "invalid origin {}: path, query, and fragment are not allowed",
                quote(origin)
            )
            .into());
        }
        self.inner
            .trusted
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(origin.to_owned());
        Ok(())
    }

    /// Go's `AddInsecureBypassPattern`. Go panics on a bad pattern; here the
    /// registration error is returned.
    pub fn add_insecure_bypass_pattern(&self, pattern: &str) -> Result<(), BoxError> {
        let sentinel = {
            let mut s = self
                .inner
                .sentinel
                .write()
                .unwrap_or_else(|e| e.into_inner());
            s.get_or_insert_with(|| Arc::new(Noop) as Arc<dyn Handler>)
                .clone()
        };
        let mut b = self.inner.bypass.write().unwrap_or_else(|e| e.into_inner());
        b.get_or_insert_with(ServeMux::new)
            .handle(pattern, sentinel)
    }

    /// Go's `SetDenyHandler`.
    pub fn set_deny_handler(&self, h: Option<Arc<dyn Handler>>) {
        *self.inner.deny.write().unwrap_or_else(|e| e.into_inner()) = h;
    }

    /// Go's `Check`.
    pub fn check(&self, req: &Request) -> Result<(), BoxError> {
        if matches!(req.method.as_str(), "GET" | "HEAD" | "OPTIONS") {
            return Ok(());
        }
        match req.header.get_str("Sec-Fetch-Site") {
            "" => {}
            "same-origin" | "none" => return Ok(()),
            _ => {
                if self.is_request_exempt(req) {
                    return Ok(());
                }
                return Err(Box::new(ERR_CROSS_ORIGIN_REQUEST));
            }
        }
        let origin = req.header.get_str("Origin");
        if origin.is_empty() {
            return Ok(());
        }
        if let Ok(o) = url::parse(origin) {
            if o.host == req.host {
                return Ok(());
            }
        }
        if self.is_request_exempt(req) {
            return Ok(());
        }
        Err(Box::new(ERR_CROSS_ORIGIN_OLD_BROWSER))
    }

    fn is_request_exempt(&self, req: &Request) -> bool {
        if let Some(bypass) = self
            .inner
            .bypass
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            let (h, _) = bypass.handler(req);
            let sentinel = self
                .inner
                .sentinel
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            if let Some(s) = sentinel {
                if std::ptr::eq(Arc::as_ptr(&h) as *const (), Arc::as_ptr(&s) as *const ()) {
                    return true;
                }
            }
        }
        let origin = req.header.get_str("Origin");
        !origin.is_empty()
            && self
                .inner
                .trusted
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .contains(origin)
    }

    /// Go's `Handler`: wraps `h`, replying 403 (or the deny handler) when
    /// `check` fails.
    pub fn handler(&self, h: Arc<dyn Handler>) -> Arc<dyn Handler> {
        let me = self.clone();
        handler_func_arc(move |w, r| {
            if let Err(e) = me.check(r) {
                let deny = me
                    .inner
                    .deny
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                if let Some(d) = deny {
                    d.serve_http(w, r);
                    return;
                }
                error(w, &e.to_string(), STATUS_FORBIDDEN);
                return;
            }
            h.serve_http(w, r);
        })
    }
}
