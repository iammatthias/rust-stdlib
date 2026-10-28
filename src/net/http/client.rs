//! Go's `http.Client`: redirect policy, header stripping on cross-domain
//! redirects, cookie jar integration, `Client.Timeout`, and the
//! `RoundTripper` interface.
#![allow(clippy::type_complexity)]
use super::body::{Body, ReadCloser};
use super::cookie::{Cookie, CookieJar};
use super::header::{BoxError, ErrorString, Header, ERR_USE_LAST_RESPONSE};
use super::request::{Request, RequestBody};
use super::response::Response;
use super::transfer::quote_list;
use crate::context::Context;
use crate::net::url::{self, Url, Values};
use crate::time::{self, Duration};
use std::{
    fmt,
    io::{self, Read},
    sync::{Arc, LazyLock, Mutex},
};

/// Go's `http.RoundTripper`: executes one HTTP transaction.
///
/// `close_idle_connections` and `cancel_request` are Go's optional
/// `CloseIdleConnections` and `CancelRequest` interfaces.
pub trait RoundTripper: Send + Sync {
    fn round_trip(&self, req: &Request) -> Result<Response, BoxError>;
    fn close_idle_connections(&self) {}
    fn cancel_request(&self, _req: &Request) {}
    /// Whether the client may cancel requests through their context (Go's
    /// `knownRoundTripperImpl`).
    fn is_known_impl(&self) -> bool {
        false
    }
}

/// `Client.CheckRedirect`.
pub type CheckRedirect = Arc<dyn Fn(&Request, &[Request]) -> Result<(), BoxError> + Send + Sync>;

/// Go's `http.Client`.
#[derive(Clone, Default)]
pub struct Client {
    pub transport: Option<Arc<dyn RoundTripper>>,
    pub check_redirect: Option<CheckRedirect>,
    pub jar: Option<Arc<dyn CookieJar>>,
    pub timeout: Duration,
}

/// Go's `http.DefaultClient`.
pub static DEFAULT_CLIENT: LazyLock<Client> = LazyLock::new(Client::default);

/// A timeout error whose text and `Timeout()` match Go's `timeoutError`.
#[derive(Debug, Clone)]
pub struct TimeoutError(pub String);
impl fmt::Display for TimeoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for TimeoutError {}
impl TimeoutError {
    pub fn timeout(&self) -> bool {
        true
    }
    pub fn temporary(&self) -> bool {
        true
    }
}

fn refer_for_url(last_req: &Url, new_req: &Url, explicit_ref: &str) -> String {
    if last_req.scheme == "https" && new_req.scheme == "http" {
        return String::new();
    }
    if !explicit_ref.is_empty() {
        return explicit_ref.to_owned();
    }
    let mut referer = last_req.to_string();
    if let Some(u) = &last_req.user {
        let auth = format!("{}@", u);
        referer = referer.replacen(&auth, "", 1);
    }
    referer
}

pub(crate) fn basic_auth(username: &str, password: &str) -> String {
    crate::encoding::base64::STANDARD.encode(format!("{username}:{password}").as_bytes())
}

impl Client {
    pub fn new() -> Self {
        Self::default()
    }

    fn transport(&self) -> Arc<dyn RoundTripper> {
        match &self.transport {
            Some(t) => t.clone(),
            None => super::transport::default_transport(),
        }
    }

    fn deadline(&self) -> Option<std::time::Instant> {
        if self.timeout.as_nanos() > 0 {
            Some(std::time::Instant::now() + self.timeout.to_std())
        } else {
            None
        }
    }

    /// Go's `Client.send`: cookies around one round trip.
    fn send_with_cookies(
        &self,
        req: &mut Request,
        deadline: Option<std::time::Instant>,
    ) -> Result<
        (Response, Option<Arc<dyn Fn() -> bool + Send + Sync>>),
        (BoxError, Option<Arc<dyn Fn() -> bool + Send + Sync>>),
    > {
        let mut cookie_url = req.url.clone();
        if !req.host.is_empty() {
            cookie_url.host = req.host.clone();
        }
        if let Some(jar) = &self.jar {
            for c in jar.cookies(&cookie_url) {
                req.add_cookie(&c);
            }
        }
        let (resp, did_timeout) = match send(req, &*self.transport(), deadline) {
            Ok(r) => r,
            Err((e, dt)) => return Err((e, dt)),
        };
        if let Some(jar) = &self.jar {
            let rc = resp.cookies();
            if !rc.is_empty() {
                jar.set_cookies(&cookie_url, &rc);
            }
        }
        Ok((resp, did_timeout))
    }

    fn check_redirect(&self, req: &Request, via: &[Request]) -> Result<(), BoxError> {
        match &self.check_redirect {
            Some(f) => f(req, via),
            None => default_check_redirect(req, via),
        }
    }

    /// Go's `Get`.
    pub fn get(&self, url: &str) -> Result<Response, BoxError> {
        let req = Request::new("GET", url)?;
        self.do_request(req)
    }

    /// Go's `Head`.
    pub fn head(&self, url: &str) -> Result<Response, BoxError> {
        let req = Request::new("HEAD", url)?;
        self.do_request(req)
    }

    /// Go's `Post`.
    pub fn post(
        &self,
        url: &str,
        content_type: &str,
        body: Option<RequestBody>,
    ) -> Result<Response, BoxError> {
        let mut req = Request::new("POST", url)?;
        if let Some(body) = body {
            req = req.with_body(body);
        }
        req.header.set("Content-Type", content_type);
        self.do_request(req)
    }

    /// Go's `PostForm`.
    pub fn post_form(&self, url: &str, data: &Values) -> Result<Response, BoxError> {
        self.post(
            url,
            "application/x-www-form-urlencoded",
            Some(RequestBody::Bytes(data.encode().into_bytes())),
        )
    }

    /// Go's `CloseIdleConnections`.
    pub fn close_idle_connections(&self) {
        self.transport().close_idle_connections();
    }

    /// Go's `Do`: sends a request and follows redirects per the policy.
    pub fn do_request(&self, req: Request) -> Result<Response, BoxError> {
        self.do_inner(req)
    }

    fn do_inner(&self, mut req: Request) -> Result<Response, BoxError> {
        if req.url == Url::default() {
            let _ = req.close_body();
            return Err(Box::new(url::Error {
                op: url_error_op(&req.method),
                url: String::new(),
                err: "http: nil Request.URL".into(),
            }));
        }
        let deadline = self.deadline();
        let mut reqs: Vec<Request> = Vec::new();
        let mut resp: Option<Response> = None;
        let mut copy_headers = self.make_headers_copier(&req);
        let mut req_body_closed = false;
        let mut redirect_method = String::new();
        let mut include_body = true;
        let mut strip_sensitive_headers = false;

        loop {
            if !reqs.is_empty() {
                let prev = resp.take().expect("redirect needs the previous response");
                let loc = prev.header.get_str("Location");
                if loc.is_empty() {
                    return Ok(prev);
                }
                let u = match req.url.parse(loc) {
                    Ok(u) => u,
                    Err(e) => {
                        prev.close_body();
                        return Err(self.uerr(
                            &req,
                            Some(&prev),
                            &reqs,
                            req_body_closed,
                            format!(
                                "failed to parse Location header {}: {e}",
                                crate::strconv::quote(loc)
                            )
                            .into(),
                        ));
                    }
                };
                let mut host = String::new();
                if !req.host.is_empty() && req.host != req.url.host {
                    if let Ok(u2) = url::parse(loc) {
                        if !u2.is_abs() {
                            host = req.host.clone();
                        }
                    }
                }
                let ireq = &reqs[0];
                let mut nreq = Request::default();
                nreq.method = redirect_method.clone();
                nreq.response = Some(Box::new(prev.clone()));
                nreq.url = u;
                nreq.header = Header::new();
                nreq.host = host;
                nreq.cancel = ireq.cancel.clone();
                nreq.set_context_opt(ireq.context_opt());
                if include_body {
                    if let Some(gb) = &ireq.get_body {
                        match gb() {
                            Ok(b) => {
                                nreq.body = Some(b);
                                nreq.get_body = ireq.get_body.clone();
                                nreq.content_length = ireq.content_length;
                            }
                            Err(e) => {
                                prev.close_body();
                                return Err(self.uerr(
                                    &req,
                                    Some(&prev),
                                    &reqs,
                                    req_body_closed,
                                    e,
                                ));
                            }
                        }
                    }
                }
                req = nreq;
                if !strip_sensitive_headers
                    && reqs[0].url.host != req.url.host
                    && !should_copy_header_on_redirect(&reqs[0].url, &req.url)
                {
                    strip_sensitive_headers = true;
                }
                copy_headers(&mut req, strip_sensitive_headers, !include_body, &prev);
                let last_url = reqs[reqs.len() - 1].url.clone();
                let rf = refer_for_url(&last_url, &req.url, req.header.get_str("Referer"));
                if !rf.is_empty() {
                    req.header.set("Referer", &rf);
                }
                let err = self.check_redirect(&req, &reqs);
                if let Err(e) = &err {
                    if e.downcast_ref::<ErrorString>() == Some(&ERR_USE_LAST_RESPONSE) {
                        return Ok(prev);
                    }
                }
                const MAX_BODY_SLURP_SIZE: u64 = 2 << 10;
                if prev.content_length == -1 || prev.content_length as u64 <= MAX_BODY_SLURP_SIZE {
                    if let Some(b) = &prev.body {
                        let mut b = b.clone();
                        let _ = io::copy(&mut (&mut b).take(MAX_BODY_SLURP_SIZE), &mut io::sink());
                    }
                }
                prev.close_body();
                if let Err(e) = err {
                    let mut ue = self.uerr(&req, Some(&prev), &reqs, req_body_closed, e);
                    if let Some(u) = ue.downcast_mut::<url::Error>() {
                        u.url = loc.to_owned();
                    }
                    return Err(ue);
                }
            }

            reqs.push(req.clone());
            let sent = {
                let mut r2 = req.clone();
                self.send_with_cookies(&mut r2, deadline)
            };
            let (resp_ok, did_timeout) = match sent {
                Ok(v) => v,
                Err((e, did_timeout)) => {
                    req_body_closed = true;
                    let mut err = e;
                    if deadline.is_some() && did_timeout.as_ref().is_some_and(|f| f()) {
                        err = Box::new(TimeoutError(format!(
                            "{err} (Client.Timeout exceeded while awaiting headers)"
                        )));
                    }
                    return Err(self.uerr(&req, None, &reqs, req_body_closed, err));
                }
            };
            let _ = did_timeout;
            let (rm, should_redirect, include_body_on_hop) =
                redirect_behavior(&req.method, &resp_ok, &reqs[0]);
            redirect_method = rm;
            if !should_redirect {
                return Ok(resp_ok);
            }
            if !include_body_on_hop {
                include_body = false;
            }
            let _ = req.close_body();
            resp = Some(resp_ok);
        }
    }

    fn uerr(
        &self,
        req: &Request,
        resp: Option<&Response>,
        reqs: &[Request],
        body_closed: bool,
        err: BoxError,
    ) -> BoxError {
        if !body_closed {
            let _ = req.close_body();
        }
        let url_str = match resp.and_then(|r| r.request.as_ref()) {
            Some(rq) => strip_password(&rq.url),
            None => strip_password(&req.url),
        };
        Box::new(url::Error {
            op: url_error_op(&reqs[0].method),
            url: url_str,
            err,
        })
    }

    #[allow(clippy::type_complexity)]
    fn make_headers_copier(
        &self,
        ireq: &Request,
    ) -> Box<dyn FnMut(&mut Request, bool, bool, &Response) + Send> {
        let mut ireqhdr = ireq.header.clone();
        let jar_present = self.jar.is_some();
        let mut icookies: Option<Vec<(String, Vec<Cookie>)>> = None;
        if jar_present && !ireq.header.get_str("Cookie").is_empty() {
            let mut m: Vec<(String, Vec<Cookie>)> = Vec::new();
            for c in ireq.cookies() {
                match m.iter_mut().find(|(n, _)| *n == c.name) {
                    Some((_, v)) => v.push(c),
                    None => m.push((c.name.clone(), vec![c])),
                }
            }
            icookies = Some(m);
        }
        Box::new(move |req, strip_sensitive, strip_body, resp| {
            if let Some(ic) = icookies.as_mut() {
                let mut changed = false;
                for c in resp.cookies() {
                    if let Some(i) = ic.iter().position(|(n, _)| *n == c.name) {
                        ic.remove(i);
                        changed = true;
                    }
                }
                if changed {
                    ireqhdr.del("Cookie");
                    let mut ss: Vec<String> = ic
                        .iter()
                        .flat_map(|(_, cs)| cs.iter().map(|c| format!("{}={}", c.name, c.value)))
                        .collect();
                    ss.sort();
                    ireqhdr.set("Cookie", &ss.join("; "));
                }
            }
            for (k, vv) in &ireqhdr.0 {
                let mut sensitive = false;
                let mut body = false;
                match crate::net::textproto::canonical_mime_header_key(k).as_str() {
                    "Authorization"
                    | "Www-Authenticate"
                    | "Cookie"
                    | "Cookie2"
                    | "Proxy-Authorization"
                    | "Proxy-Authenticate" => sensitive = true,
                    "Content-Encoding" | "Content-Language" | "Content-Location"
                    | "Content-Type" => body = true,
                    _ => {}
                }
                if !(sensitive && strip_sensitive) && !(body && strip_body) {
                    req.header.0.insert(k.clone(), vv.clone());
                }
            }
        })
    }
}

fn url_error_op(method: &str) -> String {
    if method.is_empty() {
        return "Get".into();
    }
    if method.is_ascii() {
        let mut s = method[..1].to_owned();
        s.push_str(&method[1..].to_ascii_lowercase());
        return s;
    }
    method.to_owned()
}

fn strip_password(u: &Url) -> String {
    if let Some(user) = &u.user {
        if user.password().is_some() {
            let with_pass = format!("{user}@");
            let without = format!("{}:***@", user.username());
            return u.to_string().replacen(&with_pass, &without, 1);
        }
    }
    u.to_string()
}

fn default_check_redirect(_req: &Request, via: &[Request]) -> Result<(), BoxError> {
    if via.len() >= 10 {
        return Err("stopped after 10 redirects".into());
    }
    Ok(())
}

fn redirect_behavior(req_method: &str, resp: &Response, ireq: &Request) -> (String, bool, bool) {
    let mut redirect_method = String::new();
    let mut should_redirect = false;
    let mut include_body = false;
    match resp.status_code {
        301..=303 => {
            redirect_method = req_method.to_owned();
            should_redirect = true;
            include_body = false;
            if req_method != "GET" && req_method != "HEAD" {
                redirect_method = "GET".into();
            }
        }
        307 | 308 => {
            redirect_method = req_method.to_owned();
            should_redirect = true;
            include_body = true;
            if ireq.get_body.is_none() && ireq.outgoing_length() != 0 {
                should_redirect = false;
            }
        }
        _ => {}
    }
    (redirect_method, should_redirect, include_body)
}

fn should_copy_header_on_redirect(initial: &Url, dest: &Url) -> bool {
    let conv = |u: &Url| -> Option<String> {
        let h = u.hostname();
        let h = if h.is_ascii() {
            h
        } else {
            super::cookiejar::to_ascii(&h)?
        };
        h.is_ascii().then(|| h.to_ascii_lowercase())
    };
    match (conv(initial), conv(dest)) {
        (Some(i), Some(d)) => is_domain_or_subdomain(&d, &i),
        _ => false,
    }
}

fn is_domain_or_subdomain(sub: &str, parent: &str) -> bool {
    if sub == parent {
        return true;
    }
    if sub.contains([':', '%']) {
        return false;
    }
    if !sub.ends_with(parent) {
        return false;
    }
    sub.as_bytes().get(sub.len().wrapping_sub(parent.len() + 1)) == Some(&b'.')
}

type DidTimeout = Option<Arc<dyn Fn() -> bool + Send + Sync>>;

/// Go's package-level `send`: validates, applies the deadline and runs one
/// round trip.
fn send(
    ireq: &mut Request,
    rt: &dyn RoundTripper,
    deadline: Option<std::time::Instant>,
) -> Result<(Response, DidTimeout), (BoxError, DidTimeout)> {
    let always_false: DidTimeout = Some(Arc::new(|| false));
    if ireq.url == Url::default() {
        let _ = ireq.close_body();
        return Err(("http: nil Request.URL".into(), always_false));
    }
    if !ireq.request_uri.is_empty() {
        let _ = ireq.close_body();
        return Err((
            "http: Request.RequestURI can't be set in client requests".into(),
            always_false,
        ));
    }
    if let Some(u) = &ireq.url.user {
        if ireq.header.get_str("Authorization").is_empty() {
            let username = u.username().to_owned();
            let password = u.password().unwrap_or("").to_owned();
            ireq.header.set(
                "Authorization",
                &format!("Basic {}", basic_auth(&username, &password)),
            );
        }
    }
    let mut stop: Option<Arc<dyn Fn() + Send + Sync>> = None;
    let mut did_timeout: DidTimeout = always_false;
    if let Some(dl) = deadline {
        let (ctx, cancel) = ireq.context().with_deadline(dl);
        ireq.set_context(ctx.clone());
        ireq.cancel = Some(ctx.done());
        stop = Some(cancel);
        did_timeout = Some(Arc::new(move || std::time::Instant::now() > dl));
    }
    let mut resp = match rt.round_trip(ireq) {
        Ok(r) => r,
        Err(e) => {
            if let Some(s) = &stop {
                s();
            }
            return Err((e, did_timeout));
        }
    };
    if resp.body.is_none() {
        if resp.content_length > 0 && ireq.method != "HEAD" {
            return Err((
                format!(
                    "http: RoundTripper implementation returned a *Response with content length {} but a nil Body",
                    resp.content_length
                )
                .into(),
                did_timeout,
            ));
        }
        resp.body = Some(Body::from_bytes(Vec::new()));
    }
    if let (Some(dl), Some(stop)) = (deadline, stop) {
        let inner = resp.body.take().expect("body set above");
        let dt = did_timeout
            .clone()
            .unwrap_or_else(|| Arc::new(move || std::time::Instant::now() > dl));
        resp.body = Some(Body::new(CancelTimerBody {
            stop,
            rc: inner,
            did_timeout: dt,
        }));
    }
    Ok((resp, did_timeout))
}

struct CancelTimerBody {
    stop: Arc<dyn Fn() + Send + Sync>,
    rc: Body,
    did_timeout: Arc<dyn Fn() -> bool + Send + Sync>,
}
impl Read for CancelTimerBody {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        match self.rc.read(p) {
            Ok(n) => Ok(n),
            Err(e) => {
                if (self.did_timeout)() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        TimeoutError(format!(
                            "{e} (Client.Timeout or context cancellation while reading body)"
                        )),
                    ));
                }
                Err(e)
            }
        }
    }
}
impl ReadCloser for CancelTimerBody {
    fn close(&mut self) -> io::Result<()> {
        let r = self.rc.close();
        (self.stop)();
        r
    }
}

// ----------------------------------------------------- package-level shortcuts

/// Go's package-level `Get`.
pub fn get(url: &str) -> Result<Response, BoxError> {
    DEFAULT_CLIENT.get(url)
}
/// Go's package-level `Head`.
pub fn head(url: &str) -> Result<Response, BoxError> {
    DEFAULT_CLIENT.head(url)
}
/// Go's package-level `Post`.
pub fn post(
    url: &str,
    content_type: &str,
    body: Option<RequestBody>,
) -> Result<Response, BoxError> {
    DEFAULT_CLIENT.post(url, content_type, body)
}
/// Go's package-level `PostForm`.
pub fn post_form(url: &str, data: &Values) -> Result<Response, BoxError> {
    DEFAULT_CLIENT.post_form(url, data)
}

#[allow(dead_code)]
fn _unused(_: Mutex<()>, _: Context, _: &str) {
    let _ = time::SECOND;
    let _ = quote_list;
}
