//! Small handlers and helpers: `Error`, `NotFound`, `Redirect`, `StripPrefix`,
//! `MaxBytesReader` and friends.
use super::body::{Body, ReadCloser};
use super::handler::{handler_func, Handler, HandlerFunc, ResponseWriter};
use super::header::io_error;
use super::request::Request;
use super::{status::*, status_text};
use crate::net::url;
use std::{
    io::{self, Read},
    sync::Arc,
};

/// Go's `http.Error`: replies with `error` as plain text and status `code`.
pub fn error(w: &mut dyn ResponseWriter, error: &str, code: u16) {
    let h = w.header();
    h.del("Content-Length");
    h.set("Content-Type", "text/plain; charset=utf-8");
    h.set("X-Content-Type-Options", "nosniff");
    w.write_header(code);
    let _ = w.write(format!("{error}\n").as_bytes());
}

/// Go's `http.NotFound`.
pub fn not_found(w: &mut dyn ResponseWriter, _r: &mut Request) {
    error(w, "404 page not found", STATUS_NOT_FOUND);
}

/// Go's `http.NotFoundHandler`.
pub fn not_found_handler() -> Arc<dyn Handler> {
    handler_func(not_found)
}

/// Go's `http.StripPrefix`.
pub fn strip_prefix(prefix: &str, h: Arc<dyn Handler>) -> Arc<dyn Handler> {
    if prefix.is_empty() {
        return h;
    }
    let prefix = prefix.to_owned();
    Arc::new(HandlerFunc(
        move |w: &mut dyn ResponseWriter, r: &mut Request| {
            let p = r
                .url
                .path
                .strip_prefix(prefix.as_str())
                .unwrap_or(&r.url.path);
            let rp = r
                .url
                .raw_path
                .strip_prefix(prefix.as_str())
                .unwrap_or(&r.url.raw_path);
            if p.len() < r.url.path.len()
                && (r.url.raw_path.is_empty() || rp.len() < r.url.raw_path.len())
            {
                let mut r2 = r.clone();
                r2.url.path = p.to_owned();
                r2.url.raw_path = rp.to_owned();
                h.serve_http(w, &mut r2);
            } else {
                not_found(w, r);
            }
        },
    ))
}

/// Go's `hexEscapeNonASCII`.
pub(crate) fn hex_escape_non_ascii(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b >= 0x80 {
            out.push_str(&format!("%{b:x}"));
        } else {
            out.push(b as char);
        }
    }
    out
}

pub(crate) fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// Go's `http.Redirect`.
pub fn redirect(w: &mut dyn ResponseWriter, r: &Request, url_str: &str, code: u16) {
    let mut target = url_str.to_owned();
    if let Ok(u) = url::parse(url_str) {
        if u.scheme.is_empty() && u.host.is_empty() {
            let mut oldpath = r.url.escaped_path();
            if oldpath.is_empty() {
                oldpath = "/".into();
            }
            if target.is_empty() || !target.starts_with('/') {
                let (olddir, _) = crate::path::split(&oldpath);
                target = format!("{olddir}{target}");
            }
            let mut query = String::new();
            if let Some(i) = target.find('?') {
                query = target[i..].to_owned();
                target.truncate(i);
            }
            let trailing = target.ends_with('/');
            target = crate::path::clean(&target);
            if trailing && !target.ends_with('/') {
                target.push('/');
            }
            target.push_str(&query);
        }
    }
    let had_ct = w.header().0.contains_key("Content-Type");
    w.header().set("Location", &hex_escape_non_ascii(&target));
    if !had_ct && (r.method == "GET" || r.method == "HEAD") {
        w.header().set("Content-Type", "text/html; charset=utf-8");
    }
    w.write_header(code);
    if !had_ct && r.method == "GET" {
        let body = format!(
            "<a href=\"{}\">{}</a>.\n",
            html_escape(&target),
            status_text(code)
        );
        let _ = w.write(format!("{body}\n").as_bytes());
    }
}

/// Go's `http.RedirectHandler`.
pub fn redirect_handler(url: &str, code: u16) -> Arc<dyn Handler> {
    let url = url.to_owned();
    handler_func(move |w, r| redirect(w, r, &url, code))
}

/// Go's `http.MaxBytesError`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxBytesError {
    pub limit: i64,
}
impl std::fmt::Display for MaxBytesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("http: request body too large")
    }
}
impl std::error::Error for MaxBytesError {}

struct MaxBytesReader {
    on_too_large: Option<Arc<dyn Fn() + Send + Sync>>,
    r: Body,
    i: i64,
    n: i64,
    err: Option<(io::ErrorKind, MaxBytesOrIo)>,
}
#[derive(Clone)]
enum MaxBytesOrIo {
    Max(MaxBytesError),
    Msg(String),
    Eof,
}
impl MaxBytesReader {
    fn sticky(&self) -> Option<io::Result<usize>> {
        self.err.as_ref().map(|(kind, e)| match e {
            MaxBytesOrIo::Max(m) => Err(io_error(*m)),
            MaxBytesOrIo::Msg(s) => Err(io::Error::new(*kind, s.clone())),
            MaxBytesOrIo::Eof => Ok(0),
        })
    }
}
impl Read for MaxBytesReader {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        if let Some(res) = self.sticky() {
            return res;
        }
        if p.is_empty() {
            return Ok(0);
        }
        let mut p = p;
        if (p.len() as i64) - 1 > self.n {
            let lim = usize::try_from(self.n + 1).unwrap_or(p.len());
            p = &mut p[..lim];
        }
        let res = self.r.read(p);
        let n = match &res {
            Ok(n) => *n,
            Err(_) => 0,
        };
        if (n as i64) <= self.n {
            self.n -= n as i64;
            match &res {
                Ok(0) => self.err = Some((io::ErrorKind::UnexpectedEof, MaxBytesOrIo::Eof)),
                Err(e) => self.err = Some((e.kind(), MaxBytesOrIo::Msg(e.to_string()))),
                _ => {}
            }
            return res;
        }
        let n = usize::try_from(self.n).unwrap_or(0);
        self.n = 0;
        if let Some(f) = &self.on_too_large {
            f();
        }
        let e = MaxBytesError { limit: self.i };
        self.err = Some((io::ErrorKind::Other, MaxBytesOrIo::Max(e)));
        if n > 0 {
            // Go returns the n bytes together with the error; std cannot.
            // Deliver the data now; the sticky error follows on the next read.
            return Ok(n);
        }
        Err(io_error(e))
    }
}
impl ReadCloser for MaxBytesReader {
    fn close(&mut self) -> io::Result<()> {
        self.r.close()
    }
}

/// Go's `http.MaxBytesReader`: limits the bytes read from `r` to `n`. The
/// response writer is told when the limit is hit so the connection closes.
pub fn max_bytes_reader(w: Option<&mut dyn ResponseWriter>, r: Body, n: i64) -> Body {
    let n = n.max(0);
    let on_too_large = w.and_then(|w| w.request_too_large_hook());
    Body::new(MaxBytesReader {
        on_too_large,
        r,
        i: n,
        n,
        err: None,
    })
    .mark_max_bytes()
}

/// Go's `http.MaxBytesHandler`.
pub fn max_bytes_handler(h: Arc<dyn Handler>, n: i64) -> Arc<dyn Handler> {
    handler_func(move |w, r| {
        let mut r2 = r.clone();
        if let Some(b) = r.body.clone() {
            r2.body = Some(max_bytes_reader(Some(&mut *w), b, n));
        }
        h.serve_http(w, &mut r2);
    })
}

/// Go's `http.AllowQuerySemicolons`: rewrites `;` in the query to `&`.
pub fn allow_query_semicolons(h: Arc<dyn Handler>) -> Arc<dyn Handler> {
    handler_func(move |w, r| {
        if r.url.raw_query.contains(';') {
            let mut r2 = r.clone();
            r2.url.raw_query = r2.url.raw_query.replace(';', "&");
            h.serve_http(w, &mut r2);
        } else {
            h.serve_http(w, r);
        }
    })
}
