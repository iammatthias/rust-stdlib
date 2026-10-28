//! Go's deprecated `httputil.ClientConn` / `ServerConn` (persist.go) over
//! `Request` and `Response`: pipelined exchanges on a `net::Conn`,
//! parsed with `http.ReadRequest` / `http.ReadResponse`.
//!
//! Go keys the pipeline by `*http.Request`; here a request is identified by
//! its process-unique id (set by `Request::new` and `read_request`).
use crate::net::http::{
    body::Body,
    header::{is_error, ErrorString, ERR_EOF, ERR_UNEXPECTED_EOF},
    request::{read_request, Request},
    response::{read_response, Response},
    BufioReader,
};
use crate::net::{Conn, NetError};
use std::{
    collections::HashMap,
    fmt,
    io::{self, Read, Write},
    sync::{Arc, Condvar, Mutex, MutexGuard},
};

/// The errors of Go's persistent connections.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnError {
    /// Go's `ErrPersistEOF`: the peer asked to close; no further exchange.
    PersistEof,
    /// Go's `ErrClosed`: closed (or hijacked) by the user.
    Closed,
    /// Go's `ErrPipeline`: unknown or out-of-order ticket.
    Pipeline,
    /// Go's unexported `errClosed` ("i/o operation on closed connection").
    ClosedIo,
    /// A server write without an unanswered request.
    PipeCount,
    /// Go's `io.EOF`: the stream ended before a message started.
    Eof,
    /// Any other parse or I/O failure, kept sticky by its message.
    Failed(String),
}
impl fmt::Display for ConnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PersistEof => "persistent connection closed",
            Self::Closed => "connection closed by user",
            Self::Pipeline => "pipeline error",
            Self::ClosedIo => "i/o operation on closed connection",
            Self::PipeCount => "persist server pipe count",
            Self::Eof => "EOF",
            Self::Failed(message) => message,
        })
    }
}
impl std::error::Error for ConnError {}

/// Go's `ErrPersistEOF`.
pub const ERR_PERSIST_EOF: ConnError = ConnError::PersistEof;
/// Go's `ErrClosed`.
pub const ERR_CLOSED: ConnError = ConnError::Closed;
/// Go's `ErrPipeline`.
pub const ERR_PIPELINE: ConnError = ConnError::Pipeline;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// `textproto.Pipeline`: orders requests and responses by id.
#[derive(Default)]
struct Pipeline {
    st: Mutex<PipeState>,
    cv: Condvar,
}
#[derive(Default)]
struct PipeState {
    next: usize,
    req_turn: usize,
    resp_turn: usize,
}
impl Pipeline {
    fn next(&self) -> usize {
        let mut s = lock(&self.st);
        let id = s.next;
        s.next += 1;
        id
    }
    fn start_request(&self, id: usize) {
        let mut s = lock(&self.st);
        while s.req_turn != id {
            s = self.cv.wait(s).unwrap_or_else(|e| e.into_inner());
        }
    }
    fn end_request(&self, _id: usize) {
        lock(&self.st).req_turn += 1;
        self.cv.notify_all();
    }
    fn start_response(&self, id: usize) {
        let mut s = lock(&self.st);
        while s.resp_turn != id {
            s = self.cv.wait(s).unwrap_or_else(|e| e.into_inner());
        }
    }
    fn end_response(&self, _id: usize) {
        lock(&self.st).resp_turn += 1;
        self.cv.notify_all();
    }
}

struct ConnRead(Arc<dyn Conn>);
impl Read for ConnRead {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.0.read(b).map_err(NetError::into_io)
    }
}
struct ConnWrite(Arc<dyn Conn>);
impl Write for ConnWrite {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.write(b).map_err(NetError::into_io)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn failed(e: impl std::fmt::Display) -> ConnError {
    ConnError::Failed(e.to_string())
}

struct Inner {
    c: Option<Arc<dyn Conn>>,
    r: Option<BufioReader>,
    re: Option<ConnError>,
    we: Option<ConnError>,
    lastbody: Option<Body>,
    nread: usize,
    nwritten: usize,
    pipereq: HashMap<u64, usize>,
}

fn new_inner(c: Arc<dyn Conn>, r: Option<BufioReader>) -> Inner {
    let r = r.unwrap_or_else(|| BufioReader::new(ConnRead(c.clone())));
    Inner {
        c: Some(c),
        r: Some(r),
        re: None,
        we: None,
        lastbody: None,
        nread: 0,
        nwritten: 0,
        pipereq: HashMap::new(),
    }
}

/// Go's `httputil.ServerConn`.
pub struct ServerConn {
    inner: Mutex<Inner>,
    pipe: Pipeline,
}

impl ServerConn {
    /// Go's `NewServerConn`.
    pub fn new(c: Box<dyn Conn>, r: Option<BufioReader>) -> ServerConn {
        ServerConn {
            inner: Mutex::new(new_inner(Arc::from(c), r)),
            pipe: Pipeline::default(),
        }
    }

    /// Go's `Hijack`: the connection and reader, after which the `ServerConn`
    /// is unusable.
    pub fn hijack(&self) -> (Option<Arc<dyn Conn>>, Option<BufioReader>) {
        let mut g = lock(&self.inner);
        (g.c.take(), g.r.take())
    }
    pub fn close(&self) -> Result<(), NetError> {
        match self.hijack().0 {
            Some(c) => c.close(),
            None => Ok(()),
        }
    }

    /// Go's `Read`: the next request and, for a connection-ending request or
    /// a failure, the error (both can be present, as in Go).
    pub fn read(&self) -> (Option<Request>, Option<ConnError>) {
        let id = self.pipe.next();
        self.pipe.start_request(id);
        let (req, err) = self.read_inner();
        self.pipe.end_request(id);
        match &req {
            None => {
                self.pipe.start_response(id);
                self.pipe.end_response(id);
            }
            Some(r) => {
                lock(&self.inner).pipereq.insert(r.id(), id);
            }
        }
        (req, err)
    }

    fn read_inner(&self) -> (Option<Request>, Option<ConnError>) {
        let (r, lastbody) = {
            let mut g = lock(&self.inner);
            if let Some(e) = &g.we {
                return (None, Some(e.clone()));
            }
            if let Some(e) = &g.re {
                return (None, Some(e.clone()));
            }
            let Some(r) = g.r.clone() else {
                return (None, Some(ConnError::ClosedIo));
            };
            (r, g.lastbody.take())
        };
        if let Some(b) = lastbody {
            if let Err(e) = b.close() {
                let ce = failed(e);
                lock(&self.inner).re = Some(ce.clone());
                return (None, Some(ce));
            }
        }
        let parsed = read_request(&r);
        let mut g = lock(&self.inner);
        match parsed {
            Err(e) => {
                if e.downcast_ref::<ErrorString>() == Some(&ERR_UNEXPECTED_EOF)
                    || is_error(&*e, &ERR_UNEXPECTED_EOF)
                {
                    g.re = Some(ConnError::PersistEof);
                    return (None, g.re.clone());
                }
                let ce = if e.downcast_ref::<ErrorString>() == Some(&ERR_EOF) {
                    ConnError::Eof
                } else {
                    failed(e)
                };
                g.re = Some(ce.clone());
                (None, Some(ce))
            }
            Ok(req) => {
                g.lastbody = req.body.clone();
                g.nread += 1;
                if req.close {
                    g.re = Some(ConnError::PersistEof);
                    return (Some(req), g.re.clone());
                }
                (Some(req), None)
            }
        }
    }

    /// Go's `Pending`: requests read but not yet answered.
    pub fn pending(&self) -> usize {
        let g = lock(&self.inner);
        g.nread - g.nwritten
    }

    /// Go's `Write`: the response to a request returned by `read`.
    pub fn write(&self, req: &Request, resp: &Response) -> Result<(), ConnError> {
        let id = {
            let mut g = lock(&self.inner);
            match g.pipereq.remove(&req.id()) {
                Some(id) => id,
                None => return Err(ConnError::Pipeline),
            }
        };
        self.pipe.start_response(id);
        let res = self.write_inner(resp);
        self.pipe.end_response(id);
        res
    }

    fn write_inner(&self, resp: &Response) -> Result<(), ConnError> {
        let c = {
            let mut g = lock(&self.inner);
            if let Some(e) = &g.we {
                return Err(e.clone());
            }
            let Some(c) = g.c.clone() else {
                return Err(ConnError::Closed);
            };
            if g.nread <= g.nwritten {
                return Err(ConnError::PipeCount);
            }
            if resp.close {
                g.re = Some(ConnError::PersistEof);
            }
            c
        };
        let r = resp.write(&mut ConnWrite(c));
        let mut g = lock(&self.inner);
        if let Err(e) = r {
            let ce = failed(e);
            g.we = Some(ce.clone());
            return Err(ce);
        }
        g.nwritten += 1;
        Ok(())
    }
}

/// Go's `httputil.ClientConn`.
pub struct ClientConn {
    inner: Mutex<Inner>,
    pipe: Pipeline,
    proxy: bool,
}

impl ClientConn {
    /// Go's `NewClientConn`.
    pub fn new(c: Box<dyn Conn>, r: Option<BufioReader>) -> ClientConn {
        ClientConn {
            inner: Mutex::new(new_inner(Arc::from(c), r)),
            pipe: Pipeline::default(),
            proxy: false,
        }
    }

    /// Go's `NewProxyClientConn`: requests are written with `WriteProxy`.
    pub fn proxy(c: Box<dyn Conn>, r: Option<BufioReader>) -> ClientConn {
        ClientConn {
            proxy: true,
            ..ClientConn::new(c, r)
        }
    }

    pub fn hijack(&self) -> (Option<Arc<dyn Conn>>, Option<BufioReader>) {
        let mut g = lock(&self.inner);
        (g.c.take(), g.r.take())
    }
    pub fn close(&self) -> Result<(), NetError> {
        match self.hijack().0 {
            Some(c) => c.close(),
            None => Ok(()),
        }
    }

    /// Go's `Write`.
    pub fn write(&self, req: &Request) -> Result<(), ConnError> {
        let id = self.pipe.next();
        self.pipe.start_request(id);
        let res = self.write_inner(req);
        self.pipe.end_request(id);
        match &res {
            Err(_) => {
                self.pipe.start_response(id);
                self.pipe.end_response(id);
            }
            Ok(()) => {
                lock(&self.inner).pipereq.insert(req.id(), id);
            }
        }
        res
    }

    fn write_inner(&self, req: &Request) -> Result<(), ConnError> {
        let c = {
            let mut g = lock(&self.inner);
            if let Some(e) = &g.re {
                return Err(e.clone());
            }
            if let Some(e) = &g.we {
                return Err(e.clone());
            }
            let Some(c) = g.c.clone() else {
                return Err(ConnError::ClosedIo);
            };
            if req.close {
                g.we = Some(ConnError::PersistEof);
            }
            c
        };
        let mut w = ConnWrite(c);
        let r = if self.proxy {
            req.write_proxy(&mut w)
        } else {
            req.write(&mut w)
        };
        let mut g = lock(&self.inner);
        if let Err(e) = r {
            let ce = failed(e);
            g.we = Some(ce.clone());
            return Err(ce);
        }
        g.nwritten += 1;
        Ok(())
    }

    /// Go's `Pending`: requests written whose responses were not read.
    pub fn pending(&self) -> usize {
        let g = lock(&self.inner);
        g.nwritten - g.nread
    }

    /// Go's `Read`: the response to `req`, a request passed to `write`.
    pub fn read(&self, req: &Request) -> (Option<Response>, Option<ConnError>) {
        let id = {
            let mut g = lock(&self.inner);
            match g.pipereq.remove(&req.id()) {
                Some(id) => id,
                None => return (None, Some(ConnError::Pipeline)),
            }
        };
        self.pipe.start_response(id);
        let r = self.read_inner(req);
        self.pipe.end_response(id);
        r
    }

    fn read_inner(&self, req: &Request) -> (Option<Response>, Option<ConnError>) {
        let (r, lastbody) = {
            let mut g = lock(&self.inner);
            if let Some(e) = &g.re {
                return (None, Some(e.clone()));
            }
            let Some(r) = g.r.clone() else {
                return (None, Some(ConnError::ClosedIo));
            };
            (r, g.lastbody.take())
        };
        if let Some(b) = lastbody {
            if let Err(e) = b.close() {
                let ce = failed(e);
                lock(&self.inner).re = Some(ce.clone());
                return (None, Some(ce));
            }
        }
        let parsed = read_response(&r, Some(req));
        let mut g = lock(&self.inner);
        match parsed {
            Err(e) => {
                let ce = failed(e);
                g.re = Some(ce.clone());
                (None, Some(ce))
            }
            Ok(resp) => {
                g.lastbody = resp.body.clone();
                g.nread += 1;
                if resp.close {
                    g.re = Some(ConnError::PersistEof);
                    return (Some(resp), g.re.clone());
                }
                (Some(resp), None)
            }
        }
    }

    /// Go's `Do`.
    pub fn do_request(&self, req: &Request) -> (Option<Response>, Option<ConnError>) {
        if let Err(e) = self.write(req) {
            return (None, Some(e));
        }
        self.read(req)
    }
}
