//! Go's `Handler`, `HandlerFunc`, `ResponseWriter` and the optional writer
//! interfaces `Flusher`, `Hijacker` and `ResponseController`.
use super::body::ReadCloser;
use super::header::{BoxError, Header, ERR_NOT_SUPPORTED};
use super::request::Request;
use super::transfer::BufioReader;
use crate::bufio;
use crate::net::Conn;
use crate::time::Time;
use std::{io, sync::Arc};

/// Go's `http.Handler`.
pub trait Handler: Send + Sync {
    fn serve_http(&self, w: &mut dyn ResponseWriter, r: &mut Request);
}

/// Go's `http.HandlerFunc`: an ordinary function as a [`Handler`].
pub struct HandlerFunc<F>(pub F);
impl<F> Handler for HandlerFunc<F>
where
    F: Fn(&mut dyn ResponseWriter, &mut Request) + Send + Sync,
{
    fn serve_http(&self, w: &mut dyn ResponseWriter, r: &mut Request) {
        (self.0)(w, r);
    }
}
impl<F> HandlerFunc<F>
where
    F: Fn(&mut dyn ResponseWriter, &mut Request) + Send + Sync,
{
    /// Go's `HandlerFunc.ServeHTTP`.
    pub fn serve_http(&self, w: &mut dyn ResponseWriter, r: &mut Request) {
        (self.0)(w, r);
    }
}
impl<H: Handler + ?Sized> Handler for Arc<H> {
    fn serve_http(&self, w: &mut dyn ResponseWriter, r: &mut Request) {
        (**self).serve_http(w, r);
    }
}
impl<H: Handler + ?Sized> Handler for Box<H> {
    fn serve_http(&self, w: &mut dyn ResponseWriter, r: &mut Request) {
        (**self).serve_http(w, r);
    }
}

/// Convenience: an `Arc<dyn Handler>` from a closure.
pub fn handler_func<F>(f: F) -> Arc<dyn Handler>
where
    F: Fn(&mut dyn ResponseWriter, &mut Request) + Send + Sync + 'static,
{
    Arc::new(HandlerFunc(f))
}

/// What a hijacked connection hands to the handler: Go's
/// `(net.Conn, *bufio.ReadWriter)`.
pub struct Hijacked {
    pub conn: Box<dyn Conn>,
    pub reader: BufioReader,
    pub writer: bufio::Writer<Box<dyn io::Write + Send>>,
}

/// Go's `http.ResponseWriter`, plus the optional interfaces Go discovers by
/// type assertion (`Flusher`, `Hijacker`, connection deadlines, `Unwrap`).
///
/// The body is written through [`std::io::Write`], so a writer can be wrapped
/// by adapters such as `compress::gzip::Writer`. `Write::flush` does not send
/// the response; Go's `Flush` is [`Flusher`].
pub trait ResponseWriter: io::Write {
    fn header(&mut self) -> &mut Header;
    /// Go's `io.WriteString(w, s)`. A writer that implements
    /// `io.StringWriter` (the server's does) may frame the data differently
    /// from `write`.
    fn write_string(&mut self, s: &str) -> io::Result<usize> {
        io::Write::write(self, s.as_bytes())
    }
    /// Go's `io.Copy(w, r)` / `io.ReaderFrom`: copies `r` to the body until
    /// EOF. The server's writer sniffs the content type from the first 512
    /// bytes and streams the rest, as Go's `response.ReadFrom` does.
    fn copy_from(&mut self, r: &mut dyn io::Read) -> io::Result<u64> {
        io::copy(r, self)
    }
    fn write_header(&mut self, status_code: u16);
    /// `w.(http.Flusher)`.
    fn flusher(&mut self) -> Option<&mut dyn Flusher> {
        None
    }
    /// `w.(http.Hijacker)`.
    fn hijacker(&mut self) -> Option<&mut dyn Hijacker> {
        None
    }
    /// `w.(http.Pusher)`: HTTP/2 server push, when the connection supports it.
    fn pusher(&mut self) -> Option<&mut dyn super::header::Pusher> {
        None
    }
    /// `w.(http.CloseNotifier)`.
    fn close_notifier(&mut self) -> Option<&mut dyn CloseNotifier> {
        None
    }
    /// The `SetReadDeadline`/`SetWriteDeadline`/`EnableFullDuplex` interfaces.
    fn conn_control(&mut self) -> Option<&mut dyn ConnControl> {
        None
    }
    /// `w.(interface{ Unwrap() ResponseWriter })`.
    fn unwrap_writer(&mut self) -> Option<&mut dyn ResponseWriter> {
        None
    }
    /// Go's unexported `requestTooLarge` hook used by `MaxBytesReader`: a
    /// callback that tells the server to close the connection after the reply.
    fn request_too_large_hook(&mut self) -> Option<Arc<dyn Fn() + Send + Sync>> {
        None
    }
}

/// Go's `http.Flusher`. `flush_error` is Go's `FlushError() error`.
pub trait Flusher {
    fn flush(&mut self);
    fn flush_error(&mut self) -> Result<(), BoxError> {
        self.flush();
        Ok(())
    }
}

/// Go's `http.Hijacker`.
pub trait Hijacker {
    fn hijack(&mut self) -> Result<Hijacked, BoxError>;
}

/// The deadline interfaces `ResponseController` looks for.
pub trait ConnControl {
    fn set_read_deadline(&mut self, deadline: &Time) -> Result<(), BoxError>;
    fn set_write_deadline(&mut self, deadline: &Time) -> Result<(), BoxError>;
    fn enable_full_duplex(&mut self) -> Result<(), BoxError>;
}

/// Go's `http.CloseNotifier` (deprecated): a receiver that fires when the
/// client connection goes away.
pub trait CloseNotifier {
    fn close_notify(&mut self) -> std::sync::mpsc::Receiver<bool>;
}

/// Go's `http.ResponseController`.
pub struct ResponseController<'a> {
    rw: &'a mut dyn ResponseWriter,
}
fn not_supported(_what: &str) -> BoxError {
    Box::new(ERR_NOT_SUPPORTED)
}
impl<'a> ResponseController<'a> {
    /// Go's `NewResponseController`.
    pub fn new(rw: &'a mut dyn ResponseWriter) -> Self {
        ResponseController { rw }
    }
    /// Go's `Flush`.
    pub fn flush(&mut self) -> Result<(), BoxError> {
        let mut rw: &mut dyn ResponseWriter = &mut *self.rw;
        loop {
            if rw.flusher().is_some() {
                return rw.flusher().map_or(Ok(()), Flusher::flush_error);
            }
            match rw.unwrap_writer() {
                Some(inner) => rw = inner,
                None => return Err(not_supported("*ResponseWriter")),
            }
        }
    }
    /// Go's `Hijack`.
    pub fn hijack(&mut self) -> Result<Hijacked, BoxError> {
        let mut rw: &mut dyn ResponseWriter = &mut *self.rw;
        loop {
            if rw.hijacker().is_some() {
                return rw
                    .hijacker()
                    .map_or_else(|| Err(not_supported("Hijack")), Hijacker::hijack);
            }
            match rw.unwrap_writer() {
                Some(inner) => rw = inner,
                None => return Err(not_supported("Hijack")),
            }
        }
    }
    fn control(&mut self, what: &str) -> Result<&mut dyn ConnControl, BoxError> {
        let mut rw: &mut dyn ResponseWriter = &mut *self.rw;
        loop {
            if rw.conn_control().is_some() {
                return rw.conn_control().ok_or_else(|| not_supported(what));
            }
            match rw.unwrap_writer() {
                Some(inner) => rw = inner,
                None => return Err(not_supported(what)),
            }
        }
    }
    /// Go's `SetReadDeadline`.
    pub fn set_read_deadline(&mut self, deadline: &Time) -> Result<(), BoxError> {
        self.control("SetReadDeadline")?.set_read_deadline(deadline)
    }
    /// Go's `SetWriteDeadline`.
    pub fn set_write_deadline(&mut self, deadline: &Time) -> Result<(), BoxError> {
        self.control("SetWriteDeadline")?
            .set_write_deadline(deadline)
    }
    /// Go's `EnableFullDuplex`.
    pub fn enable_full_duplex(&mut self) -> Result<(), BoxError> {
        self.control("EnableFullDuplex")?.enable_full_duplex()
    }
}

/// `fmt.Fprint` to a `ResponseWriter`.
pub fn write_string(w: &mut dyn ResponseWriter, s: &str) -> io::Result<usize> {
    w.write(s.as_bytes())
}

#[allow(dead_code)]
fn _assert_read_closer<T: ReadCloser>() {}
