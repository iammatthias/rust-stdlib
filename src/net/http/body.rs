//! Go's `io.ReadCloser` bodies: `NoBody` and a shareable body handle.
use std::{
    io::{self, Read},
    sync::{Arc, Mutex},
};

/// Go's `io.ReadCloser`. `close` defaults to a no-op.
pub trait ReadCloser: Read + Send {
    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Go's `http.NoBody`: an always-empty body.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoBody;
impl Read for NoBody {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}
impl ReadCloser for NoBody {}

/// Adapts any `Read` into a [`ReadCloser`] whose `close` does nothing
/// (`io.NopCloser`).
pub struct NopCloser<R>(pub R);
impl<R: Read> Read for NopCloser<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}
impl<R: Read + Send> ReadCloser for NopCloser<R> {}

/// The write half of a body that is also an `io.Writer`: the body of a
/// `101 Switching Protocols` response owns the connection (Go's
/// `readWriteCloserBody`).
pub trait BodyWriter: Send + Sync {
    fn write(&self, data: &[u8]) -> io::Result<usize>;
    /// `CloseWrite`, when the connection supports a half close.
    fn close_write(&self) -> io::Result<()>;
}

/// Go's `io.ReadCloser` interface value held by `Request.Body` and
/// `Response.Body`. Clones share the underlying reader, as copies of the Go
/// interface value share one object.
#[derive(Clone)]
pub struct Body {
    inner: Arc<Mutex<Box<dyn ReadCloser>>>,
    no_body: bool,
    in_memory: bool,
    max_bytes: bool,
    writer: Option<Arc<dyn BodyWriter>>,
}
impl Body {
    pub fn new<R: ReadCloser + 'static>(reader: R) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Box::new(reader))),
            no_body: false,
            in_memory: false,
            max_bytes: false,
            writer: None,
        }
    }
    /// A body over a plain reader with a no-op `close`.
    pub fn from_reader<R: Read + Send + 'static>(reader: R) -> Self {
        Self::new(NopCloser(reader))
    }
    pub fn from_bytes(data: impl Into<Vec<u8>>) -> Self {
        let mut b = Self::from_reader(io::Cursor::new(data.into()));
        b.in_memory = true;
        b
    }
    /// Go's `isKnownInMemoryReader`.
    pub fn is_in_memory(&self) -> bool {
        self.in_memory
    }
    /// Marks this body as `MaxBytesReader`'s (Go checks the dynamic type).
    pub(crate) fn mark_max_bytes(mut self) -> Self {
        self.max_bytes = true;
        self
    }
    pub(crate) fn is_max_bytes(&self) -> bool {
        self.max_bytes
    }
    /// Adds the write half (Go: the body also implements `io.Writer`).
    pub fn with_writer(mut self, w: Arc<dyn BodyWriter>) -> Self {
        self.writer = Some(w);
        self
    }
    /// `body.(io.Writer)`: the write half of a protocol-switch body.
    pub fn as_writer(&self) -> Option<&Arc<dyn BodyWriter>> {
        self.writer.as_ref()
    }
    /// `body == http.NoBody`.
    pub fn is_no_body(&self) -> bool {
        self.no_body
    }
    /// Pointer identity, Go's interface equality for pointer bodies.
    pub fn ptr_eq(&self, other: &Body) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
    pub fn close(&self) -> io::Result<()> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).close()
    }
    /// Read to EOF (`io.ReadAll`).
    pub fn read_all(&self) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut me = self.clone();
        me.read_to_end(&mut out)?;
        Ok(out)
    }
}
impl From<NoBody> for Body {
    fn from(_: NoBody) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Box::new(NoBody))),
            no_body: true,
            in_memory: true,
            max_bytes: false,
            writer: None,
        }
    }
}
impl Read for Body {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .read(buf)
    }
}
impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.no_body { "NoBody" } else { "Body" })
    }
}
