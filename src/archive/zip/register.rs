//! Compression-method registry (Go's `archive/zip/register.go`).
use super::header::{DEFLATE, STORE};
use crate::archive::iofs::{ReadCloser, WriteCloser};
use crate::compress::{self, flate, Decoder};
use std::{
    collections::HashMap,
    io::{self, Read, Write},
    sync::{Arc, Mutex, OnceLock},
};

/// Go's `zip.Compressor`: wraps the destination in a stream that compresses
/// what is written. `close` must finish the compressed stream.
pub type Compressor = Arc<dyn Fn(Box<dyn Write>) -> io::Result<Box<dyn WriteCloser>> + Send + Sync>;

/// Go's `zip.Decompressor`: wraps a reader of compressed bytes. The closure
/// is generic over the input's lifetime (the archive's reader may be a
/// borrow), so the result must borrow no more than its input: a
/// `Box<dyn Read + 'a>` in, a `Box<dyn ReadCloser + 'a>` out.
pub type Decompressor =
    Arc<dyn for<'a> Fn(Box<dyn Read + 'a>) -> Box<dyn ReadCloser + 'a> + Send + Sync>;

struct Passthrough<T>(T);

impl Write for Passthrough<Box<dyn Write>> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
impl WriteCloser for Passthrough<Box<dyn Write>> {
    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Read for Passthrough<Box<dyn Read + '_>> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.0.read(b)
    }
}
impl ReadCloser for Passthrough<Box<dyn Read + '_>> {}

/// Go's `flate.NewWriter(w, 5)` over the member's sink.
struct DeflateWriter(Option<flate::Writer<Box<dyn Write>>>);

impl Write for DeflateWriter {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        match &mut self.0 {
            Some(fw) => fw.write(b),
            None => Err(io::Error::other("Write after Close")),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl WriteCloser for DeflateWriter {
    fn close(&mut self) -> io::Result<()> {
        match self.0.take() {
            Some(mut fw) => fw.close(),
            None => Ok(()),
        }
    }
}

struct FailedReader(String, io::ErrorKind);
impl Read for FailedReader {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(self.1, self.0.clone()))
    }
}
impl ReadCloser for FailedReader {}

struct Flate<'a>(Decoder<Box<dyn Read + 'a>>);
impl Read for Flate<'_> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.0.read(b)
    }
}
impl ReadCloser for Flate<'_> {}

type Registry = (HashMap<u16, Compressor>, HashMap<u16, Decompressor>);

fn registries() -> &'static Mutex<Registry> {
    static R: OnceLock<Mutex<Registry>> = OnceLock::new();
    R.get_or_init(|| {
        let mut c: HashMap<u16, Compressor> = HashMap::new();
        let mut d: HashMap<u16, Decompressor> = HashMap::new();
        c.insert(
            STORE,
            Arc::new(|w| Ok(Box::new(Passthrough(w)) as Box<dyn WriteCloser>)),
        );
        c.insert(
            DEFLATE,
            Arc::new(|w| {
                Ok(Box::new(DeflateWriter(Some(flate::Writer::new(w, 5)?)))
                    as Box<dyn WriteCloser>)
            }),
        );
        d.insert(
            STORE,
            Arc::new(|r| Box::new(Passthrough(r)) as Box<dyn ReadCloser + '_>),
        );
        d.insert(
            DEFLATE,
            Arc::new(|r| {
                let unlimited = compress::Limits {
                    max_input: usize::MAX,
                    max_output: usize::MAX,
                };
                match Decoder::deflate_prefix(r, unlimited) {
                    Ok(dec) => Box::new(Flate(dec)) as Box<dyn ReadCloser>,
                    Err(e) => Box::new(FailedReader(e.to_string(), e.kind())),
                }
            }),
        );
        Mutex::new((c, d))
    })
}

/// `RegisterDecompressor`: register `dcomp` for `method` for every reader.
/// Panics if the method is already registered, as in Go.
pub fn register_decompressor(method: u16, dcomp: Decompressor) {
    let mut r = lock();
    if r.1.contains_key(&method) {
        drop(r); // do not poison the registry
        panic!("decompressor already registered");
    }
    r.1.insert(method, dcomp);
}

/// `RegisterCompressor`: register `comp` for `method` for every writer.
/// Panics if the method is already registered, as in Go.
pub fn register_compressor(method: u16, comp: Compressor) {
    let mut r = lock();
    if r.0.contains_key(&method) {
        drop(r); // do not poison the registry
        panic!("compressor already registered");
    }
    r.0.insert(method, comp);
}

fn lock() -> std::sync::MutexGuard<'static, Registry> {
    registries().lock().unwrap_or_else(|e| e.into_inner())
}

pub(super) fn compressor(method: u16) -> Option<Compressor> {
    lock().0.get(&method).cloned()
}

pub(super) fn decompressor(method: u16) -> Option<Decompressor> {
    lock().1.get(&method).cloned()
}
