//! `io.Pipe`: a synchronous in-memory pipe.

use super::stored::Stored;
use super::{CopyError, Error};
use std::io::{self, Read, Write};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

#[derive(Default)]
struct State {
    done: bool,
    rerr: Option<Stored>,
    werr: Option<Stored>,
    /// The writer's bytes not yet consumed and whether they are on offer.
    data: Vec<u8>,
    pos: usize,
    offered: bool,
    /// A Write is in progress (Go's `wrMu`).
    writing: bool,
}

#[derive(Default)]
struct Pipe {
    state: Mutex<State>,
    cond: Condvar,
}

impl Pipe {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn read(&self, b: &mut [u8]) -> io::Result<usize> {
        let mut s = self.lock();
        loop {
            if s.done {
                return Err(read_close_error(&s));
            }
            if s.offered {
                let n = b.len().min(s.data.len() - s.pos);
                b[..n].copy_from_slice(&s.data[s.pos..s.pos + n]);
                s.pos += n;
                s.offered = false;
                self.cond.notify_all();
                return Ok(n);
            }
            s = self.cond.wait(s).unwrap_or_else(|e| e.into_inner());
        }
    }

    fn write(&self, b: &[u8]) -> (usize, Option<io::Error>) {
        let mut s = self.lock();
        if s.done {
            return (0, Some(write_close_error(&s)));
        }
        while s.writing {
            s = self.cond.wait(s).unwrap_or_else(|e| e.into_inner());
        }
        s.writing = true;
        s.data = b.to_vec();
        s.pos = 0;
        let mut once = true;
        let result = loop {
            if !(once || s.pos < s.data.len()) {
                break (s.pos, None);
            }
            once = false;
            if s.done {
                break (s.pos, Some(write_close_error(&s)));
            }
            s.offered = true;
            self.cond.notify_all();
            while s.offered && !s.done {
                s = self.cond.wait(s).unwrap_or_else(|e| e.into_inner());
            }
            if s.offered {
                // Closed before a reader took the offer.
                s.offered = false;
                break (s.pos, Some(write_close_error(&s)));
            }
        };
        s.data = Vec::new();
        s.pos = 0;
        s.writing = false;
        self.cond.notify_all();
        result
    }

    fn close_read(&self, err: Option<io::Error>) {
        let mut s = self.lock();
        if s.rerr.is_none() {
            s.rerr = Some(Stored::new(err.unwrap_or_else(|| Error::ClosedPipe.into())));
        }
        s.done = true;
        self.cond.notify_all();
    }

    fn close_write(&self, err: Option<io::Error>) {
        let mut s = self.lock();
        if s.werr.is_none() {
            s.werr = Some(Stored::new(err.unwrap_or_else(super::eof)));
        }
        s.done = true;
        self.cond.notify_all();
    }
}

fn read_close_error(s: &State) -> io::Error {
    match (&s.rerr, &s.werr) {
        (None, Some(w)) => w.get(),
        _ => Error::ClosedPipe.into(),
    }
}

fn write_close_error(s: &State) -> io::Error {
    match (&s.werr, &s.rerr) {
        (None, Some(r)) => r.get(),
        _ => Error::ClosedPipe.into(),
    }
}

/// The read half of a pipe (`io.PipeReader`). Clones share the pipe.
#[derive(Clone)]
pub struct PipeReader(Arc<Pipe>);

/// The write half of a pipe (`io.PipeWriter`). Clones share the pipe.
#[derive(Clone)]
pub struct PipeWriter(Arc<Pipe>);

/// Creates a synchronous in-memory pipe (`io.Pipe`).
///
/// Each write blocks until its data has been consumed by one or more reads
/// or the pipe is closed. As in Go, dropping a half does not close it.
pub fn pipe() -> (PipeReader, PipeWriter) {
    let p = Arc::new(Pipe::default());
    (PipeReader(p.clone()), PipeWriter(p))
}

impl PipeReader {
    /// Go's `PipeReader.Read` with its exact result. Unlike the [`Read`]
    /// impl (where `Ok(0)` would mean EOF to std), a zero-length write
    /// consumed by a read of a non-empty buffer returns `Ok(0)`, and EOF is
    /// an error ([`is_eof`](super::is_eof) recognises it).
    pub fn read_raw(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }

    /// Closes the reader; later writes return `ErrClosedPipe`
    /// (`PipeReader.Close`).
    pub fn close(&self) {
        self.close_with_error(None);
    }

    /// Closes the reader; later writes return `err` (`PipeReader.CloseWithError`).
    /// `None` means `ErrClosedPipe`.
    pub fn close_with_error(&self, err: Option<io::Error>) {
        self.0.close_read(err);
    }
}

impl PipeWriter {
    /// Closes the writer; reads return EOF once it is closed (`PipeWriter.Close`).
    pub fn close(&self) {
        self.close_with_error(None);
    }

    /// Closes the writer; reads return `err` (`PipeWriter.CloseWithError`).
    /// `None` means `io.EOF`.
    pub fn close_with_error(&self, err: Option<io::Error>) {
        self.0.close_write(err);
    }

    /// Writes `data` through a shared handle (`PipeWriter.Write`) and
    /// returns the bytes consumed; an error reports the bytes consumed
    /// before it ([`CopyError::written`]).
    pub fn write_shared(&self, data: &[u8]) -> Result<usize, CopyError> {
        match self.0.write(data) {
            (n, None) => Ok(n),
            (n, Some(e)) => Err(CopyError::new(n as u64, e)),
        }
    }
}

impl Read for PipeReader {
    /// `PipeReader.Read` in std form; EOF after the writer closed with
    /// `io.EOF` is `Ok(0)`, any other close error is returned. A zero-length
    /// `Write` consumed by this read is skipped (std would take `Ok(0)` for
    /// EOF); [`PipeReader::read_raw`] has Go's exact result.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.0.read(buf) {
                Err(e) if super::is_eof(&e) => return Ok(0),
                // A zero-length Write is consumed by a Read that returns
                // (0, nil) in Go; std reads it as EOF, so read again.
                Ok(0) if !buf.is_empty() => {}
                other => return other,
            }
        }
    }
}

impl Read for &PipeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut r = (*self).clone();
        r.read(buf)
    }
}

impl Write for PipeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.0.write(buf) {
            (_, Some(e)) => Err(e),
            (n, None) => Ok(n),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
