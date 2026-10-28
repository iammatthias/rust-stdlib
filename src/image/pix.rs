//! A pixel buffer: the Rust form of the `[]byte` slices that Go's `Pix`, `Y`,
//! `Cb`, `Cr` and `A` fields hold.
//!
//! A [`Pix`] starts out owning a plain `Vec<u8>`, so per-pixel access is
//! ordinary slice indexing. [`Pix::slice_from`] (behind every `sub_image`)
//! moves the bytes into a reference-counted buffer and returns another window
//! onto it, so a `SubImage` shares pixels with its parent exactly as Go's
//! `p.Pix[i:]` does; only windows that have been shared pay for a lock.
//! `Clone` copies the bytes into a new owned buffer.
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

type Shared = Arc<Mutex<Vec<u8>>>;

#[derive(Debug)]
enum Buf {
    Owned(Vec<u8>),
    Shared { buf: Shared, off: usize, len: usize },
}

impl Default for Buf {
    fn default() -> Buf {
        Buf::Owned(Vec::new())
    }
}

/// A window onto a byte buffer that sub-images may share.
#[derive(Default)]
pub struct Pix(Buf);

impl Pix {
    /// A buffer owning `v`.
    pub fn new(v: Vec<u8>) -> Pix {
        Pix(Buf::Owned(v))
    }

    /// The number of bytes in the window.
    pub fn len(&self) -> usize {
        match &self.0 {
            Buf::Owned(v) => v.len(),
            Buf::Shared { len, .. } => *len,
        }
    }

    /// Whether the window is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A window from `start` to the end of this one, sharing its bytes
    /// (Go's `pix[start:]`). Panics when `start` exceeds the length.
    ///
    /// The first call moves the bytes into a shared buffer, which is why it
    /// takes `&mut self`; this window then reads and writes through a lock.
    pub fn slice_from(&mut self, start: usize) -> Pix {
        assert!(start <= self.len(), "slice bounds out of range");
        if let Buf::Owned(v) = &mut self.0 {
            let len = v.len();
            self.0 = Buf::Shared {
                buf: Arc::new(Mutex::new(std::mem::take(v))),
                off: 0,
                len,
            };
        }
        match &self.0 {
            Buf::Shared { buf, off, len } => Pix(Buf::Shared {
                buf: Arc::clone(buf),
                off: off + start,
                len: len - start,
            }),
            Buf::Owned(_) => unreachable!("promoted above"),
        }
    }

    /// Whether both windows are backed by the same shared buffer.
    pub fn shares_with(&self, other: &Pix) -> bool {
        match (&self.0, &other.0) {
            (Buf::Shared { buf: a, .. }, Buf::Shared { buf: b, .. }) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }

    /// Shorten the window to `len` bytes; longer values are ignored.
    pub fn truncate(&mut self, len: usize) {
        match &mut self.0 {
            Buf::Owned(v) => v.truncate(len),
            Buf::Shared { len: l, .. } => *l = (*l).min(len),
        }
    }

    /// Run `f` on the bytes of the window.
    ///
    /// `f` must not touch another window onto the same buffer.
    pub fn with<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        match &self.0 {
            Buf::Owned(v) => f(v),
            Buf::Shared { buf, off, len } => {
                let g = buf.lock().unwrap_or_else(PoisonError::into_inner);
                f(&g[*off..off + len])
            }
        }
    }

    /// Run `f` on the mutable bytes of the window. The same restriction as
    /// [`Pix::with`] applies.
    pub fn with_mut<R>(&mut self, f: impl FnOnce(&mut [u8]) -> R) -> R {
        match &mut self.0 {
            Buf::Owned(v) => f(v),
            Buf::Shared { buf, off, len } => {
                let mut g = buf.lock().unwrap_or_else(PoisonError::into_inner);
                f(&mut g[*off..*off + *len])
            }
        }
    }

    /// The byte at `i`. Panics when out of range, like slice indexing.
    pub fn get(&self, i: usize) -> u8 {
        match &self.0 {
            Buf::Owned(v) => v[i],
            Buf::Shared { .. } => self.with(|s| s[i]),
        }
    }

    /// Store `v` at `i`. Panics when out of range.
    pub fn set(&mut self, i: usize, v: u8) {
        match &mut self.0 {
            Buf::Owned(b) => b[i] = v,
            Buf::Shared { .. } => self.with_mut(|s| s[i] = v),
        }
    }

    /// Set every byte of the window to `v`.
    pub fn fill(&mut self, v: u8) {
        self.with_mut(|s| s.fill(v));
    }

    /// Copy `src` over the window; the lengths must match.
    pub fn copy_from_slice(&mut self, src: &[u8]) {
        self.with_mut(|s| s.copy_from_slice(src));
    }

    /// A copy of the window's bytes.
    pub fn to_vec(&self) -> Vec<u8> {
        self.with(<[u8]>::to_vec)
    }
}

impl Clone for Pix {
    /// Copies the bytes into a new buffer.
    fn clone(&self) -> Pix {
        Pix::new(self.to_vec())
    }
}

impl From<Vec<u8>> for Pix {
    fn from(v: Vec<u8>) -> Pix {
        Pix::new(v)
    }
}

impl PartialEq for Pix {
    fn eq(&self, other: &Pix) -> bool {
        if self.shares_with(other) {
            return self.to_vec() == other.to_vec();
        }
        self.with(|a| other.with(|b| a == b))
    }
}

impl Eq for Pix {}

impl PartialEq<[u8]> for Pix {
    fn eq(&self, other: &[u8]) -> bool {
        self.with(|s| s == other)
    }
}

impl PartialEq<Vec<u8>> for Pix {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.with(|s| s == other.as_slice())
    }
}

impl<const N: usize> PartialEq<[u8; N]> for Pix {
    fn eq(&self, other: &[u8; N]) -> bool {
        self.with(|s| s == other.as_slice())
    }
}

impl fmt::Debug for Pix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.with(|s| s.fmt(f))
    }
}
