//! Random sources for the reviewed asymmetric crates, and Go's `GODEBUG`
//! settings that decide whether a caller-supplied reader is used.
//!
//! [`Source::System`] reads [`crate::rand`] (the operating system, or the
//! deterministic stream installed by `testing/cryptotest.SetGlobalRandom`).
//! [`Source::Reader`] reads the caller's `io::Read`; if it fails, the first
//! error is recorded and the rest of the operation draws from the system source
//! (so a failing reader cannot make a rejection-sampling loop spin), and the
//! caller reports the error with [`Source::finish`].

use std::io;

use rand_core::{Infallible, TryCryptoRng, TryRng};

/// The value of a `GODEBUG` setting (Go's `internal/godebug`), read from the
/// `GODEBUG` environment variable on every call, as Go does.
pub(crate) fn godebug(name: &str) -> Option<String> {
    let value = std::env::var("GODEBUG").ok()?;
    let mut found = None;
    for pair in value.split(',') {
        if let Some((key, setting)) = pair.split_once('=') {
            if key == name {
                found = Some(setting.to_string());
            }
        }
    }
    found
}

/// Reports whether `GODEBUG=cryptocustomrand=1` asks the `crypto/*` functions
/// that ignore their random reader by default to honour it.
pub(crate) fn custom_rand() -> bool {
    godebug("cryptocustomrand").as_deref() == Some("1")
}

/// A `rand_core` generator over [`crate::rand`] or a caller's reader.
pub(crate) enum Source<'a> {
    /// The system source.
    System,
    /// The caller's reader.
    Reader {
        reader: &'a mut dyn io::Read,
        error: Option<io::Error>,
        failed: bool,
    },
}

impl<'a> Source<'a> {
    /// Go's `rand.CustomReader`: the reader only when
    /// `GODEBUG=cryptocustomrand=1`, the system source otherwise.
    pub(crate) fn custom(reader: Option<&'a mut dyn io::Read>) -> Source<'a> {
        match reader {
            Some(reader) if custom_rand() => Source::explicit_reader(reader),
            _ => Source::System,
        }
    }

    /// The reader if there is one (functions that always honour it), the
    /// system source for Go's nil reader.
    pub(crate) fn explicit(reader: Option<&'a mut dyn io::Read>) -> Source<'a> {
        match reader {
            Some(reader) => Source::explicit_reader(reader),
            None => Source::System,
        }
    }

    fn explicit_reader(reader: &'a mut dyn io::Read) -> Source<'a> {
        Source::Reader {
            reader,
            error: None,
            failed: false,
        }
    }

    /// Fills `buf`.
    pub(crate) fn fill(&mut self, buf: &mut [u8]) {
        match self {
            Source::System => {
                crate::rand::read(buf);
            }
            Source::Reader {
                reader,
                error,
                failed,
            } => {
                if !*failed {
                    match reader.read_exact(buf) {
                        Ok(()) => return,
                        Err(e) => {
                            *error = Some(e);
                            *failed = true;
                        }
                    }
                }
                crate::rand::read(buf);
            }
        }
    }

    /// Takes the reader's first error, if any, without ending the source.
    pub(crate) fn check(&mut self) -> io::Result<()> {
        match self {
            Source::Reader { error, .. } => error.take().map_or(Ok(()), Err),
            Source::System => Ok(()),
        }
    }

    /// Reports the reader's first error, if any; call it after using the
    /// source and discard the result of the operation when it fails.
    #[cfg(any(feature = "dsa", feature = "ecdh", feature = "rsa"))]
    pub(crate) fn finish(self) -> io::Result<()> {
        match self {
            Source::Reader {
                error: Some(error), ..
            } => Err(error),
            _ => Ok(()),
        }
    }
}

impl TryRng for Source<'_> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut bytes = [0u8; 4];
        self.fill(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut bytes = [0u8; 8];
        self.fill(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.fill(dst);
        Ok(())
    }
}

impl TryCryptoRng for Source<'_> {}
