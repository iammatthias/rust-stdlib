//! Go's `os.File` with read and write deadlines: [`File`], [`pipe`], and the
//! `SetDeadline` family.
use crate::errno::Errno;
use crate::ffi::{self, Fd};
use crate::net::Cause;
use crate::poll::{Core, IoError};
use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::FileTypeExt;
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
use std::time::SystemTime;

/// How a descriptor reached [`File::new`]; Go decides pollability from it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FileKind {
    /// `os.NewFile`: pollable only if the descriptor is already non-blocking.
    NewFile,
    /// `os.Open`, `os.Create` and `os.OpenFile`.
    OpenFile,
    /// `os.Pipe`.
    Pipe,
}

/// `os.PathError` for a file operation, with Go's file-specific causes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FileError {
    /// "read", "write" or "close".
    pub op: String,
    /// The name the file was created with.
    pub path: String,
    /// What went wrong.
    pub err: Cause,
}

impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.op, self.path, self.err)
    }
}

impl std::error::Error for FileError {}

impl From<FileError> for io::Error {
    fn from(e: FileError) -> io::Error {
        let kind = match &e.err {
            Cause::Timeout => io::ErrorKind::TimedOut,
            Cause::FileClosed => io::ErrorKind::NotConnected,
            Cause::Errno(n) => io::Error::from_raw_os_error(n.0).kind(),
            _ => io::ErrorKind::Other,
        };
        io::Error::new(kind, e)
    }
}

/// The error from `SetDeadline`, `SetReadDeadline` and `SetWriteDeadline`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeadlineError {
    /// `os.ErrNoDeadline`: the file type does not support deadlines.
    NoDeadline,
    /// "use of closed file".
    Closing,
}

impl fmt::Display for DeadlineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DeadlineError::NoDeadline => "file type does not support deadline",
            DeadlineError::Closing => "use of closed file",
        })
    }
}

impl std::error::Error for DeadlineError {}

impl From<DeadlineError> for io::Error {
    fn from(e: DeadlineError) -> io::Error {
        io::Error::new(io::ErrorKind::Unsupported, e)
    }
}

/// `os.File`: an open file whose pollable kinds (pipes, terminals, sockets,
/// FIFOs where the platform allows) support deadlines.
pub struct File {
    core: Core,
    name: String,
}

#[cfg(target_os = "linux")]
fn device_major(rdev: u64) -> u64 {
    ((rdev >> 8) & 0xfff) | ((rdev >> 32) & !0xfff)
}

/// Whether Go would register the descriptor with its poller.
fn pollable_file(fd: &Fd, kind: FileKind) -> bool {
    let nonblocking = ffi::is_nonblocking(fd.raw()).unwrap_or(false);
    let mut pollable = kind != FileKind::NewFile || nonblocking;
    if kind == FileKind::OpenFile {
        // The metadata comes from a borrowed duplicate so `fd` stays owned here.
        let meta = fd
            .try_clone()
            .ok()
            .map(|d| std::fs::File::from(d.into_owned()))
            .and_then(|f| f.metadata().ok());
        if let Some(meta) = meta {
            let ty = meta.file_type();
            // epoll and kqueue reject regular files and directories; kqueue
            // also does not report FIFO writers closing.
            if ty.is_file() || ty.is_dir() {
                pollable = false;
            }
            #[cfg(target_os = "macos")]
            if ty.is_fifo() {
                pollable = false;
            }
            // kqueue rejects character devices other than terminals
            // (/dev/null, /dev/zero, ...).
            #[cfg(target_os = "macos")]
            if ty.is_char_device() && !ffi::isatty(fd.raw()) {
                pollable = false;
            }
            // Linux's memory devices (/dev/null, /dev/zero, ...) have no poll.
            #[cfg(target_os = "linux")]
            if ty.is_char_device() && device_major(meta.rdev()) == 1 {
                pollable = false;
            }
        }
    }
    pollable
}

impl File {
    /// `os.NewFile` / the end of `os.OpenFile`: wraps an open file.
    pub fn new(file: std::fs::File, name: &str, kind: FileKind) -> io::Result<File> {
        let fd = Fd::from_owned(OwnedFd::from(file));
        let pollable = pollable_file(&fd, kind);
        let core = Core::new(fd, pollable).map_err(io::Error::from)?;
        Ok(File {
            core,
            name: name.to_string(),
        })
    }

    /// `File.Name`.
    pub fn name(&self) -> &str {
        &self.name
    }

    fn wrap(&self, op: &str, e: IoError) -> FileError {
        FileError {
            op: op.into(),
            path: self.name.clone(),
            err: match e {
                IoError::Timeout => Cause::Timeout,
                IoError::Closed => Cause::FileClosed,
                IoError::Errno(n) => Cause::Errno(n),
            },
        }
    }

    /// `File.Read`: reads up to `buf.len()` bytes; 0 means end of file.
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, FileError> {
        if buf.is_empty() && self.core.raw().is_none() {
            return Err(self.wrap("read", IoError::Closed));
        }
        if buf.is_empty() {
            return Ok(0);
        }
        self.core
            .read_with(|fd| ffi::read(fd, buf))
            .map_err(|e| self.wrap("read", e))
    }

    /// `File.Write`: writes all of `buf` unless an error stops it.
    pub fn write(&self, buf: &[u8]) -> Result<usize, FileError> {
        let mut done = 0;
        while done < buf.len() {
            match self.core.write_with(|fd| ffi::write(fd, &buf[done..])) {
                Ok(n) => done += n,
                Err(e) => return Err(self.wrap("write", e)),
            }
        }
        if buf.is_empty() && self.core.raw().is_none() {
            return Err(self.wrap("write", IoError::Closed));
        }
        Ok(done)
    }

    /// `File.Stat`: describes the open file.
    pub fn stat(&self) -> Result<crate::os::FileInfo, FileError> {
        let Some(fd) = self.core.raw() else {
            return Err(self.wrap("stat", IoError::Closed));
        };
        ffi::at::fstat(fd)
            .map(|st| crate::os::FileInfo::from_stat(&st, &self.name))
            .map_err(|e| self.wrap("stat", IoError::Errno(e)))
    }

    /// `File.Close`: closes the file; blocked reads and writes fail with
    /// "file already closed".
    pub fn close(&self) -> Result<(), FileError> {
        if self.core.close() {
            Ok(())
        } else {
            Err(self.wrap("close", IoError::Closed))
        }
    }

    fn set(&self, read: bool, write: bool, t: Option<SystemTime>) -> Result<(), DeadlineError> {
        if self.core.raw().is_none() {
            return Err(DeadlineError::Closing);
        }
        self.core
            .set_deadline(read, write, t)
            .map_err(|()| DeadlineError::NoDeadline)
    }

    /// `File.SetDeadline`: sets the read and write deadlines; `None` (Go's zero
    /// time) clears them.
    pub fn set_deadline(&self, t: Option<SystemTime>) -> Result<(), DeadlineError> {
        self.set(true, true, t)
    }

    /// `File.SetReadDeadline`.
    pub fn set_read_deadline(&self, t: Option<SystemTime>) -> Result<(), DeadlineError> {
        self.set(true, false, t)
    }

    /// `File.SetWriteDeadline`.
    pub fn set_write_deadline(&self, t: Option<SystemTime>) -> Result<(), DeadlineError> {
        self.set(false, true, t)
    }
}

impl fmt::Debug for File {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("File").field("name", &self.name).finish()
    }
}

impl AsRawFd for File {
    /// The descriptor, or -1 once the file is closed.
    fn as_raw_fd(&self) -> RawFd {
        self.core.raw().unwrap_or(-1)
    }
}

impl io::Read for File {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        File::read(self, buf).map_err(Into::into)
    }
}

impl io::Read for &File {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        File::read(self, buf).map_err(Into::into)
    }
}

impl io::Write for File {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        File::write(self, buf).map_err(Into::into)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl io::Write for &File {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        File::write(self, buf).map_err(Into::into)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// `os.Pipe`: a connected pair, (read end, write end). Both support
/// deadlines.
pub fn pipe() -> Result<(File, File), Errno> {
    let (r, w) = ffi::pipe()?;
    let make = |fd: Fd, name: &str| -> Result<File, Errno> {
        Ok(File {
            core: Core::new(fd, true)?,
            name: name.to_string(),
        })
    };
    Ok((make(r, "|0")?, make(w, "|1")?))
}
