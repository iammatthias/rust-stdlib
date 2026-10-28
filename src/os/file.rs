//! `os.File`: an open file or directory over `std::fs::File`.

use super::error::{errno, from_errno, path_err, Error};
use crate::io::fs::{self, DirEntry, FileInfo, FileMode, PathError, ReadDirError};
use crate::io::{self as gio, ReadAt, WriteAt};
use crate::time::Time;
use std::fs as stdfs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::sync::{Mutex, RwLock};

/// Open the file read-only (`os.O_RDONLY`).
pub const O_RDONLY: i32 = 0;
/// Open the file write-only (`os.O_WRONLY`).
pub const O_WRONLY: i32 = 1;
/// Open the file read-write (`os.O_RDWR`).
pub const O_RDWR: i32 = 2;
/// Append data to the file when writing (`os.O_APPEND`).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub const O_APPEND: i32 = 0x400;
/// Create a new file if none exists (`os.O_CREATE`).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub const O_CREATE: i32 = 0x40;
/// With `O_CREATE`, the file must not exist (`os.O_EXCL`).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub const O_EXCL: i32 = 0x80;
/// Open for synchronous I/O (`os.O_SYNC`).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub const O_SYNC: i32 = 0x101000;
/// Truncate a regular writable file when opened (`os.O_TRUNC`).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub const O_TRUNC: i32 = 0x200;
/// Append data to the file when writing (`os.O_APPEND`).
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub const O_APPEND: i32 = 0x8;
/// Create a new file if none exists (`os.O_CREATE`).
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub const O_CREATE: i32 = 0x200;
/// With `O_CREATE`, the file must not exist (`os.O_EXCL`).
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub const O_EXCL: i32 = 0x800;
/// Open for synchronous I/O (`os.O_SYNC`).
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub const O_SYNC: i32 = 0x80;
/// Truncate a regular writable file when opened (`os.O_TRUNC`).
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub const O_TRUNC: i32 = 0x400;

/// Fails unless the path is a directory (`O_DIRECTORY`; not an `os` constant,
/// used by `read_dir` like Go's `openDir`).
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    not(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "powerpc64"
    ))
))]
pub(crate) const O_DIRECTORY: i32 = 0x10000;
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "powerpc64"
    )
))]
pub(crate) const O_DIRECTORY: i32 = 0x4000;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(crate) const O_DIRECTORY: i32 = 0x100000;

/// Fails if the final component is a symbolic link (`O_NOFOLLOW`).
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    not(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "powerpc64"
    ))
))]
pub(crate) const O_NOFOLLOW: i32 = 0x20000;
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "powerpc64"
    )
))]
pub(crate) const O_NOFOLLOW: i32 = 0x8000;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(crate) const O_NOFOLLOW: i32 = 0x100;

/// Go's `syscallMode`: the permission, setuid, setgid and sticky bits.
pub(crate) fn syscall_mode(mode: FileMode) -> u32 {
    let mut o = mode.0 & 0o777;
    if mode.0 & fs::MODE_SETUID.0 != 0 {
        o |= 0o4000;
    }
    if mode.0 & fs::MODE_SETGID.0 != 0 {
        o |= 0o2000;
    }
    if mode.0 & fs::MODE_STICKY.0 != 0 {
        o |= 0o1000;
    }
    o
}

/// Go's `basename`: the last element after trailing slashes are removed.
pub(crate) fn basename(name: &str) -> String {
    let mut name = name;
    while name.len() > 1 && name.ends_with('/') {
        name = &name[..name.len() - 1];
    }
    match name.rfind('/') {
        Some(i) if name.len() > 1 => name[i + 1..].to_string(),
        _ => name.to_string(),
    }
}

/// An open file (`os.File`).
///
/// All methods take `&self`; the descriptor is guarded by a lock so that
/// [`File::close`] can be called from any thread. `std::io::{Read, Write,
/// Seek}` are implemented for `File` and `&File`. A `File` is closed when
/// dropped.
#[derive(Debug)]
pub struct File {
    name: String,
    /// The path used to read the directory and for `chdir`: the name, except
    /// for files opened in a `Root`, where it is the resolved path.
    path: String,
    in_root: bool,
    inner: RwLock<Option<stdfs::File>>,
    append: bool,
    dir: Mutex<Option<stdfs::ReadDir>>,
}

/// Opens `name` with `O_*` flags; the raw `std` error.
pub(crate) fn open_std(name: &str, flag: i32, perm: FileMode) -> io::Result<stdfs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = stdfs::OpenOptions::new();
    match flag & 3 {
        O_WRONLY => opts.write(true),
        O_RDWR => opts.read(true).write(true),
        _ => opts.read(true),
    };
    // Everything but the access mode goes through unchanged, so every
    // combination `open(2)` accepts is accepted here too.
    opts.custom_flags(flag & !3).mode(syscall_mode(perm));
    opts.open(name)
}

/// Opens the named file with the given `O_*` flags and permission bits
/// (`os.OpenFile`). The flag bits are those of this module's constants.
pub fn open_file(name: &str, flag: i32, perm: FileMode) -> io::Result<File> {
    let f = open_std(name, flag, perm).map_err(|e| path_err("open", name, e))?;
    Ok(File::from_std(f, name.to_string(), flag & O_APPEND != 0))
}

/// Opens the named file for reading (`os.Open`).
pub fn open(name: &str) -> io::Result<File> {
    open_file(name, O_RDONLY, FileMode(0))
}

/// Creates or truncates the named file, mode 0666 before umask (`os.Create`).
pub fn create(name: &str) -> io::Result<File> {
    open_file(name, O_RDWR | O_CREATE | O_TRUNC, FileMode(0o666))
}

fn dup_std(fd: std::os::fd::BorrowedFd<'_>) -> io::Result<stdfs::File> {
    Ok(stdfs::File::from(fd.try_clone_to_owned()?))
}

/// A file for the process's standard input (`os.Stdin`). The descriptor is
/// duplicated; each call returns a new `File`.
pub fn stdin() -> File {
    use std::os::fd::AsFd;
    std_file(dup_std(io::stdin().as_fd()), "/dev/stdin")
}

/// A file for the process's standard output (`os.Stdout`).
pub fn stdout() -> File {
    use std::os::fd::AsFd;
    std_file(dup_std(io::stdout().as_fd()), "/dev/stdout")
}

/// A file for the process's standard error (`os.Stderr`).
pub fn stderr() -> File {
    use std::os::fd::AsFd;
    std_file(dup_std(io::stderr().as_fd()), "/dev/stderr")
}

fn std_file(f: io::Result<stdfs::File>, name: &str) -> File {
    match f {
        Ok(f) => File::from_std(f, name.to_string(), false),
        // A closed standard descriptor: a file that reports ErrClosed.
        Err(_) => File {
            name: name.to_string(),
            path: name.to_string(),
            in_root: false,
            inner: RwLock::new(None),
            append: false,
            dir: Mutex::new(None),
        },
    }
}

/// Creates a pipe and returns its read and write ends (`os.Pipe`). Both ends
/// are close-on-exec.
pub fn pipe() -> io::Result<(File, File)> {
    use std::os::fd::OwnedFd;
    let (r, w) =
        io::pipe().map_err(|e| io::Error::from(super::error::SyscallError::new("pipe", e)))?;
    Ok((
        File::from_std(stdfs::File::from(OwnedFd::from(r)), "|0".into(), false),
        File::from_std(stdfs::File::from(OwnedFd::from(w)), "|1".into(), false),
    ))
}

impl File {
    /// A `File` for an existing descriptor (`os.NewFile`). Rust cannot adopt a
    /// bare integer descriptor without `unsafe`, so the descriptor is passed as
    /// an owned handle (`OwnedFd`, or anything convertible to it).
    pub fn from_fd(fd: impl Into<std::os::fd::OwnedFd>, name: &str) -> File {
        File::from_std(stdfs::File::from(fd.into()), name.to_string(), false)
    }

    pub(crate) fn from_std(f: stdfs::File, name: String, append: bool) -> File {
        File {
            path: name.clone(),
            name,
            in_root: false,
            inner: RwLock::new(Some(f)),
            append,
            dir: Mutex::new(None),
        }
    }

    /// Runs `f` on the open descriptor; a closed file fails with `ErrClosed`.
    fn with<R>(&self, op: &str, f: impl FnOnce(&stdfs::File) -> io::Result<R>) -> io::Result<R> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            None => Err(PathError::new(op, &self.name, fs::Error::Closed).into()),
            Some(file) => f(file).map_err(|e| self.wrap(op, e)),
        }
    }

    /// Go's `wrapErr`: `PathError` unless `err` is EOF.
    fn wrap(&self, op: &str, err: io::Error) -> io::Error {
        if gio::is_eof(&err) {
            return err;
        }
        path_err(op, &self.name, err)
    }

    /// Marks the file as opened in a `Root` at the resolved `path`; directory
    /// entries are then `lstat`ed eagerly, as in Go.
    pub(crate) fn in_root(mut self, path: String) -> File {
        self.path = path;
        self.in_root = true;
        self
    }

    /// A duplicate of the descriptor as a `std::fs::File`.
    pub(crate) fn try_clone_std(&self) -> io::Result<stdfs::File> {
        self.with("dup", |f| f.try_clone())
    }

    /// Returns the name of the file as presented to open (`File.Name`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the integer file descriptor (`File.Fd`); `u32::MAX as usize`
    /// (Go's `^uintptr(0)`) once the file is closed.
    pub fn fd(&self) -> usize {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(f) => f.as_raw_fd() as usize,
            None => usize::MAX,
        }
    }

    /// Closes the file (`File.Close`). Closing twice fails with `ErrClosed`.
    pub fn close(&self) -> io::Result<()> {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        *self.dir.lock().unwrap_or_else(|e| e.into_inner()) = None;
        match guard.take() {
            None => Err(PathError::new("close", &self.name, fs::Error::Closed).into()),
            Some(f) => {
                drop(guard);
                // `std::fs::File` closes on drop and cannot report failure.
                drop(f);
                Ok(())
            }
        }
    }

    /// Returns the `FileInfo` describing the file (`File.Stat`).
    pub fn stat(&self) -> io::Result<Box<dyn FileInfo>> {
        let meta = self.with("stat", |f| f.metadata())?;
        Ok(Box::new(fs::dirfs::StdInfo {
            name: basename(&self.name),
            meta,
        }))
    }

    /// Commits the file's contents to stable storage (`File.Sync`).
    pub fn sync(&self) -> io::Result<()> {
        self.with("sync", |f| f.sync_all())
    }

    /// Changes the size of the file (`File.Truncate`).
    pub fn truncate(&self, size: i64) -> io::Result<()> {
        self.with("truncate", |f| {
            let size = u64::try_from(size)
                .map_err(|_| io::Error::from(super::error::Errno(errno::EINVAL)))?;
            f.set_len(size)
        })
    }

    /// Changes the mode of the file (`File.Chmod`).
    pub fn chmod(&self, mode: FileMode) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        self.with("chmod", |f| {
            f.set_permissions(stdfs::Permissions::from_mode(syscall_mode(mode)))
        })
    }

    /// Changes the numeric uid and gid of the file; -1 leaves one unchanged
    /// (`File.Chown`).
    pub fn chown(&self, uid: i32, gid: i32) -> io::Result<()> {
        let opt = |v: i32| u32::try_from(v).ok();
        self.with("chown", |f| {
            std::os::unix::fs::fchown(f, opt(uid), opt(gid))
        })
    }

    /// Changes the current directory to the file, which must be a directory
    /// (`File.Chdir`).
    pub fn chdir(&self) -> io::Result<()> {
        // Re-checks that the descriptor is open and a directory, then moves
        // by the name it was opened with.
        self.with("chdir", |f| {
            if !f.metadata()?.is_dir() {
                return Err(from_errno(errno::ENOTDIR));
            }
            std::env::set_current_dir(&self.path)
        })
    }

    /// `File.SetDeadline`. Regular files do not support deadlines, so this
    /// returns `ErrNoDeadline` as Go does for non-pollable files. (Go also
    /// supports deadlines on pipes and ttys; here those files report
    /// `ErrNoDeadline` too.)
    pub fn set_deadline(&self, t: Time) -> io::Result<()> {
        let _ = t;
        self.deadline_unsupported("SetDeadline")
    }

    /// `File.SetReadDeadline`; see [`File::set_deadline`].
    pub fn set_read_deadline(&self, t: Time) -> io::Result<()> {
        let _ = t;
        self.deadline_unsupported("SetReadDeadline")
    }

    /// `File.SetWriteDeadline`; see [`File::set_deadline`].
    pub fn set_write_deadline(&self, t: Time) -> io::Result<()> {
        let _ = t;
        self.deadline_unsupported("SetWriteDeadline")
    }

    fn deadline_unsupported(&self, op: &str) -> io::Result<()> {
        self.with(op, |_| Ok(()))?;
        Err(Error::NoDeadline.into())
    }

    // ---- directory reading -------------------------------------------------

    fn dir_op(&self) -> &'static str {
        if cfg!(any(target_os = "macos", target_os = "ios")) {
            "fdopendir"
        } else {
            "readdirent"
        }
    }

    /// Reads up to `n` raw entries (all of them for `n <= 0`). With `n > 0`
    /// and nothing left it fails with `io.EOF`.
    fn read_entries(&self, n: i32) -> io::Result<Vec<fs::dirfs::StdEntry>> {
        let op = self.dir_op();
        self.with(op, |f| {
            if !f.metadata()?.is_dir() {
                return Err(from_errno(errno::ENOTDIR));
            }
            Ok(())
        })?;
        let mut state = self.dir.lock().unwrap_or_else(|e| e.into_inner());
        if state.is_none() {
            *state = Some(stdfs::read_dir(&self.path).map_err(|e| path_err(op, &self.name, e))?);
        }
        let it = state.as_mut().expect("opened above");
        let mut out = Vec::new();
        loop {
            if n > 0 && out.len() >= n as usize {
                break;
            }
            match it.next() {
                None => {
                    if n > 0 && out.is_empty() {
                        return Err(gio::eof());
                    }
                    break;
                }
                Some(Err(e)) => return Err(path_err(op, &self.name, e)),
                Some(Ok(e)) => {
                    let ft = e.file_type().map_err(|e| path_err(op, &self.name, e))?;
                    let name = e.file_name().to_string_lossy().into_owned();
                    if self.in_root {
                        // Entries of a Root's directories are never lazy.
                        if let Err(err) = stdfs::symlink_metadata(e.path()) {
                            return Err(path_err(
                                "fstatat",
                                &format!("{}/{}", self.name, name),
                                err,
                            ));
                        }
                    }
                    out.push(fs::dirfs::StdEntry {
                        name,
                        path: e.path(),
                        ft,
                    });
                }
            }
        }
        Ok(out)
    }

    /// Reads the directory's contents (`File.ReadDir`): up to `n` entries in
    /// directory order, or all of them when `n <= 0`. With `n > 0` the end is
    /// signalled by an `io.EOF` error.
    pub fn read_dir(&self, n: i32) -> io::Result<Vec<Box<dyn DirEntry>>> {
        Ok(self
            .read_entries(n)?
            .into_iter()
            .map(|e| Box::new(e) as Box<dyn DirEntry>)
            .collect())
    }

    /// Reads the directory and returns `Lstat` info for each entry
    /// (`File.Readdir`). Entries that vanish between listing and `lstat` are
    /// skipped, as in Go.
    pub fn readdir(&self, n: i32) -> io::Result<Vec<Box<dyn FileInfo>>> {
        let mut out: Vec<Box<dyn FileInfo>> = Vec::new();
        for e in self.read_entries(n)? {
            match DirEntry::info(&e) {
                Ok(i) => out.push(i),
                Err(err) if super::is_not_exist(&err) => {}
                Err(err) => return Err(err),
            }
        }
        Ok(out)
    }

    /// Reads the names of the directory's entries (`File.Readdirnames`).
    pub fn readdirnames(&self, n: i32) -> io::Result<Vec<String>> {
        Ok(self.read_entries(n)?.into_iter().map(|e| e.name).collect())
    }

    // ---- I/O ---------------------------------------------------------------

    fn read_impl(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.with("read", |f| {
            let mut f = f;
            loop {
                match f.read(buf) {
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    r => return r,
                }
            }
        })
    }

    fn write_impl(&self, buf: &[u8]) -> io::Result<usize> {
        self.with("write", |f| {
            let mut f = f;
            // Like Go, issue at least one write, even for an empty buffer.
            let mut n = 0;
            loop {
                match f.write(&buf[n..]) {
                    Ok(k) => {
                        n += k;
                        if n == buf.len() {
                            return Ok(n);
                        }
                        if k == 0 {
                            return Err(io::ErrorKind::WriteZero.into());
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
        })
    }

    fn seek_impl(&self, pos: SeekFrom) -> io::Result<u64> {
        let r = self.with("seek", |f| {
            let mut f = f;
            f.seek(pos)
        })?;
        *self.dir.lock().unwrap_or_else(|e| e.into_inner()) = None;
        Ok(r)
    }
}

impl Read for File {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_impl(buf)
    }
}
impl Read for &File {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_impl(buf)
    }
}

impl Write for File {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_impl(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Write for &File {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_impl(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for File {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.seek_impl(pos)
    }
}
impl Seek for &File {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.seek_impl(pos)
    }
}

impl ReadAt for File {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize, gio::ReadError> {
        if offset > i64::MAX as u64 {
            return Err(gio::ReadError::new(
                0,
                PathError::new("readat", &self.name, io::Error::other("negative offset")).into(),
            ));
        }
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            None => Err(gio::ReadError::new(
                0,
                PathError::new("read", &self.name, fs::Error::Closed).into(),
            )),
            Some(f) => ReadAt::read_at(f, buf, offset).map_err(|e| {
                let n = e.read();
                gio::ReadError::new(n, self.wrap("read", e.into_source()))
            }),
        }
    }
}

impl WriteAt for File {
    fn write_at(&mut self, buf: &[u8], offset: u64) -> io::Result<()> {
        if self.append {
            return Err(io::Error::other(
                "os: invalid use of WriteAt on file opened with O_APPEND",
            ));
        }
        if offset > i64::MAX as u64 {
            return Err(
                PathError::new("writeat", &self.name, io::Error::other("negative offset")).into(),
            );
        }
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            None => Err(PathError::new("write", &self.name, fs::Error::Closed).into()),
            Some(f) => {
                use std::os::unix::fs::FileExt;
                f.write_all_at(buf, offset)
                    .map_err(|e| self.wrap("write", e))
            }
        }
    }
}

impl File {
    /// Reads from `r` until EOF and writes it to the file (`File.ReadFrom`);
    /// returns the bytes written.
    pub fn read_from<R: Read + ?Sized>(&mut self, r: &mut R) -> io::Result<u64> {
        let mut buf = vec![0u8; 32 * 1024];
        let mut total = 0u64;
        loop {
            let n = match r.read(&mut buf) {
                Ok(0) => return Ok(total),
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            self.write_impl(&buf[..n])?;
            total += n as u64;
        }
    }

    /// Writes the rest of the file to `w` (`File.WriteTo`); returns the bytes
    /// written.
    pub fn write_to<W: Write + ?Sized>(&mut self, w: &mut W) -> io::Result<u64> {
        let mut buf = vec![0u8; 32 * 1024];
        let mut total = 0u64;
        loop {
            let n = self.read_impl(&mut buf)?;
            if n == 0 {
                return Ok(total);
            }
            w.write_all(&buf[..n])?;
            total += n as u64;
        }
    }
}

impl AsRawFd for File {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        guard.as_ref().map_or(-1, |f| f.as_raw_fd())
    }
}

impl fs::File for File {
    fn stat(&self) -> io::Result<Box<dyn FileInfo>> {
        File::stat(self)
    }
    fn close(&mut self) -> io::Result<()> {
        File::close(self)
    }
    fn as_read_dir_file(&mut self) -> Option<&mut dyn fs::ReadDirFile> {
        let is_dir = self
            .with("stat", |f| f.metadata())
            .is_ok_and(|m| m.is_dir());
        if is_dir {
            Some(self)
        } else {
            None
        }
    }
}

impl fs::ReadDirFile for File {
    fn read_dir(&mut self, n: i32) -> Result<Vec<Box<dyn DirEntry>>, ReadDirError> {
        Ok(File::read_dir(self, n)?)
    }
}
