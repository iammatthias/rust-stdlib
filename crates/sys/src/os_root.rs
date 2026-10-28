//! Go's `os.Root`: file system access confined to a directory tree, built on
//! `openat(2)` and friends so that no path is ever resolved by the kernel
//! outside the root. The traversal is Go's `doInRoot`: names are walked one
//! component at a time from a directory descriptor, `..` restarts from the
//! root and may not climb above it, symbolic links are followed by hand (at
//! most eight) and anything that leaves the root fails with "path escapes
//! from parent".
use crate::errno::{
    Errno, EACCES, EEXIST, EINVAL, ELOOP, EMLINK, ENAMETOOLONG, ENOTDIR, ENOTSUP,
    EOPNOTSUPP, EISDIR, EPERM,
};
use crate::ffi::at::{self, Stat};
use crate::os_file::{File, FileError, FileKind};
use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub use crate::ffi::at::{
    O_APPEND, O_CLOEXEC, O_CREATE, O_EXCL, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY,
};

const MAX_SYMLINKS: usize = 8;
/// Do not check the terminal slash (Go: `doInRootNoHandleTerminalSlash`).
const NO_HANDLE_TERMINAL_SLASH: u32 = 1;
/// The final component may not exist yet (`doInRootCreatingDirectory`).
const CREATING_DIRECTORY: u32 = 2;

/// `os.FileMode`: permission bits plus Go's type bits.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct FileMode(pub u32);

impl FileMode {
    pub const DIR: u32 = 1 << 31;
    pub const APPEND: u32 = 1 << 30;
    pub const EXCLUSIVE: u32 = 1 << 29;
    pub const TEMPORARY: u32 = 1 << 28;
    pub const SYMLINK: u32 = 1 << 27;
    pub const DEVICE: u32 = 1 << 26;
    pub const NAMED_PIPE: u32 = 1 << 25;
    pub const SOCKET: u32 = 1 << 24;
    pub const SETUID: u32 = 1 << 23;
    pub const SETGID: u32 = 1 << 22;
    pub const CHAR_DEVICE: u32 = 1 << 21;
    pub const STICKY: u32 = 1 << 20;
    pub const IRREGULAR: u32 = 1 << 19;
    pub const TYPE: u32 = Self::DIR | Self::SYMLINK | Self::NAMED_PIPE | Self::SOCKET | Self::DEVICE | Self::IRREGULAR;
    pub const PERM: u32 = 0o777;

    /// `FileMode.IsDir`.
    pub fn is_dir(self) -> bool {
        self.0 & Self::DIR != 0
    }

    /// `FileMode.IsRegular`.
    pub fn is_regular(self) -> bool {
        self.0 & Self::TYPE == 0
    }

    /// `FileMode.Type`.
    pub fn file_type(self) -> FileMode {
        FileMode(self.0 & Self::TYPE)
    }

    /// `FileMode.Perm`.
    pub fn perm(self) -> FileMode {
        FileMode(self.0 & Self::PERM)
    }

    /// The `FileMode` for a Unix `st_mode`.
    pub fn from_unix_mode(m: u32) -> FileMode {
        let mut mode = m & 0o777;
        match m & 0o170000 {
            0o060000 => mode |= Self::DEVICE,
            0o020000 => mode |= Self::DEVICE | Self::CHAR_DEVICE,
            0o040000 => mode |= Self::DIR,
            0o010000 => mode |= Self::NAMED_PIPE,
            0o120000 => mode |= Self::SYMLINK,
            0o140000 => mode |= Self::SOCKET,
            _ => {}
        }
        if m & 0o4000 != 0 {
            mode |= Self::SETUID;
        }
        if m & 0o2000 != 0 {
            mode |= Self::SETGID;
        }
        if m & 0o1000 != 0 {
            mode |= Self::STICKY;
        }
        FileMode(mode)
    }
}

impl fmt::Display for FileMode {
    /// `FileMode.String`: "drwxr-xr-x" style.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const STR: &[u8] = b"dalTLDpSugct?";
        let mut out = String::new();
        for (i, c) in STR.iter().enumerate() {
            if self.0 & (1 << (31 - i)) != 0 {
                out.push(*c as char);
            }
        }
        if out.is_empty() {
            out.push('-');
        }
        const RWX: &[u8] = b"rwxrwxrwx";
        for (i, c) in RWX.iter().enumerate() {
            if self.0 & (1 << (8 - i)) != 0 {
                out.push(*c as char);
            } else {
                out.push('-');
            }
        }
        f.write_str(&out)
    }
}

/// `os.FileInfo` as returned by `Root.Stat` and `Root.Lstat`.
#[derive(Clone, Debug)]
pub struct FileInfo {
    name: String,
    size: i64,
    mode: FileMode,
    mod_time: SystemTime,
    dev: u64,
    ino: u64,
}

impl FileInfo {
    pub(crate) fn from_stat(st: &Stat, name: &str) -> FileInfo {
        let (secs, nanos) = st.mtime;
        let mod_time = if secs >= 0 {
            UNIX_EPOCH + Duration::new(secs as u64, nanos as u32)
        } else {
            UNIX_EPOCH - Duration::new(secs.unsigned_abs(), 0) + Duration::new(0, nanos as u32)
        };
        FileInfo {
            name: basename(name),
            size: st.size,
            mode: FileMode::from_unix_mode(st.mode),
            mod_time,
            dev: st.dev,
            ino: st.ino,
        }
    }

    /// `FileInfo.Name`.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// `FileInfo.Size`.
    pub fn size(&self) -> i64 {
        self.size
    }
    /// `FileInfo.Mode`.
    pub fn mode(&self) -> FileMode {
        self.mode
    }
    /// `FileInfo.ModTime`.
    pub fn mod_time(&self) -> SystemTime {
        self.mod_time
    }
    /// `FileInfo.IsDir`.
    pub fn is_dir(&self) -> bool {
        self.mode.is_dir()
    }
    /// `os.SameFile`.
    pub fn same_file(&self, other: &FileInfo) -> bool {
        self.dev == other.dev && self.ino == other.ino
    }
}

/// Go's `basename`: the last element, ignoring trailing slashes.
fn basename(name: &str) -> String {
    let trimmed = if name.len() > 1 {
        name.trim_end_matches('/')
    } else {
        name
    };
    let trimmed = if trimmed.is_empty() && !name.is_empty() {
        "/"
    } else {
        trimmed
    };
    match trimmed.rfind('/') {
        Some(i) if trimmed.len() > 1 => trimmed[i + 1..].to_string(),
        _ => trimmed.to_string(),
    }
}

/// `fs.DirEntry` as returned by [`RootFS::read_dir`].
#[derive(Clone, Debug)]
pub struct DirEntry {
    info: FileInfo,
}

impl DirEntry {
    /// `DirEntry.Name`.
    pub fn name(&self) -> &str {
        &self.info.name
    }
    /// `DirEntry.IsDir`.
    pub fn is_dir(&self) -> bool {
        self.info.mode.is_dir()
    }
    /// `DirEntry.Type`.
    pub fn file_type(&self) -> FileMode {
        self.info.mode.file_type()
    }
    /// `DirEntry.Info`.
    pub fn info(&self) -> &FileInfo {
        &self.info
    }
}

/// What went wrong inside a [`RootError`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Cause {
    /// An operating-system error.
    Errno(Errno),
    /// "path escapes from parent".
    PathEscapes,
    /// `os.ErrClosed`: "file already closed".
    Closed,
    /// `os.ErrInvalid`: "invalid argument".
    Invalid,
    /// Any other message (Go's `errors.New`).
    Other(String),
    /// An error from another operation, carried as the cause (Go wraps the
    /// `*PathError` of `Stat` inside `MkdirAll`'s).
    Wrapped(Box<RootError>),
}

impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Cause::Errno(e) => e.fmt(f),
            Cause::PathEscapes => f.write_str("path escapes from parent"),
            Cause::Closed => f.write_str("file already closed"),
            Cause::Invalid => f.write_str("invalid argument"),
            Cause::Other(s) => f.write_str(s),
            Cause::Wrapped(e) => e.fmt(f),
        }
    }
}

impl Cause {
    fn errno(&self) -> Option<Errno> {
        match self {
            Cause::Errno(e) => Some(*e),
            Cause::Wrapped(e) => e.errno(),
            _ => None,
        }
    }
}

/// `*os.PathError`, `*os.LinkError` or a file error from a [`Root`] operation.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RootError {
    /// `os.PathError`.
    Path {
        op: String,
        path: String,
        err: Cause,
    },
    /// `os.LinkError`.
    Link {
        op: String,
        old: String,
        new: String,
        err: Cause,
    },
    /// An error from reading, writing or closing a file.
    File(FileError),
}

impl RootError {
    fn path(op: &str, path: &str, err: Cause) -> RootError {
        RootError::Path {
            op: op.into(),
            path: path.into(),
            err,
        }
    }

    /// The underlying cause, when it is not a file error.
    pub fn cause(&self) -> Option<&Cause> {
        match self {
            RootError::Path { err, .. } | RootError::Link { err, .. } => Some(err),
            RootError::File(_) => None,
        }
    }

    fn errno(&self) -> Option<Errno> {
        match self {
            RootError::File(e) => match &e.err {
                crate::net::Cause::Errno(n) => Some(*n),
                _ => None,
            },
            other => other.cause().and_then(Cause::errno),
        }
    }

    /// The errno `os.IsExist` and friends see: they unwrap one level only,
    /// so an error carried inside another is not examined.
    fn errno_shallow(&self) -> Option<Errno> {
        match self {
            RootError::Path { err, .. } | RootError::Link { err, .. } => match err {
                Cause::Errno(e) => Some(*e),
                _ => None,
            },
            RootError::File(_) => self.errno(),
        }
    }

    /// `os.IsExist`.
    pub fn is_exist(&self) -> bool {
        self.errno_shallow().is_some_and(|e| e.is("exist"))
    }
    /// `os.IsNotExist`.
    pub fn is_not_exist(&self) -> bool {
        self.errno_shallow().is_some_and(|e| e.is("not-exist"))
    }
    /// `os.IsPermission`.
    pub fn is_permission(&self) -> bool {
        self.errno_shallow().is_some_and(|e| e.is("permission"))
    }
    /// `os.IsTimeout`.
    pub fn is_timeout(&self) -> bool {
        self.errno_shallow().is_some_and(|e| e.timeout())
    }
    /// `errors.Is(err, fs.ErrExist)`: unwraps every level.
    pub fn err_is_exist(&self) -> bool {
        self.errno().is_some_and(|e| e.is("exist"))
    }
    /// `errors.Is(err, fs.ErrNotExist)`.
    pub fn err_is_not_exist(&self) -> bool {
        self.errno().is_some_and(|e| e.is("not-exist"))
    }
    /// `errors.Is(err, fs.ErrPermission)`.
    pub fn err_is_permission(&self) -> bool {
        self.errno().is_some_and(|e| e.is("permission"))
    }
    /// `errors.Is(err, fs.ErrClosed)`.
    pub fn is_closed(&self) -> bool {
        match self {
            RootError::File(e) => matches!(e.err, crate::net::Cause::FileClosed),
            other => matches!(other.cause(), Some(Cause::Closed)),
        }
    }
    /// `errors.Is(err, fs.ErrInvalid)`.
    pub fn is_invalid(&self) -> bool {
        matches!(self.cause(), Some(Cause::Invalid))
    }
}

impl fmt::Display for RootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RootError::Path { op, path, err } => write!(f, "{op} {path}: {err}"),
            RootError::Link { op, old, new, err } => write!(f, "{op} {old} {new}: {err}"),
            RootError::File(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for RootError {}

impl From<FileError> for RootError {
    fn from(e: FileError) -> RootError {
        RootError::File(e)
    }
}

impl From<RootError> for io::Error {
    fn from(e: RootError) -> io::Error {
        let kind = if e.is_not_exist() {
            io::ErrorKind::NotFound
        } else if e.is_exist() {
            io::ErrorKind::AlreadyExists
        } else if e.is_permission() {
            io::ErrorKind::PermissionDenied
        } else {
            io::ErrorKind::Other
        };
        io::Error::new(kind, e)
    }
}

/// An error inside the traversal: Go's `errSymlink`, a `*PathError` whose
/// path `do_in_root` fills in, or a bare cause.
enum IErr {
    Symlink(String),
    Path { op: &'static str, err: Cause },
    PathAt { op: &'static str, path: String, err: Cause },
    Cause(Cause),
}

impl IErr {
    fn errno(e: Errno) -> IErr {
        IErr::Cause(Cause::Errno(e))
    }

    fn into_cause(self) -> Cause {
        match self {
            IErr::Cause(c) | IErr::Path { err: c, .. } | IErr::PathAt { err: c, .. } => c,
            IErr::Symlink(_) => Cause::Errno(ELOOP),
        }
    }

    fn is_not_exist(&self) -> bool {
        match self {
            IErr::Cause(c) | IErr::Path { err: c, .. } | IErr::PathAt { err: c, .. } => {
                c.errno().is_some_and(|e| e.is("not-exist"))
            }
            IErr::Symlink(_) => false,
        }
    }
}

type IResult<T> = Result<T, IErr>;

fn eno<T>(e: Errno) -> IResult<T> {
    Err(IErr::errno(e))
}

fn is_nofollow_err(e: Errno) -> bool {
    e == ELOOP || e == EMLINK
}

/// Go's `checkSymlink`: the link's target as `IErr::Symlink`, or `orig`.
fn check_symlink(parent: RawFd, name: &str, orig: Option<Errno>) -> Option<IErr> {
    match at::readlinkat(parent, name.as_bytes()) {
        Ok(target) => Some(IErr::Symlink(String::from_utf8_lossy(&target).into_owned())),
        Err(_) => orig.map(IErr::errno),
    }
}

/// Go's `rootOpenDir`.
fn root_open_dir(parent: RawFd, name: &str) -> IResult<OwnedFd> {
    match at::openat(parent, name.as_bytes(), at::O_NOFOLLOW | at::O_DIRECTORY, 0) {
        Ok(fd) => Ok(fd),
        Err(e) if is_nofollow_err(e) || e == ENOTDIR => {
            Err(check_symlink(parent, name, Some(e)).unwrap_or(IErr::errno(e)))
        }
        Err(e) if e == ENOTSUP || e == EOPNOTSUPP => eno(ENOTDIR),
        Err(e) => eno(e),
    }
}

fn lstatat(parent: RawFd, name: &str) -> Result<Stat, Errno> {
    at::lstatat(parent, name.as_bytes())
}

/// Go's `splitPathInRoot`.
fn split_path(
    s: &str,
    prefix: &[String],
    suffix: &[String],
) -> Result<(Vec<String>, bool), Cause> {
    if s.is_empty() {
        return Err(Cause::Other("empty path".into()));
    }
    if s.starts_with('/') {
        return Err(Cause::PathEscapes);
    }
    let b = s.as_bytes();
    let mut parts: Vec<String> = prefix.to_vec();
    let mut ends_in_slash = false;
    let (mut i, mut j) = (0usize, 1usize);
    loop {
        if j < b.len() && b[j] != b'/' {
            j += 1;
            continue;
        }
        parts.push(s[i..j].to_string());
        let part_end = j;
        while j < b.len() && b[j] == b'/' {
            j += 1;
        }
        if j == b.len() {
            if b.len() > part_end {
                ends_in_slash = true;
            }
            break;
        }
        if parts.last().is_some_and(|p| p == ".") {
            parts.pop();
        }
        i = j;
    }
    if !suffix.is_empty() && parts.last().is_some_and(|p| p == ".") {
        parts.pop();
    }
    parts.extend(suffix.iter().cloned());
    Ok((parts, ends_in_slash))
}

fn join_path(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

struct Inner {
    fd: Option<Arc<OwnedFd>>,
}

/// `os.Root`: a directory whose tree file operations are confined to.
pub struct Root {
    name: String,
    inner: Mutex<Inner>,
}

impl fmt::Debug for Root {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Root").field("name", &self.name).finish()
    }
}

/// `os.OpenRoot`: opens the directory `name` as a [`Root`].
pub fn open_root(name: &str) -> Result<Root, RootError> {
    let fd = at::openat(at::k::AT_FDCWD, name.as_bytes(), 0, 0)
        .map_err(|e| RootError::path("open", name, Cause::Errno(e)))?;
    new_root(fd, name)
}

/// `os.OpenInRoot`: opens the file `name` in the directory `dir`, refusing
/// any name that escapes it.
pub fn open_in_root(dir: &str, name: &str) -> Result<File, RootError> {
    let r = open_root(dir)?;
    let f = r.open(name);
    let _ = r.close();
    f
}

fn new_root(fd: OwnedFd, name: &str) -> Result<Root, RootError> {
    if let Ok(st) = at::fstat(fd.as_raw_fd()) {
        if FileMode::from_unix_mode(st.mode).0 & FileMode::DIR == 0 {
            return Err(RootError::path(
                "open",
                name,
                Cause::Other("not a directory".into()),
            ));
        }
    }
    Ok(Root {
        name: name.to_string(),
        inner: Mutex::new(Inner {
            fd: Some(Arc::new(fd)),
        }),
    })
}

fn lock(m: &Mutex<Inner>) -> std::sync::MutexGuard<'_, Inner> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

type OpenDirFn<'a> = dyn Fn(RawFd, &str) -> IResult<OwnedFd> + 'a;

impl Root {
    /// `Root.Name`: the name given to [`open_root`] (or joined by
    /// [`Root::open_root`]).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// `Root.Close`: later operations fail with `ErrClosed`; operations in
    /// progress finish first.
    pub fn close(&self) -> Result<(), RootError> {
        lock(&self.inner).fd = None;
        Ok(())
    }

    /// Go's `doInRoot`: resolves `name` and calls `f` with the directory
    /// descriptor holding the final component, its name and whether `name`
    /// ended in a slash.
    fn do_in_root<T>(
        &self,
        name: &str,
        flags: u32,
        open_dir: Option<&OpenDirFn<'_>>,
        f: &mut dyn FnMut(RawFd, &str, bool) -> IResult<T>,
    ) -> IResult<T> {
        let Some(rootfd) = lock(&self.inner).fd.clone() else {
            return Err(IErr::Cause(Cause::Closed));
        };
        let rootraw = rootfd.as_raw_fd();
        let (mut parts, mut ends_in_slash) = split_path(name, &[], &[]).map_err(IErr::Cause)?;
        // None means the root itself.
        let mut dir: Option<OwnedFd> = None;
        let cur = |d: &Option<OwnedFd>| d.as_ref().map_or(rootraw, |f| f.as_raw_fd());
        let (mut i, mut steps, mut restarts, mut symlinks) = (0usize, 0usize, 0usize, 0usize);
        loop {
            steps += 1;
            if steps > 255 && restarts > 8 {
                return eno(ENAMETOOLONG);
            }
            if parts[i] == ".." {
                restarts += 1;
                let mut end = i + 1;
                while end < parts.len() && parts[end] == ".." {
                    end += 1;
                }
                let count = end - i;
                if count > i {
                    return Err(IErr::Cause(Cause::PathEscapes));
                }
                parts.drain(i - count..end);
                if parts.is_empty() {
                    parts.push(".".to_string());
                }
                i = 0;
                dir = None;
                continue;
            }
            let last = i == parts.len() - 1;
            let dirfd = cur(&dir);
            let mut err: Option<IErr> = None;
            if last {
                if ends_in_slash && flags & NO_HANDLE_TERMINAL_SLASH == 0 {
                    match lstatat(dirfd, &parts[i]) {
                        Err(e)
                            if e.is("not-exist") && flags & CREATING_DIRECTORY != 0 => {}
                        Err(e) => return eno(e),
                        Ok(st) => match FileMode::from_unix_mode(st.mode).file_type().0 {
                            FileMode::DIR => {}
                            FileMode::SYMLINK => {
                                err = check_symlink(dirfd, &parts[i], Some(ENOTDIR));
                            }
                            _ => return eno(ENOTDIR),
                        },
                    }
                }
                if err.is_none() {
                    match f(dirfd, &parts[i], ends_in_slash) {
                        Ok(v) => return Ok(v),
                        Err(e) => err = Some(e),
                    }
                }
            } else {
                let res = match open_dir {
                    Some(od) => od(dirfd, &parts[i]),
                    None => root_open_dir(dirfd, &parts[i]),
                };
                match res {
                    Ok(fd) => dir = Some(fd),
                    Err(e) => err = Some(e),
                }
            }
            match err {
                None => {}
                Some(IErr::Symlink(target)) => {
                    symlinks += 1;
                    if symlinks > MAX_SYMLINKS {
                        return eno(ELOOP);
                    }
                    let (newparts, new_slash) =
                        split_path(&target, &parts[..i], &parts[i + 1..]).map_err(IErr::Cause)?;
                    if last && new_slash {
                        ends_in_slash = true;
                    }
                    if newparts.len() < i || parts[..i] != newparts[..i] {
                        i = 0;
                        dir = None;
                    }
                    parts = newparts;
                    continue;
                }
                Some(IErr::Path { op, err }) => {
                    return Err(IErr::PathAt {
                        op,
                        path: parts[..=i].join("/"),
                        err,
                    });
                }
                Some(IErr::PathAt { op, err, .. }) => {
                    return Err(IErr::PathAt {
                        op,
                        path: parts[..=i].join("/"),
                        err,
                    });
                }
                Some(other) => return Err(other),
            }
            i += 1;
        }
    }

    /// `do_in_root` wrapped as Go's `&PathError{Op: op, Path: name, Err: err}`.
    fn path_op<T>(
        &self,
        op: &'static str,
        name: &str,
        flags: u32,
        f: &mut dyn FnMut(RawFd, &str, bool) -> IResult<T>,
    ) -> Result<T, RootError> {
        self.do_in_root(name, flags, None, f)
            .map_err(|e| match e {
                IErr::PathAt { op, path, err } => RootError::path(op, &path, err),
                other => RootError::path(op, name, other.into_cause()),
            })
    }

    fn open_flags(
        &self,
        name: &str,
        flag: i32,
        perm: u32,
        opname: &'static str,
    ) -> Result<OwnedFd, RootError> {
        let create_excl = flag & (O_CREATE | O_EXCL) == (O_CREATE | O_EXCL);
        self.path_op(opname, name, 0, &mut |parent, n, _| {
            match at::openat(parent, n.as_bytes(), at::O_NOFOLLOW | flag, perm) {
                Ok(fd) => Ok(fd),
                Err(e) => {
                    let mut err = IErr::errno(e);
                    if !create_excl && (is_nofollow_err(e) || e == ENOTDIR) {
                        if let Some(s) = check_symlink(parent, n, Some(e)) {
                            err = s;
                        }
                    }
                    if create_excl && e == ELOOP {
                        err = IErr::errno(EEXIST);
                    }
                    Err(err)
                }
            }
        })
    }

    /// `Root.Open`: opens the named file for reading.
    pub fn open(&self, name: &str) -> Result<File, RootError> {
        self.open_file(name, O_RDONLY, 0)
    }

    /// `Root.Create`: creates or truncates the named file.
    pub fn create(&self, name: &str) -> Result<File, RootError> {
        self.open_file(name, O_RDWR | O_CREATE | O_TRUNC, 0o666)
    }

    /// `Root.OpenFile`: opens the named file with flags and permissions.
    pub fn open_file(&self, name: &str, flag: i32, perm: u32) -> Result<File, RootError> {
        if perm & 0o777 != perm {
            return Err(RootError::path(
                "openat",
                name,
                Cause::Other("unsupported file mode".into()),
            ));
        }
        let fd = self.open_flags(name, flag, perm, "openat")?;
        let full = join_path(&self.name, name);
        File::new(std::fs::File::from(fd), &full, FileKind::OpenFile)
            .map_err(|e| RootError::path("openat", name, Cause::Errno(e.into())))
    }

    /// `Root.OpenRoot`: opens the directory `name` as a new [`Root`].
    pub fn open_root(&self, name: &str) -> Result<Root, RootError> {
        let fd = self.path_op("openat", name, 0, &mut |parent, n, _| {
            match at::openat(parent, n.as_bytes(), at::O_NOFOLLOW, 0) {
                Ok(fd) => Ok(fd),
                Err(e) => {
                    if is_nofollow_err(e) {
                        if let Some(s) = check_symlink(parent, n, Some(e)) {
                            return Err(s);
                        }
                    }
                    eno(e)
                }
            }
        })?;
        new_root(fd, &join_path(&self.name, name))
    }

    /// Go's `afterResolvingSymlink`: fails with the link target (to be
    /// followed) when the final component is a symbolic link.
    fn after_resolving(
        &self,
        op: &'static str,
        name: &str,
        act: &dyn Fn(RawFd, &str) -> Result<(), Errno>,
    ) -> Result<(), RootError> {
        self.path_op(op, name, 0, &mut |parent, n, _| {
            if let Some(s) = check_symlink(parent, n, None) {
                return Err(s);
            }
            act(parent, n).map_err(IErr::errno)
        })
    }

    /// `Root.Chmod`.
    pub fn chmod(&self, name: &str, mode: FileMode) -> Result<(), RootError> {
        let bits = (mode.0 & 0o777)
            | if mode.0 & FileMode::SETUID != 0 { 0o4000 } else { 0 }
            | if mode.0 & FileMode::SETGID != 0 { 0o2000 } else { 0 }
            | if mode.0 & FileMode::STICKY != 0 { 0o1000 } else { 0 };
        self.after_resolving("chmodat", name, &|p, n| {
            at::fchmodat_nofollow(p, n.as_bytes(), bits)
        })
    }

    /// `Root.Chown`.
    pub fn chown(&self, name: &str, uid: i32, gid: i32) -> Result<(), RootError> {
        self.after_resolving("chownat", name, &|p, n| {
            at::fchownat_nofollow(p, n.as_bytes(), uid, gid)
        })
    }

    /// `Root.Lchown`.
    pub fn lchown(&self, name: &str, uid: i32, gid: i32) -> Result<(), RootError> {
        self.path_op("lchownat", name, 0, &mut |p, n, _| {
            at::fchownat_nofollow(p, n.as_bytes(), uid, gid).map_err(IErr::errno)
        })
    }

    /// `Root.Chtimes`; `None` (Go's zero time) leaves that time unchanged.
    pub fn chtimes(
        &self,
        name: &str,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> Result<(), RootError> {
        let (a, m) = (atime.map(crate::os::timespec), mtime.map(crate::os::timespec));
        self.after_resolving("chtimesat", name, &|p, n| {
            at::utimensat_nofollow(p, n.as_bytes(), a, m)
        })
    }

    fn mkdir_flags() -> u32 {
        // Linux does not follow "symlink" on "mkdir symlink/".
        if cfg!(target_os = "linux") {
            CREATING_DIRECTORY | NO_HANDLE_TERMINAL_SLASH
        } else {
            CREATING_DIRECTORY
        }
    }

    /// `Root.Mkdir`.
    pub fn mkdir(&self, name: &str, perm: u32) -> Result<(), RootError> {
        if perm & 0o777 != perm {
            return Err(RootError::path(
                "mkdirat",
                name,
                Cause::Other("unsupported file mode".into()),
            ));
        }
        self.path_op("mkdirat", name, Self::mkdir_flags(), &mut |p, n, _| {
            at::mkdirat(p, n.as_bytes(), perm).map_err(IErr::errno)
        })
    }

    /// `Root.MkdirAll`.
    pub fn mkdir_all(&self, fullname: &str, perm: u32) -> Result<(), RootError> {
        if perm & 0o777 != perm {
            return Err(RootError::path(
                "mkdirat",
                fullname,
                Cause::Other("unsupported file mode".into()),
            ));
        }
        let open_dir = |parent: RawFd, n: &str| -> IResult<OwnedFd> {
            for attempt in 0..2 {
                match root_open_dir(parent, n) {
                    Ok(fd) => return Ok(fd),
                    Err(IErr::Symlink(t)) => return Err(IErr::Symlink(t)),
                    Err(e) => {
                        if attempt > 0 || !e.is_not_exist() {
                            return Err(IErr::Path {
                                op: "openat",
                                err: e.into_cause(),
                            });
                        }
                        if let Err(e) = at::mkdirat(parent, n.as_bytes(), perm) {
                            if e != EEXIST {
                                return Err(IErr::Path {
                                    op: "mkdirat",
                                    err: Cause::Errno(e),
                                });
                            }
                        }
                    }
                }
            }
            eno(EINVAL)
        };
        let mut last = |parent: RawFd, n: &str, _: bool| -> IResult<()> {
            let mut err: Option<IErr> = at::mkdirat(parent, n.as_bytes(), perm)
                .err()
                .map(IErr::errno);
            if matches!(&err, Some(IErr::Cause(Cause::Errno(e))) if *e == EEXIST) {
                if let Ok(st) = lstatat(parent, n) {
                    let mode = FileMode::from_unix_mode(st.mode);
                    if mode.is_dir() {
                        err = None;
                    } else if mode.0 & FileMode::SYMLINK != 0 {
                        match self.stat(fullname) {
                            Ok(fi) if fi.mode().is_dir() => err = None,
                            Ok(_) => err = Some(IErr::errno(ENOTDIR)),
                            Err(e) if !e.is_not_exist() => {
                                err = Some(IErr::Cause(Cause::Wrapped(Box::new(e))))
                            }
                            Err(_) => {}
                        }
                    }
                }
            }
            match err {
                None => Ok(()),
                Some(IErr::Symlink(t)) => Err(IErr::Symlink(t)),
                Some(e) => Err(IErr::Path {
                    op: "mkdirat",
                    err: e.into_cause(),
                }),
            }
        };
        match self.do_in_root(fullname, Self::mkdir_flags(), Some(&open_dir), &mut last) {
            Ok(()) => Ok(()),
            Err(IErr::PathAt { op, path, err }) => Err(RootError::path(op, &path, err)),
            Err(e) => Err(RootError::path("mkdirat", fullname, e.into_cause())),
        }
    }

    /// `Root.Remove`: removes a file or empty directory.
    pub fn remove(&self, name: &str) -> Result<(), RootError> {
        self.path_op("removeat", name, 0, &mut |p, n, _| {
            removeat(p, n).map_err(IErr::errno)
        })
    }

    /// `Root.RemoveAll`: removes the path and any children.
    pub fn remove_all(&self, name: &str) -> Result<(), RootError> {
        let mut name = name;
        while name.ends_with('/') {
            name = &name[..name.len() - 1];
        }
        if name == "." || name.ends_with("/.") {
            return Err(RootError::path("RemoveAll", name, Cause::Errno(EINVAL)));
        }
        match self.do_in_root(name, 0, None, &mut |p, n, _| remove_all_from(p, n)) {
            Ok(()) => Ok(()),
            Err(e) if e.is_not_exist() => Ok(()),
            Err(e) => Err(RootError::path("RemoveAll", name, e.into_cause())),
        }
    }

    /// `Root.Stat`: follows a final symbolic link inside the root.
    pub fn stat(&self, name: &str) -> Result<FileInfo, RootError> {
        self.stat_at(name, false)
    }

    /// `Root.Lstat`.
    pub fn lstat(&self, name: &str) -> Result<FileInfo, RootError> {
        self.stat_at(name, true)
    }

    fn stat_at(&self, name: &str, lstat: bool) -> Result<FileInfo, RootError> {
        self.path_op("statat", name, 0, &mut |p, n, _| {
            let st = lstatat(p, n).map_err(IErr::errno)?;
            let fi = FileInfo::from_stat(&st, name);
            if !lstat && fi.mode.0 & FileMode::SYMLINK != 0 {
                return Err(check_symlink(p, n, Some(ELOOP)).unwrap_or(IErr::errno(ELOOP)));
            }
            Ok(fi)
        })
    }

    /// `Root.Readlink`.
    pub fn readlink(&self, name: &str) -> Result<String, RootError> {
        self.path_op("readlinkat", name, 0, &mut |p, n, _| {
            at::readlinkat(p, n.as_bytes())
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .map_err(IErr::errno)
        })
    }

    /// `Root.Rename`.
    pub fn rename(&self, oldname: &str, newname: &str) -> Result<(), RootError> {
        let r = self.do_in_root(oldname, 0, None, &mut |oldp, oldn, _| {
            self.do_in_root(newname, CREATING_DIRECTORY, None, &mut |newp, newn, new_slash| {
                if new_slash {
                    let st = lstatat(oldp, oldn).map_err(IErr::errno)?;
                    if FileMode::from_unix_mode(st.mode).file_type().0 != FileMode::DIR {
                        return eno(ENOTDIR);
                    }
                }
                if let Ok(fi) = lstatat(newp, newn) {
                    if FileMode::from_unix_mode(fi.mode).is_dir() {
                        let ofi = lstatat(oldp, oldn).map_err(IErr::errno)?;
                        let same = ofi.dev == fi.dev && ofi.ino == fi.ino;
                        if newn == oldn || !same {
                            return eno(EEXIST);
                        }
                    }
                }
                at::renameat(oldp, oldn.as_bytes(), newp, newn.as_bytes()).map_err(IErr::errno)
            })
        });
        r.map_err(|e| link_error("renameat", oldname, newname, e))
    }

    /// `Root.Link`.
    pub fn link(&self, oldname: &str, newname: &str) -> Result<(), RootError> {
        let r = self.do_in_root(oldname, 0, None, &mut |oldp, oldn, _| {
            self.do_in_root(newname, 0, None, &mut |newp, newn, _| {
                at::linkat(oldp, oldn.as_bytes(), newp, newn.as_bytes()).map_err(IErr::errno)
            })
        });
        r.map_err(|e| link_error("linkat", oldname, newname, e))
    }

    /// `Root.Symlink`: the target is stored as given and checked when followed.
    pub fn symlink(&self, oldname: &str, newname: &str) -> Result<(), RootError> {
        let r = self.do_in_root(newname, 0, None, &mut |p, n, _| {
            at::symlinkat(oldname.as_bytes(), p, n.as_bytes()).map_err(IErr::errno)
        });
        r.map_err(|e| link_error("symlinkat", oldname, newname, e))
    }

    /// `Root.ReadFile`.
    pub fn read_file(&self, name: &str) -> Result<Vec<u8>, RootError> {
        let f = self.open(name)?;
        let mut data = Vec::new();
        let mut buf = vec![0u8; 8192];
        let result = loop {
            match f.read(&mut buf) {
                Ok(0) => break Ok(()),
                Ok(n) => data.extend_from_slice(&buf[..n]),
                Err(e) => break Err(RootError::File(e)),
            }
        };
        let _ = f.close();
        result.map(|()| data)
    }

    /// `Root.WriteFile`: writes data, creating or truncating the file.
    pub fn write_file(&self, name: &str, data: &[u8], perm: u32) -> Result<(), RootError> {
        let f = self.open_file(name, O_WRONLY | O_CREATE | O_TRUNC, perm)?;
        let w = f.write(data).map(|_| ()).map_err(RootError::File);
        let c = f.close().map_err(RootError::File);
        w.and(c)
    }

    /// `Root.FS`: a read-only view with `io/fs` style methods.
    pub fn fs(&self) -> RootFS<'_> {
        RootFS { root: self }
    }
}

fn link_error(op: &str, old: &str, new: &str, e: IErr) -> RootError {
    RootError::Link {
        op: op.into(),
        old: old.into(),
        new: new.into(),
        err: e.into_cause(),
    }
}

/// Go's `removeat`: unlink, then rmdir, choosing the more useful error.
fn removeat(fd: RawFd, name: &str) -> Result<(), Errno> {
    let e = match at::unlinkat(fd, name.as_bytes(), false) {
        Ok(()) => return Ok(()),
        Err(e) => e,
    };
    let e1 = match at::unlinkat(fd, name.as_bytes(), true) {
        Ok(()) => return Ok(()),
        Err(e1) => e1,
    };
    Err(if e1 != ENOTDIR { e1 } else { e })
}

/// Go's `removeAllFrom`.
fn remove_all_from(parent: RawFd, base: &str) -> IResult<()> {
    let err = match at::unlinkat(parent, base.as_bytes(), false) {
        Ok(()) => return Ok(()),
        Err(e) if e.is("not-exist") => return Ok(()),
        Err(e) => e,
    };
    if err != EISDIR && err != EPERM && err != EACCES {
        return Err(path_at("unlinkat", base, err));
    }
    let u_err = err;
    let mut recurse_err: Option<IErr> = None;
    loop {
        const REQ_SIZE: usize = 1024;
        let dir = match root_open_dir(parent, base) {
            Ok(d) => d,
            Err(e) => {
                if e.is_not_exist() {
                    return Ok(());
                }
                let cause = match e {
                    IErr::Cause(Cause::Errno(n)) if n == ENOTDIR => {
                        return Err(path_at("unlinkat", base, u_err));
                    }
                    IErr::Symlink(_) => Cause::Errno(u_err),
                    other => other.into_cause(),
                };
                recurse_err = Some(IErr::PathAt {
                    op: "openfdat",
                    path: base.to_string(),
                    err: cause,
                });
                break;
            }
        };
        let names = match at::read_dir_names(dir.as_raw_fd()) {
            Ok(n) => n,
            Err(e) if e.is("not-exist") => return Ok(()),
            Err(e) => return Err(path_at("readdirnames", base, e)),
        };
        let resp = names.len();
        for name in names {
            let name = String::from_utf8_lossy(&name).into_owned();
            if let Err(e) = remove_all_from(dir.as_raw_fd(), &name) {
                let e = match e {
                    IErr::PathAt { op, path, err } => IErr::PathAt {
                        op,
                        path: format!("{base}/{path}"),
                        err,
                    },
                    other => other,
                };
                recurse_err.get_or_insert(e);
            }
        }
        drop(dir);
        if resp < REQ_SIZE {
            break;
        }
    }
    match at::unlinkat(parent, base.as_bytes(), true) {
        Ok(()) => Ok(()),
        Err(e) if e.is("not-exist") => Ok(()),
        Err(e) => Err(recurse_err.unwrap_or_else(|| path_at("unlinkat", base, e))),
    }
}

fn path_at(op: &'static str, path: &str, e: Errno) -> IErr {
    IErr::PathAt {
        op,
        path: path.to_string(),
        err: Cause::Errno(e),
    }
}

/// The result of [`Root::fs`]: `io/fs`-style read-only access.
#[derive(Debug)]
pub struct RootFS<'a> {
    root: &'a Root,
}

/// `fs.ValidPath`.
pub fn valid_path(name: &str) -> bool {
    if name == "." {
        return true;
    }
    name.split('/')
        .all(|elem| !(elem.is_empty() || elem == "." || elem == ".."))
}

impl RootFS<'_> {
    fn check(&self, op: &str, name: &str) -> Result<(), RootError> {
        if valid_path(name) {
            Ok(())
        } else {
            Err(RootError::path(op, name, Cause::Invalid))
        }
    }

    /// `FS.Open`.
    pub fn open(&self, name: &str) -> Result<File, RootError> {
        self.check("open", name)?;
        self.root.open(name)
    }

    /// `ReadDirFS.ReadDir`: the entries of the directory, sorted by name.
    pub fn read_dir(&self, name: &str) -> Result<Vec<DirEntry>, RootError> {
        self.check("readdir", name)?;
        let f = self.root.open(name)?;
        let fd = f.as_raw_fd();
        let call = if cfg!(target_os = "macos") { "fdopendir" } else { "readdirent" };
        let names = at::read_dir_names(fd)
            .map_err(|e| RootError::path(call, f.name(), Cause::Errno(e)));
        let result = names.map(|names| {
            let mut out = Vec::new();
            for n in names {
                let n = String::from_utf8_lossy(&n).into_owned();
                match lstatat(fd, &n) {
                    Ok(st) => out.push(DirEntry {
                        info: FileInfo::from_stat(&st, &n),
                    }),
                    // The file disappeared between readdir and stat.
                    Err(e) if e.is("not-exist") => {}
                    Err(e) => {
                        let path = format!("{}/{n}", f.name());
                        return Err(RootError::path("fstatat", &path, Cause::Errno(e)));
                    }
                }
            }
            out.sort_by(|a, b| a.name().cmp(b.name()));
            Ok(out)
        })
        .and_then(|r| r);
        let _ = f.close();
        result
    }

    /// `ReadFileFS.ReadFile`.
    pub fn read_file(&self, name: &str) -> Result<Vec<u8>, RootError> {
        self.check("readfile", name)?;
        self.root.read_file(name)
    }

    /// `ReadLinkFS.ReadLink`.
    pub fn read_link(&self, name: &str) -> Result<String, RootError> {
        self.check("readlink", name)?;
        self.root.readlink(name)
    }

    /// `StatFS.Stat`.
    pub fn stat(&self, name: &str) -> Result<FileInfo, RootError> {
        self.check("stat", name)?;
        self.root.stat(name)
    }

    /// `ReadLinkFS.Lstat`.
    pub fn lstat(&self, name: &str) -> Result<FileInfo, RootError> {
        self.check("lstat", name)?;
        self.root.lstat(name)
    }
}
