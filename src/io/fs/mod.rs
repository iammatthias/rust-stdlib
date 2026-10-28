//! Go's `io/fs`: a read-only file system abstraction.
//!
//! Go checks optional interfaces with type assertions (`fsys.(GlobFS)`);
//! Rust trait objects cannot be downcast, so [`FS`] carries `as_*` hooks that
//! an implementation overrides to advertise the extension traits it
//! implements ([`GlobFS`], [`ReadDirFS`], [`ReadFileFS`], [`StatFS`],
//! [`SubFS`], [`ReadLinkFS`]). The package functions ([`glob`], [`read_dir`],
//! ...) consult those hooks exactly where Go consults the assertions.
//!
//! Errors are `io::Error`s. A [`PathError`] is the payload of the `io::Error`
//! (use [`path_error`] to get it back) and its kind is that of the inner
//! error, so `err.kind() == NotFound` and `Error::NotExist.is(&err)` both
//! work on errors from `std::fs`, [`DirFS`] and [`MapFS`].

use crate::time::Time;
use std::any::Any;
use std::fmt;
use std::io::{self, Read};

pub(crate) mod dirfs;
mod mapfs;

pub use dirfs::DirFS;
pub use mapfs::{MapFS, MapFile};

/// Go's `fs` sentinel errors (`ErrInvalid`, ..., `SkipDir`, `SkipAll`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// `fs.ErrInvalid`
    Invalid,
    /// `fs.ErrPermission`
    Permission,
    /// `fs.ErrExist`
    Exist,
    /// `fs.ErrNotExist`
    NotExist,
    /// `fs.ErrClosed`
    Closed,
    /// `fs.SkipDir`
    SkipDir,
    /// `fs.SkipAll`
    SkipAll,
}

/// `fs.ErrInvalid`.
pub const ERR_INVALID: Error = Error::Invalid;
/// `fs.ErrPermission`.
pub const ERR_PERMISSION: Error = Error::Permission;
/// `fs.ErrExist`.
pub const ERR_EXIST: Error = Error::Exist;
/// `fs.ErrNotExist`.
pub const ERR_NOT_EXIST: Error = Error::NotExist;
/// `fs.ErrClosed`.
pub const ERR_CLOSED: Error = Error::Closed;
/// `fs.SkipDir`: returned from a walk function to skip a directory.
pub const SKIP_DIR: Error = Error::SkipDir;
/// `fs.SkipAll`: returned from a walk function to stop the walk.
pub const SKIP_ALL: Error = Error::SkipAll;

impl Error {
    fn kind(self) -> io::ErrorKind {
        match self {
            Error::Invalid => io::ErrorKind::InvalidInput,
            Error::Permission => io::ErrorKind::PermissionDenied,
            Error::Exist => io::ErrorKind::AlreadyExists,
            Error::NotExist => io::ErrorKind::NotFound,
            Error::Closed | Error::SkipDir | Error::SkipAll => io::ErrorKind::Other,
        }
    }

    /// Reports whether `err` is, or wraps, this error (`errors.Is`). The
    /// four OS errors also match by `io::ErrorKind`, so errors from `std::fs`
    /// satisfy them.
    pub fn is(self, err: &io::Error) -> bool {
        if crate::io::chain_has(err, &self) {
            return true;
        }
        // The four OS errors also match by kind, at any depth.
        if matches!(self, Error::Closed | Error::SkipDir | Error::SkipAll) {
            return false;
        }
        // Go's `ENOTEMPTY.Is(ErrExist)` is true as well.
        let matches_kind = |k: io::ErrorKind| {
            k == self.kind() || (self == Error::Exist && k == io::ErrorKind::DirectoryNotEmpty)
        };
        if matches_kind(err.kind()) {
            return true;
        }
        let mut cur: Option<&(dyn std::error::Error + 'static)> = err.get_ref().map(|e| e as _);
        while let Some(e) = cur {
            if e.downcast_ref::<io::Error>()
                .is_some_and(|e| matches_kind(e.kind()))
            {
                return true;
            }
            cur = e.source();
        }
        false
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Invalid => "invalid argument",
            Error::Permission => "permission denied",
            Error::Exist => "file already exists",
            Error::NotExist => "file does not exist",
            Error::Closed => "file already closed",
            Error::SkipDir => "skip this directory",
            Error::SkipAll => "skip everything and stop the walk",
        })
    }
}

impl std::error::Error for Error {}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        io::Error::new(e.kind(), e)
    }
}

/// An error from a file system operation (`fs.PathError`).
#[derive(Debug)]
pub struct PathError {
    /// The operation (`PathError.Op`).
    pub op: String,
    /// The path (`PathError.Path`).
    pub path: String,
    /// The underlying error (`PathError.Err`).
    pub err: io::Error,
}

impl PathError {
    /// Reports whether the underlying error is a timeout (`PathError.Timeout`).
    pub fn timeout(&self) -> bool {
        self.err.kind() == io::ErrorKind::TimedOut
    }

    /// The underlying error (`PathError.Unwrap`).
    pub fn unwrap(&self) -> &io::Error {
        &self.err
    }
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.op, self.path, self.err)
    }
}

impl std::error::Error for PathError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.err)
    }
}

impl From<PathError> for io::Error {
    fn from(e: PathError) -> io::Error {
        io::Error::new(e.err.kind(), e)
    }
}

impl PathError {
    /// A `PathError` for `op` on `path` caused by `err`.
    pub fn new(op: &str, path: &str, err: impl Into<io::Error>) -> PathError {
        PathError {
            op: op.to_string(),
            path: path.to_string(),
            err: err.into(),
        }
    }
}

/// The error of [`read_dir`] and the `ReadDir` methods: the failure plus the
/// entries read before it (Go returns both).
#[derive(Debug)]
pub struct ReadDirError {
    list: Vec<Box<dyn DirEntry>>,
    source: io::Error,
}

impl ReadDirError {
    /// An error after the entries in `list` were read.
    pub fn new(list: Vec<Box<dyn DirEntry>>, source: io::Error) -> Self {
        ReadDirError { list, source }
    }

    /// The entries read before the failure.
    pub fn list(&self) -> &[Box<dyn DirEntry>] {
        &self.list
    }

    /// Consumes the error and returns the entries read before the failure.
    pub fn into_list(self) -> Vec<Box<dyn DirEntry>> {
        self.list
    }

    /// The underlying error.
    pub fn source(&self) -> &io::Error {
        &self.source
    }

    /// Consumes the error and returns the underlying one.
    pub fn into_source(self) -> io::Error {
        self.source
    }

    /// Consumes the error and returns the entries and the underlying error.
    pub fn into_parts(self) -> (Vec<Box<dyn DirEntry>>, io::Error) {
        (self.list, self.source)
    }
}

impl fmt::Display for ReadDirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.source, f)
    }
}

impl std::error::Error for ReadDirError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl From<io::Error> for ReadDirError {
    fn from(source: io::Error) -> Self {
        ReadDirError::new(Vec::new(), source)
    }
}

impl From<PathError> for ReadDirError {
    fn from(e: PathError) -> Self {
        io::Error::from(e).into()
    }
}

impl From<ReadDirError> for io::Error {
    fn from(e: ReadDirError) -> io::Error {
        e.source
    }
}

/// Returns the [`PathError`] inside `err`, if any (`errors.As(err, &*PathError)`).
pub fn path_error(err: &io::Error) -> Option<&PathError> {
    err.get_ref().and_then(|e| e.downcast_ref::<PathError>())
}

/// File mode bits (`fs.FileMode`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileMode(pub u32);

/// `fs.ModeDir`: is a directory.
pub const MODE_DIR: FileMode = FileMode(1 << 31);
/// `fs.ModeAppend`: append-only.
pub const MODE_APPEND: FileMode = FileMode(1 << 30);
/// `fs.ModeExclusive`: exclusive use.
pub const MODE_EXCLUSIVE: FileMode = FileMode(1 << 29);
/// `fs.ModeTemporary`: temporary file (Plan 9 only).
pub const MODE_TEMPORARY: FileMode = FileMode(1 << 28);
/// `fs.ModeSymlink`: symbolic link.
pub const MODE_SYMLINK: FileMode = FileMode(1 << 27);
/// `fs.ModeDevice`: device file.
pub const MODE_DEVICE: FileMode = FileMode(1 << 26);
/// `fs.ModeNamedPipe`: named pipe (FIFO).
pub const MODE_NAMED_PIPE: FileMode = FileMode(1 << 25);
/// `fs.ModeSocket`: Unix domain socket.
pub const MODE_SOCKET: FileMode = FileMode(1 << 24);
/// `fs.ModeSetuid`: setuid.
pub const MODE_SETUID: FileMode = FileMode(1 << 23);
/// `fs.ModeSetgid`: setgid.
pub const MODE_SETGID: FileMode = FileMode(1 << 22);
/// `fs.ModeCharDevice`: Unix character device, when `MODE_DEVICE` is set.
pub const MODE_CHAR_DEVICE: FileMode = FileMode(1 << 21);
/// `fs.ModeSticky`: sticky.
pub const MODE_STICKY: FileMode = FileMode(1 << 20);
/// `fs.ModeIrregular`: non-regular file; nothing else is known about it.
pub const MODE_IRREGULAR: FileMode = FileMode(1 << 19);
/// `fs.ModeType`: mask for the type bits.
pub const MODE_TYPE: FileMode = FileMode(
    MODE_DIR.0
        | MODE_SYMLINK.0
        | MODE_NAMED_PIPE.0
        | MODE_SOCKET.0
        | MODE_DEVICE.0
        | MODE_CHAR_DEVICE.0
        | MODE_IRREGULAR.0,
);
/// `fs.ModePerm`: Unix permission bits.
pub const MODE_PERM: FileMode = FileMode(0o777);

impl FileMode {
    /// Reports whether the mode describes a directory (`FileMode.IsDir`).
    pub fn is_dir(self) -> bool {
        self.0 & MODE_DIR.0 != 0
    }

    /// Reports whether the mode describes a regular file (`FileMode.IsRegular`).
    pub fn is_regular(self) -> bool {
        self.0 & MODE_TYPE.0 == 0
    }

    /// Returns the Unix permission bits (`FileMode.Perm`).
    pub fn perm(self) -> FileMode {
        FileMode(self.0 & MODE_PERM.0)
    }

    /// Returns the type bits (`FileMode.Type`).
    pub fn file_type(self) -> FileMode {
        FileMode(self.0 & MODE_TYPE.0)
    }
}

impl std::ops::BitOr for FileMode {
    type Output = FileMode;
    fn bitor(self, o: FileMode) -> FileMode {
        FileMode(self.0 | o.0)
    }
}

impl std::ops::BitAnd for FileMode {
    type Output = FileMode;
    fn bitand(self, o: FileMode) -> FileMode {
        FileMode(self.0 & o.0)
    }
}

impl std::ops::Not for FileMode {
    type Output = FileMode;
    fn not(self) -> FileMode {
        FileMode(!self.0)
    }
}

impl fmt::Display for FileMode {
    /// `FileMode.String`: `dalTLDpSugct?` flags followed by `rwxrwxrwx`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const STR: &[u8] = b"dalTLDpSugct?";
        let mut buf = String::new();
        for (i, c) in STR.iter().enumerate() {
            if self.0 & (1 << (31 - i)) != 0 {
                buf.push(*c as char);
            }
        }
        if buf.is_empty() {
            buf.push('-');
        }
        for (i, c) in "rwxrwxrwx".chars().enumerate() {
            buf.push(if self.0 & (1 << (8 - i)) != 0 { c } else { '-' });
        }
        f.write_str(&buf)
    }
}

/// Information about a file (`fs.FileInfo`).
pub trait FileInfo: fmt::Debug {
    /// Base name of the file.
    fn name(&self) -> &str;
    /// Length in bytes for regular files; system-dependent for others.
    fn size(&self) -> i64;
    /// File mode bits.
    fn mode(&self) -> FileMode;
    /// Modification time.
    fn mod_time(&self) -> Time;
    /// Abbreviation for `mode().is_dir()`.
    fn is_dir(&self) -> bool {
        self.mode().is_dir()
    }
    /// Underlying data source, if any (`FileInfo.Sys`).
    fn sys(&self) -> Option<&dyn Any> {
        None
    }
}

/// An entry read from a directory (`fs.DirEntry`).
pub trait DirEntry: fmt::Debug {
    /// The name of the file (or subdirectory) the entry describes.
    fn name(&self) -> &str;
    /// Reports whether the entry describes a directory.
    fn is_dir(&self) -> bool;
    /// The type bits for the entry (`DirEntry.Type`).
    fn file_type(&self) -> FileMode;
    /// The `FileInfo` for the entry.
    fn info(&self) -> io::Result<Box<dyn FileInfo>>;
}

/// An open file (`fs.File`). `Read` is `std::io::Read`.
pub trait File: Read + fmt::Debug {
    /// Returns the file's `FileInfo` (`File.Stat`).
    fn stat(&self) -> io::Result<Box<dyn FileInfo>>;
    /// Closes the file (`File.Close`).
    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
    /// Go's `file.(ReadDirFile)` assertion: `Some` for directories.
    fn as_read_dir_file(&mut self) -> Option<&mut dyn ReadDirFile> {
        None
    }
    /// Go's `file.(io.Seeker)` assertion: `Some` if the file can seek.
    fn as_seek(&mut self) -> Option<&mut dyn std::io::Seek> {
        None
    }
    /// Go's `file.(io.ReaderAt)` assertion: `Some` if the file supports
    /// positional reads.
    fn as_reader_at(&self) -> Option<&dyn crate::io::ReadAt> {
        None
    }
}

/// A directory opened for reading (`fs.ReadDirFile`).
pub trait ReadDirFile: File {
    /// Reads up to `n` entries in directory order (`ReadDirFile.ReadDir`).
    /// With `n <= 0` it returns all remaining entries; with `n > 0` an
    /// `io.EOF` error signals the end.
    /// A failure part-way carries the entries read so far
    /// ([`ReadDirError::list`]), as Go returns both.
    fn read_dir(&mut self, n: i32) -> Result<Vec<Box<dyn DirEntry>>, ReadDirError>;
}

/// A file system (`fs.FS`).
///
/// The `as_*` methods are Go's optional-interface assertions: override the
/// ones for the extension traits the type implements, returning `Some(self)`.
#[allow(clippy::upper_case_acronyms)]
pub trait FS: fmt::Debug {
    /// Opens the named file (`FS.Open`).
    fn open(&self, name: &str) -> io::Result<Box<dyn File>>;
    /// `fsys.(GlobFS)`
    fn as_glob_fs(&self) -> Option<&dyn GlobFS> {
        None
    }
    /// `fsys.(ReadDirFS)`
    fn as_read_dir_fs(&self) -> Option<&dyn ReadDirFS> {
        None
    }
    /// `fsys.(ReadFileFS)`
    fn as_read_file_fs(&self) -> Option<&dyn ReadFileFS> {
        None
    }
    /// `fsys.(StatFS)`
    fn as_stat_fs(&self) -> Option<&dyn StatFS> {
        None
    }
    /// `fsys.(SubFS)`
    fn as_sub_fs(&self) -> Option<&dyn SubFS> {
        None
    }
    /// `fsys.(ReadLinkFS)`
    fn as_read_link_fs(&self) -> Option<&dyn ReadLinkFS> {
        None
    }
}

impl<T: FS + ?Sized> FS for &T {
    fn open(&self, name: &str) -> io::Result<Box<dyn File>> {
        (**self).open(name)
    }
    fn as_glob_fs(&self) -> Option<&dyn GlobFS> {
        (**self).as_glob_fs()
    }
    fn as_read_dir_fs(&self) -> Option<&dyn ReadDirFS> {
        (**self).as_read_dir_fs()
    }
    fn as_read_file_fs(&self) -> Option<&dyn ReadFileFS> {
        (**self).as_read_file_fs()
    }
    fn as_stat_fs(&self) -> Option<&dyn StatFS> {
        (**self).as_stat_fs()
    }
    fn as_sub_fs(&self) -> Option<&dyn SubFS> {
        (**self).as_sub_fs()
    }
    fn as_read_link_fs(&self) -> Option<&dyn ReadLinkFS> {
        (**self).as_read_link_fs()
    }
}

/// A file system with a `Glob` method (`fs.GlobFS`).
pub trait GlobFS: FS {
    /// Returns the names of all files matching `pattern` (`GlobFS.Glob`).
    fn glob(&self, pattern: &str) -> io::Result<Vec<String>>;
}

/// A file system with a `ReadDir` method (`fs.ReadDirFS`).
pub trait ReadDirFS: FS {
    /// Reads the named directory, sorted by filename (`ReadDirFS.ReadDir`).
    fn read_dir(&self, name: &str) -> Result<Vec<Box<dyn DirEntry>>, ReadDirError>;
}

/// A file system with a `ReadFile` method (`fs.ReadFileFS`).
pub trait ReadFileFS: FS {
    /// Reads the named file and returns its contents (`ReadFileFS.ReadFile`).
    fn read_file(&self, name: &str) -> io::Result<Vec<u8>>;
}

/// A file system with a `Stat` method (`fs.StatFS`).
pub trait StatFS: FS {
    /// Returns a `FileInfo` describing the file (`StatFS.Stat`).
    fn stat(&self, name: &str) -> io::Result<Box<dyn FileInfo>>;
}

/// A file system with a `Sub` method (`fs.SubFS`).
pub trait SubFS: FS {
    /// Returns an `FS` corresponding to the subtree rooted at `dir` (`SubFS.Sub`).
    fn sub(&self, dir: &str) -> io::Result<Box<dyn FS + '_>>;
}

/// A file system that can read symbolic links (`fs.ReadLinkFS`).
pub trait ReadLinkFS: FS {
    /// Returns the destination of the named symbolic link (`ReadLinkFS.ReadLink`).
    fn read_link(&self, name: &str) -> io::Result<String>;
    /// Like `stat` but does not follow a final symbolic link (`ReadLinkFS.Lstat`).
    fn lstat(&self, name: &str) -> io::Result<Box<dyn FileInfo>>;
}

/// Reports whether `name` is a valid path for `FS::open` (`fs.ValidPath`).
/// (Rust strings are always valid UTF-8.)
pub fn valid_path(name: &str) -> bool {
    if name == "." {
        return true;
    }
    name.split('/')
        .all(|elem| !(elem.is_empty() || elem == "." || elem == ".."))
}

/// Opens `name` in `fsys` and returns its info (`fs.Stat`).
pub fn stat(fsys: &dyn FS, name: &str) -> io::Result<Box<dyn FileInfo>> {
    if let Some(s) = fsys.as_stat_fs() {
        return s.stat(name);
    }
    let mut file = fsys.open(name)?;
    let info = file.stat();
    let _ = file.close();
    info
}

/// Reads the named directory, sorted by filename (`fs.ReadDir`).
///
/// When reading fails part-way the error carries the entries read so far,
/// sorted ([`ReadDirError::list`]).
pub fn read_dir(fsys: &dyn FS, name: &str) -> Result<Vec<Box<dyn DirEntry>>, ReadDirError> {
    if let Some(r) = fsys.as_read_dir_fs() {
        return r.read_dir(name);
    }
    let mut file = fsys.open(name)?;
    let result = match file.as_read_dir_file() {
        None => Err(PathError::new("readdir", name, io::Error::other("not implemented")).into()),
        Some(dir) => {
            let sort = |list: &mut Vec<Box<dyn DirEntry>>| {
                list.sort_by(|a, b| a.name().cmp(b.name()));
            };
            match dir.read_dir(-1) {
                Ok(mut list) => {
                    sort(&mut list);
                    Ok(list)
                }
                Err(mut e) => {
                    sort(&mut e.list);
                    Err(e)
                }
            }
        }
    };
    let _ = file.close();
    result
}

/// Reads the named file from `fsys` (`fs.ReadFile`).
pub fn read_file(fsys: &dyn FS, name: &str) -> io::Result<Vec<u8>> {
    if let Some(r) = fsys.as_read_file_fs() {
        return r.read_file(name);
    }
    let mut file = fsys.open(name)?;
    let size = file
        .stat()
        .ok()
        .and_then(|i| usize::try_from(i.size()).ok())
        .unwrap_or(0);
    let mut data = Vec::with_capacity(size.saturating_add(1));
    let result = file.read_to_end(&mut data).map(|_| data);
    let _ = file.close();
    result
}

/// Like [`stat`] but does not follow symbolic links when `fsys` is a
/// [`ReadLinkFS`] (`fs.Lstat`).
pub fn lstat(fsys: &dyn FS, name: &str) -> io::Result<Box<dyn FileInfo>> {
    match fsys.as_read_link_fs() {
        Some(s) => s.lstat(name),
        None => stat(fsys, name),
    }
}

/// Returns the destination of the symbolic link `name` (`fs.ReadLink`).
pub fn read_link(fsys: &dyn FS, name: &str) -> io::Result<String> {
    match fsys.as_read_link_fs() {
        Some(s) => s.read_link(name),
        None => Err(PathError::new("readlink", name, Error::Invalid).into()),
    }
}

fn bad_pattern() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, crate::path::BadPattern)
}

fn has_meta(path: &str) -> bool {
    path.bytes()
        .any(|c| matches!(c, b'*' | b'?' | b'[' | b'\\'))
}

/// Returns the names of all files matching `pattern`, or none if nothing
/// matches (`fs.Glob`). The pattern syntax is that of `path::matches`.
pub fn glob(fsys: &dyn FS, pattern: &str) -> io::Result<Vec<String>> {
    glob_with_limit(fsys, pattern, 0)
}

fn glob_with_limit(fsys: &dyn FS, pattern: &str, depth: usize) -> io::Result<Vec<String>> {
    const PATH_SEPARATORS_LIMIT: usize = 10000;
    if let Some(g) = fsys.as_glob_fs() {
        if depth <= PATH_SEPARATORS_LIMIT {
            return g.glob(pattern);
        }
    }
    // Go recurses once per directory element that has a wildcard (up to the
    // limit above). Walk down iteratively, remembering the file pattern of
    // each level, then resolve the levels from the innermost outwards.
    let mut files: Vec<&str> = Vec::new();
    let mut pattern = pattern;
    let mut depth = depth;
    let mut m = loop {
        if depth > PATH_SEPARATORS_LIMIT {
            return Err(bad_pattern());
        }
        crate::path::matches(pattern, "").map_err(|_| bad_pattern())?;
        if !has_meta(pattern) {
            break if stat(fsys, pattern).is_err() {
                Vec::new()
            } else {
                vec![pattern.to_string()]
            };
        }
        let (dir, file) = crate::path::split(pattern);
        let dir = if dir.is_empty() {
            "."
        } else {
            &dir[..dir.len() - 1]
        };
        if !has_meta(dir) {
            break glob_dir(fsys, dir, file, Vec::new())?;
        }
        if dir == pattern {
            return Err(bad_pattern());
        }
        files.push(file);
        pattern = dir;
        depth += 1;
    };
    while let Some(file) = files.pop() {
        let mut matches = Vec::new();
        for d in m {
            matches = glob_dir(fsys, &d, file, matches)?;
        }
        m = matches;
    }
    Ok(m)
}

fn glob_dir(
    fsys: &dyn FS,
    dir: &str,
    pattern: &str,
    mut matches: Vec<String>,
) -> io::Result<Vec<String>> {
    let Ok(infos) = read_dir(fsys, dir) else {
        return Ok(matches); // ignore I/O error
    };
    for info in infos {
        let n = info.name();
        match crate::path::matches(pattern, n) {
            Err(_) => return Err(bad_pattern()),
            Ok(true) => matches.push(crate::path::join(&[dir, n])),
            Ok(false) => {}
        }
    }
    Ok(matches)
}

/// Returns an `FS` for the subtree of `fsys` rooted at `dir` (`fs.Sub`).
pub fn sub<'a>(fsys: &'a dyn FS, dir: &str) -> io::Result<Box<dyn FS + 'a>> {
    if !valid_path(dir) {
        return Err(PathError::new("sub", dir, Error::Invalid).into());
    }
    if dir == "." {
        return Ok(Box::new(fsys));
    }
    if let Some(s) = fsys.as_sub_fs() {
        return s.sub(dir);
    }
    Ok(Box::new(SubTree {
        fsys: Box::new(fsys),
        dir: dir.to_string(),
    }))
}

/// [`sub`] for an owned inner file system that has no `Sub` method.
pub(crate) fn sub_owned<'a>(fsys: Box<dyn FS + 'a>, dir: &str) -> io::Result<Box<dyn FS + 'a>> {
    if !valid_path(dir) {
        return Err(PathError::new("sub", dir, Error::Invalid).into());
    }
    if dir == "." {
        return Ok(fsys);
    }
    Ok(Box::new(SubTree {
        fsys,
        dir: dir.to_string(),
    }))
}

#[derive(Debug)]
struct SubTree<'a> {
    fsys: Box<dyn FS + 'a>,
    dir: String,
}

impl SubTree<'_> {
    fn full_name(&self, op: &str, name: &str) -> io::Result<String> {
        if !valid_path(name) {
            return Err(PathError::new(op, name, Error::Invalid).into());
        }
        Ok(crate::path::join(&[self.dir.as_str(), name]))
    }

    fn shorten(&self, name: &str) -> Option<String> {
        if name == self.dir {
            return Some(".".to_string());
        }
        if name.len() >= self.dir.len() + 2
            && name.as_bytes()[self.dir.len()] == b'/'
            && name.starts_with(&self.dir)
        {
            return Some(name[self.dir.len() + 1..].to_string());
        }
        None
    }

    fn fix_err(&self, err: io::Error) -> io::Error {
        let Some(pe) = path_error(&err) else {
            return err;
        };
        let Some(short) = self.shorten(&pe.path) else {
            return err;
        };
        match err.into_inner().map(|b| b.downcast::<PathError>()) {
            Some(Ok(mut pe)) => {
                pe.path = short;
                (*pe).into()
            }
            _ => unreachable!("path_error found a PathError"),
        }
    }
}

impl FS for SubTree<'_> {
    fn open(&self, name: &str) -> io::Result<Box<dyn File>> {
        let full = self.full_name("open", name)?;
        self.fsys.open(&full).map_err(|e| self.fix_err(e))
    }
    fn as_glob_fs(&self) -> Option<&dyn GlobFS> {
        Some(self)
    }
    fn as_read_dir_fs(&self) -> Option<&dyn ReadDirFS> {
        Some(self)
    }
    fn as_read_file_fs(&self) -> Option<&dyn ReadFileFS> {
        Some(self)
    }
    fn as_sub_fs(&self) -> Option<&dyn SubFS> {
        Some(self)
    }
    fn as_read_link_fs(&self) -> Option<&dyn ReadLinkFS> {
        Some(self)
    }
}

impl ReadDirFS for SubTree<'_> {
    fn read_dir(&self, name: &str) -> Result<Vec<Box<dyn DirEntry>>, ReadDirError> {
        let full = self.full_name("read", name)?;
        read_dir(self.fsys.as_ref(), &full).map_err(|e| {
            let (list, source) = e.into_parts();
            ReadDirError::new(list, self.fix_err(source))
        })
    }
}

impl ReadFileFS for SubTree<'_> {
    fn read_file(&self, name: &str) -> io::Result<Vec<u8>> {
        let full = self.full_name("read", name)?;
        read_file(self.fsys.as_ref(), &full).map_err(|e| self.fix_err(e))
    }
}

impl ReadLinkFS for SubTree<'_> {
    fn read_link(&self, name: &str) -> io::Result<String> {
        let full = self.full_name("readlink", name)?;
        read_link(self.fsys.as_ref(), &full).map_err(|e| self.fix_err(e))
    }
    fn lstat(&self, name: &str) -> io::Result<Box<dyn FileInfo>> {
        let full = self.full_name("lstat", name)?;
        lstat(self.fsys.as_ref(), &full).map_err(|e| self.fix_err(e))
    }
}

impl GlobFS for SubTree<'_> {
    fn glob(&self, pattern: &str) -> io::Result<Vec<String>> {
        crate::path::matches(pattern, "").map_err(|_| bad_pattern())?;
        if pattern == "." {
            return Ok(vec![".".to_string()]);
        }
        let full = format!("{}/{}", self.dir, pattern);
        let list = glob(self.fsys.as_ref(), &full).map_err(|e| self.fix_err(e))?;
        list.into_iter()
            .map(|name| {
                self.shorten(&name).ok_or_else(|| {
                    io::Error::other(format!(
                        "invalid result from inner fsys Glob: {name} not in {}",
                        self.dir
                    ))
                })
            })
            .collect()
    }
}

impl SubFS for SubTree<'_> {
    fn sub(&self, dir: &str) -> io::Result<Box<dyn FS + '_>> {
        if dir == "." {
            return Ok(Box::new(SubTree {
                fsys: Box::new(&*self.fsys),
                dir: self.dir.clone(),
            }));
        }
        let full = self.full_name("sub", dir)?;
        Ok(Box::new(SubTree {
            fsys: Box::new(&*self.fsys),
            dir: full,
        }))
    }
}

#[derive(Debug)]
struct DirInfo(Box<dyn FileInfo>);

impl DirEntry for DirInfo {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn is_dir(&self) -> bool {
        self.0.is_dir()
    }
    fn file_type(&self) -> FileMode {
        self.0.mode().file_type()
    }
    fn info(&self) -> io::Result<Box<dyn FileInfo>> {
        Ok(Box::new(InfoRef(
            self.0.name().to_string(),
            self.snapshot(),
        )))
    }
}

impl DirInfo {
    fn snapshot(&self) -> (i64, FileMode, Time) {
        (self.0.size(), self.0.mode(), self.0.mod_time())
    }
}

/// A plain-data `FileInfo` (the snapshot `DirEntry::info` returns here).
#[derive(Debug)]
struct InfoRef(String, (i64, FileMode, Time));

impl FileInfo for InfoRef {
    fn name(&self) -> &str {
        &self.0
    }
    fn size(&self) -> i64 {
        self.1 .0
    }
    fn mode(&self) -> FileMode {
        self.1 .1
    }
    fn mod_time(&self) -> Time {
        self.1 .2.clone()
    }
}

/// Returns a `DirEntry` that reports information from `info`
/// (`fs.FileInfoToDirEntry`); `None` gives `None`.
pub fn file_info_to_dir_entry(info: Option<Box<dyn FileInfo>>) -> Option<Box<dyn DirEntry>> {
    info.map(|i| Box::new(DirInfo(i)) as Box<dyn DirEntry>)
}

/// Formats `info` for human analysis (`fs.FormatFileInfo`).
pub fn format_file_info(info: &dyn FileInfo) -> String {
    let mut s = info.mode().to_string();
    s.push(' ');
    s.push_str(&info.size().to_string());
    s.push(' ');
    s.push_str(&info.mod_time().format(crate::time::DATE_TIME));
    s.push(' ');
    s.push_str(info.name());
    if info.is_dir() {
        s.push('/');
    }
    s
}

/// Formats `dir` for human analysis (`fs.FormatDirEntry`).
pub fn format_dir_entry(dir: &dyn DirEntry) -> String {
    let mode = dir.file_type().to_string();
    let mut s = mode[..mode.len() - 9].to_string();
    s.push(' ');
    s.push_str(dir.name());
    if dir.is_dir() {
        s.push('/');
    }
    s
}

/// The type of the function called by [`walk_dir`] (`fs.WalkDirFunc`).
///
/// Arguments are the path, the entry (`None` when the root could not be
/// stat'ed) and the error that prevented reading, if any. Return
/// `Err(SKIP_DIR.into())`, `Err(SKIP_ALL.into())` or another error to alter
/// or end the walk.
pub trait WalkDirFunc:
    FnMut(&str, Option<&dyn DirEntry>, Option<io::Error>) -> io::Result<()>
{
}
impl<F: FnMut(&str, Option<&dyn DirEntry>, Option<io::Error>) -> io::Result<()>> WalkDirFunc for F {}

fn walk_dir_inner(
    fsys: &dyn FS,
    name: &str,
    d: &dyn DirEntry,
    f: &mut dyn WalkDirFunc,
) -> io::Result<()> {
    if let Err(err) = f(name, Some(d), None) {
        if Error::SkipDir.is(&err) && d.is_dir() {
            return Ok(());
        }
        return Err(err);
    }
    if !d.is_dir() {
        return Ok(());
    }
    let dirs = match read_dir(fsys, name) {
        Ok(dirs) => dirs,
        Err(err) => {
            // Go keeps the entries read before the failure and walks them
            // when the callback accepts the error.
            let (list, source) = err.into_parts();
            if let Err(err) = f(name, Some(d), Some(source)) {
                if Error::SkipDir.is(&err) && d.is_dir() {
                    return Ok(());
                }
                return Err(err);
            }
            list
        }
    };
    for d1 in &dirs {
        let name1 = crate::path::join(&[name, d1.name()]);
        if let Err(err) = walk_dir_inner(fsys, &name1, d1.as_ref(), f) {
            if Error::SkipDir.is(&err) {
                break;
            }
            return Err(err);
        }
    }
    Ok(())
}

/// Walks the file tree rooted at `root`, calling `f` for each file or
/// directory in lexical order (`fs.WalkDir`).
pub fn walk_dir<F: WalkDirFunc>(fsys: &dyn FS, root: &str, mut f: F) -> io::Result<()> {
    let result = match stat(fsys, root) {
        Err(err) => f(root, None, Some(err)),
        Ok(info) => {
            let d = file_info_to_dir_entry(Some(info)).expect("entry for Some(info)");
            walk_dir_inner(fsys, root, d.as_ref(), &mut f)
        }
    };
    match result {
        Err(e) if Error::SkipDir.is(&e) || Error::SkipAll.is(&e) => Ok(()),
        other => other,
    }
}
