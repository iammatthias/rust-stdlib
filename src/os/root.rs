//! `os.Root`: file system access confined to a directory tree.
//!
//! Go implements `Root` with `openat(2)` relative to a directory descriptor.
//! `std` has no `openat`, so this implementation follows Go's algorithm
//! (`doInRoot`) over paths: every name is resolved one component at a time,
//! `..` may not climb above the root, absolute names and absolute
//! symbolic-link targets escape (`path escapes from parent`), and at most
//! eight symbolic links are followed. The directory that is the parent of
//! the final component is a path whose components were all checked, but the
//! final operation is performed by path, so a concurrent attacker who can
//! rename directories inside the root can still win a time-of-check to
//! time-of-use race. Do not rely on it against hostile concurrent
//! modification of the tree.

use super::error::{errno, errno_of, from_errno, link_err, os_error, path_err, unwrap_layers};
use super::file::{
    open_std, File, O_APPEND, O_CREATE, O_EXCL, O_NOFOLLOW, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY,
};
use super::fsops;
use crate::io::fs::dirfs::StdInfo;
use crate::io::fs::{
    self, DirEntry, FileInfo, FileMode, PathError, ReadDirError, ReadDirFS, ReadFileFS, ReadLinkFS,
    StatFS, FS,
};
use crate::time::Time;
use std::fs as stdfs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_SYMLINKS: usize = 8;
/// Do not check the terminal slash (Go: `doInRootNoHandleTerminalSlash`).
const NO_HANDLE_TERMINAL_SLASH: u32 = 1;
/// The final component may not exist yet (`doInRootCreatingDirectory`).
const CREATING_DIRECTORY: u32 = 2;

fn escapes() -> io::Error {
    io::Error::other("path escapes from parent")
}

/// Go's `errSymlink` or an ordinary failure.
enum RErr {
    Symlink(String),
    Err(io::Error),
}

impl From<io::Error> for RErr {
    fn from(e: io::Error) -> RErr {
        RErr::Err(os_error(e))
    }
}

type RR<T> = Result<T, RErr>;
type OpenDirFn<'a> = dyn Fn(&Path, &str) -> RR<PathBuf> + 'a;

fn is_errno(err: &io::Error, code: i32) -> bool {
    errno_of(err).is_some_and(|n| n.0 == code)
}

/// A directory confined file system view (`os.Root`).
#[derive(Debug)]
pub struct Root {
    name: String,
    base: PathBuf,
    closed: AtomicBool,
}

/// Opens the directory `name` for use as a [`Root`] (`os.OpenRoot`).
pub fn open_root(name: &str) -> io::Result<Root> {
    let meta = stdfs::File::open(name)
        .and_then(|f| f.metadata())
        .map_err(|e| path_err("open", name, e))?;
    if !meta.is_dir() {
        return Err(PathError::new("open", name, io::Error::other("not a directory")).into());
    }
    let base = stdfs::canonicalize(name).unwrap_or_else(|_| PathBuf::from(name));
    Ok(Root {
        name: name.to_string(),
        base,
        closed: AtomicBool::new(false),
    })
}

/// Opens the file `name` in the directory `dir` (`os.OpenInRoot`).
pub fn open_in_root(dir: &str, name: &str) -> io::Result<File> {
    let r = open_root(dir)?;
    r.open(name)
}

fn join_name(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// Go's `splitPathInRoot`: the elements of `s` with `prefix` and `suffix`
/// attached, and whether `s` ends in a slash.
fn split_path(
    s: &str,
    prefix: &[String],
    suffix: &[String],
) -> Result<(Vec<String>, bool), io::Error> {
    if s.is_empty() {
        return Err(io::Error::other("empty path"));
    }
    if s.starts_with('/') {
        return Err(escapes());
    }
    let mut parts: Vec<String> = prefix.to_vec();
    let ends_in_slash = s.ends_with('/');
    let elems: Vec<&str> = s.split('/').filter(|p| !p.is_empty()).collect();
    for (k, e) in elems.iter().enumerate() {
        // A "." followed by more elements is dropped; a final one stays.
        if *e == "." && k + 1 < elems.len() {
            continue;
        }
        parts.push((*e).to_string());
    }
    if !suffix.is_empty() && parts.last().is_some_and(|p| p == ".") {
        parts.pop();
    }
    parts.extend(suffix.iter().cloned());
    if parts.is_empty() {
        parts.push(".".to_string());
    }
    Ok((parts, ends_in_slash))
}

/// The target of the symbolic link `parent/name`, if it is one.
fn symlink_target(parent: &Path, name: &str) -> Option<String> {
    stdfs::read_link(parent.join(name))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// `rootOpenDir`: the directory `parent/name`, not following a link.
fn open_dir_at(parent: &Path, name: &str) -> RR<PathBuf> {
    let full = parent.join(name);
    let meta = stdfs::symlink_metadata(&full).map_err(os_error)?;
    if meta.file_type().is_symlink() {
        return Err(RErr::Symlink(
            symlink_target(parent, name).unwrap_or_default(),
        ));
    }
    if !meta.is_dir() {
        return Err(from_errno(errno::ENOTDIR).into());
    }
    // Opening the directory checks that it can be searched, as `openat` does.
    stdfs::File::open(&full).map_err(os_error)?;
    Ok(full)
}

impl Root {
    /// The name of the directory presented to [`open_root`] (`Root.Name`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Closes the root (`Root.Close`). Later operations fail with
    /// `ErrClosed`.
    pub fn close(&self) -> io::Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Go's `doInRoot`: resolves `name` and calls `f` with the directory
    /// that holds the final component, its name and whether the name ended
    /// in a slash.
    fn do_in_root<T>(
        &self,
        name: &str,
        flags: u32,
        open_dir: Option<&OpenDirFn<'_>>,
        f: &dyn Fn(&Path, &str, bool) -> RR<T>,
    ) -> io::Result<T> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(fs::Error::Closed.into());
        }
        let (mut parts, mut ends_in_slash) = split_path(name, &[], &[])?;
        let rootdir = self.base.clone();
        let mut dirfd = rootdir.clone();
        let (mut i, mut steps, mut restarts, mut symlinks) = (0usize, 0usize, 0usize, 0usize);
        loop {
            steps += 1;
            if steps > 255 && restarts > 8 {
                return Err(from_errno(errno::ENAMETOOLONG));
            }
            if parts[i] == ".." {
                restarts += 1;
                let mut end = i + 1;
                while end < parts.len() && parts[end] == ".." {
                    end += 1;
                }
                let count = end - i;
                if count > i {
                    return Err(escapes());
                }
                parts.drain(i - count..end);
                if parts.is_empty() {
                    parts.push(".".to_string());
                }
                i = 0;
                dirfd = rootdir.clone();
                continue;
            }
            let last = i == parts.len() - 1;
            let err: RErr;
            if last {
                let mut pre: Option<RErr> = None;
                if ends_in_slash && flags & NO_HANDLE_TERMINAL_SLASH == 0 {
                    match stdfs::symlink_metadata(dirfd.join(&parts[i])) {
                        Err(e) => {
                            let e = os_error(e);
                            if !(super::is_not_exist(&e) && flags & CREATING_DIRECTORY != 0) {
                                return Err(e);
                            }
                        }
                        Ok(m) if m.is_dir() => {}
                        Ok(m) if m.file_type().is_symlink() => {
                            pre = Some(match symlink_target(&dirfd, &parts[i]) {
                                Some(t) => RErr::Symlink(t),
                                None => RErr::Err(from_errno(errno::ENOTDIR)),
                            });
                        }
                        Ok(_) => return Err(from_errno(errno::ENOTDIR)),
                    }
                }
                match pre {
                    Some(e) => err = e,
                    None => match f(&dirfd, &parts[i], ends_in_slash) {
                        Ok(v) => return Ok(v),
                        Err(e) => err = e,
                    },
                }
            } else {
                let res = match open_dir {
                    Some(od) => od(&dirfd, &parts[i]),
                    None => open_dir_at(&dirfd, &parts[i]),
                };
                match res {
                    Ok(fd) => {
                        dirfd = fd;
                        i += 1;
                        continue;
                    }
                    Err(e) => err = e,
                }
            }
            match err {
                RErr::Symlink(target) => {
                    symlinks += 1;
                    if symlinks > MAX_SYMLINKS {
                        return Err(from_errno(errno::ELOOP));
                    }
                    let (newparts, new_slash) = split_path(&target, &parts[..i], &parts[i + 1..])?;
                    if last && new_slash {
                        ends_in_slash = true;
                    }
                    if newparts.len() < i || parts[..i] != newparts[..i] {
                        i = 0;
                        dirfd = rootdir.clone();
                    }
                    parts = newparts;
                }
                RErr::Err(e) => {
                    // A `PathError` from a callback names the resolved path.
                    if fs::path_error(&e).is_some() {
                        let joined = parts[..=i].join("/");
                        return Err(super::error::map_path_error(e, |op, _, err| {
                            (op, joined, err)
                        }));
                    }
                    return Err(e);
                }
            }
        }
    }

    /// `do_in_root` with the common wrapping: the failure of `op` on `name`.
    fn op<T>(
        &self,
        opname: &str,
        name: &str,
        flags: u32,
        f: &dyn Fn(&Path, &str, bool) -> RR<T>,
    ) -> io::Result<T> {
        self.do_in_root(name, flags, None, f)
            .map_err(|e| path_err(opname, name, e))
    }

    /// Opens the named file for reading (`Root.Open`).
    pub fn open(&self, name: &str) -> io::Result<File> {
        self.open_file(name, O_RDONLY, FileMode(0))
    }

    /// Creates or truncates the named file (`Root.Create`).
    pub fn create(&self, name: &str) -> io::Result<File> {
        self.open_file(name, O_RDWR | O_CREATE | O_TRUNC, FileMode(0o666))
    }

    /// Opens the named file with flags and permissions (`Root.OpenFile`).
    pub fn open_file(&self, name: &str, flag: i32, perm: FileMode) -> io::Result<File> {
        if perm.0 & 0o777 != perm.0 {
            return Err(
                PathError::new("openat", name, io::Error::other("unsupported file mode")).into(),
            );
        }
        let create_excl = flag & (O_CREATE | O_EXCL) == (O_CREATE | O_EXCL);
        let (file, real) = self.op("openat", name, 0, &|parent, n, _| {
            let full = parent.join(n);
            match open_std(&full.to_string_lossy(), flag | O_NOFOLLOW, perm) {
                Ok(f) => Ok((f, full.to_string_lossy().into_owned())),
                Err(e) => {
                    let e = os_error(e);
                    let nofollow = is_errno(&e, errno::ELOOP) || is_errno(&e, errno::EMLINK);
                    if !create_excl && (nofollow || is_errno(&e, errno::ENOTDIR)) {
                        if let Some(t) = symlink_target(parent, n) {
                            return Err(RErr::Symlink(t));
                        }
                    }
                    if create_excl && is_errno(&e, errno::ELOOP) {
                        return Err(RErr::Err(from_errno(errno::EEXIST)));
                    }
                    Err(RErr::Err(e))
                }
            }
        })?;
        Ok(File::from_std(file, join_name(&self.name, name), flag & O_APPEND != 0).in_root(real))
    }

    /// Opens the directory `name` as a new [`Root`] (`Root.OpenRoot`).
    pub fn open_root(&self, name: &str) -> io::Result<Root> {
        let file = self.op("openat", name, 0, &|parent, n, _| {
            let full = parent.join(n);
            match open_std(&full.to_string_lossy(), O_NOFOLLOW, FileMode(0)) {
                Ok(f) => Ok((f, full)),
                Err(e) => {
                    let e = os_error(e);
                    if is_errno(&e, errno::ELOOP) || is_errno(&e, errno::ENOTDIR) {
                        if let Some(t) = symlink_target(parent, n) {
                            return Err(RErr::Symlink(t));
                        }
                    }
                    Err(RErr::Err(e))
                }
            }
        })?;
        let (f, full) = file;
        let joined = join_name(&self.name, name);
        match f.metadata() {
            Ok(m) if m.is_dir() => Ok(Root {
                name: joined,
                base: stdfs::canonicalize(&full).unwrap_or(full),
                closed: AtomicBool::new(false),
            }),
            _ => Err(PathError::new("open", &joined, io::Error::other("not a directory")).into()),
        }
    }

    /// Runs `f` on the named file after following a final symbolic link
    /// (Go's `afterResolvingSymlink`).
    fn after_resolving(
        &self,
        opname: &str,
        name: &str,
        f: &dyn Fn(&str) -> io::Result<()>,
    ) -> io::Result<()> {
        self.op(opname, name, 0, &|parent, n, _| {
            if let Some(t) = symlink_target(parent, n) {
                return Err(RErr::Symlink(t));
            }
            f(&parent.join(n).to_string_lossy()).map_err(|e| RErr::Err(unwrap_layers(e)))
        })
    }

    /// Changes the mode of the named file (`Root.Chmod`).
    pub fn chmod(&self, name: &str, mode: FileMode) -> io::Result<()> {
        self.after_resolving("chmodat", name, &|p| fsops::chmod(p, mode))
    }

    /// Changes the owner of the named file (`Root.Chown`).
    pub fn chown(&self, name: &str, uid: i32, gid: i32) -> io::Result<()> {
        self.after_resolving("chownat", name, &|p| fsops::chown(p, uid, gid))
    }

    /// Like [`Root::chown`] but does not follow a symbolic link
    /// (`Root.Lchown`).
    pub fn lchown(&self, name: &str, uid: i32, gid: i32) -> io::Result<()> {
        self.op("lchownat", name, 0, &|parent, n, _| {
            fsops::lchown(&parent.join(n).to_string_lossy(), uid, gid)
                .map_err(|e| RErr::Err(unwrap_layers(e)))
        })
    }

    /// Changes the access and modification times (`Root.Chtimes`).
    pub fn chtimes(&self, name: &str, atime: Time, mtime: Time) -> io::Result<()> {
        self.after_resolving("chtimesat", name, &|p| {
            fsops::chtimes(p, atime.clone(), mtime.clone())
        })
    }

    fn mkdir_flags() -> u32 {
        let mut flags = CREATING_DIRECTORY;
        if cfg!(any(
            target_os = "linux",
            target_os = "windows",
            target_os = "openbsd"
        )) {
            flags |= NO_HANDLE_TERMINAL_SLASH;
        }
        flags
    }

    /// Creates a directory (`Root.Mkdir`).
    pub fn mkdir(&self, name: &str, perm: FileMode) -> io::Result<()> {
        if perm.0 & 0o777 != perm.0 {
            return Err(
                PathError::new("mkdirat", name, io::Error::other("unsupported file mode")).into(),
            );
        }
        self.op("mkdirat", name, Self::mkdir_flags(), &|parent, n, _| {
            fsops::mkdir(&parent.join(n).to_string_lossy(), perm)
                .map_err(|e| RErr::Err(unwrap_layers(e)))
        })
    }

    /// Creates a directory and any missing parents (`Root.MkdirAll`).
    pub fn mkdir_all(&self, fullname: &str, perm: FileMode) -> io::Result<()> {
        if perm.0 & 0o777 != perm.0 {
            return Err(PathError::new(
                "mkdirat",
                fullname,
                io::Error::other("unsupported file mode"),
            )
            .into());
        }
        let mkdirat = |parent: &Path, n: &str| -> io::Result<()> {
            fsops::mkdir(&parent.join(n).to_string_lossy(), perm).map_err(unwrap_layers)
        };
        let open_dir = |parent: &Path, n: &str| -> RR<PathBuf> {
            for attempt in 0..2 {
                match open_dir_at(parent, n) {
                    Ok(p) => return Ok(p),
                    Err(RErr::Symlink(t)) => return Err(RErr::Symlink(t)),
                    Err(RErr::Err(e)) => {
                        if attempt > 0 || !super::is_not_exist(&e) {
                            return Err(RErr::Err(PathError::new("openat", "", e).into()));
                        }
                        if let Err(e) = mkdirat(parent, n) {
                            if !is_errno(&e, errno::EEXIST) {
                                return Err(RErr::Err(PathError::new("mkdirat", "", e).into()));
                            }
                        }
                    }
                }
            }
            Err(RErr::Err(io::Error::other("unreachable")))
        };
        let last = |parent: &Path, n: &str, _: bool| -> RR<()> {
            let mut err = mkdirat(parent, n).err();
            if err.as_ref().is_some_and(|e| is_errno(e, errno::EEXIST)) {
                if let Ok(m) = stdfs::symlink_metadata(parent.join(n)) {
                    if m.is_dir() {
                        err = None;
                    } else if m.file_type().is_symlink() {
                        match self.stat(fullname) {
                            Ok(fi) if fi.is_dir() => err = None,
                            Ok(_) => err = Some(from_errno(errno::ENOTDIR)),
                            Err(e) if !super::is_not_exist(&e) => err = Some(e),
                            Err(_) => {}
                        }
                    }
                }
            }
            match err {
                None => Ok(()),
                Some(e) => Err(RErr::Err(PathError::new("mkdirat", "", e).into())),
            }
        };
        match self.do_in_root(fullname, Self::mkdir_flags(), Some(&open_dir), &last) {
            Ok(()) => Ok(()),
            Err(e) => {
                if fs::path_error(&e).is_some() {
                    Err(e)
                } else {
                    Err(PathError::new("mkdirat", fullname, e).into())
                }
            }
        }
    }

    /// Removes the named file or empty directory (`Root.Remove`).
    pub fn remove(&self, name: &str) -> io::Result<()> {
        self.op("removeat", name, 0, &|parent, n, _| {
            fsops::remove(&parent.join(n).to_string_lossy())
                .map_err(|e| RErr::Err(unwrap_layers(e)))
        })
    }

    /// Removes the named path and any children (`Root.RemoveAll`).
    pub fn remove_all(&self, name: &str) -> io::Result<()> {
        let mut name = name;
        while name.ends_with('/') {
            name = &name[..name.len() - 1];
        }
        if name == "." || name.ends_with("/.") {
            return Err(path_err("RemoveAll", name, from_errno(errno::EINVAL)));
        }
        let r = self.do_in_root(name, 0, None, &|parent, n, _| {
            fsops::remove_all_from(&parent.to_string_lossy(), n)
                .map_err(|e| RErr::Err(unwrap_layers(e)))
        });
        match r {
            Ok(()) => Ok(()),
            Err(e) if super::is_not_exist(&e) => Ok(()),
            Err(e) => Err(path_err("RemoveAll", name, unwrap_layers(e))),
        }
    }

    /// Returns a `FileInfo` for the named file, following links (`Root.Stat`).
    pub fn stat(&self, name: &str) -> io::Result<Box<dyn FileInfo>> {
        self.stat_at(name, false)
    }

    /// Like [`Root::stat`] but does not follow a final link (`Root.Lstat`).
    pub fn lstat(&self, name: &str) -> io::Result<Box<dyn FileInfo>> {
        self.stat_at(name, true)
    }

    fn stat_at(&self, name: &str, lstat: bool) -> io::Result<Box<dyn FileInfo>> {
        let meta = self.op("statat", name, 0, &|parent, n, _| {
            let meta = stdfs::symlink_metadata(parent.join(n)).map_err(os_error)?;
            if !lstat && meta.file_type().is_symlink() {
                return Err(match symlink_target(parent, n) {
                    Some(t) => RErr::Symlink(t),
                    None => RErr::Err(from_errno(errno::ELOOP)),
                });
            }
            Ok(meta)
        })?;
        Ok(Box::new(StdInfo {
            name: super::file::basename(name),
            meta,
        }))
    }

    /// Returns the destination of the symbolic link (`Root.Readlink`).
    pub fn readlink(&self, name: &str) -> io::Result<String> {
        self.op("readlinkat", name, 0, &|parent, n, _| {
            stdfs::read_link(parent.join(n))
                .map(|p| p.to_string_lossy().into_owned())
                .map_err(|e| RErr::Err(os_error(e)))
        })
    }

    /// Renames within the root (`Root.Rename`).
    pub fn rename(&self, oldname: &str, newname: &str) -> io::Result<()> {
        let r = self.do_in_root(oldname, 0, None, &|oldparent, oldn, _| {
            self.do_in_root(
                newname,
                CREATING_DIRECTORY,
                None,
                &|newparent, newn, new_slash| {
                    if new_slash {
                        let m = stdfs::symlink_metadata(oldparent.join(oldn)).map_err(os_error)?;
                        if !m.is_dir() {
                            return Err(RErr::Err(from_errno(errno::ENOTDIR)));
                        }
                    }
                    if let Ok(fi) = stdfs::symlink_metadata(newparent.join(newn)) {
                        if fi.is_dir() {
                            let ofi =
                                stdfs::symlink_metadata(oldparent.join(oldn)).map_err(os_error)?;
                            use std::os::unix::fs::MetadataExt;
                            let same = ofi.dev() == fi.dev() && ofi.ino() == fi.ino();
                            if newn == oldn || !same {
                                return Err(RErr::Err(from_errno(errno::EEXIST)));
                            }
                        }
                    }
                    stdfs::rename(oldparent.join(oldn), newparent.join(newn))
                        .map_err(|e| RErr::Err(os_error(e)))
                },
            )
            .map_err(RErr::Err)
        });
        r.map_err(|e| link_err("renameat", oldname, newname, e))
    }

    /// Creates a hard link within the root (`Root.Link`).
    pub fn link(&self, oldname: &str, newname: &str) -> io::Result<()> {
        let r = self.do_in_root(oldname, 0, None, &|oldparent, oldn, _| {
            self.do_in_root(newname, 0, None, &|newparent, newn, _| {
                stdfs::hard_link(oldparent.join(oldn), newparent.join(newn))
                    .map_err(|e| RErr::Err(os_error(e)))
            })
            .map_err(RErr::Err)
        });
        r.map_err(|e| link_err("linkat", oldname, newname, e))
    }

    /// Creates a symbolic link `newname` to `oldname` (`Root.Symlink`). The
    /// target is stored as given; it is checked when followed.
    pub fn symlink(&self, oldname: &str, newname: &str) -> io::Result<()> {
        let r = self.do_in_root(newname, 0, None, &|parent, n, _| {
            std::os::unix::fs::symlink(oldname, parent.join(n)).map_err(|e| RErr::Err(os_error(e)))
        });
        r.map_err(|e| link_err("symlinkat", oldname, newname, e))
    }

    /// Reads the named file (`Root.ReadFile`).
    pub fn read_file(&self, name: &str) -> io::Result<Vec<u8>> {
        let f = self.open(name)?;
        let mut data = Vec::new();
        (&f).read_to_end(&mut data)?;
        Ok(data)
    }

    /// Writes data to the named file, creating it if necessary
    /// (`Root.WriteFile`).
    pub fn write_file(&self, name: &str, data: &[u8], perm: FileMode) -> io::Result<()> {
        use std::io::Write;
        let f = self.open_file(name, O_WRONLY | O_CREATE | O_TRUNC, perm)?;
        let r = (&f).write_all(data);
        r.and(f.close())
    }

    /// Returns a read-only [`FS`] over the root (`Root.FS`).
    pub fn fs(&self) -> RootFS<'_> {
        RootFS { root: self }
    }
}

/// The [`FS`] of a [`Root`] (`Root.FS`).
#[derive(Debug)]
pub struct RootFS<'a> {
    root: &'a Root,
}

impl RootFS<'_> {
    fn check(&self, op: &str, name: &str) -> io::Result<()> {
        if fs::valid_path(name) {
            Ok(())
        } else {
            Err(PathError::new(op, name, fs::Error::Invalid).into())
        }
    }
}

impl FS for RootFS<'_> {
    fn open(&self, name: &str) -> io::Result<Box<dyn fs::File>> {
        self.check("open", name)?;
        Ok(Box::new(self.root.open(name)?))
    }
    fn as_read_dir_fs(&self) -> Option<&dyn ReadDirFS> {
        Some(self)
    }
    fn as_read_file_fs(&self) -> Option<&dyn ReadFileFS> {
        Some(self)
    }
    fn as_stat_fs(&self) -> Option<&dyn StatFS> {
        Some(self)
    }
    fn as_read_link_fs(&self) -> Option<&dyn ReadLinkFS> {
        Some(self)
    }
}

impl ReadDirFS for RootFS<'_> {
    fn read_dir(&self, name: &str) -> Result<Vec<Box<dyn DirEntry>>, ReadDirError> {
        self.check("readdir", name)?;
        let f = self.root.open(name)?;
        let mut dirs = f.read_dir(-1)?;
        dirs.sort_by(|a, b| a.name().cmp(b.name()));
        Ok(dirs)
    }
}

impl ReadFileFS for RootFS<'_> {
    fn read_file(&self, name: &str) -> io::Result<Vec<u8>> {
        self.check("readfile", name)?;
        self.root.read_file(name)
    }
}

impl StatFS for RootFS<'_> {
    fn stat(&self, name: &str) -> io::Result<Box<dyn FileInfo>> {
        self.check("stat", name)?;
        self.root.stat(name)
    }
}

impl ReadLinkFS for RootFS<'_> {
    fn read_link(&self, name: &str) -> io::Result<String> {
        self.check("readlink", name)?;
        self.root.readlink(name)
    }
    fn lstat(&self, name: &str) -> io::Result<Box<dyn FileInfo>> {
        self.check("lstat", name)?;
        self.root.lstat(name)
    }
}
