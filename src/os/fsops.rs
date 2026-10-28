//! Path-based file system operations of `os`.

use super::error::{errno, from_errno, link_err, os_error, path_err};
use super::file::{
    basename, open_file, syscall_mode, File, O_CREATE, O_EXCL, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY,
};
use super::{is_exist, is_not_exist};
use crate::io::fs::dirfs::StdInfo;
use crate::io::fs::{self, DirEntry, FileInfo, FileMode, PathError, FS};
use crate::time::Time;
use std::fs as stdfs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::Path;

/// Creates a new directory with the given permission bits (`os.Mkdir`).
pub fn mkdir(name: &str, perm: FileMode) -> io::Result<()> {
    let mut b = stdfs::DirBuilder::new();
    b.mode(syscall_mode(perm));
    b.create(name).map_err(|e| path_err("mkdir", name, e))
}

/// Creates a directory and any necessary parents (`os.MkdirAll`).
pub fn mkdir_all(path: &str, perm: FileMode) -> io::Result<()> {
    if let Ok(dir) = stat(path) {
        if dir.is_dir() {
            return Ok(());
        }
        return Err(path_err("mkdir", path, from_errno(errno::ENOTDIR)));
    }
    // Find the parent: strip trailing separators, then the last element.
    let b = path.as_bytes();
    let mut i = b.len() as isize - 1;
    while i >= 0 && b[i as usize] == b'/' {
        i -= 1;
    }
    while i >= 0 && b[i as usize] != b'/' {
        i -= 1;
    }
    if i < 0 {
        i = 0;
    }
    let parent = &path[..i as usize];
    if !parent.is_empty() {
        mkdir_all(parent, perm)?;
    }
    match mkdir(path, perm) {
        Ok(()) => Ok(()),
        Err(err) => match lstat(path) {
            Ok(dir) if dir.is_dir() => Ok(()),
            _ => Err(err),
        },
    }
}

/// Removes the named file or (empty) directory (`os.Remove`).
pub fn remove(name: &str) -> io::Result<()> {
    let e = match stdfs::remove_file(name) {
        Ok(()) => return Ok(()),
        Err(e) => e,
    };
    let e1 = match stdfs::remove_dir(name) {
        Ok(()) => return Ok(()),
        Err(e1) => e1,
    };
    // Both failed: report the unlink error unless rmdir's is more specific
    // than "not a directory".
    let err = if e1.raw_os_error() != Some(errno::ENOTDIR) {
        e1
    } else {
        e
    };
    Err(path_err("remove", name, err))
}

fn ends_with_dot(path: &str) -> bool {
    path == "." || path.ends_with("/.")
}

/// Go's `splitPath`: the parent directory and base name of `path`.
fn split_path(path: &str) -> (String, String) {
    let mut dirname = ".".to_string();
    let mut path = path.to_string();
    // Remove all but one leading slash.
    while path.len() > 1 && path.starts_with("//") {
        path.remove(0);
    }
    // Remove trailing slashes.
    while path.len() > 1 && path.ends_with('/') {
        path.pop();
    }
    let mut basename = path.clone();
    let b = path.as_bytes();
    let mut i = b.len() as isize - 2;
    while i >= 0 {
        if b[i as usize] == b'/' {
            dirname = if i == 0 {
                path[..1].to_string()
            } else {
                path[..i as usize].to_string()
            };
            basename = path[i as usize + 1..].to_string();
            break;
        }
        i -= 1;
    }
    (dirname, basename)
}

/// Removes `path` and any children it contains; a missing path is not an
/// error (`os.RemoveAll`).
pub fn remove_all(path: &str) -> io::Result<()> {
    if path.is_empty() {
        return Ok(());
    }
    if ends_with_dot(path) {
        return Err(path_err("RemoveAll", path, from_errno(errno::EINVAL)));
    }
    match remove(path) {
        Ok(()) => return Ok(()),
        Err(e) if is_not_exist(&e) => return Ok(()),
        Err(_) => {}
    }
    let (parent_dir, base) = split_path(path);
    let _parent = match open_file(&parent_dir, O_RDONLY, FileMode(0)) {
        Ok(f) => f,
        Err(e) if is_not_exist(&e) => return Ok(()),
        Err(e) => return Err(e),
    };
    match remove_all_from(&parent_dir, &base) {
        Ok(()) => Ok(()),
        Err(e) => Err(super::error::map_path_error(e, |op, p, err| {
            (op, format!("{parent_dir}/{p}"), err)
        })),
    }
}

fn errno_is(err: &io::Error, code: i32) -> bool {
    super::error::errno_of(err).is_some_and(|n| n.0 == code)
}

/// Go's `removeAllFrom`, with `parent` and `base` joined by name instead of
/// being resolved through a directory descriptor.
pub(crate) fn remove_all_from(parent: &str, base: &str) -> io::Result<()> {
    let full = join_path(parent, base);
    let uerr = match stdfs::remove_file(&full) {
        Ok(()) => return Ok(()),
        Err(e) => os_error(e),
    };
    if is_not_exist(&uerr) {
        return Ok(());
    }
    if ![errno::EISDIR, errno::EPERM, errno::EACCES]
        .iter()
        .any(|c| errno_is(&uerr, *c))
    {
        return Err(PathError::new("unlinkat", base, uerr).into());
    }
    let mut recurse_err: Option<io::Error> = None;
    // Open the directory without following a final symbolic link.
    let opened = match stdfs::symlink_metadata(&full) {
        Err(e) => {
            let e = os_error(e);
            if is_not_exist(&e) {
                return Ok(());
            }
            Err(e)
        }
        Ok(m) if m.file_type().is_symlink() => Err(super::error::clone_errno_error(&uerr)),
        Ok(m) if !m.is_dir() => {
            return Err(PathError::new("unlinkat", base, uerr).into());
        }
        Ok(_) => stdfs::read_dir(&full).map_err(os_error),
    };
    match opened {
        Err(e) => {
            recurse_err = Some(PathError::new("openfdat", base, e).into());
        }
        Ok(entries) => {
            let mut names = Vec::new();
            for entry in entries {
                match entry {
                    Ok(e) => names.push(e.file_name().to_string_lossy().into_owned()),
                    Err(e) => {
                        let e = os_error(e);
                        if is_not_exist(&e) {
                            return Ok(());
                        }
                        return Err(PathError::new("readdirnames", base, e).into());
                    }
                }
            }
            for name in names {
                if let Err(err) = remove_all_from(&full, &name) {
                    let err = super::error::map_path_error(err, |op, p, e| {
                        (op, format!("{base}/{p}"), e)
                    });
                    if recurse_err.is_none() {
                        recurse_err = Some(err);
                    }
                }
            }
        }
    }
    match stdfs::remove_dir(&full) {
        Ok(()) => Ok(()),
        Err(e) => {
            let e = os_error(e);
            if is_not_exist(&e) {
                return Ok(());
            }
            if let Some(r) = recurse_err {
                return Err(r);
            }
            Err(PathError::new("unlinkat", base, e).into())
        }
    }
}

/// Renames (moves) `oldpath` to `newpath` (`os.Rename`).
pub fn rename(oldpath: &str, newpath: &str) -> io::Result<()> {
    // Go reports a bad oldname and a bad newname distinctly when the target
    // is a directory.
    if let Ok(fi) = lstat(newpath) {
        if fi.is_dir() {
            match lstat(oldpath) {
                Err(err) => {
                    return Err(link_err(
                        "rename",
                        oldpath,
                        newpath,
                        super::error::unwrap_layers(err),
                    ));
                }
                Ok(ofi) => {
                    if newpath == oldpath || !same_file(fi.as_ref(), ofi.as_ref()) {
                        return Err(link_err(
                            "rename",
                            oldpath,
                            newpath,
                            from_errno(errno::EEXIST),
                        ));
                    }
                }
            }
        }
    }
    stdfs::rename(oldpath, newpath).map_err(|e| link_err("rename", oldpath, newpath, e))
}

/// Creates `newname` as a hard link to `oldname` (`os.Link`).
pub fn link(oldname: &str, newname: &str) -> io::Result<()> {
    stdfs::hard_link(oldname, newname).map_err(|e| link_err("link", oldname, newname, e))
}

/// Creates `newname` as a symbolic link to `oldname` (`os.Symlink`).
pub fn symlink(oldname: &str, newname: &str) -> io::Result<()> {
    std::os::unix::fs::symlink(oldname, newname)
        .map_err(|e| link_err("symlink", oldname, newname, e))
}

/// Returns the destination of the named symbolic link (`os.Readlink`).
pub fn readlink(name: &str) -> io::Result<String> {
    stdfs::read_link(name)
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|e| path_err("readlink", name, e))
}

/// Returns a `FileInfo` for the named file, following symbolic links
/// (`os.Stat`).
pub fn stat(name: &str) -> io::Result<Box<dyn FileInfo>> {
    let meta = stdfs::metadata(name).map_err(|e| path_err("stat", name, e))?;
    Ok(Box::new(StdInfo {
        name: basename(name),
        meta,
    }))
}

/// Like [`stat`] but does not follow a final symbolic link (`os.Lstat`).
pub fn lstat(name: &str) -> io::Result<Box<dyn FileInfo>> {
    let meta = stdfs::symlink_metadata(name).map_err(|e| path_err("lstat", name, e))?;
    Ok(Box::new(StdInfo {
        name: basename(name),
        meta,
    }))
}

/// Reports whether two `FileInfo`s describe the same file (`os.SameFile`).
/// Only infos produced by this package (`stat`, `lstat`, `File::stat`,
/// directory reads) can be compared; others are never the same.
pub fn same_file(fi1: &dyn FileInfo, fi2: &dyn FileInfo) -> bool {
    let meta = |fi: &dyn FileInfo| {
        fi.sys()
            .and_then(|s| s.downcast_ref::<stdfs::Metadata>())
            .cloned()
    };
    match (meta(fi1), meta(fi2)) {
        (Some(a), Some(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

/// Changes the mode of the named file (`os.Chmod`).
pub fn chmod(name: &str, mode: FileMode) -> io::Result<()> {
    stdfs::set_permissions(name, stdfs::Permissions::from_mode(syscall_mode(mode)))
        .map_err(|e| path_err("chmod", name, e))
}

fn id(v: i32) -> Option<u32> {
    u32::try_from(v).ok()
}

/// Changes the numeric uid and gid of the named file; -1 leaves one
/// unchanged (`os.Chown`).
pub fn chown(name: &str, uid: i32, gid: i32) -> io::Result<()> {
    std::os::unix::fs::chown(name, id(uid), id(gid)).map_err(|e| path_err("chown", name, e))
}

/// Like [`chown`] but does not follow a symbolic link (`os.Lchown`).
pub fn lchown(name: &str, uid: i32, gid: i32) -> io::Result<()> {
    std::os::unix::fs::lchown(name, id(uid), id(gid)).map_err(|e| path_err("lchown", name, e))
}

fn system_time(t: &Time) -> std::time::SystemTime {
    let secs = t.unix();
    let nanos = t.nanosecond() as u32;
    if secs >= 0 {
        std::time::UNIX_EPOCH + std::time::Duration::new(secs as u64, nanos)
    } else {
        std::time::UNIX_EPOCH - std::time::Duration::from_secs(secs.unsigned_abs())
            + std::time::Duration::from_nanos(u64::from(nanos))
    }
}

/// Changes the access and modification times of the named file; a zero
/// `Time` leaves that time unchanged (`os.Chtimes`).
pub fn chtimes(name: &str, atime: Time, mtime: Time) -> io::Result<()> {
    let f = stdfs::File::open(name).map_err(|e| path_err("chtimes", name, e))?;
    let mut times = stdfs::FileTimes::new();
    if !atime.is_zero() {
        times = times.set_accessed(system_time(&atime));
    }
    if !mtime.is_zero() {
        times = times.set_modified(system_time(&mtime));
    }
    f.set_times(times).map_err(|e| path_err("chtimes", name, e))
}

/// Changes the size of the named file (`os.Truncate`).
pub fn truncate(name: &str, size: i64) -> io::Result<()> {
    if size < 0 {
        // The system call checks the size before it looks at the file.
        return Err(path_err("truncate", name, from_errno(errno::EINVAL)));
    }
    let f = stdfs::OpenOptions::new()
        .write(true)
        .open(name)
        .map_err(|e| path_err("truncate", name, e))?;
    let size =
        u64::try_from(size).map_err(|_| path_err("truncate", name, from_errno(errno::EINVAL)))?;
    f.set_len(size).map_err(|e| path_err("truncate", name, e))
}

/// Reads the named file and returns its contents (`os.ReadFile`).
pub fn read_file(name: &str) -> io::Result<Vec<u8>> {
    let f = super::file::open(name)?;
    let mut data = Vec::new();
    (&f).read_to_end(&mut data)?;
    Ok(data)
}

/// Writes data to the named file, creating it with `perm` if necessary
/// (`os.WriteFile`).
pub fn write_file(name: &str, data: &[u8], perm: FileMode) -> io::Result<()> {
    let f = open_file(name, O_WRONLY | O_CREATE | O_TRUNC, perm)?;
    let r = (&f).write_all(data);
    let c = f.close();
    r.and(c)
}

/// Reads the named directory and returns its entries sorted by filename
/// (`os.ReadDir`).
pub fn read_dir(name: &str) -> io::Result<Vec<Box<dyn DirEntry>>> {
    let f = open_dir(name)?;
    let mut dirs = f.read_dir(-1)?;
    dirs.sort_by(|a, b| a.name().cmp(b.name()));
    Ok(dirs)
}

/// Reads the named directory and returns `Lstat` info for its entries sorted
/// by filename (`ioutil.ReadDir`, which returns `FileInfo`s where
/// [`read_dir`] returns `DirEntry`s).
pub fn read_dir_info(name: &str) -> io::Result<Vec<Box<dyn FileInfo>>> {
    let f = open_dir(name)?;
    let list = f.readdir(-1);
    let c = f.close();
    let mut list = list?;
    c?;
    list.sort_by(|a, b| a.name().cmp(b.name()));
    Ok(list)
}

fn open_dir(name: &str) -> io::Result<File> {
    open_file(name, O_RDONLY | super::file::O_DIRECTORY, FileMode(0))
}

/// A file system rooted at the directory `dir` (`os.DirFS`).
pub fn dir_fs(dir: &str) -> fs::DirFS {
    fs::DirFS::new(dir)
}

fn join_path(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// Copies the file system `fsys` into the local directory `dir`, creating
/// `dir` if needed (`os.CopyFS`). Existing files are not overwritten.
pub fn copy_fs(dir: &str, fsys: &dyn FS) -> io::Result<()> {
    fs::walk_dir(fsys, ".", |path, d, err| {
        if let Some(err) = err {
            return Err(err);
        }
        let d = d.expect("entry present without error");
        let fpath = crate::path::filepath::localize(path)?;
        let new_path = join_path(dir, &fpath);
        let ty = d.file_type();
        if ty == fs::MODE_DIR {
            mkdir_all(&new_path, FileMode(0o777))
        } else if ty == fs::MODE_SYMLINK {
            let target = fs::read_link(fsys, path)?;
            symlink(&target, &new_path)
        } else if ty.0 == 0 {
            let mut r = fsys.open(path)?;
            let info = r.stat()?;
            let w = open_file(
                &new_path,
                O_CREATE | O_EXCL | O_WRONLY,
                FileMode(0o666 | (info.mode().0 & 0o777)),
            )?;
            if let Err(e) = std::io::copy(&mut r, &mut &w) {
                let _ = w.close();
                return Err(PathError::new("Copy", &new_path, e).into());
            }
            w.close()
        } else {
            Err(PathError::new("CopyFS", path, fs::Error::Invalid).into())
        }
    })
}

fn next_random() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let mut h = RandomState::new().build_hasher();
    h.write_u32(COUNTER.fetch_add(1, Ordering::Relaxed));
    h.write_u32(std::process::id());
    (h.finish() as u32).to_string()
}

fn prefix_and_suffix(pattern: &str) -> Result<(&str, &str), io::Error> {
    if pattern.contains('/') {
        return Err(io::Error::other("pattern contains path separator"));
    }
    Ok(match pattern.rfind('*') {
        Some(pos) => (&pattern[..pos], &pattern[pos + 1..]),
        None => (pattern, ""),
    })
}

/// Creates a new temporary file in `dir` (the default temporary directory
/// if empty), opens it for reading and writing and returns it
/// (`os.CreateTemp`). The last `*` of `pattern` is replaced by a random
/// string.
pub fn create_temp(dir: &str, pattern: &str) -> io::Result<File> {
    let dir = if dir.is_empty() {
        temp_dir()
    } else {
        dir.to_string()
    };
    let (prefix, suffix) = prefix_and_suffix(pattern)
        .map_err(|e| std::io::Error::from(PathError::new("createtemp", pattern, e)))?;
    let prefix = join_path(&dir, prefix);
    let mut tries = 0;
    loop {
        let name = format!("{prefix}{}{suffix}", next_random());
        match open_file(&name, O_RDWR | O_CREATE | O_EXCL, FileMode(0o600)) {
            Err(e) if is_exist(&e) => {
                tries += 1;
                if tries < 10000 {
                    continue;
                }
                return Err(PathError::new(
                    "createtemp",
                    &format!("{prefix}*{suffix}"),
                    fs::Error::Exist,
                )
                .into());
            }
            other => return other,
        }
    }
}

/// Creates a new temporary directory in `dir` (the default temporary
/// directory if empty) and returns its name (`os.MkdirTemp`).
pub fn mkdir_temp(dir: &str, pattern: &str) -> io::Result<String> {
    let dir = if dir.is_empty() {
        temp_dir()
    } else {
        dir.to_string()
    };
    let (prefix, suffix) = prefix_and_suffix(pattern)
        .map_err(|e| std::io::Error::from(PathError::new("mkdirtemp", pattern, e)))?;
    let prefix = join_path(&dir, prefix);
    let mut tries = 0;
    loop {
        let name = format!("{prefix}{}{suffix}", next_random());
        match mkdir(&name, FileMode(0o700)) {
            Ok(()) => return Ok(name),
            Err(e) if is_exist(&e) => {
                tries += 1;
                if tries < 10000 {
                    continue;
                }
                return Err(PathError::new(
                    "mkdirtemp",
                    &format!("{prefix}*{suffix}"),
                    fs::Error::Exist,
                )
                .into());
            }
            Err(e) => {
                if is_not_exist(&e) {
                    if let Err(e2) = stat(&dir) {
                        if is_not_exist(&e2) {
                            return Err(e2);
                        }
                    }
                }
                return Err(e);
            }
        }
    }
}

/// The default directory for temporary files (`os.TempDir`).
pub fn temp_dir() -> String {
    let dir = super::getenv("TMPDIR");
    if dir.is_empty() {
        "/tmp".to_string()
    } else {
        dir
    }
}

/// Returns an absolute path name for the current directory (`os.Getwd`).
pub fn getwd() -> io::Result<String> {
    // Honor $PWD when it names the current directory, as Go does.
    if let Some(dir) = std::env::var_os("PWD") {
        let dir = dir.to_string_lossy().into_owned();
        if dir.starts_with('/') {
            let dot = stat(".")?;
            if let Ok(d) = stat(&dir) {
                if same_file(dot.as_ref(), d.as_ref()) {
                    return Ok(dir);
                }
            }
        }
    }
    std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|e| super::SyscallError::new("getwd", e).into())
}

/// Changes the current working directory (`os.Chdir`).
pub fn chdir(dir: &str) -> io::Result<()> {
    std::env::set_current_dir(Path::new(dir)).map_err(|e| path_err("chdir", dir, e))
}
