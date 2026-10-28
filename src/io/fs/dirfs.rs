//! `os.DirFS`: an [`FS`] over a directory of the operating system's file system.

use super::{
    valid_path, DirEntry, Error, File, FileInfo, FileMode, PathError, ReadDirError, ReadDirFS,
    ReadDirFile, ReadFileFS, ReadLinkFS, StatFS, FS, MODE_CHAR_DEVICE, MODE_DEVICE, MODE_DIR,
    MODE_IRREGULAR, MODE_NAMED_PIPE, MODE_SETGID, MODE_SETUID, MODE_SOCKET, MODE_STICKY,
    MODE_SYMLINK,
};
use crate::time::{self, Time};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// A file system rooted at a directory (`os.DirFS`).
///
/// Names follow `fs.ValidPath` (slash separated, no `.`/`..` elements), so
/// they cannot escape the directory lexically. Like Go, symbolic links inside
/// the tree are followed by the operating system.
#[derive(Clone, Debug)]
pub struct DirFS {
    dir: PathBuf,
}

impl DirFS {
    /// Returns a file system for the tree rooted at `dir` (`os.DirFS`).
    pub fn new(dir: impl Into<PathBuf>) -> DirFS {
        DirFS { dir: dir.into() }
    }

    fn join(&self, op: &str, name: &str) -> io::Result<PathBuf> {
        if self.dir.as_os_str().is_empty() {
            return Err(
                PathError::new(op, name, io::Error::other("os: DirFS with empty root")).into(),
            );
        }
        if !valid_path(name) {
            return Err(PathError::new(op, name, Error::Invalid).into());
        }
        if cfg!(windows) && (name.contains('\\') || name.contains(':')) {
            return Err(PathError::new(op, name, Error::Invalid).into());
        }
        Ok(self.dir.join(name))
    }
}

fn wrap(op: &str, name: &str, err: io::Error) -> io::Error {
    // Go prints the operating system's message, not Rust's.
    #[cfg(unix)]
    let err = crate::os::os_error(err);
    PathError::new(op, name, err).into()
}

/// A `FileInfo` from `std::fs::Metadata`.
#[derive(Debug)]
pub(crate) struct StdInfo {
    pub(crate) name: String,
    pub(crate) meta: fs::Metadata,
}

/// Permission, special and device bits of `meta` (Go's `fillFileStatFromSys`).
#[cfg(unix)]
fn base_mode(meta: &fs::Metadata) -> FileMode {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let ft = meta.file_type();
    let raw = meta.mode();
    let mut m = FileMode(raw & 0o777);
    if ft.is_block_device() {
        m = m | MODE_DEVICE;
    } else if ft.is_char_device() {
        m = m | MODE_DEVICE | MODE_CHAR_DEVICE;
    } else if ft.is_fifo() {
        m = m | MODE_NAMED_PIPE;
    } else if ft.is_socket() {
        m = m | MODE_SOCKET;
    }
    if raw & 0o4000 != 0 {
        m = m | MODE_SETUID;
    }
    if raw & 0o2000 != 0 {
        m = m | MODE_SETGID;
    }
    if raw & 0o1000 != 0 {
        m = m | MODE_STICKY;
    }
    m
}

#[cfg(not(unix))]
fn base_mode(meta: &fs::Metadata) -> FileMode {
    FileMode(if meta.permissions().readonly() {
        0o444
    } else {
        0o666
    })
}

pub(crate) fn mode_of(meta: &fs::Metadata) -> FileMode {
    let ft = meta.file_type();
    let m = base_mode(meta);
    if ft.is_dir() {
        m | MODE_DIR
    } else if ft.is_symlink() {
        m | MODE_SYMLINK
    } else if !ft.is_file() && m.file_type().0 == 0 {
        m | MODE_IRREGULAR
    } else {
        m
    }
}

pub(crate) fn time_of(meta: &fs::Metadata) -> Time {
    match meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
    {
        Some(d) => time::unix(d.as_secs() as i64, i64::from(d.subsec_nanos())),
        None => Time::default(),
    }
}

impl FileInfo for StdInfo {
    fn name(&self) -> &str {
        &self.name
    }
    fn size(&self) -> i64 {
        self.meta.len() as i64
    }
    fn mode(&self) -> FileMode {
        mode_of(&self.meta)
    }
    fn mod_time(&self) -> Time {
        time_of(&self.meta)
    }
    fn sys(&self) -> Option<&dyn std::any::Any> {
        Some(&self.meta)
    }
}

fn base_name(p: &Path, fallback: &str) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| fallback.to_string())
}

#[derive(Debug)]
pub(crate) struct StdEntry {
    pub(crate) name: String,
    pub(crate) path: PathBuf,
    pub(crate) ft: fs::FileType,
}

impl DirEntry for StdEntry {
    fn name(&self) -> &str {
        &self.name
    }
    fn is_dir(&self) -> bool {
        self.ft.is_dir()
    }
    fn file_type(&self) -> FileMode {
        if self.ft.is_dir() {
            MODE_DIR
        } else if self.ft.is_symlink() {
            MODE_SYMLINK
        } else if self.ft.is_file() {
            FileMode(0)
        } else {
            special_type(&self.ft)
        }
    }
    fn info(&self) -> io::Result<Box<dyn FileInfo>> {
        let meta = fs::symlink_metadata(&self.path)?;
        Ok(Box::new(StdInfo {
            name: self.name.clone(),
            meta,
        }))
    }
}

/// The type bits of a file that is neither a directory, a symlink nor regular.
#[cfg(unix)]
fn special_type(ft: &fs::FileType) -> FileMode {
    use std::os::unix::fs::FileTypeExt;
    if ft.is_block_device() {
        MODE_DEVICE
    } else if ft.is_char_device() {
        MODE_DEVICE | MODE_CHAR_DEVICE
    } else if ft.is_fifo() {
        MODE_NAMED_PIPE
    } else if ft.is_socket() {
        MODE_SOCKET
    } else {
        MODE_IRREGULAR
    }
}

#[cfg(not(unix))]
fn special_type(_: &fs::FileType) -> FileMode {
    MODE_IRREGULAR
}

#[derive(Debug)]
struct DirFile {
    name: String,
    path: PathBuf,
    file: Option<fs::File>,
    entries: Option<fs::ReadDir>,
}

impl Read for DirFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.file {
            None => Err(wrap("read", &self.name, Error::Closed.into())),
            Some(f) => f.read(buf).map_err(|e| wrap("read", &self.name, e)),
        }
    }
}

impl io::Seek for DirFile {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        match &mut self.file {
            None => Err(wrap("seek", &self.name, Error::Closed.into())),
            Some(f) => io::Seek::seek(f, pos).map_err(|e| wrap("seek", &self.name, e)),
        }
    }
}

impl crate::io::ReadAt for DirFile {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize, crate::io::ReadError> {
        use crate::io::ReadError;
        match &self.file {
            None => Err(ReadError::new(
                0,
                wrap("read", &self.name, Error::Closed.into()),
            )),
            Some(f) => crate::io::ReadAt::read_at(f, buf, offset).map_err(|e| {
                let n = e.read();
                let e = e.into_source();
                ReadError::new(
                    n,
                    if crate::io::is_eof(&e) {
                        e
                    } else {
                        wrap("read", &self.name, e)
                    },
                )
            }),
        }
    }
}

impl File for DirFile {
    fn stat(&self) -> io::Result<Box<dyn FileInfo>> {
        let f = self
            .file
            .as_ref()
            .ok_or_else(|| wrap("stat", &self.name, Error::Closed.into()))?;
        let meta = f.metadata().map_err(|e| wrap("stat", &self.name, e))?;
        Ok(Box::new(StdInfo {
            name: base_name(&self.path, &self.name),
            meta,
        }))
    }

    fn close(&mut self) -> io::Result<()> {
        if self.file.take().is_none() {
            return Err(wrap("close", &self.name, Error::Closed.into()));
        }
        self.entries = None;
        Ok(())
    }

    fn as_seek(&mut self) -> Option<&mut dyn io::Seek> {
        self.file.is_some().then_some(self as &mut dyn io::Seek)
    }

    fn as_reader_at(&self) -> Option<&dyn crate::io::ReadAt> {
        self.file
            .is_some()
            .then_some(self as &dyn crate::io::ReadAt)
    }

    fn as_read_dir_file(&mut self) -> Option<&mut dyn ReadDirFile> {
        let is_dir = self
            .file
            .as_ref()
            .is_some_and(|f| f.metadata().map(|m| m.is_dir()).unwrap_or(false));
        if is_dir {
            Some(self)
        } else {
            None
        }
    }
}

impl ReadDirFile for DirFile {
    fn read_dir(&mut self, n: i32) -> Result<Vec<Box<dyn DirEntry>>, ReadDirError> {
        if self.entries.is_none() {
            self.entries =
                Some(fs::read_dir(&self.path).map_err(|e| wrap("readdirent", &self.name, e))?);
        }
        let it = self.entries.as_mut().expect("entries opened above");
        let mut out: Vec<Box<dyn DirEntry>> = Vec::new();
        loop {
            if n > 0 && out.len() >= n as usize {
                break;
            }
            match it.next() {
                None => {
                    if n > 0 && out.is_empty() {
                        return Err(super::super::eof().into());
                    }
                    break;
                }
                Some(Err(e)) => {
                    return Err(ReadDirError::new(out, wrap("readdirent", &self.name, e)));
                }
                Some(Ok(e)) => out.push(Box::new(StdEntry {
                    name: e.file_name().to_string_lossy().into_owned(),
                    path: e.path(),
                    ft: e
                        .file_type()
                        .map_err(|e| wrap("readdirent", &self.name, e))?,
                })),
            }
        }
        Ok(out)
    }
}

impl FS for DirFS {
    fn open(&self, name: &str) -> io::Result<Box<dyn File>> {
        let full = self.join("open", name)?;
        let file = fs::File::open(&full).map_err(|e| wrap("open", name, e))?;
        Ok(Box::new(DirFile {
            name: name.to_string(),
            path: full,
            file: Some(file),
            entries: None,
        }))
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

impl ReadDirFS for DirFS {
    fn read_dir(&self, name: &str) -> Result<Vec<Box<dyn DirEntry>>, ReadDirError> {
        let full = self.join("readdir", name)?;
        let mut list: Vec<Box<dyn DirEntry>> = Vec::new();
        for e in fs::read_dir(&full).map_err(|e| wrap("open", name, e))? {
            let e = e.map_err(|e| wrap("readdirent", name, e))?;
            list.push(Box::new(StdEntry {
                name: e.file_name().to_string_lossy().into_owned(),
                path: e.path(),
                ft: e.file_type().map_err(|e| wrap("readdirent", name, e))?,
            }));
        }
        list.sort_by(|a, b| a.name().cmp(b.name()));
        Ok(list)
    }
}

impl ReadFileFS for DirFS {
    fn read_file(&self, name: &str) -> io::Result<Vec<u8>> {
        let full = self.join("readfile", name)?;
        // Like Go (`os.ReadFile`), failures are reported as `open` or `read`.
        let mut f = fs::File::open(&full).map_err(|e| wrap("open", name, e))?;
        let mut data = Vec::new();
        f.read_to_end(&mut data)
            .map_err(|e| wrap("read", name, e))?;
        Ok(data)
    }
}

impl StatFS for DirFS {
    fn stat(&self, name: &str) -> io::Result<Box<dyn FileInfo>> {
        let full = self.join("stat", name)?;
        let meta = fs::metadata(&full).map_err(|e| wrap("stat", name, e))?;
        Ok(Box::new(StdInfo {
            name: base_name(&full, name),
            meta,
        }))
    }
}

impl ReadLinkFS for DirFS {
    fn read_link(&self, name: &str) -> io::Result<String> {
        let full = self.join("readlink", name)?;
        let target = fs::read_link(&full).map_err(|e| wrap("readlink", name, e))?;
        Ok(target.to_string_lossy().into_owned())
    }

    fn lstat(&self, name: &str) -> io::Result<Box<dyn FileInfo>> {
        let full = self.join("lstat", name)?;
        let meta = fs::symlink_metadata(&full).map_err(|e| wrap("lstat", name, e))?;
        Ok(Box::new(StdInfo {
            name: base_name(&full, name),
            meta,
        }))
    }
}
