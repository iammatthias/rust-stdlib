//! An in-memory [`FS`] (Go's `testing/fstest.MapFS`), also the engine behind
//! `embed::FS`.

use super::{
    stat, valid_path, DirEntry, Error, File, FileInfo, FileMode, GlobFS, PathError, ReadDirError,
    ReadDirFS, ReadDirFile, ReadFileFS, ReadLinkFS, StatFS, SubFS, FS, MODE_DIR, MODE_SYMLINK,
};
use crate::time::Time;
use std::any::Any;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io::{self, Read};
use std::sync::Arc;

/// A file in a [`MapFS`] (`fstest.MapFile`).
#[derive(Clone, Debug, Default)]
pub struct MapFile {
    /// File content or symlink destination.
    pub data: Cow<'static, [u8]>,
    /// `FileInfo::mode`.
    pub mode: FileMode,
    /// `FileInfo::mod_time`.
    pub mod_time: Time,
    /// `FileInfo::sys`.
    pub sys: Option<Arc<dyn Any + Send + Sync>>,
}

impl MapFile {
    /// A regular file with the given content and mode bits.
    pub fn new(data: impl Into<Cow<'static, [u8]>>, mode: FileMode) -> MapFile {
        MapFile {
            data: data.into(),
            mode,
            mod_time: Time::default(),
            sys: None,
        }
    }
}

/// A file system built from a map of names to files (`fstest.MapFS`).
///
/// Directories are synthesized from the file names: a name `a/b` implies
/// the directory `a`. An entry with `MODE_DIR` set describes a directory
/// explicitly. Symbolic links are stored (`MODE_SYMLINK`, destination in
/// `data`); `open` follows them (absolute destinations and link loops do not
/// resolve) and `lstat`/`read_link` report the link itself.
#[derive(Clone, Debug, Default)]
pub struct MapFS {
    files: BTreeMap<String, Arc<MapFile>>,
}

impl MapFS {
    /// An empty file system.
    pub fn new() -> MapFS {
        MapFS::default()
    }

    /// Adds or replaces the file `name`.
    pub fn insert(&mut self, name: impl Into<String>, file: MapFile) {
        self.files.insert(name.into(), Arc::new(file));
    }

    /// Returns the explicit entry `name`.
    pub fn get(&self, name: &str) -> Option<&MapFile> {
        self.files.get(name).map(|f| &**f)
    }

    /// Reports whether there are no entries.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    fn synthetic_dir() -> Arc<MapFile> {
        Arc::new(MapFile::new(Vec::new(), MODE_DIR | FileMode(0o555)))
    }

    /// Resolves symbolic links in `name`, including those in parent
    /// directories (Go's `resolveSymlinks`). `None` if a link is absolute,
    /// the result is not a valid path, or the links loop.
    fn resolve_symlinks(&self, name: &str) -> Option<String> {
        self.resolve_symlinks_depth(name, 0)
    }

    fn resolve_symlinks_depth(&self, name: &str, depth: usize) -> Option<String> {
        // Go recurses without bound on a link loop; stop instead.
        if depth > 255 {
            return None;
        }
        // Fast path: if a symlink is in the map, resolve it.
        if let Some(file) = self.files.get(name) {
            if file.mode.file_type() == MODE_SYMLINK {
                let target = String::from_utf8_lossy(&file.data).into_owned();
                if crate::path::is_abs(&target) {
                    return None;
                }
                let joined = crate::path::join(&[crate::path::dir(name), target]);
                return self.resolve_symlinks_depth(&joined, depth + 1);
            }
        }
        // Check if each parent directory (starting at root) is a symlink.
        let mut i = 0;
        while i < name.len() {
            let dir;
            match name[i..].find('/') {
                None => {
                    dir = name;
                    i = name.len();
                }
                Some(j) => {
                    dir = &name[..i + j];
                    i += j;
                }
            }
            if let Some(file) = self.files.get(dir) {
                if file.mode.file_type() == MODE_SYMLINK {
                    let target = String::from_utf8_lossy(&file.data).into_owned();
                    if crate::path::is_abs(&target) {
                        return None;
                    }
                    let joined = crate::path::join(&[crate::path::dir(dir), target]);
                    return self
                        .resolve_symlinks_depth(&format!("{joined}{}", &name[i..]), depth + 1);
                }
            }
            i += 1;
        }
        valid_path(name).then(|| name.to_string())
    }

    fn lstat_info(&self, name: &str) -> Result<MapInfo, Error> {
        if !valid_path(name) {
            return Err(Error::NotExist);
        }
        let real_dir = self
            .resolve_symlinks(&crate::path::dir(name))
            .ok_or(Error::NotExist)?;
        let elem = crate::path::base(name).to_string();
        let real_name = crate::path::join(&[real_dir, elem.clone()]);
        if let Some(f) = self.files.get(&real_name) {
            return Ok(MapInfo {
                name: elem,
                f: f.clone(),
            });
        }
        if real_name == "." {
            return Ok(MapInfo {
                name: elem,
                f: Self::synthetic_dir(),
            });
        }
        let prefix = format!("{real_name}/");
        if self.files.keys().any(|k| k.starts_with(&prefix)) {
            return Ok(MapInfo {
                name: elem,
                f: Self::synthetic_dir(),
            });
        }
        Err(Error::NotExist)
    }
}

impl FromIterator<(String, MapFile)> for MapFS {
    fn from_iter<I: IntoIterator<Item = (String, MapFile)>>(iter: I) -> MapFS {
        let mut m = MapFS::new();
        for (k, v) in iter {
            m.insert(k, v);
        }
        m
    }
}

#[derive(Clone, Debug)]
struct MapInfo {
    name: String,
    f: Arc<MapFile>,
}

impl FileInfo for MapInfo {
    fn name(&self) -> &str {
        &self.name
    }
    fn size(&self) -> i64 {
        self.f.data.len() as i64
    }
    fn mode(&self) -> FileMode {
        self.f.mode
    }
    fn mod_time(&self) -> Time {
        self.f.mod_time.clone()
    }
    fn sys(&self) -> Option<&dyn Any> {
        self.f.sys.as_ref().map(|a| &**a as &dyn Any)
    }
}

impl DirEntry for MapInfo {
    fn name(&self) -> &str {
        &self.name
    }
    fn is_dir(&self) -> bool {
        self.f.mode.is_dir()
    }
    fn file_type(&self) -> FileMode {
        self.f.mode.file_type()
    }
    fn info(&self) -> io::Result<Box<dyn FileInfo>> {
        Ok(Box::new(self.clone()))
    }
}

#[derive(Debug)]
struct OpenFile {
    path: String,
    info: MapInfo,
    offset: usize,
}

impl Read for OpenFile {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let data = &self.info.f.data;
        if self.offset >= data.len() {
            return Ok(0);
        }
        let n = b.len().min(data.len() - self.offset);
        b[..n].copy_from_slice(&data[self.offset..self.offset + n]);
        self.offset += n;
        Ok(n)
    }
}

impl File for OpenFile {
    fn stat(&self) -> io::Result<Box<dyn FileInfo>> {
        Ok(Box::new(self.info.clone()))
    }
    fn as_seek(&mut self) -> Option<&mut dyn io::Seek> {
        Some(self)
    }
    fn as_reader_at(&self) -> Option<&dyn crate::io::ReadAt> {
        Some(self)
    }
}

impl io::Seek for OpenFile {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let len = self.info.f.data.len() as i64;
        let target = match pos {
            io::SeekFrom::Start(o) => i64::try_from(o).unwrap_or(i64::MAX),
            io::SeekFrom::Current(o) => o.wrapping_add(self.offset as i64),
            io::SeekFrom::End(o) => o.wrapping_add(len),
        };
        if target < 0 || target > len {
            return Err(PathError::new("seek", &self.path, Error::Invalid).into());
        }
        self.offset = target as usize;
        Ok(target as u64)
    }
}

impl crate::io::ReadAt for OpenFile {
    fn read_at(&self, b: &mut [u8], offset: u64) -> Result<usize, crate::io::ReadError> {
        use crate::io::ReadError;
        let data = &self.info.f.data;
        if offset > data.len() as u64 {
            return Err(ReadError::new(
                0,
                PathError::new("read", &self.path, Error::Invalid).into(),
            ));
        }
        let src = &data[offset as usize..];
        let n = b.len().min(src.len());
        b[..n].copy_from_slice(&src[..n]);
        if n < b.len() {
            return Err(ReadError::new(n, crate::io::eof()));
        }
        Ok(n)
    }
}

#[derive(Debug)]
struct OpenDir {
    path: String,
    info: MapInfo,
    entries: Vec<MapInfo>,
    offset: usize,
}

impl Read for OpenDir {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(PathError::new("read", &self.path, Error::Invalid).into())
    }
}

impl File for OpenDir {
    fn stat(&self) -> io::Result<Box<dyn FileInfo>> {
        Ok(Box::new(self.info.clone()))
    }
    fn as_read_dir_file(&mut self) -> Option<&mut dyn ReadDirFile> {
        Some(self)
    }
}

impl ReadDirFile for OpenDir {
    fn read_dir(&mut self, count: i32) -> Result<Vec<Box<dyn DirEntry>>, ReadDirError> {
        let mut n = self.entries.len() - self.offset;
        if n == 0 && count > 0 {
            return Err(crate::io::eof().into());
        }
        if count > 0 && n > count as usize {
            n = count as usize;
        }
        let list = self.entries[self.offset..self.offset + n]
            .iter()
            .map(|e| Box::new(e.clone()) as Box<dyn DirEntry>)
            .collect();
        self.offset += n;
        Ok(list)
    }
}

/// The `FS` interface of a [`MapFS`] only, so the package functions run
/// their generic paths (Go's `fsOnly`).
#[derive(Debug)]
pub(super) struct FsOnly<'a>(pub(super) &'a MapFS);

impl FS for FsOnly<'_> {
    fn open(&self, name: &str) -> io::Result<Box<dyn File>> {
        self.0.open(name)
    }
}

impl FS for MapFS {
    fn open(&self, name: &str) -> io::Result<Box<dyn File>> {
        if !valid_path(name) {
            return Err(PathError::new("open", name, Error::NotExist).into());
        }
        let Some(real_name) = self.resolve_symlinks(name) else {
            return Err(PathError::new("open", name, Error::NotExist).into());
        };
        let real_name = real_name.as_str();
        let file = self.files.get(real_name);
        if let Some(f) = file {
            if !f.mode.is_dir() {
                return Ok(Box::new(OpenFile {
                    path: name.to_string(),
                    info: MapInfo {
                        name: crate::path::base(name).to_string(),
                        f: f.clone(),
                    },
                    offset: 0,
                }));
            }
        }
        let mut list: Vec<MapInfo> = Vec::new();
        let mut need: std::collections::BTreeSet<String> = Default::default();
        if real_name == "." {
            for (fname, f) in &self.files {
                match fname.find('/') {
                    None => {
                        if fname != "." {
                            list.push(MapInfo {
                                name: fname.clone(),
                                f: f.clone(),
                            });
                        }
                    }
                    Some(i) => {
                        need.insert(fname[..i].to_string());
                    }
                }
            }
        } else {
            let prefix = format!("{real_name}/");
            for (fname, f) in &self.files {
                if let Some(felem) = fname.strip_prefix(&prefix) {
                    match felem.find('/') {
                        None => list.push(MapInfo {
                            name: felem.to_string(),
                            f: f.clone(),
                        }),
                        Some(i) => {
                            need.insert(felem[..i].to_string());
                        }
                    }
                }
            }
            if file.is_none() && list.is_empty() && need.is_empty() {
                return Err(PathError::new("open", name, Error::NotExist).into());
            }
        }
        for fi in &list {
            need.remove(&fi.name);
        }
        for n in need {
            list.push(MapInfo {
                name: n,
                f: MapFS::synthetic_dir(),
            });
        }
        list.sort_by(|a, b| a.name.cmp(&b.name));
        let f = file.cloned().unwrap_or_else(MapFS::synthetic_dir);
        let elem = if name == "." {
            ".".to_string()
        } else {
            name[name.rfind('/').map_or(0, |i| i + 1)..].to_string()
        };
        Ok(Box::new(OpenDir {
            path: name.to_string(),
            info: MapInfo { name: elem, f },
            entries: list,
            offset: 0,
        }))
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
    fn as_stat_fs(&self) -> Option<&dyn StatFS> {
        Some(self)
    }
    fn as_sub_fs(&self) -> Option<&dyn SubFS> {
        Some(self)
    }
    fn as_read_link_fs(&self) -> Option<&dyn ReadLinkFS> {
        Some(self)
    }
}

impl ReadFileFS for MapFS {
    fn read_file(&self, name: &str) -> io::Result<Vec<u8>> {
        super::read_file(&FsOnly(self), name)
    }
}

impl StatFS for MapFS {
    fn stat(&self, name: &str) -> io::Result<Box<dyn FileInfo>> {
        stat(&FsOnly(self), name)
    }
}

impl ReadDirFS for MapFS {
    fn read_dir(&self, name: &str) -> Result<Vec<Box<dyn DirEntry>>, ReadDirError> {
        super::read_dir(&FsOnly(self), name)
    }
}

impl GlobFS for MapFS {
    fn glob(&self, pattern: &str) -> io::Result<Vec<String>> {
        super::glob(&FsOnly(self), pattern)
    }
}

impl SubFS for MapFS {
    fn sub(&self, dir: &str) -> io::Result<Box<dyn FS + '_>> {
        super::sub_owned(Box::new(FsOnly(self)), dir)
    }
}

impl ReadLinkFS for MapFS {
    fn read_link(&self, name: &str) -> io::Result<String> {
        let info = self
            .lstat_info(name)
            .map_err(|e| std::io::Error::from(PathError::new("readlink", name, e)))?;
        if info.f.mode.file_type() != MODE_SYMLINK {
            return Err(PathError::new("readlink", name, Error::Invalid).into());
        }
        Ok(String::from_utf8_lossy(&info.f.data).into_owned())
    }

    fn lstat(&self, name: &str) -> io::Result<Box<dyn FileInfo>> {
        self.lstat_info(name)
            .map(|i| Box::new(i) as Box<dyn FileInfo>)
            .map_err(|e| PathError::new("lstat", name, e).into())
    }
}
