//! Go's `embed`: a read-only file system over files compiled into the binary.
//!
//! Go embeds files with a `//go:embed` directive. Rust has no equivalent
//! directive, so a file set is a table of `(name, bytes)` pairs built with
//! `include_bytes!`:
//!
//! - [`embed_files!`](crate::embed_files) lists files by path (relative to
//!   the invoking source file, as `include_bytes!` resolves them);
//! - the `embed!` macro of the `rust-stdlib-derive` crate walks directories
//!   and wildcard patterns at compile time with Go's rules (names starting
//!   with `.` or `_` are skipped in embedded directories unless the pattern
//!   starts with `all:`) and expands to the same table.
//!
//! ```
//! use rust_stdlib::embed::FS;
//! use rust_stdlib::io::fs;
//!
//! static ASSETS: FS = FS::new(&[
//!     ("hello.txt", b"hello, world\n"),
//!     ("docs/a.txt", b"a"),
//! ]);
//!
//! assert_eq!(ASSETS.read_file("hello.txt")?, b"hello, world\n");
//! let names: Vec<String> = ASSETS
//!     .read_dir(".")?
//!     .iter()
//!     .map(|e| e.name().to_string())
//!     .collect();
//! assert_eq!(names, ["docs", "hello.txt"]);
//! assert!(fs::valid_path("docs/a.txt"));
//! # Ok::<(), std::io::Error>(())
//! ```

use crate::io::fs::{
    self, valid_path, DirEntry, Error, File, FileInfo, FileMode, PathError, ReadDirError,
    ReadDirFS, ReadDirFile, ReadFileFS, MODE_DIR,
};
use crate::time::Time;
use std::collections::BTreeMap;
use std::io::{self, Read};
use std::sync::{Arc, OnceLock};

/// A read-only collection of files (`embed.FS`).
///
/// Directories are implied by the file names: `a/b.txt` creates the directory
/// `a`. Files have mode `0444`, directories `ModeDir|0555`, and every
/// modification time is the zero `Time`.
#[allow(clippy::upper_case_acronyms)]
pub struct FS {
    files: &'static [(&'static str, &'static [u8])],
    table: OnceLock<Table>,
}

/// Lists every `FS` entry by directory then name: `dir -> elem -> entry`.
type Table = BTreeMap<String, BTreeMap<String, Entry>>;

#[derive(Clone, Debug)]
struct Entry {
    /// Full name; directories end in `/` and the root is `./`, as in Go.
    full_name: String,
    elem: String,
    data: Arc<[u8]>,
    is_dir: bool,
}

impl FS {
    /// Builds a file system from `(name, contents)` pairs. Names must be
    /// valid `fs::valid_path` paths; others are ignored.
    pub const fn new(files: &'static [(&'static str, &'static [u8])]) -> FS {
        FS {
            files,
            table: OnceLock::new(),
        }
    }

    fn table(&self) -> &Table {
        self.table.get_or_init(|| {
            let mut t = Table::new();
            for (name, data) in self.files {
                if *name == "." || !valid_path(name) {
                    continue;
                }
                let parts: Vec<&str> = name.split('/').collect();
                for i in 1..parts.len() {
                    let dir = parts[..i - 1].join("/");
                    let dir = if dir.is_empty() { ".".to_string() } else { dir };
                    t.entry(dir)
                        .or_default()
                        .entry(parts[i - 1].to_string())
                        .or_insert(Entry {
                            full_name: format!("{}/", parts[..i].join("/")),
                            elem: parts[i - 1].to_string(),
                            data: Arc::from(&[][..]),
                            is_dir: true,
                        });
                }
                let dir = parts[..parts.len() - 1].join("/");
                let dir = if dir.is_empty() { ".".to_string() } else { dir };
                let elem = parts[parts.len() - 1].to_string();
                t.entry(dir).or_default().insert(
                    elem.clone(),
                    Entry {
                        full_name: name.to_string(),
                        elem,
                        data: Arc::from(*data),
                        is_dir: false,
                    },
                );
            }
            t
        })
    }

    fn lookup(&self, name: &str) -> Option<Entry> {
        if !valid_path(name) {
            return None;
        }
        if name == "." {
            return Some(Entry {
                full_name: "./".to_string(),
                elem: ".".to_string(),
                data: Arc::from(&[][..]),
                is_dir: true,
            });
        }
        let (dir, elem) = match name.rfind('/') {
            Some(i) => (&name[..i], &name[i + 1..]),
            None => (".", name),
        };
        self.table().get(dir)?.get(elem).cloned()
    }

    fn read_dir_entries(&self, dir: &str) -> Vec<Entry> {
        self.table()
            .get(dir)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }
}

impl Clone for FS {
    fn clone(&self) -> FS {
        FS::new(self.files)
    }
}

impl Default for FS {
    fn default() -> FS {
        FS::new(&[])
    }
}

impl std::fmt::Debug for FS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FS")
            .field("files", &self.files.len())
            .finish()
    }
}

impl FileInfo for Entry {
    fn name(&self) -> &str {
        &self.elem
    }
    fn size(&self) -> i64 {
        self.data.len() as i64
    }
    fn mode(&self) -> FileMode {
        if self.is_dir {
            MODE_DIR | FileMode(0o555)
        } else {
            FileMode(0o444)
        }
    }
    fn mod_time(&self) -> Time {
        Time::default()
    }
}

impl DirEntry for Entry {
    fn name(&self) -> &str {
        &self.elem
    }
    fn is_dir(&self) -> bool {
        self.is_dir
    }
    fn file_type(&self) -> FileMode {
        FileInfo::mode(self).file_type()
    }
    fn info(&self) -> io::Result<Box<dyn FileInfo>> {
        Ok(Box::new(self.clone()))
    }
}

#[derive(Debug)]
struct OpenFile {
    f: Entry,
    offset: i64,
}

impl Read for OpenFile {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        if self.offset >= self.f.data.len() as i64 {
            return Ok(0);
        }
        let n = b.len().min(self.f.data.len() - self.offset as usize);
        b[..n].copy_from_slice(&self.f.data[self.offset as usize..self.offset as usize + n]);
        self.offset += n as i64;
        Ok(n)
    }
}

impl File for OpenFile {
    fn stat(&self) -> io::Result<Box<dyn FileInfo>> {
        Ok(Box::new(self.f.clone()))
    }
    /// Go's embed files implement `io.Seeker`, so `http.FileServerFS` can
    /// serve byte ranges from them.
    fn as_seek(&mut self) -> Option<&mut dyn io::Seek> {
        Some(self)
    }
    fn as_reader_at(&self) -> Option<&dyn crate::io::ReadAt> {
        Some(self)
    }
}

/// Go's `openFile.Seek`: offsets outside `0..=len` are `fs.ErrInvalid`.
impl io::Seek for OpenFile {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let len = self.f.data.len() as i64;
        let target = match pos {
            io::SeekFrom::Start(o) => i64::try_from(o).unwrap_or(i64::MAX),
            io::SeekFrom::Current(o) => o.wrapping_add(self.offset),
            io::SeekFrom::End(o) => o.wrapping_add(len),
        };
        if target < 0 || target > len {
            return Err(PathError::new("seek", &self.f.full_name, Error::Invalid).into());
        }
        self.offset = target;
        Ok(target as u64)
    }
}

/// Go's `openFile.ReadAt`: a short read ends with `io.EOF`.
impl crate::io::ReadAt for OpenFile {
    fn read_at(&self, b: &mut [u8], offset: u64) -> Result<usize, crate::io::ReadError> {
        use crate::io::ReadError;
        let data = &self.f.data;
        if offset > data.len() as u64 {
            return Err(ReadError::new(
                0,
                PathError::new("read", &self.f.full_name, Error::Invalid).into(),
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
    f: Entry,
    files: Vec<Entry>,
    offset: usize,
}

impl Read for OpenDir {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(PathError::new(
            "read",
            &self.f.full_name,
            io::Error::other("is a directory"),
        )
        .into())
    }
}

impl File for OpenDir {
    fn stat(&self) -> io::Result<Box<dyn FileInfo>> {
        Ok(Box::new(self.f.clone()))
    }
    fn as_read_dir_file(&mut self) -> Option<&mut dyn ReadDirFile> {
        Some(self)
    }
}

impl ReadDirFile for OpenDir {
    fn read_dir(&mut self, count: i32) -> Result<Vec<Box<dyn DirEntry>>, ReadDirError> {
        let mut n = self.files.len() - self.offset;
        if n == 0 {
            if count <= 0 {
                return Ok(Vec::new());
            }
            return Err(crate::io::eof().into());
        }
        if count > 0 && n > count as usize {
            n = count as usize;
        }
        let list = self.files[self.offset..self.offset + n]
            .iter()
            .map(|e| Box::new(e.clone()) as Box<dyn DirEntry>)
            .collect();
        self.offset += n;
        Ok(list)
    }
}

impl fs::FS for FS {
    /// `FS.Open`.
    fn open(&self, name: &str) -> io::Result<Box<dyn File>> {
        let Some(file) = self.lookup(name) else {
            return Err(PathError::new("open", name, Error::NotExist).into());
        };
        if file.is_dir {
            let files = self.read_dir_entries(name);
            return Ok(Box::new(OpenDir {
                f: file,
                files,
                offset: 0,
            }));
        }
        Ok(Box::new(OpenFile { f: file, offset: 0 }))
    }

    fn as_read_dir_fs(&self) -> Option<&dyn ReadDirFS> {
        Some(self)
    }

    fn as_read_file_fs(&self) -> Option<&dyn ReadFileFS> {
        Some(self)
    }
}

impl ReadDirFS for FS {
    /// `FS.ReadDir`: reads and returns the entire named directory.
    fn read_dir(&self, name: &str) -> Result<Vec<Box<dyn DirEntry>>, ReadDirError> {
        let Some(file) = self.lookup(name) else {
            return Err(PathError::new("open", name, Error::NotExist).into());
        };
        if !file.is_dir {
            return Err(PathError::new("read", name, io::Error::other("not a directory")).into());
        }
        Ok(self
            .read_dir_entries(name)
            .into_iter()
            .map(|e| Box::new(e) as Box<dyn DirEntry>)
            .collect())
    }
}

impl ReadFileFS for FS {
    /// `FS.ReadFile`: reads and returns the content of the named file.
    fn read_file(&self, name: &str) -> io::Result<Vec<u8>> {
        let Some(file) = self.lookup(name) else {
            return Err(PathError::new("open", name, Error::NotExist).into());
        };
        if file.is_dir {
            return Err(PathError::new("read", name, io::Error::other("is a directory")).into());
        }
        Ok(file.data.to_vec())
    }
}

impl FS {
    /// Opens the named file (`FS.Open`).
    pub fn open(&self, name: &str) -> io::Result<Box<dyn File>> {
        fs::FS::open(self, name)
    }

    /// Reads and returns the entire named directory (`FS.ReadDir`).
    pub fn read_dir(&self, name: &str) -> Result<Vec<Box<dyn DirEntry>>, ReadDirError> {
        ReadDirFS::read_dir(self, name)
    }

    /// Reads and returns the content of the named file (`FS.ReadFile`).
    pub fn read_file(&self, name: &str) -> io::Result<Vec<u8>> {
        ReadFileFS::read_file(self, name)
    }
}

/// Builds an [`FS`] from files listed by path, each embedded with
/// `include_bytes!` (relative to the invoking source file). A pair
/// `"name" => "path"` embeds `path` under a different name.
///
/// See `tests/embed.rs` for a complete example over `tests/fixtures`.
#[macro_export]
macro_rules! embed_files {
    ($($name:literal $(=> $path:literal)?),* $(,)?) => {
        $crate::embed::FS::new(&[
            $( $crate::embed_files!(@entry $name $(=> $path)?) ),*
        ])
    };
    (@entry $name:literal) => {
        ($name, include_bytes!($name) as &'static [u8])
    };
    (@entry $name:literal => $path:literal) => {
        ($name, include_bytes!($path) as &'static [u8])
    };
}
