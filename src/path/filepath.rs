//! Go's `path/filepath`: file name manipulation with the operating system's
//! rules (Unix: `/` separates elements, `:` separates lists, no volumes).
//!
//! The lexical functions share their implementation with [`crate::path`],
//! whose Unix semantics are the same. Names are UTF-8 `&str`. The Windows
//! rules (volume names, `\` separators) are not implemented; the module is
//! compiled on Unix only.

use crate::io::fs::{self, DirEntry, FileInfo};
use crate::os;
use std::io;

/// The path separator (`filepath.Separator`).
pub const SEPARATOR: char = '/';
/// The path list separator (`filepath.ListSeparator`).
pub const LIST_SEPARATOR: char = ':';

pub use super::{base, clean, ext, is_abs, join, split};

/// Returns the directory part of `path` (`filepath.Dir`).
pub fn dir(path: &str) -> String {
    super::dir(path)
}

/// Reports whether `name` matches the shell pattern (`filepath.Match`).
///
/// Like Go, malformed patterns are only reported when matching reaches the
/// malformed part, so `matches("a[", "b")` is `Ok(false)`.
pub fn matches(pattern: &str, name: &str) -> Result<bool, super::BadPattern> {
    super::match_pattern(pattern, name, false)
}

/// Returns `path` with each separator replaced by `/` (`filepath.ToSlash`);
/// the identity on Unix.
pub fn to_slash(path: &str) -> String {
    path.to_string()
}

/// Returns `path` with each `/` replaced by the separator
/// (`filepath.FromSlash`); the identity on Unix.
pub fn from_slash(path: &str) -> String {
    path.to_string()
}

/// Splits a list of paths joined by `:` (`filepath.SplitList`); an empty
/// string yields an empty list.
pub fn split_list(path: &str) -> Vec<String> {
    if path.is_empty() {
        return Vec::new();
    }
    path.split(LIST_SEPARATOR).map(str::to_string).collect()
}

/// The leading volume name (`filepath.VolumeName`); always empty on Unix.
pub fn volume_name(path: &str) -> &str {
    let _ = path;
    ""
}

/// Reports whether `path` begins with `prefix` (`filepath.HasPrefix`,
/// deprecated).
pub fn has_prefix(p: &str, prefix: &str) -> bool {
    p.starts_with(prefix)
}

/// Returns an absolute representation of `path` (`filepath.Abs`).
pub fn abs(path: &str) -> io::Result<String> {
    if is_abs(path) {
        return Ok(clean(path));
    }
    let wd = os::getwd()?;
    Ok(join(&[wd.as_str(), path]))
}

/// Reports whether `path` is local: lexically within the directory it is
/// evaluated in, non-empty and not absolute (`filepath.IsLocal`).
pub fn is_local(path: &str) -> bool {
    if is_abs(path) || path.is_empty() {
        return false;
    }
    let has_dots = path.split('/').any(|p| p == "." || p == "..");
    let cleaned;
    let path = if has_dots {
        cleaned = clean(path);
        cleaned.as_str()
    } else {
        path
    };
    !(path == ".." || path.starts_with("../"))
}

/// Converts a slash-separated, valid `io/fs` path into an operating system
/// path (`filepath.Localize`).
pub fn localize(path: &str) -> io::Result<String> {
    if !fs::valid_path(path) || path.contains('\0') {
        return Err(io::Error::other("invalid path"));
    }
    Ok(path.to_string())
}

fn rel_error(targ: &str, base: &str) -> io::Error {
    io::Error::other(format!("Rel: can't make {targ} relative to {base}"))
}

/// Returns a relative path that is lexically equivalent to `targpath` when
/// joined to `basepath` (`filepath.Rel`).
pub fn rel(basepath: &str, targpath: &str) -> io::Result<String> {
    let base = clean(basepath);
    let targ = clean(targpath);
    if targ == base {
        return Ok(".".to_string());
    }
    let base = if base == "." { "" } else { base.as_str() };
    let targ = targ.as_str();
    let (bb, tb) = (base.as_bytes(), targ.as_bytes());
    let base_slashed = bb.first() == Some(&b'/');
    let targ_slashed = tb.first() == Some(&b'/');
    if base_slashed != targ_slashed {
        return Err(rel_error(targpath, basepath));
    }
    let (bl, tl) = (bb.len(), tb.len());
    let (mut b0, mut bi, mut t0, mut ti) = (0, 0, 0, 0);
    loop {
        while bi < bl && bb[bi] != b'/' {
            bi += 1;
        }
        while ti < tl && tb[ti] != b'/' {
            ti += 1;
        }
        if tb[t0..ti] != bb[b0..bi] {
            break;
        }
        if bi < bl {
            bi += 1;
        }
        if ti < tl {
            ti += 1;
        }
        b0 = bi;
        t0 = ti;
    }
    if &base[b0..bi] == ".." {
        return Err(rel_error(targpath, basepath));
    }
    if b0 != bl {
        // Base elements left: go up before going down.
        let seps = base[b0..bl].bytes().filter(|&c| c == b'/').count();
        let mut buf = String::from("..");
        for _ in 0..seps {
            buf.push_str("/..");
        }
        if t0 != tl {
            buf.push('/');
            buf.push_str(&targ[t0..]);
        }
        return Ok(clean(&buf));
    }
    Ok(targ[t0..].to_string())
}

/// Returns `path` after evaluating any symbolic links (`filepath.EvalSymlinks`).
pub fn eval_symlinks(path: &str) -> io::Result<String> {
    let mut path = path.to_string();
    let vol_len = usize::from(path.starts_with('/'));
    let mut dest = path[..vol_len].to_string();
    let mut links_walked = 0;
    let mut end = vol_len;
    loop {
        let mut start = end;
        if start >= path.len() {
            break;
        }
        let b = path.as_bytes();
        while start < b.len() && b[start] == b'/' {
            start += 1;
        }
        end = start;
        while end < b.len() && b[end] != b'/' {
            end += 1;
        }
        if end == start {
            break;
        }
        let comp = path[start..end].to_string();
        if comp == "." {
            continue;
        }
        if comp == ".." {
            // Back up to the previous element, unless there is none or it
            // is itself "..".
            let db = dest.as_bytes();
            let mut r = db.len() as isize - 1;
            while r >= vol_len as isize {
                if db[r as usize] == b'/' {
                    break;
                }
                r -= 1;
            }
            if r < vol_len as isize || &dest[(r + 1) as usize..] == ".." {
                if dest.len() > vol_len {
                    dest.push('/');
                }
                dest.push_str("..");
            } else {
                dest.truncate(r as usize);
            }
            continue;
        }
        if !dest.is_empty() && !dest.ends_with('/') {
            dest.push('/');
        }
        dest.push_str(&comp);
        let fi = os::lstat(&dest)?;
        if fi.mode().0 & fs::MODE_SYMLINK.0 == 0 {
            if !fi.mode().is_dir() && end < path.len() {
                return Err(os::from_errno(os::errno::ENOTDIR));
            }
            continue;
        }
        links_walked += 1;
        if links_walked > 255 {
            return Err(io::Error::other("EvalSymlinks: too many links"));
        }
        let link = os::readlink(&dest)?;
        path = format!("{}{}", link, &path[end..]);
        if link.starts_with('/') {
            dest = "/".to_string();
            end = 1;
        } else {
            let db = dest.as_bytes();
            let mut r = db.len() as isize - 1;
            while r >= vol_len as isize {
                if db[r as usize] == b'/' {
                    break;
                }
                r -= 1;
            }
            if r < vol_len as isize {
                dest.truncate(vol_len);
            } else {
                dest.truncate(r as usize);
            }
            end = 0;
        }
    }
    Ok(clean(&dest))
}

/// One visited file or directory of a [`WalkDir`] walk.
#[derive(Debug)]
pub struct WalkEntry {
    path: String,
    entry: Box<dyn DirEntry>,
}

impl WalkEntry {
    /// The path of the entry: the walk root joined with the names below it.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The final element of the path.
    pub fn name(&self) -> &str {
        self.entry.name()
    }

    /// Reports whether the entry is a directory.
    pub fn is_dir(&self) -> bool {
        self.entry.is_dir()
    }

    /// The type bits of the entry (`DirEntry.Type`).
    pub fn file_type(&self) -> fs::FileMode {
        self.entry.file_type()
    }

    /// The `FileInfo` of the entry; symbolic links are not followed.
    pub fn metadata(&self) -> io::Result<Box<dyn FileInfo>> {
        self.entry.info()
    }

    /// Consumes the entry and returns the directory entry.
    pub fn into_dir_entry(self) -> Box<dyn DirEntry> {
        self.entry
    }
}

/// An error met while walking: reading a directory or a path failed.
#[derive(Debug)]
pub struct WalkError {
    path: String,
    source: io::Error,
}

impl WalkError {
    /// The path the walk could not read.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The underlying error.
    pub fn source(&self) -> &io::Error {
        &self.source
    }

    /// Consumes the error and returns the underlying one.
    pub fn into_source(self) -> io::Error {
        self.source
    }
}

impl std::fmt::Display for WalkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.source, f)
    }
}

impl std::error::Error for WalkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl From<WalkError> for io::Error {
    fn from(e: WalkError) -> io::Error {
        e.source
    }
}

/// The entries of one directory still to be visited.
struct Level {
    path: String,
    /// Each name with its entry, or why the entry could not be examined.
    entries: std::vec::IntoIter<(String, io::Result<Box<dyn DirEntry>>)>,
}

/// The directory just yielded whose contents have not been read yet.
enum Pending {
    /// Read the directory when the walk continues (`WalkDir`).
    Unread { path: String },
    /// The directory was listed before it was visited (`Walk`).
    Listed(Level),
}

/// What the walk yielded last, for [`WalkDir::skip_current_dir`].
enum Last {
    Nothing,
    /// A directory that will be entered unless skipped.
    Dir,
    /// A file, or a failed directory: skipping leaves the rest of its parent.
    File,
    /// A path that could not be examined: skipping does nothing.
    Failed,
}

/// Walks the file tree rooted at a path in lexical order, symbolic links
/// not followed, yielding each file and directory (`filepath.WalkDir` and
/// `filepath.Walk`). A directory is yielded before its contents. The
/// walk ends at the first `None`; stop early by dropping the iterator
/// (`SkipAll`, or returning an error from the callback in Go).
///
/// An item is an error when a path could not be read: a root that does not
/// exist, or a directory whose listing failed. The walk goes on after it.
/// Go's callback returning `SkipDir` is [`WalkDir::skip_current_dir`].
///
/// ```
/// use rust_stdlib::path::filepath::WalkDir;
/// let root = std::env::temp_dir();
/// for item in WalkDir::new(root.to_str().unwrap()).take(3) {
///     let _ = item;
/// }
/// ```
pub struct WalkDir {
    root: Option<String>,
    levels: Vec<Level>,
    pending: Option<Pending>,
    last: Last,
    list_first: bool,
}

impl WalkDir {
    /// A walk of the tree rooted at `root`. A directory whose listing fails
    /// is yielded, then reported as an error (`filepath.WalkDir`).
    pub fn new(root: &str) -> Self {
        WalkDir {
            root: Some(root.to_string()),
            levels: Vec::new(),
            pending: None,
            last: Last::Nothing,
            list_first: false,
        }
    }

    /// Lists each directory before yielding it, so that a directory whose
    /// listing fails is reported once, as an error, and not yielded
    /// (`filepath.Walk`). Entries are examined with `lstat` as they are
    /// found, and a failure of that is an error item for the entry.
    pub fn list_first(mut self) -> Self {
        self.list_first = true;
        self
    }

    /// Skips the rest of the walk below the entry just yielded: for a
    /// directory its contents, for a file the remaining entries of its
    /// directory (`filepath.SkipDir`).
    pub fn skip_current_dir(&mut self) {
        match self.last {
            Last::Dir => self.pending = None,
            Last::File => {
                self.levels.pop();
            }
            Last::Nothing | Last::Failed => {}
        }
        self.last = Last::Nothing;
    }

    /// The directory names, read and sorted as Go's `Walk` does.
    fn list_names(dirname: &str) -> io::Result<Vec<String>> {
        let f = os::open(dirname)?;
        let names = f.readdirnames(-1);
        let _ = f.close();
        let mut names = names?;
        names.sort();
        Ok(names)
    }

    /// Lists `dir` for a walk and returns the level, or why it failed.
    fn open_level(&self, dir: &str) -> io::Result<Level> {
        let entries: Vec<_> = if self.list_first {
            let mut out = Vec::new();
            for name in Self::list_names(dir)? {
                let filename = join(&[dir, name.as_str()]);
                let entry = os::lstat(&filename).map(|info| {
                    fs::file_info_to_dir_entry(Some(info)).expect("entry for Some(info)")
                });
                out.push((name, entry));
            }
            out
        } else {
            os::read_dir(dir)?
                .into_iter()
                .map(|e| (e.name().to_string(), Ok(e)))
                .collect()
        };
        Ok(Level {
            path: dir.to_string(),
            entries: entries.into_iter(),
        })
    }

    /// Yields `entry` at `path`, remembering to enter it if it is a directory.
    fn visit(
        &mut self,
        path: String,
        entry: Box<dyn DirEntry>,
    ) -> Option<Result<WalkEntry, WalkError>> {
        if !entry.is_dir() {
            self.last = Last::File;
            return Some(Ok(WalkEntry { path, entry }));
        }
        self.last = Last::Dir;
        if self.list_first {
            match self.open_level(&path) {
                Ok(level) => self.pending = Some(Pending::Listed(level)),
                Err(source) => {
                    self.last = Last::Failed;
                    return Some(Err(WalkError { path, source }));
                }
            }
        } else {
            self.pending = Some(Pending::Unread { path: path.clone() });
        }
        Some(Ok(WalkEntry { path, entry }))
    }
}

impl Iterator for WalkDir {
    type Item = Result<WalkEntry, WalkError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(root) = self.root.take() {
            return match os::lstat(&root) {
                Err(source) => {
                    self.last = Last::Failed;
                    Some(Err(WalkError { path: root, source }))
                }
                Ok(info) => {
                    let entry =
                        fs::file_info_to_dir_entry(Some(info)).expect("entry for Some(info)");
                    self.visit(root, entry)
                }
            };
        }
        // Enter the directory just yielded, unless it was skipped.
        match self.pending.take() {
            Some(Pending::Listed(level)) => self.levels.push(level),
            Some(Pending::Unread { path }) => match self.open_level(&path) {
                Ok(level) => self.levels.push(level),
                Err(source) => {
                    // Second call, to report the ReadDir error.
                    self.last = Last::Failed;
                    return Some(Err(WalkError { path, source }));
                }
            },
            None => {}
        }
        loop {
            let level = self.levels.last_mut()?;
            let Some((name, entry)) = level.entries.next() else {
                self.levels.pop();
                continue;
            };
            return match entry {
                Ok(entry) => {
                    let path = join(&[level.path.as_str(), name.as_str()]);
                    self.visit(path, entry)
                }
                Err(source) => {
                    self.last = Last::Failed;
                    Some(Err(WalkError {
                        path: join(&[level.path.as_str(), name.as_str()]),
                        source,
                    }))
                }
            };
        }
    }
}

fn bad_pattern() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, super::BadPattern)
}

fn has_meta(path: &str) -> bool {
    path.bytes()
        .any(|b| matches!(b, b'*' | b'?' | b'[' | b'\\'))
}

fn glob_in(dir: &str, pattern: &str, matches_out: &mut Vec<String>) -> io::Result<()> {
    let Ok(fi) = os::stat(dir) else { return Ok(()) };
    if !fi.is_dir() {
        return Ok(());
    }
    let Ok(d) = os::open(dir) else { return Ok(()) };
    let names = d.readdirnames(-1);
    let _ = d.close();
    let mut names = names.unwrap_or_default();
    names.sort();
    for n in names {
        match matches(pattern, &n) {
            Err(_) => return Err(bad_pattern()),
            Ok(true) => matches_out.push(join(&[dir, n.as_str()])),
            Ok(false) => {}
        }
    }
    Ok(())
}

fn glob_with_limit(pattern: &str, depth: usize) -> io::Result<Vec<String>> {
    const PATH_SEPARATORS_LIMIT: usize = 10000;
    if depth == PATH_SEPARATORS_LIMIT {
        return Err(bad_pattern());
    }
    if matches(pattern, "").is_err() {
        return Err(bad_pattern());
    }
    if !has_meta(pattern) {
        if os::lstat(pattern).is_err() {
            return Ok(Vec::new());
        }
        return Ok(vec![pattern.to_string()]);
    }
    let (dir, file) = split(pattern);
    let dir = match dir {
        "" => ".",
        "/" => dir,
        d => &d[..d.len() - 1],
    };
    let mut out = Vec::new();
    if !has_meta(dir) {
        glob_in(dir, file, &mut out)?;
        return Ok(out);
    }
    if dir == pattern {
        return Err(bad_pattern());
    }
    let m = glob_with_limit(dir, depth + 1)?;
    for d in m {
        glob_in(&d, file, &mut out)?;
    }
    Ok(out)
}

/// Returns the names of all files matching `pattern`, or an empty list if
/// none match (`filepath.Glob`). The only possible error is a malformed
/// pattern ([`BadPattern`](super::BadPattern), as an `InvalidData` error).
pub fn glob(pattern: &str) -> io::Result<Vec<String>> {
    glob_with_limit(pattern, 0)
}
