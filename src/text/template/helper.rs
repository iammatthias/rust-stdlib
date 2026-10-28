//! Helper functions to make constructing templates easier (Go
//! `text/template` `helper.go`): `Must`, `ParseFiles`, `ParseGlob` and
//! `ParseFS`.

use super::{Error, Template};
use crate::io::fs::{self, FS};
use crate::path;
use std::io;

fn read_os_dir(dir: &std::path::Path) -> io::Result<Vec<(String, bool)>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let is_dir = e.metadata().map(|m| m.is_dir()).unwrap_or(false);
        out.push((e.file_name().to_string_lossy().into_owned(), is_dir));
    }
    out.sort();
    Ok(out)
}

/// The operating system's files.
pub(crate) struct OsFiles;

fn has_meta(path: &str) -> bool {
    path.contains(['*', '?', '[', '\\'])
}

/// Lists a directory as (entry name, is directory) pairs.
type ReadDir<'a> = &'a dyn Fn(&str) -> io::Result<Vec<(String, bool)>>;

/// Go's `fs.Glob` over a directory lister.
fn glob(
    read_dir: ReadDir<'_>,
    exists: &dyn Fn(&str) -> bool,
    pattern: &str,
) -> Result<Vec<String>, Error> {
    // Check pattern is well-formed.
    path::matches(pattern, "").map_err(|_| Error::Msg("syntax error in pattern".to_owned()))?;
    if !has_meta(pattern) {
        if !exists(pattern) {
            return Ok(Vec::new());
        }
        return Ok(vec![pattern.to_owned()]);
    }
    let (dir, file) = path::split(pattern);
    let dir = clean_glob_path(dir);
    if !has_meta(&dir) {
        return glob_dir(read_dir, &dir, file);
    }
    // Prevent infinite recursion.
    if dir == pattern {
        return Err(Error::Msg("syntax error in pattern".to_owned()));
    }
    let mut m = Vec::new();
    for d in glob(read_dir, exists, &dir)? {
        m.extend(glob_dir(read_dir, &d, file)?);
    }
    Ok(m)
}

fn clean_glob_path(p: &str) -> String {
    if p.is_empty() {
        return ".".to_owned();
    }
    let p = if p.len() > 1 {
        p.trim_end_matches('/')
    } else {
        p
    };
    p.to_owned()
}

fn glob_dir(read_dir: ReadDir<'_>, dir: &str, pattern: &str) -> Result<Vec<String>, Error> {
    let Ok(entries) = read_dir(dir) else {
        return Ok(Vec::new()); // ignore I/O error
    };
    let mut m = Vec::new();
    for (name, _) in entries {
        match path::matches(pattern, &name) {
            Ok(true) => m.push(path::join(&[dir, &name])),
            Ok(false) => {}
            Err(_) => return Err(Error::Msg("syntax error in pattern".to_owned())),
        }
    }
    Ok(m)
}

/// Reads files for the parse helpers.
pub(crate) trait FileSource {
    /// The template name for the file, and its contents.
    fn read(&self, file: &str) -> Result<(String, Vec<u8>), Error>;
}

impl FileSource for OsFiles {
    fn read(&self, file: &str) -> Result<(String, Vec<u8>), Error> {
        let name = path::base(file).to_owned();
        match std::fs::read(file) {
            Ok(b) => Ok((name, b)),
            Err(e) => Err(os_error("open", file, e)),
        }
    }
}

pub(crate) struct FsFiles<'a>(&'a dyn FS);

impl FileSource for FsFiles<'_> {
    fn read(&self, file: &str) -> Result<(String, Vec<u8>), Error> {
        let name = path::base(file).to_owned();
        match fs::read_file(self.0, file) {
            Ok(b) => Ok((name, b)),
            Err(e) => Err(Error::Msg(e.to_string())),
        }
    }
}

fn os_error(op: &str, file: &str, e: io::Error) -> Error {
    let reason = match e.kind() {
        io::ErrorKind::NotFound => "no such file or directory".to_owned(),
        io::ErrorKind::PermissionDenied => "permission denied".to_owned(),
        _ => e.to_string(),
    };
    Error::Msg(format!("{op} {file}: {reason}"))
}

/// A wrapper that panics if the result is an error and otherwise returns the
/// template (Go `template.Must`).
pub fn must(r: Result<Template, Error>) -> Template {
    match r {
        Ok(t) => t,
        Err(e) => panic!("{e}"),
    }
}

/// Creates a new template and parses the template definitions from the named
/// files. The returned template's name will have the base name and parsed
/// contents of the first file (Go `template.ParseFiles`).
pub fn parse_files(filenames: &[&str]) -> Result<Template, Error> {
    parse_files_into(None, &OsFiles, filenames)
}

pub(crate) fn parse_files_into(
    t: Option<Template>,
    src: &dyn FileSource,
    filenames: &[&str],
) -> Result<Template, Error> {
    if filenames.is_empty() {
        // Not really a problem, but be consistent.
        return Err(Error::Msg(
            "template: no files named in call to ParseFiles".to_owned(),
        ));
    }
    let mut t = t;
    for filename in filenames {
        let (name, b) = src.read(filename)?;
        let s = String::from_utf8_lossy(&b).into_owned();
        // First template becomes return value if not already defined, and we
        // use that one for subsequent New calls to associate all the
        // templates together. Also, if this file has the same name as t,
        // this file becomes the contents of t, so t, with name t.Name(),
        // works.
        let tmpl = match &t {
            None => {
                let nt = Template::new(&name);
                t = Some(nt.clone());
                nt
            }
            Some(existing) => {
                if name == existing.name() {
                    existing.clone()
                } else {
                    existing.associated(&name)
                }
            }
        };
        tmpl.parse(&s)?;
    }
    Ok(t.expect("at least one file"))
}

/// Creates a new template and parses the template definitions from the files
/// identified by the pattern (Go `template.ParseGlob`).
pub fn parse_glob(pattern: &str) -> Result<Template, Error> {
    parse_glob_into(None, pattern)
}

pub(crate) fn parse_glob_into(t: Option<Template>, pattern: &str) -> Result<Template, Error> {
    let read_dir = |d: &str| read_os_dir(std::path::Path::new(d));
    let exists = |p: &str| std::path::Path::new(p).exists();
    let filenames = glob(&read_dir, &exists, pattern)?;
    if filenames.is_empty() {
        return Err(Error::Msg(format!(
            "template: pattern matches no files: {}",
            sharp_q(pattern)
        )));
    }
    let names: Vec<&str> = filenames.iter().map(String::as_str).collect();
    parse_files_into(t, &OsFiles, &names)
}

/// The operating system files matching the glob pattern (Go
/// `filepath.Glob`).
pub(crate) fn os_glob(pattern: &str) -> Result<Vec<String>, Error> {
    let read_dir = |d: &str| read_os_dir(std::path::Path::new(d));
    let exists = |p: &str| std::path::Path::new(p).exists();
    glob(&read_dir, &exists, pattern)
}

/// The files of the file system matching the glob pattern (Go `fs.Glob`).
pub(crate) fn fs_glob(fsys: &dyn FS, pattern: &str) -> Result<Vec<String>, Error> {
    fs::glob(fsys, pattern).map_err(|e| Error::Msg(e.to_string()))
}

/// A [`FileSource`] that reads from a file system.
pub(crate) fn fs_files(fsys: &dyn FS) -> FsFiles<'_> {
    FsFiles(fsys)
}

/// Go's `%#q`: a raw string when possible.
pub(crate) fn sharp_q(s: &str) -> String {
    if crate::strconv::can_backquote(s) {
        format!("`{s}`")
    } else {
        crate::strconv::quote(s)
    }
}

/// Creates a new template and parses the template definitions from the files
/// in the file system identified by the patterns (Go `template.ParseFS`).
/// Patterns use [`fs::glob`] semantics.
pub fn parse_fs(fsys: &dyn FS, patterns: &[&str]) -> Result<Template, Error> {
    parse_fs_into(None, fsys, patterns)
}

pub(crate) fn parse_fs_into(
    t: Option<Template>,
    fsys: &dyn FS,
    patterns: &[&str],
) -> Result<Template, Error> {
    let mut filenames: Vec<String> = Vec::new();
    for pattern in patterns {
        let list = fs_glob(fsys, pattern)?;
        if list.is_empty() {
            return Err(Error::Msg(format!(
                "template: pattern matches no files: {}",
                sharp_q(pattern)
            )));
        }
        filenames.extend(list);
    }
    let names: Vec<&str> = filenames.iter().map(String::as_str).collect();
    parse_files_into(t, &FsFiles(fsys), &names)
}
