//! Go's `testing/fstest`: support for testing implementations and users of
//! file systems.
//!
//! [`MapFS`] and [`MapFile`] are the in-memory file system of
//! [`crate::io::fs`], re-exported here; [`test_fs`] is a port of Go's
//! `fstest.TestFS` checker.

use std::{
    collections::BTreeSet,
    error::Error as StdError,
    fmt,
    io::{self, Read},
};

pub use crate::io::fs::{MapFS, MapFile};

use crate::{
    io::{
        fs::{self, DirEntry, File, FileInfo, FS},
        is_eof,
    },
    strconv,
};

use super::iotest::{test_reader, TestableReader};

impl TestableReader for dyn File {
    fn as_seek(&mut self) -> Option<&mut dyn io::Seek> {
        File::as_seek(self)
    }
    fn as_read_at(&self) -> Option<&dyn crate::io::ReadAt> {
        File::as_reader_at(self)
    }
}

/// One problem found by [`test_fs`], keeping the underlying error of Go's
/// `%w` verbs for [`StdError::source`].
#[derive(Debug)]
struct Issue {
    msg: String,
    source: Option<io::Error>,
}

impl fmt::Display for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

impl StdError for Issue {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source.as_ref().map(|e| e as &(dyn StdError + 'static))
    }
}

/// The error returned by [`test_fs`]: a list of the misbehaviours found.
#[derive(Debug)]
pub struct TestFSError {
    prefix: String,
    errors: Vec<io::Error>,
}

impl TestFSError {
    /// The individual problems, in the order they were found.
    pub fn errors(&self) -> &[io::Error] {
        &self.errors
    }
}

impl fmt::Display for TestFSError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}TestFS found errors:", self.prefix)?;
        for (i, e) in self.errors.iter().enumerate() {
            if i > 0 {
                f.write_str("\n")?;
            }
            write!(f, "{e}")?;
        }
        Ok(())
    }
}

impl StdError for TestFSError {
    /// The first problem; use [`errors`](TestFSError::errors) to browse all
    /// of them, as `errors.Is` does over Go's joined list.
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.errors.first().map(|e| e as &(dyn StdError + 'static))
    }
}

/// Go's `fstest.TestFS`: tests a file system implementation.
///
/// It walks the entire tree of files in `fsys`, opening and checking that
/// each file behaves correctly. Symbolic links are not followed, but their
/// `lstat` values are checked if the file system implements
/// [`ReadLinkFS`](fs::ReadLinkFS). It also checks that the file system
/// contains at least the `expected` files; if none are listed, `fsys` must be
/// empty. The contents of `fsys` must not change concurrently.
///
/// If a misbehaviour is found it returns the first error, or an
/// `io::Error` wrapping a [`TestFSError`] listing all of them.
pub fn test_fs(fsys: &dyn FS, expected: &[&str]) -> io::Result<()> {
    test_fs_inner(fsys, expected, "").map_err(|e| match e {
        Failure::List(l) => {
            // The kind of the first problem that has one, so that
            // `fs::Error::is` finds a wrapped sentinel like `errors.Is` does.
            let kind = l
                .errors
                .iter()
                .map(io::Error::kind)
                .find(|k| *k != io::ErrorKind::Other)
                .unwrap_or(io::ErrorKind::Other);
            io::Error::new(kind, l)
        }
        Failure::Plain(e) => e,
    })
}

enum Failure {
    List(TestFSError),
    Plain(io::Error),
}

fn test_fs_inner(fsys: &dyn FS, expected: &[&str], prefix: &str) -> Result<(), Failure> {
    if let Some(list) = run_test_fs(fsys, expected, prefix) {
        return Err(Failure::List(list));
    }
    if prefix.is_empty() {
        for name in expected {
            if let Some(i) = name.find('/') {
                let (dir, dir_slash) = (&name[..i], &name[..=i]);
                let sub_expected: Vec<&str> = expected
                    .iter()
                    .filter_map(|n| n.strip_prefix(dir_slash))
                    .collect();
                let sub = fs::sub(fsys, dir).map_err(Failure::Plain)?;
                let p = format!("testing fs.Sub(fsys, {dir}): ");
                if let Some(list) = run_test_fs(&*sub, &sub_expected, &p) {
                    return Err(Failure::List(list));
                }
                break; // one sub-test is enough
            }
        }
    }
    Ok(())
}

fn run_test_fs(fsys: &dyn FS, expected: &[&str], prefix: &str) -> Option<TestFSError> {
    let mut t = FsTester {
        fsys,
        errors: Vec::new(),
        dirs: Vec::new(),
        files: Vec::new(),
    };
    t.check_dir(".");
    t.check_open(".");
    let mut found: BTreeSet<String> = BTreeSet::new();
    found.extend(t.dirs.iter().cloned());
    found.extend(t.files.iter().cloned());
    found.remove(".");
    if expected.is_empty() && !found.is_empty() {
        let mut list: Vec<String> = found.iter().cloned().collect();
        if list.len() > 15 {
            list.truncate(10);
            list.push("...".to_string());
        }
        t.errorf(format!(
            "expected empty file system but found files:\n{}",
            list.join("\n")
        ));
    }
    for name in expected {
        if !found.contains(*name) {
            t.errorf(format!("expected but not found: {name}"));
        }
    }
    if t.errors.is_empty() {
        None
    } else {
        Some(TestFSError {
            prefix: prefix.to_string(),
            errors: t.errors,
        })
    }
}

/// `%#q`: a raw string if possible, else a double-quoted one.
fn quote_sharp(s: &str) -> String {
    if strconv::can_backquote(s) {
        format!("`{s}`")
    } else {
        strconv::quote(s)
    }
}

/// `%w` of a possibly nil error.
fn werr(e: &Option<io::Error>) -> String {
    match e {
        None => "%!w(<nil>)".to_string(),
        Some(e) => e.to_string(),
    }
}

fn type_of(f: &dyn fmt::Debug) -> String {
    let s = format!("{f:?}");
    s.split([' ', '{', '(']).next().unwrap_or("").to_string()
}

fn format_entry(e: &dyn DirEntry) -> String {
    format!("{} IsDir={} Type={}", e.name(), e.is_dir(), e.file_type())
}

fn format_info_entry(i: &dyn FileInfo) -> String {
    format!(
        "{} IsDir={} Type={}",
        i.name(),
        i.is_dir(),
        i.mode().file_type()
    )
}

fn format_info(i: &dyn FileInfo) -> String {
    format!(
        "{} IsDir={} Mode={} Size={} ModTime={}",
        i.name(),
        i.is_dir(),
        i.mode(),
        i.size(),
        i.mod_time()
    )
}

struct FsTester<'a> {
    fsys: &'a dyn FS,
    errors: Vec<io::Error>,
    dirs: Vec<String>,
    files: Vec<String>,
}

type Entries = Vec<Box<dyn DirEntry>>;

fn read_dir_file(f: &mut Box<dyn File>) -> &mut dyn fs::ReadDirFile {
    f.as_read_dir_file().expect("checked by open_dir")
}

impl FsTester<'_> {
    fn errorf(&mut self, msg: String) {
        self.errors
            .push(io::Error::other(Issue { msg, source: None }));
    }

    /// An error whose text is `prefix` followed by `err` (a `%w` verb).
    fn errorw(&mut self, prefix: String, err: io::Error) {
        let msg = format!("{prefix}{err}");
        let kind = err.kind();
        self.errors.push(io::Error::new(
            kind,
            Issue {
                msg,
                source: Some(err),
            },
        ));
    }

    fn open_dir(&mut self, dir: &str) -> Option<Box<dyn File>> {
        match self.fsys.open(dir) {
            Err(e) => {
                self.errorw(format!("{dir}: Open: "), e);
                None
            }
            Ok(mut f) => {
                if f.as_read_dir_file().is_none() {
                    let _ = f.close();
                    let ty = type_of(&f);
                    self.errorf(format!(
                        "{dir}: Open returned File type {ty}, not a fs.ReadDirFile"
                    ));
                    return None;
                }
                Some(f)
            }
        }
    }

    /// Checks the directory `dir`, which is expected to exist (it is the root
    /// or was found in a directory listing with `is_dir` true).
    fn check_dir(&mut self, dir: &str) {
        self.dirs.push(dir.to_string());
        let Some(mut d) = self.open_dir(dir) else {
            return;
        };
        // Read entire directory.
        let list = match read_dir_file(&mut d).read_dir(-1) {
            Ok(l) => l,
            Err(e) => {
                let _ = d.close();
                self.errorw(format!("{dir}: ReadDir(-1): "), e.into_source());
                return;
            }
        };

        // Check all children.
        let prefix = if dir == "." {
            String::new()
        } else {
            format!("{dir}/")
        };
        for info in &list {
            let name = info.name();
            if name == "." || name == ".." || name.is_empty() {
                self.errorf(format!(
                    "{dir}: ReadDir: child has invalid name: {}",
                    quote_sharp(name)
                ));
                continue;
            }
            if name.contains('/') {
                self.errorf(format!(
                    "{dir}: ReadDir: child name contains slash: {}",
                    quote_sharp(name)
                ));
                continue;
            }
            if name.contains('\\') {
                self.errorf(format!(
                    "{dir}: ReadDir: child name contains backslash: {}",
                    quote_sharp(name)
                ));
                continue;
            }
            let path = format!("{prefix}{name}");
            self.check_stat(&path, &**info);
            self.check_open(&path);
            let ty = info.file_type();
            if ty == fs::MODE_DIR {
                self.check_dir(&path);
            } else if ty == fs::MODE_SYMLINK {
                // No further processing: do not follow symlinks.
                self.files.push(path);
            } else {
                self.check_file(&path);
            }
        }

        // Check ReadDir(-1) at EOF.
        let r = read_dir_file(&mut d).read_dir(-1);
        let (n, err) = match r {
            Ok(l) => (l.len(), None),
            Err(e) => (0, Some(e.into_source())),
        };
        if n > 0 || err.is_some() {
            let _ = d.close();
            self.errorf(format!(
                "{dir}: ReadDir(-1) at EOF = {n} entries, {}, wanted 0 entries, nil",
                werr(&err)
            ));
            return;
        }

        // Check ReadDir(1) at EOF (different results).
        let r = read_dir_file(&mut d).read_dir(1);
        let (n, err) = match r {
            Ok(l) => (l.len(), None),
            Err(e) => (0, Some(e.into_source())),
        };
        if n > 0 || !err.as_ref().is_some_and(is_eof) {
            let _ = d.close();
            self.errorf(format!(
                "{dir}: ReadDir(1) at EOF = {n} entries, {}, wanted 0 entries, EOF",
                werr(&err)
            ));
            return;
        }

        // Check that close does not report an error.
        if let Err(e) = d.close() {
            self.errorw(format!("{dir}: Close: "), e);
        }
        // Check that closing twice doesn't crash.
        let _ = d.close();

        // Reopen directory, read a second time, make sure contents match.
        let Some(mut d) = self.open_dir(dir) else {
            return;
        };
        let list2 = match read_dir_file(&mut d).read_dir(-1) {
            Ok(l) => l,
            Err(e) => {
                self.errorw(format!("{dir}: second Open+ReadDir(-1): "), e.into_source());
                let _ = d.close();
                return;
            }
        };
        let _ = d.close();
        self.check_dir_list(
            dir,
            "first Open+ReadDir(-1) vs second Open+ReadDir(-1)",
            &list,
            &list2,
        );

        // Reopen directory, read a third time in pieces, make sure contents match.
        let Some(mut d) = self.open_dir(dir) else {
            return;
        };
        let mut list2: Entries = Vec::new();
        loop {
            let n: i32 = if list2.is_empty() { 1 } else { 2 };
            let (frag, err) = match read_dir_file(&mut d).read_dir(n) {
                Ok(f) => (f, None),
                Err(e) => {
                    let (list, source) = e.into_parts();
                    (list, Some(source))
                }
            };
            if frag.len() > n as usize {
                self.errorf(format!(
                    "{dir}: third Open: ReadDir({n}) after {}: {} entries (too many)",
                    list2.len(),
                    frag.len()
                ));
                let _ = d.close();
                return;
            }
            list2.extend(frag);
            match err {
                Some(e) if is_eof(&e) => break,
                Some(e) => {
                    self.errorw(
                        format!("{dir}: third Open: ReadDir({n}) after {}: ", list2.len()),
                        e,
                    );
                    let _ = d.close();
                    return;
                }
                None => {}
            }
        }
        let _ = d.close();
        self.check_dir_list(
            dir,
            "first Open+ReadDir(-1) vs third Open+ReadDir(1,2) loop",
            &list,
            &list2,
        );

        // If fsys has ReadDir, check that it matches and is sorted.
        if let Some(rd) = self.fsys.as_read_dir_fs() {
            let list2 = match rd.read_dir(dir) {
                Ok(l) => l,
                Err(e) => {
                    self.errorw(format!("{dir}: fsys.ReadDir: "), e.into_source());
                    return;
                }
            };
            self.check_dir_list(dir, "first Open+ReadDir(-1) vs fsys.ReadDir", &list, &list2);
            for w in list2.windows(2) {
                if w[0].name() >= w[1].name() {
                    self.errorf(format!(
                        "{dir}: fsys.ReadDir: list not sorted: {} before {}",
                        w[0].name(),
                        w[1].name()
                    ));
                }
            }
        }

        // Check fs.ReadDir as well.
        let list2 = match fs::read_dir(self.fsys, dir) {
            Ok(l) => l,
            Err(e) => {
                self.errorw(format!("{dir}: fs.ReadDir: "), e.into_source());
                return;
            }
        };
        self.check_dir_list(dir, "first Open+ReadDir(-1) vs fs.ReadDir", &list, &list2);
        for w in list2.windows(2) {
            if w[0].name() >= w[1].name() {
                self.errorf(format!(
                    "{dir}: fs.ReadDir: list not sorted: {} before {}",
                    w[0].name(),
                    w[1].name()
                ));
            }
        }

        self.check_glob(dir, &list2);
    }

    /// Checks that various glob patterns work if the file system implements
    /// `GlobFS`.
    fn check_glob(&mut self, dir: &str, list: &Entries) {
        let Some(gfs) = self.fsys.as_glob_fs() else {
            return;
        };
        // Make a complex glob pattern prefix that only matches dir.
        let mut glob = String::new();
        if dir != "." {
            let mut elems: Vec<String> = dir.split('/').map(str::to_string).collect();
            for (i, e) in elems.iter_mut().enumerate() {
                let mut pattern = String::new();
                for (j, r) in e.chars().enumerate() {
                    if matches!(r, '*' | '?' | '\\' | '[' | '-') {
                        pattern.push('\\');
                        pattern.push(r);
                        continue;
                    }
                    match (i + j) % 5 {
                        0 => pattern.push(r),
                        1 => {
                            pattern.push('[');
                            pattern.push(r);
                            pattern.push(']');
                        }
                        2 => {
                            pattern.push('[');
                            pattern.push(r);
                            pattern.push('-');
                            pattern.push(r);
                            pattern.push(']');
                        }
                        3 => {
                            pattern.push_str("[\\");
                            pattern.push(r);
                            pattern.push(']');
                        }
                        _ => {
                            pattern.push_str("[\\");
                            pattern.push(r);
                            pattern.push_str("-\\");
                            pattern.push(r);
                            pattern.push(']');
                        }
                    }
                }
                *e = pattern;
            }
            glob = elems.join("/") + "/";
        }

        // Test that malformed patterns are detected.
        let bad = format!("{glob}nonexist/[]");
        if gfs.glob(&bad).is_ok() {
            self.errorf(format!(
                "{dir}: Glob({}): bad pattern not detected",
                quote_sharp(&bad)
            ));
        }

        // Try to find a letter that appears in only some of the final names.
        let mut c = 'a';
        while c <= 'z' {
            let mut have = false;
            let mut have_not = false;
            for d in list {
                if d.name().contains(c) {
                    have = true;
                } else {
                    have_not = true;
                }
            }
            if have && have_not {
                break;
            }
            c = (c as u8 + 1) as char;
        }
        if c > 'z' {
            c = 'a';
        }
        glob.push('*');
        glob.push(c);
        glob.push('*');

        let mut want: Vec<String> = Vec::new();
        for d in list {
            if d.name().contains(c) {
                want.push(crate::path::join(&[dir, d.name()]));
            }
        }

        let mut names = match gfs.glob(&glob) {
            Ok(n) => n,
            Err(e) => {
                self.errorw(format!("{dir}: Glob({}): ", quote_sharp(&glob)), e);
                return;
            }
        };
        if want == names {
            return;
        }
        if !names.windows(2).all(|w| w[0] <= w[1]) {
            self.errorf(format!(
                "{dir}: Glob({}): unsorted output:\n{}",
                quote_sharp(&glob),
                names.join("\n")
            ));
            names.sort();
        }
        let mut problems: Vec<String> = Vec::new();
        let (mut wi, mut ni) = (0, 0);
        while wi < want.len() || ni < names.len() {
            if wi < want.len() && ni < names.len() && want[wi] == names[ni] {
                wi += 1;
                ni += 1;
            } else if wi < want.len() && (ni == names.len() || want[wi] < names[ni]) {
                problems.push(format!("missing: {}", want[wi]));
                wi += 1;
            } else {
                problems.push(format!("extra: {}", names[ni]));
                ni += 1;
            }
        }
        self.errorf(format!(
            "{dir}: Glob({}): wrong output:\n{}",
            quote_sharp(&glob),
            problems.join("\n")
        ));
    }

    /// Checks that a direct stat of `path` matches `entry`, which was found
    /// in the parent's directory listing.
    fn check_stat(&mut self, path: &str, entry: &dyn DirEntry) {
        let mut file = match self.fsys.open(path) {
            Ok(f) => f,
            Err(e) => {
                self.errorw(format!("{path}: Open: "), e);
                return;
            }
        };
        let info = file.stat();
        let _ = file.close();
        let info = match info {
            Ok(i) => i,
            Err(e) => {
                self.errorw(format!("{path}: Stat: "), e);
                return;
            }
        };
        let fentry = format_entry(entry);
        let fientry = format_info_entry(&*info);
        let is_link = entry.file_type().0 & fs::MODE_SYMLINK.0 != 0;
        // A mismatch is fine for a symlink, because Open dereferences it.
        if fentry != fientry && !is_link {
            self.errorf(format!(
                "{path}: mismatch:\n\tentry = {fentry}\n\tfile.Stat() = {fientry}"
            ));
        }

        let einfo = match entry.info() {
            Ok(i) => i,
            Err(e) => {
                self.errorw(format!("{path}: entry.Info: "), e);
                return;
            }
        };
        let finfo = format_info(&*info);
        if is_link {
            // For a symlink, just check that entry.Info matches entry on
            // common fields.
            let feentry = format_info_entry(&*einfo);
            if fentry != feentry {
                self.errorf(format!(
                    "{path}: mismatch\n\tentry = {fentry}\n\tentry.Info() = {feentry}\n"
                ));
            }
        } else {
            let feinfo = format_info(&*einfo);
            if feinfo != finfo {
                self.errorf(format!(
                    "{path}: mismatch:\n\tentry.Info() = {feinfo}\n\tfile.Stat() = {finfo}\n"
                ));
            }
        }

        // Stat should be the same as Open+Stat, even for symlinks.
        let info2 = match fs::stat(self.fsys, path) {
            Ok(i) => i,
            Err(e) => {
                self.errorw(format!("{path}: fs.Stat: "), e);
                return;
            }
        };
        let finfo2 = format_info(&*info2);
        if finfo2 != finfo {
            self.errorf(format!("{path}: fs.Stat(...) = {finfo2}\n\twant {finfo}"));
        }

        if let Some(sfs) = self.fsys.as_stat_fs() {
            let info2 = match sfs.stat(path) {
                Ok(i) => i,
                Err(e) => {
                    self.errorw(format!("{path}: fsys.Stat: "), e);
                    return;
                }
            };
            let finfo2 = format_info(&*info2);
            if finfo2 != finfo {
                self.errorf(format!("{path}: fsys.Stat(...) = {finfo2}\n\twant {finfo}"));
            }
        }

        if let Some(lfs) = self.fsys.as_read_link_fs() {
            let info2 = match lfs.lstat(path) {
                Ok(i) => i,
                Err(e) => {
                    self.errorf(format!("{path}: fsys.Lstat: {e}"));
                    return;
                }
            };
            let fientry2 = format_info_entry(&*info2);
            if fentry != fientry2 {
                self.errorf(format!(
                    "{path}: mismatch:\n\tentry = {fentry}\n\tfsys.Lstat(...) = {fientry2}"
                ));
            }
            let feinfo = format_info(&*einfo);
            let finfo2 = format_info(&*info2);
            if feinfo != finfo2 {
                self.errorf(format!(
                    "{path}: mismatch:\n\tentry.Info() = {feinfo}\n\tfsys.Lstat(...) = {finfo2}\n"
                ));
            }
        }
    }

    /// Checks that two directory lists contain the same files and file info.
    /// The order of the lists need not match.
    fn check_dir_list(&mut self, dir: &str, desc: &str, list1: &Entries, list2: &Entries) {
        let mut old: Vec<(String, &dyn DirEntry)> = Vec::new();
        let mut errs: Vec<String> = Vec::new();
        let mut check_mode = |entry: &dyn DirEntry| {
            let is_dir_type = entry.file_type().0 & fs::MODE_DIR.0 != 0;
            if entry.is_dir() != is_dir_type {
                if entry.is_dir() {
                    errs.push(format!(
                        "{dir}: ReadDir returned {} with IsDir() = true, Type() & ModeDir = 0",
                        entry.name()
                    ));
                } else {
                    errs.push(format!(
                        "{dir}: ReadDir returned {} with IsDir() = false, Type() & ModeDir = ModeDir",
                        entry.name()
                    ));
                }
            }
        };
        for e in list1 {
            if let Some(slot) = old.iter_mut().find(|(n, _)| n == e.name()) {
                slot.1 = &**e;
            } else {
                old.push((e.name().to_string(), &**e));
            }
            check_mode(&**e);
        }
        let mut diffs: Vec<String> = Vec::new();
        for entry2 in list2 {
            match old.iter().position(|(n, _)| n == entry2.name()) {
                None => {
                    check_mode(&**entry2);
                    diffs.push(format!("+ {}", format_entry(&**entry2)));
                }
                Some(pos) => {
                    let entry1 = old[pos].1;
                    if format_entry(entry1) != format_entry(&**entry2) {
                        diffs.push(format!("- {}", format_entry(entry1)));
                        diffs.push(format!("+ {}", format_entry(&**entry2)));
                    }
                    old.remove(pos);
                }
            }
        }
        for (_, e) in &old {
            diffs.push(format!("- {}", format_entry(*e)));
        }
        for e in errs {
            self.errorf(e);
        }
        if diffs.is_empty() {
            return;
        }
        // Sort by name, then "+" before "-".
        diffs.sort_by(|a, b| {
            let fa: Vec<&str> = a.split_whitespace().collect();
            let fb: Vec<&str> = b.split_whitespace().collect();
            let ka = format!("{} {}", fa[1], fb[0]);
            let kb = format!("{} {}", fb[1], fa[0]);
            ka.cmp(&kb)
        });
        self.errorf(format!("{dir}: diff {desc}:\n\t{}", diffs.join("\n\t")));
    }

    /// Checks that basic file reading works correctly.
    fn check_file(&mut self, file: &str) {
        self.files.push(file.to_string());

        // Read entire file.
        let mut f = match self.fsys.open(file) {
            Ok(f) => f,
            Err(e) => {
                self.errorw(format!("{file}: Open: "), e);
                return;
            }
        };
        let mut data = Vec::new();
        if let Err(e) = read_all(&mut *f, &mut data) {
            let _ = f.close();
            self.errorw(format!("{file}: Open+ReadAll: "), e);
            return;
        }
        if let Err(e) = f.close() {
            self.errorw(format!("{file}: Close: "), e);
        }
        // Check that closing twice doesn't crash.
        let _ = f.close();

        // Check that ReadFile works if present.
        if let Some(rfs) = self.fsys.as_read_file_fs() {
            let mut data2 = match rfs.read_file(file) {
                Ok(d) => d,
                Err(e) => {
                    self.errorw(format!("{file}: fsys.ReadFile: "), e);
                    return;
                }
            };
            self.check_file_read(file, "ReadAll vs fsys.ReadFile", &data, &data2);

            // Modifying the returned bytes should not affect the next call.
            for b in &mut data2 {
                *b = b.wrapping_add(1);
            }
            let data2 = match rfs.read_file(file) {
                Ok(d) => d,
                Err(e) => {
                    self.errorw(format!("{file}: second call to fsys.ReadFile: "), e);
                    return;
                }
            };
            self.check_file_read(file, "Readall vs second fsys.ReadFile", &data, &data2);

            let mut bad_results = Vec::new();
            check_bad_path(
                file,
                "ReadFile",
                &mut |name| rfs.read_file(name).map(|_| ()),
                &mut bad_results,
            );
            for m in bad_results {
                self.errorf(m);
            }
        }

        // Check that fs.ReadFile works with t.fsys.
        let data2 = match fs::read_file(self.fsys, file) {
            Ok(d) => d,
            Err(e) => {
                self.errorw(format!("{file}: fs.ReadFile: "), e);
                return;
            }
        };
        self.check_file_read(file, "ReadAll vs fs.ReadFile", &data, &data2);

        // Use iotest.TestReader to check small reads, Seek, ReadAt.
        let mut f = match self.fsys.open(file) {
            Ok(f) => f,
            Err(e) => {
                self.errorw(format!("{file}: second Open: "), e);
                return;
            }
        };
        if let Err(e) = test_reader(&mut f, &data) {
            self.errorf(format!(
                "{file}: failed TestReader:\n\t{}",
                e.to_string().replace('\n', "\n\t")
            ));
        }
        let _ = f.close();
    }

    fn check_file_read(&mut self, file: &str, desc: &str, data1: &[u8], data2: &[u8]) {
        if data1 != data2 {
            self.errorf(format!(
                "{file}: {desc}: different data returned\n\t{}\n\t{}",
                strconv::quote(data1),
                strconv::quote(data2)
            ));
        }
    }

    /// Validates file opening behavior by attempting to open and close the
    /// given file path with various invalid forms.
    fn check_open(&mut self, file: &str) {
        let fsys = self.fsys;
        let mut results = Vec::new();
        check_bad_path(
            file,
            "Open",
            &mut |name| {
                let mut f = fsys.open(name)?;
                let _ = f.close();
                Ok(())
            },
            &mut results,
        );
        for m in results {
            self.errorf(m);
        }
    }
}

fn read_all(r: &mut dyn Read, out: &mut Vec<u8>) -> io::Result<()> {
    let mut buf = [0u8; 4096];
    loop {
        match r.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// Checks that various invalid forms of `file`'s name cannot be opened using
/// `open`; failures are appended to `out`.
fn check_bad_path(
    file: &str,
    desc: &str,
    open: &mut dyn FnMut(&str) -> io::Result<()>,
    out: &mut Vec<String>,
) {
    let mut bad = vec![format!("/{file}"), format!("{file}/.")];
    if file == "." {
        bad.push("/".to_string());
    }
    if let Some(i) = file.find('/') {
        bad.push(format!("{}//{}", &file[..i], &file[i + 1..]));
        bad.push(format!("{}/./{}", &file[..i], &file[i + 1..]));
        bad.push(format!("{}\\{}", &file[..i], &file[i + 1..]));
        bad.push(format!("{}/../{}", &file[..i], file));
    }
    if let Some(i) = file.rfind('/') {
        bad.push(format!("{}//{}", &file[..i], &file[i + 1..]));
        bad.push(format!("{}/./{}", &file[..i], &file[i + 1..]));
        bad.push(format!("{}\\{}", &file[..i], &file[i + 1..]));
        bad.push(format!("{file}/../{}", &file[i + 1..]));
    }
    for b in bad {
        if open(&b).is_ok() {
            out.push(format!("{file}: {desc}({b}) succeeded, want error"));
        }
    }
}
