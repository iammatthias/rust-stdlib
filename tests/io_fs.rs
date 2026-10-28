//! Tests for `rust_stdlib::io::fs`, ported from
//! Go's `io/fs` tests (fs_test.go, format_test.go, glob_test.go,
//! walk_test.go, sub_test.go) and run against `MapFS` and the real
//! file system through `DirFS` (BSD license, see NOTICE).

use rust_stdlib::io as rio;
use rust_stdlib::io::fs::{
    self, DirEntry, DirFS, FileInfo, FileMode, GlobFS, MapFS, MapFile, FS, MODE_APPEND,
    MODE_CHAR_DEVICE, MODE_DEVICE, MODE_DIR, MODE_EXCLUSIVE, MODE_IRREGULAR, MODE_NAMED_PIPE,
    MODE_PERM, MODE_SETGID, MODE_SETUID, MODE_SOCKET, MODE_STICKY, MODE_SYMLINK, MODE_TEMPORARY,
    MODE_TYPE,
};
use rust_stdlib::time::{self, Time};
use std::fs as stdfs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// A temporary directory removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> TempDir {
        TempDir(std::path::PathBuf::from(
            rust_stdlib::os::mkdir_temp("", name).expect("temp dir"),
        ))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = stdfs::remove_dir_all(&self.0);
    }
}

fn names(list: &[Box<dyn DirEntry>]) -> Vec<String> {
    list.iter().map(|e| e.name().to_string()).collect()
}

fn map(entries: &[(&str, &str)]) -> MapFS {
    let mut m = MapFS::new();
    for (name, data) in entries {
        m.insert(
            *name,
            MapFile::new(data.as_bytes().to_vec(), FileMode(0o644)),
        );
    }
    m
}

// ---------------------------------------------------------------- fs.go

#[test]
fn valid_path_table() {
    // TestValidPath
    for (name, ok) in [
        (".", true),
        ("x", true),
        ("x/y", true),
        ("", false),
        ("..", false),
        ("/", false),
        ("x/", false),
        ("/x", false),
        ("x/y/", false),
        ("/x/y", false),
        ("./", false),
        ("./x", false),
        ("x/.", false),
        ("x/./y", false),
        ("../", false),
        ("../x", false),
        ("x/..", false),
        ("x/../y", false),
        ("x//y", false),
        ("x\\", true),
        ("x\\y", true),
        ("x:y", true),
        ("\\x", true),
    ] {
        assert_eq!(fs::valid_path(name), ok, "ValidPath({name:?})");
    }
}

#[test]
fn file_mode_bits_and_strings() {
    // Bit values and String, from Go's os/fs mode tests.
    assert_eq!(MODE_DIR.0, 1 << 31);
    assert_eq!(MODE_APPEND.0, 1 << 30);
    assert_eq!(MODE_EXCLUSIVE.0, 1 << 29);
    assert_eq!(MODE_TEMPORARY.0, 1 << 28);
    assert_eq!(MODE_SYMLINK.0, 1 << 27);
    assert_eq!(MODE_DEVICE.0, 1 << 26);
    assert_eq!(MODE_NAMED_PIPE.0, 1 << 25);
    assert_eq!(MODE_SOCKET.0, 1 << 24);
    assert_eq!(MODE_SETUID.0, 1 << 23);
    assert_eq!(MODE_SETGID.0, 1 << 22);
    assert_eq!(MODE_CHAR_DEVICE.0, 1 << 21);
    assert_eq!(MODE_STICKY.0, 1 << 20);
    assert_eq!(MODE_IRREGULAR.0, 1 << 19);
    assert_eq!(MODE_PERM.0, 0o777);
    assert_eq!(
        MODE_TYPE,
        MODE_DIR
            | MODE_SYMLINK
            | MODE_NAMED_PIPE
            | MODE_SOCKET
            | MODE_DEVICE
            | MODE_CHAR_DEVICE
            | MODE_IRREGULAR
    );

    for (mode, want) in [
        (FileMode(0), "----------"),
        (FileMode(0o644), "-rw-r--r--"),
        (MODE_DIR | FileMode(0o755), "drwxr-xr-x"),
        (MODE_APPEND | FileMode(0o600), "arw-------"),
        (MODE_SYMLINK | FileMode(0o777), "Lrwxrwxrwx"),
        (MODE_DEVICE | MODE_CHAR_DEVICE, "Dc---------"),
        (
            MODE_SETUID | MODE_SETGID | MODE_STICKY | FileMode(0o755),
            "ugtrwxr-xr-x",
        ),
        (MODE_IRREGULAR | FileMode(0o4), "?------r--"),
        (FileMode(!0), "dalTLDpSugct?rwxrwxrwx"),
    ] {
        assert_eq!(mode.to_string(), want, "{:#o}", mode.0);
    }
    let m = MODE_DIR | FileMode(0o750);
    assert!(m.is_dir() && !m.is_regular());
    assert_eq!(m.perm(), FileMode(0o750));
    assert_eq!(m.file_type(), MODE_DIR);
    assert!(FileMode(0o644).is_regular());
    assert!(!(MODE_SOCKET | FileMode(0o1)).is_regular());
}

#[derive(Debug)]
struct FormatTest {
    name: &'static str,
    size: i64,
    mode: FileMode,
    is_dir: bool,
}

impl FileInfo for FormatTest {
    fn name(&self) -> &str {
        self.name
    }
    fn size(&self) -> i64 {
        self.size
    }
    fn mode(&self) -> FileMode {
        self.mode
    }
    fn mod_time(&self) -> Time {
        time::date(1970, time::JANUARY, 1, 12, 0, 0, 0, &time::Location::utc())
    }
    fn is_dir(&self) -> bool {
        self.is_dir
    }
}

#[test]
fn format_file_info_and_dir_entry() {
    // TestFormatFileInfo / TestFormatDirEntry
    let tests = [
        (
            FormatTest {
                name: "hello.go",
                size: 100,
                mode: FileMode(0o644),
                is_dir: false,
            },
            "-rw-r--r-- 100 1970-01-01 12:00:00 hello.go",
            "- hello.go",
        ),
        (
            FormatTest {
                name: "home/gopher",
                size: 0,
                mode: MODE_DIR | FileMode(0o755),
                is_dir: true,
            },
            "drwxr-xr-x 0 1970-01-01 12:00:00 home/gopher/",
            "d home/gopher/",
        ),
        (
            FormatTest {
                name: "big",
                size: i64::MAX,
                mode: MODE_IRREGULAR | FileMode(0o644),
                is_dir: false,
            },
            "?rw-r--r-- 9223372036854775807 1970-01-01 12:00:00 big",
            "? big",
        ),
        (
            FormatTest {
                name: "small",
                size: i64::MIN,
                mode: MODE_SOCKET | MODE_SETUID | FileMode(0o644),
                is_dir: false,
            },
            "Surw-r--r-- -9223372036854775808 1970-01-01 12:00:00 small",
            "S small",
        ),
    ];
    for (info, want_info, want_entry) in tests {
        assert_eq!(fs::format_file_info(&info), want_info);
        let name = info.name;
        let entry = fs::file_info_to_dir_entry(Some(Box::new(info))).unwrap();
        assert_eq!(fs::format_dir_entry(entry.as_ref()), want_entry, "{name}");
    }
    assert!(fs::file_info_to_dir_entry(None).is_none());
}

#[test]
fn path_error_and_sentinels() {
    let err: std::io::Error = fs::PathError::new("open", "x/y", fs::ERR_NOT_EXIST).into();
    assert_eq!(err.to_string(), "open x/y: file does not exist");
    let pe = fs::path_error(&err).unwrap();
    assert_eq!((pe.op.as_str(), pe.path.as_str()), ("open", "x/y"));
    assert_eq!(pe.unwrap().to_string(), "file does not exist");
    assert!(!pe.timeout());
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
    assert!(fs::ERR_NOT_EXIST.is(&err));
    assert!(!fs::ERR_EXIST.is(&err));

    let timeout = fs::PathError::new("read", "x", io::Error::from(io::ErrorKind::TimedOut)).into();
    assert!(fs::path_error(&timeout).unwrap().timeout());

    for (e, text, kind) in [
        (
            fs::ERR_INVALID,
            "invalid argument",
            io::ErrorKind::InvalidInput,
        ),
        (
            fs::ERR_PERMISSION,
            "permission denied",
            io::ErrorKind::PermissionDenied,
        ),
        (
            fs::ERR_EXIST,
            "file already exists",
            io::ErrorKind::AlreadyExists,
        ),
        (
            fs::ERR_NOT_EXIST,
            "file does not exist",
            io::ErrorKind::NotFound,
        ),
        (fs::ERR_CLOSED, "file already closed", io::ErrorKind::Other),
        (fs::SKIP_DIR, "skip this directory", io::ErrorKind::Other),
        (
            fs::SKIP_ALL,
            "skip everything and stop the walk",
            io::ErrorKind::Other,
        ),
    ] {
        assert_eq!(e.to_string(), text);
        let err = io::Error::from(e);
        assert_eq!(err.kind(), kind);
        assert!(e.is(&err));
    }
    // OS errors from std match the sentinels by kind.
    let os = stdfs::read("/definitely/not/here").unwrap_err();
    assert!(fs::ERR_NOT_EXIST.is(&os));
    assert!(!fs::ERR_CLOSED.is(&os));
    assert!(!fs::SKIP_DIR.is(&os));
}

// ---------------------------------------------------------------- MapFS and the generic functions

#[test]
fn map_fs_open_stat_read() {
    let mut m = map(&[
        ("hello.txt", "hello, world\n"),
        ("a/b/c.txt", "c"),
        ("a/d.txt", "d"),
    ]);
    m.insert(
        "empty",
        MapFile::new(Vec::new(), MODE_DIR | FileMode(0o755)),
    );
    assert_eq!(fs::read_file(&m, "hello.txt").unwrap(), b"hello, world\n");
    let info = fs::stat(&m, "a/b").unwrap();
    assert!(info.is_dir() && info.name() == "b");
    assert_eq!(info.mode().to_string(), "dr-xr-xr-x");
    assert_eq!(fs::stat(&m, ".").unwrap().name(), ".");
    assert_eq!(names(&fs::read_dir(&m, "a").unwrap()), ["b", "d.txt"]);
    assert_eq!(
        names(&fs::read_dir(&m, ".").unwrap()),
        ["a", "empty", "hello.txt"]
    );
    assert!(fs::read_dir(&m, "empty").unwrap().is_empty());

    let err = fs::read_file(&m, "nope").unwrap_err();
    assert_eq!(err.to_string(), "open nope: file does not exist");
    let err = fs::read_file(&m, "a").unwrap_err();
    assert_eq!(err.to_string(), "read a: invalid argument");
    let err = m.open("/bad").err().unwrap();
    assert_eq!(err.to_string(), "open /bad: file does not exist");
    // Seek and ReadAt exist on the opened file in Go; reading in pieces works.
    let mut f = m.open("hello.txt").unwrap();
    let mut b = [0u8; 5];
    f.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"hello");
    assert_eq!(f.stat().unwrap().size(), 13);
}

struct GlobOnly(MapFS);

impl std::fmt::Debug for GlobOnly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GlobOnly")
    }
}

impl FS for GlobOnly {
    fn open(&self, _: &str) -> io::Result<Box<dyn fs::File>> {
        Err(fs::ERR_NOT_EXIST.into())
    }
    fn as_glob_fs(&self) -> Option<&dyn GlobFS> {
        Some(self)
    }
}

impl GlobFS for GlobOnly {
    fn glob(&self, pattern: &str) -> io::Result<Vec<String>> {
        fs::glob(&self.0, pattern)
    }
}

/// A file system with only `open` (Go's `openOnly`).
#[derive(Debug)]
struct OpenOnly(MapFS);

impl FS for OpenOnly {
    fn open(&self, name: &str) -> io::Result<Box<dyn fs::File>> {
        self.0.open(name)
    }
}

#[test]
fn glob_uses_the_extension_method_when_present() {
    // TestGlobMethod
    let m = map(&[("hello.txt", "hi"), ("sub/other.go", "x")]);
    let via_method = fs::glob(&GlobOnly(m.clone()), "*.txt").unwrap();
    assert_eq!(via_method, ["hello.txt"]);
    let via_open = fs::glob(&OpenOnly(m), "*.txt").unwrap();
    assert_eq!(via_open, ["hello.txt"]);
}

#[test]
fn glob_patterns() {
    // TestGlob / TestGlobError over the real directory of this test file.
    let tests = DirFS::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests"));
    for (pattern, result) in [
        ("io_fs.rs", "io_fs.rs"),
        ("io_f?.rs", "io_fs.rs"),
        ("io\\_fs.rs", "io_fs.rs"),
        ("io_*.rs", "io_fs.rs"),
        ("fixtures/embed/*.txt", "fixtures/embed/hello.txt"),
        ("*/embed/sub/a.txt", "fixtures/embed/sub/a.txt"),
        ("fixtures/[e]mbed/hello.txt", "fixtures/embed/hello.txt"),
    ] {
        let matches = fs::glob(&tests, pattern).unwrap();
        assert!(
            matches.contains(&result.to_string()),
            "{pattern}: {matches:?}"
        );
    }
    for pattern in ["no_match", "../*/no_match", "\\*"] {
        assert!(fs::glob(&tests, pattern).unwrap().is_empty(), "{pattern}");
    }
    for pattern in ["[]", "nonexist/[]"] {
        let err = fs::glob(&tests, pattern).unwrap_err();
        assert_eq!(err.to_string(), "syntax error in pattern", "{pattern}");
        assert!(err.get_ref().unwrap().is::<rust_stdlib::path::BadPattern>());
    }
    // TestCVE202230630: too many separators is a bad pattern, not a stack overflow.
    let long = format!("/*{}", "/".repeat(10001));
    let err = fs::glob(&tests, &long).unwrap_err();
    assert_eq!(err.to_string(), "syntax error in pattern");
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct Visit {
    dir: bool,
}

#[test]
fn walk_dir_visits_every_node_once() {
    // TestWalkDir over Go's tree
    let mut m = MapFS::new();
    for f in [
        "testdata/a",
        "testdata/c",
        "testdata/d/x",
        "testdata/d/z/u",
        "testdata/d/z/v",
    ] {
        m.insert(f, MapFile::default());
    }
    for d in ["testdata/b", "testdata/d/y"] {
        m.insert(d, MapFile::new(Vec::new(), MODE_DIR));
    }
    let mut seen = Vec::new();
    fs::walk_dir(&m, ".", |p, d, e| {
        assert!(e.is_none(), "{p}");
        seen.push((
            p.to_string(),
            Visit {
                dir: d.unwrap().is_dir(),
            },
        ));
        Ok(())
    })
    .unwrap();
    let paths: Vec<&str> = seen.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(
        paths,
        [
            ".",
            "testdata",
            "testdata/a",
            "testdata/b",
            "testdata/c",
            "testdata/d",
            "testdata/d/x",
            "testdata/d/y",
            "testdata/d/z",
            "testdata/d/z/u",
            "testdata/d/z/v",
        ]
    );
    assert!(seen.iter().filter(|(_, v)| v.dir).count() == 6);
}

#[test]
fn walk_dir_skip_semantics() {
    let m = map(&[
        ("a/1", ""),
        ("a/2", ""),
        ("b/1", ""),
        ("b/2", ""),
        ("c", ""),
    ]);
    let walk = |skip: &dyn Fn(&str, bool) -> Option<fs::Error>| {
        let mut seen = Vec::new();
        let res = fs::walk_dir(&m, ".", |p, d, _| {
            seen.push(p.to_string());
            match skip(p, d.unwrap().is_dir()) {
                Some(e) => Err(e.into()),
                None => Ok(()),
            }
        });
        (seen, res)
    };
    // SkipDir on a directory skips its contents only.
    let (seen, res) = walk(&|p, d| (d && p == "a").then_some(fs::SKIP_DIR));
    assert_eq!(seen, [".", "a", "b", "b/1", "b/2", "c"]);
    assert!(res.is_ok());
    // SkipDir on a file skips the rest of the containing directory.
    let (seen, res) = walk(&|p, _| (p == "b/1").then_some(fs::SKIP_DIR));
    assert_eq!(seen, [".", "a", "a/1", "a/2", "b", "b/1", "c"]);
    assert!(res.is_ok());
    // SkipAll ends the walk without an error.
    let (seen, res) = walk(&|p, _| (p == "a/2").then_some(fs::SKIP_ALL));
    assert_eq!(seen, [".", "a", "a/1", "a/2"]);
    assert!(res.is_ok());
    // Any other error ends the walk and is returned.
    let mut count = 0;
    let err = fs::walk_dir(&m, ".", |p, _, _| {
        count += 1;
        if p == "a" {
            Err(io::Error::other("stop"))
        } else {
            Ok(())
        }
    })
    .unwrap_err();
    assert_eq!((err.to_string(), count), ("stop".to_string(), 2));
    // A missing root is reported to the function with a None entry.
    let mut got = None;
    fs::walk_dir(&m, "missing", |p, d, e| {
        got = Some((p.to_string(), d.is_none(), e.unwrap().to_string()));
        Ok(())
    })
    .unwrap();
    assert_eq!(
        got.unwrap(),
        (
            "missing".into(),
            true,
            "open missing: file does not exist".into()
        )
    );
}

#[test]
fn sub_file_systems() {
    // sub_test.go: names are validated and prefixed; errors shorten their paths.
    let m = map(&[("a/b/c.txt", "c"), ("a/d.txt", "d"), ("e.txt", "e")]);
    let a = fs::sub(&m, "a").unwrap();
    assert_eq!(fs::read_file(a.as_ref(), "d.txt").unwrap(), b"d");
    assert_eq!(
        names(&fs::read_dir(a.as_ref(), ".").unwrap()),
        ["b", "d.txt"]
    );
    assert_eq!(fs::glob(a.as_ref(), "*/*.txt").unwrap(), ["b/c.txt"]);
    assert_eq!(fs::glob(a.as_ref(), ".").unwrap(), ["."]);
    let err = fs::read_file(a.as_ref(), "missing").unwrap_err();
    assert_eq!(err.to_string(), "open missing: file does not exist");
    let err = fs::read_file(a.as_ref(), "../e.txt").unwrap_err();
    assert_eq!(err.to_string(), "read ../e.txt: invalid argument");
    let ab = fs::sub(a.as_ref(), "b").unwrap();
    assert_eq!(fs::read_file(ab.as_ref(), "c.txt").unwrap(), b"c");
    assert_eq!(fs::stat(ab.as_ref(), "c.txt").unwrap().size(), 1);
    // Sub of "." is the file system itself; invalid names are rejected.
    let same = fs::sub(&m, ".").unwrap();
    assert_eq!(fs::read_file(same.as_ref(), "e.txt").unwrap(), b"e");
    let err = fs::sub(&m, "../a").err().unwrap();
    assert_eq!(err.to_string(), "sub ../a: invalid argument");
    // A generic file system (open only) gets the same wrapper.
    let o = OpenOnly(m.clone());
    let a = fs::sub(&o, "a").unwrap();
    assert_eq!(fs::read_file(a.as_ref(), "b/c.txt").unwrap(), b"c");
    let err = fs::read_file(a.as_ref(), "x").unwrap_err();
    assert_eq!(err.to_string(), "open x: file does not exist");
    // ReadLink on a file system without links is invalid; Lstat falls back to Stat.
    let err = fs::read_link(&o, "a").unwrap_err();
    assert_eq!(err.to_string(), "readlink a: invalid argument");
    assert_eq!(fs::lstat(&o, "a/d.txt").unwrap().size(), 1);
}

// ---------------------------------------------------------------- DirFS (os.DirFS)

fn make_tree(root: &Path) {
    stdfs::create_dir_all(root.join("sub/deep")).unwrap();
    stdfs::create_dir(root.join("empty")).unwrap();
    stdfs::write(root.join("b.txt"), "bee").unwrap();
    stdfs::write(root.join("a.txt"), "ay").unwrap();
    stdfs::write(root.join("sub/c.txt"), "sea").unwrap();
    stdfs::write(root.join("sub/deep/d.txt"), "dee").unwrap();
}

#[test]
fn dir_fs_read_dir_stat_read_file() {
    let tmp = TempDir::new("dirfs-*");
    make_tree(tmp.path());
    let d = DirFS::new(tmp.path());
    assert_eq!(
        names(&fs::read_dir(&d, ".").unwrap()),
        ["a.txt", "b.txt", "empty", "sub"]
    );
    let entries = fs::read_dir(&d, "sub").unwrap();
    assert_eq!(names(&entries), ["c.txt", "deep"]);
    assert!(entries[1].is_dir() && entries[1].file_type() == MODE_DIR);
    assert!(!entries[0].is_dir() && entries[0].file_type() == FileMode(0));
    assert_eq!(entries[0].info().unwrap().size(), 3);

    assert_eq!(fs::read_file(&d, "sub/deep/d.txt").unwrap(), b"dee");
    let info = fs::stat(&d, "a.txt").unwrap();
    assert_eq!(
        (info.name(), info.size(), info.is_dir()),
        ("a.txt", 2, false)
    );
    assert!(info.mode().is_regular());
    assert!(!info.mod_time().is_zero());
    assert!(fs::stat(&d, "sub").unwrap().is_dir());

    // Open + Read + Close.
    let mut f = d.open("b.txt").unwrap();
    let mut s = String::new();
    f.read_to_string(&mut s).unwrap();
    assert_eq!(s, "bee");
    assert_eq!(f.stat().unwrap().name(), "b.txt");
    f.close().unwrap();
    assert!(fs::ERR_CLOSED.is(&f.close().unwrap_err()));
    assert!(fs::ERR_CLOSED.is(&f.read(&mut [0u8; 1]).unwrap_err()));
}

#[test]
fn dir_fs_errors() {
    let tmp = TempDir::new("dirfs-err-*");
    make_tree(tmp.path());
    let d = DirFS::new(tmp.path());
    let err = d.open("missing.txt").err().unwrap();
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
    assert!(fs::ERR_NOT_EXIST.is(&err));
    let pe = fs::path_error(&err).unwrap();
    assert_eq!((pe.op.as_str(), pe.path.as_str()), ("open", "missing.txt"));
    for bad in ["../x", "/etc/passwd", "a//b", "sub/", "", "./a.txt"] {
        let err = d.open(bad).err().unwrap();
        assert_eq!(
            err.to_string(),
            format!("open {bad}: invalid argument"),
            "{bad:?}"
        );
        assert!(fs::ERR_INVALID.is(&err));
    }
    let err = fs::read_file(&d, "sub").unwrap_err();
    assert!(fs::path_error(&err).is_some());
    let err = fs::read_dir(&d, "a.txt").unwrap_err();
    assert!(fs::path_error(err.source()).is_some());
    assert!(fs::ERR_NOT_EXIST.is(&fs::stat(&d, "nope").err().unwrap()));
}

#[test]
fn dir_fs_directory_file_batches() {
    let tmp = TempDir::new("dirfs-batch-*");
    make_tree(tmp.path());
    let d = DirFS::new(tmp.path());
    let mut dir = d.open(".").unwrap();
    let rd = dir.as_read_dir_file().expect("directory");
    let first = rd.read_dir(2).unwrap();
    assert_eq!(first.len(), 2);
    let rest = rd.read_dir(10).unwrap();
    assert_eq!(first.len() + rest.len(), 4);
    assert!(rio::is_eof(rd.read_dir(1).unwrap_err().source()));
    assert!(rd.read_dir(0).unwrap().is_empty());
    // A regular file is not a ReadDirFile.
    let mut f = d.open("a.txt").unwrap();
    assert!(f.as_read_dir_file().is_none());
    // Reading a directory handle as bytes fails.
    assert!(dir.read(&mut [0u8; 1]).is_err());
}

#[test]
fn dir_fs_walk_glob_sub() {
    let tmp = TempDir::new("dirfs-walk-*");
    make_tree(tmp.path());
    let d = DirFS::new(tmp.path());
    let mut seen = Vec::new();
    fs::walk_dir(&d, ".", |p, _, e| {
        assert!(e.is_none());
        seen.push(p.to_string());
        Ok(())
    })
    .unwrap();
    assert_eq!(
        seen,
        [
            ".",
            "a.txt",
            "b.txt",
            "empty",
            "sub",
            "sub/c.txt",
            "sub/deep",
            "sub/deep/d.txt"
        ]
    );
    assert_eq!(fs::glob(&d, "sub/*/*.txt").unwrap(), ["sub/deep/d.txt"]);
    assert_eq!(fs::glob(&d, "*.txt").unwrap(), ["a.txt", "b.txt"]);
    let sub = fs::sub(&d, "sub/deep").unwrap();
    assert_eq!(fs::read_file(sub.as_ref(), "d.txt").unwrap(), b"dee");
}

#[cfg(unix)]
#[test]
fn dir_fs_symlinks_and_lstat() {
    use std::os::unix::fs::symlink;
    let tmp = TempDir::new("dirfs-link-*");
    make_tree(tmp.path());
    symlink("a.txt", tmp.path().join("link")).unwrap();
    symlink("sub", tmp.path().join("dirlink")).unwrap();
    let d = DirFS::new(tmp.path());
    // Stat follows, Lstat does not; ReadLink returns the target.
    let st = fs::stat(&d, "link").unwrap();
    assert!(st.mode().is_regular() && st.size() == 2);
    let ls = fs::lstat(&d, "link").unwrap();
    assert_eq!(ls.mode().file_type(), MODE_SYMLINK);
    assert_eq!(fs::read_link(&d, "link").unwrap(), "a.txt");
    assert!(fs::stat(&d, "dirlink").unwrap().is_dir());
    assert!(!fs::lstat(&d, "dirlink").unwrap().is_dir());
    assert_eq!(fs::read_file(&d, "link").unwrap(), b"ay");
    let err = fs::read_link(&d, "a.txt").unwrap_err();
    assert!(fs::path_error(&err).is_some_and(|p| p.op == "readlink"));
    // Directory entries report the link type without following it.
    let entries = fs::read_dir(&d, ".").unwrap();
    let link = entries.iter().find(|e| e.name() == "link").unwrap();
    assert_eq!(link.file_type(), MODE_SYMLINK);
    assert!(!link.is_dir());
    let dirlink = entries.iter().find(|e| e.name() == "dirlink").unwrap();
    assert_eq!(dirlink.file_type(), MODE_SYMLINK);
    // Walking does not descend into symbolic links (the entry is not a directory).
    let mut seen = Vec::new();
    fs::walk_dir(&d, ".", |p, _, _| {
        seen.push(p.to_string());
        Ok(())
    })
    .unwrap();
    assert!(seen.contains(&"dirlink".to_string()) && !seen.contains(&"dirlink/c.txt".to_string()));
    // Sub keeps the link operations.
    let sub = fs::sub(&d, "sub").unwrap();
    assert!(fs::read_link(sub.as_ref(), "missing").is_err());
}

#[cfg(unix)]
#[test]
fn walk_dir_unreadable_directory_can_be_skipped() {
    // TestIssue51617
    use std::os::unix::fs::PermissionsExt;
    let tmp = TempDir::new("dirfs-perm-*");
    for sub in ["a", "a/bad", "a/next"] {
        stdfs::create_dir(tmp.path().join(sub)).unwrap();
    }
    let bad = tmp.path().join("a/bad");
    stdfs::set_permissions(&bad, stdfs::Permissions::from_mode(0o000)).unwrap();
    let readable = stdfs::read_dir(&bad).is_ok(); // root ignores permissions
    let mut saw = Vec::new();
    let res = fs::walk_dir(&DirFS::new(tmp.path()), ".", |p, d, e| {
        if e.is_some() {
            assert!(!readable);
            return Err(fs::SKIP_DIR.into());
        }
        if d.unwrap().is_dir() {
            saw.push(p.to_string());
        }
        Ok(())
    });
    stdfs::set_permissions(&bad, stdfs::Permissions::from_mode(0o700)).unwrap();
    res.unwrap();
    assert_eq!(saw, [".", "a", "a/bad", "a/next"]);
}

/// A directory file that yields two entries (out of order) and then fails.
#[derive(Debug)]
struct FailingDir;

impl Read for FailingDir {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

impl fs::File for FailingDir {
    fn stat(&self) -> io::Result<Box<dyn FileInfo>> {
        fs::stat(&map(&[("x", "")]), ".")
    }
    fn as_read_dir_file(&mut self) -> Option<&mut dyn fs::ReadDirFile> {
        Some(self)
    }
}

impl fs::ReadDirFile for FailingDir {
    fn read_dir(&mut self, _: i32) -> Result<Vec<Box<dyn DirEntry>>, fs::ReadDirError> {
        let m = map(&[("z", ""), ("a", "")]);
        let list = fs::read_dir(&m, ".").unwrap();
        let mut list: Vec<_> = list.into_iter().rev().collect();
        list.truncate(2);
        Err(fs::ReadDirError::new(list, io::Error::other("boom")))
    }
}

#[derive(Debug)]
struct FailingFS;

impl FS for FailingFS {
    fn open(&self, _: &str) -> io::Result<Box<dyn fs::File>> {
        Ok(Box::new(FailingDir))
    }
}

#[test]
fn read_dir_returns_sorted_partial_list_with_error() {
    let err = fs::read_dir(&FailingFS, ".").unwrap_err();
    assert_eq!(err.to_string(), "boom");
    assert_eq!(names(err.list()), ["a", "z"]);
    let (list, source) = err.into_parts();
    assert_eq!(list.len(), 2);
    assert_eq!(source.to_string(), "boom");
}

#[test]
fn walk_dir_visits_the_partial_list_when_the_callback_accepts_the_error() {
    let mut seen: Vec<(String, bool)> = Vec::new();
    fs::walk_dir(
        &FailingFS,
        ".",
        |path: &str, _: Option<&dyn DirEntry>, err: Option<io::Error>| {
            seen.push((path.to_owned(), err.is_some()));
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        seen,
        [
            (".".to_owned(), false),
            (".".to_owned(), true),
            ("a".to_owned(), false),
            ("z".to_owned(), false),
        ]
    );
}
