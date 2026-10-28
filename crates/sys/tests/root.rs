//! `os.Root` (rust_stdlib_sys::os::Root): the cases of Go's os/root_test.go
//! table, run against every operation, plus the error texts and the
//! symlink-escape behaviour. tools/os_check.py compares the same API with Go.
#![cfg(all(
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64"
))]

use rust_stdlib_sys::os::{self, FileMode, Root};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A fresh scratch directory.
fn scratch() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sysroot-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::canonicalize(dir).unwrap()
}

/// Go's `makefs`: "d/" is a directory, "a => b" a symbolic link, anything
/// else a file holding its own name. The tree is in a directory named ROOT.
fn makefs(entries: &[&str]) -> (PathBuf, PathBuf) {
    let outer = scratch();
    let root = outer.join("ROOT");
    std::fs::create_dir(&root).unwrap();
    for ent in entries {
        let ent = ent.replace("$ABS", root.to_str().unwrap());
        let (base, link) = match ent.split_once(" => ") {
            Some((b, l)) => (b.to_string(), Some(l.to_string())),
            None => (ent.clone(), None),
        };
        let path = root.join(&base);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        if let Some(l) = link {
            std::os::unix::fs::symlink(l, &path).unwrap();
        } else if ent.ends_with('/') {
            std::fs::create_dir_all(&path).unwrap();
        } else {
            std::fs::write(&path, &ent).unwrap();
        }
    }
    (outer, root)
}

struct Case {
    name: &'static str,
    fs: &'static [&'static str],
    open: &'static str,
    target: &'static str,
    ltarget: &'static str,
    want_error: bool,
}

const fn case(
    name: &'static str,
    fs: &'static [&'static str],
    open: &'static str,
    target: &'static str,
    ltarget: &'static str,
    want_error: bool,
) -> Case {
    Case {
        name,
        fs,
        open,
        target,
        ltarget,
        want_error,
    }
}

/// Go's rootTestCases.
const CASES: &[Case] = &[
    case("plain path", &[], "target", "target", "", false),
    case(
        "path in directory",
        &["a/b/c/"],
        "a/b/c/target",
        "a/b/c/target",
        "",
        false,
    ),
    case(
        "symlink",
        &["link => target"],
        "link",
        "target",
        "link",
        false,
    ),
    case(
        "symlink dotdot slash",
        &["link => ../"],
        "link",
        "",
        "link",
        true,
    ),
    case(
        "symlink ending in slash",
        &["dir/", "link => dir/"],
        "link/target",
        "dir/target",
        "",
        false,
    ),
    case(
        "slash after symlink to file",
        &["link => ../ROOT/target"],
        "link/",
        "target",
        "",
        true,
    ),
    case(
        "slash after symlink to dir",
        &["link => ../ROOT/target", "target/"],
        "link/",
        "",
        "",
        true,
    ),
    case(
        "symlink dotdot dotdot slash",
        &["dir/link => ../../"],
        "dir/link",
        "",
        "dir/link",
        true,
    ),
    case(
        "symlink chain",
        &[
            "link => a/b/c/target",
            "a/b => e",
            "a/e => ../f",
            "f => g/h/i",
            "g/h/i => ..",
            "g/c/",
        ],
        "link",
        "g/c/target",
        "link",
        false,
    ),
    case(
        "path with dot",
        &["a/b/"],
        "./a/./b/./target",
        "a/b/target",
        "",
        false,
    ),
    case(
        "path with dotdot",
        &["a/b/"],
        "a/../a/b/../../a/b/../b/target",
        "a/b/target",
        "",
        false,
    ),
    case("path with dotdot slash", &[], "../", "", "", true),
    case(
        "path with dotdot dotdot slash",
        &["a/"],
        "a/../../",
        "",
        "",
        true,
    ),
    case(
        "dotdot no symlink",
        &["a/"],
        "a/../target",
        "target",
        "",
        false,
    ),
    case(
        "dotdot after symlink",
        &["a => b/c", "b/c/"],
        "a/../target",
        "b/target",
        "",
        false,
    ),
    case(
        "dotdot before symlink",
        &["a => b/c", "b/c/"],
        "b/../a/target",
        "b/c/target",
        "",
        false,
    ),
    case(
        "symlink ends in dot",
        &["a => b/.", "b/"],
        "a/target",
        "b/target",
        "",
        false,
    ),
    case("directory does not exist", &[], "a/file", "", "", true),
    case("empty path", &[], "", "", "", true),
    case("symlink cycle", &["a => a"], "a", "", "a", true),
    case("path escapes", &[], "../ROOT/target", "target", "", true),
    case(
        "long path escapes",
        &["a/"],
        "a/../../ROOT/target",
        "target",
        "",
        true,
    ),
    case(
        "absolute symlink",
        &["link => $ABS/target"],
        "link",
        "target",
        "link",
        true,
    ),
    case(
        "relative symlink",
        &["link => ../ROOT/target"],
        "link",
        "target",
        "link",
        true,
    ),
    case(
        "symlink chain escapes",
        &[
            "link => a/b/c/target",
            "a/b => e",
            "a/e => ../../ROOT",
            "c/",
        ],
        "link",
        "c/target",
        "link",
        true,
    ),
];

fn each(f: impl Fn(&Case, &Path, &Root)) {
    for c in CASES {
        let (_outer, root) = makefs(c.fs);
        let r = os::open_root(root.to_str().unwrap()).unwrap();
        f(c, &root, &r);
    }
}

fn exists(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok()
}

#[test]
fn open_file() {
    each(|c, root, r| {
        let target = (!c.target.is_empty()).then(|| root.join(c.target));
        if let Some(t) = &target {
            std::fs::create_dir_all(t.parent().unwrap()).unwrap();
            std::fs::write(t, "file").unwrap();
        }
        let got = r.open(c.open);
        match (c.want_error, got) {
            (true, Ok(_)) => panic!("{}: Open({:?}) succeeded", c.name, c.open),
            (false, Err(e)) => panic!("{}: Open({:?}) = {e}", c.name, c.open),
            (false, Ok(f)) => {
                let mut buf = [0u8; 16];
                let n = f.read(&mut buf).unwrap();
                assert_eq!(&buf[..n], b"file", "{}", c.name);
                assert_eq!(
                    f.name(),
                    format!("{}/{}", root.display(), c.open),
                    "{}",
                    c.name
                );
            }
            (true, Err(_)) => {}
        }
    });
}

#[test]
fn create_never_creates_outside() {
    each(|c, root, r| {
        let got = r.create(c.open);
        assert_eq!(
            got.is_err(),
            c.want_error,
            "{}: Create({:?})",
            c.name,
            c.open
        );
        if c.want_error && !c.target.is_empty() {
            assert!(
                !exists(&root.join(c.target)),
                "{}: escaped file created",
                c.name
            );
        }
        if !c.want_error {
            assert!(exists(&root.join(c.target)), "{}", c.name);
        }
    });
}

#[test]
fn mkdir() {
    each(|c, root, r| {
        let got = r.mkdir(c.open, 0o777);
        // A symbolic link in the last position is never followed by Mkdir.
        let expect_err = c.want_error || !c.ltarget.is_empty() || c.open.is_empty();
        if c.name == "symlink" || c.name == "symlink chain" {
            assert!(got.is_err(), "{}: Mkdir through a link", c.name);
            return;
        }
        if expect_err {
            assert!(got.is_err(), "{}: Mkdir({:?}) succeeded", c.name, c.open);
            if !c.target.is_empty() {
                assert!(
                    !exists(&root.join(c.target)),
                    "{}: escaped dir created",
                    c.name
                );
            }
        } else if let Err(e) = got {
            // "link/" style paths end in a slash; the target need not exist.
            if !c.open.ends_with('/') {
                panic!("{}: Mkdir({:?}) = {e}", c.name, c.open);
            }
        }
    });
}

#[test]
fn stat_and_lstat() {
    each(|c, root, r| {
        if !c.target.is_empty() {
            let t = root.join(c.target);
            std::fs::create_dir_all(t.parent().unwrap()).unwrap();
            std::fs::write(&t, "x").unwrap();
        }
        assert_eq!(
            r.stat(c.open).is_err(),
            c.want_error || c.open.is_empty() || (c.target.is_empty() && !c.name.contains("slash")),
            "{}: Stat({:?})",
            c.name,
            c.open
        );
        if !c.ltarget.is_empty() && !c.want_error {
            let fi = r.lstat(c.open).unwrap();
            assert!(
                fi.mode().0 & FileMode::SYMLINK != 0,
                "{}: Lstat not a link",
                c.name
            );
        }
    });
}

#[test]
fn remove_stays_inside() {
    each(|c, root, r| {
        if c.target.is_empty() || c.want_error {
            return;
        }
        let t = root.join(if c.ltarget.is_empty() {
            c.target
        } else {
            c.ltarget
        });
        std::fs::create_dir_all(t.parent().unwrap()).unwrap();
        if !exists(&t) {
            std::fs::write(&t, "x").unwrap();
        }
        r.remove(c.open)
            .unwrap_or_else(|e| panic!("{}: Remove({:?}) = {e}", c.name, c.open));
        assert!(!exists(&t), "{}: not removed", c.name);
    });
}

#[test]
fn escape_error_text() {
    let (_o, root) = makefs(&["link => ../ROOT/target", "abs => $ABS/target"]);
    let r = os::open_root(root.to_str().unwrap()).unwrap();
    let e = r.open("../ROOT/target").unwrap_err();
    assert_eq!(
        e.to_string(),
        "openat ../ROOT/target: path escapes from parent"
    );
    let e = r.open("link").unwrap_err();
    assert_eq!(e.to_string(), "openat link: path escapes from parent");
    let e = r.open("abs").unwrap_err();
    assert_eq!(e.to_string(), "openat abs: path escapes from parent");
    let e = r.open("/etc/passwd").unwrap_err();
    assert_eq!(
        e.to_string(),
        "openat /etc/passwd: path escapes from parent"
    );
    let e = r.open("").unwrap_err();
    assert_eq!(e.to_string(), "openat : empty path");
    let e = r.stat("link").unwrap_err();
    assert_eq!(e.to_string(), "statat link: path escapes from parent");
    let e = r.rename("../ROOT/target", "x").unwrap_err();
    assert_eq!(
        e.to_string(),
        "renameat ../ROOT/target x: path escapes from parent"
    );
    let e = r.symlink("t", "../ROOT/y").unwrap_err();
    assert_eq!(
        e.to_string(),
        "symlinkat t ../ROOT/y: path escapes from parent"
    );
}

#[test]
fn symlink_cycle_and_depth() {
    let (_o, root) = makefs(&["a => a"]);
    let r = os::open_root(root.to_str().unwrap()).unwrap();
    let e = r.open("a").unwrap_err();
    assert_eq!(e.to_string(), "openat a: too many levels of symbolic links");
    // Nine links in a row exceed the limit of eight; eight do not.
    let (_o, root) = makefs(&["target"]);
    let r = os::open_root(root.to_str().unwrap()).unwrap();
    let mut prev = "target".to_string();
    for i in 0..9 {
        let n = format!("l{i}");
        r.symlink(&prev, &n).unwrap();
        prev = n;
        if i == 7 {
            assert!(r.open(&prev).is_ok(), "eight links");
        }
    }
    assert!(r.open(&prev).is_err(), "nine links");
}

#[test]
fn use_after_close() {
    let (_o, root) = makefs(&["f"]);
    let r = os::open_root(root.to_str().unwrap()).unwrap();
    r.close().unwrap();
    r.close().unwrap();
    let e = r.open("f").unwrap_err();
    assert_eq!(e.to_string(), "openat f: file already closed");
    assert!(e.is_closed());
    let e = r.stat("f").unwrap_err();
    assert_eq!(e.to_string(), "statat f: file already closed");
    let e = r.mkdir("d", 0o777).unwrap_err();
    assert_eq!(e.to_string(), "mkdirat d: file already closed");
}

#[test]
fn non_permission_mode() {
    let (_o, root) = makefs(&[]);
    let r = os::open_root(root.to_str().unwrap()).unwrap();
    let e = r
        .open_file("f", os::O_RDWR | os::O_CREATE, 0o1000)
        .unwrap_err();
    assert_eq!(e.to_string(), "openat f: unsupported file mode");
    let e = r.mkdir("d", 0o1000).unwrap_err();
    assert_eq!(e.to_string(), "mkdirat d: unsupported file mode");
    let e = r.mkdir_all("d", 0o1000).unwrap_err();
    assert_eq!(e.to_string(), "mkdirat d: unsupported file mode");
}

#[test]
fn name_and_open_root() {
    let (_o, root) = makefs(&["sub/f"]);
    let dir = root.to_str().unwrap().to_string();
    let r = os::open_root(&dir).unwrap();
    assert_eq!(r.name(), dir);
    let s = r.open_root("sub").unwrap();
    assert_eq!(s.name(), format!("{dir}/sub"));
    assert_eq!(s.read_file("f").unwrap(), b"sub/f");
    assert!(s.open("../sub/f").is_err());
    assert!(s.open("../f").is_err());
    let e = r.open_root("sub/f").unwrap_err();
    assert_eq!(e.to_string(), format!("open {dir}/sub/f: not a directory"));
    let slash = os::open_root(&format!("{dir}/")).unwrap();
    assert_eq!(slash.open_root("sub").unwrap().name(), format!("{dir}/sub"));
}

#[test]
fn open_in_root() {
    let (_o, root) = makefs(&["f", "link => ../ROOT/f"]);
    let dir = root.to_str().unwrap();
    let f = os::open_in_root(dir, "f").unwrap();
    let mut buf = [0u8; 4];
    assert_eq!(f.read(&mut buf).unwrap(), 1);
    assert!(os::open_in_root(dir, "link").is_err());
    assert!(os::open_in_root(dir, "../ROOT/f").is_err());
    let e = os::open_in_root(&format!("{dir}/f"), "x").unwrap_err();
    assert_eq!(e.to_string(), format!("open {dir}/f: not a directory"));
    let e = os::open_in_root(&format!("{dir}/nosuch"), "x").unwrap_err();
    assert!(e.is_not_exist());
}

#[test]
fn write_read_file_and_modes() {
    let (_o, root) = makefs(&[]);
    let r = os::open_root(root.to_str().unwrap()).unwrap();
    r.write_file("f", b"hello", 0o640).unwrap();
    assert_eq!(r.read_file("f").unwrap(), b"hello");
    let fi = r.stat("f").unwrap();
    assert_eq!(fi.name(), "f");
    assert_eq!(fi.size(), 5);
    assert_eq!(fi.mode().to_string(), "-rw-r-----");
    r.chmod("f", FileMode(0o600)).unwrap();
    assert_eq!(r.stat("f").unwrap().mode().to_string(), "-rw-------");
    r.symlink("f", "l").unwrap();
    assert_eq!(r.readlink("l").unwrap(), "f");
    assert!(r.lstat("l").unwrap().mode().0 & FileMode::SYMLINK != 0);
    r.chmod("l", FileMode(0o644)).unwrap();
    assert_eq!(r.stat("f").unwrap().mode().to_string(), "-rw-r--r--");
    r.chtimes(
        "f",
        Some(std::time::UNIX_EPOCH + std::time::Duration::new(1_000_000_000, 5)),
        None,
    )
    .unwrap();
    let want = std::time::UNIX_EPOCH + std::time::Duration::new(1_000_000_000, 5);
    let _ = want; // only atime was set; mtime is unchanged
    r.chtimes("f", None, Some(want)).unwrap();
    assert_eq!(r.stat("f").unwrap().mod_time(), want);
}

#[test]
fn mkdir_all_remove_all_rename_link() {
    let (_o, root) = makefs(&["out/secret"]);
    let r = os::open_root(root.to_str().unwrap()).unwrap();
    r.mkdir_all("a/b/c", 0o755).unwrap();
    r.mkdir_all("a/b/c", 0o755).unwrap();
    r.write_file("a/b/c/f", b"x", 0o644).unwrap();
    r.symlink("a", "alink").unwrap();
    r.mkdir_all("alink/b/d", 0o755).unwrap();
    assert!(root.join("a/b/d").is_dir());
    r.rename("a/b/c/f", "a/g").unwrap();
    r.link("a/g", "a/h").unwrap();
    assert_eq!(r.read_file("a/h").unwrap(), b"x");
    let e = r.mkdir_all("../out/x", 0o755).unwrap_err();
    assert_eq!(e.to_string(), "mkdirat ../out/x: path escapes from parent");
    r.symlink("../out", "esc").unwrap();
    let e = r.mkdir_all("esc/x", 0o755).unwrap_err();
    assert!(e.to_string().ends_with("path escapes from parent"), "{e}");
    assert!(!root.join("out/x").exists());
    assert!(r.rename("a/g", "esc/g").is_err());
    assert!(r.link("a/g", "esc/g").is_err());
    assert!(!root.join("out/g").exists());
    let e = r.remove_all(".").unwrap_err();
    assert_eq!(e.to_string(), "RemoveAll .: invalid argument");
    r.remove_all("nosuch/deeper").unwrap();
    r.remove_all("a/").unwrap();
    assert!(!root.join("a").exists());
    assert!(root.join("out/secret").exists());
    // RemoveAll does not follow a link out of the root.
    assert!(r.remove_all("esc/secret").is_err());
    assert!(root.join("out/secret").exists());
    r.remove_all("esc").unwrap();
    assert!(root.join("out/secret").exists());
}

#[test]
fn symlink_to_root_and_rename_after_open() {
    let (_o, root) = makefs(&["d/f"]);
    let r = os::open_root(root.to_str().unwrap()).unwrap();
    r.symlink(".", "self").unwrap();
    assert_eq!(r.read_file("self/self/d/f").unwrap(), b"d/f");
    r.symlink("..", "d/up").unwrap();
    assert!(r.read_file("d/up/up/ROOT/d/f").is_err());
    // A directory moved after the Root was opened is still the root.
    let moved = root.with_file_name("MOVED");
    std::fs::rename(&root, &moved).unwrap();
    assert_eq!(r.read_file("d/f").unwrap(), b"d/f");
    assert!(r.read_file("d/up/up/ROOT/d/f").is_err());
}

#[test]
fn fs_view() {
    let (_o, root) = makefs(&["d/f", "d/g", "link => ../ROOT/d/f", "in => d/f"]);
    let r = os::open_root(root.to_str().unwrap()).unwrap();
    let fs = r.fs();
    assert_eq!(fs.read_file("d/f").unwrap(), b"d/f");
    let names: Vec<String> = fs
        .read_dir("d")
        .unwrap()
        .iter()
        .map(|e| format!("{}/{}", e.name(), e.file_type()))
        .collect();
    assert_eq!(names, ["f/----------", "g/----------"]);
    assert_eq!(
        fs.open("../d").unwrap_err().to_string(),
        "open ../d: invalid argument"
    );
    assert_eq!(
        fs.read_dir("/d").unwrap_err().to_string(),
        "readdir /d: invalid argument"
    );
    assert_eq!(
        fs.stat("d//f").unwrap_err().to_string(),
        "stat d//f: invalid argument"
    );
    assert_eq!(fs.read_link("in").unwrap(), "d/f");
    assert!(fs.lstat("in").unwrap().mode().0 & FileMode::SYMLINK != 0);
    assert!(fs.read_file("link").is_err());
    assert!(os::valid_path(".") && !os::valid_path("") && !os::valid_path("a/"));
}

#[test]
fn file_mode_string() {
    assert_eq!(FileMode(FileMode::DIR | 0o755).to_string(), "drwxr-xr-x");
    assert_eq!(
        FileMode(FileMode::SYMLINK | 0o777).to_string(),
        "Lrwxrwxrwx"
    );
    assert_eq!(
        FileMode(FileMode::DEVICE | FileMode::CHAR_DEVICE | 0o620).to_string(),
        "Dcrw--w----"
    );
    assert_eq!(
        FileMode(FileMode::SETUID | FileMode::STICKY | 0o4).to_string(),
        "ut------r--"
    );
    assert_eq!(FileMode(0).to_string(), "----------");
}
