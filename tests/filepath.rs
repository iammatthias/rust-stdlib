//! Port of the portable parts of Go's `path/filepath` tests (`path_test.go`,
//! `match_test.go`), Unix variants. The table rows come from
//! `tools/gen_filepath_tables.py`.
#![cfg(unix)]

use rust_stdlib::io::fs::{self, FileMode};
use rust_stdlib::os;
use rust_stdlib::path::filepath as fp;
use std::io;
use std::sync::Mutex;

include!("fixtures/filepath_tables.rs");

/// Tests that change the working directory take this lock.
static CWD: Mutex<()> = Mutex::new(());

fn temp() -> String {
    let d = os::mkdir_temp("", "fptest").expect("mkdir_temp");
    fp::eval_symlinks(&d).expect("canonical temp dir")
}

#[test]
fn clean() {
    for (path, want) in clean_tests() {
        assert_eq!(fp::clean(path), want, "Clean({path:?})");
        assert_eq!(fp::clean(want), want, "Clean({want:?}) is not idempotent");
    }
}

#[test]
fn is_local() {
    for (path, want) in is_local_tests() {
        assert_eq!(fp::is_local(path), want, "IsLocal({path:?})");
    }
}

#[test]
fn localize() {
    for (path, want) in localize_tests() {
        match fp::localize(path) {
            Ok(got) => assert_eq!(got, want, "Localize({path:?})"),
            Err(_) => assert_eq!(want, "", "Localize({path:?}) failed, want {want:?}"),
        }
    }
}

#[test]
fn from_and_to_slash() {
    // Identity on Unix.
    for p in ["", "/", "a/b", "a\\b", "//x//"] {
        assert_eq!(fp::from_slash(p), p);
        assert_eq!(fp::to_slash(p), p);
    }
}

#[test]
fn split_list() {
    let cases: [(&str, Vec<&str>); 4] = [
        ("", vec![]),
        ("a", vec!["a"]),
        ("a:b:c", vec!["a", "b", "c"]),
        ("a::b:", vec!["a", "", "b", ""]),
    ];
    for (list, want) in cases {
        assert_eq!(fp::split_list(list), want, "SplitList({list:?})");
    }
}

#[test]
fn split() {
    for (path, dir, file) in split_tests() {
        let (d, f) = fp::split(path);
        assert_eq!((d, f), (dir, file), "Split({path:?})");
        assert_eq!(format!("{d}{f}"), path);
    }
}

#[test]
fn join() {
    for (elem, want) in join_tests() {
        assert_eq!(fp::join(&elem), want, "Join({elem:?})");
    }
}

#[test]
fn ext() {
    for (path, want) in ext_tests() {
        assert_eq!(fp::ext(path), want, "Ext({path:?})");
    }
}

#[test]
fn base() {
    for (path, want) in base_tests() {
        assert_eq!(fp::base(path), want, "Base({path:?})");
    }
}

#[test]
fn dir() {
    for (path, want) in dir_tests() {
        assert_eq!(fp::dir(path), want, "Dir({path:?})");
    }
}

#[test]
fn is_abs() {
    for (path, want) in is_abs_tests() {
        assert_eq!(fp::is_abs(path), want, "IsAbs({path:?})");
    }
}

#[test]
fn rel() {
    for (root, path, want) in rel_tests() {
        let got = fp::rel(root, path);
        if want == "err" {
            assert!(
                got.is_err(),
                "Rel({root:?}, {path:?}) = {got:?}, want error"
            );
        } else {
            assert_eq!(got.as_deref().ok(), Some(want), "Rel({root:?}, {path:?})");
        }
    }
    assert_eq!(
        fp::rel("..", "a").unwrap_err().to_string(),
        "Rel: can't make a relative to .."
    );
    assert!(fp::rel("/a", "b").is_err());
}

#[test]
fn match_tests_from_go() {
    for (pattern, s, want, want_err) in match_tests() {
        let got = fp::matches(pattern, s);
        match (got, want_err) {
            (Err(_), true) => {}
            (Ok(m), false) => assert_eq!(m, want, "Match({pattern:?}, {s:?})"),
            (got, _) => panic!("Match({pattern:?}, {s:?}) = {got:?}, want error: {want_err}"),
        }
    }
}

#[test]
fn match_is_lazy_about_errors() {
    // Go reports a malformed pattern only when matching reaches it.
    assert_eq!(fp::matches("/-ab*[^]b[", "cbb\u{96ea}]/c"), Ok(false));
    assert_eq!(fp::matches("a*[", "b"), Ok(false));
    assert!(fp::matches("a[", "a").is_err());
    assert_eq!(fp::matches("*", "a/b"), Ok(false));
    assert_eq!(fp::matches("[", ""), Err(rust_stdlib::path::BadPattern));
}

// ---- Walk -------------------------------------------------------------------

struct Node {
    name: &'static str,
    entries: Option<Vec<Node>>,
    mark: std::cell::Cell<i32>,
}

fn file(name: &'static str) -> Node {
    Node {
        name,
        entries: None,
        mark: 0.into(),
    }
}

fn dir_node(name: &'static str, entries: Vec<Node>) -> Node {
    Node {
        name,
        entries: Some(entries),
        mark: 0.into(),
    }
}

fn tree() -> Node {
    dir_node(
        "testdata",
        vec![
            file("a"),
            dir_node("b", vec![]),
            file("c"),
            dir_node(
                "d",
                vec![
                    file("x"),
                    dir_node("y", vec![]),
                    dir_node("z", vec![file("u"), file("v")]),
                ],
            ),
        ],
    )
}

fn walk_tree(n: &Node, path: &str, f: &mut dyn FnMut(&str, &Node)) {
    f(path, n);
    for e in n.entries.iter().flatten() {
        walk_tree(e, &fp::join(&[path, e.name]), f);
    }
}

fn make_tree(base: &str, t: &Node) {
    walk_tree(t, &fp::join(&[base, t.name]), &mut |path, n| {
        if n.entries.is_none() {
            os::create(path).expect("create").close().unwrap();
        } else {
            let _ = os::mkdir(path, FileMode(0o770));
        }
    });
}

fn mark_tree(n: &Node) {
    walk_tree(n, "", &mut |_, n| n.mark.set(n.mark.get() + 1));
}

fn check_marks(t: &Node, report: bool) {
    walk_tree(t, t.name, &mut |path, n| {
        if report {
            assert_eq!(n.mark.get(), 1, "node {path} mark");
        }
        n.mark.set(0);
    });
}

fn mark(t: &Node, name: &str) {
    walk_tree(t, t.name, &mut |_, n| {
        if n.name == name {
            n.mark.set(n.mark.get() + 1);
        }
    });
}

type WalkCb<'a> = dyn FnMut(&str, &str, Option<io::Error>) -> io::Result<()> + 'a;

type Walker = fn(&str, &mut WalkCb<'_>) -> io::Result<()>;

/// Go's callback-style walk over the iterator: `f(path, entry, err)` returns
/// `SkipDir`, `SkipAll` or an error as in Go.
fn go_walk<F>(root: &str, list_first: bool, mut f: F) -> io::Result<()>
where
    F: FnMut(&str, Option<&fp::WalkEntry>, Option<io::Error>) -> io::Result<()>,
{
    let mut it = fp::WalkDir::new(root);
    if list_first {
        it = it.list_first();
    }
    while let Some(item) = it.next() {
        let res = match item {
            Ok(entry) => f(entry.path(), Some(&entry), None),
            Err(e) => {
                let path = e.path().to_string();
                f(&path, None, Some(e.into_source()))
            }
        };
        match res {
            Ok(()) => {}
            Err(e) if fs::Error::SkipDir.is(&e) => it.skip_current_dir(),
            Err(e) if fs::Error::SkipAll.is(&e) => return Ok(()),
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn walk_fn(root: &str, f: &mut WalkCb) -> io::Result<()> {
    go_walk(root, true, |p, entry, err| {
        let name = entry
            .map(|e| e.name().to_string())
            .unwrap_or_else(|| fp::base(p).to_string());
        f(p, &name, err)
    })
}

fn walk_dir_fn(root: &str, f: &mut WalkCb) -> io::Result<()> {
    go_walk(root, false, |p, entry, err| {
        let name = entry
            .map(|e| e.name().to_string())
            .unwrap_or_else(|| fp::base(p).to_string());
        f(p, &name, err)
    })
}

fn test_walk(walk: Walker, err_visit: i32) {
    let base = temp();
    let t = tree();
    make_tree(&base, &t);
    let root = fp::join(&[base.as_str(), t.name]);
    let errors = std::cell::RefCell::new(Vec::<String>::new());
    let clear = std::cell::Cell::new(true);
    let mut mark_fn = |_: &str, name: &str, err: Option<io::Error>| -> io::Result<()> {
        mark(&t, name);
        match err {
            Some(e) => {
                errors.borrow_mut().push(e.to_string());
                if clear.get() {
                    Ok(())
                } else {
                    Err(e)
                }
            }
            None => Ok(()),
        }
    };
    // Expect no errors.
    walk(&root, &mut mark_fn).expect("no error expected");
    assert!(
        errors.borrow().is_empty(),
        "unexpected errors: {:?}",
        errors.borrow()
    );
    check_marks(&t, true);

    if os::geteuid() != 0 {
        let entries = t.entries.as_ref().unwrap();
        let (b, d) = (&entries[1], &entries[3]);
        // Introduce 2 errors: chmod top-level directories to 0.
        os::chmod(&fp::join(&[root.as_str(), b.name]), FileMode(0)).unwrap();
        os::chmod(&fp::join(&[root.as_str(), d.name]), FileMode(0)).unwrap();
        mark_tree(b);
        mark_tree(d);
        b.mark.set(b.mark.get() - err_visit);
        d.mark.set(d.mark.get() - err_visit);
        walk(&root, &mut mark_fn).expect("expected no error return from Walk");
        assert_eq!(errors.borrow().len(), 2, "errors: {:?}", errors.borrow());
        check_marks(&t, true);
        errors.borrow_mut().clear();

        // Stop after the first error.
        mark_tree(b);
        mark_tree(d);
        b.mark.set(b.mark.get() - err_visit);
        d.mark.set(d.mark.get() - err_visit);
        clear.set(false);
        let r = walk(&root, &mut mark_fn);
        assert!(r.is_err(), "expected error return from Walk");
        assert_eq!(errors.borrow().len(), 1, "errors: {:?}", errors.borrow());
        check_marks(&t, false);
        os::chmod(&fp::join(&[root.as_str(), b.name]), FileMode(0o770)).unwrap();
        os::chmod(&fp::join(&[root.as_str(), d.name]), FileMode(0o770)).unwrap();
    }
    os::remove_all(&base).unwrap();
}

#[test]
fn walk() {
    test_walk(walk_fn, 1);
}

#[test]
fn walk_dir() {
    test_walk(walk_dir_fn, 2);
}

#[test]
fn walk_skip_dir_on_file() {
    let td = temp();
    os::mkdir_all(&fp::join(&[td.as_str(), "dir"]), FileMode(0o755)).unwrap();
    for f in ["dir/foo1", "dir/foo2", "dir/subdir/foo3", "foo4"] {
        let p = fp::join(&[td.as_str(), f]);
        os::mkdir_all(fp::dir(&p).as_str(), FileMode(0o755)).unwrap();
        os::create(&p).unwrap().close().unwrap();
    }
    let mut seen: Vec<String> = Vec::new();
    go_walk(&td, false, |p, entry, err| {
        assert!(err.is_none());
        seen.push(p.strip_prefix(&td).unwrap().to_string());
        if entry.unwrap().name() == "foo1" {
            return Err(fs::SKIP_DIR.into());
        }
        Ok(())
    })
    .unwrap();
    // SkipDir on a file skips the rest of its directory.
    assert_eq!(seen, ["", "/dir", "/dir/foo1", "/foo4"]);
    os::remove_all(&td).unwrap();
}

#[test]
fn walk_skip_all_on_file() {
    let td = temp();
    for f in ["dir/foo1", "dir/foo2", "dir2/foo3", "dir2/foo4"] {
        let p = fp::join(&[td.as_str(), f]);
        os::mkdir_all(fp::dir(&p).as_str(), FileMode(0o755)).unwrap();
        os::create(&p).unwrap().close().unwrap();
    }
    let mut seen: Vec<String> = Vec::new();
    let r = go_walk(&td, true, |p, entry, err| {
        assert!(err.is_none());
        seen.push(p.strip_prefix(&td).unwrap().to_string());
        if entry.unwrap().name() == "foo1" {
            return Err(fs::SKIP_ALL.into());
        }
        Ok(())
    });
    assert!(r.is_ok());
    assert_eq!(seen, ["", "/dir", "/dir/foo1"]);
    os::remove_all(&td).unwrap();
}

#[test]
fn walk_file_error() {
    let td = temp();
    let (dir, foo, bar) = (
        fp::join(&[td.as_str(), "dir"]),
        fp::join(&[td.as_str(), "dir/foo"]),
        fp::join(&[td.as_str(), "dir/bar"]),
    );
    os::mkdir_all(&dir, FileMode(0o755)).unwrap();
    os::create(&foo).unwrap().close().unwrap();
    os::create(&bar).unwrap().close().unwrap();
    // A file that cannot be lstat'ed is reported to the callback with the error.
    let mut got: Vec<(String, bool)> = Vec::new();
    go_walk(&td, true, |p, entry, err| {
        got.push((
            p.strip_prefix(&td).unwrap().to_string(),
            entry.is_some() && err.is_none(),
        ));
        Ok(())
    })
    .unwrap();
    assert_eq!(
        got,
        [
            ("".to_string(), true),
            ("/dir".to_string(), true),
            ("/dir/bar".to_string(), true),
            ("/dir/foo".to_string(), true)
        ]
    );
    // The walk of a missing root reports the error once, with no info.
    let mut calls = 0;
    let missing = fp::join(&[td.as_str(), "missing"]);
    go_walk(&missing, true, |_, entry, err| {
        calls += 1;
        assert!(entry.is_none());
        assert!(os::is_not_exist(&err.expect("error")));
        Ok(())
    })
    .unwrap();
    assert_eq!(calls, 1);
    os::remove_all(&td).unwrap();
}

#[test]
fn walk_symlink_root_is_not_followed() {
    let td = temp();
    os::mkdir(&fp::join(&[td.as_str(), "real"]), FileMode(0o755)).unwrap();
    os::create(&fp::join(&[td.as_str(), "real/f"]))
        .unwrap()
        .close()
        .unwrap();
    let link = fp::join(&[td.as_str(), "link"]);
    os::symlink("real", &link).unwrap();
    let mut seen = Vec::new();
    go_walk(&link, true, |p, _, _| {
        seen.push(p.to_string());
        Ok(())
    })
    .unwrap();
    assert_eq!(seen, std::slice::from_ref(&link));
    let mut seen = Vec::new();
    go_walk(&format!("{link}/"), true, |p, _, _| {
        seen.push(p.to_string());
        Ok(())
    })
    .unwrap();
    assert_eq!(seen.len(), 2, "a trailing slash follows the link: {seen:?}");
    os::remove_all(&td).unwrap();
}

// ---- EvalSymlinks, Abs, Glob -------------------------------------------------

const EVAL_DIRS: [(&str, &str); 17] = [
    ("test", ""),
    ("test/dir", ""),
    ("test/dir/link3", "../../"),
    ("test/link1", "../test"),
    ("test/link2", "dir"),
    ("test/linkabs", "/"),
    ("test/link4", "../test2"),
    ("test2", "test/dir"),
    ("src", ""),
    ("src/pool", ""),
    ("src/pool/test", ""),
    ("src/versions", ""),
    ("src/versions/current", "../../version"),
    ("src/versions/v1", ""),
    ("src/versions/v1/modules", ""),
    ("src/versions/v1/modules/test", "../../../pool/test"),
    ("version", "src/versions/v1"),
];

const EVAL_TESTS: [(&str, &str); 12] = [
    ("test", "test"),
    ("test/dir", "test/dir"),
    ("test/dir/../..", "."),
    ("test/link1", "test"),
    ("test/link2", "test/dir"),
    ("test/link1/dir", "test/dir"),
    ("test/link2/..", "test"),
    ("test/dir/link3", "."),
    ("test/link2/link3/test", "test"),
    ("test/linkabs", "/"),
    ("test/link4/..", "test"),
    ("src/versions/current/modules/test", "src/pool/test"),
];

#[test]
fn eval_symlinks() {
    let _g = CWD.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = temp();
    for (path, dest) in EVAL_DIRS {
        let p = format!("{tmp}/{path}");
        if dest.is_empty() {
            os::mkdir(&p, FileMode(0o755)).unwrap();
        } else {
            os::symlink(dest, &p).unwrap();
        }
    }
    let check = |path: &str, want: &str| {
        let have =
            fp::eval_symlinks(path).unwrap_or_else(|e| panic!("EvalSymlinks({path:?}): {e}"));
        assert_eq!(fp::clean(&have), fp::clean(want), "EvalSymlinks({path:?})");
    };
    for (path, dest) in EVAL_TESTS {
        let full = format!("{tmp}/{path}");
        let want = if dest.starts_with('/') {
            dest.to_string()
        } else {
            format!("{tmp}/{dest}")
        };
        check(&full, &want);
        // EvalSymlinks(".") from inside, and relative paths after a chdir.
        os::chdir(&full).unwrap();
        check(".", ".");
        os::chdir(&format!("{tmp}/test")).unwrap();
        let dotdot = if dest.starts_with('/') {
            dest.to_string()
        } else {
            format!("../{dest}")
        };
        check(&format!("../{path}"), &dotdot);
        os::chdir(&tmp).unwrap();
        check(path, dest);
    }
    os::chdir("/").unwrap();
    os::remove_all(&tmp).unwrap();
}

#[test]
fn eval_symlinks_is_not_exist() {
    let _g = CWD.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = temp();
    os::chdir(&tmp).unwrap();
    let err = fp::eval_symlinks("notexist").unwrap_err();
    assert!(os::is_not_exist(&err), "{err}");
    os::symlink("notexist", "link").unwrap();
    let err = fp::eval_symlinks("link").unwrap_err();
    assert!(os::is_not_exist(&err), "{err}");
    os::symlink("loop", "loop").unwrap();
    assert_eq!(
        fp::eval_symlinks("loop").unwrap_err().to_string(),
        "EvalSymlinks: too many links"
    );
    os::chdir("/").unwrap();
    os::remove_all(&tmp).unwrap();
}

#[test]
fn abs() {
    let _g = CWD.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = temp();
    os::chdir(&tmp).unwrap();
    for rel in ["a/b", ".", "", "../x", "a/../b/./c/", "//x"] {
        let want = if rel.starts_with('/') {
            fp::clean(rel)
        } else {
            fp::join(&[os::getwd().unwrap().as_str(), rel])
        };
        assert_eq!(fp::abs(rel).unwrap(), want, "Abs({rel:?})");
    }
    assert!(fp::is_abs(&fp::abs("").unwrap()));
    os::chdir("/").unwrap();
    os::remove_all(&tmp).unwrap();
}

#[test]
fn glob() {
    let _g = CWD.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = temp();
    for d in ["a", "b", "b/c", "d.dir"] {
        os::mkdir(&format!("{tmp}/{d}"), FileMode(0o755)).unwrap();
    }
    for f in [
        "a/x.go", "a/y.go", "b/c/z.go", "b/t.txt", "top.go", ".hidden",
    ] {
        os::write_file(&format!("{tmp}/{f}"), b"", FileMode(0o644)).unwrap();
    }
    os::chdir(&tmp).unwrap();
    let cases: [(&str, Vec<&str>); 13] = [
        ("*", vec![".hidden", "a", "b", "d.dir", "top.go"]),
        (".*", vec![".hidden"]),
        ("*.go", vec!["top.go"]),
        ("a/*.go", vec!["a/x.go", "a/y.go"]),
        ("*/*.go", vec!["a/x.go", "a/y.go"]),
        ("*/*/*.go", vec!["b/c/z.go"]),
        ("[ab]/*", vec!["a/x.go", "a/y.go", "b/c", "b/t.txt"]),
        ("a/[xy].go", vec!["a/x.go", "a/y.go"]),
        ("a/?.go", vec!["a/x.go", "a/y.go"]),
        ("nope", vec![]),
        ("nope*", vec![]),
        ("a/x.go", vec!["a/x.go"]),
        ("*.dir", vec!["d.dir"]),
    ];
    for (pattern, want) in cases {
        assert_eq!(fp::glob(pattern).unwrap(), want, "Glob({pattern:?})");
    }
    let abs = format!("{tmp}/a/*.go");
    assert_eq!(
        fp::glob(&abs).unwrap(),
        [format!("{tmp}/a/x.go"), format!("{tmp}/a/y.go")]
    );
    // Malformed patterns are errors, however they are reached.
    for bad in ["[", "a[", "a/[", "\\", "[a-", "[]a]x/[", "*/["] {
        assert!(fp::glob(bad).is_err(), "Glob({bad:?}) should fail");
    }
    os::chdir("/").unwrap();
    os::remove_all(&tmp).unwrap();
}

#[test]
fn constants_and_misc() {
    assert_eq!(fp::SEPARATOR, '/');
    assert_eq!(fp::LIST_SEPARATOR, ':');
    assert_eq!(fp::volume_name("/a/b"), "");
    assert!(fp::has_prefix("/a/b", "/a"));
    assert!(!fp::has_prefix("/a", "/a/b"));
    assert_eq!(fs::SKIP_DIR.to_string(), "skip this directory");
    assert_eq!(
        fs::SKIP_ALL.to_string(),
        "skip everything and stop the walk"
    );
}
