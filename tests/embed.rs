//! Tests for `rust_stdlib::embed` (Go's `embed.FS`), including the
//! `embed_files!` macro over `tests/fixtures/embed`. The `embed!` directory
//! macro is covered in `tools/derive-check`.

use rust_stdlib::embed::FS;
use rust_stdlib::embed_files;
use rust_stdlib::io as rio;
use rust_stdlib::io::fs::{self, DirEntry, FileMode, MODE_DIR};
use std::io::Read;

static FILES: FS = embed_files!(
    "fixtures/embed/hello.txt",
    "fixtures/embed/sub/a.txt",
    "fixtures/embed/sub/b.txt",
    "alias.txt" => "fixtures/embed/hello.txt",
);

#[test]
fn macro_embeds_file_contents() {
    assert_eq!(
        FILES.read_file("fixtures/embed/hello.txt").unwrap(),
        b"hello, world\n"
    );
    assert_eq!(FILES.read_file("alias.txt").unwrap(), b"hello, world\n");
    assert_eq!(
        FILES.read_file("fixtures/embed/sub/b.txt").unwrap(),
        b"bravo"
    );
}

fn names(list: Vec<Box<dyn DirEntry>>) -> Vec<String> {
    list.iter()
        .map(|e| format!("{}{}", e.name(), if e.is_dir() { "/" } else { "" }))
        .collect()
}

#[test]
fn read_dir_lists_sorted_entries_with_synthesized_directories() {
    assert_eq!(
        names(FILES.read_dir(".").unwrap()),
        ["alias.txt", "fixtures/"]
    );
    assert_eq!(names(FILES.read_dir("fixtures").unwrap()), ["embed/"]);
    assert_eq!(
        names(FILES.read_dir("fixtures/embed").unwrap()),
        ["hello.txt", "sub/"]
    );
    assert_eq!(
        names(FILES.read_dir("fixtures/embed/sub").unwrap()),
        ["a.txt", "b.txt"]
    );
}

#[test]
fn open_stat_and_modes() {
    let f = FILES.open("fixtures/embed/sub/a.txt").unwrap();
    let info = f.stat().unwrap();
    assert_eq!(info.name(), "a.txt");
    assert_eq!(info.size(), 6);
    assert_eq!(info.mode(), FileMode(0o444));
    assert!(!info.is_dir() && info.mod_time().is_zero());
    let dir = FILES.open("fixtures").unwrap().stat().unwrap();
    assert!(dir.is_dir());
    assert_eq!(dir.mode(), MODE_DIR | FileMode(0o555));
    assert_eq!(dir.mode().to_string(), "dr-xr-xr-x");
    let root = FILES.open(".").unwrap().stat().unwrap();
    assert_eq!((root.name(), root.is_dir()), (".", true));
}

#[test]
fn errors_match_go() {
    let err = FILES.open("missing").err().unwrap();
    assert_eq!(err.to_string(), "open missing: file does not exist");
    assert!(fs::ERR_NOT_EXIST.is(&err));
    let err = FILES.open("/abs").err().unwrap();
    assert_eq!(err.to_string(), "open /abs: file does not exist");
    let err = FILES.read_file("fixtures").unwrap_err();
    assert_eq!(err.to_string(), "read fixtures: is a directory");
    let err = FILES.read_dir("alias.txt").unwrap_err();
    assert_eq!(err.to_string(), "read alias.txt: not a directory");
    // Reading a directory handle fails with the directory's Go name.
    let mut d = FILES.open("fixtures").unwrap();
    let err = d.read(&mut [0u8; 4]).unwrap_err();
    assert_eq!(err.to_string(), "read fixtures/: is a directory");
}

#[test]
fn read_dir_file_batches_and_eof() {
    let mut d = FILES.open("fixtures/embed/sub").unwrap();
    let dir = d.as_read_dir_file().expect("directory");
    assert_eq!(names(dir.read_dir(1).unwrap()), ["a.txt"]);
    assert_eq!(names(dir.read_dir(5).unwrap()), ["b.txt"]);
    assert!(rio::is_eof(dir.read_dir(1).unwrap_err().source()));
    assert!(dir.read_dir(-1).unwrap().is_empty());
}

#[test]
fn generic_fs_functions_work() {
    let m = fs::glob(&FILES, "fixtures/*/sub/*.txt").unwrap();
    assert_eq!(m, ["fixtures/embed/sub/a.txt", "fixtures/embed/sub/b.txt"]);
    let mut seen = Vec::new();
    fs::walk_dir(&FILES, "fixtures/embed", |p, d, e| {
        assert!(e.is_none());
        seen.push(format!("{p}{}", if d.unwrap().is_dir() { "/" } else { "" }));
        Ok(())
    })
    .unwrap();
    assert_eq!(
        seen,
        [
            "fixtures/embed/",
            "fixtures/embed/hello.txt",
            "fixtures/embed/sub/",
            "fixtures/embed/sub/a.txt",
            "fixtures/embed/sub/b.txt",
        ]
    );
    let sub = fs::sub(&FILES, "fixtures/embed/sub").unwrap();
    assert_eq!(fs::read_file(sub.as_ref(), "b.txt").unwrap(), b"bravo");
    let err = fs::read_file(sub.as_ref(), "../hello.txt").unwrap_err();
    assert_eq!(err.to_string(), "read ../hello.txt: invalid argument");
    assert_eq!(fs::stat(&FILES, "alias.txt").unwrap().size(), 13);
}

#[test]
fn empty_and_manual_file_sets() {
    let empty = FS::default();
    assert!(empty.read_dir(".").unwrap().is_empty());
    assert!(empty.open("x").is_err());
    static SET: FS = FS::new(&[
        ("b/c.txt", b"c"),
        ("a.txt", b"a"),
        ("bad//name", b"x"),
        (".", b"y"),
    ]);
    assert_eq!(names(SET.read_dir(".").unwrap()), ["a.txt", "b/"]);
    assert_eq!(SET.read_file("b/c.txt").unwrap(), b"c");
    assert!(SET.open("bad//name").is_err());
    let copy = SET.clone();
    assert_eq!(copy.read_file("a.txt").unwrap(), b"a");
}
