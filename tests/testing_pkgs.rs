//! Ports of the tests of Go's `testing/iotest`, `testing/fstest`,
//! `testing/quick`, `testing/slogtest` and `testing/synctest`.
//!
//! `tools/testing_check.py` compares the same packages with Go on generated
//! scenarios.
use rust_stdlib::{
    encoding::json,
    io::fs::{self, DirEntry, File, FileMode, ReadDirFile, FS, MODE_DIR, MODE_SYMLINK},
    log::slog::{Handler, JSONHandler},
    testing::{
        self,
        fstest::{test_fs, MapFS, MapFile},
        iotest::{self, ERR_TIMEOUT},
        quick::{self, Generator},
        slogtest, synctest, Options, TB,
    },
};
use std::{
    io::{self, Cursor, Read, Write},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

// ----------------------------------------------------------------- iotest

fn read_all_ones<R: Read>(mut r: R, buf_len: usize) -> (String, Vec<usize>) {
    let mut got = Vec::new();
    let mut sizes = Vec::new();
    let mut b = vec![0u8; buf_len];
    loop {
        let n = r.read(&mut b).unwrap();
        if n == 0 {
            break;
        }
        sizes.push(n);
        got.extend_from_slice(&b[..n]);
    }
    (String::from_utf8(got).unwrap(), sizes)
}

#[test]
fn one_byte_and_half_readers() {
    let msg = "Hello, World!";
    let (got, sizes) = read_all_ones(iotest::one_byte_reader(msg.as_bytes()), 3);
    assert_eq!(got, msg);
    assert!(sizes.iter().all(|&n| n == 1));
    assert_eq!(
        iotest::one_byte_reader(msg.as_bytes())
            .read(&mut [])
            .unwrap(),
        0
    );

    let (got, sizes) = read_all_ones(iotest::half_reader(msg.as_bytes()), 2);
    assert_eq!(got, msg);
    assert!(sizes.iter().all(|&n| n == 1));
    let (got, sizes) = read_all_ones(iotest::half_reader(msg.as_bytes()), 5);
    assert_eq!(got, msg);
    assert_eq!(sizes[0], 3);
    // Empty readers hit EOF immediately.
    assert_eq!(
        iotest::one_byte_reader(io::empty())
            .read(&mut [0u8; 5])
            .unwrap(),
        0
    );
}

#[test]
fn timeout_reader() {
    let mut r = iotest::timeout_reader(Cursor::new(b"Hello, World!".to_vec()));
    assert_eq!(r.read(&mut []).unwrap(), 0);
    let e = r.read(&mut []).unwrap_err();
    assert!(iotest::is_err_timeout(&e));
    assert_eq!(e.to_string(), "timeout");
    assert_eq!(e.kind(), io::ErrorKind::TimedOut);
    assert_eq!(ERR_TIMEOUT.to_string(), "timeout");
    // Later reads succeed.
    let mut b = [0u8; 3];
    assert_eq!(r.read(&mut b).unwrap(), 3);
    assert_eq!(&b, b"Hel");
}

#[test]
fn data_err_reader_look_ahead() {
    // The error found by the look-ahead arrives with the call after the last data.
    let mut r = iotest::data_err_reader(Cursor::new(b"Hello, World!".to_vec()));
    let mut got = Vec::new();
    let mut b = [0u8; 3];
    let mut reads = 0;
    loop {
        let n = r.read(&mut b).unwrap();
        reads += 1;
        if n == 0 {
            break;
        }
        got.extend_from_slice(&b[..n]);
    }
    assert_eq!(got, b"Hello, World!");
    assert_eq!(reads, 6, "5 data reads and the end of input");

    // A reader whose error follows its data: the error is delivered after it.
    struct DataThenError(bool);
    impl Read for DataThenError {
        fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
            if !self.0 {
                self.0 = true;
                p[..2].copy_from_slice(b"ab");
                Ok(2)
            } else {
                Err(io::Error::other("boom"))
            }
        }
    }
    let mut r = iotest::data_err_reader(DataThenError(false));
    assert_eq!(r.read(&mut b).unwrap(), 2);
    assert_eq!(r.read(&mut b).unwrap_err().to_string(), "boom");
}

#[test]
fn err_reader() {
    let mut r = iotest::err_reader(io::Error::other("custom"));
    for _ in 0..3 {
        let e = r.read(&mut [0u8; 4]).unwrap_err();
        assert_eq!(e.to_string(), "custom");
        assert_eq!(e.kind(), io::ErrorKind::Other);
    }
    let e = iotest::err_reader(io::Error::from(io::ErrorKind::NotFound))
        .read(&mut [])
        .unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::NotFound);
}

#[test]
fn truncate_writer_table() {
    for (input, want, trunc, n) in [
        ("hello", "", -1, 5),
        ("world", "", 0, 5),
        ("abcde", "abc", 3, 5),
        ("edcba", "edcba", 7, 5),
    ] {
        let mut buf = Vec::new();
        let mut tw = iotest::truncate_writer(&mut buf, trunc);
        assert_eq!(tw.write(input.as_bytes()).unwrap(), n);
        assert_eq!(String::from_utf8(buf).unwrap(), want);
    }
}

#[test]
fn read_and_write_loggers() {
    use rust_stdlib::log;
    // Serialise: the standard logger is process-wide.
    static LOCK: Mutex<()> = Mutex::new(());
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    #[derive(Clone)]
    struct Shared(Arc<Mutex<Vec<u8>>>);
    impl Write for Shared {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let out = Shared(Arc::new(Mutex::new(Vec::new())));
    let (old_flags, old_prefix) = (log::flags(), log::prefix());
    log::set_prefix("lw: ");
    log::set_flags(0);
    log::set_output(out.clone());

    let mut sink = Vec::new();
    let mut wl = iotest::WriteLogger::new("write:", &mut sink);
    wl.write_all(b"Hello, World!").unwrap();
    assert_eq!(sink, b"Hello, World!");
    let mut rl = iotest::ReadLogger::new("read:", &b"Hi"[..]);
    let mut b = [0u8; 8];
    assert_eq!(rl.read(&mut b).unwrap(), 2);
    assert_eq!(rl.read(&mut b).unwrap(), 0);

    struct ErrWriter;
    impl Write for ErrWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("Write error"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut wl = iotest::WriteLogger::new("write:", ErrWriter);
    assert!(wl.write(b"x").is_err());

    log::set_flags(old_flags);
    log::set_prefix(&old_prefix);
    log::set_output(io::stderr());
    let text = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        text,
        "lw: write: 48656c6c6f2c20576f726c6421\nlw: read: 4869\nlw: read: \nlw: write: : Write error\n"
    );
}

#[test]
fn test_reader_accepts_correct_readers() {
    for content in [
        &b""[..],
        b"a",
        b"ab",
        b"abc",
        b"Hello, World! Hello, World!",
    ] {
        iotest::test_reader(&mut rust_stdlib::text::Reader::new(content), content).unwrap();
        iotest::test_reader(&mut Cursor::new(content.to_vec()), content).unwrap();
        iotest::test_reader(&mut { content }, content).unwrap();
        let s = std::str::from_utf8(content).unwrap();
        iotest::test_reader(&mut rust_stdlib::text::Reader::new(s), content).unwrap();
        iotest::test_reader(
            &mut rust_stdlib::io::SectionReader::new(content.to_vec(), 0, content.len() as i64),
            content,
        )
        .unwrap();
    }
}

#[test]
fn test_reader_rejects_wrong_content_and_empty_read_errors() {
    let e = iotest::test_reader(&mut &b"abc"[..], b"abd").unwrap_err();
    assert_eq!(
        e.to_string(),
        "ReadAll(small amounts) = \"abc\"\n\twant \"abd\""
    );
    // A reader returning an error from a read is reported with its offset.
    let mut er = iotest::err_reader(io::Error::other("bad"));
    let e = iotest::test_reader(&mut er, b"x").unwrap_err();
    assert!(e.to_string().contains("bad"), "{e}");
}

// ----------------------------------------------------------------- fstest

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

#[test]
fn map_fs_passes_test_fs() {
    let m = map(&[
        ("hello", "hello, world\n"),
        (
            "fortune/k/ken.txt",
            "If a program is too slow, it must have a loop.\n",
        ),
    ]);
    test_fs(&m, &["hello", "fortune", "fortune/k", "fortune/k/ken.txt"]).unwrap();
    // The expected list must be present; an empty list demands an empty tree.
    let e = test_fs(&m, &["missing"]).unwrap_err();
    assert_eq!(
        e.to_string(),
        "TestFS found errors:\nexpected but not found: missing"
    );
    let e = test_fs(&m, &[]).unwrap_err();
    assert!(
        e.to_string().starts_with("TestFS found errors:\nexpected empty file system but found files:\nfortune\nfortune/k\nfortune/k/ken.txt\nhello"),
        "{e}"
    );
    test_fs(&MapFS::new(), &[]).unwrap();
    test_fs(&map(&[("a-b/a", "a-b/a")]), &["a-b/a"]).unwrap();
}

#[test]
fn map_fs_chmod_dot_and_file_info_name() {
    let mut m = MapFS::new();
    m.insert("a/b.txt", MapFile::new(Vec::new(), FileMode(0o666)));
    m.insert(".", MapFile::new(Vec::new(), FileMode(0o777) | MODE_DIR));
    let mut got = String::new();
    fs::walk_dir(&m, ".", |path, d, _err| {
        let fi = d.unwrap().info()?;
        got.push_str(&format!("{path}: {}\n", fi.mode()));
        Ok(())
    })
    .unwrap();
    assert_eq!(got, ".: drwxrwxrwx\na: dr-xr-xr-x\na/b.txt: -rw-rw-rw-\n");

    let m = map(&[("path/to/b.txt", "")]);
    assert_eq!(fs::stat(&m, "path/to/b.txt").unwrap().name(), "b.txt");
}

#[test]
fn map_fs_symlinks() {
    const CONTENT: &str = "If a program is too slow, it must have a loop.\n";
    let mut m = MapFS::new();
    m.insert(
        "fortune/k/ken.txt",
        MapFile::new(CONTENT.as_bytes().to_vec(), FileMode(0)),
    );
    for (name, target) in [
        ("dirlink", "fortune/k"),
        ("linklink", "dirlink"),
        ("ken.txt", "dirlink/ken.txt"),
    ] {
        m.insert(name, MapFile::new(target.as_bytes().to_vec(), MODE_SYMLINK));
    }
    test_fs(&m, &["fortune/k/ken.txt", "dirlink", "ken.txt", "linklink"]).unwrap();
    assert_eq!(fs::read_file(&m, "ken.txt").unwrap(), CONTENT.as_bytes());
    assert_eq!(fs::read_link(&m, "dirlink").unwrap(), "fortune/k");
    for (name, want_mode_of_lstat) in [("dirlink", MODE_SYMLINK), ("linklink", MODE_SYMLINK)] {
        let info = fs::lstat(&m, name).unwrap();
        assert_eq!((info.name(), info.mode()), (name, want_mode_of_lstat));
        let info = fs::stat(&m, name).unwrap();
        assert_eq!(info.name(), name);
        assert_eq!(info.mode(), MODE_DIR | FileMode(0o555));
    }
    // Absolute and looping links do not resolve.
    m.insert("abs", MapFile::new(b"/etc".to_vec(), MODE_SYMLINK));
    m.insert("loop1", MapFile::new(b"loop2".to_vec(), MODE_SYMLINK));
    m.insert("loop2", MapFile::new(b"loop1".to_vec(), MODE_SYMLINK));
    assert!(fs::stat(&m, "abs").is_err());
    assert!(fs::stat(&m, "loop1").is_err());
}

#[test]
fn map_file_sys_is_reported() {
    let mut m = MapFS::new();
    let mut f = MapFile::new(b"x".to_vec(), FileMode(0o644));
    f.sys = Some(Arc::new(42u32));
    m.insert("f", f);
    let info = fs::stat(&m, "f").unwrap();
    assert_eq!(info.sys().and_then(|s| s.downcast_ref::<u32>()), Some(&42));
}

/// A MapFS whose directory listings from `Open` come back in reverse order.
#[derive(Debug)]
struct ShuffledFS(MapFS);

#[derive(Debug)]
struct ShuffledFile(Box<dyn File>);

impl Read for ShuffledFile {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        self.0.read(p)
    }
}

impl File for ShuffledFile {
    fn stat(&self) -> io::Result<Box<dyn fs::FileInfo>> {
        self.0.stat()
    }
    fn close(&mut self) -> io::Result<()> {
        self.0.close()
    }
    fn as_read_dir_file(&mut self) -> Option<&mut dyn ReadDirFile> {
        self.0.as_read_dir_file()?;
        Some(self)
    }
}

impl ReadDirFile for ShuffledFile {
    fn read_dir(&mut self, n: i32) -> Result<Vec<Box<dyn DirEntry>>, fs::ReadDirError> {
        let mut list = self.0.as_read_dir_file().unwrap().read_dir(n)?;
        list.sort_by(|a, b| b.name().cmp(a.name()));
        Ok(list)
    }
}

impl FS for ShuffledFS {
    fn open(&self, name: &str) -> io::Result<Box<dyn File>> {
        Ok(Box::new(ShuffledFile(self.0.open(name)?)))
    }
}

#[test]
fn test_fs_ignores_directory_order() {
    let fsys = ShuffledFS(map(&[
        ("tmp/one", "1"),
        ("tmp/two", "2"),
        ("tmp/three", "3"),
    ]));
    test_fs(&fsys, &["tmp/one", "tmp/two", "tmp/three"]).unwrap();
}

#[derive(Debug)]
struct FailPermFS;

impl FS for FailPermFS {
    fn open(&self, name: &str) -> io::Result<Box<dyn File>> {
        if !fs::valid_path(name) {
            return Err(fs::PathError::new("open", name, fs::ERR_INVALID).into());
        }
        Err(fs::PathError::new("open", name, fs::ERR_PERMISSION).into())
    }
}

#[test]
fn test_fs_wraps_errors() {
    let err = test_fs(&FailPermFS, &[]).unwrap_err();
    assert!(
        fs::ERR_PERMISSION.is(&err),
        "error should wrap ErrPermission: {err}"
    );
    let list = err
        .get_ref()
        .and_then(|e| e.downcast_ref::<testing::fstest::TestFSError>())
        .expect("the error carries the list of problems");
    assert!(!list.errors().is_empty());
    for e in list.errors() {
        assert!(fs::ERR_PERMISSION.is(e), "unexpected error: {e}");
    }
    assert!(err
        .to_string()
        .starts_with("TestFS found errors:\n.: Open: open .: permission denied"));
}

#[test]
fn test_fs_on_a_real_directory_with_symlinks() {
    let dir = std::env::temp_dir().join(format!("fstest_rs_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("hello"), "hello, world\n").unwrap();
    std::fs::write(dir.join("sub/x"), "x").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(dir.join("hello"), dir.join("hello.link")).unwrap();
        std::os::unix::fs::symlink("hello", dir.join("hello_rel.link")).unwrap();
    }
    let fsys = rust_stdlib::io::fs::DirFS::new(&dir);
    test_fs(&fsys, &["hello", "hello.link", "sub/x"]).unwrap_or_else(|e| panic!("{e}"));
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------ quick

#[test]
fn check_equal_identity_functions() {
    quick::check_equal(|a: [u8; 4]| a, |a: [u8; 4]| a, None).unwrap();
    quick::check_equal(|a: bool| a, |a: bool| a, None).unwrap();
    quick::check_equal(|a: i16| a, |a: i16| a, None).unwrap();
    quick::check_equal(|a: u64| a, |a: u64| a, None).unwrap();
    quick::check_equal(|a: String| a, |a: String| a, None).unwrap();
    quick::check_equal(|a: Vec<u8>| a, |a: Vec<u8>| a, None).unwrap();
    quick::check_equal(
        |a: std::collections::BTreeMap<i64, i64>| a,
        |a: std::collections::BTreeMap<i64, i64>| a,
        None,
    )
    .unwrap();
    quick::check_equal(|a: Option<i64>| a, |a: Option<i64>| a, None).unwrap();
    // NaN != NaN, like reflect.DeepEqual: floats must be finite to be equal, and
    // the generated ones are.
    quick::check_equal(|a: f64| a, |a: f64| a, None).unwrap();
    quick::check_equal(|a: f32| a, |a: f32| a, None).unwrap();
}

struct MyStruct {
    x: i64,
}

impl Generator for MyStruct {
    fn generate(_rand: &mut quick::Rand, _size: usize) -> Self {
        MyStruct { x: 42 }
    }
}

impl Clone for MyStruct {
    fn clone(&self) -> Self {
        MyStruct { x: self.x }
    }
}

impl std::fmt::Debug for MyStruct {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MyStruct{{x: {}}}", self.x)
    }
}

#[test]
fn check_uses_generators() {
    quick::check(|m: MyStruct| m.x == 42, None).unwrap();
}

#[test]
fn check_failure_and_config() {
    let err = quick::check(|_: i64| false, None).unwrap_err();
    let quick::Error::Check(e) = &err else {
        panic!("not a CheckError: {err}");
    };
    assert_eq!(e.count, 1);
    assert_eq!(e.in_.len(), 1);
    assert!(err.to_string().starts_with("#1: failed on input "));

    let err = quick::check_equal(|x: i64| x, |x: i64| x + 1, None).unwrap_err();
    let quick::Error::CheckEqual(e) = &err else {
        panic!("not a CheckEqualError: {err}");
    };
    assert_eq!(e.check_error.count, 1);
    assert_eq!(e.out1.len(), 1);
    assert!(err.to_string().contains(". Output 1: "));

    // MaxCount and MaxCountScale; a seeded Rand makes runs repeatable.
    let calls = std::cell::Cell::new(0);
    let mut cfg = quick::Config {
        max_count: 7,
        rand: Some(quick::seeded_rand(1)),
        ..quick::Config::default()
    };
    quick::check(
        |_: u8| {
            calls.set(calls.get() + 1);
            true
        },
        Some(&mut cfg),
    )
    .unwrap();
    assert_eq!(calls.get(), 7);
    let mut cfg = quick::Config {
        max_count_scale: 0.5,
        ..quick::Config::default()
    };
    quick::set_default_max_count(40);
    let calls = std::cell::Cell::new(0);
    quick::check(
        |_: u8| {
            calls.set(calls.get() + 1);
            true
        },
        Some(&mut cfg),
    )
    .unwrap();
    assert_eq!(calls.get(), 20);
    quick::set_default_max_count(100);

    let first = |seed| {
        let mut cfg = quick::Config {
            max_count: 3,
            rand: Some(quick::seeded_rand(seed)),
            ..quick::Config::default()
        };
        quick::check(|_: i64| false, Some(&mut cfg))
            .unwrap_err()
            .to_string()
    };
    assert_eq!(first(5), first(5));
    assert_ne!(first(5), first(6));

    // Config.Values supplies the arguments.
    let mut cfg = quick::Config {
        max_count: 3,
        values: Some(Box::new(|_rand| {
            Box::new((5i64,)) as Box<dyn std::any::Any>
        })),
        ..quick::Config::default()
    };
    quick::check(|x: i64| x == 5, Some(&mut cfg)).unwrap();
    // The wrong argument type is a setup error.
    let mut cfg = quick::Config {
        max_count: 1,
        values: Some(Box::new(|_rand| Box::new("x") as Box<dyn std::any::Any>)),
        ..quick::Config::default()
    };
    assert!(matches!(
        quick::check(|_: i64| true, Some(&mut cfg)),
        Err(quick::Error::Setup(_))
    ));
}

#[test]
fn int64_covers_the_full_range() {
    let (lo, hi) = (std::cell::Cell::new(0i64), std::cell::Cell::new(0i64));
    let mut cfg = quick::Config {
        max_count: 10000,
        ..quick::Config::default()
    };
    quick::check(
        |x: i64| {
            lo.set(lo.get().min(x));
            hi.set(hi.get().max(x));
            true
        },
        Some(&mut cfg),
    )
    .unwrap();
    assert!((lo.get() as u64) >> 62 != 0 && (hi.get() as u64) >> 62 != 0);
}

#[test]
fn recursive_generators_terminate() {
    // Issues 8818 and 11148: the size hint shrinks with indirection.
    #[derive(Clone, Debug)]
    struct R {
        ptr: Option<Box<R>>,
        slice: Vec<R>,
    }
    impl R {
        fn size(&self) -> usize {
            1 + self.ptr.as_ref().map_or(0, |p| p.size())
                + self.slice.iter().map(R::size).sum::<usize>()
        }
    }
    impl Generator for R {
        fn generate(rand: &mut quick::Rand, size: usize) -> Self {
            let n = 2;
            let left = if n > size { 1 } else { size / n };
            let ptr = if rand.intn(left as i64) == 0 {
                None
            } else {
                Some(Box::new(R::generate(rand, left)))
            };
            let k = rand.intn(left as i64) as usize;
            let slice = (0..k).map(|_| R::generate(rand, left - k)).collect();
            R { ptr, slice }
        }
    }
    quick::check(|r: R| r.size() > 0, None).unwrap();
    // Zero-size values.
    quick::check(|_: ()| true, None).unwrap();
}

// -------------------------------------------------------------- slogtest

#[derive(Clone)]
struct Shared(Arc<Mutex<Vec<u8>>>);

impl Write for Shared {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn slogtest_run_and_test_handler_on_the_json_handler() {
    let buf = Shared(Arc::new(Mutex::new(Vec::new())));
    let b2 = buf.clone();
    let b3 = buf.clone();
    let r = testing::run_test_with(&Options::default(), "TestRun", move |t| {
        slogtest::run(
            t,
            |_t| {
                b2.0.lock().unwrap().clear();
                Arc::new(JSONHandler::new(b2.clone(), None)) as Arc<dyn Handler>
            },
            |_t| {
                (String::from_utf8(b3.0.lock().unwrap().clone()).unwrap())
                    .parse::<json::Value>()
                    .unwrap()
            },
        );
    });
    assert!(r.ok, "{}", r.output);

    let buf = Shared(Arc::new(Mutex::new(Vec::new())));
    let b2 = buf.clone();
    let h: Arc<dyn Handler> = Arc::new(JSONHandler::new(buf, None));
    slogtest::test_handler(h, move || {
        String::from_utf8(b2.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(|l| l.parse::<json::Value>().unwrap())
            .collect()
    })
    .unwrap();
}

#[test]
fn slogtest_reports_a_handler_that_misses_the_contract() {
    // A handler that drops everything: wrong result count.
    let h: Arc<dyn Handler> = Arc::new(JSONHandler::new(io::sink(), None));
    let e = slogtest::test_handler(h, Vec::new).unwrap_err();
    assert_eq!(e.to_string(), "got 0 results, want 17");
    // Results without the standard keys are reported check by check.
    let h: Arc<dyn Handler> = Arc::new(JSONHandler::new(io::sink(), None));
    let e = slogtest::test_handler(h, || (0..17).map(|_| json::Value::object([])).collect())
        .unwrap_err();
    let text = e.to_string();
    assert!(
        text.starts_with("missing key \"time\": this test expects slog.TimeKey"),
        "{text}"
    );
    assert!(
        text.contains("missing group \"G\": a Handler should handle Group attributes"),
        "{text}"
    );
}

// -------------------------------------------------------------- synctest

#[test]
fn synctest_fake_clock_and_wait() {
    let r = testing::run_test_with(&Options::default(), "TestTime", |t| {
        synctest::test(t, |t| {
            let start = synctest::now();
            assert_eq!(start.unix(), 946_684_800, "midnight UTC, 2000-01-01");
            let seen = Arc::new(Mutex::new(Vec::new()));
            let s2 = seen.clone();
            synctest::spawn(move || {
                synctest::time_sleep(rust_stdlib::time::Duration::from_secs(1));
                s2.lock()
                    .unwrap()
                    .push(synctest::now().unix() - 946_684_800);
            });
            let begin = std::time::Instant::now();
            synctest::time_sleep(rust_stdlib::time::Duration::from_secs(2));
            assert!(
                begin.elapsed() < Duration::from_millis(900),
                "no real time passes"
            );
            assert_eq!(
                *seen.lock().unwrap(),
                [1],
                "the goroutine ran before the sleep returned"
            );
            assert_eq!(synctest::now().unix() - 946_684_800, 2);
            t.log(&[&"done"]);
        });
    });
    assert!(r.ok, "{}", r.output);
}

#[test]
fn synctest_wait_blocks_until_others_are_blocked() {
    let r = testing::run_test_with(&Options::default(), "TestWait", |t| {
        synctest::test(t, |_t| {
            let done = Arc::new(AtomicBool::new(false));
            let d2 = done.clone();
            synctest::spawn(move || d2.store(true, Ordering::SeqCst));
            synctest::wait();
            assert!(done.load(Ordering::SeqCst));

            // Sleep is time.Sleep followed by Wait: a sleeping goroutine that wakes at
            // the same time has settled by the time Sleep returns.
            let steps = Arc::new(AtomicUsize::new(0));
            let s2 = steps.clone();
            synctest::spawn(move || {
                synctest::time_sleep(rust_stdlib::time::Duration::from_millis(10));
                s2.store(1, Ordering::SeqCst);
                synctest::time_sleep(rust_stdlib::time::Duration::from_millis(10));
                s2.store(2, Ordering::SeqCst);
            });
            synctest::sleep(rust_stdlib::time::Duration::from_millis(10));
            assert_eq!(steps.load(Ordering::SeqCst), 1);
            synctest::sleep(rust_stdlib::time::Duration::from_millis(10));
            assert_eq!(steps.load(Ordering::SeqCst), 2);
        });
    });
    assert!(r.ok, "{}", r.output);
}

#[test]
fn synctest_channels_are_durably_blocking() {
    let r = testing::run_test_with(&Options::default(), "TestChan", |t| {
        synctest::test(t, |_t| {
            let ch = synctest::Chan::new();
            let c2 = ch.clone();
            synctest::spawn(move || {
                synctest::time_sleep(rust_stdlib::time::Duration::from_secs(5));
                c2.send(7u32);
            });
            assert_eq!(ch.recv(), Some(7));
            assert_eq!(synctest::now().unix() - 946_684_800, 5);
            ch.close();
            assert_eq!(ch.recv(), None);
        });
    });
    assert!(r.ok, "{}", r.output);
}

#[test]
fn synctest_deadlock_fails_the_test() {
    let r = testing::run_test_with(&Options::default(), "TestDeadlock", |t| {
        synctest::test(t, |_t| {
            let ch: synctest::Chan<u8> = synctest::Chan::new();
            let _ = ch.recv(); // nothing can ever send
        });
    });
    assert!(!r.ok);
    assert!(
        r.output
            .contains("deadlock: all threads in bubble are durably blocked"),
        "{}",
        r.output
    );
}

#[test]
fn synctest_cleanup_and_failure_semantics() {
    let r = testing::run_test_with(&Options::default(), "TestCleanup", |t| {
        let ran = Arc::new(AtomicBool::new(false));
        let r2 = ran.clone();
        synctest::test(t, move |t| {
            assert!(synctest::in_bubble());
            let r3 = r2.clone();
            t.cleanup(move || {
                assert!(synctest::in_bubble(), "cleanups run inside the bubble");
                r3.store(true, Ordering::SeqCst);
            });
        });
        assert!(
            ran.load(Ordering::SeqCst),
            "cleanups ran before Test returned"
        );
        assert!(!synctest::in_bubble());
    });
    assert!(r.ok, "{}", r.output);

    // A failure in the bubble fails the enclosing test; its log goes to the parent.
    let r = testing::run_test_with(&Options::default(), "TestFail", |t| {
        synctest::test(t, |t| t.errorf(format_args!("inside")));
    });
    assert!(!r.ok);
    assert!(r.output.contains("--- FAIL: TestFail"), "{}", r.output);
    assert!(r.output.contains("inside"), "{}", r.output);
    assert!(!r.output.contains("--- FAIL: TestFail/"), "{}", r.output);

    // Run, Parallel and Deadline are not allowed in a bubble.
    let r = testing::run_test_with(&Options::default(), "TestForbidden", |t| {
        synctest::test(t, |t| {
            for f in [
                Box::new(|t: &testing::T| {
                    t.run("x", |_| {});
                }) as Box<dyn Fn(&testing::T)>,
                Box::new(|t: &testing::T| t.parallel()),
                Box::new(|t: &testing::T| {
                    t.deadline();
                }),
            ] {
                let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(t)));
                assert!(res.is_err());
            }
        });
    });
    assert!(r.ok, "{}", r.output);
}
