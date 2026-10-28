//! Go `archive/zip` parity tests. Tables are ported from Go's reader_test.go,
//! writer_test.go and zip_test.go (BSD-licensed, see NOTICE); fixtures in
//! tests/fixtures/archive/zip are from Go's testdata. zip_golden.txt is Go's
//! own transcript of those fixtures (kept fresh by tools/check_archive_api.py).
#[path = "../examples/common/archive_transcript.rs"]
mod archive_transcript;
use archive_transcript::zip_transcript;
use rust_stdlib::archive::iofs::{self, time_parts, time_unix, FileInfo, FileMode, ReadCloser};
use rust_stdlib::archive::zip::{self, *};
use rust_stdlib::io::fs::{self, MapFS, MapFile, FS};
use rust_stdlib::io::ReadAt;
use std::io::{self, Read, Write};
use std::sync::Arc;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/archive/zip/");

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}{name}")).unwrap()
}

fn open(name: &str) -> Reader<Vec<u8>> {
    let data = fixture(name);
    let size = data.len() as i64;
    Reader::new(data, size).unwrap()
}

fn read_file<R: ReadAt>(f: &File<R>) -> io::Result<Vec<u8>> {
    let mut rc = f.open()?;
    let mut out = Vec::new();
    rc.read_to_end(&mut out)?;
    Ok(out)
}

fn new_reader(bytes: Vec<u8>) -> io::Result<Reader<Vec<u8>>> {
    let size = bytes.len() as i64;
    Reader::new(bytes, size).map_err(io::Error::from)
}

fn cp437_to_utf8_hex(hex: &str) -> String {
    let raw: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    let text = match std::str::from_utf8(&raw) {
        Ok(_) => return hex.to_string(),
        Err(_) => cp437_decode(&raw),
    };
    text.bytes().map(|b| format!("{b:02x}")).collect()
}

/// Apply the accepted differences to a transcript (see tools/check_archive_api.py).
fn relax(lines: &[&str], drop_fs: bool) -> Vec<String> {
    lines
        .iter()
        .filter(|l| !(drop_fs && l.starts_with("FS ")))
        .map(|l| {
            let mut l = l.to_string();
            if l.starts_with("F ") || l.starts_with("Z ") {
                l = l
                    .split(' ')
                    .map(|kv| match kv.split_once('=') {
                        Some((k @ ("name" | "comment"), v)) => {
                            format!("{k}={}", cp437_to_utf8_hex(v))
                        }
                        _ => kv.to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
            }
            if l.starts_with(['D', 'R']) && l.ends_with("err=1") {
                l = format!("{} err=1", &l[..1]);
            }
            l
        })
        .collect()
}

#[test]
fn golden_transcripts_match_go() {
    let golden = std::fs::read_to_string(format!("{FIXTURES}../zip_golden.txt")).unwrap();
    let mut seen = 0;
    for block in golden.split("@@ ").skip(1) {
        let (name, want) = block.split_once('\n').unwrap();
        let data = fixture(name);
        let size = data.len() as i64;
        let got = zip_transcript(Reader::new(data, size).map_err(io::Error::from));
        let want: Vec<&str> = want.lines().collect();
        let got: Vec<&str> = got.lines().collect();
        let drop_fs = want.iter().any(|l| {
            l.starts_with("F ")
                && l.split(' ')
                    .find_map(|kv| kv.strip_prefix("name="))
                    .is_some_and(|h| cp437_to_utf8_hex(h) != h)
        });
        assert_eq!(relax(&got, drop_fs), relax(&want, drop_fs), "{name}");
        seen += 1;
    }
    assert!(seen >= 30, "only {seen} fixtures in the golden file");
}

struct Want(&'static str, Option<&'static [u8]>, i64, u32);

fn check_files(name: &str, comment: &str, files: &[Want]) {
    let zr = open(name);
    assert_eq!(zr.comment, comment, "{name}");
    assert_eq!(zr.file.len(), files.len(), "{name}");
    for (f, Want(file_name, content, modified, mode)) in zr.file.iter().zip(files) {
        assert_eq!(f.file_header.name, *file_name, "{name}");
        assert_eq!(
            time_parts(&f.file_header.modified).0,
            *modified,
            "{name}/{file_name}"
        );
        assert_eq!(f.file_header.mode().0, *mode, "{name}/{file_name}");
        if let Some(content) = content {
            assert_eq!(read_file(f).unwrap(), *content, "{name}/{file_name}");
        }
    }
}

#[test]
fn reader_table() {
    let test_files = [
        Want(
            "test.txt",
            Some(b"This is a test text file.\n"),
            1283652721,
            0o644,
        ),
        Want("gophercolor16x16.png", None, 1283665978, 0o644),
    ];
    for name in [
        "test.zip",
        "test-trailing-junk.zip",
        "test-prefix.zip",
        "test-baddirsz.zip",
        "test-badbase.zip",
    ] {
        check_files(name, "This is a zipfile comment.", &test_files);
    }
    check_files(
        "symlink.zip",
        "",
        &[Want(
            "symlink",
            Some(b"../target"),
            1328306208,
            0o777 | FileMode::SYMLINK.0,
        )],
    );
    let zr = open("readme.zip");
    assert_eq!(zr.file.len(), 1);
    assert_eq!(zr.file[0].file_header.name, "README");
    assert_eq!(read_file(&zr.file[0]).unwrap().len(), 1096);
    assert!(zr.comment.starts_with("This is the source code repository"));
    check_files(
        "dd.zip",
        "",
        &[Want(
            "filename",
            Some(b"This is a test textfile.\n"),
            1296651980,
            0o666,
        )],
    );
    let dir_mode = FileMode::DIR.0 | 0o777;
    for name in ["winxp.zip", "unix.zip"] {
        check_files(
            name,
            "",
            &[
                Want("hello", Some(b"world \r\n"), 1323338664, 0o666),
                Want("dir/bar", Some(b"foo \r\n"), 1323338690, 0o666),
                Want("dir/empty/", Some(b""), 1323338886, dir_mode),
                Want("readonly", Some(b"important \r\n"), 1323338768, 0o444),
            ],
        );
    }
    let foo_bar = [
        Want("foo.txt", Some(b"foo\n"), 1331254750, 0o644),
        Want("bar.txt", Some(b"bar\n"), 1331254752, 0o644),
    ];
    check_files("go-no-datadesc-sig.zip", "", &foo_bar);
    check_files("crc32-not-streamed.zip", "", &foo_bar);
    check_files(
        "go-with-datadesc-sig.zip",
        "",
        &[
            Want("foo.txt", Some(b"foo\n"), 312768000, 0o666),
            Want("bar.txt", Some(b"bar\n"), 312768000, 0o666),
        ],
    );
    check_files(
        "zip64.zip",
        "",
        &[Want(
            "README",
            Some(b"This small file is in ZIP64 format.\n"),
            1344609212,
            0o644,
        )],
    );
    check_files(
        "zip64-2.zip",
        "",
        &[Want(
            "README",
            Some(b"This small file is in ZIP64 format.\n"),
            1344623612,
            0o644,
        )],
    );
}

#[test]
fn not_a_zip_file() {
    let bytes = std::fs::read(format!("{FIXTURES}../zip/../zip/readme.zip")).unwrap();
    assert!(new_reader(bytes[..bytes.len() - 30].to_vec()).is_err());
    assert!(new_reader(Vec::new()).is_err());
    let err = Reader::new(Vec::<u8>::new(), -1).unwrap_err();
    assert!(err.to_string().contains("size cannot be negative"));
    let err =
        new_reader(b"this is not a zip file at all, just text padding.....".to_vec()).unwrap_err();
    assert!(ERR_FORMAT.matches(&err));
}

#[test]
fn utf8_and_extended_timestamps() {
    // utf8-7zip: flag set; times with 100ns precision come from the NTFS field.
    let zr = open("utf8-7zip.zip");
    let h = &zr.file[0].file_header;
    assert_eq!(h.name, "\u{4e16}\u{754c}");
    assert!(!h.non_utf8);
    assert_eq!(time_parts(&h.modified), (1510002567, 867862500));

    // utf8-infozip: flag set (Go 1.27 fixture), valid UTF-8.
    let zr = open("utf8-infozip.zip");
    assert!(!zr.file[0].file_header.non_utf8);
    assert_eq!(zr.file[0].file_header.name, "\u{4e16}\u{754c}");

    // time-infozip: extended timestamp field, whole seconds.
    let zr = open("time-infozip.zip");
    assert_eq!(time_parts(&zr.file[0].file_header.modified).1, 0);
    assert_eq!(zr.file[0].file_header.mode(), FileMode(0o644));
    let zr = open("time-7zip.zip");
    assert_eq!(time_parts(&zr.file[0].file_header.modified).1, 244817900);
}

#[test]
fn checksum_and_size_errors() {
    // Stored member written by this crate.
    let mut buf = Vec::new();
    {
        let mut w = Writer::new(&mut buf);
        let mut f = w
            .create_header(&FileHeader {
                name: "a.txt".into(),
                method: STORE,
                ..FileHeader::default()
            })
            .unwrap();
        f.write_all(b"hello world").unwrap();
        w.close().unwrap();
    }
    assert_eq!(
        read_file(&new_reader(buf.clone()).unwrap().file[0]).unwrap(),
        b"hello world"
    );

    // Corrupt the data: the CRC in the data descriptor no longer matches.
    let at = buf.windows(11).position(|w| w == b"hello world").unwrap();
    let mut bad = buf.clone();
    bad[at] ^= 1;
    let err = read_file(&new_reader(bad).unwrap().file[0]).unwrap_err();
    assert!(ERR_CHECKSUM.matches(&err), "{err}");

    // Central directory claims a larger size: data ends early.
    let zr = new_reader(buf.clone()).unwrap();
    let mut f = zr.file[0].clone();
    f.file_header.uncompressed_size64 += 5;
    let err = read_file(&f).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);

    // Smaller size: more data than declared.
    let mut f = zr.file[0].clone();
    f.file_header.uncompressed_size64 -= 5;
    let err = read_file(&f).unwrap_err();
    assert!(ERR_FORMAT.matches(&err), "{err}");

    // A member whose CRC-32 is recorded as zero is not checked when it has no descriptor.
    let zr = open("crc32-not-streamed.zip");
    assert_eq!(read_file(&zr.file[0]).unwrap(), b"foo\n");
    let mut data = fixture("crc32-not-streamed.zip");
    let at = data.windows(4).position(|w| w == b"foo\n").unwrap();
    data[at] = b'x';
    let zr = new_reader(data).unwrap();
    assert!(ERR_CHECKSUM.matches(&read_file(&zr.file[0]).unwrap_err()));
    assert_eq!(read_file(&zr.file[1]).unwrap(), b"bar\n");
}

#[test]
fn algorithm_errors_and_registration() {
    let mut buf = Vec::new();
    {
        let mut w = Writer::new(&mut buf);
        let err = w
            .create_header(&FileHeader {
                name: "x".into(),
                method: 99,
                ..FileHeader::default()
            })
            .err()
            .unwrap();
        assert!(ERR_ALGORITHM.matches(&err));
        // Register a toy "XOR" method on this writer only.
        w.register_compressor(
            99,
            Arc::new(|sink: Box<dyn Write>| {
                struct Xor(Box<dyn Write>);
                impl Write for Xor {
                    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                        let enc: Vec<u8> = b.iter().map(|c| c ^ 0x5a).collect();
                        self.0.write_all(&enc)?;
                        Ok(b.len())
                    }
                    fn flush(&mut self) -> io::Result<()> {
                        self.0.flush()
                    }
                }
                impl iofs::WriteCloser for Xor {
                    fn close(&mut self) -> io::Result<()> {
                        Ok(())
                    }
                }
                Ok(Box::new(Xor(sink)) as Box<dyn iofs::WriteCloser>)
            }),
        );
        let mut f = w
            .create_header(&FileHeader {
                name: "x".into(),
                method: 99,
                ..FileHeader::default()
            })
            .unwrap();
        f.write_all(b"secret").unwrap();
        w.close().unwrap();
    }
    let zr = new_reader(buf).unwrap();
    assert!(ERR_ALGORITHM.matches(&zr.file[0].open().err().unwrap()));
    zr.register_decompressor(
        99,
        Arc::new(|r| {
            struct Xor<'a>(Box<dyn Read + 'a>);
            impl Read for Xor<'_> {
                fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                    let n = self.0.read(b)?;
                    b[..n].iter_mut().for_each(|c| *c ^= 0x5a);
                    Ok(n)
                }
            }
            impl ReadCloser for Xor<'_> {}
            Box::new(Xor(r))
        }),
    );
    assert_eq!(read_file(&zr.file[0]).unwrap(), b"secret");
    // The raw bytes are the XOR of the data.
    let mut raw = Vec::new();
    zr.file[0]
        .open_raw()
        .unwrap()
        .read_to_end(&mut raw)
        .unwrap();
    assert_eq!(raw, b"secret".iter().map(|c| c ^ 0x5a).collect::<Vec<_>>());

    // Process-wide registration; duplicates panic as in Go.
    let comp: Compressor = Arc::new(|w| {
        struct Nop(Box<dyn Write>);
        impl Write for Nop {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.0.write(b)
            }
            fn flush(&mut self) -> io::Result<()> {
                self.0.flush()
            }
        }
        impl iofs::WriteCloser for Nop {
            fn close(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        Ok(Box::new(Nop(w)) as Box<dyn iofs::WriteCloser>)
    });
    register_compressor(65_000, comp.clone());
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| register_compressor(
            65_000, comp
        )))
        .is_err()
    );
    let dcomp: Decompressor = Arc::new(|r| {
        struct Nop<'a>(Box<dyn Read + 'a>);
        impl Read for Nop<'_> {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                self.0.read(b)
            }
        }
        impl ReadCloser for Nop<'_> {}
        Box::new(Nop(r))
    });
    register_decompressor(65_000, dcomp.clone());
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| register_decompressor(
            65_000, dcomp
        )))
        .is_err()
    );
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| register_decompressor(
            STORE,
            Arc::new(|r| {
                struct N<'a>(Box<dyn Read + 'a>);
                impl Read for N<'_> {
                    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                        self.0.read(b)
                    }
                }
                impl ReadCloser for N<'_> {}
                Box::new(N(r))
            })
        )))
        .is_err()
    );
}

struct WriteTest {
    name: &'static str,
    data: &'static [u8],
    method: u16,
    mode: FileMode,
}

const WRITE_TESTS: &[WriteTest] = &[
    WriteTest {
        name: "foo",
        data: b"Rabbits, guinea pigs, gophers, marsupial rats, and quolls.",
        method: STORE,
        mode: FileMode(0o666),
    },
    WriteTest {
        name: "bar",
        data: b"",
        method: DEFLATE,
        mode: FileMode(0o644),
    },
    WriteTest {
        name: "setuid",
        data: b"setuid file",
        method: DEFLATE,
        mode: FileMode(0o755 | (1 << 23)),
    },
    WriteTest {
        name: "setgid",
        data: b"setgid file",
        method: DEFLATE,
        mode: FileMode(0o755 | (1 << 22)),
    },
    WriteTest {
        name: "symlink",
        data: b"../link/target",
        method: DEFLATE,
        mode: FileMode(0o755 | (1 << 27)),
    },
    WriteTest {
        name: "device",
        data: b"device file",
        method: DEFLATE,
        mode: FileMode(0o755 | (1 << 26)),
    },
    WriteTest {
        name: "chardevice",
        data: b"char device file",
        method: DEFLATE,
        mode: FileMode(0o755 | (1 << 26) | (1 << 21)),
    },
    WriteTest {
        name: "pipe",
        data: b"named pipe file",
        method: DEFLATE,
        mode: FileMode(0o755 | (1 << 25)),
    },
    WriteTest {
        name: "socket",
        data: b"socket file",
        method: DEFLATE,
        mode: FileMode(0o755 | (1 << 24)),
    },
];

fn write_tests_archive() -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut w = Writer::new(&mut buf);
        for wt in WRITE_TESTS {
            let mut fh = FileHeader {
                name: wt.name.into(),
                method: wt.method,
                ..FileHeader::default()
            };
            fh.set_mode(wt.mode);
            let mut f = w.create_header(&fh).unwrap();
            f.write_all(wt.data).unwrap();
        }
        w.close().unwrap();
    }
    buf
}

#[test]
fn writer_round_trip_and_copy() {
    let bytes = write_tests_archive();
    let zr = new_reader(bytes).unwrap();
    for (f, wt) in zr.file.iter().zip(WRITE_TESTS) {
        assert_eq!(f.file_header.name, wt.name);
        assert_eq!(f.file_header.method, wt.method);
        assert_eq!(f.file_header.mode(), wt.mode, "{}", wt.name);
        assert_eq!(read_file(f).unwrap(), wt.data, "{}", wt.name);
        assert_eq!(
            f.file_header.flags & 0x8,
            0x8,
            "streamed members use data descriptors"
        );
        assert_eq!(f.file_header.creator_version, 3 << 8 | 20);
    }
    // Copy: the compressed bytes move without recompression.
    let mut buf2 = Vec::new();
    {
        let mut dst = Writer::new(&mut buf2);
        for f in &zr.file {
            dst.copy(f).unwrap();
        }
        dst.close().unwrap();
    }
    let r2 = new_reader(buf2).unwrap();
    for ((a, b), wt) in zr.file.iter().zip(&r2.file).zip(WRITE_TESTS) {
        assert_eq!(read_file(b).unwrap(), wt.data);
        let (mut ra, mut rb) = (Vec::new(), Vec::new());
        a.open_raw().unwrap().read_to_end(&mut ra).unwrap();
        b.open_raw().unwrap().read_to_end(&mut rb).unwrap();
        assert_eq!(ra, rb, "{}", wt.name);
        assert_eq!(a.file_header.crc32, b.file_header.crc32);
    }
}

#[test]
fn writer_comment_offset_flush_and_close() {
    let mut buf = Vec::new();
    {
        let mut w = Writer::new(&mut buf);
        w.set_comment("hi there").unwrap();
        assert!(w.set_comment(&"x".repeat(1 << 16)).is_err());
        w.set_comment("hi there").unwrap();
        w.create("foo").unwrap();
        w.flush().unwrap();
        w.close().unwrap();
        assert!(w.close().is_err(), "closing twice is an error");
    }
    let zr = new_reader(buf).unwrap();
    assert_eq!(zr.comment, "hi there");
    assert_eq!(zr.file.len(), 1);

    // SetOffset: an archive appended to other data, with offsets shifted.
    let mut out = b"preamble".to_vec();
    {
        let mut w = Writer::new(&mut out);
        w.set_offset(8);
        let mut f = w
            .create_header(&FileHeader {
                name: "a".into(),
                method: STORE,
                ..FileHeader::default()
            })
            .unwrap();
        f.write_all(b"data").unwrap();
        w.close().unwrap();
    }
    let zr = new_reader(out).unwrap();
    assert_eq!(read_file(&zr.file[0]).unwrap(), b"data");
    assert!(std::panic::catch_unwind(|| {
        let mut w = Writer::new(Vec::new());
        w.create("x").unwrap();
        w.set_offset(5);
    })
    .is_err());
}

#[test]
fn writer_directories() {
    let mut w = Writer::new(Vec::new());
    let mut d = w.create("dir/").unwrap();
    assert_eq!(d.write(&[]).unwrap(), 0);
    assert!(d.write(b"hello").is_err());

    // Sizes and method of a directory header are reset; no data descriptor.
    let mut buf = Vec::new();
    {
        let mut w = Writer::new(&mut buf);
        w.create_header(&FileHeader {
            name: "dir/".into(),
            method: DEFLATE,
            compressed_size64: 1234,
            uncompressed_size64: 5678,
            ..FileHeader::default()
        })
        .unwrap();
        w.close().unwrap();
    }
    let at = buf
        .windows(4)
        .position(|w| w == [0x50, 0x4b, 3, 4])
        .unwrap();
    assert_eq!(&buf[at + 6..at + 10], &[0, 0, 0, 0], "flags and method");
    assert_eq!(&buf[at + 14..at + 26], &[0u8; 12], "crc and sizes");
    assert!(
        !buf.windows(4).any(|w| w == [0x50, 0x4b, 7, 8]),
        "no data descriptor"
    );

    // Directory mode attributes.
    let mut fh = FileHeader {
        name: "d/".into(),
        ..FileHeader::default()
    };
    fh.set_mode(FileMode::DIR | FileMode(0o755));
    assert_eq!(fh.external_attrs & 0x10, 0x10);
    assert_eq!(fh.mode(), FileMode::DIR | FileMode(0o755));
}

#[test]
fn writer_utf8_flags() {
    let tests: &[(&str, &str, bool, u16)] = &[
        ("hi, hello", "in the world", false, 0x8),
        (
            "hi, \u{3053}\u{3093}\u{306b}\u{3061}\u{308f}",
            "in the world",
            false,
            0x808,
        ),
        (
            "hi, \u{3053}\u{3093}\u{306b}\u{3061}\u{308f}",
            "in the world",
            true,
            0x8,
        ),
        ("hi, hello", "in the \u{4e16}\u{754c}", false, 0x808),
        (
            "the replacement rune is \u{fffd}",
            "the replacement rune is \u{fffd}",
            false,
            0x808,
        ),
    ];
    let mut buf = Vec::new();
    {
        let mut w = Writer::new(&mut buf);
        for (name, comment, non_utf8, _) in tests {
            let mut f = w
                .create_header(&FileHeader {
                    name: (*name).into(),
                    comment: (*comment).into(),
                    non_utf8: *non_utf8,
                    method: DEFLATE,
                    ..FileHeader::default()
                })
                .unwrap();
            f.write_all(&[]).unwrap();
        }
        w.close().unwrap();
    }
    let zr = new_reader(buf).unwrap();
    for (f, (name, comment, non_utf8, flags)) in zr.file.iter().zip(tests) {
        assert_eq!(f.file_header.flags, *flags, "{name:?}");
        assert_eq!(f.file_header.comment, *comment);
        assert_eq!(
            f.file_header.non_utf8,
            *non_utf8 || f.file_header.flags & 0x800 == 0 && !name.is_ascii()
        );
    }
}

#[test]
fn cp437_names_round_trip() {
    // 0x82 is e-acute in CP437.
    let raw = [b'c', b'a', b'f', 0x82, b'.', b't', b'x', b't'];
    assert_eq!(cp437_decode(&raw), "caf\u{e9}.txt");
    assert_eq!(cp437_encode("caf\u{e9}.txt").unwrap(), raw);
    assert!(cp437_encode("\u{65e5}").is_none());
    for b in 0..=255u8 {
        let s = cp437_decode(&[b]);
        assert_eq!(cp437_encode(&s).unwrap(), [b], "byte {b:#x}");
    }
    // Writer: like Go, the name bytes are written as given (raw_name when set); CP437
    // bytes come from cp437_encode. The reader decodes them and keeps the raw bytes.
    let mut buf = Vec::new();
    {
        let mut w = Writer::new(&mut buf);
        w.create_header(&FileHeader {
            name: "caf\u{e9}.txt".into(),
            comment: "\u{2502}note".into(),
            raw_name: Some(raw.to_vec()),
            raw_comment: cp437_encode("\u{2502}note"),
            non_utf8: true,
            method: STORE,
            ..FileHeader::default()
        })
        .unwrap();
        w.close().unwrap();
    }
    assert!(buf.windows(raw.len()).any(|w| w == raw));
    let zr = new_reader(buf).unwrap();
    let h = &zr.file[0].file_header;
    assert_eq!(h.name, "caf\u{e9}.txt");
    assert_eq!(h.comment, "\u{2502}note");
    assert_eq!(h.name_bytes(), raw);
    assert_eq!(h.raw_name.as_deref(), Some(&raw[..]));
    assert!(h.non_utf8);
    assert_eq!(h.flags & 0x800, 0);

    // NonUTF8 with a UTF-8 name keeps the UTF-8 bytes (no CP437 re-encoding), as in Go.
    let mut buf = Vec::new();
    {
        let mut w = Writer::new(&mut buf);
        w.create_header(&FileHeader {
            name: "caf\u{e9}.txt".into(),
            non_utf8: true,
            method: STORE,
            ..FileHeader::default()
        })
        .unwrap();
        w.close().unwrap();
    }
    let utf8 = "caf\u{e9}.txt".as_bytes();
    assert!(buf.windows(utf8.len()).any(|w| w == utf8));
    let h = &new_reader(buf).unwrap().file[0].file_header;
    assert_eq!(h.raw_name, None);
    assert_eq!(h.name_bytes(), utf8);
}

#[test]
fn extended_timestamps_and_dos_times() {
    let t = time_unix(1_509_509_517, 0); // 2017-11-01 04:11:57 UTC
    let mut buf = Vec::new();
    {
        let mut w = Writer::new(&mut buf);
        w.create_header(&FileHeader {
            name: "test.txt".into(),
            modified: t,
            method: STORE,
            ..FileHeader::default()
        })
        .unwrap();
        w.close().unwrap();
    }
    let zr = new_reader(buf).unwrap();
    let h = &zr.file[0].file_header;
    assert_eq!(h.modified, t);
    assert_eq!(h.extra[..4], [0x55, 0x54, 5, 0], "extended timestamp field");
    assert_eq!((h.modified_date, h.modified_time), (19297, 8572));

    // Go's TestModTime and the DOS conversion table.
    let mut fh = FileHeader::default();
    let test_time = time_unix(1_257_896_758, 0); // 2009-11-10 23:45:58 UTC
    fh.set_mod_time(test_time);
    assert_eq!(fh.mod_time(), test_time);
    for (secs, date, time) in [
        (315_532_800i64, 0x0021u16, 0x0000u16), // 1980-01-01
        (312_768_000, 65406, 0x0000),           // 1979-11-30: year wraps
        (1_700_000_000, 22382, 45482),
    ] {
        let mut fh = FileHeader::default();
        fh.set_mod_time(time_unix(secs, 0));
        assert_eq!((fh.modified_date, fh.modified_time), (date, time), "{secs}");
    }
    // Fields outside their ranges normalise like time.Date.
    let fh = FileHeader {
        modified_date: 0,
        modified_time: 0,
        ..FileHeader::default()
    };
    assert_eq!(time_parts(&fh.mod_time()).0, 312_768_000); // month 0 day 0: 1979-11-30
}

fn header_round_trip(fh: &FileHeader, want32: u32, want64: u64) {
    let fi = fh.file_info();
    let fh2 = file_info_header(&fi).unwrap();
    assert_eq!(fh2.name, fh.name);
    assert_eq!(fh2.uncompressed_size, want32);
    assert_eq!(fh2.uncompressed_size64, want64);
    assert_eq!(fh2.modified_time, fh.modified_time);
    assert_eq!(fh2.modified_date, fh.modified_date);
    assert!(fi.sys().is_some_and(|s| s.is::<FileHeader>()));
}

#[test]
fn file_header_round_trips() {
    header_round_trip(
        &FileHeader {
            name: "foo.txt".into(),
            uncompressed_size: 987654321,
            uncompressed_size64: 987654321,
            modified_time: 1234,
            modified_date: 5678,
            ..FileHeader::default()
        },
        987654321,
        987654321,
    );
    header_round_trip(
        &FileHeader {
            name: "foo.txt".into(),
            uncompressed_size64: 9876543210,
            modified_time: 1234,
            modified_date: 5678,
            ..FileHeader::default()
        },
        u32::MAX,
        9876543210,
    );
    let fh = FileHeader {
        name: "foo.txt".into(),
        uncompressed_size64: 987654321,
        modified: time_unix(1_600_000_000, 123),
        modified_time: 1234,
        modified_date: 5678,
        ..FileHeader::default()
    };
    let fi = fh.file_info();
    let fh2 = file_info_header(&fi).unwrap();
    assert_eq!(fh2.modified, fh.modified);
    assert_eq!(fi.mod_time(), fh.modified);
    assert_eq!(fi.name(), "foo.txt");
    assert_eq!(fi.size(), 987654321);
}

#[test]
fn modes_round_trip() {
    for (mode, attrs) in [
        (FileMode(0o644), 0o100644u32),
        (FileMode(0o755) | FileMode::SETUID, 0o104755),
        (FileMode(0o755) | FileMode::SETGID, 0o102755),
        (FileMode(0o777) | FileMode::STICKY, 0o101777),
        (FileMode(0o777) | FileMode::SYMLINK, 0o120777),
        (FileMode(0o600) | FileMode::NAMED_PIPE, 0o010600),
        (FileMode(0o600) | FileMode::SOCKET, 0o140600),
        (FileMode(0o600) | FileMode::DEVICE, 0o060600),
        (
            FileMode(0o600) | FileMode::DEVICE | FileMode::CHAR_DEVICE,
            0o020600,
        ),
        (FileMode(0o755) | FileMode::DIR, 0o040755),
    ] {
        let mut fh = FileHeader {
            name: "n".into(),
            ..FileHeader::default()
        };
        fh.set_mode(mode);
        assert_eq!(fh.external_attrs >> 16, attrs, "{mode}");
        assert_eq!(fh.creator_version >> 8, 3);
        assert_eq!(
            fh.mode().0 & !FileMode::DIR.0,
            mode.0 & !FileMode::DIR.0,
            "{mode}"
        );
    }
    // MS-DOS attribute bytes from FAT/NTFS creators.
    let fh = FileHeader {
        name: "r".into(),
        creator_version: 0,
        external_attrs: 0x01,
        ..FileHeader::default()
    };
    assert_eq!(fh.mode(), FileMode(0o444));
    let fh = FileHeader {
        name: "d/".into(),
        creator_version: 11 << 8,
        external_attrs: 0x10,
        ..FileHeader::default()
    };
    assert_eq!(fh.mode(), FileMode::DIR | FileMode(0o777));
    assert_eq!(FileHeader::default().mode(), FileMode(0o666));
}

#[test]
fn over_65k_files_use_zip64_directory() {
    const N: usize = (1 << 16) + 42;
    let mut buf = Vec::new();
    {
        let mut w = Writer::new(&mut buf);
        for i in 0..N {
            w.create_header(&FileHeader {
                name: format!("{i}.dat"),
                method: STORE,
                ..FileHeader::default()
            })
            .unwrap();
        }
        w.close().unwrap();
    }
    // ZIP64 end of central directory record and locator are present.
    assert!(buf.windows(4).any(|w| w == [0x50, 0x4b, 6, 6]));
    assert!(buf.windows(4).any(|w| w == [0x50, 0x4b, 6, 7]));
    let zr = new_reader(buf).unwrap();
    assert_eq!(zr.file.len(), N);
    for (i, f) in zr.file.iter().enumerate() {
        assert_eq!(f.file_header.name, format!("{i}.dat"));
    }
}

#[test]
fn zip64_sizes_and_offsets_round_trip() {
    // CreateRaw lets a header claim sizes beyond 4 GiB without the data.
    let mut buf = Vec::new();
    let big = 5u64 << 30;
    {
        let mut w = Writer::new(&mut buf);
        let fh = FileHeader {
            name: "big".into(),
            method: STORE,
            crc32: 0x1234_5678,
            compressed_size64: big,
            uncompressed_size64: big + 7,
            ..FileHeader::default()
        };
        w.create_raw(&fh).unwrap();
        w.close().unwrap();
    }
    let zr = new_reader(buf.clone()).unwrap();
    let h = &zr.file[0].file_header;
    assert_eq!(h.compressed_size64, big);
    assert_eq!(h.uncompressed_size64, big + 7);
    assert_eq!(h.compressed_size, u32::MAX);
    assert_eq!(h.uncompressed_size, u32::MAX);
    assert_eq!(h.crc32, 0x1234_5678);
    assert_eq!(h.reader_version, 45);
    assert_eq!(zr.file[0].data_offset().unwrap(), 30 + 3 + 20);
    assert_eq!(zr.file[0].file_info().size(), (big + 7) as i64);
    // Local header carries the ZIP64 extra field too.
    assert!(buf.windows(4).any(|w| w == [1, 0, 16, 0]));
}

#[test]
fn create_raw_with_descriptors() {
    let payload = b"raw payload";
    let crc = rust_stdlib::compress::crc32(payload);
    let mut buf = Vec::new();
    {
        let mut w = Writer::new(&mut buf);
        let mut f = w
            .create_raw(&FileHeader {
                name: "r".into(),
                method: STORE,
                flags: 0x8,
                crc32: crc,
                compressed_size64: payload.len() as u64,
                uncompressed_size64: payload.len() as u64,
                ..FileHeader::default()
            })
            .unwrap();
        f.write_all(payload).unwrap();
        w.close().unwrap();
    }
    let zr = new_reader(buf).unwrap();
    assert_eq!(read_file(&zr.file[0]).unwrap(), payload);
    assert_eq!(zr.file[0].file_header.crc32, crc);
}

#[test]
fn data_offset_and_open_raw() {
    let zr = open("test.zip");
    for f in &zr.file {
        let off = f.data_offset().unwrap();
        assert!(off > 0);
        let mut raw = Vec::new();
        f.open_raw().unwrap().read_to_end(&mut raw).unwrap();
        assert_eq!(raw.len() as u64, f.file_header.compressed_size64);
    }
}

fn walk(fsys: &dyn FS) -> Vec<String> {
    let mut out = Vec::new();
    let r = fs::walk_dir(
        fsys,
        ".",
        |name: &str, _: Option<&dyn fs::DirEntry>, err| {
            if let Some(e) = err {
                return Err(e);
            }
            out.push(name.to_string());
            Ok(())
        },
    );
    if r.is_err() {
        out.push("ERROR".into());
    }
    out
}

#[test]
fn fs_view() {
    let z = open("unix.zip");
    assert_eq!(
        walk(&z),
        [".", "dir", "dir/bar", "dir/empty", "hello", "readonly"]
    );
    let z = open("subdir.zip");
    assert_eq!(walk(&z), [".", "a", "a/b", "a/b/c"]);
    // Duplicate names make directory listings fail.
    let z = open("dupdir.zip");
    assert_eq!(walk(&z).last().map(String::as_str), Some("ERROR"));

    let z = open("unix.zip");
    let mut f = z.open("hello").unwrap();
    let mut body = String::new();
    f.read_to_string(&mut body).unwrap();
    assert_eq!(body, "world \r\n");
    assert_eq!(f.stat().unwrap().name(), "hello");
    // Directories: synthesised and explicit.
    let mut d = z.open("dir").unwrap();
    assert!(d.stat().unwrap().is_dir());
    assert_eq!(
        d.stat().unwrap().mode(),
        fs::FileMode(fs::MODE_DIR.0 | 0o555)
    );
    let entries = d.as_read_dir_file().unwrap().read_dir(-1).unwrap();
    let names: Vec<String> = entries.iter().map(|e| e.name().to_string()).collect();
    assert_eq!(names, ["bar", "empty"]);
    assert!(entries[1].is_dir());
    assert!(d.read(&mut [0u8; 1]).is_err(), "reading a directory fails");
    // Errors: invalid and missing names.
    for bad in ["/abs", "a//b", "dir/", ".."] {
        let err = z.open(bad).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{bad}");
    }
    assert_eq!(
        z.open("missing").err().unwrap().kind(),
        io::ErrorKind::NotFound
    );
    // Batched ReadDir ends with EOF.
    let mut root = z.open(".").unwrap();
    assert_eq!(
        root.as_read_dir_file().unwrap().read_dir(2).unwrap().len(),
        2
    );
    assert_eq!(
        root.as_read_dir_file().unwrap().read_dir(2).unwrap().len(),
        1
    );
    assert_eq!(
        root.as_read_dir_file()
            .unwrap()
            .read_dir(2)
            .err()
            .unwrap()
            .source()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
    // Names are cleaned: backslashes, leading slashes and "../".
    let mut buf = Vec::new();
    {
        let mut w = Writer::new(&mut buf);
        for name in ["a\\b.txt", "/abs.txt", "../up.txt"] {
            let mut f = w
                .create_header(&FileHeader {
                    name: name.into(),
                    method: STORE,
                    ..FileHeader::default()
                })
                .unwrap();
            f.write_all(name.as_bytes()).unwrap();
        }
        w.close().unwrap();
    }
    let z = new_reader(buf).unwrap();
    assert_eq!(walk(&z), [".", "a", "a/a\\b.txt", "abs.txt", "up.txt"]);
    let mut body = String::new();
    z.open("abs.txt")
        .unwrap()
        .read_to_string(&mut body)
        .unwrap();
    assert_eq!(body, "/abs.txt");
}

#[test]
fn insecure_paths() {
    let mut buf = Vec::new();
    {
        let mut w = Writer::new(&mut buf);
        for name in ["ok/file", "../escape"] {
            w.create_header(&FileHeader {
                name: name.into(),
                method: STORE,
                ..FileHeader::default()
            })
            .unwrap();
        }
        w.close().unwrap();
    }
    let data = buf.clone();
    let size = buf.len() as i64;
    // Default: accepted.
    let zr = Reader::with_options(data.clone(), size, false).unwrap();
    assert_eq!(zr.file.len(), 2);
    assert!(ERR_INSECURE_PATH.matches(&zr.check_insecure_paths().unwrap_err()));
    // zipinsecurepath=0: ErrInsecurePath carrying the usable reader.
    let as_io = Reader::with_options(data.clone(), size, true)
        .err()
        .unwrap();
    assert!(ERR_INSECURE_PATH.matches(&io::Error::from(as_io)));
    let err = Reader::with_options(data, size, true).err().unwrap();
    assert_eq!(err.to_string(), "zip: insecure file path");
    let carried = err.into_reader().unwrap();
    assert_eq!(carried.file.len(), 2);
    // Backslashes are insecure too; plain names are fine.
    let secure = zip_with(&["a/b.txt", "c.txt"]);
    assert!(secure.check_insecure_paths().is_ok());
    assert!(zip_with(&["a\\b.txt"]).check_insecure_paths().is_err());
}

fn zip_with(names: &[&str]) -> Reader<Vec<u8>> {
    let mut buf = Vec::new();
    {
        let mut w = Writer::new(&mut buf);
        for n in names {
            w.create_header(&FileHeader {
                name: (*n).into(),
                method: STORE,
                ..FileHeader::default()
            })
            .unwrap();
        }
        w.close().unwrap();
    }
    new_reader(buf).unwrap()
}

#[test]
fn open_reader_from_file() {
    let path = std::env::temp_dir().join(format!("rust-stdlib-zip-{}.zip", std::process::id()));
    std::fs::write(&path, fixture("unix.zip")).unwrap();
    let rc = open_reader(&path).unwrap();
    assert_eq!(rc.reader.file.len(), 4);
    assert_eq!(rc.file.len(), 4, "ReadCloser derefs to Reader");
    assert_eq!(read_file(&rc.file[0]).unwrap(), b"world \r\n");
    rc.close().unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(open_reader(&path).is_err());
}

#[test]
fn add_fs_writes_deflated_members() {
    let mut fsys = MapFS::new();
    fsys.insert("file.go", MapFile::new(&b"hello"[..], fs::FileMode(0o644)));
    fsys.insert(
        "subfolder/another.go",
        MapFile::new(&b"world"[..], fs::FileMode(0o644)),
    );
    fsys.insert(
        "emptyfolder",
        MapFile::new(&b""[..], fs::FileMode(fs::MODE_DIR.0 | 0o755)),
    );
    let mut buf = Vec::new();
    {
        let mut w = Writer::new(&mut buf);
        w.add_fs(&fsys).unwrap();
        w.close().unwrap();
    }
    let zr = new_reader(buf).unwrap();
    let names: Vec<&str> = zr
        .file
        .iter()
        .map(|f| f.file_header.name.as_str())
        .collect();
    assert_eq!(
        names,
        [
            "emptyfolder/",
            "file.go",
            "subfolder/",
            "subfolder/another.go"
        ]
    );
    assert_eq!(read_file(&zr.file[1]).unwrap(), b"hello");
    assert_eq!(read_file(&zr.file[3]).unwrap(), b"world");
    assert_eq!(zr.file[1].file_header.method, DEFLATE);
    assert_eq!(zr.file[0].file_header.method, STORE);
    assert!(zr.file[0].file_header.mode().is_dir());

    // Symlinks (non-regular files) are refused, as in Go.
    let mut bad = MapFS::new();
    bad.insert(
        "symlink",
        MapFile::new(&b"x"[..], fs::FileMode(fs::MODE_SYMLINK.0 | 0o777)),
    );
    let mut w = Writer::new(Vec::new());
    assert!(w.add_fs(&bad).is_err());
}

#[test]
fn directory_entries_with_data_fail_to_read() {
    // A directory entry that claims data reads as ErrFormat; one without reads as empty.
    let zr = open("unix.zip");
    let mut f = zr.file[2].clone();
    assert_eq!(f.file_header.name, "dir/empty/");
    assert_eq!(read_file(&f).unwrap(), b"");
    f.file_header.uncompressed_size64 = 5;
    let mut rc = f.open().unwrap();
    assert!(ERR_FORMAT.matches(&rc.read(&mut [0u8; 8]).unwrap_err()));
}

#[test]
fn legacy_api_still_strict() {
    // ZIP64 stays rejected by the bounded helpers; plain archives still read.
    assert!(zip::read(&fixture("zip64.zip")[..], zip::Limits::default()).is_err());
    let entries = zip::read(&fixture("test.zip")[..], zip::Limits::default()).unwrap();
    assert_eq!(entries.len(), 2);
}

#[test]
fn writer_exposes_the_headers_go_updates_in_place() {
    let mut buf = Vec::new();
    let mut w = Writer::new(&mut buf);
    let mut fw = w
        .create_header(&FileHeader {
            name: "a.txt".into(),
            method: STORE,
            ..FileHeader::default()
        })
        .unwrap();
    assert_eq!(
        fw.header().flags & 0x8,
        0x8,
        "data descriptor flag is set at creation"
    );
    fw.write_all(b"hello").unwrap();
    let header = fw.finish().unwrap();
    assert_eq!(header.uncompressed_size64, 5);
    assert_eq!(header.compressed_size64, 5);
    assert_eq!(header.crc32, 0x3610a686);
    w.close().unwrap();
    let headers: Vec<_> = w.headers().collect();
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].crc32, 0x3610a686);
}

#[cfg(feature = "net")]
#[test]
fn writer_wraps_borrowed_response_writer() {
    use rust_stdlib::net::http::{httptest::ResponseRecorder, ResponseWriter};
    fn stream(w: &mut dyn ResponseWriter) {
        {
            let mut zw = zip::Writer::new(&mut *w);
            let mut f = zw.create("a.txt").unwrap();
            f.write_all(b"hello").unwrap();
            zw.close().unwrap();
        }
        w.header().set("X-After", "still usable");
    }
    let mut rec = ResponseRecorder::new();
    stream(&mut rec);
    let body = rec.body.clone().unwrap();
    let n = body.len() as i64;
    let r = Reader::new(body, n).unwrap();
    assert_eq!(read_file(&r.file[0]).unwrap(), b"hello");
    assert_eq!(rec.header_map.get("X-After"), Some("still usable"));
}

#[test]
fn reader_over_cursor_and_file() {
    let bytes = fixture("test.zip");
    let size = bytes.len() as i64;
    let over_cursor = Reader::new(io::Cursor::new(bytes.clone()), size).unwrap();
    let over_vec = new_reader(bytes.clone()).unwrap();
    assert_eq!(over_cursor.file.len(), over_vec.file.len());
    for (a, b) in over_cursor.file.iter().zip(&over_vec.file) {
        assert_eq!(a.file_header.name, b.file_header.name);
        assert_eq!(read_file(a).unwrap(), read_file(b).unwrap());
    }
    // The cursor position does not matter to positional reads.
    let mut moved = io::Cursor::new(bytes.clone());
    moved.set_position(7);
    assert!(Reader::new(moved, size).is_ok());

    let path =
        std::env::temp_dir().join(format!("rust-stdlib-zip-file-{}.zip", std::process::id()));
    std::fs::write(&path, &bytes).unwrap();
    let over_file = Reader::new(std::fs::File::open(&path).unwrap(), size).unwrap();
    assert_eq!(over_file.file.len(), over_vec.file.len());
    assert_eq!(
        read_file(&over_file.file[0]).unwrap(),
        read_file(&over_vec.file[0]).unwrap()
    );
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn reader_over_borrowed_file_and_slice() {
    let bytes = fixture("test.zip");
    let size = bytes.len() as i64;
    let owned = new_reader(bytes.clone()).unwrap();

    // A borrowed slice needs no copy and no 'static.
    let over_slice = Reader::new(&bytes[..], size).unwrap();
    assert_eq!(over_slice.file.len(), owned.file.len());
    for (a, b) in over_slice.file.iter().zip(&owned.file) {
        assert_eq!(a.file_header.name, b.file_header.name);
        assert_eq!(read_file(a).unwrap(), read_file(b).unwrap());
    }

    // A borrowed &File needs no try_clone; the file stays usable afterwards.
    let path =
        std::env::temp_dir().join(format!("rust-stdlib-zip-borrow-{}.zip", std::process::id()));
    std::fs::write(&path, &bytes).unwrap();
    let file = std::fs::File::open(&path).unwrap();
    {
        let over_file = Reader::new(&file, size).unwrap();
        assert_eq!(over_file.file.len(), owned.file.len());
        assert_eq!(
            read_file(&over_file.file[0]).unwrap(),
            read_file(&owned.file[0]).unwrap()
        );
        let mut raw = Vec::new();
        over_file.file[0]
            .open_raw()
            .unwrap()
            .read_to_end(&mut raw)
            .unwrap();
        assert!(!raw.is_empty() || over_file.file[0].file_header.compressed_size64 == 0);
    }
    let again = Reader::new(&file, size).unwrap();
    assert_eq!(again.file.len(), owned.file.len());
    drop(again);
    drop(file);
    std::fs::remove_file(&path).unwrap();
}
