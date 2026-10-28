//! Go `archive/tar` parity tests. Tables are ported from Go's reader_test.go,
//! writer_test.go and tar_test.go (BSD-licensed, see NOTICE); the fixtures in
//! tests/fixtures/archive/tar are from Go's testdata. The golden transcript
//! (tar_golden.txt) was produced by Go's own Reader and is checked by
//! tools/check_archive_api.py for staleness.
#[path = "../examples/common/archive_transcript.rs"]
mod archive_transcript;
use archive_transcript::tar_transcript;
use rust_stdlib::archive::iofs::{time_unix, time_zero, FileInfo, FileInfoNames, FileMode};
use rust_stdlib::archive::tar::{self, *};
use rust_stdlib::hash::crc32::Crc32;
use rust_stdlib::io::fs::{self as iofs_fs, MapFS, MapFile};
use std::collections::BTreeMap;
use std::io::{self, Read, Write};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/archive/tar/");

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}{name}")).unwrap()
}

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Read every entry, returning headers and the CRC-32 of each entry's data,
/// plus the error that ended the archive (`None` for a normal end).
fn read_all(data: &[u8]) -> (Vec<(Header, u32)>, Option<io::Error>) {
    let mut tr = Reader::new(data);
    let mut out = Vec::new();
    loop {
        match tr.next() {
            Ok(None) => return (out, None),
            Err(e) => return (out, Some(e)),
            Ok(Some(h)) => {
                // Entries of many megabytes are skipped by the next call to next().
                if h.size > 1 << 24 {
                    out.push((h, 0));
                    continue;
                }
                let mut hash = Crc32::ieee();
                let result = io::copy(&mut tr, &mut hash);
                let mut sum = Vec::new();
                hash.sum(&mut sum);
                let crc = u32::from_be_bytes(sum.try_into().unwrap());
                out.push((h, crc));
                if let Err(e) = result {
                    return (out, Some(e));
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn hdr(
    name: &str,
    mode: i64,
    uid: i64,
    gid: i64,
    size: i64,
    mtime: i64,
    typeflag: u8,
    uname: &str,
    gname: &str,
    format: Format,
) -> Header {
    Header {
        typeflag,
        name: name.into(),
        mode,
        uid,
        gid,
        size,
        uname: uname.into(),
        gname: gname.into(),
        mod_time: time_unix(mtime, 0),
        format,
        ..Header::default()
    }
}

#[test]
fn golden_transcripts_match_go() {
    let golden = std::fs::read_to_string(format!("{FIXTURES}../tar_golden.txt")).unwrap();
    let mut seen = 0;
    for block in golden.split("@@ ").skip(1) {
        let (name, want) = block.split_once('\n').unwrap();
        let got = tar_transcript(&fixture(name));
        let want: Vec<&str> = want.lines().collect();
        let got: Vec<&str> = got.lines().collect();
        // Go strings may hold non-UTF-8 bytes; comparison stops at such an entry.
        let end = want
            .iter()
            .position(|l| l.starts_with("H ") && l.contains(" nonutf8=1"))
            .unwrap_or(want.len());
        assert_eq!(&got[..end.min(got.len())], &want[..end], "{name}");
        if end == want.len() {
            assert_eq!(got, want, "{name}");
        }
        seen += 1;
    }
    assert!(seen >= 37, "only {seen} fixtures in the golden file");
}

#[test]
fn reader_table() {
    // testdata/gnu.tar
    let (hs, err) = read_all(&fixture("gnu.tar"));
    assert!(err.is_none());
    let want = [
        hdr(
            "small.txt",
            0o640,
            73025,
            5000,
            5,
            1244428340,
            b'0',
            "dsymonds",
            "eng",
            FORMAT_GNU,
        ),
        hdr(
            "small2.txt",
            0o640,
            73025,
            5000,
            11,
            1244436044,
            b'0',
            "dsymonds",
            "eng",
            FORMAT_GNU,
        ),
    ];
    assert_eq!(hs.len(), 2);
    for ((got, crc), (want, want_crc)) in hs.iter().zip(want.iter().zip([0x6cbd88fc, 0xddac04b3])) {
        assert_eq!(got, want);
        assert_eq!(*crc, want_crc);
    }

    // testdata/v7.tar and star.tar
    let (hs, _) = read_all(&fixture("v7.tar"));
    assert_eq!(
        hs[0].0,
        hdr(
            "small.txt",
            0o444,
            73025,
            5000,
            5,
            1244593104,
            b'0',
            "",
            "",
            FORMAT_UNKNOWN
        )
    );
    let (hs, _) = read_all(&fixture("star.tar"));
    let mut small = hdr(
        "small.txt",
        0o640,
        73025,
        5000,
        5,
        1244592783,
        b'0',
        "dsymonds",
        "eng",
        FORMAT_UNKNOWN,
    );
    small.access_time = time_unix(1244592783, 0);
    small.change_time = time_unix(1244592783, 0);
    assert_eq!(hs[0].0, small);

    // testdata/pax.tar: long names, sub-second times and PAX records.
    let (hs, _) = read_all(&fixture("pax.tar"));
    let long_path = "a/123456789101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899100";
    assert_eq!(hs[0].0.name, long_path);
    assert_eq!(hs[0].0.mod_time, time_unix(1350244992, 23960108));
    assert_eq!(hs[0].0.format, FORMAT_PAX);
    assert_eq!(
        hs[0].0.pax_records,
        map(&[
            ("path", long_path),
            ("mtime", "1350244992.023960108"),
            ("atime", "1350244992.023960108"),
            ("ctime", "1350244992.023960108"),
        ])
    );
    assert_eq!(hs[1].0.typeflag, TYPE_SYMLINK);
    assert_eq!(hs[1].0.linkname.len(), 192);
    assert!(hs[1].0.linkname.starts_with("12345678910111213"));

    // testdata/xattrs.tar
    let (hs, _) = read_all(&fixture("xattrs.tar"));
    assert_eq!(hs[0].0.xattrs.len(), 3);
    assert_eq!(hs[0].0.xattrs["user.key"], "value");
    assert_eq!(
        hs[0].0.xattrs["security.selinux"],
        "unconfined_u:object_r:default_t:s0\0"
    );
    assert_eq!(hs[0].0.mod_time, time_unix(1386065770, 448252320));
    assert_eq!(hs[0].0.access_time, time_unix(1389782991, 419875220));

    // testdata/pax-global-records.tar
    let (hs, _) = read_all(&fixture("pax-global-records.tar"));
    assert_eq!(hs.len(), 6);
    assert_eq!(hs[0].0.typeflag, TYPE_X_GLOBAL_HEADER);
    assert_eq!(hs[0].0.name, "global1");
    assert_eq!(
        hs[0].0.pax_records,
        map(&[("path", "global1"), ("mtime", "1500000000.0")])
    );
    assert_eq!(hs[1].0.format, FORMAT_USTAR);
    assert_eq!(hs[2].0.pax_records, map(&[("path", "file2")]));
    assert_eq!(hs[3].0.name, "GlobalHead.0.0");
    assert_eq!(hs[5].0.mod_time, time_unix(1400000000, 0));

    // testdata/pax-pos-size-file.tar: a PAX size with leading zeros.
    let (hs, _) = read_all(&fixture("pax-pos-size-file.tar"));
    assert_eq!(hs[0].0.size, 999);
    assert_eq!(hs[0].1, 0x5fd7e86a);
    assert_eq!(
        hs[0].0.pax_records,
        map(&[("size", "000000000000000000000999")])
    );

    // GNU long name and link name headers (testdata/gnu-multi-hdrs.tar)
    let (hs, _) = read_all(&fixture("gnu-multi-hdrs.tar"));
    assert_eq!(hs[0].0.name, "GNU2/GNU2/long-path-name");
    assert_eq!(hs[0].0.linkname, "GNU4/GNU4/long-linkpath-name");
    assert_eq!(hs[0].0.format, FORMAT_GNU);

    // Both BSD and GNU tar truncate GNU long names at the first NUL.
    let (hs, _) = read_all(&fixture("gnu-long-nul.tar"));
    assert_eq!(hs[0].0.name, "0123456789");

    // gnu-incremental.tar: access and change times in the GNU header.
    let (hs, _) = read_all(&fixture("gnu-incremental.tar"));
    assert_eq!(hs[0].0.typeflag, b'D');
    assert_eq!(hs[0].0.access_time, time_unix(1441974501, 0));
    assert_eq!(hs[0].0.change_time, time_unix(1441973436, 0));
    assert_eq!(hs[2].0.typeflag, b'S');
    assert_eq!(hs[2].0.size, 536870912);

    // UTF-8 names in GNU format.
    let (hs, _) = read_all(&fixture("gnu-utf8.tar"));
    assert_eq!(hs[0].0.uname, "\u{263a}");
    assert_eq!(hs[0].0.gname, "\u{26b9}");
    assert_eq!(hs[0].0.name.chars().count(), 54);
}

#[test]
fn reader_errors() {
    for (name, why) in [
        ("pax-bad-hdr-file.tar", "bad PAX record"),
        ("pax-bad-mtime-file.tar", "bad PAX mtime"),
        ("pax-nul-xattrs.tar", "NUL in PAX key"),
        ("pax-nul-path.tar", "NUL in PAX path"),
    ] {
        let (hs, err) = read_all(&fixture(name));
        let err = err.unwrap_or_else(|| panic!("{name} ({why}) must fail"));
        assert!(ERR_HEADER.matches(&err), "{name}: {err}");
        assert!(hs.is_empty(), "{name}");
    }
    // Names that are not UTF-8 cannot be held in Rust strings (Go keeps the bytes).
    let (hs, err) = read_all(&fixture("gnu-not-utf8.tar"));
    assert!(hs.is_empty() && err.is_some_and(|e| ERR_HEADER.matches(&e)));
}

#[test]
fn sparse_formats() {
    let (hs, err) = read_all(&fixture("sparse-formats.tar"));
    assert!(err.is_none());
    assert_eq!(hs.len(), 5);
    let names: Vec<&str> = hs.iter().map(|(h, _)| h.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "sparse-gnu",
            "sparse-posix-0.0",
            "sparse-posix-0.1",
            "sparse-posix-1.0",
            "end"
        ]
    );
    assert_eq!(hs[0].0.typeflag, b'S');
    assert_eq!(hs[0].0.format, FORMAT_GNU);
    for (h, _) in &hs[1..4] {
        assert_eq!(h.format, FORMAT_PAX);
        assert_eq!(h.size, 200);
    }
    assert_eq!(hs[3].0.pax_records["GNU.sparse.major"], "1");
    // Holes read as zeros: all four layouts describe the same 200 bytes.
    for (_, crc) in &hs[..4] {
        assert_eq!(*crc, 0x5375e1d2);
    }
    assert_eq!(hs[4].1, 0x8eb179ba);
}

#[test]
fn nil_sparse_files() {
    for name in [
        "gnu-nil-sparse-data.tar",
        "gnu-nil-sparse-hole.tar",
        "pax-nil-sparse-data.tar",
        "pax-nil-sparse-hole.tar",
    ] {
        let (hs, err) = read_all(&fixture(name));
        assert!(err.is_none(), "{name}");
        assert_eq!(hs.len(), 1, "{name}");
        assert_eq!(hs[0].0.size, 1000, "{name}");
        assert_eq!(hs[0].0.name, "sparse.db", "{name}");
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum End {
    Eof,
    UnexpectedEof,
    Header,
}

/// TestReadTruncation: ending conditions on truncated and padded archives.
#[test]
fn read_truncation() {
    let data1 = fixture("gnu.tar");
    let mut data2 = fixture("ustar-file-reg.tar");
    data2.extend(vec![0u8; 10 * 512]);
    let pax = fixture("pax-path-hdr.tar");
    let sparse = fixture("sparse-formats.tar");
    let trash = "garbage ".repeat(64).into_bytes();
    let cat = |a: &[u8], b: &[u8]| [a, b].concat();
    use End::*;
    let vectors: Vec<(Vec<u8>, usize, End)> = vec![
        (vec![], 0, Eof),
        (data1[..511].to_vec(), 0, UnexpectedEof),
        (data1[..512].to_vec(), 1, UnexpectedEof),
        (data1[..1024].to_vec(), 1, Eof),
        (data1[..1536].to_vec(), 2, UnexpectedEof),
        (data1[..2048].to_vec(), 2, Eof),
        (data1.clone(), 2, Eof),
        (cat(&data1[..2048], &data2[..1536]), 3, Eof),
        (data2[..511].to_vec(), 0, UnexpectedEof),
        (data2[..512].to_vec(), 1, UnexpectedEof),
        (data2[..1195].to_vec(), 1, UnexpectedEof),
        (data2[..1196].to_vec(), 1, Eof),
        (data2[..1200].to_vec(), 1, Eof),
        (data2[..1535].to_vec(), 1, Eof),
        (data2[..1536].to_vec(), 1, Eof),
        (cat(&data2[..1536], &trash[..1]), 1, UnexpectedEof),
        (cat(&data2[..1536], &trash[..511]), 1, UnexpectedEof),
        (cat(&data2[..1536], &trash), 1, Header),
        (data2[..2048].to_vec(), 1, Eof),
        (cat(&data2[..2048], &trash[..1]), 1, UnexpectedEof),
        (cat(&data2[..2048], &trash[..511]), 1, UnexpectedEof),
        (cat(&data2[..2048], &trash), 1, Header),
        (data2[..2560].to_vec(), 1, Eof),
        (cat(&data2[..2560], &trash[..1]), 1, Eof),
        (cat(&data2[..2560], &trash[..511]), 1, Eof),
        (cat(&data2[..2560], &trash), 1, Eof),
        (data2[..3072].to_vec(), 1, Eof),
        (pax.clone(), 0, Eof),
        (cat(&pax, &trash[..1]), 0, UnexpectedEof),
        (cat(&pax, &trash[..511]), 0, UnexpectedEof),
        (sparse[..511].to_vec(), 0, UnexpectedEof),
        (sparse[..512].to_vec(), 0, UnexpectedEof),
        (sparse[..3584].to_vec(), 1, Eof),
        (sparse[..9200].to_vec(), 1, Eof),
        (sparse[..9216].to_vec(), 1, Eof),
        (sparse[..9728].to_vec(), 2, UnexpectedEof),
        (sparse[..10240].to_vec(), 2, Eof),
        (sparse[..11264].to_vec(), 2, UnexpectedEof),
        (sparse.clone(), 5, Eof),
        (cat(&sparse, &trash), 5, Eof),
    ];
    for (i, (input, count, want)) in vectors.iter().enumerate() {
        // Both skipping with next() and reading each entry's data first.
        for read_data in [false, true] {
            let mut tr = Reader::new(&input[..]);
            let mut cnt = 0;
            let end = loop {
                match tr.next() {
                    Ok(None) => break Eof,
                    Err(e) if ERR_HEADER.matches(&e) => break Header,
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break UnexpectedEof,
                    Err(e) => panic!("vector {i}: {e}"),
                    Ok(Some(_)) => cnt += 1,
                }
                if read_data {
                    if let Err(e) = io::copy(&mut tr, &mut io::sink()) {
                        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof, "vector {i}");
                        break UnexpectedEof;
                    }
                }
            };
            assert_eq!(
                (cnt, end),
                (*count, *want),
                "vector {i} read_data={read_data}"
            );
        }
    }
}

#[test]
fn read_header_only() {
    let data = fixture("hdr-only.tar");
    let mut tr = Reader::new(&data[..]);
    let mut hdrs = Vec::new();
    while let Some(h) = tr.next().unwrap() {
        let mut b = [0u8; 1];
        let n = tr.read(&mut b).unwrap();
        assert!(
            n == 0 || h.typeflag == TYPE_REG,
            "special file {h:?} has data"
        );
        hdrs.push(h);
    }
    assert_eq!(hdrs.len(), 16);
    for i in 0..8 {
        let (mut a, mut b) = (hdrs[i].clone(), hdrs[i + 8].clone());
        a.size = 0;
        b.size = 0;
        assert_eq!(a, b);
    }
}

#[test]
fn partial_and_uninitialized_reads() {
    let data = fixture("gnu.tar");
    let mut tr = Reader::new(&data[..]);
    assert_eq!(tr.read(&mut [0u8; 4]).unwrap(), 0, "no entry yet");
    tr.next().unwrap().unwrap();
    let mut b = [0u8; 2];
    tr.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"Ki");
    // Next skips the unread remainder of the entry.
    assert_eq!(tr.next().unwrap().unwrap().name, "small2.txt");
    let mut rest = String::new();
    tr.read_to_string(&mut rest).unwrap();
    assert_eq!(rest, "Google.com\n");
    assert!(tr.next().unwrap().is_none());
    assert!(tr.next().unwrap().is_none(), "end of archive is sticky");
}

#[test]
fn insecure_paths_carry_the_header() {
    let mut w = Writer::new(Vec::new());
    for name in ["ok/file", "../escape", "/abs", "a/../../b"] {
        w.write_header(&Header {
            name: name.into(),
            typeflag: TYPE_REG,
            ..Header::default()
        })
        .unwrap();
    }
    w.close().unwrap();
    let mut buf = Vec::new();
    {
        let mut w = Writer::new(&mut buf);
        for name in ["ok/file", "../escape", "/abs", "a/../../b"] {
            w.write_header(&Header {
                name: name.into(),
                typeflag: TYPE_REG,
                ..Header::default()
            })
            .unwrap();
        }
        w.close().unwrap();
    }
    // Default (GODEBUG=tarinsecurepath=1): accepted.
    let mut tr = Reader::new(&buf[..]);
    tr.set_reject_insecure_paths(false);
    for name in ["ok/file", "../escape", "/abs", "a/../../b"] {
        assert_eq!(tr.next().unwrap().unwrap().name, name);
    }
    // tarinsecurepath=0: ErrInsecurePath with the header attached.
    let mut tr = Reader::new(&buf[..]);
    tr.set_reject_insecure_paths(true);
    assert_eq!(tr.next().unwrap().unwrap().name, "ok/file");
    for name in ["../escape", "/abs", "a/../../b"] {
        let err = tr.next().unwrap_err();
        assert!(ERR_INSECURE_PATH.matches(&err));
        let carried = err
            .get_ref()
            .and_then(|e| e.downcast_ref::<InsecurePathError>())
            .expect("error carries the header");
        assert_eq!(carried.header.name, name);
    }
    assert!(tr.next().unwrap().is_none());
}

fn write_all_entries(entries: &[(Header, &str)]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut tw = Writer::new(&mut buf);
        for (h, data) in entries {
            tw.write_header(h).unwrap();
            tw.write_all(data.as_bytes()).unwrap();
        }
        tw.close().unwrap();
    }
    buf
}

#[test]
fn writer_matches_gnu_tar_fixtures() {
    // writer.tar: GNU tar --format=ustar
    let mut small = hdr(
        "small.txt",
        0o640,
        73025,
        5000,
        5,
        1246508266,
        TYPE_REG,
        "dsymonds",
        "eng",
        FORMAT_UNKNOWN,
    );
    let mut small2 = hdr(
        "small2.txt",
        0o640,
        73025,
        5000,
        11,
        1245217492,
        TYPE_REG,
        "dsymonds",
        "eng",
        FORMAT_UNKNOWN,
    );
    let mut link = hdr(
        "link.txt",
        0o777,
        1000,
        1000,
        0,
        1314603082,
        TYPE_SYMLINK,
        "strings",
        "strings",
        FORMAT_UNKNOWN,
    );
    link.linkname = "small.txt".into();
    let got = write_all_entries(&[
        (small.clone(), "Kilts"),
        (small2.clone(), "Google.com\n"),
        (link, ""),
    ]);
    assert_eq!(got, fixture("writer.tar"));

    // ustar.tar: long names split into prefix and name
    let long = "longname/".repeat(15) + "file.txt";
    small = hdr(
        &long,
        0o644,
        501,
        20,
        6,
        1360135598,
        TYPE_REG,
        "shane",
        "staff",
        FORMAT_UNKNOWN,
    );
    let got = write_all_entries(&[(small.clone(), "hello\n")]);
    assert_eq!(got, fixture("ustar.tar"));

    // hardlink.tar
    small2 = hdr(
        "file.txt",
        0o644,
        1000,
        100,
        15,
        1425484303,
        TYPE_REG,
        "vbatts",
        "users",
        FORMAT_UNKNOWN,
    );
    let mut hard = hdr(
        "hard.txt",
        0o644,
        1000,
        100,
        0,
        1425484303,
        TYPE_LINK,
        "vbatts",
        "users",
        FORMAT_UNKNOWN,
    );
    hard.linkname = "file.txt".into();
    let got = write_all_entries(&[(small2, "Slartibartfast\n"), (hard, "")]);
    assert_eq!(got, fixture("hardlink.tar"));

    // gnu-utf8.tar: UTF-8 names force the GNU format here.
    let mut u = hdr(
        &"\u{263a}\u{263b}\u{2639}".repeat(18),
        0o644,
        1000,
        1000,
        0,
        0,
        TYPE_REG,
        "\u{263a}",
        "\u{26b9}",
        FORMAT_GNU,
    );
    u.mod_time = time_unix(0, 0);
    let got = write_all_entries(&[(u, "")]);
    assert_eq!(got, fixture("gnu-utf8.tar"));

    // pax-records.tar: unknown records are kept, basic ones are ignored.
    let mut p = hdr(
        "file",
        0,
        0,
        0,
        0,
        0,
        TYPE_REG,
        &"long".repeat(10),
        "",
        FORMAT_UNKNOWN,
    );
    p.pax_records = map(&[
        ("path", "FILE"),
        ("GNU.sparse.map", "0,0"),
        ("comment", "Hello, \u{4e16}\u{754c}"),
        ("GOLANG.pkg", "tar"),
    ]);
    let got = write_all_entries(&[(p, "")]);
    assert_eq!(got, fixture("pax-records.tar"));

    // pax-global-records.tar
    let g1 = Header {
        typeflag: TYPE_X_GLOBAL_HEADER,
        pax_records: map(&[("path", "global1"), ("mtime", "1500000000.0")]),
        ..Header::default()
    };
    let file = |name: &str| Header {
        typeflag: TYPE_REG,
        name: name.into(),
        ..Header::default()
    };
    let g2 = Header {
        typeflag: TYPE_X_GLOBAL_HEADER,
        pax_records: map(&[("path", "")]),
        ..Header::default()
    };
    let mut file2 = file("file2");
    file2.pax_records = map(&[("path", "file2")]);
    let mut file4 = file("file4");
    file4.mod_time = time_unix(1400000000, 0);
    file4.pax_records = map(&[("mtime", "1400000000")]);
    let got = write_all_entries(&[
        (g1, ""),
        (file("file1"), ""),
        (file2, ""),
        (g2, ""),
        (file("file3"), ""),
        (file4, ""),
    ]);
    assert_eq!(got, fixture("pax-global-records.tar"));
}

#[test]
fn writer_big_header_only() {
    // writer-big.tar is the first 8 blocks of a 16 GiB file archive.
    let h = hdr(
        "tmp/16gig.txt",
        0o640,
        73025,
        5000,
        16 << 30,
        1254699560,
        TYPE_REG,
        "dsymonds",
        "eng",
        FORMAT_GNU,
    );
    let mut buf = Vec::new();
    let mut tw = Writer::new(&mut buf);
    tw.write_header(&h).unwrap();
    drop(tw);
    assert_eq!(&buf[..], &fixture("writer-big.tar")[..512]);
}

#[test]
fn writer_errors() {
    // Header-only entries accept no data.
    let mut tw = Writer::new(Vec::new());
    tw.write_header(&Header {
        name: "dir/".into(),
        typeflag: TYPE_DIR,
        ..Header::default()
    })
    .unwrap();
    assert!(ERR_WRITE_TOO_LONG.matches(&tw.write(&[0]).unwrap_err()));

    // Negative size on a regular file.
    let mut tw = Writer::new(Vec::new());
    let err = tw
        .write_header(&Header {
            name: "small.txt".into(),
            size: -1,
            ..Header::default()
        })
        .unwrap_err();
    assert!(err
        .to_string()
        .starts_with("archive/tar: cannot encode header"));

    // Writing before any header.
    let mut tw = Writer::new(Vec::new());
    assert!(ERR_WRITE_TOO_LONG.matches(&tw.write(b"Kilts").unwrap_err()));

    // After Close: writes fail, flush fails, a second close succeeds.
    let mut tw = Writer::new(Vec::new());
    tw.write_header(&Header {
        name: "small.txt".into(),
        ..Header::default()
    })
    .unwrap();
    tw.close().unwrap();
    assert!(ERR_WRITE_AFTER_CLOSE.matches(&tw.write(b"Kilts").unwrap_err()));
    assert!(ERR_WRITE_AFTER_CLOSE.matches(&tw.flush().unwrap_err()));
    tw.close().unwrap();

    // Flush and Close before the declared size is written.
    for close in [false, true] {
        let mut tw = Writer::new(Vec::new());
        tw.write_header(&Header {
            name: "small.txt".into(),
            size: 5,
            ..Header::default()
        })
        .unwrap();
        let err = if close { tw.close() } else { tw.flush() }.unwrap_err();
        assert!(err.to_string().contains("missed writing 5 bytes"), "{err}");
    }

    // Writing more than the size accepts the prefix, then fails.
    let mut tw = Writer::new(Vec::new());
    tw.write_header(&Header {
        name: "f".into(),
        size: 3,
        ..Header::default()
    })
    .unwrap();
    assert_eq!(tw.write(b"abcdef").unwrap(), 3);
    assert!(ERR_WRITE_TOO_LONG.matches(&tw.write(b"def").unwrap_err()));
    tw.close().unwrap();

    // NUL in a name or an xattr key cannot be encoded.
    let mut tw = Writer::new(Vec::new());
    assert!(tw
        .write_header(&Header {
            name: "null\0.txt".into(),
            ..Header::default()
        })
        .is_err());
    assert!(tw
        .write_header(&Header {
            name: "bad-null.txt".into(),
            xattrs: map(&[("null\0null\0", "fizzbuzz")]),
            ..Header::default()
        })
        .is_err());

    // Manually encoding meta headers is refused.
    for typeflag in [TYPE_X_HEADER, TYPE_GNU_LONG_NAME, TYPE_GNU_LONG_LINK] {
        assert!(tw
            .write_header(&Header {
                typeflag,
                name: "x".into(),
                ..Header::default()
            })
            .is_err());
    }
}

struct FailOnce(bool);
impl Write for FailOnce {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if !self.0 {
            self.0 = true;
            return Err(io::ErrorKind::WriteZero.into());
        }
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn writer_errors_persist() {
    let mut tw = Writer::new(FailOnce(false));
    assert!(tw.write_header(&Header::default()).is_err());
    assert!(tw
        .write_header(&Header {
            name: "small.txt".into(),
            ..Header::default()
        })
        .is_err());
    assert!(tw.write(&[]).is_err());
    assert!(tw.flush().is_err());
    assert!(tw.close().is_err());
}

#[test]
fn format_selection_and_round_trip() {
    // Each header round-trips through the format the writer picks for it.
    let mut base = hdr(
        "a/b.txt", 0o644, 1000, 100, 4, 1700000000, TYPE_REG, "u", "g", FORMAT_PAX,
    );
    base.mod_time = time_unix(1700000000, 123456789);
    base.access_time = time_unix(1700000001, 5);
    base.change_time = time_unix(1700000002, 0);
    let cases: Vec<(Header, Format)> = vec![
        (base.clone(), FORMAT_PAX),
        (
            Header {
                format: FORMAT_GNU,
                ..base.clone()
            },
            FORMAT_GNU,
        ),
        (
            Header {
                name: "d".repeat(150) + "/f",
                uid: 1 << 40,
                ..base.clone()
            },
            FORMAT_PAX,
        ),
        (
            Header {
                name: "d".repeat(150) + "/f",
                uid: 1 << 40,
                format: FORMAT_UNKNOWN,
                ..base.clone()
            },
            FORMAT_PAX,
        ),
        (
            Header {
                name: "\u{65e5}\u{672c}\u{8a9e}".into(),
                uname: "\u{6d4b}\u{8bd5}".into(),
                ..base.clone()
            },
            FORMAT_PAX,
        ),
    ];
    for (mut h, format) in cases {
        h.access_time = if format == FORMAT_PAX || format == FORMAT_GNU {
            h.access_time
        } else {
            time_zero()
        };
        let bytes = write_all_entries(&[(h.clone(), "data")]);
        let (hs, err) = read_all(&bytes);
        assert!(err.is_none());
        let got = &hs[0].0;
        assert_eq!(got.format, format, "{h:?}");
        assert_eq!(got.name, h.name);
        assert_eq!(got.uid, h.uid);
        assert_eq!(got.uname, h.uname);
        assert_eq!(got.size, 4);
        if h.format == FORMAT_PAX {
            assert_eq!(got.mod_time, h.mod_time, "sub-second times use PAX records");
            assert_eq!(got.access_time, h.access_time);
        } else if h.format == FORMAT_UNKNOWN {
            // Without an explicit format times are rounded to seconds.
            assert_eq!(got.mod_time, time_unix(1700000000, 0));
            assert_eq!(got.access_time, time_zero());
        } else {
            // GNU stores whole seconds.
            assert_eq!(got.mod_time, time_unix(1700000000, 0));
        }
    }
}

#[test]
fn zero_format_rounds_times_and_drops_atime() {
    let mut h = hdr("f", 0o644, 0, 0, 0, 0, TYPE_REG, "", "", FORMAT_UNKNOWN);
    h.mod_time = time_unix(10, 600_000_000);
    h.access_time = time_unix(5, 0);
    let (hs, _) = read_all(&write_all_entries(&[(h, "")]));
    assert_eq!(hs[0].0.mod_time, time_unix(11, 0));
    assert_eq!(hs[0].0.access_time, time_zero());
    assert_eq!(hs[0].0.format, FORMAT_USTAR);
}

#[test]
fn base256_numbers_in_gnu_headers() {
    let mut h = hdr("big", 0o644, 0, 0, 0, 0, TYPE_REG, "", "", FORMAT_GNU);
    h.uid = 1 << 40;
    h.gid = -5;
    h.devmajor = 1 << 33;
    let (hs, err) = read_all(&write_all_entries(&[(h.clone(), "")]));
    assert!(err.is_none());
    assert_eq!(hs[0].0.uid, 1 << 40);
    assert_eq!(hs[0].0.gid, -5);
    assert_eq!(hs[0].0.devmajor, 1 << 33);
    assert_eq!(hs[0].0.format, FORMAT_GNU);
}

#[test]
fn long_gnu_names_and_links() {
    let mut h = hdr(
        &"n".repeat(300),
        0o644,
        0,
        0,
        0,
        0,
        TYPE_SYMLINK,
        "",
        "",
        FORMAT_GNU,
    );
    h.linkname = "t".repeat(200);
    let (hs, err) = read_all(&write_all_entries(&[(h.clone(), "")]));
    assert!(err.is_none());
    assert_eq!(hs[0].0.name, h.name);
    assert_eq!(hs[0].0.linkname, h.linkname);
}

#[test]
fn sparse_write_round_trip() {
    let mut content = vec![0u8; 5000];
    content[600..1100].fill(7);
    content[3000..3600].fill(9);
    let holes = [
        SparseEntry {
            offset: 0,
            length: 512,
        },
        SparseEntry {
            offset: 1100,
            length: 1900,
        },
        SparseEntry {
            offset: 3600,
            length: 1400,
        },
    ];
    for (typeflag, format) in [(TYPE_REG, FORMAT_PAX), (TYPE_GNU_SPARSE, FORMAT_GNU)] {
        let h = Header {
            typeflag,
            name: "sparse.bin".into(),
            size: content.len() as i64,
            mode: 0o644,
            format,
            ..Header::default()
        };
        let mut buf = Vec::new();
        {
            let mut tw = Writer::new(&mut buf);
            tw.write_sparse_header(&h, &holes).unwrap();
            tw.write_all(&content).unwrap();
            tw.close().unwrap();
        }
        // Only the data fragments are stored: far smaller than the logical size.
        assert!(buf.len() < content.len() + 3 * 512, "{} bytes", buf.len());
        let mut tr = Reader::new(&buf[..]);
        let got = tr.next().unwrap().unwrap();
        assert_eq!(got.size, 5000);
        assert_eq!(got.name, "sparse.bin");
        let mut body = Vec::new();
        tr.read_to_end(&mut body).unwrap();
        assert_eq!(body, content);
    }
}

#[test]
fn sparse_write_rejects_data_in_holes() {
    let h = Header {
        typeflag: TYPE_REG,
        name: "s".into(),
        size: 2048,
        ..Header::default()
    };
    let holes = [SparseEntry {
        offset: 512,
        length: 1024,
    }];
    let mut tw = Writer::new(Vec::new());
    tw.write_sparse_header(&h, &holes).unwrap();
    let mut data = vec![0u8; 2048];
    data[700] = 1;
    let err = tw.write_all(&data).unwrap_err();
    assert!(ERR_WRITE_HOLE_FOR_TEST.matches(&err), "{err}");
    // Invalid hole maps are rejected up front.
    let mut tw = Writer::new(Vec::new());
    assert!(tw
        .write_sparse_header(
            &h,
            &[SparseEntry {
                offset: 0,
                length: 4096
            }]
        )
        .is_err());
}

const ERR_WRITE_HOLE_FOR_TEST: tar::Error = tar::Error::WriteHole;

#[test]
fn file_info_header_and_names() {
    let h = Header {
        name: "dir/file.txt".into(),
        mode: 0o4755,
        size: 12,
        typeflag: TYPE_REG,
        mod_time: time_unix(100, 0),
        ..Header::default()
    };
    let fi = h.file_info();
    assert_eq!(fi.name(), "file.txt");
    assert_eq!(fi.size(), 12);
    assert_eq!(fi.mode(), FileMode(0o755) | FileMode::SETUID);
    assert!(!fi.is_dir());
    assert!(fi.sys().is_some_and(|s| s.is::<Header>()));

    let d = Header {
        name: "a/b/".into(),
        mode: 0o40755,
        typeflag: TYPE_DIR,
        ..Header::default()
    };
    assert_eq!(d.file_info().name(), "b");
    assert!(d.file_info().is_dir());
    assert_eq!(d.file_info().mode(), FileMode::DIR | FileMode(0o755));

    // FileInfoHeader of a regular file, directory and symlink.
    let got = file_info_header(&fi, "").unwrap();
    assert_eq!(got.typeflag, TYPE_REG);
    assert_eq!(got.name, "file.txt");
    assert_eq!(got.mode, 0o755 | 0o4000);
    assert_eq!(got.size, 12);
    let got = file_info_header(&d.file_info(), "").unwrap();
    assert_eq!((got.typeflag, got.name.as_str()), (TYPE_DIR, "b/"));
    let link = Header {
        name: "l".into(),
        typeflag: TYPE_SYMLINK,
        mode: 0o120777,
        ..Header::default()
    };
    let got = file_info_header(&link.file_info(), "target").unwrap();
    assert_eq!(
        (got.typeflag, got.linkname.as_str()),
        (TYPE_SYMLINK, "target")
    );
    // Sockets are refused.
    let sock = rust_stdlib::archive::iofs::BasicFileInfo {
        name: "s".into(),
        size: 0,
        mode: FileMode::SOCKET,
        mod_time: time_zero(),
        uname: None,
        gname: None,
    };
    assert!(file_info_header(&sock, "").is_err());

    // FileInfoNames supply user and group names.
    let named = rust_stdlib::archive::iofs::BasicFileInfo {
        name: "f".into(),
        size: 1,
        mode: FileMode(0o644),
        mod_time: time_zero(),
        uname: Some("alice".into()),
        gname: Some("staff".into()),
    };
    let got = file_info_header(&named, "").unwrap();
    assert_eq!((got.uname.as_str(), got.gname.as_str()), ("alice", "staff"));
    assert_eq!(named.uname().unwrap(), "alice");
    assert_eq!(named.gname().unwrap(), "staff");

    // A Header carried as Sys() keeps ids, times, xattrs and hard links.
    let mut src = Header {
        name: "x".into(),
        typeflag: TYPE_LINK,
        linkname: "orig".into(),
        uid: 7,
        gid: 8,
        uname: "u".into(),
        gname: "g".into(),
        access_time: time_unix(9, 0),
        xattrs: map(&[("user.k", "v")]),
        pax_records: map(&[("comment", "c")]),
        ..Header::default()
    };
    src.mod_time = time_unix(5, 0);
    let got = file_info_header(&src.file_info(), "").unwrap();
    assert_eq!(got.typeflag, TYPE_LINK);
    assert_eq!((got.uid, got.gid, got.linkname.as_str()), (7, 8, "orig"));
    assert_eq!(got.xattrs, src.xattrs);
    assert_eq!(got.pax_records, src.pax_records);
}

#[test]
fn add_fs() {
    let mut fsys = MapFS::new();
    fsys.insert(
        "emptyfolder",
        MapFile::new(&b""[..], iofs_fs::FileMode(iofs_fs::MODE_DIR.0 | 0o755)),
    );
    fsys.insert(
        "file.go",
        MapFile::new(&b"hello"[..], iofs_fs::FileMode(0o644)),
    );
    fsys.insert(
        "subfolder/another.go",
        MapFile::new(&b"world"[..], iofs_fs::FileMode(0o644)),
    );
    fsys.insert(
        "symlink.go",
        MapFile::new(
            &b"file.go"[..],
            iofs_fs::FileMode(iofs_fs::MODE_SYMLINK.0 | 0o777),
        ),
    );

    let mut buf = Vec::new();
    {
        let mut tw = Writer::new(&mut buf);
        tw.add_fs(&fsys).unwrap();
        tw.close().unwrap();
    }
    let mut tr = Reader::new(&buf[..]);
    let mut seen = Vec::new();
    while let Some(h) = tr.next().unwrap() {
        let mut body = String::new();
        tr.read_to_string(&mut body).unwrap();
        seen.push((
            h.name.clone(),
            h.typeflag,
            h.linkname.clone(),
            h.file_info().mode(),
            body,
        ));
    }
    let want: Vec<(&str, u8, &str, FileMode, &str)> = vec![
        (
            "emptyfolder/",
            TYPE_DIR,
            "",
            FileMode::DIR | FileMode(0o755),
            "",
        ),
        ("file.go", TYPE_REG, "", FileMode(0o644), "hello"),
        (
            "subfolder/",
            TYPE_DIR,
            "",
            FileMode::DIR | FileMode(0o555),
            "",
        ),
        (
            "subfolder/another.go",
            TYPE_REG,
            "",
            FileMode(0o644),
            "world",
        ),
        (
            "symlink.go",
            TYPE_SYMLINK,
            "file.go",
            FileMode::SYMLINK | FileMode(0o777),
            "",
        ),
    ];
    assert_eq!(seen.len(), want.len(), "{seen:?}");
    for (got, want) in seen.iter().zip(want) {
        assert_eq!(
            (got.0.as_str(), got.1, got.2.as_str(), got.3, got.4.as_str()),
            want
        );
    }

    // Non-regular files are refused.
    let mut bad = MapFS::new();
    bad.insert(
        "device",
        MapFile::new(
            &b"hello"[..],
            iofs_fs::FileMode(0o755 | iofs_fs::MODE_DEVICE.0),
        ),
    );
    let mut tw = Writer::new(Vec::new());
    assert!(tw.add_fs(&bad).is_err());
}

#[test]
fn legacy_api_still_strict() {
    // The bounded helpers keep rejecting GNU/PAX extensions.
    assert!(tar::read(&fixture("gnu.tar")[..], tar::Limits::default()).is_err());
    assert!(tar::read(&fixture("pax.tar")[..], tar::Limits::default()).is_err());
    let entries = tar::read(&fixture("writer.tar")[..], tar::Limits::default()).unwrap();
    assert_eq!(entries.len(), 3);
}

#[cfg(feature = "net")]
#[test]
fn writer_wraps_borrowed_response_writer() {
    use rust_stdlib::net::http::{httptest::ResponseRecorder, ResponseWriter};
    fn stream(w: &mut dyn ResponseWriter) {
        {
            let mut tw = Writer::new(&mut *w);
            tw.write_header(&Header {
                name: "a.txt".into(),
                typeflag: TYPE_REG,
                size: 5,
                ..Header::default()
            })
            .unwrap();
            tw.write_all(b"hello").unwrap();
            tw.close().unwrap();
        }
        w.header().set("X-After", "still usable");
    }
    let mut rec = ResponseRecorder::new();
    stream(&mut rec);
    let body = rec.body.clone().unwrap();
    let mut r = Reader::new(&body[..]);
    let h = r.next().unwrap().unwrap();
    assert_eq!(h.name, "a.txt");
    let mut got = Vec::new();
    r.read_to_end(&mut got).unwrap();
    assert_eq!(got, b"hello");
    assert_eq!(rec.header_map.get("X-After"), Some("still usable"));
}

/// Go's FileInfoHeader skips the user database when the FileInfo provides
/// FileInfoNames (doNameLookups = false), even if Sys() is the OS stat.
#[cfg(unix)]
#[test]
fn file_info_names_are_not_overwritten_by_the_user_database() {
    use rust_stdlib::archive::iofs::{FileInfo, FileInfoNames, FileMode};
    use std::any::Any;
    struct Named(std::fs::Metadata);
    impl FileInfo for Named {
        fn name(&self) -> String {
            "f".into()
        }
        fn size(&self) -> i64 {
            0
        }
        fn mode(&self) -> FileMode {
            FileMode(0o644)
        }
        fn mod_time(&self) -> std::time::SystemTime {
            std::time::SystemTime::UNIX_EPOCH
        }
        fn sys(&self) -> Option<&dyn Any> {
            Some(&self.0)
        }
        fn as_names(&self) -> Option<&dyn FileInfoNames> {
            Some(self)
        }
    }
    impl FileInfoNames for Named {
        fn uname(&self) -> std::io::Result<String> {
            Ok("named-user".into())
        }
        fn gname(&self) -> std::io::Result<String> {
            Ok("named-group".into())
        }
    }
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata("/etc/passwd").unwrap();
    let uid = i64::from(meta.uid());
    let h = rust_stdlib::archive::tar::file_info_header(&Named(meta), "").unwrap();
    assert_eq!(
        (h.uname.as_str(), h.gname.as_str()),
        ("named-user", "named-group")
    );
    assert_eq!(h.uid, uid, "uid still comes from the stat");
}
