//! `Reader::read_form` spills large file parts to `multipart-*` temporary
//! files in `$TMPDIR`, as Go does. `TMPDIR` is process-wide, so everything runs
//! in one test of this file's own process.
#![cfg(unix)]

use rust_stdlib::io::ReadAt;
use rust_stdlib::multipart::{Reader, Writer, ERR_MESSAGE_TOO_LARGE};
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

fn tmp_files(dir: &PathBuf) -> Vec<(String, u64)> {
    let mut files: Vec<(String, u64)> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap())
        .filter(|e| e.file_name().to_string_lossy().starts_with("multipart-"))
        .map(|e| {
            (
                e.file_name().to_string_lossy().into_owned(),
                e.metadata().unwrap().len(),
            )
        })
        .collect();
    files.sort();
    files
}

fn form_body(files: &[(&str, &[u8])]) -> (String, Vec<u8>) {
    let mut out = Vec::new();
    let mut w = Writer::new(&mut out);
    w.set_boundary("spill").unwrap();
    w.write_field("note", "hello").unwrap();
    for (name, data) in files {
        use std::io::Write;
        let mut part = w.create_form_file(name, &format!("{name}.bin")).unwrap();
        part.write_all(data).unwrap();
    }
    w.close().unwrap();
    drop(w);
    ("spill".into(), out)
}

fn data(len: u32, seed: u32) -> Vec<u8> {
    (0..len).map(|i| ((i + seed) % 251) as u8).collect()
}

#[test]
fn spill_to_tmpdir() {
    let dir = std::env::temp_dir().join(format!("multipart-spill-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::env::set_var("TMPDIR", &dir);
    std::env::remove_var("GODEBUG");
    let (a, b) = (data(5000, 1), data(3000, 7));

    // One file above max_memory spills to one temporary file; a small one
    // after it still fits in memory.
    let (boundary, body) = form_body(&[("big", &a), ("small", b"tiny")]);
    let form = Reader::new(&body[..], &boundary).read_form(100).unwrap();
    assert_eq!(form.value["note"], ["hello"]);
    let files = tmp_files(&dir);
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].1, 5000);
    assert_eq!(form.file["big"][0].size, 5000);
    let mut content = Vec::new();
    let mut f = form.file["big"][0].open().unwrap();
    f.read_to_end(&mut content).unwrap();
    assert_eq!(content, a);
    let mut buf = [0u8; 4];
    assert_eq!(f.read_at(&mut buf, 10).unwrap(), 4);
    assert_eq!(buf, a[10..14]);
    assert_eq!(f.seek(SeekFrom::End(-2)).unwrap(), 4998);
    assert_eq!(f.read_at(&mut buf, 4998).unwrap_err().read(), 2);
    drop(f);
    let mut small = Vec::new();
    form.file["small"][0]
        .open()
        .unwrap()
        .read_to_end(&mut small)
        .unwrap();
    assert_eq!(small, b"tiny");
    // Dropping a form leaves the files; remove_all deletes them.
    form.remove_all().unwrap();
    assert_eq!(tmp_files(&dir).len(), 0);
    form.remove_all().unwrap();

    // Several spilled files share one temporary file.
    let (boundary, body) = form_body(&[("a", &a), ("b", &b)]);
    let form = Reader::new(&body[..], &boundary).read_form(100).unwrap();
    let files = tmp_files(&dir);
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].1, 8000);
    for (name, want) in [("a", &a), ("b", &b)] {
        let mut got = Vec::new();
        form.file[name][0]
            .open()
            .unwrap()
            .read_to_end(&mut got)
            .unwrap();
        assert_eq!(&got, want);
    }
    form.remove_all().unwrap();
    assert_eq!(tmp_files(&dir).len(), 0);

    // GODEBUG=multipartfiles=distinct gives each spilled file its own.
    std::env::set_var("GODEBUG", "multipartfiles=distinct");
    let form = Reader::new(&body[..], &boundary).read_form(100).unwrap();
    let sizes: Vec<u64> = tmp_files(&dir).iter().map(|f| f.1).collect();
    assert_eq!(sizes.len(), 2);
    assert_eq!(sizes.iter().sum::<u64>(), 8000);
    let mut got = Vec::new();
    form.file["b"][0]
        .open()
        .unwrap()
        .read_to_end(&mut got)
        .unwrap();
    assert_eq!(got, b);
    form.remove_all().unwrap();
    assert_eq!(tmp_files(&dir).len(), 0);
    std::env::remove_var("GODEBUG");

    // Everything fits: nothing on disk.
    let form = Reader::new(&body[..], &boundary)
        .read_form(1 << 20)
        .unwrap();
    assert_eq!(tmp_files(&dir).len(), 0);
    drop(form);

    // An error after a spill removes the temporary files, as Go does.
    let mut out = Vec::new();
    {
        use std::io::Write;
        let mut w = Writer::new(&mut out);
        w.set_boundary("spill").unwrap();
        w.create_form_file("a", "a.bin")
            .unwrap()
            .write_all(&a)
            .unwrap();
        w.create_form_field("huge")
            .unwrap()
            .write_all(&vec![b'x'; 11 << 20])
            .unwrap();
        w.close().unwrap();
    }
    let err = Reader::new(&out[..], "spill").read_form(100).unwrap_err();
    assert!(err
        .get_ref()
        .and_then(|e| e.downcast_ref::<rust_stdlib::multipart::Error>())
        .is_some_and(|e| e.0 == ERR_MESSAGE_TOO_LARGE.0));
    assert_eq!(tmp_files(&dir).len(), 0);

    std::fs::remove_dir_all(&dir).unwrap();
}
