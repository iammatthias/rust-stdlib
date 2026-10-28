//! Go's lenient multipart framing in `multipart::Reader` (the Go differential
//! is `tools/multipart_check.py`).
use rust_stdlib::multipart::{Reader, ERR_MESSAGE_TOO_LARGE};
use std::io::Read;

fn parts(raw: bool, boundary: &str, doc: &[u8]) -> Vec<(String, String, Vec<u8>)> {
    let mut reader = Reader::new(doc, boundary);
    let mut out = Vec::new();
    loop {
        let next = if raw {
            reader.next_raw_part()
        } else {
            reader.next_part()
        };
        let Some(mut part) = next.unwrap() else {
            return out;
        };
        let mut body = Vec::new();
        part.read_to_end(&mut body).unwrap();
        out.push((part.form_name(), part.file_name(), body));
    }
}

#[test]
fn accepts_lf_line_endings() {
    let doc = b"--b\nContent-Disposition: form-data; name=\"a\"\n\nva\r\nlue\n--b\nContent-Disposition: form-data; name=\"f\"; filename=\"d/x.txt\"\n\nz\n--b--\n";
    assert_eq!(
        parts(false, "b", doc),
        [
            ("a".into(), String::new(), b"va\r\nlue".to_vec()),
            ("f".into(), "x.txt".into(), b"z".to_vec()),
        ]
    );
}

#[test]
fn disposition_is_optional_and_may_repeat_or_fold() {
    let doc = b"--b\r\nX: y\r\n\r\none\r\n--b\r\nContent-Disposition: form-data;\r\n name=\"n\"\r\nContent-Disposition: form-data; name=\"m\"\r\n\r\ntwo\r\n--b--\r\n";
    assert_eq!(
        parts(false, "b", doc),
        [
            (String::new(), String::new(), b"one".to_vec()),
            ("n".into(), String::new(), b"two".to_vec()),
        ]
    );
}

#[test]
fn quoted_printable_is_decoded_by_next_part_only() {
    let doc = b"--b\r\nContent-Disposition: form-data; name=\"a\"\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nh=C3=A9llo=\r\n w\r\n--b--\r\n";
    assert_eq!(parts(false, "b", doc)[0].2, "h\u{e9}llo w".as_bytes());
    assert_eq!(parts(true, "b", doc)[0].2, b"h=C3=A9llo=\r\n w");
    let mut reader = Reader::new(&doc[..], "b");
    let part = reader.next_part().unwrap().unwrap();
    assert!(part.header.get("Content-Transfer-Encoding").is_none());
    let mut reader = Reader::new(&doc[..], "b");
    let part = reader.next_raw_part().unwrap().unwrap();
    assert_eq!(
        part.header.get("Content-Transfer-Encoding"),
        Some("quoted-printable")
    );
}

#[test]
fn truncation_and_stray_lines_are_errors_where_go_errors() {
    let mut reader = Reader::new(&b""[..], "b");
    assert!(reader.next_part().is_err());
    let mut reader = Reader::new(
        &b"--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nxyz"[..],
        "b",
    );
    let mut part = reader.next_part().unwrap().unwrap();
    let mut body = Vec::new();
    // The bytes before the error are returned, then the error.
    assert!(part.read_to_end(&mut body).is_err());
    assert_eq!(body, b"xyz");
    let mut reader = Reader::new(&b"--b\r\nA: b\r\n\r\nx\r\n--b \r\nstray\r\n--b--"[..], "b");
    let mut part = reader.next_part().unwrap().unwrap();
    let mut body = Vec::new();
    part.read_to_end(&mut body).unwrap();
    assert_eq!(body, b"x");
    // The second part's header line has no colon.
    assert!(reader.next_part().is_err());
    assert!(Reader::new(&b"--\r\n"[..], "").next_part().is_err());
}

#[test]
fn read_form_uses_go_memory_accounting() {
    let doc = b"--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n12345\r\n--b--\r\n";
    let form = Reader::new(&doc[..], "b").read_form(0).unwrap();
    assert_eq!(form.value["a"], ["12345"]);
    // A budget below the fixed overheads is too large, as in Go.
    let error = Reader::new(&doc[..], "b")
        .read_form(-(10 << 20))
        .unwrap_err();
    let inner = error
        .get_ref()
        .and_then(|e| e.downcast_ref::<rust_stdlib::multipart::Error>());
    assert_eq!(inner, Some(&ERR_MESSAGE_TOO_LARGE));
}

#[test]
fn part_streams_and_next_part_discards_the_unread_rest() {
    let big = vec![b'x'; 100_000];
    let mut doc =
        b"--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.bin\"\r\n\r\n".to_vec();
    doc.extend_from_slice(&big);
    doc.extend_from_slice(
        b"\r\n--b\r\nContent-Disposition: form-data; name=\"n\"\r\n\r\nafter\r\n--b--\r\n",
    );
    let mut reader = Reader::new(&doc[..], "b");
    let mut part = reader.next_part().unwrap().unwrap();
    assert_eq!(part.file_name(), "a.bin");
    // Read a little, then move on: the rest of the part is discarded.
    let mut head = [0u8; 10];
    part.read_exact(&mut head).unwrap();
    assert_eq!(&head, b"xxxxxxxxxx");
    drop(part);
    let part = reader.next_part().unwrap().unwrap();
    assert_eq!(part.form_name(), "n");
    assert_eq!(part.into_owned().unwrap().body, b"after");
    assert!(reader.next_part().unwrap().is_none());
}

#[test]
fn skipped_malformed_quoted_printable_part_matches_go() {
    // Checked against Go 1.27: the first part is skipped unread and the
    // second still reads "second".
    let doc = b"--b\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nab=ZZcd\r\n--b\r\n\r\nsecond\r\n--b--\r\n";
    let mut reader = Reader::new(&doc[..], "b");
    assert!(reader.next_part().unwrap().is_some());
    let mut second = reader.next_part().unwrap().expect("second part");
    let mut body = String::new();
    second.read_to_string(&mut body).unwrap();
    assert_eq!(body, "second");
}

#[test]
fn writer_exposes_its_inner_writer() {
    use rust_stdlib::multipart::Writer;
    let mut w = Writer::new(Vec::new());
    w.set_boundary("xyz").unwrap();
    assert!(w.get_ref().is_empty());
    w.write_field("a", "1").unwrap();
    w.get_mut().extend_from_slice(b"");
    w.close().unwrap();
    let body = w.into_inner();
    let text = String::from_utf8(body).unwrap();
    assert!(text.starts_with("--xyz\r\n"), "{text:?}");
    assert!(text.ends_with("\r\n--xyz--\r\n"), "{text:?}");
}
