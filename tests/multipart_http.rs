#![cfg(feature = "net")]
//! `multipart` over `net/http` bodies: an owning part streamed as a request
//! body, and `MaxBytesError` reaching the caller through multipart reads.
use rust_stdlib::multipart::{Reader, Writer};
use rust_stdlib::net::http::{
    self, handler_func, httptest::Server, request::Request, Body, MaxBytesError,
};
use std::io::{Cursor, Read};

/// A multipart document with a small field and a large file, and its boundary.
fn document(file: &[u8]) -> (Vec<u8>, String) {
    let mut out = Vec::new();
    let mut w = Writer::new(&mut out);
    w.write_field("note", "hello").unwrap();
    let mut part = w.create_form_file("upload", "data.bin").unwrap();
    std::io::Write::write_all(&mut part, file).unwrap();
    w.close().unwrap();
    let boundary = w.boundary().to_owned();
    drop(w);
    (out, boundary)
}

#[test]
fn owned_part_streams_into_a_request_body() {
    let file: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let (doc, boundary) = document(&file);
    let server = Server::new(handler_func(|w, r| {
        let body = r.body.as_ref().map(|b| b.read_all().unwrap());
        let _ = w.write(&body.unwrap_or_default());
    }))
    .unwrap();

    // Skip to the file part, then hand it over as the request body.
    let mut reader = Reader::new(Cursor::new(doc), &boundary);
    let note = reader.next_part().unwrap().unwrap().into_owned().unwrap();
    assert_eq!(note.form_name(), "note");
    assert_eq!(note.body, b"hello");
    let part = reader.into_next_part().unwrap().unwrap();
    assert_eq!(part.file_name(), "data.bin");

    let mut req = Request::new("POST", &server.url).unwrap();
    req.body = Some(Body::from_reader(part));
    let resp = server.client().do_request(req).unwrap();
    assert_eq!(resp.body.unwrap().read_all().unwrap(), file);
}

#[test]
fn owned_part_gives_the_reader_back() {
    let (doc, boundary) = document(b"file body");
    let mut part = Reader::new(Cursor::new(doc), &boundary)
        .into_next_part()
        .unwrap()
        .unwrap();
    assert_eq!(part.form_name(), "note");
    let mut some = [0u8; 2];
    part.read_exact(&mut some).unwrap();
    assert_eq!(&some, b"he");
    // The rest of the note is discarded by the next call.
    let mut next = part.into_reader().into_next_part().unwrap().unwrap();
    assert_eq!(next.file_name(), "data.bin");
    let mut body = Vec::new();
    next.read_to_end(&mut body).unwrap();
    assert_eq!(body, b"file body");
    assert!(next.into_reader().into_next_part().unwrap().is_none());
}

#[test]
fn owned_part_decodes_quoted_printable() {
    let doc = "--b\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nh=C3=A9llo=\r\n!\r\n--b--\r\n";
    let mut part = Reader::new(Cursor::new(doc.as_bytes().to_vec()), "b")
        .into_next_part()
        .unwrap()
        .unwrap();
    assert!(part.header.get("Content-Transfer-Encoding").is_none());
    let mut body = String::new();
    part.read_to_string(&mut body).unwrap();
    assert_eq!(body, "héllo!");
}

/// Go's `errors.As` over `source` links and the inner errors of `io::Error`s.
fn error_as<'a, T: std::error::Error + 'static>(
    mut err: &'a (dyn std::error::Error + 'static),
) -> Option<&'a T> {
    loop {
        if let Some(t) = err.downcast_ref::<T>() {
            return Some(t);
        }
        if let Some(inner) = err
            .downcast_ref::<std::io::Error>()
            .and_then(|e| e.get_ref())
        {
            err = inner;
            continue;
        }
        err = err.source()?;
    }
}

fn limited(doc: &[u8], limit: i64) -> Body {
    http::max_bytes_reader(None, Body::from_bytes(doc.to_vec()), limit)
}

#[test]
fn max_bytes_error_survives_a_part_read() {
    let (doc, boundary) = document(&vec![b'x'; 10_000]);
    let mut reader = Reader::new(limited(&doc, 2000), &boundary);
    let mut part = reader.next_part().unwrap().unwrap(); // the note
    part.close().unwrap();
    let mut part = reader.next_part().unwrap().unwrap();
    let err = part.read_to_end(&mut Vec::new()).unwrap_err();
    let max = err
        .get_ref()
        .and_then(|e| e.downcast_ref::<MaxBytesError>())
        .expect("MaxBytesError");
    assert_eq!(max.limit, 2000);
}

#[test]
fn max_bytes_error_survives_read_form() {
    let (doc, boundary) = document(&vec![b'x'; 10_000]);
    let err = Reader::new(limited(&doc, 2000), &boundary)
        .read_form(1 << 20)
        .unwrap_err();
    let max = err
        .get_ref()
        .and_then(|e| e.downcast_ref::<MaxBytesError>())
        .expect("MaxBytesError");
    assert_eq!(max.limit, 2000);
}

/// The first error `next_part` reports with the body cut off at `cut`.
fn next_part_error(doc: &[u8], boundary: &str, cut: usize) -> std::io::Error {
    let mut reader = Reader::new(limited(doc, cut as i64), boundary);
    loop {
        match reader.next_part() {
            Ok(Some(_)) => continue,
            Ok(None) => panic!("no error"),
            Err(e) => return e,
        }
    }
}

#[test]
fn max_bytes_error_survives_next_part() {
    let (doc, boundary) = document(b"file");
    // Cut inside the second part's headers: the error comes back as is.
    let cut = doc.windows(8).position(|w| w == b"filename").unwrap();
    let err = next_part_error(&doc, &boundary, cut);
    assert!(error_as::<MaxBytesError>(&err).is_some(), "{err:?}");

    // Cut inside the second boundary line: Go wraps it in "NextPart: %w".
    let cut = doc.windows(5).rposition(|w| w == b"hello").unwrap() + 12;
    let err = next_part_error(&doc, &boundary, cut);
    assert!(
        err.to_string().starts_with("multipart: NextPart: "),
        "{err}"
    );
    assert!(error_as::<MaxBytesError>(&err).is_some(), "{err:?}");
}
