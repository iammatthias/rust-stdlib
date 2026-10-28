use rust_stdlib::{mime, multipart};
use std::io::Read;

/// Builds a body with Go's Writer: `(name, filename, body)` per part.
fn build(boundary: &str, parts: &[(&str, Option<&str>, &[u8])]) -> Vec<u8> {
    use std::io::Write;
    let mut out = Vec::new();
    let mut writer = multipart::Writer::new(&mut out);
    writer.set_boundary(boundary).unwrap();
    for (name, filename, body) in parts {
        match filename {
            Some(filename) => writer.create_form_file(name, filename).unwrap(),
            None => writer.create_form_field(name).unwrap(),
        }
        .write_all(body)
        .unwrap();
    }
    writer.close().unwrap();
    out
}

/// Reads every part with Go's Reader: `(form name, file name, body)`.
fn read_all(bytes: &[u8], boundary: &str) -> Vec<(String, String, Vec<u8>)> {
    let mut reader = multipart::Reader::new(bytes, boundary);
    let mut out = Vec::new();
    while let Some(part) = reader.next_part().unwrap() {
        let part = part.into_owned().unwrap();
        out.push((part.form_name(), part.file_name(), part.body));
    }
    out
}

#[test]
fn mime_parameters_round_trip_with_quotes_and_case() {
    let media = mime::MediaType::parse("Text/Plain; CHARSET=utf-8; title=\"a; b\\\"c\"").unwrap();
    assert_eq!(media.essence, "text/plain");
    assert_eq!(media.parameters["title"], "a; b\"c");
    assert_eq!(
        mime::MediaType::parse(&media.encode().unwrap()).unwrap(),
        media
    );
    assert_eq!(
        mime::type_by_extension(".JPG").as_deref(),
        Some("image/jpeg")
    );
    assert_eq!(mime::type_by_extension(".unknown"), None);
}
#[test]
fn mime_rejects_ambiguous_and_injected_parameters() {
    for invalid in [
        "text/plain; a=x; A=y",
        "text/plain; x=\"unterminated",
        "text/plain; x=a b",
        "text/plain; x=",
        "text/plain;",
        "text/plain\r\nX: y",
        "text/plain; name*=utf-8''x",
        "text/plain; x=\"a\\\r\nb\"",
    ] {
        assert!(mime::MediaType::parse(invalid).is_err(), "{invalid:?}");
    }
    assert!(mime::MediaType::parse_with_limits(
        "text/plain",
        mime::Limits {
            max_bytes: 9,
            max_parameters: 1
        }
    )
    .is_err());
    assert!(mime::MediaType::parse_with_limits(
        "text/plain; a=x",
        mime::Limits {
            max_bytes: 100,
            max_parameters: 0
        }
    )
    .is_err());
}
#[test]
fn multipart_binary_round_trip_and_boundary_prefixes() {
    let data = b"\x00\xff\r\n--samplex\r\n--sample-\r\nend";
    let bytes = build(
        "sample",
        &[
            ("name", None, b"Matthias"),
            ("file", Some("photo.bin"), data),
            ("name", None, b""),
        ],
    );
    let parsed = read_all(&bytes, "sample");
    assert_eq!(parsed.len(), 3);
    assert_eq!(
        parsed[0],
        ("name".into(), String::new(), b"Matthias".to_vec())
    );
    assert_eq!(
        parsed[1],
        ("file".into(), "photo.bin".into(), data.to_vec())
    );
    assert_eq!(parsed[2], ("name".into(), String::new(), Vec::new()));
    // A payload line that starts like a closing delimiter (`--sample--x`) is not
    // protected by Go's Writer: the Reader ends the part before it and then
    // fails (checked against Go 1.27).
    let bytes = build("sample", &[("f", None, b"a\r\n--sample--x\r\nend")]);
    let mut reader = multipart::Reader::new(bytes.as_slice(), "sample");
    let first = reader.next_part().unwrap().unwrap().into_owned().unwrap();
    assert_eq!(first.body, b"a");
    assert!(reader.next_part().is_err());
    let mut writer = multipart::Writer::new(Vec::new());
    writer.set_boundary("sample").unwrap();
    assert_eq!(
        writer.form_data_content_type(),
        "multipart/form-data; boundary=sample"
    );
}
#[test]
fn multipart_preamble_epilogue_and_transport_padding() {
    let bytes = b"preamble\r\n--a \t\r\nContent-Disposition: form-data; name=field\r\n\r\nbody\r\n--a--\t\r\nepilogue";
    let parts = read_all(bytes, "a");
    assert_eq!(parts, [("field".into(), String::new(), b"body".to_vec())]);
    assert!(read_all(b"--a--", "a").is_empty());
}
#[test]
fn multipart_go_framing_of_malformed_and_unusual_input() {
    // Go (unlike a strict codec) accepts bare LF framing, repeated
    // Content-Disposition headers (the first one names the part) and an
    // unsupported Content-Transfer-Encoding (the body is passed through).
    let lf = b"--a\nContent-Disposition: form-data; name=x\n\nx\n--a--";
    assert_eq!(read_all(lf, "a")[0].2, b"x");
    let dup = b"--a\r\nContent-Disposition: form-data; name=x\r\nContent-Disposition: form-data; name=y\r\n\r\nx\r\n--a--";
    assert_eq!(read_all(dup, "a")[0].0, "x");
    let cte = b"--a\r\nContent-Disposition: form-data; name=x\r\nContent-Transfer-Encoding: base64\r\n\r\nx\r\n--a--";
    assert_eq!(read_all(cte, "a")[0].2, b"x");
    // A folded first header line is malformed, as in Go.
    let folded = b"--a\r\n Content-Disposition: form-data; name=x\r\n\r\nx\r\n--a--";
    assert!(multipart::Reader::new(&folded[..], "a")
        .next_part()
        .is_err());
    // A missing closing delimiter is an unexpected EOF while reading the body.
    let truncated = b"--a\r\nContent-Disposition: form-data; name=x\r\n\r\nx";
    let mut reader = multipart::Reader::new(&truncated[..], "a");
    let mut part = reader.next_part().unwrap().unwrap();
    let error = part.read_to_end(&mut Vec::new()).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
}
#[test]
fn multipart_writer_validates_boundaries_like_go() {
    let mut writer = multipart::Writer::new(Vec::new());
    for boundary in ["", "x ", "x\r\n", "\u{1f4a5}"] {
        assert!(writer.set_boundary(boundary).is_err(), "{boundary:?}");
    }
    assert!(writer.set_boundary(&"a".repeat(71)).is_err());
    assert!(writer.set_boundary(&"a".repeat(70)).is_ok());
}
#[test]
fn multipart_writer_handles_partial_io_and_propagates_failure() {
    struct Partial(Vec<u8>);
    impl std::io::Write for Partial {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let count = bytes.len().min(2);
            self.0.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut sink = Partial(Vec::new());
    {
        let mut writer = multipart::Writer::new(&mut sink);
        writer.set_boundary("a").unwrap();
        writer.write_field("x", "content").unwrap();
        writer.close().unwrap();
    }
    assert_eq!(read_all(&sink.0, "a")[0].2, b"content");
    struct Fail;
    impl std::io::Write for Fail {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "closed",
            ))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    assert_eq!(
        multipart::Writer::new(Fail)
            .write_field("x", "content")
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::BrokenPipe
    );
}

#[test]
fn mime_and_http_token_grammars_are_distinct() {
    assert!(mime::MediaType::parse("application/{custom}").is_ok());
    assert!(mime::parse_parameters("form=data", Default::default()).is_err());
    assert!(mime::format_parameters("form=data", &Default::default()).is_err());
    #[cfg(feature = "net")]
    assert!(rust_stdlib::net::http::parse_cookie("{name}=x").is_err());
}

#[test]
fn multipart_reader_handles_every_buffer_split_with_binary_data() {
    let parts: [(&str, Option<&str>, &[u8]); 3] = [
        (
            "x",
            None,
            b"\x00\xff\r\n--boundary-prefix\r\n--boundary-\r\n",
        ),
        ("x", Some("file"), b""),
        ("y", None, b"tail"),
    ];
    let bytes = build("boundary", &parts);
    for capacity in 1..=bytes.len() {
        let input = std::io::BufReader::with_capacity(capacity, bytes.as_slice());
        let mut reader = multipart::Reader::new(input, "boundary");
        for (name, filename, body) in &parts {
            let part = reader.next_part().unwrap().unwrap().into_owned().unwrap();
            assert_eq!(part.form_name(), *name, "buffer {capacity}");
            assert_eq!(
                part.file_name(),
                filename.unwrap_or(""),
                "buffer {capacity}"
            );
            assert_eq!(part.body, *body, "buffer {capacity}");
        }
        assert!(reader.next_part().unwrap().is_none());
    }
}
#[test]
fn multipart_reader_reports_truncation() {
    let bytes = build("a", &[("x", None, b"abc"), ("x", None, b"def")]);
    for end in 0..bytes.len() - 2 {
        let mut reader =
            multipart::Reader::new(std::io::BufReader::with_capacity(1, &bytes[..end]), "a");
        while matches!(reader.next_part(), Ok(Some(_))) {}
        assert!(reader.next_part().is_err(), "truncation {end}");
    }
}

#[test]
fn multipart_reader_ignores_epilogue_and_propagates_io_failure() {
    let mut bytes = build("a", &[("x", None, b"content")]);
    bytes.extend_from_slice(b"epilogue");
    let mut reader = multipart::Reader::new(std::io::Cursor::new(&bytes), "a");
    assert_eq!(
        reader
            .next_part()
            .unwrap()
            .unwrap()
            .into_owned()
            .unwrap()
            .body,
        b"content"
    );
    assert!(reader.next_part().unwrap().is_none());
    struct Fail;
    impl std::io::Read for Fail {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
    }
    impl std::io::BufRead for Fail {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
        fn consume(&mut self, _: usize) {}
    }
    let mut reader = multipart::Reader::new(Fail, "a");
    assert_eq!(
        reader.next_part().unwrap_err().kind(),
        std::io::ErrorKind::BrokenPipe
    );
}

#[test]
fn multipart_reader_treats_boundary_after_headers_as_empty_body() {
    let bytes = b"--a\r\nContent-Disposition: form-data; name=x\r\n\r\n--a--\r\n";
    // Go's reader treats the boundary right after the headers as an empty body.
    let mut reader = multipart::Reader::new(std::io::Cursor::new(bytes), "a");
    assert_eq!(
        reader
            .next_part()
            .unwrap()
            .unwrap()
            .into_owned()
            .unwrap()
            .body,
        b""
    );
    assert!(reader.next_part().unwrap().is_none());
}
