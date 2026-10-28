//! Independent review corpus: cross-protocol framing and metadata injection.
#![cfg(feature = "net")]
use rust_stdlib::{mime, multipart, net::http};
use std::io::{Cursor, Write};

#[test]
fn request_smuggling_variants_never_produce_a_request() {
    let attacks: &[&[u8]] = &[
        b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0, 5\r\n\r\nhello",
        b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked, chunked\r\n\r\n0\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n \tContent-Length: 0\r\n\r\n0\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: good.test\r\nHost: evil.test\r\n\r\n",
    ];
    for attack in attacks {
        assert!(
            http::request::read_request(&http::BufioReader::new(Cursor::new(attack.to_vec())))
                .is_err(),
            "{:?}",
            String::from_utf8_lossy(attack)
        );
    }
}

#[test]
fn mime_metadata_cannot_inject_headers() {
    // Go's Writer percent-escapes CR and LF in field names, so a name cannot
    // start a new header line; other bytes pass through inside the quotes (NUL is
    // refused by the reader).
    for value in [
        "x\r\nSet-Cookie: admin=true",
        "x\nHost: evil",
        "x\0y",
        "x;y",
    ] {
        let mut out = Vec::new();
        let mut writer = multipart::Writer::new(&mut out);
        writer.set_boundary("boundary").unwrap();
        writer.write_field(value, "data").unwrap();
        writer.close().unwrap();
        let wire = String::from_utf8(out.clone()).unwrap();
        assert_eq!(wire.matches("\r\n").count(), 5, "{wire:?}");
        let mut reader = multipart::Reader::new(out.as_slice(), "boundary");
        if value.contains('\0') {
            // Go's header parser refuses control bytes, so it never yields a part.
            assert!(reader.next_part().is_err(), "{wire:?}");
            continue;
        }
        let part = reader.next_part().unwrap().unwrap();
        assert_eq!(part.header.iter().count(), 1, "{wire:?}");
        let expected = value.replace('\r', "%0D").replace('\n', "%0A");
        assert_eq!(part.form_name(), expected);
    }
    assert!(mime::MediaType::parse("multipart/form-data; boundary=safe; boundary=evil").is_err());
}

#[test]
fn multipart_duplicate_dispositions_and_boundary_collisions_follow_go() {
    // Go does not reject a repeated Content-Disposition; the first value names
    // the part (a strict codec would refuse the message).
    let wire = b"--boundary\r\nContent-Disposition: form-data; name=public\r\nContent-Disposition: form-data; name=admin\r\n\r\ndata\r\n--boundary--\r\n";
    let mut reader = multipart::Reader::new(&wire[..], "boundary");
    assert_eq!(reader.next_part().unwrap().unwrap().form_name(), "public");

    // Go's Writer does not check bodies for the boundary: a delimiter line in
    // a payload ends the part when read back (here the rest is a malformed
    // header block), so the boundary must be unpredictable (the default is
    // random).
    let mut out = Vec::new();
    let mut writer = multipart::Writer::new(&mut out);
    writer.set_boundary("boundary").unwrap();
    writer
        .write_field("upload", "data\r\n--boundary\r\nother")
        .unwrap();
    writer.close().unwrap();
    let mut reader = multipart::Reader::new(out.as_slice(), "boundary");
    let first = reader.next_part().unwrap().unwrap().into_owned().unwrap();
    assert_eq!(first.body, b"data");
    assert!(reader.next_part().is_err());

    let payload = b"prefix--boundary\r\n--boundary-not-delimiter\r\nbinary\0";
    let mut out = Vec::new();
    let mut writer = multipart::Writer::new(&mut out);
    writer.set_boundary("boundary").unwrap();
    writer
        .create_form_field("upload")
        .unwrap()
        .write_all(payload)
        .unwrap();
    writer.close().unwrap();
    let mut reader = multipart::Reader::new(out.as_slice(), "boundary");
    let part = reader.next_part().unwrap().unwrap().into_owned().unwrap();
    assert_eq!(part.body, payload);
}

fn read(wire: &[u8]) -> http::Request {
    http::request::read_request(&http::BufioReader::new(Cursor::new(wire.to_vec()))).unwrap()
}

#[test]
fn go_interpretation_of_ambiguous_framing() {
    // Space before the colon: Go does not see a Transfer-Encoding field.
    let req = read(b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\n");
    assert!(req.transfer_encoding.is_empty());
    assert_eq!(req.content_length, 0);
    let body = req.body.map(|b| b.read_all().unwrap()).unwrap_or_default();
    assert!(body.is_empty());

    // Chunked wins over Content-Length, which is dropped.
    let req = read(
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    );
    assert_eq!(req.transfer_encoding, ["chunked"]);
    assert_eq!(req.content_length, -1);
    assert!(!req.header.0.contains_key("Content-Length"));

    // Bare LF line endings are accepted.
    let req = read(b"GET / HTTP/1.1\nHost: a\n\n");
    assert_eq!(req.method, "GET");
    assert_eq!(req.host, "a");
}

#[test]
fn cookie_string_sanitises_injection() {
    use http::Cookie;
    let c = |name: &str, value: &str| Cookie {
        name: name.into(),
        value: value.into(),
        ..Cookie::default()
    };
    // An invalid name yields no header at all.
    assert_eq!(c("a\r\nb", "x").to_string(), "");
    assert_eq!(c("{name}", "x").to_string(), "");
    // Invalid value bytes are dropped, never emitted.
    for value in [
        "x\r\nSet-Cookie: admin=true",
        "x\nHost: evil",
        "x\0y",
        "x;y",
    ] {
        let s = c("session", value).to_string();
        assert!(!s.contains(['\r', '\n', '\0', ';']), "{s:?}");
    }
    let mut cookie = c("a", "b");
    cookie.path = "/; Secure".into();
    assert!(!cookie.to_string().contains("; Secure"));
}
