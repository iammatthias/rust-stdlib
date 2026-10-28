use rust_stdlib::encoding::hex::{self, Error, InvalidByteError};
use std::io::Write;

#[test]
fn lengths_and_buffer_encoding_match_go() {
    assert_eq!(hex::encoded_len(3), 6);
    assert_eq!(hex::decoded_len(7), 3);
    assert_eq!(hex::encode(b"\x01\xab\xff"), "01abff");
    let mut out = b"x".to_vec();
    hex::encode_into(b"\x10", &mut out);
    assert_eq!(out, b"x10");
}

/// Decodes into a fresh buffer: the bytes decoded before an error, and the error.
fn partial(input: &[u8]) -> (Vec<u8>, Result<(), Error>) {
    let mut out = Vec::new();
    let result = hex::decode_into(input, &mut out);
    (out, result)
}

#[test]
fn decode_into_reports_bytes_decoded_before_an_error() {
    assert_eq!(
        partial(b"0102zz"),
        (vec![1, 2], Err(Error::InvalidByte(InvalidByteError(b'z'))))
    );
    // An odd trailing digit is ErrLength, but a bad trailing byte is an invalid byte.
    assert_eq!(partial(b"abc"), (vec![0xab], Err(Error::Length)));
    assert_eq!(
        partial(b"ab1g"),
        (vec![0xab], Err(Error::InvalidByte(InvalidByteError(b'g'))))
    );
    assert_eq!(partial(b"ab1"), (vec![0xab], Err(Error::Length)));
    assert_eq!(partial(b"f"), (vec![], Err(Error::Length)));
    assert_eq!(
        partial(b"g"),
        (vec![], Err(Error::InvalidByte(InvalidByteError(b'g'))))
    );
    assert_eq!(partial(b"0a0b"), (vec![10, 11], Ok(())));
}

#[test]
fn decode_into_appends_and_keeps_partial_output() {
    let mut dst = vec![0x7f];
    assert!(hex::decode_into(b"01zz", &mut dst).is_err());
    assert_eq!(dst, [0x7f, 0x01]);
}

#[test]
fn error_messages_match_go() {
    assert_eq!(
        Error::Length.to_string(),
        "encoding/hex: odd length hex string"
    );
    assert_eq!(
        InvalidByteError(b'g').to_string(),
        "encoding/hex: invalid byte: U+0067 'g'"
    );
    assert_eq!(
        InvalidByteError(0x00).to_string(),
        "encoding/hex: invalid byte: U+0000"
    );
    assert_eq!(
        InvalidByteError(0xad).to_string(),
        "encoding/hex: invalid byte: U+00AD"
    );
    assert_eq!(
        InvalidByteError(0xe9).to_string(),
        "encoding/hex: invalid byte: U+00E9 'é'"
    );
}

#[test]
fn dump_matches_hexdump_layout() {
    assert_eq!(
        hex::dump(b"A"),
        "00000000  41                                                |A|\n"
    );
    let full = hex::dump(b"0123456789abcdefg");
    assert_eq!(
        full,
        "00000000  30 31 32 33 34 35 36 37  38 39 61 62 63 64 65 66  |0123456789abcdef|\n\
         00000010  67                                                |g|\n"
    );
    assert_eq!(hex::dump(b""), "");
}

#[test]
fn dumper_matches_dump_for_chunked_writes() {
    let data: Vec<u8> = (0..=255u8).cycle().take(100).collect();
    let mut out = Vec::new();
    let mut dumper = hex::Dumper::new(&mut out);
    for chunk in data.chunks(7) {
        dumper.write_all(chunk).unwrap();
    }
    dumper.close().unwrap();
    assert_eq!(out, hex::dump(&data).into_bytes());
}

#[test]
fn stream_decoder_errors_match_go() {
    use std::io::Read;
    let run = |input: &[u8]| {
        let mut out = Vec::new();
        let r = hex::decoder(input).read_to_end(&mut out);
        (out, r)
    };
    let (out, r) = run(b"0aff");
    assert_eq!((out, r.is_ok()), (vec![0x0a, 0xff], true));
    // A lone valid trailing digit is io.ErrUnexpectedEOF.
    let (out, r) = run(b"0aF");
    let e = r.unwrap_err();
    assert_eq!(out, [0x0a]);
    assert!(rust_stdlib::io::is_unexpected_eof(&e), "{e}");
    // A lone invalid trailing byte is reported as such.
    let e = run(b"0ag").1.unwrap_err();
    assert_eq!(
        e.get_ref()
            .and_then(|x| x.downcast_ref::<InvalidByteError>()),
        Some(&InvalidByteError(b'g'))
    );
    // The first bad byte in a pair, and in a later pair.
    let (out, r) = run(b"0a1zq1");
    let e = r.unwrap_err();
    assert_eq!(out, [0x0a]);
    assert_eq!(e.to_string(), InvalidByteError(b'z').to_string());
    assert_eq!(e.to_string(), "encoding/hex: invalid byte: U+007A 'z'");
}
