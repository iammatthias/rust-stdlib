use rust_stdlib::encoding::base64::{PAD, STANDARD, STANDARD_NO_PAD};

#[test]
fn lengths_and_padding() {
    assert_eq!(STANDARD.encoded_len(1), 4);
    assert_eq!(STANDARD.decoded_len(8), 6);
    assert_eq!(STANDARD_NO_PAD.decoded_len(7), 5);
    assert_eq!(STANDARD.with_padding(None).unwrap(), STANDARD_NO_PAD);
    assert_eq!(PAD, b'=');
    assert_eq!(STANDARD_NO_PAD.encode("f"), "Zg");
}

#[test]
fn encode_into_appends() {
    let mut out = b"x:".to_vec();
    STANDARD.encode_into("fo", &mut out);
    assert_eq!(out, b"x:Zm8=");
}

#[test]
fn decode_into_keeps_complete_quanta_before_an_error() {
    // "Zm9v" decodes fully, then "Yg==" is a complete quantum followed by trailing data.
    let mut out = Vec::new();
    let error = STANDARD.decode_into("Zm9vYg==X", &mut out).unwrap_err();
    assert_eq!(out, b"foob");
    assert_eq!(error.offset(), 8);

    let mut out = vec![0xaa];
    assert!(STANDARD.decode_into("Zm9v!", &mut out).is_err());
    assert_eq!(out, [0xaa, b'f', b'o', b'o']);
}

#[test]
fn decoding_skips_newlines_and_strict_checks_trailing_bits() {
    assert_eq!(STANDARD.decode("Zm9v\r\nYmFy").unwrap(), b"foobar");
    // "Zh==" has non-zero unused bits: accepted by default, rejected when strict.
    assert_eq!(STANDARD.decode("Zh==").unwrap(), b"f");
    assert!(STANDARD.strict().decode("Zh==").is_err());
}

#[test]
fn error_text() {
    let error = STANDARD.decode("Zm9!").unwrap_err();
    assert_eq!(error.to_string(), "illegal base64 data at input byte 3");
}

// Go builds these as package-level vars (`base64.RawURLEncoding.Strict()`);
// here they can be constants.
const STRICT_URL: rust_stdlib::encoding::base64::Engine =
    rust_stdlib::encoding::base64::URL_SAFE_NO_PAD.strict();
const BANG_PADDED: Result<
    rust_stdlib::encoding::base64::Engine,
    rust_stdlib::encoding::base64::AlphabetError,
> = STANDARD_NO_PAD.with_padding(Some(b'!'));
const BAD_PADDING: Result<
    rust_stdlib::encoding::base64::Engine,
    rust_stdlib::encoding::base64::AlphabetError,
> = STANDARD.with_padding(Some(b'A'));

#[test]
fn engine_builders_are_const() {
    assert!(STRICT_URL.decode(b"Zm9").is_err());
    assert_eq!(STRICT_URL.decode(b"Zm8").unwrap(), b"fo");
    assert_eq!(BANG_PADDED.unwrap().encode(b"f"), "Zg!!");
    assert!(BAD_PADDING.is_err());
}
