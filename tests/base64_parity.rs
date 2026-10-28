use rust_stdlib::encoding::base64;
use std::io::{Read, Write};

#[test]
fn engines_match_go_rules() {
    assert_eq!(base64::STANDARD.decode("Zh==").unwrap(), b"f");
    assert!(base64::STANDARD.strict().decode("Zh==").is_err());
    assert_eq!(base64::STANDARD.decode("Zg\n==\r").unwrap(), b"f");
    assert_eq!(base64::STANDARD.decode("Zg\n==").unwrap(), b"f");
    assert_eq!(base64::STANDARD.decode("Zg==\nX").unwrap_err().offset(), 5);
    assert_eq!(base64::STANDARD_NO_PAD.decode("Zm9").unwrap(), b"fo");

    let custom =
        base64::Engine::new(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!?")
            .unwrap();
    assert_eq!(custom.encode(b"hello"), "AgvSBg8=");
    assert_eq!(custom.decode("AgvSBg8=").unwrap(), b"hello");
    let alternate_pad = custom.with_padding(Some(b'~')).unwrap();
    assert_eq!(alternate_pad.encode(b"hello"), "AgvSBg8~");
    assert_eq!(alternate_pad.decode("AgvSBg8~").unwrap(), b"hello");
    let equals_alphabet =
        base64::Engine::new(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+=")
            .unwrap()
            .with_padding(Some(b'~'))
            .unwrap();
    assert_eq!(equals_alphabet.encode([255]), "=w~~");
    assert_eq!(equals_alphabet.decode("=w~~").unwrap(), [255]);
    let raw = custom.with_padding(None).unwrap();
    assert_eq!(raw.encode(b"hello"), "AgvSBg8");
    assert_eq!(raw.decode("AgvSBg8").unwrap(), b"hello");
    assert!(base64::Engine::new(
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    )
    .is_err());
    assert!(base64::Engine::new(
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+\n"
    )
    .is_err());
    assert!(custom.with_padding(Some(b'a')).is_err());
    assert!(custom.with_padding(Some(b'\r')).is_err());
    assert!(custom.with_padding(Some(0x80)).is_ok());
}

#[test]
fn stream_decoder_filters_newlines_and_checks_after_padding() {
    let mut decoded = vec![];
    base64::STANDARD
        .decoder(&b"Zg\n==\r"[..])
        .read_to_end(&mut decoded)
        .unwrap();
    assert_eq!(decoded, b"f");

    let mut decoded = vec![];
    assert!(base64::STANDARD
        .decoder(&b"Zg==\nX"[..])
        .read_to_end(&mut decoded)
        .is_err());
    assert_eq!(decoded, b"f");

    let mut decoder = base64::STANDARD.decoder(&b"Zm9v\nZg=#"[..]);
    let mut valid = [0; 8];
    assert_eq!(decoder.read(&mut valid).unwrap(), 3);
    let error = decoder.read(&mut valid).unwrap_err();
    let codec_error = error
        .get_ref()
        .and_then(|e| e.downcast_ref::<base64::Error>())
        .unwrap();
    assert_eq!(codec_error.offset(), 7);
}

#[test]
fn stream_encoder_handles_partial_writes() {
    let engine = base64::URL_SAFE_NO_PAD;
    for n in 0..96 {
        let input: Vec<_> = (0..n).map(|i| (i * 71) as u8).collect();
        let mut encoder = engine.encoder(Vec::new());
        for chunk in input.chunks(2) {
            encoder.write_all(chunk).unwrap();
        }
        let encoded = encoder.finish().unwrap();
        assert_eq!(encoded, engine.encode(&input).as_bytes());
        let mut output = vec![];
        engine
            .decoder(&encoded[..])
            .read_to_end(&mut output)
            .unwrap();
        assert_eq!(output, input);
    }
}

#[test]
fn partial_decode_and_non_ascii_padding_match_go() {
    let mut out = Vec::new();
    let error = base64::STANDARD
        .decode_into(b"Zm9vYmFy!!!!", &mut out)
        .unwrap_err();
    assert_eq!(out, b"foobar");
    assert_eq!(error.offset(), 8);
    let padded = base64::STANDARD.with_padding(Some(0xff)).unwrap();
    assert_eq!(padded.encode_to_vec(b"f"), b"Zg\xff\xff");
    assert_eq!(padded.decode(b"Zg\xff\xff").unwrap(), b"f");
}
