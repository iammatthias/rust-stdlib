use rust_stdlib::encoding::base32;
use std::io::{self, Read, Write};

#[test]
fn rfc4648_standard_and_hex_vectors() {
    for (plain, standard, hex) in [
        (b"".as_slice(), "", ""),
        (b"f", "MY======", "CO======"),
        (b"fo", "MZXQ====", "CPNG===="),
        (b"foo", "MZXW6===", "CPNMU==="),
        (b"foob", "MZXW6YQ=", "CPNMUOG="),
        (b"fooba", "MZXW6YTB", "CPNMUOJ1"),
        (b"foobar", "MZXW6YTBOI======", "CPNMUOJ1E8======"),
    ] {
        assert_eq!(base32::STANDARD.encode(plain), standard);
        assert_eq!(base32::HEX.encode(plain), hex);
        assert_eq!(base32::STANDARD.decode(standard).unwrap(), plain);
        assert_eq!(base32::HEX.decode(hex).unwrap(), plain);
    }
}

#[test]
fn raw_encodings_and_newlines_match_go_behavior() {
    for (enc, expected) in [
        (base32::STANDARD_NO_PAD, "MZXW6YTBOI"),
        (base32::HEX_NO_PAD, "CPNMUOJ1E8"),
    ] {
        assert_eq!(enc.encode(b"foobar"), expected);
        assert_eq!(enc.decode(expected).unwrap(), b"foobar");
    }
    assert_eq!(
        base32::STANDARD.decode("MZ\nXW\r6YTBOI======").unwrap(),
        b"foobar"
    );
    assert_eq!(base32::STANDARD.decode("MY======X").unwrap(), b"f");
    assert_eq!(
        base32::STANDARD_NO_PAD.decode("MZ\nXW6YTBOI").unwrap(),
        b"foobar"
    );
    // Go's decoder ignores unused low bits rather than enforcing a canonical tail.
    assert_eq!(base32::STANDARD_NO_PAD.decode("MZ").unwrap(), b"f");
}

#[test]
fn custom_alphabet_and_padding_validation() {
    let custom = base32::Engine::new(b"abcdefghijklmnopqrstuvwxyz234567").unwrap();
    assert_eq!(custom.encode(b"f"), "my======");
    assert_eq!(custom.decode("my======").unwrap(), b"f");
    let raw = custom.with_padding(None).unwrap();
    assert_eq!(raw.encode(b"f"), "my");
    assert_eq!(raw.decode("my").unwrap(), b"f");
    assert!(base32::Engine::new(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_err());
    let mut newline = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    newline[4] = b'\n';
    assert!(base32::Engine::new(&newline).is_err());
    assert!(custom.with_padding(Some(b'a')).is_err());
    assert!(custom.with_padding(Some(b'\n')).is_err());

    let bytes: [u8; 32] = std::array::from_fn(|i| 128 + i as u8);
    let byte_alphabet = base32::Engine::new(&bytes).unwrap();
    assert_eq!(byte_alphabet.encode("x"), "\u{fffd}\u{fffd}======");
    assert_eq!(byte_alphabet.encode_to_vec(b"x").len(), 8);
}

#[test]
fn malformed_lengths_padding_and_alphabets_reject() {
    for bad in [
        "A",
        "AAA",
        "AAAAAA",
        "A=======",
        "AAA=====",
        "AAAAAA==",
        "MY=====X",
        "MY======XYZ",
        "my======",
    ] {
        assert!(base32::STANDARD.decode(bad).is_err(), "{bad:?}");
    }
    for bad in ["M=", "M=Y", "MY======"] {
        assert!(base32::STANDARD_NO_PAD.decode(bad).is_err(), "{bad:?}");
    }
    assert_eq!(base32::STANDARD_NO_PAD.decode("A").unwrap(), b"");
    // Go writes nothing for a 3- or 6-symbol quantum, and five bytes for nine symbols.
    assert_eq!(base32::STANDARD_NO_PAD.decode("AAA").unwrap(), b"");
    assert_eq!(base32::STANDARD_NO_PAD.decode("AAAAAA").unwrap(), b"");
    assert_eq!(base32::STANDARD_NO_PAD.decode("AAAAAAAAA").unwrap(), [0; 5]);
    assert!(base32::HEX.decode("CPNMUOJ1E8======").is_ok());
    assert!(base32::STANDARD.decode("CPNMUOJ1E8======").is_err());
}

#[test]
fn streaming_roundtrip_flush_and_partial_io() {
    for encoding in [
        base32::STANDARD,
        base32::HEX,
        base32::STANDARD_NO_PAD,
        base32::HEX_NO_PAD,
    ] {
        for n in 0..130 {
            let plain: Vec<_> = (0..n).map(|i| (i * 67) as u8).collect();
            let mut encoder = encoding.encoder(Short {
                bytes: vec![],
                at: 0,
                interrupt: true,
            });
            for chunk in plain.chunks(3) {
                encoder.write_all(chunk).unwrap();
                encoder.flush().unwrap();
            }
            let coded = encoder.finish().unwrap().bytes;
            assert_eq!(coded, encoding.encode_to_vec(&plain));
            let unpadded = encoding == base32::STANDARD_NO_PAD || encoding == base32::HEX_NO_PAD;
            let mut decoder = encoding.decoder(Short {
                bytes: coded.clone(),
                at: 0,
                interrupt: true,
            });
            assert_eq!(decoder.read(&mut []).unwrap(), 0);
            let mut decoded = vec![];
            let result = decoder.read_to_end(&mut decoded);
            if unpadded && coded.len() > 1 {
                // Go's stream decoder treats a short unpadded chunk as the end
                // of the message and rejects the data that follows it.
                assert!(result.is_err());
            } else {
                result.unwrap();
                assert_eq!(decoded, plain);
            }
            let mut decoded = vec![];
            encoding
                .decoder(&coded[..])
                .read_to_end(&mut decoded)
                .unwrap();
            assert_eq!(decoded, plain);
        }
    }
}

#[test]
fn streaming_decoder_emits_valid_prefix_then_reports_chunk_error_offset() {
    let data = b"MZXW6YTB\n!";
    let mut decoder = base32::STANDARD_NO_PAD.decoder(&data[..]);
    let mut output = Vec::new();
    assert!(decoder.read_to_end(&mut output).is_err());
    assert_eq!(output, b"fooba");

    let mut decoder = base32::STANDARD_NO_PAD.decoder(&b"MZXW6YTBOI\n!"[..]);
    let mut valid = [0; 16];
    assert_eq!(decoder.read(&mut valid).unwrap(), 5);
    let error = decoder.read(&mut [0; 16]).unwrap_err();
    let codec_error = error
        .get_ref()
        .and_then(|e| e.downcast_ref::<base32::Error>())
        .unwrap();
    // The offset is relative to the chunk after CR and LF are filtered out, as in Go.
    assert_eq!(codec_error.offset(), 10);
}

#[test]
fn buffer_forms_partial_output_and_go_error_text() {
    let enc = base32::STANDARD;
    assert_eq!(enc.encode_to_vec(b"foobar"), b"MZXW6YTBOI======");
    let mut out = b"x".to_vec();
    enc.encode_into(b"fo", &mut out);
    assert_eq!(out, b"xMZXQ====");
    assert_eq!((enc.encoded_len(6), enc.decoded_len(16)), (16, 10));
    assert_eq!(
        (
            base32::STANDARD_NO_PAD.encoded_len(6),
            base32::STANDARD_NO_PAD.decoded_len(10)
        ),
        (10, 6)
    );

    // Decoding reports the bytes written before the first corrupt byte, as Go does.
    let mut out = Vec::new();
    let error = enc.decode_into(b"MZXW6YTB!", &mut out).unwrap_err();
    assert_eq!((out.len(), &out[..]), (5, &b"fooba"[..]));
    assert_eq!(error.offset(), 8);
    let mut out = Vec::new();
    assert!(enc.decode_into(b"MZXW6YTB\r\n!", &mut out).is_err());
    assert_eq!(out, b"fooba");
    assert_eq!(error.to_string(), "illegal base32 data at input byte 8");
    assert!(enc.with_padding(Some(base32::PAD)).is_ok());
}

struct Short {
    bytes: Vec<u8>,
    at: usize,
    interrupt: bool,
}
impl Read for Short {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.interrupt {
            self.interrupt = false;
            return Err(io::ErrorKind::Interrupted.into());
        }
        if out.is_empty() || self.at == self.bytes.len() {
            return Ok(0);
        }
        out[0] = self.bytes[self.at];
        self.at += 1;
        Ok(1)
    }
}
impl Write for Short {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if self.interrupt {
            self.interrupt = false;
            return Err(io::ErrorKind::Interrupted.into());
        }
        if input.is_empty() {
            return Ok(0);
        }
        self.bytes.push(input[0]);
        Ok(1)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn decode_into_keeps_the_bytes_decoded_before_the_error() {
    let mut out = Vec::new();
    let err = base32::STANDARD
        .decode_into(b"MZXW6YTBMZXW6!!!", &mut out)
        .unwrap_err();
    assert_eq!(out, b"fooba");
    assert_eq!(err.offset(), 13);
    let mut out = Vec::new();
    assert!(base32::STANDARD.decode_into(b"MZXW6YTB", &mut out).is_ok());
    assert_eq!(out, b"fooba");
}

const HEX_BANG: Result<base32::Engine, base32::AlphabetError> =
    base32::HEX_NO_PAD.with_padding(Some(b'!'));
const HEX_BAD: Result<base32::Engine, base32::AlphabetError> = base32::HEX.with_padding(Some(b'0'));

#[test]
fn with_padding_is_const() {
    assert_eq!(HEX_BANG.unwrap().encode(b"f"), "CO!!!!!!");
    assert!(HEX_BAD.is_err());
}
