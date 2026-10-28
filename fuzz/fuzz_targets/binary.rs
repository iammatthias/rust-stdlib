#![no_main]
#![forbid(unsafe_code)]
use libfuzzer_sys::fuzz_target;
use rust_stdlib::{
    archive::{tar, zip},
    compress,
    encoding::{ascii85, base32, base64, hex, pem},
    quotedprintable,
};
use std::io::{Read, Write};
fuzz_target!(|data: &[u8]| {
    if data.len() > 8192 {
        return;
    }
    let limits = compress::Limits {
        max_input: 8192,
        max_output: 65536,
    };
    let _ = compress::decode_deflate(data, &mut Vec::new(), limits);
    let _ = compress::decode_gzip(data, &mut Vec::new(), limits);
    let _ = compress::decode_zlib(data, &mut Vec::new(), limits);
    for mut decoder in [
        compress::Decoder::deflate(data, limits),
        compress::Decoder::gzip(data, limits),
        compress::Decoder::zlib(data, limits),
    ]
    .into_iter()
    .flatten()
    {
        let _ = decoder.read_to_end(&mut Vec::new());
        let _ = decoder.finish();
    }
    let _ = compress::bzip2::decode(
        data,
        compress::bzip2::Limits {
            max_output: 65536,
            max_block_size: 200_000,
        },
    );
    let _ = hex::decoder(data).read_to_end(&mut Vec::new());
    for codec in [
        base32::STANDARD,
        base32::HEX,
        base32::STANDARD_NO_PAD,
        base32::HEX_NO_PAD,
    ] {
        let _ = codec.decode(data);
        let _ = codec.decoder(data).read_to_end(&mut Vec::new());
        if data.len() <= 256 {
            let encoded = codec.encode_to_vec(data);
            let mut decoded = Vec::new();
            codec
                .decoder(encoded.as_slice())
                .read_to_end(&mut decoded)
                .unwrap();
            assert_eq!(decoded, data);
        }
    }
    let _ = ascii85::Decoder::new(data).read_to_end(&mut Vec::new());
    let _ = quotedprintable::Reader::new(data).read_to_end(&mut Vec::new());
    let _ = pem::decode(data);
    if data.len() <= 256 {
        let encoded = ascii85::encode_to_vec(data);
        let mut decoded = Vec::new();
        ascii85::Decoder::new(encoded.as_slice())
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, data);
        let block = pem::Block::new("FUZZ", data);
        let encoded = pem::encode(&block).unwrap();
        let (decoded, remainder) = pem::decode(&encoded).unwrap();
        assert_eq!(decoded, block);
        assert!(remainder.is_empty());
    }
    for order in [compress::lzw::Order::Lsb, compress::lzw::Order::Msb] {
        let width = data.first().copied().unwrap_or(0) % 7 + 2;
        let _ = compress::lzw::decode(data, order, width, 65536);
        if data.len() <= 256 {
            let encoded = compress::lzw::encode(data, order, 8).unwrap();
            assert_eq!(
                compress::lzw::decode(&encoded, order, 8, 65536).unwrap(),
                data
            );
        }
    }
    for codec in [
        base64::STANDARD,
        base64::STANDARD_NO_PAD,
        base64::URL_SAFE,
        base64::URL_SAFE_NO_PAD,
        base64::STANDARD.strict(),
        base64::STANDARD_NO_PAD.strict(),
    ] {
        let _ = codec.decoder(data).read_to_end(&mut Vec::new());
        if data.len() <= 256 {
            let mut encoder = codec.encoder(Vec::new());
            for chunk in data.chunks(7) {
                encoder.write_all(chunk).unwrap();
            }
            let encoded = encoder.finish().unwrap();
            let mut decoded = Vec::new();
            codec
                .decoder(encoded.as_slice())
                .read_to_end(&mut decoded)
                .unwrap();
            assert_eq!(decoded, data);
        }
    }
    if data.len() <= 256 {
        let mut encoder = hex::encoder(Vec::new());
        for chunk in data.chunks(7) {
            encoder.write_all(chunk).unwrap();
        }
        let encoded = encoder.finish().unwrap();
        let mut decoded = Vec::new();
        hex::decoder(encoded.as_slice())
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, data);
    }
    let _ = tar::read(
        data,
        tar::Limits {
            max_archive: 8192,
            max_entries: 64,
            max_file: 65536,
            max_total: 65536,
        },
    );
    let _ = zip::read(
        data,
        zip::Limits {
            max_archive: 8192,
            max_entries: 64,
            max_file: 65536,
            max_total: 65536,
        },
    );
    let mut encoded = [0u8; 10];
    if let Ok((value, _)) = rust_stdlib::encoding::binary::uvarint(data) {
        let count = rust_stdlib::encoding::binary::put_uvarint(&mut encoded, value).unwrap();
        assert_eq!(
            rust_stdlib::encoding::binary::uvarint(&encoded[..count])
                .unwrap()
                .0,
            value
        );
    }
    if let Ok((value, _)) = rust_stdlib::encoding::binary::varint(data) {
        let duration = rust_stdlib::time::Duration::from_nanos(value);
        assert_eq!(
            duration
                .to_string()
                .parse::<rust_stdlib::time::Duration>()
                .unwrap(),
            duration
        );
        let count = rust_stdlib::encoding::binary::put_varint(&mut encoded, value).unwrap();
        assert_eq!(
            rust_stdlib::encoding::binary::varint(&encoded[..count])
                .unwrap()
                .0,
            value
        );
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = hex::decode(text);
        for codec in [
            base64::STANDARD,
            base64::STANDARD_NO_PAD,
            base64::URL_SAFE,
            base64::URL_SAFE_NO_PAD,
        ] {
            let _ = codec.decode(text);
        }
    }
    assert_eq!(
        base64::STANDARD
            .decode(base64::STANDARD.encode(data))
            .unwrap(),
        data
    );
});
