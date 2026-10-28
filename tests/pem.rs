use rust_stdlib::encoding::pem::{self, Block, Error, Limits};
use std::collections::BTreeMap;
use std::io::{self, Write};

fn block(type_: &str, bytes: &[u8]) -> Block {
    Block::new(type_, bytes.to_vec())
}

#[test]
fn encode_uses_proc_type_first_sorted_headers_and_64_columns() {
    let mut value = block("TEST BLOCK", &(0..100).collect::<Vec<_>>());
    value.headers = BTreeMap::from([
        ("Z-last".to_owned(), "z".to_owned()),
        ("A-first".to_owned(), "a".to_owned()),
        ("Proc-Type".to_owned(), "4,ENCRYPTED".to_owned()),
    ]);
    let encoded = String::from_utf8(pem::encode(&value).unwrap()).unwrap();
    let lines: Vec<_> = encoded.lines().collect();
    assert_eq!(lines[0], "-----BEGIN TEST BLOCK-----");
    assert_eq!(lines[1], "Proc-Type: 4,ENCRYPTED");
    assert_eq!(lines[2], "A-first: a");
    assert_eq!(lines[3], "Z-last: z");
    assert_eq!(lines[4], "");
    assert_eq!(lines[5].len(), 64);
    assert_eq!(lines[6].len(), 64);
    assert_eq!(lines[7].len(), 8);
    assert_eq!(lines[8], "-----END TEST BLOCK-----");
}

#[test]
fn encode_rejects_colon_header_before_writing() {
    let mut value = block("X", b"x");
    value.headers.insert("bad:key".into(), "v".into());
    let mut writer = Vec::new();
    assert!(matches!(
        pem::encode_to_writer(&value, &mut writer),
        Err(pem::EncodeError::InvalidHeaderKey)
    ));
    assert!(writer.is_empty());
}

#[test]
fn decode_handles_headers_crlf_whitespace_and_remainder() {
    let source = b"junk\r\n-----BEGIN CERTIFICATE----- \t\r\nProc-Type:  4,ENCRYPTED \t\r\nName: value\r\n\r\nY WJj\t\r\n-----END CERTIFICATE----- \t\r\ntrailing";
    let (decoded, remainder) = pem::decode(source).unwrap();
    assert_eq!(decoded.type_, "CERTIFICATE");
    assert_eq!(decoded.headers["Proc-Type"], "4,ENCRYPTED");
    assert_eq!(decoded.headers["Name"], "value");
    assert_eq!(decoded.bytes, b"abc");
    assert_eq!(remainder, b"trailing");
}

#[test]
fn decoder_resynchronizes_after_bad_candidates_and_preserves_input_on_miss() {
    let source = b"-----BEGIN BROKEN-----\n%%%\n-----END BROKEN-----\n-----BEGIN GOOD-----\ndGVzdA==\n-----END GOOD-----\nrest";
    let (decoded, remainder) = pem::decode(source).unwrap();
    assert_eq!(decoded.type_, "GOOD");
    assert_eq!(decoded.bytes, b"test");
    assert_eq!(remainder, b"rest");
    let miss = b"prefix\n-----BEGIN NOT ENDED-----\n";
    assert!(pem::decode(miss).is_none());
}

#[test]
fn explicit_limits_reject_input_headers_blocks_and_decoded_payloads() {
    let source = b"-----BEGIN X-----\ndGVzdA==\n-----END X-----\n";
    assert_eq!(
        pem::decode_with_limits(
            source,
            Limits {
                max_input_bytes: 2,
                ..Limits::default()
            }
        ),
        Err(Error::InputLimit)
    );
    assert_eq!(
        pem::decode_with_limits(
            source,
            Limits {
                max_decoded_bytes: 3,
                ..Limits::default()
            }
        ),
        Err(Error::DecodedLimit)
    );
    let one_byte = b"-----BEGIN X-----\nYQ==\n-----END X-----\n";
    let (one_byte, _) = pem::decode_with_limits(
        one_byte,
        Limits {
            max_decoded_bytes: 1,
            ..Limits::default()
        },
    )
    .unwrap()
    .unwrap();
    assert_eq!(one_byte.bytes, b"a");
    let with_header = b"-----BEGIN X-----\nA: b\n\ndA==\n-----END X-----\n";
    assert_eq!(
        pem::decode_with_limits(
            with_header,
            Limits {
                max_headers: 0,
                ..Limits::default()
            }
        ),
        Err(Error::HeaderCountLimit)
    );
    assert_eq!(
        pem::decode_with_limits(
            with_header,
            Limits {
                max_header_bytes: 1,
                ..Limits::default()
            }
        ),
        Err(Error::HeaderBytesLimit)
    );
    assert_eq!(
        pem::decode_with_limits(
            source,
            Limits {
                max_block_bytes: 8,
                ..Limits::default()
            }
        ),
        Err(Error::BlockLimit)
    );
}

#[test]
fn rejects_over_limit_input_before_scanning_its_many_markers() {
    let mut input = b"\n-----END X-----".repeat(20_000);
    input.extend_from_slice(b"-----BEGIN X-----\ndGVzdA==\n-----END X-----");
    assert_eq!(
        pem::decode_with_limits(
            &input,
            Limits {
                max_input_bytes: 8,
                ..Limits::default()
            }
        ),
        Err(Error::InputLimit)
    );
    assert!(pem::decode(&input).is_none());
}

struct PartialWriter(Vec<u8>);
impl Write for PartialWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = bytes.len().min(3);
        self.0.extend_from_slice(&bytes[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn writer_helper_handles_partial_writes() {
    let expected = pem::encode(&block("X", b"payload")).unwrap();
    let mut writer = PartialWriter(Vec::new());
    pem::encode_to_writer(&block("X", b"payload"), &mut writer).unwrap();
    assert_eq!(writer.0, expected);
}

#[test]
fn decode_raw_keeps_non_utf8_types_and_headers_and_decode_has_no_limits() {
    let data = b"junk\n-----BEGIN \xff\xfe-----\nK\xff: v\n\nYWJj\n-----END \xff\xfe-----\nrest";
    let (block, rest) = pem::decode_raw(data).unwrap();
    assert_eq!(block.type_, b"\xff\xfe");
    assert_eq!(block.headers[&b"K\xff".to_vec()], b"v");
    assert_eq!(block.bytes, b"abc");
    assert_eq!(rest, b"rest");
    // The String form cannot hold the block and skips it.
    assert!(pem::decode(data).is_none());
    // No default budget: a payload above the old 8 MiB default decodes.
    let payload = vec![7u8; 9 << 20];
    let encoded = pem::encode(&Block::new("BIG", payload.clone())).unwrap();
    let (big, _) = pem::decode(&encoded).unwrap();
    assert_eq!(big.bytes, payload);
}
