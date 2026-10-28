use rust_stdlib::encoding::ascii85;
use std::io::{self, Read, Write};

#[test]
fn encode_decode_matches_ascii85_vectors() {
    let cases: &[(&[u8], &[u8])] = &[
        (b"", b""),
        (b"\0\0\0\0", b"z"),
        (b"Man ", b"9jqo^"),
        (b"Man is", b"9jqo^Bla"),
        (b"\xff\xff\xff\xff", b"s8W-!"),
        (b"\0\0\0", b"!!!!"),
        (b"\0", b"!!"),
    ];
    for (plain, encoded) in cases {
        assert_eq!(ascii85::encode_to_vec(plain), *encoded);
        let mut decoded = [0u8; 16];
        let (n, consumed, result) = ascii85::decode(&mut decoded, encoded, true);
        assert!(result.is_ok());
        assert_eq!(&decoded[..n], *plain);
        assert_eq!(consumed, encoded.len());
    }
}

#[test]
fn whitespace_z_and_go_decode_consumption_semantics() {
    let mut dst = [0u8; 16];
    let (n, consumed, err) = ascii85::decode(&mut dst, b" \t\nz !!!!!", true);
    assert!(err.is_ok());
    assert_eq!(n, 8);
    assert_eq!(consumed, 10);
    assert_eq!(&dst[..4], &[0; 4]);
    assert_eq!(&dst[4..8], &[0; 4]);

    let (n, consumed, err) = ascii85::decode(&mut [0; 4], b"!!!!! tail", false);
    assert!(err.is_ok());
    assert_eq!(n, 4);
    assert_eq!(consumed, 5);
}

#[test]
fn malformed_and_fragment_rules() {
    for (input, offset) in [(b"v".as_slice(), 0), (b"z!", 2), (b"~>", 0), (b"a", 1)] {
        let mut out = [0u8; 16];
        let (_, _, e) = ascii85::decode(&mut out, input, true);
        assert_eq!(e.unwrap_err().0, offset, "{input:?}");
    }
    let mut out = [0u8; 16];
    let (n, _, e) = ascii85::decode(&mut out, b"!!!!\x7f", false);
    assert!(e.is_err());
    assert_eq!(n, 0); // Go Decode reports 0,0 on a malformed input byte.
}

#[test]
fn stream_round_trip_short_writes_and_reads() {
    let input: Vec<u8> = (0..8197).map(|i| (i * 47) as u8).collect();
    let mut writer = ascii85::Encoder::new(ShortWriter {
        bytes: Vec::new(),
        interrupt: true,
    });
    for chunk in input.chunks(7) {
        writer.write_all(chunk).unwrap();
    }
    assert_eq!(writer.write(&[]).unwrap(), 0);
    writer.flush().unwrap();
    let encoded = writer.finish().unwrap().bytes;
    assert_eq!(encoded, ascii85::encode_to_vec(&input));
    let mut decoded = Vec::new();
    ascii85::Decoder::new(ShortReader {
        data: encoded,
        pos: 0,
        interrupt: true,
    })
    .read_to_end(&mut decoded)
    .unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn decoder_handles_whitespace_shorthand_and_errors_after_valid_data() {
    let mut decoded = Vec::new();
    ascii85::Decoder::new(&b"z\n!!!!!!!"[..])
        .read_to_end(&mut decoded)
        .unwrap();
    assert_eq!(&decoded[..4], &[0; 4]);
    // Go discards the output of a chunk that contains corrupt input and keeps
    // the error sticky.
    let mut reader = ascii85::Decoder::new(&b"!!!!!x"[..]);
    let mut output = [0; 8];
    let first = reader.read(&mut output).unwrap_err();
    assert_eq!(first.kind(), io::ErrorKind::InvalidData);
    assert_eq!(first.to_string(), "illegal ascii85 data at input byte 5");
    let second = reader.read(&mut output).unwrap_err();
    assert_eq!(second.to_string(), first.to_string());
}

/// Yields one chunk of data, then fails like a broken source.
struct ThenFail(Option<&'static [u8]>);

impl Read for ThenFail {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        match self.0.take() {
            Some(data) => {
                out[..data.len()].copy_from_slice(data);
                Ok(data.len())
            }
            None => Err(io::Error::other("source failed")),
        }
    }
}

#[test]
fn decoder_flushes_partial_block_before_source_error_like_go() {
    let mut reader = ascii85::Decoder::new(ThenFail(Some(b"!!!!!!!")));
    let mut output = [0; 8];
    assert_eq!(reader.read(&mut output).unwrap(), 4);
    assert_eq!(reader.read(&mut output).unwrap(), 1);
    let error = reader.read(&mut output).unwrap_err();
    assert_eq!(error.to_string(), "source failed");
}

#[test]
fn decoder_reports_offsets_relative_to_its_chunk_like_go() {
    // Go decodes 1024-byte chunks: the first chunk yields 816 bytes, and the
    // corrupt 'x' is at byte 80 of the second chunk (absolute byte 1100).
    let mut input = vec![b'!'; 1100];
    input.push(b'x');
    let mut reader = ascii85::Decoder::new(&input[..]);
    let mut output = [0; 2048];
    assert_eq!(reader.read(&mut output).unwrap(), 816);
    let error = reader.read(&mut output).unwrap_err();
    assert_eq!(error.to_string(), "illegal ascii85 data at input byte 80");
    assert_eq!(
        reader.read(&mut output).unwrap_err().to_string(),
        error.to_string()
    );
}

struct ShortWriter {
    bytes: Vec<u8>,
    interrupt: bool,
}
impl Write for ShortWriter {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if self.interrupt {
            self.interrupt = false;
            return Err(io::ErrorKind::Interrupted.into());
        }
        let n = b.len().min(2);
        self.bytes.extend_from_slice(&b[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct ShortReader {
    data: Vec<u8>,
    pos: usize,
    interrupt: bool,
}
impl Read for ShortReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.interrupt {
            self.interrupt = false;
            return Err(io::ErrorKind::Interrupted.into());
        }
        if out.is_empty() || self.pos == self.data.len() {
            return Ok(0);
        }
        out[0] = self.data[self.pos];
        self.pos += 1;
        Ok(1)
    }
}
