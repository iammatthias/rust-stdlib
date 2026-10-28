use rust_stdlib::encoding::{base64, hex};
use std::io::{self, Read, Write};
#[test]
fn base64_stream_groups_flush_and_finish() {
    for encoding in [
        base64::STANDARD,
        base64::URL_SAFE,
        base64::STANDARD_NO_PAD,
        base64::URL_SAFE_NO_PAD,
    ] {
        for n in 0..129 {
            let input: Vec<u8> = (0..n).map(|i| i as u8).collect();
            let mut writer = encoding.encoder(Vec::new());
            for chunk in input.chunks(2) {
                writer.write_all(chunk).unwrap();
                writer.flush().unwrap()
            }
            let out = writer.finish().unwrap();
            assert_eq!(out, encoding.encode(&input).as_bytes());
            let mut decoded = vec![];
            encoding
                .decoder(&out[..])
                .read_to_end(&mut decoded)
                .unwrap();
            assert_eq!(decoded, input);
        }
    }
}
#[test]
fn stream_errors_and_noncanonical_suffixes_reject() {
    for input in [
        "A", "AAA", "AA=", "AA===", "AA==X", "Zh==", "Zm9=", "Z g==", "AAAA====",
    ] {
        let mut decoder = base64::STANDARD.strict().decoder(input.as_bytes());
        let mut out = vec![];
        assert!(decoder.read_to_end(&mut out).is_err(), "{input}");
        assert_eq!(decoder.read(&mut [0u8; 1]).unwrap(), 0)
    }
    for input in ["A", "AA=", "Zh", "Zm9"] {
        assert!(base64::STANDARD_NO_PAD
            .strict()
            .decoder(input.as_bytes())
            .read_to_end(&mut vec![])
            .is_err())
    }
    for input in ["0", "fg", "00zz", "00f"] {
        assert!(hex::decoder(input.as_bytes())
            .read_to_end(&mut vec![])
            .is_err())
    }
}
#[test]
fn hex_stream_roundtrip_and_deferred_error() {
    let plain = vec![42u8; 4097];
    let mut writer = hex::encoder(Vec::new());
    for chunk in plain.chunks(19) {
        writer.write_all(chunk).unwrap()
    }
    let out = writer.finish().unwrap();
    assert_eq!(out, hex::encode(&plain).as_bytes());
    let mut decoded = vec![];
    hex::decoder(&out[..]).read_to_end(&mut decoded).unwrap();
    assert_eq!(decoded, plain);
    let mut decoder = hex::decoder(&b"00zz"[..]);
    let mut buffer = [0u8; 8];
    assert_eq!(decoder.read(&mut buffer).unwrap(), 1);
    assert_eq!(buffer[0], 0);
    assert!(decoder.read(&mut buffer).is_err());
    assert_eq!(decoder.read(&mut buffer).unwrap(), 0);
}
struct Short {
    bytes: Vec<u8>,
    position: usize,
    interrupt: bool,
}
impl Read for Short {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.interrupt {
            self.interrupt = false;
            return Err(io::ErrorKind::Interrupted.into());
        }
        if self.position == self.bytes.len() || out.is_empty() {
            return Ok(0);
        }
        out[0] = self.bytes[self.position];
        self.position += 1;
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
fn streaming_handles_partial_interrupted_io_and_empty_reads() {
    let mut writer = base64::STANDARD.encoder(Short {
        bytes: vec![],
        position: 0,
        interrupt: true,
    });
    writer.write_all(b"hello").unwrap();
    let encoded = writer.finish().unwrap();
    assert_eq!(encoded.bytes, b"aGVsbG8=");
    let mut reader = base64::STANDARD.decoder(Short {
        bytes: encoded.bytes,
        position: 0,
        interrupt: true,
    });
    assert_eq!(reader.read(&mut []).unwrap(), 0);
    let mut decoded = vec![];
    reader.read_to_end(&mut decoded).unwrap();
    assert_eq!(decoded, b"hello");
    let mut reader = hex::decoder(Short {
        bytes: b"4869".to_vec(),
        position: 0,
        interrupt: true,
    });
    assert_eq!(reader.read(&mut []).unwrap(), 0);
    decoded.clear();
    reader.read_to_end(&mut decoded).unwrap();
    assert_eq!(decoded, b"Hi");
}
struct Broken;
impl Write for Broken {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::BrokenPipe.into())
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::ErrorKind::BrokenPipe.into())
    }
}
#[test]
fn failed_encoders_remain_terminal() {
    let mut b = base64::STANDARD.encoder(Broken);
    assert!(b.write_all(b"abc").is_err());
    assert!(b.write_all(b"a").is_err());
    assert!(b.finish().is_err());
    let mut h = hex::encoder(Broken);
    assert!(h.write_all(b"a").is_err());
    assert!(h.write_all(b"a").is_err());
    assert!(h.finish().is_err());
}
