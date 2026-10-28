use rust_stdlib::compress::lzw::{self, Order, Reader, Writer};
use std::io::{Read, Write};

#[test]
fn round_trips_empty_literals_and_all_orders_and_widths() {
    for order in [Order::Lsb, Order::Msb] {
        for lit_width in 2..=8 {
            let alphabet = 1usize << lit_width;
            let input: Vec<u8> = (0..alphabet * 3).map(|i| (i % alphabet) as u8).collect();
            let encoded = lzw::encode(&input, order, lit_width).unwrap();
            assert_eq!(
                lzw::decode(&encoded, order, lit_width, input.len()).unwrap(),
                input
            );
            let empty = lzw::encode(&[], order, lit_width).unwrap();
            assert!(lzw::decode(&empty, order, lit_width, 0).unwrap().is_empty());
        }
    }
}

#[test]
fn streaming_chunks_preserve_phrase_state() {
    for order in [Order::Lsb, Order::Msb] {
        for lit_width in 2..=8 {
            let input: Vec<u8> = (0..10_000)
                .map(|i| ((i * 17 + i / 19) % (1 << lit_width)) as u8)
                .collect();
            let expected = lzw::encode(&input, order, lit_width).unwrap();
            let mut encoder = Writer::new(Vec::new(), order, lit_width);
            for chunk in input.chunks(7) {
                encoder.write_all(chunk).unwrap();
            }
            assert_eq!(encoder.finish().unwrap(), expected);
            let mut decoder =
                Reader::new(&expected[..], order, lit_width).with_max_output(input.len());
            let mut output = Vec::new();
            let mut small = [0; 11];
            loop {
                let count = decoder.read(&mut small).unwrap();
                if count == 0 {
                    break;
                }
                output.extend_from_slice(&small[..count]);
            }
            assert_eq!(output, input);
        }
    }
}

#[test]
fn dictionary_width_growth_and_clear_resets_round_trip() {
    let input: Vec<u8> = (0..240_000)
        .map(|i| ((i * 73 + i / 13 + i / 4093) & 255) as u8)
        .collect();
    for order in [Order::Lsb, Order::Msb] {
        let encoded = lzw::encode(&input, order, 8).unwrap();
        assert_eq!(lzw::decode(&encoded, order, 8, input.len()).unwrap(), input);
    }
}

#[test]
fn output_and_literal_limits_are_enforced() {
    let input = b"ABABABABABABABABABAB";
    let encoded = lzw::encode(input, Order::Lsb, 8).unwrap();
    let error = lzw::decode(&encoded, Order::Lsb, 8, input.len() - 1).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    let mut encoder = Writer::new(Vec::new(), Order::Lsb, 2);
    assert_eq!(
        encoder.write(&[0, 4]).unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
}

#[test]
fn missing_eof_and_truncated_codes_are_errors() {
    for order in [Order::Lsb, Order::Msb] {
        let encoded = lzw::encode(b"hello lzw", order, 8).unwrap();
        for cut in 0..encoded.len() {
            let result = lzw::decode(&encoded[..cut], order, 8, 100);
            assert!(
                result.is_err(),
                "accepted truncated stream at {cut}/{}, {order:?}",
                encoded.len()
            );
        }
    }
}

struct FailAfterOneByte {
    written: Vec<u8>,
    calls: usize,
}
impl Write for FailAfterOneByte {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.calls += 1;
        if self.calls > 1 {
            return Err(std::io::Error::other("writer failed"));
        }
        self.written.push(bytes[0]);
        Ok(1)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn writer_latches_errors_after_partial_output() {
    let writer = FailAfterOneByte {
        written: Vec::new(),
        calls: 0,
    };
    let mut encoder = Writer::new(writer, Order::Lsb, 2);
    encoder.write_all(&[1, 2, 3]).unwrap();
    assert!(encoder.write_all(&[0, 1, 2]).is_err());
    let calls = encoder.get_ref().calls;
    assert_eq!(calls, 2);
    assert!(encoder.write(&[0]).is_err());
    assert_eq!(encoder.get_ref().calls, calls);
    assert!(encoder.finish().is_err());
}

struct FlushFails {
    writes: usize,
}
impl Write for FlushFails {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.writes += 1;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other("flush failed"))
    }
}

#[test]
fn writer_latches_flush_errors() {
    let mut encoder = Writer::new(FlushFails { writes: 0 }, Order::Msb, 8);
    assert!(encoder.flush().is_err());
    assert_eq!(encoder.get_ref().writes, 0);
    assert!(encoder.write(&[1, 2, 3]).is_err());
    assert_eq!(encoder.get_ref().writes, 0);
    assert!(encoder.finish().is_err());
}

#[test]
fn go_close_and_reset_lifecycle() {
    let mut writer = Writer::new(Vec::new(), Order::Lsb, 8);
    writer.write_all(b"first").unwrap();
    writer.close().unwrap();
    writer.close().unwrap();
    assert!(writer.write(&[1]).is_err());
    let first = writer.get_ref().clone();
    writer.reset(Vec::new(), Order::Msb, 8);
    writer.write_all(b"second").unwrap();
    writer.close().unwrap();
    assert_eq!(
        writer.get_ref(),
        &lzw::encode(b"second", Order::Msb, 8).unwrap()
    );
    assert_eq!(first, lzw::encode(b"first", Order::Lsb, 8).unwrap());

    let encoded = lzw::encode(b"reader", Order::Lsb, 8).unwrap();
    let mut reader = Reader::new(&encoded[..], Order::Lsb, 8);
    reader.close().unwrap();
    let mut buffer = [0u8; 8];
    assert!(reader.read(&mut buffer).is_err());
    reader.reset(&encoded[..], Order::Lsb, 8);
    let mut decoded = Vec::new();
    reader.read_to_end(&mut decoded).unwrap();
    assert_eq!(decoded, b"reader");
}

#[test]
fn bad_lit_width_is_reported_on_first_use_like_go() {
    for width in [0, 1, 9, 200] {
        let mut writer = Writer::new(Vec::new(), Order::Lsb, width);
        let error = writer.write(&[0]).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("lzw: litWidth {width} out of range")
        );
        assert!(writer.close().is_err());
        writer.reset(Vec::new(), Order::Lsb, 8);
        writer.write_all(b"ok").unwrap();
        writer.close().unwrap();

        let mut reader = Reader::new(&[0u8][..], Order::Lsb, width);
        let error = reader.read(&mut [0u8; 4]).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("lzw: litWidth {width} out of range")
        );
    }
}

#[test]
fn reader_has_no_output_budget() {
    let input = vec![7u8; 3 << 20];
    let encoded = lzw::encode(&input, Order::Lsb, 8).unwrap();
    let mut reader = Reader::new(&encoded[..], Order::Lsb, 8);
    let mut decoded = Vec::new();
    reader.read_to_end(&mut decoded).unwrap();
    assert_eq!(decoded.len(), input.len());
}
