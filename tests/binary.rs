use rust_stdlib::encoding::binary::{
    self, AppendByteOrder, ByteOrder, BIG_ENDIAN, LITTLE_ENDIAN, NATIVE_ENDIAN,
};
use std::io::{self, Read, Write};

#[test]
fn varint_go_vectors_boundaries() {
    for (value, expected) in [
        (0, vec![0]),
        (1, vec![1]),
        (127, vec![127]),
        (128, vec![128, 1]),
        (300, vec![172, 2]),
        (
            u64::MAX,
            vec![255, 255, 255, 255, 255, 255, 255, 255, 255, 1],
        ),
    ] {
        let mut out = [0u8; 10];
        let n = binary::put_uvarint(&mut out, value).unwrap();
        assert_eq!(&out[..n], expected);
        assert_eq!(binary::uvarint(&expected).unwrap(), (value, n));
        assert_eq!(binary::read_uvarint(&mut &expected[..]).unwrap(), value);
        let mut appended = vec![7];
        binary::append_uvarint(&mut appended, value);
        assert_eq!(&appended[1..], expected);
    }
    for (value, expected) in [
        (-1, vec![1]),
        (1, vec![2]),
        (-2, vec![3]),
        (
            i64::MIN,
            vec![255, 255, 255, 255, 255, 255, 255, 255, 255, 1],
        ),
        (
            i64::MAX,
            vec![254, 255, 255, 255, 255, 255, 255, 255, 255, 1],
        ),
    ] {
        let mut out = [0u8; 10];
        let n = binary::put_varint(&mut out, value).unwrap();
        assert_eq!(&out[..n], expected);
        assert_eq!(binary::varint(&expected).unwrap(), (value, n));
        assert_eq!(binary::read_varint(&mut &expected[..]).unwrap(), value);
        let mut appended = Vec::new();
        binary::append_varint(&mut appended, value);
        assert_eq!(appended, expected);
    }
    assert_eq!(binary::MAX_VARINT_LEN16, 3);
    assert_eq!(binary::MAX_VARINT_LEN32, 5);
    assert_eq!(binary::MAX_VARINT_LEN64, 10);
}

#[test]
fn varint_overflow_truncation_and_nonminimal() {
    for bytes in [
        vec![],
        vec![128],
        vec![255; 9],
        vec![255; 10],
        vec![255, 255, 255, 255, 255, 255, 255, 255, 255, 2],
        vec![128; 11],
    ] {
        assert!(binary::uvarint(&bytes).is_err());
        assert!(binary::read_uvarint(&mut &bytes[..]).is_err());
    }
    assert_eq!(binary::uvarint(&[128, 0]).unwrap(), (0, 2));
    let mut output = [42u8; 1];
    assert!(binary::put_uvarint(&mut output, 128).is_err());
    assert_eq!(output, [42]);
}

#[test]
fn byte_orders_known_values_names_and_short_buffers() {
    let bytes = [0x12, 0x34, 0x56, 0x78];
    assert_eq!(BIG_ENDIAN.uint32(&bytes), 0x12345678);
    assert_eq!(LITTLE_ENDIAN.uint32(&bytes), 0x78563412);
    assert_eq!(NATIVE_ENDIAN.uint32(&bytes), u32::from_ne_bytes(bytes));
    let mut out = [0u8; 4];
    BIG_ENDIAN.put_uint32(&mut out, 0x12345678);
    assert_eq!(out, bytes);
    let mut appended = vec![0xff];
    LITTLE_ENDIAN.append_uint16(&mut appended, 0x1234);
    assert_eq!(appended, [0xff, 0x34, 0x12]);
    assert_eq!(
        [
            BIG_ENDIAN.to_string(),
            LITTLE_ENDIAN.to_string(),
            NATIVE_ENDIAN.to_string()
        ],
        ["BigEndian", "LittleEndian", "NativeEndian"]
    );
    assert_eq!(BIG_ENDIAN.to_string(), "BigEndian");
    assert!(binary::encode(&mut out[..3], &BIG_ENDIAN, &0x12345678u32).is_err());
}

struct Short {
    bytes: Vec<u8>,
    position: usize,
}
impl Write for Short {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        self.bytes.push(bytes[0]);
        Ok(1)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Read for Short {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() || self.position == self.bytes.len() {
            return Ok(0);
        }
        bytes[0] = self.bytes[self.position];
        self.position += 1;
        Ok(1)
    }
}

#[test]
fn read_write_handle_partial_operations_and_exact_float_bits() {
    let mut io = Short {
        bytes: vec![],
        position: 0,
    };
    for order in [&LITTLE_ENDIAN as &dyn ByteOrder, &BIG_ENDIAN] {
        binary::write(&mut io, order, &-7i16).unwrap();
        binary::write(&mut io, order, &u64::MAX).unwrap();
        binary::write(&mut io, order, &f64::from_bits(0x7ff8000000000123)).unwrap();
        binary::write(&mut io, order, &-0.0f32).unwrap();
        binary::write(&mut io, order, &true).unwrap();
        binary::write(&mut io, order, &[1u32, 2, 3][..]).unwrap();
        binary::write(&mut io, order, &[[9i8, -9], [1, 2]]).unwrap();
        binary::write(&mut io, order, &i64::MIN).unwrap();
    }
    for order in [&LITTLE_ENDIAN as &dyn ByteOrder, &BIG_ENDIAN] {
        let mut signed = 0i16;
        binary::read(&mut io, order, &mut signed).unwrap();
        assert_eq!(signed, -7);
        let mut unsigned = 0u64;
        binary::read(&mut io, order, &mut unsigned).unwrap();
        assert_eq!(unsigned, u64::MAX);
        let mut float = 0f64;
        binary::read(&mut io, order, &mut float).unwrap();
        assert_eq!(float.to_bits(), 0x7ff8000000000123);
        let mut negative_zero = 0f32;
        binary::read(&mut io, order, &mut negative_zero).unwrap();
        assert_eq!(negative_zero.to_bits(), (-0.0f32).to_bits());
        let mut flag = false;
        binary::read(&mut io, order, &mut flag).unwrap();
        assert!(flag);
        let mut words = [0u32; 3];
        binary::read(&mut io, order, &mut words[..]).unwrap();
        assert_eq!(words, [1, 2, 3]);
        let mut pairs = [[0i8; 2]; 2];
        binary::read(&mut io, order, &mut pairs).unwrap();
        assert_eq!(pairs, [[9, -9], [1, 2]]);
        let mut minimum = 0i64;
        binary::read(&mut io, order, &mut minimum).unwrap();
        assert_eq!(minimum, i64::MIN);
    }
    let mut extra = 0u8;
    assert!(binary::read(&mut io, &BIG_ENDIAN, &mut extra).is_err());
}

#[test]
fn size_encode_decode_and_append_match_go_sizes() {
    assert_eq!(binary::size(&0u8), 1);
    assert_eq!(binary::size(&0i16), 2);
    assert_eq!(binary::size(&0f32), 4);
    assert_eq!(binary::size(&[0u64; 3]), 24);
    assert_eq!(binary::size(&[0u16; 0][..]), 0);

    let mut buf = [0u8; 8];
    assert_eq!(
        binary::encode(&mut buf, &BIG_ENDIAN, &0x0102u16).unwrap(),
        2
    );
    assert_eq!(&buf[..2], [1, 2]);
    let mut value = 0u16;
    assert_eq!(binary::decode(&buf, &LITTLE_ENDIAN, &mut value).unwrap(), 2);
    assert_eq!(value, 0x0201);
    assert!(binary::decode(&buf[..1], &BIG_ENDIAN, &mut value).is_err());

    let mut out = vec![0xaa];
    binary::append(&mut out, &BIG_ENDIAN, &0x01020304u32);
    assert_eq!(out, [0xaa, 1, 2, 3, 4]);
    binary::append(&mut out, &BIG_ENDIAN, &true);
    assert_eq!(out, [0xaa, 1, 2, 3, 4, 1]);
}
