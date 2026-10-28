//! Go's `encoding/binary`: byte orders, fixed-size values and base-128 varints.
//! Byte orders are the `ByteOrder` and `AppendByteOrder` traits, implemented by
//! `BigEndian`, `LittleEndian` and `NativeEndian`. Go's reflection over
//! fixed-size data becomes the `FixedSize` trait, with `read`, `write`, `size`,
//! `encode`, `decode` and `append` as free functions over it. Varints accept
//! non-minimal encodings, as Go does; overflow and truncation are errors.
//! Reference: <https://pkg.go.dev/encoding/binary>
use std::fmt;
use std::io::{self, Read, Write};

/// Go's `ByteOrder`: converts between 16, 32 and 64-bit integers and bytes.
/// Short slices panic, as Go's do.
pub trait ByteOrder: fmt::Display {
    fn uint16(&self, b: &[u8]) -> u16;
    fn uint32(&self, b: &[u8]) -> u32;
    fn uint64(&self, b: &[u8]) -> u64;
    fn put_uint16(&self, b: &mut [u8], v: u16);
    fn put_uint32(&self, b: &mut [u8], v: u32);
    fn put_uint64(&self, b: &mut [u8], v: u64);
}

/// Go's `AppendByteOrder`: appends 16, 32 and 64-bit integers to a `Vec`.
pub trait AppendByteOrder: fmt::Display {
    fn append_uint16(&self, b: &mut Vec<u8>, v: u16);
    fn append_uint32(&self, b: &mut Vec<u8>, v: u32);
    fn append_uint64(&self, b: &mut Vec<u8>, v: u64);
}

/// Go's `BigEndian`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BigEndian;
/// Go's `LittleEndian`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LittleEndian;
/// Go's `NativeEndian`: the byte order of the target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeEndian;

pub const BIG_ENDIAN: BigEndian = BigEndian;
pub const LITTLE_ENDIAN: LittleEndian = LittleEndian;
pub const NATIVE_ENDIAN: NativeEndian = NativeEndian;

fn array<const N: usize>(b: &[u8]) -> [u8; N] {
    let mut out = [0; N];
    out.copy_from_slice(&b[..N]);
    out
}

macro_rules! byte_order {
    ($ty:ident, $name:literal, $from:ident, $to:ident) => {
        impl ByteOrder for $ty {
            fn uint16(&self, b: &[u8]) -> u16 {
                u16::$from(array(b))
            }
            fn uint32(&self, b: &[u8]) -> u32 {
                u32::$from(array(b))
            }
            fn uint64(&self, b: &[u8]) -> u64 {
                u64::$from(array(b))
            }
            fn put_uint16(&self, b: &mut [u8], v: u16) {
                b[..2].copy_from_slice(&v.$to());
            }
            fn put_uint32(&self, b: &mut [u8], v: u32) {
                b[..4].copy_from_slice(&v.$to());
            }
            fn put_uint64(&self, b: &mut [u8], v: u64) {
                b[..8].copy_from_slice(&v.$to());
            }
        }
        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($name)
            }
        }
        impl AppendByteOrder for $ty {
            fn append_uint16(&self, b: &mut Vec<u8>, v: u16) {
                b.extend_from_slice(&v.$to());
            }
            fn append_uint32(&self, b: &mut Vec<u8>, v: u32) {
                b.extend_from_slice(&v.$to());
            }
            fn append_uint64(&self, b: &mut Vec<u8>, v: u64) {
                b.extend_from_slice(&v.$to());
            }
        }
    };
}
byte_order!(BigEndian, "BigEndian", from_be_bytes, to_be_bytes);
byte_order!(LittleEndian, "LittleEndian", from_le_bytes, to_le_bytes);
byte_order!(NativeEndian, "NativeEndian", from_ne_bytes, to_ne_bytes);

/// A fixed-size value that the free functions in this module encode and decode.
/// Go accepts such values through reflection; Rust names them with this trait,
/// so unsupported types fail to compile instead of returning an error.
pub trait FixedSize {
    /// Encoded size in bytes.
    fn size(&self) -> usize;
    /// Encodes into `out`, which holds at least `size()` bytes.
    fn encode_into(&self, order: &dyn ByteOrder, out: &mut [u8]);
    /// Decodes from `src`, which holds at least `size()` bytes.
    fn decode_from(&mut self, order: &dyn ByteOrder, src: &[u8]);
}

macro_rules! fixed_byte {
    ($($ty:ty),*) => {$(
        impl FixedSize for $ty {
            fn size(&self) -> usize {
                1
            }
            fn encode_into(&self, _: &dyn ByteOrder, out: &mut [u8]) {
                out[0] = *self as u8;
            }
            fn decode_from(&mut self, _: &dyn ByteOrder, src: &[u8]) {
                *self = src[0] as $ty;
            }
        }
    )*};
}
fixed_byte!(u8, i8);

macro_rules! fixed_int {
    ($ty:ty, $n:expr, $put:ident, $get:ident, $unsigned:ty) => {
        impl FixedSize for $ty {
            fn size(&self) -> usize {
                $n
            }
            fn encode_into(&self, order: &dyn ByteOrder, out: &mut [u8]) {
                order.$put(out, *self as $unsigned);
            }
            fn decode_from(&mut self, order: &dyn ByteOrder, src: &[u8]) {
                *self = order.$get(src) as $ty;
            }
        }
    };
}
fixed_int!(u16, 2, put_uint16, uint16, u16);
fixed_int!(i16, 2, put_uint16, uint16, u16);
fixed_int!(u32, 4, put_uint32, uint32, u32);
fixed_int!(i32, 4, put_uint32, uint32, u32);
fixed_int!(u64, 8, put_uint64, uint64, u64);
fixed_int!(i64, 8, put_uint64, uint64, u64);

impl FixedSize for bool {
    fn size(&self) -> usize {
        1
    }
    fn encode_into(&self, _: &dyn ByteOrder, out: &mut [u8]) {
        out[0] = u8::from(*self);
    }
    fn decode_from(&mut self, _: &dyn ByteOrder, src: &[u8]) {
        *self = src[0] != 0;
    }
}

impl FixedSize for f32 {
    fn size(&self) -> usize {
        4
    }
    fn encode_into(&self, order: &dyn ByteOrder, out: &mut [u8]) {
        order.put_uint32(out, self.to_bits());
    }
    fn decode_from(&mut self, order: &dyn ByteOrder, src: &[u8]) {
        *self = f32::from_bits(order.uint32(src));
    }
}

impl FixedSize for f64 {
    fn size(&self) -> usize {
        8
    }
    fn encode_into(&self, order: &dyn ByteOrder, out: &mut [u8]) {
        order.put_uint64(out, self.to_bits());
    }
    fn decode_from(&mut self, order: &dyn ByteOrder, src: &[u8]) {
        *self = f64::from_bits(order.uint64(src));
    }
}

/// Slices of fixed-size values, as Go's `Read` and `Write` accept.
impl<T: FixedSize> FixedSize for [T] {
    fn size(&self) -> usize {
        self.iter().map(FixedSize::size).sum()
    }
    fn encode_into(&self, order: &dyn ByteOrder, out: &mut [u8]) {
        let mut at = 0;
        for value in self {
            let n = value.size();
            value.encode_into(order, &mut out[at..at + n]);
            at += n;
        }
    }
    fn decode_from(&mut self, order: &dyn ByteOrder, src: &[u8]) {
        let mut at = 0;
        for value in self {
            let n = value.size();
            value.decode_from(order, &src[at..at + n]);
            at += n;
        }
    }
}

impl<T: FixedSize, const N: usize> FixedSize for [T; N] {
    fn size(&self) -> usize {
        self[..].size()
    }
    fn encode_into(&self, order: &dyn ByteOrder, out: &mut [u8]) {
        self[..].encode_into(order, out);
    }
    fn decode_from(&mut self, order: &dyn ByteOrder, src: &[u8]) {
        self[..].decode_from(order, src);
    }
}

fn buffer_too_small() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "buffer too small")
}

fn overflow() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "binary: varint overflows a 64-bit integer",
    )
}

/// Go's `Size`: the encoded size of a fixed-size value or slice.
pub fn size<T: FixedSize + ?Sized>(data: &T) -> usize {
    data.size()
}

/// Go's `io.ReadFull`: [`crate::io::Error::Eof`] if nothing could be read and
/// [`crate::io::Error::UnexpectedEof`] if the input ended part way.
fn read_full<R: Read + ?Sized>(r: &mut R, buf: &mut [u8]) -> io::Result<()> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) if n == 0 => return Err(crate::io::Error::Eof.into()),
            Ok(0) => return Err(crate::io::Error::UnexpectedEof.into()),
            Ok(m) => n += m,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Go's `Read`: reads exactly `size(data)` bytes and decodes them into `data`.
pub fn read<R: Read + ?Sized, T: FixedSize + ?Sized>(
    r: &mut R,
    order: &dyn ByteOrder,
    data: &mut T,
) -> io::Result<()> {
    let mut buf = vec![0; data.size()];
    read_full(r, &mut buf)?;
    data.decode_from(order, &buf);
    Ok(())
}

/// Go's `Write`: encodes `data` and writes all of it.
pub fn write<W: Write + ?Sized, T: FixedSize + ?Sized>(
    w: &mut W,
    order: &dyn ByteOrder,
    data: &T,
) -> io::Result<()> {
    let mut buf = vec![0; data.size()];
    data.encode_into(order, &mut buf);
    w.write_all(&buf)
}

/// Go's `Encode`: encodes `data` into `buf` and returns the bytes written.
pub fn encode<T: FixedSize + ?Sized>(
    buf: &mut [u8],
    order: &dyn ByteOrder,
    data: &T,
) -> io::Result<usize> {
    let n = data.size();
    if buf.len() < n {
        return Err(buffer_too_small());
    }
    data.encode_into(order, &mut buf[..n]);
    Ok(n)
}

/// Go's `Decode`: decodes `data` from the start of `buf` and returns the bytes consumed.
pub fn decode<T: FixedSize + ?Sized>(
    buf: &[u8],
    order: &dyn ByteOrder,
    data: &mut T,
) -> io::Result<usize> {
    let n = data.size();
    if buf.len() < n {
        return Err(buffer_too_small());
    }
    data.decode_from(order, &buf[..n]);
    Ok(n)
}

/// Go's `Append`: appends the encoding of `data` to `buf`.
pub fn append<T: FixedSize + ?Sized>(buf: &mut Vec<u8>, order: &dyn ByteOrder, data: &T) {
    let start = buf.len();
    buf.resize(start + data.size(), 0);
    data.encode_into(order, &mut buf[start..]);
}

/// Largest varint length for a 16-bit value.
pub const MAX_VARINT_LEN16: usize = 3;
/// Largest varint length for a 32-bit value.
pub const MAX_VARINT_LEN32: usize = 5;
/// Largest varint length for a 64-bit value.
pub const MAX_VARINT_LEN64: usize = 10;

fn unsigned_bytes(mut value: u64) -> ([u8; MAX_VARINT_LEN64], usize) {
    let mut b = [0u8; MAX_VARINT_LEN64];
    let mut n = 0;
    while value >= 128 {
        b[n] = (value as u8) | 128;
        value >>= 7;
        n += 1
    }
    b[n] = value as u8;
    (b, n + 1)
}

fn zigzag(value: i64) -> u64 {
    ((value as u64) << 1) ^ ((value >> 63) as u64)
}

fn unzigzag(value: u64) -> i64 {
    ((value >> 1) as i64) ^ -((value & 1) as i64)
}

/// Go's `PutUvarint`. Returns an error instead of panicking when `buf` is short.
pub fn put_uvarint(buf: &mut [u8], x: u64) -> io::Result<usize> {
    let (b, n) = unsigned_bytes(x);
    if buf.len() < n {
        return Err(buffer_too_small());
    }
    buf[..n].copy_from_slice(&b[..n]);
    Ok(n)
}

/// Go's `PutVarint`: zigzag-encodes `x`. Returns an error when `buf` is short.
pub fn put_varint(buf: &mut [u8], x: i64) -> io::Result<usize> {
    put_uvarint(buf, zigzag(x))
}

/// Go's `AppendUvarint`.
pub fn append_uvarint(buf: &mut Vec<u8>, x: u64) {
    let (b, n) = unsigned_bytes(x);
    buf.extend_from_slice(&b[..n]);
}

/// Go's `AppendVarint`.
pub fn append_varint(buf: &mut Vec<u8>, x: i64) {
    append_uvarint(buf, zigzag(x));
}

/// Go's `Uvarint`: decodes a varint from the start of `buf` and returns it with
/// its length. Truncated input is `UnexpectedEof`; overflow is `InvalidData`.
pub fn uvarint(buf: &[u8]) -> io::Result<(u64, usize)> {
    let mut x = 0u64;
    let mut s = 0;
    for (i, &b) in buf.iter().enumerate() {
        if i == MAX_VARINT_LEN64 {
            return Err(overflow());
        }
        if b < 0x80 {
            if i == MAX_VARINT_LEN64 - 1 && b > 1 {
                return Err(overflow());
            }
            return Ok((x | u64::from(b) << s, i + 1));
        }
        x |= u64::from(b & 0x7f) << s;
        s += 7;
    }
    Err(buffer_too_small())
}

/// Go's `Varint`: decodes a zigzag varint from the start of `buf`.
pub fn varint(buf: &[u8]) -> io::Result<(i64, usize)> {
    uvarint(buf).map(|(v, n)| (unzigzag(v), n))
}

/// Go's `ReadUvarint`. Running out of input before the first byte is
/// [`crate::io::Error::Eof`] and after it [`crate::io::Error::UnexpectedEof`];
/// both have kind `UnexpectedEof`.
pub fn read_uvarint<R: Read + ?Sized>(r: &mut R) -> io::Result<u64> {
    let mut x = 0u64;
    let mut s = 0;
    for i in 0..MAX_VARINT_LEN64 {
        let mut b = [0u8; 1];
        read_full(r, &mut b).map_err(|e| {
            if i > 0 && crate::io::is_eof(&e) {
                crate::io::Error::UnexpectedEof.into()
            } else {
                e
            }
        })?;
        if b[0] < 0x80 {
            if i == MAX_VARINT_LEN64 - 1 && b[0] > 1 {
                return Err(overflow());
            }
            return Ok(x | u64::from(b[0]) << s);
        }
        x |= u64::from(b[0] & 0x7f) << s;
        s += 7;
    }
    Err(overflow())
}

/// Go's `ReadVarint`: reads a zigzag varint.
pub fn read_varint<R: Read + ?Sized>(r: &mut R) -> io::Result<i64> {
    read_uvarint(r).map(unzigzag)
}
