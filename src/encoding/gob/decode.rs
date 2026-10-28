//! The decoder: Go's `decoder.go` and `decode.go`.
//!
//! Like Go, decoding first compiles, for each (local type, remote type id)
//! pair, an engine that checks the two are compatible and says what to do
//! with every remote field; only then is data consumed.

use std::collections::HashMap;
use std::io::{self, Read};
use std::sync::{Arc, Mutex, OnceLock};

use crate::reflect::{self, Kind, Reflect, Type, Value};
use crate::strconv::Complex;

use super::encode::{error_text, TOO_BIG};
use super::types::{
    errorf, is_exported, lock, name_to_concrete_type, plain, table, user_type, GKind, UserTypeInfo,
    FIRST_USER_ID, T_BOOL, T_BYTES, T_COMPLEX, T_FLOAT, T_INT, T_INTERFACE, T_STRING, T_UINT,
    T_WIRE_TYPE, X_BINARY, X_GOB, X_TEXT,
};
use super::wire::{self, WireType};

/// Go `saferio` chunk: allocations driven by untrusted lengths stay below it
/// until the data actually arrives.
const CHUNK: u64 = 10 << 20;

const MAX_IGNORE_NESTING_DEPTH: usize = 10000;

fn err_bad_uint() -> io::Error {
    plain("gob: encoded unsigned integer out of range")
}

fn err_range() -> io::Error {
    plain("gob: bad data: field numbers out of bounds")
}

fn overflow(name: &str) -> String {
    name.to_string()
}

fn ovfl_error(name: &str) -> io::Error {
    plain(format!("value for \"{name}\" out of range"))
}

/// The first `n` runes of `b`, counting each invalid byte as one (`%.20q`).
fn truncate_runes(b: &[u8], n: usize) -> &[u8] {
    let (mut i, mut count) = (0, 0);
    while i < b.len() && count < n {
        let end = (i + 4).min(b.len());
        let width = match std::str::from_utf8(&b[i..end]) {
            Ok(s) => s.chars().next().map_or(1, char::len_utf8),
            Err(e) if e.valid_up_to() > 0 => std::str::from_utf8(&b[i..i + e.valid_up_to()])
                .ok()
                .and_then(|s| s.chars().next())
                .map_or(1, char::len_utf8),
            Err(_) => 1,
        };
        i += width;
        count += 1;
    }
    &b[..i]
}

/// Go `saferio.SliceCapWithSize`.
fn slice_cap_with_size(size: u64, c: u64) -> i64 {
    if (c as i64) < 0 {
        return -1;
    }
    if size > 0 && c > u64::MAX / size {
        return -1;
    }
    let mut c = c;
    if c.saturating_mul(size) > CHUNK {
        c = CHUNK / size;
        if c == 0 {
            c = 1;
        }
    }
    c as i64
}

/// Go `decBuffer`.
#[derive(Default)]
struct DecBuf {
    data: Vec<u8>,
    off: usize,
}

impl DecBuf {
    fn len(&self) -> usize {
        self.data.len() - self.off
    }

    fn bytes(&self) -> &[u8] {
        &self.data[self.off..]
    }

    fn drop_n(&mut self, n: usize) {
        self.off += n;
    }

    fn reset(&mut self) {
        self.data.clear();
        self.off = 0;
    }
}

type EnginePtr = Arc<OnceLock<Arc<DecEngine>>>;
type OpRef = Arc<OpCell>;

struct OpCell(OnceLock<Op>);

impl OpCell {
    fn new() -> OpRef {
        Arc::new(OpCell(OnceLock::new()))
    }

    fn with(op: Op) -> OpRef {
        let c = OpCell::new();
        let _ = c.0.set(op);
        c
    }
}

/// How many elements an array or slice helper handles; Go has per-kind
/// helpers with their own error texts.
type Helper = Option<&'static str>;

enum Op {
    Bool,
    Int8,
    Int16,
    Int32,
    Int64,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Float32,
    Float64,
    Complex64,
    Complex128,
    Str,
    Bytes,
    Array {
        elem: OpRef,
        len: usize,
        ovfl: String,
        helper: Helper,
    },
    Map {
        typ: Type,
        key: OpRef,
        elem: OpRef,
        ovfl: String,
    },
    Slice {
        elem: OpRef,
        ovfl: String,
        helper: Helper,
    },
    Struct {
        engine: EnginePtr,
    },
    Interface {
        typ: Type,
    },
    GobDecoder {
        ut: Arc<UserTypeInfo>,
        rcvr_is_ptr: bool,
    },
    IgnoreUint,
    IgnoreTwoUints,
    IgnoreBytes,
    IgnoreInterface,
    IgnoreArray {
        elem: OpRef,
        len: usize,
    },
    IgnoreMap {
        key: OpRef,
        elem: OpRef,
    },
    IgnoreSlice {
        elem: OpRef,
    },
    IgnoreStruct {
        engine: EnginePtr,
    },
    IgnoreGobDecoder,
}

struct DecInstr {
    op: OpRef,
    index: Option<Vec<usize>>,
    ovfl: String,
}

struct DecEngine {
    instr: Vec<DecInstr>,
    num_instr: usize,
}

fn helper_for(kind: Kind) -> Helper {
    match kind {
        Kind::Bool
        | Kind::Complex64
        | Kind::Complex128
        | Kind::Float32
        | Kind::Float64
        | Kind::Int
        | Kind::Int8
        | Kind::Int16
        | Kind::Int32
        | Kind::Int64
        | Kind::String
        | Kind::Uint
        | Kind::Uint8
        | Kind::Uint16
        | Kind::Uint32
        | Kind::Uint64
        | Kind::Uintptr => Some(kind.name()),
        _ => None,
    }
}

/// Go `decAlloc`: a settable value that can be assigned to; if the value is a
/// pointer, it is guaranteed to point to storage.
fn dec_alloc(v: &Value) -> Value {
    let mut v = v.clone();
    while v.kind() == Kind::Pointer {
        if v.is_nil() {
            v.set(&reflect::new(&v.type_().elem()));
        }
        v = v.elem();
    }
    v
}

fn float64_from_bits(u: u64) -> f64 {
    f64::from_bits(u.swap_bytes())
}

fn float32_from_bits(u: u64, name: &str) -> io::Result<f64> {
    let v = float64_from_bits(u);
    let av = v.abs();
    // +Inf is OK in both 32- and 64-bit floats. Underflow is always OK.
    if av > f32::MAX as f64 && av <= f64::MAX {
        return Err(ovfl_error(name));
    }
    Ok(v)
}

/// The decoder's mutable state; every decode runs under its lock.
struct DecCore {
    r: Box<dyn Read + Send>,
    buf: DecBuf,
    wire_type: HashMap<i32, Arc<WireType>>,
    decoder_cache: HashMap<Type, HashMap<i32, EnginePtr>>,
    ignorer_cache: HashMap<i32, EnginePtr>,
    ignore_depth: usize,
    /// Go `Decoder.err`: Go records the first failure of the type sequence
    /// here, and later steps look at it.
    err: Option<io::Error>,
}

/// A `Decoder` manages the receipt of type and data information read from
/// the remote side of a connection (Go `gob.Decoder`). It is safe for
/// concurrent use by multiple threads.
///
/// The Decoder does only basic sanity checking on decoded input sizes, and
/// its limits are not configurable. Take caution when decoding gob data from
/// untrusted sources.
pub struct Decoder {
    core: Mutex<DecCore>,
}

impl Decoder {
    /// Go `NewDecoder`: a decoder that reads from `r`. The reader is
    /// buffered, so it may be read ahead of the values decoded; use
    /// [`Decoder::from_byte_reader`] when it must not be.
    pub fn new<R: Read + Send + 'static>(r: R) -> Decoder {
        Decoder::from_byte_reader(io::BufReader::new(r))
    }

    /// Go `NewDecoder` for a reader that is its own buffer (Go's test for
    /// `io.ByteReader`): it is not wrapped, and the decoder reads exactly the
    /// bytes of the messages it decodes (a byte at a time for each message's
    /// length), so decoders created one after another on a shared reader see
    /// the rest of the input.
    pub fn from_byte_reader<R: Read + Send + 'static>(r: R) -> Decoder {
        Decoder {
            core: Mutex::new(DecCore {
                r: Box::new(r),
                buf: DecBuf::default(),
                wire_type: HashMap::new(),
                decoder_cache: HashMap::new(),
                ignorer_cache: HashMap::new(),
                ignore_depth: 0,
                err: None,
            }),
        }
    }

    /// Go `Decoder.Decode`: reads the next value from the input stream and
    /// stores it in `e`. If the input is at EOF, Decode returns the `io.EOF`
    /// error (see [`crate::io::is_eof`]) and does not modify `e`.
    pub fn decode<T: Reflect>(&self, e: &mut T) -> io::Result<()> {
        let mut result = Ok(());
        reflect::edit(e, |p| {
            result = self.decode_value(p);
        })
        .map_err(|err| plain(err.to_string()))?;
        result
    }

    /// Go `Decoder.Decode(nil)`: reads the next value and discards it.
    pub fn decode_discard(&self) -> io::Result<()> {
        self.decode_value(&Value::default())
    }

    /// Go `Decoder.DecodeValue`: reads the next value from the input stream.
    /// If `v` is the invalid value, the value is discarded. Otherwise it is
    /// stored into `v`, which must represent a non-nil pointer to data or be
    /// an assignable value (`can_set`). If the input is at EOF, DecodeValue
    /// returns the `io.EOF` error and does not modify `v`.
    pub fn decode_value(&self, v: &Value) -> io::Result<()> {
        if v.is_valid() && !(v.kind() == Kind::Pointer && !v.is_nil()) && !v.can_set() {
            return Err(plain("gob: DecodeValue of unassignable value"));
        }
        let mut core = lock(&self.core);
        // In case data lingers from previous invocation.
        core.buf.reset();
        core.err = None;
        let id = core.decode_type_sequence(false);
        if core.err.is_none() {
            // A failure is left in `err`, as Go's decodeValue does.
            if let Err(e) = core.decode_value_inner(id, v) {
                core.err = Some(e);
            }
        }
        match core.err.take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl DecCore {
    // ---- reading the stream ----

    /// Go `decodeUintReader`: the message length is read straight from the
    /// reader.
    fn read_uint(&mut self) -> io::Result<u64> {
        let mut first = [0u8; 1];
        loop {
            match self.r.read(&mut first) {
                Ok(0) => return Err(crate::io::eof()),
                Ok(_) => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        let b = first[0];
        if b <= 0x7f {
            return Ok(b as u64);
        }
        let n = -(b as i8 as i32);
        if n > 8 {
            return Err(err_bad_uint());
        }
        let mut buf = [0u8; 8];
        self.read_full(&mut buf[..n as usize])?;
        Ok(buf[..n as usize]
            .iter()
            .fold(0u64, |x, &b| (x << 8) | b as u64))
    }

    fn read_full(&mut self, buf: &mut [u8]) -> io::Result<()> {
        match self.r.read_exact(buf) {
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                Err(crate::io::Error::UnexpectedEof.into())
            }
            r => r,
        }
    }

    /// Go `recvMessage`: reads the next count-delimited item from the input.
    /// It returns false on EOF or other error reading the message.
    fn recv_message(&mut self) -> bool {
        let r = self.read_uint().and_then(|nbytes| {
            if nbytes >= TOO_BIG {
                return Err(plain("invalid message length"));
            }
            self.read_message(nbytes)
        });
        match r {
            Ok(()) => self.err.is_none(),
            Err(e) => {
                self.err = Some(e);
                false
            }
        }
    }

    /// Go `readMessage`, reading in bounded chunks as `saferio.ReadData`.
    fn read_message(&mut self, nbytes: u64) -> io::Result<()> {
        let mut data = Vec::new();
        let mut left = nbytes;
        while left > 0 {
            let next = left.min(CHUNK) as usize;
            let start = data.len();
            data.resize(start + next, 0);
            self.read_full(&mut data[start..])?;
            left -= next as u64;
        }
        self.buf.data = data;
        self.buf.off = 0;
        Ok(())
    }

    /// Go `decodeUint` on the message buffer.
    fn decode_uint(&mut self) -> io::Result<u64> {
        let Some(&b) = self.buf.bytes().first() else {
            return Err(crate::io::eof());
        };
        self.buf.drop_n(1);
        if b <= 0x7f {
            return Ok(b as u64);
        }
        let n = -(b as i8 as i32);
        if n > 8 {
            return Err(err_bad_uint());
        }
        let n = n as usize;
        let rest = self.buf.bytes();
        if rest.len() < n {
            return Err(errorf(format!(
                "invalid uint data length {}: exceeds input size {}",
                n,
                rest.len()
            )));
        }
        let x = rest[..n].iter().fold(0u64, |x, &b| (x << 8) | b as u64);
        self.buf.drop_n(n);
        Ok(x)
    }

    /// Go `Decoder.nextUint`: like `decodeUintReader` on the message buffer,
    /// so a short buffer is `io.ErrUnexpectedEOF`. A failure is recorded in
    /// `err` and zero is returned.
    fn next_uint(&mut self) -> u64 {
        match self.next_uint_result() {
            Ok(x) => x,
            Err(e) => {
                self.err = Some(e);
                0
            }
        }
    }

    fn next_uint_result(&mut self) -> io::Result<u64> {
        let Some(&b) = self.buf.bytes().first() else {
            return Err(crate::io::eof());
        };
        self.buf.drop_n(1);
        if b <= 0x7f {
            return Ok(b as u64);
        }
        let n = -(b as i8 as i32);
        if n > 8 {
            return Err(err_bad_uint());
        }
        let n = n as usize;
        let rest = self.buf.bytes();
        if rest.len() < n {
            self.buf.drop_n(rest.len());
            return Err(crate::io::Error::UnexpectedEof.into());
        }
        let x = rest[..n].iter().fold(0u64, |x, &b| (x << 8) | b as u64);
        self.buf.drop_n(n);
        Ok(x)
    }

    /// Go `Decoder.nextInt`.
    fn next_int(&mut self) -> i64 {
        let x = self.next_uint();
        if x & 1 != 0 {
            !((x >> 1) as i64)
        } else {
            (x >> 1) as i64
        }
    }

    /// Go `decodeInt`.
    fn decode_int(&mut self) -> io::Result<i64> {
        let x = self.decode_uint()?;
        Ok(if x & 1 != 0 {
            !((x >> 1) as i64)
        } else {
            (x >> 1) as i64
        })
    }

    /// Go `getLength`: the next uint, if it is a possible size for a data
    /// item that follows.
    fn get_length(&mut self) -> io::Result<Option<usize>> {
        let n = self.decode_uint()?;
        if (n as i64) < 0 || (self.buf.len() as u64) < n || TOO_BIG <= n {
            return Ok(None);
        }
        Ok(Some(n as usize))
    }

    /// Go `recvType`: loads the definition of a type.
    fn recv_type(&mut self, id: i32) {
        if id < FIRST_USER_ID || self.wire_type.contains_key(&id) {
            self.err = Some(plain("gob: duplicate type received"));
            return;
        }
        let wt = wire::types();
        let p = reflect::new(&wt.wire_type);
        if let Err(e) = self.decode_value_inner(T_WIRE_TYPE, &p) {
            self.err = Some(e);
        }
        if self.err.is_some() {
            return;
        }
        // Remember we've seen this type.
        self.wire_type
            .insert(id, Arc::new(wire::from_value(&p.elem())));
    }

    /// Go `decodeTypeSequence`: parses any type definitions that precede a
    /// value and returns the type id of the next value, or -1 at EOF or on an
    /// error (left in `err`). Like Go, a failure to read the id itself is left
    /// in `err` and yields id 0.
    fn decode_type_sequence(&mut self, is_interface: bool) -> i32 {
        let mut first_message = true;
        while self.err.is_none() {
            if self.buf.len() == 0 && !self.recv_message() {
                // We can only return io.EOF if the input was empty. If we read
                // one or more type spec messages, require a data item message
                // to follow.
                if !first_message && self.err.as_ref().is_some_and(crate::io::is_eof) {
                    self.err = Some(crate::io::Error::UnexpectedEof.into());
                }
                break;
            }
            // Receive a type id.
            let id = self.next_int() as i32;
            if id >= 0 {
                // Value follows.
                return id;
            }
            // Type definition for (-id) follows.
            self.recv_type(id.wrapping_neg());
            if self.err.is_some() {
                break;
            }
            // When decoding an interface, after a type there may be a
            // DelimitedValue still in the buffer. Skip its count.
            if self.buf.len() > 0 {
                if !is_interface {
                    self.err = Some(plain("extra data in buffer"));
                    break;
                }
                self.next_uint();
            }
            first_message = false;
        }
        -1
    }

    // ---- executing ops ----

    fn exec(&mut self, op: &OpRef, ovfl: &str, value: &Value) -> io::Result<()> {
        let Some(op) = op.0.get() else {
            return Err(errorf("decoder op not compiled"));
        };
        match op {
            Op::Bool => {
                let u = self.decode_uint()?;
                value.set_bool(u != 0);
            }
            Op::Int8 => {
                let v = self.decode_int()?;
                if v < i8::MIN as i64 || v > i8::MAX as i64 {
                    return Err(ovfl_error(ovfl));
                }
                value.set_int(v);
            }
            Op::Int16 => {
                let v = self.decode_int()?;
                if v < i16::MIN as i64 || v > i16::MAX as i64 {
                    return Err(ovfl_error(ovfl));
                }
                value.set_int(v);
            }
            Op::Int32 => {
                let v = self.decode_int()?;
                if v < i32::MIN as i64 || v > i32::MAX as i64 {
                    return Err(ovfl_error(ovfl));
                }
                value.set_int(v);
            }
            Op::Int64 => {
                let v = self.decode_int()?;
                value.set_int(v);
            }
            Op::Uint8 => {
                let v = self.decode_uint()?;
                if v > u8::MAX as u64 {
                    return Err(ovfl_error(ovfl));
                }
                value.set_uint(v);
            }
            Op::Uint16 => {
                let v = self.decode_uint()?;
                if v > u16::MAX as u64 {
                    return Err(ovfl_error(ovfl));
                }
                value.set_uint(v);
            }
            Op::Uint32 => {
                let v = self.decode_uint()?;
                if v > u32::MAX as u64 {
                    return Err(ovfl_error(ovfl));
                }
                value.set_uint(v);
            }
            Op::Uint64 => {
                let v = self.decode_uint()?;
                value.set_uint(v);
            }
            Op::Float32 => {
                let u = self.decode_uint()?;
                value.set_float(float32_from_bits(u, ovfl)?);
            }
            Op::Float64 => {
                let u = self.decode_uint()?;
                value.set_float(float64_from_bits(u));
            }
            Op::Complex64 => {
                let re = float32_from_bits(self.decode_uint()?, ovfl)?;
                let im = float32_from_bits(self.decode_uint()?, ovfl)?;
                value.set_complex(Complex { re, im });
            }
            Op::Complex128 => {
                let re = float64_from_bits(self.decode_uint()?);
                let im = float64_from_bits(self.decode_uint()?);
                value.set_complex(Complex { re, im });
            }
            Op::Str => {
                let Some(n) = self.get_length()? else {
                    return Err(errorf(format!("bad {} slice length: 0", value.type_())));
                };
                let data = self.buf.bytes();
                if data.len() < n {
                    return Err(errorf(format!(
                        "invalid string length {}: exceeds input size {}",
                        n,
                        data.len()
                    )));
                }
                let s = data[..n].to_vec();
                self.buf.drop_n(n);
                value.set_string(s);
            }
            Op::Bytes => {
                let Some(n) = self.get_length()? else {
                    return Err(errorf(format!("bad {} slice length: 0", value.type_())));
                };
                let data = self.buf.bytes()[..n].to_vec();
                self.buf.drop_n(n);
                if n == 0 && value.cap() == 0 {
                    // SetLen(0) on a nil slice leaves it nil.
                } else if n == 0 {
                    value.set_len(0);
                } else {
                    value.set_bytes(&data);
                }
            }
            Op::Array {
                elem,
                len,
                ovfl: eovfl,
                helper,
            } => {
                let n = self.decode_uint()?;
                if n != *len as u64 {
                    return Err(errorf("length mismatch in decodeArray"));
                }
                self.decode_array_helper(value, elem, *len, eovfl, *helper)?;
            }
            Op::Map {
                typ,
                key,
                elem,
                ovfl: eovfl,
            } => self.decode_map(typ, value, key, elem, eovfl)?,
            Op::Slice {
                elem,
                ovfl: eovfl,
                helper,
            } => self.decode_slice(value, elem, eovfl, *helper)?,
            Op::Struct { engine } => {
                let Some(engine) = engine.get() else {
                    return Err(errorf("decoder engine not compiled"));
                };
                let engine = engine.clone();
                self.decode_struct(&engine, value)?;
            }
            Op::Interface { typ } => self.decode_interface(typ, value)?,
            Op::GobDecoder { ut, rcvr_is_ptr } => {
                let mut v = value.clone();
                if v.kind() != Kind::Pointer && *rcvr_is_ptr {
                    v = v.addr();
                }
                self.decode_gob_decoder(ut, &v)?;
            }
            Op::IgnoreUint => {
                self.decode_uint()?;
            }
            Op::IgnoreTwoUints => {
                self.decode_uint()?;
                self.decode_uint()?;
            }
            Op::IgnoreBytes => {
                let Some(n) = self.get_length()? else {
                    return Err(errorf("slice length too large"));
                };
                let bn = self.buf.len();
                if bn < n {
                    return Err(errorf(format!(
                        "invalid slice length {n}: exceeds input size {bn}"
                    )));
                }
                self.buf.drop_n(n);
            }
            Op::IgnoreInterface => self.ignore_interface()?,
            Op::IgnoreArray { elem, len } => {
                let n = self.decode_uint()?;
                if n != *len as u64 {
                    return Err(errorf("length mismatch in ignoreArray"));
                }
                self.ignore_array_helper(elem, *len)?;
            }
            Op::IgnoreMap { key, elem } => {
                let n = self.decode_uint()? as i64;
                for _ in 0..n.max(0) {
                    self.exec(key, "no error", &Value::default())?;
                    self.exec(elem, "no error", &Value::default())?;
                }
            }
            Op::IgnoreSlice { elem } => {
                let n = self.decode_uint()? as i64;
                self.ignore_array_helper(elem, n.max(0) as usize)?;
            }
            Op::IgnoreStruct { engine } => {
                let Some(engine) = engine.get() else {
                    return Err(errorf("decoder engine not compiled"));
                };
                let engine = engine.clone();
                self.ignore_struct(&engine)?;
            }
            Op::IgnoreGobDecoder => {
                let Some(n) = self.get_length()? else {
                    return Err(errorf("GobDecoder: length too large for buffer"));
                };
                let bn = self.buf.len();
                if bn < n {
                    return Err(errorf(format!(
                        "GobDecoder: invalid data length {n}: exceeds input size {bn}"
                    )));
                }
                self.buf.drop_n(n);
            }
        }
        Ok(())
    }

    /// Go `decodeSingle`: a top-level value that is not a struct. Such values
    /// are preceded by a zero, making them have the memory layout of a struct
    /// field (although with an illegal field number).
    fn decode_single(&mut self, engine: &DecEngine, value: &Value) -> io::Result<()> {
        if self.decode_uint()? != 0 {
            return Err(errorf(
                "decode: corrupted data: non-zero delta for singleton",
            ));
        }
        let instr = &engine.instr[0];
        self.exec(&instr.op, &instr.ovfl, value)
    }

    /// Go `decodeStruct`.
    fn decode_struct(&mut self, engine: &DecEngine, value: &Value) -> io::Result<()> {
        let mut fieldnum: i64 = -1;
        while self.buf.len() > 0 {
            let delta = self.decode_uint()? as i64;
            if delta < 0 {
                return Err(errorf("decode: corrupted data: negative delta"));
            }
            if delta == 0 {
                // The struct terminator is zero delta fieldnum.
                break;
            }
            if fieldnum >= engine.instr.len() as i64 - delta {
                return Err(err_range());
            }
            fieldnum += delta;
            let instr = &engine.instr[fieldnum as usize];
            let mut field = Value::default();
            if let Some(index) = &instr.index {
                // Otherwise the field is unknown to us and the op ignores it.
                field = value
                    .field_by_index_err(index)
                    .map_err(|e| plain(e.to_string()))?;
                if field.kind() == Kind::Pointer {
                    field = dec_alloc(&field);
                }
            }
            self.exec(&instr.op, &instr.ovfl, &field)?;
        }
        Ok(())
    }

    /// Go `ignoreStruct`: discards the data for a struct with no destination.
    fn ignore_struct(&mut self, engine: &DecEngine) -> io::Result<()> {
        let mut fieldnum: i64 = -1;
        while self.buf.len() > 0 {
            let delta = self.decode_uint()? as i64;
            if delta < 0 {
                return Err(errorf("ignore decode: corrupted data: negative delta"));
            }
            if delta == 0 {
                break;
            }
            fieldnum += delta;
            if fieldnum >= engine.instr.len() as i64 {
                return Err(err_range());
            }
            let instr = &engine.instr[fieldnum as usize];
            self.exec(&instr.op, &instr.ovfl, &Value::default())?;
        }
        Ok(())
    }

    /// Go `ignoreSingle`.
    fn ignore_single(&mut self, engine: &DecEngine) -> io::Result<()> {
        let delta = self.decode_uint()?;
        if delta != 0 {
            return Err(errorf(
                "decode: corrupted data: non-zero delta for singleton",
            ));
        }
        let instr = &engine.instr[0];
        self.exec(&instr.op, &instr.ovfl, &Value::default())
    }

    fn ignore_array_helper(&mut self, elem: &OpRef, length: usize) -> io::Result<()> {
        for _ in 0..length {
            if self.buf.len() == 0 {
                return Err(errorf(format!(
                    "decoding array or slice: length exceeds input size ({length} elements)"
                )));
            }
            self.exec(elem, "no error", &Value::default())?;
        }
        Ok(())
    }

    /// Go `decodeArrayHelper`, with the per-kind helpers' messages.
    fn decode_array_helper(
        &mut self,
        value: &Value,
        elem_op: &OpRef,
        length: usize,
        ovfl: &str,
        helper: Helper,
    ) -> io::Result<()> {
        let vt = value.type_();
        let elem_t = vt.elem();
        let exact = helper.is_some_and(|_| {
            let basic = Type::basic(elem_t.kind());
            elem_t == basic
                && match vt.kind() {
                    Kind::Slice => vt == reflect::slice_of(&basic),
                    _ => vt == reflect::array_of(vt.len() as isize, &basic) && value.can_addr(),
                }
        });
        let is_ptr = elem_t.kind() == Kind::Pointer;
        let mut ln = value.len();
        for i in 0..length {
            if self.buf.len() == 0 {
                return Err(match helper {
                    Some(name) if exact => errorf(format!(
                        "decoding {name} array or slice: length exceeds input size ({length} elements)"
                    )),
                    _ => errorf(format!(
                        "decoding array or slice: length exceeds input size ({length} elements)"
                    )),
                });
            }
            if i >= ln {
                // This is a slice that we only partially allocated. Grow it
                // up to length.
                value.grow(1);
                let mut cp = value.cap();
                if cp > length {
                    cp = length;
                }
                value.set_len(cp as isize);
                ln = cp;
            }
            let mut v = value.index(i);
            if is_ptr {
                v = dec_alloc(&v);
            }
            if exact && elem_t.kind() == Kind::String {
                self.decode_string_elem(&v)?;
            } else {
                self.exec(elem_op, ovfl, &v)?;
            }
        }
        Ok(())
    }

    /// The string-slice helper's element decoder.
    fn decode_string_elem(&mut self, v: &Value) -> io::Result<()> {
        let u = self.decode_uint()?;
        let n = u as i64;
        if n < 0 || n as u64 != u || n as usize > self.buf.len() {
            return Err(errorf(format!(
                "length of string exceeds input size ({u} bytes)"
            )));
        }
        let n = n as usize;
        let data = self.buf.bytes()[..n].to_vec();
        self.buf.drop_n(n);
        v.set_string(data);
        Ok(())
    }

    /// Go `decodeSlice`: an unsigned length followed by the elements.
    fn decode_slice(
        &mut self,
        value: &Value,
        elem_op: &OpRef,
        ovfl: &str,
        helper: Helper,
    ) -> io::Result<()> {
        let u = self.decode_uint()?;
        let typ = value.type_();
        let size = typ.elem().size() as u64;
        let n_bytes = u.wrapping_mul(size);
        let n = u as i64;
        // Take care with overflow in this calculation.
        if n < 0 || n as u64 != u || n_bytes > TOO_BIG || (size > 0 && n_bytes / size != u) {
            return Err(errorf(format!(
                "{} slice too big: {} elements of {} bytes",
                typ.elem(),
                u,
                size
            )));
        }
        let n = n as usize;
        if value.cap() < n {
            let safe = slice_cap_with_size(size, u);
            if safe < 0 {
                return Err(errorf(format!(
                    "{} slice too big: {} elements of {} bytes",
                    typ.elem(),
                    u,
                    size
                )));
            }
            value.set(&reflect::make_slice(&typ, safe as isize, safe as isize));
        } else {
            value.set_len(n as isize);
        }
        self.decode_array_helper(value, elem_op, n, ovfl, helper)
    }

    /// Go `decodeMap`: a length followed by key:value pairs.
    fn decode_map(
        &mut self,
        mtyp: &Type,
        value: &Value,
        key_op: &OpRef,
        elem_op: &OpRef,
        ovfl: &str,
    ) -> io::Result<()> {
        let n = self.decode_uint()? as i64;
        if value.is_nil() {
            let mut safe = slice_cap_with_size(mtyp.elem().size() as u64, n as u64);
            if safe < 0 {
                safe = 1;
            }
            value.set(&reflect::make_map_with_size(mtyp, safe as usize));
        }
        let key_is_ptr = mtyp.key().kind() == Kind::Pointer;
        let elem_is_ptr = mtyp.elem().kind() == Kind::Pointer;
        let key_p = reflect::new(&mtyp.key());
        let elem_p = reflect::new(&mtyp.elem());
        for _ in 0..n.max(0) {
            let key = key_p.elem();
            let k = if key_is_ptr {
                dec_alloc(&key)
            } else {
                key.clone()
            };
            self.exec(key_op, ovfl, &k)?;
            let elem = elem_p.elem();
            let e = if elem_is_ptr {
                dec_alloc(&elem)
            } else {
                elem.clone()
            };
            self.exec(elem_op, ovfl, &e)?;
            value.set_map_index(&key, &elem);
            key.set_zero();
            elem.set_zero();
        }
        Ok(())
    }

    /// Go `decodeInterface`: the name of a concrete type followed by a value.
    /// If the name is empty, the value is nil and no value is sent.
    fn decode_interface(&mut self, ityp: &Type, value: &Value) -> io::Result<()> {
        // Read the name of the concrete type.
        let nr = self.decode_uint()?;
        if nr > 1 << 31 {
            // Zero is permissible for anonymous types.
            return Err(errorf(format!("invalid type name length {nr}")));
        }
        if nr > self.buf.len() as u64 {
            return Err(errorf(format!(
                "invalid type name length {nr}: exceeds input size"
            )));
        }
        let n = nr as usize;
        let name = self.buf.bytes()[..n].to_vec();
        self.buf.drop_n(n);
        // Allocate the destination interface value.
        if name.is_empty() {
            // Copy the nil interface value to the target.
            value.set_zero();
            return Ok(());
        }
        if name.len() > 1024 {
            return Err(errorf(format!(
                "name too long ({} bytes): {}...",
                name.len(),
                crate::strconv::quote(truncate_runes(&name, 20))
            )));
        }
        // The concrete type must be registered.
        let name_s = String::from_utf8_lossy(&name).into_owned();
        let Some(typ) = name_to_concrete_type(&name_s) else {
            return Err(errorf(format!(
                "name not registered for interface: {}",
                crate::strconv::quote(&name)
            )));
        };
        // Read the type id of the concrete value.
        let concrete_id = self.decode_type_sequence(true);
        if concrete_id < 0 {
            return Err(self.take_err());
        }
        // Byte count of value is next; we don't care what it is (it's there
        // in case we want to ignore the value by skipping it completely).
        self.decode_uint()?;
        // Read the concrete value.
        let v = reflect::new(&typ).elem();
        self.decode_value(concrete_id, &v)?;
        // Assign the concrete value to the interface. Tread carefully; it
        // might not satisfy the interface.
        if !typ.assignable_to(ityp) {
            return Err(errorf(format!("{typ} is not assignable to type {ityp}")));
        }
        value.set(&v);
        Ok(())
    }

    /// The recorded failure (Go's `error_(dec.err)`).
    fn take_err(&mut self) -> io::Error {
        self.err
            .take()
            .unwrap_or_else(|| plain("gob: unknown error"))
    }

    /// Go `ignoreInterface`.
    fn ignore_interface(&mut self) -> io::Result<()> {
        let Some(n) = self.get_length()? else {
            return Err(errorf("bad interface encoding: name too large for buffer"));
        };
        let bn = self.buf.len();
        if bn < n {
            return Err(errorf(format!(
                "invalid interface value length {n}: exceeds input size {bn}"
            )));
        }
        self.buf.drop_n(n);
        if self.decode_type_sequence(true) < 0 {
            return Err(self.take_err());
        }
        // At this point, the decoder buffer contains a delimited value. Just
        // toss it.
        let Some(n) = self.get_length()? else {
            return Err(errorf(
                "bad interface encoding: data length too large for buffer",
            ));
        };
        self.buf.drop_n(n);
        Ok(())
    }

    /// Go `decodeGobDecoder`: the data is a byte slice.
    fn decode_gob_decoder(&mut self, ut: &UserTypeInfo, value: &Value) -> io::Result<()> {
        let Some(n) = self.get_length()? else {
            return Err(errorf("GobDecoder: length too large for buffer"));
        };
        let b = self.buf.bytes();
        if b.len() < n {
            return Err(errorf(format!(
                "GobDecoder: invalid data length {}: exceeds input size {}",
                n,
                b.len()
            )));
        }
        let data = b[..n].to_vec();
        self.buf.drop_n(n);
        let name = match ut.external_dec {
            X_GOB => "GobDecode",
            X_BINARY => "UnmarshalBinary",
            _ => "UnmarshalText",
        };
        let results = value.method_by_name(name).call(&[data.to_value()]);
        if let Some(err) = results.first() {
            if !err.is_nil() {
                return Err(plain(error_text(err)));
            }
        }
        Ok(())
    }

    // ---- compiling ----

    /// Go `decOpFor`: the decoding op for the base type under `rt`.
    fn dec_op_for(
        &mut self,
        wire_id: i32,
        rt: &Type,
        name: &str,
        in_progress: &mut HashMap<Type, OpRef>,
    ) -> io::Result<OpRef> {
        let ut = user_type(rt)?;
        // If the type implements GobDecoder, we handle it without further
        // processing.
        if ut.external_dec != 0 {
            return Ok(gob_decode_op_for(&ut));
        }
        // If this type is already in progress, it's a recursive type (e.g.
        // map[string]*T). Return the op we're already building.
        if let Some(op) = in_progress.get(rt) {
            return Ok(op.clone());
        }
        let typ = ut.base.clone();
        let simple = match typ.kind() {
            Kind::Bool => Some(Op::Bool),
            Kind::Int8 => Some(Op::Int8),
            Kind::Int16 => Some(Op::Int16),
            Kind::Int32 => Some(Op::Int32),
            Kind::Int64 | Kind::Int => Some(Op::Int64),
            Kind::Uint8 => Some(Op::Uint8),
            Kind::Uint16 => Some(Op::Uint16),
            Kind::Uint32 => Some(Op::Uint32),
            Kind::Uint64 | Kind::Uint | Kind::Uintptr => Some(Op::Uint64),
            Kind::Float32 => Some(Op::Float32),
            Kind::Float64 => Some(Op::Float64),
            Kind::Complex64 => Some(Op::Complex64),
            Kind::Complex128 => Some(Op::Complex128),
            Kind::String => Some(Op::Str),
            _ => None,
        };
        if let Some(op) = simple {
            return Ok(OpCell::with(op));
        }
        let cell = OpCell::new();
        in_progress.insert(rt.clone(), cell.clone());
        let op = match typ.kind() {
            Kind::Array => {
                let name = format!("element of {name}");
                let elem_id = self
                    .wire_type
                    .get(&wire_id)
                    .and_then(|w| w.array_t.as_ref())
                    .map(|a| a.elem)
                    .ok_or_else(|| errorf("bad data: array type not defined"))?;
                let elem_op = self.dec_op_for(elem_id, &typ.elem(), &name, in_progress)?;
                Some(Op::Array {
                    elem: elem_op,
                    len: typ.len(),
                    ovfl: overflow(&name),
                    helper: helper_for(typ.elem().kind()),
                })
            }
            Kind::Map => {
                let (key_id, elem_id) = self
                    .wire_type
                    .get(&wire_id)
                    .and_then(|w| w.map_t.as_ref())
                    .map(|m| (m.key, m.elem))
                    .ok_or_else(|| errorf("bad data: map type not defined"))?;
                let key_op =
                    self.dec_op_for(key_id, &typ.key(), &format!("key of {name}"), in_progress)?;
                let elem_op = self.dec_op_for(
                    elem_id,
                    &typ.elem(),
                    &format!("element of {name}"),
                    in_progress,
                )?;
                Some(Op::Map {
                    typ: typ.clone(),
                    key: key_op,
                    elem: elem_op,
                    ovfl: overflow(name),
                })
            }
            Kind::Slice => {
                let name = format!("element of {name}");
                if typ.elem().kind() == Kind::Uint8 {
                    Some(Op::Bytes)
                } else {
                    let builtin_elem = {
                        let t = table();
                        match t.builtin_by_id(wire_id) {
                            Some(n) => match n.kind {
                                GKind::Slice { elem } => Some(elem),
                                _ => None,
                            },
                            None => None,
                        }
                    };
                    let elem_id = match builtin_elem {
                        Some(e) => e,
                        None => self
                            .wire_type
                            .get(&wire_id)
                            .and_then(|w| w.slice_t.as_ref())
                            .map(|s| s.elem)
                            .ok_or_else(|| errorf("bad data: slice type not defined"))?,
                    };
                    let elem_op = self.dec_op_for(elem_id, &typ.elem(), &name, in_progress)?;
                    Some(Op::Slice {
                        elem: elem_op,
                        ovfl: overflow(&name),
                        helper: helper_for(typ.elem().kind()),
                    })
                }
            }
            Kind::Struct => {
                // Generate an op that calls out to the engine for the nested
                // type.
                let ut2 = user_type(&typ)?;
                let engine = self.get_dec_engine_ptr(wire_id, &ut2)?;
                Some(Op::Struct { engine })
            }
            Kind::Interface => Some(Op::Interface { typ: typ.clone() }),
            _ => None,
        };
        let Some(op) = op else {
            return Err(errorf(format!("decode can't handle type {rt}")));
        };
        let _ = cell.0.set(op);
        Ok(cell)
    }

    /// Go `decIgnoreOpFor`: the op for a field that has no destination.
    fn dec_ignore_op_for(
        &mut self,
        wire_id: i32,
        in_progress: &mut HashMap<i32, OpRef>,
    ) -> io::Result<OpRef> {
        // Track how deep we've recursed trying to skip nested ignored fields.
        self.ignore_depth += 1;
        let r = self.dec_ignore_op_for_inner(wire_id, in_progress);
        self.ignore_depth -= 1;
        r
    }

    fn dec_ignore_op_for_inner(
        &mut self,
        wire_id: i32,
        in_progress: &mut HashMap<i32, OpRef>,
    ) -> io::Result<OpRef> {
        if self.ignore_depth > MAX_IGNORE_NESTING_DEPTH {
            return Err(plain("invalid nesting depth"));
        }
        if let Some(op) = in_progress.get(&wire_id) {
            return Ok(op.clone());
        }
        let simple = match wire_id {
            T_BOOL | T_INT | T_UINT | T_FLOAT => Some(Op::IgnoreUint),
            T_BYTES | T_STRING => Some(Op::IgnoreBytes),
            T_COMPLEX => Some(Op::IgnoreTwoUints),
            _ => None,
        };
        if let Some(op) = simple {
            return Ok(OpCell::with(op));
        }
        let cell = OpCell::new();
        in_progress.insert(wire_id, cell.clone());
        if wire_id == T_INTERFACE {
            // Special case because it's a method: the ignored item might
            // define types and we need to record their state in the decoder.
            let _ = cell.0.set(Op::IgnoreInterface);
            return Ok(cell);
        }
        let Some(wire) = self.wire_type.get(&wire_id).cloned() else {
            let s = table().id_string(wire_id);
            return Err(errorf(format!("bad data: undefined type {s}")));
        };
        let op = if let Some(a) = &wire.array_t {
            let elem = self.dec_ignore_op_for(a.elem, in_progress)?;
            Some(Op::IgnoreArray {
                elem,
                len: a.len as usize,
            })
        } else if let Some(m) = &wire.map_t {
            let key = self.dec_ignore_op_for(m.key, in_progress)?;
            let elem = self.dec_ignore_op_for(m.elem, in_progress)?;
            Some(Op::IgnoreMap { key, elem })
        } else if let Some(s) = &wire.slice_t {
            let elem = self.dec_ignore_op_for(s.elem, in_progress)?;
            Some(Op::IgnoreSlice { elem })
        } else if wire.struct_t.is_some() {
            let engine = self.get_ignore_engine_ptr(wire_id)?;
            Some(Op::IgnoreStruct { engine })
        } else if wire.gob_encoder_t.is_some()
            || wire.binary_marshaler_t.is_some()
            || wire.text_marshaler_t.is_some()
        {
            Some(Op::IgnoreGobDecoder)
        } else {
            None
        };
        let Some(op) = op else {
            let s = table().id_string(wire_id);
            return Err(errorf(format!("bad data: ignore can't handle type {s}")));
        };
        let _ = cell.0.set(op);
        Ok(cell)
    }

    /// Go `compatibleType`: are these two gob types compatible? Answers the
    /// question for basic types, arrays, maps and slices, plus
    /// GobEncoder/Decoder pairs. Structs are considered ok; fields will be
    /// checked later.
    fn compatible_type(
        &self,
        fr: &Type,
        fw: i32,
        in_progress: &mut HashMap<Type, i32>,
    ) -> io::Result<bool> {
        if let Some(rhs) = in_progress.get(fr) {
            return Ok(*rhs == fw);
        }
        in_progress.insert(fr.clone(), fw);
        let ut = user_type(fr)?;
        let wire = self.wire_type.get(&fw);
        // If wire was encoded with an encoding method, fr must have that
        // method. And if not, it must not.
        let has = |f: fn(&WireType) -> bool| wire.is_some_and(|w| f(w));
        if (ut.external_dec == X_GOB) != has(|w| w.gob_encoder_t.is_some())
            || (ut.external_dec == X_BINARY) != has(|w| w.binary_marshaler_t.is_some())
            || (ut.external_dec == X_TEXT) != has(|w| w.text_marshaler_t.is_some())
        {
            return Ok(false);
        }
        if ut.external_dec != 0 {
            // This test trumps all others.
            return Ok(true);
        }
        let t = &ut.base;
        Ok(match t.kind() {
            Kind::Bool => fw == T_BOOL,
            Kind::Int | Kind::Int8 | Kind::Int16 | Kind::Int32 | Kind::Int64 => fw == T_INT,
            Kind::Uint
            | Kind::Uint8
            | Kind::Uint16
            | Kind::Uint32
            | Kind::Uint64
            | Kind::Uintptr => fw == T_UINT,
            Kind::Float32 | Kind::Float64 => fw == T_FLOAT,
            Kind::Complex64 | Kind::Complex128 => fw == T_COMPLEX,
            Kind::String => fw == T_STRING,
            Kind::Interface => fw == T_INTERFACE,
            Kind::Array => match wire.and_then(|w| w.array_t.as_ref()) {
                Some(array) => {
                    t.len() as i64 == array.len
                        && self.compatible_type(&t.elem(), array.elem, in_progress)?
                }
                None => false,
            },
            Kind::Map => match wire.and_then(|w| w.map_t.as_ref()) {
                Some(m) => {
                    self.compatible_type(&t.key(), m.key, in_progress)?
                        && self.compatible_type(&t.elem(), m.elem, in_progress)?
                }
                None => false,
            },
            Kind::Slice => {
                // Is it an array of bytes?
                if t.elem().kind() == Kind::Uint8 {
                    fw == T_BYTES
                } else {
                    // Extract and compare element types.
                    let builtin = {
                        let tb = table();
                        match tb.builtin_by_id(fw) {
                            Some(n) => match n.kind {
                                GKind::Slice { elem } => Some(Some(elem)),
                                _ => Some(None),
                            },
                            None => None,
                        }
                    };
                    let sw_elem = match builtin {
                        Some(e) => e,
                        None => wire.and_then(|w| w.slice_t.as_ref()).map(|s| s.elem),
                    };
                    let elem = user_type(&t.elem())?.base.clone();
                    match sw_elem {
                        Some(e) => self.compatible_type(&elem, e, in_progress)?,
                        None => false,
                    }
                }
            }
            Kind::Struct => true,
            // chan, etc: cannot handle.
            _ => false,
        })
    }

    /// Go `typeString`: a human-readable description of the remote type.
    fn type_string(&self, remote_id: i32) -> String {
        let t = table();
        if t.node_by_id(remote_id).is_some() {
            // Globally known type.
            return t.id_string(remote_id);
        }
        drop(t);
        match self.wire_type.get(&remote_id) {
            Some(w) => w.string(),
            None => "unknown type".to_string(),
        }
    }

    /// Go `compileSingle`: the engine for a non-struct top-level value,
    /// including GobDecoders.
    fn compile_single(&mut self, remote_id: i32, ut: &UserTypeInfo) -> io::Result<DecEngine> {
        let rt = ut.user.clone();
        let name = rt.to_string();
        if !self.compatible_type(&rt, remote_id, &mut HashMap::new())? {
            let remote_type = self.type_string(remote_id);
            // Common confusing case: local interface type, remote concrete type.
            if ut.base.kind() == Kind::Interface && remote_id != T_INTERFACE {
                return Err(plain(format!(
                    "gob: local interface type {name} can only be decoded from remote interface type; received concrete type {remote_type}"
                )));
            }
            return Err(plain(format!(
                "gob: decoding into local type {name}, received remote type {remote_type}"
            )));
        }
        let op = self.dec_op_for(remote_id, &rt, &name, &mut HashMap::new())?;
        Ok(DecEngine {
            instr: vec![DecInstr {
                op,
                index: None,
                ovfl: name,
            }],
            num_instr: 1,
        })
    }

    /// Go `compileIgnoreSingle`.
    fn compile_ignore_single(&mut self, remote_id: i32) -> io::Result<DecEngine> {
        let op = self.dec_ignore_op_for(remote_id, &mut HashMap::new())?;
        let ovfl = self.type_string(remote_id);
        Ok(DecEngine {
            instr: vec![DecInstr {
                op,
                index: None,
                ovfl,
            }],
            num_instr: 1,
        })
    }

    /// Go `compileDec`: the engine for a value. If the value is not a struct
    /// it calls out to `compile_single`.
    fn compile_dec(&mut self, remote_id: i32, ut: &UserTypeInfo) -> io::Result<DecEngine> {
        let srt = ut.base.clone();
        if srt.kind() != Kind::Struct || ut.external_dec != 0 {
            return self.compile_single(remote_id, ut);
        }
        // Builtin types can come from the global pool; the rest must be
        // defined by the decoder. We know we're decoding a struct now, so the
        // client must have sent one.
        let builtin = {
            let t = table();
            t.builtin_by_id(remote_id).map(|n| match &n.kind {
                GKind::Struct { fields } => Some((n.name.clone(), fields.clone())),
                _ => None,
            })
        };
        let wire_struct: Option<(String, Vec<(String, i32)>)> = match builtin {
            Some(b) => b,
            None => {
                let wire = self
                    .wire_type
                    .get(&remote_id)
                    .ok_or_else(|| plain("gob: unknown type id or corrupted data"))?;
                wire.struct_t
                    .as_ref()
                    .map(|s| (s.common.name.clone(), s.fields.clone()))
            }
        };
        let Some((wire_name, wire_fields)) = wire_struct else {
            return Err(errorf(format!(
                "type mismatch in decoder: want struct type {srt}; got non-struct"
            )));
        };
        let mut instr = Vec::with_capacity(wire_fields.len());
        let mut num_instr = 0;
        let mut seen: HashMap<Type, OpRef> = HashMap::new();
        // Loop over the fields of the wire type.
        for (fname, fid) in wire_fields.iter() {
            if fname.is_empty() {
                return Err(errorf(format!(
                    "empty name for remote field of type {wire_name}"
                )));
            }
            let ovfl = overflow(fname);
            // Find the field of the local type with the same name.
            let local = srt.field_by_name(fname);
            match local {
                Some(local) if is_exported(fname) => {
                    if !self.compatible_type(&local.type_, *fid, &mut HashMap::new())? {
                        return Err(errorf(format!(
                            "wrong type ({}) for received field {}.{}",
                            local.type_, wire_name, fname
                        )));
                    }
                    let op = self.dec_op_for(*fid, &local.type_, &local.name, &mut seen)?;
                    instr.push(DecInstr {
                        op,
                        index: Some(local.index.clone()),
                        ovfl,
                    });
                    num_instr += 1;
                }
                _ => {
                    let op = self.dec_ignore_op_for(*fid, &mut HashMap::new())?;
                    instr.push(DecInstr {
                        op,
                        index: None,
                        ovfl,
                    });
                }
            }
        }
        Ok(DecEngine { instr, num_instr })
    }

    /// Go `getDecEnginePtr`.
    fn get_dec_engine_ptr(&mut self, remote_id: i32, ut: &UserTypeInfo) -> io::Result<EnginePtr> {
        let rt = ut.user.clone();
        if let Some(p) = self.decoder_cache.get(&rt).and_then(|m| m.get(&remote_id)) {
            return Ok(p.clone());
        }
        // To handle recursive types, mark this engine as underway before
        // compiling.
        let ptr: EnginePtr = Arc::new(OnceLock::new());
        self.decoder_cache
            .entry(rt.clone())
            .or_default()
            .insert(remote_id, ptr.clone());
        match self.compile_dec(remote_id, ut) {
            Ok(engine) => {
                let _ = ptr.set(Arc::new(engine));
                Ok(ptr)
            }
            Err(e) => {
                if let Some(m) = self.decoder_cache.get_mut(&rt) {
                    m.remove(&remote_id);
                }
                Err(e)
            }
        }
    }

    /// Go `getIgnoreEnginePtr`.
    fn get_ignore_engine_ptr(&mut self, wire_id: i32) -> io::Result<EnginePtr> {
        if let Some(p) = self.ignorer_cache.get(&wire_id) {
            return Ok(p.clone());
        }
        let ptr: EnginePtr = Arc::new(OnceLock::new());
        self.ignorer_cache.insert(wire_id, ptr.clone());
        let is_struct = self
            .wire_type
            .get(&wire_id)
            .is_some_and(|w| w.struct_t.is_some());
        let r = if is_struct {
            let ut = user_type(&empty_struct_type())?;
            self.compile_dec(wire_id, &ut)
        } else {
            self.compile_ignore_single(wire_id)
        };
        match r {
            Ok(engine) => {
                let _ = ptr.set(Arc::new(engine));
                Ok(ptr)
            }
            Err(e) => {
                self.ignorer_cache.remove(&wire_id);
                Err(e)
            }
        }
    }

    /// Go `decodeValue` as its callers see it: a failure, or one left in
    /// `err` earlier, is returned.
    fn decode_value(&mut self, wire_id: i32, value: &Value) -> io::Result<()> {
        if let Err(e) = self.decode_value_inner(wire_id, value) {
            self.err = Some(e);
        }
        match self.err.take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Go `decodeValue`: decodes the data stream representing a value and
    /// stores it in `value`.
    fn decode_value_inner(&mut self, wire_id: i32, value: &Value) -> io::Result<()> {
        // If the value is nil, it means we should just ignore this item.
        if !value.is_valid() {
            return self.decode_ignored_value(wire_id);
        }
        // Dereference down to the underlying type.
        let ut = user_type(&value.type_())?;
        let base = ut.base.clone();
        let engine_ptr = self.get_dec_engine_ptr(wire_id, &ut)?;
        let value = dec_alloc(value);
        let Some(engine) = engine_ptr.get().cloned() else {
            return Err(errorf("decoder engine not compiled"));
        };
        if base.kind() == Kind::Struct && ut.external_dec == 0 {
            let fields_on_wire = self
                .wire_type
                .get(&wire_id)
                .and_then(|w| w.struct_t.as_ref())
                .map(|s| s.fields.len());
            if engine.num_instr == 0
                && base.num_field() > 0
                && fields_on_wire.is_some_and(|n| n > 0)
            {
                return Err(errorf(format!(
                    "type mismatch: no fields matched compiling decoder for {}",
                    base.name()
                )));
            }
            self.decode_struct(&engine, &value)
        } else {
            self.decode_single(&engine, &value)
        }
    }

    /// Go `decodeIgnoredValue`.
    fn decode_ignored_value(&mut self, wire_id: i32) -> io::Result<()> {
        let engine_ptr = self.get_ignore_engine_ptr(wire_id)?;
        let Some(engine) = engine_ptr.get().cloned() else {
            return Err(errorf("decoder engine not compiled"));
        };
        let is_struct = self
            .wire_type
            .get(&wire_id)
            .is_some_and(|w| w.struct_t.is_some());
        if is_struct {
            self.ignore_struct(&engine)
        } else {
            self.ignore_single(&engine)
        }
    }
}

/// Go `gobDecodeOpFor`.
fn gob_decode_op_for(ut: &Arc<UserTypeInfo>) -> OpRef {
    let mut rcvr = ut.user.clone();
    if ut.dec_indir == -1 {
        rcvr = reflect::pointer_to(&rcvr);
    } else if ut.dec_indir > 0 {
        for _ in 0..ut.dec_indir {
            rcvr = rcvr.elem();
        }
    }
    OpCell::with(Op::GobDecoder {
        ut: ut.clone(),
        rcvr_is_ptr: rcvr.kind() == Kind::Pointer,
    })
}

/// Go `emptyStruct`: the type compiled into when ignoring a struct value.
fn empty_struct_type() -> Type {
    static T: std::sync::LazyLock<Type> = std::sync::LazyLock::new(|| {
        Type::named(
            "encoding/gob",
            "emptyStruct",
            &reflect::struct_of(&[]),
            Vec::new(),
        )
    });
    T.clone()
}
