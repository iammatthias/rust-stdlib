//! The encoder: Go's `encoder.go` and `encode.go`.
//!
//! Go compiles an instruction list per type and runs it; here the same rules
//! run directly over the reflect value, in the same order, so the bytes (and
//! the order in which type descriptors and ids are produced) are identical.

use std::collections::{HashMap, HashSet};
use std::io::{self, Write};
use std::sync::{LazyLock, Mutex};

use crate::reflect::{self, Kind, Reflect, Type, Value};

use super::types::{
    concrete_type_to_name, errorf, get_type_info, is_exported, is_sent, lock, plain, user_type,
    valid_user_type, UserTypeInfo, X_BINARY, X_GOB,
};
use super::wire;

/// Go `tooBig`.
pub(crate) const TOO_BIG: u64 = (1 << 30) << 3;
/// Go `maxLength`: the room reserved for a message's length.
const MAX_LENGTH: usize = 9;

/// Go `encBuffer` with `spaceForLength` already written.
pub(crate) struct EncBuf {
    pub data: Vec<u8>,
}

impl EncBuf {
    pub(crate) fn with_space() -> EncBuf {
        EncBuf {
            data: vec![0; MAX_LENGTH],
        }
    }

    fn reset(&mut self) {
        self.data.clear();
        self.data.resize(MAX_LENGTH, 0);
    }

    /// Go `encodeUint`.
    pub(crate) fn encode_uint(&mut self, x: u64) {
        if x <= 0x7F {
            self.data.push(x as u8);
            return;
        }
        let bytes = x.to_be_bytes();
        let skip = (x.leading_zeros() >> 3) as usize;
        self.data.push((skip as u8).wrapping_sub(8));
        self.data.extend_from_slice(&bytes[skip..]);
    }

    /// Go `encodeInt`.
    pub(crate) fn encode_int(&mut self, i: i64) {
        let x = if i < 0 {
            ((!i) << 1) as u64 | 1
        } else {
            (i << 1) as u64
        };
        self.encode_uint(x);
    }
}

/// Where a finished message goes: the connection, or an enclosing buffer
/// (while a nested interface value is being built).
pub(crate) enum Out<'a> {
    Conn(&'a mut dyn Write),
    Buf(&'a mut EncBuf),
}

impl Out<'_> {
    /// Go `writeMessage`: sends the buffer preceded by its length and resets it.
    fn write_message(&mut self, b: &mut EncBuf) -> io::Result<()> {
        let message_len = (b.data.len() - MAX_LENGTH) as u64;
        if message_len >= TOO_BIG {
            return Err(plain("gob: encoder: message too big"));
        }
        let mut count = EncBuf { data: Vec::new() };
        count.encode_uint(message_len);
        let offset = MAX_LENGTH - count.data.len();
        b.data[offset..MAX_LENGTH].copy_from_slice(&count.data);
        let r = match self {
            Out::Conn(w) => w.write_all(&b.data[offset..]),
            Out::Buf(o) => {
                o.data.extend_from_slice(&b.data[offset..]);
                Ok(())
            }
        };
        b.reset();
        r
    }
}

/// Go `encoderState`: whether zero values are sent and the last field number.
struct State {
    send_zero: bool,
    fieldnum: i64,
}

impl State {
    fn new(send_zero: bool, fieldnum: i64) -> State {
        State {
            send_zero,
            fieldnum,
        }
    }

    /// Go `update`: emits the field number as a delta.
    fn update(&mut self, b: &mut EncBuf, field: Option<i64>) {
        if let Some(f) = field {
            b.encode_uint((f - self.fieldnum) as u64);
            self.fieldnum = f;
        }
    }
}

/// Go `floatBits`.
fn float_bits(f: f64) -> u64 {
    f.to_bits().swap_bytes()
}

/// Go `valid`.
fn valid(v: &Value) -> bool {
    match v.kind() {
        Kind::Invalid => false,
        Kind::Pointer => !v.is_nil(),
        _ => true,
    }
}

/// Go `encIndirect`.
fn enc_indirect(mut v: Value, indir: i32) -> Value {
    let mut n = indir;
    while n > 0 {
        if v.is_nil() {
            break;
        }
        v = v.elem();
        n -= 1;
    }
    v
}

/// The indirections the op for this type expects its caller to have made.
fn op_indir(ut: &UserTypeInfo) -> i32 {
    if ut.external_enc != 0 {
        ut.enc_indir as i32
    } else {
        ut.indir as i32
    }
}

static ENC_OK: LazyLock<Mutex<HashSet<Type>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

/// Go `getEncEngine`'s error cases: the checks `compileEnc` makes before a
/// value of the type is encoded.
fn check_enc(ut: &UserTypeInfo) -> io::Result<()> {
    if lock(&ENC_OK).contains(&ut.user) {
        return Ok(());
    }
    check_compile(ut, &mut HashSet::new())?;
    lock(&ENC_OK).insert(ut.user.clone());
    Ok(())
}

fn check_compile(ut: &UserTypeInfo, seen: &mut HashSet<Type>) -> io::Result<()> {
    let srt = &ut.base;
    if ut.external_enc == 0 && srt.kind() == Kind::Struct {
        let mut sent = 0;
        for i in 0..srt.num_field() {
            let f = srt.field(i);
            if !is_sent(&f) {
                continue;
            }
            sent += 1;
            check_op(&f.type_, seen)?;
        }
        if srt.num_field() > 0 && sent == 0 {
            return Err(errorf(format!("type {srt} has no exported fields")));
        }
        Ok(())
    } else {
        let rt = if ut.external_enc != 0 {
            ut.user.clone()
        } else {
            ut.base.clone()
        };
        check_op(&rt, seen)
    }
}

fn check_op(rt: &Type, seen: &mut HashSet<Type>) -> io::Result<()> {
    let ut = user_type(rt)?;
    if ut.external_enc != 0 {
        return Ok(());
    }
    if !seen.insert(rt.clone()) {
        return Ok(());
    }
    let t = &ut.base;
    match t.kind() {
        Kind::Bool
        | Kind::Int
        | Kind::Int8
        | Kind::Int16
        | Kind::Int32
        | Kind::Int64
        | Kind::Uint
        | Kind::Uint8
        | Kind::Uint16
        | Kind::Uint32
        | Kind::Uint64
        | Kind::Uintptr
        | Kind::Float32
        | Kind::Float64
        | Kind::Complex64
        | Kind::Complex128
        | Kind::String
        | Kind::Interface => Ok(()),
        Kind::Slice => {
            if t.elem().kind() == Kind::Uint8 {
                Ok(())
            } else {
                check_op(&t.elem(), seen)
            }
        }
        Kind::Array => check_op(&t.elem(), seen),
        Kind::Map => {
            check_op(&t.key(), seen)?;
            check_op(&t.elem(), seen)
        }
        Kind::Struct => check_compile(&ut, seen),
        _ => Err(errorf(format!("can't happen: encode type {rt}"))),
    }
}

/// The part of an encoder that every nested call shares.
pub(crate) struct Ctx<'a> {
    /// Which types have been sent (Go `Encoder.sent`).
    pub sent: &'a mut HashMap<Type, i32>,
}

impl Ctx<'_> {
    /// Go `sendActualType`.
    fn send_actual_type(
        &mut self,
        out: &mut Out,
        b: &mut EncBuf,
        ut: &UserTypeInfo,
        actual: &Type,
    ) -> io::Result<bool> {
        if self.sent.contains_key(actual) {
            return Ok(false);
        }
        let info = get_type_info(ut)?;
        // Send the pair (-id, type).
        b.encode_int(-(info.id as i64));
        let wv = wire::to_value(&info.wire);
        let wut = valid_user_type(&wire::types().wire_type)?;
        let r = self.encode(out, b, wv, &wut);
        out.write_message(b)?;
        r?;
        // Remember we've sent this type, both what the user gave us and the
        // base type.
        self.sent.insert(ut.base.clone(), info.id);
        if ut.user != ut.base {
            self.sent.insert(ut.user.clone(), info.id);
        }
        // Now send the inner types.
        match actual.kind() {
            Kind::Struct => {
                for i in 0..actual.num_field() {
                    let f = actual.field(i);
                    if is_exported(&f.name) {
                        self.send_type(out, b, &f.type_)?;
                    }
                }
            }
            Kind::Array | Kind::Slice => {
                self.send_type(out, b, &actual.elem())?;
            }
            Kind::Map => {
                self.send_type(out, b, &actual.key())?;
                self.send_type(out, b, &actual.elem())?;
            }
            _ => {}
        }
        Ok(true)
    }

    /// Go `sendType`: sends the type info to the other side, if necessary.
    fn send_type(&mut self, out: &mut Out, b: &mut EncBuf, origt: &Type) -> io::Result<bool> {
        let ut = user_type(origt)?;
        if ut.external_enc != 0 {
            // Regardless of the underlying type's representation, tell the
            // other side that the base type is a GobEncoder.
            return self.send_actual_type(out, b, &ut, &ut.base);
        }
        let rt = &ut.base;
        match rt.kind() {
            Kind::Slice => {
                // []uint8 is considered basic.
                if rt.elem().kind() == Kind::Uint8 {
                    return Ok(false);
                }
            }
            Kind::Array | Kind::Map | Kind::Struct => {}
            // Basic types and interfaces need no description; a chan or func
            // here is a field of a struct, which is ignored.
            _ => return Ok(false),
        }
        self.send_actual_type(out, b, &ut, rt)
    }

    /// Go `sendTypeDescriptor`: makes sure the remote side knows this type.
    pub(crate) fn send_type_descriptor(
        &mut self,
        out: &mut Out,
        b: &mut EncBuf,
        ut: &UserTypeInfo,
    ) -> io::Result<()> {
        let rt = if ut.external_enc != 0 {
            ut.user.clone()
        } else {
            ut.base.clone()
        };
        if !self.sent.contains_key(&rt) {
            let sent = self.send_type(out, b, &rt)?;
            // A singleton basic type at top level needs no descriptor, but
            // `sent` must still learn its id.
            if !sent {
                let info = get_type_info(ut)?;
                self.sent.insert(rt, info.id);
            }
        }
        Ok(())
    }

    /// Go `sendTypeId`.
    pub(crate) fn send_type_id(&mut self, b: &mut EncBuf, ut: &UserTypeInfo) {
        let id = self.sent.get(&ut.base).copied().unwrap_or(0);
        b.encode_int(id as i64);
    }

    /// Go `encode`: encodes a value of the user type into `b`.
    pub(crate) fn encode(
        &mut self,
        out: &mut Out,
        b: &mut EncBuf,
        mut value: Value,
        ut: &UserTypeInfo,
    ) -> io::Result<()> {
        check_enc(ut)?;
        let indir = if ut.external_enc != 0 {
            ut.enc_indir as i32
        } else {
            ut.indir as i32
        };
        for _ in 0..indir {
            value = reflect::indirect(&value);
        }
        if ut.external_enc == 0 && value.kind() == Kind::Struct {
            self.encode_struct(out, b, &value)
        } else {
            self.encode_single(out, b, value, ut)
        }
    }

    /// Go `encodeSingle`: a top-level non-struct value.
    fn encode_single(
        &mut self,
        out: &mut Out,
        b: &mut EncBuf,
        mut value: Value,
        ut: &UserTypeInfo,
    ) -> io::Result<()> {
        // There is no surrounding struct to frame the transmission, so data
        // is generated even if the item is zero.
        let mut state = State::new(true, 0);
        let (op_ut, indir) = if ut.external_enc != 0 {
            (user_type(&ut.user)?, ut.enc_indir as i32)
        } else {
            (user_type(&ut.base)?, 0)
        };
        if indir > 0 {
            value = enc_indirect(value, indir);
        }
        if valid(&value) {
            self.enc_op(out, b, &mut state, Some(0), &value, &op_ut)?;
        }
        Ok(())
    }

    /// Go `encodeStruct`.
    fn encode_struct(&mut self, out: &mut Out, b: &mut EncBuf, value: &Value) -> io::Result<()> {
        if !valid(value) {
            return Ok(());
        }
        let t = value.type_();
        let mut state = State::new(false, -1);
        let mut wire_field = 0i64;
        for i in 0..t.num_field() {
            let f = t.field(i);
            if !is_sent(&f) {
                continue;
            }
            let fut = user_type(&f.type_)?;
            let this = wire_field;
            wire_field += 1;
            let mut field = value.field_by_index(&f.index);
            let indir = op_indir(&fut);
            if indir > 0 {
                field = enc_indirect(field, indir);
                if !valid(&field) {
                    continue;
                }
            }
            self.enc_op(out, b, &mut state, Some(this), &field, &fut)?;
        }
        // The struct terminator.
        b.encode_uint(0);
        Ok(())
    }

    /// Go `encodeArray`.
    fn encode_array(
        &mut self,
        out: &mut Out,
        b: &mut EncBuf,
        value: &Value,
        elem_ut: &UserTypeInfo,
        length: usize,
    ) -> io::Result<()> {
        let mut state = State::new(true, -1);
        b.encode_uint(length as u64);
        let indir = op_indir(elem_ut);
        for i in 0..length {
            let mut elem = value.index(i);
            if indir > 0 {
                elem = enc_indirect(elem, indir);
                if !valid(&elem) {
                    return Err(errorf("encodeArray: nil element"));
                }
            }
            self.enc_op(out, b, &mut state, None, &elem, elem_ut)?;
        }
        Ok(())
    }

    /// Go `encodeReflectValue`.
    fn encode_reflect_value(
        &mut self,
        out: &mut Out,
        b: &mut EncBuf,
        state: &mut State,
        mut v: Value,
        ut: &UserTypeInfo,
    ) -> io::Result<()> {
        let indir = op_indir(ut);
        let mut i = 0;
        while i < indir && v.is_valid() {
            v = reflect::indirect(&v);
            i += 1;
        }
        if !v.is_valid() {
            return Err(errorf("encodeReflectValue: nil element"));
        }
        self.enc_op(out, b, state, None, &v, ut)
    }

    /// Go `encodeMap`: an unsigned count followed by key:value pairs.
    fn encode_map(
        &mut self,
        out: &mut Out,
        b: &mut EncBuf,
        mv: &Value,
        key_ut: &UserTypeInfo,
        elem_ut: &UserTypeInfo,
    ) -> io::Result<()> {
        let mut state = State::new(true, -1);
        b.encode_uint(mv.len() as u64);
        for (k, v) in mv.entries() {
            self.encode_reflect_value(out, b, &mut state, k, key_ut)?;
            self.encode_reflect_value(out, b, &mut state, v, elem_ut)?;
        }
        Ok(())
    }

    /// Go `encodeInterface`: the name of the concrete type, its type id (after
    /// defining the type if need be), then the length-prefixed value. A nil
    /// interface is the empty name and no value.
    fn encode_interface(&mut self, out: &mut Out, b: &mut EncBuf, iv: &Value) -> io::Result<()> {
        // Gobs can encode nil interface values but not typed interface values
        // holding nil pointers, since nil pointers point to no value.
        let elem = iv.elem();
        if elem.is_valid() && elem.kind() == Kind::Pointer && elem.is_nil() {
            return Err(errorf(format!(
                "gob: cannot encode nil pointer of type {} inside interface",
                elem.type_()
            )));
        }
        if iv.is_nil() {
            b.encode_uint(0);
            return Ok(());
        }
        let ut = user_type(&elem.type_())?;
        let Some(name) = concrete_type_to_name(&ut.base) else {
            return Err(errorf(format!(
                "type not registered for interface: {}",
                ut.base
            )));
        };
        // Send the name.
        b.encode_uint(name.len() as u64);
        b.data.extend_from_slice(name.as_bytes());
        // Define the type id if necessary.
        self.send_type_descriptor(out, b, &ut)?;
        // Send the type id.
        self.send_type_id(b, &ut);
        // Encode the value into a new buffer. Any nested type definitions
        // should be written to b, before the encoded value.
        let mut data = EncBuf::with_space();
        self.encode(&mut Out::Buf(b), &mut data, elem, &ut)?;
        Out::Buf(b).write_message(&mut data)
    }

    /// Go `encodeGobEncoder`: the data is sent as a byte array.
    fn encode_gob_encoder(
        &mut self,
        b: &mut EncBuf,
        ut: &UserTypeInfo,
        v: &Value,
    ) -> io::Result<()> {
        let name = match ut.external_enc {
            X_GOB => "GobEncode",
            X_BINARY => "MarshalBinary",
            _ => "MarshalText",
        };
        let results = v.method_by_name(name).call(&[]);
        if let Some(err) = results.get(1) {
            if !err.is_nil() {
                return Err(plain(error_text(err)));
            }
        }
        let data = results.first().map(|d| d.bytes()).unwrap_or_default();
        b.encode_uint(data.len() as u64);
        b.data.extend_from_slice(&data);
        Ok(())
    }

    /// The op for a value of the user type `ut` (Go `encOpFor`), applied to
    /// `v`, which has had its indirections made.
    fn enc_op(
        &mut self,
        out: &mut Out,
        b: &mut EncBuf,
        state: &mut State,
        field: Option<i64>,
        v: &Value,
        ut: &UserTypeInfo,
    ) -> io::Result<()> {
        // If the type implements GobEncoder, we handle it without further
        // processing.
        if ut.external_enc != 0 {
            let mut v = v.clone();
            if ut.enc_indir == -1 {
                // Need to climb up one level to turn value into pointer.
                if !v.can_addr() {
                    return Err(errorf(format!(
                        "unaddressable value of type {}",
                        reflect::pointer_to(&ut.user)
                    )));
                }
                v = v.addr();
            }
            if !state.send_zero && v.is_zero() {
                return Ok(());
            }
            state.update(b, field);
            return self.encode_gob_encoder(b, ut, &v);
        }
        let typ = &ut.base;
        match typ.kind() {
            Kind::Bool => {
                let x = v.bool();
                if x || state.send_zero {
                    state.update(b, field);
                    b.encode_uint(x as u64);
                }
            }
            Kind::Int | Kind::Int8 | Kind::Int16 | Kind::Int32 | Kind::Int64 => {
                let x = v.int();
                if x != 0 || state.send_zero {
                    state.update(b, field);
                    b.encode_int(x);
                }
            }
            Kind::Uint
            | Kind::Uint8
            | Kind::Uint16
            | Kind::Uint32
            | Kind::Uint64
            | Kind::Uintptr => {
                let x = v.uint();
                if x != 0 || state.send_zero {
                    state.update(b, field);
                    b.encode_uint(x);
                }
            }
            Kind::Float32 | Kind::Float64 => {
                let f = v.float();
                if f != 0.0 || state.send_zero {
                    state.update(b, field);
                    b.encode_uint(float_bits(f));
                }
            }
            Kind::Complex64 | Kind::Complex128 => {
                let c = v.complex();
                if c.re != 0.0 || c.im != 0.0 || state.send_zero {
                    state.update(b, field);
                    b.encode_uint(float_bits(c.re));
                    b.encode_uint(float_bits(c.im));
                }
            }
            Kind::String => {
                let s = v.string_bytes();
                if !s.is_empty() || state.send_zero {
                    state.update(b, field);
                    b.encode_uint(s.len() as u64);
                    b.data.extend_from_slice(&s);
                }
            }
            Kind::Slice => {
                if typ.elem().kind() == Kind::Uint8 {
                    let bytes = v.bytes();
                    if !bytes.is_empty() || state.send_zero {
                        state.update(b, field);
                        b.encode_uint(bytes.len() as u64);
                        b.data.extend_from_slice(&bytes);
                    }
                } else {
                    if !state.send_zero && v.len() == 0 {
                        return Ok(());
                    }
                    state.update(b, field);
                    let elem_ut = user_type(&typ.elem())?;
                    self.encode_array(out, b, v, &elem_ut, v.len())?;
                }
            }
            Kind::Array => {
                state.update(b, field);
                let elem_ut = user_type(&typ.elem())?;
                self.encode_array(out, b, v, &elem_ut, v.len())?;
            }
            Kind::Map => {
                // Zero-length (but non-nil) maps are sent because the
                // receiver might want to use the map.
                if !state.send_zero && v.is_nil() {
                    return Ok(());
                }
                state.update(b, field);
                let key_ut = user_type(&typ.key())?;
                let elem_ut = user_type(&typ.elem())?;
                self.encode_map(out, b, v, &key_ut, &elem_ut)?;
            }
            Kind::Struct => {
                state.update(b, field);
                self.encode_struct(out, b, v)?;
            }
            Kind::Interface => {
                if !state.send_zero && (!v.is_valid() || v.is_nil()) {
                    return Ok(());
                }
                state.update(b, field);
                self.encode_interface(out, b, v)?;
            }
            _ => return Err(errorf(format!("can't happen: encode type {}", ut.user))),
        }
        Ok(())
    }
}

/// The text of a (non-nil) Go `error` value.
pub(crate) fn error_text(err: &Value) -> String {
    let results = err.method_by_name("Error").call(&[]);
    results
        .first()
        .map(|r| String::from_utf8_lossy(&r.string_bytes()).into_owned())
        .unwrap_or_default()
}

/// An `Encoder` manages the transmission of type and data information to the
/// other side of a connection (Go `gob.Encoder`). It is safe for concurrent
/// use by multiple threads.
pub struct Encoder {
    core: Mutex<EncCore>,
}

struct EncCore {
    w: Box<dyn Write + Send>,
    sent: HashMap<Type, i32>,
}

impl Encoder {
    /// Go `NewEncoder`: an encoder that will transmit on `w`.
    pub fn new<W: Write + Send + 'static>(w: W) -> Encoder {
        Encoder {
            core: Mutex::new(EncCore {
                w: Box::new(w),
                sent: HashMap::new(),
            }),
        }
    }

    /// Go `Encoder.Encode`: transmits the data item, guaranteeing that all
    /// necessary type information has been transmitted first. A value that is
    /// a nil pointer (`None`) panics, as Go's does, because gob cannot
    /// transmit it.
    pub fn encode<T: Reflect>(&self, e: &T) -> io::Result<()> {
        // reflect.ValueOf(e) sees through an interface.
        let v = e.to_value();
        if v.is_valid() && v.kind() == Kind::Interface {
            return self.encode_value(&v.elem());
        }
        self.encode_value(&v)
    }

    /// Go `Encoder.EncodeValue`: transmits the data item represented by the
    /// reflection value. The invalid value is an error; a nil pointer panics.
    pub fn encode_value(&self, value: &Value) -> io::Result<()> {
        let value = value.clone();
        if !value.is_valid() {
            return Err(plain("gob: cannot encode nil value"));
        }
        if value.kind() == Kind::Pointer && value.is_nil() {
            panic!("gob: cannot encode nil pointer of type {}", value.type_());
        }
        // Each item must be sent atomically.
        let mut core = lock(&self.core);
        let ut = valid_user_type(&value.type_())?;
        let core = &mut *core;
        let mut b = EncBuf::with_space();
        let mut ctx = Ctx {
            sent: &mut core.sent,
        };
        let mut out = Out::Conn(&mut *core.w);
        ctx.send_type_descriptor(&mut out, &mut b, &ut)?;
        ctx.send_type_id(&mut b, &ut);
        ctx.encode(&mut out, &mut b, value, &ut)?;
        out.write_message(&mut b)
    }
}
