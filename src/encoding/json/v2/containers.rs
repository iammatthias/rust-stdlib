//! The default arshalers of byte strings, slices, arrays, pointers and maps,
//! ported from Go's `arshal_default.go`.
//!
//! Rust has no nil slice or map: an empty `Vec` or map stands for both Go's
//! nil and its empty value (`omitzero` omits it and `FormatNilSliceAsNull`
//! and `FormatNilMapAsNull` write it as `null`), and a pointer is an
//! `Option`.
use std::any::TypeId;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::hash::{BuildHasher, Hash};

use super::arshal::{marshal_value, unmarshal_value, MarshalTo, UnmarshalFrom};
use super::errors::{
    duplicate_name_error_at, err_array_overflow, err_array_underflow, err_invalid_string_tag,
    marshal_error_before, unmarshal_error_after, unmarshal_error_before,
};
use super::scalars::{
    invalid_format_error_dec, invalid_format_error_enc, reject_tags_dec, reject_tags_enc,
};
use super::typeinfo::{TypeInfo, TypeKind};
use crate::encoding::json::jsontext::flags;
use crate::encoding::json::jsontext::{
    self, wire, Decoder, Encoder, Error, Value, ValueFlags, KIND_BEGIN_ARRAY, KIND_BEGIN_OBJECT,
    KIND_NULL, KIND_STRING,
};
use crate::encoding::json::Bytes;
use crate::encoding::{base32, base64, hex};

// ------------------------------------------------------------------ bytes

fn encode_bytes(format: &str, src: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    match format {
        "base64" => out = base64::STANDARD.encode_to_vec(src),
        "base64url" => out = base64::URL_SAFE.encode_to_vec(src),
        "base32" => out = base32::STANDARD.encode_to_vec(src),
        "base32hex" => out = base32::HEX.encode_to_vec(src),
        "base16" | "hex" => hex::encode_into(src, &mut out),
        _ => return None,
    }
    Some(out)
}

type DecodeResult = (Vec<u8>, usize, Result<(), Error>);

fn decode_bytes(format: &str, src: &[u8]) -> Option<DecodeResult> {
    let mut out = Vec::new();
    let (res, encoded_len): (Result<(), Error>, fn(usize) -> usize) = match format {
        "base64" => (
            base64::STANDARD
                .decode_into(src, &mut out)
                .map_err(Error::other),
            |n| base64::STANDARD.encoded_len(n),
        ),
        "base64url" => (
            base64::URL_SAFE
                .decode_into(src, &mut out)
                .map_err(Error::other),
            |n| base64::URL_SAFE.encoded_len(n),
        ),
        "base32" => (
            base32::STANDARD
                .decode_into(src, &mut out)
                .map_err(Error::other),
            |n| base32::STANDARD.encoded_len(n),
        ),
        "base32hex" => (
            base32::HEX.decode_into(src, &mut out).map_err(Error::other),
            |n| base32::HEX.encoded_len(n),
        ),
        "base16" | "hex" => (
            hex::decode_into(src, &mut out).map_err(Error::other),
            hex::encoded_len,
        ),
        _ => return None,
    };
    let n = encoded_len(out.len());
    Some((out, n, res))
}

impl MarshalTo for Bytes {
    fn type_info() -> TypeInfo {
        TypeInfo::of::<Bytes>("[]uint8", TypeKind::Slice)
    }
    fn marshal_default(&self, enc: &mut Encoder<'_>) -> Result<(), Error> {
        let t = <Self as MarshalTo>::type_info();
        let mut format = "base64".to_string();
        if enc
            .s
            .opts
            .flags
            .has(flags::TAG_FLAGS | flags::FORMAT_NIL_SLICE_AS_NULL)
        {
            if enc.s.opts.flags.get(flags::STRING_TAG) {
                return Err(marshal_error_before(
                    enc,
                    Some(t),
                    Some(err_invalid_string_tag()),
                ));
            } else if enc.s.opts.flags.has(flags::FORMAT_TAG) {
                format = enc.s.opts.format.clone();
                if format == "array" {
                    enc.s.opts.flags.clear(flags::FORMAT_TAG);
                    return marshal_seq(enc, &t, self.0.iter(), self.0.len(), false);
                }
                if encode_bytes(&format, &[]).is_none() {
                    return Err(invalid_format_error_enc(enc, t));
                }
            }
            if enc.s.opts.flags.get(flags::FORMAT_NIL_SLICE_AS_NULL) && self.0.is_empty() {
                return enc.write_token(&jsontext::null());
            }
        }
        let text = encode_bytes(&format, &self.0).expect("format checked above");
        enc.s.append_raw(KIND_STRING, true, |b| {
            b.extend_from_slice(&text);
            Ok(())
        })
    }
    fn is_zero_value(&self) -> bool {
        self.0.is_empty()
    }
    fn is_empty_value(&self) -> Option<bool> {
        Some(self.0.is_empty())
    }
}

impl UnmarshalFrom for Bytes {
    fn type_info() -> TypeInfo {
        TypeInfo::of::<Bytes>("[]uint8", TypeKind::Slice)
    }
    fn zero() -> Self {
        Bytes(Vec::new())
    }
    fn set_zero(&mut self) {
        self.0.clear();
    }
    fn unmarshal_default(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error> {
        let t = <Self as UnmarshalFrom>::type_info();
        let mut format = "base64".to_string();
        if dec.s.opts.flags.has(flags::TAG_FLAGS) {
            if dec.s.opts.flags.get(flags::STRING_TAG) {
                return Err(unmarshal_error_before(
                    dec,
                    Some(t),
                    Some(err_invalid_string_tag()),
                ));
            } else if dec.s.opts.flags.has(flags::FORMAT_TAG) {
                format = dec.s.opts.format.clone();
                if format == "array" {
                    dec.s.opts.flags.clear(flags::FORMAT_TAG);
                    let mut v: Vec<u8> = std::mem::take(&mut self.0);
                    let r = unmarshal_vec(&mut v, dec, &t);
                    self.0 = v;
                    return r;
                }
                if decode_bytes(&format, &[]).is_none() {
                    return Err(invalid_format_error_dec(dec, t));
                }
            }
        }
        let mut vf = ValueFlags::default();
        let val = dec.s.read_value(&mut vf)?;
        match Value(val.clone()).kind() {
            KIND_NULL => {
                self.0.clear();
                Ok(())
            }
            KIND_STRING => {
                let val = wire::unquote_may_copy(&val, vf.is_verbatim());
                let (b, encoded_len, res) = decode_bytes(&format, &val).expect("format checked");
                if let Err(e) = res {
                    return Err(unmarshal_error_after(dec, Some(t), Some(e)));
                }
                if val.len() != encoded_len {
                    let i = val
                        .iter()
                        .position(|&c| c == b'\r' || c == b'\n')
                        .unwrap_or(0);
                    let err = Error::msg(&format!(
                        "illegal character {} at offset {}",
                        wire::quote_rune(&val[i..]),
                        i
                    ));
                    return Err(unmarshal_error_after(dec, Some(t), Some(err)));
                }
                self.0 = b;
                Ok(())
            }
            _ => Err(unmarshal_error_after(dec, Some(t), None)),
        }
    }
}

// ----------------------------------------------------------------- slices

fn marshal_seq<'a, T: MarshalTo + 'a>(
    enc: &mut Encoder<'_>,
    t: &TypeInfo,
    items: impl Iterator<Item = &'a T>,
    n: usize,
    is_slice: bool,
) -> Result<(), Error> {
    if is_slice {
        let mut emit_null = enc.s.opts.flags.get(flags::FORMAT_NIL_SLICE_AS_NULL);
        if enc.s.opts.flags.has(flags::TAG_FLAGS) {
            if enc.s.opts.flags.get(flags::STRING_TAG) {
                return Err(marshal_error_before(
                    enc,
                    Some(t.clone()),
                    Some(err_invalid_string_tag()),
                ));
            }
            if enc.s.opts.flags.has(flags::FORMAT_TAG) {
                match enc.s.opts.format.as_str() {
                    "emitnull" => emit_null = true,
                    "emitempty" => emit_null = false,
                    _ => return Err(invalid_format_error_enc(enc, t.clone())),
                }
            }
        }
        if n == 0 && emit_null {
            return enc.write_token(&jsontext::null());
        }
    } else {
        reject_tags_enc(enc, t)?;
    }
    enc.write_token(&jsontext::begin_array())?;
    for item in items {
        marshal_value(enc, item)?;
    }
    enc.write_token(&jsontext::end_array())
}

impl<T: MarshalTo> MarshalTo for Vec<T> {
    fn type_info() -> TypeInfo {
        TypeInfo::of::<Vec<T>>(&format!("[]{}", T::type_info().name), TypeKind::Slice)
            .with_elem(T::type_info())
    }
    fn marshal_default(&self, enc: &mut Encoder<'_>) -> Result<(), Error> {
        marshal_seq(
            enc,
            &<Self as MarshalTo>::type_info(),
            self.iter(),
            self.len(),
            true,
        )
    }
    fn is_zero_value(&self) -> bool {
        self.is_empty()
    }
    fn is_empty_value(&self) -> Option<bool> {
        Some(self.is_empty())
    }
}

fn unmarshal_vec<T: UnmarshalFrom>(
    v: &mut Vec<T>,
    dec: &mut Decoder<'_>,
    t: &TypeInfo,
) -> Result<(), Error> {
    if dec.s.opts.flags.has(flags::TAG_FLAGS) {
        if dec.s.opts.flags.get(flags::STRING_TAG) {
            return Err(unmarshal_error_before(
                dec,
                Some(t.clone()),
                Some(err_invalid_string_tag()),
            ));
        }
        if dec.s.opts.flags.has(flags::FORMAT_TAG)
            && !matches!(dec.s.opts.format.as_str(), "emitnull" | "emitempty")
        {
            return Err(invalid_format_error_dec(dec, t.clone()));
        }
    }
    let tok = dec.read_token()?;
    match tok.kind() {
        KIND_NULL => {
            v.clear();
            Ok(())
        }
        KIND_BEGIN_ARRAY => {
            let mut i = 0usize;
            while dec.peek_kind() != jsontext::KIND_END_ARRAY {
                if i == v.len() {
                    v.push(T::zero());
                } else {
                    v[i].set_zero();
                }
                i += 1;
                if let Err(e) = unmarshal_value(dec, &mut v[i - 1]) {
                    v.truncate(i);
                    return Err(e);
                }
            }
            v.truncate(i);
            dec.read_token()?;
            Ok(())
        }
        _ => Err(unmarshal_error_after(dec, Some(t.clone()), None)),
    }
}

impl<T: UnmarshalFrom> UnmarshalFrom for Vec<T> {
    fn type_info() -> TypeInfo {
        TypeInfo::of::<Vec<T>>(
            &format!("[]{}", <T as UnmarshalFrom>::type_info().name),
            TypeKind::Slice,
        )
        .with_elem(<T as UnmarshalFrom>::type_info())
    }
    fn zero() -> Self {
        Vec::new()
    }
    fn set_zero(&mut self) {
        self.clear();
    }
    fn unmarshal_default(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error> {
        let t = <Self as UnmarshalFrom>::type_info();
        unmarshal_vec(self, dec, &t)
    }
}

// ----------------------------------------------------------------- arrays

impl<T: MarshalTo, const N: usize> MarshalTo for [T; N] {
    fn type_info() -> TypeInfo {
        TypeInfo::of::<[T; N]>(&format!("[{N}]{}", T::type_info().name), TypeKind::Array)
            .with_elem(T::type_info())
    }
    fn marshal_default(&self, enc: &mut Encoder<'_>) -> Result<(), Error> {
        marshal_seq(
            enc,
            &<Self as MarshalTo>::type_info(),
            self.iter(),
            N,
            false,
        )
    }
    fn is_zero_value(&self) -> bool {
        self.iter().all(|e| e.is_zero_value())
    }
    fn is_empty_value(&self) -> Option<bool> {
        Some(N == 0)
    }
}

impl<T: UnmarshalFrom, const N: usize> UnmarshalFrom for [T; N] {
    fn type_info() -> TypeInfo {
        TypeInfo::of::<[T; N]>(
            &format!("[{N}]{}", <T as UnmarshalFrom>::type_info().name),
            TypeKind::Array,
        )
        .with_elem(<T as UnmarshalFrom>::type_info())
    }
    fn zero() -> Self {
        std::array::from_fn(|_| T::zero())
    }
    fn set_zero(&mut self) {
        for e in self.iter_mut() {
            e.set_zero();
        }
    }
    fn unmarshal_default(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error> {
        let t = <Self as UnmarshalFrom>::type_info();
        reject_tags_dec(dec, &t)?;
        let tok = dec.read_token()?;
        match tok.kind() {
            KIND_NULL => {
                self.set_zero();
                Ok(())
            }
            KIND_BEGIN_ARRAY => {
                let mut i = 0usize;
                let mut err: Option<Error> = None;
                while dec.peek_kind() != jsontext::KIND_END_ARRAY {
                    if i >= N {
                        dec.skip_value()?;
                        err = Some(err_array_overflow());
                        continue;
                    }
                    self[i].set_zero();
                    unmarshal_value(dec, &mut self[i])?;
                    i += 1;
                }
                while i < N {
                    self[i].set_zero();
                    err = Some(err_array_underflow());
                    i += 1;
                }
                dec.read_token()?;
                if let Some(e) = err {
                    return Err(unmarshal_error_after(dec, Some(t), Some(e)));
                }
                Ok(())
            }
            _ => Err(unmarshal_error_after(dec, Some(t), None)),
        }
    }
}

// --------------------------------------------------------------- pointers

impl<T: MarshalTo> MarshalTo for Option<T> {
    fn type_info() -> TypeInfo {
        TypeInfo::of::<Option<T>>(&format!("*{}", T::type_info().name), TypeKind::Pointer)
            .with_elem(T::type_info())
    }
    fn marshal_default(&self, enc: &mut Encoder<'_>) -> Result<(), Error> {
        match self {
            None => enc.write_token(&jsontext::null()),
            Some(v) => marshal_value(enc, v),
        }
    }
    fn is_zero_value(&self) -> bool {
        self.is_none()
    }
    fn is_empty_value(&self) -> Option<bool> {
        Some(self.is_none())
    }
    fn marshal_to(&self, enc: &mut Encoder<'_>) -> Result<(), Error> {
        // Pointers have no methods of their own: the pointee's apply.
        self.marshal_default(enc)
    }
    fn struct_desc() -> Option<super::structs::StructDesc> {
        T::struct_desc()
    }
    fn as_fallback(&self) -> Option<&dyn super::structs::FallbackMarshal> {
        self.as_ref()?.as_fallback()
    }
}

impl<T: UnmarshalFrom> UnmarshalFrom for Option<T> {
    fn type_info() -> TypeInfo {
        TypeInfo::of::<Option<T>>(
            &format!("*{}", <T as UnmarshalFrom>::type_info().name),
            TypeKind::Pointer,
        )
        .with_elem(<T as UnmarshalFrom>::type_info())
    }
    fn zero() -> Self {
        None
    }
    fn set_zero(&mut self) {
        *self = None;
    }
    fn unmarshal_default(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error> {
        if dec.peek_kind() == KIND_NULL {
            dec.read_token()?;
            *self = None;
            return Ok(());
        }
        if self.is_none() {
            *self = Some(T::zero());
        }
        unmarshal_value(dec, self.as_mut().expect("allocated above"))
    }
    fn unmarshal_from(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error> {
        self.unmarshal_default(dec)
    }
    fn struct_desc() -> Option<super::structs::StructDesc> {
        <T as UnmarshalFrom>::struct_desc()
    }
    fn as_fallback_mut(&mut self) -> Option<&mut dyn super::structs::FallbackUnmarshal> {
        if self.is_none() {
            *self = Some(T::zero());
        }
        self.as_mut()?.as_fallback_mut()
    }
}

impl<T: MarshalTo> MarshalTo for Box<T> {
    fn type_info() -> TypeInfo {
        TypeInfo::of::<Box<T>>(&format!("*{}", T::type_info().name), TypeKind::Pointer)
            .with_elem(T::type_info())
    }
    fn marshal_default(&self, enc: &mut Encoder<'_>) -> Result<(), Error> {
        marshal_value(enc, &**self)
    }
    fn is_zero_value(&self) -> bool {
        false
    }
    fn is_empty_value(&self) -> Option<bool> {
        Some(false)
    }
    fn marshal_to(&self, enc: &mut Encoder<'_>) -> Result<(), Error> {
        self.marshal_default(enc)
    }
    fn struct_desc() -> Option<super::structs::StructDesc> {
        T::struct_desc()
    }
    fn as_fallback(&self) -> Option<&dyn super::structs::FallbackMarshal> {
        (**self).as_fallback()
    }
}

impl<T: UnmarshalFrom> UnmarshalFrom for Box<T> {
    fn type_info() -> TypeInfo {
        TypeInfo::of::<Box<T>>(
            &format!("*{}", <T as UnmarshalFrom>::type_info().name),
            TypeKind::Pointer,
        )
        .with_elem(<T as UnmarshalFrom>::type_info())
    }
    fn zero() -> Self {
        Box::new(T::zero())
    }
    fn set_zero(&mut self) {
        (**self).set_zero();
    }
    fn unmarshal_default(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error> {
        if dec.peek_kind() == KIND_NULL {
            dec.read_token()?;
            (**self).set_zero();
            return Ok(());
        }
        unmarshal_value(dec, &mut **self)
    }
    fn unmarshal_from(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error> {
        self.unmarshal_default(dec)
    }
    fn struct_desc() -> Option<super::structs::StructDesc> {
        <T as UnmarshalFrom>::struct_desc()
    }
    fn as_fallback_mut(&mut self) -> Option<&mut dyn super::structs::FallbackUnmarshal> {
        (**self).as_fallback_mut()
    }
}

// ------------------------------------------------------------------- maps

/// Whether the key kind always has a unique JSON representation, so the
/// encoder need not check names for duplicates.
fn map_key_with_unique_representation(k: TypeKind, allow_invalid_utf8: bool) -> bool {
    match k {
        TypeKind::Bool
        | TypeKind::Int
        | TypeKind::Int8
        | TypeKind::Int16
        | TypeKind::Int32
        | TypeKind::Int64
        | TypeKind::Uint
        | TypeKind::Uint8
        | TypeKind::Uint16
        | TypeKind::Uint32
        | TypeKind::Uint64
        | TypeKind::Uintptr => true,
        TypeKind::String => !allow_invalid_utf8,
        _ => false,
    }
}

fn marshal_map<K: MarshalTo, V: MarshalTo>(
    enc: &mut Encoder<'_>,
    t: &TypeInfo,
    entries: Vec<(&K, &V)>,
) -> Result<(), Error> {
    let mut emit_null = enc.s.opts.flags.get(flags::FORMAT_NIL_MAP_AS_NULL);
    if enc.s.opts.flags.has(flags::TAG_FLAGS) {
        if enc.s.opts.flags.get(flags::STRING_TAG) {
            return Err(marshal_error_before(
                enc,
                Some(t.clone()),
                Some(err_invalid_string_tag()),
            ));
        }
        if enc.s.opts.flags.has(flags::FORMAT_TAG) {
            match enc.s.opts.format.as_str() {
                "emitnull" => emit_null = true,
                "emitempty" => emit_null = false,
                _ => return Err(invalid_format_error_enc(enc, t.clone())),
            }
        }
    }
    let n = entries.len();
    if n == 0 && emit_null {
        return enc.write_token(&jsontext::null());
    }
    enc.write_token(&jsontext::begin_object())?;
    if n > 0 {
        let key_kind = K::type_info().kind;
        let non_default_key = entries[0].0.has_methods()
            || enc
                .s
                .opts
                .marshalers
                .as_ref()
                .is_some_and(|m| !m.lookup(TypeId::of::<K>()).is_empty());
        if !non_default_key
            && map_key_with_unique_representation(
                key_kind,
                enc.s.opts.flags.get(flags::ALLOW_INVALID_UTF8),
            )
        {
            enc.s.state.tokens.last.disable_namespace();
        }
        let deterministic = enc.s.opts.flags.get(flags::DETERMINISTIC);
        if !deterministic || n <= 1 {
            for (k, v) in entries {
                marshal_map_key(enc, k)?;
                marshal_value(enc, v)?;
            }
        } else if !non_default_key
            && key_kind == TypeKind::String
            && entries[0].0.as_str_key().is_some()
        {
            let mut entries = entries;
            entries.sort_by(|a, b| {
                a.0.as_str_key()
                    .unwrap_or("")
                    .cmp(b.0.as_str_key().unwrap_or(""))
            });
            for (k, v) in entries {
                enc.write_token(&jsontext::string(k.as_str_key().unwrap_or("")))?;
                marshal_value(enc, v)?;
            }
        } else {
            let mut members: Vec<(Vec<u8>, &V)> = Vec::with_capacity(n);
            for (k, v) in entries {
                marshal_map_key(enc, k)?;
                let name = enc.s.unwrite_only_object_member_name();
                members.push((name, v));
            }
            members.sort_by(|a, b| a.0.cmp(&b.0));
            for (name, v) in members {
                enc.write_token(&jsontext::string_bytes(&name))?;
                marshal_value(enc, v)?;
            }
        }
    }
    enc.write_token(&jsontext::end_object())
}

fn marshal_map_key<K: MarshalTo>(enc: &mut Encoder<'_>, k: &K) -> Result<(), Error> {
    match marshal_value(enc, k) {
        Err(Error::Syntactic(s)) if matches!(s.err, Some(Error::NonStringName)) => Err(
            marshal_error_before(enc, Some(K::type_info()), Some(Error::Syntactic(s))),
        ),
        other => other,
    }
}

/// What the generic map unmarshaler needs from a map.
trait MapAccess<K, V> {
    type Seen: Default;
    fn len(&self) -> usize;
    fn take(&mut self, k: &K) -> Option<V>;
    fn put(&mut self, k: K, v: V);
    fn clear(&mut self);
    fn seen_has(seen: &Self::Seen, k: &K) -> bool;
    fn seen_add(seen: &mut Self::Seen, k: K);
}

impl<K: Ord, V> MapAccess<K, V> for BTreeMap<K, V> {
    type Seen = BTreeSet<K>;
    fn len(&self) -> usize {
        BTreeMap::len(self)
    }
    fn take(&mut self, k: &K) -> Option<V> {
        self.remove(k)
    }
    fn put(&mut self, k: K, v: V) {
        self.insert(k, v);
    }
    fn clear(&mut self) {
        BTreeMap::clear(self)
    }
    fn seen_has(seen: &BTreeSet<K>, k: &K) -> bool {
        seen.contains(k)
    }
    fn seen_add(seen: &mut BTreeSet<K>, k: K) {
        seen.insert(k);
    }
}

impl<K: Hash + Eq, V, S: BuildHasher + Default> MapAccess<K, V> for HashMap<K, V, S> {
    type Seen = HashSet<K>;
    fn len(&self) -> usize {
        HashMap::len(self)
    }
    fn take(&mut self, k: &K) -> Option<V> {
        self.remove(k)
    }
    fn put(&mut self, k: K, v: V) {
        self.insert(k, v);
    }
    fn clear(&mut self) {
        HashMap::clear(self)
    }
    fn seen_has(seen: &HashSet<K>, k: &K) -> bool {
        seen.contains(k)
    }
    fn seen_add(seen: &mut HashSet<K>, k: K) {
        seen.insert(k);
    }
}

fn unmarshal_map<K, V, M>(map: &mut M, dec: &mut Decoder<'_>, t: &TypeInfo) -> Result<(), Error>
where
    K: UnmarshalFrom + Clone,
    V: UnmarshalFrom,
    M: MapAccess<K, V>,
{
    if dec.s.opts.flags.has(flags::TAG_FLAGS) {
        if dec.s.opts.flags.get(flags::STRING_TAG) {
            return Err(unmarshal_error_before(
                dec,
                Some(t.clone()),
                Some(err_invalid_string_tag()),
            ));
        }
        if dec.s.opts.flags.has(flags::FORMAT_TAG)
            && !matches!(dec.s.opts.format.as_str(), "emitnull" | "emitempty")
        {
            return Err(invalid_format_error_dec(dec, t.clone()));
        }
    }
    let tok = dec.read_token()?;
    match tok.kind() {
        KIND_NULL => {
            map.clear();
            Ok(())
        }
        KIND_BEGIN_OBJECT => {
            let mut probe = K::zero();
            let non_default_key = probe.has_methods()
                || dec
                    .s
                    .opts
                    .unmarshalers
                    .as_ref()
                    .is_some_and(|u| !u.lookup(TypeId::of::<K>()).is_empty());
            if !non_default_key
                && map_key_with_unique_representation(
                    <K as UnmarshalFrom>::type_info().kind,
                    dec.s.opts.flags.get(flags::ALLOW_INVALID_UTF8),
                )
            {
                dec.s.state.tokens.last.disable_namespace();
            }
            probe.set_zero();
            let allow_dup = dec.s.opts.flags.get(flags::ALLOW_DUPLICATE_NAMES);
            let mut seen: Option<M::Seen> = (!allow_dup && map.len() > 0).then(M::Seen::default);
            while dec.peek_kind() != jsontext::KIND_END_OBJECT {
                let mut k = K::zero();
                unmarshal_value(dec, &mut k)?;
                let existing = map.take(&k);
                let mut v = match existing {
                    Some(v2) => {
                        if !allow_dup && seen.as_ref().is_none_or(|s| M::seen_has(s, &k)) {
                            map.put(k, v2);
                            let name_len = dec.s.previous_token_or_value().len() as i64;
                            let mut ptr = Vec::new();
                            dec.s.append_stack_pointer(&mut ptr, -1);
                            return Err(duplicate_name_error_at(
                                jsontext::Pointer::from(String::from_utf8_lossy(&ptr).into_owned()),
                                None,
                                dec.input_offset() - name_len,
                            ));
                        }
                        v2
                    }
                    None => V::zero(),
                };
                let r = unmarshal_value(dec, &mut v);
                map.put(k.clone(), v);
                if let Some(s) = &mut seen {
                    M::seen_add(s, k);
                }
                r?;
            }
            dec.read_token()?;
            Ok(())
        }
        _ => Err(unmarshal_error_after(dec, Some(t.clone()), None)),
    }
}

impl<K: MarshalTo, V: MarshalTo> MarshalTo for BTreeMap<K, V> {
    fn type_info() -> TypeInfo {
        TypeInfo::of::<BTreeMap<K, V>>(
            &format!("map[{}]{}", K::type_info().name, V::type_info().name),
            TypeKind::Map,
        )
        .with_key(K::type_info())
        .with_elem(V::type_info())
    }
    fn marshal_default(&self, enc: &mut Encoder<'_>) -> Result<(), Error> {
        marshal_map(
            enc,
            &<Self as MarshalTo>::type_info(),
            self.iter().collect(),
        )
    }
    fn is_zero_value(&self) -> bool {
        self.is_empty()
    }
    fn is_empty_value(&self) -> Option<bool> {
        Some(self.is_empty())
    }
    fn as_fallback(&self) -> Option<&dyn super::structs::FallbackMarshal> {
        Some(self)
    }
}

impl<K: MarshalTo, V: MarshalTo> super::structs::FallbackMarshal for BTreeMap<K, V> {
    fn marshal_all(
        &self,
        enc: &mut Encoder<'_>,
        insert: Option<super::structs::InsertName<'_>>,
    ) -> Result<(), Error> {
        super::structs::marshal_map_fallback(enc, self.iter().collect(), insert)
    }
}

impl<K: UnmarshalFrom + Ord + Clone, V: UnmarshalFrom> super::structs::FallbackUnmarshal
    for BTreeMap<K, V>
{
    fn unmarshal_next(
        &mut self,
        dec: &mut Decoder<'_>,
        _quoted_name: &[u8],
        unquoted_name: &[u8],
    ) -> Result<(), Error> {
        let name = String::from_utf8_lossy(unquoted_name).into_owned();
        let Some(k) = K::from_str_key(&name) else {
            return dec.skip_value();
        };
        let mut v = self.remove(&k).unwrap_or_else(V::zero);
        let r = unmarshal_value(dec, &mut v);
        self.insert(k, v);
        r
    }
}

impl<K: UnmarshalFrom + Ord + Clone, V: UnmarshalFrom> UnmarshalFrom for BTreeMap<K, V> {
    fn as_fallback_mut(&mut self) -> Option<&mut dyn super::structs::FallbackUnmarshal> {
        Some(self)
    }
    fn type_info() -> TypeInfo {
        TypeInfo::of::<BTreeMap<K, V>>(
            &format!(
                "map[{}]{}",
                <K as UnmarshalFrom>::type_info().name,
                <V as UnmarshalFrom>::type_info().name
            ),
            TypeKind::Map,
        )
        .with_key(<K as UnmarshalFrom>::type_info())
        .with_elem(<V as UnmarshalFrom>::type_info())
    }
    fn zero() -> Self {
        BTreeMap::new()
    }
    fn set_zero(&mut self) {
        self.clear();
    }
    fn unmarshal_default(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error> {
        let t = <Self as UnmarshalFrom>::type_info();
        unmarshal_map::<K, V, Self>(self, dec, &t)
    }
}

impl<K: MarshalTo, V: MarshalTo, S: 'static> MarshalTo for HashMap<K, V, S> {
    fn type_info() -> TypeInfo {
        TypeInfo::of::<HashMap<K, V, S>>(
            &format!("map[{}]{}", K::type_info().name, V::type_info().name),
            TypeKind::Map,
        )
        .with_key(K::type_info())
        .with_elem(V::type_info())
    }
    fn marshal_default(&self, enc: &mut Encoder<'_>) -> Result<(), Error> {
        marshal_map(
            enc,
            &<Self as MarshalTo>::type_info(),
            self.iter().collect(),
        )
    }
    fn is_zero_value(&self) -> bool {
        self.is_empty()
    }
    fn is_empty_value(&self) -> Option<bool> {
        Some(self.is_empty())
    }
}

impl<K, V, S> UnmarshalFrom for HashMap<K, V, S>
where
    K: UnmarshalFrom + Hash + Eq + Clone,
    V: UnmarshalFrom,
    S: BuildHasher + Default + 'static,
{
    fn type_info() -> TypeInfo {
        TypeInfo::of::<HashMap<K, V, S>>(
            &format!(
                "map[{}]{}",
                <K as UnmarshalFrom>::type_info().name,
                <V as UnmarshalFrom>::type_info().name
            ),
            TypeKind::Map,
        )
        .with_key(<K as UnmarshalFrom>::type_info())
        .with_elem(<V as UnmarshalFrom>::type_info())
    }
    fn zero() -> Self {
        HashMap::default()
    }
    fn set_zero(&mut self) {
        self.clear();
    }
    fn unmarshal_default(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error> {
        let t = <Self as UnmarshalFrom>::type_info();
        unmarshal_map::<K, V, Self>(self, dec, &t)
    }
}
