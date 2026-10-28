//! HPACK (RFC 7541) header compression: the static and dynamic tables, the
//! Huffman code, and an encoder and decoder that follow Go's
//! `golang.org/x/net/http2/hpack` byte for byte.
//!
//! The codec is pure: it works on byte slices and `Vec<u8>` and knows nothing
//! about connections or threads. Names and values are opaque octet strings,
//! as in Go.
use super::hpack_tables::{HUFFMAN_CODES, HUFFMAN_CODE_LEN, STATIC_TABLE};
use std::{
    collections::{HashMap, VecDeque},
    fmt,
    sync::LazyLock,
};

/// Go's `hpack.HeaderField`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeaderField {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    /// Sensitive fields are never indexed.
    pub sensitive: bool,
}

impl HeaderField {
    pub fn new(name: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> Self {
        Self {
            name: name.as_ref().to_vec(),
            value: value.as_ref().to_vec(),
            sensitive: false,
        }
    }
    /// Go's `IsPseudo`: the name starts with a colon.
    pub fn is_pseudo(&self) -> bool {
        self.name.first() == Some(&b':')
    }
    /// Go's `Size`: the entry size of RFC 7541 section 4.1.
    pub fn size(&self) -> u32 {
        (self.name.len() + self.value.len() + 32) as u32
    }
    /// The name as text (lossy for non-UTF-8 octets).
    pub fn name_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.name)
    }
    /// The value as text (lossy for non-UTF-8 octets).
    pub fn value_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.value)
    }
}

impl fmt::Display for HeaderField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "header field {:?} = {:?}{}",
            self.name_str(),
            self.value_str(),
            if self.sensitive { " (sensitive)" } else { "" }
        )
    }
}

/// The errors of Go's hpack package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HpackError {
    /// Go's `DecodingError`.
    Decoding(String),
    /// Go's `InvalidIndexError`.
    InvalidIndex(u64),
    /// Go's `ErrStringLength`.
    StringLength,
    /// Go's `ErrInvalidHuffman`.
    InvalidHuffman,
}

impl fmt::Display for HpackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decoding(s) => write!(f, "decoding error: {s}"),
            Self::InvalidIndex(i) => {
                write!(
                    f,
                    "decoding error: invalid indexed representation index {i}"
                )
            }
            Self::StringLength => f.write_str("hpack: string too long"),
            Self::InvalidHuffman => f.write_str("hpack: invalid Huffman-encoded data"),
        }
    }
}
impl std::error::Error for HpackError {}

const UINT32_MAX: u32 = u32::MAX;
const INITIAL_HEADER_TABLE_SIZE: u32 = 4096;

// ---------------------------------------------------------------- tables

type Pair = (Vec<u8>, Vec<u8>);

/// Go's `headerFieldTable`.
#[derive(Default)]
struct FieldTable {
    ents: VecDeque<HeaderField>,
    evict_count: u64,
    by_name: HashMap<Vec<u8>, u64>,
    by_name_value: HashMap<Pair, u64>,
}

impl FieldTable {
    fn len(&self) -> usize {
        self.ents.len()
    }
    fn add_entry(&mut self, f: HeaderField) {
        let id = self.len() as u64 + self.evict_count + 1;
        self.by_name.insert(f.name.clone(), id);
        self.by_name_value
            .insert((f.name.clone(), f.value.clone()), id);
        self.ents.push_back(f);
    }
    fn evict_oldest(&mut self, n: usize) {
        for k in 0..n {
            let id = self.evict_count + k as u64 + 1;
            let f = &self.ents[k];
            if self.by_name.get(&f.name) == Some(&id) {
                self.by_name.remove(&f.name);
            }
            let p = (f.name.clone(), f.value.clone());
            if self.by_name_value.get(&p) == Some(&id) {
                self.by_name_value.remove(&p);
            }
        }
        self.ents.drain(..n);
        self.evict_count += n as u64;
    }
    /// Go's `search`. `is_static` selects the static index numbering.
    fn search(&self, f: &HeaderField, is_static: bool) -> (u64, bool) {
        if !f.sensitive {
            if let Some(&id) = self.by_name_value.get(&(f.name.clone(), f.value.clone())) {
                return (self.id_to_index(id, is_static), true);
            }
        }
        if let Some(&id) = self.by_name.get(&f.name) {
            return (self.id_to_index(id, is_static), false);
        }
        (0, false)
    }
    fn id_to_index(&self, id: u64, is_static: bool) -> u64 {
        let k = id - self.evict_count - 1;
        if !is_static {
            return self.len() as u64 - k;
        }
        k + 1
    }
}

static STATIC: LazyLock<FieldTable> = LazyLock::new(|| {
    let mut t = FieldTable::default();
    for (n, v) in STATIC_TABLE {
        t.add_entry(HeaderField::new(n, v));
    }
    t
});

/// Go's `dynamicTable`.
#[derive(Default)]
struct DynamicTable {
    table: FieldTable,
    size: u32,
    max_size: u32,
    allowed_max_size: u32,
}

impl DynamicTable {
    fn set_max_size(&mut self, v: u32) {
        self.max_size = v;
        self.evict();
    }
    fn add(&mut self, f: HeaderField) {
        self.size = self.size.wrapping_add(f.size());
        self.table.add_entry(f);
        self.evict();
    }
    fn evict(&mut self) {
        let mut n = 0;
        while self.size > self.max_size && n < self.table.len() {
            self.size -= self.table.ents[n].size();
            n += 1;
        }
        self.table.evict_oldest(n);
    }
}

// --------------------------------------------------------------- huffman

/// A leaf is `LEAF | code_len << 8 | sym`; an internal node is an index into
/// the arena (index 0 is the root and is never a child, so 0 means absent).
const LEAF: u32 = 1 << 31;

static HUFFMAN_TREE: LazyLock<Vec<[u32; 256]>> = LazyLock::new(|| {
    let mut arena: Vec<[u32; 256]> = vec![[0; 256]];
    for (sym, &code) in HUFFMAN_CODES.iter().enumerate() {
        let mut code_len = HUFFMAN_CODE_LEN[sym];
        let mut cur = 0usize;
        while code_len > 8 {
            code_len -= 8;
            let i = (code >> code_len) as u8 as usize;
            if arena[cur][i] == 0 {
                arena.push([0; 256]);
                let idx = (arena.len() - 1) as u32;
                arena[cur][i] = idx;
            }
            cur = arena[cur][i] as usize;
        }
        let shift = 8 - code_len;
        let start = ((code << shift) as u8) as usize;
        let end = 1usize << shift;
        arena[cur][start..start + end].fill(LEAF | (u32::from(code_len) << 8) | sym as u32);
    }
    arena
});

/// Go's `HuffmanEncodeLength`: bytes needed to Huffman-encode `s`.
pub fn huffman_encode_length(s: &[u8]) -> u64 {
    let n: u64 = s
        .iter()
        .map(|&c| u64::from(HUFFMAN_CODE_LEN[c as usize]))
        .sum();
    n.div_ceil(8)
}

/// Go's `AppendHuffmanString`.
pub fn append_huffman_string(dst: &mut Vec<u8>, s: &[u8]) {
    let mut acc: u64 = 0;
    let mut nbits: u32 = 0;
    for &c in s {
        let l = u32::from(HUFFMAN_CODE_LEN[c as usize]);
        acc = (acc << l) | u64::from(HUFFMAN_CODES[c as usize]);
        nbits += l;
        while nbits >= 8 {
            nbits -= 8;
            dst.push((acc >> nbits) as u8);
        }
    }
    if nbits > 0 {
        let pad = 8 - nbits;
        // EOS prefix padding: all one bits.
        let v = (acc << pad) | ((1u64 << pad) - 1);
        dst.push(v as u8);
    }
}

/// Go's `HuffmanDecode`/`huffmanDecode`: appends the expansion of `v` to
/// `out`. `max_len` of 0 means unlimited.
pub fn huffman_decode(out: &mut Vec<u8>, max_len: usize, v: &[u8]) -> Result<(), HpackError> {
    let tree = &*HUFFMAN_TREE;
    let start_len = out.len();
    let produced = |out: &Vec<u8>| out.len() - start_len;
    let mut n: usize = 0;
    let (mut cur, mut cbits, mut sbits) = (0u64, 0u8, 0u8);
    let leaf = |e: u32| -> (u8, u8) { ((e >> 8) as u8, e as u8) };
    for &b in v {
        cur = (cur << 8) | u64::from(b);
        cbits += 8;
        sbits = sbits.wrapping_add(8);
        while cbits >= 8 {
            let idx = (cur >> (cbits - 8)) as u8 as usize;
            let e = tree[n][idx];
            if e == 0 {
                return Err(HpackError::InvalidHuffman);
            }
            if e & LEAF != 0 {
                if max_len != 0 && produced(out) == max_len {
                    return Err(HpackError::StringLength);
                }
                let (code_len, sym) = leaf(e);
                out.push(sym);
                cbits -= code_len;
                n = 0;
                sbits = cbits;
            } else {
                n = e as usize;
                cbits -= 8;
            }
        }
    }
    while cbits > 0 {
        let idx = (cur << (8 - cbits)) as u8 as usize;
        let e = tree[n][idx];
        if e == 0 {
            return Err(HpackError::InvalidHuffman);
        }
        if e & LEAF == 0 {
            break;
        }
        let (code_len, sym) = leaf(e);
        if code_len > cbits {
            break;
        }
        if max_len != 0 && produced(out) == max_len {
            return Err(HpackError::StringLength);
        }
        out.push(sym);
        cbits -= code_len;
        n = 0;
        sbits = cbits;
    }
    if sbits > 7 {
        return Err(HpackError::InvalidHuffman);
    }
    let mask = (1u64 << cbits) - 1;
    if cur & mask != mask {
        return Err(HpackError::InvalidHuffman);
    }
    Ok(())
}

// --------------------------------------------------------------- encoder

/// Go's `hpack.Encoder`.
pub struct Encoder {
    dyn_tab: DynamicTable,
    min_size: u32,
    max_size_limit: u32,
    table_size_update: bool,
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder {
    /// Go's `NewEncoder`.
    pub fn new() -> Self {
        let mut e = Self {
            dyn_tab: DynamicTable::default(),
            min_size: UINT32_MAX,
            max_size_limit: INITIAL_HEADER_TABLE_SIZE,
            table_size_update: false,
        };
        e.dyn_tab.set_max_size(INITIAL_HEADER_TABLE_SIZE);
        e
    }

    /// Go's `WriteField`: appends the encoding of `f` (preceded by any
    /// pending table size update) to `out`.
    pub fn write_field(&mut self, f: &HeaderField, out: &mut Vec<u8>) {
        if self.table_size_update {
            self.table_size_update = false;
            if self.min_size < self.dyn_tab.max_size {
                append_table_size(out, self.min_size);
            }
            self.min_size = UINT32_MAX;
            append_table_size(out, self.dyn_tab.max_size);
        }
        let (idx, name_value_match) = self.search_table(f);
        if name_value_match {
            append_indexed(out, idx);
        } else {
            let indexing = self.should_index(f);
            if indexing {
                self.dyn_tab.add(f.clone());
            }
            if idx == 0 {
                append_new_name(out, f, indexing);
            } else {
                append_indexed_name(out, f, idx, indexing);
            }
        }
    }

    fn search_table(&self, f: &HeaderField) -> (u64, bool) {
        let (i, nvm) = STATIC.search(f, true);
        if nvm {
            return (i, true);
        }
        let (j, nvm) = self.dyn_tab.table.search(f, false);
        if nvm || (i == 0 && j != 0) {
            return (j + STATIC.len() as u64, nvm);
        }
        (i, false)
    }

    /// Go's `SetMaxDynamicTableSize`.
    pub fn set_max_dynamic_table_size(&mut self, mut v: u32) {
        if v > self.max_size_limit {
            v = self.max_size_limit;
        }
        if v < self.min_size {
            self.min_size = v;
        }
        self.table_size_update = true;
        self.dyn_tab.set_max_size(v);
    }

    /// Go's `MaxDynamicTableSize`.
    pub fn max_dynamic_table_size(&self) -> u32 {
        self.dyn_tab.max_size
    }

    /// Go's `SetMaxDynamicTableSizeLimit`.
    pub fn set_max_dynamic_table_size_limit(&mut self, v: u32) {
        self.max_size_limit = v;
        if self.dyn_tab.max_size > v {
            self.table_size_update = true;
            self.dyn_tab.set_max_size(v);
        }
    }

    fn should_index(&self, f: &HeaderField) -> bool {
        !f.sensitive && f.size() <= self.dyn_tab.max_size
    }
}

fn append_indexed(dst: &mut Vec<u8>, i: u64) {
    let first = dst.len();
    append_var_int(dst, 7, i);
    dst[first] |= 0x80;
}

fn append_new_name(dst: &mut Vec<u8>, f: &HeaderField, indexing: bool) {
    dst.push(encode_type_byte(indexing, f.sensitive));
    append_hpack_string(dst, &f.name);
    append_hpack_string(dst, &f.value);
}

fn append_indexed_name(dst: &mut Vec<u8>, f: &HeaderField, i: u64, indexing: bool) {
    let first = dst.len();
    let n = if indexing { 6 } else { 4 };
    append_var_int(dst, n, i);
    dst[first] |= encode_type_byte(indexing, f.sensitive);
    append_hpack_string(dst, &f.value);
}

fn append_table_size(dst: &mut Vec<u8>, v: u32) {
    let first = dst.len();
    append_var_int(dst, 5, u64::from(v));
    dst[first] |= 0x20;
}

/// Go's `appendVarInt`: RFC 7541 section 5.1.
pub fn append_var_int(dst: &mut Vec<u8>, n: u8, mut i: u64) {
    let k = (1u64 << n) - 1;
    if i < k {
        dst.push(i as u8);
        return;
    }
    dst.push(k as u8);
    i -= k;
    while i >= 128 {
        dst.push(0x80 | (i & 0x7f) as u8);
        i >>= 7;
    }
    dst.push(i as u8);
}

/// Go's `appendHpackString`: Huffman only when strictly shorter.
pub fn append_hpack_string(dst: &mut Vec<u8>, s: &[u8]) {
    let hl = huffman_encode_length(s);
    if hl < s.len() as u64 {
        let first = dst.len();
        append_var_int(dst, 7, hl);
        append_huffman_string(dst, s);
        dst[first] |= 0x80;
    } else {
        append_var_int(dst, 7, s.len() as u64);
        dst.extend_from_slice(s);
    }
}

fn encode_type_byte(indexing: bool, sensitive: bool) -> u8 {
    if sensitive {
        0x10
    } else if indexing {
        0x40
    } else {
        0
    }
}

// --------------------------------------------------------------- decoder

enum Fail {
    NeedMore,
    Err(HpackError),
}
impl From<HpackError> for Fail {
    fn from(e: HpackError) -> Self {
        Fail::Err(e)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IndexType {
    True,
    False,
    Never,
}

/// Go's `hpack.Decoder`. Fields are delivered to the callback passed to
/// [`Decoder::write`].
pub struct Decoder {
    dyn_tab: DynamicTable,
    emit_enabled: bool,
    max_str_len: usize,
    save_buf: Vec<u8>,
    first_field: bool,
}

impl Decoder {
    /// Go's `NewDecoder`.
    pub fn new(max_dynamic_table_size: u32) -> Self {
        let mut d = Self {
            dyn_tab: DynamicTable::default(),
            emit_enabled: true,
            max_str_len: 0,
            save_buf: Vec::new(),
            first_field: true,
        };
        d.dyn_tab.allowed_max_size = max_dynamic_table_size;
        d.dyn_tab.set_max_size(max_dynamic_table_size);
        d
    }
    /// Go's `SetMaxStringLength`; 0 means unlimited.
    pub fn set_max_string_length(&mut self, n: usize) {
        self.max_str_len = n;
    }
    /// Go's `SetEmitEnabled`.
    pub fn set_emit_enabled(&mut self, v: bool) {
        self.emit_enabled = v;
    }
    /// Go's `EmitEnabled`.
    pub fn emit_enabled(&self) -> bool {
        self.emit_enabled
    }
    /// Go's `SetMaxDynamicTableSize`.
    pub fn set_max_dynamic_table_size(&mut self, v: u32) {
        self.dyn_tab.set_max_size(v);
    }
    /// Go's `SetAllowedMaxDynamicTableSize`.
    pub fn set_allowed_max_dynamic_table_size(&mut self, v: u32) {
        self.dyn_tab.allowed_max_size = v;
    }

    fn max_table_index(&self) -> usize {
        self.dyn_tab.table.len() + STATIC.len()
    }

    fn at(&self, i: u64) -> Option<&HeaderField> {
        if i == 0 {
            return None;
        }
        if i <= STATIC.len() as u64 {
            return Some(&STATIC.ents[i as usize - 1]);
        }
        if i > self.max_table_index() as u64 {
            return None;
        }
        let dt = &self.dyn_tab.table;
        Some(&dt.ents[dt.len() - (i as usize - STATIC.len())])
    }

    /// Go's `DecodeFull`: decodes an entire block.
    pub fn decode_full(&mut self, p: &[u8]) -> Result<Vec<HeaderField>, HpackError> {
        let mut hf = Vec::new();
        self.write(p, &mut |f| {
            hf.push(f);
            true
        })?;
        self.close()?;
        Ok(hf)
    }

    /// Go's `Close`: ends the block and resets for the next one.
    pub fn close(&mut self) -> Result<(), HpackError> {
        if !self.save_buf.is_empty() {
            self.save_buf.clear();
            return Err(HpackError::Decoding("truncated headers".into()));
        }
        self.first_field = true;
        Ok(())
    }

    /// Go's `Write`: decodes as much of `p` as is complete, calling `emit`
    /// for each field, and keeps a trailing partial field for the next call.
    /// `emit` returns `false` to switch emission off for the rest of the
    /// stream of fields, as Go's callbacks do with `SetEmitEnabled(false)`.
    pub fn write(
        &mut self,
        p: &[u8],
        emit: &mut dyn FnMut(HeaderField) -> bool,
    ) -> Result<usize, HpackError> {
        if p.is_empty() {
            return Ok(0);
        }
        let owned;
        let mut buf: &[u8] = if self.save_buf.is_empty() {
            p
        } else {
            let mut v = std::mem::take(&mut self.save_buf);
            v.extend_from_slice(p);
            owned = v;
            &owned
        };
        while !buf.is_empty() {
            match self.parse_header_field_repr(&mut buf, emit) {
                Ok(()) => self.first_field = false,
                Err(Fail::NeedMore) => {
                    const VAR_INT_OVERHEAD: i64 = 8;
                    if self.max_str_len != 0
                        && buf.len() as i64 > 2 * (self.max_str_len as i64 + VAR_INT_OVERHEAD)
                    {
                        return Err(HpackError::StringLength);
                    }
                    self.save_buf = buf.to_vec();
                    return Ok(p.len());
                }
                Err(Fail::Err(e)) => {
                    self.first_field = false;
                    return Err(e);
                }
            }
        }
        Ok(p.len())
    }

    fn parse_header_field_repr(
        &mut self,
        buf: &mut &[u8],
        emit: &mut dyn FnMut(HeaderField) -> bool,
    ) -> Result<(), Fail> {
        let b = buf[0];
        if b & 128 != 0 {
            self.parse_field_indexed(buf, emit)
        } else if b & 192 == 64 {
            self.parse_field_literal(buf, 6, IndexType::True, emit)
        } else if b & 240 == 0 {
            self.parse_field_literal(buf, 4, IndexType::False, emit)
        } else if b & 240 == 16 {
            self.parse_field_literal(buf, 4, IndexType::Never, emit)
        } else if b & 224 == 32 {
            self.parse_dynamic_table_size_update(buf)
        } else {
            Err(HpackError::Decoding("invalid encoding".into()).into())
        }
    }

    fn parse_field_indexed(
        &mut self,
        buf: &mut &[u8],
        emit: &mut dyn FnMut(HeaderField) -> bool,
    ) -> Result<(), Fail> {
        let (idx, rest) = read_var_int(7, buf)?;
        let Some(hf) = self.at(idx) else {
            return Err(HpackError::InvalidIndex(idx).into());
        };
        let f = HeaderField {
            name: hf.name.clone(),
            value: hf.value.clone(),
            sensitive: false,
        };
        *buf = rest;
        self.call_emit(f, emit)?;
        Ok(())
    }

    fn parse_field_literal(
        &mut self,
        buf: &mut &[u8],
        n: u8,
        it: IndexType,
        emit: &mut dyn FnMut(HeaderField) -> bool,
    ) -> Result<(), Fail> {
        let (name_idx, mut rest) = read_var_int(n, buf)?;
        let mut hf = HeaderField::default();
        let want_str = self.emit_enabled || it == IndexType::True;
        let mut undecoded_name = Undecoded::default();
        if name_idx > 0 {
            let Some(ihf) = self.at(name_idx) else {
                return Err(HpackError::InvalidIndex(name_idx).into());
            };
            hf.name = ihf.name.clone();
        } else {
            let (u, r) = self.read_string(rest)?;
            undecoded_name = u;
            rest = r;
        }
        let (undecoded_value, rest) = self.read_string(rest)?;
        if want_str {
            if name_idx == 0 {
                hf.name = self.decode_string(&undecoded_name)?;
            }
            hf.value = self.decode_string(&undecoded_value)?;
        }
        *buf = rest;
        if it == IndexType::True {
            self.dyn_tab.add(hf.clone());
        }
        hf.sensitive = it == IndexType::Never;
        self.call_emit(hf, emit)?;
        Ok(())
    }

    fn call_emit(
        &mut self,
        hf: HeaderField,
        emit: &mut dyn FnMut(HeaderField) -> bool,
    ) -> Result<(), HpackError> {
        if self.max_str_len != 0
            && (hf.name.len() > self.max_str_len || hf.value.len() > self.max_str_len)
        {
            return Err(HpackError::StringLength);
        }
        if self.emit_enabled && !emit(hf) {
            self.emit_enabled = false;
        }
        Ok(())
    }

    fn parse_dynamic_table_size_update(&mut self, buf: &mut &[u8]) -> Result<(), Fail> {
        if !self.first_field && self.dyn_tab.size > 0 {
            return Err(HpackError::Decoding(
                "dynamic table size update MUST occur at the beginning of a header block".into(),
            )
            .into());
        }
        let (size, rest) = read_var_int(5, buf)?;
        if size > u64::from(self.dyn_tab.allowed_max_size) {
            return Err(HpackError::Decoding("dynamic table size update too large".into()).into());
        }
        self.dyn_tab.set_max_size(size as u32);
        *buf = rest;
        Ok(())
    }

    fn read_string<'a>(&self, p: &'a [u8]) -> Result<(Undecoded<'a>, &'a [u8]), Fail> {
        if p.is_empty() {
            return Err(Fail::NeedMore);
        }
        let is_huff = p[0] & 128 != 0;
        let (str_len, p) = read_var_int(7, p)?;
        if self.max_str_len != 0 && str_len > self.max_str_len as u64 {
            return Err(HpackError::StringLength.into());
        }
        if (p.len() as u64) < str_len {
            return Err(Fail::NeedMore);
        }
        let n = str_len as usize;
        Ok((
            Undecoded {
                is_huff,
                b: &p[..n],
            },
            &p[n..],
        ))
    }

    fn decode_string(&self, u: &Undecoded<'_>) -> Result<Vec<u8>, HpackError> {
        if !u.is_huff {
            return Ok(u.b.to_vec());
        }
        let mut out = Vec::new();
        huffman_decode(&mut out, self.max_str_len, u.b)?;
        Ok(out)
    }
}

#[derive(Default)]
struct Undecoded<'a> {
    is_huff: bool,
    b: &'a [u8],
}

/// Go's `readVarInt`.
fn read_var_int(n: u8, p: &[u8]) -> Result<(u64, &[u8]), Fail> {
    if p.is_empty() {
        return Err(Fail::NeedMore);
    }
    let mut i = u64::from(p[0]);
    if n < 8 {
        i &= (1u64 << n) - 1;
    }
    if i < (1u64 << n) - 1 {
        return Ok((i, &p[1..]));
    }
    let mut rest = &p[1..];
    let mut m: u64 = 0;
    while let Some((&b, r)) = rest.split_first() {
        rest = r;
        i = i.wrapping_add(u64::from(b & 127) << m);
        if b & 128 == 0 {
            return Ok((i, rest));
        }
        m += 7;
        if m >= 63 {
            return Err(HpackError::Decoding("varint integer overflow".into()).into());
        }
    }
    Err(Fail::NeedMore)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7541_c3_requests_without_huffman_state() {
        // RFC 7541 C.3 round trip through our encoder/decoder pair.
        let mut enc = Encoder::new();
        let mut dec = Decoder::new(4096);
        for path in ["/", "/index.html", "/a"] {
            let fields = vec![
                HeaderField::new(":method", "GET"),
                HeaderField::new(":path", path),
                HeaderField::new("x-custom", "value"),
            ];
            let mut out = Vec::new();
            for f in &fields {
                enc.write_field(f, &mut out);
            }
            assert_eq!(dec.decode_full(&out).unwrap(), fields);
        }
    }

    #[test]
    fn rfc7541_c4_1_huffman_request() {
        // "www.example.com" Huffman (C.4.1).
        let mut out = Vec::new();
        append_huffman_string(&mut out, b"www.example.com");
        assert_eq!(
            out,
            [0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff]
        );
        let mut back = Vec::new();
        huffman_decode(&mut back, 0, &out).unwrap();
        assert_eq!(back, b"www.example.com");
    }

    #[test]
    fn decoder_rejects_bad_padding_and_index() {
        let mut d = Decoder::new(4096);
        assert_eq!(
            d.decode_full(&[0xbe]).unwrap_err(),
            HpackError::InvalidIndex(62)
        );
        let mut out = Vec::new();
        assert_eq!(
            huffman_decode(&mut out, 0, &[0x00]),
            Err(HpackError::InvalidHuffman)
        );
    }

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc7541_c4_request_sequence_with_huffman_and_dynamic_table() {
        // RFC 7541 appendix C.4.1-C.4.3 (requests, Huffman coded).
        let blocks = [
            "8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff",
            "8286 84be 5886 a8eb 1064 9cbf",
            "8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf",
        ];
        let mut dec = Decoder::new(4096);
        let want: [Vec<(&str, &str)>; 3] = [
            vec![
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
            ],
            vec![
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
                ("cache-control", "no-cache"),
            ],
            vec![
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/index.html"),
                (":authority", "www.example.com"),
                ("custom-key", "custom-value"),
            ],
        ];
        for (b, w) in blocks.iter().zip(want) {
            let got = dec.decode_full(&unhex(b)).unwrap();
            let got: Vec<(String, String)> = got
                .iter()
                .map(|f| (f.name_str().into_owned(), f.value_str().into_owned()))
                .collect();
            let w: Vec<(String, String)> =
                w.into_iter().map(|(a, b)| (a.into(), b.into())).collect();
            assert_eq!(got, w);
        }
    }

    #[test]
    fn rfc7541_c5_response_eviction_with_small_table() {
        // C.5: responses with a 256-byte dynamic table, no Huffman.
        let mut dec = Decoder::new(256);
        let b1 = unhex("4803 3330 3258 0770 7269 7661 7465 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a 3133 3a32 3120 474d 546e 1768 7474 7073 3a2f 2f77 7777 2e65 7861 6d70 6c65 2e63 6f6d");
        let f = dec.decode_full(&b1).unwrap();
        assert_eq!(f[0], HeaderField::new(":status", "302"));
        assert_eq!(f.len(), 4);
        let b2 = unhex("4803 3330 37c1 c0bf");
        let f = dec.decode_full(&b2).unwrap();
        assert_eq!(f[0], HeaderField::new(":status", "307"));
        assert_eq!(f[1], HeaderField::new("cache-control", "private"));
    }
}
