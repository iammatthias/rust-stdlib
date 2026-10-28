//! PEM block encoding and decoding.
//!
//! This module handles the textual envelope and base64 payload only. It does
//! not parse certificates, keys, or any cryptographic data inside a block.
use super::base64;
use std::collections::BTreeMap;
use std::io::{self, Write};

const BEGIN: &[u8] = b"-----BEGIN ";
const END_MARKER: &[u8] = b"\n-----END ";

/// A decoded PEM block. Header order on encode is deterministic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub type_: String,
    pub headers: BTreeMap<String, String>,
    pub bytes: Vec<u8>,
}

impl Block {
    pub fn new(type_: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            type_: type_.into(),
            headers: BTreeMap::new(),
            bytes: bytes.into(),
        }
    }
}

/// A decoded PEM block whose type and headers keep Go's arbitrary-byte strings.
/// [`Block`] is the `String` form for the common UTF-8 case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawBlock {
    pub type_: Vec<u8>,
    pub headers: BTreeMap<Vec<u8>, Vec<u8>>,
    pub bytes: Vec<u8>,
}

impl RawBlock {
    /// The `String` form, or `None` when the type or a header is not UTF-8.
    pub fn into_block(self) -> Option<Block> {
        let mut headers = BTreeMap::new();
        for (key, value) in self.headers {
            headers.insert(String::from_utf8(key).ok()?, String::from_utf8(value).ok()?);
        }
        Some(Block {
            type_: String::from_utf8(self.type_).ok()?,
            headers,
            bytes: self.bytes,
        })
    }
}

/// Resource budgets for [`decode_with_limits`]. They are opt-in: [`decode`] and
/// [`decode_raw`] apply none, as Go has none. `Limits::default()` is a
/// hardened preset for untrusted input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_input_bytes: usize,
    pub max_block_bytes: usize,
    pub max_decoded_bytes: usize,
    pub max_headers: usize,
    pub max_header_bytes: usize,
}

impl Limits {
    /// No limits, which is what [`decode`] uses.
    pub const UNLIMITED: Limits = Limits {
        max_input_bytes: usize::MAX,
        max_block_bytes: usize::MAX,
        max_decoded_bytes: usize::MAX,
        max_headers: usize::MAX,
        max_header_bytes: usize::MAX,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input_bytes: 16 * 1024 * 1024,
            max_block_bytes: 12 * 1024 * 1024,
            max_decoded_bytes: 8 * 1024 * 1024,
            max_headers: 128,
            max_header_bytes: 32 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    HeaderKeyContainsColon,
    InputLimit,
    BlockLimit,
    DecodedLimit,
    HeaderCountLimit,
    HeaderBytesLimit,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Error::HeaderKeyContainsColon => {
                "pem: cannot encode a header key that contains a colon"
            }
            Error::InputLimit => "PEM input exceeds configured limit",
            Error::BlockLimit => "PEM block exceeds configured limit",
            Error::DecodedLimit => "PEM decoded payload exceeds configured limit",
            Error::HeaderCountLimit => "PEM header count exceeds configured limit",
            Error::HeaderBytesLimit => "PEM headers exceed configured limit",
        };
        f.write_str(message)
    }
}
impl std::error::Error for Error {}

/// Writes a PEM block using sorted headers, with `Proc-Type` written first.
pub fn encode_to_writer(block: &Block, mut writer: impl Write) -> Result<(), EncodeError> {
    if block.headers.keys().any(|key| key.contains(':')) {
        return Err(EncodeError::InvalidHeaderKey);
    }
    writer.write_all(BEGIN)?;
    writer.write_all(block.type_.as_bytes())?;
    writer.write_all(b"-----\n")?;

    if let Some(value) = block.headers.get("Proc-Type") {
        write_header(&mut writer, "Proc-Type", value)?;
    }
    for (key, value) in &block.headers {
        if key != "Proc-Type" {
            write_header(&mut writer, key, value)?;
        }
    }
    if !block.headers.is_empty() {
        writer.write_all(b"\n")?;
    }

    let encoded = base64::STANDARD.encode(&block.bytes);
    for line in encoded.as_bytes().chunks(64) {
        writer.write_all(line)?;
        writer.write_all(b"\n")?;
    }
    writer.write_all(b"-----END ")?;
    writer.write_all(block.type_.as_bytes())?;
    writer.write_all(b"-----\n")?;
    Ok(())
}

fn write_header(writer: &mut impl Write, key: &str, value: &str) -> io::Result<()> {
    writer.write_all(key.as_bytes())?;
    writer.write_all(b": ")?;
    writer.write_all(value.as_bytes())?;
    writer.write_all(b"\n")
}

/// Encodes a block into memory.
pub fn encode(block: &Block) -> Result<Vec<u8>, EncodeError> {
    let mut output = Vec::new();
    encode_to_writer(block, &mut output)?;
    Ok(output)
}

#[derive(Debug)]
pub enum EncodeError {
    InvalidHeaderKey,
    Io(io::Error),
}
impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncodeError::InvalidHeaderKey => {
                f.write_str("pem: cannot encode a header key that contains a colon")
            }
            EncodeError::Io(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for EncodeError {}
impl From<io::Error> for EncodeError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Go's `Decode` with no resource limits: finds and decodes the first valid
/// PEM block. A block whose type or headers are not UTF-8 cannot be held by
/// [`Block`] and is skipped; [`decode_raw`] returns it.
pub fn decode(data: &[u8]) -> Option<(Block, &[u8])> {
    decode_with_limits(data, Limits::UNLIMITED).ok().flatten()
}

/// Finds and decodes the first valid PEM block under explicit resource limits.
/// A limit violation is reported separately from an input containing no block.
/// Blocks that are not UTF-8 are skipped as in [`decode`].
pub fn decode_with_limits(data: &[u8], limits: Limits) -> Result<Option<(Block, &[u8])>, Error> {
    let mut data = data;
    loop {
        let Some((raw, rest)) = decode_raw_with_limits(data, limits)? else {
            return Ok(None);
        };
        if let Some(block) = raw.into_block() {
            return Ok(Some((block, rest)));
        }
        data = rest;
    }
}

/// Go's `Decode` exactly: the type and headers are arbitrary bytes. No limits.
pub fn decode_raw(data: &[u8]) -> Option<(RawBlock, &[u8])> {
    decode_raw_with_limits(data, Limits::UNLIMITED)
        .ok()
        .flatten()
}

/// [`decode_raw`] under explicit resource limits.
pub fn decode_raw_with_limits(
    data: &[u8],
    limits: Limits,
) -> Result<Option<(RawBlock, &[u8])>, Error> {
    if data.len() > limits.max_input_bytes {
        return Err(Error::InputLimit);
    }
    let mut search_from = 0;
    let mut begin_scan_from = 0;
    loop {
        let Some(relative_marker) = find_subslice(&data[search_from..], END_MARKER) else {
            return Ok(None);
        };
        let marker = search_from + relative_marker;
        let mut latest_begin = None;
        while begin_scan_from < marker {
            let Some(relative_begin) = find_subslice(&data[begin_scan_from..marker], BEGIN) else {
                break;
            };
            let begin = begin_scan_from + relative_begin;
            begin_scan_from = begin + 1;
            if begin == 0 || data[begin - 1] == b'\n' {
                latest_begin = Some(begin);
            }
        }
        let Some(begin) = latest_begin else {
            search_from = marker + END_MARKER.len();
            begin_scan_from = search_from;
            continue;
        };
        match parse_candidate(data, begin, marker, limits)? {
            Candidate::Valid(block, end) => return Ok(Some((block, &data[end..]))),
            Candidate::Invalid => {
                search_from = marker + END_MARKER.len();
                begin_scan_from = search_from;
            }
        }
    }
}

enum Candidate {
    Valid(RawBlock, usize),
    Invalid,
}

fn parse_candidate(
    data: &[u8],
    begin: usize,
    marker: usize,
    limits: Limits,
) -> Result<Candidate, Error> {
    if marker.saturating_sub(begin) > limits.max_block_bytes {
        return Err(Error::BlockLimit);
    }
    let after_begin = begin + BEGIN.len();
    let (type_line, mut cursor) = get_line(data, after_begin);
    if !type_line.ends_with(b"-----") {
        return Ok(Candidate::Invalid);
    }
    let type_bytes = &type_line[..type_line.len() - 5];
    if cursor > marker.saturating_add(1) {
        return Ok(Candidate::Invalid);
    }

    let mut headers = BTreeMap::new();
    let mut header_count = 0usize;
    let mut header_bytes = 0usize;
    let mut separator_seen = false;
    loop {
        if cursor > marker {
            break;
        }
        let (line, next) = get_line(data, cursor);
        let Some(colon) = line.iter().position(|&byte| byte == b':') else {
            separator_seen = true;
            break;
        };
        header_bytes = header_bytes.saturating_add(next - cursor);
        if header_bytes > limits.max_header_bytes {
            return Err(Error::HeaderBytesLimit);
        }
        if header_count >= limits.max_headers {
            return Err(Error::HeaderCountLimit);
        }
        header_count += 1;
        let key = trim_space(&line[..colon]);
        let value = trim_space(&line[colon + 1..]);
        headers.insert(key.to_vec(), value.to_vec());
        cursor = next;
    }
    if cursor > marker.saturating_add(1) {
        return Ok(Candidate::Invalid);
    }
    if !headers.is_empty() && !separator_seen {
        return Ok(Candidate::Invalid);
    }
    let body_start = cursor;
    let end_line_start = marker + 1;
    let (end_line, end_line_next) = get_line(data, end_line_start);
    let expected = [b"-----END ".as_slice(), type_bytes, b"-----".as_slice()].concat();
    if !end_line.starts_with(&expected) || end_line.len() != expected.len() {
        return Ok(Candidate::Invalid);
    }
    let block_end = end_line_next;
    if block_end.saturating_sub(begin) > limits.max_block_bytes {
        return Err(Error::BlockLimit);
    }
    let body = if body_start > marker {
        &data[marker..marker]
    } else {
        &data[body_start..marker]
    };
    let encoded: Vec<u8> = body
        .iter()
        .copied()
        .filter(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        .collect();
    let padding = encoded
        .iter()
        .rev()
        .take_while(|&&byte| byte == b'=')
        .count();
    let decoded_bound = encoded
        .len()
        .saturating_div(4)
        .saturating_mul(3)
        .saturating_sub(padding.min(2));
    if decoded_bound > limits.max_decoded_bytes {
        return Err(Error::DecodedLimit);
    }
    let decoded = match base64::STANDARD.decode(&encoded) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(Candidate::Invalid),
    };
    if decoded.len() > limits.max_decoded_bytes {
        return Err(Error::DecodedLimit);
    }
    Ok(Candidate::Valid(
        RawBlock {
            type_: type_bytes.to_vec(),
            headers,
            bytes: decoded,
        },
        block_end,
    ))
}

fn get_line(data: &[u8], start: usize) -> (&[u8], usize) {
    let rest = &data[start..];
    let newline = rest.iter().position(|&byte| byte == b'\n');
    let (mut end, next) = match newline {
        Some(index) => (start + index, start + index + 1),
        None => (data.len(), data.len()),
    };
    if end > start && data[end - 1] == b'\r' {
        end -= 1;
    }
    while end > start && matches!(data[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    (&data[start..end], next)
}

/// Go's `bytes.TrimSpace`: trims Unicode white space, leaving invalid UTF-8 bytes alone.
fn trim_space(mut bytes: &[u8]) -> &[u8] {
    while let Some((c, width)) = first_char(bytes) {
        if !c.is_whitespace() {
            break;
        }
        bytes = &bytes[width..];
    }
    while let Some((c, width)) = last_char(bytes) {
        if !c.is_whitespace() {
            break;
        }
        bytes = &bytes[..bytes.len() - width];
    }
    bytes
}

fn first_char(bytes: &[u8]) -> Option<(char, usize)> {
    let head = &bytes[..bytes.len().min(4)];
    let valid = match std::str::from_utf8(head) {
        Ok(text) => text,
        Err(e) => std::str::from_utf8(&head[..e.valid_up_to()]).unwrap_or(""),
    };
    valid.chars().next().map(|c| (c, c.len_utf8()))
}

fn last_char(bytes: &[u8]) -> Option<(char, usize)> {
    let last = *bytes.last()?;
    if last < 0x80 {
        return Some((char::from(last), 1));
    }
    for width in 2..=bytes.len().min(4) {
        if let Ok(text) = std::str::from_utf8(&bytes[bytes.len() - width..]) {
            return text.chars().next().map(|c| (c, width));
        }
    }
    None
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod internal_tests {
    use super::trim_space;

    #[test]
    fn trims_unicode_whitespace() {
        assert_eq!(trim_space("\u{a0}Key\u{a0}".as_bytes()), b"Key");
    }
}
