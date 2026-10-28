//! The PEM framing `crypto/x509` needs (Go's `encoding/pem`).
//!
//! This crate cannot depend on the root crate's `encoding/pem`
//! (docs/adr/0003), so Go's `pem.Decode` and `pem.EncodeToMemory` are
//! reproduced here in the form `AppendCertsFromPEM`, `ParseCRL` and the legacy
//! PEM encryption functions use them: a [`Block`] with a type, headers and the
//! decoded bytes.

use std::collections::BTreeMap;

const BEGIN: &[u8] = b"-----BEGIN ";
const END_MARKER: &[u8] = b"\n-----END ";

/// Go's `pem.Block`: a PEM encoded structure.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Block {
    /// The type, taken from the preamble (such as "RSA PRIVATE KEY").
    pub type_: String,
    /// Optional headers.
    pub headers: BTreeMap<String, String>,
    /// The decoded bytes of the contents.
    pub bytes: Vec<u8>,
}

/// A decoded block whose type and headers are arbitrary bytes, as in Go.
struct RawBlock {
    type_: Vec<u8>,
    headers: BTreeMap<Vec<u8>, Vec<u8>>,
    bytes: Vec<u8>,
}

impl RawBlock {
    fn into_block(self) -> Option<Block> {
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

/// Go's `pem.Decode`: finds the first PEM block in the input and returns it
/// with the rest of the input. A block whose type or headers are not UTF-8 is
/// skipped. `None` means no block was found, with the remaining input.
pub fn decode(data: &[u8]) -> (Option<Block>, &[u8]) {
    let mut data = data;
    loop {
        let Some((raw, rest)) = decode_raw(data) else {
            return (None, data);
        };
        if let Some(block) = raw.into_block() {
            return (Some(block), rest);
        }
        data = rest;
    }
}

/// Go's `pem.EncodeToMemory`: the PEM encoding of a block, `None` where Go
/// returns nil (a header key containing a colon). `Proc-Type` is written first
/// among the sorted headers.
pub fn encode_to_memory(block: &Block) -> Option<Vec<u8>> {
    if block.headers.keys().any(|key| key.contains(':')) {
        return None;
    }
    let mut out = Vec::new();
    out.extend_from_slice(BEGIN);
    out.extend_from_slice(block.type_.as_bytes());
    out.extend_from_slice(b"-----\n");
    fn write_header(out: &mut Vec<u8>, key: &str, value: &str) {
        out.extend_from_slice(key.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.push(b'\n');
    }
    if let Some(value) = block.headers.get("Proc-Type") {
        write_header(&mut out, "Proc-Type", value);
    }
    for (key, value) in &block.headers {
        if key != "Proc-Type" {
            write_header(&mut out, key, value);
        }
    }
    if !block.headers.is_empty() {
        out.push(b'\n');
    }
    let encoded = base64_encode(&block.bytes);
    for line in encoded.as_bytes().chunks(64) {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out.extend_from_slice(b"-----END ");
    out.extend_from_slice(block.type_.as_bytes());
    out.extend_from_slice(b"-----\n");
    Some(out)
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Go's `base64.StdEncoding.Decode` on input without line breaks: strict
/// padding, trailing bits ignored.
pub(crate) fn base64_decode(input: &[u8]) -> Option<Vec<u8>> {
    if !input.len().is_multiple_of(4) {
        return None;
    }
    let value = |c: u8| -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let chunk_count = input.len() / 4;
    for (i, chunk) in input.chunks(4).enumerate() {
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && i + 1 != chunk_count) {
            return None;
        }
        let mut n = 0u32;
        for (j, &c) in chunk.iter().enumerate() {
            let v = if j >= 4 - pad {
                if c != b'=' {
                    return None;
                }
                0
            } else {
                value(c)?
            };
            n = n << 6 | v;
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

fn decode_raw(data: &[u8]) -> Option<(RawBlock, &[u8])> {
    let mut search_from = 0;
    let mut begin_scan_from = 0;
    loop {
        let relative_marker = find_subslice(&data[search_from..], END_MARKER)?;
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
        match parse_candidate(data, begin, marker) {
            Some((block, end)) => return Some((block, &data[end..])),
            None => {
                search_from = marker + END_MARKER.len();
                begin_scan_from = search_from;
            }
        }
    }
}

fn parse_candidate(data: &[u8], begin: usize, marker: usize) -> Option<(RawBlock, usize)> {
    let after_begin = begin + BEGIN.len();
    let (type_line, mut cursor) = get_line(data, after_begin);
    if !type_line.ends_with(b"-----") {
        return None;
    }
    let type_bytes = &type_line[..type_line.len() - 5];
    if cursor > marker.saturating_add(1) {
        return None;
    }

    let mut headers = BTreeMap::new();
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
        let key = trim_space(&line[..colon]);
        let value = trim_space(&line[colon + 1..]);
        headers.insert(key.to_vec(), value.to_vec());
        cursor = next;
    }
    if cursor > marker.saturating_add(1) {
        return None;
    }
    if !headers.is_empty() && !separator_seen {
        return None;
    }
    let body_start = cursor;
    let end_line_start = marker + 1;
    let (end_line, end_line_next) = get_line(data, end_line_start);
    let expected = [b"-----END ".as_slice(), type_bytes, b"-----".as_slice()].concat();
    if !end_line.starts_with(&expected) || end_line.len() != expected.len() {
        return None;
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
    let decoded = base64_decode(&encoded)?;
    Some((
        RawBlock {
            type_: type_bytes.to_vec(),
            headers,
            bytes: decoded,
        },
        end_line_next,
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

/// Go's `bytes.TrimSpace`: trims Unicode white space, leaving invalid UTF-8
/// bytes alone.
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
