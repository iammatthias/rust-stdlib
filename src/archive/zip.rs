//! Go's `archive/zip`: [`Reader`], [`ReadCloser`], [`Writer`], [`File`],
//! [`FileHeader`], ZIP64, data descriptors, extended timestamps, the UTF-8
//! flag and CP437 names, compressor registration and the `fs.FS` view of an
//! archive (see [`crate::archive::iofs`]).
//!
//! The bounded in-memory helpers [`read()`] and [`write()`] (with [`Entry`] and
//! [`Limits`]) are a stricter convenience layer: single-disk archives with
//! stored or DEFLATE members, no ZIP64, no preambles or unreferenced data,
//! ASCII or UTF-8 names only; they write stored members. Entries remain
//! metadata; no extraction occurs.
//!
//! ```
//! use rust_stdlib::archive::zip::{Reader, Writer};
//! use std::io::{Read, Write};
//!
//! let mut zw = Writer::new(Vec::new());
//! zw.create("hello.txt")?.write_all(b"hello, zip")?;
//! zw.close()?;
//! let archive = zw.into_inner()?;
//!
//! let size = archive.len() as i64;
//! let zr = Reader::new(archive, size)?;
//! let mut body = String::new();
//! zr.file[0].open()?.read_to_string(&mut body)?;
//! assert_eq!((zr.file[0].file_header.name.as_str(), body.as_str()), ("hello.txt", "hello, zip"));
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! Boundaries compared with Go: names and comments are Rust `String`s, so
//! names that are not valid UTF-8 are decoded as CP437 and their exact bytes
//! are kept in `raw_name` and `raw_comment` (`name_bytes` is Go's `Name`);
//! `Modified` is an instant, without Go's zone offset; `create_header` works
//! on a copy of its header, which `FileWriter::header`, `FileWriter::finish`
//! and `Writer::headers` expose with the updates Go makes in place;
//! `ErrInsecurePath` is opt-in.
mod header;
mod reader;
mod register;
mod writer;
use crate::compress::{self, crc32};
pub use header::*;
pub use reader::{open_reader, File, InsecurePathError, OpenError, ReadCloser, Reader};
pub use register::{register_compressor, register_decompressor, Compressor, Decompressor};
use std::io::{self, Read, Write};
pub use writer::{FileWriter, Writer};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub data: Vec<u8>,
    pub directory: bool,
}
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_archive: usize,
    pub max_entries: usize,
    pub max_file: usize,
    pub max_total: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_archive: 64 * 1024 * 1024,
            max_entries: 10000,
            max_file: 16 * 1024 * 1024,
            max_total: 64 * 1024 * 1024,
        }
    }
}
fn invalid(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}
fn part(b: &[u8], p: usize, n: usize) -> io::Result<&[u8]> {
    let end = p
        .checked_add(n)
        .ok_or_else(|| invalid("ZIP offset overflow"))?;
    b.get(p..end).ok_or_else(|| invalid("truncated ZIP record"))
}
fn u16at(b: &[u8], p: usize) -> io::Result<u16> {
    Ok(u16::from_le_bytes(part(b, p, 2)?.try_into().unwrap()))
}
fn u32at(b: &[u8], p: usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(part(b, p, 4)?.try_into().unwrap()))
}
fn extra(mut b: &[u8]) -> io::Result<()> {
    while !b.is_empty() {
        let tag = u16at(b, 0)?;
        let n = usize::from(u16at(b, 2)?);
        if tag == 1 {
            return Err(invalid("ZIP64 unsupported"));
        }
        part(b, 4, n)?;
        b = &b[4 + n..];
    }
    Ok(())
}
/// Read a complete archive. Central/local headers, data descriptors, sizes and
/// checksums must agree before any entries are returned.
pub fn read(mut reader: impl Read, limits: Limits) -> io::Result<Vec<Entry>> {
    let mut b = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = match reader.read(&mut buf) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            r => r?,
        };
        if n == 0 {
            break;
        }
        if n > limits.max_archive.saturating_sub(b.len()) {
            return Err(invalid("ZIP archive limit exceeded"));
        }
        b.extend_from_slice(&buf[..n]);
    }
    if b.len() < 22 {
        return Err(invalid("missing ZIP end record"));
    }
    let lower = b.len().saturating_sub(22 + 65535);
    let end = (lower..=b.len() - 22)
        .rev()
        .find(|&p| {
            b[p..p + 4] == [80, 75, 5, 6]
                && u16at(&b, p + 20).is_ok_and(|n| p + 22 + usize::from(n) == b.len())
        })
        .ok_or_else(|| invalid("missing ZIP end record"))?;
    if u16at(&b, end + 4)? != 0
        || u16at(&b, end + 6)? != 0
        || u16at(&b, end + 8)? != u16at(&b, end + 10)?
    {
        return Err(invalid("multi-disk ZIP unsupported"));
    }
    let count = usize::from(u16at(&b, end + 10)?);
    let size = u32at(&b, end + 12)? as usize;
    let start = u32at(&b, end + 16)? as usize;
    if count == 65535 || size == u32::MAX as usize || start == u32::MAX as usize {
        return Err(invalid("ZIP64 unsupported"));
    }
    if count > limits.max_entries {
        return Err(invalid("ZIP entry limit exceeded"));
    }
    if start.checked_add(size) != Some(end) {
        return Err(invalid("invalid ZIP central-directory span"));
    }
    let mut p = start;
    let mut total = 0usize;
    let mut entries = Vec::new();
    let mut ranges = Vec::new();
    for _ in 0..count {
        if u32at(&b, p)? != 0x02014b50 {
            return Err(invalid("invalid ZIP central header"));
        }
        part(&b, p, 46)?;
        let version = u16at(&b, p + 6)?;
        let flags = u16at(&b, p + 8)?;
        let method = u16at(&b, p + 10)?;
        if version > 20
            || flags & !0x080e != 0
            || !matches!(method, 0 | 8)
            || (method == 0 && flags & 6 != 0)
        {
            return Err(invalid("unsupported ZIP version, flags or compression"));
        }
        let crc = u32at(&b, p + 16)?;
        let compressed = u32at(&b, p + 20)? as usize;
        let decoded = u32at(&b, p + 24)? as usize;
        if compressed == u32::MAX as usize || decoded == u32::MAX as usize {
            return Err(invalid("ZIP64 unsupported"));
        }
        if decoded > limits.max_file || decoded > limits.max_total.saturating_sub(total) {
            return Err(invalid("ZIP decoded data limit exceeded"));
        }
        let nn = usize::from(u16at(&b, p + 28)?);
        let en = usize::from(u16at(&b, p + 30)?);
        let cn = usize::from(u16at(&b, p + 32)?);
        if u16at(&b, p + 34)? != 0 {
            return Err(invalid("multi-disk ZIP unsupported"));
        }
        let name_bytes = part(&b, p + 46, nn)?;
        if name_bytes.is_empty()
            || name_bytes.contains(&0)
            || (flags & 0x0800 == 0 && !name_bytes.is_ascii())
        {
            return Err(invalid("ZIP name must be ASCII or explicitly UTF-8"));
        }
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| invalid("invalid ZIP UTF-8 name"))?
            .to_string();
        extra(part(&b, p + 46 + nn, en)?)?;
        part(&b, p + 46 + nn + en, cn)?;
        let local = u32at(&b, p + 42)? as usize;
        if local == u32::MAX as usize {
            return Err(invalid("ZIP64 unsupported"));
        }
        if u32at(&b, local)? != 0x04034b50 {
            return Err(invalid("invalid ZIP local header"));
        }
        part(&b, local, 30)?;
        if u16at(&b, local + 4)? != version
            || u16at(&b, local + 6)? != flags
            || u16at(&b, local + 8)? != method
            || part(&b, local + 10, 4)? != part(&b, p + 12, 4)?
        {
            return Err(invalid("ZIP local/central metadata mismatch"));
        }
        let ln = usize::from(u16at(&b, local + 26)?);
        let le = usize::from(u16at(&b, local + 28)?);
        if part(&b, local + 30, ln)? != name_bytes {
            return Err(invalid("ZIP local/central name mismatch"));
        }
        extra(part(&b, local + 30 + ln, le)?)?;
        let body = local + 30 + ln + le;
        let data = part(&b, body, compressed)?;
        let mut finish = body
            .checked_add(compressed)
            .ok_or_else(|| invalid("ZIP offset overflow"))?;
        if flags & 8 == 0 {
            if u32at(&b, local + 14)? != crc
                || u32at(&b, local + 18)? as usize != compressed
                || u32at(&b, local + 22)? as usize != decoded
            {
                return Err(invalid("ZIP local/central size or checksum mismatch"));
            }
        } else {
            for (off, expected) in [(14, crc), (18, compressed as u32), (22, decoded as u32)] {
                let v = u32at(&b, local + off)?;
                if v != 0 && v != expected {
                    return Err(invalid("invalid ZIP deferred local metadata"));
                }
            }
            let matches = |at: usize| -> bool {
                u32at(&b, at).is_ok_and(|v| v == crc)
                    && u32at(&b, at + 4).is_ok_and(|v| v as usize == compressed)
                    && u32at(&b, at + 8).is_ok_and(|v| v as usize == decoded)
            };
            // An unsigned descriptor CRC can equal the optional signature.
            // Prefer a valid signed descriptor, then test the unsigned form.
            if u32at(&b, finish)? == 0x08074b50 && matches(finish + 4) {
                finish += 16;
            } else if matches(finish) {
                finish += 12;
            } else {
                return Err(invalid("ZIP data descriptor mismatch"));
            }
        }
        if finish > start {
            return Err(invalid("ZIP member overlaps central directory"));
        }
        ranges.push((local, finish));
        let mut out = Vec::new();
        if method == 0 {
            if compressed != decoded {
                return Err(invalid("stored ZIP size mismatch"));
            }
            out.extend_from_slice(data);
        } else {
            compress::decode_deflate(
                data,
                &mut out,
                compress::Limits {
                    max_input: compressed,
                    max_output: decoded,
                },
            )?;
        }
        if out.len() != decoded || crc32(&out) != crc {
            return Err(invalid("ZIP checksum or decoded size mismatch"));
        }
        let directory = name.ends_with('/');
        if directory && decoded != 0 {
            return Err(invalid("ZIP directory carries data"));
        }
        entries.push(Entry {
            name,
            data: out,
            directory,
        });
        total += decoded;
        p += 46 + nn + en + cn;
        if p > end {
            return Err(invalid("ZIP central directory overflow"));
        }
    }
    if p != end {
        return Err(invalid("ZIP central directory entry count mismatch"));
    }
    ranges.sort_unstable();
    let mut finish = 0;
    for (s, e) in ranges {
        if s != finish {
            return Err(invalid("ZIP member gap or overlap"));
        }
        finish = e;
    }
    if finish != start {
        return Err(invalid("unreferenced ZIP data"));
    }
    Ok(entries)
}
fn put16(b: &mut Vec<u8>, v: u16) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_le_bytes());
}
/// Write a deterministic stored ZIP archive with UTF-8 names and no comments.
pub fn write(entries: &[Entry], mut writer: impl Write, limits: Limits) -> io::Result<()> {
    if entries.len() > limits.max_entries || entries.len() >= 65535 {
        return Err(invalid("ZIP entry limit exceeded"));
    }
    let mut result = Vec::new();
    let mut central = Vec::new();
    let mut total = 0usize;
    for entry in entries {
        let name = entry.name.as_bytes();
        let size = entry.data.len();
        if name.is_empty()
            || name.len() > 65535
            || name.contains(&0)
            || entry.directory != entry.name.ends_with('/')
            || (entry.directory && size != 0)
        {
            return Err(invalid("invalid ZIP entry name or directory"));
        }
        if size >= u32::MAX as usize
            || size > limits.max_file
            || size > limits.max_total.saturating_sub(total)
        {
            return Err(invalid("ZIP data limit exceeded"));
        }
        let growth = 76usize
            .checked_add(name.len() * 2)
            .and_then(|v| v.checked_add(size))
            .ok_or_else(|| invalid("ZIP size overflow"))?;
        let existing = result
            .len()
            .checked_add(central.len())
            .ok_or_else(|| invalid("ZIP size overflow"))?;
        if growth
            > limits
                .max_archive
                .saturating_sub(existing)
                .saturating_sub(22)
            || result.len() >= u32::MAX as usize
        {
            return Err(invalid("ZIP archive limit exceeded"));
        }
        let offset = result.len() as u32;
        let crc = crc32(&entry.data);
        put32(&mut result, 0x04034b50);
        put16(&mut result, 20);
        put16(&mut result, 0x0800);
        put16(&mut result, 0);
        put16(&mut result, 0);
        put16(&mut result, 33);
        put32(&mut result, crc);
        put32(&mut result, size as u32);
        put32(&mut result, size as u32);
        put16(&mut result, name.len() as u16);
        put16(&mut result, 0);
        result.extend_from_slice(name);
        result.extend_from_slice(&entry.data);
        put32(&mut central, 0x02014b50);
        put16(&mut central, 20);
        put16(&mut central, 20);
        put16(&mut central, 0x0800);
        put16(&mut central, 0);
        put16(&mut central, 0);
        put16(&mut central, 33);
        put32(&mut central, crc);
        put32(&mut central, size as u32);
        put32(&mut central, size as u32);
        put16(&mut central, name.len() as u16);
        put16(&mut central, 0);
        put16(&mut central, 0);
        put16(&mut central, 0);
        put16(&mut central, 0);
        put32(&mut central, if entry.directory { 16 } else { 0 });
        put32(&mut central, offset);
        central.extend_from_slice(name);
        total += size;
    }
    if central.len() >= u32::MAX as usize || result.len() >= u32::MAX as usize {
        return Err(invalid("ZIP64 required"));
    }
    let offset = result.len() as u32;
    let size = central.len() as u32;
    result.extend_from_slice(&central);
    put32(&mut result, 0x06054b50);
    put16(&mut result, 0);
    put16(&mut result, 0);
    put16(&mut result, entries.len() as u16);
    put16(&mut result, entries.len() as u16);
    put32(&mut result, size);
    put32(&mut result, offset);
    put16(&mut result, 0);
    if result.len() > limits.max_archive {
        return Err(invalid("ZIP archive limit exceeded"));
    }
    writer.write_all(&result)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn python_stored_deflate_and_descriptors() {
        for fixture in [
            include_bytes!("../../tests/fixtures/compress/python.zip").as_slice(),
            include_bytes!("../../tests/fixtures/compress/stored.zip").as_slice(),
            include_bytes!("../../tests/fixtures/compress/descriptor.zip").as_slice(),
        ] {
            let entries = read(fixture, Limits::default()).unwrap();
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0].name, "hello.txt");
            assert_eq!(entries[0].data, b"hello hello hello");
            assert!(entries[1].directory);
        }
    }
    #[test]
    fn write_and_corrupt() {
        let entries = vec![Entry {
            name: "héllo.txt".into(),
            data: b"hello".to_vec(),
            directory: false,
        }];
        let mut bytes = Vec::new();
        write(&entries, &mut bytes, Limits::default()).unwrap();
        assert_eq!(read(&bytes[..], Limits::default()).unwrap(), entries);
        bytes[40] ^= 1;
        assert!(read(&bytes[..], Limits::default()).is_err());
    }
    #[test]
    fn limits_and_truncation() {
        let bytes = include_bytes!("../../tests/fixtures/compress/python.zip");
        for n in 0..bytes.len() {
            assert!(read(&bytes[..n], Limits::default()).is_err());
        }
        assert!(read(
            bytes.as_slice(),
            Limits {
                max_total: 16,
                ..Limits::default()
            }
        )
        .is_err());
        assert!(read(
            bytes.as_slice(),
            Limits {
                max_entries: 1,
                ..Limits::default()
            }
        )
        .is_err());
    }
}
