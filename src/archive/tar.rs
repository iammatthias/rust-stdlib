//! Go's `archive/tar`: [`Reader`], [`Writer`], [`Header`], [`Format`], the GNU
//! and PAX extensions (long names, PAX records and time precision, sparse
//! files, base-256 numbers) and [`file_info_header`].
//!
//! The bounded in-memory helpers [`read()`], [`read_each()`], [`write()`] and
//! [`write_stream()`] (with [`Entry`] and [`Limits`]) are a stricter
//! convenience layer: they accept only POSIX USTAR regular files,
//! directories and symbolic links, require UTF-8 metadata and reject GNU/PAX
//! extensions. Paths are preserved as metadata; this module never writes to
//! a filesystem.
//!
//! ```
//! use rust_stdlib::archive::tar::{Header, Reader, Writer, TYPE_REG};
//! use std::io::{Read, Write};
//!
//! let mut archive = Vec::new();
//! let mut tw = Writer::new(&mut archive);
//! let hdr = Header {
//!     name: "hello.txt".into(),
//!     typeflag: TYPE_REG,
//!     mode: 0o644,
//!     size: 5,
//!     ..Header::default()
//! };
//! tw.write_header(&hdr)?;
//! tw.write_all(b"hello")?;
//! tw.close()?;
//!
//! let mut tr = Reader::new(&archive[..]);
//! let got = tr.next()?.expect("one entry");
//! let mut body = String::new();
//! tr.read_to_string(&mut body)?;
//! assert_eq!((got.name.as_str(), body.as_str()), ("hello.txt", "hello"));
//! assert!(tr.next()?.is_none());
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! Boundaries compared with Go: header strings are Rust `String`s, so
//! non-UTF-8 names fail with `ErrHeader`; user/group names are not looked up
//! from the system databases in [`file_info_header`]; times are
//! `SystemTime` (Go's zero time is [`crate::archive::iofs::time_zero`]).
#[cfg(test)]
mod api_tests;
mod header;
mod reader;
mod sparse;
mod strconv;
mod writer;
pub use header::*;
pub use reader::Reader;
pub use sparse::SparseEntry;
use std::io::{self, Read, Write};
pub use writer::Writer;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Directory,
    Symlink,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub modified: u64,
    pub kind: Kind,
    pub link: String,
    pub data: Vec<u8>,
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
fn number(bytes: &[u8]) -> io::Result<u64> {
    if bytes[0] & 128 != 0 {
        return Err(invalid("base-256 tar numbers unsupported"));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| invalid("invalid tar number"))?
        .trim_matches(['\0', ' ']);
    if text.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(text, 8).map_err(|_| invalid("invalid or overflowing tar octal number"))
}
fn text(bytes: &[u8]) -> io::Result<String> {
    let end = bytes.iter().position(|&v| v == 0).unwrap_or(bytes.len());
    if bytes[end..].iter().any(|&v| v != 0) {
        return Err(invalid("invalid tar string padding"));
    }
    Ok(std::str::from_utf8(&bytes[..end])
        .map_err(|_| invalid("tar metadata must be UTF-8"))?
        .to_string())
}
/// Read a complete USTAR archive, validating checksums and all size limits.
pub fn read(reader: impl Read, limits: Limits) -> io::Result<Vec<Entry>> {
    let mut entries = Vec::new();
    read_each(reader, limits, |entry| {
        entries.push(entry);
        Ok(())
    })?;
    Ok(entries)
}
/// Go's `io.ReadFull` for archive members: input that ends early is
/// `io.ErrUnexpectedEOF`, as Go's tar reader reports for a short header or
/// payload.
fn full(reader: &mut impl Read, buf: &mut [u8]) -> io::Result<()> {
    reader.read_exact(buf).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            crate::io::Error::UnexpectedEof.into()
        } else {
            e
        }
    })
}

/// Visit USTAR entries incrementally with at most one bounded file payload in
/// memory. The visitor runs after checksum and data padding validation.
/// A subsequent member error does not undo earlier visitor side effects.
pub fn read_each(
    mut reader: impl Read,
    limits: Limits,
    mut visit: impl FnMut(Entry) -> io::Result<()>,
) -> io::Result<()> {
    let mut count = 0usize;
    let mut archive = 0usize;
    let mut total = 0usize;
    loop {
        if 512 > limits.max_archive.saturating_sub(archive) {
            return Err(invalid("tar archive limit exceeded"));
        }
        let mut header = [0u8; 512];
        full(&mut reader, &mut header)?;
        archive += 512;
        if header.iter().all(|&v| v == 0) {
            if 512 > limits.max_archive.saturating_sub(archive) {
                return Err(invalid("tar archive limit exceeded"));
            }
            full(&mut reader, &mut header)?;
            archive += 512;
            if header.iter().any(|&v| v != 0) {
                return Err(invalid("missing second tar end block"));
            }
            let mut block = [0u8; 512];
            loop {
                let n = match reader.read(&mut block) {
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    result => result?,
                };
                if n == 0 {
                    return Ok(());
                }
                if n > limits.max_archive.saturating_sub(archive) {
                    return Err(invalid("tar archive limit exceeded"));
                }
                archive += n;
                if block[..n].iter().any(|&v| v != 0) {
                    return Err(invalid("nonzero trailing tar bytes"));
                }
            }
        }
        if count == limits.max_entries {
            return Err(invalid("tar entry limit exceeded"));
        }
        let checksum = number(&header[148..156])?;
        let actual: u64 = header
            .iter()
            .enumerate()
            .map(|(i, &v)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    u64::from(v)
                }
            })
            .sum();
        if checksum != actual {
            return Err(invalid("tar checksum mismatch"));
        }
        if &header[257..263] != b"ustar\0" || &header[263..265] != b"00" {
            return Err(invalid("only POSIX USTAR archives supported"));
        }
        let mut path = text(&header[..100])?;
        let prefix = text(&header[345..500])?;
        if !prefix.is_empty() {
            path = format!("{prefix}/{path}");
        }
        if path.is_empty() {
            return Err(invalid("empty tar entry path"));
        }
        let kind = match header[156] {
            0 | b'0' => Kind::File,
            b'5' => Kind::Directory,
            b'2' => Kind::Symlink,
            _ => return Err(invalid("unsupported tar entry type")),
        };
        let size = usize::try_from(number(&header[124..136])?)
            .map_err(|_| invalid("tar size overflow"))?;
        if size > limits.max_file || size > limits.max_total.saturating_sub(total) {
            return Err(invalid("tar data limit exceeded"));
        }
        if kind != Kind::File && size != 0 {
            return Err(invalid("non-file tar entry carries data"));
        }
        let padding = (512 - size % 512) % 512;
        let space = size
            .checked_add(padding)
            .ok_or_else(|| invalid("tar size overflow"))?;
        if space > limits.max_archive.saturating_sub(archive) {
            return Err(invalid("tar archive limit exceeded"));
        }
        let mut data = vec![0u8; size];
        full(&mut reader, &mut data)?;
        let mut pad = vec![0u8; padding];
        full(&mut reader, &mut pad)?;
        if pad.iter().any(|&v| v != 0) {
            return Err(invalid("nonzero tar data padding"));
        }
        archive += space;
        total += size;
        visit(Entry {
            path,
            mode: u32::try_from(number(&header[100..108])?)
                .map_err(|_| invalid("tar mode overflow"))?,
            uid: u32::try_from(number(&header[108..116])?)
                .map_err(|_| invalid("tar uid overflow"))?,
            gid: u32::try_from(number(&header[116..124])?)
                .map_err(|_| invalid("tar gid overflow"))?,
            modified: number(&header[136..148])?,
            kind,
            link: text(&header[157..257])?,
            data,
        })?;
        count += 1;
    }
}
fn put_text(target: &mut [u8], s: &str) -> io::Result<()> {
    if s.len() > target.len() || s.as_bytes().contains(&0) {
        return Err(invalid("USTAR metadata length or NUL violation"));
    }
    target[..s.len()].copy_from_slice(s.as_bytes());
    Ok(())
}
fn put_number(target: &mut [u8], v: u64) -> io::Result<()> {
    let s = format!("{v:o}");
    if s.len() >= target.len() {
        return Err(invalid("USTAR octal number overflow"));
    }
    target.fill(b'0');
    let n = target.len();
    target[n - 1 - s.len()..n - 1].copy_from_slice(s.as_bytes());
    target[n - 1] = 0;
    Ok(())
}
/// Write a deterministic USTAR archive. Metadata is validated before output.
pub fn write(entries: &[Entry], mut writer: impl Write, limits: Limits) -> io::Result<()> {
    if entries.len() > limits.max_entries {
        return Err(invalid("tar entry limit exceeded"));
    }
    let mut result = Vec::new();
    let mut total = 0usize;
    for entry in entries {
        if entry.path.is_empty() || (entry.kind != Kind::File && !entry.data.is_empty()) {
            return Err(invalid("invalid tar entry"));
        }
        let size = entry.data.len();
        if size > limits.max_file || size > limits.max_total.saturating_sub(total) {
            return Err(invalid("tar data limit exceeded"));
        }
        let space = 512usize
            .checked_add(size)
            .and_then(|v| v.checked_add((512 - size % 512) % 512))
            .ok_or_else(|| invalid("tar size overflow"))?;
        if space
            > limits
                .max_archive
                .saturating_sub(result.len())
                .saturating_sub(1024)
        {
            return Err(invalid("tar archive limit exceeded"));
        }
        let mut header = [0u8; 512];
        if entry.path.len() <= 100 {
            put_text(&mut header[..100], &entry.path)?;
        } else {
            let split = entry
                .path
                .char_indices()
                .rev()
                .find(|&(i, c)| c == '/' && i <= 155 && entry.path.len() - i - 1 <= 100)
                .map(|(i, _)| i)
                .ok_or_else(|| invalid("USTAR path too long"))?;
            put_text(&mut header[..100], &entry.path[split + 1..])?;
            put_text(&mut header[345..500], &entry.path[..split])?;
        }
        put_number(&mut header[100..108], u64::from(entry.mode))?;
        put_number(&mut header[108..116], u64::from(entry.uid))?;
        put_number(&mut header[116..124], u64::from(entry.gid))?;
        put_number(&mut header[124..136], size as u64)?;
        put_number(&mut header[136..148], entry.modified)?;
        header[148..156].fill(b' ');
        header[156] = match entry.kind {
            Kind::File => b'0',
            Kind::Directory => b'5',
            Kind::Symlink => b'2',
        };
        put_text(&mut header[157..257], &entry.link)?;
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let sum: u64 = header.iter().map(|&v| u64::from(v)).sum();
        put_number(&mut header[148..155], sum)?;
        header[155] = b' ';
        result.extend_from_slice(&header);
        result.extend_from_slice(&entry.data);
        result.resize(result.len() + (512 - size % 512) % 512, 0);
        total += size;
    }
    if 1024 > limits.max_archive.saturating_sub(result.len()) {
        return Err(invalid("tar archive limit exceeded"));
    }
    result.resize(result.len() + 1024, 0);
    writer.write_all(&result)
}
/// Write entries one at a time, bounding temporary memory to a single member.
/// Errors may leave a partial archive; metadata and payload budgets remain global.
pub fn write_stream(entries: &[Entry], mut writer: impl Write, limits: Limits) -> io::Result<()> {
    if entries.len() > limits.max_entries {
        return Err(invalid("tar entry limit exceeded"));
    }
    let mut archive = 0usize;
    let mut total = 0usize;
    for entry in entries {
        let mut encoded = Vec::new();
        write(
            std::slice::from_ref(entry),
            &mut encoded,
            Limits {
                max_archive: limits.max_archive.saturating_sub(archive),
                max_entries: 1,
                max_file: limits.max_file,
                max_total: limits.max_total.saturating_sub(total),
            },
        )?;
        let body = encoded.len() - 1024;
        writer.write_all(&encoded[..body])?;
        archive += body;
        total += entry.data.len();
    }
    if 1024 > limits.max_archive.saturating_sub(archive) {
        return Err(invalid("tar archive limit exceeded"));
    }
    writer.write_all(&[0u8; 1024])
}

#[cfg(test)]
mod tests {
    use super::*;
    fn file() -> Entry {
        Entry {
            path: "notes/hello.txt".into(),
            mode: 0o644,
            uid: 1,
            gid: 2,
            modified: 123,
            kind: Kind::File,
            link: String::new(),
            data: b"hello".to_vec(),
        }
    }
    #[test]
    fn external_ustar() {
        let entries = read(
            include_bytes!("../../tests/fixtures/compress/python.tar").as_slice(),
            Limits::default(),
        )
        .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, b"hello");
        assert_eq!(entries[0].path, "notes/hello.txt");
    }
    #[test]
    fn round_trip_and_limits() {
        let entry = file();
        let mut out = Vec::new();
        write(std::slice::from_ref(&entry), &mut out, Limits::default()).unwrap();
        assert_eq!(read(&out[..], Limits::default()).unwrap(), vec![entry]);
        assert!(read(
            &out[..],
            Limits {
                max_file: 4,
                ..Limits::default()
            }
        )
        .is_err());
        out[0] ^= 1;
        assert!(read(&out[..], Limits::default()).is_err());
    }
    #[test]
    fn long_path_and_unsupported_types() {
        let mut entry = file();
        entry.path = format!("{}/{}", "a".repeat(140), "b".repeat(90));
        let mut out = Vec::new();
        write(std::slice::from_ref(&entry), &mut out, Limits::default()).unwrap();
        assert_eq!(read(&out[..], Limits::default()).unwrap()[0], entry);
        assert!(read(&out[..out.len() - 512], Limits::default()).is_err());
    }
    #[test]
    fn incremental_visiting_and_writing() {
        let entries = vec![file(), file()];
        let mut bytes = Vec::new();
        write_stream(&entries, &mut bytes, Limits::default()).unwrap();
        let mut visited = Vec::new();
        read_each(&bytes[..], Limits::default(), |entry| {
            visited.push(entry);
            Ok(())
        })
        .unwrap();
        assert_eq!(visited, entries);
        let mut all = Vec::new();
        write(&entries, &mut all, Limits::default()).unwrap();
        assert_eq!(all, bytes);
        let mut count = 0;
        assert!(read_each(&bytes[..], Limits::default(), |_| {
            count += 1;
            Err(io::Error::other("visitor failed"))
        })
        .is_err());
        assert_eq!(count, 1);
        assert!(write_stream(
            &entries,
            &mut Vec::new(),
            Limits {
                max_total: 9,
                ..Limits::default()
            }
        )
        .is_err());
    }
}
