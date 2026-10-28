//! ZIP reader following Go's `archive/zip/reader.go`: central-directory
//! parsing (ZIP64, preambles, extended timestamps), `File::open` with CRC and
//! size checking, and the `fs.FS` view of an archive.
use super::header::*;
use super::register::{decompressor, Decompressor};
use crate::archive::iofs::{
    self, godebug, is_local, read_full_at, read_some_at, time_is_zero, time_unix, time_zero,
    valid_path, DirEntry, FileInfo, FileInfoRef, FileMode, PathError, ReadCloser as IoReadCloser,
};
use crate::hash::crc32::Crc32;
use crate::io::fs;
use crate::io::ReadAt;
use std::{
    collections::HashMap,
    io::{self, BufReader, Read},
    sync::{Arc, Mutex, OnceLock},
    time::SystemTime,
};

/// Why [`Reader::new`] or [`Reader::with_options`] did not return a reader.
///
/// Go's `NewReader` returns `(reader, ErrInsecurePath)` and documents that
/// callers may continue to use the reader; [`OpenError::InsecurePath`]
/// carries it, and [`OpenError::into_reader`] takes it back. Converting to an
/// [`io::Error`] (for `?`) drops the reader and keeps Go's error value.
pub enum OpenError<R> {
    /// The archive could not be read.
    Io(io::Error),
    /// A file name is not local (`ErrInsecurePath`); the reader is usable.
    InsecurePath(Reader<R>),
}

impl<R> OpenError<R> {
    /// The reader of an [`OpenError::InsecurePath`] error.
    pub fn into_reader(self) -> Option<Reader<R>> {
        match self {
            OpenError::Io(_) => None,
            OpenError::InsecurePath(r) => Some(r),
        }
    }
}

impl<R> std::fmt::Debug for OpenError<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::Io(e) => f.debug_tuple("Io").field(e).finish(),
            OpenError::InsecurePath(_) => f.write_str("InsecurePath(..)"),
        }
    }
}

impl<R> std::fmt::Display for OpenError<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::Io(e) => std::fmt::Display::fmt(e, f),
            OpenError::InsecurePath(_) => std::fmt::Display::fmt(&Error::InsecurePath, f),
        }
    }
}

impl<R> std::error::Error for OpenError<R> {}

impl<R> From<io::Error> for OpenError<R> {
    fn from(e: io::Error) -> Self {
        OpenError::Io(e)
    }
}

impl<R> From<OpenError<R>> for io::Error {
    fn from(e: OpenError<R>) -> io::Error {
        match e {
            OpenError::Io(e) => e,
            OpenError::InsecurePath(_) => Error::InsecurePath.into(),
        }
    }
}

/// `ErrInsecurePath` returned together with the reader that [`open_reader`]
/// opened: Go's `OpenReader` returns `(reader, ErrInsecurePath)` and documents
/// that callers may continue to use the reader. [`Reader::new`] uses
/// [`OpenError`] instead.
#[derive(Debug)]
pub struct InsecurePathError {
    reader: Reader<std::fs::File>,
    from_open_reader: bool,
}

impl InsecurePathError {
    /// The reader that was opened.
    pub fn into_reader(self) -> Reader<std::fs::File> {
        self.reader
    }
    /// The read-closer, if the error came from [`open_reader`].
    pub fn into_read_closer(self) -> Option<ReadCloser> {
        self.from_open_reader.then_some(ReadCloser {
            reader: self.reader,
        })
    }
}
impl std::fmt::Display for InsecurePathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&Error::InsecurePath, f)
    }
}
impl std::error::Error for InsecurePathError {}

/// Go's `zip.ReadCloser`: a [`Reader`] that owns an open file.
#[derive(Debug)]
pub struct ReadCloser {
    pub reader: Reader<std::fs::File>,
}

impl std::ops::Deref for ReadCloser {
    type Target = Reader<std::fs::File>;
    fn deref(&self) -> &Reader<std::fs::File> {
        &self.reader
    }
}

struct Shared<R> {
    r: R,
    decompressors: Mutex<HashMap<u16, Decompressor>>,
}

impl<R> std::fmt::Debug for Shared<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Shared")
    }
}

/// A ZIP archive reader (Go's `zip.Reader`) over a positional reader `R`:
/// a `Vec<u8>`, a `&[u8]`, a [`std::fs::File`], or a borrow of any of them
/// (`&File` needs no `try_clone`). The archive's files borrow from `R`
/// through their own handle on the reader, so `Reader<&File>` cannot outlive
/// the file. Only the `fs::FS` view needs `R: 'static`.
pub struct Reader<R> {
    shared: Arc<Shared<R>>,
    /// The files in the archive, in central-directory order.
    pub file: Vec<File<R>>,
    /// The end-of-archive comment.
    pub comment: String,
    file_list: OnceLock<Arc<FileList<R>>>,
}

impl<R> std::fmt::Debug for Reader<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reader")
            .field("file", &self.file)
            .field("comment", &self.comment)
            .finish()
    }
}

/// A single file in a ZIP archive (Go's `zip.File`).
pub struct File<R> {
    pub file_header: FileHeader,
    shared: Arc<Shared<R>>,
    header_offset: i64,
}

impl<R> Clone for File<R> {
    fn clone(&self) -> Self {
        File {
            file_header: self.file_header.clone(),
            shared: self.shared.clone(),
            header_offset: self.header_offset,
        }
    }
}

impl<R> std::fmt::Debug for File<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("File")
            .field("file_header", &self.file_header)
            .field("header_offset", &self.header_offset)
            .finish()
    }
}

/// Directory-record reading errors, distinguishing `io.EOF` from
/// `io.ErrUnexpectedEOF` as Go's loop does.
enum DirErr {
    Format,
    UnexpectedEof,
    Eof,
    Io(io::Error),
}

impl From<DirErr> for io::Error {
    fn from(e: DirErr) -> io::Error {
        match e {
            DirErr::Format => Error::Format.into(),
            DirErr::UnexpectedEof => unexpected_eof(),
            DirErr::Eof => io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"),
            DirErr::Io(e) => e,
        }
    }
}

struct SectionReader<R> {
    r: Arc<Shared<R>>,
    pos: i64,
    end: i64,
}

impl<R> SectionReader<R> {
    fn new(r: Arc<Shared<R>>, off: i64, n: i64) -> Self {
        Self {
            r,
            pos: off,
            end: off.saturating_add(n.max(0)),
        }
    }
}

impl<R: ReadAt> Read for SectionReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos < 0 || self.pos >= self.end {
            return Ok(0);
        }
        let max = ((self.end - self.pos) as u64).min(buf.len() as u64) as usize;
        let n = read_some_at(&self.r.r, &mut buf[..max], self.pos as u64)?;
        self.pos += n as i64;
        Ok(n)
    }
}

fn read_full(r: &mut dyn Read, buf: &mut [u8]) -> Result<(), DirErr> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => {
                return Err(if n == 0 {
                    DirErr::Eof
                } else {
                    DirErr::UnexpectedEof
                })
            }
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(DirErr::Io(e)),
        }
    }
    Ok(())
}

fn u16le(b: &[u8], p: usize) -> u16 {
    u16::from_le_bytes([b[p], b[p + 1]])
}
fn u32le(b: &[u8], p: usize) -> u32 {
    u32::from_le_bytes(b[p..p + 4].try_into().unwrap())
}
fn u64le(b: &[u8], p: usize) -> u64 {
    u64::from_le_bytes(b[p..p + 8].try_into().unwrap())
}

struct DirectoryEnd {
    directory_records: u64,
    directory_size: u64,
    directory_offset: u64,
    comment: String,
}

/// `GODEBUG=zipinsecurepath=0` makes archives with insecure names an error.
fn reject_insecure_default() -> bool {
    godebug("zipinsecurepath").as_deref() == Some("0")
}

impl<R: ReadAt> Reader<R> {
    /// `NewReader`: read a ZIP archive of `size` bytes from `r`, which may be
    /// a borrow such as `&File` or `&[u8]`. With `GODEBUG=zipinsecurepath=0`
    /// an archive containing a non-local name returns
    /// [`OpenError::InsecurePath`] carrying the usable reader.
    pub fn new(r: R, size: i64) -> Result<Reader<R>, OpenError<R>> {
        Self::with_options(r, size, reject_insecure_default())
    }

    /// Like [`Reader::new`], but states explicitly whether non-local names
    /// are rejected with `ErrInsecurePath`.
    pub fn with_options(r: R, size: i64, reject_insecure: bool) -> Result<Reader<R>, OpenError<R>> {
        if size < 0 {
            return Err(io::Error::other("zip: size cannot be negative").into());
        }
        let zr = Self::init(r, size)?;
        if reject_insecure && zr.check_insecure_paths().is_err() {
            return Err(OpenError::InsecurePath(zr));
        }
        Ok(zr)
    }

    /// Report `ErrInsecurePath` if any file name is not local or contains a
    /// backslash.
    pub fn check_insecure_paths(&self) -> io::Result<()> {
        for f in &self.file {
            let name = &f.file_header.name;
            if name.is_empty() {
                continue;
            }
            if !is_local(name) || name.contains('\\') {
                return Err(Error::InsecurePath.into());
            }
        }
        Ok(())
    }

    fn init(rdr: R, size: i64) -> io::Result<Reader<R>> {
        let (end, base_offset) = read_directory_end(&rdr, size)?;
        let shared = Arc::new(Shared {
            r: rdr,
            decompressors: Mutex::new(HashMap::new()),
        });
        let mut zr = Reader {
            shared: shared.clone(),
            file: Vec::new(),
            comment: end.comment,
            file_list: OnceLock::new(),
        };
        let start = base_offset.wrapping_add(end.directory_offset as i64);
        let mut buf = BufReader::new(SectionReader::new(
            shared.clone(),
            start,
            size.saturating_sub(start),
        ));
        let last_err: DirErr;
        loop {
            let mut f = File {
                file_header: FileHeader::default(),
                shared: shared.clone(),
                header_offset: 0,
            };
            match read_directory_header(&mut f.file_header, &mut f.header_offset, &mut buf) {
                Ok(()) => {}
                Err(DirErr::Format) => {
                    last_err = DirErr::Format;
                    break;
                }
                Err(DirErr::UnexpectedEof) => {
                    last_err = DirErr::UnexpectedEof;
                    break;
                }
                Err(e) => return Err(e.into()),
            }
            f.header_offset = f.header_offset.wrapping_add(base_offset);
            zr.file.push(f);
        }
        if zr.file.len() as u16 != end.directory_records as u16 {
            return Err(last_err.into());
        }
        Ok(zr)
    }

    /// `RegisterDecompressor`: use `dcomp` for `method` in this reader,
    /// overriding the process-wide registry.
    pub fn register_decompressor(&self, method: u16, dcomp: Decompressor) {
        self.shared
            .decompressors
            .lock()
            .unwrap()
            .insert(method, dcomp);
    }

    fn init_file_list(&self) -> Arc<FileList<R>> {
        self.file_list
            .get_or_init(|| Arc::new(FileList::new(build_file_list(&self.file))))
            .clone()
    }
}

/// `OpenReader`: open the named ZIP file. See [`Reader::new`] for the
/// `ErrInsecurePath` behaviour; the error then carries the [`ReadCloser`].
pub fn open_reader(name: impl AsRef<std::path::Path>) -> io::Result<ReadCloser> {
    let f = std::fs::File::open(name)?;
    let size = f.metadata()?.len() as i64;
    let reader = Reader::init(f, size)?;
    if reject_insecure_default() && reader.check_insecure_paths().is_err() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            InsecurePathError {
                reader,
                from_open_reader: true,
            },
        ));
    }
    Ok(ReadCloser { reader })
}

impl ReadCloser {
    /// `Close`: release the file. Files opened earlier keep their own handle
    /// until dropped.
    pub fn close(self) -> io::Result<()> {
        Ok(())
    }
}

impl<R: ReadAt> File<R> {
    /// `DataOffset`: the offset of the file's compressed data in the archive.
    pub fn data_offset(&self) -> io::Result<i64> {
        let body = self.find_body_offset()?;
        Ok(self.header_offset + body)
    }

    /// `Open`: a reader of the file's decompressed contents. Reading to the
    /// end verifies the size and CRC-32 (`ErrChecksum`).
    pub fn open<'a>(&self) -> io::Result<Box<dyn IoReadCloser + 'a>>
    where
        R: 'a,
    {
        Ok(Box::new(self.open_checksum()?))
    }

    fn open_checksum<'a>(&self) -> io::Result<ChecksumReader<'a, R>>
    where
        R: 'a,
    {
        let body = self.find_body_offset()?;
        let fh = &self.file_header;
        if fh.name.ends_with('/') {
            let err = if fh.uncompressed_size64 != 0 {
                Some(Error::Format)
            } else {
                None
            };
            return Ok(ChecksumReader::dir(self.clone(), err));
        }
        let size = fh.compressed_size64 as i64;
        let r = SectionReader::new(self.shared.clone(), self.header_offset + body, size);
        let dcomp = self
            .shared
            .decompressors
            .lock()
            .unwrap()
            .get(&fh.method)
            .cloned()
            .or_else(|| decompressor(fh.method))
            .ok_or(Error::Algorithm)?;
        let rc = dcomp(Box::new(r));
        let desr = fh.has_data_descriptor().then(|| {
            SectionReader::new(
                self.shared.clone(),
                self.header_offset + body + size,
                DATA_DESCRIPTOR_LEN as i64,
            )
        });
        Ok(ChecksumReader {
            rc: Some(rc),
            hash: Crc32::ieee(),
            nread: 0,
            f: self.clone(),
            desr,
            err: None,
            done: false,
            dir_err: None,
        })
    }

    /// `OpenRaw`: a reader of the raw (compressed) data.
    pub fn open_raw<'a>(&self) -> io::Result<Box<dyn Read + 'a>>
    where
        R: 'a,
    {
        let body = self.find_body_offset()?;
        Ok(Box::new(SectionReader::new(
            self.shared.clone(),
            self.header_offset + body,
            self.file_header.compressed_size64 as i64,
        )))
    }

    fn find_body_offset(&self) -> io::Result<i64> {
        let mut buf = [0u8; FILE_HEADER_LEN];
        read_full_at(&self.shared.r, &mut buf, self.header_offset as u64)?;
        if u32le(&buf, 0) != FILE_HEADER_SIGNATURE {
            return Err(Error::Format.into());
        }
        let filename_len = i64::from(u16le(&buf, 26));
        let extra_len = i64::from(u16le(&buf, 28));
        Ok(FILE_HEADER_LEN as i64 + filename_len + extra_len)
    }

    /// `FileHeader.Mode` convenience.
    pub fn mode(&self) -> FileMode {
        self.file_header.mode()
    }

    /// `FileHeader.FileInfo` convenience.
    pub fn file_info(&self) -> HeaderFileInfo {
        self.file_header.file_info()
    }

    /// `FileHeader.ModTime` convenience (deprecated in Go).
    pub fn mod_time(&self) -> SystemTime {
        self.file_header.mod_time()
    }
}

/// Reader returned by [`File::open`]: verifies size and checksum at EOF.
struct ChecksumReader<'a, R> {
    rc: Option<Box<dyn IoReadCloser + 'a>>,
    hash: Crc32,
    nread: u64,
    f: File<R>,
    desr: Option<SectionReader<R>>,
    /// Sticky failure (kind, message, zip error value).
    err: Option<(io::ErrorKind, String, Option<Error>)>,
    /// Sticky success: end of data reached and verified.
    done: bool,
    /// For directories: every read returns this (`None` is end of file).
    dir_err: Option<Option<Error>>,
}

impl<R> ChecksumReader<'_, R> {
    fn dir(f: File<R>, err: Option<Error>) -> Self {
        Self {
            rc: None,
            hash: Crc32::ieee(),
            nread: 0,
            f,
            desr: None,
            err: None,
            done: false,
            dir_err: Some(err),
        }
    }

    fn latch(&mut self, e: io::Error) -> io::Error {
        let tag = Error::from_io(&e);
        self.err = Some((e.kind(), e.to_string(), tag));
        e
    }
}

impl<R: ReadAt> Read for ChecksumReader<'_, R> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        if let Some(e) = &self.dir_err {
            return match e {
                Some(e) => Err((*e).into()),
                None => Ok(0),
            };
        }
        if let Some((kind, msg, tag)) = &self.err {
            return Err(match tag {
                Some(t) => (*t).into(),
                None => io::Error::new(*kind, msg.clone()),
            });
        }
        if self.done || b.is_empty() {
            return Ok(0);
        }
        let n = match self.rc.as_mut().unwrap().read(b) {
            Ok(n) => n,
            Err(e) => return Err(self.latch(e)),
        };
        self.hash.update(&b[..n]);
        self.nread += n as u64;
        if self.nread > self.f.file_header.uncompressed_size64 {
            return Err(Error::Format.into());
        }
        if n > 0 {
            return Ok(n);
        }
        // End of the decompressed stream.
        if self.nread != self.f.file_header.uncompressed_size64 {
            return Err(unexpected_eof());
        }
        let sum = {
            let mut out = Vec::new();
            self.hash.sum(&mut out);
            u32::from_be_bytes(out.try_into().unwrap())
        };
        let want = self.f.file_header.crc32;
        let result = if let Some(desr) = &mut self.desr {
            match read_data_descriptor(desr, want) {
                Err(e) => Err(e),
                Ok(()) if sum != want => Err(Error::Checksum.into()),
                Ok(()) => Ok(()),
            }
        } else if want != 0 && sum != want {
            Err(Error::Checksum.into())
        } else {
            Ok(())
        };
        match result {
            Ok(()) => {
                self.done = true;
                Ok(0)
            }
            Err(e) => Err(self.latch(e)),
        }
    }
}

impl<R: ReadAt> IoReadCloser for ChecksumReader<'_, R> {
    fn close(&mut self) -> io::Result<()> {
        match self.rc.as_mut() {
            Some(rc) => rc.close(),
            None => Ok(()),
        }
    }
}

impl<R: ReadAt> iofs::File for ChecksumReader<'_, R> {
    fn stat(&self) -> io::Result<FileInfoRef> {
        Ok(Arc::new(self.f.file_header.file_info()))
    }
}

fn read_data_descriptor<R: ReadAt>(r: &mut SectionReader<R>, crc: u32) -> io::Result<()> {
    let map = |e: DirErr| match e {
        DirErr::Eof | DirErr::UnexpectedEof => unexpected_eof(),
        other => io::Error::from(other),
    };
    let mut buf = [0u8; DATA_DESCRIPTOR_LEN];
    read_full(r, &mut buf[..4]).map_err(map)?;
    let mut off = 0;
    if u32le(&buf, 0) != DATA_DESCRIPTOR_SIGNATURE {
        // No signature: these four bytes are the CRC.
        off = 4;
    }
    read_full(r, &mut buf[off..12]).map_err(map)?;
    if u32le(&buf, 0) != crc {
        return Err(Error::Checksum.into());
    }
    // The sizes that follow may be 32 or 64 bits wide and are not checked.
    Ok(())
}

fn read_directory_header(
    fh: &mut FileHeader,
    header_offset: &mut i64,
    r: &mut dyn Read,
) -> Result<(), DirErr> {
    let mut buf = [0u8; DIRECTORY_HEADER_LEN];
    read_full(r, &mut buf)?;
    if u32le(&buf, 0) != DIRECTORY_HEADER_SIGNATURE {
        return Err(DirErr::Format);
    }
    fh.creator_version = u16le(&buf, 4);
    fh.reader_version = u16le(&buf, 6);
    fh.flags = u16le(&buf, 8);
    fh.method = u16le(&buf, 10);
    fh.modified_time = u16le(&buf, 12);
    fh.modified_date = u16le(&buf, 14);
    fh.crc32 = u32le(&buf, 16);
    fh.compressed_size = u32le(&buf, 20);
    fh.uncompressed_size = u32le(&buf, 24);
    fh.compressed_size64 = u64::from(fh.compressed_size);
    fh.uncompressed_size64 = u64::from(fh.uncompressed_size);
    let filename_len = usize::from(u16le(&buf, 28));
    let extra_len = usize::from(u16le(&buf, 30));
    let comment_len = usize::from(u16le(&buf, 32));
    // Skipped: start disk number and internal attributes.
    fh.external_attrs = u32le(&buf, 38);
    *header_offset = i64::from(u32le(&buf, 42));
    let mut d = vec![0u8; filename_len + extra_len + comment_len];
    read_full(r, &mut d)?;
    let name = &d[..filename_len];
    let comment = &d[filename_len + extra_len..];
    fh.extra = d[filename_len..filename_len + extra_len].to_vec();
    let (valid1, require1) = detect_utf8(name);
    let (valid2, require2) = detect_utf8(comment);
    fh.non_utf8 = if !valid1 || !valid2 {
        true
    } else if !require1 && !require2 {
        false
    } else {
        fh.flags & 0x800 == 0
    };
    (fh.name, fh.raw_name) = text_and_raw(name);
    (fh.comment, fh.raw_comment) = text_and_raw(comment);

    let mut modified: Option<SystemTime> = None;
    let extra = fh.extra.clone();
    let mut rest: &[u8] = &extra;
    'extras: while rest.len() >= 4 {
        let tag = u16le(rest, 0);
        let size = usize::from(u16le(rest, 2));
        rest = &rest[4..];
        if rest.len() < size {
            break;
        }
        let mut field = &rest[..size];
        rest = &rest[size..];
        match tag {
            ZIP64_EXTRA_ID => {
                if fh.uncompressed_size == u32::MAX {
                    if field.len() < 8 {
                        return Err(DirErr::Format);
                    }
                    fh.uncompressed_size64 = u64le(field, 0);
                    field = &field[8..];
                }
                if fh.compressed_size == u32::MAX {
                    if field.len() < 8 {
                        return Err(DirErr::Format);
                    }
                    fh.compressed_size64 = u64le(field, 0);
                    field = &field[8..];
                }
                if *header_offset == i64::from(u32::MAX) {
                    if field.len() < 8 {
                        return Err(DirErr::Format);
                    }
                    *header_offset = u64le(field, 0) as i64;
                }
            }
            NTFS_EXTRA_ID => {
                if field.len() < 4 {
                    continue 'extras;
                }
                field = &field[4..]; // reserved
                while field.len() >= 4 {
                    let attr_tag = u16le(field, 0);
                    let attr_size = usize::from(u16le(field, 2));
                    field = &field[4..];
                    if field.len() < attr_size {
                        continue 'extras;
                    }
                    let attr = &field[..attr_size];
                    field = &field[attr_size..];
                    if attr_tag != 1 || attr_size != 24 {
                        continue;
                    }
                    // 100ns ticks since 1601-01-01.
                    let ts = u64le(attr, 0) as i64;
                    let secs = ts / 10_000_000;
                    let nsecs = 100 * (ts % 10_000_000);
                    modified = Some(time_unix(-11_644_473_600 + secs, nsecs));
                }
            }
            UNIX_EXTRA_ID | INFO_ZIP_UNIX_EXTRA_ID => {
                if field.len() < 8 {
                    continue 'extras;
                }
                modified = Some(time_unix(i64::from(u32le(field, 4)), 0));
            }
            EXT_TIME_EXTRA_ID => {
                if field.len() < 5 || field[0] & 1 == 0 {
                    continue 'extras;
                }
                modified = Some(time_unix(i64::from(u32le(field, 1)), 0));
            }
            _ => {}
        }
    }
    fh.modified = match modified {
        Some(m) if !time_is_zero(&m) => m,
        _ => ms_dos_time_to_time(fh.modified_date, fh.modified_time),
    };
    Ok(())
}

fn find_signature_in_block(b: &[u8]) -> Option<usize> {
    if b.len() < DIRECTORY_END_LEN {
        return None;
    }
    for i in (0..=b.len() - DIRECTORY_END_LEN).rev() {
        if b[i] == b'P' && b[i + 1] == b'K' && b[i + 2] == 0x05 && b[i + 3] == 0x06 {
            let n = usize::from(b[i + DIRECTORY_END_LEN - 2])
                | usize::from(b[i + DIRECTORY_END_LEN - 1]) << 8;
            if n + DIRECTORY_END_LEN + i > b.len() {
                return None;
            }
            return Some(i);
        }
    }
    None
}

fn read_directory_end(r: &dyn ReadAt, size: i64) -> io::Result<(DirectoryEnd, i64)> {
    let mut buf: Vec<u8> = Vec::new();
    let mut directory_end_offset = 0i64;
    for (i, mut b_len) in [1024i64, 65 * 1024].into_iter().enumerate() {
        if b_len > size {
            b_len = size;
        }
        buf = vec![0u8; b_len as usize];
        read_full_at(r, &mut buf, (size - b_len) as u64)?;
        if let Some(p) = find_signature_in_block(&buf) {
            buf.drain(..p);
            directory_end_offset = size - b_len + p as i64;
            break;
        }
        if i == 1 || b_len == size {
            return Err(Error::Format.into());
        }
    }
    let b = &buf[4..];
    let mut d = DirectoryEnd {
        directory_records: u64::from(u16le(b, 6)),
        directory_size: u64::from(u32le(b, 8)),
        directory_offset: u64::from(u32le(b, 12)),
        comment: String::new(),
    };
    let comment_len = usize::from(u16le(b, 16));
    let b = &b[18..];
    if comment_len > b.len() {
        return Err(io::Error::other("zip: invalid comment length"));
    }
    d.comment = decode_text(&b[..comment_len]);

    if d.directory_records == 0xffff
        || d.directory_size == 0xffff_ffff
        || d.directory_offset == 0xffff_ffff
    {
        if let Some(p) = find_directory64_end(r, directory_end_offset)? {
            directory_end_offset = p;
            read_directory64_end(r, p, &mut d)?;
        }
    }

    let max_i64 = i64::MAX as u64;
    if d.directory_size > max_i64 || d.directory_offset > max_i64 {
        return Err(Error::Format.into());
    }
    let mut base_offset = directory_end_offset
        .wrapping_sub(d.directory_size as i64)
        .wrapping_sub(d.directory_offset as i64);
    let o = base_offset.wrapping_add(d.directory_offset as i64);
    if o < 0 || o >= size {
        return Err(Error::Format.into());
    }
    if base_offset > 0 {
        // A preamble shifts every offset; if the directory is readable at its
        // recorded offset the archive is not shifted after all.
        let off = d.directory_offset as i64;
        let mut probe = ProbeSection {
            r,
            pos: off,
            end: size,
        };
        let (mut fh, mut offset) = (FileHeader::default(), 0i64);
        if read_directory_header(&mut fh, &mut offset, &mut probe).is_ok() {
            base_offset = 0;
        }
    }
    Ok((d, base_offset))
}

fn find_directory64_end(r: &dyn ReadAt, directory_end_offset: i64) -> io::Result<Option<i64>> {
    let loc_offset = directory_end_offset - DIRECTORY64_LOC_LEN as i64;
    if loc_offset < 0 {
        return Ok(None);
    }
    let mut buf = [0u8; DIRECTORY64_LOC_LEN];
    read_full_at(r, &mut buf, loc_offset as u64)?;
    if u32le(&buf, 0) != DIRECTORY64_LOC_SIGNATURE {
        return Ok(None);
    }
    if u32le(&buf, 4) != 0 {
        return Ok(None);
    }
    let p = u64le(&buf, 8);
    if u32le(&buf, 16) != 1 {
        return Ok(None);
    }
    Ok(Some(p as i64))
}

fn read_directory64_end(r: &dyn ReadAt, offset: i64, d: &mut DirectoryEnd) -> io::Result<()> {
    let mut buf = [0u8; DIRECTORY64_END_LEN];
    read_full_at(r, &mut buf, offset as u64)?;
    if u32le(&buf, 0) != DIRECTORY64_END_SIGNATURE {
        return Err(Error::Format.into());
    }
    // Skipped: size, versions, disk numbers and entries on this disk.
    d.directory_records = u64le(&buf, 32);
    d.directory_size = u64le(&buf, 40);
    d.directory_offset = u64le(&buf, 48);
    Ok(())
}

/// Sequential reads over a borrowed [`ReadAt`].
struct ProbeSection<'a> {
    r: &'a dyn ReadAt,
    pos: i64,
    end: i64,
}
impl Read for ProbeSection<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos < 0 || self.pos >= self.end {
            return Ok(0);
        }
        let max = ((self.end - self.pos) as u64).min(buf.len() as u64) as usize;
        let n = read_some_at(self.r, &mut buf[..max], self.pos as u64)?;
        self.pos += n as i64;
        Ok(n)
    }
}

// ---- fs.FS view -------------------------------------------------------

#[derive(Debug)]
struct FileList<R> {
    entries: Vec<ListEntry<R>>,
    by_name: HashMap<String, usize>,
    by_dir: HashMap<String, Vec<usize>>,
}

impl<R> FileList<R> {
    fn new(entries: Vec<ListEntry<R>>) -> Self {
        let mut by_name = HashMap::new();
        let mut by_dir: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, e) in entries.iter().enumerate() {
            by_name.insert(e.name.clone(), i);
            by_dir
                .entry(split(&e.name).0.to_string())
                .or_default()
                .push(i);
        }
        Self {
            entries,
            by_name,
            by_dir,
        }
    }
}

#[derive(Debug)]
struct ListEntry<R> {
    name: String,
    file: Option<File<R>>,
    is_dir: bool,
    is_dup: bool,
}

fn split(name: &str) -> (&str, &str, bool) {
    let (name, is_dir) = match name.strip_suffix('/') {
        Some(n) => (n, true),
        None => (name, false),
    };
    match name.rfind('/') {
        None => (".", name, is_dir),
        Some(i) => (&name[..i], &name[i + 1..], is_dir),
    }
}

fn to_valid_name(name: &str) -> String {
    let name = name.replace('\\', "/");
    let mut p = crate::path::clean(&name);
    if let Some(rest) = p.strip_prefix('/') {
        p = rest.to_string();
    }
    while let Some(rest) = p.strip_prefix("../") {
        p = rest.to_string();
    }
    p
}

fn entry_compare(x: &str, y: &str) -> std::cmp::Ordering {
    let (xdir, xelem, _) = split(x);
    let (ydir, yelem, _) = split(y);
    xdir.cmp(ydir).then_with(|| xelem.cmp(yelem))
}

fn build_file_list<R>(files: &[File<R>]) -> Vec<ListEntry<R>> {
    let mut list: Vec<ListEntry<R>> = Vec::with_capacity(files.len());
    let mut file_idx: HashMap<String, usize> = HashMap::new();
    let mut known_dirs: HashMap<String, usize> = HashMap::new();
    let mut dirs: HashMap<String, bool> = HashMap::new();

    for file in files {
        let fname = &file.file_header.name;
        let is_dir = fname.ends_with('/');
        let name = to_valid_name(fname);
        if name.is_empty() {
            continue;
        }
        if let Some(&idx) = file_idx.get(&name) {
            list[idx].is_dup = true;
            continue;
        }
        if let Some(&idx) = known_dirs.get(&name) {
            list[idx].is_dup = true;
            continue;
        }
        let mut dir = name.as_str();
        while let Some(i) = dir.rfind('/') {
            dir = &dir[..i];
            if dirs.contains_key(dir) {
                break;
            }
            dirs.insert(dir.to_string(), true);
        }
        let idx = list.len();
        list.push(ListEntry {
            name: name.clone(),
            file: Some(file.clone()),
            is_dir,
            is_dup: false,
        });
        if is_dir {
            known_dirs.insert(name, idx);
        } else {
            file_idx.insert(name, idx);
        }
    }
    let mut synthetic: Vec<String> = dirs.into_keys().collect();
    synthetic.sort();
    for dir in synthetic {
        if known_dirs.contains_key(&dir) {
            continue;
        }
        if let Some(&idx) = file_idx.get(&dir) {
            list[idx].is_dup = true;
        } else {
            list.push(ListEntry {
                name: dir,
                file: None,
                is_dir: true,
                is_dup: false,
            });
        }
    }
    list.sort_by(|a, b| entry_compare(&a.name, &b.name));
    list
}

/// `fileListEntry` as a [`FileInfo`] / [`DirEntry`] for directories, or the
/// file's header info for files.
#[derive(Clone)]
struct ListInfo {
    name: String,
    /// The modification time of the directory's first file, if any.
    modified: Option<SystemTime>,
}

impl FileInfo for ListInfo {
    fn name(&self) -> String {
        split(&self.name).1.to_string()
    }
    fn size(&self) -> i64 {
        0
    }
    fn mode(&self) -> FileMode {
        FileMode::DIR | FileMode(0o555)
    }
    fn mod_time(&self) -> SystemTime {
        self.modified.unwrap_or_else(time_zero)
    }
    fn is_dir(&self) -> bool {
        true
    }
}

struct HeaderEntry(HeaderFileInfo);
impl FileInfo for HeaderEntry {
    fn name(&self) -> String {
        self.0.name()
    }
    fn size(&self) -> i64 {
        self.0.size()
    }
    fn mode(&self) -> FileMode {
        self.0.mode()
    }
    fn mod_time(&self) -> SystemTime {
        self.0.mod_time()
    }
    fn sys(&self) -> Option<&dyn std::any::Any> {
        self.0.sys()
    }
}

struct EntryRef {
    info: FileInfoRef,
    mode: FileMode,
}
impl DirEntry for EntryRef {
    fn name(&self) -> String {
        self.info.name()
    }
    fn is_dir(&self) -> bool {
        self.info.is_dir()
    }
    fn type_(&self) -> FileMode {
        self.mode.type_()
    }
    fn info(&self) -> io::Result<FileInfoRef> {
        Ok(self.info.clone())
    }
}

fn stat_entry<R>(e: &ListEntry<R>) -> io::Result<FileInfoRef> {
    if e.is_dup {
        return Err(io::Error::other(format!(
            "{}: duplicate entries in zip file",
            e.name
        )));
    }
    if !e.is_dir {
        let f = e.file.as_ref().expect("file entries carry their header");
        return Ok(Arc::new(HeaderEntry(f.file_header.file_info())));
    }
    Ok(Arc::new(ListInfo {
        name: e.name.clone(),
        modified: e.file.as_ref().map(|f| f.file_header.modified),
    }))
}

struct OpenDir<R> {
    e: ListInfo,
    dup: Option<String>,
    files: Vec<usize>,
    list: Arc<FileList<R>>,
    offset: usize,
}

impl<R> Read for OpenDir<R> {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(PathError::new(
            "read",
            &self.e.name,
            "is a directory",
            io::ErrorKind::InvalidInput,
        )
        .into())
    }
}

impl<R> iofs::File for OpenDir<R> {
    fn stat(&self) -> io::Result<FileInfoRef> {
        match &self.dup {
            Some(name) => Err(io::Error::other(format!(
                "{name}: duplicate entries in zip file"
            ))),
            None => Ok(Arc::new(self.e.clone())),
        }
    }
    fn read_dir(&mut self, count: i64) -> io::Result<Vec<Box<dyn DirEntry>>> {
        let left = self.files.len() - self.offset;
        let n = if count > 0 {
            left.min(count as usize)
        } else {
            left
        };
        if n == 0 {
            if count <= 0 {
                return Ok(Vec::new());
            }
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"));
        }
        let mut out: Vec<Box<dyn DirEntry>> = Vec::with_capacity(n);
        for i in 0..n {
            let entry = &self.list.entries[self.files[self.offset + i]];
            let info = stat_entry(entry)?;
            let name = info.name();
            if name == "." || !valid_path(&name) {
                return Err(PathError::new(
                    "readdir",
                    &self.e.name,
                    &format!("invalid file name: {}", entry.name),
                    io::ErrorKind::InvalidData,
                )
                .into());
            }
            let mode = info.mode();
            out.push(Box::new(EntryRef { info, mode }));
        }
        self.offset += n;
        Ok(out)
    }
}

impl<R: ReadAt + 'static> fs::FS for Reader<R> {
    /// `Reader.Open`: the `fs.FS` view of the archive. Names are cleaned
    /// (backslashes become slashes, leading `/` and `../` are dropped),
    /// missing parent directories are synthesised, and duplicate names make
    /// `stat` fail.
    fn open(&self, name: &str) -> io::Result<Box<dyn fs::File>> {
        Ok(Box::new(iofs::ArchiveFile::new(self.open_entry(name)?)?))
    }
}

impl<R: ReadAt + 'static> Reader<R> {
    fn open_entry(&self, name: &str) -> io::Result<Box<dyn iofs::File>> {
        let list = self.init_file_list();
        if !valid_path(name) {
            return Err(PathError::new(
                "open",
                name,
                "invalid argument",
                io::ErrorKind::InvalidInput,
            )
            .into());
        }
        let idx = if name == "." {
            None
        } else {
            let Some(&i) = list.by_name.get(name) else {
                return Err(PathError::new(
                    "open",
                    name,
                    "file does not exist",
                    io::ErrorKind::NotFound,
                )
                .into());
            };
            Some(i)
        };
        let (is_dir, dup, info_name, file) = match idx {
            None => (true, None, "./".to_string(), None),
            Some(i) => {
                let e = &list.entries[i];
                (
                    e.is_dir,
                    e.is_dup.then(|| e.name.clone()),
                    e.name.clone(),
                    e.file.clone(),
                )
            }
        };
        if is_dir {
            let dir = if name == "." { "." } else { name };
            let files = list.by_dir.get(dir).cloned().unwrap_or_default();
            return Ok(Box::new(OpenDir {
                e: ListInfo {
                    name: info_name,
                    modified: file.map(|f| f.file_header.modified),
                },
                dup,
                files,
                list,
                offset: 0,
            }));
        }
        let f = file.expect("file entries carry their header");
        Ok(Box::new(f.open_checksum()?))
    }
}
