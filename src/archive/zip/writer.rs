//! ZIP writer following Go's `archive/zip/writer.go`: streaming members with
//! data descriptors, ZIP64 records, raw copies, extended timestamps and
//! `AddFS`.
use super::header::*;
use super::register::{compressor, Compressor};
use crate::archive::iofs::{self, time_is_zero, time_parts, WriteCloser};
use crate::hash::crc32::Crc32;
use crate::io::fs;
use std::{
    cell::RefCell,
    collections::HashMap,
    io::{self, BufWriter, Write},
    rc::Rc,
};

const MAX_UINT16: usize = (1 << 16) - 1;

struct CountWriter<W: Write> {
    w: BufWriter<W>,
    count: i64,
}

impl<W: Write> CountWriter<W> {
    fn write_all(&mut self, b: &[u8]) -> io::Result<()> {
        self.w.write_all(b)?;
        self.count += b.len() as i64;
        Ok(())
    }
}

/// Destination handed to a [`Compressor`]; the writer drains it into the
/// archive after every write.
struct Sink(Rc<RefCell<Vec<u8>>>);

impl Write for Sink {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct DirRecord {
    fh: FileHeader,
    offset: u64,
    raw: bool,
}

struct FileState {
    idx: usize,
    comp: Option<Box<dyn WriteCloser>>,
    sink: Rc<RefCell<Vec<u8>>>,
    comp_count: u64,
    raw_count: u64,
    crc: Crc32,
    closed: bool,
    raw: bool,
}

/// A ZIP archive writer (Go's `zip.Writer`).
pub struct Writer<W: Write> {
    cw: CountWriter<W>,
    dir: Vec<DirRecord>,
    last: Option<FileState>,
    closed: bool,
    compressors: HashMap<u16, Compressor>,
    comment: String,
}

/// The sink for one member's contents, returned by [`Writer::create`],
/// [`Writer::create_header`] and [`Writer::create_raw`]. Its contents must be
/// written before the next member is created or the writer is closed.
pub struct FileWriter<'a, W: Write> {
    w: &'a mut Writer<W>,
    dir: bool,
}

impl<W: Write> FileWriter<'_, W> {
    /// The member's header as the writer holds it. Go's `CreateHeader` updates
    /// the `*FileHeader` it is given (flags, versions, extra, DOS time at
    /// creation; CRC and sizes when the member is finished); a Rust writer
    /// owns a copy, and this is that copy.
    pub fn header(&self) -> &FileHeader {
        &self.w.dir.last().expect("an open member has a header").fh
    }

    /// Finishes the member now, which Go does on the next `Create*` or `Close`,
    /// and returns its header with the CRC and sizes Go writes back into the
    /// header it was given.
    pub fn finish(self) -> io::Result<FileHeader> {
        self.w.prepare()?;
        Ok(self
            .w
            .dir
            .last()
            .expect("an open member has a header")
            .fh
            .clone())
    }
}

impl<W: Write> Write for FileWriter<'_, W> {
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        if self.dir {
            if p.is_empty() {
                return Ok(0);
            }
            return Err(io::Error::other("zip: write to directory"));
        }
        self.w.write_file(p)?;
        Ok(p.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn put16(b: &mut Vec<u8>, v: u16) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut Vec<u8>, v: u64) {
    b.extend_from_slice(&v.to_le_bytes());
}

impl<W: Write> Writer<W> {
    /// `NewWriter`: write a ZIP archive to `w`.
    pub fn new(w: W) -> Self {
        Self {
            cw: CountWriter {
                w: BufWriter::new(w),
                count: 0,
            },
            dir: Vec::new(),
            last: None,
            closed: false,
            compressors: HashMap::new(),
            comment: String::new(),
        }
    }

    /// `SetOffset`: set the offset of the archive's beginning within the
    /// underlying writer, for archives appended to other data. Panics if data
    /// has already been written, as in Go.
    pub fn set_offset(&mut self, n: i64) {
        if self.cw.count != 0 {
            panic!("zip: SetOffset called after data was written");
        }
        self.cw.count = n;
    }

    /// Recover the underlying writer (Rust extension; Go has no equivalent).
    /// Call [`Writer::close`] first: unfinished members are not completed.
    pub fn into_inner(self) -> io::Result<W> {
        self.cw.w.into_inner().map_err(|e| e.into_error())
    }

    /// `Flush`: flush buffered data to the underlying writer.
    pub fn flush(&mut self) -> io::Result<()> {
        self.cw.w.flush()
    }

    /// `SetComment`: set the end-of-central-directory comment.
    pub fn set_comment(&mut self, comment: &str) -> io::Result<()> {
        if comment.len() > MAX_UINT16 {
            return Err(io::Error::other("zip: Writer.Comment too long"));
        }
        self.comment = comment.to_string();
        Ok(())
    }

    /// `RegisterCompressor`: use `comp` for `method` in this writer,
    /// overriding the process-wide registry.
    pub fn register_compressor(&mut self, method: u16, comp: Compressor) {
        self.compressors.insert(method, comp);
    }

    fn compressor(&self, method: u16) -> Option<Compressor> {
        self.compressors
            .get(&method)
            .cloned()
            .or_else(|| compressor(method))
    }

    /// The headers of the members created so far, in order, as the writer
    /// holds them: the headers Go updates in place. CRC and sizes are final
    /// once the member is finished, and a zip64 extra field is appended by
    /// [`Writer::close`], as in Go.
    pub fn headers(&self) -> impl Iterator<Item = &FileHeader> {
        self.dir.iter().map(|record| &record.fh)
    }

    /// `Create`: add a file with DEFLATE compression and the given name.
    pub fn create(&mut self, name: &str) -> io::Result<FileWriter<'_, W>> {
        let fh = FileHeader {
            name: name.to_string(),
            method: DEFLATE,
            ..FileHeader::default()
        };
        self.create_header(&fh)
    }

    fn prepare(&mut self) -> io::Result<()> {
        if self.last.as_ref().is_some_and(|l| !l.closed) {
            self.close_last()?;
        }
        Ok(())
    }

    /// `CreateHeader`: add a file using the given header. The writer works on a
    /// copy, where Go updates the header it is given in place; the updated
    /// header is [`FileWriter::header`], [`FileWriter::finish`] and
    /// [`Writer::headers`].
    pub fn create_header(&mut self, fh: &FileHeader) -> io::Result<FileWriter<'_, W>> {
        self.prepare()?;
        let mut fh = fh.clone();

        let (valid1, require1) = detect_utf8(fh.name_bytes());
        let (valid2, require2) = detect_utf8(fh.comment_bytes());
        if fh.non_utf8 {
            fh.flags &= !0x800;
        } else if (require1 || require2) && (valid1 && valid2) {
            fh.flags |= 0x800;
        }

        fh.creator_version = fh.creator_version & 0xff00 | ZIP_VERSION_20;
        fh.reader_version = ZIP_VERSION_20;

        if !time_is_zero(&fh.modified) {
            let (date, time) = time_to_ms_dos_time(&fh.modified);
            fh.modified_date = date;
            fh.modified_time = time;
            let mt = time_parts(&fh.modified).0 as u32;
            put16(&mut fh.extra, EXT_TIME_EXTRA_ID);
            put16(&mut fh.extra, 5);
            fh.extra.push(1);
            put32(&mut fh.extra, mt);
        }

        let offset = self.cw.count as u64;
        let mut state = None;
        let is_dir = fh.name_bytes().ends_with(b"/");
        if is_dir {
            fh.method = STORE;
            fh.flags &= !0x8;
            fh.compressed_size = 0;
            fh.compressed_size64 = 0;
            fh.uncompressed_size = 0;
            fh.uncompressed_size64 = 0;
        } else {
            fh.flags |= 0x8;
            let comp = self.compressor(fh.method).ok_or(Error::Algorithm)?;
            let sink = Rc::new(RefCell::new(Vec::new()));
            let wc = comp(Box::new(Sink(sink.clone())))?;
            state = Some(FileState {
                idx: self.dir.len(),
                comp: Some(wc),
                sink,
                comp_count: 0,
                raw_count: 0,
                crc: Crc32::ieee(),
                closed: false,
                raw: false,
            });
        }
        self.dir.push(DirRecord {
            fh,
            offset,
            raw: false,
        });
        let idx = self.dir.len() - 1;
        write_header(&mut self.cw, &self.dir[idx])?;
        self.last = state;
        Ok(FileWriter {
            w: self,
            dir: is_dir,
        })
    }

    /// `CreateRaw`: add a file whose contents are already compressed. The
    /// caller supplies the CRC-32 and sizes in the header.
    pub fn create_raw(&mut self, fh: &FileHeader) -> io::Result<FileWriter<'_, W>> {
        self.prepare()?;
        let mut fh = fh.clone();
        fh.compressed_size = fh.compressed_size64.min(UINT32_MAX) as u32;
        fh.uncompressed_size = fh.uncompressed_size64.min(UINT32_MAX) as u32;
        let is_dir = fh.name_bytes().ends_with(b"/");
        let offset = self.cw.count as u64;
        self.dir.push(DirRecord {
            fh,
            offset,
            raw: true,
        });
        let idx = self.dir.len() - 1;
        write_header(&mut self.cw, &self.dir[idx])?;
        if is_dir {
            self.last = None;
            return Ok(FileWriter { w: self, dir: true });
        }
        self.last = Some(FileState {
            idx,
            comp: None,
            sink: Rc::new(RefCell::new(Vec::new())),
            comp_count: 0,
            raw_count: 0,
            crc: Crc32::ieee(),
            closed: false,
            raw: true,
        });
        Ok(FileWriter {
            w: self,
            dir: false,
        })
    }

    /// `Copy`: copy the raw contents of `f` (from a [`super::Reader`]) into
    /// the archive without decompressing them.
    pub fn copy<R: crate::io::ReadAt>(&mut self, f: &super::File<R>) -> io::Result<()> {
        let mut r = f.open_raw()?;
        let fh = f.file_header.clone();
        let mut fw = self.create_raw(&fh)?;
        io::copy(&mut r, &mut fw)?;
        Ok(())
    }

    fn write_file(&mut self, p: &[u8]) -> io::Result<()> {
        let Some(st) = self.last.as_mut() else {
            return Err(io::Error::other("zip: write to closed file"));
        };
        if st.closed {
            return Err(io::Error::other("zip: write to closed file"));
        }
        if st.raw {
            return self.cw.write_all(p);
        }
        st.crc.update(p);
        st.comp
            .as_mut()
            .expect("open member has a compressor")
            .write_all(p)?;
        st.raw_count += p.len() as u64;
        let drained = std::mem::take(&mut *st.sink.borrow_mut());
        st.comp_count += drained.len() as u64;
        self.cw.write_all(&drained)
    }

    fn close_last(&mut self) -> io::Result<()> {
        let Some(mut st) = self.last.take() else {
            return Ok(());
        };
        let r = self.close_state(&mut st);
        self.last = Some(st);
        r
    }

    fn close_state(&mut self, st: &mut FileState) -> io::Result<()> {
        if st.closed {
            return Err(io::Error::other("zip: file closed twice"));
        }
        st.closed = true;
        if st.raw {
            return write_data_descriptor(&mut self.cw, &self.dir[st.idx].fh);
        }
        st.comp
            .as_mut()
            .expect("open member has a compressor")
            .close()?;
        let drained = std::mem::take(&mut *st.sink.borrow_mut());
        st.comp_count += drained.len() as u64;
        self.cw.write_all(&drained)?;

        let mut sum = Vec::new();
        st.crc.sum(&mut sum);
        let fh = &mut self.dir[st.idx].fh;
        fh.crc32 = u32::from_be_bytes(sum.try_into().expect("CRC-32 is four bytes"));
        fh.compressed_size64 = st.comp_count;
        fh.uncompressed_size64 = st.raw_count;
        if fh.compressed_size64 > UINT32_MAX || fh.uncompressed_size64 > UINT32_MAX {
            fh.compressed_size = UINT32_MAX as u32;
            fh.uncompressed_size = UINT32_MAX as u32;
            fh.reader_version = ZIP_VERSION_45;
        } else {
            fh.compressed_size = fh.compressed_size64 as u32;
            fh.uncompressed_size = fh.uncompressed_size64 as u32;
        }
        write_data_descriptor(&mut self.cw, &self.dir[st.idx].fh)
    }

    /// `Close`: finish the archive by writing the central directory. It does
    /// not close the underlying writer.
    pub fn close(&mut self) -> io::Result<()> {
        if self.last.as_ref().is_some_and(|l| !l.closed) {
            self.close_last()?;
            self.last = None;
        }
        if self.closed {
            return Err(io::Error::other("zip: writer closed twice"));
        }
        self.closed = true;

        let start = self.cw.count;
        let mut used_zip64 = false;
        for h in self.dir.iter_mut() {
            let fh = &mut h.fh;
            let mut reader_version = fh.reader_version;
            if fh.compressed_size64 >= UINT32_MAX
                || fh.uncompressed_size64 >= UINT32_MAX
                || h.offset >= UINT32_MAX
            {
                used_zip64 = true;
                reader_version = reader_version.max(ZIP_VERSION_45);
                let mut body = Vec::new();
                if fh.uncompressed_size64 >= UINT32_MAX {
                    put64(&mut body, fh.uncompressed_size64);
                }
                if fh.compressed_size64 >= UINT32_MAX {
                    put64(&mut body, fh.compressed_size64);
                }
                if h.offset >= UINT32_MAX {
                    put64(&mut body, h.offset);
                }
                put16(&mut fh.extra, ZIP64_EXTRA_ID);
                put16(&mut fh.extra, body.len() as u16);
                fh.extra.extend_from_slice(&body);
            }
            let name = fh.name_bytes().to_vec();
            let comment = fh.comment_bytes().to_vec();
            let mut b = Vec::with_capacity(DIRECTORY_HEADER_LEN);
            put32(&mut b, DIRECTORY_HEADER_SIGNATURE);
            put16(&mut b, fh.creator_version);
            put16(&mut b, reader_version);
            put16(&mut b, fh.flags);
            put16(&mut b, fh.method);
            put16(&mut b, fh.modified_time);
            put16(&mut b, fh.modified_date);
            put32(&mut b, fh.crc32);
            put32(&mut b, fh.compressed_size64.min(UINT32_MAX) as u32);
            put32(&mut b, fh.uncompressed_size64.min(UINT32_MAX) as u32);
            put16(&mut b, name.len() as u16);
            put16(&mut b, fh.extra.len() as u16);
            put16(&mut b, comment.len() as u16);
            put32(&mut b, 0); // disk number start, internal attributes
            put32(&mut b, fh.external_attrs);
            put32(&mut b, h.offset.min(UINT32_MAX) as u32);
            b.extend_from_slice(&name);
            b.extend_from_slice(&fh.extra);
            b.extend_from_slice(&comment);
            self.cw.write_all(&b)?;
        }
        let end = self.cw.count;

        let records = self.dir.len() as u64;
        let size = (end - start) as u64;
        let offset = start as u64;

        if used_zip64 || records >= UINT16_MAX || size >= UINT32_MAX || offset >= UINT32_MAX {
            let mut b = Vec::with_capacity(DIRECTORY64_END_LEN + DIRECTORY64_LOC_LEN);
            put32(&mut b, DIRECTORY64_END_SIGNATURE);
            put64(&mut b, DIRECTORY64_END_LEN as u64 - 12);
            put16(&mut b, ZIP_VERSION_45);
            put16(&mut b, ZIP_VERSION_45);
            put32(&mut b, 0);
            put32(&mut b, 0);
            put64(&mut b, records);
            put64(&mut b, records);
            put64(&mut b, size);
            put64(&mut b, offset);

            put32(&mut b, DIRECTORY64_LOC_SIGNATURE);
            put32(&mut b, 0);
            put64(&mut b, end as u64);
            put32(&mut b, 1);
            self.cw.write_all(&b)?;
        }

        let mut b = Vec::with_capacity(DIRECTORY_END_LEN);
        let comment = self.comment.as_bytes();
        put32(&mut b, DIRECTORY_END_SIGNATURE);
        put32(&mut b, 0); // disk numbers
        put16(&mut b, records.min(UINT16_MAX) as u16);
        put16(&mut b, records.min(UINT16_MAX) as u16);
        put32(&mut b, size.min(UINT32_MAX) as u32);
        put32(&mut b, offset.min(UINT32_MAX) as u32);
        put16(&mut b, comment.len() as u16);
        b.extend_from_slice(comment);
        self.cw.write_all(&b)?;
        self.cw.w.flush()
    }

    /// `AddFS`: add the files of `fsys` to the archive with DEFLATE
    /// compression. Only regular files and directories are supported.
    pub fn add_fs(&mut self, fsys: &dyn fs::FS) -> io::Result<()> {
        fs::walk_dir(
            fsys,
            ".",
            |name: &str, d: Option<&dyn fs::DirEntry>, err| {
                if let Some(e) = err {
                    return Err(e);
                }
                let d = d.expect("walk_dir provides an entry when there is no error");
                if name == "." {
                    return Ok(());
                }
                let info = iofs::FsInfo(d.info()?);
                if !d.is_dir() && !iofs::FileInfo::mode(&info).is_regular() {
                    return Err(io::Error::other("zip: cannot add non-regular file"));
                }
                let mut h = file_info_header(&info)?;
                h.name = name.to_string();
                if d.is_dir() {
                    h.name.push('/');
                }
                h.method = DEFLATE;
                let mut fw = self.create_header(&h)?;
                if d.is_dir() {
                    return Ok(());
                }
                let mut f = fsys.open(name)?;
                io::copy(&mut f, &mut fw)?;
                Ok(())
            },
        )
    }
}

fn write_header<W: Write>(w: &mut CountWriter<W>, h: &DirRecord) -> io::Result<()> {
    let fh = &h.fh;
    let name = fh.name_bytes().to_vec();
    if name.len() > MAX_UINT16 {
        return Err(io::Error::other("zip: FileHeader.Name too long"));
    }
    if fh.extra.len() > MAX_UINT16 {
        return Err(io::Error::other("zip: FileHeader.Extra too long"));
    }
    let mut zip64_extra: Vec<u8> = Vec::new();
    let mut reader_version = fh.reader_version;
    let no_data_descriptor = h.raw && !fh.has_data_descriptor();
    if no_data_descriptor
        && (fh.compressed_size64 > UINT32_MAX || fh.uncompressed_size64 > UINT32_MAX)
    {
        reader_version = reader_version.max(ZIP_VERSION_45);
        put16(&mut zip64_extra, ZIP64_EXTRA_ID);
        put16(&mut zip64_extra, 16);
        put64(&mut zip64_extra, fh.uncompressed_size64);
        put64(&mut zip64_extra, fh.compressed_size64);
    }
    let mut b = Vec::with_capacity(FILE_HEADER_LEN);
    put32(&mut b, FILE_HEADER_SIGNATURE);
    put16(&mut b, reader_version);
    put16(&mut b, fh.flags);
    put16(&mut b, fh.method);
    put16(&mut b, fh.modified_time);
    put16(&mut b, fh.modified_date);
    if no_data_descriptor {
        put32(&mut b, fh.crc32);
        if !zip64_extra.is_empty() {
            put32(&mut b, UINT32_MAX as u32);
            put32(&mut b, UINT32_MAX as u32);
        } else {
            put32(&mut b, fh.compressed_size64 as u32);
            put32(&mut b, fh.uncompressed_size64 as u32);
        }
    } else {
        put32(&mut b, 0);
        put32(&mut b, 0);
        put32(&mut b, 0);
    }
    put16(&mut b, name.len() as u16);
    put16(&mut b, (fh.extra.len() + zip64_extra.len()) as u16);
    b.extend_from_slice(&name);
    b.extend_from_slice(&fh.extra);
    b.extend_from_slice(&zip64_extra);
    w.write_all(&b)
}

fn write_data_descriptor<W: Write>(w: &mut CountWriter<W>, fh: &FileHeader) -> io::Result<()> {
    if !fh.has_data_descriptor() {
        return Ok(());
    }
    let mut b = Vec::with_capacity(DATA_DESCRIPTOR64_LEN);
    put32(&mut b, DATA_DESCRIPTOR_SIGNATURE);
    put32(&mut b, fh.crc32);
    if fh.compressed_size64 > UINT32_MAX || fh.uncompressed_size64 > UINT32_MAX {
        put64(&mut b, fh.compressed_size64);
        put64(&mut b, fh.uncompressed_size64);
    } else {
        put32(&mut b, fh.compressed_size);
        put32(&mut b, fh.uncompressed_size);
    }
    w.write_all(&b)
}
