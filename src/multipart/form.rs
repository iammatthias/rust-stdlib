//! Go's `multipart.Form`, `FileHeader` and `File`, and [`Reader::read_form`].
//!
//! File parts are kept in memory up to the `max_memory` given to
//! [`Reader::read_form`]; larger ones are written to temporary files named
//! `multipart-*` in `$TMPDIR` (`/tmp` if unset), with Go's memory accounting
//! and [`ERR_MESSAGE_TOO_LARGE`]. As in Go, nothing deletes those files for
//! you: call [`Form::remove_all`] when done (dropping a [`Form`] leaves them
//! in place). On non-Unix targets there is no `os` module, so every file
//! stays in memory.
use super::reader::max_mime_headers;
use super::{stream_error, Reader, ERR_MESSAGE_TOO_LARGE};
use crate::archive::iofs::godebug;
use crate::io::{ReadAt, ReadError, SectionReader};
use crate::net::textproto::MIMEHeader;
use std::collections::BTreeMap;
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::Arc;

/// Form values and file parts keyed by field name (Go's `multipart.Form`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Form {
    pub value: BTreeMap<String, Vec<String>>,
    pub file: BTreeMap<String, Vec<FileHeader>>,
}

impl Form {
    /// Removes any temporary files associated with the form. Files that are
    /// already gone are ignored; the first other error is returned after all
    /// removals were attempted.
    pub fn remove_all(&self) -> io::Result<()> {
        let mut first = None;
        for header in self.file.values().flatten() {
            #[cfg(unix)]
            if let Storage::Disk { path, .. } = &header.storage {
                if let Err(e) = crate::os::remove(path) {
                    if !crate::os::is_not_exist(&e) && first.is_none() {
                        first = Some(e);
                    }
                }
            }
            #[cfg(not(unix))]
            let _ = header;
        }
        first.map_or(Ok(()), Err)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Storage {
    Memory(Arc<[u8]>),
    #[cfg(unix)]
    Disk {
        path: String,
        offset: i64,
    },
}

/// A file part of a [`Form`] (Go's `multipart.FileHeader`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileHeader {
    pub filename: String,
    pub header: MIMEHeader,
    pub size: i64,
    storage: Storage,
}

impl FileHeader {
    /// Opens the file contents, in memory or from the temporary file, without
    /// copying them. The returned [`File`] is independent of this header.
    pub fn open(&self) -> io::Result<File> {
        Ok(File(match &self.storage {
            Storage::Memory(data) => Inner::Memory(SectionReader::new(
                Bytes(Arc::clone(data)),
                0,
                data.len() as i64,
            )),
            #[cfg(unix)]
            Storage::Disk { path, offset } => Inner::Disk(SectionReader::new(
                crate::os::open(path)?,
                *offset,
                self.size,
            )),
        }))
    }
}

/// Shared bytes as a [`ReadAt`] source.
#[derive(Clone, Debug)]
struct Bytes(Arc<[u8]>);

impl ReadAt for Bytes {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize, ReadError> {
        self.0.as_ref().read_at(buf, offset)
    }
}

#[derive(Debug)]
enum Inner {
    Memory(SectionReader<Bytes>),
    #[cfg(unix)]
    Disk(SectionReader<crate::os::File>),
}

/// The contents of a file part (Go's `multipart.File`): [`Read`], [`Seek`]
/// and [`ReadAt`]. It is closed when dropped.
#[derive(Debug)]
pub struct File(Inner);

impl File {
    /// Releases the file; the same as dropping it, but reports a close error
    /// of a file on disk.
    pub fn close(self) -> io::Result<()> {
        match self.0 {
            Inner::Memory(_) => Ok(()),
            #[cfg(unix)]
            Inner::Disk(section) => section.into_inner().close(),
        }
    }
}

impl Read for File {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.0 {
            Inner::Memory(r) => r.read(buf),
            #[cfg(unix)]
            Inner::Disk(r) => r.read(buf),
        }
    }
}

impl Seek for File {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match &mut self.0 {
            Inner::Memory(r) => r.seek(pos),
            #[cfg(unix)]
            Inner::Disk(r) => r.seek(pos),
        }
    }
}

impl ReadAt for File {
    /// Reads at `offset`, which is relative to the start of the file; a short
    /// read at the end is an [`Error::Eof`](crate::io::Error::Eof) error that
    /// carries the count, as in Go.
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize, ReadError> {
        match &self.0 {
            Inner::Memory(r) => r.read_at(buf, offset),
            #[cfg(unix)]
            Inner::Disk(r) => r.read_at(buf, offset),
        }
    }
}

/// Go's `mimeHeaderSize`: the budget charged for a file part's headers.
fn header_size(header: &MIMEHeader) -> i64 {
    let mut size: i64 = 400;
    for (key, values) in header.iter() {
        size += key.len() as i64 + 200;
        size += values.iter().map(|v| v.len() as i64).sum::<i64>();
    }
    size
}

fn too_large() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, ERR_MESSAGE_TOO_LARGE)
}

/// Go's default for `multipartmaxparts`: the `GODEBUG` setting when it is a
/// non-negative integer.
fn max_parts() -> i64 {
    godebug("multipartmaxparts")
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|v| *v >= 0)
        .unwrap_or(1000)
}

/// The temporary file shared by the spilled parts of one `read_form` call.
#[cfg(unix)]
struct Spill {
    file: Option<crate::os::File>,
    /// Where the next part starts in `file`.
    offset: i64,
    /// Go's `combineFiles`: all spilled parts share one temporary file
    /// unless `GODEBUG=multipartfiles=distinct`.
    combine: bool,
}

impl<R: Read> Reader<R> {
    /// Reads every part into a [`Form`] (Go's `Reader.ReadForm`).
    ///
    /// Parts with a `filename` are files; the others are values, which must
    /// be UTF-8. It stores up to `max_memory` bytes of file content, plus 10
    /// MiB reserved for everything else, in memory. A file part that does not
    /// fit is written to a temporary file in `$TMPDIR` (see
    /// [`Form::remove_all`] and [`FileHeader::open`]). Returns
    /// [`ERR_MESSAGE_TOO_LARGE`] when a budget is exceeded or there are more
    /// than 1000 parts; temporary files created before an error are removed.
    pub fn read_form(&mut self, max_memory: i64) -> io::Result<Form> {
        let mut form = Form::default();
        #[cfg(unix)]
        let mut spill = Spill {
            file: None,
            offset: 0,
            combine: godebug("multipartfiles").as_deref() != Some("distinct"),
        };
        #[cfg(unix)]
        let result = self.fill_form(max_memory, &mut form, &mut spill);
        #[cfg(not(unix))]
        let result = self.fill_form(max_memory, &mut form);
        // Go's deferred cleanup.
        #[cfg(unix)]
        {
            if let Some(file) = spill.file.take() {
                let _ = file.close();
                if result.is_err() {
                    let _ = crate::os::remove(file.name());
                }
            }
            // Go also marks headers `tmpshared` here when several parts share
            // the file; every header opens a section of its file regardless,
            // which reads the same bytes.
        }
        match result {
            Ok(()) => Ok(form),
            Err(e) => {
                let _ = form.remove_all();
                Err(e)
            }
        }
    }

    fn fill_form(
        &mut self,
        max_memory: i64,
        form: &mut Form,
        #[cfg(unix)] spill: &mut Spill,
    ) -> io::Result<()> {
        let mut max_parts = max_parts();
        let mut max_headers = max_mime_headers();
        let mut max_file_memory_bytes = max_memory;
        if max_file_memory_bytes == i64::MAX {
            max_file_memory_bytes -= 1;
        }
        let mut max_memory_bytes = max_memory.wrapping_add(10 << 20);
        if max_memory_bytes <= 0 {
            max_memory_bytes = if max_memory < 0 { 0 } else { i64::MAX };
        }
        while let Some(mut part) = self.next_part_with(false, max_memory_bytes, max_headers)? {
            if max_parts <= 0 {
                return Err(too_large());
            }
            max_parts -= 1;
            let name = part.form_name();
            if name.is_empty() {
                continue;
            }
            let filename = part.file_name();
            // Go charges a fixed overhead per map entry.
            max_memory_bytes -= name.len() as i64;
            max_memory_bytes -= 200;
            if max_memory_bytes < 0 {
                return Err(too_large());
            }
            let mut body = Vec::new();
            if filename.is_empty() {
                // A value is read up to the budget plus one byte.
                let n = Read::take(&mut part, max_memory_bytes.saturating_add(1).max(0) as u64)
                    .read_to_end(&mut body)? as i64;
                max_memory_bytes -= n;
                if max_memory_bytes < 0 {
                    return Err(too_large());
                }
                let value = String::from_utf8(body)
                    .map_err(|_| stream_error("multipart value is not UTF-8"))?;
                form.value.entry(name).or_default().push(value);
                continue;
            }
            max_memory_bytes -= header_size(&part.header);
            max_memory_bytes -= 200;
            max_memory_bytes -= 100;
            if max_memory_bytes < 0 {
                return Err(too_large());
            }
            for values in part.header.iter().map(|(_, v)| v) {
                max_headers -= values.len() as i64;
            }
            let n = Read::take(
                &mut part,
                max_file_memory_bytes.saturating_add(1).max(0) as u64,
            )
            .read_to_end(&mut body)? as i64;
            let storage;
            let size;
            if n > max_file_memory_bytes {
                // Too large for memory: the part goes to a temporary file and
                // its bytes are not charged to the memory budget.
                #[cfg(unix)]
                {
                    use std::io::Write;
                    if spill.file.is_none() {
                        spill.file = Some(crate::os::create_temp("", "multipart-")?);
                    }
                    let file = spill
                        .file
                        .as_ref()
                        .expect("temporary file was just created");
                    let mut out = file;
                    out.write_all(&body)?;
                    let remaining = io::copy(&mut part, &mut out)? as i64;
                    size = body.len() as i64 + remaining;
                    storage = Storage::Disk {
                        path: file.name().to_string(),
                        offset: if spill.combine { spill.offset } else { 0 },
                    };
                    spill.offset += size;
                    if !spill.combine {
                        // A failed close leaves the file in place for the
                        // caller's cleanup, as in Go.
                        if let Some(file) = &spill.file {
                            file.close()?;
                        }
                        spill.file = None;
                    }
                }
                #[cfg(not(unix))]
                {
                    part.read_to_end(&mut body)?;
                    size = body.len() as i64;
                    storage = Storage::Memory(body.into());
                }
            } else {
                max_file_memory_bytes -= n;
                max_memory_bytes -= n;
                size = body.len() as i64;
                storage = Storage::Memory(body.into());
            }
            form.file.entry(name).or_default().push(FileHeader {
                filename,
                header: part.header,
                size,
                storage,
            });
        }
        Ok(())
    }
}
