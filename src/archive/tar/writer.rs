//! Sequential tar writer following Go's `archive/tar/writer.go`: format
//! selection (USTAR, PAX, GNU), PAX records, GNU long names and `AddFS`.
//!
//! Go keeps sparse-file writing disabled behind unexported code. This module
//! enables the same algorithm through [`Writer::write_sparse_header`] (PAX 1.0
//! maps, or old GNU maps for `TypeGNUSparse`).
use super::header::*;
use super::reader::Fail;
use super::sparse::*;
use super::strconv::*;
use super::Error;
use crate::archive::iofs::{self, time_is_zero, time_parts, time_round_second, time_zero};
use crate::io::fs;
use std::{
    collections::BTreeMap,
    io::{self, Write},
};

struct SparseWriter {
    /// Data fragments; the final element always remains.
    data: Vec<SparseEntry>,
    idx: usize,
    pos: i64,
}

/// A sequential tar writer (Go's `tar.Writer`). Call [`Writer::write_header`],
/// write exactly `size` bytes of data, and finish with [`Writer::close`].
/// [`Write::flush`] is Go's `Flush`: it pads the current entry and fails if
/// bytes are still owed.
pub struct Writer<W: Write> {
    w: W,
    pad: i64,
    /// Bytes of the current entry still to be written (physical).
    nb: i64,
    sparse: Option<SparseWriter>,
    err: Option<Fail>,
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Ustar,
    Pax,
    Gnu,
}

fn set_format(blk: &mut [u8; BLOCK_SIZE], format: Format) {
    if format.has(FORMAT_GNU) {
        blk[257..263].copy_from_slice(b"ustar ");
        blk[263..265].copy_from_slice(b" \0");
    } else if format.has(Format(FORMAT_USTAR.0 | FORMAT_PAX.0)) {
        blk[257..263].copy_from_slice(b"ustar\0");
        blk[263..265].copy_from_slice(b"00");
    }
    let sum: i64 = blk
        .iter()
        .enumerate()
        .map(|(i, &c)| {
            if (148..156).contains(&i) {
                i64::from(b' ')
            } else {
                i64::from(c)
            }
        })
        .sum();
    let mut f = Formatter::default();
    f.octal(&mut blk[148..155], sum);
    blk[155] = b' ';
}

impl<W: Write> Writer<W> {
    /// `NewWriter`: write a tar archive to `w`.
    pub fn new(w: W) -> Self {
        Self {
            w,
            pad: 0,
            nb: 0,
            sparse: None,
            err: None,
        }
    }

    fn logical_remaining(&self) -> i64 {
        match &self.sparse {
            None => self.nb,
            Some(s) => s.data.last().map_or(0, |d| d.end_offset()) - s.pos,
        }
    }

    fn sticky<T>(&mut self, r: io::Result<T>) -> io::Result<T> {
        if let Err(e) = &r {
            self.err = Some(Fail::io(io::Error::new(e.kind(), e.to_string())));
            if let Some(t) = Error::from_io(e) {
                self.err = Some(Fail::Tar(t));
            }
        }
        r
    }

    fn zero_pad(&mut self) -> io::Result<()> {
        let zeros = [0u8; BLOCK_SIZE];
        let pad = self.pad as usize;
        let r = self.w.write_all(&zeros[..pad]);
        self.sticky(r)?;
        self.pad = 0;
        Ok(())
    }

    /// Finish the current entry: fails if its declared size was not written,
    /// otherwise writes the padding up to the block boundary.
    fn flush_entry(&mut self) -> io::Result<()> {
        if let Some(e) = &self.err {
            return Err(e.clone().into_io());
        }
        let nb = self.logical_remaining();
        if nb > 0 {
            return Err(io::Error::other(format!(
                "archive/tar: missed writing {nb} bytes"
            )));
        }
        self.zero_pad()
    }

    /// `WriteHeader`: write `hdr` and prepare to accept the entry's contents.
    /// A header no format can encode returns an error and leaves the writer
    /// usable.
    pub fn write_header(&mut self, hdr: &Header) -> io::Result<()> {
        self.write_header_inner(hdr, None)
    }

    /// Write the header of a sparse file whose holes are `holes` (offsets in
    /// the logical file of `hdr.size` bytes). Only the data between holes is
    /// stored; write the full logical content to the writer and every byte in
    /// a hole must be zero. With `typeflag` `TYPE_GNU_SPARSE` the old GNU map
    /// is used, otherwise a PAX 1.0 map.
    pub fn write_sparse_header(&mut self, hdr: &Header, holes: &[SparseEntry]) -> io::Result<()> {
        self.write_header_inner(hdr, Some(holes))
    }

    fn write_header_inner(
        &mut self,
        hdr: &Header,
        holes: Option<&[SparseEntry]>,
    ) -> io::Result<()> {
        self.flush_entry()?;
        let mut h = hdr.clone();
        if h.typeflag == TYPE_REG_A {
            h.typeflag = if h.name.ends_with('/') {
                TYPE_DIR
            } else {
                TYPE_REG
            };
        }
        if h.format == FORMAT_UNKNOWN {
            h.mod_time = time_round_second(&h.mod_time);
            h.access_time = time_zero();
            h.change_time = time_zero();
        }
        let spd = match holes {
            Some(holes) => {
                if is_header_only_type(h.typeflag) {
                    return Err(
                        Error::CannotEncode("header-only type cannot be sparse".into()).into(),
                    );
                }
                if !validate_sparse_entries(holes, h.size) {
                    return Err(Error::CannotEncode("invalid sparse holes".into()).into());
                }
                Some(holes)
            }
            None => None,
        };
        let (allowed, pax) = h.allowed_formats(spd.is_some()).map_err(io::Error::from)?;
        let r = if allowed.has(FORMAT_USTAR) {
            self.write_ustar_header(&mut h)
        } else if allowed.has(FORMAT_PAX) {
            self.write_pax_header(&mut h, pax, spd)
        } else if allowed.has(FORMAT_GNU) {
            self.write_gnu_header(&mut h, spd)
        } else {
            return Err(Error::CannotEncode(String::new()).into());
        };
        match r {
            Ok(()) => {
                self.err = None;
                Ok(())
            }
            Err(e) => self.sticky(Err(e)),
        }
    }

    fn template(&self, hdr: &Header, mode: Mode) -> ([u8; BLOCK_SIZE], Formatter) {
        let mut blk = [0u8; BLOCK_SIZE];
        let mut f = Formatter::default();
        let mod_time = if time_is_zero(&hdr.mod_time) {
            0
        } else {
            time_parts(&hdr.mod_time).0
        };
        let s = |f: &mut Formatter, b: &mut [u8], v: &str| {
            if mode == Mode::Pax {
                f.string(b, &to_ascii(v));
            } else {
                f.string(b, v);
            }
        };
        let n = |f: &mut Formatter, b: &mut [u8], v: i64| {
            if mode == Mode::Gnu {
                f.numeric(b, v);
            } else {
                f.octal(b, v);
            }
        };
        blk[156] = hdr.typeflag;
        s(&mut f, &mut blk[0..100], &hdr.name);
        s(&mut f, &mut blk[157..257], &hdr.linkname);
        n(&mut f, &mut blk[100..108], hdr.mode);
        n(&mut f, &mut blk[108..116], hdr.uid);
        n(&mut f, &mut blk[116..124], hdr.gid);
        n(&mut f, &mut blk[124..136], hdr.size);
        n(&mut f, &mut blk[136..148], mod_time);
        s(&mut f, &mut blk[265..297], &hdr.uname);
        s(&mut f, &mut blk[297..329], &hdr.gname);
        n(&mut f, &mut blk[329..337], hdr.devmajor);
        n(&mut f, &mut blk[337..345], hdr.devminor);
        (blk, f)
    }

    fn write_ustar_header(&mut self, hdr: &mut Header) -> io::Result<()> {
        let mut name_prefix = String::new();
        if let Some((prefix, suffix)) = split_ustar_path(&hdr.name) {
            name_prefix = prefix;
            hdr.name = suffix;
        }
        let (mut blk, mut f) = self.template(hdr, Mode::Ustar);
        f.string(&mut blk[345..500], &name_prefix);
        set_format(&mut blk, FORMAT_USTAR);
        if let Some(e) = f.err {
            return Err(e.into());
        }
        self.write_raw_header(&blk, hdr.size, hdr.typeflag)
    }

    fn write_pax_header(
        &mut self,
        hdr: &mut Header,
        mut pax: BTreeMap<String, String>,
        holes: Option<&[SparseEntry]>,
    ) -> io::Result<()> {
        let real_name = hdr.name.clone();
        let real_size = hdr.size;
        let mut sparse_data: Option<(Vec<SparseEntry>, Vec<u8>)> = None;
        if let Some(holes) = holes {
            let sph = align_sparse_entries(holes, hdr.size);
            let spd = invert_sparse_entries(&sph, hdr.size);
            hdr.size = 0;
            let mut spb = format!("{}\n", spd.len()).into_bytes();
            for s in &spd {
                hdr.size += s.length;
                spb.extend_from_slice(format!("{}\n{}\n", s.offset, s.length).as_bytes());
            }
            let pad = block_padding(spb.len() as i64) as usize;
            spb.resize(spb.len() + pad, 0);
            hdr.size += spb.len() as i64;

            let (dir, file) = crate::path::split(&real_name);
            hdr.name = crate::path::join(&[dir, "GNUSparseFile.0", file]);
            pax.insert(PAX_GNU_SPARSE_MAJOR.into(), "1".into());
            pax.insert(PAX_GNU_SPARSE_MINOR.into(), "0".into());
            pax.insert(PAX_GNU_SPARSE_NAME.into(), real_name.clone());
            pax.insert(PAX_GNU_SPARSE_REAL_SIZE.into(), real_size.to_string());
            pax.insert(PAX_SIZE.into(), hdr.size.to_string());
            pax.remove(PAX_PATH);
            sparse_data = Some((spd, spb));
        }

        let is_global = hdr.typeflag == TYPE_X_GLOBAL_HEADER;
        if !pax.is_empty() || is_global {
            let mut buf = String::new();
            for (k, v) in &pax {
                buf.push_str(&format_pax_record(k, v)?);
            }
            let (name, flag) = if is_global {
                let name = if real_name.is_empty() {
                    "GlobalHead.0.0".to_string()
                } else {
                    real_name.clone()
                };
                (name, TYPE_X_GLOBAL_HEADER)
            } else {
                let (dir, file) = crate::path::split(&real_name);
                (
                    crate::path::join(&[dir, "PaxHeaders.0", file]),
                    TYPE_X_HEADER,
                )
            };
            if buf.len() > MAX_SPECIAL_FILE_SIZE {
                return Err(Error::FieldTooLong.into());
            }
            self.write_raw_file(&name, buf.as_bytes(), flag, FORMAT_PAX)?;
            if is_global {
                return Ok(());
            }
        }

        // Formatting errors are expected here; PAX records carry the truth.
        let (mut blk, _) = self.template(hdr, Mode::Pax);
        set_format(&mut blk, FORMAT_PAX);
        self.write_raw_header(&blk, hdr.size, hdr.typeflag)?;

        if let Some((spd, spb)) = sparse_data {
            self.write_data(&spb)?;
            self.sparse = Some(SparseWriter {
                data: spd,
                idx: 0,
                pos: 0,
            });
        }
        Ok(())
    }

    fn write_gnu_header(
        &mut self,
        hdr: &mut Header,
        holes: Option<&[SparseEntry]>,
    ) -> io::Result<()> {
        const LONG_NAME: &str = "././@LongLink";
        if hdr.name.len() > NAME_SIZE {
            let data = format!("{}\0", hdr.name);
            self.write_raw_file(LONG_NAME, data.as_bytes(), TYPE_GNU_LONG_NAME, FORMAT_GNU)?;
        }
        if hdr.linkname.len() > NAME_SIZE {
            let data = format!("{}\0", hdr.linkname);
            self.write_raw_file(LONG_NAME, data.as_bytes(), TYPE_GNU_LONG_LINK, FORMAT_GNU)?;
        }

        let (mut blk, mut f) = self.template(hdr, Mode::Gnu);
        if !time_is_zero(&hdr.access_time) {
            f.numeric(&mut blk[345..357], time_parts(&hdr.access_time).0);
        }
        if !time_is_zero(&hdr.change_time) {
            f.numeric(&mut blk[357..369], time_parts(&hdr.change_time).0);
        }
        let mut spd: Vec<SparseEntry> = Vec::new();
        let mut spb: Vec<u8> = Vec::new();
        if let (Some(holes), TYPE_GNU_SPARSE) = (holes, hdr.typeflag) {
            let sph = align_sparse_entries(holes, hdr.size);
            spd = invert_sparse_entries(&sph, hdr.size);

            // Fill up to `max` entries of the array starting at `base`; the
            // byte after the entries is the "extended" flag.
            let mut fill = |blk: &mut [u8], base: usize, max: usize, sp: &[SparseEntry]| -> usize {
                let mut used = 0;
                while used < max && used < sp.len() {
                    let e = base + used * 24;
                    f.numeric(&mut blk[e..e + 12], sp[used].offset);
                    f.numeric(&mut blk[e + 12..e + 24], sp[used].length);
                    used += 1;
                }
                if sp.len() > used {
                    blk[base + max * 24] = 1;
                }
                used
            };
            let mut used = fill(&mut blk, 386, 4, &spd);
            while used < spd.len() {
                let mut ext = [0u8; BLOCK_SIZE];
                used += fill(&mut ext, 0, BLOCK_SIZE / 24, &spd[used..]);
                spb.extend_from_slice(&ext);
            }

            let real_size = hdr.size;
            hdr.size = spd.iter().map(|s| s.length).sum();
            blk[124..136].fill(0);
            f.numeric(&mut blk[124..136], hdr.size);
            f.numeric(&mut blk[483..495], real_size);
        }
        set_format(&mut blk, FORMAT_GNU);
        self.write_raw_header(&blk, hdr.size, hdr.typeflag)?;

        if !spd.is_empty() {
            self.w.write_all(&spb)?;
            self.sparse = Some(SparseWriter {
                data: spd,
                idx: 0,
                pos: 0,
            });
        }
        Ok(())
    }

    /// Write a PAX or GNU meta-record entry (`name` is truncated to fit).
    fn write_raw_file(
        &mut self,
        name: &str,
        data: &[u8],
        flag: u8,
        format: Format,
    ) -> io::Result<()> {
        let mut blk = [0u8; BLOCK_SIZE];
        let mut name = to_ascii(name);
        if name.len() > NAME_SIZE {
            name.truncate(NAME_SIZE);
        }
        let name = name.trim_end_matches('/');
        let mut f = Formatter::default();
        blk[156] = flag;
        f.string(&mut blk[0..100], name);
        f.octal(&mut blk[100..108], 0);
        f.octal(&mut blk[108..116], 0);
        f.octal(&mut blk[116..124], 0);
        f.octal(&mut blk[124..136], data.len() as i64);
        f.octal(&mut blk[136..148], 0);
        set_format(&mut blk, format);
        if let Some(e) = f.err {
            return Err(e.into());
        }
        self.write_raw_header(&blk, data.len() as i64, flag)?;
        self.write_data(data)
    }

    fn write_raw_header(&mut self, blk: &[u8; BLOCK_SIZE], size: i64, flag: u8) -> io::Result<()> {
        self.flush_entry()?;
        self.w.write_all(blk)?;
        let size = if is_header_only_type(flag) { 0 } else { size };
        self.nb = size;
        self.sparse = None;
        self.pad = block_padding(size);
        Ok(())
    }

    /// Write all of `data` to the current entry.
    fn write_data(&mut self, data: &[u8]) -> io::Result<()> {
        Write::write_all(self, data)
    }

    fn reg_write(&mut self, b: &[u8]) -> io::Result<usize> {
        if b.is_empty() {
            return Ok(0);
        }
        if self.nb == 0 {
            return Err(Error::WriteTooLong.into());
        }
        let take = (b.len() as i64).min(self.nb) as usize;
        self.w.write_all(&b[..take])?;
        self.nb -= take as i64;
        Ok(take)
    }

    fn sparse_write(&mut self, b: &[u8]) -> Result<usize, Fail> {
        let remaining = self.logical_remaining();
        if b.is_empty() {
            return Ok(0);
        }
        if remaining == 0 {
            return Err(Fail::Tar(Error::WriteTooLong));
        }
        let b = &b[..(b.len() as i64).min(remaining) as usize];
        let mut done = 0usize;
        let mut failure: Option<Fail> = None;
        while done < b.len() && failure.is_none() {
            let s = self.sparse.as_ref().unwrap();
            let (data_start, data_end) = (s.data[s.idx].offset, s.data[s.idx].end_offset());
            let pos = s.pos;
            let left = (b.len() - done) as i64;
            let nf;
            if pos < data_start {
                let want = left.min(data_start - pos) as usize;
                match b[done..done + want].iter().position(|&c| c != 0) {
                    Some(i) => {
                        nf = i;
                        failure = Some(Fail::Tar(Error::WriteHole));
                    }
                    None => nf = want,
                }
            } else {
                let want = left.min(data_end - pos) as usize;
                match self.reg_write(&b[done..done + want]) {
                    Ok(n) => nf = n,
                    Err(e) => {
                        nf = 0;
                        failure = Some(match Error::from_io(&e) {
                            Some(Error::WriteTooLong) => Fail::Tar(Error::MissData),
                            _ => Fail::io(e),
                        });
                    }
                }
            }
            done += nf;
            let s = self.sparse.as_mut().unwrap();
            s.pos += nf as i64;
            if s.pos >= data_end && s.idx + 1 < s.data.len() {
                s.idx += 1;
            }
        }
        if failure.is_none() && self.logical_remaining() == 0 && self.nb > 0 {
            failure = Some(Fail::Tar(Error::UnrefData));
        }
        match failure {
            None => Ok(done),
            Some(e) if done == 0 => Err(e),
            Some(e) => {
                self.err = Some(e);
                Ok(done)
            }
        }
    }

    /// `Close`: flush the last entry and write the two zero blocks that end
    /// an archive. Further writes fail with `ErrWriteAfterClose`; closing
    /// again succeeds.
    pub fn close(&mut self) -> io::Result<()> {
        match &self.err {
            Some(Fail::Tar(Error::WriteAfterClose)) => return Ok(()),
            Some(e) => return Err(e.clone().into_io()),
            None => {}
        }
        let mut r = self.flush_entry();
        for _ in 0..2 {
            if r.is_err() {
                break;
            }
            r = self.w.write_all(&[0u8; BLOCK_SIZE]);
        }
        self.err = Some(Fail::Tar(Error::WriteAfterClose));
        r
    }

    /// `AddFS`: add the files of `fsys` to the archive in lexical order. Only
    /// regular files, directories and symbolic links are supported.
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
                let typ = iofs::FileMode(d.file_type().0);
                let mut link_target = String::new();
                if typ == iofs::FileMode::SYMLINK {
                    link_target = fs::read_link(fsys, name)?;
                } else if !typ.is_regular() && typ != iofs::FileMode::DIR {
                    return Err(io::Error::other("tar: cannot add non-regular file"));
                }
                let mut h = file_info_header(&info, &link_target)?;
                h.name = name.to_string();
                if d.is_dir() {
                    h.name.push('/');
                }
                self.write_header(&h)?;
                if !typ.is_regular() {
                    return Ok(());
                }
                let mut f = fsys.open(name)?;
                io::copy(&mut f, self)?;
                Ok(())
            },
        )
    }
}

impl<W: Write> Write for Writer<W> {
    /// `Write`: write entry data. Writing beyond the declared size fails with
    /// `ErrWriteTooLong` (after the permitted prefix has been accepted).
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if let Some(e) = &self.err {
            return Err(e.clone().into_io());
        }
        let r = if self.sparse.is_some() {
            self.sparse_write(b).map_err(Fail::into_io)
        } else {
            self.reg_write(b)
        };
        match r {
            Err(e) if matches!(Error::from_io(&e), Some(Error::WriteTooLong)) => Err(e),
            other => self.sticky(other),
        }
    }

    /// `Flush`: write the padding of the current entry; fails if the entry's
    /// declared size has not been fully written.
    fn flush(&mut self) -> io::Result<()> {
        self.flush_entry()
    }
}
