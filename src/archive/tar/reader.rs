//! Sequential tar reader following Go's `archive/tar/reader.go`: USTAR, PAX
//! and GNU headers, long names, global headers and sparse files (old GNU
//! maps and PAX 0.0, 0.1 and 1.0), with sparse holes read as zeros.
use super::header::*;
use super::sparse::*;
use super::strconv::*;
use super::Error;
use crate::archive::iofs::{godebug, is_local, time_representable, time_unix, time_zero};
use std::{
    collections::BTreeMap,
    io::{self, Read},
    time::SystemTime,
};

/// An error latched by the reader, cloneable so it can be returned again.
#[derive(Clone, Debug)]
pub(super) enum Fail {
    Eof,
    Tar(Error),
    Io(io::ErrorKind, String),
}

impl Fail {
    pub(super) fn io(e: io::Error) -> Fail {
        match Error::from_io(&e) {
            Some(t) => Fail::Tar(t),
            None => Fail::Io(e.kind(), e.to_string()),
        }
    }
    pub(super) fn into_io(self) -> io::Error {
        match self {
            Fail::Eof => io::ErrorKind::UnexpectedEof.into(),
            Fail::Tar(e) => e.into(),
            Fail::Io(k, m) => io::Error::new(k, m),
        }
    }
}
impl From<Error> for Fail {
    fn from(e: Error) -> Fail {
        Fail::Tar(e)
    }
}
impl From<io::Error> for Fail {
    fn from(e: io::Error) -> Fail {
        Fail::io(e)
    }
}
type Res<T> = Result<T, Fail>;

fn unexpected_eof() -> Fail {
    Fail::Io(io::ErrorKind::UnexpectedEof, "unexpected EOF".into())
}

struct SparseState {
    /// Normalised holes; the final element always remains.
    holes: Vec<SparseEntry>,
    idx: usize,
    pos: i64,
}

/// A sequential reader of tar archives (Go's `tar.Reader`). Call
/// [`Reader::next`] to advance to the next entry, then read its contents with
/// [`Read::read`].
pub struct Reader<R: Read> {
    r: R,
    pad: i64,
    /// Physical bytes of the current entry still unread.
    nb: i64,
    sparse: Option<SparseState>,
    err: Option<Fail>,
    reject_insecure: bool,
}

const MAGIC_GNU: &[u8] = b"ustar ";
const VERSION_GNU: &[u8] = b" \0";
const MAGIC_USTAR: &[u8] = b"ustar\0";
const TRAILER_STAR: &[u8] = b"tar\0";

fn compute_checksum(b: &[u8; BLOCK_SIZE]) -> (i64, i64) {
    let (mut unsigned, mut signed) = (0i64, 0i64);
    for (i, &c) in b.iter().enumerate() {
        let c = if (148..156).contains(&i) { b' ' } else { c };
        unsigned += i64::from(c);
        signed += i64::from(c as i8);
    }
    (unsigned, signed)
}

fn get_format(b: &[u8; BLOCK_SIZE]) -> Format {
    let mut p = Parser::default();
    let value = p.octal(&b[148..156]);
    let (c1, c2) = compute_checksum(b);
    if p.err.is_some() || (value != c1 && value != c2) {
        return FORMAT_UNKNOWN;
    }
    let magic = &b[257..263];
    let version = &b[263..265];
    let trailer = &b[508..512];
    if magic == MAGIC_USTAR && trailer == TRAILER_STAR {
        FORMAT_STAR
    } else if magic == MAGIC_USTAR {
        Format(FORMAT_USTAR.0 | FORMAT_PAX.0)
    } else if magic == MAGIC_GNU && version == VERSION_GNU {
        FORMAT_GNU
    } else {
        FORMAT_V7
    }
}

fn parse_time(p: &mut Parser, secs: i64) -> SystemTime {
    if !time_representable(secs) {
        p.err = Some(Error::Header);
        return time_zero();
    }
    time_unix(secs, 0)
}

impl<R: Read> Reader<R> {
    /// `NewReader`: read tar entries from `r`. The `GODEBUG=tarinsecurepath=0`
    /// setting makes [`Reader::next`] report `ErrInsecurePath`, as in Go.
    pub fn new(r: R) -> Self {
        Self {
            r,
            pad: 0,
            nb: 0,
            sparse: None,
            err: None,
            reject_insecure: godebug("tarinsecurepath").as_deref() == Some("0"),
        }
    }

    /// Choose whether [`Reader::next`] reports `ErrInsecurePath` for names
    /// that are not local (absolute, or containing `..`). The error carries
    /// the header as an [`InsecurePathError`]; reading may continue.
    pub fn set_reject_insecure_paths(&mut self, reject: bool) {
        self.reject_insecure = reject;
    }

    /// Advance to the next entry with byte-string names, which is Go's `Next`.
    /// `Ok(None)` is the end of the archive (`io.EOF`). Errors are sticky.
    pub fn next_raw(&mut self) -> io::Result<Option<RawHeader>> {
        if let Some(e) = &self.err {
            return match e {
                Fail::Eof => Ok(None),
                other => Err(other.clone().into_io()),
            };
        }
        match self.next_inner() {
            Ok(hdr) => {
                self.err = None;
                if self.reject_insecure && !is_local(&String::from_utf8_lossy(&hdr.name)) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        InsecureRawPathError { header: hdr },
                    ));
                }
                Ok(Some(hdr))
            }
            Err(f) => {
                self.err = Some(f.clone());
                match f {
                    Fail::Eof => Ok(None),
                    other => Err(other.into_io()),
                }
            }
        }
    }

    /// [`Reader::next_raw`] with `String` fields. A header whose names or
    /// PAX records are not UTF-8 cannot be held, and is `ErrHeader`.
    #[allow(clippy::should_implement_trait)] // Go's name; not an Iterator
    pub fn next(&mut self) -> io::Result<Option<Header>> {
        let raw = match self.next_raw() {
            Ok(raw) => raw,
            Err(e) => {
                return match e
                    .get_ref()
                    .and_then(|i| i.downcast_ref::<InsecureRawPathError>())
                {
                    Some(insecure) => {
                        let header = insecure.header.clone().into_header().ok_or_else(|| {
                            let error = Fail::Tar(Error::Header);
                            self.err = Some(error.clone());
                            error.into_io()
                        })?;
                        Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            InsecurePathError { header },
                        ))
                    }
                    None => Err(e),
                };
            }
        };
        let Some(raw) = raw else { return Ok(None) };
        match raw.into_header() {
            Some(header) => Ok(Some(header)),
            None => {
                let error = Fail::Tar(Error::Header);
                self.err = Some(error.clone());
                Err(error.into_io())
            }
        }
    }

    fn next_inner(&mut self) -> Res<RawHeader> {
        let mut pax: Option<BTreeMap<Vec<u8>, Vec<u8>>> = None;
        let (mut gnu_long_name, mut gnu_long_link) = (Vec::new(), Vec::new());
        let mut format = Format(FORMAT_USTAR.0 | FORMAT_PAX.0 | FORMAT_GNU.0);
        loop {
            self.discard(self.nb)?;
            self.nb = 0;
            self.sparse = None;
            let pad = self.pad as usize;
            let mut padbuf = [0u8; BLOCK_SIZE];
            if self.try_read_full(&mut padbuf[..pad])? < pad {
                return Err(Fail::Eof);
            }
            self.pad = 0;

            let (mut hdr, raw) = self.read_header()?;
            self.handle_regular_file(&hdr)?;
            format.may_only_be(hdr.format);

            match hdr.typeflag {
                TYPE_X_HEADER | TYPE_X_GLOBAL_HEADER => {
                    format.may_only_be(FORMAT_PAX);
                    let records = self.parse_pax()?;
                    if hdr.typeflag == TYPE_X_GLOBAL_HEADER {
                        let _ = merge_pax(&mut hdr, Some(records));
                        return Ok(RawHeader {
                            name: hdr.name,
                            typeflag: hdr.typeflag,
                            xattrs: hdr.xattrs,
                            pax_records: hdr.pax_records,
                            format,
                            ..RawHeader::default()
                        });
                    }
                    pax = Some(records);
                    continue;
                }
                TYPE_GNU_LONG_NAME | TYPE_GNU_LONG_LINK => {
                    format.may_only_be(FORMAT_GNU);
                    let real = self.read_special_file()?;
                    let s = Parser::default().string(&real);
                    if hdr.typeflag == TYPE_GNU_LONG_NAME {
                        gnu_long_name = s;
                    } else {
                        gnu_long_link = s;
                    }
                    continue;
                }
                _ => {
                    merge_pax(&mut hdr, pax.take())?;
                    if !gnu_long_name.is_empty() {
                        hdr.name = gnu_long_name;
                    }
                    if !gnu_long_link.is_empty() {
                        hdr.linkname = gnu_long_link;
                    }
                    if hdr.typeflag == TYPE_REG_A {
                        hdr.typeflag = if hdr.name.ends_with(b"/") {
                            TYPE_DIR
                        } else {
                            TYPE_REG
                        };
                    }
                    self.handle_regular_file(&hdr)?;
                    self.handle_sparse_file(&mut hdr, raw)?;
                    if format.has(FORMAT_USTAR) && format.has(FORMAT_PAX) {
                        format.may_only_be(FORMAT_USTAR);
                    }
                    hdr.format = format;
                    return Ok(hdr);
                }
            }
        }
    }

    fn handle_regular_file(&mut self, hdr: &RawHeader) -> Res<()> {
        let mut nb = hdr.size;
        if is_header_only_type(hdr.typeflag) {
            nb = 0;
        }
        if nb < 0 {
            return Err(Error::Header.into());
        }
        self.pad = block_padding(nb);
        self.nb = nb;
        self.sparse = None;
        Ok(())
    }

    fn handle_sparse_file(&mut self, hdr: &mut RawHeader, raw: [u8; BLOCK_SIZE]) -> Res<()> {
        let spd = if hdr.typeflag == TYPE_GNU_SPARSE {
            Some(self.read_old_gnu_sparse_map(hdr, raw)?)
        } else {
            self.read_gnu_sparse_pax_headers(hdr)?
        };
        if let Some(spd) = spd {
            if is_header_only_type(hdr.typeflag) || !validate_sparse_entries(&spd, hdr.size) {
                return Err(Error::Header.into());
            }
            self.sparse = Some(SparseState {
                holes: invert_sparse_entries(&spd, hdr.size),
                idx: 0,
                pos: 0,
            });
        }
        Ok(())
    }

    fn read_gnu_sparse_pax_headers(
        &mut self,
        hdr: &mut RawHeader,
    ) -> Res<Option<Vec<SparseEntry>>> {
        let get =
            |h: &RawHeader, k: &str| h.pax_records.get(k.as_bytes()).cloned().unwrap_or_default();
        let (major, minor) = (
            get(hdr, PAX_GNU_SPARSE_MAJOR),
            get(hdr, PAX_GNU_SPARSE_MINOR),
        );
        let is1x0 = if major == b"0" && (minor == b"0" || minor == b"1") {
            false
        } else if major == b"1" && minor == b"0" {
            true
        } else if !major.is_empty() || !minor.is_empty() {
            return Ok(None); // unknown GNU sparse PAX version
        } else if !get(hdr, PAX_GNU_SPARSE_MAP).is_empty() {
            false // 0.0 and 0.1 had no explicit version records
        } else {
            return Ok(None);
        };
        hdr.format.may_only_be(FORMAT_PAX);

        let name = get(hdr, PAX_GNU_SPARSE_NAME);
        if !name.is_empty() {
            hdr.name = name;
        }
        let mut size = get(hdr, PAX_GNU_SPARSE_SIZE);
        if size.is_empty() {
            size = get(hdr, PAX_GNU_SPARSE_REAL_SIZE);
        }
        if !size.is_empty() {
            hdr.size = parse_i64(&size)?;
        }
        if is1x0 {
            return Ok(Some(self.read_gnu_sparse_map_1x0()?));
        }
        Ok(Some(read_gnu_sparse_map_0x1(&hdr.pax_records)?))
    }

    fn read_header(&mut self) -> Res<(RawHeader, [u8; BLOCK_SIZE])> {
        let mut blk = [0u8; BLOCK_SIZE];
        let n = self.try_read_full(&mut blk)?;
        if n == 0 {
            return Err(Fail::Eof);
        }
        if n < BLOCK_SIZE {
            return Err(unexpected_eof());
        }
        if blk.iter().all(|&c| c == 0) {
            let n = self.try_read_full(&mut blk)?;
            if n == 0 {
                return Err(Fail::Eof);
            }
            if n < BLOCK_SIZE {
                return Err(unexpected_eof());
            }
            if blk.iter().all(|&c| c == 0) {
                return Err(Fail::Eof);
            }
            return Err(Error::Header.into());
        }
        let format = get_format(&blk);
        if format == FORMAT_UNKNOWN {
            return Err(Error::Header.into());
        }

        let mut p = Parser::default();
        let name = p.string(&blk[0..100]);
        let linkname = p.string(&blk[157..257]);
        let mut hdr = RawHeader {
            typeflag: blk[156],
            name,
            linkname,
            size: p.numeric(&blk[124..136]),
            mode: p.numeric(&blk[100..108]),
            uid: p.numeric(&blk[108..116]),
            gid: p.numeric(&blk[116..124]),
            ..RawHeader::default()
        };
        let secs = p.numeric(&blk[136..148]);
        hdr.mod_time = parse_time(&mut p, secs);

        if format.0 > FORMAT_V7.0 {
            hdr.uname = p.string(&blk[265..297]);
            hdr.gname = p.string(&blk[297..329]);
            hdr.devmajor = p.numeric(&blk[329..337]);
            hdr.devminor = p.numeric(&blk[337..345]);

            let mut prefix = Vec::new();
            if format.has(Format(FORMAT_USTAR.0 | FORMAT_PAX.0)) {
                hdr.format = format;
                prefix = p.string(&blk[345..500]);
                if blk.iter().any(|&c| c >= 0x80) {
                    hdr.format = FORMAT_UNKNOWN;
                }
                let nul = |r: std::ops::Range<usize>| blk[r.end - 1] == 0;
                if !(nul(124..136)
                    && nul(100..108)
                    && nul(108..116)
                    && nul(116..124)
                    && nul(136..148)
                    && nul(329..337)
                    && nul(337..345))
                {
                    hdr.format = FORMAT_UNKNOWN;
                }
            } else if format.has(FORMAT_STAR) {
                prefix = p.string(&blk[345..476]);
                let a = p.numeric(&blk[476..488]);
                hdr.access_time = parse_time(&mut p, a);
                let c = p.numeric(&blk[488..500]);
                hdr.change_time = parse_time(&mut p, c);
            } else if format.has(FORMAT_GNU) {
                hdr.format = format;
                let mut p2 = Parser::default();
                if blk[345] != 0 {
                    let a = p2.numeric(&blk[345..357]);
                    hdr.access_time = parse_time(&mut p2, a);
                }
                if blk[357] != 0 {
                    let c = p2.numeric(&blk[357..369]);
                    hdr.change_time = parse_time(&mut p2, c);
                }
                if p2.err.is_some() {
                    hdr.access_time = time_zero();
                    hdr.change_time = time_zero();
                    let mut p3 = Parser::default();
                    let s = p3.string(&blk[345..500]);
                    if s.iter().all(|&c| c < 0x80 && c != 0) {
                        prefix = s;
                    }
                    hdr.format = FORMAT_UNKNOWN;
                }
            }
            if !prefix.is_empty() {
                prefix.push(b'/');
                prefix.extend_from_slice(&hdr.name);
                hdr.name = prefix;
            }
        }
        match p.err {
            Some(e) => Err(e.into()),
            None => Ok((hdr, blk)),
        }
    }

    fn read_old_gnu_sparse_map(
        &mut self,
        hdr: &mut RawHeader,
        mut blk: [u8; BLOCK_SIZE],
    ) -> Res<Vec<SparseEntry>> {
        if get_format(&blk) != FORMAT_GNU {
            return Err(Error::Header.into());
        }
        hdr.format.may_only_be(FORMAT_GNU);

        let mut p = Parser::default();
        hdr.size = p.numeric(&blk[483..495]);
        if let Some(e) = p.err.take() {
            return Err(e.into());
        }
        let mut spd = Vec::new();
        // The first array is 4 entries in the header block (offset 386); extension
        // blocks hold 21 entries.
        let mut base = 386usize;
        let mut max_entries = 4usize;
        let mut total_size = 24 * 4 + 1;
        while total_size < MAX_SPECIAL_FILE_SIZE {
            for i in 0..max_entries {
                let e = base + i * 24;
                if blk[e] == 0 {
                    break;
                }
                let offset = p.numeric(&blk[e..e + 12]);
                let length = p.numeric(&blk[e + 12..e + 24]);
                if let Some(err) = p.err.take() {
                    return Err(err.into());
                }
                append_sparse_entry(&mut spd, SparseEntry { offset, length })?;
            }
            if blk[base + max_entries * 24] > 0 {
                if self.try_read_full(&mut blk)? < BLOCK_SIZE {
                    return Err(unexpected_eof());
                }
                base = 0;
                max_entries = BLOCK_SIZE / 24;
                total_size += BLOCK_SIZE;
                continue;
            }
            return Ok(spd);
        }
        Err(Error::SparseTooLong.into())
    }

    fn read_gnu_sparse_map_1x0(&mut self) -> Res<Vec<SparseEntry>> {
        let mut cnt_newline: i64 = 0;
        let mut buf: Vec<u8> = Vec::new();
        let mut pos = 0usize;
        let mut total_size = 0usize;

        fn feed(
            this: &mut dyn FnMut(&mut [u8]) -> Res<usize>,
            cnt: &mut i64,
            buf: &mut Vec<u8>,
            total: &mut usize,
            n: i64,
        ) -> Res<()> {
            while *cnt < n {
                *total += BLOCK_SIZE;
                if *total > MAX_SPECIAL_FILE_SIZE {
                    return Err(Error::SparseTooLong.into());
                }
                let mut blk = [0u8; BLOCK_SIZE];
                if this(&mut blk)? < BLOCK_SIZE {
                    return Err(unexpected_eof());
                }
                buf.extend_from_slice(&blk);
                *cnt += blk.iter().filter(|&&c| c == b'\n').count() as i64;
            }
            Ok(())
        }
        let mut read = |b: &mut [u8]| -> Res<usize> { self.try_read_full_reg(b) };
        let next_token = |buf: &Vec<u8>, pos: &mut usize, cnt: &mut i64| -> String {
            *cnt -= 1;
            let rest = &buf[*pos..];
            let end = rest.iter().position(|&c| c == b'\n');
            let tok = match end {
                Some(i) => {
                    *pos += i + 1;
                    &rest[..i]
                }
                None => {
                    *pos = buf.len();
                    rest
                }
            };
            String::from_utf8_lossy(tok).into_owned()
        };

        feed(&mut read, &mut cnt_newline, &mut buf, &mut total_size, 1)?;
        let n: i64 = next_token(&buf, &mut pos, &mut cnt_newline)
            .parse()
            .map_err(|_| Error::Header)?;
        if n < 0 || n.checked_mul(2).is_none() {
            return Err(Error::Header.into());
        }
        feed(
            &mut read,
            &mut cnt_newline,
            &mut buf,
            &mut total_size,
            2 * n,
        )?;
        let mut spd = Vec::new();
        for _ in 0..n {
            let offset = next_token(&buf, &mut pos, &mut cnt_newline).parse::<i64>();
            let length = next_token(&buf, &mut pos, &mut cnt_newline).parse::<i64>();
            let (Ok(offset), Ok(length)) = (offset, length) else {
                return Err(Error::Header.into());
            };
            append_sparse_entry(&mut spd, SparseEntry { offset, length })?;
        }
        Ok(spd)
    }

    /// Parse a PAX extended header; keys and values are arbitrary bytes.
    fn parse_pax(&mut self) -> Res<BTreeMap<Vec<u8>, Vec<u8>>> {
        let buf = self.read_special_file()?;
        let mut s: &[u8] = &buf;
        let mut sparse_map: Vec<Vec<u8>> = Vec::new();
        let mut records = BTreeMap::new();
        while !s.is_empty() {
            let (key, value, rest) = parse_pax_record(s).map_err(|_| Error::Header)?;
            s = rest;
            let (key, value) = (key.to_vec(), value.to_vec());
            if key == PAX_GNU_SPARSE_OFFSET.as_bytes() || key == PAX_GNU_SPARSE_NUM_BYTES.as_bytes()
            {
                if (sparse_map.len().is_multiple_of(2) && key != PAX_GNU_SPARSE_OFFSET.as_bytes())
                    || (sparse_map.len() % 2 == 1 && key != PAX_GNU_SPARSE_NUM_BYTES.as_bytes())
                    || value.contains(&b',')
                {
                    return Err(Error::Header.into());
                }
                sparse_map.push(value);
            } else {
                records.insert(key, value);
            }
        }
        if !sparse_map.is_empty() {
            records.insert(
                PAX_GNU_SPARSE_MAP.as_bytes().to_vec(),
                sparse_map.join(&b','),
            );
        }
        Ok(records)
    }

    /// Read the whole current entry (a PAX or GNU long-name record) with the
    /// special-file size limit.
    fn read_special_file(&mut self) -> Res<Vec<u8>> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        while buf.len() <= MAX_SPECIAL_FILE_SIZE {
            let want = chunk.len().min(MAX_SPECIAL_FILE_SIZE + 1 - buf.len());
            let n = self.reg_read(&mut chunk[..want])?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        if buf.len() > MAX_SPECIAL_FILE_SIZE {
            return Err(Error::FieldTooLong.into());
        }
        Ok(buf)
    }

    /// Fill `b` from the archive; returns fewer bytes only at end of input.
    fn try_read_full(&mut self, b: &mut [u8]) -> Res<usize> {
        let mut n = 0;
        while n < b.len() {
            match self.r.read(&mut b[n..]) {
                Ok(0) => break,
                Ok(k) => n += k,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(n)
    }

    /// Fill `b` from the current entry's data. Returns the bytes read, which
    /// is fewer than requested only when the entry's data ends or fails.
    fn read_full_reg(&mut self, b: &mut [u8]) -> (usize, Option<Fail>) {
        let mut n = 0;
        while n < b.len() {
            match self.reg_read(&mut b[n..]) {
                Ok(0) => break,
                Ok(k) => n += k,
                Err(e) => return (n, Some(Fail::io(e))),
            }
        }
        (n, None)
    }

    fn try_read_full_reg(&mut self, b: &mut [u8]) -> Res<usize> {
        match self.read_full_reg(b) {
            (n, None) => Ok(n),
            (_, Some(e)) => Err(e),
        }
    }

    fn discard(&mut self, n: i64) -> Res<()> {
        if n <= 0 {
            return Ok(());
        }
        let copied = io::copy(&mut (&mut self.r).take(n as u64), &mut io::sink())?;
        if (copied as i64) < n {
            return Err(unexpected_eof());
        }
        Ok(())
    }

    /// Read from the current entry's physical data (`regFileReader.Read`).
    fn reg_read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let len = (b.len() as i64).min(self.nb) as usize;
        if len == 0 {
            return Ok(0);
        }
        loop {
            match self.r.read(&mut b[..len]) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => {
                    self.nb -= n as i64;
                    return Ok(n);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    fn logical_remaining(&self) -> i64 {
        match &self.sparse {
            None => self.nb,
            Some(s) => s.holes.last().map_or(0, |h| h.end_offset()) - s.pos,
        }
    }

    fn sparse_read(&mut self, b: &mut [u8]) -> Res<usize> {
        let remaining = self.logical_remaining();
        let finished = b.len() as i64 >= remaining;
        let b = if finished {
            &mut b[..remaining as usize]
        } else {
            b
        };
        let total = b.len();
        let mut done = 0usize;
        let mut failure: Option<Fail> = None;
        while done < total && failure.is_none() {
            let s = self.sparse.as_ref().unwrap();
            let (hole_start, hole_end) = (s.holes[s.idx].offset, s.holes[s.idx].end_offset());
            let pos = s.pos;
            let left = (total - done) as i64;
            let nf;
            if pos < hole_start {
                let want = left.min(hole_start - pos) as usize;
                let (n, err) = self.read_full_reg(&mut b[done..done + want]);
                nf = n;
                if err.is_some() {
                    failure = err;
                } else if n < want {
                    failure = Some(Fail::Eof);
                }
            } else {
                let want = left.min(hole_end - pos) as usize;
                b[done..done + want].fill(0);
                nf = want;
            }
            done += nf;
            let s = self.sparse.as_mut().unwrap();
            s.pos += nf as i64;
            if s.pos >= hole_end && s.idx + 1 < s.holes.len() {
                s.idx += 1;
            }
        }
        let outcome = match failure {
            Some(Fail::Eof) => Some(Fail::Tar(Error::MissData)),
            Some(e) => Some(e),
            None if self.logical_remaining() == 0 && self.nb > 0 => {
                Some(Fail::Tar(Error::UnrefData))
            }
            None => None,
        };
        match outcome {
            None => Ok(done),
            Some(e) if done == 0 => Err(e),
            Some(e) => {
                self.err = Some(e);
                Ok(done)
            }
        }
    }
}

fn append_sparse_entry(spd: &mut Vec<SparseEntry>, ent: SparseEntry) -> Res<()> {
    if spd.len() >= MAX_SPARSE_FILE_ENTRIES {
        return Err(Error::SparseTooLong.into());
    }
    spd.push(ent);
    Ok(())
}

/// Go's `strconv.ParseInt(s, 10, 64)` on record bytes.
fn parse_i64(v: &[u8]) -> Result<i64, Error> {
    std::str::from_utf8(v)
        .ok()
        .and_then(|t| t.parse::<i64>().ok())
        .ok_or(Error::Header)
}

fn read_gnu_sparse_map_0x1(pax: &BTreeMap<Vec<u8>, Vec<u8>>) -> Res<Vec<SparseEntry>> {
    let get = |k: &str| pax.get(k.as_bytes()).map_or(&[][..], Vec::as_slice);
    let n = parse_i64(get(PAX_GNU_SPARSE_NUM_BLOCKS))?;
    if n < 0 || n.checked_mul(2).is_none() {
        return Err(Error::Header.into());
    }
    let map = get(PAX_GNU_SPARSE_MAP);
    let fields: Vec<&[u8]> = if map.is_empty() {
        Vec::new()
    } else {
        map.split(|&c| c == b',').collect()
    };
    if fields.len() as i64 != 2 * n {
        return Err(Error::Header.into());
    }
    let mut spd = Vec::new();
    for pair in fields.chunks(2) {
        let (Ok(offset), Ok(length)) = (parse_i64(pair[0]), parse_i64(pair[1])) else {
            return Err(Error::Header.into());
        };
        append_sparse_entry(&mut spd, SparseEntry { offset, length })?;
    }
    Ok(spd)
}

fn merge_pax(hdr: &mut RawHeader, pax: Option<BTreeMap<Vec<u8>, Vec<u8>>>) -> Result<(), Error> {
    let records = pax.unwrap_or_default();
    for (k, v) in &records {
        if v.is_empty() {
            continue;
        }
        let time = |v: &[u8]| parse_pax_time(std::str::from_utf8(v).map_err(|_| Error::Header)?);
        match k.as_slice() {
            k if k == PAX_PATH.as_bytes() => hdr.name = v.clone(),
            k if k == PAX_LINKPATH.as_bytes() => hdr.linkname = v.clone(),
            k if k == PAX_UNAME.as_bytes() => hdr.uname = v.clone(),
            k if k == PAX_GNAME.as_bytes() => hdr.gname = v.clone(),
            k if k == PAX_UID.as_bytes() => hdr.uid = parse_i64(v)?,
            k if k == PAX_GID.as_bytes() => hdr.gid = parse_i64(v)?,
            k if k == PAX_ATIME.as_bytes() => hdr.access_time = time(v)?,
            k if k == PAX_MTIME.as_bytes() => hdr.mod_time = time(v)?,
            k if k == PAX_CTIME.as_bytes() => hdr.change_time = time(v)?,
            k if k == PAX_SIZE.as_bytes() => hdr.size = parse_i64(v)?,
            k => {
                if let Some(attr) = k.strip_prefix(PAX_SCHILY_XATTR.as_bytes()) {
                    hdr.xattrs.insert(attr.to_vec(), v.clone());
                }
            }
        }
    }
    hdr.pax_records = records;
    Ok(())
}

impl<R: Read> Read for Reader<R> {
    /// Read the current entry's data. Returns `Ok(0)` at its end. Sparse
    /// holes read as zeros.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &self.err {
            Some(Fail::Eof) => return Ok(0),
            Some(e) => return Err(e.clone().into_io()),
            None => {}
        }
        let result = if self.sparse.is_some() {
            self.sparse_read(buf)
        } else {
            self.reg_read(buf).map_err(Fail::io)
        };
        match result {
            Ok(n) => Ok(n),
            Err(e) => {
                self.err = Some(e.clone());
                Err(e.into_io())
            }
        }
    }
}
