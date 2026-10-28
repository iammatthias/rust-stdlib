//! `Header`, `Format`, the error values and `FileInfoHeader` of Go's
//! `archive/tar` (`common.go`, `format.go`).
use super::strconv::{
    fits_in_base256, fits_in_octal, format_pax_time, has_nul, is_ascii, valid_pax_record,
};
use crate::archive::iofs::{time_is_zero, time_parts, time_zero, FileInfo, FileMode};
use std::{any::Any, collections::BTreeMap, fmt, io, sync::RwLock, time::SystemTime};

pub(super) const BLOCK_SIZE: usize = 512;
pub(super) const NAME_SIZE: usize = 100;
pub(super) const PREFIX_SIZE: usize = 155;
pub(super) const MAX_SPECIAL_FILE_SIZE: usize = 1 << 20;
pub(super) const MAX_SPARSE_FILE_ENTRIES: usize = 1 << 20;

/// Tar's error values (`ErrHeader`, `ErrWriteTooLong`, ...), plus the
/// unexported errors Go's package can return. Returned inside `io::Error`;
/// test with [`Error::matches`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// `ErrHeader`: invalid tar header.
    Header,
    /// `ErrWriteTooLong`: write beyond the size declared in the header.
    WriteTooLong,
    /// `ErrFieldTooLong`: header field too long.
    FieldTooLong,
    /// `ErrWriteAfterClose`: write after close.
    WriteAfterClose,
    /// `ErrInsecurePath`: insecure file path.
    InsecurePath,
    /// Sparse file references non-existent data.
    MissData,
    /// Sparse file contains unreferenced data.
    UnrefData,
    /// Write of a non-NUL byte in a sparse hole.
    WriteHole,
    /// Sparse map too long.
    SparseTooLong,
    /// The header cannot be encoded in any allowed format; carries the reasons.
    CannotEncode(String),
}

pub const ERR_HEADER: Error = Error::Header;
pub const ERR_WRITE_TOO_LONG: Error = Error::WriteTooLong;
pub const ERR_FIELD_TOO_LONG: Error = Error::FieldTooLong;
pub const ERR_WRITE_AFTER_CLOSE: Error = Error::WriteAfterClose;
pub const ERR_INSECURE_PATH: Error = Error::InsecurePath;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Header => f.write_str("archive/tar: invalid tar header"),
            Error::WriteTooLong => f.write_str("archive/tar: write too long"),
            Error::FieldTooLong => f.write_str("archive/tar: header field too long"),
            Error::WriteAfterClose => f.write_str("archive/tar: write after close"),
            Error::InsecurePath => f.write_str("archive/tar: insecure file path"),
            Error::MissData => f.write_str("archive/tar: sparse file references non-existent data"),
            Error::UnrefData => f.write_str("archive/tar: sparse file contains unreferenced data"),
            Error::WriteHole => f.write_str("archive/tar: write non-NUL byte in sparse hole"),
            Error::SparseTooLong => f.write_str("archive/tar: sparse map too long"),
            Error::CannotEncode(why) if why.is_empty() => {
                f.write_str("archive/tar: cannot encode header")
            }
            Error::CannotEncode(why) => write!(f, "archive/tar: cannot encode header: {why}"),
        }
    }
}
impl std::error::Error for Error {}

impl Error {
    fn kind(&self) -> io::ErrorKind {
        match self {
            Error::Header
            | Error::MissData
            | Error::UnrefData
            | Error::SparseTooLong
            | Error::InsecurePath => io::ErrorKind::InvalidData,
            Error::WriteAfterClose => io::ErrorKind::BrokenPipe,
            _ => io::ErrorKind::InvalidInput,
        }
    }
    /// The tar error carried by `err`, if any (Go's `errors.Is` with a sentinel).
    pub fn from_io(err: &io::Error) -> Option<Error> {
        let inner = err.get_ref()?;
        if let Some(e) = inner.downcast_ref::<Error>() {
            return Some(e.clone());
        }
        if inner.is::<InsecurePathError>() || inner.is::<InsecureRawPathError>() {
            return Some(Error::InsecurePath);
        }
        None
    }
    /// Report whether `err` is this error value.
    pub fn matches(&self, err: &io::Error) -> bool {
        Error::from_io(err).as_ref() == Some(self)
    }
}
impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        io::Error::new(e.kind(), e)
    }
}

/// `ErrInsecurePath` returned together with its header: Go's `Next` returns
/// `(hdr, ErrInsecurePath)` and documents that callers may use the header.
#[derive(Debug)]
pub struct InsecurePathError {
    pub header: Header,
}
impl fmt::Display for InsecurePathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Error::InsecurePath, f)
    }
}
impl std::error::Error for InsecurePathError {}

/// [`InsecurePathError`] for [`Reader::next_raw`](super::Reader::next_raw),
/// which carries the byte-string header.
#[derive(Debug)]
pub struct InsecureRawPathError {
    pub header: RawHeader,
}
impl fmt::Display for InsecureRawPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Error::InsecurePath, f)
    }
}
impl std::error::Error for InsecureRawPathError {}

pub const TYPE_REG: u8 = b'0';
pub const TYPE_REG_A: u8 = 0;
pub const TYPE_LINK: u8 = b'1';
pub const TYPE_SYMLINK: u8 = b'2';
pub const TYPE_CHAR: u8 = b'3';
pub const TYPE_BLOCK: u8 = b'4';
pub const TYPE_DIR: u8 = b'5';
pub const TYPE_FIFO: u8 = b'6';
pub const TYPE_CONT: u8 = b'7';
pub const TYPE_X_HEADER: u8 = b'x';
pub const TYPE_X_GLOBAL_HEADER: u8 = b'g';
pub const TYPE_GNU_SPARSE: u8 = b'S';
pub const TYPE_GNU_LONG_NAME: u8 = b'L';
pub const TYPE_GNU_LONG_LINK: u8 = b'K';

pub(super) const PAX_PATH: &str = "path";
pub(super) const PAX_LINKPATH: &str = "linkpath";
pub(super) const PAX_SIZE: &str = "size";
pub(super) const PAX_UID: &str = "uid";
pub(super) const PAX_GID: &str = "gid";
pub(super) const PAX_UNAME: &str = "uname";
pub(super) const PAX_GNAME: &str = "gname";
pub(super) const PAX_MTIME: &str = "mtime";
pub(super) const PAX_ATIME: &str = "atime";
pub(super) const PAX_CTIME: &str = "ctime";
pub(super) const PAX_SCHILY_XATTR: &str = "SCHILY.xattr.";
pub(super) const PAX_GNU_SPARSE: &str = "GNU.sparse.";
pub(super) const PAX_GNU_SPARSE_NUM_BLOCKS: &str = "GNU.sparse.numblocks";
pub(super) const PAX_GNU_SPARSE_OFFSET: &str = "GNU.sparse.offset";
pub(super) const PAX_GNU_SPARSE_NUM_BYTES: &str = "GNU.sparse.numbytes";
pub(super) const PAX_GNU_SPARSE_MAP: &str = "GNU.sparse.map";
pub(super) const PAX_GNU_SPARSE_NAME: &str = "GNU.sparse.name";
pub(super) const PAX_GNU_SPARSE_MAJOR: &str = "GNU.sparse.major";
pub(super) const PAX_GNU_SPARSE_MINOR: &str = "GNU.sparse.minor";
pub(super) const PAX_GNU_SPARSE_SIZE: &str = "GNU.sparse.size";
pub(super) const PAX_GNU_SPARSE_REAL_SIZE: &str = "GNU.sparse.realsize";

pub(super) fn is_basic_key(k: &str) -> bool {
    matches!(
        k,
        "path"
            | "linkpath"
            | "size"
            | "uid"
            | "gid"
            | "uname"
            | "gname"
            | "mtime"
            | "atime"
            | "ctime"
    )
}

/// A tar archive format (or, as a set of bits, the formats a header allows).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Format(pub i32);

pub const FORMAT_UNKNOWN: Format = Format(0);
pub(super) const FORMAT_V7: Format = Format(1);
pub const FORMAT_USTAR: Format = Format(2);
pub const FORMAT_PAX: Format = Format(4);
pub const FORMAT_GNU: Format = Format(8);
pub(super) const FORMAT_STAR: Format = Format(16);
const FORMAT_MAX: i32 = 32;

impl Format {
    pub(super) fn has(self, f2: Format) -> bool {
        self.0 & f2.0 != 0
    }
    pub(super) fn may_be(&mut self, f2: Format) {
        self.0 |= f2.0;
    }
    pub(super) fn may_only_be(&mut self, f2: Format) {
        self.0 &= f2.0;
    }
    pub(super) fn must_not_be(&mut self, f2: Format) {
        self.0 &= !f2.0;
    }
}
impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ss = Vec::new();
        let mut f2 = 1;
        while f2 < FORMAT_MAX {
            if self.has(Format(f2)) {
                ss.push(match Format(f2) {
                    FORMAT_V7 => "V7",
                    FORMAT_USTAR => "USTAR",
                    FORMAT_PAX => "PAX",
                    FORMAT_GNU => "GNU",
                    _ => "STAR",
                });
            }
            f2 <<= 1;
        }
        match ss.len() {
            0 => f.write_str("<unknown>"),
            1 => f.write_str(ss[0]),
            _ => write!(f, "({})", ss.join(" | ")),
        }
    }
}

/// A single header in a tar archive. Maps are empty rather than nil.
#[derive(Clone, Debug, PartialEq)]
pub struct Header {
    pub typeflag: u8,
    pub name: String,
    pub linkname: String,
    pub size: i64,
    pub mode: i64,
    pub uid: i64,
    pub gid: i64,
    pub uname: String,
    pub gname: String,
    pub mod_time: SystemTime,
    pub access_time: SystemTime,
    pub change_time: SystemTime,
    pub devmajor: i64,
    pub devminor: i64,
    /// Deprecated in Go in favour of `pax_records` (`SCHILY.xattr.` prefix).
    pub xattrs: BTreeMap<String, String>,
    pub pax_records: BTreeMap<String, String>,
    pub format: Format,
}

/// A [`Header`] whose strings are bytes, which is what Go's header strings
/// hold: names and PAX records need not be UTF-8. [`Reader::next_raw`](super::Reader::next_raw)
/// returns it; [`RawHeader::into_header`] gives the `String` form.
#[derive(Clone, Debug, PartialEq)]
pub struct RawHeader {
    pub typeflag: u8,
    pub name: Vec<u8>,
    pub linkname: Vec<u8>,
    pub size: i64,
    pub mode: i64,
    pub uid: i64,
    pub gid: i64,
    pub uname: Vec<u8>,
    pub gname: Vec<u8>,
    pub mod_time: SystemTime,
    pub access_time: SystemTime,
    pub change_time: SystemTime,
    pub devmajor: i64,
    pub devminor: i64,
    pub xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
    pub pax_records: BTreeMap<Vec<u8>, Vec<u8>>,
    pub format: Format,
}

impl Default for RawHeader {
    fn default() -> Self {
        Header::default().into()
    }
}

impl From<Header> for RawHeader {
    fn from(h: Header) -> Self {
        let bytes = |m: BTreeMap<String, String>| {
            m.into_iter()
                .map(|(k, v)| (k.into_bytes(), v.into_bytes()))
                .collect()
        };
        RawHeader {
            typeflag: h.typeflag,
            name: h.name.into_bytes(),
            linkname: h.linkname.into_bytes(),
            size: h.size,
            mode: h.mode,
            uid: h.uid,
            gid: h.gid,
            uname: h.uname.into_bytes(),
            gname: h.gname.into_bytes(),
            mod_time: h.mod_time,
            access_time: h.access_time,
            change_time: h.change_time,
            devmajor: h.devmajor,
            devminor: h.devminor,
            xattrs: bytes(h.xattrs),
            pax_records: bytes(h.pax_records),
            format: h.format,
        }
    }
}

impl RawHeader {
    /// The `String` form, or `None` when a name, user, group or PAX record is
    /// not valid UTF-8.
    pub fn into_header(self) -> Option<Header> {
        let strings = |m: BTreeMap<Vec<u8>, Vec<u8>>| -> Option<BTreeMap<String, String>> {
            m.into_iter()
                .map(|(k, v)| Some((String::from_utf8(k).ok()?, String::from_utf8(v).ok()?)))
                .collect()
        };
        Some(Header {
            typeflag: self.typeflag,
            name: String::from_utf8(self.name).ok()?,
            linkname: String::from_utf8(self.linkname).ok()?,
            size: self.size,
            mode: self.mode,
            uid: self.uid,
            gid: self.gid,
            uname: String::from_utf8(self.uname).ok()?,
            gname: String::from_utf8(self.gname).ok()?,
            mod_time: self.mod_time,
            access_time: self.access_time,
            change_time: self.change_time,
            devmajor: self.devmajor,
            devminor: self.devminor,
            xattrs: strings(self.xattrs)?,
            pax_records: strings(self.pax_records)?,
            format: self.format,
        })
    }
}

impl Default for Header {
    fn default() -> Self {
        Self {
            typeflag: 0,
            name: String::new(),
            linkname: String::new(),
            size: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            uname: String::new(),
            gname: String::new(),
            mod_time: time_zero(),
            access_time: time_zero(),
            change_time: time_zero(),
            devmajor: 0,
            devminor: 0,
            xattrs: BTreeMap::new(),
            pax_records: BTreeMap::new(),
            format: FORMAT_UNKNOWN,
        }
    }
}

pub(super) fn is_header_only_type(flag: u8) -> bool {
    matches!(
        flag,
        TYPE_LINK | TYPE_SYMLINK | TYPE_CHAR | TYPE_BLOCK | TYPE_DIR | TYPE_FIFO
    )
}

/// Split a name into the USTAR prefix and suffix fields, if possible.
pub(super) fn split_ustar_path(name: &str) -> Option<(String, String)> {
    let mut length = name.len();
    if length <= NAME_SIZE || !is_ascii(name) {
        return None;
    } else if length > PREFIX_SIZE + 1 {
        length = PREFIX_SIZE + 1;
    } else if name.as_bytes()[length - 1] == b'/' {
        length -= 1;
    }
    let i = name[..length].rfind('/')?;
    let nlen = name.len() - i - 1;
    let plen = i;
    if i == 0 || nlen > NAME_SIZE || nlen == 0 || plen > PREFIX_SIZE {
        return None;
    }
    Some((name[..i].to_string(), name[i + 1..].to_string()))
}

struct Allowed<'a> {
    h: &'a Header,
    format: Format,
    pax: BTreeMap<String, String>,
    why_no_ustar: String,
    why_no_pax: String,
    why_no_gnu: String,
    prefer_pax: bool,
}

impl Allowed<'_> {
    fn string(&mut self, s: &str, size: usize, name: &str, pax_key: &str) {
        let too_long = s.len() > size;
        let allow_long_gnu = pax_key == PAX_PATH || pax_key == PAX_LINKPATH;
        if has_nul(s) || (too_long && !allow_long_gnu) {
            self.why_no_gnu = format!("GNU cannot encode {name}={s:?}");
            self.format.must_not_be(FORMAT_GNU);
        }
        if !is_ascii(s) || too_long {
            let can_split_ustar = pax_key == PAX_PATH;
            if !can_split_ustar || split_ustar_path(s).is_none() {
                self.why_no_ustar = format!("USTAR cannot encode {name}={s:?}");
                self.format.must_not_be(FORMAT_USTAR);
            }
            if pax_key.is_empty() {
                self.why_no_pax = format!("PAX cannot encode {name}={s:?}");
                self.format.must_not_be(FORMAT_PAX);
            } else {
                self.pax.insert(pax_key.to_string(), s.to_string());
            }
        }
        if let Some(v) = self.h.pax_records.get(pax_key) {
            if v == s {
                self.pax.insert(pax_key.to_string(), v.clone());
            }
        }
    }

    fn numeric(&mut self, n: i64, size: usize, name: &str, pax_key: &str) {
        if !fits_in_base256(size, n) {
            self.why_no_gnu = format!("GNU cannot encode {name}={n}");
            self.format.must_not_be(FORMAT_GNU);
        }
        if !fits_in_octal(size, n) {
            self.why_no_ustar = format!("USTAR cannot encode {name}={n}");
            self.format.must_not_be(FORMAT_USTAR);
            if pax_key.is_empty() {
                self.why_no_pax = format!("PAX cannot encode {name}={n}");
                self.format.must_not_be(FORMAT_PAX);
            } else {
                self.pax.insert(pax_key.to_string(), n.to_string());
            }
        }
        if let Some(v) = self.h.pax_records.get(pax_key) {
            if *v == n.to_string() {
                self.pax.insert(pax_key.to_string(), v.clone());
            }
        }
    }

    fn time(&mut self, ts: &SystemTime, size: usize, name: &str, pax_key: &str) {
        if time_is_zero(ts) {
            return;
        }
        let (secs, nanos) = time_parts(ts);
        if !fits_in_base256(size, secs) {
            self.why_no_gnu = format!("GNU cannot encode {name}={secs}");
            self.format.must_not_be(FORMAT_GNU);
        }
        let is_mtime = pax_key == PAX_MTIME;
        let fits_octal = fits_in_octal(size, secs);
        if (is_mtime && !fits_octal) || !is_mtime {
            self.why_no_ustar = format!("USTAR cannot encode {name}={secs}");
            self.format.must_not_be(FORMAT_USTAR);
        }
        let needs_nano = nanos != 0;
        if !is_mtime || !fits_octal || needs_nano {
            self.prefer_pax = true;
            if pax_key.is_empty() {
                self.why_no_pax = format!("PAX cannot encode {name}={secs}");
                self.format.must_not_be(FORMAT_PAX);
            } else {
                self.pax.insert(pax_key.to_string(), format_pax_time(ts));
            }
        }
        if let Some(v) = self.h.pax_records.get(pax_key) {
            if *v == format_pax_time(ts) {
                self.pax.insert(pax_key.to_string(), v.clone());
            }
        }
    }
}

fn header_error(parts: &[&str]) -> Error {
    let ss: Vec<&str> = parts.iter().copied().filter(|s| !s.is_empty()).collect();
    Error::CannotEncode(ss.join("; and "))
}

impl Header {
    /// Determine which formats can encode this header and the PAX records
    /// needed. `sparse` selects the sparse-file rules of Go's (disabled)
    /// `SparseHoles` support; see `Writer::write_sparse_header`.
    pub(super) fn allowed_formats(
        &self,
        sparse: bool,
    ) -> Result<(Format, BTreeMap<String, String>), Error> {
        let mut a = Allowed {
            h: self,
            format: Format(FORMAT_USTAR.0 | FORMAT_PAX.0 | FORMAT_GNU.0),
            pax: BTreeMap::new(),
            why_no_ustar: String::new(),
            why_no_pax: String::new(),
            why_no_gnu: String::new(),
            prefer_pax: false,
        };
        a.string(&self.name, 100, "Name", PAX_PATH);
        a.string(&self.linkname, 100, "Linkname", PAX_LINKPATH);
        a.string(&self.uname, 32, "Uname", PAX_UNAME);
        a.string(&self.gname, 32, "Gname", PAX_GNAME);
        a.numeric(self.mode, 8, "Mode", "");
        a.numeric(self.uid, 8, "Uid", PAX_UID);
        a.numeric(self.gid, 8, "Gid", PAX_GID);
        a.numeric(self.size, 12, "Size", PAX_SIZE);
        a.numeric(self.devmajor, 8, "Devmajor", "");
        a.numeric(self.devminor, 8, "Devminor", "");
        a.time(&self.mod_time, 12, "ModTime", PAX_MTIME);
        a.time(&self.access_time, 12, "AccessTime", PAX_ATIME);
        a.time(&self.change_time, 12, "ChangeTime", PAX_CTIME);

        let mut why_only_pax = String::new();
        let mut why_only_gnu = String::new();
        match self.typeflag {
            TYPE_REG | TYPE_CHAR | TYPE_BLOCK | TYPE_FIFO | TYPE_GNU_SPARSE => {
                if self.name.ends_with('/') {
                    return Err(header_error(&["filename may not have trailing slash"]));
                }
            }
            TYPE_X_HEADER | TYPE_GNU_LONG_NAME | TYPE_GNU_LONG_LINK => {
                return Err(header_error(&[
                    "cannot manually encode TypeXHeader, TypeGNULongName, or TypeGNULongLink headers",
                ]));
            }
            TYPE_X_GLOBAL_HEADER => {
                let h2 = Header {
                    name: self.name.clone(),
                    typeflag: self.typeflag,
                    xattrs: self.xattrs.clone(),
                    pax_records: self.pax_records.clone(),
                    format: self.format,
                    ..Header::default()
                };
                if *self != h2 {
                    return Err(header_error(&[
                        "only PAXRecords should be set for TypeXGlobalHeader",
                    ]));
                }
                why_only_pax = "only PAX supports TypeXGlobalHeader".into();
                a.format.may_only_be(FORMAT_PAX);
            }
            _ => {}
        }
        if !is_header_only_type(self.typeflag) && self.size < 0 {
            return Err(header_error(&["negative size on header-only type"]));
        }

        if !self.xattrs.is_empty() {
            for (k, v) in &self.xattrs {
                a.pax.insert(format!("{PAX_SCHILY_XATTR}{k}"), v.clone());
            }
            why_only_pax = "only PAX supports Xattrs".into();
            a.format.may_only_be(FORMAT_PAX);
        }
        if !self.pax_records.is_empty() {
            for (k, v) in &self.pax_records {
                if a.pax.contains_key(k) {
                    continue;
                }
                // Global headers copy every record; for others, records that
                // could conflict with the header's own fields are ignored.
                if self.typeflag == TYPE_X_GLOBAL_HEADER
                    || (!is_basic_key(k) && !k.starts_with(PAX_GNU_SPARSE))
                {
                    a.pax.insert(k.clone(), v.clone());
                }
            }
            why_only_pax = "only PAX supports PAXRecords".into();
            a.format.may_only_be(FORMAT_PAX);
        }
        for (k, v) in &a.pax {
            if !valid_pax_record(k, v) {
                return Err(header_error(&[&format!(
                    "invalid PAX record: {:?}",
                    format!("{k} = {v}")
                )]));
            }
        }

        if sparse {
            if self.typeflag == TYPE_GNU_SPARSE {
                why_only_gnu = "only GNU supports TypeGNUSparse".into();
                a.format.may_only_be(FORMAT_GNU);
            } else {
                a.why_no_gnu = "GNU supports sparse files only with TypeGNUSparse".into();
                a.format.must_not_be(FORMAT_GNU);
            }
            a.why_no_ustar = "USTAR does not support sparse files".into();
            a.format.must_not_be(FORMAT_USTAR);
        }

        if self.format != FORMAT_UNKNOWN {
            let mut want = self.format;
            if want.has(FORMAT_PAX) && !a.prefer_pax {
                want.may_be(FORMAT_USTAR);
            }
            a.format.may_only_be(want);
        }
        if a.format == FORMAT_UNKNOWN {
            let err = match self.format {
                FORMAT_USTAR => header_error(&[
                    "Format specifies USTAR",
                    &a.why_no_ustar,
                    &why_only_pax,
                    &why_only_gnu,
                ]),
                FORMAT_PAX => header_error(&["Format specifies PAX", &a.why_no_pax, &why_only_gnu]),
                FORMAT_GNU => header_error(&["Format specifies GNU", &a.why_no_gnu, &why_only_pax]),
                _ => header_error(&[
                    &a.why_no_ustar,
                    &a.why_no_pax,
                    &a.why_no_gnu,
                    &why_only_pax,
                    &why_only_gnu,
                ]),
            };
            return Err(err);
        }
        Ok((a.format, a.pax))
    }

    /// `Header.FileInfo`: a [`FileInfo`] describing this header.
    pub fn file_info(&self) -> HeaderFileInfo {
        HeaderFileInfo { h: self.clone() }
    }
}

const C_ISUID: i64 = 0o4000;
const C_ISGID: i64 = 0o2000;
const C_ISVTX: i64 = 0o1000;
const C_ISDIR: i64 = 0o40000;
const C_ISFIFO: i64 = 0o10000;
const C_ISLNK: i64 = 0o120000;
const C_ISBLK: i64 = 0o60000;
const C_ISCHR: i64 = 0o20000;
const C_ISSOCK: i64 = 0o140000;

/// The [`FileInfo`] returned by [`Header::file_info`]; `sys()` is the [`Header`].
#[derive(Clone, Debug)]
pub struct HeaderFileInfo {
    h: Header,
}

impl FileInfo for HeaderFileInfo {
    fn name(&self) -> String {
        if self.is_dir() {
            crate::path::base(&crate::path::clean(&self.h.name)).to_string()
        } else {
            crate::path::base(&self.h.name).to_string()
        }
    }
    fn size(&self) -> i64 {
        self.h.size
    }
    fn mode(&self) -> FileMode {
        let hm = self.h.mode;
        let mut mode = FileMode((hm & 0o777) as u32);
        if hm & C_ISUID != 0 {
            mode |= FileMode::SETUID;
        }
        if hm & C_ISGID != 0 {
            mode |= FileMode::SETGID;
        }
        if hm & C_ISVTX != 0 {
            mode |= FileMode::STICKY;
        }
        // Go converts through uint32 before masking off the permission bits.
        match (hm as u32 as i64) & !0o7777 {
            C_ISDIR => mode |= FileMode::DIR,
            C_ISFIFO => mode |= FileMode::NAMED_PIPE,
            C_ISLNK => mode |= FileMode::SYMLINK,
            C_ISBLK => mode |= FileMode::DEVICE,
            C_ISCHR => mode |= FileMode::DEVICE | FileMode::CHAR_DEVICE,
            C_ISSOCK => mode |= FileMode::SOCKET,
            _ => {}
        }
        match self.h.typeflag {
            TYPE_SYMLINK => mode |= FileMode::SYMLINK,
            TYPE_CHAR => mode |= FileMode::DEVICE | FileMode::CHAR_DEVICE,
            TYPE_BLOCK => mode |= FileMode::DEVICE,
            TYPE_DIR => mode |= FileMode::DIR,
            TYPE_FIFO => mode |= FileMode::NAMED_PIPE,
            _ => {}
        }
        mode
    }
    fn mod_time(&self) -> SystemTime {
        self.h.mod_time
    }
    fn sys(&self) -> Option<&dyn Any> {
        Some(&self.h)
    }
}

/// `tar.FileInfoNames` is the same trait the crate's [`FileInfo`] uses to
/// expose user and group names.
pub use crate::archive::iofs::FileInfoNames;

/// Resolves a decimal user or group id to its name.
pub type NameLookupFn = fn(&str) -> Option<String>;

static NAME_LOOKUP: RwLock<Option<(NameLookupFn, NameLookupFn)>> = RwLock::new(None);

/// Makes [`file_info_header`] resolve Uname and Gname with `user` and `group`
/// instead of the built-in lookup. A later call replaces an earlier one.
///
/// Go looks names up through the C library, so NSS and macOS Open Directory
/// accounts resolve. The root crate has no FFI, so by default it reads
/// `/etc/passwd` and `/etc/group` and knows the current user through `$USER`.
/// Installing the lookups of `rust_stdlib_sys::os::user` gives Go's result:
///
/// ```ignore
/// use rust_stdlib_sys::os::user::{lookup_group_id, lookup_id};
/// rust_stdlib::archive::tar::set_name_lookup(
///     |uid| lookup_id(uid).ok().map(|u| u.username),
///     |gid| lookup_group_id(gid).ok().map(|g| g.name),
/// );
/// ```
pub fn set_name_lookup(user: NameLookupFn, group: NameLookupFn) {
    *NAME_LOOKUP.write().unwrap_or_else(|e| e.into_inner()) = Some((user, group));
}

/// `FileInfoHeader`: create a [`Header`] from file information. If `fi`
/// describes a symlink, `link` is the target. User and group names are taken
/// from [`FileInfoNames`] when available, and on Unix looked up for real files
/// (best effort, as in Go) through [`set_name_lookup`]'s lookups or the
/// `/etc` files.
pub fn file_info_header(fi: &dyn FileInfo, link: &str) -> io::Result<Header> {
    let fm = fi.mode();
    let mut h = Header {
        name: fi.name(),
        mod_time: fi.mod_time(),
        mode: i64::from(fm.perm().0),
        ..Header::default()
    };
    if fm.is_regular() {
        h.typeflag = TYPE_REG;
        h.size = fi.size();
    } else if fi.is_dir() {
        h.typeflag = TYPE_DIR;
        h.name.push('/');
    } else if fm.has(FileMode::SYMLINK) {
        h.typeflag = TYPE_SYMLINK;
        h.linkname = link.to_string();
    } else if fm.has(FileMode::DEVICE) {
        h.typeflag = if fm.has(FileMode::CHAR_DEVICE) {
            TYPE_CHAR
        } else {
            TYPE_BLOCK
        };
    } else if fm.has(FileMode::NAMED_PIPE) {
        h.typeflag = TYPE_FIFO;
    } else if fm.has(FileMode::SOCKET) {
        return Err(io::Error::other("archive/tar: sockets not supported"));
    } else {
        return Err(io::Error::other(format!(
            "archive/tar: unknown file mode {fm}"
        )));
    }
    if fm.has(FileMode::SETUID) {
        h.mode |= C_ISUID;
    }
    if fm.has(FileMode::SETGID) {
        h.mode |= C_ISGID;
    }
    if fm.has(FileMode::STICKY) {
        h.mode |= C_ISVTX;
    }
    if let Some(sys) = fi.sys().and_then(|s| s.downcast_ref::<Header>()) {
        h.uid = sys.uid;
        h.gid = sys.gid;
        h.uname = sys.uname.clone();
        h.gname = sys.gname.clone();
        h.access_time = sys.access_time;
        h.change_time = sys.change_time;
        h.xattrs = sys.xattrs.clone();
        if sys.typeflag == TYPE_LINK {
            h.typeflag = TYPE_LINK;
            h.size = 0;
            h.linkname = sys.linkname.clone();
        }
        h.pax_records = sys.pax_records.clone();
    }
    let names = fi.as_names();
    if let Some(names) = names {
        h.gname = names.gname()?;
        h.uname = names.uname()?;
    }
    #[cfg(unix)]
    if let Some(meta) = fi.sys().and_then(|s| s.downcast_ref::<std::fs::Metadata>()) {
        stat_unix(meta, &mut h, names.is_none());
    }
    Ok(h)
}

#[cfg(unix)]
fn stat_unix(meta: &std::fs::Metadata, h: &mut Header, do_name_lookups: bool) {
    use crate::archive::iofs::time_unix;
    use std::os::unix::fs::MetadataExt;
    h.uid = i64::from(meta.uid());
    h.gid = i64::from(meta.gid());
    if do_name_lookups {
        let (user, group) = NAME_LOOKUP
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .unwrap_or((crate::os::user::user_name, crate::os::user::group_name));
        // Best effort, as in Go: lookup failures leave Uname and Gname as they are.
        if let Some(name) = user(&h.uid.to_string()) {
            h.uname = name;
        }
        if let Some(name) = group(&h.gid.to_string()) {
            h.gname = name;
        }
    }
    h.access_time = time_unix(meta.atime(), meta.atime_nsec());
    h.change_time = time_unix(meta.ctime(), meta.ctime_nsec());
    if h.typeflag == TYPE_CHAR || h.typeflag == TYPE_BLOCK {
        let dev = meta.rdev();
        let (major, minor) = if cfg!(target_os = "linux") {
            (
                ((dev & 0x0000_0000_000f_ff00) >> 8) | ((dev & 0xffff_f000_0000_0000) >> 32),
                (dev & 0xff) | ((dev & 0x0000_0fff_fff0_0000) >> 12),
            )
        } else if cfg!(any(target_os = "macos", target_os = "ios")) {
            ((dev >> 24) & 0xff, dev & 0xff_ffff)
        } else if cfg!(any(target_os = "freebsd", target_os = "dragonfly")) {
            ((dev >> 8) & 0xff, dev & 0xffff_00ff)
        } else if cfg!(target_os = "netbsd") {
            (
                (dev & 0x000f_ff00) >> 8,
                (dev & 0xff) | ((dev & 0xfff0_0000) >> 12),
            )
        } else if cfg!(target_os = "openbsd") {
            (
                (dev & 0xff00) >> 8,
                (dev & 0xff) | ((dev & 0xffff_0000) >> 8),
            )
        } else {
            (0, 0)
        };
        h.devmajor = i64::from(major as u32);
        h.devminor = i64::from(minor as u32);
    }
}
