//! `FileHeader`, error values and name encodings of Go's `archive/zip`
//! (`struct.go`).
use crate::archive::iofs::{
    civil_from_unix, time_is_zero, time_parts, time_unix, time_zero, unix_from_civil, FileInfo,
    FileMode,
};
use std::{any::Any, fmt, io, time::SystemTime};

/// No compression.
pub const STORE: u16 = 0;
/// DEFLATE compression.
pub const DEFLATE: u16 = 8;

pub(super) const FILE_HEADER_SIGNATURE: u32 = 0x04034b50;
pub(super) const DIRECTORY_HEADER_SIGNATURE: u32 = 0x02014b50;
pub(super) const DIRECTORY_END_SIGNATURE: u32 = 0x06054b50;
pub(super) const DIRECTORY64_LOC_SIGNATURE: u32 = 0x07064b50;
pub(super) const DIRECTORY64_END_SIGNATURE: u32 = 0x06064b50;
pub(super) const DATA_DESCRIPTOR_SIGNATURE: u32 = 0x08074b50;
pub(super) const FILE_HEADER_LEN: usize = 30;
pub(super) const DIRECTORY_HEADER_LEN: usize = 46;
pub(super) const DIRECTORY_END_LEN: usize = 22;
pub(super) const DATA_DESCRIPTOR_LEN: usize = 16;
pub(super) const DATA_DESCRIPTOR64_LEN: usize = 24;
pub(super) const DIRECTORY64_LOC_LEN: usize = 20;
pub(super) const DIRECTORY64_END_LEN: usize = 56;

pub(super) const CREATOR_FAT: u16 = 0;
pub(super) const CREATOR_UNIX: u16 = 3;
pub(super) const CREATOR_NTFS: u16 = 11;
pub(super) const CREATOR_VFAT: u16 = 14;
pub(super) const CREATOR_MACOSX: u16 = 19;

pub(super) const ZIP_VERSION_20: u16 = 20;
pub(super) const ZIP_VERSION_45: u16 = 45;

pub(super) const UINT16_MAX: u64 = (1 << 16) - 1;
pub(super) const UINT32_MAX: u64 = (1 << 32) - 1;

pub(super) const ZIP64_EXTRA_ID: u16 = 0x0001;
pub(super) const NTFS_EXTRA_ID: u16 = 0x000a;
pub(super) const UNIX_EXTRA_ID: u16 = 0x000d;
pub(super) const EXT_TIME_EXTRA_ID: u16 = 0x5455;
pub(super) const INFO_ZIP_UNIX_EXTRA_ID: u16 = 0x5855;

/// The error values of `archive/zip`. Returned inside `io::Error`; test with
/// [`Error::matches`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// `ErrFormat`: not a valid zip file.
    Format,
    /// `ErrAlgorithm`: unsupported compression algorithm.
    Algorithm,
    /// `ErrChecksum`: checksum error.
    Checksum,
    /// `ErrInsecurePath`: insecure file path.
    InsecurePath,
}

pub const ERR_FORMAT: Error = Error::Format;
pub const ERR_ALGORITHM: Error = Error::Algorithm;
pub const ERR_CHECKSUM: Error = Error::Checksum;
pub const ERR_INSECURE_PATH: Error = Error::InsecurePath;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Format => "zip: not a valid zip file",
            Error::Algorithm => "zip: unsupported compression algorithm",
            Error::Checksum => "zip: checksum error",
            Error::InsecurePath => "zip: insecure file path",
        })
    }
}
impl std::error::Error for Error {}

impl Error {
    /// The zip error carried by `err`, if any (Go's `errors.Is` on a sentinel).
    pub fn from_io(err: &io::Error) -> Option<Error> {
        let inner = err.get_ref()?;
        if let Some(e) = inner.downcast_ref::<Error>() {
            return Some(*e);
        }
        inner
            .downcast_ref::<super::InsecurePathError>()
            .map(|_| Error::InsecurePath)
    }
    /// Report whether `err` is this error value.
    pub fn matches(&self, err: &io::Error) -> bool {
        Error::from_io(err) == Some(*self)
    }
}
impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        let kind = match e {
            Error::Algorithm => io::ErrorKind::Unsupported,
            _ => io::ErrorKind::InvalidData,
        };
        io::Error::new(kind, e)
    }
}

/// `ErrUnexpectedEOF`.
pub(super) fn unexpected_eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")
}

/// Describes a file within a zip file (Go's `zip.FileHeader`).
#[derive(Clone, Debug, PartialEq)]
pub struct FileHeader {
    /// Name of the file. It must be a relative path, not start with a drive
    /// letter, and use forward slashes. A trailing slash marks a directory.
    pub name: String,
    pub comment: String,
    /// The exact bytes of `name` when they are not valid UTF-8 (Go's `Name`
    /// holds arbitrary bytes). A reader sets it for such names, with `name`
    /// the CP437 reading of them (see [`cp437_decode`]); a writer stores it
    /// instead of `name` when it is `Some`. [`FileHeader::name_bytes`] is the
    /// bytes in either case.
    pub raw_name: Option<Vec<u8>>,
    /// Like `raw_name`, for `comment`.
    pub raw_comment: Option<Vec<u8>>,
    /// Names and comments that are not UTF-8 are CP437 on the wire; see
    /// [`cp437_decode`].
    pub non_utf8: bool,
    pub creator_version: u16,
    pub reader_version: u16,
    pub flags: u16,
    /// Compression method; [`STORE`] or [`DEFLATE`] unless registered.
    pub method: u16,
    /// Modified time (UTC instant; Go also carries a zone offset).
    pub modified: SystemTime,
    /// Deprecated: use `modified`.
    pub modified_time: u16,
    /// Deprecated: use `modified`.
    pub modified_date: u16,
    pub crc32: u32,
    /// Deprecated: use `compressed_size64`.
    pub compressed_size: u32,
    /// Deprecated: use `uncompressed_size64`.
    pub uncompressed_size: u32,
    pub compressed_size64: u64,
    pub uncompressed_size64: u64,
    pub extra: Vec<u8>,
    pub external_attrs: u32,
}

impl Default for FileHeader {
    fn default() -> Self {
        Self {
            name: String::new(),
            comment: String::new(),
            raw_name: None,
            raw_comment: None,
            non_utf8: false,
            creator_version: 0,
            reader_version: 0,
            flags: 0,
            method: 0,
            modified: time_zero(),
            modified_time: 0,
            modified_date: 0,
            crc32: 0,
            compressed_size: 0,
            uncompressed_size: 0,
            compressed_size64: 0,
            uncompressed_size64: 0,
            extra: Vec::new(),
            external_attrs: 0,
        }
    }
}

const S_IFMT: u32 = 0xf000;
const S_IFSOCK: u32 = 0xc000;
const S_IFLNK: u32 = 0xa000;
const S_IFREG: u32 = 0x8000;
const S_IFBLK: u32 = 0x6000;
const S_IFDIR: u32 = 0x4000;
const S_IFCHR: u32 = 0x2000;
const S_IFIFO: u32 = 0x1000;
const S_ISUID: u32 = 0x800;
const S_ISGID: u32 = 0x400;
const S_ISVTX: u32 = 0x200;
const MSDOS_DIR: u32 = 0x10;
const MSDOS_READ_ONLY: u32 = 0x01;

/// `msDosTimeToTime`: DOS date and time as a UTC instant, with `time.Date`
/// normalisation of out-of-range fields.
pub(super) fn ms_dos_time_to_time(dos_date: u16, dos_time: u16) -> SystemTime {
    time_unix(
        unix_from_civil(
            i64::from(dos_date >> 9) + 1980,
            i64::from(dos_date >> 5 & 0xf),
            i64::from(dos_date & 0x1f),
            i64::from(dos_time >> 11),
            i64::from(dos_time >> 5 & 0x3f),
            i64::from(dos_time & 0x1f) * 2,
        ),
        0,
    )
}

/// `timeToMsDosTime` for a UTC instant.
pub(super) fn time_to_ms_dos_time(t: &SystemTime) -> (u16, u16) {
    let (y, mo, d, h, mi, s) = civil_from_unix(time_parts(t).0);
    let date = (d + (mo << 5) + ((y - 1980) << 9)) as u16;
    let time = (s / 2 + (mi << 5) + (h << 11)) as u16;
    (date, time)
}

impl FileHeader {
    /// `FileHeader.FileInfo`: a [`FileInfo`] for this header.
    pub fn file_info(&self) -> HeaderFileInfo {
        HeaderFileInfo { fh: self.clone() }
    }

    /// Deprecated: `ModTime` from the MS-DOS date and time fields, as UTC.
    pub fn mod_time(&self) -> SystemTime {
        ms_dos_time_to_time(self.modified_date, self.modified_time)
    }

    /// Deprecated: set `modified` and the MS-DOS date and time fields.
    pub fn set_mod_time(&mut self, t: SystemTime) {
        self.modified = t;
        let (date, time) = time_to_ms_dos_time(&t);
        self.modified_date = date;
        self.modified_time = time;
    }

    /// The permission and mode bits.
    pub fn mode(&self) -> FileMode {
        let mut mode = FileMode(0);
        match self.creator_version >> 8 {
            CREATOR_UNIX | CREATOR_MACOSX => {
                mode = unix_mode_to_file_mode(self.external_attrs >> 16);
            }
            CREATOR_NTFS | CREATOR_VFAT | CREATOR_FAT => {
                mode = msdos_mode_to_file_mode(self.external_attrs);
            }
            _ => {}
        }
        if self.name.ends_with('/') {
            mode |= FileMode::DIR;
        }
        mode
    }

    /// Set the permission and mode bits (Unix creator).
    pub fn set_mode(&mut self, mode: FileMode) {
        self.creator_version = self.creator_version & 0xff | CREATOR_UNIX << 8;
        self.external_attrs = file_mode_to_unix_mode(mode) << 16;
        if mode.has(FileMode::DIR) {
            self.external_attrs |= MSDOS_DIR;
        }
        if mode.0 & 0o200 == 0 {
            self.external_attrs |= MSDOS_READ_ONLY;
        }
    }

    pub(super) fn has_data_descriptor(&self) -> bool {
        self.flags & 0x8 != 0
    }
}

fn msdos_mode_to_file_mode(m: u32) -> FileMode {
    let mut mode = if m & MSDOS_DIR != 0 {
        FileMode::DIR.0 | 0o777
    } else {
        0o666
    };
    if m & MSDOS_READ_ONLY != 0 {
        mode &= !0o222;
    }
    FileMode(mode)
}

fn file_mode_to_unix_mode(mode: FileMode) -> u32 {
    let t = mode.0 & FileMode::TYPE.0;
    let mut m = if t == FileMode::DIR.0 {
        S_IFDIR
    } else if t == FileMode::SYMLINK.0 {
        S_IFLNK
    } else if t == FileMode::NAMED_PIPE.0 {
        S_IFIFO
    } else if t == FileMode::SOCKET.0 {
        S_IFSOCK
    } else if t == FileMode::DEVICE.0 {
        S_IFBLK
    } else if t == FileMode::DEVICE.0 | FileMode::CHAR_DEVICE.0 {
        S_IFCHR
    } else {
        S_IFREG
    };
    if mode.has(FileMode::SETUID) {
        m |= S_ISUID;
    }
    if mode.has(FileMode::SETGID) {
        m |= S_ISGID;
    }
    if mode.has(FileMode::STICKY) {
        m |= S_ISVTX;
    }
    m | (mode.0 & 0o777)
}

fn unix_mode_to_file_mode(m: u32) -> FileMode {
    let mut mode = FileMode(m & 0o777);
    match m & S_IFMT {
        S_IFBLK => mode |= FileMode::DEVICE,
        S_IFCHR => mode |= FileMode::DEVICE | FileMode::CHAR_DEVICE,
        S_IFDIR => mode |= FileMode::DIR,
        S_IFIFO => mode |= FileMode::NAMED_PIPE,
        S_IFLNK => mode |= FileMode::SYMLINK,
        S_IFSOCK => mode |= FileMode::SOCKET,
        _ => {}
    }
    if m & S_ISGID != 0 {
        mode |= FileMode::SETGID;
    }
    if m & S_ISUID != 0 {
        mode |= FileMode::SETUID;
    }
    if m & S_ISVTX != 0 {
        mode |= FileMode::STICKY;
    }
    mode
}

/// The [`FileInfo`] of a [`FileHeader`]; `sys()` is the [`FileHeader`].
#[derive(Clone, Debug)]
pub struct HeaderFileInfo {
    pub(super) fh: FileHeader,
}

impl FileInfo for HeaderFileInfo {
    fn name(&self) -> String {
        crate::path::base(&self.fh.name).to_string()
    }
    fn size(&self) -> i64 {
        if self.fh.uncompressed_size64 > 0 {
            self.fh.uncompressed_size64 as i64
        } else {
            i64::from(self.fh.uncompressed_size)
        }
    }
    fn mode(&self) -> FileMode {
        self.fh.mode()
    }
    fn mod_time(&self) -> SystemTime {
        if time_is_zero(&self.fh.modified) {
            self.fh.mod_time()
        } else {
            self.fh.modified
        }
    }
    fn sys(&self) -> Option<&dyn Any> {
        Some(&self.fh)
    }
}

/// `FileInfoHeader`: create a [`FileHeader`] from file information. Names are
/// base names; callers set `name` to the path they want. The header's
/// compression method is left as [`STORE`].
pub fn file_info_header(fi: &dyn FileInfo) -> io::Result<FileHeader> {
    let size = fi.size();
    let mut fh = FileHeader {
        name: fi.name(),
        uncompressed_size64: size as u64,
        ..FileHeader::default()
    };
    fh.set_mod_time(fi.mod_time());
    fh.set_mode(fi.mode());
    fh.uncompressed_size = if fh.uncompressed_size64 > UINT32_MAX {
        UINT32_MAX as u32
    } else {
        fh.uncompressed_size64 as u32
    };
    Ok(fh)
}

/// CP437 characters for bytes 0x80 through 0xFF.
const CP437_HIGH: [char; 128] = [
    'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å', 'É', 'æ', 'Æ',
    'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ', 'á', 'í', 'ó', 'ú', 'ñ', 'Ñ',
    'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»', '░', '▒', '▓', '│', '┤', '╡', '╢', '╖', '╕',
    '╣', '║', '╗', '╝', '╜', '╛', '┐', '└', '┴', '┬', '├', '─', '┼', '╞', '╟', '╚', '╔', '╩', '╦',
    '╠', '═', '╬', '╧', '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘', '┌', '█', '▄', '▌', '▐',
    '▀', 'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ', '∞', 'φ', 'ε', '∩', '≡', '±',
    '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²', '■', '\u{a0}',
];

/// Decode CP437 bytes (the legacy ZIP name encoding). Bytes below 0x80 map to
/// themselves; every byte has a character, so decoding never fails.
pub fn cp437_decode(b: &[u8]) -> String {
    b.iter()
        .map(|&c| {
            if c < 0x80 {
                c as char
            } else {
                CP437_HIGH[usize::from(c - 0x80)]
            }
        })
        .collect()
}

/// Encode `s` as CP437, or `None` if a character has no CP437 byte.
pub fn cp437_encode(s: &str) -> Option<Vec<u8>> {
    s.chars()
        .map(|c| {
            if (c as u32) < 0x80 {
                Some(c as u8)
            } else {
                CP437_HIGH
                    .iter()
                    .position(|&h| h == c)
                    .map(|i| 0x80 + i as u8)
            }
        })
        .collect()
}

impl FileHeader {
    /// Go's `Name`: the exact bytes, [`FileHeader::raw_name`] or else `name`.
    pub fn name_bytes(&self) -> &[u8] {
        self.raw_name.as_deref().unwrap_or(self.name.as_bytes())
    }

    /// Go's `Comment`: the exact bytes, [`FileHeader::raw_comment`] or else `comment`.
    pub fn comment_bytes(&self) -> &[u8] {
        self.raw_comment
            .as_deref()
            .unwrap_or(self.comment.as_bytes())
    }
}

/// The text of `b` and, when `b` is not valid UTF-8, `b` itself.
pub(super) fn text_and_raw(b: &[u8]) -> (String, Option<Vec<u8>>) {
    match std::str::from_utf8(b) {
        Ok(_) => (decode_text(b), None),
        Err(_) => (decode_text(b), Some(b.to_vec())),
    }
}

/// Names and comments: valid UTF-8 stays text; anything else is CP437.
pub(super) fn decode_text(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(s) => s.to_string(),
        Err(_) => cp437_decode(b),
    }
}

/// `detectUTF8`: whether `s` is valid UTF-8, and whether it contains
/// characters that need the UTF-8 flag (control characters, anything above
/// `}` or a backslash).
pub(super) fn detect_utf8(s: &[u8]) -> (bool, bool) {
    let Ok(text) = std::str::from_utf8(s) else {
        return (false, false);
    };
    let require = text
        .chars()
        .any(|r| (r as u32) < 0x20 || (r as u32) > 0x7d || r == '\\');
    (true, require)
}
