//! The file model of `archive/tar` and `archive/zip`: [`FileMode`],
//! [`FileInfo`], [`DirEntry`] and [`File`] with `std::time::SystemTime` times
//! (Go's zero `time.Time` is [`time_zero`]). File systems are the crate-wide
//! [`io::fs::FS`](crate::io::fs::FS): the readers implement it and the
//! writers' `add_fs` take it.
use crate::io::fs;
use crate::io::{is_eof, ReadAt};
use std::{
    any::Any,
    fmt, io,
    io::Read,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Seconds from the Go zero time (January 1, year 1 UTC) to the Unix epoch.
const ZERO_TIME_UNIX: i64 = -62_135_596_800;

/// Go's zero `time.Time`, used for "unset" timestamps.
pub fn time_zero() -> SystemTime {
    time_unix(ZERO_TIME_UNIX, 0)
}

/// Report whether `t` is Go's zero time.
pub fn time_is_zero(t: &SystemTime) -> bool {
    time_parts(t) == (ZERO_TIME_UNIX, 0)
}

/// Build a time from Unix seconds and nanoseconds (`time.Unix`). Nanoseconds
/// outside `0..1e9` carry into the seconds. Unrepresentable values saturate
/// at the platform limits.
pub fn time_unix(secs: i64, nanos: i64) -> SystemTime {
    let secs = secs.saturating_add(nanos.div_euclid(1_000_000_000));
    let nanos = nanos.rem_euclid(1_000_000_000) as u32;
    if secs >= 0 {
        UNIX_EPOCH
            .checked_add(Duration::new(secs as u64, nanos))
            .unwrap_or(UNIX_EPOCH)
    } else {
        let base = UNIX_EPOCH
            .checked_sub(Duration::new(secs.unsigned_abs(), 0))
            .unwrap_or(UNIX_EPOCH);
        base.checked_add(Duration::new(0, nanos)).unwrap_or(base)
    }
}

/// Report whether Unix seconds can be held by `SystemTime` on this platform.
pub(crate) fn time_representable(secs: i64) -> bool {
    let t = time_unix(secs, 0);
    time_parts(&t).0 == secs
}

/// Unix seconds (floor) and nanoseconds in `0..1e9` (`Time.Unix`, `Time.Nanosecond`).
pub fn time_parts(t: &SystemTime) -> (i64, u32) {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
        Err(e) => {
            let d = e.duration();
            if d.subsec_nanos() == 0 {
                (-(d.as_secs() as i64), 0)
            } else {
                (-(d.as_secs() as i64) - 1, 1_000_000_000 - d.subsec_nanos())
            }
        }
    }
}

/// Round to the nearest second, halves rounding up (`Time.Round(time.Second)`).
pub fn time_round_second(t: &SystemTime) -> SystemTime {
    let (s, n) = time_parts(t);
    time_unix(if n >= 500_000_000 { s + 1 } else { s }, 0)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Unix seconds of a UTC civil time with `time.Date` normalisation of
/// out-of-range month, day, hour, minute and second values.
pub(crate) fn unix_from_civil(
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    min: i64,
    sec: i64,
) -> i64 {
    let m0 = month - 1;
    let year = year + m0.div_euclid(12);
    let month = m0.rem_euclid(12) + 1;
    (days_from_civil(year, month, 1) + day - 1) * 86_400 + hour * 3600 + min * 60 + sec
}

/// `(year, month, day, hour, minute, second)` of Unix seconds in UTC.
pub(crate) fn civil_from_unix(secs: i64) -> (i64, i64, i64, i64, i64, i64) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d, rem / 3600, rem % 3600 / 60, rem % 60)
}

/// Go's `fs.FileMode`: permission bits plus the type bits below.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct FileMode(pub u32);

impl FileMode {
    pub const DIR: FileMode = FileMode(1 << 31);
    pub const APPEND: FileMode = FileMode(1 << 30);
    pub const EXCLUSIVE: FileMode = FileMode(1 << 29);
    pub const TEMPORARY: FileMode = FileMode(1 << 28);
    pub const SYMLINK: FileMode = FileMode(1 << 27);
    pub const DEVICE: FileMode = FileMode(1 << 26);
    pub const NAMED_PIPE: FileMode = FileMode(1 << 25);
    pub const SOCKET: FileMode = FileMode(1 << 24);
    pub const SETUID: FileMode = FileMode(1 << 23);
    pub const SETGID: FileMode = FileMode(1 << 22);
    pub const CHAR_DEVICE: FileMode = FileMode(1 << 21);
    pub const STICKY: FileMode = FileMode(1 << 20);
    pub const IRREGULAR: FileMode = FileMode(1 << 19);
    pub const TYPE: FileMode = FileMode(
        Self::DIR.0
            | Self::SYMLINK.0
            | Self::NAMED_PIPE.0
            | Self::SOCKET.0
            | Self::DEVICE.0
            | Self::CHAR_DEVICE.0
            | Self::IRREGULAR.0,
    );
    pub const PERM: FileMode = FileMode(0o777);
    pub fn is_dir(self) -> bool {
        self.0 & Self::DIR.0 != 0
    }
    pub fn is_regular(self) -> bool {
        self.0 & Self::TYPE.0 == 0
    }
    pub fn perm(self) -> FileMode {
        FileMode(self.0 & Self::PERM.0)
    }
    pub fn type_(self) -> FileMode {
        FileMode(self.0 & Self::TYPE.0)
    }
    pub fn has(self, other: FileMode) -> bool {
        self.0 & other.0 != 0
    }
}
impl std::ops::BitOr for FileMode {
    type Output = FileMode;
    fn bitor(self, rhs: FileMode) -> FileMode {
        FileMode(self.0 | rhs.0)
    }
}
impl std::ops::BitOrAssign for FileMode {
    fn bitor_assign(&mut self, rhs: FileMode) {
        self.0 |= rhs.0;
    }
}
impl fmt::Display for FileMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const STR: &[u8] = b"dalTLDpSugct?";
        let mut out = String::new();
        for (i, c) in STR.iter().enumerate() {
            if self.0 & (1 << (31 - i)) != 0 {
                out.push(*c as char);
            }
        }
        if out.is_empty() {
            out.push('-');
        }
        const RWX: &[u8] = b"rwxrwxrwx";
        for (i, c) in RWX.iter().enumerate() {
            if self.0 & (1 << (8 - i)) != 0 {
                out.push(*c as char);
            } else {
                out.push('-');
            }
        }
        f.write_str(&out)
    }
}

/// Go's `fs.FileInfo`.
pub trait FileInfo {
    fn name(&self) -> String;
    fn size(&self) -> i64;
    fn mode(&self) -> FileMode;
    fn mod_time(&self) -> SystemTime;
    fn is_dir(&self) -> bool {
        self.mode().is_dir()
    }
    /// Underlying data source (`Sys()`); `None` when there is none.
    fn sys(&self) -> Option<&dyn Any> {
        None
    }
    /// Go's type assertion to `tar.FileInfoNames`.
    fn as_names(&self) -> Option<&dyn FileInfoNames> {
        None
    }
}

/// Go's `tar.FileInfoNames`: a [`FileInfo`] that can report user and group names.
pub trait FileInfoNames: FileInfo {
    fn uname(&self) -> io::Result<String>;
    fn gname(&self) -> io::Result<String>;
}

/// Shared handle to a [`FileInfo`].
pub type FileInfoRef = Arc<dyn FileInfo>;

/// Go's `fs.DirEntry`.
pub trait DirEntry {
    fn name(&self) -> String;
    fn is_dir(&self) -> bool {
        self.type_().is_dir()
    }
    fn type_(&self) -> FileMode;
    fn info(&self) -> io::Result<FileInfoRef>;
}

/// Go's `io.ReadCloser`. Dropping the value also releases its resources.
pub trait ReadCloser: Read {
    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Go's `io.WriteCloser`: `close` flushes any buffered data and finishes
/// the stream.
pub trait WriteCloser: io::Write {
    fn close(&mut self) -> io::Result<()>;
}

/// Go's `fs.File`; dropping the value closes it.
pub trait File: Read {
    fn stat(&self) -> io::Result<FileInfoRef>;
    /// Go's `ReadDirFile.ReadDir(n)`; `n <= 0` returns all remaining entries.
    fn read_dir(&mut self, n: i64) -> io::Result<Vec<Box<dyn DirEntry>>> {
        let _ = n;
        Err(PathError::new("readdir", "", "not implemented", io::ErrorKind::Unsupported).into())
    }
}

/// Fill `buf` from `offset`, returning `io.ErrUnexpectedEOF` when the input
/// ends first (Go's `ReadAt` contract for short reads, with `io.EOF` mapped).
pub(crate) fn read_full_at(r: &dyn ReadAt, buf: &mut [u8], offset: u64) -> io::Result<()> {
    match r.read_at(buf, offset) {
        Ok(_) => Ok(()),
        Err(e) if e.read() < buf.len() && is_eof(e.source()) => {
            Err(crate::io::Error::UnexpectedEof.into())
        }
        Err(e) => Err(e.into_source()),
    }
}

/// One `Read::read` step over a [`ReadAt`]: the bytes available at `offset`,
/// with end of data as `Ok(n)` (`Ok(0)` when nothing is left).
pub(crate) fn read_some_at(r: &dyn ReadAt, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    match r.read_at(buf, offset) {
        Ok(n) => Ok(n),
        Err(e) if is_eof(e.source()) => Ok(e.read()),
        Err(e) => Err(e.into_source()),
    }
}

/// Go's `*fs.PathError`.
#[derive(Debug)]
pub struct PathError {
    pub op: String,
    pub path: String,
    pub err: String,
    pub kind: io::ErrorKind,
}
impl PathError {
    pub fn new(op: &str, path: &str, err: &str, kind: io::ErrorKind) -> Self {
        Self {
            op: op.into(),
            path: path.into(),
            err: err.into(),
            kind,
        }
    }
}
impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.op, self.path, self.err)
    }
}
impl std::error::Error for PathError {}
impl From<PathError> for io::Error {
    fn from(e: PathError) -> io::Error {
        io::Error::new(e.kind, e)
    }
}

/// `fs.ValidPath`: unrooted, slash-separated, no empty/`.`/`..` elements
/// (except the single name `.`).
pub fn valid_path(name: &str) -> bool {
    if name == "." {
        return true;
    }
    name.split('/')
        .all(|e| !e.is_empty() && e != "." && e != "..")
}

/// A [`FileInfo`] defined by its parts, with optional `sys` data and names.
#[derive(Clone)]
pub struct BasicFileInfo {
    pub name: String,
    pub size: i64,
    pub mode: FileMode,
    pub mod_time: SystemTime,
    pub uname: Option<String>,
    pub gname: Option<String>,
}
impl FileInfo for BasicFileInfo {
    fn name(&self) -> String {
        self.name.clone()
    }
    fn size(&self) -> i64 {
        self.size
    }
    fn mode(&self) -> FileMode {
        self.mode
    }
    fn mod_time(&self) -> SystemTime {
        self.mod_time
    }
    fn as_names(&self) -> Option<&dyn FileInfoNames> {
        if self.uname.is_some() || self.gname.is_some() {
            Some(self)
        } else {
            None
        }
    }
}
impl FileInfoNames for BasicFileInfo {
    fn uname(&self) -> io::Result<String> {
        Ok(self.uname.clone().unwrap_or_default())
    }
    fn gname(&self) -> io::Result<String> {
        Ok(self.gname.clone().unwrap_or_default())
    }
}

/// An [`io::fs::FileInfo`](fs::FileInfo) as this module's [`FileInfo`], so
/// file systems of the crate-wide `io/fs` feed `file_info_header`.
pub struct FsInfo(pub Box<dyn fs::FileInfo>);

impl FileInfo for FsInfo {
    fn name(&self) -> String {
        self.0.name().to_owned()
    }
    fn size(&self) -> i64 {
        self.0.size()
    }
    fn mode(&self) -> FileMode {
        FileMode(self.0.mode().0)
    }
    fn mod_time(&self) -> SystemTime {
        let t = self.0.mod_time();
        time_unix(t.unix(), t.nanosecond())
    }
    fn sys(&self) -> Option<&dyn Any> {
        self.0.sys()
    }
}

/// A [`FileInfo`] of this module as an [`io::fs::FileInfo`](fs::FileInfo).
struct ArchiveInfo {
    name: String,
    info: FileInfoRef,
}

impl ArchiveInfo {
    fn new(info: FileInfoRef) -> ArchiveInfo {
        ArchiveInfo {
            name: info.name(),
            info,
        }
    }
}

impl fmt::Debug for ArchiveInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileInfo({})", self.name)
    }
}

impl fs::FileInfo for ArchiveInfo {
    fn name(&self) -> &str {
        &self.name
    }
    fn size(&self) -> i64 {
        self.info.size()
    }
    fn mode(&self) -> fs::FileMode {
        fs::FileMode(self.info.mode().0)
    }
    fn mod_time(&self) -> crate::time::Time {
        let (s, n) = time_parts(&self.info.mod_time());
        crate::time::unix(s, i64::from(n))
    }
    fn sys(&self) -> Option<&dyn Any> {
        self.info.sys()
    }
}

struct ArchiveEntry {
    name: String,
    mode: FileMode,
    info: FileInfoRef,
}

impl fmt::Debug for ArchiveEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DirEntry({})", self.name)
    }
}

impl fs::DirEntry for ArchiveEntry {
    fn name(&self) -> &str {
        &self.name
    }
    fn is_dir(&self) -> bool {
        self.mode.is_dir()
    }
    fn file_type(&self) -> fs::FileMode {
        fs::FileMode(self.mode.0)
    }
    fn info(&self) -> io::Result<Box<dyn fs::FileInfo>> {
        Ok(Box::new(ArchiveInfo::new(self.info.clone())))
    }
}

/// A [`File`] of this module as an [`io::fs::File`](fs::File), the value the
/// archive readers' [`FS`](fs::FS) views open.
pub(crate) struct ArchiveFile {
    file: Box<dyn File>,
    dir: bool,
}

impl ArchiveFile {
    pub(crate) fn new(file: Box<dyn File>) -> io::Result<ArchiveFile> {
        let dir = file.stat()?.is_dir();
        Ok(ArchiveFile { file, dir })
    }
}

impl fmt::Debug for ArchiveFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("File")
    }
}

impl Read for ArchiveFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl fs::File for ArchiveFile {
    fn stat(&self) -> io::Result<Box<dyn fs::FileInfo>> {
        Ok(Box::new(ArchiveInfo::new(self.file.stat()?)))
    }
    fn as_read_dir_file(&mut self) -> Option<&mut dyn fs::ReadDirFile> {
        if self.dir {
            Some(self)
        } else {
            None
        }
    }
}

impl fs::ReadDirFile for ArchiveFile {
    fn read_dir(&mut self, n: i32) -> Result<Vec<Box<dyn fs::DirEntry>>, fs::ReadDirError> {
        let list = self.file.read_dir(i64::from(n))?;
        let mut out: Vec<Box<dyn fs::DirEntry>> = Vec::with_capacity(list.len());
        for e in list {
            out.push(Box::new(ArchiveEntry {
                name: e.name(),
                mode: e.type_(),
                info: e.info()?,
            }));
        }
        Ok(out)
    }
}

/// The value of `name` in the `GODEBUG` environment variable (last setting wins).
pub(crate) fn godebug(name: &str) -> Option<String> {
    let v = std::env::var("GODEBUG").ok()?;
    let mut found = None;
    for kv in v.split(',') {
        if let Some((k, val)) = kv.split_once('=') {
            if k == name {
                found = Some(val.to_string());
            }
        }
    }
    found
}

/// `filepath.IsLocal` for slash-separated (Unix) paths.
pub fn is_local(path: &str) -> bool {
    if path.is_empty() || path.starts_with('/') {
        return false;
    }
    let cleaned;
    let mut p = path;
    if path.split('/').any(|e| e == "." || e == "..") {
        cleaned = crate::path::clean(path);
        p = &cleaned;
    }
    !(p == ".." || p.starts_with("../"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn civil_round_trip_and_zero() {
        assert_eq!(civil_from_unix(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(civil_from_unix(ZERO_TIME_UNIX), (1, 1, 1, 0, 0, 0));
        for s in [
            -62_135_596_800,
            -1,
            0,
            951_782_400,
            1_700_000_000,
            4_102_444_800,
        ] {
            let (y, mo, d, h, mi, se) = civil_from_unix(s);
            assert_eq!(unix_from_civil(y, mo, d, h, mi, se), s);
        }
        assert_eq!(
            unix_from_civil(1980, 0, 0, 0, 0, 0),
            315_532_800 - 32 * 86_400
        );
        assert!(time_is_zero(&time_zero()));
        assert_eq!(time_parts(&time_unix(-1, 500)), (-1, 500));
        assert_eq!(time_parts(&time_unix(5, -1)), (4, 999_999_999));
    }
    #[test]
    fn modes_and_paths() {
        assert_eq!((FileMode::DIR | FileMode(0o755)).to_string(), "drwxr-xr-x");
        assert!(is_local("a/b") && !is_local("../a") && !is_local("/a") && !is_local("a/../.."));
        assert!(valid_path(".") && !valid_path("a//b") && !valid_path("/a"));
    }
}
