//! Go's `http.FileServer`, `ServeContent`, `ServeFile`, `Dir`, `FS` and the
//! `File`/`FileSystem` interfaces, with Range, conditional-request, index
//! redirect and directory-listing behaviour as in `fs.go`.
use super::handler::{Handler, ResponseWriter};
use super::header::{parse_time, BoxError, ErrorString};
use super::request::Request;
use super::server::SERVER_CONTEXT_KEY;
use super::status::*;
use super::util::{error, html_escape, not_found};
use super::{detect_content_type, status_text, SNIFF_LEN, TIME_FORMAT};
use crate::io::fs::{self as iofs, FS as _};
use crate::net::textproto::{trim_string, MIMEHeader};
use crate::net::url::Url;
use crate::time::{self, Time};
use std::{
    io::{self, Read, Seek, SeekFrom, Write},
    sync::Arc,
};

/// Go's `http.File`: what a [`FileSystem`] returns.
pub trait File: Read + Seek {
    fn close(&mut self) -> io::Result<()>;
    /// Go's `Readdir`: up to `count` entries, or all with `count <= 0`.
    fn readdir(&mut self, count: i32) -> io::Result<Vec<Box<dyn iofs::FileInfo>>>;
    fn stat(&self) -> io::Result<Box<dyn iofs::FileInfo>>;
    /// Go's `f.(fs.ReadDirFile)` assertion.
    fn as_read_dir_file(&mut self) -> Option<&mut dyn iofs::ReadDirFile> {
        None
    }
}

/// Go's `http.FileSystem`.
pub trait FileSystem: Send + Sync {
    fn open(&self, name: &str) -> io::Result<Box<dyn File>>;
}

/// Go's `http.Dir`: a [`FileSystem`] over a directory of the native file
/// system. An empty string means the current directory.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Dir(pub String);

const ERR_INVALID_UNSAFE_PATH: ErrorString = ErrorString("http: invalid or unsafe file path");

fn not_exist() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "file does not exist")
}

/// Go's `mapOpenError`.
fn map_open_error(
    original: io::Error,
    name: &str,
    sep: char,
    stat: &dyn Fn(&str) -> io::Result<Box<dyn iofs::FileInfo>>,
) -> io::Error {
    if matches!(
        original.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
    ) {
        return original;
    }
    let parts: Vec<&str> = name.split(sep).collect();
    for i in 0..parts.len() {
        if parts[i].is_empty() {
            continue;
        }
        match stat(&parts[..=i].join(&sep.to_string())) {
            Err(_) => return original,
            Ok(fi) => {
                if !fi.is_dir() {
                    return not_exist();
                }
            }
        }
    }
    original
}

impl FileSystem for Dir {
    fn open(&self, name: &str) -> io::Result<Box<dyn File>> {
        let cleaned = crate::path::clean(&format!("/{name}"));
        let mut path = cleaned[1..].to_owned();
        if path.is_empty() {
            path = ".".into();
        }
        // filepath.Localize: reject elements the host cannot represent.
        if path.contains('\0') || (cfg!(windows) && (path.contains('\\') || path.contains(':'))) {
            return Err(super::header::io_error(ERR_INVALID_UNSAFE_PATH));
        }
        let dir = if self.0.is_empty() { "." } else { &self.0 };
        let full = if path == "." {
            dir.to_owned()
        } else {
            format!("{}/{}", dir.trim_end_matches('/'), path)
        };
        // Go joins the cleaned path onto Dir and opens it with the OS, so
        // symbolic links inside the tree are followed.
        let base = iofs_root(&full);
        match iofs::DirFS::new(base.0).open(&base.1) {
            Ok(f) => Ok(Box::new(FsFile(f))),
            Err(e) => Err(map_open_error(e, &full, '/', &|p: &str| {
                let (root, name) = iofs_root(p);
                iofs::stat(&iofs::DirFS::new(root), &name)
            })),
        }
    }
}

/// Splits `full` into the `DirFS` root and an `fs.ValidPath` name.
fn iofs_root(full: &str) -> (String, String) {
    if let Some(i) = full.rfind('/') {
        let root = if i == 0 { "/" } else { &full[..i] };
        let name = &full[i + 1..];
        if name.is_empty() {
            (full.to_owned(), ".".to_owned())
        } else {
            (root.to_owned(), name.to_owned())
        }
    } else {
        (".".to_owned(), full.to_owned())
    }
}

/// An [`iofs::File`] as an http [`File`] (Go's `ioFile`).
struct FsFile(Box<dyn iofs::File>);

impl Read for FsFile {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.0.read(b)
    }
}
impl Seek for FsFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match self.0.as_seek() {
            Some(s) => s.seek(pos),
            None => Err(io::Error::other("io.File missing Seek method")),
        }
    }
}
impl File for FsFile {
    fn close(&mut self) -> io::Result<()> {
        self.0.close()
    }
    fn stat(&self) -> io::Result<Box<dyn iofs::FileInfo>> {
        self.0.stat()
    }
    fn as_read_dir_file(&mut self) -> Option<&mut dyn iofs::ReadDirFile> {
        self.0.as_read_dir_file()
    }
    fn readdir(&mut self, count: i32) -> io::Result<Vec<Box<dyn iofs::FileInfo>>> {
        let Some(d) = self.0.as_read_dir_file() else {
            return Err(io::Error::other("io.File directory missing ReadDir method"));
        };
        let mut list: Vec<Box<dyn iofs::FileInfo>> = Vec::new();
        loop {
            let want = if count > 0 {
                count - list.len() as i32
            } else {
                count
            };
            let dirs = d.read_dir(want);
            let (entries, err) = match dirs {
                Ok(e) => (e, None),
                Err(e) => {
                    let (list, source) = e.into_parts();
                    (list, Some(source))
                }
            };
            for dir in entries {
                if let Ok(info) = dir.info() {
                    list.push(info);
                }
            }
            if let Some(e) = err {
                return if crate::io::is_eof(&e) && !list.is_empty() {
                    Ok(list)
                } else {
                    Err(e)
                };
            }
            if count <= 0 || list.len() as i32 >= count {
                break;
            }
        }
        Ok(list)
    }
}

/// Go's `http.FS`: adapts an [`iofs::FS`] to a [`FileSystem`].
pub fn fs_adapter(fsys: Arc<dyn iofs::FS + Send + Sync>) -> Arc<dyn FileSystem> {
    Arc::new(IoFs(fsys))
}
struct IoFs(Arc<dyn iofs::FS + Send + Sync>);
impl FileSystem for IoFs {
    fn open(&self, name: &str) -> io::Result<Box<dyn File>> {
        let name = if name == "/" {
            "."
        } else {
            name.strip_prefix('/').unwrap_or(name)
        };
        match self.0.open(name) {
            Ok(f) => Ok(Box::new(FsFile(f))),
            Err(e) => Err(map_open_error(e, name, '/', &|p: &str| {
                iofs::stat(&*self.0, p)
            })),
        }
    }
}

/// Go's `http.FileServer`.
pub fn file_server(root: Arc<dyn FileSystem>) -> Arc<dyn Handler> {
    Arc::new(FileHandler { root })
}

/// Go's `http.FileServerFS`.
pub fn file_server_fs(root: Arc<dyn iofs::FS + Send + Sync>) -> Arc<dyn Handler> {
    file_server(fs_adapter(root))
}

struct FileHandler {
    root: Arc<dyn FileSystem>,
}
impl Handler for FileHandler {
    fn serve_http(&self, w: &mut dyn ResponseWriter, r: &mut Request) {
        let mut upath = r.url.path.clone();
        if !upath.starts_with('/') {
            upath.insert(0, '/');
            r.url.path = upath.clone();
        }
        serve_file_impl(w, r, &*self.root, &crate::path::clean(&upath), true);
    }
}

fn log_req(r: &Request, args: std::fmt::Arguments<'_>) {
    match r.context().value(&SERVER_CONTEXT_KEY) {
        Some(s) => s.logf(args),
        None => crate::log::printf(args),
    }
}

fn dir_list(w: &mut dyn ResponseWriter, r: &Request, f: &mut dyn File) {
    let mut names: Vec<(String, bool)> = Vec::new();
    let res: io::Result<()> = if let Some(d) = f.as_read_dir_file() {
        d.read_dir(-1).map_err(io::Error::from).map(|list| {
            for e in list {
                names.push((e.name().to_owned(), e.is_dir()));
            }
        })
    } else {
        f.readdir(-1).map(|list| {
            for e in list {
                names.push((e.name().to_owned(), e.is_dir()));
            }
        })
    };
    if let Err(e) = res {
        log_req(r, format_args!("http: error reading directory: {e}"));
        error(w, "Error reading directory", STATUS_INTERNAL_SERVER_ERROR);
        return;
    }
    names.sort_by(|a, b| a.0.cmp(&b.0));
    w.header().set("Content-Type", "text/html; charset=utf-8");
    let _ = w.write(b"<!doctype html>\n");
    let _ = w.write(b"<meta name=\"viewport\" content=\"width=device-width\">\n");
    let _ = w.write(b"<pre>\n");
    for (mut name, is_dir) in names {
        if is_dir {
            name.push('/');
        }
        let u = Url {
            path: name.clone(),
            ..Url::default()
        };
        let _ = w.write(format!("<a href=\"{}\">{}</a>\n", u, html_escape(&name)).as_bytes());
    }
    let _ = w.write(b"</pre>\n");
}

fn serve_error(w: &mut dyn ResponseWriter, text: &str, code: u16) {
    let h = w.header();
    for k in ["Cache-Control", "Content-Encoding", "Etag", "Last-Modified"] {
        if h.0.contains_key(k) {
            h.0.remove(k);
        }
    }
    error(w, text, code);
}

/// A `Read + Seek` content source for [`serve_content`].
pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek + ?Sized> ReadSeek for T {}

/// Go's `http.ServeContent`.
pub fn serve_content(
    w: &mut dyn ResponseWriter,
    req: &Request,
    name: &str,
    modtime: &Time,
    content: &mut dyn ReadSeek,
) {
    let size_func = |c: &mut dyn ReadSeek| -> Result<i64, String> {
        let size = c
            .seek(SeekFrom::End(0))
            .map_err(|_| "seeker can't seek".to_owned())?;
        c.seek(SeekFrom::Start(0))
            .map_err(|_| "seeker can't seek".to_owned())?;
        Ok(size as i64)
    };
    serve_content_impl(w, req, name, modtime, &size_func, content);
}

const ERR_NO_OVERLAP: &str = "invalid range: failed to overlap";

#[derive(Clone, Copy, Debug)]
struct HttpRange {
    start: i64,
    length: i64,
}
impl HttpRange {
    fn content_range(&self, size: i64) -> String {
        format!(
            "bytes {}-{}/{}",
            self.start,
            self.start + self.length - 1,
            size
        )
    }
    fn mime_header(&self, content_type: &str, size: i64) -> MIMEHeader {
        let mut h = MIMEHeader::new();
        h.set("Content-Range", &self.content_range(size));
        h.set("Content-Type", content_type);
        h
    }
}

fn parse_range(s: &str, size: i64) -> Result<Vec<HttpRange>, String> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    const B: &str = "bytes=";
    if !s.starts_with(B) {
        return Err("invalid range".into());
    }
    let mut ranges = Vec::new();
    let mut no_overlap = false;
    for ra in s[B.len()..].split(',') {
        let ra = trim_string(ra);
        if ra.is_empty() {
            continue;
        }
        let Some((start, end)) = ra.split_once('-') else {
            return Err("invalid range".into());
        };
        let (start, end) = (trim_string(start), trim_string(end));
        let mut r = HttpRange {
            start: 0,
            length: 0,
        };
        if start.is_empty() {
            if end.is_empty() || end.starts_with('-') {
                return Err("invalid range".into());
            }
            let mut i = parse_i64(end).ok_or("invalid range")?;
            if i < 0 {
                return Err("invalid range".into());
            }
            if i > size {
                i = size;
            }
            r.start = size - i;
            r.length = size - r.start;
        } else {
            let i = parse_i64(start).ok_or("invalid range")?;
            if i < 0 {
                return Err("invalid range".into());
            }
            if i >= size {
                no_overlap = true;
                continue;
            }
            r.start = i;
            if end.is_empty() {
                r.length = size - r.start;
            } else {
                let mut i = parse_i64(end).ok_or("invalid range")?;
                if r.start > i {
                    return Err("invalid range".into());
                }
                if i >= size {
                    i = size - 1;
                }
                r.length = i - r.start + 1;
            }
        }
        ranges.push(r);
    }
    if no_overlap && ranges.is_empty() {
        return Err(ERR_NO_OVERLAP.into());
    }
    Ok(ranges)
}

/// `strconv.ParseInt(s, 10, 64)`.
fn parse_i64(s: &str) -> Option<i64> {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn sum_ranges_size(ranges: &[HttpRange]) -> i64 {
    ranges.iter().map(|r| r.length).sum()
}

struct CountingWriter(i64);
impl Write for CountingWriter {
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        self.0 += p.len() as i64;
        Ok(p.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn ranges_mime_size(
    ranges: &[HttpRange],
    content_type: &str,
    content_size: i64,
    boundary: &str,
) -> i64 {
    let mut cw = CountingWriter(0);
    let mut enc = 0;
    {
        let mut mw = crate::multipart::Writer::new(&mut cw);
        let _ = mw.set_boundary(boundary);
        for ra in ranges {
            let _ = mw.create_part(&ra.mime_header(content_type, content_size));
            enc += ra.length;
        }
        let _ = mw.close();
    }
    enc + cw.0
}

fn scan_etag(s: &str) -> (&str, &str) {
    let s = trim_string(s);
    let start = if s.starts_with("W/") { 2 } else { 0 };
    let b = s.as_bytes();
    if b.len() - start < 2 || b[start] != b'"' {
        return ("", "");
    }
    for i in start + 1..b.len() {
        let c = b[i];
        if c == 0x21 || (0x23..=0x7e).contains(&c) || c >= 0x80 {
            continue;
        }
        if c == b'"' {
            return (&s[..=i], &s[i + 1..]);
        }
        return ("", "");
    }
    ("", "")
}

fn etag_strong_match(a: &str, b: &str) -> bool {
    a == b && !a.is_empty() && a.starts_with('"')
}
fn etag_weak_match(a: &str, b: &str) -> bool {
    a.strip_prefix("W/").unwrap_or(a) == b.strip_prefix("W/").unwrap_or(b)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Cond {
    None,
    True,
    False,
}

fn check_if_match(w: &mut dyn ResponseWriter, r: &Request) -> Cond {
    let im = r.header.get_str("If-Match");
    if im.is_empty() {
        return Cond::None;
    }
    let mut im: &str = im;
    loop {
        im = trim_string(im);
        if im.is_empty() {
            break;
        }
        if im.starts_with(',') {
            im = &im[1..];
            continue;
        }
        if im.starts_with('*') {
            return Cond::True;
        }
        let (etag, remain) = scan_etag(im);
        if etag.is_empty() {
            break;
        }
        if etag_strong_match(etag, w.header().get_exact("Etag")) {
            return Cond::True;
        }
        im = remain;
    }
    Cond::False
}

fn check_if_unmodified_since(r: &Request, modtime: &Time) -> Cond {
    let ius = r.header.get_str("If-Unmodified-Since");
    if ius.is_empty() || is_zero_time(modtime) {
        return Cond::None;
    }
    let Ok(t) = parse_time(ius) else {
        return Cond::None;
    };
    let modtime = modtime.truncate(time::SECOND);
    if modtime.compare(&t) <= 0 {
        Cond::True
    } else {
        Cond::False
    }
}

fn check_if_none_match(w: &mut dyn ResponseWriter, r: &Request) -> Cond {
    let inm = r.header.get_exact("If-None-Match").to_owned();
    if inm.is_empty() {
        return Cond::None;
    }
    let mut buf: &str = &inm;
    loop {
        buf = trim_string(buf);
        if buf.is_empty() {
            break;
        }
        if buf.starts_with(',') {
            buf = &buf[1..];
            continue;
        }
        if buf.starts_with('*') {
            return Cond::False;
        }
        let (etag, remain) = scan_etag(buf);
        if etag.is_empty() {
            break;
        }
        if etag_weak_match(etag, w.header().get_exact("Etag")) {
            return Cond::False;
        }
        buf = remain;
    }
    Cond::True
}

fn check_if_modified_since(r: &Request, modtime: &Time) -> Cond {
    if r.method != "GET" && r.method != "HEAD" {
        return Cond::None;
    }
    let ims = r.header.get_str("If-Modified-Since");
    if ims.is_empty() || is_zero_time(modtime) {
        return Cond::None;
    }
    let Ok(t) = parse_time(ims) else {
        return Cond::None;
    };
    let modtime = modtime.truncate(time::SECOND);
    if modtime.compare(&t) <= 0 {
        Cond::False
    } else {
        Cond::True
    }
}

fn check_if_range(w: &mut dyn ResponseWriter, r: &Request, modtime: &Time) -> Cond {
    if r.method != "GET" && r.method != "HEAD" {
        return Cond::None;
    }
    let ir = r.header.get_exact("If-Range").to_owned();
    if ir.is_empty() {
        return Cond::None;
    }
    let (etag, _) = scan_etag(&ir);
    if !etag.is_empty() {
        return if etag_strong_match(etag, w.header().get_str("Etag")) {
            Cond::True
        } else {
            Cond::False
        };
    }
    if modtime.is_zero() {
        return Cond::False;
    }
    let Ok(t) = parse_time(&ir) else {
        return Cond::False;
    };
    if t.unix() == modtime.unix() {
        Cond::True
    } else {
        Cond::False
    }
}

fn is_zero_time(t: &Time) -> bool {
    t.is_zero() || t.equal(&time::unix(0, 0))
}

fn set_last_modified(w: &mut dyn ResponseWriter, modtime: &Time) {
    if !is_zero_time(modtime) {
        w.header()
            .set("Last-Modified", &modtime.utc().format(TIME_FORMAT));
    }
}

fn write_not_modified(w: &mut dyn ResponseWriter) {
    let h = w.header();
    h.0.remove("Content-Type");
    h.0.remove("Content-Length");
    h.0.remove("Content-Encoding");
    if !h.get_str("Etag").is_empty() {
        h.0.remove("Last-Modified");
    }
    w.write_header(STATUS_NOT_MODIFIED);
}

fn check_preconditions(w: &mut dyn ResponseWriter, r: &Request, modtime: &Time) -> (bool, String) {
    let mut ch = check_if_match(w, r);
    if ch == Cond::None {
        ch = check_if_unmodified_since(r, modtime);
    }
    if ch == Cond::False {
        w.write_header(STATUS_PRECONDITION_FAILED);
        return (true, String::new());
    }
    match check_if_none_match(w, r) {
        Cond::False => {
            if r.method == "GET" || r.method == "HEAD" {
                write_not_modified(w);
                return (true, String::new());
            }
            w.write_header(STATUS_PRECONDITION_FAILED);
            return (true, String::new());
        }
        Cond::None => {
            if check_if_modified_since(r, modtime) == Cond::False {
                write_not_modified(w);
                return (true, String::new());
            }
        }
        Cond::True => {}
    }
    let mut range_header = r.header.get_exact("Range").to_owned();
    if !range_header.is_empty() && check_if_range(w, r, modtime) == Cond::False {
        range_header.clear();
    }
    (false, range_header)
}

/// `filepath.Ext`.
fn file_ext(path: &str) -> &str {
    let mut i = path.len();
    while i > 0 && path.as_bytes()[i - 1] != b'/' {
        i -= 1;
        if path.as_bytes()[i] == b'.' {
            return &path[i..];
        }
    }
    ""
}

fn serve_content_impl(
    w: &mut dyn ResponseWriter,
    r: &Request,
    name: &str,
    modtime: &Time,
    size_func: &dyn Fn(&mut dyn ReadSeek) -> Result<i64, String>,
    content: &mut dyn ReadSeek,
) {
    set_last_modified(w, modtime);
    let (done, range_req) = check_preconditions(w, r, modtime);
    if done {
        return;
    }
    let mut code = STATUS_OK;
    let ctypes = w.header().0.get("Content-Type").cloned();
    let ctype: String = match ctypes {
        None => {
            let mut c = crate::mime::type_by_extension(file_ext(name)).unwrap_or_default();
            if c.is_empty() {
                let mut buf = vec![0u8; SNIFF_LEN];
                let n = read_full(content, &mut buf);
                c = detect_content_type(&buf[..n]).to_owned();
                if content.seek(SeekFrom::Start(0)).is_err() {
                    serve_error(w, "seeker can't seek", STATUS_INTERNAL_SERVER_ERROR);
                    return;
                }
            }
            w.header().set("Content-Type", &c);
            c
        }
        Some(v) => v.first().cloned().unwrap_or_default(),
    };
    let size = match size_func(content) {
        Ok(s) => s,
        Err(e) => {
            serve_error(w, &e, STATUS_INTERNAL_SERVER_ERROR);
            return;
        }
    };
    if size < 0 {
        serve_error(
            w,
            "negative content size computed",
            STATUS_INTERNAL_SERVER_ERROR,
        );
        return;
    }
    let mut send_size = size;
    let mut ranges = match parse_range(&range_req, size) {
        Ok(r) => r,
        Err(e) if e == ERR_NO_OVERLAP && size == 0 => Vec::new(),
        Err(e) => {
            if e == ERR_NO_OVERLAP {
                w.header().set("Content-Range", &format!("bytes */{size}"));
            }
            serve_error(w, &e, STATUS_REQUESTED_RANGE_NOT_SATISFIABLE);
            return;
        }
    };
    if sum_ranges_size(&ranges) > size {
        ranges.clear();
    }
    let mut multipart_boundary: Option<String> = None;
    if ranges.len() == 1 {
        let ra = ranges[0];
        if let Err(e) = content.seek(SeekFrom::Start(ra.start as u64)) {
            serve_error(w, &e.to_string(), STATUS_REQUESTED_RANGE_NOT_SATISFIABLE);
            return;
        }
        send_size = ra.length;
        code = STATUS_PARTIAL_CONTENT;
        w.header().set("Content-Range", &ra.content_range(size));
    } else if ranges.len() > 1 {
        // The boundary is random in Go too; byte-for-byte comparisons skip it.
        let boundary = crate::multipart::Writer::new(io::sink())
            .boundary()
            .to_owned();
        send_size = ranges_mime_size(&ranges, &ctype, size, &boundary);
        code = STATUS_PARTIAL_CONTENT;
        w.header().set(
            "Content-Type",
            &format!("multipart/byteranges; boundary={boundary}"),
        );
        multipart_boundary = Some(boundary);
    }
    w.header().set("Accept-Ranges", "bytes");
    if !ranges.is_empty() || w.header().get_str("Content-Encoding").is_empty() {
        w.header().set("Content-Length", &send_size.to_string());
    }
    w.write_header(code);
    if r.method != "HEAD" {
        match multipart_boundary {
            Some(boundary) => {
                let mut mw = crate::multipart::Writer::new(&mut *w);
                let _ = mw.set_boundary(&boundary);
                for ra in &ranges {
                    let Ok(mut part) = mw.create_part(&ra.mime_header(&ctype, size)) else {
                        return;
                    };
                    if content.seek(SeekFrom::Start(ra.start as u64)).is_err() {
                        return;
                    }
                    if copy_n(&mut part, content, ra.length).is_err() {
                        return;
                    }
                }
                let _ = mw.close();
            }
            None => {
                // Go's `io.CopyN(w, content, n)`, which reaches the server's
                // `ReadFrom`.
                let _ = w.copy_from(&mut content.take(send_size.max(0) as u64));
            }
        }
    }
}

/// `io.ReadFull` that reports how many bytes it got.
fn read_full(r: &mut dyn Read, buf: &mut [u8]) -> usize {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) | Err(_) => break,
            Ok(k) => n += k,
        }
    }
    n
}

/// `io.CopyN`.
fn copy_n(dst: &mut dyn Write, src: &mut dyn Read, n: i64) -> io::Result<()> {
    let mut buf = vec![0u8; 32 * 1024];
    let mut left = n;
    while left > 0 {
        let want = usize::try_from(left).unwrap_or(buf.len()).min(buf.len());
        let k = src.read(&mut buf[..want])?;
        if k == 0 {
            return Err(crate::io::eof());
        }
        dst.write_all(&buf[..k])?;
        left -= k as i64;
    }
    Ok(())
}

/// `&mut dyn File` as a plain `Read + Seek` (no trait upcasting before 1.86).
struct FileAsReadSeek<'a>(&'a mut dyn File);
impl Read for FileAsReadSeek<'_> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.0.read(b)
    }
}
impl Seek for FileAsReadSeek<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.0.seek(pos)
    }
}

fn serve_file_impl(
    w: &mut dyn ResponseWriter,
    r: &Request,
    fsys: &dyn FileSystem,
    name: &str,
    redirect: bool,
) {
    const INDEX_PAGE: &str = "/index.html";
    if r.url.path.ends_with(INDEX_PAGE) {
        local_redirect(w, r, "./");
        return;
    }
    let mut f = match fsys.open(name) {
        Ok(f) => f,
        Err(e) => {
            let (msg, code) = to_http_error(&e);
            serve_error(w, msg, code);
            return;
        }
    };
    serve_opened(w, r, fsys, name, redirect, &mut *f);
    let _ = f.close();
}

fn serve_opened(
    w: &mut dyn ResponseWriter,
    r: &Request,
    fsys: &dyn FileSystem,
    name: &str,
    redirect: bool,
    f: &mut dyn File,
) {
    const INDEX_PAGE: &str = "/index.html";
    let mut d = match f.stat() {
        Ok(d) => d,
        Err(e) => {
            let (msg, code) = to_http_error(&e);
            serve_error(w, msg, code);
            return;
        }
    };
    if redirect {
        let url = &r.url.path;
        if d.is_dir() {
            if !url.ends_with('/') {
                local_redirect(w, r, &format!("{}/", crate::path::base(url)));
                return;
            }
        } else if url.ends_with('/') {
            let base = crate::path::base(url);
            if base == "/" || base == "." {
                serve_error(
                    w,
                    "http: attempting to traverse a non-directory",
                    STATUS_INTERNAL_SERVER_ERROR,
                );
                return;
            }
            local_redirect(w, r, &format!("../{base}"));
            return;
        }
    }
    let mut index_file: Option<Box<dyn File>> = None;
    if d.is_dir() {
        let url = &r.url.path;
        if url.is_empty() || !url.ends_with('/') {
            local_redirect(w, r, &format!("{}/", crate::path::base(url)));
            return;
        }
        let index = format!("{}{INDEX_PAGE}", name.strip_suffix('/').unwrap_or(name));
        if let Ok(ff) = fsys.open(&index) {
            match ff.stat() {
                Ok(dd) => {
                    d = dd;
                    index_file = Some(ff);
                }
                Err(_) => {
                    let mut ff = ff;
                    let _ = ff.close();
                }
            }
        }
    }
    let file: &mut dyn File = match index_file.as_mut() {
        Some(ff) => &mut **ff,
        None => f,
    };
    if d.is_dir() {
        if check_if_modified_since(r, &d.mod_time()) == Cond::False {
            write_not_modified(w);
        } else {
            set_last_modified(w, &d.mod_time());
            dir_list(w, r, file);
        }
    } else {
        let size = d.size();
        let size_func = move |_: &mut dyn ReadSeek| Ok(size);
        serve_content_impl(
            w,
            r,
            d.name(),
            &d.mod_time(),
            &size_func,
            &mut FileAsReadSeek(file),
        );
    }
    if let Some(mut ff) = index_file {
        let _ = ff.close();
    }
}

fn to_http_error(err: &io::Error) -> (&'static str, u16) {
    match err.kind() {
        io::ErrorKind::NotFound => ("404 page not found", STATUS_NOT_FOUND),
        io::ErrorKind::PermissionDenied => ("403 Forbidden", STATUS_FORBIDDEN),
        _ => {
            if super::header::is_error(err, &ERR_INVALID_UNSAFE_PATH) {
                ("404 page not found", STATUS_NOT_FOUND)
            } else {
                ("500 Internal Server Error", STATUS_INTERNAL_SERVER_ERROR)
            }
        }
    }
}

fn local_redirect(w: &mut dyn ResponseWriter, r: &Request, new_path: &str) {
    let p = r.url.escaped_path();
    if p.contains("%2f") || p.contains("%2F") {
        let mut r2 = r.clone();
        not_found(w, &mut r2);
        return;
    }
    let mut new_path = new_path.to_owned();
    if !r.url.raw_query.is_empty() {
        new_path.push('?');
        new_path.push_str(&r.url.raw_query);
    }
    w.header().set("Location", &new_path);
    w.write_header(STATUS_MOVED_PERMANENTLY);
}

fn contains_dot_dot(v: &str) -> bool {
    if !v.contains("..") {
        return false;
    }
    v.split(['/', '\\']).any(|e| e == "..")
}

/// Go's `http.ServeFile`.
pub fn serve_file(w: &mut dyn ResponseWriter, r: &Request, name: &str) {
    if contains_dot_dot(&r.url.path) {
        serve_error(w, "invalid URL path", STATUS_BAD_REQUEST);
        return;
    }
    let (dir, file) = match name.rfind('/') {
        Some(i) => (&name[..=i], &name[i + 1..]),
        None => ("", name),
    };
    serve_file_impl(w, r, &Dir(dir.to_owned()), file, false);
}

/// Go's `http.ServeFileFS`.
pub fn serve_file_fs(
    w: &mut dyn ResponseWriter,
    r: &Request,
    fsys: Arc<dyn iofs::FS + Send + Sync>,
    name: &str,
) {
    if contains_dot_dot(&r.url.path) {
        serve_error(w, "invalid URL path", STATUS_BAD_REQUEST);
        return;
    }
    serve_file_impl(w, r, &IoFs(fsys), name, false);
}

#[allow(dead_code)]
fn _unused(_: BoxError) {
    let _ = status_text;
}
