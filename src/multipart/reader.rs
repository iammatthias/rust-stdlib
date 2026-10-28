//! Go's `multipart.Reader` and `Part`: a port of `mime/multipart/multipart.go`.
//!
//! Framing follows Go exactly, including its leniency: lines may end in `\n`
//! (decided by the first boundary line), a part need not have a
//! `Content-Disposition`, header lines may be folded, and
//! `Content-Transfer-Encoding: quoted-printable` is decoded by
//! [`Reader::next_part`] and left alone by [`Reader::next_raw_part`]. The
//! reader keeps Go's 4096-byte look-ahead buffer, so Go's behaviour at its
//! edges (a preamble line longer than the buffer, a boundary split across
//! reads) is the same.
//!
//! A [`Part`] streams its part's body from the underlying reader
//! (Go's `Part` is an `io.Reader` over the same stream), so a large upload is
//! never buffered. It borrows the [`Reader`]: asking for the next part
//! discards what is left of the current one, as Go's `NextPart` does. A read
//! error in the middle of a body is returned by `Read` once the bytes before
//! it are consumed. [`Part::into_owned`] is the buffered form.
//!
//! [`Reader::into_next_part`] gives an [`OwnedPartReader`] instead: the part
//! owns the reader, so it is `'static` and can be a thread's input or an HTTP
//! request body, and [`OwnedPartReader::into_reader`] returns the reader for
//! the next part.
//!
//! An error of the underlying reader reaches the caller as the original
//! [`io::Error`], so `get_ref().downcast_ref` finds its inner error the first
//! time it is reported (later reports carry its kind and text, since an
//! `io::Error` cannot be cloned). [`Reader::next_part`] wraps it as Go's
//! `NextPart: %w` does: it is the `source` of the returned error.
use super::ERR_MESSAGE_TOO_LARGE;
use crate::mime;
use crate::net::textproto::{self, MIMEHeader};
use crate::quotedprintable;
use crate::strconv::quote;
use std::collections::BTreeMap;
use std::io::{self, BufRead, Read};
use std::sync::{Arc, Mutex};

/// Go's `peekBufferSize`.
const PEEK_BUFFER_SIZE: usize = 4096;
/// Go's `maxMIMEHeaderSize`.
pub(super) const MAX_MIME_HEADER_SIZE: i64 = 10 << 20;
/// Go's default `maxMIMEHeaders`.
const MAX_MIME_HEADERS: i64 = 10000;

/// Go's `maxMIMEHeaders`: the default, or `GODEBUG=multipartmaxheaders` when
/// it is a non-negative integer.
pub(super) fn max_mime_headers() -> i64 {
    crate::archive::iofs::godebug("multipartmaxheaders")
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|v| *v >= 0)
        .unwrap_or(MAX_MIME_HEADERS)
}

/// A sticky error of the underlying reader. Go hands the same error value to
/// every later read; an [`io::Error`] cannot be cloned, so the first delivery
/// carries the original (and its inner error, for `downcast_ref`) and later
/// ones carry its kind and text.
#[derive(Clone, Debug)]
struct SharedErr {
    kind: io::ErrorKind,
    text: String,
    original: Arc<Mutex<Option<io::Error>>>,
}

impl SharedErr {
    fn new(err: io::Error) -> Self {
        SharedErr {
            kind: err.kind(),
            text: err.to_string(),
            original: Arc::new(Mutex::new(Some(err))),
        }
    }

    fn take(&self) -> Option<io::Error> {
        self.original
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }
}

/// `multipart: NextPart: <err>`: Go's `%w` wrapping, reachable through
/// [`std::error::Error::source`].
#[derive(Debug)]
struct NextPartError {
    text: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl std::fmt::Display for NextPartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "multipart: NextPart: {}", self.text)
    }
}

impl std::error::Error for NextPartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|e| e as _)
    }
}

/// A sticky error of the underlying reader, or one of the `bufio`/`io`
/// sentinels the parser reacts to.
#[derive(Clone, Debug)]
enum ReadErr {
    Eof,
    UnexpectedEof,
    BufferFull,
    Other(SharedErr),
}

impl ReadErr {
    fn into_io(self) -> io::Error {
        match self {
            ReadErr::Eof => io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"),
            ReadErr::UnexpectedEof => {
                io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")
            }
            ReadErr::BufferFull => io::Error::other("bufio: buffer full"),
            ReadErr::Other(e) => e.take().unwrap_or_else(|| io::Error::new(e.kind, e.text)),
        }
    }

    /// Like `into_io` without handing out the original error, for reads
    /// whose result is discarded.
    fn into_io_lossy(self) -> io::Error {
        match self {
            ReadErr::Other(e) => io::Error::new(e.kind, e.text),
            other => other.into_io(),
        }
    }

    /// `multipart: NextPart: <err>`, keeping the original error as `source`.
    fn into_next_part(self) -> io::Error {
        let (kind, source) = match &self {
            ReadErr::Eof | ReadErr::UnexpectedEof => (io::ErrorKind::UnexpectedEof, None),
            ReadErr::BufferFull => (io::ErrorKind::InvalidData, None),
            ReadErr::Other(e) => (
                e.kind,
                e.take().map(|err| {
                    if err.get_ref().is_some() {
                        err.into_inner().expect("checked above")
                    } else {
                        Box::new(err) as _
                    }
                }),
            ),
        };
        let text = self.text();
        io::Error::new(kind, NextPartError { text, source })
    }

    fn text(&self) -> String {
        match self {
            ReadErr::Eof => "EOF".into(),
            ReadErr::UnexpectedEof => "unexpected EOF".into(),
            ReadErr::BufferFull => "bufio: buffer full".into(),
            ReadErr::Other(e) => e.text.clone(),
        }
    }
}

fn parse_error(text: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, text)
}

/// The parts of Go's `bufio.Reader` (4096 bytes) that the parser uses, over a
/// reader whose first error is sticky (`stickyErrorReader`).
struct PeekBuf<R> {
    rd: R,
    buf: Box<[u8]>,
    r: usize,
    w: usize,
    err: Option<ReadErr>,
    sticky: Option<ReadErr>,
}

impl<R: Read> PeekBuf<R> {
    fn new(rd: R) -> Self {
        PeekBuf {
            rd,
            buf: vec![0; PEEK_BUFFER_SIZE].into_boxed_slice(),
            r: 0,
            w: 0,
            err: None,
            sticky: None,
        }
    }

    /// Go's `fill`: slide the data down and read once more.
    fn fill(&mut self) {
        if self.r > 0 {
            self.buf.copy_within(self.r..self.w, 0);
            self.w -= self.r;
            self.r = 0;
        }
        assert!(self.w < self.buf.len(), "bufio: tried to fill full buffer");
        if let Some(e) = &self.sticky {
            self.err = Some(e.clone());
            return;
        }
        loop {
            match self.rd.read(&mut self.buf[self.w..]) {
                Ok(0) => {
                    self.sticky = Some(ReadErr::Eof);
                    self.err = Some(ReadErr::Eof);
                    return;
                }
                Ok(n) => {
                    self.w += n;
                    return;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    let err = ReadErr::Other(SharedErr::new(e));
                    self.sticky = Some(err.clone());
                    self.err = Some(err);
                    return;
                }
            }
        }
    }

    fn read_err(&mut self) -> Option<ReadErr> {
        self.err.take()
    }

    fn buffered(&self) -> usize {
        self.w - self.r
    }

    fn data(&self) -> &[u8] {
        &self.buf[self.r..self.w]
    }

    /// Go's `Peek(n)`, returning only its error.
    fn peek(&mut self, n: usize) -> Option<ReadErr> {
        while self.w - self.r < n && self.w - self.r < self.buf.len() && self.err.is_none() {
            self.fill();
        }
        if n > self.buf.len() {
            return Some(ReadErr::BufferFull);
        }
        if self.w - self.r < n {
            return Some(self.read_err().unwrap_or(ReadErr::BufferFull));
        }
        None
    }

    /// Go's `ReadSlice('\n')`: the line (with its newline) and any error.
    fn read_line(&mut self) -> (Vec<u8>, Option<ReadErr>) {
        let mut s = 0;
        loop {
            if let Some(i) = self.buf[self.r + s..self.w]
                .iter()
                .position(|&b| b == b'\n')
            {
                let end = self.r + s + i + 1;
                let line = self.buf[self.r..end].to_vec();
                self.r = end;
                return (line, None);
            }
            if self.err.is_some() {
                let line = self.buf[self.r..self.w].to_vec();
                self.r = self.w;
                return (line, self.read_err());
            }
            if self.buffered() >= self.buf.len() {
                let line = self.buf.to_vec();
                self.r = self.w;
                return (line, Some(ReadErr::BufferFull));
            }
            s = self.w - self.r;
            self.fill();
        }
    }
}

impl<R: Read> Read for PeekBuf<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let n = available.len().min(out.len());
        out[..n].copy_from_slice(&available[..n]);
        self.consume(n);
        Ok(n)
    }
}

impl<R: Read> BufRead for PeekBuf<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.r == self.w {
            self.fill();
            if self.r == self.w {
                return match self.err.take() {
                    Some(ReadErr::Eof) | None => Ok(&[]),
                    Some(other) => Err(other.into_io()),
                };
            }
        }
        Ok(&self.buf[self.r..self.w])
    }

    fn consume(&mut self, amt: usize) {
        self.r = (self.r + amt).min(self.w);
    }
}

/// Go's `matchAfterPrefix`.
fn match_after_prefix(buf: &[u8], prefix: &[u8], read_err: bool) -> i32 {
    if buf.len() == prefix.len() {
        return if read_err { 1 } else { 0 };
    }
    let c = buf[prefix.len()];
    if matches!(c, b' ' | b'\t' | b'\r' | b'\n') {
        return 1;
    }
    if c == b'-' {
        if buf.len() == prefix.len() + 1 {
            return if read_err { -1 } else { 0 };
        }
        if buf[prefix.len() + 1] == b'-' {
            return 1;
        }
    }
    -1
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Go's `scanUntilBoundary`: how much of `buf` is body, and the error to
/// return after it (`Some(Eof)` marks the end of the part).
fn scan_until_boundary(
    buf: &[u8],
    dash_boundary: &[u8],
    nl_dash_boundary: &[u8],
    total: i64,
    read_err: &Option<ReadErr>,
) -> (usize, Option<ReadErr>) {
    if total == 0 {
        if buf.starts_with(dash_boundary) {
            match match_after_prefix(buf, dash_boundary, read_err.is_some()) {
                -1 => return (dash_boundary.len(), None),
                0 => return (0, None),
                _ => return (0, Some(ReadErr::Eof)),
            }
        }
        if dash_boundary.starts_with(buf) {
            return (0, read_err.clone());
        }
    }
    if let Some(i) = find(buf, nl_dash_boundary) {
        match match_after_prefix(&buf[i..], nl_dash_boundary, read_err.is_some()) {
            -1 => return (i + nl_dash_boundary.len(), None),
            0 => return (i, None),
            _ => return (i, Some(ReadErr::Eof)),
        }
    }
    if nl_dash_boundary.starts_with(buf) {
        return (0, read_err.clone());
    }
    if let Some(i) = buf.iter().rposition(|&b| b == nl_dash_boundary[0]) {
        if nl_dash_boundary.starts_with(&buf[i..]) {
            return (i, None);
        }
    }
    (buf.len(), read_err.clone())
}

/// A part with its body read into memory: the buffered form of a
/// [`Part`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedPart {
    /// The headers, with canonical keys (Go's `Part.Header`).
    pub header: MIMEHeader,
    /// The body: with `Content-Transfer-Encoding: quoted-printable` it is the
    /// decoded text.
    pub body: Vec<u8>,
}

impl OwnedPart {
    /// The `name` of a form-data disposition, or "" (Go's `Part.FormName`).
    pub fn form_name(&self) -> String {
        form_name(&self.header)
    }

    /// The base name of the disposition's `filename`, or "" (Go's `Part.FileName`).
    pub fn file_name(&self) -> String {
        file_name(&self.header)
    }
}

/// Go's `ParseMediaType` of the Content-Disposition header. A parse error
/// gives `None`, which Go also reports as empty names.
fn disposition(header: &MIMEHeader) -> Option<(String, BTreeMap<String, String>)> {
    let raw = header.get("Content-Disposition").unwrap_or("");
    let (kind, params) = mime::parse_media_type(raw);
    Some((kind, params.ok()?))
}

fn form_name(header: &MIMEHeader) -> String {
    match disposition(header) {
        Some((kind, params)) if kind == "form-data" => {
            params.get("name").cloned().unwrap_or_default()
        }
        _ => String::new(),
    }
}

fn file_name(header: &MIMEHeader) -> String {
    match disposition(header).and_then(|(_, mut params)| params.remove("filename")) {
        Some(filename) if !filename.is_empty() => base_name(&filename).to_owned(),
        _ => String::new(),
    }
}

/// Go's `partReader` state for the part being read.
#[derive(Default)]
struct PartState {
    /// Bytes of the buffer that belong to the body.
    n: usize,
    /// The error to return after those bytes (`Eof` ends the part).
    err: Option<ReadErr>,
    /// Body bytes returned so far.
    total: i64,
    /// A read error of the underlying reader seen while looking ahead.
    read_err: Option<ReadErr>,
    /// The part is read through a quoted-printable decoder, so discarding
    /// its rest goes through one too (Go's `Part.Close`).
    quoted_printable: bool,
}

/// The raw body of the reader's current part (Go's `partReader`). A `quiet`
/// body is being discarded, so it does not hand out the original error of
/// the underlying reader: the next read of the stream reports it.
struct RawBody<'a, R> {
    reader: &'a mut Reader<R>,
    quiet: bool,
}

impl<'a, R> RawBody<'a, R> {
    fn new(reader: &'a mut Reader<R>) -> Self {
        RawBody {
            reader,
            quiet: false,
        }
    }

    fn quiet(reader: &'a mut Reader<R>) -> Self {
        RawBody {
            reader,
            quiet: true,
        }
    }
}

impl<R: Read> Read for RawBody<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read_body(buf, self.quiet)
    }
}

/// The raw body of a part that owns its [`Reader`].
struct OwnedRawBody<R>(Reader<R>);

impl<R: Read> Read for OwnedRawBody<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read_body(buf, false)
    }
}

enum Body<B> {
    Raw(B),
    QuotedPrintable(quotedprintable::Reader<B>),
}

impl<B: Read> Read for Body<B> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Body::Raw(r) => r.read(buf),
            Body::QuotedPrintable(r) => r.read(buf),
        }
    }
}

/// One part of a multipart body (Go's `multipart.Part`): its headers and an
/// [`io::Read`] over its body, borrowing the [`Reader`] it came from.
pub struct Part<'a, R> {
    /// The headers, with canonical keys (Go's `Part.Header`). A
    /// `Content-Transfer-Encoding: quoted-printable` header is removed by
    /// [`Reader::next_part`].
    pub header: MIMEHeader,
    body: Body<RawBody<'a, R>>,
}

impl<R> std::fmt::Debug for Part<'_, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Part")
            .field("header", &self.header)
            .finish_non_exhaustive()
    }
}

impl<R: Read> Part<'_, R> {
    /// The `name` of a form-data disposition, or "" (Go's `Part.FormName`).
    pub fn form_name(&self) -> String {
        form_name(&self.header)
    }

    /// The base name of the disposition's `filename`, or "" (Go's `Part.FileName`).
    pub fn file_name(&self) -> String {
        file_name(&self.header)
    }

    /// Discards the rest of the body (Go's `Part.Close`).
    pub fn close(&mut self) -> io::Result<()> {
        let _ = io::copy(self, &mut io::sink());
        Ok(())
    }

    /// Reads the rest of the body into memory.
    pub fn into_owned(mut self) -> io::Result<OwnedPart> {
        let mut body = Vec::new();
        self.read_to_end(&mut body)?;
        Ok(OwnedPart {
            header: self.header,
            body,
        })
    }
}

impl<R: Read> Read for Part<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.body.read(buf)
    }
}

/// One part of a multipart body that owns its [`Reader`] (see
/// [`Reader::into_next_part`]): its headers and an [`io::Read`] over its
/// body. It is `'static` and `Send` when `R` is, so it can be handed to a
/// thread or to an HTTP request body. [`OwnedPartReader::into_reader`] gives
/// the [`Reader`] back to continue with the next part.
pub struct OwnedPartReader<R> {
    /// The headers, with canonical keys (Go's `Part.Header`). A
    /// `Content-Transfer-Encoding: quoted-printable` header is removed by
    /// [`Reader::into_next_part`].
    pub header: MIMEHeader,
    body: Body<OwnedRawBody<R>>,
}

impl<R> std::fmt::Debug for OwnedPartReader<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedPartReader")
            .field("header", &self.header)
            .finish_non_exhaustive()
    }
}

impl<R: Read> OwnedPartReader<R> {
    /// The `name` of a form-data disposition, or "" (Go's `Part.FormName`).
    pub fn form_name(&self) -> String {
        form_name(&self.header)
    }

    /// The base name of the disposition's `filename`, or "" (Go's `Part.FileName`).
    pub fn file_name(&self) -> String {
        file_name(&self.header)
    }

    /// Returns the [`Reader`], to ask for the next part. What is left of this
    /// part's body is discarded by that call.
    pub fn into_reader(self) -> Reader<R> {
        match self.body {
            Body::Raw(raw) => raw.0,
            Body::QuotedPrintable(decoder) => decoder.into_inner().0,
        }
    }
}

impl<R: Read> Read for OwnedPartReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.body.read(buf)
    }
}

/// Go's `filepath.Base` for slash-separated names.
fn base_name(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/";
    }
    trimmed.rsplit('/').next().unwrap_or(trimmed)
}

/// The parts of a MIME multipart body (Go's `multipart.Reader`), read one at
/// a time with [`Reader::next_part`].
pub struct Reader<R> {
    br: PeekBuf<R>,
    /// The part being read, once its headers are parsed (Go's `currentPart`).
    current: Option<PartState>,
    parts_read: usize,
    nl: Vec<u8>,
    nl_dash_boundary: Vec<u8>,
    dash_boundary_dash: Vec<u8>,
    dash_boundary: Vec<u8>,
}

impl<R: Read> Reader<R> {
    /// Go's `NewReader`: reads `reader` with the given MIME boundary.
    pub fn new(reader: R, boundary: &str) -> Self {
        let b = format!("\r\n--{boundary}--").into_bytes();
        Reader {
            br: PeekBuf::new(reader),
            current: None,
            parts_read: 0,
            nl: b[..2].to_vec(),
            nl_dash_boundary: b[..b.len() - 2].to_vec(),
            dash_boundary_dash: b[2..].to_vec(),
            dash_boundary: b[2..b.len() - 2].to_vec(),
        }
    }

    /// Go's `NextPart`: the next part, or `None` at the end. A
    /// `Content-Transfer-Encoding: quoted-printable` header is hidden and the
    /// body decoded.
    pub fn next_part(&mut self) -> io::Result<Option<Part<'_, R>>> {
        self.next_part_with(false, MAX_MIME_HEADER_SIZE, max_mime_headers())
    }

    /// Go's `NextRawPart`: like [`Reader::next_part`] without the
    /// quoted-printable handling.
    pub fn next_raw_part(&mut self) -> io::Result<Option<Part<'_, R>>> {
        self.next_part_with(true, MAX_MIME_HEADER_SIZE, max_mime_headers())
    }

    /// Go's `nextPart`.
    pub(super) fn next_part_with(
        &mut self,
        raw_part: bool,
        max_header_size: i64,
        max_headers: i64,
    ) -> io::Result<Option<Part<'_, R>>> {
        let Some((header, quoted_printable)) =
            self.advance(raw_part, max_header_size, max_headers)?
        else {
            return Ok(None);
        };
        let raw = RawBody::new(self);
        let body = if quoted_printable {
            Body::QuotedPrintable(quotedprintable::Reader::new(raw))
        } else {
            Body::Raw(raw)
        };
        Ok(Some(Part { header, body }))
    }

    /// Like [`Reader::next_part`], but the part owns the reader, so it is
    /// `'static` and can outlive the caller's stack frame. At the end of the
    /// parts, or on an error, the reader is dropped.
    pub fn into_next_part(self) -> io::Result<Option<OwnedPartReader<R>>> {
        self.into_part(false)
    }

    /// Like [`Reader::next_raw_part`], with an owning part.
    pub fn into_next_raw_part(self) -> io::Result<Option<OwnedPartReader<R>>> {
        self.into_part(true)
    }

    fn into_part(mut self, raw_part: bool) -> io::Result<Option<OwnedPartReader<R>>> {
        let Some((header, quoted_printable)) =
            self.advance(raw_part, MAX_MIME_HEADER_SIZE, max_mime_headers())?
        else {
            return Ok(None);
        };
        let raw = OwnedRawBody(self);
        let body = if quoted_printable {
            Body::QuotedPrintable(quotedprintable::Reader::new(raw))
        } else {
            Body::Raw(raw)
        };
        Ok(Some(OwnedPartReader { header, body }))
    }

    /// Go's `nextPart` up to the part's headers: the headers and whether the
    /// body is quoted-printable.
    fn advance(
        &mut self,
        raw_part: bool,
        max_header_size: i64,
        max_headers: i64,
    ) -> io::Result<Option<(MIMEHeader, bool)>> {
        if self.dash_boundary == b"--" {
            return Err(parse_error("multipart: boundary is empty".into()));
        }
        // The rest of the current part is discarded; its errors resurface in
        // the line read below, since the underlying error is sticky.
        if let Some(state) = &self.current {
            if state.quoted_printable {
                let mut decoder = quotedprintable::Reader::new(RawBody::quiet(&mut *self));
                let _ = io::copy(&mut decoder, &mut io::sink());
            } else {
                let _ = io::copy(&mut RawBody::quiet(&mut *self), &mut io::sink());
            }
            self.current = None;
        }
        let mut expect_new_part = false;
        loop {
            let (line, err) = self.br.read_line();
            if matches!(err, Some(ReadErr::Eof)) && self.is_final_boundary(&line) {
                return Ok(None);
            }
            if let Some(err) = err {
                return Err(err.into_next_part());
            }
            if self.is_boundary_delimiter_line(&line) {
                self.parts_read += 1;
                return self.new_part(raw_part, max_header_size, max_headers);
            }
            if self.is_final_boundary(&line) {
                return Ok(None);
            }
            if expect_new_part {
                return Err(parse_error(format!(
                    "multipart: expecting a new Part; got line {}",
                    quote(&line)
                )));
            }
            if self.parts_read == 0 {
                continue;
            }
            if line == self.nl {
                expect_new_part = true;
                continue;
            }
            return Err(parse_error(format!(
                "multipart: unexpected line in Next(): {}",
                quote(&line)
            )));
        }
    }

    /// Go's `newPart`.
    fn new_part(
        &mut self,
        raw_part: bool,
        max_header_size: i64,
        max_headers: i64,
    ) -> io::Result<Option<(MIMEHeader, bool)>> {
        let header = {
            let mut tp = textproto::Reader::new(&mut self.br);
            tp.read_mime_header_limited(max_header_size, max_headers)
        };
        let mut header = match header {
            Ok(header) => header,
            // Go returns io.EOF here, which NextPart callers see as the end.
            Err(textproto::Error::Eof) => return Ok(None),
            Err(textproto::Error::MessageTooLarge) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    ERR_MESSAGE_TOO_LARGE,
                ))
            }
            Err(textproto::Error::Io(e)) => return Err(e),
            Err(other) => return Err(parse_error(other.to_string())),
        };
        self.current = Some(PartState::default());
        let mut quoted_printable = false;
        if !raw_part {
            const CTE: &str = "Content-Transfer-Encoding";
            if header
                .get(CTE)
                .is_some_and(|v| v.eq_ignore_ascii_case("quoted-printable"))
            {
                header.del(CTE);
                quoted_printable = true;
            }
        }
        if let Some(state) = &mut self.current {
            state.quoted_printable = quoted_printable;
        }
        Ok(Some((header, quoted_printable)))
    }

    /// Go's `partReader.Read`. A `quiet` read does not hand out the original
    /// error of the underlying reader.
    fn read_body(&mut self, out: &mut [u8], quiet: bool) -> io::Result<usize> {
        let Reader {
            br,
            current,
            dash_boundary,
            nl_dash_boundary,
            ..
        } = self;
        let Some(st) = current.as_mut() else {
            return Ok(0);
        };
        // Read into the buffer until some data to return is identified, or
        // there is a reason to stop (boundary or read error).
        while st.n == 0 && st.err.is_none() {
            let (n, err) = scan_until_boundary(
                br.data(),
                dash_boundary,
                nl_dash_boundary,
                st.total,
                &st.read_err,
            );
            st.n = n;
            st.err = err;
            if st.n == 0 && st.err.is_none() {
                // Force buffered I/O to read more into the buffer.
                let have = br.buffered();
                st.read_err = br.peek(have + 1);
                if matches!(st.read_err, Some(ReadErr::Eof)) {
                    st.read_err = Some(ReadErr::UnexpectedEof);
                }
            }
        }
        if st.n == 0 {
            return match &st.err {
                Some(ReadErr::Eof) | None => Ok(0),
                Some(err) if quiet => Err(err.clone().into_io_lossy()),
                Some(err) => Err(err.clone().into_io()),
            };
        }
        let n = out.len().min(st.n);
        out[..n].copy_from_slice(&br.data()[..n]);
        br.consume(n);
        st.total += n as i64;
        st.n -= n;
        Ok(n)
    }

    /// Go's `isFinalBoundary`: `^--boundary--[ \t]*(\r\n)?$`.
    fn is_final_boundary(&self, line: &[u8]) -> bool {
        if !line.starts_with(&self.dash_boundary_dash) {
            return false;
        }
        let rest = skip_lwsp(&line[self.dash_boundary_dash.len()..]);
        rest.is_empty() || rest == self.nl
    }

    /// Go's `isBoundaryDelimiterLine`.
    fn is_boundary_delimiter_line(&mut self, line: &[u8]) -> bool {
        if !line.starts_with(&self.dash_boundary) {
            return false;
        }
        let rest = skip_lwsp(&line[self.dash_boundary.len()..]);
        // On the first part, lines ending in \n instead of \r\n switch the
        // reader into that mode.
        if self.parts_read == 0 && rest == b"\n" {
            self.nl.remove(0);
            self.nl_dash_boundary.remove(0);
        }
        rest == self.nl
    }
}

fn skip_lwsp(mut b: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = b {
        b = rest;
    }
    b
}
