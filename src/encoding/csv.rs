//! Go's `encoding/csv`: records of fields with Go's quoting, line endings,
//! comments, leading-space trimming, lazy quotes, field-count checks and error
//! positions. The reader is a port of Go's line-based `readLine` and
//! `readRecord`, and the writer of `Writer.Write`. `Reader::read_raw` is Go's
//! `Read`: byte fields, and the record returned together with the error.
//! `Reader::read` is the `String`, `Result` form. `Limits` are opt-in byte,
//! field and record budgets, unlimited by default.
//! Reference: <https://pkg.go.dev/encoding/csv>
use std::{
    error, fmt,
    io::{self, BufRead, BufReader, BufWriter, Read, Write},
};

/// Go's exported sentinel errors, compared by value like `errors.Is`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SentinelError(&'static str);
impl fmt::Display for SentinelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl error::Error for SentinelError {}

pub const ERR_BARE_QUOTE: SentinelError = SentinelError("bare \" in non-quoted-field");
pub const ERR_QUOTE: SentinelError = SentinelError("extraneous or missing \" in quoted-field");
pub const ERR_FIELD_COUNT: SentinelError = SentinelError("wrong number of fields");
pub const ERR_TRAILING_COMMA: SentinelError = SentinelError("extra delimiter at end of line");

/// Go's `ParseError`. `column` is a 1-based byte index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseError {
    pub start_line: usize,
    pub line: usize,
    pub column: usize,
    pub err: SentinelError,
}
impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.err == ERR_FIELD_COUNT {
            write!(f, "record on line {}: {}", self.line, self.err)
        } else if self.start_line != self.line {
            write!(
                f,
                "record on line {}; parse error on line {}, column {}: {}",
                self.start_line, self.line, self.column, self.err
            )
        } else {
            write!(
                f,
                "parse error on line {}, column {}: {}",
                self.line, self.column, self.err
            )
        }
    }
}
impl error::Error for ParseError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(&self.err)
    }
}

/// The error from `Reader::read`, Go's `error` value for the reader.
#[derive(Debug)]
pub enum Error {
    Parse(ParseError),
    /// Go's invalid field or comment delimiter error.
    InvalidDelimiter,
    /// An I/O error from the input, or a `Limits` budget.
    Io(io::Error),
    /// Go's `io.EOF`, returned only by [`Reader::read_raw`] and
    /// [`Reader::read_raw_into`] at the end of the input.
    Eof,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(e) => fmt::Display::fmt(e, f),
            Self::InvalidDelimiter => f.write_str("csv: invalid field or comment delimiter"),
            Self::Io(e) => fmt::Display::fmt(e, f),
            Self::Eof => f.write_str("EOF"),
        }
    }
}
impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Parse(e) => Some(e),
            Self::InvalidDelimiter | Self::Eof => None,
            Self::Io(e) => Some(e),
        }
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Go's delimiter rule: no NUL, quote, CR, LF or U+FFFD.
fn valid_delim(c: char) -> bool {
    !matches!(c, '\0' | '"' | '\r' | '\n' | '\u{FFFD}')
}

fn budget(message: &'static str) -> Error {
    Error::Io(io::Error::new(io::ErrorKind::InvalidData, message))
}

fn invalid_utf8() -> Error {
    Error::Io(io::Error::new(
        io::ErrorKind::InvalidData,
        "CSV invalid UTF-8",
    ))
}

/// Byte, field and record budgets. Go has none, so they are opt-in: the
/// default is unlimited.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_bytes: usize,
    pub max_record_bytes: usize,
    pub max_field_bytes: usize,
    pub max_fields: usize,
    pub max_records: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: usize::MAX,
            max_record_bytes: usize::MAX,
            max_field_bytes: usize::MAX,
            max_fields: usize::MAX,
            max_records: usize::MAX,
        }
    }
}

/// UTF-8 bytes of `c` and their length.
fn encode(c: char) -> ([u8; 4], usize) {
    let mut buf = [0; 4];
    let n = c.encode_utf8(&mut buf).len();
    (buf, n)
}

fn length_nl(b: &[u8]) -> usize {
    usize::from(b.last() == Some(&b'\n'))
}

/// Decodes the first character; invalid UTF-8 is U+FFFD with width 1, as in Go.
fn decode_char(s: &[u8]) -> (char, usize) {
    for n in 1..=s.len().min(4) {
        if let Ok(text) = std::str::from_utf8(&s[..n]) {
            if let Some(c) = text.chars().next() {
                return (c, n);
            }
        }
    }
    ('\u{FFFD}', 1)
}

fn first_non_space(s: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < s.len() {
        let (c, n) = decode_char(&s[i..]);
        if !c.is_whitespace() {
            return Some(i);
        }
        i += n;
    }
    None
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn starts_with_char(line: &[u8], c: char) -> bool {
    let (buf, n) = encode(c);
    line.starts_with(&buf[..n])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Position {
    line: usize,
    col: usize,
}

/// Go's `Reader`. Set the public fields before reading.
pub struct Reader<R: Read> {
    /// Go's `Comma`: the field delimiter.
    pub comma: char,
    /// Go's `Comment`: lines starting with it are skipped. `None` is Go's zero rune.
    pub comment: Option<char>,
    /// Go's `FieldsPerRecord`. Zero takes the first record's width; negative disables the check.
    pub fields_per_record: isize,
    /// Go's `LazyQuotes`: accept quotes that appear in unquoted fields or are not doubled.
    pub lazy_quotes: bool,
    /// Go's `TrimLeadingSpace`: ignore leading white space in each field.
    pub trim_leading_space: bool,
    /// Go's `ReuseRecord`. Go only permits sharing the previous record's storage;
    /// `read_raw` returns fresh records, and [`Reader::read_raw_into`] reuses the
    /// caller's. This flag has no further effect.
    pub reuse_record: bool,
    /// Go's deprecated `TrailingComma`. Go no longer uses it, so this has no effect.
    pub trailing_comma: bool,
    /// Rust budgets on input size. Go has none, so the default is unlimited.
    pub limits: Limits,
    r: BufReader<R>,
    num_line: usize,
    offset: u64,
    record_buffer: Vec<u8>,
    field_indexes: Vec<usize>,
    field_positions: Vec<Position>,
    records: usize,
    last_line_size: usize,
}

impl<R: Read> Reader<R> {
    /// Go's `NewReader`.
    pub fn new(r: R) -> Self {
        Self {
            comma: ',',
            comment: None,
            fields_per_record: 0,
            lazy_quotes: false,
            trim_leading_space: false,
            reuse_record: false,
            trailing_comma: false,
            limits: Limits::default(),
            r: BufReader::new(r),
            num_line: 0,
            offset: 0,
            record_buffer: Vec::new(),
            field_indexes: Vec::new(),
            field_positions: Vec::new(),
            records: 0,
            last_line_size: 0,
        }
    }

    /// Go's `Read` with fields as bytes, which is what Go's strings are: the
    /// record and the error come back together, as in Go. A field-count or
    /// parse error comes with the fields parsed before it, an I/O error with
    /// the partial record, and end of input is `Error::Eof` (Go's `io.EOF`)
    /// with no fields.
    pub fn read_raw(&mut self) -> (Vec<Vec<u8>>, Option<Error>) {
        let mut record = Vec::new();
        let err = self.read_raw_into(&mut record);
        (record, err)
    }

    /// [`Reader::read_raw`] reusing the storage of `record`, which is Go's
    /// `ReuseRecord`: the slice and its fields are overwritten rather than
    /// reallocated.
    pub fn read_raw_into(&mut self, record: &mut Vec<Vec<u8>>) -> Option<Error> {
        let err = match self.read_record() {
            Ok(err) => err,
            Err(e) => {
                record.clear();
                return Some(e);
            }
        };
        let count = self.field_indexes.len();
        record.truncate(count);
        record.resize_with(count, Vec::new);
        let mut start = 0;
        for (field, &end) in record.iter_mut().zip(&self.field_indexes) {
            field.clear();
            field.extend_from_slice(&self.record_buffer[start..end]);
            start = end;
        }
        if !matches!(err, Some(Error::Eof | Error::InvalidDelimiter)) {
            self.records += 1;
        }
        err
    }

    /// `Read` in Rust's `Result` shape with `String` fields. Returns `Ok(None)`
    /// at end of input, where Go returns `io.EOF`. An error is returned
    /// without its record ([`Reader::read_raw`] returns both), and a field
    /// that is not UTF-8 is an error.
    pub fn read(&mut self) -> Result<Option<Vec<String>>, Error> {
        let (record, err) = self.read_raw();
        match err {
            Some(Error::Eof) => return Ok(None),
            Some(e) => return Err(e),
            None => {}
        }
        record
            .into_iter()
            .map(|field| String::from_utf8(field).map_err(|_| invalid_utf8()))
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    }

    /// Go's `ReadAll` with fields as bytes: all records, or the first error
    /// (and no records), as Go does.
    pub fn read_all_raw(&mut self) -> Result<Vec<Vec<Vec<u8>>>, Error> {
        let mut records = Vec::new();
        loop {
            match self.read_raw() {
                (_, Some(Error::Eof)) => return Ok(records),
                (_, Some(e)) => return Err(e),
                (record, None) => records.push(record),
            }
        }
    }

    /// `ReadAll` with `String` fields: reads until end of input or the first error.
    pub fn read_all(&mut self) -> Result<Vec<Vec<String>>, Error> {
        let mut records = Vec::new();
        while let Some(record) = self.read()? {
            records.push(record);
        }
        Ok(records)
    }

    /// Go's `FieldPos`: the line and column where field `field` of the last
    /// record started. Panics when `field` is out of range, as Go does.
    pub fn field_pos(&self, field: usize) -> (usize, usize) {
        let p = self.field_positions[field];
        (p.line, p.col)
    }

    /// Go's `InputOffset`: bytes consumed so far.
    pub fn input_offset(&self) -> u64 {
        self.offset
    }

    /// Go's `readLine`: one line with CRLF folded to LF, and the read error
    /// (`Error::Eof` at end of input) that Go returns with it. The outer
    /// `Err` is a `Limits` budget.
    #[allow(clippy::type_complexity)]
    fn read_line(&mut self) -> Result<(Vec<u8>, Option<Error>), Error> {
        let mut line = Vec::new();
        let mut err = match self.r.read_until(b'\n', &mut line) {
            Ok(_) => None,
            Err(e) => Some(Error::Io(e)),
        };
        let size = line.len();
        if err.is_none() && size == 0 {
            err = Some(Error::Eof);
        }
        self.num_line += 1;
        self.last_line_size = size;
        if self.offset + size as u64 > self.limits.max_bytes as u64 {
            return Err(budget("CSV input byte limit"));
        }
        // A final line without a newline drops a trailing CR, as Go does.
        if size > 0 && err.is_none() && line.last() == Some(&b'\r') {
            line.pop();
        }
        self.offset += size as u64;
        let n = line.len();
        if n >= 2 && line[n - 2] == b'\r' && line[n - 1] == b'\n' {
            line[n - 2] = b'\n';
            line.pop();
        }
        Ok((line, err))
    }

    /// Records a field that ends at the current end of `record_buffer`.
    fn end_field(&mut self, pos: Position) -> Result<(), Error> {
        let start = self.field_indexes.last().copied().unwrap_or(0);
        if self.record_buffer.len() - start > self.limits.max_field_bytes {
            return Err(budget("CSV field byte limit"));
        }
        if self.field_indexes.len() >= self.limits.max_fields {
            return Err(budget("CSV field count limit"));
        }
        self.field_indexes.push(self.record_buffer.len());
        self.field_positions.push(pos);
        Ok(())
    }

    /// Go's `readRecord`, leaving the fields in `record_buffer` and
    /// `field_indexes`. Returns the error Go returns alongside the record
    /// (`Error::Eof` at end of input), or `Err` for a `Limits` budget, which
    /// has no record. Blank and comment lines are skipped.
    fn read_record(&mut self) -> Result<Option<Error>, Error> {
        self.record_buffer.clear();
        self.field_indexes.clear();
        self.field_positions.clear();
        if Some(self.comma) == self.comment
            || !valid_delim(self.comma)
            || self.comment.is_some_and(|c| !valid_delim(c))
        {
            return Ok(Some(Error::InvalidDelimiter));
        }
        let mut err_read = None;
        let mut line = Vec::new();
        while err_read.is_none() {
            (line, err_read) = self.read_line()?;
            if self.comment.is_some_and(|c| starts_with_char(&line, c)) {
                line = Vec::new();
                continue;
            }
            if err_read.is_none() && line.len() == length_nl(&line) {
                line = Vec::new();
                continue;
            }
            break;
        }
        if matches!(err_read, Some(Error::Eof)) {
            return Ok(err_read);
        }
        if self.records >= self.limits.max_records {
            return Err(budget("CSV record count limit"));
        }
        let rec_line = self.num_line;
        let record_start = self.offset - self.last_line_size as u64;
        if self.offset - record_start > self.limits.max_record_bytes as u64 {
            return Err(budget("CSV record byte limit"));
        }
        let mut pos = Position {
            line: self.num_line,
            col: 1,
        };
        let (comma_buf, comma_len) = encode(self.comma);
        let comma_bytes = &comma_buf[..comma_len];
        let mut err: Option<Error> = None;
        let mut at = 0;
        'fields: loop {
            if self.trim_leading_space {
                let rest = &line[at..];
                let i = match first_non_space(rest) {
                    Some(i) => i,
                    None => {
                        pos.col = pos.col.saturating_sub(length_nl(rest));
                        rest.len()
                    }
                };
                at += i;
                pos.col += i;
            }
            let rest = &line[at..];
            if rest.first() != Some(&b'"') {
                let i = find(rest, comma_bytes);
                let field = match i {
                    Some(i) => &rest[..i],
                    None => &rest[..rest.len() - length_nl(rest)],
                };
                if !self.lazy_quotes {
                    if let Some(j) = field.iter().position(|&b| b == b'"') {
                        err = Some(Error::Parse(ParseError {
                            start_line: rec_line,
                            line: self.num_line,
                            column: pos.col + j,
                            err: ERR_BARE_QUOTE,
                        }));
                        break 'fields;
                    }
                }
                self.record_buffer.extend_from_slice(field);
                self.end_field(pos)?;
                let Some(i) = i else {
                    break 'fields;
                };
                at += i + comma_len;
                pos.col += i + comma_len;
                continue 'fields;
            }
            let field_pos = pos;
            at += 1;
            pos.col += 1;
            loop {
                let rest = &line[at..];
                if let Some(i) = rest.iter().position(|&b| b == b'"') {
                    self.record_buffer.extend_from_slice(&rest[..i]);
                    at += i + 1;
                    pos.col += i + 1;
                    let next = &line[at..];
                    if next.first() == Some(&b'"') {
                        self.record_buffer.push(b'"');
                        at += 1;
                        pos.col += 1;
                    } else if next.starts_with(comma_bytes) {
                        at += comma_len;
                        pos.col += comma_len;
                        self.end_field(field_pos)?;
                        continue 'fields;
                    } else if length_nl(next) == next.len() {
                        self.end_field(field_pos)?;
                        break 'fields;
                    } else if self.lazy_quotes {
                        self.record_buffer.push(b'"');
                    } else {
                        err = Some(Error::Parse(ParseError {
                            start_line: rec_line,
                            line: self.num_line,
                            column: pos.col - 1,
                            err: ERR_QUOTE,
                        }));
                        break 'fields;
                    }
                } else if !rest.is_empty() {
                    self.record_buffer.extend_from_slice(rest);
                    if err_read.is_some() {
                        break 'fields;
                    }
                    pos.col += rest.len();
                    (line, err_read) = self.read_line()?;
                    if self.offset - record_start > self.limits.max_record_bytes as u64 {
                        return Err(budget("CSV record byte limit"));
                    }
                    at = 0;
                    if !line.is_empty() {
                        pos.line += 1;
                        pos.col = 1;
                    }
                    if matches!(err_read, Some(Error::Eof)) {
                        err_read = None;
                    }
                } else {
                    if !self.lazy_quotes && err_read.is_none() {
                        err = Some(Error::Parse(ParseError {
                            start_line: rec_line,
                            line: pos.line,
                            column: pos.col,
                            err: ERR_QUOTE,
                        }));
                        break 'fields;
                    }
                    self.end_field(field_pos)?;
                    break 'fields;
                }
            }
        }
        if err.is_none() {
            err = err_read;
        }
        let count = self.field_indexes.len();
        if self.fields_per_record > 0 {
            if count as isize != self.fields_per_record && err.is_none() {
                err = Some(Error::Parse(ParseError {
                    start_line: rec_line,
                    line: rec_line,
                    column: 1,
                    err: ERR_FIELD_COUNT,
                }));
            }
        } else if self.fields_per_record == 0 {
            self.fields_per_record = count as isize;
        }
        Ok(err)
    }
}

impl<R: Read> Iterator for Reader<R> {
    type Item = Result<Vec<String>, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        self.read().transpose()
    }
}

/// Go's `Writer`. Writes go through a buffer; `flush` or `write_all` reach the
/// underlying writer. The first failed write is sticky, as in Go's `bufio`.
pub struct Writer<W: Write> {
    /// Go's `Comma`: the field delimiter.
    pub comma: char,
    /// Go's `UseCRLF`: end lines with CRLF, and drop bare CR inside quoted fields.
    pub use_crlf: bool,
    w: BufWriter<W>,
    error: Option<io::Error>,
}

fn copy_error(e: &io::Error) -> io::Error {
    io::Error::new(e.kind(), e.to_string())
}

impl<W: Write> Writer<W> {
    /// Go's `NewWriter`.
    pub fn new(w: W) -> Self {
        Self {
            comma: ',',
            use_crlf: false,
            w: BufWriter::new(w),
            error: None,
        }
    }

    /// Flushes buffered output and returns the underlying writer.
    pub fn into_inner(self) -> io::Result<W> {
        self.w.into_inner().map_err(|e| e.into_error())
    }

    fn sticky<T>(&mut self, result: io::Result<T>) -> io::Result<T> {
        result.map_err(|e| {
            let copy = copy_error(&e);
            self.error.get_or_insert(e);
            copy
        })
    }

    /// Go's `Write`: writes one record and its line ending.
    pub fn write<S: AsRef<str>>(&mut self, record: &[S]) -> io::Result<()> {
        if !valid_delim(self.comma) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "csv: invalid field or comment delimiter",
            ));
        }
        if let Some(e) = &self.error {
            return Err(copy_error(e));
        }
        let result = self.write_fields(record);
        self.sticky(result)
    }

    /// Go's `WriteAll`: writes every record and flushes.
    pub fn write_all<S: AsRef<str>>(&mut self, records: &[Vec<S>]) -> io::Result<()> {
        for record in records {
            self.write(record.as_slice())?;
        }
        self.flush()
    }

    /// Go's `Flush`. Unlike Go, the error is returned as well as kept by `error`.
    pub fn flush(&mut self) -> io::Result<()> {
        if let Some(e) = &self.error {
            return Err(copy_error(e));
        }
        let result = self.w.flush();
        self.sticky(result)
    }

    /// Go's `Error`: the sticky error from a failed write or flush, if any.
    pub fn error(&self) -> Option<&io::Error> {
        self.error.as_ref()
    }

    fn needs_quotes(&self, field: &str) -> bool {
        if field.is_empty() {
            return false;
        }
        if field == "\\." {
            return true;
        }
        if field.contains(self.comma) || field.contains(['"', '\r', '\n']) {
            return true;
        }
        field.chars().next().is_some_and(char::is_whitespace)
    }

    fn write_fields<S: AsRef<str>>(&mut self, record: &[S]) -> io::Result<()> {
        let (comma_buf, comma_len) = encode(self.comma);
        let comma = &comma_buf[..comma_len];
        for (n, field) in record.iter().enumerate() {
            let field = field.as_ref();
            if n > 0 {
                self.w.write_all(comma)?;
            }
            if !self.needs_quotes(field) {
                self.w.write_all(field.as_bytes())?;
                continue;
            }
            self.w.write_all(b"\"")?;
            let mut rest = field.as_bytes();
            while !rest.is_empty() {
                let i = rest
                    .iter()
                    .position(|&b| matches!(b, b'"' | b'\r' | b'\n'))
                    .unwrap_or(rest.len());
                self.w.write_all(&rest[..i])?;
                rest = &rest[i..];
                if let Some(&c) = rest.first() {
                    match c {
                        b'"' => self.w.write_all(b"\"\"")?,
                        b'\r' => {
                            if !self.use_crlf {
                                self.w.write_all(b"\r")?;
                            }
                        }
                        _ => {
                            if self.use_crlf {
                                self.w.write_all(b"\r\n")?;
                            } else {
                                self.w.write_all(b"\n")?;
                            }
                        }
                    }
                    rest = &rest[1..];
                }
            }
            self.w.write_all(b"\"")?;
        }
        self.w
            .write_all(if self.use_crlf { b"\r\n" } else { b"\n" })
    }
}
