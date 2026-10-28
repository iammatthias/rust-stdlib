//! Go's multipart `Writer`: parts are written in the order created, with
//! sorted header lines and the boundary Go uses.
use super::Error;
use crate::net::textproto::MIMEHeader;
use std::collections::BTreeMap;
use std::io::{self, Write};

const AFTER_WRITE: Error = Error("mime: SetBoundary called after write");
const INVALID_BOUNDARY_LENGTH: Error = Error("mime: invalid boundary length");
const INVALID_BOUNDARY_CHARACTER: Error = Error("mime: invalid boundary character");

/// Go's `SetBoundary` rules: 1 to 70 RFC 2046 `bchars`, and a space only
/// before the last character.
fn validate_writer_boundary(boundary: &str) -> Result<(), Error> {
    if boundary.is_empty() || boundary.len() > 70 {
        return Err(INVALID_BOUNDARY_LENGTH);
    }
    let end = boundary.len() - 1;
    for (index, b) in boundary.bytes().enumerate() {
        let allowed = b.is_ascii_alphanumeric()
            || b"'()+_,-./:=?".contains(&b)
            || (b == b' ' && index != end);
        if !allowed {
            return Err(INVALID_BOUNDARY_CHARACTER);
        }
    }
    Ok(())
}

/// Escapes a field or file name for a quoted Content-Disposition parameter,
/// as Go's `escapeQuotes` does.
fn escape_quotes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\r' => out.push_str("%0D"),
            '\n' => out.push_str("%0A"),
            other => out.push(other),
        }
    }
    out
}

/// Go's `FileContentDisposition`: `form-data; name="..."; filename="..."`.
pub fn file_content_disposition(fieldname: &str, filename: &str) -> String {
    format!(
        "form-data; name=\"{}\"; filename=\"{}\"",
        escape_quotes(fieldname),
        escape_quotes(filename)
    )
}

/// Go's `randomBoundary`: 30 random bytes as 60 hex digits. The bytes come
/// from the operating system's generator (`/dev/urandom`, as `crypto/rand`
/// reads it). Like Go, it panics when that source cannot be read: there is no
/// weaker fallback.
fn random_boundary() -> String {
    let mut bytes = [0u8; 30];
    let read = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut bytes));
    if let Err(err) = read {
        panic!("multipart: no operating-system random source: {err}");
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Writes a multipart body to an [`io::Write`] (Go's `multipart.Writer`).
#[derive(Debug)]
pub struct Writer<W> {
    writer: W,
    boundary: String,
    last_part: bool,
}

impl<W> Writer<W> {
    /// Gets a reference to the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.writer
    }

    /// Gets a mutable reference to the underlying writer. Writing to it
    /// directly can corrupt the multipart framing.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    /// Unwraps this `Writer`, returning the underlying writer. Nothing is
    /// written: call [`close`](Writer::close) first to end the body.
    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl<W: Write> Writer<W> {
    /// Returns a writer with a random boundary.
    ///
    /// # Panics
    ///
    /// Panics, as Go does, if the operating system random source cannot be read.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            boundary: random_boundary(),
            last_part: false,
        }
    }

    pub fn boundary(&self) -> &str {
        &self.boundary
    }

    /// Replaces the boundary. It must be set before the first part.
    pub fn set_boundary(&mut self, boundary: &str) -> Result<(), Error> {
        if self.last_part {
            return Err(AFTER_WRITE);
        }
        validate_writer_boundary(boundary)?;
        self.boundary = boundary.to_owned();
        Ok(())
    }

    /// The `Content-Type` value for the body, quoting the boundary when needed.
    pub fn form_data_content_type(&self) -> String {
        if self.boundary.contains(|c| "()<>@,;:\\\"/[]?= ".contains(c)) {
            format!("multipart/form-data; boundary=\"{}\"", self.boundary)
        } else {
            format!("multipart/form-data; boundary={}", self.boundary)
        }
    }

    /// Starts a part with the given headers. The returned writer receives the
    /// part body until the next part is created or the writer is closed.
    pub fn create_part(&mut self, header: &MIMEHeader) -> io::Result<PartWriter<'_, W>> {
        let map: BTreeMap<String, Vec<String>> = header
            .iter()
            .map(|(key, values)| (key.to_owned(), values.to_vec()))
            .collect();
        self.create_part_map(&map)
    }

    /// Go's `CreatePart` with a plain map: the keys are written exactly as
    /// given, in byte order, without canonicalization.
    pub fn create_part_map(
        &mut self,
        header: &BTreeMap<String, Vec<String>>,
    ) -> io::Result<PartWriter<'_, W>> {
        let mut out = if self.last_part {
            format!("\r\n--{}\r\n", self.boundary)
        } else {
            format!("--{}\r\n", self.boundary)
        };
        for (key, values) in header {
            for value in values {
                out.push_str(&format!("{key}: {value}\r\n"));
            }
        }
        out.push_str("\r\n");
        self.writer.write_all(out.as_bytes())?;
        self.last_part = true;
        Ok(PartWriter {
            writer: &mut self.writer,
        })
    }

    /// Starts a file part with `Content-Type: application/octet-stream`.
    pub fn create_form_file(
        &mut self,
        fieldname: &str,
        filename: &str,
    ) -> io::Result<PartWriter<'_, W>> {
        let mut header = MIMEHeader::new();
        header.set(
            "Content-Disposition",
            &file_content_disposition(fieldname, filename),
        );
        header.set("Content-Type", "application/octet-stream");
        self.create_part(&header)
    }

    /// Starts a form field part.
    pub fn create_form_field(&mut self, fieldname: &str) -> io::Result<PartWriter<'_, W>> {
        let mut header = MIMEHeader::new();
        header.set(
            "Content-Disposition",
            &format!("form-data; name=\"{}\"", escape_quotes(fieldname)),
        );
        self.create_part(&header)
    }

    /// Writes a form field with the given value.
    pub fn write_field(&mut self, fieldname: &str, value: &str) -> io::Result<()> {
        self.create_form_field(fieldname)?
            .write_all(value.as_bytes())
    }

    /// Writes the closing delimiter. The writer is not usable for more parts
    /// after this without calling [`Writer::set_boundary`] or creating a new one.
    pub fn close(&mut self) -> io::Result<()> {
        self.last_part = false;
        write!(self.writer, "\r\n--{}--\r\n", self.boundary)
    }
}

/// The body writer for one part, returned by [`Writer::create_part`].
#[derive(Debug)]
pub struct PartWriter<'a, W> {
    writer: &'a mut W,
}

impl<W: Write> Write for PartWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}
