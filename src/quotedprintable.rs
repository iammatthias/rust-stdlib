//! Streaming quoted-printable encoding and decoding (RFC 2045).
//!
//! The decoder follows Go's `mime/quotedprintable` compatibility behavior:
//! LF soft breaks, literal malformed equals signs except at line endings,
//! unescaped high bytes, and permissive bare CR/LF. It processes bounded
//! 4096-byte chunks like Go's buffered `ReadSlice`; a chunk without LF returns
//! `bufio: buffer full` after its decoded prefix. Partial data is emitted before
//! an underlying read error.
use std::io::{self, Read, Write};

const LINE_MAX: usize = 76;
// Go's bufio.Reader uses a 4096-byte buffer; matching its ReadSlice chunks
// bounds per-line memory while preserving behavior for oversized input lines.
const DECODE_CHUNK: usize = 4096;

/// A streaming quoted-printable decoder.
pub struct Reader<R> {
    inner: R,
    line: Vec<u8>,
    output: Vec<u8>,
    out_pos: usize,
    eof: bool,
    pending_error: Option<io::Error>,
}

fn qp_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
fn quote_go_bytes(bytes: &[u8]) -> String {
    let mut out = String::from("\"");
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b < 0x80 {
            match b {
                b'"' => out.push_str("\\\""),
                b'\\' => out.push_str("\\\\"),
                b'\n' => out.push_str("\\n"),
                b'\r' => out.push_str("\\r"),
                b'\t' => out.push_str("\\t"),
                0x07 => out.push_str("\\a"),
                0x08 => out.push_str("\\b"),
                0x0b => out.push_str("\\v"),
                0x0c => out.push_str("\\f"),
                0x00..=0x1f | 0x7f => out.push_str(&format!("\\x{b:02x}")),
                _ => out.push(b as char),
            }
            i += 1;
            continue;
        }
        match std::str::from_utf8(&bytes[i..]) {
            Ok(s) => {
                let c = s.chars().next().unwrap();
                if c.is_control() {
                    if (c as u32) <= 0xffff {
                        out.push_str(&format!("\\u{:04x}", c as u32));
                    } else {
                        out.push_str(&format!("\\U{:08x}", c as u32));
                    }
                } else {
                    out.push(c);
                }
                i += c.len_utf8();
            }
            Err(e) if e.valid_up_to() > 0 => {
                let s = std::str::from_utf8(&bytes[i..i + e.valid_up_to()]).unwrap();
                let c = s.chars().next().unwrap();
                out.push(c);
                i += c.len_utf8();
            }
            Err(_) => {
                out.push_str(&format!("\\x{b:02x}"));
                i += 1;
            }
        }
    }
    out.push('"');
    out
}
fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

impl<R: Read> Reader<R> {
    /// Wrap `reader` with a quoted-printable decoder.
    pub fn new(reader: R) -> Self {
        Reader {
            inner: reader,
            line: Vec::new(),
            output: Vec::new(),
            out_pos: 0,
            eof: false,
            pending_error: None,
        }
    }

    /// Returns the wrapped reader, dropping any buffered, undelivered output.
    pub fn into_inner(self) -> R {
        self.inner
    }

    fn next_line(&mut self) -> io::Result<bool> {
        self.line.clear();
        if self.eof {
            return Ok(false);
        }
        loop {
            let mut b = [0];
            match self.inner.read(&mut b) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(_) => {
                    self.line.push(b[0]);
                    if b[0] == b'\n' {
                        break;
                    }
                    if self.line.len() == DECODE_CHUNK {
                        self.pending_error = Some(qp_error("bufio: buffer full"));
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    self.eof = true;
                    self.pending_error = Some(e);
                    break;
                }
            }
        }
        if self.line.is_empty() {
            return Ok(false);
        }
        self.decode_line();
        Ok(true)
    }

    fn decode_line(&mut self) {
        self.output.clear();
        self.out_pos = 0;
        let whole = &self.line;
        let mut end = whole.len();
        while end > 0 && matches!(whole[end - 1], b'\n' | b'\r' | b' ' | b'\t') {
            end -= 1;
        }
        let mut source = &whole[..end];
        let mut delayed = None;
        let mut soft_break = false;
        if source.last() == Some(&b'=') {
            source = &source[..source.len() - 1];
            let mut suffix = &whole[end..];
            while suffix.first().is_some_and(|b| *b == b' ' || *b == b'\t') {
                suffix = &suffix[1..];
            }
            let soft = suffix.starts_with(b"\n")
                || suffix.starts_with(b"\r\n")
                || (suffix.is_empty() && self.eof && !source.is_empty());
            if !soft {
                delayed = Some(qp_error(format!(
                    "quotedprintable: invalid bytes after =: {}",
                    quote_go_bytes(suffix)
                )));
            } else {
                soft_break = true;
            }
        }

        let mut i = 0;
        while i < source.len() {
            let b = source[i];
            if b == b'=' {
                if i + 2 < source.len() {
                    match (hex(source[i + 1]), hex(source[i + 2])) {
                        (Some(h), Some(l)) => {
                            self.output.push(h << 4 | l);
                            i += 3;
                            continue;
                        }
                        // Go treats malformed `=XX` as a literal equals when
                        // the first byte after it is not a line ending.
                        _ if !matches!(source[i + 1], b'\r' | b'\n') => {
                            self.output.push(b'=');
                            i += 1;
                            continue;
                        }
                        (Some(_), None) => {
                            delayed = Some(qp_error(format!(
                                "quotedprintable: invalid hex byte 0x{:02x}",
                                source[i + 2]
                            )));
                            break;
                        }
                        (None, _) => {
                            delayed = Some(qp_error(format!(
                                "quotedprintable: invalid hex byte 0x{:02x}",
                                source[i + 1]
                            )));
                            break;
                        }
                    }
                }
                if i + 1 < source.len() && !matches!(source[i + 1], b'\r' | b'\n') {
                    self.output.push(b'=');
                    i += 1;
                    continue;
                }
                delayed = Some(qp_error("unexpected EOF"));
                break;
            }
            if (b < b' ' && !matches!(b, b'\t' | b'\r' | b'\n')) || b == 0x7f {
                delayed = Some(qp_error(format!(
                    "quotedprintable: invalid unescaped byte 0x{b:02x} in body"
                )));
                break;
            }
            self.output.push(b);
            i += 1;
        }
        // Ordinary source line endings survive, while soft line endings above
        // are consumed with the equals marker.
        if !soft_break && whole.ends_with(b"\r\n") && delayed.is_none() {
            self.output.extend_from_slice(b"\r\n");
        } else if !soft_break && whole.ends_with(b"\n") && delayed.is_none() {
            self.output.push(b'\n');
        }
        if delayed.is_some() {
            self.pending_error = delayed;
        }
    }
}

impl<R: Read> Read for Reader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.out_pos < self.output.len() {
            let n = out.len().min(self.output.len() - self.out_pos);
            out[..n].copy_from_slice(&self.output[self.out_pos..self.out_pos + n]);
            self.out_pos += n;
            return Ok(n);
        }
        self.output.clear();
        self.out_pos = 0;
        if let Some(e) = self.pending_error.take() {
            return Err(e);
        }
        loop {
            if !self.next_line()? {
                if let Some(e) = self.pending_error.take() {
                    return Err(e);
                }
                return Ok(0);
            }
            if !self.output.is_empty() {
                let n = out.len().min(self.output.len());
                out[..n].copy_from_slice(&self.output[..n]);
                self.out_pos = n;
                return Ok(n);
            }
            if let Some(e) = self.pending_error.take() {
                return Err(e);
            }
        }
    }
}

/// A streaming quoted-printable encoder. Encoded bytes may remain buffered
/// until the line fills, a source newline occurs, or [`Writer::close`] runs.
pub struct Writer<W> {
    inner: W,
    line: Vec<u8>,
    column: usize,
    previous_cr: bool,
    pub binary: bool,
    closed: bool,
    failure: Option<(io::ErrorKind, String)>,
}

impl<W: Write> Writer<W> {
    /// Wrap `writer` with a quoted-printable encoder.
    pub fn new(writer: W) -> Self {
        Writer {
            inner: writer,
            line: Vec::with_capacity(78),
            column: 0,
            previous_cr: false,
            binary: false,
            closed: false,
            failure: None,
        }
    }

    fn prior_failure(&self) -> Option<io::Error> {
        self.failure
            .as_ref()
            .map(|(kind, message)| io::Error::new(*kind, message.clone()))
    }
    fn latch(&mut self, error: &io::Error) {
        self.failure
            .get_or_insert_with(|| (error.kind(), error.to_string()));
    }
    fn flush_line(&mut self) -> io::Result<()> {
        self.inner.write_all(&self.line)?;
        self.line.clear();
        Ok(())
    }
    fn soft_break(&mut self) -> io::Result<()> {
        self.line.push(b'=');
        self.line.extend_from_slice(b"\r\n");
        self.flush_line()?;
        self.column = 0;
        Ok(())
    }
    fn encode_byte(&mut self, b: u8) -> io::Result<()> {
        if LINE_MAX - 1 - self.column < 3 {
            self.soft_break()?;
        }
        const H: &[u8; 16] = b"0123456789ABCDEF";
        self.line
            .extend_from_slice(&[b'=', H[(b >> 4) as usize], H[(b & 15) as usize]]);
        self.column += 3;
        Ok(())
    }
    fn emit_plain(&mut self, b: u8) -> io::Result<()> {
        if self.column == LINE_MAX - 1 {
            self.soft_break()?;
        }
        self.line.push(b);
        self.column += 1;
        Ok(())
    }
    fn write_data(&mut self, bytes: &[u8]) -> io::Result<()> {
        for &b in bytes {
            if matches!(b, b'\r' | b'\n') {
                if self.previous_cr && b == b'\n' {
                    self.previous_cr = false;
                    continue;
                }
                self.previous_cr = b == b'\r';
                self.encode_trailing()?;
                self.line.extend_from_slice(b"\r\n");
                self.flush_line()?;
                self.column = 0;
                continue;
            }
            self.previous_cr = false;
            if matches!(b, b' ' | b'\t') || ((b'!'..=b'~').contains(&b) && b != b'=') {
                self.emit_plain(b)?;
            } else {
                self.encode_byte(b)?;
            }
        }
        Ok(())
    }
    fn encode_trailing(&mut self) -> io::Result<()> {
        if let Some(b) = self.line.pop_if(|b| matches!(*b, b' ' | b'\t')) {
            self.column -= 1;
            self.encode_byte(b)?;
        }
        Ok(())
    }
    /// Flush buffered output and finish the encoded stream; the underlying writer stays open.
    pub fn close(&mut self) -> io::Result<()> {
        if let Some(e) = self.prior_failure() {
            return Err(e);
        }
        if self.closed {
            return Ok(());
        }
        if let Err(e) = self.encode_trailing().and_then(|_| self.flush_line()) {
            self.latch(&e);
            return Err(e);
        }
        self.closed = true;
        Ok(())
    }
    /// Return the underlying writer, finishing the encoding first.
    pub fn into_inner(mut self) -> io::Result<W> {
        self.close()?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for Writer<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Some(e) = self.prior_failure() {
            return Err(e);
        }
        if self.closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "quotedprintable: write after close",
            ));
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        // Match the standard writer's two paths: printable bytes and text
        // line endings pass through its line processor; escaped bytes bypass
        // it and therefore do not reset a pending CR state.
        let result = (|| -> io::Result<()> {
            for &b in bytes {
                if ((b'!'..=b'~').contains(&b) && b != b'=')
                    || matches!(b, b' ' | b'\t')
                    || (!self.binary && matches!(b, b'\r' | b'\n'))
                {
                    self.write_data(&[b])?;
                } else {
                    self.encode_byte(b)?;
                }
            }
            Ok(())
        })();
        if let Err(e) = result {
            self.latch(&e);
            return Err(e);
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        if let Some(e) = self.prior_failure() {
            return Err(e);
        }
        let result = self
            .encode_trailing()
            .and_then(|_| self.flush_line())
            .and_then(|_| self.inner.flush());
        if let Err(e) = result {
            self.latch(&e);
            return Err(e);
        }
        Ok(())
    }
}
