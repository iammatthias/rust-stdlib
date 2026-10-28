//! The raw FastCGI protocol and its utilities (Go's `net/http/fcgi/fcgi.go`).
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use crate::net::Conn;

pub(super) const TYPE_BEGIN_REQUEST: u8 = 1;
pub(super) const TYPE_ABORT_REQUEST: u8 = 2;
pub(super) const TYPE_END_REQUEST: u8 = 3;
pub(super) const TYPE_PARAMS: u8 = 4;
pub(super) const TYPE_STDIN: u8 = 5;
pub(super) const TYPE_STDOUT: u8 = 6;
pub(super) const TYPE_STDERR: u8 = 7;
pub(super) const TYPE_DATA: u8 = 8;
pub(super) const TYPE_GET_VALUES: u8 = 9;
pub(super) const TYPE_GET_VALUES_RESULT: u8 = 10;
pub(super) const TYPE_UNKNOWN_TYPE: u8 = 11;

/// Keep the connection between web server and responder open.
pub(super) const FLAG_KEEP_CONN: u8 = 1;

/// Maximum record body.
pub(super) const MAX_WRITE: usize = 65535;
const MAX_PAD: usize = 255;

pub(super) const ROLE_RESPONDER: u16 = 1;

pub(super) const STATUS_REQUEST_COMPLETE: u8 = 0;
pub(super) const STATUS_UNKNOWN_ROLE: u8 = 3;

/// A record header.
#[derive(Clone, Copy, Default)]
pub(super) struct Header {
    pub version: u8,
    pub typ: u8,
    pub id: u16,
    pub content_length: u16,
    pub padding_length: u8,
}

impl Header {
    fn init(typ: u8, req_id: u16, content_length: usize) -> Header {
        Header {
            version: 1,
            typ,
            id: req_id,
            content_length: content_length as u16,
            padding_length: (content_length.wrapping_neg() & 7) as u8,
        }
    }

    fn bytes(&self) -> [u8; 8] {
        let id = self.id.to_be_bytes();
        let len = self.content_length.to_be_bytes();
        [
            self.version,
            self.typ,
            id[0],
            id[1],
            len[0],
            len[1],
            self.padding_length,
            0,
        ]
    }
}

/// A begin-request body.
pub(super) struct BeginRequest {
    pub role: u16,
    pub flags: u8,
}

impl BeginRequest {
    pub fn read(content: &[u8]) -> Result<BeginRequest, io::Error> {
        if content.len() != 8 {
            return Err(io::Error::other("fcgi: invalid begin request record"));
        }
        Ok(BeginRequest {
            role: u16::from_be_bytes([content[0], content[1]]),
            flags: content[2],
        })
    }
}

/// Sends records over a connection.
pub(super) struct Records {
    conn: Arc<dyn Conn>,
    mutex: Mutex<()>,
}

impl Records {
    pub fn new(conn: Arc<dyn Conn>) -> Arc<Records> {
        Arc::new(Records {
            conn,
            mutex: Mutex::new(()),
        })
    }

    pub fn conn(&self) -> &Arc<dyn Conn> {
        &self.conn
    }

    /// Closes the connection (Go's `conn.Close`; closing twice returns the
    /// first close's result in Go and is harmless here).
    pub fn close(&self) -> io::Result<()> {
        self.conn.close().map_err(crate::net::NetError::into_io)
    }

    fn write_all(&self, mut b: &[u8]) -> io::Result<()> {
        while !b.is_empty() {
            let n = self.conn.write(b).map_err(crate::net::NetError::into_io)?;
            if n == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            b = &b[n..];
        }
        Ok(())
    }

    /// Writes and sends a single record.
    pub fn write_record(&self, typ: u8, req_id: u16, b: &[u8]) -> io::Result<()> {
        let _guard = self.mutex.lock().unwrap_or_else(|e| e.into_inner());
        let h = Header::init(typ, req_id, b.len());
        let mut buf = Vec::with_capacity(8 + b.len() + MAX_PAD);
        buf.extend_from_slice(&h.bytes());
        buf.extend_from_slice(b);
        buf.extend_from_slice(&[0u8; MAX_PAD][..usize::from(h.padding_length)]);
        self.write_all(&buf)
    }

    pub fn write_end_request(
        &self,
        req_id: u16,
        app_status: i32,
        protocol_status: u8,
    ) -> io::Result<()> {
        let mut b = [0u8; 8];
        b[..4].copy_from_slice(&(app_status as u32).to_be_bytes());
        b[4] = protocol_status;
        self.write_record(TYPE_END_REQUEST, req_id, &b)
    }

    pub fn write_pairs(
        self: &Arc<Self>,
        typ: u8,
        req_id: u16,
        pairs: &BTreeMap<String, String>,
    ) -> io::Result<()> {
        let mut w = BufStream::new(self, typ, req_id);
        let mut b = [0u8; 8];
        for (k, v) in pairs {
            let mut n = encode_size(&mut b, k.len() as u32);
            n += encode_size(&mut b[n..], v.len() as u32);
            w.write_all(&b[..n])?;
            w.write_all(k.as_bytes())?;
            w.write_all(v.as_bytes())?;
        }
        w.close()
    }
}

/// Reads a size: one byte, or four bytes with the top bit set.
pub(super) fn read_size(s: &[u8]) -> (u32, usize) {
    if s.is_empty() {
        return (0, 0);
    }
    let (mut size, mut n) = (u32::from(s[0]), 1);
    if size & (1 << 7) != 0 {
        if s.len() < 4 {
            return (0, 0);
        }
        n = 4;
        size = u32::from_be_bytes([s[0], s[1], s[2], s[3]]);
        size &= !(1 << 31);
    }
    (size, n)
}

pub(super) fn read_string(s: &[u8], size: u32) -> String {
    if size as usize > s.len() {
        return String::new();
    }
    String::from_utf8_lossy(&s[..size as usize]).into_owned()
}

fn encode_size(b: &mut [u8], size: u32) -> usize {
    if size > 127 {
        b[..4].copy_from_slice(&(size | (1 << 31)).to_be_bytes());
        return 4;
    }
    b[0] = size as u8;
    1
}

/// Splits a stream into records of at most [`MAX_WRITE`] bytes (Go's
/// `streamWriter`).
pub(super) struct StreamWriter {
    records: Arc<Records>,
    typ: u8,
    req_id: u16,
}

impl Write for StreamWriter {
    fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        for chunk in p.chunks(MAX_WRITE) {
            self.records.write_record(self.typ, self.req_id, chunk)?;
        }
        Ok(p.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A buffered record stream that sends an empty record when closed (Go's
/// `bufWriter` over `bufio.NewWriterSize(s, maxWrite)`). The buffering is
/// Go's, so the record boundaries are Go's: the buffer is filled to its size
/// before each flush.
pub(super) struct BufStream {
    buf: Vec<u8>,
    sink: StreamWriter,
    err: Option<io::ErrorKind>,
}

impl Write for BufStream {
    fn write(&mut self, mut p: &[u8]) -> io::Result<usize> {
        let total = p.len();
        while p.len() > MAX_WRITE - self.buf.len() && self.err.is_none() {
            if self.buf.is_empty() {
                // Large write, empty buffer: write directly.
                if let Err(e) = self.sink.write_all(p) {
                    self.err = Some(e.kind());
                    return Err(e);
                }
                return Ok(total);
            }
            let n = MAX_WRITE - self.buf.len();
            self.buf.extend_from_slice(&p[..n]);
            p = &p[n..];
            self.flush()?;
        }
        if let Some(kind) = self.err {
            return Err(kind.into());
        }
        self.buf.extend_from_slice(p);
        Ok(total)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(kind) = self.err {
            return Err(kind.into());
        }
        if self.buf.is_empty() {
            return Ok(());
        }
        let r = self.sink.write_all(&self.buf);
        self.buf.clear();
        if let Err(e) = &r {
            self.err = Some(e.kind());
        }
        r
    }
}

impl BufStream {
    /// Flushes, then sends the empty record that ends the stream.
    pub fn close(&mut self) -> io::Result<()> {
        let flushed = self.flush();
        let closed = self
            .sink
            .records
            .write_record(self.sink.typ, self.sink.req_id, &[]);
        flushed.and(closed)
    }
}

impl BufStream {
    pub(super) fn new(records: &Arc<Records>, typ: u8, req_id: u16) -> BufStream {
        BufStream {
            buf: Vec::with_capacity(MAX_WRITE),
            sink: StreamWriter {
                records: records.clone(),
                typ,
                req_id,
            },
            err: None,
        }
    }
}
