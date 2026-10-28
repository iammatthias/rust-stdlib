//! The gob codecs of Go's `client.go` and `server.go`.

use std::io::{self, BufWriter, Write};
use std::sync::{Arc, Mutex};

use crate::encoding::gob::{Decoder, Encoder};
use crate::reflect::{self, Reflect, ReflectType, Value};

use super::{ClientCodec, ConnIo, Error, ReadWriteCloser, Request, Response, ServerCodec};

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The write half: a buffer in front of the connection so the header and
/// payload are sent as a unit (Go's `bufio.Writer`).
#[derive(Clone)]
struct Buffered(Arc<Mutex<BufWriter<ConnIo>>>);

impl Write for Buffered {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        lock(&self.0).write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        lock(&self.0).flush()
    }
}

fn new_halves(conn: &Arc<dyn ReadWriteCloser>) -> (Decoder, Encoder, Buffered) {
    let buf = Buffered(Arc::new(Mutex::new(BufWriter::new(ConnIo(conn.clone())))));
    (
        Decoder::new(ConnIo(conn.clone())),
        Encoder::new(buf.clone()),
        buf,
    )
}

/// The gob server codec (Go `gobServerCodec`).
pub(crate) struct GobServerCodec {
    rwc: Arc<dyn ReadWriteCloser>,
    dec: Decoder,
    enc: Encoder,
    enc_buf: Buffered,
    closed: Mutex<bool>,
}

impl GobServerCodec {
    pub(crate) fn new(conn: Arc<dyn ReadWriteCloser>) -> GobServerCodec {
        let (dec, enc, enc_buf) = new_halves(&conn);
        GobServerCodec {
            rwc: conn,
            dec,
            enc,
            enc_buf,
            closed: Mutex::new(false),
        }
    }
}

impl ServerCodec for GobServerCodec {
    fn read_request_header(&self, r: &mut Request) -> Result<(), Error> {
        let v = reflect::new(&Request::reflect_type());
        self.dec.decode_value(&v)?;
        *r = Request::from_value(&v.elem()).map_err(|e| Error::new(e.to_string()))?;
        Ok(())
    }

    fn read_request_body(&self, body: &Value) -> Result<(), Error> {
        Ok(self.dec.decode_value(body)?)
    }

    fn write_response(&self, r: &Response, body: &Value) -> Result<(), Error> {
        if let Err(err) = self.enc.encode(r) {
            if self.enc_buf.clone().flush().is_ok() {
                // Gob couldn't encode the header. Should not happen, so if it
                // does, shut down the connection to signal that the
                // connection is broken.
                crate::log::println(format_args!("rpc: gob error encoding response: {err}"));
                let _ = self.close();
            }
            return Err(err.into());
        }
        if let Err(err) = self.enc.encode_value(body) {
            if self.enc_buf.clone().flush().is_ok() {
                // Was a gob problem encoding the body but the header has been
                // written. Shut down the connection to signal that the
                // connection is broken.
                crate::log::println(format_args!("rpc: gob error encoding body: {err}"));
                let _ = self.close();
            }
            return Err(err.into());
        }
        Ok(self.enc_buf.clone().flush()?)
    }

    fn close(&self) -> Result<(), Error> {
        let mut closed = lock(&self.closed);
        if *closed {
            // Only call rwc.close once; otherwise the semantics are undefined.
            return Ok(());
        }
        *closed = true;
        Ok(self.rwc.close()?)
    }
}

/// The gob client codec (Go `gobClientCodec`).
pub(crate) struct GobClientCodec {
    rwc: Arc<dyn ReadWriteCloser>,
    dec: Decoder,
    enc: Encoder,
    enc_buf: Buffered,
}

impl GobClientCodec {
    pub(crate) fn new(conn: Arc<dyn ReadWriteCloser>) -> GobClientCodec {
        let (dec, enc, enc_buf) = new_halves(&conn);
        GobClientCodec {
            rwc: conn,
            dec,
            enc,
            enc_buf,
        }
    }
}

impl ClientCodec for GobClientCodec {
    fn write_request(&self, r: &Request, body: &Value) -> Result<(), Error> {
        self.enc.encode(r)?;
        self.enc.encode_value(body)?;
        Ok(self.enc_buf.clone().flush()?)
    }

    fn read_response_header(&self, r: &mut Response) -> Result<(), Error> {
        let v = reflect::new(&Response::reflect_type());
        self.dec.decode_value(&v)?;
        *r = Response::from_value(&v.elem()).map_err(|e| Error::new(e.to_string()))?;
        Ok(())
    }

    fn read_response_body(&self, body: &Value) -> Result<(), Error> {
        Ok(self.dec.decode_value(body)?)
    }

    fn close(&self) -> Result<(), Error> {
        Ok(self.rwc.close()?)
    }
}
