//! The SMTP client (Go's `net/smtp/smtp.go`).
use std::collections::HashMap;
use std::error;
use std::fmt;
use std::io::{self, BufReader, BufWriter, Write};
use std::sync::Arc;

use super::auth::{Auth, ServerInfo};
use crate::encoding::base64;
use crate::net::http::TlsConfig;
use crate::net::textproto::{self, DotWriter, ReadHalf, Reader, ResponseError, Stream, WriteHalf};
use crate::net::{self, AddrRef, Conn, NetError, TlsConnectionState};
use crate::time::Time;

/// The errors of the SMTP client. Each variant keeps the Go error it stands
/// for, and its text is Go's.
#[derive(Debug)]
pub enum Error {
    /// A `textproto` error: a numeric response (Go `*textproto.Error`), end of
    /// input, or a protocol violation.
    Text(textproto::Error),
    /// A network error from dialing.
    Net(NetError),
    /// A write or close error on the connection.
    Io(io::Error),
    /// A plain `errors.New` error, or an error from an [`Auth`] mechanism.
    Other(Box<dyn error::Error + Send + Sync>),
    /// The error remembered from a failed hello, returned again by every
    /// later method (Go's `helloError`).
    Shared(Arc<Error>),
}

impl Error {
    fn msg(text: &str) -> Error {
        Error::Other(text.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Text(e) => e.fmt(f),
            Error::Net(e) => e.fmt(f),
            Error::Io(e) => e.fmt(f),
            Error::Other(e) => e.fmt(f),
            Error::Shared(e) => e.fmt(f),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::Text(e) => Some(e),
            Error::Net(e) => Some(e),
            Error::Io(e) => Some(e),
            Error::Other(e) => Some(&**e),
            Error::Shared(e) => Some(&**e),
        }
    }
}

impl From<textproto::Error> for Error {
    fn from(e: textproto::Error) -> Self {
        Error::Text(e)
    }
}

impl From<NetError> for Error {
    fn from(e: NetError) -> Self {
        Error::Net(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

/// A shared connection: the client's [`textproto::Conn`] and the connection
/// kept for `StartTLS` and `TLSConnectionState` use the same underlying one.
#[derive(Clone)]
pub struct SharedConn(Arc<dyn Conn>);

impl fmt::Debug for SharedConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedConn")
    }
}

impl Stream for SharedConn {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf).map_err(NetError::into_io)
    }
    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf).map_err(NetError::into_io)
    }
    fn close(&self) -> io::Result<()> {
        self.0.close().map_err(NetError::into_io)
    }
}

impl Conn for SharedConn {
    fn read(&self, b: &mut [u8]) -> Result<usize, NetError> {
        self.0.read(b)
    }
    fn write(&self, b: &[u8]) -> Result<usize, NetError> {
        self.0.write(b)
    }
    fn close(&self) -> Result<(), NetError> {
        self.0.close()
    }
    fn local_addr(&self) -> Option<AddrRef> {
        self.0.local_addr()
    }
    fn remote_addr(&self) -> Option<AddrRef> {
        self.0.remote_addr()
    }
    fn set_deadline(&self, t: &Time) -> Result<(), NetError> {
        self.0.set_deadline(t)
    }
    fn set_read_deadline(&self, t: &Time) -> Result<(), NetError> {
        self.0.set_read_deadline(t)
    }
    fn set_write_deadline(&self, t: &Time) -> Result<(), NetError> {
        self.0.set_write_deadline(t)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self.0.as_any()
    }
    fn tls_connection_state(&self) -> Option<TlsConnectionState> {
        self.0.tls_connection_state()
    }
    fn handshake(&self) -> Result<(), NetError> {
        self.0.handshake()
    }
}

type TextReader = Reader<BufReader<ReadHalf<SharedConn>>>;

/// Go's `smtp.Client`: a client connection to an SMTP server.
pub struct Client {
    /// The `textproto::Conn` used by the client. It is public to allow
    /// clients to add extensions (Go `Text`).
    pub text: textproto::Conn<SharedConn>,
    /// The connection, kept so it can be wrapped in TLS later.
    conn: SharedConn,
    /// Whether the client is using TLS.
    tls: bool,
    server_name: String,
    /// Supported extensions; `None` is Go's nil map.
    ext: Option<HashMap<String, String>>,
    /// Supported auth mechanisms.
    auth: Vec<String>,
    /// The name to use in HELO/EHLO.
    local_name: String,
    /// Whether HELO/EHLO has been sent.
    did_hello: bool,
    /// The error from the hello.
    hello_error: Option<Arc<Error>>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("server_name", &self.server_name)
            .field("tls", &self.tls)
            .field("local_name", &self.local_name)
            .finish_non_exhaustive()
    }
}

/// Go's `smtp.Dial`: a new [`Client`] connected to an SMTP server at `addr`.
/// The `addr` must include a port, as in "mail.example.com:smtp".
pub fn dial(addr: &str) -> Result<Client, Error> {
    let conn = net::dial("tcp", addr)?;
    let host = net::split_host_port(addr)
        .map(|(h, _)| h)
        .unwrap_or_default();
    Client::new(conn, &host)
}

/// Go's `validateLine`: a line must not contain CR or LF (RFC 5321).
fn validate_line(line: &str) -> Result<(), Error> {
    if line.contains(['\n', '\r']) {
        return Err(Error::msg("smtp: A line must not contain CR or LF"));
    }
    Ok(())
}

impl Client {
    /// Go's `smtp.NewClient`: a new [`Client`] using an existing connection and
    /// `host` as a server name to be used when authenticating.
    pub fn new(conn: Box<dyn Conn>, host: &str) -> Result<Client, Error> {
        let tls = conn.tls_connection_state().is_some();
        let conn = SharedConn(Arc::from(conn));
        let mut text = textproto::Conn::new(conn.clone());
        if let Err(e) = text.reader.read_response(220) {
            let _ = text.close();
            return Err(e.into());
        }
        Ok(Client {
            text,
            conn,
            tls,
            server_name: host.to_owned(),
            ext: None,
            auth: Vec::new(),
            local_name: "localhost".to_owned(),
            did_hello: false,
            hello_error: None,
        })
    }

    /// Go's `Client.Close`: closes the connection.
    pub fn close(&mut self) -> Result<(), Error> {
        Ok(self.text.close()?)
    }

    /// Runs a hello exchange if needed.
    fn hello_once(&mut self) -> Result<(), Error> {
        if !self.did_hello {
            self.did_hello = true;
            if self.ehlo().is_err() {
                self.hello_error = self.helo().err().map(Arc::new);
            }
        }
        match &self.hello_error {
            Some(e) => Err(Error::Shared(e.clone())),
            None => Ok(()),
        }
    }

    /// Go's `Client.Hello`: sends a HELO or EHLO to the server as the given
    /// host name. Calling this method is only necessary if the client needs
    /// control over the host name used; the client introduces itself as
    /// "localhost" automatically otherwise. If called, it must be called
    /// before any of the other methods.
    pub fn hello(&mut self, local_name: &str) -> Result<(), Error> {
        validate_line(local_name)?;
        if self.did_hello {
            return Err(Error::msg("smtp: Hello called after other methods"));
        }
        self.local_name = local_name.to_owned();
        self.hello_once()
    }

    /// Sends a command and returns the response.
    fn cmd(&mut self, expect_code: i32, line: impl fmt::Display) -> Result<(u16, String), Error> {
        let id = self.text.cmd(line)?;
        self.text.pipeline.start_response(id);
        let result = self.text.reader.read_response(expect_code);
        self.text.pipeline.end_response(id);
        Ok(result?)
    }

    /// Sends the HELO greeting; used only when the server does not support
    /// EHLO.
    fn helo(&mut self) -> Result<(), Error> {
        self.ext = None;
        let name = self.local_name.clone();
        self.cmd(250, format_args!("HELO {name}"))?;
        Ok(())
    }

    /// Sends the EHLO (extended hello) greeting to the server.
    fn ehlo(&mut self) -> Result<(), Error> {
        let name = self.local_name.clone();
        let (_, msg) = self.cmd(250, format_args!("EHLO {name}"))?;
        let mut ext = HashMap::new();
        let lines: Vec<&str> = msg.split('\n').collect();
        if lines.len() > 1 {
            for line in &lines[1..] {
                let (k, v) = line.split_once(' ').unwrap_or((line, ""));
                ext.insert(k.to_owned(), v.to_owned());
            }
        }
        if let Some(mechs) = ext.get("AUTH") {
            self.auth = mechs.split(' ').map(str::to_owned).collect();
        }
        self.ext = Some(ext);
        Ok(())
    }

    /// Go's `Client.StartTLS`: sends the STARTTLS command and encrypts all
    /// further communication. Only servers that advertise the STARTTLS
    /// extension support this function. `config` performs the handshake (the
    /// `rust-stdlib-tls` backend implements [`TlsConfig`]); the server name
    /// it verifies is the host the client was created with.
    pub fn start_tls(&mut self, config: &dyn TlsConfig) -> Result<(), Error> {
        self.hello_once()?;
        self.cmd(220, "STARTTLS")?;
        let name = self.server_name.clone();
        let wrapped = config
            .client_conn(Box::new(self.conn.clone()), &name, &[])
            .map_err(Error::Other)?;
        self.conn = SharedConn(Arc::from(wrapped));
        self.text = textproto::Conn::new(self.conn.clone());
        self.tls = true;
        self.ehlo()
    }

    /// Go's `Client.TLSConnectionState`: the client's TLS connection state,
    /// or `None` if [`start_tls`](Self::start_tls) did not succeed (Go returns
    /// the zero state and `false`).
    pub fn tls_connection_state(&self) -> Option<TlsConnectionState> {
        self.conn.tls_connection_state()
    }

    /// Go's `Client.Verify`: checks the validity of an email address on the
    /// server. Many servers will not verify addresses for security reasons.
    pub fn verify(&mut self, addr: &str) -> Result<(), Error> {
        validate_line(addr)?;
        self.hello_once()?;
        self.cmd(250, format_args!("VRFY {addr}"))?;
        Ok(())
    }

    /// Go's `Client.Auth`: authenticates a client using the provided
    /// authentication mechanism. A failed authentication closes the
    /// connection. Only servers that advertise the AUTH extension support
    /// this function.
    pub fn auth(&mut self, a: &mut dyn Auth) -> Result<(), Error> {
        self.hello_once()?;
        let encoding = base64::STANDARD;
        let info = ServerInfo {
            name: self.server_name.clone(),
            tls: self.tls,
            auth: self.auth.clone(),
        };
        let (mech, resp) = match a.start(&info) {
            Ok(started) => started,
            Err(e) => {
                let _ = self.quit();
                return Err(Error::Other(e));
            }
        };
        let resp64 = encoding.encode(&resp);
        let line = format!("AUTH {mech} {resp64}");
        let (mut code, mut msg64) = self.cmd(0, line.trim())?;
        loop {
            let msg: Result<Vec<u8>, Error> = match code {
                334 => encoding
                    .decode(&msg64)
                    .map_err(|e| Error::Other(Box::new(e))),
                // The last message isn't base64 because it isn't a challenge.
                235 => Ok(msg64.clone().into_bytes()),
                _ => Err(Error::Text(textproto::Error::Response(ResponseError {
                    code: i32::from(code),
                    msg: msg64.clone(),
                }))),
            };
            let next = match msg {
                Ok(msg) => a.next(&msg, code == 334).map_err(Error::Other),
                Err(e) => Err(e),
            };
            match next {
                Err(e) => {
                    // Abort the AUTH.
                    let _ = self.cmd(501, "*");
                    let _ = self.quit();
                    return Err(e);
                }
                Ok(None) => return Ok(()),
                Ok(Some(resp)) => {
                    let resp64 = encoding.encode(&resp);
                    (code, msg64) = self.cmd(0, resp64)?;
                }
            }
        }
    }

    /// Go's `Client.Mail`: issues a MAIL command using the provided email
    /// address. If the server supports the 8BITMIME extension, adds the
    /// BODY=8BITMIME parameter; if it supports SMTPUTF8, adds the SMTPUTF8
    /// parameter. This initiates a mail transaction and is followed by one or
    /// more [`rcpt`](Self::rcpt) calls.
    pub fn mail(&mut self, from: &str) -> Result<(), Error> {
        validate_line(from)?;
        self.hello_once()?;
        let mut suffix = String::new();
        if let Some(ext) = &self.ext {
            if ext.contains_key("8BITMIME") {
                suffix.push_str(" BODY=8BITMIME");
            }
            if ext.contains_key("SMTPUTF8") {
                suffix.push_str(" SMTPUTF8");
            }
        }
        self.cmd(250, format_args!("MAIL FROM:<{from}>{suffix}"))?;
        Ok(())
    }

    /// Go's `Client.Rcpt`: issues a RCPT command using the provided email
    /// address. A call must be preceded by [`mail`](Self::mail) and may be
    /// followed by [`data`](Self::data) or another `rcpt`.
    pub fn rcpt(&mut self, to: &str) -> Result<(), Error> {
        validate_line(to)?;
        self.cmd(25, format_args!("RCPT TO:<{to}>"))?;
        Ok(())
    }

    /// Go's `Client.Data`: issues a DATA command and returns a writer for the
    /// mail headers and body. The caller should [`close`](DataWriter::close)
    /// the writer before calling any more methods. A call must be preceded by
    /// one or more [`rcpt`](Self::rcpt) calls.
    pub fn data(&mut self) -> Result<DataWriter<'_>, Error> {
        self.cmd(354, "DATA")?;
        let textproto::Conn { reader, writer, .. } = &mut self.text;
        Ok(DataWriter {
            dot: writer.dot_writer(),
            reader,
        })
    }

    /// Go's `Client.Extension`: reports whether an extension is supported by
    /// the server, with any parameters the server specifies for it. The
    /// extension name is case-insensitive.
    pub fn extension(&mut self, ext: &str) -> (bool, String) {
        if self.hello_once().is_err() {
            return (false, String::new());
        }
        let Some(map) = &self.ext else {
            return (false, String::new());
        };
        match map.get(&ext.to_uppercase()) {
            Some(param) => (true, param.clone()),
            None => (false, String::new()),
        }
    }

    /// Go's `Client.Reset`: sends the RSET command, aborting the current mail
    /// transaction.
    pub fn reset(&mut self) -> Result<(), Error> {
        self.hello_once()?;
        self.cmd(250, "RSET")?;
        Ok(())
    }

    /// Go's `Client.Noop`: sends the NOOP command, which only checks that the
    /// connection to the server is okay.
    pub fn noop(&mut self) -> Result<(), Error> {
        self.hello_once()?;
        self.cmd(250, "NOOP")?;
        Ok(())
    }

    /// Go's `Client.Quit`: sends the QUIT command and closes the connection.
    pub fn quit(&mut self) -> Result<(), Error> {
        let _ = self.hello_once(); // ignore the error; we're quitting anyhow
        self.cmd(221, "QUIT")?;
        Ok(self.text.close()?)
    }
}

/// The writer returned by [`Client::data`] (Go's `dataCloser`): a dot-encoding
/// writer whose [`close`](Self::close) reads the server's reply.
pub struct DataWriter<'a> {
    dot: DotWriter<'a, BufWriter<WriteHalf<SharedConn>>>,
    reader: &'a mut TextReader,
}

impl Write for DataWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.dot.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.dot.flush()
    }
}

impl DataWriter<'_> {
    /// Ends the message and reads the server's 250 response; the dot writer's
    /// own close error is ignored, as in Go.
    pub fn close(self) -> Result<(), Error> {
        let DataWriter { dot, reader } = self;
        let _ = dot.close();
        reader.read_response(250)?;
        Ok(())
    }
}

/// Go's `smtp.SendMail`: connects to the server at `addr`, switches to TLS if
/// possible, authenticates with the optional mechanism `a` if possible, and
/// then sends an email from address `from`, to addresses `to`, with message
/// `msg`. The `addr` must include a port, as in "mail.example.com:smtp".
///
/// `msg` should be an RFC 822-style email with headers first, a blank line,
/// and then the body, with CRLF-terminated lines. To send "Bcc" messages,
/// include the address in `to` but not in the message headers.
///
/// Go always upgrades with STARTTLS when the server offers it, using its own
/// TLS stack. This crate has none, so `tls` supplies the handshake; if the
/// server advertises STARTTLS and `tls` is `None`, the call fails rather than
/// sending the message in the clear.
pub fn send_mail(
    addr: &str,
    a: Option<&mut (dyn Auth + '_)>,
    from: &str,
    to: &[&str],
    msg: &[u8],
    tls: Option<&dyn TlsConfig>,
) -> Result<(), Error> {
    validate_line(from)?;
    for recp in to {
        validate_line(recp)?;
    }
    let mut c = dial(addr)?;
    let result = send_mail_on(&mut c, a, from, to, msg, tls);
    let _ = c.close();
    result
}

fn send_mail_on(
    c: &mut Client,
    a: Option<&mut (dyn Auth + '_)>,
    from: &str,
    to: &[&str],
    msg: &[u8],
    tls: Option<&dyn TlsConfig>,
) -> Result<(), Error> {
    c.hello_once()?;
    if c.extension("STARTTLS").0 {
        let Some(tls) = tls else {
            return Err(Error::msg(
                "smtp: server offers STARTTLS but no TLS configuration was supplied",
            ));
        };
        c.start_tls(tls)?;
    }
    if let Some(a) = a {
        if let Some(ext) = &c.ext {
            if !ext.contains_key("AUTH") {
                return Err(Error::msg("smtp: server doesn't support AUTH"));
            }
            c.auth(a)?;
        }
    }
    c.mail(from)?;
    for addr in to {
        c.rcpt(addr)?;
    }
    let mut w = c.data()?;
    w.write_all(msg)?;
    w.close()?;
    c.quit()
}
