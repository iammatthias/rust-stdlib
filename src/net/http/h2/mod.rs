//! HTTP/2 for net/http: the protocol engine behind `Server`'s `h2` and
//! `h2c` support and `Transport`'s HTTP/2 connections.
//!
//! Layout: [`hpack`], [`frame`], `flow` and `pipe` are pure codecs and
//! bookkeeping with no sockets or threads; `server` and `transport` run one
//! connection each with a reader thread, a writer thread and one thread per
//! request, the synchronous counterpart of Go's goroutine structure. Ported
//! from Go's `net/http/internal/http2` (BSD-3-Clause, see `NOTICE`).
mod cipher_tables;
pub mod flow;
pub mod frame;
pub mod hpack;
mod hpack_tables;
pub mod pipe;
mod sched;
pub(crate) mod server;
mod sfv;
pub(crate) mod transport;

use super::header::Http2Config;
use crate::time::Duration;
use frame::{err_code_string, ErrCode};
use std::{fmt, sync::Arc};

/// Go's `ClientPreface`.
pub use frame::CLIENT_PREFACE;
/// The ALPN protocol name of HTTP/2 over TLS (`NextProtoTLS`).
pub const NEXT_PROTO_TLS: &str = "h2";
/// `TLSNextProto` key for unencrypted HTTP/2 (Go's `nextProtoUnencryptedHTTP2`).
pub const NEXT_PROTO_UNENCRYPTED_HTTP2: &str = "unencrypted_http2";

pub(crate) const INITIAL_MAX_FRAME_SIZE: u32 = 16384;
pub(crate) const INITIAL_HEADER_TABLE_SIZE: u32 = 4096;
pub(crate) const INITIAL_WINDOW_SIZE: i32 = 65535;
pub(crate) const DEFAULT_MAX_READ_FRAME_SIZE: i64 = 1 << 20;
pub(crate) const DEFAULT_MAX_STREAMS: i64 = 250;
pub(crate) const TRANSPORT_DEFAULT_CONN_FLOW: i64 = 1 << 30;
pub(crate) const TRANSPORT_DEFAULT_STREAM_FLOW: i64 = 4 << 20;

/// Every error the HTTP/2 engine reports. The `Display` texts are Go's.
#[derive(Clone, Debug)]
pub enum H2Error {
    /// Go's `io.EOF`.
    Eof,
    /// Go's `io.ErrUnexpectedEOF`.
    UnexpectedEof,
    /// Go's `StreamError`.
    Stream {
        stream_id: u32,
        code: ErrCode,
        cause: Option<Arc<H2Error>>,
        /// Go's `errFromPeer` cause: the error arrived in a RST_STREAM.
        from_peer: bool,
    },
    /// Go's `ConnectionError`.
    Connection(ErrCode),
    /// Go's `GoAwayError`.
    GoAway {
        last_stream_id: u32,
        code: ErrCode,
        debug: String,
    },
    /// An error given only by its text (Go's `errors.New` sentinels).
    Msg(Arc<str>),
    /// A deadline passed (Go's `os.ErrDeadlineExceeded`).
    DeadlineExceeded,
    /// An I/O failure on the connection.
    Io(Arc<std::io::Error>),
}

impl H2Error {
    pub fn msg(s: impl AsRef<str>) -> Self {
        Self::Msg(Arc::from(s.as_ref()))
    }
    pub fn stream(stream_id: u32, code: ErrCode) -> Self {
        Self::Stream {
            stream_id,
            code,
            cause: None,
            from_peer: false,
        }
    }
    pub fn stream_cause(stream_id: u32, code: ErrCode, cause: H2Error) -> Self {
        Self::Stream {
            stream_id,
            code,
            cause: Some(Arc::new(cause)),
            from_peer: false,
        }
    }
    /// True for the sentinel error with this text.
    pub fn is_msg(&self, s: &str) -> bool {
        matches!(self, Self::Msg(m) if &**m == s)
    }
    pub fn is_eof(&self) -> bool {
        matches!(self, Self::Eof)
    }
    pub(crate) fn from_frame_error(e: frame::FrameError) -> Self {
        use frame::FrameError as F;
        match e {
            F::Eof => Self::Eof,
            F::UnexpectedEof => Self::UnexpectedEof,
            F::Io(e) => Self::Io(Arc::new(e)),
            F::Connection(c) => Self::Connection(c),
            F::Stream {
                stream_id,
                code,
                cause,
            } => Self::Stream {
                stream_id,
                code,
                cause: cause.map(|c| Arc::new(Self::msg(c))),
                from_peer: false,
            },
            other => Self::msg(other.to_string()),
        }
    }
    /// The error as an `io::Error` carrying this value (`EOF` is not an error).
    pub(crate) fn into_io(self) -> std::io::Error {
        let kind = match &self {
            Self::UnexpectedEof => std::io::ErrorKind::UnexpectedEof,
            Self::DeadlineExceeded => std::io::ErrorKind::TimedOut,
            _ => std::io::ErrorKind::Other,
        };
        std::io::Error::new(kind, self)
    }
}

impl fmt::Display for H2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eof => f.write_str("EOF"),
            Self::UnexpectedEof => f.write_str("unexpected EOF"),
            Self::Stream {
                stream_id,
                code,
                cause,
                from_peer,
            } => {
                let c = err_code_string(*code);
                if *from_peer {
                    // Go's errFromPeer text.
                    return write!(
                        f,
                        "stream error: stream ID {stream_id}; {c}; received from peer"
                    );
                }
                match cause {
                    Some(cause) => write!(f, "stream error: stream ID {stream_id}; {c}; {cause}"),
                    None => write!(f, "stream error: stream ID {stream_id}; {c}"),
                }
            }
            Self::Connection(c) => write!(f, "connection error: {}", err_code_string(*c)),
            Self::GoAway {
                last_stream_id,
                code,
                debug,
            } => write!(
                f,
                "http2: server sent GOAWAY and closed the connection; LastStreamID={last_stream_id}, ErrCode={}, debug={}",
                err_code_string(*code),
                crate::strconv::quote(debug)
            ),
            Self::Msg(m) => f.write_str(m),
            Self::DeadlineExceeded => f.write_str("i/o timeout"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for H2Error {}

/// Go's `http2.Config`, built from `HTTP2Config` with defaults applied.
#[derive(Clone)]
pub struct Config {
    pub max_concurrent_streams: i64,
    pub strict_max_concurrent_requests: bool,
    pub max_decoder_header_table_size: i64,
    pub max_encoder_header_table_size: i64,
    pub max_read_frame_size: i64,
    pub max_receive_buffer_per_connection: i64,
    pub max_receive_buffer_per_stream: i64,
    pub send_ping_timeout: Duration,
    pub ping_timeout: Duration,
    pub write_byte_timeout: Duration,
    pub permit_prohibited_cipher_suites: bool,
    pub count_error: Option<frame::CountError>,
}

fn set_default(v: &mut i64, min: i64, max: i64, def: i64) {
    if *v < min || *v > max {
        *v = def;
    }
}

impl Config {
    /// Go's `configFromServer`/`configFromTransport`: the merged
    /// `HTTP2Config` (server and transport values filled in over the
    /// zero config) with the package defaults for unset fields.
    pub fn from_http2(h: Option<&Http2Config>, server: bool) -> Self {
        let mut c = Config {
            max_concurrent_streams: 0,
            strict_max_concurrent_requests: false,
            max_decoder_header_table_size: 0,
            max_encoder_header_table_size: 0,
            max_read_frame_size: 0,
            max_receive_buffer_per_connection: 0,
            max_receive_buffer_per_stream: 0,
            send_ping_timeout: Duration::ZERO,
            ping_timeout: Duration::ZERO,
            write_byte_timeout: Duration::ZERO,
            permit_prohibited_cipher_suites: false,
            count_error: None,
        };
        if let Some(h) = h {
            c.max_concurrent_streams = h.max_concurrent_streams;
            c.strict_max_concurrent_requests = h.strict_max_concurrent_requests;
            c.max_encoder_header_table_size = h.max_encoder_header_table_size;
            c.max_decoder_header_table_size = h.max_decoder_header_table_size;
            c.max_read_frame_size = h.max_read_frame_size;
            c.max_receive_buffer_per_connection = h.max_receive_buffer_per_connection;
            c.max_receive_buffer_per_stream = h.max_receive_buffer_per_stream;
            c.send_ping_timeout = h.send_ping_timeout;
            c.ping_timeout = h.ping_timeout;
            c.write_byte_timeout = h.write_byte_timeout;
            c.permit_prohibited_cipher_suites = h.permit_prohibited_cipher_suites;
            c.count_error = h.count_error.clone();
        }
        let max = i64::from(i32::MAX);
        set_default(&mut c.max_concurrent_streams, 1, max, DEFAULT_MAX_STREAMS);
        set_default(
            &mut c.max_encoder_header_table_size,
            1,
            max,
            i64::from(INITIAL_HEADER_TABLE_SIZE),
        );
        set_default(
            &mut c.max_decoder_header_table_size,
            1,
            max,
            i64::from(INITIAL_HEADER_TABLE_SIZE),
        );
        if server {
            set_default(
                &mut c.max_receive_buffer_per_connection,
                i64::from(INITIAL_WINDOW_SIZE),
                max,
                1 << 20,
            );
            set_default(&mut c.max_receive_buffer_per_stream, 1, max, 1 << 20);
        } else {
            set_default(
                &mut c.max_receive_buffer_per_connection,
                i64::from(INITIAL_WINDOW_SIZE),
                max,
                TRANSPORT_DEFAULT_CONN_FLOW,
            );
            set_default(
                &mut c.max_receive_buffer_per_stream,
                1,
                max,
                TRANSPORT_DEFAULT_STREAM_FLOW,
            );
        }
        set_default(
            &mut c.max_read_frame_size,
            i64::from(frame::MIN_MAX_FRAME_SIZE),
            i64::from(frame::MAX_FRAME_SIZE),
            DEFAULT_MAX_READ_FRAME_SIZE,
        );
        if c.ping_timeout.is_zero() {
            c.ping_timeout = Duration::from_secs(15);
        }
        c
    }
}

/// Go's `mergeHTTP2Config` for the two-source case: `a` wins field by field.
pub(crate) fn merge_http2_config(
    a: Option<&Http2Config>,
    b: Option<&Http2Config>,
) -> Option<Http2Config> {
    match (a, b) {
        (None, None) => None,
        (Some(x), None) | (None, Some(x)) => Some(x.clone()),
        (Some(a), Some(b)) => {
            let mut c = a.clone();
            if c.max_concurrent_streams == 0 {
                c.max_concurrent_streams = b.max_concurrent_streams;
            }
            c.strict_max_concurrent_requests |= b.strict_max_concurrent_requests;
            if c.max_decoder_header_table_size == 0 {
                c.max_decoder_header_table_size = b.max_decoder_header_table_size;
            }
            if c.max_encoder_header_table_size == 0 {
                c.max_encoder_header_table_size = b.max_encoder_header_table_size;
            }
            if c.max_read_frame_size == 0 {
                c.max_read_frame_size = b.max_read_frame_size;
            }
            if c.max_receive_buffer_per_connection == 0 {
                c.max_receive_buffer_per_connection = b.max_receive_buffer_per_connection;
            }
            if c.max_receive_buffer_per_stream == 0 {
                c.max_receive_buffer_per_stream = b.max_receive_buffer_per_stream;
            }
            if c.send_ping_timeout.is_zero() {
                c.send_ping_timeout = b.send_ping_timeout;
            }
            if c.ping_timeout.is_zero() {
                c.ping_timeout = b.ping_timeout;
            }
            if c.write_byte_timeout.is_zero() {
                c.write_byte_timeout = b.write_byte_timeout;
            }
            c.permit_prohibited_cipher_suites |= b.permit_prohibited_cipher_suites;
            if c.count_error.is_none() {
                c.count_error = b.count_error.clone();
            }
            Some(c)
        }
    }
}

/// Go's `isBadCipher`: TLS 1.2 cipher suites HTTP/2 prohibits.
pub fn is_bad_cipher(cipher: u16) -> bool {
    cipher_tables::BAD_CIPHERS.binary_search(&cipher).is_ok()
}

/// Go's `adjustHTTP1MaxHeaderSize`.
pub(crate) fn adjust_http1_max_header_size(n: i64) -> i64 {
    const PER_FIELD_OVERHEAD: i64 = 32;
    const TYPICAL_HEADERS: i64 = 10;
    n + TYPICAL_HEADERS * PER_FIELD_OVERHEAD
}

/// Go's `bodyAllowedForStatus`.
pub(crate) fn body_allowed_for_status(status: u16) -> bool {
    !((100..=199).contains(&status) || status == 204 || status == 304)
}

/// `foreachHeaderElement`: calls `f` for each comma-separated, trimmed,
/// non-empty element of a header value.
pub(crate) fn foreach_header_element(v: &str, mut f: impl FnMut(&str)) {
    let v = v.trim_matches(|c| c == ' ' || c == '\t');
    if v.is_empty() {
        return;
    }
    if !v.contains(',') {
        f(v);
        return;
    }
    for part in v.split(',') {
        let part = part.trim_matches(|c| c == ' ' || c == '\t');
        if !part.is_empty() {
            f(part);
        }
    }
}
