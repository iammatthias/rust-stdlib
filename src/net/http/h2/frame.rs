//! The HTTP/2 frame codec: every frame type of RFC 9113 plus PRIORITY_UPDATE
//! (RFC 9218), read with Go's validation rules and written one `Write` call
//! at a time. Ported from Go's `net/http/internal/http2/frame.go`.
//!
//! The codec is pure: it works over `io::Read`/`io::Write` and owns no
//! threads or connections.
use super::hpack::{Decoder, HeaderField};
use super::sfv;
use std::{fmt, io, sync::Arc};

pub const FRAME_HEADER_LEN: usize = 9;
pub const MIN_MAX_FRAME_SIZE: u32 = 1 << 14;
pub const MAX_FRAME_SIZE: u32 = (1 << 24) - 1;
/// The client connection preface (RFC 9113 section 3.4).
pub const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// ------------------------------------------------------------ error codes

/// An HTTP/2 error code.
pub type ErrCode = u32;
pub const ERR_CODE_NO: ErrCode = 0x0;
pub const ERR_CODE_PROTOCOL: ErrCode = 0x1;
pub const ERR_CODE_INTERNAL: ErrCode = 0x2;
pub const ERR_CODE_FLOW_CONTROL: ErrCode = 0x3;
pub const ERR_CODE_SETTINGS_TIMEOUT: ErrCode = 0x4;
pub const ERR_CODE_STREAM_CLOSED: ErrCode = 0x5;
pub const ERR_CODE_FRAME_SIZE: ErrCode = 0x6;
pub const ERR_CODE_REFUSED_STREAM: ErrCode = 0x7;
pub const ERR_CODE_CANCEL: ErrCode = 0x8;
pub const ERR_CODE_COMPRESSION: ErrCode = 0x9;
pub const ERR_CODE_CONNECT: ErrCode = 0xa;
pub const ERR_CODE_ENHANCE_YOUR_CALM: ErrCode = 0xb;
pub const ERR_CODE_INADEQUATE_SECURITY: ErrCode = 0xc;
pub const ERR_CODE_HTTP_1_1_REQUIRED: ErrCode = 0xd;

fn err_code_name(c: ErrCode) -> Option<&'static str> {
    Some(match c {
        0x0 => "NO_ERROR",
        0x1 => "PROTOCOL_ERROR",
        0x2 => "INTERNAL_ERROR",
        0x3 => "FLOW_CONTROL_ERROR",
        0x4 => "SETTINGS_TIMEOUT",
        0x5 => "STREAM_CLOSED",
        0x6 => "FRAME_SIZE_ERROR",
        0x7 => "REFUSED_STREAM",
        0x8 => "CANCEL",
        0x9 => "COMPRESSION_ERROR",
        0xa => "CONNECT_ERROR",
        0xb => "ENHANCE_YOUR_CALM",
        0xc => "INADEQUATE_SECURITY",
        0xd => "HTTP_1_1_REQUIRED",
        _ => return None,
    })
}

/// Go's `ErrCode.String`.
pub fn err_code_string(c: ErrCode) -> String {
    err_code_name(c).map_or_else(|| format!("unknown error code 0x{c:x}"), str::to_owned)
}

/// Go's `ErrCode.stringToken`.
pub fn err_code_token(c: ErrCode) -> String {
    err_code_name(c).map_or_else(|| format!("ERR_UNKNOWN_{c}"), str::to_owned)
}

/// What can go wrong reading or writing a frame.
#[derive(Debug)]
pub enum FrameError {
    /// End of stream before any byte of the next frame (Go's `io.EOF`).
    Eof,
    /// End of stream inside a frame (Go's `io.ErrUnexpectedEOF`).
    UnexpectedEof,
    /// Any other I/O error from the underlying stream.
    Io(io::Error),
    /// Go's `ErrFrameTooLarge`; `http1` notes an HTTP/1.1-looking header.
    TooLarge { http1: bool },
    /// The payload could not be read for a frame that looked like HTTP/1.1.
    Http1Looking(Box<FrameError>),
    /// Go's `ConnectionError`.
    Connection(ErrCode),
    /// Go's `StreamError`.
    Stream {
        stream_id: u32,
        code: ErrCode,
        cause: Option<String>,
    },
    /// A write refused by the framer (invalid stream ID, bad padding...).
    Illegal(&'static str),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eof => f.write_str("EOF"),
            Self::UnexpectedEof => f.write_str("unexpected EOF"),
            Self::Io(e) => write!(f, "{e}"),
            Self::TooLarge { http1: false } => f.write_str("http2: frame too large"),
            Self::TooLarge { http1: true } => f.write_str(
                "http2: failed reading the frame payload: http2: frame too large, note that the frame header looked like an HTTP/1.1 header",
            ),
            Self::Http1Looking(e) => write!(
                f,
                "http2: failed reading the frame payload: {e}, note that the frame header looked like an HTTP/1.1 header"
            ),
            Self::Connection(c) => write!(f, "connection error: {}", err_code_string(*c)),
            Self::Stream {
                stream_id,
                code,
                cause,
            } => match cause {
                Some(c) => write!(
                    f,
                    "stream error: stream ID {stream_id}; {}; {c}",
                    err_code_string(*code)
                ),
                None => write!(
                    f,
                    "stream error: stream ID {stream_id}; {}",
                    err_code_string(*code)
                ),
            },
            Self::Illegal(s) => f.write_str(s),
        }
    }
}
impl std::error::Error for FrameError {}

impl From<io::Error> for FrameError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::UnexpectedEof => Self::UnexpectedEof,
            _ => Self::Io(e),
        }
    }
}

impl FrameError {
    /// Go's `terminalReadFrameError`: the frame stream is unusable.
    pub fn is_terminal(&self) -> bool {
        !matches!(self, Self::Stream { .. })
    }
}

// ------------------------------------------------------------- frame types

pub const FRAME_DATA: u8 = 0x0;
pub const FRAME_HEADERS: u8 = 0x1;
pub const FRAME_PRIORITY: u8 = 0x2;
pub const FRAME_RST_STREAM: u8 = 0x3;
pub const FRAME_SETTINGS: u8 = 0x4;
pub const FRAME_PUSH_PROMISE: u8 = 0x5;
pub const FRAME_PING: u8 = 0x6;
pub const FRAME_GOAWAY: u8 = 0x7;
pub const FRAME_WINDOW_UPDATE: u8 = 0x8;
pub const FRAME_CONTINUATION: u8 = 0x9;
pub const FRAME_PRIORITY_UPDATE: u8 = 0x10;

/// Go's `FrameType.String`.
pub fn frame_type_string(t: u8) -> String {
    match t {
        FRAME_DATA => "DATA".into(),
        FRAME_HEADERS => "HEADERS".into(),
        FRAME_PRIORITY => "PRIORITY".into(),
        FRAME_RST_STREAM => "RST_STREAM".into(),
        FRAME_SETTINGS => "SETTINGS".into(),
        FRAME_PUSH_PROMISE => "PUSH_PROMISE".into(),
        FRAME_PING => "PING".into(),
        FRAME_GOAWAY => "GOAWAY".into(),
        FRAME_WINDOW_UPDATE => "WINDOW_UPDATE".into(),
        FRAME_CONTINUATION => "CONTINUATION".into(),
        FRAME_PRIORITY_UPDATE => "PRIORITY_UPDATE".into(),
        _ => format!("UNKNOWN_FRAME_TYPE_{t}"),
    }
}

pub const FLAG_DATA_END_STREAM: u8 = 0x1;
pub const FLAG_DATA_PADDED: u8 = 0x8;
pub const FLAG_HEADERS_END_STREAM: u8 = 0x1;
pub const FLAG_HEADERS_END_HEADERS: u8 = 0x4;
pub const FLAG_HEADERS_PADDED: u8 = 0x8;
pub const FLAG_HEADERS_PRIORITY: u8 = 0x20;
pub const FLAG_SETTINGS_ACK: u8 = 0x1;
pub const FLAG_PING_ACK: u8 = 0x1;
pub const FLAG_CONTINUATION_END_HEADERS: u8 = 0x4;
pub const FLAG_PUSH_PROMISE_END_HEADERS: u8 = 0x4;
pub const FLAG_PUSH_PROMISE_PADDED: u8 = 0x8;

/// Go's `FrameHeader`: the 9 bytes preceding every frame payload.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FrameHeader {
    pub ftype: u8,
    pub flags: u8,
    pub length: u32,
    pub stream_id: u32,
}

impl FrameHeader {
    pub fn has(&self, flag: u8) -> bool {
        self.flags & flag == flag
    }
}

/// Go's `PriorityParam`, a superset of the RFC 7540 and RFC 9218 schemes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PriorityParam {
    pub stream_dep: u32,
    pub exclusive: bool,
    pub weight: u8,
    pub(crate) urgency: u8,
    pub(crate) incremental: u8,
}

impl PriorityParam {
    pub fn is_zero(&self) -> bool {
        *self == Self::default()
    }
    /// An RFC 7540 priority (dependency, exclusivity, zero-based weight).
    pub fn new(stream_dep: u32, exclusive: bool, weight: u8) -> Self {
        Self {
            stream_dep,
            exclusive,
            weight,
            ..Self::default()
        }
    }
    /// The RFC 9218 urgency, 0 (most urgent) to 7.
    pub fn urgency(&self) -> u8 {
        self.urgency
    }
    /// The RFC 9218 incremental flag (0 or 1).
    pub fn incremental(&self) -> u8 {
        self.incremental
    }
    /// An RFC 9218 priority with the given urgency and incremental flag.
    pub fn rfc9218(urgency: u8, incremental: bool) -> Self {
        Self {
            urgency,
            incremental: u8::from(incremental),
            ..Self::default()
        }
    }
}

/// Go's `defaultRFC9218Priority`.
pub fn default_rfc9218_priority(can_use_default: bool) -> PriorityParam {
    PriorityParam {
        urgency: 3,
        incremental: u8::from(!can_use_default),
        ..PriorityParam::default()
    }
}

/// Go's `parseRFC9218Priority`.
pub fn parse_rfc9218_priority(s: &str, can_use_default: bool) -> (PriorityParam, bool) {
    let mut p = default_rfc9218_priority(can_use_default);
    let ok = sfv::parse_dictionary(s, &mut |key, val, _| match key {
        "u" => {
            if let Some(u) = sfv::parse_integer(val) {
                if (0..=7).contains(&u) {
                    p.urgency = u as u8;
                }
            }
        }
        "i" => {
            if let Some(i) = sfv::parse_boolean(val) {
                p.incremental = u8::from(i);
            }
        }
        _ => {}
    });
    if !ok {
        return (default_rfc9218_priority(can_use_default), false);
    }
    (p, true)
}

/// A SETTINGS parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Setting {
    pub id: u16,
    pub val: u32,
}

pub const SETTING_HEADER_TABLE_SIZE: u16 = 0x1;
pub const SETTING_ENABLE_PUSH: u16 = 0x2;
pub const SETTING_MAX_CONCURRENT_STREAMS: u16 = 0x3;
pub const SETTING_INITIAL_WINDOW_SIZE: u16 = 0x4;
pub const SETTING_MAX_FRAME_SIZE: u16 = 0x5;
pub const SETTING_MAX_HEADER_LIST_SIZE: u16 = 0x6;
pub const SETTING_ENABLE_CONNECT_PROTOCOL: u16 = 0x8;
pub const SETTING_NO_RFC7540_PRIORITIES: u16 = 0x9;

/// Go's `SettingID.String`.
pub fn setting_name(id: u16) -> String {
    match id {
        SETTING_HEADER_TABLE_SIZE => "HEADER_TABLE_SIZE".into(),
        SETTING_ENABLE_PUSH => "ENABLE_PUSH".into(),
        SETTING_MAX_CONCURRENT_STREAMS => "MAX_CONCURRENT_STREAMS".into(),
        SETTING_INITIAL_WINDOW_SIZE => "INITIAL_WINDOW_SIZE".into(),
        SETTING_MAX_FRAME_SIZE => "MAX_FRAME_SIZE".into(),
        SETTING_MAX_HEADER_LIST_SIZE => "MAX_HEADER_LIST_SIZE".into(),
        SETTING_ENABLE_CONNECT_PROTOCOL => "ENABLE_CONNECT_PROTOCOL".into(),
        SETTING_NO_RFC7540_PRIORITIES => "NO_RFC7540_PRIORITIES".into(),
        _ => format!("UNKNOWN_SETTING_{id}"),
    }
}

impl Setting {
    /// Go's `Setting.Valid`: the connection error code for an illegal value.
    pub fn valid(&self) -> Result<(), ErrCode> {
        match self.id {
            SETTING_ENABLE_PUSH | SETTING_ENABLE_CONNECT_PROTOCOL if self.val > 1 => {
                Err(ERR_CODE_PROTOCOL)
            }
            SETTING_INITIAL_WINDOW_SIZE if self.val > (1 << 31) - 1 => Err(ERR_CODE_FLOW_CONTROL),
            SETTING_MAX_FRAME_SIZE if !(16384..=(1 << 24) - 1).contains(&self.val) => {
                Err(ERR_CODE_PROTOCOL)
            }
            _ => Ok(()),
        }
    }
}

/// A parsed frame. Payload bytes are owned copies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Data {
        header: FrameHeader,
        data: Vec<u8>,
    },
    Headers {
        header: FrameHeader,
        priority: PriorityParam,
        fragment: Vec<u8>,
    },
    Priority {
        header: FrameHeader,
        priority: PriorityParam,
    },
    RstStream {
        header: FrameHeader,
        code: ErrCode,
    },
    Settings {
        header: FrameHeader,
        settings: Vec<Setting>,
    },
    PushPromise {
        header: FrameHeader,
        promise_id: u32,
        fragment: Vec<u8>,
    },
    Ping {
        header: FrameHeader,
        data: [u8; 8],
    },
    GoAway {
        header: FrameHeader,
        last_stream_id: u32,
        code: ErrCode,
        debug_data: Vec<u8>,
    },
    WindowUpdate {
        header: FrameHeader,
        increment: u32,
    },
    Continuation {
        header: FrameHeader,
        fragment: Vec<u8>,
    },
    PriorityUpdate {
        header: FrameHeader,
        priority: Vec<u8>,
        prioritized_stream_id: u32,
    },
    Unknown {
        header: FrameHeader,
        payload: Vec<u8>,
    },
    /// HEADERS plus CONTINUATION frames merged and HPACK-decoded; only
    /// produced when a decoder is installed with
    /// [`FrameReader::set_meta_headers_decoder`].
    Meta(MetaHeadersFrame),
}

impl Frame {
    pub fn header(&self) -> FrameHeader {
        match self {
            Self::Data { header, .. }
            | Self::Headers { header, .. }
            | Self::Priority { header, .. }
            | Self::RstStream { header, .. }
            | Self::Settings { header, .. }
            | Self::PushPromise { header, .. }
            | Self::Ping { header, .. }
            | Self::GoAway { header, .. }
            | Self::WindowUpdate { header, .. }
            | Self::Continuation { header, .. }
            | Self::PriorityUpdate { header, .. }
            | Self::Unknown { header, .. } => *header,
            Self::Meta(m) => m.header,
        }
    }
}

/// Go's `MetaHeadersFrame`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetaHeadersFrame {
    pub header: FrameHeader,
    pub priority: PriorityParam,
    pub fields: Vec<HeaderField>,
    pub truncated: bool,
}

impl MetaHeadersFrame {
    pub fn stream_ended(&self) -> bool {
        self.header.has(FLAG_HEADERS_END_STREAM)
    }
    pub fn has_priority(&self) -> bool {
        self.header.has(FLAG_HEADERS_PRIORITY)
    }
    /// Go's `PseudoValue`; `pseudo` has no leading colon.
    pub fn pseudo_value(&self, pseudo: &str) -> &[u8] {
        for hf in &self.fields {
            if !hf.is_pseudo() {
                return b"";
            }
            if &hf.name[1..] == pseudo.as_bytes() {
                return &hf.value;
            }
        }
        b""
    }
    /// Go's `RegularFields`.
    pub fn regular_fields(&self) -> &[HeaderField] {
        match self.fields.iter().position(|f| !f.is_pseudo()) {
            Some(i) => &self.fields[i..],
            None => &[],
        }
    }
    /// Go's `PseudoFields`.
    pub fn pseudo_fields(&self) -> &[HeaderField] {
        match self.fields.iter().position(|f| !f.is_pseudo()) {
            Some(i) => &self.fields[..i],
            None => &self.fields,
        }
    }
    /// Go's `rfc9218Priority`.
    pub fn rfc9218_priority(&self, mut priority_aware: bool) -> (PriorityParam, bool, bool) {
        let mut s = String::new();
        let mut has_intermediary = false;
        for field in &self.fields {
            if field.name == b"priority" {
                s = String::from_utf8_lossy(&field.value).into_owned();
                priority_aware = true;
            }
            if [&b"via"[..], b"forwarded", b"x-forwarded-for"].contains(&&field.name[..]) {
                has_intermediary = true;
            }
        }
        let (p, _) = parse_rfc9218_priority(&s, priority_aware && !has_intermediary);
        (p, priority_aware, has_intermediary)
    }
    fn check_pseudos(&self) -> Result<(), String> {
        let (mut is_request, mut is_response) = (false, false);
        let pf = self.pseudo_fields();
        for (i, hf) in pf.iter().enumerate() {
            match &hf.name[..] {
                b":method" | b":path" | b":scheme" | b":authority" | b":protocol" => {
                    is_request = true;
                }
                b":status" => is_response = true,
                _ => return Err(format!("invalid pseudo-header {}", go_quote(&hf.name))),
            }
            if pf[..i].iter().any(|h2| h2.name == hf.name) {
                return Err(format!("duplicate pseudo-header {}", go_quote(&hf.name)));
            }
        }
        if is_request && is_response {
            return Err("mix of request and response pseudo headers".into());
        }
        Ok(())
    }
}

/// Go's `%q` for a byte string (ASCII-safe subset used in error texts).
fn go_quote(b: &[u8]) -> String {
    crate::strconv::quote(b)
}

/// `httpguts.ValidHeaderFieldValue` over bytes.
pub fn valid_header_field_value(v: &[u8]) -> bool {
    v.iter()
        .all(|&b| !(b < b' ' || b == 0x7f) || b == b' ' || b == b'\t')
}

/// `validWireHeaderFieldName`: a token without upper-case letters.
pub fn valid_wire_header_field_name(v: &[u8]) -> bool {
    !v.is_empty()
        && v.iter()
            .all(|&b| is_token_byte(b) && !b.is_ascii_uppercase())
}

fn is_token_byte(b: u8) -> bool {
    matches!(b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_'
        | b'`' | b'|' | b'~' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z')
}

// ----------------------------------------------------------------- reader

pub type CountError = Arc<dyn Fn(&str) + Send + Sync>;

/// Go's `Framer` read half.
pub struct FrameReader<R: io::Read> {
    r: R,
    last_header_stream: u32,
    last_frame_type: u8,
    max_read_size: u32,
    err_detail: Option<String>,
    count_error: Option<CountError>,
    /// Go's `AllowIllegalReads`.
    pub allow_illegal_reads: bool,
    meta: Option<Decoder>,
    max_header_list_size: u32,
    max_header_value_count: usize,
}

fn read_full<R: io::Read>(r: &mut R, buf: &mut [u8]) -> Result<(), FrameError> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => {
                return Err(if n == 0 {
                    FrameError::Eof
                } else {
                    FrameError::UnexpectedEof
                })
            }
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// A frame parse failure: a connection error with its reason, or a final error.
enum Parse {
    Conn(ErrCode, Option<String>),
    Err(FrameError),
}

impl<R: io::Read> FrameReader<R> {
    /// Go's `NewFramer` (read half): reads up to the maximum frame size.
    pub fn new(r: R) -> Self {
        Self {
            r,
            last_header_stream: 0,
            last_frame_type: 0,
            max_read_size: MAX_FRAME_SIZE,
            err_detail: None,
            count_error: None,
            allow_illegal_reads: false,
            meta: None,
            max_header_list_size: 0,
            max_header_value_count: 0,
        }
    }
    pub fn get_ref(&self) -> &R {
        &self.r
    }
    /// Go's `SetMaxReadFrameSize`.
    pub fn set_max_read_frame_size(&mut self, v: u32) {
        self.max_read_size = v.min(MAX_FRAME_SIZE);
    }
    /// Sets the callback invoked with a token on each frame parse error
    /// (`Config.CountError`).
    pub fn set_count_error(&mut self, f: Option<CountError>) {
        self.count_error = f;
    }
    /// Go's `ReadMetaHeaders`: merge HEADERS and CONTINUATION frames and
    /// decode them with `d`.
    pub fn set_meta_headers_decoder(&mut self, d: Option<Decoder>) {
        self.meta = d;
    }
    pub fn meta_headers_decoder(&mut self) -> Option<&mut Decoder> {
        self.meta.as_mut()
    }
    /// Go's `MaxHeaderListSize`; 0 means 16 MiB.
    pub fn set_max_header_list_size(&mut self, v: u32) {
        self.max_header_list_size = v;
    }
    /// Go's `MaxHeaderValueCount`; 0 means no limit.
    pub fn set_max_header_value_count(&mut self, v: usize) {
        self.max_header_value_count = v;
    }
    /// Go's `ErrorDetail`.
    pub fn error_detail(&self) -> Option<&str> {
        self.err_detail.as_deref()
    }

    fn max_header_list_size(&self) -> u32 {
        if self.max_header_list_size == 0 {
            16 << 20
        } else {
            self.max_header_list_size
        }
    }

    fn count(&self, token: &str) {
        if let Some(f) = &self.count_error {
            f(token);
        }
    }

    fn conn_error(&mut self, code: ErrCode, reason: &str) -> FrameError {
        self.err_detail = Some(reason.to_owned());
        FrameError::Connection(code)
    }

    fn http1_looking(fh: &FrameHeader) -> bool {
        // readFrameHeader of "HTTP/1.1 ".
        *fh == FrameHeader {
            ftype: b'P',
            flags: b'/',
            length: 0x48_54_54,
            stream_id: 0x312e_3120 & 0x7fff_ffff,
        }
    }

    /// Go's `ReadFrameHeader`.
    pub fn read_frame_header(&mut self) -> Result<FrameHeader, (Option<FrameHeader>, FrameError)> {
        self.err_detail = None;
        let mut buf = [0u8; FRAME_HEADER_LEN];
        read_full(&mut self.r, &mut buf).map_err(|e| (None, e))?;
        let fh = FrameHeader {
            length: u32::from(buf[0]) << 16 | u32::from(buf[1]) << 8 | u32::from(buf[2]),
            ftype: buf[3],
            flags: buf[4],
            stream_id: u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7fff_ffff,
        };
        if fh.length > self.max_read_size {
            return Err((
                Some(fh),
                FrameError::TooLarge {
                    http1: Self::http1_looking(&fh),
                },
            ));
        }
        self.check_frame_order(&fh).map_err(|e| (Some(fh), e))?;
        Ok(fh)
    }

    fn check_frame_order(&mut self, fh: &FrameHeader) -> Result<(), FrameError> {
        let last_type = self.last_frame_type;
        self.last_frame_type = fh.ftype;
        if self.allow_illegal_reads {
            return Ok(());
        }
        if self.last_header_stream != 0 {
            if fh.ftype != FRAME_CONTINUATION {
                let reason = format!(
                    "got {} for stream {}; expected CONTINUATION following {} for stream {}",
                    frame_type_string(fh.ftype),
                    fh.stream_id,
                    frame_type_string(last_type),
                    self.last_header_stream
                );
                return Err(self.conn_error(ERR_CODE_PROTOCOL, &reason));
            }
            if fh.stream_id != self.last_header_stream {
                let reason = format!(
                    "got CONTINUATION for stream {}; expected stream {}",
                    fh.stream_id, self.last_header_stream
                );
                return Err(self.conn_error(ERR_CODE_PROTOCOL, &reason));
            }
        } else if fh.ftype == FRAME_CONTINUATION {
            let reason = format!("unexpected CONTINUATION for stream {}", fh.stream_id);
            return Err(self.conn_error(ERR_CODE_PROTOCOL, &reason));
        }
        if fh.ftype == FRAME_HEADERS || fh.ftype == FRAME_CONTINUATION {
            self.last_header_stream = if fh.has(FLAG_HEADERS_END_HEADERS) {
                0
            } else {
                fh.stream_id
            };
        }
        Ok(())
    }

    /// Go's `ReadFrame`.
    pub fn read_frame(&mut self) -> Result<Frame, FrameError> {
        let fh = self.read_frame_header().map_err(|(_, e)| e)?;
        self.read_frame_for_header(fh)
    }

    /// Go's `ReadFrameForHeader`.
    pub fn read_frame_for_header(&mut self, fh: FrameHeader) -> Result<Frame, FrameError> {
        let mut payload = vec![0u8; fh.length as usize];
        if let Err(e) = read_full(&mut self.r, &mut payload) {
            if Self::http1_looking(&fh) {
                return Err(FrameError::Http1Looking(Box::new(e)));
            }
            return Err(e);
        }
        let f = match self.parse(fh, payload) {
            Ok(f) => f,
            Err(Parse::Conn(code, reason)) => {
                if let Some(r) = reason {
                    self.err_detail = Some(r);
                }
                return Err(FrameError::Connection(code));
            }
            Err(Parse::Err(e)) => return Err(e),
        };
        if fh.ftype == FRAME_HEADERS && self.meta.is_some() {
            if let Frame::Headers {
                header,
                priority,
                fragment,
            } = f
            {
                return self.read_meta_frame(header, priority, fragment);
            }
        }
        Ok(f)
    }

    fn parse(&mut self, fh: FrameHeader, p: Vec<u8>) -> Result<Frame, Parse> {
        let conn = |code, reason: &str| Parse::Conn(code, Some(reason.to_owned()));
        let conn_plain = |code| Parse::Conn(code, None);
        match fh.ftype {
            FRAME_DATA => {
                if fh.stream_id == 0 {
                    self.count("frame_data_stream_0");
                    return Err(conn(ERR_CODE_PROTOCOL, "DATA frame with stream ID 0"));
                }
                let mut p = &p[..];
                let mut pad = 0usize;
                if fh.has(FLAG_DATA_PADDED) {
                    let Some((&b, rest)) = p.split_first() else {
                        self.count("frame_data_pad_byte_short");
                        return Err(Parse::Err(FrameError::UnexpectedEof));
                    };
                    pad = b as usize;
                    p = rest;
                }
                if pad > p.len() {
                    self.count("frame_data_pad_too_big");
                    return Err(conn(ERR_CODE_PROTOCOL, "pad size larger than data payload"));
                }
                Ok(Frame::Data {
                    header: fh,
                    data: p[..p.len() - pad].to_vec(),
                })
            }
            FRAME_HEADERS => {
                if fh.stream_id == 0 {
                    self.count("frame_headers_zero_stream");
                    return Err(conn(ERR_CODE_PROTOCOL, "HEADERS frame with stream ID 0"));
                }
                let mut p = &p[..];
                let mut pad = 0usize;
                if fh.has(FLAG_HEADERS_PADDED) {
                    let Some((&b, rest)) = p.split_first() else {
                        self.count("frame_headers_pad_short");
                        return Err(Parse::Err(FrameError::UnexpectedEof));
                    };
                    pad = b as usize;
                    p = rest;
                }
                let mut prio = PriorityParam::default();
                if fh.has(FLAG_HEADERS_PRIORITY) {
                    if p.len() < 4 {
                        self.count("frame_headers_prio_short");
                        return Err(Parse::Err(FrameError::UnexpectedEof));
                    }
                    let v = u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
                    p = &p[4..];
                    prio.stream_dep = v & 0x7fff_ffff;
                    prio.exclusive = v != prio.stream_dep;
                    let Some((&w, rest)) = p.split_first() else {
                        self.count("frame_headers_prio_weight_short");
                        return Err(Parse::Err(FrameError::UnexpectedEof));
                    };
                    prio.weight = w;
                    p = rest;
                }
                if p.len() < pad {
                    self.count("frame_headers_pad_too_big");
                    return Err(Parse::Err(FrameError::Stream {
                        stream_id: fh.stream_id,
                        code: ERR_CODE_PROTOCOL,
                        cause: None,
                    }));
                }
                Ok(Frame::Headers {
                    header: fh,
                    priority: prio,
                    fragment: p[..p.len() - pad].to_vec(),
                })
            }
            FRAME_PRIORITY => {
                if fh.stream_id == 0 {
                    self.count("frame_priority_zero_stream");
                    return Err(conn(ERR_CODE_PROTOCOL, "PRIORITY frame with stream ID 0"));
                }
                if p.len() != 5 {
                    self.count("frame_priority_bad_length");
                    return Err(conn(
                        ERR_CODE_FRAME_SIZE,
                        &format!("PRIORITY frame payload size was {}; want 5", p.len()),
                    ));
                }
                let v = u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
                let id = v & 0x7fff_ffff;
                Ok(Frame::Priority {
                    header: fh,
                    priority: PriorityParam {
                        weight: p[4],
                        stream_dep: id,
                        exclusive: id != v,
                        ..PriorityParam::default()
                    },
                })
            }
            FRAME_RST_STREAM => {
                if p.len() != 4 {
                    self.count("frame_rststream_bad_len");
                    return Err(conn_plain(ERR_CODE_FRAME_SIZE));
                }
                if fh.stream_id == 0 {
                    self.count("frame_rststream_zero_stream");
                    return Err(conn_plain(ERR_CODE_PROTOCOL));
                }
                Ok(Frame::RstStream {
                    header: fh,
                    code: u32::from_be_bytes([p[0], p[1], p[2], p[3]]),
                })
            }
            FRAME_SETTINGS => {
                if fh.has(FLAG_SETTINGS_ACK) && fh.length > 0 {
                    self.count("frame_settings_ack_with_length");
                    return Err(conn_plain(ERR_CODE_FRAME_SIZE));
                }
                if fh.stream_id != 0 {
                    self.count("frame_settings_has_stream");
                    return Err(conn_plain(ERR_CODE_PROTOCOL));
                }
                if !p.len().is_multiple_of(6) {
                    self.count("frame_settings_mod_6");
                    return Err(conn_plain(ERR_CODE_FRAME_SIZE));
                }
                let settings: Vec<Setting> = p
                    .chunks_exact(6)
                    .map(|c| Setting {
                        id: u16::from_be_bytes([c[0], c[1]]),
                        val: u32::from_be_bytes([c[2], c[3], c[4], c[5]]),
                    })
                    .collect();
                if let Some(s) = settings
                    .iter()
                    .find(|s| s.id == SETTING_INITIAL_WINDOW_SIZE)
                {
                    if s.val > (1 << 31) - 1 {
                        self.count("frame_settings_window_size_too_big");
                        return Err(conn_plain(ERR_CODE_FLOW_CONTROL));
                    }
                }
                Ok(Frame::Settings {
                    header: fh,
                    settings,
                })
            }
            FRAME_PUSH_PROMISE => {
                if fh.stream_id == 0 {
                    self.count("frame_pushpromise_zero_stream");
                    return Err(conn_plain(ERR_CODE_PROTOCOL));
                }
                let mut p = &p[..];
                let mut pad = 0usize;
                if fh.has(FLAG_PUSH_PROMISE_PADDED) {
                    let Some((&b, rest)) = p.split_first() else {
                        self.count("frame_pushpromise_pad_short");
                        return Err(Parse::Err(FrameError::UnexpectedEof));
                    };
                    pad = b as usize;
                    p = rest;
                }
                if p.len() < 4 {
                    self.count("frame_pushpromise_promiseid_short");
                    return Err(Parse::Err(FrameError::UnexpectedEof));
                }
                let promise_id = u32::from_be_bytes([p[0], p[1], p[2], p[3]]) & 0x7fff_ffff;
                p = &p[4..];
                if pad > p.len() {
                    self.count("frame_pushpromise_pad_too_big");
                    return Err(conn_plain(ERR_CODE_PROTOCOL));
                }
                Ok(Frame::PushPromise {
                    header: fh,
                    promise_id,
                    fragment: p[..p.len() - pad].to_vec(),
                })
            }
            FRAME_PING => {
                if p.len() != 8 {
                    self.count("frame_ping_length");
                    return Err(conn_plain(ERR_CODE_FRAME_SIZE));
                }
                if fh.stream_id != 0 {
                    self.count("frame_ping_has_stream");
                    return Err(conn_plain(ERR_CODE_PROTOCOL));
                }
                let mut data = [0u8; 8];
                data.copy_from_slice(&p);
                Ok(Frame::Ping { header: fh, data })
            }
            FRAME_GOAWAY => {
                if fh.stream_id != 0 {
                    self.count("frame_goaway_has_stream");
                    return Err(conn_plain(ERR_CODE_PROTOCOL));
                }
                if p.len() < 8 {
                    self.count("frame_goaway_short");
                    return Err(conn_plain(ERR_CODE_FRAME_SIZE));
                }
                Ok(Frame::GoAway {
                    header: fh,
                    last_stream_id: u32::from_be_bytes([p[0], p[1], p[2], p[3]]) & 0x7fff_ffff,
                    code: u32::from_be_bytes([p[4], p[5], p[6], p[7]]),
                    debug_data: p[8..].to_vec(),
                })
            }
            FRAME_WINDOW_UPDATE => {
                if p.len() != 4 {
                    self.count("frame_windowupdate_bad_len");
                    return Err(conn_plain(ERR_CODE_FRAME_SIZE));
                }
                let inc = u32::from_be_bytes([p[0], p[1], p[2], p[3]]) & 0x7fff_ffff;
                if inc == 0 {
                    if fh.stream_id == 0 {
                        self.count("frame_windowupdate_zero_inc_conn");
                        return Err(conn_plain(ERR_CODE_PROTOCOL));
                    }
                    self.count("frame_windowupdate_zero_inc_stream");
                    return Err(Parse::Err(FrameError::Stream {
                        stream_id: fh.stream_id,
                        code: ERR_CODE_PROTOCOL,
                        cause: None,
                    }));
                }
                Ok(Frame::WindowUpdate {
                    header: fh,
                    increment: inc,
                })
            }
            FRAME_CONTINUATION => {
                if fh.stream_id == 0 {
                    self.count("frame_continuation_zero_stream");
                    return Err(conn(
                        ERR_CODE_PROTOCOL,
                        "CONTINUATION frame with stream ID 0",
                    ));
                }
                Ok(Frame::Continuation {
                    header: fh,
                    fragment: p,
                })
            }
            FRAME_PRIORITY_UPDATE => {
                if fh.stream_id != 0 {
                    self.count("frame_priority_update_non_zero_stream");
                    return Err(conn(
                        ERR_CODE_PROTOCOL,
                        "PRIORITY_UPDATE frame with non-zero stream ID",
                    ));
                }
                if p.len() < 4 {
                    self.count("frame_priority_update_bad_length");
                    return Err(conn(
                        ERR_CODE_FRAME_SIZE,
                        &format!(
                            "PRIORITY_UPDATE frame payload size was {}; want at least 4",
                            p.len()
                        ),
                    ));
                }
                let id = u32::from_be_bytes([p[0], p[1], p[2], p[3]]) & 0x7fff_ffff;
                if id == 0 {
                    self.count("frame_priority_update_prioritizing_zero_stream");
                    return Err(conn(
                        ERR_CODE_PROTOCOL,
                        "PRIORITY_UPDATE frame with prioritized stream ID of zero",
                    ));
                }
                Ok(Frame::PriorityUpdate {
                    header: fh,
                    prioritized_stream_id: id,
                    priority: p[4..].to_vec(),
                })
            }
            _ => Ok(Frame::Unknown {
                header: fh,
                payload: p,
            }),
        }
    }

    /// Go's `readMetaFrame`.
    fn read_meta_frame(
        &mut self,
        header: FrameHeader,
        priority: PriorityParam,
        first: Vec<u8>,
    ) -> Result<Frame, FrameError> {
        if self.allow_illegal_reads {
            return Err(FrameError::Illegal(
                "illegal use of AllowIllegalReads with ReadMetaHeaders",
            ));
        }
        let mut mh = MetaHeadersFrame {
            header,
            priority,
            fields: Vec::new(),
            truncated: false,
        };
        let mut remain_size = i64::from(self.max_header_list_size());
        let mut saw_regular = false;
        let mut header_count = 0usize;
        let mut invalid: Option<String> = None;
        let value_limit = self.max_header_value_count;
        let max_str = {
            let v = self.max_header_list_size() as i64;
            if v < 0 {
                0
            } else {
                v as usize
            }
        };
        let mut hdec = self.meta.take().expect("meta decoder");
        hdec.set_emit_enabled(true);
        hdec.set_max_string_length(max_str);
        let mut frag = first;
        let mut hc_header = header;
        let result: Result<(), FrameError> = loop {
            // Avoid parsing large amounts of headers that we will then discard.
            if frag.len() as i64 > 2 * remain_size {
                break Err(FrameError::Connection(ERR_CODE_PROTOCOL));
            }
            if invalid.is_some() {
                break Err(FrameError::Connection(ERR_CODE_PROTOCOL));
            }
            let w = hdec.write(&frag, &mut |hf| {
                header_count += 1;
                if value_limit > 0 && header_count > value_limit {
                    mh.truncated = true;
                    remain_size = 0;
                    return false;
                }
                if !valid_header_field_value(&hf.value) {
                    invalid = Some(format!(
                        "invalid header field value for {}",
                        go_quote(&hf.name)
                    ));
                }
                if hf.name.first() == Some(&b':') {
                    if saw_regular {
                        invalid = Some("pseudo header field after regular".into());
                    }
                } else {
                    saw_regular = true;
                    if !valid_wire_header_field_name(&hf.name) {
                        invalid = Some(format!("invalid header field name {}", go_quote(&hf.name)));
                    }
                }
                if invalid.is_some() {
                    return false;
                }
                let size = i64::from(hf.size());
                if size > remain_size {
                    mh.truncated = true;
                    remain_size = 0;
                    return false;
                }
                remain_size -= size;
                mh.fields.push(hf);
                true
            });
            if w.is_err() {
                break Err(FrameError::Connection(ERR_CODE_COMPRESSION));
            }
            if hc_header.has(FLAG_HEADERS_END_HEADERS) {
                break Ok(());
            }
            // The next frame is guaranteed to be a CONTINUATION by check_frame_order.
            match self.read_frame() {
                Ok(Frame::Continuation {
                    header: ch,
                    fragment,
                }) => {
                    hc_header = ch;
                    frag = fragment;
                }
                Ok(_) => unreachable!("frame order check guarantees CONTINUATION"),
                Err(e) => {
                    self.meta = Some(hdec);
                    return Err(e);
                }
            }
        };
        let close = hdec.close();
        self.meta = Some(hdec);
        result?;
        if close.is_err() {
            return Err(FrameError::Connection(ERR_CODE_COMPRESSION));
        }
        if let Some(inv) = invalid {
            self.err_detail = Some(inv.clone());
            return Err(FrameError::Stream {
                stream_id: mh.header.stream_id,
                code: ERR_CODE_PROTOCOL,
                cause: Some(inv),
            });
        }
        if let Err(e) = mh.check_pseudos() {
            self.err_detail = Some(e.clone());
            return Err(FrameError::Stream {
                stream_id: mh.header.stream_id,
                code: ERR_CODE_PROTOCOL,
                cause: Some(e),
            });
        }
        Ok(Frame::Meta(mh))
    }
}

// ----------------------------------------------------------------- writer

/// Parameters for [`FrameWriter::write_headers`] (Go's `HeadersFrameParam`).
#[derive(Clone, Debug, Default)]
pub struct HeadersParam<'a> {
    pub stream_id: u32,
    pub block_fragment: &'a [u8],
    pub end_stream: bool,
    pub end_headers: bool,
    pub pad_length: u8,
    pub priority: PriorityParam,
}

/// Parameters for [`FrameWriter::write_push_promise`].
#[derive(Clone, Debug, Default)]
pub struct PushPromiseParam<'a> {
    pub stream_id: u32,
    pub promise_id: u32,
    pub block_fragment: &'a [u8],
    pub end_headers: bool,
    pub pad_length: u8,
}

/// Go's `Framer` write half. Every method performs exactly one `Write` of
/// the whole encoded frame.
pub struct FrameWriter<W: io::Write> {
    w: W,
    wbuf: Vec<u8>,
    /// Go's `AllowIllegalWrites`.
    pub allow_illegal_writes: bool,
}

fn valid_stream_id_or_zero(id: u32) -> bool {
    id & (1 << 31) == 0
}
fn valid_stream_id(id: u32) -> bool {
    id != 0 && id & (1 << 31) == 0
}

const ERR_STREAM_ID: FrameError = FrameError::Illegal("invalid stream ID");
const ERR_DEP_STREAM_ID: FrameError = FrameError::Illegal("invalid dependent stream ID");
const ERR_PAD_LENGTH: FrameError = FrameError::Illegal("pad length too large");
const ERR_PAD_BYTES: FrameError =
    FrameError::Illegal("padding bytes must all be zeros unless AllowIllegalWrites is enabled");

impl<W: io::Write> FrameWriter<W> {
    pub fn new(w: W) -> Self {
        Self {
            w,
            wbuf: Vec::new(),
            allow_illegal_writes: false,
        }
    }
    pub fn get_ref(&self) -> &W {
        &self.w
    }
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.w
    }
    pub fn into_inner(self) -> W {
        self.w
    }

    fn start_write(&mut self, ftype: u8, flags: u8, stream_id: u32) {
        self.wbuf.clear();
        self.wbuf.extend_from_slice(&[0, 0, 0, ftype, flags]);
        self.wbuf.extend_from_slice(&stream_id.to_be_bytes());
    }

    fn end_write(&mut self) -> Result<(), FrameError> {
        let length = self.wbuf.len() - FRAME_HEADER_LEN;
        if length >= 1 << 24 {
            return Err(FrameError::TooLarge { http1: false });
        }
        self.wbuf[0] = (length >> 16) as u8;
        self.wbuf[1] = (length >> 8) as u8;
        self.wbuf[2] = length as u8;
        self.w.write_all(&self.wbuf).map_err(FrameError::from)
    }

    /// Go's `WriteData`.
    pub fn write_data(
        &mut self,
        stream_id: u32,
        end_stream: bool,
        data: &[u8],
    ) -> Result<(), FrameError> {
        self.write_data_padded(stream_id, end_stream, data, None)
    }

    /// Go's `WriteDataPadded`; `pad` of `None` omits the padding bit.
    pub fn write_data_padded(
        &mut self,
        stream_id: u32,
        end_stream: bool,
        data: &[u8],
        pad: Option<&[u8]>,
    ) -> Result<(), FrameError> {
        if !valid_stream_id(stream_id) && !self.allow_illegal_writes {
            return Err(ERR_STREAM_ID);
        }
        if let Some(pad) = pad {
            if !pad.is_empty() {
                if pad.len() > 255 {
                    return Err(ERR_PAD_LENGTH);
                }
                if !self.allow_illegal_writes && pad.iter().any(|&b| b != 0) {
                    return Err(ERR_PAD_BYTES);
                }
            }
        }
        let mut flags = 0;
        if end_stream {
            flags |= FLAG_DATA_END_STREAM;
        }
        if pad.is_some() {
            flags |= FLAG_DATA_PADDED;
        }
        self.start_write(FRAME_DATA, flags, stream_id);
        if let Some(pad) = pad {
            self.wbuf.push(pad.len() as u8);
        }
        self.wbuf.extend_from_slice(data);
        if let Some(pad) = pad {
            self.wbuf.extend_from_slice(pad);
        }
        self.end_write()
    }

    /// Go's `WriteSettings`.
    pub fn write_settings(&mut self, settings: &[Setting]) -> Result<(), FrameError> {
        self.start_write(FRAME_SETTINGS, 0, 0);
        for s in settings {
            self.wbuf.extend_from_slice(&s.id.to_be_bytes());
            self.wbuf.extend_from_slice(&s.val.to_be_bytes());
        }
        self.end_write()
    }

    /// Go's `WriteSettingsAck`.
    pub fn write_settings_ack(&mut self) -> Result<(), FrameError> {
        self.start_write(FRAME_SETTINGS, FLAG_SETTINGS_ACK, 0);
        self.end_write()
    }

    /// Go's `WritePing`.
    pub fn write_ping(&mut self, ack: bool, data: [u8; 8]) -> Result<(), FrameError> {
        self.start_write(FRAME_PING, if ack { FLAG_PING_ACK } else { 0 }, 0);
        self.wbuf.extend_from_slice(&data);
        self.end_write()
    }

    /// Go's `WriteGoAway`.
    pub fn write_goaway(
        &mut self,
        max_stream_id: u32,
        code: ErrCode,
        debug_data: &[u8],
    ) -> Result<(), FrameError> {
        self.start_write(FRAME_GOAWAY, 0, 0);
        self.wbuf
            .extend_from_slice(&(max_stream_id & 0x7fff_ffff).to_be_bytes());
        self.wbuf.extend_from_slice(&code.to_be_bytes());
        self.wbuf.extend_from_slice(debug_data);
        self.end_write()
    }

    /// Go's `WriteWindowUpdate`.
    pub fn write_window_update(&mut self, stream_id: u32, incr: u32) -> Result<(), FrameError> {
        if !(1..=2_147_483_647).contains(&incr) && !self.allow_illegal_writes {
            return Err(FrameError::Illegal("illegal window increment value"));
        }
        self.start_write(FRAME_WINDOW_UPDATE, 0, stream_id);
        self.wbuf.extend_from_slice(&incr.to_be_bytes());
        self.end_write()
    }

    /// Go's `WriteHeaders`.
    pub fn write_headers(&mut self, p: &HeadersParam<'_>) -> Result<(), FrameError> {
        if !valid_stream_id(p.stream_id) && !self.allow_illegal_writes {
            return Err(ERR_STREAM_ID);
        }
        let mut flags = 0;
        if p.pad_length != 0 {
            flags |= FLAG_HEADERS_PADDED;
        }
        if p.end_stream {
            flags |= FLAG_HEADERS_END_STREAM;
        }
        if p.end_headers {
            flags |= FLAG_HEADERS_END_HEADERS;
        }
        if !p.priority.is_zero() {
            flags |= FLAG_HEADERS_PRIORITY;
        }
        self.start_write(FRAME_HEADERS, flags, p.stream_id);
        if p.pad_length != 0 {
            self.wbuf.push(p.pad_length);
        }
        if !p.priority.is_zero() {
            let mut v = p.priority.stream_dep;
            if !valid_stream_id_or_zero(v) && !self.allow_illegal_writes {
                return Err(ERR_DEP_STREAM_ID);
            }
            if p.priority.exclusive {
                v |= 1 << 31;
            }
            self.wbuf.extend_from_slice(&v.to_be_bytes());
            self.wbuf.push(p.priority.weight);
        }
        self.wbuf.extend_from_slice(p.block_fragment);
        self.wbuf
            .extend(std::iter::repeat_n(0u8, p.pad_length as usize));
        self.end_write()
    }

    /// Go's `WritePriority`.
    pub fn write_priority(&mut self, stream_id: u32, p: PriorityParam) -> Result<(), FrameError> {
        if !valid_stream_id(stream_id) && !self.allow_illegal_writes {
            return Err(ERR_STREAM_ID);
        }
        if !valid_stream_id_or_zero(p.stream_dep) {
            return Err(ERR_DEP_STREAM_ID);
        }
        self.start_write(FRAME_PRIORITY, 0, stream_id);
        let mut v = p.stream_dep;
        if p.exclusive {
            v |= 1 << 31;
        }
        self.wbuf.extend_from_slice(&v.to_be_bytes());
        self.wbuf.push(p.weight);
        self.end_write()
    }

    /// Go's `WritePriorityUpdate`.
    pub fn write_priority_update(
        &mut self,
        stream_id: u32,
        priority: &str,
    ) -> Result<(), FrameError> {
        if !valid_stream_id(stream_id) && !self.allow_illegal_writes {
            return Err(ERR_STREAM_ID);
        }
        self.start_write(FRAME_PRIORITY_UPDATE, 0, 0);
        self.wbuf.extend_from_slice(&stream_id.to_be_bytes());
        self.wbuf.extend_from_slice(priority.as_bytes());
        self.end_write()
    }

    /// Go's `WriteRSTStream`.
    pub fn write_rst_stream(&mut self, stream_id: u32, code: ErrCode) -> Result<(), FrameError> {
        if !valid_stream_id(stream_id) && !self.allow_illegal_writes {
            return Err(ERR_STREAM_ID);
        }
        self.start_write(FRAME_RST_STREAM, 0, stream_id);
        self.wbuf.extend_from_slice(&code.to_be_bytes());
        self.end_write()
    }

    /// Go's `WriteContinuation`.
    pub fn write_continuation(
        &mut self,
        stream_id: u32,
        end_headers: bool,
        fragment: &[u8],
    ) -> Result<(), FrameError> {
        if !valid_stream_id(stream_id) && !self.allow_illegal_writes {
            return Err(ERR_STREAM_ID);
        }
        let flags = if end_headers {
            FLAG_CONTINUATION_END_HEADERS
        } else {
            0
        };
        self.start_write(FRAME_CONTINUATION, flags, stream_id);
        self.wbuf.extend_from_slice(fragment);
        self.end_write()
    }

    /// Go's `WritePushPromise`.
    pub fn write_push_promise(&mut self, p: &PushPromiseParam<'_>) -> Result<(), FrameError> {
        if !valid_stream_id(p.stream_id) && !self.allow_illegal_writes {
            return Err(ERR_STREAM_ID);
        }
        let mut flags = 0;
        if p.pad_length != 0 {
            flags |= FLAG_PUSH_PROMISE_PADDED;
        }
        if p.end_headers {
            flags |= FLAG_PUSH_PROMISE_END_HEADERS;
        }
        self.start_write(FRAME_PUSH_PROMISE, flags, p.stream_id);
        if p.pad_length != 0 {
            self.wbuf.push(p.pad_length);
        }
        if !valid_stream_id(p.promise_id) && !self.allow_illegal_writes {
            return Err(ERR_STREAM_ID);
        }
        self.wbuf.extend_from_slice(&p.promise_id.to_be_bytes());
        self.wbuf.extend_from_slice(p.block_fragment);
        self.wbuf
            .extend(std::iter::repeat_n(0u8, p.pad_length as usize));
        self.end_write()
    }

    /// Go's `WriteRawFrame`.
    pub fn write_raw_frame(
        &mut self,
        ftype: u8,
        flags: u8,
        stream_id: u32,
        payload: &[u8],
    ) -> Result<(), FrameError> {
        self.start_write(ftype, flags, stream_id);
        self.wbuf.extend_from_slice(payload);
        self.end_write()
    }
}
