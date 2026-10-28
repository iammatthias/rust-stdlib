//! The error values of `crypto/tls`, with Go's messages.
use super::x509;
use rust_stdlib::net::{Conn as NetConn, NetError};
use std::fmt;
use std::sync::Arc;

/// Go's `tls.AlertError`: a TLS alert received from, or to be sent to, the peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlertError(pub u8);

impl AlertError {
    /// Go's `AlertError.Error`: the alert description, prefixed with `tls: `.
    pub fn error(&self) -> String {
        let text = match self.0 {
            0 => "close notify",
            10 => "unexpected message",
            20 => "bad record MAC",
            21 => "decryption failed",
            22 => "record overflow",
            30 => "decompression failure",
            40 => "handshake failure",
            42 => "bad certificate",
            43 => "unsupported certificate",
            44 => "revoked certificate",
            45 => "expired certificate",
            46 => "unknown certificate",
            47 => "illegal parameter",
            48 => "unknown certificate authority",
            49 => "access denied",
            50 => "error decoding message",
            51 => "error decrypting message",
            60 => "export restriction",
            70 => "protocol version not supported",
            71 => "insufficient security level",
            80 => "internal error",
            86 => "inappropriate fallback",
            90 => "user canceled",
            100 => "no renegotiation",
            109 => "missing extension",
            110 => "unsupported extension",
            111 => "certificate unobtainable",
            112 => "unrecognized name",
            113 => "bad certificate status response",
            114 => "bad certificate hash value",
            115 => "unknown PSK identity",
            116 => "certificate required",
            120 => "no application protocol",
            121 => "encrypted client hello required",
            v => return format!("tls: alert({v})"),
        };
        format!("tls: {text}")
    }
}
impl fmt::Display for AlertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.error())
    }
}
impl std::error::Error for AlertError {}

/// Go's `tls.RecordHeaderError`: a TLS record header is invalid.
#[derive(Clone)]
pub struct RecordHeaderError {
    /// A human readable description of the problem.
    pub msg: String,
    /// The five bytes of record header that triggered the error.
    pub record_header: [u8; 5],
    /// The underlying connection when a client sent something that did not
    /// look like TLS.
    pub conn: Option<Arc<dyn NetConn>>,
}
impl fmt::Debug for RecordHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordHeaderError")
            .field("msg", &self.msg)
            .field("record_header", &self.record_header)
            .finish()
    }
}
impl RecordHeaderError {
    /// Go's `RecordHeaderError.Error`.
    pub fn error(&self) -> String {
        format!("tls: {}", self.msg)
    }
}
impl fmt::Display for RecordHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.error())
    }
}
impl std::error::Error for RecordHeaderError {}

/// Go's `tls.CertificateVerificationError`: certificate verification failed
/// during the handshake.
#[derive(Clone, Debug)]
pub struct CertificateVerificationError {
    /// The certificates the peer presented, leaf first.
    pub unverified_certificates: Vec<Arc<x509::Certificate>>,
    /// The verification error (an `x509:` error with Go's text).
    pub err: Arc<Error>,
}
impl CertificateVerificationError {
    /// Go's `CertificateVerificationError.Error`.
    pub fn error(&self) -> String {
        format!("tls: failed to verify certificate: {}", self.err)
    }
    /// Go's `CertificateVerificationError.Unwrap`.
    pub fn unwrap(&self) -> &Error {
        &self.err
    }
}
impl fmt::Display for CertificateVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.error())
    }
}
impl std::error::Error for CertificateVerificationError {}

/// Go's `tls.ECHRejectionError`: the server rejected Encrypted Client Hello.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ECHRejectionError {
    /// An ECHConfigList the server offered for retries, if any.
    pub retry_config_list: Vec<u8>,
}
impl ECHRejectionError {
    /// Go's `ECHRejectionError.Error`.
    pub fn error(&self) -> String {
        "tls: server rejected ECH".into()
    }
}
impl fmt::Display for ECHRejectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.error())
    }
}
impl std::error::Error for ECHRejectionError {}

/// Every error `crypto/tls` returns. Go's concrete error types are variants,
/// recovered in Go with `errors.As`.
#[derive(Clone, Debug)]
pub enum Error {
    /// A plain `errors.New` / `fmt.Errorf` value, such as `tls: ...`.
    Message(String),
    /// A local TLS alert condition (`AlertError`, e.g. from a QUIC transport).
    Alert(AlertError),
    /// An alert received from the peer: Go's `*net.OpError{Op: "remote error"}`.
    RemoteAlert(AlertError),
    /// Go's `RecordHeaderError`.
    RecordHeader(RecordHeaderError),
    /// Go's `*CertificateVerificationError`.
    CertificateVerification(CertificateVerificationError),
    /// Go's `*ECHRejectionError`.
    ECHRejection(ECHRejectionError),
    /// An `x509:` error.
    X509(String),
    /// The transport failed.
    Net(NetError),
    /// A `*net.OpError` with operation `local error`: an alert sent to the peer.
    LocalAlert(AlertError),
}

impl Error {
    /// An `errors.New(text)` value.
    pub fn new(text: impl Into<String>) -> Error {
        Error::Message(text.into())
    }
    /// Whether this is a timeout (`net.Error.Timeout`).
    pub fn timeout(&self) -> bool {
        match self {
            Error::Net(n) => rust_stdlib::net::Error::timeout(n),
            _ => false,
        }
    }
    /// The certificate verification error, when this is one.
    pub fn as_certificate_verification(&self) -> Option<&CertificateVerificationError> {
        match self {
            Error::CertificateVerification(e) => Some(e),
            _ => None,
        }
    }
    /// The remote or local alert, when this wraps one (`errors.As(err, &AlertError)`).
    pub fn as_alert(&self) -> Option<AlertError> {
        match self {
            Error::Alert(a) | Error::RemoteAlert(a) | Error::LocalAlert(a) => Some(*a),
            _ => None,
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Message(m) | Error::X509(m) => f.write_str(m),
            Error::Alert(a) => a.fmt(f),
            Error::RemoteAlert(a) => write!(f, "remote error: {a}"),
            Error::LocalAlert(a) => write!(f, "local error: {a}"),
            Error::RecordHeader(e) => e.fmt(f),
            Error::CertificateVerification(e) => e.fmt(f),
            Error::ECHRejection(e) => e.fmt(f),
            Error::Net(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for Error {}
impl From<NetError> for Error {
    fn from(e: NetError) -> Error {
        Error::Net(e)
    }
}
impl From<Error> for NetError {
    fn from(e: Error) -> NetError {
        match e {
            Error::Net(n) => n,
            other => NetError::other(other.to_string()),
        }
    }
}
impl From<Error> for std::io::Error {
    fn from(e: Error) -> std::io::Error {
        std::io::Error::other(e)
    }
}
