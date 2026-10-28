//! The error values of `crypto/x509`, with Go's messages.

use std::fmt;
use std::sync::Arc;

use super::net::parse_ip;
use super::types::{InvalidReason, SignatureAlgorithm};
use super::verify::{match_hostnames, split_hostname};
use super::Certificate;

/// The error type of `crypto/x509`. Go's functions return `error` values of
/// the concrete types below (recovered with `errors.As`); here each is a
/// variant, and every other Go error is a [`Error::Message`] with Go's text.
#[derive(Clone, Debug)]
pub enum Error {
    /// An error with only a message, as `errors.New` or `fmt.Errorf` creates.
    Message(String),
    /// Go's `ErrUnsupportedAlgorithm`.
    UnsupportedAlgorithm,
    /// Go's `InsecureAlgorithmError`.
    InsecureAlgorithm(InsecureAlgorithmError),
    /// Go's `ConstraintViolationError`.
    ConstraintViolation(ConstraintViolationError),
    /// Go's `UnhandledCriticalExtension`.
    UnhandledCriticalExtension(UnhandledCriticalExtension),
    /// Go's `CertificateInvalidError`.
    CertificateInvalid(CertificateInvalidError),
    /// Go's `HostnameError`.
    Hostname(HostnameError),
    /// Go's `UnknownAuthorityError`.
    UnknownAuthority(UnknownAuthorityError),
    /// Go's `SystemRootsError`.
    SystemRoots(SystemRootsError),
    /// Go's `IncorrectPasswordError`.
    IncorrectPassword,
}

impl Error {
    /// An error with the given message, like `errors.New`.
    pub fn new(message: impl Into<String>) -> Error {
        Error::Message(message.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Message(m) => f.write_str(m),
            Error::UnsupportedAlgorithm => {
                f.write_str("x509: cannot verify signature: algorithm unimplemented")
            }
            Error::InsecureAlgorithm(e) => e.fmt(f),
            Error::ConstraintViolation(e) => e.fmt(f),
            Error::UnhandledCriticalExtension(e) => e.fmt(f),
            Error::CertificateInvalid(e) => e.fmt(f),
            Error::Hostname(e) => e.fmt(f),
            Error::UnknownAuthority(e) => e.fmt(f),
            Error::SystemRoots(e) => e.fmt(f),
            Error::IncorrectPassword => f.write_str("x509: decryption password incorrect"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::SystemRoots(e) => e.unwrap_err(),
            _ => None,
        }
    }
}

impl From<InsecureAlgorithmError> for Error {
    fn from(e: InsecureAlgorithmError) -> Error {
        Error::InsecureAlgorithm(e)
    }
}

impl From<ConstraintViolationError> for Error {
    fn from(e: ConstraintViolationError) -> Error {
        Error::ConstraintViolation(e)
    }
}

impl From<UnhandledCriticalExtension> for Error {
    fn from(e: UnhandledCriticalExtension) -> Error {
        Error::UnhandledCriticalExtension(e)
    }
}

impl From<CertificateInvalidError> for Error {
    fn from(e: CertificateInvalidError) -> Error {
        Error::CertificateInvalid(e)
    }
}

impl From<HostnameError> for Error {
    fn from(e: HostnameError) -> Error {
        Error::Hostname(e)
    }
}

impl From<UnknownAuthorityError> for Error {
    fn from(e: UnknownAuthorityError) -> Error {
        Error::UnknownAuthority(e)
    }
}

impl From<SystemRootsError> for Error {
    fn from(e: SystemRootsError) -> Error {
        Error::SystemRoots(e)
    }
}

/// Go's `InsecureAlgorithmError`: the [`SignatureAlgorithm`] used to generate
/// the signature is not secure, and the signature has been rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InsecureAlgorithmError(pub SignatureAlgorithm);

impl fmt::Display for InsecureAlgorithmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "x509: cannot verify signature: insecure algorithm {}",
            self.0
        )
    }
}

impl std::error::Error for InsecureAlgorithmError {}

/// Go's `ConstraintViolationError`: a requested usage is not permitted by a
/// certificate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ConstraintViolationError;

impl fmt::Display for ConstraintViolationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "x509: invalid signature: parent certificate cannot sign this kind of certificate",
        )
    }
}

impl std::error::Error for ConstraintViolationError {}

/// Go's `UnhandledCriticalExtension`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UnhandledCriticalExtension;

impl fmt::Display for UnhandledCriticalExtension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("x509: unhandled critical extension")
    }
}

impl std::error::Error for UnhandledCriticalExtension {}

/// Go's `CertificateInvalidError`: results when an odd error occurs.
#[derive(Clone, Debug)]
pub struct CertificateInvalidError {
    /// The certificate that caused the error.
    pub cert: Arc<Certificate>,
    /// Why it is invalid.
    pub reason: InvalidReason,
    /// More detail for some reasons.
    pub detail: String,
}

impl fmt::Display for CertificateInvalidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let detail = &self.detail;
        match self.reason {
            InvalidReason::NOT_AUTHORIZED_TO_SIGN => {
                f.write_str("x509: certificate is not authorized to sign other certificates")
            }
            InvalidReason::EXPIRED => {
                write!(f, "x509: certificate has expired or is not yet valid: {detail}")
            }
            InvalidReason::CA_NOT_AUTHORIZED_FOR_THIS_NAME => write!(
                f,
                "x509: a root or intermediate certificate is not authorized to sign for this name: {detail}"
            ),
            InvalidReason::CA_NOT_AUTHORIZED_FOR_EXT_KEY_USAGE => write!(
                f,
                "x509: a root or intermediate certificate is not authorized for an extended key usage: {detail}"
            ),
            InvalidReason::TOO_MANY_INTERMEDIATES => {
                f.write_str("x509: too many intermediates for path length constraint")
            }
            InvalidReason::INCOMPATIBLE_USAGE => {
                f.write_str("x509: certificate specifies an incompatible key usage")
            }
            InvalidReason::NAME_MISMATCH => {
                f.write_str("x509: issuer name does not match subject from issuing certificate")
            }
            InvalidReason::NAME_CONSTRAINTS_WITHOUT_SANS => f.write_str(
                "x509: issuer has name constraints but leaf doesn't have a SAN extension",
            ),
            InvalidReason::UNCONSTRAINED_NAME => write!(
                f,
                "x509: issuer has name constraints but leaf contains unknown or unconstrained name: {detail}"
            ),
            InvalidReason::NO_VALID_CHAINS => {
                f.write_str("x509: no valid chains built")?;
                if !detail.is_empty() {
                    write!(f, ": {detail}")?;
                }
                Ok(())
            }
            _ => f.write_str("x509: unknown error"),
        }
    }
}

impl std::error::Error for CertificateInvalidError {}

/// Go's `HostnameError`: the set of authorized names doesn't match the
/// requested name.
#[derive(Clone, Debug)]
pub struct HostnameError {
    /// The certificate that was checked.
    pub certificate: Arc<Certificate>,
    /// The requested host.
    pub host: String,
}

impl fmt::Display for HostnameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c = &self.certificate;
        let max_names_included = 100;

        if !c.has_san_extension()
            && match_hostnames(&c.subject.common_name, &split_hostname(&self.host))
        {
            return f.write_str(
                "x509: certificate relies on legacy Common Name field, use SANs instead",
            );
        }

        let mut valid = String::new();
        if parse_ip(&self.host).is_some() {
            // Trying to validate an IP.
            if c.ip_addresses.is_empty() {
                return write!(
                    f,
                    "x509: cannot validate certificate for {} because it doesn't contain any IP SANs",
                    self.host
                );
            }
            if c.ip_addresses.len() >= max_names_included {
                return write!(
                    f,
                    "x509: certificate is valid for {} IP SANs, but none matched {}",
                    c.ip_addresses.len(),
                    self.host
                );
            }
            for san in &c.ip_addresses {
                if !valid.is_empty() {
                    valid.push_str(", ");
                }
                valid.push_str(&san.to_string());
            }
        } else {
            if c.dns_names.len() >= max_names_included {
                return write!(
                    f,
                    "x509: certificate is valid for {} names, but none matched {}",
                    c.dns_names.len(),
                    self.host
                );
            }
            valid.push_str(&c.dns_names.join(", "));
        }

        if valid.is_empty() {
            return write!(
                f,
                "x509: certificate is not valid for any names, but wanted to match {}",
                self.host
            );
        }
        write!(
            f,
            "x509: certificate is valid for {valid}, not {}",
            self.host
        )
    }
}

impl std::error::Error for HostnameError {}

/// Go's `UnknownAuthorityError`: the certificate issuer is unknown.
#[derive(Clone, Debug)]
pub struct UnknownAuthorityError {
    /// The certificate whose issuer is unknown.
    pub cert: Arc<Certificate>,
    /// An error that may help to determine why an authority wasn't found.
    pub(crate) hint_err: Option<Box<Error>>,
    /// A possible authority certificate that was rejected because of
    /// `hint_err`.
    pub(crate) hint_cert: Option<Arc<Certificate>>,
}

impl UnknownAuthorityError {
    /// An error without a hint.
    pub fn new(cert: Arc<Certificate>) -> UnknownAuthorityError {
        UnknownAuthorityError {
            cert,
            hint_err: None,
            hint_cert: None,
        }
    }
}

impl fmt::Display for UnknownAuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("x509: certificate signed by unknown authority")?;
        if let (Some(hint_err), Some(hint_cert)) = (&self.hint_err, &self.hint_cert) {
            let mut cert_name = hint_cert.subject.common_name.clone();
            if cert_name.is_empty() {
                if let Some(org) = hint_cert.subject.organization.first() {
                    cert_name = org.clone();
                } else {
                    cert_name = format!(
                        "serial:{}",
                        hint_cert
                            .serial_number
                            .as_ref()
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| "0".to_string())
                    );
                }
            }
            write!(
                f,
                " (possibly because of {} while trying to verify candidate authority certificate {})",
                quote(&hint_err.to_string()),
                quote(&cert_name)
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for UnknownAuthorityError {}

/// Go's `SystemRootsError`: the system root certificates failed to load.
#[derive(Clone, Debug)]
pub struct SystemRootsError {
    /// The underlying error, if any.
    pub err: Option<Arc<dyn std::error::Error + Send + Sync>>,
}

impl SystemRootsError {
    /// Go's `SystemRootsError.Unwrap`.
    pub fn unwrap_err(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.err
            .as_deref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}

impl fmt::Display for SystemRootsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("x509: failed to load system roots and no roots provided")?;
        if let Some(err) = &self.err {
            write!(f, "; {err}")?;
        }
        Ok(())
    }
}

impl std::error::Error for SystemRootsError {}

/// Go's `%q` for strings (`strconv.Quote`).
pub(crate) fn quote(s: &str) -> String {
    quote_bytes(s.as_bytes())
}

/// Go's `%q` for a string that may hold invalid UTF-8. `utf8.DecodeRune`
/// gives every invalid byte width 1, so each byte of an invalid sequence
/// prints as `\xNN` and decoding resumes at the next byte.
pub(crate) fn quote_bytes(s: &[u8]) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    let mut rest = s;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(valid) => {
                quote_chars(valid, &mut out);
                break;
            }
            Err(e) => {
                let (valid, invalid) = rest.split_at(e.valid_up_to());
                quote_chars(std::str::from_utf8(valid).unwrap_or(""), &mut out);
                out.push_str(&format!("\\x{:02x}", invalid[0]));
                rest = &invalid[1..];
            }
        }
    }
    out.push('"');
    out
}

fn quote_chars(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x07' => out.push_str("\\a"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x0b' => out.push_str("\\v"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c if is_go_printable(c) => out.push(c),
            c if (c as u32) < 0x10000 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push_str(&format!("\\U{:08x}", c as u32)),
        }
    }
}

/// A close approximation of `strconv.IsPrint`: graphic characters other than
/// control, format, unassigned and separator code points.
fn is_go_printable(c: char) -> bool {
    if c.is_control() {
        return false;
    }
    let cp = c as u32;
    // Non-ASCII space separators, format characters and private use areas are
    // not printable in Go.
    if c.is_whitespace() && c != ' ' {
        return false;
    }
    !matches!(cp,
        0x00ad | 0x061c | 0x180e | 0x200b..=0x200f | 0x2028..=0x202e | 0x2060..=0x206f
        | 0xe000..=0xf8ff | 0xfeff | 0xfff9..=0xfffb | 0xfffe | 0xffff
        | 0xf0000..=0x10ffff)
}
