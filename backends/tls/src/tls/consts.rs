//! Version, curve, signature scheme and client authentication constants with
//! Go's names and `String` tables (`common.go`, `common_string.go`,
//! `cipher_suites.go`).
use super::tables;
use std::fmt;

/// SSLv3. Go no longer implements it and neither does Rustls.
pub const VERSION_SSL30: u16 = 0x0300;
/// TLS 1.0.
pub const VERSION_TLS10: u16 = 0x0301;
/// TLS 1.1.
pub const VERSION_TLS11: u16 = 0x0302;
/// TLS 1.2.
pub const VERSION_TLS12: u16 = 0x0303;
/// TLS 1.3.
pub const VERSION_TLS13: u16 = 0x0304;

/// Go's `tls.VersionName`.
pub fn version_name(version: u16) -> String {
    match version {
        VERSION_SSL30 => "SSLv3".into(),
        VERSION_TLS10 => "TLS 1.0".into(),
        VERSION_TLS11 => "TLS 1.1".into(),
        VERSION_TLS12 => "TLS 1.2".into(),
        VERSION_TLS13 => "TLS 1.3".into(),
        v => format!("0x{v:04X}"),
    }
}

/// Go's `tls.CipherSuite`: a cipher suite implemented by Go's package.
///
/// Go's tables are reproduced exactly. Which of these suites can be negotiated
/// here is decided by Rustls: TLS 1.3 AEAD suites and the ECDHE AES-GCM and
/// ChaCha20-Poly1305 suites; see `Config::cipher_suites`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CipherSuite {
    pub id: u16,
    pub name: String,
    /// The TLS versions that can negotiate this suite.
    pub supported_versions: Vec<u16>,
    /// True if the suite has known security issues.
    pub insecure: bool,
}

/// Go's `tls.CipherSuites`: the secure suites, sorted by ID as Go lists them.
pub fn cipher_suites() -> Vec<CipherSuite> {
    tables::secure_suites()
}

/// Go's `tls.InsecureCipherSuites`.
pub fn insecure_cipher_suites() -> Vec<CipherSuite> {
    tables::insecure_suites()
}

/// Go's `tls.CipherSuiteName`.
pub fn cipher_suite_name(id: u16) -> String {
    cipher_suites()
        .into_iter()
        .chain(insecure_cipher_suites())
        .find(|c| c.id == id)
        .map(|c| c.name)
        .unwrap_or_else(|| format!("0x{id:04X}"))
}

macro_rules! newtype_consts {
    ($(#[$m:meta])* $name:ident($inner:ty) { $($(#[$cm:meta])* $const:ident = $val:expr;)* }) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(pub $inner);
        $($(#[$cm])* pub const $const: $name = $name($val);)*
    };
}

newtype_consts! {
    /// Go's `tls.CurveID`: the key exchange mechanism (named group) identifier.
    CurveID(u16) {
        CURVE_P256 = 23;
        CURVE_P384 = 24;
        CURVE_P521 = 25;
        X25519 = 29;
        X25519_MLKEM768 = 4588;
        SEC_P256R1_MLKEM768 = 4587;
        SEC_P384R1_MLKEM1024 = 4589;
        MLKEM1024 = 514;
    }
}

impl CurveID {
    /// Go's `CurveID.String`.
    fn string(&self) -> String {
        match self.0 {
            23 => "CurveP256".into(),
            24 => "CurveP384".into(),
            25 => "CurveP521".into(),
            29 => "X25519".into(),
            514 => "MLKEM1024".into(),
            4587 => "SecP256r1MLKEM768".into(),
            4588 => "X25519MLKEM768".into(),
            4589 => "SecP384r1MLKEM1024".into(),
            v => format!("CurveID({v})"),
        }
    }
}
impl fmt::Display for CurveID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string())
    }
}

newtype_consts! {
    /// Go's `tls.SignatureScheme`: a TLS SignatureScheme (RFC 8446 section 4.2.3).
    SignatureScheme(u16) {
        PKCS1_WITH_SHA256 = 0x0401;
        PKCS1_WITH_SHA384 = 0x0501;
        PKCS1_WITH_SHA512 = 0x0601;
        PSS_WITH_SHA256 = 0x0804;
        PSS_WITH_SHA384 = 0x0805;
        PSS_WITH_SHA512 = 0x0806;
        ECDSA_WITH_P256_AND_SHA256 = 0x0403;
        ECDSA_WITH_P384_AND_SHA384 = 0x0503;
        ECDSA_WITH_P521_AND_SHA512 = 0x0603;
        ED25519 = 0x0807;
        MLDSA44 = 0x0904;
        MLDSA65 = 0x0905;
        MLDSA87 = 0x0906;
        /// Legacy; rejected by Rustls.
        PKCS1_WITH_SHA1 = 0x0201;
        /// Legacy; rejected by Rustls.
        ECDSA_WITH_SHA1 = 0x0203;
    }
}

impl SignatureScheme {
    /// Go's `SignatureScheme.String`.
    fn string(&self) -> String {
        let name = match self.0 {
            0x0201 => "PKCS1WithSHA1",
            0x0203 => "ECDSAWithSHA1",
            0x0401 => "PKCS1WithSHA256",
            0x0403 => "ECDSAWithP256AndSHA256",
            0x0501 => "PKCS1WithSHA384",
            0x0503 => "ECDSAWithP384AndSHA384",
            0x0601 => "PKCS1WithSHA512",
            0x0603 => "ECDSAWithP521AndSHA512",
            0x0804 => "PSSWithSHA256",
            0x0805 => "PSSWithSHA384",
            0x0806 => "PSSWithSHA512",
            0x0807 => "Ed25519",
            0x0904 => "MLDSA44",
            0x0905 => "MLDSA65",
            0x0906 => "MLDSA87",
            v => return format!("SignatureScheme({v})"),
        };
        name.into()
    }
}
impl fmt::Display for SignatureScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string())
    }
}

newtype_consts! {
    /// Go's `tls.ClientAuthType`: the policy a server follows for client authentication.
    ClientAuthType(i32) {
        /// No client certificate is requested; any sent are not verified.
        NO_CLIENT_CERT = 0;
        /// A certificate is requested but not required.
        REQUEST_CLIENT_CERT = 1;
        /// A certificate is required, but need not be valid.
        REQUIRE_ANY_CLIENT_CERT = 2;
        /// A certificate is requested; if given it must be valid.
        VERIFY_CLIENT_CERT_IF_GIVEN = 3;
        /// A valid certificate is required.
        REQUIRE_AND_VERIFY_CLIENT_CERT = 4;
    }
}

impl ClientAuthType {
    /// Go's `ClientAuthType.String`.
    fn string(&self) -> String {
        match self.0 {
            0 => "NoClientCert".into(),
            1 => "RequestClientCert".into(),
            2 => "RequireAnyClientCert".into(),
            3 => "VerifyClientCertIfGiven".into(),
            4 => "RequireAndVerifyClientCert".into(),
            v => format!("ClientAuthType({v})"),
        }
    }
    pub(crate) fn requires_client_cert(&self) -> bool {
        matches!(
            *self,
            REQUIRE_ANY_CLIENT_CERT | REQUIRE_AND_VERIFY_CLIENT_CERT
        )
    }
}
impl fmt::Display for ClientAuthType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string())
    }
}

/// Go's `tls.RenegotiationSupport`: whether a client accepts server renegotiation.
///
/// Rustls never renegotiates: only [`RENEGOTIATE_NEVER`] is honoured.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct RenegotiationSupport(pub i32);
/// Disables renegotiation.
pub const RENEGOTIATE_NEVER: RenegotiationSupport = RenegotiationSupport(0);
/// Allows a remote server to request renegotiation once per connection.
pub const RENEGOTIATE_ONCE_AS_CLIENT: RenegotiationSupport = RenegotiationSupport(1);
/// Allows a remote server to repeatedly request renegotiation.
pub const RENEGOTIATE_FREELY_AS_CLIENT: RenegotiationSupport = RenegotiationSupport(2);

pub use tables::*;
