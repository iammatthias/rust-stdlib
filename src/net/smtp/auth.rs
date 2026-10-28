//! SMTP authentication mechanisms (Go's `net/smtp/auth.go`).
use std::error;
use std::fmt;

/// The error type of [`Auth`] methods (Go's `error` return).
pub type AuthError = Box<dyn error::Error + Send + Sync>;

/// Go's `smtp.ServerInfo`: information about an SMTP server.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerInfo {
    /// SMTP server name (Go `Name`).
    pub name: String,
    /// Whether the connection uses TLS, with a valid certificate for `name`
    /// (Go `TLS`).
    pub tls: bool,
    /// Advertised authentication mechanisms (Go `Auth`).
    pub auth: Vec<String>,
}

/// Go's `smtp.Auth`: implemented by an SMTP authentication mechanism.
///
/// Go's nil `toServer` slice is `None` from [`next`](Self::next); an empty
/// but non-nil slice is `Some(vec![])`, which still sends an (empty)
/// response line.
pub trait Auth {
    /// Begins an authentication with a server. It returns the name of the
    /// authentication protocol and optionally data to include in the initial
    /// AUTH message sent to the server. If it returns an error, the SMTP
    /// client aborts the authentication attempt and closes the connection.
    fn start(&mut self, server: &ServerInfo) -> Result<(String, Vec<u8>), AuthError>;

    /// Continues the authentication. The server has just sent `from_server`.
    /// If `more` is true, the server expects a response, which `next` should
    /// return; otherwise it should return `None`. If it returns an error, the
    /// SMTP client aborts the authentication attempt and closes the
    /// connection.
    fn next(&mut self, from_server: &[u8], more: bool) -> Result<Option<Vec<u8>>, AuthError>;
}

/// The PLAIN mechanism of RFC 4616, from [`plain_auth`].
#[derive(Clone, Debug)]
pub struct PlainAuth {
    identity: String,
    username: String,
    password: String,
    host: String,
}

/// Go's `smtp.PlainAuth`: an [`Auth`] that implements the PLAIN authentication
/// mechanism as defined in RFC 4616. The returned `Auth` uses the given
/// username and password to authenticate to `host` and act as `identity`.
/// Usually `identity` should be the empty string, to act as `username`.
///
/// It only sends the credentials if the connection is using TLS or is
/// connected to localhost. Otherwise authentication fails with an error,
/// without sending the credentials.
pub fn plain_auth(identity: &str, username: &str, password: &str, host: &str) -> PlainAuth {
    PlainAuth {
        identity: identity.to_owned(),
        username: username.to_owned(),
        password: password.to_owned(),
        host: host.to_owned(),
    }
}

fn is_localhost(name: &str) -> bool {
    name == "localhost" || name == "127.0.0.1" || name == "::1"
}

impl Auth for PlainAuth {
    fn start(&mut self, server: &ServerInfo) -> Result<(String, Vec<u8>), AuthError> {
        // Must have TLS, or else a localhost server. If TLS is not true, we
        // can't trust anything in ServerInfo: it doesn't matter if the server
        // advertises PLAIN.
        if !server.tls && !is_localhost(&server.name) {
            return Err("unencrypted connection".into());
        }
        if server.name != self.host {
            return Err("wrong host name".into());
        }
        let resp = format!("{}\0{}\0{}", self.identity, self.username, self.password);
        Ok(("PLAIN".to_owned(), resp.into_bytes()))
    }

    fn next(&mut self, _from_server: &[u8], more: bool) -> Result<Option<Vec<u8>>, AuthError> {
        if more {
            // We've already sent everything.
            return Err("unexpected server challenge".into());
        }
        Ok(None)
    }
}

/// A function computing HMAC-MD5 of a message under a key, the one primitive
/// CRAM-MD5 needs. The root crate has no cryptography (ADR 0003); the
/// reviewed implementation lives in `rust_stdlib_crypto` (`hmac::Hmac::new`
/// with `Hash::Md5`) and is passed in here.
pub type HmacMd5 = fn(key: &[u8], message: &[u8]) -> Vec<u8>;

/// The CRAM-MD5 mechanism of RFC 2195, from [`cram_md5_auth`].
#[derive(Clone)]
pub struct CramMd5Auth {
    username: String,
    secret: String,
    hmac_md5: HmacMd5,
}

impl fmt::Debug for CramMd5Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CramMd5Auth")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

/// Go's `smtp.CRAMMD5Auth`: an [`Auth`] that implements the CRAM-MD5
/// authentication mechanism as defined in RFC 2195, using `username` and
/// `secret` in the challenge-response exchange. `hmac_md5` supplies the
/// HMAC-MD5 primitive (see [`HmacMd5`]); Go calls `crypto/hmac` directly.
pub fn cram_md5_auth(username: &str, secret: &str, hmac_md5: HmacMd5) -> CramMd5Auth {
    CramMd5Auth {
        username: username.to_owned(),
        secret: secret.to_owned(),
        hmac_md5,
    }
}

impl Auth for CramMd5Auth {
    fn start(&mut self, _server: &ServerInfo) -> Result<(String, Vec<u8>), AuthError> {
        Ok(("CRAM-MD5".to_owned(), Vec::new()))
    }

    fn next(&mut self, from_server: &[u8], more: bool) -> Result<Option<Vec<u8>>, AuthError> {
        if more {
            let mac = (self.hmac_md5)(self.secret.as_bytes(), from_server);
            let mut out = format!("{} ", self.username).into_bytes();
            for b in mac {
                out.extend_from_slice(format!("{b:02x}").as_bytes());
            }
            return Ok(Some(out));
        }
        Ok(None)
    }
}
