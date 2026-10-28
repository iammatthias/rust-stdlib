//! Go's `net/http`: an HTTP/1.1 and HTTP/2 client and server, with cookies,
//! file serving, redirects, middleware and the supporting subpackages.
//!
//! [`Request`] and [`Response`] are Go's structs; handlers implement
//! [`Handler`] and write through a [`ResponseWriter`]; [`Client`] and
//! [`Transport`] send requests. TLS is available through the separately
//! packaged reviewed backend. See `docs/HTTP.md`.
pub mod body;
pub mod cgi;
pub mod client;
pub mod cookie;
pub mod cookiejar;
pub mod fcgi;
pub mod fs;
pub mod h2;
pub mod handler;
pub mod header;
pub mod httptest;
pub mod httptrace;
pub mod httputil;
pub mod middleware;
pub mod pprof;
pub mod request;
pub mod response;
pub mod servemux;
pub mod server;
mod sniff;
pub mod status;
pub mod tlsstate;
mod transfer;
pub mod transport;
pub mod util;

pub use body::{Body, BodyWriter, NoBody, NopCloser, ReadCloser};
pub use client::{
    get as http_get, head as http_head, post as http_post, post_form as http_post_form,
    CheckRedirect, Client, RoundTripper, TimeoutError, DEFAULT_CLIENT,
};
pub use cookie::{
    parse_cookie, parse_set_cookie, set_cookie, Cookie, CookieJar, SameSite,
    SAME_SITE_DEFAULT_MODE, SAME_SITE_LAX_MODE, SAME_SITE_NONE_MODE, SAME_SITE_STRICT_MODE,
};
pub use fs::{
    file_server, file_server_fs, fs_adapter, serve_content, serve_file, serve_file_fs, Dir, File,
    FileSystem, ReadSeek,
};
pub use handler::{
    handler_func, CloseNotifier, ConnControl, Flusher, Handler, HandlerFunc, Hijacked, Hijacker,
    ResponseController, ResponseWriter,
};
pub use header::*;
pub use middleware::{timeout_handler, CrossOriginProtection};
pub use request::{GetBody, Request, RequestBody};
pub use response::Response;
pub use servemux::{handle, handle_func, ServeMux, DEFAULT_SERVE_MUX};
pub use server::{
    listen_and_serve, listen_and_serve_tls, serve, serve_tls, ConnState, Server, TlsNextProtoFn,
    LOCAL_ADDR_CONTEXT_KEY, SERVER_CONTEXT_KEY, STATE_ACTIVE, STATE_CLOSED, STATE_HIJACKED,
    STATE_IDLE, STATE_NEW,
};
pub use sniff::{detect_content_type, SNIFF_LEN};
pub use status::*;
pub use tlsstate::{ConnectionState, TlsConfig};
pub use transfer::BufioReader;
pub use transport::{
    default_transport, proxy_from_environment, proxy_func_for, proxy_url, set_default_transport,
    ClientConn, FileTransport, Transport, DEFAULT_MAX_IDLE_CONNS_PER_HOST,
};
pub use util::{
    allow_query_semicolons, error as http_error, max_bytes_handler, max_bytes_reader, not_found,
    not_found_handler, redirect, redirect_handler, strip_prefix, MaxBytesError,
};

pub(crate) fn token(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Go's `http.StatusText`: the registered reason phrase, or `""` for an
/// unknown code.
pub fn status_text(code: u16) -> &'static str {
    match code {
        100 => "Continue",
        101 => "Switching Protocols",
        102 => "Processing",
        103 => "Early Hints",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        208 => "Already Reported",
        226 => "IM Used",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Request Entity Too Large",
        414 => "Request URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Requested Range Not Satisfiable",
        417 => "Expectation Failed",
        418 => "I'm a teapot",
        421 => "Misdirected Request",
        422 => "Unprocessable Entity",
        423 => "Locked",
        424 => "Failed Dependency",
        425 => "Too Early",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        506 => "Variant Also Negotiates",
        507 => "Insufficient Storage",
        508 => "Loop Detected",
        510 => "Not Extended",
        511 => "Network Authentication Required",
        _ => "",
    }
}
