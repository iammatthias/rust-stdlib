//! Go's `net/http/httputil`: wire dumps, the chunked transfer codec, the
//! deprecated persistent connections and a streaming reverse proxy, over the
//! crate's [`Request`](crate::net::http::Request) and
//! [`Response`](crate::net::http::Response).
mod chunked;
mod dump;
mod persist;
mod reverseproxy;

pub use chunked::{ChunkedReader, ChunkedWriter, MAX_LINE_LENGTH};
pub use dump::{dump_request, dump_request_out, dump_response};
pub use persist::{ClientConn, ConnError, ServerConn, ERR_CLOSED, ERR_PERSIST_EOF, ERR_PIPELINE};
pub use reverseproxy::{
    remove_hop_by_hop_headers, BufferPool, ProxyErrorHandler, ProxyModifyResponse, ProxyRequest,
    ReverseProxy,
};

/// Go's `ErrLineTooLong`: the message of the `io::Error` a chunked reader
/// returns for an over-long chunk-size line.
pub const ERR_LINE_TOO_LONG: &str = "header line too long";
