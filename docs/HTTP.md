# HTTP scope and contracts

## Go-shaped `net/http` (HTTP/1.1)

`net::http` implements Go's `net/http` API and semantics, one thread per connection on `std::net`/`net::Conn`, with no async runtime. Each concept has one implementation and its plain name, re-exported at `net::http` and also available from its module:

| Go | Rust |
| --- | --- |
| `Request`, `NewRequest`, `ReadRequest` | `Request`, `Request::new`, `Request::in_context`, `Request::with_body`, `request::{read_request, RequestBody}` |
| `Response`, `ReadResponse` | `Response`, `response::read_response` |
| `Header`, `CanonicalHeaderKey`, `ParseTime`, `ProtocolError`, `Err*` | `header::*` (re-exported at `net::http`) |
| `Cookie`, `SameSite`, `CookieJar`, `ParseCookie`, `SetCookie` | `cookie::*`; `cookiejar::Jar` implements `CookieJar`; `Display for Cookie` is `Cookie.String` |
| `Handler`, `HandlerFunc`, `ResponseWriter`, `Flusher`, `Hijacker`, `ResponseController` | `handler::*` (`ResponseController::new`) |
| `ServeMux` (Go 1.22 patterns), `Redirect`, `StripPrefix`, `MaxBytesReader` | `ServeMux::new`, `util::*` |
| `Server`, `ConnState`, `ListenAndServe`, `Serve` | `server::*` |
| `FileServer`, `ServeContent`, `ServeFile`, `Dir`, `FS` | `fs::*` |
| `TimeoutHandler`, `CrossOriginProtection` | `middleware::*` (`CrossOriginProtection::new`) |
| `Client`, `RoundTripper`, `Get`/`Post`/`PostForm` | `Client`, `client::*` |
| `Transport`, `ProxyFromEnvironment`, `NewFileTransport`, `ClientConn` | `transport::*` (`FileTransport::new`, `Transport::client_conn`) |
| `httptest.ResponseRecorder`, `NewRequest`, `Server` | `httptest::{ResponseRecorder, request, Server}` |
| `httputil.ReverseProxy`, `ServerConn`, `ClientConn`, `DumpRequest` | `httputil::*` |

`docs/api/net_http.json` maps every symbol of Go's `net/http` (406). `Request` and `Response` carry every Go field. A `Body` is a shareable `io.ReadCloser` handle (clones read the same stream, as copies of the Go interface value do); `NoBody`, `GetBody`, `MaxBytesReader`, trailers (`Trailer`, filled when the body reaches EOF), `Request.Cancel`/`WithContext`/`Clone`, path values and `Request.Pattern` behave as in Go. Handlers take `&mut dyn ResponseWriter` and `&mut Request`; the optional writer interfaces Go finds by type assertion (`Flusher`, `Hijacker`, deadlines, `Unwrap`) are provided methods of `ResponseWriter` so `ResponseController` can walk wrappers.

Parsing and framing follow Go byte for byte: `ReadRequest`, `ReadResponse`, `Request.Write`/`WriteProxy`, `Response.Write`, the server's automatic `Content-Length`, chunking, `Content-Type` sniffing, `Date`, `Connection` handling, `Expect: 100-continue`, hijacking, and `io.WriteString`-versus-`Write` buffering (the server writes through a 2048-byte buffer; `ResponseWriter::write_string` takes Go's string path). `Transport` pools connections per proxy/scheme/address (`MaxIdleConns*`, `MaxConnsPerHost`, `IdleConnTimeout`), writes request bodies on a helper thread while reading the response (`Expect: 100-continue`, early responses), retries replayable requests on a dead reused connection, decodes gzip transparently, honours `ResponseHeaderTimeout`, `DisableKeepAlives`, `DisableCompression`, request contexts and `Request.Cancel`, tunnels HTTPS through HTTP proxies with `CONNECT`, supports SOCKS5 proxies, and exposes Go 1.27's `ClientConn`. `Client` implements Go's redirect policy (`CheckRedirect`, method rewriting, body replay through `GetBody`, `Referer`, header stripping across domains, cookie jar updates) and `Timeout`.

**TLS.** The core has no TLS stack. `Server::tls_config` and `Transport::tls_client_config` hold a `TlsConfig` (a hook with `server_listener` and `client_conn`); `rust_stdlib_tls::tls::Config` implements it (as client and as server configuration, like Go's `tls.Config`) over the reviewed Rustls adapter, and the connection reports `ConnectionState` through `net::Conn::tls_connection_state` for `Request.TLS`/`Response.TLS`. Without a backend `https` fails with an explicit error; nothing falls back to plain HTTP and certificate validation cannot be disabled. `rust_stdlib_tls::httptest::tls_server` is `httptest.NewTLSServer`.

**HTTP/2.** `net::http::h2` implements RFC 9113 and RFC 7541 first-party, ported from Go's `net/http/internal/http2`: `hpack`, `frame`, flow control, an RFC 9218 (or round-robin) write scheduler, `server` and `transport`. The server accepts `h2` over TLS (the TLS hook is given the ALPN list `h2`, `http/1.1` per `Server.Protocols`, and `serve_inner` hands the negotiated connection over) and `h2c` with prior knowledge (`Protocols.UnencryptedHTTP2`; the client preface is peeked without consuming bytes past it). Go's net/http does not implement the h2c `Upgrade` flow, so neither do we. Handlers get `Flusher`, `CloseNotifier`, deadlines (`ConnControl`) and `Pusher` (`ResponseWriter::pusher`); push honours the client's `SETTINGS_ENABLE_PUSH` (Go's transport always disables it). `Server.http2`/`Transport.http2` (`Http2Config`) set stream limits, table sizes, frame size, receive buffers, ping and write timeouts, the prohibited-cipher check and the error counter. The transport keeps one multiplexed connection per host in an HTTP/2 pool, retries streams refused or unprocessed after GOAWAY, and uses `h2c` when `Transport.protocols` enables only UnencryptedHTTP2. `httptest::Server::enable_http2` makes `start_tls` offer only `h2` and gives `client()` `ForceAttemptHTTP2`.

**Deviations and differences** (`docs/api/net_http*.json`): Go's panics are `Result`s (`ServeMux.Handle`/`HandleFunc`, package `Handle`/`HandleFunc`, `Transport.RegisterProtocol`, `CrossOriginProtection.AddInsecureBypassPattern`, `httptest.NewRequest*`, `Server.Start`/`StartTLS`, `ResponseRecorder.WriteHeader`); header values and request/status lines are Rust strings, so non-UTF-8 header bytes are rejected where Go keeps them; `Server.TLSConfig`/`Transport.TLSClientConfig` take the backend hook instead of `crypto/tls.Config` (`crypto-tls-config`); a `Director` opts out of `X-Forwarded-For` with a present-but-empty header; `Request.WithContext` copies the Header and Form maps that Go shares (`value-semantics`). Informational (1xx) responses reach `ReverseProxy` through `httptrace::ClientTrace::got_1xx_response`, as in Go. A connection hijacked from a `ServeMux` handler returns `(Box<dyn Conn>, BufioReader, bufio::Writer)`.

**Evidence.** `tools/http_check.py` compares 18,428 generated vectors with Go: ServeMux routing tables (matched pattern, path values, status, `Allow`, redirects, registration conflicts), cookie parse/format/validate, `ReadRequest`/`ReadResponse` plus `Write` round trips on mutated and truncated input, `ParseTime`/`ParseHTTPVersion`/`StatusText`, whole server transcripts over TCP (framing, chunking, sniffing, keep-alive, `Expect`, errors), FileServer/ServeContent/ServeFile over generated trees with Range and conditional headers, client redirect transcripts across two servers with a jar, `CrossOriginProtection`, `ReverseProxy.ServeHTTP` and `ServerConn`/`ClientConn`. `tools/smoke.py` adds Python and Go clients against the example server and the Rust client against a Go server. Run:

```sh
cargo test --offline --locked --test http_api --test http_client
cargo test --offline --locked --manifest-path backends/tls/Cargo.toml --test gohttp
python3 tools/http_check.py
python3 tools/smoke.py
```

Go's own files `pattern.go`, `routing_tree.go`, `fs.go`, `transfer.go`, `cookie.go`, `client.go`, `transport.go`, `server.go`, `csrf.go` and `httputil/reverseproxy.go`/`persist.go` were the reference for the ported logic (see `NOTICE`).

## httptest and httputil

`net::http::httptest` and `net::http::httputil` mirror Go's packages. `docs/api/net_http_httptest.json` and `docs/api/net_http_httputil.json` map every exported Go symbol to a Rust path or a coded deviation; `tools/api_parity.py` fails on any missing or unresolvable entry. Go panics on caller misuse (invalid NewRequest arguments, WriteHeader codes, starting twice) become errors.

**Recorder.** `ResponseRecorder` reproduces Go's implicit 200, its Content-Type sniffing on the first write (skipped when Content-Type is present or Transfer-Encoding is set), the header snapshot at `WriteHeader`, recording bytes for bodyless statuses while returning an error, `Flush`, and `Result`'s cached Status, ContentLength and declared trailers. `httptest::request` builds a server request as `httptest.NewRequest` does.

**Test servers.** `httptest::Server` binds 127.0.0.1:0 (falling back to [::1]:0). It tracks Go's connection states: `close` stops accepting, closes New and Idle connections, lets Active requests finish and waits for them, and `close_client_connections` shuts every connection. `Server::for_test` routes every plain-HTTP URL to the server under `http://example.com`, as Go's in-memory network does. `rust_stdlib_tls::httptest` provides `tls_server` and `start_tls`, with `certificate()`, a trusting `client()` and the `tls` config. Go's own test certificate is a CA certificate, which webpki rejects as an end entity, so the backend embeds an equivalent self-signed certificate (`backends/tls/tools/httptest_cert.go`; SANs 127.0.0.1, ::1, example.com, *.example.com).

**Dumps and chunking.** `dump_request`, `dump_request_out` and `dump_response` are byte-identical to Go: canonical sorted headers, Go's transport additions (`User-Agent: Go-http-client/1.1`, `Content-Length: 0` for empty POST/PUT/PATCH, `Accept-Encoding: gzip`), single-chunk re-encoding, `body=false` truncation and the `ContentLength=N with Body length M` error. `ChunkedReader`/`ChunkedWriter` port Go's lenient codec: extensions are ignored, reading stops at the zero-size chunk line (trailers left unread), the 4096-byte line limit and the 16 KiB excess-overhead check apply, and error messages are Go's.

**Persistent connections.** `ClientConn` and `ServerConn` port persist.go over a `net::Conn`: pipeline counts, sticky errors, `ErrPersistEOF` when either side closes, `ErrClosed`/`ErrPipeline`, hijack and `Request::write`/`write_proxy`/`Response::write`. Go keys the pipeline by request pointer; a request here is identified by its process-unique id.

**Reverse proxy.** `ReverseProxy` is Go's: `Director` or `Rewrite`, hop-by-hop removal, `FlushInterval`, response trailers, `ModifyResponse`, `ErrorHandler`, informational (1xx) responses and protocol upgrades through `Hijack`. `ReverseProxy::single_host` is `NewSingleHostReverseProxy`.

**Differential evidence.** `tools/httputil_check.py` (registered in `tools/parity_check.py`) compares 12,781 generated vectors with Go byte for byte: DumpRequest across HTTP/1.0, 1.1 and 2.0, DumpRequestOut, DumpResponse, Request.Write/WriteProxy, ServerConn/ClientConn transcripts, chunked reader output and errors on mutated and truncated streams, the chunked writer, DetectContentType, and the reverse proxy's outbound request and response header sets (Go runs `ServeHTTP` with a capturing `RoundTripper`).

## Executed evidence

```sh
cargo test --offline --locked --test httptest --test httputil --test http_api --test http_client
cargo test --offline --locked --manifest-path backends/tls/Cargo.toml --test gohttp
python3 tools/httputil_check.py
python3 tools/api_parity.py
```

## HTTP/2 evidence

```sh
cargo test --offline --locked --test http2
python3 tools/h2_check.py      # 55,683 vectors against Go's hpack and frame codecs
python3 tools/h2_interop.py    # Go client/server against ours, h2c and TLS
```
