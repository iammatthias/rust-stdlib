# MIME, cookies and multipart contracts

The portable `mime`, `multipart`, and `net::http::cookie` modules use only Rust std
and are available with the default features disabled.

## MIME

`MediaType` parses and canonicalizes a type/subtype with case-insensitive
parameter names. `parse_parameters` and `format_parameters` also support
Content-Disposition token/parameter values. Duplicate parameters, malformed
quoted strings, controls and extended/continued RFC 2231 names are rejected.
Quoted parameters permit printable UTF-8 for interoperable form filenames.
The caller can bound input bytes and parameter count. The extension table is a
deterministic built-in subset; operating system MIME databases and RFC 2231
decoding remain absent. RFC 2047 encoded words are handled by `WordEncoder` and
`WordDecoder`, which follow Go and reject decoded text that is not UTF-8.

Source: https://www.rfc-editor.org/rfc/rfc2045#section-5.1

## Cookies

Cookies are Go's `http.Cookie` (`net::http::cookie`): `parse_cookie`, `parse_set_cookie`, `Cookie`'s `Display` form, validation and `SameSite`, with Go's grammar and limits. `net::http::cookiejar::Jar` is Go's RFC 6265 jar, with Go's storage, matching and ordering, Punycode host handling and nanosecond expiry. No public suffix database is bundled: supply a `PublicSuffixList`.

Source: https://www.rfc-editor.org/rfc/rfc6265#section-4

## Multipart

Parsing borrows binary body slices instead of copying file payloads. Global
bytes, part bytes, part count, header bytes and header count have independent
limits. CRLF delimiters, transport padding, preamble and epilogue are supported.
A boundary prefix in a payload remains payload unless it is a complete
delimiter line. Each part requires exactly one form-data disposition with a
name; repeated names and files are preserved in order. Folding and
Content-Transfer-Encoding are rejected. Extended disposition parameters are
unsupported as documented by MIME. File paths are untrusted metadata and are
never opened by this module.

Encoding validates parts and checks boundary collisions before writing. The
`Write` API buffers the bounded encoded message, handles partial writes using
`write_all`, and propagates destination failures. The `Reader<R: BufRead>` iterator consumes multipart incrementally and returns
one bounded owned part at a time; it never buffers the entire message. It
counts consumed bytes globally, enforces all part/header limits, and leaves
epilogue unread after the closing delimiter. Preamble lines and boundary
transport padding are additionally bounded by the header-byte budget. Errors
latch the reader into a failed state. Returning an owned part permits the
caller to release each file before advancing to the next; retained parts are
caller-owned memory.

Sources:

- https://www.rfc-editor.org/rfc/rfc2046#section-5.1
- https://www.rfc-editor.org/rfc/rfc7578

## Executed tests

`cargo test --offline --test web_formats` covers binary and quoted parameter
round trips, duplicate cookies, injection and overflow rejection, all multipart
budgets, delimiter prefixes, preamble/epilogue, transport padding, malformed
headers, truncated input, boundary collisions, partial writes and I/O failure.

A Go oracle (`go run tools/web_formats_oracle.go`) was executed for MIME case/quoted-pair behavior, conflicting duplicate parameters, malformed quoted input, duplicate request cookies, and multipart preamble/epilogue/transport padding. Its accepted values match the corresponding Rust tests. Go tolerates some malformed cookies and MIME parameter cases that this strict API rejects. This is deliberately partial interoperability evidence.
