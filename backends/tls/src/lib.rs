//! Explicit TLS adapter. Roots are caller supplied DER certificates.
//! No platform root discovery, certificate bypass, redirect or HTTP downgrade.
#![forbid(unsafe_code)]

#[cfg(doc)]
mod api_surface;
pub mod httptest;
pub mod tls;
