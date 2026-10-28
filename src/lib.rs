//! Application-level extensions to Rust's standard library.
//!
//! The implementation uses only `std`. Public I/O APIs use `Read`, `BufRead`,
//! and `Write`. This is an experimental companion library with a deliberately
//! documented subset of Go's application-library coverage.
//!
//! ```
//! use rust_stdlib::encoding::{base64, json};
//! let value: json::Value = r#"{"message":"hello","count":9007199254740993}"#.parse()?;
//! assert_eq!(value.get("message").and_then(json::Value::as_str), Some("hello"));
//! assert_eq!(base64::STANDARD.encode(b"hello"), "aGVsbG8=");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
#![forbid(unsafe_code)]

#[cfg(doc)]
mod api_surface;
pub mod archive;
pub mod bufio;
pub mod collections;
pub mod compress;
pub mod concurrent;
pub mod context;
pub mod database;
pub mod embed;
pub mod encoding;
pub mod error;
pub mod expvar;
pub mod flag;
pub mod hash;
pub mod html;
pub mod image;
pub mod index;
pub mod io;
pub mod log;
pub mod math;
pub mod mime;
pub mod multipart;
pub mod net;
#[cfg(unix)]
pub mod os;
pub mod path;
pub mod plugin;
pub mod printf;
pub mod quotedprintable;
pub mod reflect;
pub mod regexp;
pub mod strconv;
pub mod tabwriter;
pub mod template;
pub mod testing;
pub mod text;
pub mod time;
pub mod unicode;
pub mod unique;
pub mod uuid;
