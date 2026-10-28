//! Go's `text/*` packages (`text/scanner`, `text/template`) and the text
//! handling of `strings` and `bytes` that Rust's std does not cover: byte
//! strings with Go's lossy UTF-8 rules ([`BytesExt`]), [`Replacer`], and the
//! unread-capable [`Reader`] and read/write [`Buffer`]. The rest of `strings`
//! and `bytes` is std (`str`, `String`, `Vec<u8>`, `<[u8]>`). The other `text`
//! packages are at their own crate paths.

mod buffer;
mod ext;
mod reader;
mod replace;
mod size_classes;

pub mod scanner;
pub mod template;

pub use buffer::{Buffer, ErrTooLarge, MIN_READ};
pub use ext::BytesExt;
pub use reader::Reader;
pub use replace::Replacer;
