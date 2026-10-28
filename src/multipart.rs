//! Go's `mime/multipart`: the streaming [`Reader`] and [`Writer`], and the
//! buffered [`Form`]. Framing is Go's, including its leniency.
mod form;
mod reader;
mod writer;

pub use form::{File, FileHeader, Form};
pub use reader::{OwnedPart, OwnedPartReader, Part, Reader};
pub use writer::{file_content_disposition, PartWriter, Writer};

use std::{error, fmt, io};

/// Go's `ErrMessageTooLarge`, returned inside an [`io::Error`] by
/// [`Reader::read_form`].
pub const ERR_MESSAGE_TOO_LARGE: Error = Error("multipart: message too large");
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(pub &'static str);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl error::Error for Error {}

fn stream_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, Error(message))
}
