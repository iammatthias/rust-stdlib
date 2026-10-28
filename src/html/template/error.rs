//! Escaping errors (Go `html/template` `error.go`).

use crate::text::template::parse::{Node, Tree};
use std::fmt;

/// An error describing why a template could not be escaped (Go
/// `template.Error`).
#[derive(Clone, Debug)]
pub struct Error {
    /// The error code describing the kind of error.
    pub error_code: ErrorCode,
    /// The node that caused the problem, if known. If not nil, it overrides
    /// `name` and `line`.
    pub node: Option<Box<Node>>,
    /// The name of the template in which the error was encountered.
    pub name: String,
    /// The line number of the error in the template source or 0 if unknown.
    pub line: usize,
    /// A human-readable description of the problem.
    pub description: String,
}

/// The kind of an escaping error (Go `template.ErrorCode`). The numeric values
/// are Go's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(i32)]
pub enum ErrorCode {
    /// No error (Go `OK`).
    Ok = 0,
    /// `ErrAmbigContext`: "... appears in an ambiguous context within a URL".
    /// Example: `<a href="{{if .C}}/path/{{else}}/search?q={{end}}{{.X}}">`.
    /// The value of `{{.X}}` could be a path or a query string.
    AmbigContext = 1,
    /// `ErrBadHTML`: "expected space, attr name, or end of tag, but got ...",
    /// "... in unquoted attr", "... in attribute name". Certain syntactically
    /// incorrect HTML constructs cannot be escaped safely.
    BadHtml = 2,
    /// `ErrBranchEnd`: "{{if}} branches end in different contexts".
    BranchEnd = 3,
    /// `ErrEndContext`: "... ends in a non-text context: ...".
    EndContext = 4,
    /// `ErrNoSuchTemplate`: "no such template ...". Examples:
    /// `{{define "main"}}<div {{template "attrs"}}>{{end}}` where "attrs" is
    /// not defined.
    NoSuchTemplate = 5,
    /// `ErrOutputContext`: "cannot compute output context for template ...".
    OutputContext = 6,
    /// `ErrPartialCharset`: "unfinished JS regexp charset in ...".
    PartialCharset = 7,
    /// `ErrPartialEscape`: "unfinished escape sequence in ...".
    PartialEscape = 8,
    /// `ErrRangeLoopReentry`: "on range loop re-entry: ...".
    RangeLoopReentry = 9,
    /// `ErrSlashAmbig`: "'/' could start a division or regexp".
    SlashAmbig = 10,
    /// `ErrPredefinedEscaper`: "predefined escaper ... disallowed in
    /// template".
    PredefinedEscaper = 11,
    /// `ErrJSTemplate`: "... appears in a JS template literal".
    JsTemplate = 12,
}

impl Error {
    /// The error message (Go `Error.Error`).
    pub fn error(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(node) = self.node.as_deref() {
            let (loc, _) = Tree::default().error_context(node);
            write!(f, "html/template:{loc}: {}", self.description)
        } else if self.line != 0 {
            write!(
                f,
                "html/template:{}:{}: {}",
                self.name, self.line, self.description
            )
        } else if !self.name.is_empty() {
            write!(f, "html/template:{}: {}", self.name, self.description)
        } else {
            write!(f, "html/template: {}", self.description)
        }
    }
}

impl std::error::Error for Error {}

/// Creates an error with the given code (Go `errorf`).
pub(crate) fn errorf(k: ErrorCode, node: Option<Node>, line: usize, description: String) -> Error {
    Error {
        error_code: k,
        node: node.map(Box::new),
        name: String::new(),
        line,
        description,
    }
}
