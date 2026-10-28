//! Runtime Go-verb formatting and scanning (Go `fmt`).
//!
//! Rust's `format!`, `print!`, `write!`, [`std::fmt::Display`] and
//! [`std::fmt::Debug`] already achieve Go's Printf family for statically
//! known formats; use them. This module exists for the one case std cannot
//! cover: a format string chosen at runtime that must produce Go's exact
//! bytes (`text/template`-style `printf`, `%v` of a decoded JSON number, the
//! `fmt` differential suite). It is small by design:
//! [`sprintf`]/[`sprint`]/[`sprintln`], their byte-exact `append*` forms and
//! [`errorf`]. Writing to a stream is `out.write_all(sprintf(..).as_bytes())`
//! or [`appendf`] into a buffer.
//!
//! Go's `fmt` is driven by reflection over `any` operands. Rust has none, so
//! the operands are an explicit model: [`Value`] (alias [`Arg`]) spells out
//! the Go type of each operand (integers of every width, floats, complex
//! numbers, strings, slices, arrays, maps, structs with field names,
//! pointers, named types with methods) and has `From` impls for Rust
//! primitives and std containers. A named type brings its `String`/`GoString`
//! methods as [`Display`](std::fmt::Display)/[`Debug`](std::fmt::Debug)
//! implementations ([`Value::with_display`], [`Value::with_debug`]). The verb
//! engine itself is Go's: every verb, flag, width, precision, `*` argument and
//! `[n]` index produces Go's bytes, including the `%!d(string=hi)`,
//! `%!(EXTRA ...)`, `%!(MISSING)`, `%!(BADWIDTH)`, `%!(NOVERB)` and
//! `%!v(PANIC=...)` error forms. Digits and quoting come from
//! [`crate::strconv`].
//!
//! Go strings are byte sequences; the `append*` functions are byte exact,
//! while `sprint*` return a `String` and replace invalid UTF-8 with U+FFFD.
//!
//! ```
//! use rust_stdlib::printf::{self, Value};
//! let args = [Value::from(3.14159), Value::from(42i64), Value::from("hi"), Value::from("hi")];
//! assert_eq!(printf::sprintf("%5.2f|%-4d|%q|%x", &args), " 3.14|42  |\"hi\"|6869");
//! assert_eq!(printf::sprintf("%d", &[Value::from("hi")]), "%!d(string=hi)");
//! let v = Value::strukt("main.P", vec![("X", 1isize.into()), ("Y", 2isize.into())]);
//! assert_eq!(printf::sprintf("%+v %#v", &[v.clone(), v]), "{X:1 Y:2} main.P{X:1, Y:2}");
//! ```
//!
//! Scanning ([`sscanf`], [`fscan`], ...) writes into [`ScanArg`] destinations;
//! std has no equivalent.

use std::io::{self, Write};

mod format;
mod print;
mod scan;
mod value;

pub use scan::{
    fscan, fscan_runes, fscanf, fscanf_runes, fscanln, fscanln_runes, scan, scanf, scanln, sscan,
    sscanf, sscanln, ScanArg, ScanError, ScanErrorKind, ScanState, Scanner, StateRunes,
};
pub use value::{
    Arg, DynError, IntKind, MapV, Methods, Named, OperandType, Ptr, Seq, StructV, UintKind, Value,
};

use format::Pp;

/// Implemented by any value that has a `Format` method, which customizes
/// every verb (Go `fmt.Formatter`).
pub trait Formatter {
    /// Go's `Format(f State, verb rune)`.
    fn format(&self, f: &mut dyn State, verb: char);
}

/// The printer state handed to a [`Formatter`] (Go `fmt.State`): the output
/// (`write`, from [`std::io::Write`]) plus the width, precision and flags.
pub trait State: Write {
    /// Go's `Width`: the width option, if present.
    fn width(&self) -> Option<isize>;
    /// Go's `Precision`: the precision option, if present.
    fn precision(&self) -> Option<isize>;
    /// Go's `Flag`: whether the flag `c` (one of `+-# 0`) is set.
    fn flag(&self, c: char) -> bool;
}

impl Write for Pp {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl State for Pp {
    fn width(&self) -> Option<isize> {
        self.wid_present.then_some(self.wid as isize)
    }
    fn precision(&self) -> Option<isize> {
        self.prec_present.then_some(self.prec as isize)
    }
    fn flag(&self, c: char) -> bool {
        match c {
            '-' => self.minus,
            '+' => self.plus || self.plus_v,
            '#' => self.sharp || self.sharp_v,
            ' ' => self.space,
            '0' => self.zero,
            _ => false,
        }
    }
}

/// Returns the fully qualified formatting directive captured by the state,
/// followed by the verb: `%`, the flags, the width and the precision (Go
/// `fmt.FormatString`).
pub fn format_string(state: &dyn State, verb: char) -> String {
    let mut b = String::from("%");
    for c in " +-#0".chars() {
        if state.flag(c) {
            b.push(c);
        }
    }
    if let Some(w) = state.width() {
        b.push_str(&w.to_string());
    }
    if let Some(p) = state.precision() {
        b.push('.');
        b.push_str(&p.to_string());
    }
    b.push(verb);
    b
}

fn printer() -> Pp {
    let mut p = Pp::new();
    p.clear_flags();
    p
}

fn into_string(b: Vec<u8>) -> String {
    match String::from_utf8(b) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    }
}

// ------------------------------------------------------------- Printf

/// Formats according to a format specifier and returns the result (Go
/// `Sprintf`). Invalid UTF-8 in the result becomes U+FFFD; use [`appendf`]
/// for the exact bytes.
pub fn sprintf(format: impl AsRef<[u8]>, args: &[Value]) -> String {
    let mut b = Vec::new();
    appendf(&mut b, format, args);
    into_string(b)
}

/// Formats according to a format specifier and appends the result to `dst`
/// (Go `Appendf`).
pub fn appendf(dst: &mut Vec<u8>, format: impl AsRef<[u8]>, args: &[Value]) {
    let mut p = printer();
    p.do_printf(format.as_ref(), args);
    dst.extend_from_slice(&p.buf);
}

// -------------------------------------------------------------- Print

/// Formats using the default formats for its operands, adding spaces between
/// operands when neither is a string (Go `Sprint`).
pub fn sprint(args: &[Value]) -> String {
    let mut b = Vec::new();
    append(&mut b, args);
    into_string(b)
}

/// Like [`sprint`], appending the exact bytes to `dst` (Go `Append`).
pub fn append(dst: &mut Vec<u8>, args: &[Value]) {
    let mut p = printer();
    p.do_print(args);
    dst.extend_from_slice(&p.buf);
}

/// Formats using the default formats; spaces are always added between
/// operands and a newline is appended (Go `Sprintln`).
pub fn sprintln(args: &[Value]) -> String {
    let mut b = Vec::new();
    appendln(&mut b, args);
    into_string(b)
}

/// Like [`sprintln`], appending the exact bytes to `dst` (Go `Appendln`).
pub fn appendln(dst: &mut Vec<u8>, args: &[Value]) {
    let mut p = printer();
    p.do_println(args);
    dst.extend_from_slice(&p.buf);
}

// ------------------------------------------------------------- Errorf

/// The error returned by [`errorf`] (Go's `*fmt.wrapError`, `*fmt.wrapErrors`
/// or `*errors.errorString`). With one `%w` operand [`std::error::Error::source`]
/// is that operand; with several, [`WrapError::sources`] lists them all (Go's
/// `Unwrap() []error`).
#[derive(Clone)]
pub struct WrapError {
    msg: String,
    errs: Vec<DynError>,
    /// The number of distinct `%w` verbs (0: `errors.New`, 1: `wrapError`,
    /// more: `wrapErrors`) and the operand values, for printing the error.
    wrapped_n: usize,
    vals: Vec<Value>,
}

impl WrapError {
    /// Go's `Unwrap() []error`: the operands of every `%w` verb, in order.
    pub fn sources(&self) -> &[DynError] {
        &self.errs
    }
}

impl WrapError {
    /// The error as an operand: Go prints `*fmt.wrapError` and friends as
    /// pointers to their unexported fields.
    pub(crate) fn to_value(&self) -> Value {
        let msg = Value::String(self.msg.clone().into_bytes());
        let (name, elem) = match self.wrapped_n {
            0 => (
                "errors.errorString",
                Value::strukt("errors.errorString", vec![("s", msg)]),
            ),
            1 => {
                let inner = match self.vals.first() {
                    Some(v) if v.as_error().is_some() => v.clone(),
                    _ => Value::NilIface("error".into()),
                };
                (
                    "fmt.wrapError",
                    Value::strukt("fmt.wrapError", vec![("msg", msg), ("err", inner)]),
                )
            }
            _ => (
                "fmt.wrapErrors",
                Value::strukt(
                    "fmt.wrapErrors",
                    vec![
                        ("msg", msg),
                        ("errs", Value::slice("error", self.vals.clone())),
                    ],
                ),
            ),
        };
        let ptr = format!("*{name}");
        let inner = Value::pointer(&ptr, 0xc0_0004_0000, elem);
        let mut v = Value::named(&ptr, inner);
        if let Value::Named(n) = &mut v {
            n.methods.error = Some(std::sync::Arc::new(self.clone()));
        }
        v
    }
}

impl std::fmt::Display for WrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::fmt::Debug for WrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WrapError({:?})", self.msg)
    }
}

impl std::error::Error for WrapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.errs.first().map(|e| {
            let e: &(dyn std::error::Error + 'static) = &**e;
            e
        })
    }
}

/// Formats according to a format specifier and returns the string as an
/// error. `%w` operands that are errors are wrapped (Go `Errorf`).
pub fn errorf(format: impl AsRef<[u8]>, args: &[Value]) -> WrapError {
    let format = format.as_ref();
    if args.is_empty() && !format.contains(&b'%') {
        return WrapError {
            msg: into_string(format.to_vec()),
            errs: Vec::new(),
            wrapped_n: 0,
            vals: Vec::new(),
        };
    }
    let mut p = printer();
    p.wrap_errs = true;
    p.do_printf(format, args);
    let msg = into_string(std::mem::take(&mut p.buf));
    let mut wrapped = std::mem::take(&mut p.wrapped_errs);
    let wrapped_n = wrapped.len();
    let mut vals = Vec::new();
    let errs = match wrapped_n {
        0 => Vec::new(),
        1 => {
            vals.push(args[wrapped[0]].clone());
            args[wrapped[0]].as_error().into_iter().collect()
        }
        _ => {
            if p.reordered {
                wrapped.sort_unstable();
            }
            let mut errs = Vec::new();
            for (i, &n) in wrapped.iter().enumerate() {
                if i > 0 && wrapped[i - 1] == n {
                    continue;
                }
                if let Some(e) = args[n].as_error() {
                    errs.push(e);
                    vals.push(args[n].clone());
                }
            }
            errs
        }
    };
    WrapError {
        msg,
        errs,
        wrapped_n,
        vals,
    }
}
