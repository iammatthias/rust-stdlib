//! Go's `log` package: a simple text logger with Go's exact line format.
//!
//! A [`Logger`] writes one line per call to a `std::io::Write` destination.
//! The flag constants ([`LDATE`], [`LTIME`], ...) select the header, and the
//! Go-compatible structured logger lives in [`slog`]. Source locations for
//! [`LSHORTFILE`] and [`LLONGFILE`] come from `#[track_caller]`.
//!
//! Local time is Go's `time.Local`, resolved from `TZ` by [`crate::time::local`];
//! `LUTC` prints UTC.
//!
//! Deviations from Go, all forced by Rust std:
//! - Go's variadic `...any` arguments become `std::fmt::Arguments`
//!   (`format_args!`); `print` and `printf` are therefore identical, and
//!   `println` appends a newline to the formatted text.
//! - `Output`'s `calldepth` is accepted for parity, but the location is always
//!   the direct caller of the `Logger` method.
//! - `Llongfile` reports the path as given to `rustc`, which is relative to
//!   the workspace for local crates.
//!
//! ```
//! use rust_stdlib::log::{self, Logger};
//! let logger = Logger::new(Vec::new(), "app: ", log::LMSGPREFIX);
//! logger.printf(format_args!("hello {}", 42));
//! ```
//!
//! The earlier JSON-line logger is available as [`json`].
use crate::time::DateTime;
use std::{
    cell::Cell,
    fmt,
    io::{self, Write},
    panic::Location,
    sync::{
        atomic::{AtomicI32, Ordering},
        Arc, Mutex, MutexGuard, OnceLock,
    },
};

pub mod json;
pub mod slog;
pub mod syslog;

/// The date in the local time zone: `2009/01/23`.
pub const LDATE: i32 = 1 << 0;
/// The time in the local time zone: `01:23:23`.
pub const LTIME: i32 = 1 << 1;
/// Microsecond resolution: `01:23:23.123123`. Assumes [`LTIME`].
pub const LMICROSECONDS: i32 = 1 << 2;
/// Full file name and line number: `/a/b/c/d.go:23`.
pub const LLONGFILE: i32 = 1 << 3;
/// Final file name element and line number: `d.go:23`. Overrides [`LLONGFILE`].
pub const LSHORTFILE: i32 = 1 << 4;
/// If [`LDATE`] or [`LTIME`] is set, use UTC rather than the local time zone.
pub const LUTC: i32 = 1 << 5;
/// Move the prefix from the beginning of the line to before the message.
pub const LMSGPREFIX: i32 = 1 << 6;
/// Initial values for the standard logger.
pub const LSTD_FLAGS: i32 = LDATE | LTIME;

type Sink = Box<dyn Write + Send>;

thread_local! {
    /// Location of the user call that is currently being written, so a
    /// destination (slog's `handlerWriter`) can recover the caller like Go's
    /// `runtime.Callers`.
    static WRITE_CALLER: Cell<Option<&'static Location<'static>>> = const { Cell::new(None) };
}

/// The call site of the `Logger` method whose output is being written on this
/// thread, if any. Used by [`slog`] to attach a source to `log` output.
pub(crate) fn current_write_caller() -> Option<&'static Location<'static>> {
    WRITE_CALLER.with(Cell::get)
}

/// An active logging object that generates lines of output to a writer.
/// Each logging operation makes a single `write` call, serialized by a mutex.
pub struct Logger {
    out: Arc<Mutex<Sink>>,
    prefix: Mutex<String>,
    flag: AtomicI32,
}

/// Handle to a logger's output destination, returned by [`Logger::writer`].
/// Writes go to whatever destination the logger currently has.
#[derive(Clone)]
pub struct OutputWriter {
    out: Arc<Mutex<Sink>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Write for OutputWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        lock(&self.out).write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        lock(&self.out).flush()
    }
}

impl fmt::Debug for Logger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Logger")
            .field("prefix", &self.prefix())
            .field("flags", &self.flags())
            .finish_non_exhaustive()
    }
}

/// Appends `i` as decimal, zero-padded to `wid` digits. A negative width
/// avoids zero-padding.
fn itoa(buf: &mut Vec<u8>, i: i64, wid: i32) {
    let digits = i.to_string();
    for _ in digits.len() as i32..wid {
        buf.push(b'0');
    }
    buf.extend_from_slice(digits.as_bytes());
}

/// Writes the log header in Go's order: prefix (unless `LMSGPREFIX`), date,
/// time, file and line, prefix (if `LMSGPREFIX`).
fn format_header(buf: &mut Vec<u8>, t: &DateTime, prefix: &str, flag: i32, file: &str, line: u32) {
    if flag & LMSGPREFIX == 0 {
        buf.extend_from_slice(prefix.as_bytes());
    }
    if flag & (LDATE | LTIME | LMICROSECONDS) != 0 {
        if flag & LDATE != 0 {
            itoa(buf, i64::from(t.year()), 4);
            buf.push(b'/');
            itoa(buf, i64::from(t.month()), 2);
            buf.push(b'/');
            itoa(buf, i64::from(t.day()), 2);
            buf.push(b' ');
        }
        if flag & (LTIME | LMICROSECONDS) != 0 {
            itoa(buf, i64::from(t.hour()), 2);
            buf.push(b':');
            itoa(buf, i64::from(t.minute()), 2);
            buf.push(b':');
            itoa(buf, i64::from(t.second()), 2);
            if flag & LMICROSECONDS != 0 {
                buf.push(b'.');
                itoa(buf, i64::from(t.nanosecond() / 1000), 6);
            }
            buf.push(b' ');
        }
    }
    if flag & (LSHORTFILE | LLONGFILE) != 0 {
        let mut file = file;
        if flag & LSHORTFILE != 0 {
            // Go scans from the end and never treats index 0 as a separator.
            let bytes = file.as_bytes();
            for i in (1..bytes.len()).rev() {
                if bytes[i] == b'/' {
                    file = &file[i + 1..];
                    break;
                }
            }
        }
        buf.extend_from_slice(file.as_bytes());
        buf.push(b':');
        itoa(buf, i64::from(line), -1);
        buf.extend_from_slice(b": ");
    }
    if flag & LMSGPREFIX != 0 {
        buf.extend_from_slice(prefix.as_bytes());
    }
}

/// The local zone's offset in seconds at the instant `seconds`.
fn local_offset(seconds: i64) -> i32 {
    crate::time::unix(seconds, 0)
        .in_location(&crate::time::local())
        .zone()
        .1
}

/// The current time in the local zone, as Go's `time.Now` gives it.
pub(crate) fn now() -> DateTime {
    let now = crate::time::now();
    let (_, offset) = now.zone();
    DateTime::from_unix(now.unix(), now.nanosecond() as u32, offset).expect("current time in range")
}

/// The wall clock a header prints for the instant `t`: local time, or UTC
/// when `flag` has `LUTC`.
fn header_time(t: &DateTime, flag: i32) -> DateTime {
    let offset = if flag & LUTC != 0 {
        0
    } else {
        local_offset(t.unix_seconds())
    };
    DateTime::from_unix(t.unix_seconds(), t.nanosecond(), offset).expect("log time in range")
}

impl Logger {
    /// Creates a new logger. `out` is the destination. `prefix` appears at the
    /// beginning of each line, or after the header with [`LMSGPREFIX`]. `flag`
    /// defines the logging properties.
    pub fn new<W: Write + Send + 'static>(out: W, prefix: &str, flag: i32) -> Logger {
        Logger {
            out: Arc::new(Mutex::new(Box::new(out))),
            prefix: Mutex::new(prefix.to_owned()),
            flag: AtomicI32::new(flag),
        }
    }

    /// Sets the output destination for the logger.
    pub fn set_output<W: Write + Send + 'static>(&self, w: W) {
        *lock(&self.out) = Box::new(w);
    }

    /// Returns a handle that writes to the logger's output destination.
    pub fn writer(&self) -> OutputWriter {
        OutputWriter {
            out: self.out.clone(),
        }
    }

    /// Returns the output flags for the logger.
    pub fn flags(&self) -> i32 {
        self.flag.load(Ordering::SeqCst)
    }

    /// Sets the output flags for the logger.
    pub fn set_flags(&self, flag: i32) {
        self.flag.store(flag, Ordering::SeqCst);
    }

    /// Returns the output prefix for the logger.
    pub fn prefix(&self) -> String {
        lock(&self.prefix).clone()
    }

    /// Sets the output prefix for the logger.
    pub fn set_prefix(&self, prefix: &str) {
        *lock(&self.prefix) = prefix.to_owned();
    }

    /// Writes one log line stamped with `t` instead of the current time.
    /// `loc` supplies the file and line for [`LSHORTFILE`] and [`LLONGFILE`];
    /// without it Go's `???:0` is printed. A newline is appended when the
    /// message does not end in one.
    pub fn output_at(
        &self,
        t: &DateTime,
        loc: Option<&'static Location<'static>>,
        s: &str,
    ) -> io::Result<()> {
        self.write_line(t, loc, s.as_bytes())
    }

    pub(crate) fn write_line(
        &self,
        t: &DateTime,
        loc: Option<&'static Location<'static>>,
        msg: &[u8],
    ) -> io::Result<()> {
        // Load prefix and flag once so they are consistent within this call.
        let prefix = self.prefix();
        let flag = self.flags();
        let (file, line) = match loc {
            Some(l) => (l.file(), l.line()),
            None => ("???", 0),
        };
        let mut buf = Vec::with_capacity(64 + msg.len());
        format_header(&mut buf, &header_time(t, flag), &prefix, flag, file, line);
        buf.extend_from_slice(msg);
        if buf.last() != Some(&b'\n') {
            buf.push(b'\n');
        }
        let mut out = lock(&self.out);
        WRITE_CALLER.with(|c| c.set(loc));
        let result = out.write_all(&buf);
        WRITE_CALLER.with(|c| c.set(None));
        result
    }

    /// Writes the output for a logging event. A newline is appended if `s` does
    /// not already end in one. `calldepth` is accepted for signature parity;
    /// the location is always the direct caller.
    #[track_caller]
    pub fn output(&self, calldepth: i32, s: &str) -> io::Result<()> {
        let _ = calldepth;
        self.write_line(&now(), Some(Location::caller()), s.as_bytes())
    }

    #[track_caller]
    fn emit(&self, s: &str) {
        let _ = self.write_line(&now(), Some(Location::caller()), s.as_bytes());
    }

    /// Prints to the logger (Go `Print`).
    #[track_caller]
    pub fn print(&self, args: fmt::Arguments<'_>) {
        self.emit(&args.to_string());
    }

    /// Prints to the logger (Go `Printf`).
    #[track_caller]
    pub fn printf(&self, args: fmt::Arguments<'_>) {
        self.emit(&args.to_string());
    }

    /// Prints to the logger, always ending the text with a newline (Go `Println`).
    #[track_caller]
    pub fn println(&self, args: fmt::Arguments<'_>) {
        let mut s = args.to_string();
        s.push('\n');
        self.emit(&s);
    }

    /// Equivalent to [`Logger::print`] followed by `std::process::exit(1)`.
    #[track_caller]
    pub fn fatal(&self, args: fmt::Arguments<'_>) -> ! {
        self.emit(&args.to_string());
        std::process::exit(1)
    }

    /// Equivalent to [`Logger::printf`] followed by `std::process::exit(1)`.
    #[track_caller]
    pub fn fatalf(&self, args: fmt::Arguments<'_>) -> ! {
        self.emit(&args.to_string());
        std::process::exit(1)
    }

    /// Equivalent to [`Logger::println`] followed by `std::process::exit(1)`.
    #[track_caller]
    pub fn fatalln(&self, args: fmt::Arguments<'_>) -> ! {
        let mut s = args.to_string();
        s.push('\n');
        self.emit(&s);
        std::process::exit(1)
    }

    /// Equivalent to [`Logger::print`] followed by a panic whose payload is the
    /// message `String`.
    #[track_caller]
    pub fn panic(&self, args: fmt::Arguments<'_>) -> ! {
        let s = args.to_string();
        self.emit(&s);
        std::panic::panic_any(s)
    }

    /// Equivalent to [`Logger::printf`] followed by a panic whose payload is
    /// the message `String`.
    #[track_caller]
    pub fn panicf(&self, args: fmt::Arguments<'_>) -> ! {
        let s = args.to_string();
        self.emit(&s);
        std::panic::panic_any(s)
    }

    /// Equivalent to [`Logger::println`] followed by a panic whose payload is
    /// the message `String`, newline included.
    #[track_caller]
    pub fn panicln(&self, args: fmt::Arguments<'_>) -> ! {
        let mut s = args.to_string();
        s.push('\n');
        self.emit(&s);
        std::panic::panic_any(s)
    }
}

static STD: OnceLock<Logger> = OnceLock::new();

/// Returns the standard logger used by the package-level output functions. It
/// writes to standard error with [`LSTD_FLAGS`].
pub fn default() -> &'static Logger {
    STD.get_or_init(|| Logger::new(io::stderr(), "", LSTD_FLAGS))
}

/// Sets the output destination for the standard logger.
pub fn set_output<W: Write + Send + 'static>(w: W) {
    default().set_output(w);
}

/// Returns the output flags for the standard logger.
pub fn flags() -> i32 {
    default().flags()
}

/// Sets the output flags for the standard logger.
pub fn set_flags(flag: i32) {
    default().set_flags(flag);
}

/// Returns the output prefix for the standard logger.
pub fn prefix() -> String {
    default().prefix()
}

/// Sets the output prefix for the standard logger.
pub fn set_prefix(prefix: &str) {
    default().set_prefix(prefix);
}

/// Returns a handle to the standard logger's output destination.
pub fn writer() -> OutputWriter {
    default().writer()
}

/// Writes `s` to the standard logger (Go `Output`).
#[track_caller]
pub fn output(calldepth: i32, s: &str) -> io::Result<()> {
    default().output(calldepth, s)
}

/// Prints to the standard logger (Go `Print`).
#[track_caller]
pub fn print(args: fmt::Arguments<'_>) {
    default().print(args);
}

/// Prints to the standard logger (Go `Printf`).
#[track_caller]
pub fn printf(args: fmt::Arguments<'_>) {
    default().printf(args);
}

/// Prints to the standard logger with a trailing newline (Go `Println`).
#[track_caller]
pub fn println(args: fmt::Arguments<'_>) {
    default().println(args);
}

/// [`fn@print`] followed by `std::process::exit(1)`.
#[track_caller]
pub fn fatal(args: fmt::Arguments<'_>) -> ! {
    default().fatal(args)
}

/// [`printf`] followed by `std::process::exit(1)`.
#[track_caller]
pub fn fatalf(args: fmt::Arguments<'_>) -> ! {
    default().fatalf(args)
}

/// [`fn@println`] followed by `std::process::exit(1)`.
#[track_caller]
pub fn fatalln(args: fmt::Arguments<'_>) -> ! {
    default().fatalln(args)
}

/// [`fn@print`] followed by a panic with the message as a `String` payload.
#[track_caller]
pub fn panic(args: fmt::Arguments<'_>) -> ! {
    default().panic(args)
}

/// [`printf`] followed by a panic with the message as a `String` payload.
#[track_caller]
pub fn panicf(args: fmt::Arguments<'_>) -> ! {
    default().panicf(args)
}

/// [`fn@println`] followed by a panic with the message as a `String` payload.
#[track_caller]
pub fn panicln(args: fmt::Arguments<'_>) -> ! {
    default().panicln(args)
}
