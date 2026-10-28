//! Go's `slog.Handler`, `HandlerOptions`, `TextHandler`, `JSONHandler` and `DiscardHandler`.
//!
//! The handlers are a port of Go's `commonHandler` state machine so that the
//! preformatted-attribute, group-prefix and separator rules produce
//! byte-identical output.
use super::{
    anyval::json_float,
    level::{Level, Leveler, LEVEL_INFO},
    record::{Record, Source},
    value::{count_empty_groups, is_zero_time, string_value, Attr, Kind, TextValue, Value},
};
use crate::{context::Context, strconv, time::DateTime, unicode};
use std::{
    io::{self, Write},
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{Arc, Mutex},
};

/// Key used by the built-in handlers for the time of the log call.
pub const TIME_KEY: &str = "time";
/// Key used by the built-in handlers for the level of the log call.
pub const LEVEL_KEY: &str = "level";
/// Key used by the built-in handlers for the message of the log call.
pub const MESSAGE_KEY: &str = "msg";
/// Key used by the built-in handlers for the source file and line of the log call.
pub const SOURCE_KEY: &str = "source";

/// Handles log records produced by a [`Logger`](super::Logger).
///
/// Any of the methods may be called concurrently. Handle methods that produce
/// output should ignore a zero `Record::time` and an unset `Record::pc`, use
/// resolved attribute values, ignore attributes whose key and value are both
/// zero, inline groups with an empty key and ignore groups without attributes.
pub trait Handler: Send + Sync {
    /// Reports whether the handler handles records at the given level.
    fn enabled(&self, ctx: &Context, level: Level) -> bool;
    /// Handles the record. It is only called when `enabled` returns true.
    fn handle(&self, ctx: &Context, r: Record) -> io::Result<()>;
    /// Returns a new handler whose attributes consist of both the receiver's
    /// attributes and the arguments.
    fn with_attrs(&self, attrs: Vec<Attr>) -> Arc<dyn Handler>;
    /// Returns a new handler with the given group appended to the receiver's
    /// existing groups.
    fn with_group(&self, name: &str) -> Arc<dyn Handler>;

    /// Reports whether this is the initial default handler, whose output
    /// `set_default` leaves wired to the `log` package. Custom handlers keep
    /// the default `false`.
    #[doc(hidden)]
    fn is_default_handler(&self) -> bool {
        false
    }
}

/// Rewrites each non-group attribute before it is logged. Receives the
/// currently open groups and the attribute; returning a zero `Attr` discards it.
pub type ReplaceAttr = Arc<dyn Fn(&[String], Attr) -> Attr + Send + Sync>;

/// Options for a [`TextHandler`] or [`JSONHandler`]. The default value
/// consists entirely of default values.
#[derive(Clone, Default)]
pub struct HandlerOptions {
    /// Causes the handler to compute the source code position of the log
    /// statement and add a `source` attribute to the output.
    pub add_source: bool,
    /// The minimum record level that will be logged; `None` means `LEVEL_INFO`.
    pub level: Option<Arc<dyn Leveler>>,
    /// Called to rewrite each non-group attribute before it is logged. See
    /// [`ReplaceAttr`].
    pub replace_attr: Option<ReplaceAttr>,
}

type Writer = Arc<Mutex<Box<dyn Write + Send>>>;

#[derive(Clone)]
pub(crate) struct CommonHandler {
    json: bool,
    opts: HandlerOptions,
    preformatted_attrs: Vec<u8>,
    /// Text handler only: the prefix for groups that were already pre-formatted.
    group_prefix: String,
    /// All groups started from `with_group`.
    groups: Vec<String>,
    /// The number of groups opened in `preformatted_attrs`.
    n_open_groups: usize,
    w: Option<Writer>,
}

impl CommonHandler {
    fn new<W: Write + Send + 'static>(json: bool, w: W, opts: Option<HandlerOptions>) -> Self {
        let w: Box<dyn Write + Send> = Box::new(w);
        CommonHandler {
            json,
            opts: opts.unwrap_or_default(),
            preformatted_attrs: Vec::new(),
            group_prefix: String::new(),
            groups: Vec::new(),
            n_open_groups: 0,
            w: Some(Arc::new(Mutex::new(w))),
        }
    }

    fn enabled(&self, l: Level) -> bool {
        let min = self.opts.level.as_ref().map_or(LEVEL_INFO, |lv| lv.level());
        l >= min
    }

    fn attr_sep(&self) -> &'static str {
        if self.json {
            ","
        } else {
            " "
        }
    }

    pub(crate) fn with_attrs(&self, attrs: &[Attr]) -> CommonHandler {
        // Empty groups are ignored, so if the entire slice consists of them
        // there is nothing to do.
        if count_empty_groups(attrs) == attrs.len() {
            return self.clone();
        }
        let mut h2 = self.clone();
        let (buf, new_prefix) = {
            let mut state = HandleState::new(&h2, h2.preformatted_attrs.clone(), "");
            state.prefix.extend_from_slice(self.group_prefix.as_bytes());
            if let Some(&last) = h2.preformatted_attrs.last() {
                state.sep = self.attr_sep();
                if h2.json && last == b'{' {
                    state.sep = "";
                }
            }
            // Remember the position in the buffer, in case all attrs are empty.
            let pos = state.buf.len();
            state.open_groups();
            if !state.append_attrs(attrs) {
                state.buf.truncate(pos);
                (state.buf, None)
            } else {
                // Remember the new prefix for later keys.
                let prefix = String::from_utf8_lossy(&state.prefix).into_owned();
                (state.buf, Some(prefix))
            }
        };
        h2.preformatted_attrs = buf;
        if let Some(prefix) = new_prefix {
            h2.group_prefix = prefix;
            // Remember how many opened groups are in preformatted_attrs, so
            // they are not opened again when a record is handled.
            h2.n_open_groups = h2.groups.len();
        }
        h2
    }

    pub(crate) fn with_group(&self, name: &str) -> CommonHandler {
        let mut h2 = self.clone();
        h2.groups.push(name.to_owned());
        h2
    }

    fn handle(&self, r: &Record) -> io::Result<()> {
        let mut state = HandleState::new(self, Vec::new(), "");
        if self.json {
            state.buf.push(b'{');
        }
        // Built-in attributes. They are not in a group.
        let state_groups = state.groups.take(); // ReplaceAttr sees no groups.
        let rep = self.opts.replace_attr.is_some();
        if !is_zero_time(&r.time) {
            if !rep {
                state.append_key(TIME_KEY);
                state.append_time(&r.time);
            } else {
                state.append_attr(Attr::new(TIME_KEY, Value::Time(r.time)));
            }
        }
        if !rep {
            state.append_key(LEVEL_KEY);
            state.append_string(&r.level.to_string());
        } else {
            state.append_attr(Attr::new(LEVEL_KEY, Value::dynamic(r.level)));
        }
        if self.opts.add_source {
            let src = r.source().unwrap_or_default();
            state.append_attr(Attr::new(SOURCE_KEY, Value::dynamic(src)));
        }
        if !rep {
            state.append_key(MESSAGE_KEY);
            state.append_string(&r.message);
        } else {
            state.append_attr(Attr::new(MESSAGE_KEY, string_value(&r.message)));
        }
        state.groups = state_groups; // Restore groups passed to ReplaceAttr.
        state.append_non_built_ins(r);
        state.buf.push(b'\n');
        let buf = state.buf;
        match &self.w {
            Some(w) => w.lock().unwrap_or_else(|e| e.into_inner()).write_all(&buf),
            None => Ok(()),
        }
    }
}

/// State for a single call to `CommonHandler::handle`.
struct HandleState<'a> {
    h: &'a CommonHandler,
    buf: Vec<u8>,
    /// Separator to write before the next key.
    sep: &'static str,
    /// For text: key prefix.
    prefix: Vec<u8>,
    /// Active groups, for ReplaceAttr.
    groups: Option<Vec<String>>,
}

/// How rendering a dynamic value failed.
enum Failure {
    Error(String),
    Panic(String),
}

fn guarded<T>(f: impl FnOnce() -> Result<T, String>) -> Result<T, Failure> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(Failure::Error(e)),
        Err(p) => {
            let mut msg = String::new();
            super::anyval::write_panic_message(&mut msg, p.as_ref());
            Err(Failure::Panic(msg))
        }
    }
}

impl<'a> HandleState<'a> {
    fn new(h: &'a CommonHandler, buf: Vec<u8>, sep: &'static str) -> Self {
        HandleState {
            h,
            buf,
            sep,
            prefix: Vec::new(),
            groups: h
                .opts
                .replace_attr
                .as_ref()
                .map(|_| h.groups[..h.n_open_groups].to_vec()),
        }
    }

    fn open_groups(&mut self) {
        let h = self.h;
        for n in &h.groups[h.n_open_groups..] {
            self.open_group(n);
        }
    }

    /// Starts a new group of attributes with the given name.
    fn open_group(&mut self, name: &str) {
        if self.h.json {
            self.append_key(name);
            self.buf.push(b'{');
            self.sep = "";
        } else {
            self.prefix.extend_from_slice(name.as_bytes());
            self.prefix.push(b'.');
        }
        // Collect group names for ReplaceAttr.
        if let Some(g) = &mut self.groups {
            g.push(name.to_owned());
        }
    }

    /// Ends the group with the given name.
    fn close_group(&mut self, name: &str) {
        if self.h.json {
            self.buf.push(b'}');
        } else {
            let n = self.prefix.len().saturating_sub(name.len() + 1);
            self.prefix.truncate(n);
        }
        self.sep = self.h.attr_sep();
        if let Some(g) = &mut self.groups {
            g.pop();
        }
    }

    fn append_non_built_ins(&mut self, r: &Record) {
        let h = self.h;
        // Preformatted attrs.
        if let Some(&last) = h.preformatted_attrs.last() {
            self.buf.extend_from_slice(self.sep.as_bytes());
            self.buf.extend_from_slice(&h.preformatted_attrs);
            self.sep = h.attr_sep();
            if h.json && last == b'{' {
                self.sep = "";
            }
        }
        // Attrs in the record -- unlike the built-in ones, they are in groups
        // started from with_group. If the record has no attrs, don't output
        // any groups.
        let mut n_open_groups = h.n_open_groups;
        if r.num_attrs() > 0 {
            self.prefix.extend_from_slice(h.group_prefix.as_bytes());
            // The group may turn out to be empty even though it has attrs (for
            // example, ReplaceAttr may delete all the attrs). So remember where
            // we are in the buffer, to restore the position later if necessary.
            let pos = self.buf.len();
            self.open_groups();
            n_open_groups = h.groups.len();
            let mut empty = true;
            r.attrs(|a| {
                if self.append_attr(a.clone()) {
                    empty = false;
                }
                true
            });
            if empty {
                self.buf.truncate(pos);
                n_open_groups = h.n_open_groups;
            }
        }
        if h.json {
            // Close all open groups.
            for _ in 0..n_open_groups {
                self.buf.push(b'}');
            }
            // Close the top-level object.
            self.buf.push(b'}');
        }
    }

    /// Appends the slice of attrs. Reports whether something was appended.
    fn append_attrs(&mut self, attrs: &[Attr]) -> bool {
        let mut non_empty = false;
        for a in attrs {
            if self.append_attr(a.clone()) {
                non_empty = true;
            }
        }
        non_empty
    }

    /// Appends the attr's key and value. It handles replacement and checking
    /// for an empty key. Reports whether something was appended.
    fn append_attr(&mut self, mut a: Attr) -> bool {
        let h = self.h;
        a.value = a.value.resolve();
        if let Some(rep) = &h.opts.replace_attr {
            if a.value.kind() != Kind::Group {
                let gs: &[String] = self.groups.as_deref().unwrap_or(&[]);
                // a.value is resolved before calling ReplaceAttr, so the user
                // doesn't have to.
                a = rep(gs, a);
                // The ReplaceAttr function may return an unresolved Attr.
                a.value = a.value.resolve();
            }
        }
        // Elide empty Attrs.
        if a.is_empty() {
            return false;
        }
        // Special case: Source.
        let source_value = match &a.value {
            Value::Any(Some(d)) => d.as_any().downcast_ref::<Source>().map(|src| {
                if src.is_empty() {
                    None
                } else if h.json {
                    Some(src.group())
                } else {
                    Some(string_value(&format!("{}:{}", src.file, src.line)))
                }
            }),
            _ => None,
        };
        match source_value {
            Some(None) => return false,
            Some(Some(v)) => a.value = v,
            None => {}
        }
        if let Value::Group(attrs) = &a.value {
            // Output only non-empty groups.
            if !attrs.is_empty() {
                // The group may turn out to be empty even though it has attrs.
                // So remember where we are in the buffer, to restore the
                // position later if necessary.
                let pos = self.buf.len();
                // Inline a group with an empty key.
                if !a.key.is_empty() {
                    self.open_group(&a.key);
                }
                if !self.append_attrs(attrs) {
                    self.buf.truncate(pos);
                    return false;
                }
                if !a.key.is_empty() {
                    self.close_group(&a.key);
                }
            }
        } else {
            self.append_key(&a.key);
            self.append_value(&a.value);
        }
        true
    }

    fn append_error(&mut self, err: &str) {
        self.append_string(&format!("!ERROR:{err}"));
    }

    fn append_key(&mut self, key: &str) {
        self.buf.extend_from_slice(self.sep.as_bytes());
        if !self.prefix.is_empty() {
            let prefix = String::from_utf8_lossy(&self.prefix).into_owned();
            self.append_two_strings(&prefix, key);
        } else {
            self.append_string(key);
        }
        self.buf.push(if self.h.json { b':' } else { b'=' });
        self.sep = self.h.attr_sep();
    }

    /// Implements `append_string(prefix + key)`, but faster.
    fn append_two_strings(&mut self, x: &str, y: &str) {
        if self.h.json {
            self.buf.push(b'"');
            append_escaped_json_string(&mut self.buf, x);
            append_escaped_json_string(&mut self.buf, y);
            self.buf.push(b'"');
        } else if !needs_quoting(x) && !needs_quoting(y) {
            self.buf.extend_from_slice(x.as_bytes());
            self.buf.extend_from_slice(y.as_bytes());
        } else {
            strconv::append_quote(&mut self.buf, format!("{x}{y}"));
        }
    }

    fn append_string(&mut self, s: &str) {
        if self.h.json {
            self.buf.push(b'"');
            append_escaped_json_string(&mut self.buf, s);
            self.buf.push(b'"');
        } else if needs_quoting(s) {
            strconv::append_quote(&mut self.buf, s);
        } else {
            self.buf.extend_from_slice(s.as_bytes());
        }
    }

    fn append_value(&mut self, v: &Value) {
        let result = if self.h.json {
            self.append_json_value(v)
        } else {
            self.append_text_value(v)
        };
        match result {
            Ok(()) => {}
            Err(Failure::Error(e)) => self.append_error(&e),
            Err(Failure::Panic(p)) => self.append_string(&format!("!PANIC: {p}")),
        }
    }

    fn append_time(&mut self, t: &DateTime) {
        if self.h.json {
            self.buf.push(b'"');
            append_rfc3339(&mut self.buf, t, false);
            self.buf.push(b'"');
        } else {
            append_rfc3339(&mut self.buf, t, true);
        }
    }

    fn append_json_value(&mut self, v: &Value) -> Result<(), Failure> {
        match v {
            Value::String(s) => self.append_string(s),
            Value::Int64(i) => strconv::append_int(&mut self.buf, *i, 10),
            Value::Uint64(u) => strconv::append_uint(&mut self.buf, *u, 10),
            Value::Float64(f) => {
                let s = json_float(*f).map_err(Failure::Error)?;
                self.buf.extend_from_slice(s.as_bytes());
            }
            Value::Bool(b) => self
                .buf
                .extend_from_slice(if *b { b"true" } else { b"false" }),
            Value::Duration(d) => strconv::append_int(&mut self.buf, d.as_nanos(), 10),
            Value::Time(t) => self.append_time(t),
            Value::Any(None) => self.buf.extend_from_slice(b"null"),
            Value::Any(Some(d)) => {
                if let Some(msg) = guarded(|| Ok(d.error_message()))? {
                    self.append_string(&msg);
                } else {
                    let s = guarded(|| d.json())?;
                    self.buf.extend_from_slice(s.as_bytes());
                }
            }
            Value::Group(_) | Value::LogValuer(_) => {
                panic!("bad kind: {}", v.kind())
            }
        }
        Ok(())
    }

    fn append_text_value(&mut self, v: &Value) -> Result<(), Failure> {
        match v {
            Value::String(s) => self.append_string(s),
            Value::Time(t) => self.append_time(t),
            Value::Any(None) => self.append_string("<nil>"),
            Value::Any(Some(d)) => match guarded(|| d.text())? {
                TextValue::Plain(s) => self.append_string(&s),
                TextValue::Literal(s) => self.buf.extend_from_slice(s.as_bytes()),
            },
            other => self.buf.extend_from_slice(other.to_string().as_bytes()),
        }
        Ok(())
    }
}

/// Appends `t` as RFC 3339. With `millis` the fraction has exactly three
/// digits (truncated); otherwise it is the shortest nanosecond form.
fn append_rfc3339(buf: &mut Vec<u8>, t: &DateTime, millis: bool) {
    let mut s = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        t.year(),
        t.month(),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    );
    if millis {
        s.push_str(&format!(".{:03}", t.nanosecond() / 1_000_000));
    } else if t.nanosecond() != 0 {
        s.push('.');
        s.push_str(format!("{:09}", t.nanosecond()).trim_end_matches('0'));
    }
    if t.offset() == 0 {
        s.push('Z');
    } else {
        // Go truncates to minutes first, so offsets under a minute print +00:00.
        let minutes = t.offset() / 60;
        s.push(if minutes < 0 { '-' } else { '+' });
        s.push_str(&format!(
            "{:02}:{:02}",
            minutes.abs() / 60,
            minutes.abs() % 60
        ));
    }
    buf.extend_from_slice(s.as_bytes());
}

/// Reports whether `s` is a character that is safe to leave unescaped in
/// quoted-or-not output (Go's `safeSet`).
fn safe(b: u8) -> bool {
    (0x20..=0x7f).contains(&b) && b != b'"' && b != b'\\'
}

fn needs_quoting(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }
    for c in s.chars() {
        if c.is_ascii() {
            let b = c as u8;
            if b != b'\\' && (b == b' ' || b == b'=' || !safe(b)) {
                return true;
            }
        } else if c == '\u{FFFD}' || unicode::is_space(c as i32) || !unicode::is_print(c as i32) {
            return true;
        }
    }
    false
}

fn append_escaped_json_string(buf: &mut Vec<u8>, s: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for c in s.chars() {
        if c.is_ascii() {
            let b = c as u8;
            if safe(b) {
                buf.push(b);
                continue;
            }
            buf.push(b'\\');
            match b {
                b'\\' | b'"' => buf.push(b),
                b'\n' => buf.push(b'n'),
                b'\r' => buf.push(b'r'),
                b'\t' => buf.push(b't'),
                _ => {
                    buf.extend_from_slice(b"u00");
                    buf.push(HEX[usize::from(b >> 4)]);
                    buf.push(HEX[usize::from(b & 0xf)]);
                }
            }
        } else if c == '\u{2028}' || c == '\u{2029}' {
            buf.extend_from_slice(b"\\u202");
            buf.push(HEX[(c as usize) & 0xf]);
        } else {
            let mut tmp = [0u8; 4];
            buf.extend_from_slice(c.encode_utf8(&mut tmp).as_bytes());
        }
    }
}

macro_rules! common_handler {
    ($name:ident, $json:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name {
            ch: CommonHandler,
        }

        impl $name {
            /// Creates a handler that writes to `w`, using the given options.
            /// `None` options are the defaults.
            pub fn new<W: Write + Send + 'static>(w: W, opts: Option<HandlerOptions>) -> Self {
                Self {
                    ch: CommonHandler::new($json, w, opts),
                }
            }
        }

        impl Handler for $name {
            fn enabled(&self, _ctx: &Context, level: Level) -> bool {
                self.ch.enabled(level)
            }
            fn handle(&self, _ctx: &Context, r: Record) -> io::Result<()> {
                self.ch.handle(&r)
            }
            fn with_attrs(&self, attrs: Vec<Attr>) -> Arc<dyn Handler> {
                Arc::new($name {
                    ch: self.ch.with_attrs(&attrs),
                })
            }
            fn with_group(&self, name: &str) -> Arc<dyn Handler> {
                Arc::new($name {
                    ch: self.ch.with_group(name),
                })
            }
        }
    };
}

common_handler!(
    TextHandler,
    false,
    "A handler that writes records to an `io::Write` as a sequence of `key=value` pairs separated by spaces and followed by a newline."
);
common_handler!(
    JSONHandler,
    true,
    "A handler that writes records to an `io::Write` as line-delimited JSON objects."
);

/// A handler that discards all log output. `enabled` returns false for all levels.
#[derive(Clone, Copy, Debug, Default)]
pub struct DiscardHandler;

/// The value of Go's `slog.DiscardHandler`.
pub const DISCARD_HANDLER: DiscardHandler = DiscardHandler;

impl Handler for DiscardHandler {
    fn enabled(&self, _ctx: &Context, _level: Level) -> bool {
        false
    }
    fn handle(&self, _ctx: &Context, _r: Record) -> io::Result<()> {
        Ok(())
    }
    fn with_attrs(&self, _attrs: Vec<Attr>) -> Arc<dyn Handler> {
        Arc::new(*self)
    }
    fn with_group(&self, _name: &str) -> Arc<dyn Handler> {
        Arc::new(*self)
    }
}

/// The handler of the initial default logger: it formats the level, message
/// and attributes as text and writes them through the standard `log` logger,
/// which adds the time and file/line.
#[derive(Clone)]
pub(crate) struct DefaultHandler {
    ch: CommonHandler,
}

impl DefaultHandler {
    pub(crate) fn new() -> Self {
        DefaultHandler {
            ch: CommonHandler {
                json: false,
                opts: HandlerOptions::default(),
                preformatted_attrs: Vec::new(),
                group_prefix: String::new(),
                groups: Vec::new(),
                n_open_groups: 0,
                w: None,
            },
        }
    }
}

impl Handler for DefaultHandler {
    fn is_default_handler(&self) -> bool {
        true
    }

    fn enabled(&self, _ctx: &Context, l: Level) -> bool {
        l >= super::logger::log_logger_level().level()
    }

    fn handle(&self, _ctx: &Context, r: Record) -> io::Result<()> {
        let mut buf = Vec::new();
        buf.extend_from_slice(r.level.to_string().as_bytes());
        buf.push(b' ');
        buf.extend_from_slice(r.message.as_bytes());
        let mut state = HandleState::new(&self.ch, buf, " ");
        state.append_non_built_ins(&r);
        crate::log::default().write_line(&crate::log::now(), r.pc, &state.buf)
    }

    fn with_attrs(&self, attrs: Vec<Attr>) -> Arc<dyn Handler> {
        Arc::new(DefaultHandler {
            ch: self.ch.with_attrs(&attrs),
        })
    }

    fn with_group(&self, name: &str) -> Arc<dyn Handler> {
        Arc::new(DefaultHandler {
            ch: self.ch.with_group(name),
        })
    }
}
