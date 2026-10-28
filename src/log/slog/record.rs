//! Go's `slog.Record` and `slog.Source`.
use super::{
    anyval::json_string,
    level::Level,
    value::{
        args_to_attr, group_value, int, string, zero_time, Arg, Attr, Dynamic, TextValue, Value,
    },
};
use crate::time::DateTime;
use std::{any::Any, panic::Location};

/// A log record: the time, level and message of a log event plus its
/// attributes. `pc` is the call site, the Rust counterpart of Go's program
/// counter.
#[derive(Clone, Debug)]
pub struct Record {
    /// The time at which the output method was called; the zero time (see
    /// [`zero_time`]) means "no time".
    pub time: DateTime,
    /// The log message.
    pub message: String,
    /// The level of the event.
    pub level: Level,
    /// The source location of the logging call, if known. `None` is Go's
    /// zero `PC`.
    pub pc: Option<&'static Location<'static>>,
    attrs: Vec<Attr>,
}

impl Default for Record {
    fn default() -> Self {
        Record::new(zero_time(), Level::default(), "", None)
    }
}

impl Record {
    /// Creates a [`Record`] from the given arguments. Use [`Record::add_attrs`]
    /// or [`Record::add`] to add attributes.
    pub fn new(
        t: DateTime,
        level: Level,
        msg: &str,
        pc: Option<&'static Location<'static>>,
    ) -> Record {
        Record {
            time: t,
            message: msg.to_owned(),
            level,
            pc,
            attrs: Vec::new(),
        }
    }

    /// Returns the number of attributes in the record.
    pub fn num_attrs(&self) -> usize {
        self.attrs.len()
    }

    /// Calls `f` on each attribute in the record, stopping early when it
    /// returns false.
    pub fn attrs(&self, mut f: impl FnMut(&Attr) -> bool) {
        for a in &self.attrs {
            if !f(a) {
                return;
            }
        }
    }

    /// Appends attributes to the record. Empty groups are dropped.
    pub fn add_attrs(&mut self, attrs: &[Attr]) {
        self.attrs
            .extend(attrs.iter().filter(|a| !a.value.is_empty_group()).cloned());
    }

    /// Converts the arguments to attributes and appends them to the record,
    /// see [`Arg`]. Empty groups are dropped.
    pub fn add(&mut self, mut args: &[Arg]) {
        while !args.is_empty() {
            let (a, rest) = args_to_attr(args);
            args = rest;
            if a.value.is_empty_group() {
                continue;
            }
            self.attrs.push(a);
        }
    }

    /// Returns the location of the logging call, or `None` if `pc` is unset.
    /// `function` is always empty: Rust exposes no function names at runtime.
    pub fn source(&self) -> Option<Source> {
        let loc = self.pc?;
        Some(Source {
            function: String::new(),
            file: loc.file().to_owned(),
            line: i64::from(loc.line()),
        })
    }
}

/// Describes the location of a line of source code.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Source {
    /// The function name; always empty for sources derived from `pc`.
    pub function: String,
    /// The file name.
    pub file: String,
    /// The line number.
    pub line: i64,
}

impl Source {
    /// Returns a group value holding the non-empty fields.
    pub(crate) fn group(&self) -> Value {
        let mut as_ = Vec::new();
        if !self.function.is_empty() {
            as_.push(string("function", &self.function));
        }
        if !self.file.is_empty() {
            as_.push(string("file", &self.file));
        }
        if self.line != 0 {
            as_.push(int("line", self.line as isize));
        }
        group_value(as_)
    }

    pub(crate) fn is_empty(&self) -> bool {
        *self == Source::default()
    }
}

impl Dynamic for Source {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn text(&self) -> Result<TextValue, String> {
        Ok(TextValue::Plain(format!(
            "&{{Function:{} File:{} Line:{}}}",
            self.function, self.file, self.line
        )))
    }
    fn json(&self) -> Result<String, String> {
        Ok(format!(
            "{{\"function\":{},\"file\":{},\"line\":{}}}",
            json_string(&self.function),
            json_string(&self.file),
            self.line
        ))
    }
    fn dyn_eq(&self, other: &dyn Dynamic) -> bool {
        other.as_any().downcast_ref::<Self>() == Some(self)
    }
}
