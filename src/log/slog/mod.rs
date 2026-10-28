//! Go's `log/slog` package: structured logging.
//!
//! A [`Logger`] turns each call into a [`Record`] (time, level, message and
//! [`Attr`]s) and passes it to a [`Handler`]. [`TextHandler`] and
//! [`JSONHandler`] produce the same bytes as Go's for the same records.
//!
//! ```
//! use rust_stdlib::log::slog::{self, HandlerOptions, Logger, TextHandler};
//! use std::sync::Arc;
//! let logger = Logger::new(Arc::new(TextHandler::new(std::io::stderr(), None)));
//! logger.info("hello", &["count".into(), 3i64.into()]);
//! let _ = (HandlerOptions::default(), slog::LEVEL_INFO);
//! ```
//!
//! Deviations from Go, all forced by Rust std:
//! - Go's `...any` argument lists are `&[Arg]` (an [`Arg`] is an [`Attr`] or a
//!   value; string values in key position start a key/value pair).
//! - Go's `any` payloads implement [`Dynamic`], which states how Go's `%+v`
//!   and `json.Marshal` would render the value; [`JsonAny`], [`ErrorValue`]
//!   and [`Bytes`] cover decoded-JSON values, errors and byte slices.
//! - Rust strings are valid UTF-8, so Go's invalid-UTF-8 repairs never occur.
//! - A `Record`'s program counter is the `#[track_caller]` location of the
//!   logging call; `Source::function` is therefore always empty.
//! - Times are `time::DateTime`; "local" time is UTC (no zone database).
//! - A `LogValuer` panic message has no Go stack trace, and `%T` is a Rust
//!   type name.
pub use anyval::{Bytes, ErrorValue, JsonAny};
pub use handler::{
    DiscardHandler, Handler, HandlerOptions, JSONHandler, ReplaceAttr, TextHandler,
    DISCARD_HANDLER, LEVEL_KEY, MESSAGE_KEY, SOURCE_KEY, TIME_KEY,
};
pub use level::{
    Level, LevelParseError, LevelVar, Leveler, LEVEL_DEBUG, LEVEL_ERROR, LEVEL_INFO, LEVEL_WARN,
};
pub use logger::{
    debug, debug_context, default, error, error_context, info, info_context, log, log_attrs,
    log_logger, set_default, set_log_logger_level, warn, warn_context, with, Logger, MultiHandler,
};
pub use record::{Record, Source};
pub use value::{
    any, any_value, bool, bool_value, duration, duration_value, float64, float64_value, group,
    group_attrs, group_value, int, int64, int64_value, int_value, is_zero_time, string,
    string_value, time, time_value, uint64, uint64_value, zero_time, Arg, Attr, Dynamic, Kind,
    LogValuer, TextValue, Value, KIND_ANY, KIND_BOOL, KIND_DURATION, KIND_FLOAT64, KIND_GROUP,
    KIND_INT64, KIND_LOG_VALUER, KIND_STRING, KIND_TIME, KIND_UINT64,
};

mod anyval;
mod handler;
mod level;
mod logger;
mod record;
mod value;
