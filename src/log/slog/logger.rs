//! Go's `slog.Logger`, the default logger and the `log` bridge.
use super::{
    handler::{DefaultHandler, Handler},
    level::{Level, LevelVar, Leveler, LEVEL_DEBUG, LEVEL_ERROR, LEVEL_INFO, LEVEL_WARN},
    record::Record,
    value::{args_to_attr_slice, Arg, Attr},
};
use crate::{context::Context, log as stdlog};
use std::{
    io::{self, Write},
    panic::Location,
    sync::{Arc, OnceLock, RwLock},
};

static LOG_LOGGER_LEVEL: LevelVar = LevelVar::new();

pub(crate) fn log_logger_level() -> &'static LevelVar {
    &LOG_LOGGER_LEVEL
}

/// Sets the level for the bridge from `log` to the default `slog` logger and
/// returns the previous level. It applies to `log` output redirected by
/// [`set_default`] and to the default handler.
pub fn set_log_logger_level(level: Level) -> Level {
    let old = LOG_LOGGER_LEVEL.level();
    LOG_LOGGER_LEVEL.set(level);
    old
}

/// A [`Leveler`] reading the package-level `log` bridge level.
struct BridgeLevel;

impl Leveler for BridgeLevel {
    fn level(&self) -> Level {
        LOG_LOGGER_LEVEL.level()
    }
}

fn default_context() -> &'static Context {
    static BACKGROUND: OnceLock<Context> = OnceLock::new();
    BACKGROUND.get_or_init(Context::background)
}

static DEFAULT_LOGGER: RwLock<Option<Logger>> = RwLock::new(None);

/// Returns the default logger. Its handler writes through the standard `log`
/// logger until [`set_default`] replaces it.
pub fn default() -> Logger {
    if let Some(l) = DEFAULT_LOGGER
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
    {
        return l.clone();
    }
    let mut guard = DEFAULT_LOGGER.write().unwrap_or_else(|e| e.into_inner());
    guard
        .get_or_insert_with(|| Logger::new(Arc::new(DefaultHandler::new())))
        .clone()
}

/// Makes `l` the default logger, which is used by the top-level functions
/// like [`info`]. It also redirects the output of the `log` package's
/// standard logger to `l`'s handler at the level set by
/// [`set_log_logger_level`], with no time or location of its own, unless
/// `l` uses the initial default handler.
pub fn set_default(l: Logger) {
    let handler = l.handler.clone();
    *DEFAULT_LOGGER.write().unwrap_or_else(|e| e.into_inner()) = Some(l);
    if !handler.is_default_handler() {
        let capture_pc = stdlog::flags() & (stdlog::LSHORTFILE | stdlog::LLONGFILE) != 0;
        stdlog::set_output(HandlerWriter {
            h: handler,
            level: Arc::new(BridgeLevel),
            capture_pc,
        });
        stdlog::set_flags(0); // we want just the log message, no time or location
    }
}

/// Adapts a [`Handler`] to `io::Write` so a `log::Logger` can feed it.
struct HandlerWriter {
    h: Arc<dyn Handler>,
    level: Arc<dyn Leveler>,
    capture_pc: bool,
}

impl Write for HandlerWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let level = self.level.level();
        let ctx = default_context();
        // Report that the entire buf was written, even when discarded.
        if !self.h.enabled(ctx, level) {
            return Ok(buf.len());
        }
        let pc = if self.capture_pc {
            stdlog::current_write_caller()
        } else {
            None
        };
        let msg = buf.strip_suffix(b"\n").unwrap_or(buf);
        let r = Record::new(stdlog::now(), level, &String::from_utf8_lossy(msg), pc);
        self.h.handle(ctx, r)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Returns a new `log::Logger` that writes each message at `level` to the
/// handler. The logger's flags are zero, so the handler supplies the time, and
/// the source is the location of the logging call when the handler asks for it.
pub fn log_logger(h: Arc<dyn Handler>, level: Level) -> stdlog::Logger {
    stdlog::Logger::new(
        HandlerWriter {
            h,
            level: Arc::new(level),
            capture_pc: true,
        },
        "",
        0,
    )
}

/// Structured logging over a [`Handler`]. The logging methods take a message
/// and a list of attributes (see [`Arg`]); a record is created and passed to
/// the handler if the handler is enabled for the level.
#[derive(Clone)]
pub struct Logger {
    handler: Arc<dyn Handler>,
}

impl Logger {
    /// Creates a new logger with the given non-nil handler.
    pub fn new(h: Arc<dyn Handler>) -> Logger {
        Logger { handler: h }
    }

    /// Returns the logger's handler.
    pub fn handler(&self) -> Arc<dyn Handler> {
        self.handler.clone()
    }

    /// Returns a logger that includes the given attributes in each output
    /// operation, see [`Arg`].
    pub fn with(&self, args: &[Arg]) -> Logger {
        if args.is_empty() {
            return self.clone();
        }
        Logger {
            handler: self.handler.with_attrs(args_to_attr_slice(args)),
        }
    }

    /// Returns a logger that starts a group, if name is nonempty.
    pub fn with_group(&self, name: &str) -> Logger {
        if name.is_empty() {
            return self.clone();
        }
        Logger {
            handler: self.handler.with_group(name),
        }
    }

    /// Reports whether the logger's handler is enabled for the level.
    pub fn enabled(&self, ctx: &Context, level: Level) -> bool {
        self.handler.enabled(ctx, level)
    }

    /// Emits a log record with the current time and the given level and message.
    #[track_caller]
    pub fn log(&self, ctx: &Context, level: Level, msg: &str, args: &[Arg]) {
        self.log_inner(ctx, level, msg, args);
    }

    /// A more efficient version of [`Logger::log`] that accepts only `Attr`s.
    #[track_caller]
    pub fn log_attrs(&self, ctx: &Context, level: Level, msg: &str, attrs: &[Attr]) {
        if !self.enabled(ctx, level) {
            return;
        }
        let mut r = Record::new(stdlog::now(), level, msg, Some(Location::caller()));
        r.add_attrs(attrs);
        let _ = self.handler.handle(ctx, r);
    }

    #[track_caller]
    fn log_inner(&self, ctx: &Context, level: Level, msg: &str, args: &[Arg]) {
        if !self.enabled(ctx, level) {
            return;
        }
        let mut r = Record::new(stdlog::now(), level, msg, Some(Location::caller()));
        r.add(args);
        let _ = self.handler.handle(ctx, r);
    }

    /// Logs at [`LEVEL_DEBUG`].
    #[track_caller]
    pub fn debug(&self, msg: &str, args: &[Arg]) {
        self.log_inner(default_context(), LEVEL_DEBUG, msg, args);
    }

    /// Logs at [`LEVEL_DEBUG`] with the given context.
    #[track_caller]
    pub fn debug_context(&self, ctx: &Context, msg: &str, args: &[Arg]) {
        self.log_inner(ctx, LEVEL_DEBUG, msg, args);
    }

    /// Logs at [`LEVEL_INFO`].
    #[track_caller]
    pub fn info(&self, msg: &str, args: &[Arg]) {
        self.log_inner(default_context(), LEVEL_INFO, msg, args);
    }

    /// Logs at [`LEVEL_INFO`] with the given context.
    #[track_caller]
    pub fn info_context(&self, ctx: &Context, msg: &str, args: &[Arg]) {
        self.log_inner(ctx, LEVEL_INFO, msg, args);
    }

    /// Logs at [`LEVEL_WARN`].
    #[track_caller]
    pub fn warn(&self, msg: &str, args: &[Arg]) {
        self.log_inner(default_context(), LEVEL_WARN, msg, args);
    }

    /// Logs at [`LEVEL_WARN`] with the given context.
    #[track_caller]
    pub fn warn_context(&self, ctx: &Context, msg: &str, args: &[Arg]) {
        self.log_inner(ctx, LEVEL_WARN, msg, args);
    }

    /// Logs at [`LEVEL_ERROR`].
    #[track_caller]
    pub fn error(&self, msg: &str, args: &[Arg]) {
        self.log_inner(default_context(), LEVEL_ERROR, msg, args);
    }

    /// Logs at [`LEVEL_ERROR`] with the given context.
    #[track_caller]
    pub fn error_context(&self, ctx: &Context, msg: &str, args: &[Arg]) {
        self.log_inner(ctx, LEVEL_ERROR, msg, args);
    }
}

impl std::fmt::Debug for Logger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Logger").finish_non_exhaustive()
    }
}

/// Calls [`Logger::with`] on the default logger.
pub fn with(args: &[Arg]) -> Logger {
    default().with(args)
}

/// Logs at [`LEVEL_DEBUG`] with the default logger.
#[track_caller]
pub fn debug(msg: &str, args: &[Arg]) {
    default().log_inner(default_context(), LEVEL_DEBUG, msg, args);
}

/// Logs at [`LEVEL_DEBUG`] with the default logger and a context.
#[track_caller]
pub fn debug_context(ctx: &Context, msg: &str, args: &[Arg]) {
    default().log_inner(ctx, LEVEL_DEBUG, msg, args);
}

/// Logs at [`LEVEL_INFO`] with the default logger.
#[track_caller]
pub fn info(msg: &str, args: &[Arg]) {
    default().log_inner(default_context(), LEVEL_INFO, msg, args);
}

/// Logs at [`LEVEL_INFO`] with the default logger and a context.
#[track_caller]
pub fn info_context(ctx: &Context, msg: &str, args: &[Arg]) {
    default().log_inner(ctx, LEVEL_INFO, msg, args);
}

/// Logs at [`LEVEL_WARN`] with the default logger.
#[track_caller]
pub fn warn(msg: &str, args: &[Arg]) {
    default().log_inner(default_context(), LEVEL_WARN, msg, args);
}

/// Logs at [`LEVEL_WARN`] with the default logger and a context.
#[track_caller]
pub fn warn_context(ctx: &Context, msg: &str, args: &[Arg]) {
    default().log_inner(ctx, LEVEL_WARN, msg, args);
}

/// Logs at [`LEVEL_ERROR`] with the default logger.
#[track_caller]
pub fn error(msg: &str, args: &[Arg]) {
    default().log_inner(default_context(), LEVEL_ERROR, msg, args);
}

/// Logs at [`LEVEL_ERROR`] with the default logger and a context.
#[track_caller]
pub fn error_context(ctx: &Context, msg: &str, args: &[Arg]) {
    default().log_inner(ctx, LEVEL_ERROR, msg, args);
}

/// Logs at the given level with the default logger.
#[track_caller]
pub fn log(ctx: &Context, level: Level, msg: &str, args: &[Arg]) {
    default().log_inner(ctx, level, msg, args);
}

/// Like [`log`] but accepts only `Attr`s.
#[track_caller]
pub fn log_attrs(ctx: &Context, level: Level, msg: &str, attrs: &[Attr]) {
    default().log_attrs(ctx, level, msg, attrs);
}

/// A [`Handler`] that invokes all the given handlers.
#[derive(Clone)]
pub struct MultiHandler {
    multi: Vec<Arc<dyn Handler>>,
}

impl MultiHandler {
    /// Returns a [`MultiHandler`] that calls each of the handlers in turn.
    pub fn new(handlers: Vec<Arc<dyn Handler>>) -> MultiHandler {
        MultiHandler { multi: handlers }
    }
}

impl Handler for MultiHandler {
    /// Reports whether any of the handlers is enabled for the level.
    fn enabled(&self, ctx: &Context, l: Level) -> bool {
        self.multi.iter().any(|h| h.enabled(ctx, l))
    }

    /// Handles the record with every handler enabled for its level, each with
    /// its own clone. Errors are joined, one per line.
    fn handle(&self, ctx: &Context, r: Record) -> io::Result<()> {
        let mut errs = Vec::new();
        for h in &self.multi {
            if h.enabled(ctx, r.level) {
                if let Err(e) = h.handle(ctx, r.clone()) {
                    errs.push(e.to_string());
                }
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(errs.join("\n")))
        }
    }

    fn with_attrs(&self, attrs: Vec<Attr>) -> Arc<dyn Handler> {
        Arc::new(MultiHandler {
            multi: self
                .multi
                .iter()
                .map(|h| h.with_attrs(attrs.clone()))
                .collect(),
        })
    }

    fn with_group(&self, name: &str) -> Arc<dyn Handler> {
        Arc::new(MultiHandler {
            multi: self.multi.iter().map(|h| h.with_group(name)).collect(),
        })
    }
}
