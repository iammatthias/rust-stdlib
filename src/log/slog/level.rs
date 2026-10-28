//! Severity levels, Go's `slog.Level`, `LevelVar` and `Leveler`.
use super::value::{Dynamic, TextValue};
use crate::strconv;
use std::{
    any::Any,
    fmt,
    sync::atomic::{AtomicI64, Ordering},
};

/// The importance or severity of a log event. The higher the level, the more
/// important or severe the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Level(pub i64);

/// Names the level of debug messages.
pub const LEVEL_DEBUG: Level = Level(-4);
/// Names the level of informational messages.
pub const LEVEL_INFO: Level = Level(0);
/// Names the level of warning messages.
pub const LEVEL_WARN: Level = Level(4);
/// Names the level of error messages.
pub const LEVEL_ERROR: Level = Level(8);

/// The error returned when parsing a level fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LevelParseError(pub String);

impl fmt::Display for LevelParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for LevelParseError {}

impl Level {
    /// Returns a name for the level. If the level has a name, then that name
    /// in uppercase is returned. Otherwise the name of the closest named level
    /// is used with a signed offset, e.g. `ERROR+2`.
    fn render(self) -> String {
        fn name(base: &str, val: i64) -> String {
            if val == 0 {
                base.to_owned()
            } else if val > 0 {
                format!("{base}+{val}")
            } else {
                format!("{base}{val}")
            }
        }
        if self < LEVEL_INFO {
            name("DEBUG", self.0.wrapping_sub(LEVEL_DEBUG.0))
        } else if self < LEVEL_WARN {
            name("INFO", self.0.wrapping_sub(LEVEL_INFO.0))
        } else if self < LEVEL_ERROR {
            name("WARN", self.0.wrapping_sub(LEVEL_WARN.0))
        } else {
            name("ERROR", self.0.wrapping_sub(LEVEL_ERROR.0))
        }
    }

    /// Returns the level's quoted name as a JSON string.
    pub fn marshal_json(self) -> Vec<u8> {
        strconv::quote(self.to_string()).into_bytes()
    }

    /// Parses a JSON string holding a level name such as `"INFO+2"`.
    pub fn unmarshal_json(&mut self, data: &[u8]) -> Result<(), LevelParseError> {
        let unquoted = strconv::unquote(data).map_err(|e| LevelParseError(e.to_string()))?;
        self.parse(&String::from_utf8_lossy(&unquoted))
    }

    /// Appends the level name to `b`.
    pub fn append_text(self, b: &mut Vec<u8>) {
        b.extend_from_slice(self.to_string().as_bytes());
    }

    /// Returns the level name as text.
    pub fn marshal_text(self) -> Vec<u8> {
        self.to_string().into_bytes()
    }

    /// Parses a level name such as `"debug"`, `"INFO+2"` or `"warn-1"`.
    /// Names are case-insensitive; an optional signed offset follows.
    pub fn unmarshal_text(&mut self, data: &[u8]) -> Result<(), LevelParseError> {
        self.parse(&String::from_utf8_lossy(data))
    }

    fn parse(&mut self, s: &str) -> Result<(), LevelParseError> {
        let wrap =
            |e: &str| LevelParseError(format!("slog: level string {}: {e}", strconv::quote(s)));
        let mut name = s;
        let mut offset = 0isize;
        if let Some(i) = s.find(['+', '-']) {
            name = &s[..i];
            offset = strconv::atoi(&s[i..]).map_err(|e| wrap(&e.to_string()))?;
        }
        // strings.ToUpper: only the four ASCII names can match.
        *self = match name.to_uppercase().as_str() {
            "DEBUG" => LEVEL_DEBUG,
            "INFO" => LEVEL_INFO,
            "WARN" => LEVEL_WARN,
            "ERROR" => LEVEL_ERROR,
            _ => return Err(wrap("unknown name")),
        };
        self.0 = self.0.wrapping_add(offset as i64);
        Ok(())
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

impl Leveler for Level {
    /// Returns the receiver.
    fn level(&self) -> Level {
        *self
    }
}

impl Dynamic for Level {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn text(&self) -> Result<TextValue, String> {
        Ok(TextValue::Plain(self.to_string()))
    }
    fn json(&self) -> Result<String, String> {
        Ok(String::from_utf8_lossy(&self.marshal_json()).into_owned())
    }
    fn dyn_eq(&self, other: &dyn Dynamic) -> bool {
        other.as_any().downcast_ref::<Self>() == Some(self)
    }
}

/// Provides a [`Level`] value. As [`Level`] itself implements `Leveler`,
/// a `Level` can be used wherever a `Leveler` is required, such as in
/// `HandlerOptions`. A [`LevelVar`] changes the level dynamically.
pub trait Leveler: Send + Sync {
    /// Returns the level.
    fn level(&self) -> Level;
}

/// A `LevelVar` is a [`Level`] variable, to allow a [`Handler`](super::Handler)
/// level to change dynamically. It implements [`Leveler`] and is safe for
/// concurrent use. The zero value is `LEVEL_INFO`.
#[derive(Debug, Default)]
pub struct LevelVar {
    val: AtomicI64,
}

impl LevelVar {
    /// Returns a zero-valued (`LEVEL_INFO`) variable.
    pub const fn new() -> Self {
        Self {
            val: AtomicI64::new(0),
        }
    }

    /// Sets the variable's level to `l`.
    pub fn set(&self, l: Level) {
        self.val.store(l.0, Ordering::SeqCst);
    }

    /// Returns the variable's level.
    pub fn level(&self) -> Level {
        Level(self.val.load(Ordering::SeqCst))
    }

    /// Returns `LevelVar(<level>)`.
    fn render(&self) -> String {
        format!("LevelVar({})", self.level())
    }

    /// Appends the current level name to `b`.
    pub fn append_text(&self, b: &mut Vec<u8>) {
        self.level().append_text(b);
    }

    /// Returns the current level name as text.
    pub fn marshal_text(&self) -> Vec<u8> {
        self.level().marshal_text()
    }

    /// Parses a level name and stores it in the variable.
    pub fn unmarshal_text(&self, data: &[u8]) -> Result<(), LevelParseError> {
        let mut l = Level::default();
        l.unmarshal_text(data)?;
        self.set(l);
        Ok(())
    }
}

impl fmt::Display for LevelVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

impl Leveler for LevelVar {
    fn level(&self) -> Level {
        LevelVar::level(self)
    }
}
