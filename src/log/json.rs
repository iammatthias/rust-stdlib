//! Mutex-serialized JSON-line logging to any `Write + Send` sink.
//! User fields live under `fields` so they cannot overwrite record metadata.
use crate::encoding::json::{self, Value};
use std::{
    collections::BTreeMap,
    io::{self, Write},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}
impl Level {
    fn name(self) -> &'static str {
        match self {
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }
}
pub struct Logger<W: Write + Send> {
    sink: Arc<Mutex<W>>,
    minimum: Level,
}
impl<W: Write + Send> Clone for Logger<W> {
    fn clone(&self) -> Self {
        Self {
            sink: self.sink.clone(),
            minimum: self.minimum,
        }
    }
}
impl<W: Write + Send> Logger<W> {
    pub fn new(sink: W, minimum: Level) -> Self {
        Self {
            sink: Arc::new(Mutex::new(sink)),
            minimum,
        }
    }
    /// Serialization finishes before the sink is locked; write failures propagate.
    pub fn write(
        &self,
        level: Level,
        message: &str,
        fields: BTreeMap<String, Value>,
    ) -> io::Result<()> {
        if level < self.minimum {
            return Ok(());
        }
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?;
        let record = Value::object([
            ("fields", Value::Object(fields.into())),
            ("level", Value::from(level.name())),
            ("message", Value::from(message)),
            ("timestamp_unix_ms", Value::from(elapsed.as_millis())),
        ]);
        let mut bytes = json::marshal(&record).map_err(io::Error::other)?;
        bytes.push(b'\n');
        let mut sink = self
            .sink
            .lock()
            .map_err(|_| io::Error::other("logger lock poisoned"))?;
        sink.write_all(&bytes)?;
        sink.flush()
    }
}
