//! Go's `expvar`: public variables, such as operation counters in servers,
//! published by name and rendered as JSON.
//!
//! ```
//! use rust_stdlib::expvar;
//!
//! let hits = expvar::Int::published("example.hits");
//! hits.add(2);
//! assert_eq!(expvar::get("example.hits").map(|v| v.to_string()), Some("2".to_string()));
//! ```
//!
//! Go's package registers `cmdline` (and `memstats`) and an HTTP handler when
//! it is imported. Here `cmdline` is registered on first use, `memstats` is
//! not (see [`get`]), and [`handler`] is an ordinary
//! [`Handler`](crate::net::http::Handler) to register on a
//! [`ServeMux`](crate::net::http::ServeMux).

use crate::encoding::json::{self, Value};
use crate::strconv;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, PoisonError, RwLock};

/// An abstract exported variable. Its [`Display`](std::fmt::Display) output is
/// a valid JSON value.
pub trait Var: fmt::Display + Send + Sync {
    /// Returns `self` if it is an [`Int`]. This is the Rust form of Go's type
    /// assertion `v.(*Int)`, which [`Map::add`] uses.
    fn as_int(&self) -> Option<&Int> {
        None
    }

    /// Returns `self` if it is a [`Float`]; see [`Var::as_int`].
    fn as_float(&self) -> Option<&Float> {
        None
    }
}

/// A 64-bit integer variable.
#[derive(Debug, Default)]
pub struct Int {
    i: AtomicI64,
}

impl Int {
    /// Returns the current value.
    pub fn value(&self) -> i64 {
        self.i.load(Ordering::SeqCst)
    }

    /// Adds `delta` to the variable. The addition wraps on overflow.
    pub fn add(&self, delta: i64) {
        self.i.fetch_add(delta, Ordering::SeqCst);
    }

    /// Sets the variable to `value`.
    pub fn set(&self, value: i64) {
        self.i.store(value, Ordering::SeqCst);
    }
}

impl Int {
    /// Creates an `Int` and publishes it as `name`; it panics if `name` is
    /// already registered (Go `NewInt`).
    pub fn published(name: &str) -> Arc<Int> {
        let v = Arc::new(Int::default());
        publish(name, Arc::clone(&v) as Arc<dyn Var>);
        v
    }
}

/// The value as JSON.
impl fmt::Display for Int {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value())
    }
}

impl Var for Int {
    fn as_int(&self) -> Option<&Int> {
        Some(self)
    }
}

/// A 64-bit float variable.
#[derive(Debug, Default)]
pub struct Float {
    // The bits of the float64 value.
    f: AtomicU64,
}

impl Float {
    /// Returns the current value.
    pub fn value(&self) -> f64 {
        f64::from_bits(self.f.load(Ordering::SeqCst))
    }

    /// Adds `delta` to the variable.
    pub fn add(&self, delta: f64) {
        let mut cur = self.f.load(Ordering::SeqCst);
        loop {
            let next = (f64::from_bits(cur) + delta).to_bits();
            match self
                .f
                .compare_exchange(cur, next, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return,
                Err(actual) => cur = actual,
            }
        }
    }

    /// Sets the variable to `value`.
    pub fn set(&self, value: f64) {
        self.f.store(value.to_bits(), Ordering::SeqCst);
    }
}

impl Float {
    /// Creates a `Float` and publishes it as `name`; it panics if `name` is
    /// already registered (Go `NewFloat`).
    pub fn published(name: &str) -> Arc<Float> {
        let v = Arc::new(Float::default());
        publish(name, Arc::clone(&v) as Arc<dyn Var>);
        v
    }
}

/// The value as JSON: Go's strconv 'g' format with the fewest digits.
impl fmt::Display for Float {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&strconv::format_float(self.value(), b'g', -1, 64))
    }
}

impl Var for Float {
    fn as_float(&self) -> Option<&Float> {
        Some(self)
    }
}

/// A string-to-variable map. Keys are kept in sorted order.
#[derive(Default)]
pub struct Map {
    entries: RwLock<BTreeMap<std::string::String, Arc<dyn Var>>>,
}

/// A single entry of a [`Map`].
#[derive(Clone)]
pub struct KeyValue {
    /// The key of the entry.
    pub key: std::string::String,
    /// The variable stored under the key.
    pub value: Arc<dyn Var>,
}

impl Map {
    fn read(&self) -> std::sync::RwLockReadGuard<'_, BTreeMap<std::string::String, Arc<dyn Var>>> {
        self.entries.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(
        &self,
    ) -> std::sync::RwLockWriteGuard<'_, BTreeMap<std::string::String, Arc<dyn Var>>> {
        self.entries.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// Removes all keys from the map and returns it.
    pub fn init(&self) -> &Map {
        self.write().clear();
        self
    }

    /// Returns the variable stored under `key`, if any.
    pub fn get(&self, key: &str) -> Option<Arc<dyn Var>> {
        self.read().get(key).cloned()
    }

    /// Stores `av` under `key`, replacing any earlier value.
    pub fn set(&self, key: &str, av: Arc<dyn Var>) {
        self.write().insert(key.to_owned(), av);
    }

    /// Adds `delta` to the [`Int`] stored under `key`, creating one if the key
    /// is absent. A value of another type is left unchanged.
    pub fn add(&self, key: &str, delta: i64) {
        let mut entries = self.write();
        let entry = entries
            .entry(key.to_owned())
            .or_insert_with(|| Arc::new(Int::default()));
        if let Some(iv) = entry.as_int() {
            iv.add(delta);
        }
    }

    /// Adds `delta` to the [`Float`] stored under `key`, creating one if the
    /// key is absent. A value of another type is left unchanged.
    pub fn add_float(&self, key: &str, delta: f64) {
        let mut entries = self.write();
        let entry = entries
            .entry(key.to_owned())
            .or_insert_with(|| Arc::new(Float::default()));
        if let Some(fv) = entry.as_float() {
            fv.add(delta);
        }
    }

    /// Deletes `key` from the map, if present.
    pub fn delete(&self, key: &str) {
        self.write().remove(key);
    }

    /// Iterates over the entries in key order.
    ///
    /// The entries are read before the iteration starts, so the map may be
    /// changed while iterating. Go holds the map's lock during `Do` instead,
    /// where adding or deleting a key from the callback blocks forever.
    pub fn iter(&self) -> std::vec::IntoIter<KeyValue> {
        let snapshot: Vec<KeyValue> = self
            .read()
            .iter()
            .map(|(key, value)| KeyValue {
                key: key.clone(),
                value: Arc::clone(value),
            })
            .collect();
        snapshot.into_iter()
    }

    /// Renders the map as JSON. With `expand`, every entry is on its own line.
    fn json(&self, expand: bool) -> std::string::String {
        let (after_comma, newline) = if expand { (b'\n', "\n") } else { (b' ', "") };
        let mut b = std::string::String::from("{");
        b.push_str(newline);
        let mut first = true;
        for kv in self.iter() {
            if !first {
                b.push(',');
                b.push(char::from(after_comma));
            }
            first = false;
            append_json_quote(&mut b, &kv.key);
            b.push_str(": ");
            b.push_str(&kv.value.to_string());
        }
        b.push_str(newline);
        b.push('}');
        b.push_str(newline);
        b
    }
}

impl Map {
    /// Creates an empty `Map` and publishes it as `name`; it panics if `name`
    /// is already registered (Go `NewMap`).
    pub fn published(name: &str) -> Arc<Map> {
        let v = Arc::new(Map::default());
        v.init();
        publish(name, Arc::clone(&v) as Arc<dyn Var>);
        v
    }
}

/// The map as JSON on one line.
impl fmt::Display for Map {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.json(false))
    }
}

impl Var for Map {}

/// A string variable.
#[derive(Debug, Default)]
pub struct String {
    s: RwLock<std::string::String>,
}

impl String {
    /// Returns the current value, unquoted.
    pub fn value(&self) -> std::string::String {
        self.s
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Sets the variable to `value`.
    pub fn set(&self, value: &str) {
        *self.s.write().unwrap_or_else(PoisonError::into_inner) = value.to_owned();
    }
}

impl String {
    /// Creates a `String` and publishes it as `name`; it panics if `name` is
    /// already registered (Go `NewString`).
    pub fn published(name: &str) -> Arc<String> {
        let v = Arc::new(String::default());
        publish(name, Arc::clone(&v) as Arc<dyn Var>);
        v
    }
}

/// The value as a quoted JSON string.
impl fmt::Display for String {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut b = std::string::String::new();
        append_json_quote(&mut b, &self.value());
        f.write_str(&b)
    }
}

impl Var for String {}

/// A variable computed on each use. Its value is rendered with JSON, as Go's
/// `json.Marshal` renders the `any` it returns.
pub struct Func(Box<dyn Fn() -> Value + Send + Sync>);

impl Func {
    /// Wraps `f` as a variable.
    pub fn new(f: impl Fn() -> Value + Send + Sync + 'static) -> Func {
        Func(Box::new(f))
    }

    /// Calls the function.
    pub fn value(&self) -> Value {
        (self.0)()
    }
}

impl fmt::Debug for Func {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Func")
    }
}

/// The value as JSON with Go's `json.Marshal` (HTML escaping). A value that
/// cannot be encoded renders as the empty string, as
/// `v, _ := json.Marshal(f())` does.
impl fmt::Display for Func {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = json::marshal(&self.value())
            .ok()
            .and_then(|bytes| std::string::String::from_utf8(bytes).ok())
            .unwrap_or_default();
        f.write_str(&s)
    }
}

impl Var for Func {}

/// Appends `s` as a quoted JSON string, escaping `<`, `>`, `&` and the
/// line separators as Go's expvar does.
fn append_json_quote(b: &mut std::string::String, s: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    b.push('"');
    for r in s.chars() {
        let code = u32::from(r);
        if code < 0x20 || matches!(r, '\\' | '"' | '<' | '>' | '&' | '\u{2028}' | '\u{2029}') {
            match r {
                '\\' | '"' => {
                    b.push('\\');
                    b.push(r);
                }
                '\n' => b.push_str("\\n"),
                '\r' => b.push_str("\\r"),
                '\t' => b.push_str("\\t"),
                _ => {
                    b.push_str("\\u");
                    for shift in [12, 8, 4, 0] {
                        b.push(char::from(HEX[((code >> shift) & 0xf) as usize]));
                    }
                }
            }
        } else {
            b.push(r);
        }
    }
    b.push('"');
}

/// All published variables. It starts with `cmdline`.
static VARS: OnceLock<Map> = OnceLock::new();

fn vars() -> &'static Map {
    VARS.get_or_init(|| {
        let map = Map::default();
        let args = Func::new(|| Value::Array(std::env::args().map(Value::String).collect()));
        map.set("cmdline", Arc::new(args));
        map
    })
}

/// Publishes a named variable. It panics if `name` is already registered.
pub fn publish(name: &str, v: Arc<dyn Var>) {
    let mut entries = vars().write();
    if entries.contains_key(name) {
        // Go's log.Panicln message, including its newline.
        panic!("Reuse of exported var name: {name}\n");
    }
    entries.insert(name.to_owned(), v);
}

/// Returns the published variable `name`, or `None` if it is not registered.
pub fn get(name: &str) -> Option<Arc<dyn Var>> {
    vars().get(name)
}

/// Iterates over the published variables in name order.
pub fn iter() -> std::vec::IntoIter<KeyValue> {
    vars().iter()
}

/// Returns a handler that writes all published variables as JSON, with one
/// entry per line, like Go's `/debug/vars`. Register it on a
/// [`ServeMux`](crate::net::http::ServeMux) (Go's default mux registers it at
/// init).
#[cfg(feature = "net")]
pub fn handler() -> std::sync::Arc<dyn crate::net::http::Handler> {
    crate::net::http::handler_func(|w, _r| {
        w.header()
            .set("Content-Type", "application/json; charset=utf-8");
        let _ = w.write(vars().json(true).as_bytes());
    })
}
