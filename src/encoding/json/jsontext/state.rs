//! The token state machine shared by the `Decoder` and `Encoder`, the stacks
//! of object member names, and RFC 6901 JSON Pointers.
use std::collections::HashSet;
use std::fmt;

use super::errors::Error;
use super::wire;

pub(crate) const MAX_NESTING_DEPTH: usize = 10000;

/// `jsontext.Pointer`: an RFC 6901 JSON Pointer.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Pointer(String);

impl From<String> for Pointer {
    fn from(s: String) -> Pointer {
        Pointer(s)
    }
}

impl From<&str> for Pointer {
    fn from(s: &str) -> Pointer {
        Pointer(s.to_string())
    }
}

impl From<Pointer> for String {
    fn from(p: Pointer) -> String {
        p.0
    }
}

impl fmt::Display for Pointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Pointer {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Pointer {
    /// The pointer as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Reports whether the pointer is a valid RFC 6901 JSON Pointer: empty,
    /// or a `/`-prefixed sequence of tokens where every `~` begins `~0` or
    /// `~1`.
    pub fn is_valid(&self) -> bool {
        let b = self.0.as_bytes();
        for (i, &c) in b.iter().enumerate() {
            if c == b'~' && (i + 1 == b.len() || (b[i + 1] != b'0' && b[i + 1] != b'1')) {
                return false;
            }
        }
        b.is_empty() || b[0] == b'/'
    }

    /// Reports whether `pc` is equal to or nested within the pointer.
    pub fn contains(&self, pc: &Pointer) -> bool {
        match pc.0.strip_prefix(&self.0) {
            Some(suffix) => suffix.is_empty() || suffix.starts_with('/'),
            None => false,
        }
    }

    /// The pointer without its last token.
    pub fn parent(&self) -> Pointer {
        let i = self.0.rfind('/').unwrap_or(0);
        Pointer(self.0[..i].to_string())
    }

    /// The last token, unescaped.
    pub fn last_token(&self) -> String {
        let i = self.0.rfind('/').unwrap_or(0);
        let last = &self.0[i..];
        unescape_pointer_token(last.strip_prefix('/').unwrap_or(last))
    }

    /// The pointer with one more token, escaped.
    pub fn append_token(&self, tok: &str) -> Pointer {
        let mut b = self.0.clone().into_bytes();
        b.push(b'/');
        append_escape_pointer_name(&mut b, tok.as_bytes());
        Pointer(String::from_utf8_lossy(&b).into_owned())
    }

    /// The unescaped tokens of the pointer, in order.
    pub fn tokens(&self) -> impl Iterator<Item = String> + '_ {
        let mut p: &str = &self.0;
        std::iter::from_fn(move || {
            if p.is_empty() {
                return None;
            }
            p = p.strip_prefix('/').unwrap_or(p);
            let i = p.find('/').unwrap_or(p.len());
            let tok = unescape_pointer_token(&p[..i]);
            p = &p[i..];
            Some(tok)
        })
    }
}

fn unescape_pointer_token(token: &str) -> String {
    if token.contains('~') {
        token.replace("~1", "/").replace("~0", "~")
    } else {
        token.to_string()
    }
}

/// `appendEscapePointerName`: appends `name` with `~` and `/` escaped; each
/// invalid UTF-8 byte becomes U+FFFD, as ranging over a Go string does.
pub(crate) fn append_escape_pointer_name(b: &mut Vec<u8>, name: &[u8]) {
    let mut rest = name;
    while !rest.is_empty() {
        let (r, n) = crate::unicode::rune::decode_rune(rest);
        match r {
            0x7e => b.extend_from_slice(b"~0"),
            0x2f => b.extend_from_slice(b"~1"),
            _ => crate::unicode::rune::append_rune(b, r),
        }
        rest = &rest[n..];
    }
}

// ---------------------------------------------------------------- entries

const STATE_TYPE_MASK: u64 = 0x8000_0000_0000_0000;
const STATE_TYPE_OBJECT: u64 = 0x8000_0000_0000_0000;
const STATE_TYPE_ARRAY: u64 = 0;
const STATE_DISABLE_NAMESPACE: u64 = 0x4000_0000_0000_0000;
const STATE_INVALID_NAMESPACE: u64 = 0x2000_0000_0000_0000;
const STATE_COUNT_MASK: u64 = 0x1fff_ffff_ffff_ffff;
const STATE_COUNT_LSB_MASK: u64 = 1;
const STATE_COUNT_ODD: u64 = 1;
const STATE_COUNT_EVEN: u64 = 0;

/// `stateEntry`: the type, namespace status and element count of one level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StateEntry(pub(crate) u64);

impl StateEntry {
    pub(crate) fn length(self) -> i64 {
        (self.0 & STATE_COUNT_MASK) as i64
    }
    pub(crate) fn is_object(self) -> bool {
        self.0 & STATE_TYPE_MASK == STATE_TYPE_OBJECT
    }
    pub(crate) fn is_array(self) -> bool {
        self.0 & STATE_TYPE_MASK == STATE_TYPE_ARRAY
    }
    pub(crate) fn need_object_name(self) -> bool {
        self.0 & (STATE_TYPE_MASK | STATE_COUNT_LSB_MASK) == STATE_TYPE_OBJECT | STATE_COUNT_EVEN
    }
    pub(crate) fn need_implicit_colon(self) -> bool {
        self.need_object_value()
    }
    pub(crate) fn need_object_value(self) -> bool {
        self.0 & (STATE_TYPE_MASK | STATE_COUNT_LSB_MASK) == STATE_TYPE_OBJECT | STATE_COUNT_ODD
    }
    pub(crate) fn need_implicit_comma(self, next: u8) -> bool {
        !self.need_object_value() && self.length() > 0 && next != b'}' && next != b']'
    }
    pub(crate) fn increment(&mut self) {
        self.0 += 1;
    }
    pub(crate) fn decrement(&mut self) {
        self.0 -= 1;
    }
    pub(crate) fn disable_namespace(&mut self) {
        self.0 |= STATE_DISABLE_NAMESPACE;
    }
    pub(crate) fn is_active_namespace(self) -> bool {
        self.0 & STATE_DISABLE_NAMESPACE == 0
    }
    pub(crate) fn invalidate_namespace(&mut self) {
        self.0 |= STATE_INVALID_NAMESPACE;
    }
    pub(crate) fn is_valid_namespace(self) -> bool {
        self.0 & STATE_INVALID_NAMESPACE == 0
    }
}

/// `stateMachine`: the stack of open objects and arrays. The bottom of the
/// stack is a virtual top-level array.
#[derive(Clone, Debug)]
pub(crate) struct StateMachine {
    pub(crate) stack: Vec<StateEntry>,
    pub(crate) last: StateEntry,
}

impl Default for StateMachine {
    fn default() -> Self {
        StateMachine {
            stack: Vec::new(),
            last: StateEntry(STATE_TYPE_ARRAY),
        }
    }
}

impl StateMachine {
    pub(crate) fn reset(&mut self) {
        self.stack.clear();
        self.last = StateEntry(STATE_TYPE_ARRAY);
    }
    pub(crate) fn depth(&self) -> usize {
        self.stack.len() + 1
    }
    pub(crate) fn index(&self, i: usize) -> StateEntry {
        if i == self.stack.len() {
            self.last
        } else {
            self.stack[i]
        }
    }
    pub(crate) fn index_mut(&mut self, i: usize) -> &mut StateEntry {
        if i == self.stack.len() {
            &mut self.last
        } else {
            &mut self.stack[i]
        }
    }
    pub(crate) fn depth_length(&self) -> (usize, i64) {
        (self.depth(), self.last.length())
    }
    pub(crate) fn append_literal(&mut self) -> Result<(), Error> {
        if self.last.need_object_name() {
            Err(Error::NonStringName)
        } else if !self.last.is_valid_namespace() {
            Err(Error::InvalidNamespace)
        } else {
            self.last.increment();
            Ok(())
        }
    }
    pub(crate) fn append_string(&mut self) -> Result<(), Error> {
        if !self.last.is_valid_namespace() {
            Err(Error::InvalidNamespace)
        } else {
            self.last.increment();
            Ok(())
        }
    }
    pub(crate) fn append_number(&mut self) -> Result<(), Error> {
        self.append_literal()
    }
    pub(crate) fn push_object(&mut self) -> Result<(), Error> {
        if self.last.need_object_name() {
            Err(Error::NonStringName)
        } else if !self.last.is_valid_namespace() {
            Err(Error::InvalidNamespace)
        } else if self.stack.len() == MAX_NESTING_DEPTH {
            Err(Error::MaxDepth)
        } else {
            self.last.increment();
            self.stack.push(self.last);
            self.last = StateEntry(STATE_TYPE_OBJECT);
            Ok(())
        }
    }
    pub(crate) fn pop_object(&mut self) -> Result<(), Error> {
        if !self.last.is_object() {
            Err(Error::MismatchDelim)
        } else if self.last.need_object_value() {
            Err(Error::MissingValue)
        } else if !self.last.is_valid_namespace() {
            Err(Error::InvalidNamespace)
        } else {
            self.last = self.stack.pop().expect("object has a parent");
            Ok(())
        }
    }
    pub(crate) fn push_array(&mut self) -> Result<(), Error> {
        if self.last.need_object_name() {
            Err(Error::NonStringName)
        } else if !self.last.is_valid_namespace() {
            Err(Error::InvalidNamespace)
        } else if self.stack.len() == MAX_NESTING_DEPTH {
            Err(Error::MaxDepth)
        } else {
            self.last.increment();
            self.stack.push(self.last);
            self.last = StateEntry(STATE_TYPE_ARRAY);
            Ok(())
        }
    }
    pub(crate) fn pop_array(&mut self) -> Result<(), Error> {
        if !self.last.is_array() || self.stack.is_empty() {
            Err(Error::MismatchDelim)
        } else if !self.last.is_valid_namespace() {
            Err(Error::InvalidNamespace)
        } else {
            self.last = self.stack.pop().expect("array has a parent");
            Ok(())
        }
    }
    /// How many levels of indentation precede the next token.
    pub(crate) fn need_indent(&self, next: u8) -> usize {
        let will_end = next == b'}' || next == b']';
        if self.depth() == 1 || (self.last.length() == 0 && will_end) {
            0
        } else if self.last.length() == 0 || self.last.need_implicit_comma(next) {
            self.depth()
        } else if will_end {
            self.depth() - 1
        } else {
            0
        }
    }
    pub(crate) fn may_append_delim(&self, b: &mut Vec<u8>, next: u8) {
        if self.last.need_implicit_colon() {
            b.push(b':');
        } else if self.last.need_implicit_comma(next) && !self.stack.is_empty() {
            b.push(b',');
        }
    }
    /// The delimiter that must precede `next`: `:`, `,` or 0.
    pub(crate) fn need_delim(&self, next: u8) -> u8 {
        if self.last.need_implicit_colon() {
            b':'
        } else if self.last.need_implicit_comma(next) && !self.stack.is_empty() {
            b','
        } else {
            0
        }
    }
    pub(crate) fn invalidate_disabled_namespaces(&mut self) {
        for i in 0..self.depth() {
            let e = self.index_mut(i);
            if !e.is_active_namespace() {
                e.invalidate_namespace();
            }
        }
    }
}

// ------------------------------------------------------------ name stacks

const INVALID_OFFSET: isize = isize::MIN;

/// `objectNameStack`: the name of the most recent member of each open
/// object. A name is recorded as its offset in the coder's buffer (stored
/// bit-inverted) until the buffer is about to move, then unquoted.
#[derive(Clone, Debug, Default)]
pub(crate) struct ObjectNameStack {
    offsets: Vec<isize>,
    unquoted_names: Vec<u8>,
}

impl ObjectNameStack {
    pub(crate) fn reset(&mut self) {
        self.offsets.clear();
        self.unquoted_names.clear();
    }
    pub(crate) fn get_unquoted(&self, i: usize) -> &[u8] {
        self.ensure_copied_buffer();
        if i == 0 {
            &self.unquoted_names[..self.offsets[0] as usize]
        } else {
            &self.unquoted_names[self.offsets[i - 1] as usize..self.offsets[i] as usize]
        }
    }
    pub(crate) fn push(&mut self) {
        self.offsets.push(INVALID_OFFSET);
    }
    pub(crate) fn replace_last_quoted_offset(&mut self, i: usize) {
        let last = self.offsets.len() - 1;
        self.offsets[last] = !(i as isize);
    }
    pub(crate) fn replace_last_unquoted_name(&mut self, s: &[u8]) {
        self.ensure_copied_buffer();
        let start = if self.offsets.len() > 1 {
            self.offsets[self.offsets.len() - 2] as usize
        } else {
            0
        };
        self.unquoted_names.truncate(start);
        self.unquoted_names.extend_from_slice(s);
        let last = self.offsets.len() - 1;
        self.offsets[last] = self.unquoted_names.len() as isize;
    }
    pub(crate) fn clear_last(&mut self) {
        let last = self.offsets.len() - 1;
        self.offsets[last] = INVALID_OFFSET;
    }
    pub(crate) fn pop(&mut self) {
        self.offsets.pop();
    }
    /// Unquotes every name that is still only an offset into `b`. A name
    /// whose first quote the decoder overwrote (to invalidate a previous
    /// read) gets it back.
    pub(crate) fn copy_quoted_buffer(&mut self, b: &mut [u8]) {
        let mut i: isize = self.offsets.len() as isize - 1;
        while i >= 0 && self.offsets[i as usize] < 0 {
            i -= 1;
        }
        let mut i = (i + 1) as usize;
        while i < self.offsets.len() {
            if i == self.offsets.len() - 1 && self.offsets[i] == INVALID_OFFSET {
                self.offsets[i] = if i == 0 { 0 } else { self.offsets[i - 1] };
                break;
            }
            let at = (!self.offsets[i]) as usize;
            if b[at] == b'#' {
                b[at] = b'"';
            }
            let quoted = &b[at..];
            let start = if i > 0 {
                self.offsets[i - 1] as usize
            } else {
                0
            };
            let n = wire::consume_simple_string(quoted);
            self.unquoted_names.truncate(start);
            if n > 0 {
                self.unquoted_names.extend_from_slice(&quoted[1..n - 1]);
            } else {
                let _ = wire::append_unquote(&mut self.unquoted_names, quoted);
            }
            self.offsets[i] = self.unquoted_names.len() as isize;
            i += 1;
        }
    }
    fn ensure_copied_buffer(&self) {
        if let Some(&last) = self.offsets.last() {
            if last < 0 {
                panic!("BUG: copyQuotedBuffer not called beforehand");
            }
        }
    }
}

/// `objectNamespace`: the names seen so far in one object.
#[derive(Clone, Debug, Default)]
pub(crate) struct ObjectNamespace {
    names: Vec<Vec<u8>>,
    set: Option<HashSet<Vec<u8>>>,
    total_bytes: usize,
}

impl ObjectNamespace {
    /// Inserts a quoted name; reports whether it was new.
    pub(crate) fn insert_quoted(&mut self, name: &[u8], is_verbatim: bool) -> bool {
        if is_verbatim {
            self.insert(name[1..name.len() - 1].to_vec())
        } else {
            let mut out = Vec::new();
            let _ = wire::append_unquote(&mut out, name);
            self.insert(out)
        }
    }

    /// Inserts an unquoted name; reports whether it was new.
    pub(crate) fn insert_unquoted(&mut self, name: &[u8]) -> bool {
        self.insert(name.to_vec())
    }

    fn insert(&mut self, name: Vec<u8>) -> bool {
        if self.set.is_none() && (self.names.len() > 64 || self.total_bytes > 1024) {
            self.set = Some(self.names.iter().cloned().collect());
        }
        match &mut self.set {
            None => {
                if self.names.contains(&name) {
                    return false;
                }
            }
            Some(set) => {
                if !set.insert(name.clone()) {
                    return false;
                }
            }
        }
        self.total_bytes += name.len();
        self.names.push(name);
        true
    }

    pub(crate) fn remove_last(&mut self) {
        if let Some(last) = self.names.pop() {
            self.total_bytes -= last.len();
            if let Some(set) = &mut self.set {
                set.remove(&last);
            }
        }
    }
}

/// `state`: everything a coder tracks about the position in the JSON text.
#[derive(Clone, Debug, Default)]
pub(crate) struct State {
    pub(crate) tokens: StateMachine,
    pub(crate) names: ObjectNameStack,
    pub(crate) namespaces: Vec<ObjectNamespace>,
}

impl State {
    pub(crate) fn reset(&mut self) {
        self.tokens.reset();
        self.names.reset();
        self.namespaces.clear();
    }
    pub(crate) fn last_namespace(&mut self) -> &mut ObjectNamespace {
        self.namespaces
            .last_mut()
            .expect("namespace stack is empty")
    }

    /// `appendStackPointer`. `where_` is <0 to point at the previous element
    /// of the innermost array, 0 when ambiguous, >0 at the next one.
    pub(crate) fn append_stack_pointer(&self, b: &mut Vec<u8>, where_: i32) {
        let mut object_depth = 0usize;
        let depth = self.tokens.depth();
        for i in 1..depth {
            let e = self.tokens.index(i);
            let mut array_delta: i64 = -1;
            if i == depth - 1 {
                if (where_ < 0 && e.length() == 0)
                    || (where_ == 0 && !e.need_object_value())
                    || (where_ > 0 && e.need_object_name())
                {
                    return;
                } else if where_ > 0 && e.is_array() {
                    array_delta = 0;
                }
            }
            if e.is_object() {
                b.push(b'/');
                append_escape_pointer_name(b, self.names.get_unquoted(object_depth));
                object_depth += 1;
            } else if e.is_array() {
                b.push(b'/');
                b.extend_from_slice((e.length() + array_delta).to_string().as_bytes());
            }
        }
    }
}
