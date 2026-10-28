//! `jsontext.Decoder`: a streaming JSON tokenizer and value reader.
use std::io::{self, Read};
use std::sync::Arc;

use super::errors::{
    finish_syntactic_error, wrap_with_array_index, wrap_with_object_name, Error, IoError, WrapInfo,
};
use super::flags;
use super::options::Options;
use super::state::{ObjectNamespace, Pointer, State, MAX_NESTING_DEPTH};
use super::token::{Kind, Token, KIND_BEGIN_ARRAY, KIND_BEGIN_OBJECT, KIND_INVALID, KIND_STRING};
use super::value::Value;
use super::wire::{self, NumberState, ValueFlags};

const INVALIDATE_BUFFER_BYTE: u8 = b'#';

/// Where a [`Decoder`] gets more input.
enum Source<'r> {
    /// All input is already in the buffer.
    None,
    /// An `io.Reader`.
    Reader(Box<dyn Read + 'r>),
    /// A `bytes.Buffer`: everything is handed over at the first fetch.
    Buffer(Vec<u8>),
}

/// The state of a [`Decoder`] (Go's `decoderState`); the v2 package drives
/// it directly.
pub(crate) struct DecoderState<'r> {
    pub(crate) state: State,
    /// Positive if a valid offset into `buf` for the start of the next token;
    /// -1 if `peek_err` holds an error to report.
    peek_pos: isize,
    peek_err: Option<Error>,
    /// Go's backing array of `buf`: its length is `cap(buf)`, and `blen`
    /// is `len(buf)`. The tail past `blen` keeps stale bytes, as in Go.
    arr: Vec<u8>,
    blen: usize,
    /// Identifies `arr`; changes when a fetch grows into a new array.
    arr_id: u64,
    /// Arrays replaced by a fetch while names captured from them were
    /// still in use (Go's slices keep seeing the old array).
    retired: Vec<(u64, Vec<u8>)>,
    capture_depth: usize,
    prev_start: usize,
    prev_end: usize,
    base_offset: i64,
    rd: Source<'r>,
    pub(crate) opts: Options,
}

/// `jsontext.Decoder`: reads a stream of JSON tokens and values.
pub struct Decoder<'r> {
    pub(crate) s: DecoderState<'r>,
}

impl<'r> Decoder<'r> {
    /// Go's `NewDecoder`: a decoder reading from `r`.
    pub fn new<R: Read + 'r>(r: R, opts: &[Options]) -> Decoder<'r> {
        let mut d = Decoder {
            s: DecoderState::empty(),
        };
        d.reset(r, opts);
        d
    }

    /// A decoder over a `bytes.Buffer`'s unread bytes (Go's
    /// `NewDecoder(bytes.NewBuffer(b))`): the whole input is taken in at the
    /// first read, so [`unread_buffer`](Self::unread_buffer) is exact.
    pub fn from_buffer(b: Vec<u8>, opts: &[Options]) -> Decoder<'r> {
        let mut d = Decoder {
            s: DecoderState::empty(),
        };
        d.s.reset(Vec::new(), Source::Buffer(b), opts);
        d
    }

    /// A decoder over bytes that are all present (Go's `getBufferedDecoder`).
    pub(crate) fn buffered(b: &[u8], opts: &[Options]) -> Decoder<'static> {
        Decoder {
            s: DecoderState::buffered(b, opts),
        }
    }

    /// Go's `Decoder.Reset`: discards state and reads from `r` with `opts`.
    pub fn reset<R: Read + 'r>(&mut self, r: R, opts: &[Options]) {
        self.check_reset();
        let was_buffer = matches!(self.s.rd, Source::Buffer(_));
        let arr = if was_buffer {
            Vec::new()
        } else {
            std::mem::take(&mut self.s.arr)
        };
        self.s.reset(arr, Source::Reader(Box::new(r)), opts);
    }

    /// Like [`reset`](Self::reset) for a `bytes.Buffer` source.
    pub fn reset_buffer(&mut self, b: Vec<u8>, opts: &[Options]) {
        self.check_reset();
        self.s.reset(Vec::new(), Source::Buffer(b), opts);
    }

    fn check_reset(&self) {
        if self.s.opts.flags.get(flags::WITHIN_ARSHAL_CALL) {
            panic!("jsontext: cannot reset Decoder passed to json.UnmarshalerFrom");
        }
    }

    /// Go's `Decoder.Options`: the options in effect.
    pub fn options(&self) -> Options {
        self.s.opts.clone()
    }

    /// Go's `Decoder.PeekKind`: the kind of the next token without consuming
    /// it, or [`KIND_INVALID`] on error (reported by the next read).
    pub fn peek_kind(&mut self) -> Kind {
        self.s.peek_kind()
    }

    /// Go's `Decoder.SkipValue`: skips the next value.
    pub fn skip_value(&mut self) -> Result<(), Error> {
        self.s.skip_value()
    }

    /// Go's `Decoder.ReadToken`: reads the next token.
    pub fn read_token(&mut self) -> Result<Token, Error> {
        self.s.read_token()
    }

    /// Go's `Decoder.ReadValue`: reads the next complete value.
    pub fn read_value(&mut self) -> Result<Value, Error> {
        let mut flags = ValueFlags::default();
        self.s.read_value(&mut flags).map(Value)
    }

    /// Go's `Decoder.InputOffset`: the offset after the last token or value.
    pub fn input_offset(&self) -> i64 {
        self.s.previous_offset_end()
    }

    /// Go's `Decoder.UnreadBuffer`: the data that has been read from the
    /// input but not yet consumed.
    pub fn unread_buffer(&self) -> &[u8] {
        self.s.unread_buffer()
    }

    /// Go's `Decoder.StackDepth`: the number of open objects and arrays.
    pub fn stack_depth(&self) -> usize {
        self.s.state.tokens.depth() - 1
    }

    /// Go's `Decoder.StackIndex`: the kind (`{` or `[`, or invalid for the
    /// top level) and length of the stack entry `i`. Panics if `i` is
    /// beyond [`stack_depth`](Self::stack_depth).
    pub fn stack_index(&self, i: usize) -> (Kind, i64) {
        let s = self.s.state.tokens.index(i);
        if i > 0 && s.is_object() {
            (KIND_BEGIN_OBJECT, s.length())
        } else if i > 0 && s.is_array() {
            (KIND_BEGIN_ARRAY, s.length())
        } else {
            (KIND_INVALID, s.length())
        }
    }

    /// Go's `Decoder.StackPointer`: the JSON Pointer of the most recently
    /// read value.
    pub fn stack_pointer(&mut self) -> Pointer {
        let mut b = Vec::new();
        self.s.append_stack_pointer(&mut b, -1);
        Pointer::from(String::from_utf8_lossy(&b).into_owned())
    }
}

impl<'r> DecoderState<'r> {
    fn empty() -> DecoderState<'r> {
        DecoderState {
            state: State::default(),
            peek_pos: 0,
            peek_err: None,
            arr: Vec::new(),
            blen: 0,
            arr_id: 0,
            retired: Vec::new(),
            capture_depth: 0,
            prev_start: 0,
            prev_end: 0,
            base_offset: 0,
            rd: Source::None,
            opts: Options::default(),
        }
    }

    /// A decoder over bytes that are all present (Go's `getBufferedDecoder`).
    pub(crate) fn buffered(b: &[u8], opts: &[Options]) -> DecoderState<'static> {
        let mut d = DecoderState::empty();
        d.reset(b.to_vec(), Source::None, opts);
        d.blen = b.len();
        d
    }

    /// `reset`: `arr` is the backing array to reuse (its length is its
    /// capacity); a reader or buffer source starts with an empty `buf`.
    fn reset(&mut self, arr: Vec<u8>, rd: Source<'r>, opts: &[Options]) {
        self.state.reset();
        self.peek_pos = 0;
        self.peek_err = None;
        self.blen = 0;
        self.arr = arr;
        self.arr_id += 1;
        self.retired.clear();
        self.capture_depth = 0;
        self.prev_start = 0;
        self.prev_end = 0;
        self.base_offset = 0;
        self.rd = rd;
        let mut o = Options::default();
        o.join_all(opts);
        self.opts = o;
    }

    /// Go's `d.buf`: the bytes read so far.
    pub(crate) fn buf(&self) -> &[u8] {
        &self.arr[..self.blen]
    }

    pub(crate) fn buf_mut(&mut self) -> &mut [u8] {
        &mut self.arr[..self.blen]
    }

    pub(crate) fn offset_at(&self, pos: usize) -> i64 {
        self.base_offset + pos as i64
    }
    pub(crate) fn previous_offset_end(&self) -> i64 {
        self.base_offset + self.prev_end as i64
    }
    pub(crate) fn unread_buffer(&self) -> &[u8] {
        &self.buf()[self.prev_end..]
    }
    fn need_more(&self, pos: usize) -> bool {
        pos == self.blen
    }

    /// `fetch`: reads more input, discarding what has been consumed.
    fn fetch(&mut self) -> Result<(), Error> {
        let reader = match &mut self.rd {
            Source::None => return Err(Error::UnexpectedEof),
            Source::Buffer(rest) => {
                self.state
                    .names
                    .copy_quoted_buffer(&mut self.arr[..self.blen]);
                if rest.is_empty() {
                    return Err(Error::UnexpectedEof);
                }
                if self.blen == 0 {
                    self.arr = std::mem::take(rest);
                    self.blen = self.arr.len();
                    self.arr_id += 1;
                    return Ok(());
                }
                return Err(Error::Io(IoError {
                    action: "read",
                    err: Arc::new(io::Error::other(
                        "invalid bytes.Buffer.Write call after calling bytes.Buffer.Next",
                    )),
                }));
            }
            Source::Reader(r) => r,
        };
        self.state
            .names
            .copy_quoted_buffer(&mut self.arr[..self.blen]);
        if self.arr.is_empty() {
            self.arr = vec![0; 64];
            self.arr_id += 1;
            self.blen = 0;
        }
        let cap = self.arr.len();
        const MAX_BUFFER_SIZE: usize = 4 << 10;
        const GROWTH_SIZE_FACTOR: usize = 2;
        const GROWTH_RATE_FACTOR: i64 = 2;
        let mut grow = cap <= MAX_BUFFER_SIZE / GROWTH_SIZE_FACTOR;
        grow =
            grow && (cap as i64) < (self.base_offset + self.prev_end as i64) / GROWTH_RATE_FACTOR;
        grow = grow || (self.prev_start == 0 && self.blen >= 3 * cap / 4);
        let kept = self.blen - self.prev_start;
        if grow {
            let mut bigger = vec![0u8; cap * GROWTH_SIZE_FACTOR];
            bigger[..kept].copy_from_slice(&self.arr[self.prev_start..self.blen]);
            let old = std::mem::replace(&mut self.arr, bigger);
            if self.capture_depth > 0 {
                self.retired.push((self.arr_id, old));
            }
            self.arr_id += 1;
        } else {
            self.arr.copy_within(self.prev_start..self.blen, 0);
        }
        self.blen = kept;
        self.base_offset += self.prev_start as i64;
        self.prev_end -= self.prev_start;
        self.prev_start = 0;
        loop {
            let (blen, cap) = (self.blen, self.arr.len());
            match reader.read(&mut self.arr[blen..cap]) {
                Ok(n) if n > 0 => {
                    self.blen += n;
                    return Ok(());
                }
                Ok(_) => return Err(Error::UnexpectedEof),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    if crate::io::is_eof(&e) {
                        return Err(Error::UnexpectedEof);
                    }
                    return Err(Error::Io(IoError {
                        action: "read",
                        err: Arc::new(e),
                    }));
                }
            }
        }
    }

    fn invalidate_previous_read(&mut self) {
        let is_buffer_or_none = !matches!(self.rd, Source::Reader(_));
        if !is_buffer_or_none && self.prev_start < self.prev_end && self.prev_start < self.blen {
            self.arr[self.prev_start] = INVALIDATE_BUFFER_BYTE;
            self.prev_start = self.prev_end;
        }
    }

    /// `PreviousTokenOrValue`: the text of the last token or value, or empty
    /// when it is unknown.
    pub(crate) fn previous_token_or_value(&self) -> &[u8] {
        let b = &self.buf()[self.prev_start..self.prev_end];
        if self.peek_pos > 0 || (!b.is_empty() && b[0] == INVALIDATE_BUFFER_BYTE) {
            return &[];
        }
        if b.is_empty() {
            let all = &self.buf()[..self.prev_end];
            for tok in ["null", "false", "true", "{", "}", "[", "]"] {
                if all.len() >= tok.len() && &all[all.len() - tok.len()..] == tok.as_bytes() {
                    return &all[all.len() - tok.len()..];
                }
            }
        }
        b
    }

    fn consume_whitespace(&mut self, mut pos: usize) -> (usize, Option<Error>) {
        loop {
            pos += wire::consume_whitespace(&self.buf()[pos..]);
            if self.need_more(pos) {
                let abs = self.base_offset + pos as i64;
                let r = self.fetch();
                pos = (abs - self.base_offset) as usize;
                if let Err(e) = r {
                    return (pos, Some(e));
                }
                continue;
            }
            return (pos, None);
        }
    }

    // ------------------------------------------------------------- errors

    /// `wrapSyntacticError`.
    pub(crate) fn wrap_syntactic_error(&mut self, err: Error, pos: usize, where_: i32) -> Error {
        if matches!(err, Error::Eof | Error::Io(_)) {
            return err;
        }
        let offset = self.offset_at(pos);
        let mut ptr = Vec::new();
        self.append_stack_pointer(&mut ptr, where_);
        let is_mismatch = match &err {
            Error::MismatchDelim => true,
            Error::PointerSuffix(s) => matches!(s.error, Error::MismatchDelim),
            _ => false,
        };
        let mismatch = is_mismatch.then(|| {
            let mut place = "at start of value";
            let mut parent = false;
            if !self.state.tokens.stack.is_empty() && self.state.tokens.last.length() > 0 {
                if self.state.tokens.last.is_array() {
                    place = "after array element (expecting ',' or ']')";
                    parent = true;
                } else if self.state.tokens.last.is_object() {
                    place = "after object value (expecting ',' or '}')";
                    parent = true;
                }
            }
            (
                wire::invalid_character_error(&self.buf()[pos.min(self.blen)..], place),
                parent,
            )
        });
        finish_syntactic_error(
            err,
            WrapInfo {
                legacy_errors: self
                    .opts
                    .flags
                    .get(flags::REPORT_ERRORS_WITH_LEGACY_SEMANTICS),
                offset,
                pointer: ptr,
                mismatch,
            },
        )
    }

    pub(crate) fn append_stack_pointer(&mut self, b: &mut Vec<u8>, where_: i32) {
        self.state
            .names
            .copy_quoted_buffer(&mut self.arr[..self.blen]);
        self.state.append_stack_pointer(b, where_);
    }

    // --------------------------------------------------------- peek / read

    pub(crate) fn peek_kind(&mut self) -> Kind {
        if self.peek_pos > 0 {
            return Kind(self.buf()[self.peek_pos as usize]).normalize();
        }
        self.invalidate_previous_read();
        let mut pos = self.prev_end;
        pos += wire::consume_whitespace(&self.buf()[pos..]);
        if self.need_more(pos) {
            let (p, err) = self.consume_whitespace(pos);
            pos = p;
            if let Some(mut err) = err {
                if matches!(err, Error::UnexpectedEof) && self.state.tokens.depth() == 1 {
                    err = Error::Eof;
                }
                self.peek_pos = -1;
                self.peek_err = Some(self.wrap_syntactic_error(err, pos, 0));
                return KIND_INVALID;
            }
        }
        let mut delim = 0u8;
        let c = self.buf()[pos];
        if c == b':' || c == b',' {
            delim = c;
            pos += 1;
            pos += wire::consume_whitespace(&self.buf()[pos..]);
            if self.need_more(pos) {
                let (p, err) = self.consume_whitespace(pos);
                pos = p;
                if let Some(err) = err {
                    let err = self.wrap_syntactic_error(err, pos, 0);
                    self.peek_pos = -1;
                    self.peek_err = Some(self.check_delim_before_io_error(delim, err));
                    return KIND_INVALID;
                }
            }
        }
        let next = Kind(self.buf()[pos]).normalize();
        if self.state.tokens.need_delim(next.0) != delim {
            self.peek_pos = -1;
            self.peek_err = Some(self.check_delim(delim, next));
            return KIND_INVALID;
        }
        self.peek_pos = pos as isize;
        self.peek_err = None;
        next
    }

    fn check_delim_before_io_error(&mut self, delim: u8, err: Error) -> Error {
        let next = Kind(b'"');
        if self.state.tokens.need_delim(next.0) != delim {
            return self.check_delim(delim, next);
        }
        err
    }

    /// `CountNextDelimWhitespace`: the number of delimiter and whitespace
    /// bytes in the input before the next token.
    pub(crate) fn count_next_delim_whitespace(&mut self) -> usize {
        self.peek_kind();
        let u = self.unread_buffer();
        let rest = u
            .iter()
            .skip_while(|c| matches!(c, b',' | b':' | b' ' | b'\n' | b'\r' | b'\t'))
            .count();
        u.len() - rest
    }

    fn check_delim(&mut self, delim: u8, next: Kind) -> Error {
        let mut place = "at start of value";
        let need = self.state.tokens.need_delim(next.0);
        if need == delim {
            // Unreachable for callers, which only ask on a mismatch.
        } else if need == b':' {
            place = "after object name (expecting ':')";
        } else if need == b',' {
            place = if self.state.tokens.last.is_object() {
                "after object value (expecting ',' or '}')"
            } else {
                "after array element (expecting ',' or ']')"
            };
        }
        let mut pos = self.prev_end;
        pos += wire::consume_whitespace(&self.buf()[pos..]);
        let err = wire::invalid_character_error(&self.buf()[pos..], place);
        self.wrap_syntactic_error(err, pos, 0)
    }

    pub(crate) fn skip_value(&mut self) -> Result<(), Error> {
        match self.peek_kind().0 {
            b'{' | b'[' => {
                let depth = self.state.tokens.depth();
                loop {
                    self.read_token()?;
                    if depth >= self.state.tokens.depth() {
                        return Ok(());
                    }
                }
            }
            _ => {
                let mut flags = ValueFlags::default();
                self.read_value(&mut flags).map(|_| ())
            }
        }
    }

    /// The prologue shared by `ReadToken` and `ReadValue`: finds the start of
    /// the next token, returning its position and kind.
    fn begin_read(&mut self) -> Result<(usize, Kind), Error> {
        let pos = self.peek_pos;
        if pos != 0 {
            if let Some(err) = self.peek_err.take() {
                self.peek_pos = 0;
                return Err(err);
            }
            let pos = pos as usize;
            let next = Kind(self.buf()[pos]).normalize();
            self.peek_pos = 0;
            return Ok((pos, next));
        }
        self.invalidate_previous_read();
        let mut pos = self.prev_end;
        pos += wire::consume_whitespace(&self.buf()[pos..]);
        if self.need_more(pos) {
            let (p, err) = self.consume_whitespace(pos);
            pos = p;
            if let Some(mut err) = err {
                if matches!(err, Error::UnexpectedEof) && self.state.tokens.depth() == 1 {
                    err = Error::Eof;
                }
                return Err(self.wrap_syntactic_error(err, pos, 0));
            }
        }
        let mut delim = 0u8;
        let c = self.buf()[pos];
        if c == b':' || c == b',' {
            delim = c;
            pos += 1;
            pos += wire::consume_whitespace(&self.buf()[pos..]);
            if self.need_more(pos) {
                let (p, err) = self.consume_whitespace(pos);
                pos = p;
                if let Some(err) = err {
                    let err = self.wrap_syntactic_error(err, pos, 0);
                    return Err(self.check_delim_before_io_error(delim, err));
                }
            }
        }
        let next = Kind(self.buf()[pos]).normalize();
        if self.state.tokens.need_delim(next.0) != delim {
            return Err(self.check_delim(delim, next));
        }
        Ok((pos, next))
    }

    pub(crate) fn read_token(&mut self) -> Result<Token, Error> {
        let (mut pos, next) = self.begin_read()?;
        let allow_dup = self.opts.flags.get(flags::ALLOW_DUPLICATE_NAMES);
        match next.0 {
            b'n' | b'f' | b't' => {
                let lit = match next.0 {
                    b'n' => "null",
                    b'f' => "false",
                    _ => "true",
                };
                let consumed = match next.0 {
                    b'n' => wire::consume_null(&self.buf()[pos..]),
                    b'f' => wire::consume_false(&self.buf()[pos..]),
                    _ => wire::consume_true(&self.buf()[pos..]),
                };
                if consumed == 0 {
                    let (p, err) = self.consume_literal(pos, lit);
                    pos = p;
                    if let Some(err) = err {
                        return Err(self.wrap_syntactic_error(err, pos, 1));
                    }
                } else {
                    pos += lit.len();
                }
                if let Err(err) = self.state.tokens.append_literal() {
                    return Err(self.wrap_syntactic_error(err, pos - lit.len(), 1));
                }
                self.prev_start = pos;
                self.prev_end = pos;
                Ok(Token::from_raw(lit.as_bytes()))
            }
            b'"' => {
                let mut vflags = ValueFlags::default();
                let mut n = wire::consume_simple_string(&self.buf()[pos..]);
                if n == 0 {
                    let old_abs = self.base_offset + pos as i64;
                    let (p, err) = self.consume_string(&mut vflags, pos);
                    pos = p;
                    let new_abs = self.base_offset + pos as i64;
                    n = (new_abs - old_abs) as usize;
                    if let Some(err) = err {
                        return Err(self.wrap_syntactic_error(err, pos, 1));
                    }
                } else {
                    pos += n;
                }
                if self.state.tokens.last.need_object_name() {
                    if !allow_dup {
                        if !self.state.tokens.last.is_valid_namespace() {
                            return Err(self.wrap_syntactic_error(
                                Error::InvalidNamespace,
                                pos - n,
                                1,
                            ));
                        }
                        if self.state.tokens.last.is_active_namespace() {
                            let verbatim = vflags.is_verbatim();
                            let name = &self.arr[pos - n..pos];
                            let ns = self.state.namespaces.last_mut().expect("namespace");
                            if !ns.insert_quoted(name, verbatim) {
                                let err = wrap_with_object_name(Error::DuplicateName, name);
                                return Err(self.wrap_syntactic_error(err, pos - n, 1));
                            }
                        }
                    }
                    self.state.names.replace_last_quoted_offset(pos - n);
                }
                if let Err(err) = self.state.tokens.append_string() {
                    return Err(self.wrap_syntactic_error(err, pos - n, 1));
                }
                self.prev_start = pos - n;
                self.prev_end = pos;
                Ok(Token::from_raw(&self.buf()[pos - n..pos]))
            }
            b'0' => {
                let mut n = wire::consume_simple_number(&self.buf()[pos..]);
                if n == 0 || self.need_more(pos + n) {
                    let old_abs = self.base_offset + pos as i64;
                    let (p, err) = self.consume_number(pos);
                    pos = p;
                    let new_abs = self.base_offset + pos as i64;
                    n = (new_abs - old_abs) as usize;
                    if let Some(err) = err {
                        return Err(self.wrap_syntactic_error(err, pos, 1));
                    }
                } else {
                    pos += n;
                }
                if let Err(err) = self.state.tokens.append_number() {
                    return Err(self.wrap_syntactic_error(err, pos - n, 1));
                }
                self.prev_start = pos - n;
                self.prev_end = pos;
                Ok(Token::from_raw(&self.buf()[pos - n..pos]))
            }
            b'{' => {
                if let Err(err) = self.state.tokens.push_object() {
                    return Err(self.wrap_syntactic_error(err, pos, 1));
                }
                self.state.names.push();
                if !allow_dup {
                    self.state.namespaces.push(ObjectNamespace::default());
                }
                self.opts.flags.clear(flags::TAG_FLAGS);
                pos += 1;
                self.prev_start = pos;
                self.prev_end = pos;
                Ok(Token::from_raw(b"{"))
            }
            b'}' => {
                if let Err(err) = self.state.tokens.pop_object() {
                    return Err(self.wrap_syntactic_error(err, pos, 1));
                }
                self.state.names.pop();
                if !allow_dup {
                    self.state.namespaces.pop();
                }
                pos += 1;
                self.prev_start = pos;
                self.prev_end = pos;
                Ok(Token::from_raw(b"}"))
            }
            b'[' => {
                if let Err(err) = self.state.tokens.push_array() {
                    return Err(self.wrap_syntactic_error(err, pos, 1));
                }
                self.opts.flags.clear(flags::TAG_FLAGS);
                pos += 1;
                self.prev_start = pos;
                self.prev_end = pos;
                Ok(Token::from_raw(b"["))
            }
            b']' => {
                if let Err(err) = self.state.tokens.pop_array() {
                    return Err(self.wrap_syntactic_error(err, pos, 1));
                }
                pos += 1;
                self.prev_start = pos;
                self.prev_end = pos;
                Ok(Token::from_raw(b"]"))
            }
            _ => {
                let err = wire::invalid_character_error(&self.buf()[pos..], "at start of value");
                Err(self.wrap_syntactic_error(err, pos, 1))
            }
        }
    }

    pub(crate) fn read_value(&mut self, vflags: &mut ValueFlags) -> Result<Vec<u8>, Error> {
        let (pos, next) = self.begin_read()?;
        let old_abs = self.base_offset + pos as i64;
        let depth = self.state.tokens.depth();
        let (pos, err) = self.consume_value(vflags, pos, depth);
        let new_abs = self.base_offset + pos as i64;
        let n = (new_abs - old_abs) as usize;
        if let Some(err) = err {
            return Err(self.wrap_syntactic_error(err, pos, 1));
        }
        let allow_dup = self.opts.flags.get(flags::ALLOW_DUPLICATE_NAMES);
        let result: Result<(), Error> = match next.0 {
            b'n' | b't' | b'f' => self.state.tokens.append_literal(),
            b'"' => {
                let mut r = Ok(());
                if self.state.tokens.last.need_object_name() {
                    let mut failed = false;
                    if !allow_dup {
                        if !self.state.tokens.last.is_valid_namespace() {
                            r = Err(Error::InvalidNamespace);
                            failed = true;
                        } else if self.state.tokens.last.is_active_namespace() {
                            let name = &self.arr[pos - n..pos];
                            let verbatim = vflags.is_verbatim();
                            let ns = self.state.namespaces.last_mut().expect("namespace");
                            if !ns.insert_quoted(name, verbatim) {
                                r = Err(wrap_with_object_name(Error::DuplicateName, name));
                                failed = true;
                            }
                        }
                    }
                    if !failed {
                        self.state.names.replace_last_quoted_offset(pos - n);
                    }
                }
                if r.is_ok() {
                    r = self.state.tokens.append_string();
                }
                r
            }
            b'0' => self.state.tokens.append_number(),
            b'{' => {
                let r = self.state.tokens.push_object();
                if r.is_ok() {
                    self.state
                        .tokens
                        .pop_object()
                        .expect("popObject should never fail immediately after pushObject");
                }
                r
            }
            b'[' => {
                let r = self.state.tokens.push_array();
                if r.is_ok() {
                    self.state
                        .tokens
                        .pop_array()
                        .expect("popArray should never fail immediately after pushArray");
                }
                r
            }
            _ => Ok(()),
        };
        if let Err(err) = result {
            return Err(self.wrap_syntactic_error(err, pos - n, 1));
        }
        self.prev_end = pos;
        self.prev_start = pos - n;
        Ok(self.buf()[pos - n..pos].to_vec())
    }

    pub(crate) fn at_eof(&mut self) -> bool {
        let (_, err) = self.consume_whitespace(self.prev_end);
        matches!(err, Some(Error::UnexpectedEof))
    }

    pub(crate) fn check_eof(&mut self) -> Result<(), Error> {
        self.check_eof_at(self.prev_end)
    }

    fn check_eof_at(&mut self, pos: usize) -> Result<(), Error> {
        let (pos, err) = self.consume_whitespace(pos);
        match err {
            None => {
                let err =
                    wire::invalid_character_error(&self.buf()[pos..], "after top-level value");
                Err(self.wrap_syntactic_error(err, pos, 0))
            }
            Some(Error::UnexpectedEof) => Ok(()),
            Some(err) => Err(err),
        }
    }

    // ------------------------------------------------------------ consume

    fn refetch(&mut self, pos: usize) -> (usize, Result<(), Error>) {
        let abs = self.base_offset + pos as i64;
        let r = self.fetch();
        ((abs - self.base_offset) as usize, r)
    }

    fn consume_value(
        &mut self,
        flags: &mut ValueFlags,
        mut pos: usize,
        depth: usize,
    ) -> (usize, Option<Error>) {
        loop {
            let next = Kind(self.buf()[pos]).normalize();
            let (n, err): (usize, Option<Error>) = match next.0 {
                b'n' => {
                    let n = wire::consume_null(&self.buf()[pos..]);
                    if n == 0 {
                        wire::consume_literal(&self.buf()[pos..], "null")
                    } else {
                        (n, None)
                    }
                }
                b'f' => {
                    let n = wire::consume_false(&self.buf()[pos..]);
                    if n == 0 {
                        wire::consume_literal(&self.buf()[pos..], "false")
                    } else {
                        (n, None)
                    }
                }
                b't' => {
                    let n = wire::consume_true(&self.buf()[pos..]);
                    if n == 0 {
                        wire::consume_literal(&self.buf()[pos..], "true")
                    } else {
                        (n, None)
                    }
                }
                b'"' => {
                    let n = wire::consume_simple_string(&self.buf()[pos..]);
                    if n == 0 {
                        return self.consume_string(flags, pos);
                    }
                    (n, None)
                }
                b'0' => {
                    let n = wire::consume_simple_number(&self.buf()[pos..]);
                    if n == 0 || self.need_more(pos + n) {
                        return self.consume_number(pos);
                    }
                    (n, None)
                }
                b'{' => return self.consume_object(flags, pos, depth),
                b'[' => return self.consume_array(flags, pos, depth),
                _ => {
                    let last = self.state.tokens.last;
                    if (last.is_object() && next.0 == b']') || (last.is_array() && next.0 == b'}') {
                        return (pos, Some(Error::MismatchDelim));
                    }
                    return (
                        pos,
                        Some(wire::invalid_character_error(
                            &self.buf()[pos..],
                            "at start of value",
                        )),
                    );
                }
            };
            if matches!(err, Some(Error::UnexpectedEof)) {
                let (p, r) = self.refetch(pos);
                pos = p;
                if let Err(e) = r {
                    return (pos + n, Some(e));
                }
                continue;
            }
            return (pos + n, err);
        }
    }

    fn consume_literal(&mut self, mut pos: usize, lit: &str) -> (usize, Option<Error>) {
        loop {
            let (n, err) = wire::consume_literal(&self.buf()[pos..], lit);
            if matches!(err, Some(Error::UnexpectedEof)) {
                let (p, r) = self.refetch(pos);
                pos = p;
                if let Err(e) = r {
                    return (pos + n, Some(e));
                }
                continue;
            }
            return (pos + n, err);
        }
    }

    fn consume_string(&mut self, flags: &mut ValueFlags, mut pos: usize) -> (usize, Option<Error>) {
        let mut n = 0usize;
        loop {
            let validate = !self.opts.flags.get(super::flags::ALLOW_INVALID_UTF8);
            let (m, err) = wire::consume_string_resumable(flags, &self.buf()[pos..], n, validate);
            n = m;
            if matches!(err, Some(Error::UnexpectedEof)) {
                let (p, r) = self.refetch(pos);
                pos = p;
                if let Err(e) = r {
                    return (pos + n, Some(e));
                }
                continue;
            }
            return (pos + n, err);
        }
    }

    fn consume_number(&mut self, mut pos: usize) -> (usize, Option<Error>) {
        let mut n = 0usize;
        let mut state = NumberState::Init;
        loop {
            let (m, st, err) = wire::consume_number_resumable(&self.buf()[pos..], n, state);
            n = m;
            state = st;
            if matches!(err, Some(Error::UnexpectedEof)) || self.need_more(pos + n) {
                let may_terminate = err.is_none();
                let (p, r) = self.refetch(pos);
                pos = p;
                if let Err(e) = r {
                    if may_terminate && matches!(e, Error::UnexpectedEof) {
                        return (pos + n, None);
                    }
                    return (pos, Some(e));
                }
                continue;
            }
            return (pos + n, err);
        }
    }

    /// The current contents of a slice of the read buffer captured earlier
    /// as (array id, start, end).
    fn alias(&self, (id, start, end): (u64, usize, usize)) -> Vec<u8> {
        if id == self.arr_id {
            return self.arr[start..end.min(self.arr.len())].to_vec();
        }
        match self.retired.iter().find(|(i, _)| *i == id) {
            Some((_, old)) => old[start..end.min(old.len())].to_vec(),
            None => Vec::new(),
        }
    }

    fn consume_object(
        &mut self,
        flags: &mut ValueFlags,
        pos: usize,
        depth: usize,
    ) -> (usize, Option<Error>) {
        let allow_dup = self.opts.flags.get(super::flags::ALLOW_DUPLICATE_NAMES);
        if !allow_dup {
            self.state.namespaces.push(ObjectNamespace::default());
        }
        self.capture_depth += 1;
        let r = self.consume_object_inner(flags, pos, depth, !allow_dup);
        self.capture_depth -= 1;
        if self.capture_depth == 0 {
            self.retired.clear();
        }
        if !allow_dup {
            self.state.namespaces.pop();
        }
        r
    }

    fn consume_object_inner(
        &mut self,
        flags: &mut ValueFlags,
        mut pos: usize,
        mut depth: usize,
        check_names: bool,
    ) -> (usize, Option<Error>) {
        if pos >= self.blen || self.buf()[pos] != b'{' {
            panic!("BUG: consumeObject must be called with a buffer that starts with '{{'");
        } else if depth == MAX_NESTING_DEPTH + 1 {
            return (pos, Some(Error::MaxDepth));
        }
        pos += 1;
        pos += wire::consume_whitespace(&self.buf()[pos..]);
        if self.need_more(pos) {
            let (p, err) = self.consume_whitespace(pos);
            pos = p;
            if err.is_some() {
                return (pos, err);
            }
        }
        if self.buf()[pos] == b'}' {
            return (pos + 1, None);
        }
        depth += 1;
        loop {
            pos += wire::consume_whitespace(&self.buf()[pos..]);
            if self.need_more(pos) {
                let (p, err) = self.consume_whitespace(pos);
                pos = p;
                if err.is_some() {
                    return (pos, err);
                }
            }
            let mut flags2 = ValueFlags::default();
            let mut n = wire::consume_simple_string(&self.buf()[pos..]);
            if n == 0 {
                let old_abs = self.base_offset + pos as i64;
                let (p, err) = self.consume_string(&mut flags2, pos);
                pos = p;
                let new_abs = self.base_offset + pos as i64;
                n = (new_abs - old_abs) as usize;
                flags.merge(flags2);
                if err.is_some() {
                    return (pos, err);
                }
            } else {
                pos += n;
            }
            // Go keeps `quotedName` as a slice of the read buffer, which a
            // later fetch may shift under it; `alias` reproduces that.
            let quoted_name = (self.arr_id, pos - n, pos);
            if check_names {
                let ns = self.state.namespaces.last_mut().expect("namespace");
                if !ns.insert_quoted(&self.arr[pos - n..pos], flags2.is_verbatim()) {
                    let name = self.alias(quoted_name);
                    return (
                        pos - n,
                        Some(wrap_with_object_name(Error::DuplicateName, &name)),
                    );
                }
            }
            pos += wire::consume_whitespace(&self.buf()[pos..]);
            if self.need_more(pos) {
                let (p, err) = self.consume_whitespace(pos);
                pos = p;
                if let Some(err) = err {
                    return (
                        pos,
                        Some(wrap_with_object_name(err, &self.alias(quoted_name))),
                    );
                }
            }
            if self.buf()[pos] != b':' {
                let err = wire::invalid_character_error(
                    &self.buf()[pos..],
                    "after object name (expecting ':')",
                );
                return (
                    pos,
                    Some(wrap_with_object_name(err, &self.alias(quoted_name))),
                );
            }
            pos += 1;
            pos += wire::consume_whitespace(&self.buf()[pos..]);
            if self.need_more(pos) {
                let (p, err) = self.consume_whitespace(pos);
                pos = p;
                if let Some(err) = err {
                    return (
                        pos,
                        Some(wrap_with_object_name(err, &self.alias(quoted_name))),
                    );
                }
            }
            let (p, err) = self.consume_value(flags, pos, depth);
            pos = p;
            if let Some(err) = err {
                return (
                    pos,
                    Some(wrap_with_object_name(err, &self.alias(quoted_name))),
                );
            }
            pos += wire::consume_whitespace(&self.buf()[pos..]);
            if self.need_more(pos) {
                let (p, err) = self.consume_whitespace(pos);
                pos = p;
                if err.is_some() {
                    return (pos, err);
                }
            }
            match self.buf()[pos] {
                b',' => {
                    pos += 1;
                    continue;
                }
                b'}' => return (pos + 1, None),
                _ => {
                    return (
                        pos,
                        Some(wire::invalid_character_error(
                            &self.buf()[pos..],
                            "after object value (expecting ',' or '}')",
                        )),
                    )
                }
            }
        }
    }

    fn consume_array(
        &mut self,
        flags: &mut ValueFlags,
        mut pos: usize,
        mut depth: usize,
    ) -> (usize, Option<Error>) {
        if pos >= self.blen || self.buf()[pos] != b'[' {
            panic!("BUG: consumeArray must be called with a buffer that starts with '['");
        } else if depth == MAX_NESTING_DEPTH + 1 {
            return (pos, Some(Error::MaxDepth));
        }
        pos += 1;
        pos += wire::consume_whitespace(&self.buf()[pos..]);
        if self.need_more(pos) {
            let (p, err) = self.consume_whitespace(pos);
            pos = p;
            if err.is_some() {
                return (pos, err);
            }
        }
        if self.buf()[pos] == b']' {
            return (pos + 1, None);
        }
        let mut idx: i64 = 0;
        depth += 1;
        loop {
            pos += wire::consume_whitespace(&self.buf()[pos..]);
            if self.need_more(pos) {
                let (p, err) = self.consume_whitespace(pos);
                pos = p;
                if err.is_some() {
                    return (pos, err);
                }
            }
            let (p, err) = self.consume_value(flags, pos, depth);
            pos = p;
            if let Some(err) = err {
                return (pos, Some(wrap_with_array_index(err, idx)));
            }
            pos += wire::consume_whitespace(&self.buf()[pos..]);
            if self.need_more(pos) {
                let (p, err) = self.consume_whitespace(pos);
                pos = p;
                if err.is_some() {
                    return (pos, err);
                }
            }
            match self.buf()[pos] {
                b',' => {
                    pos += 1;
                    idx += 1;
                    continue;
                }
                b']' => return (pos + 1, None),
                _ => {
                    return (
                        pos,
                        Some(wire::invalid_character_error(
                            &self.buf()[pos..],
                            "after array element (expecting ',' or ']')",
                        )),
                    )
                }
            }
        }
    }
}

impl std::fmt::Debug for Decoder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decoder")
            .field("offset", &self.s.previous_offset_end())
            .finish()
    }
}

pub(crate) const _ASSERT_KIND_STRING: Kind = KIND_STRING;
