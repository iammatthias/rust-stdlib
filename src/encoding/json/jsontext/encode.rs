//! `jsontext.Encoder`: a streaming JSON token and value writer.
use std::io::Write;
use std::sync::Arc;

use super::errors::{
    finish_syntactic_error, wrap_with_array_index, wrap_with_object_name, Error, IoError, WrapInfo,
};
use super::flags;
use super::options::Options;
use super::state::{ObjectNamespace, Pointer, State, MAX_NESTING_DEPTH};
use super::token::{
    Kind, Token, KIND_BEGIN_ARRAY, KIND_BEGIN_OBJECT, KIND_INVALID, KIND_NUMBER, KIND_STRING,
};
use super::value::{must_reorder_objects, Value};
use super::wire;

/// The state of an [`Encoder`] (Go's `encoderState`); the v2 package drives
/// it directly.
pub(crate) struct EncoderState<'w> {
    pub(crate) state: State,
    /// The unflushed output.
    pub(crate) buf: Vec<u8>,
    /// Stands in for Go's `cap(Buf)`, which decides when to flush.
    cap: usize,
    base_offset: i64,
    wr: Option<Box<dyn Write + 'w>>,
    max_value: usize,
    pub(crate) opts: Options,
}

/// `jsontext.Encoder`: writes a stream of JSON tokens and values.
pub struct Encoder<'w> {
    pub(crate) s: EncoderState<'w>,
}

impl<'w> Encoder<'w> {
    /// Go's `NewEncoder`: an encoder writing to `w`. Output is written when a
    /// top-level value is complete or the buffer fills.
    pub fn new<W: Write + 'w>(w: W, opts: &[Options]) -> Encoder<'w> {
        let mut e = Encoder {
            s: EncoderState::empty(),
        };
        e.reset(w, opts);
        e
    }

    /// An encoder that collects its output in memory (Go's
    /// `getBufferedEncoder`).
    pub(crate) fn buffered(opts: &[Options]) -> Encoder<'static> {
        Encoder {
            s: EncoderState::buffered(opts),
        }
    }

    /// Go's `Encoder.Reset`: discards state and writes to `w` with `opts`.
    pub fn reset<W: Write + 'w>(&mut self, w: W, opts: &[Options]) {
        if self.s.opts.flags.get(flags::WITHIN_ARSHAL_CALL) {
            panic!("jsontext: cannot reset Encoder passed to json.MarshalerTo");
        }
        let b = std::mem::take(&mut self.s.buf);
        let cap = self.s.cap;
        self.s.reset(b, cap, Some(Box::new(w)), opts);
    }

    /// Go's `Encoder.Options`: the options in effect.
    pub fn options(&self) -> Options {
        self.s.opts.clone()
    }

    /// Go's `Encoder.WriteToken`: writes one token.
    pub fn write_token(&mut self, t: &Token) -> Result<(), Error> {
        self.s.write_token(t)
    }

    /// Go's `Encoder.WriteValue`: writes one complete value, reformatted per
    /// the options.
    pub fn write_value(&mut self, v: &Value) -> Result<(), Error> {
        self.s.write_value(&v.0)
    }

    /// Go's `Encoder.OutputOffset`: the offset after the last token or value
    /// written, including output not yet flushed.
    pub fn output_offset(&self) -> i64 {
        self.s.previous_offset_end()
    }

    /// Go's `Encoder.AvailableBuffer`: an empty buffer to build the argument
    /// of [`write_value`](Self::write_value) in.
    pub fn available_buffer(&mut self) -> Vec<u8> {
        let bits = usize::BITS - (self.s.max_value | 63).leading_zeros();
        Vec::with_capacity(1usize << bits)
    }

    /// Go's `Encoder.StackDepth`: the number of open objects and arrays.
    pub fn stack_depth(&self) -> usize {
        self.s.state.tokens.depth() - 1
    }

    /// Go's `Encoder.StackIndex`: the kind (`{` or `[`, or invalid for the
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

    /// Go's `Encoder.StackPointer`: the JSON Pointer of the most recently
    /// written value.
    pub fn stack_pointer(&mut self) -> Pointer {
        let mut b = Vec::new();
        self.s.append_stack_pointer(&mut b, -1);
        Pointer::from(String::from_utf8_lossy(&b).into_owned())
    }

    /// Flushes any buffered output to the writer. Output is flushed after
    /// every top-level value, so this matters only mid-value.
    pub fn flush(&mut self) -> Result<(), Error> {
        self.s.flush()
    }
}

impl std::fmt::Debug for Encoder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Encoder")
            .field("offset", &self.s.previous_offset_end())
            .finish()
    }
}

impl<'w> EncoderState<'w> {
    fn empty() -> EncoderState<'w> {
        EncoderState {
            state: State::default(),
            buf: Vec::new(),
            cap: 0,
            base_offset: 0,
            wr: None,
            max_value: 0,
            opts: Options::default(),
        }
    }

    /// An encoder that collects its output in memory (Go's
    /// `getBufferedEncoder`).
    pub(crate) fn buffered(opts: &[Options]) -> EncoderState<'static> {
        let mut e = EncoderState::empty();
        e.reset(Vec::new(), 0, None, opts);
        e
    }

    fn reset(
        &mut self,
        mut buf: Vec<u8>,
        cap: usize,
        wr: Option<Box<dyn Write + 'w>>,
        opts: &[Options],
    ) {
        self.state.reset();
        buf.clear();
        self.buf = buf;
        self.cap = cap;
        self.base_offset = 0;
        self.wr = wr;
        self.max_value = 0;
        let mut o = Options::default();
        o.join_all(opts);
        if o.flags.get(flags::MULTILINE) {
            o.initialize_multiline();
        }
        self.opts = o;
    }

    pub(crate) fn offset_at(&self, pos: usize) -> i64 {
        self.base_offset + pos as i64
    }
    pub(crate) fn previous_offset_end(&self) -> i64 {
        self.base_offset + self.buf.len() as i64
    }

    fn grow_cap(&mut self) {
        if self.buf.len() > self.cap {
            self.cap = self.buf.len().next_power_of_two().max(8);
        }
    }

    fn need_flush(&self) -> bool {
        self.wr.is_some() && (self.state.tokens.depth() == 1 || self.buf.len() > 3 * self.cap / 4)
    }

    /// `Flush`: writes the buffered output, unless a member is half written.
    pub(crate) fn flush(&mut self) -> Result<(), Error> {
        if self.wr.is_none() || self.avoid_flush() {
            return Ok(());
        }
        if self.state.tokens.depth() == 1 && !self.opts.flags.get(flags::OMIT_TOP_LEVEL_NEWLINE) {
            self.buf.push(b'\n');
        }
        self.grow_cap();
        self.state.names.copy_quoted_buffer(&mut self.buf);
        let wr = self.wr.as_mut().expect("writer");
        match wr.write_all(&self.buf) {
            Ok(()) => {
                self.base_offset += self.buf.len() as i64;
            }
            Err(e) => {
                return Err(Error::Io(IoError {
                    action: "write",
                    err: Arc::new(e),
                }));
            }
        }
        self.buf.clear();
        const MAX_BUFFER_SIZE: usize = 4 << 10;
        let mut grow = self.cap <= MAX_BUFFER_SIZE / 2;
        grow = grow && (self.cap as i64) < self.previous_offset_end() / 2;
        if grow {
            self.cap *= 2;
        }
        Ok(())
    }

    fn avoid_flush(&self) -> bool {
        let last = self.state.tokens.last;
        if last.length() == 0 || last.need_object_value() {
            return true;
        }
        if last.need_object_name() && self.buf.len() >= 2 {
            return matches!(
                &self.buf[self.buf.len() - 2..],
                b"ll" | b"\"\"" | b"{}" | b"[]"
            );
        }
        false
    }

    /// `UnwriteEmptyObjectMember`: removes the last member of the innermost
    /// object if its value is `null`, `""`, `{}` or `[]`. `prev_name`
    /// becomes the object's last name when the member was removed.
    pub(crate) fn unwrite_empty_object_member(&mut self, prev_name: Option<&[u8]>) -> bool {
        let last = self.state.tokens.last;
        if !last.is_object() || !last.need_object_name() || last.length() == 0 {
            panic!("BUG: must be called on an object after writing a value");
        }
        let b = &self.buf;
        let mut n = 0usize;
        if b.len() >= 3 {
            match &b[b.len() - 2..] {
                b"ll" => n = 4,
                b"\"\"" => {
                    if b[b.len() - 3] == b'\\' {
                        return false;
                    }
                    n = 2;
                }
                b"{}" => n = 2,
                b"[]" => n = 2,
                _ => {}
            }
        }
        if n == 0 {
            return false;
        }
        let mut b: &[u8] = &b[..b.len() - n];
        b = wire::trim_suffix_whitespace(b);
        b = wire::trim_suffix_byte(b, b':');
        b = wire::trim_suffix_string(b);
        b = wire::trim_suffix_whitespace(b);
        b = wire::trim_suffix_byte(b, b',');
        let new_len = b.len();
        self.buf.truncate(new_len);
        self.state.tokens.last.decrement();
        self.state.tokens.last.decrement();
        if !self.opts.flags.get(flags::ALLOW_DUPLICATE_NAMES)
            && self.state.tokens.last.is_active_namespace()
        {
            self.state.last_namespace().remove_last();
        }
        self.state.names.clear_last();
        if let Some(prev) = prev_name {
            self.state.names.copy_quoted_buffer(&mut self.buf);
            self.state.names.replace_last_unquoted_name(prev);
        }
        true
    }

    /// `UnwriteOnlyObjectMemberName`: removes the first name of the
    /// innermost object, which has no value yet, and returns it.
    pub(crate) fn unwrite_only_object_member_name(&mut self) -> Vec<u8> {
        let last = self.state.tokens.last;
        if !last.is_object() || last.length() != 1 {
            panic!("BUG: must be called on an object after writing first name");
        }
        let trimmed_len = wire::trim_suffix_string(&self.buf).len();
        let quoted = &self.buf[trimmed_len..];
        let is_verbatim = !quoted.contains(&b'\\');
        let name = wire::unquote_may_copy(quoted, is_verbatim);
        let end = wire::trim_suffix_whitespace(&self.buf[..trimmed_len]).len();
        self.buf.truncate(end);
        self.state.tokens.last.decrement();
        if !self.opts.flags.get(flags::ALLOW_DUPLICATE_NAMES)
            && self.state.tokens.last.is_active_namespace()
        {
            self.state.last_namespace().remove_last();
        }
        self.state.names.clear_last();
        name
    }

    /// `wrapSyntacticError`.
    pub(crate) fn wrap_syntactic_error(&mut self, err: Error, pos: usize, where_: i32) -> Error {
        if matches!(err, Error::Eof | Error::Io(_)) {
            return err;
        }
        let offset = self.offset_at(pos);
        let mut ptr = Vec::new();
        self.append_stack_pointer(&mut ptr, where_);
        finish_syntactic_error(
            err,
            WrapInfo {
                legacy_errors: self
                    .opts
                    .flags
                    .get(flags::REPORT_ERRORS_WITH_LEGACY_SEMANTICS),
                offset,
                pointer: ptr,
                mismatch: None,
            },
        )
    }

    pub(crate) fn append_stack_pointer(&mut self, b: &mut Vec<u8>, where_: i32) {
        self.state.names.copy_quoted_buffer(&mut self.buf);
        self.state.append_stack_pointer(b, where_);
    }

    /// Finishes a write that built its output in `b` (the taken buffer):
    /// stores it back on success, or truncates it to `orig_len` on error.
    fn commit(
        &mut self,
        mut b: Vec<u8>,
        orig_len: usize,
        err: Option<(Error, usize)>,
    ) -> Result<(), Error> {
        match err {
            Some((err, pos)) => {
                b.truncate(orig_len);
                self.buf = b;
                Err(self.wrap_syntactic_error(err, pos, 1))
            }
            None => {
                self.buf = b;
                self.grow_cap();
                if self.need_flush() {
                    return self.flush();
                }
                Ok(())
            }
        }
    }

    #[allow(clippy::needless_late_init)]
    pub(crate) fn write_token(&mut self, t: &Token) -> Result<(), Error> {
        let k = t.kind();
        let mut b = std::mem::take(&mut self.buf);
        let orig_len = b.len();
        self.state.tokens.may_append_delim(&mut b, k.0);
        if self.opts.flags.get(flags::ANY_WHITESPACE) {
            self.append_whitespace(&mut b, k.0);
        }
        let pos = b.len();
        let allow_dup = self.opts.flags.get(flags::ALLOW_DUPLICATE_NAMES);
        let err: Option<Error>;
        match k.0 {
            b'n' => {
                b.extend_from_slice(b"null");
                err = self.state.tokens.append_literal().err();
            }
            b'f' => {
                b.extend_from_slice(b"false");
                err = self.state.tokens.append_literal().err();
            }
            b't' => {
                b.extend_from_slice(b"true");
                err = self.state.tokens.append_literal().err();
            }
            b'"' => 'string: {
                if let Some(e) = t.append_string(&mut b, &self.opts.flags) {
                    err = Some(e);
                    break 'string;
                }
                if self.state.tokens.last.need_object_name() {
                    if !allow_dup {
                        if !self.state.tokens.last.is_valid_namespace() {
                            err = Some(Error::InvalidNamespace);
                            break 'string;
                        }
                        if self.state.tokens.last.is_active_namespace() {
                            let ns = self.state.namespaces.last_mut().expect("namespace");
                            if !ns.insert_quoted(&b[pos..], false) {
                                err = Some(wrap_with_object_name(Error::DuplicateName, &b[pos..]));
                                break 'string;
                            }
                        }
                    }
                    self.state.names.replace_last_quoted_offset(pos);
                }
                err = self.state.tokens.append_string().err();
            }
            b'0' => 'number: {
                if let Some(e) = t.append_number(&mut b, &self.opts.flags) {
                    err = Some(e);
                    break 'number;
                }
                err = self.state.tokens.append_number().err();
            }
            b'{' => {
                b.push(b'{');
                err = self.state.tokens.push_object().err();
                if err.is_none() {
                    self.state.names.push();
                    if !allow_dup {
                        self.state.namespaces.push(ObjectNamespace::default());
                    }
                    self.opts.flags.clear(flags::TAG_FLAGS);
                }
            }
            b'}' => {
                b.push(b'}');
                err = self.state.tokens.pop_object().err();
                if err.is_none() {
                    self.state.names.pop();
                    if !allow_dup {
                        self.state.namespaces.pop();
                    }
                }
            }
            b'[' => {
                b.push(b'[');
                err = self.state.tokens.push_array().err();
                self.opts.flags.clear(flags::TAG_FLAGS);
            }
            b']' => {
                b.push(b']');
                err = self.state.tokens.pop_array().err();
            }
            _ => err = Some(Error::InvalidToken),
        }
        self.commit(b, orig_len, err.map(|e| (e, pos)))
    }

    /// `AppendRaw`: writes a string or number whose text `f` appends.
    #[allow(clippy::needless_late_init)]
    pub(crate) fn append_raw<F>(&mut self, k: Kind, safe_ascii: bool, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut Vec<u8>) -> Result<(), Error>,
    {
        let mut b = std::mem::take(&mut self.buf);
        let orig_len = b.len();
        self.state.tokens.may_append_delim(&mut b, k.0);
        if self.opts.flags.get(flags::ANY_WHITESPACE) {
            self.append_whitespace(&mut b, k.0);
        }
        let pos = b.len();
        let allow_dup = self.opts.flags.get(flags::ALLOW_DUPLICATE_NAMES);
        let err: Option<Error>;
        match k.0 {
            b'"' => 'string: {
                b.push(b'"');
                if let Err(e) = f(&mut b) {
                    b.truncate(orig_len);
                    self.buf = b;
                    return Err(e);
                }
                b.push(b'"');
                let is_verbatim = safe_ascii || !wire::need_escape(&b[pos + 1..b.len() - 1]);
                if !is_verbatim {
                    let b2 = b[pos + 1..b.len() - 1].to_vec();
                    b.truncate(pos);
                    if let Some(e) = wire::append_quote(&mut b, &b2, &self.opts.flags) {
                        err = Some(e);
                        break 'string;
                    }
                }
                if self.state.tokens.last.need_object_name() {
                    if !allow_dup {
                        if !self.state.tokens.last.is_valid_namespace() {
                            err = Some(Error::InvalidNamespace);
                            break 'string;
                        }
                        if self.state.tokens.last.is_active_namespace() {
                            let ns = self.state.namespaces.last_mut().expect("namespace");
                            if !ns.insert_quoted(&b[pos..], is_verbatim) {
                                err = Some(wrap_with_object_name(Error::DuplicateName, &b[pos..]));
                                break 'string;
                            }
                        }
                    }
                    self.state.names.replace_last_quoted_offset(pos);
                }
                err = self.state.tokens.append_string().err();
            }
            b'0' => {
                if let Err(e) = f(&mut b) {
                    b.truncate(orig_len);
                    self.buf = b;
                    return Err(e);
                }
                err = self.state.tokens.append_number().err();
            }
            _ => panic!("BUG: invalid kind"),
        }
        self.commit(b, orig_len, err.map(|e| (e, pos)))
    }

    #[allow(clippy::needless_late_init)]
    pub(crate) fn write_value(&mut self, v: &[u8]) -> Result<(), Error> {
        self.max_value |= v.len();
        let k = value_kind(v);
        let mut b = std::mem::take(&mut self.buf);
        let orig_len = b.len();
        self.state.tokens.may_append_delim(&mut b, k.0);
        if self.opts.flags.get(flags::ANY_WHITESPACE) {
            self.append_whitespace(&mut b, k.0);
        }
        let pos = b.len();
        let mut n = wire::consume_whitespace(v);
        let depth = self.state.tokens.depth();
        let (m, err) = self.reformat_value(&mut b, &v[n..], depth);
        if let Some(err) = err {
            return self.commit(b, orig_len, Some((err, pos + n + m)));
        }
        n += m;
        n += wire::consume_whitespace(&v[n..]);
        if v.len() > n {
            let err = wire::invalid_character_error(&v[n..], "after top-level value");
            b.truncate(orig_len);
            self.buf = b;
            return Err(self.wrap_syntactic_error(err, pos + n, 0));
        }
        let allow_dup = self.opts.flags.get(flags::ALLOW_DUPLICATE_NAMES);
        let mut err: Option<Error> = None;
        match k.0 {
            b'n' | b'f' | b't' => err = self.state.tokens.append_literal().err(),
            b'"' => 'string: {
                if self.state.tokens.last.need_object_name() {
                    if !allow_dup {
                        if !self.state.tokens.last.is_valid_namespace() {
                            err = Some(Error::InvalidNamespace);
                            break 'string;
                        }
                        if self.state.tokens.last.is_active_namespace() {
                            let ns = self.state.namespaces.last_mut().expect("namespace");
                            if !ns.insert_quoted(&b[pos..], false) {
                                err = Some(wrap_with_object_name(Error::DuplicateName, &b[pos..]));
                                break 'string;
                            }
                        }
                    }
                    self.state.names.replace_last_quoted_offset(pos);
                }
                err = self.state.tokens.append_string().err();
            }
            b'0' => err = self.state.tokens.append_number().err(),
            b'{' => {
                err = self.state.tokens.push_object().err();
                if err.is_none() {
                    self.state
                        .tokens
                        .pop_object()
                        .expect("popObject should never fail immediately after pushObject");
                    if self.opts.flags.get(flags::REORDER_RAW_OBJECTS) {
                        must_reorder_objects(&mut b[pos..]);
                    }
                }
            }
            b'[' => {
                err = self.state.tokens.push_array().err();
                if err.is_none() {
                    self.state
                        .tokens
                        .pop_array()
                        .expect("popArray should never fail immediately after pushArray");
                    if self.opts.flags.get(flags::REORDER_RAW_OBJECTS) {
                        must_reorder_objects(&mut b[pos..]);
                    }
                }
            }
            _ => {}
        }
        self.commit(b, orig_len, err.map(|e| (e, pos)))
    }

    /// `CountNextDelimWhitespace`: the number of delimiter and whitespace
    /// bytes that will precede the next value.
    pub(crate) fn count_next_delim_whitespace(&self) -> usize {
        let next = b'"';
        let delim = self.state.tokens.need_delim(next);
        let mut n = 0;
        if delim > 0 {
            n += 1;
        }
        if delim == b':' {
            if self.opts.flags.get(flags::SPACE_AFTER_COLON) {
                n += 1;
            }
        } else {
            if delim == b',' && self.opts.flags.get(flags::SPACE_AFTER_COMMA) {
                n += 1;
            }
            if self.opts.flags.get(flags::MULTILINE) {
                let m = self.state.tokens.need_indent(next);
                if m > 0 {
                    n += 1 + self.opts.indent_prefix.len() + (m - 1) * self.opts.indent.len();
                }
            }
        }
        n
    }

    fn append_whitespace(&self, b: &mut Vec<u8>, next: u8) {
        let delim = self.state.tokens.need_delim(next);
        if delim == b':' {
            if self.opts.flags.get(flags::SPACE_AFTER_COLON) {
                b.push(b' ');
            }
        } else {
            if delim == b',' && self.opts.flags.get(flags::SPACE_AFTER_COMMA) {
                b.push(b' ');
            }
            if self.opts.flags.get(flags::MULTILINE) {
                self.append_indent(b, self.state.tokens.need_indent(next));
            }
        }
    }

    fn append_indent(&self, b: &mut Vec<u8>, mut n: usize) {
        if n == 0 {
            return;
        }
        b.push(b'\n');
        b.extend_from_slice(self.opts.indent_prefix.as_bytes());
        while n > 1 {
            b.extend_from_slice(self.opts.indent.as_bytes());
            n -= 1;
        }
    }

    /// `reformatValue`: appends the value at the start of `src` to `dst`.
    fn reformat_value(
        &mut self,
        dst: &mut Vec<u8>,
        src: &[u8],
        depth: usize,
    ) -> (usize, Option<Error>) {
        if src.is_empty() {
            return (0, Some(Error::UnexpectedEof));
        }
        match Kind(src[0]).normalize().0 {
            b'n' => {
                if wire::consume_null(src) == 0 {
                    return wire::consume_literal(src, "null");
                }
                dst.extend_from_slice(b"null");
                (4, None)
            }
            b'f' => {
                if wire::consume_false(src) == 0 {
                    return wire::consume_literal(src, "false");
                }
                dst.extend_from_slice(b"false");
                (5, None)
            }
            b't' => {
                if wire::consume_true(src) == 0 {
                    return wire::consume_literal(src, "true");
                }
                dst.extend_from_slice(b"true");
                (4, None)
            }
            b'"' => {
                let n = wire::consume_simple_string(src);
                if n > 0 {
                    dst.extend_from_slice(&src[..n]);
                    return (n, None);
                }
                wire::reformat_string(dst, src, &self.opts.flags)
            }
            b'0' => {
                let n = wire::consume_simple_number(src);
                if n > 0 && !self.opts.flags.get(flags::CANONICALIZE_NUMBERS) {
                    dst.extend_from_slice(&src[..n]);
                    return (n, None);
                }
                wire::reformat_number(dst, src, &self.opts.flags)
            }
            b'{' => self.reformat_object(dst, src, depth),
            b'[' => self.reformat_array(dst, src, depth),
            _ => (
                0,
                Some(wire::invalid_character_error(src, "at start of value")),
            ),
        }
    }

    fn reformat_object(
        &mut self,
        dst: &mut Vec<u8>,
        src: &[u8],
        depth: usize,
    ) -> (usize, Option<Error>) {
        if src.is_empty() || src[0] != b'{' {
            panic!("BUG: reformatObject must be called with a buffer that starts with '{{'");
        } else if depth == MAX_NESTING_DEPTH + 1 {
            return (0, Some(Error::MaxDepth));
        }
        dst.push(b'{');
        let mut n = 1;
        n += wire::consume_whitespace(&src[n..]);
        if src.len() <= n {
            return (n, Some(Error::UnexpectedEof));
        }
        if src[n] == b'}' {
            dst.push(b'}');
            return (n + 1, None);
        }
        let check_names = !self.opts.flags.get(flags::ALLOW_DUPLICATE_NAMES);
        if check_names {
            self.state.namespaces.push(ObjectNamespace::default());
        }
        let r = self.reformat_object_members(dst, src, depth + 1, n, check_names);
        if check_names {
            self.state.namespaces.pop();
        }
        r
    }

    fn reformat_object_members(
        &mut self,
        dst: &mut Vec<u8>,
        src: &[u8],
        depth: usize,
        mut n: usize,
        check_names: bool,
    ) -> (usize, Option<Error>) {
        loop {
            if self.opts.flags.get(flags::MULTILINE) {
                self.append_indent(dst, depth);
            }
            n += wire::consume_whitespace(&src[n..]);
            if src.len() <= n {
                return (n, Some(Error::UnexpectedEof));
            }
            let mut m = wire::consume_simple_string(&src[n..]);
            let is_verbatim = m > 0;
            if is_verbatim {
                dst.extend_from_slice(&src[n..n + m]);
            } else {
                let (mm, err) = wire::reformat_string(dst, &src[n..], &self.opts.flags);
                m = mm;
                if let Some(err) = err {
                    return (n + m, Some(err));
                }
            }
            let quoted_name = &src[n..n + m];
            if check_names {
                let ns = self.state.namespaces.last_mut().expect("namespace");
                if !ns.insert_quoted(quoted_name, is_verbatim) {
                    return (
                        n,
                        Some(wrap_with_object_name(Error::DuplicateName, quoted_name)),
                    );
                }
            }
            n += m;
            n += wire::consume_whitespace(&src[n..]);
            if src.len() <= n {
                return (
                    n,
                    Some(wrap_with_object_name(Error::UnexpectedEof, quoted_name)),
                );
            }
            if src[n] != b':' {
                let err =
                    wire::invalid_character_error(&src[n..], "after object name (expecting ':')");
                return (n, Some(wrap_with_object_name(err, quoted_name)));
            }
            dst.push(b':');
            n += 1;
            if self.opts.flags.get(flags::SPACE_AFTER_COLON) {
                dst.push(b' ');
            }
            n += wire::consume_whitespace(&src[n..]);
            if src.len() <= n {
                return (
                    n,
                    Some(wrap_with_object_name(Error::UnexpectedEof, quoted_name)),
                );
            }
            let (m, err) = self.reformat_value(dst, &src[n..], depth);
            if let Some(err) = err {
                return (n + m, Some(wrap_with_object_name(err, quoted_name)));
            }
            n += m;
            n += wire::consume_whitespace(&src[n..]);
            if src.len() <= n {
                return (n, Some(Error::UnexpectedEof));
            }
            match src[n] {
                b',' => {
                    dst.push(b',');
                    if self.opts.flags.get(flags::SPACE_AFTER_COMMA) {
                        dst.push(b' ');
                    }
                    n += 1;
                }
                b'}' => {
                    if self.opts.flags.get(flags::MULTILINE) {
                        self.append_indent(dst, depth - 1);
                    }
                    dst.push(b'}');
                    return (n + 1, None);
                }
                _ => {
                    return (
                        n,
                        Some(wire::invalid_character_error(
                            &src[n..],
                            "after object value (expecting ',' or '}')",
                        )),
                    )
                }
            }
        }
    }

    fn reformat_array(
        &mut self,
        dst: &mut Vec<u8>,
        src: &[u8],
        mut depth: usize,
    ) -> (usize, Option<Error>) {
        if src.is_empty() || src[0] != b'[' {
            panic!("BUG: reformatArray must be called with a buffer that starts with '['");
        } else if depth == MAX_NESTING_DEPTH + 1 {
            return (0, Some(Error::MaxDepth));
        }
        dst.push(b'[');
        let mut n = 1;
        n += wire::consume_whitespace(&src[n..]);
        if src.len() <= n {
            return (n, Some(Error::UnexpectedEof));
        }
        if src[n] == b']' {
            dst.push(b']');
            return (n + 1, None);
        }
        let mut idx: i64 = 0;
        depth += 1;
        loop {
            if self.opts.flags.get(flags::MULTILINE) {
                self.append_indent(dst, depth);
            }
            n += wire::consume_whitespace(&src[n..]);
            if src.len() <= n {
                return (n, Some(Error::UnexpectedEof));
            }
            let (m, err) = self.reformat_value(dst, &src[n..], depth);
            if let Some(err) = err {
                return (n + m, Some(wrap_with_array_index(err, idx)));
            }
            n += m;
            n += wire::consume_whitespace(&src[n..]);
            if src.len() <= n {
                return (n, Some(Error::UnexpectedEof));
            }
            match src[n] {
                b',' => {
                    dst.push(b',');
                    if self.opts.flags.get(flags::SPACE_AFTER_COMMA) {
                        dst.push(b' ');
                    }
                    n += 1;
                    idx += 1;
                }
                b']' => {
                    if self.opts.flags.get(flags::MULTILINE) {
                        self.append_indent(dst, depth - 1);
                    }
                    dst.push(b']');
                    return (n + 1, None);
                }
                _ => {
                    return (
                        n,
                        Some(wire::invalid_character_error(
                            &src[n..],
                            "after array value (expecting ',' or ']')",
                        )),
                    )
                }
            }
        }
    }
}

/// The kind of the value in `v` (Go's `Value.Kind`).
pub(crate) fn value_kind(v: &[u8]) -> Kind {
    let rest = &v[wire::consume_whitespace(v)..];
    match rest.first() {
        Some(&c) => Kind(c).normalize(),
        None => KIND_INVALID,
    }
}

pub(crate) const _KINDS: (Kind, Kind) = (KIND_NUMBER, KIND_STRING);
