//! Regular expressions (Go `regexp`), with the RE2 syntax of
//! [`syntax`] and guaranteed linear-time matching.
//!
//! [`compile`] gives leftmost-first ("Perl") semantics; [`compile_posix`] and
//! [`Regexp::longest`] give leftmost-longest. Matching takes time
//! O(text length x pattern size). As in Go, each search picks one of three
//! matchers with identical results: the one-pass matcher for anchored,
//! unambiguous patterns; the bit-state backtracker for patterns of at most
//! 500 instructions on byte inputs shorter than 256K bits / instructions;
//! otherwise the Pike VM. Text is UTF-8 bytes; an invalid byte matches as
//! U+FFFD with width 1, as in Go. All indices are byte offsets.
//!
//! [`Regexp::find_index_at`] and its siblings search from an offset with the
//! text before it as context, and the `find_anchored_*` forms accept only a
//! match that begins exactly there; together they make a tokenizer that tries
//! many patterns at one position cheap.
//!
//! Differences from Go's API, all forced by the language:
//!
//! - Methods whose Go form returns a nil slice for "no match" return `Option`
//!   (or an empty `Vec` for the `find_all` family); `""` and a failed
//!   `FindString` are therefore distinguishable. A group that did not take part
//!   in the match is `None` in `*_submatch` results and `-1` in index vectors,
//!   which keeps [`Regexp::expand`]'s `match` argument in Go's shape.
//! - Single matches are `(start, end)` tuples; submatch indices are
//!   `Vec<isize>` laid out as Go's `[]int`.
//! - [`Regexp::match_reader`] and friends take a [`RuneReader`]; wrap any
//!   [`std::io::Read`] in a [`Utf8RuneReader`].
//! - `must_compile` panics like `MustCompile`. There are no invalid-UTF-8
//!   patterns for the `&str` entry points.
//!
//! ```
//! use rust_stdlib::regexp::compile;
//! let re = compile(r"(?P<year>\d{4})-(?P<month>\d{2})")?;
//! let m = re.find_string_submatch("date: 2024-05-17").unwrap();
//! assert_eq!(m, [Some("2024-05"), Some("2024"), Some("05")]);
//! assert_eq!(re.replace_all_string("2024-05", "${month}/${year}"), "05/2024");
//! # Ok::<(), rust_stdlib::regexp::syntax::Error>(())
//! ```
mod backtrack;
#[cfg(test)]
mod engine_tests;
mod exec;
mod onepass;
pub mod syntax;

pub use crate::io::RuneReader;
pub use exec::Utf8RuneReader;

use backtrack::BitState;
use exec::{BytesInput, Machine, Params, ReaderInput};
use onepass::OnePassProg;
use std::{
    fmt,
    str::FromStr,
    sync::{Arc, Mutex, PoisonError, TryLockError},
};
use syntax::{EmptyOp, Error, Flags, Prog};

const MAX_POOLED_MACHINES: usize = 8;

/// A compiled regular expression. It is safe to use from several threads.
#[derive(Clone)]
pub struct Regexp {
    expr: String,
    prog: Arc<Prog>,
    onepass: Option<Arc<OnePassProg>>,
    num_subexp: usize,
    subexp_names: Vec<String>,
    /// Required prefix of every match: after the leading `\A` for a one-pass
    /// program, else of unanchored matches.
    prefix: String,
    prefix_complete: bool,
    prefix_end: u32,
    prefix_rune: i32,
    cond: EmptyOp,
    longest: bool,
    /// Fewest bytes any match spans.
    min_input_len: isize,
    /// Inputs shorter than this run on the backtracker (when not one-pass).
    max_bit_state_len: usize,
    engine: Engine,
    pool: Arc<Pool>,
}

/// Which matcher runs a search; tests force each to check they agree.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Engine {
    /// Go's choice.
    #[default]
    Auto,
    /// The one-pass matcher, when the program is one-pass.
    OnePass,
    /// The backtracker, for byte inputs of any length.
    Backtrack,
    /// The Pike VM.
    Pike,
}

/// The `(start, end)` of a match from its capture positions.
fn span(a: &[isize]) -> (usize, usize) {
    (a[0] as usize, a[1] as usize)
}

/// Pooled matcher state, reused across searches.
#[derive(Default)]
struct Cache {
    pike: Option<Machine>,
    bits: BitState,
    onepass: Vec<isize>,
}

/// The matcher state of one regexp. A search uses `first` in place, taking
/// one lock; searches that find it busy share the states in `rest`.
#[derive(Default)]
struct Pool {
    first: Mutex<Cache>,
    rest: Mutex<Vec<Cache>>,
}

impl Pool {
    fn with<T>(&self, f: impl FnOnce(&mut Cache) -> T) -> T {
        match self.first.try_lock() {
            Ok(mut c) => f(&mut c),
            Err(TryLockError::Poisoned(e)) => {
                // A search panicked (a caller's RuneReader can) and left the
                // state mid-run.
                let mut c = e.into_inner();
                *c = Cache::default();
                self.first.clear_poison();
                f(&mut c)
            }
            Err(TryLockError::WouldBlock) => {
                let rest = || self.rest.lock().unwrap_or_else(PoisonError::into_inner);
                let mut c = rest().pop().unwrap_or_default();
                let out = f(&mut c);
                let mut rest = rest();
                if rest.len() < MAX_POOLED_MACHINES {
                    rest.push(c);
                }
                out
            }
        }
    }
}

impl fmt::Debug for Regexp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Regexp").field(&self.expr).finish()
    }
}

/// Displays the source text of the regular expression.
impl fmt::Display for Regexp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.expr)
    }
}

impl FromStr for Regexp {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        compile(s)
    }
}

/// Parses a regular expression and returns, if successful, a [`Regexp`] with
/// leftmost-first matching.
pub fn compile(expr: &str) -> Result<Regexp, Error> {
    Regexp::build(expr.as_bytes(), Flags::PERL, false)
}

/// Like [`compile`] but restricts the syntax to POSIX ERE (egrep) and selects
/// leftmost-longest matching. The restrictions are: no `\d \w \s`, no
/// non-greedy operators, no `(?:` groups, no `\A \z \b \B`, no named groups,
/// and counted repetitions are limited to 1000.
pub fn compile_posix(expr: &str) -> Result<Regexp, Error> {
    Regexp::build(expr.as_bytes(), Flags::POSIX, true)
}

/// Compiles with explicit syntax flags and match preference (Go's unexported
/// `compile`; exposed for the ported Go tests).
#[doc(hidden)]
pub fn compile_with(expr: &str, mode: Flags, longest: bool) -> Result<Regexp, Error> {
    Regexp::build(expr.as_bytes(), mode, longest)
}

/// The regexp that matches the empty string.
impl Default for Regexp {
    fn default() -> Self {
        must_compile("")
    }
}

/// Like [`compile`] but panics if the expression cannot be parsed.
pub fn must_compile(expr: &str) -> Regexp {
    match compile(expr) {
        Ok(re) => re,
        Err(e) => panic!("regexp: Compile({}): {}", quote(expr), e),
    }
}

/// Like [`compile_posix`] but panics if the expression cannot be parsed.
pub fn must_compile_posix(expr: &str) -> Regexp {
    match compile_posix(expr) {
        Ok(re) => re,
        Err(e) => panic!("regexp: CompilePOSIX({}): {}", quote(expr), e),
    }
}

/// Reports whether the text contains any match of the pattern.
pub fn match_string(pattern: &str, s: &str) -> Result<bool, Error> {
    Ok(compile(pattern)?.match_string(s))
}

/// Reports whether the byte slice contains any match of the pattern.
pub fn match_bytes(pattern: &str, b: &[u8]) -> Result<bool, Error> {
    Ok(compile(pattern)?.match_bytes(b))
}

/// Reports whether the runes returned by the reader contain any match of the
/// pattern.
pub fn match_reader<R: RuneReader + ?Sized>(pattern: &str, r: &mut R) -> Result<bool, Error> {
    Ok(compile(pattern)?.match_reader(r))
}

fn can_backquote(s: &str) -> bool {
    s.chars()
        .all(|c| !((c < ' ' && c != '\t') || c == '`' || c == '\u{7f}' || c == '\u{feff}'))
}

/// Go's `quote`: backquoted when possible, else `strconv.Quote`.
fn quote(s: &str) -> String {
    if can_backquote(s) {
        return format!("`{s}`");
    }
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x07' => out.push_str("\\a"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x0b' => out.push_str("\\v"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c if crate::unicode::is_print(c as i32) => out.push(c),
            c if (c as u32) < 0x10000 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push_str(&format!("\\U{:08x}", c as u32)),
        }
    }
    out.push('"');
    out
}

fn is_special(b: u8) -> bool {
    b"\\.+*?()|[]{}^$".contains(&b)
}

/// Returns a string that escapes all regular expression metacharacters inside
/// the argument text; the returned string is a regular expression matching the
/// literal text.
pub fn quote_meta(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        if c.is_ascii() && is_special(c as u8) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Where a match search reads its text.
enum Source<'a, 'r, R: RuneReader + ?Sized> {
    Bytes(&'a [u8]),
    Reader(&'r mut R),
}

/// Never constructed; the type of the unused reader in byte searches.
struct NoReader;
impl RuneReader for NoReader {
    fn read_rune(&mut self) -> std::io::Result<(char, usize)> {
        Err(std::io::ErrorKind::UnexpectedEof.into())
    }
}

impl Regexp {
    /// Same as [`compile`].
    pub fn new(expr: &str) -> Result<Regexp, Error> {
        compile(expr)
    }

    fn build(expr: &[u8], mode: Flags, longest: bool) -> Result<Regexp, Error> {
        // Syntax trees up to Go's nesting limit (1000) are processed
        // recursively; long patterns can nest deeply, so give them a roomy
        // stack of their own instead of risking the caller's.
        let front = if expr.len() > 256 {
            std::thread::scope(|s| {
                std::thread::Builder::new()
                    .stack_size(64 << 20)
                    .spawn_scoped(s, || Self::front_end(expr, mode))
                    .map_err(|_| Error::new(syntax::ErrorCode::INTERNAL_ERROR, b""))?
                    .join()
                    .map_err(|_| Error::new(syntax::ErrorCode::INTERNAL_ERROR, b""))?
            })?
        } else {
            Self::front_end(expr, mode)?
        };
        let (max_cap, cap_names, min_input_len, prog) = front;
        let onepass = onepass::compile_one_pass(&prog);
        let (prefix, prefix_complete, prefix_end, max_bit_state_len) = if onepass.is_some() {
            let (p, c, end) = onepass::one_pass_prefix(&prog);
            (p, c, end, 0)
        } else {
            let (p, c) = prog.prefix();
            (p, c, 0, backtrack::max_bit_state_len(&prog))
        };
        let prefix_rune = prefix.chars().next().map_or(0, |c| c as i32);
        Ok(Regexp {
            expr: String::from_utf8_lossy(expr).into_owned(),
            cond: prog.start_cond(),
            prog: Arc::new(prog),
            onepass: onepass.map(Arc::new),
            num_subexp: max_cap,
            subexp_names: cap_names,
            prefix,
            prefix_complete,
            prefix_end,
            prefix_rune,
            longest,
            min_input_len,
            max_bit_state_len,
            engine: Engine::Auto,
            pool: Arc::default(),
        })
    }

    fn front_end(expr: &[u8], mode: Flags) -> Result<(usize, Vec<String>, isize, Prog), Error> {
        let re = syntax::parse_bytes(expr, mode)?;
        let max_cap = re.max_cap() as usize;
        let cap_names = re.cap_names();
        let re = re.simplify();
        Ok((
            max_cap,
            cap_names,
            min_input_len(&re),
            syntax::compile(&re)?,
        ))
    }

    /// Makes every search use `engine` where it can run (one-pass needs a
    /// one-pass program, the backtracker a byte input); for tests.
    #[doc(hidden)]
    pub fn force_engine(&mut self, engine: Engine) {
        self.engine = engine;
    }

    /// Makes future searches prefer the leftmost-longest match. That is, when
    /// matching against text, the regexp returns a match that begins as early
    /// as possible in the input (leftmost), and among those it chooses a match
    /// that is as long as possible. This method modifies the [`Regexp`] and may
    /// not be called concurrently with any other methods.
    pub fn longest(&mut self) {
        self.longest = true;
    }

    /// Returns the number of parenthesized subexpressions.
    pub fn num_subexp(&self) -> usize {
        self.num_subexp
    }

    /// Returns the names of the parenthesized subexpressions, indexed by group
    /// number; unnamed groups, and the whole match at index 0, have an empty
    /// name.
    pub fn subexp_names(&self) -> &[String] {
        &self.subexp_names
    }

    /// Returns the index of the first subexpression with the given name, or
    /// `None` if there is no subexpression with that name. Note that multiple
    /// subexpressions can be written using the same name, as in
    /// `(?P<bob>a+)(?P<bob>b+)`, which declares two subexpressions named "bob".
    pub fn subexp_index(&self, name: &str) -> Option<usize> {
        if name.is_empty() {
            return None;
        }
        self.subexp_names.iter().position(|s| s == name)
    }

    /// Returns any literal prefix that must begin every match of the regexp,
    /// and whether that prefix is the entire regexp.
    pub fn literal_prefix(&self) -> (&str, bool) {
        (&self.prefix, self.prefix_complete)
    }

    /// Returns the source text used to compile the regular expression.
    pub fn as_str(&self) -> &str {
        &self.expr
    }

    /// Returns the textual form of the regular expression (Go's
    /// `AppendText`).
    pub fn append_text(&self, b: &mut Vec<u8>) {
        b.extend_from_slice(self.expr.as_bytes());
    }

    /// Returns the textual form of the regular expression (its source).
    pub fn marshal_text(&self) -> Vec<u8> {
        self.expr.as_bytes().to_vec()
    }

    /// Recompiles the regular expression from `text`, replacing `self`. On
    /// error `self` is unchanged.
    pub fn unmarshal_text(&mut self, text: &[u8]) -> Result<(), Error> {
        *self = Regexp::build(text, Flags::PERL, false)?;
        Ok(())
    }

    // ---- searching ----

    /// Chooses the matcher for a search as Go's `find` does.
    fn engine_for(&self, bytes_len: Option<usize>) -> Engine {
        match self.engine {
            Engine::OnePass if self.onepass.is_some() => Engine::OnePass,
            Engine::Backtrack if bytes_len.is_some() => Engine::Backtrack,
            Engine::Pike => Engine::Pike,
            _ if self.onepass.is_some() => Engine::OnePass,
            _ if bytes_len.is_some_and(|n| n < self.max_bit_state_len) => Engine::Backtrack,
            _ => Engine::Pike,
        }
    }

    /// Runs the leftmost-match search from `pos` (Go's `doExecute`); with
    /// `anchored`, only a match that begins at `pos` counts. `out` reads the
    /// capture positions while the pooled matcher still holds them.
    fn find_source<R: RuneReader + ?Sized, T>(
        &self,
        src: Source<'_, '_, R>,
        pos: usize,
        ncap: usize,
        anchored: bool,
        out: impl FnOnce(&[isize]) -> T,
    ) -> Option<T> {
        let bytes_len = match &src {
            Source::Bytes(b) => {
                // Every match needs min_input_len bytes from pos and starts
                // with the prefix.
                if ((b.len() - pos) as isize) < self.min_input_len
                    || (anchored && !b[pos..].starts_with(self.prefix.as_bytes()))
                {
                    return None;
                }
                Some(b.len())
            }
            Source::Reader(_) => None,
        };
        let engine = self.engine_for(bytes_len);
        // A one-pass program's prefix is Go's onePassPrefix, the literal after
        // `\A`; the other matchers see the program's own prefix, which is
        // empty for a program anchored at the start of the text.
        let foreign = self.onepass.is_some() && engine != Engine::OnePass;
        let params = Params {
            cond: self.cond,
            prefix: if foreign { b"" } else { self.prefix.as_bytes() },
            prefix_rune: if foreign { 0 } else { self.prefix_rune },
            prefix_end: if foreign { 0 } else { self.prefix_end },
            longest: self.longest,
            anchored,
        };
        self.pool.with(|c| match (engine, src) {
            (Engine::OnePass, src) => {
                let onepass = self
                    .onepass
                    .as_deref()
                    .expect("engine_for chooses OnePass only for one-pass programs");
                let matched = match src {
                    Source::Bytes(b) => {
                        onepass.run(&params, &mut BytesInput(b), pos, ncap, &mut c.onepass)
                    }
                    Source::Reader(r) => onepass.run(
                        &params,
                        &mut ReaderInput {
                            r,
                            at_eot: false,
                            pos: 0,
                        },
                        pos,
                        ncap,
                        &mut c.onepass,
                    ),
                };
                matched.then(|| out(&c.onepass))
            }
            (Engine::Backtrack, Source::Bytes(b)) => c
                .bits
                .run(&self.prog, &params, &mut BytesInput(b), b.len(), pos, ncap)
                .then(|| out(&c.bits.matchcap)),
            (_, src) => {
                let m = c
                    .pike
                    .get_or_insert_with(|| Machine::new(self.prog.inst.len()));
                let matched = match src {
                    Source::Bytes(b) => m.run(&self.prog, &params, &mut BytesInput(b), pos, ncap),
                    Source::Reader(r) => {
                        let mut input = ReaderInput {
                            r,
                            at_eot: false,
                            pos: 0,
                        };
                        m.run(&self.prog, &params, &mut input, pos, ncap)
                    }
                };
                matched.then(|| out(&m.matchcap))
            }
        })
    }

    fn exec_at<T>(
        &self,
        b: &[u8],
        pos: usize,
        ncap: usize,
        out: impl FnOnce(&[isize]) -> T,
    ) -> Option<T> {
        self.find_source::<NoReader, T>(Source::Bytes(b), pos, ncap, false, out)
    }

    fn exec_from<T>(
        &self,
        b: &[u8],
        start: usize,
        ncap: usize,
        anchored: bool,
        out: impl FnOnce(&[isize]) -> T,
    ) -> Option<T> {
        assert!(
            start <= b.len(),
            "regexp: start {start} out of range for text of length {}",
            b.len()
        );
        self.find_source::<NoReader, T>(Source::Bytes(b), start, ncap, anchored, out)
    }

    /// Pads a submatch vector with -1 to `2 * (1 + num_subexp)` entries.
    fn pad(&self, mut a: Vec<isize>) -> Vec<isize> {
        let n = (1 + self.num_subexp) * 2;
        if a.len() < n {
            a.resize(n, -1);
        }
        a
    }

    /// Calls `f` with each successive non-overlapping match (padded when `ncap`
    /// is the full capture count), stopping after `max` matches if `max >= 0`.
    fn matches(&self, b: &[u8], max: isize, ncap: usize, mut f: impl FnMut(Vec<isize>)) {
        if max == 0 {
            return;
        }
        let end = b.len();
        let mut max = max;
        let (mut pos, mut prev_match_end) = (0usize, -1isize);
        while pos <= end {
            let Some(matches) = self.exec_at(b, pos, ncap, <[isize]>::to_vec) else {
                break;
            };

            let mut accept = true;
            if matches[1] == pos as isize {
                // We've found an empty match.
                if matches[0] == prev_match_end {
                    // We don't allow an empty match right after a previous match,
                    // so ignore it.
                    accept = false;
                }
                // Move up one char.
                let width = if pos < end {
                    crate::unicode::rune::decode_rune(&b[pos..]).1
                } else {
                    0
                };
                if width > 0 {
                    pos += width;
                } else {
                    pos = end + 1;
                }
            } else {
                pos = matches[1] as usize;
            }
            prev_match_end = matches[1];

            if accept {
                f(self.pad(matches));
                if max > 0 {
                    max -= 1;
                    if max == 0 {
                        return;
                    }
                }
            }
        }
    }

    /// Reports whether the byte slice contains any match of the regexp.
    pub fn match_bytes(&self, b: &[u8]) -> bool {
        self.exec_at(b, 0, 0, |_| ()).is_some()
    }

    /// Reports whether the string contains any match of the regexp.
    pub fn match_string(&self, s: &str) -> bool {
        self.match_bytes(s.as_bytes())
    }

    /// Reports whether the runes returned by the reader contain any match of
    /// the regexp.
    pub fn match_reader<R: RuneReader + ?Sized>(&self, r: &mut R) -> bool {
        self.find_source(Source::Reader(r), 0, 0, false, |_| ())
            .is_some()
    }

    /// Returns the leftmost match in `b`.
    pub fn find<'a>(&self, b: &'a [u8]) -> Option<&'a [u8]> {
        let (s, e) = self.exec_at(b, 0, 2, span)?;
        Some(&b[s..e])
    }

    /// Returns the leftmost match in `s`.
    pub fn find_string<'a>(&self, s: &'a str) -> Option<&'a str> {
        let (start, end) = self.exec_at(s.as_bytes(), 0, 2, span)?;
        Some(&s[start..end])
    }

    /// Returns the `(start, end)` byte offsets of the leftmost match in `b`.
    pub fn find_index(&self, b: &[u8]) -> Option<(usize, usize)> {
        self.exec_at(b, 0, 2, span)
    }

    /// Returns the `(start, end)` byte offsets of the leftmost match in `s`.
    pub fn find_string_index(&self, s: &str) -> Option<(usize, usize)> {
        self.find_index(s.as_bytes())
    }

    /// Returns the `(start, end)` offsets of the leftmost match in the text
    /// read from `r`, consuming as much of the reader as the search needs.
    pub fn find_reader_index<R: RuneReader + ?Sized>(&self, r: &mut R) -> Option<(usize, usize)> {
        self.find_source(Source::Reader(r), 0, 2, false, span)
    }

    /// Returns the leftmost match and the matches of its subexpressions; a
    /// group that did not participate is `None`.
    pub fn find_submatch<'a>(&self, b: &'a [u8]) -> Option<Vec<Option<&'a [u8]>>> {
        let m = self.exec_at(b, 0, self.prog.num_cap, <[isize]>::to_vec)?;
        Some(
            (0..=self.num_subexp)
                .map(|i| {
                    (2 * i < m.len() && m[2 * i] >= 0)
                        .then(|| &b[m[2 * i] as usize..m[2 * i + 1] as usize])
                })
                .collect(),
        )
    }

    /// Like [`find_submatch`](Regexp::find_submatch) for strings.
    pub fn find_string_submatch<'a>(&self, s: &'a str) -> Option<Vec<Option<&'a str>>> {
        let m = self.exec_at(s.as_bytes(), 0, self.prog.num_cap, <[isize]>::to_vec)?;
        Some(
            (0..=self.num_subexp)
                .map(|i| {
                    (2 * i < m.len() && m[2 * i] >= 0)
                        .then(|| &s[m[2 * i] as usize..m[2 * i + 1] as usize])
                })
                .collect(),
        )
    }

    /// Returns the byte offsets of the leftmost match and its subexpressions
    /// as pairs `[start0, end0, start1, end1, ...]`; -1 marks a group that did
    /// not participate.
    pub fn find_submatch_index(&self, b: &[u8]) -> Option<Vec<isize>> {
        self.exec_at(b, 0, self.prog.num_cap, <[isize]>::to_vec)
            .map(|a| self.pad(a))
    }

    /// Like [`find_submatch_index`](Regexp::find_submatch_index) for strings.
    pub fn find_string_submatch_index(&self, s: &str) -> Option<Vec<isize>> {
        self.find_submatch_index(s.as_bytes())
    }

    /// Like [`find_submatch_index`](Regexp::find_submatch_index) for text read
    /// from `r`.
    pub fn find_reader_submatch_index<R: RuneReader + ?Sized>(
        &self,
        r: &mut R,
    ) -> Option<Vec<isize>> {
        self.find_source(
            Source::Reader(r),
            0,
            self.prog.num_cap,
            false,
            <[isize]>::to_vec,
        )
        .map(|a| self.pad(a))
    }

    // ---- searching from an offset ----

    /// Returns the `(start, end)` offsets in `b` of the leftmost match that
    /// begins at or after `start`.
    ///
    /// Unlike `find_index(&b[start..])`, the text before `start` stays
    /// context and the offsets are into `b`: `^`, `\b` and `\B` look at the
    /// rune before `start`, and `\A` matches only at offset 0. This is the
    /// search Go's `FindAll` methods run from each position. `start` may fall
    /// inside a UTF-8 sequence; the bytes there match as U+FFFD, as anywhere.
    ///
    /// # Panics
    ///
    /// If `start > b.len()`, like slicing.
    ///
    /// ```
    /// use rust_stdlib::regexp::compile;
    /// let re = compile(r"\bfoo")?;
    /// assert_eq!(re.find_index_at(b"foo xfoo foo", 1), Some((9, 12)));
    /// assert_eq!(re.find_index(&b"foo xfoo foo"[5..]), Some((0, 3)));
    /// # Ok::<(), rust_stdlib::regexp::syntax::Error>(())
    /// ```
    pub fn find_index_at(&self, b: &[u8], start: usize) -> Option<(usize, usize)> {
        self.exec_from(b, start, 2, false, span)
    }

    /// Like [`find_index_at`](Regexp::find_index_at) but returns the
    /// submatch offsets laid out as by
    /// [`find_submatch_index`](Regexp::find_submatch_index).
    ///
    /// # Panics
    ///
    /// If `start > b.len()`.
    pub fn find_submatch_index_at(&self, b: &[u8], start: usize) -> Option<Vec<isize>> {
        self.exec_from(b, start, self.prog.num_cap, false, <[isize]>::to_vec)
            .map(|a| self.pad(a))
    }

    /// Returns the `(start, end)` offsets of the match that begins exactly at
    /// `start`, the one [`find_index_at`](Regexp::find_index_at) returns when
    /// its leftmost match begins there, and `None` otherwise. Context is as
    /// for `find_index_at`. A tokenizer tries its patterns in turn at the
    /// current offset; the search stops as soon as no match can begin at
    /// `start`, so it costs time in the length of the match, not the text.
    ///
    /// # Panics
    ///
    /// If `start > b.len()`.
    ///
    /// ```
    /// use rust_stdlib::regexp::compile;
    /// let ident = compile(r"[A-Za-z_]\w*")?;
    /// let src = b"let x1 = y;";
    /// assert_eq!(ident.find_anchored_index_at(src, 4), Some((4, 6)));
    /// assert_eq!(ident.find_anchored_index_at(src, 6), None);
    /// # Ok::<(), rust_stdlib::regexp::syntax::Error>(())
    /// ```
    pub fn find_anchored_index_at(&self, b: &[u8], start: usize) -> Option<(usize, usize)> {
        self.exec_from(b, start, 2, true, span)
    }

    /// Like [`find_anchored_index_at`](Regexp::find_anchored_index_at) but
    /// returns the submatch offsets laid out as by
    /// [`find_submatch_index`](Regexp::find_submatch_index).
    ///
    /// # Panics
    ///
    /// If `start > b.len()`.
    pub fn find_anchored_submatch_index_at(&self, b: &[u8], start: usize) -> Option<Vec<isize>> {
        self.exec_from(b, start, self.prog.num_cap, true, <[isize]>::to_vec)
            .map(|a| self.pad(a))
    }

    /// Returns all successive matches in `b`, at most `n` of them if `n >= 0`
    /// (none if `n == 0`).
    pub fn find_all<'a>(&self, b: &'a [u8], n: isize) -> Vec<&'a [u8]> {
        let mut out = Vec::new();
        self.matches(b, n, 2, |m| out.push(&b[m[0] as usize..m[1] as usize]));
        out
    }

    /// Like [`find_all`](Regexp::find_all) for strings.
    pub fn find_all_string<'a>(&self, s: &'a str, n: isize) -> Vec<&'a str> {
        let mut out = Vec::new();
        self.matches(s.as_bytes(), n, 2, |m| {
            out.push(&s[m[0] as usize..m[1] as usize])
        });
        out
    }

    /// Returns the `(start, end)` offsets of all successive matches in `b`.
    pub fn find_all_index(&self, b: &[u8], n: isize) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        self.matches(b, n, 2, |m| out.push((m[0] as usize, m[1] as usize)));
        out
    }

    /// Like [`find_all_index`](Regexp::find_all_index) for strings.
    pub fn find_all_string_index(&self, s: &str, n: isize) -> Vec<(usize, usize)> {
        self.find_all_index(s.as_bytes(), n)
    }

    /// Returns all successive matches in `b` with their subexpressions.
    pub fn find_all_submatch<'a>(&self, b: &'a [u8], n: isize) -> Vec<Vec<Option<&'a [u8]>>> {
        let mut out = Vec::new();
        self.matches(b, n, self.prog.num_cap, |m| {
            out.push(
                (0..m.len() / 2)
                    .map(|i| (m[2 * i] >= 0).then(|| &b[m[2 * i] as usize..m[2 * i + 1] as usize]))
                    .collect(),
            )
        });
        out
    }

    /// Like [`find_all_submatch`](Regexp::find_all_submatch) for strings.
    pub fn find_all_string_submatch<'a>(&self, s: &'a str, n: isize) -> Vec<Vec<Option<&'a str>>> {
        let mut out = Vec::new();
        self.matches(s.as_bytes(), n, self.prog.num_cap, |m| {
            out.push(
                (0..m.len() / 2)
                    .map(|i| (m[2 * i] >= 0).then(|| &s[m[2 * i] as usize..m[2 * i + 1] as usize]))
                    .collect(),
            )
        });
        out
    }

    /// Returns the submatch index vectors of all successive matches in `b`.
    pub fn find_all_submatch_index(&self, b: &[u8], n: isize) -> Vec<Vec<isize>> {
        let mut out = Vec::new();
        self.matches(b, n, self.prog.num_cap, |m| out.push(m));
        out
    }

    /// Like [`find_all_submatch_index`](Regexp::find_all_submatch_index) for
    /// strings.
    pub fn find_all_string_submatch_index(&self, s: &str, n: isize) -> Vec<Vec<isize>> {
        self.find_all_submatch_index(s.as_bytes(), n)
    }

    // ---- replacing ----

    /// Replaces every match in `src` by what `repl` appends; `nmatch` is how
    /// many capture slots `repl` needs.
    fn replace_all_with(
        &self,
        src: &[u8],
        nmatch: usize,
        mut repl: impl FnMut(&mut Vec<u8>, &[isize]),
    ) -> Vec<u8> {
        let mut last_match_end = 0; // end position of the most recent match
        let mut search_pos = 0; // position where we next look for a match
        let mut buf = Vec::new();
        let end_pos = src.len();
        let nmatch = nmatch.min(self.prog.num_cap);

        while search_pos <= end_pos {
            let Some(a) = self.exec_at(src, search_pos, nmatch, <[isize]>::to_vec) else {
                break; // no more matches
            };

            // Copy the unmatched characters before this match.
            buf.extend_from_slice(&src[last_match_end..a[0] as usize]);

            // Now insert a copy of the replacement string, but not for a
            // match of the empty string immediately after another match.
            // (Otherwise, we get double replacement for patterns that
            // match both empty and nonempty strings.)
            if a[1] as usize > last_match_end || a[0] == 0 {
                repl(&mut buf, &a);
            }
            last_match_end = a[1] as usize;

            // Advance past this match; always advance at least one character.
            let width = if search_pos < end_pos {
                crate::unicode::rune::decode_rune(&src[search_pos..]).1
            } else {
                0
            };
            if search_pos + width > a[1] as usize {
                search_pos += width;
            } else if search_pos + 1 > a[1] as usize {
                // This clause is only needed at the end of the input
                // string. In that case, DecodeRuneInString returns width=0.
                search_pos += 1;
            } else {
                search_pos = a[1] as usize;
            }
        }

        // Copy the unmatched characters after the last match.
        buf.extend_from_slice(&src[last_match_end..]);
        buf
    }

    /// Returns a copy of `src`, replacing matches of the regexp with the
    /// replacement text `repl`. Inside `repl`, `$` signs are interpreted as in
    /// [`expand`](Regexp::expand), so for instance `$1` represents the text of
    /// the first submatch.
    pub fn replace_all(&self, src: &[u8], repl: &[u8]) -> Vec<u8> {
        let n = if repl.contains(&b'$') {
            2 * (self.num_subexp + 1)
        } else {
            2
        };
        self.replace_all_with(src, n, |dst, m| self.expand_bytes(dst, repl, src, m))
    }

    /// Like [`replace_all`](Regexp::replace_all) for strings.
    pub fn replace_all_string(&self, src: &str, repl: &str) -> String {
        let n = if repl.contains('$') {
            2 * (self.num_subexp + 1)
        } else {
            2
        };
        let b = self.replace_all_with(src.as_bytes(), n, |dst, m| {
            self.expand_bytes(dst, repl.as_bytes(), src.as_bytes(), m)
        });
        bytes_to_string(b)
    }

    /// Returns a copy of `src`, replacing matches with `repl` without
    /// expanding `$`.
    pub fn replace_all_literal(&self, src: &[u8], repl: &[u8]) -> Vec<u8> {
        self.replace_all_with(src, 2, |dst, _| dst.extend_from_slice(repl))
    }

    /// Like [`replace_all_literal`](Regexp::replace_all_literal) for strings.
    pub fn replace_all_literal_string(&self, src: &str, repl: &str) -> String {
        bytes_to_string(self.replace_all_with(src.as_bytes(), 2, |dst, _| {
            dst.extend_from_slice(repl.as_bytes())
        }))
    }

    /// Returns a copy of `src` in which all matches have been replaced by the
    /// return value of `repl` applied to the matched slice. The replacement is
    /// substituted directly, without using [`expand`](Regexp::expand).
    pub fn replace_all_func(&self, src: &[u8], mut repl: impl FnMut(&[u8]) -> Vec<u8>) -> Vec<u8> {
        self.replace_all_with(src, 2, |dst, m| {
            dst.extend_from_slice(&repl(&src[m[0] as usize..m[1] as usize]))
        })
    }

    /// Like [`replace_all_func`](Regexp::replace_all_func) for strings.
    pub fn replace_all_string_func(
        &self,
        src: &str,
        mut repl: impl FnMut(&str) -> String,
    ) -> String {
        bytes_to_string(self.replace_all_with(src.as_bytes(), 2, |dst, m| {
            dst.extend_from_slice(repl(&src[m[0] as usize..m[1] as usize]).as_bytes())
        }))
    }

    /// Appends `template` to `dst` with variables replaced by the submatches
    /// of `src` described by `match_` (as returned by
    /// [`find_submatch_index`](Regexp::find_submatch_index)).
    ///
    /// In the template, a variable is denoted by a substring of the form
    /// `$name` or `${name}`, where name is a non-empty sequence of letters,
    /// digits, and underscores. A purely numeric name like `$1` refers to the
    /// submatch with the corresponding index; other names refer to capturing
    /// parentheses named with the `(?P<name>...)` syntax. A reference to an
    /// out of range or unmatched index or a name that is not present in the
    /// regular expression is replaced with an empty slice.
    ///
    /// In the `$name` form, name is taken to be as long as possible: `$1x` is
    /// equivalent to `${1x}`, not `${1}x`, and `$10` is equivalent to `${10}`,
    /// not `${1}0`. To insert a literal `$` in the output, use `$$`.
    pub fn expand(&self, dst: &mut Vec<u8>, template: &[u8], src: &[u8], match_: &[isize]) {
        self.expand_bytes(dst, template, src, match_)
    }

    /// Like [`expand`](Regexp::expand) but the template and source are
    /// strings.
    pub fn expand_string(&self, dst: &mut Vec<u8>, template: &str, src: &str, match_: &[isize]) {
        self.expand_bytes(dst, template.as_bytes(), src.as_bytes(), match_)
    }

    fn expand_bytes(&self, dst: &mut Vec<u8>, mut template: &[u8], src: &[u8], m: &[isize]) {
        while !template.is_empty() {
            let Some(i) = template.iter().position(|&b| b == b'$') else {
                break;
            };
            dst.extend_from_slice(&template[..i]);
            template = &template[i + 1..];
            if !template.is_empty() && template[0] == b'$' {
                // Treat $$ as $.
                dst.push(b'$');
                template = &template[1..];
                continue;
            }
            let Some((name, num, rest)) = extract(template) else {
                // Malformed; treat $ as raw text.
                dst.push(b'$');
                continue;
            };
            template = rest;
            if let Some(num) = num {
                // Process as a numbered group.
                if 2 * num + 1 < m.len() && m[2 * num] >= 0 {
                    dst.extend_from_slice(&src[m[2 * num] as usize..m[2 * num + 1] as usize]);
                }
            } else {
                // Process as a named group.
                for (i, namei) in self.subexp_names.iter().enumerate() {
                    if name == namei.as_bytes() && 2 * i + 1 < m.len() && m[2 * i] >= 0 {
                        dst.extend_from_slice(&src[m[2 * i] as usize..m[2 * i + 1] as usize]);
                        break;
                    }
                }
            }
        }
        dst.extend_from_slice(template);
    }

    /// Slices `s` into substrings separated by matches of the regexp and
    /// returns the substrings between those matches.
    ///
    /// The count determines the number of substrings to return: `n > 0` at
    /// most `n` substrings (the last is the unsplit remainder); `n == 0` the
    /// result is empty; `n < 0` all substrings.
    pub fn split<'a>(&self, s: &'a str, n: isize) -> Vec<&'a str> {
        if n == 0 {
            return Vec::new();
        }
        if !self.expr.is_empty() && s.is_empty() {
            return vec![""];
        }

        let matches = self.find_all_string_index(s, n);
        let mut strings = Vec::with_capacity(matches.len());

        let (mut beg, mut end) = (0, 0);
        for (m0, m1) in matches {
            if n > 0 && strings.len() as isize >= n - 1 {
                break;
            }
            end = m0;
            if m1 != 0 {
                strings.push(&s[beg..end]);
            }
            beg = m1;
        }

        if end != s.len() {
            strings.push(&s[beg..]);
        }
        strings
    }
}

/// The fewest bytes a match of `re` spans (Go `minInputLen`).
fn min_input_len(re: &syntax::Regexp) -> isize {
    use syntax::Op;
    match re.op {
        Op::ANY_CHAR | Op::ANY_CHAR_NOT_NL | Op::CHAR_CLASS => 1,
        Op::LITERAL => re
            .rune
            .iter()
            .map(|&r| {
                if r == crate::unicode::rune::RUNE_ERROR {
                    1
                } else {
                    crate::unicode::rune::rune_len(r)
                }
            })
            .sum(),
        Op::CAPTURE | Op::PLUS => min_input_len(&re.sub[0]),
        Op::REPEAT => re.min * min_input_len(&re.sub[0]),
        Op::CONCAT => re.sub.iter().map(|s| min_input_len(s)).sum(),
        Op::ALTERNATE => re.sub.iter().map(|s| min_input_len(s)).min().unwrap_or(0),
        _ => 0,
    }
}

fn bytes_to_string(b: Vec<u8>) -> String {
    String::from_utf8(b).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// Parses a `$` reference at the start of `s` (the text after the `$`):
/// returns the name, its number if all digits, and the rest of the text.
fn extract(mut s: &[u8]) -> Option<(&[u8], Option<usize>, &[u8])> {
    if s.is_empty() {
        return None;
    }
    let mut brace = false;
    if s[0] == b'{' {
        brace = true;
        s = &s[1..];
    }
    let mut i = 0;
    while i < s.len() {
        let (r, size) = crate::unicode::rune::decode_rune(&s[i..]);
        if !crate::unicode::is_letter(r) && !crate::unicode::is_digit(r) && r != '_' as i32 {
            break;
        }
        i += size;
    }
    if i == 0 {
        // empty name is not okay
        return None;
    }
    let name = &s[..i];
    if brace {
        if i >= s.len() || s[i] != b'}' {
            // missing closing brace
            return None;
        }
        i += 1;
    }

    // Parse number.
    let mut num = Some(0usize);
    for &d in name {
        if !d.is_ascii_digit() || num.is_some_and(|n| n >= 100_000_000) {
            num = None;
            break;
        }
        num = num.map(|n| n * 10 + usize::from(d - b'0'));
    }
    if name[0] == b'0' && name.len() > 1 {
        // Disallow leading zeros.
        num = None;
    }

    Some((name, num, &s[i..]))
}
