//! Regular expression parser (Go `regexp/syntax/parse.go`).
//!
//! The parser keeps its nodes in an arena and refers to them by index, which
//! plays the role of Go's pointer identity (the parser mutates nodes in place
//! and keys its limit caches by node). Go recycles freed nodes; the arena never
//! does, but `free` counts them so that `num_regexp`, which triggers the size
//! and height checks, evolves exactly as in Go.
#![allow(
    clippy::int_plus_one,
    clippy::needless_range_loop,
    clippy::manual_range_contains
)]
use super::perl_groups::{perl_group, posix_group, CharGroup};
use super::{Error, ErrorCode, Flags, Op, Regexp};
use crate::unicode::{self, rune::decode_rune, RangeTable};
use std::{collections::HashMap, sync::Arc};

type R<T> = Result<T, Error>;

const OP_LEFT_PAREN: Op = Op(128);
const OP_VERTICAL_BAR: Op = Op(129);

/// Maximum nesting depth of a compiled regexp.
const MAX_HEIGHT: usize = 1000;
/// Maximum compiled size, in instructions, Go's `128 << 20 / instSize`.
const MAX_SIZE: i64 = (128 << 20) / (5 * 8);
/// Maximum number of runes in character classes.
const MAX_RUNES: i64 = (128 << 20) / 4;

const MIN_FOLD: i32 = 0x0041;
const MAX_FOLD: i32 = 0x1e943;
const MAX_RUNE: i32 = unicode::MAX_RUNE;

#[derive(Clone, Default)]
struct Node {
    op: Op,
    flags: Flags,
    sub: Vec<usize>,
    rune: Vec<i32>,
    min: isize,
    max: isize,
    cap: isize,
    name: String,
}

struct Parser<'a> {
    flags: Flags,
    stack: Vec<usize>,
    nodes: Vec<Node>,
    free: usize,
    num_cap: isize,
    whole: &'a [u8],
    tmp_class: Vec<i32>,
    num_regexp: usize,
    num_runes: i64,
    repeats: i64,
    height: Option<HashMap<usize, usize>>,
    size: Option<HashMap<usize, i64>>,
}

/// Parses a regular expression string into a syntax tree.
pub fn parse(s: &str, flags: Flags) -> R<Regexp> {
    parse_bytes(s.as_bytes(), flags)
}

/// Like [`parse`] for patterns that may not be valid UTF-8; such patterns fail
/// with [`ErrorCode::INVALID_UTF8`] where the offending bytes are reached.
pub fn parse_bytes(s: &[u8], flags: Flags) -> R<Regexp> {
    match parse_inner(s, flags) {
        Err(mut e) if e.code == ErrorCode::LARGE || e.code == ErrorCode::NESTING_DEPTH => {
            e.expr = String::from_utf8_lossy(s).into_owned();
            Err(e)
        }
        other => other,
    }
}

fn slice_before<'a>(before: &'a [u8], after: &[u8]) -> &'a [u8] {
    &before[..before.len() - after.len()]
}

fn parse_inner(s: &[u8], flags: Flags) -> R<Regexp> {
    if flags.contains(Flags::LITERAL) {
        // Trivial parser for literal string.
        check_utf8(s)?;
        return Ok(literal_regexp(s, flags));
    }

    let mut p = Parser {
        flags,
        stack: Vec::new(),
        nodes: Vec::new(),
        free: 0,
        num_cap: 0,
        whole: s,
        tmp_class: Vec::new(),
        num_regexp: 0,
        num_runes: 0,
        repeats: 0,
        height: None,
        size: None,
    };
    let mut t = s;
    let mut last_repeat: &[u8] = b"";
    while !t.is_empty() {
        let mut repeat: &[u8] = b"";
        match t[0] {
            b'(' => {
                if p.flags.contains(Flags::PERL_X) && t.len() >= 2 && t[1] == b'?' {
                    // Flag changes and non-capturing groups.
                    t = p.parse_perl_flags(t)?;
                } else {
                    p.num_cap += 1;
                    let re = p.op_node(OP_LEFT_PAREN)?;
                    p.nodes[re].cap = p.num_cap;
                    t = &t[1..];
                }
            }
            b'|' => {
                p.parse_vertical_bar()?;
                t = &t[1..];
            }
            b')' => {
                p.parse_right_paren()?;
                t = &t[1..];
            }
            b'^' => {
                if p.flags.contains(Flags::ONE_LINE) {
                    p.op(Op::BEGIN_TEXT)?;
                } else {
                    p.op(Op::BEGIN_LINE)?;
                }
                t = &t[1..];
            }
            b'$' => {
                if p.flags.contains(Flags::ONE_LINE) {
                    let re = p.op_node(Op::END_TEXT)?;
                    p.nodes[re].flags |= Flags::WAS_DOLLAR;
                } else {
                    p.op(Op::END_LINE)?;
                }
                t = &t[1..];
            }
            b'.' => {
                if p.flags.contains(Flags::DOT_NL) {
                    p.op(Op::ANY_CHAR)?;
                } else {
                    p.op(Op::ANY_CHAR_NOT_NL)?;
                }
                t = &t[1..];
            }
            b'[' => t = p.parse_class(t)?,
            b'*' | b'+' | b'?' => {
                let before = t;
                let op = match t[0] {
                    b'*' => Op::STAR,
                    b'+' => Op::PLUS,
                    _ => Op::QUEST,
                };
                let after = p.repeat(op, 0, 0, before, &t[1..], last_repeat)?;
                repeat = before;
                t = after;
            }
            b'{' => {
                let before = t;
                match p.parse_repeat(t) {
                    None => {
                        // If the repeat cannot be parsed, { is a literal.
                        p.literal('{' as i32)?;
                        t = &t[1..];
                    }
                    Some((min, max, after)) => {
                        if min < 0 || min > 1000 || max > 1000 || max >= 0 && min > max {
                            // Numbers were too big, or max is present and min > max.
                            return Err(Error::new(
                                ErrorCode::INVALID_REPEAT_SIZE,
                                slice_before(before, after),
                            ));
                        }
                        let after = p.repeat(Op::REPEAT, min, max, before, after, last_repeat)?;
                        repeat = before;
                        t = after;
                    }
                }
            }
            b'\\' => {
                if p.flags.contains(Flags::PERL_X) && t.len() >= 2 {
                    let simple = match t[1] {
                        b'A' => Some(Op::BEGIN_TEXT),
                        b'b' => Some(Op::WORD_BOUNDARY),
                        b'B' => Some(Op::NO_WORD_BOUNDARY),
                        b'z' => Some(Op::END_TEXT),
                        _ => None,
                    };
                    if let Some(op) = simple {
                        p.op(op)?;
                        t = &t[2..];
                        last_repeat = repeat;
                        continue;
                    }
                    match t[1] {
                        b'C' => {
                            // \C: any byte [sic]
                            return Err(Error::new(ErrorCode::INVALID_ESCAPE, &t[..2]));
                        }
                        b'Q' => {
                            // \Q ... \E: the ... is all literals
                            let rest = &t[2..];
                            let (lit, after) = match find_sub(rest, b"\\E") {
                                Some(i) => (&rest[..i], &rest[i + 2..]),
                                None => (rest, &rest[rest.len()..]),
                            };
                            t = after;
                            let mut lit = lit;
                            while !lit.is_empty() {
                                let (c, r) = next_rune(lit)?;
                                p.literal(c)?;
                                lit = r;
                            }
                            last_repeat = repeat;
                            continue;
                        }
                        _ => {}
                    }
                }

                let re = p.new_regexp(Op::CHAR_CLASS);
                p.nodes[re].flags = p.flags;

                // Look for Unicode character group like \p{Han}
                if t.len() >= 2 && (t[1] == b'p' || t[1] == b'P') {
                    let mut class = Vec::new();
                    if let Some(rest) = p.parse_unicode_class(t, &mut class)? {
                        p.nodes[re].rune = class;
                        t = rest;
                        p.push(re)?;
                        last_repeat = repeat;
                        continue;
                    }
                }

                // Perl character class escape.
                let mut class = Vec::new();
                if let Some(rest) = p.parse_perl_class_escape(t, &mut class) {
                    p.nodes[re].rune = class;
                    t = rest;
                    p.push(re)?;
                    last_repeat = repeat;
                    continue;
                }
                p.reuse(re);

                // Ordinary single-character escape.
                let (c, rest) = p.parse_escape(t)?;
                t = rest;
                p.literal(c)?;
            }
            _ => {
                let (c, rest) = next_rune(t)?;
                t = rest;
                p.literal(c)?;
            }
        }
        last_repeat = repeat;
    }

    p.concat()?;
    if p.swap_vertical_bar() {
        // pop vertical bar
        p.stack.pop();
    }
    p.alternate()?;

    if p.stack.len() != 1 {
        return Err(Error::new(ErrorCode::MISSING_PAREN, s));
    }
    Ok(p.to_regexp(p.stack[0]))
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Returns a literal regexp for the string `s`.
fn literal_regexp(s: &[u8], flags: Flags) -> Regexp {
    let mut re = Regexp::with_op(Op::LITERAL);
    re.flags = flags;
    let mut rest = s;
    while !rest.is_empty() {
        let (c, size) = decode_rune(rest);
        re.rune.push(c);
        rest = &rest[size..];
    }
    re
}

impl<'a> Parser<'a> {
    /// Converts the arena subtree at `root` into a [`Regexp`], children first
    /// and without recursion so that deeply nested patterns cannot exhaust the
    /// stack.
    fn to_regexp(&self, root: usize) -> Regexp {
        let mut done: HashMap<usize, Arc<Regexp>> = HashMap::new();
        let mut stack = vec![(root, false)];
        while let Some((idx, ready)) = stack.pop() {
            let n = &self.nodes[idx];
            if !ready {
                stack.push((idx, true));
                stack.extend(n.sub.iter().map(|&s| (s, false)));
                continue;
            }
            let sub = n
                .sub
                .iter()
                .map(|s| done.remove(s).unwrap_or_default())
                .collect();
            done.insert(
                idx,
                Arc::new(Regexp {
                    op: n.op,
                    flags: n.flags,
                    sub,
                    rune: n.rune.clone(),
                    min: n.min,
                    max: n.max,
                    cap: n.cap,
                    name: n.name.clone(),
                }),
            );
        }
        let top = done.remove(&root).unwrap_or_default();
        Arc::try_unwrap(top).unwrap_or_else(|a| (*a).clone())
    }

    fn new_regexp(&mut self, op: Op) -> usize {
        if self.free > 0 {
            self.free -= 1;
        } else {
            self.num_regexp += 1;
        }
        self.nodes.push(Node {
            op,
            ..Node::default()
        });
        self.nodes.len() - 1
    }

    fn reuse(&mut self, re: usize) {
        if let Some(h) = self.height.as_mut() {
            h.remove(&re);
        }
        self.free += 1;
    }

    fn check_limits(&mut self, re: usize) -> R<()> {
        if self.num_runes > MAX_RUNES {
            return Err(Error::new(ErrorCode::LARGE, b""));
        }
        self.check_size(re)?;
        self.check_height(re)
    }

    fn check_size(&mut self, re: usize) -> R<()> {
        if self.size.is_none() {
            // We haven't started tracking size yet. Do a relatively cheap check
            // to see if we need to start. Maintain the product of all the repeats
            // we've seen and don't track if the total number of regexp nodes we've
            // seen times the repeat product is in budget.
            if self.repeats == 0 {
                self.repeats = 1;
            }
            if self.nodes[re].op == Op::REPEAT {
                let mut n = self.nodes[re].max;
                if n == -1 {
                    n = self.nodes[re].min;
                }
                if n <= 0 {
                    n = 1;
                }
                if n as i64 > MAX_SIZE / self.repeats {
                    self.repeats = MAX_SIZE;
                } else {
                    self.repeats *= n as i64;
                }
            }
            if (self.num_regexp as i64) < MAX_SIZE / self.repeats {
                return Ok(());
            }

            // We need to start tracking size. Make the map and count the nodes
            // already on the stack.
            self.size = Some(HashMap::new());
            for re in self.stack.clone() {
                self.check_size(re)?;
            }
        }

        if self.calc_size(re, true) > MAX_SIZE {
            return Err(Error::new(ErrorCode::LARGE, b""));
        }
        Ok(())
    }

    fn calc_size(&mut self, re: usize, force: bool) -> i64 {
        if !force {
            if let Some(&size) = self.size.as_ref().and_then(|m| m.get(&re)) {
                return size;
            }
        }
        let n = self.nodes[re].clone();
        let mut size: i64 = 0;
        match n.op {
            Op::LITERAL => size = n.rune.len() as i64,
            Op::CAPTURE | Op::STAR => {
                // star can be 1+ or (1+)?
                size = 2 + self.calc_size(n.sub[0], false);
            }
            Op::PLUS | Op::QUEST => size = 1 + self.calc_size(n.sub[0], false),
            Op::CONCAT => {
                for &sub in &n.sub {
                    size += self.calc_size(sub, false);
                }
            }
            Op::ALTERNATE => {
                for &sub in &n.sub {
                    size += self.calc_size(sub, false);
                }
                if n.sub.len() > 1 {
                    size += n.sub.len() as i64 - 1;
                }
            }
            Op::REPEAT => {
                let sub = self.calc_size(n.sub[0], false);
                if n.max == -1 {
                    if n.min == 0 {
                        size = 2 + sub; // x*
                    } else {
                        size = 1 + n.min as i64 * sub; // xxx+
                    }
                } else {
                    // x{2,5} = xx(x(x(x)?)?)?
                    size = n.max as i64 * sub + (n.max - n.min) as i64;
                }
            }
            _ => {}
        }
        size = size.max(1);
        if let Some(m) = self.size.as_mut() {
            m.insert(re, size);
        }
        size
    }

    fn check_height(&mut self, re: usize) -> R<()> {
        if self.num_regexp < MAX_HEIGHT {
            return Ok(());
        }
        if self.height.is_none() {
            self.height = Some(HashMap::new());
            for re in self.stack.clone() {
                self.check_height(re)?;
            }
        }
        if self.calc_height(re, true) > MAX_HEIGHT {
            return Err(Error::new(ErrorCode::NESTING_DEPTH, b""));
        }
        Ok(())
    }

    fn calc_height(&mut self, re: usize, force: bool) -> usize {
        if !force {
            if let Some(&h) = self.height.as_ref().and_then(|m| m.get(&re)) {
                return h;
            }
        }
        let mut h = 1;
        for sub in self.nodes[re].sub.clone() {
            let hsub = self.calc_height(sub, false);
            if h < 1 + hsub {
                h = 1 + hsub;
            }
        }
        if let Some(m) = self.height.as_mut() {
            m.insert(re, h);
        }
        h
    }

    /// Pushes the regexp onto the parse stack and returns it, or `None` when
    /// it was folded into the literal below it.
    fn push(&mut self, re: usize) -> R<Option<usize>> {
        self.num_runes += self.nodes[re].rune.len() as i64;
        let n = &self.nodes[re];
        let fold_pair = n.op == Op::CHAR_CLASS
            && n.rune.len() == 4
            && n.rune[0] == n.rune[1]
            && n.rune[2] == n.rune[3]
            && unicode::simple_fold(n.rune[0]) == n.rune[2]
            && unicode::simple_fold(n.rune[2]) == n.rune[0]
            || n.op == Op::CHAR_CLASS
                && n.rune.len() == 2
                && n.rune[0] + 1 == n.rune[1]
                && unicode::simple_fold(n.rune[0]) == n.rune[1]
                && unicode::simple_fold(n.rune[1]) == n.rune[0];
        if n.op == Op::CHAR_CLASS && n.rune.len() == 2 && n.rune[0] == n.rune[1] {
            // Single rune.
            let r = n.rune[0];
            if self.maybe_concat(r, self.flags & !Flags::FOLD_CASE) {
                return Ok(None);
            }
            let flags = self.flags & !Flags::FOLD_CASE;
            let n = &mut self.nodes[re];
            n.op = Op::LITERAL;
            n.rune.truncate(1);
            n.flags = flags;
        } else if fold_pair {
            // Case-insensitive rune like [Aa] or [Δδ].
            let r = n.rune[0];
            if self.maybe_concat(r, self.flags | Flags::FOLD_CASE) {
                return Ok(None);
            }
            // Rewrite as (case-insensitive) literal.
            let flags = self.flags | Flags::FOLD_CASE;
            let n = &mut self.nodes[re];
            n.op = Op::LITERAL;
            n.rune.truncate(1);
            n.flags = flags;
        } else {
            // Incremental concatenation.
            self.maybe_concat(-1, Flags(0));
        }

        self.stack.push(re);
        self.check_limits(re)?;
        Ok(Some(re))
    }

    /// If the top two elements on the stack are both literal or string
    /// literals, merges them into one. If `r >= 0`, the top element is then
    /// reused to hold `r` with `flags`, and true is returned (the caller must
    /// not push anything).
    fn maybe_concat(&mut self, r: i32, flags: Flags) -> bool {
        let n = self.stack.len();
        if n < 2 {
            return false;
        }
        let re1 = self.stack[n - 1];
        let re2 = self.stack[n - 2];
        if self.nodes[re1].op != Op::LITERAL
            || self.nodes[re2].op != Op::LITERAL
            || self.nodes[re1].flags & Flags::FOLD_CASE != self.nodes[re2].flags & Flags::FOLD_CASE
        {
            return false;
        }

        // Push re1 into re2.
        let runes = std::mem::take(&mut self.nodes[re1].rune);
        self.nodes[re2].rune.extend_from_slice(&runes);

        // Reuse re1 if possible.
        if r >= 0 {
            let n1 = &mut self.nodes[re1];
            n1.rune = vec![r];
            n1.flags = flags;
            return true;
        }

        self.stack.pop();
        self.reuse(re1);
        false // did not push r
    }

    fn literal(&mut self, mut r: i32) -> R<()> {
        let re = self.new_regexp(Op::LITERAL);
        self.nodes[re].flags = self.flags;
        if self.flags.contains(Flags::FOLD_CASE) {
            r = min_fold_rune(r);
        }
        self.nodes[re].rune = vec![r];
        self.push(re)?;
        Ok(())
    }

    /// Pushes a new node for a zero-width or marker operator.
    fn op(&mut self, op: Op) -> R<Option<usize>> {
        let re = self.new_regexp(op);
        self.nodes[re].flags = self.flags;
        self.push(re)
    }

    /// Like [`op`](Parser::op) for operators that are never folded away.
    fn op_node(&mut self, op: Op) -> R<usize> {
        self.op(op)?
            .ok_or_else(|| Error::new(ErrorCode::INTERNAL_ERROR, b""))
    }

    /// Applies a repetition operator to the top of the stack and returns the
    /// rest of the input.
    fn repeat(
        &mut self,
        op: Op,
        min: isize,
        max: isize,
        before: &'a [u8],
        mut after: &'a [u8],
        last_repeat: &'a [u8],
    ) -> R<&'a [u8]> {
        let mut flags = self.flags;
        if self.flags.contains(Flags::PERL_X) {
            if !after.is_empty() && after[0] == b'?' {
                after = &after[1..];
                flags ^= Flags::NON_GREEDY;
            }
            if !last_repeat.is_empty() {
                // In Perl it is not allowed to stack repetition operators:
                //   a** is a syntax error, not a doubled star.
                // (and a++ means something else entirely, which we don't support!)
                return Err(Error::new(
                    ErrorCode::INVALID_REPEAT_OP,
                    slice_before(last_repeat, after),
                ));
            }
        }
        let n = self.stack.len();
        if n == 0 {
            return Err(Error::new(
                ErrorCode::MISSING_REPEAT_ARGUMENT,
                slice_before(before, after),
            ));
        }
        let sub = self.stack[n - 1];
        if self.nodes[sub].op >= Op::PSEUDO {
            return Err(Error::new(
                ErrorCode::MISSING_REPEAT_ARGUMENT,
                slice_before(before, after),
            ));
        }

        let re = self.new_regexp(op);
        {
            let r = &mut self.nodes[re];
            r.min = min;
            r.max = max;
            r.flags = flags;
            r.sub = vec![sub];
        }
        self.stack[n - 1] = re;
        self.check_limits(re)?;

        if op == Op::REPEAT && (min >= 2 || max >= 2) && !self.repeat_is_valid(re, 1000) {
            return Err(Error::new(
                ErrorCode::INVALID_REPEAT_SIZE,
                slice_before(before, after),
            ));
        }
        Ok(after)
    }

    /// Reports whether the repetition `re` is valid. Valid means that the
    /// combination of the top-level repetition and any inner repetitions does
    /// not exceed `n` copies of the innermost thing.
    fn repeat_is_valid(&self, re: usize, mut n: isize) -> bool {
        let node = &self.nodes[re];
        if node.op == Op::REPEAT {
            let mut m = node.max;
            if m == 0 {
                return true;
            }
            if m < 0 {
                m = node.min;
            }
            if m > n {
                return false;
            }
            if m > 0 {
                n /= m;
            }
        }
        node.sub.iter().all(|&sub| self.repeat_is_valid(sub, n))
    }

    /// Collapses the regexps on the stack above the last marker into a
    /// concatenation.
    fn concat(&mut self) -> R<Option<usize>> {
        self.maybe_concat(-1, Flags(0));

        // Scan down to find pseudo-operator | or (.
        let mut i = self.stack.len();
        while i > 0 && self.nodes[self.stack[i - 1]].op < Op::PSEUDO {
            i -= 1;
        }
        let subs = self.stack.split_off(i);

        // Empty concatenation is special case.
        if subs.is_empty() {
            let re = self.new_regexp(Op::EMPTY_MATCH);
            return self.push(re);
        }

        let c = self.collapse(subs, Op::CONCAT)?;
        self.push(c)
    }

    /// Collapses the regexps on the stack above the last marker into an
    /// alternation.
    fn alternate(&mut self) -> R<Option<usize>> {
        // Scan down to find pseudo-operator (.
        // There are no | above (.
        let mut i = self.stack.len();
        while i > 0 && self.nodes[self.stack[i - 1]].op < Op::PSEUDO {
            i -= 1;
        }
        let subs = self.stack.split_off(i);

        // Make sure top class is clean.
        // All the others already are (see swapVerticalBar).
        if let Some(&last) = subs.last() {
            self.clean_alt(last);
        }

        // Empty alternate is special case
        // (shouldn't happen but easy to handle).
        if subs.is_empty() {
            let re = self.new_regexp(Op::NO_MATCH);
            return self.push(re);
        }

        let c = self.collapse(subs, Op::ALTERNATE)?;
        self.push(c)
    }

    /// Cleans the character class and rewrites it as `.` where it matches
    /// everything.
    fn clean_alt(&mut self, re: usize) {
        let n = &mut self.nodes[re];
        if n.op == Op::CHAR_CLASS {
            clean_class(&mut n.rune);
            if n.rune.len() == 2 && n.rune[0] == 0 && n.rune[1] == MAX_RUNE {
                n.rune = Vec::new();
                n.op = Op::ANY_CHAR;
                return;
            }
            if n.rune.len() == 4
                && n.rune[0] == 0
                && n.rune[1] == '\n' as i32 - 1
                && n.rune[2] == '\n' as i32 + 1
                && n.rune[3] == MAX_RUNE
            {
                n.rune = Vec::new();
                n.op = Op::ANY_CHAR_NOT_NL;
            }
        }
    }

    /// Returns the result of collapsing `subs` into a single regexp using `op`
    /// (flattening nested operators of the same kind).
    fn collapse(&mut self, subs: Vec<usize>, op: Op) -> R<usize> {
        if subs.len() == 1 {
            return Ok(subs[0]);
        }
        let re = self.new_regexp(op);
        let mut flat = Vec::new();
        for sub in subs {
            if self.nodes[sub].op == op {
                flat.extend(self.nodes[sub].sub.clone());
                self.reuse(sub);
            } else {
                flat.push(sub);
            }
        }
        if op == Op::ALTERNATE {
            flat = self.factor(flat)?;
            if flat.len() == 1 {
                let only = flat[0];
                self.reuse(re);
                return Ok(only);
            }
        }
        self.nodes[re].sub = flat;
        Ok(re)
    }

    /// Factors common prefixes from the alternation list `sub`: first common
    /// leading literal strings, then common leading regexps (single characters
    /// and repeats of them), then merges adjacent single-character
    /// alternatives into one class, and finally collapses empty matches.
    fn factor(&mut self, mut sub: Vec<usize>) -> R<Vec<usize>> {
        if sub.len() < 2 {
            return Ok(sub);
        }

        // Round 1: Factor out common literal prefixes.
        let mut str: Vec<i32> = Vec::new();
        let mut strflags = Flags(0);
        let mut start = 0;
        let mut out: Vec<usize> = Vec::new();
        let mut i = 0;
        while i <= sub.len() {
            // Invariant: the Regexps that were in sub[0:start] have been
            // used or marked for reuse, and the slice space has been reused
            // for out (len(out) <= start).
            //
            // Invariant: sub[start:i] consists of regexps that all begin with str as modified by strflags.
            let mut istr: Vec<i32> = Vec::new();
            let mut iflags = Flags(0);
            if i < sub.len() {
                (istr, iflags) = self.leading_string(sub[i]);
                if iflags == strflags {
                    let mut same = 0;
                    while same < str.len() && same < istr.len() && str[same] == istr[same] {
                        same += 1;
                    }
                    if same > 0 {
                        // Matches at least one rune in current range.
                        // Keep going around.
                        str.truncate(same);
                        i += 1;
                        continue;
                    }
                }
            }

            // Found end of a run with common leading literal string:
            // sub[start:i] all begin with str[:len(str)], but sub[i]
            // does not even begin with str[0].
            //
            // Factor out common string and append factored expression to out.
            if i == start {
                // Nothing to do - run of length 0.
            } else if i == start + 1 {
                // Just one: don't bother factoring.
                out.push(sub[start]);
            } else {
                // Construct factored form: prefix(suffix1|suffix2|...)
                let prefix = self.new_regexp(Op::LITERAL);
                self.nodes[prefix].flags = strflags;
                self.nodes[prefix].rune = str.clone();

                for j in start..i {
                    sub[j] = self.remove_leading_string(sub[j], str.len());
                    self.check_limits(sub[j])?;
                }
                let suffix = self.collapse(sub[start..i].to_vec(), Op::ALTERNATE)?; // recurse

                let re = self.new_regexp(Op::CONCAT);
                self.nodes[re].sub = vec![prefix, suffix];
                out.push(re);
            }

            // Prepare for next iteration.
            start = i;
            str = istr;
            strflags = iflags;
            i += 1;
        }
        sub = out;

        // Round 2: Factor out common simple prefixes,
        // just the first piece of each concatenation.
        // This will be good enough a lot of the time.
        //
        // Complex subexpressions (e.g. involving quantifiers)
        // are not safe to factor because that collapses their
        // distinct paths through the automaton, which affects
        // correctness in some cases.
        start = 0;
        out = Vec::new();
        let mut first: Option<usize> = None;
        i = 0;
        while i <= sub.len() {
            // Invariant: the Regexps that were in sub[0:start] have been
            // used or marked for reuse, and the slice space has been reused
            // for out (len(out) <= start).
            //
            // Invariant: sub[start:i] consists of regexps that all begin with ifirst.
            let mut ifirst: Option<usize> = None;
            if i < sub.len() {
                ifirst = self.leading_regexp(sub[i]);
                if let (Some(f), Some(g)) = (first, ifirst) {
                    if self.equal(f, g)
                        && (self.is_char_class(f)
                            || (self.nodes[f].op == Op::REPEAT
                                && self.nodes[f].min == self.nodes[f].max
                                && self.is_char_class(self.nodes[f].sub[0])))
                    {
                        i += 1;
                        continue;
                    }
                }
            }

            // Found end of a run with common leading regexp:
            // sub[start:i] all begin with first but sub[i] does not.
            //
            // Factor out common regexp and append factored expression to out.
            if i == start {
                // Nothing to do - run of length 0.
            } else if i == start + 1 {
                // Just one: don't bother factoring.
                out.push(sub[start]);
            } else {
                // Construct factored form: prefix(suffix1|suffix2|...)
                let prefix = first.ok_or_else(|| Error::new(ErrorCode::INTERNAL_ERROR, b""))?;
                for j in start..i {
                    let reuse = j != start; // prefix came from sub[start]
                    sub[j] = self.remove_leading_regexp(sub[j], reuse);
                    self.check_limits(sub[j])?;
                }
                let suffix = self.collapse(sub[start..i].to_vec(), Op::ALTERNATE)?; // recurse

                let re = self.new_regexp(Op::CONCAT);
                self.nodes[re].sub = vec![prefix, suffix];
                out.push(re);
            }

            // Prepare for next iteration.
            start = i;
            first = ifirst;
            i += 1;
        }
        sub = out;

        // Round 3: Collapse runs of single literals or character classes into character classes.
        start = 0;
        out = Vec::new();
        i = 0;
        while i <= sub.len() {
            // Invariant: the Regexps that were in sub[0:start] have been
            // used or marked for reuse, and the slice space has been reused
            // for out (len(out) <= start).
            //
            // Invariant: sub[start:i] consists of regexps that are either
            // literal runes or character classes.
            if i < sub.len() && self.is_char_class(sub[i]) {
                i += 1;
                continue;
            }

            // sub[i] is not a char or char class;
            // emit char class for sub[start:i]...
            if i == start {
                // Nothing to do - run of length 0.
            } else if i == start + 1 {
                out.push(sub[start]);
            } else {
                // Make new char class.
                // Start with most complex regexp in sub[start].
                let mut max = start;
                for j in start + 1..i {
                    let (a, b) = (&self.nodes[sub[max]], &self.nodes[sub[j]]);
                    if a.op < b.op || a.op == b.op && a.rune.len() < b.rune.len() {
                        max = j;
                    }
                }
                sub.swap(start, max);

                for j in start + 1..i {
                    self.merge_char_class(sub[start], sub[j]);
                    self.reuse(sub[j]);
                }
                self.clean_alt(sub[start]);
                out.push(sub[start]);
            }

            // ... and then emit sub[i].
            if i < sub.len() {
                out.push(sub[i]);
            }
            start = i + 1;
            i += 1;
        }
        sub = out;

        // Round 4: Collapse runs of empty matches into a single empty match.
        out = Vec::new();
        for i in 0..sub.len() {
            if i + 1 < sub.len()
                && self.nodes[sub[i]].op == Op::EMPTY_MATCH
                && self.nodes[sub[i + 1]].op == Op::EMPTY_MATCH
            {
                continue;
            }
            out.push(sub[i]);
        }
        Ok(out)
    }

    /// Returns the leading literal string that `re` begins with and its fold
    /// flag.
    fn leading_string(&self, mut re: usize) -> (Vec<i32>, Flags) {
        let n = &self.nodes[re];
        if n.op == Op::CONCAT && !n.sub.is_empty() {
            re = n.sub[0];
        }
        let n = &self.nodes[re];
        if n.op != Op::LITERAL {
            return (Vec::new(), Flags(0));
        }
        (n.rune.clone(), n.flags & Flags::FOLD_CASE)
    }

    /// Removes the first `n` leading runes from the beginning of `re`.
    fn remove_leading_string(&mut self, mut re: usize, n: usize) -> usize {
        if self.nodes[re].op == Op::CONCAT && !self.nodes[re].sub.is_empty() {
            // Removing a leading string in a concatenation might simplify
            // the concatenation.
            let sub = self.remove_leading_string(self.nodes[re].sub[0], n);
            self.nodes[re].sub[0] = sub;
            if self.nodes[sub].op == Op::EMPTY_MATCH {
                self.reuse(sub);
                // Delete first element of concat.
                match self.nodes[re].sub.len() {
                    0 | 1 => {
                        // Impossible but handle.
                        self.nodes[re].op = Op::EMPTY_MATCH;
                        self.nodes[re].sub = Vec::new();
                    }
                    2 => {
                        // Replace re with next element.
                        let old = re;
                        re = self.nodes[re].sub[1];
                        self.reuse(old);
                    }
                    _ => {
                        self.nodes[re].sub.remove(0);
                    }
                }
            }
            return re;
        }

        if self.nodes[re].op == Op::LITERAL {
            let node = &mut self.nodes[re];
            let n = n.min(node.rune.len());
            node.rune.drain(..n);
            if node.rune.is_empty() {
                node.op = Op::EMPTY_MATCH;
            }
        }
        re
    }

    /// Returns the leading regexp that `re` begins with. The regexp refers to
    /// storage in `re` or its children.
    fn leading_regexp(&self, re: usize) -> Option<usize> {
        let n = &self.nodes[re];
        if n.op == Op::EMPTY_MATCH {
            return None;
        }
        if n.op == Op::CONCAT && !n.sub.is_empty() {
            let sub = n.sub[0];
            if self.nodes[sub].op == Op::EMPTY_MATCH {
                return None;
            }
            return Some(sub);
        }
        Some(re)
    }

    /// Removes the leading regexp in `re`. It returns the replacement for `re`.
    /// If `reuse` is true, it passes the removed regexp (if no longer needed)
    /// to `reuse`.
    fn remove_leading_regexp(&mut self, mut re: usize, reuse: bool) -> usize {
        if self.nodes[re].op == Op::CONCAT && !self.nodes[re].sub.is_empty() {
            if reuse {
                let first = self.nodes[re].sub[0];
                self.reuse(first);
            }
            self.nodes[re].sub.remove(0);
            match self.nodes[re].sub.len() {
                0 => {
                    self.nodes[re].op = Op::EMPTY_MATCH;
                    self.nodes[re].sub = Vec::new();
                }
                1 => {
                    let old = re;
                    re = self.nodes[re].sub[0];
                    self.reuse(old);
                }
                _ => {}
            }
            return re;
        }
        if reuse {
            self.reuse(re);
        }
        self.new_regexp(Op::EMPTY_MATCH)
    }

    /// Reports whether `re` is a single rune or a character class.
    fn is_char_class(&self, re: usize) -> bool {
        let n = &self.nodes[re];
        n.op == Op::LITERAL && n.rune.len() == 1
            || n.op == Op::CHAR_CLASS
            || n.op == Op::ANY_CHAR_NOT_NL
            || n.op == Op::ANY_CHAR
    }

    /// Reports whether the single-character regexp `re` matches `r`.
    fn match_rune(&self, re: usize, r: i32) -> bool {
        let n = &self.nodes[re];
        match n.op {
            Op::LITERAL => n.rune.len() == 1 && n.rune[0] == r,
            Op::CHAR_CLASS => n.rune.chunks(2).any(|p| p[0] <= r && r <= p[1]),
            Op::ANY_CHAR_NOT_NL => r != '\n' as i32,
            Op::ANY_CHAR => true,
            _ => false,
        }
    }

    /// Adds the match set of `src` to `dst`. `dst` must be of a kind that can
    /// hold it, which the callers ensure by merging into the larger operator.
    fn merge_char_class(&mut self, dst: usize, src: usize) {
        let (src_op, src_rune, src_flags) = {
            let s = &self.nodes[src];
            (s.op, s.rune.clone(), s.flags)
        };
        match self.nodes[dst].op {
            Op::ANY_CHAR => {
                // src doesn't add anything.
            }
            Op::ANY_CHAR_NOT_NL => {
                // src might add \n
                if self.match_rune(src, '\n' as i32) {
                    self.nodes[dst].op = Op::ANY_CHAR;
                }
            }
            Op::CHAR_CLASS => {
                // src is simpler, so either literal or char class
                let d = &mut self.nodes[dst];
                if src_op == Op::LITERAL {
                    append_literal(&mut d.rune, src_rune[0], src_flags);
                } else {
                    append_class(&mut d.rune, &src_rune);
                }
            }
            Op::LITERAL => {
                // both literal
                let d = &mut self.nodes[dst];
                if src_rune[0] == d.rune[0] && src_flags == d.flags {
                    return;
                }
                d.op = Op::CHAR_CLASS;
                let d0 = d.rune[0];
                d.rune.clear();
                append_literal(&mut d.rune, d0, d.flags);
                append_literal(&mut d.rune, src_rune[0], src_flags);
            }
            _ => {}
        }
    }

    /// Reports whether the two arena subtrees are structurally equal, like
    /// [`Regexp::equal`].
    #[allow(clippy::collapsible_match)]
    fn equal(&self, x: usize, y: usize) -> bool {
        let (a, b) = (&self.nodes[x], &self.nodes[y]);
        if a.op != b.op {
            return false;
        }
        match a.op {
            Op::END_TEXT => {
                if a.flags & Flags::WAS_DOLLAR != b.flags & Flags::WAS_DOLLAR {
                    return false;
                }
            }
            Op::LITERAL | Op::CHAR_CLASS => {
                return a.flags & Flags::FOLD_CASE == b.flags & Flags::FOLD_CASE
                    && a.rune == b.rune;
            }
            Op::ALTERNATE | Op::CONCAT => {
                return a.sub.len() == b.sub.len()
                    && a.sub.iter().zip(&b.sub).all(|(&p, &q)| self.equal(p, q));
            }
            Op::STAR | Op::PLUS | Op::QUEST => {
                if a.flags & Flags::NON_GREEDY != b.flags & Flags::NON_GREEDY
                    || !self.equal(a.sub[0], b.sub[0])
                {
                    return false;
                }
            }
            Op::REPEAT => {
                if a.flags & Flags::NON_GREEDY != b.flags & Flags::NON_GREEDY
                    || a.min != b.min
                    || a.max != b.max
                    || !self.equal(a.sub[0], b.sub[0])
                {
                    return false;
                }
            }
            Op::CAPTURE => {
                if a.cap != b.cap || a.name != b.name || !self.equal(a.sub[0], b.sub[0]) {
                    return false;
                }
            }
            _ => {}
        }
        true
    }

    fn parse_vertical_bar(&mut self) -> R<()> {
        self.concat()?;

        // The concatenation we just parsed is on top of the stack.
        // If it sits above an opVerticalBar, swap it below
        // (things below an opVerticalBar become an alternation).
        // Otherwise, push a new vertical bar.
        if !self.swap_vertical_bar() {
            self.op(OP_VERTICAL_BAR)?;
        }
        Ok(())
    }

    /// If the top of the stack is an element followed by an opVerticalBar,
    /// swaps the two and returns true. Otherwise returns false. Merges single
    /// characters and classes around the bar into one class.
    fn swap_vertical_bar(&mut self) -> bool {
        // If above and below vertical bar are literal or char class,
        // can merge into a single char class.
        let n = self.stack.len();
        if n >= 3
            && self.nodes[self.stack[n - 2]].op == OP_VERTICAL_BAR
            && self.is_char_class(self.stack[n - 1])
            && self.is_char_class(self.stack[n - 3])
        {
            let mut re1 = self.stack[n - 1];
            let mut re3 = self.stack[n - 3];
            // Make re3 the more complex of the two.
            if self.nodes[re1].op > self.nodes[re3].op {
                std::mem::swap(&mut re1, &mut re3);
                self.stack[n - 3] = re3;
            }
            self.merge_char_class(re3, re1);
            self.reuse(re1);
            self.stack.truncate(n - 1);
            return true;
        }

        if n >= 2 {
            let re1 = self.stack[n - 1];
            let re2 = self.stack[n - 2];
            if self.nodes[re2].op == OP_VERTICAL_BAR {
                if n >= 3 {
                    // Now out of reach.
                    // Clean opportunistically.
                    self.clean_alt(self.stack[n - 3]);
                }
                self.stack[n - 2] = re1;
                self.stack[n - 1] = re2;
                return true;
            }
        }
        false
    }

    fn parse_right_paren(&mut self) -> R<()> {
        self.concat()?;
        if self.swap_vertical_bar() {
            // pop vertical bar
            self.stack.pop();
        }
        self.alternate()?;

        let n = self.stack.len();
        if n < 2 {
            return Err(Error::new(ErrorCode::UNEXPECTED_PAREN, self.whole));
        }
        let re1 = self.stack[n - 1];
        let re2 = self.stack[n - 2];
        self.stack.truncate(n - 2);
        if self.nodes[re2].op != OP_LEFT_PAREN {
            return Err(Error::new(ErrorCode::UNEXPECTED_PAREN, self.whole));
        }
        // Restore flags at time of paren.
        self.flags = self.nodes[re2].flags;
        if self.nodes[re2].cap == 0 {
            // Just for grouping.
            self.push(re1)?;
        } else {
            self.nodes[re2].op = Op::CAPTURE;
            self.nodes[re2].sub = vec![re1];
            self.push(re2)?;
        }
        Ok(())
    }

    /// Parses `{n}`, `{n,}` and `{n,m}`; `None` if `s` is not one of them.
    fn parse_repeat(&self, s: &'a [u8]) -> Option<(isize, isize, &'a [u8])> {
        if s.is_empty() || s[0] != b'{' {
            return None;
        }
        let s = &s[1..];
        let (mut min, s) = parse_int(s)?;
        if s.is_empty() {
            return None;
        }
        let mut s = s;
        let max;
        if s[0] != b',' {
            max = min;
        } else {
            s = &s[1..];
            if s.is_empty() {
                return None;
            }
            if s[0] == b'}' {
                max = -1;
            } else {
                let (m, rest) = parse_int(s)?;
                max = m;
                s = rest;
                if max < 0 {
                    // parseInt found too big a number
                    min = -1;
                }
            }
        }
        if s.is_empty() || s[0] != b'}' {
            return None;
        }
        Some((min, max, &s[1..]))
    }

    /// Parses a Perl flag setting or non-capturing group or both, like
    /// `(?i)` or `(?: ... )` or `(?i: ... )`, or a named capture. `s` begins
    /// with `(?`.
    fn parse_perl_flags(&mut self, s: &'a [u8]) -> R<&'a [u8]> {
        let mut t = s;

        // Check for named captures, first introduced in Python's regexp library.
        // support all three as well. EcmaScript 4 uses (?<name>expr),
        // Python uses (?P<name>expr), and .NET uses (?<name>expr) too.
        let starts_with_p = t.len() > 4 && t[2] == b'P' && t[3] == b'<';
        let starts_with_name = t.len() > 3 && t[2] == b'<';

        if starts_with_p || starts_with_name {
            // Pull out name.
            let expr_start_pos = if starts_with_name { 3 } else { 4 };

            let end = match t.iter().position(|&b| b == b'>') {
                Some(end) => end,
                None => {
                    check_utf8(t)?;
                    return Err(Error::new(ErrorCode::INVALID_NAMED_CAPTURE, s));
                }
            };

            let capture = &t[..end + 1]; // "(?P<name>" or "(?<name>"
            let name = &t[expr_start_pos..end]; // "name"
            check_utf8(name)?;
            if !is_valid_capture_name(name) {
                return Err(Error::new(ErrorCode::INVALID_NAMED_CAPTURE, capture));
            }

            // Like ordinary capture, but named.
            self.num_cap += 1;
            let re = self.op_node(OP_LEFT_PAREN)?;
            self.nodes[re].cap = self.num_cap;
            self.nodes[re].name = String::from_utf8_lossy(name).into_owned();
            return Ok(&t[end + 1..]);
        }

        // Non-capturing group. Might also twiddle Perl flags.
        t = &t[2..]; // skip (?
        let mut flags = self.flags;
        let mut sign = 1;
        let mut saw_flag = false;
        while !t.is_empty() {
            let (c, rest) = next_rune(t)?;
            t = rest;
            match u32::try_from(c).ok().and_then(char::from_u32) {
                // Flags.
                Some('i') => {
                    flags |= Flags::FOLD_CASE;
                    saw_flag = true;
                }
                Some('m') => {
                    flags &= !Flags::ONE_LINE;
                    saw_flag = true;
                }
                Some('s') => {
                    flags |= Flags::DOT_NL;
                    saw_flag = true;
                }
                Some('U') => {
                    flags |= Flags::NON_GREEDY;
                    saw_flag = true;
                }

                // Switch to negation.
                Some('-') => {
                    if sign < 0 {
                        break;
                    }
                    sign = -1;
                    // Invert flags so that | above turn into &^ and vice versa.
                    // We'll invert flags again before using it below.
                    flags = !flags;
                    saw_flag = false;
                }

                // End of flags, starting group or not.
                Some(':') | Some(')') => {
                    if sign < 0 {
                        if !saw_flag {
                            break;
                        }
                        flags = !flags;
                    }
                    if c == ':' as i32 {
                        // Open new group
                        self.op_node(OP_LEFT_PAREN)?;
                    }
                    self.flags = flags;
                    return Ok(t);
                }
                _ => break,
            }
        }

        Err(Error::new(ErrorCode::INVALID_PERL_OP, slice_before(s, t)))
    }

    /// Parses a single escape sequence at the beginning of `s` and returns the
    /// rune.
    fn parse_escape(&self, s: &'a [u8]) -> R<(i32, &'a [u8])> {
        let mut t = &s[1..];
        if t.is_empty() {
            return Err(Error::new(ErrorCode::TRAILING_BACKSLASH, b""));
        }
        let (c, rest) = next_rune(t)?;
        t = rest;
        'invalid: {
            match u32::try_from(c)
                .ok()
                .and_then(char::from_u32)
                .unwrap_or('\0')
            {
                // Octal escapes.
                d @ '1'..='7' => {
                    // Single non-zero digit is a backreference; not supported
                    if t.is_empty() || t[0] < b'0' || t[0] > b'7' {
                        break 'invalid;
                    }
                    return Ok(self.octal(d as i32 - '0' as i32, t));
                }
                '0' => return Ok(self.octal(0, t)),

                // Hexadecimal escapes.
                'x' => {
                    if t.is_empty() {
                        break 'invalid;
                    }
                    let (c, rest) = next_rune(t)?;
                    t = rest;
                    if c == '{' as i32 {
                        // Any number of digits in braces.
                        // Perl accepts any text at all; it ignores all text
                        // after the first non-hex digit. We require only hex digits,
                        // and at least one.
                        let mut nhex = 0;
                        let mut r = 0;
                        loop {
                            if t.is_empty() {
                                break 'invalid;
                            }
                            let (c, rest) = next_rune(t)?;
                            t = rest;
                            if c == '}' as i32 {
                                break;
                            }
                            let v = unhex(c);
                            if v < 0 {
                                break 'invalid;
                            }
                            r = r * 16 + v;
                            if r > MAX_RUNE {
                                break 'invalid;
                            }
                            nhex += 1;
                        }
                        if nhex == 0 {
                            break 'invalid;
                        }
                        return Ok((r, t));
                    }

                    // Easy case: two hex digits.
                    let x = unhex(c);
                    let (c, rest) = next_rune(t)?;
                    t = rest;
                    let y = unhex(c);
                    if x < 0 || y < 0 {
                        break 'invalid;
                    }
                    return Ok((x * 16 + y, t));
                }

                // C escapes. There is no case 'b', to avoid misparsing
                // the Perl word-boundary \b as the C backspace \b
                // when in POSIX mode. In Perl, /\b/ means word-boundary
                // but /[\b]/ means backspace. We don't support that.
                // If you want a backspace, embed a literal backspace
                // character or use \x08.
                'a' => return Ok((7, t)),
                'f' => return Ok((12, t)),
                'n' => return Ok((10, t)),
                'r' => return Ok((13, t)),
                't' => return Ok((9, t)),
                'v' => return Ok((11, t)),
                _ => {
                    if c < unicode::rune::RUNE_SELF && !isalnum(c) {
                        // Escaped non-word characters are always themselves.
                        // PCRE is not quite so rigorous: it accepts things like
                        // \q, but we don't. We once rejected \_, but too many
                        // programs and people insist on using it, so allow \_.
                        return Ok((c, t));
                    }
                }
            }
        }
        Err(Error::new(ErrorCode::INVALID_ESCAPE, slice_before(s, t)))
    }

    /// Up to two more octal digits after `r`.
    fn octal(&self, mut r: i32, mut t: &'a [u8]) -> (i32, &'a [u8]) {
        for _ in 1..3 {
            if t.is_empty() || t[0] < b'0' || t[0] > b'7' {
                break;
            }
            r = r * 8 + i32::from(t[0]) - '0' as i32;
            t = &t[1..];
        }
        (r, t)
    }

    /// Parses a character class character at the beginning of `s`.
    fn parse_class_char(&self, s: &'a [u8], whole_class: &[u8]) -> R<(i32, &'a [u8])> {
        if s.is_empty() {
            return Err(Error::new(ErrorCode::MISSING_BRACKET, whole_class));
        }

        // Allow regular escape sequences even though
        // many need not be escaped in this context.
        if s[0] == b'\\' {
            return self.parse_escape(s);
        }

        next_rune(s)
    }

    /// Parses a leading Perl character class escape like `\d`, appending the
    /// class to `r`.
    fn parse_perl_class_escape(&mut self, s: &'a [u8], r: &mut Vec<i32>) -> Option<&'a [u8]> {
        if !self.flags.contains(Flags::PERL_X) || s.len() < 2 || s[0] != b'\\' {
            return None;
        }
        let g = perl_group(&s[..2])?;
        self.append_group(r, g);
        Some(&s[2..])
    }

    /// Parses a leading POSIX named class like `[:alnum:]`, appending it to
    /// `r`.
    fn parse_named_class(&mut self, s: &'a [u8], r: &mut Vec<i32>) -> R<Option<&'a [u8]>> {
        if s.len() < 2 || s[0] != b'[' || s[1] != b':' {
            return Ok(None);
        }

        let i = match find_sub(&s[2..], b":]") {
            Some(i) => i + 2,
            None => return Ok(None),
        };
        let (name, rest) = (&s[..i + 2], &s[i + 2..]);
        let g = posix_group(name).ok_or_else(|| Error::new(ErrorCode::INVALID_CHAR_RANGE, name))?;
        self.append_group(r, g);
        Ok(Some(rest))
    }

    fn append_group(&mut self, r: &mut Vec<i32>, g: CharGroup) {
        if !self.flags.contains(Flags::FOLD_CASE) {
            if g.sign < 0 {
                append_negated_class(r, g.class);
            } else {
                append_class(r, g.class);
            }
        } else {
            let mut tmp = std::mem::take(&mut self.tmp_class);
            tmp.clear();
            append_folded_class(&mut tmp, g.class);
            clean_class(&mut tmp);
            if g.sign < 0 {
                append_negated_class(r, &tmp);
            } else {
                append_class(r, &tmp);
            }
            self.tmp_class = tmp;
        }
    }

    /// Parses a leading Unicode character class like `\p{Han}`, appending it
    /// to `r`. Returns `None` if `s` does not start with one (or Unicode
    /// groups are not enabled).
    fn parse_unicode_class(&mut self, s: &'a [u8], r: &mut Vec<i32>) -> R<Option<&'a [u8]>> {
        if !self.flags.contains(Flags::UNICODE_GROUPS)
            || s.len() < 2
            || s[0] != b'\\'
            || s[1] != b'p' && s[1] != b'P'
        {
            return Ok(None);
        }

        // Committed to parse.
        let mut sign = 1;
        if s[1] == b'P' {
            sign = -1;
        }
        let (c, mut t) = next_rune(&s[2..])?;
        let seq: &[u8];
        let mut name: &[u8];
        if c != '{' as i32 {
            // Single-letter name.
            seq = slice_before(s, t);
            name = &seq[2..];
        } else {
            // Name is in braces.
            let end = match s.iter().position(|&b| b == b'}') {
                Some(end) => end,
                None => {
                    check_utf8(s)?;
                    return Err(Error::new(ErrorCode::INVALID_CHAR_RANGE, s));
                }
            };
            seq = &s[..end + 1];
            t = &s[end + 1..];
            name = &s[3..end];
            check_utf8(name)?;
        }

        // Group can have leading negation too.  \p{^Han} == \P{Han}, \P{^Han} == \p{Han}.
        if !name.is_empty() && name[0] == b'^' {
            sign = -sign;
            name = &name[1..];
        }

        let (tab, fold, tsign) =
            unicode_table(name).ok_or_else(|| Error::new(ErrorCode::INVALID_CHAR_RANGE, seq))?;
        if tsign < 0 {
            sign = -sign;
        }

        match fold {
            Some(fold) if self.flags.contains(Flags::FOLD_CASE) => {
                // Merge and clean tab and fold in a temporary buffer.
                // This is necessary for the negative case and just tidy
                // for the positive case.
                let mut tmp = std::mem::take(&mut self.tmp_class);
                tmp.clear();
                append_table(&mut tmp, tab);
                append_table(&mut tmp, fold);
                clean_class(&mut tmp);
                if sign > 0 {
                    append_class(r, &tmp);
                } else {
                    append_negated_class(r, &tmp);
                }
                self.tmp_class = tmp;
            }
            _ => {
                if sign > 0 {
                    append_table(r, tab);
                } else {
                    append_negated_table(r, tab);
                }
            }
        }
        Ok(Some(t))
    }

    /// Parses a character class at the beginning of `s` and pushes it.
    fn parse_class(&mut self, s: &'a [u8]) -> R<&'a [u8]> {
        let mut t = &s[1..]; // chop [
        let re = self.new_regexp(Op::CHAR_CLASS);
        self.nodes[re].flags = self.flags;
        let mut class: Vec<i32> = Vec::new();

        let mut sign = 1;
        if !t.is_empty() && t[0] == b'^' {
            sign = -1;
            t = &t[1..];

            // If character class does not match \n, add it here,
            // so that negation later will do the right thing.
            if !self.flags.contains(Flags::CLASS_NL) {
                class.push('\n' as i32);
                class.push('\n' as i32);
            }
        }

        let mut first = true; // ] and - are okay as first char in class
        while t.is_empty() || t[0] != b']' || first {
            // POSIX: - is only okay unescaped as first or last in class.
            // Perl: - is okay anywhere.
            if !t.is_empty()
                && t[0] == b'-'
                && !self.flags.contains(Flags::PERL_X)
                && !first
                && (t.len() == 1 || t[1] != b']')
            {
                let (_, size) = decode_rune(&t[1..]);
                return Err(Error::new(ErrorCode::INVALID_CHAR_RANGE, &t[..1 + size]));
            }
            first = false;

            // Look for POSIX [:alnum:] etc.
            if t.len() > 2 && t[0] == b'[' && t[1] == b':' {
                if let Some(nt) = self.parse_named_class(t, &mut class)? {
                    t = nt;
                    continue;
                }
            }

            // Look for Unicode character group like \p{Han}.
            if let Some(nt) = self.parse_unicode_class(t, &mut class)? {
                t = nt;
                continue;
            }

            // Look for Perl character class symbols (extension).
            if let Some(nt) = self.parse_perl_class_escape(t, &mut class) {
                t = nt;
                continue;
            }

            // Single character or simple range.
            let rng = t;
            let (lo, nt) = self.parse_class_char(t, s)?;
            t = nt;
            let mut hi = lo;
            // [a-] means (a|-) so check for final ].
            if t.len() >= 2 && t[0] == b'-' && t[1] != b']' {
                let (h, nt) = self.parse_class_char(&t[1..], s)?;
                hi = h;
                t = nt;
                if hi < lo {
                    return Err(Error::new(
                        ErrorCode::INVALID_CHAR_RANGE,
                        slice_before(rng, t),
                    ));
                }
            }
            if !self.flags.contains(Flags::FOLD_CASE) {
                append_range(&mut class, lo, hi);
            } else {
                append_folded_range(&mut class, lo, hi);
            }
        }
        t = &t[1..]; // chop ]

        // Use &re.Rune instead of &class to avoid allocation.
        clean_class(&mut class);
        if sign < 0 {
            negate_class(&mut class);
        }
        self.nodes[re].rune = class;
        self.push(re)?;
        Ok(t)
    }
}

/// Parses the digits at the beginning of `s` as a decimal number, -1 if it
/// overflows 1e8. Leading zeros are rejected (except the number 0).
fn parse_int(s: &[u8]) -> Option<(isize, &[u8])> {
    if s.is_empty() || !s[0].is_ascii_digit() {
        return None;
    }
    // Disallow leading zeros.
    if s.len() >= 2 && s[0] == b'0' && s[1].is_ascii_digit() {
        return None;
    }
    let digits = s.iter().take_while(|b| b.is_ascii_digit()).count();
    let mut n: isize = 0;
    for &d in &s[..digits] {
        // Avoid overflow.
        if n >= 100_000_000 {
            n = -1;
            break;
        }
        n = n * 10 + isize::from(d - b'0');
    }
    Some((n, &s[digits..]))
}

fn is_valid_capture_name(name: &[u8]) -> bool {
    if name.is_empty() {
        return false;
    }
    // Validated as UTF-8 by the caller; any non-ASCII byte is invalid anyway.
    name.iter().all(|&c| c == b'_' || c.is_ascii_alphanumeric())
}

fn isalnum(c: i32) -> bool {
    (0x30..=0x39).contains(&c) || (0x41..=0x5a).contains(&c) || (0x61..=0x7a).contains(&c)
}

fn unhex(c: i32) -> i32 {
    if ('0' as i32..='9' as i32).contains(&c) {
        return c - '0' as i32;
    }
    if ('a' as i32..='f' as i32).contains(&c) {
        return c - 'a' as i32 + 10;
    }
    if ('A' as i32..='F' as i32).contains(&c) {
        return c - 'A' as i32 + 10;
    }
    -1
}

/// Returns the smallest rune in the case-folding orbit of `r`.
fn min_fold_rune(r: i32) -> i32 {
    if !(MIN_FOLD..=MAX_FOLD).contains(&r) {
        return r;
    }
    let mut m = r;
    let r0 = r;
    let mut r = unicode::simple_fold(r);
    while r != r0 {
        m = m.min(r);
        r = unicode::simple_fold(r);
    }
    m
}

/// Reports an error for the first invalid UTF-8 sequence in `s`.
fn check_utf8(mut s: &[u8]) -> R<()> {
    while !s.is_empty() {
        let (rune, size) = decode_rune(s);
        if rune == unicode::rune::RUNE_ERROR && size == 1 {
            return Err(Error::new(ErrorCode::INVALID_UTF8, s));
        }
        s = &s[size..];
    }
    Ok(())
}

fn next_rune(s: &[u8]) -> R<(i32, &[u8])> {
    let (c, size) = decode_rune(s);
    if c == unicode::rune::RUNE_ERROR && size == 1 {
        return Err(Error::new(ErrorCode::INVALID_UTF8, s));
    }
    Ok((c, &s[size..]))
}

// ---- Character class helpers: classes are flat lists of (lo, hi) pairs. ----

/// Sorts the pairs, merges overlapping and adjacent ranges.
fn clean_class(r: &mut Vec<i32>) {
    let mut pairs: Vec<(i32, i32)> = r.chunks_exact(2).map(|c| (c[0], c[1])).collect();
    // Sort by lo, then by hi decreasing.
    pairs.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    r.clear();
    for (lo, hi) in pairs {
        if r.len() >= 2 && lo <= r[r.len() - 1] + 1 {
            // Merge with previous range.
            let last = r.len() - 1;
            if hi > r[last] {
                r[last] = hi;
            }
            continue;
        }
        r.push(lo);
        r.push(hi);
    }
}

fn append_literal(r: &mut Vec<i32>, x: i32, flags: Flags) {
    if flags.contains(Flags::FOLD_CASE) {
        append_folded_range(r, x, x);
    } else {
        append_range(r, x, x);
    }
}

/// Appends the range `lo-hi` to the class, merging with either of the last
/// two ranges if possible. Keeps the list sorted for common inputs.
fn append_range(r: &mut Vec<i32>, lo: i32, hi: i32) {
    let n = r.len();
    for i in [2, 4] {
        // twice, using i=2, i=4
        if n >= i {
            let (rlo, rhi) = (r[n - i], r[n - i + 1]);
            if lo <= rhi + 1 && rlo <= hi + 1 {
                if lo < rlo {
                    r[n - i] = lo;
                }
                if hi > rhi {
                    r[n - i + 1] = hi;
                }
                return;
            }
        }
    }
    r.push(lo);
    r.push(hi);
}

/// Appends the range `lo-hi` together with all its case-folded equivalents.
fn append_folded_range(r: &mut Vec<i32>, mut lo: i32, mut hi: i32) {
    // Optimizations.
    if lo <= MIN_FOLD && hi >= MAX_FOLD {
        // Range is full: folding can't add more.
        return append_range(r, lo, hi);
    }
    if hi < MIN_FOLD || lo > MAX_FOLD {
        // Range is outside folding possibilities.
        return append_range(r, lo, hi);
    }
    if lo < MIN_FOLD {
        // [lo, minFold-1] needs no folding.
        append_range(r, lo, MIN_FOLD - 1);
        lo = MIN_FOLD;
    }
    if hi > MAX_FOLD {
        // [maxFold+1, hi] needs no folding.
        append_range(r, MAX_FOLD + 1, hi);
        hi = MAX_FOLD;
    }

    // Brute force. Depend on appendRange to coalesce ranges on the fly.
    for c in lo..=hi {
        append_range(r, c, c);
        let mut f = unicode::simple_fold(c);
        while f != c {
            append_range(r, f, f);
            f = unicode::simple_fold(f);
        }
    }
}

fn append_class(r: &mut Vec<i32>, x: &[i32]) {
    for pair in x.chunks_exact(2) {
        append_range(r, pair[0], pair[1]);
    }
}

fn append_folded_class(r: &mut Vec<i32>, x: &[i32]) {
    for pair in x.chunks_exact(2) {
        append_folded_range(r, pair[0], pair[1]);
    }
}

fn append_negated_class(r: &mut Vec<i32>, x: &[i32]) {
    let mut next_lo = 0;
    for pair in x.chunks_exact(2) {
        let (lo, hi) = (pair[0], pair[1]);
        if next_lo <= lo - 1 {
            append_range(r, next_lo, lo - 1);
        }
        next_lo = hi + 1;
    }
    if next_lo <= MAX_RUNE {
        append_range(r, next_lo, MAX_RUNE);
    }
}

/// Calls `f(lo, hi)` for each range of the table, expanding strides.
fn each_table_range(x: &RangeTable, mut f: impl FnMut(i32, i32)) {
    for xr in x.r16 {
        let (lo, hi, stride) = (i32::from(xr.lo), i32::from(xr.hi), i32::from(xr.stride));
        if stride == 1 {
            f(lo, hi);
            continue;
        }
        let mut c = lo;
        while c <= hi {
            f(c, c);
            c += stride;
        }
    }
    for xr in x.r32 {
        let (lo, hi, stride) = (xr.lo as i32, xr.hi as i32, xr.stride as i32);
        if stride == 1 {
            f(lo, hi);
            continue;
        }
        let mut c = lo;
        while c <= hi {
            f(c, c);
            c += stride;
        }
    }
}

fn append_table(r: &mut Vec<i32>, x: &RangeTable) {
    each_table_range(x, |lo, hi| append_range(r, lo, hi));
}

fn append_negated_table(r: &mut Vec<i32>, x: &RangeTable) {
    let mut next_lo = 0;
    each_table_range(x, |lo, hi| {
        if next_lo <= lo - 1 {
            append_range(r, next_lo, lo - 1);
        }
        next_lo = hi + 1;
    });
    if next_lo <= MAX_RUNE {
        append_range(r, next_lo, MAX_RUNE);
    }
}

/// Negates a sorted, cleaned class in place.
fn negate_class(r: &mut Vec<i32>) {
    let mut next_lo = 0;
    let mut w = 0; // write index
    for i in (0..r.len()).step_by(2) {
        let (lo, hi) = (r[i], r[i + 1]);
        if next_lo <= lo - 1 {
            r[w] = next_lo;
            r[w + 1] = lo - 1;
            w += 2;
        }
        next_lo = hi + 1;
    }
    r.truncate(w);
    if next_lo <= MAX_RUNE {
        // It's possible for the negation to have one more
        // range - this one - than the original class, so use append.
        r.push(next_lo);
        r.push(MAX_RUNE);
    }
}

// ---- Unicode tables for \p{...} ----

static ANY_R16: [unicode::Range16; 1] = [unicode::Range16 {
    lo: 0,
    hi: 0xFFFF,
    stride: 1,
}];
static ANY_R32: [unicode::Range32; 1] = [unicode::Range32 {
    lo: 0x10000,
    hi: 0x10FFFF,
    stride: 1,
}];
static ANY_TABLE: RangeTable = RangeTable {
    r16: &ANY_R16,
    r32: &ANY_R32,
    latin_offset: 0,
};
static ASCII_R16: [unicode::Range16; 1] = [unicode::Range16 {
    lo: 0,
    hi: 0x7F,
    stride: 1,
}];
static ASCII_TABLE: RangeTable = RangeTable {
    r16: &ASCII_R16,
    r32: &[],
    latin_offset: 1,
};
static ASCII_FOLD_R16: [unicode::Range16; 3] = [
    unicode::Range16 {
        lo: 0,
        hi: 0x7F,
        stride: 1,
    },
    // Old English long s (ſ), folds to S/s.
    unicode::Range16 {
        lo: 0x017F,
        hi: 0x017F,
        stride: 1,
    },
    // Kelvin K, folds to K/k.
    unicode::Range16 {
        lo: 0x212A,
        hi: 0x212A,
        stride: 1,
    },
];
static ASCII_FOLD_TABLE: RangeTable = RangeTable {
    r16: &ASCII_FOLD_R16,
    r32: &[],
    latin_offset: 1,
};

/// Go's `canonicalName`: separators (`_`, `-`, space) are dropped, the first
/// remaining ASCII letter is upper-cased and the other ASCII letters
/// lower-cased, so `latin`, `LATIN` and `Latin` agree.
fn canonical_name(name: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len());
    let mut first = true;
    for &c in name {
        match c {
            b'_' | b'-' | b' ' => {}
            _ if first => {
                out.push(c.to_ascii_uppercase());
                first = false;
            }
            _ => out.push(c.to_ascii_lowercase()),
        }
    }
    out
}

type Table = &'static RangeTable;

fn lookup(list: &'static [(&'static str, Table)], name: &str) -> Option<Table> {
    list.iter().find(|&&(n, _)| n == name).map(|&(_, t)| t)
}

/// Returns the table for the Unicode category or script `name`, its folding
/// table and whether the class is inverted (-1).
fn unicode_table(name: &[u8]) -> Option<(Table, Option<Table>, i32)> {
    let name = canonical_name(name);
    let name = std::str::from_utf8(&name).ok()?;
    match name {
        "Any" => return Some((&ANY_TABLE, Some(&ANY_TABLE), 1)),
        "Assigned" => {
            let cn = lookup(unicode::CATEGORIES, "Cn")?;
            return Some((cn, Some(cn), -1));
        }
        "Ascii" => return Some((&ASCII_TABLE, Some(&ASCII_FOLD_TABLE), 1)),
        "Lc" => {
            return Some((
                lookup(unicode::CATEGORIES, "LC")?,
                lookup(unicode::FOLD_CATEGORY, "LC"),
                1,
            ))
        }
        _ => {}
    }
    if let Some(t) = lookup(unicode::CATEGORIES, name) {
        return Some((t, lookup(unicode::FOLD_CATEGORY, name), 1));
    }
    if let Some(t) = lookup(unicode::SCRIPTS, name) {
        return Some((t, lookup(unicode::FOLD_SCRIPT, name), 1));
    }
    // Aliases are matched by canonical name: category aliases such as
    // "Letter" and script names such as "Old_Italic".
    for &(alias, actual) in unicode::CATEGORY_ALIASES {
        if canonical_name(alias.as_bytes()) == name.as_bytes() {
            let t = lookup(unicode::CATEGORIES, actual)?;
            return Some((t, lookup(unicode::FOLD_CATEGORY, actual), 1));
        }
    }
    for &(script, t) in unicode::SCRIPTS {
        if canonical_name(script.as_bytes()) == name.as_bytes() {
            return Some((t, lookup(unicode::FOLD_SCRIPT, script), 1));
        }
    }
    None
}
