//! The syntax tree and its printer (Go `regexp/syntax/regexp.go`).
use super::Flags;
use crate::unicode;
use std::{collections::HashMap, fmt, sync::Arc};

/// A regular expression operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Op(pub u8);

impl Op {
    /// Matches no strings.
    pub const NO_MATCH: Op = Op(1);
    /// Matches the empty string.
    pub const EMPTY_MATCH: Op = Op(2);
    /// Matches the `rune` sequence.
    pub const LITERAL: Op = Op(3);
    /// Matches `rune` interpreted as a range pair list.
    pub const CHAR_CLASS: Op = Op(4);
    /// Matches any character except newline.
    pub const ANY_CHAR_NOT_NL: Op = Op(5);
    /// Matches any character.
    pub const ANY_CHAR: Op = Op(6);
    /// Matches the empty string at the beginning of a line.
    pub const BEGIN_LINE: Op = Op(7);
    /// Matches the empty string at the end of a line.
    pub const END_LINE: Op = Op(8);
    /// Matches the empty string at the beginning of the text.
    pub const BEGIN_TEXT: Op = Op(9);
    /// Matches the empty string at the end of the text.
    pub const END_TEXT: Op = Op(10);
    /// Matches a word boundary `\b`.
    pub const WORD_BOUNDARY: Op = Op(11);
    /// Matches a word non-boundary `\B`.
    pub const NO_WORD_BOUNDARY: Op = Op(12);
    /// A capturing subexpression with index `cap` and optional `name`.
    pub const CAPTURE: Op = Op(13);
    /// Matches `sub[0]` zero or more times.
    pub const STAR: Op = Op(14);
    /// Matches `sub[0]` one or more times.
    pub const PLUS: Op = Op(15);
    /// Matches `sub[0]` zero or one times.
    pub const QUEST: Op = Op(16);
    /// Matches `sub[0]` at least `min` times, at most `max` (-1 is no limit).
    pub const REPEAT: Op = Op(17);
    /// Matches the concatenation of `sub`.
    pub const CONCAT: Op = Op(18);
    /// Matches the alternation of `sub`.
    pub const ALTERNATE: Op = Op(19);
    /// Where the parser's pseudo-operators start.
    pub(crate) const PSEUDO: Op = Op(128);
}

const OP_NAMES: [&str; 19] = [
    "NoMatch",
    "EmptyMatch",
    "Literal",
    "CharClass",
    "AnyCharNotNL",
    "AnyChar",
    "BeginLine",
    "EndLine",
    "BeginText",
    "EndText",
    "WordBoundary",
    "NoWordBoundary",
    "Capture",
    "Star",
    "Plus",
    "Quest",
    "Repeat",
    "Concat",
    "Alternate",
];

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1..=19 => f.write_str(OP_NAMES[usize::from(self.0) - 1]),
            128 => f.write_str("opPseudo"),
            n => write!(f, "Op({n})"),
        }
    }
}

/// A node of the regular expression syntax tree.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Regexp {
    /// The operator.
    pub op: Op,
    pub flags: Flags,
    /// Subexpressions, if any.
    pub sub: Vec<Arc<Regexp>>,
    /// Matched runes, for `LITERAL` and `CHAR_CLASS` (range pairs).
    pub rune: Vec<i32>,
    /// Minimum for `REPEAT`.
    pub min: isize,
    /// Maximum for `REPEAT`.
    pub max: isize,
    /// Capturing index, for `CAPTURE`.
    pub cap: isize,
    /// Capturing name, for `CAPTURE`.
    pub name: String,
}

impl Regexp {
    pub(crate) fn with_op(op: Op) -> Regexp {
        Regexp {
            op,
            ..Regexp::default()
        }
    }

    /// Reports whether `self` and `other` have identical structure.
    #[allow(clippy::collapsible_match)]
    pub fn equal(&self, other: &Regexp) -> bool {
        if self.op != other.op {
            return false;
        }
        match self.op {
            Op::END_TEXT => {
                if self.flags & Flags::WAS_DOLLAR != other.flags & Flags::WAS_DOLLAR {
                    return false;
                }
            }
            Op::LITERAL | Op::CHAR_CLASS => {
                return self.flags & Flags::FOLD_CASE == other.flags & Flags::FOLD_CASE
                    && self.rune == other.rune;
            }
            Op::ALTERNATE | Op::CONCAT => {
                return self.sub.len() == other.sub.len()
                    && self.sub.iter().zip(&other.sub).all(|(a, b)| a.equal(b));
            }
            Op::STAR | Op::PLUS | Op::QUEST => {
                if self.flags & Flags::NON_GREEDY != other.flags & Flags::NON_GREEDY
                    || !self.sub[0].equal(&other.sub[0])
                {
                    return false;
                }
            }
            Op::REPEAT => {
                if self.flags & Flags::NON_GREEDY != other.flags & Flags::NON_GREEDY
                    || self.min != other.min
                    || self.max != other.max
                    || !self.sub[0].equal(&other.sub[0])
                {
                    return false;
                }
            }
            Op::CAPTURE => {
                if self.cap != other.cap
                    || self.name != other.name
                    || !self.sub[0].equal(&other.sub[0])
                {
                    return false;
                }
            }
            _ => {}
        }
        true
    }

    /// Returns the highest capturing group index in the expression.
    pub fn max_cap(&self) -> isize {
        let mut m = 0;
        if self.op == Op::CAPTURE {
            m = self.cap;
        }
        for sub in &self.sub {
            m = m.max(sub.max_cap());
        }
        m
    }

    /// Returns the capturing group names, indexed by group number; unnamed
    /// groups and the whole match have the empty name.
    pub fn cap_names(&self) -> Vec<String> {
        let mut names = vec![String::new(); self.max_cap() as usize + 1];
        self.fill_cap_names(&mut names);
        names
    }

    fn fill_cap_names(&self, names: &mut [String]) {
        if self.op == Op::CAPTURE {
            names[self.cap as usize] = self.name.clone();
        }
        for sub in &self.sub {
            sub.fill_cap_names(names);
        }
    }
}

type PrintFlags = u8;
const FLAG_I: PrintFlags = 1; // (?i:
const FLAG_M: PrintFlags = 2; // (?m:
const FLAG_S: PrintFlags = 4; // (?s:
const FLAG_OFF: PrintFlags = 8; // )
const FLAG_PREC: PrintFlags = 16; // (?: )
const NEG_SHIFT: u32 = 5; // FLAG_I << NEG_SHIFT is (?-i:

const MIN_FOLD: i32 = 0x0041;
const MAX_FOLD: i32 = 0x1e943;

type FlagMap = HashMap<*const Regexp, PrintFlags>;

fn add_span(start: &Arc<Regexp>, last: &Arc<Regexp>, f: PrintFlags, flags: &mut FlagMap) {
    flags.insert(Arc::as_ptr(start), f);
    *flags.entry(Arc::as_ptr(last)).or_insert(0) |= FLAG_OFF;
}

/// Reports whether `r` is within the sorted range-pair list `class`.
pub(crate) fn in_char_class(r: i32, class: &[i32]) -> bool {
    let (mut lo, mut hi) = (0, class.len() / 2);
    while lo < hi {
        let m = (lo + hi) / 2;
        if r > class[2 * m + 1] {
            lo = m + 1;
        } else if r < class[2 * m] {
            hi = m;
        } else {
            return true;
        }
    }
    false
}

fn calc_flags(re: &Regexp, flags: &mut FlagMap) -> (PrintFlags, PrintFlags) {
    match re.op {
        Op::LITERAL => {
            for &r in &re.rune {
                if (MIN_FOLD..=MAX_FOLD).contains(&r) && unicode::simple_fold(r) != r {
                    return if re.flags & Flags::FOLD_CASE != Flags(0) {
                        (FLAG_I, 0)
                    } else {
                        (0, FLAG_I)
                    };
                }
            }
            (0, 0)
        }
        Op::CHAR_CLASS => {
            for pair in re.rune.chunks(2) {
                let lo = MIN_FOLD.max(pair[0]);
                let hi = MAX_FOLD.min(pair[1]);
                for r in lo..=hi {
                    let mut f = unicode::simple_fold(r);
                    while f != r {
                        if !(lo <= f && f <= hi) && !in_char_class(f, &re.rune) {
                            return (0, FLAG_I);
                        }
                        f = unicode::simple_fold(f);
                    }
                }
            }
            (0, 0)
        }
        Op::ANY_CHAR_NOT_NL => (0, FLAG_S),
        Op::ANY_CHAR => (FLAG_S, 0),
        Op::BEGIN_LINE | Op::END_LINE => (FLAG_M, 0),
        Op::END_TEXT => {
            if re.flags & Flags::WAS_DOLLAR != Flags(0) {
                (0, FLAG_M)
            } else {
                (0, 0)
            }
        }
        Op::CAPTURE | Op::STAR | Op::PLUS | Op::QUEST | Op::REPEAT => calc_flags(&re.sub[0], flags),
        Op::CONCAT | Op::ALTERNATE => {
            let (mut must, mut cant, mut all_cant) = (0, 0, 0);
            let (mut start, mut last) = (0, 0);
            let mut did = false;
            for (i, sub) in re.sub.iter().enumerate() {
                let (sub_must, sub_cant) = calc_flags(sub, flags);
                if must & sub_cant != 0 || sub_must & cant != 0 {
                    if must != 0 {
                        add_span(&re.sub[start], &re.sub[last], must, flags);
                    }
                    must = 0;
                    cant = 0;
                    start = i;
                    did = true;
                }
                must |= sub_must;
                cant |= sub_cant;
                all_cant |= sub_cant;
                if sub_must != 0 {
                    last = i;
                }
                if must == 0 && start == i {
                    start += 1;
                }
            }
            if !did {
                return (must, cant);
            }
            if must != 0 {
                add_span(&re.sub[start], &re.sub[last], must, flags);
            }
            (0, all_cant)
        }
        _ => (0, 0),
    }
}

fn write_regexp(b: &mut String, re: &Regexp, mut f: PrintFlags, flags: &FlagMap) {
    f |= flags.get(&(re as *const Regexp)).copied().unwrap_or(0);
    if f & FLAG_PREC != 0 && f & !(FLAG_OFF | FLAG_PREC) != 0 && f & FLAG_OFF != 0 {
        f &= !FLAG_PREC;
    }
    if f & !(FLAG_OFF | FLAG_PREC) != 0 {
        b.push_str("(?");
        if f & FLAG_I != 0 {
            b.push('i');
        }
        if f & FLAG_M != 0 {
            b.push('m');
        }
        if f & FLAG_S != 0 {
            b.push('s');
        }
        if f & ((FLAG_M | FLAG_S) << NEG_SHIFT) != 0 {
            b.push('-');
            if f & (FLAG_M << NEG_SHIFT) != 0 {
                b.push('m');
            }
            if f & (FLAG_S << NEG_SHIFT) != 0 {
                b.push('s');
            }
        }
        b.push(':');
    }
    let mut suffix = 0;
    if f & FLAG_OFF != 0 {
        suffix += 1;
    }
    if f & FLAG_PREC != 0 {
        b.push_str("(?:");
        suffix += 1;
    }

    match re.op {
        Op::NO_MATCH => b.push_str(r"[^\x00-\x{10FFFF}]"),
        Op::EMPTY_MATCH => b.push_str("(?:)"),
        Op::LITERAL => {
            for &r in &re.rune {
                escape(b, r, false);
            }
        }
        Op::CHAR_CLASS => write_class(b, &re.rune),
        Op::ANY_CHAR_NOT_NL | Op::ANY_CHAR => b.push('.'),
        Op::BEGIN_LINE => b.push('^'),
        Op::END_LINE => b.push('$'),
        Op::BEGIN_TEXT => b.push_str(r"\A"),
        Op::END_TEXT => {
            if re.flags & Flags::WAS_DOLLAR != Flags(0) {
                b.push('$');
            } else {
                b.push_str(r"\z");
            }
        }
        Op::WORD_BOUNDARY => b.push_str(r"\b"),
        Op::NO_WORD_BOUNDARY => b.push_str(r"\B"),
        Op::CAPTURE => {
            if !re.name.is_empty() {
                b.push_str("(?P<");
                b.push_str(&re.name);
                b.push('>');
            } else {
                b.push('(');
            }
            if re.sub[0].op != Op::EMPTY_MATCH {
                let key = Arc::as_ptr(&re.sub[0]);
                write_regexp(b, &re.sub[0], flags.get(&key).copied().unwrap_or(0), flags);
            }
            b.push(')');
        }
        Op::STAR | Op::PLUS | Op::QUEST | Op::REPEAT => {
            let sub = &re.sub[0];
            let mut p = 0;
            if sub.op > Op::CAPTURE || sub.op == Op::LITERAL && sub.rune.len() > 1 {
                p = FLAG_PREC;
            }
            write_regexp(b, sub, p, flags);
            match re.op {
                Op::STAR => b.push('*'),
                Op::PLUS => b.push('+'),
                Op::QUEST => b.push('?'),
                _ => {
                    b.push('{');
                    b.push_str(&re.min.to_string());
                    if re.max != re.min {
                        b.push(',');
                        if re.max >= 0 {
                            b.push_str(&re.max.to_string());
                        }
                    }
                    b.push('}');
                }
            }
            if re.flags & Flags::NON_GREEDY != Flags(0) {
                b.push('?');
            }
        }
        Op::CONCAT => {
            for sub in &re.sub {
                let p = if sub.op == Op::ALTERNATE {
                    FLAG_PREC
                } else {
                    0
                };
                write_regexp(b, sub, p, flags);
            }
        }
        Op::ALTERNATE => {
            for (i, sub) in re.sub.iter().enumerate() {
                if i > 0 {
                    b.push('|');
                }
                write_regexp(b, sub, 0, flags);
            }
        }
        other => {
            b.push_str("<invalid op");
            b.push_str(&other.0.to_string());
            b.push('>');
        }
    }
    for _ in 0..suffix {
        b.push(')');
    }
}

fn write_class(b: &mut String, rune: &[i32]) {
    if !rune.len().is_multiple_of(2) {
        b.push_str("[invalid char class]");
        return;
    }
    b.push('[');
    if rune.is_empty() {
        b.push_str(r"^\x00-\x{10FFFF}");
    } else if rune[0] == 0 && rune[rune.len() - 1] == unicode::MAX_RUNE && rune.len() > 2 {
        // Contains 0 and MaxRune: print as a negated class.
        b.push('^');
        let mut i = 1;
        while i < rune.len() - 1 {
            write_pair(b, rune[i] + 1, rune[i + 1] - 1);
            i += 2;
        }
    } else {
        for pair in rune.chunks(2) {
            write_pair(b, pair[0], pair[1]);
        }
    }
    b.push(']');
}

fn write_pair(b: &mut String, lo: i32, hi: i32) {
    escape(b, lo, lo == '-' as i32);
    if lo != hi {
        // Two adjacent runes print as "ab", not "a-b".
        if hi != lo + 1 {
            b.push('-');
        }
        escape(b, hi, hi == '-' as i32);
    }
}

const META: &str = r"\.+*?()|[]{}^$";

fn escape(b: &mut String, r: i32, force: bool) {
    if unicode::is_print(r) {
        if let Some(c) = char::from_u32(r as u32) {
            if META.contains(c) || force {
                b.push('\\');
            }
            b.push(c);
            return;
        }
    }
    match r {
        7 => b.push_str(r"\a"),
        12 => b.push_str(r"\f"),
        10 => b.push_str(r"\n"),
        13 => b.push_str(r"\r"),
        9 => b.push_str(r"\t"),
        11 => b.push_str(r"\v"),
        _ if r < 0x100 => b.push_str(&format!(r"\x{r:02x}")),
        _ => b.push_str(&format!(r"\x{{{r:x}}}")),
    }
}

impl fmt::Display for Regexp {
    /// Returns a string representation of the expression, a pattern that
    /// parses back to an equivalent tree.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags = FlagMap::new();
        let (mut must, cant) = calc_flags(self, &mut flags);
        must |= (cant & !FLAG_I) << NEG_SHIFT;
        if must != 0 {
            must |= FLAG_OFF;
        }
        let mut b = String::new();
        write_regexp(&mut b, self, must, &flags);
        f.write_str(&b)
    }
}
