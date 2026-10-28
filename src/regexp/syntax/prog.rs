//! Compiled programs (Go `regexp/syntax/prog.go`).
use super::Flags;
use crate::unicode;
use std::{fmt, ops};

/// A compiled regular expression program.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Prog {
    pub inst: Vec<Inst>,
    /// Index of the start instruction.
    pub start: usize,
    /// Number of `CAPTURE` instructions in the program.
    pub num_cap: usize,
}

/// The operator of an [`Inst`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct InstOp(pub u8);

impl InstOp {
    pub const ALT: InstOp = InstOp(0);
    pub const ALT_MATCH: InstOp = InstOp(1);
    pub const CAPTURE: InstOp = InstOp(2);
    pub const EMPTY_WIDTH: InstOp = InstOp(3);
    pub const MATCH: InstOp = InstOp(4);
    pub const FAIL: InstOp = InstOp(5);
    pub const NOP: InstOp = InstOp(6);
    pub const RUNE: InstOp = InstOp(7);
    pub const RUNE1: InstOp = InstOp(8);
    pub const RUNE_ANY: InstOp = InstOp(9);
    pub const RUNE_ANY_NOT_NL: InstOp = InstOp(10);
}

const INST_OP_NAMES: [&str; 11] = [
    "InstAlt",
    "InstAltMatch",
    "InstCapture",
    "InstEmptyWidth",
    "InstMatch",
    "InstFail",
    "InstNop",
    "InstRune",
    "InstRune1",
    "InstRuneAny",
    "InstRuneAnyNotNL",
];

impl fmt::Display for InstOp {
    /// Go's names; an out-of-range operator prints as the empty string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            INST_OP_NAMES
                .get(usize::from(self.0))
                .copied()
                .unwrap_or(""),
        )
    }
}

/// Conditions of an `EMPTY_WIDTH` instruction, a bit set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct EmptyOp(pub u8);

impl EmptyOp {
    pub const BEGIN_LINE: EmptyOp = EmptyOp(1);
    pub const END_LINE: EmptyOp = EmptyOp(2);
    pub const BEGIN_TEXT: EmptyOp = EmptyOp(4);
    pub const END_TEXT: EmptyOp = EmptyOp(8);
    pub const WORD_BOUNDARY: EmptyOp = EmptyOp(16);
    pub const NO_WORD_BOUNDARY: EmptyOp = EmptyOp(32);
}
impl ops::BitOr for EmptyOp {
    type Output = EmptyOp;
    fn bitor(self, o: EmptyOp) -> EmptyOp {
        EmptyOp(self.0 | o.0)
    }
}
impl ops::BitAnd for EmptyOp {
    type Output = EmptyOp;
    fn bitand(self, o: EmptyOp) -> EmptyOp {
        EmptyOp(self.0 & o.0)
    }
}
impl ops::BitXor for EmptyOp {
    type Output = EmptyOp;
    fn bitxor(self, o: EmptyOp) -> EmptyOp {
        EmptyOp(self.0 ^ o.0)
    }
}
impl ops::Not for EmptyOp {
    type Output = EmptyOp;
    fn not(self) -> EmptyOp {
        EmptyOp(!self.0)
    }
}
impl ops::BitOrAssign for EmptyOp {
    fn bitor_assign(&mut self, o: EmptyOp) {
        self.0 |= o.0;
    }
}

/// Returns the zero-width assertions satisfied at the position between the
/// runes `r1` and `r2`. A negative rune stands for the beginning (`r1`) or end
/// (`r2`) of the text.
pub fn empty_op_context(r1: i32, r2: i32) -> EmptyOp {
    let mut op = EmptyOp::NO_WORD_BOUNDARY;
    let mut boundary = 0u8;
    if is_word_char(r1) {
        boundary = 1;
    } else if r1 == '\n' as i32 {
        op |= EmptyOp::BEGIN_LINE;
    } else if r1 < 0 {
        op |= EmptyOp::BEGIN_TEXT | EmptyOp::BEGIN_LINE;
    }
    if is_word_char(r2) {
        boundary ^= 1;
    } else if r2 == '\n' as i32 {
        op |= EmptyOp::END_LINE;
    } else if r2 < 0 {
        op |= EmptyOp::END_TEXT | EmptyOp::END_LINE;
    }
    if boundary != 0 {
        // IsWordChar(r1) != IsWordChar(r2)
        op = op ^ (EmptyOp::WORD_BOUNDARY | EmptyOp::NO_WORD_BOUNDARY);
    }
    op
}

/// Reports whether `r` is an ASCII word character, as used by `\b`.
pub fn is_word_char(r: i32) -> bool {
    (0x61..=0x7a).contains(&r)
        || (0x41..=0x5a).contains(&r)
        || (0x30..=0x39).contains(&r)
        || r == 0x5f
}

/// A single instruction in a [`Prog`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Inst {
    pub op: InstOp,
    /// All but `MATCH` and `FAIL`.
    pub out: u32,
    /// `ALT`, `ALT_MATCH`, `CAPTURE`, `EMPTY_WIDTH`; for the rune operators the
    /// [`Flags`] bits (only `FOLD_CASE` is set).
    pub arg: u32,
    /// `RUNE`: a single rune, or range pairs.
    pub rune: Vec<i32>,
}

impl fmt::Display for Prog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (j, i) in self.inst.iter().enumerate() {
            let mut pc = j.to_string();
            if pc.len() < 3 {
                f.write_str(&"   "[pc.len()..])?;
            }
            if j == self.start {
                pc.push('*');
            }
            writeln!(f, "{pc}\t{i}")?;
        }
        Ok(())
    }
}

impl Prog {
    fn skip_nop(&self, mut pc: u32) -> &Inst {
        let mut i = &self.inst[pc as usize];
        while i.op == InstOp::NOP || i.op == InstOp::CAPTURE {
            pc = i.out;
            i = &self.inst[pc as usize];
        }
        i
    }

    /// Returns a literal string that all matches for the regexp must start
    /// with, and whether the literal is the complete regexp.
    pub fn prefix(&self) -> (String, bool) {
        let mut i = self.skip_nop(self.start as u32);
        // Avoid allocation of buffer if prefix is empty.
        if i.simple_op() != InstOp::RUNE || i.rune.len() != 1 {
            return (String::new(), i.op == InstOp::MATCH);
        }
        let mut buf = String::new();
        while i.simple_op() == InstOp::RUNE
            && i.rune.len() == 1
            && Flags(i.arg as u16) & Flags::FOLD_CASE == Flags(0)
            && i.rune[0] != unicode::rune::RUNE_ERROR
        {
            buf.push(char::from_u32(i.rune[0] as u32).unwrap_or('\u{fffd}'));
            i = self.skip_nop(i.out);
        }
        (buf, i.op == InstOp::MATCH)
    }

    /// Returns the `EmptyOp` flags that must be true for any match to exist at
    /// the start of the program, or all bits set when no match is possible.
    pub fn start_cond(&self) -> EmptyOp {
        let mut flag = EmptyOp(0);
        let mut i = &self.inst[self.start];
        loop {
            match i.op {
                InstOp::EMPTY_WIDTH => flag |= EmptyOp(i.arg as u8),
                InstOp::FAIL => return EmptyOp(!0),
                InstOp::CAPTURE | InstOp::NOP => {}
                _ => break,
            }
            i = &self.inst[i.out as usize];
        }
        flag
    }
}

const NO_MATCH: isize = -1;

impl Inst {
    /// Normalizes the three single-purpose rune operators to `RUNE`.
    fn simple_op(&self) -> InstOp {
        match self.op {
            InstOp::RUNE1 | InstOp::RUNE_ANY | InstOp::RUNE_ANY_NOT_NL => InstOp::RUNE,
            op => op,
        }
    }

    /// Reports whether the instruction matches (and consumes) `r`. It should
    /// only be called when `op` is `RUNE`, `RUNE1`, `RUNE_ANY` or
    /// `RUNE_ANY_NOT_NL`.
    pub fn match_rune(&self, r: i32) -> bool {
        self.match_rune_pos(r) != NO_MATCH
    }

    /// Like [`match_rune`](Inst::match_rune) but returns the index of the
    /// matching range pair (0 for a single rune), or -1.
    pub fn match_rune_pos(&self, r: i32) -> isize {
        let rune = &self.rune;
        match rune.len() {
            0 => return NO_MATCH,
            1 => {
                let r0 = rune[0];
                if r == r0 {
                    return 0;
                }
                if Flags(self.arg as u16) & Flags::FOLD_CASE != Flags(0) {
                    let mut r1 = unicode::simple_fold(r0);
                    while r1 != r0 {
                        if r == r1 {
                            return 0;
                        }
                        r1 = unicode::simple_fold(r1);
                    }
                }
                return NO_MATCH;
            }
            2 => {
                return if r >= rune[0] && r <= rune[1] {
                    0
                } else {
                    NO_MATCH
                };
            }
            4 | 6 | 8 => {
                // Linear search for a few pairs.
                for j in (0..rune.len()).step_by(2) {
                    if r < rune[j] {
                        return NO_MATCH;
                    }
                    if r <= rune[j + 1] {
                        return (j / 2) as isize;
                    }
                }
                return NO_MATCH;
            }
            _ => {}
        }
        // Otherwise binary search.
        let (mut lo, mut hi) = (0, rune.len() / 2);
        while lo < hi {
            let m = (lo + hi) / 2;
            if rune[2 * m] <= r {
                if r <= rune[2 * m + 1] {
                    return m as isize;
                }
                lo = m + 1;
            } else {
                hi = m;
            }
        }
        NO_MATCH
    }

    /// Reports whether the instruction matches the empty string between the
    /// runes `before` and `after`. It should only be called when `op` is
    /// `EMPTY_WIDTH`; any other argument panics like Go.
    pub fn match_empty_width(&self, before: i32, after: i32) -> bool {
        match EmptyOp(self.arg as u8) {
            EmptyOp::BEGIN_LINE => before == '\n' as i32 || before == -1,
            EmptyOp::END_LINE => after == '\n' as i32 || after == -1,
            EmptyOp::BEGIN_TEXT => before == -1,
            EmptyOp::END_TEXT => after == -1,
            EmptyOp::WORD_BOUNDARY => is_word_char(before) != is_word_char(after),
            EmptyOp::NO_WORD_BOUNDARY => is_word_char(before) == is_word_char(after),
            _ => panic!("unknown empty width arg"),
        }
    }
}

/// Go's `strconv.QuoteToASCII` of the string made from `runes`.
fn quote_to_ascii(runes: &[i32]) -> String {
    let mut s = String::from("\"");
    for &r in runes {
        let c = char::from_u32(r as u32).unwrap_or('\u{fffd}');
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '\x07' => s.push_str("\\a"),
            '\x08' => s.push_str("\\b"),
            '\x0c' => s.push_str("\\f"),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            '\x0b' => s.push_str("\\v"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                s.push_str(&format!("\\x{:02x}", c as u32))
            }
            c if c.is_ascii() => s.push(c),
            c if (c as u32) < 0x10000 => s.push_str(&format!("\\u{:04x}", c as u32)),
            c => s.push_str(&format!("\\U{:08x}", c as u32)),
        }
    }
    s.push('"');
    s
}

impl fmt::Display for Inst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (out, arg) = (self.out, self.arg);
        match self.op {
            InstOp::ALT => write!(f, "alt -> {out}, {arg}"),
            InstOp::ALT_MATCH => write!(f, "altmatch -> {out}, {arg}"),
            InstOp::CAPTURE => write!(f, "cap {arg} -> {out}"),
            InstOp::EMPTY_WIDTH => write!(f, "empty {arg} -> {out}"),
            InstOp::MATCH => f.write_str("match"),
            InstOp::FAIL => f.write_str("fail"),
            InstOp::NOP => write!(f, "nop -> {out}"),
            InstOp::RUNE => {
                write!(f, "rune {}", quote_to_ascii(&self.rune))?;
                if Flags(arg as u16) & Flags::FOLD_CASE != Flags(0) {
                    f.write_str("/i")?;
                }
                write!(f, " -> {out}")
            }
            InstOp::RUNE1 => write!(f, "rune1 {} -> {out}", quote_to_ascii(&self.rune)),
            InstOp::RUNE_ANY => write!(f, "any -> {out}"),
            InstOp::RUNE_ANY_NOT_NL => write!(f, "anynotnl -> {out}"),
            _ => Ok(()),
        }
    }
}
