//! The one-pass matcher (Go `regexp/onepass.go`).
//!
//! A program anchored at the start of text in which every alternation can be
//! decided by the next input rune ("one-pass") runs without thread lists or
//! backtracking: each step follows exactly one instruction. This module
//! decides whether a program is one-pass (`compileOnePass`), builds the
//! dispatch tables, and runs it (`doOnePass`).
use super::exec::{Input, LazyFlag, Params, END_OF_TEXT};
use super::syntax::{EmptyOp, Flags, Inst, InstOp, Prog};
use crate::unicode;

const MERGE_FAILED: u32 = 0xffff_ffff;
const MAX_RUNE: i32 = unicode::MAX_RUNE;

fn is_alt(op: InstOp) -> bool {
    op == InstOp::ALT || op == InstOp::ALT_MATCH
}

/// Go's `iop`: the three single-purpose rune instructions count as `RUNE`.
fn iop(i: &Inst) -> InstOp {
    match i.op {
        InstOp::RUNE1 | InstOp::RUNE_ANY | InstOp::RUNE_ANY_NOT_NL => InstOp::RUNE,
        op => op,
    }
}

/// Returns the literal prefix following a leading `\A` of an anchored
/// program, whether that prefix is the whole expression, and the instruction
/// after the prefix (Go `onePassPrefix`).
pub(super) fn one_pass_prefix(p: &Prog) -> (String, bool, u32) {
    let mut i = &p.inst[p.start];
    if i.op != InstOp::EMPTY_WIDTH || EmptyOp(i.arg as u8) & EmptyOp::BEGIN_TEXT == EmptyOp(0) {
        return (String::new(), i.op == InstOp::MATCH, p.start as u32);
    }
    let mut pc = i.out;
    i = &p.inst[pc as usize];
    while i.op == InstOp::NOP {
        pc = i.out;
        i = &p.inst[pc as usize];
    }
    // Avoid allocation of buffer if prefix is empty.
    if iop(i) != InstOp::RUNE || i.rune.len() != 1 {
        return (String::new(), i.op == InstOp::MATCH, p.start as u32);
    }

    // Have prefix; gather characters.
    let mut buf = String::new();
    while iop(i) == InstOp::RUNE
        && i.rune.len() == 1
        && Flags(i.arg as u16) & Flags::FOLD_CASE == Flags(0)
        && i.rune[0] != unicode::rune::RUNE_ERROR
    {
        buf.push(char::from_u32(i.rune[0] as u32).unwrap_or('\u{fffd}'));
        pc = i.out;
        i = &p.inst[pc as usize];
    }
    let complete = i.op == InstOp::EMPTY_WIDTH
        && EmptyOp(i.arg as u8) & EmptyOp::END_TEXT != EmptyOp(0)
        && p.inst[i.out as usize].op == InstOp::MATCH;
    (buf, complete, pc)
}

#[derive(Clone, Copy, PartialEq)]
enum Field {
    Out,
    Arg,
}

fn get(inst: &Inst, f: Field) -> u32 {
    match f {
        Field::Out => inst.out,
        Field::Arg => inst.arg,
    }
}

fn set(inst: &mut Inst, f: Field, v: u32) {
    match f {
        Field::Out => inst.out = v,
        Field::Arg => inst.arg = v,
    }
}

/// Sparse set with a cursor, Go's `queueOnePass`.
struct Queue {
    sparse: Vec<u32>,
    dense: Vec<u32>,
    size: u32,
    next_index: u32,
}

impl Queue {
    fn new(size: usize) -> Queue {
        Queue {
            sparse: vec![0; size],
            dense: vec![0; size],
            size: 0,
            next_index: 0,
        }
    }
    fn empty(&self) -> bool {
        self.next_index >= self.size
    }
    fn next(&mut self) -> u32 {
        let n = self.dense[self.next_index as usize];
        self.next_index += 1;
        n
    }
    fn clear(&mut self) {
        self.size = 0;
        self.next_index = 0;
    }
    fn contains(&self, u: u32) -> bool {
        if u as usize >= self.sparse.len() {
            return false;
        }
        self.sparse[u as usize] < self.size && self.dense[self.sparse[u as usize] as usize] == u
    }
    fn insert(&mut self, u: u32) {
        if !self.contains(u) {
            self.insert_new(u);
        }
    }
    fn insert_new(&mut self, u: u32) {
        if u as usize >= self.sparse.len() {
            return;
        }
        self.sparse[u as usize] = self.size;
        self.dense[self.size as usize] = u;
        self.size += 1;
    }
}

/// Merges two sorted range-pair lists into one, remembering for each merged
/// range which instruction it leads to. Fails (returns `None`) when the two
/// overlap, i.e. when a rune could take either branch.
fn merge_rune_sets(
    left: &[i32],
    right: &[i32],
    left_pc: u32,
    right_pc: u32,
) -> Option<(Vec<i32>, Vec<u32>)> {
    let (mut lx, mut rx) = (0, 0);
    let mut merged: Vec<i32> = Vec::new();
    let mut next: Vec<u32> = Vec::new();
    while lx < left.len() || rx < right.len() {
        let (src, at, pc) = if rx >= right.len() {
            (left, &mut lx, left_pc)
        } else if lx >= left.len() || right[rx] < left[lx] {
            (right, &mut rx, right_pc)
        } else {
            (left, &mut lx, left_pc)
        };
        if !merged.is_empty() && src[*at] <= merged[merged.len() - 1] {
            return None;
        }
        merged.push(src[*at]);
        merged.push(src[*at + 1]);
        *at += 2;
        next.push(pc);
    }
    Some((merged, next))
}

struct OnePass {
    inst: Vec<Inst>,
    next: Vec<Vec<u32>>,
    runes: Vec<Vec<i32>>,
    inst_queue: Queue,
    visit_queue: Queue,
    m: Vec<bool>,
}

fn fold_orbit_runes(r0: i32) -> Vec<i32> {
    let mut runes = vec![r0, r0];
    let mut r1 = unicode::simple_fold(r0);
    while r1 != r0 {
        runes.push(r1);
        runes.push(r1);
        r1 = unicode::simple_fold(r1);
    }
    runes.sort_unstable();
    runes
}

impl OnePass {
    /// Records the decision for `pc`; returns false when the program is not
    /// one-pass.
    fn check(&mut self, pc: u32) -> bool {
        let p = pc as usize;
        if self.visit_queue.contains(pc) {
            return true;
        }
        self.visit_queue.insert(pc);
        let mut ok = true;
        match self.inst[p].op {
            InstOp::ALT | InstOp::ALT_MATCH => {
                let (out, arg) = (self.inst[p].out, self.inst[p].arg);
                ok = self.check(out) && self.check(arg);
                // check no-input paths to InstMatch
                let (out, arg) = (self.inst[p].out, self.inst[p].arg);
                let mut match_out = self.m[out as usize];
                let match_arg = self.m[arg as usize];
                if match_out && match_arg {
                    return false;
                }
                // Match on empty goes in inst.Out
                if match_arg {
                    let i = &mut self.inst[p];
                    std::mem::swap(&mut i.out, &mut i.arg);
                    match_out = true;
                }
                if match_out {
                    self.m[p] = true;
                    self.inst[p].op = InstOp::ALT_MATCH;
                }

                // build a dispatch operator from the two legs
                let (out, arg) = (self.inst[p].out, self.inst[p].arg);
                let merged = {
                    let (l, r) = (&self.runes[out as usize], &self.runes[arg as usize]);
                    merge_rune_sets(l, r, out, arg)
                };
                match merged {
                    Some((runes, next)) => {
                        self.runes[p] = runes;
                        self.next[p] = next;
                    }
                    None => {
                        self.runes[p] = Vec::new();
                        self.next[p] = vec![MERGE_FAILED];
                        return false;
                    }
                }
            }
            InstOp::CAPTURE | InstOp::NOP | InstOp::EMPTY_WIDTH => {
                let out = self.inst[p].out;
                ok = self.check(out);
                self.m[p] = self.m[out as usize];
                // pass matching runes back through these no-ops.
                self.runes[p] = self.runes[out as usize].clone();
                self.next[p] = vec![out; self.runes[p].len() / 2 + 1];
            }
            InstOp::MATCH | InstOp::FAIL => {
                self.m[p] = self.inst[p].op == InstOp::MATCH;
            }
            InstOp::RUNE => {
                self.m[p] = false;
                if !self.next[p].is_empty() {
                    return ok;
                }
                let out = self.inst[p].out;
                self.inst_queue.insert(out);
                if self.inst[p].rune.is_empty() {
                    self.runes[p] = Vec::new();
                    self.next[p] = vec![out];
                    return ok;
                }
                let i = &self.inst[p];
                let runes =
                    if i.rune.len() == 1 && Flags(i.arg as u16) & Flags::FOLD_CASE != Flags(0) {
                        fold_orbit_runes(i.rune[0])
                    } else {
                        i.rune.clone()
                    };
                self.next[p] = vec![out; runes.len() / 2 + 1];
                self.runes[p] = runes;
                self.inst[p].op = InstOp::RUNE;
            }
            InstOp::RUNE1 => {
                self.m[p] = false;
                if !self.next[p].is_empty() {
                    return ok;
                }
                let out = self.inst[p].out;
                self.inst_queue.insert(out);
                let i = &self.inst[p];
                let runes = if Flags(i.arg as u16) & Flags::FOLD_CASE != Flags(0) {
                    fold_orbit_runes(i.rune[0])
                } else {
                    vec![i.rune[0], i.rune[0]]
                };
                self.next[p] = vec![out; runes.len() / 2 + 1];
                self.runes[p] = runes;
                self.inst[p].op = InstOp::RUNE;
            }
            InstOp::RUNE_ANY => {
                self.m[p] = false;
                if !self.next[p].is_empty() {
                    return ok;
                }
                let out = self.inst[p].out;
                self.inst_queue.insert(out);
                self.runes[p] = vec![0, MAX_RUNE];
                self.next[p] = vec![out];
            }
            InstOp::RUNE_ANY_NOT_NL => {
                self.m[p] = false;
                if !self.next[p].is_empty() {
                    return ok;
                }
                let out = self.inst[p].out;
                self.inst_queue.insert(out);
                self.runes[p] = vec![0, '\n' as i32 - 1, '\n' as i32 + 1, MAX_RUNE];
                self.next[p] = vec![out; self.runes[p].len() / 2 + 1];
            }
            _ => {}
        }
        ok
    }
}

/// A one-pass program: the instructions with their rune sets merged into
/// dispatch tables. For `ALT`, `ALT_MATCH` and `RUNE`, `rune` holds sorted
/// range pairs and `next[k]` is the instruction taken for pair `k`.
pub(crate) struct OnePassProg {
    inst: Vec<Inst>,
    next: Vec<Vec<u32>>,
    start: usize,
}

/// Returns the one-pass form of the program, or `None` if it is not one-pass
/// (Go `compileOnePass`).
pub(super) fn compile_one_pass(prog: &Prog) -> Option<OnePassProg> {
    if prog.start == 0 {
        return None;
    }
    let s = &prog.inst[prog.start];
    if s.op != InstOp::EMPTY_WIDTH
        || EmptyOp(s.arg as u8) & EmptyOp::BEGIN_TEXT != EmptyOp::BEGIN_TEXT
    {
        return None;
    }
    // every instruction leading to InstMatch must be EmptyEndText
    let has_alt = prog.inst.iter().any(|i| is_alt(i.op));
    for inst in &prog.inst {
        let op_out = prog.inst[inst.out as usize].op;
        match inst.op {
            InstOp::ALT | InstOp::ALT_MATCH => {
                // If this is a Alt/AltMatch, check both branches.
                if op_out == InstOp::MATCH || prog.inst[inst.arg as usize].op == InstOp::MATCH {
                    return None;
                }
            }
            InstOp::EMPTY_WIDTH => {
                // Match on empty goes in inst.Out
                if op_out == InstOp::MATCH {
                    if EmptyOp(inst.arg as u8) & EmptyOp::END_TEXT == EmptyOp::END_TEXT {
                        continue;
                    }
                    return None;
                }
            }
            _ => {
                // Match on empty goes in inst.Out
                if op_out == InstOp::MATCH && has_alt {
                    return None;
                }
            }
        }
    }

    let mut inst = prog.inst.clone();
    one_pass_copy(&mut inst);
    let mut op = make_one_pass(inst, prog.start)?;
    cleanup_one_pass(&mut op, prog);
    Some(op)
}

/// Restores the single-purpose rune instructions the analysis widened, and
/// drops the tables of instructions that do not dispatch (Go
/// `cleanupOnePass`).
fn cleanup_one_pass(op: &mut OnePassProg, original: &Prog) {
    for (ix, orig) in original.inst.iter().enumerate() {
        match orig.op {
            InstOp::ALT | InstOp::ALT_MATCH | InstOp::RUNE => {}
            InstOp::RUNE1 | InstOp::RUNE_ANY | InstOp::RUNE_ANY_NOT_NL => {
                op.next[ix] = Vec::new();
                op.inst[ix] = orig.clone();
            }
            _ => op.next[ix] = Vec::new(),
        }
    }
}

/// Rewrites alternations of the form `(x|(y|x...))` loops so that the
/// analysis sees the same choice points (Go `onePassCopy`).
fn one_pass_copy(inst: &mut [Inst]) {
    for pc in 0..inst.len() {
        if !is_alt(inst[pc].op) {
            continue;
        }
        // p_A_Other and p_A_Alt name the fields of inst[pc].
        let (mut a_other, mut a_alt) = (Field::Out, Field::Arg);
        let mut alt_idx = get(&inst[pc], a_alt) as usize;
        if !is_alt(inst[alt_idx].op) {
            std::mem::swap(&mut a_other, &mut a_alt);
            alt_idx = get(&inst[pc], a_alt) as usize;
            if !is_alt(inst[alt_idx].op) {
                continue;
            }
        }
        let other_idx = get(&inst[pc], a_other) as usize;
        if is_alt(inst[other_idx].op) {
            continue;
        }
        let inst_alt = inst[alt_idx].clone();
        let (mut b_alt, mut b_other) = (Field::Out, Field::Arg);
        let mut patch = false;
        if inst_alt.out == pc as u32 {
            patch = true;
        } else if inst_alt.arg == pc as u32 {
            patch = true;
            std::mem::swap(&mut b_alt, &mut b_other);
        }
        if patch {
            let v = get(&inst[pc], a_other);
            set(&mut inst[alt_idx], b_alt, v);
        }
        if get(&inst[pc], a_other) == get(&inst[alt_idx], b_alt) {
            let v = get(&inst[alt_idx], b_other);
            set(&mut inst[pc], a_alt, v);
        }
    }
}

fn make_one_pass(inst: Vec<Inst>, start: usize) -> Option<OnePassProg> {
    if inst.len() >= 1000 {
        return None;
    }
    let n = inst.len();
    let mut op = OnePass {
        inst,
        next: vec![Vec::new(); n],
        runes: vec![Vec::new(); n],
        inst_queue: Queue::new(n),
        visit_queue: Queue::new(n),
        m: vec![false; n],
    };
    op.inst_queue.clear();
    op.inst_queue.insert(start as u32);
    while !op.inst_queue.empty() {
        op.visit_queue.clear();
        let pc = op.inst_queue.next();
        if !op.check(pc) {
            return None;
        }
    }
    let mut inst = op.inst;
    for (i, runes) in inst.iter_mut().zip(op.runes) {
        i.rune = runes;
    }
    Some(OnePassProg {
        inst,
        next: op.next,
        start,
    })
}

impl OnePassProg {
    /// The instruction an `ALT` or `ALT_MATCH` takes on rune `r` (Go
    /// `onePassNext`); 0, the fail instruction, when neither branch can.
    fn next(&self, pc: usize, r: i32) -> u32 {
        let i = &self.inst[pc];
        let next = i.match_rune_pos(r);
        if next >= 0 {
            return self.next[pc][next as usize];
        }
        if i.op == InstOp::ALT_MATCH {
            return i.out;
        }
        0
    }

    /// Runs the program over `i` from `pos` (Go `doOnePass`). A one-pass
    /// program begins with `\A`, so only a search from 0 can match. On a match
    /// the capture positions are left in `matchcap`.
    pub(crate) fn run<I: Input>(
        &self,
        p: &Params<'_>,
        i: &mut I,
        mut pos: usize,
        ncap: usize,
        matchcap: &mut Vec<isize>,
    ) -> bool {
        if p.cond == EmptyOp(!0) {
            // impossible
            return false;
        }
        matchcap.clear();
        matchcap.resize(ncap, -1);

        let (mut r, mut width) = i.step(pos);
        let (mut r1, mut width1) = (END_OF_TEXT, 0);
        if r != END_OF_TEXT {
            (r1, width1) = i.step(pos + width);
        }
        let mut flag = if pos == 0 {
            LazyFlag::new(-1, r)
        } else {
            i.context(pos)
        };
        let mut pc = self.start;
        // If there is a simple literal prefix, skip over it.
        if pos == 0
            && flag.matches(EmptyOp(self.inst[pc].arg as u8))
            && !p.prefix.is_empty()
            && i.can_check_prefix()
        {
            // Match requires literal prefix; fast search for it.
            if !i.has_prefix(p.prefix) {
                return false;
            }
            pos += p.prefix.len();
            (r, width) = i.step(pos);
            (r1, width1) = i.step(pos + width);
            flag = i.context(pos);
            pc = p.prefix_end as usize;
        }
        loop {
            let cur = pc;
            let inst = &self.inst[cur];
            pc = inst.out as usize;
            match inst.op {
                InstOp::MATCH => {
                    if !matchcap.is_empty() {
                        matchcap[0] = 0;
                        matchcap[1] = pos as isize;
                    }
                    return true;
                }
                InstOp::RUNE => {
                    if !inst.match_rune(r) {
                        return false;
                    }
                }
                InstOp::RUNE1 => {
                    if r != inst.rune[0] {
                        return false;
                    }
                }
                InstOp::RUNE_ANY => {}
                InstOp::RUNE_ANY_NOT_NL => {
                    if r == '\n' as i32 {
                        return false;
                    }
                }
                // Peek at the input rune to see which branch of the Alt to take.
                InstOp::ALT | InstOp::ALT_MATCH => {
                    pc = self.next(cur, r) as usize;
                    continue;
                }
                InstOp::NOP => continue,
                InstOp::EMPTY_WIDTH => {
                    if !flag.matches(EmptyOp(inst.arg as u8)) {
                        return false;
                    }
                    continue;
                }
                InstOp::CAPTURE => {
                    if (inst.arg as usize) < matchcap.len() {
                        matchcap[inst.arg as usize] = pos as isize;
                    }
                    continue;
                }
                // FAIL.
                _ => return false,
            }
            if width == 0 {
                return false;
            }
            flag = LazyFlag::new(r, r1);
            pos += width;
            (r, width) = (r1, width1);
            if r != END_OF_TEXT {
                (r1, width1) = i.step(pos + width);
            }
        }
    }
}
