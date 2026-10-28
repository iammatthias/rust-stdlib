//! The bit-state backtracker (Go `regexp/backtrack.go`): a depth-first search
//! with submatch tracking for small programs on short byte inputs. A visited
//! bitmap of (instruction, position) pairs ensures no state is explored
//! twice, so a search stays linear in the input length; the bitmap's size,
//! program length x (input length + 1) bits, is what limits where it is used.
//!
//! Unlike Go, the bitmap is laid out position-major and only the words a
//! search touched are cleared afterwards, so a search that stops early (one
//! anchored at an offset, say) does not pay to clear the whole bitmap. The
//! set of visited states, and so every result, is the same.
use super::exec::{Input, LazyFlag, Params};
use super::syntax::{EmptyOp, InstOp, Prog};

const VISITED_BITS: usize = 32;
const MAX_BACKTRACK_PROG: usize = 500;
const MAX_BACKTRACK_VECTOR: usize = 256 * 1024;

/// The longest input (exclusive) the backtracker runs on for `prog`; 0 when
/// the program is too long for it (Go `maxBitStateLen`).
pub(crate) fn max_bit_state_len(prog: &Prog) -> usize {
    if prog.inst.len() > MAX_BACKTRACK_PROG {
        return 0;
    }
    MAX_BACKTRACK_VECTOR / prog.inst.len()
}

/// An entry on the job stack. `arg` marks a continuation: for `ALT`, try the
/// second branch; for `CAPTURE`, restore the slot to `pos`, the old value
/// (which may be -1).
#[derive(Clone, Copy)]
struct Job {
    pc: u32,
    arg: bool,
    pos: isize,
}

/// Reusable backtracker state.
#[derive(Default)]
pub(crate) struct BitState {
    end: usize,
    ninst: usize,
    cap: Vec<isize>,
    pub(crate) matchcap: Vec<isize>,
    jobs: Vec<Job>,
    /// Bit `pos * ninst + pc` marks `(pc, pos)` visited. All zero between
    /// searches, except for words `dirty`.
    visited: Vec<u32>,
    dirty: std::ops::Range<usize>,
}

impl BitState {
    fn reset(&mut self, prog: &Prog, end: usize, ncap: usize) {
        self.end = end;
        self.ninst = prog.inst.len();
        self.jobs.clear();
        let visited_size = (self.ninst * (end + 1)).div_ceil(VISITED_BITS);
        let dirty = std::mem::take(&mut self.dirty);
        self.visited[dirty].fill(0);
        if self.visited.len() < visited_size {
            self.visited.resize(visited_size, 0);
        }
        self.cap.clear();
        self.cap.resize(ncap, -1);
        self.matchcap.clear();
        self.matchcap.resize(ncap, -1);
    }

    /// Reports whether `(pc, pos)` is new, and marks it visited.
    fn should_visit(&mut self, pc: u32, pos: usize) -> bool {
        let n = pos * self.ninst + pc as usize;
        let (word, bit) = (n / VISITED_BITS, 1u32 << (n % VISITED_BITS));
        if self.visited[word] & bit != 0 {
            return false;
        }
        self.visited[word] |= bit;
        if self.dirty.is_empty() {
            self.dirty = word..word + 1;
        } else {
            self.dirty.start = self.dirty.start.min(word);
            self.dirty.end = self.dirty.end.max(word + 1);
        }
        true
    }

    fn push(&mut self, prog: &Prog, pc: u32, pos: isize, arg: bool) {
        // A continuation (arg) resumes a visit that was already checked.
        if prog.inst[pc as usize].op != InstOp::FAIL && (arg || self.should_visit(pc, pos as usize))
        {
            self.jobs.push(Job { pc, arg, pos });
        }
    }

    /// Runs a backtracking search from `(pc0, pos0)` for a match starting at
    /// `pos0`.
    fn try_backtrack<I: Input>(
        &mut self,
        prog: &Prog,
        longest: bool,
        i: &mut I,
        pc0: u32,
        pos0: usize,
    ) -> bool {
        self.push(prog, pc0, pos0 as isize, false);
        while let Some(job) = self.jobs.pop() {
            let (mut pc, mut pos, mut arg) = (job.pc, job.pos, job.arg);
            // A popped job was checked when pushed; every later step is not.
            let mut check = false;
            loop {
                if check && !self.should_visit(pc, pos as usize) {
                    break;
                }
                check = true;
                let inst = &prog.inst[pc as usize];
                match inst.op {
                    InstOp::ALT => {
                        // Push a reminder to try inst.arg after inst.out rather
                        // than inst.arg itself: if inst.out reaches inst.arg by
                        // another path, it must be explored from there.
                        if arg {
                            arg = false;
                            pc = inst.arg;
                        } else {
                            self.push(prog, pc, pos, true);
                            pc = inst.out;
                        }
                    }
                    InstOp::ALT_MATCH => {
                        // One branch consumes runes; the other leads to match.
                        let end = self.end as isize;
                        match prog.inst[inst.out as usize].op {
                            InstOp::RUNE
                            | InstOp::RUNE1
                            | InstOp::RUNE_ANY
                            | InstOp::RUNE_ANY_NOT_NL => {
                                self.push(prog, inst.arg, pos, false);
                                pc = inst.arg;
                                pos = end;
                            }
                            _ => {
                                self.push(prog, inst.out, end, false);
                                pc = inst.out;
                            }
                        }
                    }
                    InstOp::RUNE => {
                        let (r, width) = i.step(pos as usize);
                        if !inst.match_rune(r) {
                            break;
                        }
                        pos += width as isize;
                        pc = inst.out;
                    }
                    InstOp::RUNE1 => {
                        let (r, width) = i.step(pos as usize);
                        if r != inst.rune[0] {
                            break;
                        }
                        pos += width as isize;
                        pc = inst.out;
                    }
                    InstOp::RUNE_ANY_NOT_NL => {
                        let (r, width) = i.step(pos as usize);
                        if r == '\n' as i32 || r == super::exec::END_OF_TEXT {
                            break;
                        }
                        pos += width as isize;
                        pc = inst.out;
                    }
                    InstOp::RUNE_ANY => {
                        let (r, width) = i.step(pos as usize);
                        if r == super::exec::END_OF_TEXT {
                            break;
                        }
                        pos += width as isize;
                        pc = inst.out;
                    }
                    InstOp::CAPTURE => {
                        let a = inst.arg as usize;
                        if arg {
                            // Finished inst.out; restore the old value.
                            self.cap[a] = pos;
                            break;
                        }
                        if a < self.cap.len() {
                            self.push(prog, pc, self.cap[a], true);
                            self.cap[a] = pos;
                        }
                        pc = inst.out;
                    }
                    InstOp::EMPTY_WIDTH => {
                        let flag: LazyFlag = i.context(pos as usize);
                        if !flag.matches(EmptyOp(inst.arg as u8)) {
                            break;
                        }
                        pc = inst.out;
                    }
                    InstOp::NOP => pc = inst.out,
                    InstOp::MATCH => {
                        // If the caller doesn't care where the match is, no
                        // point going further.
                        if self.cap.is_empty() {
                            return true;
                        }
                        // Only the end needs comparing: this whole call
                        // considers one start position.
                        if self.cap.len() > 1 {
                            self.cap[1] = pos;
                        }
                        let old = self.matchcap[1];
                        if old == -1 || (longest && pos > 0 && pos > old) {
                            self.matchcap.copy_from_slice(&self.cap);
                        }
                        if !longest || pos as usize == self.end {
                            return true;
                        }
                        // Continue in hope of a longer match.
                        break;
                    }
                    // FAIL is never pushed; there are no other instructions.
                    _ => break,
                }
            }
        }
        longest && self.matchcap.len() > 1 && self.matchcap[1] >= 0
    }

    /// Runs a backtracking search over an input of length `end` from `pos`;
    /// `p.anchored` restricts it to matches that begin at `pos`. On success
    /// the capture positions are left in `matchcap`.
    pub(crate) fn run<I: Input>(
        &mut self,
        prog: &Prog,
        p: &Params<'_>,
        i: &mut I,
        end: usize,
        mut pos: usize,
        ncap: usize,
    ) -> bool {
        let start_cond = p.cond;
        if start_cond == EmptyOp(!0) {
            // impossible
            return false;
        }
        let begin_text = start_cond.0 & EmptyOp::BEGIN_TEXT.0 != 0;
        if begin_text && pos != 0 {
            // Anchored match, past beginning of text.
            return false;
        }
        self.reset(prog, end, ncap);
        if begin_text || p.anchored {
            if !self.cap.is_empty() {
                self.cap[0] = pos as isize;
            }
            return self.try_backtrack(prog, p.longest, i, prog.start as u32, pos);
        }
        // Unanchored: try each start position, including the empty string at
        // the end. The visited bitmap is kept between attempts, so no work is
        // repeated and the whole search stays linear.
        while pos <= end {
            if !p.prefix.is_empty() {
                // Match requires literal prefix; fast search for it.
                let Some(advance) = i.index(p.prefix, pos) else {
                    return false;
                };
                pos += advance;
            }
            if !self.cap.is_empty() {
                self.cap[0] = pos as isize;
            }
            if self.try_backtrack(prog, p.longest, i, prog.start as u32, pos) {
                // Match must be leftmost; done.
                return true;
            }
            let (_, width) = i.step(pos);
            if width == 0 {
                break;
            }
            pos += width;
        }
        false
    }
}
