//! The Pike VM (Go `regexp/exec.go`): a breadth-first simulation of the
//! compiled program that tracks capture positions per thread. It visits every
//! instruction at most once per input position, so a search takes
//! O(input length x program size) time and never backtracks. Thread order in
//! the run queue is priority order, which yields leftmost-first (Perl)
//! semantics; in longest mode the longest of the leftmost matches wins.
use super::syntax::{EmptyOp, InstOp, Prog};
use crate::io::RuneReader;
use crate::unicode::rune::decode_rune;
use std::io;

/// End of text, as a rune.
pub(crate) const END_OF_TEXT: i32 = -1;

/// A [`RuneReader`] over any [`io::Read`], decoding UTF-8 like Go's
/// `bufio.Reader.ReadRune`.
///
/// ```
/// use rust_stdlib::regexp::{compile, Utf8RuneReader};
/// let re = compile("b+")?;
/// let mut r = Utf8RuneReader::new(&b"aabbb"[..]);
/// assert_eq!(re.find_reader_index(&mut r), Some((2, 5)));
/// # Ok::<(), rust_stdlib::regexp::syntax::Error>(())
/// ```
pub struct Utf8RuneReader<R: io::Read> {
    inner: R,
    buf: Vec<u8>,
    pos: usize,
    end: usize,
    done: bool,
}

impl<R: io::Read> Utf8RuneReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buf: vec![0; 4096],
            pos: 0,
            end: 0,
            done: false,
        }
    }

    fn fill(&mut self) {
        if self.pos > 0 {
            self.buf.copy_within(self.pos..self.end, 0);
            self.end -= self.pos;
            self.pos = 0;
        }
        loop {
            match self.inner.read(&mut self.buf[self.end..]) {
                Ok(0) => self.done = true,
                Ok(n) => self.end += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => self.done = true,
            }
            return;
        }
    }
}

impl<R: io::Read> RuneReader for Utf8RuneReader<R> {
    fn read_rune(&mut self) -> io::Result<(char, usize)> {
        while self.end - self.pos < 4 && !self.done {
            self.fill();
        }
        if self.pos == self.end {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let (r, size) = decode_rune(&self.buf[self.pos..self.end]);
        self.pos += size;
        Ok((char::from_u32(r as u32).unwrap_or('\u{fffd}'), size))
    }
}

/// The matcher's view of the text.
pub(crate) trait Input {
    fn step(&mut self, pos: usize) -> (i32, usize);
    fn can_check_prefix(&self) -> bool;
    fn has_prefix(&self, prefix: &[u8]) -> bool;
    fn index(&self, prefix: &[u8], pos: usize) -> Option<usize>;
    fn context(&mut self, pos: usize) -> LazyFlag;
}

pub(crate) struct BytesInput<'a>(pub &'a [u8]);

pub(crate) fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    let first = *needle.first()?;
    let mut from = 0;
    while from + needle.len() <= hay.len() {
        let i = hay[from..=hay.len() - needle.len()]
            .iter()
            .position(|&b| b == first)?;
        if &hay[from + i..from + i + needle.len()] == needle {
            return Some(from + i);
        }
        from += i + 1;
    }
    None
}

impl Input for BytesInput<'_> {
    fn step(&mut self, pos: usize) -> (i32, usize) {
        if pos < self.0.len() {
            let b = self.0[pos];
            if b < 0x80 {
                return (i32::from(b), 1);
            }
            decode_rune(&self.0[pos..])
        } else {
            (END_OF_TEXT, 0)
        }
    }
    fn can_check_prefix(&self) -> bool {
        true
    }
    fn has_prefix(&self, prefix: &[u8]) -> bool {
        self.0.starts_with(prefix)
    }
    fn index(&self, prefix: &[u8], pos: usize) -> Option<usize> {
        find_sub(&self.0[pos..], prefix)
    }
    fn context(&mut self, pos: usize) -> LazyFlag {
        let b = self.0;
        let (mut r1, mut r2) = (END_OF_TEXT, END_OF_TEXT);
        if pos >= 1 && pos <= b.len() {
            r1 = crate::unicode::rune::decode_last_rune(&b[..pos]).0;
        }
        if pos < b.len() {
            r2 = decode_rune(&b[pos..]).0;
        }
        LazyFlag::new(r1, r2)
    }
}

pub(crate) struct ReaderInput<'a, R: RuneReader + ?Sized> {
    pub r: &'a mut R,
    pub at_eot: bool,
    pub pos: usize,
}

impl<R: RuneReader + ?Sized> Input for ReaderInput<'_, R> {
    fn step(&mut self, pos: usize) -> (i32, usize) {
        if !self.at_eot && pos != self.pos {
            return (END_OF_TEXT, 0);
        }
        match self.r.read_rune() {
            Ok((r, w)) => {
                self.pos += w;
                (r as i32, w)
            }
            Err(_) => {
                self.at_eot = true;
                (END_OF_TEXT, 0)
            }
        }
    }
    fn can_check_prefix(&self) -> bool {
        false
    }
    fn has_prefix(&self, _prefix: &[u8]) -> bool {
        false
    }
    fn index(&self, _prefix: &[u8], _pos: usize) -> Option<usize> {
        None
    }
    fn context(&mut self, _pos: usize) -> LazyFlag {
        LazyFlag::new(END_OF_TEXT, END_OF_TEXT) // not used
    }
}

/// The runes on either side of a position, from which the empty-width
/// assertions are evaluated lazily.
#[derive(Clone, Copy)]
pub(crate) struct LazyFlag {
    r1: i32,
    r2: i32,
}

impl LazyFlag {
    pub(crate) fn new(r1: i32, r2: i32) -> Self {
        Self { r1, r2 }
    }

    pub(crate) fn matches(self, op: EmptyOp) -> bool {
        let mut op = op.0;
        if op == 0 {
            return true;
        }
        let r1 = self.r1;
        if op & EmptyOp::BEGIN_LINE.0 != 0 {
            if r1 != '\n' as i32 && r1 >= 0 {
                return false;
            }
            op &= !EmptyOp::BEGIN_LINE.0;
        }
        if op & EmptyOp::BEGIN_TEXT.0 != 0 {
            if r1 >= 0 {
                return false;
            }
            op &= !EmptyOp::BEGIN_TEXT.0;
        }
        if op == 0 {
            return true;
        }
        let r2 = self.r2;
        if op & EmptyOp::END_LINE.0 != 0 {
            if r2 != '\n' as i32 && r2 >= 0 {
                return false;
            }
            op &= !EmptyOp::END_LINE.0;
        }
        if op & EmptyOp::END_TEXT.0 != 0 {
            if r2 >= 0 {
                return false;
            }
            op &= !EmptyOp::END_TEXT.0;
        }
        if op == 0 {
            return true;
        }
        if super::syntax::is_word_char(r1) != super::syntax::is_word_char(r2) {
            op &= !EmptyOp::WORD_BOUNDARY.0;
        } else {
            op &= !EmptyOp::NO_WORD_BOUNDARY.0;
        }
        op == 0
    }
}

/// What the machine needs to know about the regexp being run.
pub(crate) struct Params<'a> {
    pub cond: EmptyOp,
    pub prefix: &'a [u8],
    pub prefix_rune: i32,
    /// The one-pass program's instruction after the literal prefix.
    pub prefix_end: u32,
    pub longest: bool,
    /// Only matches that begin at the starting position count.
    pub anchored: bool,
}

#[derive(Default)]
struct Queue {
    sparse: Vec<u32>,
    dense: Vec<Entry>,
}

#[derive(Clone, Copy)]
struct Entry {
    pc: u32,
    t: Option<usize>,
}

struct Thread {
    pc: u32,
    cap: Vec<isize>,
}

enum Frame {
    Visit(u32),
    Restore(usize, isize),
}

/// Reusable matching state for one program.
#[derive(Default)]
pub(crate) struct Machine {
    q0: Queue,
    q1: Queue,
    threads: Vec<Thread>,
    free: Vec<usize>,
    matched: bool,
    pub(crate) matchcap: Vec<isize>,
    scratch: Vec<isize>,
    stack: Vec<Frame>,
}

impl Machine {
    pub(crate) fn new(ninst: usize) -> Machine {
        Machine {
            q0: Queue {
                sparse: vec![0; ninst],
                dense: Vec::new(),
            },
            q1: Queue {
                sparse: vec![0; ninst],
                dense: Vec::new(),
            },
            ..Machine::default()
        }
    }

    fn alloc(&mut self, pc: u32) -> usize {
        let t = match self.free.pop() {
            Some(t) => t,
            None => {
                self.threads.push(Thread {
                    pc,
                    cap: Vec::new(),
                });
                self.threads.len() - 1
            }
        };
        let th = &mut self.threads[t];
        th.pc = pc;
        th.cap.clear();
        th.cap.extend_from_slice(&self.scratch);
        t
    }

    fn clear(&mut self, q: &mut Queue) {
        for d in q.dense.drain(..) {
            if let Some(t) = d.t {
                self.free.push(t);
            }
        }
    }

    /// Runs the program over `i` starting at `pos` and reports whether it
    /// matched; the capture positions (-1 when unset) are left in `matchcap`.
    /// When `p.anchored`, only a thread started at `pos` is run.
    pub(crate) fn run<I: Input>(
        &mut self,
        prog: &Prog,
        p: &Params<'_>,
        i: &mut I,
        mut pos: usize,
        ncap: usize,
    ) -> bool {
        let start_cond = p.cond;
        if start_cond == EmptyOp(!0) {
            // impossible
            return false;
        }
        self.matched = false;
        self.matchcap.clear();
        self.matchcap.resize(ncap, -1);
        self.scratch.clear();
        self.scratch.resize(ncap, -1);

        let mut runq = std::mem::take(&mut self.q0);
        let mut nextq = std::mem::take(&mut self.q1);
        let start = pos;
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
        loop {
            if runq.dense.is_empty() {
                if start_cond.0 & EmptyOp::BEGIN_TEXT.0 != 0 && pos != 0 {
                    // Anchored match, past beginning of text.
                    break;
                }
                if p.anchored && pos != start {
                    break;
                }
                if self.matched {
                    // Have match; finished exploring alternatives.
                    break;
                }
                if !p.anchored
                    && !p.prefix.is_empty()
                    && r1 != p.prefix_rune
                    && i.can_check_prefix()
                {
                    // Match requires literal prefix; fast search for it.
                    let Some(advance) = i.index(p.prefix, pos) else {
                        break;
                    };
                    pos += advance;
                    (r, width) = i.step(pos);
                    (r1, width1) = i.step(pos + width);
                }
            }
            if !self.matched && (!p.anchored || pos == start) {
                if !self.matchcap.is_empty() {
                    self.matchcap[0] = pos as isize;
                }
                self.scratch.clone_from(&self.matchcap);
                self.add(prog, &mut runq, prog.start as u32, pos as isize, &flag);
            }
            flag = LazyFlag::new(r, r1);
            self.step(prog, p, &mut runq, &mut nextq, pos, pos + width, r, &flag);
            if width == 0 {
                break;
            }
            if self.matchcap.is_empty() && self.matched {
                // Found a match and not paying attention to where it is.
                break;
            }
            pos += width;
            (r, width) = (r1, width1);
            if r != END_OF_TEXT {
                (r1, width1) = i.step(pos + width);
            }
            std::mem::swap(&mut runq, &mut nextq);
        }
        self.clear(&mut nextq);
        self.clear(&mut runq);
        self.q0 = runq;
        self.q1 = nextq;
        self.matched
    }

    /// Runs one step of every thread in `runq` on the rune `c` at `pos`,
    /// queueing the survivors in `nextq` at `next_pos`.
    #[allow(clippy::too_many_arguments)]
    fn step(
        &mut self,
        prog: &Prog,
        p: &Params<'_>,
        runq: &mut Queue,
        nextq: &mut Queue,
        pos: usize,
        next_pos: usize,
        c: i32,
        next_cond: &LazyFlag,
    ) {
        let longest = p.longest;
        let mut j = 0;
        while j < runq.dense.len() {
            let Some(t) = runq.dense[j].t else {
                j += 1;
                continue;
            };
            if longest
                && self.matched
                && !self.threads[t].cap.is_empty()
                && self.matchcap[0] < self.threads[t].cap[0]
            {
                // Match: this thread started later than the best match so far.
                self.free.push(t);
                j += 1;
                continue;
            }
            let inst = &prog.inst[self.threads[t].pc as usize];
            let mut add = false;
            match inst.op {
                InstOp::MATCH => {
                    if self.threads[t].cap.len() > 1
                        && (!longest || !self.matched || self.matchcap[1] < pos as isize)
                    {
                        self.threads[t].cap[1] = pos as isize;
                        self.matchcap.copy_from_slice(&self.threads[t].cap);
                    }
                    if !longest {
                        // First-match mode: cut off all lower-priority threads.
                        for d in &runq.dense[j + 1..] {
                            if let Some(t2) = d.t {
                                self.free.push(t2);
                            }
                        }
                        runq.dense.clear();
                    }
                    self.matched = true;
                }
                InstOp::RUNE => add = inst.match_rune(c),
                InstOp::RUNE1 => add = c == inst.rune[0],
                InstOp::RUNE_ANY => add = true,
                InstOp::RUNE_ANY_NOT_NL => add = c != '\n' as i32,
                _ => {}
            }
            if add {
                self.scratch.clear();
                self.scratch.extend_from_slice(&self.threads[t].cap);
                self.add(prog, nextq, inst.out, next_pos as isize, next_cond);
            }
            self.free.push(t);
            j += 1;
        }
        runq.dense.clear();
    }

    /// Follows all empty-width and control-flow instructions from `pc0`,
    /// adding a thread to `q` for every instruction that consumes input or
    /// matches. The capture state being propagated is in `self.scratch`.
    /// This is the recursive `add` of Go's machine with an explicit stack, so
    /// deeply nested programs cannot overflow the call stack.
    fn add(&mut self, prog: &Prog, q: &mut Queue, pc0: u32, pos: isize, cond: &LazyFlag) {
        let mut stack = std::mem::take(&mut self.stack);
        stack.push(Frame::Visit(pc0));
        while let Some(frame) = stack.pop() {
            let mut pc = match frame {
                Frame::Restore(i, v) => {
                    self.scratch[i] = v;
                    continue;
                }
                Frame::Visit(pc) => pc,
            };
            loop {
                if pc == 0 {
                    break;
                }
                let j = q.sparse[pc as usize] as usize;
                if j < q.dense.len() && q.dense[j].pc == pc {
                    // Already on the queue.
                    break;
                }
                let j = q.dense.len();
                q.dense.push(Entry { pc, t: None });
                q.sparse[pc as usize] = j as u32;

                let i = &prog.inst[pc as usize];
                match i.op {
                    InstOp::FAIL => break,
                    InstOp::ALT | InstOp::ALT_MATCH => {
                        stack.push(Frame::Visit(i.arg));
                        pc = i.out;
                    }
                    InstOp::EMPTY_WIDTH => {
                        if cond.matches(EmptyOp(i.arg as u8)) {
                            pc = i.out;
                        } else {
                            break;
                        }
                    }
                    InstOp::NOP => pc = i.out,
                    InstOp::CAPTURE => {
                        let a = i.arg as usize;
                        if a < self.scratch.len() {
                            stack.push(Frame::Restore(a, self.scratch[a]));
                            self.scratch[a] = pos;
                        }
                        pc = i.out;
                    }
                    _ => {
                        // MATCH and the rune instructions.
                        let t = self.alloc(pc);
                        q.dense[j].t = Some(t);
                        break;
                    }
                }
            }
        }
        self.stack = stack;
    }
}
