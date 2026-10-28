//! Compiler from syntax trees to programs (Go `regexp/syntax/compile.go`).
use super::{EmptyOp, Error, Flags, Inst, InstOp, Op, Prog, Regexp};
use crate::unicode;

/// A list of instruction exits still to be patched. Each entry is
/// `pc << 1 | which`, where `which` selects `out` (0) or `arg` (1); the list is
/// threaded through the unpatched fields themselves.
#[derive(Clone, Copy, Default)]
struct PatchList {
    head: u32,
    tail: u32,
}

impl PatchList {
    fn make(n: u32) -> PatchList {
        PatchList { head: n, tail: n }
    }

    fn patch(self, p: &mut Prog, val: u32) {
        let mut head = self.head;
        while head != 0 {
            let i = &mut p.inst[(head >> 1) as usize];
            if head & 1 == 0 {
                head = i.out;
                i.out = val;
            } else {
                head = i.arg;
                i.arg = val;
            }
        }
    }

    fn append(self, p: &mut Prog, l2: PatchList) -> PatchList {
        if self.head == 0 {
            return l2;
        }
        if l2.head == 0 {
            return self;
        }
        let i = &mut p.inst[(self.tail >> 1) as usize];
        if self.tail & 1 == 0 {
            i.out = l2.head;
        } else {
            i.arg = l2.head;
        }
        PatchList {
            head: self.head,
            tail: l2.tail,
        }
    }
}

/// A compiled fragment: the first instruction, where it ends and whether it
/// can match the empty string.
#[derive(Clone, Copy, Default)]
struct Frag {
    i: u32,
    out: PatchList,
    nullable: bool,
}

struct Compiler {
    p: Prog,
}

const MAX_RUNE: i32 = unicode::MAX_RUNE;
const NL: i32 = '\n' as i32;

/// Compiles a parsed (and usually simplified) regexp into a program.
pub fn compile(re: &Regexp) -> Result<Prog, Error> {
    let mut c = Compiler {
        p: Prog {
            inst: Vec::new(),
            start: 0,
            num_cap: 2, // implicit ( and ) for whole match $0
        },
    };
    c.inst(InstOp::FAIL);
    let f = c.compile(re);
    let m = c.inst(InstOp::MATCH).i;
    f.out.patch(&mut c.p, m);
    c.p.start = f.i as usize;
    Ok(c.p)
}

impl Compiler {
    fn compile(&mut self, re: &Regexp) -> Frag {
        match re.op {
            Op::NO_MATCH => self.fail(),
            Op::EMPTY_MATCH => self.nop(),
            Op::LITERAL => {
                if re.rune.is_empty() {
                    return self.nop();
                }
                let mut f = Frag::default();
                for j in 0..re.rune.len() {
                    let f1 = self.rune(&re.rune[j..j + 1], re.flags);
                    f = if j == 0 { f1 } else { self.cat(f, f1) };
                }
                f
            }
            Op::CHAR_CLASS => self.rune(&re.rune, re.flags),
            Op::ANY_CHAR_NOT_NL => self.rune(&[0, NL - 1, NL + 1, MAX_RUNE], Flags(0)),
            Op::ANY_CHAR => self.rune(&[0, MAX_RUNE], Flags(0)),
            Op::BEGIN_LINE => self.empty(EmptyOp::BEGIN_LINE),
            Op::END_LINE => self.empty(EmptyOp::END_LINE),
            Op::BEGIN_TEXT => self.empty(EmptyOp::BEGIN_TEXT),
            Op::END_TEXT => self.empty(EmptyOp::END_TEXT),
            Op::WORD_BOUNDARY => self.empty(EmptyOp::WORD_BOUNDARY),
            Op::NO_WORD_BOUNDARY => self.empty(EmptyOp::NO_WORD_BOUNDARY),
            Op::CAPTURE => {
                let bra = self.cap((re.cap << 1) as u32);
                let sub = self.compile(&re.sub[0]);
                let ket = self.cap((re.cap << 1 | 1) as u32);
                let f = self.cat(bra, sub);
                self.cat(f, ket)
            }
            Op::STAR => {
                let f = self.compile(&re.sub[0]);
                self.star(f, re.flags & Flags::NON_GREEDY != Flags(0))
            }
            Op::PLUS => {
                let f = self.compile(&re.sub[0]);
                self.plus(f, re.flags & Flags::NON_GREEDY != Flags(0))
            }
            Op::QUEST => {
                let f = self.compile(&re.sub[0]);
                self.quest(f, re.flags & Flags::NON_GREEDY != Flags(0))
            }
            Op::CONCAT => {
                if re.sub.is_empty() {
                    return self.nop();
                }
                let mut f = Frag::default();
                for (i, sub) in re.sub.iter().enumerate() {
                    if i == 0 {
                        f = self.compile(sub);
                    } else {
                        let g = self.compile(sub);
                        f = self.cat(f, g);
                    }
                }
                f
            }
            Op::ALTERNATE => {
                let mut f = Frag::default();
                for sub in &re.sub {
                    let g = self.compile(sub);
                    f = self.alt(f, g);
                }
                f
            }
            // Unreachable for parsed trees; the zero fragment is "fail".
            _ => self.fail(),
        }
    }

    fn inst(&mut self, op: InstOp) -> Frag {
        let f = Frag {
            i: self.p.inst.len() as u32,
            out: PatchList::default(),
            nullable: true,
        };
        self.p.inst.push(Inst {
            op,
            ..Inst::default()
        });
        f
    }

    fn nop(&mut self) -> Frag {
        let mut f = self.inst(InstOp::NOP);
        f.out = PatchList::make(f.i << 1);
        f
    }

    fn fail(&mut self) -> Frag {
        Frag::default()
    }

    fn cap(&mut self, arg: u32) -> Frag {
        let mut f = self.inst(InstOp::CAPTURE);
        f.out = PatchList::make(f.i << 1);
        self.p.inst[f.i as usize].arg = arg;
        if self.p.num_cap < arg as usize + 1 {
            self.p.num_cap = arg as usize + 1;
        }
        f
    }

    fn cat(&mut self, f1: Frag, f2: Frag) -> Frag {
        // concat of failure is failure
        if f1.i == 0 || f2.i == 0 {
            return Frag::default();
        }
        f1.out.patch(&mut self.p, f2.i);
        Frag {
            i: f1.i,
            out: f2.out,
            nullable: f1.nullable && f2.nullable,
        }
    }

    fn alt(&mut self, f1: Frag, f2: Frag) -> Frag {
        // alt of failure is other
        if f1.i == 0 {
            return f2;
        }
        if f2.i == 0 {
            return f1;
        }
        let mut f = self.inst(InstOp::ALT);
        let i = &mut self.p.inst[f.i as usize];
        i.out = f1.i;
        i.arg = f2.i;
        f.out = f1.out.append(&mut self.p, f2.out);
        f.nullable = f1.nullable || f2.nullable;
        f
    }

    fn quest(&mut self, f1: Frag, nongreedy: bool) -> Frag {
        let mut f = self.inst(InstOp::ALT);
        let i = &mut self.p.inst[f.i as usize];
        if nongreedy {
            i.arg = f1.i;
            f.out = PatchList::make(f.i << 1);
        } else {
            i.out = f1.i;
            f.out = PatchList::make(f.i << 1 | 1);
        }
        f.out = f.out.append(&mut self.p, f1.out);
        f
    }

    /// Loop returns the fragment for the main loop of a plus or star: for a
    /// plus it is the loop body followed by the loop test; for a star it is
    /// only the loop test.
    fn loop_(&mut self, f1: Frag, nongreedy: bool) -> Frag {
        let mut f = self.inst(InstOp::ALT);
        let i = &mut self.p.inst[f.i as usize];
        if nongreedy {
            i.arg = f1.i;
            f.out = PatchList::make(f.i << 1);
        } else {
            i.out = f1.i;
            f.out = PatchList::make(f.i << 1 | 1);
        }
        f1.out.patch(&mut self.p, f.i);
        f
    }

    fn star(&mut self, f1: Frag, nongreedy: bool) -> Frag {
        if f1.nullable {
            // Use (f1+)? to get priority match order correct.
            let p = self.plus(f1, nongreedy);
            return self.quest(p, nongreedy);
        }
        self.loop_(f1, nongreedy)
    }

    fn plus(&mut self, f1: Frag, nongreedy: bool) -> Frag {
        let l = self.loop_(f1, nongreedy);
        Frag {
            i: f1.i,
            out: l.out,
            nullable: f1.nullable,
        }
    }

    fn empty(&mut self, op: EmptyOp) -> Frag {
        let mut f = self.inst(InstOp::EMPTY_WIDTH);
        self.p.inst[f.i as usize].arg = u32::from(op.0);
        f.out = PatchList::make(f.i << 1);
        f
    }

    fn rune(&mut self, r: &[i32], flags: Flags) -> Frag {
        let mut f = self.inst(InstOp::RUNE);
        f.nullable = false;
        let mut flags = flags & Flags::FOLD_CASE; // only relevant flag is FoldCase
        if r.len() != 1 || unicode::simple_fold(r[0]) == r[0] {
            // and sometimes not even that
            flags &= !Flags::FOLD_CASE;
        }
        let i = &mut self.p.inst[f.i as usize];
        i.rune = r.to_vec();
        i.arg = u32::from(flags.0);
        f.out = PatchList::make(f.i << 1);

        // Special cases for exec machine.
        if flags & Flags::FOLD_CASE == Flags(0) && (r.len() == 1 || r.len() == 2 && r[0] == r[1]) {
            i.op = InstOp::RUNE1;
        } else if r.len() == 2 && r[0] == 0 && r[1] == MAX_RUNE {
            i.op = InstOp::RUNE_ANY;
        } else if r.len() == 4 && r[0] == 0 && r[1] == NL - 1 && r[2] == NL + 1 && r[3] == MAX_RUNE
        {
            i.op = InstOp::RUNE_ANY_NOT_NL;
        }
        f
    }
}
