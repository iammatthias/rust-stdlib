//! Regexp simplification (Go `regexp/syntax/simplify.go`).
use super::{Flags, Op, Regexp};
use std::sync::Arc;

impl Regexp {
    /// Returns a regexp equivalent to `self` but without counted repetitions
    /// and with various other simplifications, such as rewriting `/(?:a+)+/`
    /// to `/a+/`. The resulting regexp will execute correctly but its string
    /// representation will not produce the same parse tree, because capturing
    /// parentheses may have been duplicated or removed. For example, the
    /// simplified form for `/(x){1,2}/` is `/(x)(x)?/` but both parentheses
    /// capture as `$1`. The returned regexp may share structure with `self`.
    pub fn simplify(&self) -> Regexp {
        let root = Arc::new(self.clone());
        let out = simplify(&root);
        Arc::try_unwrap(out).unwrap_or_else(|a| (*a).clone())
    }
}

fn simplify(re: &Arc<Regexp>) -> Arc<Regexp> {
    match re.op {
        Op::CAPTURE | Op::CONCAT | Op::ALTERNATE => {
            // Simplify children, building new Regexp if children change.
            let mut nre: Option<Regexp> = None;
            for (i, sub) in re.sub.iter().enumerate() {
                let nsub = simplify(sub);
                if nre.is_none() && !Arc::ptr_eq(&nsub, sub) {
                    // Start a copy.
                    let mut copy = (**re).clone();
                    copy.rune = Vec::new();
                    copy.sub = re.sub[..i].to_vec();
                    nre = Some(copy);
                }
                if let Some(n) = nre.as_mut() {
                    n.sub.push(nsub);
                }
            }
            match nre {
                Some(n) => Arc::new(n),
                None => re.clone(),
            }
        }
        Op::STAR | Op::PLUS | Op::QUEST => {
            let sub = simplify(&re.sub[0]);
            simplify1(re.op, re.flags, sub, Some(re))
        }
        Op::REPEAT => {
            // Special special case: x{0} matches the empty string and
            // doesn't even need to consider x.
            if re.min == 0 && re.max == 0 {
                return Arc::new(Regexp::with_op(Op::EMPTY_MATCH));
            }

            // The fun begins.
            let sub = simplify(&re.sub[0]);

            // x{n,} means at least n matches of x.
            if re.max == -1 {
                // Special case: x{0,} is x*.
                if re.min == 0 {
                    return simplify1(Op::STAR, re.flags, sub, None);
                }
                // Special case: x{1,} is x+.
                if re.min == 1 {
                    return simplify1(Op::PLUS, re.flags, sub, None);
                }
                // General case: x{4,} is xxxx+.
                let mut nre = Regexp::with_op(Op::CONCAT);
                for _ in 0..re.min - 1 {
                    nre.sub.push(sub.clone());
                }
                nre.sub.push(simplify1(Op::PLUS, re.flags, sub, None));
                return Arc::new(nre);
            }

            // Special case x{0} handled above.

            // Special case: x{1} is just x.
            if re.min == 1 && re.max == 1 {
                return sub;
            }

            // General case: x{n,m} means n copies of x and m copies of x?
            // The machine will do less work if we nest the final m copies,
            // so that x{2,5} = xx(x(x(x)?)?)?

            // Build leading prefix: xx.
            let mut prefix: Option<Regexp> = None;
            if re.min > 0 {
                let mut p = Regexp::with_op(Op::CONCAT);
                for _ in 0..re.min {
                    p.sub.push(sub.clone());
                }
                prefix = Some(p);
            }

            // Build and attach suffix: (x(x(x)?)?)?
            if re.max > re.min {
                let mut suffix = simplify1(Op::QUEST, re.flags, sub.clone(), None);
                for _ in re.min + 1..re.max {
                    let mut nre2 = Regexp::with_op(Op::CONCAT);
                    nre2.sub = vec![sub.clone(), suffix];
                    suffix = simplify1(Op::QUEST, re.flags, Arc::new(nre2), None);
                }
                match prefix.as_mut() {
                    None => return suffix,
                    Some(p) => p.sub.push(suffix),
                }
            }
            if let Some(p) = prefix {
                return Arc::new(p);
            }

            // Some degenerate case like min > max or min < max < 0.
            // Handle as impossible match.
            Arc::new(Regexp::with_op(Op::NO_MATCH))
        }
        _ => re.clone(),
    }
}

/// Applies the operator to `sub`, applying a few simplifications: `(?:a*)*`
/// is `a*`, an empty `sub` makes the whole thing empty, and the original `re`
/// is reused when it is already in the requested form.
fn simplify1(op: Op, flags: Flags, sub: Arc<Regexp>, re: Option<&Arc<Regexp>>) -> Arc<Regexp> {
    // Special case: repeat the empty string as much as
    // you want, but it's still the empty string.
    if sub.op == Op::EMPTY_MATCH {
        return sub;
    }
    // The operators are idempotent if the flags match.
    if op == sub.op && flags & Flags::NON_GREEDY == sub.flags & Flags::NON_GREEDY {
        return sub;
    }
    if let Some(r) = re {
        if r.op == op
            && r.flags & Flags::NON_GREEDY == flags & Flags::NON_GREEDY
            && Arc::ptr_eq(&sub, &r.sub[0])
        {
            return r.clone();
        }
    }
    let mut n = Regexp::with_op(op);
    n.flags = flags;
    n.sub = vec![sub];
    Arc::new(n)
}
