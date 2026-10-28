//! Per-call cost of anchored search in a syntax-highlighting tokenizer: many
//! rules, each tried with `find_anchored_index_at` at an advancing offset in
//! one long text. `cargo run --release --example regexp_tokenizer_bench
//! [filter]`; `tools/regexp/bench/tokenizer.go` runs the same calls on Go.
//!
//! A tokenizer pass over the text records every (rule, offset) it tries; the
//! cases replay those calls. `lex` is all of them, `hit` the ones that match,
//! `miss` the ones that do not, and `miss_noprefix` the misses of rules with
//! no literal prefix (a literal prefix rejects a miss before the matcher
//! runs). `fixed_hit` and `fixed_miss` run a one-character class at every
//! offset, so their cost is the per-call overhead with almost no scan.
//! `slice/*` replays the calls as `^(?:rule)` on `&text[pos..]`, the form Go's
//! API offers. Each line is the median ns per call with the min and max of the
//! runs, and a checksum that proves the calls ran and must agree between
//! builds and with Go.
use rust_stdlib::regexp::{must_compile, Regexp};
use std::hint::black_box;
use std::time::Instant;

const RUNS: usize = 9;
const TARGET_NS: u128 = 40_000_000;

const SOURCE: &str = r#"package main

import "fmt"

// Point is a 2D point; see https://example.com/doc?q=1.
type Point struct {
	X, Y float64
	name string
}

/* block comment
   spanning lines */
func (p *Point) Scale(k float64) Point {
	if k == 0 || p == nil {
		return Point{}
	}
	for i := 0; i < 10; i++ {
		k += 0x1F * 3.25e-2
	}
	s := `raw string`
	c := '\n'
	fmt.Println("scaled:\t", p.X*k, s, c)
	return Point{X: p.X * k, Y: p.Y * k, name: p.name + "'"}
}
"#;

const RULES: &[&str] = &[
    r"[ \t]+",
    r"\r?\n",
    r"//[^\n]*",
    r"/\*(?s:.)*?\*/",
    r#""(?:[^"\\\n]|\\.)*""#,
    r"`[^`]*`",
    r"'(?:[^'\\]|\\.)'",
    r"(?:break|case|chan|const|continue|default|defer|else|fallthrough|for|func|go|goto|if|import|interface|map|package|range|return|select|struct|switch|type|var)\b",
    r"(?:true|false|nil|iota)\b",
    r"(?:bool|byte|float64|int|rune|string|error)\b",
    r"https?://[^\s)]+",
    r"0[xX][0-9a-fA-F_]+",
    r"[0-9]+\.[0-9]*(?:[eE][+-]?[0-9]+)?",
    r"[0-9]+",
    r"[A-Za-z_]\w*\(",
    r"\.[A-Za-z_]\w*",
    r"[\pL_][\pL\pN_]*",
    r":=|==|!=|<=|>=|&&|\|\||\+\+|--|<-|\.\.\.",
    r"[-+*/%<>=!&|^]=?",
    r"[{}()\[\];,.:]",
];

fn source(n: usize) -> Vec<u8> {
    let mut s = Vec::with_capacity(n + SOURCE.len());
    while s.len() < n {
        s.extend_from_slice(SOURCE.as_bytes());
    }
    s.truncate(n);
    s
}

/// The (rule, offset) calls a first-match tokenizer makes over `text`, and
/// whether each matched.
fn trace(res: &[Regexp], text: &[u8]) -> Vec<(usize, usize, bool)> {
    let mut calls = Vec::new();
    let mut pos = 0;
    'outer: while pos < text.len() {
        for (k, re) in res.iter().enumerate() {
            let m = re.find_anchored_index_at(text, pos);
            let hit = matches!(m, Some((_, e)) if e > pos);
            calls.push((k, pos, hit));
            if hit {
                pos = m.unwrap().1;
                continue 'outer;
            }
        }
        pos += 1;
    }
    calls
}

fn bench(filter: &str, name: &str, calls: usize, mut f: impl FnMut() -> usize) {
    if !name.contains(filter) || calls == 0 {
        return;
    }
    let check = f();
    let start = Instant::now();
    let mut iters = 0u128;
    while start.elapsed().as_nanos() < TARGET_NS / 10 || iters == 0 {
        black_box(f());
        iters += 1;
    }
    let per = (start.elapsed().as_nanos() / iters).max(1);
    let n = (TARGET_NS / per).max(1);
    let mut runs: Vec<f64> = (0..RUNS)
        .map(|_| {
            let t = Instant::now();
            for _ in 0..n {
                black_box(f());
            }
            t.elapsed().as_nanos() as f64 / (n as f64 * calls as f64)
        })
        .collect();
    runs.sort_by(|a, b| a.total_cmp(b));
    println!(
        "{name:<32} {:>8.1} ns/call (min {:.1} max {:.1}, {RUNS} runs, {calls} calls) check={check}",
        runs[RUNS / 2],
        runs[0],
        runs[RUNS - 1]
    );
}

fn replay(res: &[Regexp], text: &[u8], calls: &[(usize, usize)]) -> usize {
    let mut check = 0usize;
    for &(k, pos) in calls {
        if let Some((s, e)) = res[k].find_anchored_index_at(text, pos) {
            check = check.wrapping_mul(31).wrapping_add(s ^ (e << 1));
        } else {
            check = check.wrapping_add(1);
        }
    }
    check
}

fn replay_slice(res: &[Regexp], text: &[u8], calls: &[(usize, usize)]) -> usize {
    let mut check = 0usize;
    for &(k, pos) in calls {
        if let Some((s, e)) = res[k].find_index(&text[pos..]) {
            check = check
                .wrapping_mul(31)
                .wrapping_add((s + pos) ^ ((e + pos) << 1));
        } else {
            check = check.wrapping_add(1);
        }
    }
    check
}

fn main() {
    let filter = std::env::args().nth(1).unwrap_or_default();
    let filter = filter.as_str();
    let res: Vec<Regexp> = RULES.iter().map(|r| must_compile(r)).collect();
    let anchored: Vec<Regexp> = RULES
        .iter()
        .map(|r| must_compile(&format!("^(?:{r})")))
        .collect();
    let fixed = [must_compile(r"[ -~\t\n]"), must_compile(r"[\x00\x01]")];
    let fixed_anchored = [must_compile(r"^[ -~\t\n]"), must_compile(r"^[\x00\x01]")];
    let has_prefix: Vec<bool> = RULES
        .iter()
        .map(|r| !must_compile(r).literal_prefix().0.is_empty())
        .collect();

    for (label, size) in [("2K", 2usize << 10), ("200K", 200 << 10)] {
        let text = source(size);
        let tr = trace(&res, &text);
        let pick = |keep: &dyn Fn(usize, bool) -> bool| -> Vec<(usize, usize)> {
            tr.iter()
                .filter(|&&(k, _, hit)| keep(k, hit))
                .map(|&(k, pos, _)| (k, pos))
                .collect()
        };
        let lex = pick(&|_, _| true);
        let hit = pick(&|_, h| h);
        let miss = pick(&|_, h| !h);
        let miss_np = pick(&|k, h| !h && !has_prefix[k]);
        let every: Vec<(usize, usize)> = (0..text.len()).map(|p| (0, p)).collect();
        let every_miss: Vec<(usize, usize)> = (0..text.len()).map(|p| (1, p)).collect();
        for (case, calls) in [
            ("lex", &lex),
            ("hit", &hit),
            ("miss", &miss),
            ("miss_noprefix", &miss_np),
        ] {
            bench(filter, &format!("at/{case}/{label}"), calls.len(), || {
                replay(&res, &text, calls)
            });
        }
        bench(
            filter,
            &format!("at/fixed_hit/{label}"),
            every.len(),
            || replay(&fixed, &text, &every),
        );
        bench(
            filter,
            &format!("at/fixed_miss/{label}"),
            every_miss.len(),
            || replay(&fixed, &text, &every_miss),
        );
        for (case, calls) in [("hit", &hit), ("miss_noprefix", &miss_np)] {
            bench(
                filter,
                &format!("slice/{case}/{label}"),
                calls.len(),
                || replay_slice(&anchored, &text, calls),
            );
        }
        bench(
            filter,
            &format!("slice/fixed_hit/{label}"),
            every.len(),
            || replay_slice(&fixed_anchored, &text, &every),
        );
        bench(
            filter,
            &format!("slice/fixed_miss/{label}"),
            every_miss.len(),
            || replay_slice(&fixed_anchored, &text, &every_miss),
        );
    }
}
