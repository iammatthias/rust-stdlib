//! Times regexp matching on a lexer-like workload and on cases from Go's
//! regexp benchmarks: `cargo run --release --example regexp_bench [filter]`.
//! Each line is `name ns/op (min median max over runs) check=<checksum>`; the
//! checksum proves the work ran and must agree between builds.
use rust_stdlib::regexp::{must_compile, Regexp};
use std::hint::black_box;
use std::time::Instant;

const RUNS: usize = 7;
const TARGET_NS: u128 = 60_000_000;

/// Go's `makeText` from exec_test.go.
fn make_text(n: usize) -> Vec<u8> {
    let mut text = vec![0u8; n];
    let mut x: u32 = !0;
    for b in &mut text {
        x = x.wrapping_add(x);
        x ^= 1;
        if (x as i32) < 0 {
            x ^= 0x8888_8eef;
        }
        *b = if x.is_multiple_of(31) {
            b'\n'
        } else {
            (x % (0x7e + 1 - 0x20) + 0x20) as u8
        };
    }
    text
}

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

const TOKENS: &[&str] = &[
    r"[ \t\r\n]+",
    r"//[^\n]*",
    r"/\*(?s:.)*?\*/",
    r#""(?:[^"\\\n]|\\.)*""#,
    r"`[^`]*`",
    r"'(?:[^'\\]|\\.)'",
    r"(?:break|case|chan|const|continue|default|defer|else|fallthrough|for|func|go|goto|if|import|interface|map|package|range|return|select|struct|switch|type|var)\b",
    r"(?:true|false|nil|iota)\b",
    r"(?:bool|byte|float64|int|rune|string|error)\b",
    r"0[xX][0-9a-fA-F_]+",
    r"[0-9]+\.[0-9]*(?:[eE][+-]?[0-9]+)?",
    r"[0-9]+(?:[eE][+-]?[0-9]+)?",
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
    s
}

/// Lexes `text` with the patterns compiled as `^(?:tok)` and matched against
/// `&text[pos..]`: the only anchored-at-offset form the Go-shaped API offers.
fn lex_slice(res: &[Regexp], text: &[u8]) -> usize {
    let (mut pos, mut check) = (0, 0);
    'outer: while pos < text.len() {
        for (k, re) in res.iter().enumerate() {
            if let Some((_, e)) = re.find_index(&text[pos..]) {
                if e > 0 {
                    pos += e;
                    check = check * 31 + k + pos;
                    continue 'outer;
                }
            }
        }
        pos += 1;
    }
    check
}

/// Lexes `text` with the anchored-at-offset API.
fn lex_at(res: &[Regexp], text: &[u8]) -> usize {
    let (mut pos, mut check) = (0, 0);
    'outer: while pos < text.len() {
        for (k, re) in res.iter().enumerate() {
            if let Some((_, e)) = re.find_anchored_index_at(text, pos) {
                if e > pos {
                    pos = e;
                    check = check * 31 + k + pos;
                    continue 'outer;
                }
            }
        }
        pos += 1;
    }
    check
}

fn bench(filter: &str, name: &str, mut f: impl FnMut() -> usize) {
    if !name.contains(filter) {
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
            t.elapsed().as_nanos() as f64 / n as f64
        })
        .collect();
    runs.sort_by(|a, b| a.total_cmp(b));
    println!(
        "{name:<34} {:>12.1} ns/op (min {:.1} max {:.1}, {RUNS} runs x {n}) check={check}",
        runs[RUNS / 2],
        runs[0],
        runs[RUNS - 1]
    );
}

fn main() {
    let filter = std::env::args().nth(1).unwrap_or_default();
    let filter = filter.as_str();

    let anchored: Vec<Regexp> = TOKENS
        .iter()
        .map(|t| must_compile(&format!("^(?:{t})")))
        .collect();
    let plain: Vec<Regexp> = TOKENS.iter().map(|t| must_compile(t)).collect();
    for size in [2 << 10, 64 << 10] {
        let text = source(size);
        bench(filter, &format!("lexer/slice/{}K", size >> 10), || {
            lex_slice(&anchored, &text)
        });
        bench(filter, &format!("lexer/at/{}K", size >> 10), || {
            lex_at(&plain, &text)
        });
    }

    for (name, re) in [
        ("Easy0", "ABCDEFGHIJKLMNOPQRSTUVWXYZ$"),
        ("Easy1", "A[AB]B[BC]C[CD]D[DE]E[EF]F[FG]G[GH]H[HI]I[IJ]J$"),
        ("Medium", "[XYZ]ABCDEFGHIJKLMNOPQRSTUVWXYZ$"),
        ("Hard", "[ -~]*ABCDEFGHIJKLMNOPQRSTUVWXYZ$"),
        (
            "Hard1",
            "ABCD|CDEF|EFGH|GHIJ|IJKL|KLMN|MNOP|OPQR|QRST|STUV|UVWX|WXYZ",
        ),
    ] {
        let re = must_compile(re);
        for (sname, n) in [("32", 32), ("1K", 1 << 10), ("32K", 32 << 10)] {
            let t = make_text(n);
            bench(filter, &format!("Match/{name}/{sname}"), || {
                usize::from(re.match_bytes(&t))
            });
        }
    }
    let onepass = must_compile(r"(?s)\A.*\z");
    for (sname, n) in [("32", 32), ("1K", 1 << 10), ("32K", 32 << 10)] {
        let t = make_text(n);
        bench(filter, &format!("Match_onepass_regex/{sname}"), || {
            usize::from(onepass.match_bytes(&t))
        });
    }

    let short = b"abcddddddeeeededd";
    let alpha = b"abcdefghijklmnopqrstuvwxyz";
    for (name, re, x) in [
        ("OnePassShortA", "^.bc(d|e)*$", &short[..]),
        ("NotOnePassShortA", ".bc(d|e)*$", short),
        ("OnePassShortB", "^.bc(?:d|e)*$", short),
        ("NotOnePassShortB", ".bc(?:d|e)*$", short),
        ("OnePassLongPrefix", "^abcdefghijklmnopqrstuvwxyz.*$", alpha),
        (
            "OnePassLongNotPrefix",
            "^.bcdefghijklmnopqrstuvwxyz.*$",
            alpha,
        ),
        ("AnchoredLiteralShortNonMatch", "^zbc(d|e)", alpha),
        ("AnchoredShortMatch", "^.bc(d|e)", alpha),
    ] {
        let re = must_compile(re);
        bench(filter, name, || usize::from(re.match_bytes(x)));
    }
    let x = "x".repeat(50) + "y";
    for (name, re) in [("Literal", "y"), ("NotLiteral", ".y")] {
        let re = must_compile(re);
        bench(filter, name, || usize::from(re.match_string(&x)));
    }
    let re = must_compile("[abcdw]");
    let x = "xxxx".repeat(20) + "w";
    bench(filter, "MatchClass", || usize::from(re.match_string(&x)));
    let re = must_compile("a(a+b+)b");
    let x = "acbb".repeat(10) + "aaabbb";
    bench(filter, "FindSubmatch", || {
        re.find_submatch_index(x.as_bytes()).map_or(0, |m| m.len())
    });
}
