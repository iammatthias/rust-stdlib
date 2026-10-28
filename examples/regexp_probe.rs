//! Line protocol used by `tools/regexp/check.py`; mirrors `tools/regexp/oracle.go`.
use rust_stdlib::regexp::syntax::{self, Flags, InstOp, Op, Regexp as Syntax};
use rust_stdlib::regexp::{self, Engine, Utf8RuneReader};
use std::io::{self, BufRead, Write};

fn hx(s: &[u8]) -> String {
    let mut out = String::from("h:");
    for b in s {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn list<T>(items: impl IntoIterator<Item = T>, f: impl Fn(T) -> String) -> String {
    let parts: Vec<String> = items.into_iter().map(f).collect();
    if parts.is_empty() {
        "nil".into()
    } else {
        format!("[{}]", parts.join(","))
    }
}

fn ints(a: &[isize]) -> String {
    list(a, |v| v.to_string())
}

fn pair(a: Option<(usize, usize)>) -> String {
    match a {
        Some((x, y)) => format!("[{x},{y}]"),
        None => "nil".into(),
    }
}

fn pairs(a: &[(usize, usize)]) -> String {
    list(a, |&(x, y)| format!("[{x},{y}]"))
}

fn intss(a: &[Vec<isize>]) -> String {
    list(a, |v| ints(v))
}

fn strs<S: AsRef<[u8]>>(a: &[S]) -> String {
    list(a, |v| hx(v.as_ref()))
}

fn opt_strs<S: AsRef<[u8]>>(a: &[Option<S>]) -> String {
    list(a, |v| hx(v.as_ref().map_or(&[][..], |s| s.as_ref())))
}

fn opt_strss<S: AsRef<[u8]>>(a: &[Vec<Option<S>>]) -> String {
    list(a, |v| opt_strs(v))
}

fn dump(b: &mut String, re: &Syntax) {
    b.push_str(&format!("({} f={}", re.op, re.flags.0));
    match re.op {
        Op::LITERAL | Op::CHAR_CLASS => {
            let runes: Vec<String> = re.rune.iter().map(|r| format!("{r:x}")).collect();
            b.push_str(&format!(" r=[{}]", runes.join(" ")));
        }
        Op::REPEAT => b.push_str(&format!(" {},{}", re.min, re.max)),
        Op::CAPTURE => b.push_str(&format!(" {},{}", re.cap, re.name)),
        _ => {}
    }
    for s in &re.sub {
        b.push(' ');
        dump(b, s);
    }
    b.push(')');
}

fn syntax_case(out: &mut String, flags: Flags, pattern: &[u8]) {
    let re = match syntax::parse_bytes(pattern, flags) {
        Err(e) => {
            out.push_str(&format!(
                "ERR code={} msg={}",
                hx(e.code.0.as_bytes()),
                hx(e.to_string().as_bytes())
            ));
            return;
        }
        Ok(re) => re,
    };
    let mut d = String::new();
    dump(&mut d, &re);
    out.push_str(&format!(
        "OK str={} dump={} maxcap={} names={}",
        hx(re.to_string().as_bytes()),
        hx(d.as_bytes()),
        re.max_cap(),
        strs(&re.cap_names())
    ));
    let again = syntax::parse(&re.to_string(), flags);
    out.push_str(&format!(
        " reparse={}",
        again.map(|a| a.equal(&re)).unwrap_or(false)
    ));
    let simp = re.simplify();
    d.clear();
    dump(&mut d, &simp);
    out.push_str(&format!(
        " simp={} simpdump={}",
        hx(simp.to_string().as_bytes()),
        hx(d.as_bytes())
    ));
    let prog = match syntax::compile(&simp) {
        Ok(p) => p,
        Err(e) => {
            out.push_str(&format!(" cerr={}", hx(e.to_string().as_bytes())));
            return;
        }
    };
    let (prefix, complete) = prog.prefix();
    out.push_str(&format!(
        " prog={} numcap={} start={} prefix={},{} cond={}",
        hx(prog.to_string().as_bytes()),
        prog.num_cap,
        prog.start,
        hx(prefix.as_bytes()),
        complete,
        prog.start_cond().0
    ));
    let mut mr = Vec::new();
    for inst in &prog.inst {
        match inst.op {
            InstOp::RUNE | InstOp::RUNE1 | InstOp::RUNE_ANY | InstOp::RUNE_ANY_NOT_NL => {
                let mut r = Vec::new();
                for c in [
                    'a' as i32,
                    'A' as i32,
                    'b' as i32,
                    'k' as i32,
                    'K' as i32,
                    '0' as i32,
                    ' ' as i32,
                    '\n' as i32,
                    0,
                    0x3b1,
                    0x391,
                    0x212a,
                    0x17f,
                    0x10000,
                    0x10ffff,
                    -1,
                ] {
                    r.push(inst.match_rune_pos(c).to_string());
                    assert_eq!(inst.match_rune(c), inst.match_rune_pos(c) != -1);
                }
                mr.push(r.join(":"));
            }
            InstOp::EMPTY_WIDTH => {
                let mut r = Vec::new();
                for (a, b) in [
                    (-1, -1),
                    (-1, 'a' as i32),
                    ('a' as i32, -1),
                    ('a' as i32, 'a' as i32),
                    ('a' as i32, ' ' as i32),
                    (' ' as i32, 'a' as i32),
                    ('\n' as i32, 'a' as i32),
                    ('a' as i32, '\n' as i32),
                    (' ' as i32, ' ' as i32),
                ] {
                    r.push(inst.match_empty_width(a, b).to_string());
                }
                mr.push(r.join(":"));
            }
            _ => {}
        }
    }
    out.push_str(&format!(" mr={}", mr.join(";")));
}

const TEMPLATES: [&str; 19] = [
    "",
    "x",
    "$0",
    "<$1>",
    "${1}x",
    "$1x",
    "$name",
    "${name}",
    "$$",
    "$",
    "${",
    "${1",
    "$2$1",
    "$a_b1",
    "$10",
    "[$0|$1|$2|$x]",
    "$n1$é",
    "$01",
    "$ 1",
];

fn compile(mode: &str, pattern: &str) -> Result<regexp::Regexp, String> {
    let compiled = if mode == "X" {
        regexp::compile_posix(pattern)
    } else {
        regexp::compile(pattern).map(|mut re| {
            if mode == "L" {
                re.longest();
            }
            re
        })
    };
    compiled.map_err(|e| format!("ERR msg={}", hx(e.to_string().as_bytes())))
}

/// Every offset: the leftmost match from there, with and without
/// submatches, and the match anchored there.
fn offset_case(out: &mut String, re: &regexp::Regexp, b: &[u8]) {
    out.push_str("OK");
    for pos in 0..=b.len() {
        out.push_str(&format!(
            " {pos}:{}:{}:{}:{}",
            pair(re.find_index_at(b, pos)),
            ints(&re.find_submatch_index_at(b, pos).unwrap_or_default()),
            pair(re.find_anchored_index_at(b, pos)),
            ints(
                &re.find_anchored_submatch_index_at(b, pos)
                    .unwrap_or_default()
            ),
        ));
    }
}

/// Runs `case` with Go's matcher choice, then with each matcher forced, and
/// panics if any disagrees; returns the line.
fn every_engine(re: regexp::Regexp, case: impl Fn(&mut String, &regexp::Regexp)) -> String {
    let mut want = String::new();
    case(&mut want, &re);
    for engine in [Engine::OnePass, Engine::Backtrack, Engine::Pike] {
        let mut forced = re.clone();
        forced.force_engine(engine);
        let mut got = String::new();
        case(&mut got, &forced);
        assert!(
            got == want,
            "{engine:?} differs on {}:\n  {got}\n  {want}",
            re.as_str()
        );
    }
    want
}

fn match_case(out: &mut String, re: &regexp::Regexp, input: &[u8]) {
    let text = std::str::from_utf8(input).ok();
    let valid = text.is_some();
    let b = input;
    let (prefix, complete) = re.literal_prefix();
    out.push_str(&format!(
        "OK expr={} nsub={} names={} lp={},{} valid={}",
        hx(re.as_str().as_bytes()),
        re.num_subexp(),
        strs(re.subexp_names()),
        hx(prefix.as_bytes()),
        complete,
        valid
    ));
    let mut idx = Vec::new();
    let mut names: Vec<String> = re.subexp_names().to_vec();
    names.push("zzz".into());
    names.push(String::new());
    for n in &names {
        idx.push(re.subexp_index(n).map_or(-1, |i| i as isize).to_string());
    }
    out.push_str(&format!(" sidx={}", idx.join(",")));
    out.push_str(&format!(
        " match={} matchb={}",
        text.map_or_else(|| re.match_bytes(b), |t| re.match_string(t)),
        re.match_bytes(b)
    ));
    let reader = || Utf8RuneReader::new(b);
    out.push_str(&format!(" mrd={}", re.match_reader(&mut reader())));
    out.push_str(&format!(
        " frdi={} frdsi={}",
        pair(re.find_reader_index(&mut reader())),
        re.find_reader_submatch_index(&mut reader())
            .map_or("nil".into(), |v| ints(&v))
    ));
    out.push_str(&format!(
        " fi={} fsi={}",
        pair(re.find_index(b)),
        re.find_submatch_index(b).map_or("nil".into(), |v| ints(&v))
    ));
    out.push_str(&format!(
        " fb={} fsb={}",
        hx(re.find(b).unwrap_or(b"")),
        re.find_submatch(b).map_or("nil".into(), |v| opt_strs(&v))
    ));
    for n in [-1isize, 0, 1, 2, 3] {
        out.push_str(&format!(
            " faib{n}={} fasib{n}={} fab{n}={} fasb{n}={}",
            pairs(&re.find_all_index(b, n)),
            intss(&re.find_all_submatch_index(b, n)),
            strs(&re.find_all(b, n)),
            opt_strss(&re.find_all_submatch(b, n))
        ));
    }
    for t in TEMPLATES {
        out.push_str(&format!(" rb={}", hx(&re.replace_all(b, t.as_bytes()))));
    }
    out.push_str(&format!(" rlb={}", hx(&re.replace_all_literal(b, b"$1"))));
    out.push_str(&format!(
        " rfb={}",
        hx(&re.replace_all_func(b, |m| {
            let mut v = vec![b'<'];
            v.extend_from_slice(m);
            v.push(b'>');
            v
        }))
    ));
    if let Some(m) = re.find_submatch_index(b) {
        for t in TEMPLATES {
            let mut dst = b"pre:".to_vec();
            re.expand(&mut dst, t.as_bytes(), b, &m);
            out.push_str(&format!(" eb={}", hx(&dst)));
        }
    }
    let Some(s) = text else {
        out.push_str(" strings=skipped");
        return;
    };
    out.push_str(&format!(
        " fsi_={} fss={} fs={}",
        pair(re.find_string_index(s)),
        re.find_string_submatch(s)
            .map_or("nil".into(), |v| opt_strs(&v)),
        hx(re.find_string(s).unwrap_or("").as_bytes())
    ));
    out.push_str(&format!(
        " fssi={}",
        re.find_string_submatch_index(s)
            .map_or("nil".into(), |v| ints(&v))
    ));
    for n in [-1isize, 0, 1, 2, 3] {
        let all = re.find_all_string(s, n);
        // The string API must agree with the byte API.
        assert_eq!(
            all.iter().map(|x| x.as_bytes()).collect::<Vec<_>>(),
            re.find_all(b, n)
        );
        out.push_str(&format!(
            " fasi{n}={} fassi{n}={} fas{n}={} fass{n}={}",
            pairs(&re.find_all_string_index(s, n)),
            intss(&re.find_all_string_submatch_index(s, n)),
            strs(&all),
            opt_strss(&re.find_all_string_submatch(s, n))
        ));
    }
    for t in TEMPLATES {
        let r = re.replace_all_string(s, t);
        assert_eq!(r.as_bytes(), &re.replace_all(b, t.as_bytes())[..]);
        out.push_str(&format!(" rs={}", hx(r.as_bytes())));
    }
    out.push_str(&format!(
        " rls={}",
        hx(re.replace_all_literal_string(s, "$1").as_bytes())
    ));
    out.push_str(&format!(
        " rfs={}",
        hx(re
            .replace_all_string_func(s, |m| format!("<{m}>"))
            .as_bytes())
    ));
    for n in [-1isize, 0, 1, 2, 3, 5] {
        out.push_str(&format!(" split{n}={}", strs(&re.split(s, n))));
    }
    if let Some(m) = re.find_string_submatch_index(s) {
        for t in TEMPLATES {
            let mut dst = b"pre:".to_vec();
            re.expand_string(&mut dst, t, s, &m);
            out.push_str(&format!(" es={}", hx(&dst)));
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdout = io::stdout();
    let mut w = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line?;
        let f: Vec<&str> = line.split('\t').collect();
        let mut out = String::new();
        match f[0] {
            "S" => syntax_case(&mut out, Flags(f[1].parse()?), &unhex(f[2])),
            "M" | "A" => {
                let pattern = String::from_utf8(unhex(f[2]))?;
                let input = unhex(f[3]);
                out = match compile(f[1], &pattern) {
                    Err(e) => e,
                    Ok(re) if f[0] == "M" => every_engine(re, |o, re| match_case(o, re, &input)),
                    Ok(re) => every_engine(re, |o, re| offset_case(o, re, &input)),
                };
            }
            "E" => {
                let (r1, r2): (i32, i32) = (f[1].parse()?, f[2].parse()?);
                out.push_str(&format!(
                    "{} {} {}",
                    syntax::empty_op_context(r1, r2).0,
                    syntax::is_word_char(r1),
                    syntax::is_word_char(r2)
                ));
            }
            other => return Err(format!("bad request {other}").into()),
        }
        writeln!(w, "{out}")?;
    }
    Ok(())
}
