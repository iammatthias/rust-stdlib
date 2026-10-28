//! Ports of Go's regexp all_test.go and find_test.go tables (generated into
//! tests/fixtures/regexp_tables.rs) plus API and linear-time checks.
use rust_stdlib::regexp::*;

#[allow(dead_code)]
#[path = "fixtures/regexp_tables.rs"]
mod tables;
use tables::regexp as t;

fn utf8(b: &[u8]) -> &str {
    std::str::from_utf8(b).unwrap()
}

#[test]
fn good_and_bad_compile() {
    for re in t::GOOD_RE {
        assert!(compile(utf8(re)).is_ok(), "{re:?}");
    }
    for &(re, err) in t::BAD_RE {
        let e = compile(re).unwrap_err().to_string();
        assert!(e.contains(err), "{re:?}: {e}");
    }
    let e = compile(&r"\pL".repeat(27000)).unwrap_err().to_string();
    assert!(e.contains("expression too large"), "{e}");
}

/// Expected FindAllStringSubmatchIndex rows -> every other Find variant.
#[test]
fn find_variants() {
    for &(pat, text, max, matches) in t::FIND_TESTS {
        let re = compile(pat).unwrap();
        let Ok(s) = std::str::from_utf8(text) else {
            let re = compile(pat).unwrap();
            assert_eq!(
                re.find_all_index(text, max).len(),
                re.find_all_submatch_index(text, max).len()
            );
            continue;
        };
        let want: Vec<Vec<isize>> = matches.iter().map(|m| m.to_vec()).collect();
        let pairs: Vec<(usize, usize)> = want
            .iter()
            .map(|m| (m[0] as usize, m[1] as usize))
            .collect();
        let ctx = format!("pat {pat:?} text {s:?} max {max}");
        assert_eq!(
            re.match_string(s),
            !want.is_empty() || max == 0 && re.match_string(s),
            "{ctx}"
        );
        assert_eq!(re.find_all_string_submatch_index(s, max), want, "{ctx}");
        assert_eq!(re.find_all_submatch_index(text, max), want, "{ctx}");
        assert_eq!(re.find_all_index(text, max), pairs, "{ctx}");
        assert_eq!(re.find_all_string_index(s, max), pairs, "{ctx}");
        let strs: Vec<&str> = pairs.iter().map(|&(a, b)| &s[a..b]).collect();
        assert_eq!(re.find_all_string(s, max), strs, "{ctx}");
        assert_eq!(re.find_all(text, max).len(), strs.len(), "{ctx}");
        let sub: Vec<Vec<Option<&str>>> = want
            .iter()
            .map(|m| {
                m.chunks(2)
                    .map(|p| (p[0] >= 0).then(|| &s[p[0] as usize..p[1] as usize]))
                    .collect()
            })
            .collect();
        assert_eq!(re.find_all_string_submatch(s, max), sub, "{ctx}");
        if max != 0 {
            let first = want.first();
            assert_eq!(re.find_string_submatch_index(s).as_ref(), first, "{ctx}");
            assert_eq!(re.find_submatch_index(text).as_ref(), first, "{ctx}");
            assert_eq!(re.find_string_index(s), pairs.first().copied(), "{ctx}");
            assert_eq!(re.find_index(text), pairs.first().copied(), "{ctx}");
            assert_eq!(re.find_string(s), strs.first().copied(), "{ctx}");
            assert_eq!(
                re.find_reader_index(&mut Utf8RuneReader::new(text)),
                pairs.first().copied(),
                "{ctx}"
            );
            assert_eq!(
                re.find_reader_submatch_index(&mut Utf8RuneReader::new(text))
                    .as_ref(),
                first,
                "{ctx}"
            );
            assert_eq!(
                re.find_string_submatch(s).map(|v| v.len()),
                sub.first().map(|v| v.len()),
                "{ctx}"
            );
        }
    }
}

#[test]
fn replace_tables() {
    for &(pat, repl, input, output) in t::REPLACE_TESTS {
        let re = compile(pat).unwrap();
        assert_eq!(
            re.replace_all_string(input, repl),
            output,
            "{pat:?} {repl:?} {input:?}"
        );
        assert_eq!(
            re.replace_all(input.as_bytes(), repl.as_bytes()),
            output.as_bytes()
        );
        if !repl.contains('$') {
            assert_eq!(re.replace_all_literal_string(input, repl), output);
            assert_eq!(
                re.replace_all_literal(input.as_bytes(), repl.as_bytes()),
                output.as_bytes()
            );
        }
    }
    for &(pat, repl, input, output) in t::REPLACE_LITERAL_TESTS {
        let re = compile(pat).unwrap();
        assert_eq!(
            re.replace_all_literal_string(input, repl),
            output,
            "{pat:?}"
        );
        assert_eq!(
            re.replace_all_literal(input.as_bytes(), repl.as_bytes()),
            output.as_bytes()
        );
    }
    let f = |s: &str| format!("x{s}y");
    for (pat, input, output) in [
        ("[a-c]", "defabcdef", "defxayxbyxcydef"),
        ("[a-c]+", "defabcdef", "defxabcydef"),
        ("[a-c]*", "defabcdef", "xydxyexyfxabcydxyexyfxy"),
    ] {
        let re = compile(pat).unwrap();
        assert_eq!(re.replace_all_string_func(input, f), output);
        let b = re.replace_all_func(input.as_bytes(), |m| f(utf8(m)).into_bytes());
        assert_eq!(b, output.as_bytes());
    }
}

#[test]
fn quote_meta_and_literal_prefix() {
    for &(pat, quoted, _, _) in t::META_TESTS {
        assert_eq!(quote_meta(pat), quoted);
        if !pat.is_empty() {
            let re = compile(quoted).unwrap();
            assert_eq!(
                re.replace_all_string(&format!("abc{pat}def"), "xyz"),
                "abcxyzdef"
            );
        }
    }
    for &(pat, _, lit, complete) in t::META_TESTS.iter().chain(t::LITERAL_PREFIX_TESTS) {
        assert_eq!(
            must_compile(pat).literal_prefix(),
            (lit, complete),
            "{pat:?}"
        );
    }
}

#[test]
fn subexp() {
    for &(input, num, names, indices) in t::SUBEXP_CASES {
        let re = must_compile(input);
        assert_eq!(re.num_subexp(), num, "{input:?}");
        assert_eq!(re.subexp_names().len(), 1 + num);
        for (i, n) in names.iter().enumerate() {
            assert_eq!(re.subexp_names()[i], *n);
        }
        for &(name, idx) in indices {
            assert_eq!(
                re.subexp_index(name).map_or(-1, |i| i as isize),
                idx,
                "{input:?} {name:?}"
            );
        }
    }
}

#[test]
fn split_tables() {
    for &(s, r, n, out) in t::SPLIT_TESTS {
        let re = compile(r).unwrap();
        assert_eq!(re.split(s, n), out, "{s:?} {r:?} {n}");
    }
}

#[test]
fn marshal_roundtrip() {
    let mut un = Regexp::default();
    for re in t::GOOD_RE {
        let re = must_compile(utf8(re));
        un.unmarshal_text(&re.marshal_text()).unwrap();
        assert_eq!(un.as_str(), re.as_str());
        let mut buf = vec![0u8; 4];
        re.append_text(&mut buf);
        un.unmarshal_text(&buf[4..]).unwrap();
        assert_eq!(un.to_string(), re.to_string());
    }
    assert!(Regexp::default().unmarshal_text(b"\\").is_err());
}

#[test]
fn longest_and_posix() {
    let mut re = compile("a(|b)").unwrap();
    assert_eq!(re.find_string("ab"), Some("a"));
    re.longest();
    assert_eq!(re.find_string("ab"), Some("ab"));
    assert_eq!(
        compile_posix("a(|b)").unwrap().find_string("ab"),
        Some("ab")
    );
    assert!(compile_posix(r"\d").is_err());
}

#[test]
fn expand_rules() {
    let re = must_compile(r"(?P<k>\w+)=(\w+)");
    let m = re.find_string_submatch_index("a=b").unwrap();
    let mut dst = Vec::new();
    re.expand_string(&mut dst, "$k:$2:${1}x:$1x:$$:$9:${k", "a=b", &m);
    assert_eq!(dst, b"a:b:ax::$::${k");
}

#[test]
fn reader_and_invalid_utf8() {
    let re = must_compile("é+");
    assert!(re.match_reader(&mut Utf8RuneReader::new("xéé".as_bytes())));
    assert_eq!(
        re.find_reader_index(&mut Utf8RuneReader::new("xéé".as_bytes())),
        Some((1, 5))
    );
    // An invalid byte reads as U+FFFD with width 1.
    let re = must_compile("\u{fffd}");
    assert_eq!(re.find_index(b"a\xffb"), Some((1, 2)));
    assert_eq!(
        re.find_reader_index(&mut Utf8RuneReader::new(&b"a\xffb"[..])),
        Some((1, 2))
    );
}

/// Yields `a`s and panics on the third rune.
struct PanickyReader(usize);

impl rust_stdlib::io::RuneReader for PanickyReader {
    fn read_rune(&mut self) -> std::io::Result<(char, usize)> {
        self.0 += 1;
        assert!(self.0 < 3, "reader failed");
        Ok(('a', 1))
    }
}

#[test]
fn search_after_reader_panic() {
    let re = must_compile("a+b");
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        re.find_reader_index(&mut PanickyReader(0))
    }));
    assert!(panicked.is_err());
    assert_eq!(re.find_index(b"xaab"), Some((1, 4)));
    assert_eq!(
        re.find_reader_index(&mut Utf8RuneReader::new(&b"xaab"[..])),
        Some((1, 4))
    );
}

#[test]
fn shared_across_threads() {
    let re = must_compile(r"[a-z]+\d");
    let text = b"... abc1 xyz ";
    std::thread::scope(|s| {
        for _ in 0..8 {
            s.spawn(|| {
                for _ in 0..2000 {
                    assert_eq!(re.find_anchored_index_at(text, 4), Some((4, 8)));
                    assert_eq!(re.find_anchored_index_at(text, 9), None);
                    assert_eq!(re.find_index_at(text, 5), Some((5, 8)));
                }
            });
        }
    });
}

/// Searches the same regexp from inside `read_rune`, so the outer search
/// holds the pooled state while the inner one runs.
struct ReentrantReader<'a> {
    re: &'a rust_stdlib::regexp::Regexp,
    text: &'a [u8],
    pos: usize,
    inner: Vec<Option<(usize, usize)>>,
}

impl rust_stdlib::io::RuneReader for ReentrantReader<'_> {
    fn read_rune(&mut self) -> std::io::Result<(char, usize)> {
        self.inner.push(self.re.find_anchored_index_at(b"ab1", 0));
        let Some(&b) = self.text.get(self.pos) else {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        };
        self.pos += 1;
        Ok((char::from(b), 1))
    }
}

#[test]
fn search_reentered_from_reader() {
    let re = must_compile(r"[a-z]+\d");
    let mut r = ReentrantReader {
        re: &re,
        text: b"..xy7",
        pos: 0,
        inner: Vec::new(),
    };
    assert_eq!(re.find_reader_index(&mut r), Some((2, 5)));
    assert!(!r.inner.is_empty());
    assert!(r.inner.iter().all(|m| *m == Some((0, 3))));
    assert_eq!(re.find_index(b"..xy7"), Some((2, 5)));
}

#[test]
fn linear_time() {
    // a?^n a^n is exponential for backtrackers.
    let n = 2000;
    let re = must_compile(&format!("{}{}", "a?".repeat(n), "a".repeat(n)));
    let text = "a".repeat(n);
    assert_eq!(re.find_index(text.as_bytes()), Some((0, n)));
    let re = must_compile("(x+x+)+y");
    assert!(!re.match_string(&"x".repeat(5000)));
    // Deeply nested alternation must not overflow the stack.
    let re = must_compile(&format!("{}a{}", "(?:".repeat(900), ")*".repeat(900)));
    assert!(re.match_string("aaa"));
}

#[test]
fn must_compile_panics_with_go_message() {
    let r = std::panic::catch_unwind(|| must_compile("a**"));
    let msg = *r.unwrap_err().downcast::<String>().unwrap();
    assert_eq!(
        msg,
        "regexp: Compile(`a**`): error parsing regexp: invalid nested repetition operator: `**`"
    );
}

#[test]
fn top_level_match_functions() {
    assert_eq!(match_string("a+b", "xaab"), Ok(true));
    assert_eq!(match_bytes("a+b", b"xb"), Ok(false));
    assert!(match_string("(", "x").is_err());
    assert_eq!(
        match_reader("b", &mut Utf8RuneReader::new(&b"abc"[..])),
        Ok(true)
    );
}

/// Go's TestRunOnePass (onepass_test.go, golang.org/issue/11905).
#[test]
fn run_one_pass() {
    let re = compile(r"^a(/b+(#c+)*)*$").unwrap();
    assert_eq!(re.literal_prefix(), ("a", false));
    assert!(re.match_string("a/b#c"));
}

/// Go's TestSwitchBacktrack: pooled state serves the Pike VM, then the
/// backtracker (golang.org/issue/10319).
#[test]
fn switch_backtrack() {
    let re = compile("a|b").unwrap();
    let long = vec![0u8; 256 * 1024 + 1];
    assert!(!re.match_bytes(&long));
    assert!(!re.match_bytes(&long[..1]));
    assert!(re.match_bytes(b"b"));
}

/// Go's TestProgramTooLongForBacktrack.
#[test]
fn program_too_long_for_backtrack() {
    let words = "one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|twentyone|twentytwo|twentythree|twentyfour|twentyfive|twentysix|twentyseven|twentyeight|twentynine|thirty|thirtyone|thirtytwo|thirtythree|thirtyfour|thirtyfive|thirtysix|thirtyseven|thirtyeight|thirtynine|forty|fortyone|fortytwo|fortythree|fortyfour|fortyfive|fortysix|fortyseven|fortyeight|fortynine|fifty|fiftyone|fiftytwo|fiftythree|fiftyfour|fiftyfive|fiftysix|fiftyseven|fiftyeight|fiftynine|sixty|sixtyone|sixtytwo|sixtythree|sixtyfour|sixtyfive|sixtysix|sixtyseven|sixtyeight|sixtynine|seventy|seventyone|seventytwo|seventythree|seventyfour|seventyfive|seventysix|seventyseven|seventyeight|seventynine|eighty|eightyone|eightytwo|eightythree|eightyfour|eightyfive|eightysix|eightyseven|eightyeight|eightynine|ninety|ninetyone|ninetytwo|ninetythree|ninetyfour|ninetyfive|ninetysix|ninetyseven|ninetyeight|ninetynine|onehundred";
    let re = compile(&format!("({words})")).unwrap();
    assert!(re.match_string("two"));
    assert!(!re.match_string("xxx"));
}

#[test]
fn find_at_keeps_context() {
    let re = compile(r"\bfoo").unwrap();
    let b = b"foo xfoo foo";
    assert_eq!(re.find_index_at(b, 0), Some((0, 3)));
    assert_eq!(re.find_index_at(b, 1), Some((9, 12)));
    assert_eq!(re.find_index_at(b, 5), Some((9, 12)));
    assert_eq!(compile("^a").unwrap().find_index_at(b"aa", 1), None);
    let ml = compile("(?m)^a").unwrap();
    assert_eq!(ml.find_index_at(b"a\na", 1), Some((2, 3)));
    assert_eq!(
        compile(r"\B.").unwrap().find_index_at(b"ab", 1),
        Some((1, 2))
    );
    assert_eq!(compile(r"\b.").unwrap().find_index_at(b"ab", 1), None);
    // A start inside a UTF-8 sequence sees an invalid byte, as U+FFFD.
    assert_eq!(
        compile(".").unwrap().find_index_at("é".as_bytes(), 1),
        Some((1, 2))
    );
    assert_eq!(compile("x*").unwrap().find_index_at(b"ab", 2), Some((2, 2)));
    let kv = compile(r"(\w+)=(\d+)?").unwrap();
    assert_eq!(
        kv.find_submatch_index_at(b"; k=v", 0),
        Some(vec![2, 4, 2, 3, -1, -1])
    );
}

#[test]
fn find_anchored_at() {
    let word = compile("[a-z]+").unwrap();
    assert_eq!(word.find_anchored_index_at(b"12 ab", 0), None);
    assert_eq!(word.find_anchored_index_at(b"12 ab", 3), Some((3, 5)));
    assert_eq!(word.find_anchored_index_at(b"12 ab", 4), Some((4, 5)));
    let ml = compile("(?m)^a").unwrap();
    assert_eq!(ml.find_anchored_index_at(b"a\na", 1), None);
    assert_eq!(ml.find_anchored_index_at(b"a\na", 2), Some((2, 3)));
    // A literal prefix that is absent at start fails fast; present, it matches.
    let comment = compile(r"//[^\n]*").unwrap();
    assert_eq!(comment.find_anchored_index_at(b"a / b // c\n", 2), None);
    assert_eq!(
        comment.find_anchored_index_at(b"a / b // c\n", 6),
        Some((6, 10))
    );
    // \A holds only at offset 0, so a one-pass pattern matches only there.
    let onepass = compile("^ab$").unwrap();
    assert_eq!(onepass.find_anchored_index_at(b"ab", 0), Some((0, 2)));
    assert_eq!(onepass.find_anchored_index_at(b"xab", 1), None);
    let mut alt = compile("a|ab").unwrap();
    assert_eq!(alt.find_anchored_index_at(b"xab", 1), Some((1, 2)));
    alt.longest();
    assert_eq!(alt.find_anchored_index_at(b"xab", 1), Some((1, 3)));
    let kv = compile(r"(\w+)=(\d+)?").unwrap();
    assert_eq!(kv.find_anchored_submatch_index_at(b"; k=v", 0), None);
    assert_eq!(
        kv.find_anchored_submatch_index_at(b"; k=v", 2),
        Some(vec![2, 4, 2, 3, -1, -1])
    );
}

/// A tokenizer: at each offset, the first pattern with a non-empty match
/// there wins.
#[test]
fn anchored_tokenizer() {
    let kinds = [
        ("space", r"\s+"),
        ("keyword", r"(?:if|else|return)\b"),
        ("ident", r"[A-Za-z_]\w*"),
        ("number", r"[0-9]+"),
        ("op", r"==|[=+(){};]"),
    ];
    let res: Vec<_> = kinds.iter().map(|(_, p)| compile(p).unwrap()).collect();
    let src = b"if (x == 10) { return x+1; } else_y";
    let (mut pos, mut tokens) = (0, Vec::new());
    'next: while pos < src.len() {
        for (k, re) in res.iter().enumerate() {
            if let Some((s, e)) = re.find_anchored_index_at(src, pos) {
                if e > s {
                    if kinds[k].0 != "space" {
                        tokens.push((kinds[k].0, utf8(&src[s..e])));
                    }
                    pos = e;
                    continue 'next;
                }
            }
        }
        panic!("no token at {pos}");
    }
    assert_eq!(
        tokens,
        [
            ("keyword", "if"),
            ("op", "("),
            ("ident", "x"),
            ("op", "=="),
            ("number", "10"),
            ("op", ")"),
            ("op", "{"),
            ("keyword", "return"),
            ("ident", "x"),
            ("op", "+"),
            ("number", "1"),
            ("op", ";"),
            ("op", "}"),
            ("ident", "else_y"),
        ]
    );
}

#[test]
#[should_panic(expected = "regexp: start 2 out of range for text of length 1")]
fn find_at_past_end_panics() {
    compile("a").unwrap().find_index_at(b"a", 2);
}
