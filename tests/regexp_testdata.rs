//! Ports of TestRE2Search/TestRE2Exhaustive/TestFowler from Go's regexp
//! exec_test.go. The checked-in copies in tests/fixtures/regexp always run;
//! when `go env GOROOT` works, the toolchain's testdata runs too, and
//! `RUST_STDLIB_RE2_EXHAUSTIVE=1` adds the 59 MB re2-exhaustive.txt.bz2
//! (decoded with `compress::bzip2`; use `--release`).
use rust_stdlib::compress::bzip2;
use rust_stdlib::regexp::{compile, compile_with, quote_meta, syntax::Flags, Regexp};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/regexp")
}

fn goroot_testdata() -> Option<PathBuf> {
    let out = std::process::Command::new("go")
        .args(["env", "GOROOT"])
        .output()
        .ok()?;
    let dir = PathBuf::from(String::from_utf8(out.stdout).ok()?.trim()).join("src/regexp/testdata");
    dir.is_dir().then_some(dir)
}

fn dirs() -> Vec<PathBuf> {
    let mut v = vec![fixtures()];
    v.extend(goroot_testdata());
    v
}

/// strconv.Unquote for a double-quoted Go string, as bytes.
fn unquote(line: &str) -> Vec<u8> {
    let b = line.as_bytes();
    assert!(
        b.len() >= 2 && b[0] == b'"' && b[b.len() - 1] == b'"',
        "{line}"
    );
    let b = &b[1..b.len() - 1];
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' {
            out.push(b[i]);
            i += 1;
            continue;
        }
        i += 1;
        let c = b[i];
        i += 1;
        let hex = |n: usize, i: &mut usize| {
            let v = u32::from_str_radix(std::str::from_utf8(&b[*i..*i + n]).unwrap(), 16).unwrap();
            *i += n;
            v
        };
        match c {
            b'a' => out.push(7),
            b'b' => out.push(8),
            b'f' => out.push(12),
            b'n' => out.push(10),
            b'r' => out.push(13),
            b't' => out.push(9),
            b'v' => out.push(11),
            b'\\' | b'"' | b'\'' => out.push(c),
            b'x' => out.push(hex(2, &mut i) as u8),
            b'u' | b'U' => {
                let v = hex(if c == b'u' { 4 } else { 8 }, &mut i);
                let mut buf = [0u8; 4];
                out.extend_from_slice(char::from_u32(v).unwrap().encode_utf8(&mut buf).as_bytes());
            }
            b'0'..=b'7' => {
                let v =
                    u32::from_str_radix(std::str::from_utf8(&b[i - 1..i + 2]).unwrap(), 8).unwrap();
                i += 2;
                out.push(v as u8);
            }
            _ => panic!("bad escape in {line}"),
        }
    }
    out
}

fn parse_result(res: &str) -> Option<Vec<isize>> {
    if res == "-" {
        return None;
    }
    let mut out = Vec::new();
    for pair in res.split(' ') {
        if pair == "-" {
            out.extend([-1, -1]);
        } else {
            let (lo, hi) = pair.split_once('-').expect("pair");
            let (lo, hi): (isize, isize) = (lo.parse().unwrap(), hi.parse().unwrap());
            assert!(lo <= hi, "invalid pair {pair}");
            out.extend([lo, hi]);
        }
    }
    Some(out)
}

fn test_re2(reader: impl Read, name: &str) -> usize {
    let mut strings: Vec<Vec<u8>> = Vec::new();
    let mut input: Vec<Vec<u8>> = Vec::new();
    let mut in_strings = false;
    let mut re: Option<(Regexp, Regexp, Regexp, Regexp)> = None; // partial, full, partial-longest, full-longest
    let (mut ncase, mut nfail) = (0, 0);
    for (n, line) in BufReader::new(reader).lines().enumerate() {
        let (lineno, line) = (n + 1, line.unwrap());
        let first = *line
            .as_bytes()
            .first()
            .unwrap_or_else(|| panic!("{name}:{lineno}: blank line"));
        match first {
            b'#' | b'A'..=b'Z' => {}
            _ if line == "strings" => {
                strings.clear();
                in_strings = true;
            }
            _ if line == "regexps" => in_strings = false,
            b'"' => {
                let q = unquote(&line);
                if in_strings {
                    strings.push(q);
                    continue;
                }
                assert!(input.is_empty(), "{name}:{lineno}: out of sync");
                re = None;
                let Ok(q) = String::from_utf8(q) else {
                    continue;
                };
                let make = |pat: &str, longest: bool| {
                    compile(pat).map(|mut r| {
                        if longest {
                            r.longest();
                        }
                        r
                    })
                };
                match make(&q, false) {
                    Err(e) => {
                        if e.to_string() != "error parsing regexp: invalid escape sequence: `\\C`" {
                            nfail += 1;
                            eprintln!("{name}:{lineno}: compile {q:?}: {e}");
                        }
                        continue;
                    }
                    Ok(p) => {
                        let full = format!(r"\A(?:{q})\z");
                        re = Some((
                            p,
                            make(&full, false).unwrap(),
                            make(&q, true).unwrap(),
                            make(&full, true).unwrap(),
                        ));
                        input = strings.clone();
                        input.reverse();
                    }
                }
            }
            b'-' | b'0'..=b'9' => {
                ncase += 1;
                let Some((p, f, pl, fl)) = &re else { continue };
                let text = input
                    .pop()
                    .unwrap_or_else(|| panic!("{name}:{lineno}: no input remaining"));
                if !text.is_ascii() && p.as_str().contains(r"\B") {
                    continue; // RE2's \B sees positions inside UTF-8 sequences
                }
                let res: Vec<&str> = line.split(';').collect();
                assert_eq!(res.len(), 4, "{name}:{lineno}");
                for (i, r) in [f, p, fl, pl].into_iter().enumerate() {
                    let want = parse_result(res[i]);
                    let have = r.find_submatch_index(&text);
                    if have != want || r.match_bytes(&text) != want.is_some() {
                        nfail += 1;
                        eprintln!(
                            "{name}:{lineno}: {:?}[{i}] on {:?} = {have:?}, want {want:?}",
                            p.as_str(),
                            String::from_utf8_lossy(&text)
                        );
                    }
                }
            }
            _ => panic!("{name}:{lineno}: out of sync: {line}"),
        }
        assert!(nfail < 100, "too many failures");
    }
    assert!(input.is_empty(), "{name}: out of sync at EOF");
    assert_eq!(nfail, 0, "{name}: failures");
    ncase
}

#[test]
fn re2_search() {
    for dir in dirs() {
        let f = std::fs::File::open(dir.join("re2-search.txt")).unwrap();
        let n = test_re2(f, "re2-search.txt");
        assert!(n > 1000, "only {n} cases");
    }
}

#[test]
fn re2_exhaustive() {
    if std::env::var_os("RUST_STDLIB_RE2_EXHAUSTIVE").is_none() {
        eprintln!("skipped: set RUST_STDLIB_RE2_EXHAUSTIVE=1 (and use --release)");
        return;
    }
    let dir = goroot_testdata().expect("GOROOT testdata");
    let f = std::fs::File::open(dir.join("re2-exhaustive.txt.bz2")).unwrap();
    let n = test_re2(bzip2::Reader::new(f), "re2-exhaustive.txt");
    eprintln!("{n} cases tested");
}

fn parse_fowler_result(s: &str) -> Option<(bool, bool, Vec<isize>)> {
    // (compiled, matched, positions)
    if s.is_empty() {
        return Some((true, true, vec![]));
    }
    if s == "NOMATCH" {
        return Some((true, false, vec![]));
    }
    if s.as_bytes()[0].is_ascii_uppercase() {
        return Some((false, false, vec![]));
    }
    let mut x = Vec::new();
    let mut rest = s;
    while !rest.is_empty() {
        let end = if x.len() % 2 == 0 {
            rest = rest.strip_prefix('(')?;
            ','
        } else {
            ')'
        };
        let i = rest.find(end)?;
        if i == 0 {
            return None;
        }
        x.push(if &rest[..i] == "?" {
            -1
        } else {
            rest[..i].parse().ok()?
        });
        rest = &rest[i + 1..];
    }
    (x.len() % 2 == 0).then_some((true, true, x))
}

fn test_fowler(path: &Path) -> usize {
    let text = std::fs::read_to_string(path).unwrap();
    let name = path.file_name().unwrap().to_string_lossy().into_owned();
    let (mut last, mut ran) = (String::new(), 0);
    'lines: for (n, line) in text.lines().enumerate() {
        let lineno = n + 1;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut field: Vec<String> = line
            .split('\t')
            .filter(|f| !f.is_empty())
            .map(String::from)
            .collect();
        for f in &mut field {
            if f == "NULL" {
                f.clear();
            }
            if f == "NIL" {
                continue 'lines;
            }
        }
        if field.is_empty() {
            continue;
        }
        let mut raw_text: Option<Vec<u8>> = None;
        let mut flag = field[0].clone();
        match flag.as_bytes()[0] {
            b'?' | b'&' | b'|' | b';' | b'{' | b'}' => {
                flag.remove(0);
                if flag.is_empty() {
                    continue;
                }
            }
            b':' => match flag[1..].split_once(':') {
                Some((_, f)) => flag = f.to_string(),
                None => continue,
            },
            b'C' | b'N' | b'T' | b'0'..=b'9' => continue,
            _ => {}
        }
        assert!(field.len() >= 4, "{name}:{lineno}: too few fields");
        if flag.contains('$') {
            field[1] = String::from_utf8(unquote(&format!("\"{}\"", field[1]))).unwrap();
            raw_text = Some(unquote(&format!("\"{}\"", field[2])));
        }
        if field[1] == "SAME" {
            field[1] = last.clone();
        }
        last = field[1].clone();
        let text = raw_text.unwrap_or_else(|| field[2].clone().into_bytes());
        let (compiled, matched, pos) =
            parse_fowler_result(&field[3]).unwrap_or_else(|| panic!("{name}:{lineno}: bad result"));
        for c in flag.chars() {
            let mut pattern = field[1].clone();
            match c {
                'E' => {}
                'L' => pattern = quote_meta(&pattern),
                _ => continue,
            }
            let mut syn = Flags::POSIX | Flags::CLASS_NL;
            if flag.contains('i') {
                syn |= Flags::FOLD_CASE;
            }
            let re = match compile_with(&pattern, syn, true) {
                Err(_) => {
                    assert!(!compiled, "{name}:{lineno}: {pattern:?} did not compile");
                    continue;
                }
                Ok(re) => re,
            };
            assert!(compiled, "{name}:{lineno}: {pattern:?} should not compile");
            assert_eq!(
                re.match_bytes(&text),
                matched,
                "{name}:{lineno}: {pattern:?} on {:?}",
                String::from_utf8_lossy(&text)
            );
            let mut have = re.find_submatch_index(&text).unwrap_or_default();
            assert_eq!(!have.is_empty(), matched, "{name}:{lineno}");
            have.truncate(pos.len());
            assert_eq!(
                have,
                pos,
                "{name}:{lineno}: {pattern:?} on {:?}",
                String::from_utf8_lossy(&text)
            );
            ran += 1;
        }
    }
    ran
}

#[test]
fn fowler() {
    for dir in dirs() {
        let mut total = 0;
        for f in ["basic.dat", "nullsubexpr.dat", "repetition.dat"] {
            total += test_fowler(&dir.join(f));
        }
        assert!(total > 300, "only {total} Fowler cases ran");
    }
}
