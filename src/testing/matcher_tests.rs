//! Ports of the tables of Go's `testing/match_test.go`.

use super::*;

fn res(s: &[&str]) -> Filter {
    Filter::Simple(s.iter().map(|s| s.to_string()).collect())
}

#[test]
fn is_space_agrees_with_unicode() {
    let mut bad = 0;
    for r in 0..=0x10ffffu32 {
        let Some(c) = char::from_u32(r) else { continue };
        // Go's unicode.IsSpace.
        let want = matches!(r, 0x09..=0x0d | 0x20 | 0x85 | 0xa0 | 0x1680 | 0x2000..=0x200a
            | 0x2028 | 0x2029 | 0x202f | 0x205f | 0x3000);
        if is_space(c) != want {
            bad += 1;
        }
    }
    assert_eq!(bad, 0);
}

#[test]
fn split_regexp_cases() {
    let alt = |m: Vec<Filter>| Filter::Alternation(m);
    let cases: Vec<(&str, Filter)> = vec![
        ("", res(&[""])),
        ("/", res(&["", ""])),
        ("//", res(&["", "", ""])),
        ("A", res(&["A"])),
        ("A/B", res(&["A", "B"])),
        ("A/B/", res(&["A", "B", ""])),
        ("/A/B/", res(&["", "A", "B", ""])),
        ("[A]/(B)", res(&["[A]", "(B)"])),
        ("[/]/[/]", res(&["[/]", "[/]"])),
        ("[/]/[:/]", res(&["[/]", "[:/]"])),
        ("/]", res(&["", "]"])),
        ("]/", res(&["]", ""])),
        ("]/[/]", res(&["]", "[/]"])),
        ("([)/][(])", res(&["([)/][(])"])),
        ("[(]/[)]", res(&["[(]", "[)]"])),
        ("A/B|C/D", alt(vec![res(&["A", "B"]), res(&["C", "D"])])),
        (")/", res(&[")/"])),
        (")/(/)", res(&[")/(", ")"])),
        ("a[/)b", res(&["a[/)b"])),
        ("(/]", res(&["(/]"])),
        ("(/", res(&["(/"])),
        ("[/]/[/", res(&["[/]", "[/"])),
        (r"\p{/}", res(&[r"\p{", "}"])),
        (r"\p/", res(&[r"\p", ""])),
        ("[[:/:]]", res(&["[[:/:]]"])),
    ];
    let m = regexp_match();
    for (pat, want) in cases {
        let mut got = split_regexp(pat);
        assert_eq!(
            format!("{got:?}"),
            format!("{want:?}"),
            "splitRegexp({pat:?})"
        );
        if crate::regexp::compile(pat).is_err() {
            assert!(
                got.verify("", &m).is_err(),
                "{pat}: expected error in any of the parts"
            );
        }
    }
}

#[test]
fn matcher_cases() {
    // pattern, skip, parent, sub, ok, partial
    let cases: &[(&str, &str, &str, &str, bool, bool)] = &[
        ("", "", "", "TestFoo", true, false),
        ("TestFoo", "", "", "TestFoo", true, false),
        ("TestFoo/", "", "", "TestFoo", true, true),
        ("TestFoo/bar/baz", "", "", "TestFoo", true, true),
        ("TestFoo", "", "", "TestBar", false, false),
        ("TestFoo/", "", "", "TestBar", false, false),
        ("TestFoo/bar/baz", "", "", "TestBar/bar/baz", false, false),
        ("", "TestBar", "", "TestFoo", true, false),
        ("", "TestBar", "", "TestBar", false, false),
        ("", "TestFoo/skipped", "", "TestFoo", true, false),
        ("TestFoo", "TestFoo/skipped", "", "TestFoo", true, false),
        ("TestFoo/", "TestFoo/skipped", "", "TestFoo", true, true),
        (
            "TestFoo/bar/baz",
            "TestFoo/skipped",
            "",
            "TestFoo",
            true,
            true,
        ),
        ("TestFoo", "TestFoo/skipped", "", "TestBar", false, false),
        ("TestFoo/", "TestFoo/skipped", "", "TestBar", false, false),
        (
            "TestFoo/bar/baz",
            "TestFoo/skipped",
            "",
            "TestBar/bar/baz",
            false,
            false,
        ),
        ("", "", "TestFoo", "x", true, false),
        ("TestFoo", "", "TestFoo", "x", true, false),
        ("TestFoo/", "", "TestFoo", "x", true, false),
        ("TestFoo/bar/baz", "", "TestFoo", "bar", true, true),
        ("", "TestFoo/skipped", "TestFoo", "x", true, false),
        ("TestFoo", "TestFoo/skipped", "TestFoo", "x", true, false),
        (
            "TestFoo",
            "TestFoo/skipped",
            "TestFoo",
            "skipped",
            false,
            false,
        ),
        ("TestFoo/", "TestFoo/skipped", "TestFoo", "x", true, false),
        (
            "TestFoo/bar/baz",
            "TestFoo/skipped",
            "TestFoo",
            "bar",
            true,
            true,
        ),
        ("TestFoo/bar/baz", "", "TestFoo", "bar/baz", true, false),
        (
            "TestFoo/bar/baz",
            "TestFoo/bar/baz",
            "TestFoo",
            "bar/baz",
            false,
            false,
        ),
        (
            "TestFoo/bar/baz",
            "TestFoo/bar/baz/skip",
            "TestFoo",
            "bar/baz",
            true,
            false,
        ),
        ("TestFoo/bar/baz", "", "TestFoo/bar", "baz", true, false),
        ("TestFoo/bar/baz", "", "TestFoo", "x", false, false),
        ("TestFoo", "", "TestBar", "x", false, false),
        ("TestFoo/", "", "TestBar", "x", false, false),
        ("TestFoo/bar/baz", "", "TestBar", "x/bar/baz", false, false),
        ("A/B|C/D", "", "TestA", "B", true, false),
        ("A/B|C/D", "", "TestC", "D", true, false),
        ("A/B|C/D", "", "TestA", "C", false, false),
        ("", "", "TestFoo", "x", true, false),
        ("/", "", "TestFoo", "x", true, false),
        ("./", "", "TestFoo", "x", true, false),
        ("./.", "", "TestFoo", "x", true, false),
        ("/bar/baz", "", "TestFoo", "bar", true, true),
        ("/bar/baz", "", "TestFoo", "bar/baz", true, false),
        ("//baz", "", "TestFoo", "bar/baz", true, false),
        ("//", "", "TestFoo", "bar/baz", true, false),
        ("/bar/baz", "", "TestFoo/bar", "baz", true, false),
        ("//foo", "", "TestFoo", "bar/baz", false, false),
        ("/bar/baz", "", "TestFoo", "x", false, false),
        ("/bar/baz", "", "TestBar", "x/bar/baz", false, false),
    ];
    for &(pattern, skip, parent, sub, ok, partial) in cases {
        let m = Matcher::new(regexp_match(), pattern, "-test.run", skip).unwrap();
        let level = usize::from(!parent.is_empty());
        let (n, got_ok, got_partial) = m.full_name(Some((parent, level)), sub);
        assert!(
            got_ok == ok && got_partial == partial,
            "pattern {pattern:?}, skip {skip:?}: fullName(parent={parent:?}, sub={sub:?}) = {n:?}, ok {got_ok} partial {got_partial}; want ok {ok} partial {partial}"
        );
    }
}

#[test]
fn naming() {
    let cases: &[(&str, &str)] = &[
        ("", "x/#00"),
        ("", "x/#01"),
        ("#0", "x/#0"),
        ("#00", "x/#00#01"),
        ("#", "x/#"),
        ("#", "x/##01"),
        ("t", "x/t"),
        ("t", "x/t#01"),
        ("t", "x/t#02"),
        ("t#00", "x/t#00"),
        ("a#01", "x/a#01"),
        ("a", "x/a"),
        ("a", "x/a#02"),
        ("a", "x/a#03"),
        ("a#02", "x/a#02#01"),
        ("b#00", "x/b#00"),
        ("b", "x/b"),
        ("b", "x/b#01"),
        ("b#9223372036854775807", "x/b#9223372036854775807"),
        ("b", "x/b#02"),
        ("b", "x/b#03"),
        ("A:1 B:2", "x/A:1_B:2"),
        ("s\t\r\u{a0}", "x/s___"),
        ("\u{1}", r"x/\x01"),
        ("\u{10ffff}", r"x/\U0010ffff"),
    ];
    let m = Matcher::new(regexp_match(), "", "", "").unwrap();
    for (i, (name, want)) in cases.iter().enumerate() {
        let (got, _, _) = m.full_name(Some(("x", 1)), name);
        assert_eq!(&got, want, "{i}:{name}");
    }
}
