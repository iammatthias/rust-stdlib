use rust_stdlib::path;

#[test]
fn slash_path_helpers_match_go_vectors() {
    for (input, expected) in [
        ("", "."),
        (".", "."),
        ("./", "."),
        ("a/..", "."),
        ("a//b/../c/", "a/c"),
        ("/../../a", "/a"),
        ("../../a/../b", "../../b"),
        ("///", "/"),
        ("a\\b/../c", "c"),
        ("é/../雪", "雪"),
    ] {
        assert_eq!(path::clean(input), expected, "{input:?}");
    }

    for (input, dir, file) in [
        ("", "", ""),
        ("a", "", "a"),
        ("/a/b", "/a/", "b"),
        ("é/雪", "é/", "雪"),
        ("a/", "a/", ""),
    ] {
        assert_eq!(path::split(input), (dir, file));
    }

    assert_eq!(path::join(&["", "a", "", "b/..", "c"]), "a/c");
    assert_eq!(path::join::<&str>(&[]), "");
    assert_eq!(path::join(&["", ""]), "");
    for (input, expected) in [
        ("", "."),
        ("/", "/"),
        ("////", "/"),
        ("a/b///", "b"),
        ("/é/雪", "雪"),
    ] {
        assert_eq!(path::base(input), expected, "{input:?}");
    }
    for (input, expected) in [
        ("", "."),
        ("a", "."),
        ("a/b/", "a/b"),
        ("/a", "/"),
        ("//a", "/"),
        ("é/雪", "é"),
    ] {
        assert_eq!(path::dir(input), expected, "{input:?}");
    }
    for (input, expected) in [
        ("a.txt", ".txt"),
        ("a/b.tar.gz", ".gz"),
        (".hidden", ".hidden"),
        ("a.", "."),
        ("a/", ""),
    ] {
        assert_eq!(path::ext(input), expected, "{input:?}");
    }
    assert!(path::is_abs("/a"));
    assert!(path::is_abs("//a"));
    assert!(!path::is_abs("a/b"));
    assert!(!path::is_abs("\\a"));
}

#[test]
fn glob_match_literals_classes_unicode_and_slash() {
    let cases = [
        ("*.txt", "name.txt", true),
        ("*.txt", "dir/name.txt", false),
        ("a?c", "abc", true),
        ("a?c", "a/c", false),
        ("a\\*b", "a*b", true),
        ("[a-c]at", "bat", true),
        ("[^a-c]at", "zat", true),
        ("[a-c]at", "dat", false),
        ("[/]", "/", true),
        ("?", "雪", true),
        ("??", "雪", false),
        ("[α-ω]", "β", true),
        ("[\\-]", "-", true),
        ("**/x", "a/x", true),
    ];
    for (pattern, name, expected) in cases {
        assert_eq!(
            path::matches(pattern, name),
            Ok(expected),
            "{pattern:?} vs {name:?}"
        );
    }
}

#[test]
fn malformed_globs_are_reported_even_after_nonmatching_prefix() {
    for pattern in ["\\", "[", "[]", "[^]", "[-a]", "[a-]", "a[", "x\\"] {
        assert_eq!(
            path::matches(pattern, "other"),
            Err(path::BadPattern),
            "{pattern:?}"
        );
    }
    for pattern in ["abc", "*", "[^a]", "[a-z]"] {
        assert!(path::matches(pattern, "different").is_ok(), "{pattern:?}");
    }
}

#[test]
fn malformed_rest_of_pattern_is_reported_when_the_match_fails_early() {
    // Go 1.27 path.Match checks the unmatched remainder before returning false.
    // filepath.Match does not (see tests/filepath.rs).
    assert_eq!(
        path::matches("/-ab*[^]b[", "cbb\u{96ea}]/c"),
        Err(path::BadPattern)
    );
    assert_eq!(path::matches("a*[", "b"), Err(path::BadPattern));
    assert_eq!(path::matches("a/b[", "x"), Err(path::BadPattern));
    assert_eq!(path::matches("*", "a/b"), Ok(false));
    assert_eq!(path::matches("a*b", "x"), Ok(false));
}

#[test]
fn wildcard_matching_is_stable_for_many_stars() {
    let pattern = format!("{}z", "*a".repeat(128));
    let name = format!("{}z", "a".repeat(2048));
    assert!(path::matches(&pattern, &name).unwrap());
}
