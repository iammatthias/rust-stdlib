//! Ports of Go's `index/suffixarray` tests (`suffixarray_test.go`).
//!
//! Go's `text_32`/`text_64` construction functions and the forced 32/64-bit
//! `maxData32` switch are internal, so construction is checked through the
//! serialized suffix array (see `serialized_suffix_array`).
use rust_stdlib::index::suffixarray::Index;
use rust_stdlib::io::Error as IoError;
use rust_stdlib::regexp;

struct TestCase {
    name: &'static str,
    source: &'static str,
    patterns: &'static [&'static str],
}

const TEST_CASES: &[TestCase] = &[
    TestCase {
        name: "empty string",
        source: "",
        patterns: &["", "foo", "(foo)", ".*", "a*"],
    },
    TestCase {
        name: "all a's",
        source: "aaaaaaaaaa", // 10 a's
        patterns: &[
            "",
            "a",
            "aa",
            "aaa",
            "aaaa",
            "aaaaa",
            "aaaaaa",
            "aaaaaaa",
            "aaaaaaaa",
            "aaaaaaaaa",
            "aaaaaaaaaa",
            "aaaaaaaaaaa", // 11 a's
            ".",
            ".*",
            "a+",
            "aa+",
            "aaaa[b]?",
            "aaa*",
        ],
    },
    TestCase {
        name: "abc",
        source: "abc",
        patterns: &["a", "b", "c", "ab", "bc", "abc", "a.c", "a(b|c)", "abc?"],
    },
    TestCase {
        name: "barbara*3",
        source: "barbarabarbarabarbara",
        patterns: &["a", "bar", "rab", "arab", "barbar", "bara?bar"],
    },
    TestCase {
        name: "typing drill",
        source: "Now is the time for all good men to come to the aid of their country.",
        patterns: &[
            "Now",
            "the time",
            "to come the aid",
            "is the time for all good men to come to the aid of their",
            "to (come|the)?",
        ],
    },
    TestCase {
        name: "godoc simulation",
        source: "package main\n\nimport(\n    \"rand\"\n    ",
        patterns: &[],
    },
];

/// Finds all occurrences of `s` in `src`, overlapping ones included; reports
/// at most `n` occurrences if `n >= 0` (Go's `find`).
fn find(src: &[u8], s: &[u8], n: isize) -> Vec<usize> {
    let mut res = Vec::new();
    if !s.is_empty() && n != 0 {
        let mut i: isize = -1;
        while n < 0 || (res.len() as isize) < n {
            let from = (i + 1) as usize;
            match src[from..].windows(s.len()).position(|w| w == s) {
                None => break,
                Some(j) => {
                    i += j as isize + 1;
                    res.push(i as usize);
                }
            }
        }
    }
    res
}

fn test_lookup(tc: &TestCase, x: &Index, s: &str, n: isize) {
    let mut res = x.lookup(s.as_bytes(), n);
    let exp = find(tc.source.as_bytes(), s.as_bytes(), n);

    // check that the lengths match
    assert_eq!(
        res.len(),
        exp.len(),
        "test {:?}, lookup {s:?} (n = {n}): result count",
        tc.name
    );

    // check that each result is a correct match, with no duplicates
    res.sort_unstable();
    for (i, &r) in res.iter().enumerate() {
        assert!(
            r < tc.source.len(),
            "test {:?}, lookup {s:?}, result {i}: index {r} out of range",
            tc.name
        );
        assert!(
            tc.source.as_bytes()[r..].starts_with(s.as_bytes()),
            "test {:?}, lookup {s:?}, result {i} (n = {n}): index {r} not a match",
            tc.name
        );
        if i > 0 {
            assert_ne!(
                res[i - 1],
                r,
                "test {:?}, lookup {s:?}: duplicate index {r}",
                tc.name
            );
        }
    }

    if n < 0 {
        // all results computed - sorted res and exp must be equal
        assert_eq!(res, exp, "test {:?}, lookup {s:?}", tc.name);
    }
}

fn test_find_all_index(tc: &TestCase, x: &Index, rx: &regexp::Regexp, n: isize) {
    let res = x.find_all_index(rx, n);
    let exp = rx.find_all_index(tc.source.as_bytes(), n);

    // check that the lengths match
    assert_eq!(
        res.len(),
        exp.len(),
        "test {:?}, FindAllIndex {:?} (n = {n}): result count",
        tc.name,
        rx.as_str()
    );

    // check that each result is in fact a match
    for (i, &(start, end)) in res.iter().enumerate() {
        assert!(
            start <= end && end <= tc.source.len(),
            "test {:?}, FindAllIndex {:?}, result {i} (n == {n}): illegal match [{start}, {end}]",
            tc.name,
            rx.as_str()
        );
        assert!(
            rx.match_bytes(&tc.source.as_bytes()[start..end]),
            "test {:?}, FindAllIndex {:?}, result {i}: [{start}, {end}] not a match",
            tc.name,
            rx.as_str()
        );
    }

    if n < 0 {
        // all results computed - the matches must be the same, in order
        assert_eq!(
            res,
            exp,
            "test {:?}, FindAllIndex {:?}",
            tc.name,
            rx.as_str()
        );
    }
}

fn test_lookups(tc: &TestCase, x: &Index, n: isize) {
    for pat in tc.patterns {
        test_lookup(tc, x, pat, n);
        if let Ok(rx) = regexp::compile(pat) {
            test_find_all_index(tc, x, &rx, n);
        }
    }
}

fn uvarint(bytes: &[u8], at: &mut usize) -> u64 {
    let (mut x, mut shift) = (0u64, 0);
    loop {
        let b = bytes[*at];
        *at += 1;
        x |= u64::from(b & 0x7f) << shift;
        shift += 7;
        if b < 0x80 {
            return x;
        }
    }
}

/// Decodes the suffix array from the serialized form, following Go's layout:
/// a 10-byte varint length, the data, then 10-byte size slots each followed by
/// uvarint indices (see TestIssue53352 in Go's tests).
fn serialized_suffix_array(x: &Index) -> Vec<usize> {
    let mut serialized = Vec::new();
    x.write(&mut serialized)
        .expect("writing to a Vec does not fail");
    let n = {
        let mut at = 0;
        let ux = uvarint(&serialized[..10], &mut at);
        ((ux >> 1) as i64 ^ -((ux & 1) as i64)) as usize
    };
    let mut at = 10 + n;
    let mut sa = Vec::new();
    while sa.len() < n {
        let size = {
            let mut slot = 0;
            let ux = uvarint(&serialized[at..at + 10], &mut slot);
            ((ux >> 1) as i64 ^ -((ux & 1) as i64)) as usize
        };
        let end = at + size;
        let mut p = at + 10;
        while p < end {
            sa.push(uvarint(&serialized[..end], &mut p) as usize);
        }
        at = end;
    }
    sa
}

/// Checks that the suffix array of `data` is sorted (Go's `testSA`).
fn test_sa(data: &[u8]) {
    let x = Index::new(data);
    let sa = serialized_suffix_array(&x);
    assert_eq!(
        sa.len(),
        data.len(),
        "len(sa) for input of {} bytes",
        data.len()
    );
    for w in sa.windows(2) {
        assert!(
            w[0] < data.len() && w[1] < data.len(),
            "sa out of range: {sa:?}"
        );
        assert!(
            data[w[0]..] < data[w[1]..],
            "suffixes out of order for input {data:?}"
        );
    }
}

fn save_restore(tc: &TestCase, x: &Index) -> usize {
    let mut buf = Vec::new();
    x.write(&mut buf)
        .unwrap_or_else(|e| panic!("failed writing index {} ({e})", tc.name));
    let size = buf.len();
    let mut y = Index::default();
    y.read(&mut buf.as_slice())
        .unwrap_or_else(|e| panic!("failed reading index {} ({e})", tc.name));
    assert!(
        *x == y,
        "restored index doesn't match saved index {}",
        tc.name
    );
    size
}

fn test_index(tc: &TestCase) {
    let x = Index::new(tc.source.as_bytes());
    assert_eq!(serialized_suffix_array(&x).len(), tc.source.len());
    save_restore(tc, &x);
    test_lookups(tc, &x, 0);
    test_lookups(tc, &x, 1);
    test_lookups(tc, &x, 10);
    test_lookups(tc, &x, 2_000_000_000);
    test_lookups(tc, &x, -1);
}

#[test]
fn index() {
    for tc in TEST_CASES {
        test_index(tc);
    }
}

#[test]
fn construction_is_sorted() {
    // Go's test(t, build): repetitive input, a pathological input with many
    // distinct LMS substrings, and exhaustive short inputs. The exhaustive
    // ranges are shorter than Go's (length 21 over two letters, 14 over
    // three) so the debug test run stays quick.
    let size = 100_000;
    let ababab: Vec<u8> = (0..size).map(|i| b"ab"[i % 2]).collect();
    test_sa(&ababab);

    let mut forcealloc = vec![0u8; 100_000];
    let (mut lo, mut hi) = (1u8, 255u8);
    for (i, b) in forcealloc.iter_mut().enumerate() {
        if i % 2 == 0 {
            *b = lo;
        } else {
            *b = hi;
            hi -= 1;
            if hi <= lo {
                lo = lo.wrapping_add(1);
                if lo == 0 {
                    lo = 1;
                }
                hi = 255;
            }
        }
    }
    test_sa(&forcealloc);

    for n in 0..=14 {
        for bits in 0..(1u32 << n) {
            let x: Vec<u8> = (0..n).map(|i| 1 + ((bits >> i) & 1) as u8).collect();
            test_sa(&x);
        }
    }
    for n in 0..=9 {
        let total = 3usize.pow(n as u32);
        for code in 0..total {
            let mut c = code;
            let x: Vec<u8> = (0..n)
                .map(|_| {
                    let digit = (c % 3) as u8 + 1;
                    c /= 3;
                    digit
                })
                .collect();
            test_sa(&x);
        }
    }
}

#[test]
fn issue_53352_extra_index_is_corrupt() {
    let data = b"x";
    let index = Index::new(data);
    let mut buf = Vec::new();
    index.write(&mut buf).unwrap();

    // buffer encoding is as follows:
    //
    // [ data length n | data bytes | index slice buffer size |  indices  ] ... (next slice, if any)
    // \__ 10 bytes __/\_ n bytes _/\_______ 10 bytes _______/\_ varuints /
    //
    // n and s are encoded as varints using 10 bytes always so they can be patched.
    // For small values x >= 0 the varint encoded value is 2*x.
    let n = data.len();
    let mut encoding = buf.clone();
    assert_eq!(usize::from(encoding[0]), 2 * n, "n");

    // The index slice buffer holds one index (0 for "x") plus its own 10-byte size.
    let s = 10 + 1;
    assert_eq!(usize::from(encoding[10 + n]), 2 * s, "s");

    // Reading back the encoding works without errors.
    let mut y = Index::default();
    y.read(&mut encoding.as_slice()).unwrap();
    assert_eq!(y.bytes(), data);

    // Adding an extra index corrupts the encoding (more indices than data bytes to be indexed).
    let s = s + 1;
    encoding.push(0);
    encoding[10 + n] = (2 * s) as u8;
    let err = Index::default().read(&mut encoding.as_slice()).unwrap_err();
    assert_eq!(err.to_string(), "suffixarray: data corrupted");
}

#[test]
fn corrupted_index_is_rejected() {
    let data = b"x";
    let index = Index::new(data);
    let mut buf = Vec::new();
    index.write(&mut buf).unwrap();

    // The encoded indices must be 0 <= i < len(data) because they index into the
    // data. Corrupt the last one and check that reading reports it.
    let last = buf.len() - 1;
    buf[last] = data.len() as u8;
    let err = Index::default().read(&mut buf.as_slice()).unwrap_err();
    assert_eq!(err.to_string(), "suffixarray: data corrupted");
}

#[test]
fn truncated_streams_report_eof_like_go() {
    let index = Index::new(b"banana");
    let mut buf = Vec::new();
    index.write(&mut buf).unwrap();

    // No bytes at all is io.EOF.
    let err = Index::default().read(&mut [].as_slice()).unwrap_err();
    assert!(IoError::Eof.is(&err), "empty input: {err}");

    // A stream that ends inside the length slot is io.ErrUnexpectedEOF.
    let err = Index::default()
        .read(&mut buf[..5].to_vec().as_slice())
        .unwrap_err();
    assert_eq!(err.to_string(), "unexpected EOF");
    assert!(!IoError::Eof.is(&err));
}

#[test]
fn read_leaves_index_unchanged_on_error() {
    let mut index = Index::new(b"abc");
    let before = index.clone();
    let mut bad = Vec::new();
    Index::new(b"xyz").write(&mut bad).unwrap();
    bad.truncate(bad.len() - 1);
    assert!(index.read(&mut bad.as_slice()).is_err());
    assert!(index == before);
}

#[test]
fn bytes_and_lookup_on_default_index() {
    let index = Index::default();
    assert!(index.bytes().is_empty());
    assert!(index.lookup(b"a", -1).is_empty());
    assert!(index.lookup(b"", -1).is_empty());
    assert!(Index::new(b"aaa").lookup(b"a", 0).is_empty());
}
