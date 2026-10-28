//! Ports of Go's unicode, unicode/utf8 and unicode/utf16 tests (the parts std lacks) (letter_test.go,
//! graphic_test.go, digit_test.go, utf8_test.go, utf16_test.go). Exhaustive
//! agreement with Go is checked by tools/unicode_check.py.
use rust_stdlib::unicode::{self as uni, rune};

fn c(ch: char) -> i32 {
    ch as i32
}

#[test]
fn constants_and_version() {
    assert_eq!(uni::VERSION, "17.0.0");
    assert_eq!(uni::MAX_RUNE, 0x10FFFF);
    assert_eq!(uni::UPPER_LOWER, 0x110000);
    assert_eq!(uni::MAX_CASE, 3);
    assert_eq!(rune::UTF_MAX, 4);
}

#[test]
fn ascii_and_latin1_classes() {
    for r in 0..=0xFF {
        let ch = char::from_u32(r as u32).unwrap();
        assert_eq!(uni::is_letter(r), uni::is(uni::L, r), "{r:#x}");
        assert_eq!(uni::is_upper(r), uni::is(uni::LU, r), "{r:#x}");
        assert_eq!(
            char::from_u32(r as u32).is_some_and(char::is_whitespace),
            ch.is_ascii_whitespace() || r == 0x0B || r == 0x85 || r == 0xA0
        );
        assert_eq!(ch.is_control(), r < 0x20 || (0x7F..0xA0).contains(&r));
    }
    // Go's Latin-1 graphic/print difference: NBSP is graphic but not printable.
    assert!(uni::is_graphic(0xA0) && !uni::is_print(0xA0));
    assert!(uni::is_print(c(' ')) && uni::is_graphic(c(' ')));
    assert!(!uni::is_digit(0xB2) && uni::is_number(0xB2));
}

#[test]
fn out_of_range_runes() {
    for r in [-1, i32::MIN, 0x110000, i32::MAX] {
        assert!(
            !uni::is_letter(r)
                && !char::from_u32(r as u32).is_some_and(char::is_whitespace)
                && !uni::is_print(r)
        );
        assert_eq!(uni::to_upper(r), r);
        assert_eq!(uni::simple_fold(r), r);
    }
    assert_eq!(uni::to(3, c('a')), uni::REPLACEMENT_CHAR);
    assert_eq!(uni::to(-1, c('a')), uni::REPLACEMENT_CHAR);
}

#[test]
fn case_mapping() {
    // From Go's caseTest: (rune, upper, lower, title).
    let cases: &[(i32, i32, i32, i32)] = &[
        (c('A'), c('A'), c('a'), c('A')),
        (c('a'), c('A'), c('a'), c('A')),
        (0x00C0, 0x00C0, 0x00E0, 0x00C0),
        (0x0100, 0x0100, 0x0101, 0x0100),
        (0x01C4, 0x01C4, 0x01C6, 0x01C5),
        (0x01C5, 0x01C4, 0x01C6, 0x01C5),
        (0x01C6, 0x01C4, 0x01C6, 0x01C5),
        (0x0131, c('I'), 0x0131, c('I')),
        (0x0130, 0x0130, c('i'), 0x0130),
        (0x1E9E, 0x1E9E, 0x00DF, 0x1E9E),
        (0x10400, 0x10400, 0x10428, 0x10400),
        (0x10428, 0x10400, 0x10428, 0x10400),
        (0xDF, 0xDF, 0xDF, 0xDF),
        (0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD),
    ];
    for &(r, up, lo, ti) in cases {
        assert_eq!(uni::to_upper(r), up, "upper {r:#x}");
        assert_eq!(uni::to_lower(r), lo, "lower {r:#x}");
        assert_eq!(uni::to_title(r), ti, "title {r:#x}");
    }
}

#[test]
fn special_case() {
    let tr = &uni::TURKISH_CASE;
    assert_eq!(tr.to_upper(c('i')), 0x130);
    assert_eq!(tr.to_lower(c('I')), 0x131);
    assert_eq!(tr.to_lower(0x130), c('i'));
    assert_eq!(tr.to_title(c('i')), 0x130);
    assert_eq!(tr.to_upper(c('x')), c('X'));
    assert_eq!(uni::AZERI_CASE, uni::TURKISH_CASE);
    let custom = uni::SpecialCase(&[uni::CaseRange {
        lo: 0x61,
        hi: 0x61,
        delta: [5, 0, 5],
    }]);
    assert_eq!(custom.to_upper(c('a')), c('a') + 5);
    assert_eq!(custom.to_lower(c('A')), c('a'));
}

#[test]
fn simple_fold_orbits() {
    // Go's simpleFoldTests: each string is one orbit, listed from the smallest.
    let orbits: &[&[i32]] = &[
        &[c('K'), c('k'), 0x212A],
        &[c('S'), c('s'), 0x17F],
        &[0xDF, 0x1E9E],
        &[0x3A3, 0x3C2, 0x3C3],
        &[0x1C4, 0x1C5, 0x1C6],
        &[0x10400, 0x10428],
        &[c('1')],
        &[c('\n')],
    ];
    for orbit in orbits {
        let mut sorted = orbit.to_vec();
        sorted.sort();
        for (i, &r) in sorted.iter().enumerate() {
            let want = sorted.get(i + 1).copied().unwrap_or(sorted[0]);
            assert_eq!(uni::simple_fold(r), want, "fold {r:#x}");
        }
    }
    assert_eq!(uni::simple_fold(-1), -1);
    assert_eq!(uni::simple_fold(0x110000), 0x110000);
}

#[test]
fn tables_and_maps() {
    assert!(uni::is(uni::HAN, c('世')));
    assert!(uni::is(uni::LATIN, c('a')) && !uni::is(uni::LATIN, c('α')));
    assert!(uni::is_one_of(&[uni::GREEK, uni::CYRILLIC], c('я')));
    assert!(uni::in_(c('٣'), &[uni::ND]) && uni::is_digit(c('٣')));
    assert!(std::ptr::eq(uni::UPPER, uni::LU));
    assert!(std::ptr::eq(uni::LETTER, uni::L));
    let look =
        |m: &[(&str, &uni::RangeTable)], k: &str| m.binary_search_by_key(&k, |e| e.0).is_ok();
    assert!(
        look(uni::CATEGORIES, "Lu") && look(uni::SCRIPTS, "Greek") && look(uni::PROPERTIES, "Dash")
    );
    assert!(look(uni::FOLD_CATEGORY, "L") && look(uni::FOLD_SCRIPT, "Common"));
    assert!(uni::CATEGORY_ALIASES
        .iter()
        .any(|&(a, b)| a == "Letter" && b == "L"));
    assert_eq!(uni::GRAPHIC_RANGES.len(), 6);
    assert_eq!(uni::PRINT_RANGES.len(), 5);
    // Latin-1 offset invariant from Go's TestLatinOffset.
    for &(_, t) in uni::CATEGORIES
        .iter()
        .chain(uni::SCRIPTS)
        .chain(uni::PROPERTIES)
    {
        let n = t.r16.iter().take_while(|r| r.hi <= 0xFF).count();
        assert_eq!(n, t.latin_offset);
    }
}

#[test]
fn utf8_decode_and_encode() {
    // Go's utf8 test strings: (bytes, rune, size).
    let cases: &[(&[u8], i32, usize)] = &[
        (b"", 0xFFFD, 0),
        (b"a", 0x61, 1),
        (b"\xc3\xa9", 0xE9, 2),
        (b"\xe4\xb8\x96", 0x4E16, 3),
        (b"\xf0\x9f\x98\x80", 0x1F600, 4),
        (b"\xff", 0xFFFD, 1),
        (b"\x80", 0xFFFD, 1),
        (b"\xc0\x80", 0xFFFD, 1),
        (b"\xed\xa0\x80", 0xFFFD, 1),
        (b"\xf4\x90\x80\x80", 0xFFFD, 1),
        (b"\xe4\xb8", 0xFFFD, 1),
        (b"\xf4\x8f\xbf\xbf", 0x10FFFF, 4),
    ];
    for &(b, r, n) in cases {
        assert_eq!(rune::decode_rune(b), (r, n), "{b:x?}");
        assert_eq!(
            std::str::from_utf8(b).is_ok(),
            n == b.len() && (r != 0xFFFD || n == 0)
        );
    }
    assert_eq!(rune::decode_last_rune("a世".as_bytes()), (0x4E16, 3));
    assert_eq!(rune::decode_last_rune(b"a\xe4\xb8"), (0xFFFD, 1));
    assert_eq!(rune::decode_last_rune(b""), (0xFFFD, 0));
    for r in [
        0, 0x7F, 0x80, 0x7FF, 0x800, 0xD7FF, 0xE000, 0xFFFF, 0x10000, 0x10FFFF,
    ] {
        let mut buf = [0u8; 4];
        let n = rune::encode_rune(&mut buf, r);
        assert_eq!(n as isize, rune::rune_len(r));
        assert_eq!(rune::decode_rune(&buf[..n]), (r, n));
        let mut v = b"x".to_vec();
        rune::append_rune(&mut v, r);
        assert_eq!(&v[1..], &buf[..n]);
    }
    for r in [-1, 0xD800, 0xDFFF, 0x110000, i32::MIN] {
        let mut buf = [0u8; 4];
        assert_eq!(rune::rune_len(r), -1);
        assert!(!rune::valid_rune(r));
        assert_eq!(rune::encode_rune(&mut buf, r), 3);
        assert_eq!(&buf[..3], b"\xef\xbf\xbd");
    }
}

#[test]
#[should_panic]
fn utf8_encode_rune_short_buffer_panics() {
    rune::encode_rune(&mut [0u8; 2], 0x4E16);
}

#[test]
fn utf8_counts_and_full_rune() {
    assert_eq!(rune::rune_count("héllo, 世界".as_bytes()), 9);
    assert_eq!(rune::rune_count(b"\xe4\xb8"), 2);
    assert_eq!(rune::rune_count(b"a\xffb"), 3);
    assert!(
        !rune::full_rune(b"") && !rune::full_rune(b"\xe4\xb8") && rune::full_rune(b"\xe4\xb8\x96")
    );
    assert!(rune::full_rune(b"\xff") && rune::full_rune(b"\xe0\x80") && rune::full_rune(b"a"));
    assert!(rune::rune_start(b'a') && !rune::rune_start(0x80));
}

#[test]
fn utf16_round_trips() {
    // Go's Encode/Decode/AppendRune/RuneLen are std's char::encode_utf16,
    // char::decode_utf16 and char::len_utf16 with U+FFFD for invalid input.
    let enc = |rs: &[i32]| -> Vec<u16> {
        rs.iter()
            .flat_map(|&r| {
                let ch = u32::try_from(r)
                    .ok()
                    .and_then(char::from_u32)
                    .unwrap_or(char::REPLACEMENT_CHARACTER);
                let mut buf = [0u16; 2];
                ch.encode_utf16(&mut buf).to_vec()
            })
            .collect()
    };
    let dec = |us: &[u16]| -> Vec<i32> {
        char::decode_utf16(us.iter().copied())
            .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER) as i32)
            .collect()
    };
    assert_eq!(
        enc(&[0x61, 0x1F600, 0xD800, -1, 0x110000]),
        vec![0x61, 0xD83D, 0xDE00, 0xFFFD, 0xFFFD, 0xFFFD]
    );
    assert_eq!(
        dec(&[0x61, 0xD83D, 0xDE00, 0xD800, 0xDC00, 0xDC00, 0xD800]),
        vec![0x61, 0x1F600, 0x10000, 0xFFFD, 0xFFFD]
    );
    assert_eq!(dec(&[0xD83D, 0x61]), vec![0xFFFD, 0x61]);
    assert_eq!(rune::encode_surrogate_pair(0x1F600), (0xD83D, 0xDE00));
    assert_eq!(rune::encode_surrogate_pair(0x41), (0xFFFD, 0xFFFD));
    assert_eq!(rune::decode_surrogate_pair(0xD83D, 0xDE00), 0x1F600);
    assert_eq!(rune::decode_surrogate_pair(0xD83D, 0x41), 0xFFFD);
    assert!(
        rune::is_surrogate(0xD800) && rune::is_surrogate(0xDFFF) && !rune::is_surrogate(0xE000)
    );
    assert_eq!('A'.len_utf16(), 1);
    assert_eq!('\u{10000}'.len_utf16(), 2);
}

#[test]
fn zero_stride_range_panics_like_go() {
    use rust_stdlib::unicode::{is, Range16, Range32, RangeTable};
    static R16: [Range16; 1] = [Range16 {
        lo: 0x100,
        hi: 0x110,
        stride: 0,
    }];
    static R32: [Range32; 1] = [Range32 {
        lo: 0x10000,
        hi: 0x10010,
        stride: 0,
    }];
    let t16 = RangeTable {
        r16: &R16,
        r32: &[],
        latin_offset: 0,
    };
    let t32 = RangeTable {
        r16: &[],
        r32: &R32,
        latin_offset: 0,
    };
    // Go's is16/is32 divide by the stride, so a zero stride panics with
    // "integer divide by zero" rather than answering.
    assert!(std::panic::catch_unwind(|| is(&t16, 0x104)).is_err());
    assert!(std::panic::catch_unwind(|| is(&t32, 0x10004)).is_err());
}
