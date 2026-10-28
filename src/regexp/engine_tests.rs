//! Go's tests of the matcher internals: onepass_test.go's
//! TestCompileOnePass, all_test.go's TestOnePassCutoff and TestMinInputLen,
//! and the matcher choice of exec.go's `find`.
use super::{compile, onepass, syntax, Engine};

fn prog(expr: &str) -> syntax::Prog {
    let re = syntax::parse(expr, syntax::Flags::PERL).unwrap();
    syntax::compile(&re.simplify()).unwrap()
}

#[test]
fn compile_one_pass() {
    let long = format!("^l{}ng$", "o".repeat(2 << 8));
    let tests = [
        (r"^(?:a|(?:a*))$", false),
        (r"^(?:(a)|(?:a*))$", false),
        (r"^(?:(?:(?:.(?:$))?))$", true),
        (r"^abcd$", true),
        (r"^abcd", true),
        (r"^(?:(?:a{0,})*?)$", false),
        (r"^(?:(?:a+)*)$", true),
        (r"^(?:(?:a|(?:aa)))$", true),
        (r"^(?:[^\s\S])$", true),
        (r"^(?:(?:a{3,4}){0,})$", false),
        (r"^(?:(?:(?:a*)+))$", true),
        (r"^[a-c]+$", true),
        (r"^[a-c]*$", true),
        (r"^(?:a*)$", true),
        (r"^(?:(?:aa)|a)$", true),
        (r"^[a-c]*", false),
        (r"^...$", true),
        (r"^...", true),
        (r"^(?:a|(?:aa))$", true),
        (r"^a((b))c$", true),
        (r"^a.[l-nA-Cg-j]?e$", true),
        (r"^a((b))$", true),
        (r"^a(?:(b)|(c))c$", true),
        (r"^a(?:(b*)|(c))c$", false),
        (r"^a(?:b|c)$", true),
        (r"^a(?:b?|c)$", true),
        (r"^a(?:b?|c?)$", false),
        (r"^a(?:b?|c+)$", true),
        (r"^a(?:b+|(bc))d$", false),
        (r"^a(?:bc)+$", true),
        (r"^a(?:[bcd])+$", true),
        (r"^a((?:[bcd])+)$", true),
        (r"^a(:?b|c)*d$", true),
        (r"^.bc(d|e)*$", true),
        (r"^(?:(?:aa)|.)$", false),
        (r"^(?:(?:a{1,2}){1,2})$", false),
        (long.as_str(), true),
    ];
    for (expr, want) in tests {
        let got = onepass::compile_one_pass(&prog(expr)).is_some();
        assert_eq!(got, want, "compile_one_pass({expr:?})");
    }
}

#[test]
fn one_pass_cutoff() {
    assert!(onepass::compile_one_pass(&prog(r"^x{1,1000}y{1,1000}$")).is_none());
}

#[test]
fn min_input_len() {
    for (expr, want) in [
        ("", 0),
        ("a", 1),
        ("aa", 2),
        ("(aa)a", 3),
        ("(?:aa)a", 3),
        ("a?a", 1),
        ("(aaa)|(aa)", 2),
        ("(aa)+a", 3),
        ("(aa)*a", 1),
        ("(aa){3,5}", 6),
        ("[a-z]", 1),
        ("日", 3),
    ] {
        let re = syntax::parse(expr, syntax::Flags::PERL).unwrap();
        assert_eq!(super::min_input_len(&re), want, "{expr:?}");
    }
}

#[test]
fn engine_choice_follows_go() {
    // One-pass wins for every input, readers included.
    let re = compile(r"^abc$").unwrap();
    assert_eq!(re.engine_for(None), Engine::OnePass);
    assert_eq!(re.engine_for(Some(1 << 20)), Engine::OnePass);

    // a+b: the backtracker takes byte inputs shorter than 256K bits / insts.
    let re = compile("a+b").unwrap();
    let n = re.max_bit_state_len;
    assert_eq!(n, 256 * 1024 / re.prog.inst.len());
    assert_eq!(re.engine_for(Some(n - 1)), Engine::Backtrack);
    assert_eq!(re.engine_for(Some(n)), Engine::Pike);
    assert_eq!(re.engine_for(None), Engine::Pike);

    // Programs over 500 instructions never backtrack.
    let re = compile("[a-z]{501}").unwrap();
    assert!(re.prog.inst.len() > 500);
    assert_eq!(re.max_bit_state_len, 0);
    assert_eq!(re.engine_for(Some(1)), Engine::Pike);
}

/// A one-pass program's prefix is Go's onePassPrefix, the literal after `\A`.
/// Go never runs the other matchers on such a program, but when they are
/// forced they must not skip ahead to that literal: `^ab` cannot match at 2.
#[test]
fn forced_engines_respect_begin_text_on_one_pass_programs() {
    for (expr, text) in [
        ("^ab", "xxab"),
        (r"\Aab", "xxab"),
        ("^abc(d|e)", "zzabcd"),
        ("^a", "b\naxb"),
    ] {
        let re = compile(expr).unwrap();
        for engine in [
            Engine::Auto,
            Engine::OnePass,
            Engine::Backtrack,
            Engine::Pike,
        ] {
            let mut forced = re.clone();
            forced.force_engine(engine);
            assert_eq!(
                forced.find_index_at(text.as_bytes(), 0),
                None,
                "{expr} on {text:?} with {engine:?}"
            );
        }
    }
}
