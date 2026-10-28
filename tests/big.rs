//! math/big against the table-driven vectors of Go's own math/big tests.
//!
//! The tables are extracted from $GOROOT/src/math/big/*_test.go by
//! tools/big_vectors.go into tests/fixtures/big_golden.rs; each test below
//! reproduces the checks of the Go test that owns the table. Tokens starting
//! with "?" are Go expressions the generator could not evaluate; rows using
//! them are skipped (and counted, so a regenerated fixture cannot silently
//! empty a test).
use rust_stdlib::math::big::{
    jacobi, Accuracy, Float, FormatSpec, Int, Rat, RoundingMode, MAX_BASE, MAX_PREC,
};
use std::cmp::Ordering;
use std::panic::{self, AssertUnwindSafe};

#[allow(dead_code)]
#[path = "fixtures/big_golden.rs"]
mod golden;
use golden::*;

fn int(s: &str) -> Int {
    Int::from_str_radix(s, 0).unwrap_or_else(|| panic!("bad int {s:?}"))
}

fn int10(s: &str) -> Int {
    Int::from_str_radix(s, 10).unwrap_or_else(|| panic!("bad int {s:?}"))
}

fn rat(s: &str) -> Rat {
    Rat::from_string(s).unwrap_or_else(|| panic!("bad rat {s:?}"))
}

/// Go's makeFloat: ParseFloat(s, 0, 1000, ToNearestEven).
fn float(s: &str) -> Float {
    Float::parse_float(s, 0, 1000, RoundingMode::ToNearestEven)
        .unwrap_or_else(|e| panic!("bad float {s:?}: {e}"))
        .0
}

fn acc(s: &str) -> Accuracy {
    match s {
        "Below" => Accuracy::Below,
        "Exact" => Accuracy::Exact,
        "Above" => Accuracy::Above,
        _ => panic!("bad accuracy {s}"),
    }
}

fn neg_acc(a: Accuracy) -> Accuracy {
    match a {
        Accuracy::Below => Accuracy::Above,
        Accuracy::Above => Accuracy::Below,
        _ => a,
    }
}

fn mode(s: &str) -> RoundingMode {
    *RoundingMode::ALL
        .iter()
        .find(|m| m.to_string() == s)
        .unwrap_or_else(|| panic!("bad mode {s}"))
}

fn num<T: std::str::FromStr>(s: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    if s.is_empty() {
        return "0".parse().unwrap();
    }
    s.parse()
        .unwrap_or_else(|e| panic!("bad number {s:?}: {e:?}"))
}

fn flag(s: &str) -> bool {
    s == "true"
}

fn usable(row: &[&str]) -> bool {
    !row.iter().any(|t| t.starts_with('?'))
}

fn panics<F: FnOnce() -> R, R>(f: F) -> bool {
    let hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let result = panic::catch_unwind(AssertUnwindSafe(f)).is_err();
    panic::set_hook(hook);
    result
}

/// Run check over the usable rows of table and require at least min of them.
fn each(table: &[&[&str]], min: usize, mut check: impl FnMut(&[&str])) {
    let mut n = 0;
    for row in table.iter().filter(|r| usable(r)) {
        check(row);
        n += 1;
    }
    assert!(n >= min, "only {n} usable rows (expected at least {min})");
}

// ---------------------------------------------------------------- Int

#[test]
fn int_sum_and_product() {
    each(SUM_ZZ, 6, |r| {
        let (z, x, y) = (int(r[0]), int(r[1]), int(r[2]));
        assert_eq!((&x + &y), z);
        assert_eq!(&y + &x, z);
        assert_eq!((&z - &x), y);
        assert_eq!((&z - &y), x);
        assert_eq!(z.sign(), z.cmp(&Int::zero()) as i32);
    });
    each(PROD_ZZ, 4, |r| {
        let (z, x, y) = (int(r[0]), int(r[1]), int(r[2]));
        assert_eq!((&x * &y), z);
        assert_eq!(&y * &x, z);
    });
}

#[test]
fn int_mul_range_and_binomial() {
    each(MUL_RANGES_Z, 14, |r| {
        let got = Int::mul_range(num(r[0]), num(r[1]));
        assert_eq!(got.to_string(), r[2], "MulRange({}, {})", r[0], r[1]);
    });
    each(TEST_BINOMIAL_0, 10, |r| {
        let got = Int::binomial(num(r[0]), num(r[1]));
        assert_eq!(got.to_string(), r[2], "Binomial({}, {})", r[0], r[1]);
    });
}

#[test]
fn int_division_signs() {
    each(DIVISION_SIGNS_TESTS, 6, |r| {
        let (x, y) = (int(r[0]), int(r[1]));
        let (q, rem, d, m) = (int(r[2]), int(r[3]), int(r[4]), int(r[5]));
        assert_eq!((&x / &y), q);
        assert_eq!((&x % &y), rem);
        assert_eq!(x.quo_rem(&y), (q.clone(), rem.clone()));
        assert_eq!(x.div_euclid(&y), d);
        assert_eq!(x.rem_euclid(&y), m);
        assert_eq!(x.div_mod(&y), (d, m));
        assert_eq!(&x / &y, q);
        assert_eq!(&x % &y, rem);
    });
    assert!(panics(|| Int::new(1) / &Int::zero()));
}

#[test]
fn int_quo_rem_large() {
    each(QUO_TESTS, 2, |r| {
        let (x, y) = (int10(r[0]), int10(r[1]));
        let (q, rem) = x.quo_rem(&y);
        assert_eq!(q, int10(r[2]));
        assert_eq!(rem, int10(r[3]));
        assert_eq!(&(&q * &y) + &rem, x);
    });
}

#[test]
fn int_divide_modes() {
    // Go's TestIntDivide checks the defining properties for every sign
    // combination of the listed values.
    let values: Vec<Int> = TEST_INT_DIVIDE_0.iter().map(|r| int(r[0])).collect();
    assert!(values.len() >= 5);
    for x in &values {
        for y in &values {
            for (sx, sy) in [(1, 1), (-1, 1), (1, -1), (-1, -1)] {
                let x = if sx < 0 { x.neg() } else { x.clone() };
                let y = if sy < 0 { y.neg() } else { y.clone() };
                for m in [
                    RoundingMode::TRUNC,
                    RoundingMode::FLOOR,
                    RoundingMode::ROUND,
                    RoundingMode::CEIL,
                ] {
                    let (q, r) = x.divide(&y, m);
                    assert_eq!(&(&q * &y) + &r, x, "{x} / {y} ({m})");
                    assert!(r.cmp_abs(&y) == Ordering::Less);
                    match m {
                        RoundingMode::ToZero => assert_eq!((q.clone(), r.clone()), x.quo_rem(&y)),
                        RoundingMode::ToNegativeInf => {
                            assert!(r.sign() == 0 || r.sign() == y.sign())
                        }
                        RoundingMode::ToPositiveInf => {
                            assert!(r.sign() == 0 || r.sign() == -y.sign())
                        }
                        _ => assert!(r.lsh(1).cmp_abs(&y) != Ordering::Greater),
                    }
                }
            }
        }
    }
    assert!(panics(
        || Int::new(1).divide(&Int::new(3), RoundingMode::ToNearestAway)
    ));
}

#[test]
fn int_bit_len_tzb_not() {
    each(BIT_LEN_TESTS, 10, |r| {
        assert_eq!(int(r[0]).bit_len(), num::<usize>(r[1]), "{}", r[0])
    });
    each(TZB_TESTS, 5, |r| {
        assert_eq!(
            int(r[0]).trailing_zero_bits(),
            num::<usize>(r[1]),
            "{}",
            r[0]
        )
    });
    each(NOT_TESTS, 5, |r| {
        let x = int(r[0]);
        assert_eq!(x.not(), int(r[1]));
        assert_eq!(!&x.not(), x);
    });
}

#[test]
fn int_exp() {
    each(EXP_TESTS, 30, |r| {
        let (x, y) = (int(r[0]), int(r[1]));
        let m = (!r[2].is_empty()).then(|| int(r[2]));
        let want = (!r[3].is_empty()).then(|| int(r[3]));
        assert_eq!(
            x.exp(&y, m.as_ref()),
            want,
            "Exp({}, {}, {})",
            r[0],
            r[1],
            r[2]
        );
        if m.is_none() {
            assert_eq!(x.exp(&y, Some(&Int::zero())), want);
        }
    });
}

#[test]
fn int_gcd() {
    each(GCD_TESTS, 10, |r| {
        let (d, x, y, a, b) = (int(r[0]), int(r[1]), int(r[2]), int(r[3]), int(r[4]));
        assert_eq!(Int::gcd(&a, &b), d, "GCD({a}, {b})");
        assert_eq!(Int::gcd_ext(&a, &b), (d.clone(), x, y), "GCD({a}, {b})");
    });
}

#[test]
fn int_shifts() {
    each(RSH_TESTS, 19, |r| {
        let got = int(r[0]).rsh(num(r[1]));
        assert_eq!(got, int(r[2]), "{} >> {}", r[0], r[1]);
    });
    each(LSH_TESTS, 19, |r| {
        let got = &int(r[0]) << num::<usize>(r[1]);
        assert_eq!(got, int(r[2]), "{} << {}", r[0], r[1]);
    });
}

#[test]
fn int_cmp_abs() {
    let values: Vec<Int> = CMP_ABS_TESTS.iter().map(|r| int10(r[0])).collect();
    assert!(values.len() >= 8);
    for (i, x) in values.iter().enumerate() {
        for (j, y) in values.iter().enumerate() {
            for (a, b) in [
                (x.clone(), y.clone()),
                (x.neg(), y.clone()),
                (x.clone(), y.neg()),
                (x.neg(), y.neg()),
            ] {
                assert_eq!(a.cmp_abs(&b), i.cmp(&j), "CmpAbs({a}, {b})");
            }
        }
    }
}

#[test]
fn int_int64_uint64() {
    each(INT64_TESTS, 10, |r| {
        let x = int(r[0]);
        let fits = x.to_string().parse::<i64>();
        assert_eq!(x.is_int64(), fits.is_ok(), "{}", r[0]);
        if let Ok(v) = fits {
            assert_eq!(x.int64(), v);
        }
    });
    each(UINT64_TESTS, 10, |r| {
        let x = int(r[0]);
        let fits = x.to_string().parse::<u64>();
        assert_eq!(x.is_uint64(), fits.is_ok(), "{}", r[0]);
        if let Ok(v) = fits {
            assert_eq!(x.uint64(), v);
        }
    });
    each(TEST_FLOAT64_0, 20, |r| {
        let (f, a) = int(r[0]).float64();
        let want: f64 = r[1].parse().unwrap();
        assert_eq!((f, a), (want, acc(r[2])), "{}", r[0]);
    });
}

#[test]
fn int_bitwise_and_bits() {
    each(BITWISE_TESTS, 17, |r| {
        let (x, y) = (int(r[0]), int(r[1]));
        assert_eq!((&x & &y), int(r[2]), "{} & {}", r[0], r[1]);
        assert_eq!(&x | &y, int(r[3]), "{} | {}", r[0], r[1]);
        assert_eq!(&x ^ &y, int(r[4]), "{} ^ {}", r[0], r[1]);
        assert_eq!(x.and_not(&y), int(r[5]), "{} &^ {}", r[0], r[1]);
        for v in [&x, &y] {
            // Go's testBitset: setting and clearing every bit round-trips.
            for i in 0..v.bit_len() + 2 {
                let b = v.bit(i);
                assert_eq!(v.set_bit(i, b), *v);
                assert_eq!(v.set_bit(i, 1 - b).set_bit(i, b), *v);
                assert_eq!(v.set_bit(i, 1).bit(i), 1);
                assert_eq!(v.set_bit(i, 0).bit(i), 0);
            }
        }
    });
    each(BITSET_TESTS, 10, |r| {
        assert_eq!(
            int(r[0]).bit(num(r[1])),
            num::<u32>(r[2]),
            "{}.Bit({})",
            r[0],
            r[1]
        );
    });
    assert_eq!(Int::zero().set_bit(2, 1), Int::new(4));
    assert!(panics(|| Int::new(1).set_bit(0, 2)));
}

#[test]
fn int_mod_inverse_and_jacobi() {
    each(MOD_INVERSE_TESTS, 5, |r| {
        let (g, n) = (int10(r[0]), int10(r[1]));
        let inv = g.mod_inverse(&n).expect("inverse exists");
        assert_eq!(
            (&inv * &g).rem_euclid(&n),
            Int::new(1),
            "ModInverse({g}, {n})"
        );
    });
    for n in 2..100 {
        let m = Int::new(n);
        for x in 1..n {
            let e = Int::new(x);
            match e.mod_inverse(&m) {
                Some(inv) => assert_eq!((&inv * &e).rem_euclid(&m), Int::new(1)),
                None => assert_ne!(Int::gcd(&e, &m), Int::new(1)),
            }
        }
    }
    each(TEST_JACOBI_0, 17, |r| {
        assert_eq!(
            jacobi(&int(r[0]), &int(r[1])),
            num::<i32>(r[2]),
            "Jacobi({}, {})",
            r[0],
            r[1]
        );
    });
    assert!(panics(|| jacobi(&Int::new(3), &Int::new(4))));
}

#[test]
fn int_mod_sqrt() {
    // Go's TestModSqrt checks z*z == x mod p for small primes.
    for p in [3i64, 5, 7, 11, 13, 17, 41, 97, 113, 193, 257, 65537] {
        let pm = Int::new(p);
        for x in 0..p.min(300) {
            let xi = Int::new(x);
            match xi.mod_sqrt(&pm) {
                Some(z) => assert_eq!((&z * &z).rem_euclid(&pm), xi, "ModSqrt({x}, {p})"),
                None => assert_eq!(jacobi(&xi, &pm), -1),
            }
        }
    }
}

#[test]
fn int_fill_bytes() {
    each(TEST_FILL_BYTES_0, 5, |r| {
        let x = int(r[0]);
        let bytes = x.bytes();
        assert_eq!(Int::from_bytes(&bytes), x.abs());
        for extra in [0, 1, 7, 20] {
            let mut buf = vec![0xffu8; bytes.len() + extra];
            x.fill_bytes(&mut buf);
            assert!(buf[..extra].iter().all(|&b| b == 0));
            assert_eq!(&buf[extra..], &bytes[..]);
        }
        if !bytes.is_empty() {
            let mut small = vec![0u8; bytes.len() - 1];
            assert!(panics(|| {
                x.fill_bytes(&mut small);
            }));
        }
    });
}

#[test]
fn int_set_string_and_text() {
    each(STRING_TESTS, 40, |r| {
        let (input, out, base) = (r[0], r[1], num::<u32>(r[2]));
        let (val, ok) = (num::<i64>(r[3]), flag(r[4]));
        let got = Int::from_str_radix(input, base);
        assert_eq!(got.is_some(), ok, "SetString({input:?}, {base})");
        if let Some(z) = got {
            assert_eq!(z, Int::new(val), "SetString({input:?}, {base})");
            let base = if base == 0 { 10 } else { base };
            assert_eq!(z.text(base), out);
            assert_eq!(
                z.append(b"x".to_vec(), base),
                [b"x", out.as_bytes()].concat()
            );
        }
    });
    assert_eq!(MAX_BASE, 62);
    assert!(panics(|| Int::new(1).text(63)));
    assert!(panics(|| Int::from_str_radix("1", 1)));
}

#[test]
fn int_format() {
    let mut skipped = 0;
    each(FORMAT_TESTS, 100, |r| {
        if r[0] == "<nil>" {
            skipped += 1;
            return;
        }
        let x = int(r[0]);
        match FormatSpec::parse(r[1]) {
            Some((spec, verb)) => assert_eq!(x.format(verb, &spec), r[2], "{:?} {}", r[1], r[0]),
            None => skipped += 1,
        }
    });
    assert!(skipped < 10, "{skipped} format rows skipped");
    assert_eq!(format!("{:+08}", Int::new(42)), "+0000042");
    assert_eq!(format!("{:#x}", Int::new(255)), "0xff");
    assert_eq!(format!("{:#o}", Int::new(8)), "0o10");
    assert_eq!(format!("{:<6}|", Int::new(-3)), "-3    |");
}

#[test]
fn int_scan() {
    each(SCAN_TESTS, 20, |r| {
        let verb = r[1].chars().last().unwrap();
        let mut input = r[0].as_bytes();
        let got = Int::scan(&mut input, verb).unwrap_or_else(|e| panic!("{r:?}: {e}"));
        assert_eq!(got.to_string(), r[2], "{r:?}");
        assert_eq!(input.len(), num::<usize>(r[3]), "{r:?} remaining");
    });
    assert!(Int::scan(&mut &b"12"[..], 'q').is_err());
    assert!(Int::scan(&mut &b"   "[..], 'v').is_err());
}

#[test]
fn int_encodings() {
    for sign in ["", "+", "-"] {
        each(ENCODING_TESTS, 5, |r| {
            let x = int(&format!("{sign}{}", r[0]));
            assert_eq!(Int::gob_decode(&x.gob_encode()).unwrap(), x);
            assert_eq!(
                Int::unmarshal_json(&x.marshal_json()).unwrap(),
                Some(x.clone())
            );
            assert_eq!(Int::unmarshal_text(&x.marshal_text()).unwrap(), x);
            assert_eq!(x.to_string().parse::<Int>().unwrap(), x);
        });
    }
    assert_eq!(Int::unmarshal_json(b"null").unwrap(), None);
    assert_eq!(
        Int::unmarshal_text(b"x").unwrap_err().to_string(),
        "math/big: cannot unmarshal \"x\" into a *big.Int"
    );
    assert!(Int::gob_decode(&[4]).is_err());
    assert_eq!(Int::gob_decode(&[]).unwrap(), Int::zero());
}

#[test]
fn int_probably_prime() {
    each(PRIMES, 20, |r| {
        let p = int10(&r[0].replace(['\n', ' '], ""));
        for n in [0, 1, 20] {
            assert!(p.probably_prime(n), "{p} should be prime (n={n})");
        }
    });
    each(COMPOSITES, 20, |r| {
        let c = int10(&r[0].replace(['\n', ' '], ""));
        for n in [0, 1, 20] {
            assert!(!c.probably_prime(n), "{c} should be composite (n={n})");
        }
    });
    each(TEST_MILLER_RABIN_PSEUDOPRIMES_0, 5, |r| {
        assert!(!int10(r[0]).probably_prime(0))
    });
    each(TEST_LUCAS_PSEUDOPRIMES_0, 5, |r| {
        assert!(!int10(r[0]).probably_prime(0))
    });
    each(TEST_PROBABLY_PRIME_0, 3, |r| {
        assert!(!int(r[0]).probably_prime(1))
    });
    assert!(panics(|| Int::new(7).probably_prime(-1)));
}

#[test]
fn int_sqrt_bits_and_ops() {
    for n in 0u64..2000 {
        let s = Int::from_u64(n).sqrt().uint64();
        assert!(s * s <= n && (s + 1) * (s + 1) > n);
    }
    assert!(panics(|| Int::new(-1).sqrt()));
    each(TEST_BITS_0, 3, |r| {
        let words: Vec<u64> = r[0]
            .trim_matches(['[', ']'])
            .split(',')
            .filter(|s| !s.is_empty() && *s != "nil")
            .map(|s| int(s).uint64())
            .collect();
        let x = Int::from_bits(&words);
        let mut norm = words.clone();
        while norm.last() == Some(&0) {
            norm.pop();
        }
        assert_eq!(x.bits(), &norm[..]);
    });
    let x = Int::new(-6);
    assert_eq!(-&x, Int::new(6));
    assert_eq!(&x >> 1, Int::new(-3));
    assert_eq!(&x >> 2, Int::new(-2));
    assert_eq!(&x & &Int::new(3), Int::new(2));
}

// ---------------------------------------------------------------- Rat

#[test]
fn rat_cmp_and_arithmetic() {
    each(RAT_CMP_TESTS, 9, |r| {
        assert_eq!(
            rat(r[0]).cmp(&rat(r[1])) as i32,
            num::<i32>(r[2]),
            "Cmp({}, {})",
            r[0],
            r[1]
        );
    });
    each(RAT_BIN_TESTS, 15, |r| {
        let (x, y, sum, prod) = (rat(r[0]), rat(r[1]), rat(r[2]), rat(r[3]));
        assert_eq!((&x + &y), sum, "{x} + {y}");
        assert_eq!(&y + &x, sum);
        assert_eq!((&sum - &y), x);
        assert_eq!(&sum - &x, y);
        assert_eq!((&x * &y), prod, "{x} * {y}");
        assert_eq!(&y * &x, prod);
        if x.sign() != 0 {
            assert_eq!((&prod / &x), y);
        }
        if y.sign() != 0 {
            assert_eq!(&prod / &y, x);
        }
    });
    assert!(panics(|| Rat::new(1, 2) / &Rat::default()));
    assert!(panics(|| Rat::default().inv()));
    assert!(panics(|| Rat::new(1, 0)));
}

#[test]
fn rat_set_frac_and_strings() {
    each(SET_FRAC64_TESTS, 5, |r| {
        let x = Rat::new(num(r[0]), num(r[1]));
        assert_eq!(x.rat_string(), r[2], "SetFrac64({}, {})", r[0], r[1]);
    });
    for table in [SET_STRING_TESTS, SET_STRING_TESTS2] {
        each(table, 15, |r| {
            let got = Rat::from_string(r[0]);
            assert_eq!(got.is_some(), flag(r[2]), "SetString({:?})", r[0]);
            if let Some(x) = got {
                assert_eq!(x.rat_string(), r[1], "SetString({:?})", r[0]);
            }
        });
    }
    each(FLOAT_STRING_TESTS, 15, |r| {
        // Go treats a negative precision like 0.
        let got = rat(r[0]).float_string(num::<i64>(r[1]).max(0) as usize);
        assert_eq!(got, r[2], "FloatString({}, {})", r[0], r[1]);
    });
    each(TEST_FLOAT_PREC_0, 15, |r| {
        // Rows naming Go variables (such as `zero`) are not literals.
        let Some(x) = Rat::from_string(r[0]) else {
            return;
        };
        let (n, exact) = x.float_prec();
        assert_eq!(
            (n, exact),
            (num::<usize>(r[1]), flag(r[2])),
            "FloatPrec({})",
            r[0]
        );
    });
    each(TEST_ISSUE45910_0, 4, |r| {
        assert_eq!(
            Rat::from_string(r[0]).is_some(),
            flag(r[1]),
            "SetString({})",
            r[0]
        );
    });
}

#[test]
fn rat_float64_inputs() {
    // Go's TestFloat32SpecialCases/TestFloat64SpecialCases: Rat.Float64 must
    // agree with correctly rounded strconv.ParseFloat (Rust's parse).
    each(FLOAT64INPUTS, 100, |r| {
        let s = r[0];
        let Some(x) = Rat::from_string(s) else { return };
        // Rust's parser has no hex floats; those rows are covered by the
        // Go differential.
        let (Ok(want64), Ok(want32)) = (s.parse::<f64>(), s.parse::<f32>()) else {
            return;
        };
        let (f64v, exact64) = x.float64();
        // Rat has no negative zero; compare zeros numerically.
        assert!(
            f64v.to_bits() == want64.to_bits() || f64v == 0.0 && want64 == 0.0,
            "Float64({s})"
        );
        if exact64 {
            assert_eq!(Rat::from_f64(f64v).unwrap(), x);
        }
        let (f32v, _) = x.float32();
        assert!(
            f32v.to_bits() == want32.to_bits() || f32v == 0.0 && want32 == 0.0,
            "Float32({s})"
        );
    });
    for bits in [
        0u64,
        1,
        0x000f_ffff_ffff_ffff,
        0x0010_0000_0000_0000,
        0x7fef_ffff_ffff_ffff,
    ] {
        let f = f64::from_bits(bits);
        let x = Rat::from_f64(f).unwrap();
        assert_eq!(x.float64(), (f, true));
        assert_eq!(Rat::from_f64(-f).unwrap().float64(), (-f, true));
    }
    each(TEST_SET_FLOAT64_NON_FINITE_0, 3, |r| {
        let f: f64 = r[0].parse().unwrap();
        assert!(Rat::from_f64(f).is_none());
    });
}

#[test]
fn rat_encodings() {
    each(RAT_NUMS, 5, |n| {
        each(RAT_DENOMS, 3, |d| {
            let x = Rat::from_frac(&int10(n[0]), &int10(d[0]));
            assert_eq!(Rat::gob_decode(&x.gob_encode().unwrap()).unwrap(), x);
            assert_eq!(Rat::unmarshal_text(&x.marshal_text()).unwrap(), x);
            assert_eq!(x.to_string().parse::<Rat>().unwrap(), x);
        });
    });
    each(TEST_RAT_GOB_DECODE_SHORT_BUFFER_0, 3, |r| {
        let bytes: Vec<u8> = r[0]
            .trim_matches(['[', ']'])
            .split(',')
            .map(|s| s.parse().unwrap())
            .collect();
        assert!(Rat::gob_decode(&bytes).is_err(), "{bytes:?}");
    });
    let mut text = &b" 3/4x"[..];
    assert_eq!(Rat::scan(&mut text, 'v').unwrap(), Rat::new(3, 4));
    let mut text = &b"1.5e2 rest"[..];
    assert_eq!(Rat::scan(&mut text, 'g').unwrap(), Rat::from_i64(150));
    assert_eq!(text, b" rest");
    assert!(Rat::scan(&mut &b"1"[..], 'd').is_err());
}

#[test]
fn rat_exponent_limits() {
    // Go caps decimal exponents at 1e6 and binary ones at 1e7.
    assert!(Rat::from_string("1e1000000").is_some());
    assert!(Rat::from_string("1e1000001").is_none());
    assert!(Rat::from_string("1p10000000").is_some());
    assert!(Rat::from_string("1p10000001").is_none());
    assert!(Rat::from_string("1p-10000001").is_none());
    assert!(Rat::from_string("0e99999999999").is_some());
}

// ---------------------------------------------------------------- Float

#[test]
fn float_set_prec_min_prec_predicates() {
    each(TEST_FLOAT_SET_PREC_0, 14, |r| {
        let mut x = float(r[0]);
        let prec = num::<u64>(r[1]).min(u64::from(MAX_PREC)) as u32;
        x.set_prec(prec);
        assert_eq!(x.prec(), prec);
        assert_eq!(
            (x.to_string(), x.acc()),
            (r[2].to_string(), acc(r[3])),
            "{}.SetPrec({})",
            r[0],
            r[1]
        );
    });
    each(TEST_FLOAT_MIN_PREC_0, 10, |r| {
        let mut x = float(r[0]);
        x.set_prec(100);
        assert_eq!(x.min_prec(), num::<u64>(r[1]), "{}.MinPrec()", r[0]);
    });
    each(TEST_FLOAT_PREDICATES_0, 6, |r| {
        let x = float(r[0]);
        assert_eq!(x.sign(), num::<i32>(r[1]), "{}", r[0]);
        assert_eq!(x.signbit(), flag(r[2]), "{}", r[0]);
        assert_eq!(x.is_inf(), flag(r[3]), "{}", r[0]);
    });
    each(TEST_FLOAT_SIGN_0, 5, |r| {
        assert_eq!(float(r[0]).sign(), num::<i32>(r[1]))
    });
    each(TEST_FLOAT_IS_INT_0, 10, |r| {
        let s = r[0].trim_end_matches(" int");
        assert_eq!(float(s).is_int(), s != r[0], "{s}.IsInt()");
    });
}

#[test]
fn float_mant_exp() {
    let alike = |a: &Float, b: &Float| a.cmp(b) == Ordering::Equal && a.signbit() == b.signbit();
    each(TEST_FLOAT_MANT_EXP_0, 8, |r| {
        let x = float(r[0]);
        let mut m = Float::new();
        let e = x.mant_exp(Some(&mut m));
        assert!(
            alike(&m, &float(r[1])) && e == num::<i32>(r[2]),
            "{}.MantExp()",
            r[0]
        );
    });
    each(TEST_FLOAT_SET_MANT_EXP_0, 8, |r| {
        let (frac, want) = (float(r[0]), float(r[2]));
        let mut z = Float::new();
        z.set_mant_exp(&frac, num(r[1]));
        assert!(alike(&z, &want), "SetMantExp({}, {}) = {z}", r[0], r[1]);
        let mut mant = Float::new();
        let e = want.mant_exp(Some(&mut mant));
        z.set_mant_exp(&mant, i64::from(e));
        assert_eq!(z.cmp(&want), Ordering::Equal);
    });
}

#[test]
fn float_round() {
    let from_binary = |s: &str| i64::from_str_radix(s, 2).unwrap();
    each(TEST_FLOAT_ROUND_0, 50, |r| {
        let prec: u32 = num(r[0]);
        let x = from_binary(r[1]);
        let (z, e, n, a) = (
            from_binary(r[2]),
            from_binary(r[3]),
            from_binary(r[4]),
            from_binary(r[5]),
        );
        let cases = [
            (x, z, RoundingMode::ToZero),
            (x, e, RoundingMode::ToNearestEven),
            (x, n, RoundingMode::ToNearestAway),
            (x, a, RoundingMode::AwayFromZero),
            (x, z, RoundingMode::ToNegativeInf),
            (x, a, RoundingMode::ToPositiveInf),
            (-x, -a, RoundingMode::ToNegativeInf),
            (-x, -z, RoundingMode::ToPositiveInf),
        ];
        for (x, want, m) in cases {
            let want_acc = match want.cmp(&x) {
                Ordering::Less => Accuracy::Below,
                Ordering::Equal => Accuracy::Exact,
                Ordering::Greater => Accuracy::Above,
            };
            let mut f = Float::new();
            f.set_mode(m).set_int64(x).set_prec(prec);
            assert_eq!(
                (f.int64().0, f.prec(), f.acc()),
                (want, prec, want_acc),
                "round {x} ({prec} bits, {m})"
            );
            let mut g = Float::new();
            g.set_mode(m).set_prec(prec).set_int64(x);
            assert_eq!(g, f);
        }
    });
}

#[test]
fn float_conversions() {
    each(TEST_FLOAT_INT64_0, 16, |r| {
        assert_eq!(
            float(r[0]).int64(),
            (num::<i64>(r[1]), acc(r[2])),
            "{}.Int64()",
            r[0]
        );
    });
    each(TEST_FLOAT_UINT64_0, 15, |r| {
        assert_eq!(
            float(r[0]).uint64(),
            (num::<u64>(r[1]), acc(r[2])),
            "{}.Uint64()",
            r[0]
        );
    });
    each(TEST_FLOAT_FLOAT32_0, 16, |r| {
        for negate in [false, true] {
            let (tx, mut tout, mut tacc) = (r[0].to_string(), num::<f32>(r[1]), acc(r[2]));
            let tx = if negate {
                tout = -tout;
                tacc = neg_acc(tacc);
                format!("-{tx}")
            } else {
                tx
            };
            let (out, a) = float(&tx).float32();
            assert_eq!((out.to_bits(), a), (tout.to_bits(), tacc), "{tx}.Float32()");
        }
    });
    each(TEST_FLOAT_FLOAT64_0, 16, |r| {
        for negate in [false, true] {
            let (tx, mut tout, mut tacc) = (r[0].to_string(), num::<f64>(r[1]), acc(r[2]));
            let tx = if negate {
                tout = -tout;
                tacc = neg_acc(tacc);
                format!("-{tx}")
            } else {
                tx
            };
            let (out, a) = float(&tx).float64();
            assert_eq!((out.to_bits(), a), (tout.to_bits(), tacc), "{tx}.Float64()");
        }
    });
    each(TEST_FLOAT_INT_0, 15, |r| {
        let (z, a) = float(r[0]).int();
        let got = z.map_or_else(|| "nil".to_string(), |z| z.to_string());
        assert_eq!((got.as_str(), a), (r[1], acc(r[2])), "{}.Int()", r[0]);
    });
    each(TEST_FLOAT_RAT_0, 10, |r| {
        let mut x = float(r[0]);
        x.set_prec(64);
        let (z, a) = x.rat();
        let got = z.as_ref().map_or_else(|| "nil".to_string(), Rat::to_string);
        assert_eq!((got.as_str(), a), (r[1], acc(r[2])), "{}.Rat()", r[0]);
        if let Some(z) = z {
            let mut back = Float::with_prec(64);
            back.set_rat(&z);
            assert_eq!(back, x);
        }
    });
    each(TEST_FLOAT_SET_INF_0, 2, |r| {
        let mut z = Float::with_prec(num(r[1]));
        z.set_inf(flag(r[0]));
        assert_eq!(z.to_string(), r[2]);
    });
}

#[test]
fn float_arithmetic_tables() {
    each(TEST_FLOAT_ARITHMETIC_OVERFLOW_0, 15, |r| {
        let (x, y) = (float(r[3]), float(r[4]));
        let mut z = Float::with_prec(num(r[0]));
        z.set_mode(mode(r[1]));
        match r[2] {
            "+" => z.add_into(&x, &y),
            "-" => z.sub_into(&x, &y),
            "*" => z.mul_into(&x, &y),
            _ => z.quo_into(&x, &y),
        }
        .unwrap();
        assert_eq!(
            (z.text(b'p', 0), z.acc()),
            (r[5].to_string(), acc(r[6])),
            "{r:?}"
        );
    });
    each(TEST_FLOAT_ARITHMETIC_ROUNDING_0, 12, |r| {
        let (x, y) = (Float::from_i64(num(r[2])), Float::from_i64(num(r[3])));
        let mut z = Float::with_prec(num(r[1]));
        z.set_mode(mode(r[0]));
        match r[5] {
            "+" => z.add_into(&x, &y),
            "-" => z.sub_into(&x, &y),
            "*" => z.mul_into(&x, &y),
            _ => z.quo_into(&x, &y),
        }
        .unwrap();
        assert_eq!(z.int64(), (num::<i64>(r[4]), Accuracy::Exact), "{r:?}");
    });
}

#[test]
fn float_nan_results() {
    let inf = |neg: bool| {
        let mut f = Float::new();
        f.set_inf(neg);
        f
    };
    let zero = Float::new();
    assert!(Float::new().add_into(&inf(false), &inf(true)).is_err());
    assert!(Float::new().sub_into(&inf(false), &inf(false)).is_err());
    assert!(Float::new().mul_into(&zero, &inf(false)).is_err());
    assert!(Float::new().quo_into(&zero, &zero).is_err());
    assert!(Float::new().quo_into(&inf(true), &inf(false)).is_err());
    assert!(Float::new().sqrt(&Float::from_i64(-1)).is_err());
    assert!(Float::from_f64(f64::NAN).is_err());
    let mut z = Float::from_i64(5);
    let err = z.add_into(&inf(false), &inf(true)).unwrap_err();
    assert_eq!(
        err.to_string(),
        "addition of infinities with opposite signs"
    );
    assert_eq!((z.sign(), z.acc()), (0, Accuracy::Exact));
}

#[test]
fn float_text_tables() {
    each(TEST_FLOAT_TEXT_0, 120, |r| {
        let (x, _) = Float::parse_float(r[0], 0, num(r[2]), RoundingMode::ToNearestEven).unwrap();
        let mut x = x;
        if r[1] != "defaultRound" {
            x.set_mode(mode(r[1]));
        }
        let got = x.text(r[3].as_bytes()[0], num(r[4]));
        assert_eq!(got, r[5], "{r:?}");
    });
    each(TEST_FLOAT64_TEXT_0, 60, |r| {
        let v: f64 = if r[0] == "-0" { -0.0 } else { num(r[0]) };
        // Go's actualPrec: denormals have fewer mantissa bits.
        let prec = if v != 0.0 && v.to_bits() & (0x7ff << 52) == 0 {
            64 - (v.to_bits() & ((1 << 52) - 1)).leading_zeros()
        } else {
            53
        };
        let mut f = Float::with_prec(prec);
        f.set_float64(v).unwrap();
        assert_eq!(f.text(r[1].as_bytes()[0], num(r[2])), r[3], "{r:?}");
    });
    each(TEST_ROUND_SHORTEST_NORMAL_0, 5, |r| {
        let v: f64 = r[0].parse().unwrap();
        let mut f = Float::with_prec(53);
        f.set_float64(v).unwrap();
        let rust = format!("{v:e}");
        let (m, e) = rust.split_once('e').unwrap();
        let e: i32 = e.parse().unwrap();
        assert_eq!(
            f.text(b'g', -1),
            format!("{m}e{}{:02}", if e < 0 { '-' } else { '+' }, e.abs())
        );
    });
}

#[test]
fn float_format_table() {
    each(TEST_FLOAT_FORMAT_0, 80, |r| {
        let value = r[1];
        let mut x = Float::new();
        if let Some(v) = value.strip_prefix("f32:") {
            x.set_prec(24)
                .set_float64(f64::from(num::<f32>(v)))
                .unwrap();
        } else if let Some(v) = value.strip_prefix("f64:") {
            let f: f64 = if v == "-0" { -0.0 } else { num(v) };
            x.set_prec(53).set_float64(f).unwrap();
        } else {
            let v = value.strip_prefix("s:").unwrap();
            x.set_prec(512);
            x.parse(v, 0).unwrap();
        }
        let (spec, verb) = FormatSpec::parse(r[0]).unwrap();
        assert_eq!(x.format(verb, &spec), r[2], "{r:?}");
    });
}

#[test]
fn float_parse_table() {
    each(TEST_FLOAT_SET_FLOAT64_STRING_0, 80, |r| {
        let mut x = Float::with_prec(53);
        let ok = x.set_string(r[0]).is_some();
        let want = match r[1] {
            "?-zero_" => Some(-0.0),
            "?nan" | "nan" | "NaN" => None,
            s => Some(num::<f64>(s)),
        };
        match want {
            Some(w) if ok => {
                let mut wf = Float::new();
                wf.set_float64(w).unwrap();
                assert!(
                    x == wf && x.signbit() == wf.signbit(),
                    "{:?}: got {x}",
                    r[0]
                );
            }
            Some(_) => panic!("{:?}: parse failed", r[0]),
            None => assert!(!ok, "{:?} should fail", r[0]),
        }
    });
    let mut z = Float::new();
    assert_eq!(
        z.parse("1p2147483648", 0).unwrap_err().to_string(),
        "exponent overflow"
    );
    assert_eq!(
        z.parse("12x", 0).unwrap_err().to_string(),
        "expected end of string, found 'x'"
    );
    assert_eq!(z.parse("", 0).unwrap_err().to_string(), "EOF");
    let mut text = &b"  0x1.8p1 rest"[..];
    let mut f = Float::new();
    f.scan(&mut text).unwrap();
    assert_eq!((f.text(b'g', -1).as_str(), text), ("3", &b" rest"[..]));
}

#[test]
fn float_sqrt_table() {
    each(TEST_FLOAT_SQRT_0, 10, |r| {
        let x = float(r[0]);
        let want = float(r[1]);
        for prec in [
            24u32, 53, 64, 65, 100, 128, 129, 200, 256, 400, 600, 700, 1000,
        ] {
            let mut z = Float::with_prec(prec);
            z.sqrt(&x).unwrap();
            let mut w = Float::with_prec(prec);
            w.set(&want);
            assert_eq!(
                z.text(b'p', 0),
                w.text(b'p', 0),
                "sqrt({}) at {prec} bits",
                r[0]
            );
        }
    });
}

#[test]
fn float_encodings() {
    each(FLOAT_VALS, 10, |r| {
        for sign in ["", "+", "-"] {
            for prec in [0u32, 1, 2, 10, 53, 64, 100, 1000] {
                let s = format!("{sign}{}", r[0]);
                let mut x = Float::with_prec(200);
                x.parse(&s, 0).unwrap();
                x.set_prec(prec);
                let mut y = Float::new();
                y.gob_decode(&x.gob_encode()).unwrap();
                assert!(
                    y == x && y.prec() == x.prec() && y.signbit() == x.signbit(),
                    "gob {s} prec {prec}"
                );
                let mut t = Float::with_prec(prec.max(1));
                t.unmarshal_text(&x.marshal_text()).unwrap();
                if prec > 0 {
                    assert_eq!(t, x, "text {s} prec {prec}");
                }
            }
        }
    });
    each(TEST_FLOAT_GOB_DECODE_SHORT_BUFFER_0, 2, |r| {
        let bytes: Vec<u8> = r[0]
            .trim_matches(['[', ']'])
            .split(',')
            .map(|s| s.parse().unwrap())
            .collect();
        assert!(Float::new().gob_decode(&bytes).is_err(), "{bytes:?}");
    });
}

// ------------------------------------------------------- performance

/// Large operands stay fast: Karatsuba multiplication, Knuth division and
/// divide-and-conquer conversions on 20,000-digit values (debug builds
/// included). The 100,000-digit measurement is `--ignored`.
#[test]
fn large_operands() {
    large_round_trip(20_000);
}

#[test]
#[ignore = "timing demonstration; run with --release -- --ignored"]
fn large_operands_100k_digits() {
    let start = std::time::Instant::now();
    large_round_trip(100_000);
    eprintln!("100k-digit round trip: {:?}", start.elapsed());
}

fn large_round_trip(digits: usize) {
    let s: String = (0..digits)
        .map(|i| char::from(b'1' + (i * 7 % 9) as u8))
        .collect();
    let x: Int = s.parse().unwrap();
    assert_eq!(x.to_string(), s);
    let t: String = (0..digits / 2)
        .map(|i| char::from(b'1' + (i * 5 % 9) as u8))
        .collect();
    let y: Int = t.parse().unwrap();
    let p = &x * &y;
    let (q, r) = (&p + &Int::new(12345)).quo_rem(&x);
    assert_eq!(q, y);
    assert_eq!(r, Int::new(12345));
    assert_eq!(Int::from_str_radix(&p.text(16), 16).unwrap(), p);
    assert_eq!((p.sqrt() * &p.sqrt()).cmp(&p), Ordering::Less);
}

#[test]
fn gob_decode_stores_what_go_stores() {
    // Int: a negative zero is kept and re-encoded.
    let x = Int::gob_decode(&[3]).unwrap();
    assert_eq!(x.gob_encode(), [3]);
    assert_eq!(x.cmp(&Int::zero()), Ordering::Less);
    assert_eq!(x.text(10), "0");

    // Rat: no denominator bytes (what Go encodes for the zero value) decode to 0/1, an
    // unreduced fraction stays unreduced, and a zero denominator is 1.
    let zero_value = Rat::gob_decode(&[2, 0, 0, 0, 0]).unwrap();
    assert_eq!(zero_value.to_string(), "0/1");
    let unreduced = Rat::gob_decode(&[2, 0, 0, 0, 1, 2, 4]).unwrap();
    assert_eq!(unreduced.to_string(), "2/4");
    assert_eq!(unreduced.cmp(&Rat::new(1, 2)), Ordering::Equal);
    let zero_den = Rat::gob_decode(&[2, 0, 0, 0, 1, 5, 0, 0]).unwrap();
    assert_eq!(zero_den.to_string(), "5/1");

    // Float: rounding mode, accuracy and form bits outside the named values are kept.
    let mut f = Float::new();
    f.gob_decode(&[1, 0b1101_1000, 0, 0, 0, 53]).unwrap();
    assert_eq!(f.mode().to_string(), "RoundingMode(6)");
    assert_eq!(f.acc().to_string(), "Accuracy(2)");
}

#[test]
fn float_operators_use_larger_precision_and_panic_on_nan() {
    let a = Float::with_prec(100).set_int64(3).clone();
    let b = Float::from_f64(0.5).unwrap();
    let sum = &a + &b;
    assert_eq!(sum.prec(), 100);
    assert_eq!(
        sum.cmp(&Float::from_f64(3.5).unwrap()),
        std::cmp::Ordering::Equal
    );
    assert_eq!(
        (&a - &b).cmp(&Float::from_f64(2.5).unwrap()),
        std::cmp::Ordering::Equal
    );
    assert_eq!(
        (a.clone() * b.clone()).cmp(&Float::from_f64(1.5).unwrap()),
        std::cmp::Ordering::Equal
    );
    assert_eq!(
        (a / b).cmp(&Float::from_f64(6.0).unwrap()),
        std::cmp::Ordering::Equal
    );
    assert_eq!(
        (-&sum).cmp(&Float::from_f64(-3.5).unwrap()),
        std::cmp::Ordering::Equal
    );
    let pos = {
        let mut f = Float::new();
        f.set_inf(false);
        f
    };
    let neg = -&pos;
    assert!(pos.checked_add(&neg).is_err());
    assert!(std::panic::catch_unwind(|| &pos + &(-&pos)).is_err());
}
