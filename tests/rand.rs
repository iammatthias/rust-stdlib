//! math/rand and math/rand/v2 against Go's own golden vectors.
use rust_stdlib::math::rand::{self, v1, ChaCha8, Pcg, Rand, Source};
use std::io::Read;

/// A golden value as written in Go's regress tests (floats as IEEE bits).
#[derive(Debug)]
enum G {
    F64(u64),
    F32(u32),
    I64(i64),
    U64(u64),
    Ints(&'static [u64]),
    Bytes(&'static [u8]),
}

include!("fixtures/rand_golden.rs");

#[derive(Debug, PartialEq)]
enum Out {
    F64(u64),
    F32(u32),
    I64(i64),
    U64(u64),
    List(Vec<u64>),
}

impl From<&G> for Out {
    fn from(value: &G) -> Self {
        match value {
            G::F64(bits) => Out::F64(*bits),
            G::F32(bits) => Out::F32(*bits),
            G::I64(v) => Out::I64(*v),
            G::U64(v) => Out::U64(*v),
            G::Ints(v) => Out::List(v.to_vec()),
            G::Bytes(v) => Out::List(v.iter().map(|&b| u64::from(b)).collect()),
        }
    }
}

fn list(values: Vec<usize>) -> Out {
    Out::List(values.into_iter().map(|v| v as u64).collect())
}

fn call_v2(r: &mut Rand<Pcg>, method: &str, arg: u64) -> Out {
    match method {
        "ExpFloat64" => Out::F64(r.exp_float64().to_bits()),
        "NormFloat64" => Out::F64(r.norm_float64().to_bits()),
        "Float64" => Out::F64(r.float64().to_bits()),
        "Float32" => Out::F32(r.float32().to_bits()),
        "Int" => Out::I64(r.int()),
        "Int32" => Out::I64(r.int32().into()),
        "Int64" => Out::I64(r.int64()),
        "Int32N" => Out::I64(r.int32_n(arg as i32).into()),
        "Int64N" => Out::I64(r.int64_n(arg as i64)),
        "IntN" => Out::I64(r.int_n(arg as i64)),
        "Uint" => Out::U64(r.uint()),
        "Uint32" => Out::U64(r.uint32().into()),
        "Uint64" => Out::U64(r.uint64()),
        "Uint32N" => Out::U64(r.uint32_n(arg as u32).into()),
        "Uint64N" => Out::U64(r.uint64_n(arg)),
        "UintN" => Out::U64(r.uint_n(arg)),
        "Perm" => list(r.perm(arg as usize)),
        other => panic!("unexpected v2 golden method {other}"),
    }
}

fn call_v1(r: &mut v1::Rand<v1::RngSource>, method: &str, arg: u64) -> Out {
    match method {
        "ExpFloat64" => Out::F64(r.exp_float64().to_bits()),
        "NormFloat64" => Out::F64(r.norm_float64().to_bits()),
        "Float64" => Out::F64(r.float64().to_bits()),
        "Float32" => Out::F32(r.float32().to_bits()),
        "Int" => Out::I64(r.int()),
        "Int31" => Out::I64(r.int31().into()),
        "Int63" => Out::I64(r.int63()),
        "Int31n" => Out::I64(r.int31n(arg as i32).into()),
        "Int63n" => Out::I64(r.int63n(arg as i64)),
        "Intn" => Out::I64(r.intn(arg as i64)),
        "Uint32" => Out::U64(r.uint32().into()),
        "Uint64" => Out::U64(r.uint64()),
        "Perm" => list(r.perm(arg as usize)),
        "Read" => {
            let mut buf = vec![0u8; arg as usize];
            assert_eq!(r.read(&mut buf).unwrap(), buf.len());
            Out::List(buf.into_iter().map(u64::from).collect())
        }
        other => panic!("unexpected v1 golden method {other}"),
    }
}

#[test]
fn v2_regress_golden() {
    assert_eq!(V2_REGRESS.len(), 17 * 20);
    let mut current = "";
    let mut r = Rand::new(Pcg::new(1, 2));
    for (index, (method, arg, want)) in V2_REGRESS.iter().enumerate() {
        if *method != current {
            current = method;
            r = Rand::new(Pcg::new(1, 2));
        }
        let got = call_v2(&mut r, method, *arg);
        assert_eq!(got, Out::from(want), "#{index} {method}({arg})");
    }
}

#[test]
fn v1_regress_golden() {
    assert_eq!(V1_REGRESS.len(), 14 * 20);
    let mut current = "";
    let mut r = v1::Rand::new(v1::RngSource::new(0));
    for (index, (method, arg, want)) in V1_REGRESS.iter().enumerate() {
        if *method != current {
            current = method;
            r.seed(0);
        }
        let got = call_v1(&mut r, method, *arg);
        assert_eq!(got, Out::from(want), "#{index} {method}({arg})");
    }
}

#[test]
fn pcg_golden_and_marshal() {
    let mut p = Pcg::new(1, 2);
    for want in PCG_OUTPUT {
        assert_eq!(p.uint64(), want);
    }

    let mut p = Pcg::default();
    p.seed(0x123456789abcdef0, 0xfedcba9876543210);
    let want = b"pcg:\x12\x34\x56\x78\x9a\xbc\xde\xf0\xfe\xdc\xba\x98\x76\x54\x32\x10";
    assert_eq!(p.marshal_binary(), want);
    assert_eq!(p.append_binary(vec![0; 4])[4..], want[..]);
    let mut q = Pcg::default();
    q.unmarshal_binary(want).unwrap();
    assert_eq!(q, p);
    assert_eq!(q.uint64(), p.uint64());

    for bad in [
        &b""[..],
        b"pcg:",
        &want[..19],
        b"PCG:\x12\x34\x56\x78\x9a\xbc\xde\xf0\xfe\xdc\xba\x98\x76\x54\x32\x10",
    ] {
        let before = q;
        let err = q.unmarshal_binary(bad).unwrap_err();
        assert_eq!(err.to_string(), "invalid PCG encoding");
        assert_eq!(q, before);
    }
    let mut long = want.to_vec();
    long.push(0);
    assert!(q.unmarshal_binary(&long).is_err());
}

#[test]
fn chacha8_golden_output_and_reseed() {
    let mut p = ChaCha8::new(CHACHA8_SEED);
    for (i, want) in CHACHA8_OUTPUT.iter().enumerate() {
        assert_eq!(p.uint64(), *want, "#{i}");
    }
    p.seed(CHACHA8_SEED);
    for want in CHACHA8_OUTPUT {
        assert_eq!(p.uint64(), want);
    }
}

fn golden_bytes() -> Vec<u8> {
    let bytes: Vec<u8> = CHACHA8_OUTPUT
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();
    assert_eq!(bytes.len(), CHACHA8_OUTLEN);
    bytes
}

#[test]
fn chacha8_read_streams() {
    let want = golden_bytes();
    let mut p = ChaCha8::new(CHACHA8_SEED);
    let mut buf = vec![0; CHACHA8_OUTLEN];
    assert_eq!(p.read(&mut buf).unwrap(), CHACHA8_OUTLEN);
    assert_eq!(buf, want);

    // One-byte reads.
    p.seed(CHACHA8_SEED);
    let mut one = Vec::new();
    for _ in 0..CHACHA8_OUTLEN {
        let mut b = [0u8; 1];
        assert_eq!(p.read(&mut b).unwrap(), 1);
        one.push(b[0]);
    }
    assert_eq!(one, want);

    // Irregular reads interleaved with marshal round trips into fresh states.
    p.seed(CHACHA8_SEED);
    assert_eq!(p.read(&mut []).unwrap(), 0);
    let mut sizes = Pcg::new(7, 8);
    let mut out = Vec::new();
    while out.len() < CHACHA8_OUTLEN {
        if sizes.uint64() & 1 == 0 {
            let enc = p.marshal_binary();
            if sizes.uint64() & 1 == 0 {
                p = ChaCha8::new([0; 32]);
            }
            p.unmarshal_binary(&enc).unwrap();
        }
        let len = ((sizes.uint64() % 100) as usize).min(CHACHA8_OUTLEN - out.len());
        let mut buf = vec![0; len];
        assert_eq!(p.read(&mut buf).unwrap(), len);
        out.extend_from_slice(&buf);
    }
    assert_eq!(out, want);
}

#[test]
fn chacha8_marshal_golden() {
    let mut p = ChaCha8::new(CHACHA8_SEED);
    for (i, want) in CHACHA8_OUTPUT.iter().enumerate() {
        let enc = p.marshal_binary();
        assert_eq!(enc, CHACHA8_MARSHAL[i], "#{i}");
        assert_eq!(p.append_binary(vec![0; 4])[4..], enc[..]);
        p = ChaCha8::new([0; 32]);
        p.unmarshal_binary(&enc).unwrap();
        assert_eq!(p.uint64(), *want, "#{i}");
    }

    let mut p = ChaCha8::new(CHACHA8_SEED);
    for (i, want) in CHACHA8_MARSHAL_READ.iter().enumerate() {
        let enc = p.marshal_binary();
        assert_eq!(enc, *want, "#{i}");
        p = ChaCha8::new([0; 32]);
        p.unmarshal_binary(&enc).unwrap();
        assert_eq!(p.read(&mut [0u8; 1]).unwrap(), 1);
    }
}

#[test]
fn chacha8_unmarshal_rejects_malformed() {
    let good = ChaCha8::new(CHACHA8_SEED).marshal_binary();
    let mut p = ChaCha8::new([9; 32]);
    let before = p.clone();
    let mut bad_used = good.clone();
    bad_used[15] = 125; // more than 124 values used in a 16-block cycle
    let mut too_long = b"readbuf:\x09".to_vec();
    too_long.extend_from_slice(&[0; 9]);
    too_long.extend_from_slice(&good);
    for bad in [
        &b""[..],
        &good[..47],
        &bad_used,
        b"readbuf:",
        b"readbuf:\x03ab",
        &too_long,
        b"Chacha8:\x00\x00\x00\x00\x00\x00\x00\x00ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
    ] {
        assert!(p.unmarshal_binary(bad).is_err(), "{bad:?}");
        assert_eq!(p, before);
    }
    // The last allowed position resumes across the reseed boundary.
    let mut edge = good.clone();
    edge[15] = 124;
    p.unmarshal_binary(&edge).unwrap();
    let mut q = ChaCha8::new(CHACHA8_SEED);
    for _ in 0..124 {
        q.uint64();
    }
    assert_eq!(p.uint64(), q.uint64());
    assert_eq!(p.uint64(), CHACHA8_OUTPUT[125]);
    assert!(format!("{p:?}").starts_with("ChaCha8"));
}

#[test]
fn v1_read_semantics_and_seed_reset() {
    let mut r = v1::Rand::new(v1::RngSource::new(42));
    let mut a = [0u8; 10];
    assert_eq!(r.read(&mut a).unwrap(), 10);
    let mut s = v1::RngSource::new(42);
    let first = v1::Source::int63(&mut s);
    let second = v1::Source::int63(&mut s);
    let mut want = first.to_le_bytes()[..7].to_vec();
    want.extend_from_slice(&second.to_le_bytes()[..3]);
    assert_eq!(&a[..], &want[..]);
    // Seed discards the 4 buffered bytes.
    r.seed(42);
    let mut b = [0u8; 7];
    assert_eq!(r.read(&mut b).unwrap(), 7);
    assert_eq!(&b[..], &first.to_le_bytes()[..7]);
}

#[test]
fn v1_known_values_and_custom_source() {
    let mut r = v1::Rand::new(v1::RngSource::new(1));
    assert_eq!(r.int63(), 5577006791947779410);
    // Negative, zero and large seeds follow Go's reduction modulo 2^31-1.
    let mut zero = v1::RngSource::new(0);
    let mut magic = v1::RngSource::new(89482311);
    let mut wrapped = v1::RngSource::new((1 << 31) - 1);
    for _ in 0..1000 {
        let z = v1::Source::uint64(&mut zero);
        assert_eq!(z, v1::Source::uint64(&mut magic));
        assert_eq!(z, v1::Source::uint64(&mut wrapped));
    }

    /// A non-Source64 source: Uint64 composes two Int63 values.
    struct Fixed(Vec<i64>);
    impl v1::Source for Fixed {
        fn int63(&mut self) -> i64 {
            self.0.remove(0)
        }
        fn seed(&mut self, _seed: i64) {}
    }
    let (a, b) = (0x7fff_ffff_8000_0001u64, 0x1234_5678_9abc_def0u64);
    let mut c = v1::Rand::new(Fixed(vec![a as i64, b as i64]));
    assert_eq!(c.uint64(), (a >> 31) | (b << 32));
}

#[test]
fn bounds_and_panics() {
    let mut r = Rand::new(Pcg::new(3, 4));
    for _ in 0..1000 {
        assert!(r.int_n(7) < 7);
        assert_eq!(r.uint64_n(1), 0);
        assert!(r.float64() < 1.0);
        assert!(r.float32() < 1.0);
        assert!(r.n(250u8) < 250);
        assert!((0..3).contains(&r.n(3i16)));
    }
    assert_eq!(r.perm(0), Vec::<usize>::new());
    let mut p = r.perm(50);
    p.sort_unstable();
    assert_eq!(p, (0..50).collect::<Vec<_>>());
    for result in [
        std::panic::catch_unwind(|| Rand::new(Pcg::new(0, 0)).int_n(0)),
        std::panic::catch_unwind(|| Rand::new(Pcg::new(0, 0)).int64_n(-1)),
        std::panic::catch_unwind(|| v1::Rand::new(v1::RngSource::new(1)).intn(0)),
    ] {
        assert!(result.is_err());
    }
    assert!(std::panic::catch_unwind(|| Rand::new(Pcg::new(0, 0)).n(0u32)).is_err());
    assert!(std::panic::catch_unwind(|| v1::Rand::new(v1::RngSource::new(1)).int31n(-5)).is_err());
}

#[test]
fn unseeded_top_level_functions() {
    // The thread-local generator is OS seeded: values are in range and two
    // threads do not share a stream.
    assert!(rand::int_n(10) < 10);
    assert!(rand::float64() < 1.0);
    assert!(rand::n(rust_stdlib::time::Duration::from_nanos(5)).as_nanos() < 5);
    let mut p = rand::perm(20);
    p.sort_unstable();
    assert_eq!(p, (0..20).collect::<Vec<_>>());
    let mut v: Vec<usize> = (0..10).collect();
    // Reentrant use from inside the swap closure must not panic.
    rand::shuffle(10, |i, j| {
        let _ = rand::uint64();
        v.swap(i, j);
    });
    let mut bytes = [0u8; 13];
    assert_eq!(v1::read(&mut bytes).unwrap(), 13);
    assert!(v1::intn(1 << 40) < 1 << 40);
    let here: Vec<u64> = (0..4).map(|_| rand::uint64()).collect();
    let there = std::thread::spawn(|| (0..4).map(|_| rand::uint64()).collect::<Vec<u64>>())
        .join()
        .unwrap();
    assert_ne!(here, there);
    let mut global = Rand::new(rand::GlobalSource);
    assert!(global.norm_float64().is_finite());
    assert!(global.exp_float64() >= 0.0);
}

#[test]
fn zipf_matches_go_seeded_output() {
    // Values from Go 1.27 (tools/rand_oracle.go) for the same seeds.
    let mut r = v1::Rand::new(v1::RngSource::new(42));
    let mut z = v1::Zipf::new(&mut r, 1.5, 1.0, 100).expect("valid parameters");
    let got: Vec<u64> = (0..6).map(|_| z.uint64()).collect();
    assert_eq!(got, [2, 30, 0, 7, 42, 2]);

    let mut r = Rand::new(Pcg::new(1, 2));
    let mut z = rand::Zipf::new(&mut r, 1.1, 2.7, 1000).expect("valid parameters");
    let got: Vec<u64> = (0..6).map(|_| z.uint64()).collect();
    assert_eq!(got, [8, 35, 26, 43, 3, 56]);
}

#[test]
fn zipf_rejects_invalid_parameters() {
    // Go's NewZipf returns nil when s <= 1 or v < 1.
    let mut r = Rand::new(Pcg::new(1, 2));
    assert!(rand::Zipf::new(&mut r, 1.0, 1.0, 5).is_none());
    assert!(rand::Zipf::new(&mut r, 0.5, 1.0, 5).is_none());
    assert!(rand::Zipf::new(&mut r, 2.0, 0.5, 5).is_none());
    let mut v1r = v1::Rand::new(v1::RngSource::new(42));
    assert!(v1::Zipf::new(&mut v1r, 1.0, 1.0, 5).is_none());
    assert!(v1::Zipf::new(&mut v1r, 2.0, 0.5, 5).is_none());
    // Every value stays within [0, imax].
    let mut z = rand::Zipf::new(&mut r, 1.5, 1.0, 10).expect("valid parameters");
    assert!((0..1000).all(|_| z.uint64() <= 10));
}
