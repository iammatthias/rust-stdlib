//! crypto/rand.Int and rand.Prime, ported from Go's util_test.go.

use rust_stdlib_crypto::bigint::Int;
use rust_stdlib_crypto::rand;
use std::io::Cursor;

#[test]
fn int_edge_cases() {
    for max in [1u64, 2, 3, 255, 256, 257, 1 << 32] {
        let max = Int::from_u64(max);
        for _ in 0..200 {
            let n = rand::int(&max).unwrap();
            assert!(n < max);
        }
    }
    assert_eq!(rand::int(&Int::from_u64(1)).unwrap(), Int::zero());
}

#[test]
#[should_panic(expected = "argument to Int is <= 0")]
fn int_rejects_zero() {
    let _ = rand::int(&Int::zero());
}

#[test]
fn int_reads_like_go() {
    // max = 300: limit 299 has 9 bits, so two bytes are read per attempt and
    // the top byte is masked to one bit. 0x01 0x2c = 300 is rejected.
    let mut reader = Cursor::new(vec![0xff, 0x2c, 0x00, 0x07]);
    let n = rand::int_with_rng(&mut reader, &Int::from_u64(300)).unwrap();
    assert_eq!(n, Int::from_u64(7));
    assert_eq!(reader.position(), 4);
    // A failing reader reports the error.
    let mut empty = Cursor::new(Vec::new());
    assert!(rand::int_with_rng(&mut empty, &Int::from_u64(300)).is_err());
}

#[test]
fn prime_has_requested_size() {
    for bits in [2usize, 3, 8, 9, 16, 64, 128, 200] {
        let p = rand::prime(bits).unwrap();
        assert_eq!(p.bit_len(), bits, "{bits}");
        assert_eq!(p.bit(0), 1);
        if bits >= 3 {
            assert_eq!(p.bit(bits - 2), 1, "{bits}: top two bits set");
        }
    }
    // Small primes are found among their only candidates.
    let p = rand::prime(2).unwrap().to_u64().unwrap();
    assert!(p == 2 || p == 3);
}

#[test]
fn prime_rejects_tiny_sizes() {
    for bits in [0usize, 1] {
        assert_eq!(
            rand::prime(bits).unwrap_err().to_string(),
            "crypto/rand: prime size must be at least 2-bit"
        );
    }
}
