//! crypto.Hash, SHA-3/SHAKE/cSHAKE, crypto/subtle and crypto/rand tests, ported
//! from Go's crypto, crypto/sha3, crypto/subtle and crypto/rand tests.

mod common;

use common::hex;
use rust_stdlib_crypto::hash::Hash as HashTrait;
use rust_stdlib_crypto::{rand, sha3, subtle, Hash};
use std::io::{Read, Write};

#[test]
fn hash_strings_sizes_and_availability() {
    let expected = [
        ("MD4", 16, false),
        ("MD5", 16, true),
        ("SHA-1", 20, true),
        ("SHA-224", 28, true),
        ("SHA-256", 32, true),
        ("SHA-384", 48, true),
        ("SHA-512", 64, true),
        ("MD5+SHA1", 36, false),
        ("RIPEMD-160", 20, false),
        ("SHA3-224", 28, true),
        ("SHA3-256", 32, true),
        ("SHA3-384", 48, true),
        ("SHA3-512", 64, true),
        ("SHA-512/224", 28, true),
        ("SHA-512/256", 32, true),
        ("BLAKE2s-256", 32, false),
        ("BLAKE2b-256", 32, false),
        ("BLAKE2b-384", 48, false),
        ("BLAKE2b-512", 64, false),
        ("ML-DSA \u{3bc} message representative", 64, false),
    ];
    assert_eq!(Hash::ALL.len(), expected.len());
    for (hash, (name, size, available)) in Hash::ALL.iter().zip(expected) {
        assert_eq!(hash.to_string(), name);
        assert_eq!(hash.size(), size, "{name}");
        assert_eq!(hash.available(), available, "{name}");
        assert_eq!(hash.hash_func(), *hash);
        if available {
            let digest = hash.new().unwrap();
            assert_eq!(digest.size(), size);
            assert_eq!(digest.crypto_hash(), Some(*hash));
        } else {
            let error = hash.new().err().unwrap();
            assert_eq!(error.hash(), *hash);
            assert!(error
                .to_string()
                .starts_with("crypto: requested hash function #"));
        }
    }
}

#[test]
fn sha3_known_answers() {
    assert_eq!(
        hex(&sha3::sum256(b"")),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    );
    assert_eq!(
        hex(&sha3::sum256(b"abc")),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    );
    assert_eq!(
        hex(&sha3::sum224(b"abc")),
        "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
    );
    assert_eq!(
        hex(&sha3::sum384(b"abc")),
        "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"
    );
    assert_eq!(
        hex(&sha3::sum512(b"abc")),
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
    );
    assert_eq!(
        hex(&sha3::sum_shake128(b"", 32)),
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
    );
    assert_eq!(
        hex(&sha3::sum_shake256(b"", 64)),
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
    );
}

#[test]
fn sha3_hash_surface_and_default() {
    let mut digest = sha3::new224();
    assert_eq!((digest.size(), digest.block_size()), (28, 144));
    digest.write_all(b"abc").unwrap();
    let mut first = Vec::new();
    digest.sum(&mut first);
    digest.reset();
    digest.write_all(b"abc").unwrap();
    let mut second = Vec::new();
    digest.sum(&mut second);
    assert_eq!(first, second);
    // Go's zero SHA3 is SHA3-256.
    assert_eq!(sha3::Sha3::default().size(), 32);
    let sizes = [
        (sha3::new256(), 136),
        (sha3::new384(), 104),
        (sha3::new512(), 72),
    ];
    for (digest, block) in sizes {
        assert_eq!(digest.block_size(), block);
    }
}

#[test]
fn sha3_marshal_round_trip_and_errors() {
    let mut digest = sha3::new256();
    digest.write_all(&[7u8; 300]).unwrap();
    let state = digest.marshal_binary();
    assert_eq!(state.len(), 4 + 1 + 200 + 2);
    assert_eq!(&state[..5], b"sha\x08\x88");
    let mut resumed = sha3::new256();
    resumed.unmarshal_binary(&state).unwrap();
    let mut a = Vec::new();
    let mut b = Vec::new();
    digest.sum(&mut a);
    resumed.sum(&mut b);
    assert_eq!(a, b);
    assert_eq!(
        sha3::new256()
            .unmarshal_binary(&state[1..])
            .unwrap_err()
            .message(),
        "sha3: invalid hash state"
    );
    let mut wrong_magic = state.clone();
    wrong_magic[0] = b'x';
    assert_eq!(
        sha3::new256()
            .unmarshal_binary(&wrong_magic)
            .unwrap_err()
            .message(),
        "sha3: invalid hash state identifier"
    );
    assert_eq!(
        sha3::new224()
            .unmarshal_binary(&state)
            .unwrap_err()
            .message(),
        "sha3: invalid hash state function"
    );
}

#[test]
fn shake_read_write_reset() {
    // Go's TestSqueezing/TestReset: output is independent of how it is read.
    let mut whole = sha3::shake128();
    whole.write_all(b"squeeze me").unwrap();
    let mut all = [0u8; 500];
    whole.read_exact(&mut all).unwrap();
    let mut pieces = sha3::shake128();
    pieces.write_all(b"squeeze me").unwrap();
    let mut joined = Vec::new();
    for size in [1, 7, 160, 168, 164] {
        let mut part = vec![0u8; size];
        pieces.read_exact(&mut part).unwrap();
        joined.extend(part);
    }
    assert_eq!(joined, all);
    assert_eq!(all.to_vec(), sha3::sum_shake128(b"squeeze me", 500));

    // Writing after reading is refused (Go panics "sha3: Write after Read").
    let error = pieces.write_all(b"more").unwrap_err();
    assert_eq!(error.to_string(), "sha3: Write after Read");
    pieces.reset();
    pieces.write_all(b"squeeze me").unwrap();
    let mut again = [0u8; 500];
    pieces.read_exact(&mut again).unwrap();
    assert_eq!(again, all);
    assert_eq!(
        (sha3::shake128().block_size(), sha3::shake256().block_size()),
        (168, 136)
    );
}

#[test]
fn cshake_with_empty_strings_is_shake_and_reset_keeps_strings() {
    assert_eq!(sha3::sum_shake256(b"data", 40), {
        let mut c = sha3::cshake256(b"", b"");
        c.write_all(b"data").unwrap();
        let mut out = vec![0; 40];
        c.read_exact(&mut out).unwrap();
        out
    });
    let mut custom = sha3::cshake128(b"N", b"S");
    custom.write_all(b"data").unwrap();
    let mut first = [0u8; 64];
    custom.read_exact(&mut first).unwrap();
    assert_ne!(first.to_vec(), sha3::sum_shake128(b"data", 64));
    custom.reset();
    custom.write_all(b"data").unwrap();
    let mut second = [0u8; 64];
    custom.read_exact(&mut second).unwrap();
    assert_eq!(first, second);
}

/// Go's testCSHAKEAccumulated: 120,000 cSHAKE instances folded into one digest,
/// checked against values generated by pycryptodome and noble-hashes.
fn cshake_accumulated(new: fn(&[u8], &[u8]) -> sha3::Shake, rate: usize, expected: &str) {
    fn copy_n(destination: &mut sha3::Shake, source: &mut sha3::Shake, count: usize) {
        let mut buffer = vec![0u8; count];
        source.read_exact(&mut buffer).unwrap();
        destination.write_all(&buffer).unwrap();
    }
    fn copy_out(accumulator: &mut sha3::Shake, source: &mut sha3::Shake, count: usize) {
        let mut buffer = vec![0u8; count];
        source.read_exact(&mut buffer).unwrap();
        accumulator.write_all(&buffer).unwrap();
    }
    let mut rnd = new(b"", b"");
    let mut acc = new(b"", b"");
    for n in 0..200 {
        let mut name = vec![0u8; n];
        rnd.read_exact(&mut name).unwrap();
        for s in 0..200 {
            let mut custom = vec![0u8; s];
            rnd.read_exact(&mut custom).unwrap();
            let mut c = new(&name, &custom);
            copy_n(&mut c, &mut rnd, 100);
            copy_out(&mut acc, &mut c, 200);
            c.reset();
            copy_n(&mut c, &mut rnd, rate);
            copy_out(&mut acc, &mut c, 200);
            c.reset();
            copy_n(&mut c, &mut rnd, 200);
            copy_out(&mut acc, &mut c, 200);
        }
    }
    let mut out = [0u8; 32];
    acc.read_exact(&mut out).unwrap();
    assert_eq!(hex(&out), expected);
}

#[test]
fn cshake128_accumulated() {
    cshake_accumulated(
        sha3::cshake128,
        (1600 - 256) / 8,
        "bb14f8657c6ec5403d0b0e2ef3d3393497e9d3b1a9a9e8e6c81dbaa5fd809252",
    );
}

#[test]
fn cshake256_accumulated() {
    cshake_accumulated(
        sha3::cshake256,
        (1600 - 512) / 8,
        "0baaf9250c6e25f0c14ea5c7f9bfde54c8a922c8276437db28f3895bdf6eeeef",
    );
}

#[test]
fn subtle_tables() {
    // Go's constant_time_test.go tables.
    let compare: [(&[u8], &[u8], i32); 5] = [
        (&[], &[], 1),
        (&[0x11], &[0x11], 1),
        (&[0x12], &[0x11], 0),
        (&[0x11], &[0x11, 0x12], 0),
        (&[0x11, 0x12], &[0x11], 0),
    ];
    for (a, b, out) in compare {
        assert_eq!(subtle::constant_time_compare(a, b), out);
    }
    for (x, y, result) in [
        (0, 0, 1),
        (1, 0, 0),
        (0, 1, 1),
        (10, 20, 1),
        (20, 10, 0),
        (10, 10, 1),
    ] {
        assert_eq!(subtle::constant_time_less_or_eq(x, y), result, "{x} <= {y}");
    }
    assert_eq!(subtle::constant_time_byte_eq(0xaa, 0xaa), 1);
    assert_eq!(subtle::constant_time_byte_eq(0xaa, 0xab), 0);
    assert_eq!(subtle::constant_time_eq(-1, -1), 1);
    assert_eq!(subtle::constant_time_eq(i32::MAX, i32::MIN), 0);
    assert_eq!(subtle::constant_time_select(1, 17, 23), 17);
    assert_eq!(subtle::constant_time_select(0, 17, 23), 23);

    let mut target = [1u8, 2, 3];
    subtle::constant_time_copy(0, &mut target, &[9, 9, 9]);
    assert_eq!(target, [1, 2, 3]);
    subtle::constant_time_copy(1, &mut target, &[9, 8, 7]);
    assert_eq!(target, [9, 8, 7]);
}

#[test]
fn subtle_xor_bytes() {
    let mut dst = [0u8; 8];
    assert_eq!(subtle::xor_bytes(&mut dst, &[1, 2, 3, 4], &[0xff, 0xff]), 2);
    assert_eq!(dst, [0xfe, 0xfd, 0, 0, 0, 0, 0, 0]);
    assert_eq!(subtle::xor_bytes(&mut dst, &[], &[1]), 0);
}

#[test]
#[should_panic(expected = "subtle.XORBytes: dst too short")]
fn subtle_xor_bytes_panics_on_short_destination() {
    subtle::xor_bytes(&mut [0u8; 1], &[1, 2], &[3, 4]);
}

#[test]
#[should_panic(expected = "subtle: slices have different lengths")]
fn subtle_copy_panics_on_length_mismatch() {
    subtle::constant_time_copy(1, &mut [0u8; 2], &[1]);
}

#[test]
fn subtle_with_data_independent_timing_runs_the_function() {
    let mut ran = false;
    subtle::with_data_independent_timing(|| ran = true);
    assert!(ran);
}

#[test]
fn rand_reads_fill_the_buffer() {
    let mut buffer = [0u8; 4096];
    assert_eq!(rand::read(&mut buffer), 4096);
    assert!(
        buffer.iter().any(|&byte| byte != 0),
        "4096 zero bytes would be astronomically unlikely"
    );
    let mut reader = rand::Reader;
    let mut other = [0u8; 4096];
    reader.read_exact(&mut other).unwrap();
    assert_ne!(buffer, other);
    assert_eq!(rand::read(&mut []), 0);
}

#[test]
fn rand_text_uses_the_base32_alphabet() {
    // Go's TestText: 26 characters over A-Z2-7, with all symbols eventually seen.
    let mut seen = std::collections::HashSet::new();
    for _ in 0..200 {
        let text = rand::text();
        assert_eq!(text.len(), 26);
        assert!(
            text.bytes()
                .all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte)),
            "{text}"
        );
        seen.extend(text.chars());
    }
    assert_eq!(seen.len(), 32);
}

/// Go's `io.Copy(h, r)`: every hash state is a `std::io::Write`.
#[test]
fn io_copy_into_hash_states_matches_one_shot() {
    use rust_stdlib_crypto::{hmac, md5, sha1, sha256, sha512};
    let data: Vec<u8> = (0..100_000u32).map(|i| (i * 31 + i / 7) as u8).collect();
    fn copied<H: HashTrait>(mut h: H, data: &[u8]) -> Vec<u8> {
        let n = std::io::copy(&mut &data[..], &mut h).unwrap();
        assert_eq!(n, data.len() as u64);
        let mut out = Vec::new();
        h.sum(&mut out);
        out
    }
    assert_eq!(copied(md5::new(), &data), md5::sum(&data));
    assert_eq!(copied(sha1::new(), &data), sha1::sum(&data));
    assert_eq!(copied(sha256::new(), &data), sha256::sum256(&data));
    assert_eq!(copied(sha256::new224(), &data), sha256::sum224(&data));
    assert_eq!(copied(sha512::new(), &data), sha512::sum512(&data));
    assert_eq!(copied(sha512::new384(), &data), sha512::sum384(&data));
    assert_eq!(
        copied(sha512::new512_224(), &data),
        sha512::sum512_224(&data)
    );
    assert_eq!(
        copied(sha512::new512_256(), &data),
        sha512::sum512_256(&data)
    );
    assert_eq!(copied(sha3::new224(), &data), sha3::sum224(&data));
    assert_eq!(copied(sha3::new256(), &data), sha3::sum256(&data));
    assert_eq!(copied(sha3::new384(), &data), sha3::sum384(&data));
    assert_eq!(copied(sha3::new512(), &data), sha3::sum512(&data));

    // HMAC, and a boxed `Hash` trait object.
    let key = b"key";
    let mut one = hmac::new(sha256::new, key).unwrap();
    one.write_all(&data).unwrap();
    let mut want = Vec::new();
    one.sum(&mut want);
    assert_eq!(copied(hmac::new(sha256::new, key).unwrap(), &data), want);
    let boxed: Box<dyn HashTrait> = Box::new(sha256::new());
    assert_eq!(copied(boxed, &data), sha256::sum256(&data));
    let mut dynamic: Box<dyn HashTrait> = Box::new(sha1::new());
    std::io::copy(&mut &data[..], &mut dynamic).unwrap();
    let mut out = Vec::new();
    dynamic.sum(&mut out);
    assert_eq!(out, sha1::sum(&data));

    // SHAKE (and cSHAKE) read their output after the copy.
    for (mut x, want) in [
        (sha3::shake128(), sha3::sum_shake128(&data, 40)),
        (sha3::shake256(), sha3::sum_shake256(&data, 40)),
        (sha3::cshake128(b"N", b"S"), {
            let mut r = sha3::cshake128(b"N", b"S");
            r.write_all(&data).unwrap();
            let mut o = vec![0; 40];
            r.read_exact(&mut o).unwrap();
            o
        }),
    ] {
        std::io::copy(&mut &data[..], &mut x).unwrap();
        let mut got = vec![0; 40];
        x.read_exact(&mut got).unwrap();
        assert_eq!(got, want);
    }
}
