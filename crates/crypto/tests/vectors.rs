//! Known-answer tests ported from Go's crypto test tables: digests (with
//! Go-format marshaled state), HMAC (FIPS 198, RFC 2202/4231), HKDF (RFC 5869)
//! and PBKDF2 (RFC 6070 and the SHA-256 companion vectors).

mod common;

use common::{boxed, check_golden, fixture, hex, Digest};
use rust_stdlib_crypto::hash::Hash as HashTrait;
use rust_stdlib_crypto::{hkdf, hmac, md5, pbkdf2, sha1, sha256, sha512, Hash};
use std::io::Write;

fn vec_of<const N: usize>(array: [u8; N]) -> Vec<u8> {
    array.to_vec()
}

#[test]
fn md5_golden() {
    check_golden(
        fixture("md5.tsv"),
        || boxed(md5::new()),
        |data| vec_of(md5::sum(data)),
    );
}

#[test]
fn sha1_golden() {
    check_golden(
        fixture("sha1.tsv"),
        || boxed(sha1::new()),
        |data| vec_of(sha1::sum(data)),
    );
}

#[test]
fn sha256_golden() {
    check_golden(
        fixture("sha256.tsv"),
        || boxed(sha256::new()),
        |data| vec_of(sha256::sum256(data)),
    );
    check_golden(
        fixture("sha224.tsv"),
        || boxed(sha256::new224()),
        |data| vec_of(sha256::sum224(data)),
    );
}

#[test]
fn sha512_golden() {
    check_golden(
        fixture("sha512.tsv"),
        || boxed(sha512::new()),
        |data| vec_of(sha512::sum512(data)),
    );
    check_golden(
        fixture("sha384.tsv"),
        || boxed(sha512::new384()),
        |data| vec_of(sha512::sum384(data)),
    );
    check_golden(
        fixture("sha512_224.tsv"),
        || boxed(sha512::new512_224()),
        |data| vec_of(sha512::sum512_224(data)),
    );
    check_golden(
        fixture("sha512_256.tsv"),
        || boxed(sha512::new512_256()),
        |data| vec_of(sha512::sum512_256(data)),
    );
}

#[test]
fn sizes_and_block_sizes() {
    let cases: Vec<(Box<dyn Digest>, usize, usize)> = vec![
        (boxed(md5::new()), md5::SIZE, md5::BLOCK_SIZE),
        (boxed(sha1::new()), sha1::SIZE, sha1::BLOCK_SIZE),
        (boxed(sha256::new()), sha256::SIZE, sha256::BLOCK_SIZE),
        (boxed(sha256::new224()), sha256::SIZE224, sha256::BLOCK_SIZE),
        (boxed(sha512::new()), sha512::SIZE, sha512::BLOCK_SIZE),
        (boxed(sha512::new384()), sha512::SIZE384, sha512::BLOCK_SIZE),
        (
            boxed(sha512::new512_224()),
            sha512::SIZE224,
            sha512::BLOCK_SIZE,
        ),
        (
            boxed(sha512::new512_256()),
            sha512::SIZE256,
            sha512::BLOCK_SIZE,
        ),
    ];
    for (digest, size, block) in cases {
        assert_eq!((digest.size(), digest.block_size()), (size, block));
        let mut sum = Vec::new();
        digest.sum(&mut sum);
        assert_eq!(sum.len(), size);
    }
}

#[test]
fn clone_is_independent() {
    let mut original = sha256::new();
    original.write_all(b"abc").unwrap();
    let mut copy = original.clone_hash();
    copy.write_all(b"def").unwrap();
    let mut a = Vec::new();
    original.sum(&mut a);
    assert_eq!(hex(&a), hex(&sha256::sum256(b"abc")));
    let mut b = Vec::new();
    copy.sum(&mut b);
    assert_eq!(hex(&b), hex(&sha256::sum256(b"abcdef")));
}

#[test]
fn marshal_rejects_other_hash_state() {
    // Go's TestMarshalTypeMismatch: a state is only valid for its own function.
    let mut sha256_state = sha256::new();
    sha256_state.write_all(b"x").unwrap();
    let state = sha256_state.marshal_binary();
    assert_eq!(
        sha256::new224()
            .unmarshal_binary(&state)
            .unwrap_err()
            .message(),
        "crypto/sha256: invalid hash state identifier"
    );
    assert_eq!(
        sha256::new()
            .unmarshal_binary(&state[..state.len() - 1])
            .unwrap_err()
            .message(),
        "crypto/sha256: invalid hash state size"
    );
    assert_eq!(
        sha512::new().unmarshal_binary(&[]).unwrap_err().message(),
        "crypto/sha512: invalid hash state identifier"
    );
    assert_eq!(
        md5::new()
            .unmarshal_binary(b"md5\x01")
            .unwrap_err()
            .message(),
        "crypto/md5: invalid hash state size"
    );
    assert_eq!(
        sha1::new()
            .unmarshal_binary(&md5::new().marshal_binary())
            .unwrap_err()
            .message(),
        "crypto/sha1: invalid hash state identifier"
    );
    for (write, make) in [
        (
            sha512::new384 as fn() -> sha512::Digest,
            sha512::new as fn() -> sha512::Digest,
        ),
        (sha512::new512_224, sha512::new512_256),
    ] {
        let state = write().marshal_binary();
        assert!(make().unmarshal_binary(&state).is_err());
    }
}

#[test]
fn append_binary_appends() {
    let mut digest = sha1::new();
    digest.update(b"hello");
    let mut out = vec![1, 2, 3];
    digest.append_binary(&mut out);
    assert_eq!(&out[..3], &[1, 2, 3]);
    assert_eq!(out[3..], digest.marshal_binary());
}

fn hash_for(name: &str) -> Hash {
    match name {
        "md5.New" => Hash::Md5,
        "sha1.New" => Hash::Sha1,
        "sha256.New" => Hash::Sha256,
        "sha256.New224" => Hash::Sha224,
        "sha512.New" => Hash::Sha512,
        "sha512.New384" => Hash::Sha384,
        other => panic!("unmapped hash constructor {other}"),
    }
}

#[test]
fn hmac_vectors() {
    let rows = fixture("hmac.tsv");
    assert_eq!(rows.len(), 28);
    for (index, row) in rows.iter().enumerate() {
        let algorithm = hash_for(row[0].name());
        let (key, input, expected) = (row[1].bytes(), row[2].bytes(), row[3].hex_text());
        let (size, block_size) = (
            algorithm.new().unwrap().size(),
            algorithm.new().unwrap().block_size(),
        );
        let mut mac = hmac::new(|| algorithm.new().unwrap(), &key).unwrap();
        assert_eq!(
            (mac.size(), mac.block_size()),
            (size, block_size),
            "row {index}"
        );
        for pass in 0..2 {
            mac.reset();
            // Write twice, as Go's TestHMAC does, to exercise Reset and Sum idempotence.
            for chunk in input.chunks(input.len().max(2) / 2) {
                mac.write_all(chunk).unwrap();
            }
            for _ in 0..2 {
                let mut tag = Vec::new();
                mac.sum(&mut tag);
                assert_eq!(hex(&tag), expected, "row {index} pass {pass}");
            }
        }
    }
}

#[test]
fn hmac_accepts_this_crates_hashes_as_constructors() {
    let tag = |mac: &mut hmac::Hmac| {
        mac.write_all(b"data").unwrap();
        let mut out = Vec::new();
        mac.sum(&mut out);
        out
    };
    let by_constructor = tag(&mut hmac::new(sha256::new, b"key").unwrap());
    let by_identifier = tag(&mut hmac::Hmac::new(Hash::Sha256, b"key").unwrap());
    let by_box = tag(&mut hmac::new(|| Hash::Sha256.new().unwrap(), b"key").unwrap());
    assert_eq!(by_constructor, by_identifier);
    assert_eq!(by_constructor, by_box);
    // A hash this crate does not implement cannot key an HMAC.
    assert!(hmac::Hmac::new(Hash::Md4, b"key").is_err());
}

#[test]
fn hmac_equal() {
    assert!(hmac::equal(b"abc", b"abc"));
    assert!(!hmac::equal(b"abc", b"abd"));
    assert!(!hmac::equal(b"abc", b"abcd"));
    assert!(hmac::equal(b"", b""));
}

#[test]
fn hkdf_rfc5869() {
    let rows = fixture("hkdf.tsv");
    assert_eq!(rows.len(), 8);
    for (index, row) in rows.iter().enumerate() {
        let algorithm = hash_for(row[0].name());
        let (master, salt, prk, info, out) = (
            row[1].bytes(),
            row[2].bytes(),
            row[3].bytes(),
            row[4].bytes(),
            row[5].bytes(),
        );
        let make = || algorithm.new().unwrap();
        assert_eq!(
            hkdf::extract(make, &master, &salt).unwrap(),
            prk,
            "extract {index}"
        );
        assert_eq!(
            hkdf::expand(make, &prk, &info, out.len()).unwrap(),
            out,
            "expand {index}"
        );
        assert_eq!(
            hkdf::key(make, &master, &salt, &info, out.len()).unwrap(),
            out,
            "key {index}"
        );
    }
}

#[test]
fn hkdf_limits_and_short_keys() {
    // Go's TestHKDFLimit: 255 * HashLen is allowed, one more byte is not.
    let make = || Hash::Sha256.new().unwrap();
    let limit = 255 * 32;
    assert_eq!(
        hkdf::key(make, b"secret", b"salt", "info", limit)
            .unwrap()
            .len(),
        limit
    );
    let error = hkdf::key(make, b"secret", b"salt", "info", limit + 1).unwrap_err();
    assert_eq!(error, hkdf::Error::KeyLengthTooLarge);
    assert_eq!(error.to_string(), "hkdf: requested key length too large");
    assert_eq!(
        hkdf::expand(make, b"secret", "", limit + 1).unwrap_err(),
        hkdf::Error::KeyLengthTooLarge
    );
    assert!(hkdf::expand(make, b"short", "", 0).unwrap().is_empty());
    assert!(hkdf::extract(|| Hash::Sha1.new().unwrap(), b"", b"").is_ok());
}

#[test]
fn pbkdf2_rfc6070() {
    for (file, algorithm) in [
        ("pbkdf2_sha1.tsv", Hash::Sha1),
        ("pbkdf2_sha256.tsv", Hash::Sha256),
    ] {
        for row in fixture(file) {
            let (password, salt, iterations, expected) =
                (row[0].bytes(), row[1].bytes(), row[2].int(), row[3].bytes());
            // The tables include 16 million rounds; the default gate skips the slow tail.
            if iterations > 100_000 {
                continue;
            }
            let derived = pbkdf2::key(
                || algorithm.new().unwrap(),
                &password,
                &salt,
                iterations as u32,
                expected.len(),
            )
            .unwrap();
            assert_eq!(derived, expected, "{file} iterations {iterations}");
        }
    }
}

#[test]
fn pbkdf2_key_length_errors() {
    let make = || Hash::Sha256.new().unwrap();
    // Go's TestZeroKeyLength.
    let error = pbkdf2::key(make, "password", b"salt", 1, 0).unwrap_err();
    assert_eq!(error, pbkdf2::Error::KeyLengthNotPositive);
    assert_eq!(error.to_string(), "pbkdf2: keyLength must be larger than 0");
    // Zero iterations behave as one round, like Go's loop.
    assert_eq!(
        pbkdf2::key(make, "password", b"salt", 0, 32).unwrap(),
        pbkdf2::key(make, "password", b"salt", 1, 32).unwrap()
    );
}

#[test]
fn keyed_constructions_reject_foreign_hashes() {
    // A hash.Hash that is not one of this crate's implementations.
    struct Counter(u8);
    impl Write for Counter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.wrapping_add(buf.len() as u8);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl HashTrait for Counter {
        fn sum(&self, into: &mut Vec<u8>) {
            into.push(self.0);
        }
        fn reset(&mut self) {
            self.0 = 0;
        }
        fn size(&self) -> usize {
            1
        }
        fn block_size(&self) -> usize {
            1
        }
        fn clone_hash(&self) -> Box<dyn HashTrait> {
            Box::new(Counter(self.0))
        }
    }
    assert!(hmac::new(|| Counter(0), b"k").is_err());
    assert_eq!(
        hkdf::extract(|| Counter(0), b"s", b"").unwrap_err(),
        hkdf::Error::UnsupportedHash
    );
    assert_eq!(
        pbkdf2::key(|| Counter(0), "p", b"s", 1, 4).unwrap_err(),
        pbkdf2::Error::UnsupportedHash
    );
}
