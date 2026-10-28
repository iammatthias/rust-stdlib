//! hash traits and hash/maphash properties (Go's maphash_test.go, hash tests).
use rust_stdlib::hash::maphash::{self, ComparableHasher, Hasher as _, Seed};
use rust_stdlib::hash::{adler32, crc32, crc64, fnv, Cloner, Hash, Hash32, Hash64};
use std::io::Write;

#[test]
fn seeds_are_random_and_valid() {
    let a = maphash::make_seed();
    let b = maphash::make_seed();
    assert_ne!(a, Seed::default());
    assert_ne!(a, b);
}

#[test]
fn bytes_string_and_hash_agree() {
    let seed = maphash::make_seed();
    for data in [&b""[..], b"a", b"hello world", &[0u8; 300], &[255u8; 129]] {
        let mut h = maphash::Hash::new();
        h.set_seed(seed);
        h.write_all(data).unwrap();
        assert_eq!(h.sum64(), maphash::bytes(seed, data));
        if let Ok(s) = std::str::from_utf8(data) {
            assert_eq!(maphash::string(seed, s), maphash::bytes(seed, data));
            let mut hs = maphash::Hash::new();
            hs.set_seed(seed);
            assert_eq!(hs.write_string(s), s.len());
            assert_eq!(hs.sum64(), h.sum64());
        }
        let mut hb = maphash::Hash::new();
        hb.set_seed(seed);
        for &byte in data {
            hb.write_byte(byte).unwrap();
        }
        assert_eq!(hb.sum64(), h.sum64(), "WriteByte matches Write");
    }
}

#[test]
fn chunking_does_not_change_the_hash() {
    let seed = maphash::make_seed();
    let data: Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
    let want = maphash::bytes(seed, &data);
    for chunk in [1, 2, 3, 7, 64, 127, 128, 129, 500] {
        let mut h = maphash::Hash::new();
        h.set_seed(seed);
        for piece in data.chunks(chunk) {
            h.write_all(piece).unwrap();
        }
        assert_eq!(h.sum64(), want, "chunk {chunk}");
    }
}

#[test]
fn reset_seed_and_clone() {
    let seed = maphash::make_seed();
    let mut h = maphash::Hash::new();
    h.set_seed(seed);
    assert_eq!(h.seed(), seed);
    h.write_all(b"abc").unwrap();
    let sum = h.sum64();
    let mut c = h.clone();
    assert_eq!(c.sum64(), sum);
    c.write_all(b"def").unwrap();
    assert_ne!(c.sum64(), sum);
    assert_eq!(h.sum64(), sum, "clone is independent");
    h.reset();
    assert_eq!(h.sum64(), maphash::bytes(seed, b""));
    assert_eq!(h.seed(), seed, "reset keeps the seed");
    // A different seed gives a different hash.
    let other = maphash::make_seed();
    assert_ne!(maphash::bytes(other, b"abc"), maphash::bytes(seed, b"abc"));
}

#[test]
fn sum_layout() {
    let mut h = maphash::Hash::new();
    h.write_all(b"xyz").unwrap();
    let out = h.sum(b"pre".to_vec());
    assert_eq!(&out[..3], b"pre");
    assert_eq!(out.len(), 11);
    assert_eq!(u64::from_le_bytes(out[3..].try_into().unwrap()), h.sum64());
    assert_eq!((h.size(), h.block_size()), (8, 128));
    let via_trait: &dyn Hash = &h;
    assert_eq!(via_trait.sum(Vec::new()).len(), via_trait.size());
}

#[test]
#[should_panic(expected = "maphash: use of uninitialized Seed")]
fn zero_seed_panics() {
    maphash::bytes(Seed::default(), b"x");
}

#[test]
#[should_panic(expected = "maphash: use of uninitialized Seed")]
fn set_zero_seed_panics() {
    maphash::Hash::new().set_seed(Seed::default());
}

#[test]
fn comparable_values() {
    let seed = maphash::make_seed();
    assert_eq!(
        maphash::comparable(seed, &42u64),
        maphash::comparable(seed, &42u64)
    );
    assert_ne!(
        maphash::comparable(seed, &42u64),
        maphash::comparable(seed, &43u64)
    );
    assert_eq!(
        maphash::comparable(seed, &("a", 1u8)),
        maphash::comparable(seed, &("a", 1u8))
    );
    let mut h = maphash::Hash::new();
    h.set_seed(seed);
    maphash::write_comparable(&mut h, &"key".to_string());
    assert_eq!(h.sum64(), maphash::comparable(seed, &"key".to_string()));
}

#[test]
fn comparable_hasher() {
    let hasher = ComparableHasher::<String>::new();
    let seed = maphash::make_seed();
    let (mut a, mut b) = (maphash::Hash::new(), maphash::Hash::new());
    a.set_seed(seed);
    b.set_seed(seed);
    hasher.hash(&mut a, &"x".to_string());
    hasher.hash(&mut b, &"x".to_string());
    assert_eq!(a.sum64(), b.sum64());
    assert!(hasher.equal(&"x".to_string(), &"x".to_string()));
    assert!(!hasher.equal(&"x".to_string(), &"y".to_string()));
}

fn digest(h: &mut dyn Hash, data: &[u8]) -> Vec<u8> {
    h.reset();
    h.write_all(data).unwrap();
    h.sum(Vec::new())
}

#[test]
fn crate_digests_implement_the_hash_traits() {
    let mut c32 = crc32::Crc32::ieee();
    let sum = digest(&mut c32, b"123456789");
    assert_eq!(sum, 0xCBF43926u32.to_be_bytes());
    assert_eq!(Hash32::sum32(&c32), 0xCBF43926);
    assert_eq!((Hash::size(&c32), Hash::block_size(&c32)), (4, 1));

    let mut a32 = adler32::Adler32::new();
    digest(&mut a32, b"Wikipedia");
    assert_eq!(Hash32::sum32(&a32), 0x11E60398);

    let mut c64 = crc64::Crc64::new(&crc64::Table::ecma());
    digest(&mut c64, b"123456789");
    assert_eq!(Hash64::sum64(&c64), 0x995DC9BBDF1939FA);

    let mut f = fnv::new64a();
    digest(&mut f, b"");
    assert_eq!(Hash64::sum64(&f), 0xcbf29ce484222325);
    let mut f32a = fnv::new32a();
    digest(&mut f32a, b"a");
    assert_eq!(Hash32::sum32(&f32a), 0xe40c292c);
    let mut f128 = fnv::new128a();
    assert_eq!(digest(&mut f128, b"").len(), 16);

    // Cloner: the clone continues independently.
    let mut base = crc32::Crc32::ieee();
    base.write_all(b"1234").unwrap();
    let mut copy = Cloner::clone_hash(&base);
    copy.write_all(b"56789").unwrap();
    assert_eq!(copy.sum(Vec::new()), 0xCBF43926u32.to_be_bytes());
    assert_ne!(Hash32::sum32(&base), 0xCBF43926);

    // maphash.Hash is a Hash64 too.
    let mut m = maphash::Hash::new();
    m.write_all(b"q").unwrap();
    assert_eq!(Hash64::sum64(&m), m.sum64());
}
