//! Go's `io.Copy(h, r)`: every hash state is a `std::io::Write`, so
//! `std::io::copy` streams a reader into it.
use rust_stdlib::hash::{adler32, crc32, crc64, fnv, maphash, Hash};

fn data() -> Vec<u8> {
    (0..100_000u32).map(|i| (i * 31 + i / 7) as u8).collect()
}

/// Streams `data` through `std::io::copy` into a hash and returns its `sum`.
fn copied<H: Hash>(mut h: H, data: &[u8]) -> Vec<u8> {
    let n = std::io::copy(&mut &data[..], &mut h).unwrap();
    assert_eq!(n, data.len() as u64);
    h.sum(Vec::new())
}

fn one_shot<H: Hash>(mut h: H, data: &[u8]) -> Vec<u8> {
    h.write_all(data).unwrap();
    h.sum(Vec::new())
}

#[test]
fn io_copy_matches_one_shot() {
    let data = data();
    let t32 = crc32::Table::new(crc32::CASTAGNOLI);
    let t64 = crc64::Table::new(crc64::ECMA);
    assert_eq!(
        copied(crc32::Crc32::new(&t32), &data),
        one_shot(crc32::Crc32::new(&t32), &data)
    );
    assert_eq!(
        copied(crc64::Crc64::new(&t64), &data),
        one_shot(crc64::Crc64::new(&t64), &data)
    );
    assert_eq!(
        copied(adler32::Adler32::new(), &data),
        one_shot(adler32::Adler32::new(), &data)
    );
    assert_eq!(copied(fnv::new32(), &data), one_shot(fnv::new32(), &data));
    assert_eq!(copied(fnv::new32a(), &data), one_shot(fnv::new32a(), &data));
    assert_eq!(copied(fnv::new64(), &data), one_shot(fnv::new64(), &data));
    assert_eq!(copied(fnv::new64a(), &data), one_shot(fnv::new64a(), &data));
    assert_eq!(copied(fnv::new128(), &data), one_shot(fnv::new128(), &data));
    assert_eq!(
        copied(fnv::new128a(), &data),
        one_shot(fnv::new128a(), &data)
    );
    let mut digest = crc32::Crc32::new(&t32);
    std::io::copy(&mut &data[..], &mut digest).unwrap();
    assert_eq!(digest.sum32(), crc32::checksum(&data, &t32));
    let mut digest = adler32::Adler32::new();
    std::io::copy(&mut &data[..], &mut digest).unwrap();
    assert_eq!(digest.sum32(), adler32::checksum(&data));
}

#[test]
fn io_copy_into_maphash() {
    let data = data();
    let seed = maphash::make_seed();
    let mut h = maphash::Hash::new();
    h.set_seed(seed);
    let n = std::io::copy(&mut &data[..], &mut h).unwrap();
    assert_eq!(n, data.len() as u64);
    assert_eq!(h.sum64(), maphash::bytes(seed, &data));
}
