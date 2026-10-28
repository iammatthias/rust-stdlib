use rust_stdlib::hash::{crc64, fnv};
use std::io::Write;

#[test]
fn fnv_known_vectors_and_append_sum() {
    let mut h = fnv::new32();
    h.write_all(b"hello").unwrap();
    assert_eq!(h.digest(), 0xb6fa_7167);
    let mut prefix = b"prefix".to_vec();
    h.sum(&mut prefix);
    assert_eq!(&prefix[..6], b"prefix");
    assert_eq!(&prefix[6..], &0xb6fa_7167u32.to_be_bytes());

    let mut h = fnv::new32a();
    h.update(b"hello");
    assert_eq!(h.digest(), 0x4f9f_2cab);
    let mut h = fnv::new64();
    h.update(b"hello");
    assert_eq!(h.digest(), 0x7b49_5389_bdbd_d4c7);
    let mut h = fnv::new64a();
    h.update(b"hello");
    assert_eq!(h.digest(), 0xa430_d846_80aa_bd0b);
}

#[test]
fn fnv_128_matches_go_and_all_updates_are_incremental() {
    // Values are from Go's hash/fnv golden tests for "hello".
    let mut h = fnv::new128();
    h.update(b"he");
    h.write_all(b"llo").unwrap();
    assert_eq!(h.digest(), 0xf14b_5848_6483_d94f_7080_3879_8c29_697f);
    let mut a = fnv::new128a();
    a.update(b"hello");
    assert_eq!(a.digest(), 0xe3e1_efd5_4283_d94f_7081_314b_599d_31b3);
    // FNV-1 and FNV-1a differ at 128 bits as well; check Go oracle below.
    assert_ne!(h.digest(), a.digest());

    h.reset();
    assert_eq!(h.digest(), fnv::new128().digest());
}

#[test]
fn crc64_go_golden_vectors_and_incremental_updates() {
    let iso = crc64::Table::iso();
    let ecma = crc64::Table::ecma();
    assert_eq!(crc64::checksum(b"", &iso), 0);
    assert_eq!(crc64::checksum(b"a", &iso), 0x3420_0000_0000_0000);
    assert_eq!(crc64::checksum(b"abc", &iso), 0x3776_c420_0000_0000);
    assert_eq!(crc64::checksum(b"abc", &ecma), 0x2cd8_094a_1a27_7627);

    let mut h = crc64::Crc64::new(&ecma);
    h.write_all(b"a").unwrap();
    h.update(b"bc");
    assert_eq!(h.sum64(), crc64::checksum(b"abc", &ecma));
    let mut appended = b"pre".to_vec();
    h.sum(&mut appended);
    assert_eq!(&appended[..3], b"pre");
    assert_eq!(&appended[3..], &h.sum64().to_be_bytes());
    h.reset();
    assert_eq!(h.sum64(), 0);

    assert_eq!(
        crc64::update(crc64::checksum(b"a", &iso), &iso, b"bc"),
        crc64::checksum(b"abc", &iso)
    );
}

#[test]
fn crc64_custom_tables_and_chunk_boundaries_preserve_state() {
    let bytes: Vec<u8> = (0..16_385)
        .map(|index| ((index * 73 + index / 7) % 256) as u8)
        .collect();
    for table in [
        crc64::Table::iso(),
        crc64::Table::ecma(),
        crc64::Table::new(0x95ac_9329_ac4b_c9b5),
    ] {
        for size in [
            0, 1, 2, 7, 8, 63, 64, 255, 256, 4095, 4096, 8192, 8193, 16_385,
        ] {
            let expected = crc64::checksum(&bytes[..size], &table);
            for chunk_size in [1, 3, 8, 64, 257] {
                let mut hash = crc64::Crc64::new(&table);
                for chunk in bytes[..size].chunks(chunk_size) {
                    hash.update(chunk);
                }
                assert_eq!(hash.sum64(), expected, "size={size}, chunk={chunk_size}");
                let before_sum = hash.sum64();
                let mut encoded = Vec::new();
                hash.sum(&mut encoded);
                assert_eq!(encoded, before_sum.to_be_bytes());
                assert_eq!(hash.sum64(), before_sum);
            }
        }
    }
    let table = crc64::Table::new(0x95ac_9329_ac4b_c9b5);
    let initial = 0x1234_5678_9abc_def0;
    let one_shot = crc64::update(initial, &table, &bytes);
    let split = crc64::update(
        crc64::update(initial, &table, &bytes[..4097]),
        &table,
        &bytes[4097..],
    );
    assert_eq!(split, one_shot);
}

#[test]
fn crc32_adler32_and_compression_checksum_compatibility() {
    use rust_stdlib::hash::{adler32, crc32};

    let ieee = crc32::Table::ieee();
    // Go's IEEETable is one shared table.
    assert!(std::ptr::eq(ieee, crc32::Table::ieee()));
    let castagnoli = crc32::Table::castagnoli();
    let koopman = crc32::Table::koopman();
    let custom = crc32::Table::new(0x741b_8cd7);
    assert_eq!(crc32::checksum(b"abc", ieee), 0x3524_41c2);
    assert_eq!(crc32::checksum(b"abc", &castagnoli), 0x364b_3fb7);
    assert_eq!(crc32::checksum(b"abc", &koopman), 0xba23_22ac);
    assert_eq!(crc32::checksum(b"abc", &custom), 0x8b07_255f);
    assert_eq!(crc32::update(0x89ab_cdef, &custom, b"abc"), 0xf56a_36e4);
    assert_eq!(adler32::checksum(b""), 1);
    assert_eq!(adler32::checksum(b"Wikipedia"), 0x11e6_0398);
    assert_eq!(adler32::checksum(b"abc"), 0x024d_0127);
    assert_eq!(rust_stdlib::compress::crc32(b"123456789"), 0xcbf4_3926);
    assert_eq!(
        rust_stdlib::compress::crc32(b"123456789"),
        crc32::checksum_ieee(b"123456789")
    );
    assert_eq!(
        rust_stdlib::compress::adler32(b"Wikipedia"),
        adler32::checksum(b"Wikipedia")
    );

    let bytes: Vec<u8> = (0..16_385)
        .map(|index| ((index * 97 + index / 3) % 256) as u8)
        .collect();
    for table in [ieee, &castagnoli, &koopman, &custom] {
        for size in [0, 1, 7, 8, 15, 16, 255, 4096, 5551, 5552, 5553, 16_385] {
            let expected = crc32::checksum(&bytes[..size], table);
            for chunk_size in [1, 3, 8, 64, 257] {
                let mut hash = crc32::Crc32::new(table);
                for chunk in bytes[..size].chunks(chunk_size) {
                    hash.update(chunk);
                }
                assert_eq!(
                    hash.sum32(),
                    expected,
                    "CRC32 size={size}, chunk={chunk_size}"
                );
            }
        }
    }
    for size in [0, 1, 7, 8, 255, 4096, 5551, 5552, 5553, 16_385] {
        let expected = adler32::checksum(&bytes[..size]);
        for chunk_size in [1, 3, 8, 64, 257, 5552] {
            let mut hash = adler32::Adler32::new();
            for chunk in bytes[..size].chunks(chunk_size) {
                hash.update(chunk);
            }
            assert_eq!(
                hash.sum32(),
                expected,
                "Adler32 size={size}, chunk={chunk_size}"
            );
            let mut appended = b"prefix".to_vec();
            hash.sum(&mut appended);
            assert_eq!(&appended[6..], &expected.to_be_bytes());
            hash.reset();
            assert_eq!(hash.sum32(), 1);
        }
    }
}
