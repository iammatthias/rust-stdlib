use rust_stdlib::hash::{adler32::Adler32, crc32::Crc32, crc64::Crc64, fnv};

macro_rules! fnv_state_roundtrip {
    ($hasher:ty, $magic:expr, $size:expr) => {{
        let mut original = <$hasher>::new();
        original.update(b"before checkpoint");
        let state = original.marshal_binary();
        assert_eq!(&state[..4], $magic);
        assert_eq!(state.len(), $size);

        let mut restored = <$hasher>::new();
        restored.unmarshal_binary(&state).unwrap();
        original.update(b" after checkpoint");
        restored.update(b" after checkpoint");
        assert_eq!(restored.digest(), original.digest());
        assert_eq!(restored.marshal_binary(), original.marshal_binary());

        let before = restored.digest();
        let error = restored.unmarshal_binary(b"nope").unwrap_err();
        assert_eq!(error.message(), "hash/fnv: invalid hash state identifier");
        assert_eq!(restored.digest(), before);
        let mut wrong_size = state.clone();
        wrong_size.push(0);
        let error = restored.unmarshal_binary(&wrong_size).unwrap_err();
        assert_eq!(error.message(), "hash/fnv: invalid hash state size");
        assert_eq!(restored.digest(), before);
    }};
}

#[test]
fn every_fnv_variant_roundtrips_and_rejects_invalid_state() {
    fnv_state_roundtrip!(fnv::Fnv32, b"fnv\x01", 8);
    fnv_state_roundtrip!(fnv::Fnv32a, b"fnv\x02", 8);
    fnv_state_roundtrip!(fnv::Fnv64, b"fnv\x03", 12);
    fnv_state_roundtrip!(fnv::Fnv64a, b"fnv\x04", 12);
    fnv_state_roundtrip!(fnv::Fnv128, b"fnv\x05", 20);
    fnv_state_roundtrip!(fnv::Fnv128a, b"fnv\x06", 20);
}

#[test]
fn crc64_state_validates_identifier_size_and_table_identity() {
    let ecma = rust_stdlib::hash::crc64::Table::ecma();
    let mut original = Crc64::new(&ecma);
    original.update(b"checkpoint payload");
    let state = original.marshal_binary();
    assert_eq!(&state[..4], b"crc\x02");

    let mut restored = Crc64::new(&ecma);
    restored.unmarshal_binary(&state).unwrap();
    original.update(b" more");
    restored.update(b" more");
    assert_eq!(restored.sum64(), original.sum64());
    assert_eq!(restored.marshal_binary(), original.marshal_binary());

    let mut other_table = Crc64::new(&rust_stdlib::hash::crc64::Table::iso());
    let before = other_table.sum64();
    let error = other_table.unmarshal_binary(&state).unwrap_err();
    assert_eq!(error.message(), "hash/crc64: tables do not match");
    assert_eq!(other_table.sum64(), before);

    let error = restored.unmarshal_binary(b"nope").unwrap_err();
    assert_eq!(error.message(), "hash/crc64: invalid hash state identifier");
    let mut wrong_size = state.clone();
    wrong_size.pop();
    let error = restored.unmarshal_binary(&wrong_size).unwrap_err();
    assert_eq!(error.message(), "hash/crc64: invalid hash state size");
}

#[test]
fn crc32_state_validates_identifier_size_and_table_identity() {
    let castagnoli = rust_stdlib::hash::crc32::Table::castagnoli();
    let mut original = Crc32::new(&castagnoli);
    original.update(b"checkpoint payload");
    let state = original.marshal_binary();
    assert_eq!(&state[..4], b"crc\x01");

    let mut restored = Crc32::new(&castagnoli);
    restored.unmarshal_binary(&state).unwrap();
    original.update(b" more");
    restored.update(b" more");
    assert_eq!(restored.sum32(), original.sum32());
    assert_eq!(restored.marshal_binary(), original.marshal_binary());

    let mut other_table = Crc32::new(rust_stdlib::hash::crc32::Table::ieee());
    let before = other_table.sum32();
    let error = other_table.unmarshal_binary(&state).unwrap_err();
    assert_eq!(error.message(), "hash/crc32: tables do not match");
    assert_eq!(other_table.sum32(), before);

    let error = restored.unmarshal_binary(b"nope").unwrap_err();
    assert_eq!(error.message(), "hash/crc32: invalid hash state identifier");
    let mut wrong_size = state.clone();
    wrong_size.push(0);
    let error = restored.unmarshal_binary(&wrong_size).unwrap_err();
    assert_eq!(error.message(), "hash/crc32: invalid hash state size");
}

#[test]
fn adler32_state_roundtrips_and_rejects_invalid_state() {
    let mut original = Adler32::new();
    original.update(b"checkpoint payload");
    let state = original.marshal_binary();
    assert_eq!(&state[..4], b"adl\x01");
    let mut restored = Adler32::new();
    restored.unmarshal_binary(&state).unwrap();
    original.update(b" more");
    restored.update(b" more");
    assert_eq!(restored.sum32(), original.sum32());

    let before = restored.sum32();
    assert_eq!(
        restored.unmarshal_binary(b"nope").unwrap_err().message(),
        "hash/adler32: invalid hash state identifier"
    );
    let mut wrong_size = state;
    wrong_size.push(0);
    assert_eq!(
        restored
            .unmarshal_binary(&wrong_size)
            .unwrap_err()
            .message(),
        "hash/adler32: invalid hash state size"
    );
    assert_eq!(restored.sum32(), before);
}

#[test]
fn adler32_arbitrary_serialized_state_matches_go_wrapping_behavior() {
    let mut hash = Adler32::new();
    hash.unmarshal_binary(b"adl\x01\xff\xff\xff\xff").unwrap();
    hash.update(&vec![0xff; 5_553]);
    assert_eq!(hash.sum32(), 0xa843_9c98);

    let mut split = Adler32::new();
    split.unmarshal_binary(b"adl\x01\xff\xff\xff\xff").unwrap();
    split.update(&vec![0xff; 5_552]);
    split.update(&[0xff]);
    assert_eq!(split.sum32(), 0xa843_9c98);
}
