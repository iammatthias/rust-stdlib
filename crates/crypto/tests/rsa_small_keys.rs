//! The crypto/rsa tests that use 512-bit keys, which Go rejects unless
//! `GODEBUG=rsa1024min=0` (ported from Go's pkcs1v15_test.go and
//! rsa_test.go). Every test sets the variable first (the default behaviour is
//! tested in tests/rsa.rs, a separate process).

mod common;

use common::{rows, unhex};
use rust_stdlib_crypto::rsa::{self, PKCS1v15DecryptOptions, PrivateKey};
use rust_stdlib_crypto::{sha1, Hash};

fn test512() -> PrivateKey {
    std::env::set_var("GODEBUG", "rsa1024min=0");
    for row in rows("rsa_go_keys.tsv") {
        if row[0] == "test512" {
            return PrivateKey::from_pkcs1_der(&unhex(&row[2])).expect("test512Key");
        }
    }
    panic!("test512 key missing");
}

/// Generated with `openssl rsautl -pkcs -encrypt`.
const DECRYPT: [(&str, &str); 4] = [
    ("8087142285640fa01330193fbbf9e509908259129d91f8c2805768df95694572ddba229784dcf55eea4b2f34d70326c4ab5e63b9cf84818e68d031effe7b77ca", "x"),
    ("63b4ce092aa87c686445bfa369544bccaf31c36712a35215112d7dbadcefea1c2fc7e33c905b285909b90f305e2426530950cf913a5abd4b846e0a7c8675060f", "testing."),
    ("6ab45e3fd0c9b445725760e0ddd0e9e1cfcf4a4d4eea5c64a09f07705ba9a11a2b0591beefed5f0c0c13d6894d75d16740c8e691bf2fc7098d3284c04ff0458d", "testing.\n"),
    ("5ad6815c8a060b9e3ebc7d0d1f40871c4f9d4433ac31cffa06b7c5bb6944a9c28bf7eb83b9669ff978fd9ab6d00a38d972942e5fbdf7cf2a24fe3b27a9efc5b7", "01234567890123456789012345678901234567890123456789012"),
];

const SESSION_KEY: [(&str, &str); 4] = [
    ("7baba491a7ba1b292ad1f2b363050ba597a15fe50f5d8ccca01e661d050312272545b393a9ab3863413a9f09ecd4106976f109722961979ceca31ffa0ed1ac62", "1234"),
    ("0ed8ace2e93fabf2d0186a8693decfe7d2b4de190221514c10565181558e000871818a42446d0c5f669da6db7dda5ebb22a3248ba895432cadd13b57dc876d13", "FAIL"),
    ("2c8c85c82602a6d3f1aef4f1a6897c17733b662be532c7f9df3b34bc7440bfeac3221d98b074baf5e3cca0f31edd390e319dcdba988bded6a43f122cd6c2be77", "abcd"),
    ("6da7e7a1b7a5e3a6cacbbe89cea53f44854e1f4b8062fcd4b5ab8a98889d2a0334b0c96fa1b61501540f79443fa131a36c8675bffe86ca2e403b80ed1ebb8677", "FAIL"),
];

#[test]
fn decrypt_pkcs1v15() {
    let key = test512();
    for (index, (input, want)) in DECRYPT.iter().enumerate() {
        let ct = unhex(input);
        assert_eq!(
            rsa::decrypt_pkcs1v15(&key, &ct).unwrap(),
            want.as_bytes(),
            "#{index}"
        );
        assert_eq!(
            key.decrypt(&ct, None).unwrap(),
            want.as_bytes(),
            "#{index} via Decrypt"
        );
    }
}

#[test]
fn session_keys() {
    let key = test512();
    for (index, (input, want)) in SESSION_KEY.iter().enumerate() {
        let ct = unhex(input);
        let mut session = *b"FAIL";
        rsa::decrypt_pkcs1v15_session_key(&key, &ct, &mut session).unwrap();
        assert_eq!(&session, want.as_bytes(), "#{index}");
        let opts = PKCS1v15DecryptOptions { session_key_len: 4 };
        let plaintext = key.decrypt(&ct, Some(&opts)).unwrap();
        assert_eq!(plaintext.len(), 4);
        if *want != "FAIL" {
            assert_eq!(plaintext, want.as_bytes(), "#{index} via Decrypt");
        }
    }
}

#[test]
fn sign_and_verify_pkcs1v15() {
    let key = test512();
    let digest = sha1::sum(b"Test.\n");
    let want = unhex("a4f3fa6ea93bcdd0c57be020c1193ecbfd6f200a3d95c409769b029578fa0e336ad9a347600e40d3ae823b8c7e6bad88cc07c1d54c3a1523cbbb6d58efc362ae");
    let sig = rsa::sign_pkcs1v15(&key, Some(Hash::Sha1), &digest).unwrap();
    assert_eq!(sig, want);
    rsa::verify_pkcs1v15(&key.public_key, Some(Hash::Sha1), &digest, &want).unwrap();
}

#[test]
fn unpadded_signature() {
    let key = test512();
    let msg = b"Thu Dec 19 18:06:16 EST 2013\n";
    let want = unhex("a57e0347c6b3cad8dd435aed5220b4e3416391ea6e42eb79ab66455f5a538c1ace54a36382c083ca22431994c236887daa95d86e197b884ca6df40565b0ba266");
    let sig = rsa::sign_pkcs1v15(&key, None, msg).unwrap();
    assert_eq!(sig, want);
    rsa::verify_pkcs1v15(&key.public_key, None, msg, &sig).unwrap();
}

#[test]
fn overlong_message_is_rejected() {
    let key = test512();
    let ct = unhex("7e3395762ad4cc5a0b96e92ff3474196530b8d7cad8487f6d9f7aa3eb368d18a088f3cb3ca830588b8c073f63892b91e675d57153848ac4bf0911899702ab99e");
    assert!(rsa::decrypt_pkcs1v15(&key, &ct).is_err());
}
