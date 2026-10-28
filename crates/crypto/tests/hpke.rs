//! crypto/hpke, ported from Go's hpke_test.go (the RFC 9180 vectors with
//! accumulated checks, and round trips).

mod common;

use std::io::Cursor;

use common::{rows, unhex};
use rust_stdlib_crypto::ecdh;
use rust_stdlib_crypto::hpke::{self, Kdf, Kem};
use rust_stdlib_crypto::sha3;

fn draw_random_input(source: &mut sha3::Shake) -> Vec<u8> {
    let mut len = [0u8; 1];
    source.read(&mut len);
    let mut bytes = vec![0u8; len[0] as usize];
    source.read(&mut bytes);
    bytes
}

#[test]
fn rfc9180_vectors() {
    let data = rows("hpke_rfc9180.tsv");
    assert_eq!(data.len(), 24);
    for row in &data {
        let id = |text: &str| text.parse::<u16>().unwrap();
        let (kem_id, kdf_id, aead_id) = (id(&row[0]), id(&row[1]), id(&row[2]));
        let kdf = hpke::kdf_from_id(kdf_id).unwrap();
        let aead = hpke::aead_from_id(aead_id).unwrap();
        let kem = hpke::kem_from_id(kem_id).unwrap();
        assert_eq!((kdf.id(), aead.id(), kem.id()), (kdf_id, aead_id, kem_id));
        let label = format!("kem {kem_id:#06x} kdf {kdf_id:#06x} aead {aead_id:#06x}");

        let (info, ikm_e, ikm_r) = (unhex(&row[3]), unhex(&row[4]), unhex(&row[5]));
        let (sk_rm, pk_rm, enc_expected) = (unhex(&row[6]), unhex(&row[7]), unhex(&row[8]));

        let sender_key = kem.public_key_from_bytes(&pk_rm).unwrap();
        assert_eq!(sender_key.kem().id(), kem.id());
        assert_eq!(sender_key.bytes(), pk_rm, "{label}");

        let mut ikm = Cursor::new(ikm_e);
        let (enc, mut sender) = hpke::Sender::with_rng(
            sender_key.as_ref(),
            kdf.as_ref(),
            aead.as_ref(),
            &info,
            &mut ikm,
        )
        .unwrap();
        assert_eq!(enc, enc_expected, "{label}");

        let recipient_key = kem.private_key_from_bytes(&sk_rm).unwrap();
        // X25519 serialized keys are clamped by the other implementations.
        if kem_id != 0x0020 {
            assert_eq!(recipient_key.bytes().unwrap(), sk_rm, "{label}");
        }
        assert_eq!(recipient_key.public_key().bytes(), pk_rm, "{label}");
        let derived = kem.derive_key_pair(&ikm_r).unwrap();
        assert_eq!(derived.public_key().bytes(), pk_rm, "{label}");
        if kem_id != 0x0020 {
            assert_eq!(derived.bytes().unwrap(), sk_rm, "{label}");
        }

        let mut recipient = hpke::Recipient::new(
            &enc,
            recipient_key.as_ref(),
            kdf.as_ref(),
            aead.as_ref(),
            &info,
        )
        .unwrap();

        if aead_id != 0xFFFF {
            let mut source = sha3::shake128();
            let mut sink = sha3::shake128();
            for _ in 0..1000 {
                let aad = draw_random_input(&mut source);
                let plaintext = draw_random_input(&mut source);
                let ciphertext = sender.seal(&aad, &plaintext).unwrap();
                sink.update(&ciphertext).unwrap();
                assert_eq!(recipient.open(&aad, &ciphertext).unwrap(), plaintext);
            }
            let mut encryptions = [0u8; 16];
            sink.read(&mut encryptions);
            assert_eq!(encryptions.to_vec(), unhex(&row[9]), "{label}: encryptions");
        } else {
            assert!(sender.seal(&[], &[]).is_err());
            assert!(recipient.open(&[], &[]).is_err());
        }

        let mut source = sha3::shake128();
        let mut sink = sha3::shake128();
        for length in 0..1000usize {
            let context = draw_random_input(&mut source);
            let value = sender.export_bytes(&context, length).unwrap();
            sink.update(&value).unwrap();
            assert_eq!(recipient.export_bytes(&context, length).unwrap(), value);
        }
        let mut exports = [0u8; 16];
        sink.read(&mut exports);
        assert_eq!(exports.to_vec(), unhex(&row[10]), "{label}: exports");
    }
}

#[test]
fn round_trips() {
    let suites: Vec<(std::sync::Arc<dyn Kem>, std::sync::Arc<dyn Kdf>)> = vec![
        (
            hpke::dhkem(ecdh::p256(), hpke::hkdf_sha256().as_ref()),
            hpke::hkdf_sha256(),
        ),
        (
            hpke::dhkem(ecdh::p384(), hpke::hkdf_sha384().as_ref()),
            hpke::hkdf_sha384(),
        ),
        (
            hpke::dhkem(ecdh::p521(), hpke::hkdf_sha512().as_ref()),
            hpke::hkdf_sha512(),
        ),
        (
            hpke::dhkem(ecdh::x25519(), hpke::hkdf_sha256().as_ref()),
            hpke::hkdf_sha384(),
        ),
    ];
    for (kem, kdf) in suites {
        for aead in [
            hpke::aes128gcm(),
            hpke::aes256gcm(),
            hpke::chacha20poly1305(),
        ] {
            let key = kem.generate_key().unwrap();
            let public = key.public_key();
            let ciphertext = hpke::seal(
                public.as_ref(),
                kdf.as_ref(),
                aead.as_ref(),
                b"info",
                b"hello",
            )
            .unwrap();
            let plaintext = hpke::open(
                key.as_ref(),
                kdf.as_ref(),
                aead.as_ref(),
                b"info",
                &ciphertext,
            )
            .unwrap();
            assert_eq!(plaintext, b"hello");
            assert!(hpke::open(
                key.as_ref(),
                kdf.as_ref(),
                aead.as_ref(),
                b"other",
                &ciphertext
            )
            .is_err());
            assert!(hpke::open(
                key.as_ref(),
                kdf.as_ref(),
                aead.as_ref(),
                b"info",
                &ciphertext[..5]
            )
            .is_err());
            let (enc, mut sender) =
                hpke::Sender::new(public.as_ref(), kdf.as_ref(), aead.as_ref(), b"i").unwrap();
            let mut recipient =
                hpke::Recipient::new(&enc, key.as_ref(), kdf.as_ref(), aead.as_ref(), b"i")
                    .unwrap();
            for round in 0..3u8 {
                let sealed = sender.seal(b"aad", &[round; 10]).unwrap();
                assert_eq!(recipient.open(b"aad", &sealed).unwrap(), vec![round; 10]);
            }
            assert_eq!(
                sender.export("ctx", 32).unwrap(),
                recipient.export("ctx", 32).unwrap()
            );
            assert_eq!(sender.export("x", 0).unwrap().len(), 0);
            assert_eq!(
                sender.export("x", 0x10000).unwrap_err().to_string(),
                "invalid length"
            );
        }
    }
}

#[test]
fn ecdh_keys_convert() {
    let private = ecdh::p256().generate_key().unwrap();
    let key = hpke::dhkem_private_key(&private).unwrap();
    assert_eq!(key.bytes().unwrap(), private.bytes());
    assert_eq!(key.public_key().bytes(), private.public_key().bytes());
    let public = hpke::dhkem_public_key(private.public_key()).unwrap();
    assert_eq!(public.bytes(), private.public_key().bytes());
    assert_eq!(public.kem().id(), 0x0010);
}

#[test]
fn identifiers() {
    assert_eq!(hpke::hkdf_sha256().id(), 1);
    assert_eq!(hpke::hkdf_sha384().id(), 2);
    assert_eq!(hpke::hkdf_sha512().id(), 3);
    assert_eq!(hpke::shake128().id(), 0x10);
    assert_eq!(hpke::shake256().id(), 0x11);
    assert_eq!(hpke::aes128gcm().id(), 1);
    assert_eq!(hpke::aes256gcm().id(), 2);
    assert_eq!(hpke::chacha20poly1305().id(), 3);
    assert_eq!(hpke::export_only().id(), 0xFFFF);
    assert_eq!(hpke::mlkem768().id(), 0x41);
    assert_eq!(hpke::mlkem1024().id(), 0x42);
    assert_eq!(hpke::mlkem768x25519().id(), 0x647a);
    assert_eq!(hpke::mlkem768p256().id(), 0x50);
    assert_eq!(hpke::mlkem1024p384().id(), 0x51);
    assert!(hpke::kem_from_id(0x9999).is_err());
    assert!(hpke::kdf_from_id(0x9999).is_err());
    assert!(hpke::aead_from_id(0x9999).is_err());
}

#[test]
fn unsupported_suites_report_errors() {
    // Post-quantum KEMs and the SHAKE KDFs are documented deviations.
    assert!(hpke::mlkem768().generate_key().is_err());
    let key = hpke::dhkem(ecdh::p256(), hpke::hkdf_sha256().as_ref())
        .generate_key()
        .unwrap();
    let public = key.public_key();
    let error = hpke::seal(
        public.as_ref(),
        hpke::shake128().as_ref(),
        hpke::aes128gcm().as_ref(),
        b"",
        b"x",
    )
    .unwrap_err();
    assert!(error.to_string().contains("not supported"), "{error}");
    // A pairing RFC 9180 does not define.
    let odd = hpke::dhkem(ecdh::p256(), hpke::hkdf_sha384().as_ref());
    assert!(odd.generate_key().is_err());
    // Export-only contexts export but do not seal.
    let (enc, mut sender) = hpke::Sender::new(
        public.as_ref(),
        hpke::hkdf_sha256().as_ref(),
        hpke::export_only().as_ref(),
        b"",
    )
    .unwrap();
    assert_eq!(
        sender.seal(&[], b"x").unwrap_err().to_string(),
        "export-only instantiation"
    );
    let recipient = hpke::Recipient::new(
        &enc,
        key.as_ref(),
        hpke::hkdf_sha256().as_ref(),
        hpke::export_only().as_ref(),
        b"",
    )
    .unwrap();
    assert_eq!(
        sender.export("e", 16).unwrap(),
        recipient.export("e", 16).unwrap()
    );
}
