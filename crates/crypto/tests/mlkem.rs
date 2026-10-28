//! crypto/mlkem and crypto/mlkem/mlkemtest, ported from Go's mlkem_test.go and
//! mlkem_wycheproof_test.go.

mod common;

use common::{rows, unhex};
use rust_stdlib_crypto::mlkem::{self, mlkemtest};
use rust_stdlib_crypto::{Decapsulator, Encapsulator};

#[test]
fn round_trip_768_and_1024() {
    let dk = mlkem::generate_key768().unwrap();
    let ek = dk.encapsulation_key();
    assert_eq!(ek.bytes().len(), mlkem::ENCAPSULATION_KEY_SIZE_768);
    let (k, c) = ek.encapsulate();
    assert_eq!(c.len(), mlkem::CIPHERTEXT_SIZE_768);
    assert_eq!(k.len(), mlkem::SHARED_KEY_SIZE);
    assert_eq!(dk.decapsulate(&c).unwrap(), k);
    assert_eq!(dk.bytes().len(), mlkem::SEED_SIZE);
    let again = mlkem::new_decapsulation_key768(&dk.bytes()).unwrap();
    assert_eq!(again.encapsulation_key().bytes(), ek.bytes());
    let parsed = mlkem::new_encapsulation_key768(&ek.bytes()).unwrap();
    assert_eq!(parsed, ek);

    let dk = mlkem::generate_key1024().unwrap();
    let ek = dk.encapsulation_key();
    assert_eq!(ek.bytes().len(), mlkem::ENCAPSULATION_KEY_SIZE_1024);
    let (k, c) = ek.encapsulate();
    assert_eq!(c.len(), mlkem::CIPHERTEXT_SIZE_1024);
    assert_eq!(dk.decapsulate(&c).unwrap(), k);
}

#[test]
fn errors_use_go_messages() {
    assert_eq!(
        mlkem::new_decapsulation_key768(&[0; 63])
            .unwrap_err()
            .to_string(),
        "mlkem: invalid seed length"
    );
    assert_eq!(
        mlkem::new_encapsulation_key768(&[0; 10])
            .unwrap_err()
            .to_string(),
        "mlkem: invalid encapsulation key length"
    );
    let dk = mlkem::generate_key768().unwrap();
    assert_eq!(
        dk.decapsulate(&[0; 5]).unwrap_err().to_string(),
        "mlkem: invalid ciphertext length"
    );
    // A tampered ciphertext decapsulates to a different (implicitly rejected) key.
    let (k, mut c) = dk.encapsulation_key().encapsulate();
    c[0] ^= 1;
    assert_ne!(dk.decapsulate(&c).unwrap(), k);
}

#[test]
fn crypto_interfaces() {
    let dk = mlkem::generate_key768().unwrap();
    let decapsulator: &dyn Decapsulator = &dk;
    let encapsulator: Box<dyn Encapsulator> = decapsulator.encapsulator();
    assert_eq!(encapsulator.bytes(), dk.encapsulation_key().bytes());
    let (k, c) = encapsulator.encapsulate();
    assert_eq!(decapsulator.decapsulate(&c).unwrap(), k);
    assert!(decapsulator.decapsulate(&c[1..]).is_err());
}

#[test]
fn mlkemtest_requires_32_random_bytes() {
    let ek = mlkem::generate_key768().unwrap().encapsulation_key();
    assert_eq!(
        mlkemtest::encapsulate768(&ek, &[0; 31])
            .unwrap_err()
            .to_string(),
        "mlkemtest: Encapsulate768: random must be 32 bytes"
    );
    let ek = mlkem::generate_key1024().unwrap().encapsulation_key();
    assert_eq!(
        mlkemtest::encapsulate1024(&ek, &[])
            .unwrap_err()
            .to_string(),
        "mlkemtest: Encapsulate1024: random must be 32 bytes"
    );
    // Derandomized encapsulation is deterministic.
    let a = mlkemtest::encapsulate1024(&ek, &[7; 32]).unwrap();
    assert_eq!(a, mlkemtest::encapsulate1024(&ek, &[7; 32]).unwrap());
}

#[test]
fn wycheproof() {
    let data = rows("mlkem_wycheproof.tsv");
    assert_eq!(data.len(), 114);
    for row in &data {
        let (kind, param) = (row[0].as_str(), row[1].as_str());
        let (seed, m, ek, c, k) = (
            unhex(&row[2]),
            unhex(&row[3]),
            unhex(&row[4]),
            unhex(&row[5]),
            unhex(&row[6]),
        );
        let should_pass = match row[7].as_str() {
            "valid" => true,
            "invalid" => false,
            other => panic!("result {other}"),
        };
        let big = param == "1024";
        match kind {
            "keygen" => {
                let (got_seed, got_ek) = if big {
                    let dk = mlkem::new_decapsulation_key1024(&seed).unwrap();
                    (dk.bytes(), dk.encapsulation_key().bytes())
                } else {
                    let dk = mlkem::new_decapsulation_key768(&seed).unwrap();
                    (dk.bytes(), dk.encapsulation_key().bytes())
                };
                assert_eq!(got_seed, seed);
                assert_eq!(got_ek, ek);
            }
            "encaps" => {
                let result = if big {
                    mlkem::new_encapsulation_key1024(&ek).and_then(|key| {
                        assert_eq!(key.bytes(), ek);
                        mlkemtest::encapsulate1024(&key, &m)
                    })
                } else {
                    mlkem::new_encapsulation_key768(&ek).and_then(|key| {
                        assert_eq!(key.bytes(), ek);
                        mlkemtest::encapsulate768(&key, &m)
                    })
                };
                match result {
                    Ok((got_k, got_c)) => {
                        assert!(should_pass, "unexpected success: {row:?}");
                        assert_eq!((got_c, got_k), (c, k));
                    }
                    Err(error) => assert!(!should_pass, "{error}: {row:?}"),
                }
            }
            "decaps" => {
                let got = if big {
                    let dk = mlkem::new_decapsulation_key1024(&seed).unwrap();
                    if !ek.is_empty() {
                        assert_eq!(dk.encapsulation_key().bytes(), ek);
                    }
                    dk.decapsulate(&c)
                } else {
                    let dk = mlkem::new_decapsulation_key768(&seed).unwrap();
                    if !ek.is_empty() {
                        assert_eq!(dk.encapsulation_key().bytes(), ek);
                    }
                    dk.decapsulate(&c)
                };
                match got {
                    Ok(got) if should_pass => assert_eq!(got, k, "{row:?}"),
                    Ok(_) => {}
                    Err(error) => assert!(!should_pass, "{error}: {row:?}"),
                }
            }
            other => panic!("kind {other}"),
        }
    }
}
