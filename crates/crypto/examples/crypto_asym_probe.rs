//! Rust side of tools/crypto_asym_check.py.
//!
//! Reads one case per line as space-separated `key=value` tokens (byte strings
//! are hex) and prints one line of `name=value` tokens per case, the same
//! protocol as tools/crypto_asym_oracle.go. Errors and panics print `err=1`.

use std::collections::{BTreeMap, HashMap};
use std::io::{self, BufRead, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use rust_stdlib_crypto::bigint::Int;
use rust_stdlib_crypto::elliptic::{self, Curve};
use rust_stdlib_crypto::{dsa, ecdh, ecdsa, ed25519, hpke, mldsa, mlkem, rsa, Hash};

type Fields = HashMap<String, String>;
type Out = BTreeMap<String, String>;
type Res = Result<Out, String>;
type Suite = (Arc<dyn hpke::Kem>, Arc<dyn hpke::Kdf>, Arc<dyn hpke::Aead>);

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn b(f: &Fields, key: &str) -> Vec<u8> {
    unhex(f.get(key).map(String::as_str).unwrap_or(""))
}

fn n(f: &Fields, key: &str) -> Int {
    Int::from_hex(f.get(key).map(String::as_str).unwrap_or("0")).unwrap_or_default()
}

fn int(f: &Fields, key: &str) -> i64 {
    f[key].parse().expect("integer")
}

fn e<E: std::fmt::Display>(error: E) -> String {
    error.to_string()
}

fn bn(value: &Int) -> String {
    hex(value.as_be_bytes())
}

fn ok(value: bool) -> String {
    if value { "1" } else { "0" }.to_string()
}

fn hash_of(name: &str) -> Hash {
    match name {
        "sha1" => Hash::Sha1,
        "sha224" => Hash::Sha224,
        "sha256" => Hash::Sha256,
        "sha384" => Hash::Sha384,
        "sha512" => Hash::Sha512,
        "sha512_256" => Hash::Sha512_256,
        "sha3_256" => Hash::Sha3_256,
        other => panic!("hash {other}"),
    }
}

fn curve_of(name: &str) -> Arc<dyn Curve> {
    match name {
        "p224" => elliptic::p224(),
        "p256" => elliptic::p256(),
        "p384" => elliptic::p384(),
        "p521" => elliptic::p521(),
        other => panic!("curve {other}"),
    }
}

fn ecdh_curve(name: &str) -> &'static dyn ecdh::Curve {
    match name {
        "p256" => ecdh::p256(),
        "p384" => ecdh::p384(),
        "p521" => ecdh::p521(),
        "x25519" => ecdh::x25519(),
        other => panic!("curve {other}"),
    }
}

fn rsa_key(f: &Fields) -> Result<rsa::PrivateKey, String> {
    rsa::PrivateKey::from_pkcs1_der(&b(f, "key")).map_err(e)
}

fn mldsa_params(name: &str) -> mldsa::Parameters {
    match name {
        "44" => mldsa::mldsa44(),
        "65" => mldsa::mldsa65(),
        _ => mldsa::mldsa87(),
    }
}

fn dsa_key(f: &Fields) -> dsa::PrivateKey {
    dsa::PrivateKey {
        public_key: dsa::PublicKey {
            parameters: dsa::Parameters {
                p: n(f, "p"),
                q: n(f, "q"),
                g: n(f, "g"),
            },
            y: n(f, "y"),
        },
        x: n(f, "x"),
    }
}

fn hpke_suite(f: &Fields) -> Result<Suite, String> {
    let kem = match f["kem"].as_str() {
        "p256" => hpke::dhkem(ecdh::p256(), hpke::hkdf_sha256().as_ref()),
        "p384" => hpke::dhkem(ecdh::p384(), hpke::hkdf_sha384().as_ref()),
        "p521" => hpke::dhkem(ecdh::p521(), hpke::hkdf_sha512().as_ref()),
        _ => hpke::dhkem(ecdh::x25519(), hpke::hkdf_sha256().as_ref()),
    };
    Ok((
        kem,
        hpke::kdf_from_id(int(f, "kdf") as u16).map_err(e)?,
        hpke::aead_from_id(int(f, "aead") as u16).map_err(e)?,
    ))
}

fn ed_options(f: &Fields) -> ed25519::Options {
    ed25519::Options {
        hash: (f["mode"] == "ph").then_some(Hash::Sha512),
        context: String::from_utf8(b(f, "ctx")).expect("text"),
    }
}

fn ed_message(f: &Fields) -> Vec<u8> {
    let msg = b(f, "msg");
    if f["mode"] == "ph" {
        rust_stdlib_crypto::sha512::sum512(&msg).to_vec()
    } else {
        msg
    }
}

fn run(f: &Fields) -> Res {
    let mut o = Out::new();
    match f["op"].as_str() {
        "ed_keygen" => {
            let key = ed25519::PrivateKey::from_seed(&b(f, "seed")).map_err(e)?;
            o.insert("pub".into(), hex(&key.public_key().0));
            o.insert("priv".into(), hex(key.as_bytes()));
        }
        "ed_sign" => {
            let key = ed25519::PrivateKey::from_seed(&b(f, "seed")).map_err(e)?;
            let sig = key.sign(&ed_message(f), &ed_options(f)).map_err(e)?;
            o.insert("sig".into(), hex(&sig));
        }
        "ed_verify" => {
            let public = ed25519::PublicKey(b(f, "pub"));
            let result =
                ed25519::verify_with_options(&public, &ed_message(f), &b(f, "sig"), &ed_options(f));
            o.insert("ok".into(), ok(result.is_ok()));
        }
        "ecdh" => {
            let curve = ecdh_curve(&f["curve"]);
            let private = curve.private_key_from_bytes(&b(f, "priv")).map_err(e)?;
            o.insert("pub".into(), hex(&private.public_key().bytes()));
            let peer = curve.public_key_from_bytes(&b(f, "peer")).map_err(e)?;
            o.insert("shared".into(), hex(&private.ecdh(&peer).map_err(e)?));
        }
        "ecdh_pub" => {
            let private = ecdh_curve(&f["curve"])
                .private_key_from_bytes(&b(f, "priv"))
                .map_err(e)?;
            o.insert("pub".into(), hex(&private.public_key().bytes()));
        }
        "ec_pub" => {
            let curve = curve_of(&f["curve"]);
            let d = b(f, "d");
            let (x, y) = curve.scalar_base_mult(&d);
            let private = ecdsa::PrivateKey {
                public_key: ecdsa::PublicKey {
                    curve,
                    x: x.clone(),
                    y: y.clone(),
                },
                d: Int::from_be_bytes(&d),
            };
            o.insert("x".into(), bn(&x));
            o.insert("y".into(), bn(&y));
            o.insert("raw".into(), hex(&private.bytes().map_err(e)?));
        }
        "ec_det" | "ec_sign" => {
            let curve = curve_of(&f["curve"]);
            let d = Int::from_be_bytes(&b(f, "d"));
            let (x, y) = curve.scalar_base_mult(d.as_be_bytes());
            let key = ecdsa::PrivateKey {
                public_key: ecdsa::PublicKey {
                    curve,
                    x: x.clone(),
                    y: y.clone(),
                },
                d,
            };
            let digest = b(f, "digest");
            let sig = if f["op"] == "ec_det" {
                let hash = hash_of(&f["hash"]);
                key.sign(&digest, Some(&hash)).map_err(e)?
            } else {
                ecdsa::sign_asn1(&key, &digest).map_err(e)?
            };
            o.insert("sig".into(), hex(&sig));
            o.insert("x".into(), bn(&x));
            o.insert("y".into(), bn(&y));
        }
        "ec_verify" => {
            let public = ecdsa::PublicKey {
                curve: curve_of(&f["curve"]),
                x: n(f, "x"),
                y: n(f, "y"),
            };
            o.insert(
                "ok".into(),
                ok(ecdsa::verify_asn1(&public, &b(f, "digest"), &b(f, "sig"))),
            );
        }
        "el_basemult" => {
            let (x, y) = curve_of(&f["curve"]).scalar_base_mult(&b(f, "k"));
            o.insert("x".into(), bn(&x));
            o.insert("y".into(), bn(&y));
        }
        "el_mult" => {
            let (x, y) = curve_of(&f["curve"]).scalar_mult(&n(f, "x"), &n(f, "y"), &b(f, "k"));
            o.insert("x".into(), bn(&x));
            o.insert("y".into(), bn(&y));
        }
        "el_add" => {
            let (x, y) =
                curve_of(&f["curve"]).add(&n(f, "x"), &n(f, "y"), &n(f, "x2"), &n(f, "y2"));
            o.insert("x".into(), bn(&x));
            o.insert("y".into(), bn(&y));
        }
        "el_double" => {
            let (x, y) = curve_of(&f["curve"]).double(&n(f, "x"), &n(f, "y"));
            o.insert("x".into(), bn(&x));
            o.insert("y".into(), bn(&y));
        }
        "el_unmarshal" | "el_unmarshalc" => {
            let curve = curve_of(&f["curve"]);
            let point = if f["op"] == "el_unmarshal" {
                elliptic::unmarshal(curve.as_ref(), &b(f, "data"))
            } else {
                elliptic::unmarshal_compressed(curve.as_ref(), &b(f, "data"))
            };
            let (x, y) = point.ok_or("invalid")?;
            o.insert("x".into(), bn(&x));
            o.insert("y".into(), bn(&y));
            o.insert("m".into(), hex(&elliptic::marshal(curve.as_ref(), &x, &y)));
            o.insert(
                "mc".into(),
                hex(&elliptic::marshal_compressed(curve.as_ref(), &x, &y)),
            );
        }
        "rsa_gen" => {
            let key = rsa::generate_key(int(f, "bits") as usize).map_err(e)?;
            o.insert("key".into(), hex(&key.to_pkcs1_der().map_err(e)?));
        }
        "rsa_p1_sign" => {
            let sig = rsa::sign_pkcs1v15(&rsa_key(f)?, Some(hash_of(&f["hash"])), &b(f, "digest"))
                .map_err(e)?;
            o.insert("sig".into(), hex(&sig));
        }
        "rsa_p1_verify" => {
            let key = rsa_key(f)?;
            let result = rsa::verify_pkcs1v15(
                &key.public_key,
                Some(hash_of(&f["hash"])),
                &b(f, "digest"),
                &b(f, "sig"),
            );
            o.insert("ok".into(), ok(result.is_ok()));
        }
        "rsa_pss_sign" => {
            let opts = rsa::PSSOptions {
                salt_length: int(f, "salt"),
                hash: None,
            };
            let sig = rsa::sign_pss(
                &rsa_key(f)?,
                hash_of(&f["hash"]),
                &b(f, "digest"),
                Some(&opts),
            )
            .map_err(e)?;
            o.insert("sig".into(), hex(&sig));
        }
        "rsa_pss_verify" => {
            let key = rsa_key(f)?;
            let opts = rsa::PSSOptions {
                salt_length: int(f, "salt"),
                hash: None,
            };
            let result = rsa::verify_pss(
                &key.public_key,
                hash_of(&f["hash"]),
                &b(f, "digest"),
                &b(f, "sig"),
                Some(&opts),
            );
            o.insert("ok".into(), ok(result.is_ok()));
        }
        "rsa_oaep_enc" => {
            let key = rsa_key(f)?;
            let opts = rsa::OAEPOptions {
                hash: Some(hash_of(&f["hash"])),
                mgf_hash: Some(hash_of(&f["mgf"])),
                label: b(f, "label"),
            };
            let ct =
                rsa::encrypt_oaep_with_options(&key.public_key, &b(f, "msg"), &opts).map_err(e)?;
            o.insert("ct".into(), hex(&ct));
        }
        "rsa_oaep_dec" => {
            let opts = rsa::OAEPOptions {
                hash: Some(hash_of(&f["hash"])),
                mgf_hash: Some(hash_of(&f["mgf"])),
                label: b(f, "label"),
            };
            let pt = rsa_key(f)?.decrypt(&b(f, "ct"), Some(&opts)).map_err(e)?;
            o.insert("msg".into(), hex(&pt));
        }
        "rsa_p1_enc" => {
            let key = rsa_key(f)?;
            let ct = rsa::encrypt_pkcs1v15(&key.public_key, &b(f, "msg")).map_err(e)?;
            o.insert("ct".into(), hex(&ct));
        }
        "rsa_p1_dec" => {
            let pt = rsa::decrypt_pkcs1v15(&rsa_key(f)?, &b(f, "ct")).map_err(e)?;
            o.insert("msg".into(), hex(&pt));
        }
        "mk_ek" => {
            let seed = b(f, "seed");
            let ek = if f["param"] == "768" {
                mlkem::new_decapsulation_key768(&seed)
                    .map_err(e)?
                    .encapsulation_key()
                    .bytes()
            } else {
                mlkem::new_decapsulation_key1024(&seed)
                    .map_err(e)?
                    .encapsulation_key()
                    .bytes()
            };
            o.insert("ek".into(), hex(&ek));
        }
        "mk_dec" => {
            let (seed, ct) = (b(f, "seed"), b(f, "ct"));
            let key = if f["param"] == "768" {
                mlkem::new_decapsulation_key768(&seed)
                    .map_err(e)?
                    .decapsulate(&ct)
            } else {
                mlkem::new_decapsulation_key1024(&seed)
                    .map_err(e)?
                    .decapsulate(&ct)
            };
            o.insert("k".into(), hex(&key.map_err(e)?));
        }
        "mk_enc" => {
            let (ek, m) = (b(f, "ek"), b(f, "m"));
            let (k, c) = if f["param"] == "768" {
                let key = mlkem::new_encapsulation_key768(&ek).map_err(e)?;
                mlkem::mlkemtest::encapsulate768(&key, &m).map_err(e)?
            } else {
                let key = mlkem::new_encapsulation_key1024(&ek).map_err(e)?;
                mlkem::mlkemtest::encapsulate1024(&key, &m).map_err(e)?
            };
            o.insert("k".into(), hex(&k));
            o.insert("c".into(), hex(&c));
        }
        "mk_encr" => {
            let ek = b(f, "ek");
            let (k, c) = if f["param"] == "768" {
                mlkem::new_encapsulation_key768(&ek)
                    .map_err(e)?
                    .encapsulate()
            } else {
                mlkem::new_encapsulation_key1024(&ek)
                    .map_err(e)?
                    .encapsulate()
            };
            o.insert("k".into(), hex(&k));
            o.insert("c".into(), hex(&c));
        }
        "md_pub" => {
            let key = mldsa::PrivateKey::from_seed(mldsa_params(&f["param"]), &b(f, "seed"))
                .map_err(e)?;
            o.insert("pub".into(), hex(&key.public_key().bytes()));
        }
        "md_sign" | "md_sign_rand" => {
            let key = mldsa::PrivateKey::from_seed(mldsa_params(&f["param"]), &b(f, "seed"))
                .map_err(e)?;
            let opts = mldsa::Options {
                context: String::from_utf8(b(f, "ctx")).expect("text"),
                hash: None,
            };
            let sig = if f["op"] == "md_sign" {
                key.sign_deterministic(&b(f, "msg"), Some(&opts))
            } else {
                key.sign(&b(f, "msg"), Some(&opts))
            }
            .map_err(e)?;
            o.insert("sig".into(), hex(&sig));
            o.insert("pub".into(), hex(&key.public_key().bytes()));
        }
        "md_verify" => {
            let public =
                mldsa::PublicKey::from_bytes(mldsa_params(&f["param"]), &b(f, "pub")).map_err(e)?;
            let opts = mldsa::Options {
                context: String::from_utf8(b(f, "ctx")).expect("text"),
                hash: None,
            };
            let result = mldsa::verify(&public, &b(f, "msg"), &b(f, "sig"), Some(&opts));
            o.insert("ok".into(), ok(result.is_ok()));
        }
        "dsa_sign" => {
            let (r, s) = dsa::sign(&dsa_key(f), &b(f, "digest")).map_err(e)?;
            o.insert("r".into(), bn(&r));
            o.insert("s".into(), bn(&s));
        }
        "dsa_verify" => {
            let key = dsa_key(f);
            o.insert(
                "ok".into(),
                ok(dsa::verify(
                    &key.public_key,
                    &b(f, "digest"),
                    &n(f, "r"),
                    &n(f, "s"),
                )),
            );
        }
        "hp_seal" => {
            let (kem, kdf, aead) = hpke_suite(f)?;
            let public: Box<dyn hpke::PublicKey> = if f.get("pub").is_some_and(|p| !p.is_empty()) {
                kem.public_key_from_bytes(&b(f, "pub")).map_err(e)?
            } else {
                let key = kem.generate_key().map_err(e)?;
                o.insert("sk".into(), hex(&key.bytes().map_err(e)?));
                let public = key.public_key();
                o.insert("pub".into(), hex(&public.bytes()));
                public
            };
            let (enc, mut sender) =
                hpke::Sender::new(public.as_ref(), kdf.as_ref(), aead.as_ref(), &b(f, "info"))
                    .map_err(e)?;
            o.insert("enc".into(), hex(&enc));
            if int(f, "aead") != 65535 {
                let ct = sender.seal(&b(f, "aad"), &b(f, "pt")).map_err(e)?;
                o.insert("ct".into(), hex(&ct));
            }
            let exp = sender
                .export_bytes(&b(f, "ectx"), int(f, "elen") as usize)
                .map_err(e)?;
            o.insert("exp".into(), hex(&exp));
        }
        "hp_open" => {
            let (kem, kdf, aead) = hpke_suite(f)?;
            let key = kem.private_key_from_bytes(&b(f, "sk")).map_err(e)?;
            let mut recipient = hpke::Recipient::new(
                &b(f, "enc"),
                key.as_ref(),
                kdf.as_ref(),
                aead.as_ref(),
                &b(f, "info"),
            )
            .map_err(e)?;
            if int(f, "aead") != 65535 {
                let pt = recipient.open(&b(f, "aad"), &b(f, "ct")).map_err(e)?;
                o.insert("pt".into(), hex(&pt));
            }
            let exp = recipient
                .export_bytes(&b(f, "ectx"), int(f, "elen") as usize)
                .map_err(e)?;
            o.insert("exp".into(), hex(&exp));
        }
        other => return Err(format!("unknown op {other}")),
    }
    Ok(o)
}

fn main() {
    // Keep panics (Go panics the API also raises) quiet.
    std::panic::set_hook(Box::new(|_| {}));
    let stdin = io::stdin();
    let mut out = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.expect("read");
        let fields: Fields = line
            .split(' ')
            .map(|token| match token.split_once('=') {
                Some((key, value)) => (key.to_string(), value.to_string()),
                None => (token.to_string(), String::new()),
            })
            .collect();
        let result =
            catch_unwind(AssertUnwindSafe(|| run(&fields))).unwrap_or_else(|_| Err("panic".into()));
        let text = match result {
            Ok(map) => map
                .into_iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(" "),
            Err(_) => "err=1".to_string(),
        };
        writeln!(out, "{text}").expect("write");
    }
}
