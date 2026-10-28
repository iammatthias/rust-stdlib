//! crypto/x509 key encodings, ported from Go's x509_test.go (PKCS #1 and PKIX
//! tests), pkcs8_test.go and sec1_test.go.

mod common;

use rust_stdlib_crypto::bigint::Int;
use rust_stdlib_crypto::x509::{
    marshal_ec_private_key, marshal_pkcs1_private_key, marshal_pkcs1_public_key,
    marshal_pkcs8_private_key, marshal_pkix_public_key, parse_certificate_request, parse_der_crl,
    parse_ec_private_key, parse_pkcs1_private_key, parse_pkcs1_public_key, parse_pkcs8_private_key,
    parse_pkix_public_key, pem, BigInt, PrivateKey, PublicKey,
};
use rust_stdlib_crypto::{ecdsa, elliptic, rsa};

fn fixture_lines(path: &str) -> Vec<Vec<String>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/x509")
        .join(path);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .lines()
        .map(|l| l.split('\t').map(str::to_string).collect())
        .collect()
}

fn hex_const(name: &str) -> Vec<u8> {
    for row in fixture_lines("hex_consts.tsv") {
        if row[0] == name {
            return common::unhex(&row[1]);
        }
    }
    panic!("no hex constant {name}");
}

fn const_der(name: &str) -> Vec<u8> {
    for row in fixture_lines("certs.tsv") {
        if row[0] == name {
            return pem_base64(&row[2]);
        }
    }
    panic!("no PEM constant {name}");
}

fn pem_base64(text: &str) -> Vec<u8> {
    let wrapped = format!("-----BEGIN X-----\n{text}\n-----END X-----\n");
    pem::decode(wrapped.as_bytes()).0.unwrap().bytes
}

fn dec(s: &str) -> Int {
    BigInt::from_decimal(s).unwrap().magnitude().clone()
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if content.len() < 128 {
        out.push(content.len() as u8);
    } else {
        let bytes = content.len().to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (8 - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

fn der_int(v: &Int) -> Vec<u8> {
    let mut bytes = v.to_be_bytes();
    if bytes.is_empty() || bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    tlv(2, &bytes)
}

fn rsa_private_key() -> rsa::PrivateKey {
    rsa::PrivateKey {
        public_key: rsa::PublicKey {
            n: dec("124737666279038955318614287965056875799409043964547386061640914307192830334599556034328900586693254156136128122194531292927142396093148164407300419162827624945636708870992355233833321488652786796134504707628792159725681555822420087112284637501705261187690946267527866880072856272532711620639179596808018872997"),
            e: 65537,
        },
        d: dec("69322600686866301945688231018559005300304807960033948687567105312977055197015197977971637657636780793670599180105424702854759606794705928621125408040473426339714144598640466128488132656829419518221592374964225347786430566310906679585739468938549035854760501049443920822523780156843263434219450229353270690889"),
        primes: vec![
            dec("11405025354575369741595561190164746858706645478381139288033759331174478411254205003127028642766986913445391069745480057674348716675323735886284176682955723"),
            dec("10937079261204603443118731009201819560867324167189758120988909645641782263430128449826989846631183550578761324239709121189827307416350485191350050332642639"),
        ],
        precomputed: rsa::PrecomputedValues::default(),
    }
}

#[test]
fn parse_pkcs1_private_key_test() {
    let der = const_der("pemPrivateKey");
    let priv_key = parse_pkcs1_private_key(&der).unwrap();
    let want = rsa_private_key();
    assert_eq!(priv_key.public_key.n, want.public_key.n);
    assert_eq!(priv_key.public_key.e, want.public_key.e);
    assert_eq!(priv_key.d, want.d);
    assert_eq!(priv_key.primes[0], want.primes[0]);
    assert_eq!(priv_key.primes[1], want.primes[1]);

    // This private key includes an invalid prime that Validate rejects.
    let data = b"0\x16\x02\x00\x02\x02\x7f\x00\x02\x0200\x02\x0200\x02\x02\x00\x01\x02\x02\x7f\x00";
    assert!(
        parse_pkcs1_private_key(data).is_err(),
        "invalid private key parsed"
    );

    // A partial key without CRT values still parses.
    let mut content = tlv(2, &[0]);
    content.extend(der_int(&priv_key.public_key.n));
    content.extend(der_int(&Int::from_u64(priv_key.public_key.e as u64)));
    content.extend(der_int(&priv_key.d));
    content.extend(der_int(&priv_key.primes[0]));
    content.extend(der_int(&priv_key.primes[1]));
    let partial = tlv(0x30, &content);
    let p2 = parse_pkcs1_private_key(&partial).unwrap();
    assert!(
        p2.equal(&priv_key),
        "partial private key did not match original key"
    );
    assert!(
        p2.precomputed.dp.is_some() && p2.precomputed.dq.is_some() && p2.precomputed.qinv.is_some(),
        "precomputed values not recomputed"
    );
}

#[test]
fn pkcs1_mismatch_public_key_format() {
    let der = hex_const("pkixPublicKey");
    let err = parse_pkcs1_public_key(&der).unwrap_err();
    assert!(
        err.to_string().contains("use ParsePKIXPublicKey instead"),
        "{err}"
    );
}

#[test]
fn marshal_invalid_public_key() {
    // A point that is not on the curve.
    let key = ecdsa::PublicKey {
        curve: elliptic::p256(),
        x: Int::from_u64(1),
        y: Int::from_u64(2),
    };
    assert!(marshal_pkix_public_key(&key).is_err());
}

fn test_parse_pkix_public_key(name: &str) -> PublicKey {
    let der = const_der(name);
    let pub_key = parse_pkix_public_key(&der).unwrap();
    let again = marshal_pkix_public_key(&pub_key).unwrap();
    assert_eq!(again, der, "reserialization of {name} didn't match");
    pub_key
}

#[test]
fn parse_pkix_public_key_test() {
    assert!(matches!(
        test_parse_pkix_public_key("pemPublicKey"),
        PublicKey::Rsa(_)
    ));
    assert!(matches!(
        test_parse_pkix_public_key("pemEd25519Key"),
        PublicKey::Ed25519(_)
    ));
    match test_parse_pkix_public_key("pemX25519Key") {
        PublicKey::Ecdh(k) => assert_eq!(k.curve().name(), "X25519"),
        other => panic!("not an X25519 key: {other:?}"),
    }
}

#[test]
fn pkix_mismatch_public_key_format() {
    let der = hex_const("pkcs1PublicKey");
    let err = parse_pkix_public_key(&der).unwrap_err();
    assert!(
        err.to_string().contains("use ParsePKCS1PublicKey instead"),
        "{err}"
    );
}

#[test]
fn marshal_rsa_private_key() {
    let priv_key = rsa::PrivateKey {
        public_key: rsa::PublicKey {
            n: dec("16346378922382193400538269749936049106320265317511766357599732575277382844051791096569333808598921852351577762718529818072849191122419410612033592401403764925096136759934497687765453905884149505175426053037420486697072448609022753683683718057795566811401938833367954642951433473337066311978821180526439641496973296037000052546108507805269279414789035461158073156772151892452251106173507240488993608650881929629163465099476849643165682709047462010581308719577053905787496296934240246311806555924593059995202856826239801816771116902778517096212527979497399966526283516447337775509777558018145573127308919204297111496233"),
            e: 3,
        },
        d: dec("10897585948254795600358846499957366070880176878341177571733155050184921896034527397712889205732614568234385175145686545381899460748279607074689061600935843283397424506622998458510302603922766336783617368686090042765718290914099334449154829375179958369993407724946186243249568928237086215759259909861748642124071874879861299389874230489928271621259294894142840428407196932444474088857746123104978617098858619445675532587787023228852383149557470077802718705420275739737958953794088728369933811184572620857678792001136676902250566845618813972833750098806496641114644760255910789397593428910198080271317419213080834885003"),
        primes: vec![
            dec("1025363189502892836833747188838978207017355117492483312747347695538428729137306368764177201532277413433182799108299960196606011786562992097313508180436744488171474690412562218914213688661311117337381958560443"),
            dec("3467903426626310123395340254094941045497208049900750380025518552334536945536837294961497712862519984786362199788654739924501424784631315081391467293694361474867825728031147665777546570788493758372218019373"),
            dec("4597024781409332673052708605078359346966325141767460991205742124888960305710298765592730135879076084498363772408626791576005136245060321874472727132746643162385746062759369754202494417496879741537284589047"),
        ],
        precomputed: rsa::PrecomputedValues::default(),
    };
    let der = marshal_pkcs1_private_key(&priv_key);
    let priv2 = parse_pkcs1_private_key(&der).unwrap();
    assert_eq!(priv_key.public_key.n, priv2.public_key.n);
    assert_eq!(priv_key.public_key.e, priv2.public_key.e);
    assert_eq!(priv_key.d, priv2.d);
    assert_eq!(priv2.primes.len(), 3);
    assert_eq!(priv_key.primes, priv2.primes);
}

#[test]
fn marshal_rsa_public_key() {
    let pub_key = rsa::PublicKey {
        n: dec("16346378922382193400538269749936049106320265317511766357599732575277382844051791096569333808598921852351577762718529818072849191122419410612033592401403764925096136759934497687765453905884149505175426053037420486697072448609022753683683718057795566811401938833367954642951433473337066311978821180526439641496973296037000052546108507805269279414789035461158073156772151892452251106173507240488993608650881929629163465099476849643165682709047462010581308719577053905787496296934240246311806555924593059995202856826239801816771116902778517096212527979497399966526283516447337775509777558018145573127308919204297111496233"),
        e: 3,
    };
    let der = marshal_pkcs1_public_key(&pub_key);
    let pub2 = parse_pkcs1_public_key(&der).unwrap();
    assert_eq!(pub_key, pub2);

    // (derBytes, expected error substring)
    let public_keys: Vec<(Vec<u8>, &str)> = vec![
        (vec![0x30, 6, 0x02, 1, 17, 0x02, 1, 3], ""),
        (vec![0x30, 6, 0x02, 1, 0xff, 0x02, 1, 3], "zero or negative"),
        (
            vec![0x30, 6, 0x02, 1, 17, 0x02, 1, 0xff],
            "zero or negative",
        ),
        (vec![0x30, 6, 0x02, 1, 17, 0x02, 1, 3, 1], "trailing data"),
        (
            vec![0x30, 9, 0x02, 1, 17, 0x02, 4, 0x7f, 0xff, 0xff, 0xff],
            "",
        ),
        (
            vec![0x30, 10, 0x02, 1, 17, 0x02, 5, 0x00, 0x80, 0x00, 0x00, 0x00],
            "large",
        ),
    ];
    for (i, (der, want)) in public_keys.iter().enumerate() {
        match parse_pkcs1_public_key(der) {
            Err(e) => {
                assert!(!want.is_empty(), "#{i}: unexpected failure: {e}");
                assert!(
                    e.to_string().contains(want),
                    "#{i}: expected error containing {want:?}, got {e}"
                );
            }
            Ok(key) => {
                assert!(want.is_empty(), "#{i}: unexpected success, got {key:?}");
                assert_eq!(
                    &marshal_pkcs1_public_key(&key),
                    der,
                    "#{i}: failed to reserialize"
                );
            }
        }
    }
}

#[test]
fn parse_ec_private_key_test() {
    let mut count = 0;
    for row in fixture_lines("hex_consts.tsv") {
        let Some(rest) = row[0].strip_prefix("ecKeyTests.") else {
            continue;
        };
        let should_reserialize = rest.ends_with(".true");
        let der = common::unhex(&row[1]);
        let key = parse_ec_private_key(&der)
            .unwrap_or_else(|e| panic!("#{count}: failed to decode EC private key: {e}"));
        let serialized = marshal_ec_private_key(&key).unwrap();
        assert_eq!(
            serialized == der,
            should_reserialize,
            "#{count}: original {der:x?}, reserialized {serialized:x?}"
        );
        count += 1;
    }
    assert_eq!(count, 3);
}

#[test]
fn ec_mismatch_key_format() {
    for (name, want) in [
        ("hexECTestPKCS8Key", "use ParsePKCS8PrivateKey instead"),
        ("hexECTestPKCS1Key", "use ParsePKCS1PrivateKey instead"),
    ] {
        let err = parse_ec_private_key(&hex_const(name)).unwrap_err();
        assert!(err.to_string().contains(want), "{name}: {err}");
    }
}

#[test]
fn pkcs8() {
    #[derive(Clone, Copy)]
    enum Kind {
        Rsa,
        Ecdsa,
        Ed25519,
        X25519,
    }
    let tests = [
        ("RSA private key", "pkcs8RSAPrivateKeyHex", Kind::Rsa, None),
        (
            "P-224 private key",
            "pkcs8P224PrivateKeyHex",
            Kind::Ecdsa,
            Some(elliptic::p224()),
        ),
        (
            "P-256 private key",
            "pkcs8P256PrivateKeyHex",
            Kind::Ecdsa,
            Some(elliptic::p256()),
        ),
        (
            "P-384 private key",
            "pkcs8P384PrivateKeyHex",
            Kind::Ecdsa,
            Some(elliptic::p384()),
        ),
        (
            "P-521 private key",
            "pkcs8P521PrivateKeyHex",
            Kind::Ecdsa,
            Some(elliptic::p521()),
        ),
        (
            "Ed25519 private key",
            "pkcs8Ed25519PrivateKeyHex",
            Kind::Ed25519,
            None,
        ),
        (
            "X25519 private key",
            "pkcs8X25519PrivateKeyHex",
            Kind::X25519,
            None,
        ),
    ];
    for (name, hex_name, kind, curve) in tests {
        let der = hex_const(hex_name);
        let key = parse_pkcs8_private_key(&der)
            .unwrap_or_else(|e| panic!("{name}: failed to decode PKCS#8: {e}"));
        match (&key, kind) {
            (PrivateKey::Rsa(_), Kind::Rsa) => {}
            (PrivateKey::Ed25519(_), Kind::Ed25519) => {}
            (PrivateKey::Ecdh(_), Kind::X25519) => {}
            (PrivateKey::Ecdsa(k), Kind::Ecdsa) => {
                assert!(
                    elliptic::same_curve(&k.public_key.curve, curve.as_ref().unwrap()),
                    "{name}: unexpected curve"
                );
            }
            _ => panic!("{name}: decoded PKCS#8 returned unexpected key type: {key:?}"),
        }
        let reserialised = marshal_pkcs8_private_key(key.as_any()).unwrap();
        assert_eq!(
            reserialised, der,
            "{name}: marshaled PKCS#8 didn't match original"
        );

        if let PrivateKey::Ecdsa(k) = &key {
            match k.ecdh() {
                Ok(ecdh_key) => {
                    let again = marshal_pkcs8_private_key(&ecdh_key).unwrap();
                    assert_eq!(
                        again, der,
                        "{name}: marshaled ECDH PKCS#8 didn't match original"
                    );
                }
                Err(e) => assert!(
                    elliptic::same_curve(&k.public_key.curve, &elliptic::p224()),
                    "{name}: failed to convert to ecdh: {e}"
                ),
            }
        }
    }
}

#[test]
fn pkcs8_mismatch_key_format() {
    for (name, want) in [
        ("hexPKCS8TestECKey", "use ParseECPrivateKey instead"),
        ("hexPKCS8TestPKCS1Key", "use ParsePKCS1PrivateKey instead"),
    ] {
        let err = parse_pkcs8_private_key(&hex_const(name)).unwrap_err();
        assert!(err.to_string().contains(want), "{name}: {err}");
    }
}

#[test]
fn pkcs1_mismatch_key_format() {
    for (name, want) in [
        ("hexPKCS1TestPKCS8Key", "use ParsePKCS8PrivateKey instead"),
        ("hexPKCS1TestECKey", "use ParseECPrivateKey instead"),
    ] {
        let err = parse_pkcs1_private_key(&hex_const(name)).unwrap_err();
        assert!(err.to_string().contains(want), "{name}: {err}");
    }
}

/// Malformed encodings and the exact error Go 1.27 returns for each (the
/// shortest example of every distinct message), from `go run` over
/// bit-flipped, retagged and truncated keys, requests and lists. Go prints the
/// address of a field's `tag` pointer in "tags don't match" errors; the
/// fixture and this crate use `0xc000000000` for it.
#[test]
fn asn1_error_text_matches_go() {
    let rows = fixture_lines("asn1_errors.tsv");
    assert!(rows.len() > 100);
    for row in rows {
        let (function, der, want) = (&row[0], common::unhex(&row[1]), &row[2]);
        let got = match function.as_str() {
            "ParsePKCS1PrivateKey" => parse_pkcs1_private_key(&der).err(),
            "ParsePKCS1PublicKey" => parse_pkcs1_public_key(&der).err(),
            "ParsePKCS8PrivateKey" => parse_pkcs8_private_key(&der).err(),
            "ParseECPrivateKey" => parse_ec_private_key(&der).err(),
            "ParsePKIXPublicKey" => parse_pkix_public_key(&der).err(),
            "ParseCertificateRequest" => parse_certificate_request(&der).err(),
            "ParseDERCRL" => parse_der_crl(&der).err(),
            other => panic!("unknown function {other}"),
        };
        let got = got.unwrap_or_else(|| panic!("{function} accepted {}", row[1]));
        assert_eq!(&got.to_string(), want, "{function} {}", row[1]);
    }
}

/// The PKCS #1 encoding of `pemPrivateKey` with its private exponent replaced.
fn pkcs1_with_private_exponent(d: &[u8]) -> Vec<u8> {
    /// The header and content lengths of the first DER element.
    fn tlv_lengths(data: &[u8]) -> (usize, usize) {
        if data[1] < 0x80 {
            return (2, usize::from(data[1]));
        }
        let count = usize::from(data[1] & 0x7f);
        let length = data[2..2 + count]
            .iter()
            .fold(0usize, |n, &b| n << 8 | usize::from(b));
        (2 + count, length)
    }
    let der = const_der("pemPrivateKey");
    let (header, length) = tlv_lengths(&der);
    let mut rest = &der[header..header + length];
    let mut fields = Vec::new();
    while !rest.is_empty() {
        let (header, length) = tlv_lengths(rest);
        fields.push(rest[..header + length].to_vec());
        rest = &rest[header + length..];
    }
    let mut value = d.to_vec();
    if value[0] & 0x80 != 0 {
        value.insert(0, 0);
    }
    fields[3] = tlv(2, &value);
    tlv(0x30, &fields.concat())
}

/// Go's `bigmod.Nat.SetBytes` names a private exponent that overflows the
/// modulus by its cause: more bytes than the modulus has 64-bit limbs, or a
/// value at least the modulus.
#[test]
fn parse_pkcs1_private_key_d_overflow_messages() {
    let n = rsa_private_key().public_key.n.to_be_bytes();
    let err = parse_pkcs1_private_key(&pkcs1_with_private_exponent(&n)).unwrap_err();
    assert_eq!(err.to_string(), "input overflows the modulus");
    let mut over = vec![0u8; n.len() + 1];
    over[0] = 1;
    let err = parse_pkcs1_private_key(&pkcs1_with_private_exponent(&over)).unwrap_err();
    assert_eq!(err.to_string(), "input overflows the modulus size");
}
