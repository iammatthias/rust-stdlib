//! Rust side of tools/crypto_hash_check.py.
//!
//! Reads one case per line as space-separated `key=value` tokens (byte strings
//! are hex) and prints one line of `name=value` tokens per case, the same
//! protocol as tools/crypto_hash_oracle.go. `st.<hash>=` tokens carry the state
//! Go marshaled, which this probe unmarshals to resume hashing.

use std::collections::HashMap;
use std::io::{self, BufRead, Write};

use rust_stdlib_crypto::hash::{Hash as HashTrait, StateError};
use rust_stdlib_crypto::{hkdf, hmac, md5, pbkdf2, sha1, sha256, sha3, sha512, subtle, Hash};

/// A digest with the inherent state methods, usable through one interface.
trait Probe: HashTrait {
    fn marshal(&self) -> Vec<u8>;
    fn append(&self, into: &mut Vec<u8>);
    fn unmarshal(&mut self, bytes: &[u8]) -> Result<(), StateError>;
}

macro_rules! probe {
    ($($ty:ty),*) => {$(
        impl Probe for $ty {
            fn marshal(&self) -> Vec<u8> {
                self.marshal_binary()
            }
            fn append(&self, into: &mut Vec<u8>) {
                self.append_binary(into);
            }
            fn unmarshal(&mut self, bytes: &[u8]) -> Result<(), StateError> {
                self.unmarshal_binary(bytes)
            }
        }
    )*};
}

probe!(
    md5::Digest,
    sha1::Digest,
    sha256::Digest,
    sha512::Digest,
    sha3::Sha3
);

type Entry = (&'static str, Hash, fn() -> Box<dyn Probe>);

fn boxed<T: Probe + 'static>(value: T) -> Box<dyn Probe> {
    Box::new(value)
}

fn entries() -> Vec<Entry> {
    vec![
        ("md5", Hash::Md5, || boxed(md5::new())),
        ("sha1", Hash::Sha1, || boxed(sha1::new())),
        ("sha224", Hash::Sha224, || boxed(sha256::new224())),
        ("sha256", Hash::Sha256, || boxed(sha256::new())),
        ("sha384", Hash::Sha384, || boxed(sha512::new384())),
        ("sha512", Hash::Sha512, || boxed(sha512::new())),
        ("sha512_224", Hash::Sha512_224, || {
            boxed(sha512::new512_224())
        }),
        ("sha512_256", Hash::Sha512_256, || {
            boxed(sha512::new512_256())
        }),
        ("sha3_224", Hash::Sha3_224, || boxed(sha3::new224())),
        ("sha3_256", Hash::Sha3_256, || boxed(sha3::new256())),
        ("sha3_384", Hash::Sha3_384, || boxed(sha3::new384())),
        ("sha3_512", Hash::Sha3_512, || boxed(sha3::new512())),
    ]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd-length hex");
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex digit"))
        .collect()
}

fn failure(error: impl std::fmt::Display) -> String {
    format!("err:{}", error.to_string().replace(' ', "_"))
}

fn result<E: std::fmt::Display>(outcome: Result<Vec<u8>, E>) -> String {
    match outcome {
        Ok(bytes) => hex(&bytes),
        Err(error) => failure(error),
    }
}

fn write_chunks(sink: &mut dyn Write, data: &[u8], chunk: usize) {
    for piece in data.chunks(chunk) {
        sink.write_all(piece).expect("hash writes cannot fail");
    }
}

fn sum_of<T: HashTrait + ?Sized>(hash: &T) -> Vec<u8> {
    let mut out = Vec::new();
    hash.sum(&mut out);
    out
}

fn run(fields: &HashMap<String, String>) -> Vec<String> {
    let mut results = Vec::new();
    let mut emit = |name: String, value: String| results.push(format!("{name}={value}"));
    let bytes = |key: &str| unhex(&fields[key]);
    let int = |key: &str| fields[key].parse::<i64>().expect("integer field");

    if fields.get("static").map(String::as_str) == Some("1") {
        for (index, hash) in Hash::ALL.iter().enumerate() {
            emit(
                format!("hash.{}", index + 1),
                format!(
                    "{},{},{}",
                    hash.to_string().replace(' ', "_"),
                    hash.size(),
                    hash.available()
                ),
            );
        }
        return results;
    }

    let (data, key, salt, info) = (bytes("data"), bytes("key"), bytes("salt"), bytes("info"));
    let split = (int("split") as usize).min(data.len());
    let chunk = int("chunk") as usize;
    let key_len = int("klen") as usize;
    let iterations = int("iter") as u32;

    for (name, algorithm, make) in entries() {
        let mut full = make();
        write_chunks(&mut full, &data, chunk);
        emit(format!("sum.{name}"), hex(&sum_of(&*full)));
        emit(
            format!("sizes.{name}"),
            format!("{},{}", full.size(), full.block_size()),
        );

        full.write_all(&[1]).unwrap();
        let mut again = make();
        again.write_all(&data).unwrap();
        again.write_all(&[1]).unwrap();
        emit(
            format!("sumagain.{name}"),
            format!("{},{}", hex(&sum_of(&*full)), hex(&sum_of(&*again))),
        );

        let mut prefix = make();
        write_chunks(&mut prefix, &data[..split], chunk);
        let state = prefix.marshal();
        emit(format!("state.{name}"), hex(&state));
        let mut appended = vec![9, 9];
        prefix.append(&mut appended);
        emit(format!("appended.{name}"), hex(&appended));

        let mut resumed = make();
        resumed
            .unmarshal(&unhex(&fields[&format!("st.{name}")]))
            .expect("Go state is accepted");
        resumed.write_all(&data[split..]).unwrap();
        emit(format!("resumed.{name}"), hex(&sum_of(&*resumed)));

        let mut clone = prefix.clone_hash();
        clone.write_all(&data[split..]).unwrap();
        emit(format!("clone.{name}"), hex(&sum_of(&*clone)));

        let mut bad = state.clone();
        bad[0] ^= 0xff;
        emit(
            format!("badid.{name}"),
            failure(make().unmarshal(&bad).unwrap_err()),
        );
        emit(
            format!("badsize.{name}"),
            failure(make().unmarshal(&state[..state.len() - 1]).unwrap_err()),
        );

        let new_hash = || algorithm.new().expect("implemented hash");
        let mut mac = hmac::new(new_hash, &key).unwrap();
        mac.write_all(&data).unwrap();
        emit(format!("hmac.{name}"), hex(&sum_of(&mac)));
        mac.reset();
        mac.write_all(&data[..split]).unwrap();
        mac.write_all(&data[split..]).unwrap();
        emit(
            format!("hmacreset.{name}"),
            format!("{},{},{}", hex(&sum_of(&mac)), mac.size(), mac.block_size()),
        );

        emit(
            format!("hkdf_extract.{name}"),
            result(hkdf::extract(new_hash, &key, &salt)),
        );
        emit(
            format!("hkdf_expand.{name}"),
            result(hkdf::expand(new_hash, &key, &info, key_len)),
        );
        emit(
            format!("hkdf_key.{name}"),
            result(hkdf::key(new_hash, &key, &salt, &info, key_len)),
        );
        emit(
            format!("pbkdf2.{name}"),
            result(pbkdf2::key(new_hash, &key, &salt, iterations, key_len)),
        );
    }

    let shake_len = int("slen") as usize;
    let (custom_name, custom) = (bytes("cn"), bytes("cs"));
    let read_twice = |shake: &mut sha3::Shake| {
        let mut output = vec![0; shake_len];
        let first = shake_len / 3;
        shake.read(&mut output[..first]);
        shake.read(&mut output[first..]);
        hex(&output)
    };
    let mut s128 = sha3::shake128();
    let mut s256 = sha3::shake256();
    let mut c128 = sha3::cshake128(&custom_name, &custom);
    let mut c256 = sha3::cshake256(&custom_name, &custom);
    for shake in [&mut s128, &mut s256, &mut c128, &mut c256] {
        write_chunks(shake, &data, chunk);
    }
    emit("shake128".into(), read_twice(&mut s128));
    emit("shake256".into(), read_twice(&mut s256));
    emit("cshake128".into(), read_twice(&mut c128));
    emit("cshake256".into(), read_twice(&mut c256));
    emit(
        "shakeblock".into(),
        format!(
            "{},{},{},{}",
            s128.block_size(),
            s256.block_size(),
            c128.block_size(),
            c256.block_size()
        ),
    );
    c128.reset();
    c128.write_all(&data).unwrap();
    let mut again = vec![0; shake_len];
    c128.read(&mut again);
    emit("cshake128reset".into(), hex(&again));
    emit(
        "sumshake128".into(),
        hex(&sha3::sum_shake128(&data, shake_len)),
    );
    emit(
        "sumshake256".into(),
        hex(&sha3::sum_shake256(&data, shake_len)),
    );
    let oneshots: Vec<(&str, Vec<u8>)> = vec![
        ("md5", md5::sum(&data).to_vec()),
        ("sha1", sha1::sum(&data).to_vec()),
        ("sha224", sha256::sum224(&data).to_vec()),
        ("sha256", sha256::sum256(&data).to_vec()),
        ("sha384", sha512::sum384(&data).to_vec()),
        ("sha512", sha512::sum512(&data).to_vec()),
        ("sha512_224", sha512::sum512_224(&data).to_vec()),
        ("sha512_256", sha512::sum512_256(&data).to_vec()),
        ("sha3_224", sha3::sum224(&data).to_vec()),
        ("sha3_256", sha3::sum256(&data).to_vec()),
        ("sha3_384", sha3::sum384(&data).to_vec()),
        ("sha3_512", sha3::sum512(&data).to_vec()),
    ];
    for (name, sum) in oneshots {
        emit(format!("oneshot.{name}"), hex(&sum));
    }

    let (x, y) = (int("x") as i32, int("y") as i32);
    let v = (int("v") & 1) as i32;
    emit(
        "compare".into(),
        subtle::constant_time_compare(&data, &key).to_string(),
    );
    emit(
        "compare_same".into(),
        subtle::constant_time_compare(&data, &data.clone()).to_string(),
    );
    emit(
        "hmacequal".into(),
        format!("{},{}", hmac::equal(&data, &key), hmac::equal(&data, &data)),
    );
    emit(
        "select".into(),
        subtle::constant_time_select(v, x, y).to_string(),
    );
    emit(
        "byteeq".into(),
        subtle::constant_time_byte_eq(x as u8, y as u8).to_string(),
    );
    emit("eq".into(), subtle::constant_time_eq(x, y).to_string());
    if x >= 0 && y >= 0 {
        emit(
            "lesseq".into(),
            subtle::constant_time_less_or_eq(x, y).to_string(),
        );
    }
    let mut dst = vec![0; data.len().min(key.len())];
    let n = subtle::xor_bytes(&mut dst, &data, &key);
    emit("xor".into(), format!("{n},{}", hex(&dst)));
    let mut target = data.clone();
    if key.len() >= data.len() {
        subtle::constant_time_copy(v, &mut target, &key[..data.len()]);
    }
    emit("copy".into(), hex(&target));

    results.sort();
    results
}

fn main() {
    let stdin = io::stdin();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line.expect("stdin");
        let fields: HashMap<String, String> = line
            .split(' ')
            .map(|token| {
                let (key, value) = token.split_once('=').unwrap_or((token, ""));
                (key.to_string(), value.to_string())
            })
            .collect();
        writeln!(out, "{}", run(&fields).join(" ")).expect("stdout");
    }
}
