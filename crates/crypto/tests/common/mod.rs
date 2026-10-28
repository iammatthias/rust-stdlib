//! Fixture loading shared by the crypto integration tests.
#![allow(dead_code)]

pub mod json;

use std::path::Path;

use rust_stdlib_crypto::hash::{Hash as HashTrait, StateError};
use rust_stdlib_crypto::{md5, sha1, sha256, sha3, sha512};

/// One typed field of a fixture row (see tools/crypto_vectors_gen.go).
pub struct Field(String);

impl Field {
    /// Raw bytes of an `s:` field.
    pub fn bytes(&self) -> Vec<u8> {
        let hex = self.0.strip_prefix("s:").expect("string field");
        (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).expect("hex"))
            .collect()
    }

    pub fn text(&self) -> String {
        String::from_utf8(self.bytes()).expect("ASCII text")
    }

    /// The lowercase hex text an `s:` field decodes to, for Go's `out string` columns.
    pub fn hex_text(&self) -> String {
        self.text()
    }

    pub fn int(&self) -> usize {
        self.0
            .strip_prefix("i:")
            .expect("int field")
            .parse()
            .expect("integer")
    }

    /// The Go identifier of an `f:` field, such as `sha256.New`.
    pub fn name(&self) -> &str {
        self.0.strip_prefix("f:").expect("function field")
    }
}

pub fn fixture(name: &str) -> Vec<Vec<Field>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(|line| {
            line.split('\t')
                .map(|field| Field(field.to_string()))
                .collect()
        })
        .collect()
}

/// Rows of a plain fixture written by tools/crypto_asym_vectors_gen.py:
/// tab-separated text fields; `#` lines are comments.
pub fn rows(name: &str) -> Vec<Vec<String>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(|line| line.split('\t').map(str::to_string).collect())
        .collect()
}

pub fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd hex length");
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A digest with its inherent state methods behind one interface.
pub trait Digest: HashTrait {
    fn marshal(&self) -> Vec<u8>;
    fn unmarshal(&mut self, bytes: &[u8]) -> Result<(), StateError>;
    fn boxed_clone(&self) -> Box<dyn Digest>;
}

macro_rules! digest {
    ($($ty:ty),*) => {$(
        impl Digest for $ty {
            fn marshal(&self) -> Vec<u8> {
                self.marshal_binary()
            }
            fn unmarshal(&mut self, bytes: &[u8]) -> Result<(), StateError> {
                self.unmarshal_binary(bytes)
            }
            fn boxed_clone(&self) -> Box<dyn Digest> {
                Box::new(self.clone())
            }
        }
    )*};
}

digest!(
    md5::Digest,
    sha1::Digest,
    sha256::Digest,
    sha512::Digest,
    sha3::Sha3
);

pub fn boxed<T: Digest + 'static>(value: T) -> Box<dyn Digest> {
    Box::new(value)
}

/// Go's `TestGolden` and `TestGoldenMarshal` for one `golden` table.
pub fn check_golden(
    rows: Vec<Vec<Field>>,
    make: fn() -> Box<dyn Digest>,
    sum: fn(&[u8]) -> Vec<u8>,
) {
    assert!(rows.len() > 25);
    for row in rows {
        let (out, input, half_state) = (row[0].hex_text(), row[1].bytes(), row[2].bytes());
        assert_eq!(
            hex(&sum(&input)),
            out,
            "one-shot sum of {:?}",
            String::from_utf8_lossy(&input)
        );

        // Writes in one piece, in two pieces with an interleaved Sum, and unaligned.
        let mut hash = make();
        for pass in 0..7 {
            hash.reset();
            let mut padded = vec![0u8; input.len() + 4];
            match pass {
                0 | 1 => hash.write_all_bytes(&input),
                2 => {
                    hash.write_all_bytes(&input[..input.len() / 2]);
                    let mut scratch = Vec::new();
                    hash.sum(&mut scratch);
                    hash.write_all_bytes(&input[input.len() / 2..]);
                }
                _ => {
                    let offset = pass - 2;
                    padded[offset..offset + input.len()].copy_from_slice(&input);
                    hash.write_all_bytes(&padded[offset..offset + input.len()]);
                }
            }
            let mut got = Vec::new();
            hash.sum(&mut got);
            assert_eq!(
                hex(&got),
                out,
                "pass {pass} of {:?}",
                String::from_utf8_lossy(&input)
            );
            // Sum appends and leaves the state running.
            let mut again = b"prefix".to_vec();
            hash.sum(&mut again);
            assert_eq!(&again[6..], got.as_slice());
        }

        // Marshal after the first half, compare Go's bytes, then resume from them.
        let half = input.len() / 2;
        let mut first = make();
        first.write_all_bytes(&input[..half]);
        assert_eq!(
            first.marshal(),
            half_state,
            "half state of {:?}",
            String::from_utf8_lossy(&input)
        );
        let mut resumed = make();
        resumed
            .unmarshal(&half_state)
            .expect("Go's state is accepted");
        resumed.write_all_bytes(&input[half..]);
        let mut got = Vec::new();
        resumed.sum(&mut got);
        assert_eq!(
            hex(&got),
            out,
            "resumed {:?}",
            String::from_utf8_lossy(&input)
        );
    }
}

fn x509_fixture_rows(name: &str) -> Vec<Vec<String>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/x509")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
        .lines()
        .map(|line| line.split('\t').map(str::to_string).collect())
        .collect()
}

/// A hexadecimal constant of Go's key tests (tests/fixtures/x509/hex_consts.tsv).
pub fn fixture_hex_const(name: &str) -> Vec<u8> {
    let row = x509_fixture_rows("hex_consts.tsv")
        .into_iter()
        .find(|row| row[0] == name)
        .unwrap_or_else(|| panic!("no hex constant {name}"));
    unhex(&row[1])
}

/// The DER of a PEM constant of Go's tests (tests/fixtures/x509/certs.tsv).
pub fn fixture_cert_der(name: &str) -> Vec<u8> {
    let row = x509_fixture_rows("certs.tsv")
        .into_iter()
        .find(|row| row[0] == name)
        .unwrap_or_else(|| panic!("no PEM constant {name}"));
    let wrapped = format!("-----BEGIN X-----\n{}\n-----END X-----\n", row[2]);
    rust_stdlib_crypto::x509::pem::decode(wrapped.as_bytes())
        .0
        .expect("PEM block")
        .bytes
}

pub trait WriteBytes {
    fn write_all_bytes(&mut self, bytes: &[u8]);
}

impl<T: HashTrait + ?Sized> WriteBytes for T {
    fn write_all_bytes(&mut self, bytes: &[u8]) {
        std::io::Write::write_all(self, bytes).expect("hash writes cannot fail");
    }
}
