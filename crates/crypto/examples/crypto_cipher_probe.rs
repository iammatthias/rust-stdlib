//! Rust side of tools/crypto_cipher_check.py.
//!
//! Reads one case per line as space-separated `key=value` tokens (byte strings
//! are hex, lists are comma-separated) and prints one line of `name=value`
//! tokens per case, the same protocol as tools/crypto_cipher_oracle.go. Errors
//! print as `err:MESSAGE` with spaces replaced by underscores, as Go's panics
//! and errors do.

use std::collections::{BTreeMap, HashMap};
use std::io::{self, BufRead, Write};

use rust_stdlib_crypto::cipher::{self, Aead, Block, Error, Stream};
use rust_stdlib_crypto::{aes, des, rc4};

type Fields = HashMap<String, String>;
type Out = BTreeMap<String, String>;

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn bytes_of(fields: &Fields, key: &str) -> Vec<u8> {
    unhex(fields.get(key).map(String::as_str).unwrap_or(""))
}

fn int_of(fields: &Fields, key: &str) -> i64 {
    fields[key].parse().expect("integer")
}

fn ints_of(fields: &Fields, key: &str) -> Vec<i64> {
    match fields.get(key).map(String::as_str) {
        None | Some("") => Vec::new(),
        Some(list) => list
            .split(',')
            .map(|n| n.parse().expect("integer"))
            .collect(),
    }
}

fn message(text: impl std::fmt::Display) -> String {
    format!("err:{}", text.to_string().replace(' ', "_"))
}

/// The same trivial invertible Block as the Go oracle's customBlock.
struct CustomBlock {
    key: Vec<u8>,
}

impl Block for CustomBlock {
    fn block_size(&self) -> usize {
        self.key.len()
    }

    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> Result<(), Error> {
        for (i, k) in self.key.iter().enumerate() {
            dst[i] = src[i].rotate_left(3) ^ k;
        }
        Ok(())
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> Result<(), Error> {
        for (i, k) in self.key.iter().enumerate() {
            dst[i] = (src[i] ^ k).rotate_right(3);
        }
        Ok(())
    }
}

fn new_block(kind: &str, key: &[u8]) -> Result<Box<dyn Block>, String> {
    match kind {
        "aes" => aes::Cipher::new(key)
            .map(|c| Box::new(c) as Box<dyn Block>)
            .map_err(message),
        "des" => des::Cipher::new(key)
            .map(|c| Box::new(c) as Box<dyn Block>)
            .map_err(message),
        "tdes" => des::TripleDesCipher::new(key)
            .map(|c| Box::new(c) as Box<dyn Block>)
            .map_err(message),
        "custom" => Ok(Box::new(CustomBlock { key: key.to_vec() })),
        other => panic!("unknown cipher {other}"),
    }
}

fn block_case(f: &Fields, out: &mut Out) {
    let block = match new_block(&f["cipher"], &bytes_of(f, "key")) {
        Ok(block) => block,
        Err(error) => {
            out.insert("ctor".into(), error);
            return;
        }
    };
    out.insert("ctor".into(), "ok".into());
    out.insert("bs".into(), block.block_size().to_string());
    let input = bytes_of(f, "data");
    let dlen = int_of(f, "dlen") as usize;
    for dir in ["enc", "dec"] {
        let mut dst = vec![0; dlen];
        let result = if dir == "enc" {
            block.encrypt(&mut dst, &input)
        } else {
            block.decrypt(&mut dst, &input)
        };
        let text = match result {
            Ok(()) => format!("ok:{}", hex(&dst[..dlen.min(block.block_size())])),
            Err(error) => message(error),
        };
        out.insert(dir.into(), text);
    }
}

/// Cuts `data` into the chunk sizes in `chunks`, the last taking the rest;
/// `xs` holds, per chunk, how much longer (or shorter) dst is than src.
fn chunked(
    data: &[u8],
    chunks: &[i64],
    xs: &[i64],
    mut each: impl FnMut(usize, &[u8], &mut Vec<u8>) -> String,
) -> String {
    let mut results = Vec::new();
    let mut rest = data;
    for (i, &size) in chunks.iter().enumerate() {
        let n = if i == chunks.len() - 1 {
            rest.len()
        } else {
            (size as usize).min(rest.len())
        };
        let (src, tail) = rest.split_at(n);
        rest = tail;
        let x = xs.get(i).copied().unwrap_or(0);
        let mut dst = vec![0; (n as i64 + x).max(0) as usize];
        results.push(each(i, src, &mut dst));
    }
    results.join(";")
}

fn finish(result: Result<(), Error>, dst: &[u8], n: usize) -> String {
    match result {
        Ok(()) => format!("ok:{}", hex(&dst[..dst.len().min(n)])),
        Err(error) => message(error),
    }
}

enum Mode<'a> {
    Block(Box<dyn cipher::BlockMode + 'a>),
    Stream(Box<dyn Stream + 'a>),
}

fn mode_case(f: &Fields, out: &mut Out) {
    let block = match new_block(&f["cipher"], &bytes_of(f, "key")) {
        Ok(block) => block,
        Err(error) => {
            out.insert("ctor".into(), error);
            return;
        }
    };
    let iv = bytes_of(f, "iv");
    let made = match f["op"].as_str() {
        "cbce" => cipher::cbc_encrypter(block.as_ref(), &iv).map(Mode::Block),
        "cbcd" => cipher::cbc_decrypter(block.as_ref(), &iv).map(Mode::Block),
        "ctr" => cipher::ctr(block.as_ref(), &iv).map(Mode::Stream),
        "ofb" => cipher::ofb(block.as_ref(), &iv).map(Mode::Stream),
        "cfbe" => cipher::cfb_encrypter(block.as_ref(), &iv).map(Mode::Stream),
        "cfbd" => cipher::cfb_decrypter(block.as_ref(), &iv).map(Mode::Stream),
        other => panic!("unknown op {other}"),
    };
    let mut mode = match made {
        Ok(mode) => mode,
        Err(error) => {
            out.insert("ctor".into(), message(error));
            return;
        }
    };
    out.insert("ctor".into(), "ok".into());
    if let Mode::Block(block_mode) = &mode {
        out.insert("bs".into(), block_mode.block_size().to_string());
    }
    let result = chunked(
        &bytes_of(f, "data"),
        &ints_of(f, "chunks"),
        &ints_of(f, "xs"),
        |_, src, dst| {
            let result = match &mut mode {
                Mode::Block(m) => m.crypt_blocks(dst, src),
                Mode::Stream(s) => s.xor_key_stream(dst, src),
            };
            finish(result, dst, src.len())
        },
    );
    out.insert("r".into(), result);
}

fn rc4_case(f: &Fields, out: &mut Out) {
    let mut c = match rc4::Cipher::new(&bytes_of(f, "key")) {
        Ok(c) => c,
        Err(error) => {
            out.insert("ctor".into(), message(error));
            return;
        }
    };
    out.insert("ctor".into(), "ok".into());
    let reset_at = int_of(f, "reset");
    let result = chunked(
        &bytes_of(f, "data"),
        &ints_of(f, "chunks"),
        &ints_of(f, "xs"),
        |i, src, dst| {
            if i as i64 == reset_at {
                c.reset();
            }
            let result = c.xor_key_stream(dst, src);
            // Go indexes out of range here, which the oracle prints as "runtime".
            match result {
                Err(_) => "err:runtime".to_string(),
                Ok(()) => finish(Ok(()), dst, src.len()),
            }
        },
    );
    out.insert("r".into(), result);
}

fn sealed(aead: &dyn Aead, pre: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> String {
    let mut dst = pre.to_vec();
    match aead.seal(&mut dst, nonce, plaintext, aad) {
        Ok(()) => format!("ok:{}", hex(&dst)),
        Err(error) => message(error),
    }
}

fn opened(aead: &dyn Aead, pre: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> String {
    let mut dst = pre.to_vec();
    match aead.open(&mut dst, nonce, ciphertext, aad) {
        Ok(()) => format!("ok:{}", hex(&dst)),
        Err(error) => message(error),
    }
}

fn flip(bytes: &[u8], at: usize) -> Vec<u8> {
    let mut copy = bytes.to_vec();
    if !copy.is_empty() {
        let len = copy.len();
        copy[at % len] ^= 0x21;
    }
    copy
}

fn gcm_case(f: &Fields, out: &mut Out) {
    let block = match new_block(&f["cipher"], &bytes_of(f, "key")) {
        Ok(block) => block,
        Err(error) => {
            out.insert("ctor".into(), error);
            return;
        }
    };
    let made = match f["variant"].as_str() {
        "std" => cipher::gcm(block.as_ref()),
        // Go's int can be negative, which it rejects like zero; usize cannot.
        "nonce" => cipher::gcm_with_nonce_size(block.as_ref(), int_of(f, "n").max(0) as usize),
        "tag" => cipher::gcm_with_tag_size(block.as_ref(), int_of(f, "t") as usize),
        "random" => cipher::gcm_with_random_nonce(block.as_ref()),
        other => panic!("unknown variant {other}"),
    };
    let aead = match made {
        Ok(aead) => aead,
        Err(error) => {
            out.insert("ctor".into(), message(error));
            return;
        }
    };
    out.insert("ctor".into(), "ok".into());
    out.insert("ns".into(), aead.nonce_size().to_string());
    out.insert("ov".into(), aead.overhead().to_string());
    let (pre, nonce) = (bytes_of(f, "pre"), bytes_of(f, "nonce"));
    let (pt, aad, raw) = (bytes_of(f, "pt"), bytes_of(f, "aad"), bytes_of(f, "raw"));
    let aead = aead.as_ref();
    if f["variant"] == "random" {
        let mut ct = Vec::new();
        aead.seal(&mut ct, &[], &pt, &aad)
            .expect("random-nonce seal");
        out.insert("rn_len".into(), ct.len().to_string());
        out.insert("rn_ct".into(), hex(&ct));
        out.insert("rn_self".into(), opened(aead, &pre, &[], &ct, &aad));
        if let Some(go) = f.get("st.rn_ct") {
            out.insert("rn_other".into(), opened(aead, &pre, &[], &unhex(go), &aad));
        }
        out.insert(
            "rn_tag".into(),
            opened(aead, &pre, &[], &flip(&ct, ct.len() - 1), &aad),
        );
        out.insert(
            "rn_nonce".into(),
            opened(aead, &pre, &[], &flip(&ct, 0), &aad),
        );
        out.insert(
            "rn_aad".into(),
            opened(aead, &pre, &[], &ct, &flip(&aad, 0)),
        );
        out.insert(
            "rn_short".into(),
            opened(aead, &pre, &[], &ct[..ct.len().min(27)], &aad),
        );
    } else {
        let good = bytes_of(f, "goodnonce");
        let mut ct = Vec::new();
        aead.seal(&mut ct, &good, &pt, &aad).expect("seal");
        out.insert("seal".into(), sealed(aead, &pre, &nonce, &pt, &aad));
        out.insert("self".into(), opened(aead, &pre, &good, &ct, &aad));
        out.insert(
            "tag".into(),
            opened(aead, &pre, &good, &flip(&ct, ct.len() - 1), &aad),
        );
        out.insert(
            "body".into(),
            opened(aead, &pre, &good, &flip(&ct, 0), &aad),
        );
        out.insert("aad".into(), opened(aead, &pre, &good, &ct, &flip(&aad, 3)));
        out.insert(
            "nonce".into(),
            opened(aead, &pre, &flip(&good, 1), &ct, &aad),
        );
        out.insert(
            "trunc".into(),
            opened(aead, &pre, &good, &ct[..ct.len() - 1], &aad),
        );
        out.insert("raw".into(), opened(aead, &pre, &nonce, &raw, &aad));
    }
    out.insert("badnonce".into(), sealed(aead, &pre, &nonce, &pt, &aad));
    out.insert("badopen".into(), opened(aead, &pre, &nonce, &raw, &aad));
}

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut writer = io::BufWriter::new(stdout.lock());
    for line in stdin.lock().lines() {
        let line = line.expect("stdin");
        if line.is_empty() {
            continue;
        }
        let fields: Fields = line
            .split(' ')
            .map(|token| {
                let (key, value) = token.split_once('=').unwrap_or((token, ""));
                (key.to_string(), value.to_string())
            })
            .collect();
        let mut out = Out::new();
        match fields["op"].as_str() {
            "block" => block_case(&fields, &mut out),
            "rc4" => rc4_case(&fields, &mut out),
            "gcm" => gcm_case(&fields, &mut out),
            _ => mode_case(&fields, &mut out),
        }
        let text: Vec<String> = out.iter().map(|(k, v)| format!("{k}={v}")).collect();
        writeln!(writer, "{}", text.join(" ")).expect("stdout");
    }
}
