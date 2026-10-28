#!/usr/bin/env python3
"""Differentially compare crypto/cipher, crypto/aes, crypto/des and crypto/rc4 with Go.

Random keys, IVs, nonces, plaintexts and chunkings are fed to
tools/crypto_cipher_oracle.go and crates/crypto/examples/crypto_cipher_probe.rs.
Every mode (CBC, CFB, CTR, OFB, GCM with every tag size and a spread of nonce
sizes, RC4) over every cipher (AES-128/192/256, DES, 3DES and a custom Block) is
compared byte for byte, including the error messages of Go's panics. GCM
decryption is also run on tampered ciphertext, tag, nonce and additional data.
Random-nonce GCM cannot be compared byte for byte: each side opens the other's
ciphertext instead.
"""
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
# crypto/cipher::GCM_NONCE_SIZES: the nonce sizes the Rust API supports.
NONCE_SIZES = list(range(1, 33)) + [36, 40, 44, 48, 56, 60, 64, 72, 80, 96, 100, 112, 120, 128, 192, 256]
CIPHERS = ["aes128", "aes192", "aes256", "des", "tdes", "custom8", "custom16"]
STREAM_OPS = ["ctr", "ofb", "cfbe", "cfbd"]
BLOCK_OPS = ["cbce", "cbcd"]


def corpus():
    rng = random.Random(20261012)

    def blob(size):
        return bytes(rng.randrange(256) for _ in range(size))

    def cipher_fields(name, wrong_key=0.0):
        """The cipher kind and key for a named configuration."""
        kind, size = {
            "aes128": ("aes", 16), "aes192": ("aes", 24), "aes256": ("aes", 32), "des": ("des", 8),
            "tdes": ("tdes", 24), "custom8": ("custom", 8), "custom16": ("custom", 16),
        }[name]
        if kind != "custom" and rng.random() < wrong_key:
            size = rng.choice([0, 1, 7, 8, 15, 16, 17, 23, 24, 25, 31, 32, 33, 48, rng.randrange(0, 70)])
        return {"cipher": kind, "key": blob(size).hex()}, size

    def block_size(name):
        return {"aes128": 16, "aes192": 16, "aes256": 16, "des": 8, "tdes": 8, "custom8": 8, "custom16": 16}[name]

    def iv_for(name):
        size = block_size(name)
        roll = rng.random()
        if roll < 0.08:
            size = rng.choice([0, 1, size - 1, size + 1, 2 * size, rng.randrange(0, 40)])
            return blob(size)
        if roll < 0.35:  # counters that carry through the low bytes, or all the way
            iv = bytearray(blob(size))
            for i in range(rng.randrange(1, size + 1)):
                iv[size - 1 - i] = 0xFF
            return bytes(iv)
        return blob(size)

    cases = []

    for _ in range(1200):
        name = rng.choice(["aes128", "aes192", "aes256", "des", "tdes"])
        fields, _ = cipher_fields(name, 0.12)
        size = block_size(name)
        data_len = rng.choice([size, size, size, 0, 1, size - 1, size + 1, 2 * size, rng.randrange(0, 40)])
        fields.update({"op": "block", "data": blob(data_len).hex(),
                       "dlen": rng.choice([size, size, size, 0, size - 1, size + 1, 2 * size, rng.randrange(0, 40)])})
        cases.append(fields)

    for op in BLOCK_OPS + STREAM_OPS:
        for name in CIPHERS:
            for _ in range(90):
                size = block_size(name)
                fields, _ = cipher_fields(name, 0.04)
                if op in BLOCK_OPS and rng.random() < 0.8:
                    data = blob(size * rng.choice([0, 1, 2, 3, 7, 16, rng.randrange(0, 20)]))
                else:
                    data = blob(rng.choice([0, 1, 2, size - 1, size, size + 1, 3 * size + 1, rng.randrange(0, 300)]))
                chunks, remaining = [], len(data)
                for _ in range(rng.randrange(1, 6)):
                    if op in BLOCK_OPS and rng.random() < 0.8:
                        chunk = size * rng.randrange(0, 4)
                    else:
                        chunk = rng.randrange(0, 70)
                    chunks.append(chunk)
                    remaining -= chunk
                xs = [rng.choice([0, 0, 0, 0, 1, 5, -1, -3, size]) for _ in chunks]
                fields.update({"op": op, "iv": iv_for(name).hex(), "data": data.hex(),
                               "chunks": ",".join(map(str, chunks)), "xs": ",".join(map(str, xs))})
                cases.append(fields)

    for _ in range(400):
        key_len = rng.choice([1, 1, 2, 5, 16, 32, 255, 256, 0, 257, 300, rng.randrange(0, 300)])
        data = blob(rng.choice([0, 1, 255, 256, 257, rng.randrange(0, 700)]))
        chunks = [rng.randrange(0, 300) for _ in range(rng.randrange(1, 6))]
        xs = [rng.choice([0, 0, 0, 3, -1, -5]) for _ in chunks]
        cases.append({"op": "rc4", "cipher": "rc4", "key": blob(key_len).hex(), "data": data.hex(),
                      "chunks": ",".join(map(str, chunks)), "xs": ",".join(map(str, xs)),
                      "reset": rng.choice([-1, -1, -1, 0, 1, 2])})

    gcm_ciphers = ["aes128", "aes192", "aes256", "aes128", "aes256", "des", "custom8", "custom16", "custom16"]
    for index in range(2200):
        name = rng.choice(gcm_ciphers)
        fields, _ = cipher_fields(name, 0.05)
        variant = rng.choice(["std", "std", "nonce", "nonce", "tag", "tag", "random"])
        nonce_size = 12
        tag_size = 16
        extra = {"n": 12, "t": 16}
        if variant == "nonce":
            nonce_size = rng.choice(NONCE_SIZES + [0, 0, -1])
            extra["n"] = nonce_size
        if variant == "tag":
            tag_size = rng.choice([12, 13, 14, 15, 16, 16, 0, 1, 11, 17, 32, -1])
            extra["t"] = tag_size
        good = blob(max(nonce_size, 0))
        nonce = good if rng.random() < 0.7 else blob(rng.choice([0, 1, 11, 12, 13, rng.randrange(0, 40)]))
        if variant == "random" and rng.random() < 0.85:
            nonce = b""
        pt = blob(rng.choice([0, 0, 1, 15, 16, 17, 31, 32, 33, 100, rng.randrange(0, 260)]))
        aad = blob(rng.choice([0, 0, 1, 12, 16, 17, 40, rng.randrange(0, 60)]))
        raw = blob(rng.choice([0, 1, 11, 12, 15, 16, 17, 28, 29, 60, rng.randrange(0, 90)]))
        pre = blob(rng.choice([0, 0, 0, 1, 4]))
        fields.update({"op": "gcm", "variant": variant, "goodnonce": good.hex(), "nonce": nonce.hex(),
                       "pt": pt.hex(), "aad": aad.hex(), "raw": raw.hex(), "pre": pre.hex(),
                       **{k: v for k, v in extra.items()}})
        cases.append(fields)

    return cases


def line_of(case, extra=None):
    tokens = [f"{k}={v}" for k, v in case.items()]
    for name, value in (extra or {}).items():
        tokens.append(f"{name}={value}")
    return " ".join(tokens)


def parse(line):
    fields = {}
    for part in line.split(" "):
        key, _, value = part.partition("=")
        fields[key] = value
    return fields


def run(command, payload, env):
    result = subprocess.run(command, input=payload, text=True, capture_output=True,
                            cwd=ROOT, env=env, timeout=240, encoding="utf-8")
    if result.returncode:
        raise RuntimeError(f"{' '.join(command)} failed:\n{result.stderr}")
    return [parse(line) for line in result.stdout.splitlines()]


def is_random(case):
    return case.get("op") == "gcm" and case.get("variant") == "random"


def main():
    if not shutil.which("go") or not shutil.which("cargo"):
        raise RuntimeError("crypto cipher differential check requires Go and Cargo on PATH")
    cases = corpus()
    env = os.environ.copy()
    env.update({"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off"})
    go_command = ["go", "run", "tools/crypto_cipher_oracle.go"]
    go = run(go_command, "".join(line_of(c) + "\n" for c in cases), env)
    if len(go) != len(cases):
        raise AssertionError("Go oracle returned the wrong number of records")
    # Rust opens Go's random-nonce ciphertexts.
    rust_payload = "".join(
        line_of(c, {"st.rn_ct": g["rn_ct"]} if is_random(c) and "rn_ct" in g else None) + "\n"
        for c, g in zip(cases, go))
    rust = run(["cargo", "run", "--offline", "--locked", "--quiet", "--manifest-path",
                "crates/crypto/Cargo.toml", "--example", "crypto_cipher_probe"], rust_payload, env)
    if len(rust) != len(cases):
        raise AssertionError("Rust probe returned the wrong number of records")
    # Go opens Rust's random-nonce ciphertexts.
    random_indexes = [i for i, c in enumerate(cases) if is_random(c) and "rn_ct" in rust[i]]
    go_back = run(go_command, "".join(
        line_of(cases[i], {"st.rn_ct": rust[i]["rn_ct"]}) + "\n" for i in random_indexes), env)
    go_back_by_index = dict(zip(random_indexes, go_back))

    compared, errors, cross_opened = 0, 0, 0
    for index, (case, want, got) in enumerate(zip(cases, go, rust)):
        if is_random(case) and "rn_ct" in want:
            # Nonces are random: compare lengths and every outcome, and cross-open.
            want = dict(want)
            got = dict(got)
            go_ct, rust_ct = want.pop("rn_ct"), got.pop("rn_ct")
            if len(go_ct) != len(rust_ct):
                raise AssertionError(f"case {index}: random-nonce ciphertext lengths differ")
            rust_opens_go = got.pop("rn_other")
            go_opens_rust = go_back_by_index[index]["rn_other"]
            if not (want["rn_self"] == rust_opens_go == go_opens_rust):
                raise AssertionError(f"case {index}: cross-opening differs: go self {want['rn_self']} "
                                     f"rust-opens-go {rust_opens_go} go-opens-rust {go_opens_rust}")
            cross_opened += 1
            # A random-nonce seal succeeds with random bytes: compare its outcome and size.
            for side in (want, got):
                if side["badnonce"].startswith("ok:"):
                    side["badnonce"] = f"ok:{len(side['badnonce'])}"
        if want != got:
            diffs = sorted(k for k in set(want) | set(got) if want.get(k) != got.get(k))
            first = diffs[0]
            raise AssertionError(f"case {index}: {len(diffs)} fields differ, first {first}:\n"
                                 f"  go  : {want.get(first)}\n  rust: {got.get(first)}\n  input: {line_of(case)[:400]}")
        compared += len(want)
        errors += sum(1 for v in want.values() if "err:" in v)
    kinds = {}
    for case in cases:
        key = case["op"] if case["op"] != "gcm" else "gcm-" + case["variant"]
        kinds[key] = kinds.get(key, 0) + 1
    print(json.dumps({"cases": len(cases), "by_operation": kinds, "fields_compared": compared,
                      "agreed_error_results": errors, "random_nonce_cross_opened": cross_opened,
                      "go_oracle": "passed", "rust_differential": "passed"}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, AssertionError, subprocess.TimeoutExpired) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
