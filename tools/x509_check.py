#!/usr/bin/env python3
"""Differentially compare crypto/x509 and crypto/x509/pkix with Go.

tools/x509_oracle.go and crates/crypto/examples/x509_probe.rs implement one
protocol (one `op=... key=value` line in, `dump=<hex text>` or `err=<hex
message>` out). The dump lists every field of a parsed certificate, request,
revocation list or key, so equal lines mean equal parsing. The corpus is every
PEM block in Go's crypto/x509 testdata and in the Go sources, the NIST PKITS
certificates, and certificates, requests and lists Go generates; each input is
also truncated and bit-flipped to compare rejections, and up to
STRING_MUTATIONS_PER_CERT strings in each certificate are tried with a byte
that is not UTF-8.

X509_SEED overrides the random seed (other seeds reach other mutations).
"""
import base64
import json
import os
from pathlib import Path
import random
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
# Mutated (bit-flipped, truncated, extended) inputs per valid key, request and
# list: the error text of every rejection must match Go's.
ERROR_TEXT_MUTATIONS = 40
SEED = int(os.environ.get("X509_SEED", "20261012"))
COUNTS = {}
# Go keeps a CRL distribution point, OCSP server or issuing certificate URL as
# the raw bytes of the certificate; the Rust `String` holds U+FFFD for each
# invalid sequence (deviation go-string-invalid-utf8 of ParseCertificate). The
# comparison accepts exactly that substitution on these fields and counts it.
LOSSY_STRING_KEYS = ("crldp[", "ocsp[", "issuing[")
ACCEPTED_LOSSY = []

PEM = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.S)


def line(**kw):
    parts = []
    for key, value in kw.items():
        if isinstance(value, (bytes, bytearray)):
            value = value.hex()
        elif isinstance(value, (list, tuple)):
            value = ",".join(v.hex() if isinstance(v, (bytes, bytearray)) else str(v) for v in value)
        parts.append(f"{key}={value}")
    return " ".join(parts)


def parse(text):
    return dict(token.split("=", 1) if "=" in token else (token, "") for token in text.split(" "))


def run(command, cases, env):
    result = subprocess.run(command, input="".join(c + "\n" for c in cases), text=True, capture_output=True,
                            cwd=ROOT, env=env, timeout=3600)
    if result.returncode != 0:
        raise RuntimeError(f"{command[0]} failed:\n{result.stderr[-3000:]}")
    lines = result.stdout.split("\n")[:-1]
    if len(lines) != len(cases):
        raise RuntimeError(f"{command[0]}: {len(lines)} outputs for {len(cases)} cases")
    return [parse(t) for t in lines]


# encoding/asn1 prints a struct tag's pointer in its "tags don't match" error as a
# heap address; the Rust side prints this placeholder for every non-nil pointer.
HEAP_ADDRESS = re.compile(r"\b(tag|defaultValue):0x[0-9a-f]+")


def normalize_sigcheck(decoded):
    kind, text = decoded
    if kind == "ok":
        text = re.sub(r"^sigcheck=(?!ok$).*$", "sigcheck=failed", text, flags=re.M)
    return (kind, text)


def decode(out):
    if "dump" in out:
        return ("ok", bytes.fromhex(out["dump"]).decode("utf-8", "replace"))
    text = bytes.fromhex(out["err"]).decode("utf-8", "replace")
    return ("err", HEAP_ADDRESS.sub(r"\1:0xc000000000", text))


class Harness:
    def __init__(self):
        self.env = os.environ.copy()
        self.env["GOTOOLCHAIN"] = "local"
        oracle = ROOT / "target" / "x509_oracle"
        oracle.parent.mkdir(exist_ok=True)
        subprocess.run(["go", "build", "-o", str(oracle), "tools/x509_oracle.go"], cwd=ROOT, env=self.env, check=True)
        self.go_cmd = [str(oracle)]
        subprocess.run(["cargo", "build", "--offline", "--locked", "--quiet", "--manifest-path",
                        "crates/crypto/Cargo.toml", "--example", "x509_probe"], cwd=ROOT, env=self.env, check=True)
        meta = json.loads(subprocess.check_output(
            ["cargo", "metadata", "--offline", "--locked", "--no-deps", "--format-version", "1",
             "--manifest-path", "crates/crypto/Cargo.toml"], cwd=ROOT, env=self.env, text=True))
        self.rs_cmd = [str(Path(meta["target_directory"]) / "debug" / "examples" / "x509_probe")]

    def go(self, cases):
        return run(self.go_cmd, cases, self.env)

    def rs(self, cases):
        return run(self.rs_cmd, cases, self.env)

    def same(self, name, cases, signature_text=True):
        """Both implementations must produce identical output for every case,
        including the text of every rejection (encoding/asn1 messages too).

        With signature_text false a failed signature check is compared as
        failed, not by message: for a corrupted ML-DSA signature this crate can
        name another of Go's rejection reasons (an encoding error where Go
        reports an invalid signature)."""
        go, rs = self.go(cases), self.rs(cases)
        failures = []
        for index, (case, g, r) in enumerate(zip(cases, go, rs)):
            gd, rd = decode(g), decode(r)
            if not signature_text:
                gd, rd = (normalize_sigcheck(gd), normalize_sigcheck(rd))
            if gd == rd:
                continue
            if lossy_string_only(gd, rd):
                ACCEPTED_LOSSY.append(name)
                continue
            failures.append((index, case, gd, rd))
        COUNTS[name] = COUNTS.get(name, 0) + len(cases)
        if failures:
            shown = []
            for index, case, gd, rd in failures[:3]:
                shown.append(f"  case {index}: {case[:int(os.environ.get('X509_CASE', '200'))]}\n    go  : {diff_text(gd, rd)[0]}\n    rust: {diff_text(gd, rd)[1]}")
            raise AssertionError(f"{name}: {len(failures)} of {len(cases)} cases differ:\n" + "\n".join(shown))
        return go, rs


def lossy_string_only(gd, rd):
    """Both parsed, and every differing line is a LOSSY_STRING_KEYS field whose
    Rust value is Go's bytes with each invalid UTF-8 sequence replaced by U+FFFD."""
    if gd[0] != "ok" or rd[0] != "ok":
        return False
    gl, rl = gd[1].split("\n"), rd[1].split("\n")
    if len(gl) != len(rl):
        return False
    for a, b in zip(gl, rl):
        if a == b:
            continue
        key, _, go_hex = a.partition("=")
        rust_key, _, rust_hex = b.partition("=")
        if key != rust_key or not key.startswith(LOSSY_STRING_KEYS):
            return False
        if bytes.fromhex(go_hex).decode("utf-8", "replace").encode().hex() != rust_hex:
            return False
    return True


def diff_text(gd, rd):
    """The first differing line of two decoded outputs."""
    if gd[0] != rd[0]:
        return (f"{gd[0]}: {gd[1][:300]}", f"{rd[0]}: {rd[1][:300]}")
    gl, rl = gd[1].split("\n"), rd[1].split("\n")
    for a, b in zip(gl, rl):
        if a != b:
            return (a[:600], b[:600])
    return (f"{len(gl)} lines", f"{len(rl)} lines")


def go_root():
    return Path(subprocess.check_output(["go", "env", "GOROOT"], text=True).strip())


def pem_blocks(text, go_source=False):
    for m in PEM.finditer(text):
        body = m.group(2)
        if go_source:
            # Go string literals: drop `"a" + "b"` concatenations, quotes and escapes.
            body = re.sub(r'"\s*\+\s*"', "", body)
            body = re.sub(r'\\n|\\t|[`"]', "", body)
        body = re.sub(r"\s", "", body)
        # Header lines (Proc-Type, DEK-Info) make the body undecodable; skip.
        try:
            yield m.group(1), base64.b64decode(body, validate=True)
        except Exception:
            continue


def corpus():
    """(kind, DER) for every PEM/DER object in Go's tree that we know."""
    root = go_root() / "src"
    seen = set()
    out = []

    def add(kind, der):
        key = (kind, der)
        if key not in seen:
            seen.add(key)
            out.append(key)

    paths = list((root / "crypto" / "x509").rglob("*"))
    for sub in ("crypto/tls", "crypto/internal", "net/http", "net/smtp", "crypto/x509", "internal", "crypto/ecdsa",
                "crypto/ed25519", "crypto/rsa", "crypto/mldsa", "crypto/ecdh"):
        paths += list((root / sub).rglob("*.go")) + list((root / sub).rglob("*.pem")) + list((root / sub).rglob("*.crt"))
    for path in paths:
        if not path.is_file():
            continue
        if path.suffix in (".go", ".pem", ".crt", ".der", ".cer", ".txt", ""):
            try:
                data = path.read_bytes()
            except OSError:
                continue
            if path.suffix in (".der", ".cer", ".crt") and not data.startswith(b"-----"):
                add("cert", data)
                continue
            for label, der in pem_blocks(data.decode("utf-8", "replace"), path.suffix == ".go"):
                kind = {"CERTIFICATE": "cert", "X509 CERTIFICATE": "cert", "TRUSTED CERTIFICATE": "cert",
                        "CERTIFICATE REQUEST": "csr", "NEW CERTIFICATE REQUEST": "csr", "X509 CRL": "crl",
                        "PRIVATE KEY": "pkcs8", "RSA PRIVATE KEY": "pkcs1", "EC PRIVATE KEY": "ec",
                        "PUBLIC KEY": "pkix", "RSA PUBLIC KEY": "pkcs1pub",
                        "TESTING KEY": "pkcs8", "RSA TESTING KEY": "pkcs1", "EC TESTING KEY": "ec"}.get(label)
                if kind:
                    add(kind, der)
    pkits = root / "crypto" / "x509" / "testdata" / "nist-pkits" / "certs"
    if pkits.is_dir():
        for path in sorted(pkits.iterdir()):
            data = path.read_bytes()
            if path.suffix == ".crl":
                add("crl", data)
            else:
                add("cert", data)
    return out


def flip(rng, data):
    if not data:
        return data
    at = rng.randrange(len(data))
    return data[:at] + bytes([data[at] ^ (1 << rng.randrange(8))]) + data[at + 1:]


def mutations(rng, der, count):
    out = []
    for _ in range(count):
        choice = rng.randrange(4)
        if choice == 0:
            out.append(der[:rng.randrange(len(der) + 1)])
        elif choice == 1:
            out.append(flip(rng, der))
        elif choice == 2:
            out.append(der + bytes([rng.randrange(256)]))
        else:
            out.append(flip(rng, flip(rng, der)))
    return out


INTERESTING = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0c, 0x13, 0x16, 0x17, 0x18, 0x30, 0x31, 0x7f, 0x80, 0x81, 0x82,
               0x83, 0xa0, 0xa1, 0xa3, 0xff]


def text_mutations(rng, der, count):
    """Inputs that break the encoding in ways that reach different error
    messages: bit flips, truncations, and tag, length or content bytes
    replaced, inserted or deleted (most near the start, where the structure is)."""
    out = []
    for _ in range(count):
        choice = rng.randrange(6)
        at = rng.randrange(min(len(der), 80)) if rng.random() < 0.6 else rng.randrange(len(der))
        if choice == 0:
            out.append(der[:rng.randrange(len(der) + 1)])
        elif choice == 1:
            out.append(flip(rng, der))
        elif choice == 2:
            out.append(der[:at] + bytes([rng.choice(INTERESTING)]) + der[at + 1:])
        elif choice == 3:
            out.append(der[:at] + der[at + 1:])
        elif choice == 4:
            out.append(der[:at] + bytes([rng.choice(INTERESTING)]) + der[at:])
        else:
            out.append(der[:at] + bytes([rng.randrange(256)]) + der[at + 1:])
    return out


# Primitive string types, and the IA5String GeneralName choices rfc822Name [1],
# dNSName [2] and uniformResourceIdentifier [6].
STRING_TAGS = {0x0c, 0x13, 0x14, 0x16, 0x1e, 0x81, 0x82, 0x86}
NON_UTF8 = [b"\xc1", b"\xff", b"\xf4", b"\xc3\xa9"]
STRING_MUTATIONS_PER_CERT = 24


def string_spans(der, lo=0, hi=None):
    """(offset, length) of the content of every string-typed primitive element,
    descending into an OCTET STRING whose content is itself DER (an extension
    value); None when the range is not a run of DER elements."""
    hi = len(der) if hi is None else hi
    out = []
    pos = lo
    while pos < hi:
        if pos + 2 > hi:
            return None
        tag, first = der[pos], der[pos + 1]
        if first < 0x80:
            start, length = pos + 2, first
        else:
            count = first & 0x7f
            start, length = pos + 2 + count, int.from_bytes(der[pos + 2:pos + 2 + count], "big")
        if start + length > hi:
            return None
        if tag & 0x20:
            inner = string_spans(der, start, start + length)
            if inner is None:
                return None
            out += inner
        elif tag == 0x04:
            out += string_spans(der, start, start + length) or []
        elif tag in STRING_TAGS and length:
            out.append((start, length))
        pos = start + length
    return out


def string_mutations(der):
    """The certificate with one byte in the middle of a string replaced by a byte
    that is not UTF-8 (or two by a non-ASCII character): the same length, so
    every other element still parses. Names, SANs, name constraints, CRL
    distribution points and authority information access all hold strings."""
    spans = string_spans(der) or []
    step = max(1, -(-len(spans) // STRING_MUTATIONS_PER_CERT))
    out = []
    for i, (at, length) in enumerate(spans[::step]):
        bad = NON_UTF8[i % len(NON_UTF8)]
        if length < len(bad):
            bad = bad[:1]
        mid = at + (length - len(bad)) // 2
        out.append(der[:mid] + bad + der[mid + len(bad):])
    return out


OPS = {"cert": "parse_cert", "csr": "parse_csr", "crl": "parse_crl"}


def parsing(h, rng):
    items = corpus()
    kinds = {}
    for kind, _ in items:
        kinds[kind] = kinds.get(kind, 0) + 1
    print("corpus:", kinds)
    certs = [d for k, d in items if k == "cert"]
    # Certificates (all of Go's messages come from cryptobyte-style parsing).
    cases = [line(op="parse_cert", der=d) for d in certs]
    h.same("parse certificates", cases)
    cases = []
    for d in certs:
        cases += [line(op="parse_cert", der=m) for m in mutations(rng, d, 4)]
    h.same("parse mutated certificates", cases)
    cases = [line(op="parse_cert", der=m) for d in certs for m in string_mutations(d)]
    h.same("parse certificates with non-UTF-8 strings", cases)
    # Several concatenated certificates.
    cases = [line(op="parse_certs", der=b"".join(rng.sample(certs, min(3, len(certs))))) for _ in range(50)]
    h.same("parse certificates (concatenated)", cases)
    # Hostname verification on every certificate.
    hosts = ["example.com", "www.example.com", "*.example.com", "foo.bar.example.com", "Example.COM.", "127.0.0.1",
             "[::1]", "10.0.0.1", "xn--e1afmkfd.xn--p1ai", "localhost", "a_b.example.com", "", "*", "[2001:db8::1]"]
    cases = [line(op="hostname", der=d, hosts=[x.encode() for x in hosts]) for d in certs]
    h.same("verify hostname", cases)
    csrs = [d for k, d in items if k == "csr"]
    cases = [line(op="parse_csr", der=d) for d in csrs]
    for d in csrs:
        cases += [line(op="parse_csr", der=m) for m in text_mutations(rng, d, ERROR_TEXT_MUTATIONS)]
    if cases:
        h.same("parse certificate requests", cases)
    crls = [d for k, d in items if k == "crl"]
    cases = []
    for d in crls:
        cases += [line(op="parse_crl", der=d), line(op="parse_der_crl", der=d)]
        for m in text_mutations(rng, d, ERROR_TEXT_MUTATIONS):
            cases += [line(op="parse_crl", der=m), line(op="parse_der_crl", der=m)]
    if cases:
        h.same("parse revocation lists", [c for c in cases if "parse_crl" in c])
        h.same("parse DER CRLs", [c for c in cases if "parse_der_crl" in c])
    for kind in ("pkcs8", "pkcs1", "ec", "pkix", "pkcs1pub"):
        keys = [d for k, d in items if k == kind]
        cases = [line(op="parse_key", kind=kind, der=d) for d in keys]
        for d in keys:
            cases += [line(op="parse_key", kind=kind, der=m) for m in text_mutations(rng, d, ERROR_TEXT_MUTATIONS)]
        if cases:
            h.same(f"parse {kind} keys", cases)


def oids(h, rng):
    cases = []
    texts = ["1.2.3", "2.999.3", "0.39", "1.40", "3.1", "2.5.4.3", "1", "1.", ".1.2", "1.2.3.", "1.+2", "1.2.-3", "",
             "2.18446744073709551616.1", "2.100000000000000000000000000000.18446744073709551615.99999999999999999999999",
             "1.2.840.113549.1.1.11", "0.0", "00.1", "1.00", "1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16.17.18.19.20",
             "2.4294967295.4294967296", "2.2147483647.2147483648", "2.5.2147483647"]
    for _ in range(300):
        parts = [str(rng.choice([0, 1, 2])), str(rng.randrange(0, 50))] + [str(rng.randrange(0, 2 ** rng.choice([7, 8, 14, 21, 31, 32, 63, 64, 70]))) for _ in range(rng.randrange(0, 6))]
        texts.append(".".join(parts))
    h.same("oid text", [line(op="oid", text=t.encode()) for t in texts])
    ders = [bytes([rng.randrange(256) for _ in range(rng.randrange(0, 8))]) for _ in range(300)]
    ders += [bytes.fromhex(x) for x in ("2a0304", "80", "8001", "00", "2a", "7f", "8f7f", "ffffffffff7f", "81ffffffff7f", "5504")]
    h.same("oid der", [line(op="oid_der", der=d) for d in ders])
    cases = []
    for _ in range(300):
        first = rng.choice([0, 1, 2, 3])
        ints = [first, rng.choice([0, 1, 39, 40, 41, 100, 2 ** 40]) ] + [rng.randrange(0, 2 ** rng.choice([7, 31, 32, 63])) for _ in range(rng.randrange(0, 5))]
        cases.append(line(op="oid_ints", ints=",".join(map(str, ints))))
    cases.append(line(op="oid_ints", ints="1"))
    h.same("oid ints", cases)


def kv(text):
    out = {}
    for ln in text.split("\n"):
        if "=" in ln:
            k, v = ln.split("=", 1)
            out[k] = v
    return out


def go_dump(h, cases):
    return [kv(decode(o)[1]) if "dump" in o else None for o in h.go(cases)]


KEY_KINDS = ["p224", "p256", "p384", "p521", "ed25519", "rsa2048", "mldsa44", "mldsa65", "mldsa87"]


def keypool(h, rng):
    """Generate keys with Go: {kind: [pkcs8, ...]}, and compare every re-marshaling form."""
    kinds = {"p256": 6, "p384": 3, "p521": 2, "p224": 2, "ed25519": 4, "rsa2048": 3, "mldsa44": 2, "mldsa65": 1, "mldsa87": 1,
             "x25519": 1, "p256ecdh": 1}
    pool = {}
    cases = []
    order = []
    for kind, n in kinds.items():
        for _ in range(n):
            cases.append(line(op="genkey", kind=kind))
            order.append(kind)
    outs = go_dump(h, cases)
    parse_cases = []
    for kind, out in zip(order, outs):
        pool.setdefault(kind, []).append(bytes.fromhex(out["key"]))
        parse_cases.append(line(op="parse_key", kind="pkcs8", der=bytes.fromhex(out["key"])))
        if "sec1" in out:
            parse_cases.append(line(op="parse_key", kind="ec", der=bytes.fromhex(out["sec1"])))
        if "pkcs1" in out:
            parse_cases.append(line(op="parse_key", kind="pkcs1", der=bytes.fromhex(out["pkcs1"])))
    h.same("parse generated keys", parse_cases)
    # Re-marshaling after parsing must agree, and the public keys round-trip.
    go, _ = h.same("marshal generated keys", [line(op="create", what="key", key=k) for ks in pool.values() for k in ks])
    pubs = []
    for out in go:
        d = kv(decode(out)[1])
        if "pub.pkix" in d:
            pubs.append(bytes.fromhex(d["pub.pkix"]))
    h.same("parse generated PKIX public keys", [line(op="parse_key", kind="pkix", der=p) for p in pubs])
    return pool


def pick_key(rng, pool, kinds=None):
    kind = rng.choice(kinds or list(KEY_KINDS))
    return kind, rng.choice(pool[kind])


SAMPLE_STRINGS = ["", "a", "Example Corp", "example.com", "héllo wörld", "日本語", "emoji \U0001F600", "a,b", "x+y", 'q"q', "back\\slash",
                  "<tag>", "semi;colon", "#hash", " lead", "trail ", "mid dle", "*.wild", "a&b", "under_score", "A" * 70,
                  "tab\there", "nul\x00x", "UPPER", "trailing.dot.", "a@b.c", "é"]


def sample_str(rng):
    s = rng.choice(SAMPLE_STRINGS)
    if rng.random() < 0.3:
        s += rng.choice(SAMPLE_STRINGS)
    return s


def b(s):
    return s.encode("utf-8")


def rand_atv(rng):
    oid = rng.choice(["2.5.4.3", "2.5.4.10", "2.5.4.11", "2.5.4.6", "2.5.4.5", "2.5.4.7", "2.5.4.8", "2.5.4.9", "2.5.4.17", "1.2.3.4",
                      "0.9.2342.19200300.100.1.25", "2.5.4.12", "1.2.840.113549.1.9.1"])
    kind = rng.choice(["s", "s", "s", "i", "b", "o", "n", "oid", "bs", "t", "raw"])
    if kind == "s":
        data = b(sample_str(rng))
    elif kind == "i":
        data = str(rng.choice([0, 1, -1, 255, 2 ** 40, -2 ** 40])).encode()
    elif kind == "b":
        data = rng.choice([b"true", b"false"])
    elif kind == "o":
        data = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 6)))
    elif kind == "n":
        data = b""
    elif kind == "oid":
        data = rng.choice([b"1.2.3", b"2.5.4.3", b"2.999.1"])
    elif kind == "bs":
        n = rng.randrange(0, 4)
        # Whole bytes only: BitLength must fit the bytes with zero padding.
        data = bytes([8 * n]) + bytes(rng.randrange(256) for _ in range(n))
    elif kind == "t":
        data = str(rng.randrange(-2 ** 31, 2 ** 33)).encode()
    else:
        data = bytes([0x13, 2, 0x41, 0x42]) if rng.random() < 0.5 else bytes([0x81, 1, 0x7f])
    return f"{oid}:{kind}:{data.hex()}"


def names(h, rng):
    cases = []
    for _ in range(600):
        sets = []
        for _ in range(rng.randrange(0, 5)):
            if rng.random() < 0.05:
                sets.append("-")
            else:
                sets.append("|".join(rand_atv(rng) for _ in range(rng.randrange(1, 4))))
        spec = ";".join(sets)
        extra = rng.choice([{}, {"noextra": 1}, {"empty_extra": 1}])
        cases.append(line(op="name", rdns=spec, **extra))
    h.same("pkix.Name.String and marshal", cases)


def hexlist(items):
    return ",".join(b(i).hex() if isinstance(i, str) else i.hex() for i in items)


def rand_subject(rng):
    f = {}
    if rng.random() < 0.8:
        f["cn"] = b(sample_str(rng))
    for key, n in (("c", 2), ("o", 2), ("ou", 2), ("l", 1), ("st", 1), ("street", 1), ("postal", 1)):
        if rng.random() < 0.4:
            f[key] = hexlist([sample_str(rng) for _ in range(rng.randrange(1, n + 1))])
    if rng.random() < 0.2:
        f["sn"] = b(sample_str(rng))
    if rng.random() < 0.2:
        f["xnames"] = "|".join(rand_atv(rng) for _ in range(rng.randrange(1, 3)))
    return f


def rand_hostname(rng):
    labels = [rng.choice(["www", "mail", "api", "a", "b-c", "x1", "*", "UPPER", "xn--e1afmkfd", "foo_bar"]) for _ in range(rng.randrange(1, 4))]
    return ".".join(labels + [rng.choice(["com", "org", "example", "co.uk", "test"])])


def rand_ip(rng):
    if rng.random() < 0.6:
        return bytes(rng.randrange(256) for _ in range(4))
    return bytes(rng.randrange(256) for _ in range(16))


def rand_ipnet(rng):
    if rng.random() < 0.6:
        ip = bytes(rng.randrange(256) for _ in range(4))
        bits = rng.randrange(0, 33)
        mask = ((0xffffffff << (32 - bits)) & 0xffffffff).to_bytes(4, "big")
    else:
        ip = bytes([0x20, 0x01]) + bytes(rng.randrange(256) for _ in range(14))
        bits = rng.randrange(0, 129)
        mask = ((((1 << 128) - 1) << (128 - bits)) & ((1 << 128) - 1)).to_bytes(16, "big")
    return ip.hex() + "/" + mask.hex()


def rand_template(rng, ca=None):
    f = rand_subject(rng)
    # A missing serial is random in each implementation; tests that compare bytes always set one.
    f["serial"] = str(rng.choice([1, 2, 255, 256, 2 ** 63, 2 ** 159, rng.randrange(1, 2 ** 100), -5, 0]))
    start = rng.randrange(-2 ** 30, 2 ** 32)
    f["nb"] = start
    f["na"] = start + rng.choice([86400, 365 * 86400, 20 * 365 * 86400, 100 * 365 * 86400, 0, -3600])
    if rng.random() < 0.5:
        f["ku"] = rng.choice([1, 2, 4, 32, 64, 33, 5, 128, 256, 511, 3])
    if rng.random() < 0.4:
        f["eku"] = ",".join(str(rng.randrange(0, 14)) for _ in range(rng.randrange(1, 4)))
    if rng.random() < 0.15:
        f["ueku"] = ",".join(rng.choice(["1.2.3.4", "1.3.6.1.4.1.99999.1", "2.999.5"]) for _ in range(rng.randrange(1, 3)))
    if rng.random() < 0.6:
        isca = rng.random() < 0.5 if ca is None else ca
        mpl = rng.choice([-1, 0, 1, 3, -1])
        zero = rng.random() < 0.5
        f["bc"] = f"true:{'true' if isca else 'false'}:{mpl}:{'true' if zero else 'false'}"
    if rng.random() < 0.3:
        f["skid"] = bytes(rng.randrange(256) for _ in range(rng.choice([1, 8, 20]))).hex()
    if rng.random() < 0.3:
        f["akid"] = bytes(rng.randrange(256) for _ in range(rng.choice([1, 8, 20]))).hex()
    if rng.random() < 0.3:
        f["ocsp"] = hexlist(["http://ocsp.example.com/" + sample_str(rng).replace(" ", "")])
    if rng.random() < 0.3:
        f["issuing"] = hexlist(["http://ca.example.com/ca.crt"])
    if rng.random() < 0.6:
        f["dns"] = hexlist([rand_hostname(rng) for _ in range(rng.randrange(1, 4))])
    if rng.random() < 0.3:
        f["email"] = hexlist(["user%d@example.com" % rng.randrange(100) for _ in range(rng.randrange(1, 3))])
    if rng.random() < 0.3:
        f["ip"] = ",".join(rand_ip(rng).hex() for _ in range(rng.randrange(1, 3)))
    if rng.random() < 0.3:
        f["uri"] = hexlist(["https://%s/path?q=1" % rand_hostname(rng).replace("*", "x"), "spiffe://example.org/ns/x"][:rng.randrange(1, 3)])
    if rng.random() < 0.3:
        f["pdc"] = rng.choice(["true", "false"])
        if rng.random() < 0.7:
            f["pdns"] = hexlist([rand_hostname(rng).replace("*", "x") for _ in range(rng.randrange(1, 3))])
        if rng.random() < 0.5:
            f["edns"] = hexlist([rand_hostname(rng).replace("*", "x")])
        if rng.random() < 0.5:
            f["pip"] = ",".join(rand_ipnet(rng) for _ in range(rng.randrange(1, 3)))
        if rng.random() < 0.5:
            f["eip"] = ",".join(rand_ipnet(rng) for _ in range(rng.randrange(1, 3)))
        if rng.random() < 0.4:
            f["pemail"] = hexlist(["example.com", "user@example.org", ".sub.example.com"][:rng.randrange(1, 4)])
        if rng.random() < 0.4:
            f["eemail"] = hexlist(["example.net"])
        if rng.random() < 0.4:
            f["puri"] = hexlist([".example.com", "example.org"][:rng.randrange(1, 3)])
        if rng.random() < 0.4:
            f["euri"] = hexlist(["bad.example"])
    if rng.random() < 0.3:
        f["crldp"] = hexlist(["http://crl.example.com/%d.crl" % i for i in range(rng.randrange(1, 3))])
    if rng.random() < 0.3:
        f["pols"] = ",".join(rng.choice(["1.2.3.4", "2.5.29.32.0", "1.3.6.1.4.1.99999.2", "2.16.840.1.101.3.2.1.48.1", "1.2.3.123456789012345678901234567890"]) for _ in range(rng.randrange(1, 4)))
    if rng.random() < 0.1:
        f["polids"] = "1.2.3.4,1.2.3.5"
    if rng.random() < 0.2:
        f["extra"] = ",".join("%s|%s|%s" % (rng.choice(["1.2.3.4.5", "2.5.29.99", "1.3.6.1.4.1.11129.2.4.2"]), rng.choice(["true", "false"]),
                                          bytes(rng.randrange(256) for _ in range(rng.randrange(0, 8))).hex()) for _ in range(rng.randrange(1, 3)))
    if rng.random() < 0.1:
        f["extra"] = (f.get("extra", "") + ("," if f.get("extra") else "")) + "2.5.29.15|true|030205a0"
    return f


SIGALGS = {
    "rsa2048": [0, 3, 4, 5, 6, 13, 14, 15, 2],
    "p224": [0, 9, 10, 11, 12, 4],
    "p256": [0, 9, 10, 11, 12, 4],
    "p384": [0, 9, 10, 11, 12],
    "p521": [0, 9, 10, 11, 12],
    "ed25519": [0, 16, 4],
    "mldsa44": [0, 17, 18],
    "mldsa65": [0, 18, 17],
    "mldsa87": [0, 19],
}
DETERMINISTIC = {("rsa2048", 0), ("rsa2048", 3), ("rsa2048", 4), ("rsa2048", 5), ("rsa2048", 6), ("ed25519", 0), ("ed25519", 16)}


def compare_created(name, cases, meta, go, rs):
    """Created DER: equal TBS (and equal bytes where signing is deterministic); equal errors."""
    created = []
    for index, (case, g, r) in enumerate(zip(cases, go, rs)):
        gd, rd = decode(g), decode(r)
        info = meta[index]
        if gd[0] != rd[0]:
            raise AssertionError(f"{name} case {index} {info}: go {gd[0]}: {gd[1][:200]} rust {rd[0]}: {rd[1][:200]}\n  {case[:600]}")
        if gd[0] == "err":
            # encoding/asn1 messages are not reproduced; our own wrapper text is.
            same_text = gd[1] == rd[1] or (" does not parse: " in gd[1] and gd[1].split(": ")[0] == rd[1].split(": ")[0])
            if not same_text:
                raise AssertionError(f"{name}: error text differs, case {index} {info}: go {gd[1]!r} rust {rd[1]!r}\n  {case[:600]}")
            continue
        gk, rk = kv(gd[1]), kv(rd[1])
        if gk["tbs"] != rk["tbs"]:
            at = next((i for i, (x, y) in enumerate(zip(gk["tbs"], rk["tbs"])) if x != y), min(len(gk["tbs"]), len(rk["tbs"])))
            raise AssertionError(f"{name} case {index} {info}: TBS differs at hex offset {at}\n go  ...{gk['tbs'][max(0, at - 60):at + 100]}\n rust ...{rk['tbs'][max(0, at - 60):at + 100]}\n  {case[:700]}")
        if info in DETERMINISTIC and gk["der"] != rk["der"]:
            raise AssertionError(f"{name} case {index} {info}: DER differs\n  {case[:600]}")
        created.append(bytes.fromhex(gk["der"]))
        created.append(bytes.fromhex(rk["der"]))
    COUNTS[name] = COUNTS.get(name, 0) + len(cases)
    return created


def creation(h, rng, pool):
    cases = []
    meta = []
    for _ in range(500):
        kind, key = pick_key(rng, pool)
        spec = rand_template(rng)
        sig = rng.choice(SIGALGS[kind])
        if sig:
            spec["sigalg"] = sig
        cases.append(line(op="create", what="cert", key=key, **spec))
        meta.append((kind, sig))
    created = compare_created("create certificates", cases, meta, h.go(cases), h.rs(cases))
    # Each side parses what the other created: identical dumps (including the signature check).
    h.same("parse created certificates", [line(op="parse_cert", der=d) for d in created])
    return created


def keys(h, rng, pool):
    """Sec1/PKCS #1 re-marshaling and malformed key encodings."""
    outs = go_dump(h, [line(op="genkey", kind=k) for k in ("p256", "p384", "p521", "p224", "rsa2048")] * 3)
    cases = []
    for out in outs:
        for kind, key in (("ec", "sec1"), ("pkcs1", "pkcs1")):
            if key in out:
                der = bytes.fromhex(out[key])
                cases.append(line(op="parse_key", kind=kind, der=der))
                for m in text_mutations(rng, der, ERROR_TEXT_MUTATIONS):
                    cases.append(line(op="parse_key", kind=kind, der=m))
        der = bytes.fromhex(out["key"])
        for m in text_mutations(rng, der, ERROR_TEXT_MUTATIONS):
            cases.append(line(op="parse_key", kind="pkcs8", der=m))
    h.same("parse mutated keys", cases)


MALFORMED_TIMES = [
    (0x17, b""), (0x17, b"2311142213Z"), (0x17, b"231114221320Z"), (0x17, b"2311142213Z0"), (0x17, b"231114221320"),
    (0x17, b"231114221320+0100"), (0x17, b"231114221320-0000"), (0x17, b"231114221320+0000"), (0x17, b"231114221320+2400"),
    (0x17, b"231114221320+2500"), (0x17, b"231114221320+0160"), (0x17, b"231114221320+0161"), (0x17, b"231114221320+01"),
    (0x17, b"231114221320.5Z"), (0x17, b"231114221320,5Z"), (0x17, b"231114221320.Z"), (0x17, b"2311142213.5Z"),
    (0x17, b"231314221320Z"), (0x17, b"231132221320Z"), (0x17, b"231131221320Z"), (0x17, b"230229221320Z"),
    (0x17, b"240229221320Z"), (0x17, b"231114241320Z"), (0x17, b"231114226120Z"), (0x17, b"231114221360Z"),
    (0x17, b"231114221320Zjunk"), (0x17, b"231114221320Z "), (0x17, b" 231114221320Z"), (0x17, b"2311142213200Z"),
    (0x17, b"23111422132aZ"), (0x17, b"+31114221320Z"), (0x17, b"-31114221320Z"), (0x17, b"69111422132Z"),
    (0x17, b"690101000000Z"), (0x17, b"500101000000Z"), (0x17, b"491231235959Z"), (0x17, b"000101000000Z"),
    (0x17, b"23111422132\xc3\xa9Z"), (0x17, b"231114221320\xffZ"), (0x17, b"\x00\x01\x02"), (0x17, b'2311"4221320Z'),
    (0x18, b""), (0x18, b"20231114221320Z"), (0x18, b"20231114221320.5Z"), (0x18, b"20231114221320.123456789Z"),
    (0x18, b"20231114221320.1234567890Z"), (0x18, b"20231114221320.50Z"), (0x18, b"20231114221320,5Z"),
    (0x18, b"20231114221320.Z"), (0x18, b"20231114221320+0100"), (0x18, b"20231114221320-0000"),
    (0x18, b"20231114221320+0000"), (0x18, b"2023111422132Z"), (0x18, b"202311142213Z"), (0x18, b"20231114221320"),
    (0x18, b"20231314221320Z"), (0x18, b"20230229221320Z"), (0x18, b"20240229221320Z"), (0x18, b"20231114221360Z"),
    (0x18, b"00000101000000Z"), (0x18, b"99991231235959Z"), (0x18, b"2023111422132aZ"), (0x18, b"-0231114221320Z"),
    (0x18, b"20231114221320Zjunk"), (0x18, b"2023111422132\xc3\xa9Z"), (0x18, b"20231114221320.123\xffZ"),
]


def tlv_split(data):
    """(tag, content, rest) of the first element of data."""
    tag, first = data[0], data[1]
    if first < 0x80:
        start, length = 2, first
    else:
        count = first & 0x7f
        start, length = 2 + count, int.from_bytes(data[2:2 + count], "big")
    return tag, data[start:start + length], data[start + length:]


def tlv_children(content):
    out = []
    while content:
        _, body, rest = tlv_split(content)
        out.append(content[:len(content) - len(rest)])
        content = rest
    return out


def crl_with_this_update(crl, time_tag, text):
    """The CRL with its thisUpdate replaced by a TLV of the given tag and contents."""
    _, content, _ = tlv_split(crl)
    top = tlv_children(content)
    _, tbs_content, _ = tlv_split(top[0])
    parts = tlv_children(tbs_content)
    at = next(i for i, part in enumerate(parts) if part[0] in (0x17, 0x18))
    parts[at] = der(time_tag, text)
    return der(0x30, der(0x30, b"".join(parts)) + b"".join(top[1:]))


def csr_and_crl(h, rng, pool):
    # Certificate requests.
    cases, meta = [], []
    for _ in range(300):
        kind, key = pick_key(rng, pool)
        spec = {k: v for k, v in rand_subject(rng).items()}
        if rng.random() < 0.7:
            spec["dns"] = hexlist([rand_hostname(rng) for _ in range(rng.randrange(1, 3))])
        if rng.random() < 0.3:
            spec["email"] = hexlist(["a@example.com"])
        if rng.random() < 0.3:
            spec["ip"] = ",".join(rand_ip(rng).hex() for _ in range(rng.randrange(1, 3)))
        if rng.random() < 0.3:
            spec["uri"] = hexlist(["https://example.com/x"])
        if rng.random() < 0.3:
            spec["extra"] = "1.2.3.4.5|false|0500,2.5.29.19|true|3000"
        if rng.random() < 0.3:
            attrs = []
            for _ in range(rng.randrange(1, 3)):
                oid = rng.choice(["1.2.840.113549.1.9.7", "1.2.840.113549.1.9.14", "1.2.3.9"])
                sets = "/".join("|".join(rand_atv(rng) for _ in range(rng.randrange(1, 3))) for _ in range(rng.randrange(1, 3)))
                attrs.append(f"{oid};{sets}")
            spec["attrs"] = "+".join(attrs)
        sig = rng.choice(SIGALGS[kind])
        if sig:
            spec["sigalg"] = sig
        cases.append(line(op="create", what="csr", key=key, **spec))
        meta.append((kind, sig))
    created = compare_created("create certificate requests", cases, meta, h.go(cases), h.rs(cases))
    h.same("parse created certificate requests", [line(op="parse_csr", der=d) for d in created])
    h.same("parse mutated created certificate requests",
           [line(op="parse_csr", der=m) for d in created for m in text_mutations(rng, d, ERROR_TEXT_MUTATIONS)])
    for d in created[:40]:
        pass
    # Revocation lists: a CA certificate with crlSign and a subject key id.
    cas = []
    for kind in ("p256", "ed25519", "rsa2048", "p384", "mldsa44"):
        key = pool[kind][0]
        spec = dict(cn=b"CRL CA " + kind.encode(), serial="1", nb=1000000000, na=3000000000, ku=96, bc="true:true:-1:false",
                    skid="0102030405", o=hexlist(["Test CA"]))
        cases = [line(op="create", what="cert", key=key, **spec)]
        out = decode(h.go(cases)[0])
        cas.append((kind, key, bytes.fromhex(kv(out[1])["der"])))
    cases, meta = [], []
    for _ in range(200):
        kind, key, issuer = rng.choice(cas)
        spec = dict(number=str(rng.choice([1, 2, 2 ** 100, 2 ** 159])), this=1700000000, next=1700000000 + rng.choice([86400, 0, -1]))
        entries = []
        for _ in range(rng.randrange(0, 4)):
            entries.append("%d:%d:%d" % (rng.randrange(1, 2 ** 70), rng.randrange(900000000, 2200000000), rng.choice([0, 1, 4, 9])))
        if entries:
            spec["entries"] = ",".join(entries)
        if rng.random() < 0.2:
            spec["dep"] = 1
        if rng.random() < 0.2:
            spec["extra"] = "1.2.3.4.5|false|0500"
        sig = rng.choice(SIGALGS[kind])
        if sig:
            spec["sigalg"] = sig
        what = "crl" if rng.random() < 0.8 else "old_crl"
        cases.append(line(op="create", what=what, key=key, issuer=issuer, **spec))
        meta.append((kind, sig, what))
    go, rs = h.go(cases), h.rs(cases)
    created, old = [], []
    for index, (case, g, r) in enumerate(zip(cases, go, rs)):
        gd, rd = decode(g), decode(r)
        if gd[0] != rd[0] or (gd[0] == "err" and gd[1] != rd[1]):
            raise AssertionError(f"create CRL case {index} {meta[index]}: go {gd[0]}: {gd[1][:300]} rust {rd[0]}: {rd[1][:300]}\n  {case[:500]}")
        if gd[0] == "err":
            continue
        gk, rk = kv(gd[1]), kv(rd[1])
        if gk["tbs"] != rk["tbs"]:
            at = next((i for i, (x, y) in enumerate(zip(gk["tbs"], rk["tbs"])) if x != y), 0)
            raise AssertionError(f"create CRL case {index} {meta[index]}: TBS differs at {at}\n go   {gk['tbs'][max(0, at - 40):at + 80]}\n rust {rk['tbs'][max(0, at - 40):at + 80]}\n  {case[:500]}")
        if meta[index][2] == "crl":
            created += [bytes.fromhex(gk["der"]), bytes.fromhex(rk["der"])]
            if gk.get("sigcheck") != rk.get("sigcheck"):
                raise AssertionError(f"CRL signature check differs, case {index}")
        else:
            old += [bytes.fromhex(gk["der"]), bytes.fromhex(rk["der"])]
    COUNTS["create revocation lists"] = len(cases)
    h.same("parse created revocation lists", [line(op="parse_crl", der=d) for d in created])
    h.same("parse created DER CRLs", [line(op="parse_der_crl", der=d) for d in created + old])
    # Times that encoding/asn1 rejects, with time.Parse's messages.
    h.same("parse CRLs with malformed times",
           [line(op=op, der=crl_with_this_update(d, tag, text))
            for d in created[:4] for tag, text in MALFORMED_TIMES for op in ("parse_der_crl",)])
    h.same("parse mutated created DER CRLs",
           [line(op="parse_der_crl", der=m) for d in created + old for m in text_mutations(rng, d, ERROR_TEXT_MUTATIONS)])


def der_len(n):
    if n < 128:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def der(tag, content=b""):
    return bytes([tag]) + der_len(len(content)) + content


def der_oid(dotted):
    arcs = [int(x) for x in dotted.split(".")]
    out = bytearray([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        chunk = [arc & 0x7f]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7f))
            arc >>= 7
        out += bytes(reversed(chunk))
    return der(6, bytes(out))


def der_int(n):
    length = max(1, (n.bit_length() + 8) // 8)
    return der(2, n.to_bytes(length, "big", signed=True))


def ext_spec(oid, critical, value):
    return "%s|%s|%s" % (oid, "true" if critical else "false", value.hex())


def policy_extensions(rng):
    """Raw policy extensions the template cannot express: mappings, constraints, inhibitAny."""
    out = []
    oids = ["1.2.3.1", "1.2.3.2", "1.2.3.3", "1.2.3.4", "2.5.29.32.0"]
    if rng.random() < 0.3:
        pairs = [(rng.choice(oids[:4]), rng.choice(oids[:4] + ["2.5.29.32.0"])) for _ in range(rng.randrange(1, 3))]
        body = b"".join(der(0x30, der_oid(a) + der_oid(b)) for a, b in pairs)
        out.append(ext_spec("2.5.29.33", rng.random() < 0.5, der(0x30, body)))
    if rng.random() < 0.3:
        body = b""
        if rng.random() < 0.6:
            body += der(0x80, rng.choice([0, 1, 2]).to_bytes(1, "big"))
        if rng.random() < 0.6:
            body += der(0x81, rng.choice([0, 1, 2]).to_bytes(1, "big"))
        out.append(ext_spec("2.5.29.36", True, der(0x30, body)))
    if rng.random() < 0.2:
        out.append(ext_spec("2.5.29.54", True, der_int(rng.choice([0, 1, 2]))))
    return out


class Skip(Exception):
    pass


class Pki:
    """Builds certificate hierarchies with Go's CreateCertificate."""

    def __init__(self, h, rng, pool):
        self.h, self.rng, self.pool = h, rng, pool
        self.certs = {}
        self.keys = {}
        self.key_of = {}
        self.serial = 1

    def key(self, name, kinds=None):
        kind, key = pick_key(self.rng, self.pool, kinds)
        self.keys[name] = (kind, key)
        return kind, key

    def make(self, name, parent=None, key_from=None, sign_with=None, **spec):
        """Create certificate `name` signed by `parent` (None: self-signed)."""
        if key_from is None:
            key_from = name
        if key_from not in self.keys:
            self.key(key_from)
        self.key_of[name] = key_from
        kind, key = self.keys[key_from]
        signer = sign_with or parent or name
        skind, skey = self.keys[self.key_of.get(signer, signer)]
        spec.setdefault("serial", str(self.serial))
        self.serial += 1
        spec.setdefault("nb", 1600000000)
        spec.setdefault("na", 2000000000)
        spec.setdefault("cn", name.encode())
        if "sigalg" not in spec:
            algs = [a for a in SIGALGS[skind] if a not in (2, 3, 4, 9) or skind not in ("rsa2048", "p256")]
            spec["sigalg"] = self.rng.choice([a for a in SIGALGS[skind] if a not in (2, 3, 9, 4)] or [0])
        fields = dict(what="cert", key=skey, **spec)
        if parent is not None:
            fields["parent"] = self.certs[parent]
        if key_from != self.key_of.get(signer, signer):
            # The subject key differs from the signing key.
            pubs = go_dump(self.h, [line(op="create", what="key", key=key)])[0]
            fields["pub"] = bytes.fromhex(pubs["pub.pkix"])
        out = decode(self.h.go([line(op="create", **fields)])[0])
        if out[0] == "err":
            raise Skip(f"scenario creation failed for {name}: {out[1]}")
        self.certs[name] = bytes.fromhex(kv(out[1])["der"])
        return self.certs[name]


def verify_line(pki, leaf, inters, roots, **opts):
    return line(op="verify", leaf=pki.certs[leaf], inter=[pki.certs[i] for i in inters], roots=[pki.certs[r] for r in roots], **opts)


def scenario_chain(h, rng, pool):
    """A random chain with random EKUs, validity windows, name constraints and path lengths."""
    pki = Pki(h, rng, pool)
    depth = rng.randrange(0, 4)
    names = ["root"] + ["inter%d" % i for i in range(depth)] + ["leaf"]
    host = rng.choice(["www.example.com", "a.b.example.org", "mail.example.net"])
    ekus_all = [1, 2, 3, 4, 8, 9, 0]
    for i, name in enumerate(names):
        spec = {}
        parent = names[i - 1] if i else None
        is_ca = name != "leaf"
        if is_ca:
            spec["bc"] = "true:true:%d:%s" % (rng.choice([-1, -1, 0, 1, 2]), rng.choice(["true", "false"]))
            spec["ku"] = rng.choice([96, 96, 32, 64, 1, 97])
            if rng.random() < 0.3:
                spec["skid"] = ("%02x" % (i + 1)) * 4
        else:
            spec["dns"] = hexlist([host, "other.example.com"])
            spec["ku"] = rng.choice([1, 5, 0, 32])
            if rng.random() < 0.3:
                spec["akid"] = ("%02x" % i) * 4
        if rng.random() < 0.5:
            spec["eku"] = ",".join(str(rng.choice(ekus_all)) for _ in range(rng.randrange(1, 3)))
        if rng.random() < 0.4:
            spec["nb"] = rng.choice([1600000000, 1700000000, 1800000000])
            spec["na"] = rng.choice([1900000000, 2000000000, 1750000000])
        if is_ca and rng.random() < 0.25:
            if rng.random() < 0.5:
                spec["pdns"] = hexlist([rng.choice(["example.com", ".example.com", "example.org", "b.example.org"])])
            if rng.random() < 0.4:
                spec["edns"] = hexlist([rng.choice(["other.example.com", "mail.example.net", "example.org"])])
            if rng.random() < 0.2:
                spec["pdc"] = rng.choice(["true", "false"])
        if rng.random() < 0.2:
            spec["pols"] = ",".join(rng.sample(["1.2.3.1", "1.2.3.2", "2.5.29.32.0"], rng.randrange(1, 3)))
        if rng.random() < 0.15:
            spec["extra"] = ",".join(policy_extensions(rng))
            if not spec["extra"]:
                del spec["extra"]
        if rng.random() < 0.05:
            spec["extra"] = (spec.get("extra", "") + ("," if spec.get("extra") else "")) + "1.2.3.4.5.6|true|0500"
        pki.make(name, parent, **spec)
    cases = []
    for _ in range(4):
        opts = {"time": rng.choice([1650000000, 1700000000, 1760000000, 1850000000, 1950000000, 2100000000, 1500000000])}
        if rng.random() < 0.8:
            opts["dns"] = b(rng.choice([host, "OTHER.example.com", "nomatch.example.com", host + ".", "1.2.3.4", ""]))
        if rng.random() < 0.5:
            opts["ekus"] = ",".join(str(rng.choice([0, 1, 2, 3, 9])) for _ in range(rng.randrange(1, 3)))
        if rng.random() < 0.3:
            opts["policies"] = ",".join(rng.choice(["1.2.3.1", "1.2.3.2", "1.2.3.3", "2.5.29.32.0"]) for _ in range(rng.randrange(1, 3)))
        # Intermediates all in the pool; sometimes drop one to get an unknown authority.
        inters = names[1:-1]
        roots = ["root"]
        if inters and rng.random() < 0.1:
            inters = inters[:-1]
        if rng.random() < 0.05:
            roots = []
        cases.append(verify_line(pki, "leaf", inters, roots, **opts))
    return cases


def scenario_cross(h, rng, pool):
    """Cross-signed intermediates and multiple roots: several chains per leaf."""
    pki = Pki(h, rng, pool)
    ca = lambda **kw: dict(bc="true:true:-1:false", ku=96, **kw)
    pki.make("rootA", None, **ca())
    pki.make("rootB", None, **ca())
    if rng.random() < 0.5:
        pki.make("rootAcross", "rootB", key_from="rootA", cn=b"rootA", **ca())
    pki.keys["inter"] = pki.keys.get("inter") or pki.key("inter")
    pki.make("interA", "rootA", key_from="inter", cn=b"inter", **ca(skid="aabbccdd"))
    pki.make("interB", "rootB", key_from="inter", cn=b"inter", **ca(skid="aabbccdd"))
    if rng.random() < 0.5:
        pki.make("interC", "interA", key_from="inter", cn=b"inter", **ca(skid="aabbccdd"))
    spec = dict(dns=hexlist(["leaf.example.com"]), ku=1)
    if rng.random() < 0.5:
        spec["akid"] = "aabbccdd"
    pki.make("leaf", "interA", key_from="inter" if False else None, **spec)
    cases = []
    inter_sets = [["interA", "interB"], ["interB", "interA"], ["interA"], ["interB"]]
    if "interC" in pki.certs:
        inter_sets.append(["interA", "interB", "interC"])
    extra_roots = ["rootAcross"] if "rootAcross" in pki.certs else []
    for inters in inter_sets:
        for roots in (["rootA", "rootB"], ["rootB"], ["rootA"], ["rootB", "rootA"]):
            cases.append(verify_line(pki, "leaf", inters + extra_roots, roots, time=1700000000, dns=b"leaf.example.com"))
    return cases


def scenario_constraints(h, rng, pool):
    """Name constraints against random SAN sets."""
    pki = Pki(h, rng, pool)
    cons = {}
    if rng.random() < 0.7:
        cons["pdns"] = hexlist(rng.sample(["example.com", ".example.com", "sub.example.com", "example.org"], rng.randrange(1, 3)))
    if rng.random() < 0.5:
        cons["edns"] = hexlist(rng.sample(["bad.example.com", ".bad.example.com", "example.net"], rng.randrange(1, 3)))
    if rng.random() < 0.4:
        cons["pip"] = rng.choice(["0a000000/ff000000", "c0a80000/ffff0000,0a000000/ff000000"])
    if rng.random() < 0.3:
        cons["eip"] = "0a010000/ffff0000"
    if rng.random() < 0.4:
        cons["pemail"] = hexlist(rng.sample(["example.com", "user@example.com", ".example.com"], rng.randrange(1, 3)))
    if rng.random() < 0.3:
        cons["eemail"] = hexlist(["bad@example.com", "example.net"][:rng.randrange(1, 3)])
    if rng.random() < 0.4:
        cons["puri"] = hexlist(rng.sample(["example.com", ".example.com", "sub.example.com"], rng.randrange(1, 3)))
    if rng.random() < 0.3:
        cons["euri"] = hexlist(["bad.example.com"])
    if not cons:
        cons["pdns"] = hexlist(["example.com"])
    cons["pdc"] = rng.choice(["true", "false"])
    where = rng.choice(["root", "inter"])
    pki.make("root", None, bc="true:true:-1:false", ku=96, **(cons if where == "root" else {}))
    pki.make("inter", "root", bc="true:true:-1:false", ku=96, **(cons if where == "inter" else {}))
    sans = {}
    sans["dns"] = hexlist(rng.sample(["a.example.com", "example.com", "sub.example.com", "bad.example.com", "x.bad.example.com", "example.org", "example.net", "*.example.com", "B.EXAMPLE.COM"], rng.randrange(0, 4)))
    if rng.random() < 0.5:
        sans["ip"] = ",".join(rng.choice(["0a000001", "0a010203", "c0a80101", "08080808", "20010db8000000000000000000000001"]) for _ in range(rng.randrange(1, 3)))
    if rng.random() < 0.5:
        sans["email"] = hexlist(rng.sample(["user@example.com", "bad@example.com", "other@example.org", "a@sub.example.com", "u@example.net"], rng.randrange(1, 3)))
    if rng.random() < 0.5:
        sans["uri"] = hexlist(rng.sample(["https://example.com/x", "https://a.example.com/", "https://bad.example.com/", "https://example.org:8443/p", "https://10.0.0.1/"], rng.randrange(1, 3)))
    pki.make("leaf", "inter", ku=1, **sans)
    return [verify_line(pki, "leaf", ["inter"], ["root"], time=1700000000)]


def scenario_misc(h, rng, pool):
    """Odd leaf/intermediate flags and errors."""
    pki = Pki(h, rng, pool)
    pki.make("root", None, bc="true:true:-1:false", ku=96, skid="01010101")
    kind = rng.choice(["notca", "noku", "pathlen0", "sha1", "unknown_critical", "wrong_signer", "dup_subject", "no_bc", "leaf_is_root", "ku_nocertsign"])
    cases = []
    if kind == "notca":
        pki.make("inter", "root", bc="true:false:-1:false", ku=96)
        pki.make("leaf", "inter", dns=hexlist(["leaf.example.com"]))
        cases.append(verify_line(pki, "leaf", ["inter"], ["root"], time=1700000000))
    elif kind == "no_bc":
        pki.make("inter", "root", ku=96)
        pki.make("leaf", "inter", dns=hexlist(["leaf.example.com"]))
        cases.append(verify_line(pki, "leaf", ["inter"], ["root"], time=1700000000))
    elif kind == "ku_nocertsign":
        pki.make("inter", "root", bc="true:true:-1:false", ku=1)
        pki.make("leaf", "inter", dns=hexlist(["leaf.example.com"]))
        cases.append(verify_line(pki, "leaf", ["inter"], ["root"], time=1700000000))
    elif kind == "pathlen0":
        pki.make("inter", "root", bc="true:true:0:true", ku=96)
        pki.make("inter2", "inter", bc="true:true:-1:false", ku=96)
        pki.make("leaf", "inter2", dns=hexlist(["leaf.example.com"]))
        cases.append(verify_line(pki, "leaf", ["inter", "inter2"], ["root"], time=1700000000))
    elif kind == "sha1":
        pki.keys["inter"] = pki.key("inter", ["rsa2048"])
        pki.make("inter", "root", bc="true:true:-1:false", ku=96, sigalg=3) if pki.keys["root"][0] == "rsa2048" else pki.make("inter", "root", bc="true:true:-1:false", ku=96)
        pki.make("leaf", "inter", dns=hexlist(["leaf.example.com"]), sigalg=3)
        cases.append(verify_line(pki, "leaf", ["inter"], ["root"], time=1700000000))
    elif kind == "unknown_critical":
        pki.make("inter", "root", bc="true:true:-1:false", ku=96)
        pki.make("leaf", "inter", dns=hexlist(["leaf.example.com"]), extra="1.2.3.4.5.6|true|0500")
        cases.append(verify_line(pki, "leaf", ["inter"], ["root"], time=1700000000))
    elif kind == "wrong_signer":
        pki.key("other")
        pki.make("inter", "root", bc="true:true:-1:false", ku=96, skid="02020202")
        pki.make("leaf", "inter", sign_with="other", dns=hexlist(["leaf.example.com"]))
        cases.append(verify_line(pki, "leaf", ["inter"], ["root"], time=1700000000))
    elif kind == "dup_subject":
        # Many intermediates with the same subject and different keys.
        for i in range(rng.choice([5, 30, 120])):
            pki.key("x%d" % i, ["p256", "ed25519"])
            pki.make("x%d" % i, "root", bc="true:true:-1:false", ku=96, cn=b"dup", skid=b"%04d" % i and ("%08x" % i))
        pki.key("realinter")
        pki.make("realinter", "root", bc="true:true:-1:false", ku=96, cn=b"dup")
        pki.make("leaf", "realinter", dns=hexlist(["leaf.example.com"]))
        inters = ["x%d" % i for i in range(len([k for k in pki.certs if k.startswith("x")]))] + ["realinter"]
        cases.append(verify_line(pki, "leaf", inters, ["root"], time=1700000000))
    elif kind == "leaf_is_root":
        cases.append(verify_line(pki, "root", [], ["root"], time=1700000000))
        cases.append(verify_line(pki, "root", [], [], time=1700000000))
    else:
        pki.make("inter", "root", bc="true:true:-1:false", ku=96)
        pki.make("leaf", "inter", dns=hexlist(["leaf.example.com"]), ku=rng.choice([1, 2]))
        cases.append(verify_line(pki, "leaf", ["inter"], ["root"], time=1700000000, dns=b"leaf.example.com"))
    return cases


def policy_scenarios(h, rng):
    """Go's policy testdata in every root/intermediate/leaf combination with several policy sets."""
    data = go_root() / "src" / "crypto" / "x509" / "testdata"
    def load(name):
        for label, d in pem_blocks((data / name).read_text()):
            if label == "CERTIFICATE":
                return d
    leaves = sorted(p.name for p in data.glob("policy_leaf*.pem"))
    inters = sorted(p.name for p in data.glob("policy_intermediate*.pem"))
    roots = sorted(p.name for p in data.glob("policy_root*.pem"))
    cases = []
    sets = ["", "1.2.3.1", "1.2.3.2", "1.2.3.3", "1.2.3.1,1.2.3.2", "2.5.29.32.0", "1.2.3.4", "1.2.3.5"]
    for leaf in leaves:
        for inter in inters:
            for root in roots:
                for pols in rng.sample(sets, 3):
                    cases.append(line(op="verify", leaf=load(leaf), inter=[load(inter)], roots=[load(root)], time=1770000000, policies=pols))
        # Also two intermediates and a chain without intermediates.
        for root in roots:
            cases.append(line(op="verify", leaf=load(leaf), inter=[load(i) for i in inters], roots=[load(root)], time=1770000000))
    return cases


def verification(h, rng, pool):
    cases = []
    skipped = 0
    for scenario, count in ((scenario_chain, 150), (scenario_cross, 20), (scenario_constraints, 150), (scenario_misc, 60)):
        for _ in range(count):
            try:
                cases += scenario(h, rng, pool)
            except Skip:
                skipped += 1
    cases += policy_scenarios(h, rng)
    go, rs = h.same("verify", cases)
    ok = sum(1 for g in go if "dump" in g and "chains=" in decode(g)[1])
    multi = sum(1 for g in go if "dump" in g and "chain[1]" in decode(g)[1])
    print(f"verify: {skipped} scenarios skipped (invalid for Go); {ok} of {len(cases)} cases built chains, {multi} with several chains")


def main():
    if not shutil.which("go") or not shutil.which("cargo"):
        raise RuntimeError("x509 differential check requires Go and Cargo on PATH")
    rng = random.Random(SEED)
    h = Harness()
    only = set(sys.argv[1:])
    pool = None
    for step in (parsing, oids, names, keys, creation, csr_and_crl, verification):
        if only and step.__name__ not in only:
            continue
        if step in (keys, creation, csr_and_crl, verification):
            pool = pool or keypool(h, rng)
            step(h, rng, pool)
        else:
            step(h, rng)
        print(f"{step.__name__}: ok", flush=True)
    total = sum(COUNTS.values())
    accepted = ""
    if ACCEPTED_LOSSY:
        groups = sorted(set(ACCEPTED_LOSSY))
        accepted = f" ({len(ACCEPTED_LOSSY)} go-string-invalid-utf8 substitutions accepted in {', '.join(groups)})"
    print(f"x509 differential: {total} cases compared in {len(COUNTS)} groups{accepted}")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, AssertionError, subprocess.SubprocessError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
