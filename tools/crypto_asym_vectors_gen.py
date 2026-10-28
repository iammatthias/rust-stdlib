#!/usr/bin/env python3
"""Extract the known-answer vectors of Go's asymmetric crypto tests into
crates/crypto/tests/fixtures/*.tsv.

Usage: crypto_asym_vectors_gen.py WYCHEPROOF_CHECKOUT [OUTDIR]

Go's tests load C2SP/wycheproof test vectors at the version pinned in
$GOROOT/src/crypto/internal/cryptotest/wycheproof/schemaversion.go (clone
https://github.com/C2SP/wycheproof and check that commit out) and a few
tables and files under $GOROOT/src/crypto/*/testdata. Each fixture row is one
test case: tab-separated hex fields (an empty field is an empty byte string)
and bare words. Wycheproof is Apache-2.0 and Go is BSD-licensed; see NOTICE.
"""
import bz2
import gzip
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
GOROOT = Path(subprocess.check_output(["go", "env", "GOROOT"], text=True).strip())


def write(out, name, header, rows):
    path = out / name
    with path.open("w") as f:
        f.write(f"# {header}\n")
        for row in rows:
            f.write("\t".join(row) + "\n")
    print(f"{name}: {len(rows)} rows")


def sample(tests, per_flag=25):
    """Keeps the first `per_flag` tests of every flag, in file order: every
    class of edge case stays covered while the fixtures stay small."""
    seen = {}
    keep = []
    for test in tests:
        flags = test.get("flags") or [""]
        if any(seen.get(flag, 0) < per_flag for flag in flags):
            keep.append(test)
            for flag in flags:
                seen[flag] = seen.get(flag, 0) + 1
    return keep


def wycheproof(wp, name):
    return json.loads((wp / "testvectors_v1" / name).read_text())


def ed25519(wp, out):
    data = wycheproof(wp, "ed25519_test.json")
    rows = []
    for group in data["testGroups"]:
        for t in group["tests"]:
            rows.append([group["publicKeyDer"], t["msg"], t["sig"], t["result"]])
    write(out, "ed25519_wycheproof.tsv",
          "Wycheproof ed25519_test.json: SPKI DER, msg, sig, result", rows)

    rows = []
    with gzip.open(GOROOT / "src/crypto/ed25519/testdata/sign.input.gz", "rt") as f:
        lines = f.read().splitlines()
    for line in lines[::8]:
        priv, pub, msg, sigmsg, _ = line.split(":")
        rows.append([priv[:64], pub, msg, sigmsg[:128]])
    write(out, "ed25519_golden.tsv",
          "Go crypto/ed25519 testdata/sign.input.gz (every 8th line): seed, public key, msg, sig", rows)


def ecdh(wp, out):
    rows = []
    for kind, names in (
        ("ecpoint", ["ecdh_secp256r1_ecpoint_test.json", "ecdh_secp384r1_ecpoint_test.json", "ecdh_secp521r1_ecpoint_test.json"]),
        ("asn", ["ecdh_secp256r1_test.json", "ecdh_secp384r1_test.json", "ecdh_secp521r1_test.json"]),
        ("x25519", ["x25519_test.json"]),
    ):
        for name in names:
            for group in wycheproof(wp, name)["testGroups"]:
                for t in sample(group["tests"]):
                    rows.append([kind, group["curve"], t["public"], t["private"], t["shared"],
                                 t["result"], ",".join(t["flags"])])
    write(out, "ecdh_wycheproof.tsv",
          "Wycheproof ecdh_secp{256,384,521}r1{,_ecpoint}_test.json and x25519_test.json: kind, curve, public, private, shared, result, flags", rows)


def ecdsa(wp, out):
    curves = {
        "secp224r1": ["sha224", "sha256", "sha512", "sha3_224", "sha3_256", "sha3_512"],
        "secp256r1": ["sha256", "sha512", "sha3_256", "sha3_512"],
        "secp384r1": ["sha256", "sha384", "sha512", "sha3_384", "sha3_512"],
        "secp521r1": ["sha512", "sha3_512"],
    }
    rows = []
    for curve, hashes in curves.items():
        for h in hashes:
            merged = []
            for group in wycheproof(wp, f"ecdsa_{curve}_{h}_test.json")["testGroups"]:
                merged += [dict(t, group=group) for t in group["tests"]]
            for t in sample(merged, 4):
                group = t["group"]
                rows.append([curve, group["sha"], group["publicKeyDer"], t["msg"], t["sig"],
                             t["result"], ",".join(t["flags"])])
    write(out, "ecdsa_wycheproof.tsv",
          "Wycheproof ecdsa_<curve>_<hash>_test.json (4 per flag): curve, hash, SPKI DER, msg, ASN.1 sig, result, flags", rows)

    rows = []
    curve = hashname = None
    fields = {}
    text = bz2.open(GOROOT / "src/crypto/ecdsa/testdata/SigVer.rsp.bz2", "rt").read()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            curve, _, hashname = line[1:-1].partition(",")
            continue
        key, _, value = line.partition(" = ")
        fields[key] = value
        if key == "Result":
            if curve in ("P-224", "P-256", "P-384", "P-521") and hashname in ("SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"):
                rows.append([curve, hashname, fields["Msg"], fields["Qx"], fields["Qy"], fields["R"], fields["S"], fields["Result"][0]])
            fields = {}
    write(out, "ecdsa_sigver.tsv",
          "NIST CAVS 186-3 SigVer (Go crypto/ecdsa/testdata/SigVer.rsp.bz2): curve, hash, msg, Qx, Qy, R, S, P|F", rows)


def elliptic(wp, out):
    src = (GOROOT / "src/crypto/elliptic/p224_test.go").read_text()
    body = src.split("var p224BaseMultTests", 1)[1].split("\n}\n", 1)[0]
    rows = []
    for k, x, y in re.findall(r'\{\s*"([0-9]+)",\s*"([0-9a-f]+)",\s*"([0-9a-f]+)",?\s*\}', body):
        rows.append([format(int(k), "x"), x, y])
    write(out, "elliptic_p224_basemult.tsv",
          "Go crypto/elliptic p224_test.go p224BaseMultTests: k, x, y (hex)", rows)


def rsa(wp, out):
    keys = {}

    def key_id(kind, der_hex):
        """Keys are shared by id so that large private keys are stored once."""
        keys.setdefault((kind, der_hex), f"k{len(keys)}")
        return keys[(kind, der_hex)]

    oaep, pkcs1_decrypt, pkcs1_sig, pss = [], [], [], []
    oaep_files = [p.name for p in sorted((wp / "testvectors_v1").glob("rsa_oaep_*_test.json"))
                  if "misc" not in p.name]
    oaep_files += ["rsa_oaep_misc_test.json"] + [
        p.name for p in sorted((wp / "testvectors_v1").glob("rsa_three_primes_oaep_*_test.json"))]
    for name in oaep_files:
        merged = []
        for group in wycheproof(wp, name)["testGroups"]:
            merged += [dict(t, group=group) for t in group["tests"]]
        for t in sample(merged, 3):
            g = t["group"]
            oaep.append([key_id("pkcs8", g["privateKeyPkcs8"]), g["sha"], g["mgfSha"], t["label"], t["ct"],
                         t["msg"], t["result"], ",".join(t["flags"])])
    write(out, "rsa_oaep.tsv",
          "Wycheproof rsa_oaep_*_test.json and rsa_three_primes_oaep_*: key, hash, mgf hash, label, ct, msg, result, flags", oaep)

    for name in ("rsa_pkcs1_2048_test.json", "rsa_pkcs1_3072_test.json", "rsa_pkcs1_4096_test.json"):
        merged = []
        for group in wycheproof(wp, name)["testGroups"]:
            merged += [dict(t, group=group) for t in group["tests"]]
        for t in sample(merged, 4):
            pkcs1_decrypt.append([key_id("pkcs8", t["group"]["privateKeyPkcs8"]), t["ct"], t["msg"],
                                  t["result"], ",".join(t["flags"])])
    write(out, "rsa_pkcs1_decrypt.tsv", "Wycheproof rsa_pkcs1_{2048,3072,4096}_test.json: key, ct, msg, result, flags",
          pkcs1_decrypt)

    mods = {2048: ["sha224", "sha256", "sha384", "sha512", "sha512_224", "sha512_256",
                   "sha3_224", "sha3_256", "sha3_384", "sha3_512"],
            3072: ["sha256", "sha384", "sha512", "sha512_256", "sha3_256", "sha3_384", "sha3_512"],
            4096: ["sha256", "sha384", "sha512", "sha512_256"], 8192: ["sha256", "sha384", "sha512"]}
    for mod, hashes in mods.items():
        for h in hashes:
            merged = []
            for group in wycheproof(wp, f"rsa_signature_{mod}_{h}_test.json")["testGroups"]:
                merged += [dict(t, group=group) for t in group["tests"]]
            for t in sample(merged, 2):
                g = t["group"]
                pkcs1_sig.append([key_id("pkcs1pub", g["publicKeyAsn"]), g["sha"], t["msg"], t["sig"],
                                  t["result"], ",".join(t["flags"])])
    write(out, "rsa_pkcs1_sig.tsv",
          "Wycheproof rsa_signature_<bits>_<hash>_test.json: key, hash, msg, sig, result, flags", pkcs1_sig)

    zero_slen = {
        "rsa_pss_2048_sha1_mgf1_20_test.json": [46, 47, 48, 49, 50, 51],
        "rsa_pss_2048_sha256_mgf1_0_test.json": [67, 68, 69, 70],
        "rsa_pss_2048_sha256_mgf1_32_test.json": [67, 68, 69, 70, 71, 72],
        "rsa_pss_3072_sha256_mgf1_32_test.json": [67, 68, 69, 70, 71, 72],
        "rsa_pss_4096_sha256_mgf1_32_test.json": [67, 68, 69, 70, 71, 72],
        "rsa_pss_4096_sha512_mgf1_32_test.json": [136, 137, 138, 139, 140, 141],
        "rsa_pss_misc_test.json": [],
    }
    for name, overrides in zero_slen.items():
        merged = []
        for group in wycheproof(wp, name)["testGroups"]:
            if name == "rsa_pss_misc_test.json" and group["sha"] != group["mgfSha"]:
                continue
            merged += [dict(t, group=group) for t in group["tests"]]
        # Keep the override cases: the zero-salt exception applies to them.
        chosen = sample(merged, 4)
        chosen += [t for t in merged if t["tcId"] in overrides and t not in chosen]
        for t in chosen:
            g = t["group"]
            pss.append([key_id("pkcs1pub", g["publicKeyAsn"]), g["sha"], str(g["sLen"]), t["msg"], t["sig"],
                        t["result"], ",".join(t["flags"]), "1" if t["tcId"] in overrides else "0"])
    write(out, "rsa_pss.tsv",
          "Wycheproof rsa_pss_*_test.json: key, hash, sLen, msg, sig, result, flags, passes-with-auto-salt", pss)

    # Go's own tests: keys, OAEP known answers and the PSS vectors from PKCS #1 v2.1.
    go_src = (GOROOT / "src/crypto/rsa/rsa_test.go").read_text()
    names = {"priv": "gnutls128", "k": "psmallerq", "test2048KeyPEM": "test2048"}
    rows = []
    import base64
    for m in re.finditer(r'(\w+)\s*:?=\s*(?:parseKey\()?testingKey\(`-----BEGIN (RSA )?TESTING KEY-----\n(.*?)-----END',
                         go_src, re.S):
        name = names.get(m.group(1), m.group(1))
        name = re.sub(r"^test(\d+)Key$", r"test\1", name)
        der = base64.b64decode(m.group(3)).hex()
        rows.append([name, "pkcs1" if m.group(2) else "pkcs8", der])
    write(out, "rsa_go_keys.tsv", "Go crypto/rsa rsa_test.go keys: name, pkcs1|pkcs8, DER", rows)

    section = go_src.split("var testEncryptOAEPData", 1)[1].split("\nfunc ", 1)[0]
    rows = []
    for block in re.split(r"\n\t// Key \d+\n", section)[1:]:
        strings = re.findall(r'"([0-9a-f]+)"', block)
        e = re.search(r'",\s*\n\s*(\d+),', block).group(1)
        modulus, d = strings[0], strings[1]
        arrays = [bytes(int(x, 16) for x in re.findall(r"0x([0-9a-f]{2})", a)).hex()
                  for a in re.findall(r"\[\]byte\{(.*?)\}", block, re.S)]
        for i in range(0, len(arrays), 3):
            rows.append([modulus, e, d, arrays[i], arrays[i + 1], arrays[i + 2]])
    write(out, "rsa_oaep_kat.tsv",
          "Go crypto/rsa testEncryptOAEPData (PKCS #1 v2.1 vectors, SHA-1): n, e, d, msg, seed, ct", rows)

    rows = []
    text = bz2.open(GOROOT / "src/crypto/rsa/testdata/pss-vect.txt.bz2", "rt").read()
    values = []
    partial = ""
    last_was_value = True
    for line in text.splitlines():
        if not line:
            if partial:
                values.append(partial.replace(" ", ""))
                partial = ""
                last_was_value = True
            continue
        if line.startswith("# ======") and last_was_value:
            values.append("START NEW KEY")
            last_was_value = False
        elif line.startswith("# ------") and last_was_value:
            values.append("START NEW SIGNATURE")
            last_was_value = False
        elif line.startswith("#"):
            continue
        else:
            partial += line
    if partial:
        values.append(partial.replace(" ", ""))
    n = e = None
    i = 0
    while i < len(values):
        if values[i] == "START NEW KEY":
            if i + 2 >= len(values):
                break
            n, e = values[i + 1], values[i + 2]
            i += 9
        elif values[i] == "START NEW SIGNATURE":
            rows.append([n, e, values[i + 1], values[i + 3]])
            i += 4
        else:
            raise SystemExit(f"unexpected marker {values[i][:20]}")
    write(out, "rsa_pss_golden.tsv", "Go crypto/rsa testdata/pss-vect.txt (SHA-1, salt = hash length): n, e, msg, sig", rows)

    write(out, "rsa_keys.tsv", "Wycheproof keys referenced by id: id, pkcs8|pkcs1pub, DER",
          [[kid, kind, der] for (kind, der), kid in keys.items()])


def mlkem(wp, out):
    rows = []
    for param in ("768", "1024"):
        for kind, name in (("keygen", f"mlkem_{param}_keygen_seed_test.json"),
                           ("encaps", f"mlkem_{param}_encaps_test.json"),
                           ("decaps", f"mlkem_{param}_test.json")):
            merged = []
            for group in wycheproof(wp, name)["testGroups"]:
                merged += group["tests"]
            for t in sample(merged, 12 if kind != "keygen" else 20):
                rows.append([kind, param, t.get("seed") or "", t.get("m") or "", t.get("ek") or "",
                             t.get("c") or "", t.get("K") or "", t["result"], ",".join(t.get("flags", []))])
    write(out, "mlkem_wycheproof.tsv",
          "Wycheproof mlkem_{768,1024}_{keygen_seed,encaps,}_test.json: kind, param, seed, m, ek, c, K, result, flags",
          rows)


def mldsa(wp, out):
    keys = {}
    verify, sign = [], []
    for param in ("44", "65", "87"):
        merged = []
        for group in wycheproof(wp, f"mldsa_{param}_verify_test.json")["testGroups"]:
            merged += [dict(t, group=group) for t in group["tests"]]
        for t in sample(merged, 2):
            pk = t["group"]["publicKey"]
            keys.setdefault(pk, f"p{len(keys)}")
            verify.append([param, keys[pk], t["msg"], t.get("ctx") or "", t["sig"], t["result"],
                           ",".join(t["flags"])])
        merged = []
        for group in wycheproof(wp, f"mldsa_{param}_sign_seed_test.json")["testGroups"]:
            merged += [dict(t, group=group) for t in group["tests"] if "Randomized" not in t["flags"]]
        for t in sample(merged, 2):
            g = t["group"]
            pk = g.get("publicKey") or ""
            if pk:
                keys.setdefault(pk, f"p{len(keys)}")
            sign.append([param, g["privateSeed"], keys.get(pk, ""), t.get("msg") or "", t.get("ctx") or "",
                         t.get("mu") or "", t["sig"], t["result"], ",".join(t["flags"])])
    write(out, "mldsa_keys.tsv", "Wycheproof ML-DSA public keys by id: id, public key", [[v, k] for k, v in keys.items()])
    write(out, "mldsa_verify.tsv", "Wycheproof mldsa_{44,65,87}_verify_test.json: param, key id, msg, ctx, sig, result, flags", verify)
    write(out, "mldsa_sign.tsv",
          "Wycheproof mldsa_{44,65,87}_sign_seed_test.json (deterministic): param, seed, public key id, msg, ctx, mu, sig, result, flags",
          sign)


def dsa(wp, out):
    rows = []
    for name in ("dsa_2048_224_sha224_test.json", "dsa_2048_224_sha256_test.json",
                 "dsa_2048_256_sha256_test.json", "dsa_3072_256_sha256_test.json"):
        merged = []
        for group in wycheproof(wp, name)["testGroups"]:
            merged += [dict(t, group=group) for t in group["tests"]]
        for t in sample(merged, 4):
            g = t["group"]
            rows.append([g["publicKeyDer"], g["sha"], t["msg"], t["sig"], t["result"], ",".join(t["flags"])])
    write(out, "dsa_wycheproof.tsv",
          "Wycheproof dsa_{2048_224_sha224,2048_224_sha256,2048_256_sha256,3072_256_sha256}_test.json: SPKI DER, hash, msg, ASN.1 sig, result, flags",
          rows)


def hpke(wp, out):
    vectors = json.loads((GOROOT / "src/crypto/hpke/testdata/rfc9180.json").read_text())
    rows = []
    for v in vectors:
        if v["mode"] != 0 or not v.get("exports_accumulated"):
            continue
        rows.append([str(v["kem_id"]), str(v["kdf_id"]), str(v["aead_id"]), v["info"], v["ikmE"], v["ikmR"],
                     v["skRm"], v["pkRm"], v["enc"], v.get("encryptions_accumulated", ""), v["exports_accumulated"]])
    write(out, "hpke_rfc9180.tsv",
          "Go crypto/hpke testdata/rfc9180.json, base mode: kem, kdf, aead, info, ikmE, ikmR, skRm, pkRm, enc, accumulated encryptions, accumulated exports",
          rows)


def main():
    wp = Path(sys.argv[1])
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "crates/crypto/tests/fixtures"
    for step in (ed25519, ecdh, ecdsa, elliptic, rsa, mlkem, mldsa, dsa, hpke):
        step(wp, out)


if __name__ == "__main__":
    main()
