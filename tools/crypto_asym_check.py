#!/usr/bin/env python3
"""Differentially compare the asymmetric crypto packages with Go.

Random keys, messages and mutated inputs are fed to tools/crypto_asym_oracle.go
and crates/crypto/examples/crypto_asym_probe.rs, which implement one protocol
(one `op=... key=value` line in, one `name=value` line out; `err=1` for an
error or panic). Deterministic operations (Ed25519 and ML-DSA signatures,
ECDSA with RFC 6979, PKCS #1 v1.5 signatures, ECDH, ML-KEM, key import and
elliptic-curve arithmetic) must produce identical bytes. Randomized operations
(ECDSA, PSS, OAEP, PKCS #1 v1.5 encryption, ML-KEM encapsulation, ML-DSA
hedged signing, DSA, HPKE) are produced by each implementation and then
verified, decrypted or opened by both.
"""
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
COUNTS = {}


def line(**kw):
    parts = []
    for key, value in kw.items():
        if isinstance(value, (bytes, bytearray)):
            value = value.hex()
        parts.append(f"{key}={value}")
    return " ".join(parts)


def parse(text):
    if text == "":
        return {}
    return dict(token.split("=", 1) for token in text.split(" "))


def run(command, cases, env):
    result = subprocess.run(command, input="".join(c + "\n" for c in cases), text=True, capture_output=True,
                            cwd=ROOT, env=env, timeout=1800)
    if result.returncode != 0:
        raise RuntimeError(f"{command[0]} failed:\n{result.stderr[-3000:]}")
    lines = result.stdout.split("\n")[:-1]
    if len(lines) != len(cases):
        raise RuntimeError(f"{command[0]}: {len(lines)} outputs for {len(cases)} cases")
    return [parse(t) for t in lines]


class Harness:
    def __init__(self):
        self.env = os.environ.copy()
        self.env["GOTOOLCHAIN"] = "local"
        oracle = ROOT / "target" / "crypto_asym_oracle"
        oracle.parent.mkdir(exist_ok=True)
        subprocess.run(["go", "build", "-o", str(oracle), "tools/crypto_asym_oracle.go"],
                       cwd=ROOT, env=self.env, check=True)
        self.go_cmd = [str(oracle)]
        subprocess.run(["cargo", "build", "--offline", "--locked", "--quiet", "--manifest-path",
                        "crates/crypto/Cargo.toml", "--example", "crypto_asym_probe"], cwd=ROOT, env=self.env, check=True)
        meta = json.loads(subprocess.check_output(
            ["cargo", "metadata", "--offline", "--locked", "--no-deps", "--format-version", "1",
             "--manifest-path", "crates/crypto/Cargo.toml"], cwd=ROOT, env=self.env, text=True))
        self.rs_cmd = [str(Path(meta["target_directory"]) / "debug" / "examples" / "crypto_asym_probe")]

    def go(self, cases):
        return run(self.go_cmd, cases, self.env)

    def rs(self, cases):
        return run(self.rs_cmd, cases, self.env)

    def same(self, name, cases, skip=()):
        """Both implementations must produce identical output for every case."""
        go, rs = self.go(cases), self.rs(cases)
        for index, (case, g, r) in enumerate(zip(cases, go, rs)):
            gv = {k: v for k, v in g.items() if k not in skip}
            rv = {k: v for k, v in r.items() if k not in skip}
            if gv != rv:
                raise AssertionError(f"{name} case {index} differs:\n  go  : {g}\n  rust: {r}\n  input: {case[:500]}")
        COUNTS[name] = COUNTS.get(name, 0) + len(cases)
        return go, rs


def flip(rng, data: bytes) -> bytes:
    if not data:
        return data
    at = rng.randrange(len(data))
    return data[:at] + bytes([data[at] ^ (1 << rng.randrange(8))]) + data[at + 1:]


def blob(rng, size):
    return bytes(rng.randrange(256) for _ in range(size))


def text(rng, size):
    """Printable ASCII: Rust contexts are Strings, Go's are arbitrary bytes."""
    return bytes(rng.randrange(0x20, 0x7f) for _ in range(size))


def digest(name, msg):
    return hashlib.new(name, msg).digest()


def ed25519(h, rng):
    cases = []
    for _ in range(300):
        seed = blob(rng, 32)
        msg = blob(rng, rng.choice([0, 1, 5, 64, 200]))
        cases.append(line(op="ed_keygen", seed=seed))
        cases.append(line(op="ed_sign", seed=seed, msg=msg, mode="plain", ctx=b""))
        cases.append(line(op="ed_sign", seed=seed, msg=msg, mode="ph", ctx=text(rng, rng.choice([0, 3, 255]))))
    cases.append(line(op="ed_keygen", seed=blob(rng, 31)))
    cases.append(line(op="ed_sign", seed=blob(rng, 32), msg=b"x", mode="ph", ctx=text(rng, 256)))
    go, rs = h.same("ed25519 keygen/sign", cases)
    # Public keys come from the keygen outputs.
    pubs = {}
    for case, out in zip(cases, go):
        f = parse_line(case)
        if f["op"] == "ed_keygen" and "pub" in out:
            pubs[f["seed"]] = out["pub"]
    verify = []
    for case, out in zip(cases, go):
        f = parse_line(case)
        if f["op"] != "ed_sign" or "sig" not in out:
            continue
        pub = bytes.fromhex(pubs[f["seed"]])
        sig = bytes.fromhex(out["sig"])
        msg = bytes.fromhex(f["msg"])
        for s, m, p in ((sig, msg, pub), (flip(rng, sig), msg, pub), (sig, msg + b"!", pub), (sig, msg, flip(rng, pub)),
                        (sig[:63], msg, pub), (rng.randbytes(64) if hasattr(rng, "randbytes") else sig, msg, pub)):
            verify.append(line(op="ed_verify", pub=p, msg=m, sig=s, mode=f["mode"], ctx=bytes.fromhex(f["ctx"])))
    h.same("ed25519 verify", verify)


def parse_line(text):
    return dict(token.split("=", 1) if "=" in token else (token, "") for token in text.split(" "))


def ecdh(h, rng):
    orders = {
        "p256": bytes.fromhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
        "p384": bytes.fromhex("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"),
        "p521": bytes.fromhex("01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409"),
    }
    sizes = {"p256": 32, "p384": 48, "p521": 66, "x25519": 32}
    for curve, size in sizes.items():
        privs = [blob(rng, size) for _ in range(80)]
        if curve in orders:
            privs += [bytes(size), orders[curve], b"\xff" * size, blob(rng, size - 1), blob(rng, size + 1)]
            privs = [p[:size] if len(p) > size and rng.random() < 0.3 else p for p in privs]
            if curve == "p521":
                privs = [bytes([p[0] & 1]) + p[1:] if len(p) == size else p for p in privs]
        else:
            privs += [blob(rng, 31), blob(rng, 33)]
        go, _ = h.same(f"ecdh {curve} pub", [line(op="ecdh_pub", curve=curve, priv=p) for p in privs])
        pubs = [bytes.fromhex(o["pub"]) for o in go if "pub" in o]
        cases = []
        for p in privs:
            for pub in rng.sample(pubs, min(3, len(pubs))):
                cases.append(line(op="ecdh", curve=curve, priv=p, peer=pub))
            if pubs:
                bad = flip(rng, rng.choice(pubs))
                cases.append(line(op="ecdh", curve=curve, priv=p, peer=bad))
                cases.append(line(op="ecdh", curve=curve, priv=p, peer=rng.choice(pubs)[:-1]))
        if curve == "x25519":
            cases.append(line(op="ecdh", curve=curve, priv=blob(rng, 32), peer=bytes(32)))
            cases.append(line(op="ecdh", curve=curve, priv=blob(rng, 32),
                              peer=bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")))
        h.same(f"ecdh {curve}", cases)


def ecdsa_and_elliptic(h, rng):
    hashes = ["sha1", "sha224", "sha256", "sha384", "sha512", "sha512_256", "sha3_256"]
    sizes = {"p224": 28, "p256": 32, "p384": 48, "p521": 66}
    orders = {
        "p224": 0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d,
        "p256": 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
        "p384": 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
        "p521": 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409,
    }
    for curve, size in sizes.items():
        n = orders[curve]
        ds = []
        for _ in range(12):
            d = rng.randrange(1, n)
            ds.append(d.to_bytes(size, "big"))
        edge = [(1).to_bytes(size, "big"), (n - 1).to_bytes(size, "big"), n.to_bytes(size, "big"),
                bytes(size), blob(rng, size - 1)]
        go, _ = h.same(f"ecdsa {curve} key import", [line(op="ec_pub", curve=curve, d=d) for d in ds + edge])
        keys = [(d, o) for d, o in zip(ds + edge, go) if "x" in o]
        det = []
        random_sign = []
        for d, o in keys:
            for _ in range(3):
                msg = blob(rng, rng.randrange(0, 100))
                for hash_name in rng.sample(hashes, 3):
                    dg = digest(hash_name, msg)
                    det.append(line(op="ec_det", curve=curve, d=d, hash=hash_name, digest=dg))
                random_sign.append(line(op="ec_sign", curve=curve, d=d, digest=digest("sha256", msg)))
        h.same(f"ecdsa {curve} rfc6979", det)
        # Cross verification: each side signs, both verify, plus mutations.
        for signer in ("go", "rs"):
            outs = h.go(random_sign) if signer == "go" else h.rs(random_sign)
            verify = []
            for case, o in zip(random_sign, outs):
                if "sig" not in o:
                    continue
                f = parse_line(case)
                dg = bytes.fromhex(f["digest"])
                sig = bytes.fromhex(o["sig"])
                for s, g in ((sig, dg), (flip(rng, sig), dg), (sig, flip(rng, dg)), (sig[:-1], dg), (sig + b"\0", dg)):
                    verify.append(line(op="ec_verify", curve=curve, x=o["x"], y=o["y"], digest=g, sig=s))
            go_v, rs_v = h.same(f"ecdsa {curve} verify ({signer} signed)", verify)
            valid = sum(1 for o in go_v if o.get("ok") == "1")
            if valid < len(random_sign) // 2:
                raise AssertionError(f"ecdsa {curve}: {signer} signatures did not verify ({valid})")
        # elliptic arithmetic.
        base = []
        for _ in range(30):
            k = blob(rng, rng.choice([1, 3, size - 1, size, size + 1, size + 8]))
            base.append(line(op="el_basemult", curve=curve, k=k))
        go, _ = h.same(f"elliptic {curve} base mult", base)
        points = [(o["x"], o["y"]) for o in go if "x" in o and o["x"] != "" and o["y"] != ""]
        cases = []
        for (x, y), (x2, y2) in zip(points, points[1:] + points[:1]):
            cases.append(line(op="el_double", curve=curve, x=x, y=y))
            cases.append(line(op="el_add", curve=curve, x=x, y=y, x2=x2, y2=y2))
            cases.append(line(op="el_add", curve=curve, x=x, y=y, x2=x, y2=y))
            cases.append(line(op="el_mult", curve=curve, x=x, y=y, k=blob(rng, rng.choice([1, size, size + 3]))))
            cases.append(line(op="el_add", curve=curve, x=x, y=y, x2=x2, y2="01"))
            cases.append(line(op="el_mult", curve=curve, x="01", y="01", k=b"\x02"))
        h.same(f"elliptic {curve} arithmetic", cases)
        enc = []
        for x, y in points:
            xb, yb = bytes.fromhex(x).rjust(size, b"\0"), bytes.fromhex(y).rjust(size, b"\0")
            full = b"\x04" + xb + yb
            comp = bytes([2 + (yb[-1] & 1)]) + xb
            enc += [line(op="el_unmarshal", curve=curve, data=full), line(op="el_unmarshal", curve=curve, data=flip(rng, full)),
                    line(op="el_unmarshalc", curve=curve, data=comp), line(op="el_unmarshalc", curve=curve, data=flip(rng, comp)),
                    line(op="el_unmarshal", curve=curve, data=comp), line(op="el_unmarshalc", curve=curve, data=full),
                    line(op="el_unmarshal", curve=curve, data=full[:-1])]
        h.same(f"elliptic {curve} marshal", enc)


def rsa(h, rng):
    keys = []
    for bits in (2048, 2048, 1024, 3072):
        keys.append(h.go([line(op="rsa_gen", bits=bits)])[0]["key"])
        keys.append(h.rs([line(op="rsa_gen", bits=bits)])[0]["key"])
    hashes = ["sha1", "sha256", "sha384", "sha512"]
    for key in keys:
        cases = []
        for hash_name in hashes:
            for _ in range(2):
                msg = blob(rng, 40)
                cases.append(line(op="rsa_p1_sign", key=key, hash=hash_name, digest=digest(hash_name, msg)))
        cases.append(line(op="rsa_p1_sign", key=key, hash="sha256", digest=blob(rng, 31)))
        go, _ = h.same("rsa pkcs1v15 sign", cases)
        verify = []
        for case, o in zip(cases, go):
            if "sig" not in o:
                continue
            f = parse_line(case)
            dg = bytes.fromhex(f["digest"])
            sig = bytes.fromhex(o["sig"])
            for s, g in ((sig, dg), (flip(rng, sig), dg), (sig, flip(rng, dg)), (sig[1:], dg)):
                verify.append(line(op="rsa_p1_verify", key=key, hash=f["hash"], digest=g, sig=s))
        h.same("rsa pkcs1v15 verify", verify)

        for signer in ("go", "rs"):
            cases = []
            for hash_name in ("sha256", "sha512"):
                for salt in (0, -1, 20):
                    cases.append(line(op="rsa_pss_sign", key=key, hash=hash_name, digest=digest(hash_name, blob(rng, 20)), salt=salt))
            outs = h.go(cases) if signer == "go" else h.rs(cases)
            verify = []
            for case, o in zip(cases, outs):
                if "sig" not in o:
                    continue
                f = parse_line(case)
                dg = bytes.fromhex(f["digest"])
                sig = bytes.fromhex(o["sig"])
                for salt in ("0", "-1", f["salt"]):
                    verify.append(line(op="rsa_pss_verify", key=key, hash=f["hash"], digest=dg, sig=sig, salt=salt))
                verify.append(line(op="rsa_pss_verify", key=key, hash=f["hash"], digest=dg, sig=flip(rng, sig), salt=0))
            go_v, _ = h.same(f"rsa pss verify ({signer} signed)", verify)
            if not any(o.get("ok") == "1" for o in go_v):
                raise AssertionError(f"rsa pss: no {signer} signature verified")

        for encryptor in ("go", "rs"):
            cases = []
            for hash_name, mgf in (("sha1", "sha1"), ("sha256", "sha256"), ("sha256", "sha1"), ("sha512", "sha512")):
                for label in (b"", b"label"):
                    cases.append(line(op="rsa_oaep_enc", key=key, hash=hash_name, mgf=mgf, label=label, msg=blob(rng, 20)))
            cases.append(line(op="rsa_p1_enc", key=key, msg=blob(rng, 20)))
            cases.append(line(op="rsa_oaep_enc", key=key, hash="sha256", mgf="sha256", label=b"", msg=blob(rng, 5000)))
            outs = h.go(cases) if encryptor == "go" else h.rs(cases)
            dec = []
            for case, o in zip(cases, outs):
                f = parse_line(case)
                if "ct" not in o:
                    continue
                ct = bytes.fromhex(o["ct"])
                if f["op"] == "rsa_p1_enc":
                    dec += [line(op="rsa_p1_dec", key=key, ct=ct), line(op="rsa_p1_dec", key=key, ct=flip(rng, ct))]
                else:
                    dec += [line(op="rsa_oaep_dec", key=key, hash=f["hash"], mgf=f["mgf"], label=bytes.fromhex(f["label"]), ct=ct),
                            line(op="rsa_oaep_dec", key=key, hash=f["hash"], mgf=f["mgf"], label=b"wrong", ct=ct),
                            line(op="rsa_oaep_dec", key=key, hash=f["hash"], mgf=f["mgf"], label=bytes.fromhex(f["label"]), ct=flip(rng, ct))]
            go_d, _ = h.same(f"rsa decrypt ({encryptor} encrypted)", dec)
            if not any("msg" in o for o in go_d):
                raise AssertionError("rsa: nothing decrypted")


def mlkem(h, rng):
    for param, ct_len in (("768", 1088), ("1024", 1568)):
        seeds = [blob(rng, 64) for _ in range(30)] + [blob(rng, 63)]
        go, _ = h.same(f"mlkem{param} keys", [line(op="mk_ek", param=param, seed=s) for s in seeds])
        enc_cases = []
        for s, o in zip(seeds, go):
            if "ek" in o:
                enc_cases.append(line(op="mk_enc", param=param, ek=o["ek"], m=blob(rng, 32)))
                enc_cases.append(line(op="mk_enc", param=param, ek=o["ek"], m=blob(rng, 31)))
        go_e, _ = h.same(f"mlkem{param} derandomized encaps", enc_cases)
        dec = []
        seed_by_ek = {o["ek"]: s for s, o in zip(seeds, go) if "ek" in o}
        for case, o in zip(enc_cases, go_e):
            if "c" not in o:
                continue
            f = parse_line(case)
            s = seed_by_ek[f["ek"]]
            c = bytes.fromhex(o["c"])
            dec += [line(op="mk_dec", param=param, seed=s, ct=c), line(op="mk_dec", param=param, seed=s, ct=flip(rng, c)),
                    line(op="mk_dec", param=param, seed=s, ct=c[:-1])]
        h.same(f"mlkem{param} decaps", dec)
        for encryptor in ("go", "rs"):
            cases = [line(op="mk_encr", param=param, ek=o["ek"]) for o in go if "ek" in o]
            outs = h.go(cases) if encryptor == "go" else h.rs(cases)
            dec = [line(op="mk_dec", param=param, seed=seed_by_ek[parse_line(c)["ek"]], ct=o["c"])
                   for c, o in zip(cases, outs)]
            go_d, rs_d = h.same(f"mlkem{param} decaps of {encryptor} ciphertexts", dec)
            for o, d in zip(outs, go_d):
                if o["k"] != d["k"]:
                    raise AssertionError(f"mlkem{param}: shared key mismatch for {encryptor} ciphertext")


def mldsa(h, rng):
    for param in ("44", "65", "87"):
        seeds = [blob(rng, 32) for _ in range(8)] + [blob(rng, 31)]
        go, _ = h.same(f"mldsa{param} keys", [line(op="md_pub", param=param, seed=s) for s in seeds])
        det = []
        for s in seeds[:8]:
            for ctx in (b"", text(rng, 10), text(rng, 255), text(rng, 256)):
                det.append(line(op="md_sign", param=param, seed=s, msg=blob(rng, rng.choice([0, 7, 300])), ctx=ctx))
        h.same(f"mldsa{param} deterministic sign", det)
        for signer in ("go", "rs"):
            cases = [line(op="md_sign_rand", param=param, seed=s, msg=blob(rng, 33), ctx=b"ctx") for s in seeds[:5]]
            outs = h.go(cases) if signer == "go" else h.rs(cases)
            ver = []
            for case, o in zip(cases, outs):
                f = parse_line(case)
                sig = bytes.fromhex(o["sig"])
                msg = bytes.fromhex(f["msg"])
                ver += [line(op="md_verify", param=param, pub=o["pub"], msg=msg, ctx=b"ctx", sig=sig),
                        line(op="md_verify", param=param, pub=o["pub"], msg=msg, ctx=b"x", sig=sig),
                        line(op="md_verify", param=param, pub=o["pub"], msg=msg + b"1", ctx=b"ctx", sig=sig),
                        line(op="md_verify", param=param, pub=o["pub"], msg=msg, ctx=b"ctx", sig=flip(rng, sig)),
                        line(op="md_verify", param=param, pub=o["pub"], msg=msg, ctx=b"ctx", sig=sig[:-1])]
            go_v, _ = h.same(f"mldsa{param} verify ({signer} signed)", ver)
            if sum(o.get("ok") == "1" for o in go_v) != len(cases):
                raise AssertionError(f"mldsa{param}: {signer} signatures did not all verify")


def dsa(h, rng):
    key = dict(
        p="A9B5B793FB4785793D246BAE77E8FF63CA52F442DA763C440259919FE1BC1D6065A9350637A04F75A2F039401D49F08E066C4D275A5A65DA5684BC563C14289D7AB8A67163BFBF79D85972619AD2CFF55AB0EE77A9002B0EF96293BDD0F42685EBB2C66C327079F6C98000FBCB79AACDE1BC6F9D5C7B1A97E3D9D54ED7951FEF".lower(),
        q="E1D3391245933D68A0714ED34BBCB7A1F422B9C1".lower(),
        g="634364FC25248933D01D1993ECABD0657CC0CB2CEED7ED2E3E8AECDFCDC4A25C3B15E9E3B163ACA2984B5539181F3EFF1A5E8903D71D5B95DA4F27202B77D2C44B430BB53741A8D59A8F86887525C9F2A6A5980A195EAA7F2FF910064301DEF89D3AA213E1FAC7768D89365318E370AF54A112EFBA9246D9158386BA1B4EEFDA".lower(),
        y="32969E5780CFE1C849A1C276D7AEB4F38A23B591739AA2FE197349AEEBD31366AEE5EB7E6C6DDB7C57D02432B30DB5AA66D9884299FAA72568944E4EEDC92EA3FBC6F39F53412FBCC563208F7C15B737AC8910DBC2D9C9B8C001E72FDC40EB694AB1F06A5A2DBD18D9E36C66F31F566742F11EC0A52E9F7B89355C02FB5D32D2".lower(),
        x="5078D4D29795CBE76D3AACFE48C9AF0BCDBEE91A".lower())
    for signer in ("go", "rs"):
        cases = [line(op="dsa_sign", digest=blob(rng, rng.choice([8, 20])), **key) for _ in range(20)]
        outs = h.go(cases) if signer == "go" else h.rs(cases)
        ver = []
        for case, o in zip(cases, outs):
            dg = bytes.fromhex(parse_line(case)["digest"])
            ver += [line(op="dsa_verify", digest=dg, r=o["r"], s=o["s"], **key),
                    line(op="dsa_verify", digest=flip(rng, dg), r=o["r"], s=o["s"], **key),
                    line(op="dsa_verify", digest=dg, r=o["s"], s=o["r"], **key)]
        go_v, _ = h.same(f"dsa verify ({signer} signed)", ver)
        if sum(o.get("ok") == "1" for o in go_v) < len(cases):
            raise AssertionError(f"dsa: {signer} signatures did not verify")


def hpke(h, rng):
    for kem in ("p256", "p384", "p521", "x25519"):
        for kdf in (1, 2, 3):
            for aead in (1, 2, 3, 65535):
                suite = dict(kem=kem, kdf=kdf, aead=aead)
                params = dict(info=blob(rng, 12), pt=blob(rng, 40), aad=blob(rng, 9), ectx=blob(rng, 5), elen=rng.choice([0, 16, 100]))
                # Each side seals to a key it generated, then both open.
                for sealer in ("go", "rs"):
                    case = line(op="hp_seal", **suite, **params)
                    out = (h.go if sealer == "go" else h.rs)([case])[0]
                    if "enc" not in out:
                        raise AssertionError(f"hpke seal failed: {out}")
                    opens = line(op="hp_open", **suite, sk=out["sk"], enc=out["enc"], ct=out.get("ct", ""),
                                 **params)
                    go_o, rs_o = h.same(f"hpke open ({sealer} sealed)", [opens])
                    if go_o[0].get("exp") != out["exp"] or go_o[0].get("pt", params["pt"].hex()) != params["pt"].hex():
                        raise AssertionError(f"hpke: {sealer} sealed {suite} opened differently: {go_o[0]} vs {out}")
                # Cross-sealing to the other's public key.
                gen = h.go([line(op="hp_seal", **suite, **params)])[0]
                case = line(op="hp_seal", pub=gen["pub"], **suite, **params)
                rs_sealed = h.rs([case])[0]
                opens = line(op="hp_open", **suite, sk=gen["sk"], enc=rs_sealed["enc"], ct=rs_sealed.get("ct", ""), **params)
                go_o, _ = h.same("hpke open (rust sealed to go key)", [opens])
                if go_o[0].get("exp") != rs_sealed["exp"]:
                    raise AssertionError("hpke: export mismatch")
                tampered = line(op="hp_open", **suite, sk=gen["sk"], enc=rs_sealed["enc"],
                                ct=flip(rng, bytes.fromhex(rs_sealed.get("ct", "00"))) if aead != 65535 else b"", **params)
                h.same("hpke tampered", [tampered])


def main():
    if not shutil.which("go") or not shutil.which("cargo"):
        raise RuntimeError("crypto asym differential check requires Go and Cargo on PATH")
    rng = random.Random(20261012)
    h = Harness()
    for step in (ed25519, ecdh, ecdsa_and_elliptic, mlkem, mldsa, dsa, hpke, rsa):
        step(h, rng)
        print(f"{step.__name__}: ok", flush=True)
    total = sum(COUNTS.values())
    print(f"crypto asym differential: {total} cases compared in {len(COUNTS)} groups")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, AssertionError, subprocess.SubprocessError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
