#!/usr/bin/env python3
"""Differentially check compress/flate, compress/gzip and compress/zlib against Go.

* Go-compressed streams at every level (plain, with preset dictionaries and with
  flush points) are decoded by Rust and must give the exact input.
* Rust-compressed streams at every level are decoded by Go and by Rust.
* Prefixes of flushed streams ending at each sync-flush point must decode to
  exactly the data written so far (then fail with `unexpected EOF`).
* Mutated and truncated streams must give identical bytes, error text, unread
  input count and gzip header in Rust and Go.
* Constructor and header error texts are compared.
* A compression-ratio report compares Rust and Go sizes on a mixed corpus; the
  default level must be within 10% of Go overall and on every large input.
"""
import os
import pathlib
import random
import subprocess
import tempfile
import time
import zlib as pyzlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
LEVELS = list(range(-2, 10))
FORMATS = ("flate", "zlib", "gzip")
RATIO_LIMIT = 1.10
# name|comment|extra|os|mtime, hex fields; extra is "-" (absent) or "+" plus hex.
HEADERS = [
    "-",
    f"{b'name.txt'.hex()}|{b'a comment'.hex()}|+0102|3|1234567890",
    f"{'é'.encode().hex()}||+|255|0",
    f"|{b'only comment'.hex()}|-|0|1",
    f"{b'n'.hex()}|{b'c'.hex()}|+{bytes(300).hex()}|7|4000000000",
    f"{b'n'.hex()}||-|9|-5",
]


def hx(data):
    return data.hex() if data else "-"


class Tool:
    def __init__(self, command):
        self.command = command

    def run(self, lines):
        payload = "".join(line + "\n" for line in lines)
        proc = subprocess.run(self.command, input=payload, text=True, capture_output=True, cwd=ROOT)
        if proc.returncode != 0:
            raise AssertionError(f"{self.command[0]} failed: {proc.stderr[-2000:]}")
        replies = proc.stdout.split("\n")
        if replies and replies[-1] == "":
            replies.pop()
        if len(replies) != len(lines):
            raise AssertionError(f"{self.command[0]}: {len(replies)} replies for {len(lines)} requests")
        return [r.split("\t") for r in replies]


def build_tools(tmp):
    oracle = pathlib.Path(tmp) / "flate_oracle"
    subprocess.run(["go", "build", "-o", str(oracle), str(ROOT / "tools/flate_oracle.go")], cwd=ROOT, check=True)
    subprocess.run(["cargo", "build", "--offline", "--locked", "--release", "--example", "flate_probe"], cwd=ROOT, check=True)
    probe = ROOT / "target/release/examples" / ("flate_probe.exe" if os.name == "nt" else "flate_probe")
    return Tool([str(probe)]), Tool([str(oracle)])


def goroot():
    return pathlib.Path(subprocess.run(["go", "env", "GOROOT"], capture_output=True, text=True, check=True).stdout.strip())


def corpus(rng):
    """Mixed corpus: natural text, source, structured text, binary, degenerate."""
    testdata = goroot() / "src/compress/testdata"
    items = {}
    for name in ("e.txt", "pi.txt", "gettysburg.txt"):
        items[name] = (testdata / name).read_bytes()
    items["Isaac.Newton-Opticks.txt"] = (goroot() / "src/testdata/Isaac.Newton-Opticks.txt").read_bytes()
    items["go-source"] = (goroot() / "src/net/http/server.go").read_bytes()[:300_000]
    items["json"] = (ROOT / "docs/api/go-surface.json").read_bytes()[:300_000]
    rows = []
    for i in range(6000):
        rows.append(b"%d,user%d@example.com,%s,%.3f\n" % (i, rng.randrange(900), rng.choice([b"ok", b"fail", b"pending"]), rng.random() * 1000))
    items["csv"] = b"".join(rows)
    items["random"] = bytes(rng.randrange(256) for _ in range(70_000))
    items["zeros"] = bytes(300_000)
    items["dna"] = bytes(rng.choice(b"ACGT") for _ in range(120_000))
    items["binary"] = b"".join(
        (i * 2654435761 & 0xFFFFFFFF).to_bytes(4, "little") + (i // 7).to_bytes(2, "little") + bytes([i % 251, 0, 0, i & 3])
        for i in range(25_000)
    )
    block = bytes(rng.randrange(256) for _ in range(20_000))
    items["far-repeat"] = block + bytes(rng.randrange(256) for _ in range(12_700)) + block + block[:5000] + bytes(30000) + block
    words = [b"alpha", b"beta", b"gamma", b"delta", b"epsilon", b"zeta", b"eta", b"theta"]
    items["words"] = b" ".join(rng.choice(words) for _ in range(40_000))
    items["runs"] = b"".join(bytes([rng.randrange(256)]) * rng.randrange(1, 600) for _ in range(500))
    items["mixed"] = items["gettysburg.txt"] + items["random"][:5000] + items["csv"][:30000] + bytes(2000) + items["binary"][:20000]
    return items


def mutate(rng, data):
    data = bytearray(data)
    kind = rng.randrange(6)
    if kind == 0 and data:
        for _ in range(rng.randrange(1, 4)):
            i = rng.randrange(len(data) * 8)
            data[i // 8] ^= 0x80 >> (i % 8)
    elif kind == 1 and data:
        data[rng.randrange(len(data))] = rng.randrange(256)
    elif kind == 2:
        del data[rng.randrange(len(data) + 1):]
    elif kind == 3:
        i = rng.randrange(len(data) + 1)
        data[i:i] = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 4)))
    elif kind == 4 and data:
        i = rng.randrange(len(data))
        del data[i:i + rng.randrange(1, 4)]
    elif data:
        i = rng.randrange(min(len(data), 40))
        data[i] ^= 1 << rng.randrange(8)
    return bytes(data)


class Report:
    def __init__(self):
        self.counts = {}

    def add(self, name, n=1):
        self.counts[name] = self.counts.get(name, 0) + n


def enc_line(fmt, level, data, dictionary="-", plan="-", hdr="-"):
    return f"enc {fmt} {level} {hx(data)} {dictionary} {plan} {hdr}"


def dec_line(fmt, stream, dictionary="-", multistream=True):
    return f"dec {fmt} {hx(stream)} {dictionary} {1 if multistream else 0}"


def check_equal(label, rust, go, vectors=None):
    if rust != go:
        raise AssertionError(f"{label}\nRust={rust!r}\nGo={go!r}")


def main():
    started = time.monotonic()
    rng = random.Random(0x1951_1952)
    report = Report()
    items = corpus(rng)
    names = sorted(items)
    sweep = {name: items[name][:24_000] for name in names}
    with tempfile.TemporaryDirectory() as tmp:
        rust, go = build_tools(tmp)

        # ---- Phase 1: level sweep, Go and Rust encoders, both decoders --------
        jobs = []  # (label, fmt, level, data, dict_field, plan)
        for name in names:
            data = sweep[name]
            for fmt in FORMATS:
                for level in LEVELS if fmt == "flate" else (-2, -1, 0, 2, 5, 9):
                    jobs.append((f"{name}/{fmt}/L{level}", fmt, level, data, "-", "-"))
        for name in ("Isaac.Newton-Opticks.txt", "far-repeat", "csv", "zeros", "runs"):
            for level in (1, 3, 4, 6, 9):
                jobs.append((f"{name}/flate/L{level}/full", "flate", level, items[name][:300_000], "-", "-"))
        # Preset dictionaries: the dictionary is part of the same text so matches reach into it.
        text = items["Isaac.Newton-Opticks.txt"]
        for dict_len in (1, 100, 5000, 32768, 40000):
            dictionary = text[1000:1000 + dict_len]
            data = text[1000 + dict_len - 3000:1000 + dict_len + 20000]
            for fmt in ("flate", "zlib"):
                for level in (-2, 0, 1, 4, 6, 9):
                    jobs.append((f"dict{dict_len}/{fmt}/L{level}", fmt, level, data, dictionary.hex(), "-"))
        for fmt in ("flate", "zlib"):
            for level in (0, 6):
                jobs.append((f"dict-empty/{fmt}/L{level}", fmt, level, text[:5000], "+", "-"))
        # Flush plans (sync flush after chunks, including empty ones).
        plans = ["1f;1f;1f", "0f;0f;100f", "5000f;1;32768f;1f", "70000f;70000f", "65535;65536f;1", "300;300;300"]
        for plan in plans:
            for fmt in FORMATS:
                for level in (-2, 0, 1, 6, 9):
                    jobs.append((f"plan[{plan}]/{fmt}/L{level}", fmt, level, text[:150_000], "-", plan))
        for fmt, level in (("flate", 6), ("zlib", 9)):
            jobs.append((f"dict+plan/{fmt}", fmt, level, text[500:60_000], text[:30_000].hex(), "10000f;1f;30000f"))
        # Random write/flush schedules over structured and random inputs: block
        # boundaries depend on the write sizes around each flush.
        for k in range(60):
            name = names[k % len(names)]
            parts = []
            for _ in range(rng.randrange(1, 8)):
                size = rng.choice([0, 1, 2, 3, 100, 4095, 32767, 32768, 65534, 65535, 65536, rng.randrange(1, 90_000)])
                parts.append(f"{size}{'f' if rng.random() < 0.5 else ''}")
            fmt = FORMATS[k % 3]
            level = rng.choice(LEVELS)
            jobs.append((f"randplan[{';'.join(parts)}]/{name}/{fmt}/L{level}", fmt, level, items[name][:rng.choice([50_000, 150_000, 400_000])], "-", ";".join(parts)))
        # Empty and tiny inputs.
        for fmt in FORMATS:
            for level in LEVELS:
                for data in (b"", b"a", b"ab", b"abc", b"aaaa", b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"):
                    jobs.append((f"tiny{len(data)}/{fmt}/L{level}", fmt, level, data, "-", "-"))

        lines = [enc_line(fmt, level, data, d, plan) for _, fmt, level, data, d, plan in jobs]
        go_enc = go.run(lines)
        rust_enc = rust.run(lines)
        # The encoder is a port of Go's: streams and flush offsets are identical.
        for (label, fmt, level, data, d, plan), g, r in zip(jobs, go_enc, rust_enc):
            if g[:3] != r[:3]:
                gs, rs = bytes.fromhex(g[1] if g[1] != "-" else ""), bytes.fromhex(r[1] if r[1] != "-" else "")
                at = next((i for i in range(min(len(gs), len(rs))) if gs[i] != rs[i]), min(len(gs), len(rs)))
                raise AssertionError(f"compressed bytes differ for {label}: go={len(gs)} rust={len(rs)} first difference at {at}; flush offsets go={g[2]} rust={r[2]}")
        report.add("byte-identical encodings", len(jobs))
        decode_cases = []  # (label, fmt, stream, dict, expected, flush_offsets, plan, data)
        for (label, fmt, level, data, d, plan), g, r in zip(jobs, go_enc, rust_enc):
            for who, reply in (("go", g), ("rust", r)):
                if reply[0] != "ok":
                    raise AssertionError(f"{who} enc failed for {label}: {reply}")
                stream = bytes.fromhex(reply[1] if reply[1] != "-" else "")
                offsets = [int(x) for x in reply[2].split(",") if x]
                decode_cases.append((f"{who}-enc {label}", fmt, stream, d, data, offsets, plan))
        dec_lines = [dec_line(fmt, stream, d) for _, fmt, stream, d, *_ in decode_cases]
        rust_dec = rust.run(dec_lines)
        go_dec = go.run(dec_lines)
        for case, r, g, line in zip(decode_cases, rust_dec, go_dec, dec_lines):
            label, fmt, stream, d, data, offsets, plan = case
            check_equal(f"decode {label}", r, g)
            if r[0] != "ok" or bytes.fromhex(r[1] if r[1] != "-" else "") != data or r[3] != "0":
                raise AssertionError(f"round trip {label}: {r[0]} {r[2]} rest={r[3]} len={len(r[1]) // 2} want={len(data)}")
        report.add("round-trip streams", len(decode_cases))

        # zlib's C inflater is a third, stricter opinion on Rust's output.
        wbits = {"flate": -15, "zlib": 15, "gzip": 31}
        for label, fmt, stream, d, data, offsets, plan in decode_cases:
            if label.startswith("rust-enc") and d != "+":
                kwargs = {"zdict": bytes.fromhex(d)} if d != "-" and fmt != "gzip" else {}
                try:
                    obj = pyzlib.decompressobj(wbits[fmt], **kwargs)
                    got = obj.decompress(stream) + obj.flush()
                except pyzlib.error as e:
                    raise AssertionError(f"python zlib rejects {label}: {e}")
                if got != data or not obj.eof:
                    raise AssertionError(f"python zlib output differs for {label}")
        report.add("python-zlib verified Rust streams", sum(1 for c in decode_cases if c[0].startswith("rust-enc") and c[3] != "+"))

        # Sync-flush points: the prefix up to each flush decodes to the data so far.
        prefix_cases = []
        for label, fmt, stream, d, data, offsets, plan in decode_cases:
            if not offsets:
                continue
            written = 0
            sizes = [int(p.rstrip("f")) for p in plan.split(";")]
            flush_after = [p.endswith("f") for p in plan.split(";")]
            remaining = len(data)
            expected = []
            for size, f in zip(sizes, flush_after):
                take = min(size, remaining)
                written += take
                remaining -= take
                if f:
                    expected.append(written)
            for off, want in zip(offsets, expected):
                prefix_cases.append((label, fmt, stream[:off], d, data[:want]))
        p_lines = [dec_line(fmt, prefix, d) for _, fmt, prefix, d, _ in prefix_cases]
        rust_p = rust.run(p_lines)
        go_p = go.run(p_lines)
        for case, r, g in zip(prefix_cases, rust_p, go_p):
            label, fmt, prefix, d, want = case
            check_equal(f"flush prefix {label}", r, g)
            got = bytes.fromhex(r[1] if r[1] != "-" else "")
            if got != want:
                raise AssertionError(f"flush prefix {label}: decoded {len(got)} bytes, want {len(want)} ({r[0]} {r[2]})")
        report.add("sync-flush prefixes", len(prefix_cases))

        # ---- Phase 2: mutated, truncated and hand-built streams ---------------
        seeds = []
        small = [b"", b"hello hello hello hello", items["gettysburg.txt"][:1500], bytes(range(256)) * 3,
                 items["csv"][:2500], items["dna"][:2000], items["zeros"][:600], items["random"][:700]]
        seed_jobs = []
        for data in small:
            for fmt in FORMATS:
                for level in (-2, 0, 1, 6, 9):
                    seed_jobs.append((fmt, level, data, "-"))
            for level in (1, 6):
                seed_jobs.append(("zlib", level, data, small[2][:300].hex()))
                seed_jobs.append(("flate", level, data, small[2][:300].hex()))
        seed_replies = go.run([enc_line(f, lv, d, dd) for f, lv, d, dd in seed_jobs])
        for (fmt, level, data, dd), reply in zip(seed_jobs, seed_replies):
            seeds.append((fmt, bytes.fromhex(reply[1] if reply[1] != "-" else ""), dd))
        # Headers with every optional field.
        for h in HEADERS:
            for lvl in (1, 6, 9):
                reply = go.run([enc_line("gzip", lvl, small[1], "-", "-", h)])[0]
                seeds.append(("gzip", bytes.fromhex(reply[1]), "-"))
        vectors = []
        for fmt, stream, dd in seeds:
            vectors.append((fmt, stream, dd, True))
            for cut in range(0, min(len(stream), 80)):
                vectors.append((fmt, stream[:cut], dd, True))
            for cut in range(80, len(stream), max(1, len(stream) // 40)):
                vectors.append((fmt, stream[:cut], dd, True))
            vectors.append((fmt, stream + b"trailing", dd, True))
            vectors.append((fmt, stream + b"trailing", dd, False))
            if fmt == "gzip":
                vectors.append((fmt, stream + stream, dd, True))
                vectors.append((fmt, stream + stream, dd, False))
                vectors.append((fmt, stream + stream[:5], dd, True))
                vectors.append((fmt, stream + b"\x1f\x8b\x08\x00" + bytes(6), dd, True))
        # Wrong dictionaries and absent dictionaries.
        for fmt, stream, dd in seeds:
            if dd != "-":
                vectors.append((fmt, stream, "-", True))
                vectors.append((fmt, stream, "+", True))
                vectors.append((fmt, stream, small[2][:299].hex(), True))
                vectors.append((fmt, stream, small[2][1:301].hex(), True))
        for _ in range(6000):
            fmt, stream, dd = rng.choice(seeds)
            vectors.append((fmt, mutate(rng, stream), dd, rng.random() < 0.8))
        # Raw random streams hit every block-type and table error path.
        for _ in range(1500):
            vectors.append(("flate", bytes(rng.randrange(256) for _ in range(rng.randrange(0, 40))), "-", True))
        for first in range(256):
            for tail in (b"", b"\x00", b"\xff\xff\xff\xff\xff\xff", bytes(range(1, 40))):
                vectors.append(("flate", bytes([first]) + tail, "-", True))
        # Header fuzz for gzip and zlib.
        for b0 in (0x1f, 0x00):
            for b1 in (0x8b, 0x8c):
                for method in (8, 7):
                    for flg in range(32):
                        vectors.append(("gzip", bytes([b0, b1, method, flg, 0, 0, 0, 0, 0, 255]) + b"\x03\x00" + bytes(8), "-", True))
        for cmf in range(0, 256, 1):
            for flg in (0x01, 0x5e, 0x9c, 0xda, 0x20, 0x3f):
                vectors.append(("zlib", bytes([cmf, flg]) + b"\x03\x00" + bytes(4), "-", True))
        vectors.append(("gzip", b"\x1f\x8b\x08\x08" + bytes(6) + b"x" * 600, "-", True))
        vectors.append(("gzip", b"\x1f\x8b\x08\x10" + bytes(6) + b"x" * 600, "-", True))
        vectors.append(("gzip", b"\x1f\x8b\x08\x04" + bytes(6) + b"\xff\xff" + b"y" * 100, "-", True))
        vectors.append(("gzip", b"\x1f\x8b\x08\x02" + bytes(6) + b"\x00\x00", "-", True))
        for fmt in FORMATS:
            vectors.append((fmt, b"", "-", True))
        m_lines = [dec_line(fmt, s, dd, ms) for fmt, s, dd, ms in vectors]
        rust_m = rust.run(m_lines)
        go_m = go.run(m_lines)
        accepted = 0
        texts = {}
        for (fmt, s, dd, ms), r, g in zip(vectors, rust_m, go_m):
            check_equal(f"mutation {fmt} ms={ms} dict={dd[:8]} stream={s[:64].hex()}", r, g)
            if r[0] == "ok":
                accepted += 1
            else:
                key = r[2].split(" before offset")[0]
                texts[key] = texts.get(key, 0) + 1
        report.add("mutated/truncated vectors", len(vectors))
        report.add("accepted by both", accepted)
        print("mutation error classes (identical in Rust and Go): " +
              ", ".join(f"{k!r}x{v}" for k, v in sorted(texts.items())))

        # ---- Phase 3: constructor and level errors ----------------------------
        err_lines = []
        for fmt in FORMATS:
            for level in (-3, 10, 100, -100):
                err_lines.append(enc_line(fmt, level, b"x"))
        e_rust = rust.run(err_lines)
        e_go = go.run(err_lines)
        for line, r, g in zip(err_lines, e_rust, e_go):
            check_equal(f"level error {line}", r, g)
            assert r[0] == "err", line
        report.add("level-error texts", len(err_lines))

        # ---- Phase 4: gzip header and zlib header/trailer bytes ---------------
        h_lines = []
        for h in HEADERS:
            for lvl in (-1, 1, 9):
                h_lines.append(enc_line("gzip", lvl, b"payload payload payload", "-", "-", h))
        for dd in ("-", "+", b"dictionary".hex()):
            for lvl in LEVELS:
                h_lines.append(enc_line("zlib", lvl, b"payload payload payload", dd))
        hg = go.run(h_lines)
        hr = rust.run(h_lines)
        for line, g, r in zip(h_lines, hg, hr):
            if g[0] != "ok" or r[0] != "ok":
                raise AssertionError(f"header encode {line}: go={g} rust={r}")
            gs, rs = bytes.fromhex(g[1]), bytes.fromhex(r[1])
            fields = line.split(" ")
            if fields[1] == "gzip":
                # Header bytes (everything before the DEFLATE data) and the trailer match exactly.
                name, comment, extra, _, _ = fields[6].split("|") if fields[6] != "-" else ("", "", "-", 0, 0)
                n = 10 + (2 + (len(extra) - 1) // 2 if extra != "-" else 0)
                for text in (name, comment):
                    if text:
                        n += len(bytes.fromhex(text).decode("utf-8").encode("latin-1")) + 1
                check_equal(f"gzip header {line[:70]}", rs[:n].hex(), gs[:n].hex())
                check_equal(f"gzip trailer {line[:70]}", rs[-8:].hex(), gs[-8:].hex())
            else:
                n = 2 if fields[4] == "-" else 6
                check_equal(f"zlib header {line[:70]}", rs[:n].hex(), gs[:n].hex())
                check_equal(f"zlib trailer {line[:70]}", rs[-4:].hex(), gs[-4:].hex())
        # Each implementation's streams must give the same header summary in both readers.
        rt_lines = [dec_line("gzip", bytes.fromhex(x[1])) for x, line in zip(hg, h_lines) if line.startswith("enc gzip")]
        rt_lines += [dec_line("gzip", bytes.fromhex(x[1])) for x, line in zip(hr, h_lines) if line.startswith("enc gzip")]
        for line, x, y in zip(rt_lines, rust.run(rt_lines), go.run(rt_lines)):
            check_equal("gzip header summary", x, y)
        report.add("gzip/zlib header streams", len(h_lines))

        # ---- Phase 5: compression ratio vs Go ---------------------------------
        requests = [(n, -1) for n in names]
        requests += [(n, level) for n in ("Isaac.Newton-Opticks.txt", "csv", "json", "go-source", "mixed") for level in (1, 5, 9)]
        r_lines = [enc_line("flate", level, items[n]) for n, level in requests]
        gr, rr = go.run(r_lines), rust.run(r_lines)
        print("\nflate compression ratio, Rust vs Go (bytes)")
        print(f"{'input':26} {'level':>5} {'raw':>9} {'go':>9} {'rust':>9} {'rust/go':>8}")
        total_go = total_rust = 0
        worst = 0.0
        for (n, level), g, r in zip(requests, gr, rr):
            gsz, rsz = len(g[1]) // 2, len(r[1]) // 2
            ratio = rsz / gsz
            print(f"{n:26} {level:>5} {len(items[n]):>9} {gsz:>9} {rsz:>9} {ratio:>8.3f}")
            if level == -1:
                total_go += gsz
                total_rust += rsz
                if len(items[n]) >= 20_000:
                    worst = max(worst, ratio)
                    if ratio > RATIO_LIMIT:
                        raise AssertionError(f"{n}: Rust output is {ratio:.3f}x Go's at the default level")
        overall = total_rust / total_go
        print(f"default level total: go={total_go} rust={total_rust} rust/go={overall:.4f} (worst large input {worst:.3f})")
        if overall > RATIO_LIMIT:
            raise AssertionError(f"default level total ratio {overall:.3f} exceeds {RATIO_LIMIT}")

    print("flate/gzip/zlib Go conformance: " + ", ".join(f"{v} {k}" for k, v in report.counts.items()) +
          f" passed in {time.monotonic() - started:.1f}s")


if __name__ == "__main__":
    main()
