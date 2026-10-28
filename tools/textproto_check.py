#!/usr/bin/env python3
"""Differentially check net/textproto framing against Go with generated and mutated inputs."""
import os
from pathlib import Path
import random
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
RNG = random.Random(0x7E47)

KEY_BYTES = (b"abcxyzABCXYZ019-_.!#$%&'*+^`|~" * 3) + b" :\t\x00\x7f\"(),/;<=>?@[\\]{}" + "é".encode()
KEYS = [b"content-type", b"CONTENT-TYPE", b"Content-type", b"x-forwarded-for", b"a", b"A-", b"-a",
        b"--x", b"foo bar", b"foo ", b" foo", b"", b"Foo:Bar", b"user_agent", b"X-\xc3\xa9",
        b"ab\x00c", b"Message-ID", b"mime-version", b"x" * 40, b"1-2-3", b"a.b-c.d"]
GOOD_VALUES = [b"text/plain", b"", b" leading", b"trailing ", b"tab\there", "caf\u00e9".encode(),
               b"a:b:c", b"  \t  ", b"x" * 60, b"multi word value", b"<id@host>"]
BAD_VALUES = [b"ctl\x01x", b"del\x7fx", b"obs\xe9text", b"bare\rcr", b"nul\x00"]
EOLS = [b"\r\n", b"\r\n", b"\n", b"\r"]
INTERESTING = [b"\r", b"\n", b"\r\n", b" ", b"\t", b":", b".", b"\x00", b"\x7f", b"\xff", "é".encode(), b"a", b"-"]


def mutate(data, count=None):
    data = bytearray(data)
    for _ in range(count or RNG.randint(1, 3)):
        op = RNG.randrange(3)
        pos = RNG.randint(0, len(data))
        if op == 0 or not data:
            data[pos:pos] = RNG.choice(INTERESTING)
        elif op == 1:
            del data[min(pos, len(data) - 1)]
        else:
            data[min(pos, len(data) - 1)] = RNG.choice(INTERESTING)[0]
    return bytes(data)


def random_key():
    if RNG.random() < 0.5:
        return RNG.choice(KEYS)
    return bytes(RNG.choice(KEY_BYTES) for _ in range(RNG.randint(0, 12)))


def value():
    return RNG.choice(GOOD_VALUES) if RNG.random() < 0.93 else RNG.choice(BAD_VALUES)


def header_block():
    out = bytearray()
    if RNG.random() < 0.05:
        out += b" leading: space\r\n"
    for _ in range(RNG.randint(0, 6)):
        key = RNG.choice(KEYS[:10]) if RNG.random() < 0.9 else random_key()
        sep = RNG.choice([b": ", b":", b":  ", b": \t"]) if RNG.random() < 0.97 else b" "
        out += key + sep + value() + RNG.choice(EOLS[:3] if RNG.random() < 0.95 else EOLS)
        for _ in range(RNG.choice([0, 0, 0, 1, 2])):
            out += RNG.choice([b" ", b"\t", b"   ", b" \t"]) + RNG.choice([value(), b""]) + RNG.choice(EOLS[:3])
    if RNG.random() < 0.92:
        out += RNG.choice([b"\r\n", b"\n"])
    if RNG.random() < 0.3:
        out += b"body bytes\r\n"
    return bytes(out)


def dot_body():
    lines = [RNG.choice([b"", b".", b"..", b"...x", b".a", b"a.", b"text", b"\r", b"x\ry", b" .", b"caf\xc3\xa9", b"\xff"])
             for _ in range(RNG.randint(0, 6))]
    out = b"".join(line + RNG.choice(EOLS) for line in lines)
    out += RNG.choice([b".\r\n", b".\r\n", b".\n", b".", b"", b"..\r\n", b".\r", b".\rx\r\n.\r\n", b".x\r\n.\r\n"])
    if RNG.random() < 0.5:
        out += b"after\r\nmore\n"
    return out


def response():
    code = RNG.choice([b"250", b"250", b"220", b"550", b"354"]) if RNG.random() < 0.85 else \
        RNG.choice([b"099", b"25x", b"+25", b"2500", b"25"])
    lines = []
    for i in range(RNG.randint(0, 3)):
        lead = RNG.choice([code + b"-", code + b"-", code + b"-", b"251-", b"", b"  ", b"250 "])
        lines.append(lead + RNG.choice([b"hello", b"", b"x y", b"\xff" if RNG.random() < 0.2 else b"8BITMIME", b"done\r"]))
    end = RNG.choice([b" ", b" ", b" ", b"-", b"", b"x"]) if RNG.random() < 0.3 else b" "
    lines.append(code + end + RNG.choice([b"ok", b"", b"final"]))
    if lines[1:] and RNG.random() < 0.5:
        lines[0] = code + b"-first"
    payload = b"".join(line + RNG.choice(EOLS[:3]) for line in lines)
    if RNG.random() < 0.15:
        payload = payload[: RNG.randint(0, len(payload))]
    return payload


RS = b"\x1e"
COMMANDS = [b"NOOP", b"HELP", b"EHLO example.com", b"DATA", b"A %s %d", b"caf\xc3\xa9", b"", b"x" * 200]


def utf8_safe(data):
    """Transcripts compare error text, so keep text valid UTF-8 (Rust rejects the rest)."""
    return data if valid_utf8(data) else data.replace(b"\xff", b"?").decode("utf-8", "replace").encode()


def transcript():
    """A scripted loopback exchange. The fake server writes every G/S blob up
    front and half-closes, so no client read can block; the client's own
    writes are compared through what the server received. C sends a command,
    T/E bracket a pipelined response, and R/Q/l/D/B/H read a response, code
    line, line, dot lines, dot bytes or header."""
    ops = []
    code = str(RNG.choice([220, 250, 354, 550, 421]))

    def expect():
        return RNG.choice([0, 2, 25, 250, 220, 5, 55, 550, 1000]) if RNG.random() < 0.8 else RNG.choice([-1, 3, 4])

    def reads(kind):
        n = RNG.randint(1, 2)
        if kind == "resp":
            return [("R" + str(expect())).encode() for _ in range(n)]
        if kind == "code":
            return [("Q" + str(expect())).encode() for _ in range(n)]
        return [RNG.choice([b"l", b"D", b"B", b"H", b"R0", b"Q0"]) for _ in range(n)]

    def server_blob(kind):
        if kind in ("resp", "code"):
            return utf8_safe(response())
        if kind == "help":
            return b"110 help\r\n" + utf8_safe(dot_body()) + RNG.choice([b"250 done\r\n", b"250-x\r\n250 y\r\n", b""])
        return utf8_safe(RNG.choice([header_block(), dot_body(), b"just a line\r\n", b"bare\rcr line\n", b"", b"\n"]))

    def maybe_mutate(blob):
        if RNG.random() < 0.25:
            mutated = mutate(blob)
            if valid_utf8(mutated):
                return mutated
        return blob

    if RNG.random() < 0.6:
        kind = RNG.choice(["resp", "resp", "code", "other"])
        ops.append(b"G" + maybe_mutate(server_blob(kind)))
        ops += reads(kind)
    # StartResponse(id) waits for every earlier response, so a script either
    # brackets all its responses or none.
    pipelined = RNG.random() < 0.6
    for _ in range(RNG.randint(1, 3)):
        kind = RNG.choice(["resp", "resp", "code", "help", "other"])
        ops.append(b"C" + RNG.choice(COMMANDS))
        if RNG.random() < 0.9:
            ops.append(b"S" + maybe_mutate(server_blob(kind)))
        if pipelined:
            ops.append(b"T")
        if kind == "help":
            ops += [b"Q" + RNG.choice([b"110", b"1", b"0"]), b"D", b"Q" + RNG.choice([b"250", b"2", b"550"])]
        else:
            ops += reads(kind)
        if pipelined:
            ops.append(b"E")
    return RS.join(ops)


def corpus():
    records = []
    keys = set(KEYS)
    while len(keys) < 1400:
        keys.add(random_key())
    keys = [k for k in keys if valid_utf8(k)]
    records += [("K", k) for k in sorted(keys)]
    records += [("T", RNG.choice([b"", b" ", b"\t\r\n x \n", b"a b", b" \x0b x\x0c "]) + RNG.choice([b"", b" ", b"\r\n"]))
                for _ in range(100)]
    seeds = [
        b"A: b\r\n  \r\nC: d\r\n\r\n", b"A: b\r\nfoo\r\n\r\n", b"Foo: bar\r\n baz\r\n\r\n",
        b"k1: v1\r\nk2: v2\r\n", b"Foo Bar: x\r\n\r\n", b": empty\r\n\r\n", b" first: x\r\n\r\n",
        b"\tfirst: x\r\n\r\n", b"a: 1\na: 2\n\n", b"X-Obs: \xe9\r\n\r\n", b"Bad\x01Key: v\r\n\r\n",
        b"K: v\r\n\t \r\n\r\n", b"K: v\r\n \r\n \r\n\r\n", b"K: v", b"", b"\r\n", b"\n",
        b"K: v\rmore\r\n\r\n", b"K:\r\n\r\n", b"K: a\r\n  b\r\n\tc\r\n\r\n",
    ]
    blocks = seeds + [header_block() for _ in range(1500)]
    blocks += [mutate(RNG.choice(blocks)) for _ in range(600)]
    records += [("H", b) for b in blocks]
    for _ in range(300):
        block = header_block()
        memory = RNG.randint(380, 400 + 3 * len(block) + 600)
        records.append((f"HL{memory},{RNG.randint(0, 8)}", block))
    records += [("C", mutate(header_block(), RNG.randint(0, 2))) for _ in range(300)]
    bodies = [dot_body() for _ in range(900)] + [b".\r\n", b"..\r\n.\r\n", b"a\n\n.\r\n", b"a\r\n.\n", b".\r.\r\n"]
    bodies += [mutate(RNG.choice(bodies)) for _ in range(300)]
    for body in bodies:
        records.append((RNG.choice("DDL"), body))
    records += [("S", dot_body()) for _ in range(150)]
    for _ in range(500):
        mode = RNG.choice("RRQ") + str(RNG.choice([0, 0, 0, 2, 25, 250, 220, 5, 55, 550, 1000, -1]))
        records.append((mode, response()))
    records += [("X", transcript()) for _ in range(250)]
    records += [("W", dot_body() + mutate(b"x.\n.y\r\n\r", 1)) for _ in range(300)]
    return records


def valid_utf8(data):
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def run(command, payload, env):
    result = subprocess.run(command, input=payload, text=True, capture_output=True,
                            cwd=ROOT, env=env, timeout=200)
    if result.returncode:
        raise RuntimeError(f"{' '.join(command)} failed:\n{result.stderr}")
    return result.stdout.splitlines()


def main():
    if not shutil.which("go") or not shutil.which("cargo"):
        raise RuntimeError("textproto differential check requires Go and Cargo on PATH")
    records = corpus()
    payload = "".join(f"{mode}:{data.hex()}\n" for mode, data in records)
    env = os.environ.copy()
    env.update({"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off"})
    go = run(["go", "run", "tools/textproto_oracle.go"], payload, env)
    rust = run(["cargo", "run", "--quiet", "--offline", "--locked", "--example", "textproto_probe"],
               payload, env)
    if len(go) != len(records) or len(rust) != len(records):
        raise AssertionError("textproto oracle returned the wrong number of records")
    failures = [(mode, data, g, r) for (mode, data), g, r in zip(records, go, rust) if g != r]
    for mode, data, g, r in failures[:10]:
        print(f"mode={mode} input={data!r}\n  Go  ={g!r}\n  Rust={r!r}")
    if failures:
        raise AssertionError(f"{len(failures)} of {len(records)} textproto vectors differ from Go")
    counts = {}
    for mode, _ in records:
        counts[mode[0]] = counts.get(mode[0], 0) + 1
    detail = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    print(f"textproto Go differential: {len(records)} vectors passed ({detail})")


if __name__ == "__main__":
    main()
