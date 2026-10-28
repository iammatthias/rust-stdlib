#!/usr/bin/env python3
"""Differentially check Go time formatting, parsing, durations and Time methods.

tools/time_oracle.go and examples/time_probe.rs answer the same requests:
Format with every layout element across years -10000..10000 and assorted
zones, Parse/ParseInLocation of Go-formatted values and their mutations, Date
normalization, AddDate, Round/Truncate/Add/Sub/Compare, the binary/JSON/text
encodings and their decoders, ParseDuration and Duration methods.

Both processes run with TZ=UTC (Unix semantics: Local is a zone named "UTC"
that is not the UTC location) and ZONEINFO pointing at the checked-in
zoneinfo.zip. A second pass sets TZ to an extracted America/New_York file so
Local has real transitions.
"""
import io
import os
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
RNG = random.Random(0x71AE)
ZIP = ROOT / "src" / "time" / "tzdata" / "zoneinfo.zip"

CHUNKS = ["January", "Jan", "1", "01", "Monday", "Mon", "2", "_2", "02", "__2", "002", "15", "3", "03",
          "4", "04", "5", "05", "2006", "06", "_2006", "PM", "pm", "MST", "Z0700", "Z070000", "Z07",
          "Z07:00", "Z07:00:00", "-0700", "-070000", "-07", "-07:00", "-07:00:00", ".0", ".000", ".999",
          ",000", ",999999999", ".000000000", ".9", ".99999999999", "Janx", "Monx", "Jany"]
LITERALS = [" ", "-", ":", "/", "T", ",", ".", "  ", "x", "é", "'", "(", ")", "日"]
STD_LAYOUTS = ["01/02 03:04:05PM '06 -0700", "Mon Jan _2 15:04:05 2006", "Mon Jan _2 15:04:05 MST 2006",
               "Mon Jan 02 15:04:05 -0700 2006", "02 Jan 06 15:04 MST", "02 Jan 06 15:04 -0700",
               "Monday, 02-Jan-06 15:04:05 MST", "Mon, 02 Jan 2006 15:04:05 MST",
               "Mon, 02 Jan 2006 15:04:05 -0700", "2006-01-02T15:04:05Z07:00",
               "2006-01-02T15:04:05.999999999Z07:00", "3:04PM", "Jan _2 15:04:05", "Jan _2 15:04:05.000",
               "Jan _2 15:04:05.000000", "Jan _2 15:04:05.000000000", "2006-01-02 15:04:05", "2006-01-02",
               "15:04:05", "2006-002", "2006-__2", "Jan 2 2006 3:04:05.999 pm", "06-1-2 15.4.5,000",
               "2006-01-02 15:04:05.999999999 -0700 MST", "2006 Jan Monday 15:04 Z070000",
               "Monday, January 2, 2006 at 3:04pm (MST)", "2006-01-02T15:04:05.000000000Z07:00:00"]
ZONES = ["U", "L", "F0," + b"".hex(), "F3600," + b"CET".hex(), "F-25200," + b"".hex(),
         "F19800," + b"IST".hex(), "F-3661," + b"".hex(), "F45296," + b"WEIRD".hex(), "F86399," + b"".hex(),
         "F-86400," + b"MAX".hex(), "F5," + b"".hex(), "F-1," + b"".hex(), "F40000000," + b"".hex(),
         "ZAmerica/Los_Angeles", "ZAustralia/Lord_Howe", "ZAsia/Kolkata", "ZEurope/Dublin",
         "ZAmerica/Sao_Paulo", "ZPacific/Chatham", "ZAfrica/Monrovia", "ZEtc/GMT+12"]
PARSE_ZONES = ["U", "L", "F3600," + b"CET".hex(), "ZAmerica/Los_Angeles", "ZEurope/Dublin"]
# Go on Windows ignores TZ for Local and names it "Local"; Local cases rely on
# the Unix rules that the Rust port follows everywhere.
UNIX_LOCAL = os.name == "posix"
if not UNIX_LOCAL:
    ZONES.remove("L")
    PARSE_ZONES.remove("L")


def h(s):
    return s.encode().hex()


def instant():
    r = RNG.random()
    if r < 0.5:
        sec = RNG.randrange(-2_208_988_800, 4_102_444_800)  # 1900..2100
    elif r < 0.8:
        sec = RNG.randrange(-62_135_596_800 - 400 * 31_556_952, 253_402_300_800 + 400 * 31_556_952)
    elif r < 0.95:
        sec = RNG.randrange(-(1 << 40), 1 << 40)
    else:
        sec = RNG.choice([-(1 << 62), (1 << 62), -62_135_596_800, -62_135_596_801, 253_402_300_799,
                          253_402_300_800, 0, -1, 1 << 33, -(1 << 33)])
    nsec = RNG.choice([0, 0, 1, 999_999_999, 500_000_000, 123_456_789, 100, RNG.randrange(1_000_000_000)])
    return sec, nsec


def random_layout():
    parts = []
    for _ in range(RNG.randint(1, 7)):
        parts.append(RNG.choice(CHUNKS) if RNG.random() < 0.7 else RNG.choice(LITERALS))
    return "".join(parts)


def mutate(text):
    chars = list(text)
    for _ in range(RNG.randint(1, 2)):
        op = RNG.randrange(4)
        pos = RNG.randint(0, len(chars))
        alphabet = "0123456789 :-+.,TZJanMonPMamUTCGMTé"
        if op == 0 or not chars:
            chars.insert(pos, RNG.choice(alphabet))
        elif op == 1:
            del chars[min(pos, len(chars) - 1)]
        elif op == 2:
            chars[min(pos, len(chars) - 1)] = RNG.choice(alphabet)
        else:
            chars = chars[:pos]
    return "".join(chars)


PARSE_VECTORS = [
    ("2006-01-02T15:04:05Z07:00", "2010-02-04T21:00:57Z"), ("2006-01-02T15:04:05Z07:00", "2010-02-04T21:00:57-08:00"),
    ("2006-01-02T15:04:05Z07:00", "2010-02-04T21:00:57.123+08:00"), ("2006-01-02T15:04:05Z07:00", "2006-01-02T15:04:05+24:00"),
    ("2006-01-02T15:04:05Z07:00", "2006-01-02T15:04:05+23:60"), ("2006-01-02T15:04:05Z07:00", "2006-01-02T15:04:5Z"),
    ("2006-01-02T15:04:05Z07:00", "2006-01-02T15:04:05,1Z"), ("2006-01-02T15:04:05Z07:00", "2006-01-02T1:04:05Z"),
    ("2006-01-02T15:04:05Z07:00", "0000-01-01T00:00:00Z"), ("2006-01-02T15:04:05Z07:00", "2000-02-30T00:00:00Z"),
    ("Mon Jan _2 15:04:05 2006", "Thu Feb  4 21:00:57 2010"), ("Mon Jan _2 15:04:05 MST 2006", "Thu Feb  4 21:00:57 PST 2010"),
    ("Mon Jan _2 15:04:05 MST 2006", "Thu Feb  4 21:00:57 GMT+5 2010"), ("Mon Jan _2 15:04:05 MST 2006", "Thu Feb  4 21:00:57 GMT-23 2010"),
    ("Mon Jan _2 15:04:05 MST 2006", "Thu Feb  4 21:00:57 GMT+24 2010"), ("Mon Jan _2 15:04:05 MST 2006", "Thu Feb  4 21:00:57 ChST 2010"),
    ("Mon Jan _2 15:04:05 MST 2006", "Thu Feb  4 21:00:57 WITA 2010"), ("Mon Jan _2 15:04:05 MST 2006", "Thu Feb  4 21:00:57 AEDT 2010"),
    ("Mon Jan _2 15:04:05 MST 2006", "Thu Feb  4 21:00:57 +07 2010"), ("Mon Jan _2 15:04:05 MST 2006", "Thu Feb  4 21:00:57 -1130 2010"),
    ("Mon Jan _2 15:04:05 MST 2006", "Thu Feb  4 21:00:57 ABCDEF 2010"), ("Mon Jan _2 15:04:05 MST 2006", "Thu Feb  4 21:00:57 PSTX 2010"),
    ("Mon Jan 02 15:04:05 -0700 2006", "Thu Feb 04 21:00:57 -0800 2010"), ("Mon Jan 02 15:04:05 -0700 2006", "Thu Feb 04 21:00:57 +2500 2010"),
    ("Monday, 02-Jan-06 15:04:05 MST", "Thursday, 04-Feb-10 21:00:57 PST"), ("Monday, 02-Jan-06 15:04:05 MST", "thursday, 04-feb-10 21:00:57 pst"),
    ("Mon, 02 Jan 2006 15:04:05 MST", "Thu, 04 Feb 2010 21:00:57 PST"), ("Mon, 02 Jan 2006 15:04:05 MST", "Thu, 04 Feb 2010 21:00:57 PDT"),
    ("Jan _2 15:04:05", "Feb  4 21:00:57"), ("Jan _2 15:04:05.000", "Feb  4 21:00:57.012"), ("Jan _2 15:04:05", "Feb  4 21:00:57.012345678"),
    ("Jan _2 15:04:05.999", "Feb  4 21:00:57.0123"), ("Jan _2 15:04:05.999999999", "Feb  4 21:00:57.012345678901"),
    ("2006-01-02 15:04:05.9999999999", "2010-02-04 21:00:57.0123456789"), ("2006-002 15:04:05", "2010-035 21:00:57"),
    ("2006-__2 15:04:05", "2010- 35 21:00:57"), ("2006-__2 15:04:05", "2010-  5 21:00:57"), ("2006-002", "2012-060"),
    ("2006-002", "2011-060"), ("2006-002", "2012-366"), ("2006-002", "2011-366"), ("2006-01-002", "2012-03-060"),
    ("2006-01-002", "2012-02-060"), ("2006-01-02-002", "2012-03-01-061"), ("3:04PM", "12:00AM"), ("3:04PM", "12:00PM"),
    ("3:04PM", "13:00PM"), ("3:04pm", "1:00am"), ("15:04", "24:00"), ("15:04", "23:60"), ("15:04:05", "23:59:60"),
    ("06", "-6"), ("06", "69"), ("06", "68"), ("2006", "-006"), ("2006", "+006"), ("Jan", "jan"), ("Jan", "JANUARY"),
    ("January", "Janu"), ("2006 01 02", "2006  01   02"), ("2006 01 02", "2006 01 02 "), ("2006-01-02", "2006-01-02x"),
    ("2006-01-02T15:04:05.000Z07:00", "2006-01-02T15:04:05.-12Z"), ("15:04:05.00", "11:22:33.1"),
    ("2006-01-02T15:04:05Z0700", "2006-01-02T15:04:05Z"), ("2006-01-02T15:04:05Z07", "2006-01-02T15:04:05+0"),
    ("2006-01-02T15:04:05 Z07:00:00", "2006-01-02T15:04:05 -07:30:15"), ("2006-01-02T15:04:05 -070000", "2006-01-02T15:04:05 +012345"),
    ("2006-01-02 15:04:05 -07:00", "2006-01-02 15:04:05 -07:61"), ("2006-01-02 15:04:05 -07:00", "2006-01-02 15:04:05 x07:00"),
    ("Mon", "Tue"), ("Monday", "Tues"), ("_2", " 1"), ("_2", "1"), ("__2", "  1"), ("002", "1"), ("2006 MST", "2006 UTC"),
    ("2006 MST", "2006 GMT"), ("2006 MST", "2006 MST"), ("2006 MST", "2006 PST"), ("2006 MST", "2006 LMT"),
    ("Jan 2 2006 MST", "Jul 4 2011 PDT"), ("Jan 2 2006 MST", "Jan 4 2011 PDT"), ("Jan 2 2006 MST", "Jun 4 2008 IST"),
    ("Jan 2 2006 MST", "Nov 6 2011 BST"), ("Jan 2 2006 MST", "Nov 6 1971 IST"), ("Jan 2 2006 -0700 MST", "Jul 4 2011 -0700 PDT"),
    ("Jan 2 2006 -0700 MST", "Jul 4 2011 -0800 PDT"), ("", ""), ("", "x"), ("x", ""), ("2006é", "2010é"), ("é2006", "é20x0"),
]


def corpus():
    reqs = []
    layouts = STD_LAYOUTS + [random_layout() for _ in range(500)]
    for _ in range(4000):
        sec, nsec = instant()
        reqs.append(("F", str(sec), str(nsec), RNG.choice(ZONES), h(RNG.choice(layouts))))
    for _ in range(1500):
        sec, nsec = instant()
        reqs.append(("S", str(sec), str(nsec), RNG.choice(ZONES)))
    for _ in range(1500):
        y = RNG.choice([RNG.randrange(1800, 2400), RNG.randrange(-5000, 15000), RNG.randrange(-(1 << 40), 1 << 40)])
        fields = [y, RNG.randrange(-30, 30), RNG.randrange(-400, 400), RNG.randrange(-50, 50),
                  RNG.randrange(-100, 100), RNG.randrange(-100, 100), RNG.randrange(-3_000_000_000, 3_000_000_000)]
        if RNG.random() < 0.6:
            fields = [RNG.randrange(1800, 2400), RNG.randrange(1, 13), RNG.randrange(1, 29), RNG.randrange(24),
                      RNG.randrange(60), RNG.randrange(60), 0]
        reqs.append(("D", *map(str, fields), RNG.choice(ZONES)))
    for _ in range(800):
        sec, nsec = instant()
        reqs.append(("A", str(sec), str(nsec), RNG.choice(ZONES), str(RNG.randrange(-500, 500)),
                     str(RNG.randrange(-30, 30)), str(RNG.randrange(-400, 400))))
    durations = [0, 1, -1, 7, 1000, 999_999_999, 10**9, 60 * 10**9, 3600 * 10**9, 86400 * 10**9,
                 7 * 86400 * 10**9, 3 * 10**8, (1 << 63) - 1, -(1 << 63), 123_456_789_012, 10**9 + 1]
    for _ in range(2000):
        sec, nsec = instant()
        u = instant()
        d = RNG.choice(durations) if RNG.random() < 0.6 else RNG.randrange(-(1 << 63), 1 << 63)
        reqs.append(("R", str(sec), str(nsec), RNG.choice(ZONES), str(d), str(u[0]), str(u[1])))
    for _ in range(1500):
        d = RNG.choice(durations) if RNG.random() < 0.3 else RNG.choice(
            [RNG.randrange(-(1 << 63), 1 << 63), RNG.randrange(-10**12, 10**12)])
        m = RNG.choice(durations + [RNG.randrange(-10**13, 10**13)])
        reqs.append(("M", str(d), str(m)))
    units = ["ns", "us", "µs", "μs", "ms", "s", "m", "h", "", "x", "d", "S", "µ"]
    for _ in range(1500):
        s = RNG.choice(["", "-", "+"]) + "".join(
            RNG.choice([str(RNG.randrange(10**RNG.randint(0, 20))), "." + str(RNG.randrange(10**9)), "1.", "0"])
            + RNG.choice(units) for _ in range(RNG.randint(1, 3)))
        if RNG.random() < 0.2:
            s = mutate(s)
        reqs.append(("N", h(s)))
    for s in ["", "0", "-0", "+0", "1", ".", ".s", "1.s", "9223372036854775807ns", "9223372036854775808ns",
              "-9223372036854775808ns", "9223372036854775808ns9223372036854775808ns", "2562047h47m16.854775808s",
              "0.000000000000000000001s", "1" + "0" * 30 + "ns", "1µ", "1ms1", "1h-1m"]:
        reqs.append(("N", h(s)))
    for m in range(-3, 16):
        reqs.append(("O", str(m), str(m - 2)))
    reqs.append(("O", str(-(1 << 63)), str((1 << 63) - 1)))
    for layout, value in PARSE_VECTORS:
        reqs.append(("P", h(layout), h(value)))
        for z in PARSE_ZONES:
            reqs.append(("I", h(layout), h(value), z))
    return reqs


def tzif_requests():
    """LoadLocationFromTZData on real zone files, their version-byte variants
    (Go accepts only versions 1 to 3), truncations and byte flips."""
    zf = zipfile.ZipFile(ZIP)
    secs = ",".join(str(x) for x in [-(1 << 40), -2_000_000_000, 0, 1_000_000_000, 1_700_000_000,
                                     2_500_000_000, 4_000_000_000, 1 << 35])
    reqs = []
    for name in ["America/New_York", "Europe/Dublin", "Asia/Kolkata", "Australia/Lord_Howe", "UTC",
                 "Etc/GMT+12", "Pacific/Chatham", "Africa/Monrovia"]:
        data = zf.read(name)
        reqs.append(("T", data.hex(), secs))
        for version in (0, ord("1"), ord("2"), ord("3"), ord("4"), ord("5"), ord("x")):
            reqs.append(("T", (data[:4] + bytes([version]) + data[5:]).hex(), secs))
        for _ in range(12):
            cut = RNG.randrange(len(data))
            reqs.append(("T", data[:cut].hex(), secs))
        for _ in range(30):
            mutated = bytearray(data)
            for _ in range(RNG.randint(1, 3)):
                mutated[RNG.randrange(len(mutated))] = RNG.randrange(256)
            reqs.append(("T", bytes(mutated).hex(), secs))
    return reqs


def run(command, payload, env):
    result = subprocess.run(command, input=payload, text=True, capture_output=True, cwd=ROOT, env=env, timeout=200)
    if result.returncode:
        raise RuntimeError(f"{' '.join(command)} failed:\n{result.stderr[-4000:]}")
    return result.stdout.splitlines()


def compare(reqs, env, label):
    payload = "".join("\t".join(r) + "\n" for r in reqs)
    go = run(["go", "run", "tools/time_oracle.go"], payload, env)
    rust = run(["cargo", "run", "--quiet", "--offline", "--locked", "--example", "time_probe"], payload, env)
    if len(go) != len(reqs) or len(rust) != len(reqs):
        raise AssertionError(f"{label}: oracle returned the wrong number of records")
    # "skip": a zone abbreviation that is not UTF-8 (Rust decodes it lossily).
    failures = [(r, g, x) for r, g, x in zip(reqs, go, rust) if g != x and g != "skip"]
    for r, g, x in failures[:10]:
        print(f"{label} {r[0]} {r[1:]}\n  Go  ={g[:300]}\n  Rust={x[:300]}")
    return go, failures


def main():
    if not shutil.which("go") or not shutil.which("cargo"):
        raise RuntimeError("time differential check requires Go and Cargo on PATH")
    env = os.environ.copy()
    env.update({"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off", "TZ": "UTC", "ZONEINFO": str(ZIP)})
    reqs = corpus()
    go, failures = compare(reqs, env, "pass1")
    # Parse Go-formatted values (and mutations) back with the same layout.
    parse_reqs = []
    for r, out in zip(reqs, go):
        if r[0] != "F":
            continue
        layout = bytes.fromhex(r[4]).decode()
        value = bytes.fromhex(out).decode("utf-8", "replace")
        for v in [value] + ([mutate(value)] if RNG.random() < 0.6 else []):
            if RNG.random() < 0.5:
                parse_reqs.append(("P", h(layout), h(v)))
            else:
                parse_reqs.append(("I", h(layout), h(v), RNG.choice(PARSE_ZONES)))
    for kind in ("json", "text"):
        for r, out in zip(reqs, go):
            if r[0] == "S" and RNG.random() < 0.5:
                fields = out.split("\t")
                data = bytes.fromhex(fields[6 if kind == "json" else 7].split(",")[0])
                if RNG.random() < 0.3:
                    data = mutate(data.decode("utf-8", "replace")).encode()
                parse_reqs.append(("U", kind, data.hex()))
    for r, out in zip(reqs, go):
        if r[0] == "S" and RNG.random() < 0.3:
            data = bytearray(bytes.fromhex(out.split("\t")[5].split(",")[0]))
            if data and RNG.random() < 0.4:
                data[RNG.randrange(len(data))] = RNG.randrange(256)
            if RNG.random() < 0.1:
                data = data[:RNG.randrange(len(data) + 1)]
            parse_reqs.append(("U", "binary", bytes(data).hex()))
    for data in [b"null", b"", b'"', b'""', b"2006", b'"2006-01-02T15:04:05Z"', b'"2006-01-02T15:04:05.1+23:59"',
                 b'"2006-01-02T15:04:05+24:00"', b'"10000-01-01T00:00:00Z"', b'"2006-01-02T15:04:05,1Z"']:
        parse_reqs += [("U", "json", data.hex()), ("U", "text", data.hex())]
    for data in [b"", b"\x01", b"\x03" + bytes(14), b"\x01" + bytes(13), b"\x02" + bytes(15), b"\x01" + bytes(12) + b"\xff\xff"]:
        parse_reqs.append(("U", "binary", data.hex()))
    parse_reqs += tzif_requests()
    _, more = compare(parse_reqs, env, "pass2")
    failures += more
    # Local with real transitions: TZ names an extracted zone file.
    local_reqs = []
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "New_York"
        path.write_bytes(zipfile.ZipFile(ZIP).read("America/New_York"))
        env2 = dict(env, TZ=str(path))
        if UNIX_LOCAL:
            local_reqs = [r for r in reqs + parse_reqs if "L" in r[1:] or r[0] in ("P", "U")]
            _, more = compare(local_reqs, env2, "pass3")
            failures += more
    total = len(reqs) + len(parse_reqs) + len(local_reqs)
    if failures:
        raise AssertionError(f"{len(failures)} of {total} time requests differ from Go")
    counts = {}
    for r in reqs + parse_reqs:
        counts[r[0]] = counts.get(r[0], 0) + 1
    detail = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    print(f"time Go differential: {total} requests passed ({detail}; {len(local_reqs)} rerun with a New_York Local)")


if __name__ == "__main__":
    main()
