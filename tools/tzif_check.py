#!/usr/bin/env python3
"""Differentially check TZif parsing, zone lookup and POSIX TZ footers against Go.

Every zone in Go's lib/time/zoneinfo.zip is loaded from the same bytes by
tools/tzif_oracle.go and examples/tzif_probe.rs. Offsets, abbreviations, DST
flags and zone bounds are compared around every transition (+-1 s), across
1800-2400, and around the footer-rule transitions Go reports for 2026-2400.
Time.String and Date are compared on samples, and accept/reject plus lookups
are compared for mutated and hand-built blobs with assorted TZ footers.
"""
import calendar
from datetime import datetime, timedelta, timezone
import io
import os
from pathlib import Path
import random
import shutil
import struct
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
RNG = random.Random(0x7A1F)
Y1800 = calendar.timegm((1800, 1, 1, 0, 0, 0))
Y2400 = calendar.timegm((2400, 1, 1, 0, 0, 0))
Y2026 = calendar.timegm((2026, 1, 1, 0, 0, 0))
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def go_zoneinfo():
    env = dict(os.environ, GOTOOLCHAIN="local")
    goroot = subprocess.check_output(["go", "env", "GOROOT"], text=True, env=env).strip()
    return Path(goroot) / "lib" / "time" / "zoneinfo.zip"


def parse(data):
    """Return (transitions, offsets per transition, footer) from the 64-bit block."""
    def counts(at):
        return struct.unpack(">6I", data[at + 20:at + 44])
    isut, isstd, leap, timecnt, typecnt, charcnt = counts(0)
    at = 44
    size = 4
    if data[4] != 0:
        at += timecnt * 5 + typecnt * 6 + charcnt + leap * 8 + isstd + isut
        isut, isstd, leap, timecnt, typecnt, charcnt = counts(at)
        at += 44
        size = 8
    fmt = ">%dq" % timecnt if size == 8 else ">%di" % timecnt
    times = list(struct.unpack(fmt, data[at:at + timecnt * size]))
    at += timecnt * size
    idx = list(data[at:at + timecnt])
    at += timecnt
    types = [struct.unpack(">iBB", data[at + 6 * i:at + 6 * i + 6]) for i in range(typecnt)]
    at += typecnt * 6 + charcnt + leap * (size + 4) + isstd + isut
    footer = data[at:]
    return times, [types[i][0] for i in idx], [t[0] for t in types], footer


def civil(sec):
    return (EPOCH + timedelta(seconds=sec)).timetuple()[:6]


def zone_requests(name, data):
    times, offs, all_offsets, footer = parse(data)
    hx = data.hex()
    instants = {Y1800, Y2400 - 1, 0, -1, Y2026}
    for t in times:
        instants.update((t - 1, t, t + 1))
    instants.update(RNG.randrange(Y1800, Y2400) for _ in range(40))
    rule_zone = b"," in footer
    sweep = []
    if rule_zone:
        years = list(range(2026, 2101)) + list(range(2101, 2400, 7))
        for y in years:
            for month in (1, 4, 7, 10):
                sweep.append(calendar.timegm((y, month, 15, 12, 0, 0)))
    instants.update(sweep)
    ordered = sorted(i for i in instants if Y1800 - 86400 <= i <= Y2400)
    reqs = [("Z", hx, ",".join(map(str, ordered)), name)]
    stamps = [RNG.randrange(Y1800, Y2400) for _ in range(12)] + [t + d for t in times[:6] for d in (-1, 0)]
    nsecs = [0, 1, 500_000_000, 999_999_999, 123_456_000]
    reqs.append(("S", hx, ",".join(f"{s}.{RNG.choice(nsecs)}" for s in stamps), name))
    dates = []
    picks = times if len(times) <= 30 else RNG.sample(times, 30)
    for t in picks:
        for off in set(all_offsets):
            for d in (-3601, -1, 0, 1, 1800, 3600):
                c = civil(t + off + d)
                if 1800 <= c[0] < 2400:
                    dates.append(".".join(map(str, c)))
    for _ in range(10):
        c = civil(RNG.randrange(Y1800, Y2400))
        dates.append(".".join(map(str, c)))
    dates.append("2023.13.32.25.61.61")
    dates.append("2023.0.0.-1.-1.-1")
    reqs.append(("D", hx, ",".join(dates), name))
    return reqs, rule_zone


def bounds_followup(zone_req, answer):
    """Around every footer transition Go reported, query -1/0/+1 s."""
    instants = set()
    for item in answer.split("\t", 1)[1].split(";"):
        for b in item.split(",")[3:5]:
            if b != "-":
                v = int(b)
                if Y2026 <= v <= Y2400:
                    instants.update((v - 1, v, v + 1))
    return ("Z", zone_req[1], ",".join(map(str, sorted(instants))), zone_req[3] + " (footer bounds)")


def header(version, counts):
    return b"TZif" + bytes([version]) + bytes(15) + struct.pack(">6I", *counts)


def build(version, times, idx, types, abbrev, footer=b"", leaps=0):
    """Hand-built TZif; v2+ files repeat the data in a 64-bit block."""
    def block(size):
        # 32-bit blocks keep the low bits; readers of v2+ skip them anyway.
        fmt, mask = (">q", None) if size == 8 else (">I", 0xFFFFFFFF)
        out = b"".join(struct.pack(fmt, t if mask is None else t & mask) for t in times) + bytes(idx)
        out += b"".join(struct.pack(">iBB", *t) for t in types) + abbrev
        out += b"".join(struct.pack(fmt, 100 * i) + struct.pack(">i", i) for i in range(leaps))
        return out + bytes(len(types)) + bytes(len(types))
    counts = (len(types), len(types), leaps, len(times), len(types), len(abbrev))
    v = 0 if version == 1 else ord(str(version))
    out = header(v, counts) + block(4)
    if version > 1:
        out += header(v, counts) + block(8) + footer
    else:
        out += footer
    return out


FOOTERS = [
    b"PST8PDT,M3.2.0,M11.1.0", b"EST5EDT", b"CET-1CEST,M3.5.0,M10.5.0/3", b"<+0330>-3:30",
    b"AEST-10AEDT,M10.1.0,M4.1.0/3", b"<-03>3<-02>,M3.5.0/-2,M10.5.0/-1", b"EST5EDT,0/0,J365/25",
    b"IST-1GMT0,M10.5.0,M3.5.0/1", b"<+13>-13", b"XXX3EDT4,J1/0,J365/24", b"WGT3WGST,M3.5.0/-2,M10.5.0/-1",
    b"ABC-1:30DEF,J60/167,J59", b"NZST-12NZDT,M9.5.0,M4.1.0/3", b"<-01>1<+00>,M3.5.0/0,M10.5.0/1",
    b"MSK-3", b"UTC0", b"EST5EDT,M3.2.0/2:30:15,M11.1.0/1:00", b"STD-24DST,M1.1.0,M12.5.6",
    b"ABC+167:59:59DEF-167:59:59,0,365", b"ABC-10DEF,59,60", b"ABC5DEF;M3.2.0,M11.1.0",
    # Malformed: Go ignores these at lookup time and uses the last transition.
    b"AB5", b"ABC", b"ABC+", b"ABC5DEF,M3.2.0", b"ABC5DEF,M13.1.0,M11.1.0", b"ABC5DEF,M3.6.0,M11.1.0",
    b"ABC5DEF,M3.2.7,M11.1.0", b"ABC5DEF,J0,J365", b"ABC5DEF,366,0", b"ABC169", b"ABC5:60",
    b"<ABC", b"<>5<>,0,1", b"ABC5DEF,M3.2.0,M11.1.0x", b"ABC5DEF6x", b"ABC5,garbage",
    b"ABC5DEF,M3.2.0/168,M11.1.0", b"ABC5DEF,M3.2.0/-168,M11.1.0/169", b"\xffBC5", b"AB\xff5DEF,0,1",
]


def footer_variants():
    out = []
    for footer in FOOTERS + [random_tz() for _ in range(300)]:
        for version, times in ((2, []), (3, [-2_000_000_000]), (1, [])):
            types = [(-18000, 0, 0), (-14400, 1, 4)]
            idx = [0] * len(times)
            data = build(version, times, idx, types, b"LMT\x00XDT\x00")
            data += b"\n" + footer + b"\n"
            out.append((data, "footer " + footer.decode("latin-1")))
    return out


def random_tz():
    def name():
        if RNG.random() < 0.2:
            return "<" + RNG.choice(["+03", "-0330", "", "A1B"]) + ">"
        return "".join(RNG.choice("ABCDEFXYZ") for _ in range(RNG.choice([3, 3, 4, 2])))

    def off():
        sign = RNG.choice(["", "", "-", "+"])
        parts = [str(RNG.randrange(0, 26 if RNG.random() < 0.9 else 170))]
        if RNG.random() < 0.3:
            parts.append("%02d" % RNG.randrange(0, 61))
            if RNG.random() < 0.3:
                parts.append("%02d" % RNG.randrange(0, 61))
        return sign + ":".join(parts)

    def rule():
        kind = RNG.randrange(3)
        if kind == 0:
            r = "J%d" % RNG.randrange(0, 367)
        elif kind == 1:
            r = "%d" % RNG.randrange(0, 367)
        else:
            r = "M%d.%d.%d" % (RNG.randrange(0, 14), RNG.randrange(0, 7), RNG.randrange(0, 8))
        if RNG.random() < 0.5:
            r += "/" + off()
        return r
    s = name() + off()
    if RNG.random() < 0.85:
        s += name()
        if RNG.random() < 0.4:
            s += off()
        if RNG.random() < 0.9:
            s += RNG.choice([",", ",", ";"]) + rule() + "," + rule()
    return s.encode()


def mutations(seeds):
    out = []
    for data, label in seeds:
        n = len(data)
        if n <= 44:
            continue
        cuts = range(n) if n < 400 else sorted(RNG.sample(range(n), 200))
        out += [(data[:i], f"{label} truncated at {i}") for i in cuts]
        for v in (0, ord("1"), ord("2"), ord("3"), ord("5"), ord("Z")):
            out.append((data[:4] + bytes([v]) + data[5:], f"{label} version {v}"))
        second = None
        if data[4] != 0:
            isut, isstd, leap, timecnt, typecnt, charcnt = struct.unpack(">6I", data[20:44])
            second = 44 + timecnt * 5 + typecnt * 6 + charcnt + leap * 8 + isstd + isut
        for base in (20, second):
            if base is None or base + 24 > n:
                continue
            for field in range(6):
                at = base + 4 * field
                old = struct.unpack(">I", data[at:at + 4])[0]
                for value in {0, 1, old + 1, max(old - 1, 0), 0x7FFFFFFF, 0xFFFFFFFF, old * 2 + 3}:
                    value &= 0xFFFFFFFF
                    out.append((data[:at] + struct.pack(">I", value) + data[at + 4:],
                                f"{label} count {field}@{at}={value}"))
        for _ in range(150):
            b = bytearray(data)
            for _ in range(RNG.randint(1, 3)):
                b[RNG.randrange(44, n)] = RNG.choice([0, 1, 0xFF, 0x0A, RNG.randrange(256)])
            out.append((bytes(b), f"{label} flipped"))
    return out


def hand_built():
    std = [(-28800, 0, 0), (-25200, 1, 4), (-25200, 0, 8)]
    abbrev = b"PST\x00PDT\x00MST\x00"
    times = [-2_000_000_000, -100, 0, 1_000_000_000, 2_000_000_000]
    blobs = [
        (build(1, times, [0, 1, 0, 1, 2], std, abbrev), "v1"),
        (build(1, times, [0, 1, 0, 1, 2], std, abbrev, b"\nMST7\n"), "v1 with footer"),
        (build(2, times, [1, 0, 1, 0, 2], std, abbrev, b"\nMST7\n"), "v2 first DST"),
        (build(3, times + [5_000_000_000], [0, 1, 0, 1, 0, 1], std, abbrev, b"\nPST8PDT,M3.2.0,M11.1.0\n"), "v3"),
        (build(2, [], [], [(19800, 0, 0)], b"IST\x00"), "v2 no transitions"),
        (build(2, [], [], [(3600, 1, 0), (0, 1, 4)], b"AAA\x00BBB\x00"), "v2 all DST"),
        (build(2, times, [1, 2, 1, 2, 1], std, abbrev, b"\n\n"), "v2 unused first zone"),
        (build(2, [5, 3, 9, 1], [0, 1, 2, 0], std, abbrev), "v2 unsorted"),
        (build(2, times, [0, 1, 0, 1, 0], std, b"PST\x00PDT\x00MST"), "v2 abbrev without NUL"),
        (build(2, times, [0, 1, 0, 1, 0], std, abbrev, leaps=3), "v2 leap seconds"),
        (build(2, times, [0, 1, 0, 1, 0], [(-28800, 0, 0), (999999, 1, 4), (-90000, 0, 8)], abbrev), "v2 large offsets"),
        (build(2, times, [0, 1, 0, 1, 0], std, b"P\xffT\x00PDT\x00MST\x00"), "v2 invalid UTF-8 abbreviation"),
        (build(2, times, [0, 1, 0, 1, 0], std, abbrev, b"\nPST8PDT\n\n"), "v2 footer with newline"),
        (build(2, times, [0, 1, 0, 1, 0], std, abbrev, b"PST8PDT\n"), "v2 footer without leading newline"),
        (build(2, times, [0, 1, 0, 1, 0], std, abbrev, b"\nX"), "v2 unterminated footer"),
        (build(2, times, [0, 1, 0, 1, 3], std, abbrev), "v2 bad zone index"),
        (build(2, times, [0, 1, 0, 1, 0], [(-28800, 0, 12)], abbrev), "v2 bad abbreviation index"),
        (build(2, [], [], [], b""), "v2 zero zones"),
        (build(1, [], [], [], b""), "v1 zero zones"),
        (b"TZif", "magic only"), (b"", "empty"), (b"TZif2" + bytes(15), "header without counts"),
        (b"TZiF2" + bytes(39), "bad magic"),
    ]
    return blobs


LOOKUPS = ",".join(map(str, [Y1800, -2_000_000_001, -2_000_000_000, -101, -100, -1, 0, 1, 2, 3, 4, 5, 9,
                             999_999_999, 1_000_000_000, 1_999_999_999, 2_000_000_000, 4_102_444_800,
                             5_000_000_000, 5_000_000_000 + 86400 * 100, 7_000_000_000, Y2400 - 1]))


NAMES = ["", "UTC", "Local", "America/New_York", "Europe/London", "Asia/Kolkata", "Etc/GMT+5", "EST5EDT",
         "Australia/Lord_Howe", "America//New_York", "./America/New_York", "America/./New_York",
         "../zoneinfo/UTC", "America/../UTC", "..", "a..b", "/etc/localtime", "\\UTC", "America", "America/",
         "America/New_York/x", "Nowhere/Zone", "utc", "local", "Mars/Olympus_Mons", "Etc/UTC", "GMT",
         "zone.tab", "iso3166.tab", "a\x00b", "posixrules", "Factory", "US/Pacific", "localtime", ". ", "."]


EMBEDDED = ROOT / "src" / "time" / "tzdata" / "zoneinfo.zip"


def name_requests(archive):
    # Go falls back to $GOROOT's archive; sample names both archives share.
    embedded = set(zipfile.ZipFile(EMBEDDED).namelist())
    names = NAMES + RNG.sample(sorted(embedded & set(archive.namelist())), 40)
    return [("L", n.encode().hex(), LOOKUPS, "LoadLocation " + repr(n)) for n in names]


def run(command, payload, env):
    result = subprocess.run(command, input=payload, text=True, capture_output=True, cwd=ROOT, env=env, timeout=200)
    if result.returncode:
        raise RuntimeError(f"{' '.join(command)} failed:\n{result.stderr}")
    return result.stdout.splitlines()


def compare(requests, env):
    payload = "".join(f"{mode}:{hx}:{args}\n" for mode, hx, args, _ in requests)
    go = run(["go", "run", "tools/tzif_oracle.go"], payload, env)
    rust = run(["cargo", "run", "--quiet", "--offline", "--locked", "--example", "tzif_probe"], payload, env)
    if len(go) != len(requests) or len(rust) != len(requests):
        raise AssertionError("tzif oracle returned the wrong number of records")
    failures = []
    for req, g, r in zip(requests, go, rust):
        if g == r:
            continue
        gi, ri = g.split("\t", 1)[-1].split(";"), r.split("\t", 1)[-1].split(";")
        args = req[2].split(",")
        detail = [(a, x, y) for a, x, y in zip(args, gi, ri) if x != y][:3] if len(gi) == len(ri) else (g[:120], r[:120])
        failures.append((req[0], req[3], detail))
    return go, failures


def main():
    if not shutil.which("go") or not shutil.which("cargo"):
        raise RuntimeError("tzif differential check requires Go and Cargo on PATH")
    env = os.environ.copy()
    env.update({"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off", "TZ": "UTC"})
    go_zip = go_zoneinfo().read_bytes()
    if go_zip != EMBEDDED.read_bytes():
        print("note: the embedded tzdata archive differs from this Go toolchain's lib/time/zoneinfo.zip")
    archive = zipfile.ZipFile(io.BytesIO(go_zip))
    zones = [(n, archive.read(n)) for n in archive.namelist()]
    requests, rule_zones = [], []
    for name, data in zones:
        reqs, rule_zone = zone_requests(name, data)
        requests += reqs
        if rule_zone:
            rule_zones.append(reqs[0])
    seeds = hand_built()
    for name in ("America/Los_Angeles", "Asia/Kolkata", "Etc/GMT+5", "Australia/Lord_Howe", "Europe/Dublin"):
        seeds.append((archive.read(name), name))
    blobs = seeds + mutations(seeds[:20] + seeds[-5:]) + footer_variants()
    requests += [("Z", data.hex(), LOOKUPS, label) for data, label in blobs]
    # LoadLocation with ZONEINFO pointing at the checked-in archive.
    env["ZONEINFO"] = str(EMBEDDED)
    requests += name_requests(archive)
    go, failures = compare(requests, env)
    # Second pass: +-1 s around every footer-rule transition Go reported.
    by_req = {id(req): answer for req, answer in zip(requests, go)}
    followups = [bounds_followup(req, by_req[id(req)]) for req in rule_zones if by_req[id(req)].startswith("ok")]
    _, more = compare(followups, env)
    failures += more
    for mode, label, detail in failures[:12]:
        print(f"mode={mode} {label}: {detail}")
    total = sum(len(r[2].split(",")) for r in requests + followups)
    if failures:
        raise AssertionError(f"{len(failures)} of {len(requests) + len(followups)} tzif requests differ from Go")
    rejected = sum(1 for (m, _, _, _), g in zip(requests, go) if g == "err")
    print(f"tzif Go differential: {len(zones)} zones, {len(blobs)} hand-built/mutated/footer blobs "
          f"({rejected} rejected), {len(rule_zones)} zones with footer rules "
          f"({sum(len(r[2].split(',')) for r in followups)} footer-transition instants), "
          f"{len(requests) + len(followups)} requests, {total} instants/dates passed")


if __name__ == "__main__":
    main()
