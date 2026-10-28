#!/usr/bin/env python3
"""Go/Rust differential for the Go-shaped archive/tar and archive/zip APIs.

Complements tools/check_archives.py (compression and single-member interchange).
Three families of vectors are compared exactly against Go's archive packages:

* read: every fixture in GOROOT/src/archive/{tar,zip}/testdata (GNU, PAX, star,
  sparse in all three layouts, hard links, ZIP64, data descriptors, preambles,
  extended timestamps, UTF-8 flag and CP437 names), plus archives written by Go
  and by Rust, are parsed by both sides and compared field by field;
* write: seeded manifests of headers are written by both Go and Rust; the
  per-entry accept/reject decisions and (for tar and stored zip members) the
  archive bytes must be identical, and every produced archive is read back by
  both implementations;
* mutations: deterministic bit flips, byte replacements, truncations and block
  splices of all of the above must produce identical accept/reject results and
  decoded content.

Documented, accepted differences: tar headers are read with Reader::next_raw,
which keeps Go's arbitrary-byte names exactly (nonutf8=1 entries included);
ZIP names that are not valid UTF-8 are compared as the raw bytes Go keeps
(FileHeader::raw_name); deflated members are compared by decoded content and,
for archives written by both sides, by exact bytes.
"""
import base64
import bz2
import os
from pathlib import Path
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zlib

ROOT = Path(__file__).resolve().parents[1]
SCALE = float(os.environ.get("ARCHIVE_API_SCALE", "1"))
# CGO_ENABLED=0 makes Go's os/user read /etc/passwd and /etc/group on Linux, as the Rust
# probe does. On macOS Go asks libSystem either way (only -tags osusergo parses /etc), so
# the files the FileInfoHeader suite stats are owned by ids /etc lists or the current user.
ENV = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off", CGO_ENABLED="0")


def run(args, **kw):
    return subprocess.run(args, cwd=ROOT, env=ENV, check=True, capture_output=True, **kw)


def goroot():
    return Path(subprocess.check_output(["go", "env", "GOROOT"], text=True, env=ENV).strip())


class Tools:
    def __init__(self, directory):
        self.go = str(directory / "archive_api_oracle")
        run(["go", "build", "-o", self.go, "tools/archive_api_oracle.go"])
        run(["cargo", "build", "--offline", "--locked", "--example", "archive_api_probe"])
        meta = subprocess.check_output(["cargo", "metadata", "--offline", "--no-deps", "--format-version", "1"],
                                       cwd=ROOT, env=ENV)
        import json
        target = Path(json.loads(meta)["target_directory"])
        self.rust = str(target / "debug" / "examples" / ("archive_api_probe.exe" if os.name == "nt" else "archive_api_probe"))

    def read(self, which, kind, files):
        """Return {file: [lines]} for the Go (which='go') or Rust reader."""
        exe = self.go if which == "go" else self.rust
        out = {}
        for start in range(0, len(files), 200):
            batch = files[start:start + 200]
            text = subprocess.run([exe, f"{kind}-read", *map(str, batch)], cwd=ROOT, env=ENV,
                                  capture_output=True, text=True, errors="replace").stdout
            current = None
            for line in text.splitlines():
                if line.startswith("@@ "):
                    current = line[3:]
                    out[current] = []
                elif current is not None:
                    out[current].append(line)
        return out

    def write(self, which, kind, manifest, target):
        exe = self.go if which == "go" else self.rust
        proc = subprocess.run([exe, f"{kind}-write", str(manifest), str(target)], cwd=ROOT, env=ENV,
                              capture_output=True, text=True)
        return proc.returncode, proc.stdout


def normalise_zip(lines):
    """Decode CP437 names (raw bytes in Go, already text in Rust)."""
    out = []
    for line in lines:
        out.append(line)
    return out


def cp437_name(hexname):
    raw = bytes.fromhex(hexname)
    try:
        raw.decode("utf-8")
        return hexname
    except UnicodeDecodeError:
        return raw.decode("cp437").encode("utf-8").hex()


def zip_view(lines):
    """Normalise a Go zip-read transcript so it is comparable with Rust's.

    Member names and comments are compared as raw bytes (FileHeader::name_bytes). The archive
    comment and the fs.FS view are Strings on the Rust side, decoded from CP437.
    """
    out = []
    for line in lines:
        if line.startswith("Z "):
            parts = line.split(" ")
            for i, kv in enumerate(parts):
                if kv.startswith("comment="):
                    parts[i] = "comment=" + cp437_name(kv[len("comment="):])
            line = " ".join(parts)
        elif line.startswith("FS "):
            parts = line.split(" ")
            for i, kv in enumerate(parts[1:], 1):
                if ":" in kv and not kv.startswith(("walkerr", "infoerr")):
                    head, rest = kv.split(":", 1)
                    parts[i] = cp437_name(head) + ":" + rest
            line = " ".join(parts)
        out.append(line)
    return out


def comparable(go_lines, rust_lines, kind):
    """Apply the documented accepted differences and return both sides."""
    if kind == "tar":
        return go_lines, rust_lines
    drop_fs = any(
        line.startswith("F ") and not valid_utf8(line.split(" name=")[1].split(" ")[0])
        for line in go_lines
    )
    return relax_zip(zip_view(go_lines), drop_fs), relax_zip(rust_lines, drop_fs)


def valid_utf8(hexname):
    try:
        bytes.fromhex(hexname).decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def relax_zip(lines, drop_fs):
    """Apply the accepted ZIP differences to one transcript.

    * Go's fs.ValidPath rejects names that are not UTF-8, so the fs.FS view of
      archives with CP437 names is not comparable (Rust lists the decoded names).
    * When reading a member fails, how many bytes arrive alongside the error is
      implementation defined (Go drops the final chunk that comes with io.EOF).
    """
    out = []
    for line in lines:
        if drop_fs and line.startswith("FS "):
            continue
        if line.startswith(("D ", "R ")) and line.endswith("err=1"):
            line = line[:2] + "err=1"
        if line.startswith("FS "):
            line = re.sub(r"D,len=\d+,fnv=[0-9a-f]+,trunc=\d,err=1", "D,err=1", line)
        out.append(line)
    return out


class Report:
    def __init__(self):
        self.count = 0
        self.failures = []

    def compare(self, tools, kind, files, label):
        go = tools.read("go", kind, files)
        rust = tools.read("rust", kind, files)
        for f in files:
            self.count += 1
            g, r = comparable(go.get(str(f), ["<missing>"]), rust.get(str(f), ["<missing>"]), kind)
            if g != r:
                self.failures.append((label, str(f), g, r))
                keep = ROOT / "target" / "archive-api-failures"
                keep.mkdir(parents=True, exist_ok=True)
                shutil.copy(f, keep / Path(f).name)


def decode_fixture(path):
    data = path.read_bytes()
    if path.name.endswith(".base64"):
        return base64.b64decode(data)
    if path.name.endswith(".bz2"):
        return bz2.decompress(data)
    return data


def mutate(rng, data, header_span):
    data = bytearray(data)
    if not data:
        return bytes(data)
    kind = rng.randrange(6)
    span = max(1, min(len(data), header_span))
    if kind == 0:
        data[rng.randrange(span)] ^= 1 << rng.randrange(8)
    elif kind == 1:
        data[rng.randrange(span)] = rng.randrange(256)
    elif kind == 2:
        return bytes(data[:rng.randrange(len(data))])
    elif kind == 3:
        pos = rng.randrange(len(data))
        data[pos:pos + rng.randrange(1, 40)] = b"\x00" * rng.randrange(1, 40)
    elif kind == 4:
        pos = rng.randrange(span)
        data[pos] = rng.choice([0, 0xff, 0x80, 0x7f, ord("0"), ord("7"), ord(" "), ord("/")])
        data[rng.randrange(span)] ^= 1 << rng.randrange(8)
    else:
        a, b = rng.randrange(len(data)), rng.randrange(len(data))
        data[a], data[b] = data[b], data[a]
    return bytes(data)


def hexs(s):
    return s.encode().hex()


def tar_manifest(rng, entries):
    names = ["a.txt", "dir/sub/file.bin", "x" * 100, "y" * 101, "é/ü/日本語.txt", "dir/", "z" * 120 + "/" + "w" * 60,
             "/".join("d" * rng.randint(1, 30) for _ in range(rng.randint(3, 12))), "q" * 300,
             "p/" * 60 + "file", "länge/" * 30 + "n"]
    times = [None, "0.0", "1700000000.0", "1700000000.123456789", "-5.0", "-5.5", "1099511627776.0",
             "8589934592.0", "8589934591.999999999", "1.5", "zero"]
    lines = []
    for _ in range(entries):
        typeflag = rng.choice([48] * 12 + [0, 0, 53, 53, 50, 50, 49, 49, 51, 52, 54, 55, 103, 103, 120, 76, 83])
        name = rng.choice(names)
        if typeflag == 53 and not name.endswith("/"):
            name += "/"
        if typeflag == 103:
            name = rng.choice(["", "global", "g" * 120])
        data = b""
        size = 0
        if typeflag in (48, 0, 55, 83):
            data = rng.randbytes(rng.choice([0, 1, 5, 511, 512, 513, 2000]))
            size = len(data)
            if rng.random() < 0.03:
                size += rng.choice([-1, 1, 600])
        d = {
            "type": typeflag, "name": hexs(name), "size": size,
            "mode": rng.choice([0o644] * 6 + [0o755, 0o4755, 0o40755, 0, 0o7777777, 1 << 33, -1]),
            "uid": rng.choice([0, 1000, 1000, 1000, 65535, 2097151, 2097152, 1 << 40, -1]),
            "gid": rng.choice([0, 1000, 1000, 1000, 8388608]),
            "fmt": rng.choice([0, 0, 0, 2, 4, 8]),
        }
        if typeflag == 103:
            d.update(size=0, mode=0, uid=0, gid=0)
            d["pax"] = f"{hexs('comment')}:{hexs('hello')},{hexs('k' + str(rng.randrange(9)))}:{hexs('v' * rng.randrange(1, 200))}"
        else:
            if rng.random() < 0.4:
                d["link"] = hexs(rng.choice(["target", "t/" * 60 + "x", "ü"]))
            if rng.random() < 0.4:
                d["uname"] = hexs(rng.choice(["root", "user" * 10, "ñandú"]))
                d["gname"] = hexs(rng.choice(["wheel", "g" * 33]))
            if rng.random() < 0.15:
                d["dmaj"] = rng.choice([1, 8, 1 << 20, 1 << 40])
                d["dmin"] = rng.choice([0, 3, 255, 1 << 22])
            for key in ("mtime", "atime", "ctime"):
                t = rng.choice(times)
                if t is not None:
                    d[key] = t
            if rng.random() < 0.15:
                d["xattr"] = f"{hexs('user.k')}:{hexs('v' + str(rng.randrange(5)))}"
            if rng.random() < 0.15:
                d["pax"] = f"{hexs('comment')}:{hexs('x')},{hexs('path')}:{hexs('p' * rng.choice([5, 200]))}"
        if data:
            d["data"] = data.hex()
        lines.append(" ".join(f"{k}={v}" for k, v in d.items()))
    return "\n".join(lines) + "\n"


def settle_symlink_atime(link):
    """Make the symlink's atime stable before either tool reads it.

    On a relatime mount a readlink bumps atime while atime <= mtime, and a
    readlink in the same coarse clock tick as the creation leaves them equal.
    Without this, whichever tool ran second saw a later atime. Filesystems that
    never bump atime on readlink (APFS) exit the loop by its bound.
    """
    for _ in range(50):
        os.readlink(link)
        st = os.lstat(link)
        if st.st_atime_ns > st.st_mtime_ns:
            return
        time.sleep(0.005)


def fileinfo_suite(tools, report, work):
    """FileInfoHeader of real files: Uname and Gname come from the user database."""
    paths = [Path("/etc"), Path("/etc/passwd"), Path("/tmp"), Path("/nonexistent/x")]
    owned = work / "owned.txt"
    owned.write_text("hello")
    os.symlink(owned, work / "link")
    settle_symlink_atime(work / "link")
    (work / "sub").mkdir()
    fifo = work / "fifo"
    os.mkfifo(fifo)
    paths += [owned, work / "link", work / "sub", fifo]
    for path in ("/dev/null", "/dev/tty", "/dev/zero"):
        if os.path.exists(path):
            paths.append(Path(path))
    args = [str(p) for p in paths]
    outputs = []
    for exe in (tools.go, tools.rust):
        proc = subprocess.run([exe, "tar-fileinfo", *args], cwd=ROOT, env=ENV, capture_output=True, text=True)
        outputs.append(proc.stdout.splitlines())
    # Device files under /dev (null, tty) are written to by the system, so their
    # timestamps can change between the Go and Rust reads; compare the rest.
    def stable(line):
        if line.startswith("FI " + "/dev/".encode().hex()):
            return re.sub(r" (mtime|atime|ctime)=\S+", r" \1=*", line)
        return line
    go, rust = ([stable(line) for line in out] for out in outputs)
    report.count += len(args)
    if go != rust:
        report.failures.append(("tar FileInfoHeader", "fileinfo", go, rust))
    named = [line for line in go if " uname=" in line and " uname= " not in line]
    if not named:
        report.failures.append(("tar FileInfoHeader", "fileinfo", ["no user names resolved"], []))
    return len(args)


def tar_suite(tools, report, work, rng):
    td = goroot() / "src/archive/tar/testdata"
    fixtures = []
    for p in sorted(td.iterdir()):
        if p.suffix in (".tar", ".base64", ".bz2"):
            out = work / ("fx_" + p.name + ".tar")
            out.write_bytes(decode_fixture(p))
            fixtures.append(out)
    report.compare(tools, "tar", fixtures, "tar fixture")

    produced = []
    mismatches = 0
    for n in range(int(80 * SCALE)):
        manifest = work / f"tar_{n}.manifest"
        manifest.write_text(tar_manifest(rng, rng.randint(1, 12)))
        go_out, rust_out = work / f"tar_{n}.go.tar", work / f"tar_{n}.rs.tar"
        gc, gr = tools.write("go", "tar", manifest, go_out)
        rc, rr = tools.write("rust", "tar", manifest, rust_out)
        report.count += 1
        if gc or rc or gr != rr or go_out.read_bytes() != rust_out.read_bytes():
            mismatches += 1
            report.failures.append(("tar write", str(manifest), gr.splitlines()[:6], rr.splitlines()[:6]))
        produced.append(go_out)
        produced.append(rust_out)
    report.compare(tools, "tar", produced, "tar read of written")

    bases = [f for f in fixtures if f.stat().st_size <= 1 << 21] + produced[:80:2]
    mutants = []
    for i in range(int(1000 * SCALE)):
        base = bases[rng.randrange(len(bases))]
        out = work / f"tar_mut_{i}.tar"
        out.write_bytes(mutate(rng, base.read_bytes(), 2048))
        mutants.append(out)
    report.compare(tools, "tar", mutants, "tar mutation")
    return len(fixtures) + len(produced) + len(mutants)


CP437_NAMES = ["café.txt", "ñandú/ü.bin", "│box─", "Ça va", "plain"]


def zip_manifest(rng, entries, offset=False):
    names = ["a.txt", "dir/sub/file.bin", "dir/", "x" * 300, "héllo/日本.txt", "back\\slash.txt",
             "../up.txt", "/abs.txt", "d/", "dup.txt", "dup.txt", "with space.txt", "t\u0001ab"]
    times = [None, "zero", "1700000000.0", "1700000000.999999999", "315532800.0", "315532799.0",
             "4354819200.0", "-1.0", "3000000000.5", "951782400.0"]
    lines = []
    if offset:
        lines.append(f"op=offset offset={rng.choice([7, 1000, 70000])}")
    for _ in range(entries):
        d = {}
        name = rng.choice(names)
        if rng.random() < 0.12:
            raw_name = rng.choice(CP437_NAMES)
            d["nonutf8"] = 1
            d["rawname"] = raw_name.encode("cp437").hex()
            name = raw_name
        elif rng.random() < 0.06:
            # NonUTF8 with a name that is valid UTF-8: Go writes the bytes unchanged.
            d["nonutf8"] = 1
        d["name"] = hexs(name)
        if rng.random() < 0.15:
            d["comment"] = hexs(rng.choice(["note", "nöte", "c" * 100]))
            if rng.random() < 0.3:
                d["rawcomment"] = d["comment"] if rng.random() < 0.5 else bytes([0x82, 0xFF, 0x61]).hex()
        data = b""
        if not name.endswith("/") or rng.random() < 0.05:
            data = rng.choice([b"", b"hello", rng.randbytes(rng.choice([1, 100, 5000])),
                               b"abc" * rng.choice([10, 3000])])
        method = rng.choice([0, 0, 8, 8, 8, 99])
        d["method"] = method
        if rng.random() < 0.3:
            d["extra"] = (bytes([0xFE, 0xCA, 4, 0]) + b"abcd").hex()
        if rng.random() < 0.1:
            d["flags"] = rng.choice([0x800, 0x1, 0x2, 0x8, 0x0])
        t = rng.choice(times)
        if t is not None:
            d["modified"] = t
        if rng.random() < 0.4:
            d["mode"] = rng.choice([0o644, 0o755, 0o40755, 0o120777, 0o4755, 1 << 31 | 0o755, 0o444])
        if rng.random() < 0.08:
            d["op"] = "raw"
            d["method"] = 0
            d["crc"] = zlib.crc32(data)
            big = rng.random() < 0.3
            d["csize64"] = (5 << 30) if big else len(data)
            d["usize64"] = (5 << 30) if big else len(data)
            if big:
                data = b""
        if data:
            d["data"] = data.hex()
        lines.append(" ".join(f"{k}={v}" for k, v in d.items()))
    if rng.random() < 0.3:
        lines.append("op=comment comment=" + hexs(rng.choice(["archive comment", "", "x" * 70000, "é"])))
    return "\n".join(lines) + "\n"


def drop_unstable(lines):
    """Remove fields that depend on the deflate encoder's output."""
    out = []
    for line in lines:
        if line.startswith("R "):
            continue
        parts = [p for p in line.split(" ")
                 if not p.startswith(("csize=", "csize64=", "offset=", "mtime="))]
        out.append(" ".join(parts))
    return out


def zip_suite(tools, report, work, rng):
    td = goroot() / "src/archive/zip/testdata"
    fixtures = []
    # The zip64 .zsparse goldens exist from Go 1.26 on.
    zip64 = list((td / "zip64").iterdir()) if (td / "zip64").is_dir() else []
    for p in sorted(list(td.iterdir()) + zip64):
        if p.suffix in (".zip", ".notzip", ".zsparse"):
            fixtures.append(p)
        elif p.suffix == ".base64":
            out = work / ("fx_" + p.name + ".zip")
            out.write_bytes(decode_fixture(p))
            fixtures.append(out)
    report.compare(tools, "zip", fixtures, "zip fixture")

    produced = []
    N_ZIP = max(2, int(70 * SCALE))
    for n in range(N_ZIP):
        manifest = work / f"zip_{n}.manifest"
        manifest.write_text(zip_manifest(rng, rng.randint(1, 10), offset=(n % 7 == 0)))
        go_out, rust_out = work / f"zip_{n}.go.zip", work / f"zip_{n}.rs.zip"
        gc, gr = tools.write("go", "zip", manifest, go_out)
        rc, rr = tools.write("rust", "zip", manifest, rust_out)
        report.count += 1
        if gc or rc or gr != rr:
            report.failures.append(("zip write decisions", str(manifest), gr.splitlines()[:8], rr.splitlines()[:8]))
        produced += [go_out, rust_out]
    # Both archives must read identically in Go and in Rust. Deflate bytes
    # are encoder specific, so the archive pair is compared by decoded content.
    report.compare(tools, "zip", produced, "zip read of written")
    reads = tools.read("go", "zip", produced)
    for n in range(N_ZIP):
        a, b = produced[2 * n], produced[2 * n + 1]
        ga = drop_unstable(zip_view(reads[str(a)]))
        gb = drop_unstable(zip_view(reads[str(b)]))
        report.count += 1
        if ga != gb:
            report.failures.append(("zip writer content", str(a), ga, gb))
        # Rust's DEFLATE encoder is a port of Go's, so the archives (default
        # method-8 compressor, flate level 5) are byte for byte the same.
        report.count += 1
        if a.read_bytes() != b.read_bytes():
            report.failures.append(("zip writer bytes", str(a), [f"{a.stat().st_size} bytes"], [f"{b.stat().st_size} bytes"]))

    # More than 65534 entries needs a ZIP64 end-of-directory record.
    lines = [f"name={hexs('f%05d' % i)} method=0 data={b'x'.hex()}" for i in range(70000)]
    manifest = work / "zip_many.manifest"
    manifest.write_text("\n".join(lines) + "\n")
    many = []
    for who in ("go", "rust"):
        out = work / f"zip_many.{who}.zip"
        tools.write(who, "zip", manifest, out)
        many.append(out)
    report.count += 1
    if many[0].read_bytes() != many[1].read_bytes():
        report.failures.append(("zip64 many entries", str(many[0]), ["bytes differ"], ["bytes differ"]))
    report.compare(tools, "zip", many, "zip64 many entries read")

    bases = [f for f in fixtures if f.suffix != ".zsparse" and f.stat().st_size <= 1 << 20] + produced[:60:2]
    mutants = []
    for i in range(int(1000 * SCALE)):
        base = bases[rng.randrange(len(bases))]
        out = work / f"zip_mut_{i}.zip"
        data = base.read_bytes()
        out.write_bytes(mutate(rng, data, len(data) if rng.random() < 0.5 else 200))
        mutants.append(out)
    report.compare(tools, "zip", mutants, "zip mutation")
    return len(fixtures) + len(produced) + len(many) + len(mutants)


def fnv64(data):
    h = 14695981039346656037
    for c in data:
        h = ((h ^ c) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h


def tar_sparse_suite(tools, report, work, rng):
    """Rust writes sparse files (Go cannot); Go and Rust must read back the logical content."""
    lines, expected = [], []
    for i in range(40):
        size = rng.choice([0, 1, 511, 512, 1000, 4096, 10000, 70000])
        content = bytearray(size)
        holes, pos = [], 0
        while pos < size:
            span = rng.choice([512, 1024, 3000, 4096])
            take = min(span, size - pos)
            if rng.random() < 0.5:
                holes.append((pos, take))
            else:
                content[pos:pos + take] = rng.randbytes(take)
            pos += take
        gnu = i % 3 == 0
        d = {"type": 83 if gnu else 48, "name": hexs(f"sparse{i}.bin"), "size": size, "mode": 420,
             "fmt": 8 if gnu else 4, "sparse": ",".join(f"{o}:{l}" for o, l in holes) or "-",
             "data": bytes(content).hex()}
        lines.append(" ".join(f"{k}={v}" for k, v in d.items()))
        expected.append((size, fnv64(content)))
    manifest = work / "tar_sparse.manifest"
    manifest.write_text("\n".join(lines) + "\n")
    out = work / "tar_sparse.rs.tar"
    code, report_text = tools.write("rust", "tar", manifest, out)
    report.count += 1
    if code or "W err" in report_text or "D err" in report_text or "CLOSE ok" not in report_text:
        report.failures.append(("tar sparse write", str(manifest), [report_text], ["expected all ok"]))
        return 1
    go = tools.read("go", "tar", [out])[str(out)]
    rust = tools.read("rust", "tar", [out])[str(out)]
    report.count += 1
    if go != rust:
        report.failures.append(("tar sparse read", str(out), go, rust))
    digests = [line for line in go if line.startswith("D ")]
    report.count += 1
    want = [f"D len={n} fnv={h:016x} trunc=0 err=0" for n, h in expected]
    if digests != want:
        report.failures.append(("tar sparse content", str(out), digests, want))
    return 1


GOLDEN = ROOT / "tests" / "fixtures" / "archive"


def golden_text(tools, kind):
    """Go's transcript of every checked-in fixture (tests/archive_*.rs compare Rust to it)."""
    files = sorted((GOLDEN / kind).glob("*.tar" if kind == "tar" else "*.zip"))
    rel = [str(f.relative_to(ROOT)) for f in files]
    go = tools.read("go", kind, rel)
    return "".join(f"@@ {Path(r).name}\n" + "\n".join(go[r]) + "\n" for r in rel)


def check_goldens(tools, report, regenerate):
    for kind in ("tar", "zip"):
        target = GOLDEN / f"{kind}_golden.txt"
        text = golden_text(tools, kind)
        if regenerate:
            target.write_text(text)
            continue
        report.count += 1
        if not target.exists() or target.read_text() != text:
            report.failures.append(("golden", str(target), ["stale"], ["rerun with --regenerate-goldens"]))


def main():
    regenerate = "--regenerate-goldens" in sys.argv
    with tempfile.TemporaryDirectory(prefix="rust-stdlib-archive-api-") as directory:
        directory = Path(directory)
        tools = Tools(directory)
        rng = random.Random(20261012)
        report = Report()
        check_goldens(tools, report, regenerate)
        if regenerate:
            print("regenerated tests/fixtures/archive/{tar,zip}_golden.txt")
            return 0
        fileinfo_suite(tools, report, directory)
        total = tar_suite(tools, report, directory, rng)
        total += tar_sparse_suite(tools, report, directory, rng)
        suites = [("tar", total)]
        suites.append(("zip", zip_suite(tools, report, directory, rng)))
        for label, name, go, rust in report.failures[:10]:
            print(f"MISMATCH [{label}] {name}")
            for a, b in zip(go + [None] * len(rust), rust + [None] * len(go)):
                if a != b:
                    print("  go  :", a)
                    print("  rust:", b)
                    break
        if report.failures:
            print(f"archive API differential: {len(report.failures)} mismatches of {report.count} vectors")
            return 1
        print(f"archive API differential: {report.count} Go/Rust vectors passed "
              + ", ".join(f"{n} {k} archives" for k, n in suites))
        return 0


if __name__ == "__main__":
    sys.exit(main())
