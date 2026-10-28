#!/usr/bin/env python3
"""Differentially check net/http/cookiejar scenarios against Go's cookiejar."""
import os
from pathlib import Path
import random
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
RNG = random.Random(0xC00C1E)

NAMES = ["sid", "a", "b", "", "ü", "__Secure-id", "x y", "n=v"]
VALUES = ["", "1", "v a l", "ü", "a=b", "22222"]
DOMAINS = ["", "", "", "example.com", ".example.com", "EXAMPLE.com", "sub.example.com", "com", "co.uk",
           "example.co.uk", "example.com.", "..", "a..b", "127.0.0.1", "localhost", "[::1]", "other.org",
           "github.io", "bücher.example.com", "BÜCHER.example.com", "k12.ma.us", "ma.us", "x.k12.ma.us",
           "1.2.3.4", "example.org", "xn--bcher-kva.example.com", "ex ample.com"]
PATHS = ["", "", "/", "/a", "/a/", "/a/b", "relative", "/a/b/c", "/ab", "//x"]
MAX_AGES = [0, 0, 0, 3600, 7200, -1, -5]
EXPIRES = ["", "", "", "PAST", "FUTURE", "garbage"]
FLAGS = ["-", "-", "s", "h", "q"]
SCHEMES = ["http", "https", "https", "ftp"]
HOSTS = ["example.com", "sub.example.com", "EXAMPLE.COM.", "other.org", "localhost", "127.0.0.1",
         "[::1]:8080", "example.com:8080", "bücher.example.com", "a.example.co.uk", "co.uk", "k12.ma.us",
         "x.github.io", "1.2.3.4", "[::ffff:127.0.0.1]", "example.org", "com", "xn--bcher-kva.example.com",
         "a.b.c.example.com", "192.168.0.1:80"]
URL_PATHS = ["", "/", "/a", "/a/", "/a/b/c", "/ab", "/a/b", "//x", "/a b"]


def imf(epoch):
    return time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(epoch))


EXPIRY = {"PAST": imf(946684800), "FUTURE": imf(4070908800), "garbage": "not a date"}


def hexify(text):
    return text.encode().hex()


def cookie_field():
    name = RNG.choice(NAMES)
    value = RNG.choice(VALUES)
    path = RNG.choice(PATHS)
    domain = RNG.choice(DOMAINS)
    age = RNG.choice(MAX_AGES)
    expires = RNG.choice(EXPIRES)
    expires_text = "" if expires == "" else EXPIRY.get(expires, expires)
    flags = RNG.choice(FLAGS)
    return "C" + ",".join([hexify(name), hexify(value), hexify(path), hexify(domain), str(age),
                           hexify(expires_text), flags])


def url():
    scheme = RNG.choice(SCHEMES)
    host = RNG.choice(HOSTS)
    path = RNG.choice(URL_PATHS)
    return f"{scheme}://{host}{path}"


def scenario():
    mode = RNG.choice(["n", "t"])
    fields = [mode]
    for _ in range(RNG.randint(1, 6)):
        fields.append("S" + hexify(url()))
        fields.extend(cookie_field() for _ in range(RNG.randint(0, 5)))
        if RNG.random() < 0.8:
            for _ in range(RNG.randint(1, 3)):
                fields.append("G" + hexify(url()))
    return "\t".join(fields)


def fixed():
    lines = []
    for mode in "nt":
        for target in ["https://example.com/", "http://sub.example.com/a/b", "https://bücher.example.com/",
                       "http://x.example.co.uk/", "http://github.io/", "http://a.k12.ma.us/"]:
            for domain in ["example.com", "com", "co.uk", "example.co.uk", "k12.ma.us", "github.io",
                           "bücher.example.com", "BÜCHER.example.com", "xn--bcher-kva.example.com", ""]:
                cookie = cookie_field_for("c", "v", "/", domain, 3600)
                lines.append("\t".join([mode, "S" + hexify(target), cookie,
                                        "G" + hexify("https://example.com/"),
                                        "G" + hexify("http://sub.example.com/a/b"),
                                        "G" + hexify(target)]))
    lines.append("n\tS" + hexify("https://example.com/") + "\tG" + hexify("http://[::1"))
    lines.append("n\tS" + hexify("http://[::1]:80/") + "\t" + cookie_field_for("l", "1", "", "", 3600)
                 + "\tG" + hexify("http://[::1]/"))
    lines.append("t\tS" + hexify("http://github.io/") + "\t" + cookie_field_for("g", "1", "", "github.io", 3600)
                 + "\tG" + hexify("http://github.io/"))
    lines.append("n\tS" + hexify("http://127.0.0.1/") + "\t" + cookie_field_for("l", "1", "", "127.0.0.1", 3600)
                 + "\tG" + hexify("http://127.0.0.1/"))
    lines.append("n\tS" + hexify("https://localhost/") + "\t" + cookie_field_for("s", "1", "", "localhost", 3600)
                 .replace(",-", ",s") + "\tG" + hexify("http://localhost/")
                 + "\tG" + hexify("https://localhost/"))
    lines.append("n\tS" + hexify("http://localhost/") + "\t" + cookie_field_for("s", "1", "", "", 3600)
                 .replace(",-", ",s") + "\tG" + hexify("http://localhost/")
                 + "\tG" + hexify("https://localhost/"))
    return lines


def cookie_field_for(name, value, path, domain, age):
    return "C" + ",".join([hexify(name), hexify(value), hexify(path), hexify(domain), str(age), "", "-"])


def run(command, payload, env):
    result = subprocess.run(command, input=payload, text=True, capture_output=True,
                            cwd=ROOT, env=env, timeout=300)
    if result.returncode:
        raise RuntimeError(f"{' '.join(command)} failed:\n{result.stderr}")
    return result.stdout.splitlines()


def main():
    if not shutil.which("go") or not shutil.which("cargo"):
        raise RuntimeError("cookiejar differential check requires Go and Cargo on PATH")
    lines = fixed() + [scenario() for _ in range(2500)]
    payload = "\n".join(lines) + "\n"
    env = os.environ.copy()
    env.update({"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off"})
    go = run(["go", "run", "tools/cookiejar_oracle.go"], payload, env)
    rust = run(["cargo", "run", "--quiet", "--offline", "--locked", "--example", "cookiejar_probe"], payload, env)
    if len(go) != len(lines) or len(rust) != len(lines):
        raise AssertionError("cookiejar oracle returned the wrong number of records")
    failures = [(line, g, r) for line, g, r in zip(lines, go, rust) if g != r]
    for line, g, r in failures[:6]:
        print(f"input={line!r}\n  Go  ={g!r}\n  Rust={r!r}")
    if failures:
        raise AssertionError(f"{len(failures)} of {len(lines)} cookiejar scenarios differ from Go")
    cookies = sum(1 for g in go for field in g.split("\t") if field not in ("", "urlerr"))
    errors = sum(1 for g in go for field in g.split("\t") if field == "urlerr")
    print(f"cookiejar Go differential: {len(lines)} scenarios passed "
          f"({cookies} non-empty cookie lists, {errors} unparsable URLs)")


if __name__ == "__main__":
    main()
