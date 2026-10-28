#!/usr/bin/env python3
"""Run persistent Go differential suites for the next stdlib parity batch."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

def main():
    for name in ("base32", "hex", "ascii85", "quotedprintable", "hash", "html", "pem",
                 "base64_parity", "path", "tabwriter", "duration", "lzw", "png",
                 "rand", "textproto", "mail", "bzip2", "asn1", "draw", "gif", "jpeg",
                 "smtp", "httptrace", "cgi", "pprof", "signal", "color", "palette",
                 "unicode", "big", "collections", "cookiejar", "mime", "multipart",
                 "strings", "bytes", "strconv", "httputil", "crypto_hash",
                 "crypto_asym", "x509", "http", "tzif", "time", "flate", "log",
                 "crypto_cipher", "xml", "io", "context", "json", "template", "url",
                 "flag", "database", "math", "cmplx", "stdsync", "netip", "net",
                 "conn", "dns", "filepath", "os", "exec", "os_user", "fmt", "testing",
                 "sys", "syscall", "reflect", "reflect_typed", "text_scanner",
                 "suffixarray", "uuid", "expvar", "jsontext", "jsonv2", "h2",
                 "h2_interop", "gob", "rpc", "gotls"):
        subprocess.run([sys.executable, str(ROOT / "tools" / f"{name}_check.py")],
                       cwd=ROOT, check=True)

if __name__ == "__main__":
    main()
