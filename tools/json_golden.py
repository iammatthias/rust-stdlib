#!/usr/bin/env python3
"""Regenerates tests/fixtures/json_golden.txt: request/response pairs recorded
from the Go oracle (tools/json_oracle.go) for tests/json.rs.

Each line is `<request>\\t<response>` in the protocol of tools/json_check.py.
Run it after changing the corpus below; the file is committed so the Rust
tests do not need Go."""
import pathlib
import random
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import json_gen  # noqa: E402

OUT = ROOT / "tests/fixtures/json_golden.txt"


def hx(b):
    return b.hex() or "-"


# Inputs taken from Go's scanner_test.go, stream_test.go and decode_test.go,
# plus edge cases found while building the differential.
FIXED = [
    b"foo", b"}{", b"{]", b"{}", b'{"foo":"bar"}', b'{"foo":"bar","bar":{"baz":["qux"]}}',
    b"1", b"[]", b'{"":2}', b"[3]", b"[1,2,3]", b'{"x":1}',
    b'[true,false,null,"x",1,1.5,0,-5e+2]', "{\"\":\"<>&  \"}".encode(), b"null \n\r\t",
    "{\" \": 1}".encode(), "{\" \" :2}".encode(),
    b'{"X": "foo", "Y"}', b'{"X": "foo" "Y": "bar"}',
    b"", b" ", b"nul", b"nulll", b"[", b"]", b"{", b"}", b'"', b'"\\', b'"\\u12', b'"\\u12zz"', b'"\\x"',
    b"-", b"-a", b"01", b"1.", b"1e", b"1e+", b"0e0", b"1E-5", b"tru", b"truex", b"[1,]", b"[,1]",
    b"{,}", b'{"a"}', b'{"a":}', b'{"a":1,}', b"[1 2]", b"1 2", b"\xff", b'"\xff"', b'"\xc3"',
    b'"\xe2\x80\xa8"', b"'a'", b"[1]\n\n", b" [ ] ", b"{ }", b"[[],{}]", b"\x00", b'{"a":1,"a":2}',
    b"\xef\xbb\xbf1", b'["\\u00zz"]', b'"\\ud83d\\ude00"', b'"\\ud83d"', b'"\\ude00x"', b'"\x01"',
    b"1e999", b"-1e999", b"1e-999", b"123456789012345678901234567890", b"[1e999]", b'{"a":[1e999]}',
    b"\n[\n\t{\n\t\t\"a\": 1\n\t}\n]\n", b'{"k":{"z":1,"y":[true,null,{}]},"a":"\\u00e9\\n"}',
    b"[" * 100 + b"]" * 100, b'{"a":' * 3 + b"0" + b"}" * 3,
    b'{"foo":1}{"bar":2}', b"1 2 3", b'"a" "b"', b"[1] [2]", b"1,2", b"{} []", b"true false null",
    b'{"k"', b'{"k":', b'{"k",', b"[0.", b"[0. ", b"[0:", b"fal ", b"  1e1000", b" [0", b"[0,",
    b'{"alpha" : "bravo" , "fizz" : "buzz"}',
    b' [\n\t\t[ ] , [ "one" ] , [ "one" , "two" ] ,\n\t\t{ } , { "alpha" : "bravo" } , { "alpha" : "bravo" , "fizz" : "buzz" }\n\t] ',
    "{\"K\": \"Kelvin\", \"ß\": \"long s\"}".encode(), b'0.1\n"hello"\nnull\ntrue\nfalse\n["a","b","c"]\n3.14\n',
]


def main():
    rng = random.Random(0x474F4C44)
    docs = list(FIXED)
    docs += [d for d in json_gen.documents(0x474F4C44, 400) if 0 < len(d) < 140][:150]
    requests = []
    for d in docs:
        h = hx(d)
        requests += [f"valid {h}", f"compact {h}", f"indent - 09 {h}", f"indent 3e 2e {h}", f"html {h}",
                     f"unmarshal {h}", f"tokens 0 0 {h}", f"decodes 0 0 {h}"]
        if rng.random() < 0.4:
            requests += [f"tokens 3 1 {h}", f"decodes 1 1 {h}"]
    payload = "".join(r + "\n" for r in requests)
    go = subprocess.run(["go", "run", "tools/json_oracle.go"], input=payload, text=True, capture_output=True, cwd=ROOT)
    if go.returncode:
        raise RuntimeError(go.stderr)
    responses = go.stdout.splitlines()
    assert len(responses) == len(requests)
    OUT.write_text("".join(f"{q}\t{r}\n" for q, r in zip(requests, responses)))
    print(f"wrote {len(requests)} vectors to {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
