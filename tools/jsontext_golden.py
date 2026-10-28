#!/usr/bin/env python3
"""Regenerates tests/fixtures/jsontext_golden.txt: request/response pairs
recorded from the Go oracle (tools/jsontext_oracle.go) for tests/jsontext.rs.

Each line is `<request>\\t<response>` in the protocol of tools/jsontext_check.py.
The corpus is Go's token accessor, value, pointer and state tables
(coder_test.go, value_test.go, state_test.go, token_test.go) plus documents of
the differential. Run it after changing the corpus below; the file is
committed so the Rust tests do not need Go."""
import pathlib
import random
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import json_gen  # noqa: E402
import jsontext_check as jc  # noqa: E402

OUT = ROOT / "tests/fixtures/jsontext_golden.txt"
hx = jc.hx

# Documents of Go's value_test.go and coder_test.go.
DOCS = [
    b'{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001,-0],"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/","literals":[null,true,false]}',
    b'{\n\t\t"\\u20ac": "Euro Sign",\n\t\t"\\r": "Carriage Return",\n\t\t"\\ufb33": "Hebrew Letter Dalet With Dagesh",\n\t\t"1": "One",\n\t\t"\\ud83d\\ude00": "Emoji: Grinning Face",\n\t\t"\\u0080": "Control",\n\t\t"\\u00f6": "Latin Small Letter O With Diaeresis"\n\t}',
    b" [ -9223372036854775808 , 9223372036854775807 ] ",
    b'  "living\xde\xad\xbe\xef\\ufffd\xef\xbf\xbd"  ',
    b'"\\ud800"', b'"\\u000B"', b' { "0" : 0 , "1" : 1 , "0" : 0 }', b" \n\r\t",
    b"null", b"false", b"true", b"0", b'""', b"[]", b"{}", b"[ ]", b"{ }",
    b'{"a":[1,2,{"b":null}],"c":"d"}', b"[[],[[]],{\"x\":{}}]",
    b' [\n\t\t[ ] , [ "one" ] , [ "one" , "two" ] ,\n\t\t{ } , { "alpha" : "bravo" } , { "alpha" : "bravo" , "fizz" : "buzz" }\n\t] ',
    b'["\\u00e9\\u2028\\u2029<>&\\/"]', b"[1.0,1.50,100e-2,1E400,-1E400,123456789012345678]",
    b"{\"b\":1,\"a\":{\"d\":2,\"c\":3}}", b'{"\xc3\xa9":1,"e":2,"\\ud83d\\ude00":3,"\\ue000":4}',
]
POINTERS = ["", "a", "~", "/a", "/foo/bar", "///", "/~0~1", "/~", "/~2", "/a~", "/é", "/\\u2028", "/😀/x", "/0/1/2", "//"]


def main():
    rng = random.Random(0x474F4C44)
    reqs = list(jc.token_requests())
    for d in DOCS + [d for d in json_gen.documents(0x47544A, 300) if len(d) < 90][:45]:
        h = hx(d)
        reqs += [f"value valid - {h}", f"value compact - {h}", f"value indent I {h}", f"value indent TP {h}",
                 f"value canon - {h}", f"value format ifr {h}", f"value format m: {h}",
                 f"decode b - T {h}", f"decode 1 - V {h}"]
        ops = jc.lex(d)
        if ops:
            reqs += ["encode w - " + " ".join(ops + ["?"]), "encode w mI " + " ".join(ops + ["?"]),
                     "encode w hjp " + " ".join(ops + ["?"])]
    for _ in range(60):
        base = jc.lex(json_gen.gen_doc(rng)) or ["tn"]
        reqs.append("encode b " + rng.choice(jc.ENCODE_OPTS) + " " + " ".join(jc.mutate_ops(rng, base) + ["?"]))
    for p in POINTERS:
        for op in ("valid", "parent", "last", "tokens"):
            reqs.append(f"pointer {op} {hx(p.encode())} -")
        reqs.append(f"pointer append {hx(p.encode())} {hx(b'a/b~')}")
        reqs.append(f"pointer contains {hx(p.encode())} {hx((p + '/x').encode())}")
    reqs += jc.quote_requests(random.Random(5))[:60] + jc.float_requests(random.Random(6))[:60]
    reqs += ["options indent 20", "options indent 78", "options prefix 09", "options prefix 70"]
    payload = "".join(r + "\n" for r in reqs)
    with tempfile.TemporaryDirectory() as tmp:
        go = jc.build_go(tmp)
        responses = jc.run(go, payload, "Go jsontext oracle")
    assert len(responses) == len(reqs)
    OUT.write_text("".join(f"{q}\t{r}\n" for q, r in zip(reqs, responses)))
    print(f"wrote {len(reqs)} vectors to {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
