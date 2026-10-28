#!/usr/bin/env python3
"""Compare HTML EscapeString and UnescapeString against Go's standard library."""
import html.entities
import json
import os
import pathlib
import random
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    started = time.monotonic()
    vectors = []
    for name in sorted(html.entities.html5):
        vectors.append("&" + name)
        if name.endswith(";"):
            vectors.append("&" + name[:-1] + "!tail")
    vectors.extend([
        "&", "&&", "&;", "&#", "&#;", "&#x", "&#x;", "&#X;",
        "&amp", "&amp=", "&ampx;", "&notin", "&notin;", "&notit;",
        "&notit=", "&unknown;", "&longentityname", "&AEligx;",
        "&#0;", "&#13;", "&#128;", "&#159;", "&#x80;", "&#x9f;",
        "&#xD800;", "&#x110000;", "&#xFFFFFFFFFFFFFFFF;",
        "&#999999999999999999999999999999999999999999;",
        "&#x10000000000000000000000000000000000000000001;",
        "x&amp;y&#x1f642;z", "&amp;amp; &amp;lt; &amp;gt;",
        "", "<", ">", "\"", "'", "<b class=\"x\">'&'</b>", "é&雪\u0000\u007f",
    ])
    rng = random.Random(420061)
    atoms = ["&", "#", "x", "X", ";", "=", "!", "a", "m", "p", "not", "notin", "copy", "unknown", "0123456789", "abcdef", "é", "雪"]
    for _ in range(600):
        vectors.append("".join(rng.choice(atoms) for _ in range(rng.randrange(1, 15))))
    escape_atoms = ["&", "<", ">", "\"", "'", "a", "é", "雪", "&amp;", "&#34;", " ", "\U0001f642"]
    for _ in range(600):
        vectors.append("".join(rng.choice(escape_atoms) for _ in range(rng.randrange(0, 15))))

    requests = [{"op": "unescape", "input": value} for value in vectors]
    requests += [{"op": "escape", "input": value} for value in vectors]
    payload = "".join(json.dumps(request, ensure_ascii=False) + "\n" for request in requests)
    subprocess.run(["cargo", "build", "--offline", "--locked", "--example", "html_probe"], cwd=ROOT, check=True)
    probe = ROOT / "target/debug/examples" / ("html_probe.exe" if os.name == "nt" else "html_probe")
    outputs = []
    for command in [[str(probe)], ["go", "run", str(ROOT / "tools/html_oracle.go")]]:
        process = subprocess.run(command, input=payload, text=True, capture_output=True, cwd=ROOT, check=True)
        # Split on LF only: JSON strings may contain U+2028, which splitlines() also breaks on.
        outputs.append([json.loads(line) for line in process.stdout.split("\n") if line])
    if not all(len(output) == len(requests) for output in outputs):
        raise AssertionError("missing oracle output")
    for index, (rust, go) in enumerate(zip(*outputs)):
        if rust != go:
            raise AssertionError(f"request {index}: {requests[index]!r}\nRust={rust!r}\nGo={go!r}")
    print(f"HTML Go conformance: {len(vectors)} UnescapeString and {len(vectors)} EscapeString vectors "
          f"passed in {time.monotonic() - started:.3f}s")


if __name__ == "__main__":
    main()
