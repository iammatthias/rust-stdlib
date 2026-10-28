#!/usr/bin/env python3
"""Regenerates tests/fixtures/jsonv2_golden.txt: request/response pairs
recorded from the Go oracle (tools/jsonv2_oracle.go) for
tools/derive-check/tests/jsonv2.rs.

Each line is `<request>\\t<response>` in the protocol of tools/jsonv2_check.py.
Run it after changing the corpus; the file is committed so the Rust tests do
not need Go."""
import pathlib
import random
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import jsonv2_check as jc  # noqa: E402

OUT = ROOT / "tests/fixtures/jsonv2_golden.txt"


def main():
    rng = random.Random(0x474F4C44)
    with tempfile.TemporaryDirectory() as tmp:
        go = jc.build_go(tmp)
        reqs = jc.marshal_requests(go, rng, 6) + jc.unmarshal_requests(go, rng, 4)
        responses = jc.run(go, "".join(r + "\n" for r in reqs), "Go jsonv2 oracle")
    assert len(responses) == len(reqs)
    OUT.write_text("".join(f"{q}\t{r}\n" for q, r in zip(reqs, responses)))
    print(f"wrote {len(reqs)} vectors to {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
