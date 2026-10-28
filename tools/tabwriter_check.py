#!/usr/bin/env python3
"""Differentially compare tabwriter formatting against Go's standard library."""
import os, pathlib, random, subprocess
ROOT=pathlib.Path(__file__).resolve().parents[1]

def main():
    rng=random.Random(240513)
    cases=[]
    samples=[b"",b"\xff\xff",b"\xff\t\xff",b"\xff\"foo\t\n\tbar\"\xff",b"abc\xff\tdef",b"\n\n\n",b"a\nb\nc",b"\t",b"*\t*",b"*\t*\n",b"*\t*\t",b"\t\n",b"a) foo",b"b) foo\tbar",b"c) foo\tbar\t\n",b"<b>a</b>\t&amp;\n",b"a\vb\nlong\vc\n",b"a\vb\fend",b"a\tb\nlong\tx\n",b"\t\t\t\n","界\tx\nxx\ty\n".encode(),b"e\xcc\x81\tx\nxx\ty\n",b"a\xffx\ty\xff\tz\n"]
    for data in samples:
        for flags in range(64):
            for padchar in [ord('.'),ord(' '),ord('\t')]: cases.append((1,4,1,padchar,flags,data))
    for _ in range(500):
        rows=[]
        for _ in range(rng.randrange(1,8)):
            cells=[rng.choice([b"",b"a",b"long",b"\xe7\x95\x8c",b"e\xcc\x81",b"<b>x</b>",b"&amp;",b"\xffx",b"  "]) for _ in range(rng.randrange(1,5))]
            sep=rng.choice([b"\t",b"\v"]);rows.append(sep.join(cells)+rng.choice([b"",b"\t",b"\v"])+rng.choice([b"\n",b"\f",b""]))
        data=b"".join(rows);cases.append((rng.randrange(0,4),rng.choice([0,2,4]),rng.randrange(0,3),rng.choice([ord('.'),ord(' '),ord('\t')]),rng.randrange(64),data))
    # Init on a reused writer: unflushed stale text must be discarded by the reinitialization.
    for _ in range(300):
        stale=rng.choice(samples)+rng.choice([b"",b"stale\tcell\n",b"x\x0bpending"])
        data=rng.choice(samples)+rng.choice([b"",b"a\tb\nlong\tx\n",b"\x0cq\tr"])
        cases.append((rng.randrange(0,4),rng.choice([0,2,4]),rng.randrange(0,3),rng.choice([ord('.'),ord(' '),ord('\t')]),rng.randrange(64),data,stale))
    def request(case):
        a,b,c,d,f,data,*reuse=case
        text=f"{a} {b} {c} {d:02x} {f} {data.hex() or '-'}"
        if reuse:
            text+=f" {reuse[0].hex() or '-'}"
        return text+"\n"
    payload="".join(request(case) for case in cases)
    env=os.environ.copy();subprocess.run(["cargo","build","--offline","--locked","--example","tabwriter_probe"],cwd=ROOT,env=env,check=True)
    exe=ROOT/"target"/"debug"/"examples"/("tabwriter_probe.exe" if os.name=="nt" else "tabwriter_probe")
    outputs=[]
    for cmd in [[str(exe)],["go","run",str(ROOT/"tools"/"tabwriter_oracle.go")]]:
        p=subprocess.run(cmd,input=payload,text=True,capture_output=True,cwd=ROOT,env=env,check=True);outputs.append(p.stdout.splitlines())
    if any(len(o)!=len(cases) for o in outputs):raise AssertionError(f"oracle row count {list(map(len,outputs))}, expected {len(cases)}")
    for i,(rust,go) in enumerate(zip(*outputs)):
        if rust!=go:raise AssertionError(f"case {i}: config/data={cases[i]!r}\nRust={rust}\nGo={go}")
    print(f"Tabwriter Go conformance: {len(cases)} cases passed")

if __name__=="__main__":main()
