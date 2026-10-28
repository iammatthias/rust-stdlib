#!/usr/bin/env python3
"""Live net/rpc interop with Go over loopback: a Go client against a Rust
server and a Rust client against a Go server, for the gob, JSON-RPC and
HTTP-CONNECT transports. Each client runs the same scenario (calls, server
errors, unknown methods, a connection that survives errors, concurrent and
asynchronous calls, Close and shutdown); the two clients' outputs must be
identical, and the /debug/rpc page of the Rust server must equal Go's."""
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
RUST_BIN = ROOT / "tools/derive-check/target/debug/examples/rpc_probe"
GO_SRC = "tools/rpc_interop.go"


def build():
    subprocess.run(["cargo", "build", "--quiet", "--offline", "--locked", "--manifest-path",
                    "tools/derive-check/Cargo.toml", "--example", "rpc_probe"], cwd=ROOT, check=True)
    subprocess.run(["go", "build", "-o", str(GO_BIN), GO_SRC], cwd=ROOT, check=True)


GO_BIN = pathlib.Path("/tmp") / f"rpc_interop_go_{__import__('os').getpid()}"


def start_server(cmd):
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, cwd=ROOT)
    line = p.stdout.readline()
    if not line.startswith("PORT "):
        p.kill()
        raise RuntimeError(f"server did not start: {line!r}")
    return p, line.split()[1]


def run_client(cmd):
    res = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, timeout=60)
    if res.returncode:
        raise RuntimeError(f"{cmd} failed:\n{res.stdout}\n{res.stderr[-2000:]}")
    return res.stdout


def scenario(server_cmd, client_cmd_fn):
    p, port = start_server(server_cmd)
    try:
        return run_client(client_cmd_fn(port)), port, p
    finally:
        pass


def add(a, b):
    return '{"method":"Arith.Add","params":[{"A":%s,"B":%s}],"id":1}' % (a, b)


class _Rich:
    """Echo vectors: Rust cannot hold a nil map or slice, so B and M are always sent."""

    def __mod__(self, body):
        if '"B"' not in body and '"M"' not in body:
            body = '{"B":"","M":{},' + body[1:]
        return '{"method":"Arith.Echo","params":[%s],"id":7}' % body


RICH = _Rich()


def post(body, seq):
    """Ledger.Post with custom JSON methods; List, Map and Sealed are always sent (Rust has no nil slice or map)."""
    return '{"method":"Ledger.Post","params":[%s],"id":%d}' % (body, seq)


def labels(body, seq):
    """Ledger.Labels with TextMarshaler values and keys; every field is sent unless the vector is an error."""
    return '{"method":"Ledger.Labels","params":[{%s}],"id":%d}' % (body, seq)


def torns(body, seq):
    return '{"method":"Ledger.Torns","params":[{%s}],"id":%d}' % (body, seq)


def ledger(method, body, seq):
    return '{"method":"Ledger.%s","params":[{%s}],"id":%d}' % (method, body, seq)


OCTETS = {"A": "[]", "B": "[]", "C": "[]", "D": "[]", "E": "[]", "F": "[]", "G": "[0,0]", "H": "[0,0]"}


def octets(seq, **over):
    f = dict(OCTETS, **over)
    return ledger("Octets", ",".join('"%s":%s' % kv for kv in f.items()), seq)


QUOTED = {"A": '"r:x"', "B": '"tier-1"', "C": '"tier-2"', "D": '["tier-3"]', "F": '"5"', "G": "[1]", "H": '"code-4"'}


def quoted(seq, **over):
    f = dict(QUOTED, **over)
    return ledger("Quoted", ",".join('"%s":%s' % kv for kv in f.items()), seq)


LABELS_OK = ('"Tier":"tier-2","TierPtr":"tier-3","Tiers":["tier-0","tier-1"],'
             '"ByTier":{"tier-3":"three","tier-1":"one<&>"},"ByRegion":{"r:north":1,"r:south":2},'
             '"Code":"code-4","Codes":["code-5"],"Mixed":[{"N":7}],"MixedMap":{}')


RAW = [
    add(1, 2), add(-5, 3), add(0, 0), add(1.5, 2), add('"x"', 1), add(1e30, 1), add(9223372036854775807, 1),
    add(9223372036854775807, 9223372036854775807),
    '{"method":"Arith.Add","params":[{"a":1,"b":2}],"id":2}',
    '{"method":"Arith.Add","params":[{"A":1,"A":5,"B":2}],"id":2}',
    '{"method":"Arith.Add","params":[{"A":1,"B":2,"Z":9}],"id":"abc"}',
    '{"method":"Arith.Add","params":[{"A":1,"B":2}],"id":null}',
    '{"method":"Arith.Add","params":[{"A":1,"B":2}]}',
    '{"method":"Arith.Add","params":[{"A":1,"B":2}],"id":{"k":[1, 2]}}',
    '{"method":"Arith.Add","params":[{"A":1,"B":2}],"id":1.50}',
    '{"method":"Arith.Add","params":[{"A":1,"B":2}],"id":"<&>"}',
    '{ "method" : "Arith.Add" , "params" : [ { "A" : 1 , "B" : 2 } ] , "id" : 3 }',
    '{"Method":"Arith.Add","Params":[{"A":1,"B":2}],"ID":4}',
    '{"method":"Arith.Add","params":[{"A":1,"B":2},{"A":9}],"id":5}',
    '{"method":"Arith.Add","params":[],"id":6}',
    '{"method":"Arith.Add","id":6}',
    '{"method":"Arith.Add","params":null,"id":6}',
    '{"method":"Arith.Add","params":{"A":1},"id":6}',
    '{"method":"Arith.Add","params":"s","id":6}',
    '{"method":"Arith.Add","params":[null],"id":6}',
    '{"method":"Arith.Add","params":[[1,2]],"id":6}',
    '{"method":"Arith.Add","params":[5],"id":6}',
    '{"method":"Arith.Unknown","params":[{}],"id":8}',
    '{"method":"Nope.Add","params":[{}],"id":8}',
    '{"method":"Add","params":[{}],"id":8}',
    '{"method":"","params":[{}],"id":8}',
    '{"method":5,"params":[{}],"id":8}',
    '{"params":[{}],"id":8}',
    '{"method":"Arith.Div","params":[{"A":7,"B":2}],"id":9}',
    '{"method":"Arith.Div","params":[{"A":7,"B":0}],"id":9}',
    '{"method":"Arith.Error","params":[{}],"id":9}',
    '{"method":"Arith.Names","params":[{}],"id":9}',
    '[1,2]', '5', '"s"', 'null', 'true', '{}', '{"id":3}',
    RICH % '{"s":"a<b>&c","F":0.1,"B":"AQID","M":{"b":2,"a":1},"P":5,"l":["x","y"],"N":-3,"In":{"X":4},"Any":{"k":[1,"two",null,true],"f":1e21}}',
    RICH % '{"s":"\\u00e9\\u2028\\ud83d\\ude00\\n\\t\\u0001","F":1e21,"B":"","M":{},"P":null,"l":[],"N":127,"In":{},"Any":null}',
    RICH % '{"s":"","F":1e-7,"B":"AA==","M":{"1":1},"N":128}',
    RICH % '{"F":"x"}', RICH % '{"B":"!!"}', RICH % '{"M":{"a":"b"}}', RICH % '{"In":5}', RICH % '{"Any":[1.5,2,{"z":false}]}',
    RICH % '{"F":123456789012345680000,"N":0,"s":"x"}', RICH % '{"F":-0.0}', RICH % '{"F":5e-324}',
    RICH % '{"S":"case","f":2.5,"b":"Zm9v"}',
    # Custom JSON methods: value and pointer receivers, raw text, compaction,
    # HTML escaping, method errors that end the decode, and nil pointers.
    post('{"Amount":"$1.50","Ptr":"$2.05","List":["$0.01","$10.00"],"Map":{"a":"$3.00"},"Raw":{"x": [1, 2]},"Stamp":"stamp-4","Hidden":"stamp-9","Sealed":{"k":{"N":3}}}', 1),
    post('{"Amount":"$0.00","List":[],"Map":{},"Sealed":{},"Raw":"<a&b>\\u2028 é"}', 2),
    post('{"Amount":"1.50","List":[],"Map":{},"Sealed":{}}', 3),
    post('{"Amount":null,"List":[],"Map":{},"Sealed":{}}', 4),
    post('{"Amount":"$0.01","Ptr":null,"List":["$1.00",5],"Map":{},"Sealed":{}}', 5),
    post('{"Amount":"$0.01","List":[],"Map":{"z":"$0.02"},"Hidden":"stamp-x","Sealed":{}}', 6),
    post('{"Amount":"$0.01","Stamp":null,"List":[],"Map":{},"Sealed":{},"Unknown":[1]}', 7),
    post('{"Amount":"$1.00","List":[],"Map":{"a":"$1.00","b":"oops"},"Sealed":{}}', 8),
    post('{"Amount":"$0.05","List":[],"Map":{},"Sealed":{},"Raw":null}', 9),
    post('{"Amount":"$0.05","List":[],"Map":{},"Sealed":{},"Raw":[ true , {"k" : "v\\u003c"} ]}', 10),
    '{"method":"Arith.Add","params":[{"A":1,"B":2}],"id":1}\n{"method":"Arith.Mul","params":[{"A":3,"B":4}],"id":2}',
    '{"method":"Arith.Add","params":[{"A":1,"B":2}],"id":1}{"method":"Arith.Mul","params":[{"A":3,"B":4}],"id":2}',
    '{"method":', 'xyz', '{"method":"Arith.Add","params":[{"A":1,"B":2}],"id":1', '{"method":"Arith.Add",}',
    # TextMarshaler and TextUnmarshaler: values, pointers, slice elements, map keys and values,
    # null, wrong JSON kinds, the first error kept, MarshalText errors and HTML escaping.
    labels(LABELS_OK, 1),
    labels('"Tier":null,"TierPtr":null,"Tiers":[],"ByTier":{},"ByRegion":{},"Code":"code-0","Codes":[],'
           '"Mixed":[],"MixedMap":{"m":{"N":2}}', 2),
    labels('"Tier":null,"TierPtr":"tier-1","Tiers":["tier-3"],"ByTier":{"tier-0":""},"ByRegion":{"r:":0},'
           '"Code":null,"Codes":[null],"Mixed":[{"N":-3}],"MixedMap":{"z":{}}', 3),
    labels(LABELS_OK.replace('"tier-2"', '"tier-9"'), 4),
    labels('"Tier":5,"Code":"bad"', 5),
    labels('"Tiers":["tier-1",[2]]', 6),
    labels('"ByRegion":{"north":1}', 7),
    labels('"ByTier":{"tier-7":"x"}', 8),
    labels('"Code":{"N":1}', 9),
    labels('"Tier":true', 10),
    labels('"Codes":["code-x"]', 11),
    labels('"Tier":"tier-1","ByRegion":{"r:a":1,"north":2}', 12),
    torns('"One":"torn-1","Keys":{"torn-2":3}', 1),
    torns('"One":"torn-x","Keys":{}', 2),
    torns('"One":"torn-1","Keys":{"torn--1":3}', 3),
    torns('"One":"torn--2","Keys":{}', 4),
    # A map key whose pointer alone has MarshalText: the reply fails with jsontext's error
    # (offset and path), unless the map is empty.
    ledger("PKeys", '"Pad":1,"M":{"pk-1":2},"Deep":[]', 1),
    ledger("PKeys", '"Pad":1,"M":{},"Deep":[]', 2),
    ledger("PKeys", '"M":{},"Deep":[{"M":{}},{"M":{"pk-3":1}}]', 3),
    ledger("PKeys", '"M":{"pk-x":1},"Deep":[]', 4),
    ledger("PKeys", '"M":{"pk-2":1,"pk-1":5},"Deep":[]', 5),
    # A map key is read through UnmarshalText with the unquoted name, never UnmarshalJSON.
    ledger("JKeys", '"M":{"a\\u0041":1,"\\/x":2,"q\\"":3}', 1),
    ledger("JKeys", '"M":{"k":3}', 2),
    ledger("JKeys", '"M":{"\\u00e9\\ud83d\\ude00":4}', 3),
    # Slices and arrays of byte kinds: a string is base64 whatever the methods, an array calls the element methods.
    octets(1, A='"AQID"', B='"AQID"', C='"AQID"', D='"AQID"', E='"AQID"', F='"AQID"'),
    octets(2, A="[1,2]", B="[1,2]", C="[1,2]", D="[1,2]", E="[1,2]", F="[1,2]"),
    octets(3, E="[1,22,333]"),
    octets(4, F="[1,2]"),
    octets(5, F='["ab","cde"]'),
    octets(6, G="[3,4]", H="[5,6]"),
    octets(7, H='["x","yy"]'),
    octets(8, G='"AQI="'),
    octets(9, H='"AQI="'),
    octets(10, A='"!!"', E='"!!"'),
    octets(11, A="null", E="null", F="null"),
    # The ,string option does not apply to a field read or written through a method.
    quoted(1),
    quoted(2, A='"\\"x\\""'),
    quoted(3, B='"\\"tier-1\\""'),
    quoted(4, C='"null"'),
    quoted(5, C="null"),
    quoted(6, F="5"),
    quoted(7, F='"x"'),
    quoted(8, G='["1"]'),
    quoted(9, H='"code-x"'),
    quoted(10, H='"\\"code-1\\""'),
    quoted(11, D='["tier-9"]'),
    # The first saved error is reported: a type error before a method error, and a method error before a type error.
    post('{"List":{},"Amount":"1.50"}', 11),
    post('{"Amount":"1.50","List":{}}', 12),
]


def raw_exchange(port, payload):
    """Send one payload, half-close, and read until the server closes. Go's
    ServeCodec stops reading at end of input, waits for the calls in flight,
    then closes, so the reply set is complete without a timing window."""
    import socket
    s = socket.create_connection(("127.0.0.1", int(port)), timeout=30)
    s.sendall(payload.encode() + b"\n")
    s.shutdown(socket.SHUT_WR)
    data = b""
    while chunk := s.recv(65536):
        data += chunk
    s.close()
    return data


def raw_vectors():
    go = [str(GO_BIN)]
    rust = [str(RUST_BIN)]
    answers = {}
    for name, binary in (("go", go), ("rust", rust)):
        p, port = start_server(binary + ["server", "json"])
        try:
            answers[name] = [raw_exchange(port, v) for v in RAW]
        finally:
            p.stdin.close()
            p.wait(timeout=10)
    def norm(b):
        # Pipelined requests are answered as the calls finish, in any order.
        return sorted(b.split(b"\n"))

    bad = [i for i in range(len(RAW)) if norm(answers["go"][i]) != norm(answers["rust"][i])]
    for i in bad[:8]:
        print(f"MISMATCH {RAW[i][:200]}\n  go:   {answers['go'][i][:300]!r}\n  rust: {answers['rust'][i][:300]!r}")
    if bad:
        raise SystemExit(f"{len(bad)} of {len(RAW)} JSON-RPC wire vectors differ")
    return len(RAW)


def main():
    build()
    rust = [str(RUST_BIN)]
    go = [str(GO_BIN)]
    lines = 0
    try:
        for mode in ("gob", "json", "http"):
            outs = {}
            for server_name, server_bin, client_name, client_bin in (
                    ("go", go, "rust", rust), ("rust", rust, "go", go),
                    ("go", go, "go", go), ("rust", rust, "rust", rust)):
                p, port = start_server(server_bin + ["server", mode])
                try:
                    out = run_client(client_bin + ["client", mode, port])
                    if mode == "http":
                        dbg = run_client(go + ["debug", port])
                        outs[(server_name, client_name, "debug")] = dbg
                finally:
                    p.stdin.close()
                    p.wait(timeout=10)
                outs[(server_name, client_name)] = out
            base = outs[("go", "go")]
            if "ok" not in base:
                raise SystemExit(f"[{mode}] the Go/Go scenario produced no results:\n{base}")
            for k, v in outs.items():
                if len(k) == 2 and v != base:
                    raise SystemExit(f"[{mode}] client {k[1]} against server {k[0]} differs from Go/Go:\n"
                                     f"--- go/go\n{base}\n--- {k}\n{v}")
                lines += len(v.splitlines()) if len(k) == 2 else 0
            if mode == "http":
                a, b = outs[("go", "go", "debug")], outs[("rust", "go", "debug")]
                if a != b:
                    raise SystemExit(f"/debug/rpc differs:\n--- go\n{a!r}\n--- rust\n{b!r}")
        nraw = raw_vectors()
    finally:
        GO_BIN.unlink(missing_ok=True)
    print(f"rpc interop: 12 client/server runs over gob, json and http match Go ({lines} result lines); "
          f"{nraw} raw JSON-RPC server exchanges match byte for byte")


if __name__ == "__main__":
    main()
