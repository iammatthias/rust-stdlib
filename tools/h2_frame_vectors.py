"""Frame vector generation for tools/h2_check.py."""


def hx(b):
    return b.hex()


def frame_bytes(ftype, flags, stream, payload, length=None):
    n = len(payload) if length is None else length
    return bytes([n >> 16 & 255, n >> 8 & 255, n & 255, ftype, flags]) + (stream & 0xFFFFFFFF).to_bytes(4, "big") + payload


def request_ops(rng, n_regular=None):
    """Header ops for a request-like block, with occasional protocol violations."""
    ops = []
    pseudo = [(":method", rng.choice(["GET", "POST", "PUT"])), (":scheme", "https"),
              (":authority", "example.com"), (":path", "/" + "x" * rng.randrange(0, 20))]
    rng.shuffle(pseudo)
    k = rng.random()
    if k < 0.04:
        pseudo.append((":bogus", "1"))
    elif k < 0.08:
        pseudo.append(pseudo[0])
    elif k < 0.11:
        pseudo.append((":status", "200"))
    for n, v in pseudo:
        ops.append("f%s/%s/0" % (hx(n.encode()), hx(v.encode())))
    for _ in range(rng.randrange(0, 8) if n_regular is None else n_regular):
        name = rng.choice(["accept", "user-agent", "x-a", "x-b", "cookie", "priority", "via"]).encode()
        value = rng.choice([b"u=1", b"i", b"u=7, i", b"v", b"text/html", b"a" * rng.randrange(0, 300)])
        if rng.random() < 0.03:
            name = name.upper()
        if rng.random() < 0.03:
            value = value + b"\x01"
        if rng.random() < 0.02:
            name = b"bad name"
        ops.append("f%s/%s/%d" % (hx(name), hx(value), rng.random() < 0.1))
        if rng.random() < 0.03:
            ops.append("f%s/%s/0" % (hx(b":late"), hx(b"1")))
    return ",".join(ops)


def gen_frame(rng, blocks):
    """One random frame (valid most of the time)."""
    t = rng.choice([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x10, 0x20, 0xfa])
    stream = rng.choice([0, 1, 3, 5, 7, 2**31 - 1, 2**31, 2**32 - 1, rng.randrange(1, 100)])
    if rng.random() < 0.7:
        stream = rng.choice([1, 3, 5, 7, 9]) if t not in (4, 6, 7, 0x10) else 0
    flags = rng.choice([0, 1, 4, 5, 8, 0x20, 0x25, 0x2d, 0xff, rng.randrange(256)])
    pad = bytes(rng.randrange(256) for _ in range(rng.choice([0, 0, 1, 3, 20])))
    sid = rng.randrange(0, 2**32)
    if t == 0:
        data = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 40)))
        payload = (bytes([len(pad)]) + data + pad) if flags & 8 else data
        if rng.random() < 0.1:
            payload = payload[:rng.randrange(len(payload) + 1)]
    elif t == 1:
        blk = bytes.fromhex(rng.choice(blocks)) if rng.random() < 0.85 else bytes(rng.randrange(256) for _ in range(rng.randrange(0, 30)))
        payload = (bytes([len(pad)]) if flags & 8 else b"") + ((sid.to_bytes(4, "big") + bytes([rng.randrange(256)])) if flags & 0x20 else b"") + blk + (pad if flags & 8 else b"")
        if rng.random() < 0.08:
            payload = payload[:rng.randrange(len(payload) + 1)]
    elif t == 2:
        payload = sid.to_bytes(4, "big") + bytes([rng.randrange(256)])
        if rng.random() < 0.1:
            payload = payload[:rng.randrange(7)]
    elif t == 3:
        payload = rng.randrange(0, 20).to_bytes(4, "big")
        if rng.random() < 0.1:
            payload = payload[:rng.randrange(6)]
    elif t == 4:
        payload = b"".join(rng.choice([1, 2, 3, 4, 5, 6, 8, 9, 99]).to_bytes(2, "big") + rng.choice([0, 1, 2, 100, 16384, 2**24, 2**31 - 1, 2**31, 2**32 - 1]).to_bytes(4, "big") for _ in range(rng.randrange(0, 4)))
        if rng.random() < 0.06:
            payload = payload + b"\x01"
        if rng.random() < 0.05:
            flags = 1
    elif t == 5:
        blk = bytes.fromhex(rng.choice(blocks))
        payload = (bytes([len(pad)]) if flags & 8 else b"") + sid.to_bytes(4, "big") + blk + (pad if flags & 8 else b"")
        if rng.random() < 0.08:
            payload = payload[:rng.randrange(len(payload) + 1)]
    elif t == 6:
        payload = bytes(rng.randrange(256) for _ in range(8 if rng.random() < 0.9 else rng.randrange(0, 12)))
    elif t == 7:
        payload = sid.to_bytes(4, "big") + rng.randrange(0, 16).to_bytes(4, "big") + bytes(rng.randrange(256) for _ in range(rng.randrange(0, 12)))
        if rng.random() < 0.08:
            payload = payload[:rng.randrange(8)]
    elif t == 8:
        payload = rng.choice([0, 1, 100, 2**31 - 1, 2**31, 2**32 - 1]).to_bytes(4, "big")
        if rng.random() < 0.08:
            payload = payload[:rng.randrange(5)]
    elif t == 9:
        payload = bytes.fromhex(rng.choice(blocks))
    elif t == 0x10:
        sid2 = rng.choice([0, 1, 3, 2**31, 2**31 + 3])
        body = rng.choice([b"u=1", b"u=0, i", b"i", b"u=9", b"u=3;x", b"", b"garbage!", b'u="a"', b"u=1,"])
        payload = sid2.to_bytes(4, "big") + body
        if rng.random() < 0.08:
            payload = payload[:rng.randrange(5)]
    else:
        payload = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 20)))
    return frame_bytes(t, flags, stream, payload)


def split_headers(rng, stream, blk, end_stream=False):
    """HEADERS + CONTINUATION frames carrying one block."""
    cuts = sorted(rng.sample(range(len(blk) + 1), min(len(blk) + 1, rng.randrange(1, 4)))) if blk else [0]
    parts, last = [], 0
    for c in cuts + [len(blk)]:
        parts.append(blk[last:c])
        last = c
    parts = [p for i, p in enumerate(parts) if p or i == 0]
    out = b""
    for i, part in enumerate(parts):
        end_h = 4 if i == len(parts) - 1 else 0
        if i == 0:
            out += frame_bytes(1, end_h | (1 if end_stream else 0), stream, part)
        else:
            out += frame_bytes(9, end_h, stream, part)
    return out


def write_ops(rng):
    ops = []
    for _ in range(rng.randrange(1, 5)):
        sid_ = rng.choice([0, 1, 3, 2**31 - 1, 2**31, 2**32 - 1])
        if rng.random() < 0.7:
            sid_ = rng.choice([1, 3, 5])
        data = hx(bytes(rng.randrange(256) for _ in range(rng.randrange(0, 12))))
        pad = rng.choice(["n", "", hx(b"\x00" * 3), hx(b"\x00" * 255), hx(b"\x00" * 256), hx(b"\x01\x00")])
        kind = rng.choice(["data", "settings", "settingsack", "ping", "goaway", "wu", "headers", "priority",
                           "pu", "rst", "cont", "pp", "raw"])
        if kind == "data":
            ops.append("data,%d,%d,%s,%s" % (sid_, rng.randrange(2), data, pad))
        elif kind == "settings":
            ops.append("settings," + ",".join("%d=%d" % (rng.choice([1, 2, 3, 4, 5, 6, 8, 9, 99]), rng.choice([0, 1, 65535, 2**31, 2**32 - 1])) for _ in range(rng.randrange(0, 4))))
        elif kind == "settingsack":
            ops.append("settingsack")
        elif kind == "ping":
            ops.append("ping,%d,%s" % (rng.randrange(2), hx(bytes(rng.randrange(256) for _ in range(8)))))
        elif kind == "goaway":
            ops.append("goaway,%d,%d,%s" % (rng.choice([0, 7, 2**31, 2**32 - 1]), rng.randrange(0, 20), data))
        elif kind == "wu":
            ops.append("wu,%d,%d" % (rng.choice([0, 1, 3, 2**31]), rng.choice([0, 1, 100, 2**31 - 1, 2**31, 2**32 - 1])))
        elif kind == "headers":
            ops.append("headers,%d,%d,%d,%d,%d,%d,%d,%s" % (sid_, rng.randrange(2), rng.randrange(2), rng.choice([0, 0, 1, 7, 255]), rng.choice([0, 0, 3, 2**31 - 1, 2**31]), rng.randrange(2), rng.choice([0, 15, 255]), data))
        elif kind == "priority":
            ops.append("priority,%d,%d,%d,%d" % (sid_, rng.choice([0, 3, 2**31]), rng.randrange(2), rng.randrange(256)))
        elif kind == "pu":
            ops.append("pu,%d,%s" % (sid_, hx(rng.choice([b"u=1", b"", b"i"]))))
        elif kind == "rst":
            ops.append("rst,%d,%d" % (sid_, rng.randrange(0, 15)))
        elif kind == "cont":
            ops.append("cont,%d,%d,%s" % (sid_, rng.randrange(2), data))
        elif kind == "pp":
            ops.append("pp,%d,%d,%d,%d,%s" % (sid_, rng.choice([0, 2, 4, 2**31]), rng.randrange(2), rng.choice([0, 0, 5]), data))
        else:
            ops.append("raw,%d,%d,%d,%s" % (rng.choice([0, 1, 0x10, 0x20, 200]), rng.randrange(256), sid_, data))
    return ";".join(ops)


def frames(h, rng):
    ops = ["E:" + request_ops(rng) for _ in range(1500)]
    ops += ["E:" + request_ops(rng) + ";" + request_ops(rng) for _ in range(300)]
    blocks = [b for line in h.compare("frame-blocks", ops) for b in line.split(";")]
    reqs = []
    cfgs = ["16384,0,0,0,0", "16384,1,0,0,0", "1048576,1,0,0,0", "100,0,0,0,0", "16384,1,200,0,0",
            "16384,1,2000,3,0", "16384,0,0,0,1", "1048576,1,64,0,0"]
    for _ in range(4000):
        stream = b"".join(gen_frame(rng, blocks) for _ in range(rng.randrange(1, 6)))
        reqs.append("R%s:%s" % (rng.choice(cfgs), hx(stream)))
    for _ in range(2500):
        blk = bytes.fromhex(rng.choice(blocks))
        data = split_headers(rng, rng.choice([1, 3, 5]), blk, rng.random() < 0.3)
        if rng.random() < 0.3:
            data += gen_frame(rng, blocks)
        if rng.random() < 0.15:
            data = data[:rng.randrange(len(data) + 1)]
        elif rng.random() < 0.1:
            b = bytearray(data)
            b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
            data = bytes(b)
        reqs.append("R%s:%s" % (rng.choice(cfgs), hx(data)))
    http1 = b"HTTP/1.1 200 OK\r\n\r\n"
    reqs.append("R16384,0,0,0,0:" + hx(http1))
    reqs.append("R16384,0,0,0,0:" + hx(http1[:12]))
    reqs.append("R16384,0,0,0,0:" + hx(b"HTTP/1.1 "))
    for n in range(0, 10):
        reqs.append("R16384,0,0,0,0:" + hx(frame_bytes(0, 0, 1, b"")[:n]))
    h.compare("frame-read", reqs)

    w = ["W%d:%s" % (rng.randrange(2), write_ops(rng)) for _ in range(3000)]
    h.compare("frame-write", w)

    atoms = ["u=0", "u=7", "u=8", "u=-1", "u=3.5", "u=a", "i", "i=?0", "i=?1", "i=1", "x=(a b)", "x=(a b);p=1",
             "u=3;k", "k=:YWJj:", 'k="s"', 'k=%"\xc3\xa9"', "k=@123", "K=1", "*a=1", "u=1,", ",", " u=2", "u=2 ,i"]
    q = []
    for _ in range(2500):
        text = rng.choice([", ", ",", " , ", "  "]).join(rng.choice(atoms) for _ in range(rng.randrange(0, 5)))
        if rng.random() < 0.1:
            text += chr(rng.randrange(1, 127))
        q.append("Q:%s,%d" % (hx(text.encode("latin-1")), rng.randrange(2)))
    h.compare("priority-parse", q)
