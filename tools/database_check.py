#!/usr/bin/env python3
"""Differentially check database/sql against Go.

Three request kinds go to both examples/database_probe.rs and
tools/database_oracle.go (which drives Go's real database/sql):

* ``C`` Scan conversions: every (driver value, destination type) pair through
  ``sql.ConvertAssign`` / ``Scanner::scan``, comparing the resulting value and
  the exact error text, including the destination after a failed conversion.
* ``V`` driver value converters (``DefaultParameterConverter``, ``Bool``,
  ``Int32``, ``String``, ``Null``, ``NotNull``, ``IsValue``) over every
  argument kind.
* ``BEGIN``..``END`` scripts: random pool, connection, transaction, statement
  and rows sequences against the fake driver of Go's ``fakedb_test.go``
  (ported identically to ``examples/common/fakedb.rs`` and
  ``tools/database_fakedb.go``), comparing every result, error text and
  ``DB.Stats`` snapshot.
"""
import concurrent.futures
import pathlib
import random
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = 320
OPS_PER_SCRIPT = 45


def hx(text):
    data = text if isinstance(text, bytes) else text.encode()
    return data.hex()


# ------------------------------------------------------------ conversions

INTS = [0, 1, -1, 2, 5, 10, 42, 100, 127, 128, -128, -129, 255, 256, 32767, 32768,
        -32768, -32769, 65535, 65536, 2147483647, 2147483648, -2147483648,
        -2147483649, 4294967295, 4294967296, 9223372036854775807,
        -9223372036854775808, 12345678901]
FLOATS = ["0", "-0", "0.5", "1.0", "3.0", "-3.0", "1.5", "-1.5", "16777217", "1e21",
          "1e20", "1e-7", "1e308", "3.4e38", "3.5e38", "1.5e39", "NaN", "+Inf", "-Inf",
          "123456.789", "255.0", "256.0", "9007199254740993", "1e6", "1e5", "0.1",
          "4294967295.0", "-9223372036854775808.0", "9223372036854775807.0",
          "1.7976931348623157e308", "5e-324"]
TEXTS = ["", "0", "1", "-1", "+1", " 1", "1 ", "1_000", "0x10", "1e3", "-0", "NaN",
         "inf", "Inf", "+Inf", "true", "T", "t", "TRUE", "True", "yes", "false", "f",
         "F", "FALSE", "False", "hello", "héllo", "2020-01-02T03:04:05Z", "3.14",
         "-3.14", "1e400", "255", "256", "-129", "-128", "127", "128", "65535", "65536",
         "9223372036854775807", "9223372036854775808", "-9223372036854775808",
         "-9223372036854775809", "18446744073709551615", "18446744073709551616",
         "00012", "٣", "0b11", "0o7", ".5", "5.", "1.0", "1e", " ", "3.4e38",
         "3.5e38", "1.5", "0.0", "-0.0", "12abc", "é", "\U0001f600", "a\"b", "a\\b",
         "tab\there", "nl\nx", "\x00"]
BAD_BYTES = [b"\xff\xfe", b"12\xff", b"\xc3", b"\x80"]
TIMES = ["zero", "0:0:0", "1700000000:123456789:0", "1700000000:0:3600",
         "1700000000:500000000:-18000", "253402300799:999999999:0", "-1:0:0",
         "1700000000:100:-3600", "1577836800:0:19800"]


def sources():
    out = ["nil", "B:true", "B:false"]
    out += [f"i:{n}" for n in INTS]
    out += [f"f:{x}" for x in FLOATS]
    out += [f"s:{hx(t)}" for t in TEXTS]
    out += [f"b:{hx(t)}" for t in TEXTS]
    out += [f"b:{hx(t)}" for t in BAD_BYTES]
    out += [f"t:{t}" for t in TIMES]
    return out


DESTS = ["string", "bytes", "raw", "bool", "any", "time", "i8", "i16", "i32", "i64",
         "int", "u8", "u16", "u32", "u64", "uint", "f32", "f64", "ns", "ni64", "ni32",
         "ni16", "nbyte", "nf64", "nbool", "ntime", "p:i64", "p:string", "p:bytes",
         "p:time", "p:bool", "p:f64", "p:ns", "N:i64", "N:string", "N:bytes", "N:time",
         "N:bool", "N:f64", "N:u8", "N:any"]
STRING_DESTS = {"string", "ns", "p:string", "p:ns", "N:string"}

# Decimals as form:negative:coefficient-hex:exponent. Go's errors for a
# decimal source name the application's own type (%T), which a Rust Decimal
# cannot know, so these only meet destinations whose result has no type name:
# every one into a decimal, *any and floats, the exponent-0 ones into ints.
FLOAT_DECIMALS = ["0:false::0", "0:true::0", "0:false:07:0", "0:true:0100:-2",
                  "0:false:0f:-1", "0:false:01:-7", "0:false:3039:3", "0:true:3039:-10",
                  "0:false:ffffffffffffffffff:0", "0:false:0100:5", "1:false::0",
                  "1:true::0", "2:false::0"]
INT_DECIMALS = ["0:false::0", "0:false:07:0", "0:true:7fffffff:0", "0:false:ff:0"]


def convert_requests():
    reqs = []
    for src in sources():
        invalid_utf8 = src.startswith("b:") and bytes.fromhex(src[2:]) in BAD_BYTES
        for dest in DESTS:
            if invalid_utf8 and dest in STRING_DESTS:
                continue  # Go strings may hold any bytes; Rust's must be UTF-8.
            reqs.append(f"C {src} {dest}")
    for dec in FLOAT_DECIMALS:
        for dest in ["dec", "any", "N:any", "f64", "f32", "nf64", "N:f64"]:
            reqs.append(f"C d:{dec} {dest}")
    for dec in INT_DECIMALS:
        for dest in ["i64", "ni64", "N:i64", "i32"]:
            reqs.append(f"C d:{dec} {dest}")
    return reqs


ARGS = ["nil", "bool:true", "bool:false", "int:5", "int:-1", "int:2", "i8:-5", "i8:1",
        "i16:300", "i32:2147483647", "i32:-2147483648", "i64:9223372036854775807",
        "i64:-2147483649", "i64:0", "uint:5", "uint:18446744073709551615", "u8:255",
        "u8:1", "u16:2", "u32:4294967295", "u32:2147483648", "u64:0", "u64:1",
        "u64:2147483647", "u64:2147483648", "u64:9223372036854775807",
        "u64:9223372036854775808", "u64:18446744073709551615", "f32:1.5", "f32:3",
        "f32:0.1", "f64:1.5", "f64:NaN", "f64:+Inf", "f64:-0", "f64:1e21", "f64:1e-5",
        "time:zero", "time:1700000000:123456789:0", "time:1700000000:0:3600"]
ARGS += [f"str:{hx(t)}" for t in ["", "0", "1", "true", "T", "x", "12", "-12",
                                   "2147483648", "-2147483649", " 12", "1e3", "+5",
                                   "false", "yes", "hé"]]
ARGS += [f"bytes:{hx(t)}" for t in ["", "0", "1", "true", "x", "12", "[1 2]"]]
ARGS += ["uuid:6ba7b8109dad11d180b400c04fd430c8", "uuid:00000000000000000000000000000000",
         "ptruuid:ffffffffffffffffffffffffffffffff"]
WEIRD = ["ptrnil", "ptr:5", "slice:int", "slice:str", "struct", "map", "func",
         "complex", "uintptr", "array", "ns:null", "ns:6162", "ni:null", "ni:7",
         "valuererr", "valuernil", "valuerstr"]
WEIRD += [f"dec:{d}" for d in FLOAT_DECIMALS] + [f"ptrdec:{d}" for d in FLOAT_DECIMALS[:4]]
CONVERTERS = ["default", "bool", "int32", "string", "null:default", "notnull:default",
              "null:bool", "notnull:int32", "null:string", "notnull:string"]


def converter_requests():
    reqs = []
    for arg in ARGS + WEIRD:
        reqs.append(f"V isvalue {arg}")
        reqs.append(f"V default {arg}")
        reqs.append(f"V null:default {arg}")
        reqs.append(f"V notnull:default {arg}")
    for arg in ARGS:
        for conv in CONVERTERS:
            if conv not in ("default", "null:default", "notnull:default"):
                reqs.append(f"V {conv} {arg}")
    # %v of these has no address or Go-specific layout, so the messages match.
    for arg in ["slice:int", "slice:str", "struct", "map", "array", "complex"]:
        reqs.append(f"V string {arg}")
        reqs.append(f"V bool {arg}")
        reqs.append(f"V int32 {arg}")
    return reqs


# ---------------------------------------------------------------- scripts

TABLE = "people"
COLS = "name=string,age=int32,bf=bool,f=float64,nick=nullstring,n=nullint64,created=datetime"
SELECT_ALL = f"SELECT|{TABLE}|name,age,bf,f,nick,n,created|"
ALL_DESTS = ["string", "i64", "bool", "f64", "ns", "ni64", "time"]
ANY_DESTS = ["any"] * 7
NAMES = ["alice", "bob", "carol", "dave", "erin"]


def insert_args(rng):
    nick = "ns:null" if rng.random() < 0.3 else f"ns:{rng.choice(NAMES)}"
    n = "n" if rng.random() < 0.3 else f"i:{rng.randint(-5, 500)}"
    return [f"s:{rng.choice(NAMES)}", f"i:{rng.randint(0, 90)}", f"B:{rng.choice(['true', 'false'])}",
            f"f:{rng.choice(['1.5', '2.25', '0', '1e3', '-7.5'])}", nick, n,
            f"t:{rng.randint(0, 1900000000)}"]


class Gen:
    def __init__(self, rng, n):
        self.rng = rng
        self.lines = []
        self.n = n
        self.rows_open = [False] * 4
        self.txs_open = [False] * 4
        self.conns_open = [False] * 4
        self.stmts_open = [False] * 4

    def emit(self, *parts):
        self.lines.append(" ".join(str(p) for p in parts))

    def slot(self, used):
        """A slot to create something in: usually a free one."""
        free = [i for i, u in enumerate(used) if not u]
        busy = [i for i, u in enumerate(used) if u]
        if free and (not busy or self.rng.random() < 0.8):
            return self.rng.choice(free)
        return self.rng.choice(busy) if busy else self.rng.randrange(4)

    def busy(self, used):
        """A slot to operate on: usually one in use."""
        busy = [i for i, u in enumerate(used) if u]
        if busy and self.rng.random() < 0.9:
            return self.rng.choice(busy)
        return self.rng.randrange(4)

    def target(self):
        rng = self.rng
        choices = ["d"] * 5
        choices += [f"c{i}" for i in range(4) if self.conns_open[i]] * 3
        choices += [f"t{i}" for i in range(4) if self.txs_open[i]] * 3
        if rng.random() < 0.08:
            choices += [f"c{rng.randrange(4)}", f"t{rng.randrange(4)}"]
        return rng.choice(choices)

    def dests_for(self, cols):
        rng = self.rng
        kind = rng.random()
        if kind < 0.5:
            return ",".join(ALL_DESTS[:cols] + (["string"] * max(0, cols - 7)))
        if kind < 0.7:
            return ",".join(["any"] * cols)
        if kind < 0.85:
            pool = ["string", "bytes", "i64", "i32", "i16", "f64", "bool", "ns", "ni64",
                    "nf64", "nbool", "any", "u8", "raw", "p:i64", "p:string", "N:i64"]
            return ",".join(rng.choice(pool) for _ in range(cols))
        return ",".join(["any"] * max(1, cols + rng.choice([-1, 1])))

    def select(self):
        rng = self.rng
        r = rng.random()
        if r < 0.3:
            return SELECT_ALL, [], 7
        if r < 0.5:
            return f"SELECT|{TABLE}|name,age|age=?", [f"i:{rng.randint(0, 90)}"], 2
        if r < 0.62:
            return f"SELECT|{TABLE}|name,nick|name=?,age=?", [f"s:{rng.choice(NAMES)}", f"i:{rng.randint(0, 90)}"], 2
        if r < 0.72:
            return f"SELECT|{TABLE}|name|;SELECT|{TABLE}|age,f|", [], 1
        if r < 0.8:
            return f"SELECT|{TABLE}|name,age|name=?name", [f"named:name={rng.choice(['s:alice', 's:bob'])}"], 2
        if r < 0.86:
            return f"SELECT|{TABLE}|nope|", [], 1
        if r < 0.9:
            return "SELECT|missing|a|", [], 1
        if r < 0.94:
            return "SELECT|tx_status|tx_status|", [], 1
        return f"SELECT|{TABLE}|name,age|age=?", [], 2

    def step(self):
        rng = self.rng
        r = rng.random()
        cancelled = "@cancelled " if rng.random() < 0.04 else ""
        if r < 0.10:
            tgt = self.target()
            if cancelled and tgt.startswith("c"):
                cancelled = ""
            self.emit(f"{cancelled}exec", tgt, f"INSERT|{TABLE}|{'name=?,age=?,bf=?,f=?,nick=?,n=?,created=?'}",
                      *insert_args(rng))
        elif r < 0.13:
            tgt = self.target()
            self.emit("exec", tgt, rng.choice([
                f"INSERT|{TABLE}|name=?,age=?", f"NOSERT|{TABLE}|name=?,age=?",
                f"INSERT|{TABLE}|name=bobby,age=33", "WIPE", f"CREATE|{TABLE}|{COLS}",
                "BOGUS|x", f"INSERT|{TABLE}|nope=?", f"INSERT|{TABLE}|name=?,age=?,bf=?"]),
                *rng.choice([[], ["s:zed", "i:3"], ["s:zed", "i32:3"], ["s:q", "s:notint"],
                             ["n", "i:1"], ["s:zed", "i:4", "B:true"], ["i:1"]]))
        elif r < 0.30:
            i = self.slot(self.rows_open)
            tgt = self.target()
            if cancelled and tgt.startswith("c"):
                cancelled = ""
            q, args, cols = self.select()
            self.last_cols = cols
            self.emit(f"{cancelled}query", tgt, f"r{i}", q, *args)
            self.rows_open[i] = True
        elif r < 0.50:
            i = self.busy(self.rows_open)
            op = rng.random()
            cols = getattr(self, "last_cols", 7)
            if op < 0.4:
                self.emit("next", f"r{i}")
            elif op < 0.7:
                self.emit("scan", f"r{i}", self.dests_for(cols))
            elif op < 0.76:
                self.emit("cols", f"r{i}")
            elif op < 0.82:
                self.emit("coltypes", f"r{i}")
            elif op < 0.88:
                self.emit("nextset", f"r{i}")
            elif op < 0.93:
                self.emit("rerr", f"r{i}")
            else:
                self.emit("rclose", f"r{i}")
                self.rows_open[i] = False
        elif r < 0.56:
            tgt = self.target()
            if cancelled and tgt.startswith("c"):
                cancelled = ""
            q, args, cols = self.select()
            self.emit(f"{cancelled}queryrow", tgt, self.dests_for(cols), q, *args)
        elif r < 0.66:
            i = self.slot(self.txs_open)
            if rng.random() < 0.55:
                src = "d"
                if rng.random() < 0.3 and any(self.conns_open):
                    src = f"c{rng.choice([j for j, u in enumerate(self.conns_open) if u])}"
                opts = rng.choice([[], [], [], ["ro"], ["iso=0"], ["iso=2"], ["ro", "iso=6"]])
                self.emit(f"{cancelled}begin", src, f"t{i}", *opts)
                self.txs_open[i] = True
            else:
                self.emit(rng.choice(["commit", "rollback"]), f"t{self.busy(self.txs_open)}")
        elif r < 0.78:
            op = rng.random()
            i = self.slot(self.stmts_open) if op < 0.3 else self.busy(self.stmts_open)
            if op < 0.3:
                tgt = self.target()
                if cancelled and tgt.startswith("c"):
                    cancelled = ""
                q = rng.choice([f"INSERT|{TABLE}|name=?,age=?", SELECT_ALL, f"SELECT|{TABLE}|name,age|age=?",
                                f"SELECT|{TABLE}|name|;SELECT|{TABLE}|age|", "BOGUS|"])
                self.emit(f"{cancelled}prepare", tgt, f"s{i}", q)
                self.stmts_open[i] = True
                self.stmt_cols = 2 if "name,age" in q else (7 if q == SELECT_ALL else 1)
            elif op < 0.5:
                self.emit(f"{cancelled}stmtexec", f"s{i}", *rng.choice([[], ["s:x", "i:1"], ["s:x", "i:2", "n"], ["s:y", "i32:9"]]))
            elif op < 0.7:
                j = self.slot(self.rows_open)
                self.emit(f"{cancelled}stmtquery", f"s{i}", f"r{j}", *rng.choice([[], ["i:30"], ["i:1", "i:2"]]))
                self.rows_open[j] = True
                self.last_cols = getattr(self, "stmt_cols", 2)
            elif op < 0.8:
                self.emit(f"{cancelled}stmtqueryrow", f"s{i}", self.dests_for(getattr(self, "stmt_cols", 2)),
                          *rng.choice([[], ["i:30"], ["i:5"]]))
            elif op < 0.9:
                self.emit("stmtclose", f"s{i}")
                self.stmts_open[i] = False
            else:
                t = self.busy(self.txs_open)
                j = self.slot(self.stmts_open)
                self.emit("txstmt", f"t{t}", f"s{i}", f"s{j}")
                self.stmts_open[j] = True
        elif r < 0.86:
            op = rng.random()
            i = self.slot(self.conns_open) if op < 0.5 else self.busy(self.conns_open)
            if op < 0.5:
                self.emit("conn", f"c{i}")
                self.conns_open[i] = True
            elif op < 0.8:
                self.emit("connclose", f"c{i}")
                self.conns_open[i] = False
            elif op < 0.9:
                self.emit("stickybad", f"c{i}")
            else:
                self.emit(f"{cancelled}ping", rng.choice(["d", f"c{i}"]))
        elif r < 0.90:
            self.emit(rng.choice(["maxopen", "maxidle"]), rng.choice([0, 1, 2, 3, -1, 5]))
        elif r < 0.93:
            self.emit(f"{cancelled}ping", "d")
        elif r < 0.931:
            self.emit("dbclose")
        else:
            self.emit(rng.choice(["stats", "fake"]))
        if rng.random() < 0.35:
            self.emit("stats")


def script_requests(rng):
    reqs = []
    for n in range(SCRIPTS):
        g = Gen(rng, n)
        driver = rng.choice(["test", "testctx"])
        dsn = f"s{n}" + (";badConn" if rng.random() < 0.2 else "")
        reqs.append("BEGIN")
        g.emit("open", driver, dsn)
        if rng.random() < 0.5:
            g.emit("maxopen", rng.choice([1, 2, 3, 4, 5, 6, 6, 8]))
        if rng.random() < 0.3:
            g.emit("maxidle", rng.choice([0, 1, 2, 4]))
        g.emit("exec", "d", "WIPE")
        g.emit("exec", "d", f"CREATE|{TABLE}|{COLS}")
        for _ in range(rng.randint(0, 4)):
            g.emit("exec", "d", f"INSERT|{TABLE}|name=?,age=?,bf=?,f=?,nick=?,n=?,created=?", *insert_args(rng))
        for _ in range(OPS_PER_SCRIPT):
            g.step()
        if rng.random() < 0.25:
            g.emit("dbclose")
            g.emit("stats")
        g.emit("stats")
        g.emit("fake")
        reqs += g.lines
        reqs.append("END")
    return reqs


def run(cmd, payload, name):
    proc = subprocess.run(cmd, input=payload, text=True, capture_output=True, cwd=ROOT, timeout=900)
    if proc.returncode:
        raise RuntimeError(f"{name} failed:\n{proc.stderr[-4000:]}")
    return proc.stdout.splitlines()


def main():
    rng = random.Random(0xDB5E1)
    conv = convert_requests()
    vals = converter_requests()
    scripts = script_requests(rng)
    records = conv + vals + scripts
    payload = "".join(r + "\n" for r in records)

    subprocess.run(["cargo", "build", "--quiet", "--offline", "--locked", "--example", "database_probe"],
                   cwd=ROOT, check=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        rust_job = pool.submit(run, ["cargo", "run", "--quiet", "--offline", "--locked", "--example",
                                     "database_probe"], payload, "Rust database probe")
        go_job = pool.submit(run, ["go", "run", str(ROOT / "tools/database_oracle.go"),
                                   str(ROOT / "tools/database_fakedb.go")], payload, "Go database oracle")
        rust, go = rust_job.result(), go_job.result()
    if len(rust) != len(go):
        raise AssertionError(f"reply counts differ: rust={len(rust)} go={len(go)}")

    # Pair each reply with its request. A script whose operation hangs (in Go
    # and in Rust alike) drops its remaining operations.
    requests = iter(r for r in records if r != "BEGIN")
    context, hung, checked, hangs, ops = [], False, 0, 0, 0
    for i, (a, b) in enumerate(zip(rust, go)):
        request = None
        while True:
            request = next(requests)
            if not hung or request == "END":
                break
        if request == "END":
            hung = False
            context = []
        else:
            context.append(f"{request}  ->  {b}")
            if b.endswith(" hang"):
                hung = True
                hangs += 1
            if b[:1].isdigit():
                ops += 1
        if a != b:
            tail = "\n".join(context[-12:])
            raise AssertionError(f"vector {i}, request={request!r}\nRust={a!r}\nGo={b!r}\nrecent script:\n{tail}")
        checked += 1
    print(f"database/sql Go differential: {len(conv)} Scan conversions, {len(vals)} value-converter "
          f"checks and {SCRIPTS} scripts ({ops} pool/transaction operations, {hangs} deliberate "
          f"deadlocks) passed")


if __name__ == "__main__":
    main()
