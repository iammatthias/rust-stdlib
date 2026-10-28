#!/usr/bin/env python3
"""Differentially check net/mail addresses, dates, messages and RFC 2047 words against Go."""
import base64
import os
from pathlib import Path
import random
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
RNG = random.Random(0x3A11)

ADDRESS_SEEDS = [
    "jdoe@machine.example", "John Doe <jdoe@machine.example>", "Mary Smith <mary@x.test>, jdoe@example.org",
    '"Joe Q. Public" <john.q.public@example.com>', "Pete(A nice \\) chap) <pete(his account)@silly.test(his host)>",
    "A Group:Ed Jones <c@a.test>,joe@where.test,John <jdoe@one.test>;", "Undisclosed recipients:;",
    "=?iso-8859-1?q?J=F6rg_Doe?= <joerg@example.com>", "=?utf-8?q?J=C3=B6rg?= <joerg@example.com>",
    "=?US-ASCII?Q?Keith_Moore?= <moore@cs.utk.edu>", "=?ISO-8859-1?B?SvZyZw==?= <joerg@example.com>",
    "=?UTF-8?B?w6nDqcOp?= <e@example.com>", "=?koi8-r?q?abc?= <a@b.c>", "Jo =?koi8-r?q?abc?= <a@b.c>",
    "=?utf-8?q?bad=?= <a@b.c>", "=?utf-8?q?=E2=82?= =?utf-8?q?=AC?= <a@b.c>", "=?utf-8?q?=FF?= <a@b.c>",
    "asdf@example.com (Display Name)", "asdf@example.com (=?utf-8?q?J=C3=B6rg?=)", "a@b (unclosed",
    '"" <a@b.c>', '"\\"quoted\\"" <a@b.c>', '"a\\b"@example.com', '"@"@example.com', '""@example.com',
    "a@[1.2.3.4]", "a@[IPv6:::1]", "a@[IPv6:1.2.3.4]", "a@[::ffff:1.2.3.4]", "a@[010.0.0.1]", "a@[1.2.3]",
    "a@[IPv6:::1%eth0]", "a@[::1]", "a@[256.1.1.1]", "a@[ 1.2.3.4]", "a@[1.2.3.4", "a@[a]b",
    ".a@b.c", "a.@b.c", "a..b@c.d", "a@.b", "a@b.", "a@b..c", "a.b@c.d", "foo.bar", "Full Name",
    "<a@b.c>", "< a@b.c>", "<a@b.c >", "<a@b.c", "a@b.c>", "a @b.c", "a@ b.c", "Ω <ω@ω.ω>", "ʎ@ʎ",
    "Jöhn <j@example.com>", "\"Jöhn\" <j@example.com>", "a@b,", ",a@b", "a@b,,c@d", "a@b, ,c@d",
    "a@b;c@d", "g: a@b, c@d", "g: ;", "g: a@b", "g:a@b;x", "g:(c) a@b (d);", "", " ", "@", "a@",
    "@b", "\x01@b", "a@b\x7f", "Name (comment) <a@b>", "Name(comment)<a@b>", "\"\\\x01\" <a@b>",
    "tab\tname <a@b>", "(c) a@b", "a@b (c) (d)", "a@b (\\(x)", "a@b ((nested) x)",
]
NAMES = ["John Doe", "Jöhn", "Ñame", "a\"b", "x, y", "q?u", "under_score", "e=mc2", "tab\there",
         "ctl\x01", "del\x7f", "ünïcödé " * 6, "x" * 80, "日本語の名前" * 4, "(paren)", "#hash", "",
         "a\\b", "spaces  inside", "émoji 😀", ".dot", "trail."]
LOCALS = ["user", "first.last", "a..b", ".lead", "trail.", "with space", "quote\"d", "x@y", "", "ünï",
          "back\\slash", "a.b.c", "(c)", "ok+tag", "-"]
DOMAINS = ["example.com", "[1.2.3.4]", "", "ex ample", "dömain.test", "a"]

WEEKDAYS = ["", "Mon, ", "mon, ", "MON, ", "Thu, ", "Tue, ", "Sat,", "Xyz, ", "Mon,  "]
DAYS = ["1", "01", "2", "02", "29", "30", "31", "0", "32", "9", "001"]
MONTHS = ["Jan", "jan", "JAN", "Feb", "feb", "Dec", "Sep", "Foo", "Ja"]
YEARS = ["2006", "06", "1997", "69", "68", "0000", "0001", "9999", "+5", "-9", "-0", "200", "20061",
         "2000", "1900", "2004", "2100"]
TIMES = ["15:04", "15:04:05", "9:04", "09:04:05", "23:59:59", "24:00", "15:60", "15:04:60",
         "15:04:05.123", "15:04:05,5", "15:04:05.1234567890123", "15:04:05.", "1:2:3", "15:4"]
ZONES = ["-0700", "+0000", "-0000", "+2359", "+2400", "-2460", "+2461", "+2500", "+07", "-07:00",
         "UTC", "UT", "GMT", "GMT+5", "GMT-23", "GMT+24", "GMT+", "EST", "EDT", "MDT", "PDT", "CEST",
         "AEST", "WITA", "ChST", "MeST", "ABCDEF", "Z", "z", "est", "+0130", "MST7"]
TRAILERS = ["", " (comment)", " (MDT)", "  ", " (unclosed", " garbage", "(x)(y)", " \t(nested (c))"]


def mutate(text, alphabet):
    chars = list(text)
    for _ in range(RNG.randint(1, 3)):
        op = RNG.randrange(3)
        pos = RNG.randint(0, len(chars))
        if op == 0 or not chars:
            chars.insert(pos, RNG.choice(alphabet))
        elif op == 1:
            del chars[min(pos, len(chars) - 1)]
        else:
            chars[min(pos, len(chars) - 1)] = RNG.choice(alphabet)
    return "".join(chars)


ADDRESS_ALPHABET = list("<>@,;:()\"\\[]. \t=?_aZ09-é") + ["=?utf-8?q?", "?=", "=?iso-8859-1?b?", "IPv6:"]
DATE_ALPHABET = list(" ,:+-.()TUCMGSa019\t") + ["\r\n", "\r", "Jan", "Mon"]


def encoded_word():
    text = RNG.choice(NAMES[:12])
    charset = RNG.choice(["utf-8", "UTF-8", "iso-8859-1", "us-ascii"]) if RNG.random() < 0.9 else \
        RNG.choice(["koi8-r", "", "utf-8*en", "u\u017f-a\u017fcii", "\u017f"])
    raw = text.encode("latin-1", "replace") if charset == "iso-8859-1" else text.encode()
    if RNG.random() < 0.5:
        body = base64.b64encode(raw).decode()
        if RNG.random() < 0.1:
            body = body.rstrip("=")
        enc = RNG.choice("bB")
    else:
        body = "".join(chr(b) if chr(b).isalnum() else "=%02X" % b for b in raw).replace("=20", "_")
        enc = RNG.choice("qQ" if RNG.random() < 0.95 else "xQ")
    return f"=?{charset}?{enc}?{body}?="


def address():
    local = RNG.choice(["user", "first.last", "o'brien", "a+b", "\"quoted local\"", "x"])
    domain = RNG.choice(["example.com", "a.b.c", "[192.0.2.1]", "[IPv6:2001:db8::1]", "localhost"])
    spec = f"{local}@{domain}"
    form = RNG.randrange(5)
    if form == 0:
        return spec
    if form == 1:
        return f"{spec} ({RNG.choice(['Name', encoded_word(), 'two words'])})"
    name = RNG.choice(["John Doe", "\"Doe, John\"", encoded_word(), f"{encoded_word()} {encoded_word()}",
                       f"Mr {encoded_word()}", "Jöhn", "\"a\\\"b\"", "first (c) last"])
    if form == 2:
        return f"{name} <{spec}>"
    if form == 3:
        return f"{name}<{spec}>"
    return f"  {name}   <{spec}>  "


def address_list():
    items = [address() for _ in range(RNG.randint(1, 4))]
    if RNG.random() < 0.3:
        items.append(f"Group: {', '.join(address() for _ in range(RNG.randint(0, 2)))};")
    return RNG.choice([", ", ",", " , ", ",, "]).join(items)


def date():
    day = RNG.choice(DAYS[:6]) if RNG.random() < 0.92 else RNG.choice(DAYS)
    year = RNG.choice(YEARS[:4]) if RNG.random() < 0.85 else RNG.choice(YEARS)
    time = RNG.choice(TIMES[:5]) if RNG.random() < 0.85 else RNG.choice(TIMES)
    zone = RNG.choice(ZONES[:3]) if RNG.random() < 0.6 else RNG.choice(ZONES)
    month = RNG.choice(MONTHS[:4]) if RNG.random() < 0.95 else RNG.choice(MONTHS)
    space = RNG.choice([" "] * 8 + ["  ", "\t"])
    weekday = RNG.choice(WEEKDAYS[:5]) if RNG.random() < 0.9 else RNG.choice(WEEKDAYS)
    trailer = RNG.choice(TRAILERS[:4]) if RNG.random() < 0.85 else RNG.choice(TRAILERS)
    text = f"{weekday}{day}{space}{month} {year} {time} {zone}{trailer}"
    if RNG.random() < 0.1:
        text = RNG.choice([" ", "\t", "\r\n "]) + text
    if RNG.random() < 0.05:
        text = text.replace(" ", "\r\n ", 1)
    return text


def message():
    fields = []
    for _ in range(RNG.randint(0, 5)):
        key = RNG.choice(["From", "to", "SUBJECT", "Date", "x-weird key", "", "Bad\x01", "Ünï"])
        value = RNG.choice(["a@b", "Hello world", " spaced", "", "café", "x\x01y", "multi:colon"])
        fields.append(f"{key}:{value}" + RNG.choice(["\r\n", "\n"]))
        if RNG.random() < 0.2:
            fields.append(RNG.choice([" folded\r\n", "\tmore\n", "   \r\n"]))
    head = "".join(fields)
    if RNG.random() < 0.05:
        head = " leading\r\n" + head
    if RNG.random() < 0.05:
        head += "no colon line\r\n"
    tail = RNG.choice(["\r\n", "\n", "", "\r\n"]) + RNG.choice(["", "Body text\r\n", "body\nwith: colon\n\n"])
    return (head + tail).encode()


def corpus():
    records = [("A", s) for s in ADDRESS_SEEDS] + [("L", s) for s in ADDRESS_SEEDS]
    generated = [address() for _ in range(900)]
    records += [("A", s) for s in generated]
    records += [("A", mutate(RNG.choice(generated + ADDRESS_SEEDS), ADDRESS_ALPHABET)) for _ in range(500)]
    lists = [address_list() for _ in range(500)]
    records += [("L", s) for s in lists]
    records += [("L", mutate(RNG.choice(lists), ADDRESS_ALPHABET)) for _ in range(300)]
    for _ in range(600):
        name = RNG.choice(NAMES) if RNG.random() < 0.7 else mutate(RNG.choice(NAMES), list("\"\\()<>,;:.@ \t\x00éΩ"))
        addr = f"{RNG.choice(LOCALS)}@{RNG.choice(DOMAINS)}" if RNG.random() < 0.9 else RNG.choice(LOCALS)
        records.append(("F", f"{name}\x00{addr}"))
    dates = ["Mon, 02 Jan 2006 15:04:05 -0700", "Thu, 20 Nov 1997 09:55:06 MDT (MDT)",
             "Fri, 21 Nov 1997 09:55:06 -0600 (MDT)", "21 Nov 97 09:55:06 GMT", "Wed, 31 Dec 1969 16:00 UT",
             "Tue, 26 May 2020 14:04:40 UT", "Tue, 26 May 2020 14:04:40 GMT", "11 Jun 2020 12:00 +0000 (UTC)",
             "Mon, 1 Feb 2021 07:00:00 GMT+5", "29 Feb 2023 00:00 +0000", "29 Feb 2024 00:00 +0000",
             "29 Feb 0000 00:00 +0000", "30 Feb 0000 00:00 +0000", "1 Jan 0001 00:00 +0100",
             "31 Dec 9999 23:59:59 -2359", "31 Dec 9999 23:00 GMT+5", "1 Jan 0001 00:00 GMT-1",
             "Mon, 02 Jan 2006 15:04:05 -0700\r", "02 Jan 2006 15:04 UTC",
             "", " ", "(", "Mon, 02 Jan 2006", "Mon, 02 Jan 2006 15:04:05 +07"]
    dates += [date() for _ in range(2000)]
    dates += [mutate(RNG.choice(dates), DATE_ALPHABET) for _ in range(800)]
    records += [("D", s) for s in dates]
    records += [("M", m) for m in [message() for _ in range(500)] + [b"", b"\r\n", b"A: b", b" A: b\r\n\r\n"]]
    # Header.Get (G), Header.AddressList (H) and Header.Date (T) take key NUL message.
    lookup_messages = [message() for _ in range(300)]
    lookup_messages += [f"Date: {d}\r\nFrom: {a}\r\nTo: {a}\r\n\r\nbody".encode() for d in dates[:40] for a in ADDRESS_SEEDS[:4]]
    for raw in lookup_messages:
        for mode in "GH":
            records.append((mode, RNG.choice(["From", "to", "Date", "x-weird key", "", "Cc", "Ünï"]).encode() + b"\0" + raw))
        records.append(("T", b"Date\0" + raw))
    words = [encoded_word() for _ in range(200)]
    headers = [" ".join(RNG.choice(words + ["plain", "a", "\t", "=?", "?=", "=?x?q?"]) for _ in range(RNG.randint(1, 4)))
               for _ in range(400)]
    headers += ["=?utf-8?q?=E2=82?= =?utf-8?q?=AC?=", "=?utf-8?q?a?=\r\n =?utf-8?q?b?=", "x=?utf-8?q?a?=y",
                "=?ISO-8859-1?Q?Andr=E9?= Pirard", "=?utf-8?q?bad=?= ok", "=?utf-8?Q??=", "=?UTF-8?b?w6k=?="]
    records += [("W", s) for s in headers]
    texts = NAMES + ["€" * 30, "a" + "é" * 40, "x" * 100 + "é", "日本" * 30]
    records += [(mode, t) for t in texts for mode in "BQ"]
    return [(mode, value if isinstance(value, bytes) else value.encode()) for mode, value in records]


def run(command, payload, env):
    result = subprocess.run(command, input=payload, text=True, capture_output=True,
                            cwd=ROOT, env=env, timeout=200)
    if result.returncode:
        raise RuntimeError(f"{' '.join(command)} failed:\n{result.stderr}")
    return result.stdout.splitlines()


def main():
    if not shutil.which("go") or not shutil.which("cargo"):
        raise RuntimeError("mail differential check requires Go and Cargo on PATH")
    records = corpus()
    payload = "".join(f"{mode}:{data.hex()}\n" for mode, data in records)
    env = os.environ.copy()
    # The oracle also pins time.Local; TZ keeps any child process consistent.
    env.update({"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off", "TZ": "UTC"})
    go = run(["go", "run", "tools/mail_oracle.go"], payload, env)
    rust = run(["cargo", "run", "--quiet", "--offline", "--locked", "--example", "mail_probe"], payload, env)
    if len(go) != len(records) or len(rust) != len(records):
        raise AssertionError("mail oracle returned the wrong number of records")
    failures = [(mode, data, g, r) for (mode, data), g, r in zip(records, go, rust) if g != r]
    for mode, data, g, r in failures[:12]:
        print(f"mode={mode} input={data!r}\n  Go  ={g!r}\n  Rust={r!r}")
    if failures:
        raise AssertionError(f"{len(failures)} of {len(records)} mail vectors differ from Go")
    counts = {}
    for mode, _ in records:
        counts[mode] = counts.get(mode, 0) + 1
    detail = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    print(f"mail Go differential: {len(records)} vectors passed ({detail})")


if __name__ == "__main__":
    main()
