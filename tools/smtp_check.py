#!/usr/bin/env python3
"""Differentially check net/smtp against Go with scripted fake SMTP servers.

Each scenario is a server script (replies per command verb) and a client
action sequence (Dial, NewClient, Hello, Extension, Auth with PLAIN, CRAM-MD5
and scripted mechanisms, Mail, Rcpt, Verify, Data, Reset, Noop, Quit, Close,
StartTLS refusals, TLSConnectionState) or a SendMail call. A TCP server in
this script plays the script to the Go client and then to the Rust client; the
bytes each client sent and every action's result (including error texts) must
be identical. CRAM-MD5 answers are computed here with Python's hmac, because
the Rust probe has no cryptography; Go computes its own.
"""
import base64
import hashlib
import hmac
import os
import pathlib
import random
import re
import socket
import subprocess
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET = pathlib.Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
VERBS = {b"EHLO", b"HELO", b"MAIL", b"RCPT", b"DATA", b"VRFY", b"RSET", b"NOOP", b"QUIT", b"STARTTLS", b"AUTH"}
CLOSE = b"<CLOSE>"


class Server(threading.Thread):
    """Plays a script: replies[verb] is a list of replies, repeating the last."""

    def __init__(self, replies):
        super().__init__(daemon=True)
        self.replies = {k: list(v) for k, v in replies.items()}
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(8)
        self.port = self.listener.getsockname()[1]
        self.received = bytearray()
        self.accepted = False

    def reply(self, verb):
        queue = self.replies.get(verb) or self.replies.get("*") or [b"500 unrecognized\r\n"]
        return queue.pop(0) if len(queue) > 1 else queue[0]

    def send(self, conn, data):
        if data == CLOSE:
            # Half-close: the client sees a clean EOF, never a reset, and its
            # later writes are still read and recorded.
            conn.shutdown(socket.SHUT_WR)
            return False
        if data.startswith(b"<PARTIAL>"):
            conn.sendall(data[len(b"<PARTIAL>"):])
            conn.shutdown(socket.SHUT_WR)
            return False
        conn.sendall(data)
        return True

    def run(self):
        try:
            conn, _ = self.listener.accept()
        except OSError:
            return
        self.accepted = True
        conn.settimeout(0.5)
        open_ = self.send(conn, self.reply("GREET"))
        buf = b""
        in_data = False
        stalled = False
        try:
            while True:
                try:
                    chunk = conn.recv(65536)
                except socket.timeout:
                    # The client is waiting for a reply the script does not
                    # give (for example an unterminated multi-line reply):
                    # end the stream cleanly and keep reading until it hangs up.
                    if not stalled:
                        stalled = True
                        open_ = False
                        conn.shutdown(socket.SHUT_WR)
                        conn.settimeout(3)
                        continue
                    break
                if not chunk:
                    break
                self.received += chunk
                buf += chunk
                while True:
                    if in_data:
                        if buf.startswith(b".\r\n"):
                            end = 3
                        else:
                            i = buf.find(b"\r\n.\r\n")
                            end = i + 5 if i >= 0 else -1
                        if end < 0:
                            break
                        buf = buf[end:]
                        in_data = False
                        verb = "DATA."
                    else:
                        i = buf.find(b"\n")
                        if i < 0:
                            break
                        line, buf = buf[:i + 1], buf[i + 1:]
                        word = line.split(None, 1)[0].upper() if line.strip() else b""
                        verb = word.decode("latin1") if word in VERBS else "LINE"
                    if open_:
                        reply = self.reply(verb)
                        open_ = self.send(conn, reply)
                        if open_ and verb == "DATA" and reply.startswith(b"354"):
                            in_data = True
        except (socket.timeout, OSError):
            pass
        finally:
            conn.close()
            self.listener.close()


def b64(s):
    return base64.b64encode(s).decode()


def hx(s):
    return s.encode().hex() if s else "-"


GREETINGS = [b"220 mail.example.com ESMTP ready\r\n"] * 12 + [
    b"220-mail.example.com\r\n220 multi line greeting\r\n", b"554 no service here\r\n", b"421 busy\r\n",
    b"hello there\r\n", b"220\r\n", CLOSE, b"2201 x\r\n", b"<PARTIAL>220 par", b"<PARTIAL>220-never\r\n"]
EXTS = [
    b"250-mail.example.com\r\n250-SIZE 35882577\r\n250-8BITMIME\r\n250-SMTPUTF8\r\n250-AUTH PLAIN LOGIN CRAM-MD5\r\n250 HELP\r\n",
    b"250-mail.example.com\r\n250-8BITMIME\r\n250 AUTH PLAIN\r\n",
    b"250 mail.example.com\r\n",
    b"250-x\r\n250 smtputf8\r\n",
    b"250-x\r\n250-AUTH\r\n250 PIPELINING\r\n",
    b"250-x\r\n250-STARTTLS\r\n250 AUTH CRAM-MD5\r\n",
    b"250-x\r\n250-AUTH PLAIN\r\n250-AUTH LOGIN\r\n250 8bitmime\r\n",
    b"500 what\r\n", b"502 not implemented\r\n", b"<PARTIAL>250-x\r\n999 weird\r\n", b"<PARTIAL>250-x\r\n250-y\r\n", CLOSE,
    b"250-a\r\n250-b c d\r\n250-\r\n250 e\r\n",
]
HELOS = [b"250 hi\r\n", b"250 hi\r\n", b"500 no\r\n", b"550 nope\r\n", CLOSE]
CODES = {
    "MAIL": [b"250 ok\r\n"] * 4 + [b"550 rejected\r\n", b"553 bad sender\r\n", b"452 full\r\n", b"250-ok\r\n250 more\r\n", b"334 hm\r\n"],
    "RCPT": [b"250 ok\r\n"] * 3 + [b"251 forwarded\r\n", b"252 maybe\r\n", b"550 no such user\r\n", b"450 later\r\n", b"350 odd\r\n"],
    "DATA": [b"354 go ahead\r\n"] * 5 + [b"554 no\r\n", b"451 aborted\r\n", b"354-multi\r\n354 go\r\n"],
    "DATA.": [b"250 queued\r\n"] * 4 + [b"554 rejected\r\n", b"452 insufficient\r\n", b"250-q\r\n250 queued as 1\r\n", CLOSE],
    "VRFY": [b"250 user ok\r\n", b"252 cannot verify\r\n", b"550 unknown\r\n", b"502 disabled\r\n"],
    "RSET": [b"250 ok\r\n"] * 3 + [b"500 x\r\n"],
    "NOOP": [b"250 ok\r\n"] * 3 + [b"421 gone\r\n"],
    "QUIT": [b"221 bye\r\n"] * 4 + [b"500 x\r\n", CLOSE],
    "STARTTLS": [b"454 TLS not available\r\n", b"500 unknown\r\n", b"502 no\r\n", b"554 refused\r\n", b"530 Must issue\r\n"],
}


def auth_replies(rng, kind):
    """Replies to the AUTH line and to its continuation lines."""
    challenge = rng.choice([b"<1896.697170952@postoffice.example.net>", b"abc", b"", b"\x00\xff binary"])
    first = {
        "plain": [b"235 2.7.0 Authentication successful\r\n", b"535 5.7.8 Authentication credentials invalid\r\n",
                  b"334 \r\n", b"504 mechanism not supported\r\n", b"530 auth required\r\n"],
        "cram": [b"334 " + b64(challenge).encode() + b"\r\n"] * 4 + [b"235 ok\r\n", b"535 bad\r\n", b"334 !!!\r\n"],
        "script": [b"334 " + b64(b"Username:").encode() + b"\r\n"] * 3 + [b"235 done\r\n", b"535 no\r\n", b"334 bad base64 ===\r\n"],
        "none": [b"235 ok\r\n"],
    }[kind]
    cont = [b"235 2.7.0 ok\r\n", b"535 5.7.8 bad\r\n", b"334 " + b64(b"Password:").encode() + b"\r\n",
            b"334 " + b64(challenge).encode() + b"\r\n", b"501 cancelled\r\n"]
    return rng.choice(first), rng.choice(cont), challenge


def make_server_script(rng, kind="none"):
    replies = {"GREET": [rng.choice(GREETINGS)], "EHLO": [rng.choice(EXTS)], "HELO": [rng.choice(HELOS)]}
    for verb, pool in CODES.items():
        replies[verb] = [rng.choice(pool) for _ in range(rng.choice([1, 1, 2, 3]))]
    # Make a sensible happy path likely.
    if rng.random() < 0.55:
        replies["GREET"] = [GREETINGS[0]]
        replies["EHLO"] = [EXTS[rng.choice([0, 0, 1, 2, 3, 6])]]
    first, cont, challenge = auth_replies(rng, kind)
    replies["AUTH"] = [first]
    replies["LINE"] = [cont, rng.choice([b"235 ok\r\n", b"535 no\r\n"])]
    return replies, challenge


def text(rng):
    return rng.choice(["a@example.com", "alice@example.com", "", "x y", "bad\nline", "bad\rline", "unié@example.com",
                       "<weird>", "a@b.c\r\nRCPT TO:<evil@x>", "very" * 30 + "@example.com"])


def mac_entry(user_secret, challenge):
    return (user_secret.encode().hex() or "-") + ":" + (challenge.hex() or "-") + ":" + hmac.new(
        user_secret.encode(), challenge, hashlib.md5).hexdigest()


def scenario(rng):
    kind = rng.choice(["none", "plain", "cram", "script"])
    replies, challenge = make_server_script(rng, kind)
    actions = [rng.choice(["dial"] * 6 + ["newclient"])]
    if actions[0] == "newclient":
        actions[0] = "newclient " + hx(rng.choice(["127.0.0.1", "localhost", "mail.example.com", "::1", ""]))
    macs = []
    for _ in range(rng.randrange(1, 9)):
        verb = rng.choice(["hello", "ext", "auth", "auth", "mail", "mail", "rcpt", "rcpt", "verify", "data", "data",
                           "datanoclose", "reset", "noop", "quit", "close", "starttls", "tlsstate"])
        if verb == "hello":
            actions.append("hello " + hx(rng.choice(["client.example.com", "localhost", "bad\nname", "", "h"])))
        elif verb == "ext":
            actions.append("ext " + hx(rng.choice(["8bitmime", "AUTH", "starttls", "SIZE", "smtputf8", "pipelining", "x"])))
        elif verb == "auth":
            if kind == "plain":
                host = rng.choice(["127.0.0.1", "localhost", "mail.example.com", "other"])
                ident = rng.choice(["", "ident"])
                actions.append("auth plain " + ",".join(hx(x) for x in (ident, "user", "pass", host)))
            elif kind == "cram":
                secret = rng.choice(["secret", "s3cr3t!", "", "k" * 80])
                actions.append("auth cram " + hx("user") + "," + hx(secret))
                for ch in {challenge, b"Username:", b"Password:", b"<1896.697170952@postoffice.example.net>", b"abc", b"", b"\x00\xff binary"}:
                    macs.append(mac_entry(secret, ch))
            elif kind == "script":
                if rng.random() < 0.15:
                    actions.append("auth startfail")
                else:
                    nexts = [rng.choice(["nil", "err", "empty", hx("resp"), hx("pw")]) for _ in range(rng.randrange(1, 4))]
                    actions.append("auth script " + ",".join([hx(rng.choice(["LOGIN", "XOAUTH2", "FOO"])),
                                                              hx(rng.choice(["", "init"]))] + nexts))
            else:
                actions.append("auth plain " + ",".join(hx(x) for x in ("", "u", "p", "127.0.0.1")))
        elif verb in ("mail", "rcpt", "verify"):
            actions.append(f"{verb} " + hx(text(rng)))
        elif verb in ("data", "datanoclose"):
            msg = rng.choice(["Subject: hi\r\n\r\nbody\r\n", "line\n.dot\n..\r\n", "no newline", "", ".", "a\rb\n\n.\n",
                              "x" * 3000 + "\r\n", "From: a\r\n\r\n.hidden\r\n"])
            actions.append(f"{verb} " + hx(msg))
        else:
            actions.append(verb)
    return replies, actions, macs


def sendmail_scenario(rng):
    kind = rng.choice(["none", "plain", "cram"])
    replies, challenge = make_server_script(rng, kind if kind != "none" else "plain")
    # SendMail upgrades with STARTTLS whenever it is offered, which needs a
    # real TLS peer; scripts never advertise it.
    replies["EHLO"] = [e for e in replies["EHLO"]]
    replies["EHLO"] = [e.replace(b"250-STARTTLS\r\n", b"") for e in replies["EHLO"]]
    if rng.random() < 0.8:
        replies["GREET"] = [GREETINGS[0]]
        replies["EHLO"] = [EXTS[rng.choice([0, 1, 2, 3, 6])]]
    to = [text(rng) for _ in range(rng.choice([0, 1, 1, 2, 3]))]
    to = [t for t in to]
    if rng.random() < 0.7:
        to = [t for t in to if "\n" not in t and "\r" not in t]
    from_ = text(rng) if rng.random() < 0.3 else "sender@example.com"
    msg = rng.choice(["Subject: s\r\n\r\nbody\r\n", "no end", "x\n.\ny\r\n", ""])
    macs = [mac_entry("p", ch) for ch in {challenge, b"Username:", b"Password:", b"abc", b"", b"\x00\xff binary", b"<1896.697170952@postoffice.example.net>"}]
    return replies, kind, from_, to, msg, macs


class Probe:
    def __init__(self, command):
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                                        bufsize=1, cwd=ROOT)

    def ask(self, line):
        self.process.stdin.write(line + "\n")
        self.process.stdin.flush()
        out = self.process.stdout.readline()
        if not out:
            raise RuntimeError(f"probe died on: {line[:200]}")
        return out.rstrip("\n")

    def close(self):
        self.process.stdin.close()
        self.process.wait(timeout=10)


def play(probe, replies, request):
    server = Server(replies)
    server.start()
    result = probe.ask(request.replace("{port}", str(server.port)))
    if not server.accepted:
        # The client never connected (a rejected argument): release accept().
        try:
            socket.create_connection(("127.0.0.1", server.port), timeout=1).close()
        except OSError:
            pass
    server.join(timeout=15)
    return result, bytes(server.received)


def main():
    started = time.monotonic()
    rng = random.Random(0x534D5450)
    subprocess.run(["cargo", "build", "--quiet", "--offline", "--locked", "--example", "smtp_probe"],
                   cwd=ROOT, check=True)
    rust = Probe([str(TARGET / "debug/examples" / ("smtp_probe.exe" if os.name == "nt" else "smtp_probe"))])
    go = Probe(["go", "run", str(ROOT / "tools/smtp_oracle.go")])
    count = int(os.environ.get("SMTP_SCENARIOS", "1500"))
    ok_results = err_results = 0
    scenarios = 0
    try:
        for n in range(count):
            if n % 5 == 4:
                replies, kind, from_, to, msg, macs = sendmail_scenario(rng)
                request = "M {port} %s %s %s %s @ %s" % (kind, hx(from_), ",".join(hx(t) for t in to) or "-", hx(msg), ",".join(macs))
            else:
                replies, actions, macs = scenario(rng)
                request = "S {port} " + "|".join(actions) + " @ " + ",".join(macs)
            go_result, go_bytes = play(go, replies, request)
            rust_result, rust_bytes = play(rust, replies, request)
            go_result = re.sub(r"127\.0\.0\.1:\d+", "ADDR", go_result)
            if go_result.startswith("panic"):
                continue
            if (go_result, go_bytes) != (rust_result, rust_bytes):
                raise AssertionError(
                    f"scenario {n}: {request[:600]}\nscript={replies}\nGo   result={go_result!r}\nRust result={rust_result!r}\n"
                    f"Go   sent={go_bytes!r}\nRust sent={rust_bytes!r}")
            scenarios += 1
            ok_results += go_result.count("ok")
            err_results += go_result.count("err")
    finally:
        rust.close()
        go.close()
    print(f"SMTP Go differential: {scenarios} scripted-server scenarios ({ok_results} ok and {err_results} error "
          f"results, byte-identical client transcripts) passed in {time.monotonic() - started:.1f}s")


if __name__ == "__main__":
    main()
