#!/usr/bin/env python3
"""The CGI program run by tools/cgi_check.py's host-side differential.

CGI_MODE selects the behavior: "env" prints the request environment, arguments,
working directory and body; "raw" prints the bytes in CGI_OUT (hex) exactly;
"stderr" writes to standard error and then prints a minimal response;
"slow" prints a response header and then dies without a body.
"""
import binascii
import os
import sys

mode = os.environ.get("CGI_MODE", "env")
if mode == "raw":
    sys.stdout.buffer.write(binascii.unhexlify(os.environ.get("CGI_OUT", "")))
elif mode == "stderr":
    sys.stderr.write("fixture stderr line\n")
    sys.stdout.write("Content-Type: text/plain\r\n\r\nafter stderr")
elif mode == "slow":
    sys.stdout.write("Content-Type: text/plain\r\n\r\nstart")
    sys.stdout.flush()
    sys.exit(3)
else:
    body = sys.stdin.buffer.read()
    skip = {"LC_CTYPE", "PWD", "SHLVL", "_", "__CF_USER_TEXT_ENCODING"}
    lines = ["%s=%s" % (k, v) for k, v in sorted(os.environ.items()) if k not in skip and not k.startswith("PYTHON")]
    out = "Content-Type: text/plain\r\n\r\n"
    out += "\n".join(lines) + "\n"
    # A script's sys.argv[0] is the file name the kernel was asked to execute,
    # not the process's argv[0]. std would search PATH for a slash-less name,
    # so the Rust handler executes "./Path"; the argv[0] it passes is still
    # Path (the "argv0" scenarios in cgi_check.py run a real binary to prove it).
    argv = [a[2:] if i == 0 and a.startswith("./") else a for i, a in enumerate(sys.argv)]
    out += "argv=%r\n" % (argv,)
    out += "cwd=%s\n" % os.path.realpath(os.getcwd())
    out += "stdin=%s\n" % binascii.hexlify(body).decode()
    sys.stdout.write(out)
