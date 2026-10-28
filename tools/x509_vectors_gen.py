#!/usr/bin/env python3
"""Extract Go's crypto/x509 test tables and test data into crates/crypto/tests/fixtures/x509.

Usage: x509_vectors_gen.py [GOROOT]

Produces:
  certs.tsv            name, PEM label, base64 of every PEM block assigned to a Go constant in
                       verify_test.go, x509_test.go and parser_test.go
  verify_tests.json    the verifyTests table of verify_test.go
  policies_valid.json  the table of TestPoliciesValid
  name_constraints.json the nameConstraintsTests table, dumped by compiling it with Go
  policy/*.pem         testdata/policy_*.pem
  pkits/               testdata/nist-pkits (vectors.json and the certificates the policy tests use)
"""
import base64
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "crates/crypto/tests/fixtures/x509"
PEM = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.S)


def go_root():
    if len(sys.argv) > 1:
        return Path(sys.argv[1])
    return Path(subprocess.check_output(["go", "env", "GOROOT"], text=True).strip())


def strip_comments(text):
    """Remove // and /* */ comments, leaving string and raw string literals alone."""
    out = []
    i = 0
    while i < len(text):
        c = text[i]
        if c == '"':
            j = i + 1
            while text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        elif c == "`":
            j = text.index("`", i + 1)
            out.append(text[i:j + 1])
            i = j + 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = len(text) if j < 0 else j
        elif text.startswith("/*", i):
            i = text.index("*/", i) + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def balanced(text, start):
    """Index just past the brace block that opens at text[start] == '{' (strings are skipped)."""
    depth = 0
    i = start
    while i < len(text):
        c = text[i]
        if c == '"':
            i += 1
            while text[i] != '"':
                i += 2 if text[i] == "\\" else 1
        elif c == "`":
            i = text.index("`", i + 1)
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise ValueError("unbalanced")


def top_level_entries(body):
    """Split the contents of a composite literal into its top-level { ... } elements."""
    out = []
    i = 0
    while True:
        j = body.find("{", i)
        if j < 0:
            return out
        k = balanced(body, j)
        out.append(body[j:k])
        i = k


def literal_body(text, header):
    start = text.index(header)
    brace = text.index("{", start + len(header) - 1)
    end = balanced(text, brace)
    return text[brace + 1:end - 1]


def certs(src):
    rows = []
    seen = set()
    for name_file in ("verify_test.go", "x509_test.go", "parser_test.go"):
        text = (src / name_file).read_text()
        for m in re.finditer(r"(?:const|var)\s+(\w+)\s*=\s*(?:\[\]byte\(|testingKey\()?`(.*?)`", text, re.S):
            name, literal = m.group(1), m.group(2)
            blocks = list(PEM.finditer(literal))
            for index, block in enumerate(blocks):
                body = re.sub(r"\s", "", block.group(2))
                try:
                    raw = base64.b64decode(body, validate=True)
                except Exception:
                    continue
                key = name if index == 0 else f"{name}#{index}"
                if key in seen:
                    continue
                seen.add(key)
                rows.append((key, block.group(1), base64.b64encode(raw).decode()))
    # certBytes: base64 of concatenated certificates in a Go string expression.
    x509_text = (src / "x509_test.go").read_text()
    m = re.search(r'var certBytes = ((?:"[^"\n]*"\s*\+?\s*)+)', x509_text)
    raw = base64.b64decode("".join(re.findall(r'"([^"]*)"', m.group(1))), validate=True)
    rows.append(("certBytes", "RAW", base64.b64encode(raw).decode()))
    # csrBase64Array: the CSRs generated with OpenSSL.
    start = x509_text.index("var csrBase64Array = [...]string{")
    brace = x509_text.index("{", start)
    block = strip_comments(x509_text[brace:balanced(x509_text, brace)])
    for index, literal in enumerate(re.findall(r'"([^"]*)"', block)):
        rows.append((f"csrBase64Array.{index}", "RAW", base64.b64encode(base64.b64decode(literal, validate=True)).decode()))
    seen.add("certBytes")
    (OUT / "certs.tsv").write_text("".join(f"{a}\t{b}\t{c}\n" for a, b, c in rows))
    return {r[0] for r in rows}


def hex_consts(src):
    """Named hexadecimal constants of the key tests, and the SEC 1 table of sec1_test.go."""
    rows = []
    for name_file in ("x509_test.go", "pkcs8_test.go", "sec1_test.go"):
        text = (src / name_file).read_text()
        for m in re.finditer(r'(?:const|var)\s+(\w+)\s*=\s*[`"]([0-9a-f]{40,})[`"]', text):
            rows.append((m.group(1), m.group(2)))
    sec1 = (src / "sec1_test.go").read_text()
    for index, m in enumerate(re.finditer(r'\{"([0-9a-f]+)", (true|false)\}', sec1)):
        rows.append((f"ecKeyTests.{index}.{m.group(2)}", m.group(1)))
    (OUT / "hex_consts.tsv").write_text("".join(f"{a}\t{b}\n" for a, b in rows))
    return len(rows)


def verify_tests(src, known):
    text = strip_comments((src / "verify_test.go").read_text())
    body = literal_body(text, "var verifyTests = []verifyTest{")
    out = []
    for entry in top_level_entries(body):
        if "generatePEMCert" in entry:
            continue  # built at run time; ported by hand
        def field(pattern, default=""):
            m = re.search(pattern, entry)
            return m.group(1) if m else default
        def idents(pattern):
            m = re.search(pattern, entry, re.S)
            return [x.strip() for x in m.group(1).split(",") if x.strip()] if m else []
        leaf = field(r"\bleaf:\s*(\w+)")
        callback = re.search(r"errorCallback:\s*(\w+)(?:\(\"(.*?)\"\))?", entry)
        chains = []
        m = re.search(r"expectedChains:\s*\[\]\[\]string\{(.*)\}", entry, re.S)
        if m:
            for group in re.finditer(r"\{([^{}]*)\}", m.group(1), re.S):
                chains.append(re.findall(r'"((?:[^"\\]|\\.)*)"', group.group(1)))
        for name in [leaf] + idents(r"intermediates:\s*\[\]string\{(.*?)\}") + idents(r"roots:\s*\[\]string\{(.*?)\}"):
            if name not in known:
                raise SystemExit(f"verify_test.go: constant {name} has no PEM")
        out.append({
            "name": field(r'\bname:\s*"(.*?)"'),
            "leaf": leaf,
            "intermediates": idents(r"intermediates:\s*\[\]string\{(.*?)\}"),
            "roots": idents(r"roots:\s*\[\]string\{(.*?)\}"),
            "time": int(field(r"currentTime:\s*(\d+)", "0")),
            "dns": field(r'dnsName:\s*"(.*?)"'),
            "ekus": [x.replace("ExtKeyUsage", "") for x in idents(r"keyUsages:\s*\[\]ExtKeyUsage\{(.*?)\}")],
            "callback": callback.group(1) if callback else "",
            "callback_arg": (callback.group(2) or "") if callback else "",
            "chains": chains,
        })
    (OUT / "verify_tests.json").write_text(json.dumps(out, indent=1) + "\n")
    return len(out)


def policies_valid(src):
    text = strip_comments((src / "verify_test.go").read_text())
    start = text.index("func TestPoliciesValid")
    body = literal_body(text[start:], "tests := []testCase{")
    out = []
    for entry in top_level_entries(body):
        def flag(name):
            return bool(re.search(rf"\b{name}:\s*true", entry))
        chain = re.search(r"chain:\s*\[\]\*Certificate\{(.*?)\}", entry, re.S)
        policies = re.search(r"policies:\s*\[\]OID\{(.*?)\}", entry, re.S)
        out.append({
            "chain": [x.strip() for x in chain.group(1).split(",") if x.strip()],
            "policies": [x.strip() for x in policies.group(1).split(",") if x.strip()] if policies else [],
            "require_explicit_policy": flag("requireExplicitPolicy"),
            "inhibit_policy_mapping": flag("inhibitPolicyMapping"),
            "inhibit_any_policy": flag("inhibitAnyPolicy"),
            "valid": flag("valid"),
        })
    (OUT / "policies_valid.json").write_text(json.dumps(out, indent=1) + "\n")
    return len(out)


GO_DUMP = r'''package main

import (
	"crypto/x509"
	"encoding/json"
	"os"
)

const (
	ExtKeyUsageAny             = x509.ExtKeyUsageAny
	ExtKeyUsageServerAuth      = x509.ExtKeyUsageServerAuth
	ExtKeyUsageClientAuth      = x509.ExtKeyUsageClientAuth
	ExtKeyUsageEmailProtection = x509.ExtKeyUsageEmailProtection
)

type ExtKeyUsage = x509.ExtKeyUsage

type nameConstraintsTest struct {
	name          string
	roots         []constraintsSpec
	intermediates [][]constraintsSpec
	leaf          leafSpec
	requestedEKUs []ExtKeyUsage
	expectedError string
	noOpenSSL     bool
	ignoreCN      bool
}

type constraintsSpec struct {
	ok   []string
	bad  []string
	ekus []string
}

type leafSpec struct {
	sans []string
	ekus []string
	cn   string
}

var nameConstraintsTests = []nameConstraintsTest{
@TABLE@
}

func spec(c constraintsSpec) map[string]any {
	return map[string]any{"ok": c.ok, "bad": c.bad, "ekus": c.ekus}
}

func main() {
	var out []map[string]any
	for _, t := range nameConstraintsTests {
		var roots []any
		for _, r := range t.roots {
			roots = append(roots, spec(r))
		}
		var inters [][]any
		for _, level := range t.intermediates {
			var l []any
			for _, c := range level {
				l = append(l, spec(c))
			}
			inters = append(inters, l)
		}
		var ekus []int
		for _, e := range t.requestedEKUs {
			ekus = append(ekus, int(e))
		}
		out = append(out, map[string]any{
			"name": t.name, "roots": roots, "intermediates": inters,
			"leaf": map[string]any{"sans": t.leaf.sans, "ekus": t.leaf.ekus, "cn": t.leaf.cn},
			"requested_ekus": ekus, "expected_error": t.expectedError,
		})
	}
	json.NewEncoder(os.Stdout).Encode(out)
}
'''


def name_constraints(src):
    text = strip_comments((src / "name_constraints_test.go").read_text())
    body = literal_body(text, "var nameConstraintsTests = []nameConstraintsTest{")
    with tempfile.TemporaryDirectory() as tmp:
        program = Path(tmp) / "main.go"
        program.write_text(GO_DUMP.replace("@TABLE@", body))
        env = dict(os.environ, GOTOOLCHAIN="local")
        out = subprocess.check_output(["go", "run", str(program)], env=env, text=True)
    data = json.loads(out)
    (OUT / "name_constraints.json").write_text(json.dumps(data, indent=1) + "\n")
    return len(data)


def policy_data(src):
    testdata = src / "testdata"
    target = OUT / "policy"
    target.mkdir(exist_ok=True)
    for path in sorted(testdata.glob("policy_*.pem")):
        shutil.copy(path, target / path.name)
    shutil.copy(testdata / "test-dir.crt", OUT / "test-dir.crt")
    shutil.copy(src / "test-file.crt", OUT / "test-file.crt")
    pkits = OUT / "pkits"
    pkits.mkdir(exist_ok=True)
    # The subset of the suite that TestNISTPKITSPolicy runs, by name.
    go = (src / "pkits_test.go").read_text()
    wanted = set(re.findall(r'^\t\t"(.+?)":\s+true,', go, re.M))
    vectors = json.loads((testdata / "nist-pkits" / "vectors.json").read_text())
    selected = [v for v in vectors if v["Name"] in wanted]
    assert len(selected) == len(wanted), (len(selected), len(wanted))
    (pkits / "vectors.json").write_text(json.dumps(selected, indent=1) + "\n")
    used = set()
    for v in selected:
        used.update(v["CertPath"])
    for name in sorted(used):
        shutil.copy(testdata / "nist-pkits" / "certs" / name, pkits / name)
    return len(used)


def main():
    src = go_root() / "src" / "crypto" / "x509"
    OUT.mkdir(parents=True, exist_ok=True)
    known = certs(src)
    n_hex = hex_consts(src)
    n_verify = verify_tests(src, known)
    n_policies = policies_valid(src)
    n_nc = name_constraints(src)
    n_pkits = policy_data(src)
    print(f"{n_hex} hex constants, {len(known)} PEM constants, {n_verify} verify tests, {n_policies} policy cases, "
          f"{n_nc} name constraint tests, {n_pkits} PKITS certificates")


if __name__ == "__main__":
    main()
