#!/usr/bin/env python3
"""Build instrumented libFuzzer targets and run bounded parallel campaigns."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from check import source_fingerprint

ROOT = Path(__file__).resolve().parent.parent
FLAGS = "-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table -Cllvm-args=-sanitizer-coverage-trace-compares -Cpanic=abort"

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--targets", nargs="+", choices=("text", "protocol", "binary"), default=["text", "protocol", "binary"])
    parser.add_argument("--no-build", action="store_true")
    args = parser.parse_args()
    if args.seconds < 1:
        parser.error("--seconds must be positive")
    initial_source = source_fingerprint()
    env = dict(os.environ, RUSTUP_TOOLCHAIN="nightly", RUSTFLAGS=FLAGS)
    rustc = subprocess.check_output(["rustc", "-vV"], env=env, text=True)
    target = re.search(r"^host: (.+)$", rustc, re.M).group(1)
    if not args.no_build:
        subprocess.run([args.cargo, "build", "--offline", "--locked", "--release", "--manifest-path", str(ROOT / "fuzz/Cargo.toml"), "--target", target], env=env, cwd=ROOT, check=True)
    destination = ROOT / "fuzz/runs" / time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    destination.mkdir(parents=True)
    def run(name):
        corpus = destination / name / "corpus"
        shutil.copytree(ROOT / "fuzz/corpus" / name, corpus)
        artifacts = destination / name / "artifacts"
        artifacts.mkdir()
        binary = ROOT / "fuzz/target" / target / "release" / name
        started = time.monotonic()
        result = subprocess.run([str(binary), str(corpus), f"-max_total_time={args.seconds}", "-max_len=8192", "-timeout=5", "-rss_limit_mb=512", f"-artifact_prefix={artifacts}/", "-print_final_stats=1"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=ROOT)
        text = result.stdout.decode("utf-8", errors="replace")
        (destination / (name + ".log")).write_text(text)
        coverage = re.findall(r"cov: (\d+) ft: (\d+)", text)
        executions = re.search(r"stat::number_of_executed_units:\s*(\d+)", text)
        return {"target": name, "exit_code": result.returncode, "elapsed_seconds": round(time.monotonic()-started, 3), "executions": int(executions.group(1)) if executions else None, "coverage_edges": int(coverage[-1][0]) if coverage else None, "features": int(coverage[-1][1]) if coverage else None, "artifacts": [p.name for p in artifacts.iterdir()]}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(args.targets)) as pool:
        results = list(pool.map(run, args.targets))
    source_changed = initial_source != source_fingerprint()
    report = {"toolchain": rustc, "instrumentation": FLAGS, "max_input_bytes":8192, "requested_seconds_per_target":args.seconds, "campaigns":results,
              "source_sha256": initial_source, "source_changed_during_run": source_changed}
    (destination / "report.json").write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps({"report":str(destination / "report.json"), **report},indent=2))
    return 0 if all(r["exit_code"] == 0 for r in results) and not source_changed else 1

if __name__ == "__main__":
    raise SystemExit(main())
