#!/usr/bin/env python3
"""Registers the HTTP/2 interop run (tools/h2_interop.py) with tools/parity_check.py."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import h2_interop

if __name__ == "__main__":
    h2_interop.main()
