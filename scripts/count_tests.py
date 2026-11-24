#!/usr/bin/env python3
"""Count tests from the test runner only (G4): `cargo test --release -- --list` in nimbus-core."""
import argparse, os, subprocess, sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "nimbus-core")


def count() -> int:
    out = subprocess.run(["cargo", "test", "--release", "--workspace", "-q", "--", "--list"],
                         cwd=ROOT, check=True, capture_output=True, text=True).stdout
    return sum(1 for line in out.splitlines() if line.endswith(": test"))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--min", type=int, default=0)
    n = count()
    a = ap.parse_args()
    print(f"tests: {n}")
    sys.exit(0 if n >= a.min else f"tests {n} < required {a.min}")
