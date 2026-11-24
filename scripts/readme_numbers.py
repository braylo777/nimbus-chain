#!/usr/bin/env python3
"""README numbers come from results/metrics.json only (G3).

The block between <!-- metrics:begin --> and <!-- metrics:end --> in README.md is generated from the JSON.
    python3 scripts/readme_numbers.py --write   # regenerate the block
    python3 scripts/readme_numbers.py --check   # CI: fail if the README block differs from the JSON
"""
import argparse, json, os, sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
BEGIN, END = "<!-- metrics:begin -->", "<!-- metrics:end -->"


def fmt_int(v):
    return f"{v:,}"


def render(d):
    m = d["metrics"]
    v = lambda k: m[k]["value"]
    mc = d["machine"]
    date = d["generated_at"][:10]
    rows = [
        (
            "Throughput (end to end, 4 threads, pipelined, one fsync per slot)",
            f"{fmt_int(v('pipeline_entries_per_s_4t'))} signed entries/s",
        ),
        (
            "Same, with 2 journal replicas required",
            f"{fmt_int(v('pipeline_entries_per_s_4t_2replicas'))} entries/s",
        ),
        (
            "Order matching",
            f"{v('match_ns_per_op')} ns/op single market · {v('match_16_markets_mops')} M ops/s across 16 markets",
        ),
        (
            "Light-client proof (21 validators)",
            f"{v('lightclient_proof_kb_n21')} KB, verified in {v('lightclient_verify_ms_n21')} ms (native, one core)",
        ),
        ("Agent receipt check", f"{v('receipt_agent_check_us')} µs"),
        (
            "Tests",
            f"{fmt_int(d['tests']['value'])} Rust tests across {d['crates']['value']} crates + 4 fuzz targets",
        ),
    ]
    out = [BEGIN, "| Metric | Value |", "|---|---|"]
    out += [f"| {a} | {b} |" for a, b in rows]
    out.append("")
    out.append(
        f"*Measured {date} on {mc['cpu']} ({mc['cores']} cores, {mc['os']}, {mc['rustc']}), commit "
        f"`{d['git_sha']}`, real hardware (not simulated). Source: [`results/metrics.json`](results/metrics.json) "
        f"← `make metrics`. Cloud-VM run: `results/bench-*-gha-ubuntu.json`.*"
    )
    out.append(END)
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--write", action="store_true")
    a = ap.parse_args()
    with open(os.path.join(ROOT, "results", "metrics.json")) as f:
        block = render(json.load(f))
    p = os.path.join(ROOT, "README.md")
    with open(p) as f:
        readme = f.read()
    if BEGIN not in readme or END not in readme:
        sys.exit("README.md has no metrics block")
    i, j = readme.index(BEGIN), readme.index(END) + len(END)
    new = readme[:i] + block + readme[j:]
    if a.check:
        if new != readme:
            sys.exit(
                "README numbers differ from results/metrics.json — run: python3 scripts/readme_numbers.py --write"
            )
        print("README numbers == results/metrics.json")
    else:
        with open(p, "w") as f:
            f.write(new)
        print("README.md metrics block written")


if __name__ == "__main__":
    main()
