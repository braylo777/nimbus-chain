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


DBEGIN, DEND = "<!-- dissertation-metrics:begin -->", "<!-- dissertation-metrics:end -->"
DISS = os.path.join("docs", "dissertation", "nimbus-dissertation.md")


def render_dissertation(ref):
    """Reference machine (metrics.json) next to the newest cloud-VM run (results/bench-*-gha-ubuntu.json)."""
    import glob

    runs = [("reference", ref)]
    cloud = sorted(glob.glob(os.path.join(ROOT, "results", "bench-*-gha-ubuntu.json")))
    if cloud:
        with open(cloud[-1]) as f:
            runs.append((os.path.relpath(cloud[-1], ROOT), json.load(f)))
    head = "| Metric | " + " | ".join(
        f"{d['machine']['cpu']}, {d['machine']['cores']} cores ({d['generated_at'][:10]}, `{d['git_sha']}`)" for _, d in runs
    ) + " |"
    out = [DBEGIN, head, "|---|" + "---|" * len(runs)]
    for k, m in ref["metrics"].items():
        cells = []
        for _, d in runs:
            x = d["metrics"].get(k)
            cells.append("—" if x is None else (fmt_int(x["value"]) if isinstance(x["value"], int) else str(x["value"])))
        out.append(f"| {m['what']} ({m['unit']}) | " + " | ".join(cells) + " |")
    out.append("")
    out.append("*Sources: " + ", ".join(f"`{'results/metrics.json' if n == 'reference' else n}`" for n, _ in runs)
               + ". Commands: `make metrics` (reference), `.github/workflows/bench.yml` (cloud VM).*")
    out.append(DEND)
    return "\n".join(out)


def splice(text, begin, end, block, name):
    if begin not in text or end not in text:
        sys.exit(f"{name} has no metrics block")
    i, j = text.index(begin), text.index(end) + len(end)
    return text[:i] + block + text[j:]


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--write", action="store_true")
    a = ap.parse_args()
    with open(os.path.join(ROOT, "results", "metrics.json")) as f:
        ref = json.load(f)
    targets = [("README.md", BEGIN, END, render(ref)), (DISS, DBEGIN, DEND, render_dissertation(ref))]
    bad = []
    for name, b, e, block in targets:
        p = os.path.join(ROOT, name)
        with open(p) as f:
            old = f.read()
        new = splice(old, b, e, block, name)
        if a.check and new != old:
            bad.append(name)
        elif a.write:
            with open(p, "w") as f:
                f.write(new)
            print(f"{name}: metrics block written")
    if a.check:
        if bad:
            sys.exit(f"numbers differ from results/*.json in: {', '.join(bad)} — run: python3 scripts/readme_numbers.py --write")
        print("README + dissertation numbers == results JSON")


if __name__ == "__main__":
    main()
