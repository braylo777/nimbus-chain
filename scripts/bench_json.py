#!/usr/bin/env python3
"""Run the nimbus-core benchmarks and write machine-readable results (G3).

Writes results/bench-YYYY-MM-DD-<label>.json (every parsed number + raw output) and, with --metrics,
results/metrics.json (the numbers the README quotes). Each value records the command that produced it.

    python3 scripts/bench_json.py --label mac-m2pro --metrics      # reference machine (README numbers)
    python3 scripts/bench_json.py --label gha-ubuntu               # cloud VM (GitHub Actions runner)
"""
import argparse, datetime, json, os, platform, re, subprocess, sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
CORE = os.path.join(ROOT, "nimbus-core")
BIN = os.path.join(CORE, "target", "release")


def sh(cmd, env=None):
    e = dict(os.environ, **(env or {}))
    return subprocess.run(
        cmd, cwd=CORE, env=e, check=True, capture_output=True, text=True
    ).stdout


def num(pattern, text, cast=float):
    m = re.search(pattern, text, re.M)
    if not m:
        sys.exit(f"pattern not found: {pattern}")
    return cast(m.group(1))


def machine():
    cpu = platform.processor() or platform.machine()
    try:
        if sys.platform == "darwin":
            cpu = sh(["sysctl", "-n", "machdep.cpu.brand_string"]).strip()
        else:
            with open("/proc/cpuinfo") as f:
                m = re.search(r"model name\s*:\s*(.+)", f.read())
                cpu = m.group(1).strip() if m else cpu
    except Exception:
        pass
    host = re.search(r"^host: (\S+)", sh(["rustc", "-vV"]), re.M).group(1)
    return {
        "os": f"{platform.system()} {platform.release()}",
        "arch": host.split("-")[0],
        "target": host,
        "cpu": cpu,
        "cores": os.cpu_count(),
        "rustc": sh(["rustc", "--version"]).strip(),
    }


def m(value, unit, cmd, what):
    return {"value": value, "unit": unit, "command": cmd, "what": what}


def run(label):
    sh(["cargo", "build", "--release", "-q"])
    raw, r = {}, {}

    def bench(name):
        raw[name] = sh([os.path.join(BIN, name)])
        return raw[name], f"nimbus-core/target/release/{name}"

    t, c = bench("pipeline-bench")
    r["pipeline_entries_per_s_4t"] = m(
        num(
            r"^pipelined \(4 threads, verify s\+1 ∥ commit s, 0 replicas\):\s+(\d+)",
            t,
            int,
        ),
        "entries/s",
        c,
        "signed entries/s end to end (verify, admit, journal + fsync, match, receipts, checkpoint), 4 threads, pipelined",
    )
    r["pipeline_entries_per_s_4t_2replicas"] = m(
        num(
            r"^pipelined \(4 threads, verify s\+1 ∥ commit s, 2 replicas\):\s+(\d+)",
            t,
            int,
        ),
        "entries/s",
        c,
        "same, 2 local journal replicas both required",
    )
    r["pipeline_baseline_entries_per_s"] = m(
        num(r"^baseline .*?:\s+(\d+) entries/s", t, int),
        "entries/s",
        c,
        "sequential single-verification baseline",
    )
    r["receipt_agent_check_us"] = m(
        num(r"agent check ([\d.]+) µs", t), "µs", c, "agent-side receipt-proof check"
    )

    t, c = bench("match-bench")
    r["match_ns_per_op"] = m(
        num(r"^single market .*?= ([\d.]+) ns/op", t),
        "ns/op",
        c,
        "single-market matching cost per operation",
    )
    r["match_16_markets_mops"] = m(
        num(r"^\s*16 markets\s*: .*?= ([\d.]+) M ops/s", t),
        "M ops/s",
        c,
        "16 markets matched in parallel",
    )

    t, c = bench("lc-bench")
    r["lightclient_proof_kb_n21"] = m(
        round(num(r"^n =\s+21 .*?proof (\d+) B", t, int) / 1000, 2),
        "KB",
        c,
        "finality proof size, 21 validators (quorum 17)",
    )
    r["lightclient_verify_ms_n21"] = m(
        round(num(r"^n =\s+21 .*?verify p50 (\d+) us", t, int) / 1000, 2),
        "ms",
        c,
        "finality proof verification p50, one core, native",
    )

    t, c = bench("hash-bench")
    r["sha384_us_per_hash"] = m(
        num(r"^reference : .*?\(([\d.]+) us/hash\)", t),
        "µs/hash",
        c,
        "domain-separated SHA-384 Merkle hashing, one core",
    )

    t, c = bench("journal-bench")
    r["journal_records_per_s_fsync256"] = m(
        num(r"^fsync every\s+256: .*?= (\d+) records/s", t, int),
        "records/s",
        c,
        "journal append with fsync every 256 records",
    )

    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    sha = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    ).stdout.strip()
    out = sh(["cargo", "test", "--release", "--workspace", "-q", "--", "--list"])
    tests = sum(1 for line in out.splitlines() if line.endswith(": test"))
    return {
        "label": label,
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "git_sha": sha,
        "machine": machine(),
        "kind": "measured on real hardware (not simulated)",
        "tests": {"value": tests, "command": "python3 scripts/count_tests.py"},
        "crates": {"value": 12, "command": "ls nimbus-core/crates"},
        "metrics": r,
        "raw": raw,
    }, now


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True)
    ap.add_argument(
        "--metrics",
        action="store_true",
        help="also write results/metrics.json (README source)",
    )
    a = ap.parse_args()
    doc, now = run(a.label)
    os.makedirs(os.path.join(ROOT, "results"), exist_ok=True)
    path = os.path.join(
        ROOT, "results", f"bench-{now.date().isoformat()}-{a.label}.json"
    )
    with open(path, "w") as f:
        json.dump(doc, f, indent=1, ensure_ascii=False)
        f.write("\n")
    print(path)
    if a.metrics:
        md = {k: v for k, v in doc.items() if k != "raw"}
        md["source"] = os.path.relpath(path, ROOT)
        with open(os.path.join(ROOT, "results", "metrics.json"), "w") as f:
            json.dump(md, f, indent=1, ensure_ascii=False)
            f.write("\n")
        print("results/metrics.json")
