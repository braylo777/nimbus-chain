#!/usr/bin/env bash
# Build everything in release mode, run all tests, run the seven benchmarks, then the static checks (fmt, clippy, cargo audit).
# Stress mode: PROPTEST_CASES=20000 PIPELINE_SLOTS=400 ./build_and_test.sh
# Native mode: NIMBUS_NATIVE=1 ./build_and_test.sh compiles for this CPU (target-cpu=native; the binaries then do not
# run on older CPUs). Measured +8% pipelined throughput on a 4-vCPU Xeon VM (AUDIT.md, P3).
set -euo pipefail
cd "$(dirname "$0")"
if [ "${NIMBUS_NATIVE:-0}" = 1 ]; then export RUSTFLAGS="${RUSTFLAGS:-} -C target-cpu=native"; echo "native build: RUSTFLAGS=$RUSTFLAGS"; fi
cargo build --release
cargo test --release
echo; echo "== hash engine ==";            ./target/release/hash-bench
echo; echo "== matching engine ==";        ./target/release/match-bench
echo; echo "== light-client verifier ==";  ./target/release/lc-bench
echo; echo "== journal ==";                ./target/release/journal-bench
echo; echo "== end-to-end pipeline ==";    ./target/release/pipeline-bench
echo; echo "== replication latency ==";   REPL_SLOTS=${REPL_SLOTS:-1000} ./target/release/repl-bench
echo; echo "== replication over TCP ==";  TCP_SLOTS=${TCP_SLOTS:-1000} TCP_SLOT_US=${TCP_SLOT_US:-1000} ./target/release/tcp-bench
echo; echo "== audit =="
cargo fmt --all -- --check
echo "fmt: clean"
cargo clippy --release --all-targets -- -D warnings
echo "clippy: clean"
if command -v cargo-audit >/dev/null; then cargo audit; else echo "(install cargo-audit for the dependency scan: cargo install cargo-audit)"; fi
