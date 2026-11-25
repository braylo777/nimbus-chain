# Nimbus Chain

[![CI](https://github.com/braylo777/nimbus-chain/actions/workflows/ci.yml/badge.svg)](https://github.com/braylo777/nimbus-chain/actions/workflows/ci.yml)
[![fuzz](https://github.com/braylo777/nimbus-chain/actions/workflows/fuzz.yml/badge.svg)](https://github.com/braylo777/nimbus-chain/actions/workflows/fuzz.yml)
![version](https://img.shields.io/badge/version-v0.18-4338ca)
![crates](https://img.shields.io/badge/crates-12-334155)

**A dual-path BFT chain for certified operations tapes, with verifiable commitment to autonomous-agent state.**
*Agent-speed SI blockchain.*

**Live demo:** [nimbus.braylo.si](https://nimbus.braylo.si) — finality proofs from a replayed tape (order → match → receipt → checkpoint → proof), verified by the light client in WebAssembly in your browser.

<!-- metrics:begin -->
| Metric | Value |
|---|---|
| Throughput (end to end, 4 threads, pipelined, one fsync per slot) | 207,141 signed entries/s |
| Same, with 2 journal replicas required | 173,895 entries/s |
| Order matching | 92.9 ns/op single market · 26.09 M ops/s across 16 markets |
| Light-client proof (21 validators) | 1.92 KB, verified in 0.46 ms (native, one core) |
| Agent receipt check | 66.4 µs |
| Tests | 309 Rust tests across 12 crates + 4 fuzz targets |

*Measured 2026-11-24 on Apple M2 Pro (12 cores, Darwin 25.6.0, rustc 1.100.0 (0ef1bc386 2026-11-09)), commit `d897eee`, real hardware (not simulated). Source: [`results/metrics.json`](results/metrics.json) ← `make metrics`. Cloud-VM run: `results/bench-*-gha-ubuntu.json`.*
<!-- metrics:end -->

## What is here
- [`nimbus-core/`](nimbus-core): v0.18 reference engine, 12 Rust crates (matching, journal, quorum replication, bridge certifier, light client, Ed25519 batch verification, feed quorum, agent SDK, key-isolating signer). See its [README](nimbus-core/README.md) and [AUDIT](nimbus-core/AUDIT.md).
- [`nimbus-core/fuzz/`](nimbus-core/fuzz): 4 cargo-fuzz targets — order decode, match engine, journal replay, light-client verify — run 30 min each nightly.
- [`docs/dissertation/`](docs/dissertation): the dissertation ([Markdown](docs/dissertation/nimbus-dissertation.md) · [PDF](docs/dissertation/nimbus-dissertation.pdf)), 13 chapters, with 6 figures in [`docs/img/`](docs/img).
- [`demo/`](demo): the WASM light-client verifier (plain C ABI, no npm) and the tape generator.
- [`results/`](results): benchmark JSON per machine (laptop + cloud VM); the numbers above are generated from it.
- [`nimbus-local-chain/`](nimbus-local-chain): `NimbusToken` Solidity contract on a local Hardhat chain (chainId 31337).
- [`whitepaper/`](whitepaper): NIMBUS whitepaper, Working Draft V3 ([PDF](whitepaper/nimbus-whitepaper-v3.pdf) · [Markdown](whitepaper/nimbus-whitepaper-v3.md)).

## Evidence, labelled
| Kind | What | Where |
|---|---|---|
| Proved | root binding at f < 1/3; light-client soundness | whitepaper §4.1, Theorems A, A\*, B; Prop. V |
| Simulated | BFT certification, f = 1 of 4, lossy/reordering network: safety + liveness proptests | `nimbus-core/crates/nimbus-bridge/tests/bft_sim.rs` |
| Simulated | deterministic replay: same input ⇒ same journal + checkpoints in both batching modes | `nimbus-core/crates/nimbus-bridge/tests/replay.rs` |
| Measured | throughput, matching, proof size and verify time (table above) | `results/*.json` ← `make metrics` |
| Fuzzed | 4 targets, 0 crashes required | `.github/workflows/fuzz.yml` |

## Build and test
```bash
cd nimbus-core && ./build_and_test.sh          # build, tests, benchmarks, fmt, clippy
python3 scripts/count_tests.py --min 300       # test count, from the test runner
make metrics                                   # benchmarks → results/*.json → README numbers
cd nimbus-core/fuzz && cargo +nightly fuzz run match_engine
./demo/build.sh && node demo/check.mjs         # WASM verifier + replayed tape
docker build -t nimbus-chain . && docker run --rm nimbus-chain
```
Requires Rust 1.88+. Local development only; not audited for production. Not investment advice.

## License
MIT. © 2026 Brandon "Braylo" Lopez · NimBros PBC.
