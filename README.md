# Nimbus Chain

**A dual-path BFT chain for certified operations tapes, with verifiable commitment to autonomous-agent state.**
*The blockchain for safe superintelligence.*

| | |
|---|---|
| Throughput (reference engine, 4 cores) | 150,000–183,000 signed entries/s, one fsync per slot |
| Order matching | 195 ns/op single market · 8.4 M ops/s across 16 markets |
| Light-client proof | 3.8 KB, verified in 1.1 ms |
| Tests | 120 Rust tests across 12 crates + property, differential and fuzz suites |

## What is here
- [`nimbus-core/`](nimbus-core): v0.17 reference engine, 12 Rust crates (matching, journal, quorum replication, bridge certifier, light client, Ed25519 batch verification, feed quorum, agent SDK, key-isolating signer). See its [README](nimbus-core/README.md) and [AUDIT](nimbus-core/AUDIT.md).
- [`nimbus-local-chain/`](nimbus-local-chain): `NimbusToken` Solidity contract on a local Hardhat chain (chainId 31337).
- [`whitepaper/`](whitepaper): NIMBUS whitepaper, Working Draft V3 ([PDF](whitepaper/nimbus-whitepaper-v3.pdf) · [Markdown](whitepaper/nimbus-whitepaper-v3.md)).

## Build and test
```bash
cd nimbus-core && ./build_and_test.sh
```
Requires Rust 1.75+. Local development only; not audited for production. Not investment advice.

## License
MIT. © 2026 Brandon "Braylo" Lopez · NimBros PBC.
