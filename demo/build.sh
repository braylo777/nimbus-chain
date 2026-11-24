#!/usr/bin/env bash
# Build the WASM light-client demo into demo/site/: verifier.wasm (wasm32, plain C ABI) and tape.json (a tape replayed
# through the real engine, with a finality proof per entry). No npm, no wasm-bindgen.
set -euo pipefail
cd "$(dirname "$0")/verifier"
cargo build --release --locked --target wasm32-unknown-unknown --lib
cp target/wasm32-unknown-unknown/release/nimbus_wasm_verifier.wasm ../site/verifier.wasm
cargo run --release --locked --bin make-tape > ../site/tape.json
cargo test --release --locked -q
ls -l ../site
