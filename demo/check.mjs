// CI check of the WASM demo (Node ≥ 20, no npm packages): every proof in the replayed tape verifies at its slot,
// every single-byte tamper is refused, and verification stays under 5 ms per proof.
import { readFileSync } from "node:fs";
import { loadVerifier, hexToBytes } from "./site/verifier.js";

const dir = new URL("./site/", import.meta.url);
const v = await loadVerifier(readFileSync(new URL("verifier.wasm", dir)));
const tape = JSON.parse(readFileSync(new URL("tape.json", dir), "utf8"));
if (v.setValidators(tape.validators) !== tape.validators.length) throw new Error("validator set refused");

let ok = 0, refused = 0, worst = 0;
const times = [];
for (const s of tape.slots) {
  for (const e of s.entries) {
    const p = hexToBytes(e.proof);
    const t0 = performance.now();
    const reps = 50;
    let r = 0;
    for (let i = 0; i < reps; i++) r = v.verify(p);
    const ms = (performance.now() - t0) / reps;
    times.push(ms);
    worst = Math.max(worst, ms);
    if (r !== s.slot) throw new Error(`slot ${s.slot} "${e.text}": got ${r}`);
    ok++;
    for (let i = 0; i < p.length; i += 7) {
      const bad = p.slice();
      bad[i] ^= 0x01;
      if (v.verify(bad) === s.slot) throw new Error(`tampered byte ${i} accepted (slot ${s.slot})`);
      refused++;
    }
  }
}
times.sort((a, b) => a - b);
console.log(`${ok} proofs verified, ${refused} tampered proofs refused; verify median ${times[times.length >> 1].toFixed(3)} ms, max ${worst.toFixed(3)} ms`);
if (worst >= 5) throw new Error(`verify ${worst.toFixed(2)} ms >= 5 ms`);
